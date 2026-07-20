"""usnmon.py -- USN Journal Monitor (the recorder).  YASDC, Inc.

A Windows forensic RECORDER. It captures 100% of NTFS USN Change Journal activity to
a single Windows event log, then rotates -> compresses -> hashes -> signs -> archives
that record forever, so investigators get months/years of file-activity history
instead of the journal's tiny ~1024-entry circular buffer.

It does ONE thing and does not decide anything: capture, rotate, compress, hash, sign,
archive. No filtering, no rules engine, no forwarding -- all noise-filtering and
signal-extraction happen later, offline, in a separate analysis tool (Program 2).

Mission: this records WHAT HAPPENED to files; it does not judge maliciousness. That is
the investigator's call, in hindsight, with context the engine lacks. See BLUEPRINT.md.

Platform: Windows-only at runtime (USN ioctls, event log, cert store). The USN binary
parsing and ioctl calls are lifted from the proven v1 engine. Pure-logic helpers live
in usn_common.py and are unit-tested cross-platform.
"""

import os
import sys
import struct
import time
import threading
import logging
import logging.handlers
from datetime import datetime, timezone

import usn_common as common

# --- Windows-only imports (guarded so the module can be inspected on non-Windows) ---
try:
    import win32api
    import win32file
    import win32evtlog
    import win32evtlogutil
    import win32service
    import win32serviceutil
    import win32event
    import servicemanager
    import winerror
    _WINDOWS = True
except Exception:
    win32api = win32file = win32evtlog = win32evtlogutil = None
    win32service = win32serviceutil = win32event = servicemanager = winerror = None
    _WINDOWS = False

# --------------------------------------------------------------------------- #
# Identity / constants
# --------------------------------------------------------------------------- #
SERVICE_NAME = "USNMonitorService"
SERVICE_DISPLAY = "USN Journal Monitor (usnmon)"
LOG_CHANNEL = "FileSystem"            # single log; everything goes here
SOURCE_NAME = "USNJournalMonitor"

DIAG_LOG_NAME = "usnmon.log"

# Windows Event Log FileSystem channel size cap (4 GB), set by
# register_event_source at install time. usnmon owns this channel and its
# size setup; ongoing rotation/archival is handled by logmon.
EVENTLOG_MAX_BYTES = 0xFFFFFFFF                  # 4 GB on channel creation


# Drive-monitor poll: every 6 seconds (10x/min).
DRIVE_POLL_SEC = 6

# Verbose stats cadence (diagnostic only).
VERBOSE = os.environ.get("USN_VERBOSE", "").strip().lower() in ("1", "true", "yes", "on")
STATS_INTERVAL_SEC = 5

# USN ioctl codes
FSCTL_QUERY_USN_JOURNAL = 0x000900f4
FSCTL_READ_USN_JOURNAL = 0x000900bb
FILE_SHARE_ALL = 0x01 | 0x02 | 0x04

# Reasons that invalidate a cached path -> never serve those from cache.
RENAME_DELETE_MASK = 0x200 | 0x1000 | 0x2000

logger = logging.getLogger("usnmon")


# --------------------------------------------------------------------------- #
# Logging / host context
# --------------------------------------------------------------------------- #
# v0.0.9: diagnostic log lives at C:\ProgramData\usnmon\usnmon.log. Previously
# it lived alongside the archive directory; archives moved to logmon so the
# diagnostic log needed a new home. ProgramData matches the convention used by
# every other piece of usnmon state (cursors, device_state.json, config).
def _logs_dir():
    base = os.environ.get("ProgramData", r"C:\ProgramData")
    return os.path.join(base, "usnmon")


def setup_logging(to_console, logs_dir=None):
    """Configure the usnmon logger. v0.0.9: no archive_dir parameter -- the
    diagnostic log lives at %ProgramData%\\usnmon\\usnmon.log by default."""
    if logs_dir is None:
        logs_dir = _logs_dir()
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    try:
        os.makedirs(logs_dir, exist_ok=True)
        fh = logging.handlers.RotatingFileHandler(
            os.path.join(logs_dir, DIAG_LOG_NAME),
            maxBytes=5 * 1024 * 1024, backupCount=3)
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    except Exception:
        pass
    if to_console:
        ch = logging.StreamHandler()
        ch.setFormatter(fmt)
        logger.addHandler(ch)


def now_utc_str():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + "Z"


def _reg_machine_guid():
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Microsoft\Cryptography") as k:
            return winreg.QueryValueEx(k, "MachineGuid")[0]
    except Exception:
        return ""


def _cloud_instance_id():
    """Best-effort IMDS instance id (Azure/AWS). Empty on-prem / no metadata svc.
    Short timeout so on-prem boxes don't stall. Inspection-verified."""
    try:
        import urllib.request
        # AWS IMDSv1 (fall through quietly if unreachable).
        req = urllib.request.Request(
            "http://169.254.169.254/latest/meta-data/instance-id")
        return urllib.request.urlopen(req, timeout=0.3).read().decode().strip()
    except Exception:
        pass
    try:
        import urllib.request
        req = urllib.request.Request(
            "http://169.254.169.254/metadata/instance/compute/vmId?api-version=2021-02-01&format=text",
            headers={"Metadata": "true"})
        return urllib.request.urlopen(req, timeout=0.3).read().decode().strip()
    except Exception:
        return ""


def gather_host_context():
    """Collect host fields once at start. Per-drive VolumeSerial/JournalId are added
    per drive in the capture thread."""
    import socket
    ctx = {
        "SchemaVersion": common.SCHEMA_VERSION,
        "Hostname": socket.gethostname(),
        "FQDN": "", "Domain": "", "MachineGuid": _reg_machine_guid(),
        "MachineSID": "", "SourceIP": "", "MAC": "", "OSBuild": "",
    }
    try:
        ctx["FQDN"] = socket.getfqdn()
    except Exception:
        pass
    try:
        ctx["SourceIP"] = socket.gethostbyname(socket.gethostname())
    except Exception:
        pass
    instance = _cloud_instance_id()
    ctx["MachineId"] = common.compute_machine_id(ctx["MachineGuid"], instance or None)
    return ctx


# --------------------------------------------------------------------------- #
# Drive enumeration  (win32api.GetLogicalDriveStrings -- the v1 fix)
# --------------------------------------------------------------------------- #
def enumerate_drive_letters():
    """CHEAP presence check: the set of drive-letter roots from GetLogicalDriveStrings.
    No device I/O -- never blocks on a spinning-up optical drive or a stalled USB probe.
    The 6s monitor loop uses this for attach/detach detection; the expensive per-drive
    identity/journal probe (classify_drive) runs off the loop in a worker thread."""
    if win32api is None:
        return {"C:\\"}
    try:
        return set(x for x in win32api.GetLogicalDriveStrings().split("\x00") if x)
    except Exception as exc:
        logger.info("Drive enumeration failed: %r", exc)
        return {"C:\\"}


def _optical_kind(root):
    """Best-effort distinguish a mounted ISO (virtual DVD) from a physical optical
    drive, for drivetype=5 volumes. Returns 'iso', 'physical', or '' (undetermined ->
    caller falls back to plain drivetype=5). Uses the PnP/friendly-name via PowerShell;
    a mounted ISO presents as a 'Microsoft Virtual DVD-ROM' (or similar 'Virtual')
    device. Bounded + best-effort: any failure returns '' and we just log drivetype=5."""
    try:
        import subprocess
        letter = root.rstrip("\\")[0]
        ps = ("$v = Get-Volume -DriveLetter '%s' -ErrorAction SilentlyContinue; "
              "if ($v) { $p = Get-Partition -DriveLetter '%s' -ErrorAction "
              "SilentlyContinue; if ($p) { (Get-Disk -Number $p.DiskNumber)"
              ".Model } }" % (letter, letter))
        out = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                             capture_output=True, text=True, timeout=8)
        model = (out.stdout or "").strip().lower()
        if not model:
            return ""
        if "virtual" in model:
            return "iso"
        return "physical"
    except Exception:
        return ""


def classify_drive(root):
    """Deep per-drive probe (the expensive part -- runs OFF the monitor loop in a worker
    thread). Returns (category, detail, drivetype):
      'journal'        : NTFS/ReFS, candidate for an active USN journal
      'unsupported_fs' : present but FS can't host a journal (exFAT/FAT32/UDF/CDFS, ISO)
      'remote'         : network/remote share
      'error'          : could not be classified (the volume itself is the evidence)
    For drivetype=5 (optical) it also tries to tag the detail with iso vs physical so an
    investigator can tell a mounted ISO (e.g. SANS training image) from a real disc; if
    that can't be determined it just records drivetype=5 and moves on."""
    if win32api is None or win32file is None:
        return ("journal", "", 3)
    try:
        dt = win32file.GetDriveType(root)
    except Exception as exc:
        return ("error", "GetDriveType: %r" % exc, -1)
    if dt == 4:  # DRIVE_REMOTE
        detail = ""
        try:
            win32api.GetVolumeInformation(root)
        except Exception as exc:
            detail = "%r" % exc
        return ("remote", detail, dt)
    if dt not in (2, 3, 6):  # not REMOVABLE/FIXED/RAMDISK (e.g. CDROM=5)
        fs = ""
        try:
            fs = win32api.GetVolumeInformation(root)[4]
        except Exception:
            pass
        detail = "drivetype=%d fs=%s" % (dt, fs)
        if dt == 5:   # optical: tag iso vs physical when we can
            kind = _optical_kind(root)
            if kind:
                detail += " kind=%s" % kind
        return ("unsupported_fs", detail, dt)
    try:
        fs = win32api.GetVolumeInformation(root)[4]
    except Exception as exc:
        return ("error", "GetVolumeInformation: %r" % exc, dt)
    if fs and fs.upper() in ("NTFS", "REFS"):
        return ("journal", fs, dt)
    return ("unsupported_fs", "fs=%s" % fs, dt)


def classify_volumes():
    """Synchronous full classification of every present volume -> list of
    (root, category, detail). Back-compat wrapper kept for non-loop callers
    (list_journal_drives etc.); the 6s monitor loop does NOT use this -- it uses cheap
    enumerate_drive_letters() + off-thread classify_drive() so a slow optical/USB probe
    can never block the loop or shutdown."""
    if win32api is None or win32file is None:
        return [("C:\\", "journal", "")]
    out = []
    for root in sorted(enumerate_drive_letters()):
        cat, detail, _dt = classify_drive(root)
        out.append((root, cat, detail))
    return out


def list_journal_drives():
    """Roots that are NTFS/ReFS journal candidates (back-compat helper)."""
    return [r for (r, cat, _d) in classify_volumes() if cat == "journal"] or ["C:\\"]


def drive_root_to_device(root):
    return r"\\.\%s" % root.rstrip("\\")


def volume_serial(root):
    try:
        return "%08X" % (win32api.GetVolumeInformation(root)[1] & 0xFFFFFFFF)
    except Exception:
        return "00000000"


def journal_active(root):
    """Probe whether a volume has an ACTIVE USN journal. Returns (True, None) if the
    journal answers QUERY_USN_JOURNAL, else (False, exc). One cheap one-shot open --
    used before spawning a drive engine so a journal-less volume (error 1179) is
    recorded once and skipped, instead of being respawned every poll (reattach thrash)."""
    device = drive_root_to_device(root)
    try:
        h = win32file.CreateFile(
            device, win32file.GENERIC_READ, FILE_SHARE_ALL, None,
            win32file.OPEN_EXISTING, 0, None)
    except Exception as exc:
        return False, exc
    try:
        win32file.DeviceIoControl(h, FSCTL_QUERY_USN_JOURNAL, None, 80)
        return True, None
    except Exception as exc:
        return False, exc
    finally:
        try:
            win32file.CloseHandle(h)
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# USN journal access  (Windows-only; lifted from proven v1, inspection-verified)
# --------------------------------------------------------------------------- #
def query_journal(h_vol):
    """Return (journal_id, next_usn). Creates nothing; the journal must exist
    (it does on any modern NTFS volume). Inspection-verified."""
    out = win32file.DeviceIoControl(h_vol, FSCTL_QUERY_USN_JOURNAL, None, 80)
    # USN_JOURNAL_DATA_V0: UsnJournalID(Q) FirstUsn(q) NextUsn(q) LowestValidUsn(q)
    # MaxUsn(q) MaximumSize(Q) AllocationDelta(Q)
    j_id, first_usn, next_usn, lowest_valid = struct.unpack_from("=Qqqq", out, 0)
    return j_id, first_usn, next_usn, lowest_valid


def build_read_input(journal_id, start_usn):
    """READ_USN_JOURNAL_DATA_V0 input buffer. The caller chooses start_usn via the
    resume-decision branches: the saved cursor on a clean resume, or first_usn on a
    first run / gap / journal-recreate. The poll loop then advances start_usn from each
    read's returned NextUsn, so any history is read once and never re-scanned."""
    # StartUsn(q) ReasonMask(L) ReturnOnlyOnClose(L) Timeout(Q) BytesToWaitFor(Q)
    # UsnJournalID(Q)
    return struct.pack("=qLLQQQ", start_usn, 0xFFFFFFFF, 0, 0, 0, journal_id)


def parse_record(buf, offset):
    """Parse a USN_RECORD_V2/V3. Returns dict with usn, reason, file_ref,
    parent_ref, name, record_length, major. (V4 range records are not requested --
    reads are V0/V2 -- so EID 106 RangeChange is RESERVED, never emitted. V4 carries
    only changed byte-ranges, no content and no before/after, so it has no forensic
    value here; see EVENT_ID.md.) Inspection-verified against v1."""
    rec_len, maj, minor = struct.unpack_from("=LHH", buf, offset)
    if maj == 2:
        # V2: RecordLength(L) Major(H) Minor(H) FileRef(Q) ParentRef(Q) Usn(q)
        # Timestamp(q) Reason(L) SourceInfo(L) SecurityId(L) FileAttr(L)
        # FileNameLength(H) FileNameOffset(H) FileName(...)
        (file_ref, parent_ref, usn, _ts, reason, _si, _sid, _attr,
         name_len, name_off) = struct.unpack_from("=QQqqLLLLHH", buf, offset + 8)
    elif maj == 3:
        # V3 uses 128-bit refs (16 bytes each).
        file_ref = buf[offset + 8:offset + 24]
        parent_ref = buf[offset + 24:offset + 40]
        (usn, _ts, reason, _si, _sid, _attr, name_len, name_off) = \
            struct.unpack_from("=qqLLLLHH", buf, offset + 40)
    else:
        return None
    name = buf[offset + name_off: offset + name_off + name_len].decode(
        "utf-16-le", errors="replace")
    return {"record_length": rec_len, "major": maj, "file_ref": file_ref,
            "parent_ref": parent_ref, "usn": usn, "reason": reason, "name": name}


# --------------------------------------------------------------------------- #
# Path resolution  (OpenFileById, cached; Windows-only, inspection-verified)
# --------------------------------------------------------------------------- #
class PathResolver:
    """Resolve a file reference to a full path via OpenFileById, with an LRU-ish
    cache. Rename/delete reasons bypass the cache (the path may be stale)."""

    def __init__(self, h_vol, drive_root):
        self.h_vol = h_vol
        self.drive_root = drive_root.rstrip("\\")
        self.cache = {}
        self.last_error = None

    def resolve(self, rec):
        # Resolve the PARENT directory and join this record's own name, rather than
        # opening the file itself. Parents are stable (a file's deletion doesn't move
        # its directory), so deleted/short-lived files STILL get a real full path; and
        # one OpenFileById per directory serves every file in it -> the cache (keyed on
        # parent_ref, which is SHARED across all files in a dir) gets a high hit rate.
        # Opening file_ref instead was the bottleneck: unique per file (~0% cache hits)
        # and a guaranteed failure (-> C:\?\) the instant the file was gone.
        pref = rec["parent_ref"]
        name = rec["name"]
        # If THIS item is being renamed/deleted and happens to be a directory, any
        # cached path keyed by its ref (as some child's parent) is now stale -> drop it.
        if rec["reason"] & RENAME_DELETE_MASK:
            self.cache.pop(rec["file_ref"], None)
        parent = self.cache.get(pref)
        if parent is None:
            raw = self._open_and_resolve(pref)
            if raw is None:
                # Parent itself unresolvable (rare: its directory was also removed).
                return self.drive_root + "\\?\\" + name
            parent = raw if raw.startswith(self.drive_root) else self.drive_root + raw
            if len(self.cache) > 20000:
                self.cache.clear()
            self.cache[pref] = parent
        return parent.rstrip("\\") + "\\" + name

    def _open_and_resolve(self, ref):
        try:
            # pywin32 signature:
            #   OpenFileById(File, FileId, DesiredAccess, ShareMode,
            #                SecurityAttributes, FlagsAndAttributes)
            # FileId takes an int directly for a 64-bit V2 reference, or bytes for
            # a 128-bit V3/ReFS reference. DesiredAccess=0 (query only) avoids
            # sharing violations on locked files; that's enough for path lookup.
            # pywin32 signature (NOTE: reordered vs the native Win32 API --
            # Flags comes BEFORE SecurityAttributes here):
            #   OpenFileById(File, FileId, DesiredAccess, ShareMode, Flags,
            #                SecurityAttributes)
            # FileId: int (64-bit V2 ref) or bytes/PyIID (128-bit V3/ReFS).
            # DesiredAccess=0 (query only) avoids sharing violations on locked
            # files. Flags=0. SecurityAttributes=None (docs: "use only None").
            share = (win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE
                     | win32file.FILE_SHARE_DELETE)
            h = win32file.OpenFileById(self.h_vol, ref, 0, share, 0, None)
            try:
                name = win32file.GetFinalPathNameByHandle(h, 0)
                # Strip the \\?\ or volume prefix down to a drive-relative path.
                if name.startswith("\\\\?\\"):
                    name = name[4:]
                if len(name) > 2 and name[1] == ":":
                    return name[2:]   # drop drive letter, keep \path...
                return name
            finally:
                win32file.CloseHandle(h)
        except Exception as exc:
            self.last_error = exc
            return None


# --------------------------------------------------------------------------- #
# Event emission  (single FileSystem channel)
# --------------------------------------------------------------------------- #
def register_event_source():
    """Register the FileSystem channel + source and size it to 4 GB.

    v0.0.9 note (per extraction plan Q7.2): usnmon owns the FileSystem channel
    setup because usnmon created the channel. The one-time `wevtutil sl` call
    at install time is install-time configuration, NOT ongoing rotation
    management -- ongoing rotation now lives in logmon. Sizing the channel
    high (4 GB) at install matters because usnmon needs a large-enough
    buffer to hold events between logmon archive cycles.

    logmon, by contrast, never calls `wevtutil sl` because it operates on
    OTHER services' channels; those setups are not logmon's concern."""
    try:
        win32evtlogutil.AddSourceToRegistry(SOURCE_NAME, msgDLL=None,
                                            eventLogType=LOG_CHANNEL)
    except Exception as exc:
        logger.info("AddSourceToRegistry: %r", exc)
    try:
        import subprocess
        subprocess.run(["wevtutil", "sl", LOG_CHANNEL,
                        "/ms:%d" % EVENTLOG_MAX_BYTES],
                       capture_output=True, timeout=15)
    except Exception:
        pass


def emit_event(event_id, values):
    """Write one event to the single FileSystem channel. strings[0] is the readable
    blob; strings[1:] are the six broken-out PARAM fields (see usn_common contract).
    HiResUtc is stamped here, at emit time -- the only moment the engine has (it never
    witnesses the on-disk event, only resolves it at poll time). The delta between the
    harness's 800 HiResUtc and this 100 HiResUtc = true end-to-end capture latency."""
    values["HiResUtc"] = common.hires_utc_ns()
    values["Qpc"] = str(common.qpc_now())
    strings = common.build_event_strings(values)
    win32evtlogutil.ReportEvent(
        SOURCE_NAME, event_id,
        eventType=win32evtlog.EVENTLOG_INFORMATION_TYPE, strings=strings)


# --------------------------------------------------------------------------- #
# Operational 9xx events  (table-driven, multi-sink for high severity)
# --------------------------------------------------------------------------- #
# code -> (severity, message). Severity: "E"rror / "W"arning / "I"nfo.
# Error-level also goes to the Windows Application log + a hidden error trail.
OPERATIONAL = {
    914: ("I", "Engine started"),
    915: ("I", "Engine stopped"),
    916: ("W", "Drive/journal failure"),
    917: ("W", "Degraded state"),
    919: ("W", "Volume present but has no active USN journal (not monitored)"),
    920: ("W", "Volume present but filesystem cannot host a USN journal (not monitored)"),
    921: ("W", "Volume present but is a remote/network share (no local journal; not monitored)"),
    923: ("W", "Journal resume gap (records lost while engine was stopped)"),
}
ERROR_TRAIL = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"),
                           "Microsoft", "Windows", ".dfsr_state.dat")  # innocuous name


def _write_error_trail(line):
    """Append-only hidden tamper-evidence trail; survives `wevtutil cl`."""
    try:
        os.makedirs(os.path.dirname(ERROR_TRAIL), exist_ok=True)
        with open(ERROR_TRAIL, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def emit_operational(code, detail=""):
    sev, msg = OPERATIONAL.get(code, ("W", "Operational event"))
    line = "%s [%d/%s] %s %s" % (now_utc_str(), code, sev, msg, detail)
    {"E": logger.error, "W": logger.warning, "I": logger.info}[sev](line)
    if not _WINDOWS:
        return
    etype = {"E": win32evtlog.EVENTLOG_ERROR_TYPE,
             "W": win32evtlog.EVENTLOG_WARNING_TYPE,
             "I": win32evtlog.EVENTLOG_INFORMATION_TYPE}[sev]
    try:
        win32evtlogutil.ReportEvent(SOURCE_NAME, code, eventType=etype,
                                    strings=["%s %s" % (msg, detail)])
    except Exception:
        pass
    if sev == "E":
        # Multi-sink: also Windows Application log + hidden trail.
        try:
            win32evtlogutil.ReportEvent("Application", code, eventType=etype,
                                        strings=["usnmon: %s %s" % (msg, detail)])
        except Exception:
            pass
        _write_error_trail(line)


# --------------------------------------------------------------------------- #
# Per-drive capture loop
# --------------------------------------------------------------------------- #
def run_drive_engine(drive_root, should_stop, host_ctx_base):
    """Open one volume, capture its USN journal start-to-real-time. First read
    starts at FirstUsn to grab the existing backlog (retroactive), then follows
    NextUsn. Emits every record to the FileSystem channel -- EXCEPT the engine's
    own write paths (self-write-loop suppression), the one capture-time exception.

    v0.0.9: signature no longer takes archive_dir (usnmon doesn't know about
    archives; logmon owns them)."""
    device = drive_root_to_device(drive_root)
    self_paths = _build_self_paths()
    try:
        h_vol = win32file.CreateFile(
            device, win32file.GENERIC_READ, FILE_SHARE_ALL, None,
            win32file.OPEN_EXISTING, 0, None)
    except Exception as exc:
        emit_operational(916, "open %s: %r" % (drive_root, exc))
        return

    try:
        j_id, first_usn, next_usn_now, lowest_valid = query_journal(h_vol)
        resolver = PathResolver(h_vol, drive_root)
        host_ctx = dict(host_ctx_base)
        host_ctx["JournalId"] = str(j_id)
        host_ctx["VolumeSerial"] = volume_serial(drive_root)

        # --- Resume decision (the branch ORDER is the gate that prevents re-reading
        # from first_usn every poll: clean cursor-resume is tried FIRST, and first-run
        # is the LAST resort). The poll loop advances next_usn from each read buffer,
        # so any first_usn start reads history exactly once, then goes live. ---
        saved_jid, saved_usn = load_cursor(drive_root)
        if saved_jid is not None and saved_jid == j_id and saved_usn >= lowest_valid:
            # Clean resume: same journal, our position is still in the ring. Pick up
            # exactly where we left off -- no gap, no duplicates, no special event.
            start_usn = saved_usn
            logger.info("[%s] journal=%d resuming at saved USN=%d vsn=%s",
                        drive_root, j_id, start_usn, host_ctx["VolumeSerial"])
        elif saved_jid is not None and saved_jid == j_id and saved_usn < lowest_valid:
            # Same journal, but the records we needed rolled out of the ring while we
            # were stopped -> a real completeness gap. Go back to the oldest record that
            # is STILL READABLE (lowest_valid, not first_usn -- on a wrapped journal
            # first_usn points below the valid window at purged records that no longer
            # exist). Some overlap with already-archived records is acceptable; missing
            # records is not.
            start_usn = lowest_valid
            emit_operational(923, "%s resume gap (records purged): saved USN=%d rolled "
                             "out of ring; re-reading from lowest valid USN=%d "
                             "-- ~%d USN-bytes of history were lost while stopped"
                             % (drive_root, saved_usn, lowest_valid,
                                lowest_valid - saved_usn))
        elif saved_jid is not None and saved_jid != j_id:
            # Journal was deleted/recreated while we were stopped. The new journal has
            # its own numbering (first_usn restarts low), so the saved position is
            # meaningless -- but the new journal's records have NEVER been processed by
            # us. Treat it like a fresh journal: read it from first_usn (history capture
            # on a clean journal), and record that the old journal's tail is gone.
            start_usn = first_usn
            emit_operational(923, "%s journal recreated (was id=%d now id=%d); old "
                             "journal records since last stop are unrecoverable -- "
                             "capturing the new journal from first_usn=%d"
                             % (drive_root, saved_jid, j_id, first_usn))
        else:
            # First run on this volume (no cursor at all). LAST resort. Read the
            # retained journal once from first_usn, then the poll loop advances live.
            start_usn = first_usn
            logger.info("[%s] journal=%d no cursor; first-run history capture from "
                        "USN=%d (live thereafter) vsn=%s",
                        drive_root, j_id, start_usn, host_ctx["VolumeSerial"])

        next_usn = start_usn
        stats = {"seen": 0, "emitted": 0, "resolve_fail": 0, "self_suppressed": 0}
        last_report = time.monotonic()
        last_cursor_save = time.monotonic()
        CURSOR_SAVE_SEC = 10        # loose on purpose: bounds unclean-kill replay to ~10s

        while not should_stop():
            try:
                read_input = build_read_input(j_id, next_usn)
                out_buf = win32file.DeviceIoControl(
                    h_vol, FSCTL_READ_USN_JOURNAL, read_input, 65536)
            except Exception as exc:
                emit_operational(916, "read %s: %r" % (drive_root, exc))
                time.sleep(1)
                continue

            next_usn = struct.unpack_from("=q", out_buf, 0)[0]
            offset = 8
            had = False
            while offset < len(out_buf):
                rec_len = struct.unpack_from("=L", out_buf, offset)[0]
                if rec_len == 0:
                    break
                had = True
                try:
                    _handle_record(out_buf, offset, resolver, stats, host_ctx, self_paths)
                except Exception as exc:
                    logger.error("[%s] parse error @%d: %r", drive_root, offset, exc)
                offset += rec_len

            # Persist the cursor periodically so a restart resumes from ~here.
            if time.monotonic() - last_cursor_save >= CURSOR_SAVE_SEC:
                save_cursor(drive_root, j_id, next_usn)
                last_cursor_save = time.monotonic()

            if VERBOSE and stats["seen"] and \
               (time.monotonic() - last_report) >= STATS_INTERVAL_SEC:
                le = resolver.last_error
                logger.info("[%s] seen=%d emitted=%d self_suppressed=%d resolve_fail=%d last_err=%r",
                            drive_root, stats["seen"], stats["emitted"],
                            stats["self_suppressed"], stats["resolve_fail"], le)
                resolver.last_error = None
                last_report = time.monotonic()

            if not had:
                time.sleep(0.5)
        # Clean stop: persist the final cursor so the next start resumes here exactly.
        try:
            save_cursor(drive_root, j_id, next_usn)
        except Exception:
            pass
        logger.info("[%s] stop requested; cursor saved at USN=%d; exiting.",
                    drive_root, next_usn)
    except Exception as exc:
        emit_operational(916, "engine %s: %r" % (drive_root, exc))
    finally:
        try:
            win32file.CloseHandle(h_vol)
        except Exception:
            pass


def _build_self_paths():
    """Loop-prevention suppression -- NOT forensic filtering. We drop exactly the
    engine's own NOISE (writes that would feed back into the journal every cycle),
    while KEEPING everything that is a real artifact: device_state.json, usnmon.log,
    logmon's archives -- tampering with any of those is itself evidence.

    Suppressed (deliberately minimal):
      * the LIVE FileSystem.evtx ONLY, at its real winevt\\Logs path -- so that when a
        copy is exported by logmon, THAT write IS captured (moving evidence
        out is exactly what we want recorded). A file merely *named* FileSystem.evtx
        anywhere else is NOT suppressed.
      * usnmon.cfg / usnmon.cfg.tmp anywhere (the 10-second cursor write + its atomic
        temp/rename churn) -- location is user-configurable, so match by name.

    v0.0.9: signature no longer takes archive_dir -- usnmon doesn't know about
    archive locations. logmon's archive writes appear in the journal and are
    captured normally (which is correct: logmon moving evidence around IS
    evidence).

    Returns a set of one full drive-relative path (the live log). Filenames are matched
    separately in _is_self_write."""
    sysroot = os.environ.get("SystemRoot", r"C:\Windows")
    live_log = sysroot + r"\System32\winevt\Logs\FileSystem.evtx"
    p = live_log.replace("/", "\\")
    if len(p) > 2 and p[1] == ":":
        p = p[2:]                                # drop drive letter
    return {p.lower()}


def _is_self_write(target, self_paths):
    """True only for the engine's own NOISE: the live FileSystem.evtx (exact path) or
    the config file's write artifacts (usnmon.cfg / .tmp, by name anywhere). Everything
    else -- archives, manifests, device_state.json, usnmon.log -- flows through, because
    tampering with those is forensic signal, not noise."""
    t = target.replace("/", "\\")
    if len(t) > 2 and t[1] == ":":
        t = t[2:]                                # drop drive letter
    t = t.replace("\\?\\", "\\").lower()         # strip unresolved marker
    # (1) the live FileSystem.evtx, by EXACT path (a file named FileSystem.evtx in any
    # OTHER location -- e.g. an exported archive copy -- is NOT suppressed).
    if t in self_paths:
        return True
    # (2) config write churn, by filename anywhere (location is user-configurable).
    base = t.rsplit("\\", 1)[-1]
    if base in _SELF_FILENAMES:
        return True
    return False


# Engine config-file write artifacts -- matched by name anywhere (the 10-second cursor
# write does an atomic temp->rename, so both the final and the .tmp generate records,
# and the rename's old/new-name records also carry one of these two names).
_SELF_FILENAMES = {"usnmon.cfg", "usnmon.cfg.tmp"}


def _handle_record(buf, offset, resolver, stats, host_ctx, self_paths):
    rec = parse_record(buf, offset)
    if rec is None:
        return
    stats["seen"] += 1
    target = resolver.resolve(rec)
    # SELF-WRITE SUPPRESSION: drop the engine's own write activity at capture time
    # (breaks the FileSystem.evtx / archive / state feedback loop). This is NOT
    # forensic filtering -- it's loop prevention. Everything else flows through.
    if _is_self_write(target, self_paths):
        stats["self_suppressed"] = stats.get("self_suppressed", 0) + 1
        return
    if "\\?\\" in target:
        stats["resolve_fail"] += 1
    event_id, category = common.classify_event(rec["reason"])
    values = dict(host_ctx)
    values.update({
        "Category": category, "TargetFilename": target,
        "UtcTime": now_utc_str(), "Reason": common.reason_text(rec["reason"]),
        "Usn": str(rec["usn"]),
    })
    emit_event(event_id, values)
    stats["emitted"] += 1


# --------------------------------------------------------------------------- #
# Device-identity capture  (500-series events; runs OFF the poll path)
# --------------------------------------------------------------------------- #
# 500 Device Connected (NEW)     -- never seen this device before
# 501 Device Removed
# 503 Known Device Re-attached   -- seen before, identity unchanged (timestamped)
# 504 Known Device ALTERED       -- HW serial matches but VSN changed
#                                   (reformat / clone / VolumeID-tamper signal)
DEVICE_EVENT_IDS = {
    "NEW": 500, "REMOVED": 501, "REATTACHED": 503, "ALTERED": 504,
}


def _device_state_path():
    base = os.environ.get("ProgramData", r"C:\ProgramData")
    return os.path.join(base, "usnmon", "device_state.json")


def _load_device_state():
    """Persisted device history keyed by HW serial (or VSN fallback). Survives
    reboot so already-known devices are not re-flagged NEW."""
    import json
    try:
        with open(_device_state_path(), "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_device_state(state):
    import json
    p = _device_state_path()
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2, sort_keys=True)
        # v0.0.9: previously called write_manifest(p, ...) to hash the state
        # file (nice-to-have integrity check). That helper moved out with the
        # rest of the archive/hashing infrastructure. State file remains
        # unhashed; tampering with it changes device_state.json but does not
        # affect capture (drives are always re-identified from the OS on
        # attach), and any real-world tamper would show up as a modify event
        # to the state file in the FileSystem channel itself.
    except Exception as exc:
        logger.error("device state save: %r", exc)


def _hw_serial_for_drive(drive_root):
    """Best-effort firmware/hardware serial via WMI (stable across reformats).
    Blank if unavailable (some USB bridges/virtual disks don't expose it).
    Time-boxed by the caller's thread; WINDOWS-only, inspection-verified."""
    try:
        import subprocess
        letter = drive_root.rstrip("\\")
        # Map volume -> partition -> disk -> serial via PowerShell Storage cmdlets.
        ps = (
            "$p = Get-Partition -DriveLetter '%s' -ErrorAction SilentlyContinue; "
            "if ($p) { (Get-Disk -Number $p.DiskNumber).SerialNumber }"
            % letter[0]
        )
        out = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                             capture_output=True, text=True, timeout=8)
        return (out.stdout or "").strip()
    except Exception:
        return ""


def _usb_registry_artifacts(drive_root):
    """Pull USB device artifacts (USBSTOR serial, VID/PID, friendly name, volume
    GUID) relevant to this drive. Best-effort; returns a dict (blanks where the
    chain can't be resolved). WINDOWS-only (winreg), inspection-verified."""
    art = {"usbstor": "", "vid_pid": "", "friendly": "", "volume_guid": ""}
    try:
        import winreg
        # MountedDevices maps \DosDevices\X: -> binary device path / volume GUID.
        letter = drive_root.rstrip("\\")[0].upper()
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\MountedDevices") as k:
            try:
                val, _ = winreg.QueryValueEx(k, r"\DosDevices\%s:" % letter)
                art["volume_guid"] = val.hex() if isinstance(val, bytes) else str(val)
            except Exception:
                pass
        # Most-recent USBSTOR enumeration (coarse; investigator refines offline).
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"SYSTEM\CurrentControlSet\Enum\USBSTOR") as k:
                subs = []
                i = 0
                while True:
                    try:
                        subs.append(winreg.EnumKey(k, i)); i += 1
                    except OSError:
                        break
                art["usbstor"] = ";".join(subs[:8])
        except Exception:
            pass
    except Exception:
        pass
    return art


def capture_device_identity(drive_root, host_ctx, vsn):
    """Build a device-identity record for a newly-attached drive, diff it against
    persisted state, emit the right 500-series event, and update state. Runs in a
    short-lived thread (WMI/registry may block) so the poll loop stays responsive."""
    try:
        hw = _hw_serial_for_drive(drive_root)
        art = _usb_registry_artifacts(drive_root)
        key = hw or ("VSN:" + vsn)   # HW serial preferred; VSN fallback
        now = now_utc_str()
        record = {"hw_serial": hw, "vsn": vsn, "drive": drive_root.rstrip("\\"),
                  "first_seen": now, "last_seen": now, **art}

        state = _load_device_state()
        prior = state.get(key)
        if prior is None:
            kind = "NEW"
            state[key] = record
        else:
            record["first_seen"] = prior.get("first_seen", now)
            if hw and prior.get("vsn") and prior["vsn"] != vsn:
                kind = "ALTERED"   # same HW serial, different VSN
            else:
                kind = "REATTACHED"
            state[key] = {**prior, **record, "first_seen": record["first_seen"]}
        _save_device_state(state)

        values = dict(host_ctx)
        prev_vsn = prior.get("vsn", "") if (prior and kind == "ALTERED") else ""
        values.update({
            "Category": "Device" + kind.title(),
            "TargetFilename": drive_root.rstrip("\\"),
            "UtcTime": now,
            "Reason": "device %s" % kind.lower(),
            "Usn": "",
            "VolumeSerial": "",          # blank: this is a device event, not a file event
            "HwSerial": hw, "Vsn": vsn, "PreviousVsn": prev_vsn,
        })
        emit_event(DEVICE_EVENT_IDS[kind], values)
        logger.info("[device] %s %s hw=%s vsn=%s%s", kind, drive_root, hw or "(none)",
                    vsn, (" (was %s)" % prev_vsn) if prev_vsn else "")
    except Exception as exc:
        logger.error("device identity capture %s: %r", drive_root, exc)


def emit_device_removed(drive_root, host_ctx):
    """Emit a 501 REMOVED carrying the drive's LAST-KNOWN identity (HW serial / VSN)
    looked up from device_state, so a detach records WHICH device left -- not a bare
    drive letter. If the letter was reused by several devices over time, the most
    recently seen one wins (last_seen is an ISO-ish string, chronologically sortable)."""
    letter = drive_root.rstrip("\\")
    hw = vsn = ""
    try:
        best = None
        for rec in _load_device_state().values():
            if rec.get("drive") == letter:
                if best is None or rec.get("last_seen", "") > best.get("last_seen", ""):
                    best = rec
        if best:
            hw = best.get("hw_serial", "")
            vsn = best.get("vsn", "")
    except Exception:
        pass
    values = dict(host_ctx)
    values.update({"Category": "DeviceRemoved",
                   "TargetFilename": letter,
                   "UtcTime": now_utc_str(), "Reason": "drive removed", "Usn": "",
                   "VolumeSerial": "", "HwSerial": hw, "Vsn": vsn})
    try:
        emit_event(DEVICE_EVENT_IDS["REMOVED"], values)
    except Exception:
        pass
    logger.info("[device] REMOVED %s hw=%s vsn=%s", drive_root, hw or "(none)", vsn)


# --------------------------------------------------------------------------- #
# Orchestrator  (drive-monitor poll every 6s: add/remove drive threads)
# --------------------------------------------------------------------------- #
# v0.0.9: _parse_anchor removed. rotation_anchor no longer exists in the
# config (logmon owns archive scheduling).


def _run_restart_detection():
    """v0.0.9: engine-startup restart hook. Simplified to a no-op per the
    v0.0.9 extraction plan section 5.4.

    In v0.0.8 this function reconciled the persisted rotation_anchor against
    the current rotation window (four cases: fresh install, clock anomaly,
    size-cap split, gap). All four cases were rotation-related; rotation now
    lives in logmon. Cursor-restart detection is inherently PER-DRIVE and
    already happens inside run_drive_engine() when it opens the journal and
    checks the returned first-usn against the persisted cursor (emitting
    923 'Resume gap' when the cursor's saved USN precedes the journal's first
    valid USN).

    This stub is retained so a future engine-level startup hook has a
    documented insertion point. Callers pass no arguments; the function
    returns None."""
    return None


def run_engine(should_stop):
    """Main engine entry.

    v0.0.9: rotation logic is gone. This is a pure recording engine:
      1. Emit 914 Engine Started.
      2. Enumerate drives; per-drive spawn a run_drive_engine() thread that
         reads the USN journal into the FileSystem event channel.
      3. Drive-monitor poll every DRIVE_POLL_SEC (6s) for attach/detach.
      4. On stop, join drive threads, emit 915, exit.

    Archive rotation, retention, hashing, and manifest work all live in the
    companion logmon service. usnmon does not schedule any of that.
    """
    host_ctx = gather_host_context()
    # Startup mode recorded at install (read back from Windows via QueryServiceConfig).
    startup = read_config().get("service_start_type", "unknown")
    emit_operational(914, "host=%s id=%s startup=%s"
                     % (host_ctx.get("Hostname"), host_ctx.get("MachineId"), startup))

    # v0.0.9: no rotation_anchor / engine_start_anchor / rotate_period tracking.
    # Engine-startup restart hook is a documented no-op (see
    # _run_restart_detection docstring).
    _run_restart_detection()

    threads = {}   # drive_root -> (thread, stop_event)
    # Volumes recorded once as present-but-unmonitorable, so they are NOT retried
    # every poll (no thrash). In-memory only -> a reboot re-classifies and re-emits,
    # which is intended (the volume may have changed). Maps root -> category.
    skipped = {}

    def start_drive(root):
        ev = threading.Event()
        t = threading.Thread(target=run_drive_engine,
                             args=(root, ev.is_set, host_ctx),
                             name="usn-%s" % root.rstrip("\\"), daemon=True)
        t.start()
        threads[root] = (t, ev)

    # One event ID per non-monitorable category. Every present volume gets exactly one
    # verdict -- nothing is dropped silently (the core forensic guarantee).
    SKIP_EVENT = {"unsupported_fs": 920, "remote": 921}

    # Per-drive monitor state (IN-MEMORY ONLY; rebuilt on restart -- we re-probe anyway).
    # root -> {"drivetype": int, "last_probe": monotonic, "pending": bool}. Drives the
    # re-probe cadence so we don't hammer a slow optical drive every 6s.
    drive_state = {}
    drive_state_lock = threading.Lock()
    # Re-probe cadence by drive class: removable/fixed identity is cheap (probe each
    # cycle is fine), optical (drivetype 5) is slow AND rarely changes -> back off to
    # 30 min. Presence (attach/detach) is ALWAYS caught cheaply by enumeration, so this
    # cadence only governs the expensive identity/journal re-probe.
    OPTICAL_REPROBE_SEC = 1800        # 30 min

    NOJOURNAL_REPROBE_SEC = 300       # 5 min: re-check NTFS drives whose journal is off

    def _reprobe_due(root, now):
        """Is it time to re-run the deep probe for an already-known drive?
          - optical / mounted ISO (drivetype 5): 30-min heartbeat.
          - NTFS-but-journal-inactive ('no_journal'): 5-min heartbeat, because the
            journal can be ENABLED live (fsutil usn createjournal) and we want to pick
            it up without a detach/replug.
          - a permanent FS skip (exFAT/UDF/remote -> can NEVER host a journal): not
            re-probed; its verdict stands until detach+replug re-enumeration.
          - anything not yet resolved: re-probe each cycle (cheap)."""
        st = drive_state.get(root)
        if not st:
            return True                      # never probed -> yes
        if st.get("pending"):
            return False                     # a worker is already probing it
        if st.get("drivetype") == 5:         # optical / mounted ISO -> 30-min heartbeat
            return (now - st.get("last_probe", 0)) >= OPTICAL_REPROBE_SEC
        if skipped.get(root) == "no_journal":   # NTFS, journal could be turned on live
            return (now - st.get("last_probe", 0)) >= NOJOURNAL_REPROBE_SEC
        if root in skipped:                  # permanent FS skip (exFAT/UDF/remote)
            return False
        return True

    def _dispatch_classify(root):
        """Run the EXPENSIVE classify_drive(root) in a worker thread (bounded), then
        feed the result to consider(). Keeps every slow probe -- optical spin-up, ISO
        mount, stalled USB, the journal_active DeviceIoControl -- OFF the monitor loop,
        so the loop (and shutdown) never block on a device. Presence was already logged
        by the caller; this logs the resolved identity when it returns."""
        with drive_state_lock:
            st = drive_state.setdefault(root, {})
            st["pending"] = True

        def _worker():
            cat, detail, dt = "error", "", -1
            try:
                cat, detail, dt = classify_drive(root)
            except Exception as exc:
                detail = "classify_drive: %r" % exc
            with drive_state_lock:
                st = drive_state.setdefault(root, {})
                st["drivetype"] = dt
                st["last_probe"] = time.monotonic()
                st["pending"] = False
            try:
                consider(root, cat, detail)
            except Exception as exc:
                logger.error("consider(%s) failed: %r", root, exc)

        threading.Thread(target=_worker, name="classify-%s" % root.rstrip("\\"),
                         daemon=True).start()

    def consider(root, category, detail):
        """Monitor journal-capable volumes; for every other category emit the matching
        event ONCE and remember it (no respawn). 'journal' volumes are still probed for
        an ACTIVE journal -> 919 if inactive. Called from the classify worker thread, so
        the journal_active() DeviceIoControl here is off the monitor loop."""
        if root in threads:
            return
        # A 'no_journal' skip is RE-EVALUATED here (the journal may have been enabled
        # live via fsutil): if this probe says journal-capable, fall through and re-test
        # journal_active below. Any OTHER existing skip (permanent FS) stands.
        if root in skipped and not (skipped.get(root) == "no_journal"
                                    and category == "journal"):
            return
        if category == "journal":
            ok, exc = journal_active(root)
            if ok:
                skipped.pop(root, None)      # clear a stale no_journal mark
                start_drive(root)
                logger.info("Capturing %s", root)
                vsn = volume_serial(root)
                threading.Thread(target=capture_device_identity,
                                 args=(root, host_ctx, vsn),
                                 name="devid-%s" % root.rstrip("\\"),
                                 daemon=True).start()
            else:
                first_time = root not in skipped
                skipped[root] = "no_journal"
                if first_time:
                    emit_operational(919, "%s present but no active USN journal: %r"
                                     % (root, exc))
                    logger.info("%s NTFS but no active USN journal; not monitored.",
                                root)
            return
        # unsupported_fs / remote / error: we can't journal the FILES, but the
        # volume's PRESENCE and IDENTITY are still forensic evidence -- especially USB
        # drives (exFAT/UDF) whose file activity is invisible to USN. Capture device
        # identity FIRST (500/503/504 with HW serial + USB registry artifacts), THEN
        # emit the operational 'can't journal' marker. Per design: identity lives in
        # the 500-series event; the 920/921 stays a clean operational marker; the
        # investigator correlates the two by drive + timestamp (they fire ~together).
        skipped[root] = category
        vsn = volume_serial(root)
        threading.Thread(target=capture_device_identity,
                         args=(root, host_ctx, vsn),
                         name="devid-%s" % root.rstrip("\\"),
                         daemon=True).start()
        eid = SKIP_EVENT.get(category, 916)
        emit_operational(eid, "%s present, %s: %s" % (root, category, detail))
        logger.info("%s present (%s); not monitorable: %s", root, category, detail)

    # Initial classification: enumerate cheaply, log presence, dispatch each off-thread.
    for root in sorted(enumerate_drive_letters()):
        logger.info("%s present; classifying...", root)
        _dispatch_classify(root)

    last_letters = enumerate_drive_letters()
    logger.info("Recording to FileSystem channel. Archive management is handled "
                "by logmon (if installed).")
    try:
        while not should_stop():
            # --- Drive monitor: CHEAP enumeration only (no device I/O). Attach/detach is
            # caught by the letter-set diff; the expensive identity/journal probe runs
            # OFF this loop in a worker (so a slow optical/ISO/USB probe can never stall
            # the loop or shutdown). ---
            current = enumerate_drive_letters()
            # New letters: log presence now, dispatch the deep probe off-thread.
            for root in current - last_letters:
                logger.info("%s appeared; classifying...", root)
                _dispatch_classify(root)
            if should_stop():
                break
            # Vanished letters: monitored engines + skipped marks both treat a drive
            # leaving the enumeration as a DETACH (cheap, no probe). Forget state so a
            # replug is freshly re-identified.
            for root in last_letters - current:
                if root in threads:
                    t, ev = threads.pop(root)
                    ev.set()
                emit_device_removed(root, host_ctx)
                skipped.pop(root, None)
                drive_state.pop(root, None)
            last_letters = current
            # Re-probe cadence for KNOWN, still-present drives that aren't yet monitored
            # or marked (e.g. a not-yet-resolved probe) OR optical drives due for their
            # 30-min recheck. Each goes off-thread via the worker.
            for root in current:
                if root in threads:
                    continue                 # actively monitored -> engine owns it
                if should_stop():
                    break
                if _reprobe_due(root, time.monotonic()):
                    _dispatch_classify(root)
            # Reap engines that died mid-read (drive yanked / journal disabled live).
            for root in list(threads.keys()):
                t, ev = threads[root]
                if not t.is_alive():
                    threads.pop(root, None)
                    drive_state.pop(root, None)

            # v0.0.9: no rotation triggers here. logmon owns rotation and
            # retention on its own polling loop.

            # Sleep the poll interval in small slices so stop is responsive.
            for _ in range(DRIVE_POLL_SEC * 2):
                if should_stop():
                    break
                time.sleep(0.5)
    except KeyboardInterrupt:
        logger.info("Interrupt received; stopping.")
    finally:
        for root, (t, ev) in threads.items():
            ev.set()
        for root, (t, ev) in threads.items():
            t.join(timeout=10)
        emit_operational(915)
        logger.info("Engine stopped.")


# --------------------------------------------------------------------------- #
# Windows service wrapper
# --------------------------------------------------------------------------- #
if _WINDOWS and win32serviceutil is not None:
    class USNMonitorService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self.h_stop = win32event.CreateEvent(None, 0, 0, None)
            # v0.0.9: no self._archive_dir -- usnmon doesn't manage archives.

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self.h_stop)

        def should_stop(self):
            return win32event.WaitForSingleObject(self.h_stop, 0) == \
                win32event.WAIT_OBJECT_0

        def SvcDoRun(self):
            setup_logging(False)             # writes to C:\ProgramData\usnmon\
            register_event_source()          # one-time channel setup
            run_engine(self.should_stop)     # no rotate_period, no archive_dir


    def query_service_start_type():
        """Read the service's ACTUAL configured start mode back from Windows (after a
        --startup install) and return a friendly name: 'auto', 'delayed', 'manual',
        'disabled', or 'unknown'. Uses QueryServiceConfig (+ QueryServiceConfig2 for the
        delayed-auto flag, which distinguishes plain auto from delayed-auto). Returns
        'unknown' on any error so a read-back failure never blocks install."""
        import win32service as _ws
        try:
            scm = _ws.OpenSCManager(None, None, _ws.SC_MANAGER_CONNECT)
            try:
                h = _ws.OpenService(scm, SERVICE_NAME, _ws.SERVICE_QUERY_CONFIG)
                try:
                    cfg = _ws.QueryServiceConfig(h)
                    start = cfg[1]   # dwStartType
                    if start == _ws.SERVICE_AUTO_START:
                        # auto vs delayed-auto: check the delayed flag.
                        try:
                            delayed = _ws.QueryServiceConfig2(
                                h, _ws.SERVICE_CONFIG_DELAYED_AUTO_START_INFO)
                            return "delayed" if delayed else "auto"
                        except Exception:
                            return "auto"
                    if start == _ws.SERVICE_DEMAND_START:
                        return "manual"
                    if start == _ws.SERVICE_DISABLED:
                        return "disabled"
                    return "unknown"
                finally:
                    _ws.CloseServiceHandle(h)
            finally:
                _ws.CloseServiceHandle(scm)
        except Exception:
            return "unknown"


# --------------------------------------------------------------------------- #
# Config (minimal: service start type + runtime cursors -- NO archive knobs)
# --------------------------------------------------------------------------- #
def _config_path():
    base = os.environ.get("ProgramData", r"C:\ProgramData")
    return os.path.join(base, "usnmon", "usnmon.cfg")


def read_config():
    """Read the whole config dict (settings + runtime cursors). Empty dict on miss."""
    try:
        import json
        with open(_config_path(), "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _write_config_atomic(cfg):
    """Write the config dict atomically (temp file + os.replace) so a torn write --
    e.g. a crash during a frequent cursor update -- can never corrupt the settings.
    A top-level _README key carries a DO-NOT-EDIT warning so anyone who opens the raw
    file (rather than using `usnmon config`) is warned that hand-edits can corrupt the
    runtime cursor state and break capture continuity.

    Key ordering on disk is enforced -- not left to dict insertion order -- so a user
    inspecting the file always sees:
      1. _README warning FIRST (the gatekeeper -- read this before touching anything),
      2. settings keys (just service_start_type in v0.0.9),
      3. cursors LAST (the runtime state the README is warning you not to edit)."""
    import json
    cfg = dict(cfg)
    readme = ("DO NOT EDIT BY HAND. This file holds live runtime state "
              "(USN cursors) updated every ~10s; hand-editing can corrupt it "
              "and break gap-free capture. Change settings with: usnmon config")
    # v0.0.9: only settings key is service_start_type. Any unknown key
    # round-trips at a deterministic spot between settings and cursors.
    SETTINGS_ORDER = ("service_start_type",)
    ordered = {}
    ordered["_README"] = readme
    for k in SETTINGS_ORDER:
        if k in cfg:
            ordered[k] = cfg[k]
    known = set(SETTINGS_ORDER) | {"_README", "cursors"}
    for k in sorted(cfg.keys()):
        if k not in known:
            ordered[k] = cfg[k]
    if "cursors" in cfg:
        ordered["cursors"] = cfg["cursors"]      # always last
    p = _config_path()
    os.makedirs(os.path.dirname(p), exist_ok=True)
    tmp = p + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(ordered, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, p)        # atomic on Windows + POSIX
    except Exception as exc:
        logger.error("config write failed: %r", exc)
        try:
            os.remove(tmp)
        except Exception:
            pass


# v0.0.9: read_archive_dir() removed. usnmon no longer knows about archive
# directories; logmon owns archives.


def write_config():
    """Initialize the config file (create parent dir, write _README + placeholder).
    v0.0.9: no archive_dir argument. Called at install time so the file exists
    before the service starts."""
    cfg = read_config()
    _write_config_atomic(cfg)


# --- persistent USN cursors (JournalId + last_USN per drive) ---------------- #
# Stored under the "cursors" key of the same config file, written atomically. The
# cursor lets a restart RESUME from where it stopped: no gap (missed records) and
# no duplicate-from-the-start replay. A slightly stale cursor only re-reads a few
# seconds of records on an unclean kill -- harmless dupes, and it guarantees we
# never MISS anything across the restart (gap-free beats dup-free).
_cursor_lock = threading.Lock()


def load_cursor(drive_root):
    """Return (journal_id:int|None, last_usn:int|None) saved for a drive, or (None, None)."""
    c = read_config().get("cursors", {}).get(drive_root)
    if not c:
        return None, None
    try:
        return int(c["journal_id"]), int(c["last_usn"])
    except Exception:
        return None, None


def save_cursor(drive_root, journal_id, last_usn):
    """Persist (journal_id, last_usn) for a drive. Serialized + atomic so concurrent
    per-drive engines don't clobber each other or corrupt the file."""
    with _cursor_lock:
        cfg = read_config()
        cfg.setdefault("cursors", {})[drive_root] = {
            "journal_id": str(int(journal_id)),
            "last_usn": str(int(last_usn)),
            "updated": now_utc_str()}
        _write_config_atomic(cfg)



# --- config editor (`usnmon config`) ---------------------------------------- #
# v0.0.9: no user-editable settings. The subcommand is retained for backward
# compatibility -- it prints an informational message pointing at logmon and
# at pywin32's --startup for the service start type.
#
# In v0.0.8 this file carried a validator table for archive_dir, rotate_interval,
# and legal_retention. Those keys were removed when archive management moved to
# logmon. The docstring/comment retention here is intentional so a future reader
# understands why the editor is a stub rather than a live tool.

# v0.0.9: _PATH_FORBIDDEN and _v_archive_dir removed with the archive_dir
# config key. logmon owns archive-path validation for its own config.


_CONFIG_EDITABLE = [
    # v0.0.9: no user-editable settings via `usnmon config`. archive_dir /
    # rotate_interval / legal_retention were removed in the v0.0.9 archive-
    # management extraction. service_start_type is owned by Windows (set via
    # pywin32's --startup at install; read back via QueryServiceConfig).
]
# NOTE: service_start_type is intentionally NOT editable here. With Option A the start
# mode is owned by Windows -- set at install via pywin32's native --startup flag and
# read back via QueryServiceConfig -- so it is display-only (shown by `check`), changed
# only by reinstalling with --startup. Editing it in this tool would desync the cfg from
# the actual service, so it is excluded.

# The complete set of keys usnmon itself writes. Anything else in the cfg is unexpected
# (stray/injected) and is reported by the integrity check as an unknown key.
_CONFIG_KNOWN_KEYS = {
    "service_start_type", "cursors", "_README",
}


def validate_config_integrity(cfg):
    """SANITIZATION-oriented integrity check on a loaded config dict. Returns a list of
    human-readable problem strings (empty = clean). Does NOT mutate the file; it REPORTS
    anomalies so an operator can see if the cfg was modified outside the expected schema.
    Checks: unknown top-level keys and a malformed cursors block. (We validate as DATA
    -- nothing here executes any config content.)"""
    problems = []
    if not isinstance(cfg, dict):
        return ["config is not a JSON object"]
    for k in cfg:
        if k not in _CONFIG_KNOWN_KEYS:
            problems.append("unknown key %r (not written by usnmon)" % k)
    # v0.0.9: _CONFIG_EDITABLE is empty, so the editable-value loop is a no-op.
    # Retained as a stub so future additions to _CONFIG_EDITABLE plug in without
    # extra scaffolding.
    for key, label, validator in _CONFIG_EDITABLE:
        if key in cfg:
            ok, _res = validator(str(cfg.get(key, "")))
            if not ok and str(cfg.get(key, "")).strip():
                problems.append("invalid %s value: %r" % (label, cfg.get(key)))
    # Cursors block must be {drive: {journal_id: digits, last_usn: digits}}.
    cur = cfg.get("cursors")
    if cur is not None:
        if not isinstance(cur, dict):
            problems.append("cursors is not an object")
        else:
            for drive, rec in cur.items():
                if not isinstance(rec, dict):
                    problems.append("cursor %r is malformed" % drive); continue
                jid, lu = str(rec.get("journal_id", "")), str(rec.get("last_usn", ""))
                if not jid.isdigit() or not lu.isdigit():
                    problems.append("cursor %r has non-numeric journal_id/last_usn"
                                    % drive)
    return problems


def _service_is_running():
    """True if the Windows service is currently running. False on any error / non-
    Windows (so the editor proceeds)."""
    if not (_WINDOWS and win32serviceutil is not None):
        return False
    try:
        status = win32serviceutil.QueryServiceStatus(SERVICE_NAME)
        return status[1] == win32service.SERVICE_RUNNING
    except Exception:
        return False


def run_config_editor():
    """v0.0.9: informational stub. usnmon no longer has user-editable settings.
    Prints where the config lives, notes the read-only start type, and directs
    the operator to logmon for archive configuration."""
    print("usnmon configuration\n" + "-" * 40)
    cfg = read_config()

    issues = validate_config_integrity(cfg)
    if issues:
        print("NOTICE: config integrity check found %d anomaly(ies):"
              % len(issues))
        for it in issues:
            print("   - %s" % it)
        print()

    print("Config file:       %s" % _config_path())
    print("Diagnostic log:    %s"
          % os.path.join(_logs_dir(), DIAG_LOG_NAME))
    print("Service start type: %s  (read-only; set with --startup at install)"
          % cfg.get("service_start_type", "unknown"))
    print()
    print("v0.0.9: usnmon has no user-editable settings. Archive management "
          "(rotation, hashing, retention, legal-hold) now lives in the "
          "companion logmon service. Configure archives there.")
    print()
    print("To change the service start type: reinstall with pywin32's "
          "--startup flag, e.g.:")
    print("   usnmon --startup delayed install")
    print()
    print("To edit the diagnostic-log location or other future settings, edit "
          "%s directly (usnmon respects atomic replace)." % _config_path())


# --------------------------------------------------------------------------- #
# Console / CLI
# --------------------------------------------------------------------------- #
def run_console_debug():
    """Foreground engine run for interactive debugging. v0.0.9: no archive_dir,
    no rotate_period."""
    setup_logging(True)
    if _WINDOWS:
        register_event_source()
    logger.info("Console debug mode (usnmon). Ctrl+C to stop.")
    stop = threading.Event()
    try:
        run_engine(stop.is_set)
    except KeyboardInterrupt:
        stop.set()


def run_console_test():
    """Foreground capture for the test harness: identical to debug (real capture,
    emits 914/100s/915, Ctrl+C/terminate stops cleanly) BUT with console logging
    SUPPRESSED -- screen stays quiet so the test wrapper's output is readable, while
    the usnmon.log file trail is still written. Lets usntest_run.py own the engine as
    a normal foreground process (no service/SCM, no doubled-engine, killable).

    v0.0.9: no archive_dir, no rotate_period."""
    setup_logging(False)                   # False = no StreamHandler -> quiet console
    if _WINDOWS:
        register_event_source()
    logger.info("Console TEST mode (usnmon). Foreground capture, quiet console.")
    stop = threading.Event()
    try:
        run_engine(stop.is_set)
    except KeyboardInterrupt:
        stop.set()


def main():
    args = sys.argv[1:]

    # v0.0.9: --archive / --log-interval / --legal-retention removed. Archive
    # management now lives in logmon. usnmon has no user-configurable rotation
    # or retention. See USNMON_v0.0.9_EXTRACTION_PLAN.md.

    if args and args[0] == "config":
        run_config_editor()
        return
    if args and args[0] == "debug":
        run_console_debug()
        return
    if args and args[0] == "test":
        run_console_test()
        return
    # v0.0.9: `archive-now` subcommand removed. Archive triggers now live in
    # logmon.
    if args and args[0] == "check":
        # v0.0.9: repurposed as an engine-health report per extraction plan
        # section 5.9. Shows service status, config file state, diagnostic log
        # location, cursors summary, and any config integrity issues.
        import json as _json
        cfg = {}
        cfg_ok = True
        cfg_path = _config_path()
        try:
            with open(cfg_path, "r", encoding="utf-8") as f:
                cfg = _json.load(f)
        except FileNotFoundError:
            cfg_ok = False
        except Exception as exc:
            cfg_ok = False
            print("Config parse error: %r" % exc)

        # Service running check.
        running = "unknown"
        if _WINDOWS and win32serviceutil is not None:
            try:
                status = win32serviceutil.QueryServiceStatus(SERVICE_NAME)
                running = ("running" if status[1] == win32service.SERVICE_RUNNING
                           else "stopped")
            except Exception:
                running = "not installed"

        log_path = os.path.join(_logs_dir(), DIAG_LOG_NAME)
        log_size = None
        try:
            log_size = os.path.getsize(log_path)
        except Exception:
            pass

        print("usnmon engine health")
        print("-" * 40)
        print("Service:            %s (%s)" % (SERVICE_NAME, running))
        print("Service start type: %s" % cfg.get("service_start_type", "unknown"))
        print("Config file:        %s (%s)"
              % (cfg_path, "present" if cfg_ok else "missing/unreadable"))
        print("Diagnostic log:     %s%s"
              % (log_path,
                 " (%d bytes)" % log_size if log_size is not None
                 else " (no log yet)"))

        cursors = cfg.get("cursors", {}) if isinstance(cfg, dict) else {}
        if not cursors:
            print("Cursors:            (none -- engine has not yet checkpointed "
                  "any drive)")
        else:
            print("Cursors:            %d drive(s)" % len(cursors))
            for drive in sorted(cursors.keys()):
                rec = cursors[drive] if isinstance(cursors[drive], dict) else {}
                print("  %s journal_id=%s last_usn=%s updated=%s"
                      % (drive, rec.get("journal_id", "?"),
                         rec.get("last_usn", "?"),
                         rec.get("updated", "?")))

        # Any config integrity anomalies (unknown keys, legacy keys, malformed
        # cursors)?
        issues = validate_config_integrity(cfg) if isinstance(cfg, dict) else []
        if issues:
            print()
            print("Config anomalies:   %d" % len(issues))
            for it in issues:
                print("  - %s" % it)
        return

    if _WINDOWS and win32serviceutil is not None:
        # IMPORTANT: pywin32's HandleCommandLine reads sys.argv DIRECTLY, not our local
        # `args`. In v0.0.8a we stripped custom flags before this handoff. v0.0.9 has
        # no custom flags left, so sys.argv passes through unchanged. Keep the
        # rebuild for safety in case Pass 2 or a future release reintroduces any.
        sys.argv = [sys.argv[0]] + args
        if not args:
            try:
                servicemanager.Initialize()
                servicemanager.PrepareToHostSingle(USNMonitorService)
                servicemanager.StartServiceCtrlDispatcher()
            except Exception:
                win32serviceutil.HandleCommandLine(USNMonitorService)
        else:
            # Service start type is handled by pywin32's NATIVE --startup flag
            # ([manual|auto|disabled|delayed]), the way Python users already install
            # services. We don't wrap it. On install we let HandleCommandLine do the
            # install (honoring --startup), then read the ACTUAL configured start
            # type back from Windows and record it in config so the `config` editor
            # / `check` can report it and the engine can log it.
            #
            # NOTE on the 'install in args' check (vs args[0] == 'install'): pywin32's
            # --startup flag and its value are passed as separate args BEFORE the verb,
            # so on `usnmon.py --startup delayed install` we have
            # args = ['--startup', 'delayed', 'install']; checking args[0] alone misses
            # the verb. We look for 'install' anywhere in args. ('install' is safe as a
            # substring scan: no known pywin32 flag takes 'install' as its value.)
            is_install = "install" in args
            if is_install:
                write_config()
            win32serviceutil.HandleCommandLine(USNMonitorService)
            if is_install:
                try:
                    st = query_service_start_type()
                    cfg = read_config()
                    cfg["service_start_type"] = st
                    _write_config_atomic(cfg)
                except Exception as exc:
                    logger.debug("could not record start type: %r", exc)
    else:
        print("usnmon: Windows required for service/capture. "
              "Use 'debug' on Windows. (Imported OK on this platform.)")


if __name__ == "__main__":
    main()
