"""
Forensic NTFS USN Journal Monitor
=================================

A Windows-native background service that monitors the NTFS USN Journal in
real time, filters activity against a user-defined whitelist, and logs
forensic metadata to a custom Windows Event Log (FileSystem.evtx).

Requires: Python 3.12+ (64-bit), pywin32  ->  pip install pywin32

Usage
-----
    python usn_monitor.py debug        # run in console for testing (Ctrl+C stops)
    python usn_monitor.py install      # install the Windows service
    python usn_monitor.py start        # start the service
    python usn_monitor.py stop         # stop the service
    python usn_monitor.py remove       # uninstall the service
    python usn_monitor.py              # (no args) launch the configuration GUI
    
    Enable Verboses debugging
    set USN_VERBOSE=1
    python usn_monitor.py debug

    Turn off Verbose debugging
    set USN_VERBOSE=0
"""

import os
import sys
import struct
import json
import time
import socket
import uuid
import threading
import subprocess
import logging
import logging.handlers
from collections import OrderedDict
from datetime import datetime, timezone, timedelta

import tkinter as tk
from tkinter import ttk, messagebox

# pywin32
import win32file
import win32evtlogutil
import win32evtlog
import win32serviceutil
import win32service
import win32event
try:
    import win32api
    import win32security
except Exception:  # pragma: no cover - best-effort enrichment only
    win32api = None
    win32security = None

# --------------------------------------------------------------------------- #
# Configuration constants
# --------------------------------------------------------------------------- #
DRIVE_PATH   = r"\\.\C:"
LOG_NAME     = "FileSystem"            # custom Windows Event Log name
SOURCE_NAME  = "USNJournalMonitor"     # event source registered under LOG_NAME
ARCHIVE_DIR  = r"C:\FileSystem_Archives"
CONFIG_FILE  = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "monitor_config.json")
DIAG_LOG     = os.path.join(ARCHIVE_DIR, "usn_monitor.log")  # our own diagnostics
EVTX_LIVE    = r"C:\Windows\System32\winevt\Logs\FileSystem.evtx"

# Win32 flags / IOCTLs
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FSCTL_QUERY_USN_JOURNAL    = 0x000900F4
FSCTL_READ_USN_JOURNAL     = 0x000900BB
FSCTL_CREATE_USN_JOURNAL   = 0x000900E7
FILE_SHARE_ALL             = win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE | win32file.FILE_SHARE_DELETE

# Distinct event IDs per change category, for easy Event Viewer / Get-WinEvent
# filtering. USN reasons are accumulating bit flags, so a record is classified
# by the highest-priority flag it carries (see classify_event).
EVENT_ID_CREATE   = 100   # FileCreate
EVENT_ID_MODIFY   = 101   # data written / extended / truncated / stream change
EVENT_ID_DELETE   = 102   # FileDelete
EVENT_ID_RENAME   = 103   # RenameOld / RenameNew
EVENT_ID_SECURITY = 104   # SecurityChange (ACL / owner)
EVENT_ID_OTHER    = 105   # attribute / index / hardlink / basic-info changes
EVENT_ID_RANGE    = 106   # USN_RECORD_V4 range-tracking (ReFS)

# Event field-contract version (see PROJECT_STATUS.md). MINOR bump = field added
# (backward-compatible); MAJOR bump = field renamed/removed (breaking).
SCHEMA_VERSION = "1.0"

# Config key order matters for readability: small, rarely-changing scalars are
# written first; the large, ever-growing "paths" list is written LAST so the top
# of the file stays quick to read and edit. (See save_config / config_ordered.)
DEFAULT_CONFIG = {
    "schema_version": SCHEMA_VERSION,
    "max_storage_gb": 60.0,
    "rotation_size_gb": 3.5,
    "paths": [r"C:\Windows"],
}

# Preferred on-disk key order: everything except "paths", then "paths" last.
CONFIG_KEY_ORDER = ["schema_version", "max_storage_gb", "rotation_size_gb"]

# Diagnostics: when USN_VERBOSE is set to a truthy value (1/true/yes/on), the
# engine logs a periodic counter summary. Off by default so the production log
# stays quiet. Read once at import; flip it by setting the environment variable
# before starting the service or the console runner.
VERBOSE = os.environ.get("USN_VERBOSE", "").strip().lower() in ("1", "true", "yes", "on")
STATS_INTERVAL_SEC = 5

# USN reasons that may invalidate a cached path -> never serve those from cache.
RENAME_DELETE_MASK = 0x200 | 0x1000 | 0x2000  # Delete | RenameOld | RenameNew

logger = logging.getLogger("USNMonitor")


# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #
def setup_logging(to_console: bool) -> None:
    """Configure the diagnostic logger. The service has no console, so it always
    logs to a rotating file; debug mode additionally logs to stdout."""
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    try:
        os.makedirs(ARCHIVE_DIR, exist_ok=True)
        fh = logging.handlers.RotatingFileHandler(
            DIAG_LOG, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8")
        fh.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s"))
        logger.addHandler(fh)
    except Exception:
        pass  # if we cannot write diagnostics we still want the service to run

    if to_console:
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
        logger.addHandler(ch)


# --------------------------------------------------------------------------- #
# Event source registration
# --------------------------------------------------------------------------- #
def _find_message_dll():
    """Locate a generic '%1' passthrough message resource so Event Viewer can
    format our events. The .NET Framework's EventLogMessages.dll defines 65536
    messages, each rendering the first insertion string -- ideal for arbitrary
    event IDs. Present on virtually every Windows install with .NET 4.x."""
    windir = os.environ.get("WINDIR", r"C:\Windows")
    candidates = [
        os.path.join(windir, r"Microsoft.NET\Framework64\v4.0.30319\EventLogMessages.dll"),
        os.path.join(windir, r"Microsoft.NET\Framework\v4.0.30319\EventLogMessages.dll"),
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return None


def register_event_source():
    """(Re)register SOURCE_NAME under the FileSystem log with a message DLL so
    events render their description instead of 'description ... cannot be found'.
    Safe to call repeatedly; it overwrites the existing registry values."""
    msg_dll = _find_message_dll()
    try:
        win32evtlogutil.AddSourceToRegistry(
            SOURCE_NAME, msgDLL=msg_dll, eventLogType=LOG_NAME)
        if msg_dll:
            logger.info("Event source registered (message DLL: %s).", msg_dll)
        else:
            logger.warning(
                "No EventLogMessages.dll found; events will show a "
                "'description not found' note but the File/Path/Reason text "
                "remains fully readable.")
    except Exception as exc:
        logger.info("Event source registration: %r", exc)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
_REASON_FLAGS = {
    0x00000001: "DataOverwrite",  0x00000002: "DataExtend",
    0x00000004: "DataTruncation", 0x00000010: "NamedDataOverwrite",
    0x00000100: "FileCreate",     0x00000200: "FileDelete",
    0x00000800: "SecurityChange", 0x00001000: "RenameOld",
    0x00002000: "RenameNew",      0x00004000: "IndexableChange",
    0x00008000: "BasicInfoChange", 0x00010000: "HardLinkChange",
    0x00100000: "StreamChange",   0x80000000: "Close",
}


def reason_text(reason: int) -> str:
    parts = [name for bit, name in _REASON_FLAGS.items() if reason & bit]
    return " + ".join(parts) if parts else hex(reason)


# Reason bit groups used for classification.
_R_DELETE   = 0x00000200
_R_CREATE   = 0x00000100
_R_RENAME   = 0x00001000 | 0x00002000
_R_SECURITY = 0x00000800
_R_MODIFY   = 0x00000001 | 0x00000002 | 0x00000004 | 0x00000010 | 0x00100000


def classify_event(reason: int):
    """Map an accumulated USN reason mask to a single (event_id, category)
    by priority -- the most forensically significant flag wins. Delete is
    ranked above Create so a create-then-delete-before-close record is
    reported as a deletion (the net on-disk effect)."""
    if reason & _R_DELETE:
        return EVENT_ID_DELETE, "Delete"
    if reason & _R_CREATE:
        return EVENT_ID_CREATE, "Create"
    if reason & _R_RENAME:
        return EVENT_ID_RENAME, "Rename"
    if reason & _R_SECURITY:
        return EVENT_ID_SECURITY, "SecurityChange"
    if reason & _R_MODIFY:
        return EVENT_ID_MODIFY, "Modify"
    return EVENT_ID_OTHER, "Other"


def strip_path_prefix(p: str) -> str:
    r"""Normalise the \\?\ and \\?\UNC\ prefixes returned by
    GetFinalPathNameByHandle into a conventional path."""
    if p.startswith("\\\\?\\UNC\\"):
        return "\\\\" + p[8:]
    if p.startswith("\\\\?\\"):
        return p[4:]
    return p


# --------------------------------------------------------------------------- #
# Forensic enrichment
# --------------------------------------------------------------------------- #
_FILETIME_EPOCH = 116444736000000000  # 1970-01-01 in FILETIME (100ns) units


def filetime_to_utc_str(ft: int):
    """Convert a Windows FILETIME (100ns intervals since 1601) to a UTC string
    formatted exactly like Sysmon's UtcTime: 'YYYY-MM-DD HH:MM:SS.fff'. This is a
    correlation key, so the format must match Sysmon. Returns None on bad input."""
    try:
        if not ft or ft <= _FILETIME_EPOCH:
            return None
        micro = (ft - _FILETIME_EPOCH) // 10
        dt = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=micro)
        return dt.strftime("%Y-%m-%d %H:%M:%S.") + "%03d" % (dt.microsecond // 1000)
    except Exception:
        return None


def now_utc_str():
    dt = datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S.") + "%03d" % (dt.microsecond // 1000)


def _machine_guid():
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Microsoft\Cryptography") as k:
            return winreg.QueryValueEx(k, "MachineGuid")[0]
    except Exception:
        return ""


def _machine_sid(hostname):
    if win32security is None or win32api is None:
        return ""
    try:
        sid, _domain, _type = win32security.LookupAccountName(None, hostname)
        return win32security.ConvertSidToStringSid(sid)
    except Exception:
        return ""


def _local_ips():
    ips = []
    try:
        for res in socket.getaddrinfo(socket.gethostname(), None):
            addr = res[4][0]
            if addr not in ("127.0.0.1", "::1") and addr not in ips:
                ips.append(addr)
    except Exception:
        pass
    return ips


def _mac_str():
    try:
        node = uuid.getnode()
        return "-".join("%02X" % ((node >> b) & 0xFF) for b in range(40, -8, -8))
    except Exception:
        return ""


def _volume_serial(drive="C:\\"):
    if win32api is None:
        return ""
    try:
        serial = win32api.GetVolumeInformation(drive)[1] & 0xFFFFFFFF
        return "%04X-%04X" % ((serial >> 16) & 0xFFFF, serial & 0xFFFF)
    except Exception:
        return ""


def _os_build():
    try:
        v = sys.getwindowsversion()
        return "%d.%d.%d" % (v.major, v.minor, v.build)
    except Exception:
        return ""


def _domain_name():
    if win32api is not None:
        try:
            # 2 == ComputerNameDnsDomain
            dom = win32api.GetComputerNameEx(2)
            if dom:
                return dom
        except Exception:
            pass
    return os.environ.get("USERDNSDOMAIN", "")


def gather_host_context():
    """Collect static host/forensic identifiers ONCE at engine start. IPs are a
    start-time snapshot (per-event enumeration would be too costly); for a
    long-running host the IP at event time is the forensically meaningful value,
    so this is refreshed if the service restarts."""
    hostname = socket.gethostname()
    drive_letter = DRIVE_PATH[-2:] if DRIVE_PATH[-1] == ":" else "C:"
    ctx = {
        "Hostname": hostname,
        "FQDN": socket.getfqdn(),
        "Domain": _domain_name(),
        "MachineGuid": _machine_guid(),
        "MachineSID": _machine_sid(hostname),
        "SourceIP": ", ".join(_local_ips()),
        "MAC": _mac_str(),
        "VolumeSerial": _volume_serial(drive_letter + "\\"),
        "OSBuild": _os_build(),
        "JournalId": "",  # filled in by the engine after the journal is queried
    }
    return ctx


# --------------------------------------------------------------------------- #
# Parent-path resolver (cached by file reference)
# --------------------------------------------------------------------------- #
class PathResolver:
    """Resolves a (parent) file-reference number to a full path.

    We resolve the *parent directory* of each record rather than the file
    itself: directories rarely change, so the cache hit-rate is high and we
    avoid one OpenFileById per file event (the original bottleneck)."""

    def __init__(self, h_vol, cache_size: int = 8192):
        self.h_vol = h_vol
        self.cache: "OrderedDict[bytes, str]" = OrderedDict()
        self.cache_size = cache_size
        self.last_error = None

    def resolve(self, ref_bytes: bytes, allow_cache: bool = True):
        if allow_cache:
            cached = self.cache.get(ref_bytes)
            if cached is not None:
                self.cache.move_to_end(ref_bytes)
                return cached
        path = self._open_and_resolve(ref_bytes)
        if path is not None and allow_cache:
            self.cache[ref_bytes] = path
            if len(self.cache) > self.cache_size:
                self.cache.popitem(last=False)
        return path

    def _candidate_refs(self, ref_bytes: bytes):
        """Yield the reference forms to try, most-likely-supported first.

        This pywin32 build wants the FileId as a Python int (not a packed
        buffer). NTFS references are 64-bit; a 16-byte FILE_ID_128 whose high
        8 bytes are zero (the NTFS case) is just its low 64 bits. True 128-bit
        ReFS ids are passed as a 128-bit int as a last resort."""
        if len(ref_bytes) == 8:
            yield int.from_bytes(ref_bytes, "little")
        elif len(ref_bytes) == 16:
            if ref_bytes[8:] == b"\x00" * 8:
                yield int.from_bytes(ref_bytes[:8], "little")   # NTFS 64-bit
            else:
                yield int.from_bytes(ref_bytes, "little")       # ReFS 128-bit

    def _open_and_resolve(self, ref_bytes: bytes):
        last_exc = None
        for ref in self._candidate_refs(ref_bytes):
            try:
                h = win32file.OpenFileById(
                    self.h_vol, ref, 0, FILE_SHARE_ALL,
                    FILE_FLAG_BACKUP_SEMANTICS, None)
            except Exception as exc:
                last_exc = exc
                continue
            try:
                raw = win32file.GetFinalPathNameByHandle(h, 0)
                return os.path.normpath(strip_path_prefix(raw))
            except Exception as exc:
                last_exc = exc
                return None
            finally:
                win32file.CloseHandle(h)
        self.last_error = last_exc
        return None


# --------------------------------------------------------------------------- #
# USN record parsing
# --------------------------------------------------------------------------- #
class UsnRecord:
    __slots__ = ("major", "file_ref", "parent_ref", "reason", "name", "usn", "timestamp")

    def __init__(self, major, file_ref, parent_ref, reason, name, usn=0, timestamp=0):
        self.major = major
        self.file_ref = file_ref      # bytes (8 for V2, 16 for V3/V4)
        self.parent_ref = parent_ref  # bytes or None (V4 has no name/parent use)
        self.reason = reason
        self.name = name              # str or None (V4 carries no file name)
        self.usn = usn                # this record's own USN (ordering primitive)
        self.timestamp = timestamp    # FILETIME (100ns since 1601), 0 if absent


def parse_record(buf: bytes, offset: int):
    """Parse one USN record beginning at *offset*. Returns (UsnRecord|None)."""
    major = struct.unpack_from("=H", buf, offset + 4)[0]

    if major == 2:
        file_ref   = buf[offset + 8:offset + 16]
        parent_ref = buf[offset + 16:offset + 24]
        usn        = struct.unpack_from("=q", buf, offset + 24)[0]
        timestamp  = struct.unpack_from("=q", buf, offset + 32)[0]
        reason     = struct.unpack_from("=L", buf, offset + 40)[0]
        n_len      = struct.unpack_from("=H", buf, offset + 56)[0]
        n_off      = struct.unpack_from("=H", buf, offset + 58)[0]
        name       = buf[offset + n_off:offset + n_off + n_len].decode("utf-16-le", "replace")
        return UsnRecord(2, file_ref, parent_ref, reason, name, usn, timestamp)

    if major == 3:
        file_ref   = buf[offset + 8:offset + 24]    # FILE_ID_128
        parent_ref = buf[offset + 24:offset + 40]   # FILE_ID_128
        usn        = struct.unpack_from("=q", buf, offset + 40)[0]
        timestamp  = struct.unpack_from("=q", buf, offset + 48)[0]
        reason     = struct.unpack_from("=L", buf, offset + 56)[0]
        n_len      = struct.unpack_from("=H", buf, offset + 72)[0]
        n_off      = struct.unpack_from("=H", buf, offset + 74)[0]
        name       = buf[offset + n_off:offset + n_off + n_len].decode("utf-16-le", "replace")
        return UsnRecord(3, file_ref, parent_ref, reason, name, usn, timestamp)

    if major == 4:
        # USN_RECORD_V4 (range tracking): carries no file name or timestamp. We
        # resolve the file itself by its 128-bit reference instead of parent+name.
        file_ref = buf[offset + 8:offset + 24]      # FILE_ID_128
        usn      = struct.unpack_from("=q", buf, offset + 40)[0]
        reason   = struct.unpack_from("=L", buf, offset + 48)[0]
        return UsnRecord(4, file_ref, None, reason, None, usn, 0)

    return None  # unknown / unsupported major version


# --------------------------------------------------------------------------- #
# Read-request structures (negotiated at startup)
# --------------------------------------------------------------------------- #
def _read_input_v1(start_usn, j_id, min_major, max_major):
    # READ_USN_JOURNAL_DATA_V1 (44 bytes): supports V2..V4 records.
    return struct.pack("=qLLQQQHH",
                       int(start_usn), 0xFFFFFFFF, 0, 0, 0, int(j_id),
                       int(min_major), int(max_major))


def _read_input_v0(start_usn, j_id):
    # READ_USN_JOURNAL_DATA_V0 (40 bytes): V2 records only.
    return struct.pack("=qLLQQQ",
                       int(start_usn), 0xFFFFFFFF, 0, 0, 0, int(j_id))


# --------------------------------------------------------------------------- #
# Journal query / create
# --------------------------------------------------------------------------- #
def query_journal(h_vol):
    """Return (journal_id, next_usn). Creates the journal if it is not active."""
    try:
        buf = win32file.DeviceIoControl(h_vol, FSCTL_QUERY_USN_JOURNAL, None, 80)
    except Exception as exc:
        logger.warning("QUERY_USN_JOURNAL failed (%s); attempting to create journal.", exc)
        create_in = struct.pack("=QQ", 32 * 1024 * 1024, 8 * 1024 * 1024)
        win32file.DeviceIoControl(h_vol, FSCTL_CREATE_USN_JOURNAL, create_in, 0)
        buf = win32file.DeviceIoControl(h_vol, FSCTL_QUERY_USN_JOURNAL, None, 80)

    # USN_JOURNAL_DATA_V0: UsnJournalID, FirstUsn, NextUsn, LowestValidUsn,
    #                      MaxUsn, MaximumSize, AllocationDelta
    fields = struct.unpack("=QqqqqQQ", buf[:56])
    j_id     = int(fields[0])
    next_usn = int(fields[2])
    return j_id, next_usn


def negotiate_reader(h_vol, j_id, next_usn):
    """Pick the richest READ request the volume accepts.

    Returns a callable build(start_usn) -> packed read-input bytes.
    Tries V1 (V2..V4) -> V1 (V2..V3) -> V0 (V2 only)."""
    # Order matters: a V0 read returns only V2 records (64-bit refs, which
    # OpenFileById resolves reliably). NTFS accepts this and it is what we
    # want. Only ReFS, which rejects V2, falls through to V3.
    candidates = [
        ("V0 records v2 (NTFS)", lambda s: _read_input_v0(s, j_id)),
        ("V1 records v3 (ReFS)", lambda s: _read_input_v1(s, j_id, 3, 3)),
        ("V1 records v2-v4",     lambda s: _read_input_v1(s, j_id, 2, 4)),
    ]
    for label, build in candidates:
        try:
            win32file.DeviceIoControl(h_vol, FSCTL_READ_USN_JOURNAL, build(next_usn), 16384)
            logger.info("Using read format: %s", label)
            return build
        except Exception as exc:
            logger.info("Read format '%s' rejected (%s); falling back.", label, exc)
    raise RuntimeError("No supported USN read format accepted by the volume.")


# --------------------------------------------------------------------------- #
# Core engine
# --------------------------------------------------------------------------- #
def run_usn_engine(monitored_paths, should_stop):
    """Poll the USN journal and emit a Windows event for every change whose
    containing directory is in the whitelist.

    *monitored_paths* : iterable of directory paths (each path plus all of its
                        recursively-selected sub-directories is present).
    *should_stop*     : zero-arg callable returning True when the engine must exit.
    """
    # Pre-normalise the whitelist once. A change is "monitored" when its parent
    # directory (or the item itself, for directory events) is in this set --
    # an O(1) lookup that also fixes the C:\Windows / C:\WindowsApps false match.
    monitored = {os.path.normcase(os.path.normpath(p)) for p in monitored_paths}
    logger.info("Engine starting. %d whitelisted directories.", len(monitored))

    try:
        h_vol = win32file.CreateFile(
            DRIVE_PATH, win32file.GENERIC_READ, FILE_SHARE_ALL, None,
            win32file.OPEN_EXISTING, 0, None)
    except Exception as exc:
        logger.error("Cannot open volume %s: %s", DRIVE_PATH, exc)
        return

    try:
        j_id, next_usn = query_journal(h_vol)
        build_read = negotiate_reader(h_vol, j_id, next_usn)
        resolver = PathResolver(h_vol)
        host_ctx = gather_host_context()
        host_ctx["JournalId"] = str(j_id)
        logger.info("Journal id=%d, starting at USN=%d.", j_id, next_usn)
        logger.info("Host context: %s / %s / GUID %s",
                    host_ctx.get("Hostname"), host_ctx.get("SourceIP"),
                    host_ctx.get("MachineGuid"))
        if VERBOSE:
            logger.info("Verbose diagnostics ON (USN_VERBOSE set); "
                        "logging stats every %ds.", STATS_INTERVAL_SEC)

        idle_sleep = 0.5
        stats = {"seen": 0, "v2": 0, "v3": 0, "v4": 0,
                 "resolve_fail": 0, "no_match": 0, "emitted": 0}
        last_report = time.monotonic()

        while not should_stop():
            try:
                read_input = build_read(next_usn)        # next_usn is always int
                out_buf = win32file.DeviceIoControl(
                    h_vol, FSCTL_READ_USN_JOURNAL, read_input, 65536)
            except Exception as exc:
                logger.error("READ_USN_JOURNAL failed: %r", exc)
                time.sleep(1)
                continue

            # First 8 bytes are the next USN to request. Extract as int *once*,
            # so it can never be reassigned to a tuple or non-integer value.
            next_usn = int(struct.unpack_from("=q", out_buf, 0)[0])

            offset = 8
            had_records = False
            while offset < len(out_buf):
                rec_len = struct.unpack_from("=L", out_buf, offset)[0]
                if rec_len == 0:
                    break
                had_records = True
                try:
                    _handle_record(out_buf, offset, resolver, monitored, stats, host_ctx)
                except Exception as exc:
                    logger.error("Record parse error at offset %d: %r", offset, exc)
                offset += rec_len

            # Periodic counter summary (diagnostics). Enabled only when
            # USN_VERBOSE is set, so the production log stays clean by default.
            if VERBOSE:
                now = time.monotonic()
                if stats["seen"] and (now - last_report) >= STATS_INTERVAL_SEC:
                    logger.info(
                        "stats: seen=%(seen)d (v2=%(v2)d v3=%(v3)d v4=%(v4)d) "
                        "resolve_fail=%(resolve_fail)d no_match=%(no_match)d "
                        "emitted=%(emitted)d  last_resolve_err=%(err)r",
                        dict(stats, err=getattr(resolver, "last_error", None)))
                    last_report = now

            if not had_records:
                # Nothing new: sleep briefly so we neither busy-spin (100% CPU)
                # nor block in a way that would prevent a clean service stop.
                if should_stop():
                    break
                time.sleep(idle_sleep)

        logger.info("Engine stop requested; exiting cleanly.")
    finally:
        win32file.CloseHandle(h_vol)


# Ordered EventData field contract. PARAM[1] is a human-readable summary (so the
# Event Viewer / Event Log Explorer description stays readable via the message
# DLL's "%1"); PARAM[2..] are the individual fields, each emitted as its own
# insertion string so they extract positionally as {PARAM[N]}.
#
#   PARAM[1]  = Summary (one line)
#   PARAM[2]  = SchemaVersion
#   PARAM[3]  = Category
#   PARAM[4]  = TargetFilename     (mirrors Sysmon)
#   PARAM[5]  = UtcTime            (mirrors Sysmon)
#   PARAM[6]  = Reason
#   PARAM[7]  = Usn
#   PARAM[8]  = JournalId
#   PARAM[9]  = Hostname
#   PARAM[10] = FQDN
#   PARAM[11] = Domain
#   PARAM[12] = MachineGuid
#   PARAM[13] = MachineSID
#   PARAM[14] = SourceIP
#   PARAM[15] = MAC
#   PARAM[16] = VolumeSerial
#   PARAM[17] = OSBuild
EVENT_FIELD_NAMES = [
    "SchemaVersion", "Category", "TargetFilename", "UtcTime", "Reason", "Usn",
    "JournalId", "Hostname", "FQDN", "Domain", "MachineGuid", "MachineSID",
    "SourceIP", "MAC", "VolumeSerial", "OSBuild",
]


def _build_event_strings(category, target_filename, utc_time, rec, host_ctx):
    """Return the list of insertion strings for ReportEvent. Index 0 is a
    readable summary; indices 1.. are the individual field VALUES in
    EVENT_FIELD_NAMES order (so they map to {PARAM[2]}.. positionally)."""
    values = {
        "SchemaVersion": SCHEMA_VERSION,
        "Category": category,
        "TargetFilename": target_filename,
        "UtcTime": utc_time,
        "Reason": reason_text(rec.reason),
        "Usn": str(rec.usn),
        "JournalId": host_ctx.get("JournalId", ""),
        "Hostname": host_ctx.get("Hostname", ""),
        "FQDN": host_ctx.get("FQDN", ""),
        "Domain": host_ctx.get("Domain", ""),
        "MachineGuid": host_ctx.get("MachineGuid", ""),
        "MachineSID": host_ctx.get("MachineSID", ""),
        "SourceIP": host_ctx.get("SourceIP", ""),
        "MAC": host_ctx.get("MAC", ""),
        "VolumeSerial": host_ctx.get("VolumeSerial", ""),
        "OSBuild": host_ctx.get("OSBuild", ""),
    }
    summary = "%s  %s  (UTC %s)" % (category, target_filename, utc_time)
    ordered_values = [values[name] for name in EVENT_FIELD_NAMES]
    # Full readable block as the summary so the description tab is still useful.
    readable = summary + "\n" + "\n".join(
        "%s: %s" % (name, values[name]) for name in EVENT_FIELD_NAMES)
    return [readable] + ordered_values


def _handle_record(buf, offset, resolver, monitored, stats, host_ctx):
    rec = parse_record(buf, offset)
    if rec is None:
        return
    stats["seen"] += 1
    stats["v%d" % rec.major] = stats.get("v%d" % rec.major, 0) + 1

    refresh = bool(rec.reason & RENAME_DELETE_MASK)  # bypass cache on rename/delete

    if rec.major in (2, 3):
        parent_path = resolver.resolve(rec.parent_ref, allow_cache=not refresh)
        if parent_path is None:
            stats["resolve_fail"] += 1
            return
        if os.path.normcase(parent_path) not in monitored:
            stats["no_match"] += 1
            return
        target_filename = os.path.join(parent_path, rec.name)
        event_id, category = classify_event(rec.reason)
        utc_time = filetime_to_utc_str(rec.timestamp) or now_utc_str()

    else:  # V4: no file name, resolve the item itself; no record timestamp
        item_path = resolver.resolve(rec.file_ref, allow_cache=not refresh)
        if item_path is None:
            stats["resolve_fail"] += 1
            return
        parent = os.path.normcase(os.path.dirname(item_path))
        if parent not in monitored and os.path.normcase(item_path) not in monitored:
            stats["no_match"] += 1
            return
        target_filename = item_path
        event_id = EVENT_ID_RANGE
        category = "RangeChange"
        utc_time = now_utc_str()

    strings = _build_event_strings(category, target_filename, utc_time, rec, host_ctx)
    win32evtlogutil.ReportEvent(
        SOURCE_NAME, event_id,
        eventType=win32evtlog.EVENTLOG_INFORMATION_TYPE,
        strings=strings)
    stats["emitted"] += 1


# --------------------------------------------------------------------------- #
# Log rotation / disk-cap cleanup
# --------------------------------------------------------------------------- #
def rotation_loop(config, should_stop):
    last_month = datetime.now().month
    counter = 1
    max_bytes = config.get("rotation_size_gb", 3.5) * 1024 ** 3
    limit_bytes = config.get("max_storage_gb", 60.0) * 1024 ** 3

    while not should_stop():
        try:
            now = datetime.now()
            if now.month != last_month:
                counter = 1
                last_month = now.month

            size = os.path.getsize(EVTX_LIVE) if os.path.exists(EVTX_LIVE) else 0
            if (now.day == 1 and now.hour == 1) or (size >= max_bytes):
                backup = os.path.join(
                    ARCHIVE_DIR,
                    "FileSystem_{m}_{c}.evtx".format(m=now.strftime("%B_%Y"), c=counter))
                logger.info("Rotating log -> %s (size=%d bytes).", backup, size)
                subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     "Clear-EventLog -LogName '{0}' -Backup '{1}'".format(LOG_NAME, backup)],
                    capture_output=True)
                counter += 1
                _enforce_storage_cap(limit_bytes)
        except Exception as exc:
            logger.error("Rotation error: %r", exc)

        # Sleep in short slices so the service can stop within ~10 s.
        for _ in range(60):
            if should_stop():
                return
            time.sleep(10)


def _enforce_storage_cap(limit_bytes):
    try:
        archives = sorted(
            (os.path.join(ARCHIVE_DIR, f) for f in os.listdir(ARCHIVE_DIR)
             if f.lower().endswith(".evtx")),
            key=os.path.getmtime)
    except Exception as exc:
        logger.error("Cannot list archive dir: %r", exc)
        return

    total = sum(os.path.getsize(f) for f in archives)
    while total > limit_bytes and archives:
        victim = archives.pop(0)  # FIFO: oldest first
        try:
            sz = os.path.getsize(victim)
            os.remove(victim)
            total -= sz
            logger.info("Storage cap: deleted oldest archive %s.", victim)
        except Exception as exc:
            logger.error("Failed to delete %s: %r", victim, exc)
            break


# --------------------------------------------------------------------------- #
# Windows service wrapper
# --------------------------------------------------------------------------- #
class USNMonitorService(win32serviceutil.ServiceFramework):
    _svc_name_ = "USNMonitorService"
    _svc_display_name_ = "FileSystem USN Journal Monitor"
    _svc_description_ = "Headless USN Journal parser with 3.5GB/60GB rolling archives."

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self._stop = threading.Event()

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self._stop.set()
        win32event.SetEvent(self.hWaitStop)

    def should_stop(self):
        return self._stop.is_set()

    def SvcDoRun(self):
        setup_logging(to_console=False)
        try:
            self._run()
        except Exception as exc:
            logger.exception("Fatal service error: %r", exc)
            raise

    def _run(self):
        os.makedirs(ARCHIVE_DIR, exist_ok=True)
        register_event_source()

        config = load_config()

        rot = threading.Thread(
            target=rotation_loop, args=(config, self.should_stop), daemon=True)
        rot.start()

        # The engine runs on this (the service) thread and polls should_stop().
        run_usn_engine(config["paths"], self.should_stop)

        # If the engine returns, wait until the SCM stop signal is fully handled.
        win32event.WaitForSingleObject(self.hWaitStop, 5000)


# --------------------------------------------------------------------------- #
# Config helpers
# --------------------------------------------------------------------------- #
def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            for k, v in DEFAULT_CONFIG.items():
                cfg.setdefault(k, v)
            return cfg
        except Exception as exc:
            logger.error("Config load failed (%r); using defaults.", exc)
    return dict(DEFAULT_CONFIG)


def config_ordered(cfg):
    """Return an ordered dict with scalar keys first (CONFIG_KEY_ORDER) and the
    large 'paths' list written LAST, so the top of the JSON stays compact."""
    ordered = OrderedDict()
    for key in CONFIG_KEY_ORDER:
        if key in cfg:
            ordered[key] = cfg[key]
    # any other non-path scalar keys, preserved, still before paths
    for key, val in cfg.items():
        if key not in ordered and key != "paths":
            ordered[key] = val
    # paths always last
    ordered["paths"] = cfg.get("paths", [])
    return ordered


def save_config(cfg):
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(config_ordered(cfg), f, indent=4)


# --------------------------------------------------------------------------- #
# Configuration GUI
# --------------------------------------------------------------------------- #
CHECKED = "[X] "
UNCHECKED = "[ ] "          # equal width (4 chars) -- fixes tag-corruption bug


class USNConfigUI:
    def __init__(self, root):
        self.root = root
        self.root.title("USN Monitor Deployment Configuration")
        self.root.geometry("850x650")

        self.config = load_config()
        # Stored as a set of monitored directories (recursive selections include
        # every physical sub-directory). Normalised compare-keys are derived
        # on the fly so display paths stay human-readable.
        self.monitored_paths = set(self.config["paths"])

        # --- search bar ---
        sf = tk.Frame(root); sf.pack(fill="x", padx=10, pady=10)
        tk.Label(sf, text="Search Folder:").pack(side="left")
        self.sv = tk.StringVar()
        self.se = tk.Entry(sf, textvariable=self.sv)
        self.se.pack(side="left", fill="x", expand=True, padx=5)
        tk.Button(sf, text="Find Next", command=self.search).pack(side="left")

        # --- tree ---
        self.tree = ttk.Treeview(root, columns=("full_path",))
        self.tree.heading("#0", text="Directory Tree (Double-click to Toggle Folder + All Children)")
        self.tree.column("#0", width=750)
        self.tree["displaycolumns"] = ()  # hide the value column
        self.tree.pack(fill="both", expand=True, padx=10)
        self.tree.bind("<<TreeviewOpen>>", self.on_expand)
        self.tree.bind("<Double-1>", self.toggle_recursive)

        self.add_node("", "C:\\", "C:\\")

        # --- footer ---
        footer = tk.Frame(root); footer.pack(fill="x", padx=10, pady=15)
        self.status = tk.Label(footer, text="", anchor="w")
        self.status.pack(side="left", fill="x", expand=True)
        tk.Button(footer, text="Save Config (JSON)", command=self.save,
                  bg="#27ae60", fg="white",
                  font=("Arial", 10, "bold")).pack(side="right")

    # -- helpers --
    @staticmethod
    def _norm(p):
        return os.path.normcase(os.path.normpath(p))

    def _is_monitored(self, fp):
        return self._norm(fp) in {self._norm(p) for p in self.monitored_paths}

    # -- tree population --
    def add_node(self, parent, label, fp):
        prefix = CHECKED if self._is_monitored(fp) else UNCHECKED
        node = self.tree.insert(parent, "end", text=prefix + label, values=(fp,))
        try:
            if os.path.isdir(fp):
                self.tree.insert(node, "end", text="dummy")  # lazy-load placeholder
        except Exception:
            pass
        return node

    def on_expand(self, _event):
        node = self.tree.focus()
        vals = self.tree.item(node, "values")
        if not vals:
            return
        fp = vals[0]
        self.tree.delete(*self.tree.get_children(node))
        try:
            for entry in sorted(os.scandir(fp), key=lambda e: e.name.lower()):
                if entry.is_dir(follow_symlinks=False):
                    self.add_node(node, entry.name, entry.path)
        except Exception:
            pass

    # -- selection --
    def toggle_recursive(self, _event):
        node = self.tree.focus()
        vals = self.tree.item(node, "values")
        if not vals:
            return
        fp = vals[0]
        adding = not self._is_monitored(fp)

        if adding:
            # Per requirement: when SELECTING, fully expand every branch and add
            # all child paths -- accepting that this can be slow / hang the UI on
            # large trees. Done synchronously on the UI thread (Tk is not
            # thread-safe), with a wait cursor and periodic progress updates.
            self.root.config(cursor="watch")
            self.se.config(state="disabled")
            try:
                count = self._expand_and_select_all(node)
            finally:
                self.root.config(cursor="")
                self.se.config(state="normal")
            self.status.config(
                text="Selected %d directories (%d total monitored)."
                % (count, len(self.monitored_paths)))
        else:
            # When DESELECTING, drop this path and every descendant from the
            # whitelist by prefix (no filesystem walk needed -- fast even if the
            # subtree was never expanded in the tree).
            norm_fp = self._norm(fp)
            self.monitored_paths = {
                p for p in self.monitored_paths
                if self._norm(p) != norm_fp
                and not self._norm(p).startswith(norm_fp + os.sep)}
            self._refresh_tags(node)
            self.status.config(
                text="%d directories monitored." % len(self.monitored_paths))

    def _expand_and_select_all(self, start_node):
        """Iteratively expand EVERY descendant of start_node, populating lazy
        nodes from the filesystem, and add each directory to the whitelist.
        Returns the number of directories selected. Intentionally synchronous;
        may hang the UI on very large subtrees (by design)."""
        stack = [start_node]
        count = 0
        while stack:
            node = stack.pop()
            vals = self.tree.item(node, "values")
            if not vals:
                continue
            fp = vals[0]

            # Select this directory and reflect it in the tree label.
            self.monitored_paths.add(fp)
            label = self.tree.item(node, "text")[4:]   # strip fixed 4-char prefix
            self.tree.item(node, text=CHECKED + label)

            # Populate children if this is still a lazy placeholder.
            children = self.tree.get_children(node)
            is_placeholder = (len(children) == 1 and
                              not self.tree.item(children[0], "values"))
            if is_placeholder:
                self.tree.delete(*children)
                try:
                    for entry in sorted(os.scandir(fp), key=lambda e: e.name.lower()):
                        if entry.is_dir(follow_symlinks=False):
                            self.add_node(node, entry.name, entry.path)
                except Exception:
                    pass
                children = self.tree.get_children(node)

            self.tree.item(node, open=True)
            stack.extend(children)

            count += 1
            if count % 250 == 0:
                self.status.config(text="Expanding... %d folders" % count)
                self.root.update()   # keep the UI responsive-ish during long runs
        return count

    def _refresh_tags(self, node):
        vals = self.tree.item(node, "values")
        if vals:
            fp = vals[0]
            prefix = CHECKED if self._is_monitored(fp) else UNCHECKED
            label = self.tree.item(node, "text")[4:]   # strip fixed 4-char prefix
            self.tree.item(node, text=prefix + label)
        for child in self.tree.get_children(node):
            self._refresh_tags(child)

    # -- search --
    def search(self):
        q = self.sv.get().strip().lower()
        if q:
            self._rec_search(self.tree.get_children(""), q)

    def _rec_search(self, items, q):
        for i in items:
            if q in self.tree.item(i, "text").lower():
                self.tree.see(i)
                self.tree.selection_set(i)
                return True
            if self._rec_search(self.tree.get_children(i), q):
                return True
        return False

    # -- save --
    def save(self):
        self.config["paths"] = sorted(self.monitored_paths)
        try:
            save_config(self.config)
            messagebox.showinfo("Saved", "Configuration exported to:\n%s" % CONFIG_FILE)
        except Exception as exc:
            messagebox.showerror("Save failed", str(exc))


# --------------------------------------------------------------------------- #
# Console (debug) runner
# --------------------------------------------------------------------------- #
def run_console_debug():
    """Run the engine + rotation in the foreground for testing (Ctrl+C stops)."""
    setup_logging(to_console=True)
    os.makedirs(ARCHIVE_DIR, exist_ok=True)
    register_event_source()

    stop = threading.Event()
    config = load_config()
    should_stop = stop.is_set

    rot = threading.Thread(target=rotation_loop, args=(config, should_stop), daemon=True)
    rot.start()

    logger.info("Console debug mode. Press Ctrl+C to stop.")
    try:
        run_usn_engine(config["paths"], should_stop)
    except KeyboardInterrupt:
        logger.info("Ctrl+C received; shutting down.")
    finally:
        stop.set()


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1].lower() == "debug":
        # Foreground test mode (does NOT go through the SCM).
        run_console_debug()
    elif len(sys.argv) > 1:
        # install / remove / start / stop / etc.
        win32serviceutil.HandleCommandLine(USNMonitorService)
    else:
        # No arguments -> configuration GUI.
        root = tk.Tk()
        USNConfigUI(root)
        root.mainloop()
