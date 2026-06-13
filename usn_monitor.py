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
    "monitor_all": False,       # True => monitor ALL drives, ignore "paths"
    "max_storage_gb": 60.0,
    "rotation_size_gb": 3.5,
    "exclude": [],              # carve-outs under "paths" roots
    "paths": [r"C:\Windows"],   # monitored ROOTS (each = that dir + all subdirs)
}

# Preferred on-disk key order: scalars first, then exclude, then the (largest) paths.
CONFIG_KEY_ORDER = ["schema_version", "monitor_all", "max_storage_gb",
                    "rotation_size_gb", "exclude"]

# Event-log max-size options (bytes). The custom FileSystem log defaults to a tiny
# size (~1 MB); we raise it. 4 GB is stored as the DWORD max (0xFFFFFFFF) since
# classic event logs use a 32-bit MaxSize. Rotation (rotation_size_gb, default
# 3.5 GB) fires before the log hits this ceiling.
LOG_SIZE_1GB = 1 * 1024 * 1024 * 1024          # 1,073,741,824
LOG_SIZE_4GB = 0xFFFFFFFF                       # 4,294,967,295 (DWORD max ~= 4 GB)
LOG_SIZE_MIN_RECOMMENDED = LOG_SIZE_1GB

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
    Safe to call repeatedly; it overwrites the existing registry values. Also
    raises the log's max size to 4 GB if it is still at the tiny default."""
    msg_dll = _find_message_dll()
    first_creation = not _log_exists()
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

    # On first creation the log is created tiny (~1 MB). Raise it to 4 GB so it
    # can hold activity up to the rotation trigger. (Service context can't prompt;
    # interactive contexts prompt separately via prompt_log_size_if_small.)
    if first_creation:
        if set_log_max_size(LOG_SIZE_4GB):
            logger.info("FileSystem log max size set to ~4 GB on first creation.")


# --------------------------------------------------------------------------- #
# Event-log sizing
# --------------------------------------------------------------------------- #
def _log_exists():
    """Return True if the FileSystem event log is already registered."""
    try:
        import winreg
        key = r"SYSTEM\CurrentControlSet\Services\EventLog\%s" % LOG_NAME
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key):
            return True
    except Exception:
        return False


def get_log_max_size():
    """Return the FileSystem log's configured max size in bytes, or None."""
    try:
        out = subprocess.run(
            ["wevtutil", "gl", LOG_NAME], capture_output=True, text=True)
        for line in out.stdout.splitlines():
            line = line.strip()
            if line.lower().startswith("maxsize:"):
                return int(line.split(":", 1)[1].strip())
    except Exception as exc:
        logger.info("get_log_max_size failed: %r", exc)
    return None


def set_log_max_size(size_bytes):
    """Set the FileSystem log's max size (bytes) via wevtutil. Requires elevation;
    returns True on success."""
    try:
        out = subprocess.run(
            ["wevtutil", "sl", LOG_NAME, "/ms:%d" % int(size_bytes)],
            capture_output=True, text=True)
        if out.returncode == 0:
            return True
        logger.warning("set_log_max_size failed: %s", out.stderr.strip())
    except Exception as exc:
        logger.warning("set_log_max_size error: %r", exc)
    return False


def prompt_log_size_if_small(ask_fn):
    """If the log's max size is below the recommended 1 GB minimum, use *ask_fn*
    to ask the user to pick 1 GB or 4 GB, then apply it. *ask_fn* takes the current
    size (bytes) and returns one of LOG_SIZE_1GB / LOG_SIZE_4GB / None (cancel).
    Used only in interactive contexts (GUI / console), never in the service."""
    current = get_log_max_size()
    if current is None or current >= LOG_SIZE_MIN_RECOMMENDED:
        return
    choice = ask_fn(current)
    if choice in (LOG_SIZE_1GB, LOG_SIZE_4GB):
        if set_log_max_size(choice):
            logger.info("FileSystem log max size set to %d bytes.", choice)


# --------------------------------------------------------------------------- #
# Drive enumeration
# --------------------------------------------------------------------------- #
def list_fixed_drives():
    """Return drive roots (e.g. 'C:\\') for fixed NTFS/ReFS volumes that can host
    a USN journal. Falls back to ['C:\\'] if enumeration is unavailable."""
    drives = []
    if win32file is not None:
        try:
            DRIVE_FIXED = 3
            for root in win32file.GetLogicalDriveStrings().split("\x00"):
                if not root:
                    continue
                try:
                    if win32file.GetDriveType(root) != DRIVE_FIXED:
                        continue
                    fs = win32file.GetVolumeInformation(root)[4]
                    if fs and fs.upper() in ("NTFS", "REFS"):
                        drives.append(root)
                except Exception:
                    continue
        except Exception as exc:
            logger.info("Drive enumeration failed: %r", exc)
    return drives or ["C:\\"]


def drive_root_to_device(root):
    r"""'C:\' -> r'\\.\C:' for CreateFile on the raw volume."""
    return r"\\.\%s" % root.rstrip("\\")


def drives_for_config(config, monitor_all):
    """Decide which drive roots to run an engine on. monitor_all => all fixed
    NTFS/ReFS drives; otherwise only the drives referenced by config['paths']."""
    if monitor_all:
        return list_fixed_drives()
    roots = set()
    for p in config.get("paths", []):
        d = os.path.splitdrive(os.path.normpath(p))[0]   # 'C:'
        if d:
            roots.add(d.upper() + "\\")
    available = set(d.upper() for d in list_fixed_drives())
    chosen = [d for d in roots if d.upper() in available]
    return chosen or ["C:\\"]


# --------------------------------------------------------------------------- #
# Path matching (roots + excludes), shared by engine and GUI
# --------------------------------------------------------------------------- #
def _norm_path(p):
    """Normalize a path (case/separator) for comparison."""
    return os.path.normcase(os.path.normpath(p))


def _is_under(path_norm, base_norm):
    """True if path_norm == base_norm or is a descendant of it (boundary-aware,
    so C:\\Windows does NOT match C:\\WindowsApps)."""
    if path_norm == base_norm:
        return True
    base = base_norm if base_norm.endswith(os.sep) else base_norm + os.sep
    return path_norm.startswith(base)


class PathMatcher:
    """Decides whether a path is monitored, given monitored ROOTS and EXCLUDES.
    A path matches when it is under some root AND not under any exclude. Roots and
    excludes are few (a handful), so the per-event loop is tiny and memory-light --
    unlike enumerating every sub-directory."""

    def __init__(self, roots, excludes):
        """Store normalized monitored roots and exclude carve-outs."""
        self.roots = [_norm_path(r) for r in roots]
        self.excludes = [_norm_path(e) for e in excludes]

    def matches(self, path):
        """Return True if path is under a root AND not under any exclude."""
        pn = _norm_path(path)
        if not any(_is_under(pn, r) for r in self.roots):
            return False
        if any(_is_under(pn, e) for e in self.excludes):
            return False
        return True


def minimize_roots(roots):
    """Collapse a set of roots so no root is a descendant of another (selecting a
    parent subsumes its children). Returns a sorted list."""
    norm = sorted({_norm_path(r): r for r in roots}.items())  # (norm, original)
    kept = []
    kept_norm = []
    for pn, original in norm:
        if any(_is_under(pn, k) for k in kept_norm):
            continue  # covered by an already-kept ancestor
        kept.append(original)
        kept_norm.append(pn)
    return sorted(kept)


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
    """Decode USN reason bit-flags into a readable '+'-joined string."""
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
    """Return the current UTC time as 'YYYY-MM-DD HH:MM:SS.fff'."""
    dt = datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S.") + "%03d" % (dt.microsecond // 1000)


def _machine_guid():
    """Return the machine's stable cryptographic GUID from the registry."""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Microsoft\Cryptography") as k:
            return winreg.QueryValueEx(k, "MachineGuid")[0]
    except Exception:
        return ""


def _machine_sid(hostname):
    """Return the machine SID (best-effort) for the given hostname."""
    if win32security is None or win32api is None:
        return ""
    try:
        sid, _domain, _type = win32security.LookupAccountName(None, hostname)
        return win32security.ConvertSidToStringSid(sid)
    except Exception:
        return ""


def _local_ips():
    """Return a snapshot of the host's local IP addresses."""
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
    """Return the primary network adapter's MAC address."""
    try:
        node = uuid.getnode()
        return "-".join("%02X" % ((node >> b) & 0xFF) for b in range(40, -8, -8))
    except Exception:
        return ""


def _volume_serial(drive="C:\\"):
    """Return the NTFS volume serial ('XXXX-XXXX') for a drive."""
    if win32api is None:
        return ""
    try:
        serial = win32api.GetVolumeInformation(drive)[1] & 0xFFFFFFFF
        return "%04X-%04X" % ((serial >> 16) & 0xFFFF, serial & 0xFFFF)
    except Exception:
        return ""


def _os_build():
    """Return the OS version/build as 'major.minor.build'."""
    try:
        v = sys.getwindowsversion()
        return "%d.%d.%d" % (v.major, v.minor, v.build)
    except Exception:
        return ""


def _domain_name():
    """Return the host's DNS domain name (empty if none)."""
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
    so this is refreshed if the service restarts. VolumeSerial and JournalId are
    per-drive and filled in by each drive's engine."""
    hostname = socket.gethostname()
    ctx = {
        "Hostname": hostname,
        "FQDN": socket.getfqdn(),
        "Domain": _domain_name(),
        "MachineGuid": _machine_guid(),
        "MachineSID": _machine_sid(hostname),
        "SourceIP": ", ".join(_local_ips()),
        "MAC": _mac_str(),
        "VolumeSerial": "",   # per-drive, set by the drive engine
        "OSBuild": _os_build(),
        "JournalId": "",      # per-drive, set after the journal is queried
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
        """Open a per-volume resolver with an LRU file-reference cache."""
        self.h_vol = h_vol
        self.cache: "OrderedDict[bytes, str]" = OrderedDict()
        self.cache_size = cache_size
        self.last_error = None

    def resolve(self, ref_bytes: bytes, allow_cache: bool = True):
        """Resolve a file reference to a full path (cache bypassed on rename/delete)."""
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
        """Open the item by file ID and build its full path."""
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
    """A single parsed USN journal record."""
    __slots__ = ("major", "file_ref", "parent_ref", "reason", "name", "usn", "timestamp")

    def __init__(self, major, file_ref, parent_ref, reason, name, usn=0, timestamp=0):
        """Store the parsed fields of one USN record."""
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
    """Build a READ_USN_JOURNAL_DATA_V1 input buffer."""
    return struct.pack("=qLLQQQHH",
                       int(start_usn), 0xFFFFFFFF, 0, 0, 0, int(j_id),
                       int(min_major), int(max_major))


def _read_input_v0(start_usn, j_id):
    # READ_USN_JOURNAL_DATA_V0 (40 bytes): V2 records only.
    """Build a READ_USN_JOURNAL_DATA_V0 input buffer."""
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
# Core engine (multi-drive)
# --------------------------------------------------------------------------- #
def run_engine(config, should_stop):
    """Top-level engine. Reads config, decides which drives to monitor, and runs
    one journal-reading worker thread per drive. With config['monitor_all'] True,
    monitors ALL fixed NTFS/ReFS drives and emits every change (paths ignored)."""
    monitor_all = bool(config.get("monitor_all", False))
    matcher = PathMatcher(config.get("paths", []), config.get("exclude", []))
    host_ctx = gather_host_context()

    drives = drives_for_config(config, monitor_all)
    if monitor_all:
        logger.info("Engine starting in --ALL mode: monitoring %d drive(s) %s; "
                    "roots/excludes IGNORED.", len(drives), drives)
    else:
        logger.info("Engine starting. %d root(s), %d exclude(s) across drive(s) %s.",
                    len(matcher.roots), len(matcher.excludes), drives)

    threads = []
    for root in drives:
        t = threading.Thread(
            target=_run_drive_engine,
            args=(root, matcher, should_stop, host_ctx, monitor_all),
            name="usn-%s" % root.rstrip("\\"), daemon=True)
        t.start()
        threads.append(t)

    # Wait until stop is requested, then let the daemon workers wind down.
    while not should_stop():
        if not any(t.is_alive() for t in threads):
            logger.error("All drive engines exited unexpectedly.")
            break
        time.sleep(0.5)
    for t in threads:
        t.join(timeout=5)
    logger.info("Engine stopped.")


def _run_drive_engine(drive_root, matcher, should_stop, host_ctx_base, monitor_all):
    """Poll one drive's USN journal and emit events. Each drive gets its own
    volume handle, journal, resolver, and a host-context copy carrying that
    drive's VolumeSerial and JournalId."""
    device = drive_root_to_device(drive_root)
    try:
        h_vol = win32file.CreateFile(
            device, win32file.GENERIC_READ, FILE_SHARE_ALL, None,
            win32file.OPEN_EXISTING, 0, None)
    except Exception as exc:
        logger.error("[%s] Cannot open volume: %s", drive_root, exc)
        return

    try:
        j_id, next_usn = query_journal(h_vol)
        build_read = negotiate_reader(h_vol, j_id, next_usn)
        resolver = PathResolver(h_vol)

        host_ctx = dict(host_ctx_base)
        host_ctx["JournalId"] = str(j_id)
        host_ctx["VolumeSerial"] = _volume_serial(drive_root)

        logger.info("[%s] Journal id=%d, starting at USN=%d (VolSerial %s).",
                    drive_root, j_id, next_usn, host_ctx["VolumeSerial"])

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
                logger.error("[%s] READ_USN_JOURNAL failed: %r", drive_root, exc)
                time.sleep(1)
                continue

            next_usn = int(struct.unpack_from("=q", out_buf, 0)[0])

            offset = 8
            had_records = False
            while offset < len(out_buf):
                rec_len = struct.unpack_from("=L", out_buf, offset)[0]
                if rec_len == 0:
                    break
                had_records = True
                try:
                    _handle_record(out_buf, offset, resolver, matcher, stats,
                                   host_ctx, monitor_all)
                except Exception as exc:
                    logger.error("[%s] Record parse error at offset %d: %r",
                                 drive_root, offset, exc)
                offset += rec_len

            if VERBOSE:
                now = time.monotonic()
                if stats["seen"] and (now - last_report) >= STATS_INTERVAL_SEC:
                    logger.info(
                        "[%s] stats: seen=%d (v2=%d v3=%d v4=%d) resolve_fail=%d "
                        "no_match=%d emitted=%d  last_resolve_err=%r",
                        drive_root, stats["seen"], stats["v2"], stats["v3"],
                        stats["v4"], stats["resolve_fail"], stats["no_match"],
                        stats["emitted"], getattr(resolver, "last_error", None))
                    last_report = now

            if not had_records:
                if should_stop():
                    break
                time.sleep(idle_sleep)

        logger.info("[%s] Drive engine stop requested; exiting cleanly.", drive_root)
    except Exception as exc:
        logger.error("[%s] Drive engine error: %r", drive_root, exc)
    finally:
        win32file.CloseHandle(h_vol)


# EventData emission. EvtxECmd renders classic events via the message template,
# collapsing insertion strings into one <Data> blob -> the EvtxECmd maps extract
# fields by regex from that blob (PARAM[1]). Event Log Explorer instead reads the
# raw insertion-strings array, so {PARAM[n]} needs SEPARATE strings. We therefore
# emit the clean blob as PARAM[1] AND a short, fixed list of high-value fields as
# PARAM[2..] for Event Log Explorer column extraction.
EVENT_FIELD_NAMES = [
    "SchemaVersion", "Category", "TargetFilename", "UtcTime", "Reason", "Usn",
    "JournalId", "Hostname", "FQDN", "Domain", "MachineGuid", "MachineSID",
    "SourceIP", "MAC", "VolumeSerial", "OSBuild",
]

# Fields exposed as separate insertion strings for Event Log Explorer {PARAM[n]}:
#   PARAM[1] = full readable block (also used by EvtxECmd regex maps)
#   PARAM[2] = Hostname
#   PARAM[3] = TargetFilename
#   PARAM[4] = UtcTime
#   PARAM[5] = MachineGuid
#   PARAM[6] = SourceIP
#   PARAM[7] = VolumeSerial
PARAM_FIELDS = [
    "Hostname", "TargetFilename", "UtcTime", "MachineGuid", "SourceIP", "VolumeSerial",
]


def _build_event_strings(category, target_filename, utc_time, rec, host_ctx):
    """Return insertion strings: [ readable_blob, <PARAM_FIELDS values...> ].
    The blob (index 0) carries all fields as 'Key: value' lines for EvtxECmd regex
    maps and the readable description; indices 1.. are the PARAM_FIELDS values for
    Event Log Explorer's {PARAM[2..]}."""
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
    blob = "\n".join("%s: %s" % (name, values[name]) for name in EVENT_FIELD_NAMES)
    extras = [values[name] for name in PARAM_FIELDS]
    return [blob] + extras


def _handle_record(buf, offset, resolver, matcher, stats, host_ctx, monitor_all=False):
    """Parse one record, apply the matcher (unless --all), and emit its event."""
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
        target_filename = os.path.join(parent_path, rec.name)
        if not monitor_all and not matcher.matches(target_filename):
            stats["no_match"] += 1
            return
        event_id, category = classify_event(rec.reason)
        utc_time = filetime_to_utc_str(rec.timestamp) or now_utc_str()

    else:  # V4: no file name, resolve the item itself; no record timestamp
        item_path = resolver.resolve(rec.file_ref, allow_cache=not refresh)
        if item_path is None:
            stats["resolve_fail"] += 1
            return
        if not monitor_all and not matcher.matches(item_path):
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
    """Background loop: back up and clear the live log past the rotation size."""
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
    """Evict oldest archives (FIFO) until total size is under the cap."""
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
    """Windows service wrapper that runs the USN engine + rotation."""
    _svc_name_ = "USNMonitorService"
    _svc_display_name_ = "FileSystem USN Journal Monitor"
    _svc_description_ = "Headless USN Journal parser with 3.5GB/60GB rolling archives."

    def __init__(self, args):
        """Initialize the service framework and stop event."""
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self._stop = threading.Event()

    def SvcStop(self):
        """Signal the engine to stop (called by the SCM)."""
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self._stop.set()
        win32event.SetEvent(self.hWaitStop)

    def should_stop(self):
        """Return True once a stop has been requested."""
        return self._stop.is_set()

    def SvcDoRun(self):
        """Service entry point: start logging and run the engine."""
        setup_logging(to_console=False)
        try:
            self._run()
        except Exception as exc:
            logger.exception("Fatal service error: %r", exc)
            raise

    def _run(self):
        """Register the source, start rotation, and run the multi-drive engine."""
        os.makedirs(ARCHIVE_DIR, exist_ok=True)
        register_event_source()

        config = load_config()

        rot = threading.Thread(
            target=rotation_loop, args=(config, self.should_stop), daemon=True)
        rot.start()

        # The engine runs on this (the service) thread and polls should_stop().
        run_engine(config, self.should_stop)

        # If the engine returns, wait until the SCM stop signal is fully handled.
        win32event.WaitForSingleObject(self.hWaitStop, 5000)


# --------------------------------------------------------------------------- #
# Config helpers
# --------------------------------------------------------------------------- #
def load_config():
    """Load monitor_config.json, filling missing keys from defaults."""
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
    """Write the config to disk in the preferred key order."""
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(config_ordered(cfg), f, indent=4)


# --------------------------------------------------------------------------- #
# Configuration GUI
# --------------------------------------------------------------------------- #
CHECKED = "[X] "
UNCHECKED = "[ ] "          # equal width (4 chars) -- fixes tag-corruption bug
EXCLUDED = "[-] "           # covered by a root but carved out via exclude list


class USNConfigUI:
    """Tkinter GUI for building the roots/excludes monitoring config."""
    def __init__(self, root):
        """Build the configuration window (drive tree, controls, size fields)."""
        self.root = root
        self.root.title("USN Monitor Deployment Configuration")
        self.root.geometry("850x650")

        self.config = load_config()
        # Roots-only model: store the minimal set of monitored ROOTS (each implies
        # all sub-directories) plus an EXCLUDE list of carve-outs. A folder is
        # monitored if it (or an ancestor) is a root and not under any exclude.
        self.roots = set(self.config.get("paths", []))
        self.excludes = set(self.config.get("exclude", []))
        self.monitor_all_var = tk.BooleanVar(value=bool(self.config.get("monitor_all", False)))
        self.rotation_var = tk.StringVar(value=str(self.config.get("rotation_size_gb", 3.5)))
        self.storage_var = tk.StringVar(value=str(self.config.get("max_storage_gb", 60.0)))

        # --- top controls ---
        top = tk.Frame(root); top.pack(fill="x", padx=10, pady=(10, 0))
        tk.Checkbutton(
            top, text="Monitor ALL drives (ignore selections below)",
            variable=self.monitor_all_var, command=self._toggle_all_mode
        ).pack(side="left")

        # --- rotation-size controls ---
        rf = tk.Frame(root); rf.pack(fill="x", padx=10, pady=(6, 0))
        tk.Label(rf, text="Rotate each log at (GB):").pack(side="left")
        tk.Entry(rf, textvariable=self.rotation_var, width=8).pack(side="left", padx=(4, 14))
        tk.Label(rf, text="Max total archive size (GB):").pack(side="left")
        tk.Entry(rf, textvariable=self.storage_var, width=8).pack(side="left", padx=4)

        # --- search bar ---
        sf = tk.Frame(root); sf.pack(fill="x", padx=10, pady=10)
        tk.Label(sf, text="Search Folder:").pack(side="left")
        self.sv = tk.StringVar()
        self.se = tk.Entry(sf, textvariable=self.sv)
        self.se.pack(side="left", fill="x", expand=True, padx=5)
        tk.Button(sf, text="Find Next", command=self.search).pack(side="left")

        # --- tree ---
        self.tree = ttk.Treeview(root, columns=("full_path",))
        self.tree.heading("#0", text="Directory Tree  ([X]=monitored  [-]=excluded  [ ]=off)  "
                                     "Double-click = toggle root")
        self.tree.column("#0", width=750)
        self.tree["displaycolumns"] = ()  # hide the value column
        self.tree.pack(fill="both", expand=True, padx=10)
        self.tree.bind("<<TreeviewOpen>>", self.on_expand)
        self.tree.bind("<Double-1>", self.toggle_recursive)

        # One root node per fixed NTFS/ReFS drive.
        for drive_root in list_fixed_drives():
            self.add_node("", drive_root, drive_root)

        # --- footer ---
        footer = tk.Frame(root); footer.pack(fill="x", padx=10, pady=15)
        self.status = tk.Label(footer, text="", anchor="w")
        self.status.pack(side="left", fill="x", expand=True)
        self.exclude_btn = tk.Button(footer, text="Mark to Exclude",
                                     command=self.toggle_exclude)
        self.exclude_btn.pack(side="right", padx=(0, 8))
        tk.Button(footer, text="Save Config (JSON)", command=self.save,
                  bg="#27ae60", fg="white",
                  font=("Arial", 10, "bold")).pack(side="right")
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        self._toggle_all_mode()  # reflect initial monitor_all state

        # Offer to enlarge the event log if it is below the recommended minimum.
        try:
            prompt_log_size_if_small(self._gui_log_size_prompt)
        except Exception:
            pass

    def _toggle_all_mode(self):
        """Enable/disable the tree depending on the 'Monitor ALL drives' checkbox."""
        state = "disabled" if self.monitor_all_var.get() else "normal"
        try:
            self.tree.state(("disabled",) if self.monitor_all_var.get() else ("!disabled",))
        except Exception:
            pass
        if self.monitor_all_var.get():
            self.status.config(text="ALL-drives mode: every change on every drive "
                                    "is monitored; root/exclude selections are ignored.")
        else:
            self.status.config(text="%d root(s), %d exclude(s)."
                               % (len(self.roots), len(self.excludes)))

    def _gui_log_size_prompt(self, current_bytes):
        """Modal dialog asking for 1 GB or 4 GB. Returns LOG_SIZE_1GB/4GB/None."""
        cur_mb = current_bytes / (1024 * 1024)
        win = tk.Toplevel(self.root)
        win.title("Event Log Size")
        win.transient(self.root)
        win.grab_set()
        tk.Label(win, justify="left", padx=15, pady=10, text=(
            "The FileSystem event log max size is only %.0f MB,\n"
            "below the 1 GB recommended minimum.\n\nChoose a size:" % cur_mb)
        ).pack()
        choice = {"v": None}

        def pick(val):
            choice["v"] = val
            win.destroy()

        bar = tk.Frame(win); bar.pack(pady=10)
        tk.Button(bar, text="1 GB (min recommended)",
                  command=lambda: pick(LOG_SIZE_1GB)).pack(side="left", padx=5)
        tk.Button(bar, text="4 GB (max)",
                  command=lambda: pick(LOG_SIZE_4GB)).pack(side="left", padx=5)
        tk.Button(bar, text="Skip", command=lambda: pick(None)).pack(side="left", padx=5)
        win.wait_window()
        return choice["v"]

    # -- helpers --
    @staticmethod
    def _norm(p):
        """Normalize a path for comparison (static helper)."""
        return os.path.normcase(os.path.normpath(p))

    def _state(self, fp):
        """Return 'monitored', 'excluded', or 'off' for a path, by ancestor."""
        pn = self._norm(fp)
        under_root = any(_is_under(pn, self._norm(r)) for r in self.roots)
        if not under_root:
            return "off"
        if any(_is_under(pn, self._norm(e)) for e in self.excludes):
            return "excluded"
        return "monitored"

    def _prefix_for(self, fp):
        """Return the '[X]/[-]/[ ]' marker for a folder's state."""
        return {"monitored": CHECKED, "excluded": EXCLUDED, "off": UNCHECKED}[self._state(fp)]

    # -- tree population --
    def add_node(self, parent, label, fp):
        """Insert a tree node for a path with a lazy-load placeholder."""
        node = self.tree.insert(parent, "end", text=self._prefix_for(fp) + label,
                                values=(fp,))
        try:
            if os.path.isdir(fp):
                self.tree.insert(node, "end", text="dummy")  # lazy-load placeholder
        except Exception:
            pass
        return node

    def on_expand(self, _event):
        """Populate a tree node's children from the filesystem on expand."""
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

    # -- root toggle (double-click): all-or-nothing on the ROOT set --
    def toggle_recursive(self, _event):
        """Double-click: toggle the folder as a monitored root (all-or-nothing)."""
        node = self.tree.focus()
        vals = self.tree.item(node, "values")
        if not vals:
            return
        fp = vals[0]
        pn = self._norm(fp)
        roots_norm = {self._norm(r): r for r in self.roots}

        if pn in roots_norm:
            # It IS a root -> remove it (and any excludes now orphaned under it).
            self.roots = {r for r in self.roots if self._norm(r) != pn}
            self.excludes = {e for e in self.excludes
                             if any(_is_under(self._norm(e), self._norm(r)) for r in self.roots)}
            self.status.config(text="Removed root: %s" % fp)
        elif any(_is_under(pn, rn) for rn in roots_norm):
            # Covered by an ancestor root -> double-click does nothing; hint user.
            self.status.config(
                text="Covered by a parent root. Use 'Mark to Exclude' to carve it out.")
            return
        else:
            # Not monitored -> add as a root, dropping any child roots it subsumes.
            self.roots = set(minimize_roots(self.roots | {fp}))
            self.status.config(text="Added root: %s" % fp)

        self._refresh_all_roots()

    # -- exclude toggle (button): carve out / restore the highlighted folder --
    def toggle_exclude(self):
        """Button: exclude or un-exclude the highlighted folder + subtree."""
        sel = self.tree.focus()
        vals = self.tree.item(sel, "values")
        if not vals:
            self.status.config(text="Select a folder first, then Mark to Exclude.")
            return
        fp = vals[0]
        state = self._state(fp)
        pn = self._norm(fp)

        if state == "off":
            self.status.config(
                text="Not monitored (no parent root) -- nothing to exclude.")
            return
        if state == "excluded":
            # If this exact path is an exclude, remove it; else can't un-exclude a
            # path covered by an ancestor exclude without restructuring.
            if any(self._norm(e) == pn for e in self.excludes):
                self.excludes = {e for e in self.excludes if self._norm(e) != pn}
                self.status.config(text="Removed exclusion: %s" % fp)
            else:
                self.status.config(
                    text="Excluded via a parent folder; remove that exclusion instead.")
                return
        else:  # monitored -> add exclusion (drop redundant child excludes)
            self.excludes = {e for e in self.excludes
                             if not _is_under(self._norm(e), pn)}
            self.excludes.add(fp)
            self.status.config(text="Excluded: %s (and all sub-directories)" % fp)

        self._refresh_all_roots()
        self._update_exclude_btn(fp)

    def _on_select(self, _event):
        """Update the Exclude button label when the selection changes."""
        sel = self.tree.focus()
        vals = self.tree.item(sel, "values")
        if vals:
            self._update_exclude_btn(vals[0])

    def _update_exclude_btn(self, fp):
        # Context-aware label: same button excludes or restores.
        """Set the Exclude button label based on the folder's state."""
        if self._state(fp) == "excluded" and any(self._norm(e) == self._norm(fp)
                                                 for e in self.excludes):
            self.exclude_btn.config(text="Remove Exclusion")
        else:
            self.exclude_btn.config(text="Mark to Exclude")

    # -- redraw all currently-visible nodes' state markers --
    def _refresh_all_roots(self):
        """Redraw state markers across every drive subtree."""
        for top in self.tree.get_children(""):
            self._refresh_tags(top)

    def _refresh_tags(self, node):
        """Recursively redraw a node's and its children's state markers."""
        vals = self.tree.item(node, "values")
        if vals:
            fp = vals[0]
            label = self.tree.item(node, "text")[4:]   # strip fixed 4-char prefix
            self.tree.item(node, text=self._prefix_for(fp) + label)
        for child in self.tree.get_children(node):
            self._refresh_tags(child)

    # -- search --
    def search(self):
        """Find and reveal the first tree node matching the search text."""
        q = self.sv.get().strip().lower()
        if q:
            self._rec_search(self.tree.get_children(""), q)

    def _rec_search(self, items, q):
        """Recursively search nodes; reveal and select the first hit."""
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
        # Validate the rotation-size fields (floats, sane bounds).
        """Validate sizes and persist roots, excludes, monitor_all, and rotation sizes."""
        try:
            rot = float(self.rotation_var.get())
            cap = float(self.storage_var.get())
            if rot <= 0 or cap <= 0:
                raise ValueError("Sizes must be positive.")
            if rot > cap:
                raise ValueError("Per-log rotation size cannot exceed the total cap.")
        except ValueError as exc:
            messagebox.showerror("Invalid size", str(exc))
            return

        self.config["paths"] = sorted(minimize_roots(self.roots))
        self.config["exclude"] = sorted(self.excludes)
        self.config["monitor_all"] = bool(self.monitor_all_var.get())
        self.config["rotation_size_gb"] = rot
        self.config["max_storage_gb"] = cap
        try:
            save_config(self.config)
            if self.config["monitor_all"]:
                mode = "ALL drives (roots/excludes ignored)"
            else:
                mode = "%d root(s), %d exclude(s)" % (
                    len(self.config["paths"]), len(self.config["exclude"]))
            messagebox.showinfo(
                "Saved", "Configuration exported to:\n%s\n\nMode: %s\n"
                         "Rotate at %.1f GB, cap %.1f GB."
                % (CONFIG_FILE, mode, rot, cap))
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
    prompt_log_size_if_small(_console_log_size_prompt)

    stop = threading.Event()
    config = load_config()
    should_stop = stop.is_set

    rot = threading.Thread(target=rotation_loop, args=(config, should_stop), daemon=True)
    rot.start()

    logger.info("Console debug mode. Press Ctrl+C to stop.")
    if config.get("monitor_all"):
        logger.info("monitor_all is ON (all drives, paths ignored).")
    try:
        run_engine(config, should_stop)
    except KeyboardInterrupt:
        logger.info("Ctrl+C received; shutting down.")
    finally:
        stop.set()


def _console_log_size_prompt(current_bytes):
    """Console prompt for the log-size choice. Returns LOG_SIZE_1GB/4GB/None."""
    cur_mb = current_bytes / (1024 * 1024)
    print("\nThe FileSystem event log max size is only %.0f MB (below the 1 GB "
          "recommended minimum)." % cur_mb)
    print("  [1] 1 GB  (minimum recommended)")
    print("  [4] 4 GB  (maximum)")
    print("  [s] skip  (leave as-is)")
    try:
        ans = input("Choose 1, 4, or s: ").strip().lower()
    except EOFError:
        return None
    if ans == "1":
        return LOG_SIZE_1GB
    if ans == "4":
        return LOG_SIZE_4GB
    return None


# --------------------------------------------------------------------------- #
# Command-line --all handling
# --------------------------------------------------------------------------- #
def _consume_all_flag():
    """If --all (or -all/--monitor-all) is present in argv, persist
    monitor_all=True into the config and remove the flag from argv so the service
    command parser doesn't choke on it. Returns True if --all was present."""
    flags = {"--all", "-all", "--monitor-all"}
    present = any(a.lower() in flags for a in sys.argv[1:])
    if present:
        sys.argv = [sys.argv[0]] + [a for a in sys.argv[1:] if a.lower() not in flags]
        try:
            cfg = load_config()
            cfg["monitor_all"] = True
            save_config(cfg)
            logger.info("monitor_all enabled via --all (persisted to config).")
        except Exception as exc:
            logger.error("Could not persist --all to config: %r", exc)
    return present


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    # --all may appear anywhere; consume it first so HandleCommandLine sees only
    # its own verbs (install/start/stop/...).
    _consume_all_flag()

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
