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

DEFAULT_ARCHIVE_DIR = r"C:\FileSystem_Archives"
DIAG_LOG_NAME = "usnmon.log"

# Rotation
ROTATE_BYTES = int(3.5 * 1024 * 1024 * 1024)   # 3.5 GB safety (evtx 4 GB hard cap)
EVENTLOG_MAX_BYTES = 0xFFFFFFFF                  # 4 GB on channel creation
SUBDAY_NAMING_THRESHOLD_SEC = 86400              # < 1 day -> timecode in archive name


def _archive_format_date(dt, with_time):
    """Format a datetime for use in an archive filename.

    ISO-8601 style: YYYY-MM-DD, four-digit year, two-digit zero-padded month and day.
    Alphabetical sort = chronological sort, which is exactly what an investigator
    walking the FileSystem_Archives directory wants. When with_time=True, append
    -HHMMSS (zero-padded 24-hour clock; hyphen separator chosen over ISO's 'T' for
    filename readability)."""
    if with_time:
        return dt.strftime("%Y-%m-%d-%H%M%S")
    return dt.strftime("%Y-%m-%d")


def _is_midnight(dt):
    """True iff this datetime is exactly midnight (00:00:00.000). Used by the naming
    logic to decide whether a span needs a sub-day timecode."""
    return (dt.hour == 0 and dt.minute == 0 and dt.second == 0
            and dt.microsecond == 0)


def _is_calendar_month_start(dt):
    """True iff this datetime is the 1st of a calendar month at exactly midnight.
    The 'is this a whole-calendar-month archive' check uses this for both ends."""
    return _is_midnight(dt) and dt.day == 1


def _next_rotation_boundary(anchor, rotate_period):
    """Given a rotation anchor datetime and a rotate_period (n, unit) tuple, return the
    datetime when the next rotation should fire.

    Calendar units (d/w/M/y) snap to calendar boundaries past `anchor`:
      - d: midnight at the start of (anchor.date + n days)
      - w: 00:00 of the Monday at the start of (anchor's-iso-week + n weeks)
      - M: 00:00 on the 1st of (anchor's month + n months)
      - y: 00:00 on Jan 1 of (anchor's year + n years)
    For calendar units the anchor's TIME component is ignored -- the rotation rule
    defines the boundary on its own. anchor matters for "which calendar window?"

    Interval units (s/m/h/t) are simply anchor + (n * unit-seconds)."""
    if not rotate_period:
        return None
    n, unit = rotate_period
    if unit not in _TIMEPERIOD_UNITS:
        return None
    secs, is_calendar = _TIMEPERIOD_UNITS[unit]
    if not is_calendar:
        from datetime import timedelta
        return anchor + timedelta(seconds=n * secs)
    # Calendar boundaries. The LOCKED RULE:
    #   - If anchor is exactly ON a U-boundary at midnight, return anchor + n U-units
    #     (clean cycle close: the rotation_anchor has been set by a previous archive
    #     close to a boundary, and we now compute the next n-unit window's end).
    #   - Otherwise, anchor is mid-window. Return the NEXT U-boundary, regardless of n
    #     (ramp-in close: the first archive after a fresh start / mode change is the
    #     partial leading unit only; clean n-cycles begin from there).
    #
    # The two-cases-per-unit design has a clean forensic signal: the first archive
    # after fresh install is shorter than the configured cadence, and the investigator
    # sees the cadence settle into clean n-unit chunks afterward.
    if unit == "d":
        from datetime import timedelta
        day0 = datetime(anchor.year, anchor.month, anchor.day)   # midnight of anchor
        if _is_midnight(anchor):
            # On boundary: advance n days for the clean n-day window close.
            return day0 + timedelta(days=n)
        # Mid-window: ramp-in close at next midnight.
        return day0 + timedelta(days=1)
    if unit == "w":
        from datetime import timedelta
        days_until_monday = (7 - anchor.weekday()) % 7
        if days_until_monday == 0 and _is_midnight(anchor):
            # Anchor IS Monday-midnight (on boundary): advance n weeks.
            return datetime(anchor.year, anchor.month, anchor.day) \
                + timedelta(weeks=n)
        # Mid-week (or Monday mid-day): ramp-in close at next Monday-midnight.
        if days_until_monday == 0:
            days_until_monday = 7      # Monday mid-day -> next Monday
        return datetime(anchor.year, anchor.month, anchor.day) \
            + timedelta(days=days_until_monday)
    if unit == "M":
        if _is_calendar_month_start(anchor):
            # On boundary (1st 00:00): advance n calendar months.
            return _add_calendar_months(anchor, n)
        # Mid-month: ramp-in close at next 1st.
        if anchor.month == 12:
            return datetime(anchor.year + 1, 1, 1)
        return datetime(anchor.year, anchor.month + 1, 1)
    if unit == "y":
        if (_is_midnight(anchor) and anchor.month == 1 and anchor.day == 1):
            # On boundary (Jan 1 00:00): advance n calendar years.
            return _add_calendar_months(anchor, n * 12)
        # Mid-year: ramp-in close at next Jan 1.
        return datetime(anchor.year + 1, 1, 1)
    return None      # unreachable


def _current_rotation_window_start(now, rotate_period):
    """Given the current wall-clock time and a rotate_period, return the start of the
    CALENDAR window the rule says we're currently inside.

    For CALENDAR units, this is the rule-defined window boundary at or before `now`:
      - 1d: today's midnight
      - 1w: this week's Monday 00:00
      - 1M: this month's 1st at 00:00
      - 1y: this year's Jan 1 at 00:00
      - 2d/2w/2M/2y: snap to N-aligned boundaries (a "1d" archive can be a 2d archive
        with one of two parities; we choose the simplest -- snap to the calendar
        boundary at-or-before `now` regardless of parity).

    For INTERVAL units, there is no calendar-aligned window -- the window depends on
    the engine's anchor (when it started). Returns None for interval units; the caller
    must use rotation_anchor + engine_start_anchor logic instead."""
    if not rotate_period:
        return None
    n, unit = rotate_period
    if unit not in _TIMEPERIOD_UNITS:
        return None
    _secs, is_calendar = _TIMEPERIOD_UNITS[unit]
    if not is_calendar:
        return None        # interval modes have no calendar-aligned window
    if unit == "d":
        return datetime(now.year, now.month, now.day)
    if unit == "w":
        from datetime import timedelta
        monday = now - timedelta(days=now.weekday())
        return datetime(monday.year, monday.month, monday.day)
    if unit == "M":
        return datetime(now.year, now.month, 1)
    if unit == "y":
        return datetime(now.year, 1, 1)
    return None


def _archive_basename(archive_dir, rotate_period, start_dt=None, end_dt=None,
                     reason=""):
    """Pick the archive base name. v0.0.8 naming (was v0.0.7c-style; now driven by
    rotate_period's unit instead of reason-string):

      (a) Calendar-month rotation (rotate_period unit == 'M') AND the archive spans a
          FULL calendar month (both endpoints at 1st-of-month midnight)
          -> FileSystem_<MonthName>_<YYYY>  (e.g. 'June_2026'). Investigator reads it
          straight: 'this is June 2026, intact.'

      (b) EVERYTHING ELSE -> ISO-style span name:
            FileSystem_YYYY-MM-DD_to_YYYY-MM-DD             (whole-day boundaries)
            FileSystem_YYYY-MM-DD-HHMMSS_to_YYYY-MM-DD-HHMMSS  (sub-day boundary at
                                                                either end)
          The filename matches the rotation window. Critically, this includes the
          case where 1M rotation was set but size cap fired mid-month: the moment a
          calendar-month rotation uses span names, the investigator sees at a glance
          'size cap hit this month' -- a forensic signal at the filename layer.

    No _N counter. Spans self-disambiguate. Alphabetical sort = chronological.

    rotate_period is (n, unit) or None. start_dt/end_dt are the rotation window's
    bounds (from rotation_anchor and now)."""
    end = end_dt or datetime.now()
    start = start_dt or end
    is_calendar_month_mode = (
        rotate_period is not None
        and rotate_period[1] == "M"
        and rotate_period[0] == 1                          # 1M only -- 2M/3M never clean
    )
    is_full_calendar_month = (
        is_calendar_month_mode
        and _is_calendar_month_start(start)                # started exactly at 1st 00:00
        and _is_calendar_month_start(end)                  # closing exactly at next 1st 00:00
    )
    if is_full_calendar_month:
        return "FileSystem_%s_%d" % (start.strftime("%B"), start.year)
    # Span naming: include timecode on each side INDEPENDENTLY. A midnight boundary
    # gets just the date; a mid-day boundary gets -HHMMSS.
    return "FileSystem_%s_to_%s" % (
        _archive_format_date(start, not _is_midnight(start)),
        _archive_format_date(end, not _is_midnight(end)),
    )


# --- legal retention -------------------------------------------------------- #
# Retention units mix calendar-accurate and fixed-span on purpose. UNIT SEMANTICS
# (document these for operators):
#   y = calendar YEARS  (leap-aware; 5y = same month/day 5 years ago = 5*12 calendar
#       months, NOT 5*365 fixed days)
#   m = calendar MONTHS (month-length/leap aware; 18m = 18 calendar months ago)
#   t = 30-day TERM units -- NOT calendar months. 18t = 18*30 = 540 fixed days.
#   w = weeks (7 fixed days)
#   d = calendar days (1 day each)
# So 60t (1800 fixed days) and 5y (5 calendar years ~ 1826 days) are close but NOT
# identical; pick the unit matching how the legal requirement is written ("retain 60
# months as 30-day terms" -> 60t; "retain 5 years" -> 5y; "retain 25 years" -> 25y).
# Integer values only (use 18M rather than 1.5y). Blank/None => keep EVERYTHING forever
# (the default). Allowed units and caps: see RETENTION_CAPS below.


def parse_retention(text):
    """Parse a legal-retention term -> (n:int, unit:str) tuple, or None for blank/empty
    (= keep everything) AND for any malformed input (fail-safe: an unparseable term must
    NEVER trigger deletion). Thin wrapper over parse_timeperiod with RETENTION_CAPS.

    Allowed units (d/w/t/M/y). NOTE: 'M' (capital) is calendar months as of v0.0.7d --
    a v0.0.7c-and-earlier 'legal_retention: 18m' will now fail-safe to keep-everything,
    which is the correct safe default for an unparseable config (deletion never
    triggered without an explicit valid term)."""
    return parse_timeperiod(text, RETENTION_CAPS)


def parse_interval(text):
    """Parse a rotation interval -> (n:int, unit:str) tuple, or None on bad/empty input.
    Thin wrapper over parse_timeperiod with ROTATION_CAPS. Returns (n, unit) -- callers
    use _period_advance() for calendar-aware boundary math (calendar units d/w/M/y) or
    seconds-from-anchor math (interval units s/m/h/t).

    v0.0.7d changes:
      - Returns (n, unit) tuple instead of float-seconds. Callers must use
        _period_advance() to compute boundary timestamps.
      - 'd'/'w' now mean CALENDAR days/weeks (was fixed 86400s / 604800s).
      - New units 'M' (calendar months) and 'y' (calendar years).
      - Sub-day caps relaxed to 2-day max for s/m/h to support inter-day cadences."""
    return parse_timeperiod(text, ROTATION_CAPS)


def _sub_calendar_months(dt, months):
    """Legacy thin wrapper -- new code should use _period_advance(dt, n, 'M', -1) or
    _add_calendar_months(dt, -months) directly. Kept for any straggling caller."""
    return _add_calendar_months(dt, -months)


def _retention_horizon(now, term):
    """Given (n, unit), return the cutoff datetime: archives whose ENTIRE month bucket
    is older than this are eligible for pruning. Calendar-aware via _period_advance
    (the same helper rotation uses) -- M/y advance by calendar months/years, d/w
    by calendar days/weeks, t by fixed 30-day terms. Unified math, no special-cases."""
    n, unit = term
    return _period_advance(now, n, unit, direction=-1)


def _bucket_end_date(year, month):
    """The last moment of a calendar month = start of the next month. Used to test
    whether an ENTIRE month bucket is older than the retention horizon (we only prune a
    bucket when even its newest possible record has aged out)."""
    if month == 12:
        return datetime(year + 1, 1, 1)
    return datetime(year, month + 1, 1)


def prune_legal_retention(archive_dir, retention_term):
    """Delete WHOLE month-bucket archives whose entire month has aged out beyond the
    retention horizon. NEVER trims or reopens a sealed (hashed) archive -- only deletes
    complete, fully-expired bundles, so every surviving archive's hash/manifest stays
    intact. A bucket is eligible only when its END-OF-MONTH is older than the horizon,
    guaranteeing we never delete a bucket still holding even one in-term day. No-op if
    retention_term is None (keep everything). retention_term is a (n, unit) tuple from
    parse_retention. Returns count of files deleted.

    v0.0.7c: handles both naming styles.
      - Calendar names (FileSystem_MonthName_YYYY[_legacyN]): the bucket end is the
        last day of that month; delete iff that end is older than the horizon.
      - Span names (FileSystem_YYYY-MM-DD..._to_YYYY-MM-DD...): the file's effective
        end is the second date in the span; delete iff THAT end is older than the
        horizon. This guarantees we never delete a span archive that still holds even
        one in-term day -- the second date IS the last day of data, so if it's older
        than the horizon, every record inside is too. Span-named files are NEVER
        partially trimmed; same whole-file rule as calendar names."""
    if not retention_term:
        return 0
    import re
    month_num = {datetime(2000, m, 1).strftime("%B"): m for m in range(1, 13)}
    horizon = _retention_horizon(datetime.now(), retention_term)
    term_str = "%d%s" % retention_term
    rx_cal = re.compile(r"FileSystem_([A-Za-z]+)_(\d{4})(?:_|\.)")
    rx_span = re.compile(
        r"FileSystem_(\d{4})-(\d{2})-(\d{2})(?:-\d{6})?"
        r"_to_(\d{4})-(\d{2})-(\d{2})(?:-\d{6})?")
    deleted = 0
    try:
        entries = os.listdir(archive_dir)
    except Exception:
        return 0
    for f in entries:
        if not f.lower().endswith((".zip", ".manifest", ".evtx")):
            continue
        effective_end = None
        m = rx_cal.match(f)
        if m and m.group(1) in month_num:
            effective_end = _bucket_end_date(
                int(m.group(2)), month_num[m.group(1)])
        else:
            m = rx_span.match(f)
            if m:
                # The second date in the span IS the last day of data. If THAT day
                # is older than the horizon, every record inside is too -- safe to
                # delete the whole file.
                try:
                    effective_end = datetime(
                        int(m.group(4)), int(m.group(5)), int(m.group(6)),
                        23, 59, 59)
                except Exception:
                    continue
        if effective_end is None:
            continue
        if effective_end < horizon:
            try:
                os.remove(os.path.join(archive_dir, f))
                deleted += 1
                logger.info("legal-retention: pruned %s (aged out beyond %s)",
                            f, term_str)
            except Exception as exc:
                logger.error("legal-retention: failed to prune %s: %r", f, exc)
    if deleted:
        emit_operational(904, "legal-retention pruned %d aged-out archive file(s) "
                         "(term=%s)" % (deleted, term_str))
    return deleted

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
def setup_logging(to_console, archive_dir):
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    try:
        os.makedirs(archive_dir, exist_ok=True)
        fh = logging.handlers.RotatingFileHandler(
            os.path.join(archive_dir, DIAG_LOG_NAME),
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
def register_event_source(archive_dir):
    """Register the FileSystem channel + source and size it to 4 GB. Interactive
    sizing prompt is intentionally omitted (kept simple; 4 GB on creation)."""
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
    904: ("I", "Archive written"),
    914: ("I", "Engine started"),
    915: ("I", "Engine stopped"),
    916: ("W", "Drive/journal failure"),
    917: ("W", "Degraded state"),
    918: ("E", "Archive completeness gap (expected month-bucket missing)"),
    919: ("W", "Volume present but has no active USN journal (not monitored)"),
    920: ("W", "Volume present but filesystem cannot host a USN journal (not monitored)"),
    921: ("W", "Volume present but is a remote/network share (no local journal; not monitored)"),
    922: ("E", "Archive sign/hash failure"),
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
def run_drive_engine(drive_root, should_stop, host_ctx_base, archive_dir):
    """Open one volume, capture its USN journal start-to-real-time. First read
    starts at FirstUsn to grab the existing backlog (retroactive), then follows
    NextUsn. Emits every record to the FileSystem channel -- EXCEPT the engine's
    own write paths (self-write-loop suppression), the one capture-time exception."""
    device = drive_root_to_device(drive_root)
    self_paths = _build_self_paths(archive_dir)
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


def _build_self_paths(archive_dir):
    """Loop-prevention suppression -- NOT forensic filtering. We drop exactly the
    engine's own NOISE (writes that would feed back into the journal every cycle),
    while KEEPING everything that is a real artifact: archives, manifests,
    device_state.json, usnmon.log -- tampering with any of those is itself evidence.

    Suppressed (deliberately minimal):
      * the LIVE FileSystem.evtx ONLY, at its real winevt\\Logs path -- so that when a
        copy is exported to the archive dir, THAT write IS captured (moving evidence
        out is exactly what we want recorded). A file merely *named* FileSystem.evtx
        anywhere else is NOT suppressed.
      * usnmon.cfg / usnmon.cfg.tmp anywhere (the 10-second cursor write + its atomic
        temp/rename churn) -- location is user-configurable, so match by name.
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
        # Hash the state file too (an output that matters).
        write_manifest(p, os.path.dirname(p))
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
def _parse_anchor(s):
    """Parse a 'YYYY-MM-DD HH:MM:SS' anchor string from config. Returns datetime or
    None on miss/error (safe -- caller treats missing anchor as fresh-install case)."""
    if not s:
        return None
    try:
        return datetime.strptime(str(s), "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None


def _run_restart_detection(archive_dir, host_ctx, now, rotate_period,
                           persisted_anchor, rule_window_start, cfg):
    """v0.0.8 restart detection. Decides which of four cases applies and acts:

      (1) FRESH INSTALL / no persisted anchor: initialize rotation_anchor to either
          the rule-derived window start (calendar mode) or 'now' (interval mode).
          No event emitted -- the 914 already documents the start.

      (2) CLOCK ANOMALY (persisted_anchor > now): emit 926. Set rotation_anchor to
          'now' since the persisted value is no longer trustworthy.

      (3) SIZE-CAP SPLIT (persisted_anchor is INSIDE the current window): we're
          continuing an in-progress window from where the previous size-cap closure
          left off. Use persisted value as-is for the next archive.

      (4) GAP (persisted_anchor is BEFORE the current window): at least one rotation
          boundary was missed. For interval modes, also write a partial archive of
          whatever was in the channel at engine_stop. Emit 925. Then reset
          rotation_anchor to the new window start (rule-derived for calendar,
          'now' for interval)."""
    new_anchor = None
    n_unit = rotate_period
    is_calendar = bool(rule_window_start)

    if persisted_anchor is None:
        # Case 1: fresh install or first run.
        new_anchor = rule_window_start or now
        logger.info("rotation: fresh start anchor=%s", new_anchor.strftime(
            "%Y-%m-%d %H:%M:%S"))
    elif persisted_anchor > now:
        # Case 2: clock anomaly. Emit 926 and reset anchor to now.
        delta_sec = (persisted_anchor - now).total_seconds()
        emit_operational(926, "Clock anomaly: persisted rotation_anchor %s is later "
                         "than now %s by %.0fs. Setting rotation_anchor=now."
                         % (persisted_anchor.strftime("%Y-%m-%d %H:%M:%S"),
                            now.strftime("%Y-%m-%d %H:%M:%S"), delta_sec))
        new_anchor = rule_window_start or now
    elif is_calendar:
        # Calendar mode: compare persisted_anchor to rule-derived window start.
        if persisted_anchor >= rule_window_start:
            # Case 3 (size-cap split): we're inside this window, persisted is the
            # in-window restart point. Keep it -- the in-progress archive will be
            # closed at the next rule boundary using this as its start.
            new_anchor = persisted_anchor
            logger.info("rotation: continuing in-progress window from %s",
                        persisted_anchor.strftime("%Y-%m-%d %H:%M:%S"))
        else:
            # Case 4 (gap): at least one rotation boundary was missed. Emit 925.
            # For calendar modes, no partial archive is needed -- the in-progress
            # channel will close at the next boundary covering the visible
            # 915/914 gap markers inside.
            n, unit = n_unit
            emit_operational(925, "Archiving gap detected: persisted "
                             "rotation_anchor %s precedes current window start %s "
                             "(missed >=1 %d%s rotation window). Resetting "
                             "rotation_anchor to current window start."
                             % (persisted_anchor.strftime("%Y-%m-%d %H:%M:%S"),
                                rule_window_start.strftime("%Y-%m-%d %H:%M:%S"),
                                n, unit))
            new_anchor = rule_window_start
    else:
        # Interval mode. Compute what the NEXT boundary should have been from the
        # persisted anchor; if it's in the past, we missed it.
        next_boundary = _next_rotation_boundary(persisted_anchor, rotate_period)
        if next_boundary and next_boundary > now:
            # Case 3 (size-cap split or simply mid-window): continue normally.
            new_anchor = persisted_anchor
            logger.info("rotation: continuing interval window from %s "
                        "(next close at %s)",
                        persisted_anchor.strftime("%Y-%m-%d %H:%M:%S"),
                        next_boundary.strftime("%Y-%m-%d %H:%M:%S"))
        else:
            # Case 4 (gap): we crossed at least one full interval boundary while down.
            # For interval modes, ALSO write a partial archive of whatever was in the
            # channel pre-stop (the records belong to the previous cycle which was
            # supposed to close at next_boundary; we close it now with that named).
            n, unit = n_unit
            try:
                archive_one(archive_dir, reason="restart-partial",
                            rotate_period=rotate_period,
                            forced_start=persisted_anchor, forced_end=now)
                emit_operational(925, "Archiving gap detected (interval mode): "
                                 "persisted rotation_anchor %s + interval %d%s "
                                 "expired before restart at %s. Wrote partial "
                                 "archive of in-channel records; new cycle "
                                 "anchored at restart time."
                                 % (persisted_anchor.strftime("%Y-%m-%d %H:%M:%S"),
                                    n, unit,
                                    now.strftime("%Y-%m-%d %H:%M:%S")))
            except Exception as exc:
                logger.error("restart-partial archive failed: %r", exc)
                emit_operational(925, "Archiving gap detected (interval mode): "
                                 "could not write partial archive: %r" % exc)
            new_anchor = now
    # Persist the resolved anchor.
    cfg = read_config()
    cfg["rotation_anchor"] = new_anchor.strftime("%Y-%m-%d %H:%M:%S")
    _write_config_atomic(cfg)


def run_engine(should_stop, archive_dir, rotate_period=None):
    """Main engine entry. v0.0.8 changes the signature: rotate_period is now a
    (n, unit) tuple from parse_interval(), NOT a raw seconds count. The unit is used
    to drive calendar-vs-interval boundary math via _period_advance() /
    _next_rotation_boundary() / _current_rotation_window_start().

    Startup performs RESTART DETECTION using three persisted state fields:
      - install_month: when usnmon was first installed (already existed)
      - engine_start_anchor: when THIS session started (every restart)
      - rotation_anchor: the start of the current rotation window (set on every
        successful archive close)

    Four restart cases are distinguished:
      (1) Clean continuation: persisted rotation_anchor matches the rule-derived
          current window start. Continue normally.
      (2) Size-cap split: persisted rotation_anchor is AFTER the calendar-window start
          (we're inside a window where a size-cap rotation already happened). Use the
          persisted value as the start of the next archive.
      (3) Gap (engine was down across >=1 rotation boundary): persisted rotation_anchor
          is BEFORE the calendar-window start. Emit a NEW 925 "Archiving Gap
          Detected" event documenting the missed window(s). For interval modes also
          emit a partial closing archive named for (rotation_anchor -> engine_start).
      (4) Clock anomaly: persisted rotation_anchor is in the FUTURE relative to now.
          Emit a NEW 926 "Clock Anomaly Detected" event documenting the inconsistency
          between persisted state and the system clock."""
    host_ctx = gather_host_context()
    # Startup mode recorded at install (read back from Windows via QueryServiceConfig).
    startup = read_config().get("service_start_type", "unknown")
    emit_operational(914, "host=%s id=%s startup=%s"
                     % (host_ctx.get("Hostname"), host_ctx.get("MachineId"), startup))

    # --- v0.0.8: rotation state machine -------------------------------------------
    # Record engine_start_anchor for THIS session. Every restart updates this.
    now = datetime.now()
    cfg = read_config()
    persisted_rot_anchor_str = cfg.get("rotation_anchor")
    persisted_rot_anchor = _parse_anchor(persisted_rot_anchor_str)
    cfg["engine_start_anchor"] = now.strftime("%Y-%m-%d %H:%M:%S")
    _write_config_atomic(cfg)
    # Compute the rule-derived window start. Calendar units have a deterministic value
    # ("today's midnight", "this Monday", etc.); interval units don't (their window
    # depends on the anchor, which is exactly what we're trying to validate).
    rule_window_start = _current_rotation_window_start(now, rotate_period) \
        if rotate_period else None
    # Decide which case we're in and what to do about it.
    _run_restart_detection(archive_dir, host_ctx, now, rotate_period,
                           persisted_rot_anchor, rule_window_start, cfg)
    # ---------------------------------------------------------------------- end ---

    # Legal-retention term from config. None/blank => keep everything forever.
    retention_term = parse_retention(read_config().get("legal_retention"))
    if retention_term:
        logger.info("Legal retention: %d%s; aged-out month buckets are pruned at "
                    "startup and on each month boundary.",
                    retention_term[0], retention_term[1])
        try:
            prune_legal_retention(archive_dir, retention_term)   # prune at startup
        except Exception as exc:
            logger.error("legal-retention startup prune: %r", exc)
    threads = {}   # drive_root -> (thread, stop_event)
    # Volumes recorded once as present-but-unmonitorable, so they are NOT retried
    # every poll (no thrash). In-memory only -> a reboot re-classifies and re-emits,
    # which is intended (the volume may have changed). Maps root -> category.
    skipped = {}

    def start_drive(root):
        ev = threading.Event()
        t = threading.Thread(target=run_drive_engine,
                             args=(root, ev.is_set, host_ctx, archive_dir),
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

    last_rotation_check = 0.0
    last_letters = enumerate_drive_letters()
    # v0.0.8: compute when the NEXT rotation boundary is, from the current
    # rotation_anchor + rotate_period. Recomputed on every successful archive close.
    def _read_next_boundary():
        anchor = _parse_anchor(read_config().get("rotation_anchor"))
        if anchor is None or rotate_period is None:
            return None
        return _next_rotation_boundary(anchor, rotate_period)
    next_boundary = _read_next_boundary()
    if rotate_period:
        n, unit = rotate_period
        secs, is_calendar = _TIMEPERIOD_UNITS.get(unit, (0, False))
        logger.info("Rotation: every %d%s (%s) OR %d-byte size cap, whichever first."
                    "%s", n, unit, "calendar" if is_calendar else "interval",
                    ROTATE_BYTES,
                    "  next close: %s" % next_boundary.strftime("%Y-%m-%d %H:%M:%S")
                    if next_boundary else "")
    else:
        logger.info("Rotation: NO period configured -- only size cap (%d bytes) "
                    "will rotate.", ROTATE_BYTES)
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

            # --- Rotation triggers ---
            # Size cap: always checked (catches a runaway between time boundaries).
            if time.time() - last_rotation_check > 60:
                try:
                    maybe_rotate(archive_dir, rotate_period)
                except Exception as exc:
                    logger.error("rotation check: %r", exc)
                last_rotation_check = time.time()
                # If size-rotate fired, the rotation_anchor moved -> recompute the
                # next boundary for the time-leg check below.
                next_boundary = _read_next_boundary()

            # Time leg: fire when we cross the next rule-derived boundary.
            if next_boundary is not None and datetime.now() >= next_boundary:
                try:
                    archive_one(archive_dir, reason="time", rotate_period=rotate_period)
                except Exception as exc:
                    logger.error("time rotate: %r", exc)
                # On a calendar-month boundary, also prune aged-out buckets.
                if rotate_period and rotate_period[1] in ("M", "y"):
                    if retention_term:
                        try:
                            prune_legal_retention(archive_dir, retention_term)
                        except Exception as exc:
                            logger.error("legal-retention prune: %r", exc)
                # Recompute the next boundary from the new anchor.
                next_boundary = _read_next_boundary()

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
# Rotation / archive  (compress -> 4-hash -> sign -> sidecar manifest)
# --------------------------------------------------------------------------- #
def _channel_size_bytes():
    try:
        import subprocess
        out = subprocess.run(["wevtutil", "gli", LOG_CHANNEL],
                             capture_output=True, text=True, timeout=15).stdout
        for line in out.splitlines():
            if "fileSize" in line:
                return int(line.split(":")[1].strip())
    except Exception:
        pass
    return 0


def maybe_rotate(archive_dir, rotate_period=None):
    """Size-cap rotation: rotate when the live channel hits 3.5 GB, regardless of the
    time leg (calendar or interval). v0.0.8: rotate_period is a (n, unit) tuple."""
    if _channel_size_bytes() < ROTATE_BYTES:
        return
    archive_one(archive_dir, reason="size", rotate_period=rotate_period)


def archive_one(archive_dir, reason="manual", rotate_period=None,
                forced_start=None, forced_end=None):
    """Export -> 4-hash+sign the EVTX -> write its .manifest -> zip the EVTX AND its
    manifest together -> 904/922.

    v0.0.8 naming: filename represents the ROTATION WINDOW (the span this archive was
    *supposed* to cover), not the timestamps of first/last events in it. This is what
    the rotation_anchor design buys us: the filename means 'this archive is the
    rotation window from <start> to <end>; coverage gaps within (engine stopped, etc.)
    are documented as 915/914 events INSIDE'.

    Start time = rotation_anchor from config (or forced_start for restart-partial
    archives). End time = now (or forced_end for forced bounds).

    After successful close, rotation_anchor is updated to the next window's start (the
    current end time, since the next archive's coverage begins where this one ends).

    Order matters forensically: the hashes/signature must cover the EVIDENCE (the
    .evtx), NOT the zip container. Hashes are taken at rest; evidence + proof are
    bound inside one zip so they can never be separated."""
    import subprocess
    os.makedirs(archive_dir, exist_ok=True)

    # Determine start/end of THIS archive's window.
    now = datetime.now()
    end_dt = forced_end or now
    if forced_start is not None:
        start_dt = forced_start
    else:
        cfg = read_config()
        start_dt = _parse_anchor(cfg.get("rotation_anchor")) or end_dt

    # Compute final basename FIRST -- no temp-name-then-rename dance anymore, because
    # the filename comes from the rotation window, not the file's contents.
    base = _archive_basename(archive_dir, rotate_period, start_dt, end_dt, reason)
    month = end_dt.strftime("%Y-%m")
    evtx = os.path.join(archive_dir, base + ".evtx")

    # Collision protection: if a duplicate close happened in the same second (or a
    # leftover from a crash), suffix with _dupN so forensic evidence is never lost.
    if os.path.exists(evtx):
        i = 2
        while os.path.exists(os.path.join(archive_dir, "%s_dup%d.evtx" % (base, i))):
            i += 1
        evtx = os.path.join(archive_dir, "%s_dup%d.evtx" % (base, i))

    try:
        subprocess.run(["wevtutil", "epl", LOG_CHANNEL, evtx],
                       capture_output=True, timeout=600, check=True)
        subprocess.run(["wevtutil", "cl", LOG_CHANNEL],
                       capture_output=True, timeout=60)
    except Exception as exc:
        emit_operational(916, "export/clear: %r" % exc)
        return None

    bundle_base = os.path.splitext(evtx)[0]
    bundle = bundle_base + ".zip"
    try:
        manifest = write_manifest(evtx, archive_dir, month=month)
        common.build_monthly_bundle(bundle, [evtx, manifest])
        for loose in (evtx, manifest):
            try:
                os.remove(loose)
            except Exception:
                pass
        emit_operational(904, "%s bundle=%s" % (reason, os.path.basename(bundle)))
        # Persist the new rotation_anchor: this archive's end becomes the next
        # archive's start. Skip for restart-partial closes (the caller has its own
        # anchor logic).
        if reason != "restart-partial":
            try:
                cfg = read_config()
                cfg["rotation_anchor"] = end_dt.strftime("%Y-%m-%d %H:%M:%S")
                _write_config_atomic(cfg)
            except Exception as exc:
                logger.error("rotation_anchor persist: %r", exc)
        return bundle
    except Exception as exc:
        emit_operational(922, "bundle/manifest: %r" % exc)
        return None


def _signing_key():
    """Load the private signing key if configured (env var path to a PEM). Returns
    None if unset -> manifest carries hashes only (still tamper-evident; not signed).
    Production: ship/configure a key. Inspection-verified for the Windows path."""
    pem = os.environ.get("USNMON_SIGNING_KEY", "").strip()
    if not pem or not os.path.exists(pem):
        return None
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        with open(pem, "rb") as f:
            return load_pem_private_key(f.read(), password=None)
    except Exception:
        return None


def write_manifest(target_file, archive_dir, month=None):
    """Sidecar manifest: four hashes (one read pass) + optional signature.
    NEVER an ADS -- a sidecar survives FAT/exFAT/S3/Dropbox/email/zip transport.
    Returns the manifest path."""
    import hashlib
    import json
    h = {"md5": hashlib.md5(), "sha1": hashlib.sha1(),
         "sha256": hashlib.sha256(), "sha512": hashlib.sha512()}
    size = 0
    with open(target_file, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            size += len(chunk)
            for d in h.values():
                d.update(chunk)   # one read, four digests in parallel
    manifest = {
        "file": os.path.basename(target_file),
        "size": size,
        "month": month or datetime.now().strftime("%Y-%m"),
        "md5": h["md5"].hexdigest(),
        "sha1": h["sha1"].hexdigest(),
        "sha256": h["sha256"].hexdigest(),
        "sha512": h["sha512"].hexdigest(),
        "generated": now_utc_str(),
        "generator": "usnmon %s" % common.SCHEMA_VERSION,
        "note": "md5/sha1 legacy-interop only (collision-broken); sha256/sha512 authoritative",
    }
    key = _signing_key()
    if key is not None:
        try:
            manifest["signature"] = common.sign_doc(manifest, key)
        except Exception as exc:
            logger.error("manifest sign: %r", exc)
    mpath = target_file + ".manifest"
    with open(mpath, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
    return mpath


def check_completeness(archive_dir, install_month):
    """Per-month-bucket FLOOR: every COMPLETED month from install->last-month must have
    >=1 archive. Extras (multiple 3.5GB rotations in a month, or sub-day interval files)
    are fine; a missing month-bucket is the 918 alarm. Returns list of missing 'YYYY-MM'.

    The CURRENT (in-progress) month is excluded from the expectation: its archive isn't
    written until the calendar-month rotation fires on the 1st of the following month, so
    a quiet current month legitimately has no archive yet and must NOT be flagged. Only
    a missing *completed* month is a real gap. (A current month that DID hit the 3.5GB
    size cap will have an archive, which is fine -- we just don't *require* one.)

    Recognizes BOTH naming styles (v0.0.7c changed the scheme):
      - Calendar names: FileSystem_<MonthName>_<Year>[_optional_legacy_N]  -- the new
        clean form 'FileSystem_June_2026' AND the legacy v0.0.7 form
        'FileSystem_June_2026_3' both count as covering June 2026.
      - Span names: FileSystem_YYYY-MM-DD[-HHMMSS]_to_YYYY-MM-DD[-HHMMSS] -- a span is
        considered to COVER every calendar month its date range touches (inclusive of
        partial months at either end), so a 30-day term spanning June 17 -> July 16
        covers both June 2026 and July 2026. This is what completeness really means:
        was data captured for that month, not 'is the name labeled with that month.'"""
    import re
    month_num = {datetime(2000, m, 1).strftime("%B"): m for m in range(1, 13)}
    have = set()
    # Calendar-name pattern: FileSystem_<MonthName>_<4digit year>[_<rest>]?
    rx_cal = re.compile(r"FileSystem_([A-Za-z]+)_(\d{4})(?:_|\.)")
    # Span-name pattern: FileSystem_YYYY-MM-DD[-HHMMSS]_to_YYYY-MM-DD[-HHMMSS]
    rx_span = re.compile(
        r"FileSystem_(\d{4})-(\d{2})-(\d{2})(?:-\d{6})?"
        r"_to_(\d{4})-(\d{2})-(\d{2})(?:-\d{6})?")
    try:
        for f in os.listdir(archive_dir):
            if not f.lower().endswith((".zip", ".manifest")):
                continue
            m = rx_cal.match(f)
            if m and m.group(1) in month_num:
                have.add("%04d-%02d" % (int(m.group(2)), month_num[m.group(1)]))
                continue
            m = rx_span.match(f)
            if m:
                sy, sm = int(m.group(1)), int(m.group(2))
                ey, em = int(m.group(4)), int(m.group(5))
                # Walk every (year, month) tuple from start through end inclusive.
                y, mo = sy, sm
                while (y, mo) <= (ey, em):
                    have.add("%04d-%02d" % (y, mo))
                    mo += 1
                    if mo > 12:
                        mo = 1; y += 1
    except Exception:
        return []
    # Expected buckets: install_month .. the LAST COMPLETED month (i.e. the month
    # BEFORE the current one). The current in-progress month is not yet required.
    iy, im = map(int, install_month.split("-"))
    now = datetime.now()
    # Last completed month = current month minus one.
    if now.month == 1:
        ey, em = now.year - 1, 12
    else:
        ey, em = now.year, now.month - 1
    missing = []
    y, mo = iy, im
    while (y, mo) <= (ey, em):
        bucket = "%04d-%02d" % (y, mo)
        if bucket not in have:
            missing.append(bucket)
        mo += 1
        if mo > 12:
            mo = 1; y += 1
    return missing


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
            self._archive_dir = read_archive_dir()

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self.h_stop)

        def should_stop(self):
            return win32event.WaitForSingleObject(self.h_stop, 0) == \
                win32event.WAIT_OBJECT_0

        def SvcDoRun(self):
            setup_logging(False, self._archive_dir)
            register_event_source(self._archive_dir)
            rotate_period = parse_interval(read_config().get("rotate_interval", ""))
            run_engine(self.should_stop, self._archive_dir, rotate_period)


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
# Config (minimal: just archive_dir + install month -- NO signed ruleset)
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
      2. settings keys (the things you might want to change with `usnmon config`),
      3. cursors LAST (the runtime state the README is warning you not to edit).
    This applies on every write, so a v0.0.7 file with cursors-first will be re-ordered
    on its next save (typically the next cursor flush, ~10s after the upgraded engine
    starts)."""
    import json
    cfg = dict(cfg)
    readme = ("DO NOT EDIT BY HAND. This file holds live runtime state "
              "(USN cursors) updated every ~10s; hand-editing can corrupt it "
              "and break gap-free capture. Change settings with: usnmon config")
    # Stable settings order. Anything not listed here gets appended alphabetically
    # between settings and cursors (forward-compatible: an unknown key from a newer
    # version still round-trips, just at a deterministic spot).
    SETTINGS_ORDER = ("archive_dir", "rotate_interval", "legal_retention",
                      "service_start_type", "install_month",
                      "engine_start_anchor", "rotation_anchor")
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


def read_archive_dir():
    """Return the configured archive directory, VALIDATED. If the stored value is
    missing or fails sanitization (e.g. it was tampered with forbidden characters or a
    traversal), fall back to the safe default rather than letting a malformed path reach
    filesystem operations. All config values are data; this one touches the FS, so it is
    validated on every read."""
    raw = read_config().get("archive_dir", DEFAULT_ARCHIVE_DIR)
    ok, result = _v_archive_dir(str(raw))
    if not ok:
        logger.warning("configured archive_dir %r invalid (%s); using default %s",
                       raw, result, DEFAULT_ARCHIVE_DIR)
        return DEFAULT_ARCHIVE_DIR
    return result


def write_config(archive_dir):
    cfg = read_config()
    cfg["archive_dir"] = archive_dir
    cfg.setdefault("install_month", datetime.now().strftime("%Y-%m"))
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


# --- time-period parsing (unified for rotation AND retention) -------------- #
#
# Every '<n><unit>' time-period in usnmon -- rotation cadence AND retention horizon --
# is parsed by the SAME function and obeys the SAME unit table. This is what makes
# `--log-interval 1M` (rotate every calendar month) and `--legal-retention 25y` (keep
# 25 calendar years of evidence) syntactically consistent rather than two parallel
# vocabularies.
#
# Each unit is either CALENDAR (boundaries are date-arithmetic: next midnight, next
# Monday 00:00, next 1st-of-month, etc., leap- and month-length-aware) or INTERVAL
# (boundaries are a fixed seconds count from a reference point). The unit's nature is
# captured per-unit in _TIMEPERIOD_UNITS and dispatches automatically via
# _period_advance(). Substitution gives flexibility without ambiguity:
#   "every calendar week"           -> 1w
#   "every 7 days from start"       -> 7d   (still calendar -- start aligns to midnight)
#   "every 7*24 = 168 hours from start" -> 168h (interval -- arbitrary anchor)
#   "every calendar month"          -> 1M
#   "every 30 days from start"      -> 1t   (interval -- 30-day fixed term)
#
# CRITICAL: 'm' is MINUTES (interval), 'M' (uppercase) is calendar MONTHS. This is
# the ONE case-sensitive distinction in the whole scheme; everything else is lower-case.
# A v0.0.7c-and-earlier config using 'm' for legal-retention months MUST be migrated
# to 'M'; the new parser rejects 'm' on retention configs (sub-day intervals make no
# sense for retention) -- bad input fails safe (= keep everything).

_TIMEPERIOD_UNITS = {
    # unit: (seconds-per, calendar?)  -- seconds-per is for interval units; calendar
    # units carry it for fixed-interval estimation only (rotation-window math uses
    # date arithmetic, NOT this number).
    "s": (1,        False),
    "m": (60,       False),
    "h": (3600,     False),
    "d": (86400,    True),       # calendar day: next-midnight boundaries
    "w": (604800,   True),       # calendar week: next-Monday-00:00 boundaries (ISO 8601)
    "t": (2592000,  False),      # 30-day "term": fixed 30*24*3600s interval
    "M": (2629800,  True),       # calendar month (avg secs for estimation; real math
                                 # uses _sub_calendar_months / _add_calendar_months)
    "y": (31557600, True),       # calendar year (avg secs; real math via date arith)
}

# Per-use-case caps: each unit has a max-N appropriate to that use case. Caller passes
# the table to parse_timeperiod; missing entries mean "this unit not allowed here."
ROTATION_CAPS = {
    "s": 172800,    # 2 days in seconds
    "m": 2880,      # 2 days in minutes
    "h": 336,       # 2 weeks in hours (allows weird inter-day cadences like 36h)
    "d": 180,       # ~6 months in calendar days
    "w": 52,        # 1 year in weeks
    "t": 12,        # 1 year in 30-day terms
    "M": 12,        # 1 calendar year in months
    "y": 1,         # 1 calendar year (rotation longer than a year weakens integrity)
}
RETENTION_CAPS = {
    # Sub-day units (s/m/h) intentionally OMITTED -- retention shorter than a day is
    # nonsensical (you'd be pruning archives that haven't even been written).
    "d": 3650,      # 10 years in days
    "w": 520,       # 10 years in weeks
    "t": 120,       # 10 years in 30-day terms
    # M/y push to 25y: real-world drivers like pediatric medical-records retention
    # (age of majority + 3y = 21y in many US states; EMR systems must demonstrate
    # the underlying SQL database file's life across that window).
    "M": 300,       # 25 years in calendar months
    "y": 25,        # 25 calendar years
}


def parse_timeperiod(text, caps):
    """Parse '<N><unit>' (e.g. '6M', '90d', '1y', '24h') into a (n:int, unit:str) tuple
    appropriate for the supplied caps table. Returns None for blank input (= caller's
    'unset' semantics: keep-everything for retention, no-override for rotation) AND for
    ANY malformed input (fail-safe: an unparseable spec must NEVER produce a usable
    value, so an attacker-controlled config can't smuggle through a hostile cadence).

    Integer magnitudes only -- fractional periods like '0.5y' are rejected; use a finer
    unit ('6M', '180d', etc.). Case is significant on 'm' vs 'M' (the only such pair in
    the scheme): 'm' = minutes, 'M' = calendar months. All other letters are lower-case.

    `caps` is one of ROTATION_CAPS or RETENTION_CAPS (or any compatible {unit: max_n}
    dict). A unit not in `caps` is rejected (e.g. '6h' for retention -> None). A
    magnitude > caps[unit] is rejected (e.g. '50y' for rotation -> None)."""
    if not text or not str(text).strip():
        return None
    import re as _re
    # Strict: digits-only magnitude, single-letter unit, case-significant.
    mo = _re.fullmatch(r"\s*([0-9]{1,5})\s*([smhdwtMy])\s*", str(text))
    if not mo:
        return None
    n = int(mo.group(1))
    unit = mo.group(2)
    if unit not in caps:
        return None              # disallowed for this use case
    if n < 1 or n > caps[unit]:
        return None              # out-of-range magnitude
    return (n, unit)


def _add_calendar_months(dt, months):
    """Add N calendar months to dt; clamps the day to the target month's last valid day
    (so e.g. Jan 31 + 1 month -> Feb 28/29). Leap- and month-length-aware. Mirror of
    _sub_calendar_months which already existed for retention horizon math."""
    import calendar
    total = (dt.year * 12 + (dt.month - 1)) + months
    y, m = divmod(total, 12)
    m += 1
    day = min(dt.day, calendar.monthrange(y, m)[1])
    return dt.replace(year=y, month=m, day=day)


def _period_advance(dt, n, unit, direction=1):
    """Move `dt` forward (+1) or backward (-1) by N units, using CALENDAR-AWARE math
    for calendar units (d/w/M/y) and FIXED-INTERVAL math for interval units (s/m/h/t).
    This is the one helper rotation and retention both use to translate a time-period
    into an actual datetime boundary."""
    if unit not in _TIMEPERIOD_UNITS:
        return dt        # safe pass-through; parse_timeperiod prevents reaching here
    secs, is_calendar = _TIMEPERIOD_UNITS[unit]
    if is_calendar:
        # Calendar-aware arithmetic per unit.
        from datetime import timedelta as _td
        if unit == "d":
            return dt + _td(days=direction * n)
        if unit == "w":
            return dt + _td(weeks=direction * n)
        if unit == "M":
            return _add_calendar_months(dt, direction * n)
        if unit == "y":
            # Calendar years preserve month/day; clamp Feb 29 -> Feb 28 in non-leap.
            return _add_calendar_months(dt, direction * n * 12)
    # Interval units: fixed seconds from dt.
    from datetime import timedelta as _td
    return dt + _td(seconds=direction * n * secs)


# --- config editor (`usnmon config`) ---------------------------------------- #
# User-editable settings ONLY. Runtime/derived keys (cursors, install_month, _README)
# are deliberately NOT exposed -- the user cannot see or edit the cursor block, so they
# can never corrupt capture continuity through this tool. Each entry: (config-key,
# label, validator). Validator returns (ok, normalized_value_or_msg).
#
# SECURITY: input SANITIZATION, not code detection. Every value is treated as DATA and
# is never executed/eval'd anywhere. Validators strip characters invalid for the input
# type and REJECT malformed values rather than coercing them. This is defense in depth
# for the config-edit surface; it is not a claim to detect "injected code" (which is
# undecidable) -- it is strict, bounded input validation.

# Characters never legitimate in a Windows path value (shell/redirection/quote/control
# metacharacters and the reserved < > | " * ? chars). Stripped on input.
_PATH_FORBIDDEN = set('<>"|*?;&`$\n\r\t\x00') | {chr(c) for c in range(32)}

def _v_archive_dir(s):
    # Benign normalization only: trim whitespace and a single layer of surrounding
    # quotes. Forbidden characters cause REJECTION (not silent stripping) -- silently
    # cleaning 'C:\evil|<>bad' into 'C:\evilbad' would accept a path the user never
    # typed; for the engine read path there's no human to confirm the cleaned result.
    s = s.strip().strip('"').strip("'").strip()
    if not s:
        return False, "path cannot be empty"
    bad = sorted(_PATH_FORBIDDEN & set(s))
    if bad:
        shown = "".join(c for c in bad if c.isprintable()) or "control chars"
        return False, "path contains forbidden character(s): %s" % shown
    import re as _re
    if not _re.match(r"^([A-Za-z]:\\|\\\\)", s):
        return False, "use an absolute path, e.g. C:\\FileSystem_Archives"
    if ".." in s.replace("\\", "/").split("/"):
        return False, "path must not contain '..' (traversal)"
    if len(s) > 248:
        return False, "path too long (max 248 chars)"
    return True, s

def _v_interval(s):
    s = s.strip()
    if not s:
        return True, ""        # cleared -> calendar-month rotation by default
    # Reject anything outside the expected alphabet rather than silently stripping it.
    # parse_interval is the strict gate; this regex is a fast pre-check that lets us
    # give a unit-list error message. Case-significant: m=minutes, M=calendar months.
    import re as _re
    if not _re.fullmatch(r"[0-9]+[smhdwtMy]", s):
        return False, ("use e.g. 10m, 6h, 1d, 2w, 1t, 1M, 1y "
                       "(m=minutes, M=calendar months); empty = default")
    return (True, s) if parse_interval(s) is not None else \
        (False, "magnitude out of range; check ROTATION_CAPS for the per-unit max")

def _v_retention(s):
    s = s.strip().strip('"').strip("'")
    if not s:
        return True, ""        # cleared -> keep everything
    # Reject (don't strip) -- '65.4y' must NOT become '654y'. Integer + unit only.
    # v0.0.8: 'M' = calendar months; 'm' (minutes) is NOT valid for retention.
    import re as _re
    if not _re.fullmatch(r"[0-9]+[dwtMy]", s):
        return False, ("use e.g. 25y, 18M, 90d, 18t, 26w, or empty to keep "
                       "everything (M = calendar months; m = minutes, not valid here)")
    return (True, s) if parse_retention(s) is not None else \
        (False, "bad term (or out of range); use e.g. 25y, 18M, 90d, 18t, 26w")


_CONFIG_EDITABLE = [
    ("archive_dir",        "Archive directory",      _v_archive_dir),
    ("rotate_interval",    "Rotation interval",      _v_interval),
    ("legal_retention",    "Legal retention term",   _v_retention),
]
# NOTE: service_start_type is intentionally NOT editable here. With Option A the start
# mode is owned by Windows -- set at install via pywin32's native --startup flag and
# read back via QueryServiceConfig -- so it is display-only (shown by `check`), changed
# only by reinstalling with --startup. Editing it in this tool would desync the cfg from
# the actual service, so it is excluded.

# The complete set of keys usnmon itself writes. Anything else in the cfg is unexpected
# (stray/injected) and is reported by the integrity check.
_CONFIG_KNOWN_KEYS = {
    "archive_dir", "rotate_interval", "legal_retention", "service_start_type",
    "install_month", "engine_start_anchor", "rotation_anchor", "cursors", "_README",
}


def validate_config_integrity(cfg):
    """SANITIZATION-oriented integrity check on a loaded config dict. Returns a list of
    human-readable problem strings (empty = clean). Does NOT mutate the file; it REPORTS
    anomalies so an operator can see if the cfg was modified outside the expected schema.
    Checks: unknown top-level keys, malformed editable values, and a malformed cursors
    block. (We validate as DATA -- nothing here executes any config content.)"""
    problems = []
    if not isinstance(cfg, dict):
        return ["config is not a JSON object"]
    for k in cfg:
        if k not in _CONFIG_KNOWN_KEYS:
            problems.append("unknown key %r (not written by usnmon)" % k)
    # Editable values must pass their validators.
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
    """Interactive, numbered console editor for the user-changeable settings. The
    monitor MUST be stopped while editing (it writes the cursor block every ~10s; a
    concurrent settings write would race it). Detects a running service and offers to
    stop it. Only whitelisted settings are shown; the cursor block is preserved
    untouched on write. Runs an input-integrity check on entry and reports any anomaly
    (unknown keys / malformed values) so config tampering is visible."""
    print("usnmon configuration\n" + "-" * 40)

    # Integrity check (sanitization-oriented): report -- don't auto-mutate.
    pre = read_config()
    issues = validate_config_integrity(pre)
    if issues:
        print("NOTICE: config integrity check found %d anomaly(ies):" % len(issues))
        for it in issues:
            print("   - %s" % it)
        print("   (Unknown keys are ignored by the engine; malformed editable values\n"
              "    can be corrected below. The cursor block is never auto-changed.)\n")

    if _service_is_running():
        print("The %s service is RUNNING. It must be stopped to edit the config\n"
              "safely (the engine writes cursor state continuously)." % SERVICE_NAME)
        ans = input("Stop the service now and edit? [y/N]: ").strip().lower()
        if ans != "y":
            print("Left running. No changes made.")
            return
        try:
            win32serviceutil.StopService(SERVICE_NAME)
            import time as _t
            for _ in range(20):
                if not _service_is_running():
                    break
                _t.sleep(0.5)
            print("Service stopped.")
        except Exception as exc:
            print("Could not stop service (%r). Aborting; no changes made." % exc)
            return
        restart_after = True
    else:
        restart_after = False

    cfg = read_config()
    while True:
        print("\nCurrent settings:")
        for n, (key, label, _v) in enumerate(_CONFIG_EDITABLE, 1):
            val = cfg.get(key, "")
            shown = val if val != "" else "(default)"
            print("  %d. %-22s %s" % (n, label + ":", shown))
        # Read-only: start type is owned by Windows (set at install via --startup).
        print("     %-22s %s  (read-only; set with --startup at install)"
              % ("Service start type:", cfg.get("service_start_type", "unknown")))
        print("  0. Save and exit")
        choice = input("\nEdit which # (0 to save): ").strip()
        if choice == "0":
            break
        if not choice.isdigit() or not (1 <= int(choice) <= len(_CONFIG_EDITABLE)):
            print("  -> enter a number 0-%d." % len(_CONFIG_EDITABLE))
            continue
        key, label, validator = _CONFIG_EDITABLE[int(choice) - 1]
        cur = cfg.get(key, "")
        print("  %s -- current: %s" % (label, cur if cur != "" else "(default)"))
        newval = input("  new value (blank to clear/default): ")
        ok, result = validator(newval)
        if not ok:
            print("  -> rejected: %s" % result)
            continue
        cfg[key] = result
        print("  -> set %s = %s" % (label, result if result != "" else "(default)"))

    # Preserve cursors + every non-editable key: we started from the full read_config()
    # dict and only touched whitelisted keys, so the cursor block is written back intact.
    _write_config_atomic(cfg)
    print("\nSaved to %s" % _config_path())

    if restart_after:
        ans = input("Restart the service now? [Y/n]: ").strip().lower()
        if ans in ("", "y"):
            try:
                win32serviceutil.StartService(SERVICE_NAME)
                print("Service restarted; new settings loaded.")
            except Exception as exc:
                print("Could not restart (%r). Start it manually: usnmon start" % exc)
        else:
            print("Service left stopped. Start it with: usnmon start")


# --------------------------------------------------------------------------- #
# Console / CLI
# --------------------------------------------------------------------------- #
def run_console_debug(rotate_period=None):
    archive_dir = read_archive_dir()
    setup_logging(True, archive_dir)
    if _WINDOWS:
        register_event_source(archive_dir)
    logger.info("Console debug mode (usnmon). Ctrl+C to stop.")
    stop = threading.Event()
    try:
        run_engine(stop.is_set, archive_dir, rotate_period)
    except KeyboardInterrupt:
        stop.set()


def run_console_test(rotate_period=None):
    """Foreground capture for the test harness: identical to debug (real capture,
    emits 914/100s/915, Ctrl+C/terminate stops cleanly) BUT with console logging
    SUPPRESSED -- screen stays quiet so the test wrapper's output is readable, while
    the usnmon.log file trail is still written. Lets usntest_run.py own the engine as
    a normal foreground process (no service/SCM, no doubled-engine, killable)."""
    archive_dir = read_archive_dir()
    setup_logging(False, archive_dir)      # False = no StreamHandler -> quiet console
    if _WINDOWS:
        register_event_source(archive_dir)
    logger.info("Console TEST mode (usnmon). Foreground capture, quiet console.")
    stop = threading.Event()
    try:
        run_engine(stop.is_set, archive_dir, rotate_period)
    except KeyboardInterrupt:
        stop.set()


def main():
    args = sys.argv[1:]
    # archive_dir override: --archive <path>
    archive_dir = DEFAULT_ARCHIVE_DIR
    if "--archive" in args:
        i = args.index("--archive")
        archive_dir = args[i + 1]
        del args[i:i + 2]
        write_config(archive_dir)

    # --log-interval <N><unit>: rotation cadence. Persisted to config so the SERVICE
    # honors it too. v0.0.8 unit table: s/m/h (interval), d/w/M/y (CALENDAR, leap-aware),
    # t (fixed 30-day term). Case-significant: 'm'=minutes, 'M'=calendar months. Size
    # cap remains active alongside any time leg.
    rotate_period = None
    if "--log-interval" in args:
        i = args.index("--log-interval")
        spec = args[i + 1] if i + 1 < len(args) else ""
        del args[i:i + 2]
        rotate_period = parse_interval(spec)
        if rotate_period is None:
            print("Bad --log-interval '%s'. Use e.g. 10m, 90s, 6h, 1d, 2w, 1t, 1M, 1y "
                  "(case-significant: m=minutes, M=calendar months)." % spec)
            return
        cfg = read_config()
        cfg["rotate_interval"] = spec
        _write_config_atomic(cfg)
    else:
        # Pick up a persisted interval (so the service uses it without a CLI flag).
        rotate_period = parse_interval(read_config().get("rotate_interval", ""))

    # --legal-retention <N><unit>: prune whole archives older than the term. Units
    # d/w/t/M/y. BLANK/absent => keep everything forever. Persisted to config so the
    # SERVICE honors it. Use '--legal-retention ""' (or the config editor) to clear it
    # back to keep-everything. v0.0.8: 'M' (capital) = calendar months -- the legacy
    # 'm' (=minutes everywhere else) is NOT valid for retention.
    if "--legal-retention" in args:
        i = args.index("--legal-retention")
        spec = args[i + 1] if i + 1 < len(args) else ""
        del args[i:i + 2]
        if spec.strip() and parse_retention(spec) is None:
            print("Bad --legal-retention '%s'. Use e.g. 25y, 18M, 90d, 18t, 26w "
                  "(or \"\" to keep everything). 'M' = calendar months (not 'm', "
                  "which is minutes)." % spec)
            return
        cfg = read_config()
        cfg["legal_retention"] = spec.strip()    # "" => keep everything
        _write_config_atomic(cfg)

    if args and args[0] == "config":
        run_config_editor()
        return
    if args and args[0] == "debug":
        run_console_debug(rotate_period)
        return
    if args and args[0] == "test":
        run_console_test(rotate_period)
        return
    if args and args[0] == "archive-now":
        setup_logging(True, read_archive_dir())
        archive_one(read_archive_dir(), reason="manual")
        return
    if args and args[0] == "check":
        import json
        cfg = {}
        try:
            cfg = json.load(open(_config_path()))
        except Exception:
            pass
        missing = check_completeness(read_archive_dir(),
                                     cfg.get("install_month",
                                             datetime.now().strftime("%Y-%m")))
        print("Archive dir       :", read_archive_dir())
        print("Service start type:", cfg.get("service_start_type", "unknown"))
        print("Missing month-buckets:", missing or "none (complete)")
        return

    if _WINDOWS and win32serviceutil is not None:
        # IMPORTANT: pywin32's HandleCommandLine reads sys.argv DIRECTLY, not our local
        # `args`. Our CLI-only flags (--archive, --log-interval, --legal-retention) were
        # stripped from `args` above but NOT from sys.argv, so without this sync pywin32
        # would still see them and reject them as unknown options
        # ("option --log-interval not recognized"). Rebuild sys.argv from the cleaned
        # `args` here so the install/update/remove/start/stop dispatch sees only the
        # flags pywin32 actually understands.
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
            # services. We don't wrap it. On install we persist archive_dir first, then
            # let HandleCommandLine do the install (honoring --startup), then read the
            # ACTUAL configured start type back from Windows and record it in config so
            # the `config` editor / `check` can report it and the engine can log it.
            #
            # NOTE on the 'install in args' check (vs args[0] == 'install'): pywin32's
            # --startup flag and its value are passed as separate args BEFORE the verb,
            # so on `usnmon.py --startup delayed install` we have
            # args = ['--startup', 'delayed', 'install']; checking args[0] alone misses
            # the verb. We look for 'install' anywhere in args. ('install' is safe as a
            # substring scan: no known pywin32 flag takes 'install' as its value.)
            is_install = "install" in args
            if is_install:
                write_config(archive_dir)
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
