r"""usn_drill.py -- targeted statistics for a directory-scoped subset of a usnmon
FileSystem evtx archive (v0.0.1).

Reads a RAW .evtx file directly (via the evtx Rust reader, or python-evtx as
fallback), filters file events to a caller-supplied directory scope, and prints a
focused statistical profile of just that scope. Complement to usn_stats.py: where
usn_stats answers "what is this archive doing in aggregate," usn_drill answers
"what is THIS APPLICATION (or subdirectory tree) specifically doing inside it."

The filter is supplied as a plain-text file (one directory-pattern per line). All
matching directories are processed together in one report. There is no glob
support; lines are case-insensitive substring matches against the TargetFilename
field, and must end with `\` to enforce directory (not file/extension) scope.

Usage:
    python usn_drill.py <archive.evtx> --filter <filterlist.txt>
                                       [--top 25] [--samples 20]

    --top N       how many top directories / extensions / files to list (default 25)
    --samples N   how many representative file-name samples per pattern (default 20)

Filter file syntax:
    # comments and blank lines are skipped
    \\Blue Iris\\
    \\Dell\\TrustedDevice\\
    C:\\ProgramData\\Steam\\

Each line is matched as a case-insensitive substring against TargetFilename. An
event is included if ANY filter line appears in its TargetFilename. Lines must end
with `\\` (directory pattern). Lines containing `<>|*?`, null bytes, control
characters, or ending in a file-extension pattern (e.g. `.xml`, `.dat`) are
rejected with a warning to stderr. Lines that are substrings of earlier-accepted
lines are also rejected as redundant.

Output sections:
    FILTER SCOPE                   match count vs file events; which lines fired
    RUN / THROUGHPUT (filtered)    in-scope file events, span, rate
    EVENT-ID FREQUENCY (filtered)  100-106 mix within scope
    FILE EVENT CATEGORIES          create/modify/delete/rename/etc mix
    BY VOLUME (filtered)           per-drive distribution within scope
    TOP DIRECTORIES (full depth)   actual subdirectory structure, not rolled up
    FILE EXTENSIONS (filtered)     per-extension count + event-type mix
    FILENAME PATTERN ANALYSIS      length stats, GUID/timestamp/hash detection,
                                   sequential-number detection, samples
    FILE LIFETIME ANALYSIS         create -> delete pairs, transient detection
    RESILIENT FILES                files modified many times (state-journaling)
    TEMPORAL ACTIVITY              per-minute, burst minutes (>3x mean)
    PER-CAMERA / PER-INSTANCE       cam1/cam2-style pattern grouping
    RESOLUTION HEALTH (filtered)   in-scope unresolved-path rate

Requires an evtx reader: `pip install evtx` (Rust, fast) or
`pip install python-evtx` (pure Python, slower). Streams the archive
record-by-record.
"""
import sys
import os
import re
import math
from collections import Counter, defaultdict
from datetime import datetime


# --- usnmon event taxonomy (mirrors usn_stats.py) -------------------------- #
FILE_EVENTS = {
    100: "File Create", 101: "File Modify", 102: "File Delete",
    103: "File Rename", 104: "Security Change", 105: "Other Change",
    106: "Range Change (RESERVED)",
}


def label_for(eid):
    return FILE_EVENTS.get(eid, "(unknown)")


def human_size(n):
    if n is None:
        return "?"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return "%.1f %s" % (n, unit) if unit != "B" else "%d %s" % (n, unit)
        n /= 1024.0
    return "%.1f PB" % n


# Key-value regex matching usnmon's EventData blob format. Each event's Data
# element contains newline-separated `Key: Value` lines (not pipe-separated;
# pipes were an earlier mental model that turned out to be wrong). The regex
# anchors on a word-shaped key followed by `:` and captures the value through
# end-of-line. Matches usn_stats.py's parser byte-for-byte; if you change one,
# change both.
_KV = re.compile(r"^\s*([A-Za-z][A-Za-z0-9]*)\s*:\s*(.*?)\s*$")


def parse_blob(blob):
    """Parse the usnmon EventData blob (newline-separated `Key: Value` lines)
    into a dict. Robust to \\r\\n line endings."""
    out = {}
    if not blob:
        return out
    for line in blob.replace("\r", "\n").split("\n"):
        if not line.strip():
            continue
        m = _KV.match(line)
        if m:
            out[m.group(1)] = m.group(2)
    return out


def parse_utc(s):
    if not s:
        return None
    s = s.strip().rstrip("Z").strip()
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(s, fmt)
        except Exception:
            pass
    return None


def drive_of(path):
    if not path:
        return ""
    m = re.match(r"^([A-Za-z]:)", path)
    return m.group(1).upper() if m else ""


def ext_of(path):
    base = os.path.basename(path)
    _, dot, ext = base.rpartition(".")
    if not dot:
        return "(none)"
    return "." + ext.lower()


def mean_std(values):
    if not values:
        return (0.0, 0.0)
    mu = sum(values) / len(values)
    var = sum((v - mu) ** 2 for v in values) / len(values)
    return (mu, math.sqrt(var))


# --- filter file parsing + validation -------------------------------------- #
# The validation gate enforces "this looks like a directory pattern, not a file
# pattern or injected garbage." We're more strict than the minimum needed for
# correctness because operator-supplied filter files come from many sources
# (copy-paste, generated lists, hand-edits) and surfacing bad lines clearly is
# more useful than silently misbehaving. Threat model: honest-mistake protection
# and defense-in-depth, NOT stopping a determined attacker -- the `in` operator
# is a pure string operation with no eval/exec/shell-out, so filter strings
# cannot cause code execution by themselves.

MAX_FILTER_LINE_LEN = 260                # Windows MAX_PATH; longer can't be real
ILLEGAL_FILTER_CHARS = '<>|*?"'          # invalid in Windows filenames per spec
# Reject patterns ending in something that looks like a file extension. The
# rule: last `.` followed by 1-5 alphanumeric chars and end-of-string = "looks
# like a file extension."
_EXT_LIKE_RE = re.compile(r"\.[A-Za-z0-9]{1,5}$")


def _validate_filter_line(line, line_no):
    """Return (cleaned, reason_if_rejected). cleaned is None on rejection."""
    # Strip comment portion. Comments start with '#' anywhere on the line.
    # Substrings that LEGITIMATELY contain '#' are unlikely for directory paths,
    # so this trade-off is acceptable.
    if "#" in line:
        line = line.split("#", 1)[0]
    line = line.rstrip("\r\n").strip()
    if not line:
        return (None, None)            # blank/comment line - silent skip

    if len(line) > MAX_FILTER_LINE_LEN:
        return (None, "exceeds %d chars (Windows MAX_PATH)"
                       % MAX_FILTER_LINE_LEN)
    if "\x00" in line:
        return (None, "contains null byte")
    for c in line:
        if c < " " and c != "\t":
            return (None, "contains control character (ord %d)" % ord(c))
    bad = [c for c in line if c in ILLEGAL_FILTER_CHARS]
    if bad:
        return (None, "contains illegal char(s): %s"
                       % " ".join(sorted(set(bad))))

    # Must contain a path separator. Without one, this couldn't be a directory.
    if "\\" not in line:
        return (None, "no path separator -- not a directory pattern")

    # Must end with `\`. Enforces unambiguous directory-pattern semantics.
    if not line.endswith("\\"):
        return (None, "must end with `\\` (directory pattern, not file/prefix)")

    # Reject anything that looks like a file extension somewhere in the line --
    # belt-and-suspenders. If the pattern ends in `\`, the only way an extension
    # could appear is mid-string, which is unusual for a directory.
    # We check the trailing component before the final `\` for extension-like
    # endings.
    trimmed = line.rstrip("\\")
    if _EXT_LIKE_RE.search(trimmed):
        return (None, "trailing path component looks like a file extension")

    return (line.lower(), None)        # normalize to lowercase for case-insensitive matching


def load_filter_file(path):
    """Read the filter file and return a list of accepted, deduplicated substrings.
    Warnings for rejected lines go to stderr."""
    accepted = []
    rejected_count = 0
    blank_count = 0
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw_lines = f.readlines()
    except Exception as exc:
        print("ERROR: could not read filter file '%s': %s" % (path, exc),
              file=sys.stderr)
        return []

    for line_no, raw in enumerate(raw_lines, start=1):
        cleaned, reason = _validate_filter_line(raw, line_no)
        if cleaned is None:
            if reason is None:
                blank_count += 1       # blank/comment - normal, no warn
                continue
            rejected_count += 1
            print("WARN: filter line %d rejected (%s): %r"
                  % (line_no, reason, raw.rstrip("\r\n")), file=sys.stderr)
            continue
        # Dedup: if any earlier-accepted filter substring is contained WITHIN
        # this new line, the new line is more specific and adds nothing to
        # scope (the earlier, broader pattern already catches everything this
        # one would). Warn and skip. Note: the reverse direction (new line is
        # broader than something already accepted) is fine -- the new line
        # legitimately expands scope, and the earlier subsumed line becomes
        # harmless overhead in match_any().
        subsumed_by = next((acc for acc in accepted if acc in cleaned), None)
        if subsumed_by is not None:
            rejected_count += 1
            print("WARN: filter line %d redundant (already covered by earlier "
                  "accepted %r): %r"
                  % (line_no, subsumed_by, raw.rstrip("\r\n")), file=sys.stderr)
            continue
        accepted.append(cleaned)

    if rejected_count or blank_count:
        print("  filter file: %d accepted, %d rejected, %d blank/comment"
              % (len(accepted), rejected_count, blank_count), file=sys.stderr)
    return accepted


def match_any(target_lower, filters):
    """Return the first filter substring that matches, or None."""
    for f in filters:
        if f in target_lower:
            return f
    return None


# --- evtx reader (mirrors usn_stats.py) ------------------------------------ #
def get_reader(path):
    def iter_records_rust():
        from evtx import PyEvtxParser
        p = PyEvtxParser(path)
        for rec in p.records():
            yield rec["data"]

    def iter_records_pure():
        from Evtx.Evtx import Evtx
        with Evtx(path) as log:
            for rec in log.records():
                yield rec.xml()

    try:
        from evtx import PyEvtxParser   # noqa: F401
        return iter_records_rust, "evtx (rust)"
    except Exception:
        pass
    try:
        import Evtx.Evtx                # noqa: F401
        return iter_records_pure, "python-evtx (pure)"
    except Exception:
        raise RuntimeError(
            "Need an evtx reader. Install one:  pip install evtx   "
            "(or: pip install python-evtx)")


def evtx_total_records(path):
    """Estimate record count for progress reporting; returns None if not possible."""
    try:
        from evtx import PyEvtxParser
        p = PyEvtxParser(path)
        return sum(1 for _ in p.records())
    except Exception:
        return None


# --- filename-pattern detectors -------------------------------------------- #
_GUID_RE = re.compile(r"\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                       r"[0-9a-f]{4}-[0-9a-f]{12}\}?", re.I)
_HEX32_RE = re.compile(r"\b[0-9a-f]{32}\b", re.I)            # MD5
_HEX40_RE = re.compile(r"\b[0-9a-f]{40}\b", re.I)            # SHA1
_HEX64_RE = re.compile(r"\b[0-9a-f]{64}\b", re.I)            # SHA256
_TIMESTAMP_ISH_RE = re.compile(r"\b(19|20)\d{2}[-_]?\d{2}[-_]?\d{2}\b")
_EPOCH_ISH_RE = re.compile(r"\b1[5-9]\d{8}\b")               # 10-digit epoch ~2017+
_SEQ_NUM_RE = re.compile(r"\b\d{3,}\b")                     # 3+ consecutive digits


def classify_filename(name):
    """Return a set of pattern labels found in `name` (basename only).
    Labels are descriptive and used for aggregate counting."""
    tags = set()
    if _GUID_RE.search(name):
        tags.add("guid")
    if _HEX64_RE.search(name):
        tags.add("hex64 (sha256-like)")
    elif _HEX40_RE.search(name):
        tags.add("hex40 (sha1-like)")
    elif _HEX32_RE.search(name):
        tags.add("hex32 (md5-like)")
    if _TIMESTAMP_ISH_RE.search(name):
        tags.add("date-like")
    if _EPOCH_ISH_RE.search(name):
        tags.add("epoch-like")
    if _SEQ_NUM_RE.search(name) and "epoch-like" not in tags:
        tags.add("sequential number")
    if not tags:
        tags.add("plain")
    return tags


# --- camera / instance detector -------------------------------------------- #
# Look for filenames or path segments shaped like an instance/camera identifier:
# "cam1", "cam_1", "camera1", "camera-1", "Camera 1", "cam01", etc. Also accept
# generic numbered-instance shapes ("instance1", "stream1") that often show up
# in NVR / monitoring software. The operator decides whether the count looks
# like the right number for their setup.
_CAM_RE = re.compile(
    r"\b(?:cam|camera|stream|chan|channel|instance)[\s_-]?(\d{1,3})\b", re.I)


def detect_instance(path):
    """Return a normalized instance label or None."""
    m = _CAM_RE.search(path)
    if not m:
        return None
    return "instance %s" % m.group(1)


# --- main processing ------------------------------------------------------- #
def process_filtered(path, filters):
    """Stream the archive, applying the filter, and accumulate stats.
    Returns a dict with all collected data."""
    file_size = os.path.getsize(path)
    reader_fn, reader_name = get_reader(path)
    import xml.etree.ElementTree as ET

    # Stats accumulators
    in_scope_events = 0           # file events that matched a filter
    total_file_events = 0         # file events seen (for the % stat)
    total_records = 0             # everything seen, for context
    eid_counts = Counter()
    cat_counts = Counter()
    drive_counts = Counter()
    ext_counts = Counter()
    ext_event_mix = defaultdict(Counter)        # ext -> Counter(eid -> n)
    dir_counts_full = Counter()                  # full directory paths, not rolled-up
    filter_hits = Counter()                      # filter_substring -> match count
    per_minute = Counter()
    per_hour = Counter()
    resolve_fail = 0
    first_dt = None
    last_dt = None

    # Filename pattern accumulators
    name_lengths = []
    pattern_tags = Counter()
    sample_names = []
    SAMPLE_CAP = 200              # cap raw samples; we'll dedupe for display

    # File-lifetime tracking: { full_path: {"create": dt, "delete": dt, "modifies": n} }
    file_lifecycle = {}

    # Per-instance counters
    instance_counts = Counter()

    # Reader setup
    est_total = evtx_total_records(path)
    if est_total:
        print("Reading %s (%s) via %s -- ~%d records..."
              % (os.path.basename(path), human_size(file_size),
                 reader_name, est_total))
    else:
        print("Reading %s (%s) via %s..."
              % (os.path.basename(path), human_size(file_size), reader_name))

    ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
    import time as _time
    t_start = _time.time()
    next_pct = 5
    try:
        for i, xml_str in enumerate(reader_fn()):
            if est_total:
                pct = 100 * (i + 1) // est_total
                if pct >= next_pct:
                    el = _time.time() - t_start
                    print("  ...%d%%  (%d / ~%d records)  [%.1fs  %s]"
                          % (pct, i + 1, est_total, el,
                             _time.strftime("%H:%M:%S")), file=sys.stderr)
                    next_pct = (pct // 5) * 5 + 5
            elif i and i % 100000 == 0:
                el = _time.time() - t_start
                print("  ...%d records  [%.1fs  %s]"
                      % (i, el, _time.strftime("%H:%M:%S")), file=sys.stderr)
            try:
                root = ET.fromstring(xml_str)
            except Exception:
                continue
            total_records += 1
            eid_el = root.find("./%sSystem/%sEventID" % (ns, ns))
            try:
                eid = int(eid_el.text)
            except Exception:
                continue
            if eid not in FILE_EVENTS:
                continue            # focused on file events only
            total_file_events += 1

            datas = root.findall("./%sEventData/%sData" % (ns, ns))
            if not datas or not datas[0].text:
                continue
            fields = parse_blob(datas[0].text)
            tf = fields.get("TargetFilename", "")
            if not tf:
                continue

            # Apply filter
            tf_lower = tf.lower()
            matched_filter = match_any(tf_lower, filters)
            if not matched_filter:
                continue
            filter_hits[matched_filter] += 1
            in_scope_events += 1

            # In scope: accumulate stats
            eid_counts[eid] += 1
            cat_counts[fields.get("Category", label_for(eid))] += 1
            drive_counts[drive_of(tf)] += 1
            ext = ext_of(tf)
            ext_counts[ext] += 1
            ext_event_mix[ext][eid] += 1
            if "\\?\\" in tf:
                resolve_fail += 1

            # Full directory path (not rolled up)
            dir_path = os.path.dirname(tf)
            if dir_path:
                dir_counts_full[dir_path] += 1

            # Filename pattern analysis
            base = os.path.basename(tf)
            if base:
                name_lengths.append(len(base))
                for tag in classify_filename(base):
                    pattern_tags[tag] += 1
                if len(sample_names) < SAMPLE_CAP:
                    sample_names.append(base)

            # Instance detection (path AND filename, to catch dir-named and file-named)
            inst = detect_instance(tf)
            if inst:
                instance_counts[inst] += 1

            # Time tracking
            dt = parse_utc(fields.get("UtcTime", ""))
            if dt:
                first_dt = dt if first_dt is None else min(first_dt, dt)
                last_dt = dt if last_dt is None else max(last_dt, dt)
                per_minute[dt.strftime("%Y-%m-%d %H:%M")] += 1
                per_hour[dt.strftime("%Y-%m-%d %H:00")] += 1

            # File lifecycle: track create/delete/modify-count per path. Cap the
            # dict at a generous size to bound memory on pathological archives.
            if len(file_lifecycle) < 50000 or tf in file_lifecycle:
                rec = file_lifecycle.get(tf)
                if rec is None:
                    rec = {"create": None, "delete": None, "modifies": 0}
                    file_lifecycle[tf] = rec
                if eid == 100 and rec["create"] is None and dt:
                    rec["create"] = dt
                elif eid == 102 and rec["delete"] is None and dt:
                    rec["delete"] = dt
                elif eid == 101:
                    rec["modifies"] += 1

    except Exception as exc:
        if total_records == 0:
            raise RuntimeError("Could not read '%s' as an evtx file (%s)."
                               % (os.path.basename(path), exc))
        print("  (stopped early after %d records: %s)"
              % (total_records, exc), file=sys.stderr)

    read_secs = _time.time() - t_start
    if total_records:
        print("  read complete: %d records (%d file events, %d in scope) in "
              "%.1fs (%.0f rec/s)"
              % (total_records, total_file_events, in_scope_events,
                 read_secs, total_records / read_secs if read_secs > 0 else 0),
              file=sys.stderr)

    return {
        "path": path,
        "file_size": file_size,
        "total_records": total_records,
        "total_file_events": total_file_events,
        "in_scope_events": in_scope_events,
        "filters": filters,
        "filter_hits": filter_hits,
        "eid_counts": eid_counts,
        "cat_counts": cat_counts,
        "drive_counts": drive_counts,
        "ext_counts": ext_counts,
        "ext_event_mix": ext_event_mix,
        "dir_counts_full": dir_counts_full,
        "per_minute": per_minute,
        "per_hour": per_hour,
        "resolve_fail": resolve_fail,
        "first_dt": first_dt,
        "last_dt": last_dt,
        "name_lengths": name_lengths,
        "pattern_tags": pattern_tags,
        "sample_names": sample_names,
        "file_lifecycle": file_lifecycle,
        "instance_counts": instance_counts,
        "read_secs": read_secs,
    }


# --- report printing ------------------------------------------------------- #
def print_report(stats, top, samples):
    path = stats["path"]
    in_scope = stats["in_scope_events"]
    total_file = stats["total_file_events"]
    total_rec = stats["total_records"]

    W = 78
    print("\n" + "=" * W)
    print("usn_drill report  --  %s" % os.path.basename(path))
    print("=" * W)

    # FILTER SCOPE
    print("\n## FILTER SCOPE")
    print("  total records in archive : %d" % total_rec)
    print("  total file events        : %d" % total_file)
    if total_file > 0:
        pct = 100.0 * in_scope / total_file
        print("  matched filter scope     : %d  (%.1f%% of file events)"
              % (in_scope, pct))
    else:
        print("  matched filter scope     : %d" % in_scope)
    print("  filter substrings        : %d" % len(stats["filters"]))
    if stats["filter_hits"]:
        print("  per-filter hits:")
        for f in stats["filters"]:
            hits = stats["filter_hits"].get(f, 0)
            print("     %9d  %s" % (hits, f))

    if in_scope == 0:
        print("\nNo events matched the filter scope. Nothing to report on.")
        return

    # RUN / THROUGHPUT (filtered)
    first_dt = stats["first_dt"]
    last_dt = stats["last_dt"]
    print("\n## RUN / THROUGHPUT (filtered scope)")
    if first_dt and last_dt and last_dt > first_dt:
        span = last_dt - first_dt
        hrs = span.total_seconds() / 3600.0
        mins = span.total_seconds() / 60.0
        print("  log start (UtcTime)    : %s" % first_dt)
        print("  log end   (UtcTime)    : %s" % last_dt)
        print("  span                   : %s (%.2f h)" % (span, hrs))
        if hrs > 0:
            print("  in-scope rec / hour    : %.1f" % (in_scope / hrs))
            print("  in-scope rec / minute  : %.1f" % (in_scope / mins))
    else:
        print("  (no parseable UtcTime span -- throughput unavailable)")

    # EVENT-ID FREQUENCY (filtered)
    print("\n## EVENT-ID FREQUENCY (filtered scope)")
    for eid, c in sorted(stats["eid_counts"].items(), key=lambda kv: -kv[1]):
        pct = 100.0 * c / in_scope
        print("  %5d  %-26s %9d  %5.1f%%"
              % (eid, label_for(eid), c, pct))

    # FILE EVENT CATEGORIES
    if stats["cat_counts"]:
        print("\n## FILE EVENT CATEGORIES (filtered scope)")
        for cat, c in stats["cat_counts"].most_common():
            print("  %-20s %9d  %5.1f%%" % (cat, c, 100.0 * c / in_scope))

    # BY VOLUME (filtered)
    if stats["drive_counts"]:
        print("\n## BY VOLUME (filtered scope)")
        for dv, c in stats["drive_counts"].most_common():
            print("  %-10s %9d  %5.1f%%" % (dv, c, 100.0 * c / in_scope))

    # TOP DIRECTORIES (full depth)
    if stats["dir_counts_full"]:
        print("\n## TOP %d DIRECTORIES (full depth, filtered scope)" % top)
        n_dirs = len(stats["dir_counts_full"])
        print("  (distinct directories within scope: %d)" % n_dirs)
        for d, c in stats["dir_counts_full"].most_common(top):
            print("  %9d  %5.1f%%  %s" % (c, 100.0 * c / in_scope, d))

    # FILE EXTENSIONS with event-type mix
    if stats["ext_counts"]:
        print("\n## TOP %d FILE EXTENSIONS (filtered scope) with event-type mix" % top)
        print("  (C=Create, M=Modify, D=Delete, R=Rename, S=Security, O=Other)")
        col_fmt = "  %-12s %9s  %5s  %5s %5s %5s %5s %5s %5s"
        print(col_fmt % ("extension", "events", "%", "C%", "M%", "D%",
                         "R%", "S%", "O%"))
        for ext, c in stats["ext_counts"].most_common(top):
            mix = stats["ext_event_mix"][ext]
            cM = mix.get(100, 0); cm = mix.get(101, 0); cD = mix.get(102, 0)
            cR = mix.get(103, 0); cS = mix.get(104, 0); cO = mix.get(105, 0)
            denom = sum([cM, cm, cD, cR, cS, cO]) or 1
            print(col_fmt
                  % (ext, c, "%.1f%%" % (100.0 * c / in_scope),
                     "%.0f" % (100.0 * cM / denom),
                     "%.0f" % (100.0 * cm / denom),
                     "%.0f" % (100.0 * cD / denom),
                     "%.0f" % (100.0 * cR / denom),
                     "%.0f" % (100.0 * cS / denom),
                     "%.0f" % (100.0 * cO / denom)))

    # FILENAME PATTERN ANALYSIS
    if stats["name_lengths"]:
        nl = stats["name_lengths"]
        srt = sorted(nl)
        mu, sd = mean_std(nl)
        print("\n## FILENAME PATTERN ANALYSIS (filtered scope)")
        print("  filenames observed (with duplicates) : %d" % len(nl))
        print("  min / median / max length            : %d / %d / %d"
              % (min(nl), srt[len(srt) // 2], max(nl)))
        print("  mean length (sigma)                  : %.1f (%.1f)"
              % (mu, sd))
        if stats["pattern_tags"]:
            print("  pattern tags (filenames may match multiple):")
            total_tagged = sum(stats["pattern_tags"].values())
            for tag, c in stats["pattern_tags"].most_common():
                print("     %-22s %9d  (%.1f%% of tag-matches)"
                      % (tag, c, 100.0 * c / total_tagged))
        # Sample filenames -- deduplicated and capped
        if stats["sample_names"]:
            uniq = []
            seen = set()
            for n in stats["sample_names"]:
                if n not in seen:
                    seen.add(n)
                    uniq.append(n)
                if len(uniq) >= samples:
                    break
            print("  sample filenames (deduplicated, up to %d):" % samples)
            for n in uniq:
                print("     %s" % n)

    # FILE LIFETIME ANALYSIS
    lc = stats["file_lifecycle"]
    if lc:
        create_delete_pairs = [
            (p, (r["delete"] - r["create"]).total_seconds())
            for p, r in lc.items()
            if r["create"] and r["delete"]
                and r["delete"] >= r["create"]
        ]
        print("\n## FILE LIFETIME ANALYSIS (filtered scope)")
        print("  files seen with at least one event   : %d" % len(lc))
        n_create_only = sum(
            1 for r in lc.values() if r["create"] and not r["delete"])
        n_delete_only = sum(
            1 for r in lc.values() if r["delete"] and not r["create"])
        print("  files with Create but no Delete      : %d (persistent)" % n_create_only)
        print("  files with Delete but no Create      : %d (existed before scope)"
              % n_delete_only)
        print("  files with both Create and Delete    : %d (transient lifecycle)"
              % len(create_delete_pairs))

        if create_delete_pairs:
            durations = [d for _, d in create_delete_pairs]
            srt = sorted(durations)
            mu, sd = mean_std(durations)

            def _fmt_dur(s):
                if s < 1: return "%.0f ms" % (s * 1000)
                if s < 60: return "%.1f s" % s
                if s < 3600: return "%.1f m" % (s / 60.0)
                return "%.1f h" % (s / 3600.0)

            print("  transient-file lifetime stats:")
            print("     min                : %s" % _fmt_dur(min(durations)))
            print("     median             : %s"
                  % _fmt_dur(srt[len(srt) // 2]))
            print("     mean (sigma)       : %s (%s)"
                  % (_fmt_dur(mu), _fmt_dur(sd)))
            print("     max                : %s" % _fmt_dur(max(durations)))
            print("     count < 1s         : %d (%.1f%%)"
                  % (sum(1 for d in durations if d < 1),
                     100.0 * sum(1 for d in durations if d < 1)
                     / len(durations)))
            print("     count < 10s        : %d (%.1f%%)"
                  % (sum(1 for d in durations if d < 10),
                     100.0 * sum(1 for d in durations if d < 10)
                     / len(durations)))

            # Top fast-cycling files (shortest lifetime)
            print("  top %d fastest-cycling files (Create->Delete duration):"
                  % min(top, len(create_delete_pairs)))
            for p, d in sorted(create_delete_pairs, key=lambda kv: kv[1])[:top]:
                print("     %-14s  %s" % (_fmt_dur(d), p))

    # RESILIENT FILES (high modify count)
    resilient = [(p, r["modifies"]) for p, r in lc.items()
                 if r["modifies"] >= 2]
    if resilient:
        resilient.sort(key=lambda kv: -kv[1])
        print("\n## RESILIENT FILES (modified 2+ times within scope)")
        print("  count: %d files" % len(resilient))
        print("  top %d by modify count:" % min(top, len(resilient)))
        for p, c in resilient[:top]:
            print("  %5d modifies  %s" % (c, p))

    # TEMPORAL
    pm = stats["per_minute"]
    if pm:
        bm, bm_c = pm.most_common(1)[0]
        permin_vals = list(pm.values())
        mu_m, sd_m = mean_std(permin_vals)
        print("\n## TEMPORAL ACTIVITY (filtered scope)")
        print("  active minutes         : %d" % len(pm))
        print("  busiest minute         : %s  (%d events)" % (bm, bm_c))
        print("  mean events/active min : %.1f  (sigma %.1f)" % (mu_m, sd_m))
        # Burst detection: minutes with > 3x mean
        threshold = max(mu_m * 3, mu_m + sd_m * 2)
        bursts = sorted([(m, c) for m, c in pm.items() if c > threshold],
                        key=lambda kv: -kv[1])
        if bursts:
            print("  burst minutes (>3x mean OR >mean+2sigma): %d" % len(bursts))
            for m, c in bursts[:top]:
                print("     %s  %d events (%.1fx mean)" % (m, c, c / mu_m if mu_m else 0))
        ph = stats["per_hour"]
        if ph:
            bh, bh_c = ph.most_common(1)[0]
            print("  busiest hour           : %s  (%d events)" % (bh, bh_c))

    # PER-INSTANCE
    ic = stats["instance_counts"]
    if ic:
        print("\n## PER-INSTANCE INFERENCE (cam/camera/stream/channel/instance N)")
        print("  (regex-detected instance markers in path or filename; verify "
              "against your setup)")
        for inst, c in ic.most_common():
            print("  %-22s %9d  %5.1f%% of in-scope events"
                  % (inst, c, 100.0 * c / in_scope))
    else:
        print("\n## PER-INSTANCE INFERENCE")
        print("  (no cam/camera/stream/channel/instance-N patterns detected)")

    # RESOLUTION HEALTH
    print("\n## RESOLUTION HEALTH (filtered scope)")
    print("  unresolved paths (\\?\\) : %d  (%.2f%% of in-scope events)"
          % (stats["resolve_fail"], 100.0 * stats["resolve_fail"] / in_scope))

    print("\n" + "=" * W)


# --- main ------------------------------------------------------------------ #
def main():
    if len(sys.argv) < 2 or "--filter" not in sys.argv:
        print(__doc__)
        return
    path = sys.argv[1]
    top = (int(sys.argv[sys.argv.index("--top") + 1])
           if "--top" in sys.argv else 25)
    samples = (int(sys.argv[sys.argv.index("--samples") + 1])
               if "--samples" in sys.argv else 20)
    filter_path = sys.argv[sys.argv.index("--filter") + 1]

    if not os.path.exists(path):
        print("ERROR: input archive not found: %s" % path, file=sys.stderr)
        return
    if not os.path.isfile(path):
        print("ERROR: input must be a file, not a directory: %s" % path,
              file=sys.stderr)
        return
    if not os.path.exists(filter_path):
        print("ERROR: filter file not found: %s" % filter_path, file=sys.stderr)
        return

    print("Loading filter from %s ..." % filter_path, file=sys.stderr)
    filters = load_filter_file(filter_path)
    if not filters:
        print("ERROR: no valid filter lines after validation. Aborting.",
              file=sys.stderr)
        return

    try:
        stats = process_filtered(path, filters)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return

    print_report(stats, top, samples)


if __name__ == "__main__":
    main()
