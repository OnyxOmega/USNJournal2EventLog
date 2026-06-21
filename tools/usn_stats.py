"""usn_stats.py -- statistics profiler for usnmon FileSystem evtx archives.

v0.2.0 -- adds SERIES MODE. Accepts either a single .evtx file (single-archive mode,
output byte-identical to v0.1.x) or a directory of .evtx files (series mode,
three-layer report: consolidated summary -> per-archive comparison -> per-archive
reports).

Reads RAW .evtx files directly (via python-evtx -- no EvtxECmd step needed) and
prints a full statistical profile of usnmon capture(s): event-ID frequency, top
directory "talkers", the directory-count distribution with mean/sigma cutoffs and an
ASCII histogram, run-time / throughput numbers, per-volume and per-extension
breakdowns, and an operational-event (9xx/5xx) summary.

Usage:
    python usn_stats.py <archive.evtx>  [--top 25] [--depth 4] [--bins 20]
    python usn_stats.py <directory>     [--top 25] [--depth 4] [--bins 20]

    --top N     how many top directory talkers to list (default 25)
    --depth N   roll paths up to N directory levels so per-file churn collapses into a
                visible bucket (default 4): C:\\A\\B\\C\\D\\E\\f.tmp -> C:\\A\\B\\C\\D
    --bins N    histogram bin count for the distribution (default 20)

Single-archive mode (argument is a file): the v0.1.x per-archive report, unchanged.
Redirect with >> or > as before.

Series mode (argument is a directory containing one or more .evtx files): three-
layer report appended to stdout:
  (1) CONSOLIDATED SUMMARY across all archives -- totals, span, aggregate event-ID
      frequency, top directories across the whole investigation period. The "what
      is this dataset" view.
  (2) PER-ARCHIVE COMPARISON TABLE -- one row per archive: filename, span,
      records, records/hour, ops events, unresolved %, top extension; plus a
      second table mapping archive -> top directory. The "which archive is
      anomalous" view.
  (3) PER-ARCHIVE REPORTS -- the full v0.1.x report for each archive in
      chronological order, with the existing === separators. The "drill down
      into a specific rotation" view.

Archives are sorted by filename (which is chronological under usnmon's span-name
format and the v0.0.7c+ calendar/span names). Subsequent v0.2.x releases will add
sections for self-integrity check (does usnmon coverage chain cleanly across the
series?), session inference (RDP/WSL/browser session start-end from known
directory patterns), and rotation capacity projection (recommend rotation cadence
from observed record/hour and bytes/record averages).

Requires an evtx reader. Prefers the fast Rust-backed `evtx` (pip install evtx) and
falls back to pure-Python `python-evtx` (pip install python-evtx). On a large archive
(hundreds of MB) the Rust reader is far faster. Streams the file record-by-record, so
the archive is processed without loading it all into memory.

If your archive is still inside a `FileSystem_<...>.zip`, unzip it first and point
this at the `.evtx` (the matching `.manifest` is not needed for stats).
"""
import sys
import os
import re
import math
from collections import Counter, defaultdict
from datetime import datetime


# --- usnmon event taxonomy (v0.0.7) ---------------------------------------- #
FILE_EVENTS = {
    100: "File Create", 101: "File Modify", 102: "File Delete",
    103: "File Rename", 104: "Security Change", 105: "Other Change",
    106: "Range Change (RESERVED)",
}
DEVICE_EVENTS = {
    500: "Device NEW", 501: "Device REMOVED", 503: "Device REATTACHED",
    504: "Device ALTERED",
}
OPERATIONAL_EVENTS = {
    904: "Archive Written", 914: "Engine Started", 915: "Engine Stopped",
    916: "Drive/Journal Failure", 917: "Degraded (reserved)",
    918: "Completeness Gap", 919: "No Active Journal",
    920: "Unsupported Filesystem", 921: "Remote/Network Share",
    922: "Sign/Hash Failure", 923: "Resume Gap",
    # v0.0.8+ retrospective-gap and clock-anomaly IDs (harmless on v0.0.7 archives:
    # the IDs just won't appear, but defining the labels here lets self-integrity
    # output show "Archiving Gap Detected" rather than "(unknown)" once v0.0.8+
    # archives are processed).
    925: "Archiving Gap Detected", 926: "Clock Anomaly Detected",
}
TEST_EVENTS = {800: "Test Create", 801: "Test Modify", 802: "Test Delete",
               803: "Test Security", 899: "Test Marker"}
ALL_EVENTS = {**FILE_EVENTS, **DEVICE_EVENTS, **OPERATIONAL_EVENTS, **TEST_EVENTS}


def label_for(eid):
    return ALL_EVENTS.get(eid, "Unknown(%d)" % eid)


# --- blob parsing ----------------------------------------------------------- #
_KV = re.compile(r"^\s*([A-Za-z][A-Za-z0-9]*)\s*:\s*(.*?)\s*$")


def parse_blob(blob):
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


def parent_at_depth(path, depth):
    p = path.replace("/", "\\").replace("\\?\\", "\\")
    parts = [x for x in p.split("\\") if x]
    if not parts:
        return p
    dirs = parts[:-1] if len(parts) > 1 else parts
    if not dirs:
        return parts[0]
    return "\\".join(dirs[:depth])


def drive_of(path):
    p = path.replace("/", "\\").replace("\\?\\", "\\").lstrip("\\")
    if len(p) >= 2 and p[1] == ":":
        return p[:2].upper()
    return "(unknown)"


def ext_of(path):
    base = path.replace("/", "\\").rstrip("\\").rsplit("\\", 1)[-1]
    if "." in base and not base.startswith("."):
        return "." + base.rsplit(".", 1)[-1].lower()
    return "(none)"


def parse_utc(s):
    if not s:
        return None
    s = s.strip().rstrip("Z")
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def mean_std(values):
    n = len(values)
    if n == 0:
        return 0.0, 0.0
    mu = sum(values) / n
    if n == 1:
        return mu, 0.0
    var = sum((v - mu) ** 2 for v in values) / (n - 1)
    return mu, math.sqrt(var)


def percentile(sorted_vals, p):
    """p-th percentile (0-100) of an already-sorted ascending list (nearest-rank)."""
    if not sorted_vals:
        return 0
    k = max(0, min(len(sorted_vals) - 1, int(round((p / 100.0) * (len(sorted_vals) - 1)))))
    return sorted_vals[k]


def median_abs_deviation(values, med):
    """MAD = median(|x - median|): an outlier-RESISTANT spread measure (unlike sigma,
    one giant value can't blow it up)."""
    if not values:
        return 0.0
    devs = sorted(abs(v - med) for v in values)
    return percentile(devs, 50)


def find_cliff(dir_count_pairs, window=10, ratio=5.0):
    """Find the 'sigma-destroyer' cliff among the top talkers.

    Sort directories by count descending; within the top `window`, compute the ratio
    between each consecutive pair. The cliff is the SINGLE LARGEST ratio that is >=
    `ratio` (default 5x) -- the most disproportionate drop is the most defensible cut
    point, wherever it falls in the window. Everything AT/ABOVE that drop is excluded.
    If no consecutive ratio in the window reaches the threshold, there is NO cliff
    (returns []). No max-exclude cap: the only bound is the search window, and the
    excluded dirs are never lost (they remain in the full tail report).

    Returns a list of (dir, count) excluded (the dominant head), or [] if no cliff.
    `dir_count_pairs` is an iterable of (dir, count)."""
    ranked = sorted(dir_count_pairs, key=lambda kv: kv[1], reverse=True)
    if len(ranked) < 2:
        return []
    top = ranked[:window]
    best_idx = None       # cut AFTER this index (0-based) -> exclude ranked[:best_idx+1]
    best_ratio = 0.0
    for i in range(len(top) - 1):
        hi, lo = top[i][1], top[i + 1][1]
        if lo <= 0:
            continue
        r = hi / lo
        if r >= ratio and r > best_ratio:
            best_ratio = r
            best_idx = i
    if best_idx is None:
        return []
    return ranked[:best_idx + 1]


def _distribution_block(counts, file_total, bins, label):
    """Print a directory-count distribution block (mean/sigma/median/max + sigma tiers +
    both histograms) for a given set of per-directory counts. Shared by the
    outliers-excluded (primary) and full (tail) reports."""
    n_dirs = len(counts)
    if n_dirs == 0:
        print("  (no directories)")
        return
    mu, sd = mean_std(counts)
    srt = sorted(counts)
    print("  distinct directories   : %d" % n_dirs)
    print("  mean events/dir        : %.2f" % mu)
    print("  std dev (sigma)        : %.2f" % sd)
    print("  median                 : %d" % srt[n_dirs // 2])
    print("  max (busiest dir)      : %d" % max(counts))
    denom = file_total if file_total else 1
    for k in (1, 2, 3):
        cut = mu + k * sd
        over = [c for c in counts if c > cut]
        ev_over = sum(over)
        print("  > mean + %dsigma (%.1f) : %d dirs (%.1f%% of dirs), "
              "%d events (%.1f%% of file events)"
              % (k, cut, len(over), 100.0 * len(over) / n_dirs,
                 ev_over, 100.0 * ev_over / denom))
    print("\n  Histogram -- events-per-directory:")
    for line in histogram(counts, bins):
        print(line)
    print("\n  Histogram -- log10(events-per-directory) [skew-friendly]:")
    for line in histogram([math.log10(c) for c in counts if c > 0], bins):
        print(line)


def _print_top_tree(dir_counts_subset, full_dir_counts, denom, top, depth, bins_unused,
                    full_dir_capped, full_dir_cap, breakdown_pct=40.0):
    """Print the 'top N directory talkers' tree for a given SUBSET of directories, with
    percentages computed against `denom` (the total event count for that subset). The
    recursive >=40%-of-parent breakdown is then applied to any depth-N bucket that hits
    the threshold WITHIN THIS SUBSET'S landscape. Used twice: once for the PRIMARY
    section (subset = kept dirs, denom = kept events) and once for the TAIL section
    (subset = all dirs, denom = full file_total).

    `full_dir_counts` is the COMPLETE per-parent-dir counter (used by the breakdown to
    find children); it isn't filtered, because excluded parent dirs aren't in the
    subset and their children won't be reached, but a kept parent's children are still
    found correctly."""
    from collections import Counter
    if not dir_counts_subset:
        return
    if full_dir_capped:
        print("  (note: distinct-dir tracking capped at %d; breakdown reflects the"
              " first %d dirs seen)" % (full_dir_cap, full_dir_cap))
    # most_common on the subset
    items = sorted(dir_counts_subset.items(), key=lambda kv: kv[1], reverse=True)[:top]
    for d, c in items:
        pct = 100.0 * c / denom if denom else 0.0
        print("  %9d  %5.1f%%  %s" % (c, pct, d))
        if pct >= breakdown_pct:
            rows = []
            breakdown_bucket(full_dir_counts, d, c, depth + 1, breakdown_pct, rows)
            if rows:
                print("             |- breakdown (%% of %s = %d events):"
                      % (d.rsplit("\\", 1)[-1] or d, c))
                for ind, sub, sc, spct in rows:
                    leaf = sub[len(d):].lstrip("\\") or sub
                    print("             %s%5.1f%%  %7d  %s"
                          % ("  " * ind, spct, sc, leaf))


def histogram(values, bins, width=50):
    if not values:
        return ["(no data)"]
    lo, hi = min(values), max(values)
    if lo == hi:
        return ["all %d values == %g" % (len(values), lo)]
    step = (hi - lo) / bins
    counts = [0] * bins
    for v in values:
        idx = min(int((v - lo) / step), bins - 1)
        counts[idx] += 1
    peak = max(counts) or 1
    lines = []
    for i, c in enumerate(counts):
        a = lo + i * step
        b = a + step
        bar = "#" * int(width * c / peak)
        lines.append("  [%9.1f .. %9.1f) %7d |%s" % (a, b, c, bar))
    return lines


def human_size(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return "%.1f %s" % (n, unit)
        n /= 1024
    return "%.1f PB" % n


def flatten_blob(blob, limit=100):
    """Collapse a multi-line Key:value blob (device/operational events carry the full
    field array, not a single message) into one readable line for compact display."""
    if not blob:
        return ""
    parts = [ln.strip() for ln in blob.replace("\r", "\n").split("\n") if ln.strip()]
    line = " | ".join(parts)
    return line[:limit] + ("..." if len(line) > limit else "")


def dir_at_depth(path, depth):
    """The directory path of a FILE `path` rolled to exactly `depth` levels (drops the
    filename first). Use roll_dir() for paths that are already directories."""
    p = path.replace("/", "\\").replace("\\?\\", "\\")
    parts = [x for x in p.split("\\") if x]
    if not parts:
        return p
    dirs = parts[:-1] if len(parts) > 1 else parts
    return "\\".join(dirs[:depth])


def roll_dir(dirpath, depth):
    """Roll an already-directory path to `depth` levels WITHOUT dropping its last
    component (unlike dir_at_depth, which assumes a trailing filename)."""
    p = dirpath.replace("/", "\\").replace("\\?\\", "\\")
    parts = [x for x in p.split("\\") if x]
    return "\\".join(parts[:depth])


def breakdown_bucket(full_dir_counts, prefix, parent_total, depth, threshold,
                     out, indent=1, max_extra_depth=8):
    """Recursively break a hot directory bucket into its children, ONE level deeper each
    step. Percentages are relative to the PARENT bucket (parent_total). A child that is
    itself >= threshold of this bucket is recursed into; recursion stops on a branch
    once no child reaches the threshold (or the depth cap is hit). Appends
    (indent, child_dir, count, pct_of_parent) rows to `out`. Pure in-memory rollup from
    full_dir_counts -- no file re-read."""
    if parent_total <= 0 or depth > max_extra_depth + 4:
        return
    # Roll every full dir that lives under `prefix` up to the next level (depth+1).
    child = Counter()
    pref = prefix + "\\"
    for d, c in full_dir_counts.items():
        if d == prefix or d.startswith(pref):
            child[roll_dir(d, depth)] += c
    # Drop the bucket's own self-level (a child identical to prefix adds nothing).
    child.pop(prefix, None)
    if not child:
        return
    for sub, c in child.most_common():
        pct = 100.0 * c / parent_total
        # A single child that IS the whole parent (100%) is a passthrough -- one dir
        # with one subdir -- so showing it and recursing adds depth with no signal.
        # Skip straight past it to its own children.
        if len(child) == 1 and abs(pct - 100.0) < 0.001:
            breakdown_bucket(full_dir_counts, sub, c, depth + 1, threshold,
                             out, indent, max_extra_depth)
            return
        out.append((indent, sub, c, pct))
        if pct >= threshold:
            breakdown_bucket(full_dir_counts, sub, c, depth + 1, threshold,
                             out, indent + 1, max_extra_depth)


def evtx_total_records(path):
    """Read the evtx FILE HEADER directly for the total record count, so progress can
    be reported as a percentage regardless of which reader is used (the Rust reader
    exposes no up-front count). EVTX file-header layout: bytes 0..7 = 'ElfFile\\x00';
    the u64 at offset 0x18 is next_record_identifier (total records written + 1).
    Returns an int estimate, or 0 if the header can't be read (progress then falls back
    to a plain running count)."""
    import struct
    try:
        with open(path, "rb") as f:
            hdr = f.read(0x20)
        if hdr[:8] != b"ElfFile\x00":
            return 0
        next_record_id = struct.unpack_from("<Q", hdr, 0x18)[0]
        return max(0, next_record_id - 1)
    except Exception:
        return 0



# --- per-archive processing (extracted from v0.1.x main()) ----------------- #
def process_archive(path, top, depth, bins):
    """Stream a single .evtx file and produce a stats dict. Side effects: prints
    progress lines to stderr (same as v0.1.x). Returns a dict that
    print_archive_report() consumes. Raises RuntimeError if reader can't be
    found or if no records can be parsed."""
    file_size = os.path.getsize(path)

    # Reader: prefer the Rust-backed 'evtx' (PyEvtxParser) -- ORDERS of magnitude faster
    # on large files -- and fall back to pure-Python 'python-evtx'. Both yield per-record
    # XML strings, so the parsing below is identical.
    def iter_records_rust():
        from evtx import PyEvtxParser
        p = PyEvtxParser(path)
        for rec in p.records():           # dict with 'data' = XML string
            yield rec["data"]

    def iter_records_pure():
        from Evtx.Evtx import Evtx
        with Evtx(path) as log:
            for rec in log.records():
                yield rec.xml()

    reader = None
    _errs = []
    try:
        import evtx as _evtx_rust          # noqa: F401
        from evtx import PyEvtxParser      # confirm the actual symbol we use exists
        reader, reader_name = iter_records_rust, "evtx (rust)"
    except Exception as _e1:
        _errs.append("evtx (rust): %r" % _e1)
        try:
            import Evtx.Evtx                # noqa: F401
            reader, reader_name = iter_records_pure, "python-evtx (pure)"
        except Exception as _e2:
            _errs.append("python-evtx: %r" % _e2)
            raise RuntimeError("Need an evtx reader. Neither importable:\n   - "
                               + "\n   - ".join(_errs)
                               + "\nInstall one:  pip install evtx   "
                                 "(or: pip install python-evtx)")
    import xml.etree.ElementTree as ET

    eid_counts = Counter()
    dir_counts = Counter()
    full_dir_counts = Counter()   # complete parent dirs (for >40% recursive breakdown)
    FULL_DIR_CAP = 5000           # cap distinct full dirs tracked; beyond this it's noise
    full_dir_capped = False
    drive_counts = Counter()
    ext_counts = Counter()
    cat_counts = Counter()
    op_counts = Counter()
    per_minute = Counter()
    per_hour = Counter()
    resolve_fail = 0
    total = 0
    file_total = 0
    first_dt = None
    last_dt = None
    engine_start_dt = None        # earliest 914 System/TimeCreated (for #4 init-dump flag)

    est_total = evtx_total_records(path)
    if est_total:
        print("Reading %s (%s) via %s -- ~%d records..."
              % (os.path.basename(path), human_size(file_size), reader_name, est_total))
    else:
        print("Reading %s (%s) via %s..."
              % (os.path.basename(path), human_size(file_size), reader_name))
    ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
    # Progress at ~5% milestones (percentage of estimated total). Falls back to a
    # coarse every-100k running count if the header count was unavailable. Printed to
    # stderr so it doesn't pollute the stats output, and infrequently (screen writes
    # are slow relative to record processing). Each line carries elapsed seconds + a
    # wall-clock timestamp so total/processing time is visible on large files.
    import time as _time
    t_start = _time.time()
    next_pct = 5
    try:
        record_iter = reader()
        for i, xml_str in enumerate(record_iter):
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
            total += 1
            eid_el = root.find("./%sSystem/%sEventID" % (ns, ns))
            try:
                eid = int(eid_el.text)
            except Exception:
                eid = -1
            eid_counts[eid] += 1
            datas = root.findall("./%sEventData/%sData" % (ns, ns))
            blob = datas[0].text if datas else ""
            fields = parse_blob(blob or "")

            if eid in FILE_EVENTS:
                file_total += 1
                tf = fields.get("TargetFilename", "")
                if tf:
                    if "\\?\\" in tf:
                        resolve_fail += 1
                    dir_counts[parent_at_depth(tf, depth)] += 1
                    drive_counts[drive_of(tf)] += 1
                    ext_counts[ext_of(tf)] += 1
                    # Full parent dir, for the >=40%-of-parent recursive breakdown.
                    # Count known keys freely; only NEW keys are gated by the cap so a
                    # pathological box can't blow up memory (beyond the cap, extra
                    # distinct dirs are dropped -- the breakdown then just reflects the
                    # first 5000 seen, which is plenty to find the heavy hitters).
                    fd = dir_at_depth(tf, 64)
                    if fd in full_dir_counts or len(full_dir_counts) < FULL_DIR_CAP:
                        full_dir_counts[fd] += 1
                    elif not full_dir_capped:
                        full_dir_capped = True
                cat_counts[fields.get("Category", label_for(eid))] += 1
                dt = parse_utc(fields.get("UtcTime", ""))
                if dt:
                    first_dt = dt if first_dt is None else min(first_dt, dt)
                    last_dt = dt if last_dt is None else max(last_dt, dt)
                    per_minute[dt.strftime("%Y-%m-%d %H:%M")] += 1
                    per_hour[dt.strftime("%Y-%m-%d %H:00")] += 1
            elif eid in DEVICE_EVENTS or eid in OPERATIONAL_EVENTS or eid in TEST_EVENTS:
                op_counts[(eid, flatten_blob(blob, 100))] += 1
                dt = parse_utc(fields.get("UtcTime", ""))
                if dt:
                    first_dt = dt if first_dt is None else min(first_dt, dt)
                    last_dt = dt if last_dt is None else max(last_dt, dt)
                # 914 (Engine Started) carries no UtcTime in its EventData blob; its
                # timestamp lives only in System/TimeCreated. Capture the EARLIEST 914
                # start so series mode can flag an archive that begins at engine boot
                # (initial dump, NOT steady-state) -- #4.
                if eid == 914:
                    tc = root.find("./%sSystem/%sTimeCreated" % (ns, ns))
                    sdt = parse_utc(tc.get("SystemTime")) if tc is not None else None
                    if sdt:
                        engine_start_dt = (sdt if engine_start_dt is None
                                           else min(engine_start_dt, sdt))
    except Exception as exc:
        if total == 0:
            raise RuntimeError("Could not read '%s' as an evtx file (%s). Is it a "
                               "valid, unzipped .evtx?"
                               % (os.path.basename(path), exc))
        print("  (stopped early after %d records: %s)" % (total, exc), file=sys.stderr)

    if total == 0:
        raise RuntimeError("No records parsed from '%s'. Is this a usnmon "
                           "FileSystem .evtx?" % os.path.basename(path))

    read_secs = _time.time() - t_start
    print("  read complete: %d records in %.1fs (%.0f rec/s)"
          % (total, read_secs, total / read_secs if read_secs > 0 else 0),
          file=sys.stderr)

    return {
        "path": path,
        "file_size": file_size,
        "reader_name": reader_name,
        "total": total,
        "file_total": file_total,
        "eid_counts": eid_counts,
        "dir_counts": dir_counts,
        "full_dir_counts": full_dir_counts,
        "full_dir_cap": FULL_DIR_CAP,
        "full_dir_capped": full_dir_capped,
        "drive_counts": drive_counts,
        "ext_counts": ext_counts,
        "cat_counts": cat_counts,
        "op_counts": op_counts,
        "per_minute": per_minute,
        "per_hour": per_hour,
        "resolve_fail": resolve_fail,
        "first_dt": first_dt,
        "last_dt": last_dt,
        "engine_start_dt": engine_start_dt,
        "read_secs": read_secs,
    }


# --- per-archive report printing (extracted from v0.1.x main(); byte-identical) -- #
def print_archive_report(stats, top, depth, bins):
    """Print the full per-archive stats report from a stats dict. Output is
    byte-identical to v0.1.x single-archive output for the same input."""
    path = stats["path"]
    file_size = stats["file_size"]
    total = stats["total"]
    file_total = stats["file_total"]
    eid_counts = stats["eid_counts"]
    dir_counts = stats["dir_counts"]
    full_dir_counts = stats["full_dir_counts"]
    full_dir_capped = stats["full_dir_capped"]
    FULL_DIR_CAP = stats["full_dir_cap"]
    drive_counts = stats["drive_counts"]
    ext_counts = stats["ext_counts"]
    cat_counts = stats["cat_counts"]
    op_counts = stats["op_counts"]
    per_minute = stats["per_minute"]
    per_hour = stats["per_hour"]
    resolve_fail = stats["resolve_fail"]
    first_dt = stats["first_dt"]
    last_dt = stats["last_dt"]

    W = 78
    print("\n" + "=" * W)
    print("usnmon archive statistics  --  %s" % os.path.basename(path))
    print("=" * W)

    print("\n## RUN / THROUGHPUT")
    print("  archive file size      : %s (%d bytes)" % (human_size(file_size), file_size))
    print("  total records          : %d" % total)
    print("  file events (100-106)  : %d" % file_total)
    print("  device events (500s)   : %d"
          % sum(c for e, c in eid_counts.items() if e in DEVICE_EVENTS))
    print("  operational (900s)     : %d"
          % sum(c for e, c in eid_counts.items() if e in OPERATIONAL_EVENTS))
    if first_dt and last_dt and last_dt > first_dt:
        span = last_dt - first_dt
        hrs = span.total_seconds() / 3600.0
        mins = span.total_seconds() / 60.0
        print("  log start (UtcTime)    : %s" % first_dt)
        print("  log end   (UtcTime)    : %s" % last_dt)
        print("  span                   : %s (%.2f h)" % (span, hrs))
        if hrs > 0:
            print("  records / hour         : %.1f" % (total / hrs))
            print("  records / minute       : %.1f" % (total / mins))
            print("  size / hour            : %s" % human_size(file_size / hrs))
            print("  bytes / record         : %.1f" % (file_size / total))
    else:
        print("  (no parseable UtcTime span -- throughput-over-time unavailable)")

    print("\n## EVENT-ID FREQUENCY")
    for eid, c in sorted(eid_counts.items(), key=lambda kv: -kv[1]):
        pct = 100.0 * c / total
        print("  %5s  %-26s %9d  %5.1f%%"
              % (eid if eid >= 0 else "?", label_for(eid), c, pct))

    if cat_counts:
        print("\n## FILE EVENT CATEGORIES")
        for cat, c in cat_counts.most_common():
            print("  %-20s %9d  %5.1f%%" % (cat, c, 100.0 * c / file_total))

    if drive_counts:
        print("\n## BY VOLUME (file events)")
        for dv, c in drive_counts.most_common():
            print("  %-10s %9d  %5.1f%%" % (dv, c, 100.0 * c / file_total))

    if dir_counts:
        counts_full = list(dir_counts.values())
        # Detect the 'sigma-destroyer' cliff: the largest >=5x drop among the top 10
        # talkers. Everything at/above it is EXCLUDED from the primary view (never
        # deleted -- it reappears in the full tail). No cliff -> single report.
        excluded = find_cliff(dir_counts.items(), window=10, ratio=5.0)
        excluded_set = set(d for d, _c in excluded)

        if excluded:
            kept = {d: c for d, c in dir_counts.items() if d not in excluded_set}
            kept_counts = list(kept.values())
            kept_events = sum(kept_counts)
            ex_events = sum(c for _d, c in excluded)

            # ---- PRIMARY: top-talkers TREE (outliers removed) + stats on kept ----
            print("\n## TOP %d DIRECTORY TALKERS -- OUTLIERS EXCLUDED "
                  "(primary, depth %d)" % (top, depth))
            print("  Excluded %d dominant directory(ies) at a >=5x cliff (they bury the"
                  % len(excluded))
            print("  rest of the landscape; shown in full in the tail). Excluded:")
            for d, c in excluded:
                print("    %9d  %5.1f%%  %s" % (c, 100.0 * c / file_total, d))
            print("  --- top talkers among the remaining %d directories "
                  "(%d events; percentages are %% of those %d events) ---"
                  % (len(kept_counts), kept_events, kept_events))
            _print_top_tree(kept, full_dir_counts, kept_events, top, depth, bins,
                            full_dir_capped, FULL_DIR_CAP)
            print("\n## DIRECTORY-COUNT DISTRIBUTION -- OUTLIERS EXCLUDED (primary)")
            _distribution_block(kept_counts, kept_events, bins, "kept")

            # ---- MIDDLE: robust stats + with/without comparison ----
            print("\n## OUTLIERS vs FULL -- comparison (robust + delta)")
            srt_full = sorted(counts_full)
            srt_kept = sorted(kept_counts)
            med_full = srt_full[len(srt_full) // 2]
            med_kept = srt_kept[len(srt_kept) // 2] if srt_kept else 0
            mu_full, sd_full = mean_std(counts_full)
            mu_kept, sd_kept = mean_std(kept_counts)
            print("  Robust stats are outlier-resistant -- median/percentiles/MAD do not"
                  " blow up the\n  way mean/sigma do when one directory dominates.")
            print("  %-22s %14s %14s" % ("", "FULL", "OUTLIERS-EXCL"))
            print("  %-22s %14d %14d" % ("directories", len(counts_full),
                                         len(kept_counts)))
            print("  %-22s %14.1f %14.1f" % ("mean", mu_full, mu_kept))
            print("  %-22s %14.1f %14.1f" % ("std dev (sigma)", sd_full, sd_kept))
            print("  %-22s %14d %14d" % ("median", med_full, med_kept))
            print("  %-22s %14d %14d" % ("MAD", median_abs_deviation(counts_full, med_full),
                                         median_abs_deviation(kept_counts, med_kept)))
            for p in (75, 90, 95, 99):
                print("  %-22s %14d %14d"
                      % ("p%d" % p, percentile(srt_full, p), percentile(srt_kept, p)))
            print("  Excluding %d of %d dirs (%.1f%% of directories) removed %d events "
                  "(%.1f%% of file events)."
                  % (len(excluded), len(counts_full),
                     100.0 * len(excluded) / len(counts_full),
                     ex_events, 100.0 * ex_events / file_total))
            print("  -> the primary view above shows 100%% of the non-dominant "
                  "directories at full resolution.")

            # ---- TAIL: complete top-talkers TREE + distribution, nothing excluded ----
            print("\n## TOP %d DIRECTORY TALKERS -- FULL (tail, depth %d; "
                  "percentages are %% of all %d file events)"
                  % (top, depth, file_total))
            _print_top_tree(dir_counts, full_dir_counts, file_total, top, depth, bins,
                            full_dir_capped, FULL_DIR_CAP)
            print("\n## DIRECTORY-COUNT DISTRIBUTION -- FULL (all directories, nothing "
                  "excluded)")
            _distribution_block(counts_full, file_total, bins, "full")
        else:
            # No cliff -> the current single report, unchanged.
            print("\n## TOP %d DIRECTORY TALKERS (depth %d)" % (top, depth))
            print("  (no >=5x cliff among the top talkers -- no outliers excluded)")
            _print_top_tree(dir_counts, full_dir_counts, file_total, top, depth, bins,
                            full_dir_capped, FULL_DIR_CAP)
            print("\n## DIRECTORY-COUNT DISTRIBUTION")
            _distribution_block(counts_full, file_total, bins, "full")

    if ext_counts:
        print("\n## TOP FILE EXTENSIONS (file events)")
        for e, c in ext_counts.most_common(15):
            print("  %-12s %9d  %5.1f%%" % (e, c, 100.0 * c / file_total))

    if per_minute:
        busiest = per_minute.most_common(1)[0]
        permin_vals = list(per_minute.values())
        mu_m, sd_m = mean_std(permin_vals)
        print("\n## TEMPORAL")
        print("  active minutes         : %d" % len(per_minute))
        print("  busiest minute         : %s  (%d events)" % busiest)
        print("  mean events/active min : %.1f  (sigma %.1f)" % (mu_m, sd_m))
        if per_hour:
            print("  per-hour buckets       : %d" % len(per_hour))
            bh = per_hour.most_common(1)[0]
            print("  busiest hour           : %s  (%d events)" % bh)

    if file_total:
        print("\n## RESOLUTION HEALTH")
        print("  unresolved paths (\\?\\) : %d  (%.2f%% of file events)"
              % (resolve_fail, 100.0 * resolve_fail / file_total))

    if op_counts:
        print("\n## OPERATIONAL / DEVICE EVENTS (detail)")
        by_eid = defaultdict(lambda: [0, ""])
        for (eid, msg), c in op_counts.items():
            by_eid[eid][0] += c
            if not by_eid[eid][1]:
                by_eid[eid][1] = msg
        for eid in sorted(by_eid):
            cnt, sample = by_eid[eid]
            print("  %5d  %-22s %6d   e.g. %s"
                  % (eid, label_for(eid), cnt, sample))

    print("\n" + "=" * W)


# --- series-mode report sections (v0.2.0 additions) ------------------------ #
INIT_DUMP_TOLERANCE_SEC = 5       # #4: first_dt within this of an engine-start 914


def is_initial_dump(stats, tolerance_sec=INIT_DUMP_TOLERANCE_SEC):
    """True if this archive begins AT an engine start: its earliest file event
    (first_dt) is within `tolerance_sec` of the earliest 914 (Engine Started)
    System/TimeCreated. Such an archive's leading portion is the startup dump, not
    steady-state activity -- its span/rate over-represent the capture and should not
    be read as a live rate (#4). Returns False when either timestamp is missing
    (e.g. v0.0.7 archives processed before TimeCreated capture, or archives with no
    914)."""
    fd = stats.get("first_dt")
    es = stats.get("engine_start_dt")
    if not (fd and es):
        return False
    return abs((fd - es).total_seconds()) <= tolerance_sec


def print_consolidated_summary(per_archive, top, depth):
    """Top-level summary across all archives in the series. Aggregates totals,
    overall span, event-ID frequency, top directories, top extensions, and
    operational events. Subsequent v0.2.x releases add sections for self-integrity
    check, session inference, and rotation capacity projection; this version
    provides the scaffold + basic aggregate numbers."""
    if not per_archive:
        return
    W = 78
    n_arch = len(per_archive)
    total_records = sum(s["total"] for s in per_archive)
    total_file_events = sum(s["file_total"] for s in per_archive)
    total_bytes = sum(s["file_size"] for s in per_archive)
    total_unresolved = sum(s["resolve_fail"] for s in per_archive)
    total_dev_events = sum(
        sum(c for e, c in s["eid_counts"].items() if e in DEVICE_EVENTS)
        for s in per_archive)
    total_op_events = sum(
        sum(c for e, c in s["eid_counts"].items() if e in OPERATIONAL_EVENTS)
        for s in per_archive)

    starts = [s["first_dt"] for s in per_archive if s["first_dt"]]
    ends = [s["last_dt"] for s in per_archive if s["last_dt"]]
    earliest = min(starts) if starts else None
    latest = max(ends) if ends else None

    agg_eid = Counter()
    agg_drive = Counter()
    agg_ext = Counter()
    agg_dir = Counter()
    agg_op = Counter()        # (eid, sample) -> count   (samples may dedupe)
    for s in per_archive:
        agg_eid.update(s["eid_counts"])
        agg_drive.update(s["drive_counts"])
        agg_ext.update(s["ext_counts"])
        agg_dir.update(s["dir_counts"])
        agg_op.update(s["op_counts"])

    print("=" * W)
    print("usnmon SERIES CONSOLIDATED SUMMARY  --  %d archive(s)" % n_arch)
    print("=" * W)

    print("\n## SERIES OVERVIEW")
    print("  archives                  : %d" % n_arch)
    print("  total records             : %d" % total_records)
    print("  total file events         : %d" % total_file_events)
    print("  total device events       : %d" % total_dev_events)
    print("  total operational events  : %d" % total_op_events)
    print("  combined archive size     : %s (%d bytes)"
          % (human_size(total_bytes), total_bytes))
    if earliest and latest and latest > earliest:
        span = latest - earliest
        hrs = span.total_seconds() / 3600.0
        print("  earliest log_start (UTC)  : %s" % earliest)
        print("  latest   log_end   (UTC)  : %s" % latest)
        print("  series span               : %s (%.2f h)" % (span, hrs))
        if hrs > 0:
            print("  series records / hour     : %.1f" % (total_records / hrs))
            print("  series MB / hour          : %.2f"
                  % (total_bytes / 1024.0 / 1024.0 / hrs))

    # #4: flag any archive that begins at engine boot (initial dump). Its startup
    # backfill is folded into the series span/rate above; warn the operator so the
    # rate isn't misread as a steady-state live rate. Label only -- no silent
    # recompute (the operator excludes it themselves if they want a live rate).
    dumps = [s for s in per_archive if is_initial_dump(s)]
    if dumps:
        print("  NOTE: %d archive(s) begin at engine start (initial dump, NOT steady-"
              "state);" % len(dumps))
        print("        the series span/rate above include that startup backfill -- "
              "exclude these")
        print("        archive(s) for a true live rate:")
        for s in dumps:
            print("          %s" % os.path.basename(s["path"]))

    if agg_eid and total_records > 0:
        print("\n## SERIES EVENT-ID FREQUENCY (aggregate)")
        for eid, c in sorted(agg_eid.items(), key=lambda kv: -kv[1]):
            pct = 100.0 * c / total_records
            print("  %5s  %-26s %9d  %5.1f%%"
                  % (eid if eid >= 0 else "?", label_for(eid), c, pct))

    if agg_drive and total_file_events > 0:
        print("\n## SERIES BY VOLUME (file events, aggregate)")
        for dv, c in agg_drive.most_common():
            print("  %-10s %9d  %5.1f%%"
                  % (dv, c, 100.0 * c / total_file_events))

    if agg_dir and total_file_events > 0:
        print("\n## SERIES TOP %d DIRECTORY TALKERS (depth %d, aggregate)"
              % (top, depth))
        for d, c in agg_dir.most_common(top):
            print("  %9d  %5.1f%%  %s"
                  % (c, 100.0 * c / total_file_events, d))

    if agg_ext and total_file_events > 0:
        print("\n## SERIES TOP FILE EXTENSIONS (aggregate)")
        for e, c in agg_ext.most_common(15):
            print("  %-12s %9d  %5.1f%%"
                  % (e, c, 100.0 * c / total_file_events))

    if total_file_events > 0:
        print("\n## SERIES RESOLUTION HEALTH")
        pct = 100.0 * total_unresolved / total_file_events
        print("  unresolved paths (\\?\\) : %d  (%.2f%% of file events)"
              % (total_unresolved, pct))

    if agg_op:
        print("\n## SERIES OPERATIONAL / DEVICE EVENTS (detail)")
        by_eid = defaultdict(lambda: [0, ""])
        for (eid, msg), c in agg_op.items():
            by_eid[eid][0] += c
            if not by_eid[eid][1]:
                by_eid[eid][1] = msg
        for eid in sorted(by_eid):
            cnt, sample = by_eid[eid]
            print("  %5d  %-22s %6d   e.g. %s"
                  % (eid, label_for(eid), cnt, sample))


def print_self_integrity_check(per_archive):
    """Self-integrity check: does usnmon's coverage chain cleanly across the series?
    Surfaces gaps, restarts, missing close events, missing self-activity, and any
    anomaly events (916/918/919/922/923/925/926).

    Sorts by chronological log_start (NOT filename) for the continuity check, so
    that archives copied in non-chronological order still get a correct gap
    analysis. Filename-sort is preserved everywhere else (comparison table, per-
    archive reports) because that's the on-disk order the investigator sees.

    Anomalies surfaced here complement (don't replace) usnmon's live 925/926
    events: live detection happens when usnmon notices a gap at startup; this
    retrospective check inspects the series after the fact and catches gaps even
    if usnmon never noticed them (e.g., if the engine was hard-killed and the
    next start happened on a different machine without a 925)."""
    if not per_archive:
        return
    W = 78
    print("\n## SERIES SELF-INTEGRITY CHECK")

    # Coverage continuity: sort chronologically by first_dt, then check each
    # archive's first_dt is "close enough" to the previous archive's last_dt.
    # "Close enough" = within 60 seconds (the rotation handoff itself takes a few
    # seconds, and clock skew between archive close and engine restart can add
    # more). Bigger gaps get reported.
    GAP_TOLERANCE_SEC = 60
    chrono = sorted(
        per_archive,
        key=lambda s: (s["first_dt"] or datetime.max, os.path.basename(s["path"]))
    )
    gaps = []
    for i in range(1, len(chrono)):
        prev = chrono[i - 1]
        cur = chrono[i]
        if not (prev["last_dt"] and cur["first_dt"]):
            continue
        delta = (cur["first_dt"] - prev["last_dt"]).total_seconds()
        if delta > GAP_TOLERANCE_SEC:
            gaps.append((prev, cur, delta))
        elif delta < -1:        # overlap suggests the order is wrong somehow
            gaps.append((prev, cur, delta))

    n_arch = len(per_archive)
    if not gaps:
        print("  Coverage continuity   : OK  (%d archives chain within %ds tolerance)"
              % (n_arch, GAP_TOLERANCE_SEC))
    else:
        print("  Coverage continuity   : %d break(s) in chronological chain "
              "(>%ds between an archive's close and the next's start)"
              % (len(gaps), GAP_TOLERANCE_SEC))
        print("     (could be intentional -- subset of archives in this dir -- "
              "or real gaps in capture; verify against expectations)")
        for prev, cur, delta in gaps:
            prev_name = os.path.basename(prev["path"])
            cur_name = os.path.basename(cur["path"])
            if delta < 0:
                marker = "OVERLAP"
                delta_s = "%.0fs" % delta
            elif delta < 3600:
                marker = "break"
                delta_s = "%.0fs" % delta
            elif delta < 86400:
                marker = "break"
                delta_s = "%.1fh" % (delta / 3600.0)
            else:
                marker = "BREAK"
                delta_s = "%.1fd" % (delta / 86400.0)
            print("     %s  %s -> %s  (%s after %s)"
                  % (marker, prev_name, cur_name, delta_s,
                     prev["last_dt"].replace(microsecond=0)))

    # Engine restarts: archives containing 914 events.
    restart_archives = [s for s in per_archive if s["eid_counts"].get(914, 0) > 0]
    total_914 = sum(s["eid_counts"].get(914, 0) for s in per_archive)
    if not restart_archives:
        print("  Engine restarts       : none (no 914 events in series)")
    else:
        print("  Engine restarts       : %d event(s) across %d archive(s)"
              % (total_914, len(restart_archives)))
        for s in restart_archives:
            n = s["eid_counts"].get(914, 0)
            print("     %s  (%d x 914)" % (os.path.basename(s["path"]), n))

    # Archive-close count: every archive that CLOSED writes a 904 (the next archive's
    # FIRST records reference the previous archive's close). A directory snapshot of
    # N archives normally contains N-1 close events (the latest archive hasn't been
    # closed yet -- it's the in-progress channel). If 904 count == N, all archives
    # are sealed (no in-progress). If 904 count < N-1, some closes are missing.
    total_904 = sum(s["eid_counts"].get(904, 0) for s in per_archive)
    if total_904 == n_arch - 1:
        print("  Archive-close events  : %d of %d  (one in-progress archive: %s)"
              % (total_904, n_arch, os.path.basename(chrono[-1]["path"])))
    elif total_904 == n_arch:
        print("  Archive-close events  : %d of %d  (all archives sealed)"
              % (total_904, n_arch))
    elif total_904 < n_arch - 1:
        print("  Archive-close events  : %d of %d  (POSSIBLE missing closes: "
              "expected %d or %d)" % (total_904, n_arch, n_arch - 1, n_arch))
    else:
        print("  Archive-close events  : %d of %d  (unexpected -- more closes "
              "than archives)" % (total_904, n_arch))

    # Self-archive activity: every archive should show FileSystem_Archives directory
    # activity (the engine writes its own bundles there during the rotation cycle).
    # If an archive shows zero, usnmon was not actually rotating during that window.
    # Honest: the dir_counts here are rolled-up at depth, so we look for any dir
    # that ENDS with FileSystem_Archives (caller may have configured a different
    # archive_dir name, in which case this won't fire -- known limitation, OK for v1).
    SELF_HINT = "FileSystem_Archives"
    self_active = 0
    self_silent = []
    for s in per_archive:
        had = any(SELF_HINT in d for d in s["dir_counts"])
        if had:
            self_active += 1
        else:
            self_silent.append(s)
    if self_active == n_arch:
        print("  Self-archive activity : %d/%d archives show '%s' writes"
              % (self_active, n_arch, SELF_HINT))
    else:
        print("  Self-archive activity : %d/%d archives show '%s' writes  "
              "(%d silent)" % (self_active, n_arch, SELF_HINT,
                               len(self_silent)))
        for s in self_silent:
            print("     silent: %s" % os.path.basename(s["path"]))

    # Anomaly events: degraded-operation IDs (916/918/919/922/923) and the v0.0.8+
    # retrospective-gap/clock-anomaly IDs (925/926). 914 (restart) and 920 (unsupported
    # FS) are LIFECYCLE events, not anomalies -- already surfaced above and in the
    # operational detail block, not double-counted here.
    ANOMALY_EIDS = {916, 918, 919, 922, 923, 925, 926}
    anomalies = []
    for s in per_archive:
        for eid in ANOMALY_EIDS:
            n = s["eid_counts"].get(eid, 0)
            if n > 0:
                anomalies.append((s, eid, n))
    if not anomalies:
        print("  Anomaly events        : none (916/918/919/922/923/925/926 all 0)")
    else:
        print("  Anomaly events        : %d total" % sum(n for _, _, n in anomalies))
        for s, eid, n in anomalies:
            print("     %5d  %-22s  %d x  in %s"
                  % (eid, label_for(eid), n, os.path.basename(s["path"])))


# --- session inference: known directory-pattern signatures ---------------------
#
# Each PATTERNS entry describes one known activity signature. The matcher walks
# the named counter on each archive's stats dict (either "dir_counts" -- the
# rolled-up depth-4 view -- or "full_dir_counts" -- the deeper view up to depth
# 64), runs the regex against each path, and accumulates event counts.
#
# If a `capture_group` is set, the regex MUST have a capture; matches are
# grouped by capture value (e.g. WSL GUID -> per-GUID totals). If
# `capture_group` is None, all matching paths in an archive are summed into a
# single "no_capture" bucket per archive.
#
# A pattern fires for the operator's attention only when an archive's matched
# event count >= `threshold`. Below threshold = "we checked, saw small or no
# activity, not worth surfacing." Tuning these defaults requires baseline data
# from multiple machine personas; the values below are starting guesses, to be
# refined as Project 3's stats-baseline tool collects data from the test boxes
# (media streamer, camera viewer, light-use laptop, busy box, idle DFIR VM).
PATTERNS = [
    {
        "label": "WSL session (Ubuntu)",
        "regex": (r"CanonicalGroupLimited\.Ubuntu[^\\]*\\LocalState\\temp\\"
                  r"(\{[0-9a-f-]+\})"),
        "capture_group": 1,
        "threshold": 50,
        "scan": "full_dir_counts",
    },
    {
        "label": "Chrome user activity",
        "regex": r"\\Google\\Chrome\\User Data\\Default",
        "capture_group": None,
        "threshold": 50,
        "scan": "full_dir_counts",
    },
    {
        "label": "Edge user activity",
        "regex": r"\\Microsoft\\Edge\\User Data\\Default",
        "capture_group": None,
        "threshold": 50,
        "scan": "full_dir_counts",
    },
    {
        "label": "Firefox profile activity",
        "regex": r"\\Mozilla\\Firefox\\Profiles\\",
        "capture_group": None,
        "threshold": 50,
        "scan": "full_dir_counts",
    },
    {
        "label": "Firefox background updates",
        "regex": r"\\Mozilla-[0-9a-f-]+\\updates",
        "capture_group": None,
        "threshold": 100,
        "scan": "dir_counts",
    },
    {
        "label": "RDP session (Terminal Server Client cache)",
        "regex": r"\\Terminal Server Client\\Cache",
        "capture_group": None,
        "threshold": 10,
        "scan": "full_dir_counts",
    },
    {
        "label": "PSReadLine (interactive PowerShell)",
        "regex": r"\\PowerShell\\PSReadLine",
        "capture_group": None,
        "threshold": 5,
        "scan": "full_dir_counts",
    },
]


def _match_pattern(pattern, per_archive):
    """Apply one PATTERNS entry across the series. Returns a list of (capture_key,
    [(archive_basename, event_count), ...]) tuples for archives whose matched
    event count >= threshold.

    `capture_key` is the regex capture value if `capture_group` is set; otherwise
    the string "*" (single bucket per archive).

    Below-threshold matches are silently dropped (they're surfaced as part of the
    "no activity above threshold" summary line in print_session_inference)."""
    rx = re.compile(pattern["regex"])
    cap = pattern.get("capture_group")
    scan_field = pattern["scan"]
    threshold = pattern["threshold"]

    # Map of capture_key -> {archive_basename: total_events_for_that_key}
    by_key = defaultdict(lambda: defaultdict(int))
    for s in per_archive:
        counter = s.get(scan_field) or Counter()
        per_archive_keys = defaultdict(int)
        for path, n in counter.items():
            m = rx.search(path)
            if not m:
                continue
            key = m.group(cap) if cap else "*"
            per_archive_keys[key] += n
        # Apply threshold per-archive per-key, not globally
        archive_name = os.path.basename(s["path"])
        for key, total in per_archive_keys.items():
            if total >= threshold:
                by_key[key][archive_name] = total

    # Convert to ordered list of (key, [(archive, count), ...])
    out = []
    for key, archives in by_key.items():
        archives_sorted = sorted(archives.items(), key=lambda kv: kv[0])
        out.append((key, archives_sorted))
    out.sort(key=lambda kv: -sum(c for _, c in kv[1]))   # most-active first
    return out


def print_session_inference(per_archive):
    """Surface known session/activity signatures with per-archive event counts.
    Output is presentation, not inference: we report what's there, the operator
    decides what it means. Below-threshold matches are summarized in a single
    line rather than enumerated."""
    if not per_archive:
        return
    print("\n## SERIES SESSION INFERENCE  (>=threshold events per archive; "
          "tune thresholds in PATTERNS list)")
    # Flag the full_dir_counts cap if any archive hit it, since session-inference
    # patterns that scan deep paths may be incomplete.
    capped = [s for s in per_archive if s.get("full_dir_capped")]
    if capped:
        print("  (NOTE: %d archive(s) hit the 5000-distinct-dir cap on deep-path "
              "tracking; some\n   deep-path patterns -- WSL, Chrome, Edge, "
              "Firefox profile, RDP, PSReadLine -- may be\n   incomplete for "
              "those archives.)" % len(capped))
    no_signal = []
    for pattern in PATTERNS:
        results = _match_pattern(pattern, per_archive)
        if not results:
            no_signal.append(pattern["label"])
            continue
        print("  %s (threshold=%d):"
              % (pattern["label"], pattern["threshold"]))
        for key, archives in results:
            grand_total = sum(c for _, c in archives)
            if key == "*":
                # No-capture pattern: just list per-archive matches
                print("     total: %d" % grand_total)
            else:
                print("     %s  total: %d" % (key, grand_total))
            for archive_name, count in archives:
                print("        archive %s   %d events" % (archive_name, count))
    if no_signal:
        print("  No activity above threshold: %s" % ", ".join(no_signal))


# --- rotation capacity projection ---------------------------------------------
#
# Surfaces operator-actionable guidance: given the observed records/hr and
# bytes/record across the series, how long does it take to reach common archive
# size targets (1 GB / 3.5 GB legal-evidence cap / 5 GB), and what cadence
# recommendation falls out?
#
# Presentation, not prescription: we publish the math and several rotation
# candidates so the operator can compare them against their own constraints
# (legal retention, disk space, investigative coverage window). The 3.5 GB
# target deserves explanation -- it's the conservative legal-evidence-handling
# threshold below which most forensic tooling and chain-of-custody workflows
# treat an archive as a single integral artifact; above that, archives often
# need to be split for evidence packaging, which adds chain-of-custody overhead.
ROTATION_TARGETS_BYTES = [
    ("1 GB", 1 * 1024 * 1024 * 1024),
    ("3.5 GB (legal-evidence cap)", int(3.5 * 1024 * 1024 * 1024)),
    ("5 GB", 5 * 1024 * 1024 * 1024),
]


def _human_duration(hours):
    """Render an hours value as 'N.Nd' if >=24h or 'N.Nh' otherwise."""
    if hours is None:
        return "?"
    if hours >= 24:
        return "%.1fd" % (hours / 24.0)
    return "%.1fh" % hours


def print_rotation_capacity_projection(per_archive):
    """Surface the observed throughput and project archive fill times. The
    operator decides what cadence to use; this section gives them the math.

    Computes from the per-archive stats (NOT from per-archive divisions, which
    suffer when one archive is the engine-restart outlier with a short span)
    using the series totals: total file size / total span = MB/hour;
    total records / total span = records/hour. These are the SUSTAINED rates
    the operator should plan around."""
    if not per_archive:
        return

    # Compute series-aggregate throughput. Same math as SERIES OVERVIEW uses,
    # repeated here to keep this section self-contained and to add the per-archive
    # min/max framing.
    total_records = sum(s["total"] for s in per_archive)
    total_bytes = sum(s["file_size"] for s in per_archive)
    starts = [s["first_dt"] for s in per_archive if s["first_dt"]]
    ends = [s["last_dt"] for s in per_archive if s["last_dt"]]
    if not (starts and ends):
        return
    earliest, latest = min(starts), max(ends)
    span_hours = (latest - earliest).total_seconds() / 3600.0
    if span_hours <= 0:
        return

    series_rec_per_hr = total_records / span_hours
    series_mb_per_hr = (total_bytes / 1024.0 / 1024.0) / span_hours
    bytes_per_record = (total_bytes / total_records) if total_records else 0

    print("\n## SERIES ROTATION CAPACITY PROJECTION")
    print("  Observed throughput (series aggregate):")
    print("     records / hour      : %.0f" % series_rec_per_hr)
    print("     MB      / hour      : %.2f" % series_mb_per_hr)
    print("     bytes   / record    : %.0f" % bytes_per_record)

    # Per-archive min/max throughput, for operators who want to plan against the
    # worst-case hour rather than the average.
    per_arc_rates = []
    for s in per_archive:
        if s["first_dt"] and s["last_dt"]:
            hrs = (s["last_dt"] - s["first_dt"]).total_seconds() / 3600.0
            if hrs > 0:
                per_arc_rates.append((s["total"] / hrs,
                                      s["file_size"] / 1024.0 / 1024.0 / hrs,
                                      os.path.basename(s["path"])))
    if per_arc_rates:
        per_arc_rates.sort(key=lambda r: r[0])
        lo_r, lo_m, lo_n = per_arc_rates[0]
        hi_r, hi_m, hi_n = per_arc_rates[-1]
        print("  Per-archive throughput range:")
        print("     quietest archive    : %.0f rec/hr, %.2f MB/hr  (%s)"
              % (lo_r, lo_m, lo_n))
        print("     busiest archive     : %.0f rec/hr, %.2f MB/hr  (%s)"
              % (hi_r, hi_m, hi_n))

    # Project fill times for common archive-size targets at the SERIES rate.
    # Operators planning for peak load should mentally substitute the busiest
    # archive's MB/hour, which is also shown above.
    print("  Projected fill time (at series rate of %.2f MB/hr):"
          % series_mb_per_hr)
    if series_mb_per_hr <= 0:
        print("     (rate is zero; cannot project)")
    else:
        for label, target_bytes in ROTATION_TARGETS_BYTES:
            target_mb = target_bytes / 1024.0 / 1024.0
            hours = target_mb / series_mb_per_hr
            print("     %-32s : %s" % (label, _human_duration(hours)))

    # Cadence recommendations: how would common rotation choices play out at the
    # observed rate? "M" = calendar month (~30 days), "h" = hours interval.
    # For each candidate, compute the projected per-archive size at observed rate.
    print("  Cadence projections (at series rate of %.2f MB/hr):"
          % series_mb_per_hr)
    if series_mb_per_hr <= 0:
        print("     (rate is zero; cannot project)")
    else:
        candidates = [
            ("1h  rotation", 1.0),
            ("6h  rotation", 6.0),
            ("12h rotation", 12.0),
            ("24h rotation", 24.0),
            ("1W  rotation (7d)", 24.0 * 7),
            ("1M  rotation (~30d)", 24.0 * 30),
        ]
        for label, hours in candidates:
            archive_mb = series_mb_per_hr * hours
            archives_per_year = (365 * 24) / hours
            # Flag candidates whose projected archive size exceeds 3.5 GB
            # (the legal-evidence threshold).
            split_warning = ""
            if archive_mb > 3.5 * 1024:
                split_warning = "  *** EXCEEDS 3.5 GB cap -- would split ***"
            elif archive_mb > 1024:
                split_warning = "  (>1 GB per archive)"
            print("     %-22s : %7.1f MB/archive, %5.0f archives/year%s"
                  % (label, archive_mb, archives_per_year, split_warning))

    # Brief framing of the math the operator can verify. Honest disclaimers:
    # rates are based on observed activity; future activity may differ; legal-
    # retention requirements may dominate the choice independently of size.
    print("  Notes:")
    print("     - Rates are observed across the SERIES; actual rates fluctuate "
          "per archive (range above).")
    print("     - 3.5 GB threshold is a common forensic-handling limit; "
          "exceeding it usually forces split.")
    print("     - Legal-retention requirements may dominate rotation choice "
          "independently of size.")
    print("     - Real activity varies week-to-week; baseline several periods "
          "before locking cadence.")


def print_comparison_table(per_archive):
    """One row per archive with the key signals. Lets an investigator scan a
    long series and spot anomalous archives at a glance."""
    if not per_archive:
        return
    W = 78
    print("\n" + "=" * W)
    print("PER-ARCHIVE COMPARISON  --  %d archive(s)" % len(per_archive))
    print("=" * W)
    print()
    # First table: throughput + counts
    fmt = ("%-44s  %8s  %9s  %10s  %6s  %7s  %-10s")
    print(fmt % ("archive", "span(h)", "records", "rec/hr", "ops",
                 "unres%", "top-ext"))
    print(fmt % ("-" * 44, "-" * 8, "-" * 9, "-" * 10, "-" * 6,
                 "-" * 7, "-" * 10))
    any_burst = False
    any_dump = False
    for s in per_archive:
        name = os.path.basename(s["path"])
        if len(name) > 44:
            name = name[:41] + "..."
        first, last = s["first_dt"], s["last_dt"]
        if first and last and last > first:
            hrs = (last - first).total_seconds() / 3600.0
            span_s = "%.2f" % hrs
            rec_per_hr = ("%d" % int(s["total"] / hrs)) if hrs > 0 else "?"
        else:
            span_s, rec_per_hr = "?", "?"
        ops = sum(c for e, c in s["eid_counts"].items()
                  if e in OPERATIONAL_EVENTS)
        unres_pct = ((100.0 * s["resolve_fail"] / s["file_total"])
                     if s["file_total"] > 0 else 0.0)
        top_ext = (s["ext_counts"].most_common(1)[0][0]
                   if s["ext_counts"] else "?")
        # Burst-vs-continuous flag (#2): a single minute holds >50% of the file
        # events AND active minutes are <10% of the span. Catches an archive whose
        # rec/hr is inflated by one short burst (e.g. an install) rather than a
        # sustained rate. per_minute counts FILE events only, so the ratio is
        # against file_total (both file-event-based) -- decision 1A.
        burst_flag = ""
        per_minute = s["per_minute"]
        if per_minute and s["file_total"] > 0 and first and last and last > first:
            top_min = max(per_minute.values())
            active_min = len(per_minute)
            span_min = (last - first).total_seconds() / 60.0
            if (top_min > 0.5 * s["file_total"]
                    and span_min > 0 and active_min < 0.1 * span_min):
                burst_flag = "  *BURST*"
                any_burst = True
        # Initial-dump flag (#4): archive begins at engine boot, so its span/rate
        # reflect the startup backfill, not steady-state.
        dump_flag = "  *INIT-DUMP*" if is_initial_dump(s) else ""
        if dump_flag:
            any_dump = True
        print((fmt % (name, span_s, "%d" % s["total"], rec_per_hr,
                      "%d" % ops, "%.2f" % unres_pct, top_ext))
              + burst_flag + dump_flag)
    if any_burst:
        print()
        print("  *BURST* = busiest minute holds >50% of file events AND active "
              "minutes < 10% of span;")
        print("            rec/hr is inflated by a short burst, not a sustained "
              "rate -- read with care.")
    if any_dump:
        print()
        print("  *INIT-DUMP* = first event within %ds of an engine-start (914); "
              "archive begins at" % INIT_DUMP_TOLERANCE_SEC)
        print("                engine boot, so its span/rec-hr reflect the startup "
              "dump, not a live rate.")
    # Second table: top directory per archive (separate to avoid line-width blowup)
    print()
    print("PER-ARCHIVE TOP DIRECTORY:")
    print()
    fmt2 = "%-44s  %9s  %s"
    print(fmt2 % ("archive", "events", "top-directory"))
    print(fmt2 % ("-" * 44, "-" * 9, "-" * 13))
    for s in per_archive:
        name = os.path.basename(s["path"])
        if len(name) > 44:
            name = name[:41] + "..."
        if s["dir_counts"]:
            d, c = s["dir_counts"].most_common(1)[0]
            print(fmt2 % (name, "%d" % c, d))
        else:
            print(fmt2 % (name, "?", "(no file events)"))


def run_series(directory, top, depth, bins):
    """Process all .evtx files in `directory`, sorted by filename (chronological
    under usnmon's naming). Print the three-layer report to stdout."""
    try:
        entries = os.listdir(directory)
    except Exception as exc:
        print("Could not list directory '%s': %s" % (directory, exc))
        return
    evtx_files = sorted(f for f in entries if f.lower().endswith(".evtx"))
    if not evtx_files:
        print("No .evtx files found in directory: %s" % directory)
        return

    per_archive = []
    for fname in evtx_files:
        path = os.path.join(directory, fname)
        try:
            stats = process_archive(path, top, depth, bins)
        except RuntimeError as exc:
            print("  [skipping %s: %s]" % (fname, exc), file=sys.stderr)
            continue
        per_archive.append(stats)

    if not per_archive:
        print("No parseable archives in directory: %s" % directory)
        return

    # Layer 1: consolidated summary
    print_consolidated_summary(per_archive, top, depth)

    # Layer 1b: self-integrity check (between consolidated and comparison)
    print_self_integrity_check(per_archive)

    # Layer 1c: session inference (known directory-pattern signatures)
    print_session_inference(per_archive)

    # Layer 1d: rotation capacity projection (operator cadence guidance)
    print_rotation_capacity_projection(per_archive)

    # Layer 2: per-archive comparison table
    print_comparison_table(per_archive)

    # Layer 3: full per-archive reports, in chronological (filename) order
    for stats in per_archive:
        print_archive_report(stats, top, depth, bins)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    path = sys.argv[1]
    top = int(sys.argv[sys.argv.index("--top") + 1]) if "--top" in sys.argv else 25
    depth = int(sys.argv[sys.argv.index("--depth") + 1]) if "--depth" in sys.argv else 4
    bins = int(sys.argv[sys.argv.index("--bins") + 1]) if "--bins" in sys.argv else 20

    if not os.path.exists(path):
        print("File not found:", path)
        return

    if os.path.isdir(path):
        # Series mode: directory of archives.
        run_series(path, top, depth, bins)
    else:
        # Single-archive mode: byte-identical output to v0.1.x.
        try:
            stats = process_archive(path, top, depth, bins)
        except RuntimeError as exc:
            print(str(exc))
            return
        print_archive_report(stats, top, depth, bins)


if __name__ == "__main__":
    main()
