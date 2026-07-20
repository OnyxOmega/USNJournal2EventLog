"""usn_common.py -- shared library for the USN Journal Monitor.

v0.0.9: LEAN recording-side utilities. Signed-ruleset infrastructure, crypto,
and archive helpers were extracted during the v0.0.9 architectural split.
See the v0.0.9 extraction plan for the architectural rationale.

Three libraries live here:
  1. Event contract  -- EventData field schema, classify, reason text
  2. Stats           -- per-directory distribution (usable by analytical tools)
  3. Archive helpers -- machine id, EvtxECmd CSV wrapper (usable by analytical
                        tools)

Removed during v0.0.9 extraction (see extraction plan for details):
  - Archive management (check_archive_completeness, build_monthly_bundle) --
    logmon now owns archive management.
  - Signed-ruleset infrastructure (RuleMatcher, load_signed_ruleset,
    merge_rulesets, validate_rules, detect_conflicts, sign_doc,
    verify_signature, canonical_bytes, sha256_hex, get_cert_from_store,
    compute_coverage, and their supporting constants) -- preserved locally in
    signed_rulesets_reference.py for future analysis-side tooling. NOT
    committed to any repository.

Platform note: the machine-id helpers use Windows APIs and CANNOT run on
non-Windows. They are written against Windows-specific facilities and must be
tested on the target. Everything else is pure-Python and portable (tested with
`ntpath` for Windows path semantics).
"""

import hashlib
import json
import math
import ntpath
import os
import subprocess
import time
import ctypes
from collections import Counter, OrderedDict

# Contract version. Event field order/names are frozen per MAJOR. The EvtxECmd
# maps, the WEC Cookbook, and SIEM parsing all bind to this.
SCHEMA_VERSION = "2.1"   # 2.1: appended HiResUtc (epoch-ns) to end of blob; additive,
                         # blob-only, no PARAM/contract change. 2.0 maps still parse.

# =========================================================================== #
#  1. EVENT CONTRACT -- field schema, classification, reason text
#     (Frozen by SCHEMA_VERSION. EvtxECmd maps + WEC Cookbook bind to this.)
# =========================================================================== #
# Event IDs by change category.
EVENT_IDS = {
    "Create": 100, "Modify": 101, "Delete": 102, "Rename": 103,
    "SecurityChange": 104, "Other": 105, "RangeChange": 106,
}

# 500-series device/removable-media events (emitted by usnmon on drive arrival/
# removal; identity determined by HW serial preferred, VolumeSerial fallback).
DEVICE_EVENT_IDS = {
    "NEW": 500,          # never seen this device before
    "REMOVED": 501,
    "REATTACHED": 503,   # seen before, identity unchanged (timestamped)
    "ALTERED": 504,      # HW serial matches but VSN changed (reformat/clone/tamper)
}

# Ordered EventData field names. EMITTED POSITIONALLY: ReportEvent gets a list of
# strings -> Data[1]=blob (PARAM[0] in Event Log Explorer), then each field below as
# its own <Data> node. Two tools, two addressing schemes for the SAME strings:
#   EvtxECmd/Timeline Explorer:  Data[1]=blob, Data[2]=field#1, ... (1-based, blob=1)
#   Event Log Explorer (ELE):    PARAM[0]=blob, PARAM[1]=field#1, ... (0-based, blob=0)
#
# ELE custom columns only reliably reach PARAM[1]..PARAM[6] (PARAM[7]+ are not exposed),
# so the eight ELE/join fields are FRONT-LOADED and the six most join-critical sit in
# the reachable PARAM[1..6] slots:
#   PARAM[1]/Data[2] TargetFilename  PARAM[2]/Data[3] UtcTime
#   PARAM[3]/Data[4] MachineGuid     PARAM[4]/Data[5] HwSerial(HWID)
#   PARAM[5]/Data[6] Vsn             PARAM[6]/Data[7] VolumeSerial
#   PARAM[7]/Data[8] Hostname        PARAM[8]/Data[9] SourceIP   (ELE-overflow; still in evtx)
# Everything else follows at Data[10+] (available to EvtxECmd/Velociraptor + the blob).
EVENT_FIELD_NAMES = [
    # --- ELE PARAM[1..8] / Data[2..9] : front-loaded join fields ---
    "TargetFilename", "UtcTime", "MachineGuid", "HwSerial", "Vsn",
    "VolumeSerial", "Hostname", "SourceIP",
    # --- Data[10+] : remaining fields (blob + EvtxECmd + Velociraptor) ---
    "SchemaVersion", "Category", "Reason", "Usn", "JournalId", "FQDN",
    "Domain", "MachineSID", "MAC", "OSBuild", "MachineId", "PreviousVsn",
    # --- appended in 2.1: high-resolution emit timestamp, epoch-nanoseconds int.
    # Blob-only (never a PARAM). Used to compute sub-ms capture-latency deltas that
    # the millisecond-resolution Event Log timestamp cannot express. Always LAST so
    # nothing else shifts and 2.0 maps keep matching their fields.
    "HiResUtc",
    # Raw QueryPerformanceCounter ticks at emit time. The MACHINE-WIDE shared counter:
    # subtracting the harness 800's Qpc from the engine 100's Qpc gives true capture
    # latency with ZERO per-process offset. HiResUtc is the human projection of this.
    "Qpc",
]
# Resulting Data[N] (1-indexed; Data[1]=blob):
#   2 TargetFilename 3 UtcTime 4 MachineGuid 5 HwSerial 6 Vsn 7 VolumeSerial
#   8 Hostname 9 SourceIP 10 SchemaVersion 11 Category 12 Reason 13 Usn
#   14 JournalId 15 FQDN 16 Domain 17 MachineSID 18 MAC 19 OSBuild
#   20 MachineId 21 PreviousVsn
# HwSerial(5)/Vsn(6) = removable-DEVICE identity (500-series; blank on file events).
# VolumeSerial(7) = drive of a FILE event. PreviousVsn(21) = old VSN on a 504.

# Legacy flat PARAM breakout list (now identical to the front-loaded order above).
# The SIX join/identity fields broken out as separate insertion strings for Event Log
# Explorer custom columns -> PARAM[1..6]. ELE reliably reaches only PARAM[0..6], so we
# emit EXACTLY six and nothing more (no PARAM[7]/[8]). Hostname and SourceIP are NOT
# here -- they remain in the blob (PARAM[0]) for EvtxECmd/Velociraptor; Hostname is
# also in ELE's native Computer column. Order = the ELE column order.
PARAM_FIELDS = [
    "TargetFilename", "UtcTime", "MachineGuid", "HwSerial", "Vsn", "VolumeSerial",
]

# USN reason bit flags -> readable names.
REASON_FLAGS = {
    0x00000001: "DataOverwrite",  0x00000002: "DataExtend",
    0x00000004: "DataTruncation", 0x00000010: "NamedDataOverwrite",
    0x00000100: "FileCreate",     0x00000200: "FileDelete",
    0x00000800: "SecurityChange", 0x00001000: "RenameOld",
    0x00002000: "RenameNew",      0x00004000: "IndexableChange",
    0x00008000: "BasicInfoChange", 0x00010000: "HardLinkChange",
    0x00100000: "StreamChange",   0x80000000: "Close",
}

# Reason-bit priority -> (EventID, Category). Higher in this list wins.
_CLASSIFY_ORDER = [
    (0x00000200, "Delete"), (0x00000100, "Create"),
    (0x00001000, "Rename"), (0x00002000, "Rename"),
    (0x00000800, "SecurityChange"),
    (0x00000001, "Modify"), (0x00000002, "Modify"),
    (0x00000004, "Modify"), (0x00000010, "Modify"),
]


def reason_text(reason):
    """Decode USN reason bit-flags into a readable '+'-joined string."""
    parts = [name for bit, name in REASON_FLAGS.items() if reason & bit]
    return " + ".join(parts) if parts else "0x%X" % reason


def classify_event(reason):
    """Map accumulated reason flags to (EventID, Category) by priority.
    Delete > Create > Rename > SecurityChange > Modify > Other."""
    for bit, category in _CLASSIFY_ORDER:
        if reason & bit:
            return EVENT_IDS[category], category
    return EVENT_IDS["Other"], "Other"


_QPC_FREQ = None        # ticks/sec, read once
_QPC_ANCHOR = None      # (anchor_wall_ns, anchor_qpc_ticks) read once at first use


def qpc_now():
    """Raw QueryPerformanceCounter value (ticks). This is the MACHINE-WIDE hardware
    counter -- every process on the box reads the IDENTICAL counter, so QPC values
    from the engine, the harness, and the wrapper are directly comparable with NO
    per-process origin/offset. (Python's time.perf_counter_ns adds a private per-
    process zero; we bypass it by calling QPC raw via ctypes so all processes share
    one timeline.) Returns 0 off-Windows."""
    try:
        c = ctypes.c_int64()
        ctypes.windll.kernel32.QueryPerformanceCounter(ctypes.byref(c))
        return c.value
    except Exception:
        return 0


def qpc_freq():
    """Raw QPC frequency (ticks/sec), cached. Same value for all processes on the box."""
    global _QPC_FREQ
    if _QPC_FREQ is None:
        try:
            f = ctypes.c_int64()
            ctypes.windll.kernel32.QueryPerformanceFrequency(ctypes.byref(f))
            _QPC_FREQ = f.value or 1
        except Exception:
            _QPC_FREQ = 1_000_000_000
    return _QPC_FREQ


def qpc_anchor():
    """One-time (wall_ns, qpc_ticks) pair anchoring the shared QPC counter to the
    coarse wall clock, so HiResUtc can be expressed on the human wall-clock timeline
    while keeping QPC's sub-microsecond RESOLUTION. The coarse wall read is only used
    for human readability; all DELTA math uses raw QPC (which is exact and shared)."""
    global _QPC_ANCHOR
    if _QPC_ANCHOR is None:
        # bracket the wall read between two QPC reads, take QPC midpoint
        q0 = qpc_now()
        w = time.time_ns()
        q1 = qpc_now()
        _QPC_ANCHOR = (w, (q0 + q1) // 2)
    return _QPC_ANCHOR


def hires_utc_ns():
    """High-resolution wall-clock timestamp, epoch-NANOSECONDS as an int string,
    derived from the shared QPC counter (sub-microsecond resolution) anchored to the
    wall clock. Because the underlying counter is machine-wide, the harness's 800
    HiResUtc and the engine's 100 HiResUtc share one timeline and subtract cleanly --
    no per-process offset to reconcile. Use the companion qpc_now() value (emitted as
    'Qpc') for exact raw-counter deltas; HiResUtc is the human-readable projection."""
    aw, aq = qpc_anchor()
    elapsed_ns = (qpc_now() - aq) * 1_000_000_000 // qpc_freq()
    return str(aw + elapsed_ns)


def build_event_strings(values):
    """Build ReportEvent insertion strings for the dual-tool contract:

      PARAM[0] / the single rendered <Data> blob = ALL 21 fields as 'Key: value'
        lines (leading newline so every label is \\n-anchored for regex). This is the
        COMPLETE record -- EvtxECmd/Timeline Explorer regex-extract from it, and
        Velociraptor reads it natively. Nothing is lost here.

      PARAM[1..6] = the six join/identity fields broken out as separate insertion
        strings, for Event Log Explorer custom columns. ELE reliably handles only
        PARAM[0..6] (PARAM[7]+ misbehave), so we emit EXACTLY six and stop -- no
        PARAM[7]/[8]. ELE's six reachable columns are the join-critical fields.

    Total: 7 insertion strings (blob + 6). The other 15 fields live only in the blob,
    which is fine -- every tool that needs them reads the blob."""
    blob = "\n" + "\n".join("%s: %s" % (n, values.get(n, "")) for n in EVENT_FIELD_NAMES)
    ele_fields = [str(values.get(n, "")) for n in PARAM_FIELDS]   # exactly 6
    return [blob] + ele_fields


# =========================================================================== #
#  2. STATS -- per-directory distribution
# =========================================================================== #
def parent_dir(path):
    """Directory portion of a Windows path (ntpath; works on any OS)."""
    return ntpath.dirname(path)


def compute_stats(dir_counts):
    """Given a {directory: count} mapping, return a dict of distribution stats:
    n_dirs, total, mean, median, stdev, and the mean+1sigma / mean+2sigma cutoffs
    with how many dirs and what % of events each removes. Right-skewed data is
    expected; mean >> median signals it."""
    counts = sorted(dir_counts.values(), reverse=True)
    n = len(counts)
    if n == 0:
        return {"n_dirs": 0, "total": 0}
    total = sum(counts)
    mean = total / n
    s = sorted(counts)
    median = s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2
    stdev = math.sqrt(sum((c - mean) ** 2 for c in counts) / n)

    def above(t):
        sel = [c for c in counts if c > t]
        return len(sel), sum(sel)

    t1, t2 = mean + stdev, mean + 2 * stdev
    n1, e1 = above(t1)
    n2, e2 = above(t2)
    return {
        "n_dirs": n, "total": total, "mean": mean, "median": median,
        "stdev": stdev, "skewed": mean > median * 2,
        "t1": t1, "n1": n1, "e1_pct": 100.0 * e1 / total,
        "t2": t2, "n2": n2, "e2_pct": 100.0 * e2 / total,
    }


def histogram_buckets(dir_counts):
    """Bucket per-directory counts by log10 magnitude -> OrderedDict(label->#dirs).
    Shows the distribution shape without a GUI."""
    buckets = OrderedDict([("1", 0), ("2-9", 0), ("10-99", 0), ("100-999", 0),
                           ("1k-9.9k", 0), ("10k-99k", 0), ("100k+", 0)])

    def b(cv):
        if cv < 2: return "1"
        if cv < 10: return "2-9"
        if cv < 100: return "10-99"
        if cv < 1000: return "100-999"
        if cv < 10000: return "1k-9.9k"
        if cv < 100000: return "10k-99k"
        return "100k+"

    for cv in dir_counts.values():
        buckets[b(cv)] += 1
    return buckets


def render_histogram(buckets, width=40):
    """ASCII bar chart from histogram_buckets()."""
    peak = max(buckets.values()) or 1
    lines = []
    for label, cnt in buckets.items():
        bar = "#" * int(round(width * cnt / peak)) if cnt else ""
        lines.append("  %-9s | %-*s %d" % (label, width, bar, cnt))
    return "\n".join(lines)


def top_directories(dir_counts, threshold):
    """Directories with count strictly above *threshold*, as sorted (count, dir)."""
    return sorted(((cv, d) for d, cv in dir_counts.items() if cv > threshold),
                  reverse=True)


# =========================================================================== #
#  3. ARCHIVE HELPERS -- machine id, EvtxECmd CSV wrapper
# =========================================================================== #
def compute_machine_id(machine_guid, instance_id=None):
    """Collector folder key. Cloud (instance_id present) => 'INSTANCEID-GUID'
    (avoids cloned-image GUID collisions); on-prem => the bare GUID."""
    if instance_id:
        return "%s-%s" % (instance_id, machine_guid)
    return machine_guid or "UNKNOWN"


def convert_evtx_to_csv(evtxecmd_path, evtx_path, out_dir, out_name):
    """Run EvtxECmd to convert an .evtx to CSV. Returns the CSV path or None.
    WINDOWS / EvtxECmd required. Inspection-verified."""
    try:
        os.makedirs(out_dir, exist_ok=True)
        res = subprocess.run(
            [evtxecmd_path, "-f", evtx_path, "--csv", out_dir, "--csvf", out_name],
            capture_output=True, text=True, timeout=600)
        csv_path = os.path.join(out_dir, out_name)
        return csv_path if (res.returncode == 0 and os.path.exists(csv_path)) else None
    except Exception:
        return None
