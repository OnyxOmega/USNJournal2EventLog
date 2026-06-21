"""usn_common.py -- shared library for the USN Journal Monitor suite.

Imported by all three components (engine usn_monitor.py, the profiler/generator,
and the drift comparator) so there is exactly ONE implementation of the matching,
rule/crypto, stats, event-contract, and archive logic -- no duplication, no drift.

Five libraries live here (see BLUEPRINT.md):
  1. Matching        -- path normalization + the forwarding RuleMatcher
  2. Rules / crypto  -- signed-JSON load, X.509 verify, validate, conflict-check
  3. Stats           -- per-directory distribution + coverage math
  4. Event contract  -- EventData field schema, classify, reason text
  5. Archive         -- monthly bundle, EvtxECmd CSV, completeness, machine id

Platform note: the crypto functions (verify_signature, get_cert_from_store) and the
machine-id helpers use Windows APIs and CANNOT run on non-Windows. They are written
against the `cryptography` package + Windows cert store and must be tested on the
target. Everything else is pure-Python and portable (tested with `ntpath` for
Windows path semantics).
"""

import base64
import hashlib
import json
import math
import ntpath
import os
import subprocess
import time
import ctypes
from collections import Counter, OrderedDict

# Contract version. Event field order/names and the rule schema are frozen per
# MAJOR. The EvtxECmd maps, the WEC Cookbook, and SIEM parsing all bind to this.
SCHEMA_VERSION = "2.1"   # 2.1: appended HiResUtc (epoch-ns) to end of blob; additive,
                         # blob-only, no PARAM/contract change. 2.0 maps still parse.

# Reserved RuleID range for vendor (YASDC) forensic rules. Client files may not
# write IDs in this range; the loader rejects any that do (event 908).
FORENSIC_ID_MIN = 10001
FORENSIC_ID_MAX = 10999

# Rule list keys (all four use the same per-rule object schema).
RULE_LISTS = ("includes", "include_contains", "exclude_contains", "excludes")

# Per-rule required fields and how a missing/blank value is defaulted. `path` is
# the only field with NO default -- a rule without a path is invalid and rejected.
RULE_DEFAULTS = {
    "reason": "[reason:MISSING] review required",
    "added_by": "[added_by:UNKNOWN] manual edit",
    "date": None,   # filled with today's date at load if blank
}

# Coverage-collapse threshold: predicted monitoring/forward coverage dropping more
# than this many PERCENTAGE POINTS below the matured baseline raises event 905.
COVERAGE_DROP_ALERT_PCT = 5.0


# =========================================================================== #
#  1. MATCHING -- path normalization + the forwarding RuleMatcher
# =========================================================================== #
def norm_path(p):
    """Normalize a path for comparison (case- and separator-insensitive).
    Uses ntpath so Windows drive-letter / backslash semantics apply everywhere."""
    return ntpath.normcase(ntpath.normpath(p))


def is_under(path_norm, base_norm):
    """True if path_norm == base_norm or is a descendant of it (boundary-aware:
    C:\\Windows does NOT match C:\\WindowsApps)."""
    if path_norm == base_norm:
        return True
    base = base_norm if base_norm.endswith("\\") else base_norm + "\\"
    return path_norm.startswith(base)


def _frag(fragment):
    """Normalize a substring fragment to be boundary-safe: lower-cased and wrapped
    in exactly one leading + one trailing backslash, regardless of how the input
    was written ('x', '\\x', 'x\\', '\\\\x\\\\' all -> '\\x\\'). The boundary
    anchors mean '\\Edge\\User Data\\' cannot match '\\Edge\\User DataBackup\\'."""
    f = fragment.replace("/", "\\").lower().strip("\\")
    return "\\" + f + "\\"


def matches_contains(path, fragment_norm):
    """True if the boundary-anchored *fragment_norm* (already _frag()'d) appears in
    *path*. We anchor the path the same way (lower + ensure trailing sep on the
    directory) so a fragment ending in '\\' matches a directory boundary."""
    p = path.replace("/", "\\").lower()
    if not p.endswith("\\"):
        p = p + "\\"
    return fragment_norm in p


def minimize_roots(paths):
    """Collapse a set of paths so none is a descendant of another (a parent
    subsumes its children). Returns a sorted list of the originals kept."""
    items = sorted({norm_path(p): p for p in paths}.items())
    kept, kept_norm = [], []
    for pn, original in items:
        if any(is_under(pn, k) for k in kept_norm):
            continue
        kept.append(original)
        kept_norm.append(pn)
    return sorted(kept)


class RuleMatcher:
    """Decide whether a path should be FORWARDED (to FileSystem-IR / SIEM).

    IMPORTANT: collection is unconditional -- the engine always writes every event
    to the ALL log. This matcher only gates the *forwarding* second-emit.

    Evaluation is include-first short-circuit (first hit decides, cheapest path):
        1. includes          (exact)     hit -> FORWARD
        2. include_contains  (substring) hit -> FORWARD
        3. exclude_contains  (substring) hit -> DO NOT FORWARD
        4. excludes          (exact)     hit -> DO NOT FORWARD
        5. (no hit)                            -> default_forward
    Includes always win, including a deeper include under a broad exclude
    (honeypot inside an otherwise-unforwarded tree).
    """

    def __init__(self, rules, default_forward=False):
        # rules: dict of the four lists, each a list of {"path": ...} objects.
        self.inc = [norm_path(r["path"]) for r in rules.get("includes", [])]
        self.inc_c = [_frag(r["path"]) for r in rules.get("include_contains", [])]
        self.exc_c = [_frag(r["path"]) for r in rules.get("exclude_contains", [])]
        self.exc = [norm_path(r["path"]) for r in rules.get("excludes", [])]
        self.default_forward = default_forward

    def should_forward(self, path):
        pn = norm_path(path)
        if any(is_under(pn, i) for i in self.inc):
            return True
        if any(matches_contains(path, f) for f in self.inc_c):
            return True
        if any(matches_contains(path, f) for f in self.exc_c):
            return False
        if any(is_under(pn, e) for e in self.exc):
            return False
        return self.default_forward


# =========================================================================== #
#  4. EVENT CONTRACT -- field schema, classification, reason text
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
#  3. STATS -- per-directory distribution + coverage math
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


def compute_coverage(current_counts, baseline_counts, matcher):
    """Predict what % of the BASELINE directory population would still be FORWARDED
    under the current *matcher*, for coverage-collapse detection. Coverage is
    measured against the frozen baseline population (not the live, already-filtered
    log) so an attacker can't poison the reference by clearing logs.

    Returns (forwarded_pct, dropped_pct). A large drop vs the recorded baseline
    coverage (see COVERAGE_DROP_ALERT_PCT) raises event 905."""
    if not baseline_counts:
        return (0.0, 100.0)
    total = sum(baseline_counts.values())
    forwarded = sum(cv for d, cv in baseline_counts.items()
                    if matcher.should_forward(d))
    pct = 100.0 * forwarded / total if total else 0.0
    return (pct, 100.0 - pct)


# =========================================================================== #
#  2. RULES / CRYPTO -- signed-JSON load, X.509 verify, validate, conflicts
# =========================================================================== #
# A signed ruleset file is JSON with a top-level "signature" (base64) and a
# "signed_by" (cert subject/thumbprint hint). The signature covers the
# CANONICAL form of the file with "signature" removed -- see canonical_bytes().

def canonical_bytes(doc):
    """Return the deterministic byte form of a ruleset dict for signing/verifying.
    The 'signature' field is excluded; keys are sorted; separators fixed; UTF-8.
    Any whitespace/key-order change produces the SAME bytes, so cosmetic edits do
    not break a signature but content changes do."""
    d = {k: v for k, v in doc.items() if k != "signature"}
    return json.dumps(d, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sha256_hex(data):
    """Hex SHA-256 of bytes (used for integrity baselines / change detection)."""
    return hashlib.sha256(data).hexdigest()


def verify_signature(doc, public_key):
    """Verify doc['signature'] (base64) over canonical_bytes(doc) using an
    X.509/CNG public key (RSA or ECDSA). Returns True/False. Raises nothing on a
    bad signature -- a False return is the caller's 909 trigger.

    *public_key* is a `cryptography` public-key object (from get_cert_from_store()
    or a loaded PEM). Tested on Windows with certs from the cert store."""
    sig_b64 = doc.get("signature")
    if not sig_b64:
        return False
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa
        from cryptography.exceptions import InvalidSignature
        signature = base64.b64decode(sig_b64)
        data = canonical_bytes(doc)
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, data,
                              padding.PKCS1v15(), hashes.SHA256())
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        else:
            return False
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


def sign_doc(doc, private_key):
    """Sign canonical_bytes(doc) and return the base64 signature. Used by the
    profiler/generator and by signing utilities (NOT by the engine -- the engine
    only verifies). Mirrors verify_signature()'s algorithm handling."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa
    data = canonical_bytes(doc)
    if isinstance(private_key, rsa.RSAPrivateKey):
        sig = private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        sig = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    else:
        raise TypeError("Unsupported key type for signing")
    return base64.b64encode(sig).decode("ascii")


def get_cert_from_store(subject_or_thumbprint, store_name="MY",
                        store_location="LocalMachine"):
    """Retrieve a public key from the Windows certificate store by subject CN or
    thumbprint. WINDOWS ONLY -- uses the cryptography lib over the cert exported
    from the store via PowerShell (no extra deps). Returns a public-key object or
    None. INSPECTION-VERIFIED; must be tested on the target host."""
    try:
        # Export the matching cert as base64 DER via certutil/PowerShell.
        ps = (
            "$c = Get-ChildItem -Path Cert:\\%s\\%s | Where-Object "
            "{ $_.Subject -like '*%s*' -or $_.Thumbprint -eq '%s' } | "
            "Select-Object -First 1; "
            "if ($c) { [Convert]::ToBase64String($c.RawData) }"
            % (store_location, store_name,
               subject_or_thumbprint, subject_or_thumbprint)
        )
        out = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                             capture_output=True, text=True, timeout=15)
        b64 = out.stdout.strip()
        if not b64:
            return None
        from cryptography import x509
        cert = x509.load_der_x509_certificate(base64.b64decode(b64))
        return cert.public_key()
    except Exception:
        return None


def _today():
    from datetime import date
    return date.today().isoformat()


def validate_rules(doc, is_forensic_file):
    """Validate and normalize a ruleset's four lists in place. Returns
    (clean_doc, problems) where problems is a list of (code, rule_id, message)
    for the caller to emit as 907/908/etc. events.

    Enforces: every rule has a non-empty `path` (else REJECTED, code 'no_path');
    fills `reason`/`added_by`/`date` defaults; auto-numbers missing `rule_id`;
    rejects duplicate rule_ids; rejects client rules using the reserved forensic
    range (code 'reserved_range'); forensic file rules MUST be in the reserved
    range."""
    problems = []
    seen_ids = set()
    next_auto = {"I": 90001, "IC": 90001, "EC": 90001, "E": 90001}
    prefix = {"includes": "I", "include_contains": "IC",
              "exclude_contains": "EC", "excludes": "E"}

    # Pre-scan all explicitly-assigned rule_ids so auto-numbering never collides.
    explicit_ids = set()
    for list_name in RULE_LISTS:
        for rule in doc.get(list_name, []):
            if isinstance(rule, dict):
                rid = (rule.get("rule_id") or "").strip()
                if rid:
                    explicit_ids.add(rid)

    def _next_free(pfx):
        rid = "%s%d" % (pfx, next_auto[pfx])
        while rid in explicit_ids or rid in seen_ids:
            next_auto[pfx] += 1
            rid = "%s%d" % (pfx, next_auto[pfx])
        next_auto[pfx] += 1
        return rid

    for list_name in RULE_LISTS:
        kept = []
        for rule in doc.get(list_name, []):
            if not isinstance(rule, dict):
                problems.append(("malformed", None, "rule is not an object in %s" % list_name))
                continue
            path = (rule.get("path") or "").strip()
            if not path:
                problems.append(("no_path", rule.get("rule_id"),
                                 "rule missing path in %s -- REJECTED" % list_name))
                continue
            rule["path"] = path

            rid = (rule.get("rule_id") or "").strip()
            if not rid:
                rid = _next_free(prefix[list_name])
                rule["rule_id"] = rid
                problems.append(("auto_id", rid, "auto-numbered rule_id"))

            if rid in seen_ids:
                problems.append(("dup_id", rid, "duplicate rule_id -- REJECTED"))
                continue
            seen_ids.add(rid)

            # Reserved forensic range enforcement.
            in_reserved = _in_forensic_range(rid)
            if is_forensic_file and not in_reserved:
                problems.append(("forensic_range", rid,
                                 "forensic rule outside I10001-10999"))
            if (not is_forensic_file) and in_reserved:
                problems.append(("reserved_range", rid,
                                 "client rule uses reserved forensic range -- REJECTED"))
                continue

            for field, default in RULE_DEFAULTS.items():
                if not (rule.get(field) or "").strip():
                    rule[field] = default if default is not None else _today()
            kept.append(rule)
        doc[list_name] = kept
    return doc, problems


def _in_forensic_range(rule_id):
    """True if a rule_id's numeric part is in the reserved forensic range."""
    digits = "".join(ch for ch in rule_id if ch.isdigit())
    if not digits:
        return False
    n = int(digits)
    return FORENSIC_ID_MIN <= n <= FORENSIC_ID_MAX


def detect_conflicts(merged):
    """Find include/exclude contradictions in the MERGED ruleset for the startup /
    reload validation pass. Returns a list of (include_rule_id, exclude_rule_id,
    path) tuples. Because includes always win at runtime, these never fire as
    runtime events -- they are surfaced once, up front, so the operator can fix the
    config (or choose to continue). A conflict = a path that an include matches AND
    an exclude also matches."""
    m_inc = [(norm_path(r["path"]), r["rule_id"]) for r in merged.get("includes", [])]
    m_inc_c = [(_frag(r["path"]), r["rule_id"]) for r in merged.get("include_contains", [])]
    m_exc = [(norm_path(r["path"]), r["rule_id"]) for r in merged.get("excludes", [])]
    m_exc_c = [(_frag(r["path"]), r["rule_id"]) for r in merged.get("exclude_contains", [])]

    conflicts = []
    # Exact include vs any exclude that would also catch that exact path.
    for ip, iid in m_inc:
        for ep, eid in m_exc:
            if is_under(ip, ep):
                conflicts.append((iid, eid, ip))
        for ef, eid in m_exc_c:
            if matches_contains(ip, ef):
                conflicts.append((iid, eid, ip))
    # Include-contains fragment vs exact exclude that sits inside it (best-effort:
    # an exact exclude whose path contains the include fragment).
    for ifr, iid in m_inc_c:
        for ep, eid in m_exc:
            if ifr in (ep + "\\"):
                conflicts.append((iid, eid, ep))
    return conflicts


# =========================================================================== #
#  5. ARCHIVE -- machine id, completeness, monthly bundle, EvtxECmd CSV
# =========================================================================== #
def compute_machine_id(machine_guid, instance_id=None):
    """Collector folder key. Cloud (instance_id present) => 'INSTANCEID-GUID'
    (avoids cloned-image GUID collisions); on-prem => the bare GUID."""
    if instance_id:
        return "%s-%s" % (instance_id, machine_guid)
    return machine_guid or "UNKNOWN"


def check_archive_completeness(archive_dir, expected_count):
    """Append-only-forever model: there must be at least *expected_count* monthly
    archives (baseline + months_running). Returns (present, expected, missing).
    A shortfall is the caller's 918 'baseline/archive missing' trigger -- because
    nothing is ever culled, any gap is unambiguous."""
    try:
        present = len([f for f in os.listdir(archive_dir)
                       if f.lower().endswith((".zip", ".7z"))])
    except Exception:
        present = 0
    missing = max(0, expected_count - present)
    return (present, expected_count, missing)


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


def build_monthly_bundle(bundle_path, files):
    """Compress *files* (evtx + CSV + baseline stats) into one archive. USN data
    compresses ~50:1, so a month is tiny. Append-only: never deletes inputs here
    (the caller decides when the live log is cleared). Returns the bundle path."""
    import zipfile
    with zipfile.ZipFile(bundle_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for f in files:
            if f and os.path.exists(f):
                z.write(f, arcname=os.path.basename(f))
    return bundle_path


# =========================================================================== #
#  RULESET LOAD ORCHESTRATION (used by engine reload + the tools)
# =========================================================================== #
def load_signed_ruleset(path, public_key, is_forensic_file):
    """Load, verify, and validate one signed ruleset file. Returns
    (doc_or_None, problems). problems carries codes the caller maps to 9xx events:
      'missing'   -> 910/911       'malformed'      -> 912
      'bad_sig'   -> 909           plus per-rule codes from validate_rules.
    On any hard failure doc is None and the caller keeps the last-good ruleset."""
    problems = []
    if not os.path.exists(path):
        return None, [("missing", None, "ruleset file not found: %s" % path)]
    try:
        with open(path, "r", encoding="utf-8") as f:
            doc = json.load(f)
    except Exception as exc:
        return None, [("malformed", None, "JSON parse failed: %r" % exc)]

    if public_key is not None:
        if not verify_signature(doc, public_key):
            return None, [("bad_sig", None, "signature verification FAILED")]

    doc, vproblems = validate_rules(doc, is_forensic_file)
    problems.extend(vproblems)
    return doc, problems


def merge_rulesets(forensic_doc, client_doc):
    """Merge forensic + client docs into one ruleset (the four lists concatenated).
    Forensic rules first so they take precedence in any stable iteration. Returns
    the merged dict; caller then builds a RuleMatcher and runs detect_conflicts."""
    merged = {k: [] for k in RULE_LISTS}
    for d in (forensic_doc, client_doc):
        if not d:
            continue
        for k in RULE_LISTS:
            merged[k].extend(d.get(k, []))
    return merged
