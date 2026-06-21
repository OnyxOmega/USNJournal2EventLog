#!/usr/bin/env python3
"""Rebuild the USN profile report from an EvtxECmd CSV export.

Use this to recover the per-directory distribution analysis when the live
profiler did not write its summary (or to re-analyze any captured run). It reads
the CSV EvtxECmd produces from the FileSystem log, tallies events per directory
(using the TargetFilename in PayloadData1), and prints the same histogram /
mean+1sigma report the live profiler does -- plus writes a per-directory CSV.

Workflow:
    1. Export the FileSystem log to CSV with EvtxECmd and the project maps:
         EvtxECmd.exe -f FileSystem.evtx --csv C:\\out --csvf usn.csv
    2. Run this:
         python usn_profile_from_csv.py C:\\out\\usn.csv

The TargetFilename column is read from 'PayloadData1' (where the maps place it).
If your CSV uses a different column, pass it:  --column PayloadData1
"""
import argparse
import csv
import math
import ntpath
import os
import sys
from collections import Counter, OrderedDict


def parent_dir(path):
    """Directory portion of a Windows path (handles backslashes on any OS)."""
    return ntpath.dirname(path)


def tally(csv_path, column):
    dirs = Counter()
    total_rows = 0
    used = 0
    with open(csv_path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if column not in (reader.fieldnames or []):
            sys.exit("Column %r not found. Available: %s"
                     % (column, ", ".join(reader.fieldnames or [])))
        for row in reader:
            total_rows += 1
            target = (row.get(column) or "").strip()
            if not target:
                continue
            d = parent_dir(target)
            if d:
                dirs[d] += 1
                used += 1
    return dirs, total_rows, used


def report(dirs, total_rows, used, top_named, out_csv):
    if not dirs:
        sys.exit("No usable TargetFilename values found; nothing to report.")
    counts = sorted(dirs.values(), reverse=True)
    n_dirs = len(counts)
    total = sum(counts)
    mean = total / n_dirs
    s = sorted(counts)
    median = s[n_dirs // 2] if n_dirs % 2 else (s[n_dirs // 2 - 1] + s[n_dirs // 2]) / 2
    stdev = math.sqrt(sum((c - mean) ** 2 for c in counts) / n_dirs)
    t1, t2 = mean + stdev, mean + 2 * stdev

    def above(t):
        sel = [c for c in counts if c > t]
        return len(sel), sum(sel)

    n1, e1 = above(t1)
    n2, e2 = above(t2)

    print("=" * 64)
    print("USN PROFILE (from CSV)")
    print("CSV rows: %d   Events tallied: %d   Directories: %d"
          % (total_rows, total, n_dirs))
    print("Per-directory counts: mean=%.1f  median=%.1f  stdev=%.1f"
          % (mean, median, stdev))
    if mean > median * 2:
        print("  (distribution is right-skewed -- a few directories dominate)")

    buckets = OrderedDict([("1", 0), ("2-9", 0), ("10-99", 0), ("100-999", 0),
                           ("1k-9.9k", 0), ("10k-99k", 0), ("100k+", 0)])

    def b(c):
        if c < 2: return "1"
        if c < 10: return "2-9"
        if c < 100: return "10-99"
        if c < 1000: return "100-999"
        if c < 10000: return "1k-9.9k"
        if c < 100000: return "10k-99k"
        return "100k+"

    for c in counts:
        buckets[b(c)] += 1
    peak = max(buckets.values()) or 1
    print("\nDistribution (events/dir -> # of dirs):")
    for label, cnt in buckets.items():
        bar = "#" * int(round(40 * cnt / peak)) if cnt else ""
        print("  %-9s | %-40s %d" % (label, bar, cnt))

    print("\nNoise cutoffs (directories ABOVE the line = exclude candidates):")
    print("  mean+1sigma (>%.0f): %d dirs remove %.1f%% of events"
          % (t1, n1, 100.0 * e1 / total))
    print("  mean+2sigma (>%.0f): %d dirs remove %.1f%% of events"
          % (t2, n2, 100.0 * e2 / total))

    noisy = sorted(((c, d) for d, c in dirs.items() if c > t1), reverse=True)
    print("\nTop directories above mean+1sigma (count : path)  [showing %d]:"
          % min(top_named, len(noisy)))
    for c, d in noisy[:top_named]:
        print("  %8d : %s" % (c, d))
    print("=" * 64)

    with open(out_csv, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["count", "directory"])
        for d, c in sorted(dirs.items(), key=lambda kv: kv[1], reverse=True):
            w.writerow([c, d])
    print("Per-directory counts written to: %s" % out_csv)


def main():
    ap = argparse.ArgumentParser(description="Rebuild the USN profile report from an EvtxECmd CSV.")
    ap.add_argument("csv_path", help="Path to the EvtxECmd CSV export")
    ap.add_argument("--column", default="PayloadData1",
                    help="CSV column holding TargetFilename (default: PayloadData1)")
    ap.add_argument("--top", type=int, default=40, help="How many top directories to name")
    ap.add_argument("--out", default=None, help="Output per-directory CSV path")
    args = ap.parse_args()

    out_csv = args.out or os.path.join(
        os.path.dirname(os.path.abspath(args.csv_path)), "usn_profile_recovered.csv")
    dirs, total_rows, used = tally(args.csv_path, args.column)
    report(dirs, total_rows, used, args.top, out_csv)


if __name__ == "__main__":
    main()
