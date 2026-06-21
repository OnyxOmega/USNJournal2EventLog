# diag_volume.py -- break down the engine records by directory and filename-family
# so we can see which churn classes dominate the volume (and thus the emit-backlog).
# Run in c:\usntest after a run:  python diag_volume.py
import csv, json, re, ntpath
from collections import Counter

CSV = r"c:\usntest\usntest_export.csv"
RE_TGT = re.compile(r"TargetFilename:\s*([^\r\n|,]+)")

def data_of(raw):
    try: return json.loads(raw).get("EventData", {}).get("Data", "")
    except Exception: return raw

# filename-family classifier: collapse the volatile part so families group together
def family(name):
    n = name.lower()
    rules = [
        (r"^msi.*\.tmp$",            "MSI*.tmp"),
        (r"^etilqs_.*",              "etilqs_*"),
        (r".*\.db-wal$",             "*.db-wal"),
        (r".*\.db-shm$",             "*.db-shm"),
        (r".*\.db-journal$",         "*.db-journal"),
        (r"^a[0-9a-f]+\.hdr$",       "a*.HDR"),
        (r"^~.*\.tmp$",              "~*.tmp"),
        (r".*\.tmp$",                "*.tmp (other)"),
        (r".*\.log$",                "*.log"),
        (r"^usntest_.*\.tmp$",       "TEST FILES"),
        (r".*\.etl$",                "*.etl"),
        (r".*\.dat$",                "*.dat"),
    ]
    for pat, label in rules:
        if re.match(pat, n):
            return label
    return "(other)"

with open(CSV, encoding="utf-8", errors="replace", newline="") as f:
    rows = list(csv.DictReader(f))
paycol = next(c for c in rows[0] if c.lstrip("\ufeff").lower() == "payload")
eidcol = next(c for c in rows[0] if c.lstrip("\ufeff").lower() == "eventid")

by_drive = Counter()
by_dir = Counter()
by_family = Counter()
total = 0
unresolved = 0

for r in rows:
    eid = (r.get(eidcol) or "").strip()
    if eid not in ("100","101","102","104"):   # engine file records only
        continue
    d = data_of(r.get(paycol) or "")
    m = RE_TGT.search(d)
    if not m:
        continue
    path = m.group(1).strip()
    total += 1
    drive = path[:2].upper() if len(path) > 1 and path[1] == ":" else "??"
    by_drive[drive] += 1
    if "\\?\\" in path:
        unresolved += 1
    dirpart = ntpath.dirname(path)
    by_dir[dirpart] += 1
    by_family[family(ntpath.basename(path))] += 1

print("TOTAL engine file-records:", total, " unresolved(C:\\?\\):", unresolved)
print("\n=== BY DRIVE ===")
for k, v in by_drive.most_common():
    print("  %-6s %8d  %5.1f%%" % (k, v, 100*v/total))
print("\n=== TOP 20 DIRECTORIES ===")
for k, v in by_dir.most_common(20):
    print("  %8d  %5.1f%%  %s" % (v, 100*v/total, k[:90]))
print("\n=== BY FILENAME FAMILY ===")
for k, v in by_family.most_common():
    print("  %-16s %8d  %5.1f%%" % (k, v, 100*v/total))
