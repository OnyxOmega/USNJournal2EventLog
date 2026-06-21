# diag_columns.py -- show how EvtxECmd columnized one engine 100 vs one harness 800.
# Run in IDLE (F5) or: python diag_columns.py
import csv

CSV = r"c:\usntest\usntest_export.csv"

def first(rows, eid):
    for x in rows:
        v = x.get("EventId") or x.get("Id") or x.get("EventID") or ""
        if str(v).strip() == eid:
            return x
    return None

with open(CSV, encoding="utf-8", errors="replace", newline="") as f:
    rows = list(csv.DictReader(f))

print("TOTAL ROWS:", len(rows))
print("COLUMNS:", list(rows[0].keys()) if rows else "none")
print()

for eid, label in (("100", "ENGINE 100"), ("800", "HARNESS 800")):
    rec = first(rows, eid)
    print("=== %s ===" % label)
    if not rec:
        print("  (none found)")
    else:
        for k, v in rec.items():
            if v and str(v).strip():
                print("  %-16s = %r" % (k, str(v)[:200]))
    print()
