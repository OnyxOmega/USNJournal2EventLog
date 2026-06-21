# diag_payload.py -- show the FULL raw Payload cell for one 800 and one 100,
# and whether Qpc/HiResUtc survive + parse.
import csv, json, re
CSV = r"c:\usntest\usntest_export.csv"
RE_QPC = re.compile(r"Qpc:\s*(\d+)")
RE_HIRES = re.compile(r"HiResUtc:\s*(\d+)")

def first(rows, eid):
    for x in rows:
        v = (x.get("EventId") or x.get("\ufeffEventId") or "")
        if str(v).strip() == eid: return x
    return None

with open(CSV, encoding="utf-8", errors="replace", newline="") as f:
    rows = list(csv.DictReader(f))

# find the payload column (BOM-safe)
paycol = next((c for c in rows[0].keys() if c.lstrip("\ufeff").lower()=="payload"), None)
print("payload column:", repr(paycol))

for eid in ("800","100"):
    rec = first(rows, eid)
    if not rec:
        print(eid, "none"); continue
    raw = rec.get(paycol) or ""
    print("\n=== EventId", eid, "=== raw len:", len(raw))
    print("RAW TAIL (last 220 chars):", repr(raw[-220:]))
    # try JSON
    data = None
    try:
        data = json.loads(raw).get("EventData",{}).get("Data","")
        print("JSON OK, data len:", len(data))
    except Exception as e:
        print("JSON FAIL:", e)
        data = raw
    q = RE_QPC.search(data or ""); h = RE_HIRES.search(data or "")
    print("Qpc found:", q.group(1) if q else None)
    print("HiResUtc found:", h.group(1) if h else None)
