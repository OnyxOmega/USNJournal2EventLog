# diag_pair.py -- for ONE test file, show its 800 marker Qpc and EVERY engine 100
# that mentions that exact filename, with their Qpc, to see the real pairing.
import csv, json, re
CSV = r"c:\usntest\usntest_export.csv"
RE_TGT = re.compile(r"TargetFilename:\s*([^\r\n|,]+)")
RE_QPC = re.compile(r"Qpc:\s*(\d+)")
RE_TID = re.compile(r"TestId:\s*([0-9a-f]{32})")

TARGET_NAME = "usntest_00_00000.tmp"   # bucket0 iter0; change if you want another

def data_of(raw):
    try: return json.loads(raw).get("EventData",{}).get("Data","")
    except Exception: return raw

with open(CSV, encoding="utf-8", errors="replace", newline="") as f:
    rows = list(csv.DictReader(f))
paycol = next(c for c in rows[0] if c.lstrip("\ufeff").lower()=="payload")
eidcol = next(c for c in rows[0] if c.lstrip("\ufeff").lower()=="eventid")

marker_qpc = None
engine_hits = []
for r in rows:
    eid = (r.get(eidcol) or "").strip()
    d = data_of(r.get(paycol) or "")
    if TARGET_NAME not in d:
        continue
    q = RE_QPC.search(d); q = int(q.group(1)) if q else None
    t = RE_TGT.search(d); t = t.group(1).strip() if t else ""
    if eid == "800":
        marker_qpc = q
        print("800 MARKER  qpc=%s  target=%s" % (q, t))
    elif eid in ("100","101","102","104"):
        engine_hits.append((eid, q, t))

print("\nENGINE records mentioning %s: %d" % (TARGET_NAME, len(engine_hits)))
for eid, q, t in engine_hits:
    delta = (q - marker_qpc) if (q and marker_qpc) else None
    dms = (delta/10_000_000*1000) if delta is not None else None
    print("  eid=%s qpc=%s  delta_from_marker=%s ticks (%s ms)  tgt=%s"
          % (eid, q, delta, ("%.1f"%dms) if dms is not None else "?", t))
