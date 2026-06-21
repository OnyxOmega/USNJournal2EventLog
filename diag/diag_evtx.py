# diag_evtx.py -- dump exactly what python-evtx produces for one engine 100 and one
# 800 marker, so we can see why the analyzer's evtx reader pairs markers but not
# engine records. No Zimmerman tools needed. Run:  python diag_evtx.py D:\usntest\FileSystem.evtx
import sys, re

try:
    from Evtx.Evtx import Evtx
except Exception:
    print("python-evtx not importable. pip install python-evtx")
    sys.exit(1)

PATH = sys.argv[1] if len(sys.argv) > 1 else r"D:\usntest\FileSystem.evtx"

RE_EID    = re.compile(r"<EventID[^>]*>(\d+)</EventID>")
RE_DATA   = re.compile(r"<Data[^>]*>(.*?)</Data>", re.S)
RE_TARGET = re.compile(r"TargetFilename:\s*([^\r\n|]+)")
RE_QPC    = re.compile(r"Qpc:\s*(\d+)")
RE_HIRES  = re.compile(r"HiResUtc:\s*(\d+)")

want = {"100": None, "800": None}

with Evtx(PATH) as log:
    for rec in log.records():
        try:
            xml = rec.xml()
        except Exception as e:
            continue
        m = RE_EID.search(xml)
        if not m:
            continue
        eid = m.group(1)
        if eid in want and want[eid] is None:
            want[eid] = xml
        if all(v is not None for v in want.values()):
            break

for eid in ("100", "800"):
    xml = want[eid]
    print("=" * 70)
    print("EventID %s  -- found: %s" % (eid, xml is not None))
    if xml is None:
        continue
    print("--- RAW XML (first 2000 chars) ---")
    print(xml[:2000])
    datas = RE_DATA.findall(xml)
    joined = " ".join(datas)
    print("--- #Data blocks: %d ---" % len(datas))
    for i, d in enumerate(datas[:3]):
        print("  Data[%d] (first 160): %r" % (i, d[:160]))
    print("--- regex hits on joined payload ---")
    t = RE_TARGET.search(joined); q = RE_QPC.search(joined); h = RE_HIRES.search(joined)
    print("  TargetFilename:", t.group(1) if t else None)
    print("  Qpc          :", q.group(1) if q else None)
    print("  HiResUtc     :", h.group(1) if h else None)
    print()
