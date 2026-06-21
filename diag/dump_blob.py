"""dump_blob.py -- print the raw EventData blob from the first N Event-100 records
in a usnmon evtx, so we can see the EXACT TargetFilename string the resolver produced
(to debug self-write suppression). Reads the evtx directly via EvtxECmd's underlying
parser is overkill -- instead just parse the XML the simple way with python-evtx if
present, else fall back to reading a CSV column.

Usage:
  python dump_blob.py <file.evtx | file.csv> [count]
"""
import sys, os

def from_csv(path, n):
    import csv
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        r = csv.DictReader(f)
        # the blob is in the Payload column; PayloadData1 has just TargetFilename
        shown = 0
        for row in r:
            eid = (row.get("EventId") or row.get("EventID") or "").strip()
            if eid and eid != "100":
                continue
            pd1 = (row.get("PayloadData1") or "").strip()
            payload = (row.get("Payload") or "")
            # extract TargetFilename: line from blob
            tf = ""
            i = payload.find("TargetFilename:")
            if i >= 0:
                tf = payload[i:payload.find("\\n", i) if "\\n" in payload[i:] else i+200]
            print("--- record %d ---" % (shown+1))
            print("  PayloadData1 :", repr(pd1))
            print("  blob TF line :", repr(tf[:200]))
            shown += 1
            if shown >= n:
                break
        if shown == 0:
            print("No Event 100 rows found. CSV columns:", r.fieldnames)

def from_evtx(path, n):
    try:
        from Evtx.Evtx import Evtx
    except Exception:
        print("python-evtx not installed; run with the CSV instead, OR:")
        print("  pip install python-evtx --break-system-packages")
        print("Then: python dump_blob.py <file.evtx>")
        return
    import re
    shown = 0
    with Evtx(path) as log:
        for rec in log.records():
            xml = rec.xml()
            if "<EventID>100</EventID>" not in xml and 'EventID Qualifiers' not in xml:
                # crude EventID check
                m = re.search(r"<EventID[^>]*>(\d+)</EventID>", xml)
                if not m or m.group(1) != "100":
                    continue
            # pull the Data element(s)
            datas = re.findall(r"<Data[^>]*>(.*?)</Data>", xml, re.S)
            print("--- record %d (%d Data nodes) ---" % (shown+1, len(datas)))
            for j, d in enumerate(datas):
                print("  Data[%d]: %r" % (j+1, d[:300]))
            shown += 1
            if shown >= n:
                break
    if shown == 0:
        print("No Event 100 records found.")

def main():
    if len(sys.argv) < 2:
        print(__doc__); return
    path = sys.argv[1]
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 5
    if path.lower().endswith(".csv"):
        from_csv(path, n)
    else:
        from_evtx(path, n)

if __name__ == "__main__":
    main()
