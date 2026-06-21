# check_version.py -- confirm the analyzer file is the NEW one
import os
f = r"c:\usntest\usntest_analyze.py"
src = open(f, encoding="utf-8").read()
print("file:", f)
print("size:", os.path.getsize(f), "bytes")
print("has nearest-Qpc fix:", "smallest value >= the marker" in src or "after = [c for c in cands" in src)
print("has JSON decode fix:", 'obj.get("EventData"' in src)
