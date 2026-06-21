# Diagnostic: run on the SIFT box. Reads a small batch of USN records on C:
# and reports, for each, whether OpenFileById succeeds, fails with 87, and what
# the reason flags are -- so we can see if failures correlate with delete/rename
# (legit transient) vs. all reason types (systematic bug).
import struct, win32file
FSCTL_QUERY = 0x000900f4
FSCTL_READ = 0x000900bb
SHARE = 0x01|0x02|0x04
h = win32file.CreateFile(r"\\.\C:", win32file.GENERIC_READ, SHARE, None,
                         win32file.OPEN_EXISTING, 0, None)
out = win32file.DeviceIoControl(h, FSCTL_QUERY, None, 80)
jid, first, nxt = struct.unpack_from("=Qqq", out, 0)
rd = struct.pack("=qLLQQQ", nxt-5000 if nxt>5000 else 0, 0xFFFFFFFF, 0, 0, 0, jid)
buf = win32file.DeviceIoControl(h, FSCTL_READ, rd, 65536)
off = 8
ok = fail87 = failother = 0
fail_reasons = {}
share = win32file.FILE_SHARE_READ|win32file.FILE_SHARE_WRITE|win32file.FILE_SHARE_DELETE
n = 0
while off < len(buf) and n < 400:
    rl, maj, mnr = struct.unpack_from("=LHH", buf, off)
    if rl == 0: break
    if maj == 2:
        fref, pref, usn, ts, reason = struct.unpack_from("=QQqqL", buf, off+8)
        try:
            fh = win32file.OpenFileById(h, fref, 0, share, 0, None)
            win32file.CloseHandle(fh); ok += 1
        except Exception as e:
            code = getattr(e, 'winerror', None) or (e.args[0] if e.args else 0)
            if code == 87: fail87 += 1
            else: failother += 1
            fail_reasons[reason] = fail_reasons.get(reason,0)+1
        n += 1
    off += rl
win32file.CloseHandle(h)
print(f"sampled={n}  ok={ok}  fail87={fail87}  failother={failother}")
print(f"resolve-fail rate: {100*(fail87+failother)/max(n,1):.0f}%")
print("reason flags among FAILURES (hex):")
for r,c in sorted(fail_reasons.items(), key=lambda x:-x[1])[:8]:
    tags=[]
    if r&0x200: tags.append("DELETE")
    if r&0x1000 or r&0x2000: tags.append("RENAME")
    if r&0x100: tags.append("CREATE")
    if r&0x1|r&0x2: tags.append("DATA")
    print(f"  0x{r:X} count={c} {'+'.join(tags) or 'other'}")
