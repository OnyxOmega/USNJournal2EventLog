# diag_drives.py -- show, for EVERY volume on the box, exactly how usnmon's
# enumeration sees it and why it's kept or dropped. No silent skips. Run:
#   python diag_drives.py
import sys
try:
    import win32api, win32file
except Exception as e:
    print("pywin32 missing:", e); sys.exit(1)

DRIVE_TYPE = {0:"UNKNOWN",1:"NO_ROOT",2:"REMOVABLE",3:"FIXED",4:"REMOTE",5:"CDROM",6:"RAMDISK"}
USABLE = (2, 3, 6)

# Every A:..Z: that exists, not just GetLogicalDriveStrings (so we see letters that
# enumeration itself might be missing).
import string
present = []
try:
    mask = win32api.GetLogicalDrives()
    for i, c in enumerate(string.ascii_uppercase):
        if mask & (1 << i):
            present.append(c + ":\\")
except Exception as e:
    print("GetLogicalDrives failed:", e)

gls = []
try:
    gls = [x for x in win32api.GetLogicalDriveStrings().split("\x00") if x]
except Exception as e:
    print("GetLogicalDriveStrings failed:", e)

print("GetLogicalDrives bitmask letters:", [p.rstrip('\\') for p in present])
print("GetLogicalDriveStrings letters  :", [g.rstrip('\\') for g in gls])
print("=" * 72)

for root in present:
    line = "%s  " % root
    try:
        dt = win32file.GetDriveType(root)
        line += "type=%-9s" % DRIVE_TYPE.get(dt, str(dt))
    except Exception as e:
        print(line + "GetDriveType ERROR: %r" % e); continue
    try:
        info = win32api.GetVolumeInformation(root)
        fs = info[4]; label = info[0]
        line += " fs=%-6s label=%-12s" % (fs, (label or "")[:12])
    except Exception as e:
        print(line + " GetVolumeInformation ERROR: %r  <-- DROPPED SILENTLY" % e); continue
    in_gls = root in gls
    usable_type = dt in USABLE
    good_fs = bool(fs) and fs.upper() in ("NTFS", "REFS")
    verdict = "ENUMERATED" if (in_gls and usable_type and good_fs) else "DROPPED"
    why = []
    if not in_gls: why.append("not in GetLogicalDriveStrings")
    if not usable_type: why.append("drivetype not in (REMOVABLE,FIXED,RAMDISK)")
    if not good_fs: why.append("fs not NTFS/ReFS")
    print(line + " -> %s %s" % (verdict, ("(" + "; ".join(why) + ")") if why else ""))
