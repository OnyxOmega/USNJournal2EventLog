# Forensic NTFS USN Journal Monitor

A Windows-native background service that monitors the **NTFS USN Change Journal**
in real time, filters filesystem activity against a user-defined whitelist, and
records forensic metadata to a dedicated Windows Event Log (`FileSystem`). It is
designed for endpoint auditing, change tracking, and lightweight host forensics.

The service is headless, survives reboots, runs under `LocalSystem`, and
self-manages its own rolling log archives so it can run unattended for long
periods without filling the disk.

---

## How it works

```
USN Journal  ->  read record  ->  resolve parent directory by file-reference
             ->  O(1) whitelist match  ->  classify by reason  ->  Windows Event
```

1. Opens the volume and queries (or creates) the USN journal.
2. Negotiates the richest read format the volume supports (V2 on NTFS, V3 on ReFS).
3. For each change, resolves the containing directory's path (cached) and checks
   it against the whitelist in constant time.
4. Classifies the change by its USN reason flags and writes a structured event
   with a category-specific Event ID.

---

## Requirements

- Windows (NTFS volume; ReFS supported via V3 records)
- Python 3.12+ (64-bit)
- [`pywin32`](https://pypi.org/project/pywin32/): `pip install pywin32`
- Administrator / `LocalSystem` privileges (USN reads and `Clear-EventLog`
  require elevation)
- .NET Framework 4.x present (its `EventLogMessages.dll` is used so events render
  a readable description; this ships with virtually all modern Windows installs)

---

## Quick start

```bat
:: 1. Install dependencies
pip install pywin32

:: 2. Configure which directories to monitor (launches the GUI)
python usn_monitor.py

:: 3. Test in the foreground (Ctrl+C to stop)
python usn_monitor.py debug

:: 4. Install and start as a Windows service
python usn_monitor.py --startup delayed install
python usn_monitor.py start
```

---

## Event ID reference

Each change is classified by its **dominant** USN reason flag (reasons accumulate
into a single close-record, so the most significant one wins). The full reason
string is always preserved in the event body.

| Event ID | Category       | Triggered by                                                        |
|:--------:|----------------|---------------------------------------------------------------------|
| **100**  | Create         | `FileCreate`                                                        |
| **101**  | Modify         | `DataOverwrite`, `DataExtend`, `DataTruncation`, `NamedDataOverwrite`, `StreamChange` |
| **102**  | Delete         | `FileDelete`                                                        |
| **103**  | Rename         | `RenameOld`, `RenameNew`                                            |
| **104**  | SecurityChange | ACL / ownership change (`SecurityChange`)                          |
| **105**  | Other          | `IndexableChange`, `BasicInfoChange`, `HardLinkChange`            |
| **106**  | RangeChange    | `USN_RECORD_V4` range-tracking (ReFS only)                         |

**Classification priority:** `Delete > Create > Rename > Security > Modify > Other`.
A file created and deleted before its close-record is reported as **Delete** (the
net on-disk effect).

### Querying events

Events are written to the **`FileSystem`** custom log, found in Event Viewer under
**Applications and Services Logs → FileSystem**.

```powershell
# All deletions
Get-WinEvent -FilterHashtable @{LogName='FileSystem'; Id=102}

# Creates and deletes together
Get-WinEvent -FilterHashtable @{LogName='FileSystem'; Id=100,102}

# Everything in the last hour, newest first
Get-WinEvent -FilterHashtable @{LogName='FileSystem'; StartTime=(Get-Date).AddHours(-1)}
```

> Note: USN close-records accumulate every reason since the file was opened, so a
> routine "save" usually arrives as one Create/Modify event rather than one per
> write. This is the intended forensic granularity.

---

## EventData fields (`{PARAM[n]}` reference)

Each event is emitted with positional insertion strings. In Event Log Explorer
(or any tool using positional `EventData`), extract a field as a custom column
with `{PARAM[n]}`, using the index below.

> `{PARAM[1]}` is a human-readable summary so the description tab stays useful;
> the individual fields begin at `{PARAM[2]}`. Positional indices are part of the
> event field contract (`SchemaVersion`) — a **MAJOR** schema bump is required if
> they ever change.

| Index | Field | Notes |
|-------|-------|-------|
| `{PARAM[1]}` | Summary | One-line summary + full readable field block |
| `{PARAM[2]}` | SchemaVersion | Field-contract version (e.g. `1.0`) |
| `{PARAM[3]}` | Category | Create / Modify / Delete / Rename / SecurityChange / Other / RangeChange |
| `{PARAM[4]}` | TargetFilename | Full path (mirrors Sysmon — correlation key) |
| `{PARAM[5]}` | UtcTime | `YYYY-MM-DD HH:MM:SS.fff` (mirrors Sysmon — correlation key) |
| `{PARAM[6]}` | Reason | Full USN reason string (all flags) |
| `{PARAM[7]}` | Usn | USN sequence number (ordering primitive) |
| `{PARAM[8]}` | JournalId | USN journal ID (detects journal resets) |
| `{PARAM[9]}` | Hostname | Source host name |
| `{PARAM[10]}` | FQDN | Fully qualified domain name |
| `{PARAM[11]}` | Domain | DNS domain |
| `{PARAM[12]}` | MachineGuid | Stable machine identifier |
| `{PARAM[13]}` | MachineSID | Machine SID (best-effort) |
| `{PARAM[14]}` | SourceIP | IP address(es) at service start |
| `{PARAM[15]}` | MAC | Primary MAC address |
| `{PARAM[16]}` | VolumeSerial | NTFS volume serial (`XXXX-XXXX`) |
| `{PARAM[17]}` | OSBuild | OS version/build |

**Note:** these `EventData` elements are *positional and unnamed* (a limitation of
classic event reporting), so `{EventData\Usn}`-style **named** lookups do **not**
work — use the positional `{PARAM[n]}` indices above. Named-field access requires
the instrumentation-manifest build (planned).

## Selecting paths to monitor

Run `python usn_monitor.py` with no arguments to open the configuration GUI:

- The tree lazily loads directories (no hang on large drives).
- **Double-click a folder** to recursively add (or remove) it *and all of its
  sub-directories* to the whitelist. Recursive walks run off the UI thread, so
  the GUI never freezes.
- **`[X]`** = monitored, **`[ ]`** = not monitored.
- Use the search box to jump to a folder by name.
- Click **Save Config (JSON)** to write `monitor_config.json`.

By default, `C:\Windows` and all sub-directories are monitored; everything else is
excluded.

### `monitor_config.json` format

The config file lives next to `usn_monitor.py`. The service reads it **once at
startup** — restart the service after any change.

```json
{
    "paths": [
        "C:\\Windows",
        "C:\\Windows\\System32",
        "C:\\Windows\\Temp"
    ],
    "rotation_size_gb": 3.5,
    "max_storage_gb": 60.0
}
```

| Key                | Meaning                                                            |
|--------------------|-------------------------------------------------------------------|
| `paths`            | Monitored directories (recursive selections include every subdir) |
| `rotation_size_gb` | Rotate the live log when it reaches this size (GB)                 |
| `max_storage_gb`   | Total archive directory cap; oldest archives deleted FIFO (GB)    |

> Changing the JSON does **not** affect a running service. Apply with:
> `python usn_monitor.py restart`

---

## Log rotation & retention

- **Live log:** `FileSystem.evtx` (the custom `FileSystem` Windows Event Log).
- **Rotation triggers (whichever comes first):**
  - The live log reaches `rotation_size_gb` (default **3.5 GB**), or
  - The calendar reaches the **1st of the month at 01:00**.
- **Archive naming:** `FileSystem_<Month>_<Year>_<counter>.evtx`
  (e.g. `FileSystem_June_2026_1.evtx`); the counter resets each month.
- **Archive location:** `C:\FileSystem_Archives`
- **Storage cap:** when the archive directory exceeds `max_storage_gb`
  (default **60 GB**), the **oldest** `.evtx` files are deleted first (FIFO) until
  the directory is back under the cap.

Rotation is performed with `Clear-EventLog -Backup`, which atomically archives and
clears the live log.

---

## Service management

```bat
python usn_monitor.py --startup delayed install   :: install (delayed auto-start)
python usn_monitor.py start                        :: start
python usn_monitor.py stop                         :: stop
python usn_monitor.py restart                      :: stop + start (reloads config)
python usn_monitor.py update                        :: re-register after editing the .py
python usn_monitor.py remove                        :: uninstall
sc query USNMonitorService                          :: check status
```

- Use `--startup auto` instead of `delayed` to start as early as possible at boot.
- Run **`update`** (not reinstall) after editing the source; the SCM caches the
  script path.

---

## Diagnostics

The service writes its own operational log (errors, startup info, rotation
activity) to:

```
C:\FileSystem_Archives\usn_monitor.log
```

For deep troubleshooting, enable a periodic counter summary (records seen /
resolve failures / whitelist matches / events emitted) by setting the
`USN_VERBOSE` environment variable to `1`, `true`, `yes`, or `on`.

```bat
:: Console (inherits your shell environment)
set USN_VERBOSE=1
python usn_monitor.py debug

:: Service (must be machine-wide, then restart so the SCM picks it up)
setx USN_VERBOSE 1 /m
python usn_monitor.py restart
```

A verbose stats line looks like:

```
stats: seen=48 (v2=48 v3=0 v4=0) resolve_fail=0 no_match=3 emitted=45 last_resolve_err=None
```

`no_match` counts changes outside the whitelist (expected to be large — it is the
whole-volume churn you are *not* capturing).

---

## Deploying to multiple machines

See **[DEPLOYMENT.md](DEPLOYMENT.md)** *(if provided)* for Group Policy / Active
Directory and packaged-executable options. In brief:

1. **With Python on targets:** copy `usn_monitor.py` + `monitor_config.json` to
   each host, then run the install/start commands (e.g. via a GPO startup script
   or remote management tool).
2. **Without Python on targets (recommended at scale):** freeze to a standalone
   executable with PyInstaller and deploy that — no Python runtime required on
   endpoints.
3. Push a standard `monitor_config.json` to all hosts so they share one whitelist
   and retention policy.

---

## Notes & caveats

- Requires elevation; under the default `LocalSystem` account this is automatic.
- The `FileSystem` log and event source are auto-registered on first run.
- On very high-I/O volumes with a broad whitelist, the live log grows quickly —
  the 3.5 GB / 60 GB rolling policy is doing real work; tune it for your retention
  needs.
- Path resolution is cached by directory; rename/delete events bypass the cache to
  avoid stale paths.

---

## License

See LICENSE file for current LICENSE used for this project.
