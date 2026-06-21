# usnmon — USN Journal Monitor

**Continuous NTFS USN-journal recorder for Windows forensic monitoring.**
Maintained by YASDC · License: [PolyForm Noncommercial 1.0.0](LICENSE)

> **Supersedes [`usn_monitor.py`](old_srcs/).** The original directory-targeted
> monitor is deprecated and preserved under [`old_srcs/`](old_srcs/) for reference.
> usnmon is a ground-up rewrite with a fundamentally different design (see below).

---

## What it does

usnmon continuously records file-system activity on every local NTFS volume by reading
the **USN change journal**, writes those records to a dedicated Windows event channel
(`FileSystem`), and periodically rotates that channel into timestamped, hashed
archives. It also tracks **removable-device identity** — including drives it cannot
journal — so USB attach/detach/reformat is recorded even when the files on those drives
are not.

It is a **witness**: it records what happened and lets you verify the record matches
what was captured. It is **not** a tamper-prevention tool — read [`SECURITY.md`](SECURITY.md)
for exactly what it does and does not guarantee before relying on it.

## Design: capture everything

The original `usn_monitor` was laser-focused — you configured specific directories to
watch. usnmon inverts that: it **captures 100% of journaled activity on all volumes**
and logs everything to a single channel, leaving filtering and analysis to downstream
tools. The only writes it deliberately suppresses are its **own** (the live event log
and its config file) to avoid a feedback loop — everything else, including its own
archives and state files, is captured, because tampering with those is forensic signal.

## Features (v0.0.7)

- **Continuous multi-volume capture** from the USN journal. On first run for a volume
  it reads the retained journal once (history capture), then advances live; on restart
  it resumes from the saved cursor — never re-reading from the start every poll.
- **Parent-reference path resolution** — deleted files still resolve to a real path,
  with a stable, high-hit-rate cache.
- **Gap-free resume** — a persisted per-drive cursor (JournalId + last USN) survives
  restarts; unavoidable gaps (records purged from the ring, or a recreated journal) are
  recorded (event 923), never silently skipped.
- **Full volume disposition** — every drive is monitored or recorded as un-monitorable
  with a reason (no active journal / unsupported filesystem / remote share — events
  919/920/921). Nothing is dropped silently.
- **Removable-device identity** — attach/detach/re-attach/reformat tracking
  (events 500/501/503/504) with hardware serial + USB registry artifacts, **including
  for non-journalable drives** (exFAT/UDF). Detach is detected by volume enumeration
  without re-probing the journal.
- **Rotation** on the calendar-month boundary **or** a 3.5 GB size cap (whichever
  first), with span-named archives (v0.0.7c+); `--log-interval` overrides the time-leg
  with any other cadence: export -> 4-hash the evidence -> write manifest -> bundle
  evidence + manifest into one zip -> events 904 (success) / 922 (failure).
- **Legal retention** — optional `--legal-retention` prunes whole aged-out archive
  bundles (default: keep everything); never alters a sealed archive.
- **Integrity manifests** — MD5/SHA-1/SHA-256/SHA-512 over the evidence file (not the
  zip container), bound inside the archive bundle so proof travels with evidence.
- **Dual-tool field contract** — the same events parse cleanly in EvtxECmd / Timeline
  Explorer (via the included [maps](maps/)) and Event Log Explorer, and read natively
  in Velociraptor.

## Quick start

Deploy `usnmon.py` and `usn_common.py` together. Run modes:

```
python usnmon.py install                       # install as a Windows service
python usnmon.py --startup delayed install     # install with a start mode (pywin32 native)
python usnmon.py start                         # start the installed service
python usnmon.py debug                         # foreground, verbose console
python usnmon.py debug --log-interval 2m       # ...rotating every 2 minutes (testing)
python usnmon.py config                        # interactive settings editor (see below)
python usnmon.py archive-now                   # force one rotation
python usnmon.py check                         # report any missing month-bucket archives
python usnmon.py                               # no args: run as service (SCM dispatch)
```

**Rotation.** By default the live log rotates into an archive on the **calendar-month
boundary** (1st at 00:00:00, closing out the previous month) **OR** when it reaches
the **3.5 GB** size cap, whichever comes first. Archive naming as of v0.0.7c/v0.0.8:
a full untouched calendar month is named `FileSystem_<MonthName>_<YYYY>.zip` (e.g.
`FileSystem_June_2026.zip`); everything else uses an ISO-style span name like
`FileSystem_2026-06-17_to_2026-07-16.zip` (whole-day boundaries) or
`FileSystem_2026-06-17-100000_to_2026-06-18-100000.zip` (sub-day boundaries). The
filename **is** the rotation window — so the moment a `1M` archive uses a span name,
the investigator sees at a glance that the size cap fired that month.

`--log-interval <N><unit>` overrides the monthly time-leg. The 3.5 GB size cap still
applies. Unit table (v0.0.8 — case-significant on `m` vs `M`):

| Unit | Meaning |
|---|---|
| `s` | seconds, fixed interval (interval unit) |
| `m` | **minutes**, fixed interval (interval unit) |
| `h` | hours, fixed interval (interval unit) |
| `d` | calendar days (midnight-to-midnight) (calendar unit) |
| `w` | calendar weeks (Monday 00:00 ISO 8601) (calendar unit) |
| `t` | 30-day fixed terms (interval unit) |
| `M` | **calendar months** (next 1st 00:00, leap-aware) (calendar unit) |
| `y` | calendar years (next Jan 1 00:00) (calendar unit) |

Substitution gives total flexibility: "every calendar week" = `1w`, "every 7 days
from start" = `7d`. "Every calendar month" = `1M`, "every 30 days from start" = `1t`.
"Every calendar year" = `1y`, "every 365 days" = `365d`. Examples: `--log-interval 24h`
(every 24 hours from anchor), `--log-interval 1d` (every calendar day at midnight),
`--log-interval 36h` (every 36 hours from anchor — supported for inter-day cadences).
Persisted to config so the service honors it.

`--legal-retention <N><unit>` prunes whole aged-out archive bundles. Allowed units:
`y` (calendar years), `M` (**calendar months — capital M, not m**), `t` (30-day
terms), `w` (calendar weeks), `d` (calendar days). Sub-day units (`s`/`m`/`h`) are
not allowed for retention (sub-day pruning is meaningless). So `25y`, `18M`, `90d`,
`18t`, `26w` are all valid. Integer values only (use `18M`, not `1.5y`). Caps are
generous (25 years for `M` and `y`, 10 years for `d`/`w`/`t`) to cover real-world
long-horizon mandates like medical-records retention. **Blank/unset = keep
everything forever (the default).** Pruning deletes only complete, fully-expired
archive bundles — never trims or reopens a sealed (hashed) archive, so every
surviving archive's integrity stays intact.

> **Important change in v0.0.8:** retention uses `M` (capital) for calendar months,
> NOT `m`. The lowercase `m` everywhere in usnmon means minutes. A pre-v0.0.8
> `legal_retention: "18m"` config will fail-safe to keep-everything; migrate to
> `18M` to restore intended behavior.

> **Persistent rotation state (v0.0.8).** Three anchor fields drive the rotation
> logic: `install_month` (when usnmon was first installed), `engine_start_anchor`
> (every engine start), and `rotation_anchor` (every archive close). On restart the
> engine detects four cases and acts: clean continuation, clock anomaly (emits 926),
> size-cap mid-window (continues from persisted), or gap (emits 925; interval modes
> also write a partial closing archive). See [`EVENT_ID.md`](EVENT_ID.md) for the
> 925 and 926 event details.

The service start mode is set with pywin32's native `--startup <manual|auto|disabled|delayed>`
flag at install (e.g. `python usnmon.py --startup delayed install`) — the standard way
Python services are installed. usnmon reads the configured mode back from Windows after
install and records it (shown by `check` and in each `Engine Started` (914) log entry).
To change it, reinstall with a different `--startup` value. `delayed` (delayed-auto) is
recommended for a forensic recorder: it self-starts after a reboot but after the boot
storm.

Archives land in `C:\FileSystem_Archives\` by default, each `.zip` containing the
`.evtx` and its `.evtx.manifest`.

> **Administrator rights are required** for journal access and for the rotation's
> export/clear of the live channel.

## Changing settings (`usnmon config`)

`python usnmon.py config` opens an interactive, numbered editor for the user-changeable
settings (archive directory, rotation interval, legal-retention term, service start
type). It shows only those settings — never the engine's internal cursor state — and if
the service is running it detects that and offers to stop it before editing (the engine
writes cursor state continuously, so editing must happen while stopped), then offers to
restart afterward. Do not hand-edit `usnmon.cfg`: it carries live runtime state and a
hand-edit can break gap-free capture.

## Requirements

- Windows, Python 3, `pywin32`.
- `cryptography` is imported by an inactive signing code path (see
  [`SECURITY.md`](SECURITY.md) — signing is **not enabled**); it is not required for
  capture, rotation, or hashing.
- `python-evtx` is optional, for reading archives directly without Zimmerman tools.

## Verifying an archive (manual)

1. Unzip `FileSystem_<Month>_<Year>_<N>.zip` — you get the matching `.evtx` and its
   `.evtx.manifest`.
2. Hash the `.evtx` with any tool (e.g. HashMyFiles, `certutil -hashfile`,
   `Get-FileHash`).
3. Compare against the `sha256` (and others) in the manifest. A match confirms the
   archive matches the hash recorded at rotation time.

(See [`SECURITY.md`](SECURITY.md) for what this does and does not prove. A guided
verification workflow is planned as part of a separate analysis tool.)

## Parsing archives in Timeline Explorer

Copy the [`maps/`](maps/) `*.map` files into EvtxECmd's `Maps` folder, then parse an
archive (or a folder of them with `-d`) to CSV and open in Timeline Explorer. Full
column-mapping details and the three event "shapes" are in
[`maps/README_maps.md`](maps/README_maps.md).

## Documentation

- **[EVENT_ID.md](EVENT_ID.md)** — the full event-ID taxonomy (file, device,
  operational, test). The Rosetta Stone for reading these logs and writing SIEM/EDR
  queries.
- **[SECURITY.md](SECURITY.md)** — scope, threat model, and honest limitations. What
  usnmon guarantees and, importantly, what it does not. **Read before relying on it.**
- **[maps/README_maps.md](maps/README_maps.md)** — EvtxECmd / Timeline Explorer / ELE /
  Velociraptor integration.

## Companion analysis tools

usnmon ships alongside two companion tools that analyze the archives it produces.
Both are self-contained Python scripts that only require `python-evtx` or the
Rust `evtx` reader:

- **`usn_stats.py` v0.2.0** — census/profiler. Single-file mode produces a full
  per-archive report (run/throughput, event-ID frequency, top directories with
  recursive >40%-of-parent breakdown, extensions, temporal, resolution health,
  operational/device summary). **Series mode** (point it at a directory of
  archives) adds: consolidated summary, self-integrity check (coverage
  continuity / engine restarts / archive-close events / anomaly events),
  session inference (WSL/Chrome/Edge/Firefox/RDP/PSReadLine patterns), rotation
  capacity projection (fill time at observed rate vs. 1/3.5/5 GB targets), and
  per-archive comparison table.

- **`usn_drill.py` v0.0.1** — targeted drill-down. Takes an archive + a filter
  file of directory substrings (one per line, strict `\` terminator validation),
  produces a focused report scoped to the filter: throughput, event-ID mix,
  top directories (full depth), file extensions with event-type mix (C/M/D/R/S/O
  %), filename pattern analysis (GUID/timestamp/hash/sequential detection),
  file lifetime analysis (Create+Delete pairs, transient detection,
  fastest-cycling files), resilient-files detection (state-journaling
  fingerprint), temporal/burst detection, per-instance inference
  (cam/camera/stream/channel/instance N regex), resolution health.

## Status

v0.0.8a — current shipping engine. Builds on v0.0.7's calendar-month rotation,
legal-retention, and configurable start-type with: unified time-period parser
(`s`/`m`/`h`/`d`/`w`/`t`/`M`/`y`), `rotation_anchor` state machine driving the
ramp-in → clean-cycle rotation rule, 4-case restart detection (clean / clock
anomaly → 926 / size-cap mid-window / cross-boundary gap → 925), and a
dead-code/consolidation cleanup pass (-72 net lines across the a/b/c series).
EID 106 (V4 range-change) is **reserved** (not emitted). Companion analyzer
tools `usn_stats.py` v0.2.0 and `usn_drill.py` v0.0.1 ship in the same release.
Planned for v0.0.8b: service-stop hang fix + `status` subcommand.
