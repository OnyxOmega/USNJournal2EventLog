# USN Journal Monitor — Features

A headless Windows service that tails the NTFS USN Change Journal and writes
enriched, structured file-change events to a custom Windows Event Log for DFIR
telemetry and Sysmon correlation.

## Core capture
- Tails the NTFS USN Change Journal directly (volume-level), catching changes a
  filesystem minifilter (e.g. Sysmon) can miss.
- Reads retroactive journal history already on disk — captures activity that
  occurred before the agent was deployed.
- USN record-format negotiation: prefers V2 for reliable 64-bit file references,
  falls back to V3 (ReFS), then V4 range records.
- Boundary-correct path resolution with a file-reference cache (cache bypassed on
  rename/delete for correctness); `C:\Windows` never false-matches `C:\WindowsApps`.

## Multi-drive
- Monitors all fixed NTFS/ReFS volumes, one journal-reader thread per drive.
- Each drive carries its own volume handle, journal ID, resolver, and volume serial.
- Non-`--all` mode runs engines only on drives referenced by the configured roots.

## Path selection (roots + excludes)
- Stores only top-most monitored **roots** — each implies all sub-directories.
- **Exclude** list carves out sub-trees under a root (include-broad / exclude-noisy).
- New sub-directories and new user profiles are matched automatically (portable
  config: `C:\Users` covers every user on any machine).
- `--all` flag (and GUI checkbox) monitors every change on every drive, ignoring
  roots/excludes; persisted to config so the service honors it.

## Event output
- Distinct Event IDs per change category: 100 Create, 101 Modify, 102 Delete,
  103 Rename, 104 SecurityChange, 105 Other, 106 RangeChange (ReFS/V4).
- Priority classification of accumulating USN reason flags
  (Delete > Create > Rename > Security > Modify > Other).
- Writes to a dedicated custom **FileSystem** event log (source `USNJournalMonitor`).
- Readable `Key: value` description block per event (single insertion string).
- Six high-value fields also emitted as positional insertion strings for Event Log
  Explorer `{PARAM[n]}` columns (Hostname, TargetFilename, UtcTime, MachineGuid,
  SourceIP, VolumeSerial).

## Forensic enrichment (per event)
- SchemaVersion, Category, TargetFilename, UtcTime (Sysmon-format, ms precision),
  Reason, Usn, JournalId.
- Host context (gathered once at start): Hostname, FQDN, Domain, MachineGuid,
  MachineSID, SourceIP, MAC, OSBuild.
- Per-drive VolumeSerial.
- TargetFilename + UtcTime deliberately mirror Sysmon field names as correlation keys.

## Event log management
- Sets the FileSystem log to ~4 GB on first creation (avoids the tiny ~1 MB default).
- On interactive start (GUI/console), if the log is below the 1 GB recommended
  minimum, prompts to set 1 GB (minimum) or 4 GB (maximum); the service never prompts.

## Archive rotation & storage
- Rolling archive of the live log to `C:\FileSystem_Archives` with backup-and-clear.
- Configurable per-log rotation trigger (default 3.5 GB) and total archive cap
  (default 60 GB, FIFO eviction of oldest archives).
- Both sizes editable in the GUI (validated: positive, per-log ≤ total cap).

## Configuration
- JSON config (`monitor_config.json`) with scalars first and the path list last for
  readability; compact even at fleet scale (roots + excludes, not enumerated trees).
- Keys: schema_version, monitor_all, max_storage_gb, rotation_size_gb, exclude, paths.

## GUI (no-argument launch)
- Drive-tree browser with lazy expansion; one root node per fixed drive.
- Three-state markers: `[X]` monitored, `[-]` excluded, `[ ]` off — propagated by
  ancestor (selecting a root visually checks its whole subtree).
- Double-click toggles a root (all-or-nothing, auto-subsuming child roots).
- "Mark to Exclude" / "Remove Exclusion" button for the highlighted folder + subtree.
- "Monitor ALL drives" checkbox; editable rotation/storage fields; folder search.

## Tool integration
- EvtxECmd maps (Events 100–106) extract every field by regex into Timeline Explorer
  `PayloadData` columns; host name lands in the standard Computer column.
- Designed for side-by-side Sysmon correlation in Timeline Explorer via TargetFilename
  and UtcTime.
- Provider GUID published for Sysmon channel correlation.

## Service & deployment
- Installs as a Windows service (`USNMonitorService`) with configurable start type
  (e.g. delayed-auto); clean stop within ~10 s.
- Console `debug` mode for foreground testing (Ctrl+C to stop).
- Fleet rollout via GPO startup script / GPP / MSI / SCCM (PyInstaller-frozen, signed).
- WEF → WEC source-initiated forwarding to a central collector (subscription targets
  the FileSystem channel; forwarder read-grant documented).

## Diagnostics
- Own diagnostic log at `C:\FileSystem_Archives\usn_monitor.log`.
- Optional verbose per-drive statistics (set `USN_VERBOSE`): seen / resolved /
  no-match / emitted counters every few seconds.

## Planned / roadmap
- Instrumentation-manifest build for named EventData fields (needs Windows SDK).
- JSON SIEM schema mirroring the event fields.
- Central collector / fleet-management features and optional licensing tier.
