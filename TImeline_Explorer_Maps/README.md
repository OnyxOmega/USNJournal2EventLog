# EvtxECmd Maps — USN Journal Monitor → Timeline Explorer

These maps let [EvtxECmd](https://ericzimmerman.github.io/) parse this tool's
`FileSystem` events into clean, named columns for **Timeline Explorer**, so USN
file-change events can be correlated alongside Sysmon (and other) sources in one
timeline.

## Files

One map per Event ID (EvtxECmd maps are per-EventID):

| File | Event | Category |
|------|:-----:|----------|
| `FileSystem_USNJournalMonitor_100.map` | 100 | File Create |
| `FileSystem_USNJournalMonitor_101.map` | 101 | File Modify |
| `FileSystem_USNJournalMonitor_102.map` | 102 | File Delete |
| `FileSystem_USNJournalMonitor_103.map` | 103 | File Rename |
| `FileSystem_USNJournalMonitor_104.map` | 104 | Security Change |
| `FileSystem_USNJournalMonitor_105.map` | 105 | Other Change |
| `FileSystem_USNJournalMonitor_106.map` | 106 | Range Change (V4) |

## Install

Copy all `*.map` files into EvtxECmd's `Maps` folder (next to `EvtxECmd.exe`),
e.g. `...\EvtxECmd\Maps\`.

## Parse to CSV

```
EvtxECmd.exe -f "C:\FileSystem_Archives\FileSystem_June_2026_1.evtx" --csv "C:\out" --csvf usn.csv
```

(Use `-d` to process a whole folder of archives at once.) Then open the CSV in
Timeline Explorer.

## Column mapping

The maps fill EvtxECmd's standard output columns. The host name is already in the
**Computer** column (from the event's System data), so the PayloadData columns are
used for the change-specific fields:

| Column | Field (source `Data[N]`) | Purpose |
|--------|--------------------------|---------|
| MapDescription | (from map) | Human-readable event meaning (e.g. "USN: File Delete") |
| Computer | System/Computer | Source host name |
| PayloadData1 | TargetFilename `Data[4]` | **Primary correlation key** (matches Sysmon `TargetFilename`) |
| PayloadData2 | Category `Data[3]` | Create / Modify / Delete / Rename / etc. — filterable |
| PayloadData3 | UtcTime `Data[5]` | USN change time, `YYYY-MM-DD HH:MM:SS.fff` (matches Sysmon `UtcTime`) |
| PayloadData4 | Reason `Data[6]` | Full USN reason flags |
| PayloadData5 | Usn `Data[7]` + JournalId `Data[8]` | Ordering primitive + journal-reset detection |
| PayloadData6 | SourceIP `Data[14]` + VolumeSerial `Data[16]` + SchemaVersion `Data[2]` | Host/disk identity + field-contract version |

Fields not given a dedicated column (FQDN, Domain, MachineGuid, MachineSID, MAC,
OSBuild) remain available in the full **Payload** column.

## Correlating with Sysmon in Timeline Explorer

1. Parse the Sysmon log with EvtxECmd (its bundled
   `Microsoft-Windows-Sysmon-Operational` maps cover Event IDs 11 / 23 / 26).
2. Parse this tool's `FileSystem` archive with these maps.
3. Load both CSVs in Timeline Explorer (or merge them).
4. Pivot/filter on **TargetFilename** and **UtcTime** — the two fields these maps
   deliberately mirror from Sysmon. Sort by time to see the USN change record
   (what changed, volume-level) next to the Sysmon record (who changed it — process
   and user). USN catches changes Sysmon's minifilter can miss, and carries
   retroactive history, so the two together close gaps neither has alone.

## Important: positional binding

These maps extract by **position** (`/Event/EventData/Data[N]`) because the current
events use classic positional insertion strings. The positions are frozen by the
event field contract (`SchemaVersion`). **If the field order in `usn_monitor.py`
ever changes, bump `SchemaVersion` (MAJOR) and update the `Data[N]` indices in
these maps to match.** A future instrumentation-manifest build would switch these
to named bindings (`Data[@Name="Usn"]`); until then, keep the order stable.

## Tip

EvtxECmd can validate a map without full processing — run it against a small sample
archive and watch for `had validation errors` messages. The maps in this folder
have been YAML-validated, but always test against real data from your build.
