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

## Important: regex extraction from a single Data node

Classic `ReportEvent` events on a custom channel render **all** their content into
a **single** `<Data>` element (there is no manifest defining separate named
fields). So these maps do **not** use positional `Data[N]` — they use EvtxECmd's
`Refine:` regex to pull each field out of the one `Data` blob.

The agent emits each field as `Key: value` on its own line. Each map Value uses a
**lookbehind** regex so the match excludes the `Key: ` prefix, e.g.:

```yaml
Name: usn
Value: "/Event/EventData/Data"
Refine: "(?<=Usn: )[0-9]+"
```

`.+` stops at the end of line (no Singleline), so multi-value fields like
`SourceIP` (IPv6, IPv4) and `Reason` (`A + B`) are captured whole.

If the field **order or names** in `usn_monitor.py` ever change, the `Key:` names
the regexes anchor on must still match — the names are the contract (tracked by
`SchemaVersion`). A future instrumentation-manifest build would replace these regex
binds with native named `Data[@Name="..."]` lookups.

## Tip

EvtxECmd can validate a map without full processing — run it against a small sample
archive and watch for `had validation errors` messages. The maps in this folder
have been YAML-validated, but always test against real data from your build.
