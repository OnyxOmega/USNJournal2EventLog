# EVENT_ID.md — usnmon Event ID Reference

Every event ID emitted to the **`FileSystem`** channel by usnmon, what it means, its
severity, and how to read it. This is the reference for investigators, SIEM/EDR query
authors, and anyone correlating these logs with other sources.

All events are written by the provider **`USNJournalMonitor`** to the custom Windows
event channel **`FileSystem`**. Archives are exported copies of that channel
(`FileSystem_<timestamp>.evtx`, bundled with their `.manifest` inside a `.zip`).

There are four families:

| Range | Family | Structure |
|-------|--------|-----------|
| 100–105 | File change (106 reserved) | full field array (`Data[1..21]`) |
| 500–504 | Removable-device identity | full field array |
| 800–803 / 899 | Test markers | full field array — **test tooling only, not in production logs** |
| 900–926 | Operational / host state | single message string (`Data[1]`) |

For how these map to EvtxECmd / Timeline Explorer columns, see
[`maps/README_maps.md`](maps/README_maps.md). For what the tool does and does not
guarantee, see [`SECURITY.md`](SECURITY.md).

---

## File events (100–105; 106 RESERVED)

Recorded for activity on monitored NTFS volumes. One event per file, per poll cycle,
with the accumulated USN reason flags resolved to a single category by priority
(**Delete > Create > Rename > SecurityChange > Modify > Other**). The path is resolved
via the **parent** file reference, so even deleted files resolve to a real path and
share a stable cache key.

| ID | Category | Meaning |
|----|----------|---------|
| **100** | File Create | A file/directory was created. |
| **101** | File Modify | Data or basic-info change (the catch-all "modify"). |
| **102** | File Delete | A file/directory was deleted (path still resolved via parent ref). |
| **103** | File Rename | A rename (old/new name reasons collapsed to one rename event). |
| **104** | Security Change | ACL/owner/security descriptor change. |
| **105** | Other Change | A change that did not match a higher-priority category. |
| **106** | Range Change (V4) | **RESERVED — never emitted.** Would carry a USN V4 range-change record (which byte ranges of a large/sparse file changed). The engine reads V0/V2 journal records and does not request V4, so 106 never fires. V4 records carry only changed byte-ranges — no content, no before/after values (the old data exists only in a VSS snapshot, not the journal) — so they add no forensic signal beyond the Modify (101) already emitted. The map file is retained in case a future non-forensic use ever enables V4. |

Key fields: **TargetFilename** (primary correlation key), **UtcTime**, **Usn**,
**JournalId**, **VolumeSerial**, **Reason** (the raw flag text), plus host identity.

---

## Removable-device events (500–504)

Recorded when a volume appears, changes, or disappears — **including volumes that
cannot be journaled** (exFAT/UDF USB, etc.). Device identity is captured from the
hardware serial (firmware-level, stable across reformats) and the USB registry
artifacts (USBSTOR, MountedDevices, volume GUID). These fire for *every* volume, so a
drive whose files can't be monitored still has its presence and identity recorded.

| ID | Category | Meaning |
|----|----------|---------|
| **500** | Device Connected (NEW) | A device never seen before (by HW serial / VSN) attached. |
| **501** | Device Removed | A known device detached. Carries the **last-known** HW serial + VSN of the drive that left (looked up from device state), so the detach records *which* device. |
| **503** | Known Device Re-attached | A previously-seen device re-attached; identity unchanged. |
| **504** | Known Device ALTERED | Same hardware serial, **different VSN** — i.e. the volume was reformatted, cloned, or had its Volume ID tampered. Carries **PreviousVsn** alongside the new VSN (the reformat/tamper delta). |

A non-NTFS USB drive typically produces a **500/503** (identity) immediately followed
by a **920** (can't journal its files) — correlate the two by drive letter and the
~6-second window.

---

## Test markers (800–803, 899) — test tooling only

These are emitted by the **local test harness**, not by the production engine, and are
**not** shipped in normal archives. They exist so capture-latency can be measured: each
marker is written immediately before a real filesystem operation, and the engine's
corresponding file event is paired to it by a shared machine-wide QPC timestamp.

| ID | Marker | Pairs with |
|----|--------|-----------|
| **800** | Test File Create | engine 100 |
| **801** | Test File Modify | engine 101 |
| **802** | Test File Delete | engine 102 |
| **803** | Test Security Change | engine 104 |
| **899** | Test run boundary/marker | — |

If you see these in a production archive, the test harness was run against a monitored
volume. They are documented here for completeness; the public map set does not include
maps for them.

---

## Operational events (900–926)

Host-state and lifecycle events describing the **monitoring machine itself** — not file
activity. **Structurally different from file/device events: each carries a single
human-readable message string only** (`Data[1]`), with no broken-out key/value fields.
Time and host come from the event's native `TimeCreated` / `Computer`. These are
typically acted on at the machine (locally or via remote-in), not parsed for
correlation.

| ID | Sev | Meaning |
|----|:---:|---------|
| **904** | Info | **Archive written** — a rotation completed: the live log was exported, hashed, manifested, and bundled. The message names the bundle. |
| **914** | Info | **Engine started** — capture began. Message carries host + machine id. |
| **915** | Info | **Engine stopped** — clean shutdown (cursors saved). |
| **916** | Warn | **Drive/journal failure** — a drive's capture failed or its journal became unreadable (e.g. export/clear error, drive yanked mid-read). |
| **917** | Warn | **Degraded state** — *reserved* (defined; not currently emitted). |
| **918** | Error | **Archive completeness gap** — an expected month-bucket archive is missing (a hole in the archive sequence). |
| **919** | Warn | **No active USN journal** — an NTFS volume is present but has no active change journal, so it is not monitored. |
| **920** | Warn | **Unsupported filesystem** — the volume's filesystem (exFAT/UDF/FAT) cannot host a USN journal; not monitored. Device identity is still captured (see 500/503). For optical/virtual volumes (drivetype 5) the detail also tags `kind=iso` (a mounted ISO, e.g. a training image) vs `kind=physical` (a real disc) when it can be determined, else just `drivetype=5`. |
| **921** | Warn | **Remote/network share** — the volume is a network share with no local journal; not monitored. |
| **922** | Error | **Archive sign/hash failure** — the rotation's hashing/manifest/bundle step failed. The evidence for that interval may be incomplete. |
| **923** | Warn | **Resume gap** — on restart, the saved cursor was older than the journal's lowest valid USN (or the journal was recreated): records were lost while the engine was stopped. A coverage hole the analyst must account for. |
| **925** | Error | **Archiving gap detected** — on engine start (v0.0.8+), the persisted `rotation_anchor` is older than the current rotation window's start, meaning the engine was stopped long enough that at least one full rotation window's archive was never produced. For **interval-mode rotation** (`24h`, `7d`, `1t`, etc.) the engine also writes a partial closing archive named for the pre-stop window's actual span, capturing whatever records had accumulated in the channel before stop. For **calendar-mode rotation** (`1d`, `1w`, `1M`, `1y`) no partial archive is written — the in-progress channel just continues, with the gap documented by the bracketing 915/914 events inside the next full archive. The detail names the missed window range and how many rotation cycles were skipped. **Distinct from 918**: 918 fires when a *completed-month archive is missing from disk* (a hole detected later by scanning); 925 fires at the *moment* of a restart that crossed a rotation boundary. |
| **926** | Error | **Clock anomaly detected** — on engine start (v0.0.8+), the persisted `rotation_anchor` is *later* than the current wall-clock time. This is evidence the system clock moved backward between sessions (manual change, ntpd correction, timezone shift on a laptop crossing time zones, hibernation drift, suspect tampering). The detail gives the persisted anchor, current `now`, and the delta. Forensically significant when correlating with filesystem timestamps: an investigator who sees 926 should treat all timestamps in the surrounding window with care. The engine resets `rotation_anchor` to `now` to recover; the previous timeline before the anomaly is intact in earlier archives. |

### The events that matter most for an investigator

- **923 (Resume gap)** and **918 (Completeness gap)** — these flag **coverage holes**.
  If present, the captured record set is not continuous, and you must account for the
  gap before drawing conclusions.
- **922 (Sign/hash failure)** — the integrity proof for that interval may be missing.
- **919/920/921** — tell you **what was *not* monitored and why** ("this exFAT USB's
  files were invisible to us — but here's its identity from the paired 500/503").
- **904** — archive boundaries; the rhythm of rotation. A missing 904 where one is
  expected is itself a signal.

---

## Quick severity legend

- **Info (904, 914, 915):** normal lifecycle. Expected rhythm.
- **Warn (916, 917, 919, 920, 921, 923):** something wasn't monitored, or coverage has
  a hole, or a drive misbehaved. Not necessarily an error — often expected (a UDF disc,
  a network share) — but always worth a glance.
- **Error (918, 922):** an archive-integrity or completeness problem. Investigate.
