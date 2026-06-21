v0.3 | 2026-06-20 | Source: usnmon project, YASDC | License: PolyForm Noncommercial 1.0.0

# EVENT_ID_ANOMALIES.md

## Purpose

This document describes the event IDs that usnmon writes to the Windows Event Log channel `FileSystem`, what each indicates, and what patterns of event ID distribution suggest about the underlying workload. Use this as a reference when interpreting the EVENT-ID FREQUENCY and OPERATIONAL / DEVICE EVENTS sections of `usn_stats` and `usn_drill` reports.

## Event ID categories

usnmon writes events into four categories:

| Range | Category | Purpose |
|---|---|---|
| 100–105 | File events | Per-file lifecycle: Create, Modify, Delete, Rename, Security, Other |
| 500s | Device events | Removable media, drive attach/detach, filesystem detection |
| 900s | Operational events | Engine lifecycle, archive management, anomaly signals |
| 904 | Archive Written | Each completed rotation writes one of these |
| 914 | Engine Started | Each engine start writes one of these |

The detailed taxonomy of every event ID is in the project's `EVENT_ID.md` design document. This file documents the analytical patterns those events produce in real captures.

## File event IDs (100–105) and their interpretation

### Event 100 — File Create

A new file or directory was created. Each create event represents one new entry in the filesystem namespace.

Typical patterns:
- **High Create percentage (>60%)**: Installation, deployment, fresh content download, bulk file copy
- **Low Create percentage (<10%)**: Steady-state operation where new files rarely appear
- **Create-dominated bursts**: Application installs, package staging, initial sync downloads

### Event 101 — File Modify

An existing file's content was changed. Each modify event represents one append, overwrite, or content update.

Typical patterns:
- **High Modify percentage (>50%)**: Active logging, database journaling, sync engines writing in chunks, application state updates
- **Modify with low Create**: Server applications writing to existing log files, surveillance state journaling, database writes
- **Single-file high-Modify count**: A file being written to repeatedly. The "Resilient Files" section of drill reports surfaces these.

### Event 102 — File Delete

A file or directory was removed.

Typical patterns:
- **High Delete percentage with high Create (both >30%)**: Heavy temp-file churn, cache validation, install/uninstall activity
- **Delete-dominated bursts**: Uninstall operations, cleanup passes, log rotation, recovery operations
- **Delete without earlier Create in same archive**: File existed before the archive's window began (normal)

### Event 103 — File Rename

A file or directory was renamed or moved.

Typical patterns:
- **High Rename in log directories**: Log file rotation (current → archived name pattern)
- **High Rename in temp directories**: Atomic-write patterns (write to temp, rename to final)
- **High Rename with high Create**: Build operations, package staging

### Event 104 — Security Change

File ACL, owner, or security descriptor changed.

Typical patterns:
- **Routine low-level (1–5%)**: Normal Windows operations setting attributes on new files
- **Elevated (>10%)**: Permission-management operations, install scripts setting ACLs, security software activity
- **Concentrated in one location**: Application-specific ACL management (e.g., installer setting permissions on its install directory)

### Event 105 — Other Change

Catch-all for USN reason flags not matching Create/Modify/Delete/Rename/Security. Includes:
- Attribute changes (read-only, hidden, system)
- Compression changes
- Encryption changes
- Hard link changes
- Indexable changes
- Integrity changes
- Named data overwrite, extend, truncation
- Object ID changes
- Reparse point changes
- Stream changes
- Transacted changes

**The Other Change percentage is one of the strongest workload-state fingerprints.**

Diagnostic interpretation:

- **>50% Other Change**: Active sync operation of some kind. Dropbox, OneDrive, Egnyte, backup, restore — any operation involving reparse points, alternate data streams, chunked writes, or named data manipulation. Identify which sync product by looking at directory talkers, not by Other Change percentage alone.

- **15–35% Other Change**: Moderate sync activity, mixed-workload machine, or applications using reparse points or alternate data streams as part of normal operation.

- **<15% Other Change**: Normal Windows file lifecycle without sync engines under load. Expected on idle or non-sync-heavy machines.

## Event mix patterns by workload type

### Sync engine active (Dropbox, OneDrive, etc.)
- Other Change: 40–65%
- Create + Modify: 30–50%
- Heavy concentration in sync-product directory
- Often spans multiple drives if sync target is on non-system drive

### Sync recovery / full re-sync
- Other Change: 55–65%
- Create: 25–35% (workspace being recreated)
- Delete: 5–10%
- Distinctive directory pattern: `(1)` suffix or doubled-name workspace appearing alongside original
- Sustained for hours rather than burst-shaped

### Application install / version upgrade
- Create: 60–80%
- Modify: 10–20%
- Other: 5–15%
- Concentrated in install directory and/or `WindowsApps\Deleted`
- Burst-shaped (typically minutes, not hours)
- Often multiple package versions visible simultaneously (new staged, old being cleaned)

### Active mail/log server processing
- Modify: 60–75%
- Create: 15–25%
- Heavy `.log` extension percentage (often >50%)
- Concentrated in service's logs directory
- Sustained rather than burst-shaped

### Surveillance / state-journaling application
- Modify: 90–100%
- Create: 0–5%
- Concentrated on a small number of state files
- Very high modify-per-file count on the state files (visible in Resilient Files section of drill)
- Sustained at consistent rate

### Initial dump (pre-engine journal accumulation)
- Mixed event types
- Spans dramatically longer than the archive's claimed window (days to weeks)
- High unresolved-path percentage (often >5%)
- Bare drive root entries appearing in top directory talkers (e.g., `C:` with no subdirectory)

### Idle background activity
- Mixed event types in approximately balanced percentages
- Low absolute counts
- Distributed across many small directories
- No single dominant talker

## Operational events (900s)

### Event 904 — Archive Written

Each completed rotation writes one 904 event. Use this as the authoritative signal for "engine successfully rotated an archive" — more reliable than the substring-based self-archive activity check (which has documented false positives).

Pattern interpretation:
- N archives in a series, N-1 archive-close events expected (the in-progress archive has not yet written its 904)
- If N archive-close events appear, all archives closed — investigate whether the in-progress one is actually closed or whether something unusual occurred
- If fewer than N-1 archive-close events appear, some rotations did not write 904 — investigate engine crashes or manual operations

### Event 914 — Engine Started

Each engine start writes one 914 event. The 914 event's `TimeCreated` field (in the Event Log System block, not the EventData) records the exact engine start time.

Pattern interpretation:
- First archive of a deployment will contain 914 as the first event (engine start triggered the archive's beginning)
- Multiple 914 events in one archive indicate engine restarts within the archive's window
- 914 timestamp matching the archive's `first_dt` within ~5 seconds indicates the engine was the source of the archive's beginning (initial dump signature, may need disclaimer)
- 914 timestamp later than the archive's `first_dt` indicates the channel contained pre-existing events (channel-not-cleared signature, see `CHANNEL_HYGIENE.md`)

### Other 900-range events (anomalies)

Specific anomaly event IDs in the 916, 918, 919, 922, 923, 925, 926 range indicate various engine-side issues. Any non-zero count in the self-integrity check's anomaly events line warrants investigation. The specific meanings are documented in the project's `EVENT_ID.md`.

When anomaly events appear:
- Document which event IDs fired and how many of each
- Cross-reference against `EVENT_ID.md` for specific cause
- Determine whether the anomaly is benign (e.g., 920 unsupported filesystem on a VM shared folder), procedural (e.g., engine restart sequence), or material (e.g., archive write failure)

## Device events (500s)

usnmon writes 500-range events when removable media or volume state changes. Per-event-ID meanings:

- 500 — Device NEW: previously unseen volume now visible
- 503 — Device REATTACHED: known volume reconnected after disconnection
- 504 — Device ALTERED: known volume's state changed (reformatted, repartitioned, label changed)
- 920 — Unsupported Filesystem: volume detected but not USN-capable (FAT32, exFAT, VMware shared folders)

Pattern interpretation:
- Many NEW + REATTACHED events: machine cycles removable media regularly (forensic VM analyzing evidence drives, photographer with SD cards, dev with USB drives)
- ALTERED events: drives being modified (cloned, wiped, reformatted) — common in forensic workflows
- Unsupported Filesystem: typically benign; engine correctly skips non-USN volumes

## Event ID anomalies worth investigating

The following patterns warrant deeper investigation when observed:

- **High unresolved path percentage (>5%)**: USN journal capture caught records before path resolution completed. May indicate initial dump, or engine catching up after a brief stall. Cross-reference with first_dt and engine start time.

- **Event 104 (Security Change) spiking in user-profile directories**: May indicate security policy reset, antivirus quarantining files, or genuine permission management. Drill to identify cause.

- **Event 102 (Delete) without corresponding 100 (Create) in the same archive at the same path**: File was created before the archive's window and deleted within it. Normal pattern. Notable only if the path is unexpected (e.g., a system file appearing as deleted without explanation).

- **Single-file modify counts in the tens of thousands**: A file being written to extremely frequently. Could be a database, log file, application state file. Identify which application is responsible via the file's path.

- **Identical event counts across multiple instances of similar paths**: Suggests deterministic automation rather than user-driven activity. See `LESSONS_LEARNED_to_avoid.md` for the user-attribution caution.

- **Event mix that does not match any documented archetype**: An unfamiliar workload. Investigate further before drawing conclusions.

## License and provenance

usnmon is a project of YASDC, licensed under PolyForm Noncommercial 1.0.0. This document is reference material for interpreting event ID patterns in usnmon output.
