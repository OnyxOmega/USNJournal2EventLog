v0.3 | 2026-06-20 | Source: usnmon project, YASDC | License: PolyForm Noncommercial 1.0.0

# INVESTIGATOR_PRIMER.md

## What this document is

This is the entry-point reference for analyzing output from `usnmon`, a Windows forensic monitoring tool that captures NTFS USN Journal events into Windows Event Log archives. If you are an AI or investigator reading this for the first time, start here.

This primer establishes the analytical mindset. Specific reference material lives in companion documents in this same directory (`docs/primer/`):

- `INTEGRITY_VERIFICATION.md` — trust-the-data checks (run BEFORE analysis)
- `CHANNEL_HYGIENE.md` — channel-clear procedures, filename-vs-content mismatches, what overlap means
- `EVENT_ID_ANOMALIES.md` — specific event ID patterns and their interpretations
- `APPLICATION_FINGERPRINTS.md` — observed signatures of common applications
- `WORKLOAD_ARCHETYPES.md` — typical machine-class baseline characterizations
- `LESSONS_LEARNED_to_avoid.md` — misattribution traps and verification protocols
- `DRILL_DECISION_TREE.md` — when to drill, how to construct filters, how to read drill output

## What usnmon is and is not

usnmon is a continuous Windows file activity monitor. It writes USN Journal entries into a Windows Event Log channel (`FileSystem`), then rotates that channel into archived `.evtx` files at a configured cadence. Two companion tools analyze the archives:

- `usn_stats.py` produces single-archive or multi-archive series reports
- `usn_drill.py` produces filtered drill-down reports scoped to specific directories or patterns

usnmon captures **file-altering operations**: Create, Modify, Delete, Rename, Security/Attribute changes, and miscellaneous "Other Change" events. It does **not** capture file reads. Read-heavy disk activity (antivirus scans, search indexing, cache validation) does NOT appear in usnmon output. When observed disk activity exceeds what usnmon shows, the gap is read activity.

## Core mindset for analysis

**Trust the data before interpreting it.** Run integrity checks first. See `INTEGRITY_VERIFICATION.md`. An archive with broken continuity, missing rotation events, or filename-content mismatch is unreliable for analysis until those issues are explained.

**Verify before asserting.** Do not state what an application is doing, what a command syntax is, or what a Windows mechanism does without checking. If you find yourself producing a confident-sounding claim from pattern-matching or memory, stop and verify — read the actual source file, check the actual directory listing, run the actual command. See `LESSONS_LEARNED_to_avoid.md` for documented cases where assertion-from-memory failed.

**Activity in user-profile directories is not user activity.** Modern Windows runs many background services that write to `\Users\<name>\AppData\` without the user doing anything. Browsers, sync engines, telemetry agents, Microsoft Store servicing, WSL background services — all write to user profiles continuously. Do NOT conclude "user X did Y at time T" from USN journal activity alone. Corroborating evidence required: logon events, application logs, network traces, file content consistent with claimed action. See `LESSONS_LEARNED_to_avoid.md` for the thirteen misattribution patterns documented across multiple captures.

**Verify operator-stated infrastructure beliefs.** When an operator describes their system configuration (drive layout, folder relocation, software inventory), treat the description as a hypothesis to test, not as authoritative truth. Operator mental models of their own systems may be incomplete or outdated. Verify against actual registry, filesystem, or configuration data before incorporating into analysis. See `LESSONS_LEARNED_to_avoid.md` Trap 11.

**Verify forensic-artifact-producing settings ARE ENABLED before treating absence of artifacts as evidence of inactivity.** Modern Windows includes operator-configurable privacy settings that suppress forensic artifacts without requiring specialized anti-forensics tools. Specifically: `Start_TrackDocs` controls whether Recent\AutomaticDestinations files update at all. When disabled, absence of Recent\ updates is meaningless for user-activity attribution. See `LESSONS_LEARNED_to_avoid.md` Trap 10.

**Event count is not disk volume.** A USN record describes one change to one file's metadata. The actual data change can be zero bytes (security/attribute change) or many gigabytes (modify event on a large file rewritten end-to-end). Use event count for activity pattern characterization. Do not use it for estimating actual disk I/O load.

**Background activity dominates modern Windows.** A genuinely idle modern Windows machine produces roughly 1,000 records/hour purely from operating system background services. See `WORKLOAD_ARCHETYPES.md` for observed baseline floors. Activity above the floor is the "interesting" portion; activity at or near the floor is the OS itself doing its work.

## How to read a usn_stats output

The output has a consistent structure. Read it in this order:

**1. SERIES OVERVIEW / RUN section.** Records the time window, total events, rate per hour, archive size. The headline rate (records/hour, MB/hour) is the first signal but may be misleading — see Burst detection below.

**2. SELF-INTEGRITY CHECK.** Coverage continuity, engine restart count, archive-close events, self-archive activity verification, anomaly events. If anything here is flagged, address it before interpreting any other section. The check has known false-positive cases (see `INTEGRITY_VERIFICATION.md`).

**3. EVENT-ID FREQUENCY.** The mix of Create/Modify/Delete/Rename/Security/Other tells you what kind of workload this is. See `EVENT_ID_ANOMALIES.md` for interpretation patterns. Event 105 (Other Change) percentage is particularly diagnostic.

**4. SERIES BY VOLUME.** Distribution across drive letters. Concentration on one drive often points to the dominant application's storage location.

**5. TOP 25 DIRECTORY TALKERS.** The dominant write locations. Each path is a clue to which application is responsible. See `APPLICATION_FINGERPRINTS.md` to identify common signatures.

**6. TOP FILE EXTENSIONS.** Helps distinguish workload types (log-heavy server, media-heavy storage, sync-heavy workspace, package-staging install).

**7. SESSION INFERENCE.** Detection patterns for browser activity, WSL sessions, RDP, PSReadLine. Note the caveats in `LESSONS_LEARNED_to_avoid.md` — these patterns detect activity in user-profile paths but cannot distinguish user-driven from background.

**8. PER-ARCHIVE COMPARISON TABLE (series mode).** Shows individual archive rates and flagged anomalies. The `*BURST*` flag (with single/multi/sigma-based criteria) marks archives where the rate is misleading because activity is concentrated in a short window.

**9. PER-ARCHIVE DETAIL.** Full statistics per archive. Use when an archive in the comparison table needs investigation.

## Burst detection — why headline rates can lie

A single-archive headline rate of "33,000 records/hour" can mean:
- Sustained 33,000 records/hour across the entire window (true high-activity workload)
- 90% of records in a 4-minute window, then quiet (initial application scan, install burst, recovery operation)
- Mixed pattern across multiple bursts and quiet periods

The `*BURST*` flag in the comparison table identifies archives where this matters. Voting model:
- 1 of 3 detectors → `*?BURST*` (possible)
- 2 of 3 detectors → `*BURST*` (likely)
- 3 of 3 detectors → `*BURST!!*` (strong)

When you see a burst flag, the headline rate is NOT representative of steady-state operation. Look at the temporal section to find when the burst occurred and `usn_drill` against the dominant directory in that window to identify the cause.

## When to drill

Use `usn_drill.py` when:
- The top-25 directory talkers point at a single application and you want deeper detail on its specific activity
- A burst flag indicates a time-concentrated event you need to understand
- An anomaly in the integrity check needs investigation
- You suspect a specific application's behavior and want its file-lifecycle pattern

See `DRILL_DECISION_TREE.md` for filter file construction and drill output interpretation.

## What to do when uncertain

If you cannot identify what an application is doing from the path alone, check `APPLICATION_FINGERPRINTS.md`. If the application is not catalogued there, do NOT guess. State that the activity is unidentified and recommend further investigation rather than asserting a tentative identification as fact.

If you cannot tell whether activity is user-driven or background, default to background unless corroborated. Modern Windows produces far more background activity than user activity. See `LESSONS_LEARNED_to_avoid.md` for the specific misattribution traps.

If integrity checks fire and the cause is unclear, do not analyze further until you have verified whether the alerts are real failures or false positives. The check has documented false-positive modes (notably the FileSystem_Archives detection's depth-4 truncation issue — see `INTEGRITY_VERIFICATION.md`).

## License and provenance

usnmon is a project of YASDC, licensed under PolyForm Noncommercial 1.0.0. This primer and companion documents are reference material for investigators using usnmon output. They describe analytical patterns derived from observed real-world captures. Patterns may not generalize to all environments. New environments warrant new baselining before analysis assumptions are locked in.
