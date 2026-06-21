v0.3 | 2026-06-20 | Source: usnmon project, YASDC | License: PolyForm Noncommercial 1.0.0

# DRILL_DECISION_TREE.md

## Purpose

This document describes when to use `usn_drill.py` for targeted investigation of `usn_stats.py` findings, how to construct effective filter files, and how to interpret drill output sections that do not appear in stats reports.

## When to drill

`usn_drill` is most valuable for these investigative goals:

### Investigative goal 1: Understand a dominant directory talker

If the top-25 directory list shows one path receiving more than 10–15% of all events, drilling that path reveals:
- Which specific files within the directory are being touched
- The lifecycle pattern of those files (Create + Delete pairs, persistent modifies, rename chains)
- The temporal concentration (sustained vs burst)
- Per-extension event mix within the scope

**Example trigger:** Office_Busybox shows `\Users\Kevin\KOE Dropbox` at 31.9% of all events. Drilling `\KOE Dropbox\` reveals whether this is normal sync activity, recovery, or workspace recreation.

### Investigative goal 2: Investigate a burst-flagged archive

If the comparison table shows `*BURST*` (any voting level) on an archive, drilling reveals:
- Which directory carried the burst events
- The exact minute(s) of concentration
- The file-lifecycle pattern during the burst
- Whether the burst was install, recovery, scan, or other

**Example trigger:** GoingPostal mail-isolation VM shows a 4-minute burst carrying 80% of events. Drilling with a broad AppData filter surfaces MailWasher Pro's initial-scan as the cause.

### Investigative goal 3: Identify an unknown application from a path

If a directory pattern in the top-25 talker list does not match any catalogued application in `APPLICATION_FINGERPRINTS.md`, drilling that path reveals:
- The specific filenames (often identifying the application)
- The file extension pattern (often distinctive per application)
- The temporal pattern (continuous, scheduled, on-demand)

### Investigative goal 4: Verify a hypothesis about correlated activity

If you suspect two patterns are correlated (e.g., "Teams burst coincided with Python install"), drilling with a filter capturing both:
- Confirms whether they occurred in the same minute
- Quantifies the concentration of each within the shared window
- Shows whether the activities are causally linked or coincidental

### Investigative goal 5: Examine a specific time window

If something happened at a known time (e.g., HDD chatter observed at 11:30 CDT) but the responsible application is unknown, drilling with a broad filter and examining the TEMPORAL section shows:
- The minute-by-minute event distribution during the window
- Which directories dominated during the peak minute(s)
- The lifecycle pattern of files touched during the window

## When NOT to drill

`usn_drill` is not always the right tool:

- **Don't drill to "see everything"** — `usn_stats` already shows everything at the archive level
- **Don't drill when integrity checks have failed** — fix the integrity issue first, then analyze
- **Don't drill across overlapping archives** — drill each separately and avoid double-counting
- **Don't drill without a clear hypothesis** — drilling produces detailed output that requires direction to interpret

## Filter file construction

`usn_drill` requires a filter file specifying which paths to include in the drilled scope. The filter file syntax accepts directory substrings, one per line.

### Strict directory matching

Each line should end with `\` to indicate strict directory boundary matching. This prevents accidental substring collisions:

```
\Blue Iris\
\Dell\TrustedDevice\
\KOE Dropbox\
```

This matches `\Blue Iris\temp\camera1.xml` but not `\BlueIrisAlt\something\` (the trailing `\` enforces the directory boundary).

### Substring matching (prefix patterns)

A planned enhancement allows section-headered filter files that distinguish strict directory matching from prefix-based substring matching:

```
[directories]
\Blue Iris\
\Dell\

[prefixes]
\MSTeams_
\Mozilla-
```

`[directories]` keeps the strict trailing-`\` rule. `[prefixes]` allows substring matches without requiring the trailing `\`. This is useful for matching versioned-package paths where the version suffix varies.

Until this enhancement ships, use multi-line strict-directory entries that cover the version variations explicitly.

### Choosing filter breadth

**Too narrow:** Single specific directory. Misses related activity in nearby directories that may be relevant.

**Too broad:** Drive-letter root or AppData root. Captures so much that the drill becomes another stats report rather than a focused investigation.

**Effective:** Multiple related paths that share an investigative subject. For example, to investigate Dropbox activity comprehensively:

```
\Users\Kevin\Dropbox\
\Users\Kevin\KOE Dropbox\
\Users\Kevin\HAPA, LLC\
\Program Files\Dropbox\
\Users\Kevin\AppData\Local\Dropbox\
```

This captures all known Dropbox-related paths on the specific machine without including unrelated activity.

## Drill report sections worth understanding

### FILTER SCOPE

Reports how many events fell within the filter and what percentage of the archive's total events this represents. If the percentage is very low, the filter may be too narrow; if very high, the filter may be too broad to be useful.

### EVENT-ID FREQUENCY (filtered scope)

Shows the event mix within the drilled scope. Compare against the archive-wide event mix from the stats report. Significant differences indicate the drilled application has a distinctive workload pattern.

### TOP 25 DIRECTORIES (full depth, filtered scope)

Unlike `usn_stats` which rolls up at depth 4, the drill report shows directories at full depth within scope. This reveals the application's actual subdirectory structure and which subdirectories receive the most activity.

### TOP 25 FILE EXTENSIONS (filtered scope) with event-type mix

Beyond raw extension counts, this section shows the Create/Modify/Delete/Rename/Security/Other percentage per extension. This reveals lifecycle patterns:

- `.log` at 100% Modify = log files being appended to (typical logging behavior)
- `.tmp` at 70% Create / 25% Rename = atomic-write pattern (temp file created, content written, renamed to final)
- `.bin` at 56% Rename / 28% Delete / 17% Modify = file lifecycle with significant renaming (could indicate batch processing or moves)

### FILENAME PATTERN ANALYSIS (filtered scope)

Categorizes filenames by structural pattern:

- `plain`: standard filenames
- `hex40 (sha1-like)`: 40-character hex strings (often hashes or content-addressed storage)
- `sequential number`: numeric filenames (often sequence-based caching or log segments)
- `guid`: UUID-format filenames (often session-scoped or content-addressed storage)
- `date-like`: timestamped filenames (often log rotation)
- `hex32 (md5-like)`, `hex64 (sha256-like)`: other hash-like filenames
- `epoch-like`: Unix timestamp filenames

The pattern distribution often identifies what kind of application is writing the files. Cache directories typically heavy on hash-like patterns. Log directories typically heavy on date-like or sequential patterns. Browser storage typically mixed plain + hash.

### FILE LIFETIME ANALYSIS (filtered scope)

For files seen with Create events and subsequent Delete events, reports:
- Count of persistent files (Created but not Deleted within scope)
- Count of pre-existing files (Deleted but not Created within scope — existed before the archive's window)
- Count of transient files (Create and Delete both within scope)
- Lifetime statistics for transient files (min, median, mean, max)
- Top 25 fastest-cycling files

**Diagnostic interpretation:**
- Many 0-millisecond Create-Delete pairs = atomic write or temp file validation pattern (typical of Chromium-engine cache, build operations, transactional database commits)
- Long-lived transient files = staged operations that complete eventually
- High persistent count = workspace creation or population

### RESILIENT FILES (modified 2+ times within scope)

Lists files that receive multiple modify events. The top of this list identifies which specific files within the drilled scope are receiving sustained write activity. Often the single most identifying signature of an application.

For example, MailWasher Pro's resilient files list begins with `MWPapi.log` (master API log, ~30,000+ modifies) followed by per-mailbox logs in clear ranking. This single section essentially documents the application's mail account inventory.

### TEMPORAL ACTIVITY (filtered scope)

Same temporal analysis as `usn_stats` but scoped to filtered events:
- Active minutes (count of minutes with any in-scope events)
- Busiest minute (and event count)
- Mean events per active minute (and sigma)
- Burst minutes (defined as >3x mean OR >mean+2sigma)
- Busiest hour

When the operator has identified a known event time and wants to confirm/explain it, the temporal section against an appropriately broad filter pinpoints the moment(s).

### PER-INSTANCE INFERENCE

Attempts to detect cam/camera/stream/channel/instance-numbered patterns in filenames. Designed for surveillance applications with per-camera streams. Currently catches standard `cam1`, `camera2`, `channel3` patterns; misses applications using directional naming (`north_2`, `south_3`).

## Interpretation workflow

When you receive a drill report, read in this order:

1. **FILTER SCOPE** — Is the scope appropriate? Too narrow or too broad means re-run with adjusted filter.
2. **TOP 25 DIRECTORIES** — Which specific subdirectories carry the activity? Often clarifies the responsible application substantially.
3. **TOP 25 EXTENSIONS with event mix** — What kind of file operations dominate? Log appends, atomic writes, hash-content storage?
4. **RESILIENT FILES** — Which specific files receive the most modifies? Often the single most identifying signature.
5. **FILE LIFETIME ANALYSIS** — Is this transient atomic-write activity or persistent file lifecycle?
6. **TEMPORAL ACTIVITY** — Is the activity sustained or burst? When did the bursts occur?
7. **FILENAME PATTERN ANALYSIS** — Does the pattern distribution match any catalogued application's expected pattern?

## Common drill patterns

### Pattern A: "What is this dominant directory?"

Filter: the unknown directory's path
Read: TOP 25 DIRECTORIES (subpaths), RESILIENT FILES (filenames), FILENAME PATTERN ANALYSIS
Goal: Identify the application

### Pattern B: "What caused this burst?"

Filter: broad enough to capture the burst (e.g., entire AppData)
Read: TEMPORAL ACTIVITY (find burst minute), TOP 25 DIRECTORIES (what dominated), RESILIENT FILES (which specific files)
Goal: Identify the activity and its cause

### Pattern C: "What is the lifecycle of this application?"

Filter: the application's known paths
Read: EVENT-ID FREQUENCY, FILE LIFETIME ANALYSIS, RESILIENT FILES, TEMPORAL ACTIVITY
Goal: Characterize the application's normal operating pattern for baseline reference

### Pattern D: "Verify a hypothesis about correlated activity"

Filter: paths for both suspected correlated activities
Read: TEMPORAL ACTIVITY (do they share a minute?), TOP 25 DIRECTORIES (which dominated, which was secondary)
Goal: Confirm or refute hypothesized correlation

## License and provenance

usnmon is a project of YASDC, licensed under PolyForm Noncommercial 1.0.0. This document is reference material for effective use of `usn_drill.py` in usnmon analysis.
