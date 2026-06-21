v0.3 | 2026-06-20 | Source: usnmon project, YASDC | License: PolyForm Noncommercial 1.0.0

# INTEGRITY_VERIFICATION.md

## Purpose

This document describes checks an investigator should run BEFORE interpreting any usnmon output. The principle: data analyzed from an untrusted source produces conclusions that should not be trusted. Establish trust first, interpret second.

If any check fails, do not proceed with analysis until the failure is explained.

## What integrity verification establishes

- The archive set is complete and chronologically continuous
- The captured content matches the filenames' claimed time windows
- The engine was operational throughout the claimed capture period
- No tampering or unaccounted procedural artifacts are present
- The integrity checks themselves are returning real signals, not known false positives

## Check sequence

Run these in order. Each builds on the previous.

### 1. Archive count expectation

Determine how many archives the operator's configured rotation cadence should have produced over the claimed capture period.

Example: 12-hour rotation cadence, 7-day capture window → expect 14 archives.

If the actual count differs significantly, ask:
- Was usnmon stopped during part of the window?
- Were archives deleted, moved, or copied between collection points?
- Was the rotation cadence changed mid-window?

The integrity check in `usn_stats` reports archive count in the SERIES OVERVIEW. Compare against expectation.

### 2. Coverage continuity

`usn_stats` series mode checks whether consecutive archives chain within a 60-second tolerance. Reported as:

```
Coverage continuity   : OK  (N archives chain within 60s tolerance)
```

Or:

```
Coverage continuity   : N break(s) detected at:
   between archive A and archive B (gap: X minutes)
```

A break means the time between one archive's last event and the next archive's first event exceeds 60 seconds. Possible causes:
- Engine was stopped between archives (intentional or not)
- Machine was powered off or sleeping during the gap
- Archive set is incomplete (some archives missing from the directory analyzed)
- Rotation cadence allowed a true quiet window with no events

Distinguish these by checking the operational events (914 Engine Started, 904 Archive Written) around the break time.

### 3. Engine restart count

Reported as:

```
Engine restarts       : N event(s) across M archive(s)
   <archive name>  (K x 914)
```

Each restart is a 914 (Engine Started) event. Expected counts:
- Single archive with no restart: 0 events (unless capture period began at engine start)
- Single archive at engine start: 1 event (the start that began the archive)
- Series spanning a manual restart: 2 events (stop, start)
- Multiple restarts during development testing: many events

Unexpected restart counts warrant investigation. A high count without operator explanation may indicate:
- Engine crashes (check for anomaly events 919, 922, 923, 925, 926)
- Service-stop hangs leading to force-kill recovery
- Power events the machine experienced
- Operator-driven version testing

### 4. Archive-close events

Reported as:

```
Archive-close events  : N of M  (one in-progress archive: <name>)
```

Each completed archive should have a 904 (Archive Written) event. The in-progress archive (the one currently being captured) will not yet have its 904 — that fires when rotation closes the archive.

If the count of 904 events is less than expected (excluding the in-progress one), some archives closed without writing the 904 event. Possible causes:
- Engine crashed during rotation
- Channel was manually exported without proper rotation
- Archive was manually copied or hand-collected outside normal rotation

### 5. Self-archive activity (with known false-positive caveat)

Reported as:

```
Self-archive activity : N/M archives show 'FileSystem_Archives' writes
```

The check searches for activity in directories matching `FileSystem_Archives` (the default archive output location). Activity here confirms the engine was writing its archives to disk.

**Known false-positive case (confirmed in production):** the check uses depth-4 directory rollup with a top-5,000 distinct-directories cap. If the archive directory had low write count in a given archive and was evicted from the top-25 directory talkers, the check may report "silent" even though the engine was operational.

**Confirmed in Office_Busybox v0.0.8a production capture:** A 2-archive 24-hour clean baseline showed `0/2 archives show 'FileSystem_Archives' writes (2 silent)` while both archives contained valid 904 (Archive Written) events. This is the textbook false-positive case — both archives were properly rotated and sealed; the substring search just didn't find FileSystem_Archives in the top-25 directory rollup because activity was below the eviction threshold.

**To verify externally:**
- Check whether the actual archive `.zip` files exist in the expected directory with modified times matching the rotation boundaries
- Check whether each archive contains 904 (Archive Written) events directly
- If both confirm engine operation, treat the "silent" flag as a known false-positive

A planned analyzer fix (TODO item in v0.0.8b queue) replaces the substring search with direct 904 event counting, eliminating this false positive.

### 6. Anomaly events

Reported as:

```
Anomaly events        : none (916/918/919/922/923/925/926 all 0)
```

Or specific anomaly event ID counts. Any non-zero count in this list warrants investigation. See `EVENT_ID_ANOMALIES.md` for what each anomaly event indicates.

### 7. Filename vs. content time-range comparison

This check is not yet automated but should be performed manually until it is:

For each archive file, compare:
- The filename's claimed time range (e.g., `FileSystem_2026-06-18-110950_to_2026-06-18-230955.evtx` claims 11:09:50 to 23:09:55)
- The archive's actual log_start and log_end UtcTime values

A significant mismatch indicates the channel was not cleared between sessions and accumulated events from outside the filename's claimed window. See `CHANNEL_HYGIENE.md` for what this signature means and how to interpret it.

## When integrity checks pass

All six checks clean: proceed with analysis. The data can be trusted to represent what it claims to represent.

## When integrity checks fire

Stop and resolve before analysis. Determine whether each fired check is:
- A genuine failure indicating data unreliability
- A known false-positive (per the documented cases above)
- A procedural artifact (stop/start cycle, manual collection, deploy-time activity)

Do not interpret rate calculations, top talkers, or anomaly events from an archive set whose integrity is unverified or known-failed. The risk is reaching analytical conclusions about data that does not represent what it claims to.

## Forensic chain of custody (when applicable)

For investigations where the archive set will be presented as evidence:

- Hash each archive file at collection time (SHA-256 recommended)
- Record collection timestamp, collecting operator, collection machine
- Verify hashes have not changed between collection and analysis
- Document any manual operations performed (export, copy, rename, recompress)
- Preserve original archives separately from working copies

If hashes do not match between collection and analysis, the working copy has been altered. This may be benign (recompression, format conversion) or material (tampering). Investigate before drawing analytical conclusions.

## What to do when a check fires unexpectedly

Document what fired, what you investigated, and what you concluded. The integrity check output is part of the analytical record. A "checks passed" claim is not credible without showing which checks were run and what they returned.

If a check fires in a way that does not match any documented case in this primer or its companion documents, that itself is a finding worth recording. The integrity check has documented false positives; the documentation of those false positives may itself be incomplete.

## License and provenance

usnmon is a project of YASDC, licensed under PolyForm Noncommercial 1.0.0. This document is reference material for investigators verifying usnmon archive integrity before analysis.
