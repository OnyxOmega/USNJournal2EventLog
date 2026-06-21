v0.3 | 2026-06-20 | Source: usnmon project, YASDC | License: PolyForm Noncommercial 1.0.0

# CHANNEL_HYGIENE.md

## Purpose

This document describes how the Windows Event Log channel (`FileSystem`) is managed during usnmon operation, what happens when channel state is disturbed outside normal rotation, and how to interpret signatures that indicate the channel was not cleared between sessions.

## How usnmon manages the channel

usnmon writes USN journal events into the Windows Event Log channel named `FileSystem`. At configured rotation intervals, the engine:

1. Exports the current channel content to an `.evtx` file
2. Packages it into a compressed `.zip` archive bundle
3. Clears the channel
4. Continues capturing new events into the cleared channel

This export-and-clear cycle is atomic. Properly-rotated consecutive archives do not overlap; each archive captures only its claimed time window's events.

## When channel hygiene is disturbed

Normal rotation preserves channel hygiene. Channel state is disturbed when:

- usnmon is stopped manually (channel retains accumulated events until next start)
- usnmon is restarted (the next archive will include events accumulated since last rotation, including pre-restart events)
- An operator manually exports the channel via `wevtutil epl` without clearing
- An operator manually clears the channel via `wevtutil cl` (creates a gap)
- An investigator collects a snapshot during a stop period
- Engine crashes prevent clean rotation
- Multiple engine versions are tested in sequence without channel clears between

In each case, the resulting archive set may contain content that does not match what its filenames claim. This is a procedural artifact, not necessarily tampering, but it must be recognized and accounted for during analysis.

## Best practice procedures

### Standard rotation (no operator intervention)

Let usnmon's normal rotation cadence handle everything. Do not manually export or clear the channel. The engine's export-and-clear cycle is the trustworthy path.

### Planned stop/start cycle (e.g., engine upgrade)

1. Allow the current rotation to complete (or accept that the current archive will include partial data)
2. Stop the engine: `usnmon stop`
3. Export remaining channel content to a snapshot file:
   ```
   wevtutil epl FileSystem <snapshot_path>.evtx /q:"*"
   ```
4. Clear the channel:
   ```
   wevtutil cl FileSystem
   ```
5. Start the new engine version: `usnmon start`

After this procedure, the new engine begins with a clean channel and the snapshot file preserves the pre-stop content as a separate artifact.

### Investigation snapshot (engine continues running)

If an investigator needs a snapshot of current channel content without stopping the engine:

1. Export without clearing:
   ```
   wevtutil epl FileSystem <snapshot_path>.evtx /q:"*"
   ```
2. The snapshot captures events accumulated since the last rotation
3. Engine continues normal rotation; the next archive will include the same events that are in the snapshot (overlap)
4. Document that the snapshot was collected so the overlap is expected, not anomalous

### Unintentional disturbance recovery

If a manual export was performed and the channel was not subsequently cleared, the next normal rotation will include the previously-exported content. This is the most common cause of filename-vs-content mismatches. To recover cleanly:

1. Wait for the next normal rotation to complete
2. The resulting archive will contain a longer-than-claimed time range
3. Note this in the analytical record
4. Subsequent rotations resume normal hygiene

## Filename vs. content mismatch — what it indicates

Each archive file has two time-range claims:

- **Filename time range:** Derived from the rotation logic at archive-write time. Encoded in the filename pattern (e.g., `FileSystem_2026-06-18-110950_to_2026-06-18-230955.evtx`).
- **Content time range:** Derived from the earliest and latest event UtcTimes actually present in the archive.

When these match (within the typical few seconds of rotation latency), the archive is hygienically clean: it contains the events from its claimed window.

When the content range significantly exceeds the filename range — particularly when the content reaches back hours or days before the filename's start time — the channel was not cleared between sessions. The archive contains accumulated events from prior sessions.

## What overlap does and does not mean

When the same machine appears across multiple archive captures and identical event counts appear in identical paths across captures, the channel was not cleared between sessions. This is a procedural signature: someone interacted with the channel outside normal rotation.

Possible explanations, equally consistent with the observed data:

- System administrator pulled a snapshot for capacity check, troubleshooting, or routine inspection
- Investigator collected an interim snapshot during an active case (correctly preserving the channel state)
- Standard operating procedure intentionally avoided manual clearing (correct discipline)
- Operator oversight during a deploy or update cycle
- Tampering attempt that left the overlap as a tell

The data confirms the channel was disturbed outside normal rotation. The data does NOT confirm who disturbed it or why. Interpretation requires context the journal alone cannot provide.

When you observe overlap or filename-content mismatch:
- Note it in the analytical record
- Do not conclude tampering without corroborating evidence
- Compute analytical rates using only the non-overlapping span
- Do not analyze the same events twice (sanity-check duplicates: identical event counts in identical paths across captures indicate overlap, not new occurrence)

## Sanity-check duplicates pattern

When analyzing multiple captures from the same machine, compare:

- `first_dt` and `last_dt` across captures — if a new capture's `first_dt` matches an earlier capture's `first_dt`, the channel still contains old data
- Per-directory event counts — identical counts at identical paths between captures indicates overlap

Rate calculations on overlapping archives are unreliable for steady-state characterization of the machine. Compute rates from only the non-overlapping portion. For example, if Archive 2 starts at the same first_dt as Archive 1 but extends to a later last_dt, the actual new period is Archive 2's last_dt minus Archive 1's last_dt — and the actual new events are those in Archive 2 not present in Archive 1.

## Anti-tampering posture (without overclaiming)

Channel hygiene patterns can be a tell for evidence tampering, but they are not specifically a tampering signature. A skilled adversary would clear the channel after manual access to avoid leaving overlap. An oversight or routine procedure would leave overlap as an unintentional tell.

Investigators should:

- Document observed channel hygiene patterns
- Consider tampering as one of several possible explanations
- Look for additional indicators that distinguish accidental from intentional disturbance:
  - Byte-identical overlap content suggests clean stop/start (low tampering concern)
  - Events differ within the overlap window (potential tampering signal, investigate)
  - Filename time range badly disagrees with embedded UTC times (likely renamed file or sloppy collection)
  - Anomaly events around the overlap boundary (potential interference with engine, investigate)
- Reserve judgment until corroborating evidence is examined

## Operational discipline summary

- Trust the data more when normal rotation produced it without operator intervention
- Trust the data less when manual exports, clears, or stops were performed
- Always prefer letting usnmon's rotation handle channel clears (the engine does it atomically)
- Avoid manual `wevtutil cl FileSystem` operations during active monitoring — they create gaps that look worse than overlap
- Document every manual operation performed on the channel as part of the analytical record
- When in doubt about a hygiene-disturbed archive set, treat the data as a snapshot for interpretation rather than as continuous steady-state characterization

## License and provenance

usnmon is a project of YASDC, licensed under PolyForm Noncommercial 1.0.0. This document is reference material for investigators understanding and verifying channel state during usnmon operation.
