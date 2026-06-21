# Changelog

All notable changes to usnmon are recorded here.

## v0.0.8a

Dead-code cleanup pass. Three orphaned items removed; zero behavior change. This is
the first of several maintenance releases (planned v0.0.8a–v0.0.8e) to address
redundancy findings without touching feature behavior.

### Removed (zero risk — all confirmed unreferenced)

- **`_evtx_time_bounds` and its nested `_iter_xml`** (~44 lines). Written in v0.0.7c
  to introspect exported evtx files for first/last record `SystemTime` values, used
  by the original v0.0.7c `archive_one` to name archives by their record contents.
  v0.0.8 reversed that naming policy (filename now reflects the rotation window from
  `rotation_anchor`, not the records inside), and `archive_one` was rewritten to no
  longer call this helper. The function was left in place during the v0.0.8 refactor
  but is no longer reachable from anywhere in the codebase.
- **`_month_year_tag(when=None)`** (~8 lines). Generated the `"June_2026"` style tag
  used by the original v0.0.7 calendar-bucket archive naming. Superseded by direct
  `strftime` calls inside `_archive_basename`. No remaining callers.
- **Orphaned `_next_month_counter` function body** (~15 lines). The `def` line was
  removed during the v0.0.7c → v0.0.8 refactor but the body was accidentally left
  behind, attached to the end of `_current_rotation_window_start` as unreachable
  module-scope code (its `return` was after the live function's own `return None`).
  Compiled but never executed; referenced variables that didn't exist in scope.

### Why this matters

These three items together account for ~67 lines of dead code that survived the
v0.0.7c → v0.0.8 refactoring. The `_next_month_counter` orphan in particular shows
that a multi-step refactor can leave true garbage in the file. Worth flagging that
the workflow for future refactors should grep for orphaned references at the end,
not just verify the new code compiles.

### Verified

All v0.0.8 functionality intact post-cleanup:
- `parse_timeperiod` (rotation + retention units, m/M case-sense)
- `_period_advance` calendar math + leap-day clamping
- `_next_rotation_boundary` (ramp-in close + clean cycle close)
- `_archive_basename` (MonthName form for full calendar months, span otherwise)
- `_parse_anchor` round-trip
- `_current_rotation_window_start` calendar/interval dispatch

## v0.0.8

Substantive consolidation pass: unified time-period parsing, calendar-aware rotation
math, and a persistent rotation-state machine that handles restart, gap, size-cap
split, and clock anomaly cases explicitly. This is a behavior change from v0.0.7c
and a config-schema extension (two new fields: `engine_start_anchor`, `rotation_anchor`).

### Rotation-boundary rule (locked v0.0.8)

For any calendar `nU` rotation (units `d`/`w`/`M`/`y`):

- **First archive after fresh install / mode change** is the partial ramp-in: anchor
  → next U-boundary. Contains the leading partial unit only.
- **Every subsequent archive** is a clean n-unit window: previous close + n calendar
  U-units.

Worked example, anchor June 17 2026 14:30:

| Spec | 1st close | 1st contents | 2nd close | Subsequent rhythm |
|---|---|---|---|---|
| `1d` | June 18 00:00 | partial June 17 | June 19 | daily at midnight |
| `2d` | June 18 00:00 | partial June 17 | June 20 | every 2 days |
| `1M` | July 1 | partial June | Aug 1 | monthly on 1st |
| `2M` | July 1 | partial June | Sept 1 | every 2 months on 1st |
| `3M` | July 1 | partial June | Oct 1 | every 3 months on 1st |
| `1y` | Jan 1 2027 | partial 2026 | Jan 1 2028 | annually |
| `2y` | Jan 1 2027 | partial 2026 | Jan 1 2029 | every 2 years on Jan 1 |

The first ramp-in archive is shorter than the configured cadence, which is a clean
forensic signal: "monitoring anchored here under this configuration, and the cadence
settled into n-unit chunks afterward."

For interval units (`s`/`m`/`h`/`t`), no boundaries exist; the next close is simply
anchor + (n × unit-seconds), with no ramp-in concept.

### Unit semantics — substitution principle

Every `<n><unit>` time-period in usnmon now obeys a single unit table:

| Unit | Meaning | Kind |
|---|---|---|
| `s` | seconds, fixed interval from anchor | interval |
| `m` | minutes, fixed interval from anchor | interval |
| `h` | hours, fixed interval from anchor | interval |
| `d` | **calendar days** (midnight-to-midnight) | calendar |
| `w` | **calendar weeks** (Monday 00:00 ISO 8601 to next Monday) | calendar |
| `t` | 30-day terms (fixed 30 × 86400s interval) | interval |
| `M` | **calendar months** (next 1st 00:00, leap-aware) | calendar |
| `y` | **calendar years** (next Jan 1 00:00) | calendar |

Case-significant on `m` vs `M`: `m`=minutes, `M`=calendar months. This is the **only**
case-sensitive distinction; everything else is lower-case.

The substitution principle gives every flexibility cleanly:
- "Calendar week" = `1w`. "Every 7 days from start" = `7d`.
- "Calendar month" = `1M`. "Every 30 days" = `1t`. "Every 31 days" = `31d`.
- "Calendar year" = `1y`. "Every 365 days" = `365d`.

### BREAKING changes from v0.0.7c

- **`--log-interval 1d` and `1w` now mean CALENDAR boundaries** (midnight-to-midnight
  and Monday-to-Monday respectively), where they previously meant fixed `86400s` and
  `604800s` intervals. To preserve the old "24h from when you started" behavior,
  switch to `24h` and `168h` (or `7d` for the 7-day-fixed which is now distinct from
  `1w` calendar).
- **`--legal-retention 18m` no longer works.** Use `18M` (capital `M` = calendar
  months) instead. The `m`-as-minutes is global (and minutes don't make sense for
  retention), so the bad-input fail-safe applies: a stale `legal_retention: "18m"`
  config now parses to `None` = keep-everything-forever. **No silent deletion** — but
  the user must migrate the spec to `18M` to restore the intended retention behavior.
- **`parse_interval()` now returns `(n, unit)` tuple**, not float-seconds. All callers
  in this codebase are updated; any external scripts importing this function need
  to migrate.

### Consolidation: one parser for two systems

Both rotation and retention go through one `parse_timeperiod(text, caps_table)` with
a per-use-case `ROTATION_CAPS` or `RETENTION_CAPS` dict. The two callers share unit
semantics, regex, magnitude validation, and calendar-vs-interval dispatch via
`_period_advance(dt, n, unit, direction)`. Removed:
- `_INTERVAL_UNITS` (folded into `_TIMEPERIOD_UNITS`)
- `_RETENTION_UNIT_CHARS` (no longer needed)
- `_RETENTION_MAX_N` (replaced by per-unit caps in `RETENTION_CAPS`)
- The old `_retention_horizon`'s unit-special-case logic (now one line through
  `_period_advance`)

### Per-unit sanity caps (`ROTATION_CAPS`, `RETENTION_CAPS`)

| Unit | Rotation cap | Retention cap |
|---|---|---|
| `s` | 172,800 (2 days) | not allowed |
| `m` | 2,880 (2 days) | not allowed |
| `h` | 336 (2 weeks) | not allowed |
| `d` | 180 (~6 months) | 3,650 (10y) |
| `w` | 52 (1 year) | 520 (10y) |
| `t` | 12 (~1 year) | 120 (10y) |
| `M` | 12 (1 year) | 300 (25y) |
| `y` | 1 | 25 |

Retention `M`/`y` push to 25 years to cover real-world long-horizon mandates (e.g.
pediatric medical-records retention — age-of-majority + 3y = 21y in many US states).

### Persistent rotation state machine

Three persisted anchor fields drive the rotation logic:

| Field | Set when | Forensic meaning |
|---|---|---|
| `install_month` | First install ever (unchanged) | Box has been monitored since this month |
| `engine_start_anchor` | Every engine start (NEW) | This session began at this exact time |
| `rotation_anchor` | Every successful archive close (NEW) | The current rotation window opened at this time; persisted as the "end of last archive / start of current" boundary |

`rotation_anchor` is the foundation of the **filename = rotation-window** principle in
v0.0.7c: an archive's name uses `rotation_anchor` as its start time and `now` as its
end. The archive REPRESENTS a window (intentional coverage span); coverage gaps WITHIN
that window are documented by 915/914 events INSIDE.

### Restart detection (four cases)

On engine start, the engine compares the persisted `rotation_anchor` against the
rule-derived current window start (via `_current_rotation_window_start` for calendar
modes or `_next_rotation_boundary` for interval modes) and branches:

1. **Fresh install / no persisted anchor:** initialize `rotation_anchor` to the rule's
   current window start (calendar) or `now` (interval). No event.
2. **Clock anomaly (persisted > now):** emit **926 "Clock Anomaly Detected"**. Reset
   `rotation_anchor` to `now`/rule-derived. The detail records the persisted value,
   `now`, and the delta in seconds.
3. **Size-cap split (persisted is INSIDE the current rotation window):** the previous
   archive closed mid-window due to a size cap. Continue normally — the next close
   will be at the rule's next boundary, named for `(persisted_anchor → boundary)`.
4. **Gap (persisted is BEFORE the current window — at least one rotation boundary
   was crossed while down):** emit **925 "Archiving Gap Detected"**. For **interval
   modes only**, ALSO write a partial closing archive of whatever was in the channel
   pre-stop, named for `(persisted_anchor → restart_time)`. The justification is
   straightforward: in interval mode the cycle's start time is shifting (no calendar
   boundary to preserve), so we close out the old cycle's records before re-anchoring.
   For calendar modes, the calendar boundary is fixed, so the next normal archive
   close handles everything (the gap is visible via 915/914 bracketing inside).

Gap-trigger condition: at least one rotation boundary was crossed while down. Brief
restarts within the same rotation window are NOT 925 events — the existing 915/914
bracket already documents them.

### Archive naming reversed from v0.0.7c

v0.0.7c named archives by their actual record-content bounds (introspected first/last
`SystemTime`). v0.0.8 changes this: the filename now uses `rotation_anchor` (the
rotation window's intent) as the start time, `now` as the end. The motivation: a
silent period (no records but engine running) under v0.0.7c naming created the
illusion of gaps where there were none. The rotation window is the more honest
forensic frame.

Implementation: dropped the temp-name-then-rename-after-introspection pattern in
`archive_one`. Now it computes the basename FIRST, exports straight to it. Simpler
code. Collision protection via `_dupN` suffix preserved.

### Other API/config changes

- `run_engine(should_stop, archive_dir, rotate_period=None)` — signature change: was
  `rotate_interval_sec` (float seconds), now `rotate_period` (`(n, unit)` tuple).
- `archive_one(archive_dir, reason, rotate_period, forced_start, forced_end)` —
  new `rotate_period` (replacing `rotate_interval_sec`); new `forced_start`/`forced_end`
  for restart-partial archives that don't read from `rotation_anchor`.
- `maybe_rotate(archive_dir, rotate_period)` — signature update.
- `_archive_basename` — calendar-month detection now via `rotate_period[1] == "M"`
  AND `rotate_period[0] == 1` AND start/end at calendar month boundaries. The
  `reason` string is no longer the calendar-month signal.
- Config schema: two new fields, `engine_start_anchor` and `rotation_anchor`. Added
  to `_CONFIG_KNOWN_KEYS` (so they aren't flagged by integrity check) and to
  `SETTINGS_ORDER` (so they appear in a stable position in the JSON output).
- CLI help text updated: `--log-interval 10m, 90s, 6h, 1d, 2w, 1t, 1M, 1y` (with
  case-significant note); `--legal-retention 25y, 18M, 90d, 18t, 26w` (with
  M-vs-m note).
- Config-editor validators updated for the new unit table and breaking changes.

### Verified

Tests pass on:
- `parse_timeperiod` for rotation and retention (12 cases each: typical, at-cap,
  over-cap, fractional rejected, blank, None).
- `_period_advance` calendar arithmetic: 1d/1M/1y back, 24h back (fixed), 30t forward,
  Jan 31 + 1M = Feb 28 clamp, leap day +1y = Feb 28 clamp.
- `_next_rotation_boundary`: 1d/1w/1M/1y/24h/1t from various anchors including
  anchor-on-boundary edge cases and December-rollover.
- `_archive_basename` v0.0.8: full calendar month → MonthName form, 1M+size-cap →
  span name, 1d → span (no MonthName), 24h offset → timecoded span, 2M → span
  (not MonthName because n>1), 1y → span.
- All four restart-detection cases (fresh, clock anomaly, calendar size-cap split,
  calendar gap, interval size-cap, interval gap with partial archive).

## v0.0.7c

Archive naming convention rewrite. The v0.0.7 calendar-bucket naming
(`FileSystem_June_2026_1.evtx`) lied about contents when rotation modes other than
strict calendar-month were used (a `1t` 30-day term starting June 17 was named "June"
but actually spanned into July). v0.0.7c replaces the scheme so the **filename always
matches what's inside the file** -- the foundational forensic principle of this
project, now extended to the filename layer.

### Naming rules (the new contract)

- **Full calendar month, no size-cap interruption** -> `FileSystem_<MonthName>_<YYYY>`
  (e.g. `FileSystem_June_2026.evtx`). Clean, human-readable. Only used when rotation
  mode is `1m` (or default) AND the archive covers the full calendar month untouched.
- **Everything else** -> ISO-8601 span name:
  `FileSystem_YYYY-MM-DD_to_YYYY-MM-DD` for boundaries at midnight, or
  `FileSystem_YYYY-MM-DD-HHMMSS_to_YYYY-MM-DD-HHMMSS` when a boundary is mid-day.
  Per-side: each side independently includes its `-HHMMSS` only when that side is
  not at midnight (so a clean midnight boundary stays terse).
- **The moment a calendar month uses span names, the investigator can see at a glance
  that size cap was hit that month** -- a deviation from baseline activity, screaming
  "look here." The naming becomes a forensic signal.
- **`_N` counter dropped entirely.** Spans self-disambiguate.

### Implementation: name the file AFTER seeing what's inside

`archive_one` now exports to a temp filename, introspects the resulting evtx for its
actual first/last record `SystemTime` values, THEN computes the final basename from
those real bounds and renames. This is robust across restarts and crashes -- no
in-memory state to lose. Prefers the fast Rust `evtx` reader, falls back to
`python-evtx`. If neither is available, falls back to using `now` for both bounds.

### Unit semantics (clarified, locked, documented)

Each unit has a single meaning. Substitution gives all the flexibility you need:
calendar-vs-interval is expressed by *which unit* you choose.

| Unit | Meaning |
|---|---|
| `s` | seconds, fixed interval from start |
| `m` | calendar months (next 1st 00:00 boundary, leap-aware) |
| `h` | hours, fixed interval from start |
| `d` | calendar days (midnight to midnight) |
| `w` | calendar weeks (Monday 00:00 ISO-8601 to next Monday 00:00) |
| `t` | 30-day terms (fixed 30x24h interval from start) |
| `y` | calendar years (Jan 1 00:00 to next Jan 1 00:00) |

Examples of the substitution principle:
- "Every calendar week" -> `1w`. "Every 7 days from start" -> `7d`.
- "Every calendar month" -> `1m`. "Every 30 days from start" -> `1t` (or `30d`).
- "Every calendar year" -> `1y`. "Every 365 days from start" -> `365d`.

Note: the calendar-vs-interval distinction now applies to ALL units, not just the
yearly/monthly ones. Earlier `t/w/d` were fixed-interval-only; `m/y` were calendar-only.
v0.0.7c keeps that exactly the same -- the change is in *naming* what falls out, not
in *triggering* the rotations themselves (which already worked correctly).

### Compatibility

- **Existing v0.0.7 archives** (legacy `FileSystem_<Month>_<Year>_<N>.zip` form) are
  recognized as covering their calendar month by `check_completeness` and treated
  correctly by `prune_legal_retention`. No migration is required. Old files stay as
  they are; new files use the new scheme. Both coexist cleanly in the same archive
  directory.
- **The `_N` legacy counter** is preserved in `_next_month_counter` for parsing legacy
  files, but no longer used for naming new files (spans self-disambiguate).
- **Collision protection:** if a target name would collide (a duplicate rotation in
  the same second, or a leftover from a crash), the file is suffixed with `_dupN` so
  forensic evidence is never overwritten.

### Verification

- `_archive_basename` produces correct names for: full calendar month, 1m+size-cap
  mid-month, 1t (30-day term), 7d midnight-boundaries, 24h offset-from-midnight, 1d
  calendar, 1h sub-day, 1m size-cap+mid-day, January (zero-padding edge), and
  single-digit-day spans.
- `check_completeness` correctly identifies coverage from BOTH naming styles: a span
  archive spanning Sep 15 -> Oct 14 covers both September and October.
- `prune_legal_retention` correctly deletes old span archives (using their END date as
  the age check) AND preserves spans that end within the retention horizon. Both
  legacy and new names handled identically.

## v0.0.7b

One additional field-discovered bug from v0.0.7a deployment, fixed. No behavior
changes; no schema changes. Existing v0.0.7/v0.0.7a installs upgrade in place — drop
in the new `usnmon.py` and run a single `install` (with whatever `--startup` you want)
to refresh the recorded start type.

### Fixed
- **`service_start_type` in `usnmon.cfg` not updated after `--startup <mode> install`.**
  The post-install read-back block checked `args[0] == "install"`, but when invoked as
  `python usnmon.py --startup delayed install` the local `args` list is
  `["--startup", "delayed", "install"]` (pywin32's flag and value come BEFORE the
  verb), so `args[0]` is `"--startup"` and the check failed silently. The service was
  installed correctly in Windows (`services.msc` showed `Automatic (Delayed Start)`),
  the standalone `query_service_start_type()` helper returned `"delayed"` correctly,
  and `python usnmon.py install` (no flags) also updated the config correctly — the
  bug only manifested when `--startup` preceded the verb. Fixed by checking
  `"install" in args` instead of `args[0] == "install"`. Now installs of any flag
  ordering update the config; the recorded start type is correctly reflected in
  `check` output and in the `914 Engine Started` log line.

## v0.0.7a

Two field-discovered bugs from v0.0.7 deployment, fixed. No behavior changes; no
schema changes; no new features. Existing v0.0.7 installs upgrade in place — drop in
the new `usnmon.py`, restart the service, and the next config write (within ~10s, on
the first cursor flush) reorders the file correctly.

### Fixed
- **`--log-interval` (and `--legal-retention`, `--archive`) rejected by pywin32 on
  `install`/`update`.** The CLI-only flags were stripped from a local `args` copy but
  not from `sys.argv`, which pywin32's `HandleCommandLine` reads directly — so it still
  saw the unknown flag and errored out (`option --log-interval not recognized`).
  Fixed by rebuilding `sys.argv` from the cleaned `args` before dispatching to
  `HandleCommandLine`. The intended one-shot install path now works:
  `python usnmon.py --startup delayed --log-interval 1h install`. The `config` editor
  workaround used in the field also continues to work.
- **`_README` warning not pinned to the top of `usnmon.cfg`.** Config writes relied on
  dict insertion order, so `_README` landed wherever it happened to be added — typically
  AFTER the `cursors` block it was warning the user not to touch. The whole point of
  `_README` is to be the gatekeeper. `_write_config_atomic` now builds the output in a
  deterministic order: `_README` first, settings keys next, `cursors` always LAST.
  Unknown/forward-compat keys are appended alphabetically between settings and cursors,
  so newer-version keys still round-trip safely. Existing v0.0.7 configs are re-ordered
  on their next write.

## v0.0.7

Builds on the locked v0.0.6 core. No changes to the capture/resolution/hashing
fundamentals demonstrated on hardware in v0.0.6; this release adds rotation, retention,
service, and configuration features, plus a resume-path correction.

### Added
- **Calendar-month rotation.** The live log now rotates on the calendar-month boundary
  (1st at 00:00:00, closing out the previous month) by default, in addition to the
  existing 3.5 GB size cap — whichever fires first.
- **Month-bucketed archive naming.** Archives are named `FileSystem_<Month>_<Year>_<N>`
  (e.g. `FileSystem_June_2026_1`). `N` increments when the size cap rotates more than
  once in a month and resets each month. Sub-day `--log-interval` values add a timecode
  to the name to avoid an unbounded counter.
- **`--legal-retention <N><unit>`** (units: `y`/`m` calendar-accurate years/months,
  `t`/`w`/`d` fixed 30/7/1-day spans). Prunes whole aged-out month
  buckets; a bucket is removed only once its end-of-month is older than the term, so an
  in-term day is never deleted. Deletes only complete sealed bundles — never trims or
  reopens a hashed archive. Blank/unset = keep everything forever (default).
- **Service start mode via pywin32's native `--startup <manual|auto|disabled|delayed>`**
  at install (the standard Python-service convention). usnmon reads the configured mode
  back from Windows (QueryServiceConfig) after install, records it, reports it in `check`,
  and appends it to each `Engine Started` (914) log entry. (An earlier `--start-type`
  wrapper was removed in favor of the native flag.)
- **`usnmon config`** — interactive numbered console editor for user-changeable settings
  (archive directory, rotation interval, legal-retention term). Service start type is
  shown read-only (it is owned by Windows, set via `--startup`). Only
  those settings are shown; the engine's cursor state is never exposed and is preserved
  intact on write. If the service is running, the editor detects it and offers to stop
  (and later restart) it, since editing must happen while the engine is stopped.
- **DO-NOT-EDIT marker** written into `usnmon.cfg` warning against hand-editing (the
  file carries live cursor state).

### Changed
- **Resume-path ordering corrected.** The decision is now, in order: clean cursor resume
  (same journal, position still in the ring) → resume from the saved USN; records purged
  from the ring while stopped → resume from the oldest still-valid USN (distinct 923);
  journal recreated → read the new journal from its start (distinct 923); first run (no
  cursor) → read the retained journal once. The branch order itself prevents re-reading
  from the journal start on every poll.
- **`check_completeness`** updated to parse the new month-bucket naming for the 918
  missing-bucket alarm, and to exclude the current in-progress month (which has no
  archive until it closes) so it is not false-flagged as missing.
- **Config input hardening.** The `config` editor rejects (does not silently strip)
  malformed values per type — forbidden path characters, traversal, non-numeric or
  out-of-range terms — and validates the loaded config against a known-key schema,
  reporting any unknown keys or malformed values (including a tampered cursor block) as
  anomalies. All config content is treated strictly as data; none is ever executed.

### Reserved
- **EID 106 (V4 RangeChange)** is documented as reserved and is not emitted. The engine
  reads V0/V2 journal records and does not request V4 range records, which carry only
  changed byte-ranges (no content, no before/after) and add no forensic signal beyond
  the Modify (101) they accompany. The map file is retained for possible future use.

### Notes
- Archive **signing remains disabled** (unchanged from v0.0.6). The signing code path
  exists but is not used; an on-host unprotected key provides no real authenticity. See
  `SECURITY.md`. Hashing (integrity) is active.
- All v0.0.7 changes were unit-tested off-platform; hardware validation (month-boundary
  rotation, service install with --startup) is the remaining pre-release step.

## v0.0.6

Project 1 lock. Continuous USN-journal capture, parent-reference resolution, persistent
cursor / gap-free resume, full volume disposition (events 919/920/921), removable-device
identity (events 500/501/503/504) including non-journalable drives, rotation with
export → 4-hash the evidence → manifest → bundle, and integrity manifests. Demonstrated
on real hardware; hashes externally verified. Supersedes the directory-targeted
`usn_monitor.py` (preserved under `old_srcs/`).
