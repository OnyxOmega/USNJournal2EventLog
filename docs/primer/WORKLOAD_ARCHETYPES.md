v0.3 | 2026-06-20 | Source: usnmon project, YASDC | License: PolyForm Noncommercial 1.0.0

# WORKLOAD_ARCHETYPES.md

## Purpose

This document describes typical baseline characteristics of different machine classes based on captured usnmon data. Use as a reference when contextualizing a single machine's observed rate against what is typical for its class.

**Critical caveat:** Baselines are environment-specific. Numbers in this document derive from specific captured machines and should not be applied as absolute thresholds. Use them as order-of-magnitude reference points, not as specifications. New environments warrant new baselining before analysis assumptions are locked in.

## How to use this document

When characterizing a machine's activity:

1. Identify which archetype the machine most closely resembles based on its role
2. Compare its observed steady-state rate to the archetype's typical range
3. If within the range, the machine is behaving as expected for its class
4. If significantly outside the range, investigate what is driving the deviation
5. Update internal expectations if the deviation has a legitimate explanation

## The background activity floor

Modern Windows produces ~1,000 records/hour purely from operating system background services with zero user activity. This includes:

- Windows Update Store polling
- Defender signature updates and per-user telemetry
- Windows Search Indexer background passes
- Browser background updaters (Edge, Firefox, Chrome update infrastructure)
- WSL service spawns (if WSL is installed)
- Telemetry submission (Glean, Microsoft diagnostic data)
- Sleep/wake deferred maintenance
- Network adapter state changes

This floor represents the "OS alone" baseline. Any observed rate above the floor is the machine's actual workload. Any observed rate near or below the floor suggests either the machine was powered off for portions of the window, or the OS has been substantially stripped of background services.

## Archetype: Idle DFIR / forensic analysis VM (no active investigation)

**Typical rate:** 1,000–1,500 records/hour
**Typical bytes/record:** 1,600–2,000
**MB/hour:** 1.5–2.5

**Characteristics:**
- WSL installed (background service spawns visible as deterministic 486-event-per-session signatures)
- Multiple browsers installed but used infrequently (background-update activity dominant)
- Device events present from VM PLATFORM operations (not analyst activity)
- Multiple 920 Unsupported Filesystem events (VM shared folder mounts)
- High share of activity in `\Users\<analyst>\AppData\`
- Variance archive-to-archive is low (predictable rhythm)

**Burst events that may appear:** .NET NGEN (Native Image Generator) optimization passes produce occasional bursts. Edge maintenance cycles produce 10x normal Edge activity in specific archives. Visible as elevated unresolved-path percentage in NGEN bursts.

**Common misattribution:** WSL session GUID counts may suggest interactive use. Check event count variance — identical counts across sessions (e.g., 486 per spawn) indicate automation, not human use. Device REATTACHED / ALTERED / 920 Unsupported FS events on VM guests typically reflect VM platform operations (host-side snapshot, suspend/resume, VMware Tools updates, shared folder activity propagated from host), NOT analyst activity. See `LESSONS_LEARNED_to_avoid.md` Trap 9 for the VM platform device-event misattribution.

**Distinguishable from active DFIR VM (with evidence-drive work):** Active DFIR work produces additional Modify event spikes on attached evidence drives, plus user-attributable application Prefetch entries (analysis tools like FTK Imager, Autopsy, hex editors, Volatility). Idle DFIR VM produces only platform-driven activity.

## Archetype: Personal laptop, light use

**Typical rate:** 2,000–3,000 records/hour (overnight quiet)
**Typical rate:** 4,000–8,000 records/hour (light user activity)
**Typical rate:** 10,000–13,000 records/hour (active browsing session)
**MB/hour:** 3–22

**Observed example baseline:** 24-hour clean capture at 5,935 rec/hr series average, per-archive range 2,322–12,728 rec/hr (5.5× daily variance).

**Characteristics:**
- Heavy concentration in `\Users\<name>\AppData\`
- Browser activity (telemetry + occasional active use)
- Possibly sync engines active (Dropbox, OneDrive, iCloud)
- Background VPN clients writing logs even when not actively connected (e.g., NordVPN .nwl files)
- Multiple browsers present but typically one primary
- Windows Update Store often actively processing recent patches (.rbf extension elevated)

**Variability:** This class shows the highest variance. Overnight quiet rates can be 5× lower than active browsing rates on the same machine. Compare like-time-of-day archives when characterizing.

**Browser cache pattern:** Active browsing produces elevated Security Change percentage (12-15%) due to Chromium-style atomic-write-with-ACL patterns on cache entries. Combined with Modify-dominant event mix in `Local\Mozilla\Firefox\Profiles\*\cache2\entries` or equivalent Chrome paths.

**Burst events that may appear:** Application launches, file save operations from active editing, sync-engine bulk operations after offline periods, browser cache fills during active sessions.

## Archetype: Active development workstation

**Typical rate (steady-state with mixed background updates):** 8,800–12,000 records/hour
**Typical rate (active workday + background updates):** 10,000–13,000 records/hour
**Typical rate (sync engine recovery):** 25,000–40,000 records/hour (anomaly)
**MB/hour:** 15–60

**Observed example baseline:** 24-hour clean capture at 10,409 rec/hr series average. Per-archive range 8,807–12,012 rec/hr (~35% daily variance). Microsoft Office Click-to-Run update, iTunes update, and Edge update all visible in the same window contributing ~27% of total events.

**Characteristics:**
- Multiple Dropbox or sync accounts often present (personal + business + team accounts)
- Multi-drive workstation pattern (see below) often present
- iTunes/iCloud or other Apple-stack activity (if user has Apple devices)
- Multiple browsers, often Chrome-primary
- Development tools and IDE caches active
- Microsoft Office Click-to-Run servicing visible periodically
- Microsoft Store servicing visible (auto-installed consumer apps and Teams updates)
- Vendor management agents (Dell/Intel/HP depending on hardware)
- ScreenConnect or similar remote access infrastructure (if remotely-administered estate)

**Multi-drive workstation pattern (vendor-constraint-driven):** Many active workstations have user content (Documents, Downloads, Dropbox content, repositories, VM images) relocated to a secondary larger drive because the OEM-supplied OS drive (typically 500GB SSD as of 2025-2026) cannot accommodate accumulated data without filling. This produces USN journal events distributed across multiple drives. Recognize this pattern: 95%+ on C: with small percentages on data drives (E:, F:, H:, etc.) is consistent with this OEM-constraint-driven layout, not anomalous. The user profile root typically remains on C: even when individual special folders (Documents, Downloads) are relocated to the data drive.

**Elevated Security Change percentage (15-25%):** Active workstations during Office Click-to-Run + iTunes + Edge update windows produce high Security Change activity as ACLs are set on updated binaries. The 19.2% Security Change observed in clean baseline reflects three concurrent update cycles, not anomalous behavior.

**Variability:** Combination of sync engine state, user browsing activity, and update windows produces the variance. Same machine can range 35% within a single day depending on activity profile.

**Burst events that may appear:**
- Microsoft Store package installations (especially Teams version upgrades)
- Microsoft Office Click-to-Run updates
- VM backup operations
- Build/compile operations
- File deduplication or workspace cleanup

**Common misattribution:** "Heavy Dropbox events = user actively editing files." Wrong. Distinguish normal sync from recovery by checking for `(1)`-suffix temporary directories and the Other Change percentage. Also: high Security Change percentage may suggest privilege escalation activity when it's actually routine Office Click-to-Run binary update ACL maintenance.

## Archetype: Mail-isolation VM / dedicated email workstation

**Typical rate (steady-state):** 10,000–12,500 records/hour
**Typical rate (initial scan on startup):** burst-dominated, may show 30,000+ records/hour headline
**MB/hour:** 17–21 (steady-state)

**Observed example baseline:** 24-hour clean capture at 11,255 rec/hr series average. Per-archive range 10,041–12,471 rec/hr (~25% daily variance — TIGHTEST variance of any user-active machine class). Two consecutive 12-hour archives produced Firefox bg update event counts within 5 events of each other (deterministic-automation signature).

**Characteristics:**
- AppData concentration extreme (typically >80%)
- `.log` extension dominance (>60%)
- `.gz` extension presence (compressed log rotation, ~10% of events)
- Modify-heavy event mix (>65%)
- Elevated Security Change (9-10%) from mail client ACL management on new log files
- Multiple SQLite-journal extensions present
- Per-mailbox log files reveal monitored email account inventory
- Embedded WebView2 components per account (if MailWasher-style isolation)
- Firefox or similar browser present for link sandbox testing
- No interactive sessions captured by session inference

**Burst events that may appear:** Initial scan on startup (first 4 minutes of capture may carry 80% of total events as the mail client enumerates all mailboxes). Microsoft Teams version upgrades. Edge maintenance cycles.

**Common misattribution:** "Mail server logging behavior" — this is actually a client doing per-mailbox processing, not a server. Distinguishing requires checking the application paths. Also: GoingPostal-class machines may show no user activity in session inference even when continuously operational — the workload is purely automated mail processing.

## Archetype: Surveillance system / Blue Iris viewer

**Typical rate (steady-state):** 5,000–10,000 records/hour above the OS floor
**Typical rate (with initial dump):** 250,000+ records/hour (heavily inflated)
**MB/hour:** 10–20 (steady-state)

**Characteristics:**
- Single dominant directory `\ProgramData\Blue Iris\temp\` at 30–40% of all events
- Modify-dominated event mix (95%+ Modify for the Blue Iris-attributable portion)
- One or two state files receive thousands of modify events each
- Vendor business hardware (Dell/HP business class)
- Vendor management agent footprint adds 10,000–15,000 events/hour beyond Blue Iris

**Burst events that may appear:** Initial dump on engine first start. Microsoft Store servicing during unrelated install activity. Vendor agent update cycles.

**Common misattribution:** Headline rates from initial-dump archives substantially overstate the steady-state. Apply the first-archive disclaimer; characterize from the second archive onward.

## Archetype: Fresh / minimal Windows install (clean baseline)

**Status:** Not yet captured. Anticipated rate: 800–1,500 records/hour with no third-party software, no sync engines, no vendor agents, no user activity. Would represent the absolute floor for Microsoft-only background activity on the specific Windows version captured.

**Why this matters:** A fresh-install baseline gives a known reference for "Microsoft Windows itself" that can be subtracted from observations on machines with software stacks. Without it, every observation is contaminated by whatever else is installed.

**Recommendation:** Capture a fresh-install baseline for each Windows version supported by the deployment context (Win 10, Win 11 base, Win 11 24H2, Win 12, etc.). Each version will produce a different floor. Include the exact build number and edition in the baseline documentation.

## Archetype: Vendor-stock new-hardware install

**Status:** Not yet captured. Anticipated rate: 2,000–4,000 records/hour for a freshly-provisioned consumer or business laptop with the vendor's complete software bundle installed but no user activity.

**Why this matters:** This baseline isolates "Microsoft Windows + vendor bloat" together. Subtracting the fresh-install baseline yields the vendor-specific bloat contribution.

**Recommendation:** Capture per-vendor baselines (Dell consumer, Dell business, HP consumer, HP business, Lenovo, ASUS, Acer, etc.). Each vendor adds different bloat at different volumes.

## Archetype: Enterprise endpoint (corporate-imaged)

**Status:** Not yet captured. Anticipated rate: highly variable depending on corporate image content. Likely includes endpoint management (Intune, SCCM, JAMF if mixed environment), endpoint detection and response (CrowdStrike, SentinelOne, Carbon Black), VPN clients (Cisco AnyConnect, GlobalProtect), corporate productivity stack (Office, Teams, possibly browser policies), and inventory/asset management agents.

**Why this matters:** Enterprise baselines establish what an internal security team would consider normal for their managed endpoints. Anomaly detection against a corporate baseline catches different things than anomaly detection against a consumer baseline.

**Recommendation:** Per-customer baselining process for enterprise deployments. Each corporate environment is its own baseline; cross-company comparisons are not meaningful.

## Rate variance interpretation

When observing rate differences between archives or between machines, consider:

**Within-machine variance:**
- Idle vs active hours (~3–4× difference typical for personal use)
- Sync engine state (idle vs sync vs recovery = potentially 4× difference)
- Microsoft Store servicing events (occasional bursts)
- Application install activity (creates discrete bursts)

**Between-machine variance for ostensibly-similar machines:**
- Different software stacks (browsers, sync engines, dev tools)
- Different vendor hardware (Dell management ≠ Lenovo management ≠ none)
- Different user habits (Chrome-primary vs. Firefox-primary vs. multi-browser)
- Different drive configurations (single drive vs. data/system split vs. dropbox-on-D)

**Cross-class variance:** Not directly comparable. A "high" rate for a personal laptop may be a "low" rate for a development workstation. Use class-specific baselines, not cross-class averages.

## How to baseline a new environment

For each machine class in scope:

1. Identify the machine's role and approximate workload class
2. Run usnmon for at least 7 days at the planned rotation cadence
3. Generate the multi-archive series report
4. Identify steady-state rate (excluding initial dump and any anomalous archives)
5. Document the baseline with:
   - Machine class and role
   - Windows version and build number
   - Vendor hardware identification
   - Installed software inventory
   - Observed steady-state rate and variance range
   - Distinctive top-talker patterns

These baselines feed into anomaly detection going forward. Anything substantially outside the baseline range warrants investigation.

## License and provenance

usnmon is a project of YASDC, licensed under PolyForm Noncommercial 1.0.0. This document is reference material for characterizing observed activity against typical patterns for machine class.
