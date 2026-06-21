v0.3 | 2026-06-20 | Source: usnmon project, YASDC | License: PolyForm Noncommercial 1.0.0

# LESSONS_LEARNED_to_avoid.md

## Purpose

This document catalogs interpretation traps that have produced wrong conclusions when analyzing usnmon output. Each lesson includes the failure pattern, the correct interpretation, and a verification protocol to prevent recurrence.

If you are an AI or investigator reading this, treat these lessons as fail-safes: when you find yourself approaching one of these patterns, stop and verify before asserting.

## The meta-lesson: verify before asserting

The most consistent failure mode across all analysis sessions is asserting from memory or pattern-matching rather than verification. This applies to:

- Command syntax claims ("usnmon supports `export <path> --clear`" — this command does not exist)
- User-attribution claims ("the user was browsing in Chrome" — based on file activity alone, unsupported)
- Mechanism explanations ("this is Microsoft Search pinning frequent results" — actually a Firefox PWA shortcut)
- Application identification ("this looks like a mail server" — actually a mail client doing per-mailbox logging)

**Verification protocol:**

Before stating any technical claim, ask:
1. Did I read the source file, documentation, or directory listing that supports this claim?
2. Is there a tool I should run to verify before asserting?
3. Am I pattern-matching to similar things I have seen before, or am I checking the specific case?
4. If I am wrong, what would the operator's correction sound like?

If you cannot answer step 1 with "yes," stop and verify. Do not assert.

## Trap 1: User-attribution from file path location

**The trap:** Concluding that activity in `\Users\<name>\AppData\` directories proves user action.

**Why it fails:** Modern Windows runs many background services that write to user-profile directories without the user being involved:

- Browser background updaters (Edge, Chrome, Firefox all write to user profile when no browser is open)
- Browser telemetry agents (Glean databases, sync state) write continuously
- WSL service spawns background instances in user temp without user shell activity
- Sync engines (Dropbox, OneDrive, iCloud) write when files change on other devices, not only when user edits locally
- Microsoft Store servicing writes to user-package directories during unrelated system events
- Per-user antivirus telemetry and signature updates
- Windows Search Indexer maintaining its database in user profile
- Sleep/wake deferred maintenance running on resume

**Observed misattribution cases (this session):**
- Teams activity claimed as "user in active session" — actually Microsoft Store maintenance during Python install
- Heavy Dropbox activity claimed as "user editing files" — actually full desync recovery
- NordVPN activity claimed as "user connected to VPN" — actually background daemon logging despite no active connection
- Brave browser activity claimed as "user browsing" — actually update infrastructure
- WSL sessions claimed as "user shells" — actually wslservice background spawns at deterministic 486-event count
- Edge activity claimed as "user browsing" — actually scheduled background maintenance

**Verification protocol:**

Before attributing activity to a user:
1. Identify the responsible application from the path
2. Check whether that application has documented background mechanisms (yes for browsers, sync engines, WSL, telemetry agents)
3. Look for corroborating user-action evidence:
   - Windows logon events (4624, 4634) around the time window
   - Specific application-level evidence (browser history database records, mail send/receive logs)
   - Network activity consistent with user behavior
   - Process tree showing interactive parent processes
4. If corroborating evidence is absent or ambiguous, default to "background activity, not user activity"

**Phrase to avoid:** "User X did Y at time T" based on USN journal alone.

**Phrase to prefer:** "Activity in <application> directory observed at time T; user attribution requires corroborating evidence."

## Trap 2: Event count as proxy for disk impact

**The trap:** Concluding that low event count means low disk activity.

**Why it fails:** Each USN record describes one change to one file's metadata. The actual data change ranges from zero bytes (attribute change) to many gigabytes (modify on a large file rewritten end-to-end). A few-hundred-event burst can represent significant disk I/O if each event is a large random-write operation on a mechanical drive.

**Observed misattribution case (this session):**
- 585 events in one minute on Chrome IndexedDB writes interpreted as "minor activity" — actually produced audible mechanical drive head chatter due to the small-random-write pattern on HDD

**Verification protocol:**

When event count suggests low activity but other signals (drive noise, system slowdown, fan ramp-up) suggest otherwise:
1. Consider that the activity may be read-heavy (USN journal does not capture reads at all)
2. Consider that few large modifies can represent significant bytes
3. Supplement with Performance Monitor disk-bytes/sec counters or Process Monitor I/O details if available
4. Do not assume event count linearly maps to disk impact

**Phrase to avoid:** "Only N events, so the activity was minor."

**Phrase to prefer:** "N events were captured. Actual disk impact depends on per-event byte volume and access pattern, which USN does not record."

## Trap 3: Headline rate as steady-state characterization

**The trap:** Using the SERIES OVERVIEW records-per-hour as the machine's typical operating rate.

**Why it fails:** Series-level rates average across all archives in the set. A single anomalous archive (initial dump, install burst, recovery operation) can inflate the series rate by 3–10×. Reading the headline as steady-state misrepresents what the machine actually does day-to-day.

**Observed misattribution cases (this session):**
- Office_Busybox series at 29,469 records/hour reported as steady-state — actually the first archive contained Dropbox recovery and dominated; true steady-state from second archive was 9,251 records/hour
- SecMon series at 53,984 records/hour reported as steady-state — actually channel-not-cleared overlap and initial dump contributed substantially; true steady-state estimate was ~7,800 records/hour
- GoingPostal mail-isolation VM at 31,895 records/hour reported as steady-state — actually the first 4 minutes carried 80% of events (MailWasher initial scan); true steady-state was ~9,900 records/hour

**Verification protocol:**

When characterizing steady-state from a series report:
1. Check the per-archive comparison table for rate variance
2. Look for `*BURST*` flags (any of the three voting levels) indicating anomalous archives
3. Look for archives where `first_dt` matches the engine start time within seconds (initial-dump indicator)
4. Compute steady-state by excluding flagged archives and re-averaging the remainder
5. Report both the raw series rate AND the steady-state estimate, not the raw rate alone

**Phrase to avoid:** "The machine runs at X records/hour" (when X is the raw series rate from a series containing anomalous archives).

**Phrase to prefer:** "Series rate is X records/hour; excluding flagged anomalous archives, estimated steady-state is Y records/hour."

## Trap 4: Sanity-check duplicates not recognized as overlap

**The trap:** Treating duplicate event counts across captures as separate occurrences.

**Why it fails:** When the Windows Event Log channel is not cleared between sessions, archives contain previously-captured events. Identical event counts in identical paths across captures indicate overlap, not new activity.

**Observed misattribution case (this session):**
- SecMon Teams burst of 16,716 events visible in two consecutive captures — was the same physical event captured twice due to channel-not-cleared, not two separate Teams operations

**Verification protocol:**

When comparing successive captures from the same machine:
1. Compare `first_dt` and `last_dt` across captures
2. If a new capture's `first_dt` matches an earlier capture's `first_dt`, the channel still contains old data
3. If identical event counts appear at identical paths across captures, it is overlap, not duplication of activity
4. Rate calculations on the overlap portion are meaningless; use only the non-overlapping new period
5. See `CHANNEL_HYGIENE.md` for the procedural mechanics and best-practice recovery

**Phrase to avoid:** "Teams burst occurred twice."

**Phrase to prefer:** "Teams burst at timestamp X is captured in both archives due to channel-not-cleared overlap; counted once for analytical purposes."

## Trap 5: Application identification from path without verifying installed inventory

**The trap:** Concluding an application is producing bloatware behavior without checking whether the operator legitimately uses related software.

**Why it fails:** Vendor software (HP Printer Control, Epson driver updates, Dell management agents) appears in USN journal in patterns that resemble Microsoft-pushed bloatware. Distinguishing legitimate vendor activity from unwanted auto-installation requires knowing what the operator actually has installed.

**Observed misattribution case (this session):**
- HP Printer Control activity classified as bloatware auto-install — operator actually had HP Printer + Epson printer + Microsoft PDF Print + PDF-XChange print drivers all installed; HP Printer Control update was legitimate maintenance

**Verification protocol:**

Before classifying vendor software activity as bloatware:
1. Check the operator's installed software inventory for related products
2. Check the operator's physical hardware inventory (printers, monitors, peripherals)
3. Distinguish "auto-pushed despite uninstall" from "legitimate maintenance of installed software"
4. The two have the same USN signature; only the operator context distinguishes them

**Phrase to avoid:** "Auto-installed bloatware detected" based on path pattern alone.

**Phrase to prefer:** "Auto-update or installation activity for <vendor> <product>. Operator context required to determine whether this is legitimate maintenance or unsolicited push."

## Trap 6: Integrity check false positive interpreted as engine failure

**The trap:** Treating the "silent on FileSystem_Archives" integrity check warning as proof the engine failed.

**Why it fails:** The check uses depth-4 directory rollup with a top-5,000 distinct-directories cap. If the archive directory had low write count in a given archive and was evicted from the rolled-up dir_counts, the check reports "silent" even though the engine was operational and rotation occurred normally.

**Observed misattribution case (this session):**
- Office_Busybox second archive reported as "silent on FileSystem_Archives" — actually the archive .zip file existed in the expected directory with correct timestamp; the check missed it due to depth-4 truncation, not engine failure

**Verification protocol:**

When integrity check reports silent-on-FileSystem_Archives:
1. Check whether archive `.zip` files actually exist in the expected directory
2. Verify modified timestamps match the rotation boundaries
3. Check whether the archive contains 904 (Archive Written) events directly
4. If both confirm engine operation, treat the "silent" flag as a known false positive
5. The planned analyzer fix replaces substring search with direct 904 event counting

**Phrase to avoid:** "Engine failed to write archive."

**Phrase to prefer:** "Self-archive activity check fired; verifying via filesystem inspection... archive .zip exists with correct timestamp; treating check fire as known false-positive of depth-4 detection mechanic."

## Trap 7: Mechanism explanation from training-data pattern-matching

**The trap:** Explaining how a Windows mechanism works from general knowledge rather than checking the specific case.

**Why it fails:** Windows mechanisms have many subspecies. PWA installation alone has multiple distinct mechanisms (Edge native, Chrome native, Firefox native, Microsoft Search pinning, Bing integration, AppX provisioning) each with different on-disk footprints. Pattern-matching produces plausible-sounding but wrong explanations.

**Observed misattribution case (this session):**
- "Colorado DMV" Start menu entry explained as "Microsoft Search phantom Start menu pinning" — actually a Firefox PWA shortcut in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Firefox Web Apps\`

**Verification protocol:**

Before explaining a Windows mechanism:
1. Identify the artifact's actual location on disk
2. Run diagnostic commands appropriate to its location (registry queries, directory listings, AppX checks)
3. Verify the mechanism matches by checking the on-disk evidence
4. Multiple plausible mechanisms may produce similar surface artifacts; the on-disk evidence is the ground truth

**Phrase to avoid:** "This is mechanism X" (when based on pattern-matching to similar-sounding cases).

**Phrase to prefer:** "Based on the artifact location at <path>, this is consistent with mechanism Y. Verified by <evidence>."

## Trap 8: Deployment-time activity treated as steady-state signal

**The trap:** Treating activity that appears in the initial dump archive as indicative of how the machine normally operates.

**Why it fails:** The initial dump archive captures USN journal accumulation from before the engine started monitoring. On a newly-deployed machine, that accumulation includes the deployment activity itself: the installation steps the operator just performed to enable usnmon. This activity is procedural, one-time, and will NOT recur in subsequent archives.

**Observed misattribution case (this session):**
- Grooella-II initial dump showed 4,850 `.py` extension events. Flagged as "Python install activity, distinctive enough to note." Wrong framing — this was the Python install that the operator performed in order to run usnmon (which is distributed as Python source, not a binary). The signature is procedural, not characteristic of the machine.

**Same pattern previously seen:** SecMon initial archive showed 4,853 `.py` extension events from the same deployment-time Python install. Two independent observations of the same procedural signature on two different machines. Should have been recognized as a known deployment pattern, not as "distinctive activity worth noting."

**Verification protocol:**

When activity appears in an initial dump archive:
1. Check whether the activity is consistent with the deployment process (Python install, dependency package installs, source file placement, engine first-start)
2. If yes, treat as procedural and do NOT include in baseline characterization
3. If unclear, wait for the second archive (steady-state) to confirm whether the activity continues
4. Persistent activity in subsequent archives is characteristic; activity only in initial dump is deployment artifact

**Common deployment-time signatures to expect (not anomalies):**

- Python install activity (`.py`, `.pyc` events, Python paths)
- pywin32 install (`.pyd` events, win32 paths)
- python-evtx install
- Microsoft Store servicing if Python was installed via Store
- usnmon source file placement at operator's chosen location
- First engine startup events (914)
- First device classification events (500)

See `APPLICATION_FINGERPRINTS.md` for the full usnmon deployment-time composite signature.

**Phrase to avoid:** "Python activity is interesting" or "the user appears to be running Python scripts" based on initial dump data alone.

**Phrase to prefer:** "Initial dump shows Python install activity consistent with usnmon deployment. Will reassess after first steady-state archive to determine whether Python continues to be active."

## Trap 9: VM platform device events misattributed as analyst activity

**The trap:** Treating device REATTACHED, ALTERED, or 920 Unsupported Filesystem events on a VM guest as evidence of analyst-driven evidence-drive handling.

**Why it fails:** VM platforms (VMware, Hyper-V, VirtualBox) produce device-state events in the guest USN journal for reasons unrelated to guest user activity:
- Virtual CD-ROM drives cycling state during snapshot or VMware Tools updates
- Shared folder mounts producing ALTERED events when host-side filesystem activity propagates to the guest
- Suspend/resume cycles re-classifying virtual drives
- Host-side device controller changes affecting guest device visibility

**Observed misattribution case (this session):**
- SANS-SIFT VM showed 3 REATTACH events on L:, 2 ALTERED events on G:, and 3 Unsupported FS events on D:. Initial interpretation framed these as "evidence-drive cycling on a forensic analysis VM." Operator correction revealed: L: and K: are virtual CD-ROMs (no media), G: is a Cases shared folder mount that propagates host-side activity, D: is the standard VMware shared folder mount. NO analyst activity occurred during the capture window.

**Verification protocol:**

When device events appear on a VM guest:
1. Identify what each drive letter actually IS via `fsutil fsinfo drives` and `fsutil fsinfo driveType <letter>:` from inside the guest
2. Distinguish virtual optical drives (CD-ROM with no media = platform cycling) from real device mounts
3. Recognize shared folder mounts (typically D: in VMware) — activity on these may reflect HOST activity, not guest activity
4. Cluster timing analysis: device events occurring within seconds of each other across drives strongly suggest host-side or VM-platform events
5. Verify with operator whether analyst-driven evidence work occurred during the window

**Phrase to avoid:** "Evidence drives were cycled by the analyst" (from device events alone on a VM guest).

**Phrase to prefer:** "Device events captured on the VM guest. Drive letter inventory and operator confirmation indicate VM platform operations rather than analyst activity."

## Trap 10: Recent\AutomaticDestinations updates assumed without verifying tracking configuration

**The trap:** Treating the absence of `\Recent\AutomaticDestinations\*.automaticDestinations-ms` updates as evidence the user was inactive, without first verifying that Windows recent-documents tracking is enabled on the target system.

**Why it fails:** The Windows registry value `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackDocs` controls whether the system updates Recent\AutomaticDestinations files. When set to 0 (the Windows UI "Show recently opened items in Start, Jump Lists, and File Explorer" toggle is off), these files do NOT update regardless of user activity level. This is operator-configurable through normal Settings UI without specialized anti-forensics tools.

**Observed misattribution case (this session):**
- Office_Busybox showed zero `\Recent\AutomaticDestinations\` events across a 12-hour active workday. Initial interpretation: "Operator not present during workday." Operator correction: "I did tons of work in that window." Investigation revealed `Start_TrackDocs = 0` — tracking had been disabled on 06/13/2026 at 07:22 AM, freezing 143 of 144 jump list files at that timestamp.

**Verification protocol:**

When proposing that absence of Recent\ updates indicates user inactivity:
1. Query the tracking registry value on the target system:
   - `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackDocs`
   - `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs`
2. If either is 0, recent-document tracking is disabled — absence of Recent\ updates is meaningless for user-activity attribution
3. Check modification timestamps on existing `.automaticDestinations-ms` files. Uniform old timestamps across most files = tracking has been off since that date
4. Verify with operator whether they have disabled tracking, used a privacy tool, or configured Group Policy that affects this setting

**Broader principle: Configurable forensic artifact suppression.** Modern Windows privacy/telemetry settings significantly affect what forensic artifacts are produced. Negative findings (absence of expected artifact) on modern systems require verifying that the relevant tracking is enabled before drawing conclusions. This category includes Start_TrackDocs, Start_TrackProgs, various Windows Search Indexer settings, telemetry collection settings, Activity History settings, and browser private mode / history clearing settings.

**Phrase to avoid:** "User was inactive during the window" (from absence of Recent\ updates alone).

**Phrase to prefer:** "Recent\ tracking configuration verified: Start_TrackDocs = [value]. Recent\ updates [were/were not] enabled during the window. [If enabled:] Absence of updates suggests user inactivity. [If disabled:] Absence of updates is meaningless for activity attribution."

## Trap 11: Operator-stated infrastructure beliefs accepted without data verification

**The trap:** Accepting an operator's stated belief about their system configuration (drive layout, folder relocation, software inventory) as authoritative without verifying against actual data.

**Why it fails:** Operators may have incomplete or outdated mental models of their own system configurations. Configurations made years ago may have been forgotten, partially completed, or unintentionally changed by Windows updates or other software. The data shows what is actually there; operator memory shows what they believe is there. These can differ.

**Observed misattribution case (this session):**
- Operator stated: "I moved my user folder pointer to F: I think" — implying Recent\ folder activity would be on F: drive. Investigation showed: registry confirmed Recent\ folder on C: (operator's belief was incorrect), but specific user content (Documents, Downloads) IS relocated to F:. The actual layout was: user profile root on C:, individual special folders relocated to F: data drive, Dropbox content on E: large data drive. Operator's "I think" hedge was warranted — the mental model was incomplete.

**Verification protocol:**

When operator describes their system configuration:
1. Treat the description as a hypothesis to be tested, not as authoritative truth
2. Verify against actual registry, filesystem, or configuration data before incorporating into analysis
3. Recognize operator-stated hedges ("I think", "probably", "might be") as explicit invitations to verify
4. Do not amplify operator-stated beliefs into stronger claims when adding analytical narrative

**Phrase to avoid:** "Per operator, the user folder is on F: drive" (when operator hedged with "I think").

**Phrase to prefer:** "Operator reports moving user folder to F: drive. Registry verification shows user profile root on C: with Documents and Downloads relocated to F: — partial relocation rather than complete pointer move."

## Trap 12: Prefetch run count interpreted as user launch count

**The trap:** Treating Prefetch modify counts (or recorded "run count" values in the Prefetch file format) as equivalent to the number of times a user initiated the program.

**Why it fails:** Multi-process applications (Chrome's per-tab processes, Firefox's content processes, modern Edge, etc.) generate multiple Prefetch updates from a single user-initiated session. Background spawning by parent processes increments the count without user involvement. Application lifecycle events (not only launches) trigger Prefetch updates. The count reflects execution-related activity, NOT literal user-initiated launches.

**Observed misattribution case (this session):**
- Firefox at 12 modifies during an evening window framed as "Firefox was launched 12 times." Operator correction: "Firefox was launched ONCE; the additional modifies were tabs opening within that single session producing more cache/process activity."
- Chrome at 342 modifies on Office_Busybox framed as "Chrome launched 342 times." Reality: Chrome's multi-process architecture (one process per tab, extension, service worker, GPU process) generated many Prefetch updates from sustained user browsing across the day, not 342 separate launches.

**Verification protocol:**

When characterizing Prefetch evidence:
1. Distinguish "Prefetch modify count" or "Prefetch run count" from "user-initiated launch count" — they are NOT equivalent
2. Frame claims around execution-related activity, not literal launch events
3. For multi-process applications, recognize that one user session produces multiple Prefetch updates
4. Use "process activity consistent with [pattern]" rather than "[N] launches"

**Phrase to avoid:** "User launched Chrome 342 times" (from Prefetch evidence alone).

**Phrase to prefer:** "Chrome process activity is consistent with sustained user browsing throughout the window. Prefetch evidence reflects execution-related activity, not literal launch count."

## Trap 13: Deployment-time procedural activity treated as steady-state characterization

(Previously numbered as Trap 8 — keeping content, renumbering for the v0.3 sequence.)

**The trap:** Treating activity that appears only in the initial dump archive as indicative of how the machine normally operates.

**Observed misattribution case:**
- Grooella-II initial dump showed 4,850 .py extension events. Initially noted as "Python install activity, distinctive enough to note." Operator correction: this was the Python install performed to enable usnmon deployment (which is distributed as Python source). The signature is procedural, not characteristic of the machine. Same pattern previously seen on SecMon at 4,853 .py events from the same deployment-time install.

**Verification protocol:**

When activity appears in an initial dump archive:
1. Check whether the activity is consistent with the deployment process (Python install, dependency package installs, source file placement, engine first-start)
2. If yes, treat as procedural and do NOT include in baseline characterization
3. If unclear, wait for the second archive (steady-state) to confirm whether the activity continues
4. Persistent activity in subsequent archives is characteristic; activity only in initial dump is deployment artifact

**See `APPLICATION_FINGERPRINTS.md`** for the full usnmon deployment-time composite signature catalog entry.

## Honest acknowledgment

Across the analysis sessions that produced this document, the thirteen traps above produced documented incorrect attributions before the operator's correction. Each was caught by operator domain knowledge that contradicted the pattern-matched conclusion. The pattern is consistent enough to be worth explicit guardrails rather than relying on operator correction at every step.

For an AI consuming this document at session start: this is a warning to apply specifically to your own outputs. The patterns above are not abstract risks. They are documented failure modes that have been confirmed to occur. Verify before asserting.

## License and provenance

usnmon is a project of YASDC, licensed under PolyForm Noncommercial 1.0.0. This document is reference material for avoiding documented misattribution patterns in usnmon analysis.
