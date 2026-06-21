v0.3 | 2026-06-20 | Source: usnmon project, YASDC | License: PolyForm Noncommercial 1.0.0

# APPLICATION_FINGERPRINTS.md

## Purpose

This document catalogs file system signatures of applications observed in usnmon captures. Use this as a reference when interpreting directory talkers and event mix patterns in `usn_stats` and `usn_drill` output.

Each fingerprint includes:
- Distinctive directory paths
- Typical event mix
- Distinguishing file extensions or naming patterns
- Common misattributions to avoid

**Caveat:** Application signatures vary across versions, configurations, and operating environments. The patterns here describe what was observed in specific captures. Different installations may produce different signatures. When an observed signature does not match the catalog, treat it as unidentified rather than forcing a match.

## How to use this document

When you encounter a dominant directory in a `usn_stats` top-25 list:

1. Match the path against the catalog below
2. Check whether the event mix matches the documented pattern
3. Check whether the file extensions match
4. If all three align, the identification is well-supported
5. If only path matches but event mix or extensions differ, the application may be present in an unusual operational state — investigate before concluding

## Sync engines

### Dropbox (normal incremental sync)

**Paths:**
- `\Users\<name>\Dropbox\` (personal account)
- `\Users\<name>\<TeamName> Dropbox\` (team/business account)
- `\Program Files\Dropbox\DropboxUpdater\`
- `\Users\<name>\AppData\Local\Dropbox\`

**Event mix:**
- Other Change: 25–45%
- Create + Modify + Delete: balanced
- File extensions include `.dbx-journal` (Dropbox's SQLite journal)

**Distinguishing markers:**
- `.dbx-journal` extension visible in top extensions list
- Activity distributed across user-modified files, not concentrated in one location
- Rate roughly correlates with how much the user actively edits synced files

**Common misattribution:** "Heavy Dropbox activity = user actively editing." Wrong. Dropbox produces equivalent events when files change on other devices that sync to this machine. Activity in `\Dropbox\` directories proves the sync engine is operational, not that the local user did anything.

### Dropbox (full re-sync / desync recovery)

**Paths:**
- Same as normal Dropbox PLUS:
- Temporary parallel directories with `(1)` suffix (e.g., `HAPA LLC (1)`)
- Nested same-name workspaces (e.g., `KOE Dropbox\KOE Dropbox`)

**Event mix:**
- Other Change: 55–65% (significantly elevated)
- Create: 25–35% (workspace recreation)
- Delete: 5–10%

**Distinguishing markers:**
- Sustained high activity for hours rather than burst-shaped
- Both original and `(1)`-suffix directories present simultaneously during recovery
- After recovery completes, the temporary `(1)` directories should be cleaned up by Dropbox

**Common misattribution:** "Active user file work." Wrong. A full re-sync produces the same event volume as recreating every file in the workspace. This is automated recovery, not user activity. Distinguishing requires checking for the `(1)` directory pattern and the high Other Change percentage.

### OneDrive / Egnyte / other commercial sync products

Similar fingerprints to Dropbox: high Other Change percentage, sync-product directory dominance, .journal-style extensions, and recovery operations producing distinctive parallel-directory patterns. Specific paths differ by product.

## Mail and logging applications

### MailWasher Pro

**Paths:**
- `\Users\<name>\AppData\Roaming\Firetrust\MailWasher\logs\logs_MM-DD-YYYY\`
- `\Users\<name>\AppData\Roaming\Firetrust\MailWasher\cache\webview2_<email>@<domain>\EBWebView\`

**Event mix:**
- Modify: 60–70% (log appending dominant)
- Security Change: 9-10% (elevated, ACL on new log files)
- Create: 8-10%
- Other Change: 6-8%
- Heavy `.log` extension (>60%)
- `.gz` extension at 8-10% (compressed log rotation of prior-day logs)

**Distinguishing markers:**
- Per-mailbox log files named `MWPapp_<account>_<domain>_<tld>.log`
- Master API log named `MWPapi.log` (highest modify count)
- Daily log subdirectories with `logs_MM-DD-YYYY` naming
- Per-account embedded WebView2 cache directories
- Compressed `.gz` archives of prior-day logs created during log rotation

**Steady-state rate (mail-isolation VM with MailWasher):** 10,000-12,500 records/hour, 17-21 MB/hour, with extremely tight variance (~25% range) between consecutive 12-hour archives.

**Forensic note:** The per-mailbox log filenames reveal which email accounts are monitored. Anyone with USN journal access can enumerate the operator's mail account inventory. For operators using identity compartmentalization (separate email addresses per professional context), the log directory exposes the complete inventory.

**Initial-scan signature:** First few minutes of an archive after engine start may show very high activity (4-minute burst at 80% of in-scope events) as MailWasher enumerates every mailbox on startup. Burst flags should fire on these archives. Headline rate from initial-dump archive may be 3× inflated relative to steady-state.

### Thunderbird

**Paths:**
- `\Users\<name>\AppData\Roaming\Thunderbird\Profiles\<profile-id>.default-release\`
- `\Users\<name>\AppData\Local\Thunderbird\Profiles\<profile-id>.default-release\cache2\entries\`
- `\Program Files\Mozilla Thunderbird\updated\` (update staging)

**Event mix:**
- Modify-heavy when active (60–70%)
- Multiple SQLite-journal extensions: `.sqlite-journal`, `.db-journal`, `.db3-journal`
- IMAP mail store under `\Profiles\<id>\ImapMail\<server>\`

**Distinguishing markers:**
- ImapMail subdirectories named after mail servers (e.g., `imap.dreamhost.com`)
- Glean telemetry database in `\datareporting\glean\db\`
- `.msf` extension files (mailbox summary files)

## Surveillance / state-journaling

### Blue Iris (camera viewer / NVR)

**Paths:**
- `\ProgramData\Blue Iris\temp\` (state journaling, very heavy)
- `\Program Files\Blue Iris X\` (application binaries)

**Event mix:**
- Modify: 95–100%
- Create: 0–5%
- Single dominant talker in `\temp\` subdirectory

**Distinguishing markers:**
- One or two state files (e.g., `South_2.xml`, `North_3.xml`) receiving thousands of modify events
- Per-camera naming convention often uses directional or position names (north/south/east/west, plus channel numbers)
- USN record-to-write ratio of 3:1 (each write produces DataTruncation + DataExtend + Close = 3 USN records)

**Rate signature:** Steady ~5 events per second per camera at typical configuration. For 5-camera install: ~25 events/sec, ~90,000 events/hour, ~150 MB/hour just from Blue Iris.

## Browsers (background and active)

### Chrome (background telemetry and storage)

**Paths:**
- `\Users\<name>\AppData\Local\Google\Chrome\User Data\Default\`
- Including subdirectories: `Local Storage`, `IndexedDB`, `Cache`, `Network`, `Storage`, `DNR Extension Rules`, `Local Extension Settings`

**Event mix:**
- Mixed Create/Modify/Delete
- Activity even when no browser session is active
- Per-tab IndexedDB writes can produce significant bursts on active tabs

**Common misattribution:** "Chrome activity = user browsing." Wrong. Chrome runs background processes for telemetry, sync, extension data, and component updates even when no window is open. Activity in Chrome User Data directories does not prove a user was browsing.

### Firefox (background updater)

**Paths:**
- `\ProgramData\Mozilla-<GUID>\updates\` (update infrastructure)
- `\Users\<name>\AppData\Roaming\Mozilla\Firefox\Background Tasks Profiles\<id>\` (background telemetry)

**Event mix:**
- Periodic bursts roughly every 7 hours
- Each cycle produces ~500–1,200 events
- Background-only when no interactive browser session
- Per-12-hour-archive: approximately 8,100 events with EXTREMELY tight variance (sub-1% between consecutive archives)

**Distinguishing markers:**
- Mozilla GUID-named ProgramData directory
- Glean telemetry database in background profiles
- Predictable cadence visible across multi-archive series
- Deterministic-automation signature: significant deviation from ~8,100 events per 12-hour window should be investigated as anomalous

### Firefox (user-attributable vs background — refining the session inference signal)

When `usn_stats` reports "Firefox profile activity" above threshold, the underlying activity falls into two distinct categories that produce the SAME session-inference signal but mean very different things:

**Background telemetry (NOT user activity):**
- Dominant subdirectory: `Roaming\Mozilla\Firefox\Profiles\<id>\datareporting\glean\db`
- Telemetry database updates run on schedule regardless of user presence
- Typical: 97% of Firefox profile activity concentrated in datareporting/glean/db when user is NOT browsing
- Modify-dominant

**Active user browsing:**
- Dominant subdirectory: `Local\Mozilla\Firefox\Profiles\<id>\cache2\entries`
- Cache writes produced by page loads, resource fetching during active sessions
- Typical: 97% of Firefox profile activity concentrated in cache2/entries when user IS browsing
- Mixed Create/Modify/Delete cycle (cache lifecycle)
- Elevated Security Change (12-15%) due to atomic-write-with-ACL pattern

**Verification protocol:** The Firefox profile activity session inference fires on BOTH cases. To distinguish user activity from background telemetry, drill down to the dominant subdirectory: cache2/entries = likely user, datareporting/glean/db = telemetry only.

### Edge (background maintenance)

**Paths:**
- `\Users\<name>\AppData\Local\Microsoft\Edge\User Data\Default\`
- Edge update infrastructure under `\Program Files (x86)\Microsoft\EdgeUpdate\`

**Common misattribution:** "Edge user activity detected" via session-inference patterns does NOT prove user browsing. Modern Edge runs WebView2 components for system integration (Widgets, Outlook, search) plus its own background updater and telemetry. Activity in Edge User Data directories without corroborating logon events or interactive process traces should default to "background, not user."

### WebView2 (Chromium-engine embedded component)

WebView2 is embedded in many applications: new Teams, new Outlook, MailWasher Pro, .NET applications, Edge sidebar. When present, WebView2 produces a distinctive signature wherever the host application stores its WebView2 cache.

**Paths:**
- `<host-app-path>\EBWebView\Default\Network\`
- `<host-app-path>\EBWebView\Default\Extension Rules\`
- `<host-app-path>\EBWebView\Default\Extension State\`
- `<host-app-path>\EBWebView\Default\Shared Dictionary\cache\index-dir\`
- `<host-app-path>\EBWebView\component_crx_cache\`
- `<host-app-path>\EBWebView\Subresource Filter\Indexed Rules\`

**Distinguishing markers:**
- Numbered segment files with extensions `.0001`, `.0002`, `.0004`, `.0005` appearing in triplet patterns with identical event counts
- Heavy 0-millisecond Create+Delete `.tmp` file churn in `\EBWebView\` paths
- Component CRX cache (Chrome extension format) regardless of host application

## WSL (Windows Subsystem for Linux)

**Paths:**
- `\Users\<name>\AppData\Local\Temp\` with GUID-named subdirectories per session

**Distinguishing markers:**
- Each WSL session creates a uniquely-GUIDed temp directory
- Baseline session-spawn activity is ~486 events per session, deterministic
- Event counts above 486 indicate user activity inside the session
- Multiple sessions with identical event counts (e.g., 5 sessions at exactly 486 events each) indicate `wslservice` background spawns, NOT user shell activity

**Common misattribution:** "WSL session GUID in journal = user opened a WSL shell." Wrong. The `wslservice` Windows service spawns background instances for various WSL APIs without any user interaction. Identical event counts across sessions is a deterministic-automation signature, not a human signature.

## Vendor management agents

### Dell business hardware (TrustedDevice + UpdateService + DellOptimizer)

**Paths:**
- `\ProgramData\Dell\TrustedDevice\`
- `\ProgramData\Dell\UpdateService\`
- `\ProgramData\<GUID>\DellOptimizer\` (the GUID is the install instance identifier)

**Volume signature:** Combined Dell management agent footprint is typically 10,000–15,000 events/hour on Dell business-class hardware. This is genuine vendor agent activity, not bloatware in the Microsoft-Store sense. Subtract from rate calculations when comparing Dell business hardware to consumer hardware.

### Intel Connectivity agents

**Paths:**
- `\ProgramData\Intel\Connectivity\`
- `\ProgramData\Intel\DSA\` (Driver and Support Assistant)

Typically lower volume than Dell management agents but present on most Intel-equipped business systems.

### HP, Lenovo, ASUS, other OEM agents

Similar pattern: vendor-named ProgramData directory with continuous low-volume background activity. Specific paths vary by vendor and model. When unidentified vendor activity appears, check the path against the OEM of the hardware before concluding bloatware.

## Microsoft Store servicing

### Auto-installed Store applications (consumer Windows)

**Paths:**
- `\Program Files\WindowsApps\<package_name>_<version>_x64__<publisher_id>\`
- `\Program Files\WindowsApps\Deleted\`

**Signature:**
- Two versions of the same package visible simultaneously (new being staged, old being cleaned)
- `\WindowsApps\Deleted` directory receiving cleanup activity
- Create-dominated burst (70–80% Create) concentrated in a short window
- Microsoft.WindowsStore packages active during the burst

**Common occurrences:** King games (Candy Crush family), Disney+, TikTok, Spotify, Netflix, various "Inbox" Microsoft apps. These can install or re-install on consumer Windows installations via the Consumer Experience / CloudContent / ContentDeliveryManager mechanisms even after the user has explicitly uninstalled them.

**Distinguishing user-installed from auto-installed:** Cannot be determined from USN journal alone. Corroborate with:
- Operator's installation history (did the user actually install this?)
- Provisioning records (`Get-AppxProvisionedPackage`)
- Start menu and Settings → Apps installation date

### Microsoft Office Click-to-Run updates

**Paths:**
- `\Program Files\Microsoft Office\root\` (Office binaries being updated)
- `\Program Files\Microsoft Office\Updates\` (update staging)
- `\Program Files\Common Files\microsoft shared\` (shared component updates)

**Signature:**
- Single Click-to-Run update window produces 25,000–35,000 events
- Elevated Security Change percentage during update window (contributes substantially to overall mix)
- Concentrated in Office root directory
- Often coincides with related Microsoft activity (Teams update, Edge update, Store maintenance)

**Frequency:** Office Click-to-Run polls Microsoft servers periodically. Major updates typically appear monthly with smaller cumulative updates more frequently. On a single workstation, Click-to-Run activity may dominate a specific 12-24 hour window without recurring at similar magnitude for weeks.

**Common misattribution:** Elevated Security Change percentage (19% observed in clean baseline) from Office Click-to-Run binary updates may suggest privilege escalation activity when it is actually routine ACL maintenance on updated Office binaries. Check the directory talker list — concentrated activity in `\Program Files\Microsoft Office\root\` indicates legitimate Click-to-Run update, not privilege manipulation.

### iTunes / Apple application updates

**Paths:**
- `\ProgramData\Apple Computer\iTunes\`
- `\Users\<name>\AppData\Local\Apple Computer\`
- `\Program Files\iTunes\`

**Signature:**
- Single iTunes update window produces 12,000–20,000 events
- Update activity often appears alongside Office and Edge updates (same maintenance window)
- Modify-dominant during update, Create-dominant for new file staging

**Frequency:** Less frequent than Microsoft updates. Major iTunes updates may appear every 1-3 months on systems where iTunes is installed and active.

## Backup and imaging tools

### VM backup operations

**Paths:**
- `\VM Backups\<vm_name>\<vm_name>\` (nested-same-name pattern common in VM backup workflows)
- Sometimes on dedicated drives separate from system drive

**Signature:**
- Sequential large-file writes
- Burst-shaped (typically 30 minutes to several hours depending on VM size)
- Event count modest relative to actual disk volume (large file writes produce few USN records)

## Print drivers and printer management

### HP Printer Control, Epson driver updates, similar OEM print software

**Paths:**
- `\Program Files\WindowsApps\<vendor>PrinterControl_<version>_x64__<id>\`
- `\Program Files\<vendor>\` for traditional install paths

**Signature similar to Microsoft Store servicing** when delivered via Store mechanism. When the operator has actually purchased a printer from that vendor, this is legitimate print driver maintenance, NOT bloatware. Check operator hardware inventory before classifying.

## Scheduled-task automation patterns

### PowerShell scheduled tasks (deterministic pattern)

**Signature:**
- `.ps1` and `.psm1` extensions appear at IDENTICAL event counts (e.g., both at 1,624 events)
- Matching counts across the two extensions indicate scheduled-task module loading, NOT interactive PowerShell sessions
- Interactive PowerShell would produce variable counts (no two sessions identical)

**Verification:** Identical .ps1/.psm1 counts is a strong indicator of automation. Check Windows Task Scheduler for PowerShell-based tasks to identify the responsible task (Defender, vendor management, custom scheduled scripts).

**Common misattribution:** PowerShell .ps1/.psm1 activity assumed to indicate user CLI use. Deterministic matching counts rule out interactive use — interactive PowerShell sessions produce variable, non-matching event counts.

### WSL service background spawns (deterministic pattern)

**Signature:**
- Each WSL session spawn produces EXACTLY 486 USN events
- Multiple sessions per 24-hour window (typically 1 spawn per 5-6 hours)
- Each spawn gets a unique GUID-named temp directory
- Multiple sessions at IDENTICAL 486-event counts indicate wslservice background spawns, NOT user shell activity
- Interactive WSL shells would produce variable counts based on what the user did inside the shell

**Common misattribution:** "WSL session GUIDs in journal = user opened WSL shells." Wrong when counts match the 486 deterministic signature. See `LESSONS_LEARNED_to_avoid.md` Trap 1.

## Operator-presence detection methodology

This section documents the methodology for using USN journal evidence to assess operator presence during a capture window. **Critical caveat:** the methodology requires verifying tracking configuration before drawing conclusions from absence of artifacts (see `LESSONS_LEARNED_to_avoid.md` Trap 10).

### Recent\AutomaticDestinations as operator-presence signal (when tracking is enabled)

**Path:** `\Users\<name>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\*.automaticDestinations-ms`

**Signal:** Modifications to these jump list files indicate active GUI interaction with Windows Explorer and applications that contribute to jump lists.

**Required precondition:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackDocs` must be 1 (enabled). If 0 (disabled via Settings or Group Policy), absence of Recent\ updates is meaningless and the methodology cannot be applied to this machine.

**Interpretation when tracking enabled:**
- Non-zero `\Recent\AutomaticDestinations\` modify events = operator was likely using the GUI during the window
- Zero modify events across an active-use window = operator was NOT using the GUI (consistent with: away, sleeping, only using CLI-based tools, only using applications that bypass jump lists)
- Note: Absence does not prove operator was not present — operator may have used CLI tools, applications that bypass jump lists, or remote access tools that don't update local Recent\

### Application-specific Prefetch as operator-presence signal

**Path:** `\Windows\Prefetch\<application>.exe-<hash>.pf`

**Signal:** Prefetch modify counts for user-attributable executables (CHROME.EXE, FIREFOX.EXE, MSEDGE.EXE, WINWORD.EXE, EXCEL.EXE, code.exe, etc.) — elevated counts indicate sustained application activity.

**Required precondition:** Prefetch must not be disabled (rare but possible). Verify via registry: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters\EnablePrefetcher`.

**Interpretation:**
- High Prefetch modify count for user-attributable executable (>20 per workday) = sustained application activity consistent with user use
- Combined with background-only executable patterns in same archive = complete operator-presence picture
- See `PREFETCH@NightTalk` analysis material for the full executable categorization framework

### Combined methodology

The strongest operator-presence signal combines:
1. Recent\AutomaticDestinations updates (when tracking enabled)
2. User-attributable Prefetch executable activity
3. Network/logon events (event log)
4. Application-specific activity logs (browser history database, mail client logs)

No single signal is sufficient on a modern Windows system. Multiple confirming signals across categories produce defensible attribution.

## Multi-drive workstation pattern

**Signature:** Active workstation with file events distributed across multiple drive letters:
- C: at 90-99% (system drive, user profile root, AppData)
- E:, F:, H:, or similar at small percentages (1-3% each)

**Cause:** OEM-supplied OS drives (typically 500GB SSD as of 2025-2026) cannot accommodate accumulated user data without filling. Operators move user content (Documents, Downloads, Dropbox content, repositories, VM images, sync folders) to secondary larger drives to prevent OS drive exhaustion.

**Recognition:** This is OEM-constraint-driven, not anomalous behavior. The user profile root typically remains on C: (registry confirms via `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`); only individual special folders are relocated. The cause is hardware vendor decisions, not deliberate forensic anti-discovery.

**Common misattribution:** Assuming operator intent in the layout. User content on a non-system drive may suggest deliberate concealment when it is actually a response to vendor-imposed storage constraints. Verify operator hardware (OS drive size, total drive count, Windows license activation history) before drawing intent-based conclusions about drive layout.

## Code editors and development tools

### Python install (Microsoft Store version)

**Paths:**
- `\Program Files\WindowsApps\PythonSoftwareFoundation.Python.3.NN_<version>_x64__<id>\`
- `\Users\<name>\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.NN_<id>\`
- `\Users\<name>\AppData\Local\Python\pythoncore-3.NN-64\` (Python core files)

**Signature:**
- Heavy `.py` extension activity during install (typically 4,000–5,000 events)
- Create-dominated event mix (install pattern)
- `.pyc` extension activity (Python bytecode compilation)
- Burst-shaped, concentrated in install window
- Often accompanied by Microsoft.WindowsStore servicing in the same window

**Distinguishing markers:**
- `\pythoncore-3.NN-64\Doc\html\library\` (Python documentation install)
- `\pythoncore-3.NN-64\Lib\` (standard library files)
- `.tcl` extension activity (Tkinter / Python GUI library install)

**Common context:** This signature appears during initial usnmon deployment because usnmon requires Python. See "usnmon deployment-time signature" below for the expanded fingerprint.

### usnmon deployment-time signature

When usnmon is being deployed to a new machine for the first time, the operator typically performs in sequence:

1. Install Python (Store or installer-based)
2. `pip install pywin32` (Windows API bindings, required by usnmon)
3. `pip install python-evtx` or equivalent EVTX reader dependency
4. Deploy usnmon source files
5. Start the engine

This sequence produces a distinctive composite signature in the first archive (the initial dump):

**Paths visible:**
- Python install paths (per above)
- `\Users\<name>\AppData\Local\Programs\Python\Python3NN\Lib\site-packages\win32\` (pywin32 install)
- `\Users\<name>\AppData\Local\Programs\Python\Python3NN\Lib\site-packages\Evtx\` (python-evtx install)
- usnmon source location (wherever the operator placed it, often `C:\Monitor\` or similar)

**Event mix:**
- Heavy Create activity from package installation
- `.py`, `.pyc`, `.pyd` (Python extension modules) extension activity
- Microsoft Store servicing if Python was installed via Store

**Distinguishing markers:**
- Concentrated in a short pre-engine window
- All visible in the initial dump archive only
- Should NOT appear in subsequent steady-state archives (unless Python is updated)

**Common misattribution:** Treating the `.py` activity as "Python is being used" by the operator. Wrong — it is the deployment installation activity, not user Python work. See `LESSONS_LEARNED_to_avoid.md` Trap 8.

### Claude Code (Anthropic CLI agent)

**Paths:**
- `\Users\<name>\.claude\` (conversation state, project context)

**Signature:**
- Modest continuous activity during active session
- Conversation state persists between sessions

### Git, npm, pip, IDE caches

Various development tools leave fingerprints in their respective configuration directories under `\Users\<name>\AppData\`. Specific patterns vary by tool. When in doubt, identify the dominant directory's top-level user and check the operator's installed development tool inventory.

## How to add new fingerprints

When you encounter a directory talker not in this catalog:

1. Identify the application by the path's vendor/product name (often visible in the path itself)
2. Verify the application is actually installed on the captured machine
3. Document the event mix, file extensions, and any distinguishing markers
4. Note any common misattribution risks
5. Add to this catalog only after multi-capture verification — single-observation fingerprints may be operational-state-specific

## License and provenance

usnmon is a project of YASDC, licensed under PolyForm Noncommercial 1.0.0. This document is reference material for identifying application activity in usnmon output.
