# Deployment — Fleet Rollout & WEF → WEC

This is a process checklist for deploying the USN Journal Monitor across many
machines and centralizing its `FileSystem` events to a collector.

There are **two independent tracks**. Do them in this order, verifying each before
moving on:

- **Track 1 — Agent deployment:** get `usn_monitor` installed and running as a
  service on every endpoint.
- **Track 2 — WEF → WEC:** forward each endpoint's `FileSystem` events to a central
  Windows Event Collector.

> Version note: exact Group Policy paths and tool switches vary slightly by Windows
> build. Verify the policy names below against your OS version; the mechanics are
> stable but labels move.

---

## Architecture (source-initiated WEF)

```
[ Endpoints (sources) ]                         [ Collector (WEC) ]
  usn_monitor service  --writes-->  FileSystem log
  WinRM (push)         --forwards (HTTP/5985, Kerberos)-->  WEC service
                                                            ForwardedEvents log
                                                            -> EvtxECmd + maps
                                                            -> Timeline Explorer / SIEM
```

**Source-initiated** (push) is recommended over collector-initiated (pull): it
scales to large fleets, is configured entirely by GPO, and new machines enroll
automatically when they fall in scope. Endpoints connect *out* to the collector,
so the collector needs no inbound account on each source.

---

## Prerequisites

- [ ] A domain (Active Directory). Source-initiated WEF uses Kerberos for auth.
- [ ] A designated **collector server** (member server; size for fleet volume —
      USN can be chatty, so plan disk for the `ForwardedEvents` log).
- [ ] Time sync across the domain (Kerberos + forensic timelines both depend on it).
- [ ] Decision: deploy the agent as a **frozen `.exe`** (recommended — no Python on
      endpoints) or as `.py` + Python. The rest of this assumes a signed `.exe`.

---

## Track 1 — Agent fleet deployment

### 1A. Build & sign (once, on a build box)

- [ ] Freeze: `pyinstaller --onefile --hidden-import win32timezone usn_monitor.py`
- [ ] **Code-sign** `usn_monitor.exe` (Authenticode). A `LocalSystem` service that
      reads the raw USN journal *will* trip Defender/SmartScreen unsigned, and the
      security-conscious audience won't run it.
- [ ] Stage a standardized `monitor_config.json` (the fleet-wide whitelist +
      retention policy) on a SYSVOL or distribution share.
- [ ] Place both on the share, e.g. `\\domain\sysvol\<dom>\scripts\usnmon\`.

### 1B. Choose a delivery method

Pick ONE (top to bottom = simpler to more managed):

**Option A — GPO Startup Script (simplest).** A startup script (runs as SYSTEM)
copies the exe + config locally and installs/starts the service if absent.

- [ ] Computer Config → Policies → Windows Settings → Scripts → **Startup**
- [ ] Point it at an **idempotent** script (see template below).
- [ ] Target via the GPO's OU link / security filtering.

**Option B — Group Policy Preferences (GPP).** Declarative, item-level targeting.

- [ ] GPP **Files**: copy `usn_monitor.exe` + `monitor_config.json` to
      `C:\Program Files\USNMonitor\`.
- [ ] GPP **Scheduled Task** (run as SYSTEM, trigger At startup): install + start
      the service if not present.
- [ ] (Optional) GPP **Registry**: pre-set `EventMessageFile` and/or a machine-wide
      `USN_VERBOSE` if desired.

**Option C — MSI via GPO Software Installation.** Package the exe in an MSI (WiX /
Advanced Installer) whose custom action registers the service.

- [ ] Build MSI; service install/remove as install/uninstall custom actions.
- [ ] Computer Config → Policies → Software Settings → **Software installation** →
      assign the MSI.

**Option D — SCCM / Intune.** Package exe as a Win32 app.

- [ ] Install command: `usn_monitor.exe --startup delayed install` then `start`.
- [ ] Detection rule: service `USNMonitorService` exists.
- [ ] Uninstall command: `usn_monitor.exe stop` then `remove`.

### 1C. Idempotent startup-script template (Option A)

```bat
@echo off
set DST=C:\Program Files\USNMonitor
set SRC=\\domain\sysvol\<dom>\scripts\usnmon

if not exist "%DST%" mkdir "%DST%"
copy /Y "%SRC%\usn_monitor.exe" "%DST%\" >nul
copy /Y "%SRC%\monitor_config.json" "%DST%\" >nul

sc query USNMonitorService >nul 2>&1
if %errorlevel%==0 goto :running
"%DST%\usn_monitor.exe" --startup delayed install
:running
sc start USNMonitorService >nul 2>&1
exit /b 0
```

### 1D. Verify Track 1

- [ ] On a sample endpoint: `sc query USNMonitorService` → STATE: RUNNING.
- [ ] `type C:\FileSystem_Archives\usn_monitor.log` shows the journal/host-context
      startup lines.
- [ ] Trigger a change in a monitored path; confirm an event in the local
      **FileSystem** log (`Get-WinEvent -LogName FileSystem -MaxEvents 5`).

**Do not start Track 2 until a sample endpoint is producing local events.**

---

## Track 2 — WEF → WEC

### 2A. Prepare the collector

- [ ] On the collector server, run once (elevated): `wecutil qc`
      (enables the Windows Event Collector service + WinRM listener).
- [ ] Confirm the `Windows Event Collector` (wecsvc) service is running/auto.
- [ ] Plan the target log: default is **ForwardedEvents**. For high volume,
      consider increasing its max size or pointing the subscription at a custom log.

### 2B. Configure sources via GPO

Create/edit a GPO linked to the endpoints' OU:

- [ ] **WinRM service:** set `Windows Remote Management (WS-Management)` to
      Automatic start (Preferences → Services, or the WinRM policy).
- [ ] **Target Subscription Manager:** Computer Config → Policies → Admin Templates
      → Windows Components → **Event Forwarding** → *Configure target Subscription
      Manager* → Enabled → add:
      `Server=http://collector.fqdn:5985/wsman/SubscriptionManager/WEC,Refresh=60`
- [ ] **Forwarder read access to the custom log (KEY GOTCHA):** the forwarder reads
      source channels as **NETWORK SERVICE**. The custom `FileSystem` log is not
      covered by the default `Event Log Readers` grant the way the built-in logs
      are. Grant read access on each source (deploy via GPP/script):
      ```
      wevtutil gl FileSystem            :: view current channel SDDL/access
      wevtutil sl FileSystem /ca:"<existing SDDL>(A;;0x1;;;NS)"
      ```
      `(A;;0x1;;;NS)` grants NETWORK SERVICE read. Without this, the subscription
      shows "Active" but forwards **zero** events from the custom channel.
- [ ] **Firewall:** allow outbound HTTP 5985 from sources to the collector (HTTPS
      5986 if you use certificate transport instead of Kerberos).

### 2C. Create the subscription (source-initiated)

On the collector, author `usn-subscription.xml` and register it with
`wecutil cs usn-subscription.xml`:

```xml
<Subscription xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription">
  <SubscriptionId>USN-FileSystem</SubscriptionId>
  <SubscriptionType>SourceInitiated</SubscriptionType>
  <Description>USN Journal Monitor file-change events</Description>
  <Enabled>true</Enabled>
  <Uri>http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog</Uri>
  <ConfigurationMode>Custom</ConfigurationMode>
  <Delivery Mode="Push">
    <Batching>
      <MaxItems>50</MaxItems>
      <MaxLatencyTime>30000</MaxLatencyTime>
    </Batching>
  </Delivery>
  <Query>
    <![CDATA[
      <QueryList>
        <Query Id="0">
          <Select Path="FileSystem">*[System[(EventID&gt;=100 and EventID&lt;=106)]]</Select>
        </Query>
      </QueryList>
    ]]>
  </Query>
  <ReadExistingEvents>true</ReadExistingEvents>
  <TransportName>HTTP</TransportName>
  <ContentFormat>Events</ContentFormat>
  <Locale Language="en-US"/>
  <LogFile>ForwardedEvents</LogFile>
  <AllowedSourceNonDomainComputers></AllowedSourceNonDomainComputers>
  <AllowedSourceDomainComputers>O:NSG:NSD:(A;;GA;;;DC)(A;;GA;;;NS)</AllowedSourceDomainComputers>
</Subscription>
```

Notes on the choices:
- [ ] `Select Path="FileSystem"` targets the custom channel; the XPath limits to
      Event IDs 100–106.
- [ ] `ContentFormat=Events` keeps records lean and preserves `EventData` (so the
      EvtxECmd maps and SIEM extraction work). Use `RenderedText` only if you need
      the human-readable description carried along.
- [ ] `ReadExistingEvents=true` pulls already-logged events on enrollment — useful
      for IR (captures the retroactive USN history already in the local log).
- [ ] `MaxLatencyTime` (ms) trades latency vs. batching. Lower it (e.g. 5000) for
      near-real-time IR; raise it to reduce chatter.
- [ ] `AllowedSourceDomainComputers` SDDL: `(A;;GA;;;DC)` = Domain Computers. Scope
      tighter with a dedicated group SID for a controlled rollout.

### 2D. Verify Track 2

- [ ] On a source: `Event Viewer → Applications and Services Logs → Microsoft →
      Windows → Eventlog-ForwardingPlugin → Operational` — look for successful
      subscription pickup (Event 100) and no errors.
- [ ] On the collector: `wecutil gr USN-FileSystem` (get runtime status) → sources
      listed as **Active**.
- [ ] On the collector: `Get-WinEvent -LogName ForwardedEvents -MaxEvents 20` —
      confirm USN events arriving, each stamped with its source **Computer**.
- [ ] Parse the collected log end-to-end:
      `EvtxECmd.exe -f ForwardedEvents.evtx --csv C:\out --csvf usn.csv` with the
      maps installed → open in Timeline Explorer; confirm `TargetFilename` /
      `UtcTime` / `Computer` columns populate across multiple hosts.

---

## Operations & scaling

- [ ] **Health:** periodically check `wecutil gr <sub>` for sources dropping to
      Inactive (indicates WinRM/network/permission drift on that host).
- [ ] **Collector disk:** the `ForwardedEvents` log grows with fleet activity; size
      it and/or archive it on the collector the way the agent archives locally.
- [ ] **Multiple collectors:** for large fleets, point OUs at different collectors
      (load distribution) or use a collector per site to keep forwarding local.
- [ ] **Config changes:** push an updated `monitor_config.json` via the same Track-1
      mechanism, then restart the service fleet-wide (the agent reads config at
      startup only).
- [ ] **Node counting / licensing:** distinct source **Computer** (or MachineGuid in
      the event data) on the collector = nodes in use — the air-gap-friendly meter.

---

## Troubleshooting quick reference

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| Subscription "Active", 0 events from `FileSystem` | Forwarder lacks read on custom channel | Grant `(A;;0x1;;;NS)` on `FileSystem` (2B) |
| Source never enrolls | WinRM not running / GPO not applied | Start WinRM; `gpupdate /force`; check 5985 reachability |
| Source Inactive in `wecutil gr` | Kerberos/SPN or firewall | Verify time sync, DNS, outbound 5985 |
| Events arrive but columns blank in TLE | Maps not installed / wrong positions | Install maps; confirm `SchemaVersion`/`Data[N]` order |
| Local events fine, none forwarded | Subscription XPath/channel mismatch | Confirm `Select Path="FileSystem"` and ID range |

---

## Quick command index

```
:: Collector
wecutil qc                         :: enable collector service
wecutil cs usn-subscription.xml    :: create subscription
wecutil gr USN-FileSystem          :: runtime status (source health)
wecutil ss USN-FileSystem /e:false :: disable; /e:true to re-enable
wecutil ds USN-FileSystem          :: delete subscription

:: Source
wevtutil gl FileSystem             :: view channel access (SDDL)
wevtutil sl FileSystem /ca:"...(A;;0x1;;;NS)"   :: grant forwarder read
gpupdate /force                    :: apply GPO
Get-WinEvent -LogName FileSystem -MaxEvents 5   :: confirm local events
```
