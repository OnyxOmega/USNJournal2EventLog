# Security Policy

The USN Journal Monitor is a forensic/DFIR agent that runs with high privilege
(reads the raw NTFS USN journal and writes to a custom Windows Event Log). We
take security reports seriously and appreciate responsible disclosure.

## Reporting a Vulnerability

**Please do not open a public issue for security vulnerabilities.** A public
report can expose users of a security-monitoring agent before a fix is available.

Report privately using **one** of these:

1. **GitHub Private Vulnerability Reporting** (preferred): on this repository, go
   to the **Security** tab and click **"Report a vulnerability."** This opens a
   private advisory visible only to you and the maintainers.
2. **Email:** send details to **[INSERT SECURITY CONTACT EMAIL]**. If you wish to
   encrypt, request our public key in your first message.

Please include, where possible:

- A description of the issue and its impact
- The Windows version/build and whether the volume is NTFS or ReFS
- Steps to reproduce, proof-of-concept, or affected code paths
- Any relevant configuration (`monitor_config.json`) and log excerpts
  (redact sensitive paths)

## What to Expect

- **Acknowledgement:** we aim to acknowledge a report within a few business days.
- **Assessment:** we will investigate, confirm the issue, and keep you updated on
  progress and expected timelines.
- **Fix & disclosure:** once a fix is ready, we will coordinate a disclosure date
  with you. We are happy to credit you in the advisory and release notes unless
  you prefer to remain anonymous.
- **Scope note:** this is a community/source-available project; we do not operate
  a paid bug-bounty program and cannot guarantee monetary rewards.

## Supported Versions

Until a formal release cadence is established, security fixes are applied to the
**latest `main`** branch. Users should track the most recent commit/release.

| Version            | Supported          |
| ------------------ | ------------------ |
| latest `main`      | :white_check_mark: |
| older revisions    | :x:                |

## Out of Scope

The following are generally **not** considered vulnerabilities in this project:

- Issues requiring the attacker to already have Administrator/SYSTEM on the host
  (the agent is installed and runs at that privilege by design)
- Event log volume/noise from a deliberately broad `--all` or root selection
- Findings in third-party dependencies (report those upstream), unless this
  project uses them in an insecure way
- Social-engineering or physical-access scenarios

## A Note on Scanners

Because this tool legitimately reads raw volume data and writes Windows event
logs, endpoint security products may flag it. That behavior is by design and is
not, by itself, a vulnerability. Genuine security issues (privilege escalation,
unsafe file handling, injection into the event pipeline, etc.) are in scope.
