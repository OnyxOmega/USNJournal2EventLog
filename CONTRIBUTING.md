# Contributing

Thanks for your interest in improving the USN Journal Monitor. This document
explains how to report issues, propose changes, and submit code.

By participating in this project you agree to abide by our
[Code of Conduct](CODE_OF_CONDUCT.md).

## Before you start

- **License:** this project is source-available under the PolyForm Noncommercial
  License 1.0.0. Contributions are accepted under the same terms, and a signed
  Contributor License Agreement ([CLA.md](CLA.md)) is required before any pull
  request can be merged (see "Contributor License Agreement" below).
- **Scope:** this is a Windows forensic/DFIR tool that reads the NTFS USN Change
  Journal and writes to a custom Windows Event Log. Changes should keep it
  headless-service-safe and avoid introducing non-Windows assumptions.

## Reporting bugs

Open an issue and include:

- Windows version/build and whether the volume is NTFS or ReFS
- How the service was run (service vs. `debug`), and the relevant
  `monitor_config.json` (redact paths if needed)
- Relevant lines from the diagnostic log `C:\FileSystem_Archives\usn_monitor.log`
  (run with the `USN_VERBOSE` environment variable set for counter stats)
- What you expected vs. what happened, and steps to reproduce

## Suggesting features

Open an issue describing the use case and the forensic/operational value. Note
whether it affects the event field contract (see "Schema" below), since that
has downstream impact on the EvtxECmd maps and SIEM parsing.

## Submitting changes

1. Fork the repository and create a branch from `main`.
2. Make focused commits with clear messages.
3. Keep changes minimal and well-commented; match the existing style (PEP 8,
   one-line docstrings on functions).
4. Verify before opening a PR (see "Testing").
5. Open a pull request describing **what** changed and **why**. Reference any
   related issue.
6. Sign the CLA if you have not already (a bot or maintainer will prompt you).

## Testing

This tool manipulates the live USN journal and the Windows Event Log, so test on
a disposable VM, not a production host.

- Syntax check: `python -m py_compile usn_monitor.py`
- Run foreground: `set USN_VERBOSE=1 && python usn_monitor.py debug`
- Generate file activity in a monitored path and confirm events land in the
  **FileSystem** log (`Get-WinEvent -LogName FileSystem -MaxEvents 5`)
- If you touched event fields, re-test the EvtxECmd maps end-to-end
  (parse to CSV, confirm the PayloadData columns populate in Timeline Explorer)
- Clear the log between clean runs: `wevtutil cl FileSystem`

## Schema (event field contract)

The order and names of event fields are a contract tracked by `SCHEMA_VERSION`.
If you add a field, bump the MINOR version (backward-compatible). If you rename,
remove, or reorder fields, bump the MAJOR version and update the EvtxECmd maps,
the `{PARAM[n]}` reference, and any SIEM parsing accordingly.

## Style

- Python 3, PEP 8, 4-space indentation
- One-line docstrings on every function/class (used by `help()`)
- Prefer standard library; new third-party dependencies need justification
- Keep the service path non-interactive (no prompts in service context)
