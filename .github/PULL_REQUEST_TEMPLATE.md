## Description

<!-- What does this PR change, and why? -->

Fixes #<!-- issue number, if applicable -->

## Type of change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that changes existing behavior)
- [ ] Documentation only
- [ ] Refactor / internal cleanup (no behavior change)

## Event field contract (schema)

<!-- The order/names of event fields are tracked by SCHEMA_VERSION. -->

- [ ] This PR does **not** change event fields.
- [ ] This PR **adds** a field (MINOR schema bump) and I updated the EvtxECmd
      maps, the {PARAM[n]} reference, and any SIEM parsing.
- [ ] This PR **renames/removes/reorders** fields (MAJOR schema bump) and I
      updated all of the above.

## Testing

<!-- This tool manipulates the live USN journal and Windows Event Log. -->

- [ ] Tested on a disposable VM, not a production host.
- [ ] `python -m py_compile usn_monitor.py` passes.
- [ ] Ran `python usn_monitor.py debug` (with `USN_VERBOSE=1`) and confirmed
      events land in the FileSystem log.
- [ ] If event fields changed, re-tested the EvtxECmd maps end-to-end
      (CSV -> Timeline Explorer columns populate).

**Test environment:** <!-- Windows build, NTFS/ReFS, single/multi-drive -->

## Checklist

- [ ] My code follows the project style (PEP 8, one-line docstrings).
- [ ] I commented anything non-obvious; no debug/dead code left in.
- [ ] I updated documentation where relevant (README / FEATURES / DEPLOYMENT).
- [ ] I have signed the Contributor License Agreement (CLA.md).
