# SECURITY.md — Scope, Threat Model, and Honest Limitations

usnmon is a **logging and recording tool**. It is **not** a tamper-prevention or
intrusion-prevention tool. This document states plainly what usnmon does and does not
defend against, so it is never relied on for a guarantee it does not make. In a
forensic context, an honest scope statement is itself part of the tool's integrity.

## What usnmon is

A continuous recorder of NTFS USN-journal activity (and removable-device identity)
across all local volumes on a Windows host. It captures file create/modify/delete/
rename/security-change events and removable-media attach/detach/reformat events, writes
them to a dedicated event channel, periodically rotates that channel into timestamped
archives, and **hashes** each archive so its contents can later be verified against the
hash recorded at rotation time.

## What usnmon guarantees

1. **Continuous capture** of journaled file activity on monitored volumes, gap-free
   across engine restarts (a persisted cursor resumes where capture left off). When a
   gap is unavoidable — the engine was stopped long enough that journal records aged
   out — it is **recorded** as a resume-gap event (923), not silently skipped.

2. **Completeness visibility.** Every local volume receives exactly one disposition:
   monitored, or recorded as un-monitorable with the reason (no active journal /
   unsupported filesystem / remote share — events 919/920/921). Nothing is silently
   dropped. Removable devices that cannot be journaled still have their **identity**
   captured (500/501/503/504).

3. **Integrity evidence at rest.** Each archive is hashed (MD5, SHA-1, SHA-256,
   SHA-512) into a manifest bound *inside* the archive bundle. Anyone can later
   recompute the hash of the evidence file and confirm it **matches the hash recorded
   when the archive was written**.

4. **Self-recording of tampering.** Because usnmon captures file activity on the
   volumes it monitors — *including the activity of altering or deleting its own
   archives* — an attempt to modify or destroy evidence generates **new** records in
   the next archive. Erasing those records requires further file operations, which are
   themselves recorded, and so on. Quiet, selective tampering is therefore **evident**
   in the record even when it is not prevented.

## What usnmon does NOT guarantee — read this carefully

1. **It does not prevent tampering or destruction.** An actor with sufficient
   privilege on the host can alter or delete archives. usnmon will (per guarantee 4
   above) tend to *record* that this happened, but it does **not stop** it. The hashes
   prove an archive matches *a* recorded hash; they do not, by themselves, prove the
   archive was never replaced — see the next point.

2. **Hashing is integrity, not authenticity.** A hash proves "this file matches this
   hash." It does **not** prove the file is the *original* — an actor who alters an
   archive can recompute the hash and regenerate a self-consistent manifest.
   Cryptographic *authenticity* (proving the archive was produced by this tool and not
   altered since) requires signing with a key the actor does not control. **usnmon does
   not currently provide working archive signing.** A signing code path exists but is
   **not enabled and not relied upon**: an unprotected on-host private key would
   provide no real authenticity (anyone with the host has the key), so it is
   deliberately not used. Authenticity via a customer-owned external signing
   authority is a planned future capability; it is **not present today**. Do not rely
   on usnmon archives for cryptographic non-repudiation at this time.

3. **It does not defend against an active, destructive attacker with full control of
   the host.** This is **out of scope, by design.** An adversary who controls the
   machine, the network, and is willing to destroy data wholesale can defeat any
   on-host recorder. usnmon's value is against the far more common case — tampering
   that tries to be *quiet and selective* — which it makes evident. It does not claim
   to defeat an omnipotent, scorched-earth adversary, and any tool that did would be
   overpromising.

4. **It does not monitor what cannot be journaled.** Activity on exFAT/UDF/FAT volumes,
   network shares, and NTFS volumes without an active journal is not captured at the
   file level. usnmon records *that* these volumes were present and un-monitorable
   (and, for removable devices, *what* they were), but the file-level activity on them
   is invisible to it.

## Legal retention and deletion of evidence

usnmon keeps **everything by default** — no archive is ever deleted unless an operator
explicitly configures a retention term (`--legal-retention`, e.g. `25y` or `18M`).
When a term is set, retention exists to satisfy records-retention obligations (an
organization that may *not* keep data beyond a legal window), and it behaves
conservatively:

- It deletes only **whole, fully-expired archive bundles** — a month bucket is removed
  only once its entire month is older than the retention term, so a still-in-term day is
  never deleted.
- It **never trims, edits, or reopens a sealed archive.** Surviving archives keep their
  original bytes, hashes, and manifests intact. Retention prunes at the file level only.
- Pruning is an operator-configured policy, recorded in the log when it runs (so the act
  of deletion is itself part of the record up to the point the records age out).

This is deliberate: deleting evidence is sensitive, so the tool makes it opt-in,
coarse-grained (whole sealed bundles), and conservative (never deletes in-term data).

## The honest summary

usnmon answers the question **"what happened on this system's files, and can I trust
that the record I'm holding matches what was recorded?"** It does not answer **"can I
cryptographically prove no one ever altered this evidence?"** — not yet. It records
tampering; it does not prevent it. It is a witness, not a guard. Used as a witness,
with its limitations understood, it is sound. Relied on as a guard, it would fail —
because that is not what it is.

## Reporting

This is non-commercial software (PolyForm Noncommercial 1.0.0) maintained by YASDC,
Inc. There are currently no users besides the developer. If that changes and you find
a security issue, the appropriate channel will be documented here.
