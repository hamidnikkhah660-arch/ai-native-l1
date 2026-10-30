# CP-0455 — QRun v0.5 PFS2 external-CAS commit protocol candidate

**Date:** 2026-10-28
**Status:** Local protocol candidate and failure-injection tests pass. This is not a deployed independent anchor service and does not activate Mainnet.

## Transaction protocol

QRun's `QRunV05ExternalCasForkStore` is a separate API over the profile-locked QFP5/PFS2 store. Its writer path is:

1. Read and cryptographically verify a fresh provider receipt for the exact current ECR1 record and immutable object generation.
2. Validate a QFP5 block in a cloned fork-choice archive and produce the full next PFS2 manifest without publishing it.
3. Durably stage any new branch plus a domain-separated, bounded `QAP1` pending record containing the previous ECR1 record, exact successor ECR1 record, and exact next manifest.
4. Send the immutable write request to `VerifiedExternalCasClient`. The provider must execute an atomic server-side compare-and-swap and sign its receipt with the pinned ML-DSA-65 key.
5. Publish the PFS2 manifest only after the signed CAS receipt verifies. Then publish in-memory fork-choice state and update the current trusted record.

## Recovery cases

- **Provider rejects before commit:** a new signed read must prove the provider still holds the previous record. The pending file is removed, old manifest/state/anchor remain active, and submit returns an error.
- **Provider commits but its response is lost:** a fresh signed read resolves the ambiguity only if it returns the exact pending successor. Recovery publishes precisely the manifest named by that record and removes `QAP1`.
- **Process exits after remote CAS but before local manifest replacement:** reopen takes the writer lock, reconciles `QAP1` before manifest replay/orphan cleanup, verifies the provider's signed record and publishes the exact prepared manifest.
- **Any third state, wrong domain, invalid signature, rollback, malformed pending file or unavailable provider:** recovery fails closed; the code must not guess success or roll the external floor backward.

The manifest writer now syncs the temporary file before replacement and requests parent-directory sync after replacement. Pending files use bounded parsing, a versioned magic, domain-separated checksum, canonical re-encoding and exact prior/successor linkage.

## Test evidence

- Local mock CAS performs real Ed25519-independent ML-DSA-65 signatures using the pinned Libcrux candidate verifier and the exact ECR1/receipt verification contract.
- `qrun_external_cas_store_resolves_lost_receipt_and_reopens_on_signed_anchor` covers CAS success with a lost response followed by signed-read reconciliation and restart.
- `qrun_external_cas_open_recovers_crash_after_remote_commit_before_local_manifest` seeds the crash window directly and proves the exact next manifest is recovered.
- `qrun_external_cas_rejection_keeps_old_manifest_and_removes_pending` proves a provider rejection that leaves remote state unchanged does not publish the candidate block or modify the current anchor.
- Each test uses the exact 10B QRun candidate Genesis and asserts total value remains 1,000,000,000,000,000,000 atoms.

## Deployment limitations and release gates

The current test provider is an in-process test fixture, not a production cloud service. Production must provide an independently administered atomic-CAS service, out-of-band pinned provider identity and ML-DSA-65 receipt key, durable off-machine storage of the latest trusted ECR1 record/object-generation floor, bootstrap ceremony for the initial Genesis manifest anchor, and monitoring/rotation/recovery procedures. The client cannot prove provider independence by itself, and a same-machine floor does not resist whole-machine snapshot rollback.

The wrapper deliberately requires the caller to supply the latest independently retained signed record and provider pin on open. A caller must durably store the returned updated record outside the PFS2 directory. Checkpoint rollover, automatic full-history pruning, multi-region/provider failure testing, real independently operated multi-host QFP5 networking, production difficulty/MTP settings, independent security audit and owner verification are still open.

Do not expose the loopback-only smoke binary. Do not treat the candidate Genesis or these local tests as proof that public 10B QZXB are already spendable.