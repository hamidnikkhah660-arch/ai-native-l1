# CP-0471 — QRun External-CAS Independent Floor and Runtime Binding

Date: 2026-10-30

Status: **A separate QCF1 floor store is implemented and bound to the wallet-aware external-CAS fork-store open and commit paths. Local Windows tests pass, including the floor-ahead crash window and rollback of the mutable node archive. This is still a single-host floor candidate, not an off-host or hardware monotonic anchor, and the node executable is not yet configured to use a remote provider at startup.**

## Problem

CP-0470 added a durable filesystem implementation for the external-CAS provider. The node-side CAS store already exposed the last trusted ECR1 record and provider object generation, but callers had to persist those values outside the mutable PFS2 archive themselves. Without a dedicated floor, restoring an older node data directory could also restore its old trusted record and make the node forget a previously observed provider generation.

## QCF1 floor store

1. Added the external_cas_floor_store_candidate module and registered it in the crate.
2. QCF1 is a fixed-width 480-byte state file. It binds the provider ID, Network ID, wallet-bound Genesis digest, receipt key ID, hash of the pinned ML-DSA-65 receipt public key, provider object generation and exact ECR1 record, with a domain-separated SHA-256 checksum.
3. ExternalCasFloorStore::initialize is explicit and create-once. It accepts only ECR1 generation zero at provider object generation one, matching the complete ExternalCasPin.
4. open never creates a missing floor. A missing state with the persistent writer-lock marker, a corrupt state, a symlink, or a mismatched provider/network/Genesis/key pin fails closed.
5. snapshot returns the trusted ECR1 record and minimum provider object generation under the OS-backed writer lock.
6. advance requires the exact currently persisted predecessor and one cryptographically linked ECR1 successor. Both logical record generation and provider object generation must advance exactly one. Exact retry is idempotent; stale writers, skipped generations and changed predecessor links are rejected.
7. reconcile_verified_observation accepts the same record or one exact successor only. Its caller must first authenticate the provider response with VerifiedExternalCasClient; the floor file itself does not verify remote signatures.
8. Floor writes use a unique temporary file, flush/sync, atomic replacement and parent-directory sync on supported targets. Separate writers wait for a bounded two-second lock window and then fail closed.

## Runtime binding and commit order

Added strict owner-aware constructors:

- QRunV05ExternalCasForkStore::open_for_owner_genesis_with_floor
- QRunV05ExternalCasForkStore::open_from_checkpoint_with_parent_for_owner_genesis_and_floor

Both take the provider pin and a separately opened floor, read the floor snapshot, open the ordinary or checkpoint-rooted CAS store with that trusted record/object-generation minimum, reconcile at most one verified provider successor, and retain the floor for subsequent commits.

With a floor attached, submit follows this order:

1. Verify the current signed provider observation and candidate block as before.
2. Persist QAP1, which names the exact old record, successor record and next PFS2 manifest.
3. Perform the provider atomic CAS and verify its signed receipt (or resolve an ambiguous result with a fresh signed read).
4. Advance the independent QCF1 floor to the exact successor.
5. Only then publish the local PFS2 manifest and in-memory branch state.

If floor persistence fails after the provider has committed, QAP1 remains available and the current store instance is blocked from further writes. It must be reopened and reconciled; it does not fall back to local-only writes. If a crash occurs after floor advancement but before local manifest publication, startup uses the retained pending record and a fresh verified provider read to publish only the exact named manifest.

Existing compatibility constructors remain available for tests and historical callers without a floor. A public node deployment must use the new floor-bound constructors; merely adding a floor directory to disk does not automatically enable it.

## Local validation

- Stable Rust formatting: PASS.
- Floor-store tests cover create-once initialize, reopen, complete pin binding, missing/corrupt state, no silent rebootstrap, exact monotonic advance, idempotent retry, stale and skipped generations, verified-observation reconciliation and simultaneous competing writers.
- Wallet-bound integration test exercises a lost provider response through QRunV05PowForkRuntime, verifies that the QCF1 floor reaches the committed ECR1 record/object generation, and proves that a Genesis-only restored PFS2 archive cannot reopen while the separate floor is ahead.
- Crash-window integration test simulates provider CAS and floor advancement with QAP1 durable but the local PFS2 manifest still old. Restart through the floor-bound constructor recovers the exact pending successor and preserves the advanced floor.
- Full 949-test library suite and cargo check --all-targets are re-run for the exact final source before this CP is committed.

## Security boundary and remaining gates

- The QCF1 floor is a separate local filesystem state. It can detect rollback of the node archive only while the floor and its persistent lock marker remain intact and are not rolled back together.
- It does not prevent an administrator or attacker from restoring the entire host, floor directory and provider state from a common old backup. Production still requires a separately administered off-host monotonic anchor, TPM/HSM-backed floor or another independently protected recovery domain.
- The checksum detects accidental corruption; it is not a MAC or signature. Restrictive OS ACLs and separate administration are required.
- ExternalCasFloorStore::advance is a persistence primitive. Production callers must only advance it using an ECR1 record/object generation authenticated by VerifiedExternalCasClient; unverified provider data must never be passed to it.
- ML-DSA-65 receipt signatures authenticate receipts, but the current Noise XX channel remains classical X25519/ChaChaPoly, not post-quantum or hybrid.
- The QRun node executable still opens its local runtime store. It does not yet load a signed provider endpoint/configuration bundle, provider Noise server key pin, independent receipt-key pin, client key, bootstrap record or floor directory at startup. No production block acceptance path is yet wired to an independently deployed provider.
- The provider service itself is not deployed or verified under a separate operator. No public listener or firewall rule has been enabled.
- Provider backup rollback, separate-operator controls, off-host floor recovery, key rotation, equivocation, filesystem fault injection and independent security review remain release gates.

**Decision:** CP-0471 closes the local node-archive rollback gap when an independently retained QCF1 floor is used and verifies the floor-ahead crash window. It does not qualify a remote provider deployment or authorize Mainnet. Keep QRUN_MAINNET_RELEASE_APPROVED = false, keep public mint disabled, and do not claim a live QZXB/USDT market.
