# CP-0707 — Read-only C:/D: Peer Identity Reconciliation

Date: 2026-11-16
Project: AI-NATIVE L1 / QRun / QZXB / QFP6
Branch: feat/cp0704-dual-attestation-rotation-gate-20261116
Worktree: D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116
Base commit: 5aba5f69d24fce03af742fd1bebf13ad00e5d9c3
Status: READ-ONLY COMPARISON API IMPLEMENTED; TARGETED TESTS PASS; NOT NODE-INTEGRATED

## 1. Scope

CP-0707 adds a read-only reconciliation decision layer between:
- the independent peer identity anchor chain represented by PeerIdentityAnchorVault; and
- the issuer-signed identity generation high-water represented by IdentityGenerationStateStore.

New module:
src/native/pow_bench/src/peer_identity_reconciliation.rs

The module is exported from lib.rs. It does not open paths itself, create directories, write records, reconcile generations, activate a peer identity, or authorize a listener.

## 2. Read-only bindings

IdentityGenerationStateStore now exposes high_water_binding(), returning the in-memory persisted tuple:
- generation;
- SHA-256 digest of the exact KeyRecord bytes accepted by observe_signed_record;
- lifecycle state byte.

PeerIdentityAnchorVault now exposes:
- active_record_binding(): generation, canonical KeyRecord digest, lifecycle of the latest ACTIVE event;
- pending_generation(): the successor generation if the latest event is PREPARED.

These are read-only accessors. The existing writer locks remain held by their respective store objects.

## 3. Comparison contract

compare_peer_identity_state() enforces:

- Missing/un-enrolled C: anchor -> AnchorNotEnrolled.
- Uninitialized D: high-water -> GenerationStoreUninitialized.
- Exact active generation, exact KeyRecord digest, and exact lifecycle -> Synchronized.
- A C: PREPARED successor is reported as RotationPrepared only if D: still matches the exact preceding ACTIVE tuple and the prepared generation is exactly active + 1.
- D: already advanced to the PREPARED generation before C: records activation -> DAdvancedBeforeAnchorActivation.
- Any generation gap/rollback, same-generation digest change, or lifecycle mismatch -> explicit error.

No mismatch is repaired automatically. This module deliberately cannot choose C: or D: as a replacement source of truth.

## 4. Validation

Targeted reconciliation tests:
cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib peer_identity_reconciliation -- --nocapture

Result: 9 passed, 0 failed: six comparison-helper tests plus three temporary-directory tests using both actual store implementations.

Existing identity-generation store regression tests:
cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib identity_generation_store::tests -- --nocapture

Result: 5 passed, 0 failed.

Existing peer identity vault regression tests:
cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib peer_identity_anchor_vault::tests -- --nocapture

Result: 9 passed, 0 failed.

Formatting and whitespace:
- cargo fmt --manifest-path src/native/pow_bench/Cargo.toml --all -- --check: PASS
- git diff --check: PASS (only existing LF-to-CRLF working-copy notices; no whitespace error).

The six comparison-helper tests exercise exact synchronization, PREPARED-but-not-active state, missing anchor, uninitialized D state, D advancing before C activation, generation gaps, unexpected prepared generations, same-generation digest mutation, and lifecycle mutation. Three additional temporary-directory tests use actual PeerIdentityAnchorVault and IdentityGenerationStateStore instances: (1) verify synchronization, persist PREPARED, advance D using a synthetic issuer-signed NRT1, confirm fail-closed divergence, then reopen both stores and confirm the divergence remains detectable; (2) persist a same-generation digest mismatch and confirm RecordDigestMismatch; and (3) persist a same-generation retired record in D while C retains an ACTIVE lifecycle binding to that exact record digest, isolating and confirming LifecycleMismatch. All fixture paths and signer material are synthetic and isolated.

## 5. Important limitations

This checkpoint is a read-only comparison primitive, not a complete cross-volume coordinator.

Not yet implemented or verified:
- production integration is still absent; the temporary-directory integration fixture is test-only and uses synthetic records and signer material;
- provisioning and ACL qualification of the real C: vault directory;
- physical-volume identity verification;
- startup ordering before Noise listener creation;
- any C:/D: write or recovery protocol;
- crash-injection and partial-write recovery;
- TPM monotonic counter or remote witness.

IdentityGenerationStateStore::open retains its existing behavior: if both its state file and stable lock file are absent, it creates an empty high-water state. The reconciliation API reports that state as uninitialized; callers must not mistake opening such a store for proof that an identity was enrolled. Do not use this behavior to recreate a missing C: anchor.

## 6. Safety and repository boundary

- Only synthetic unit-test tuples were used for the reconciliation decision tests.
- No real C: or D: store was opened, initialized, or changed.
- No production/user private key or identity was accessed.
- No node, listener, testnet, or mainnet was started or activated.
- No commit, push, merge, PR update, or release was performed.
- Work remains isolated in the CP-0704 worktree; original checkout remains separate.

## 7. Next step

The next engineering step is to design and independently review the two-volume crash/recovery protocol, physical-volume identity checks, and independent pin provenance before considering startup-gate integration. Keep the coordinator read-only; do not point it at real C: or D: paths and do not wire it into node startup yet.

