# CP-0706 — Peer Identity Anchor Vault Persistence Primitive

Date: 2026-11-16
Project: AI-NATIVE L1 / QRun / QZXB / QFP6
Branch: feat/cp0704-dual-attestation-rotation-gate-20261116
Worktree: D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116
Base commit: 5aba5f69d24fce03af742fd1bebf13ad00e5d9c3
Status: LOCAL PERSISTENCE PRIMITIVE IMPLEMENTED AND TARGETED TESTS PASS; NOT NODE-INTEGRATED; NO COMMIT OR PUSH

## 1. Scope and relationship to CP-0705

CP-0705 defined the lifecycle and recovery requirements for a distinct peer-identity anchor chain. CP-0706 implements the first isolated persistence primitive in:

src/native/pow_bench/src/peer_identity_anchor_vault.rs

The crate exports it through src/native/pow_bench/src/lib.rs as peer_identity_anchor_vault.

This is not the existing QFP6 manifest Anchor Vault, and it does not modify its record directory or parser. It is not yet wired to IdentityGenerationStateStore, the QFP6 node startup path, a listener, or rotate-peer activation. It is deliberately a persistence/API foundation only.

## 2. Persisted scope

The immutable scope digest commits to:
- network ID;
- QFP6 profile ID;
- QFP6 genesis/root anchor identity;
- peer role;
- issuer ID and issuer public-key SHA-256 fingerprint;
- key purpose;
- credential ID;
- key ID.

Zero/absent scope values are rejected. open requires an absolute path to an already-existing directory; it does not create a missing vault or infer an enrollment baseline from D:.

The root directory must be provisioned and protected by a separate reviewed procedure. This primitive does not itself prove that the selected path is on C:, validate physical-volume identity, or verify Windows ACLs.

## 3. Event and wire format

The append-only event chain uses:
- magic PIV1, wire version 1;
- domain-separated SHA-256 digest under AI-NATIVE-L1-PEER-IDENTITY-ANCHOR\0v1;
- monotonically numbered event-<20-digit-sequence>.piv1 files;
- exact fixed-length records, bounded event count, contiguous sequence checks, and predecessor vault-record digest checks.

Each event binds:
- event kind, peer identity generation, previous generation, and lifecycle;
- current Noise public-key SHA-256 fingerprint;
- exact current NPI1 artifact digest and canonical KeyRecord digest;
- previous generation's canonical KeyRecord digest (zero only for initial enrollment);
- NRT1 transition digest (zero only for initial enrollment);
- dual-attestation intent digest and nonce for rotations;
- owner and independent operator signer-pin fingerprints;
- immutable network/profile/genesis/role/issuer/credential/key/purpose scope digest;
- predecessor vault-record digest and this event's domain-separated digest.

The previous KeyRecord digest is checked against the previous active event's KeyRecord digest. It is distinct from the predecessor vault-record digest used to chain the event files.

## 4. Lifecycle behavior implemented

- open: validates the existing event chain from the genesis event, rejects gaps, malformed records, scope mismatch, tampering, invalid transitions, and symlink/non-regular event entries.
- enroll_genesis: permits only an explicit initial active baseline. Enrollment requires non-zero and distinct owner/operator pin fingerprints; there is no automatic enrollment on open.
- prepare_rotation: permits only the exact immediate successor; requires non-zero rotation evidence/intent/nonce/pin values; requires the prior KeyRecord digest to match the active predecessor; and requires signer pins to remain identical to the genesis pins.
- Exact re-submission of the latest PREPARED event is idempotent, including after reopen.
- Reuse of a consumed nonce with altered content is rejected. A second, different PREPARED rotation is rejected while one is pending.
- activate_prepared: appends an ACTIVE event only for the exact latest PREPARED nonce. Exact retry while that activation is still the latest event is idempotent.
- active_generation intentionally remains at the previous ACTIVE generation while a successor is PREPARED.

The stable SnapshotWriterLock sibling is held for the vault object's lifetime. A second simultaneous writer open is rejected with PeerAnchorError::Locked. Event files use create_new so an existing sequence file is never overwritten, and the record is sync_all'd before the in-memory tip advances.

## 5. Targeted tests and validation

Command:

cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib peer_identity_anchor_vault -- --nocapture

Latest result: 9 passed, 0 failed.

The nine tests cover:
1. explicit enrollment and reopen/high-water persistence;
2. durable nonce, exact idempotent retry, conflicting nonce reuse rejection, and pending-rotation exclusion;
3. exact-nonce activation and idempotent activation retry;
4. tampered-chain rejection;
5. scope mismatch (including issuer public-key fingerprint);
6. rejection of invalid transitions before a file is created, including changed previous-record digest and changed signer pin;
7. no self-enrollment of an empty vault;
8. exclusive writer-lock contention and clean reopen after release;
9. next generation can be prepared only after the previous generation is active, with correct previous-record digest.

Also passed:
- cargo fmt --manifest-path src/native/pow_bench/Cargo.toml --all -- --check
- git diff --check

The git diff --check output included only Git line-ending notices (LF may be converted to CRLF); it emitted no whitespace-error failure.

Previously validated CP-0704 suites remain documented in CP-0704: Provisioner handler suite 20/20, standalone verifier suite 6/6, and the earlier targeted cargo check --bin devnet_trust_provisioner.

## 6. Explicit security boundaries / remaining work

This checkpoint does not claim the vault is ready for real identity state or node startup.

Still required:
- independently provisioned/out-of-band owner and operator pin provenance; the vault only preserves the pin fingerprints supplied to the genesis enrollment ceremony;
- real integration that calls and checks the CP-0704 dual-attestation verifier before appending PREPARED;
- cryptographic validation of NPI1, NRT1, and issuer signatures by the calling workflow; this module is not a signature verifier;
- C:-volume path selection, physical-volume qualification, and Windows ACL validation;
- binding/reconciliation with D:-volume IdentityGenerationStateStore, including exact generation and digest checks;
- startup gating before any listener or peer acceptance;
- a separate activation/reload/session-drain control; activate_prepared records a caller-authorized state transition but does not reload Noise trust or terminate existing sessions;
- crash-injection testing and an audited partial-write recovery procedure;
- two-volume recovery tests for C:/D: divergence and restart;
- full-machine rollback protection through a qualified TPM monotonic counter or independently administered remote witness, if that assurance tier is later authorized.

The append path currently creates the final event file with create_new, writes it, and calls sync_all. A process or power failure during a write can leave a malformed partial event. Reopen fails closed on that file; automatic repair or rollback is intentionally not attempted. Temporary-file staging, directory-entry durability, and systematic crash injection remain follow-up work.

The local C:/D: design, even after integration, would detect D:-only rollback while C: remains intact; it would not resist a full-machine restore, simultaneous rollback of both disks, or hostile local Administrator access. No TPM counter or remote witness has been provisioned.

## 7. Safety and repository boundary

- Tests use temporary directories and synthetic values only.
- No production/user private key was read, generated, exported, or rotated.
- No production identity, real C: vault, or real D: high-water store was opened or modified.
- No node, listener, testnet, or mainnet was started or activated.
- No commit, push, merge, PR update, or release was performed.
- The original checkout D:\Temp\ASUS\QRUN_QFP6_CP0596_20261111 remains a separate worktree with its pre-existing changes preserved. Its devnet_trust_provisioner.rs SHA-256 remains DDD2BBB6D320986CA0DB1A796B3B9DECF14BAD22B9F7D4E7212D6FB9DE451E8F.
- The CP-0704 isolated worktree's Provisioner source remains a separate file with SHA-256 DB94B9B2F0D9E8415778398176BD2A1A3BDD7A21792FD6305F47890424DCB662.

## 8. Next engineering step

Implement a reviewed coordinator that:
1. verifies CP-0704 owner/operator authorization and every bound NPI1/NRT1/evidence file;
2. constructs the exact PeerAnchorEvent from verified artifacts and the current anchored predecessor;
3. persists PREPARED on the independent C: volume;
4. compares the C: event tip with D: IdentityGenerationStateStore;
5. leaves activation disabled until startup gating, restart recovery, crash injection, and session-lifetime behavior have passed.

Do not initialize a missing anchor from D:, do not start a node/listener, and do not enable identity activation as part of this next persistence-only step.
