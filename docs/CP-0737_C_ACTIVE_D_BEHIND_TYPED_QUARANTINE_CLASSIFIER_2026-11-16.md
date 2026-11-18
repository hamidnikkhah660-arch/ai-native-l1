# CP-0737 — C-ACTIVE / D-BEHIND Typed Quarantine Classification

Date: 2026-11-16  
Project: AI-NATIVE L1 / QRun / QZXB / QFP6  
Branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`  
Worktree: `D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116`  
Base HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`  
Status: **READ-ONLY CLASSIFIER EXTENDED / TARGETED TESTS PASS / NO RECOVERY WRITER OR STARTUP INTEGRATION**

## 1. Purpose

CP-0708 finding F-06 identified an important cross-volume crash window: the C-side peer identity anchor may have durably recorded `ROTATION_ACTIVE(n+1)` while the D-side `IdentityGenerationStateStore` still contains the exact previous active generation `n`. The prior comparator returned only a generic generation mismatch for this state.

This checkpoint adds a typed, fail-closed classification for the narrow exact-successor shape. It does not make that state recoverable by itself.

## 2. Implementation

### C-side immutable event binding

Added `PeerAnchorRotationActiveBinding` and `PeerIdentityAnchorVault::latest_rotation_active_binding()`.

The accessor returns metadata only when the latest event is `ROTATION_ACTIVE` and is the chain tail. It exposes:

- anchor sequence and event digest;
- predecessor vault-event digest;
- previous and successor generation / KeyRecord digests;
- Noise public-key fingerprint and NPI1 digest;
- NRT1 digest and dual-attestation intent digest;
- nonce and owner/operator pin fingerprints.

A trailing `PREPARED` event is not exposed as an active rotation. The accessor performs no I/O or mutation and does not independently verify the referenced NPI1/NRT1 bytes or signer-pin provenance.

### Typed comparator result

Extended `PeerIdentityReconciliationError` with:

`AnchorAheadOfGenerationStoreUnverified`

It is emitted only when all of these conditions hold:

1. C's active generation is exactly D generation + 1 (checked arithmetic; no wrap).
2. The C chain tail is a `ROTATION_ACTIVE` event for that active generation.
3. The event's previous generation equals D's generation.
4. The event's previous KeyRecord digest equals D's exact persisted digest.
5. The event's successor KeyRecord digest equals C's active binding digest.
6. Both C successor and D predecessor lifecycle values are ACTIVE.

The error carries the C event sequence/digests and the exact artifact/authorization digests, nonce and signer-pin fingerprints needed by a future verifier.

All other gaps, same-generation mismatches, wrong predecessor bindings, and non-tail/non-active events remain fail-closed errors. The existing D-ahead-of-C classification is unchanged.

## 3. Critical interpretation boundary

The new variant is deliberately an **error/quarantine state**, not a successful reconciliation result.

It does NOT establish that:
- the NPI1 artifact bytes are present or match the recorded digest;
- the NRT1 bytes are present, issuer-signed, or bind the exact predecessor/successor;
- the owner/operator signatures are valid for the recorded intent;
- owner/operator pin fingerprints have trusted out-of-band provenance;
- D can safely be advanced, or that startup/listeners may proceed.

No automatic repair, C-to-D copy, state rewrite, retry, activation, or startup authorization was added. A separate recovery writer must independently validate the exact NPI1, NRT1, issuer signature, dual-attestation envelope, scope, pins and crash-state evidence before it can even be designed for review.

## 4. Validation

Command:

`cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib peer_identity_reconciliation -- --nocapture`

Result: **10 passed, 0 failed, 0 ignored** (including the new persisted-store restart test).

The new test:
- creates synthetic C/D stores in a unique temporary directory;
- enrolls generation 2 and persists D high-water generation 2;
- confirms a trailing PREPARED event is not exposed as an active rotation;
- prepares and activates the exact generation 3 successor in C only;
- mutates the in-memory predecessor digest in a copied binding and confirms the classifier falls back to generic `IdentityGenerationMismatch`;
- confirms the comparator returns `AnchorAheadOfGenerationStoreUnverified` with exact old/new record, NPI1, NRT1 and intent digests;
- closes and reopens both stores and confirms the same typed quarantine state remains.

Also completed in the same command:
- `cargo fmt --manifest-path src/native/pow_bench/Cargo.toml --all`: PASS.
- `git diff --check`: PASS (only pre-existing LF-to-CRLF working-copy notices).

No broad test suite was run.

## 5. Safety and repository boundary

- Tests used synthetic records, issuer keys and isolated temporary directories only.
- No real C:/D: store path was opened or modified.
- No production/user private key, identity, wallet, node, listener, testnet or mainnet was accessed or activated.
- No startup integration, recovery writer, commit, push, merge, PR update or release was performed.
- Work remains in the isolated CP-0704 worktree; the protected main checkout remains separate and untouched.
- Earlier CP-0724 through CP-0735 ACL/rename tests were not rerun.

## 6. Next bounded engineering step

Build a pure, independently testable artifact-verification layer for the C-anchored successor. It must accept exact bounded NPI1, NRT1 and dual-authorization bytes, verify their digests against this binding, verify the issuer-signed NRT1 against D's exact predecessor tuple and C's exact successor tuple, and validate the owner/operator signatures and independently provisioned pins. It must return a typed proof object without writing either store.

Only after that proof layer and its negative tests pass should a separate idempotent D-recovery writer be designed. Do not wire any of this into startup until the Windows path/namespace qualification and independent review gates are resolved.

[executed on device: heymed (9d9913e5-d5eb-4a93-8744-5427303647e3)]
