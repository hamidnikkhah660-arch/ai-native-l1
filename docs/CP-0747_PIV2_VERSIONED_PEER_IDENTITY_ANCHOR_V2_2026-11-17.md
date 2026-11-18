# CP-0747 — PIV2 versioned peer-identity anchor vault

Date: 2026-11-17
Project: QRun Blockchain / QFP6 / QZXB
Branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`
Worktree: `D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116`
Base HEAD observed: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`
Disposition: IMPLEMENTED AS AN ISOLATED PERSISTENCE CANDIDATE; FOCUSED PIV2 AND PIV1 REGRESSION TESTS PASS; NO PRODUCTION C/D, NODE-STARTUP, OR IDENTITY-ACTIVATION INTEGRATION.

## 1. Purpose and boundary

CP-0746 introduced a typed PIS2 scope and canonical scope digest. CP-0747 adds a distinct PIV2 append-only peer-identity anchor candidate that stores that PIS2 scope digest and avoids reinterpreting legacy PIV1 event records.

This work is limited to a local persistence primitive. It does not:
- verify NPI1/NRT1 signatures or the upstream dual-attestation proof;
- establish trusted provenance for owner/operator signer pins;
- authenticate the origin of the caller's expected QVDN profile;
- implement independent CAS, an external witness, TPM monotonicity, or whole-host rollback protection;
- connect PIV2 to the existing C:/D: identity stores, to `verify_anchored_successor_proof`, or to a production caller;
- activate peer identity, admit peers, start listeners/nodes, or authorize any public deployment.

The module-level warning explicitly prohibits production C:/D: or node-startup use until separate path, ACL, volume, recovery, and review gates pass.

## 2. Files and format separation

New source:
`src/native/pow_bench/src/peer_identity_anchor_v2.rs`

Library registration:
`pub mod peer_identity_anchor_v2;`

PIV2 format constants and namespace:
- Magic: `PIV2`.
- Version: `2`.
- Distinct digest domain: `AI-NATIVE-L1-PEER-IDENTITY-ANCHOR\0v2`.
- Event suffix: `.piv2`.
- Event filename sequence: `event-{sequence:020}.piv2`.
- Maximum accepted event count: 1,000,000.
- Scope commitment: canonical PIS2 scope digest.

PIV2 and PIV1 use distinct event filename suffixes and independent wire magic/version/digest domains. PIV2's directory scan rejects a non-PIV2 event filename, including PIV1's `.piv1`; the regression test also opens a PIV2 directory with PIV1 and a PIV1 directory with PIV2 and expects both attempts to fail. No automatic conversion or migration exists.

PIV2 and PIV1 intentionally share the stable writer-lock pathname `peer-identity-vault.lockstate` and the existing staged no-overwrite publication primitive. To reuse that primitive rather than duplicate it, the helper `publish_new_event` in `peer_identity_anchor_vault.rs` was widened from private to `pub(crate)`. The PIV1 record codec, PIV1 event encoding, PIV1 parser, and existing PIV1 event files were not migrated or intentionally redefined. The source file containing the helper did change, and PIV1 regression tests were rerun.

## 3. PIV2 behavior

The store exposes explicit operations for:
- opening an absolute, existing non-symlink directory;
- reading event count, scope match, active generation, pending generation, nonce presence, and the latest tail ROTATION_ACTIVE binding;
- explicit genesis enrollment;
- persistence of a PREPARED rotation;
- activation of only the exact most-recent prepared nonce.

Safety properties implemented in this candidate:
- Opening an empty store does not self-enroll an identity.
- Genesis enrollment requires generation 1-or-higher, zero predecessor generation, required nonzero evidence fields, and distinct nonzero owner/operator pin fingerprints.
- Rotation preparation requires an existing active generation and exactly the next generation, checked for overflow.
- Reusing a nonce with different event content is rejected as replay; an exact retry of the same pending event is idempotent.
- Only one pending rotation is accepted.
- Activation requires the exact pending nonce and appends a ROTATION_ACTIVE event; it is not an upstream signature/proof verifier.
- Events are chained by sequence, scope digest, previous digest, and event digest.
- Records are written through a create-new staged file, flushed and sync'd, read back and decoded, checked against the intended bytes and predecessor, then passed to the shared no-overwrite publisher.
- A remaining staged file causes open to fail closed. It is retained for forensic inspection; open does not promote, delete, or auto-repair it.
- Event paths and files are checked against symlinks/non-regular files during open.

These properties are bounded to the candidate implementation and its temporary-directory tests. They do not establish Windows ACL correctness, resistance to privileged path replacement, directory-entry durability under power loss, cross-volume independence, or disk-failure recovery.

## 4. Tests

Focused PIV2 command:
`cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib peer_identity_anchor_v2::tests:: -- --nocapture`

Final recorded result:
- 9 passed.
- 0 failed.
- 0 ignored.
- 1,487 filtered out.

Covered cases:
1. Explicit enrollment, reopen, persisted active generation, and scope binding.
2. Prepared nonce persistence, exact idempotent retry, rejection of conflicting reuse, and exact activation.
3. No self-enrollment and rejection of invalid/non-successor generation state.
4. Mutual PIV1/PIV2 format rejection.
5. Tamper, wrong scope, and truncated record rejection.
6. Unsupported magic and version rejection.
7. Interrupted stage is retained and causes fail-closed open without repair.
8. Final publication does not overwrite an existing sequence.
9. Writer lock is exclusive and released when the store is dropped.

PIV1 regression command:
`cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib peer_identity_anchor_vault::tests:: -- --nocapture`

Final recorded result:
- 11 passed.
- 0 failed.
- 0 ignored.
- 1,485 filtered out.

Additional validation:
- `cargo check --manifest-path src/native/pow_bench/Cargo.toml --bin devnet_trust_provisioner`: PASS. The build emitted 10 warnings in other/pre-existing modules (unused imports/dead code); no new warning was attributed to PIV2 in the recorded result.
- `cargo fmt --all -- --check`: PASS.
- `git diff --check`: PASS.
- The full library suite was not rerun for CP-0747. CP-0743's earlier parallel full run remains recorded as 1,479 passed / 2 failed; the two failing tests passed individually on sequential rerun, but the full parallel suite is not considered wholly green.

## 5. Source evidence

PIV2 source:
- Size: 37,150 bytes.
- SHA-256: `F24DEACDC41687662AD347CC16AFD959BC2216C0CBE54BBE54DA4BC22612B31A`

Shared PIV1 vault source (including the visibility-only exposure of the shared publisher):
- Size: 34,410 bytes.
- SHA-256: `4FEB3F691655CE4FF250ADDE6CC8FC7BEBB35D9E78E50B0F09903C32A356BAFD`

PIV2 module registration is present in `src/native/pow_bench/src/lib.rs` adjacent to the PIV1 vault registration. PIS2 is the scope input. Its source contract and caveats remain those recorded in CP-0746.

## 6. Repository and safety state

Rechecked after implementation and before this document:
- Branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`.
- HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3` (unchanged).
- Git status: 64 entries = 7 modified tracked files + 57 untracked files.
- Staged entries: 0.
- The status includes prior isolated-worktree changes and prior untracked handoff/checkpoint artifacts; it must not be interpreted as 64 files newly authored by CP-0747.
- No commit, push, PR update, merge, reset, checkout, clean, stash, or worktree cleanup was performed.
- No live C/D identity store, peer key, owner/operator key, deployment key, TPM, running node, listener, public network, website, wallet, or asset was accessed for mutation.

The protected G2/G8 worktree and root checkout were not accessed for writes in this checkpoint.

## 7. Remaining blockers and next checkpoint

PIV2 is not a production identity trust anchor yet. Before any production integration, the following remain open:
1. Independent provenance for the expected profile configuration, genesis commitment, and signer pins.
2. Windows path canonicalization/reparse-point handling, ACL verification, volume identity verification, and protection against privileged path replacement.
3. Physical crash/power-loss tests across write, flush, sync, rename/publication, and restart boundaries; directory durability must be demonstrated rather than assumed.
4. Cross-volume recovery and independent rollback-resistance tests involving both C and D stores, including corruption, stale generation, and whole-host rollback limits.
5. An independent external witness or equivalent protected monotonic trust anchor; local file locking and hash chaining do not supply this.
6. A separately reviewed read-only composite-proof caller that verifies exact current PIV2/C/D state without implicitly authorizing activation.
7. Independent security review and reproducible full-suite results.

Next safe task: CP-0748 should be a read-only audit of the actual provisioning/pin-provenance path and Windows path/ACL/volume assumptions. First identify the exact call sites and evidence inputs; do not provision keys, alter the devnet provisioner, write to live C/D paths, or connect PIV2 to node startup. Any proposed change should be tested only in disposable temporary directories until the path and trust model is independently qualified.

Current disposition: CP-0747 local PIV2 persistence candidate implemented; focused PIV2 tests and PIV1 regression tests pass. Gate 8 remains OPEN. Production peer-identity activation, mainnet, token release, public trading, liquidity, and mining readiness remain NO-GO absent their separate evidence.
