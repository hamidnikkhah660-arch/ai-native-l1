# CP-0747 — PIV2 versioned peer-identity anchor store

Date: 2026-11-17
Project: QRun Blockchain / QFP6 / QZXB
Branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`
Worktree: `D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116`
Base HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`
Disposition: IMPLEMENTED IN ISOLATED WORKTREE; PIV2 AND PIV1 FOCUSED TESTS PASS; PRODUCTION INTEGRATION NOT AUTHORIZED.

## 1. Purpose

CP-0746 introduced the typed PIS2 scope contract. CP-0747 adds a separate PIV2 append-only peer-identity anchor store that consumes the PIS2 scope digest.

PIV2 is a separate candidate persistence primitive. It is not wired to node startup, production identity activation, or the operational C:/D: stores. It does not establish signer-pin provenance, independently verify NPI1/NRT1, authorize recovery, or prevent rollback if an attacker controls the complete host or both storage devices.

## 2. Version separation

New source:
`src/native/pow_bench/src/peer_identity_anchor_v2.rs`

New store type:
`PeerIdentityAnchorVaultV2`

Wire properties:
- Magic: `PIV2`
- Version: `2`
- Event filename suffix: `.piv2`
- Separate PIV2 digest domain: `AI-NATIVE-L1-PEER-IDENTITY-ANCHOR\\0v2`
- Fixed record layout and bounded maximum event count.
- Each record binds the canonical PIS2 scope digest, sequence, event, predecessor digest, and its own digest.

PIV1 remains a separate format with its original magic/version/domain and `.piv1` event filename suffix. Neither implementation attempts fallback decoding. PIV2 rejects PIV1 event files; PIV1 rejects PIV2 event files. Both use the same stable writer-lock path, preventing concurrent writers using different format versions from opening the same root at once.

The only edit to the PIV1 source in this checkpoint is changing the staged no-overwrite publication helper visibility to `pub(crate)`, allowing PIV2 to reuse the exact tested helper. The PIV1 record codec, digest domain, event schema, and filename suffix were not changed.

## 3. Persistence behavior

PIV2 implements:
- Strict absolute, existing directory requirement; no implicit directory or identity-baseline creation.
- Stable OS-backed writer lock shared with PIV1.
- Full ordered replay of the event chain on open.
- Exact PIS2 scope digest match on every event.
- Sequence and predecessor-digest continuity.
- Explicit enrollment only; an empty store never self-enrolls.
- PREPARED and ACTIVE rotation event transition validation.
- Durable nonce replay lookup and exact retry handling.
- Bounded, staged event write; flush and sync; reopen and byte-level verification; publication without replacement.
- Interrupted stage detection and fail-closed quarantine on reopen; no automatic promotion or deletion.
- Read-only latest-active binding metadata for a later independent proof verifier.

The publication helper is the existing PIV1 `publish_new_event` primitive, now crate-visible. It deliberately does not replace an existing destination. The PIV2 temporary name is distinct and remains detectable by the store's stage-quarantine scan.

PIV2's `enroll_genesis`, `prepare_rotation`, and `activate_prepared` are persistence operations. Callers must independently verify the required signatures, owner/operator authorization, signer-pin provenance, session controls, and external policy before invoking them. This store alone is not authorization.

## 4. Test coverage

Focused PIV2 command:
`cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib peer_identity_anchor_v2::tests:: -- --nocapture`

Result:
- 9 passed.
- 0 failed.
- 0 ignored.
- 1,487 filtered out.

PIV2 coverage includes:
1. Explicit enrollment and durable reopen.
2. PREPARED nonce persistence, exact retry, conflicting nonce rejection, exact activation nonce, and active-tail evidence.
3. Empty store does not self-enroll; invalid generation rejected.
4. PIV1 and PIV2 event formats reject each other in both directions.
5. Record tampering, wrong PIS2 scope, and truncated record rejected.
6. Unsupported magic and version rejected.
7. Interrupted PIV2 staging file quarantined and left untouched.
8. Existing final sequence cannot be overwritten.
9. Shared writer lock is exclusive and released on drop.

Focused legacy regression command:
`cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib peer_identity_anchor_vault::tests:: -- --nocapture`

Result:
- 11 passed.
- 0 failed.
- 0 ignored.
- 1,485 filtered out.

PIV1 regression coverage includes explicit enrollment/reopen, durable high-water, nonce replay, rotation transitions, tamper rejection, invalid transitions, writer locking, interrupted stages, and no-overwrite publication.

Build:
`cargo check --manifest-path src/native/pow_bench/Cargo.toml --bin devnet_trust_provisioner`

Result: PASS, exit code 0. Existing warnings about unused imports/dead code in unrelated modules were emitted; no build error was reported.

Formatting and diff checks:
- `cargo fmt --manifest-path src/native/pow_bench/Cargo.toml --all -- --check`: PASS.
- `git diff --check`: PASS.

CP-0746's PIS2 focused suite also passed 6/6 before PIV2 was added. The full library suite was not rerun in CP-0747. The prior CP-0743 full parallel result remains 1,479 passed / 2 failed; both failed tests later passed individually, but the full parallel suite is not labelled wholly passing.

## 5. Source evidence

Current source SHA-256:
- `peer_identity_scope_v2.rs` (18,232 bytes): `E7545F55116DF17E57847CB5C495BDBC15B5CFE0F77FC4D66FD68B6BCBD36F11`
- `peer_identity_anchor_v2.rs` (37,150 bytes): `F24DEACDC41687662AD347CC16AFD959BC2216C0CBE54BBE54DA4BC22612B31A`
- `peer_identity_anchor_vault.rs` (34,410 bytes): `4FEB3F691655CE4FF250ADDE6CC8FC7BEBB35D9E78E50B0F09903C32A356BAFD`
- `CP-0746_PIS2_VERSIONED_PEER_IDENTITY_SCOPE_V2_2026-11-17.md` (9,031 bytes): `0CF7C08061E6F93755A126268898485E17E092DB6DF6F22B60C197B2D6674FD8`

The PIV2 source digest above was read from the actual worktree after formatting. PIV2 and PIS2 module declarations are registered in `lib.rs`.

## 6. Safety and repository state

At the latest verification:
- Branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`
- HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3` (unchanged).
- Working-tree status entries: 63.
- Staged files: 0.
- No commit, push, PR update, merge, reset, checkout, clean, stash, or worktree cleanup.
- All pre-existing tracked and untracked work was preserved.
- The protected `AI_NATIVE_L1_G2_G8_20261024` worktree was last observed clean on `feat/qrun-qvap-offline-prototype-20261030` at `801471c90b307a5c12f6785173d2d8986ffb74d3`.
- The root checkout and its four pre-existing private/handoff files were not modified.
- No production C/D path, key, TPM, node, listener, network, wallet, public website, or live identity was mutated.
- GitHub API remote verification remains unavailable in this session because the connected API returned HTTP 403 with `Your account was suspended`; this is not evidence that the repository itself is suspended.

## 7. Remaining assurance gaps

PIV2 does not close:
- Windows path ancestry/reparse-point race qualification.
- Actual physical-volume and disk identity binding for operational stores.
- Effective ACL/owner authorization and concurrent security-descriptor mutation.
- Cross-volume crash/recovery and independent high-water witness.
- Whole-machine and dual-disk rollback/deletion resistance.
- Independent owner/operator pin provenance.
- Durable authorization nonce consumption outside the local event chain.
- Production caller integration for `verify_anchored_successor_proof`.
- Session drain/reload and independent activation authorization.
- Mainnet or public network launch readiness.

The PIV2 implementation uses path-based directory enumeration and file opens, like the isolated PIV1 implementation. It is therefore intentionally detached from production paths pending the separate Windows qualification gates; CP-0747 does not claim those path-race risks are solved.

## 8. Exact continuation point — CP-0748

Next task:
1. Build a PIS2-to-PIV2 adapter in a dedicated read-only proof caller, first in library/test scope only.
2. Audit whether the anchored successor proof can consume an immutable PIV2 active-tail binding without exposing a legacy PIV1 scope path.
3. Ensure the caller opens each already-provisioned store once, holds all writer locks through verification, and never calls observe/accept/write/repair/initialize/activate.
4. Produce a machine-readable evidence-only result with explicit trust provenance and error categories.
5. Keep the caller detached from node startup until all Windows storage qualification, trusted pin provenance, independent review, recovery, and session gates are complete.

No production startup or identity activation is authorized by CP-0747.

Current disposition: PIS2 and PIV2 focused tests pass; PIV1 focused regression passes; the trust provisioner binary checks. PIV1 record format remains unchanged. The mainnet/public-network readiness decision remains NO-GO.
