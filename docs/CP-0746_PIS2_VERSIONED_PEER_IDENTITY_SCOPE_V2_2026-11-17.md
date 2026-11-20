# CP-0746 — PIS2 versioned peer-identity scope V2

Date: 2026-11-17
Project: QRun Blockchain / QFP6 / QZXB
Branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`
Worktree: `D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116`
Base HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`
Disposition: IMPLEMENTED IN ISOLATED WORKTREE; FOCUSED TESTS PASS; NO PIV1 MIGRATION OR RUNTIME/STARTUP INTEGRATION.

## 1. Purpose and scope

CP-0745 established that the legacy peer-anchor scope stores an opaque numeric role byte and opaque genesis root, while the signed rotation intent uses textual `seed` / `joining`. No authoritative cross-schema mapping existed. CP-0746 introduces a separate typed, versioned PIS2 scope so the next proof/caller work no longer needs to interpret these fields by guesswork.

This implementation is deliberately candidate-only:
- It supports the existing QVDN devnet profile candidate family only.
- It distinguishes the normal QVDN candidate profile from the QVDN local Test-PoW profile.
- It verifies exact QVDN manifest bytes against a locally constructed expected `DevnetProfileCandidate`.
- It does not claim that the QVDN manifest digest is a signature or independent source of trust.
- It does not change, decode as V2, migrate, or write legacy PIV1 anchor records.
- It does not connect to C/D stores, the identity-rotation proof caller, node startup, peer activation, or listeners.

## 2. PIS2 role contract

The PIS2 role namespace is now explicit and canonical:
- `0x01 = Seed` with text label `seed`.
- `0x02 = Joining` with text label `joining`.
- Zero, unknown codes, unknown labels, and non-canonical case variants are rejected.

The same numeric values may occur in other protocol namespaces, but PIS2 defines their meaning only inside its own versioned peer-identity scope and domain-separated digest. The implementation does not import or reuse the meanings of auth-transport client/server role bytes or signing-key custody roles.

## 3. Profile and genesis binding

PIS2 currently defines one supported profile family:
- Family code `1`: QVDN candidate devnet profile.

It defines two distinct modes:
- Mode `1`: normal QVDN candidate.
- Mode `2`: QVDN local Test-PoW profile.

The genesis commitment kind is:
- Kind code `1`: QVDN `genesis_state_root` from the exact locally expected QVDN profile.

The scope binds:
- Network ID.
- QVDN profile ID.
- Profile mode.
- Consensus-parameter digest.
- Genesis state root.
- QVDN profile-manifest digest.
- Peer role.
- Issuer ID and issuer public-key fingerprint.
- Key purpose, credential ID, and key ID.

Construction first calls `DevnetProfileCandidate::verify_manifest` with the supplied QVDN bytes. This is an exact comparison against the caller's locally constructed expected profile. The caller must obtain that expected profile from independently trusted configuration. The QVDN manifest digest remains an unkeyed SHA-256 integrity digest; it is not treated as a signature, external witness, or proof of who supplied the manifest.

Profiles outside this QVDN candidate family are rejected as unsupported. This is not yet a generic Mainnet/production genesis descriptor contract.

## 4. Canonical wire and digest

New module:
`src/native/pow_bench/src/peer_identity_scope_v2.rs`

Registered in the library:
`pub mod peer_identity_scope_v2;`

PIS2 wire:
- Magic: `PIS2`
- Version: `2`
- Fixed length: `227 bytes`
- Fixed big-endian integer widths and field order.
- No JSON reserialization or optional fields.

Scope digest:
`SHA-256("AI-NATIVE-L1-PEER-IDENTITY-SCOPE-V2\\0" || canonical_PIS2_wire)`

The implementation provides:
- Typed `PeerIdentityRoleV2` with strict text and numeric decoding.
- Typed profile-mode codes.
- A constructor that verifies exact QVDN bytes against a supplied expected profile.
- Canonical PIS2 encoding.
- A decoder that requires the expected profile and manifest bytes, then compares the decoded wire against a full canonical re-encoding.
- Fail-closed handling for unsupported versions, role codes, profile families/modes, genesis commitment kinds, malformed lengths, trailing bytes, wrong profile bytes, tampered manifests, and invalid identity tuple fields.

## 5. Tests and validation

Focused command:
`cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib peer_identity_scope_v2::tests:: -- --nocapture`

Final result:
- 6 passed.
- 0 failed.
- 0 ignored.
- 1,481 filtered out.

Covered cases:
1. Canonical Seed/Joining labels and numeric role codes; unknown/zero values rejected.
2. Normal QVDN scope round-trip against the exact expected profile.
3. Local Test-PoW profile has a distinct mode, profile ID, consensus digest, and scope digest; it cannot be decoded as the normal candidate profile.
4. Changing Seed to Joining changes canonical bytes and scope digest.
5. Unsupported version, unsupported role, and trailing bytes fail closed.
6. Manifest tampering and zero issuer identity binding fail closed.

One initial test run was 5/6 because a negative test expected the later PIS2 profile-binding error, while QVDN correctly rejected the mismatched manifest earlier with `DevnetProfileError::ProfileMismatch`. The assertion was corrected to the actual upstream rejection layer; the final focused run passed 6/6. No production behavior was changed to satisfy the test.

Additional validation:
- `rustfmt --edition 2021 src/native/pow_bench/src/peer_identity_scope_v2.rs`: completed.
- `cargo fmt --manifest-path src/native/pow_bench/Cargo.toml --all -- --check`: PASS.
- `git diff --check`: PASS.
- Full library suite was not rerun in CP-0746. The prior CP-0743 full parallel run remains recorded as 1,479 passed / 2 failed; both failed tests passed individually on sequential rerun, but the full parallel suite is not called wholly successful.

## 6. Source evidence

PIS2 source:
- Size: 18,232 bytes.
- SHA-256: `E7545F55116DF17E57847CB5C495BDBC15B5CFE0F77FC4D66FD68B6BCBD36F11`

No PIV1 source or stored PIV1 data was modified by this checkpoint. The only library registration change is the new `peer_identity_scope_v2` module line in the already-modified isolated `lib.rs`.

## 7. Repository and safety state

At final verification:
- Branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`
- HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3` (unchanged)
- Working tree: 61 status entries = 7 modified tracked files + 54 untracked files.
- No staged files.
- No commit, push, PR update, merge, reset, checkout, clean, stash, or worktree cleanup.
- The 59 pre-existing entries, CP-0745 document, and new PIS2 source were preserved.
- The protected `AI_NATIVE_L1_G2_G8_20261024` worktree remains on `feat/qrun-qvap-offline-prototype-20261030` at `801471c90b307a5c12f6785173d2d8986ffb74d3`, clean at the last check.
- The root checkout remains on `work/cp0390-pfm5-checkpoint-fork-choice` at `69eb732d2672f5b9aa1bc4ee9c3c80402cff8a47`, with its four pre-existing untracked private/handoff files untouched.
- No live C/D identity store, peer key, owner/operator key, deployment key, TPM, node, listener, public network, public website, wallet, or asset was accessed for mutation.

## 8. Remaining gaps

PIS2 does not by itself:
- Authenticate the provenance of the expected profile configuration.
- Authenticate the provenance of owner/operator signer pins.
- Provide a signed external genesis/profile attestation.
- Supply a PIV2 on-disk anchor format or migrate PIV1.
- Persist authorization nonce consumption or provide whole-machine rollback resistance.
- Invoke `verify_anchored_successor_proof` from a production caller.
- Authorize identity activation, startup, peer admission, recovery, or public deployment.

## 9. Exact continuation point — CP-0747

The next safe engineering task is a separate PIV2 anchor-format design/implementation using PIS2 scope digests, while preserving PIV1 byte-for-byte compatibility and fail-closed version separation. Reuse the existing staged atomic publication and persistence primitives where possible; do not copy the entire vault implementation blindly.

Required CP-0747 gates:
1. Audit the PIV1 record codec, chain digest, writer lock, staged publication, and recovery behavior.
2. Define a PIV2 record magic/version and explicit schema discriminator; PIV1 files must never be interpreted as PIV2.
3. Bind the PIS2 digest and exact role/profile/genesis contract into PIV2 records.
4. Add positive, tamper, wrong-scope, unsupported-version, interrupted-write, no-overwrite, and reopen/replay tests in disposable temporary directories.
5. Keep the new PIV2 store detached from production C/D paths until the Windows path/ACL/volume qualification and cross-volume recovery gates are independently satisfied.
6. Only after separate review may a read-only caller be built around already-open stores. No startup or activation integration is part of CP-0747.

Current disposition: PIS2 V2 scope codec implemented and focused tests pass. PIV1 remains unchanged. Production identity activation and Mainnet readiness remain NO-GO.
