# CP-0740 ? DPC1 / IRG1 trust-chain binding

Date: 2026-11-16

## Change

The read-only anchored successor proof now verifies the trust artifacts it previously only hash-bound through the dual-attestation intent.

1. DPC1 is checked with the canonical verifier, the proof scope's network ID, a caller-supplied out-of-band deployment-authority public key, and a caller-supplied minimum DPC1 sequence.
2. IRG1 is checked with the canonical verifier under the Governance public key obtained from the verified DPC1.
3. The verified IRG1 sequence must meet DPC1's minimum_registry_sequence.
4. The selected scope.issuer_id must be Active and its registry public key must exactly equal the issuer public key used to verify previous/successor NPI1 and NRT1.
5. Proof output carries DPC1 digest/sequence, GRC1 digest/epoch, IRG1 digest/sequence, and Governance/issuer-key fingerprints. Dual-attestation still checks exact DPC1/IRG1 hashes.

## Test fixture

The composite test now creates a genuine zero-transition GRC1 anchor, signs DPC1 with a separate synthetic deployment-authority key, and signs IRG1 under the DPC1 Governance key. It also checks wrong deployment authority, DPC1 below caller floor, tampered DPC1 signature, wrong DPC1 network, IRG1 below DPC1 registry floor, tampered IRG1 signature, wrong IRG1 network, revoked issuer status, and an Active issuer entry with a mismatched key. All keys are synthetic test-only keys.

## Security boundary

- Deployment-authority public key and minimum DPC1 sequence are caller-supplied trust inputs; this function does not establish their provenance or persist the floor. Callers must obtain them independently of the writable artifacts.
- scope.genesis_root is not bound to DPC1/GRC1: the inspected DPC1 schema has no corresponding signed genesis-root field.
- Numeric anchor role to dual-intent role-string mapping remains unresolved.
- Owner/operator pin provenance remains external; only signatures and exact fingerprints against the C anchor are checked.
- This remains a read-only evidence builder, not recovery authorization. It does not update C/D, repair high-water state, activate keys, start node/listener, or authorize startup.
- No real keys, network service, node process, public endpoint, release, or public site was touched.

## Validation

Validation results are recorded at the end of this file after the focused test/build run.

Validation: cargo fmt PASS; focused noise identity authorization tests PASS; devnet_trust_provisioner cargo check PASS; git diff --check PASS.

## Recorded validation results

- cargo fmt --manifest-path src/native/pow_bench/Cargo.toml --all: PASS (exit code 0).
- cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib noise_identity_rotation_authorization::tests:: -- --nocapture: PASS — 15 passed, 0 failed, 0 ignored; 1466 filtered out.
- cargo check --manifest-path src/native/pow_bench/Cargo.toml --bin devnet_trust_provisioner: PASS (exit code 0; 21.79s). Existing crate warnings remain; no errors.
- git diff --check: PASS (exit code 0; only pre-existing LF/CRLF notices).
- HEAD remains 5aba5f69d24fce03af742fd1bebf13ad00e5d9c3. No staging, commit, push, merge, or change to the protected main checkout.
- CP-0740 implementation remains in the isolated worktree; earlier uncommitted/untracked baseline work was preserved.

Source SHA-256:
- peer_identity_successor_proof.rs: 75C7B4A0BC0A94C38F61348CD039AC5D4778089047CAB960BE858A49B871F6BF
- noise_identity_rotation_authorization.rs: 8D9F87942ADFC573FAE1205C17644A2D3D12C5FAD74D718A83DC7A792E0ABB0C


## Extended negative-case rerun

- cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib noise_identity_rotation_authorization::tests:: -- --nocapture: PASS ? 15 passed, 0 failed; composite proof now also rejects tampered/wrong-network DPC1, wrong-network IRG1, and revoked issuer status.
- cargo fmt: PASS; git diff --check: PASS.
