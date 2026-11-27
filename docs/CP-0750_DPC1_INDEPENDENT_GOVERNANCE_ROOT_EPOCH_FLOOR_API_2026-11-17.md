# CP-0750 — DPC1 independent governance-root epoch-floor API

Date: 2026-11-17
Project: QRun Blockchain / QFP6 / QZXB
Branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`
Worktree: `D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116`
HEAD observed: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3` (unchanged)
Disposition: STRICT LIBRARY API IMPLEMENTED AND TESTED; NOT YET WIRED INTO NODE/PROVISIONER RUNTIME CONFIGURATION.

## 1. Objective

CP-0749 identified that the DPC1 verification entry point accepted an external minimum DPC1 sequence and deployment-authority public key, but read the minimum governance-root epoch only from the signed DPC1 payload. This checkpoint adds a strict library API that requires the root-epoch floor as a separate caller-supplied parameter.

The change is a foundation. It does not close the runtime rollback gate because production/testnet call sites still use the compatibility API until a separately reviewed configuration migration is completed.

## 2. Source change

File:
`src/native/pow_bench/src/noise_deployment_config.rs`

New public API:
`verify_signed_deployment_config_with_floors(wire, expected_network_id, deployment_authority_public_key, minimum_sequence, minimum_root_epoch)`

Behavior:
1. Reject `minimum_root_epoch == 0` with `InvalidMinimumRootEpoch`.
2. Run the existing DPC1 parser and verifier, including network binding, deployment-authority Ed25519 signature, DPC1 sequence floor, key-role separation, and GRC1 signature/chain validation.
3. Require the signed DPC1 `minimum_root_epoch` field to be at least the independently supplied minimum.
4. Require the verified GRC1 chain tip epoch to be at least the independently supplied minimum.
5. Reject either floor mismatch with `RootEpochBelowMinimum`.

The compatibility API `verify_signed_deployment_config` remains available and is now explicitly documented as validating only the floor embedded inside DPC1. Callers that need an independently supplied root-epoch rollback floor must use the new strict API.

New error variants:
- `InvalidMinimumRootEpoch`
- `RootEpochBelowMinimum`

The existing `StateNotCurrent` variant and `DeploymentConfigStateStore::matches_current` implementation were already present in the active worktree before CP-0750; they remain part of the existing local DCS1 high-water work and are not claimed as newly implemented by this checkpoint.

## 3. Test coverage

New focused test:
`noise_deployment_config::tests::strict_verifier_enforces_independent_governance_root_epoch_floor`

The test constructs deterministic synthetic Ed25519 deployment, governance-anchor, next-root, and recovery keys in memory. It verifies:
- An otherwise valid epoch-1 DPC1 is accepted by the compatibility API, demonstrating the old embedded-floor behavior.
- The same epoch-1 DPC1 is rejected by the strict API when the independent external root floor is 2.
- A valid GRC1 transition from epoch 1 to epoch 2, with a DPC1 that acknowledges minimum epoch 2, is accepted by the strict API at external floor 2.
- A zero external root-epoch floor is rejected.

The test uses only synthetic keys. It does not represent a real owner, operator, deployment authority or governance root.

Final command:
`cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib noise_deployment_config::tests:: -- --nocapture`

Result:
- 4 passed.
- 0 failed.
- 0 ignored.
- 1,493 filtered out.

The focused new test also passed independently:
- 1 passed.
- 0 failed.
- 1,496 filtered out.

## 4. Additional validation

- `cargo fmt --manifest-path src/native/pow_bench/Cargo.toml --all -- --check`: PASS.
- `git diff --check`: PASS.
- `cargo check --manifest-path src/native/pow_bench/Cargo.toml --bin devnet_trust_provisioner`: PASS, exit code 0.
- The provisioner build emitted 10 crate warnings in existing/unrelated modules (unused imports/dead code, including candidate modules and the test-only reconciliation helper). No new error occurred.
- No full library suite was run for CP-0750.

An initial format-check command was mistakenly invoked from the repository root without a `Cargo.toml`; it exited before running rustfmt. The corrected manifest-qualified format check above passed. The code was formatted on the target file before tests.

## 5. Runtime integration remains required

The following runtime configurations currently supply the deployment-authority key and minimum DPC1 sequence through command-line options:
- `private_testnet_node`: `--deployment-authority-key-hex` and `--deployment-config-min-sequence`.
- `chain_import_node`: `--peer-noise-deployment-authority-public-key-hex` and `--peer-noise-deployment-min-sequence`.

The inspected call sites still call the compatibility `verify_signed_deployment_config`. CP-0750 does not add or require a runtime minimum-root-epoch argument and does not switch those call sites to the strict API. The `devnet_trust_provisioner` commands that verify DPC1 also remain to be migrated.

Next checkpoint CP-0751 must:
1. Add an explicit nonzero external minimum-root-epoch option/field to each relevant signed-identity runtime mode.
2. Require the option whenever the DPC1/GRC1 trust path is enabled; do not default production paths to epoch 1.
3. Pass it to `verify_signed_deployment_config_with_floors` in `private_testnet_node`, `chain_import_node`, and every provisioner path that authorizes a rotation or issuer change.
4. Add/adjust parser tests and node-startup trust tests to reject missing/zero/too-low floors.
5. Confirm there is no signed-identity path that silently falls back to the compatibility API.
6. Preserve all existing DPC1 and DCS1 sequence/digest behavior and re-run focused tests/builds.

Only after runtime integration and independent deployment trust-configuration storage are verified can this particular root-epoch configuration gate be considered closed. Even then, local DCS1 is not a TPM or independent remote witness and does not defeat whole-device rollback by itself.

## 6. Exact source and repository evidence

Current `noise_deployment_config.rs`:
- Size: 989 lines at final check.
- SHA-256: `FB71A9787890F5832D5B9EFCCDC13A068523E12FB54DE2B861BBA8C2236F5CA5`.

Targeted diff against the current branch base includes the prior `StateNotCurrent` / `matches_current` change already present in the worktree, plus the CP-0750 strict root-floor API, error variants, fixture, and test. It reports 153 insertions and 1 deletion for the file relative to HEAD; this is not a CP-0750-only diff count.

Repository status at final check:
- Branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`.
- HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3` (unchanged).
- Status entries: 67.
- Modified tracked: 7.
- Untracked: 60.
- Staged: 0.

Status includes checkpoint documents and candidate files accumulated before CP-0750. It must not be interpreted as 67 files newly authored by this checkpoint.

No commit, push, PR update, merge, reset, checkout, clean, stash, or worktree cleanup was performed. No node, listener, production configuration, real key, C/D vault, ACL, physical volume, wallet, public network, or asset was changed.

## 7. Gate disposition

- DPC1 compatibility verifier: remains available; insufficient alone for an independent root-epoch floor.
- Strict independent root-floor library API: implemented and tested.
- Strict API wired into runtime configuration: NOT DONE.
- Signer Trust Bundle STB1: design only (CP-0749).
- Owner/operator pin provenance: NOT ESTABLISHED.
- PIV2 C-side anchor: local candidate only; no production caller.
- C/D production reconciliation: no production caller.
- Gate 8: OPEN.
- Mainnet, public token release, liquidity, trading, and mining readiness: NO-GO absent separate technical, security, legal, and operational evidence.

[executed on device: heymed (de0adbe3-6583-4775-a26e-c479a62aa941)]
