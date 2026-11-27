# CP-0751 — Strict DPC1 runtime integration and DCS1 root-epoch high-water

Date: 2026-11-17
Project: QRun Blockchain / QFP6 / QZXB
Branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`
Worktree: `D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116`
HEAD observed before and after: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3` (unchanged)
Disposition: STRICT DPC1 FLOOR WIRED INTO THE INSPECTED EXECUTABLE PATHS; DCS1 V2 ROOT-EPOCH HIGH-WATER IMPLEMENTED; FOCUSED LIBRARY AND BINARY TESTS PASS; NO COMMIT/PUSH.

## 1. Executive result

CP-0750 added the strict `verify_signed_deployment_config_with_floors` API. CP-0751 carries the independently configured minimum governance-root epoch into the runtime and provisioner call paths, then extends durable DCS1 state to persist the highest accepted GRC1 root epoch as well as DPC1 sequence and digest.

Verified results:
- Strict DPC1 verification is now used by the inspected executable call sites in `private_testnet_node`, `chain_import_node`, and the `devnet_trust_provisioner` commands.
- A source search found no direct use of the compatibility `verify_signed_deployment_config` API in `src/native/pow_bench/src/bin`.
- DCS1 v2 persists the GRC1 tip epoch and rejects a newer DPC1 sequence whose governance-root epoch is lower than the durable value.
- DCS1 v1 compatibility is fail-closed for successor migration: a legacy state with a previously accepted sequence must first be upgraded using the exact current signed DPC1 manifest already recorded by that state.
- Formatting, diff whitespace validation, `cargo check --bins`, and 62 targeted tests passed.

This is a local filesystem rollback-control improvement, not a remote witness or protection against restoring an older full-disk image. Gate 8 remains OPEN.

## 2. Strict DPC1 API and runtime integration

### 2.1 Strict API

Source:
`src/native/pow_bench/src/noise_deployment_config.rs`

API:
`verify_signed_deployment_config_with_floors(wire, expected_network_id, deployment_authority_public_key, minimum_sequence, minimum_root_epoch)`

The strict API:
1. Rejects a zero external minimum root epoch.
2. Calls the existing signature/network/sequence/GRC1 verification path.
3. Requires the signed DPC1 `minimum_root_epoch` field to be at least the independent external floor.
4. Requires the verified GRC1 current tip epoch to be at least that external floor.
5. Returns `RootEpochBelowMinimum` if either signed floor or verified root tip is below the independent floor.

The former `verify_signed_deployment_config` API remains only as a clearly documented compatibility verifier for callers that intentionally validate the embedded DPC1 floor. It is still used by library-internal encoding/self-check logic and legacy unit tests; the executable `src/bin` path search found no direct legacy call.

### 2.2 Private-testnet node

Source:
`src/native/pow_bench/src/bin/private_testnet_node.rs`

Added required option:
`--deployment-config-min-root-epoch N`

The parser:
- accepts the flag once;
- rejects non-integer and zero values;
- treats the flag as part of the complete signed-peer-identity trust configuration;
- rejects incomplete combinations rather than silently falling back to the old verifier.

In the signed-identity startup path, the value is required and passed to `verify_signed_deployment_config_with_floors` before DCS1/IRG1 state acceptance and peer identity resolution.

The existing raw-key/non-signed-identity mode is not forced to supply this DPC1 trust flag.

### 2.3 Chain-import node

Source:
`src/native/pow_bench/src/bin/chain_import_node.rs`

Added provider-bound Noise option:
`--peer-noise-deployment-min-root-epoch N`

Provider-bound Noise mode requires a nonzero value alongside the existing DPC1 file, deployment-authority pin, DPC1 sequence floor, and trust-state inputs. The verified DPC1 is passed through the strict API before DCS1 and issuer-registry state are accepted.

The parser test verifies complete mode selection, presence of the new option, and rejection of a zero root-epoch floor.

### 2.4 Offline trust provisioner

Source:
`src/native/pow_bench/src/bin/devnet_trust_provisioner.rs`

The following operations now require `--minimum-root-epoch N` and call the strict DPC1 API:
- `update-issuer-status`;
- `issue-peer`;
- `rotate-peer`.

Their internal builders also take the explicit root floor and verify DPC1/GRC1 before constructing their respective signed artifacts. Test fixtures were updated to supply a synthetic floor.

A test-only canonical-intent/SHA-256 helper was added inside the provisioner's `#[cfg(test)]` module so the binary test does not depend on crate-private helpers. The production visibility of the rotation-authorizer functions was not widened for this purpose.

### 2.5 Read-only successor-proof helper

Source:
`src/native/pow_bench/src/peer_identity_successor_proof.rs`

`DualAttestationEvidence` now carries `minimum_dpc1_root_epoch` separately from `minimum_dpc1_sequence`. The proof verifier uses the strict DPC1 API. Its existing status remains unchanged: this helper has no production caller, does not mutate stores, and does not activate identity or authorize startup.

## 3. DCS1 v2 format

Source:
`src/native/pow_bench/src/noise_deployment_config.rs`

DPC1 remains wire version 1. The local DCS1 persistence envelope has its own version field and is now version 2.

### 3.1 DCS1 v1 compatibility layout

- Magic: `DCS1`.
- State version: 1.
- Core length: 110 bytes.
- Checksum: 32 bytes.
- Total length: 142 bytes.
- Persisted fields: Network ID, deployment-authority fingerprint, highest DPC1 sequence, and exact DPC1 digest.
- Does not contain a governance-root epoch high-water.

### 3.2 DCS1 v2 layout

- Magic remains: `DCS1`.
- State version: 2.
- Core length: 118 bytes.
- Checksum: 32 bytes.
- Total length: 150 bytes.
- Preserves all v1 fields and appends `highest_root_epoch: u64` before the checksum.
- Checksummed bytes include the added root epoch.

Decoder behavior:
- accepts only exact v1/142-byte or v2/150-byte state records;
- validates magic, version, length, checksum, network, and deployment-authority fingerprint;
- rejects unknown versions, malformed state, and v2 empty/nonempty field inconsistencies;
- reports v1 `highest_root_epoch` as unknown internally until exact-current migration has established it.

### 3.3 DCS1 v2 high-water behavior

`DeploymentConfigStateStore::observe`:
- requires the verified manifest's current root epoch to be nonzero;
- persists DPC1 sequence, exact DPC1 digest, and GRC1 tip epoch together;
- accepts an exact same-sequence/same-digest/same-root-epoch restart idempotently;
- rejects a same-sequence digest conflict;
- rejects non-consecutive DPC1 sequence advances;
- rejects a successor whose GRC1 tip epoch is below the durable `highest_root_epoch` with `RootEpochRollback`;
- persists the next state atomically before updating the in-memory state.

`matches_current` now checks exact sequence, exact DPC1 digest, and exact GRC1 tip epoch. `highest_root_epoch()` is available for v2 state and returns `StateMigrationRequired` for a v1 state that has not yet been upgraded.

### 3.4 DCS1 v1 migration policy

The migration does not invent an unknown epoch from a successor:
- A v1 state with a previously accepted nonzero sequence can be upgraded only when the caller presents the exact same sequence and exact same DPC1 digest already recorded in v1.
- The verifier revalidates that signed manifest, obtains the actual GRC1 current tip epoch, and writes a v2 state.
- If a newer sequence is presented before exact-current migration, `StateMigrationRequired` is returned.
- After migration, a lower GRC1 epoch is rejected by the persisted v2 high-water.
- An uninitialized legacy state with sequence zero has no previously accepted manifest epoch; the first accepted verified manifest creates v2 state.

This behavior is intentionally fail-closed. Operators with an existing v1 state must provide the exact currently accepted signed DPC1 manifest once before advancing to a successor under v2.

## 4. Test evidence

### 4.1 DPC1/DCS1 module

Command:
`cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib noise_deployment_config::tests:: -- --nocapture`

Result:
- 6 passed.
- 0 failed.
- 0 ignored.

Coverage includes:
1. DPC1 signature/network/key/floor/chain binding.
2. Independent external root-epoch floor enforcement.
3. DCS1 v2 root-epoch high-water and rejection of a lower-epoch successor with a higher DPC1 sequence.
4. DCS1 v1 exact-current migration and refusal of a successor before migration.
5. DPC1 sequence continuity and signer-role separation.
6. DPC1 sequence/digest high-water, replay conflict, and missing-state fail-closed behavior.

### 4.2 Provisioner binary

Command:
`cargo test --manifest-path src/native/pow_bench/Cargo.toml --bin devnet_trust_provisioner -- --nocapture`

Result:
- 6 passed.
- 0 failed.

Coverage includes duplicate/private-seed argument rejection, bootstrap, peer artifact integrity, issuer status monotonicity, peer-key successor generation, and dual-attestation-gated rotation.

### 4.3 Chain-import binary

Command:
`cargo test --manifest-path src/native/pow_bench/Cargo.toml --bin chain_import_node -- --nocapture`

Result:
- 9 passed.
- 0 failed.

Coverage includes complete provider-bound Noise configuration, required deployment trust, and zero external root-floor rejection.

### 4.4 Private-testnet binary

Command:
`cargo test --manifest-path src/native/pow_bench/Cargo.toml --bin private_testnet_node -- --nocapture`

Result:
- 41 passed.
- 0 failed.

This includes signed-identity runtime, trust reload/issuer revocation, NRT1 reload behavior, durable generation state, and the existing node's other runtime/network tests.

### 4.5 Aggregate

Total targeted tests after DCS1 v2 implementation:
- DPC1/DCS1 module: 6 passed.
- Provisioner: 6 passed.
- Chain-import: 9 passed.
- Private-testnet: 41 passed.
- Total: 62 passed, 0 failed.

The full library test suite was not run for CP-0751. The earlier CP-0743 full parallel run remains recorded as 1,479 passed / 2 failed; the two tests passed individually on sequential rerun, but that does not make the earlier full run wholly green.

## 5. Additional validation

- `cargo fmt --manifest-path src/native/pow_bench/Cargo.toml --all -- --check`: PASS.
- `git diff --check`: PASS. Git emitted line-ending normalization warnings (LF may be replaced by CRLF on later Git writes) for existing modified working-copy files; no whitespace error was reported.
- `cargo check --manifest-path src/native/pow_bench/Cargo.toml --bins`: PASS, exit code 0.
- Build output contained unused-import/dead-code warnings in existing/candidate modules and binaries; no build error occurred.

## 6. Exact source evidence

Final source sizes and SHA-256:
- `src/native/pow_bench/src/noise_deployment_config.rs` — 47,898 bytes — `DF6779E287785A7C82D7B03FC222BE4848EEFFDE6342553301A58A560DD6126C`
- `src/native/pow_bench/src/bin/private_testnet_node.rs` — 390,106 bytes — `E482BCFE821893E9E50E5EFFEB19920E421FD098D6054CA375D8FEF765CAAD5B`
- `src/native/pow_bench/src/bin/chain_import_node.rs` — 89,025 bytes — `5A27780D3A534DC486D9A77218E665764811BC7C407B5F0DC321FF7839669CA3`
- `src/native/pow_bench/src/bin/devnet_trust_provisioner.rs` — 71,396 bytes — `D8C96FFA4B9CC8C12324572F901F26C013AE1A7320EF26F2D06922ABB690CCEA`
- `src/native/pow_bench/src/peer_identity_successor_proof.rs` — 13,321 bytes — `1BC1F817AFE58EF55E9A04D70CC486DDC9D688D75420A4BE01ABEE3694F84A3D`
- `src/native/pow_bench/src/noise_identity_rotation_authorization.rs` — 53,390 bytes — `623650EEAD9760E1D61FDB9907BDD3C124DE2899C656BD358105260845BAF1B9`

Executable call-site audit:
- 7 strict verifier invocations found across the inspected binaries (private-testnet, chain-import, and provisioner).
- 0 direct compatibility-verifier calls found under `src/native/pow_bench/src/bin`.
- The compatibility API remains in the library for documented compatibility/self-check and unit-test use.

## 7. Repository state and scope

Final Git check:
- Branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`.
- HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3` (unchanged).
- `git status --porcelain`: 70 entries.
- Modified tracked entries: 9.
- Untracked entries: 61.
- Staged entries: 0.

The nine modified tracked files and 61 untracked files represent the cumulative isolated worktree state from earlier CP checkpoints and existing candidate work, not 70 files newly authored in CP-0751. The working-tree diff stat shows 1,368 insertions / 113 deletions across nine tracked files; this is cumulative relative to the unchanged HEAD and must not be interpreted as CP-0751-only delta.

No commit, push, PR update, merge, reset, checkout, clean, stash, or worktree cleanup was performed. The root checkout and protected G2/G8 worktree were not changed by this checkpoint. No production C/D identity vault, peer-identity PIV2 directory, real signer key, owner/operator pin, wallet, node, listener, mainnet, asset, liquidity pool, or public service was provisioned or mutated by this checkpoint. Tests used synthetic keys and temporary test paths.

## 8. Remaining limitations

1. The minimum DPC1 sequence and minimum root epoch are runtime configuration inputs. Their source and operator-change ceremony still need independent review; the CLI does not prove the person supplying the values is authorized.
2. DCS1 v2 is local filesystem state behind the existing writer lock. It does not resist a full-disk snapshot rollback, privileged Administrator tampering, hostile path replacement, controller/firmware rollback, or simultaneous C/D loss.
3. Actual DCS1 data-directory ACL, reparse-point ancestry, handle identity, and physical volume identity are not qualified by this checkpoint.
4. Existing DCS1 v1 stores with accepted state require one exact-current-manifest migration before advancing under v2; deployments must plan for that explicitly.
5. The owner/operator pin-provenance issue remains unresolved. STB1 is design-only (CP-0749); this checkpoint does not create or enroll a real independent operator.
6. PIV2 still has no production caller; C/D composite reconciliation is not integrated into node startup.
7. The full library test suite is not newly certified green.

## 9. Gate disposition and next step

- Strict DPC1 root-floor library API: implemented (CP-0750).
- Strict DPC1 floor wired into inspected runtime and provisioner paths: implemented and focused-tested (CP-0751).
- DCS1 v2 root-epoch high-water: implemented and focused-tested.
- DCS1 v1 safe migration: implemented and focused-tested for exact-current migration/refusal of premature successor.
- Owner/operator trust bundle and pin provenance: NOT IMPLEMENTED.
- Windows path/ACL/volume hardening and physical crash/disk-failure testing: NOT COMPLETE.
- PIV2 production caller and C/D reconciliation: NOT IMPLEMENTED.
- Gate 8: OPEN.

Next safe checkpoint CP-0752 should define and implement the pure STB1 codec/verifier against a verified DPC1/GRC1 context, using only synthetic test keys. It must not enroll real signer identities, change the production provisioner, create production C/D directories, or wire node startup. Keep the trust-root and genuine independent-operator ceremony explicit.

Mainnet, public token release, public trading, liquidity, and mining remain NO-GO until their separate technical, security, legal, and operational gates pass.

[executed on device: heymed (de0adbe3-6583-4775-a26e-c479a62aa941)]
