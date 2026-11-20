# CP-0743 — Exact-current DPC1 / IRG1 high-water proof binding

Date: 2026-11-16
Disposition: implemented and tested in isolated worktree; read-only proof composition only.

## Change

The anchored successor proof now requires references to already-open:
- DeploymentConfigStateStore (DCS1);
- IssuerRegistryStateStore (IRH1).

The proof never opens, initializes, observes, accepts, or writes either store.

### DCS1 API

DeploymentConfigStateStore::matches_current(&VerifiedDeploymentConfig):
- checks network and deployment-authority fingerprint against the store identity;
- rejects an uninitialized high-water (StateMissing);
- requires exact sequence and manifest digest equality;
- rejects any stale/future/different accepted snapshot (StateNotCurrent).

### IRH1 API

IssuerRegistryStateStore::matches_current_registry(&VerifiedIssuerRegistry, &VerifiedGovernanceRootChain):
- requires the proof's verified root chain to equal the store's root chain;
- checks network and current Governance key binding;
- rejects an uninitialized accepted registry (StateMissing);
- resolves the persisted Governance fingerprint only through the already-verified historical root chain;
- re-verifies the persisted signed IRG1 bytes under that historical key;
- requires exact sequence and digest equality with the proof's verified registry;
- rejects a different current registry (StateNotCurrent).

The proof calls these methods after cryptographically verifying DPC1 and IRG1, then applies the DPC1 registry floor and active issuer-key checks.

## Tests and validation

- Composite anchored-successor proof test: PASS — 1 passed, 0 failed. Positive path requires current DCS1 and IRH1 snapshots. Added stale-but-valid DPC1 vs newer DCS1 and stale-but-valid IRG1 vs newer IRH1 rejection cases. Existing tampered signature, wrong network, revoked issuer, issuer-key mismatch, scope mismatch, expired NPI1 and NRT1 tamper cases remain covered.
- noise_identity_rotation_authorization::tests: PASS — 15 passed, 0 failed.
- noise_deployment_config::tests: PASS — 3 passed, 0 failed.
- noise_issuer_registry::tests: PASS — 5 passed, 0 failed.
- cargo check --manifest-path src/native/pow_bench/Cargo.toml --bin devnet_trust_provisioner: PASS, exit code 0; existing unrelated crate warnings remain.
- cargo fmt --manifest-path src/native/pow_bench/Cargo.toml --all -- --check: PASS.
- git diff --check: PASS (only existing LF/CRLF working-copy notices).

## Source hashes after CP-0743

- noise_deployment_config.rs: 92469A5D28B73ED77D06FBF563DB593A0A405E72E621F2E06969189568E077D1
- noise_issuer_registry.rs: 3829E19DB8B7FFEEF0559FF423893FDDF1268C99B3FE0BF09B1F12444EE12403
- peer_identity_successor_proof.rs: 3120BFBD20A04BC6A39352A5BA6170E8F9F779CC1CF3E2FC611F369D5922019F
- noise_identity_rotation_authorization.rs: 8CDEA7FF30CBE88124C5CA204237797818532495800D5027C04453A4C659381F

## Security boundary

- These are process-local durable state snapshots protected by existing writer locks and local high-water files; they are not hardware monotonic counters or an external witness.
- The proof only establishes exact equality against the store objects supplied by its caller. The caller must open the correct protected production stores, with trusted launch-time network, deployment authority, DPC1 minimum sequence and root-chain inputs, before invoking the proof.
- This does not resolve whole-directory rollback/deletion or rollback of the trusted launch configuration.
- Role-byte mapping and genesis/profile provenance remain explicitly unresolved per CP-0741.
- The proof remains evidence-only; no recovery writer, startup authorization, identity activation, key creation, node/listener operation or public deployment is introduced.

## Scope and repository state

- Isolated worktree only: D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116.
- No production DCS1/IRH1 data, keys, active node, listener, public network or public website was touched.
- No stage, commit, push, merge, reset or cleanup was performed.
- Existing pre-change modified/untracked files were preserved.

## Resume point

CP-0743 is complete. Next work should audit and, if appropriate, integrate the already-open DCS1/IRH1 store references into the intended production proof caller. Before that, define the versioned peer-identity role and genesis/profile scope contract (CP-0741). Do not add a recovery writer or enable startup/activation until the complete caller, trust inputs and recovery procedure have separate review.

## Full-library regression follow-up

- Full parallel library run: 1,479 passed, 2 failed, 0 ignored (1,481 total). The two failures were outside the CP-0743 identity/trust modules:
  - external_cas_offhost_anchor_noise_daemon_candidate::tests::worker_panic_releases_active_connection_counts_failure_and_is_reported
  - qrun_v06_node_supervisor_candidate::tests::cp0604_permissionless_supervisor_mines_and_recovers_durable_genesis_state
- Both exact tests passed when rerun individually and sequentially (1 passed each, exit code 0). This is consistent with concurrency/timing sensitivity in the parallel full-suite run; the root cause is not established, so the full suite is not recorded as wholly passing.
