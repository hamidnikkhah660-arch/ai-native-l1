# CP-0566C Release Manifest — 2026-11-05

## Purpose and decision

This is a locally prepared, non-published release manifest for the QFP6/QAP1 two-host qualification. It describes the integration footprint that passed filtered QAP1/QFP6 validation on a detached worktree based on the live GitHub default-branch tip. It is a validated integration set, not a claim that no smaller dependency set is theoretically possible.

## Verified source identities

- Default branch: main
- Default-branch SHA: ba120c1191956468a1106daff6a915c155f50f8a
- Candidate baseline Commit: 4b8cfd53f8debb9d77086e6830e6d10f827ceb2d
- Merge base: 0c489c1b19fe85a8956872b8b23e83342863f475
- GitHub compare: main...4b8cfd53f8debb9d77086e6830e6d10f827ceb2d is diverged, 259 ahead / 18 behind.
- Remote branch carrying the candidate base commit is feat/qrun-v05-netbird-cross-host-qualification-20261102; the newer expected branch feat/qzxb-usdt-trading-gate-20261104 was not present on origin during live verification.

## Release lanes

### Lane A — default branch (main)

Only this file is required on the default branch to make the manual workflow discoverable:

- .github/workflows/qfp6-qap1-netbird-cross-host.yml

The workflow file must also be present on the selected feature branch so the branch-specific workflow contents and branch guard agree. Do not publish Rust implementation or Runner/controller tooling to main solely to expose workflow_dispatch.

### Lane B — feature qualification branch

The feature branch needs:

- The same .github/workflows/qfp6-qap1-netbird-cross-host.yml file.
- tools/qrun-v06-qfp6-qap1-node-a-controller.ps1.
- tools/qrun-v06-qfp6-qap1-runner.ps1.
- The validated Crate integration footprint listed below.
- The external fixture dependencies listed below.
- docs/engineering/CP-0566_QFP6_QAP1_CROSS_HOST_QUALIFICATION_DESIGN_2026-11-05.md as qualification evidence/design documentation.

#### Crate integration footprint

Unique paths reconciled under src/native/pow_bench: 105.

#### External fixture dependencies

New paths required outside src/native/pow_bench by the trial dependency closure: 4.

- src/native/pow_bench/Cargo.lock
- src/native/pow_bench/Cargo.toml
- src/native/pow_bench/src/bin/devnet_node.rs
- src/native/pow_bench/src/bin/private_testnet_node.rs
- src/native/pow_bench/src/bin/qrun_v05_external_cas_provider.rs
- src/native/pow_bench/src/bin/qrun_v05_local_node.rs
- src/native/pow_bench/src/bin/qrun_v05_noise_key_provision.rs
- src/native/pow_bench/src/bin/qrun_v05_noise_keygen.rs
- src/native/pow_bench/src/bin/qrun_v05_partition_proxy.rs
- src/native/pow_bench/src/bin/qrun_v05_pow_local_node.rs
- src/native/pow_bench/src/bin/qrun_v05_pow_rate_probe.rs
- src/native/pow_bench/src/bin/qrun_v05_public_alpha_process_smoke.rs
- src/native/pow_bench/src/bin/qrun_v05_reference_time_authority.rs
- src/native/pow_bench/src/bin/qrun_v05_smoke_tx_builder.rs
- src/native/pow_bench/src/bin/qrun_v05_smoke_tx_sender.rs
- src/native/pow_bench/src/bin/qzbe_v04_candidate_smoke.rs
- src/native/pow_bench/src/bin/qzbe_v04_peer_node.rs
- src/native/pow_bench/src/bin/qzbe_v04_test_tx_signer.rs
- src/native/pow_bench/src/bin/qzxb_amm_client.rs
- src/native/pow_bench/src/bin/qzxb_wallet.rs
- src/native/pow_bench/src/chain_admission.rs
- src/native/pow_bench/src/chain_import.rs
- src/native/pow_bench/src/consensus.rs
- src/native/pow_bench/src/consensus_native_recovery_gate_candidate.rs
- src/native/pow_bench/src/devnet_noise_transport_candidate.rs
- src/native/pow_bench/src/devnet_profile_candidate.rs
- src/native/pow_bench/src/external_cas_aws_kms_signer_candidate.rs
- src/native/pow_bench/src/external_cas_disk_provider_candidate.rs
- src/native/pow_bench/src/external_cas_floor_store_candidate.rs
- src/native/pow_bench/src/external_cas_noise_transport_candidate.rs
- src/native/pow_bench/src/external_cas_offhost_anchor_aws_dynamodb_candidate.rs
- src/native/pow_bench/src/external_cas_offhost_anchor_candidate.rs
- src/native/pow_bench/src/external_cas_offhost_anchor_file_store_candidate.rs
- src/native/pow_bench/src/external_cas_offhost_anchor_node_lifecycle_candidate.rs
- src/native/pow_bench/src/external_cas_offhost_anchor_noise_daemon_candidate.rs
- src/native/pow_bench/src/external_cas_offhost_anchor_noise_transport_candidate.rs
- src/native/pow_bench/src/external_cas_offhost_anchor_protocol_candidate.rs
- src/native/pow_bench/src/issuance_schedule.rs
- src/native/pow_bench/src/lib.rs
- src/native/pow_bench/src/monetary_allocation_v04_candidate.rs
- src/native/pow_bench/src/monetary_genesis_v04_candidate.rs
- src/native/pow_bench/src/monetary_issuance_v04_candidate.rs
- src/native/pow_bench/src/monetary_ledger_v04_candidate.rs
- src/native/pow_bench/src/monetary_pow_v04_candidate.rs
- src/native/pow_bench/src/monetary_pow_v04_checkpoint_candidate.rs
- src/native/pow_bench/src/monetary_pow_v04_checkpoint_store_candidate.rs
- src/native/pow_bench/src/monetary_pow_v04_store_candidate.rs
- src/native/pow_bench/src/monetary_runtime_v04_candidate.rs
- src/native/pow_bench/src/monetary_transition_v04_candidate.rs
- src/native/pow_bench/src/offline_signing_key_store.rs
- src/native/pow_bench/src/private_testnet_archive_range_loopback_candidate.rs
- src/native/pow_bench/src/private_testnet_consensus.rs
- src/native/pow_bench/src/private_testnet_driver.rs
- src/native/pow_bench/src/private_testnet_fork_choice.rs
- src/native/pow_bench/src/private_testnet_fork_store.rs
- src/native/pow_bench/src/private_testnet_mempool_candidate.rs
- src/native/pow_bench/src/private_testnet_monetary_wire.rs
- src/native/pow_bench/src/private_testnet_wire.rs
- src/native/pow_bench/src/qrun_node_shutdown_signal_candidate.rs
- src/native/pow_bench/src/qrun_v05_checkpoint_candidate.rs
- src/native/pow_bench/src/qrun_v05_checkpoint_migration_candidate.rs
- src/native/pow_bench/src/qrun_v05_checkpoint_migration_recovery_candidate.rs
- src/native/pow_bench/src/qrun_v05_fee_pow_wire_candidate.rs
- src/native/pow_bench/src/qrun_v05_genesis_candidate.rs
- src/native/pow_bench/src/qrun_v05_history_archive_candidate.rs
- src/native/pow_bench/src/qrun_v05_noise_transport_candidate.rs
- src/native/pow_bench/src/qrun_v05_pow_fork_runtime_candidate.rs
- src/native/pow_bench/src/qrun_v05_profile_identity_candidate.rs
- src/native/pow_bench/src/qrun_v05_runtime_candidate.rs
- src/native/pow_bench/src/qrun_v06_asset_registry_candidate.rs
- src/native/pow_bench/src/qrun_v06_canonical_execution_candidate.rs
- src/native/pow_bench/src/qrun_v06_checkpoint_candidate.rs
- src/native/pow_bench/src/qrun_v06_external_anchor_candidate.rs
- src/native/pow_bench/src/qrun_v06_genesis_descriptor_candidate.rs
- src/native/pow_bench/src/qrun_v06_historical_trust_candidate.rs
- src/native/pow_bench/src/qrun_v06_node_runtime_candidate.rs
- src/native/pow_bench/src/qrun_v06_noise_transport_candidate.rs
- src/native/pow_bench/src/qrun_v06_orderbook_candidate.rs
- src/native/pow_bench/src/qrun_v06_peer_listener_candidate.rs
- src/native/pow_bench/src/qrun_v06_pow_fork_choice_candidate.rs
- src/native/pow_bench/src/qrun_v06_pow_fork_store_candidate.rs
- src/native/pow_bench/src/qrun_v06_pow_wire_candidate.rs
- src/native/pow_bench/src/qrun_v06_profile_pin_candidate.rs
- src/native/pow_bench/src/qrun_v06_profile_trust_candidate.rs
- src/native/pow_bench/src/qrun_v06_profile_trust_dynamodb_floor_candidate.rs
- src/native/pow_bench/src/qrun_v06_qap1_coordinator_candidate.rs
- src/native/pow_bench/src/qrun_v06_qap1_journal_candidate.rs
- src/native/pow_bench/src/qrun_v06_quote_asset_qualification_candidate.rs
- src/native/pow_bench/src/qrun_v06_tokenomics_candidate.rs
- src/native/pow_bench/src/qrun_v06_unified_asset_candidate.rs
- src/native/pow_bench/src/qzbe_amm_ingress_candidate.rs
- src/native/pow_bench/src/qzbe_history_replay_candidate.rs
- src/native/pow_bench/src/qzbe_tx_ingress_candidate.rs
- src/native/pow_bench/src/qzxb_amm_candidate.rs
- src/native/pow_bench/src/qzxb_wallet_store_candidate.rs
- src/native/pow_bench/src/reference_time_authority.rs
- src/native/pow_bench/src/reference_time_store.rs
- src/native/pow_bench/src/reference_time_tcp.rs
- src/native/pow_bench/src/reward_pool_durable_store.rs
- src/native/pow_bench/src/state_machine.rs
- src/native/pow_bench/src/store_writer_lock.rs
- src/native/pow_bench/src/timestamp_policy.rs
- src/native/pow_bench/src/transaction_auth.rs
- src/native/pow_bench/tests/fixtures/cp0419_qzbe_genesis_checkpoint.hex
- src/native/pow_bench/tests/qrun_node_shutdown_signal_subprocess_candidate.rs

- simulations/quantumzxb_v04_genesis_vectors.txt
- simulations/quantumzxb_v04_issuance_schedule_vectors.txt
- simulations/quantumzxb_v04_ledger_snapshot_vectors.txt
- simulations/quantumzxb_v04_transition_profile_vectors.txt

## Validated gates on the mainline-based integration trial

| Gate | Result |
|---|---:|
| cargo fmt --check | PASS |
| QAP1 filtered library tests | 24 passed / 0 failed |
| QFP6 filtered library tests | 37 passed / 0 failed |
| Total filtered QAP1/QFP6 tests | 61 passed / 0 failed |
| Literal include_str! / include_bytes! dependency closure | 44 references, 0 unresolved |

These are filtered library tests, not the complete Crate test suite. Two-process/restart tests run on one physical Windows host; they do not constitute cross-host qualification.

## Explicit exclusions

- The remaining paths in the GitHub compare response outside src/native/pow_bench are not included unless a later dependency audit proves a specific path is required.
- Unrelated site, market UI, wallet, funding, historical design documents, release checksum refreshes and unrelated workflows are excluded from this qualification package.
- The old 259-commit divergent history is not merged into main as a shortcut.
- No AWS resource, paid service, public RPC, public listener, production secret, real-money trade, QZXB market listing or liquidity operation is part of this CP-0566C qualification.

## Initial publication and execution blockers (historical, 2026-11-05)

The following blockers were true when this manifest was first prepared. They were subsequently resolved for the scoped CP-0566C candidate qualification: the workflow was available on main, the technical branch was published, Node A reconnected to NetBird, the reviewed narrow peer policies were used, and a clean feature commit was dispatched.

## Original preparation safety record (historical, 2026-11-05)

- Main worktree: retained at the original HEAD with its existing change entries; no cleanup, staging, reset or commit.
- Clean mainline baseline worktree: detached at ba120c1191956468a1106daff6a915c155f50f8a, zero changes.
- Integration trial worktree: detached at the same SHA, with local changes representing the validated transplant.
- No commit, push, merge, remote branch creation, workflow dispatch, GitHub secret write, NetBird login, ACL change, public listener, cloud provisioning or real transaction was performed.

## Cross-host qualification status update (2026-11-06)

CP-0566C candidate cross-host qualification PASSED on exact feature commit `30bd6a19da87a991b51feed4a7a76aebf1895bff` in GitHub Actions run [42205440686](https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/42205440686). The job completed successfully; the ephemeral NetBird peer disconnect/cleanup step also succeeded. See `CP-0566C_FINAL_MAINLINE_RELEASE_PREP_2026-11-05.md` for exact evidence, state commitments and limits.

This is a private-overlay, two-host candidate qualification using Node A on the user's Windows host and an ephemeral GitHub-hosted Windows Runner as Node B. It is not a public Devnet/Mainnet, independent-operator qualification, production security approval or real-value transaction. PR #135 remains OPEN and Draft.

The owner reconfirmed the eight-bucket CP-0566D target on 2026-11-06: 1B owner Genesis, up to 3B PoW mining/security, and six conditional 1B reserves. CP-0566D supersedes CP-0437 for future production design. The QFP6 CP-0528 code is a candidate implementation of that selected model, not frozen production consensus. Issue [#136](https://github.com/hamidnikkhah660-arch/ai-native-l1/issues/136) tracks profile/source/docs integration, exact mining-schedule remainder handling and lifecycle invariants.
## Integrity / counts

Historical Crate diff paths (origin/main to local candidate HEAD): 83.
Dirty/untracked Crate paths in the main worktree at manifest generation: 44.
Unique Crate integration paths: 105.
External fixture paths added to the trial: 4.
Integration trial status entries: 109.

### Workflow dependency hardening (2026-11-05)
The workflow now pins actions/checkout to the immutable upstream commit
3d3c42e5aac5ba805825da76410c181273ba90b1 (release v7.0.1), rather than a movable major-version tag.
The upstream tag commit is GitHub-verified; its action metadata declares node24.
The exact same Workflow bytes are present in the main-overlay and feature-overlay.
### Installed NetBird binary trust-path hardening (2026-11-05)
The workflow no longer accepts an already-present NetBird CLI based on version string alone.
The reuse path also requires a valid Windows Authenticode signature with NetBird GmbH as signer.
If that check fails, the workflow downloads the pinned MSI and verifies both its fixed SHA-256 and Authenticode signer before installation.
### Mainline-based feature preparation update (2026-11-05)
The security fix PR #134 is merged. The current mainline base for the isolated QRun feature preparation worktree is 8de9812e7d1a49020f1a7fc169c40d4b8a72a144. A 114-file feature overlay was applied with an exact Git status path-set match and zero unexpected paths. On this base, cargo fmt passed; focused QAP1 passed 24/24 and focused QFP6 passed 37/37; Controller/Runner PowerShell AST, Workflow YAML and policy marker checks passed. See CP-0566C_MAINLINE_FEATURE_PREP_2026-11-05.md for the complete evidence and limits. Full all-target testing and actual two-host qualification remain separate open gates.
### Full all-target validation completed (2026-11-05)
The mainline-based feature preparation worktree passed cargo test --all-targets --locked --offline with exit code 0 in 510.33 seconds: 1,268 library tests passed, zero failed, and every binary/integration target completed successfully. Existing compiler warnings concerned unused imports, unused mutability and dead code only. Full evidence is recorded in CP-0566C_MAINLINE_FEATURE_PREP_2026-11-05.md. At the time of this 2026-11-05 entry, this was single-host local evidence; the subsequent 2026-11-06 cross-host outcome is recorded in the qualification update above.
### Two-host execution evidence (2026-11-06)
- Rust validation CI run `42203421682` on `30bd6a1`: all three jobs passed.
- QFP6/QAP1 cross-host run `42205440686`: workflow conclusion SUCCESS; Node B server and restart workers passed; exact Manifest Anchor, State Root, Height and Generation continuity was verified by the controller; ephemeral peer cleanup passed.
- Temporary Actions secrets were deleted after the run. The local NetBird control plane remained connected; no VPN route, firewall or ACL changes were performed during cleanup.
- This update supersedes the initial NOT RUN status above only for the stated private-overlay qualification scope. It does not close the remaining public Mainnet gates.
