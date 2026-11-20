# CP-0678 - QFP6 Anchor Pinned, Config Bound, and Replay Startup Verified

Date: 2026-11-15
Project: AI-NATIVE L1 / QRun / QZXB / QFP6
Worktree: D:\Temp\ASUS\QRUN_QFP6_CP0596_20261111
Scope: LOCAL SINGLE-OPERATOR LOOPBACK ONLY.
Status: OWNER-REPORTED OUT-OF-BAND PIN RECORDED; CONFIG BOUND; ISOLATED RELEASE REPLAY STARTUP PASSED; ORIGINAL DATA UNCHANGED.

## 1. Owner-reported independent record

The owner confirmed that the exact canonical QFP6 manifest anchor from CP-0677 was copied into a separate Google Docs record. This checkpoint records that owner confirmation; the Google Docs contents were not independently accessed or inspected by the tool session.

Pinned value:
- Manifest: `qfp6-manifest-00000000000000001024.q6mf`
- Generation: `1024`
- Canonical QFP6 anchor: `652ad475a0646e285329d690f493b9b10bf89d44f6ff1cf381c96b7d83ed25b0`
- Ordinary SHA-256 of the raw manifest file (reference only): `29e3a69735cf0a1bfdc355b03e96b333868c279e2f0cebd833293e9f7a06401c`

The canonical anchor is derived by the QFP6 store algorithm:
`SHA-256("QRUN-V06-DURABLE-FORK-STORE-COMMITMENT-V1" || 0x00 || complete_raw_Q6MF_bytes)`.

## 2. Local package config updated and integrity rebound

Updated:
`release/qfp6-local-single-operator-devnet-2026-11-15/permissionless-config.json`

Added:
`permissionless_runtime.trusted_manifest_anchor = 652ad475a0646e285329d690f493b9b10bf89d44f6ff1cf381c96b7d83ed25b0`

New exact config SHA-256:
`89e7048fe36a326d7cd8d9f0c76ad1f695601400d373b795ac419e4c0e74978c`

Updated:
`release/qfp6-local-single-operator-devnet-2026-11-15/local-devnet-manifest.json`

Verified:
- actual config SHA-256 equals local manifest `permissionless_config_sha256`;
- Q6GA sidecar SHA-256 still equals config and manifest pins;
- Q6GD, Q6CP, Q6PN, Genesis and bootstrap artifact bindings remain valid;
- listener remains `127.0.0.1:30333`;
- public listener remains false;
- bootstrap peer count remains zero;
- approved outbound peer sync remains false;
- Q6AR remains false;
- Public Testnet and Mainnet authorization remain false.

Pre-change backups were preserved outside the repository:
- `D:\Temp\QFP6_CP0677_pre_anchor_backup\permissionless-config.pre-anchor.json`
- `D:\Temp\QFP6_CP0677_pre_anchor_backup\local-devnet-manifest.pre-anchor.json`

No Q6GA approval artifact or Genesis-bound file was changed.

## 3. Focused test results

Launcher anchor gate:
`cargo test --bin qrun_v06_node manifest_anchor_tests --locked --offline -j 1`
- 1 passed
- 0 failed

QFP6 durable fork store:
`cargo test --lib qrun_v06_pow_fork_store_candidate:: --locked --offline -j 1`
- 26 passed
- 0 failed
- includes rejection of missing/stale anchor, manifest checksum mismatch, durable replay, crash-boundary recovery and the 1,024-block retarget/checkpoint path.

Existing unrelated compiler warnings remain; the tests completed with exit code 0.

## 4. Release end-to-end startup using an isolated copy

To avoid altering the canonical local history, the Release `qrun_v06_node.exe` was run against a temporary replay-test package:
`D:\Temp\QFP6_CP0677_REPLAY_TEST_20261115`

The test package contained a copy of:
- all 1,025 Q6MF manifests (generations 0 through 1024);
- all 1,024 referenced QFP6 branch files;
- local mempool journals;
- Q6GA/Q6GD/Q6CP/Q6PN/Genesis/bootstrap artifacts.

The DPAPI-protected Noise key was referenced from its original protected package path and was not duplicated into the scratch package. The scratch config used `max_nonce_attempts_per_block=1` to keep the smoke run bounded.

Release node output:
- `owner_genesis_approval=Q6GA_ED25519_MLDSA65_VERIFIED`
- `owner_genesis_approval_scope=LOCAL_CANDIDATE_ONLY_NOT_MAINNET_AUTHORIZATION`
- `QFP6 PERMISSIONLESS BASE RUNTIME: STARTING (candidate qualification only)`
- `listener=127.0.0.1:30333`
- `bootstrap_peer_count=0`
- `Q6TS/Q6QA=NOT_CONFIGURED`
- `external_quote_asset_admission=DENIED_FAIL_CLOSED`
- `Provider=NOT_REQUIRED; Q6EA=NOT_REQUIRED; QAP1=NOT_REQUIRED`

The launcher reaches this STARTING state only after the QFP6 durable store successfully opens with the supplied anchor and rebuilds/replays its existing history. The loopback TCP listener was independently observed on `127.0.0.1:30333` and owned by the test node process.

## 5. Test cleanup and original-data preservation

The isolated test node process was terminated after startup evidence was captured. Follow-up checks confirmed:
- qrun_v06_node process count: 0
- TCP listener count on port 30333: 0
- original data directory: 1,025 manifests, 1,024 branches
- isolated scratch data directory: 1,025 manifests, 1,024 branches
- original canonical anchor remains `652ad475a0646e285329d690f493b9b10bf89d44f6ff1cf381c96b7d83ed25b0`
- scratch canonical anchor remains identical to the original.

The original runtime data directory was not opened by the Release node during this end-to-end test and remains unchanged. The original package config is now anchor-pinned and integrity-bound, but the canonical data directory has not yet been run as a live service.

## 6. Current boundary and next controlled action

Completed:
1. Canonical local manifest/branch integrity audit.
2. Owner-reported out-of-band anchor recording.
3. Config and manifest hash rebinding.
4. Anchor-gate unit test and QFP6 store regression suite.
5. Release end-to-end replay/startup verification on an isolated copy.

Not claimed:
- original canonical data directory running;
- public P2P peers or public reachability;
- independent external seed/bootstrap infrastructure;
- independent consensus, cryptography or economics review;
- Public Testnet or Mainnet authorization;
- public issuance or real-value transfer.

Before starting the original canonical data directory, decide whether the node should be permitted to mine/advance its local history. Any new durable manifest changes the latest anchor and will require a fresh out-of-band pin before the next restart. Do not start mining on the canonical store without an explicit anchor-persistence/rotation procedure. Keep all public listener, router/firewall and Public Testnet paths disabled.

CP-0678 supersedes CP-0677 with the successful pin/config/test status. It does not claim a public network launch.
