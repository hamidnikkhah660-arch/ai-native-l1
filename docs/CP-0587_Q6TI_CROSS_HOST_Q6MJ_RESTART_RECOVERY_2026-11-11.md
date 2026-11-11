# CP-0587 - Q6TI cross-host admission and Q6MJ restart recovery
Date: 2026-11-11

## Objective

Qualify the CP-0586 durable Q6TI pending-transaction journal across two independent processes on separate hosts. Q6TA Accepted is pending/journaled only; it does not mean mined, confirmed, finalized, or tradeable.

## Exact scope

- Base revision: CP-0586, `83185d4a243be83503321228d75f9c797f796e0e`.
- Node A runs the QFP6 Provider and Q6EA test services and acts as the pinned Noise peer.
- Node B is an ephemeral Windows GitHub Actions runner enrolled into the private NetBird overlay.
- Node A sends a Q6PB block admission and replay, then sends a signed Q6HA native-transfer transaction over the same pinned Noise session using Q6TI/Q6TA.
- Node B uses the Q6TI application dispatcher, hybrid transaction authenticator and Q6MJ journal. It persists the accepted pending transaction before returning Q6TA Accepted.
- A second independent Node B process reopens the QFP6 store and Q6MJ journal, recovers canonical QAP1 state, then restores/revalidates the pending transfer.
- The second process reports the exact same TXID and one pending transaction. Journal generation advances exactly once.
- QAP1 canonical height, state root, manifest anchor and generation remain identical across restart.

## Cross-host qualification: PASS

GitHub Actions run [43017541194](https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/43017541194) completed successfully on 2026-11-11.

- Workflow job `qfp6-qap1-cross-host`: completed / success.
- All 7 job steps succeeded, including private one-shot configuration validation, NetBird installation, ephemeral peer enrollment, remote admission/recovery, and peer disconnection.
- Node B overlay endpoint was `100.113.234.124:48664`; Node A callback was ready.
- Q6TI admission and duplicate handling passed.
- Q6MJ pending count remained 1.
- TXID before and after process restart matched exactly: `ae89ddd387768836056cba007104ed62d1f91bb9b634ff1c10160e72210b077d`.
- Q6MJ generation advanced from 4 to 5.
- Markers included `QFP6_QAP1_REMOTE_NODE_ADMISSION_AND_RESTART=PASS`, `QFP6_Q6MJ_CROSS_PROCESS_RECOVERY=PASS`, `QFP6_QAP1_NODE_A_Q6MJ_TXID_MATCH=PASS`, and `QFP6_QAP1_NODE_A_RESTART_CALLBACK_SENT=PASS`.
- The ephemeral Node B peer was disconnected successfully after qualification.

The cross-host workflow run reports head SHA `dd59e768ef6d50c2c7bec033a9315a3456ab93d5`, which was the PR head at dispatch time and contains the CP-0587 protocol/workflow code. The current PR head was subsequently advanced to `d827087b934cd1098eec9669f2a67648849ed48d` by a documentation-only commit; no protocol or workflow code changed after the qualified head. Latest-head Rust validation is running separately as run `43018636352`.

## Local verification

- `cargo fmt --all -- --check`: passed.
- `cargo check --all-targets --locked --offline`: passed.
- Q6TI/Noise/Supervisor targeted tests: 6 passed.
- Q6MJ/QAP1 journal tests and separate-process recovery checks passed as recorded in the PR's local verification.
- PowerShell runner parser, YAML workflow parse, and `git diff --check`: passed.

## Security and interpretation

- Deterministic Q6HA seeds and candidate-testnet Genesis are test-only fixtures, not wallet credentials and do not create QZXB mainnet value.
- Node B was reached through the private NetBird overlay and pinned Noise XX identity. Noise uses classical X25519; transport is not post-quantum.
- Provider/Q6EA pins and ML-DSA-65 receipt keys are ephemeral test-service material, not externally governed production trust.
- Q6TA Accepted means pending and journaled only. It is not mined, confirmed, finalized, or tradeable.
- The Q6MJ checksum is local integrity evidence, not an external anti-rollback anchor.
- This qualification does not enable production node startup, public Devnet/Mainnet, public issuance, production mining/payouts, public RPC/explorer, or QZXB/USDT settlement.
- The NetBird policy set observed during qualification included a broad All-to-All allow policy; this was not modified. Treat the overlay ACL as requiring least-privilege hardening before any long-lived/public deployment.

## Release gate

CP-0587 cross-host Q6TI/Q6MJ qualification is passed. Keep this PR as an engineering candidate until the latest-head CI/review state is checked and the next production-readiness gates are separately qualified. Do not merge or describe this result as Mainnet readiness.
