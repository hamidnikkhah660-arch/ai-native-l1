# CP-0566C final mainline release preparation

Original preparation date: 2026-11-05
Qualification update: 2026-11-06
Current main base: `c536caec696217234d6b35582663c0aa58652b9c`
Technical branch: `feat/qzxb-usdt-trading-gate-20261104`
Qualified feature commit: `30bd6a19da87a991b51feed4a7a76aebf1895bff`

## Release source reconciliation
- The integration package began as a 114-path feature overlay on the mainline-based preparation worktree; subsequent qualification fixes are recorded as exact commits on the technical branch.
- The default-branch workflow was preserved and invoked manually against the exact feature SHA.
- PR #135 is still OPEN and Draft. No merge or production release was performed.

## Test evidence
- Local `cargo fmt --manifest-path src/native/pow_bench/Cargo.toml -- --check`: PASS.
- Local targeted QAP1 Node A driver compile (`cargo test --locked --no-run ... qfp6_qap1_node_a_driver`): PASS.
- GitHub Actions Rust validation run [42203421682](https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/42203421682), exact head `30bd6a19da87a991b51feed4a7a76aebf1895bff`: all 3 jobs PASS, including Format/Check/Test, Windows PMT4/TXN4 two-node loopback, and EVM/wallet/dependency audit.
- Actual QFP6/QAP1 cross-host run [42205440686](https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/42205440686), same exact head: conclusion SUCCESS; the cross-host job and ephemeral-peer cleanup both succeeded.

## Cross-host qualification result — 2026-11-06
The test paired Node A on the user's Windows host with an ephemeral GitHub-hosted Windows Runner (Node B) enrolled in the private NetBird overlay. It is a two-host candidate qualification, not an independently operated public network or Mainnet deployment.

Verified evidence from run `42205440686`:
- `QFP6_QAP1_NODE_B_BIND_PREFLIGHT=PASS` and `QFP6_QAP1_RUNNER_OVERLAY_READY=PASS`.
- Node A callback readiness and the Node B server worker completed successfully.
- `QFP6_QAP1_PROCESS_SERVER=PASS`.
- The separate restart process emitted `QFP6_QAP1_RESTART_SERVER=PASS`.
- `QFP6_QAP1_REMOTE_NODE_ADMISSION_AND_RESTART=PASS` and the authenticated Node A restart callback was sent.
- Manifest Anchor: `e736515927f69406d12eda1d0fa76328578d34aecb9fd00a8ba312ac89ef79d1`.
- State Root: `e5c5a9ac79379adb090caf9bd1f798e27556a5b4ecdb9b612d91e8d418330363`.
- Height: `1`; Generation: `1`. The restart process reported the same values.
- Workflow cleanup disconnected the ephemeral NetBird peer. After completion, the GitHub Actions secret list was empty; Node A remained connected to its own NetBird control plane.

The test demonstrates authenticated candidate admission, replay rejection checked by the Node A driver, and second-process QAP1 state continuity for the tested fixture. It does not establish public inbound reachability, independent operator diversity, full-history public sync, production consensus calibration, public RPC/explorer operations, external security review, or real-value transfers.

## Remaining production gates
- At least three independent node/benchmark operators across separate hosts/providers and external-network reachability.
- The owner-confirmed target is now CP-0566D: 1B owner Genesis (10%), up to 3B PoW mining/security (30%), and six 1B conditional reserves (10% each). CP-0566D supersedes CP-0437 for future production design; preserve CP-0437 as historical evidence. QFP6 CP-0528 is a candidate implementation of this target, not frozen production consensus. Issue [#136](https://github.com/hamidnikkhah660-arch/ai-native-l1/issues/136) tracks policy/source/docs integration, mining-schedule remainder semantics and full lifecycle invariants.
- Full-history replay or an independently verifiable checkpoint rollover and monotonic anti-rollback trust model, end to end.
- Independent protocol/cryptography/security review, remediation and reproducible signed release artifacts.
- Public devnet operation, native wallet/restore qualification, public explorer/read-only API, monitoring and incident/reorg procedures.
- A genuine, independently verifiable settlement and market path before any QZXB/USDT trade claim.

## Non-claims
No value-bearing Mainnet, public RPC, public explorer, real USDT liquidity, cross-chain bridge, exchange listing, public QZXB price or real-money QZXB trade is claimed. PR #135 remains Draft; its feature qualification is not a production approval.
