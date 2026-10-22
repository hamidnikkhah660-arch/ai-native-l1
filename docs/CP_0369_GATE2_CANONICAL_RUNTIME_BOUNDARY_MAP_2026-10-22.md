# CP-0369 — Gate 2 Canonical Runtime Boundary Map

Date: 2026-10-22
Reviewed commit: `863f43fbd8bb3cf1c99a55d4bc16ce9bdf58f20c` (main after PR #32)
Project: QuantumZXB / AI-Native L1
Scope: evidence-oriented source/call-boundary inventory; documentation only.

## Result

**Gate 2 remains OPEN.** The tree contains useful monetary-state, issuance, MBK3/PMT3 and MBK4/PMT4 candidate implementations with local and cross-language tests. It does not yet select and run one frozen production monetary protocol through a canonical public node. This map deliberately distinguishes existing candidate APIs from an end-to-end production path; it makes no runtime or consensus change and is not a gate pass.

## Actual source boundaries

| Layer | Verified source/API | Evidence present | Boundary / missing evidence |
|---|---|---|---|
| Default executable | `src/native/pow_bench/src/main.rs` | Benchmark-oriented entry point; documented benchmark output explicitly says its synthetic work is not cryptographic PoW. | Not a native chain node, producer or public consensus runtime. |
| Module registry | `src/native/pow_bench/src/lib.rs` | Exposes legacy ledger, monetary state, issuance schedule, chain admission/import, PMT3/PFM3 and PMT4/PFM4 modules. Multiple module-level comments identify candidate-only/not-consensus-wired boundaries. | Module exports are not runtime wiring and do not select one protocol version. |
| Monetary state | `state_machine.rs::MonetaryLedgerState` — `genesis`, `total_value`, `expected_miner_reward`, `apply_block`, `apply_v4_hybrid_block_candidate`, `encode_snapshot`, `decode_snapshot` | Candidate Genesis/allocation validation; height-derived reward; cumulative issuance counter, 10B global-value check, state root and versioned snapshot checks; negative, replay and restart tests. | Candidate code only. The checks prove properties of exercised APIs, not every public-node state transition. |
| Shared emission arithmetic | `issuance_schedule.rs::IssuanceParameters` | Checked/capped integer schedule and boundary/remaining-budget/large-height tests; candidate Python vectors are checked against Rust. | A reusable schedule is not the owner-frozen production emission policy. |
| Consensus parameter binding | `consensus.rs::ConsensusParameters::validate_monetary_execution_compatibility` plus the private-testnet driver/fork-choice callers | Monetary execution rejects a mismatch between its configured issuance schedule and the monetary state machine's schedule. The PMT4 fork-choice suite covers this mismatch. | Uses provisional candidate parameters; does not freeze network ID, Genesis, wire/snapshot version, fee policy, activation/migration and producer behavior as one production profile. |
| Admission APIs | `chain_admission.rs` — legacy monetary and explicit MBK4 live/historical admission/replay methods | Explicit path APIs check timestamps/clock policy and delegate to atomic state transitions. | Method existence is not proof that every live node/import/reorg/restart path calls the same monetary APIs. |
| Generic durable importer | `chain_import.rs::ChainImportService` | Stages the generic `LedgerState`, persists via `snapshot_store`, then publishes the committed state; tests cover commit failure and reopen/replay behavior. | It is not an importer for `MonetaryLedgerState` / MBK4 monetary snapshots. This is a concrete end-to-end integration gap, not a missing unit test. |
| PMT3 / PFM3 candidate | `private_testnet_monetary_wire.rs`, `private_testnet_monetary_fork_choice.rs`, `private_testnet_monetary_fork_store.rs` | Version-specific monetary wire, branch archive, fork choice, reward validation and deterministic replay. | Separate private-testnet candidate. It must not be silently combined with V4 semantics. The old PMT3 smoke path can reject transfers and is not a public production runtime. |
| PMT4 / PFM4 candidate | `private_testnet_v4_hybrid_fork_choice_candidate.rs`, `private_testnet_v4_hybrid_fork_store_candidate.rs` | MBK4/TXN4 admission, signature/manifest binding, candidate branch archive, reorg, persisted manifest, replay/reopen and optional external-CAS contract calls. | Candidate research/testnet store, not one frozen public canonical runtime. Its CAS transport is an interface; existing in-process/fake providers in tests do not prove a deployed HTTPS provider or independent trust domain. |
| Local smoke runtime | `src/native/pow_bench/src/bin/private_testnet_node.rs` and its local PMT3/PMT4 smoke modes | Local loopback diagnostics exercise selected paths. | Diagnostic/easy-PoW profile; reports `public_launch_approved=false`. Not public-network, real mining or production transfer readiness evidence. |
| Wire profile | `protocol_profile.rs` | Defines the generic framed-message constants and message type registry. | This does not itself freeze the full monetary protocol profile, Genesis bytes/hash, selected PMT/TXN version or migration policy. |

## Gate 2 exit criteria mapped to current gaps

1. **Freeze one production profile:** select and version network ID, exact Genesis manifest/bytes/hash, block/transaction/snapshot versions, consensus/PoW settings, fees, miner subsidy/beneficiary, founder/treasury/public-goods accounting, activation height and migration/replay rules. Current code has several explicit profiles/candidates, not a single owner-approved end-to-end profile.
2. **Prove allocation and lifetime supply:** account for every Genesis bucket and beneficiary binding; prove the 10,000,000,000-coin ceiling through every state-creation path, block validation/import, competing-fork replay/reorg, persistence, restart, and snapshot restore. Current unit/snapshot/schedule tests are necessary but do not establish the whole public runtime invariant.
3. **Wire one path end to end:** implement the chosen monetary importer/producer path and ensure validation, durable commit, fork-choice, reorg, replay, state root, snapshot and RPC/explorer derive the same canonical state. The current generic importer is legacy `LedgerState`; PMT4 is a separate candidate store.
4. **Independent conformance:** freeze language-neutral byte vectors for the selected Genesis/block/transaction/snapshot; compare two independently built implementations for state root, balances, issuance counter and canonical tip on ordinary blocks, boundary/over-cap cases, invalid rewards, forks/reorg, restart and replay.
5. **Independent sign-off:** externally review economic transitions, supply issuance, serialization/version migration and consensus/fork choice; resolve all Critical/High findings. Owner approval of policy is not a substitute for that review.

## Existing CI evidence on the reviewed base

For exact commit `863f43fbd8bb3cf1c99a55d4bc16ce9bdf58f20c`, the Rust validation workflow run `39714555490` completed successfully. Its `Format, check, and test` job passed formatting, all-target check/tests and the independent monetary Genesis snapshot and issuance oracle steps. Its Windows PMT4/TXN4 loopback job passed signed TXN4 admission/replay and PFM4 paged archive reorg/stale-cursor checks. Pages run `39714554872` also completed build/deploy/status reporting successfully. These results establish CI for that commit, not production protocol completeness.

## Safe next implementation sequence

- First, approve/version the monetary profile and Genesis/migration decisions as immutable test vectors; do not infer policy by combining PMT3 and PMT4.
- Then add a monetary-aware durable import/replay path for the selected version and call it from the selected node runtime. Make publication of in-memory state conditional on the durable commit and same-profile validation.
- Add end-to-end cap/fork/reorg/restart/snapshot properties on that actual path, then differential tests against a separate reference implementation.
- Keep value-bearing listeners and public network launch disabled until these steps and external review pass.

Under the owner spend cap of USD 0, external audit or any independent operational service not actually available at no cost remains an unfunded prerequisite; it must not be marked satisfied by local tests. No production key, paid resource, live transfer, public listener or Mainnet action was created by this checkpoint.
