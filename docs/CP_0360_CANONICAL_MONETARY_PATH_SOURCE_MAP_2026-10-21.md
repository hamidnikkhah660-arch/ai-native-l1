# CP-0360 — Canonical Monetary Path Source Map

Date: 2026-10-21
Reviewed public source commit: `941568baf5a0eb6fdfe1978e9d83f3ad0d6a9bdb` (main after PR #15 and PR #16).
Scope: source-level map for Gate 2; **no consensus or runtime code is changed by this document**.

## Executive result

**Gate 2 remains OPEN.** The repository has working monetary-state, MBK3/PMT3 and MBK4/PMT4 research/runtime candidates, but these are not yet one frozen production protocol integrated end-to-end through a public mainnet node. The source map below distinguishes the APIs that exist from the canonical path that Gate 2 requires.

## Actual entry points and data paths

| Layer | File/API | What the source establishes | Boundary / missing production evidence |
|---|---|---|---|
| Default crate entry point | `src/native/pow_bench/src/main.rs` | Synthetic memory-bound benchmark that explicitly prints `NOT cryptographic PoW`. | It is not a native-chain node or a production block producer. |
| Library registry | `src/native/pow_bench/src/lib.rs` | Exposes the legacy ledger, chain admission/import, monetary policy, MBK3/PMT3 and V4 hybrid candidate modules. Several module comments explicitly say candidate-only or not consensus-wired. | Module presence and unit tests do not select a canonical protocol or make a candidate production-active. |
| State / issuance | `src/native/pow_bench/src/state_machine.rs` — `MonetaryLedgerState` | Has directed Genesis validation, height-derived miner reward, state-root calculation, MBK3 block application, MBK4 hybrid block application, and a versioned monetary snapshot codec. | This is candidate state logic. Gate 2 still requires a frozen profile and verified producer/import/reorg/store/replay/snapshot path using the same rules. |
| Admission boundary | `src/native/pow_bench/src/chain_admission.rs` — `admit_live_monetary`, `replay_monetary`, `admit_live_v4_hybrid_monetary`, `replay_v4_hybrid_monetary` | The legacy path and both monetary candidate paths have explicit admission/replay APIs, including time-source and timestamp checks for live admission. | This module describes itself as research/testnet integration, not a complete node-consensus layer. API existence is not proof that every live runtime uses the same path. |
| Generic import service | `src/native/pow_bench/src/chain_import.rs` — `ChainImportService` | Imports decoded legacy `Block`/BLK2 into `LedgerState`, stages state, persists via `snapshot_store`, then publishes the updated state. | It stores `LedgerState`, not `MonetaryLedgerState`; this is not an end-to-end monetary import service for MBK3/MBK4. |
| MBK3 wire | `src/native/pow_bench/src/private_testnet_monetary_wire.rs` | Defines version-3 monetary network-block encoding/decoding for the candidate PMT3 path. | Candidate private-testnet wire; not a frozen public/mainnet wire contract. |
| PMT3 store / fork choice | `src/native/pow_bench/src/private_testnet_monetary_fork_store.rs`, `private_testnet_monetary_fork_choice.rs` | Provides candidate PFM3 durable archive/fork-choice/replay machinery for MBK3 monetary blocks. | Not independently qualified as canonical production storage/reorg. The local peer-smoke mode rejects transactions and uses local easy-PoW settings. |
| MBK4 wire / TXN4 identity | `state_machine.rs`, `v4_account_identity_candidate.rs`, `private_testnet_monetary_wire.rs` | Implements candidate version-4 hybrid monetary blocks and explicit Ed25519 + ML-DSA-65 transaction authorization checks. | V4 is an opt-in candidate path; signature verification candidates and selected tests are not a full production key-migration review or protocol audit. |
| PFM4 store / fork choice | `src/native/pow_bench/src/private_testnet_v4_hybrid_fork_store_candidate.rs`, `private_testnet_v4_hybrid_fork_choice_candidate.rs` | Provides a candidate PFM4 durable branch store and fork/replay path. | It is not yet a frozen canonical mainnet runtime or an independently administered anti-rollback domain. |
| Local PMT3 runtime | `src/native/pow_bench/src/bin/private_testnet_node.rs` — `--monetary-candidate-local-smoke` / peer-smoke path | Runtime code builds and exercises PMT3/PFM3; its ready log reports `transactions=RejectAll`, `LOCAL_EASY_POW_8MIB` and `public_launch_approved=false`. | Local smoke only; no normal value-transfer path and no production PoW profile. |
| Local PMT4 runtime | `private_testnet_node.rs` — `--monetary-v4-hybrid-local-smoke` / peer-smoke path | Exercises PFM4/PMT4 and TXN4; its ready log explicitly reports `profile_scope=loopback_diagnostic`, `LOCAL_EASY_POW_8MIB`, `value_bearing=true` and `public_launch_approved=false`. | Diagnostic candidate only. It does not authorize public value-bearing exposure or prove the full public-network security boundary. |
| Zero-value Devnet | `src/native/pow_bench/src/bin/devnet_node.rs` and `devnet_profile_candidate.rs` | The entry point calls `main_devnet`; the profile candidate validates a zero-balance Genesis manifest and intentionally does not open sockets/start a node itself. | The wrapper currently shares the PTB2/PFS2 loop and is documented as loopback-only until authenticated peer transport is wired before parsing/import. It is not the monetary PFM4 mainnet path. |

## Candidate choice implications

- PMT3/PFM3 is not suitable as the intended public transaction path as currently wired: the local peer-smoke reports `transactions=RejectAll`.
- PMT4/PFM4 is the more complete *research candidate* for hybrid signed monetary transactions, but its local runtime explicitly uses a diagnostic/loopback profile and easy PoW. It must not be relabeled public Mainnet or enabled for external value-bearing use based on the existing smoke tests.
- The standard zero-value Devnet runtime is a separate PTB2/PFS2 profile. Its existence does not prove monetary issuance or public multi-operator readiness.
- The project must freeze one profile/version and one activation/migration rule; it must not combine PMT3/PFM3 and PMT4/PFM4 behavior by assumption.

## Gate 2 exit items still missing

1. Versioned production protocol decision: network ID, Genesis bytes/hash, block/transaction/snapshot formats, monetary schedule, fees, beneficiary key binding and activation/migration semantics.
2. One canonical node/runtime path that derives rewards internally and applies the 10B lifetime cap across producer, validator/import, fork choice/reorg, durable persistence, restart/replay, snapshots and state roots.
3. Real public-key-derived founder/treasury/public-goods identities established through a separately reviewed key ceremony; the local `local_monetary_account_id` helper is explicitly based on non-key role labels and must not become a production beneficiary scheme.
4. Independent byte-level Genesis/block/transaction/snapshot vectors plus a separately implemented oracle and differential agreement across independently built nodes.
5. Adversarial/cap-boundary tests on that integrated path, reproducible clean-checkout build/test evidence, and independent review of monetary transitions and migration semantics.

Gate 8 remains OPEN separately: the local model and store tests do not replace an independently administered monotonic anchor/CAS provider, multi-host restore/power-loss qualification, and independent security sign-off. Gate 12 remains OPEN because the standalone EVM/revm lab is not the canonical native-node VM. Public operations, wallet/RPC/explorer qualification, legal/offer review, real counterparties, and actual paired-asset liquidity are separate gates beyond code tests.

## Current evidence after PR #15 and PR #16

- PR #16 merged: `84d674b3ddfc0f773d94e98524b9bba35f310650`. It added Linux `cargo fmt`, `cargo check`, and `cargo test --all-targets --locked` CI, plus a path-portability fix for the CP-0237 test harness and serialized test execution after a real file-lock collision appeared under parallel test execution.
- PR #15 merged: `941568baf5a0eb6fdfe1978e9d83f3ad0d6a9bdb`. It adds Genesis allocation negative tests and exact-budget split coverage.
- PR-specific Linux CI passed for both changes. A fresh all-target run on the merge commit was in progress at the time of this source map; check the Actions run before treating post-merge CI as fully verified.
- These changes improve reproducibility and allocation guardrails; they do **not** close Gate 2.

## Stop rule

Do not expose a value-bearing listener, create production keys, send a transaction, deploy a native Mainnet, claim liquidity/listings/revenue, or mark Gate 2/8 PASS until the corresponding acceptance evidence exists. Under the USD 0.00 owner-spend directive, unavailable independent operators/auditors/providers are unfunded external prerequisites, not assumed passes.
