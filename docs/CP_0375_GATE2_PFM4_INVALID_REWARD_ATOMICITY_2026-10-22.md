# CP-0375 — PFM4 Invalid Miner-Reward Atomicity Regression

Date: 2026-10-22
Project: QuantumZXB / AI-Native L1
Base commit: `b8cf1b7a2b249f3783b35a7cf796ee3c23a4a536`
Branch: `test/gate2-pfm4-invalid-reward-atomicity`
Scope: store-level negative test only; no monetary rule, consensus parameter, or runtime mode changes.

## Motivation

The MBK4 monetary state candidate already derives the permitted miner subsidy from the next block height and cumulative issued amount, rather than trusting the block's peer-supplied `claimed_subsidy_atoms`. Existing state-machine tests cover a wrong reward. This adds an integration assertion at the durable PFM4 store boundary so the invalid monetary claim is proved not to publish a branch or manifest and not to mutate the selected tip.

## Regression test

Added `pfm4_rejects_invalid_miner_reward_without_publishing_manifest_or_branch` in `src/native/pow_bench/src/private_testnet_v4_hybrid_fork_store_candidate.rs`.

- Start from the exact valid Genesis-parent MBK4 envelope produced by the existing helper.
- Preserve its header, header/body state-root binding, ancestry, and a digest that meets the declared PoW target.
- Mutate only `claimed_subsidy_atoms` by adding one atomic unit and canonically encode the MBK4 envelope again.
- Submit through `PrivateTestnetV4HybridForkStore::submit`; admission rejects the invalid reward.
- Verify canonical height remains 0, canonical tip remains Genesis, archive length remains 0, manifest commitment is unchanged, and no branch file exists.
- Reopen the store and assert the same state and anchor again.

The test isolates the monetary reward check from the PoW failure tested by CP-0374. It proves only candidate-path behavior; it does not ratify the production subsidy schedule or close Gate 2.

## Local validation on the authorized Windows host

- Focused `pfm4_rejects_invalid_miner_reward_without_publishing_manifest_or_branch` — PASS (1 passed, 0 failed).
- `cargo fmt --all -- --check` — PASS.
- `cargo check --all-targets --locked --offline` — PASS (exit code 0; pre-existing unused/dead-code warnings in diagnostic targets remain).
- `cargo test --all-targets --locked --offline -- --test-threads=1` — PASS (751 library tests passed, 0 failed/ignored; both `devnet_node` and `private_testnet_node` had 36/36 tests pass; every remaining binary, example and integration-vector target passed; command completed with exit code 0 in 785.96s).
- `python simulations/rebuild_release_checksums.py` — PASS (306 Git-index blob entries, manifest self-hash excluded).
- `python simulations/public_docs_refresh_checker.py` — PASS (14 HTML IDs, 23 README relative links, direct-contact check, candidate issuance arithmetic and all 306 blob checksums).
- The focused invalid-reward regression also passed independently (1/1).


## Gate boundary

This is a defensive test for the existing loopback-only PMT4/PFM4 candidate. No public listener, production key, external CAS provider, issuance change, public value transfer, market pair, or owner-funded spend is created. Gate 2 and Gate 8 remain **OPEN**.
