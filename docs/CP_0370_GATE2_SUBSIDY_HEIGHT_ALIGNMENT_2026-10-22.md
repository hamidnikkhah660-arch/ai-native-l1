# CP-0370 — Gate 2 Subsidy Height Alignment

Date: 2026-10-22
Project: QuantumZXB / AI-Native L1
Base commit: `298eee9682142fcd98d8198041535f741496ec69`
Branch: `fix/gate2-subsidy-height-1-based`
Scope: candidate schedule API consistency; no network activation.

## Finding

`MonetaryLedgerState::expected_miner_reward` treated native block heights as 1-based: block height 1 is the first block after Genesis and uses the emission schedule's index 0 (`block_height - 1`). Before this checkpoint, `consensus::expected_block_subsidy` passed the native block height directly to `IssuanceParameters::reward_for_block`. That disagreed at the halving boundary: height H was assigned the next era's reward by the consensus candidate function even though the monetary-state candidate assigns the full era to heights 1 through H and the first halved reward to H+1.

## Change

- `expected_block_subsidy` now accepts positive, 1-based native heights and converts once to the schedule's zero-based index.
- Height zero fails closed with `ConsensusError::InvalidBlockHeight`.
- Replaced the old subsidy unit test with explicit checks for height 1, the final full-subsidy height H, the first halved height H+1, zero reward at the total supply cap, and rejection of height zero.
- The test uses the existing candidate Genesis allocations and the same subsidy/halving constants used by `MonetaryLedgerState`; it does not declare those provisional constants to be final Mainnet policy.

## Validation run locally on Windows

- `cargo fmt --all` — completed.
- `cargo fmt --all -- --check` — PASS.
- `cargo test -p ai_native_l1_pow_bench --locked --offline issuance_is_wired_to_one_based_native_heights_and_exact_halving_boundaries` — PASS (1 passed, 0 failed).
- `cargo check --all-targets --locked --offline` — PASS (exit code 0; existing unused/dead-code warnings remain in diagnostic targets).
- `cargo test --lib --locked --offline` — PASS, 749 passed / 0 failed / 0 ignored; test runtime 154.72s.

## Gate boundary

This aligns a candidate PoW subsidy helper with the monetary-state candidate. It does not wire the function into a production producer/importer or canonical public node. The default executable remains a benchmark, `ChainImportService` persists legacy `LedgerState`, PMT3/PFM3 and PMT4/PFM4 remain separate candidates, and there is still no frozen production network/Genesis/fee/reward/migration profile, independent multi-client agreement, or independent protocol/economic sign-off.

Gate 2 remains **OPEN**. Do not enable production issuance, public value transfers, native token marketing, Mainnet, or liquidity based on this change. No production keys, paid services, public listeners, transactions or owner-funded spending were created; owner budget remains USD 0.
