# CP-0442 — QZXB Native AMM Candidate (2026-10-27)

## Purpose

This change adds a deterministic Rust candidate for a permissionless constant-product AMM so the QZXB project has a testable native-market accounting core rather than only a chart/indexer. The module is exported as `qzxb_amm_candidate`.

## Implemented in this candidate

- Canonically ordered 32-byte asset IDs and a deterministic SHA-256 pair ID.
- Permissionless pair creation for two registered assets.
- Bounded in-memory asset balances, pool custody accounts, and LP-share accounting.
- Initial/proportional liquidity add and proportional liquidity removal.
- Exact-input swaps with a 30-basis-point fee, checked integer arithmetic, a caller-supplied minimum output, and the constant-product non-decrease check.
- Clone-then-commit execution so failed operations preserve the original state.
- Deterministic candidate state root over asset IDs, holdings, reserves, LP shares, and the fee-policy constants.
- Bounded canonical `QAMS` snapshot codec with version, limits, checksummed body, canonical re-encoding check, and invariant verification after decode.
- Unit tests for pair canonicalization, duplicate/unknown assets, liquidity add/remove, successful swap, fee/invariant behavior, optimal-ratio deposits, slippage rollback, arithmetic-overflow rollback, snapshot round-trip, and corrupt/trailing snapshot rejection.

## Verification

The targeted Rust test command is:

```powershell
cargo fmt --manifest-path src/native/pow_bench/Cargo.toml --all -- --check
cargo test --manifest-path src/native/pow_bench/Cargo.toml qzxb_amm_candidate --lib
```

## Critical activation boundary

**This is not a public DEX or Mainnet activation.** The candidate module does not yet serialize AMM calls into the canonical TXN4/QZB4 transaction format, execute them in the node's block transition, include its state root inside the canonical consensus state root, wire the `QAMS` codec into the node's durable/reorg-safe snapshots, or emit finalized native swap events to the candle indexer. The codec is a candidate API and is not called by the live runtime. Its `credit_genesis_balance` helper is for test/genesis construction only and is not an authenticated mint route.

A production activation must integrate all of those boundaries atomically, preserve legacy-wire compatibility or deliberately version the protocol, cover rollback/reorg/replay and resource exhaustion, and pass independent security review. In particular, a symbol named USDT is not proof of USDT backing: the quote asset must have a verifiable representation and supply/redemption model on the selected network.

The existing confirmed-swap candle engine is an indexer, not an AMM; it only creates OHLCV from canonical, sufficiently confirmed swap logs. It must be given finalized events from the native AMM before real hourly, daily, weekly, and monthly candles can appear.
