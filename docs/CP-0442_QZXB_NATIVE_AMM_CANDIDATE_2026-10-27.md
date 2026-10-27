# CP-0442 — QZXB Native AMM Candidate (2026-10-27)

## Purpose

This change adds a deterministic Rust candidate for a permissionless constant-product AMM so the QZXB project has a testable native-market accounting core rather than only a chart/indexer. The module is exported as `qzxb_amm_candidate`.

## Implemented in this candidate

- Canonically ordered 32-byte asset IDs and a deterministic SHA-256 pair ID.
- Permissionless pair creation for two registered assets.
- Bounded in-memory asset balances, pool custody accounts, and LP-share accounting.
- Initial/proportional liquidity add and proportional liquidity removal.
- Exact-input swaps with a 30-basis-point fee, checked integer arithmetic, a caller-supplied minimum output, and the constant-product non-decrease check.
- Versioned canonical `QAO1` operation wire format and `QAX1` signed envelope covering asset registration, pair creation, transfers, liquidity add/remove and swaps.
- Domain-separated signing digest bound to network ID, sender, nonce, expiry and operation payload. QZB4 v3 block validation invokes the operation path, uses the next nonce from the canonical native ledger, validates expiry/signature, and atomically commits the resulting candidate state.
- Clone-then-commit execution so failed operations preserve the original state.
- Deterministic AMM state root over network ID, configured resource limits, asset IDs, holdings, AMM operation nonces, reserves, LP shares and fee policy; when AMM is activated, this root is included in the QZB4 transition state root.
- Bounded canonical `QAMS` v2 snapshot codec binds network ID and AMM nonces as well as balances/reserves/LP shares. Profile-bound `QZP4` snapshot v2 nests it for restart/replay; historical v1 snapshots remain readable only when the old empty-AMM state root matches.
- Focused tests cover pair canonicalization, duplicate/unknown assets, liquidity add/remove, successful swaps, fees/invariants, optimal-ratio deposits, slippage/overflow rollback, snapshot corruption, signed wire format, network/expiry/replay/signature rejection, QZB4 v3 producer/importer agreement, native-ledger custody reconciliation, swap receipts, and restart restoration.

## Verification

Targeted Rust tests and `cargo check --all-targets` are used before CI:

```powershell
cargo fmt --manifest-path src/native/pow_bench/Cargo.toml --all -- --check
cargo test --manifest-path src/native/pow_bench/Cargo.toml qzxb_amm_candidate --lib
cargo test --manifest-path src/native/pow_bench/Cargo.toml qzbe_amm_ingress_candidate --lib
cargo test --manifest-path src/native/pow_bench/Cargo.toml monetary_transition_v04_candidate --lib
cargo test --manifest-path src/native/pow_bench/Cargo.toml monetary_pow_v04_candidate --lib
cargo test --manifest-path src/native/pow_bench/Cargo.toml --bin qzbe_v04_peer_node
cargo check --manifest-path src/native/pow_bench/Cargo.toml --all-targets
```

## Current activation boundary

**The QZB4 v3 AMM transition and candidate-node ingress are now wired together, but this is still not a public DEX or Mainnet activation.** Legacy QZB4 v2 blocks remain supported. QZB4 v3 encodes bounded signed `QAX1` operations; the candidate transition validates and applies them, commits AMM state into the transition state root, and persists it via profile-bound `QZP4` v2 snapshots. The `qzbe_v04_peer_node` candidate also exposes bounded `QZAS/1` ingress (`--amm-listen`), previews operations against the canonical candidate state before admission, and selects admitted operations for block production. The listener defaults to loopback; any non-loopback AMM ingress is restricted to the explicitly enabled zero-value testnet profile. The AMM mempool is transient and is not a durable transaction pool.

The missing market asset route is still fundamental: the runtime has no authenticated asset issuance/deposit/redemption or bridge integration for a second asset such as USDT. The `credit_genesis_balance` helper is test/genesis construction only, not a mint route. A token ID or label called `USDT` is not proof of backing; real use requires a verifiable bridged/issuer-backed representation, supply accounting, redemption path and two-sided live liquidity. No real USDT market or real-value swap should be claimed until this exists and is independently checked.

The candidate transition returns canonical swap receipts, but those receipts are not yet persisted/exposed as finalized native swap events to the candle/indexer pipeline. The existing candle engine remains an indexer rather than an AMM and does not yet produce real QZXB-native hourly/daily/weekly/monthly candles. Native receipt indexing, reorg/finality handling, public wallet/RPC methods, cross-platform end-to-end tests, external checkpoint anti-rollback, and independent security review remain before public activation. The QZBE candidate also remains explicitly marked `mainnet=false` and `public_launch_approved=false`.
