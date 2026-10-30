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
node --test tools/qzxb-market/candles.test.mjs tools/qzxb-market/indexer.test.mjs tools/qzxb-market/native-candles.test.mjs tools/qzxb-market/native-indexer.test.mjs
```

## Current activation boundary

**The QZB4 v3 AMM transition and candidate-node ingress are now wired together, but this is still not a public DEX or Mainnet activation.** Legacy QZB4 v2 blocks remain supported. QZB4 v3 encodes bounded signed `QAX1` operations; the candidate transition validates and applies them, commits AMM state into the transition state root, and persists it via profile-bound `QZP4` v2 snapshots. The `qzbe_v04_peer_node` candidate also exposes bounded `QZAS/1` ingress (`--amm-listen`), previews operations against the canonical candidate state before admission, and selects admitted operations for block production. The listener defaults to loopback; any non-loopback AMM ingress is restricted to the explicitly enabled zero-value testnet profile. The AMM mempool is transient and is not a durable transaction pool.

The missing market asset route is still fundamental: the runtime has no authenticated asset issuance/deposit/redemption or bridge integration for a second asset such as USDT. The `credit_genesis_balance` helper is test/genesis construction only, not a mint route. A token ID or label called `USDT` is not proof of backing; real use requires a verifiable bridged/issuer-backed representation, supply accounting, redemption path and two-sided live liquidity. No real USDT market or real-value swap should be claimed until this exists and is independently checked.

The candidate fork-choice now retains each executed swap receipt alongside its AMM-operation index in the validated QZBE branch. The read-only loopback RPC `GET /v1/amm/swaps` exposes bounded pages from the selected canonical ancestry, including block height/hash/time, operation-indexed receipts, confirmation count, retained-base height and reorg counter. Receipts are deterministically reconstructed from retained block envelopes on archive replay; they are not a consensus-level durable event log independent of that archive. The RPC defaults to six PoW confirmations and states explicitly that this is probabilistic confirmation depth, not deterministic protocol finality. The new `tools/qzxb-market/native-indexer.mjs` pages this endpoint and aborts if tip/reorg metadata changes or history is incomplete; `native-candles.mjs` computes QZXB-native hourly/daily/weekly/monthly candles using 32-byte asset/pair IDs and integer arithmetic. These modules are tested against fixtures only; no real QZXB/USDT swap has occurred, so they do not establish a live market or live price series. The candidate RPC remains loopback-only, and wallet signing/submit UX, public RPC methods, cross-platform end-to-end tests, external checkpoint anti-rollback, and independent security review remain before public activation. The QZBE candidate continues to report `mainnet=false` and `public_launch_approved=false`.
