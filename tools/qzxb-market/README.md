# QZXB market-data candle engine (candidate)

This repository module computes hourly (`1h`), daily (`1d`), Monday-UTC weekly (`1w`) and calendar-month (`1M`) OHLC candles from confirmed AMM swap logs. Price is quote-token units per base-token unit, normalized for token decimals with integer arithmetic; volume fields remain atomic-unit strings. Empty candles are never fabricated.

## Components

- `candles.mjs` is the deterministic EVM candle builder. It filters noncanonical/unconfirmed swap events, handles reversed token order, deduplicates overlapping log pages, and rejects conflicting event identities.
- `native-candles.mjs` builds hourly, daily, Monday-UTC weekly, and calendar-month candles from the candidate native node's `/v1/amm/swaps` response. It consumes 32-byte native pair/asset IDs and operation-indexed swap receipts, rejects conflicting canonical hashes at the same height, and uses integer arithmetic for token-decimal-aware price calculation.
- `native-indexer.mjs` fetches bounded pages from the node's loopback-only candidate RPC, checks that tip/reorg metadata stays unchanged across the read, and fails closed on incomplete history rather than serving a partial candle series as complete.
- `indexer.mjs` is a JSON-RPC adapter for Uniswap-V2-compatible pools. It requires two HTTP(S) RPC endpoints with different origins, verifies their chain IDs, deployed pair/factory bytecode, exact token0/token1 addresses, factory `getPair` mapping, token decimals, bounded log scans and confirmation depth. Both endpoints must return the same swap logs and canonical block hashes/timestamps before a candle is accepted.

The endpoints should be operated by independent providers; different URL origins alone do not prove operational independence. For high-value use, reconcile with a third source and monitor provider freshness. The configured quote-token address must be the official stablecoin contract on that exact chain. A symbol such as `USDT` is not token identity. The configured factory must be the reviewed DEX factory for that chain.

## Safety boundary

This package is data ingestion, not a token bridge, AMM deployment, liquidity pool, mainnet node, market, listing or public API. The caller must select the canonical pair and quote-token contract, provide a safe block range, and rebuild indexed data from canonical events after reorganisation. No price is emitted without confirmed swaps.

**Current status (2026-10-27):** the repository does not establish a native QZXB Mainnet or QZXB/USDT pool, so no live QZXB/USDT candles exist yet. The existing Sepolia QX ERC-20 is a separate test asset and must not be presented as native QZXB. Do not attach real funds or market claims to this candidate before the native asset/wrapped-asset policy, pair, liquidity and data-source identities are approved and verified.

## Candidate native wallet client

The Rust CLI `cargo run --manifest-path src/native/pow_bench/Cargo.toml --bin qzxb_amm_client -- ...` can sign QAX1 AMM operations locally and submit them over QZAS/1 to the candidate node. Use a **dedicated testnet-only** Ed25519 seed file with exactly 64 hex characters; keep it outside the repository and never send the seed to an RPC node. Start with `--show-account`, then run an operation without `--submit` to inspect the signed payload before explicitly submitting. The default endpoint is loopback `127.0.0.1:49337`; remote testnet submission requires `--allow-remote-testnet` explicitly. A mempool ACK is not block inclusion or finality. This client does not mint or back USDT and is not approved for real funds or Mainnet.

## Tests

Run with Node.js:

```powershell
node --test tools/qzxb-market/candles.test.mjs tools/qzxb-market/indexer.test.mjs tools/qzxb-market/native-candles.test.mjs tools/qzxb-market/native-indexer.test.mjs
```
