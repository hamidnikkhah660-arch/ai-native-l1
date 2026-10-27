# QZXB market-data candle engine (candidate)

This module computes hourly (`1h`), daily (`1d`), Monday-UTC weekly (`1w`) and calendar-month (`1M`) OHLC candles from confirmed swap logs. Prices are quote-token units per base-token unit and are derived from the actual token amounts in each swap; token decimals are accounted for using integer arithmetic. Volume fields are unrounded atomic-unit strings. Empty candles are not invented.

## Safety boundary

The caller must obtain swap logs from an actual deployed pair, decode them, and verify each log against the current canonical block hash and configured pair/asset identities. Only events marked `canonical: true` with the required confirmation depth are included. A chain adapter must drop/rebuild events from orphaned blocks after a reorganisation. The module is an aggregator, not an RPC node, token bridge, liquidity pool, market, or listing. It does not create prices in the absence of trades.

**Current status (2026-10-27):** this repository has no established native QZXB Mainnet or QZXB/USDT pool, so this code produces no live QZXB/USDT candles yet. The existing Sepolia QX ERC-20 is a separate test asset and must not be represented as the native QZXB coin. Do not connect real funds or market claims to this candidate module before a real pair and its canonical data source are qualified.

## Tests

Run with Node.js:

```powershell
node --test tools/qzxb-market/candles.test.mjs
```
