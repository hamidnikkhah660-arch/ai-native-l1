# QZXB market-data candle engine (candidate)

This repository module computes hourly (`1h`), daily (`1d`), Monday-UTC weekly (`1w`) and calendar-month (`1M`) OHLC candles from confirmed AMM swap logs. Price is quote-token units per base-token unit, normalized for each token's decimals with integer arithmetic; volume fields remain unrounded atomic-unit strings. It emits no fabricated empty candles.

## Components

- `candles.mjs` is the deterministic candle builder. It filters noncanonical/unconfirmed swap events, handles reversed token order, deduplicates overlapping log pages, and rejects conflicting event identities.
- `indexer.mjs` is a JSON-RPC adapter for Uniswap-V2-compatible pools. It verifies the expected chain ID, deployed pair and factory bytecode, exact token0/token1 addresses, the factory's `getPair(token0,token1)` result, confirmation depth and each swap's canonical block hash. It queries bounded log ranges. RPC access must use a trusted HTTPS endpoint; for high-value decisions, reconcile against an independently operated RPC source as well.

The configured `quoteTokenAddress` must be the official stablecoin contract address on that exact chain. A ticker string such as `USDT` is not token identity. The configured `factoryAddress` must be the official factory for the chosen DEX. Contract-address configuration and the RPC trust boundary must be reviewed before a public production feed is exposed.

## Safety boundary

This package is data ingestion, not a token bridge, AMM deployment, liquidity pool, mainnet node, market, listing or live feed endpoint. The caller must select the canonical pair and quote-token contract, supply an appropriate block range, and rebuild data from canonical chain events after a reorganisation. No price is emitted when there are no confirmed swaps.

**Current status (2026-10-27):** this repository has no established native QZXB Mainnet or QZXB/USDT pool, so no live QZXB/USDT candles exist yet. The existing Sepolia QX ERC-20 is a separate test asset and must not be represented as the native QZXB coin. Do not attach real funds or market claims to this candidate before the native asset / wrapped-asset policy, pair, liquidity and data-source identities are approved and verified.

## Tests

Run with Node.js:

```powershell
node --test tools/qzxb-market/candles.test.mjs tools/qzxb-market/indexer.test.mjs
```
