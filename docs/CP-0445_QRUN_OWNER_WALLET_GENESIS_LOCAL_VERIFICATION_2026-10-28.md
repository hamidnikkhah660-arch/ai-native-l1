# CP-0445 - QRun owner wallet Genesis verification (local-only)

Date: 2026-10-28

Status: local integration evidence only. No production Genesis activation or Mainnet issuance is claimed.

## Observed

- The existing Windows CurrentUser DPAPI wallet was opened by the native wallet CLI to derive and validate its public account ID and Ed25519 public key. No seed or private key was output.
- A fresh QRun v0.5 node was started with that public wallet identity, a fresh random network ID, a fresh local store, and loopback-only RPC / transaction / block listeners.
- The local runtime reported mainnet=false, network_class=local_loopback_pow_testnet_not_public, height=0, and security_note=loopback_only_max_target_smoke_profile_not_public_consensus.
- The native wallet queried its own balance from the node RPC. The returned owner balance was 1,000,000,000,000,000,000 atoms = 10,000,000,000.00000000 QZXB; total supply equalled the same amount. The node independently reported the same state root and Genesis commitment.
- The node's RPC, transaction-ingress and block listeners are bound only to 127.0.0.1. Its PoW target is intentionally trivial and is not a public-consensus configuration.

## Allocation policy boundary

The current QRun v0.5 direction in CP-0437 assigns the entire 10B supply to the owner at Genesis, sets all later issuance and miner subsidy to zero, and creates no pre-issued category buckets. This supersedes the older 1B Founder / separate allocation-envelope model for the future QRun profile. It cannot simultaneously be presented as the older split allocation model: an alternative split requires a different reviewed Genesis decision and commitment before activation.

## Still not established

This test does not establish public consensus, peer discovery, independent operators, secure production difficulty, production fees/miner economics, automatic checkpoint rollover, external anti-rollback operation, a public explorer or public RPC, independent security review, EVM integration, or a real market.

No USD, USDT or other quote asset is present; no buy/sell order, swap, market price, liquidity reserve or trade occurred. The local candidate balance is not a redeemable or publicly transferable Mainnet asset. CoinMarketCap, CoinGecko, TradingView and DEX market data must not be populated from this Genesis balance or synthetic candles.
