# Liquidity, Market-Data Platforms and Public-Launch Readiness — v0.1

Date: 2026-10-27
Status: Engineering/commercial readiness assessment reconciled to the CP-0422 v0.4 allocation decision. No native market, liquidity pool, production listing or listing approval is claimed.

## Executive view

QuantumZXB already has a public project site, curated source repository, technical white paper, roadmap, founder contact route, and published research on candidate mining/halving and performance. The remaining gap is not simply "get the coin listed". The native monetary profile and public network must become reproducible, independently operated and observable before platforms can reliably track the native asset.

**The proposed native QZXB coin and the QX ERC-20 experiment on Ethereum Sepolia are different assets.** Never submit the Sepolia QX contract as the native QZXB coin. No native Mainnet, native explorer, live native market price, trading pair, liquidity, confirmed sponsor, independent security audit, or verified project revenue is established in the current public evidence.

The current owner-directed v0.4 policy uses a 10,000,000,000-QZXB design cap with eight exclusive allocation ceilings: 3B mining/network security (30%) and seven 1B categories (10% each)—community airdrop, exchange/market-integration/liquidity partnerships, marketing/promotional partners, developers/security contributors, financial/strategic supporters, protocol burn reserve, and founder. The founder ceiling is 1B QZXB (10%), as recorded in [CP-0422](CP-0422_CANONICAL_TOKENOMICS_DECISION_2026-10-26.md); the former 4B/3B/3B split is historical v0.3 only. These are ceilings, not minted balances, current circulating supply, sponsor awards or liquidity. The v0.4 Genesis candidate currently credits only the 1B owner allocation; mining subsidy and all other category releases require deterministic canonical runtime rules and independent conformance evidence. Gate 2 remains OPEN. Any sponsor/contributor award must stay within an approved v0.4 category cap and is not cash, issued market liquidity, or a guaranteed payment.

## 1. Platform requirements and present gap

Platform rules change; the linked official documentation was checked on 21 October 2026. Each platform makes its own integration and listing decisions.

| Platform | Relevant published prerequisite | Present gap / action |
|---|---|---|
| CoinMarketCap | Tracked-asset criteria include a functional website and block explorer, public active trading with material volume on at least one CMC-tracked exchange, and a reachable project representative. Meeting the guidance does not guarantee acceptance. | Public site and contact exist; native Mainnet/explorer and a real native market are not established. Do not submit the Sepolia QX contract as QZXB. |
| CoinGecko | The official listing guide requires active trading on an exchange tracked by CoinGecko. Its methodology also identifies a project-owned, functional site, a working explorer, an integrated exchange, and clear circulating-supply information. | Native coin is not established as an actively traded production asset; native explorer and supply data are not available. Reapply only after those prerequisites are real. |
| DEX Screener | Tokens on supported networks are automatically indexed after a liquidity pool exists and at least one transaction has occurred. Its data are derived from chains it tracks. | No native QZXB pool/market has been established; support for a new native chain is a separate dependency. A testnet token or a fake pool is not a substitute. |
| TradingView | Unsupported symbols cannot simply be added manually. A real market/data source and an exchange/provider integration path are needed. | No authentic native exchange feed, market pair or reliable price/volume stream exists to chart. Build a real integration path before requesting symbol support. |
| Centralised exchanges | Each exchange has its own due diligence, chain/wallet integration, deposit/withdrawal, security, liquidity and operational requirements. | No exchange listing or exchange integration is established. Any future approach should include a frozen network profile, secure wallet/RPC, explorer, incident contact, supply methodology and independent technical evidence. |
| Wallets / explorers / data APIs | Need a stable network identity, deterministic RPC responses, account/transaction formats, chain data and clear asset metadata. | A production native wallet, public RPC, explorer/indexer and publicly operated native devnet are still roadmap work. |

### Official platform references

- CoinMarketCap, *Listings Criteria* (updated 1 September 2026): https://support.coinmarketcap.com/hc/en-us/articles/360043659351-Listings-Criteria
- CoinGecko, *How to List a New Cryptocurrency* (updated 2 October 2026): https://support.coingecko.com/articles/9489827481-how-to-list-a-new-cryptocurrency-on-coingecko
- CoinGecko, *Methodology*: https://www.coingecko.com/en/methodology
- DEX Screener, *Token Listing*: https://docs.dexscreener.com/token-listing
- DEX Screener, *FAQ and data sources*: https://docs.dexscreener.com/
- TradingView, *How to add an asset that is not supported*: https://www.tradingview.com/support/solutions/43000756141-how-to-add-an-asset-that-is-not-supported-on-the-platform/
- TradingView, *Broker/exchange connection guidance*: https://www.tradingview.com/support/solutions/43000479602-the-broker-i-want-to-trade-through-is-not-supported-can-you-add-it/

## 2. Critical engineering gates before a native market

### Gate 2 — canonical Genesis, issuance, and supply

This is the highest-priority integration gate. Freeze the network ID, Genesis hash, transaction/block/snapshot versions, allocation accounting, fee rules, subsidy schedule and halving behaviour. Apply the 10B lifetime cap in block production, validation/import, fork-choice/reorg, persistence, restart/replay, snapshots and state roots. Independently implemented clients must agree on reward boundaries, balances, issued supply and state roots. Candidate modules and arithmetic tests alone do not close this gate.

### Gate 8 — independent rollback protection and recovery

A local store and local trust marker can roll back together. Select and integrate a genuinely independent monotonic trust provider outside the node's restore boundary, then qualify concurrency, stale restores, ambiguous commits, key rotation, VM reset and storage failure across independent hosts. Existing process-termination tests are useful but do not prove sudden physical power-loss durability.

### Gate 12 — native EVM and application execution

The revm lab is separate from the canonical native node. Freeze EVM fork/gas rules, chain ID, account and signature mapping, code/storage roots, receipts/logs, rollback semantics and RPC. Cross-check a real Solidity application on independently operated native nodes and prove that receipts/state roots agree after restart and reorganisation.

### Public devnet, operations and trust

Provide multiple independently operated nodes; native wallet; read/write RPC appropriate to testnet safety; explorer/indexer; peer and operator identity setup; monitoring; backup/recovery and incident procedures. Publish actual network observations with commit IDs, configuration, node count, hardware and raw logs.

### Release qualification and identity

Complete reproducible-build/provenance/SBOM work and obtain independent protocol/cryptography review. The working name and QZXB ticker are provisional; public screening has recorded nearby ZXB/ZBX symbols. Broader name/ticker/domain/social-handle review remains a distinct task before asserting uniqueness. No external audit, trademark clearance or platform acceptance is implied by this document.

## 3. What can produce cash flow before native trading exists?

The project should pursue cash flow through things that can be delivered and accepted now, rather than wait for token trading or present a proposed token allocation as cash.

1. **Milestone-based technical sponsorship.** Scope one deliverable at a time: canonical issuance conformance, mining/halving vectors, recovery qualification, ML-DSA review, native EVM integration, or reproducible release engineering. Define acceptance tests, time, budget/resource commitment and written conditions before work begins.
2. **Contracted systems engineering.** Offer scoped Rust/protocol integration, deterministic state/replay testing, wallet/developer tooling, contract integration, build provenance, and technical documentation where the exact skills and deliverables are agreed.
3. **AI / ML / LLM engineering engagements.** Separately scope model-backed application integration, Python ML prototypes, evaluation/benchmark pipelines, optimisation, or agent/compute workflow prototypes. Do not market these as existing QuantumZXB production services unless a working demonstrator and measurable service level exist.
4. **Research grants and academic collaborations.** Target defined research outputs with reproducible experiments and open deliverables; state sponsor attribution, milestone acceptance and any conflicts clearly.
5. **Paid support/training.** Developer onboarding, node-operator exercises, technical workshops and integration support can become a revenue line once the relevant materials and support capacity are operational.

### Cash-flow controls

- There is no verified QuantumZXB revenue or confirmed sponsor in the current evidence.
- A conditional future allocation of up to 1B native coins does not itself provide spendable cash and must not be described as a signed sponsor award.
- Native transaction fees and AI/compute marketplace fees are future possibilities only after their services are implemented and used.
- Do not pay for liquidity, listings, audit or infrastructure services out of an unapproved budget; prioritize no-cost reproducible work and funded, milestone-based contributions.
- Do not promise coin returns, a listing, a market price, a liquidity depth, miner profit or sponsor acceptance.

## 4. Liquidity is different from market data

A platform page or a price chart does not create liquidity. Real liquidity requires an authentic and accessible market, willing counterparties, credible deposits/withdrawals or a supported DEX pool, accurate prices/volume and transparent circulating-supply information. In a thin market, a displayed price may not be executable for meaningful size.

Never create fake trades, wash volume, synthetic candles, misleading circulating-supply figures, or a QX/QZXB identity substitution. Any later market report should clearly distinguish last trade, spread, depth, 24-hour volume, total supply, circulating supply, locked versus transferable quantities, and the source/time of every figure.

## 5. Authentic charts we can build before a coin market exists

A native price chart must wait for real market data, but the website can show useful engineering/network telemetry as soon as a public devnet emits reliable records:

- block height, block interval distribution and chain-tip progress;
- canonical reward/subsidy by height, modelled versus observed issuance, and cumulative supply counters;
- validated/rejected transaction counts and mempool depth;
- measured TPS and p50/p95/p99 inclusion latency from a published load test;
- node uptime, peer count, sync rate, CPU/RAM/disk/network use and recovery results;
- miner H/s, power/joules per hash and configuration **only** for clearly identified devices and tests;
- state-root/receipt agreement across independent nodes and clients.

Every chart must display its data source, network, measurement window, version/commit and whether the series is live, simulated, candidate-only or historical. The current candidate PoW screens and single-host asset-state workload are not native network TPS or production telemetry. No live-network dashboard should be labelled live until it actually consumes authenticated devnet/mainnet data.

## 6. Recommended no-hype execution sequence

1. Close Gate 2 with one versioned monetary/Genesis profile and independent cross-language vectors.
2. Close Gate 8 with an independent trust provider and multi-host rollback/storage qualification.
3. Integrate canonical native EVM semantics, RPC and a real deploy/call flow; close Gate 12.
4. Operate a zero-value devnet with independent operators; publish native wallet, explorer, API and reproducible measurements.
5. Publish a release evidence packet with source revision, build provenance, supply methodology, security-review status and incident/support contact.
6. Establish a real market or supported DEX pair only when the production scope and relevant network/integration prerequisites are met.
7. Then request CMC/CoinGecko review and pursue data-provider/exchange integration for TradingView; treat outcomes and timelines as decisions of the platforms, not project-controlled milestones.

**Bottom line:** the nearest monetisation path is a funded engineering milestone or scoped AI/ML/Rust integration engagement. The nearest credibility milestone is canonical issuance plus a multi-operator devnet. A native price chart and tracked listings follow a real, verifiable market; they are not prerequisites to earning the first project revenue from engineering services.
