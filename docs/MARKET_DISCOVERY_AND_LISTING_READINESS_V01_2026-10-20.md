# Market Discovery, Listings and Ethical Adoption Plan V01

Date: 2026-10-20
Project identity: QuantumZXB (working identity)
Native ticker proposal: QZXB (not cleared, deployed, or listed)

## Verified current state

- Public source repository: https://github.com/hamidnikkhah660-arch/ai-native-l1
- Project website: https://hamidnikkhah660-arch.github.io/ai-native-l1/
- Public source release: https://github.com/hamidnikkhah660-arch/ai-native-l1/releases/tag/v0.1.0-source
- Native Mainnet: not live; no native coin trading pair, price, exchange volume or liquidity pool.
- Native block explorer: not available in this release.
- The only recorded token contract is a separate Ethereum Sepolia testnet ERC-20, previously named `Qanvoryx Launch Candidate` with symbol `QX`. It must not be submitted or advertised as a live QZXB token.
- No listing request has been submitted to CoinMarketCap or TradingView, and neither platform has approved this project.
- Owner spend cap remains USD 0.00; no paid listing service, liquidity purchase, advertising, or cloud resource is authorized.

## CoinMarketCap (CMC)

Official sources:
- Listing criteria, last reviewed June 22, 2026: https://support.coinmarketcap.com/hc/en-us/articles/360043659351-Listings-Criteria
- Official request form: https://coinmarketcap.com/request/
- CMC's listing criteria say that a cryptoasset considered for a tracked listing should have a functional website and block explorer, be publicly and actively traded on at least one CMC-tracked exchange with material volume, and have a representative available for clarification. Meeting the guidelines does not guarantee a listing.
- CMC also has preview/untracked routes and automated DexScan discovery, but that is not a reason to misrepresent a testnet or a nonexistent market. An unverified page is not an endorsement, and CMC says tracked market data requires a supported/integrated exchange data source.

### Current decision

**DO NOT SUBMIT the native asset request yet.** The native mainnet asset, explorer and publicly traded pair do not exist, so a submission would be incomplete or misleading. The Sepolia ERC-20 is not a substitute for the native coin.

### CMC release checklist

- [ ] Freeze the production native asset identity and tokenomics.
- [ ] Finish native issuance/Genesis/transaction integration (Gate 2) and production rollback protection (Gate 8).
- [ ] Complete all other release gates and independent security review.
- [ ] Launch a verified native chain only after the release decision; publish chain specification, network ID, Genesis hash, software release, nodes and reproducible install instructions.
- [ ] Operate a public explorer that reports canonical blocks, transactions, receipts/status, address balances and supply from the actual native chain.
- [ ] Publish source-of-truth supply accounting, founder/miner/public-goods buckets, vesting/unlock state and treasury control evidence.
- [ ] If and when a lawful, real trading market exists, document authentic pair URLs, exchange name, market depth and volume. Never create wash trades, fake volume, fabricated prices or staged holders.
- [ ] Submit through CMC's official form, with truthful evidence; request a preview/untracked route only if the factual evidence supports it. Do not pay for priority or use intermediaries under the USD 0.00 spend policy.

## TradingView

Official sources:
- Unsupported asset guidance: https://www.tradingview.com/support/solutions/43000756141-how-to-add-an-asset-that-is-not-supported-on-the-platform/
- Symbol search and data sources: https://www.tradingview.com/support/solutions/43000746682-symbol-search-find-any-symbol-on-tradingview/
- Exchange/data context: https://www.tradingview.com/support/solutions/43000753166-exchange/
- TradingView's support page says unsupported instruments cannot currently be directly added by an ordinary user. Symbols are tied to exchanges/data sources; a ticker is not itself a market-data feed. TradingView's broker integration is a separate process for trading execution, not a way to invent chart data.

### Current decision

**No native QZXB TradingView symbol or price chart is available today.** There is no real market feed, pair or trading history to display. Do not publish synthetic candles as market prices.

### TradingView path

- [ ] After a legitimate native market pair is active, make sure the exchange/data provider publishes documented, consistent market data.
- [ ] Ask the exchange/data provider to pursue TradingView's data integration. TradingView indicates that exchange/broker integration is the most practical path for unsupported symbols.
- [ ] Provide full asset name, proposed/cleared ticker, underlying network, contract/address where appropriate, pair URL, exchange data and market integrity disclosures.
- [ ] Request symbol indexing only when TradingView or its data partner can verify the source; report no price history before actual trading begins.
- [ ] Do not market the existence of a TradingView entry as endorsement, a price target, or a liquidity promise.

## 30-day adoption and funding plan (milestones, not promises)

### Stage A — source adoption and evidence (now)

- Keep the public source/site current; publish release checksums, SBOMs and honest status.
- Seek independent Rust, consensus, storage and cryptography reviewers through the public issue tracker.
- Measure documentation visits, reproducible builds, meaningful issues/PRs, distinct independent reviewers and response/closure time.
- Ask for scoped research sponsorship, a grant or volunteer collaboration with written deliverables and transparent reporting; do not promise profits, token allocations or listing access.

### Stage B — release engineering

- Publish canonical protocol/Genesis/network specification, threat model, operator runbook and versioned conformance suite.
- Complete Gate 2 and Gate 8 acceptance criteria, independently review the results, and fix all high-severity findings before any public testnet exposure.
- Operate zero-value devnet first with multiple independently administered nodes and reproducible builds; publish uptime, height convergence, reorg/restart, negative-case and operator records.

### Stage C — real adoption

- Invite independent operators and developers through reproducible tasks; measure node diversity, successful builds, first-time setup completion, retained contributors, testnet transactions and confirmed bug fixes.
- Publish wallet/transaction docs, explorer provenance and network-status data only when backed by actual nodes.
- Publish founder allocation, unlock/vesting, governance and treasury policies before value-bearing activity. Use actual chain measurements, not predictions.

### Stage D — lawful market discovery

- Identify the exact native asset and the party offering it; obtain qualified review for the actual planned activities and relevant jurisdictions before value-bearing offers or paid promotion.
- Establish real market access only after technical, custody, security, operating-budget and activity-specific review.
- Seek CMC and TradingView data-source discovery when their factual prerequisites are met. Approval remains entirely up to each platform and participating exchange/provider.

## Market conduct and success metrics

No price target (including +50%, +100%, +200%), no scheduled pump, no pre-planned dump, and no guarantee of appreciation is a project milestone. A price chart cannot be engineered into a trustworthy asset by promising percentage gains.

Use evidence-based metrics instead:
- independently operated nodes and network availability;
- reproducible clean-checkout builds and conformance pass rate;
- unique active contributors and retained developers;
- testnet wallet onboarding and successful transaction completion;
- real on-chain activity with bots/spam disclosed;
- liquidity depth/slippage and concentration after actual markets exist;
- disclosed allocation/unlock concentration and treasury attestations;
- critical security issues opened/resolved and external-audit coverage;
- grant/sponsor commitments that are signed and verifiable, and actual costs/runway.

Prohibit fake trading volume, wash trading, undisclosed paid promotion, fabricated user counts, misleading partnerships, hidden founder unlocks and promises of price performance. A deep, honest market is a result of real users and market participants, not a percentage target.

## Current gate status

- Public source distribution: DONE.
- Website and public call for collaboration: LIVE.
- Brand working identity: QuantumZXB selected; QZXB remains un-cleared and unissued.
- Native Gate 2: OPEN.
- Native Gate 8: OPEN.
- Independent protocol/cryptographic audit: OPEN.
- Public zero-value devnet/operator qualification: OPEN.
- CMC tracked listing eligibility: NOT MET.
- TradingView native symbol/feed: NOT AVAILABLE.
- Native Mainnet / sale / liquidity pool / revenue: NOT active or claimed.
