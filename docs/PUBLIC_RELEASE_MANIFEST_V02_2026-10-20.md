# Public Source Release Manifest V02 — QuantumZXB / AI-Native L1

Prepared: 2026-10-20
Release: `v0.1.1-source`
Stable repository URL: https://github.com/hamidnikkhah660-arch/ai-native-l1
Global site: https://hamidnikkhah660-arch.github.io/ai-native-l1/

## Identity

The project has consolidated the public working identity to **QuantumZXB** (display: Quantum ZXB). **QZXB** is only a proposed native-asset ticker. An initial exact search did not find an obvious QZXB cryptoasset, but an existing Ethereum ERC-20 uses `ZXB` and the market has nearby symbol collisions. Therefore no global uniqueness, registered trademark, reserved exchange ticker, listing or deployment is claimed. Official registry review remains an open issue: https://github.com/hamidnikkhah660-arch/ai-native-l1/issues/5.

The older Ethereum Sepolia contract retains its own immutable `Qanvoryx Launch Candidate` / `QX` metadata. It is a separate testnet ERC-20, not the native coin and not QZXB. “Quantum” is branding only and does not claim end-to-end quantum-resistant security.

## Public evidence and roadmap

- [Brand decision](BRAND_IDENTITY_DECISION_V02_2026-10-20.md)
- [CMC / TradingView market readiness](MARKET_DISCOVERY_AND_LISTING_READINESS_V01_2026-10-20.md)
- [Gate 2 and Gate 8 engineering closure plan](NATIVE_GATE2_GATE8_CLOSURE_PLAN_V01_2026-10-20.md)
- [Gate 2 tracking issue](https://github.com/hamidnikkhah660-arch/ai-native-l1/issues/2)
- [Gate 8 tracking issue](https://github.com/hamidnikkhah660-arch/ai-native-l1/issues/3)
- [Listing readiness tracking issue](https://github.com/hamidnikkhah660-arch/ai-native-l1/issues/4)
- [Brand clearance tracking issue](https://github.com/hamidnikkhah660-arch/ai-native-l1/issues/5)
- [Contributor / research sponsor call](https://github.com/hamidnikkhah660-arch/ai-native-l1/issues/1)

## CMC and TradingView decision

No CMC request has been submitted and no TradingView symbol integration has been requested, because there is no live native Mainnet asset, native block explorer, real native trading pair or authentic market data feed. The distinct Sepolia QX ERC-20 must not be represented as the proposed native QZXB asset.

Current official platform references:
- CMC criteria: https://support.coinmarketcap.com/hc/en-us/articles/360043659351-Listings-Criteria
- CMC official request: https://coinmarketcap.com/request/
- TradingView unsupported asset policy: https://www.tradingview.com/support/solutions/43000756141-how-to-add-an-asset-that-is-not-supported-on-the-platform/
- TradingView symbol search/data source notes: https://www.tradingview.com/support/solutions/43000746682-symbol-search-find-any-symbol-on-tradingview/

Listings remain platform decisions. A chart must be based on real source data. No synthetic candles, fake volume, wash trading, fabricated users or promised +50/+100/+200% gains are permitted. Sustainable adoption work focuses on reproducible builds, independent node operators, verifiable activity, external reviews, actual contributors and transparent operating economics.

## Verification inherited from v0.1.0 source

No consensus/runtime code changes are included in this docs-and-public-identity update. The last full native verification from the release tree:
- Rust format check and locked offline all-target build: PASS.
- Rust `cargo test --all-targets --locked --offline`: exit code 0; 735/735 library tests passed and the other binary/integration targets had zero failures.
- EVM local contract/wallet-console/server tests: PASS; tests did not contact a public network.
- CycloneDX SBOM checks: PASS, with no duplicate component refs or dangling dependency refs.
- Privacy pattern scan: PASS for the documented pattern set; not a comprehensive secret detector.

## Gates are not waived

- Gate 2 — canonical issuance, Genesis, reward buckets and end-to-end supply invariants: OPEN.
- Gate 8 — independent monotonic trust, exact-successor CAS, canonical runtime integration and rollback/power-failure recovery evidence: OPEN.
- External protocol/cryptography security audit: OPEN.
- Public zero-value native devnet/operator qualification: OPEN.
- Activity-specific public-offer review: OPEN.
- Trademark/ticker clearance: OPEN.
- CMC tracked-listing eligibility: NOT MET.
- TradingView native symbol/data feed: NOT AVAILABLE.

The public source and site are globally accessible. They are not a production Mainnet, sale, market listing or active revenue source. The owner cash-spend cap remains USD 0.00.
