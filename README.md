# QuantumZXB — AI-Native L1 Research

Latest documentation release: [v0.1.1-source](https://github.com/hamidnikkhah660-arch/ai-native-l1/releases/tag/v0.1.1-source) (identity and readiness documentation; no runtime code changes).

**Global open-source research project.** The selected public working identity is **QuantumZXB** (display form “Quantum ZXB”); **QZXB** is a proposed native-asset ticker only, not a deployed or listed token.

- [Global project page](https://hamidnikkhah660-arch.github.io/ai-native-l1/)
- [Latest public source release — v0.1.1-source](https://github.com/hamidnikkhah660-arch/ai-native-l1/releases/tag/v0.1.1-source)
- [Original code/test release — v0.1.0-source](https://github.com/hamidnikkhah660-arch/ai-native-l1/releases/tag/v0.1.0-source)
- [Brand identity decision and collision findings](docs/BRAND_IDENTITY_DECISION_V02_2026-10-20.md)
- [CMC/TradingView readiness and ethical adoption plan](docs/MARKET_DISCOVERY_AND_LISTING_READINESS_V01_2026-10-20.md)
- [Gate 2 and Gate 8 engineering closure plan](docs/NATIVE_GATE2_GATE8_CLOSURE_PLAN_V01_2026-10-20.md)
- [v0.1.1 source release manifest](docs/PUBLIC_RELEASE_MANIFEST_V02_2026-10-20.md)
- [Open call for reviewers, contributors and research sponsorship](https://github.com/hamidnikkhah660-arch/ai-native-l1/issues/1)

## Identity and ticker are not market clearance

The name is now unified as **QuantumZXB** per the project owner's delegated naming instruction. An initial web search for the exact string `QZXB` did not surface an obvious exact crypto listing, but the existing Ethereum ERC-20 `ZXB` (ZxbCoin) and a `ZBX` token are collision signals. Therefore `QZXB` remains a proposed ticker, not a globally unique/registered/cleared symbol. See the brand decision for links and scope. No trademark filing, permission or domain right is claimed.

“Quantum” is branding only. It does not claim end-to-end post-quantum security. The existence of ML-DSA research/benchmark code does not prove quantum-resistant transaction signatures, wallets, consensus and peer networking across the whole protocol.

## What is in this source tree

- `src/native/pow_bench`: Rust proof-of-work, authenticated transport, deterministic state, monetary-policy candidates, recovery and research/benchmark harnesses.
- `src/prototype`: small Python network/chain models.
- `simulations/`: the specific language-neutral test vectors and upstream data required for reproducible source tests.
- `contracts/launch-asset`: a separate fixed-supply ERC-20 research candidate with isolated local-EVM tests.
- `tools/evm_testnet_wallet*.html`: browser console sources for isolated testnet experiments.
- `sbom/`: CycloneDX inventories for the native Cargo crate and separate EVM candidate.
- `docs/`: release scope, testnet status, third-party notices, brand decision, market-readiness plan and Gate 2/Gate 8 work plan.

This is a **curated public release tree** from the larger working repository. Anyone worldwide can browse, clone, fork and review it without login. It excludes the full owner workspace/history, owner-only records, deployment secrets/private keys, brand artwork and broad unrelated historical fixture corpora. The exact fixtures referenced by this release's tests are included with available provenance/license notices. This is not a claim that every file in the owner's private working tree is released.

## Critical distinction: native L1 vs Sepolia ERC-20

The EVM asset in `contracts/launch-asset` is **not the native QuantumZXB coin**. The historical Ethereum Sepolia contract records the name `Qanvoryx Launch Candidate` and symbol `QX`; its immutable contract metadata is not renamed by this source-repository naming decision. It is testnet-only. It is not QZXB, a production token, or an invitation to buy/transfer valuable assets.

The native L1 is still a research prototype. No native Mainnet, public native trading pair, verified native explorer, production price feed, exchange listing, liquidity pool or revenue is active or claimed here.

## Gates and trading-platform readiness

- **Gate 2 — canonical issuance/Genesis/runtime: OPEN.** Candidate modules and tests exist, but a single frozen monetary profile is not yet integrated and independently verified through canonical producer/importer, fork-choice, store/replay and state transition with end-to-end supply invariants.
- **Gate 8 — independent anti-rollback/recovery: OPEN.** Models and local/process-termination tests exist; an independent trust domain/CAS, canonical integration, independent multi-host and physical-failure qualification, and external review remain outstanding.
- **CoinMarketCap: not submitted.** Its tracked-listing guidelines call for a functioning website and block explorer, plus real public trading on at least one CMC-tracked exchange with material volume. The native asset has no live mainnet, explorer or market yet. Do not submit the unrelated Sepolia QX contract as QZXB.
- **TradingView: no native symbol/data feed yet.** TradingView says unsupported instruments cannot be directly added by an ordinary user; real market data needs a supported data source/exchange path. Do not create fictitious candles, prices or volumes.

See [the evidence-based market/listing plan](docs/MARKET_DISCOVERY_AND_LISTING_READINESS_V01_2026-10-20.md) and [Gate 2/Gate 8 acceptance plan](docs/NATIVE_GATE2_GATE8_CLOSURE_PLAN_V01_2026-10-20.md).

## Reproducible local checks

Rust research crate (locked dependencies; Rust 1.82-compatible):

```powershell
Set-Location .\src\native\pow_bench
cargo fmt --all -- --check
cargo check --all-targets --locked --offline
cargo test --all-targets --locked --offline
```

Separate EVM candidate (Node.js/npm):

```powershell
Set-Location .\contracts\launch-asset
npm ci
npm run compile
npm test
```

The EVM tests use an ephemeral local chain and do not contact a public network. Do not run a deployment script against a live network or valuable asset as routine verification.

## License

Original project-authored material in this curated tree is offered under Apache-2.0 only within the scope in `LICENSE`, `NOTICE` and `LICENSES/README.md`, and only to the extent the project owner has authority to license it. The Solidity file retains its own MIT license. Third-party data and dependencies keep their own notices/terms. No trademark, ticker, logo or domain license is granted by the source license.

## Collaboration and sustainable funding

Independent Rust developers, protocol/cryptography reviewers, test operators and research sponsors are invited to propose concrete, scoped work through [public issue #1](https://github.com/hamidnikkhah660-arch/ai-native-l1/issues/1). No sponsor agreement, grant, payment route or funding receipt is currently claimed. New owner cash spend remains capped at USD 0.00.

There are no promised returns or target price increases. The project prohibits fake volume, wash trading, undisclosed paid promotion and pump/dump campaigns. Adoption metrics are real users, reproducible builds, independently operated nodes, meaningful contributions, issue resolution, uptime and transparent market integrity after a genuine market exists.

---
**Release boundary:** public source code does not mean production Mainnet or approval to offer/sell an asset. Gates 2, 8, independent audit, public zero-value devnet/operator qualification and the activity-specific public-offer review remain open.
