# CP-0401 - Global Native Coin Launch and Liquidity Fast Path

**Date:** 2026-10-24
**Reviewed working-tree commit:** `a839c3241262032d3084ab418678ec45d60686e1`
**Status:** Source-based launch-readiness assessment and execution proposal only. It does not approve Mainnet activation, a coin sale, market-making, bridge deployment, or spending.

## Executive decision

QuantumZXB is intended to be an independent Layer-1 network with its own native coin. It should not be presented as an ERC-20 project. The repository contains meaningful native-chain work, network and ledger candidates, a separate EVM feasibility lab, Solidity/testnet tooling, and public project documentation. However, the current evidence does not establish a public production network on which the native coin can yet be safely distributed and traded.

**Fastest honest path:** start global project cash flow now through scoped engineering sponsorship/services while finishing a publicly accessible, zero-value native devnet; then activate the native coin only after one canonical monetary profile and production state-transition path are approved and independently qualified. For actual market liquidity, first integrate a real exchange that supports deposits/withdrawals for the native chain, or complete the native EVM + asset-bridge dependencies required for a native-chain DEX. There is no safe shortcut that turns the isolated VM lab into a production smart-contract network.

Keep two meanings of liquidity separate:

- **Project cash flow:** grants, paid engineering, sponsorship, training/support, or clearly disclosed voluntary donations can fund work before native coin trading exists.
- **Coin market liquidity:** real two-sided orders or accessible pool reserves and counterparties for the live native coin. A website, listing application, estimated price, allocation spreadsheet, or testnet contract does not create it.

## What the repository currently proves

| Component | Evidence in the working tree | Launch conclusion |
|---|---|---|
| Native Layer-1 / ledger | Rust state, block, import, persistence, monetary and private-testnet candidate modules | Substantial engineering foundation; not proof of a frozen production consensus or a live public Mainnet. |
| Versioned monetary work | CP-0397/0398/0400 candidate schedule, profile-bound transition and QZP4 snapshot, plus independent Python vectors | Candidate-only. The 10,000-atom / two-block halving values in the new golden vector are test fixtures, not production economics. |
| Current monetary runtime | PMT4/PFM4/TXN4 loopback diagnostic path; source map says diagnostic profile, local easy-PoW and `public_launch_approved=false` | Do not expose it as production value-bearing infrastructure. Gate 2 and Gate 8 remain OPEN. |
| Public devnet | `devnet_node.rs` and a zero-balance profile candidate exist | The recorded devnet path is not yet a qualified multi-operator public network with the complete authenticated peer boundary and production services. |
| Smart-contract execution | A standalone `revm 19.5.0` feasibility lab with selected contract-creation/call/storage/gas/rollback tests | Real research work, but not yet the canonical EVM runtime/state/receipt/RPC path of the native node. Gate 12 remains OPEN. |
| Solidity asset | `contracts/launch-asset/contracts/FixedSupplyLaunchAsset.sol`; documented deployment on Ethereum Sepolia at `0x7f144fe3dcfbe36ed17ef6c60ea3913179dcf4af` | This is a separate ERC-20 test asset, not the native coin, not redeemable for the native coin, and not evidence of a native market. It is not a Mainnet sale. |
| Wallet console | Browser console under `contracts/launch-asset`; server binds to loopback and deployment policy permits only Base Sepolia / Ethereum Sepolia | A useful EVM test tool, not a native production wallet or public wallet service. |
| RPC / explorer / indexer | Existing docs explicitly call native production wallet/RPC/explorer and market-data integration roadmap work | Production public endpoints and a native explorer/indexer need to be released and operated before market-data providers or users can reliably verify the coin. |
| Release and CI | Commit `a839c3241262032d3084ab418678ec45d60686e1`; recorded GitHub Actions run 40100016061 passed both jobs | Good regression evidence only; it does not close consensus, anti-rollback, VM, operational, or launch gates. |

## Two launch-critical distinctions

### Native coin versus the existing Sepolia ERC-20

The native asset must derive its identity and balances from the independent L1's canonical Genesis and consensus rules. The Sepolia contract has its own ERC-20 contract address, a separate test supply/allocation (4B/3B/3B in that contract), and freely transferable test balances. It has no native-coin redemption or guaranteed migration. Do not reuse its contract address, balances, allocation statement, or ticker as evidence for native QZXB. The current native allocation proposal is different and is still not a frozen production profile.

### Smart-contract lab versus production smart contracts

The repo includes an EVM lab and Solidity examples. That is a real ecosystem foundation, but a contract becomes a native-network application only when independently built native nodes execute the same transaction under canonical consensus and agree on state roots, receipts/logs, rollback/reorg, and restart results. The required production boundary includes a pinned EVM fork and gas rules, chain ID, sender/nonce/fee/funding mapping, code/storage state, transaction admission, receipts/logs, state commitments, canonical persistence, `eth_*` RPC, and cross-client tests. Until then, do not advertise native Solidity deployment as live.

## Recommended execution plan

### Track A - begin global project cash flow without pretending coin trading exists

1. Offer one scoped, testable paid engineering milestone at a time: Rust protocol/replay work, consensus conformance vectors, wallet/developer tooling, EVM integration, post-quantum verification research, AI/ML evaluation, or reproducible build and release engineering.
2. Accept only written sponsor/customer scope, acceptance criteria, responsible counterparties, and payment conditions. Publish the agreed deliverable and its evidence after acceptance.
3. Keep donations clearly separate from a coin purchase, investment, reward entitlement, or promise of conversion. Verify a real receipt and the owner-controlled payout route before reporting donations or revenue.
4. Maintain the zero-owner-spend assumption: use volunteer/third-party resources and signed funding commitments rather than assuming future coin sales, listing fees, audit work, or liquidity capital will appear.

This is the fastest credible project cash-flow path because it does not depend on Mainnet, a listing, or coin price discovery.

### Track B - global public distribution of the native coin

**B1. Freeze one production profile.** Record the network ID, canonical Genesis/hash, exact total-supply and allocation rules, issuance/reward/halving and fees, beneficiary key derivation/ownership process, block/transaction/snapshot versions, and activation/migration rule. Resolve any difference between older allocation examples and the current native allocation proposal. Never treat test fixtures as economics.

**B2. Close Gate 2.** Wire the single approved transition through producer and importer, and also through fork choice/reorg, durable storage, restart/replay and snapshot restoration. Derive rewards locally, reject peer-selected subsidy, enforce the lifetime supply cap and all allocation invariants atomically, and prove independent Rust/oracle agreement on valid and adversarial vectors. Preserve legacy behavior and reject unsupported versions without silent downgrade.

**B3. Close Gate 8.** Integrate an independently administered monotonic/CAS trust service outside the node's snapshot/restore domain. Test rollback, stale restore, concurrency, crash/recovery, timeouts, receipt verification and key rotation across independent hosts. A local checksum or local marker is not enough.

**B4. Launch a public zero-value native devnet before Mainnet.** Publish reproducible node binaries/configuration, at least three independently operated nodes, authenticated public peer discovery/transport, a read/write test RPC, native wallet/address and signing flow, explorer/indexer, faucet, status/monitoring, backup and incident runbooks. Test transfer, restart, replay, fork/reorg, malformed peers and cross-node root agreement. If native EVM compatibility is a launch promise, deploy and call a sample Solidity contract on this devnet across independent nodes before calling that capability live.

**B5. Publish the launch evidence packet.** Include the exact source SHA and reproducible build instructions, Genesis and supply methodology, circulating-versus-reserved supply, allocation controls/vesting, node/wallet/RPC/explorer endpoints, fees and mining rules, known limitations, security-review status, incident contact, and a clear statement of which functions are operational. Obtain independent protocol/cryptography review before exposing material real value.

**B6. Activate and distribute.** Only after the above passes, publish the selected Mainnet Genesis, node release, native wallet and explorer together. Make initial distribution auditable through the frozen Genesis and on-chain rules; communicate any mining, airdrop, contributor or treasury method exactly as implemented. Do not describe planned allocations as issued or circulating coins. Global reach of a website/repository does not by itself satisfy every jurisdiction's rules for sales, promotions, custody, exchange, or other regulated activities; obtain advice for the intended global distribution model and target markets before taking money for the coin.

### Track C - first real market and liquidity

There are two plausible routes. Neither is available solely because the Solidity lab exists.

**Route C1 - native-chain listing on a real exchange.** This keeps QZXB as the actual native coin. After Mainnet is reliable, provide an exchange-grade node/API, deterministic deposit detection and confirmations, withdrawal signing and recovery controls, explorer links, supply methodology, security/incident contact and operational support. Approach exchanges that explicitly support new native L1 integrations. A listing is the exchange's decision; no listing, timeframe, volume or price is guaranteed.

**Route C2 - native DEX.** This is aligned with the EVM ecosystem goal but depends on Gate 12 being closed first. Integrate and qualify the native EVM, then use a reviewed AMM design, a transparent native-coin wrapping interface if needed by the AMM, and a real second asset on the chain (for example a securely bridged stablecoin or another supported asset). Bridge/custody, contract, price/oracle and reserve risks need independent review. Seed the pool with real two-sided assets and disclose who supplied them, ownership/lock terms, fees and risks. Without the EVM integration and a real quote asset, a DEX interface alone cannot create a market for the native coin.

For either route, never manufacture volume, wash-trade, self-report a fictional price, or imply a liquidity reserve exists before assets are verifiably deposited.

## Global market-data sequence

Do not apply to aggregators before the evidence and actual trading route exist. Current platform rules are materially data/market dependent:

- [CoinMarketCap listing criteria](https://support.coinmarketcap.com/hc/en-us/articles/360043659351-Listings-Criteria) says a tracked cryptoasset should have a functional website and block explorer and be publicly/actively traded on a CMC-tracked exchange with material volume; the platform says tracked price/volume comes from integrated exchange APIs. Free review is not guaranteed.
- [CoinGecko's new cryptocurrency listing guide](https://support.coingecko.com/articles/9489827481-how-to-list-a-new-cryptocurrency-on-coingecko) says the asset must be actively tradable on an exchange tracked by CoinGecko; a preview application is a separate process, not proof of a market.
- [DEX Screener token listing guide](https://docs.dexscreener.com/token-listing) describes indexing after a token is added to a liquidity pool and has a transaction. For a new independent L1, do not assume a native coin or custom DEX is automatically supported: confirm chain/indexer integration and feed real on-chain data.

Submit requests only after linking the actual Mainnet, explorer, native market/pair, data source and contact details. CoinMarketCap/CoinGecko are data platforms, not the venue that creates liquidity.

## Solana comparison: what to copy and what not to claim

Solana's official [core documentation](https://solana.com/docs/core) describes programs as the on-chain execution layer, while its [RPC documentation](https://solana.com/docs/rpc) and [cluster documentation](https://solana.com/docs/references/clusters) expose distinct Mainnet, Devnet and Testnet environments and public service endpoints. The transferable lesson is the integrated, observable stack: deterministic protocol, program execution, independent operators, stable RPC, wallet/developer tools, explorer, test faucet, status/telemetry, and apps that can actually deploy and execute.

The repo has foundations in several of these areas, but source availability, local test binaries, an isolated VM and a testnet ERC-20 are not substitutes for that integrated production stack. Publicly launch the devnet as a builder ecosystem first; launch the value-bearing native coin only once its canonical rules and services can be verified end to end.

## Go / no-go criteria

**GO for global builder participation now:** source/docs, clearly labelled local/testnet demonstrations, sponsor/customer outreach, scoped engineering services, and a public zero-value devnet when the operator and transport gates are actually met.

**NO-GO for native-coin sale, value-bearing public mining, native market or liquidity claims at the reviewed commit:** Gate 2 and Gate 8 remain open; native production EVM/RPC is not integrated; a qualified public multi-operator native devnet, native wallet/explorer, independent security review, and real pair/counterparty liquidity are not established by current evidence.

**Next highest-value implementation task:** complete a line-specific producer/importer/runtime dispatch map and compatibility matrix, then close the canonical Genesis/reward/runtime contract. In parallel, spec the public devnet operator package and native RPC/wallet/explorer acceptance checklist. Do not connect QZP4/QZB4 candidates to live value-bearing runtime or mark a launch gate closed solely because CI passes.

## Evidence and references

- [CP-0396 native runtime call-graph audit](CP-0396_V04_RUNTIME_INTEGRATION_CALLGRAPH_AUDIT_2026-10-24.md)
- [CP-0399 versioned runtime integration plan and Gate 2 / Gate 8 evidence](CP-0399_V04_VERSIONED_RUNTIME_INTEGRATION_PLAN_AND_GATES_2026-10-24.md)
- [CP-0400 profile-bound snapshot candidate](CP-0400_V04_PROFILE_BOUND_SNAPSHOT_CANDIDATE_2026-10-24.md)
- [Liquidity and market-data readiness](LIQUIDITY_MARKET_DATA_AND_PUBLIC_LAUNCH_READINESS_V01.md)
- [Zero-budget launch and liquidity directive](OWNER_DIRECTIVE_ZERO_BUDGET_LAUNCH_AND_LIQUIDITY_GATE_V01_2026-10-21.md)
- GitHub Actions run `40100016061` passed both jobs for commit `a839c3241262032d3084ab418678ec45d60686e1`; CI success is regression evidence, not launch approval.
