# QRun - QZXB Native Layer-1 & Open Ecosystem

**QRun** is the public brand of an independently developed native Layer-1 project; **QZXB** is the selected native-coin ticker and **QRun Blockchain** is the network name. The source contains a Rust-native ledger research programme, deterministic state/recovery candidates, ML-DSA-65 and hybrid-identity research, an isolated EVM/revm smart-contract laboratory, and an AI-native ecosystem roadmap.


## Public ecosystem status (2026-10-29)

The source repository and project website are public, and we are actively inviting independent node operators, code contributors, security reviewers, AI/ML researchers, application developers and milestone sponsors. **The running node remains experimental public-alpha; value-bearing native Mainnet and a genuine QZXB/USDT market are not live.** A public source tree is open for review/contribution; it is not a claim that candidate balances are publicly spendable.

- **Join the ecosystem:** [operator onboarding issue #72](https://github.com/hamidnikkhah660-arch/ai-native-l1/issues/72), [independent protocol review #73](https://github.com/hamidnikkhah660-arch/ai-native-l1/issues/73), [sponsors/contributors #1](https://github.com/hamidnikkhah660-arch/ai-native-l1/issues/1), and [CONTRIBUTING.md](CONTRIBUTING.md).
- **Current identity:** [QRun/QZXB brand decision](docs/CP-0464_QRUN_QZXB_BRAND_IDENTITY_2026-10-29.md).
- **Mainnet and market release decision:** [CP-0465](docs/CP-0465_QRUN_MAINNET_PUBLIC_TRADING_NO_GO_2026-10-29.md).
- **Zero-budget liquidity routes:** [CP-0466](docs/CP-0466_QRUN_ZERO_BUDGET_REAL_LIQUIDITY_PATH_2026-10-29.md).
- **Public outreach kit:** [English-only project description and platform-specific drafts](docs/QRUN_PUBLIC_OUTREACH_KIT_2026-10-29.md).
- **Public community announcement:** [QRun contributor discussion](https://github.com/hamidnikkhah660-arch/ai-native-l1/discussions/77).
- **Independent zero-value Devnet onboarding:** [operator packet](docs/QZXB_ZERO_VALUE_DEVNET_OPERATOR_ONBOARDING_V01_2026-10-27.md).
- **Global project site:** https://hamidnikkhah660-arch.github.io/ai-native-l1/
- **Technology guide:** [Rust Layer-1 architecture and implementation boundaries](technology.html).
- **Cryptography guide:** [ML-DSA-65, the selected 53-case fixture, hybrid-signature limits](cryptography.html).
- **Current economics:** [10B Genesis direction and superseded emission model](economics.html).
- **Release status:** [Current source branch, test inventory, production blockers](status.html).
- **Contributions and sponsorship:** [How to submit a review, work plan or funding proposal](contribute.html).
- **EVM toolchain security follow-up:** [Hardhat/EDR validation, clean dependency audit and CI coverage](docs/CP-0467_QRUN_EVM_TOOLCHAIN_DEPENDENCY_HARDENING_2026-10-29.md).
- **Technical readiness and sponsorship milestones:** [M0–M6 deliverables, evidence gates, proposal format and zero-budget fallback](docs/QRUN_TECHNICAL_READINESS_AND_SPONSORSHIP_PLAN_V1_2026-10-29.md).
- **Source and contribution issues:** https://github.com/hamidnikkhah660-arch/ai-native-l1
- **Latest experimental QRun source (not a production release):** [work branch](https://github.com/hamidnikkhah660-arch/ai-native-l1/tree/work/qzbe-v04-persistent-mining-20261026).
- **Engineering white paper:** [QuantumZXB Native Coin White Paper v0.3](docs/QUANTUMZXB_NATIVE_COIN_WHITEPAPER_V03.md)
- **Master roadmap:** [QuantumZXB Engineering & Ecosystem Roadmap v0.3](docs/QUANTUMZXB_MASTER_ROADMAP_V03.md)
- **Technical review and test evidence:** [CP-0343 report](docs/CP_0343_TECHNICAL_REVIEW_AND_TEST_RESULTS.md)
- **Latest halving visualization and emission-data checkpoint:** [CP-0349](docs/CP_0349_REPRODUCIBLE_CANDIDATE_HALVING_VISUALIZATION_2026-10-21.md)
- **Latest full curated source validation:** [CP-0347](docs/CP_0347_PUBLIC_CURATED_CHECKOUT_VALIDATION_2026-10-21.md) - **Latest founder/market-readiness docs:** [CP-0348](docs/CP_0348_FOUNDER_CREDENTIAL_MARKET_READINESS_2026-10-21.md)
- **Current public release and source-evidence manifest:** [v1.8 manifest](docs/PUBLIC_RELEASE_MANIFEST_V18_2026-10-22.md)
- **Gate 2 bounded checkpoint/replay reachability finding:** [CP-0379](docs/CP_0379_GATE2_PFM4_BOUNDED_CHECKPOINT_DESIGN_2026-10-22.md) — durable logical height, retained archive, retarget history, halving, and trust requirements; no production cap changes.
- **Gate 2 checkpoint schema and trust-boundary proposal:** [CP-0380](docs/CP_0380_GATE2_CHECKPOINT_SCHEMA_THREAT_MODEL_2026-10-22.md) - proposed PCP4/PFM5 record layout, logical-height retarget-history requirements, rollback/freshness assumptions and adversarial acceptance criteria; design only, no runtime implementation.
- **Gate 2 bounded target-history snapshot candidate (CP-0381):** [Snapshot/restore tests and limits](docs/CP_0381_BOUNDED_TARGET_HISTORY_SNAPSHOT_2026-10-22.md) - in-memory support only; no PCP4 codec, durable checkpoint persistence, integrated canonical fork-choice/reorg, or independent trust proof.
- **Gate 2 checked chainwork overflow candidate (CP-0382):** [Fail-closed 256-bit accumulation and atomicity tests](docs/CP_0382_GATE2_CHAINWORK_OVERFLOW_FAIL_CLOSED_2026-10-22.md) - overflow now returns an explicit error before candidate state mutation; Gate 2 remains open pending integrated checkpoint/reorg and independent validation.
- **Gate 2 canonical PCP4 record codec candidate (CP-0384):** [Byte format, independent golden vector and trust limits](docs/CP_0384_PCP4_CANONICAL_RECORD_CODEC_CANDIDATE_2026-10-22.md) - a standalone codec with context binding only; no PFM5 persistence, checkpoint authorization, anti-rollback service or node/reorg integration.
- **PFM5 checkpoint manifest codec candidate (CP-0386):** [Canonical manifest format, PCP4 metadata binding and independent vector](docs/CP_0386_PFM5_CHECKPOINT_MANIFEST_CODEC_CANDIDATE_2026-10-22.md) - a standalone serialization/binding codec; no durable checkpoint publication, authenticated ancestry or anti-rollback integration.
- **PFM5 full-archive replay-binding candidate (CP-0388):** [Genesis checkpoint and replay binding](docs/CP_0388_PFM5_FULL_ARCHIVE_REPLAY_BINDING_CANDIDATE_2026-10-23.md) ? recomputes every PMT4 envelope digest and checks the branch set and selected canonical tip against a replayed archive; rejects pruned non-Genesis checkpoints. Not wired into durable-store commit/startup or external anti-rollback.
- **PFM5 externally anchored checkpoint-restore candidate (CP-0389):** [Restore checks and trust limitations](docs/CP_0389_PFM5_CHECKPOINT_BASELINE_RESTORE_CANDIDATE_2026-10-23.md) ? restores only after an exact external manifest commitment and monotonic floors match; rejects manifests that still need post-checkpoint archive replay. Not yet wired into the live PFM4 store/runtime.
- **Publication checkpoint:** [CP-0344](docs/CP_0344_PUBLIC_DOCUMENTATION_REFRESH_2026-10-20.md)
- **Historical allocation proposal (superseded by CP-0437):** [Tokenomics policy v0.4](docs/FOUNDER_SPONSOR_CONTRIBUTOR_ALLOCATION_POLICY_V04_2026-10-24.md)
- **Current curated source baseline:** [v0.1.1-source](https://github.com/hamidnikkhah660-arch/ai-native-l1/releases/tag/v0.1.1-source)
- **Founder profile and collaboration contact:** [Founder / AI research profile](docs/FOUNDER_PROFILE_AND_COLLABORATION.md) - email: [hamidnikkhah660@gmail.com](mailto:hamidnikkhah660@gmail.com?subject=QuantumZXB%20collaboration)
- **Fixed-scope paid engineering offer (G1):** [Rust/protocol reproducibility and AI/ML sprint, deliverables, acceptance criteria, and payment terms](docs/ENGINEERING_SERVICE_OFFER_V01.md)
- **Public launch compliance / G0 readiness (not legal advice):** [MiCAR, donation status, payout and owner-side verification checklist](docs/CP_0372_G0_PUBLIC_LAUNCH_COMPLIANCE_CHECKLIST_2026-10-22.md)
- **Mainnet architecture boundary (Gate 2 / Gate 8):** [PMT4/PFM4 runtime, loopback-only smoke limits and production prerequisites](docs/CP_0373_GATE2_PFM4_RUNTIME_PRODUCTION_BOUNDARY_2026-10-22.md)
- **PMT4/PFM4 invalid-proof-of-work regression:** [Atomic rejection without changing manifest, branch archive, or canonical tip](docs/CP_0374_GATE2_PFM4_INVALID_POW_ATOMICITY_2026-10-22.md)
- **PMT4/PFM4 invalid miner-reward regression:** [Valid-PoW block with a wrong subsidy is rejected without durable state mutation](docs/CP_0375_GATE2_PFM4_INVALID_REWARD_ATOMICITY_2026-10-22.md)
- **PMT4/PFM4 expected-target binding regression:** [PoW meeting a peer-forged easier target is rejected without durable mutation](docs/CP_0376_GATE2_PFM4_EXPECTED_TARGET_ATOMICITY_2026-10-22.md)
- **PMT4/PFM4 archive-replay target regression:** [Recovery rejects a block that only meets a peer-forged easier target](docs/CP_0377_GATE2_PFM4_ARCHIVE_REPLAY_TARGET_BINDING_2026-10-22.md)
- **Branch-derived retarget observation (Gate 2):** [Timestamp-window derivation, override rejection, and atomic replay validation](docs/CP_0378_GATE2_BRANCH_DERIVED_RETARGET_2026-10-22.md)
- **Mining, halving and performance evidence:** [Candidate parameters and benchmark methodology](docs/MINING_HALVING_PERFORMANCE_AND_SCALING_V01.md)
- **Reproducible halving charts and data:** [Candidate curve generator](simulations/candidate_halving_curve.py) - [Per-era CSV](simulations/candidate_halving_curve.csv); candidate-only, not live supply.
- **Liquidity, market-data and public launch readiness:** [Platform prerequisites, cash-flow options and launch blockers](docs/LIQUIDITY_MARKET_DATA_AND_PUBLIC_LAUNCH_READINESS_V01.md)
- **Owner's zero-budget launch and liquidity directive:** [Persistent launch gate and fresh-session handoff](docs/OWNER_DIRECTIVE_ZERO_BUDGET_LAUNCH_AND_LIQUIDITY_GATE_V01_2026-10-21.md) - [live execution issue #12](https://github.com/hamidnikkhah660-arch/ai-native-l1/issues/12)
- **Sponsorship and contributor discussion:** [Public issue #1](https://github.com/hamidnikkhah660-arch/ai-native-l1/issues/1)
- **Previous public documentation release:** [v0.2.0-docs](https://github.com/hamidnikkhah660-arch/ai-native-l1/releases/tag/v0.2.0-docs)

## Support QuantumZXB's open-source development

QuantumZXB has a project page on Giveth; check the [official campaign page](https://giveth.io/project/quantumzxb) directly for its current status and any available donation options. Wallet control, actual receipts, payout access, gas or third-party costs, and tax treatment are not certified by this repository. Donations, if available, are voluntary support for public-benefit open-source engineering, reproducible testing, technical documentation, developer tools, and independent technical review when resources are available.

**[Support QuantumZXB on Giveth](https://giveth.io/project/quantumzxb)**

Transparency note: the native QZXB mainnet and a liquid native-coin market have not launched. Donations are not a purchase of QZXB tokens or an investment; no token rewards, profits, financial returns, or guaranteed outcomes are promised. As of the initial campaign check on 2026-10-21, Giveth showed the direct project page as active with donations enabled, public directory review still pending, and GIVbacks status not eligible. These platform statuses may change; consult the live campaign page for current status. No donations are claimed here.

## Engineering highlights

### Native Layer-1

The Rust working tree includes research and candidate components for proof-of-work and difficulty adjustment, deterministic transaction/state validation, chain selection and reorganisation, state-root commitments, snapshot validation, durable storage and archive recovery. The next release milestone integrates one frozen monetary/Genesis profile through the canonical producer, validator/importer, fork-choice, persistence, replay and state-root paths.

### Post-quantum and hybrid-signature research

The project has a real Libcrux ML-DSA-65 verification adapter, selected hash-pinned external verification vectors, differential-testing artefacts and V4 hybrid identity/transaction candidates that combine Ed25519 with ML-DSA-65. The selected external fixture includes 53 cases (48 expected-valid and 5 expected-invalid). The selected hybrid profile still needs full production-path integration and independent deployment/security qualification before any end-to-end post-quantum claim.

### Smart contracts and EVM compatibility

An isolated EVM lab pins revm and explores call/create, storage, gas, rollback and cross-client execution behaviour. The separate QX ERC-20 candidate is deployed on Ethereum Sepolia and has a testnet-only wallet/deployment console. **QX is a distinct Sepolia test asset, not the proposed native QZXB coin.** The revm lab is not yet the canonical VM dependency of the native node; native EVM account/code/storage state, receipts, gas rules and RPC integration are defined in the roadmap.

### Infrastructure and resource safety

The codebase covers bounded wire parsing and ingress/worker queues, authenticated peer-session research, state-commitment candidates, fork/reorg history replay, archive paging, snapshot/store recovery models and process-crash tests. The next qualification stage adds an independently administered monotonic trust provider and tests across independently operated hosts and storage-failure conditions.

## Current native QZXB direction (CP-0437, 2026-10-28)

The current owner-directed candidate targets a fixed Genesis supply of **10,000,000,000 QZXB**, all allocated to the owner at Genesis, with **zero post-Genesis minting and zero block subsidy**. This is the selected design direction; it is not evidence that value-bearing Mainnet has launched, that the local candidate balance is publicly spendable, or that any market price/liquidity exists. Fee-only block production, canonical issuance, recovery, independent operators and production review remain release gates.

- **Current direction:** [CP-0437 - Full-supply Genesis direction](docs/CP-0437_QRUN_FULL_SUPPLY_GENESIS_DIRECTION_2026-10-28.md).
- **Genesis/profile context:** [CP-0436](docs/CP-0436_MAINNET_GENESIS_PROFILE_FREEZE_PACKET_2026-10-27.md) and [CP-0447](docs/CP-0447_QRUN_MAINNET_10B_RELEASE_GATE_2026-10-28.md).
- **Production gate:** [CP-0465 - Mainnet / public trading decision](docs/CP-0465_QRUN_MAINNET_PUBLIC_TRADING_NO_GO_2026-10-29.md).
<details>
<summary>Historical v0.4 allocation proposal - superseded for the current QRun Genesis direction</summary>

## Historical native coin design and tokenomics (owner-directed policy v0.4)

The planned maximum native QZXB supply is **10,000,000,000 coins**: **30% mining/network-security rewards (3B); 10% community airdrop (1B); 10% exchange, market-integration and liquidity partnerships (1B); 10% major marketing partners (1B); 10% developers/security contributors (1B); 10% financial/strategic supporters (1B); 10% protocol burn reserve (1B); and 10% owner allocation (1B)**. The eight buckets total exactly 100%.

These are planned allocations, not active Genesis issuance, circulating supply, cash raised, signed awards, a completed airdrop or an actual burn. Exchange listing is not guaranteed; the exchange reserve is conditional on documented services/milestones, not a promise to buy a listing. Sponsor, marketing and contributor awards must be documented. The burn reserve is not burned until a verifiable burn occurs and carries no price-support promise. The owner allocation is explicitly 1B / 10%; control does not authorize hidden issuance or bypassing published consensus rules.

- **Historical allocation proposal, superseded by CP-0437:** [Tokenomics and Distribution Policy v0.4](docs/FOUNDER_SPONSOR_CONTRIBUTOR_ALLOCATION_POLICY_V04_2026-10-24.md)
- **Historical white paper:** [QuantumZXB Native Coin White Paper v0.3](docs/QUANTUMZXB_NATIVE_COIN_WHITEPAPER_V03.md) (read alongside the later CP-0437 and CP-0465 release decisions)
- **Current engineering roadmap:** [QuantumZXB Engineering & Ecosystem Roadmap v0.3](docs/QUANTUMZXB_MASTER_ROADMAP_V03.md)
- **Production gate status:** Gate 2 and Gate 8 remain open; native QZXB mainnet and a liquid native-coin market are not launched.

Both the former 4B founder / 3B mining / 3B public-goods proposal and the later v0.4 percentage-bucket proposal are historical. CP-0437 is the latest owner-directed Genesis target: 10B QZXB to one owner account at Genesis, with zero later minting and zero block subsidy. The separate QX ERC-20 deployment on Ethereum Sepolia is a test asset, not the native QZXB coin or a production market.


</details>

## Experimental branch test inventory and recorded validation (2026-10-29)

The active experimental source branch is work/qzbe-v04-persistent-mining-20261026; its source lives under src/native/pow_bench. The branch is not a production release and is separate from the smaller public curated baseline described below.

- cargo test --all-targets --locked --offline -- --list enumerated 1,187 test cases across 74 Cargo test targets, including 931 tests in src/lib.rs. This command lists test cases; it does not execute them.
- The dated [CP-0465 release-gate report](docs/CP-0465_QRUN_MAINNET_PUBLIC_TRADING_NO_GO_2026-10-29.md) records a full local cargo test --all-targets --locked run with exit code 0, plus focused QRun node and wallet tests. These are local regression results, not an independent security review, third-party build attestation or multi-host production qualification.
- Follow-up EVM validation on 2026-10-29: clean npm ci, npm run compile, all three npm test suites and npm audit passed (zero reported vulnerabilities) using Hardhat 3.21.1 and patched Zod/Undici resolutions. These tests use only an ephemeral loopback EVM; QX on Sepolia remains a separate test asset, not native QZXB. See [CP-0467](docs/CP-0467_QRUN_EVM_TOOLCHAIN_DEPENDENCY_HARDENING_2026-10-29.md).

## Latest curated public checkout validation (2026-10-21)

The public curated tree at source commit c3a5474aea60d3925f45ccc5f964f1229e4565e8 was independently rebuilt and tested on Windows with Rust/Cargo 1.82.0: cargo fmt --all -- --check, cargo check --all-targets --locked --offline, and cargo test --all-targets --locked --offline all exited 0. The public checkout library suite passed 735/735 tests, and the remaining targets completed with no failures. This is separate from the larger maintainer checkout earlier 736/736 count; see [CP-0347](docs/CP_0347_PUBLIC_CURATED_CHECKOUT_VALIDATION_2026-10-21.md). Existing unused/dead-code warnings remain. These checks are regression evidence, not a security audit or throughput benchmark.

## Roadmap

1. Freeze and integrate the canonical native Genesis, monetary profile and end-to-end supply invariants.
2. Integrate the selected hybrid identity/signature profile and an independent anti-rollback trust domain.
3. Integrate EVM gas/fork/account/state/receipt semantics and RPC in the canonical native node.
4. Operate a zero-value devnet with independent nodes, native wallet, RPC and explorer.
5. Complete reproducible-release qualification and independent protocol/cryptography review.
6. Grow through sponsor-funded engineering, developer tooling, integration services and later verifiable AI/compute applications.
7. Make the production and market-launch decision against measured evidence and the intended product scope.

## Founder background and direct proposals

The founder profile now reflects the founder-confirmed **Ph.D. in Artificial Intelligence (completed 2024; institution omitted by request)** and summarises the AI, quantum-machine-learning, fuzzy/evolutionary optimisation, and post-quantum blockchain research described in the supplied CV and the engineering demonstrated in this repository. Sponsors, Rust/protocol engineers, cryptography reviewers, EVM developers, AI/LLM researchers, academic groups, grant programmes, infrastructure providers, exchanges and market-data platforms can send a concrete proposal to [hamidnikkhah660@gmail.com](mailto:hamidnikkhah660@gmail.com?subject=QuantumZXB%20collaboration). Exchange or data-platform contact is for technical diligence/readiness discussion only; no listing or market is represented as live. See the [liquidity and public-launch readiness plan](docs/LIQUIDITY_MARKET_DATA_AND_PUBLIC_LAUNCH_READINESS_V01.md).

## Historical mining/emission candidate (superseded for the current Genesis direction)

Older research records modelled a 3B mining/security envelope with a candidate 30-second target, 2,016-block difficulty window, Argon2id parameters and a halving/subsidy schedule. Those numbers remain in dated historical simulation reports only. They are not the current supply policy after CP-0437 and must not be promoted as a live emission plan.

The current owner-directed target assigns all 10,000,000,000 QZXB at Genesis to one owner account, with zero post-Genesis minting and zero block subsidy. Any block production would therefore be fee-only. Canonical consensus, Genesis, issuance invariants, recovery and fee-only security economics remain release gates; no production mining payout, live supply or native TPS benchmark is claimed. See [CP-0437](docs/CP-0437_QRUN_FULL_SUPPLY_GENESIS_DIRECTION_2026-10-28.md) and [CP-0465](docs/CP-0465_QRUN_MAINNET_PUBLIC_TRADING_NO_GO_2026-10-29.md).

The source tree is a curated public selection. Review specific files, reproduce commands in the relevant package, and use the [current public release manifest](docs/PUBLIC_RELEASE_MANIFEST_V18_2026-10-22.md) to identify the versioned public baseline. The public white paper and roadmap describe the engineering plan; they do not assert that future integrations are already operating on native Mainnet.
