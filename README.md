# QuantumZXB - AI-Native Layer-1 Engineering Project

**QuantumZXB** is the public working identity of an independently developed native Layer-1 and programmable-ecosystem project. The source combines a Rust-native ledger research programme, deterministic state/recovery candidates, ML-DSA-65 and hybrid-identity research, an isolated EVM/revm smart-contract laboratory, and a roadmap toward an AI-native developer ecosystem.

- **Global project site:** https://hamidnikkhah660-arch.github.io/ai-native-l1/
- **Source and contribution issues:** https://github.com/hamidnikkhah660-arch/ai-native-l1
- **Engineering white paper:** [QuantumZXB Native Coin White Paper v0.2](docs/QUANTUMZXB_NATIVE_COIN_WHITEPAPER_V02.md)
- **Master roadmap:** [QuantumZXB Engineering & Ecosystem Roadmap v0.2](docs/QUANTUMZXB_MASTER_ROADMAP_V02.md)
- **Technical review and test evidence:** [CP-0343 report](docs/CP_0343_TECHNICAL_REVIEW_AND_TEST_RESULTS.md)
- **Latest full curated source validation:** [CP-0347](docs/CP_0347_PUBLIC_CURATED_CHECKOUT_VALIDATION_2026-10-21.md) - **Latest founder/market-readiness docs:** [CP-0348](docs/CP_0348_FOUNDER_CREDENTIAL_MARKET_READINESS_2026-10-21.md)
- **Current public documentation manifest:** [v0.6 manifest](docs/PUBLIC_RELEASE_MANIFEST_V06_2026-10-21.md)
- **Publication checkpoint:** [CP-0344](docs/CP_0344_PUBLIC_DOCUMENTATION_REFRESH_2026-10-20.md)
- **Founder/sponsor/contributor economics:** [Allocation policy v0.3](docs/FOUNDER_SPONSOR_CONTRIBUTOR_ALLOCATION_POLICY_V03.md)
- **Current curated source baseline:** [v0.1.1-source](https://github.com/hamidnikkhah660-arch/ai-native-l1/releases/tag/v0.1.1-source)
- **Founder profile and collaboration contact:** [Founder / AI research profile](docs/FOUNDER_PROFILE_AND_COLLABORATION.md) - email: [hamidnikkhah660@gmail.com](mailto:hamidnikkhah660@gmail.com?subject=QuantumZXB%20collaboration)
- **Fixed-scope paid engineering offer (G1):** [Rust/protocol reproducibility and AI/ML sprint, deliverables, acceptance criteria, and payment terms](docs/ENGINEERING_SERVICE_OFFER_V01.md)
- **Public launch compliance / G0 readiness (not legal advice):** [MiCAR, donation status, payout and owner-side verification checklist](docs/CP_0372_G0_PUBLIC_LAUNCH_COMPLIANCE_CHECKLIST_2026-10-22.md)
- **Mainnet architecture boundary (Gate 2 / Gate 8):** [PMT4/PFM4 runtime, loopback-only smoke limits and production prerequisites](docs/CP_0373_GATE2_PFM4_RUNTIME_PRODUCTION_BOUNDARY_2026-10-22.md)
- **Mining, halving and performance evidence:** [Candidate parameters and benchmark methodology](docs/MINING_HALVING_PERFORMANCE_AND_SCALING_V01.md)
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

## Native coin design and sponsor proposal

The current design targets a maximum of **10,000,000,000 native coins**, with 4B founder (40%), 3B mining/network-security (30%) and 3B public-goods/ecosystem (30%) allocation envelopes. These are monetary design terms until the selected canonical production profile and Genesis are frozen.

The owner direction is that the 4B founder allocation remains freely transferable with no protocol lock or time vesting. A future sponsor may qualify for up to **1,000,000,000 coins (10% of the total cap)** from inside the founder tranche only after fulfilling written, agreed sponsorship milestones. A proposed **1%-10% contributor/professional pool** is likewise drawn from that same founder allocation and tied to accepted work. If both pools reach 1B, at least 2B (20% of total cap) remains the founder's direct discretionary allocation. No sponsor is currently claimed as selected or contracted, and these designations are not a guarantee of value or return.

The arithmetic invariant helper and the public documentation preflight can be run using Python:

    python simulations/sponsor_allocation_checker.py
    python simulations/public_docs_refresh_checker.py

## Current engineering validation

On the maintainer's complete working checkout at review time:

- cargo fmt --all -- --check - PASS.
- cargo check --all-targets --locked --offline - PASS.
- cargo test --all-targets --locked --offline - PASS, 736/736 library tests and no failures across remaining test targets.
- npm test in contracts/launch-asset - PASS for the fixed-supply local EVM, wallet-console and loopback server suites.

The complete maintainer checkout is larger than this curated public release tree; these counts describe the working checkout used for the review, not a claim that every internal historical fixture is included here. They are engineering regression evidence, not an independent security audit or a TPS/latency benchmark. The separate contracts/vm-lab Rust 1.99 toolchain test suite was not rerun in the current review environment.

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

## Mining and performance status

The current 10B design cap assigns 3B to the mining/network-security envelope. A shared research candidate uses 8 decimal places, a 30-second target, 2,016-block difficulty window, Argon2id v1.3 (64 MiB, one iteration, one lane), and a 4,204,800-block halving interval with a 356.73515981-coin initial subsidy. These are candidate arithmetic values, not frozen production rules; Gate 2 remains open and the reward path is not yet integrated through canonical block production/import, Genesis, reorganisation, snapshots and state roots. The project has no validated end-to-end native TPS or public-network latency benchmark. See the mining/performance report for the single-host candidate screens, their limitations, and the exact benchmark plan.

The source tree is a curated public selection. Review specific files, reproduce commands in the relevant package, and use the [current public release manifest](docs/PUBLIC_RELEASE_MANIFEST_V06_2026-10-21.md) to identify the versioned public baseline. The public white paper and roadmap describe the engineering plan; they do not assert that future integrations are already operating on native Mainnet.
