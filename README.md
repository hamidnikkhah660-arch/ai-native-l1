# QuantumZXB - AI-Native Layer-1 Engineering Project

**QuantumZXB** is the public working identity of an independently developed native Layer-1 and programmable-ecosystem project. The source combines a Rust-native ledger research programme, deterministic state/recovery candidates, ML-DSA-65 and hybrid-identity research, an isolated EVM/revm smart-contract laboratory, and a roadmap toward an AI-native developer ecosystem.

- **Global project site:** https://hamidnikkhah660-arch.github.io/ai-native-l1/
- **Source and contribution issues:** https://github.com/hamidnikkhah660-arch/ai-native-l1
- **Engineering white paper:** [QuantumZXB Native Coin White Paper v0.2](docs/QUANTUMZXB_NATIVE_COIN_WHITEPAPER_V02.md)
- **Master roadmap:** [QuantumZXB Engineering & Ecosystem Roadmap v0.2](docs/QUANTUMZXB_MASTER_ROADMAP_V02.md)
- **Technical review and test evidence:** [CP-0343 report](docs/CP_0343_TECHNICAL_REVIEW_AND_TEST_RESULTS.md)
- **Current public documentation manifest:** [v0.2 manifest](docs/PUBLIC_RELEASE_MANIFEST_V03_2026-10-20.md)
- **Publication checkpoint:** [CP-0344](docs/CP_0344_PUBLIC_DOCUMENTATION_REFRESH_2026-10-20.md)
- **Founder/sponsor/contributor economics:** [Allocation policy v0.3](docs/FOUNDER_SPONSOR_CONTRIBUTOR_ALLOCATION_POLICY_V03.md)
- **Current curated source baseline:** [v0.1.1-source](https://github.com/hamidnikkhah660-arch/ai-native-l1/releases/tag/v0.1.1-source)
- **Sponsorship and contributor discussion:** [Public issue #1](https://github.com/hamidnikkhah660-arch/ai-native-l1/issues/1)

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

The arithmetic invariant helper can be run using Python:

    python simulations/sponsor_allocation_checker.py

## Current engineering validation

On the maintainer's complete working checkout at review time:

- cargo fmt --all -- --check - PASS.
- cargo check --all-targets --locked --offline - PASS.
- cargo test --all-targets --locked --offline - PASS, 736/736 library tests and no failures across remaining test targets.
- npm test in contracts/launch-asset - PASS for the fixed-supply local EVM, wallet-console and loopback server suites.

The complete maintainer checkout is larger than this curated public release tree; these counts describe the working checkout used for the review, not a claim that every internal historical fixture is included here. They are engineering regression evidence, not an independent security audit or a TPS/latency benchmark. The separate contracts/vm-lab Rust 1.99 toolchain test suite was not rerun in the current review environment.

## Roadmap

1. Freeze and integrate the canonical native Genesis, monetary profile and end-to-end supply invariants.
2. Integrate the selected hybrid identity/signature profile and an independent anti-rollback trust domain.
3. Integrate EVM gas/fork/account/state/receipt semantics and RPC in the canonical native node.
4. Operate a zero-value devnet with independent nodes, native wallet, RPC and explorer.
5. Complete reproducible-release qualification and independent protocol/cryptography review.
6. Grow through sponsor-funded engineering, developer tooling, integration services and later verifiable AI/compute applications.
7. Make the production and market-launch decision against measured evidence and the intended product scope.

The source tree is a curated public selection. Review specific files, reproduce commands in the relevant package, and use the [release manifest](docs/PUBLIC_RELEASE_MANIFEST_V02_2026-10-20.md) to identify the versioned public baseline. The public white paper and roadmap describe the engineering plan; they do not assert that future integrations are already operating on native Mainnet.
