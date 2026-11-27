> **Historical-document notice (2026-11-27):** This v0.2/v0.3 white-paper snapshot is retained for engineering history. Its original 10B/3B-mining tokenomics and v0.4 allocation references are superseded by CP-0651 and CP-0651-A v1.0. Read the current candidate economics at `economics.html` and the [CP-0651-A allocation/release policy](CP-0651A_QZXB_ALLOCATION_AND_RELEASE_POLICY_V1_2026-11-27.md). Neither document authorizes a live Mainnet, issuance, or real-value transfer.

# QuantumZXB - AI-Native L1 Native Coin and Ecosystem White Paper
## Version 0.2 - Public Technical Engineering White Paper

Date: 20 October 2026
Document status: Public engineering white paper describing architecture, test evidence and integration roadmap. It is not a frozen production protocol specification or a claim that native Mainnet is active.

## Abstract

QuantumZXB is the current working identity for an independently developed native Layer-1 project. Its engineering programme combines a Rust-based native ledger and proof-of-work research, deterministic state and chain-selection candidates, authenticated peer transport, durable-storage and recovery experiments, a post-quantum signature research path, and a separate EVM-compatibility laboratory for smart-contract execution.

The native asset is a coin of its own network, distinct from the Ethereum Sepolia ERC-20 experiment. The current CP-0651 candidate policy defines a 7,000,000,000-QZXB gross accounting ceiling: a 1B owner Genesis allocation plus six additional 1B accounting labels. Those six labels are non-circulating ceilings, not issued balances, transferable tokens, or mint authority. Block subsidy is zero and candidate producer compensation is canonical transaction fees only. CP-0651-A v1.0 proposes that 100M of the founder allocation may become transferable only at an authorized Mainnet launch, with the remaining 900M released linearly over 24 months from launch and no additional cliff. These remain candidate rules pending implementation, testing and authorization; no live Mainnet balance or transfer is implied.

The project has substantial code and testing infrastructure. The maintainer's complete working checkout passed a full Rust regression with 736 library tests and no failures; the locked/offline all-target build check and format check also passed. The full working checkout is larger than this curated public tree, so this test count is tied to that review scope. The separate EVM launch-asset package's local test suite also passed. These are reproducible engineering signals, not substitutes for production-network qualification or an independent protocol audit.

## 1. Project vision

The long-term goal is to build an open, CPU-accessible, verifiable network in which native coin transfers and fees, programmable applications, secure identities, machine-to-machine coordination and verified AI/compute services can share one economic environment. The design prioritizes deterministic validation, a transparent supply ceiling, bounded resource use, recoverable state and cryptographic agility.

The name "AI-Native" expresses the project's intended product direction. It does not mean a production inference marketplace, model-training market or proof-of-useful-AI reward mechanism is already running. Those capabilities require their own interfaces, verification rules, economics and operational testing.

## 2. Native coin identity and supply design

- **Network/project identity:** QuantumZXB is the current working brand.
- **Proposed native coin ticker:** QZXB; it remains a proposal rather than a frozen production network identifier or verified listing symbol.
- **Current candidate accounting ceiling (CP-0651):** 7,000,000,000 QZXB gross accounting units.
- **Owner Genesis allocation:** 1,000,000,000 QZXB.
- **Additional labels:** six conditional 1B accounting ceilings for developers/network security, community/public distribution, exchange/platform integration, marketing/growth, financial/strategic supporters and protocol burn reserve. They are not Genesis balances or issued/transferable tokens.
- **Producer compensation:** zero block subsidy; candidate producers receive canonical transaction fees only.
- **Founder release candidate (CP-0651-A v1.0):** 100M may become transferable only at authorized Mainnet launch; 900M released linearly over 24 months from launch, with no additional cliff. Implementation, tests and authorization remain prerequisites.

The older 10B/3B-mining and v0.4 bucket model is historical and superseded. The 7B figure is a gross accounting ceiling, not circulating supply or a live token balance. CP-0651 and CP-0651-A remain candidate policy documents; they do not activate issuance, minting, transferability, a market or Mainnet.

### 2.1 Owner, sponsor and contributor allocation framework

Under CP-0651-A v1.0, the owner allocation is a 1B accounting allocation within the 7B gross ceiling. The six other 1B labels are conditional accounting ceilings with purpose-specific release controls. No sponsor is confirmed and no recipient entitlement or live balance is created by the policy. Awards require written terms, verified milestones, account checks and the applicable authorization. Coin allocation is not, by itself, company equity, revenue share, a redemption right or a promise of financial return. See `CP-0651A_QZXB_ALLOCATION_AND_RELEASE_POLICY_V1_2026-11-27.md`.

## 3. Architecture overview

### 3.1 Native ledger and consensus research

The Rust native codebase contains candidate components for proof-of-work checks, difficulty-adjustment experiments, deterministic block/state transitions, transaction authorization, fork-choice/reorganisation, state roots, snapshots, durable stores and archive synchronisation. Protocol work also includes replay, wrong-network rejection, bounded parsing, mutation testing and restart/crash scenarios.

The production protocol still needs one canonical, versioned monetary/Genesis profile connected end-to-end across block production, admission/import, fork choice/reorg, storage, restart/replay, archive sync and state-root calculations. Several newer monetary and V4 paths are deliberately isolated candidates rather than all being active in the default runtime. The design must freeze which profile is canonical and how upgrades/migrations occur; combining separate candidates implicitly would weaken determinism rather than improve it.

### 3.2 Networking and node operations

The repository includes authenticated transport, Noise-based peer-connection candidates, pinned peer identities, bounded ingress/queue accounting, archive transfer limits and loopback/private devnet harnesses. Earlier peer-to-peer design exploration borrowed concepts from Bitcoin-style peer gossip; that historical design context is not, by itself, the final QRun networking specification. Newer Q6PD work separately implements signed peer-discovery records, address/session management and NAT-friendly outbound persistent-session candidates (including the CP-0848/CP-0849 review lineage). These newer components must be evaluated on their own source and interoperability evidence rather than being conflated with the earlier Bitcoin-inspired exploration. The CP-0849 Joiner completed local pinned-Noise/Q6PD pull-gossip/history-sync tests, but persistent heartbeat interoperability against the then-running CP-0843 Seed was not passed; independent multi-operator mesh qualification remains open. Classical transport includes X25519/ChaChaPoly and is not post-quantum.

A successful local two-node or loopback test is evidence for the specific profile tested, not evidence that a public production network is active.

### 3.3 State commitments and recoverable persistence

The codebase contains flat, adaptive, bucketed and incremental state-commitment candidates, canonical snapshot codecs, state-root vectors, durable-store models, fork/reorg handling and multiple process-failure tests. These experiments target reproducible state reconstruction and bounded state/proof processing.

The anti-rollback work also includes signed receipt and compare-and-swap (CAS) client models. The remaining production step is an independently administered monotonic trust provider integrated into the canonical state-commit lifecycle, with out-of-band trust provisioning, independent operator control, multi-host and device/storage-failure qualification. The present local model demonstrates fail-closed behaviours, but joint restoration of the local manifest/journal and model anchor can reproduce a documented rollback gap; a model alone is not an independent production trust boundary.

## 4. Smart contracts and programmable execution

### 4.1 What exists

The project contains a standalone EVM feasibility lab using pinned `revm 19.5.0`. Its recorded test programme includes raw-bytecode calls, contract creation, runtime bytecode, storage reads/writes, REVERT/HALT behaviour, gas accounting, nested calls, CREATE edge cases and cross-engine comparisons against local Ganache/EthereumJS fixtures. A typed-transaction parser and execution/receipt adapter models also exist in the isolated lab, with strict encoding/state-diff tests.

The project separately has a fixed-supply Solidity ERC-20 candidate and a browser wallet/deployment console. The QX candidate was deployed to Ethereum Sepolia at:

- Contract: `0x7f144fe3dcfbe36ed17ef6c60ea3913179dcf4af`
- Deployment transaction: `0x8828f2e6aef3d7b6ddab583a41e2322a62c8961adf62188634dbcd3e634b0814`
- Network: Ethereum Sepolia, chain ID 11155111.
- Contract name/symbol: `Qanvoryx Launch Candidate` / `QX`.

This is an EVM testnet experiment and a separate asset. It is not the QuantumZXB native coin, not a native-L1 contract deployment, and not a production market. Its 10B supply and 4B/3B/3B balances are transferable; the contract does not enforce a lock or vesting schedule.

### 4.2 Native smart-contract roadmap

The native Rust node does **not** currently link the standalone `contracts/vm-lab` EVM engine as a canonical state-transition dependency. The EVM adapter lab does not yet define and integrate canonical EVM transaction bytes/signature admission, the production fork/gas schedule, deterministic EVM account/code/storage commitments in the native state root, receipts/logs and receipts root, durable commit/reorg recovery, production Ethereum JSON-RPC, or cross-node execution agreement in the canonical node.

The strategic direction is EVM-compatible application execution because Solidity and existing development tools can lower adoption friction. The order of work is to freeze the VM fork and resource/gas profile, define native-coin funding/address/nonce rules, integrate account/code/storage state and receipt/state commitments, add the canonical RPC surface, cross-check independent clients and then deploy a sample application on a controlled zero-value native devnet. Until these acceptance steps pass, the EVM lab is evidence and preparation for the native smart-contract platform-not a claim that the platform is already running on native Mainnet.

## 5. Post-quantum and hybrid-signature research

### 5.1 Real implementation and tests

The repository pins `libcrux-ml-dsa` and has a real ML-DSA-65 verification adapter based on FIPS 204 semantics for a 32-byte domain-separated signing digest with an empty ML-DSA context. The selected C2SP/Wycheproof fixture contains 53 hash-pinned test cases: 48 expected-valid signatures and 5 expected-invalid signatures. The suite checks valid signatures and rejects tampered signatures, wrong digests and invalid public keys. Additional local artefacts include ML-DSA ACVP-format testing, a C-based differential harness/provenance inventory and candidate key/identity-policy migration tests.

The V4 hybrid-identity/transaction candidate carries an Ed25519 public key and an ML-DSA-65 public key, and uses a combined signature. The opt-in candidate node includes real ML-DSA verification paths in research/test flows and tests wrong-signature rejection. This is more than naming a future algorithm: it is real verification code exercised by selected external vectors.

### 5.2 Scope boundary

The hybrid transaction/identity and FAT1 verification paths remain candidates, with runtime activation, account-migration rules, default transaction-admission integration and independent deployment review still required. The standard peer transport is still classical, and the existence of ML-DSA code does not make every wallet, key exchange, network handshake, block signature and state transition post-quantum secure.

The correct security objective is a controlled transition: explicit algorithm and context binding, no silent downgrade after a policy lock, key rotation and revocation, cross-implementation vectors, dependency/provenance review, adversarial and side-channel testing, and an independent security review before making end-to-end post-quantum claims.

## 6. Cryptographic and operational security approach

The repository's security programme includes exact wire-format parsing, length/resource limits, network/domain binding, replay protection, signature verification, bounded queues, transaction admission models, store validation, fork/reorg handling, checksum-manifest and restart tests, independent Python/vector oracles, and selected differential tests. Recent local verification also ran the entire native Rust all-target test programme and the separate EVM launch-asset test suite.

The remaining security engineering sequence is to integrate the selected monetary and signature profile into the canonical runtime, connect real independent anti-rollback trust, run multi-node and storage-failure qualification, review key management and deployment operations, commission independent protocol/cryptography review, and publish the exact release commit, test evidence and known-scope statement. No single unit-test count or library-level proof should be described as a complete network audit.

## 7. Ecosystem and utility direction

The intended ecosystem may include:

- a native coin and fee market under published monetary rules;
- native wallets, RPC, explorer/indexer and developer SDKs;
- EVM-compatible contracts and familiar Solidity tooling after canonical integration;
- identity/attestation and secure agent-to-agent interactions;
- AI/compute service coordination, provider reputation and verifiable job accounting when independently specified;
- grants, open-source contributions, ecosystem applications and third-party integrations.

The present release includes research assets and a separate EVM testnet demonstrator. It does not yet provide a native-production wallet/explorer, production RPC, live AI inference marketplace or production useful-AI-work rewards. These form the ordered build roadmap instead of being implied by the project name.

## 8. Token economics, value and market integrity

The 10B design cap is not a market quotation. No price, fully diluted valuation, liquidity, revenue, exchange listing or financial return is guaranteed. An illustrative price multiplied by maximum supply is arithmetic, not an executable market value. Genuine liquidity requires actual quote assets and real transactions; the native coin cannot create external collateral by being held against itself.

The project prohibits fabricated volume, wash trading, misleading supply figures, counterfeit market data and guaranteed-return statements. Native circulating supply must be derived consistently from the canonical Genesis and supply rules, not estimated from an isolated token contract or a spreadsheet. The native L1 coin and the Sepolia QX ERC-20 must always be presented as different assets.

## 9. Governance and release engineering

The project's release workflow should publish versioned protocol decisions and reproducible evidence. Consensus changes require a written specification, deterministic vectors, multi-node test, migration and rollback handling, independent review of critical transitions and an explicit activation rule. Founder ownership of coins does not imply a hidden minting or consensus override.

A production release should ship a source commit and checksums, reproducible build instructions, dependency/license inventory, network and Genesis identity, monitoring and incident runbooks, wallet/explorer/RPC compatibility and independent security-review evidence. Every public claim should map to a specific source file, test, deployment record or release artifact.

## 10. Phased roadmap

1. **Monetary and Genesis freeze:** select one canonical runtime/profile; implement the CP-0651 7B gross accounting ceiling, 1B owner Genesis allocation, six conditional non-circulating 1B labels and zero-subsidy/fee-only producer model; implement and test the CP-0651-A release controls across block production/import, fork choice, persistence, replay and snapshots. Historical 10B/3B-mining/v0.4 schedules must not be reactivated.
2. **Hybrid identity and recovery:** define the canonical signature/authentication suite and migration boundary; integrate ML-DSA into the selected native transaction path; close independent monotonic trust and crash/recovery requirements.
3. **Native EVM execution:** ratify fork/gas rules, native account/fee/funding mapping, EVM state representation, receipts/logs/roots, canonical node storage and RPC; pass cross-client end-to-end deployment tests.
4. **Zero-value public testnet:** operate multiple independent nodes with a frozen profile, external participants, wallet/RPC/explorer, sync and upgrade rehearsals, real workload measurements and an incident-response programme.
5. **Independent qualification:** external protocol/cryptography/security review, reproducible release/build and dependency/provenance review, remediation of high-impact findings.
6. **Ecosystem and sustainable operations:** external developer applications, transparent contributor/sponsor agreements, technical support/integration services, developer tools, and-after its verification design is ready-AI/compute coordination with measured provider work.
7. **Production launch decision:** freeze the final network identity and genesis, publish protocol and supply data, verify operations and key recovery, and make the market/distribution decision based on the actual product and intended users.

Each stage has its own evidence. Reaching the EVM laboratory stage, passing tests or publishing code does not by itself constitute a production Mainnet.

## Appendix A - current engineering verification for this review

On the owner's connected local working checkout (local branch `master`, latest existing commit CP-0340 before this documentation refresh):

- `cargo fmt --all -- --check`: PASS.
- `cargo check --all-targets --locked --offline`: exit 0.
- `cargo test --all-targets --locked --offline`: exit 0; 736/736 library tests passed and the remaining binary/integration targets completed without failure.
- `npm test` in `contracts/launch-asset`: exit 0; fixed-supply contract, wallet-console and loopback-wallet-server suites passed.
- The main native Cargo package pins Rust 1.82-compatible dependencies. The isolated EVM lab has a separate toolchain requirement documented as Rust/Cargo 1.99; that VM-lab suite was not rerun during this review because the connected checkout exposed Rust/Cargo 1.82. Existing VM-lab checkpoints document prior local differential results.
- The project repository was clean at the start of the review. The newer CP-0340/CP-0339 documentation exists only in the local checkout and the public GitHub release remains the earlier curated source/documentation release; they have not been published by this review.

This appendix records the specific maintainer-checkout regression at the stated date. It is not an external audit or a performance guarantee.
