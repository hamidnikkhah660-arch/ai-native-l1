# CP-0473 — QRun Quantum-Resilient Multi-Domain Platform Vision and Roadmap

Date: 2026-10-30

Status: **Founder-approved strategic planning direction.** This document records the product ambition and sequencing discussed on 2026-10-30. It is a roadmap, not evidence that the proposed features are implemented, a security certification, a Mainnet approval, an asset-offering authorization, or a market-value promise.

## 1. Executive direction

QRun should become a modular Layer-1 settlement and application platform with a distinctive combination of:

1. Quantum-resilient cryptographic design and crypto-agility.
2. Verifiable privacy with carefully scoped selective disclosure.
3. Performance that is measured and independently reproducible.
4. Real-world asset (RWA) tokenization with explicit legal-rights, custody, attestation and lifecycle controls.
5. Programmable assets, payments, smart contracts and DeFi modules.
6. Interoperability and developer tooling.
7. Optional AI-agent and machine-to-machine payment infrastructure.

Proposed public positioning:

**QRun — Quantum-Resilient. Privacy-Preserving. Asset-Ready. Performance-Verified.**

Alternative descriptive line: **A quantum-resilient payment and asset-settlement network.**

The project must earn each adjective through implementation, measurements and review. Do not advertise the entire platform vision as an existing capability.

## 2. Product thesis and differentiation

Quantum resistance alone is not a sufficient differentiator. Low fees or high TPS alone are not durable differentiators either. QRun's proposed differentiation is their integration with an asset lifecycle model:

- Secure assets and transactions against anticipated quantum threats through a documented migration strategy.
- Protect user and business transaction data while allowing validity proofs and limited, consent-based disclosures.
- Support both native payments and regulated/tokenized asset workflows without forcing every asset to use the same privacy or permission model.
- Publish benchmark methodology, source revisions, hardware profiles and failure cases instead of unverified TPS slogans.
- Make core protocol rules deterministic and verifiable, while keeping application-specific policy in modular layers.

No claim is made that these features are unique to QRun or unavailable on other networks. The competitive claim must be about the measured quality and integration of the implementation.

## 3. Architecture principle: one secure core, modular product domains

Do not attempt to implement every blockchain category in one monolithic consensus/runtime change. Keep the base protocol narrow, deterministic and auditable. Add domain capabilities as versioned modules or application standards with explicit trust boundaries.

Proposed layers:

- **Layer 0 — cryptographic and identity foundation:** algorithm agility, key lifecycle, wallet identity, authenticated peer channels and software/release signing.
- **Layer 1 — settlement core:** canonical transaction rules, PoW/fork choice, state transition, supply rules, durable storage, history verification and network synchronization.
- **Layer 2 — execution and scaling:** smart-contract execution, batching, rollups or other scaling systems only when data availability, proof verification, sequencing and recovery assumptions are specified.
- **Asset and payment standards:** native QZXB transfers, multi-asset records, token issuance/burn/transfer, payment requests and asset lifecycle operations.
- **Privacy and proof services:** private transaction formats, ZK verification, selective disclosure and audit evidence.
- **Application ecosystem:** RWA, DeFi, exchanges/AMMs, identity/credentials, supply chain, gaming/digital collectibles, DAO tooling, merchant payments and AI-agent services.
- **Interoperability and data:** light clients, verified cross-chain messages, oracle attestations, indexers, explorer APIs and developer SDKs.

A module must not silently change Genesis, Network ID, monetary policy, consensus, or the security assumptions of an existing asset. Protocol upgrades need versioning, migration tests and independent-node compatibility.

## 4. Quantum-resilient security programme

The objective is not to claim that QRun is "quantum-proof" or impossible to break. The objective is to reduce known cryptographic exposure, use standardized post-quantum algorithms where appropriate, maintain algorithm agility, and demonstrate a documented threat model.

Required surfaces to inventory and qualify:

- User transaction signatures and wallet key derivation/recovery.
- Node identity and peer-channel key establishment.
- Consensus-related signatures, receipts and checkpoints.
- Bridge/light-client/oracle attestations.
- Contract account signatures and account abstraction.
- Release, update, governance and key-rotation signatures.
- Backup, recovery, hardware and service credentials.

Standards baseline to evaluate:

- NIST FIPS 203 / ML-KEM for key establishment.
- NIST FIPS 204 / ML-DSA for digital signatures.
- NIST FIPS 205 / SLH-DSA as a hash-based signature alternative.

A hybrid transition may be appropriate for selected surfaces, but it must be designed and benchmarked rather than added as an unreviewed combination. Define domain separation, downgrade protection, transcript binding, key rotation, algorithm identifiers, recovery behavior and test vectors. Record signature sizes, verification cost, handshake bytes, CPU and bandwidth impact.

**Current limitation:** the current QRun external-CAS candidate uses ML-DSA-65 to sign provider receipts. That is not evidence that wallet transaction signatures, consensus, or the full network are post-quantum. The current Noise XX transport uses classical X25519/ChaChaPoly and is not yet a post-quantum or hybrid channel. Do not describe the present network as fully quantum-resistant.

Acceptance evidence:
- Full cryptographic inventory and threat model.
- Independent known-answer and cross-implementation vectors.
- Wallet migration/rotation and recovery tests.
- Hybrid handshake tests including downgrade and transcript attacks.
- CPU, memory, bandwidth and signature-size benchmarks.
- Independent cryptographic review before production claims.

Reference standards: NIST CSRC, FIPS 203/204/205 — https://csrc.nist.gov/Projects/post-quantum-cryptography and https://csrc.nist.gov/News/2024/postquantum-cryptography-fips-approved

## 5. Verifiable privacy programme

Proposed objective: allow users and applications to keep selected transaction details confidential while the network still verifies monetary conservation, authorization, valid state transitions and absence of double spending.

Potential capabilities, subject to a separate cryptographic design:
- Confidential transfer amounts and, where practical, transaction relationships.
- Zero-knowledge proofs for validity and balance/conservation rules.
- Selective disclosure chosen by the asset holder for a specific transaction or fact.
- Auditable disclosures for an authorized business workflow without publishing a user's complete wallet history.
- Distinct privacy policies for public assets, confidential payments and permissioned/tokenized instruments.

Security requirements:
- Specify exactly what is hidden, from whom, and what metadata still leaks.
- Evaluate transparent proof systems such as STARK-style constructions where quantum assumptions matter; do not assume every ZK system is post-quantum.
- Measure proof generation time, verification time, proof size, memory and mobile-device feasibility.
- Include trusted setup, circuit soundness, parameter updates, key compromise and recovery assumptions in the threat model.
- Never promise untraceability, perfect anonymity or immunity from lawful investigation.
- Do not weaken the base ledger's supply/authorization checks to achieve privacy.

The initial design should allow privacy levels or asset policies rather than imposing a single privacy mode on every use case. This supports public transparency for some assets and confidentiality for other payment or business flows.

## 6. Real-world asset tokenization (RWA)

RWA tokenization is a strategic product domain and a potential source of real-world utility. It must be treated as a legal, operational and technical system, not merely as minting an NFT or token.

Candidate asset classes for research and later controlled pilots:
- Tokenized invoices and receivables.
- Supply-chain and warehouse receipts.
- Commodity or inventory claims.
- Real estate interests or legally structured participation rights.
- Bonds, fund units and other regulated financial instruments, only through an appropriate issuer and legal structure.
- Certificates, warranties, licenses and other verifiable non-financial claims.

Proposed RWA lifecycle:
1. Issuer onboarding and documented authority to represent the asset.
2. Legal instrument / contract that defines exactly what the token holder owns or can claim.
3. Asset identity, unique registry reference and double-issuance prevention.
4. Independent custody, ownership or existence attestation where relevant.
5. Valuation and status oracles with provenance, timestamps, expiry and dispute procedures.
6. Token mint, transfer, freeze/hold where legally required, redemption, burn and cancellation workflows.
7. Corporate actions such as coupon, dividend, maturity, split, recall or replacement where relevant.
8. Audit trail, selective disclosure, investor/holder eligibility and transfer restrictions appropriate to that asset and jurisdiction.
9. Operational contingency: issuer insolvency, custodian failure, oracle disagreement, lost keys, legal dispute and redemption failure.

Important boundary: **a blockchain token does not automatically create legal title to an off-chain asset.** The legal claim, issuer, custodian, registry, redemption route and applicable law must support the token's representation. A proof that tokens exist is not proof that an equivalent real-world asset exists or is unencumbered.

Build RWA support as optional asset-specific policy modules. The base chain should not require every user to identify themselves merely because some tokenized instruments require permissioned transfer rules. Conversely, do not represent regulated securities or other regulated assets as permissionless retail products without specialist review.

QRun is a **global-first product**. No country, region, founder residence or current hosting location is the default market or the architectural center of the protocol. The network should be designed for worldwide participation, localization and integration. The same core protocol and asset standards should remain portable across jurisdictions.

Regulatory and operational analysis must be **jurisdiction- and activity-specific**, not Europe-first or US-first. For any particular RWA issuance or service, map all relevant connections: issuer and its place of establishment; asset location and registry; custodian and its location; token holder/eligible investor location; offer, distribution and trading venue; operator and service-provider locations; and the places where custody, exchange, payment, brokerage or other regulated activities actually occur. A founder's present or future residence (including the United States, Iran, Europe or elsewhere) must not be used as a proxy for the product's global target market.

Design jurisdiction-specific controls as modular application/deployment policy profiles where technically and legally appropriate. Keep them outside base consensus wherever possible: asset-specific eligibility, transfer restrictions, disclosures, record retention, sanctions screening, tax reporting, consumer protections, data-protection duties and redemption procedures must not silently become universal rules for every QRun user or every token. Some issuers or services may be unable to operate in particular places; that should be handled transparently at the affected application, issuer or service boundary after qualified review, not by hard-coding one region's law into the global protocol.

The project should maintain a global regulatory research matrix covering, at minimum, the jurisdictions actually relevant to a proposed issuer, asset, custodian, venue, user group and service operator. The matrix should record the specific activity, asset classification, responsible party, applicable rules, licensing/registration status where relevant, restrictions, evidence owner and review date. Do not assume that the same token has the same legal classification in every jurisdiction. Do not assume that the use of a decentralized protocol removes obligations from an issuer, custodian, exchange, broker, payment provider or other identifiable service operator.

Initial RWA delivery should be a non-value-bearing testnet prototype with synthetic assets and simulated attestations. Do not tokenize a real person's property, securities, commodity or receivable, solicit funds, or promise redemption before issuer authority, enforceable legal terms, custody, independent asset evidence, oracle controls, audit, redemption and the relevant jurisdictional reviews are in place. This is a global safety rule, not an EU-only launch policy.

## 7. Performance and scalable execution

The ambition is elastic, workload-aware scalability with security preserved. **Literal infinite scalability is not physically or technically achievable**: compute, bandwidth, storage, data availability, verification and coordination are finite. Never advertise "infinite TPS".

Preferred design goal:
- Increase capacity through safe horizontal scaling and modular execution.
- Keep the settlement/consensus layer conservative and independently verifiable.
- Explore batching, parallel transaction execution, state access scheduling, compact propagation and proof-based execution layers.
- Consider rollups or sharding only after their data-availability, sequencing, censorship, withdrawal, fraud/validity proof and recovery assumptions are specified.
- Keep a simple, independently runnable node path for users who do not want to trust a centralized sequencer or hosted service.

Required benchmark methodology:
- Publish exact source commit, build flags, compiler, hardware, OS, network topology, block/consensus profile and test duration.
- Measure sustained valid transactions per second, not only synthetic signature checks or short bursts.
- Report p50/p95/p99 inclusion latency, confirmation/finality model, reorg rate, propagation delay and time-to-sync.
- Measure CPU, RAM, disk IOPS, bandwidth, state growth and fee paid per workload.
- Test at one, three and multiple independently administered hosts with realistic latency, loss, partitions and restart/reorg events.
- Separate native transfers, contract calls, ZK transactions and RWA policy checks; they have different costs.
- Publish failed runs and bottlenecks alongside successful results.

No TPS, block time, finality, fee or scalability number is approved by this vision document. Freeze performance targets only after a reproducible baseline and threat model exist. Do not improve benchmark throughput by weakening validation, proof-of-work, data availability or recovery.

## 8. Broader blockchain product domains

The platform can eventually support multiple domains without claiming every module is already production-ready:

| Domain | Candidate QRun capability | Main qualification risk |
|---|---|---|
| Native payments | QZXB transfers, payment requests, merchant APIs | Wallet safety, fees, finality and availability |
| Multi-asset issuance | Fungible and non-fungible asset standards | Supply integrity, permissions and issuer authority |
| RWA | Receivables, commodities, real-estate claims, regulated instruments | Legal rights, custody, oracles, redemption and regulation |
| Smart contracts | Deterministic VM and optional EVM compatibility | Consensus integration, gas determinism, state/reorg correctness |
| DeFi | AMM, swaps, lending, collateral and escrow | Oracle manipulation, liquidations, MEV and liquidity risk |
| Stable-value assets | Integration with independently backed, redeemable assets | Issuer, reserves, redemption, legal and depeg risk |
| Identity / credentials | Verifiable credentials and selective disclosure | Privacy, revocation, issuer trust and key recovery |
| Supply chain | Provenance, attestations and event tracking | Truthfulness of off-chain inputs |
| Gaming / digital items | Ownership and programmable digital goods | Throughput, UX, custody and contract safety |
| DAO / governance | Transparent proposals and delegated execution | Capture, governance attacks and upgrade safety |
| AI-agent economy | Machine-to-machine micropayments, budgets and scoped keys | Agent authorization, fraud limits and recoverability |
| Cross-chain interoperability | Light-client verified messages and asset movement | Bridge trust, replay, finality and failure containment |
| Developer infrastructure | SDKs, RPC, indexers, explorers, test harnesses | Reliability, versioning and public operations |

Do not build these all at once. Prioritize the modules with a real user, testable demand and a defensible safety model. A few integrated, reliable use cases are more valuable than a long feature checklist.

## 9. AI-native economy as an optional differentiator

Given QRun's AI-native research direction, evaluate an additional use case: autonomous software agents paying for APIs, compute, data, model inference and other digital services.

Candidate primitives:
- Machine-readable payment requests and receipts.
- Per-agent wallet or subaccount with strict spending limits.
- Scoped session keys that cannot transfer arbitrary balances or change owner settings.
- Budget windows, rate limits, revocation and emergency stop.
- Verifiable service-delivery receipts where practical.
- Micropayment/batched-settlement paths to avoid an on-chain transaction for every tiny interaction.

Do not market this as autonomous financial safety. Agents need narrow authority, human-configured spending policies, auditability and reliable revocation.

## 10. Delivery sequence and release discipline

### Phase 0 — finish and qualify the present QRun base
Immediate priority. Do not divert the release-critical work into speculative modules.
- Review the current PR90/PR91 stack and keep dependency order intact.
- Complete independent provider/anti-rollback design and actual remote deployment qualification; local files, KMS signatures and same-host tests are not a separate trust domain.
- Close canonical consensus, wallet, Genesis, supply, full-history/recovery and multi-host technical gaps according to CP-0443 and CP-0463–CP-0472.
- Keep the Mainnet source gate closed until the actual technical blockers are resolved.
- Preserve the exact Network ID, Genesis identity and 10B QZXB direction unless a separately reviewed protocol migration explicitly changes them.
- Keep any public market or liquidity activity separate from protocol-launch readiness.

### Phase 1 — cryptographic inventory and PQ migration design
- Map every cryptographic surface, including wallet and P2P channels.
- Design algorithm agility, key/version migration and hybrid channels.
- Benchmark ML-KEM/ML-DSA/SLH-DSA choices for the actual QRun traffic.
- Add test vectors and downgrade/interop tests before changing production formats.

### Phase 2 — reproducible performance baseline
- Build an open benchmark harness for valid end-to-end transactions.
- Measure real multi-host propagation, inclusion and confirmation behavior.
- Fix bottlenecks without changing consensus safety.
- Decide whether capacity needs batching, parallel execution or a distinct Layer-2/rollup path.

### Phase 3 — payment and developer experience
- Harden wallet backup/recovery, merchant payment request, transaction receipts and public read APIs.
- Publish SDKs, integration examples and operator documentation.
- Use real user workflows and measured reliability as acceptance criteria.

### Phase 4 — RWA and multi-asset testnet pilot
- Define an asset standard and issuer/custody/oracle interfaces.
- Use synthetic assets first.
- Design redemption, legal-rights mapping, transfer controls and audit disclosures.
- Obtain qualified legal and security review before any real-world asset or investor funds are involved.

### Phase 5 — privacy proof prototype
- Write a threat model and formal specification.
- Prototype proof generation/verification in isolation.
- Measure prover/verifier costs and metadata leakage.
- Add selective disclosure and recovery tests.
- Keep it off the production asset path until reviewed.

### Phase 6 — smart contracts, DeFi and interoperability
- Choose one deterministic execution strategy; do not promise native EVM until fully integrated and tested.
- Build AMM or swap capability only with authentic assets, auditable reserves and explicit slippage/MEV risks.
- Add bridge/light-client support only with a clear trust model and adversarial tests.
- Treat lending, stable-value assets and leveraged products as separate high-risk projects.

### Phase 7 — ecosystem and adoption
- Build real applications and recruit independent operators/developers.
- Publish reproducible performance, security and asset-attestation evidence.
- Pursue exchange access and liquidity as separate commercial activities; do not invent price, volume, listing or investor interest.

## 11. Measurable acceptance gates

Each proposed feature requires an evidence packet before it can be described as live:

- **Quantum-resilient:** full algorithm inventory, standardized algorithms where appropriate, hybrid/downgrade tests, migration plan, cross-implementation vectors and independent cryptographic review.
- **Private:** explicit leakage model, proof soundness review, double-spend/supply invariants, performance results and selective-disclosure tests.
- **High performance:** reproducible multi-host benchmarks with workload, p50/p95/p99, sustained TPS, resource consumption and failure cases.
- **Scalable:** documented bottleneck and trust model for each scaling layer, with data availability and recovery proof.
- **RWA-ready:** legal issuer authority, rights mapping, custody evidence, oracle controls, lifecycle, redemption, dispute and jurisdiction review for the specific asset.
- **Smart-contract-ready:** deterministic execution, gas/fee accounting, upgrade policy, reorg handling, fuzzing, formal/property tests and independent review.
- **DeFi-ready:** authentic liquidity, reserve accounting, oracle defenses, MEV/slippage disclosure, pause/recovery policy and adversarial tests.
- **AI-agent-ready:** constrained keys, spending policies, rate limits, revocation and failure recovery.

The website and public material must distinguish: implemented and deployed; implemented but candidate/test-only; designed but not implemented; and future research. Never use future-vision claims as current product claims.

## 12. Explicit non-goals and safety rules

- No "unhackable", "unbreakable", "impossible to trace", "infinite TPS" or guaranteed "quantum-proof" claims.
- No price target guarantee, guaranteed appreciation, guaranteed exchange listing or guaranteed liquidity.
- No real RWA offering or custody claim without a valid legal structure, authorized issuer, asset verification and redemption path.
- No forced identity collection for all base-layer users merely because selected RWA instruments need permissioned transfers.
- No hidden supply inflation, unreviewed Genesis/Network ID changes or bypass of the Mainnet release gate.
- No production feature promoted solely because unit tests pass; integration, deployment, adversarial testing and independent review are separate evidence.
- No owner-funded cloud, audit, legal, exchange or infrastructure spend without explicit owner approval.

## 13. Current engineering snapshot at the time this vision was recorded

Verified on 2026-10-30:
- Checkout branch: work/qrun-v05-cas-kms-signer-20261030.
- Working tree was clean and branch head was commit 7f736565ccddbf2eee5a9f17583848c23d4e0789.
- PR #90 is OPEN and Draft, base work/qrun-v05-cas-floor-20261030, head work/qrun-v05-cas-node-wiring-20261030, head SHA 627d901e94f630fa19e6dbfbc080e0bc8acf0c60. Both reported Rust validation workflows and matrix checks were successful. PR URL: https://github.com/hamidnikkhah660-arch/ai-native-l1/pull/90
- PR #91 is OPEN and Draft, based on PR #90's head branch work/qrun-v05-cas-node-wiring-20261030, head work/qrun-v05-cas-kms-signer-20261030, SHA 7f736565ccddbf2eee5a9f17583848c23d4e0789. Both reported Rust validation workflows and Ubuntu/Windows/macOS plus Windows loopback checks were successful. PR URL: https://github.com/hamidnikkhah660-arch/ai-native-l1/pull/91
- PRs are not merged. Preserve the stack order; review before changing Draft status or merging.
- Local Windows validation recorded for this source line: full all-target tests passed before the final provider CLI parser-hardening edit (951 library tests, 0 failed); after that final edit, focused external-CAS provider binary tests passed 5/5, and format, all-target check and diff check passed. Do not describe the full 951-test suite as rerun after the final small parser edit.
- Current provider is a single-host durable filesystem implementation. It is not cloud object storage and cannot resist a common rollback of provider and floor directories/host backups.
- The candidate AWS KMS ML-DSA-65 adapter is implemented but no real AWS KMS key/account signing test or remote deployment has been performed. AWS CLI was not installed and AWS config/credentials were not present in the checked host session.
- Node external-CAS integration is limited to the QFP5 fee-only profile. Current Noise XX is classical X25519/ChaChaPoly; a hybrid/PQ channel remains future work.
- The local process list check found no QRun provider or node daemon running at the time of the check.
- The source-level Mainnet release approval remains false. No public Mainnet, public mint, verified QZXB/USDT pool, exchange listing or price is established by these PRs.

Relevant project records:
- CP-0443 — permissionless-first protocol launch policy.
- CP-0463 — repository audit and release decision.
- CP-0464 — brand identity.
- CP-0465 — Mainnet/public-trading no-go.
- CP-0466 — zero-budget real-liquidity path.
- CP-0470 — durable external-CAS provider.
- CP-0471 — independent local floor store.
- CP-0472 — node external-CAS startup wiring.

## 14. Instructions for the next AI/engineering session

1. Read this CP-0473 document and the root NEXT_AGENT_HANDOFF.md first.
2. Verify current git branch, working tree, remote refs, PR #90/#91 state and exact-head CI. Never assume this snapshot is still current.
3. Preserve PR90 → PR91 dependency order. Do not force-push, rebase, merge, convert Draft to Ready, or enable Mainnet without a reviewable reason and the owner's authorization where required.
4. Continue from the actual code state. The immediate technical focus is the independent trust/anti-rollback boundary and real multi-host verification, not premature privacy/RWA feature coding.
5. Treat PQ migration, privacy, RWA, scale, EVM/DeFi and AI-agent payments as the strategic roadmap. Start with architecture/threat-model documents and isolated prototypes; do not inject them into the live consensus/Genesis path prematurely.
6. Never request, display or commit wallet recovery phrases, private keys, cloud credentials, API secrets or unredacted personal information.
7. Before any cloud provisioning, legal/audit engagement, paid infrastructure, asset issuance or liquidity deployment, state the proposed cost/risk and obtain explicit authorization.
8. Keep public statements aligned with measured reality; do not promise the target QZXB price of USD 0.01–0.90 or imply that it can be guaranteed.

This record is a founder-directed product vision and an engineering handoff. It does not certify safety, authorize a sale or override versioned protocol decisions.
