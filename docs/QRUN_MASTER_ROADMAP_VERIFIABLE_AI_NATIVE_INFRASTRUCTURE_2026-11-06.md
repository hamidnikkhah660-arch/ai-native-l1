# QRun Master Roadmap: Verifiable AI-Native Blockchain Infrastructure

**Document ID:** QRUN-MASTER-ROADMAP-001  
**Version:** 1.0  
**Established:** 2026-11-06  
**Status:** Strategic product and engineering roadmap; not a declaration of launch readiness  
**Canonical project:** QRun Blockchain  
**Native asset:** QZXB

## 1. Purpose and continuity rule

This is the canonical, cross-session roadmap for QRun. It is intended to survive changes of browser, developer, AI assistant, workstation, and working branch. Every contributor should read this document before proposing architecture, changing priorities, writing public claims, or implementing a new feature.

The roadmap is a coverage map, not a claim that every listed capability exists today. A feature must never be described as implemented, secure, production-ready, post-quantum, deployed, or publicly available unless repository evidence and reproducible tests support that exact statement.

**Continuity rule:** preserve this document in Git history. Update it through reviewed commits and pull requests; do not silently replace historical decisions. When implementation status changes, update the relevant status and link the code, test, benchmark, threat model, deployment evidence, and review record.

## 2. Strategic identity and competitive thesis

### 2.1 Chosen identity

> **Verifiable AI-Native Blockchain Infrastructure**

QRun should aim to become infrastructure in which independent participants can verify not only transactions and state transitions, but also the permissions, provenance, and settlement evidence behind digital-asset and AI-agent activity.

This is the intended differentiator and investment thesis. It is a direction to engineer and prove, not a present-day marketing claim for features that have not shipped.

### 2.2 What is not a moat by itself

Proof of Work, low fees, speed, scalability, and quantum-related language are not exclusive advantages on their own. Other projects make similar claims. QRun must publish reproducible measurements, threat models, independent verification paths, and useful developer/user workflows rather than rely on adjectives or unsupported TPS, fee, security, or quantum claims.

### 2.3 The defensible combination to build

1. Independently verifiable ledger state, history, checkpoints, and recovery.
2. Open participation through independently operated nodes and transparent PoW rules.
3. A carefully governed cryptographic migration path, including hybrid and post-quantum components where actually integrated and tested.
4. Privacy-preserving proofs and selective disclosure, subject to explicit design and audit.
5. Programmable assets and settlement interfaces suitable for applications and real-world assets, with compliance controls left to application and jurisdictional design.
6. AI-agent payment authorization: cryptographically verifiable, bounded permissions for an agent to spend only within an approved budget, service scope, recipient/purpose policy, and validity period.
7. Developer tooling and evidence APIs that make these guarantees straightforward to integrate and independently inspect.

## 3. Ten-layer capability map (zero-to-one-hundred coverage)

The ten layers are the permanent top-level coverage taxonomy. New work should map to one or more layers; a feature that does not fit should trigger a documented roadmap review rather than disappear into an untracked side project.

### Layer 1 — Core Layer-1 protocol and network

**Scope:** canonical Genesis and Network ID; consensus and fork choice; PoW validation and difficulty adjustment; block/transaction rules; P2P discovery and transport; independent node operation; mempool; RPC; chain synchronization; persistent storage; deterministic state transitions; reorganization handling; resource limits; protocol versioning and upgrade rules.

**Proof required:** independent-node sync from a clean state; deterministic replay; multi-operator network tests; adversarial fork/reorg tests; restart and crash recovery; resource-exhaustion tests; protocol compatibility vectors; documented network parameters.

### Layer 2 — Security, cryptography, and post-quantum transition

**Scope:** key generation and custody; signatures and domain separation; transaction authorization; anti-replay; nonce/sequence rules; secure randomness; hybrid authentication; ML-DSA or other standardized PQC integration; P2P key exchange and transport migration; key rotation and recovery; dependency and supply-chain security; threat modeling; external audits and vulnerability response.

**Proof required:** per-path cryptographic inventory; positive and negative vectors; interoperability tests; signature-size and latency benchmarks; downgrade and replay tests; key lifecycle tests; independent cryptographic review. Do not call the whole network post-quantum while any security-critical path remains classical.

### Layer 3 — Privacy, confidentiality, and verifiable disclosure

**Scope:** privacy-preserving transactions where appropriate; zero-knowledge proof systems; selective disclosure; private identity/credential claims; confidential application metadata; proof verification interfaces; privacy-preserving auditability; data minimization and metadata leakage analysis.

**Proof required:** explicit privacy goals and leakage model; soundness/security assumptions; verifier vectors; performance and proof-size benchmarks; independent cryptographic review; documented limits. Privacy must not be implied merely because data is hashed, encrypted in transit, or stored off-chain.

### Layer 4 — Performance, scalability, and reliability

**Scope:** throughput and latency measurement; block propagation; parallel execution where deterministic; state/storage growth; pruning and archival modes; indexing; fee-market behavior; congestion handling; light-client paths; sync acceleration; availability and recovery objectives; observability and capacity planning.

**Proof required:** reproducible benchmark harnesses and hardware/configuration disclosure; sustained-load tests; tail latency; propagation and reorg measurements; state-growth projections; bottleneck analysis; fault-injection and recovery tests. Publish measured values, not targets as achievements.

### Layer 5 — Developer platform and programmability

**Scope:** Native Rust Library; stable APIs and SDKs; command-line tools; documentation and examples; deterministic contract execution; EVM compatibility and Solidity toolchain if maintained; token/asset standards; event/indexer interfaces; test frameworks; local dev environments; versioning and backwards compatibility.

**Proof required:** clean-machine build; reproducible examples; API compatibility tests; contract conformance tests; dependency audits; developer onboarding validation; explicit feature matrix for native and EVM paths.

### Layer 6 — QZXB monetary policy, issuance, and mining economy

**Scope:** Genesis allocation; maximum supply; issuance schedule; PoW rewards; halving and integer rounding; fee policy; treasury/reserve constraints; burn semantics; miner incentives; allocation vesting/lockups if any; transparent circulating-supply accounting; economic attack analysis.

**Current governing direction:** 10,000,000,000 QZXB gross maximum-supply target; 1B founder Genesis allocation target; up to 3B PoW mining/security ceiling; six additional 1B conditional category ceilings (community airdrop, exchange/market/liquidity partnerships, marketing partners, developers/security contributors, financial/strategic supporters, and protocol burn reserve). These ceilings are not automatically Genesis-credited; unused amounts remain unissued. Burn reserve is not burned until an irreversible on-chain burn is demonstrated. Keep gross issuance, circulating supply, restricted balances, and actual burns distinct.

**Proof required:** frozen consensus rules; independent monetary oracle; genesis snapshot; integer-exact emission vectors; boundary/overflow tests; independent supply reconciliation; wallet ownership proof for any allocation claim; transparent explorer accounting. The inherited halving schedule currently sums to 2,999,999,999.139264 QZXB, 0.860736 QZXB below the 3B ceiling; resolve or explicitly preserve this rounding remainder before consensus freeze. The corrected initial subsidy is 35,673,515,981 base units at 8 decimals = 356.73515981 QZXB per initial block. Do not revive the superseded 10B all-founder Genesis model.

### Layer 7 — Payments and merchant settlement

**Scope:** wallet-to-wallet payments; payment requests and invoices; payment links; merchant APIs; receipts; confirmations/finality semantics; fee estimation; micropayments; recurring/streaming payment primitives if justified; refunds/escrow patterns; cross-border settlement integrations; accounting and reconciliation tools.

**Proof required:** end-to-end wallet tests; correct signature and replay behavior; clear pending/accepted/included/finalized states; idempotent merchant APIs; failure/retry semantics; fee and confirmation measurements; security review. An ingress acknowledgement is not proof of block inclusion or finality.

### Layer 8 — DeFi, tokenization, and real-world assets

**Scope:** fungible and non-fungible assets; token issuance and lifecycle; AMM/liquidity infrastructure; lending and collateral primitives; escrow; bridges only with explicit trust assumptions; tokenized real-world assets; issuer attestations; transfer restrictions and compliance-aware application controls; custody and institutional integration.

**Proof required:** contract audits; asset-standard conformance; bridge threat models and limits; oracle design; issuer and redemption disclosures; legal/jurisdictional review by qualified parties; proof of reserves or backing where claimed. Do not imply tokenization creates legal ownership or guarantees redemption.

### Layer 9 — AI Agent Economy and bounded payment authorization

**Scope:** agent identity and key ownership; delegated authority; spend budgets; allowed services and recipients; purpose constraints; time windows and expiry; revocation; per-transaction and aggregate limits; human approval thresholds; agent-to-agent settlement; escrow; verifiable service/compute receipts; dispute evidence; policy-aware wallet and SDK interfaces.

**Priority differentiator: AI-agent payment authorization.** An agent should not receive unrestricted access to a user's wallet. The protocol/application authorization model should support a signed, auditable capability (or equivalent policy object) that binds at least:

- principal/owner and authorized agent key or identity;
- maximum amount per transaction and aggregate budget;
- asset/network and fee-spending limits;
- allowed service categories, contract methods, recipients, or destination allowlists;
- purpose/context constraints where they can be safely and deterministically represented;
- not-before and expiry timestamps or block heights;
- nonce/sequence and replay protection;
- revocation mechanism and policy version;
- optional human approval threshold and emergency freeze;
- receipt binding the authorization ID to the resulting transaction and settlement evidence.

**Required safety properties:** fail closed on missing/ambiguous policy; enforce aggregate spend atomically across concurrent requests; prevent replay and cross-chain/domain reuse; make revocation effective under a documented finality model; avoid trusting agent-supplied claims as proof; make authorization and settlement independently verifiable; protect privacy by minimizing exposed policy data. The design must specify race conditions, reorg behavior, fee accounting, key compromise, time-source assumptions, and recovery.

**Status:** strategic design priority only. This capability is not to be advertised as implemented until protocol semantics, threat model, reference implementation, adversarial tests, SDK integration, and independent review are complete.

### Layer 10 — Ecosystem, governance, operations, and adoption

**Scope:** block explorer; indexers; public node/operator program; monitoring and incident response; wallets across desktop/mobile/hardware where supported; documentation and learning paths; grants and contributor programs; governance and upgrade process; ecosystem partnerships; exchange/liquidity readiness; communications; legal/compliance review; bug bounty; release management and support.

**Proof required:** independently operated services; documented SLAs only where supportable; reproducible releases; incident playbooks; governance transparency; security disclosure process; user-tested onboarding; exchange-specific due diligence and actual market/liquidity evidence. No listing, trading-pair, price, or regulatory-approval claim without direct evidence.

## 4. Capability status vocabulary

Every feature in code, docs, website, and partner materials must use one of these evidence states:

- **Proposed:** concept only; no implementation commitment.
- **Designed:** architecture/specification and assumptions documented; implementation may not exist.
- **In progress:** code exists but acceptance criteria are incomplete.
- **Implemented:** code path exists; not necessarily independently verified or production-ready.
- **Tested:** named tests pass in a stated environment; scope and limitations must be shown.
- **Independently verified:** an independent operator/reviewer reproduced the stated property using documented artifacts.
- **Production deployed:** deployed on the intended production environment with operational evidence.
- **Released:** public users can access it under stated terms and support boundaries.

Never collapse these states into a single vague word such as “complete.” A passing CI job proves only the checks it actually ran.

## 5. Evidence and release discipline

For every material capability, maintain:

1. A specification and explicit non-goals.
2. Threat model and trust assumptions where security-relevant.
3. Acceptance criteria and negative/adversarial tests.
4. Reproducible commands, fixtures, and expected outputs.
5. Benchmark methodology and environment for performance claims.
6. Independent reproduction evidence where the claim warrants it.
7. Deployment/operations evidence before production claims.
8. Public wording aligned exactly with the strongest verified status.
9. A named owner, issue/PR, and next blocking dependency.

Do not infer mainnet readiness from local tests, loopback tests, CI, or private-overlay multi-host qualification. Public mainnet readiness requires independent public-network operators, clean-node synchronization, durable storage/recovery, consensus and fork-choice adversarial testing, calibrated production parameters, security review, operational monitoring, and an explicit release decision.

## 6. Immediate engineering priorities

The following sequence is intended to prevent attractive ecosystem work from outrunning the trust foundation:

1. Maintain the existing release gates: persistent storage/CAS, anti-rollback, checkpoint and full-history validation/recovery, fork/reorg safety, independent provider deployment, production PoW calibration, and multi-operator public sync.
2. Freeze and independently reconcile Genesis, QZXB allocation, issuance, subsidy, halving, rounding, and circulating-supply semantics before public issuance claims.
3. Build a cryptographic path inventory and staged PQ migration plan across wallet, transaction, P2P, storage receipts, and upgrades; explicitly identify classical components.
4. Reconcile and reuse the existing QVAAC grant/escrow prototype in PR #93 before any new agent-capability code. Complete the QVAAC-to-CP-0567 gap matrix, then design only the missing canonical ledger registry, owner-authorized register/revoke transitions, capability nonce, fee and aggregate spend accounting, state-root/snapshot commitment, and fork/reorg integration. Do not create a parallel grant/escrow module.
5. Establish privacy and proof-system requirements before selecting a ZK stack.
6. Publish reproducible performance baselines before optimizing or advertising speed/fees.
7. Expand developer tooling, payments, assets, and ecosystem integrations only against stable protocol interfaces and audited trust boundaries.

## 7. AI-agent authorization: proposed staged delivery

- **A0 — Research/spec:** threat model, attacker capabilities, policy semantics, identity/delegation model, revocation and finality assumptions.
- **A1 — Reference policy engine:** deterministic evaluation library and test vectors; no mainnet consensus change yet.
- **A2 — Wallet/SDK prototype:** user creates, inspects, limits, expires, and revokes an agent capability; safe simulation and explicit confirmation.
- **A3 — Transaction binding:** authorization identifier, nonce, asset, recipient/service scope, amount and fee limits bound to signed transaction data.
- **A4 — Atomic ledger enforcement:** consensus-level or securely enforced execution semantics, aggregate budget accounting, concurrency safety, reorg-safe state transitions.
- **A5 — Adversarial qualification:** replay, race, policy bypass, key compromise, expiry boundary, revocation race, cross-domain replay, malicious recipient, fee manipulation, reorg and recovery tests.
- **A6 — Independent review and staged release:** external security review, limited pilot, monitoring, incident controls, then broader availability only after release approval.

No stage is complete merely because a document or prototype exists.

## 8. Roadmap governance and change control

- This file is the canonical strategic coverage map; implementation truth remains in source code, tests, issues, PRs, and release evidence.
- Every new major capability gets a stable issue/spec reference and is mapped to one of the ten layers.
- Changes to consensus, Genesis, monetary policy, cryptographic trust, or authorization semantics require explicit decision records, migration plans, compatibility analysis, and independent vectors.
- Preserve superseded decisions as history and mark them superseded; do not erase them.
- Before each release, reconcile the roadmap against open blockers and actual evidence. Do not manufacture a percentage-complete score; report layer-by-layer status and blockers instead.
- Any AI assistant or developer joining the project should read this document and the latest release/status decision records, verify the current branch and CI state, and continue from repository evidence rather than relying on chat history.

## 9. Current scope boundary (2026-11-06)

This document establishes strategy and coverage, not a certification. Current branch evidence includes: (a) PR #132, whose current head contains the final Stage C2 commit `66b5349c2014c2cb7384fed67d81061d56d26039` and run [41556590085](https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/41556590085), demonstrating controlled two-host NetBird partition, reconnect, greater-work reorg, orphan-receipt removal, and durable reopen; and (b) PR #135, whose current head contains the qualified commit `30bd6a19da87a991b51feed4a7a76aebf1895bff` and run [42205440686](https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/42205440686), demonstrating the scoped QFP6/QAP1 remote admission/restart path with matching state root, height, and generation after restart. Both use a temporary GitHub-hosted runner over a private NetBird overlay; neither proves independently administered operators or native public-Internet convergence. These are branch-level candidate qualifications, not production deployment or mainnet approval. The whole network is not yet post-quantum: the current inventory includes classical Ed25519 transaction paths and X25519/ChaChaPoly Noise P2P, while ML-DSA-65 is present only in specific experimental/candidate or receipt-verification paths. AI-agent payment authorization is a future protocol investment, not a shipped capability. No verified QZXB/USDT public market or exchange listing is established by this roadmap.

---

**Canonical short identity:** QRun Blockchain — Verifiable AI-Native Blockchain Infrastructure.  
**Primary long-term differentiator to engineer:** verifiable, bounded AI-agent authorization and settlement, backed by independently verifiable ledger state, explicit cryptographic trust boundaries, and reproducible evidence.

## 10. Repository continuity and handoff control

The dated living continuation handoff is [`QRUN_CONTINUATION_CONTROL_PLANE_2026-11-06.md`](QRUN_CONTINUATION_CONTROL_PLANE_2026-11-06.md). Every new session, contributor, or AI assistant must read it, verify the live repository/PR/CI state, and update it alongside the relevant technical record when material status changes. The handoff is not live telemetry: exact branch heads, CI outcomes, PR dependencies, and deployment status must always be rechecked. If a conflict exists, source code, reproducible tests, and exact commit/run evidence outrank chat history and stale handoff text.
