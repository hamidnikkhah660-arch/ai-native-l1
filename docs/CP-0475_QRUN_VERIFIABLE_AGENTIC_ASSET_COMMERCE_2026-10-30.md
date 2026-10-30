# CP-0475 — QRun Verifiable Agentic Asset Commerce (QVAAC)

Date: 2026-10-30

Status: **Research-backed product architecture proposal with an isolated offline Rust state-machine candidate. Candidate differentiator only; no "first in the world" claim is approved.** It is not a production protocol, deployed service or authorized value-bearing system.

## 1. Product thesis

Build **QRun Verifiable Agentic Asset Commerce (QVAAC)** as an application and settlement capability that composes:
- QVAP (CP-0474): an evidence-linked passport and lifecycle for a tokenized asset.
- Agent identity and reputation that can interoperate with ERC-8004 and other agent registries.
- Delegated, scope-limited agent authority controlled by the human or organization that owns the wallet.
- Independent evidence checks and deterministic policy evaluation.
- Escrow / conditional settlement that can compose with ERC-8183 and other existing commerce standards.
- A signed, hash-linked receipt connecting the human's intent, agent authority, asset passport version, evidence claims, delivery, and final settlement.
- Privacy-preserving selective disclosure and a future post-quantum signature migration.

The user-facing experience is simple: a person or organization gives a bounded objective; agents find and evaluate assets; deterministic rules verify the evidence and authority; the parties complete transfer/fulfilment; and settlement occurs only under the pre-agreed conditions.

The key design principle is: **AI may plan and negotiate; cryptographic policy and independently verifiable evidence authorize the transaction.** An LLM is not a source of truth, custodian, auditor, oracle, legal authority, or wallet root key.

## 2. Problem and proposed experience

Example: an organization wants to acquire a quantity of a commodity or inventory lot, subject to quality, custody and delivery conditions.

1. A human creates a purchase intent with asset class, amount range, price ceiling, required evidence, seller constraints, expiry and maximum spend.
2. A local or hosted AI agent discovers available sellers and services through interoperable A2A / MCP-compatible endpoints.
3. The agent resolves the seller's agent identity and any portable reputation / validation data. This can use ERC-8004-compatible registries; QRun should not create an incompatible identity silo without a demonstrated reason.
4. The agent obtains the candidate QVAP passport and verifies its version, issuer, rights commitment, independent custody/quantity and inspection claims, freshness, revocations, liens, dispute status and redemption / transfer policy.
5. A deterministic policy engine checks that the requested asset and seller satisfy the human's mandate. The agent cannot expand the budget, change the permitted asset class, waive required evidence or extend its own authority.
6. The buyer and seller agree on a transaction contract: passport/version, quantity, price, delivery method, evaluator, required fulfilment proof, challenge window, timeout and refund rules.
7. Funds are escrowed or otherwise reserved under a suitable existing payment/escrow profile. The network only settles after the required independent proof and authorized state transitions are satisfied.
8. A QRun transaction receipt links all the relevant commitments and signatures. The receipt can update an agent's portable track record and support later dispute review.
9. The buyer can selectively disclose required evidence to an auditor or counterparty without publishing personal or commercially sensitive source documents to every network participant.

High-value or legally consequential purchases require explicit human approval at the configured checkpoint. Low-risk machine-to-machine purchases may run within narrowly defined budgets and allow-lists.

## 3. Candidate QRun differentiator

The proposed differentiator is the **single verifiable evidence chain from asset identity and rights, through agent authority and transaction execution, to fulfilment and settlement**.

Candidate features to evaluate:
- An asset passport is a first-class input to an agent commerce policy, not an optional URL or free-form metadata field.
- Evidence requirements are chosen by the asset-class policy profile; the policy is explicit and versioned.
- The buyer's delegated authority is bound to a specific intent, spend limit, asset constraints, counterparty constraints, expiry, and permitted operations.
- Transaction settlement records which exact passport version and evidence digests were checked, which authority grant was used, who evaluated fulfilment, and why funds were released or returned.
- Updates, revocations, liens and expiries have deterministic consequences for transfer, collateralization, delivery or redemption.
- Agents receive portable, evidence-derived performance receipts rather than relying only on self-reported ratings.
- The evidence model is designed for cryptographic algorithm agility and future PQ migration; PQ capability is not claimed until every relevant signing and channel layer is implemented and reviewed.

This is a hypothesis about a useful product combination, not proof that no one else has proposed or patented the same combination. A "first" claim requires a formal prior-art, patent, standards, academic and product review before public use.

## 4. Competitive and standards landscape — checked 2026-10-30

The individual building blocks already exist or are actively being specified:

### Agent identity, reputation and validation
- Ethereum ERC-8004 defines on-chain Identity, Reputation and Validation registries for agent discovery and trust. The current ethereum.org AI agents page says ERC-8004 is deployed on 16 networks. QRun should evaluate compatibility rather than rebrand agent registries as an invention. https://eips.ethereum.org/EIPS/eip-8004
- A2A and MCP address agent communication, task orchestration, tools and resource discovery. They should remain supported at the application boundary where practical. https://ethereum.org/ai-agents/

### Agent authorization and delegated authority
- OpenA2A AAP, Internet-Draft draft-fane-opena2a-aap-02 (30 September 2026), specifies agent identity assertion, scoped capability grants, cross-agent delegation, behavioural attestation, federation and revocation propagation. It is an individual Internet-Draft, not an IETF-approved standard. QRun should design an adapter / profile and avoid creating a competing generic agent-authorization framework. https://datatracker.ietf.org/doc/draft-fane-opena2a-aap/
- AAP's broker approach keeps credentials and backend secrets out of the agent/model context. QRun's wallet and transaction interface should follow the same secret-confinement principle. https://specs.opena2a.org/specs/aap

### Agent payments and commerce
- x402 is an open HTTP-native payment standard for programmatic and agent-facing internet resources. QRun should consider a compatible facilitator / settlement adapter, not claim that HTTP 402 agent payments are new. https://x402.org/
- ERC-8183 specifies agentic job escrow with evaluator approval and refund / completion states. Its state machine covers payment for completed work, but does not by itself establish title, custody or legal rights for a real-world asset. https://eips.ethereum.org/EIPS/eip-8183
- IETF Internet-Draft VCAP (September 2026) proposes agent commerce settlement tied to cryptographically verifiable work delivery and independent verification. It is an individual Internet-Draft, not an IETF standard. https://datatracker.ietf.org/doc/draft-stone-vcap/
- IETF Internet-Draft PACT (July 2026) proposes agent contracts, escrow, challenge windows and signed work attestations. It is an experimental individual submission, not an approved IETF standard. https://datatracker.ietf.org/doc/html/draft-laxsharma-pact-00

### Physical custody and RWA lifecycle
- NOANE publicly describes a hardware-anchored physical-asset custody layer for agentic commerce and cites US Patent 12,387,199 B2. Its stated focus includes object-bound proof, owner authorization and custody-state advancement. Avoid claiming QRun is the first agent-verifiable physical custody or agentic asset-transfer system. https://noane.io/ and https://noane.io/patent/
- IEEE P3274.03 is an active PAR for business requirements for RWA tokenization across registration, verification, issuance, trading, settlement, custody, transfer, redemption and retirement. This is a standards project, not itself proof that every implementation exists. https://standards.ieee.org/ieee/3274.03/12284/
- Other hardware-rooted agent identity and multi-agent attestation / provenance patent applications exist. The competitive landscape extends beyond blockchain products.

### Strategic conclusion
QRun must not claim to be the first chain for AI agents, agent payments, identity/reputation, escrow, RWA tokenization, physical custody, or post-quantum signatures in isolation. The available evidence already contradicts those broad claims.

A narrower integrated implementation may still be meaningfully differentiated. The product's merits must be established by its exact protocol semantics, open test vectors, working software, user adoption and independent comparison.

## 5. Trust boundaries and safety model

### Agent authority
- Root wallet key remains under the human / organizational owner, not in the LLM context.
- Each agent operates with a short-lived capability grant bound to a principal, intent digest, agent key, asset classes, permitted operations, counterparty allow-list, maximum amount, maximum cumulative spend, expiry and revocation epoch.
- Delegation only narrows authority; a child agent cannot increase scope, value, lifetime or permitted operations.
- Every transaction checks the current capability grant; cached or stale grants must fail closed.
- Separate capabilities should exist for discovery, quote requests, reservation, escrow funding, settlement approval, transfer, redemption and administration.
- Human approval is required when an action exceeds its configured threshold or crosses a high-risk boundary.

### Asset evidence
- The AI may summarize an evidence packet, but the deterministic verifier checks signatures, policy IDs, key status, issuer/custodian independence, timestamps, expiry, sequence, revocation and exact asset/passport IDs.
- No AI model output counts as a custody, quantity, inspection, title, insurance or delivery attestation.
- For physical goods, hardware sensors, signed inspectors, custodians and independent service providers remain separate trust domains. Cryptography authenticates their claims; it cannot make false claims true.
- Conflicts, expiry, legal disputes and evidence unavailability must produce explicit non-success states.

### Fulfilment and settlement
- Buyer, seller and evaluator roles are explicit.
- Seller cannot approve its own fulfilment.
- Single-oracle dependence must be disclosed and minimized according to asset risk.
- Escrow state transitions, refunds, challenge windows, timeouts, cancellation and partial fulfilment must be deterministic and bounded.
- No settlement based solely on an AI agent's natural-language statement that an item was delivered or a task was completed.

### Privacy
- Keep full personal identity, invoices, contracts, inspection photos and source evidence off-chain and access-controlled.
- Put only canonical commitments, bounded claims, status and references needed for verification on-chain.
- Add selective-disclosure / ZK proofs only after leakage, revocation and verifier assumptions are specified.
- Do not promise perfect privacy or non-traceability.

### Quantum migration
- Bind signature algorithm IDs and version to every agent grant, passport attestation, custody proof, transaction contract and receipt.
- Evaluate NIST FIPS 204 ML-DSA and FIPS 205 SLH-DSA and define crypto-agile key rotation and revocation.
- The current QRun Noise XX channel and wallet transaction signatures remain separate migration tracks. This proposal does not make the whole network quantum-resistant.

## 6. Protocol objects — candidate

A future QVAAC profile may define:

- AgentCapabilityGrant: principal, agent identity, intent commitment, permitted action set, asset policy, counterparties, max per-transaction and cumulative spend, expiry, sequence, revocation epoch, signature metadata.
- AssetEvidenceBundle: passport ID/version, required policy profile, issuer/custodian/inspector attestation digests, freshness window, lien/dispute/revocation status, evidence availability commitments.
- AssetTransactionIntent: buyer, seller, asset passport, exact quantity, price / currency, escrow terms, delivery criteria, evaluator, timeout, challenge window, policy profile and human approval reference.
- FulfilmentAttestation: authorized evaluator, delivery / service claim, evidence hash, location or time commitment where appropriate, sequence, expiry and signature metadata.
- QRunAgenticSettlementReceipt: intent digest, capability-grant digest, agent ID, passport/version digest, evidence-bundle digest, transaction/escrow ID, fulfilment digest, settlement/refund result, block reference and receipt version.

Encoding must be canonical, bounded, versioned, domain-separated and independently implementable. Do not store private source documents or prompts in public transaction payloads.

## 7. Minimum viable prototype

Start with a synthetic, zero-value warehouse-receipt purchase on a local test harness:

1. Create a synthetic QVAP passport for a fictional lot.
2. Use three distinct test keys for issuer, custodian and inspector.
3. Register two synthetic agents through an ERC-8004-shaped test adapter (no live funds or external registry dependency).
4. Create a human-owner capability grant with a low spend ceiling, allowed asset class and expiry.
5. Have a buyer agent request the passport and an evidence bundle.
6. Reject an expired, revoked, wrong-network, under-attested or encumbered asset.
7. Create a transaction intent, fund a simulated escrow and submit synthetic fulfilment.
8. Require a distinct evaluator to sign the fulfilment receipt.
9. Release the simulated amount only when the intent, grant, passport version and proof all match.
10. Test refund, timeout, changed passport version, replay, double-spend, delegated overreach and compromised-agent key.
11. Replay the same events on two independent test nodes and verify identical state / receipt roots.
12. Export a portable receipt that a second verifier can validate without trusting the original UI or AI model.

No real commodity, invoice, security, property, buyer funds, stablecoin reserves or redemption promise is involved.

### Acceptance gates
- An agent cannot spend outside its owner-approved grant.
- Delegated capabilities are strictly attenuating and revocable.
- A model prompt-injection or hallucinated claim cannot bypass deterministic checks.
- A seller cannot supply its own independent custody, inspection or evaluator key where role independence is required.
- No asset transfer or settlement succeeds against an expired, revoked, disputed or mismatched passport version.
- Settlement and refunds are replay-safe and deterministic.
- Every final receipt cryptographically commits to the exact evidence and authorization used.
- Two independent nodes compute the same state after replay / reorg.
- Sensitive personal and commercial source documents remain off-chain.
- Existing QRun Genesis, Network ID, QZXB supply, QFP5 consensus, current public-launch gates and wallet format remain unchanged.

## 8. "First in the world" claim policy

A first claim is not approved by a web search result, a draft paper, a prototype, a GitHub timestamp or a marketing tagline.

Before making any public first claim:
1. Define the exact claim in one sentence, with exact required properties.
2. Separate "first proposal", "first public specification", "first open-source implementation", "first production deployment", "first independently audited implementation" and "first at measured scale". These are different claims.
3. Search academic papers, standards, patents and patent applications, product documentation, code repositories and actual deployments across jurisdictions.
4. Review patent claims and ownership with qualified counsel if potential patent protection or freedom-to-operate matters. Public disclosure may affect protection options in some jurisdictions; get advice before publishing additional enabling detail.
5. Compare like-for-like, including what competitors truly implement rather than only what their marketing says.
6. Publish reproducible tests, code, vectors and limitations that independently verify the claimed distinction.
7. Use time-bounded language ("as of [date]") with citations and a correction process.

Public language approved at the proposal stage:
- "QRun is designing an evidence-linked, agentic asset-settlement architecture."
- "The proposed design combines asset passports, delegated agent authority, independent attestations and conditional settlement."
- "QRun is building a testable prototype; production readiness and novelty are not yet established."

Public language not approved yet:
- "World's first AI blockchain."
- "First autonomous asset chain."
- "First trustless RWA agent settlement."
- "Fully quantum-safe AI asset network."
- "Unhackable", "fully backed", "guaranteed liquidity" or any guaranteed QZXB price.

## 9. Delivery without blocking the current QRun launch

This work is an application-level product track, not a reason to delay or rewrite the current base chain.

Order:
1. Finish the existing QRun v0.5 release gates: independent external-CAS trust boundary, cross-host anti-rollback, full history/recovery validation, independent operators, adversarial sync and Mainnet gates.
2. Keep QVAP and QVAAC as isolated offline/testnet prototypes.
3. Integrate QVAP asset operations into canonical node transactions only after a separate reviewed protocol proposal, resource analysis, wire compatibility design and deterministic multi-node testing.
4. Implement agent identity adapters and capability grants off-chain / in an isolated contract or state-machine candidate.
5. Implement an escrow/settlement profile compatible with existing standards before considering a native replacement.
6. Add privacy and PQ layers only when their security assumptions and implementation status are independently verified.
7. Pilot one asset class with authorized issuers, custody, enforceable rights, verifiable evidence and operational redress.

Never change Genesis, Network ID, monetary supply, current fee-only QFP5 consensus or public-launch approval as a shortcut for QVAAC. QZXB market/liquidity work remains separately gated.

## 10. References

- ERC-8004 Trustless Agents: https://eips.ethereum.org/EIPS/eip-8004
- Ethereum agent ecosystem overview: https://ethereum.org/ai-agents/
- x402: https://x402.org/
- ERC-8183 Agentic Commerce: https://eips.ethereum.org/EIPS/eip-8183
- IETF VCAP Internet-Draft: https://datatracker.ietf.org/doc/draft-stone-vcap/
- IETF PACT Internet-Draft: https://datatracker.ietf.org/doc/html/draft-laxsharma-pact-00
- NOANE custody protocol: https://noane.io/
- NOANE patent information page: https://noane.io/patent/
- IEEE P3274.03 RWA Tokenization PAR: https://standards.ieee.org/ieee/3274.03/12284/
- NIST Post-Quantum Cryptography: https://csrc.nist.gov/Projects/post-quantum-cryptography

This document is a product / protocol design proposal, not an implemented feature, prior-art opinion, freedom-to-operate opinion, patentability opinion, legal classification, security audit or authorization to accept funds.


## 11. Offline Rust candidate implementation snapshot — 2026-10-30

A separate local/offline state-machine candidate now exists on branch feat/qrun-qvap-offline-prototype-20261030:

- src/native/pow_bench/src/qrun_verifiable_agentic_settlement_candidate.rs
- src/native/pow_bench/src/lib.rs exports the candidate module for tests only; no production node, canonical transaction decoder, QFP5 state transition or consensus call site was changed.
- The candidate composes the QVAP evidence model (CP-0474) with an intent-bound owner/agent capability grant, verified asset evidence bundle, escrow state machine, independent evaluator fulfilment proof, timeout/rejection refund and a signed/hash-linked receipt.

Candidate controls exercised:
- grant binds network, principal/owner, agent/key, exact intent digest, asset class, seller/counterparty, action scope, per-transaction and cumulative spend ceilings, not-before/expiry, sequence, revocation epoch and signature algorithm;
- evidence bundle binds the passport and evidence digests, asset ID/class, issuer/custodian/inspector identities/claim digests, freshness, status and transferable quantity;
- owner grant and evidence verifier are rechecked at escrow funding; evidence is rechecked again at final settlement;
- seller cannot act as independent evaluator;
- evaluator proof binds buyer, seller, evaluator, asset/passport/evidence, quantity and delivery evidence;
- accepted fulfilment settles; signed evaluator rejection refunds; timeout after the challenge window refunds;
- receipt and append-only event chain bind intent, grant, passport, evidence, fulfilment, amount and outcome.

Verification on Windows development checkout (2026-10-30):
- 16 focused QVAAC unit tests passed, including agent/principal/evaluator role separation, prevention of future-dated fulfilment approval, grant/evidence revocation rechecks at funding, and evidence revalidation at settlement.
- 15 focused QVAP unit tests passed.
- \`cargo +stable check --all-targets --locked --offline\` passed after both modules were present. Warnings are pre-existing in unrelated modules/binaries.
- \`git diff --check\` passed.
- The earlier full library suite had 962 passing tests and one failure in the unrelated Windows multi-process reward-pool file-writer test; the failing test passed when rerun alone. Do not claim the full suite is entirely green.

Limitations that remain:
- All grant, evidence and fulfilment verifiers are injected interfaces. The current test-only verifier is intentionally non-cryptographic and must never be used in production.
- No production AAP adapter, ERC-8004 registry adapter, x402 facilitator, persistent global grant sequence/revocation registry, production evaluator-key registry or real QVAP/ML-DSA attestation adapter is connected.
- No trusted clock, production escrow/payment asset, chain-state persistence, canonical node transaction, consensus/block/state-root integration, reorg persistence, wallet, explorer/API or independent-node deployment exists for these candidates.
- No real asset, buyer money, seller money, stablecoin reserve, redemption claim or public trading exists.
- This is a deterministic local research model only, not a complete security audit, legal opinion, proof of novelty, production feature or Mainnet readiness.

Immediate next steps:
1. Review QVAP/QVAAC models and trust boundaries independently.
2. Define canonical wire codecs and independent cross-language golden vectors for grant, evidence, intent, fulfilment and receipt.
3. Build production-grade adapters for AAP-compatible authorization, QVAP attestation verification and evaluator key registry, with revocation/sequence persistence and trusted-time policy.
4. Add a multi-process/two-node replay harness and tamper/reorg/rollback tests before any node integration.
5. Keep both candidates isolated from QFP5 and the current QRun public-launch gates until separate protocol approval, security review and release decision.
