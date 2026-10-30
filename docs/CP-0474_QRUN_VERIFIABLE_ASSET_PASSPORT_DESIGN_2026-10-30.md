# CP-0474 — QRun Verifiable Asset Passport (QVAP): Evidence-Linked Asset Lifecycle Design

Date: 2026-10-30

Status: **Strategic architecture proposal, based on repository inspection and competitive research.** This record is not an implemented protocol, legal title, proof that any off-chain asset exists, a security audit, or authorization to issue real assets or solicit funds.

## 1. Decision summary

Create a future product capability called **QRun Verifiable Asset Passport (QVAP)**.

QVAP is a standardized, cryptographically verifiable lifecycle record that binds an on-chain asset identifier to independently signed claims about an off-chain asset, the rights represented by the token, its issuer/custodian, and important lifecycle events.

QVAP should be the connective product layer for several future QRun domains:
- Real-world asset (RWA) tokenization.
- Inventory, warehouse receipts and supply-chain provenance.
- Receivables and invoice financing.
- Certificates, warranties, licenses and other verifiable claims.
- Reserve and collateral attestations.
- Tokenized funds or securities where an authorized issuer and an appropriate legal structure exist.
- AI-assisted asset monitoring, verification and machine-to-machine settlement.

The proposed differentiator is **not tokenization by itself**. It is the combination of:
1. Asset identity and rights commitments.
2. Multiple independently attributable attestations.
3. Versioned, revocable and time-bounded lifecycle evidence.
4. Privacy-preserving proofs and selective disclosure.
5. Quantum-resilient signature migration as the cryptographic foundation matures.
6. Native settlement and programmable asset operations.
7. Machine-readable interfaces for applications and tightly constrained AI agents.

Proposed positioning for this capability:

**QRun Verifiable Asset Passport — evidence-linked assets, verifiable lifecycle, programmable settlement.**

Do not describe QVAP or any of these capabilities as live until implementation, integration, deployment and independent validation are complete.

## 2. Why this is a better flagship than a list of buzzwords

The project already has candidate work for native asset creation, transfers, supply control, state commitments and a native AMM. Those primitives can become a substrate, but token creation alone does not establish that an underlying real-world asset exists, is legally represented, is unencumbered, is held by a custodian, or can be redeemed.

QVAP addresses the gap between:
- the **digital fact** that a token exists and has an on-chain owner; and
- the **external facts** about what the token represents, who is authorized to issue it, what rights attach to it, and what evidence currently supports those claims.

A well-designed passport is reusable across several asset classes. The base protocol need not understand the legal details of every asset. It should verify bounded, deterministic commitments and signatures; application-level asset policies should define the meaning and permitted transitions of each asset type.

This approach is a coherent product proposition rather than a promise to be the fastest, most private, most quantum-safe, and most universal chain all at once.

## 3. Competitive research and strategic implications

The market is already moving in each individual direction:
- Sui published a 6 August 2026 plan for adding NIST-standardized ML-DSA-65 account signatures and SLH-DSA-SHA2-128s for selected vault use cases. This means PQ account security is an active competitive area, not a defensible "only chain" claim. https://www.sui.io/blog/making-sui-quantum-ready
- Ethereum's post-quantum roadmap describes dedicated research and a multi-year migration programme; the page was updated 8 September 2026. https://ethereum.org/roadmap/security/quantum-resistance/
- TRM Labs' 9 September 2026 analysis says x402 is a widely used agent-payment rail, while cautioning that most measured volume is not actually agentic and much is not commerce. Therefore AI payments are worth exploring, but raw transaction counts do not prove real customer demand. https://www.trmlabs.com/trm-tech-blog/whos-actually-paying-measuring-ai-agent-payments-onchain
- Coinbase Institutional's 10 January 2026 research describes growing RWA tokenization activity and notes that many tokenized equity offerings are derivatives rather than direct share ownership. Asset representation and legal rights must therefore be made explicit. https://www.coinbase.com/institutional/research-insights/research/market-intelligence/major-trends-in-tokenization
- The IMF's June 2026 note frames tokenization across infrastructure, assets and services, and emphasizes market-structure, risk-management and policy complexities. https://www.elibrary.imf.org/view/journals/068/2026/006/article-A001-en.xml

Strategic conclusion:
- Do not claim QRun is the first or only post-quantum chain.
- Do not claim AI-agent payments are a unique invention.
- Do not claim that minting an RWA token proves ownership of the underlying object.
- Differentiate through a usable, evidence-linked asset lifecycle that connects attestations, privacy, security, settlement and developer APIs in one interoperable model.
- Make comparative claims only after a current, documented, like-for-like evaluation.

## 4. QVAP data model — proposal

The first version should be deliberately small, canonical and versioned. Avoid putting sensitive documents, personal details or large evidence blobs directly on-chain.

### 4.1 Passport header

A passport should bind, at minimum:
- Network ID and schema/version.
- Asset ID from the QRun native asset primitive.
- Asset class and policy profile identifier.
- Issuer identity / issuer key identifier.
- Commitment to the underlying asset's unique external reference.
- Commitment to the legal terms / rights document.
- Supply cap and representation ratio (for example, how many token units may represent one verified unit).
- Evidence policy identifier and minimum attestation requirements.
- Lifecycle status and monotonically versioned event sequence.

Jurisdiction or transfer policy may be referenced through a versioned application policy profile where needed. Do not make one country's rules universal base-layer consensus rules.

### 4.2 Attestation envelope

An attestation should be a signed, bounded claim with:
- Claim type (existence, custody, quantity, valuation, inspection, insurance, lien/encumbrance status, delivery, redemption status, etc.).
- Passport and asset identifier.
- Issuer / attestor role and signer key ID.
- Claim commitment and evidence-content hash.
- Issued-at and expiry times, with an explicit clock/trust policy.
- Sequence number and revocation/status reference.
- Signature algorithm/version and canonical signing domain.

High-value or high-risk asset classes may require independent multi-party attestations, threshold approval, or distinct issuer and custodian keys. A single issuer must not be able to impersonate an independent custodian or assessor.

### 4.3 Lifecycle events

Define an explicit, append-only event model. Candidate event types:
- Created
- IssuerVerified
- CustodyConfirmed
- AssetInspected
- InsuranceConfirmed
- EncumbranceRecorded
- EncumbranceReleased
- ValuationUpdated
- Issued
- TransferRestricted
- TransferEnabled
- RedemptionRequested
- Redeemed
- Matured
- Disputed
- Suspended
- Revoked
- Cancelled

A state transition must specify its authorized role, preconditions, evidence requirements, expiry/revocation behavior and effects on transferability, outstanding supply and redemption. A lifecycle event is not merely a string in metadata.

### 4.4 Evidence storage

On-chain:
- canonical passport identity and commitments;
- bounded attestation envelopes or their hashes;
- event sequence and current status commitment;
- token supply and policy-relevant state;
- references to verifiable evidence.

Off-chain:
- full contracts, invoices, inspection reports, personal identity documents, photographs and other large/sensitive material;
- encrypted or access-controlled evidence retrieval;
- redundant availability and independent backups for evidence required to exercise redemption.

The design must state the data-availability assumption. A hash proves that retrieved bytes match a commitment; it does not ensure those bytes remain retrievable.

## 5. Trust model and attack cases

QVAP must never imply that cryptography can make an untrue real-world claim true.

Threats and required controls:
- **Fake issuer:** verify issuer authority through a documented onboarding / registry process; bind its identity and key lifecycle.
- **Colluding issuer and custodian:** require independent parties for relevant asset classes, disclose residual collusion risk and use external audits where appropriate.
- **Double tokenization:** use stable external asset identifiers, issuer namespaces, uniqueness registries and conflict/dispute procedures. No single blockchain can guarantee global uniqueness where authoritative registries are absent or fragmented.
- **Over-issuance / fractionalization abuse:** enforce a deterministic supply cap against the accepted quantity and representation ratio; test overflow, rounding and subsequent asset-quantity reductions.
- **Expired or revoked attestation:** require expiry, revocation sequence and status checks at issuance, transfer, collateralization and redemption.
- **Oracle compromise:** separate data sources, signer roles and update policies; record provenance and dispute windows.
- **Custodian failure / lost asset:** document legal recovery, replacement and claims process; a token cannot magically restore a missing physical asset.
- **Insolvency, lien or title dispute:** freeze or restrict only according to the published asset-specific legal and policy framework; expose dispute status without pretending the chain resolves off-chain law.
- **Key compromise / quantum migration:** support algorithm/version changes, revocation and successor-key authorization with explicit recovery procedures.
- **Evidence unavailability:** redundant, independently administered evidence storage and clear user-visible degraded states.

The passport should report evidence status such as VERIFIED, STALE, DISPUTED, SUSPENDED or REDEEMED; these labels must be tied to deterministic acceptance rules and should not be interpreted as an absolute guarantee of asset quality.

## 6. Privacy, quantum security and interoperability

### Privacy

- Store hashes and commitments rather than personal data or full legal documents on the public ledger.
- Use selective disclosure so an owner can prove a particular fact without disclosing their entire identity or asset portfolio.
- Explore zero-knowledge proofs for holder eligibility, quantity bounds and transfer-policy satisfaction.
- Model metadata leakage and correlation risks; hiding the amount alone is not full privacy.
- Allow public, confidential and permissioned asset policies according to the asset class and holder choice where lawful.
- Never promise perfect anonymity or untraceability.

### Quantum-resilient signatures

- Inventory every signer: user, issuer, custodian, verifier, oracle, governance, service and release keys.
- Evaluate NIST FIPS 204 ML-DSA and FIPS 205 SLH-DSA for attestation and long-lived asset evidence.
- Use algorithm identifiers, domain separation, key validity intervals, revocation and crypto-agility.
- Evaluate hybrid signing during migration only with explicit downgrade resistance and independently tested transcript/claim binding.
- Existing QRun ML-DSA-65 CAS receipt support is a candidate component, not a proof that wallet transactions, every QVAP attestation or the full Noise channel is post-quantum.
- The present QRun Noise XX path uses classical X25519/ChaChaPoly; any PQ or hybrid channel is a separate future work item.

### Interoperability

- Define stable asset identifiers and portable passport proofs.
- Expose read APIs and verifiable evidence bundles for wallets, explorers, custodians and external applications.
- A cross-chain representation must carry the same underlying asset identity, supply lineage, restrictions and redemption policy; wrapped assets must not be mistaken for native assets.
- Prefer verified light-client or independently reviewed bridge designs over trusting a single operator's API.
- The issuer's canonical liability / redemption ledger must remain explicit. Cross-chain copies must not silently create additional claims on the same asset.

## 7. AI-agent and machine-to-machine extension

QVAP can become useful to AI agents without granting agents unrestricted financial authority.

Candidate workflow:
1. An agent requests a passport status or a specific evidence check.
2. It verifies signatures, schema, expiry, revocation and the required attestation threshold.
3. It can request a quote, inspection, delivery confirmation or redemption workflow.
4. It may pay for an API or verification request through a scoped, budget-limited wallet.
5. A human or authorized institution retains approval for high-value or legally consequential actions.

Controls:
- separate agent identity and owner identity;
- scoped session keys and allow-listed operations;
- spending caps, time windows, rate limits, revocation and emergency stop;
- explicit human consent for material asset transfer, issuance or redemption;
- machine-readable audit trails and evidence references;
- no AI-generated assertion may substitute for an authorized issuer, custodian, auditor or physical inspection.

The agent-payment integration must be interoperable with relevant existing payment standards where practical. Do not invent a proprietary payment rail unless it solves a demonstrated gap.

## 8. How this fits the existing QRun repository

The current checkout contains useful **candidate/test-only** building blocks:
- token_forge.rs: canonical asset definitions/IDs, fixed/capped/scheduled supply and issuer powers.
- asset_transactions.rs: bounded AOP1 create/mint/burn/freeze/transfer payloads.
- asset_state_candidate.rs and related commitment/store candidates: deterministic test state, snapshots and asset-state commitments.
- qzxb_amm_candidate.rs: a candidate constant-product AMM with bounded state, signed operations and a separate zero-value test-quote asset.

Their own module documentation explicitly says the asset-operation payloads are not yet embedded in TXN2 or LedgerState, the asset state is pre-activation, and the AMM is not part of canonical TXN4/QZB4 consensus or the production node decoder.

QVAP should **reuse and extend** these modules behind explicit versioned interfaces. Do not create a second competing token primitive or silently switch on candidate asset transitions in the live QRun v0.5 QFP5 fee-only path.

Before integration:
- map the existing asset IDs, metadata commitments, authorities, state roots, operation payloads and persistence formats;
- identify any incompatible historical candidate and choose one canonical successor only after review;
- specify exact byte formats, bounds, state transitions and independent golden vectors;
- keep RWA attestations separate from QZXB monetary supply and Genesis;
- require replay, reorg, rollback, snapshot and multi-node determinism tests.

## 9. Minimum viable demonstration — synthetic warehouse-receipt passport

The first demonstration should be a zero-value testnet simulation, not a real asset offering.

Scenario:
1. A synthetic warehouse operator creates an asset passport for a fictional lot of 1,000 units.
2. A simulated issuer signs the rights/quantity commitment.
3. A separate simulated custodian attests custody.
4. A separate simulated verifier attests inspection.
5. The test asset is issued only up to the configured represented quantity.
6. A test transfer occurs while all required evidence is current.
7. An encumbrance event temporarily restricts transfer.
8. A release event clears that restriction with the required signer evidence.
9. An attestation expires or is revoked; the passport changes to STALE or DISPUTED according to its policy and rejects the disallowed operation.
10. A synthetic redemption burns or retires the test tokens and records the terminal event.
11. Independent nodes replay the same event stream and produce the same passport/state root.

Acceptance tests:
- wrong issuer/custodian/verifier key rejected;
- issuer cannot satisfy the independent-custodian role using its own key;
- duplicate external-reference commitment is detected within the configured registry scope;
- issuance beyond verified quantity plus representation ratio rejected;
- stale, revoked or conflicting evidence rejected according to policy;
- event-sequence rollback and replay rejected;
- reorg restores the exact prior passport and balances;
- expired or missing off-chain evidence is visibly distinguishable from current verified evidence;
- large or malformed evidence payloads cannot create unbounded on-chain state;
- all nodes agree on canonical passport state after replay;
- no real asset, buyer funds, redemption promise or market liquidity is involved.

A successful synthetic demo proves only the simulated workflow and deterministic protocol implementation. It does not certify a real-world claim or legal right.

## 10. Rollout sequence

1. **Design freeze:** threat model, canonical passport schema, attestation roles, event state machine and data-availability assumptions.
2. **Offline codec/model:** canonical encoding, bounds, hash commitments, signature verification interface, expiry/revocation and model-based tests.
3. **Zero-value testnet demo:** synthetic warehouse-receipt lifecycle, explorer-readable status and reproducible independent-node replay.
4. **Privacy prototype:** selective disclosure and ZK proofs isolated from production until independently reviewed.
5. **PQ attestation migration:** use standardized signatures across issuer/custodian/verifier and document key lifecycle; separately qualify user transaction and peer-channel PQ migration.
6. **Single asset-class pilot:** only with an authorized issuer, enforceable legal terms, independent custody/inspection, asset evidence, redemption process and qualified jurisdiction-specific review.
7. **Broader ecosystem:** APIs, SDK, developer templates, additional asset classes, verified interoperability and constrained AI-agent workflows.
8. **Commercial scale:** production operators, monitoring, external review, real counterparties and sustainable demand; no token-price or liquidity promises.

Do not begin Phase 6 while the base QRun settlement, supply, wallet, recovery and independent-node launch gates are unresolved.

## 11. Product and trust metrics

QVAP should be measured by:
- fraction of passports with current independent attestations;
- time between evidence expiry/revocation and status update;
- number of independent attestor roles and key domains per asset class;
- detected duplicate-issuance/conflicting-claim attempts;
- correct rejection rate for expired, revoked or insufficient evidence;
- redemption completion and dispute-resolution evidence for any real pilot;
- on-chain bytes/state growth per passport and lifecycle event;
- verification latency and cost;
- proof size and privacy-leakage review;
- replay/reorg agreement across independently operated nodes.

Do not report an asset as "backed" based only on total token supply, issuer self-attestation or a hash stored on-chain.

## 12. Go/no-go and communications rules

**Allowed now:**
- Describe QVAP as a proposed product capability and published design.
- Build zero-value synthetic demonstrations.
- Reuse existing asset primitives in isolated test harnesses.
- Invite issuer, custodian, auditor and developer feedback without soliciting funds.

**Not allowed on current evidence:**
- Claim QVAP is already implemented or live.
- Claim that a token proves legal ownership of real estate, commodities, securities or invoices.
- Issue a real RWA token, sell fractional interests, accept investor money or promise redemption.
- Advertise "fully backed", "audited", "quantum-safe" or "institutional-grade" without the corresponding independent evidence.
- Treat a simulated oracle, issuer or custodian as a real attestation provider.
- Change QZXB Genesis, Network ID, supply or current fee-only consensus to accommodate the proposal.

## 13. Next engineering-session actions

1. Read CP-0473 and the root NEXT_AGENT_HANDOFF.md.
2. Verify current repository status, branch and PRs before making any changes.
3. Continue the existing base-chain technical line first: review PR90 then PR91 in dependency order, keep them Draft until reviewed, and qualify the independent CAS trust boundary and cross-host operation.
4. Treat QVAP as a separate design track. The next code task, after design review, is an offline bounded schema/state-machine prototype using existing Token Forge primitives; do not integrate it into QFP5 consensus yet.
5. Add only synthetic test data. Never ask for or store private keys, recovery phrases, personal identity data or actual asset documents in source control.
6. Do not provision paid cloud, legal, audit, custody or issuer services without explicit owner approval.

## 14. References

- Sui, "Making Sui Quantum Ready", 6 August 2026: https://www.sui.io/blog/making-sui-quantum-ready
- Ethereum, "Post-quantum cryptography on Ethereum", updated 8 September 2026: https://ethereum.org/roadmap/security/quantum-resistance/
- TRM Labs, "Who's Actually Paying? Measuring AI Agent Payments Onchain", 9 September 2026: https://www.trmlabs.com/trm-tech-blog/whos-actually-paying-measuring-ai-agent-payments-onchain
- Coinbase Institutional, "Major Trends in Tokenization", 10 January 2026: https://www.coinbase.com/institutional/research-insights/research/market-intelligence/major-trends-in-tokenization
- IMF, "The Rise of Tokenization", June 2026: https://www.elibrary.imf.org/view/journals/068/2026/006/article-A001-en.xml
- NIST Post-Quantum Cryptography: https://csrc.nist.gov/Projects/post-quantum-cryptography

This is an architecture proposal and research checkpoint. It does not certify the protocol, establish the truth of an external asset claim, authorize a securities offering or replace independent legal/security review.
