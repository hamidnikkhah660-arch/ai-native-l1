# CP-0651-B — Owner-Directed 10B QZXB Supply and Conditional Allocation Amendment

**Policy ID:** CP-0651-B  
**Date:** 2026-11-27  
**Status:** Owner-directed amendment draft for review. It is not yet the active canonical monetary profile, a production Genesis, an issuance transaction, a listing commitment, or authorization to transfer value.  
**Parent:** CP-0651 and its appendix CP-0651-A  
**Intended effect:** Supersede conflicting economic parameters in CP-0651-A only after this amendment is reviewed, accepted, and reconciled with the canonical consensus/Genesis implementation and all affected public documents.

## 1. Owner direction and scope

This amendment records the owner's current direction for the QZXB economic model. It corrects the seven-billion accounting ceiling and the removal of the mining envelope stated in CP-0651-A. It preserves CP-0651-A, its pull request, reviews, commits, and historical rationale as immutable project history.

The intended total accounting ceiling is **10,000,000,000 QZXB**, with exactly three top-level components:

1. **3,000,000,000 QZXB — Mining and network security envelope.**
2. **1,000,000,000 QZXB — Owner allocation.**
3. **6,000,000,000 QZXB — Owner-controlled allocation-label pool**, comprising five one-billion purpose allocations and one separate one-billion burn reserve.

No additional allocation may be added above the ten-billion ceiling. The arithmetic is inclusive: 3B + 1B + 6B = 10B.

This document is a policy specification. It does not create tokens, balances, entitlements, cash, liquidity, sponsor commitments, listing commitments, or mint authority. An accounting label is not an issued or transferable balance. No value-bearing Mainnet or live market is claimed.

## 2. Supply schedule

| Component | Ceiling | Treatment |
|---|---:|---|
| Mining and network security | 3,000,000,000 | Reserved for deterministic, consensus-enforced mining/network-security issuance after the mining profile passes its release gates |
| Owner allocation | 1,000,000,000 | Owner allocation; no additional project-imposed time vesting or protocol lock under this direction |
| Developers and security contributors | 1,000,000,000 | Conditional purpose allocation from the owner-controlled six-billion pool |
| Community and public distribution | 1,000,000,000 | Conditional purpose allocation from the owner-controlled six-billion pool |
| Exchanges and platform integration | 1,000,000,000 | Conditional purpose allocation from the owner-controlled six-billion pool |
| Marketing and growth | 1,000,000,000 | Conditional purpose allocation from the owner-controlled six-billion pool |
| Financial and strategic supporters/investors | 1,000,000,000 | Conditional purpose allocation from the owner-controlled six-billion pool |
| Protocol burn reserve | 1,000,000,000 | Separate burn-designation ceiling within the six-billion pool; not burned until an irreversible, verifiable burn occurs |
| **Total** | **10,000,000,000** | **Hard gross accounting ceiling; no allocation above it** |

The six-billion pool is an owner-controlled accounting envelope. The five purpose allocations and the burn reserve are separate accounting labels inside that envelope, not six-billion of additional supply on top of the ten-billion cap. The owner retains discretion over the timing and scope of prospective awards, subject to this policy, network invariants, agreements actually made, and applicable law.

## 3. Owner allocation — 1B QZXB

The one-billion owner allocation is controlled by the owner. This policy does **not** impose a mandatory project-created time vesting schedule, cliff, or protocol lock on that allocation.

The owner may hold, use, transfer, or sell the owner allocation subject to the canonical network rules and any mandatory law, court order, sanctions restriction, or other binding legal obligation that applies to the specific transaction. A platform's preference or a voluntary project policy is not, by itself, a legal requirement.

The owner allocation does not grant hidden issuance authority, a consensus override, a right to change the ten-billion ceiling unilaterally, or permission to misstate issued or circulating supply. Genesis, wallet, RPC, and explorer records must identify the owner allocation consistently and distinguish its accounting ceiling from any amount actually issued, spendable, or transferred.

## 4. Owner-controlled six-billion allocation-label pool

The owner-controlled pool is not an automatic grant to recipients. Each one-billion label identifies a maximum purpose envelope. A prospective award becomes an obligation only after the owner authorizes a defined award and the required agreement, evidence, technical controls, and legal checks are complete.

### 4.1 Developers and security contributors — 1B

Eligible work may include protocol engineering, consensus and storage implementation, reproducible tests, security engineering, cryptographic review, documentation, developer tooling, and approved infrastructure work.

Required evidence includes a written scope, measurable acceptance criteria, reviewed deliverables, recipient/account verification, the approved amount, and an acceptance record. Independent security reviewers must remain free to report findings; token compensation must never purchase an approval, suppress a finding, or be described as a substitute for an independent audit.

### 4.2 Community and public distribution — 1B

This envelope may support eligibility-based community distribution, user onboarding, and airdrops. Before a distribution, publish the eligibility and snapshot method, anti-Sybil controls, duplicate-account handling, per-recipient caps, claim process and dates, unclaimed-token treatment, and any lock-up or release schedule.

An airdrop is a distribution mechanism, not proof of market demand, cash proceeds, or liquidity. No participant is promised a dollar value, profit, redemption, or price floor.

### 4.3 Exchanges and platform integration — 1B

Eligible work may include technically verified integration with exchanges, wallets, custodians, explorers, RPC providers, infrastructure platforms, and ecosystem services.

Before an award, record the counterparty, written agreement, supported network and asset identifiers, technical deliverables, acceptance tests, security responsibilities, service levels where relevant, and the staged release conditions. The envelope is not a guaranteed listing, a promise that any exchange will accept QZXB, or a default payment-for-listing fee. Each platform retains its own independent listing, custody, risk, and compliance decision.

### 4.4 Marketing and growth — 1B

Eligible work may include educational content, disclosed campaigns, community growth, public relations, brand partnerships, and measurable user acquisition.

Each campaign must specify scope, budget, deliverables, schedule, measurement method, and paid-promotion disclosures. Prohibit false price or return claims, undisclosed promotion, wash trading, artificial volume, and any attempt to represent campaign activity as genuine organic liquidity.

### 4.5 Financial and strategic supporters/investors — 1B

This is a prospective, conditional reserve. No investor, sponsor, supporter, or funding commitment is secured merely because the allocation exists.

A release requires a signed agreement, verified support actually received or a separately approved and enforceable milestone obligation, a clear description and valuation of cash/services/infrastructure, recipient and account verification, and jurisdiction-specific legal, tax, sanctions, and compliance review.

An award does not by itself create equity, debt, a redemption right, revenue share, governance rights, or a guaranteed investment return. Any such rights require a separate lawful instrument and review. No public offer or solicitation is authorized by this policy alone.

### 4.6 Protocol burn reserve — 1B

The burn label is a reserve ceiling, not a statement that tokens have already been burned. Report a burn only when issued tokens are irreversibly removed through a defined canonical method and the transaction or protocol event can be independently verified.

Record amount, date, reason, authorization, transaction/event identifier, and verification evidence. Cancelling an unissued accounting ceiling is a cancelled allocation, not a token burn. Burn activity is not a price-support mechanism and does not guarantee appreciation.

## 5. Mining and network-security envelope — 3B

The three-billion QZXB envelope is reserved for mining and network security. It is part of the ten-billion ceiling and is not an extra emission allowance.

This amendment restores the mining/security allocation as an owner-directed supply category; it does **not** automatically reactivate any historical subsidy curve, halving interval, target block time, difficulty parameter, or miner payout implementation. Those parameters must be specified and approved in a versioned canonical mining/monetary profile before value-bearing use.

Before any mining reward is enabled, the project must prove that:

- the cumulative miner issuance cannot exceed 3,000,000,000 QZXB;
- the complete ten-billion accounting ceiling cannot be exceeded through any combination of Genesis, mining, owner allocation, conditional releases, imports, replay, recovery, or reorganization;
- reward calculation and eligibility are deterministic and identical in block production, validation, import, replay, fork choice, reorganization, snapshot, and recovery paths;
- difficulty adjustment, target/work validation, subsidy boundaries, halving or other emission transitions, integer overflow, and boundary heights are covered by independent golden vectors and adversarial tests;
- invalid, duplicate, stale, or non-canonical rewards fail closed without partial state mutation;
- independent nodes can reproduce the same issuance and chain state from the canonical history;
- the final profile, Genesis fingerprint, wallet/RPC display, explorer accounting, and supply reports agree;
- any required legal and security reviews are complete.

Until those gates pass and a separate explicit release authorization is recorded, the 3B envelope is a reserved accounting ceiling, not an active payout promise, spendable miner balance, or proof that production mining is operating. Mining must not be described as live merely because historical PoW code, simulations, or local mining tests exist.

## 6. Common release controls for the five conditional allocations

Every award from the five purpose allocations must use one traceable release record containing:

1. owner authorization identifying the purpose, recipient, maximum amount, and release scope;
2. recipient identity and destination-account verification appropriate to the risk and applicable law;
3. a written agreement or published distribution terms;
4. objective milestones or eligibility evidence and a recorded acceptance decision;
5. the required jurisdiction-specific legal, tax, sanctions, and platform/compliance checks;
6. an implemented and tested release mechanism appropriate to the award (for example, canonical on-chain escrow, vesting, or milestone release where required);
7. a unique transaction/event reference and independently reproducible accounting entry;
8. public reporting of amounts designated, approved, earned, released, returned/cancelled, and actually burned as separate figures.

A spreadsheet, website statement, PR approval, wallet label, or off-chain promise is not proof that a token is issued, vested, locked, transferred, or spendable. Do not claim on-chain enforcement until the canonical runtime implements and tests it.

Conditional restrictions should be applied where justified by the agreement, platform rules, risk controls, or mandatory law. They must not be invented after an award or selectively hidden. The owner allocation remains distinct and is not subjected to an extra project-imposed lock by this amendment.

## 7. Indicative price and liquidity language

The owner may use **US$0.01 per QZXB as a proposed indicative reference for planning and negotiations**, clearly labelled as an owner-proposed reference and not a market-established price, guaranteed opening quote, redemption value, minimum price, or promise of exchange acceptance.

A real market price is established by actual trading. The theoretical product of a reference price and an accounting ceiling is not cash, project revenue, market capitalization, or realizable owner proceeds.

An airdrop may increase distribution and the number of holders, but an airdrop alone does not create dollar liquidity. Genuine liquidity requires actual paired assets or other eligible quote assets, verifiable reserves, functioning deposits and withdrawals, real counterparties and orders, and transparent trading. Do not simulate volume, promise a guaranteed market, or misrepresent an unlaunched pool as funded.

## 8. Operational acceptance requirements for platforms and exchanges

Before presenting QZXB as ready for production integration, the release package must provide consistent, testable evidence for:

- canonical chain/network identity, chain ID, native asset ticker, decimals, address and signature formats;
- frozen Genesis and monetary profile, total cap, mining issuance schedule, owner allocation, conditional allocation accounting, and burn semantics;
- independently reproducible node build, signed release artifacts, supported operating systems/architectures, configuration and upgrade procedures;
- consensus, finality/confirmation behavior, fork/reorganization policy, replay protection, and clear deposit/withdrawal safety guidance;
- stable, documented RPC/API schemas, rate limits, error codes, health/readiness endpoints, and version compatibility;
- wallet creation/recovery, transaction signing, nonce/sequence handling, fee estimation, and hardware/custody integration boundaries;
- explorer and indexer consistency for balances, issued supply, circulating supply, miner rewards, conditional releases, and burns;
- monitoring, incident response, key rotation/revocation, backup/recovery, and operator onboarding;
- reproducible integration tests and independent evidence for each supported platform path;
- jurisdiction-specific legal/compliance review where a platform, token distribution, exchange service, or public market requires it.

Compatibility is demonstrated per platform and version. No document can guarantee that every exchange or platform will list or support the asset.

## 9. Public accounting and disclosure vocabulary

Use these terms consistently:

- **Ceiling / reserved:** a maximum accounting designation, not an issued balance.
- **Allocated:** assigned to a purpose under this policy; not necessarily issued or owed.
- **Approved:** an exact award authorized for a defined recipient or distribution.
- **Earned:** applicable work or eligibility conditions have been satisfied.
- **Issued:** created only through the authorized canonical issuance path.
- **Vested / unlocked:** restrictions defined by the applicable implemented mechanism have expired or been satisfied.
- **Released / transferred:** actually made spendable or transferred under canonical rules.
- **Circulating:** publicly available under a disclosed, reproducible methodology.
- **Burned:** issued supply irreversibly removed with verifiable evidence.
- **Cancelled ceiling:** an unissued designation removed from the accounting plan; not a burn.

Never combine these statuses into one “released supply” or “circulating supply” number.

## 10. Historical records, review scope, and migration

CP-0651-A and PR #211 remain intact as historical records, including their commits, review records, and original seven-billion/fee-only policy. This amendment does not rewrite or erase their past.

The existing records for PR #195, PR #211, PR #212, and PR #200 must remain available with their original review scopes and merge targets. An approval of documentation or a technical subcomponent is not a blanket approval of this amendment, production mining, Mainnet, legal compliance, or exchange readiness. This amendment requires its own review.

Open documentation work that aligns the white paper or roadmap with the older CP-0651 parameters (including PR #197 and PR #213) must be reconciled against this amendment before merge. Unrelated technical changes in those branches must be reviewed separately rather than silently mixed with economic-policy edits.

After this amendment is reviewed and accepted, the migration must update and cross-check, as applicable:

- the canonical monetary profile, Genesis data/fingerprint, issuance and reward code;
- block production, validation/import, replay, fork/reorganization, and recovery paths;
- wallet, RPC, explorer, indexer, and public supply/accounting views;
- README, economics page, status page, website, white paper, roadmap, outreach kit, and exchange/platform documentation;
- release manifests, hashes, test vectors, and evidence references.

The previous seven-billion policy must remain identifiable as superseded history. It must not be represented as the current active policy once CP-0651-B is approved and activated.

## 11. Activation checklist

This amendment is not production-active until all applicable items are complete:

- [ ] Owner confirms the exact ten-billion arithmetic and allocation labels.
- [ ] Independent reviewers assess this amendment and record scope, findings, and reviewed commit.
- [ ] Canonical mining/monetary profile defines a bounded 3B mining issuance schedule.
- [ ] Canonical supply invariants enforce the 10B ceiling across every state-transition and recovery path.
- [ ] Owner allocation is represented without an extra project-imposed time lock, while respecting binding law.
- [ ] Five conditional allocation mechanisms and the burn path are implemented and tested.
- [ ] Genesis, snapshot, wallet, RPC, explorer, and accounting views reconcile to the same profile.
- [ ] Security, operational recovery, and independent-node qualification gates pass.
- [ ] Public documents and platform integration package are reconciled and reproducible.
- [ ] Required legal, tax, sanctions, and platform-specific reviews are complete.
- [ ] A separate explicit owner authorization identifies the exact production activation and release scope.

Until then, this document is an owner-directed amendment draft for review, not an active Mainnet policy or a claim that mining, airdrop, liquidity, trading, or exchange integration is live.

---

**Public status:** Draft amendment. No tokens are issued or transferred by this document. No Genesis, runtime, wallet, network, or liquidity state is changed by this documentation-only proposal.
