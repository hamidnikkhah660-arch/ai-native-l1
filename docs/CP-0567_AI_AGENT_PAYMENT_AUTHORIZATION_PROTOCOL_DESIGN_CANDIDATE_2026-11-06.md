# CP-0567 — AI-Agent Payment Authorization: Protocol Design Candidate

**Document ID:** CP-0567  
**Version:** 0.2 (design candidate; not consensus-frozen)  
**Date:** 2026-11-06  
**Roadmap layer:** 9 — AI Agent Economy and bounded payment authorization  
**Parent roadmap:** `QRUN_MASTER_ROADMAP_VERIFIABLE_AI_NATIVE_INFRASTRUCTURE_2026-11-06.md`  
**Status:** Proposed architecture for review; no production implementation is claimed  

## 1. Executive decision

QRun should develop a native, cryptographically verifiable delegated-payment capability. A wallet owner grants an AI agent narrowly bounded authority to submit payments without granting unrestricted control of the owner's keys or account.

The capability must bind authority to a specific network and account, agent identity, asset, amount and fee budgets, permitted recipients and/or service identifiers, validity interval, nonce/version, and revocation state. Ledger execution must enforce aggregate limits atomically, not merely trust a wallet-side or agent-side check.

This is a strategic differentiator to build, not a current QRun feature or public marketing claim. This document is a design candidate. It does not authorize a consensus change.

## 2. Problem statement and security objective

An AI agent may need to pay for compute, data, APIs, software, storage, or another agent's service. Giving the agent the owner's seed phrase or unrestricted signing key creates an unacceptable blast radius. A local policy check alone is insufficient because a malicious or compromised agent can bypass its own client.

**Security objective:** an agent can cause value to move only when a valid owner-authorized capability permits the exact transaction under deterministic protocol rules. Every accepted spend is attributable to a capability and independently auditable without disclosing unrelated wallet secrets.

The design must fail closed: absent, malformed, expired, revoked, wrong-network, over-budget, out-of-scope, or unverifiable authority means rejection.

## 3. Threat model

Assume any of the following may be malicious or compromised:

- the AI agent process, model, plugin, tool, or host machine;
- the service or recipient requesting payment;
- the agent's network path or RPC provider;
- a relayer, mempool participant, or block producer;
- multiple agent requests arriving concurrently;
- a wallet UI or SDK integration bug;
- a stale, reorganized, or inconsistent node view.

The owner key may remain uncompromised in the base model. If the owner key is compromised, an attacker can create new capabilities; recovery and key rotation are separate controls. If the agent key is compromised, damage must remain bounded by the capability's remaining authority and expiry, subject to revocation finality.

Out of scope for the first version: proving that an off-chain service actually delivered a promised service; interpreting arbitrary natural-language intent on-chain; guaranteeing an AI model's honesty; legal or regulatory determinations; and privacy against all chain observers.

## 4. Authority model and lifecycle

1. **Create:** owner wallet constructs a canonical capability policy and signs it with the owner's authorized account key.
2. **Register:** the chain validates owner authorization, account/network binding, validity bounds, and unique capability identifier, then records the capability as active.
3. **Use:** the agent signs a payment request referencing the capability identifier. The transaction binds the actual recipient, asset, amount, fee, service/action identifier, and transaction nonce.
4. **Enforce:** every validating node checks capability status and all limits against canonical state, then atomically updates spent counters with the transfer.
5. **Revoke:** the owner submits a signed revocation or capability-version increment. Revocation takes effect according to deterministic transaction ordering and the chain's documented finality/reorg model.
6. **Expire:** authority becomes unusable after the exclusive expiry boundary. Expired records may be pruned only when historical verification remains possible.
7. **Audit:** the transaction and receipt expose the capability identifier, policy version, spend delta, and resulting state commitment; secret keys are never included.

A wallet must display the effective authority in human-readable form before signing: total remaining amount, fee allowance, destinations/services, validity, and revocation controls.

## 5. Canonical capability fields (candidate schema)

The exact wire format and integer widths require a separate codec/vector decision. The logical schema should include:

| Field | Required semantics |
|---|---|
| `version` | Explicit schema and policy version; unknown versions fail closed |
| `network_id` | Exact QRun network binding; no cross-network replay |
| `manifest_or_domain_id` | Bind to the applicable protocol/consensus domain where required |
| `capability_id` | Hash of canonical owner-signed capability bytes under a dedicated domain separator |
| `owner_account` | Account whose funds are delegated |
| `agent_account_or_key_id` | Exact agent identity authorized to request spends |
| `asset_id` | Native QZXB or an explicitly supported asset; no implicit asset substitution |
| `max_amount_per_tx` | Maximum transfer amount for one payment |
| `max_total_amount` | Aggregate transfer ceiling over capability lifetime |
| `max_fee_per_tx` | Maximum fee for one payment |
| `max_total_fee` | Aggregate fee ceiling over capability lifetime |
| `recipient_scope` | Exact allowlist or a precisely specified recipient-set commitment |
| `service_scope` | Canonical service IDs and action/method IDs; no vague natural-language policy interpreted by consensus |
| `not_before` | Earliest valid block height or protocol-defined time boundary |
| `expires_at` | Exclusive expiry boundary; prefer block height for deterministic consensus semantics |
| `capability_nonce` | Unique owner-side sequence preventing duplicate registration |
| `policy_epoch` | Owner-controlled monotonic epoch/version for invalidation and key/policy rotation |
| `human_approval_rule` | Optional explicit threshold requiring a separate owner signature for larger or exceptional spends |

The capability identifier must be computed from a canonical encoding with a dedicated domain tag and include the network/domain binding. No JSON serialization or unordered map representation may be consensus-canonical unless separately specified and frozen.

### Scope semantics

- If a recipient allowlist is present, only exact listed account IDs are valid. Empty-list semantics must be explicit; never interpret an omitted list as unrestricted by accident.
- Service identifiers must be stable, canonical identifiers. A service label supplied by the agent is not proof that a service performed work.
- For the MVP, prefer a small explicit set of payment actions over arbitrary contract-call permissions. Contract address, method selector, and argument constraints require a separate canonical policy grammar.
- Natural-language purpose can be shown to the owner and included as a non-authoritative audit annotation, but consensus must not attempt to infer meaning from free text.

## 6. Payment transaction binding

An agent-authorized payment must bind, at minimum:

- capability ID and policy version;
- network/domain and owner account;
- agent identity/key reference;
- transaction nonce or sequence;
- asset ID, recipient, amount, and fee;
- service/action identifier when service scoping is used;
- any required owner approval proof;
- agent signature over the complete canonical payment intent.

The chain must verify both the owner's capability authorization and the agent's transaction authorization. The agent signature does not create or enlarge authority. A transaction must not be accepted by silently falling back to the owner's unrestricted authorization path when capability validation fails.

The current TXN4 candidate already models network and manifest binding, sender/recipient identifiers, nonce, amount, fee, expiry, and hybrid signature material. That is useful adjacent infrastructure, but it does not by itself implement delegated capabilities, aggregate spend state, revocation, or atomic policy enforcement. Existing TXN4/mempool candidate code explicitly describes itself as not wired into the production node CLI, peer protocol, RPC, or runtime. Reuse must be preceded by a code-path audit and a clear production integration plan.

## 7. Deterministic ledger enforcement

For each capability, canonical state should track at least:

- active/revoked/expired status and policy epoch;
- cumulative amount spent;
- cumulative fees charged;
- registration and expiry boundaries;
- any per-capability transaction sequence or replay-protection state.

For every candidate payment, validation must check all conditions against the same canonical pre-state and then apply transfer and counter updates as one atomic state transition:

1. capability exists and is active;
2. network, domain, owner, agent, and asset all match;
3. current block is within the validity interval;
4. capability and transaction signatures verify under the declared scheme;
5. nonce/sequence is valid and unused;
6. recipient and service/action satisfy scope;
7. per-transaction amount and fee limits are not exceeded;
8. checked arithmetic proves cumulative amount and fee totals remain within aggregate ceilings;
9. owner approval is present if the threshold rule requires it;
10. transfer, fee debit, replay state, and cumulative counters commit atomically.

**Concurrency rule:** two individually valid requests must not both spend the same remaining budget. Consensus execution must serialize or otherwise atomically reserve budget against one canonical state. A wallet-side mutex, RPC preflight, or mempool simulation is not a security boundary.

**Ordering rule:** registration, revocation, and spend operations in one block require a deterministic canonical order. The chosen order must be included in transaction/block semantics and vectors. Do not leave same-block revocation races to implementation accident.

**Reorganization rule:** spent counters and revocation status must be derived from or recoverable with canonical chain state. A reorg must roll back the affected spend and capability updates together. Wallets and agents must distinguish submitted, included, and finalized status; an ingress acknowledgement is not settlement finality.

## 8. Revocation, expiry, and recovery

- Revocation must be owner-authorized and capability-specific, with a monotonic sequence/epoch to reject stale state.
- Define whether a revocation transaction is effective at its canonical execution position or only after finality. UI and APIs must disclose this exact rule.
- Expiry uses an exclusive boundary: at or after `expires_at`, the capability is invalid. Block-height expiry is preferable for consensus determinism; timestamp expiry requires a bounded clock-drift and timestamp-validation model.
- Owner key rotation must define how active capabilities are invalidated, migrated, or reauthorized.
- Agent key rotation must require a new owner-authorized capability; no agent may self-assign a replacement key.
- Emergency freeze may be an owner-wide policy epoch increment, but it must not permit a third party to freeze arbitrary accounts.
- Lost owner key recovery is not solved by delegated authorization; it needs a separate account recovery design and explicit trust assumptions.

## 9. Privacy and auditability

Public-chain capability details can reveal spending plans, business relationships, budgets, and service usage. The MVP should minimize unnecessary metadata while preserving verifiability.

Potential later options include commitments to recipient/service sets, selective disclosure, and zero-knowledge proofs of policy compliance. These are not part of the first implementation until soundness assumptions, leakage, verifier costs, and audit requirements are specified. Hiding a field from a UI does not make it private on-chain.

Receipts should prove which capability authorized a spend and what state transition occurred. They must not expose private signing material or imply that a service was delivered unless a separate verifiable service-attestation mechanism exists.

## 10. Cryptographic agility and PQ transition

The capability format must carry an explicit signature-scheme/version identifier and domain separation. It should permit future hybrid/PQ authorization without ambiguous algorithm fallback. Key lengths, signature lengths, verification costs, and transaction-size limits must be bounded before admission.

Do not describe the capability system as post-quantum until owner authorization, agent authorization, account recovery, and all relevant transport/storage paths have a reviewed PQ security profile. Existing QRun classical Ed25519 and X25519/ChaChaPoly paths remain material limitations; experimental ML-DSA-65 use in selected paths is not whole-network PQ protection.

## 11. Required adversarial test matrix

No implementation may be considered accepted without deterministic vectors and negative tests covering at least:

- missing, malformed, unknown-version, and non-canonical capability encodings;
- wrong network, manifest/domain, owner, agent, asset, or policy epoch;
- invalid owner signature and invalid agent signature;
- replayed registration, payment, and revocation;
- nonce reuse, skipped nonce, overflow, and integer-boundary values;
- amount over per-transaction limit and aggregate limit;
- fee over per-transaction limit and aggregate fee limit;
- two or more concurrent spends racing for the final budget;
- recipient not in allowlist and service/action outside scope;
- expiry immediately before, at, and after the exclusive boundary;
- not-before boundary and future-dated capability;
- revocation racing with a payment, including same-block ordering;
- owner epoch increment and agent key rotation;
- required human approval missing, malformed, or for different transaction bytes;
- duplicate transaction through different peers/relayers;
- reorg removing registration, spend, or revocation;
- restart/recovery restoring exact capability counters and status;
- malicious RPC/mempool returning stale preflight results;
- oversized scope lists, excessive verification work, and resource-exhaustion attempts;
- classical/PQ scheme downgrade and cross-domain signature reuse.

Every test should state the expected error/result and assert no partial state mutation on rejection.

## 12. Staged implementation plan and gates

| Stage | Deliverable | Exit gate |
|---|---|---|
| A0 | Threat model, canonical schema, state machine, ordering and finality decision | Independent design review; unresolved consensus questions recorded |
| A1 | Pure deterministic policy evaluator and vectors, isolated from node runtime | Property tests, fuzzing, canonical codec vectors; no state side effects on reject |
| A2 | Wallet/SDK capability create/inspect/revoke and safe simulation | User-visible scope clarity; key custody tests; no seed sharing with agent |
| A3 | Transaction binding and receipt format | Signature, replay, domain, expiry, and compatibility tests |
| A4 | Atomic ledger budget enforcement and persistent state | Concurrent-spend, restart, reorg, and recovery tests pass |
| A5 | Node/RPC/mempool/peer integration | Multi-node adversarial qualification and resource bounds |
| A6 | Independent audit and limited pilot | Findings triaged; operational monitoring, emergency controls, and release approval |

Do not skip A0/A1 and jump directly to a consensus change. The first deliverable should be a pure policy model and adversarial vectors, not a live-money feature.

## 13. Open design decisions before implementation

1. Native protocol primitive versus deterministic smart-contract standard: compare consensus complexity, upgradeability, composability, and auditability before choosing.
2. Whether budgets are denominated only in native QZXB for MVP or support asset IDs from day one.
3. Whether fee spending is included in amount budget or tracked in a separate fee ceiling. This candidate recommends separate explicit limits.
4. Whether capability registration/revocation is on-chain state or an account-authenticated state object. The MVP should favor independently verifiable, reorg-aware state.
5. Block-height versus timestamp validity. This candidate recommends block-height boundaries for consensus-critical expiry.
6. Canonical transaction ordering and same-block revocation semantics.
7. Owner approval threshold representation and whether a second key or multisig is required.
8. Whether recipient/service scope is explicit list, Merkle commitment, or another bounded representation.
9. Capability state growth, pruning, and historical proof strategy.
10. Cryptographic algorithm agility and future PQ migration compatibility.

These decisions are narrowed by the provisional A0 record: `CP-0567_A0_DECISION_RECORD_AI_AGENT_PAYMENT_AUTHORIZATION_2026-11-06.md`. The record makes explicit MVP recommendations and preserves unresolved code-dependent questions. Both documents remain design-only and require review before A1 implementation.

## 14. Acceptance and public-claim policy

This document is **Proposed/Designed**, not Implemented, Tested, Independently Verified, Production Deployed, or Released. No QRun public material may claim AI-agent payment authorization is live until the relevant stages have passed their exit gates and the evidence is linked.

The strongest future public claim should be narrow and testable, for example: “QRun supports owner-authorized agent spending with deterministic per-payment and aggregate budgets, explicit recipient/service scopes, expiry, revocation, and independently verifiable settlement receipts,” but only after all those properties are implemented, tested, and independently verified.

---

**Decision requested:** review this candidate architecture and resolve the open decisions before any consensus or production-runtime implementation begins.

