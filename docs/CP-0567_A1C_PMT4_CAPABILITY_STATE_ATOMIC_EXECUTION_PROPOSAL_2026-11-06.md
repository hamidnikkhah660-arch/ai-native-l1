# CP-0567 — A1C PMT4 Capability State and Atomic Execution Proposal

Date: 2026-11-06  
Status: DESIGN PROPOSAL ONLY — not implemented, not consensus-approved, not a public-network feature.

## 1. Source baseline and verified execution boundary

This proposal is based on `origin/main` commit `c536caec696217234d6b35582663c0aa58652b9c` and the source reconciliation in `CP-0567_A1B_SOURCE_PATH_RECONCILIATION_2026-11-06.md`.

The PMT4 node import path decodes a PMT4 candidate and calls `PrivateTestnetV4HybridForkStore::submit`. The fork store validates/inserts the candidate into a cloned candidate archive before publishing the new manifest/archive state. PMT4 monetary execution is performed through the candidate monetary state transition; the transaction loop verifies each TXN4 envelope, projects its account transfer, applies nonce/balance/fee checks to a cloned ledger, then validates subsidy/supply and state root before publishing the resulting state. The fork store's fork-choice archive is the place where branch-specific state is replayed and canonical selection/reorganization occurs.

This is the right conceptual boundary for CP-0567. It is not permission to add capability state directly to production consensus today: the current PMT4 node harness is loopback-only and local PFM4 persistence is used in its peer-smoke path.

## 2. Non-negotiable invariants

1. No delegated payment may be authorized solely by RPC, mempool admission, or an agent-held account key. The canonical block state transition must enforce the capability.
2. Capability state, account balances/nonces, fees, transaction replay protection, and capability spend counters must commit or reject as one deterministic state transition.
3. A failed block candidate must leave the prior state byte-for-byte/logically unchanged.
4. Replaying the same canonical history must produce the same capability registry root and monetary state root on every conforming node.
5. Fork choice/reorg must select capability state by replaying the selected branch, not by retaining mutable side effects from a previously canonical branch.
6. A revoked, expired, exhausted, wrong-network, wrong-asset, wrong-recipient, wrong-agent, wrong-service, or over-fee capability must fail closed.
7. No capability can mint, alter issuance, bypass ordinary account nonce rules, or bypass ordinary fee/balance checks.
8. Initial scope is QZXB only and one explicit network/manifest domain. No implicit multi-asset or cross-chain authority.

## 3. Proposed state model (conceptual Rust types)

`CapabilityId = Hash(domain || network_id || owner_id || owner_nonce || canonical_policy_bytes)`.

`AgentCapability` immutable fields:
- capability_id, network_id, manifest_id, owner_account_id;
- agent_key_id / agent public-key commitment and authorization scheme;
- asset_id (initially the one native QZXB asset identifier only);
- max_amount_per_payment, max_total_amount;
- max_fee_per_payment, max_total_fee;
- allowed_recipient_set (sorted, unique, bounded);
- allowed_service_action_set (canonical identifiers, sorted, unique, bounded);
- not_before and exclusive expiry (unit must be fixed before wire-format approval);
- policy_version, owner_nonce, optional approval threshold;
- canonical policy digest.

Mutable consensus state:
- capability record or tombstone;
- amount_spent_total and fee_spent_total;
- next capability-use nonce (or a separately domain-separated per-capability sequence);
- revoked flag / revocation height and policy epoch;
- deterministic registry commitment included in the monetary state root.

Do not store an unbounded list of every historical payment in the capability record. Use monotonic counters and existing transaction/block history for auditability; define pruning only after snapshot/recovery rules are specified.

## 4. Proposed action semantics

The block's ordered action stream needs three semantic operations:

A. `RegisterCapability`: owner-authenticated; validates owner account nonce, policy bounds, canonical encoding, unique capability ID, owner/agent separation, expiry range, and network/manifest binding. Registration initializes counters to zero.

B. `RevokeCapability`: owner-authenticated; validates owner nonce and capability ownership; creates a deterministic revocation state/tombstone. Revocation is irreversible for a capability ID. Re-authorization creates a new ID and policy version; no silent mutation of an existing signed policy.

C. `DelegatedPayment`: agent-authenticated; binds capability ID, policy version, agent identity, capability-use nonce, asset, recipient, amount, fee, service/action ID, network, manifest and expiry. It checks the stored capability and atomically increments amount/fee counters while applying the ordinary account transfer and fee debit.

The action stream must preserve canonical block order. A capability registered earlier in a block may be usable later in that same block only if this is explicitly adopted; otherwise all registrations become effective at the next block. A revocation earlier in the block must invalidate later uses in that same block. This proposal recommends ordered same-block semantics because the existing candidate transition iterates block transactions in vector order, but this must be verified against all block encoding/decoding and producer/import paths before protocol freeze.

## 5. Atomic delegated-payment transition

For each delegated payment, in canonical action order:

1. Verify exact network and manifest; reject wrong asset or unsupported scheme.
2. Resolve capability ID; require active, correct policy version, not revoked, within validity interval.
3. Verify agent signature over a domain-separated canonical digest containing every payment field and the capability ID/version.
4. Require capability-use nonce exactly previous + 1; reject duplicate/replayed transaction/action IDs.
5. Check recipient and service/action allowlists.
6. Check per-payment amount and fee caps.
7. Checked-add amount and fee to aggregate counters; reject overflow or cap exceedance.
8. Apply ordinary sender/owner escrow or debit semantics, recipient credit, ordinary account nonce rules and fee-pool accounting. Exact debit model must be selected: owner-paid from owner account is preferred for initial design; agent must never gain independent spending power over owner funds outside the capability.
9. Publish the cloned candidate state only after the complete block, subsidy, supply and state-root checks pass.

Concurrency: two candidate payments against one capability in the same block are processed in canonical order against the evolving cloned state. Across competing branches, each branch gets independent replayed counters; only the selected branch is canonical. Mempool prechecks are advisory and must never reserve or authorize spend by themselves.

## 6. Wire-format recommendation

Do not mutate the fixed-width TXN4 encoding in place. It currently binds network/manifest, sender/recipient, nonce, amount, fee, expiry, identity scheme, and the Ed25519/ML-DSA-65 key/signature tuple; it has no capability ID, service scope, asset ID, or delegated-agent binding.

Before selecting TXN5 versus a versioned block action envelope, write a separate wire-format decision with:
- exact domain separators and canonical byte layout;
- version/suite negotiation and downgrade rejection;
- bounded lengths and canonical sorted allowlists;
- signature coverage for every policy/payment field;
- transaction/action IDs and replay domains;
- backward compatibility and activation rules;
- independent encode/decode test vectors.

No silent projection from a delegated envelope to TXN4 is allowed because it would discard delegation authority fields.

## 7. Fork choice, reorg, persistence and external anchoring

- Capability registry and counters must be part of the branch's monetary state and state root, not a process-global side database.
- Branch insertion/replay must derive capability state from the branch's parent state and ordered actions.
- On reorg, canonical capability state becomes exactly the state derived from the newly selected branch. A payment that existed only on the abandoned branch must not remain counted or permanently consume a capability nonce on the new canonical branch.
- Snapshot format/version must persist the capability registry root and all live capability records/counters/tombstones. Recovery must validate the complete state commitment against the selected chain tip and manifest.
- If external CAS anti-rollback is adopted, the PFM4 pending-manifest/verified-receipt protocol must cover the exact manifest that commits both monetary and capability state. The current PMT4 peer-smoke runtime calls local `store.submit`; external-CAS store APIs exist separately and are not wired into that runtime. Do not claim external anti-rollback protection for this path until node startup, commit, restart and recovery use the anchored API end-to-end.
- Provider ambiguity, crash between pending-manifest sync and CAS, crash after CAS before local publication, stale signed anchor, and full-disk rollback all need deterministic recovery tests.

## 8. Mandatory deterministic test vectors before implementation approval

Positive cases:
- owner registers; authorized agent pays allowed recipient within caps;
- multiple payments consume aggregate budget exactly to the boundary;
- valid fee boundary and expiry just before exclusive expiry;
- same-block ordering if adopted; persistence/restart; archive replay; fork switch and switch-back.

Negative/adversarial cases:
- wrong owner, agent key, network, manifest, asset, recipient, service/action, policy version;
- altered amount/fee/recipient/service/nonce after signature;
- duplicate capability ID, duplicate payment ID, replayed capability nonce;
- amount/fee one atom above per-payment and aggregate caps;
- integer overflow; zero/invalid limits; oversized allowlists; duplicate/noncanonical entries;
- expired and not-yet-valid boundaries;
- revoke then spend; spend then revoke; duplicate revocation; unauthorized revocation;
- two simultaneous submissions racing for final budget; deterministic canonical ordering;
- reorg removes registration, payment, or revocation; abandoned-branch counters and nonce do not leak;
- crash at each persistence/CAS boundary; restart with stale or mismatched anchor; corrupted snapshot; rollback to older disk image;
- downgrade to TXN4 or legacy TXN2; malformed version/suite; signature suite mismatch.

Every rejected block must preserve prior state root, account balances/nonces, fee pool, capability counters, registry commitment and selected tip.

## 9. Open decisions (must be resolved before wire format or consensus code)

1. Owner-paid transfer model versus a dedicated owner escrow account. Recommendation: owner-paid direct debit with a capability-specific allowance counter, not transferable agent-held owner keys.
2. Block-height versus timestamp validity. Recommendation: block-height after a reliable production clock/finality contract exists; until then do not freeze semantics. TXN4 currently uses block timestamp for exclusive `expires_at`.
3. Same-block registration/revocation effectiveness. Recommendation: ordered block action semantics with revoke immediately effective for later actions; confirm all producer/import code preserves the same order.
4. Per-capability nonce versus owner account nonce for capability management. Recommendation: owner account nonce for register/revoke plus independent capability-use nonce for agent payments.
5. Native protocol action versus smart-contract implementation. Recommendation: keep policy enforcement in the ledger for v1; do not trust an off-chain agent gateway or ordinary smart-contract caller to enforce the spending ceiling.
6. Asset ID representation and future multi-asset scope. Initial implementation must remain native QZXB only.
7. State growth, tombstone retention, capability limits per owner, maximum allowlist sizes and pruning proofs.
8. Finality and revocation UX: no claim that a revocation is irreversible until the chain's finality/reorg contract is specified.

## 10. Implementation gate

A1C is a proposal only. The next implementation step, if separately approved, is a pure Rust capability policy/state-transition module with typed errors and deterministic vectors, independent of node CLI, peer protocol, wire format, Genesis and live monetary state. It must operate on cloned candidate state and return a new state plus execution summary; no I/O, clocks, network calls, or mutable global state. Only after that module passes adversarial/property tests should the team decide the canonical wire envelope and integration into PMT4 block execution.

No production code, consensus behavior, Genesis, supply schedule, wallet, node flags, network configuration, or live balance was changed in this proposal.

## 11. Source-backed implementation seam (read-only audit, 2026-11-06)

This section records a focused inspection of the pinned `origin/main` source baseline `c536caec696217234d6b35582663c0aa58652b9c`. It refines the integration plan without changing source code.

### 11.1 Monetary state boundary

`src/native/pow_bench/src/state_machine.rs` defines `MonetaryLedgerState` with exactly two stored fields: `ledger: LedgerState` and `total_mined_atoms: u128` (around lines 950-953). Its monetary `state_root()` commits the monetary policy fingerprint, `LedgerState::state_root()`, and cumulative mined atoms (around lines 1294-1301). No capability registry, capability-use nonce, spend counters, revocation tombstone, or delegated-payment state is currently represented in this state object or root.

The TXN4 candidate transition `prepare_v4_hybrid_monetary_candidate` (around lines 1370-1487) clones the account ledger, validates each TXN4 authorization, projects the signed transfer into the existing account transaction checks, and returns the candidate ledger plus issuance and fee totals. `apply_v4_hybrid_block_candidate` (around lines 1508-1541) checks the committed root before publishing the candidate ledger and issuance counter. This is a useful atomic-execution pattern, but it has no capability authorization or capability state transition today.

### 11.2 Snapshot boundary

`MonetaryLedgerState::encode_snapshot` / `decode_snapshot` (around lines 1681-1755) persist the monetary policy fingerprint, cumulative mined atoms, and encoded `LedgerState`, protected by a checksum and invariant validation. The snapshot is explicitly not an anti-rollback mechanism. Capability records, counters, nonces, and revocation tombstones are absent. Any future capability-state integration therefore requires a versioned monetary snapshot format and restore-time root/invariant checks; merely adding a process-local registry would be incorrect.

### 11.3 Fork-choice behavior that can be reused

`PrivateTestnetV4HybridForkChoice` stores each accepted branch as a `StoredV4HybridBranch` containing the encoded envelope and its fully replayed `PrivateTestnetChain`. On insertion it clones the selected parent chain, appends and validates the candidate, stores that branch-local chain, and selects the best tip. This means that if capability state becomes part of `MonetaryLedgerState` and its deterministic block transition, the existing branch-clone/replay model can carry independent capability state per branch. Reorg correctness should be achieved by deriving the selected chain's complete state, not by manually undoing global capability counters.

### 11.4 PFM4 durability and external-CAS boundary

`PrivateTestnetV4HybridForkStore::submit` clones the fork-choice archive, inserts/validates the candidate, writes the branch envelope and atomically publishes a manifest before replacing its in-memory archive. The separate `submit_with_external_anchor` API implements an external-CAS pending-manifest/verified-receipt sequence. The current PMT4 peer-smoke node path calls the local `store.submit` API; the existence of the anchored API alone does not prove end-to-end external anti-rollback protection in that node runtime.

### 11.5 Consequence for the implementation sequence

The safest next coding boundary is now more precise:

1. Build a pure, deterministic capability policy/state module and adversarial vectors without modifying `MonetaryLedgerState`, TXN4, PMT4, PFM4, wire formats, CLI, or consensus.
2. Separately design the versioned monetary-state/root/snapshot extension that would carry capability registry state. Define canonical serialization, limits, state-root domain separation, migration/activation and recovery behavior before integrating it.
3. Reuse the existing branch-local replay model only after capability state is part of the canonical monetary state transition; add reorg/switch-back tests proving counters and revocations follow the selected branch.
4. Treat external-CAS integration as a separate end-to-end deployment gate: node startup, submit, crash recovery, restart and operator-held anchor must use the anchored API and be independently tested.

**Audit conclusion:** QRun already has useful candidate machinery for atomic state transitions, branch-local replay/reorg, durable PFM4 manifests and a separate external-CAS API. The missing capability is not generic fork-choice from scratch; it is deterministic, committed and persisted agent-capability state plus its execution semantics and production wiring. This section is a source audit, not implementation evidence or launch approval.

### 11.6 Existing QVAAC agent-capability implementation — mandatory reuse check

A broader repository/branch audit on 2026-11-06 found an important pre-existing implementation that was not included in the first CP-0567 source-path review. Before writing any new agent-capability Rust module, reuse and reconcile this work:

- PR #93, `feat/qrun-qvap-offline-prototype-20261030`, commit `801471c90b307a5c12f6785173d2d8986ffb74d3`, adds `src/native/pow_bench/src/qrun_verifiable_agentic_settlement_candidate.rs` (1,478 lines) and `src/native/pow_bench/src/qrun_verifiable_asset_passport_candidate.rs` (1,594 lines), plus CP-0474/CP-0475 product/design records.
- The existing `QvaacAgentCapabilityGrant` already binds network, grant ID, principal/owner, agent ID/key ID, intent digest, asset class, counterparty, allowed-action mask, per-transaction spend cap, cumulative spend cap, prior-spend value, not-before/expiry, sequence, revocation epoch, signature algorithm and signature.
- The existing `QvaacEscrowCandidate` has deterministic shape/digest checks, injected grant/evidence/fulfilment verifier interfaces, rechecks grant and evidence at funding, enforces per-transaction and cumulative spend limits, models escrow funding, independent evaluator fulfilment/rejection, timeout refund, and hash-linked event/receipt verification. PR #93 records 15 QVAP tests and 16 QVAAC tests passing in its isolated Windows validation.

This is substantial prior art and overlaps the proposed CP-0567 agent grant/policy model. **Do not create a second standalone capability-policy module or duplicate QVAAC grant/escrow state machine.** The next engineering step must be a focused gap analysis and adaptation plan against this existing candidate.

Important gaps remain, so PR #93 is not equivalent to CP-0567 ledger enforcement:

1. PR #93 is still Draft and stacked on PR #92; its own body says the PR90 → PR91 → PR92 dependency chain must be reviewed first. It is not part of `main` and is not production-integrated.
2. Grant cryptographic verification is an injected adapter contract; the test verifier is deliberately non-cryptographic. No production AAP/wallet signature, key-status, or durable revocation-registry adapter is connected.
3. `spent_before` and `spent_after` belong to the isolated escrow candidate. There is no canonical global capability registry, atomic shared counter across multiple transactions, block ordering, or concurrency-safe reservation/consumption in `MonetaryLedgerState`.
4. The candidate does not wire capability state into TXN4/PMT4 consensus execution, monetary state root, durable monetary snapshot, branch replay/reorg, node/mempool/peer paths or external-CAS recovery.
5. The grant currently models amount limits, not the complete CP-0567 fee-cap policy; its counterparty/action scope is intent-specific rather than a general canonical recipient/service/asset policy registry. These differences require explicit mapping, not assumptions.

### 11.7 Revised no-duplicate implementation sequence

1. Treat PR #93 / CP-0475 QVAAC as the existing application-level capability and escrow prototype. Review its complete code/tests and dependency chain; do not rebuild its existing grant, fulfilment, refund, event or receipt mechanisms.
2. Produce a concise gap matrix mapping QVAAC grant fields and transitions to CP-0567 requirements (including fee caps, capability lifecycle, canonical nonce/replay, atomic multi-payment counters, owner debit, block ordering, revocation, and branch semantics). Prefer extending/reusing the existing types where their semantics fit; introduce a new type only for a demonstrated incompatible consensus requirement.
3. Separately design how the adapted capability state becomes part of `MonetaryLedgerState`, block execution, state root, versioned snapshot and branch replay. This is the genuinely missing protocol/consensus layer.
4. Only after the PR90–93 dependency chain is reconciled and the gap matrix is reviewed should code integration be proposed. Keep all new work isolated from Genesis, supply, TXN4 wire bytes and live network until the explicit consensus/wire-format gates are approved.

**Audit correction:** The earlier A1C recommendation for a new pure Rust capability module is superseded by this repository-wide finding. The correct next step is reuse-first gap analysis of QVAAC, followed by the missing canonical-ledger integration design—not a parallel implementation.
