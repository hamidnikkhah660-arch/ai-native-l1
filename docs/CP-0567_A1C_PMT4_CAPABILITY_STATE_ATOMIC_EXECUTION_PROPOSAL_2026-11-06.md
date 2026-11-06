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

### 11.8 QVAAC-to-CP-0567 gap matrix (reuse boundary)

The following is the practical reuse map from the QVAAC source at PR #93 commit `801471c90b307a5c12f6785173d2d8986ffb74d3` to the narrower CP-0567 A0 native-transfer MVP. “Present” means present in the offline candidate model, not production consensus support.

| CP-0567 requirement | Existing QVAAC candidate | Required treatment |
|---|---|---|
| Network binding | Present in intent, grant and evidence bundle | Reuse canonical domain rules; verify against PMT4 network/manifest at ledger boundary |
| Capability/grant identifier | `grant_id` present | Reuse only after defining canonical ID, uniqueness and permanent no-reuse rules |
| Owner/principal identity | `principal_id` present; test intent uses buyer as principal | Map to the actual QRun owner account and its authorization primitive |
| Agent identity/key | `agent_id` and `agent_key_id` present | Reuse identity binding; add per-payment agent authorization/signature if retained by A0 |
| Asset binding | Intent binds `asset_id` and `payment_asset_id`; grant binds `asset_class` and intent digest | Make native QZXB asset ID explicit in canonical capability state; reject every unsupported asset |
| Per-payment amount ceiling | `max_per_transaction` present | Reuse checked amount rule |
| Aggregate amount ceiling | `max_cumulative_spend` plus `spent_before`/`spent_after` in one escrow candidate | Replace local escrow-only accounting with one canonical capability counter shared by all payments |
| Fee ceiling | No separate per-payment or aggregate fee counters | Add `max_fee_per_tx`, `max_total_fee`, and canonical `spent_fee` accounting |
| Recipient restriction | One `counterparty_id` bound to the intent | Adapt to A0's bounded exact-recipient allowlist; define recipient account ID semantics |
| Service/action restriction | `allowed_actions` bitmask exists for QVAAC escrow actions | A0 v1 defers service/action semantics; do not carry the QVAAC bitmask into consensus without a frozen action grammar |
| Validity window | `not_before` and exclusive-style `expires_at` checks use supplied timestamp | Define block-height validity for consensus; do not silently reuse wall-clock checks |
| Registration sequence / revocation epoch | `sequence` and `revocation_epoch` fields present | Keep as signed grant metadata only until backed by owner-authorized canonical register/revoke transitions and durable registry |
| Per-payment replay nonce | No distinct capability-use `next_nonce` in the grant/escrow payment call | Add exact per-capability next nonce and consume only after successful atomic payment |
| Owner signature / grant verification | `QvaacGrantVerifier` adapter interface exists | Production owner-signature/key-status verifier is missing; test verifier is non-cryptographic |
| Agent signature on each payment | No distinct signed delegated-payment envelope in the current funding call | Add only if required by final A0 wire/security design; bind every payment field and capability ID |
| Revocation registry | Adapter rechecks grant and test verifier models epoch 1 vs 2 | No persistent global registry/tombstones or on-chain revocation transition; implement in canonical ledger state |
| Conditional fulfilment / escrow | Present: evaluator proof, acceptance/rejection, deadline refund and receipt | Keep as an application/escrow extension; A0 native-transfer v1 must not claim service delivery or require escrow semantics |
| Atomic multi-payment/concurrency safety | Local candidate mutates one escrow object after checks | Not shared across simultaneous escrows, transactions or validators; move counters and balances into one cloned block candidate |
| State root / durable snapshot | Hash-linked local events/receipt only | Add registry/counters/tombstones to monetary state root and versioned snapshot |
| Fork/reorg/restart | Not wired to canonical PMT4 branch replay or monetary snapshot | Derive state from branch parent and ordered actions; prove reorg, switch-back and restart invariants |
| Node/mempool/peer integration | Offline candidate only | No production runtime wiring; separate integration gate after deterministic ledger model |

**Decision from this matrix:** QVAAC already supplies a useful application-level grant schema, evidence checks, escrow/fulfilment lifecycle and receipt pattern. CP-0567's genuinely new work is not another grant object: it is the missing canonical QZXB ledger registry, explicit fee budget and capability nonce, owner-authorized register/revoke actions, atomic shared spend accounting, state-root/snapshot commitment, and branch/reorg integration. The v1 native-transfer policy intentionally excludes QVAAC's service-fulfilment and escrow requirements; preserve those as a later composable layer rather than duplicating or forcing them into consensus.
### 11.9 Full branch ancestry and monetary-policy reconciliation gate

This section supersedes the narrower PR90-93-only dependency reference in 11.7 item 4. A fresh GitHub metadata and Git-ancestry audit on 2026-11-06 established that PR #93 is not a branch directly from `main`. Its verified primary dependency lineage is:

`main` -> PR #61 -> #62 -> #63 -> #65 -> #66 -> #67 -> #68 -> #69 -> #70 -> #87 -> #88 -> #89 -> #90 -> #91 -> #92 -> #93.

- PR #61 is the root branch based on `main`; it carries the QZB4 v2 / QZBE monetary and fork-choice candidate, local persistent archive, external-CAS candidate, and offline-only smoke. Its own PR body says canonical producer/importer/runtime integration was not yet switched to QZBE.
**Change-size warning:** the PR #90 increment over PR #89 is only 6 files (+855/-26 lines), but the complete PR #93 branch compared with `main` is 198 files (+56,149/-656 lines). The large cumulative change is mostly inherited candidate history, not new QVAAC functionality. This is strong evidence against merging the full stack as one unit; isolate and port only reviewed components.
- PRs #62-#70 extend that isolated QZBE v0.4 candidate line (body-bound digest, bounded miner, loopback transaction/Noise/runtime tests, dispatch, profile lock, and tokenomics boundary). PR #64 is a sibling of #65 on the #63 base, not an ancestor of #93.
- PR #84 was merged into the PR #71 work branch, and PR #71 was then merged into the PR #70 branch. Git ancestry confirms both merges are present in the PR #70 branch; neither merge is a merge into `main`.
**Incremental component inventory (diffs against each immediate parent):**
- PR #87: 12 files, +2,741/-116; adds the disk provider candidate (1,062 lines), Noise transport candidate (631 lines), and modifies the v0.5 runtime/fork-store path.
- PR #88: 2 files, only 2 insertions/2 deletions; documentation and release-hash update, not a second provider implementation.
- PR #89: 6 files, +1,064/-17; adds the independent-floor store candidate (786 lines) and fork-store integration.
- PR #90: 6 files, +855/-26; adds the local-node external-CAS startup path (789-line node change) and runtime adjustment.
- PR #91: 6 files, +972; adds a provider executable (570 lines) and AWS KMS signer candidate (388 lines).
- PR #92: 3 documentation/handoff files, +716 lines; vision and asset-passport design, no runtime code.
- PR #93: 7 files, +3,380/-2; adds QVAAC settlement (1,478 lines), QVAP passport (1,594 lines), and their design/registration changes.
- PR #87 starts from PR #70, and #88-#93 continue the stacked branch. PR #93's base branch `work/qrun-qvap-ci-base-20261030` is exactly PR #92's head commit `9f7b9bb4804a3db0f7d26c56be07cf93c16edbf3`.
**External-CAS security boundary from the candidate source itself:** PR #87's disk provider is explicitly single-host and does not protect against restoring the entire provider filesystem from backup. PR #89's floor detects node-archive rollback only while the separate floor remains intact; it also does not protect against restoring the floor or whole host. PR #91's AWS KMS adapter can keep the ML-DSA private key in KMS and verify key metadata/public-key pin/challenge signatures, but this does not make provider state independently monotonic. The branch therefore still lacks demonstrated off-host anti-rollback and independently administered provider operations; CI/local tests do not close those production gaps.
- The stack is not a single review-ready change set: PR #61 and #70 are open non-Draft, the intermediate candidate PRs are mostly Draft, and their validation/check coverage differs. Passing checks on selected heads does not certify every inherited commit or resolve branch integration.

**CI inventory at audit time:** PR #61, #62, #70, #71, and #87-#93 show passing check rollups on their recorded heads (PR #92 is documentation-only and its rollup is inherited from the same stacked workflow). PRs #63-#69 have no individual check rollup on their current heads; PR #70 is a checked descendant of that line and passed its recorded validation. PR #64 is a sibling branch and is not part of PR #93 ancestry. This is evidence about recorded checks, not independent security review or permission to merge.

**Direct branch-content confirmation:** the PR #93 tree contains `docs/CP-0437_QRUN_FULL_SUPPLY_GENESIS_DIRECTION_2026-10-28.md`, does not contain the later `CP-0566D` decision file, and its README still calls CP-0437 the current direction: 10B QZXB to one owner at Genesis, zero later issuance, and zero block subsidy. The same assumption is repeated in inherited CP-0445/0446/0447/0456/0464/0468 material. This is a concrete source/documentation mismatch, not merely stale PR prose.

**Monetary-policy conflict requiring resolution before any merge/rebase:** PR #70's body explicitly describes CP-0437 as the current 10B all-founder Genesis / zero post-Genesis mint / zero-subsidy direction. The owner's later CP-0566D decision selects 1B founder Genesis, up to 3B PoW security issuance, and six conditional 1B ceilings. CP-0566D supersedes CP-0437 for future production design. Therefore the inherited #70/#87-93 stack must not be merged as-is or treated as aligned with current economics. Reconcile all inherited Genesis, supply, subsidy, mining, README, manifest, and candidate-profile assumptions against CP-0566D and issue #136 first. Preserve CP-0437 as historical evidence.

**Integration decision:** keep PR #61-#70 and #87-#93 as historical candidate branches and source references until reviewed. Do not merge the entire stack merely to obtain QVAAC or external-CAS functionality. If a component is selected for current QRun, create a main-based integration plan, port only the smallest compatible component, reconcile it with PMT4/PFM4/TXN4 and CP-0566D, then run exact-head tests. Reuse QVAAC's application-level grant/escrow model; do not inherit its entire old QZBE branch stack into canonical consensus by default.

### 11.10 Mainline compatibility boundary for the external-CAS candidate stack

A direct tree comparison against `origin/main` confirms:

- Already present on `main`: `external_cas_anchor_candidate.rs`, `store_writer_lock.rs`, `private_testnet_fork_store.rs`, `devnet_node.rs`, and `private_testnet_node.rs`.
- Not present on `main`: `qrun_v05_pow_local_node.rs` and `qrun_v05_pow_fork_runtime_candidate.rs`, which are introduced/extended by the PR #87/#90 candidate stack.
- The current PMT4 peer-smoke entrypoint is `run_monetary_v4_hybrid_peer_smoke` in `private_testnet_node.rs`; it is the current integration target, not the absent v0.5 local-node binary.

Therefore PR #90's node-startup wiring cannot be cherry-picked into current `main` as-is. PR #87's disk provider, PR #89's floor store, and PR #91's KMS signer are useful source references, but their adapters and dependencies must be reviewed against the existing `ExternalCasPin` / `ExternalCasRecord` contract and then integrated deliberately into the PMT4/PFM4 path. Do not revive the old v0.5 binary merely to make the stacked PR compile. The next safe engineering task is a narrow mainline compatibility design for provider open/verify/commit, floor advancement, startup fail-closed behavior, and restart/recovery tests, with independent provider deployment kept as a separate release gate.
