# CP-0567 A0 — AI-Agent Payment Authorization Decision Record

- Document ID: CP-0567-A0-ADR-001
- Parent: `CP-0567_AI_AGENT_PAYMENT_AUTHORIZATION_PROTOCOL_DESIGN_CANDIDATE_2026-11-06.md`
- Status: **Provisional design decisions; review required; not consensus-frozen**
- Date: 2026-11-06
- Scope: Resolve the MVP design choices needed before A1 pure reference-model work

## Decision summary

| Topic | MVP recommendation | Reason / boundary |
|---|---|---|
| Enforcement location | Native ledger state transition | Aggregate budgets and transfers must be enforced atomically by every validator; a client-only or optional contract check is insufficient |
| Asset scope | Native QZXB only in v1; retain explicit `asset_id` in the schema | Avoid depending on unfinished/general asset semantics; reject unsupported assets, never silently convert |
| Budget accounting | Separate transfer-amount and fee ceilings | Makes owner consent and receipts unambiguous; check both per-payment and aggregate limits with checked arithmetic |
| Registration/revocation | Explicit owner-authorized on-chain state transitions | Gives all nodes the same reorg-aware state and audit trail |
| Validity | Block-height `not_before` and exclusive `expires_at` | Avoids wall-clock drift in consensus-critical authorization |
| Ordering | Canonical sequential transaction execution order within a block | Registration, payment, and revocation races become deterministic and vector-testable |
| Payment nonce | Exact per-capability next-sequence value | Simple replay protection and deterministic ordering; out-of-order requests must be re-signed/resequenced |
| Recipient scope | Mandatory bounded exact-recipient allowlist | Fail-closed MVP; no wildcard or accidental unrestricted semantics |
| Service/action scope | Defer arbitrary service/action authorization; v1 authorizes native transfers only | On-chain labels do not prove off-chain service delivery; arbitrary call grammar is a separate protocol design |
| Human approval thresholds | Defer from v1 | Requires a separate canonical second-approval model; do not simulate it with UI prompts |
| State pruning | Preserve a tombstone/replay guard; prune only with verifiable historical proof strategy | Expiry must not permit identifier reuse or replay after pruning |
| Cryptography | Explicit scheme ID and domain separation; use only schemes already supported in the production verification path | Experimental PQ support in a candidate path is not production-wide PQ authorization |
| PQ scope | Not a v1 acceptance claim | Whole-network PQ transition remains incomplete; algorithm agility is required but does not itself provide PQ security |

## 1. Native ledger primitive, not client-only policy

**Decision:** implement v1 as a native, deterministic ledger state machine. A future smart-contract interface may expose or compose with the primitive, but must not be the sole security boundary unless the contract runtime itself guarantees mandatory execution for every relevant spend path.

**Rationale:** aggregate spend limits are shared mutable state. If two individually valid requests race for the remaining balance, every validator must serialize the budget check and debit with the transfer and fee settlement. Wallet preflight, RPC simulation, agent code, and mempool admission are advisory only.

**Required invariant:** no accepted payment can debit the owner account through the delegated path without an atomic capability-state transition.

## 2. MVP asset and budget model

- v1 permits only native QZXB. Keep an explicit asset identifier in the canonical schema for forward compatibility, but reject all unsupported asset IDs.
- `max_amount_per_tx` and `max_total_amount` count transfer value only.
- `max_fee_per_tx` and `max_total_fee` count fees separately.
- All values use the chain's canonical integer base units; no floating-point values, decimal strings, implicit rounding, or off-chain conversions in consensus.
- Use checked arithmetic. Overflow, underflow, missing counters, or inconsistent state means rejection with no partial mutation.
- The aggregate spend check must include the current payment before committing: `spent_amount + amount <= max_total_amount` and `spent_fee + fee <= max_total_fee`.
- A failed payment changes neither transfer balance nor capability counters nor nonce state.

## 3. Registration, revocation, and block ordering

- Registration and revocation are explicit owner-authorized state transitions included in the canonical ledger history.
- Process transactions in the block's canonical execution order. Each operation observes the state resulting from all earlier operations in that order.
- If a valid payment is ordered before a revocation in the same block, it may execute under the then-active policy; payments ordered after the revocation must fail. This exact rule must be encoded in vectors and user-facing confirmation language.
- Registration ordered before a payment can authorize that payment in the same block only if the protocol explicitly permits same-block use and the canonical state machine processes it first. For MVP, **require registration to be included in an earlier block** before first use. This avoids surprising same-block activation and simplifies wallet confirmation.
- Revocation is effective at its canonical execution position, but inclusion is not finality. The UI must distinguish submitted, included, and finalized revocation. A reorg restores the canonical pre-reorg state; clients must not claim irreversible revocation before the chain's finality rule.
- Owner-wide emergency invalidation, if later introduced, must be an explicit owner-authorized epoch increment, not a third-party freeze primitive.

## 4. Validity and nonce rules

- Use block heights only for v1: `not_before <= current_height < expires_at`.
- `expires_at` is exclusive. Test height `expires_at - 1` (valid) and `expires_at` (invalid).
- Each capability has a monotonically increasing `next_nonce`. A payment is valid only when its nonce exactly equals `next_nonce`; increment only after the full payment transition succeeds.
- Duplicate, stale, or future nonces fail closed. Concurrent requests compete for the next sequence; only the first canonically executed valid request can consume it.
- Nonce and counters must be restored exactly after restart and reorg.

## 5. Scope and human approval

- Every v1 capability must contain a non-empty, bounded list of exact recipient account identifiers. No wildcard, prefix match, arbitrary recipient, or empty-list-as-unrestricted behavior.
- v1 authorizes native transfers only. Do not claim it proves a service was delivered. Service/action identifiers, contract method selectors, and argument-level constraints are deferred until a separate canonical scope grammar and threat model exist.
- Free-text purpose may be shown in wallet UX as a non-authoritative note; consensus must not interpret it.
- Defer automatic human-approval thresholds from v1. A later version may require an additional owner/multisig signature over the exact payment bytes. A UI confirmation without a cryptographically bound approval is not a protocol control.

## 6. State growth, tombstones, and proofs

- Active capabilities cannot be pruned.
- On revocation or expiry, retain a compact tombstone sufficient to reject replay, duplicate registration, and stale policy versions.
- Do not reuse a capability identifier or owner-side registration nonce.
- Detailed historical data may be compacted only after a separately specified checkpoint/archive proof mechanism can establish the prior registration, spend totals, revocation/expiry, and tombstone commitment.
- State pruning must be tested across restart, checkpoint restore, reorg, and historical proof verification before activation.

## 7. Cryptographic compatibility

- The canonical capability and payment encodings include explicit version and signature-scheme identifiers, network/domain binding, and dedicated domain separation.
- v1 may use only an authorization scheme that the actual production ledger verification path supports and whose key ownership semantics are defined. Do not assume a TXN4 candidate verifier is production-wired.
- No automatic downgrade or fallback to a weaker signature scheme is allowed. Unknown scheme IDs fail closed.
- Do not require experimental ML-DSA-65 in v1 unless its exact production verification path, canonical encoding, transaction-size/resource limits, wallet custody, and migration behavior are independently specified and tested.
- Algorithm agility is a compatibility property, not proof that the current network is post-quantum.

## 8. A1 pure reference model — required interface and invariants

A1 should implement a pure deterministic evaluator over immutable input state and one operation, returning either a typed rejection or a proposed new state plus receipt fields. It must not perform I/O, RPC, signing, clock reads, network access, or hidden mutable global state.

Minimum model operations:

1. `RegisterCapability`
2. `ExecuteDelegatedPayment`
3. `RevokeCapability`
4. `AdvanceHeight` (test harness/state context only; not necessarily a transaction)

Minimum state:

- network/domain identifier;
- current block height;
- owner account and capability registry;
- canonical policy bytes/hash and version;
- active/revoked/expired state and tombstone;
- amount and fee spent counters;
- exact next nonce;
- deterministic receipt/transition commitment inputs.

Required invariants:

- rejected operation returns byte-for-byte/equality-identical input state;
- accepted payment changes transfer result, amount counter, fee counter, and nonce together;
- aggregate and per-transaction ceilings are never exceeded;
- no wrong-network, wrong-owner, wrong-agent, wrong-asset, wrong-recipient, stale nonce, expired, revoked, or unsupported-scheme operation succeeds;
- operation order is deterministic and reordering tests demonstrate the documented semantics;
- replayed operation cannot produce a second spend;
- integer boundary and overflow tests never wrap;
- state transitions are deterministic across repeated executions and platform builds.

## 9. A1 adversarial vector minimum

Create table-driven positive and negative vectors for:

- valid registration and first payment in a later block;
- payment before registration in same block (rejected because registration must predate use);
- payment before and after same-block revocation (position-dependent as specified);
- exact amount and fee ceilings; one base unit over each ceiling;
- two payments racing for final remaining amount or fee budget;
- duplicate, stale, skipped, and maximum-width nonce;
- recipient absent from allowlist, empty allowlist, oversized allowlist;
- `not_before - 1`, `not_before`, `expires_at - 1`, and `expires_at`;
- wrong network/domain, asset, owner, agent, policy version, and signature scheme;
- replay after revoke/expiry and after tombstone compaction simulation;
- reorg rollback of registration, payment, and revocation;
- restart snapshot round-trip preserving counters, nonce, status, and tombstone;
- checked arithmetic at zero, maximum integer, and overflow boundaries.

Every negative vector must assert both the exact rejection category and unchanged state. Fuzz the canonical decoder and evaluator after the deterministic vectors are stable.

## 10. Explicit non-goals for A1

A1 must not modify consensus, node CLI, peer protocol, RPC, wallet production behavior, monetary policy, genesis, mining, or live balances. It must not claim service delivery, zero-knowledge privacy, post-quantum security, production integration, or public availability. It is a reference model used to expose logic defects before any protocol integration proposal.

## 11. Exit gate before A1 implementation is considered ready

- The project owner reviews this provisional decision record.
- A reviewer checks consistency with current QRun account, fee, transaction, state, reorg, and finality semantics.
- All unresolved dependencies are recorded with exact source paths and owners.
- A1 API and error taxonomy are specified before code.
- No consensus or production path is modified during A1.

## 12. Open questions intentionally retained

1. Exact production account authorization primitive and owner-key rotation behavior.
2. Canonical integer widths and encoding library/path.
3. Actual fee debit semantics and whether fees are paid by owner account or a separately funded capability account.
4. Exact canonical block transaction ordering and finality guarantees in the current QRun implementation.
5. Existing persistent-state and checkpoint mechanisms available for capability registry/tombstones.
6. Maximum recipient allowlist size and bounded state/verification cost.
7. Whether registration fee and revocation fee are paid by owner or relayer, and how relayers are reimbursed.

These are implementation dependencies, not assumptions. Resolve them against actual code before A1 or any consensus work.

---

This record narrows the design candidate; it does not authorize protocol changes or imply that delegated AI-agent payments are implemented.
