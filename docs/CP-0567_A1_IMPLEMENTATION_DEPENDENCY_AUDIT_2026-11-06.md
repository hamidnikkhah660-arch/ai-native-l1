# CP-0567 A1 — Implementation Dependency Audit

- Document ID: CP-0567-A1-AUDIT-001
- Date: 2026-11-06
- Status: **Source inspection only; provisional; not an implementation approval**
- Parent design: `CP-0567_AI_AGENT_PAYMENT_AUTHORIZATION_PROTOCOL_DESIGN_CANDIDATE_2026-11-06.md`
- Decision record: `CP-0567_A0_DECISION_RECORD_AI_AGENT_PAYMENT_AUTHORIZATION_2026-11-06.md`
- Inspected working tree: `docs/qrun-master-roadmap-20261106` at `86477692f8b491eace08cafa9397bd92fee2fcfe`

## 1. Purpose and scope

This audit compares CP-0567 A0 assumptions with the Rust source present in the inspected working tree. It does not claim that the inspected modules are all production-wired, that the source branch is a frozen Mainnet release, or that the findings constitute an independent security review.

No Rust source, consensus behavior, transaction format, Genesis data, monetary policy, wallet behavior, or live balance was changed by this audit.

## 2. Directly observed source facts

### 2.1 Legacy TXN2 ledger substrate

Source: `src/native/pow_bench/src/state_machine.rs`

- `AccountState` contains `balance: u64` and `nonce: u64` (lines 45–49).
- `Transaction` contains network ID, sender, recipient, nonce, amount, fee, exclusive `expires_at`, and signature (lines 51–63). It has no asset identifier or delegated-capability identifier.
- `LedgerState` stores network ID, height, last timestamp, tip hash, aggregate fee pool, and a BTreeMap of accounts (lines 174–182). No delegated capability registry, per-capability budget counters, policy version, revocation status, or tombstone appears in this state structure.
- Block encoding and decoding preserve the transaction vector sequence (lines 359–440); candidate execution iterates `for tx in &block.transactions` in that sequence (lines 665–725). This is evidence of input-vector execution order in this module, not proof that every live block producer/import path supplies or preserves the same canonical order.
- `apply_transaction` requires the next account nonce to equal prior nonce + 1, using checked addition (lines 811–824).
- The normal sender debit is checked `amount + fee`; insufficient funds reject (lines 826–832). The fee is added to the aggregate `fee_pool` with checked arithmetic (lines 833–836).
- A self-transfer follows a special branch: it deducts the fee and advances the nonce without crediting a separate recipient (lines 838–848). CP-0567 must explicitly define whether delegated self-payments are prohibited or inherit this exact behavior; aggregate delegated amount accounting must not accidentally diverge from actual ledger debit semantics.
- The snapshot codec stores network, height, timestamp, tip hash, fee pool, and sorted account balance/nonce records (lines 541–576 and 579–662). It contains no capability state. The checksum is explicitly described as corruption detection, not authenticity (lines 541–545 and 579–580).

### 2.2 Explicit transaction authentication

Source: `src/native/pow_bench/src/transaction_auth.rs`

- The inspected module describes explicit Ed25519 transaction authentication; account IDs are derived from registered public keys.
- Its module comments leave production key custody, migration, and independent cryptographic review open.
- This source does not establish a production-ready delegated-agent key ownership or owner-key rotation model.

### 2.3 TXN4 / hybrid monetary candidate

Sources:
- `src/native/pow_bench/src/v4_account_identity_candidate.rs`
- `src/native/pow_bench/src/v4_transaction_mempool_candidate.rs`
- `src/native/pow_bench/src/state_machine.rs`
- `src/native/pow_bench/src/chain_admission.rs`

- TXN4 has its own versioned hybrid authorization envelope, account identity scheme, nonce, amount, fee, expiry, and signature material.
- The TXN4 mempool module states explicitly that it is not wired into the node CLI, peer protocol, RPC, or production runtime; its local sender/nonce ordering is a pool policy, not a consensus ordering rule.
- The separate V4 hybrid monetary block path is explicitly described as not yet wired to the PMT3/PFM3 node import/fork-choice runtime (`state_machine.rs`, around lines 1508–1510).
- `chain_admission.rs` describes the V4 path as a candidate admission API pending PMT4/PFM4 and node runtime dispatch (around lines 288–291).
- Therefore, the presence of a real ML-DSA-65 verifier in this candidate path does not establish that TXN4 is the production transaction path or that agent authorization can safely depend on it.

### 2.4 Import and persistence boundary

Source: `src/native/pow_bench/src/chain_import.rs`

- `ChainImportService::import_bytes` stages a cloned state, validates/admit/replays the block, saves the staged snapshot atomically, and only then publishes the in-memory state (around lines 105–137).
- The inspected service is a linear snapshot importer. This observation alone does not identify a canonical fork-choice/reorg service or prove how a future capability registry would be restored across competing branches.
- The existing legacy snapshot format has no capability counters or tombstones. A capability state migration, persistence format, checkpoint commitment, and reorg rollback strategy must be designed explicitly rather than inferred from the existing account snapshot.

## 3. A0 assumptions that require correction or proof before A1

1. **Expiry clock:** Legacy TXN2 uses block timestamp for exclusive transaction expiry. The TXN4 candidate currently supplies a candidate timestamp to expiry checks. A0's proposed block-height capability validity is a new policy choice, not an already-established convention. Define capability expiry separately from payment-envelope expiry and test boundary semantics.
2. **Canonical order:** The inspected ledger executes block transaction vector order. The TXN4 mempool's sender/nonce sort is explicitly local-only. Identify the actual canonical block-body ordering rule for the intended release path before specifying registration/payment/revocation ordering.
3. **Asset scope:** The inspected TXN2 account ledger is a single native-balance ledger with no transaction asset ID. “QZXB only” is consistent with that limited substrate, but an asset identifier in a future capability schema must not imply generic multi-asset support.
4. **Fee accounting:** Normal TXN2 payments debit amount plus fee from the sender and credit the fee pool. Self-transfer has a special amount-handling branch. Determine the exact intended V4/production fee semantics and delegated receipt semantics before freezing budget counters.
5. **Authorization:** Establish the production account authentication primitive, key registry lifecycle, owner-key rotation, and how an agent key is independently bound to an owner-authorized capability.
6. **Persistence and reorg:** Identify the actual selected-chain fork-choice, durable state, checkpoint, and recovery components for the release target. Do not assume the linear `ChainImportService` snapshot is sufficient for capability state.
7. **Finality:** No finality guarantee is established by this source inspection. Revocation UX and any “finalized” receipt must wait for a documented and tested finality contract.

## 4. A1 readiness gate

A1 pure reference-model implementation remains **blocked on source-path resolution**, not on the general capability concept.

Before writing A1, record exact source paths and tests for:

- the intended release branch's canonical account state and transaction execution entry point;
- production account authentication and key rotation;
- fee debit, fee pooling, self-transfer, and miner/reward accounting;
- canonical block transaction ordering;
- selected-chain fork choice, reorg rollback, persistent snapshots, checkpoint and restart;
- transaction/capability canonical encoding and integer widths.

Then revise A0 where its proposed model differs from verified implementation semantics. If no production-wired path exists for a required behavior, record that as an integration dependency rather than pretending it is implemented.

## 5. Safe next action

The next safe action is a read-only source-path audit against the intended release/base branch and its actual node runtime entry points. After the dependencies are resolved, specify the pure A1 API, typed rejection taxonomy, immutable-state transition contract, and deterministic vectors.

A1 must remain isolated: no consensus, node CLI, peer protocol, RPC, wallet production path, Genesis, monetary policy, or live ledger changes.

---

This audit records source observations and unresolved dependencies only. It does not authorize a merge, consensus change, production integration, public availability claim, or post-quantum security claim.
