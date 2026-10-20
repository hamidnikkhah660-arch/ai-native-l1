# Native Mainnet Gate 2 and Gate 8 — Integrated Closure Work Plan V01

Date: 2026-10-20
Project identity: QuantumZXB (working name)
Purpose: convert the long-standing open gates into a finite, testable set of engineering deliverables. This plan does **not** mark either gate closed.

## Gate 2 — canonical issuance, Genesis and monetary invariants

### Existing evidence

The repository contains substantial candidate modules and test harnesses for Genesis/state, fixed supply, 10B tokenomics, founder/public-goods/miner budgets, canonical wire formats and separate private-testnet runtimes. All-target Rust tests pass on the curated source release. Those facts are necessary evidence but not sufficient to close Gate 2.

The canonical release ledger records Gate 2 open because the selected monetary profile is not frozen and end-to-end canonical node issuance, Genesis accounting, bucket enforcement and supply invariants are not fully integrated across producer, importer, fork-choice, store/replay and state transition.

### Required outputs

1. **Protocol freeze**: one explicitly selected version of the native block, transaction, Genesis, state snapshot/root, network ID and monetary policy. Resolve current candidate/legacy format boundaries and define activation/migration rules.
2. **Genesis accounting**: validate network ID, exact allocation buckets, account uniqueness, beneficiary identity/key bindings, founder allocation and reserve/treasury policy. Cap all lifetime native issuance at 10,000,000,000 coins, including founder, miner rewards, public goods, gifts/grants and every other value-creation path.
3. **Canonical issuance path**: derive every reward from the frozen height-based subsidy schedule inside the validator, not from peer-provided reward fields. Apply reward + transaction fees + transfers atomically and enforce the supply invariant on every accepted block and snapshot.
4. **Full runtime integration**: connect the single selected version through the canonical block producer/admission/importer, PoW/fork-choice/reorg, persistent store, restart/replay, snapshots and RPC/explorer state. Do not merge isolated candidate profiles by assumption.
5. **Independent conformance evidence**: implement an independent language/reference oracle; freeze byte-level Genesis/block/transaction/snapshot vectors; cover exact 10B boundary and +1, reward schedule boundaries, grants/treasury, overflow, duplicate/replay, malformed inputs, wrong network, conflicting forks/reorgs, restart/replay and fault injection.
6. **End-to-end differential tests**: run two independently built implementations against the same vectors and candidate chain; state roots, balances, issuance counters, canonical tip and replay results must match exactly.
7. **Independent sign-off**: an independent reviewer must inspect economic transitions, serialization/version migration and test evidence; fix all critical/high findings. Owner approval of policy decisions is separate from external audit.

### Gate 2 exit test

Gate 2 is DONE only when all seven outputs are versioned, reproducible in a clean checkout, integrated into one canonical runtime, cross-checked by independent implementations, all adversarial/mutation tests pass, no open critical/high defect remains, and a dated checkpoint references the exact release commit and independent review. Unit tests alone cannot close it.

## Gate 8 — independently protected anti-rollback trust and recovery

### Existing evidence

The repository has FAT1/anchor/CAS/recovery models and extensive local-store crash/process-termination tests. Those tests do not establish an independent production trust domain. A local anchor and a local manifest restored together can roll back together; process termination while the OS remains alive is not physical power-loss evidence.

### Required outputs

1. **Threat model**: enumerate local administrator/host compromise, cloned disk/VM snapshot, old backup restore, concurrent writers, response loss after commit, key loss/revocation, network partition, stale/forked peers, anchor outage, corruption and storage-device cache loss.
2. **Independent trust boundary**: choose a trust provider not restorable along with the canonical node data. Define operators/authority, provisioning, network/deployment binding, trust roots, signing keys, rotation/revocation, key loss recovery, incident process and no-single-person recovery risks.
3. **Exact-successor CAS protocol**: authenticated fresh challenge/receipt bound to network, deployment, policy/version, prior generation+digest and exact next generation+digest. Duplicate identical operations may be idempotent; skips, conflicting operation IDs, stale state, unverifiable receipts and ambiguous timeout states fail closed. Recovery must use a fresh trusted read and never guess.
4. **Canonical runtime integration**: put the independently verified anchor into real state commit/reopen/fork choice/migration/reorg paths. A test model or trait without a deployed independent provider does not close this requirement.
5. **Failure evidence**: adversarial negative tests for stale/tampered/forged receipts, replayed challenges, provider outage, restored old disk, concurrent writers, partial/ambiguous commit, stale snapshot, fork conflict, key rotation and recovery. Demonstrate only the old or exact newly anchored state can be recovered.
6. **Durability qualification**: test actual process kill, VM reset/power-off and storage fault cases across at least two independently administered hosts/platforms. Document filesystem/storage semantics and caveats; do not label a process-kill test as sudden power-loss proof.
7. **Independent security review**: threat-model review and protocol/implementation audit; all critical/high findings resolved before production use.

### Gate 8 exit test

Gate 8 is DONE only when an independent monotonic trust service is deployed/operated outside the node's rollback boundary, canonical integration passes clean-checkout tests, the crash/recovery matrix is reproducible on independent environments, key lifecycle/recovery is documented, and an external reviewer signs off against the defined threat model.

## Execution order and stop rules

- First: inventory actual call sites and version boundaries; pick a single canonical path instead of wiring every candidate. Publish that source map with commit hashes.
- Second: finish Gate 2 integration and independent vectors without enabling public value transfer.
- Third: integrate Gate 8 against the frozen canonical state format; exercise commit/restart/fork paths under fault injection.
- Fourth: public zero-value multi-operator devnet and external security review.
- Only then consider native Mainnet, explorer, CMC/TradingView data discovery, or any value-bearing market.

Do not generate production private keys, pay for an external service, deploy a public listener, send a transaction, create a pool, or expose valuable funds under the existing USD 0.00 spend cap. If a required independent provider or audit cannot be obtained for zero cash, record it as an unfunded external prerequisite, not a fictitious pass.

## Public claim boundary

The project may say the code is public and its local tests passed. It may not say Gate 2 or Gate 8 is closed, that Mainnet is live, that supply is production-enforced, that a public market exists, or that the network is quantum-resistant until the cited acceptance evidence exists.
