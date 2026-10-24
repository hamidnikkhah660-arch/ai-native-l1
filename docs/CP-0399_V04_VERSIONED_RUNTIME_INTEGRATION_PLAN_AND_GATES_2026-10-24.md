# CP-0399 — v0.4 Versioned Runtime Integration Plan and Gate Evidence

**Date:** 2026-10-24  
**Status:** Planning and evidence only. This change does not activate v0.4 in a node runtime, freeze economics, or close Gate 2 or Gate 8.

## Executive state

The v0.4 monetary work now has candidate allocation accounting, a Genesis manifest, a Genesis-to-ledger bridge, QZL4 snapshot support, independent Python vectors, an explicit mining schedule, and a profile-bound candidate atomic transition. CP-0398 remains isolated from live producer/importer paths. This document defines the order and acceptance criteria for a future, reviewable integration; it is not evidence that the criteria have already been met.

Validated baseline before this CP-0399 documentation/diagnostic patch:
- Commit **3b5c86d47bebdc67bfefd0cb0abb82512547895c**.
- CI run [40098084960](https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/40098084960): both Rust validation and Windows PMT4/TXN4 loopback jobs succeeded for that exact SHA.
- [PR #61](https://github.com/hamidnikkhah660-arch/ai-native-l1/pull/61) was open and unmerged at the time of inspection.
- The baseline full offline test suite completed successfully. This does not replace the earlier recorded one-test transient failure; see the separate spawn investigation.

## Current implementation boundaries

Candidate modules and independent vectors:
- **src/native/pow_bench/src/monetary_allocation_v04_candidate.rs**
- **src/native/pow_bench/src/monetary_genesis_v04_candidate.rs**
- **src/native/pow_bench/src/monetary_ledger_v04_candidate.rs**
- **src/native/pow_bench/src/monetary_issuance_v04_candidate.rs**
- **src/native/pow_bench/src/monetary_transition_v04_candidate.rs**
- **simulations/quantumzxb_v04_genesis_vectors.py**
- **simulations/quantumzxb_v04_ledger_snapshot_vectors.py**
- **simulations/quantumzxb_v04_issuance_schedule_vectors.py**
- **simulations/quantumzxb_v04_transition_profile_vectors.py**

Runtime integration must be audited against the actual producer/importer and state boundaries, including **state_machine.rs**, **chain_import.rs**, **private_testnet_node.rs**, current MBK3/MBK4 decoding and existing reward calculation. Do not infer integration from module registration or passing unit tests. QZCP and QZB4 are currently candidate formats; QZL4 does not automatically become profile-bound merely because the candidate transition binds a profile.

## Non-negotiable invariants

1. No silent change to legacy MBK3/MBK4 semantics or current monetary policy.
2. No network may start using v0.4 unless a reviewed, explicit network profile and activation rule selects it.
3. A peer-supplied reward value is never authoritative. Producer and importer must independently derive the allowed reward from the same frozen profile and block height.
4. Invalid profile, Genesis binding, parent, height, timestamp, claimed subsidy, state root, cap, accounting invariant or authorization fails before any live state mutation.
5. A block is accepted only after one staged transition has validated transactions, reward issuance, burn, bucket ceilings, total supply and the resulting canonical state root; commit occurs once.
6. Unknown versions fail closed. Downgrade and migration require explicit rules and tests; there is no automatic fallback from v0.4 to legacy processing.
7. No economic schedule defaults are inferred from test fixtures. The test subsidy and halving interval are not proposed production parameters.
8. Checksums are not signatures, freshness proofs or anti-rollback protection.

## Ordered integration plan

### Phase A — Freeze the reviewed profile before touching live call sites

**Required work**
- Specify the network identifier, Genesis manifest hash/root, monetary policy fingerprint, profile fingerprint, encoding versions, block activation height and the approved mining reward schedule.
- Record who approved the policy and the source/revision of that approval in a versioned manifest.
- Define behavior for pre-activation blocks, post-activation blocks, unknown profiles and invalid profile bindings.
- Resolve how profile state is persisted and recovered without treating the existing QZL4 envelope as profile-aware by assumption.

**Acceptance evidence**
- A reviewable canonical profile fixture and independent byte-level vectors.
- Explicit rejection vectors for wrong network, wrong Genesis, wrong policy fingerprint, unknown version and invalid activation.
- No live producer/importer changes until the profile and schedule are approved.

### Phase B — Add an explicit version-dispatch boundary

**Required work**
- Trace and document the concrete producer, block validation/import, reward calculation, fork-choice/reorg and snapshot/restart call sites.
- Implement a version-dispatch adapter that selects legacy versus v0.4 rules from the configured network profile and activation rule.
- Keep the legacy decoder and transition path available for the exact historical versions they are intended to support.
- Reject ambiguous or unsupported block/profile combinations before calling state mutation.

**Acceptance evidence**
- Call-graph and compatibility tests for legacy-only, v0.4-only, pre-activation, post-activation, unknown version and wrong-profile cases.
- Byte-for-byte legacy fixtures remain unchanged.
- No implicit mixed-version transition.

### Phase C — Make producer and importer use one consensus transition contract

**Required work**
- Producer computes the subsidy locally from the frozen schedule and builds a candidate block from the staged result.
- Importer decodes the candidate block and recomputes the allowed reward; it must not trust the peer's claimed subsidy.
- Stage all transfer/application, mining issuance, burn, bucket accounting, supply checks, state-root derivation and block commitment before committing.
- Recompute parent/height/timestamp/profile bindings during import and ensure producer/importer have identical acceptance semantics.

**Acceptance evidence**
- Same-input producer/importer parity tests and independent vectors across each reward boundary.
- Forged subsidy, cap overflow, double issuance, invalid burn, wrong state root and invalid authorization are rejected with unchanged state.
- Replay of a valid block derives the same state root and block identifier on a clean process.

### Phase D — Reorg, snapshot and restart consistency

**Required work**
- Identify the canonical source of state during fork choice and reorganization; avoid mutating canonical state while merely validating a competing branch.
- Define a new explicitly versioned snapshot envelope if profile-bound state does not fit the current version. Do not silently reinterpret QZL4.
- Bind the saved profile/version and monetary root; validate total live supply, accounting counters, mining counters and recomputed state root on restore.
- Specify crash behavior around write, sync, replacement, checkpoint and recovery boundaries.

**Acceptance evidence**
- Deterministic replay, reorg rollback/re-apply, old/new snapshot compatibility, corruption, wrong-profile, truncated-input and restart tests.
- Process termination at documented commit boundaries leaves only a known complete prior or new state.
- Import/restart/replay from the same block history yields identical state and root.

### Phase E — Adversarial, cross-platform and independent review

**Required work**
- Run the relevant suite on Windows and a second supported platform; preserve failure evidence rather than masking it.
- Stress concurrent import/producer access, repeated restarts, malformed lengths, conflicting branches and policy-boundary heights.
- Obtain independent security and consensus review; classify and resolve all critical/high findings before release consideration.
- Publish reproducible commands, exact commit SHAs and logs/artifacts for each release candidate.

**Acceptance evidence**
- No unresolved consensus-critical test failures.
- Differential vectors pass in Rust and the independent oracle.
- Independent review findings and closure evidence are public and tied to a revision.

## Gate 2 — Consensus / state transition checklist

Gate 2 remains **OPEN**. Checkboxes are deliberately unchecked because the evidence is not yet complete.

- [ ] Network profile, Genesis manifest, policy and approved reward schedule are frozen and versioned.
- [ ] Live producer and importer select the same explicit versioned profile and transition.
- [ ] Consensus derives reward locally and rejects peer-selected amounts.
- [ ] Transfers, issuance, burns, authorizations, bucket caps, supply caps and root calculation are atomic.
- [ ] Legacy MBK3/MBK4 compatibility and no-downgrade behavior are tested.
- [ ] Replay, fork choice, reorg, snapshot and restart operate on the same canonical v0.4 state.
- [ ] Rust implementation matches independent vectors across valid and invalid cases.
- [ ] Cross-process, malformed input, crash/recovery and concurrency tests pass on supported hosts.
- [ ] Independent security review finds no unresolved critical/high issue.
- [ ] Release/activation decision is explicit and documented; CI success alone is not activation approval.

## Gate 8 — Anti-rollback / external CAS checklist

Gate 8 remains **OPEN**. Local checksum, lock, test double or on-disk high-water file is not enough.

- [ ] An external CAS service exists in a separate rollback/trust domain from the node's state disk.
- [ ] Atomic compare-and-swap is executed by that service, with documented conflict semantics.
- [ ] Receipt verification keys are pinned and recoverable independently of the snapshot being checked.
- [ ] The live runtime calls the service and fails closed on invalid receipt, stale generation, timeout or conflict.
- [ ] Multi-host and independent-volume tests cover rollback, restore, race, timeout, retry and idempotency.
- [ ] The trust-domain and threat model receive independent security review.

## Proposed next merge-sized implementation

After the profile and schedule receive explicit approval, implement only the version-dispatch adapter and producer/importer integration tests in a separate reviewable step. Before changing live logic, attach a call-site map, compatibility matrix and independent vectors. Do not connect candidate QZCP/QZB4 to a live node or make release claims as part of a planning-only change.
