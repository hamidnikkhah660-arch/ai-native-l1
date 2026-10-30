# CP-0395 — Versioned v0.4 Runtime Integration Plan (Candidate)

**Status:** Design plan only. No runtime integration is claimed by this document.
**Baseline:** b99aae3789d18ed73ed576ff028b566d5dcb8f3f
**Related work:** PR #61; CP-0391–CP-0394 candidate work.
**Gate status:** Gate 2 (consensus/state transition) OPEN; Gate 8 (anti-rollback/external CAS) OPEN.

## 1. Purpose and safety boundary

Define the next implementation boundary for monetary policy v0.4 without silently replacing the older monetary rules. QZL4 remains a candidate snapshot format; its checksum is not a freshness proof, signature, or external anti-rollback anchor. This plan does not authorize mainnet activation, token issuance, a public sale, exchange listing, or merger of PR #61.

The v0.4 policy describes a 10,000,000,000-coin allocation ceiling at 8 decimal places. The candidate Genesis manifest currently records only the owner's 1,000,000,000-coin initial allocation. The mining allocation and the other six one-billion-coin allocations are not all issued at Genesis merely because they exist in the policy.

## 2. Current implementation boundaries observed

The v0.4 ledger candidate exposes Genesis construction, ledger and allocation-accounting accessors, validation, state-root calculation, and QZL4 encode/decode. Independent Python fixtures exist for the Genesis and QZL4 snapshot contracts.

The existing monetary fork-choice code is separate: PrivateTestnetMonetaryForkChoice and PrivateTestnetV4HybridForkChoice operate over their existing chain/state-machine APIs. The corresponding PFM3/PFM4 fork stores have their own persistence, replay and commit behavior. The presence of these components does not establish that the v0.4 ledger candidate is invoked by the canonical producer/importer path.

Before writing an adapter, trace and document the exact call graph for:
- block production and reward calculation;
- network block decoding and importing;
- state transition and transaction validation;
- fork choice and reorg replay;
- durable commit, snapshot export/import, and restart recovery.

Do not assume that the generic chain_import path is the authority for the monetary candidate until the call graph proves it.

## 3. Recommended versioned design

### CP-0395-A — Freeze a consensus profile

Introduce a candidate profile type in a new module/file; do not change legacy codec semantics in place. The profile must bind, using canonical serialization and a domain-separated fingerprint:
- network ID and Genesis-manifest digest;
- monetary policy version and exact allocation/issuance schedule;
- consensus parameters and transaction/state-transition rules;
- block/header and snapshot format versions;
- activation condition (for example, a precommitted network-specific activation height), with no implicit activation.

Reject zero/unknown IDs, unsupported versions, inconsistent fingerprints, and profile mismatches. Profile changes require an explicit new version and migration/activation tests.

### CP-0395-B — One reward rule for producer and importer

Define one deterministic function that derives the permitted mining reward from the active profile and consensus context (including height and parent state). Both block construction and block import must call the same rule. A peer-provided reward value may be compared against the locally derived value but must never determine issuance.

Reject a block if it would exceed the mining allocation or total supply, use a different profile, repeat issuance, or otherwise violate the height schedule. Preserve the old behavior only for explicitly selected legacy profiles; never silently reinterpret MBK3/MBK4 or accept a downgrade.

### CP-0395-C — Atomic monetary state transition

Stage transaction effects, mining issuance, authorized burns, per-allocation counters, account balances, live supply, and the monetary state root in one candidate transition. Validate all invariants before publishing any state. Any failed check must leave the prior state unchanged.

Required invariants include:
- issued amounts never exceed each allocation's ceiling;
- aggregate issuance never exceeds the profile's total cap;
- live supply equals valid issuance minus valid burns;
- sum of account balances equals live supply;
- the stored allocation accounting and recomputed state root agree;
- the network, Genesis and policy fingerprints remain bound throughout replay and reorg.

### CP-0395-D — Persistence and restart boundary

Keep QZL4 version 1 decoding stable. If runtime persistence requires new fields or semantics, specify a new format version or new magic (for example, a separately reviewed QZL5 proposal); do not change the meaning of an existing v1 byte stream.

The runtime persistence design must bind the monetary profile, canonical tip/height, ledger snapshot, allocation counters, issuance counters, and recomputed state root. Define import/export compatibility and fail-closed behavior before implementation. A checksum detects accidental corruption but cannot prove freshness or prevent an attacker from restoring a valid old snapshot; Gate 8 therefore remains open until an independently operated atomic CAS/anchor is actually connected and tested.

## 4. Required implementation and acceptance sequence

1. **Call-graph review:** record concrete functions/files for producer, importer, state transition, fork choice, reorg, durable store and snapshot paths. Identify every legacy-format entry point.
2. **Profile/codec tests:** golden bytes and cross-implementation fingerprint vectors; reject wrong network, wrong policy, wrong activation, malformed lengths, unknown versions and downgrade attempts.
3. **Transition tests:** producer/importer reward parity at boundary heights; peer-forged reward rejection; cap/overflow/burn authorization; atomic failure; duplicate/replay cases.
4. **Integration tests:** identical block sequences must yield identical account balances, allocation counters, live supply and state roots on producer and importer.
5. **Recovery tests:** restart, snapshot round-trip, partial durable writes, process termination around commit, competing branches, reorg/replay, and restore of an old snapshot.
6. **Independent oracle:** extend Python fixtures independently of Rust implementation; compare exact serialized bytes and state-root values, including negative vectors.
7. **Security review:** review transition atomicity, replay protection, downgrade/migration rules, state-root binding, durable-store races and anti-rollback. Do not close the gate with unresolved critical/high findings.

Recommended focused commands (run from src/native/pow_bench):
- cargo fmt --all -- --check
- cargo check --all-targets --locked --offline
- cargo test --locked --offline --lib monetary_ledger_v04_candidate -- --nocapture
- cargo test --locked --offline --lib -- --test-threads=1
- python ..\..\..\simulations\quantumzxb_v04_genesis_vectors.py
- python ..\..\..\simulations\quantumzxb_v04_ledger_snapshot_vectors.py

Run the full target set prescribed by the repository CI as well. Keep parallel process/lock-probe test results separate from serialized CI results and investigate any flake rather than deleting or suppressing it.

## 5. Gate evidence checklist

Gate 2 can be considered for closure only after the frozen profile, canonical producer/importer parity, atomic state transition, legacy incompatibility rules, replay/reorg/restart integration, independent vectors and independent security review all have reproducible evidence.

Gate 8 remains open until an external CAS/anchor service is truly independent of node rollback, performs atomic compare-and-swap, uses pinned receipt-verification keys outside the restorable snapshot, is invoked fail-closed by runtime code, and passes multi-host/disk/VM rollback, crash, race, timeout, retry and idempotency tests.

## 6. Non-goals

This candidate plan does not claim that QZL4 is a production snapshot, that v0.4 consensus is active, that a production mainnet exists, or that the native coin has a public liquid market. It does not close Gate 2 or Gate 8 and does not authorize merging PR #61.
