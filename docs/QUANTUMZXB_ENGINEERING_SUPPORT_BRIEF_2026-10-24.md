# QuantumZXB / AI_NATIVE_L1 — Engineering Support Brief

**Prepared:** 2026-10-24
**Purpose:** Request technical review, open-source collaboration, grant/sponsorship support, and in-kind testing resources.
**Scope:** Evidence-backed engineering progress only; not an investment offer.

## Project

Repository: https://github.com/hamidnikkhah660-arch/ai-native-l1
Active candidate PR: https://github.com/hamidnikkhah660-arch/ai-native-l1/pull/61
Verified CI run for the current candidate commit: https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/40092772241

QuantumZXB / AI_NATIVE_L1 is an experimental Rust-based Layer 1 research project. The current workstream is focused on deterministic monetary accounting, a versioned Genesis manifest, ledger snapshots, and consensus/recovery correctness. The code is under active development and remains candidate work rather than a production-ready network.

## Evidence available for review

At commit b99aae3789d18ed73ed576ff028b566d5dcb8f3f:
- A candidate module defines eight policy allocation buckets with issuance ceilings and burn/accounting checks.
- A candidate Genesis manifest binds policy and network identifiers and the initial owner allocation.
- A candidate bridge validates the Genesis manifest against the ledger and accounting state.
- QZL4 version-1 snapshot encode/decode has corruption, wrong-network, version, length and round-trip tests.
- Independent Python fixtures provide byte-level reference vectors for candidate Genesis and QZL4 snapshot serialization.
- GitHub Actions run 40092772241 completed successfully for that exact SHA. The recorded jobs were “Format, check, and test” and “Windows PMT4 TXN4 two-node loopback”; both were completed with success. The workflow includes format checks, all-target check/tests, Python oracles, and Windows two-node loopback/reorg scenarios.

These artifacts are reproducible engineering evidence, not proof of production readiness or market demand. The active PR has not been merged.

## Important limitations disclosed up front

- Gate 2 (consensus/state transition) is open. The v0.4 ledger candidate is not yet proven to be the canonical runtime rule for block production and importing. Existing legacy monetary codecs/state paths still need explicit, tested version selection and migration boundaries.
- Gate 8 (anti-rollback/external CAS) is open. A local checksum or simulated CAS test is not an independently operated anti-rollback service.
- The 10-billion-coin figure is a policy ceiling, not evidence that the full amount has been issued or distributed. The current candidate Genesis manifest records only the 1-billion-coin owner allocation.
- A public production mainnet, public liquid market, verified listing, live price chart, and public mining income have not been established by the evidence used for this brief.
- The Sepolia ERC-20 test asset is not the native production coin.
- No guaranteed token price, revenue, grant, bounty award, listing, or investment return is represented or promised.

## What support would unlock

1. **Independent protocol review:** review of monetary state transitions, issuance, replay protection, versioning/downgrade rejection, supply invariants and account-state consistency.
2. **Windows reliability contributor:** help reproduce and diagnose intermittent “Access is denied” in a subprocess-based durable-store test; preserve the failure record and fix the cause rather than hiding the test.
3. **Persistence/anti-rollback review:** design and external test environment for truly independent atomic CAS/receipt verification, including restore of stale snapshots.
4. **Reproducible testing:** CI time, cross-platform test execution, crash/restart/reorg scenarios, independent vector generation and documentation.
5. **Open-source contribution:** Rust, consensus testing, protocol specifications, test harnesses, documentation, threat modeling and independent security review.

## Proposed milestone-based use of support

Funding or in-kind resources should be tied to public, reviewable deliverables rather than token-price targets:

- **Milestone A — Versioned runtime integration plan and frozen profile:** publish codec/state-transition contracts, producer/importer call graph, activation/version-selection rules and independent vectors.
- **Milestone B — Deterministic integration tests:** demonstrate producer/importer parity, atomic cap/burn/issuance behavior, replay/reorg correctness, restart and snapshot recovery.
- **Milestone C — External anti-rollback proof:** connect an independent CAS/anchor service and provide multi-host rollback and crash-test evidence.
- **Milestone D — Independent security review:** publish findings, severity and remediation evidence; do not claim gate closure while critical/high findings remain unresolved.

Scope, deadlines and any cash budget should be agreed only after a public review of the proposed work. This brief does not authorize spending, subscriptions, infrastructure purchases or contracts on behalf of the project owner. Prefer free CI, in-kind collaboration and no-cost development until a grant or sponsorship is actually confirmed.

## Ways to participate

Start with the repository, PR and CI artifacts linked above. Contributions should be proposed as focused pull requests with tests and evidence. Grant/sponsorship programs, bounty scopes and payment channels must be checked for current eligibility and explicitly confirmed before being represented as active or awarded. This brief intentionally does not name an unverified program or imply that funding has been secured.

## Status statement

The project is seeking engineering collaboration and support for validation. It is not soliciting funds on the promise of a coin listing, speculative price appreciation, guaranteed revenue or a production launch date.
