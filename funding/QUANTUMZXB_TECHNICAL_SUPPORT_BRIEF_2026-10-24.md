# QuantumZXB / AI_NATIVE_L1 — Technical Support Brief

**Prepared:** 24 October 2026  
**Purpose:** Request for scoped engineering collaboration, independent review and in-kind support. This is not an investment offer or a token-sale document.

## Project and public evidence

- Repository: https://github.com/hamidnikkhah660-arch/ai-native-l1
- Active review: https://github.com/hamidnikkhah660-arch/ai-native-l1/pull/61
- Validated CP-0398 baseline commit: **3b5c86d47bebdc67bfefd0cb0abb82512547895c**
- CI evidence for that exact baseline: https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/40098084960
- Technical plan: **docs/CP-0399_V04_VERSIONED_RUNTIME_INTEGRATION_PLAN_AND_GATES_2026-10-24.md**

The baseline CI run succeeded in both the Rust validation job and the Windows PMT4/TXN4 loopback job. Candidate-only changes after that baseline must be assessed using the live checks attached to PR #61, not by assuming the baseline result applies to every later revision.

## What is available to review

The repository contains Rust research/candidate work for bounded allocation accounting, a versioned Genesis manifest and ledger bridge, snapshot validation, an explicit mining schedule, and a profile-bound staged monetary transition. Independent standard-library Python scripts produce byte-level reference vectors for key candidate formats. The CP-0398 baseline also passed its recorded full offline test run.

These are concrete review artifacts, not a claim that the chain is production-ready.

## What is not being claimed

- No public production mainnet or frozen production monetary schedule has been established by this work.
- The v0.4 candidate transition is not connected to live block-producer/importer consensus paths.
- Gate 2 (consensus/state transition) remains open.
- Gate 8 (external anti-rollback/CAS) remains open; no independent production CAS service is being represented as live.
- No independently verified liquid market, exchange listing, live market price, public mining programme or coin-derived revenue is claimed.
- Test subsidies, halving intervals and fixture allocations are not production economic promises.
- No return, token price, grant award or future market success is promised.

## Specific support requested

The most useful initial help is scoped, evidence-producing work that does not require a payment from the project owner:

1. **Consensus review:** independent review of the version-dispatch plan, reward derivation, state-transition atomicity and legacy compatibility.
2. **Windows persistence testing:** help diagnose and reproduce the recorded intermittent child-process launch error in the reward-pool durable-store test. Six controlled serial reruns passed, but the original Access is denied (os error 5) incident remains unexplained.
3. **Security review:** threat-model feedback for the future external CAS and anti-rollback trust domain before implementation is treated as a gate-closing result.
4. **In-kind engineering infrastructure:** temporary CI capacity, cross-platform test time or reproducible test support, offered with transparent scope and no obligation to purchase anything.
5. **Milestone-based grant or sponsorship discussion:** support only for a written, reviewable milestone with acceptance tests, public evidence and explicit limitations.

## Suggested milestones

- **M1 — Profile and compatibility specification:** reviewed canonical profile, activation rule and legacy compatibility matrix.
- **M2 — Producer/importer parity:** one versioned transition path with independent reward vectors and atomic-failure tests.
- **M3 — Reorg and recovery:** deterministic replay, fork-choice/reorg, versioned snapshot and restart evidence.
- **M4 — External anti-rollback:** deployed independent CAS service, verified receipts, fail-closed integration and cross-host tests.
- **M5 — Independent security review:** public findings and closure status before any production activation decision.

Milestones should be funded or supported only after scope, ownership, deliverables and acceptance criteria are agreed. No budget amount is stated because no reviewed cost estimate is available in this brief.

## How to contribute safely

Review the public repository and PR, file reproducible issues, submit code with tests, or offer a clearly scoped independent review. Any financial or in-kind arrangement should be documented transparently before work starts. No token purchase, wallet transfer, listing commitment, private-key access or paid subscription is requested by this brief.

The project seeks a credible, reviewable path toward a reliable protocol. Progress will be reported by exact commit, test and CI evidence; an open gate will remain open until its acceptance criteria are demonstrated.
