# QRun Technical Readiness and Sponsorship Milestone Plan v1

**Date:** 2026-10-29  
**Status:** Public proposal for scoped support; no sponsor, contract, cash revenue, or production release is claimed.  
**Project:** QRun Blockchain (native coin design: QZXB)  
**Contact:** hamidnikkhah660@gmail.com

## Purpose

This document gives prospective sponsors, grant reviewers, operators, and engineering partners a verifiable way to support QRun without confusing repository activity with a production network. Funding may support a milestone; it does not bypass a release gate, purchase a listing, or make candidate QZXB balances publicly spendable.

**Current public status:** source and documentation are public; the node is experimental public-alpha. No value-bearing production Mainnet, independently converged Internet-scale network, public explorer, live native QZXB market, market price, exchange listing, independent security audit, or secured sponsor is claimed.

## What is evidenced today

- The default `main` branch includes the public website and curated engineering/documentation baseline.
- The separate experimental branch `work/qzbe-v04-persistent-mining-20261026` contains additional implementation work; it must not be described as a production release.
- On the active experimental checkout, `cargo test --all-targets --locked --offline -- --test-threads=1` completed locally with exit code 0; its captured log recorded 89 successful test-target summaries and no failed summaries.
- The active branch test inventory lists 1,187 cases across 74 Cargo targets, including 931 tests in the main Rust library target. Inventory counts are not the same as independent verification.
- GitHub Actions passed Rust formatting, all-target compilation, full Rust test execution, plus Windows two-node signed-transaction, invalid-signature rejection, peer propagation, replay, paged archive synchronization, inter-page reorganisation and stale-cursor checks for the public-release PR.
- ML-DSA-65 verification and hybrid-signature formats exist in research code; this does not mean post-quantum protection is active across every production path.
- EVM/revm is an isolated integration lab; canonical EVM execution in native QRun state is not claimed as complete.
- QZXB's latest owner-directed design targets 10,000,000,000 units at Genesis to one owner account, with zero later minting and zero block subsidy. Canonical production integration is not complete. Older allocation and halving/subsidy proposals are historical and superseded for this target.

## Proposed funded milestones

The project welcomes cash, infrastructure, independent engineering, research or audit support. Each milestone must have a written scope, named owner, independent acceptance reviewer, deadline agreed after scoping, budget/currency, evidence bundle and explicit exclusions. There is no preset price in this document because provider, operator and auditor quotes have not been obtained.

### M0 — Freeze the review baseline

**Objective:** make every reviewer evaluate the same exact source, network and monetary rules.

**Deliverables**
- Versioned release-candidate SHA and signed or otherwise independently recorded source/binary hashes.
- One canonical network/profile specification: network ID, Genesis commitment, consensus fingerprint, wire/schema versions, owner public account ID and monetary rules.
- Explicit supersession table for legacy 4B, v0.4 percentage-bucket and 3B mining/halving models.
- Reproducible build and test commands, dependencies, known limitations, vulnerability-reporting route and test evidence.

**Acceptance evidence**
- An independent reviewer reproduces the stated build and tests from the tagged commit.
- Golden vectors and a Genesis manifest agree on two clean checkouts.
- No seed phrase, private key or personal credential appears in source, logs or release artifacts.

### M1 — Independent multi-host zero-value Devnet

**Objective:** prove that separate operators can run the same candidate protocol outside one developer machine without assigning market value to test balances.

**Deliverables**
- At least three independently operated node/benchmark participants across separate hosts or providers for production-profile calibration; an initial independent seed must be reachable from a different network.
- Authenticated, pinned peer identities; exact agreement on network ID, Genesis commitment and consensus fingerprint.
- External inbound P2P reachability evidence from an unrelated network. RPC and transaction ingress stay private or behind a separately hardened authenticated gateway.
- Signed test transaction propagation, invalid-signature rejection, independent balance queries, equal state roots, restart/recovery, fork/reorganisation and partition/rejoin evidence.

**Acceptance evidence**
- Dated logs, scripts, source hashes and state-root comparisons from each operator.
- Each operator confirms its own host/network and independently reports results.
- A local listener or loopback-only test is not accepted as proof of Internet reachability.

### M2 — Consensus and monetary invariants

**Objective:** freeze and verify the intended 10B Genesis/no-subsidy design across all canonical state-transition paths.

**Deliverables**
- Genesis, block production, import, fork choice, durable storage, restart, replay and checkpoint paths enforce one identical monetary profile.
- Tests prove total issuance never exceeds the Genesis allocation; no later minting or block subsidy is accepted; fees cannot create supply; reorgs and recovery cannot reopen issuance.
- Independent analysis of timestamp bounds, difficulty/retarget extremes, hash-rate shifts, chainwork and adversarial-peer behavior.
- A written security/economic analysis of fee-only proof-of-work incentives, including how miners/operators are expected to remain available when no block subsidy exists.

**Acceptance evidence**
- Shared golden vectors and adversarial/regression tests from a pinned release candidate.
- Independent reviewer signs off on invariants and records any unresolved limitation.
- No claim of Bitcoin-equivalent security or production-grade permissionless incentives unless supported by analysis.

### M3 — Complete history and rollback-safe recovery

**Objective:** recover from a new node, interruption, crash, stale archive, bad checkpoint and competing forks without trusting one unverified local snapshot.

**Deliverables**
- Full history replay from Genesis or an end-to-end, independently verifiable checkpoint rollover and monotonic anti-rollback trust design.
- Authenticated paged catch-up under interruption, reorganisation, missing-parent, corrupted-manifest and stale-cursor conditions.
- Operator runbook for backups, restore, migration, recovery, incident triage and reorg response.

**Acceptance evidence**
- Independent operators reproduce the same canonical tip and state root after each recovery scenario.
- Invalid, stale, downgraded or mismatched manifests fail closed.
- Checkpoint trust anchors are documented with an explicit independent trust domain; increasing size limits alone does not satisfy this gate.

### M4 — Independent protocol and cryptography review

**Objective:** obtain external review that is separate from the implementation author.

**Deliverables**
- Written scope and threat model covering consensus, transaction signing, P2P/session authentication, ML-DSA/hybrid policy, downgrade rules, storage, replay/rollback, malformed inputs, DoS/resource limits and key recovery.
- Reproduction instructions and a private channel for embargoed high-risk findings.
- Findings classified by severity, remediation commits, regression tests and a re-review of critical/high fixes.

**Acceptance evidence**
- Published executive summary and review scope (sensitive exploit details may be coordinated responsibly).
- No open critical/high issue accepted for launch; exceptions, if any, require an explicit risk owner and must not be hidden.
- A passing unit suite is not a substitute for this review.

### M5 — User operations, wallet and public observability

**Objective:** let independent users verify the chain and safely understand wallet and transaction state.

**Deliverables**
- An independently operated read-only explorer/indexer and documented public query API, with monitoring and abuse controls.
- Verified wallet creation, recovery, address derivation, signed transfers, independent confirmation queries and failure/reorg guidance.
- Reproducible release artifacts, hashes, supported OS/toolchain, bootstrap configuration, privacy/security notes, incident policy and public service-status page.

**Acceptance evidence**
- A new user follows the instructions on a clean machine and independently verifies address, signed transaction, inclusion, confirmations and balance.
- Public endpoints are tested externally and do not expose local administrative RPC.
- Native QZXB is not conflated with the historical QX Sepolia test token.

### M6 — Coordinated production decision

**Objective:** make a documented go/no-go decision after all technical evidence exists.

**Deliverables**
- Signed checklist covering M0–M5, three independent operators, external reachability, consensus/monetary integration, recovery, independent security review, reproducible build hashes, wallet and explorer, monitoring and incident response.
- A coordinated multi-node launch and rollback plan, clear support contact, versioned release notes and known-limitations list.
- A separately reviewed decision on any later external bridge, stablecoin, exchange or market route. A market is not a prerequisite to finishing the native protocol; no market may be invented or implied.

**Acceptance evidence**
- Every release gate links to concrete reproducible evidence.
- Mainnet activation is approved only after the evidence is complete and all critical/high security issues are resolved.
- A website update or sponsor payment alone never changes the technical release status.

## Sponsorship and procurement format

A proposal should include:

1. Sponsor/organisation name, authorised contact and relevant experience.
2. Selected milestone and exact deliverables; explicitly state what is out of scope.
3. Requested amount, currency, whether cash or in-kind support, invoice/payee details and any tax/legal requirements.
4. A budget broken into labour, infrastructure, review/audit or testing costs, with source quotes where appropriate.
5. Start/end assumptions, dependencies, payment schedule, acceptance reviewer and evidence to publish.
6. Intellectual-property/licensing, confidentiality, data-handling, conflict-of-interest and termination terms.
7. A statement that funding is for engineering/review/infrastructure, not for a guaranteed exchange listing, market price, investment return, token allocation or vote manipulation.

Use milestone-based payments agreed in writing. A proposed scope, email expression of interest or verbal conversation is not a secured sponsor or received cash. Do not release tokens as a substitute for cash unless a separate, reviewed written agreement explicitly covers that arrangement.

## Suggested opening email

**Subject:** QRun milestone sponsorship proposal — [M0–M6]

Please identify your organisation and the milestone you wish to support. Include the exact deliverables, proposed budget and currency, timeframe, payment approach, acceptance criteria, reviewer and evidence you expect to receive. The project will respond with a scoped statement of work and dependencies before any work or payment obligation is assumed.

Contact: hamidnikkhah660@gmail.com  
Public project: https://hamidnikkhah660-arch.github.io/ai-native-l1/  
Source: https://github.com/hamidnikkhah660-arch/ai-native-l1  
Release decision: https://github.com/hamidnikkhah660-arch/ai-native-l1/blob/main/docs/CP-0465_QRUN_MAINNET_PUBLIC_TRADING_NO_GO_2026-10-29.md

## Zero-budget fallback if no sponsor commits

The project can continue improving without pretending that a production launch is ready:

1. Keep the zero-value Devnet and explicit release gates; do not enable value-bearing Mainnet to improve appearances.
2. Split M0–M3 into small public issues with reproducible acceptance tests; accept volunteer reviews and independent operator reports.
3. Use existing CI, local test fixtures, public documentation and eligible free/open-source infrastructure credits where available; confirm limits and expiry before depending on them.
4. Apply to relevant grants and open-source sponsorship programmes with this milestone plan, rather than requesting unspecific money.
5. Publish a monthly evidence report: merged changes, test/CI status, operator count, unresolved blockers and funds actually received/spent.
6. Defer paid promotion, token-market plans and any launch promise until the protocol and operations gates are passed.

**Bottom line:** support can accelerate independent validation, infrastructure and security work, but no single sponsor can instantly make an unproven distributed network production-ready. The project should be prepared to accept a proposal immediately, while keeping release approval evidence-based.
