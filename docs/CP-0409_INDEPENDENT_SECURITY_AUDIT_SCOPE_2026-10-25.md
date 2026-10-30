# CP-0409 — Independent Security Audit Scope and Request for Proposal

Date: 2026-10-25

Status: **audit brief only; no auditor engaged, no audit delivered, and no approval granted**

## Purpose

This brief is intended to obtain a fixed-scope proposal from an independent blockchain/protocol security firm for the v0.4 QZB4 v2/QZBE candidate path and its persistent-store/external-CAS contract. It deliberately separates source-code review from production qualification and from legal/regulatory clearance.

The current engineering checkpoint is commit beb531ecd2ef23ba09c5e113bb2cd1e6a4661a03 on branch work/g2-g8-allocation-ledger-v04-20261024, in PR #61. A clean local test run is not an independent audit. The commit-specific GitHub Actions run is tracked on PR #61; the vendor proposal should identify and pin the source SHA actually reviewed.

## Requested audit scope

The reviewer should perform a source-based, adversarial review of the full reachable candidate path and its trust boundaries, not only individual codecs.

| Area | Files / components | Main questions |
|---|---|---|
| Genesis and monetary profile | monetary_genesis_v04_candidate.rs, monetary_issuance_v04_candidate.rs, monetary_transition_v04_candidate.rs | Is the network/Genesis/schedule/profile bound consistently? Are issuance, caps, rounding, height offsets, and reward derivation exact? Can different clients produce divergent roots? |
| Block and PoW envelope | monetary_pow_v04_candidate.rs and associated consensus/fork-choice code | Are the parent, target, digest, version, profile, timestamp, and state-root bindings complete? Is cumulative work/reorg selection deterministic? Are downgrade/fallback paths impossible? |
| Persistent archive and crash recovery | monetary_pow_v04_store_candidate.rs | Are manifests canonical and bounded? Can branch-file mutation, missing files, symlinks/hardlinks, lock races, torn writes, stale manifests, or crash windows change canonical state? Is replay complete and deterministic? |
| External CAS protocol contract | external_cas_anchor_candidate.rs, QZBE store adapter | Are pinned signed reads and signed receipts bound to provider, network, Genesis, operation/challenge, generation, exact successor, and state digest? Are conflict, duplicate operation, timeout/lost response, replay, concurrent writer, restore, and stale-floor cases correct? |
| Local anchored-mode latch | QZCA mode-marker code in monetary_pow_v04_store_candidate.rs | The marker is a local mutable operational guard, not an independent anti-rollback trust anchor. Can ordinary API mistakes bypass CAS? How should production configuration force anchored-only mode so deleting/restoring the marker cannot reopen local-only submission? Require a documented and tested external enforcement design. |
| Candidate importer / transition adapter | monetary_runtime_v04_candidate.rs | Are pending snapshot / anchor compare-and-set / final replacement ordering, rollback rejection, and startup recovery atomic? Do invalid blocks and signatures leave state and anchor unchanged? |
| Offline smoke executable | src/bin/qzbe_v04_candidate_smoke.rs | Does the explicit-parameter tool remain isolated from node listeners and transactions? Can it accidentally reuse legacy data or imply production economics? |
| Runtime compatibility boundary | src/bin/private_testnet_node.rs, CP-0402 compatibility audit | Verify which PMT4/PFM4 producer/importer/listener paths remain live. Assess whether there is an unsafe mixed-version or implicit-downgrade boundary. Do not assume QZB4/QZBE is already wired into the canonical node. |

The reviewer should inspect the test harnesses and reproduce relevant tests, then add adversarial tests wherever the current evidence does not cover the stated threat model.

## Threat model and required cases

At a minimum, test and report on: malicious or stale peers; malformed/truncated/non-canonical wire input; wrong network, Genesis, schedule, PoW, or profile; forged reward and invalid signatures; duplicate/replayed transactions and blocks; fork-choice reorg and parent mismatch; arithmetic overflow/cap boundaries; path traversal and non-regular filesystem entries; competing writers; crash or power loss before and after each durability boundary; CAS conflicts; lost/ambiguous provider responses; receipt tampering/replay; provider-key mismatch/rotation; stale or rolled-back object-generation floor; joint/local directory restore; deletion/corruption of the QZCA marker; and provider outage/network partition.

The review must explicitly distinguish (1) protection against accidental ordinary API misuse, (2) protection against a malicious local disk/host restore, and (3) protection provided by a genuinely independent provider/floor. A local checksum, local marker, in-memory fixture, or single-machine crash test must not be credited as independent anti-rollback protection.

## Evidence presently available

The candidate working tree has passed local formatting, cargo test --all-targets --locked --offline (826 library tests; devnet_node and private_testnet_node 36 each; QZBE smoke binary 6; all other targets passed), cargo check --all-targets --locked --offline, 10 focused QZBE-store tests, 4 CP-0404 runtime tests, 379 release-checksum entries, 49 README-relative links, and the public documentation preflight. A deterministic local smoke run advanced height 0→3, closed/reopened and replayed, then resumed height 3→5 with replay.

These are engineering test results only. They do not mean an independent audit has occurred. The provider used by the CAS adapter is still a test fixture, the QZCA marker can be deleted or restored with local data, and no separately protected production object-generation floor has been deployed. The current canonical node runtime still uses the older PMT4/PFM4 path; the QZB4/QZBE candidate has not been substituted into the canonical producer/importer/listener path.

## Deliverables requested from the audit firm

1. A written threat model, scope statement, exact commit SHA, tooling/methodology, limitations, and list of reviewed modules.
2. Reproducible findings with severity, preconditions, concrete impact, minimal proof-of-concept or test, and recommended remediation.
3. Explicit review of consensus-critical arithmetic and serialization; state-transition and fork-choice invariants; filesystem/locking/crash behavior; CAS trust assumptions and rollback gaps; cryptographic key/receipt handling; and runtime integration boundaries.
4. A findings register with severity and disposition; patch review and retest for all critical/high findings; and a final report tied to the exact remediated SHA.
5. A clear statement of what was not audited, including any production provider, cloud configuration, deployment key custody, live node runtime, wallet/RPC, release pipeline, third-party dependencies, or legal/compliance matters outside the contracted scope.

## Acceptance criteria before any production-use claim

- The audit firm is independent of the code authors and discloses conflicts.
- The report pins an exact SHA and includes both findings and limitations.
- Critical/high issues are fixed and independently retested; remaining risk has an owner-approved disposition.
- A real provider is deployed and separately administered; key custody, signing-key rotation/revocation, object retention, operation idempotency, backup/restore and alerting are documented.
- The monotonic provider floor is protected outside the node's restore/rollback domain and is tested under whole-host and storage restores.
- Crash/power-loss/network-partition tests are run against the chosen production configuration on multiple hosts.
- Gate 2 separately proves that one explicitly approved Genesis/schedule/profile is wired consistently into canonical producer, importer, state transition, PoW/fork choice, persistence/replay and network version activation.
- Launch, supply, legal, tax, and jurisdiction decisions are handled separately by the owner and qualified advisers.

Passing this audit scope is not a regulator approval, legal opinion, exchange listing, guarantee, or authorization to issue or trade a value-bearing asset.

## Proposal questions for vendors

Please quote a fixed scope or a not-to-exceed amount, schedule, lead reviewer and relevant blockchain/storage/CAS experience. State whether the quote covers manual code review, fuzzing/property testing, crash/restore tests, multi-host provider validation, patch verification, and a final public report. Identify prerequisites and the precise runtime/provider components excluded from the quote. Do not request live signing secrets, customer funds, production private keys, or unrestricted deployment access as a condition of a source-based review.

No vendor has been contracted through this repository or this document. Gate 8 and Gate 2 remain open.
