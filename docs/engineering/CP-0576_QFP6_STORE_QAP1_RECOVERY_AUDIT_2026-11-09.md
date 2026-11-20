# CP-0576 — QFP6 Durable Store / QAP1 restart audit

**Status:** local audit implementation candidate; not a node runtime or Mainnet approval.
**Branch:** feat/cp0576-qfp6-store-qap1-recovery-audit-20261109
**Base:** CP-0575 / aa9d9b8ae37e5a077c78d43a57016d8a13f75946.

## Scope

CP-0576 adds an explicit audit path for an already-existing **Genesis-rooted** QFP6 durable fork store and its QAP1 intent journal. It is intentionally separate from the ordinary Store open/recovery path. The existing open path can clean temporary files and reconcile (including deleting) unreferenced branch files; an audit must not do that before the operator has seen the evidence.

The new APIs are:

- `QRunV06Qap1Journal::audit_latest(...)`: load the latest phase without cleanup, validate the phase chain, and re-verify every saved Provider/Q6EA receipt signature using the pinned identities.
- `QRunV06DurableForkStore::audit_existing_with_trust_authorized_profile_pin(...)`: audit/replay the existing Genesis-rooted archive under a Q6TS-authorized Q6PN profile, a supplied trusted Manifest Anchor, a pinned Q6EA identity, and explicit transaction/receipt verifiers.
- `audit_existing_with_trust_authorized_profile_pin_and_quote_asset_authorization(...)`: same audit, but historical non-native quote activity must be freshly authorized during replay.

The checkpoint-segment form is **not** covered by this CP. The method deliberately rejects a root containing `qfp6-base.checkpoint`; it does not silently try a Genesis-only replay against a checkpoint store.

## What the Store audit verifies

1. Requires v0.6 consensus parameters and an exact Q6TS-authorized profile pin. The Genesis descriptor fingerprint is checked with the Genesis/checkpoint fingerprint function; the durable Manifest's own consensus fingerprint is recomputed with the existing Store fingerprint function. These are distinct domains and are not conflated.
2. Requires the exact independently supplied nonzero latest Manifest Anchor. Missing or mismatched anchors fail closed.
3. Acquires the existing Store OS writer lock and validates the root, branch and Manifest directories without creating them.
4. Loads the complete immutable Manifest chain, checks generation/parent linkage, checksum and commitment, then checks the final Manifest identity against network/profile/consensus.
5. Reads every referenced immutable branch envelope, checks file length and SHA-256, decodes its PoW block, recomputes the digest using the exact supplied QFP6 PoW parameters, and replays the archive from the supplied canonical Genesis state with the supplied transaction authenticator. The quote-aware API requires fresh height-correct quote-asset authorization during historical replay.
6. Recomputes canonical tip, canonical height, state root and cumulative chainwork and matches them to the externally anchored Manifest.
7. Audits QAP1 phase snapshots without cleaning. Every persisted Provider and Q6EA receipt is cryptographically re-verified with the exact pins/verifiers; journal contents and next Manifest are checked against the replayed local Store.
8. Rejects symlinks, unknown entries, malformed files and unrecognized/orphan branch files. The only exception is one exact candidate envelope named by a valid QAP1 journal at **AnchorConfirmed** while local Store is still at the predecessor. In that specific crash window the candidate may already have been installed before the Manifest rename; audit verifies its exact bytes and PoW digest, reports it, and leaves it in place.

## QAP1 recovery findings

The report's `qap1_disposition` is a local finding, not a remote service status:

| QAP1 phase / observed local state | Finding | Meaning |
|---|---|---|
| No phase file | `Clean` | No local outstanding QAP1 journal was found. This does not query Provider/Q6EA. |
| Prepared + local predecessor | `PreparedNeedsRemoteReconciliation` | Intent and next Manifest replay correctly; remote status must be freshly reconciled before any resume. |
| ProviderCommitted + local predecessor | `ProviderCommittedNeedsAnchorRecovery` | Provider receipt is verified locally; remote Provider/Q6EA state still needs fresh reads before any next operation. |
| AnchorCasPrepared + local predecessor | `AnchorCasPreparedNeedsAnchorReconciliation` | Exact Anchor CAS request is journaled; ambiguity must be reconciled by a fresh signed Anchor read. |
| AnchorCommitted + local predecessor | `AnchorCommittedNeedsFreshAnchorRead` | Persisted Anchor receipt verifies locally; a new challenge-bound Anchor read is still required. |
| AnchorConfirmed + local predecessor | `AnchorConfirmedNeedsLocalManifestPublish` | Provider and Anchor evidence in the journal verifies; candidate and Manifest replay exactly. This is the one phase where the candidate branch file may exist unreferenced. A fresh remote check is still required before publishing the local Manifest. |
| AnchorConfirmed + local successor | `AnchorConfirmedLocalManifestAlreadyPublished` | Exact next Manifest is already present and anchored locally; journal phase update may have been interrupted. |
| LocalManifestCommitted + local successor | `LocalManifestCommittedNeedsFinalize` | Local Manifest matches the signed successor; QAP1 Finalized transition remains. |
| Finalized + local successor | `FinalizedNeedsCleanup` | Finalized snapshot exists; interrupted phase cleanup may remain. |

Any phase gap, signature mismatch, different predecessor/successor, bad Manifest bytes, different candidate, unknown file, extra orphan, or replay mismatch is a hard error. The audit never guesses that an ambiguous CAS succeeded.

## Side effects and non-effects

The Store and QAP1 journal's OS mutual-exclusion lock files may be created or have their diagnostic PID header updated. Those are local lock metadata, not trust records.

The audit does **not**:
- write, replace, clean, or delete Manifest, branch, checkpoint, or QAP1 phase data;
- remove interrupted temporary files or reconcile/delete orphan branches;
- advance the Q6TS Profile Trust Floor or the Provider monotonic trust record;
- call Provider CAS, Q6EA Anchor CAS, or write either remote service;
- publish a block, admit a transaction, acknowledge a peer, start P2P, start the node, or mine.

QAP1 local phase evidence being valid does not prove current remote state. Any recovery action must first perform fresh, challenge-bound Provider and Q6EA reads through the configured pinned transports and reconcile the exact journal phase; this audit itself never performs those network calls.

## Local validation

Validated on the Windows development host with Rust/Cargo 1.82 and locked offline dependencies:

- `cargo fmt --all -- --check` — passed.
- `cargo check --all-targets --locked --offline` — passed.
- `cargo test --all-targets --locked --offline` — **1,302 library tests passed; every binary, integration and example test target completed successfully; exit code 0**.
- Focused CP-0576 Store/QAP1 audit test — passed, including an existing Q6TS-authorized Genesis-rooted Store, exact external Manifest Anchor, bad-anchor rejection, orphan preservation, and a real Prepared QAP1 journal whose candidate and next Manifest are replayed byte-exactly.
- QAP1 audit interrupted-temp preservation test — passed.
- Existing Provider Noise, Q6EA Anchor Noise and QFP6 mining/QAP1 end-to-end regressions — passed.

The audit test records the Manifest and Prepared phase-file bytes before/after and verifies they remain byte-identical. It also confirms the local canonical height/Manifest Anchor remain at the predecessor after auditing a Prepared intent.

## Validation and limits

Tests use generated, test-only keys, local directories, a candidate ML-DSA verifier, and a candidate consensus profile. They prove code-path behavior only. The current `LibcruxMlDsa65VerifierCandidate` is not independently production-approved. No actual production Q6TS floor, Provider, Q6EA Anchor, key custodian, public listener, or Mainnet store was supplied or contacted.

A successful local audit is a diagnostic/replay qualification, not Mainnet readiness. Remaining gates include:
- actual independent Provider and Q6EA services with separate administrative/compromise domains and production-approved crypto;
- secure node/client key custody (HSM/KMS or reviewed equivalent) and independent trust-floor operations;
- checkpoint-segment audit/recovery and complete archive/history sync with external anti-rollback;
- QAP1 crash/fault-injection across all CAS/Manifest install boundaries, including fresh remote-read reconciliation before resumption;
- independent consensus/PoW/economics and issuance approval;
- public P2P infrastructure and multiple independently operated nodes;
- production wallet, RPC, explorer, release artifacts and security review;
- genuine USDT quote-asset qualification, custody/settlement, counterparties and liquidity for any QZXB/USDT market.

The node's `--run` command remains fail-closed in CP-0573/0574/0575. CP-0576 provides a library audit API; it does not activate a node or permit real-value transactions.
