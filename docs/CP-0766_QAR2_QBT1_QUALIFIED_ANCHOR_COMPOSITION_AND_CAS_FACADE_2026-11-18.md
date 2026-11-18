# CP-0766 — QAR2/QBT1 Qualified Anchor Composition and CAS Facade
Date: 2026-11-18
Worktree: D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116
Branch: feat/cp0704-dual-attestation-rotation-gate-20261116
Base HEAD (unchanged): 5aba5f69d24fce03af742fd1bebf13ad00e5d9c3

## Scope

This checkpoint extends the existing CP-0765 QAR2 protocol candidate. It does not replace QAR1 V1, does not claim a live AWS deployment, and does not close Gate 8.

## Code changes

File:
- src/native/pow_bench/src/external_cas_offhost_anchor_protocol_v2_candidate.rs

Changes:
1. The direct QAR2BoundAnchorService constructor is now private. External callers cannot create this QBT1-bound facade by injecting an arbitrary in-memory model.
2. Added public QAR2BoundAnchorService::with_qualified_aws_dynamodb(...). It requires:
   - a VerifiedBootstrapTrust capability;
   - pinned AWS account, role, table ARN, region, and table name;
   - exact Anchor and Provider pins;
   - an injectable AWS DynamoDB runner.
3. The factory obtains AwsDynamoDbOffhostAnchorStore through the existing with_qualified_verified_bootstrap_runner constructor, then injects that QBT1-bound store into ExternalCasOffhostAnchorMemoryModel::with_store.
4. Added a facade CAS test. It constructs and verifies a Provider commit receipt using deterministic unit-test fixture keys, performs atomic CAS through the facade, verifies the signed QAR2 receipt against the exact QBT1 capability, round-trips the canonical QAR2 wire, then reads and verifies the successor state.
5. Added a fail-closed composition test. When STS returns the wrong AWS account, construction returns Unavailable after only sts get-caller-identity; no DynamoDB operation is issued.

Source SHA-256:
AA0249BC211BDC202C5A91967A7EF2241B85D1FB8E92AFBCAD8E90F4F22684B4

## Verification on heymed

Device: heymed
Device ID: d350fcce-b411-45dd-b2ff-568acbef16dc

Targeted tests:
- external_cas_offhost_anchor_protocol_v2_candidate: 7 passed, 0 failed
- external_cas_offhost_anchor_protocol_candidate (QAR1 regression): 12 passed, 0 failed
- external_cas_bootstrap_trust_candidate (QBT1 regression): 10 passed, 0 failed

Build / hygiene:
- cargo check --bins: passed (run after the production factory/facade change; before the final test-only additions)
- cargo fmt --all -- --check: passed after the final additions
- git diff --check: passed at the final status inspection

Warnings:
- Existing dead-code warnings remain for the process AWS CLI runner and legacy crate-private DynamoDB constructors.
- Other pre-existing unused/dead-code warnings remain in unrelated modules and binaries.
- No warning was promoted to an error.

## Important integration finding

The new QAR2 facade and qualified AWS composition factory currently have no production caller.

The existing QRun V0.6 QAP1 route still constructs NoiseTcpOffhostAnchorTransport. Its QARQ/QARS wire handler emits and consumes QAR1 receipts. QRunV06Qap1AnchorTransport also returns ExternalCasOffhostAnchorReceipt (QAR1) to QRunV06Qap1ExternalCoordinator.

Therefore CP-0766 proves:
- a QBT1-bound QAR2 facade can read and perform CAS over the existing anchor model;
- its qualified AWS composition boundary rejects a wrong AWS account before any DynamoDB command;
- QAR1 and QBT1 targeted regressions still pass.

It does NOT prove:
- QAR2 is transported over the production Noise connection;
- QAR2 is required by the QFP6/QAP1 production startup path;
- a remote QAR2 client verifies QBT1 and rejects downgrade;
- a real QAR2 AWS read/CAS has been executed.

The next runtime integration must be a separately versioned QAR2 Noise server/transport (or an equivalently strict protocol adapter) with explicit QBT1 verification on the client and server, pinned protocol/profile identity, and no automatic QAR1 fallback in QBT1-bound mode. Only after that can the QAP1 coordinator be switched through a transport implementation that verifies the outer QAR2 receipt before exposing its inner QAR1 proof to existing coordinator logic. This transition must be deliberate and covered by negative downgrade/replay tests; do not silently route QBT1-bound requests to the current QAR1 endpoint.

## Gate 8 and deployment status

Gate 8 remains OPEN.

Still unproven:
- QAR2 remote Noise transport and production startup/caller enforcement;
- same-session AWS identity/endpoint assurance (the current revalidating CLI runner still has a TOCTOU boundary);
- a real AWS account, IAM/SCP policy, independent table, and separate operator/custodian;
- independently controlled monotonic CAS/witness and authenticated root enrollment;
- full rollback, restart, power-loss, and recovery qualification against the independent witness.

No AWS account, role, table, credentials, endpoint, or cloud resource was accessed or modified during these tests. The wrong-account runner was synthetic. No live AWS deployment is claimed.

Mainnet remains NO-GO. Existing P0 consensus, Genesis, complete V0.6 node, independent history/anchor and public multi-operator Devnet gates remain separate from this QAR2 work.

## Git safety

- HEAD remains 5aba5f69d24fce03af742fd1bebf13ad00e5d9c3.
- No files were staged.
- No commit, push, merge, reset, clean, stash, or checkout was performed.
- Existing modified and untracked worktree contents were preserved.
- This document is an untracked checkpoint note; it is not a commit or a release authorization.
