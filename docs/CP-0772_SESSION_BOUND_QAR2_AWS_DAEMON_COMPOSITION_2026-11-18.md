# CP-0772 — Session-Bound QAR2/QBT1 AWS Anchor Daemon Composition

**Date:** 2026-11-18  
**Project:** QRun / QFP6 / QZXB  
**Branch:** `feat/cp0704-dual-attestation-rotation-gate-20261116`  
**Worktree:** `D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116`  
**Observed HEAD before/after:** `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`

## Disposition

**SESSION-BOUND QAR2/QBT1 AWS-BACKED DAEMON COMPOSITION API ADDED / DEPLOYMENT-PIN SUBSTITUTION FAILS CLOSED / TARGETED TESTS PASS / NO LIVE AWS / GATE 8 OPEN**

This checkpoint closes a code-composition gap identified after CP-0771: the repository had a public session-bound QAR2 AWS service factory and a QBT1 Noise daemon binder, but no production composition method joined them. The new API constructs and qualifies the AWS-backed QAR2 service before binding the QBT1-only listener.

## Code change

Updated:

`src/native/pow_bench/src/external_cas_offhost_anchor_noise_daemon_candidate.rs`

Added:

`OffhostAnchorNoiseDaemon::bind_qbt1_session_bound_aws_dynamodb(...)`

The method:
1. Accepts one concrete `SessionBoundAwsDynamoDbCliRunner`, its exact `AwsDynamoDbDeploymentPin`, the already verified `VerifiedBootstrapTrust`, daemon configuration, Provider verifier and Anchor signer.
2. Constructs `QAR2BoundAnchorService::with_session_bound_aws_dynamodb` using the same immutable runner/session and the exact Anchor/Provider pins from daemon configuration.
3. Only after the service/store qualification succeeds, passes that service into the existing `bind_qbt1` path. The QBT1 Noise profile and service pins are rechecked before the TCP listener is opened.
4. Uses neither ambient AWS credential discovery nor QAR1 fallback.
5. Does not create or bootstrap the generation-zero trust state. That state and the real owner/custodian QBTB1 material must already have been provisioned through a separate authorized process.

Added regression test:

`session_bound_aws_daemon_factory_rejects_deployment_pin_substitution`

It uses deterministic test fixtures and synthetic non-live credentials. A region/table deployment-pin substitution is rejected at composition time before a listener is opened. No AWS command or external network call is made by this test.

## Verification on heymed

| Target | Result |
|---|---:|
| AWS DynamoDB/session-bound adapter module | 23 passed |
| AWS deployment qualification module | 14 passed |
| QAR2/QBT1 protocol module | 8 passed |
| QAR2 Noise v2 module | 5 passed |
| QAR2 Noise daemon module, including new composition test | 22 passed |
| QRun V0.6 node binary tests, after the new change | 30 passed |
| **Total targeted tests** | **102 passed, 0 failed** |

Additional checks after the new change:
- `cargo check --bins`: PASS
- `cargo fmt --all -- --check`: PASS
- `git diff --check`: PASS

The 102 tests are targeted module/binary regressions, not the complete crate suite. Existing unrelated unused/dead-code warnings remain. Git's LF-to-CRLF working-copy notices are informational.

## Source integrity

SHA-256 of `external_cas_offhost_anchor_noise_daemon_candidate.rs` after formatting and verification:

`E64E8DC408120E52A94309C9173BA84381C7EE2EB4E5E7B8613D5CCFA7DA8AE8`

## Explicit limits

- The new method is a production-shaped composition API; it was not used to connect to a real AWS account or start a deployed Anchor service.
- CP-0771's live host inspection found AWS CLI v2 and ambient AWS credentials absent. No credentials were supplied or inspected during this checkpoint.
- The successful path against AWS, actual STS role/table qualification, live DynamoDB bootstrap/read/CAS, and live QAR2 listener start remain unverified.
- No real QBTB1 owner/custodian ceremony or independently delivered trust bundle was performed.
- No separate administrator, independently controlled monotonic witness, whole-host snapshot rollback test, external recovery exercise, or independent security review was available.
- This does not finish Gate 2 (PMT4/PFM4 runtime integration, authenticated networking, archive sync, two-process reorg/restart) and does not prove public multi-operator Devnet readiness.

**Gate 8 remains OPEN. Gate 2 remains OPEN. Mainnet/public release remains NO-GO.**

## Git preservation

- HEAD remains `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`.
- No files were staged.
- No commit, push, merge, reset, clean, stash, or checkout was performed.
- All pre-existing modified and untracked files were preserved.
- This is an untracked engineering checkpoint, not a release tag or launch authorization.
