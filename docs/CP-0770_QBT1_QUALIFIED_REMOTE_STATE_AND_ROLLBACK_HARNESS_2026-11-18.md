# CP-0770 — QBT1 Qualified Remote-State and Stale-Snapshot Rollback Harness
**Date:** 2026-11-18
**Project:** QRun / QFP6 / QZXB
**Branch:** `feat/cp0704-dual-attestation-rotation-gate-20261116`
**Worktree:** `D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116`
**Observed HEAD before/after:** `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`

## Disposition

**PUBLIC QUALIFIED QAR2/QBT1 + DYNAMODB ADAPTER COMPOSITION EXERCISED AGAINST A STATEFUL AWS-CLI SERVICE DOUBLE / IDENTITY DRIFT FAILS CLOSED / STALE SERVER-SIDE CAS REJECTED / TARGETED TESTS PASS / NO LIVE AWS / GATE 8 OPEN**

CP-0770 moves the CP-0769 restart/replay scenario off the `cfg(test)` local-file service factory and through the public QBT1-qualified AWS adapter and `QAR2BoundAnchorService::with_qualified_aws_dynamodb` composition path. The backend remains a deterministic in-process AWS CLI test double. This is stronger adapter-composition and failure-path evidence, not cloud deployment or independent-custody evidence.

## 1. Code change

Only the test section of:

`src/native/pow_bench/src/external_cas_offhost_anchor_protocol_v2_candidate.rs`

was extended. Added module:

`qualified_aws_remote_state_tests`

The stateful runner:
- returns exact synthetic STS caller, IAM role, single-region DynamoDB table, SSE, deletion-protection and PITR qualification responses;
- persists the DynamoDB item across independently constructed adapter and QAR2 facade instances;
- accepts only the pinned table and region;
- rejects GetItem unless `--consistent-read` is present;
- emulates absent-key bootstrap insertion;
- emulates the atomic PutItem condition by comparing the predecessor sequence, complete state digest and all three immutable QBT1 bootstrap attributes;
- returns a conditional-check failure when any predecessor or trust-binding condition does not match;
- can switch to a wrong AWS account identity to exercise fail-closed requalification.

No production code path was changed in this checkpoint.

## 2. Exercised flow

1. Construct the QBT1-bound DynamoDB adapter through `with_qualified_verified_bootstrap_runner` and perform generation-zero bootstrap with absent-key conditional insertion and strong read-back.
2. Drop the bootstrap adapter.
3. Construct the public QAR2 facade through `with_qualified_aws_dynamodb`; its injected store performs an authoritative strong read.
4. Submit a valid Provider-signed generation-one commit through the QAR2 facade. Verify the returned outer QAR2 receipt against the exact test QBT1 capability and confirm the successor state.
5. Drop the facade and retain only the shared stateful remote-service double.
6. Change the simulated STS identity to a different AWS account. Attempt facade reconstruction and verify it fails at the first STS call; no DynamoDB operation follows.
7. Restore the expected synthetic identity and rebuild the facade. A fresh QAR2 read observes sequence two from the shared backend.
8. Submit a different valid transaction signed against the old generation-zero predecessor. The QAR2 facade returns a signed Conflict with the authoritative sequence-two state.
9. Force the stale predecessor through the DynamoDB adapter itself. Its conditional PutItem is rejected; the adapter performs a fresh strongly consistent read and returns Conflict with the sequence-two state.
10. Read once more and confirm the stored item remains at sequence two. The test also asserts that every GetItem/PutItem is preceded by the four expected identity/role/table/backup qualification calls and that successor PutItem conditions include all three immutable QBT1 fields.

The facade rebuild and stale-client replay simulate a restored node-side snapshot while the separate test-double backend remains advanced. They do not restore an actual machine image or contact an independently administered remote service.

## 3. Verification on heymed

| Check | Result |
|---|---:|
| Focused qualified QAR2/QBT1 state/restart/replay test | 1 passed, 0 failed |
| QAR2 v2 module tests (including focused test) | 8 passed, 0 failed |
| AWS deployment qualification tests | 12 passed, 0 failed |
| DynamoDB adapter tests | 17 passed, 0 failed |
| Total targeted regression tests | **37 passed, 0 failed** |
| `cargo check --bins` | PASS |
| `cargo fmt --all -- --check` | PASS |
| `git diff --check` | PASS |

This is not the full crate suite (1,591 tests). Existing unused/dead-code and unrelated-bin warnings remain; no warning was promoted to an error. Git emitted the existing LF-to-CRLF working-copy notices; `git diff --check` returned zero.

## 4. Source integrity

SHA-256 after formatting and all passing test/build checks:

| File | SHA-256 |
|---|---|
| `external_cas_offhost_anchor_protocol_v2_candidate.rs` | `1495FBD43D3F6BD61B7821830776903E205C9854B9826B7F906DD0FDB18F8FEF` |

## 5. Explicit limits

- All account, assumed-role, table and backup values are synthetic fixtures. The runner is in-process and never calls AWS or the network.
- The stateful double models the adapter's required command/condition contract. It does not prove AWS DynamoDB's actual strong-read, conditional-write, regional consistency or operational behavior.
- It does not bind an AWS credential session and endpoint atomically. The CP-0764 TOCTOU limitation remains: revalidation before a separate AWS CLI invocation is not proof that both use one immutable authenticated session and endpoint.
- No actual AWS account, IAM role, DynamoDB table, KMS key, credential, resource policy, SCP, backup vault or CloudTrail configuration was inspected or changed.
- The test's “rollback” is a facade/client reconstruction with an old signed predecessor while the shared mock backend remains advanced. It is not a whole-host snapshot restore, power-loss recovery, separate OS process, second physical host or independent monotonic witness.
- Deterministic ML-DSA test keys are not real owner/custodian keys. No two-person ceremony, external root delivery, independent witness administration or security review occurred.
- The QAR2 Noise listener and full QRun consensus/node launch were not started by this test. This checkpoint does not prove production startup enforcement or a live external Anchor call from the QAP1 coordinator.

Therefore:
- **Gate 8 remains OPEN.**
- **Gate 2 remains OPEN** unless independently closed by its separate runtime/network/reorg evidence.
- Mainnet/public release remains **NO-GO**.

## 6. Next required boundary

The next genuine Gate 8 step is not another local success fixture. It requires an operator-provisioned QBTB1 bundle delivered out-of-band, real separately administered cloud account/role/table and credentials, same-session authenticated client/endpoint binding for every operation, a separately controlled recovery custodian and monotonic witness, plus an independently witnessed whole-host rollback/restart test against that live witness. External security review remains mandatory.

## 7. Git preservation

- Branch unchanged: `feat/cp0704-dual-attestation-rotation-gate-20261116`.
- HEAD unchanged: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`.
- Staged file count: zero.
- CP-0770 source and this note remain uncommitted working-tree changes.
- All previously modified/untracked project work was preserved.
- No commit, push, merge, reset, clean, stash or checkout was performed.

**Final disposition: the public qualified composition and stale-CAS guard are now covered by a stateful service-double harness; 37 targeted tests and the bin build pass; no live AWS or independent anti-rollback proof; Gate 8 OPEN.**
