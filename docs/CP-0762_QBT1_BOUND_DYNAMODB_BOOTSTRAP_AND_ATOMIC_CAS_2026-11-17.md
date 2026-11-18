# CP-0762 — QBT1-bound DynamoDB bootstrap and immutable CAS

Date: 2026-11-17  
Project: QRun Blockchain / QFP6 / QZXB  
Parent: CP-0761 — Versioned dual-attested bootstrap trust receipt  
Branch: feat/cp0704-dual-attestation-rotation-gate-20261116  
Worktree: D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116  
Observed HEAD: 5aba5f69d24fce03af742fd1bebf13ad00e5d9c3  
Disposition: **QBT1-BOUND DYNAMODB ADAPTER CANDIDATE IMPLEMENTED / SCRIPTED WINDOWS TESTS PASS / NO LIVE AWS DEPLOYMENT / GATE 8 OPEN**

## 1. Objective

CP-0762 binds the CP-0761 QBT1 dual-attested bootstrap receipt to the existing DynamoDB off-host Anchor item and every subsequent conditional state transition. It avoids a separate receipt item/table and therefore avoids a two-item bootstrap commit protocol.

The implementation is candidate-only. It does not contact AWS, provision a table, enroll a real signer, install an Anchor service, or activate a production runtime.

## 2. QBT1 capability input

The QBT1 verifier result VerifiedBootstrapTrust is now a sealed capability with private fields and read-only accessors. The DynamoDB QBT1-bound constructor requires a reference to VerifiedBootstrapTrust; callers cannot pass a naked receipt digest or construct the token outside the verifier module.

AwsDynamoDbOffhostAnchorStore::with_verified_bootstrap_runner rechecks the token's binding against the supplied Provider and Anchor pins:

- Provider ID, Anchor ID, network ID and Genesis digest;
- Provider and Anchor receipt-key IDs and ML-DSA-65 public-key fingerprints;
- initial Anchor sequence 1, Provider object generation 1 and ECR1 generation 0;
- exact initial ECR1 record digest and initial Anchor-state digest;
- exact encoded QBT1 receipt digest.

The adapter stores the canonical receipt bytes and its digest in a private immutable BootstrapTrustBinding. A path-backed constructor new_with_verified_bootstrap delegates to the same validation.

The existing unbound constructor remains for legacy candidate compatibility, but an unbound adapter now rejects an item containing QBT1 binding attributes. It cannot silently accept a QBT1-bound state.

## 3. One-item bootstrap commitment

The existing Anchor DynamoDB item now carries three immutable QBT1 attributes when constructed through the verified path:

- bootstrap_trust_receipt_digest
- bootstrap_trust_receipt_wire_b64
- bootstrap_initial_anchor_state_digest

item_for_state includes those exact attributes in the full PutItem image for the initial state and every successor. parse_item checks exact digest, exact Base64-encoded receipt bytes and exact initial-state digest on every strongly consistent read.

QBT1-bound bootstrap admission requires the exact generation-zero Provider record, Anchor sequence 1, Provider object generation 1, and a recomputed initial Anchor-state digest equal to the verifier-pinned value before any PutItem is sent.

The existing one-time bootstrap operation still uses server-side attribute_not_exists(anchor_id) conditional insertion. A concurrent loser does not trust a caller-supplied conflict payload; it obtains a fresh consistent read. In the QBT1-bound path, that read rejects missing, altered or different receipt commitments. A successful PutItem is followed by a fresh strongly consistent read and complete state comparison before Provisioned is returned.

## 4. Successor CAS commitment

For a QBT1-bound adapter, every successor PutItem condition now compares, in the same server-side conditional write:

- expected current Anchor sequence;
- expected full current Anchor-state digest;
- exact immutable QBT1 receipt digest;
- exact immutable initial Anchor-state digest;
- exact Base64-encoded QBT1 receipt wire bytes.

The successor PutItem image contains the same three immutable QBT1 attributes. A write that drops or substitutes the enrollment proof therefore fails the server-side condition. No client-side read-then-unconditional-write fallback was added.

The QBT1 attributes remain outside the legacy QAR1 V1 state wire and digest. The binding is enforced as immutable, separately pinned DynamoDB item metadata and as CAS preconditions. This preserves the existing QAR1/ECR1 V1 encodings; it does not claim that QBT1 has been incorporated into every QAR1 signed receipt payload.

## 5. Targeted tests

The following tests executed on heymed using Windows PowerShell 5.1 and the repository Rust toolchain:

| Test group / command | Result |
|---|---:|
| cargo fmt --manifest-path ... --all -- --check | PASS |
| external_cas_bootstrap_trust_candidate::tests | 10 passed, 0 failed |
| external_cas_offhost_anchor_aws_dynamodb_candidate::tests | 17 passed, 0 failed |
| external_cas_offhost_anchor_protocol_candidate::tests | 12 passed, 0 failed |
| qrun_v06_node_runtime_candidate::tests::qap1 | 12 passed, 0 failed |
| cargo check --manifest-path ... --bins | PASS |
| git diff --check | PASS |

Total: 51 targeted tests passed, zero failed. These are separate module test groups, not a full library test-suite run.

The five new DynamoDB adapter tests verify:

1. QBT1 receipt bytes, receipt digest and initial Anchor-state digest are included in the conditional bootstrap item and verified by strong read-back.
2. Every successor CAS includes the exact QBT1 receipt digest, exact initial-state digest and exact receipt-wire bytes in the same server-side condition, while preserving those fields in the successor item.
3. A strong read rejects an altered receipt digest or receipt wire.
4. Bootstrap refuses a state that does not match the verifier-pinned initial state before issuing any storage call.
5. The legacy unbound adapter refuses to read a QBT1-bound item.

The existing adapter tests continue to cover absent-key conditional bootstrap, concurrent provisioning loser behavior, fresh consistent reads, malformed/missing records, authoritative conflict state, and fail-closed AWS command errors.

The existing QAR1 tests cover signed reads, challenge replay, CAS concurrency, authoritative read-back and fail-closed behavior. The existing QAP1 group covers restart, lost-CAS-response recovery, cross-host driver/overlay policy, hybrid transfer finalization and QZXB/QUSDT test paths. The bind-policy test prints expected panic text while rejecting intentionally invalid addresses, and it finishes successfully.

The bin check completed successfully with existing unused-import/dead-code warnings in unrelated legacy modules and binaries. No new QBT1/DynamoDB compile error remained. Working-copy LF-to-CRLF notices were emitted by Git; git diff --check exited zero.

## 6. Deployment and trust limitations

No live AWS operation occurred. The AWS CLI was not available on the host during the earlier environment audit, and this CP uses the scripted AwsDynamoDbCliRunner test double. No credentials, AWS account ID, calling-role ARN, exact table ARN, table schema/ACTIVE status, region mode, IAM policy, SCP policy, KMS key policy or recovery-custodian permissions were verified.

The candidate adapter constructor still accepts a region and table name; it does not yet pin or prove the AWS account ID, exact table ARN, exact schema, single-region/global-table mode or the actual caller role. Production requires a separately administered AWS account, a qualified single-region table, strict IAM/SCP boundaries and a genuinely independent recovery custodian. A scripted CLI request is not cloud deployment evidence.

No dedicated off-host Anchor service executable or installed Windows service was created. No real owner/custodian ceremony, external BootstrapTrustPin delivery, second-person custody verification, production runtime callsite, Windows service SID/token, full effective AccessCheck, ACL policy, TPM-backed key, or independent monotonic witness was qualified.

QBT1 commitment is not yet included in the QAR1 V1 signed receipt payload or in each QAR1 successor's signed canonical payload. It is held in separate immutable DynamoDB item attributes and required by every conditional write. A versioned successor receipt/state format or separately authenticated startup proof still needs an explicit review before this is used as a complete production bootstrap chain.

Accordingly:

- Gate 8 remains **OPEN**.
- The external monotonic/anti-rollback witness is not deployed or proven independent of the host/cloud administrator.
- The ECR1/QAR1/QBT1 candidate is not yet integrated into the QAP1 node launch path.
- No public network, Mainnet, QZXB public release or public-launch readiness claim is authorized.

## 7. Next steps

CP-0763 should focus on a deployment-qualification contract that pins AWS account/role/table identity and rejects unsupported table modes before any bootstrap or CAS call. The live qualification must then verify:

1. exact table ARN and account ID;
2. base-table strongly consistent GetItem semantics;
3. single-region write serialization and rejection of unsupported global-table configuration;
4. caller role and IAM/SCP separation from node operator/owner roles;
5. independent recovery-custodian administration and immutable audit;
6. real bootstrap attribute_not_exists conditional creation, strong read-back, successor CAS and restoration/rollback attempt tests.

Only after those checks should a controlled real two-custodian enrollment and service provisioning be considered.

## 8. Repository safety and disposition

- Branch remains feat/cp0704-dual-attestation-rotation-gate-20261116.
- HEAD remains 5aba5f69d24fce03af742fd1bebf13ad00e5d9c3.
- Existing unrelated modified and untracked work was preserved.
- The DynamoDB adapter source is modified; CP-0762 adds this document.
- Nothing was staged, committed, pushed, merged, reset, cleaned or stashed.
- No AWS resource, Windows service, ACL, TPM, real signer key, node process, listener, wallet, account balance or network state was created or changed.

**Final disposition: QBT1-bound DynamoDB bootstrap/CAS candidate implemented; 51 targeted tests pass; no live AWS deployment; Gate 8 OPEN.**
