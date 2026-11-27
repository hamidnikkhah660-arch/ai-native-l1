# CP-0763 - Read-only AWS deployment qualification candidate

Date: 2026-11-17  
Project: QRun Blockchain / QFP6 / QZXB  
Parent: CP-0762 QBT1-bound DynamoDB bootstrap and immutable CAS  
Branch: feat/cp0704-dual-attestation-rotation-gate-20261116  
Worktree: D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116  
Observed HEAD: 5aba5f69d24fce03af742fd1bebf13ad00e5d9c3  
Disposition: **READ-ONLY QUALIFICATION CANDIDATE PRESENT AND COMPILES / 7 SCRIPTED TESTS PASS / NO LIVE AWS / NOT WIRED AS A MANDATORY ADAPTER GATE / GATE 8 OPEN**

## 1. Scope and provenance

The worktree already contained `src/native/pow_bench/src/external_cas_offhost_anchor_aws_qualification_candidate.rs` as an untracked source file and its module declaration in `src/native/pow_bench/src/lib.rs` before this CP audit. This checkpoint records a direct source review and runtime validation; it does not claim that the source was newly created in this checkpoint.

The module is a read-only preflight candidate. It makes four AWS CLI calls in order: `sts get-caller-identity`, `iam get-role`, `dynamodb describe-table`, and `dynamodb describe-continuous-backups`. The source comment's description of five calls is inaccurate; the implementation performs four.

## 2. Pin and identity checks

`AwsDynamoDbDeploymentPin` pins account ID, IAM role ARN, DynamoDB table ARN, region and table name. Local validation checks a 12-digit account ID, nonempty ASCII region/table name, account-scoped IAM role ARN prefix and exact region/account/table ARN prefix.

The live-response parser (currently exercised only with scripted outputs) checks:

- STS account ID equals the pinned account;
- caller ARN is an assumed-role session for the pinned role name, not an IAM user or another role;
- `iam get-role` returns the exact pinned role ARN and role name;
- `describe-table` returns the exact pinned table ARN and `ACTIVE` status.

## 3. Table safety profile

The current contract rejects Global Tables indicators (`GlobalTableVersion` or nonempty/malformed `Replicas`), and requires the exact one-partition-key schema `anchor_id` of type string. It also requires deletion protection enabled, DynamoDB server-side encryption status `ENABLED`, and point-in-time recovery status `ENABLED`.

This is a useful deployment identity/configuration filter, not a complete cloud-security qualification. In particular, it does not verify the effective IAM permission set, permission boundaries, SCPs, resource policies, KMS key identity/key policy, CloudTrail immutability, backup-vault isolation, organization/account ownership, network boundaries, or a distinct recovery custodian. It does not prove strong-read behavior against a live table or the operational behavior of conditional CAS.

## 4. Tests and build evidence

Executed on `heymed` using Windows PowerShell 5.1 and the repository Rust toolchain:

| Check | Result |
|---|---:|
| `cargo fmt --manifest-path ... --all -- --check` | PASS |
| `cargo test --manifest-path ... --lib external_cas_offhost_anchor_aws_qualification_candidate::tests:: -- --nocapture --test-threads=1` | 7 passed, 0 failed |
| `cargo check --manifest-path ... --bins` | PASS |

The seven scripted tests cover the valid exact pin, wrong account early rejection, wrong/user caller principal, role/table ARN drift, non-ACTIVE/global/wrong-key-schema tables, disabled deletion protection/SSE/PITR, and malformed responses/invalid pins. The valid-path test asserts exactly four read-only CLI calls and excludes mutation commands such as PutItem, UpdateItem, CreateTable and DeleteTable.

The bin check passed with existing unused-import/dead-code warnings in unrelated modules and binaries. This was not a full test-suite run.

## 5. Critical integration limitation

`QualifiedAwsDynamoDbDeployment` is a sealed result with read-only accessors, but the current DynamoDB adapter constructors do not require this qualification capability. The qualification result is not yet consumed by `AwsDynamoDbOffhostAnchorStore`, and it does not bind later adapter commands to an immutable AWS credential/session. Therefore a successful preflight must not be treated as a hard runtime authorization barrier: credentials or CLI profile could change after preflight, and callers can still construct/use the adapter through its existing paths.

Before production integration, design a fail-closed execution boundary that binds the verified account, role, region and table to the same authenticated execution context used for each read/write, or revalidates that identity at the point of every mutation. A one-time CLI preflight followed by unrelated CLI invocations is insufficient evidence of identity continuity.

## 6. Live deployment status and Gate 8

The AWS CLI was not found on the Windows host during this session. No live AWS API call was made; all tests used `ScriptedRunner`. No AWS credentials, account ID, real role ARN, real table ARN, table, IAM/SCP policy, KMS key, backup vault, service or external witness was created or changed. The example account/role/table values in tests are synthetic fixtures only.

Gate 8 remains **OPEN**. An independent monotonic anti-rollback witness, authenticated authoritative reads/receipts, real two-custodian bootstrap, independent recovery administration, production service identity and rollback/recovery attempt testing remain unproven. The QBT1-bound DynamoDB adapter remains a candidate and is not yet gated by this preflight in its runtime call path. No public network/Mainnet/public-launch authorization follows from this checkpoint.

## 7. Next required work

1. Design and test a mandatory execution boundary so no bootstrap/CAS can occur without a live identity-bound qualification for the same AWS execution context.
2. Obtain real independently controlled account/role/table identifiers and credentials through the authorized operator; do not invent them or store secrets in source/docs.
3. Independently inspect IAM policies, permission boundaries, SCPs, KMS and backup custody; prove separation from node operator and owner roles.
4. In a controlled non-production account, run real read-only qualification, then separately authorize a two-custodian bootstrap, strongly consistent read-back, conditional successor CAS, stale-write rejection, and rollback/recovery attempts.
5. Integrate the QBT1/QAR1 trust chain with the production caller and independent monotonic witness; require external review before closing Gate 8.

## 8. Repository safety

- Branch and HEAD remain unchanged.
- Existing modified and untracked work was preserved.
- No file was staged or committed; nothing was pushed, merged, reset, cleaned or stashed.
- No live AWS resources or credentials were accessed or changed.

**Final disposition: read-only AWS qualification candidate validated with seven scripted tests and all bins compiling; not a live cloud qualification and not yet a mandatory runtime gate; Gate 8 OPEN.**
