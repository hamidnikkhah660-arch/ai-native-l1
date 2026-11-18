# CP-0764 - QBT1 qualified AWS runner boundary and CLI scope hardening

Date: 2026-11-17  
Project: QRun Blockchain / QFP6 / QZXB  
Parent: CP-0763 read-only AWS deployment qualification  
Branch: feat/cp0704-dual-attestation-rotation-gate-20261116  
Worktree: D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116  
Observed HEAD: 5aba5f69d24fce03af742fd1bebf13ad00e5d9c3  
Disposition: **QUALIFIED QBT1 CONSTRUCTOR AND STRICT CLI COMMAND GATE ADDED / 29 TARGETED TESTS PASS / BIN CHECK PASS / NO LIVE AWS / GATE 8 OPEN**

## 1. Baseline discovery

The worktree already contained an initial `RevalidatingAwsDynamoDbCliRunner` in the CP-0763 qualification candidate. It re-ran account/role/table qualification before each delegated DynamoDB operation and checked the pinned table and region. This checkpoint does not claim that wrapper was newly invented here. Review found that its original argument check was too permissive: it did not reject endpoint/profile overrides, duplicate flags, unknown CLI options or unapproved DynamoDB operations.

## 2. Strict command grammar

The revalidating runner now permits only `dynamodb get-item` and `dynamodb put-item`. It parses the argument vector and rejects:

- any unrecognized CLI option or positional argument;
- duplicate flags, including duplicate table/region selectors;
- endpoint/profile overrides, `--no-sign-request`, TLS verification overrides and alternate CLI input sources;
- any command other than get-item/put-item;
- wrong/missing table or region, missing JSON output, changed timeout settings, or missing required operation-specific arguments.

The allowed option grammar is deliberately limited to the adapter's reviewed command construction. Each accepted storage command still triggers fresh read-only account, assumed-role, role ARN, table ARN, ACTIVE/schema/single-region, encryption/deletion-protection and PITR checks before the delegated storage command.

## 3. Qualified QBT1 construction path

Added `AwsDynamoDbOffhostAnchorStore::with_qualified_verified_bootstrap_runner`. It accepts the raw runner, exact `AwsDynamoDbDeploymentPin`, Anchor and Provider pins, and sealed `VerifiedBootstrapTrust`; it obtains the revalidating runner through `qualified_aws_dynamodb_runner` before constructing the QBT1-bound store.

The prior unqualified adapter constructors (`new`, `from_path`, `with_runner`, `with_verified_bootstrap_runner`, and `new_with_verified_bootstrap`) are now crate-private. This prevents external crate consumers from selecting those unqualified construction paths. The qualified constructor is the public construction entry point for external callers. In-repository search found no production callsite for the adapter; only its own tests referenced the legacy constructors. Thus this is a safe candidate API boundary, not proof that a production node is already using it.

## 4. Tests and build evidence

Executed on `heymed` with Windows PowerShell 5.1 and repository Rust toolchain:

| Check | Result |
|---|---:|
| `cargo fmt --manifest-path ... --all -- --check` | PASS |
| `external_cas_offhost_anchor_aws_qualification_candidate::tests` | 12 passed, 0 failed |
| `external_cas_offhost_anchor_aws_dynamodb_candidate::tests` | 17 passed, 0 failed |
| `cargo check --manifest-path ... --bins` | PASS |

Total: 29 targeted tests passed, zero failed. New negative tests reject endpoint/profile overrides, duplicate table/region flags, `--no-sign-request`, `--no-verify-ssl`, alternate input source, unapproved operations and incomplete PutItem command contracts. An additional test constructs the QBT1 store through the qualified public constructor and confirms the four initial read-only qualification calls occur.

The bin check completed with existing unused-import/dead-code/unused-mut warnings in legacy modules and binaries. This is not a full test-suite run. The first test run after tightening the grammar exposed an outdated test fixture that lacked the newly required PutItem arguments; the fixture was corrected to model the actual adapter command and the full qualification test group then passed.

## 5. Important residual trust limits

This remains a candidate boundary, not an atomic AWS credential/session binding. The wrapper performs identity/table preflight and then delegates a separate AWS CLI invocation. A concurrent change to shared AWS credential/configuration files, a changed credential provider result, or endpoint configuration outside the command-line argument vector could still create a time-of-check/time-of-use gap. The current process runner inherits its environment and AWS CLI configuration; the command allowlist alone does not prove the actual TLS endpoint or effective IAM/SCP policy. The role ARN check does not prove that the caller's effective permissions are least-privilege.

A production-grade boundary still needs an authenticated AWS SDK/client or isolated credential/configuration context that pins the actual service endpoint and credential identity for the same execution context used by every operation, plus independently verified IAM permission boundaries/SCP/resource policies/KMS and recovery-custodian separation. A real AWS deployment and external review are still mandatory.

## 6. Live status and Gate 8

AWS CLI was not found on the host. All tests used scripted runners and synthetic identities/table responses. No AWS credentials, accounts, roles, tables, policies, KMS keys, backups, services or network resources were accessed or changed. No real bootstrap, live strongly consistent read, CAS, stale-write test or rollback attempt occurred.

Gate 8 remains **OPEN**. The independent monotonic anti-rollback witness, independent custodian, production caller integration, Windows service identity/effective ACL authorization and live cloud recovery evidence remain unproven. No public network, Mainnet or public launch authorization follows from this checkpoint.

## 7. Repository safety

- Branch remains `feat/cp0704-dual-attestation-rotation-gate-20261116`.
- HEAD remains `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`.
- Existing unrelated modified and untracked files were preserved.
- Nothing was staged, committed, pushed, merged, reset, cleaned or stashed.
- No live cloud resources or credentials were touched.

**Final disposition: public QBT1 construction now requires the qualified runner API; the runner rejects unreviewed CLI command/option paths and revalidates before each storage call; 29 targeted tests pass and all bins compile; no live AWS evidence; Gate 8 OPEN.**
