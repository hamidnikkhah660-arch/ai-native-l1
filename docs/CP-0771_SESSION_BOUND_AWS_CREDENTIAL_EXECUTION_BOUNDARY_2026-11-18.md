# CP-0771 — Session-Bound AWS Credential Execution Boundary
**Date:** 2026-11-18
**Project:** QRun / QFP6 / QZXB
**Parent:** CP-0770 — QBT1 Qualified Remote-State and Stale-Snapshot Rollback Harness
**Branch:** `feat/cp0704-dual-attestation-rotation-gate-20261116`
**Observed HEAD before/after:** `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`

## Disposition

**PRODUCTION AWS CONSTRUCTION PATH HARDENED TO ONE EXPLICIT TEMPORARY STS CREDENTIAL SNAPSHOT / EXACT CALLER ARN + STS USER-ID PINNED ACROSS REVALIDATION / AMBIENT AWS CONFIGURATION AND COMMAND OVERRIDES BLOCKED / TARGETED TESTS PASS / NO LIVE AWS CREDENTIALS OR CLI ON HOST / GATE 8 OPEN**

CP-0771 addresses the CP-0764 time-of-check/time-of-use boundary in the code contract. The public production service constructor no longer accepts an arbitrary `AwsDynamoDbCliRunner`; it requires a concrete session-bound runner carrying one temporary STS credential snapshot and the exact account/role/table/region deployment pin.

This is an implementation and scripted verification checkpoint. It is not a live cloud qualification.

## 1. Code changes

### 1.1 Immutable temporary credential session

Added `AwsTemporaryCredentialSession` in:

`src/native/pow_bench/src/external_cas_offhost_anchor_aws_dynamodb_candidate.rs`

The session:
- requires nonempty access-key ID, secret key and STS session token;
- rejects whitespace-padded/control-character values;
- rejects credentials already expired or within a 30-second safety window;
- has no refresh/discovery path and is not `Clone`;
- redacts every credential field in `Debug`;
- exposes only the expiry timestamp, not the credential material.

The credential acquisition/AssumeRole ceremony is deliberately not implemented here. An authorized operator must obtain short-lived credentials out-of-band and supply them in memory. Secrets must not be placed in source, checkpoint documents, command-line arguments, or chat.

### 1.2 Session-bound AWS CLI process runner

Added `SessionBoundAwsDynamoDbCliRunner`.

At construction it:
- requires an absolute AWS CLI executable path and canonicalizes it;
- binds the runner to one complete `AwsDynamoDbDeploymentPin`;
- owns the one temporary credential snapshot and does not accept a replacement or refresh provider.

Before every child process it:
- checks the credential expiry safety window again;
- validates the command against a closed grammar;
- accepts only the exact STS identity, IAM role, pinned DynamoDB table/region qualification calls, and the adapter's reviewed GetItem/PutItem operations;
- rejects duplicate flags, unknown flags, alternate command families, endpoint/profile switches and endpoint values embedded in a combined flag.

The child process is started without a shell and with `env_clear()`. Only the explicit temporary STS credentials, pinned region, null config/shared-credentials paths, standard retry controls, metadata-provider disablement, and endpoint-config ignore setting are installed. Ambient AWS profiles, shared credential files, web-identity/container credential sources, endpoint overrides, CA-bundle overrides, and proxy environment variables are not inherited. On Windows only the minimal OS process-start/certificate-store variables are additionally passed.

### 1.3 Exact caller-session continuity

Updated the qualification result and revalidating wrapper in:

`src/native/pow_bench/src/external_cas_offhost_anchor_aws_qualification_candidate.rs`

Initial qualification records both:
- exact STS assumed-role caller ARN;
- exact STS `UserId` (role unique ID plus session identity).

Before every DynamoDB operation, all four identity/role/table/backup qualification checks are repeated. The request is delegated only if both exact caller values still match the values pinned by the initial qualification. A same-account/same-role session replacement is therefore rejected before GetItem/PutItem.

The runner itself also checks the exact deployment pin. The public store constructor refuses a caller-supplied account/role/table/region pin that differs from the runner's immutable pin.

### 1.4 Public construction surface

Updated:

`src/native/pow_bench/src/external_cas_offhost_anchor_protocol_v2_candidate.rs`

The public production factory is now:

`QAR2BoundAnchorService::with_session_bound_aws_dynamodb(...)`

It accepts the concrete `SessionBoundAwsDynamoDbCliRunner`, exact deployment pin, Anchor/Provider pins and verified QBT1 capability.

The arbitrary-runner QAR2 composition entry point is now `cfg(test)` only. The raw revalidating-runner factory and arbitrary-runner store constructor are crate-private. The previous process runner that relied on the ambient AWS CLI credential chain, along with its legacy constructors, is test-only and cannot be selected by a production build.

## 2. Verification on heymed

| Test group | Result |
|---|---:|
| Session-bound runner / environment / strict command grammar | 6 passed, 0 failed |
| AWS qualification / exact session continuity / deployment-pin substitution | 14 passed, 0 failed |
| QAR2 v2 / QBT1 / qualified-state restart and stale replay | 8 passed, 0 failed |
| DynamoDB adapter regression tests | 17 passed, 0 failed |
| **Total targeted tests** | **45 passed, 0 failed** |
| `cargo check --bins` (production, non-test build) | PASS |
| `cargo fmt --all -- --check` | PASS |
| `git diff --check` | PASS |

The QAR2 group includes the CP-0770 stateful service-double test. The 45 tests are targeted module groups, not the full crate suite. Existing unrelated unused/dead-code warnings remain; no warning was promoted to an error. Existing Git LF-to-CRLF informational notices remain.

Specific negative checks include:
- expired/near-expiry STS credentials rejected;
- missing STS session token rejected;
- credential values absent from Debug output;
- ambient profile, shared-credentials, metadata, endpoint and proxy sources absent from the child environment allowlist;
- endpoint override supplied as `--endpoint-url=value`, duplicate region, missing consistent-read, and unapproved commands rejected by the runner itself;
- same account/role but changed assumed-role session ARN/UserId rejected before GetItem;
- deployment-pin substitution rejected before any AWS call.

## 3. Live environment inspection

The actual `heymed` environment was inspected without reading or disclosing any secret values:

- AWS CLI executable: **not found**.
- `AWS_ACCESS_KEY_ID`: absent.
- `AWS_SECRET_ACCESS_KEY`: absent.
- `AWS_SESSION_TOKEN`: absent.

Consequently no real STS call, role qualification, DynamoDB read, conditional write, bootstrap, or rollback operation could be performed. Test credentials used by the unit tests are synthetic and never leave the test process. No AWS account or cloud resource was contacted or changed.

## 4. Remaining limits — why Gate 8 is still open

This checkpoint closes an important code-level credential/session substitution gap, but does not prove the real independent anti-rollback property.

Still required:
1. Install/qualify AWS CLI v2 on the authorized operator host and obtain a short-lived assumed-role STS credential session through the authorized, separately administered role. Do not paste credentials into source or chat.
2. Run the new public session-bound API against the actual pinned account, assumed-role identity and single-region DynamoDB table; preserve redacted command/result receipts and independently verify the exact AWS caller identity.
3. Independently audit IAM policies, permission boundaries, SCPs, table/resource policies, KMS key policy, CloudTrail/audit retention, backup-vault isolation and operator/custodian separation.
4. Provision the QBTB1 bundle out-of-band with real owner/custodian pins and a second-person ceremony.
5. Operate the QAR2 Anchor service under a separate administrative boundary and demonstrate that a whole-host snapshot restore/replay cannot roll its monotonic state backward. The CP-0770 backend was a test double and is not this witness.
6. Perform independent restart/recovery and external security review.

The runner remains an AWS CLI child-process boundary. It pins the same temporary credentials and caller identity across invocations and strips ambient endpoint/profile/proxy configuration, but this checkpoint does not prove live TLS routing, actual AWS service semantics, or the absence of host compromise. Those require the live deployment and independent review above.

Therefore:
- **Gate 8 remains OPEN.**
- **Gate 2 remains OPEN**; this change does not finish PMT4/PFM4 runtime/network/reorg integration.
- Mainnet and public launch remain **NO-GO**.

## 5. Git preservation

- Branch unchanged: `feat/cp0704-dual-attestation-rotation-gate-20261116`.
- HEAD unchanged: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`.
- No files staged; no commit, push, merge, reset, clean, stash or checkout.
- Existing uncommitted work, including CP-0770 and all older CP documents/modules, was preserved.
- This note is an untracked engineering checkpoint, not a tag or release authorization.

**Final disposition: CP-0771 session-bound credential execution boundary implemented and 45 targeted tests plus production bin build pass; live AWS and independent monotonic-witness evidence absent; Gate 8 OPEN.**
