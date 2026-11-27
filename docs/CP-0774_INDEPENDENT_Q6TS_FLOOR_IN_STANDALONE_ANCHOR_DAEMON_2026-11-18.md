# CP-0774 — Independent Q6TS Floor in Standalone QAR2/QBT1 Anchor Daemon

**Date:** 2026-11-18  
**Project:** QRun / QFP6 / QZXB  
**Branch:** `feat/cp0704-dual-attestation-rotation-gate-20261116`  
**Worktree:** `D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116`  
**Observed HEAD:** `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`

## Disposition

**Q6TS STARTUP AUTHORIZATION ADDED TO STANDALONE ANCHOR / SEPARATE AWS ACCOUNT + ROLE + TABLE ENFORCED / DISTINCT READ-ONLY STS SESSION / PUTITEM DENIED IN RUNNER / TARGETED TESTS PASS / NO LIVE AWS / GATE 8 STILL OPEN**

CP-0773 added the standalone Anchor process but explicitly recorded that its startup did not yet load Q6TS or compare the signed profile-trust envelope with the independent monotonic floor. CP-0774 closes that code-level integration gap by reusing the existing Q6TS dual-signature verifier and read-only DynamoDB floor adapter. It does not claim the independent AWS trust service is deployed or operationally independent until external account and custodian evidence is supplied.

## 1. Trust design

The standalone daemon now requires two separate AWS trust contexts:

### Anchor service account

- QAR2/QBT1 DynamoDB Anchor store
- Anchor KMS ML-DSA-65 receipt key
- One short-lived STS assumed-role session
- One immutable runner shared only by the Anchor DynamoDB adapter and Anchor KMS signer
- Exact account, role, table, region and KMS key ARN pins

Environment variables supplied by the approved launcher:

- `QRUN_ANCHOR_STS_ACCESS_KEY_ID`
- `QRUN_ANCHOR_STS_SECRET_ACCESS_KEY`
- `QRUN_ANCHOR_STS_SESSION_TOKEN`
- `QRUN_ANCHOR_STS_EXPIRES_AT_UNIX`

### Independent Q6TS trust-floor account

- Separate AWS account ID (enforced to differ from Anchor account)
- Separate assumed role ARN
- Separate DynamoDB table ARN and region
- Separate short-lived STS session
- Read-only strongly consistent floor reads only
- Independently pinned Ed25519 + ML-DSA-65 Q6TS authority keyset
- Signed Q6TS envelope must be the exact already-published head of the monotonic floor

Environment variables supplied by the separately authorized launcher:

- `QRUN_Q6TS_STS_ACCESS_KEY_ID`
- `QRUN_Q6TS_STS_SECRET_ACCESS_KEY`
- `QRUN_Q6TS_STS_SESSION_TOKEN`
- `QRUN_Q6TS_STS_EXPIRES_AT_UNIX`

The two STS sessions are distinct. Both are captured once, expired sessions fail closed, child AWS CLI processes receive a clean allowlisted environment, and secret fields are zeroized on drop / invalid-session construction paths. No secret is accepted in the JSON config or command line.

## 2. Code changes

### 2.1 Read-only session-bound AWS runner

Updated `external_cas_offhost_anchor_aws_dynamodb_candidate.rs`:

- Added `SessionBoundAwsDynamoDbCliRunner::new_read_only`.
- Added an immutable operation-capability flag.
- The read-only runner accepts the reviewed `GetItem` and qualification operations but rejects `PutItem` before starting a child process.
- Unsupported operations such as `UpdateItem` remain outside the accepted command grammar.
- The normal Anchor runner still has the reviewed conditional PutItem capability required by QAR2 CAS and shares its exact STS session with KMS.

### 2.2 Qualified Q6TS read-only floor adapter

Updated `qrun_v06_profile_trust_dynamodb_floor_candidate.rs`:

- Added a bridge from the common session-bound AWS runner to the Q6TS floor CLI interface.
- Added `AwsDynamoDbQ6tsReadOnlyProfileTrustFloorStore::with_session_bound_read_only_runner`.
- The constructor refuses a writable runner and any deployment-pin substitution before AWS qualification.
- It runs the existing account/assumed-role/table qualification and revalidates the identity before every floor read.
- The Q6TS node-facing adapter still rejects `compare_and_swap`; startup cannot initialize, advance, or revoke the floor.

### 2.3 Q6TS authorization is now mandatory in standalone Anchor startup

Updated `bin/qrun_v06_anchor_daemon.rs`:

- Added Q6TS trust-envelope, Ed25519 authority key, ML-DSA-65 authority key and keyset-ID fields to the strict config.
- Added a distinct Q6TS floor deployment pin.
- The Q6TS account/role/table is validated and must be separate from the Anchor account/role/table. Same-account configuration fails closed.
- The Ed25519 and ML-DSA-65 public-key lengths and independently pinned keyset ID are verified.
- Q6TS trust envelope bytes are loaded as an untrusted input; the existing verifier authenticates both signatures and the exact Q6PN network/profile/commitment.
- The separately administered DynamoDB floor is loaded using strongly consistent reads. Q6TS epoch, status, record ID and envelope ID must match the already-published floor head.
- A revoked profile, missing floor, stale envelope, same-epoch conflict, wrong keyset, wrong profile context, role/table drift, or trust-service outage aborts startup.
- No Q6TS fallback, local floor, automatic floor bootstrap or floor update is allowed.
- Q6TS authorization is performed before the Anchor runner is created and before the TCP listener can be bound. The READY log includes the authorized Q6TS trust epoch.

This uses the existing `authorize_qrun_v06_profile_pin` path and its read-only floor semantics. The trust publisher remains a separate administrative process; the Anchor daemon is not a trust publisher.

## 3. Config additions

The digest-pinned JSON config now requires:

- `q6ts_trust_envelope_path`
- `q6ts_authority_ed25519_path`
- `q6ts_authority_mldsa65_path`
- `q6ts_authority_keyset_id`
- `q6ts_floor_account_id`
- `q6ts_floor_role_arn`
- `q6ts_floor_table_arn`
- `q6ts_floor_region`
- `q6ts_floor_table_name`

All referenced paths must be absolute regular non-symlink files within configured size limits. The full config SHA-256 remains supplied separately at launch. The Q6TS floor must be pre-provisioned; startup never creates it.

## 4. Verification on heymed

| Check | Result |
|---|---:|
| Read-only AWS runner command-scope test | 1 passed |
| Q6TS DynamoDB floor adapter suite | 12 passed |
| Standalone Anchor executable tests | 4 passed |
| `cargo check --bin qrun_v06_anchor_daemon` | PASS |
| `cargo check --bins` | PASS |
| `cargo build --bin qrun_v06_anchor_daemon` | PASS |
| No-argument executable smoke test | Expected FAIL_CLOSED usage error, exit code 1 |
| `cargo fmt --all -- --check` | PASS |
| `git diff --check` | PASS |

The executable smoke test did not load credentials, make an AWS request, bind a port or change any external service. These are targeted tests, not the full repository suite. Existing unrelated unused/dead-code warnings remain.

## 5. Source / executable SHA-256

| File | SHA-256 |
|---|---|
| `external_cas_offhost_anchor_aws_dynamodb_candidate.rs` | `6CAFCDBAC4B7DB018AE5C997CF4AAEED99AA7E8655AFA6D784BA52FDD46088B9` |
| `qrun_v06_profile_trust_dynamodb_floor_candidate.rs` | `4B0F89EE01C0180787785D1BF01932B7369B43DFEC3AA720931AB15D533D3347` |
| `bin/qrun_v06_anchor_daemon.rs` | `1486E532C787A44A39FED5C5C1F8885CED968F3EC90405D756BAA3C2A2C4E654` |
| `target/debug/qrun_v06_anchor_daemon.exe` | `9E6991F96CB216E07ACA3D055E5A5AD0650522351EEAF96AD9482DC130EEA130` |

## 6. Remaining operational blockers

This checkpoint closes the source-level Q6TS startup integration gap only. The following are still not verified:

- The Q6TS AWS account, role, DynamoDB table and read-only IAM policy have not been created or independently inspected in this environment.
- No live Q6TS STS session, live GetItem, CloudTrail event or external Q6TS authority ceremony was exercised.
- The Q6TS trust publisher must separately pre-provision the epoch-zero floor and advance it before publishing the exact signed Q6TS envelope. Startup refuses to do either operation.
- The local Q6TS envelope and key files still require secure deployment, provenance, independent backups and operator control.
- The actual Anchor listener was not started; no remote client performed live QAR2 Read/CAS against AWS.
- Windows handle-bound ACL/ancestor/volume qualification and whole-host snapshot rollback proof remain open.
- Independent custodian, backup-vault isolation, external security review, public operator test and recovery ceremony remain outstanding.

Therefore:

- **Q6TS startup integration: CODE-LEVEL COMPLETE / LIVE DEPLOYMENT UNVERIFIED**
- **Gate 8: OPEN**
- **Gate 2: OPEN**
- **Public launch / Mainnet / trading readiness: NO-GO**

## 7. Git preservation

- Branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`.
- Observed HEAD remains: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`.
- No files staged.
- No commit, push, merge, reset, clean, stash or checkout was performed.
- All previously modified and untracked work was preserved.
- This checkpoint is an engineering audit note, not a release tag or launch authorization.

**Final disposition:** the standalone QAR2/QBT1 Anchor daemon now performs mandatory Q6TS dual-signature verification against a separately pinned read-only monotonic floor in a distinct AWS account and a distinct STS session. This removes the code-level trust-floor omission noted in CP-0773. Live independent AWS deployment and whole-host rollback evidence are still outstanding.
