# CP-0773 — Standalone QAR2/QBT1 Anchor Daemon and Shared Session-Bound KMS

**Date:** 2026-11-18  
**Project:** QRun / QFP6 / QZXB  
**Branch:** `feat/cp0704-dual-attestation-rotation-gate-20261116`  
**Worktree:** `D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116`  
**Observed HEAD before/after:** `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`

## Disposition

**STANDALONE QAR2/QBT1 ANCHOR EXECUTABLE ADDED / Q6PN+QBTB1 CONFIGURATION PINNED / NOISE KEY LOADED FROM DPAPI / SAME TEMPORARY STS RUNNER SHARED BY DYNAMODB AND KMS / TARGETED TESTS PASS / ALL BINARIES CHECK / NO LIVE AWS / GATE 8 OPEN**

CP-0773 takes the session-bound QAR2 daemon composition from CP-0772 and gives it a dedicated executable entry point. It also closes a credential-boundary gap: the Anchor KMS signer now uses the exact same immutable temporary-STS runner as the DynamoDB Anchor store, not the normal ambient AWS credential provider chain.

## 1. Code changes

### 1.1 Shared session-bound DynamoDB and KMS runner

Updated:

- `external_cas_offhost_anchor_aws_dynamodb_candidate.rs`
- `external_cas_aws_kms_signer_candidate.rs`
- `external_cas_offhost_anchor_aws_qualification_candidate.rs`
- `external_cas_offhost_anchor_protocol_v2_candidate.rs`
- `external_cas_offhost_anchor_noise_daemon_candidate.rs`

The concrete `Arc<SessionBoundAwsDynamoDbCliRunner>` is now shared by:

- `AwsDynamoDbOffhostAnchorStore` / `QAR2BoundAnchorService`; and
- `SessionBoundAwsKmsCliOffhostAnchorReceiptSigner`.

The runner is constructed with one temporary STS credential snapshot, one account/role/table/region deployment pin and one exact KMS key ARN. The allowed AWS command grammar is limited to the reviewed STS/IAM/DynamoDB operations plus KMS `GetPublicKey` and `Sign`. KMS signing requires the exact pinned key ARN, `RAW`, `ML_DSA_SHAKE_256`, and a base64 message that decodes to exactly 32 bytes. Aliases, foreign account/region keys, alternate key ARNs and other KMS command families are rejected.

The session-bound KMS signer validates KMS key metadata (`ML_DSA_65`, `SIGN_VERIFY`, supported signing algorithm), checks the SPKI public key against the independently pinned Anchor key and verifies a startup challenge signature locally. Every receipt signature is also verified locally before it is returned.

Temporary STS strings are zeroized when the session is dropped and on invalid-session construction paths. Debug output redacts credential fields.

### 1.2 Standalone executable

Added:

`src/native/pow_bench/src/bin/qrun_v06_anchor_daemon.rs`

The binary requires exactly two CLI arguments:

`qrun_v06_anchor_daemon <absolute-config-path> <config-sha256>`

The complete config bytes are SHA-256 checked against the separately supplied command-line pin before deserialization. The JSON struct rejects unknown and duplicate fields. Q6PN and QBTB1 are then independently checked using their configured commitments/digests; the QBT1 receipt is verified against the Provider and Anchor pins derived from Q6PN plus the supplied Anchor public key.

The executable then:

1. Captures the short-lived STS session from the four explicit `QRUN_ANCHOR_STS_*` environment variables and removes those variables from its process environment.
2. Constructs one session-bound runner pinned to the AWS deployment and exact Anchor KMS key ARN.
3. Uses that same runner to qualify the KMS key, verify its public key and perform the startup signature test.
4. Loads the Anchor Noise private key through the existing NPK1 / Windows CurrentUser DPAPI loader, bound to the Q6PN network ID.
5. Constructs the QAR2/QBT1 Anchor daemon through `bind_qbt1_session_bound_aws_dynamodb`. The constructor qualifies the DynamoDB deployment and QBT1-bound store before it binds the TCP listener.
6. Runs the bounded daemon with Windows console shutdown or Unix SIGINT/SIGTERM handling.

It does not accept secret material on the command line or in the JSON config. It does not discover ambient AWS profiles, refresh credentials, generate owner/custodian keys, enroll a first-use Anchor, create AWS resources, or fall back to QAR1.

### 1.3 Configuration contract

The JSON configuration contains only public deployment parameters and file paths:

- Q6PN path and independently pinned profile commitment;
- QBTB1 path and full-file SHA-256;
- Anchor ID, receipt-key ID and public-key path;
- protected NPK1 Noise-key path and trusted client Noise public-key pins;
- listener address and bounded worker/queue sizes;
- absolute AWS CLI path, account ID, role ARN, DynamoDB table ARN/name and region;
- full Anchor KMS key ARN.

The external launcher must separately supply the SHA-256 of the complete config file as the second CLI argument. The temporary credential inputs are:

- `QRUN_ANCHOR_STS_ACCESS_KEY_ID`
- `QRUN_ANCHOR_STS_SECRET_ACCESS_KEY`
- `QRUN_ANCHOR_STS_SESSION_TOKEN`
- `QRUN_ANCHOR_STS_EXPIRES_AT_UNIX`

The operator must obtain these short-lived assumed-role credentials through the authorized process and inject them securely into the service environment. They must not be stored in the config, source, checkpoint or command line.

The QBT1 generation-zero item must already be provisioned in the pinned DynamoDB table. This executable deliberately refuses to perform first-use enrollment.

## 2. Verification on heymed

| Check | Result |
|---|---:|
| Session-bound AWS runner tests | 8 passed |
| QAR2 v2 protocol/facade tests | 8 passed |
| AWS deployment qualification tests | 14 passed |
| QAR2 Noise daemon tests | 22 passed |
| AWS KMS signer tests | 4 passed |
| Standalone Anchor executable config/digest tests | 3 passed |
| `cargo check --bin qrun_v06_anchor_daemon` | PASS |
| `cargo build --bin qrun_v06_anchor_daemon` | PASS — executable produced |
| Executable no-argument smoke test | Expected fail-closed usage error, exit code 1; no AWS or listener activity |
| `cargo check --bins` | PASS |
| `cargo fmt --all -- --check` | PASS |
| `git diff --check` | PASS |

The suite counts above are targeted module/binary tests, not the full repository suite. The dedicated session-bound KMS key-substitution and daemon deployment-pin-substitution tests are included in their respective module counts. Existing unrelated unused/dead-code warnings remain; no warning was promoted to an error.

## 3. Source integrity

SHA-256 after formatting and the successful targeted checks:

| File | SHA-256 |
|---|---|
| `Cargo.toml` | `885DD2111D9E1C97CEE8809C7E7910A226FB7D2F930082C776579D0383632BA5` |
| `Cargo.lock` | `B7F2D4E878707D4395BFFEC423560CE71428C0DF2C22EA0B959FCC6F274905C7` |
| `external_cas_offhost_anchor_aws_dynamodb_candidate.rs` | `421B1BDF04BF1EBDB1C7741D28B592EF43A249A84E169D77C6F6DF5D08CB64BC` |
| `external_cas_aws_kms_signer_candidate.rs` | `B17A8A00CCB3ED8FB4DF31ADF3D9F8703A55D307BDA2AFE34FA7EB53DB3CFF0B` |
| `external_cas_offhost_anchor_aws_qualification_candidate.rs` | `D8D10FD79FB118DE710061F1FF92F89D8CB93A741FB415A07C432D8E76AB5B9A` |
| `external_cas_offhost_anchor_protocol_v2_candidate.rs` | `1837A9627FC18EFC6D483044CE89065CF11C7875F0AAEC309678801D6C51F6DD` |
| `external_cas_offhost_anchor_noise_daemon_candidate.rs` | `E2A66D1C7F644EBF1A80F2A2223F897E7EC209A59FF1C7414A2D6C8680580B99` |
| `bin/qrun_v06_anchor_daemon.rs` | `6D4A05AD30AF249960F625349CA40DC657373B6DFA0D23E4C1DDF21A034E5739` |
| `target/debug/qrun_v06_anchor_daemon.exe` | `2CB904520AFE309EC6F2E5DAFF3AE5ACB36D7987A7C490FF6318318B3EF950E2` |

## 4. Explicit limits and open requirements

This is a compiled standalone executable and a code-level composition path, not a deployed Anchor service.

- No AWS CLI, live STS credentials, AWS account/table/KMS key or custodian session was available for a real deployment test. No live AWS API was called and no cloud resource was changed.
- The actual listener was not started. No real client performed QAR2 Read/CAS against a live Anchor.
- Q6TS profile trust-envelope revocation and its independent monotonic trust-floor lookup are not yet integrated into this standalone daemon's startup path. Q6PN/QBTB1 verification alone must not be represented as the complete Q6TS revocation policy.
- The NPK1 loader uses Windows CurrentUser DPAPI; this is at-rest protection for the provisioned Windows user, not an HSM and not protection against that user's live-process inspection.
- The binary's bounded regular-file checks and digest verification do not replace the unfinished handle-bound Windows ancestor/ACL/volume qualification. A whole-host snapshot rollback test against a separately administered monotonic witness is still required.
- IAM/SCP/KMS key policies, CloudTrail retention, backup-vault isolation, independent owner/custodian ceremony and external security review remain unverified.
- This work does not implement PMT4/PFM4 runtime networking, archive sync or a two-process reorg/restart test.

Therefore:

- **Gate 8 remains OPEN.**
- **Gate 2 remains OPEN.**
- Public launch / Mainnet remains **NO-GO**.

## 5. Git preservation

- Branch unchanged: `feat/cp0704-dual-attestation-rotation-gate-20261116`.
- HEAD unchanged: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`.
- No files staged.
- No commit, push, merge, reset, clean, stash or checkout was performed.
- All prior modified and untracked work was preserved.
- This note is an untracked engineering checkpoint, not a release tag or launch authorization.

**Final disposition: the standalone QAR2/QBT1 Anchor executable compiles, strict config/preflight tests pass, the shared STS/DynamoDB/KMS code path passes targeted regressions, and all binaries check successfully. Live AWS deployment, Q6TS floor integration and independent anti-rollback proof remain outstanding.**
