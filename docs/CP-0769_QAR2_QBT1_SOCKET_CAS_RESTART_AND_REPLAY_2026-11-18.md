# CP-0769 — QAR2/QBT1 Socket CAS, QAP1 Adapter and Durable Restart Qualification
**Date:** 2026-11-18
**Project:** QRun / QFP6 / QZXB
**Branch:** `feat/cp0704-dual-attestation-rotation-gate-20261116`
**Worktree:** `D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116`
**Observed HEAD before/after:** `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`

## Disposition

**QAR2/QBT1 TCP LOOPBACK → QAP1 ADAPTER READ/CAS → LOCAL DURABLE REOPEN AND STALE-CAS REPLAY QUALIFIED / TARGETED REGRESSIONS PASS / NO LIVE AWS OR INDEPENDENT-WITNESS QUALIFICATION / GATE 8 OPEN**

CP-0769 closes a local network-integration gap left by CP-0767. It does not close the external trust, cloud deployment, whole-host rollback, or public launch requirements.

## 1. Change made

Updated only the test section of:
`src/native/pow_bench/src/external_cas_offhost_anchor_noise_daemon_candidate.rs`

Added:
`qbt1_q2_socket_read_cas_read_and_durable_restart_through_qap1_adapter`

The test exercises the actual QAR2 TCP/Noise handler through the bounded daemon, not a direct in-memory call to the QAR2 service facade. It constructs `QAR2Qap1AnchorTransport`, the same adapter contract used by QFP6 runtime, and sends Read/CAS operations through that adapter.

### End-to-end sequence in the test

1. Load the deterministic, test-only `VerifiedBootstrapTrust` fixture and its exact Provider/Anchor pins. The ML-DSA keys are synthetic fixture material (provider seed `0x11`, Anchor seed `0x22`); no real operator/custodian keys are used.
2. Provision a test-local `ExternalCasOffhostAnchorFileStore` at the exact generation-zero QBT1 initial state and compose it with the QAR2-bound service using the `cfg(test)`-only model factory.
3. Bind the explicit `OffhostAnchorNoiseDaemon::bind_qbt1` listener on loopback with two bounded workers and a pinned Noise client.
4. Attempt a QAR1 client request against that same QAR2 listener. The legacy request fails; the server does not negotiate down or return a QAR1 response.
5. Use `QAR2Qap1AnchorTransport` over the live TCP listener to read the initial state. The adapter verifies the QAR2/QBT1 outer receipt before returning the inner QAR1-shaped receipt to the caller.
6. Construct and sign a valid generation-one ECR1 Provider commit and ECS1 Provider receipt. Send the QAP1-shaped CAS through the adapter. The server returns an applied receipt; verification confirms the exact successor Anchor state.
7. Replay a request using the old predecessor sequence/state digest. The server returns `Conflict`; the accepted successor state remains unchanged. A subsequent Read returns that same successor.
8. Request daemon shutdown and join its worker pool. Drop the service/store handles, reopen the durable local file store, create a fresh QAR2-bound service with new Noise server/client keys and bind a new listener.
9. Read the persisted successor over a new Noise connection. Replay the same stale CAS again after reopening; it still returns `Conflict` and the successor state remains unchanged. Shutdown/join verifies zero active workers.

This demonstrates the full local transport/adapter/storage boundary for the tested state transition. It is not a live QFP6 mining/consensus process and is not an independent external witness.

## 2. Exact daemon request accounting

First daemon run:

| Counter | Observed |
|---|---:|
| Accepted connections | 5 |
| Completed requests | 4 |
| Failed requests | 1 |
| Active worker threads after join | 0 |

The one failed connection is the rejected legacy QAR1 downgrade probe. The four completed QAR2 operations are initial Read, successful CAS, stale-CAS Conflict, and post-CAS Read.

After closing and reopening the local durable store and binding a fresh daemon:

| Counter | Observed |
|---|---:|
| Accepted connections | 2 |
| Completed requests | 2 |
| Failed requests | 0 |
| Active worker threads after join | 0 |

The two restarted-daemon operations are the successor Read and stale-CAS replay Conflict.

## 3. Verification on heymed

The following targeted commands passed:

| Test/build | Result |
|---|---:|
| `cargo test --lib external_cas_offhost_anchor_noise_daemon_candidate::tests` | 21 passed, 0 failed |
| `cargo test --lib external_cas_offhost_anchor_noise_v2_candidate::tests` | 5 passed, 0 failed |
| `cargo test --lib external_cas_bootstrap_trust_bundle_candidate::tests` | 4 passed, 0 failed |
| `cargo test --bin qrun_v06_node qrun_v06_node_runtime_launch::tests` | 6 passed, 0 failed |
| Focused QAR2/QBT1 socket + CAS + durable-reopen + stale replay test | 1 passed, 0 failed |
| `cargo check --bins` | PASS, exit code 0 |
| `cargo fmt --all -- --check` | PASS |
| `git diff --check` | PASS |

The daemon panic messages printed during the test suite are expected fault-injection tests (`injected signer panic`); those tests pass by verifying the daemon fails closed and joins its workers. Existing unused/dead-code warnings remain in legacy modules and are not new failures.

This is targeted module/runtime verification, not the full 1,591-test crate suite. The focused one-test run, the final full 21-test daemon run, and the bins check completed successfully.

## 4. Source SHA-256

Hashes computed after formatting and the final passing test/build runs:

| File | SHA-256 |
|---|---|
| `external_cas_offhost_anchor_noise_daemon_candidate.rs` | `3A03F1A94E24F08310101D7F1AB56BB7FAB968BB79168732E3ADD56C0B48997C` |
| `external_cas_offhost_anchor_noise_v2_candidate.rs` | `8D03D3B4AEBB1A6BE8533D6DAFE7F0B2E41286F8968B882F8B52FAF242629A7B` |
| `external_cas_bootstrap_trust_bundle_candidate.rs` | `10A71A24C20C64F6668AEF31F1EC1D347269E9794FBB13866903D34E47D0B836` |
| `bin/qrun_v06_node.rs` | `F7B61F60BE9B9FA4E895E55841AED6017B6B0CF814C40285C421B82898F5C9E7` |
| `bin/qrun_v06_node_runtime_launch/mod.rs` | `C7EA64C4719F6C65D240EFEBEFA6B5A1E6E87EF217D919A97BDB7E0981B6B788` |
| `lib.rs` | `C9265959F516AE98E8BA095DF3CDF66AD684C0D90EB6816CD751E39D2C82B69C` |

## 5. Explicit limits — what this does not prove

- The test uses deterministic synthetic owner/custodian/Provider/Anchor keys supplied by unit-test fixtures. It does not prove a real independently administered owner and custodian ceremony or key provenance.
- The test constructs the QAR2 service through a `cfg(test)`-only local-model factory backed by the local file store. It does not run `QAR2BoundAnchorService::with_qualified_aws_dynamodb` against AWS.
- The daemon is spawned, joined, and rebound inside the test process. The durable store is closed and reopened, and new Noise identities are used. This is not a separate OS-process crash/power-loss test, a second physical host, or a whole-host snapshot rollback test.
- The stale-CAS replay check proves rejection against the reopened local file state. It does not prevent an attacker from restoring the entire local file store to an older snapshot. A separately administered, monotonic external witness is still required to defeat that attack.
- The test invokes the `QAR2Qap1AnchorTransport` trait methods directly. It does not launch the complete `qrun_v06_node` private runtime, instantiate the production `QRunV06Qap1ExternalCoordinator` with a real Provider endpoint, or run consensus block import/mining through a live external Anchor.
- QBTB1 codec tests and Q6PN/QBT1 runtime selector tests pass, but no real QBTB1 production bundle was enrolled or passed to an operator-launched node.
- No AWS account, credentials, KMS key, DynamoDB table, IAM role, public endpoint, or cloud resource was accessed or modified. No live off-host service or independent witness was used.
- No independent external security review, multi-operator testnet qualification, or legal/economic launch qualification was performed.

**Gate 8 remains OPEN. Public/Mainnet release remains NO-GO.** Local TCP, test fixture signatures, and a reopened local file do not constitute independent anti-rollback custody.

## 6. Next required boundary

The next meaningful Gate 8 qualification is not another in-memory success test. It requires an operator-provisioned QBTB1 trust bundle whose digest and custodian pins arrive out of band, a separately administered QAR2 Anchor service using the qualified cloud adapter, authenticated session-bound AWS deployment evidence, and a rollback attempt that restores the whole node host while the external monotonic witness remains advanced. That must be followed by independent restart/recovery and security review.

## 7. Git preservation

- Branch remains `feat/cp0704-dual-attestation-rotation-gate-20261116`.
- HEAD remains `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`.
- No files were staged; no commit, push, merge, reset, clean, stash or checkout was performed.
- All pre-existing modified and untracked CP-0703..CP-0768 work was preserved.
- This is an untracked engineering checkpoint, not a release tag or Gate 8 closure.
