# CP-0501 — QRun v0.5 Authority durable sequence leases

Date: 2026-11-02

Status: **Implemented and validated on Windows.** The Authority now reserves a bounded sequence range durably before it starts serving, then issues unique sequence values from the in-memory lease. The Authority keeps its two-second per-connection request/response deadline; no timeout was widened to mask storage latency.

## Why this checkpoint exists

The CP-0499 Authority initially performed a durable RTS1 state-file replacement for every signed time response. Under eight concurrent loopback clients, the per-response file sync serialized behind the store mutex and caused otherwise valid exchanges to exceed the signed RTP1 maximum RTT. The full Rust run exposed this under load as `StaleResponse`; the test was reproduced outside the all-targets run, so it was treated as a real operational issue rather than dismissed as test noise.

The correction is to amortize durable storage across a bounded sequence lease instead of weakening the time-freshness policy.

## Sequence lease design

The Authority uses a lease size of **64** values.

When `ReferenceTimeAuthorityService` is constructed:

1. The RTS1 store durably advances its authority sequence high-water by 64 using the existing atomic replacement, flush/sync and process-exclusive writer lock.
2. Only after the reservation commits does the service become ready.
3. Each valid request claims one value from the shared in-memory lease under a mutex. No per-response disk sync is required.
4. The service signs the selected value into the challenge-bound TMA1 response.
5. When the lease is exhausted, the service durably reserves the next 64-value range before issuing from it.

On process crash or restart, any unused suffix of the previous lease is intentionally skipped. The next process starts strictly above the durable reserved high-water. This can create gaps (up to 63 values for a mostly unused 64-value lease), but it cannot reuse a previously reserved value. The client protocol already requires strictly increasing sequence values, not contiguous values, so gaps remain valid.

Example demonstrated by the smoke test:
- first process serves node 1 with sequence **1**;
- first process serves independent node 2 with sequence **2**;
- first process has already reserved through **64**;
- after restart, the next process reserves **65–128**;
- next authenticated probe accepts sequence **65**.

The RTS1 state file remains single-writer/process-exclusive per Authority. This does not enable two active Authority processes sharing one sequence file, and it does not provide distributed consensus.

## Source changes

- `reference_time_store.rs`: `reserve_authority_sequence_range(count)` atomically advances and persists the inclusive range high-water, rejects zero/overflowing reservations, and is covered by a reopen/non-overlap test.
- `reference_time_authority.rs`: `AuthoritySequenceAllocator` reserves 64 values during service construction and serializes concurrent in-memory claims. Private signing material remains redacted from `Debug`. Its telemetry distinguishes the last sequence issued by the current process from the durable reserved high-water; a restarted process begins with current-process issued sequence 0 and reports the inherited reserved range separately.
- `qrun_v05_reference_time_authority.rs`: readiness output exposes `last_issued_sequence_in_process` and `reserved_sequence_high_water` as separate fields; it does not mislabel unused reserved values as delivered responses.
- `reference_time_tcp.rs`: test-only signed policy RTT is set to the protocol maximum of 5 seconds; child-process accept/read/write allowances are extended to tolerate Windows test-runner startup under load. Production Authority I/O remains 2 seconds and public RTP1 maximum remains 5 seconds.
- `qrun-v05-reference-time-authority-smoke.ps1`: waits for the Authority's post-bind readiness marker instead of opening a dummy TCP connection that would occupy a handler waiting for an invalid request; after restart it verifies sequence 65 and reports the reserved range 65–128.

## Observed validation on Windows

Run with:
```powershell
$env:TEMP='E:\QRUN_TEST_TMP'
$env:TMP='E:\QRUN_TEST_TMP'
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\qrun-v05-reference-time-authority-smoke.ps1
```

Observed result:
```
non_loopback_bind_guard=PASS
node1-probe1 accepted_authority_sequence=1
node2-independent-probe accepted_authority_sequence=2
probe3-after-restart accepted_authority_sequence=65
policy_admin_role_separation=PASS
AUTHORITY_MULTI_PROCESS_SMOKE=PASS
sequence_progression=1,2,65
restart_reserved_range=65-128
```

Targeted Rust validation after the lease implementation:
- `reference_time_store::tests`: **3/3 PASS**, including durable non-overlapping range reservation, restart behavior and zero-count rejection.
- `reference_time_authority::tests`: **3/3 PASS**, including eight concurrent TCP clients with unique monotonic sequences, invalid-network/malformed-request rejection, signed challenge response and lease renewal across service recreation.
- `reference_time_tcp::tests::signed_tcp_replies_persist_across_process_restart_and_authority_rotation`: **1/1 PASS**, with a separate child process and five-second signed policy RTT.
- CP-0499 Authority Windows smoke: **PASS**, with sequence progression 1,2,65.

A first broad `cargo test --all-targets` run with six test threads, while the host was also copying another large project, reported 1047 passed and 3 process/CAS timing failures. All three failed cases then passed individually. A full library run with two test threads subsequently completed **1050/1050 PASS, 0 failed**, including those three cases and all new Authority lease tests. This is the complete library unit/integration harness; it is not evidence of a physical multi-host network.

Additional validation after CP-0501:
- QRun local node binary: `cargo test --bin qrun_v05_pow_local_node`: **33/33 PASS**. This includes Public Alpha startup configuration, authenticated reference-time requirements, Public Alpha two-node P2P convergence, signed-time profile mismatch Noise rejection and transaction ingress.
- Authority binary test target: compiled/executed successfully (0 inline tests; the CLI is covered by the Windows operational smoke).
- Noise key provisioner binary test target: compiled/executed successfully (0 inline tests; end-to-end key provisioning and overwrite rejection are covered by CP-0500 smoke).
- `cargo check --all-targets --locked --offline`: **PASS**.
- `cargo fmt --all -- --check`: **PASS**.
- `git diff --check`: **PASS** (Git reports normal working-copy LF-to-CRLF notices only).

The six-thread failures therefore did not reproduce in the complete two-thread library run; the implementation remains fail-closed and no security deadline or timestamp tolerance was relaxed to make the tests pass.

## Security and release boundary

- Durable range reservation is monotonic. Crashes may waste sequence values but cannot roll the persisted high-water backwards.
- A single active Authority process must own the RTS1 store. The existing writer lock enforces this locally.
- This Authority still signs its own host OS clock. It is one trusted time attester, not BFT time consensus, not a quorum clock and not a substitute for host clock monitoring.
- The service has not yet been tested between physical machines or independently operated hosts.
- `QRUN_MAINNET_RELEASE_APPROVED = false` remains unchanged.
- No Mainnet Genesis epoch, wallet identity manifest, Network ID, Profile ID, ECR1/QCF1/QRCP pin or public release decision is changed by this checkpoint.
- No claim is made about public trading, external adoption, exchange listing or liquidity.

**Decision:** keep the two-second Authority connection deadline and fail-closed public-node behavior. The range-lease implementation is an operational hardening step; the next qualification remains multi-host remote Noise/P2P, Authority clock monitoring, partition/restart/reorg scenarios and independent security review.
