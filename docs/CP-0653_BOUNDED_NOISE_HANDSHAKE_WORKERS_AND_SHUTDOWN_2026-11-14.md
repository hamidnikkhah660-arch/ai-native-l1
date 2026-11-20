# CP-0653 — Bounded QFP6 Noise Handshake Workers and Prompt Shutdown

Date: 2026-11-14  
Project: AI-NATIVE L1 / QRUN-QFP6  
Branch: `feat/cp0600-bootstrap-sync-startup`  
Observed base HEAD: `df673d07050688a64b26822d97e6ea609b68ce88`  
Status: **implemented in local candidate worktree; focused offline tests passed; public listener remains unqualified**

## 1. Objective

Remove the synchronous Noise XX handshake from the single-threaded TCP accept path without parallelizing canonical runtime/state access. A slow or incomplete unauthenticated handshake must not occupy the listener's only application-processing thread while other bounded handshake workers are available.

## 2. Implementation

### Fixed worker and queue limits

The QFP6 listener now has:

- Exactly **4 fixed Noise handshake workers** per listener service round.
- A bounded input queue of **8 accepted sockets** waiting for handshake.
- A bounded completion queue of **4 results**.
- Queue overflow is fail-closed: the newly accepted socket is dropped; no unbounded thread creation or queue growth occurs.
- Separate `handshake_queue_rejections` and `cancelled_handshakes` counters are aggregated through the supervisor statistics path.
- Source-prefix and global pre-authentication token buckets remain in the accept thread and still run before a socket is enqueued.

The worker pool uses a bounded channel and a shared receiver lock only while dequeueing. Each worker releases the receiver lock before doing handshake I/O.

### Strict separation of concurrent and serialized work

Workers only perform the Noise XX handshake, peer static-key pin evaluation, and return the resulting stream/session to the listener thread.

The following operations remain on the listener thread, preserving the existing single-writer/canonical-state safety model:

- Q6TI/Q6TA transaction admission and mempool callbacks.
- Q6HI/Q6HR/Q6HS/Q6HC history and status request handling.
- Q6AR callback/persistence and operator trust-domain policy enforcement.
- Any callback that can access the canonical runtime, durable store, mempool or fork-choice state.

Only one established application session is processed at a time. CP-0653 does **not** claim parallel application-state processing.

### Deadlines and cancellation

- The existing absolute Noise handshake deadline remains **8 seconds**.
- Handshake read/write polling continues to use bounded 100 ms I/O slices.
- New shutdown-aware pinned and anonymous handshake entry points check cancellation between I/O slices.
- Listener shutdown/round termination cancels workers, closes the job sender, discards queued sockets, and joins every worker before returning.
- Each worker's copy of the local Noise static private key is wrapped in `zeroize::Zeroizing` and cleared when that worker exits.

### Existing admission controls retained

- Global and /24 IPv4, /56 IPv6 source-prefix rate limiting remains before worker-queue admission.
- IPv4-mapped IPv6 prefix normalization remains unchanged.
- Pinned outbound/relay trust rules, no-auto-trust for Q6AR advertisements, per-trust-domain quotas and bootstrap snapshot agreement are unchanged.
- Listener response validation, replay guards, per-session request limits, history egress budget and canonical callback serialization remain unchanged.

## 3. Focused verification

All tests below used the locked offline Cargo dependency set and the QFP6 pow_bench manifest.

| Test/filter | Observed result |
|---|---:|
| `bounded_handshake_workers_allow_valid_peers_while_one_peer_stalls` | PASS — 1/1 |
| `bounded_handshake_worker_queue_rejects_connections_above_fixed_capacity` | PASS — 1/1 |
| `qfp6_noise_incomplete_handshake_cancels_promptly_on_shutdown` | PASS — 1/1; cancellation observed in 0.12 s |
| `qfp6_listener_` | PASS — 9/9 |
| `supervisor_q6ar_` | PASS — 4/4 |
| `cp0604_permissionless_supervisor_mines_and_recovers_durable_genesis_state` | PASS — 1/1 |
| `pinned_noise_sync_imports_a_heavier_competing_branch_and_recovers_after_restart` | PASS — 1/1 |
| `two_independent_noise_sources_with_divergent_histories_fail_bootstrap_agreement` | PASS — 1/1 |
| `two_independent_noise_sources_with_same_history_pass_bootstrap_agreement` | PASS — 1/1 on isolated rerun |

The paired two-source bootstrap filter initially ran both loopback integration tests in parallel and the same-history case hit a Windows durable-store writer-lock collision. The same-history test passed when rerun alone; the divergent-history test passed in the paired run. This is recorded as a test-fixture concurrency collision, not silently counted as a paired green result.

Final candidate-tree validation after the worker-pool, manifest and checkpoint changes:

- `cargo check --manifest-path src/native/pow_bench/Cargo.toml --bins --locked --offline` — **PASS**, exit code 0.
- `cargo fmt --manifest-path src/native/pow_bench/Cargo.toml -- --check` — **PASS**.
- `git diff --check` — **PASS**.
- `cargo test --manifest-path src/native/pow_bench/Cargo.toml --bin qrun_v06_node --locked --offline` — **PASS, 36 passed, 0 failed**. This includes the CP-0651-only permissionless Genesis gate, public-testnet topology/acknowledgement gates, Q6AR registry gates and full Genesis preflight regressions.
- Supervisor statistics aggregation regression for the new queue rejection/cancellation counters — **PASS, 1/1**.

The build continues to report pre-existing unused-import/dead-code warnings in unrelated legacy candidate modules; no warning was promoted to an error.

## 4. Known limits that remain

1. **Application session handling remains serial.** A peer that has completed Noise can occupy the single canonical application-processing path while it waits for requests/records, up to the existing per-record timeout and per-session limits. CP-0653 removes handshake serialization but does not yet implement parallel application-session scheduling.
2. **Anonymous inbound identity remains unresolved.** Public inbound Noise XX still uses X25519 and an anonymous static key; transport encryption/domain separation is not proof of the remote operator's identity. An active MITM can terminate/re-encrypt the session. This transport is classical, not post-quantum.
3. **External adversarial qualification remains required.** The new tests use local loopback sockets and controlled test clients. They are not multi-prefix Internet flood, slowloris, NAT fairness, kernel backlog, memory/CPU saturation, or physical multi-host public-listener qualification.
4. **Public peer discovery remains unimplemented/unqualified.** Outbound bootstrap sync still requires independently pinned peers.
5. **Release artifacts and independent reviews remain missing/pending.** Genesis/Q6GD/Q6CP/Q6PN/bootstrap artifacts, protected operator key provisioning, separate-host release checks, independent consensus/cryptography/economics reviews and operator runbooks remain open.

The release manifest deliberately retains:
- `public_listener_qualified=false`
- `full_history_replay_qualified=false`
- `inbound_peer_identity_authenticated=false`
- `public_peer_discovery_qualified=false`
- `public_mining_authorized=false`
- `production_authorized=false`

## 5. Operational boundary

- No QRun/QFP6 node was launched.
- No public listener was bound.
- No TCP port 30333 was opened.
- No firewall/router/port-forward change was made.
- No deployment or public Testnet launch occurred.
- No commit, push, merge, tag or release was created.
- Existing uncommitted CP-0632 through CP-0652 work and the CP-0651 economics policy were preserved.

## 6. Current decision

The **serial handshake bottleneck is mitigated in candidate code** by four fixed workers, an eight-job bounded queue, a four-result completion queue, cancellation-aware deadlines, and joined shutdown. It is not a public-listener qualification or a broad DoS-resistance proof. The next gates are application-session resource scheduling, authenticated peer identity/PQ transport plan, externally provisioned independent seed hosts and signed network artifacts, multi-host qualification, and independent review.

**Public Testnet remains NO-GO at CP-0653.** The CP-0651 7B / 1B owner / six accounting labels / zero subsidy / fee-only producer economics remain the active candidate policy.
