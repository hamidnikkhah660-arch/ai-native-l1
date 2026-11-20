# CP-0632 — Public Testnet Entry Gate and QFP6 Listener Admission Hardening

Date: 2026-11-13  
Project: QuantumZXB / QRun native L1 (QFP6)  
Status: **LOCAL CANDIDATE WORK — NOT A PUBLIC TESTNET RELEASE**  
Base commit: `df673d07050688a64b26822d97e6ea609b68ce88`  
Branch: `feat/cp0600-bootstrap-sync-startup`

## 1. Scope and source-of-truth reconciliation

The active worktree was verified at:

`D:\Temp\ASUS\QRUN_QFP6_CP0596_20261111`

The branch HEAD matches the local QFP6 handoff base at `df673d0`. The old C: worktree is not the continuation target. The active worktree already contained uncommitted CP-0631 changes in `qrun_v06_peer_address_manager_candidate.rs` and a Sybil-handshake reproduction test in `qrun_v06_peer_listener_candidate.rs`. The address-manager WIP was left untouched in this work session.

The pre-existing listener flood test reproduced the vulnerable behavior: enough invalid Noise handshakes could terminate a listener round. This was a demonstrated defect, not a successful mitigation.

## 2. Local admission-hardening implementation

The following changes are present locally but have **not** been committed or pushed:

- Added source-prefix admission buckets: IPv4 /24, IPv6 /56, with IPv4-mapped IPv6 normalized into the matching IPv4 prefix.
- Prefix state is capped at 4,096 entries and idle entries expire after 600 seconds.
- Per-prefix buckets use the configured `max_failed_handshakes` value as their initial burst and refill one token every two seconds.
- A shared global bucket starts with a burst of 64 and refills one token every 250 milliseconds.
- A TCP connection denied by either bucket is closed before the Noise handshake and counted in the new `rate_limited_connections` statistic.
- Invalid/failed handshakes no longer exhaust the listener's successful-session budget. `max_sessions` now counts established Noise sessions, not raw accepted TCP sockets.
- Supervisor-owned limiter state is carried across listener rounds rather than recreated every round, so a caller cannot reset source/global budgets merely by waiting for the next service round.
- The former flood reproduction test now asserts that two invalid handshakes are counted, a further connection from the same source prefix is throttled, and the listener remains alive until explicit shutdown.

### Important remaining limitation

The listener still processes one active peer at a time. A peer that starts a handshake can hold that serial path until the existing Noise handshake deadline (currently eight seconds). Rate limiting does not by itself solve serial head-of-line blocking or a distributed multi-source flood. A bounded handshake worker/queue design, explicit connection-stage deadlines, capacity accounting, and external adversarial testing remain required before public binding.

Prefix throttling also creates a deliberate NAT fairness trade-off: distinct users sharing one /24 or /56 share the same pre-authentication burst. The values are candidate defaults, not public-network-calibrated parameters.

## 3. Validation evidence

Observed on the active Windows worktree:

| Check | Observed result |
|---|---|
| `cargo test --lib source_rate_limiter` | PASS, 2/2 |
| QFP6 listener test family (`qfp6_listener_`) | PASS, 9/9 |
| Permissionless supervisor durable Genesis test, isolated rerun | PASS, 1/1 |
| External-CAS simultaneous writer test, isolated rerun | PASS, 1/1 |
| `cargo check --all-targets --locked --offline` | PASS, exit code 0 |
| `cargo fmt -- --check` for the pow_bench manifest | PASS |
| `git diff --check` | PASS |
| Full library run | 1,400 passed, 2 failed under parallel execution; both failed tests passed when rerun individually |

The two failures in the parallel full-library run were:
1. `cp0604_permissionless_supervisor_mines_and_recovers_durable_genesis_state`, which passed in isolation. It has a short 180 ms shutdown fixture and did not mine before shutdown under the full suite's concurrent load.
2. `simultaneous_writers_have_exactly_one_atomic_cas_winner`, which hit a Windows file-lock `WouldBlock` error under the parallel suite and passed in isolation.

These individual reruns are diagnostic evidence, **not** a clean full-suite pass. Existing unrelated compiler warnings remain. No security audit or external network test is implied.

## 4. Current worktree state

Expected modified tracked files:

- `src/native/pow_bench/src/qrun_v06_peer_listener_candidate.rs` — listener limiter, shared-limiter entry points, statistics, and regression tests.
- `src/native/pow_bench/src/qrun_v06_node_supervisor_candidate.rs` — persistent limiter ownership and established-session accounting.
- `src/native/pow_bench/src/qrun_v06_peer_address_manager_candidate.rs` — pre-existing CP-0631 local WIP; not changed in this work session.

No commit, push, merge, release artifact, firewall change, port-forward, public listener launch, or live-node restart was performed. No QRun/QFP6 node process was started.

## 5. Public Testnet launch gate — current blocker

The current QFP6 command-line binary `qrun_v06_node` is explicitly **preflight-only**. Its source states that it does not open a QFP6 data directory, mutate the QFP6 store or trust floor, bind a P2P listener, or start consensus/mining.

The QFP6 supervisor and permissionless runtime are library candidate components, not yet a complete standalone public-node launcher. The peer-book utility only lists/approves/revokes local peer pins; approval does not dial a peer. The older `qzbe_v04_peer_node` binary is a separate QZBE v0.4 line with its own test-easy-PoW flags and AMM/transaction-ingress modes. It is not a substitute for a QRun QFP6 public-testnet node.

Therefore **do not expose a port or label the network public yet**. The following implementation/evidence gates remain open:

1. **QFP6 node launcher:** a reviewed, explicit zero-value Public Testnet binary/config path must validate an exact Genesis descriptor, consensus profile, network ID, data directory, Noise identity and bootstrap configuration before starting the QFP6 runtime/Supervisor. It must not silently select legacy QZBE/QRun v0.5 code or Mainnet values.
2. **Network identity and Genesis freeze:** select and publish a dedicated Public Testnet Network ID, Genesis commitment, profile fingerprint, consensus parameters and explicit zero-value/test-only economic policy. Candidate/test fixture IDs must not be promoted by assumption.
3. **Inbound authentication and DoS:** finish bounded handshake concurrency/deadlines; define how anonymous inbound Noise XX sessions are authenticated or safely treated as untrusted; preserve no-auto-trust for Gossip/Q6AR; test multi-prefix floods, slow handshakes, resource budgets, shutdown and NAT fairness.
4. **Independent bootstrap operators:** obtain at least one independently controlled seed host for initial multi-host integration and preferably multiple independent operators/providers for a sustained public test network. Verify endpoint, Network/Genesis/profile hashes and Noise key fingerprints out-of-band; store explicit pins.
5. **History, fork and restart qualification:** exercise clean Genesis sync, long catch-up, interrupted sync, competing forks, reorg, checkpoint/restart, peer loss and state-root convergence across separate hosts. Distinguish permissionless full-history replay from any optional anchored/QAP1 mode.
6. **Public operations:** define a bounded public P2P port only after the preceding gates pass; keep RPC and transaction-management endpoints private or behind a separately hardened gateway. Add health/metrics, logs, seed rotation, incident/reorg procedures, reproducible builds and a public read-only explorer/indexer.
7. **Independent release review:** review the exact release commit and binaries, fix critical/high findings, and publish limitations and operator instructions. A passing local test suite is not an external audit.

The prior CP-0465 decision remains authoritative for **value-bearing Mainnet and QZXB/USDT trading: NO-GO**. A zero-value Public Testnet is a separate milestone and must not be described as a Mainnet, exchange listing, liquidity pool, investment offer, or real-value QZXB market. Public token offers or regulated services require their own qualified legal/compliance review; technical testnet status does not close that gate.

## 6. Next engineering sequence

1. Complete and review the QFP6 listener admission patch; add bounded handshake concurrency/deadline protections and tests.
2. Design and implement the dedicated QFP6 zero-value Public Testnet launcher with a manifest-driven, fail-closed startup path.
3. Run the focused and full validation suite, then independent two-/multi-host integration with verified pins and state-root convergence.
4. Only after these results are recorded, prepare a separate public-testnet deployment packet and approve a narrowly scoped inbound P2P exposure.

**Decision at CP-0632:** listener admission hardening is implemented locally and focused checks pass, but the QFP6 Public Testnet launcher and several security/operations gates are still missing. No public-network activation is authorized by this checkpoint.
