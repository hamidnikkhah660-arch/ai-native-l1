# CP-0566 — QFP6/QAP1 Cross-Host Qualification Design
Date: 2026-11-05
Status: **CP-0566A local Noise/TCP integration regression PASS; dedicated QFP6/QAP1 process host and cross-host workflow remain open. No workflow dispatched.**

## Objective

Prove that a QFP6 peer block can traverse a real two-host private overlay, be admitted by the QFP6 runtime, and receive a positive Q6PA acknowledgement only after the remote QAP1 Provider and Q6EA Anchor have durably advanced and verified the same successor state.

This is a test qualification, not Mainnet activation, not public peer reachability, and not independent-operator certification.

## Current verified building blocks

- `QRunV06NodeRuntime::recover_qap1_after_process_restart` provides the QAP1-aware runtime recovery constructor.
- `process_qfp6_peer_frame_with_qap1` connects a Q6PB peer request to QFP6 admission and QAP1 commit/reconciliation.
- `serve_qfp6_noise_listener` provides a bounded, serial Noise XX listener. It rejects wildcard/public bind addresses, requires explicit peer pins, and supports finite session/request budgets and cooperative shutdown.
- QAP1 has separate pinned Provider and Q6EA Noise/TCP client transports.
- Durable Provider and Q6EA file-store adapters exist for development qualification.
- CP-0563/0564/0565 already cover local durable service restart, two-process Q6EA CAS competition, AMM test-swap admission, replay rejection and exact state equality after service/runtime restart.

## Critical gap

The current QFP6 components are library candidates. There is no dedicated QFP6/QAP1 node executable that owns the complete lifecycle:

1. open the QFP6 durable fork store from an independently supplied Genesis/anchor profile;
2. open and verify the QAP1 Provider and Q6EA endpoints and monotonic floor;
3. recover QAP1 before exposing the runtime;
4. bind the peer listener only to an approved private/NetBird interface;
5. route authenticated Q6PB frames through `process_qfp6_peer_frame_with_qap1`;
6. translate only an `Acknowledged` admission into positive Q6PA;
7. stop the listener and external service clients cleanly, preserving durable state.

Do not disguise a same-process unit test or a successful TCP probe as this qualification.

## CP-0566A local Noise/TCP integration result

The existing QFP6 AMM/QAP1 restart regression was strengthened to exercise the real bounded QFP6 Noise listener over a loopback TCP socket:

- A separate Noise XX peer keypair and listener keypair are generated for the test session.
- The test starts `serve_qfp6_noise_listener` with a one-session/two-request budget and an explicit peer pin.
- A Q6PB frame is sent through `QRunV06NoiseSession`; the listener callback calls `process_qfp6_peer_frame_with_qap1`.
- The first response is Q6PA Accepted only after the QFP6/QAP1 path commits. Replaying the identical request on the same authenticated session returns Q6PA Rejected.
- Listener counters are asserted: one authenticated session, two requests, two responses and one closed session.
- Existing assertions still verify the QZXB/QUSDT-TST AMM state, durable Provider/Q6EA service restart, QFP6 store reopen, QAP1 recovery, and exact post-restart state/balance equality.

Verification:
- `cargo fmt --manifest-path src/native/pow_bench/Cargo.toml` — passed.
- `cargo test --manifest-path src/native/pow_bench/Cargo.toml qap1_peer_ingress_executes_qzxb_qusdt_amm_swap_and_restarts -- --nocapture` — 1 passed, 0 failed; the overall filtered Cargo command exited 0 after visiting the remaining targets.
- This is a same-host loopback integration test. It does **not** prove cross-host communication, independent operator domains, or production readiness.
- No commit, push, workflow dispatch, cloud resource, public listener or Mainnet action was performed.

## Proposed zero-cost topology

**Node A — owner's Windows laptop**
- Acts as the peer test driver and hosts the temporary durable Provider and Q6EA test services.
- Provider and Q6EA use distinct data roots, signing identities, Noise identities and explicit pins.
- The test peer driver submits a bounded, zero-value QFP6 fixture over the NetBird overlay.
- Provider and Q6EA are separate processes but remain on the same physical host and administrative domain.

**Node B — one-off GitHub-hosted Windows runner**
- Runs the dedicated QFP6/QAP1 candidate node process.
- Uses a fresh local QFP6 store and an independently supplied expected anchor state.
- Reaches Provider and Q6EA on Node A over separately pinned Noise/TCP transports.
- Accepts the Node A peer only on its NetBird address and an explicitly scoped port.
- Is destroyed after the manually dispatched qualification.

This topology proves cross-host transport and runtime admission, but **does not** prove independent Provider/Q6EA administration or anti-rollback protection against whole-host restoration. Those remain later production gates.

## Required implementation units

### CP-0566A — hostable candidate node
Create a dedicated, explicitly test-profiled executable or equivalent supervised integration target. It must compose the existing QFP6 runtime, QAP1 coordinator and bounded Noise listener without introducing a second consensus or admission implementation.

Configuration must be validated fail-closed. Private keys must not be printed, logged, passed on command lines, or committed. No automatic bootstrap may be inferred from a local manifest. The runtime must not start listening if QAP1 recovery or pin verification fails.

### CP-0566B — peer driver and service host
Provide a laptop-side, bounded test driver and service-host lifecycle. It must generate/use only deterministic zero-value test fixtures, never a production wallet or real quote asset. Provider and Q6EA must have separate keys and stores and must expose only their required private-overlay endpoints.

### CP-0566C — cross-host workflow
Add a separate manual-only GitHub Actions workflow for the QFP6/QAP1 qualification. Do not repurpose or rerun the QRun v0.5 workflow as evidence for QFP6. Pin checkout to the dispatched SHA, use a short-lived one-off NetBird Setup Key stored only as a GitHub secret, and keep public configuration limited to non-secret pins/profile metadata.

No push, dispatch, router change, public listener, cloud resource purchase or Mainnet action is authorized by this design note.

## Mandatory pass criteria

1. NetBird path is established between the laptop and ephemeral runner; no public router port is opened.
2. QFP6 listener binds only to the explicitly approved private/overlay address; RPC and transaction-ingress interfaces are not exposed.
3. Wrong peer Noise key, Provider pin, Q6EA pin, network ID, profile ID or Genesis/anchor state fails closed.
4. Node B receives a valid Q6PB fixture from Node A over the overlay and validates the QFP6 envelope and block.
5. QAP1 obtains and verifies the signed Provider and Q6EA observations and commits the exact successor; positive Q6PA is returned only after finalization.
6. Replayed request does not receive a positive ACK and does not advance the manifest or external generation a second time.
7. Node B and both external services are stopped and reopened; the exact canonical height, tip, state root, manifest generation and QAP1 anchor state are reproduced.
8. Temporary runner files, processes, NetBird peer and firewall rules are cleaned up even on failure; only non-secret evidence is retained.

A separate follow-on qualification must run two QFP6 nodes through an actual partition, competing branches, reconnect, cumulative-work selection, restart and durable reorg. The CP-0512 Stage C2 evidence is QRun v0.5 evidence and is not a substitute.

## Test-only boundaries

- Any quote asset remains `QUSDT-TST` (or another explicitly test-labelled zero-value asset), with no USD/Tether representation, backing, redemption or monetary value.
- A deterministic test authenticator and test Q6QA/Q6PN authorization fixture are not production wallet verification or independent governance.
- A local file-backed Q6EA store is not an independent production anchor and cannot prevent rollback of the entire laptop/backup domain.
- ML-DSA receipt verification in this candidate path does not by itself establish deployment certification, key custody or independent operator governance.

## Production release remains NO-GO

QFP6 Mainnet, public mining, public QZXB trading, QZXB/USDT, public liquidity and cross-chain value transfer remain blocked pending a dedicated reviewed node/service, independent trust and anti-rollback domains, production wallet/key custody, independent multi-host partition/reorg tests, monitored operations, security review, legal/compliance review, and a real quote asset with a verified issuer/network/contract and backing/redemption or qualified listing. Cross-chain transfers additionally require source-chain finality verification and a reviewed lock/mint or burn/release supply invariant.

## CP-0566B Process-boundary evidence reconciliation (2026-11-05)

### Fresh local qualification results

The following targeted test commands were run on the Windows development laptop:

- `cargo test --manifest-path src/native/pow_bench/Cargo.toml qfp6_listener_ -- --nocapture`: **5 passed, 0 failed**.
- `cargo test --manifest-path src/native/pow_bench/Cargo.toml qfp6_noise_ -- --nocapture`: **8 passed, 0 failed**.

The listener suite covers rejection of wildcard/public binds, invalid budgets and trust sets, unpinned peers, replay-guard session behavior, and cooperative shutdown. The Noise suite covers two-sided static-key pinning, encrypted bounded records, prologue mismatch, untrusted initiators, and oversized-record rejection.

### Important separation between existing proofs

The existing `qfp6_noise_xx_qualifies_two_independent_processes` test does spawn distinct operating-system processes and performs a Q6PB/Q6PA exchange. However, its server child opens a fresh test store and constructs `QRunV06NodeRuntime` with `MockAnchorGate`; it does **not** instantiate the QAP1 Coordinator or connect to the durable Provider and Q6EA services.

The CP-0565 AMM/QAP1 regression exercises the actual durable Provider and Q6EA Noise/TCP transports, the QFP6 Noise listener, replay rejection, and restart-state equality. In that test, the QFP6 listener callback and Runtime are owned by the test process; the Provider and Anchor servers are test-managed threads/tasks. It is still a same-host integration.

Therefore the two results are complementary, not interchangeable. Neither currently proves that a distinct QFP6 node process performs QAP1-backed admission.

### CP-0566B required implementation

The next local milestone is a process-separated QFP6/QAP1 qualification harness:

1. Keep the durable Provider and Q6EA services on the laptop with their separate stores, Noise identities, and ML-DSA receipt pins.
2. Start a distinct QFP6 node process with an explicit test profile, independently supplied Genesis/manifest anchor, Provider and Q6EA endpoints, client Noise keys, and peer pins.
3. Require that process to build its QAP1 Coordinator from the pinned Noise/TCP transports and recover the Runtime through `recover_qap1_after_process_restart` before binding the bounded peer listener.
4. Send one deterministic zero-value Q6PB fixture to the child process. It must return positive Q6PA only after QAP1 finalization; the replay must be rejected without advancing the durable generation.
5. Stop and reopen the child node and both services, then compare canonical height, tip, state root, manifest generation, and Q6EA anchor state.

The child-process test must use isolated temporary directories and non-production fixtures. No private key may be logged or committed. The local file-backed Q6EA service remains in the laptop's administrative domain.

### Cross-host gate remains separate

Only after CP-0566B passes locally should CP-0566C run the same process contract between the laptop and a one-off Windows runner over the private NetBird overlay. That run requires a fresh, short-lived NetBird Setup Key stored privately as a GitHub secret and a reviewed, narrowly scoped ACL. The existing QRun v0.5 Stage C2 result remains v0.5 evidence only.

No workflow was dispatched, no cloud resource was created, no listener was exposed publicly, and no commit or push was made in this update.

## CP-0566B process-separated QAP1 admission result (2026-11-05)

### Implementation and verification

Added a test-only child-process worker and parent harness in `src/native/pow_bench/src/qrun_v06_node_runtime_candidate.rs`.

- Parent process provisions a durable file-backed Provider, a durable Q6EA file-backed Anchor served by its Noise daemon, and the separate monotonic Provider floor.
- Parent launches a distinct operating-system test process. The child constructs pinned Provider and Q6EA Noise/TCP transports, opens the floor, and constructs the QAP1 coordinator using the independently supplied test pins.
- Before opening its QFP6 peer listener, the child calls `recover_qap1_after_process_restart` and requires `qap1_required == true`.
- Parent establishes a separately pinned QFP6 Noise XX session and submits the deterministic Q6PB fixture twice. The first Q6PA is Accepted only after the child callback runs `process_qfp6_peer_frame_with_qap1`; the exact replay is Rejected.
- The child listener asserts one authenticated session, two requests, two responses, one closed session, canonical height 1, manifest generation 1, and no unresolved QAP1 intent.
- The child reports `QFP6_QAP1_PROCESS_SERVER=PASS`; the parent checks its exit code and report before shutting down Provider and Q6EA and removing the temporary service root.

Verification:
- `cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib qap1_peer_ingress_qualifies_separate_qfp6_process -- --nocapture`: **1 passed, 0 failed**.
- `cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib qap1_peer_ingress -- --nocapture`: **4 passed, 0 failed** (QAP1 positive-ACK finalization, QZXB test-trade admission, durable swap/restart regression, and separate QFP6/QAP1 process admission).
- `cargo fmt --manifest-path src/native/pow_bench/Cargo.toml -- --check`: passed.
- `git diff --check`: passed (Git emitted existing LF/CRLF working-copy notices only).

### Qualification limits

This is now proof that a distinct QFP6 OS process performs QAP1-backed peer admission against separate durable Provider and Q6EA services. The test services and node still run on the same physical laptop and under the same administrative account/domain. The QFP6 process test does not yet reopen the child node's own committed store in a second process; it verifies QAP1 recovery-constructor startup before admission and the QAP1 commit during the child process. Cross-process node restart continuity and the two-physical-host NetBird run remain open.

The fixture is zero-value and test-only. Its test authenticator, test trust authorization, ephemeral process environment keys, and local file-backed Q6EA do not establish production wallet custody, independent governance, or independent anti-rollback.

No commit, push, merge, workflow dispatch, cloud resource, public listener, production key, real-money transaction, or Mainnet action was performed.

## CP-0566B2 cross-process durable Node restart qualification (2026-11-05)

### Implemented lifecycle

Extended the CP-0566B harness so the QFP6 child process owns a stable test archive directory rather than an ephemeral in-process test directory.

1. First child opens the empty QFP6 test archive with the independently fixed Genesis descriptor, recovers QAP1 against the durable Provider and Q6EA services, and serves the bounded pinned Noise listener.
2. Parent submits one Q6PB fixture and an exact replay. The first response is positive only after QAP1 finalization; the replay is rejected.
3. First child exits completely after recording and reporting its Manifest anchor, canonical height, generation and state root.
4. Parent reopens that archive using the reported Manifest anchor, reconstructs the resulting external-anchor state, and verifies it against fresh signed Provider and Q6EA observations through QAP1 before accepting it as the restart pin.
5. A second OS process opens the same archive using that externally checked Manifest anchor, constructs fresh pinned Provider/Q6EA transports and a fresh QAP1 coordinator, calls `recover_qap1_after_process_restart`, and checks exact height, generation, state root, Manifest anchor and absence of unresolved QAP1 intent.
6. Both external services are shut down and the entire temporary service/archive root is removed.

### Verification

- Full focused test `cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib qap1_peer_ingress_qualifies_separate_qfp6_process -- --nocapture`: **1 passed, 0 failed** with both child processes and parent-side Provider/Q6EA verification.
- QAP1 regression group `cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib qap1_peer_ingress -- --nocapture`: **4 passed, 0 failed**.
- `cargo fmt --manifest-path src/native/pow_bench/Cargo.toml -- --check`: passed.
- `git diff --check`: passed; only existing LF/CRLF working-copy notices were emitted.
- Temporary CP-0566B service roots remaining after the test: **0**.
- Branch and HEAD unchanged; worktree count remains **184**. Cargo.lock files unchanged.

### Qualification boundary

This now proves, on one physical Windows laptop, a complete QFP6/QAP1 admission followed by process exit, externally checked durable state, and recovery by a second OS process. It does not prove two physical hosts, separate administrative/operator domains, protection against whole-host backup rollback, production node supervision, or Mainnet readiness. The local Q6EA and Provider are durable test services, not independent production operators.

No commit, push, merge, workflow dispatch, cloud resource, public listener, production key, real-money transaction, or Mainnet action was performed.

## CP-0566C cross-host preflight and architecture gap (2026-11-05)

### Local preflight — observed, not inferred

- The Windows laptop currently reports NetBird CLI **0.82.0** and daemon status **NeedsLogin**. It has no authenticated management/signal session or usable overlay endpoint in this state. CP-0566C was therefore not attempted.
- The existing .github/workflows/qrun-v05-netbird-cross-host-qualification.yml is specifically a QRun **v0.5** workflow. Its manual stages are c1, c2, d1, and d2, and its jobs are guarded to the old branch feat/qrun-v05-netbird-cross-host-qualification-20261102. It invokes tools/qrun-v05-netbird-cross-host-runner.ps1; the legacy C2 path builds qrun_v05_pow_local_node, qrun_v05_noise_key_provision, and qrun_v05_public_alpha_process_smoke. It is not a QFP6/QAP1 workflow and must not be dispatched as CP-0566C evidence.
- The current QFP6/QAP1 process worker is compiled as a library test worker (qfp6_qap1_process_worker), not as a supervised node executable. It accepts explicit listener, Provider and Q6EA socket addresses through test environment variables.
- The parent CP-0566B2 harness starts the durable Provider Noise server on 127.0.0.1:0, starts the Q6EA Noise daemon on 127.0.0.1:0, spawns the QFP6 worker as a local child process, and drives that worker from the parent over loopback. Thus CP-0566B2 proves a distinct OS process and a second-process restart, but the full topology is still one physical host.

### Required CP-0566C refactor — do not bypass

1. Split the parent harness into independently startable **laptop service/driver** and **remote QFP6 peer** roles. The current parent-child process spawn cannot be retained as the cross-host transport.
2. Add explicit, validated bind-address configuration to the Provider and Q6EA test services. The only non-loopback bind accepted by the cross-host profile must be a specifically supplied NetBird overlay IPv4 in 100.64.0.0/10; wildcard, public, LAN and unspecified binds must fail closed.
3. Keep the laptop's Provider and Q6EA stores, signing keys and Noise server identities distinct. The remote QFP6 process must use separate pinned client identities for each service and a separate pinned QFP6 peer identity. All fixtures remain zero-value and test-only.
4. The laptop driver must connect to the remote QFP6 listener over NetBird, authenticate the pinned Noise XX peer, submit one Q6PB fixture and an exact replay, and check the first Q6PA is positive only after Provider CAS, Q6EA CAS, fresh signed Q6EA read and local manifest finalization. The replay must not advance state.
5. The remote QFP6 process must connect back to the laptop Provider and Q6EA endpoints over distinct pinned Noise/TCP sessions, recover QAP1 before binding its peer listener, persist its QFP6 archive, exit, and recover the exact archive in a second OS process on the same remote runner.
6. Use a new manual-only CP-0566C workflow with checkout pinned to the dispatched SHA and contents: read. The old v0.5 workflow is not reused. NetBird Setup Key remains a short-lived GitHub Actions secret; no secret or private key is placed in the repository, workflow logs, command line, or chat.
7. ACL/firewall scope is limited to the two ephemeral overlay peers and the three explicitly required test TCP endpoints. RPC and transaction ingress remain loopback-only. Teardown must remove only resources created by this run and must execute on success and failure.

### Current disposition

**CP-0566C: BLOCKED / NOT RUN.** The first blocker is local NetBird authentication (NeedsLogin). A second, independent implementation blocker is that the existing CP-0566B2 test harness hardcodes its Provider/Q6EA services to loopback and locally spawns the QFP6 worker. Merely reconnecting NetBird or changing the old v0.5 workflow would not close this gap.

Next engineering work is the role-split, bind-configurable test harness and dedicated manual-only workflow. Only after those changes are reviewed, the laptop's NetBird session is authenticated, and the peer ACL is verified may the two-host test be run. No login, ACL change, listener bind, workflow dispatch, push, cloud resource, or public-network action was performed during this preflight.

### CP-0566C implementation preparation — service bind policy (2026-11-05)

Added explicit-address variants for the test-only durable Provider Noise server and Q6EA Noise daemon. Existing helper entry points remain backward-compatible and continue to default to 127.0.0.1:0. The explicit-address variants call a fail-closed address guard before binding: loopback is accepted for local tests; non-loopback is accepted only for IPv4 within NetBird's 100.64.0.0/10 overlay range. Wildcard, LAN, public IPv4, out-of-range CGNAT and non-loopback IPv6 addresses are rejected. This prepares the service layer for the future Node A overlay bind without exposing any listener now.

Fresh verification on the Windows laptop:

- qap1_service_bind_policy_accepts_only_loopback_or_netbird_overlay: **1 passed, 0 failed**. The test confirms loopback and both edges of the NetBird overlay range are accepted by policy, while wildcard, LAN, public and adjacent out-of-range IPv4 addresses are rejected. The expected panic-hook messages are from the deliberate rejection checks; the test result is PASS.
- qap1_peer_ingress regression group: **4 passed, 0 failed** (positive ACK only after finalization, zero-value QZXB/QUSDT-TST test trade, durable AMM swap/restart, and two-process QFP6/QAP1 admission plus restart).
- cargo fmt --manifest-path src/native/pow_bench/Cargo.toml -- --check: **PASS**.
- git diff --check: **PASS**; only pre-existing LF/CRLF working-copy notices were emitted.

This is a code-level preflight improvement, not a cross-host result. No overlay-address bind was attempted because the local NetBird daemon remains NeedsLogin. The new explicit-address helper path has not yet been exercised against a live NetBird interface. CP-0566C remains **BLOCKED / NOT RUN** pending the role-split driver/remote-worker harness, dedicated manual-only workflow, authenticated NetBird session and reviewed peer ACL.

Branch remains feat/qzxb-usdt-trading-gate-20261104; HEAD remains 4b8cfd53f8debb9d77086e6830e6d10f827ceb2d. Worktree status count remains 184; Cargo.lock files unchanged. No commit, push, merge, workflow dispatch, cloud resource, public listener, production key, real-money transaction or Mainnet action was performed.

### CP-0566C implementation preparation — explicit overlay endpoints (2026-11-05, continued)

The test-only service helpers now read two explicit optional environment variables:

- QRUN_QFP6_QAP1_PROVIDER_BIND_ADDR
- QRUN_QFP6_QAP1_ANCHOR_BIND_ADDR

When absent, both preserve the existing 127.0.0.1:0 behavior. When present, the value must parse as a SocketAddr and pass the loopback/NetBird IPv4 allowlist before the socket is bound. The separate QFP6 worker now applies the same allowlist to its peer listener bind address and both Provider/Q6EA destination addresses. This prevents accidental use of wildcard, LAN, or public addresses in the test worker profile. It does not create or open any listener by itself.

The existing qfp6_qap1_process_worker test entry point is independently invocable through the Rust test harness when QRUN_QFP6_QAP1_PROCESS_ROLE=server|restart and the complete explicit test configuration is supplied. This is a candidate for the remote Runner role, but cross-host operation still requires the laptop-side driver to export/provision the matching ephemeral pins securely, the remote Runner to publish its overlay address and pinned listener public key, and the Node A driver to submit the Q6PB frame while the remote worker is alive. The local parent test still starts a child process and must not be reported as a cross-host driver.

Fresh verification after these changes:

- qap1_service_bind_policy_accepts_only_loopback_or_netbird_overlay: **1 passed, 0 failed**, including default-loopback parsing, explicit in-range overlay parsing, acceptance of loopback/overlay endpoints, and rejection of wildcard/LAN/public/out-of-range addresses.
- QAP1 peer-ingress regression group: **4 passed, 0 failed**.
- cargo fmt --manifest-path src/native/pow_bench/Cargo.toml -- --check: **PASS**.
- git diff --check: **PASS**; only existing LF/CRLF working-copy notices remain.

CP-0566C remains **BLOCKED / NOT RUN**. NetBird on the laptop is still NeedsLogin; no live overlay bind or connection has been attempted. Dedicated Node A driver/config handoff and the manual-only QFP6/QAP1 workflow remain open. The bind-address guard is tested; the actual non-loopback service startup path is not yet tested on a real NetBird interface.

No commit, push, merge, workflow dispatch, cloud resource, public listener, production key, real-money transaction, or Mainnet action was performed.

### CP-0566C test-isolation correction (2026-11-05)

A potential parallel-test collision was identified in the first bind-configuration approach: reading fixed overlay bind addresses from process-wide environment variables in the common Provider/Q6EA helper wrappers could cause unrelated QAP1 tests to contend for the same fixed service ports when Cargo runs tests concurrently.

Correction:
- The common Provider and Q6EA helper wrappers are explicitly restored to 127.0.0.1:0.
- The separate _at constructors retain the validated explicit-address parameter for a dedicated cross-host controller only.
- The cross-host worker continues validating its listener and both external service endpoints against the loopback/NetBird allowlist.
- The process-separated QFP6/QAP1 parent test now explicitly asserts that its default Provider and Q6EA services remain loopback-bound.

Fresh post-correction verification:
- Bind policy test: **1 passed, 0 failed**.
- QAP1 peer-ingress regression group: **4 passed, 0 failed**.
- Rust formatting check: **PASS**.
- git diff --check: **PASS**, with only existing LF/CRLF working-copy notices.

This correction deliberately avoids process-global environment configuration. The future laptop controller must supply explicit overlay SocketAddr values only at its dedicated _at service-constructor call sites; normal QAP1 tests remain isolated and loopback-only.

CP-0566C remains **BLOCKED / NOT RUN**. GitHub CLI is authenticated for the repository, but the repository currently has no Actions secrets or variables configured. The laptop NetBird client remains NeedsLogin. No Setup Key or bootstrap token was created, no secret was set, and no workflow was dispatched.

## CP-0566C remote Runner role scaffold (2026-11-05)

### New files

- .github/workflows/qfp6-qap1-netbird-cross-host.yml — separate manual-only workflow, restricted to feat/qzxb-usdt-trading-gate-20261104, contents: read, checkout pinned to the dispatched SHA, pinned NetBird 0.82.0 MSI SHA-256 plus Authenticode verification, one-shot NetBird enrollment, explicit overlay-range check, and unconditional NetBird disconnect.
- tools/qrun-v06-qfp6-qap1-runner.ps1 — independent Node B runner role. It reads a secret JSON configuration only from QRUN_QFP6_QAP1_RUNNER_CONFIG_JSON, validates endpoint syntax and private Overlay IPv4 addresses, validates all 32-byte Noise keys and 1952-byte ML-DSA-65 public keys, creates isolated temporary QFP6/floor directories, invokes the worker once in server mode and again in restart mode, verifies one block / one generation and exact state-root/manifest-anchor continuity, then removes its temporary state and key-bearing environment variables.
- The QFP6 worker bounded listener timeout is configurable through QRUN_QFP6_QAP1_LISTENER_TIMEOUT_SECS, constrained to 1–900 seconds. The default remains 15 seconds for existing local tests; the Runner role selects 600 seconds so the separate laptop driver has time to establish the authenticated session.

### Fresh local preflight

- PowerShell parser: **PASS** for the Runner script.
- IPv4 endpoint syntax parser: **PASS**.
- Overlay policy rejects a public IPv4 address: **PASS**.
- Workflow placeholder expansion check: **PASS**.
- GitHub Actions workflow YAML parse: **PASS** using the local YAML parser.
- QAP1 peer-ingress regression group after listener-timeout change: **4 passed, 0 failed**.
- Rust formatting check: **PASS**.
- git diff --check: **PASS**, with only existing LF/CRLF working-copy notices.

### Remaining gap — do not dispatch

This is only the remote Node B role scaffold. The matching Node A controller is not yet implemented. It must generate separate ephemeral Noise identities, start Provider and Q6EA on the laptop's actual NetBird IPv4 using the explicit-address constructors, pin the Runner's Provider/Q6EA client public keys, derive the expected remote QFP6 listener public key, submit the Q6PB fixture and exact replay, and verify the signed Provider/Q6EA state. It must also provision QRUN_QFP6_QAP1_RUNNER_CONFIG_JSON as a short-lived repository Actions secret, dispatch the manual workflow, discover the Runner endpoint, and remove temporary GitHub secrets during cleanup. This must be one bounded, fail-closed controller lifecycle; do not store private keys in repository variables, workflow files, command lines, or logs.

The GitHub repository presently has no Actions secrets or variables configured, and the laptop NetBird daemon remains NeedsLogin. Therefore the new workflow is not runnable yet and was not dispatched. The workflow is not evidence of cross-host success. No ACL change, Setup Key creation, secret creation, push, cloud resource, or listener bind was performed.

CP-0566C remains **BLOCKED / NOT RUN** pending the Node A controller, safe bootstrap/pinning handoff, authenticated laptop NetBird session, and reviewed two-peer ACL.

### CP-0566C Node A driver scaffold (2026-11-05)

Added test-harness role qfp6_qap1_node_a_driver inside qrun_v06_node_runtime_candidate.rs. It is inert unless QRUN_QFP6_QAP1_NODE_A_ROLE=driver is explicitly set. In driver mode it:

- requires an explicit Node A NetBird IPv4 and binds only the reserved private test endpoints Provider TCP/49661, Q6EA TCP/49662, callback TCP/49663; Node B QFP6 listens on TCP/49664;
- creates per-run ML-DSA-65 signing keys from OS-random seed material, separate Noise client/server identities, a one-run 256-bit callback nonce, and the exact CP-0566B zero-value Genesis bootstrap record;
- initializes the durable Provider and Q6EA services at the explicit Overlay address and writes the Runner JSON configuration only to a caller-supplied protected temporary file (never stdout);
- accepts a callback only from a NetBird-range peer, checks the callback nonce, requires the announced QFP6 endpoint IP to equal the callback peer IP, and pins the announced Runner listener public key against the independently generated expected key;
- sends one Q6PB fixture and an exact replay through a pinned Noise session, requires ACCEPTED then REJECTED, and keeps both external services alive until the Runner's second process reports exact state/manifest restart continuity;
- shuts down the Provider and Q6EA services after the Runner completion callback.

The remote Runner script was updated to precompile before callback, send READY over the private Overlay, run the QFP6 server role, run the second restart role, then send DONE containing the manifest anchor, state root, height and generation. Private configuration values are not printed.

Fixed transport ports for the proposed first cross-host run are TCP 49661–49664. A reviewed NetBird ACL and host firewall must allow only the intended peer-to-peer direction/ports: Node B -> Node A 49661, 49662, 49663; Node A -> Node B 49664. No RPC or transaction port is exposed. These endpoints have not been bound on the live laptop because NetBird is still NeedsLogin.

### Fresh validation after Node A role addition

- PowerShell parser for tools/qrun-v06-qfp6-qap1-runner.ps1: **PASS**.
- GitHub Actions workflow YAML parser: **PASS** (syntax only; does not validate runtime secret schema).
- QAP1 bind policy: **1 passed, 0 failed**.
- Node A driver test with no role enabled: **1 passed, 0 failed** (confirms default invocation is inert; does not execute live driver).
- QAP1 peer-ingress regression group: **4 passed, 0 failed**.
- QFP6 listener suite: **5 passed, 0 failed**.
- QFP6 Noise suite: **8 passed, 0 failed**.
- Rust formatting and git diff checks: **PASS**.
- Branch and HEAD unchanged; worktree count now 187. Both Cargo.lock files remain unchanged.

### Remaining blockers found in the orchestration layer

1. The current workflow's Setup Key validation still assumes a UUID-shaped token. NetBird's current documentation gives a different example token form (AAAA-BBB-CCC-DDDDDD) and supports NB_SETUP_KEY for netbird up; therefore the workflow validator must be relaxed to a bounded non-whitespace token before it can accept a valid setup key. No Setup Key is present or has been created.
2. The workflow's early JSON validation list still needs the Node A callback address, callback nonce and Node B listener public key fields, although the Runner script now requires them. The callback flow is not end-to-end runnable until this schema is brought into sync.
3. The PowerShell Node A orchestration wrapper is not yet implemented. It must check an already-authenticated Node A NetBird session, create an ACL-scoped config directory, start the Rust driver, pass the one-shot JSON file to a temporary GitHub Actions secret without printing it, dispatch the committed workflow, wait for the Node A READY/DONE callbacks and Runner completion, then delete the temporary GitHub secret and local files.
4. All new files and changes remain local/uncommitted. The GitHub branch still points at the older HEAD. No push has been authorized or performed, so the remote runner cannot yet check out these changes.
5. NetBird on the laptop remains NeedsLogin; there is no reviewed ACL or short-lived one-use Setup Key. No cross-host socket bind, workflow dispatch, secret creation, push, cloud resource or real-money transaction was performed.

**CP-0566C status: BLOCKED / NOT RUN.** The Node A and Node B roles are now scaffolded and locally compiled, but a true two-host qualification still requires the workflow/schema correction, controller wrapper, authenticated NetBird, reviewed ACL, and an authorized publication of the code to the remote branch.


### CP-0566C static orchestration review — additional blockers (2026-11-05)

The next read-only review identified the following issues. These are review findings, not live qualification results:

1. **Setup Key minimum-length mismatch.** The workflow currently requires at least 20 characters. NetBird's documented example form `AAAA-BBB-CCC-DDDDDD` is 19 characters, so a valid key in that documented form would be rejected. Replace the minimum-length assumption with bounded, non-whitespace token validation while retaining a reasonable maximum length. Do not log the key.
2. **Workflow dispatch discoverability.** The repository default branch is `main`. The new CP-0566C workflow file is not present on that branch (GitHub contents lookup returned 404 for this path on the default branch). GitHub's `workflow_dispatch` workflow must be present on the default branch to be manually dispatchable. The workflow must be safely added to the default branch before relying on the Actions UI/API for dispatch; no such publication has been made.
3. **Workflow/Runner schema mismatch.** The PowerShell Runner requires `node_a_callback_address`, `callback_nonce_hex`, and `node_b_listener_public_hex`, while the workflow's early validation list omits those names. Synchronize the validation lists so malformed configuration is rejected before installation/enrollment rather than later in the run.
4. **Node A role must be stricter than shared local test bind policy.** The shared `assert_qap1_test_bind_address` intentionally permits loopback for local tests. The explicit Node A driver currently calls it for its Node A overlay IP and callback peer. The dedicated cross-host driver should separately require IPv4 in NetBird's `100.64.0.0/10` range, while local test helpers continue accepting loopback. This avoids relying on the remote Runner's later validation as the first enforcement point.
5. **Callback encoding/BOM risk.** The Runner creates its callback writer with `[System.Text.Encoding]::UTF8`. Microsoft's .NET documentation states that the `Encoding.UTF8` property returns a UTF8Encoding configured to provide a UTF-8 preamble/BOM, unlike the default StreamWriter constructor's BOM-less encoding. The Node A Rust callback parser compares the first split field directly with `READY` and does not strip U+FEFF. Consequently the first callback line may parse as `\u{FEFF}READY` and fail the handshake. Construct the writer using `[System.Text.UTF8Encoding]::new($false)` (no BOM); additionally consider stripping a leading U+FEFF defensively on the Rust side. Add a protocol-level test for both READY and DONE framing before any live network run.
6. **No-BOM change is not yet applied or tested.** The suggested encoding change above is a static-review recommendation only. Do not mark it fixed until the Runner script is changed and a test verifies the exact bytes/parsed fields.

### Recommended resolution order

- First, fix and test the callback framing (BOM-less encoding and parser robustness).
- Add a Node A-only strict NetBird IPv4 guard and tests; keep shared local bind policy unchanged.
- Align all workflow/runner required-field lists and correct Setup Key token validation.
- Complete the protected local orchestrator and cleanup path, including temporary secret removal on all exits.
- Publish the workflow through a reviewed, explicit change on the repository default branch, then dispatch only after NetBird authentication and peer ACL review.

**Disposition remains CP-0566C: BLOCKED / NOT RUN.** No live callback, two-host connection, ACL update, Setup Key creation, GitHub Secret mutation, push, merge, workflow dispatch, public listener, paid cloud resource, market order, liquidity provision, or Mainnet operation occurred as part of this review.


### CP-0566C cross-host trust-boundary and callback hardening (2026-11-05)

The local Node A driver and Runner callback path received a small hardening pass. These are local/uncommitted changes.

1. Added a dedicated `is_qap1_netbird_overlay_ip` / `assert_qap1_netbird_overlay_ip` policy. The actual `qfp6_qap1_node_a_driver` now requires Node A's configured address and the accepted callback peer source address to be IPv4 inside `100.64.0.0/10`. The shared local test bind policy remains unchanged and continues to allow loopback.
2. Added a focused positive/negative policy test covering valid NetBird endpoints, loopback, IPv6 loopback, adjacent out-of-range addresses, LAN IPv4 and unspecified IPv4.
3. Added `qap1_callback_fields`, which strips a leading UTF-8 BOM before parsing either callback line. READY and DONE parsing now use this helper.
4. Changed the Runner's callback writer to `[System.Text.UTF8Encoding]::new($false)`, so it emits UTF-8 without a preamble/BOM. A parser test covers BOM-less and BOM-prefixed READY and DONE framing.
5. Node A now cross-checks the DONE manifest anchor, height and generation against the Q6PA Accepted response it received. The response encodes manifest anchor at bytes 96..128, height at bytes 80..88 and generation at bytes 88..96. The DONE state root is syntax-checked and rejected if zero; Node A still cannot independently compare that root because Q6PA does not carry a state-root field. The Runner's second-process restart worker remains responsible for verifying the exact expected state root against persisted state.

#### Fresh local validation

- `cargo fmt` and `cargo fmt -- --check`: **PASS**.
- `qap1_cross_host_overlay_policy_requires_netbird_ipv4`: **1 passed**.
- `qap1_callback_parser_accepts_bomless_and_bom_prefixed_ready_done`: **1 passed**.
- `qap1_service_bind_policy_accepts_only_loopback_or_netbird_overlay`: **1 passed**.
- `qfp6_qap1_node_a_driver` without the explicit driver role: **1 passed**; normal test invocation remains inert.
- PowerShell Runner script parser: **PASS**.
- BOM-less .NET UTF-8 encoding preamble assertion: **PASS**.
- `git diff --check`: **PASS**, with existing LF/CRLF working-copy notices only.

These are local code and protocol tests. They do not establish a live NetBird connection or a two-host result.

#### Orchestrator/Runner contract mismatch found

The existing `tools/qrun-v06-qfp6-qap1-node-a-controller.ps1` file is present, but it is not integrated with the current Node A driver/Runner contract:

1. It invokes the older test worker `qap1_cross_host_node_a_driver_worker` and sets the older `QRUN_QFP6_QAP1_DRIVER_*` variables. The current driver is `qfp6_qap1_node_a_driver`, which requires `QRUN_QFP6_QAP1_NODE_A_ROLE`, `QRUN_QFP6_QAP1_NODE_A_OVERLAY_IP`, and `QRUN_QFP6_QAP1_NODE_A_CONFIG_PATH`.
2. The controller expects `QFP6_QAP1_DRIVER_CONFIG_JSON=...` on stdout. The current Node A driver writes the JSON to a caller-supplied file and emits only readiness markers. The controller must be reconciled to read that protected file instead of waiting for the obsolete stdout JSON marker.
3. The controller's `Wait-RunnerEndpoint` expects `QFP6_QAP1_RUNNER_LISTEN_ENDPOINT=...`, but the current Runner does not emit that marker. Align the endpoint handoff with the authenticated READY callback used by the current Node A driver, or define and test one canonical alternative.
4. The controller does not yet establish a restrictive ACL on its temporary configuration directory before the Rust driver creates the secret-bearing JSON file. This must be done before the file is created; cleanup alone is insufficient.
5. The controller's Setup Key validation still has a 20-character minimum and must be aligned with the Workflow validator and the documented Setup Key format.
6. The workflow still needs the three callback-related JSON fields in its early validation list, and the manual workflow must be safely present on the repository default branch before dispatch. These workflow changes have not been made.

#### Disposition

CP-0566C remains **BLOCKED / NOT RUN**. The local trust-boundary and callback hardening tests pass, but the Node A controller is still stale and not safe to dispatch. No local NetBird enrollment, Setup Key entry, GitHub Actions secret creation/deletion, ACL/firewall change, push, merge, workflow dispatch, public listener, cloud resource, real transaction, liquidity provision or Mainnet operation occurred.


### CP-0566C Node A controller reconciliation and protected bootstrap (2026-11-05)

The existing local Node A PowerShell controller was reconciled to the current QFP6 driver and Runner contract. These are local/uncommitted changes only.

1. The controller now invokes `qfp6_qap1_node_a_driver` and supplies `QRUN_QFP6_QAP1_NODE_A_ROLE`, `QRUN_QFP6_QAP1_NODE_A_OVERLAY_IP`, and `QRUN_QFP6_QAP1_NODE_A_CONFIG_PATH`. The old worker name and obsolete `QRUN_QFP6_QAP1_DRIVER_*` environment variables are no longer used by the active launch path.
2. Before starting the driver, the controller creates a per-run temporary directory and applies a protected Windows DACL allowing FullControl only to the current user, LocalSystem and local Administrators. The Rust driver writes its one-run Runner JSON file into that directory. The controller reads the file without printing it; its final cleanup removes the temporary directory.
3. Both stdout and stderr are drained asynchronously from the child process so cargo/test output cannot block the driver on a full redirected pipe.
4. The controller waits for the protected configuration file (bounded to ten minutes), parses it, and checks all fourteen fields consumed by the current Runner. It no longer waits for the obsolete JSON-on-stdout marker.
5. The Runner endpoint is no longer passed to Node A through stdin or inferred from a CI log marker. Node A obtains it only from the authenticated NetBird callback, then validates callback source IP, announced endpoint IP/port, nonce and independently pinned listener public key.
6. The controller watches the exact dispatched run while the Node A driver is active. A failed completed run aborts the local driver; successful completion still requires Node A's restart confirmation marker and the Runner's remote admission/restart marker.
7. Runner port is pinned to TCP 49664, matching the current Rust Node A driver. Provider, Q6EA and callback endpoints remain the reserved 49661, 49662 and 49663 ports.
8. The controller's Setup Key check now accepts bounded non-whitespace tokens (1..256 characters), including the documented 19-character example format; it does not log the token.
9. The Workflow's early JSON validation now includes `node_a_callback_address`, `callback_nonce_hex` and `node_b_listener_public_hex`. Its Setup Key validation uses the same bounded non-whitespace rule as the controller.

#### Fresh local validation

- PowerShell parser for the Node A controller: **PASS**.
- PowerShell parser for the Node B Runner: **PASS**.
- Workflow YAML parse: **PASS**.
- Static Workflow/Runner required-field check for all three previously omitted fields: **PASS**.
- Controller safe preflight mode: **PASS**; confirmed no secrets, workflow runs or network listeners were created.
- Protected temporary-directory ACL smoke test: **PASS**; DACL inheritance disabled and only current user, LocalSystem and local Administrators present; test directory removed afterward.
- `git diff --check`: **PASS**, with pre-existing LF/CRLF notices only.
- Previously in this pass: callback BOM framing test **1 passed**, overlay IPv4 policy test **1 passed**, local bind-policy regression test **1 passed**, and inert Node A driver test **1 passed**.

#### Remaining release/qualification blockers

- The local Git worktree remains broadly dirty with many unrelated and previously existing project changes. The controller intentionally refuses dispatch from a dirty worktree or when the remote feature branch does not point to the exact local HEAD. No mass staging or commit was performed.
- The manual Workflow was previously confirmed absent from the repository's default `main` branch. GitHub requires a `workflow_dispatch` Workflow file on the default branch for manual dispatch. No publication to `main` or feature branch push was performed.
- The laptop NetBird client remains `NeedsLogin`; no ACL/host-firewall review, one-time Setup Key creation, GitHub Secret mutation or live socket bind was performed.
- The Workflow/Runner/controller have not yet been exercised end-to-end against GitHub Actions. All verification in this section is local static/preflight verification.
- The Node A controller still intentionally requires explicit `-Dispatch -AclReviewed` and checks the local/remote revision, default-branch workflow visibility, NetBird connection, and absence of conflicting pre-existing temporary secrets before any side effects.

**CP-0566C disposition remains BLOCKED / NOT RUN.** No two-host proof, public Devnet, market, liquidity, Mainnet or cross-chain transfer is claimed.


### CP-0566C bootstrap-file race closure (2026-11-05)

A final review of the reconciled controller found that the JSON file becomes visible in the filesystem as soon as `OpenOptions::create_new` succeeds, before the Rust driver completes `write_all` and `sync_all`. A single immediate read could therefore observe an empty or partial file. `Read-DriverBootstrap` now retries within a bounded ten-minute window until JSON parsing succeeds and all fourteen required fields are present; it then checks the canonical listener port. If the driver exits or the deadline expires, the controller fails closed and its existing cleanup path terminates the child and removes the protected temp directory/secrets.

The Windows ACL smoke test for the exact DACL construction passed on a disposable temporary directory. No project secret or key material was used in that test, and the temporary directory was removed.

The latest controller edit was not re-run through the final full validation command after this retry change because the remote command invocation was blocked by the execution safety layer. Earlier in this same pass, both controller and Runner PowerShell parsers, Workflow YAML parsing, Workflow/Runner schema field check, controller safe preflight, and `git diff --check` had passed before the final retry-loop-only edit. Treat the retry-loop change as implemented but pending one final syntax/preflight pass.

**CP-0566C remains BLOCKED / NOT RUN.** No setup key was requested, no Actions secret was created, and no network listener, workflow dispatch or remote connection was attempted.


### Final targeted parser check after bootstrap retry update (2026-11-05)

- PowerShell parser for `tools/qrun-v06-qfp6-qap1-node-a-controller.ps1` after the bounded JSON retry-loop edit: **PASS**.
- No dispatch or other external side effect was performed.
- This targeted parser result does not replace a complete end-to-end test of the Controller/Workflow/Runner combination. The local dirty worktree, required default-branch workflow publication, and unauthenticated NetBird laptop remain hard blockers.

**CP-0566C remains BLOCKED / NOT RUN.**


### Isolated source-snapshot build and QFP6/QAP1 regression results (2026-11-05)

A temporary source snapshot was created outside the repository worktree at `D:\Temp\ASUS\QRUN_CP0566C_CRATE_SNAPSHOT_20261105_103855`. It contains the current `src/native/pow_bench` crate copied from the local working tree plus compile-time fixtures discovered by scanning the crate's `include_str!` and `include_bytes!` references. The scan found 44 distinct in-repository fixture files and zero missing references. The first crate-only copy could not compile because those compile-time fixtures live outside the crate; after copying the exact referenced files, the snapshot compiled successfully.

The snapshot contains 232 Rust source files. Tests were run with Cargo offline. The snapshot source/fixture tree was separate from the main worktree; for resource efficiency, `CARGO_TARGET_DIR` reused the repository's existing ignored `target` cache, so this was source isolation rather than a fully independent toolchain/cache environment.

Results:
- `cargo test --offline --manifest-path <snapshot>/src/native/pow_bench/Cargo.toml --lib qap1_ -- --nocapture`: **24 passed, 0 failed, 0 ignored**, 4.83 seconds; exit code 0.
- `cargo test --offline --manifest-path <snapshot>/src/native/pow_bench/Cargo.toml --lib qfp6_ -- --nocapture`: **37 passed, 0 failed, 0 ignored**, 8.02 seconds; exit code 0.
- Combined these are two filtered suites with overlapping tests; do not report the sum as a unique test count.
- `qfp6_qap1_node_a_driver` passing in this run is only its ordinary inert/no-role test path. The live driver role was not invoked, and no sockets, NetBird enrollment, GitHub workflow, or two-host qualification were exercised.

This gives an isolated-source regression baseline for the current local candidate, not a release artifact or proof that a clean minimal Git commit can be built from the remote repository. The source snapshot was copied from local HEAD `4b8cfd53f8de` plus the current uncommitted crate overlay. No commit, push, staging, secret mutation, or remote workflow dispatch was performed.

**CP-0566C disposition remains BLOCKED / NOT RUN.** Two distinct physical hosts, remote Runner enrollment, end-to-end Controller/Workflow/Runner execution, and the one-time ACL review remain outstanding.

Input manifest verification:
- Snapshot source files: **232**, source SHA-256 mismatches against the copied working-tree inputs: **0**.
- Compile-time fixture references: **44**, fixture SHA-256 mismatches: **0**.
- Manifest: `D:\Temp\ASUS\QRUN_CP0566C_CRATE_SNAPSHOT_20261105_103855\CP0566C_INPUT_MANIFEST.tsv`.
- Manifest SHA-256: `b40b0161d01d3748c9b27be424e27fd6d9163d48aa2a69c420d0d3813532979e`.
- Main worktree status count after snapshot/testing: **187**, unchanged from the initial read-only inventory; no source was staged or committed.


### GitHub remote branch topology recheck (read-only, 2026-11-05)

GitHub API read-only inspection found:
- Repository default branch is `main`, currently at `ba120c1191956468a1106daff6a915c155f50f8a`.
- The local base commit `4b8cfd53f8debb9d77086e6830e6d10f827ceb2d` exists remotely as the head of `feat/qrun-v05-netbird-cross-host-qualification-20261102`.
- The locally configured target ref `feat/qzxb-usdt-trading-gate-20261104` does **not** appear in the remote branch listing; a Contents API lookup using that ref returned `No commit found for the ref`.
- `.github/workflows/qfp6-qap1-netbird-cross-host.yml` is absent from `main` (Contents API 404), and also absent at the expected `feat/qzxb-usdt-trading-gate-20261104` ref.
- GitHub compare `main...4b8cfd53f8debb9d77086e6830e6d10f827ceb2d` reports `diverged`, with the 4b8 side 259 commits ahead and 18 commits behind `main`.

Consequences:
- The current Controller's hard-coded expected feature ref and the Workflow's `github.ref` guard are not dispatchable against the current remote branch inventory.
- The existing v0.5 NetBird branch is a valid remote pointer to the local base SHA, but it does not contain the current uncommitted QFP6/QAP1 overlay. Do not silently repoint the QFP6 workflow to that old branch or assume it contains the new driver/Runner.
- Do not push the 259-ahead/18-behind branch to `main` or merge it automatically. A deliberate integration/rebase and minimal release-branch decision is required first.
- GitHub's current documentation confirms `workflow_dispatch` must be registered on the default branch; once registered, the run can target a selected branch/ref. The run then uses the workflow version on the selected ref. See https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow and https://docs.github.com/en/actions/concepts/workflows-and-actions/workflows.

This is now an explicit hard blocker in addition to the dirty local worktree and NetBird/ACL prerequisites. No GitHub writes, branch creation, commit, push, merge, secret changes or workflow dispatch were performed.

**CP-0566C remains BLOCKED / NOT RUN.**


### Local Git topology and NetBird recheck (2026-11-05)

Read-only inspection on the authorized Windows device `heymed` established:

- Current local branch: `feat/qzxb-usdt-trading-gate-20261104`.
- Current HEAD: `4b8cfd53f8debb9d77086e6830e6d10f827ceb2d`.
- Local `origin/main` tracking ref: `ba120c1191956468a1106daff6a915c155f50f8a`.
- Merge base: `0c489c1b19fe85a8956872b8b23e83342863f475`.
- `git rev-list --left-right --count HEAD...origin/main`: 259 commits ahead and 18 commits behind.
- No matching `origin/feat/qzxb-usdt-trading-gate-20261104` remote-tracking branch is present locally.
- The CP-0566C workflow file is absent from both committed `HEAD` and `origin/main`; it exists only as an untracked local file.
- NetBird daemon status is `NeedsLogin`; no peer connection is currently established.
- Main worktree remains at 187 porcelain entries (76 modified/staged-status entries and 111 untracked entries at the time of inspection); no cleanup, staging, or commit was performed.
- Independent Snapshot remains present at `D:\Temp\ASUS\QRUN_CP0566C_CRATE_SNAPSHOT_20261105_103855`. Its manifest has 279 lines including the header and SHA-256 `b40b0161d01d3748c9b27be424e27fd6d9163d48aa2a69c420d0d3813532979e`.

Release implication: do not merge or rebase this 259-ahead/18-behind local branch into `main` as an expedient way to expose `workflow_dispatch`. First prepare a separate, auditable integration plan that preserves the current worktree and identifies the minimum dependency set against the current default-branch tip. Publishing the workflow or creating/pushing branches remains an explicit-approval boundary.

No Git commit, push, merge, workflow dispatch, GitHub secret change, NetBird login, ACL change, listener binding, cloud provisioning, or real transaction was performed during this recheck.

CP-0566C remains **BLOCKED / NOT RUN** pending a clean release boundary, a workflow available on the default branch, and an authenticated second NetBird peer.


### Live Git remote verification (2026-11-05)

A read-only `git ls-remote --heads origin main feat/qzxb-usdt-trading-gate-20261104` completed successfully with exit code 0. It returned only:

- `refs/heads/main` at `ba120c1191956468a1106daff6a915c155f50f8a`.

No live remote head was returned for `feat/qzxb-usdt-trading-gate-20261104`. This confirms the candidate feature branch has not been published to origin; the local branch and its uncommitted changes remain local.

The remote default-branch tip matches the local `origin/main` tracking ref at the time of this check. No remote refs were changed.


### Mainline-based isolated Crate integration trial (2026-11-05)

Two detached worktrees were created from the live-verified `origin/main` SHA `ba120c1191956468a1106daff6a915c155f50f8a`:

- Clean baseline: `D:\Temp\ASUS\QRUN_CP0566C_MAINLINE_BASELINE_20261105` — final Git status count 0.
- Integration trial: `D:\Temp\ASUS\QRUN_CP0566C_MAINLINE_INTEGRATION_TRIAL_20261105` — detached at the same SHA, with 109 local entries representing the isolated Crate transplant and referenced fixtures.

Dependency reconciliation found:
- 83 committed path differences under `src/native/pow_bench` between the local feature HEAD and `origin/main`.
- 44 dirty/untracked paths under the local Crate at transplant time.
- 105 unique Crate paths reconciled into the integration trial.
- The local feature HEAD contains 210 tracked Rust source files under the Crate versus 156 in `origin/main`; 54 Rust source paths are present only in the local feature history.
- A first 30-file-only trial failed formatting because it omitted `consensus_native_recovery_gate_candidate.rs`, a source file present in local HEAD history but absent from `origin/main`. This was a dependency-closure discovery, not a compiler defect.
- Scanning 243 Rust source files found 44 literal `include_str!` / `include_bytes!` references. All 44 referenced source files were copied into the trial; unresolved source references: 0.

Validation on the expanded mainline-based integration trial:
- `cargo fmt --manifest-path ... -- --check`: PASS.
- `cargo test --offline --manifest-path ... --lib qap1_ -- --nocapture`: PASS, 24 passed, 0 failed, 1,244 filtered out.
- `cargo test --offline --manifest-path ... --lib qfp6_ -- --nocapture`: PASS, 37 passed, 0 failed, 1,231 filtered out.
- QAP1 and QFP6 are filtered library test groups, not the full Crate test suite.
- These tests include two-process and restart simulations; they do not execute the live Node A/Node B controller over two physical NetBird hosts.

Final safety check after the trial:
- Original feature worktree remains on `feat/qzxb-usdt-trading-gate-20261104`, HEAD `4b8cfd53f8debb9d77086e6830e6d10f827ceb2d`, with 187 status entries — unchanged from preflight.
- Clean mainline baseline remains at `ba120c1191956468a1106daff6a915c155f50f8a` with 0 status entries.
- Integration trial remains detached at the mainline SHA and contains 109 local entries.
- No commit, push, merge, workflow dispatch, secret mutation, NetBird login, ACL edit, or real-market transaction occurred.

This establishes a mainline-based, isolated Crate integration test path for the QFP6/QAP1 candidate. It does not yet establish the minimal final public release patch outside the Crate. CP-0566C remains **BLOCKED / NOT RUN** until the Controller/Runner/Workflow release boundary is independently reconciled, the workflow is available on the default branch, and a second authenticated NetBird peer is connected.


### Controller / Runner / Workflow contract audit (2026-11-05)

A three-file read-through and targeted local checks were completed:

- Controller, Runner, and Workflow agree on the 14 bootstrap JSON field names.
- Controller's required Runner port is exactly 49664; Node A driver emits that port and Runner reads and validates it.
- Callback contract is aligned: Node B writes READY with nonce, listener endpoint and listener public key; Node A checks callback source overlay IP, announced endpoint IP/port, nonce and pinned listener identity. Node B later writes DONE over the same callback stream; Node A checks nonce, manifest anchor, height, generation, nonzero state-root and PASS status.
- Node A driver environment variable names match the Rust implementation for role, overlay IP and protected config path.
- Runner process environment names match the Rust process worker, including role, listen/provider/anchor addresses and expected restart state-root.
- Runner uses `NB_SETUP_KEY` for `netbird up`. NetBird's current CLI documentation explicitly documents flag-derived environment variables and `NB_SETUP_KEY`; this use is supported. See https://docs.netbird.io/get-started/cli and https://docs.netbird.io/manage/peers/bootstrap-via-config-file.
- Current GitHub Windows Server 2025 runner image documentation lists Rust, Cargo and Rustfmt as installed, so the workflow's `rustc --version` / `cargo --version` preflight does not require an extra Rust installation step. See https://github.com/actions/runner-images/blob/main/images/windows/Windows2025-VS2026-Readme.md.
- GitHub's current manual workflow documentation states that a `workflow_dispatch` workflow must exist in the default branch to be manually triggerable. See https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow?trk=public_post_comment-text.

One over-strict release check was corrected in the local Controller:
- Before: required both Workflow and Runner script to exist on both default and feature branches.
- After: requires the Workflow file on the default branch, and both Workflow and Runner script on the selected feature branch. The Runner script is checked out from the selected feature SHA and does not need an unnecessary copy on the default branch.
- This is a local-only edit; no commit or push was performed.

Post-edit checks:
- Controller PowerShell AST parse: PASS.
- Runner PowerShell AST parse: PASS.
- Controller default-branch/feature-branch release boundary assertions: PASS.
- Workflow dispatch and Runner wiring static markers: PASS.
- Runner bootstrap and restart contract static markers: PASS.

A stale, unused `Wait-RunnerEndpoint` helper remains in the Controller. It is not called by the active flow; the live endpoint arrives through the authenticated READY callback. It should either be removed in a later cleanup or remain clearly unused. This is not a current execution blocker.

No GitHub workflow dispatch, branch creation, commit, push, merge, secret mutation, NetBird login, ACL/firewall modification, or real transaction was performed.

CP-0566C remains **BLOCKED / NOT RUN**. The remaining path is a separately reviewed minimal release boundary, default-branch workflow availability, creation/publication of the exact feature ref, followed by a two-host NetBird run.


### CP-0566C release manifest prepared (2026-11-05)

A local, non-published release manifest was created at:

`docs/engineering/CP-0566C_RELEASE_MANIFEST_2026-11-05.md`

Manifest SHA-256:
`aeea186932aff768f7c21befe91811307453e268ced251197504873e65d19dd0`

The manifest records the validated mainline-based integration set:
- 105 unique paths under `src/native/pow_bench`.
- 4 additional external fixture files under `simulations/`.
- Controller and Runner scripts plus the same Workflow on the feature branch.
- Workflow file alone on the default branch to make manual dispatch discoverable.

Live GitHub compare confirmed the 4b8cfd candidate commit is 259 commits ahead and 18 behind main. The currently published branch carrying the old candidate base is `feat/qrun-v05-netbird-cross-host-qualification-20261102`; the newer expected branch name `feat/qzxb-usdt-trading-gate-20261104` was absent from origin. Do not merge the divergent history as a shortcut.

The manifest was generated locally. No branch was created, no GitHub file was written, and no publication was performed. The main worktree's status count is now 188 because the manifest itself is an additional untracked local document; the existing code and project changes remain preserved.

CP-0566C remains **BLOCKED / NOT RUN**.

### Mainline-based feature preparation update (2026-11-05)
The security fix PR #134 is merged. The current mainline base for the isolated QRun feature preparation worktree is 8de9812e7d1a49020f1a7fc169c40d4b8a72a144. A 114-file feature overlay was applied with an exact Git status path-set match and zero unexpected paths. On this base, cargo fmt passed; focused QAP1 passed 24/24 and focused QFP6 passed 37/37; Controller/Runner PowerShell AST, Workflow YAML and policy marker checks passed. See CP-0566C_MAINLINE_FEATURE_PREP_2026-11-05.md for the complete evidence and limits. Full all-target testing and actual two-host qualification remain separate open gates.
### Full all-target validation completed (2026-11-05)
The mainline-based feature preparation worktree passed cargo test --all-targets --locked --offline with exit code 0 in 510.33 seconds: 1,268 library tests passed, zero failed, and every binary/integration target completed successfully. Existing compiler warnings concerned unused imports, unused mutability and dead code only. Full evidence is recorded in CP-0566C_MAINLINE_FEATURE_PREP_2026-11-05.md. This is still single-host local evidence; CP-0566C cross-host NetBird remains NOT RUN.