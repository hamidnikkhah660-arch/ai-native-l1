# CP-0513 ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â QRun v0.5 NetBird Cross-Host CI Harness

**Date:** 2026-11-02
**Status:** Cross-host authenticated startup PASS (run 41540604143). Stage C1 signed transaction and QFP5 block-gossip PASS (run 41546003659). Cross-host partition/reorg and independent-operator gates remain unqualified.
**Branch:** `feat/qrun-v05-netbird-cross-host-qualification-20261102`
**Last verified implementation commit before this harness:** `38df9662baa457e4b2a2ca98d9797e87cf0a11fd`

## Objective

Prepare a zero-cost, temporary Windows GitHub-hosted runner as Node B to qualify QRun's authenticated P2P startup sync against the owner's Windows laptop as Node A over the private NetBird overlay. This is a cross-host CI test only. It is not independent-operator, native public-Internet, Mainnet, or public-market qualification.

## Harness components

- `tools/qrun-v05-netbird-prepare-node-a.ps1`: guarded Node A provisioning. Requires the explicit `-ConfirmRestrictiveNetBirdPolicyVerified` switch, verifies the connected NetBird overlay and absence of connected peers from the local CLI, creates a fresh zero-value Public Alpha network identity, provisions network-bound Windows CurrentUser DPAPI keys, creates a signed RTP1 policy, starts the authenticated time authority and Node A, verifies repeated loopback RPC and TCP transaction-ingress probes, verifies the NetBird-only P2P bind marker and live overlay RPC/TX canaries, and exports only public test configuration. Windows TCP-table enumeration was removed from this gate because it returned inconsistent states for the local userspace-overlay environment.
- `tools/qrun-v05-netbird-cross-host-runner.ps1`: installs/verifies NetBird v0.82.0 on the temporary Windows runner when needed, trims and validates `NETBIRD_SETUP_KEY` as a canonical 36-character UUID before use, then consumes `NB_SETUP_KEY` without printing it, waits up to 90 seconds for the overlay P2P and authenticated-time TCP paths after peer enrollment, validates the restricted ingress canaries, builds QRun Node B, provisions a unique DPAPI NPK1 key locally, pins Node A's Noise public key, and performs authenticated startup sync.
- `tools/qrun-v05-netbird-policy-canary.ps1`: temporary no-protocol TCP canaries bound only to Node A's overlay IP on ports 49339 and 49340. These allow the runner to test that remote RPC and transaction-ingress reachability are denied even though the actual QRun listeners are loopback-only. The canaries accept no application payload.
- `tools/qrun-v05-netbird-stop-node-a.ps1`: stops the temporary canary, QRun Node A and time authority, then removes the dedicated temporary key/data directory.
- `.github/workflows/qrun-v05-netbird-cross-host-qualification.yml`: manual `workflow_dispatch` only, guarded to the exact qualification branch, with `contents: read`; checkout credentials are not persisted. It deliberately does not run on push or pull-request events because the job consumes a one-off NetBird Setup Key and opens narrowly scoped private-overlay listeners on Node A.

## Network boundary

Before Node A is started, re-verify in NetBird:

1. Node A is the sole peer in group `qrun-node-a`.
2. The default All-to-All policy is OFF.
3. Only the necessary Node B-to-Node A TCP rules are enabled: P2P TCP 49341 and authenticated time TCP 49550.
4. The temporary runner's one-off Setup Key assigns its peer to `qrun-node-b` and is configured as ephemeral.
5. No rule grants the runner access to RPC 49339, transaction ingress 49340, or other laptop services.

Node A's P2P listener is bound to its NetBird address at TCP 49341. The signed reference-time authority is bound to that same overlay address at TCP 49550. Actual QRun RPC and transaction ingress remain on 127.0.0.1:49339 and 127.0.0.1:49340. The temporary canaries deliberately bind only to the overlay address on 49339 and 49340 so a permissive NetBird ACL is detected rather than mistaken for a safe loopback-only setup.

The Node A script clears the NetBird client-side `block-inbound` override only after the operator supplies the explicit policy-verification switch. Never run that script while the Default all-to-all policy is active or when the two narrow rules are not confirmed.

## GitHub Actions configuration

- Repository Actions variable: `QRUN_CROSS_HOST_CONFIG_JSON`. It contains only public/disposable test network values and the signed RTP1 policy bytes.
- Repository Actions secret: `NETBIRD_SETUP_KEY`. This must be a one-off, ephemeral, short-lived key scoped to `qrun-node-b`. Never place it in source files, workflow YAML, logs, or this report.
- The PR trigger is intentionally limited by the job condition to the exact qualification branch from the same repository. Do not use `pull_request_target`.
- The GitHub-hosted VM is temporary and is decommissioned after the job. The ephemeral NetBird peer should disappear after it remains offline for the configured ephemeral cleanup interval. Rotate/delete the one-off setup key and remove the repository secret after the run.

## PASS criteria for this first cross-host stage

- Runner enrolls as a peer in `qrun-node-b`.
- Runner can reach Node A's overlay TCP 49341 and 49550.
- Runner cannot connect to the overlay TCP canaries on 49339 and 49340.
- Runner reports a NetBird overlay address; no public router port or public NIC listener is opened.
- Node B uses a unique CurrentUser-DPAPI NPK1 key and the exact Node A Noise static public-key pin.
- Authenticated Noise XX startup sync completes against the same Network ID, Genesis epoch, consensus profile and signed RTP1 policy.
- Node B status reports the expected network/profile/tip/state-root tuple and identifies itself as Public Alpha, not Mainnet.
- No private keys or wallet seeds are copied between hosts or emitted in logs.

This first stage does not yet test signed transaction propagation, partition/reconnect, reorg, durable restart, independent receipt/balance queries, or independent administrators. Those are later gates.

## Local code verification before this harness commit

- QRun node binary tests: 34 passed, 0 failed.
- Reorg-focused library tests: 20 passed, 0 failed.
- `cargo check --offline --locked --all-targets`: passed.
- `cargo fmt --all -- --check`: passed.
- Wallet-bound manifest checker `unittest`: 6 passed.
- PowerShell parser: all four cross-host scripts passed syntax parsing.
- YAML parser: workflow parsed successfully.
- `QRUN_MAINNET_RELEASE_APPROVED` remains `false`.

## Current verified network posture (updated 2026-11-03)

- NetBird dashboard authentication was confirmed. The visible peer list shows `heymed` at `100.113.232.54` in `qrun-node-a`. The first hosted Runner is now confirmed registered by its assigned overlay IP and its presence in Node A's `netbird status -d`; the actual `qrun-node-b` group label still needs dashboard confirmation.
- `Default` All-to-All is OFF and was verified again after the change.
- `QRun P2P B-to-A TCP 49341` is ON; `QRun Time B-to-A TCP 49550` is ON; the reverse `QRun P2P TCP 49341` rule (A-to-B) is OFF. No other NetBird policy was changed.
- The repository secret `NETBIRD_SETUP_KEY` was accepted by NetBird once; the literal value was never exposed in chat, source, or logs. Because it was a one-off key, it is consumed for future enrollments. The repository variable `QRUN_CROSS_HOST_CONFIG_JSON` is configured with public-only disposable test values.
- Node A is now started on `heymed` using a newly generated disposable Public Alpha identity (`mainnet=false`). The signed reference-time probe passed, repeated loopback RPC status checks passed, loopback transaction TCP connect passed, the overlay RPC/TX canary reported ready, and the P2P listener reported the expected NetBird address. Only public configuration values were emitted; private keys remain protected by Windows CurrentUser DPAPI on Node A.
- While Node A is active, NetBird's client-side `block-inbound` override is cleared only under the verified restrictive ACL. The guarded stop script and failure path restore `block-inbound=true` and remove the dedicated temporary key/data root.

## First hosted Runner attempt (2026-11-03)

- GitHub Actions run [41531341977](https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/41531341977) successfully checked out the qualification commit and validated the public runner configuration.
- The updated secret was accepted by NetBird: the temporary Runner received a NetBird overlay address and the CLI returned `Connected`. This confirms the secret value was a valid Setup Key; it does not establish a working peer tunnel.
- The Runner failed its first allowed-port probe: Node A TCP 49341 was unreachable. Node A's `netbird status -d` then showed the temporary Runner peer as `Connecting`, with no WireGuard handshake and `Peers count: 0/1 Connected`. No Node B QRun process was built or started, and no authenticated Noise XX sync occurred.
- The failure is at the NetBird peer-transport stage, before QRun P2P protocol execution. NetBird's documented diagnostic distinction is that an unconnected peer/no handshake is a transport issue, not yet an application or QRun issue.
- The first-run canary log showed its 30-minute lifetime had elapsed before the hosted Runner attempt. The Node A preparation script now gives the RPC/TX canary a four-hour lifetime. The canary has been manually restarted and currently reports `CANARY_READY`.
- The Runner script now waits up to 90 seconds for both allowed overlay TCP paths after Management/Signal registration, rather than probing immediately and failing during a possible tunnel-establishment race. The edited PowerShell scripts passed parser validation.
- The successful Runner enrollment consumed the one-off Setup Key. NetBird documents one-off keys as single-use; a fresh one-off ephemeral key scoped to `qrun-node-b` is required for the next hosted attempt. Replace the repository secret with that new key value before retrying.

## Second hosted Runner attempt and ACL diagnosis (2026-11-03)

- GitHub Actions run [41532581169](https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/41532581169) used commit `39ffa01a581b7f109478969abb002a838c13b440`. Checkout and Runner configuration validation passed, and NetBird accepted the replacement one-off Setup Key.
- Node A observed Runner peer `100.113.192.57` with a recent WireGuard handshake and nonzero transfer counters during the run. However, both allowed TCP probes (49341 and 49550) remained unreachable for the full 90-second wait. The workflow failed before building or starting QRun Node B. No Noise XX or authenticated startup sync occurred.
- After the Runner terminated, its ephemeral peer disconnected as expected. The active peer was no longer present in Node A's peer list.
- Node A diagnostic `netbird debug trace in 100.113.192.57 self -p tcp --dport <port> --syn` returned `Peer ACL: Blocked by peer ACL rules (<no id>)` and `Final disposition: DENIED` for TCP 49341, 49550, 49339 and 49340. Denial of 49339/49340 is correct; denial of the two intended allowed ports shows that the active access-control policy did not match this B-to-A flow.
- Most likely items to audit in the NetBird dashboard are Runner peer group membership (source must be `qrun-node-b`), Node A membership (destination must be `qrun-node-a`), policy activation, B-to-A direction, protocol TCP, and ports 49341/49550. Do not enable Default All-to-All or broaden access to all ports as a workaround.
- Local safety cleanup completed after the failed run: Node A and time authority stopped, RPC/TX canary stopped, `block-inbound=true` restored, and the temporary root containing disposable keys and test state deleted. No QRun test listener remains exposed on the overlay.

## Current blockers / non-actions

- Repeat the hosted qualification using a new one-off ephemeral Setup Key and verify the Node A ↔ Runner WireGuard handshake and both allowed TCP paths.
- Only after transport is connected can the test evaluate the RPC/TX ACL canaries, build Node B, and attempt authenticated Noise XX startup sync.
- GitHub Actions variable `QRUN_CROSS_HOST_CONFIG_JSON` is configured with disposable public-only test configuration; repository secret `NETBIRD_SETUP_KEY` is set but its one-off value has already been consumed.
- Draft PR #132 remains open and unmerged. The qualification branch is separate from `main`; no Mainnet activation, public RPC/TX ingress, public router port, QZXB live market, or trading claim is made.


## Correction and updated diagnosis (2026-11-03)

The operator directly confirmed that the NetBird Default All-to-All policy is OFF. A read-only automated dashboard inspection returned a contradictory ON state; no dashboard policy was changed during these inspections. Treat the automated Default-policy reading as unreliable. Do not enable or otherwise modify the Default policy.

The detailed dashboard inspection confirmed:
- Node A peer heymed (100.113.232.54) belongs to qrun-node-a.
- Temporary Node B peer runnervmhao91 (100.113.192.57) belongs to qrun-node-b.
- QRun P2P B-to-A TCP 49341 is enabled, unidirectional from qrun-node-b to qrun-node-a.
- QRun Time B-to-A TCP 49550 is enabled, unidirectional from qrun-node-b to qrun-node-a.
- The reverse P2P policy is disabled. RPC/TX ports 49339 and 49340 have no allow rule.

**Leading root-cause diagnosis:** NetBird official CLI documentation/source says that netbird up on an already-connected peer prints Already connected and exits without applying changed configuration flags. The original Node A preparation script invoked netbird up --block-inbound=false while already connected. Therefore the client-side Block Inbound override may have remained enabled, overriding the two correctly configured B-to-A ACL policies and causing the peer ACL trace to deny all inbound ports. This is strongly supported by the observed Already connected output, but must be verified in a new cross-host test.

The preparation script now performs an explicit netbird down followed by netbird up --block-inbound=false before opening Node A listeners. The preparation failure path and normal stop script likewise force down followed by up --block-inbound, restoring fail-closed behavior. Both scripts passed PowerShell parser validation after the edits.

The last failed run remains unqualified: Node B did not build or start, and no authenticated Noise XX sync or block convergence was demonstrated. Node A, the time authority, and the policy canary are stopped; the temporary test root was deleted; block-inbound=true was restored through an actual reconnect; no QRun test listener remains open on the overlay. A fresh one-off ephemeral Setup Key will be required for the next hosted run.

## Cross-host authenticated startup qualification PASS (2026-11-03)

This section supersedes earlier historical statements that the NetBird peer tunnel or authenticated startup sync remained unqualified.

GitHub Actions run [41540604143](https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/41540604143) completed with **success** on commit `8c23199b3e376fabce04a12f6f1579c4eb5cf088`.

Observed evidence:
- The temporary Windows runner enrolled into NetBird and Node A observed the peer at `100.113.55.84`.
- Node A reported a direct WireGuard `P2P` connection, a recent handshake and nonzero receive/send counters.
- TCP 49341 (QRun P2P) and TCP 49550 (signed reference time) were reachable from Node B.
- Remote TCP 49339 (RPC canary) and 49340 (transaction-ingress canary) remained blocked.
- Node B created its own CurrentUser-DPAPI-protected NPK1 Noise key; the private key was not exported.
- Pinned Noise XX authenticated startup sync completed.
- Node B reported the expected network ID, profile ID, tip and state root. The startup stage ended at height 0; no transaction or block propagation was tested in that run.
- The job completed and the hosted runner disconnected. Node A's QRun services, temporary keys and data were stopped/removed. `block-inbound=true` was restored through an explicit reconnect. The consumed one-off `NETBIRD_SETUP_KEY` was deleted from GitHub Actions Secrets. NetBird Management/Signal remain connected on Node A; no QRun test listener remains open.

## Stage C1: cross-host signed transaction and QFP5 block gossip (implemented; NOT RUN)

The runner script now extends the existing B-to-A-only network path after authenticated startup sync:

1. Build `qrun_v05_public_alpha_process_smoke.exe` on the temporary Windows runner.
2. Run its `identity` command and require its public account/key to match the newly generated Node A Genesis owner identity. This helper uses the documented deterministic `TEST_ONLY_SEED` fixture in source; it is a publicly visible test fixture, not a wallet secret, not a production identity, and must only be used with the fresh disposable Public Alpha network.
3. Submit nonce-1 (recipient account consisting of 32 bytes of `0x78`, amount 1,000 atoms) to Node B's own loopback-only QZTS/1 listener at `127.0.0.1:49340`. No remote RPC or TX endpoint is opened.
4. Require the Node B QZTA/1 acknowledgement to say Accepted, Node B's canonical height to reach 1, the transaction receipt to be `confirmed`, owner nonce to be 1 and the test recipient balance to be 1,000 atoms.
5. Require Node B's log to contain `qrun_pow_local_block_broadcast peer=<Node-A-overlay-IP>:49341`. This marker is written only after the remote peer's encrypted QRA5 acknowledgement passes the expected protocol version, block height, block ID and non-rejection status checks. Thus the test will fail if Node A cannot authenticate, validate or acknowledge the received block.

The extension was parser-checked and its Release test-signer binary built successfully on the authorized Windows workstation. The helper's public identity was verified; the private seed is not printed. **No Stage C1 workflow run has occurred yet**, so transaction/block gossip across the physical hosts is not yet claimed as PASS.

Safety boundary remains unchanged:
- Only the existing qrun-node-b-to-qrun-node-a TCP 49341 and 49550 rules are used.
- No reverse A-to-B policy is enabled.
- RPC 49339 and TX 49340 remain loopback-only and are tested as blocked from Node B.
- No router/WAN port, public RPC or public TX listener is opened.
- The Setup Key used by run 41540604143 was one-off and consumed; `NETBIRD_SETUP_KEY` was subsequently removed. A fresh one-off ephemeral key scoped to `qrun-node-b` must be created and stored in the Actions Secret before Stage C1 can run. Do not reuse a consumed key.
- The Stage C1 result, if it passes, proves one-way B-to-A signed transaction/block propagation and independent Node A block acceptance. It does not prove reverse A-to-B propagation, cross-host partition/reorg, independent operators, public Internet reachability, or Mainnet readiness.

**Current state summary:** Stage B authenticated cross-host startup = PASS. Stage C1 signed transaction and block gossip = implemented, parser/build checks PASS, workflow NOT RUN. The earlier failed-run chronology above remains as historical record only. `QRUN_MAINNET_RELEASE_APPROVED=false`.

## Manual dispatch safeguard (2026-11-03)

After the Stage C1 runner extension was committed, an automatic push-triggered run started while NETBIRD_SETUP_KEY had deliberately been removed. The workflow reached the runner step and failed its missing-secret precondition before NetBird enrollment; no key was consumed and Node A was not modified. The run was cancelled during cleanup. The workflow now uses workflow_dispatch only, restricted to the exact qualification branch, so private listeners and one-off setup keys are never activated by routine branch pushes or PR updates. A new one-off key is required only when the operator explicitly starts the manual run.


## Stage C1 cross-host signed transaction and QFP5 block-gossip PASS (2026-11-03)

This section supersedes the earlier "implemented; NOT RUN" status above. Stage C1 completed successfully on the exact qualification branch using GitHub Actions run [41546003659](https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/41546003659). The run completed with **success** on the manual-only workflow.

Observed evidence from the Runner log and Node A's local RPC/logs:

- The temporary Windows GitHub-hosted Node B enrolled into NetBird as ephemeral peer `runnervmhao91-49-120` at overlay IP `100.113.49.120`. Node A observed a direct WireGuard `P2P` connection with a recent handshake and nonzero transfer counters.
- Node B reached Node A's overlay TCP 49341 (QRun P2P) and 49550 (signed reference time). Remote access to RPC 49339 and transaction ingress 49340 remained blocked.
- Node B created its own CurrentUser-DPAPI-protected NPK1 key. The Runner emitted `NODE_B_PRIVATE_KEY_EXPORTED=NO`; no private Noise key or wallet seed was transferred.
- Pinned Noise XX authenticated startup sync completed against the fresh disposable Public Alpha network.
- The test-only signer public identity matched the fresh Node A Genesis owner identity; the deterministic fixture seed was not exported.
- Node B submitted a signed QZTS/1 transaction and received Accepted. Its canonical receipt became `confirmed`; owner nonce reached 1; recipient balance reached 1,000 atoms.
- Node B received a valid encrypted QRA5 acknowledgement from Node A after Node A validated the incoming height-1 block. Runner markers included `CROSS_HOST_NOISE_QFP5_BLOCK_GOSSIP_NODE_A_ACK=PASS`.
- Node A's own stdout recorded `qrun_pow_local_block_gossip accepted height=1 canonical_height=1`. A subsequent loopback-only RPC query independently confirmed Node A at height 1 with the same canonical tip and state root as Node B.
- Transaction ID: `eaedac9df248b37f40b735deed95696895c4a3e62d34f0a558d07ca1b1308efe`.
- Canonical height: `1`.
- Canonical tip: `0055f5a920c3ee5377e89af7d979f27a1fe6a70ef7aaf478e1a9c215f5035acb`.
- State root: `f71d7ca1ca2bc34d33c95dcfa263769332e206b6837b74375136bf826f01cb81`.
- Node A local RPC reported owner nonce 1, owner balance `999999999999999000` atoms and recipient balance `1000` atoms.
- All Runner markers passed: `NETBIRD_PEER_TUNNEL_READY`, `CROSS_HOST_TEST_SIGNER_MATCHES_GENESIS`, `CROSS_HOST_SIGNED_QZTS_TX_ACCEPTED`, `CROSS_HOST_NODE_B_CANONICAL_RECEIPT`, `CROSS_HOST_NODE_B_RECIPIENT_BALANCE`, `CROSS_HOST_NOISE_QFP5_BLOCK_GOSSIP_NODE_A_ACK`, `NETBIRD_CROSS_HOST_TCP_P2P_49341`, `NETBIRD_CROSS_HOST_AUTH_TIME_49550`, `REMOTE_RPC_49339_BLOCKED`, `REMOTE_TX_49340_BLOCKED`, and `NOISE_XX_PINNED_STARTUP_SYNC`.

Cleanup completed successfully after the run:

- Node B's Runner `finally` path stopped the temporary Node B process, disconnected its NetBird peer, removed its ephemeral DPAPI key and data directory, and cleared the setup-key environment variables.
- The guarded Node A stop script stopped Node A, the reference-time authority and the policy canary; restored NetBird `block-inbound=true` through an explicit reconnect; and removed the entire dedicated temporary root containing Node A keys and test state. The script exited 0 and emitted `NETBIRD_BLOCK_INBOUND_RESTORED=PASS` and `NODE_A_TEMP_KEYS_AND_DATA_REMOVED=PASS`.
- A post-cleanup check found no QRun processes and no listeners on 49339, 49340, 49341 or 49550. Node A's NetBird Management and Signal remain Connected; the temporary peer is disconnected.
- The consumed `NETBIRD_SETUP_KEY` repository secret and temporary `QRUN_CROSS_HOST_CONFIG_JSON` repository variable were both deleted and verified absent.

Scope and limitations:

- **Verified:** one-way cross-host B-to-A signed transaction and block propagation over a direct NetBird P2P tunnel; pinned Noise XX startup authentication; independent Node A block validation/acknowledgement; and canonical height-1 state agreement on both hosts.
- **Not verified by Stage C1:** reverse A-to-B propagation, cross-host partition/reconnect/reorg, multiple independently administered operators, native public-Internet reachability, external users, Mainnet readiness or any live-market/QZXB trading claim.
- Node A and Node B ran the same disposable Public Alpha network with `mainnet=false`. The test-only signer fixture is not a production wallet identity.
- The workstation is back in its restrictive fail-closed inbound posture. No temporary key, QRun listener, test process or test data remains active.
- Draft PR #132 remains open and unmerged; `main` was not changed.

**Updated state:** Stage B authenticated cross-host startup = PASS. Stage C1 cross-host signed transaction and QFP5 block gossip = PASS. Cross-host partition/reorg and independent-operator qualification remain future gates. `QRUN_MAINNET_RELEASE_APPROVED=false`.


## Stage C2 preparation: cross-host partition, reconnect, reorg and durable reopen (2026-11-03)

**Status: HARNESS PREPARED; NOT RUN.** Stage C2 is a separate manually selected job in the existing registered cross-host qualification workflow; it does not alter the already-passed Stage C1 behavior.

Files:
- `.github/workflows/qrun-v05-netbird-cross-host-qualification.yml`: the already registered manual-only workflow now has an explicit `stage` choice (`c1` or `c2`) and mutually exclusive exact-branch-guarded jobs. This keeps GitHub's existing dispatch entry point and avoids adding a separate workflow file that is not registered on the default branch. Both jobs use read-only contents permission, ephemeral Windows runners, and the same disposable public-only config plus one-off `NETBIRD_SETUP_KEY`.
- `tools/qrun-v05-netbird-partition-controller.ps1`: runs on Node A after the guarded prepare script. It waits for all stale peers to disappear, then requires exactly one stable directly connected P2P Node B peer. After a bounded delay it submits Node A's nonce-1 and nonce-2 test transactions locally, confirms height 2 and the expected receipt/balance state, and logs Node A's canonical tip/state root under the dedicated temporary root.
- `tools/qrun-v05-netbird-cross-host-runner.ps1`: gained an opt-in `-StagePartitionReconnectReorg` mode. The original Stage C1 behavior remains the default. The C2 mode prebuilds the Node B release binaries before NetBird enrollment, completes pinned startup sync at Genesis, then adds a temporary Windows Firewall **outbound-only** block rule restricted to Node A's exact overlay IP and TCP 49341. It proves TCP 49341 is blocked while authenticated-time TCP 49550 and NetBird Management/Signal remain reachable.

Planned C2 evidence:
1. Node B submits a signed conflicting nonce-1 transaction while P2P is isolated and must reach canonical height 1 with its own confirmed receipt and recipient balance.
2. Node B's attempted P2P block broadcast must appear as a failed send on stderr; no successful broadcast marker may exist for the isolated competing block.
3. Node A independently builds a nonce-1/nonce-2 branch while Node B's outbound P2P path is blocked. Node A must reach canonical height 2 with owner nonce 2, owner balance `999999999999995998` atoms, and only the two Node A test-recipient balances.
4. The runner removes only its temporary TCP 49341 outbound block, proves P2P and authenticated-time connectivity recovered, then restarts Node B with the same DPAPI key/data and pinned `--sync-on-start true`. Node B must select Node A's higher-work height-2 branch, remove the losing Node B receipt from canonical view, and reproduce the expected owner/recipient balances.
5. Node B is restarted once more without startup sync and must preserve the post-reorg canonical tip, state root, orphan receipt status, nonce and balances from durable storage.

Safety / execution boundary:
- Only Node B's temporary Windows Firewall outbound TCP 49341 rule is added. It is restricted to Node A's private overlay IP and is removed on the normal path and in the runner's `finally` path.
- The NetBird group/ACLs are unchanged. No reverse A-to-B policy, Default All-to-All, public NIC listener, router port, RPC 49339 or transaction ingress 49340 exposure is introduced.
- Node A continues to bind RPC/TX to loopback and P2P/reference-time to its existing private overlay addresses. Port 49550 remains reachable during the P2P partition for authenticated time.
- The Node A preparation/stop scripts retain the existing fail-closed lifecycle: temporary keys/data are disposable, and `block-inbound=true` is restored after the run.
- A **fresh** one-off ephemeral Setup Key and regenerated public runner config are required because C1 cleanup intentionally deleted both the old `NETBIRD_SETUP_KEY` Secret and `QRUN_CROSS_HOST_CONFIG_JSON` Variable.
- Before dispatch, start the Node A partition controller and confirm its `NODE_A_CONTROLLER_READY=PASS` / `NETBIRD_PRETEST_PEERS_CLEAR=PASS` log markers. Dispatch the existing registered workflow on the exact qualification branch with `stage=c2`, only after the controller is waiting for the single Node B peer. After any runner conclusion, execute the guarded Node A stop script and delete the consumed Secret and temporary Variable.
- The runner and controller PowerShell files passed the PowerShell parser; the workflow YAML parsed; `git diff --check` passed. These are harness validations, not a Stage C2 execution result.

**Scope remains explicitly unqualified:** no cross-host partition/reconnect/reorg or durable-reopen PASS is claimed until a real Stage C2 workflow run and matching Node A controller evidence are recorded. `mainnet=false`; `QRUN_MAINNET_RELEASE_APPROVED=false`.
