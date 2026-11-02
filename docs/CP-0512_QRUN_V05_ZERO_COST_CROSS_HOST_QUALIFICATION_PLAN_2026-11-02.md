# CP-0512 — QRun v0.5 Zero-Cost Cross-Host Qualification Plan
Date: 2026-11-02
Status: **Prepared; laptop enrolled in NetBird; second peer NOT RUN. No VPS purchased.**

## Objective
Qualify QRun from the owner's existing Windows laptop against a second, temporary Windows VM without purchasing a VPS or using the old/infected computer. The first target is a real cross-host authenticated P2P test over a private overlay. This is not yet independent-operator or native public-Internet qualification.

## Verified project facts
- Repository hamidnikkhah660-arch/ai-native-l1 is public and its LICENSE is Apache License 2.0.
- GitHub's public-repository runner reference lists standard windows-latest as a new Windows VM and says standard hosted runners are free for public repositories.
- The current QRun v0.5 executable has a Public Alpha startup path, a Windows CurrentUser-DPAPI NPK1 Noise-key path, and loopback-only RPC/transaction defaults.
- The current local branch has uncommitted worktree changes. Preserve them. This plan does not authorize reset, clean, commit, push, merge, or Mainnet activation.
- Existing evidence: actual Public Alpha startup with authenticated reference-time service on Windows loopback; two independent OS processes on one host for partition/reconnect/reorg/restart; and authenticated retained-snapshot sync across a competing reorg.
- Still not evidenced: cross-host QRun P2P, independent administrators, native public-Internet P2P reachability, public NAT/firewall reachability, and an externally operated time authority.

## Primary zero-cost candidate: NetBird Cloud Free + GitHub-hosted Windows VM
NetBird's current Cloud Free plan documentation lists up to 5 users and 100 machines and includes peer-to-peer encrypted connectivity and access controls. The Windows client supports silent installation and unattended registration using a Setup Key. NetBird Setup Keys can be one-off or reusable; ephemeral peers are automatically removed after remaining offline for more than 10 minutes.

GitHub's public standard Windows runner is a new VM and is free for public repositories. A Windows runner is a good fit for the current QRun NPK1 implementation, which uses Windows CurrentUser DPAPI. GitHub-hosted Windows VMs run as administrators with UAC disabled, allowing the job to install the NetBird client. The job VM is decommissioned when the workflow ends.

### Proposed topology
1. Owner's existing Windows laptop remains Node A and initially runs the QRun reference-time authority.
2. A GitHub-hosted windows-latest VM becomes temporary Node B for one manually dispatched workflow.
3. NetBird connects Node A and the temporary runner over a private encrypted overlay. Do not open a router port or publish the P2P listener to the public NIC for this stage.
4. Install the NetBird Windows client on the runner from the official MSI, verify the publisher/hash, and register it using a short-lived one-off ephemeral Setup Key held only in a GitHub Actions secret.
5. Provision Node B's NPK1 key locally inside the temporary Windows VM. The runner's private key remains inside its ephemeral Windows user/machine context and is never copied to the laptop or repository.
6. Exchange only public identity/profile fields, RTP1 policy bytes, authority public key, and Noise public-key pins needed for the disposable zero-value test.

### Network policy
- Use separate NetBird groups for Node A and the ephemeral CI peer.
- Allow CI-to-Node-A only to the QRun P2P TCP port (49341) and, if needed, the reference-time TCP authority port (49550).
- Keep QRun RPC (49339) and transaction ingress (49340) bound to loopback and unreachable from the CI peer.
- Bind QRun P2P to the specific NetBird interface address where practical; otherwise use a host firewall rule restricted to NetBird's assigned source range and verify the effective rule. Do not bind unrestricted public interfaces for this overlay test.
- Use manual workflow_dispatch only for this test; do not run privileged networking setup on untrusted pull-request workflows. Keep the Setup Key in encrypted GitHub Actions secrets and never echo it.
- Create a one-off ephemeral Setup Key with a short expiry and a restricted peer group. Revoke it after the first test; if another run is needed, create a fresh key.

## Test stages and pass criteria
### Stage A — Safe overlay preflight
- Confirm laptop NetBird connection and record its assigned private overlay address locally.
- Start no QRun listener until the access-control policy and Windows Firewall scope have been reviewed.
- From the ephemeral Windows runner, prove a TCP connection to the laptop's P2P endpoint and (if necessary) the reference-time authority endpoint.
- Confirm the runner cannot connect to RPC or transaction ingress.
- Capture NetBird direct/relay path information; both are overlay connectivity, not native public-Internet reachability.

### Stage B — Authenticated QRun cross-host session
- Run Node B from a disposable workspace with a fresh DPAPI NPK1 key.
- Use the exact same Network ID, Genesis epoch, calibrated consensus profile and signed RTP1 policy bytes on both nodes, with separate RTS1 high-water files and data directories.
- Node B pins Node A's Noise static public key. Wrong key, wrong Network ID or wrong profile must fail closed.
- Run bounded authenticated startup sync and/or submit a harmless zero-value test block. Verify independent block validation and matching canonical height, tip and state root.
- Capture non-secret output only. Destroy all temporary runner files and keys when the job completes.

### Stage C — Cross-host recovery
- If Stage B is green, extend the harness to perform signed zero-value transaction propagation, intentional partition/reconnect, a competing branch and reorg, then durable restart.
- Compare canonical tip, state root, cumulative work, owner nonce, supply, balances, and canonical/orphan receipt status.
- A temporary GitHub VM is a separately provisioned host, not an independent operator. Report this result as cross-host CI qualification, not independent-operator qualification.

### Stage D — Native public-Internet qualification
- This is a separate release gate. NetBird is a private overlay and does not prove direct public P2P reachability, router/NAT traversal, public seed availability, or permissionless peer discovery.
- For that gate, obtain at least one genuinely separate volunteer operator with an independently administered machine and a natively reachable P2P endpoint, or a volunteer-operated reachable seed node.
- Verify the actual non-overlay remote source address, Noise identity pinning, same network/profile, signed test transactions, partition/reorg/restart, and independent receipt/balance reads.
- If the owner's ISP uses CGNAT, the laptop may not be able to host a native inbound seed. Do not buy anything; qualify outbound peer behavior against a volunteer's reachable seed first.

## Tailscale alternative
Tailscale's Personal free plan is documented for non-commercial use, so do not assume it applies to QRun's eventual commercial use. Tailscale separately documents a Community on GitHub plan for GitHub organizations using OSI-licensed open-source projects and requires GitHub authentication plus contacting Tailscale Support. QRun's public Apache-2.0 repository may be relevant, but it currently belongs to a personal GitHub account, not an organization. Do not transfer the repository or create an organization until Tailscale Support confirms eligibility.

## Why Windows runner instead of Linux
The current QRun NPK1 protection implementation uses Windows CurrentUser DPAPI and its non-Windows path deliberately returns DpapiUnavailable. Therefore a Windows hosted runner can test the current key-custody code without prematurely introducing a new cross-platform private-key format. A Linux operator path still needs a separately designed and reviewed key-custody solution if Linux is part of the intended release matrix.

## Mainnet/public-release separation
This plan does not close the technical Mainnet gates already recorded in CP-0490:
1. Freeze and reproducibly validate the production consensus/difficulty/retarget policy.
2. Integrate full-history validation/recovery and safe repeated checkpoint rollover/rebase.
3. Complete real multi-host restart/reorg/partition/transaction-relay and independently queried receipt/balance evidence.
4. Verify native external Mainnet P2P reachability, authenticated bootstrap and monitored recovery.

The public-alpha candidate can be documented and opened for carefully labeled zero-value operator testing as evidence grows. It must not be described as Mainnet, a value-bearing network, or an available QZXB trading market. A real QZXB market/liquidity path is separate from technical P2P publication.

## Local Windows preflight — 2026-11-02
The connected laptop received a read-only baseline inspection followed by installation of the official NetBird Windows MSI. The cross-host test remains NOT RUN.

- Host: Windows 11 Enterprise, build 26300; current remote process token was not elevated.
- Baseline free space on C: approximately 54.92 GiB.
- Existing OpenVPN and Cisco AnyConnect-related services were already running. The TAP virtual adapter was active and had a low interface metric; the Wi-Fi interface was also connected. These services and adapter settings were left untouched.
- GitHub official latest stable release at inspection: NetBird v0.82.0.
- MSI: netbird_installer_0.82.0_windows_amd64.msi, 23,789,568 bytes.
- SHA-256: 8155544c557676069c49d43ccf2c62a5ccb2fefec9d92ec58fa6920db8bc43e9; exact match with GitHub Release asset digest.
- Authenticode: Valid; signer NetBird GmbH.
- Windows Installer event 11707: installation completed successfully, status 0.
- Installed CLI reports version 0.82.0; NetBird service is Running / Automatic.
- No QRun process, repository file, NPK1/DPAPI key, wallet key, Genesis secret, RTP1 policy-admin key, or reference-time Authority private key was sent to NetBird.
- No P2P port, router port-forward, or public listener was opened.

## NetBird Cloud enrollment — 2026-11-02
Status: **Laptop connected; peer onboarding paused pending restrictive access-policy setup.**

- The user completed browser-based NetBird SSO successfully.
- The separate CLI login command exited 0. The first status command still showed NeedsLogin because the tunnel had not yet been brought up; NetBird's CLI documentation distinguishes authentication (login) from starting the connection (up).
- Ran netbird up --block-inbound; command returned Connected, exit code 0.
- netbird status reports Management Connected, Signal Connected, NetBird client and daemon both v0.82.0, and 0 connected peers.
- WireGuard interface wt0 is Up. The private overlay address is intentionally omitted from this report.
- Existing OpenVPN and Cisco AnyConnect-related services remain Running; default-route interface set and metrics remain as baseline.
- NetBird documents block-inbound as a client-side override that drops every inbound peer connection regardless of server-side policies. This was applied via the successful command.
- NetBird Cloud creates a permissive All-to-All Default policy. No second peer may be enrolled until this policy is removed and restrictive policies are created.
- Before the next stage, create groups qrun-node-a (owner laptop) and qrun-node-b (temporary CI runner); assign the laptop to the first group and configure a narrow bidirectional TCP 49341 policy for QRun P2P, plus a unidirectional TCP 49550 policy from qrun-node-b to qrun-node-a for the reference-time authority. Save and verify both policies and group assignments before removing the All-to-All Default policy.
- Only after that policy is verified may the laptop's block-inbound override be disabled to accept explicitly allowed P2P/time traffic. RPC 49339 and transaction ingress 49340 remain loopback-only.
- No second peer, Setup Key, GitHub Actions secret, QRun P2P listener, or public port has been created or enabled.

## Explicit non-actions
- No VPS purchase or cryptocurrency payment.
- No use of the old/infected computer.
- No router port-forward, public RPC, or public transaction ingress.
- No NetBird Setup Key, OAuth client, GitHub Actions secret, or repository setting created.
- No Mainnet gate change; QRUN_MAINNET_RELEASE_APPROVED remains false.
- No commit, push, PR, merge, reset, or clean.
