# CP-0513 — QRun v0.5 NetBird Cross-Host CI Harness

**Date:** 2026-11-02
**Status:** Harness prepared on the isolated qualification branch; NOT RUN.
**Branch:** `feat/qrun-v05-netbird-cross-host-qualification-20261102`
**Last verified implementation commit before this harness:** `38df9662baa457e4b2a2ca98d9797e87cf0a11fd`

## Objective

Prepare a zero-cost, temporary Windows GitHub-hosted runner as Node B to qualify QRun's authenticated P2P startup sync against the owner's Windows laptop as Node A over the private NetBird overlay. This is a cross-host CI test only. It is not independent-operator, native public-Internet, Mainnet, or public-market qualification.

## Harness components

- `tools/qrun-v05-netbird-prepare-node-a.ps1`: guarded Node A provisioning. Requires the explicit `-ConfirmRestrictiveNetBirdPolicyVerified` switch, verifies the connected NetBird overlay and absence of existing peers, creates a fresh zero-value Public Alpha network identity, provisions network-bound Windows CurrentUser DPAPI keys, creates a signed RTP1 policy, starts the authenticated time authority and Node A, and exports only public test configuration.
- `tools/qrun-v05-netbird-cross-host-runner.ps1`: installs/verifies NetBird v0.82.0 on the temporary Windows runner when needed, consumes `NB_SETUP_KEY` without printing it, validates the overlay path, builds QRun Node B, provisions a unique DPAPI NPK1 key locally, pins Node A's Noise public key, and performs authenticated startup sync.
- `tools/qrun-v05-netbird-policy-canary.ps1`: temporary no-protocol TCP canaries bound only to Node A's overlay IP on ports 49339 and 49340. These allow the runner to test that remote RPC and transaction-ingress reachability are denied even though the actual QRun listeners are loopback-only. The canaries accept no application payload.
- `tools/qrun-v05-netbird-stop-node-a.ps1`: stops the temporary canary, QRun Node A and time authority, then removes the dedicated temporary key/data directory.
- `.github/workflows/qrun-v05-netbird-cross-host-qualification.yml`: restricted Windows hosted runner job. It uses `pull_request` activity for the exact same-repository qualification branch and has `contents: read`; checkout credentials are not persisted. `workflow_dispatch` is also declared for later use once the workflow exists on the default branch.

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

## Current verified network posture (2026-11-02)

- Authenticated NetBird dashboard access was confirmed; `heymed` is the only current peer and belongs to `qrun-node-a` (`100.113.232.54`).
- `qrun-node-b` exists and currently has zero peers.
- The catch-all `Default` All-to-All policy is OFF.
- The only enabled QRun inbound paths to Node A are `qrun-node-b` → `qrun-node-a` TCP 49341 (P2P) and TCP 49550 (authenticated reference time).
- The reverse A-to-B P2P policy is OFF. The Node A machine remains fail-closed with NetBird `block-inbound` enabled until the guarded preparation script is explicitly run.

## Current blockers / non-actions

- No second peer, Setup Key, Actions variable, Actions secret, PR, or cross-host run has been created.
- No public P2P, RPC, transaction-ingress or router port has been opened.
- No Mainnet activation, QZXB market, or trading claim is made.
