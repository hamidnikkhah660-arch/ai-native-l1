# QRun v0.5 NetBird Full-Duplex Qualification

**Status:** design contract only. D1/D2 implementation and live execution are not yet complete. Existing C1/C2 workflow stages remain unchanged.

## Verified current-state constraints

- The cross-host runner discovers Node B's NetBird overlay IPv4 address and provisions a protected Noise static key, but it does not deliver Node B's public metadata to Node A.
- Node B starts with Node A as an outbound peer and pins Node A's Noise public key. The Node A preparation script starts Node A without an outbound peer or peer pin.
- The QRun CLI accepts repeated `--peer` and `--peer-static-public-key-hex` options. With `--sync-on-start true`, it requires at least one peer and exactly one static-key pin per peer.
- Peer configuration is supplied at process startup. Therefore, enrolling Node B for outbound traffic from Node A requires a controlled Node A restart using the same durable data directory and identity/policy files.
- The existing C2 partition rule blocks Node B outbound TCP/49341 to Node A only. It retains authenticated reference-time TCP/49550 and NetBird management/signalling. It is not a bidirectional partition.
- The existing Node A partition controller creates Node A's competing signed transactions locally after observing the temporary NetBird peer. This mechanism can be reused as a transaction origin for a later bidirectional test, but it does not itself prove QRun peer pinning.

## D1 — Full-duplex baseline

### Goal

Prove that two distinct hosts, each running a separate QRun process, have mutually configured and pinned Noise peers and can independently originate and validate blocks in both directions on the same Public Alpha network.

### Bootstrap protocol

1. Node A starts a temporary TCP bootstrap listener bound only to its NetBird overlay address on port 49342. It must not bind to a public interface or expose RPC/transaction ingress.
2. The NetBird policy permits the bootstrap port only from the dedicated, short-lived Node B enrollment group. The setup key must be narrowly scoped, preferably one-time-use, and revoked after qualification.
3. Node A creates a cryptographically random, one-use challenge with a short expiry. Node B connects over the authenticated encrypted NetBird overlay and returns only its overlay IPv4 address and Noise public key, together with the challenge response.
4. The application-level response is authenticated with a dedicated random bootstrap token. Node A stores its token copy protected with Windows DPAPI for the current user; the Actions runner receives the same token only as a GitHub Actions secret. Do not reuse `NETBIRD_SETUP_KEY` as the application token.
5. The authenticated message must bind the protocol version, Network ID, Node B overlay IP, Node B Noise public key, challenge nonce and expiry. Node A must reject stale/replayed challenges, mismatched source IPs, malformed or zero public keys, a mismatched Network ID, duplicate enrollment and any request outside the configured expiry window.
6. After successful validation, Node A closes the bootstrap listener and restarts QRun with its existing durable data directory, owner/network/genesis identity and reference-time policy unchanged, plus `--peer <NodeBOverlayIp>:49341`, `--peer-static-public-key-hex <NodeBNoisePublicKeyHex>` and `--sync-on-start true`.
7. Node A must not run two QRun processes against the same data directory. The restart is complete only after the new process reports authenticated startup sync from the exact Node B endpoint and its loopback RPC reports the expected network/profile identity.
8. The bootstrap token is removed from the local DPAPI file after successful enrollment and the GitHub secret is rotated or deleted after the qualification run. Secrets and Noise private keys must never appear in logs or artifacts.

### D1 execution and acceptance

- Keep C1 and C2 unchanged. Add D1 as a separate manually dispatched workflow stage.
- Start Node B with its existing Node A static-key pin and verify initial authenticated startup sync.
- Complete the one-shot bootstrap, restart Node A with the reverse Node B pin, and verify Node A's authenticated startup sync from Node B.
- Originate at least one signed transaction from Node A and one from Node B. Each receiving host must independently validate the QFP5 block, confirm the corresponding receipt, and update the expected balances.
- Both hosts must end with the same Network ID, profile ID, canonical height, canonical tip and state root. Logs must provide explicit evidence of successful block propagation/acknowledgement in both directions.
- Verify remote RPC TCP/49339 and transaction ingress TCP/49340 remain unreachable. Keep `mainnet=false` throughout.
- Close the bootstrap listener, remove its temporary firewall allowance and clear temporary enrollment material on success and failure.

## D2 — Bidirectional partition, reconnect and reorg

D2 is separate from D1. Once both peers are configured, a one-way B-to-A firewall rule is insufficient to create a partition because A can still send blocks to B. D2 must block QRun TCP/49341 in both directions using narrowly scoped host firewall rules or a verified directional NetBird ACL. It must prove both P2P directions are unavailable while the authenticated reference-time path and NetBird management/signalling remain available. After generating competing branches, heal both directions, verify cumulative-work fork choice, verify the losing receipt is absent from the canonical chain, verify balances/nonces, and verify durable reopen preserves the winning tip and state root.

## Security boundaries and non-goals

- Never transfer or log either host's Noise private key.
- Do not open RPC/transaction ingress beyond loopback; retain TCP/49339 and TCP/49340 as loopback-only.
- Keep P2P on the NetBird overlay at TCP/49341. Keep reference-time TCP/49550 separately scoped to the required peers.
- Do not enable NetBird default all-to-all access. The bootstrap allowance must be temporary and restricted to the specific enrollment group.
- Do not change consensus, PoW difficulty, fork-choice rules, timestamp policy, or Mainnet guards as part of D1.
- D1 proves bidirectional cross-host peer operation and independent block validation; it does not prove independent third-party operators, production readiness or Mainnet readiness.

## Rollback requirements

If bootstrap authentication or Node A's pinned restart fails, close the listener, remove temporary firewall rules, stop any partially started process and restore Node A using the original startup arguments against the same durable data directory. Preserve C1/C2 evidence and do not merge the qualification branch to `main` as part of D1.

## D1 operator runbook (implementation in progress)

The following sequence is required when the D1 code has passed CI and the repository Actions settings are available:

1. On Node A, first prepare the isolated Public Alpha node with the existing qrun-v05-netbird-prepare-node-a.ps1 script. Retain the exact PUBLIC_CONFIG_PATH emitted by that script.
2. In NetBird, verify that the dedicated temporary Node B enrollment group is the only source permitted to reach Node A TCP/49342. Permit the two intended P2P peers on TCP/49341 and the required Node B to Node A reference-time path on TCP/49550. Do not enable default all-to-all. Keep TCP/49339 and TCP/49340 inaccessible remotely.
3. In a separate elevated PowerShell window on Node A, start the D1 controller using the emitted path:

    .\tools\qrun-v05-netbird-node-a-full-duplex-controller.ps1 -PublicConfigPath "<PUBLIC_CONFIG_PATH>" -ConfirmBootstrapAclRestricted -PublishBootstrapSecret

   The controller creates a one-use random token, protects the Node A copy with DPAPI, publishes only the matching GitHub Actions secret, and opens a temporary firewall allowance bound to the Node A overlay address. It waits for authenticated Node B enrollment.
4. Only after the controller reports D1_BOOTSTRAP_LISTENER_READY=PASS, dispatch .github/workflows/qrun-v05-netbird-cross-host-qualification.yml on the qualification branch with stage d1.
5. Keep the Node A controller window open until it reports D1_NODE_A_FULL_DUPLEX_CONTROLLER=PASS. The workflow must independently report Node B received Node A's reciprocal block, with matching network/profile and expected ledger balances.
6. On successful qualification, the controller removes the local DPAPI token, temporary firewall rule and one-shot GitHub secret. If the workflow fails before completion, inspect the controller output and rotate/remove the one-shot secret before retrying.

Before dispatch, the workflow also requires the existing repository variable QRUN_CROSS_HOST_CONFIG_JSON and repository secret NETBIRD_SETUP_KEY. The D1 controller creates only QRUN_PEER_BOOTSTRAP_TOKEN; it does not fabricate or replace the other two settings.

This runbook does not authorize a live run by itself. Do not dispatch D1 until the CI parse/self-tests are green and the restrictive NetBird ACL has been checked in the NetBird control plane.
