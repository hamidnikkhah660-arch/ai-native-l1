# CP-0510 — QRun v0.5 Two-Physical-Host Operator Qualification Runbook
**Status:** Independent-operator/LAN runbook remains NOT RUN. A temporary GitHub-hosted Windows runner has passed private-overlay startup qualification; cross-host signed transaction/block propagation is prepared but not yet run.
**Date:** 2026-11-02
**Scope:** Public Alpha/test-only, private LAN first; no Mainnet or public QZXB trading.

## Objective
Qualify two QRun v0.5 node processes on different physical computers, administered independently, using real TCP over a LAN (then separately over independently routed networks). Prove authenticated peer identity, isolation during partition, branch convergence, transaction receipt correction, and durable restart.

## Preconditions
1. Two physical computers with independent storage and node processes. For the independent-operator stage, the computers should be administered by different operators; two PCs controlled by one person are only a two-host test.
2. Both computers use the same explicitly generated Public Alpha test Network ID, Genesis identity/time, calibrated QRun v0.5 consensus profile, and exact same signed RTP1 reference-time policy bytes/admin public key.
3. A reachable authenticated reference-time authority endpoint. Its service key remains on the authority machine; both nodes receive only its configured numeric endpoint and the exact signed policy. The time oracle is not a Byzantine consensus clock.
4. Each QRun node gets its own network-bound NPK1 Noise static private key, unique node data directory, unique reference-time high-water state file, and unique P2P listen port. Private Noise keys must not be copied between operators.
5. Operators exchange only the Noise static public-key pins out of band and verify the fingerprints verbally or through another trusted channel.
6. Use a temporary Public Alpha test wallet/test signer only. Never reuse smoke keys or temporary files for Mainnet.

## Listener and firewall policy
- Bind `--block-listen` to the node computer's private LAN interface IP and a fixed P2P TCP port. Avoid binding RPC/transaction endpoints to non-loopback addresses.
- Keep `--rpc-listen` and `--tx-listen` on `127.0.0.1` only. They are local administrative/test interfaces and must not be exposed through Windows Firewall, router port forwarding, or a reverse proxy.
- Permit inbound TCP only on the chosen P2P port, ideally restricted to the other test computer's private LAN IP during the LAN phase.
- Permit outbound TCP to the configured peer P2P address and authenticated time-authority address.
- Do not create router port-forwarding rules for RPC or transaction ingress. WAN/NAT qualification is a later, separately authorized step.
- Use `--public-alpha`; never use `--mainnet`. Both nodes configure the peer address plus the exact peer static public-key pin and use `--sync-on-start true` for recovery tests.

## Test sequence
1. Record both hosts' OS/build versions, interface/route used, listener addresses, firewall rule scope, Genesis ID, profile ID, policy digest, and Noise public-key fingerprints. Do not record private keys.
2. Start the reference-time authority and verify both hosts can obtain valid authenticated samples under the same policy.
3. Start Node A and Node B with independent data/state directories, unique Noise keypairs, mutually pinned peer keys, the same test Genesis/profile, and reachable P2P endpoints.
4. Verify Noise XX authentication in both directions and exchange a harmless test block/transaction. Record peer authentication outcomes, heights, tips, and state roots.
5. Close the firewall rule or otherwise cut the P2P path in both directions. Submit distinct conflicting nonce-1 test transfers on A and B. Verify each node's canonical receipt is local-only and the tips diverge.
6. Extend one branch with nonce 2 while the other remains partitioned. Record heights, tips, receipts and balances on both machines.
7. Restore the P2P path. Restart the lagging node with authenticated `--sync-on-start true`. Verify it receives the peer's canonical path, independently validates imported blocks, selects the greater cumulative-work branch, drops losing-branch receipts, and rebuilds canonical transaction locations/balances.
8. Repeat with the peer advancing its canonical tip during multi-page sync. Verify the original pinned snapshot is served from retained fork history, and a subsequent sync catches the newer tip.
9. Restart the recovering node again without sync. Verify exact canonical tip, state root, receipts, nonce and balances survive durable reopen.
10. Negative tests: wrong Noise static-key pin; mismatched network/profile/Genesis/time policy; unreachable peer; blocked port; corrupted or missing retained snapshot; checkpoint-base mismatch. Each must fail closed without RPC/transaction exposure or silent fallback.
11. Repeat a separate test over two independently administered routed networks only after the LAN stage is green. Record NAT/firewall details and actual remote source addresses. Do not conflate LAN qualification with Internet reachability.

## Evidence required for PASS
- Two separate physical host identities and independent node process IDs.
- Mutually verified Noise static public-key fingerprints; no private keys in logs.
- Same Network/Genesis/profile and signed time policy digest.
- P2P connection evidence with actual non-loopback remote addresses.
- Partition evidence in both directions and distinct canonical tips while isolated.
- Reconnect convergence with exact matching canonical tip/state root/cumulative-work decision.
- Correct canonical and orphaned receipt statuses, balances, supply and owner nonce.
- Durable restart results without relying on peer availability.
- RPC/transaction listeners remain loopback-only, confirmed by listener inspection and firewall scope.
- Complete logs, test scripts/commit references, and signed operator run notes.

## Current readiness
The code has same-host two-process partition/reconnect/reorg/restart evidence and authenticated retained-snapshot pagination. It does **not** yet have two-physical-host or independent-administrator evidence. Only one Desktop Commander device (`heymed`) was online in this preparation session. Therefore this runbook is prepared but the physical-host test is **NOT RUN**.

## Stop conditions
Stop immediately on Noise pin mismatch, Genesis/profile/time-policy mismatch, unexpected RPC/transaction exposure, a balance/supply invariant failure, receipt inconsistency after reorg, failure to preserve the canonical tip on durable reopen, or any attempt to enable Mainnet. Keep `QRUN_MAINNET_RELEASE_APPROVED=false`.

## 2026-11-03 distinction from the CI qualification

The temporary GitHub-hosted Windows runner is a second physical virtual machine and completed authenticated NetBird/Noise XX startup qualification against Node A. It is not an independently administered volunteer operator and does not complete this runbook.

The CI runner's signed transaction/QFP5 block-gossip extension is implemented but not yet executed. This operator runbook still requires a separately administered second computer for the LAN phase, followed by the separately controlled routed-network phase. Do not describe temporary CI execution as independent-operator evidence. QRUN_MAINNET_RELEASE_APPROVED=false.