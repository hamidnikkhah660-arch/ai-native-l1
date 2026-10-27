# CP-0434 — Explicit authenticated public-candidate P2P binding

**Date:** 2026-10-27

**Status:** Implemented; parser suite and same-host Windows Release integration passed. This is not a deployed public network, permissionless peer discovery, production monetary runtime, or Mainnet approval.

## Explicit activation boundary

The QZBE v0.4 diagnostic peer node can bind its P2P listener to a non-loopback socket only when both flags are explicitly present:

- --test-easy-pow
- --public-testnet-p2p

With that combination, it may bind a non-loopback peer-listen address and connect to concrete non-loopback peer IPs. Outbound peer targets must have a nonzero port and cannot use unspecified or multicast IPs. Each static outbound peer remains paired by order with the configured Noise static public-key pin; inbound Noise connections must authenticate to a key in the configured trust set.

The accepted peer stream now has bounded 3-second read and write timeouts around Noise handling, so an unauthenticated socket cannot hold the single-threaded peer loop indefinitely during a stalled handshake.

The public-candidate switch does not change the transaction-ingress or read-only RPC exposure rules: --tx-listen and --rpc-listen still require loopback addresses, and both handlers reject non-loopback clients. Startup/shutdown telemetry explicitly emits network_surface=explicit_testnet_public_p2p_noise_pinned, tx_rpc_loopback_only=true, mainnet=false and public_launch_approved=false.

This is intentionally a permissioned, static-key testnet transport mode. It is not Bitcoin-like permissionless peer discovery or a production networking policy, and --test-easy-pow changes the consensus profile; its store/profile must not be reused for production.

## Validation evidence

- QZBE focused Rust suite: 15/15 tests passed, including explicit public-mode gating, non-loopback peer validation, and rejection of public transaction/RPC listeners.
- Windows Release scenario simulations/cp0414_qzbe_authenticated_transaction_loopback.ps1 passed on the same development host:
  - CP-0414 PUBLIC_BIND_GUARD_PASS — non-loopback peer bind without both explicit flags is rejected.
  - CP-0434 PUBLIC_CANDIDATE_P2P_NOISE_PINNED_BIND_PASS — one candidate peer bound 0.0.0.0 only with the explicit test-PoW/public-P2P flags and authenticated the pinned peer.
  - CP-0433 NATIVE_WALLET_SIGN_AND_QZTS_SUBMIT_PASS — the DPAPI wallet signed and submitted using QZTS/1; ACK TXID matched.
  - CP-0414 READ_ONLY_RPC_CANONICAL_TXID_RECEIPT_PASS — the received transfer appeared at height 1 with two observed confirmations at height 2.
  - CP-0432 NATIVE_WALLET_READ_ONLY_RPC_PASS — wallet-side RPC reported height 2, recipient balance 2,500 atoms, and mainnet=false.
  - CP-0414 QZBE_AUTHENTICATED_TXN_TWO_NODE_PASS — invalid signature rejected atomically, peer state converged and persisted replay matched.

This validates that the listener can bind in explicit candidate P2P mode while RPC and transaction ingress remain loopback-only. Because both processes ran on one machine and reached each other through loopback, it does not prove real Internet reachability or independent-host behavior.

## Required before any public Mainnet claim

Three independently administered hosts and their actual network paths must still be tested; static Noise trust pins must be provisioned and rotated operationally; rate limits/peer-abuse policy and public node observability need review; the canonical monetary Genesis, producer/importer and state-transition integration must be activated only through the approved profile; Gate 8 external CAS/anti-rollback must be independently deployed and attacked; and fresh-node sync/recovery, wallet recovery, explorer, independent security audit and launch/legal review must pass. No USDT pair or real liquidity is created here.
