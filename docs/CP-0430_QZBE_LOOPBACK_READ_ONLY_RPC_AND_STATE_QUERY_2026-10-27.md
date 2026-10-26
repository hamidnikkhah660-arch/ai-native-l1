# CP-0430 — QZBE loopback read-only RPC and canonical state queries

**Date:** 2026-10-27

**Status:** Implemented and locally integration-tested as an isolated QZBE candidate capability. This is not public RPC, production runtime activation, or Mainnet approval.

## Scope

The QZBE v0.4 candidate node accepts an optional --rpc-listen 127.0.0.1:PORT. The option is parsed fail-closed: non-loopback addresses are rejected, and the RPC socket may not collide with the peer or transaction-ingress sockets. It remains separate from the authenticated Noise peer listener and the QZTS/1 transaction-ingress listener.

The bounded HTTP handler exposes only:

- GET /v1/status: network, Genesis and consensus-profile identifiers; canonical height, tip, state root and generation; explicit mainnet=false and read_only=true.
- GET /v1/balance/{64-hex-account-id}: the same canonical state identity plus the requested account's balance in atoms.

Requests are bounded to 2,048 bytes, accept GET only, reject malformed paths, request bodies and transfer-encoding, and are handled only for loopback clients. The listener is polled in the normal observer loop and during PoW attempts so that a long-running mining candidate does not make these read-only queries unavailable. No mutating RPC method is present.

## Validation evidence

The QZBE binary's focused Rust suite passed 12/12 tests, including bounded status/balance parsing, malformed request rejection, oversize rejection, loopback-only RPC binding, and port-conflict guards.

The repeatable Windows Release integration runner simulations/cp0414_qzbe_authenticated_transaction_loopback.ps1 passed with these markers:

- CP-0414 PUBLIC_BIND_GUARD_PASS
- CP-0414 READ_ONLY_RPC_GENESIS_PASS
- CP-0414 READ_ONLY_RPC_SETTLED_STATE_PASS height=2 balance_atoms=2500
- CP-0414 QZBE_AUTHENTICATED_TXN_TWO_NODE_PASS ... invalid_signature=atomically_rejected replay=matched public_bind=denied

The integration test queried the receiver before transfer inclusion (height 0 and recipient balance 0), then after the two-node candidate chain reached height 2. The balance response and status response reported the same tip and state root, with the recipient balance at 2,500 atoms. The transfer and balances exist only in disposable candidate state.

## Explicit limitations

This is a loopback diagnostic RPC for the QZBE candidate, not a public endpoint and not the canonical production node. Its response does not provide a transaction receipt or proof of finality by transaction ID. It must not be exposed through a firewall or reverse proxy.

The canonical monetary Genesis, block producer/importer and state transitions are not yet activated as the production runtime. Gate 8 external CAS/anti-rollback still requires a durable provider in an independently administered trust domain and multi-host race, rollback, outage and recovery testing. Three independently hosted nodes, fresh-node synchronization, wallet confirmation/receipt support, explorer, independent security review and genuine two-sided market liquidity remain release gates. No Mainnet balance, QZXB/USDT pair, price or liquidity is created by this change.
