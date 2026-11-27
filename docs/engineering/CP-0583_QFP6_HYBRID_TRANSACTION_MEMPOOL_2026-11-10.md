# CP-0583 — Bounded QFP6 hybrid transaction mempool candidate

**Date:** 2026-11-10  
**Parent:** CP-0582 / Q6HA + QAP1 admission qualification  
**Status:** Process-local candidate with unit tests; not wired into the node executable

## Changes

- Adds a distinct QFP6 native-transaction pool. It does not change or raise the 4 KiB common/legacy TXN2 limit.
- Uses the explicit QFP6 8 KiB NativeTransfer codec/transaction-ID limit, allowing the 5,365-byte Q6HA dual-signature envelope.
- Enforces network, expiry, producer, timestamp, transaction-count and byte limits.
- Deterministically sorts candidate transfers by sender, nonce and transaction ID and previews the entire proposed block against QFP6 canonical execution before mutating the pool.
- Exposes ordered entries, deterministic QFB6 block-template construction, inclusion removal and explicit reconciliation after canonical-tip changes.
- Requires the caller to perform PoW and QAP1 durable admission before acknowledging/publishing a block. The mempool itself has no network or disk side effects.

## Tests

- Q6HA signed transfer is admitted although its encoded signature exceeds 4 KiB.
- Mempool output builds a canonical QFB6 NativeTransfer body.
- Ed25519-only signature is rejected for a Q6HA identity without changing the pool.
- Sequential nonces are ordered and retained correctly after the first entry becomes canonical.

## Limits

- Process-local only; no transaction ingress, RPC, P2P gossip, disk persistence, fee replacement or production lifecycle is wired.
- The Q6HA Libcrux verifier remains candidate-only pending independent cryptographic review.
- No public node, Mainnet, issuance, public balance or market is activated.
