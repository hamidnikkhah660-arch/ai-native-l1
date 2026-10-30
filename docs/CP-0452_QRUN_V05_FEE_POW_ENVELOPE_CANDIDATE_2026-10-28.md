# CP-0452 — QRun v0.5 fee-bound PoW envelope candidate

**Date:** 2026-10-28
**Status:** QFP5 canonical wire codec and tamper-rejection tests pass locally. Mainnet remains not activated.

## Why QFP5 exists

QFB5 commits the fee-block producer and transaction body, while its inner state root describes the post-execution ledger. A PoW header that commits only the inner ledger root is insufficient for a zero-fee block: changing the producer may leave the ledger state unchanged. QFP5 closes that specific gap by placing a domain-separated commitment over the inner state root, canonical QFB5 block ID and canonical payload length in the `PowHeader.state_root` field that the PoW digest actually hashes.

## Candidate wire contract

- Magic `QFP5`, version 1, fixed-width PoW header followed by one canonical QFB5 payload.
- Encoder and decoder bind protocol version, network ID, height, timestamp, parent, target, fee-block state root, complete producer-inclusive QFB5 identity and the outer PoW commitment.
- Strict bounded parsing rejects unknown versions, invalid magic, truncation, trailing bytes, bad canonical payloads, altered producer fields and altered header commitments.
- The producer account is part of the block identity even when the fee pool for that block is zero.

## Local test evidence

- `qfp5_round_trip_binds_producer_and_inner_state_root_to_pow_header`: canonical round-trip plus producer/commitment tamper rejection.
- `qfp5_rejects_bad_version_trailing_bytes_and_wrong_magic`: malformed wire rejection.
- The QFB5 state/runtime tests independently confirm that only same-block fees are paid, total supply remains exactly 10,000,000,000 QZXB, and store replay survives restart.

## Important remaining integration gates

QFP5 is presently a candidate codec. It is **not yet wired into** `PrivateTestnetForkChoice`, the PFS2 durable branch archive, the canonical QRun producer/importer, peer relay, RPC or checkpoint mode/profile binding. Do not allow a QFP5 candidate and legacy PTB2 block to share a canonical branch until execution mode is an immutable, checkpoint-bound profile setting and all replay paths dispatch to the same validated state transition. QFP5's different meaning for the header state-root field must never be silently accepted by the PTB2 decoder.

Before a value-bearing launch, add mode-bound canonical PoW admission and fork choice, durable branch-store replay, checkpoint compatibility, external monotonic anti-rollback, multi-host peer/restart/reorg/fault tests, production difficulty/time/identity settings, and independent security review. Public listeners and Mainnet activation stay disabled until all gates pass.

## Supply decision

Genesis intends to allocate exactly 1,000,000,000,000,000,000 atoms (10,000,000,000 QZXB at 8 decimals) to the configured owner account. Later minting and block subsidy are zero; fees are transfers of existing supply, not new issuance. This candidate commitment does not prove public-chain activation, spendable Mainnet balance, market price or a real trade.