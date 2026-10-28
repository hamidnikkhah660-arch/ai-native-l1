# CP-0451 — QRun v0.5 fee-only block and durable replay candidate

**Date:** 2026-10-28
**Status:** State-machine codec and local durable replay tests pass. This is not production consensus integration and does not activate Mainnet.

## Candidate changes

- QFB5 is a versioned canonical envelope containing the normal transaction block and the producer account. The producer is included in the block encoding and block ID.
- Execution derives the producer payout from the transaction fees actually verified and collected in that block. The block cannot specify a subsidy or arbitrary payout amount.
- A non-zero pre-existing fee_pool is rejected on this path. All current-block fees are credited to the committed producer and the pool is reset to zero.
- The full-supply invariant is checked before/after execution. Tests assert that total supply remains exactly 1,000,000,000,000,000,000 atoms (10,000,000,000 QZXB).
- The local execution candidate's QRS5 store was upgraded to version 3 with a typed history byte. Versions 1 and 2 remain readable; v1 is restricted to untouched Genesis. Version 3 records whether each canonical history entry is a legacy BLK2 candidate or a QFB5 fee block.
- Reopen replays the stored block history against Genesis and compares the replayed snapshot with the persisted snapshot. The new test verifies fee payout and exact supply survive restart.

## Tests executed locally

- QFB5 canonical round-trip, producer binding, malformed envelope rejection, stale fee-pool rejection, atomic failure, and exact supply conservation.
- QFB5 local runtime block construction, import, persistence, close/reopen, full-history replay, and mode separation.
- Existing QRun local runtime tests for Genesis, Ed25519 transaction verification, corrupt-store rejection, and immutable Genesis identity.

## What this does not solve

The QFB5 codec/transition is **not yet wired into the canonical QRun PoW header, producer, importer, fork choice, network relay, or production RPC**. The currently tested QRun node remains loopback-only with test difficulty and is not a public node. QRS5's local checksum does not provide an external anti-rollback anchor. Durable fee accounting alone does not qualify consensus or make a chain safe for value-bearing public operation.

## Release decision

Keep Mainnet activation and public listeners disabled. Continue by introducing a QRun-specific PoW envelope that commits the producer and the QFB5 block ID, then route block creation, independent admission, fork choice, recovery and cross-node replay through the same canonical transition. Test two or more independent nodes, restart/crash and reorg cases, attack malformed/oversized inputs, add a real external monotonic checkpoint provider, and complete an independent security review before considering activation. The proposed Genesis commitment is a candidate commitment, not evidence that 10B QZXB are already spendable on a launched public network.