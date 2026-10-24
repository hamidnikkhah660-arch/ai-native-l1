# CP-0394 — Gate 2 v0.4 ledger snapshot candidate — 2026-10-24

## Status

**Candidate only; not a Gate 2 closure.** This adds a versioned snapshot envelope around the v0.4 Genesis-to-ledger candidate. It does not connect the format to the live node, the MBK3/MBK4 importer, block production, fork choice, a durable fork store, or external anti-rollback.

## QZL4 snapshot wire contract

All integer fields use unsigned big-endian encoding. The format is:

1. QZL4 magic (4 bytes).
2. Format version 1 (u16).
3. Expected network ID (32 bytes; must be nonzero and match the caller's configured network).
4. Ledger snapshot length (u32), then exactly that many bytes from the existing canonical LedgerState snapshot encoder.
5. Allocation accounting record (QZAL, accounting version 1; fixed-width counters for all eight buckets plus cumulative burned atoms).
6. Cumulative mined issuance (u128).
7. v0.4 monetary state root (32 bytes).
8. SHA-256 checksum over the preceding bytes under the domain QUANTUMZXB-MONETARY-SNAPSHOT-CHECK-V04\0.

The envelope has a fixed overhead of 272 bytes in addition to the embedded ledger snapshot. The maximum encoded size is the current ledger snapshot limit plus this overhead.

## Restore-time checks

Decoding rejects oversize/truncated envelopes, checksum errors, wrong magic or version, zero/mismatched network IDs, malformed declared lengths, invalid embedded ledger snapshots, invalid accounting bytes, bucket/supply invariant violations, miner-counter mismatch, account-total/live-supply mismatch, and a recomputed monetary root that differs from the committed root. Tests cover successful byte-for-byte round-trip, checksum corruption, wrong/zero network, truncation, unsupported version, and inconsistent length.

The outer checksum detects byte changes but is not a signature, authenticated storage, freshness proof, or anti-rollback control. A valid older snapshot can still be replayed unless a separately operated external anchor rejects rollback.

## Local validation recorded for this candidate

- cargo fmt --all: passed.
- cargo test --locked --offline --lib monetary_ledger_v04_candidate -- --nocapture: 5 passed, 0 failed.
- cargo check --all-targets --locked --offline: passed (pre-existing unused/dead-code warnings remain).

These checks are local to this worktree. Current remote CI for the pushed commit must be checked independently; no CI result is inferred from these local checks.

## Remaining Gate 2 work

This format still needs an independent golden-vector implementation, runtime importer/exporter integration under an explicitly versioned profile, block-by-block issuance and transaction authorization, deterministic replay across implementations, fork choice/reorganization tests, a durable store integration, restart/crash/power-loss testing, and independent security review. Legacy MBK3/MBK4 policy remains separate and has not been silently migrated.

## Gate 8 boundary

QZL4 does not implement Gate 8. There is no claim here that an independently operated, provider-side atomic compare-and-swap service is live or that rollback protection survives VM/disk restoration and multi-host races. Gate 8 remains open.
