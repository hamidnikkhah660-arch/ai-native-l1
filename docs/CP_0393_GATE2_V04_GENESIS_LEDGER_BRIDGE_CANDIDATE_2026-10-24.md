# CP-0393 — v0.4 Genesis-to-Ledger Bridge Candidate

**Date:** 2026-10-24
**Status:** Initial-ledger bridge candidate with focused tests. Gate 2 and Gate 8 remain OPEN; this is not production-runtime integration.

## What changed

Adds `MonetaryLedgerStateV04Candidate::from_genesis_manifest`. It validates the v0.4 manifest, materializes its single initially issued allocation into the existing deterministic `LedgerState::genesis` substrate, clones the eight-bucket accounting counters, validates that live ledger value equals accounting live supply, and proves the computed monetary state root matches the root embedded in the manifest.

To make that comparison meaningful, CP-0392's state root now binds:
- the existing deterministic account-ledger state root,
- the v0.4 policy fingerprint,
- the committed bucket-issuance and burn counters, and
- cumulative miner issuance (zero at Genesis).

The independent Python vector generator was updated to compute the underlying `AIN1-STATE-ROOT-V2` canonical ledger root and then the v0.4 monetary root independently. The shared fixture is regenerated and the Rust tests compare the exact fingerprint, accounting bytes/commitment, ledger-bound Genesis root, manifest bytes, and manifest hash.

## Test evidence

- `monetary_ledger_v04_candidate`: 3 tests passed.
- `monetary_genesis_v04_candidate`: 5 tests passed, including the independent Python golden-vector test.
- The tests prove the initial supply is 1B owner coins, not the old 7B 4/3/3 pre-allocation, and verify network/account domain separation.

## Explicit remaining gaps

This bridge only constructs and validates the initial state. It does not implement signed allocation releases, miner block rewards, normal transaction execution under the new v0.4 counters, snapshots of this state type, PFM5 durable storage, fork-choice/reorg rollback, node startup, peer import, or RPC. The legacy MBK3/MBK4 paths remain unchanged and retain the old economics. Do not select this candidate as production until the complete transition and recovery path is wired and independently reviewed.

Gate 8 remains separate: no independent production CAS service, remote signing boundary, provider-side atomic CAS deployment, or real multi-host rollback qualification was added by this change.
