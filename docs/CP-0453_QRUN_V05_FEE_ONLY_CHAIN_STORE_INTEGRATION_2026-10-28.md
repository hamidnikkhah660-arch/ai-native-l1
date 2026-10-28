# CP-0453 — QRun v0.5 fee-only QFP5 chain/store integration candidate

**Date:** 2026-10-28
**Status:** Local mode-locked PoW/fork-choice/PFS2 candidate tests pass, including the exact 10B candidate Genesis across restart. Public Mainnet remains not activated.

## Integration now covered

- QFP5 decoding shares the bounded candidate-envelope dispatch while preserving PTB2 as a separate legacy format. `CandidateNetworkBlock` preserves the typed QFB5 payload rather than silently flattening it into a legacy block.
- The QRun chain driver checks protocol/network/height/timestamp/parent/previous-consensus hash, expected difficulty target, PoW digest and QFP5's producer-inclusive payload commitment before applying QFB5.
- QRun fee-only execution mode is locked on first accepted block; the driver rejects legacy PTB2 and monetary-format blocks on this mode, and rejects QFP5 on a legacy chain.
- The QRun fork-choice constructor requires protocol version 5 and rejects any Genesis whose network ID, state root or computed commitment differs from the pinned 10B Genesis profile. A small fixture Genesis cannot be relabelled as QRun.
- Fork choice has an explicit QRun Genesis-rooted constructor and a deterministic historical QFP5 replay path. QRun profile replay validates the same state transitions and full-supply invariant as live admission.
- PFS2 has a distinct domain-separated QRun fee-only profile fingerprint and Genesis-rooted open APIs. It rejects cross-profile branch payloads, rebuilds the fork graph through QFP5 historical replay, and accepts an external manifest anchor on restart. Checkpoint-suffix import is intentionally not enabled for QRun yet.
- The new full-supply store test uses the fixed candidate QRun Genesis, confirms the exact owner account and total supply of 1,000,000,000,000,000,000 atoms, persists a QFP5 block, reopens using the independently retained manifest anchor, and verifies the 10B owner balance and total supply still match.

## Tests executed locally

- QFP5 PoW commitment changes when the producer changes, including zero-fee blocks; the wire codec round-trips and rejects malformed envelopes.
- QRun mode-locked chain driver accepts its QFP5 path and atomically rejects attempts to mix legacy blocks.
- QRun fork choice accepts and deterministically replays QFP5, while rejecting cross-mode input.
- Genesis-rooted QRun PFS2 store persists and restarts under its distinct profile, accepts the external manifest anchor, and rejects a legacy-store reopen or QFP5 input on a legacy store.
- Exact 10B candidate Genesis survives a QFP5-store restart with unchanged owner allocation and total value.

## Still not a public production network

This work is a candidate integration layer, not activation. The QRun-specific path is not yet the public node's complete mining/transaction relay/P2P/RPC startup path, and an independently operated multi-host QFP5 network has not been demonstrated. The currently runnable `qrun_v05_pow_local_node` remains loopback-only and uses disposable test difficulty. Its settings must not be made public by a flag change.

PFS2 anchored reopen only compares a supplied expected manifest commitment. A production external monotonic checkpoint provider, automatic verified checkpoint rollover, full-history/archive migration policy, and QFP5-compatible checkpoint/snapshot replay remain open. Consensus parameters still require a frozen production profile; the local candidate cannot stand in for difficulty calibration or an independent security review.

## Release decision

Keep public listeners and Mainnet activation disabled. Next gates: wire the QRun mode into a purpose-built node startup/configuration, actual peer relay and mining producer; carry the mode binding through every RPC, archive, checkpoint and restart path; implement independent monotonic anti-rollback and verified checkpoint rollover; test multi-host block/transaction propagation, churn, crash/power-loss and reorg/fork adversarial cases; complete independent security review and owner-side genesis/identity verification.

The 10B balance remains a deterministic candidate Genesis state, not proof of spendable public Mainnet coins. No market price or actual trade is asserted.