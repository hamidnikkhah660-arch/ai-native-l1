# CP-0378 — Branch-Derived Retarget Observation and Atomic Admission

Date: 2026-10-22
Project: QuantumZXB / AI-Native L1
Implementation base: `bdae1bd64e2ce0281e8b24429761830863102429`
Integrated main baseline reviewed: `4e800b63e57757bb8523317d62d6a904f69c2c95`
Scope: candidate chain-driver consensus validation; no public-network activation or frozen Mainnet profile.

## Changes in the candidate path

- `TargetHistory` records each accepted header timestamp by height along with target history. Fork/branch clones therefore carry their own timestamps, and deterministic archive replay reconstructs the same observations from that branch.
- At a configured retarget boundary, elapsed time is derived from the branch's recorded window timestamps plus one nominal target interval. The default candidate window remains 2,016 blocks: the next target is derived from the first and last timestamps of the preceding window, not from an untrusted operator-supplied duration.
- If a caller supplies a duration at a retarget boundary, it must exactly match the branch-derived value. Mismatches, missing timestamps, reversed ranges and arithmetic overflow fail closed.
- `validate_next` validates target-history height, target bounds and strictly increasing branch timestamp before each of the five state-mutating append/replay paths. The record is checked again when stored. This avoids surfacing a history-validation error after a state transition has already mutated ledger state.
- Regression coverage includes deterministic branch-window derivation, rejecting caller overrides, an actual PMT4/MBK4 retarget boundary with archive rebuild/replay, and atomic rejection when a candidate ledger timestamp conflicts with target-history observations.

## Test-window note and remaining incompatibility

The direct `TargetHistory` test uses the default 2,016-block window and verifies the arithmetic at next height 2,017. Full MBK4 envelope plus archive-rebuild coverage uses an explicit 32-block test window because the independent PMT4 fork-choice candidate enforces a 1,024-block maximum branch height. This is a test-only override; it is not a change to the default candidate window or a Mainnet parameter.

An earlier version of the integration test attempted to rebuild a 2,017-envelope archive and correctly received `BranchHeightExceeded`. The test was adjusted to respect that fixture ceiling rather than weakening the archive bound.

**Reachability gap:** with `difficulty_window_blocks = 2,016`, the first retarget applies at block height 2,017, but the archive-backed PMT4 fork-choice candidate caps a branch at height 1,024. The current archive-backed candidate therefore cannot reach its first default retarget boundary. The production profile must reconcile the retarget window with branch-height, archive byte/block and replay resource ceilings before Gate 2 can close. Do not silently weaken those limits or claim Mainnet readiness.

## Local validation on the authorized Windows host (locked/offline)

- `cargo fmt --all -- --check` — PASS.
- `cargo check --all-targets --locked --offline` — PASS (exit code 0; existing diagnostic/test-target unused/dead-code warnings remain).
- `cargo test --all-targets --locked --offline -- --test-threads=1` — PASS (756 library tests, 0 failed/ignored; `devnet_node` 36/36; `private_testnet_node` 36/36; all remaining binary, example and integration-vector targets passed; exit code 0, runtime 553.93s).
- Focused atomicity test `v4_historical_timestamp_history_rejection_is_atomic_before_state_replay` — PASS (1/1).
- Driver retarget observation tests — PASS (3/3).
- End-to-end boundary/replay test `v4_hybrid_historical_chain_retargets_at_first_window_boundary_from_branch_timestamps` — PASS (1/1).
- The integrated main baseline above has separate successful Rust validation and Pages runs; these results qualify the candidate path only, not a production difficulty specification.

## Gate boundary

This hardens branch-derived target observation in the candidate chain driver and deterministic PMT4 replay. It is not an independently reviewed production difficulty specification; it does not freeze target interval, retarget window or clamping rules, add a reviewed median-time-past/future-drift policy, or connect this driver to a public listener. The default PMT4/PFM4 node smoke remains loopback-only, uses an easy target and reduced Argon2 memory, and is not launch-approved.

Gate 2 remains **OPEN** pending one reviewed production network/Genesis/economic/retarget profile, complete canonical-runtime wiring, cross-client vectors, fork/reorg/restart qualification, and independent protocol/economic security review. Gate 8 remains **OPEN** pending a real independently operated HTTPS CAS provider and rollback qualification. Owner-funded spend remains USD 0.
