# CP-0493 - QRun v0.5 adversarial retarget and checkpoint recovery

Date: 2026-11-02

Status: **Two additional deterministic adversarial-retarget regressions pass. The calibrated profile remains a candidate; Mainnet remains disabled.**

## Purpose

CP-0492 established that the checked-in candidate profile, wallet-bound Genesis identity and Rust runtime fingerprint agree across languages. The next consensus-risk step is to exercise timestamp-derived retarget arithmetic under hostile but structurally admissible histories, including checkpoint boundaries and integer extremes.

Existing tests already cover ordinary retarget arithmetic, 90% and 99% hash-rate drops, timestamp-derived observations and two checkpoint restores across successive retarget windows. CP-0493 adds focused tests for the edges not covered by that suite; it does not add duplicate 90%/99% scenarios.

## What the new tests exercise

- `retarget_timestamp_extremes_are_clamped_across_checkpoint_recovery` uses an eight-block test window to keep the regression fast while preserving the same retarget function and clamp rules. A one-second timestamp cadence is compressed to the minimum 1/4 target adjustment. After a checkpoint restore, a deliberately expanded window is clamped to the maximum 4x adjustment. After a second checkpoint restore, a nominal third window produces the same target without drift.
- `retarget_timestamp_elapsed_overflow_fails_closed_after_checkpoint_restore` constructs a strictly increasing branch timestamp range near the `u64` limit. Adding the configured virtual initial interval would overflow; the target decision returns `DifficultyOverflow`. The same failure remains after serializing and restoring the bounded target history.

The tests operate on the real `TargetHistory` implementation used by the QRun v0.5 fork runtime. They validate deterministic branch-derived timestamps, bounded integer retarget arithmetic, checkpoint serialization/restore and fail-closed overflow handling.

## Local validation

- `cargo fmt --all -- --check`: **PASS**.
- Focused Windows Rust tests for `private_testnet_driver::tests::retarget_timestamp_`: **2/2 PASS**.
- Both new tests exercise the shared `retarget_target` rule with the configured 1/4..4x clamp; no consensus parameter values are changed.
- `cargo check --all-targets --locked --offline`: **PASS**.
- Full `cargo test --all-targets --locked --offline -- --test-threads=4`: **PASS**, exit code 0; library **1,039/1,039**, `devnet_node` **68/68**, `private_testnet_node` **41/41**, `qrun_v05_pow_local_node` **28/28**, `qrun_v05_local_node` **5/5**, QZBE smoke **6/6**, QZBE peer node **26/26**, and all remaining binary, integration and example targets passed. Total runtime: **629.52 seconds**.
- Public-doc refresh preflight: **PASS**; README relative links **92/92**, HTML IDs **14**, and canonical Git-blob checksum verification **532/532**.
- GitHub CI for this CP-0493 branch: pending until the pull-request checks complete.

## Scope and non-goals

This checkpoint changes tests and engineering evidence only. It does not modify the consensus profile JSON, Argon2id settings, initial target, 30-second target interval, 2,016-block production candidate window, difficulty clamps, PoW limit, Genesis, Network ID, owner, token supply or fee-only issuance policy.

The tests do not constitute a live multi-host mining experiment, independent operator qualification, external security review, public Devnet, production profile freeze, or proof of real-world block timing. The eight-block window is a test fixture, not a proposed production parameter. The test histories are deterministic software inputs rather than measured wall-clock behavior.

**Gate 2 remains OPEN.** `QRUN_MAINNET_RELEASE_APPROVED` remains false. Mainnet, public mining and value-bearing QZXB issuance remain disabled.
