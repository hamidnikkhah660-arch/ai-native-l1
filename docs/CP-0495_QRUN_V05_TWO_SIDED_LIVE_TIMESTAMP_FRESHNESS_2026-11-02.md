# CP-0495 - QRun v0.5 two-sided live timestamp freshness hardening

Date: 2026-11-02

Status: **Candidate live-admission hardening implemented and focused tests pass. This is not a complete consensus time-warp fix; historical archive provenance and Genesis activation time remain open.**

## Purpose

CP-0494 reproduced a first-retarget time-warp through the actual QFP5 live-admission path. The local timestamp policy had an upper future bound but no symmetric lower bound, so a new block could be almost arbitrarily old while still being strictly greater than its parent.

CP-0495 adds an explicit past-freshness bound to the candidate live timestamp policy while preserving historical replay's deliberate independence from the current wall clock.

## Changes

- `TimestampPolicy` now supports an optional `max_past_drift_secs` in addition to `max_future_drift_secs`.
- `TimestampPolicy::qrun_v05_live()` uses an inclusive 120-second window on both sides of the caller's reference time. Arithmetic saturates at zero and `u64::MAX`; no wrapping occurs.
- Generic `TimestampPolicy::testnet()` and `TimestampPolicy::new(max_future_drift_secs)` preserve their existing future-only behavior for legacy and other testnet paths. Only `PrivateTestnetChain::append_qrun_v05_fee_live` selects the two-sided QFP5 live policy.
- Added `TimestampPolicyError::TooFarInPast` and matching fail-closed state-machine error mapping.
- The chain-import historical replay test now uses the same two-sided testnet policy configuration but demonstrates that historical replay still does not consult the present-day clock.
- Added a QFP5 live-path regression: a first block timestamped far behind the reference clock rejects atomically; an eight-block first-window sequence using both inclusive ±120-second edges can stretch the measured window from 240 to 480 seconds (2x), but cannot reproduce the previous 4x easing sequence.

## What this does and does not solve

This is a **node-local live-admission freshness policy**, not a canonical timestamp rule. It reduces the time-warp surface when blocks are received and admitted live, but the reference clock must be accurate and coordinated. Nodes with clock skew outside the configured window may disagree on live admission. Production must use a qualified, authenticated time source and specify the tolerated inter-node skew.

Historical replay intentionally does not compare old blocks with today's wall clock. Therefore this change does not by itself prove that an arbitrary peer-supplied full-history archive was originally admitted live inside its time window. Untrusted bootstrap still needs authenticated checkpoint/anchor provenance or another independently verifiable launch-history trust path.

A deterministic Genesis activation timestamp is still unresolved. A mere lower bound of `block.timestamp > genesis_timestamp` is not sufficient if activation is delayed; the actual launch epoch and its acceptance window must be fixed and bound into Genesis/network/profile identity. MTP remains an additional check, not a substitute.

## Validation

- Timestamp-policy boundary and overflow tests: **2/2 PASS**.
- State-machine stale-block rejection and atomicity: **1/1 PASS**.
- Actual QFP5 live first-window regression: **1/1 PASS**.
- Full all-target tests, all-target check, formatting, and CI for this exact branch: pending final validation.

## Release status

No consensus profile JSON, Argon2id setting, initial target, Genesis commitment, Network ID, wallet identity, supply, issuance mode or profile fingerprint is changed here. The ±120-second values are provisional local testnet admission settings and are not frozen Mainnet consensus parameters.

**Gate 2 remains OPEN.** `QRUN_MAINNET_RELEASE_APPROVED` remains false. No Mainnet activation, public mining authorization or value-bearing QZXB launch is approved by this checkpoint.
