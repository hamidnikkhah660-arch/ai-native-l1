# CP-0382 - Fail-Closed Cumulative Chainwork Overflow

Date: 2026-10-22
Source parent: CP-0381 bounded target-history snapshot candidate (PR #50 merge).
Scope: explicit 256-bit overflow semantics for chainwork arithmetic in the candidate consensus library and private-testnet driver. This is not a Mainnet activation or Gate 2 closure.

## Changes in this candidate

- Adds `Uint256::checked_add`, which propagates carry across all four big-endian limbs and returns `None` if the mathematical result exceeds the unsigned 256-bit range. It never wraps.
- Adds `ConsensusError::ChainworkOverflow` with a stable error description for cumulative work beyond the 256-bit range.
- Changes `cumulative_chain_work` from saturating accumulation to checked accumulation. A branch sum that overflows now returns `Err(ChainworkOverflow)` rather than collapsing distinct work totals to `Uint256::MAX` and potentially creating a false fork-choice tie.
- Precomputes the next cumulative-work total before candidate admission/state mutation in the five private-testnet append paths: legacy live; monetary live; monetary historical replay; V4 hybrid monetary live; and V4 hybrid monetary historical replay. The precomputed value is published only after successful admission and target-history recording.
- Changes the synthetic CP-0132 branch-history exporter to fail loudly if its fixture chainwork does not fit, rather than silently saturating. Existing test expectations use checked addition when comparing ordinary, non-overflow totals.

## Local validation evidence

On the Windows development checkout, on top of the CP-0381 branch:

- `cargo fmt --all -- --check` - passed.
- `cargo test --locked --offline --lib uint256_checked_add_reports_overflow_without_wrapping -- --nocapture` - 1 passed.
- `cargo test --locked --offline --lib cumulative_chain_work_rejects_overflow_instead_of_saturating -- --nocapture` - 1 passed.
- `cargo test --locked --offline --lib driver_rejects_cumulative_work_overflow_before_mutating_state -- --nocapture` - 1 passed; the test sets the total to `Uint256::MAX`, submits a candidate whose block work is one, expects `ChainworkOverflow`, and asserts the entire driver equals its pre-call snapshot.
- `cargo check --all-targets --locked --offline` - exit 0. It reports existing dead-code/unused warnings in other modules; no compile errors.

This CP-0382 candidate has **not** yet completed a new local full `cargo test --all-targets` run after the chainwork change. The PR GitHub Actions matrix must pass before merge. These tests do not constitute independent cross-client vectors or an external security review.

## Scope and remaining blockers

The fail-closed sum is a necessary chainwork prerequisite for checkpoint trust, but it is not sufficient to authenticate any restored total. A future canonical checkpoint must replay or authenticate every relevant work contribution and bind chainwork to the exact checkpoint block/tip, network/Genesis and profile fingerprints, state root, issuance state, parent commitment, freshness, and independently anchored anti-rollback state.

- **Gate 2 remains OPEN.** Canonical PCP4 encoding/decoding, PFM5 manifest integration, crash-safe durable checkpoint publication, bounded archive replay and reorg recovery, frozen Genesis/consensus/issuance/retarget profile, independent boundary vectors, and independent protocol/economic review remain outstanding.
- **Gate 8 remains OPEN.** No production independent CAS transport, server-side atomic generation compare-and-swap, separate pinned receipt signer trust, multi-host rollback high-water state, or full disk-loss/crash/race recovery qualification is added here.
- **Mainnet/public launch remain unenabled and unclaimed.** No public mining, native liquidity/listing, or value-bearing deployment is activated by this patch.
- **Owner-funded spend remains USD 0.** No paid infrastructure or independent review is claimed; production hosting and independent review need actual sponsors, customers, or explicit third-party credits.