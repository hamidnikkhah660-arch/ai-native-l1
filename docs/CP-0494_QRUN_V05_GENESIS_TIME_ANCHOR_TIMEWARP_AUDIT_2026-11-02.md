# CP-0494 - QRun v0.5 Genesis-time anchor and first-retarget time-warp audit

Date: 2026-11-02

Status: **A first-retarget timestamp manipulation was reproduced through the actual QFP5 live-admission path. The current candidate must not be frozen or activated for Mainnet until a deterministic Genesis-time floor is specified, fingerprinted, and enforced.**

## Executive finding

The QRun v0.5 candidate's timestamp policy rejects zero, non-increasing timestamps, and timestamps more than 120 seconds ahead of the local reference clock. It does not impose a lower bound tied to the network's creation time. The QFP5 Genesis ledger has no timestamp, and the target-history Genesis entry stores no timestamp.

This leaves a first-window time-warp surface: a producer can begin with a very old but valid nonzero timestamp, keep subsequent timestamps strictly increasing while remaining behind current wall time, and then jump the final block of the first retarget window to the allowed local future-time ceiling. The window's endpoint difference is then far larger than the real time elapsed since the first block.

## Reproduction evidence

The new Rust regression, `qrun_v05_first_window_accepts_stale_epoch_and_eases_target_to_max_clamp`, exercises `PrivateTestnetChain::append_qrun_v05_fee_live` rather than a standalone mathematical model.

- Test window: eight blocks, solely to make the regression fast. The production candidate window remains 2,016 blocks.
- The first accepted block uses Unix timestamp 1 while the live reference clock is 1,000,000 seconds.
- Blocks 2-7 use timestamps 2-7 while the reference clock advances by 30 seconds per block.
- The eighth block jumps to exactly reference time + 120 seconds, the inclusive future-time ceiling.
- Every block is admitted by the present live timestamp policy, and the timestamp sequence remains strictly increasing.
- The derived retarget observation is approximately 1,000,359 seconds, although the configured eight-block target duration is 240 seconds.
- The target is eased by exactly the maximum permitted 4x.

The test also passes the same forward jump through the repository's research-only 11-ancestor MTP helper. That helper is not wired into canonical QFP5 admission, and even if it were, MTP alone would not solve this case: a jump far above the median is valid. A deterministic lower time bound anchored to Genesis is separately required.

## Root cause

- The height-zero QRun v0.5 target-history timestamp is `None`.
- The Genesis ledger's `last_timestamp` starts at zero.
- Live timestamp admission has an upper future-drift bound but no protocol-defined past-time floor.
- Retarget uses the first and last accepted block timestamps in the branch window. A large first-window gap can therefore be interpreted as genuine elapsed time.

The eight-block fixture does not change production parameters. The issue follows from the same branch-derived elapsed-time function used at the configured 2,016-block boundary.

## Required design before profile freeze

1. Give each QRun network a deterministic, nonzero `genesis_timestamp` bound into the Genesis commitment and network/profile identity. It must represent the actual activation epoch, not an arbitrary build date.
2. A Genesis lower bound alone is insufficient if the network is activated later than that timestamp. First-block live admission must also require a bounded freshness window against a trusted reference-time source; activation time and its acceptance window must be fixed before launch.
3. Keep historical replay independent of a moving local clock, but do not treat an arbitrary peer-supplied full-history archive as proof that each block was admitted in its original live-time window. Require authenticated checkpoint/anchor provenance or another independently verifiable launch-history trust path for untrusted bootstrap.
4. Retain branch-local MTP as an additional deterministic rule only after its exact interaction with Genesis time, checkpoint prefixes, reorgs and cross-language vectors is specified. MTP alone is insufficient.
5. Update the runtime fingerprint, wallet-bound identity manifest, Genesis/checkpoint codecs, independent Python oracle, public-alpha zero-value profile and all history/replay paths together. Do not silently reuse the existing profile ID or Genesis identity after changing these rules.
6. Run adversarial tests at the actual 2,016-block production boundary, including delayed activation, first-block backdating, forward jumps before/at/after the retarget boundary, reorgs and checkpoint restart.

No production parameter or Genesis identity is changed in CP-0494. Choosing a deterministic Genesis timestamp is a network-identity decision and must be coordinated across all profile and Genesis commitments before any freeze.

## Validation

- Focused Windows test through `append_qrun_v05_fee_live`: **1/1 PASS** (the vulnerable sequence is accepted and the 4x ease is reproduced).
- `cargo fmt --all`: applied successfully; format check and broader validation remain part of this PR's CI.
- This report is a security finding, not a readiness claim. The test's PASS means the described behavior was reproduced, not that the behavior is safe.

**Gate 2 remains OPEN.** `QRUN_MAINNET_RELEASE_APPROVED` remains false. No Mainnet activation, public mining authorization or value-bearing QZXB launch is approved by this checkpoint.
