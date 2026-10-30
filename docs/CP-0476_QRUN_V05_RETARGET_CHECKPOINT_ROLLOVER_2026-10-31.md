# CP-0476 — QRun v0.5 Checkpoint Rollover Through First Retarget

Date: 2026-10-31

Status: **A new regression test proves QFP5 checkpoint rollover can preserve the complete 2,016-block target-history window across two 1,024-height-bounded fork segments, calculate the first retarget at height 2,017, persist that block in a checkpoint-rooted PFS2 suffix, and recover the exact state after restart when the manifest anchor is supplied. This is local test evidence only; it does not close Mainnet release gates.**

## Gap addressed

QRun v0.5 uses a candidate difficulty window of 2,016 blocks, while the fork-choice archive deliberately limits one segment to 1,024 heights. A Genesis-rooted archive therefore cannot retain the whole first retarget window in one segment. The QRCP checkpoint format and suffix constructors already carry the target-history window, cumulative work, tip, state snapshot, profile fingerprint and parent-checkpoint link. The missing regression was an exact QFP5 proof that two bounded rollovers preserve the history needed at the first retarget boundary.

## New regression

Added `qrun_v05_retarget_window_survives_two_checkpoint_rollovers_and_restart` to `qrun_v05_pow_fork_runtime_candidate.rs`.

1. Build a Genesis-rooted QFP5 history through height 1,024, capture an anchored QRCP checkpoint and restore it as a new bounded fork segment.
2. Continue through height 2,016 in the second segment and capture a child checkpoint linked to the exact previous checkpoint commitment.
3. Restore the height-2,016 checkpoint and compare its derived next target with the independent `retarget_target` calculation using the exact timestamp window.
4. Open a durable checkpoint-rooted QFP5 suffix, mine and submit height 2,017, then close and reopen the store. Reopen without the expected manifest anchor is rejected; reopen with the exact anchor reproduces the same height, state root and consensus tip.

The 8 KiB Argon2 memory and maximum test target are confined to the regression fixture. No production difficulty, memory, issuance, Genesis, Network ID or release-gate parameter changed.

## Validation on the exact working tree

- `cargo +stable fmt --manifest-path src/native/pow_bench/Cargo.toml --all -- --check`: PASS.
- `git diff --check`: PASS.
- `cargo +stable check --manifest-path src/native/pow_bench/Cargo.toml --all-targets --locked --offline`: PASS. Existing unused-import/dead-code/unused-mut warnings remain in unrelated code.
- New checkpoint/retarget regression: PASS.
- Existing wallet-bound external-CAS checkpoint rollover/lost-response test: PASS.
- Existing local checkpoint suffix/reopen test: PASS.
- Full library suite: **952 passed, 0 failed**, 164.28 seconds.

## Release boundary

This test demonstrates local checkpoint/history continuity and durable suffix restart. It does not prove a deployed off-host provider, an independently protected QCF1 floor, public peer sync, adversarial multi-host reorganization/recovery, production consensus calibration, or independent security review. The current QRun consensus profile remains a candidate; `QRUN_MAINNET_RELEASE_APPROVED` remains false and public mint remains disabled. No public Mainnet, 10B spendable Genesis balance or QZXB/USDT market is claimed.
