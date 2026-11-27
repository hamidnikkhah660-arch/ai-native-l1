# CP-0617 â€” Resumable Permissionless PoW Nonce Batches

Date: 2026-11-12

## Problem closed

The permissionless QFP6 supervisor previously treated `NonceBudgetExhausted` as a fatal mining error. The miner also started every invocation at nonce zero. With a realistic PoW target, any block requiring more than the configured one-million-attempt slice terminated the node instead of allowing continued work. This made the earlier easy smoke-test target hide a real production-path blocker.

## Implementation

- Added `mine_qfp6_block_on_tip_from_nonce`, which mines a checked half-open nonce range beginning at the caller's cursor. The original `mine_qfp6_block_on_tip` API remains as a compatibility wrapper that starts at zero.
- `NonceBudgetExhausted` now reports the first nonce for the next slice. Overflow of the `u64` nonce space fails closed as `NonceSpaceExhausted`.
- `QRunV06PermissionlessMempool` retains an in-memory PoW nonce cursor across listener/mining rounds. On an exhausted slice it advances the cursor and returns a distinct non-fatal service result.
- The permissionless supervisor treats that result as a completed mining slice, returns to its listener round, and then starts the next bounded slice. Peer/transaction service is therefore not blocked by an unbounded nonce loop, and the node no longer exits solely because a one-million-attempt slice did not find a block.
- On a newly canonical block, the cursor is reset for the new parent/template. A side-branch commit advances it past the nonce that was found. On process restart the in-memory cursor starts at zero; this can repeat local hash work but does not alter block validity, state, or issuance.

## Local SHA-256d measurement

The additional `qrun_v06_sha256d_rate_probe` diagnostic binary measures the exact QFP6 canonical-header plus SHA-256d `pow_digest` path in a release build. On the current Windows laptop, after a 100,000-hash warm-up, five two-second samples were:

| Sample | Hashes/second |
|---:|---:|
| 1 | 639,315.500 |
| 2 | 536,573.259 |
| 3 | 460,282.977 |
| 4 | 463,783.291 |
| 5 | 467,831.860 |

Median: **467,831.860 hashes/second**. The first sample is a high outlier; later samples are consistent with a lower sustained rate. This measures only one laptop CPU, not a public network's aggregate hashrate or miners' expected hardware mix.

At that one-host median, a notional 30-second expected interval corresponds to about 14.03 million hash attempts. The implied target for this single machine is a measurement illustration only; it is deliberately not installed in Q6CP. A Mainnet target must be selected against an approved network-wide security/hasrate model and independently reviewed. The present Q6CP initial target and `pow_limit` remain candidate/testnet values, and no public mining authorization is created by this change.

## Validation

- `cargo test --lib qrun_v06_miner_candidate::tests --locked --offline`: 8 passed, including bounded-exhaustion behavior, non-zero starting nonce, and nonce-space overflow rejection.
- `cargo test --lib exhausted_nonce_batches_advance_the_in_memory_cursor_across_listener_rounds --locked --offline`: 1 passed; successive slices advance from 0 to 1,000,000 to 2,000,000.
- `cargo check --all-targets --locked --offline`: passed.
- `cargo test --bin qrun_v06_node --locked --offline`: 26 passed, 0 failed.
- `cargo fmt -- --check`: passed.
- `git diff --check`: passed before commit.
- Existing CP-0566C/0572/0587 independent-host and transaction evidence was not repeated.

## Release boundary

This is candidate runtime reliability work, not a Mainnet activation. The nonce cursor is in-memory only; restart may repeat hash work. Q6CP difficulty/initial target/pow limit are still unapproved, the SHA-256d single-host rate is not a network hashrate, authenticated public peer discovery remains unqualified, final canonical Genesis/trust artifacts are missing, and no public mining release or QZXB/USDT market/liquidity is created here.

