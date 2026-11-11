# CP-0589 - QFP6 branch-time consensus integration gate

**Date:** 2026-11-11
**Status:** Candidate implementation and local qualification complete; no Mainnet parameter freeze, public runtime activation, or Mainnet authorization
**Parent:** CP-0588 / permissionless Genesis runtime gate

## Executive finding

The repository already contains a tested research implementation of an 11-ancestor median-time-past (MTP) rule in `asert_anchor_policy_candidate.rs`. It validates contiguous height and parent links and requires a candidate timestamp to be strictly greater than the median of the last at most 11 ancestors. It is explicitly documented as research-only and is not called by QFP6 canonical block admission.

QFP6 currently has multiple weaker timestamp checks:

- `qrun_v06_pow_fork_choice_candidate.rs`: `TargetHistoryNode::append` rejects timestamps not strictly greater than the immediate parent. `from_checkpoint_entries` performs the same monotonicity check while rebuilding a retained target-history tail.
- `qrun_v06_canonical_execution_candidate.rs`: `validate_block_header` rejects zero timestamps and timestamps not greater than the execution parent's timestamp.
- `qrun_v06_checkpoint_candidate.rs`: checkpoint history validation checks increasing timestamps and target bounds, but not branch-local MTP.
- `qrun_v06_miner_candidate.rs` and `qrun_v06_node_supervisor_candidate.rs`: candidate construction uses parent-relative increasing timestamps; these are producer paths, not a substitute for consensus admission.
- `timestamp_policy.rs`: wall-clock future/past freshness checks are caller-supplied and explicitly provisional/testnet or v0.5-live policy. They must not be applied to historical replay or used as a deterministic cross-node consensus rule.

The MTP candidate's tests and shared vectors are useful prior work; duplicating that algorithm would be wasteful. The CP-0589 implementation now adds one QFP6 time-consensus module and connects its MTP check to branch-linked fork-choice admission and checkpoint validation. The earlier checkpoint gap is closed for this candidate format: a checkpoint retains `min(height, max(difficulty_window_blocks, 12))` target/timestamp entries, enough to validate the checkpoint tip against its up-to-11 ancestors and continue validating the next block. The checkpoint codec is version 3, and the shared QFP6 consensus fingerprint commits to the MTP window and policy identifier.

## Required design boundary

1. **Deterministic chain rule:** candidate timestamp must be strictly greater than the median of the last at most 11 timestamps on that candidate's own parent branch. Genesis and short prefixes use all available ancestors. The candidate itself is excluded. Height and parent linkage must be checked before computing the median.
2. **Branch-local history:** never compute MTP from the current canonical tip when validating a competing branch. Fork choice must use the proposed block's actual parent ancestry.
3. **Replay and restore:** block import, fork-choice insertion, canonical execution, archive replay, and checkpoint-history restoration must agree on the same versioned rule. A checkpoint may not bypass validation merely because it contains a valid commitment; its retained history must be sufficient to recompute the required MTP boundary, or the checkpoint must carry a separately specified authenticated boundary sample.
4. **Local clock policy is separate:** a future-time guard may be applied at live network ingress to limit resource abuse, but its reference clock and tolerance are node-local policy. It must not change historical consensus validity or make two honest nodes disagree about an otherwise valid historical block. Define and test the exact ingress-only behavior separately.
5. **Difficulty is separate but coupled to timestamps:** current retarget calculation uses timestamps in the branch-linked `TargetHistoryNode`. MTP integration must not change retarget endpoints, window, rounding, clamping, target encoding, or ASERT selection without a separately versioned consensus decision and cross-client vectors.
6. **Fail closed:** insufficient ancestry, missing timestamps, broken links, overflow, or mismatched profile/version must reject validation; no fallback to parent-only monotonicity.

## Implemented in CP-0589\n\n- Added `qrun_v06_time_consensus_candidate.rs`: deterministic median of up to 11 prior timestamps, candidate strictly above median, checked short histories, and fail-closed empty history.\n- `TargetHistoryNode::append` now computes MTP from the exact candidate parent ancestry, not the canonical tip. A regression test builds two branches with different medians and proves the same candidate timestamp passes one branch policy and fails the other.\n- Checkpoint export/restore retains `max(difficulty_window_blocks, 12)` entries (bounded by the existing checkpoint cap); the checkpoint validator independently recomputes MTP for the checkpoint tip using Genesis plus retained prior timestamps. A regression test covers a 2-block difficulty window and history lengths 0, 4, 11, 12 and 30.\n- Checkpoint format/checksum/commitment domains advanced to version 3. The QFP6 consensus fingerprint now includes `QFP6-MTP-11-V1`, so Q6CP/Q6GD identity derived through the shared fingerprint binds the policy. Version-2 checkpoint bytes are not silently reinterpreted as version 3.\n- The existing immediate-parent timestamp-increasing rule remains in place in QFP6 fork choice and QFB6 execution. Therefore MTP is currently an explicit additional branch-local consensus gate and versioned commitment, not a relaxation that permits timestamps earlier than the immediate parent. Difficulty retarget arithmetic and local wall-clock policy were not changed.\n- QFB6 execution state remains a state-transition validator, not an ancestry provider; full chain admission must continue to pass through the branch-aware QFP6 fork-choice path before execution. Direct isolated state application is not, by itself, proof of chain consensus validity.\n\n## Implementation sequence

- Completed: added a separate QFP6 MTP policy module and retained the research-only ASERT/MTP module unchanged.
- Completed: fork-choice history computes MTP on the exact parent branch; checkpoint v3 retains the required target/timestamp tail and authenticates it through the checkpoint commitment.
- Completed for chain admission: fork choice checks MTP before invoking QFB6 execution. QFB6 state execution independently retains its immediate-parent timestamp check; direct state application without branch context is not a complete consensus admission path.
- Completed locally: branch-specific median test, checkpoint-tail boundary test, fork-choice/reorg suite, checkpoint restore and existing durable-store replay tests passed.
- Add independent shared vectors consumed by Rust and a second implementation. Include even/odd sample counts, duplicate timestamps, out-of-order ancestor timestamps, exact-median rejection, median-plus-one acceptance, height 0-10, and 11+ ancestor rolling window.
- Separately specify a node-local future-time ingress bound and test that replay/import of old valid history is unaffected by the current wall clock.
- Run targeted tests, then full Rust CI and Windows cross-host recovery only after code changes. Existing CP0587 green CI remains valid for its exact SHA and is not evidence for this new code.

## Parameters deliberately not frozen here

- No Mainnet Genesis timestamp, network ID, profile fingerprint, or immutable Genesis commitment is selected.
- No SHA-256d target, block interval, retarget window, retarget bounds, ASERT anchor, or expected hashrate is approved. CP-0578 explicitly leaves candidate target calibration open.
- No local future-drift value is promoted from testnet/v0.5 policy into QFP6 Mainnet.
- No change is made to founder allocation, 10B supply, issuance, fee routing, rewards, or burn policy.

## Local qualification evidence\n\nOn the Windows working tree, exact current candidate source passed:\n\n- `cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib --locked --offline`: **1333 passed, 0 failed**.\n- `cargo fmt --manifest-path src/native/pow_bench/Cargo.toml -- --check`: passed.\n- `cargo check --manifest-path src/native/pow_bench/Cargo.toml --all-targets --locked --offline`: passed.\n- Targeted fork-choice (15 tests), checkpoint (3 tests), MTP policy (4 tests), branch-specific MTP and checkpoint-retention tests passed.\n\nExisting unrelated compiler warnings remain. GitHub Actions for the new exact commit has not yet run.\n\n## Acceptance criteria for the code phase

- One versioned QFP6 policy is called by block admission and branch-aware fork choice; checkpoint/replay paths verify the same rule.
- Reorg tests prove that MTP is computed from each candidate branch, not the old canonical branch.
- A checkpoint missing enough MTP ancestry is rejected unless an explicitly committed and independently verified boundary representation is introduced.
- Historical replay is independent of local wall-clock time.
- Rust and independent shared-vector implementations agree byte-for-byte on all cases.
- All targeted tests, `cargo fmt --all -- --check`, `cargo check --all-targets --locked --offline`, and full `cargo test --all-targets --locked --offline` pass on the exact PR head.

## Explicit non-claims

This CP implements and locally qualifies candidate MTP checks in QFP6 branch-aware fork choice and checkpoint validation. It does not start a node, enable `--run`, create Genesis, establish public peers, issue QZXB, authorize Mainnet, or create QZXB/USDT liquidity. Strict parent-time monotonicity remains additionally required. QFP6 remains not production-ready until exact-head CI, full independent runtime/network/economic/security qualification, frozen Mainnet parameters and authorization are completed.
