# CP-0589 - QFP6 branch-time consensus integration gate

**Date:** 2026-11-11
**Status:** Audit and implementation specification; no consensus parameter freeze, runtime activation, or Mainnet authorization
**Parent:** CP-0588 / permissionless Genesis runtime gate

## Executive finding

The repository already contains a tested research implementation of an 11-ancestor median-time-past (MTP) rule in `asert_anchor_policy_candidate.rs`. It validates contiguous height and parent links and requires a candidate timestamp to be strictly greater than the median of the last at most 11 ancestors. It is explicitly documented as research-only and is not called by QFP6 canonical block admission.

QFP6 currently has multiple weaker timestamp checks:

- `qrun_v06_pow_fork_choice_candidate.rs`: `TargetHistoryNode::append` rejects timestamps not strictly greater than the immediate parent. `from_checkpoint_entries` performs the same monotonicity check while rebuilding a retained target-history tail.
- `qrun_v06_canonical_execution_candidate.rs`: `validate_block_header` rejects zero timestamps and timestamps not greater than the execution parent's timestamp.
- `qrun_v06_checkpoint_candidate.rs`: checkpoint history validation checks increasing timestamps and target bounds, but not branch-local MTP.
- `qrun_v06_miner_candidate.rs` and `qrun_v06_node_supervisor_candidate.rs`: candidate construction uses parent-relative increasing timestamps; these are producer paths, not a substitute for consensus admission.
- `timestamp_policy.rs`: wall-clock future/past freshness checks are caller-supplied and explicitly provisional/testnet or v0.5-live policy. They must not be applied to historical replay or used as a deterministic cross-node consensus rule.

The MTP candidate's tests and shared vectors are useful prior work; duplicating that algorithm would be wasteful. The missing work is one canonical, versioned QFP6 consensus policy and consistent application to every branch-aware path. A further concrete checkpoint gap was confirmed: `checkpoint_history_count` retains `min(height, difficulty_window_blocks)` entries, not necessarily the 11 timestamps required by MTP. Unless the difficulty window is at least 11 (which is not yet a frozen Mainnet parameter), checkpoint restore cannot independently recompute the MTP boundary from its current target-history tail. The checkpoint format must therefore explicitly retain `max(difficulty_window_blocks, 11)` ancestry entries (subject to its cap) or add a separately committed/authenticated MTP boundary representation.

## Required design boundary

1. **Deterministic chain rule:** candidate timestamp must be strictly greater than the median of the last at most 11 timestamps on that candidate's own parent branch. Genesis and short prefixes use all available ancestors. The candidate itself is excluded. Height and parent linkage must be checked before computing the median.
2. **Branch-local history:** never compute MTP from the current canonical tip when validating a competing branch. Fork choice must use the proposed block's actual parent ancestry.
3. **Replay and restore:** block import, fork-choice insertion, canonical execution, archive replay, and checkpoint-history restoration must agree on the same versioned rule. A checkpoint may not bypass validation merely because it contains a valid commitment; its retained history must be sufficient to recompute the required MTP boundary, or the checkpoint must carry a separately specified authenticated boundary sample.
4. **Local clock policy is separate:** a future-time guard may be applied at live network ingress to limit resource abuse, but its reference clock and tolerance are node-local policy. It must not change historical consensus validity or make two honest nodes disagree about an otherwise valid historical block. Define and test the exact ingress-only behavior separately.
5. **Difficulty is separate but coupled to timestamps:** current retarget calculation uses timestamps in the branch-linked `TargetHistoryNode`. MTP integration must not change retarget endpoints, window, rounding, clamping, target encoding, or ASERT selection without a separately versioned consensus decision and cross-client vectors.
6. **Fail closed:** insufficient ancestry, missing timestamps, broken links, overflow, or mismatched profile/version must reject validation; no fallback to parent-only monotonicity.

## Implementation sequence

- Extract or adapt the existing MTP calculation into a QFP6 consensus-policy module with an explicit policy/profile version. Preserve the existing research module and its vectors until equivalence is demonstrated.
- Extend the branch-linked QFP6 target-history representation to compute MTP from the proposed parent chain. Confirm that the retained checkpoint history always includes the last 11 ancestors even when the difficulty retarget window is shorter; otherwise add an explicit MTP-history section to the checkpoint codec and commitment.
- Enforce the same deterministic MTP check before canonical execution mutates state and during fork-choice insertion. Avoid relying on execution state alone if it cannot prove the competing branch ancestry.
- Add checkpoint validation and replay tests for MTP boundary, short history, reorgs, two branches with different medians, restart, truncated history, stale/mixed ancestry, and malformed timestamps.
- Add independent shared vectors consumed by Rust and a second implementation. Include even/odd sample counts, duplicate timestamps, out-of-order ancestor timestamps, exact-median rejection, median-plus-one acceptance, height 0-10, and 11+ ancestor rolling window.
- Separately specify a node-local future-time ingress bound and test that replay/import of old valid history is unaffected by the current wall clock.
- Run targeted tests, then full Rust CI and Windows cross-host recovery only after code changes. Existing CP0587 green CI remains valid for its exact SHA and is not evidence for this new code.

## Parameters deliberately not frozen here

- No Mainnet Genesis timestamp, network ID, profile fingerprint, or immutable Genesis commitment is selected.
- No SHA-256d target, block interval, retarget window, retarget bounds, ASERT anchor, or expected hashrate is approved. CP-0578 explicitly leaves candidate target calibration open.
- No local future-drift value is promoted from testnet/v0.5 policy into QFP6 Mainnet.
- No change is made to founder allocation, 10B supply, issuance, fee routing, rewards, or burn policy.

## Acceptance criteria for the code phase

- One versioned QFP6 policy is called by block admission and branch-aware fork choice; checkpoint/replay paths verify the same rule.
- Reorg tests prove that MTP is computed from each candidate branch, not the old canonical branch.
- A checkpoint missing enough MTP ancestry is rejected unless an explicitly committed and independently verified boundary representation is introduced.
- Historical replay is independent of local wall-clock time.
- Rust and independent shared-vector implementations agree byte-for-byte on all cases.
- All targeted tests, `cargo fmt --all -- --check`, `cargo check --all-targets --locked --offline`, and full `cargo test --all-targets --locked --offline` pass on the exact PR head.

## Explicit non-claims

This CP is an audit/specification only. It does not connect MTP to production admission, start a node, enable `--run`, create Genesis, establish public peers, issue QZXB, authorize Mainnet, or create QZXB/USDT liquidity. QFP6 remains not production-ready until the implementation and the independent runtime/network/economic/security gates are completed.
