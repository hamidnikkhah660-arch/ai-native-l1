# CP-0511 — QRun v0.5 Retained-Snapshot Sync Across a Competing Reorg
**Date:** 2026-11-02
**Branch:** `feat/qrun-v05-live-two-sided-timestamp-window-20261102`
**HEAD:** `2a15038fe512ee768d127c77da7101d7567386c6`
**Result:** PASS — actual canonical reorganization while multi-page Noise XX sync is in flight

## Objective
Go beyond CP-0509's normal tip-growth test. Prove a serving node can keep exporting a pinned historical canonical snapshot after a genuinely competing branch wins fork choice, and then expose the new canonical branch on a separate subsequent sync.

## Adversarial scenario
Test: `authenticated_sync_serves_retained_snapshot_across_competing_reorg_then_catches_up`.

1. The serving QRun runtime builds a Genesis-rooted canonical branch through height 18. It includes a signed transfer at height 2.
2. An authenticated Noise XX sync client requests the first bounded page. The response pins the exact height-18 tip.
3. After that page has been returned, a second independent runtime (same test network, same Genesis, separate durable directory) supplies a competing 19-block branch from Genesis.
4. The serving runtime independently validates and imports those blocks. At height 19, cumulative work makes the rival branch canonical. The original height-18 branch remains retained in the fork-choice graph.
5. The same authenticated sync session requests pages 2 and 3 with the original snapshot pin. The server resolves the pinned tip from the retained graph and serves the remainder of the height-18 path, not the new height-19 canonical path.
6. The receiver completes the first sync at height 18 and has the original branch's transfer state.
7. A second full authenticated sync observes the new height-19 canonical branch, imports it, and reorgs the receiver. The losing-branch transaction no longer has a canonical receipt; its recipient account is absent/zero. Total supply remains invariant.
8. Final receiver and source heights, canonical tip, and state root match the new winning branch.

Observed handler output confirms:
- first snapshot page: start 1, count 8, peer height 18;
- second/third pages remain pinned to peer height 18 after the live reorg;
- a subsequent sync serves pages from peer height 19;
- receiver first completes at 18, then converges to 19.

## Additional fail-closed archive test
Extended `canonical_range_export_is_ordered_bounded_and_respects_checkpoint_base`:
- A known retained tip exports the requested bounded page in height order.
- An unknown snapshot tip `[0xFF; 32]` returns `ForkChoiceError::UnknownParent`.
- Unknown snapshots cannot silently fall back to the live canonical tip.

## Final verification
- Complete `qrun_v05_pow_local_node` suite: **34 passed, 0 failed**.
- Library `reorg` selection: **20 passed, 0 failed** (77.24 seconds).
- Focused pinned-branch export test: PASS.
- Focused authenticated competing-reorg pagination test: PASS.
- `cargo check --all-targets --locked --offline`: PASS.
- Rustfmt check: PASS.
- `git diff --check`: PASS.

The previously recorded CP-0509 Release smoke remains the latest full Release-mode, two-independent-OS-process partition/reconnect/reorg/restart run. CP-0511 adds a deterministic authenticated in-flight fork-choice reorg regression; it does not claim a new two-physical-host or a new Release smoke run.

## Interpretation and limits
The serving node can retain a snapshot through a live canonical reorganization while it remains in the validated fork-choice archive. If the snapshot is unknown or no longer retained, the range request fails closed. The receiver still validates imported block envelopes locally and applies fork choice; it does not trust the peer's snapshot assertion as consensus state.

This remains a same-host deterministic authenticated-socket regression. It does not prove two physical hosts, Internet reachability, NAT traversal, independent administration, Byzantine consensus, or Mainnet safety.

## Release posture
- `QRUN_MAINNET_RELEASE_APPROVED` remains `false`.
- The CP-0510 two-physical-host operator runbook remains prepared but NOT RUN; only one authorized device was online in the working session.
- Existing dirty worktree changes were preserved.
- No commit, push, reset, or clean was performed.
