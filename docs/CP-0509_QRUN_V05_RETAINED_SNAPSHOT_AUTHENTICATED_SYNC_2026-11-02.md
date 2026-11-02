# CP-0509 — QRun v0.5 Retained-Snapshot Authenticated Sync
**Date:** 2026-11-02
**Branch:** `feat/qrun-v05-live-two-sided-timestamp-window-20261102`
**HEAD at task start:** `2a15038fe512ee768d127c77da7101d7567386c6`
**Result:** PASS — stable multi-page snapshot while canonical tip advances

## Why CP-0509 supersedes the first CP-0508 implementation
CP-0508 introduced exact (height, tip) pinning. Its first server behavior rejected any request if the live canonical tip changed between pages. That was safe against page mixing, but unnecessarily fragile under normal block production: an actively mining peer could invalidate a long sync on every new block.

CP-0509 keeps the same authenticated snapshot pin but changes how the server resolves subsequent pages: it serves the exact retained branch snapshot, even after that branch is no longer the live canonical tip. This is possible because QRun's validated fork-choice graph retains branch envelopes and state by tip digest.

## Implementation
Files changed:
- `src/native/pow_bench/src/private_testnet_fork_choice.rs`
- `src/native/pow_bench/src/qrun_v05_pow_fork_runtime_candidate.rs`
- `src/native/pow_bench/src/bin/qrun_v05_pow_local_node.rs`

Added `branch_envelopes_range_for_tip` to the fork-choice archive and a read-only runtime wrapper `archived_branch_envelopes_range`.
- First sync page still snapshots the current canonical height, tip and state root.
- Later requests include the snapshot height/tip pin.
- The server resolves that exact tip through the retained-branch summary and exports the requested page from that branch.
- The server does not silently switch to a new canonical branch.
- Unknown, pruned, or mismatched retained snapshots fail closed.
- The receiver still independently admits every imported envelope through normal consensus validation and fork choice.
- A follow-up sync can then observe the peer's newer canonical tip and import its additional blocks.

## Adversarial growth test
Test: `authenticated_sync_serves_pinned_snapshot_after_peer_tip_growth_then_catches_up`.

The source had 18 canonical blocks. After serving page one, it extended the live canonical tip to height 19. The server then served pages two and three from the retained height-18 snapshot. The first sync completed consistently at height 18. A second sync observed and imported height 19. The receiver finished with the source's exact canonical tip/state root and correct canonical transaction receipt.

This tests normal tip growth during pagination. It does not yet simulate a competing canonical reorg while pages are in flight; retained-branch export is designed to support that case, which remains a separate qualification target.

## Regression and Release smoke results
- Complete QRun v0.5 node binary suite: **34 passed, 0 failed**.
- Library reorg selection: **20 passed, 0 failed** (77.43 seconds).
- `cargo check --all-targets --locked --offline`: PASS.
- Rustfmt check: PASS.
- `git diff --check`: PASS.
- Release partition/reconnect/reorg multi-process smoke: PASS; process exit code 0 (377.90 seconds).

Release smoke observed:
- Two independent QRun OS node processes on one Windows host.
- Bidirectional partition gates closed; conflicting nonce-1 branches remained isolated.
- Node B extended its branch to height 2.
- After reconnect, Node A used authenticated startup sync and reorged to the greater-cumulative-work branch.
- Losing-branch receipt was removed; winning-branch receipts and balances were correct.
- Node A restarted without sync and recovered the selected chain/receipts from durable storage.

Final values:
- Node A height: 2
- Node B height: 2
- Canonical tip: `007a8b5ab56b412ea65179961cad7fd044ac5f81a664816fca56941e95c0796d`
- Canonical state root: `5dc73df1629b400bd4c0b7148e426b976cec2682d5272a61ad199636df0449df`
- Orphaned transaction: `b9863a22738831dcfbebb2cbdb131f3df75cf2fa7de405dfe94ddcf1aff303b0`
- Selected branch nonce-1 transaction: `f71fa241a529e2e0f367ccb503a0d87d77d839676f151dd6e5ad920a4e0d307b`
- Selected branch nonce-2 transaction: `6cc2f2d29327960fa47f2f533cdb577e0f3adc8b47b839e80e71b36e4d7fe9bb`

## Network independence boundary
This remains a same-host, loopback TCP, two-process Public Alpha qualification. The current Desktop Commander account reports only one authorized device online. The Windows host has Ethernet and Wi-Fi interfaces, but no second physical host was connected to this session. Therefore no two-physical-host or independent-operator result is claimed.

## Release posture
- `QRUN_MAINNET_RELEASE_APPROVED` remains `false`.
- Public Alpha smoke keys and temporary data are test-only.
- No commit, push, reset, or clean was performed.
- Existing dirty worktree changes were preserved.

## Next gate
Execute CP-0510 with two physical hosts, then repeat from separately administered network locations. Specifically add a true competing-branch reorg while pagination is in progress, test stale/pruned snapshot failure, firewall interruption, restart recovery, and peer-pin mismatch rejection.


## Follow-up completed — CP-0511
The competing-canonical-reorg-during-pagination case named above as a separate qualification target has now passed. A genuinely competing 19-block branch replaced the live height-18 canonical branch after the first page; the remaining pages were served from the retained height-18 snapshot, and a subsequent sync converged to height 19. Unknown snapshot tips now have an explicit fail-closed regression (`UnknownParent`). See `CP-0511_QRUN_V05_REORG_DURING_RETAINED_SNAPSHOT_SYNC_2026-11-02.md` for the scenario and full regression results.
