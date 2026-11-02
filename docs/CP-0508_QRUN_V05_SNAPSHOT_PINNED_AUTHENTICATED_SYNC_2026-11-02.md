# CP-0508 — QRun v0.5 Snapshot-Pinned Authenticated Sync Pagination
**Date:** 2026-11-02
**Branch:** `feat/qrun-v05-live-two-sided-timestamp-window-20261102`
**HEAD at start of task:** `2a15038fe512ee768d127c77da7101d7567386c6`
**Result:** PASS — protocol hardening and same-host multi-process regression

## Problem found
The previous authenticated sync implementation requested each canonical page independently. The response advertised the peer's current height and tip, but the next request did not bind itself to that same canonical snapshot. A peer could therefore reorganize or advance between page requests, allowing one catch-up attempt to observe different canonical snapshots.

## Change
Updated `src/native/pow_bench/src/bin/qrun_v05_pow_local_node.rs`:
- Bumped the internal canonical sync wire protocol version from 1 to 2.
- Extended the request from 20 to 61 bytes with a snapshot-pin flag, expected canonical height, and expected canonical tip hash.
- The first page request is unpinned; its authenticated response establishes the snapshot.
- Every following page request carries that exact height/tip pair.
- The serving node checks the pin while holding the node-state lock, before exporting page envelopes.
- The requesting node independently checks each response against the pin before importing any envelope from that page.
- A changed height or tip fails closed; the client must begin a fresh sync attempt rather than mix pages from different snapshots.
- Added codec and snapshot-pin regressions for correct pins, changed heights, changed tips, and invalid pin flags.

The page's block envelopes continue to be submitted through the normal local consensus admission/validation path. Snapshot pinning does not turn peer data into trusted state and does not bypass fork choice.

## Verification
- Bounded sync wire/snapshot-pin focused test: PASS.
- Authenticated multi-page sync through the real Noise XX node handler: PASS.
- Complete `qrun_v05_pow_local_node` test suite: **34 passed, 0 failed**.
- Library reorg test selection: **20 passed, 0 failed** (81.32 seconds).
- `cargo check --all-targets --locked --offline`: PASS.
- `rustfmt --edition 2021 --check`: PASS.
- `git diff --check`: PASS.
- Release partition/reconnect/reorg multi-process smoke: PASS, process exit code 0 (269.37 seconds).

## Release smoke result
Two independent QRun node OS processes shared one test Genesis and were isolated behind two closed TCP proxy gates. Node A mined its own nonce-1 branch; Node B mined a conflicting nonce-1 branch and extended it with nonce 2. After both gates opened, Node A restarted with authenticated startup sync and reorged to Node B's greater-cumulative-work branch. The losing-branch receipt disappeared; canonical transaction receipts, owner nonce, balances, and state root matched the selected branch. A second Node A restart without sync recovered the same selected tip and receipts from durable storage.

Observed final values:
- Node A height: 2
- Node B height: 2
- Canonical tip: `002182bfc5e2ac49a1c82b782d7caeecec34f208418c95dec4e72758d2cf09c5`
- Canonical state root: `9786ddc4e3d996d0f17bdf2d646e482483488c8bbf31c53378f4d2de21c428e9`
- Orphaned transaction: `0de2590632c8430f89b1ede77403ada1fef08ac83969b7bc126a5944dbdaad09`
- Selected branch nonce-1 transaction: `2b033972c57627fb38dc3b68ef0c588acc54dec3c3dfdd55b958158c7b9b98e1`
- Selected branch nonce-2 transaction: `6a7b20d1ad63cb2a422a6a5f3c8469e1e3135598a36b1dbc4c0ec710363ef7c9`

## Boundaries and release posture
- The process-level test used two independent OS processes on the same Windows host and loopback TCP. It is **not** a two-physical-host, Internet, firewall/NAT, or operator-diversity qualification.
- This is a Public Alpha/test-only qualification, not a Mainnet launch or public QZXB trading approval.
- `QRUN_MAINNET_RELEASE_APPROVED` remains `false`.
- Existing dirty worktree changes were preserved. No reset, clean, commit, or push was performed.
- Compiler warnings observed during checks are pre-existing unused-import/dead-code/unused-mut warnings; no build or test errors remained.

## Next engineering gate
Run the same partition/reconnect/reorg and snapshot-pinned multi-page sync qualification between two independently administered physical hosts, then test forced tip changes during pagination and recovery/retry semantics.

## Superseding refinement — CP-0509
The first CP-0508 implementation used an exact snapshot pin and rejected any request after the peer's live canonical tip changed. CP-0509 supersedes that server behavior: the peer now serves subsequent pages from the exact retained branch identified by the pin, even if live fork choice advances or changes. If that branch is no longer retained, service fails closed. See `CP-0509_QRUN_V05_RETAINED_SNAPSHOT_AUTHENTICATED_SYNC_2026-11-02.md` for the final design and its adversarial tip-growth test.
