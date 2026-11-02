# CP-0505 — QRun v0.5 durable reorg and canonical receipt-index reopen regression

Date: 2026-11-02

Status: **Regression strengthened; targeted QRun v0.5 restart test and complete library reorg filter pass. No production consensus behavior changed.**

## Existing behavior reviewed

The QRun v0.5 runtime already rebuilds canonical transaction locations from the selected fork-choice branch. The node's `NodeState::refresh_receipts` rebuilds its in-memory receipt lookup from those canonical locations after a newly retained block is submitted. The P2P block-import path invokes this refresh after successful insertion, including when a newly inserted block changes the canonical branch.

Existing fork-choice coverage also exercises:
- equal-height competing branches and deterministic digest tie-breaking;
- cumulative-work selection when a previously losing branch is extended;
- deterministic archive replay and canonical state-root comparison;
- branch-specific transaction-index and ledger reconstruction.

A QRun v0.5 runtime regression existed for receipt removal/restoration during reorg, but it only asserted the post-reorg in-memory runtime state.

## Regression extension

File: `src/native/pow_bench/src/qrun_v05_pow_fork_runtime_candidate.rs`

Extended `reorg_drops_receipts_from_losing_branch_and_restores_winning_branch_index`:

1. Create two distinct signed transactions from the same owner/nonce, to different recipients, in competing height-1 QFP5 branches.
2. Insert both branches, then extend the previously losing branch so cumulative work makes it canonical at height 2.
3. Confirm the canonical transaction location contains only the transaction on the winning branch, and confirm its recipient balance and full-supply invariant.
4. Capture the canonical tip and state root, drop the runtime, and reopen the same durable store.
5. Reconfirm height, tip, state root, canonical transaction location, total supply and the winning recipient balance after recovery.

The test explicitly requires the losing branch's transaction receipt not to reappear after restart. This extends validation of the existing implementation; it does not change fork-choice, block-admission, transaction execution or receipt semantics.

## Validation

- Focused extended QRun v0.5 regression: **1 passed, 0 failed**.
- Complete library reorg filter after the extension — `cargo test --lib reorg --locked --offline`: **20 passed, 0 failed**.
- `cargo check --all-targets --locked --offline`: **PASS**.
- `rustfmt --edition 2021 --check` on the changed runtime and node source files: **PASS**.
- `git diff --check`: **PASS** (Git reports line-ending conversion notices only).
- Public Alpha smoke script PowerShell parser: **0 errors**.
- The preceding Public Alpha Debug and optimized Release two-process smokes both passed signed TXN2 ingress, Noise XX block broadcast, canonical convergence, dual-node receipt checks and matching owner balance/nonce.

## Boundary and next gate

This is durable local-runtime regression evidence, not a live multi-host partition/reorg qualification. A next network-level test should partition two independent nodes, construct distinct competing QFP5 branches, reconnect them, and verify cumulative-work convergence plus receipt/balance correction through the actual authenticated P2P path. It must use the same consensus profile and must not alter PoW difficulty or timestamp-admission policy to force a result.

`QRUN_MAINNET_RELEASE_APPROVED = false` remains unchanged. No commit or push was made.
