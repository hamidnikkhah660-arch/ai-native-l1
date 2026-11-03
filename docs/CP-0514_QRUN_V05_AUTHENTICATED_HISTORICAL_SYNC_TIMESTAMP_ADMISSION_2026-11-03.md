# CP-0514 ? QRun v0.5 authenticated historical-sync timestamp admission

Date: 2026-11-03

Status: Corrective implementation and focused regression pass locally. Physical-host C2 requalification pending.

## Triggering evidence

Stage C2 run 41551873878 completed the private P2P partition, independent branch creation and P2P reconnect. Node B then attempted pinned authenticated sync of Node A's canonical QFP5 branch and failed:

- earliest_allowed = 1793665551
- actual = 1793665366
- difference = 185 seconds
- error: TimestampTooFarInPast

This was not a transport or firewall failure. A block mined during the partition was presented to the recipient after enough wall-clock time had elapsed that it no longer satisfied the recipient's local live freshness window.

## Root cause

The authenticated canonical-sync importer called QRunV05PowForkRuntime::submit_block, the same entrypoint used for live P2P gossip. That entrypoint forwards into PrivateTestnetForkChoice::insert_encoded, which applies append_qrun_v05_fee_live and the current-time 300-second past / 120-second future policy.

The QRun chain already had a deterministic historical QFP5 validator (append_qrun_v05_fee_historical) used by archive rebuild/replay, but the authenticated sync import path did not expose or select it.

## Corrective design

A separate QFP5-only historical import path was added at each layer:

1. PrivateTestnetForkChoice::insert_encoded_historical.
2. PrivateTestnetForkStore::submit_historical, retaining isolated candidate validation and atomic PFS2 manifest publication.
3. QRunV05ExternalCasForkStore::submit_historical, retaining the signed CAS transaction, QAP1 pending recovery and floor reconciliation.
4. QRunV05RuntimeStore::submit_historical plus QRunV05PowForkRuntime::submit_authenticated_sync_block.
5. Only the pinned Noise XX authenticated canonical-sync importer invokes the new runtime method.

The live P2P gossip receiver and other live candidate paths remain on submit_block and keep current-time freshness bounds. Legacy/PTB2 authenticated sync retains its prior submit behavior; only QFP5 sync uses this historical replay entrypoint. Historical admission still verifies QFP5 profile, expected target, PoW, height, parent and previous consensus digest, fee-only state commitment, producer/fee state transition, branch supply and durable commit. The block timestamp must remain valid relative to its parent; the present-day clock window is not applied to historical sync.

## Regression evidence

Test:
qrun_v05_pow_fork_runtime_candidate::tests::authenticated_sync_historical_import_rejects_live_stale_block_then_replays_and_reopens

The same timestamp-1 QFP5 envelope is evaluated at reference time 1,000:

- Live submit_block: rejected with TimestampTooFarInPast.
- Authenticated historical sync: accepted with full consensus validation.
- Durable reopen: canonical height, tip, state root and total supply remain unchanged.

Result: 1 passed, 0 failed.

## Remaining qualification

The targeted regression passes locally. Full Rust checks on the modified branch and another physical-host Stage C2 run remain required. That run must prove the Node B conflicting receipt is removed from canonical view, Node A's greater-work branch becomes canonical, balances/state roots agree, and a second reopen without startup sync preserves the canonical result.

No public Mainnet, independent-operator, public RPC or QZXB market-readiness claim is made. QRUN_MAINNET_RELEASE_APPROVED=false. PR #132 remains Draft and unmerged until these gates are satisfied.
