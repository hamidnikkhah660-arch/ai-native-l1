# CP-0506 — QRun v0.5 reorg-aware authenticated canonical sync

Date: 2026-11-02

Status: **Reorg-aware sync candidate implemented; isolated competing-QFP5-branch regression, authenticated Noise XX sync, receipt correction and durable reopen all pass. Multi-process/multi-host partition qualification remains open. Mainnet remains disabled.**

## Problem confirmed

The previous authenticated sync client requested only `local_canonical_height + 1` and required every returned block to extend the receiver's current canonical tip. That is sufficient for a fresh node or a node that is merely behind on the same branch, but it cannot reliably recover a node that was partitioned onto a different valid branch.

For example:

- Node A has branch A at height 1.
- Node B independently has branch B at height 1 and extends it to height 2.
- The two nodes share the same trusted Genesis/checkpoint base, but their height-1 tips differ.
- Requesting only height 2 from B cannot work on A: B's height-2 block extends B's height-1 parent, not A's canonical height-1 tip.

Rejecting the mismatched parent is correct for the old direct-extension protocol. The missing capability was a safe way to import a competing canonical path into the existing fork-choice graph.

## Protocol and runtime changes

Files:
- `src/native/pow_bench/src/bin/qrun_v05_pow_local_node.rs`
- `src/native/pow_bench/src/qrun_v05_pow_fork_runtime_candidate.rs`

### 1. Sync from the latest already-trusted base

The sync client now begins at `archive_base_height + 1`, not `local_canonical_height + 1`. It requests the peer's canonical path in the existing bounded pages (maximum 16 blocks per page and the current Noise application-record byte cap).

Each response must advertise the exact same trusted base height and base tip as the local node. A different checkpoint/base remains a hard error; the sync client does not adopt peer-supplied checkpoints, skip missing history or silently rebase.

### 2. Import into fork choice, not directly over the local tip

Each envelope must:
- appear at its exact contiguous absolute height for that page;
- match the local QFP5/legacy execution mode;
- pass the existing runtime's full block/PoW/ancestry/state-transition admission through the authenticated-sync-only runtime entrypoint submit_authenticated_sync_block.

The client no longer insists that the block extends the current canonical tip. The fork runtime must already know its authenticated parent branch, so a valid competing branch can be retained and evaluated by the existing cumulative-work fork-choice implementation. Canonical transaction receipts are rebuilt whenever a new branch is retained.

The existing bounded page budget remains in force. Sync beyond the configured catch-up budget fails rather than looping indefinitely.

### 3. Verify the peer tip and local fork-choice result

After all advertised pages are imported, the node verifies that:
- the peer's advertised canonical tip exists in the retained branch graph;
- the retained branch height and state root exactly match the authenticated peer response;
- the local canonical branch is the greatest cumulative-work branch, with the existing deterministic lexicographic tip-hash tie-break applied for equal work.

The runtime exposes only a small read-only `archived_branch_summary` (height, state root, cumulative work) and `canonical_cumulative_work` to the node layer. It does not expose a mutable fork-choice graph API.

### 3. Separate authenticated historical sync from live admission

Canonical sync now enters the explicitly named submit_authenticated_sync_block runtime method. The method accepts QFP5 only and forwards through the storage contract's submit_historical operation to PrivateTestnetForkChoice::insert_encoded_historical. That path uses the existing append_qrun_v05_fee_historical / ChainAdmissionBoundary::testnet().replay_qrun_v05_fee implementation.

Historical admission still checks the envelope/profile, exact height and parent linkage, previous consensus hash, target history, PoW digest, fee-only state commitment, complete fee/state transition and branch supply. Parent timestamp monotonicity remains enforced by the state transition; target history is also updated from the block timestamps. It does not compare an already-mined historical block with the receiver's present-day wall clock or sample a moving freshness window.

This entrypoint is used only by the pinned Noise XX authenticated canonical-sync importer after the peer and common trusted base have been authenticated and the bounded response page has been validated. For QFP5, live P2P gossip, local block submissions and newly mined candidates continue through submit_block / insert_encoded / append_qrun_v05_fee_live, preserving the existing 300-second past and 120-second future live-admission bounds. Authenticated legacy/PTB2 sync retains its prior submit path; the historical timestamp bypass is QFP5-only. The change does not globally relax live timestamp admission. The External-CAS backend uses the same historical validation mode but retains its signed atomic-CAS commit, pending-intent recovery and independent floor checks.

### 4. Preserve fail-closed checkpoint behavior

A peer with a different or higher checkpoint base is rejected. A node that has pruned the required common history must receive and validate the correct checkpoint through the existing separate trust path first. The sync change does not weaken checkpoint provenance or historical replay rules.

## New partition/reconnect regression

New test:
`tests::qrun_v05_partitioned_sync_reorgs_to_peer_cumulative_work_and_recovers_receipts_after_restart`

Test construction:

1. Create two QFP5 runtimes with separate durable directories, same Network ID, owner, Genesis and consensus profile.
2. Do not exchange blocks. Node A mines a valid height-1 transfer to recipient A; Node B independently mines a conflicting nonce-1 transfer to recipient B.
3. Node B extends its own competing branch to height 2. Before reconnect, A remains at height 1 and B at height 2; each node reports only its own branch's transaction receipt.
4. Provision independent Noise XX static keys and perform an authenticated canonical-sync request over a real loopback TCP listener.
5. Node A imports B's canonical height-1 and height-2 path into its fork graph. Cumulative work selects B's branch.
6. Verify A and B now have the same height, canonical tip, state root, owner balance and total supply. The A-only receipt disappears; B's receipt remains.
7. Drop A's runtime and reopen the same durable store. Verify the selected tip/root and the corrected receipt index and recipient balance survive restart.

Result: **PASS**. The server emitted `qrun_pow_local_canonical_sync_served start_height=1 count=2 tip_height=2 base_height=0`; the client imported both blocks, retained the peer tip, and logged `selected_peer_branch=true`.

## Validation

- Focused partition/reorg sync regression: **1 passed, 0 failed**, test runtime **8.23 seconds**.
- Complete node binary suite: `cargo test --bin qrun_v05_pow_local_node --locked --offline`: **34 passed, 0 failed**.
- The complete node suite includes the existing authenticated multi-page sync regression; it continues to pass with the new base-first pagination.
- `cargo check --all-targets --locked --offline`: **PASS**.
- `rustfmt --edition 2021 --check` on the changed runtime and node files: **PASS**.
- `git diff --check`: **PASS** (line-ending conversion notices only).

## Scope limitations and next gate

- The new partition regression creates two separate durable QFP5 runtimes in one test process and uses a real loopback Noise XX sync exchange. It is not yet a test of two independent OS processes or two physical hosts.
- It simulates a partition by withholding all block exchange while each independent runtime creates a distinct branch, then performs an authenticated reconnect/sync. A live TCP proxy/firewall partition test and process restart/resync smoke remain the next qualification.
- Sync remains bounded by the configured page count and by the common trusted checkpoint base. It is not a replacement for full-history archive recovery or checkpoint acquisition.
- The trusted reference-time Authority is still a single configured time attester, not BFT time consensus.
- Mainnet Genesis/identity freeze, repeated checkpoint recovery, External-CAS failure injection, remote-host reachability, adversarial multi-host restart/partition/reorg and independent security review remain open.
- `QRUN_MAINNET_RELEASE_APPROVED = false` remains unchanged. No Mainnet launch, public-value QZXB trading, liquidity or exchange readiness is claimed.

**Decision:** retain reorg-aware canonical sync as a QRun v0.5 Public Alpha candidate. Next, qualify the same scenario with two separate node processes and then two independent hosts before reconsidering any release gate.

## Cross-host timestamp admission correction (2026-11-03)

The first full Stage C2 cross-host reconnect run demonstrated why this split is required. The Node B P2P partition healed and CROSS_HOST_PARTITION_RECONNECTED=PASS was emitted, but the first historical Node A branch block was submitted through the live submit_block path. Its timestamp was 185 seconds older than the receiver's calculated earliest_allowed value, so the receiver correctly rejected it under the live 300-second freshness policy even though the block was part of the authenticated, already-mined canonical history.

The sync importer now calls submit_authenticated_sync_block; live P2P gossip remains on submit_block. A targeted regression proves that the same stale QFP5 envelope is rejected by live admission, accepted by authenticated historical replay after full PoW/ancestry/state validation, and survives durable reopen with an identical canonical tip, state root and total supply.

Focused regression: 1 passed, 0 failed. A second physical-host C2 run is still required to verify that this fix completes cross-host fork choice, orphan-receipt removal and durable reopen. No cross-host reorg PASS is claimed yet.
