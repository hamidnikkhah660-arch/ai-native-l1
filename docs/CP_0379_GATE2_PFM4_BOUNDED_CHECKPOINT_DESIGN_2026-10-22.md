# CP-0379 — Gate 2 bounded PFM4 checkpoint architecture and boundary finding

Date: 2026-10-22
Status: **FINDING RECORDED — Gate 2 remains OPEN**
Validated source baseline: `a16951a1e36f04e99937e749022b85cf7818d82f`

## Executive finding

The current PMT4/PFM4 monetary fork-choice candidate has two independent bounds:

- `MAX_V4_HYBRID_FORK_ARCHIVE_HEIGHT = 1,024` rejects any candidate header claiming a greater logical height.
- `MAX_V4_HYBRID_FORK_ARCHIVE_BLOCKS = 4,096` caps the number of retained branch records; it is not the logical height limit.

The candidate default retarget window is 2,016 blocks, so the first default retarget for next height 2,017 is unreachable while the logical-height ceiling remains 1,024. The candidate monetary state machine uses `MONETARY_BLOCKS_PER_HALVING = 4,204,800`, also beyond that logical-height ceiling. The integrated short-window retarget test sets a test-only 32-block window; it does not validate reachability of the default 2,016-block boundary.

This does **not** mean the existing CI failed. It means the currently bounded candidate cannot demonstrate those production-profile boundaries end to end. The candidate settings are not frozen production rules and Gate 2 is not closed.

## Evidence inspected

On baseline `a16951a1e36f04e99937e749022b85cf7818d82f`:

- `src/native/pow_bench/src/private_testnet_v4_hybrid_fork_choice_candidate.rs` defines the 1,024 logical-height ceiling, rejects an over-ceiling header before parent/consensus admission, stores each retained envelope with a cloned `PrivateTestnetChain`, caps retained records at 4,096, and rebuilds the archive by replaying the stored envelope graph in height/digest order.
- `src/native/pow_bench/src/consensus.rs` sets `PROVISIONAL_DIFFICULTY_WINDOW_BLOCKS = 2_016`.
- `src/native/pow_bench/src/private_testnet_driver.rs` derives retarget observations from the branch's timestamp history and requires the observation to be available at retarget boundaries.
- `src/native/pow_bench/src/state_machine.rs` sets `MONETARY_BLOCKS_PER_HALVING = 4_204_800`; `MonetaryLedgerState::total_value` checks accumulated mining issuance against the height-derived candidate schedule.
- `src/native/pow_bench/src/private_testnet_v4_hybrid_fork_store_candidate.rs` persists all manifest-referenced branch envelopes and reconstructs the archive on open. The manifest digest/checksum is not an independent anti-rollback trust anchor.

Post-merge validation on that exact source baseline passed: Rust Actions reports 753 library tests passing, zero failed/ignored, in 268.12 seconds, and the Windows PMT4/TXN4 two-node job passed. GitHub Pages also built and deployed successfully. These are regression results, not an independent audit or proof that the default retarget/halving boundaries are reachable.

- Rust validation: https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/39762045384
- Pages build/deployment: https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/39762046089
- Gate 2 issue: https://github.com/hamidnikkhah660-arch/ai-native-l1/issues/2
- Gate 8 issue: https://github.com/hamidnikkhah660-arch/ai-native-l1/issues/3

## Why a one-line limit increase is not an adequate fix

1. Raising the logical-height ceiling to 2,017 could make the first retarget boundary reachable only if the ancestry, retained-record budget, replay policy, and memory/time costs remain valid. It does not make height 4,204,800 reachable.
2. Raising the bound to the first halving height while keeping the current full envelope graph and per-branch history/state clones would contradict the bounded-resource design and could make storage, replay, and memory costs unacceptable.
3. Reducing the consensus difficulty window or halving interval to fit the current test fixture would alter consensus/economic behavior and is not authorized by this checkpoint.
4. Pruning old envelopes without a verifiable checkpoint, target-history continuity, explicit reorg boundary, and independent anti-rollback trust would weaken replay/recovery semantics.

Accordingly, this change does not relax either bound or select a production monetary profile.

## Architecture direction to review

Treat **logical chain height**, **retained fork count**, **retained bytes**, **maximum reorg depth**, and **replay work** as separate dimensions. Explore a versioned, durable checkpointed archive rather than equating the chain's lifetime height with the number of retained full block envelopes.

A checkpoint candidate would need to bind, at minimum:

- network ID, Genesis fingerprint, consensus/monetary profile fingerprint, active transaction manifest and snapshot schema/version;
- checkpoint logical height, exact block digest, state bytes and state root;
- cumulative mined/issued accounting and cumulative chainwork required by fork choice;
- active target and the timestamp/target history necessary to calculate the next default retarget correctly, including the exact first-boundary case;
- parent/checkpoint commitment and a canonical digest covered by the durable commit manifest.

The fork archive after a checkpoint would retain only the configured reorg/fork window and enforce independent count/byte/replay budgets. Reorgs crossing the checkpoint must be rejected unless the protocol explicitly defines how to recover and validate a replacement checkpoint. Old blocks may be pruned only after the replacement checkpoint and manifest are durable.

**Trust prerequisite:** a local checksum is not proof that a checkpoint is authentic or fresh. Recovery must either replay the complete ancestry from an authenticated origin or validate an explicitly selected, independently trusted checkpoint/certificate. The checkpoint trust source, operator independence, rollback behavior and key lifecycle must be reviewed jointly with Gate 8. A local checkpoint file and local manifest that can be restored together are not independent anti-rollback protection.

## Required implementation and acceptance sequence

1. **Freeze the checkpoint threat model and wire schema before coding.** Specify trusted origin, checkpoint authenticity/freshness, exact retarget-history coverage, chainwork semantics, retained fork window, reorg cutoff, snapshot migration and crash-recovery transitions.
2. **Implement canonical encode/decode with independent byte vectors.** Reject wrong network/Genesis/profile, missing or inconsistent target-history entries, state-root/counter mismatch, arithmetic overflow, stale checkpoint versions, wrong checkpoint block digest, corrupt/truncated/oversized data, and a checkpoint that skips unverified history.
3. **Integrate with branch choice and durable store as one design.** Checkpoint publication must be atomic with its manifest; failed writes/CAS must leave the previous committed state authoritative. Reopen must recover only the old valid state or the exact newly committed checkpoint and replayed suffix.
4. **Prove fork/reorg boundaries.** Exercise forks beginning at the checkpoint, reorgs exactly at and beyond the allowed cutoff, stale snapshots, duplicate/conflicting branches, rollback of local files, malformed target history, and a competing heavier branch across restart.
5. **Prove default protocol boundaries end to end.** Use independently generated vectors for height 2,017's first default retarget and the halving schedule around heights 4,204,799/4,204,800/4,204,801. Avoid requiring millions of expensive real PoW blocks by using test fixtures only if the fixture still verifies the exact checkpoint/history/cumulative-work transitions and is cross-checked independently; a short substituted production parameter is not sufficient evidence.
6. **Qualify bounded operations and Gate 8.** Measure/limit retained bytes, replay work, branch fan-out and reorg depth; run concurrent-writer, crash/power-loss, restore/rollback and independently hosted CAS tests; complete cross-client vectors and independent protocol/economic/security review.

## Regression test added by this checkpoint branch

`pfm4_rejects_logical_height_over_ceiling_without_publishing_manifest_or_branch` submits an encoded PMT4 candidate whose header/body agree on a height one above the configured ceiling, confirms its digest meets the test profile's encoded maximum target, and verifies rejection leaves tip, height, archive, manifest anchor, branch files and reopened state unchanged. It protects the current fail-closed bound; it is **not** evidence that checkpointing or the unreachable default boundaries have been implemented.

## Validation results for the CP-0379 change

Validation was run on the branch worktree before commit; the PR head still must pass GitHub Actions independently.

- `cargo fmt --all -- --check`: PASS.
- `cargo check --all-targets --locked --offline`: PASS. Existing unused-import/dead-code warnings from unrelated targets remain; there are no compile errors.
- Focused `pfm4_rejects_logical_height_over_ceiling_without_publishing_manifest_or_branch`: PASS, 1 passed, 0 failed, 756 filtered out.
- `cargo test --all-targets --locked --offline -- --test-threads=1`: PASS, exit code 0. Library suite: 757 passed, 0 failed, 0 ignored, 415.80 seconds. `devnet_node`: 36/36; `private_testnet_node`: 36/36; every other binary, integration-vector target and example completed without failure. Total command runtime was 564.11 seconds.
- `python simulations/rebuild_release_checksums.py`: PASS, 316 checksum entries after adding CP-0379 and manifest v1.4.
- `python simulations/public_docs_refresh_checker.py`: PASS; 14 HTML IDs, 27 README relative links, candidate issuance arithmetic and all 316 Git-index blob checksums passed.
- `git diff --cached --check`: PASS after the final documentation update and checksum refresh.

This validates current configured candidates and regression coverage only. It does not implement checkpointed history, make the 2,017 retarget or 4,204,800 halving boundary reachable through the current archive path, close Gate 2/Gate 8, or substitute for independent review.
## Gate status and boundary

- Gate 2: **OPEN** — canonical production profile, checkpoint/replay/reorg architecture, full issuance path, independent cross-client agreement and independent review remain outstanding.
- Gate 8: **OPEN** — production external CAS transport, independent provider/trust domain, authenticated checkpoint freshness, multi-host anti-rollback and power-loss qualification remain outstanding.
- Mainnet/native QZXB, public mining and native liquidity are not activated or claimed by this checkpoint.
- Owner-funded spend: **USD 0**. No paid service, public listener, production key ceremony, or value-bearing deployment is introduced.