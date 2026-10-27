# CP-0435 — Zero-Budget Alternative to an External CAS Provider: Consensus-Native Recovery

Date: 2026-10-27
Status: Bounded, test-only QZBE archive sync is integrated into the candidate node and has passed a three-node loopback exercise; the separate pure Rust readiness-gate model is tested but not wired into node readiness. Gate 8 remains open.
Purpose: evaluate whether QZXB can avoid operating a separate CAS trust service by making the chain history the source of truth and treating local databases/snapshots as disposable caches until verified.

## 1. Why evaluate this alternative?

A permissionless blockchain does not inherently need a central authority to approve transactions. Bitcoin relies on independently validating blocks and selecting the valid chain with the greatest cumulative proof of work, rather than trusting a restored local balance database. This is a valid architectural alternative to evaluate; it does not imply that an unfinished candidate runtime is ready for value-bearing traffic.

The current Gate 8 design expects an independently administered monotonic compare-and-swap (CAS) service to detect stale restores. No independent provider has responded to the project's zero-budget outreach as of this date. A provider-independent CAS wire contract and candidate store APIs exist, but no real independent provider endpoint, signing-key custody, or deployment is established.

A chain-native alternative could remove the separate provider dependency only by refusing to treat an unverified local snapshot or checkpoint as canonical state. The pure Rust readiness model in src/native/pow_bench/src/consensus_native_recovery_gate_candidate.rs has 11 passing tests and distinguishes SYNCING, READY and QUARANTINED outcomes based on profile, Genesis, full-history replay, peer reconciliation, state-root agreement, cumulative-chainwork agreement and explicit peer conflicts. That model is not yet called by node startup, so it is not runtime enforcement. Separately, CP-0437 adds bounded QZBE archive transfer over an authenticated Noise session to an already-pinned peer, with Genesis/profile binding, a digest over the ordered envelope bytes, per-envelope consensus validation, and final height/tip/state-root/cumulative-chainwork comparison. The explicit --sync-from-peers option is rejected unless both --test-easy-pow and --public-testnet-p2p are set and at least two statically pinned peers are configured. Each peer is checked sequentially; the node fails closed if their Genesis/profile, height, tip, state root or cumulative chainwork do not converge.

## 2. Required design if external CAS is removed

Source of truth: the valid chain of blocks from the frozen Genesis, not a locally restored balance database or an unverified checkpoint.

Startup and recovery: replay and validate archived blocks from Genesis, including transaction authentication, state transitions, difficulty/proof of work, cumulative chainwork, reward schedule, issuance accounting and all state roots. A stale or restored directory is only an old local view; it must be treated as behind and reconciled against independently observed, valid peer histories before the node enters READY state.

Snapshots: no pruned or checkpoint-only snapshot may be accepted as authoritative unless its full ancestry and validity are independently reconstructed or verified by a separately approved trust model. The conservative first release is to retain and validate full block history from Genesis instead of requiring trusted snapshot restore.

Transaction safety: the RPC must expose separate SYNCING, READY and QUARANTINED states. It must not describe a local mempool transaction as confirmed. Mining on a restored/stale tip and any value-bearing wallet operation must remain disabled while replay is incomplete, the profile mismatches, peer histories conflict, or the local tip has not been reconciled. Confirmation is determined by the valid chain's cumulative work and the published confirmation policy, not a local snapshot height.

Reorganization: validate a candidate branch from a known common ancestor, recompute branch-local state, rewards, roots and cumulative work, then commit the reorganization atomically. Never select a branch just because it has greater height or a peer claims it is canonical.

Operations: publish reproducible source/binary/configuration, logs, sync state, storage format, archive retention policy, recovery procedures and explicit limitations. Multiple independently operated peers are still needed to qualify public operation and reduce dependence on one peer; a fixed operator count alone does not guarantee security.

## 3. Candidate archive-sync milestone (CP-0437)

The node can now export/import its bounded retained QZBE branch archive for an explicit zero-value test profile. The protocol limits the transfer to at most 4,096 envelopes and 64 MiB; the current in-memory archive itself also has a 1,024-height bound. It is therefore a bounded candidate synchronization path, not an unbounded full-history/archive retention solution. A fresh three-process loopback test mines three blocks, checks that two pinned source peers agree, transfers both peer archives to a new data directory, validates/imports each envelope, and proves the fresh node matches the same height, tip, state root and cumulative chainwork. The test is tracked in simulations/cp0437_qzbe_fresh_node_archive_sync.ps1 and is required in the Windows CI workflow.

This does not yet make the node READY based on independent peer agreement, does not solve stale-directory rollback when the recovered directory contains a matching but old manifest, does not retain or serve history beyond the current archive limits, and does not provide pagination/continuation for history exceeding those limits. The node's RPC, mining and confirmation paths are not yet gated by the pure readiness model. Gate 8 remains OPEN.

## 4. Acceptance tests before this alternative could replace Gate 8

- [ ] The canonical runtime starts from a pinned Genesis and replays the full block history without a trusted external state anchor.
- [ ] A byte-for-byte restored older data directory is recognized as stale and cannot enable confirmation, mining as READY, or value-bearing RPC before validated catch-up.
- [ ] Missing, corrupted, reordered or mismatched historical blocks fail closed; no implicit fallback to an older snapshot or profile is permitted.
- [ ] Replayed state roots, issuance counters, balances, canonical tip and cumulative work match independently across separate node builds.
- [ ] Stale restore, deep reorg, competing valid branches, network partition/rejoin, wrong-network peers, malformed history and interrupted durable commits are tested.
- [ ] The operator-facing interface reports SYNCING until independently observed chain data are fully validated; unavailable peers never cause the node to claim fresh canonical state.
- [ ] A second operator or reviewer verifies the threat model and tests against an exact commit.
- [ ] The owner explicitly accepts the revised threat model and records that consensus-native recovery replaces the external-CAS requirement.

## 5. Trade-offs and boundary

This alternative may be cheaper because it does not require an external CAS provider, but it requires complete validated history, robust chainwork/fork-choice/replay and strict synchronization gating. It gives up the external monotonic receipt as an additional rollback signal. It is not a shortcut around consensus correctness, public multi-node testing or independent review.

If full-history verification cannot be implemented and demonstrated, the external CAS path remains required. A local checksum, local high-water file, GitHub issue comment, in-memory mock, or second process on the same host is not a substitute for an independently administered trust boundary.

## 6. Current status

Gate 8 remains OPEN pending either (A) a deployed independent CAS with signed receipts, separate trust domain and qualified recovery, or (B) explicit owner acceptance of this alternative, wiring the readiness gate into node startup/RPC/mining, full-history consensus-native recovery implementation and all acceptance evidence above. The 11 passing unit tests cover the pure readiness-gate model only.

Gate 2 remains OPEN until the single v0.4 monetary profile is integrated end-to-end from the final Genesis. Gate 13 remains OPEN until a qualified public zero-value devnet and independent operators are genuinely available. No native Mainnet, public value-bearing transaction path, verified QZXB/USDT pair, liquidity or authentic QZXB candles is established.
