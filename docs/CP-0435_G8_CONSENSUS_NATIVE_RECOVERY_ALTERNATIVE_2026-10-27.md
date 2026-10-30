# CP-0435 — Zero-Budget Alternative to an External CAS Provider: Consensus-Native Recovery

Date: 2026-10-27
Status: Bounded, test-only QZBE archive sync is integrated and passed a three-node loopback exercise. Recovery classification is wired into QZBE candidate-node startup and read-only status RPC; pinned peers must agree on final height/tip/state-root/chainwork summaries. Gate 8 remains OPEN.
Purpose: evaluate whether QZXB can avoid operating a separate CAS trust service by making the chain history the source of truth and treating local databases/snapshots as disposable caches until verified.

## 1. Why evaluate this alternative?

A permissionless blockchain does not inherently need a central authority to approve transactions. Bitcoin relies on independently validating blocks and selecting the valid chain with the greatest cumulative proof of work, rather than trusting a restored local balance database. This is a valid architectural alternative to evaluate; it does not imply that an unfinished candidate runtime is ready for value-bearing traffic.

The current Gate 8 design expects an independently administered monotonic compare-and-swap (CAS) service to detect stale restores. No independent provider has responded to the project's zero-budget outreach as of this date. A provider-independent CAS wire contract and candidate store APIs exist, but no real independent provider endpoint, signing-key custody, or deployment is established.

A chain-native alternative could remove the separate provider dependency only by refusing to treat an unverified local snapshot or checkpoint as canonical state. The pure recovery policy in src/native/pow_bench/src/consensus_native_recovery_gate_candidate.rs is now called by the QZBE candidate node after store open and optional peer sync. It checks whether the retained canonical ancestry reaches the Genesis base and exposes point-in-time recovery_readiness_at_startup / recovery_detail_at_startup in the loopback read-only status RPC. If Genesis ancestry is incomplete or invalid, startup fails closed. Without explicit peer reconciliation the reported recovery state remains SYNCING. CP-0437 uses bounded QZBE archive transfer over authenticated Noise sessions to statically pinned peers, binds Genesis/profile, hashes ordered envelope bytes, validates every envelope under consensus, and compares height/tip/state-root/cumulative chainwork. The --sync-from-peers option remains restricted to the explicit zero-value test profile and requires at least two statically pinned peers. The runtime now additionally compares the final summaries from every configured peer; disagreement on height, tip, root or work aborts startup. This is a startup snapshot, not a continuously refreshed status, and it does not attest that peers are independently operated.

## 2. Required design if external CAS is removed

Source of truth: the valid chain of blocks from the frozen Genesis, not a locally restored balance database or an unverified checkpoint.

Startup and recovery: replay and validate archived blocks from Genesis, including transaction authentication, state transitions, difficulty/proof of work, cumulative chainwork, reward schedule, issuance accounting and all state roots. A stale or restored directory is only an old local view; it must be treated as behind and reconciled against independently observed, valid peer histories before the node enters READY state.

Snapshots: no pruned or checkpoint-only snapshot may be accepted as authoritative unless its full ancestry and validity are independently reconstructed or verified by a separately approved trust model. The conservative first release is to retain and validate full block history from Genesis instead of requiring trusted snapshot restore.

Transaction safety: the RPC must expose separate SYNCING, READY and QUARANTINED states. It must not describe a local mempool transaction as confirmed. Mining on a restored/stale tip and any value-bearing wallet operation must remain disabled while replay is incomplete, the profile mismatches, peer histories conflict, or the local tip has not been reconciled. Confirmation is determined by the valid chain's cumulative work and the published confirmation policy, not a local snapshot height.

Reorganization: validate a candidate branch from a known common ancestor, recompute branch-local state, rewards, roots and cumulative work, then commit the reorganization atomically. Never select a branch just because it has greater height or a peer claims it is canonical.

Operations: publish reproducible source/binary/configuration, logs, sync state, storage format, archive retention policy, recovery procedures and explicit limitations. Multiple independently operated peers are still needed to qualify public operation and reduce dependence on one peer; a fixed operator count alone does not guarantee security.

## 3. Candidate archive-sync milestone (CP-0437)

The node can now export/import its bounded retained QZBE branch archive for an explicit zero-value test profile. The protocol limits the transfer to at most 4,096 envelopes and 64 MiB; the current in-memory archive itself also has a 1,024-height bound. It is therefore a bounded candidate synchronization path, not an unbounded full-history/archive retention solution. A fresh three-process loopback test mines three blocks, checks that two pinned source peers agree, transfers both peer archives to a new data directory, validates/imports each envelope, and proves the fresh node matches the same height, tip, state root and cumulative chainwork. The test is tracked in simulations/cp0437_qzbe_fresh_node_archive_sync.ps1 and is required in the Windows CI workflow.

This does not establish independent operators, does not solve stale-directory rollback when a restored directory contains a matching but old manifest, does not retain or serve history beyond current archive/height limits, and does not provide continuation for longer histories. Recovery status is a point-in-time startup classification; it does not continuously refresh peer liveness or gate zero-value test mining. RPC output continues to state mainnet=false and public_launch_approved=false. Gate 8 remains OPEN.

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

Gate 8 remains OPEN. Runtime startup/RPC classification and pinned-peer summary convergence are now wired, but the design remains bounded to the current archive/height limits and does not provide unbounded full-history recovery. The RPC explicitly reports mainnet=false and public_launch_approved=false; READY refers only to the candidate recovery checks at startup, not independent operator qualification or Mainnet readiness. Gate closure still requires either (A) an independently administered CAS with signed receipts and multi-host qualification, or (B) owner-accepted consensus-native recovery with retained full history from Genesis, stale-restore/deep-reorg/crash/partition tests, independent operator/reviewer evidence, and the remaining acceptance items above.

Gate 2 remains OPEN until the single v0.4 monetary profile is integrated end-to-end from the final Genesis. Gate 13 remains OPEN until a qualified public zero-value devnet and independent operators are genuinely available. CP-0440 adds an explicit public signed-transaction ingress option for zero-value easy-PoW testnet only; same-host integration does not establish outside-Internet reachability or independent operators. No native Mainnet, public value-bearing transaction path, verified QZXB/USDT pair, liquidity or authentic QZXB candles is established.
