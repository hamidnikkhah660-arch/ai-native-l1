# CP-0586 — Durable Q6TI pending-transaction journal

**Date:** 2026-11-10
**Parent:** CP-0585 / Q6TI ingress into supervised QFP6 mining
**Status:** Local implementation and targeted Windows tests pass; all-target offline Cargo check passes. Exact-head GitHub CI and independent review pending. Candidate integration only.

## Scope

CP-0585 connected authenticated Q6TI transaction submission to the QFP6 mining supervisor, but its bounded mempool was process-local. A process restart could discard transactions that had received a Q6TA Accepted response. CP-0586 adds a durable, bounded pending-transaction journal and integrates its lifecycle into the supervisor.

## Journal format and safety

- Introduces versioned Q6MJ snapshots with domain-separated SHA-256 checksums, strict frame/length/count/byte bounds, canonical QFP6 transaction encoding and duplicate-TXID rejection.
- Writes immutable generation-named snapshots. The latest complete generation is loaded at startup; up to 16 generations are retained.
- Installs new snapshots atomically without replacing an existing generation: Windows uses MoveFileExW with write-through; Unix uses a same-filesystem hard link, removes the temporary name and syncs the parent directory.
- Uses the repository's OS-backed exclusive writer lock. A second writer handle is rejected while the first is live.
- Rejects symlink/special-file journal paths and files, and cleans stale temporary files only while holding the writer lock.
- A local checksum proves snapshot integrity, not freshness. The journal is not an independent anti-rollback authority; external QAP1/provider anchors and canonical chain recovery remain authoritative.

## Supervisor integration

- Startup loads the journal only after the caller has supplied an already QAP1-recovered runtime, then revalidates every saved transaction against the recovered canonical state, Q6HA authenticator, expiry, nonce, balance and execution rules. Included, expired, conflicting or otherwise invalid entries are dropped. The pruned result is persisted before service resumes.
- A Q6TI response is decoded and its Accepted result is persisted before the listener sends Q6TA Accepted. If the durable write fails, the in-memory pool is reverted and the application handler returns an error; the supervisor requests shutdown rather than acknowledging a transaction that was not journaled.
- Q6PB canonical admission/reorganization triggers mempool reconciliation and a new journal snapshot.
- Pending transfers selected for mining are persisted before the mining attempt. After QAP1 mining/commit, the pool is reconciled against the new canonical state and the resulting snapshot is installed.
- The supervisor report exposes the current journal generation plus pending mempool count and bytes.

## Local verification on heymed

Using the locked offline Cargo dependency set:

- Journal snapshot, checksum/length and single-writer/restart recovery tests: **3 passed**.
- QFP6 Noise peer → durable QAP1 admission → local mining supervisor integration test with the journal enabled: **1 passed**.
- `cargo check --all-targets --locked --offline`: passed.
- `cargo fmt --check`: passed.
- `git diff --check`: passed.

These are local Windows tests. They are not proof of a separate independently operated NetBird peer, public service availability, fresh-node public synchronization or a value-bearing public transaction.

## Acceptance semantics and production limits

- Q6TA Accepted now means the transaction is pending in the bounded mempool **and present in a durable journal snapshot**. It still does not mean mined, block-confirmed, QAP1-finalized, externally settled or tradeable.
- The journal persists only pending transaction data. It is not canonical history, a block archive, a settlement ledger or an anti-rollback anchor. Restored transactions must always be reconciled against the independently recovered canonical QAP1 state.
- The `qrun_v06_node` executable remains preflight/read-only. CP-0586 does not create a complete production bootstrap that verifies and composes production Q6PN/Q6TS/Q6CP/Genesis trust material, Provider/Q6EA services, durable fork store, QAP1 recovery, protected node identities, the supervisor and a production miner.
- Production fees, issuance/supply-cap enforcement, miner reward payouts, independent operator-node qualification, fresh-node history sync, public RPC/explorer APIs, and production service management remain open.
- Noise remains `Noise_XX_25519_ChaChaPoly_SHA256` (classical X25519), not post-quantum transport security. The ML-DSA-65 verifier candidate still requires independent cryptographic/security review.

## Remaining gates before public Devnet/Mainnet and trading

1. Build and verify a fail-closed production node bootstrap and long-running service around the recovered QFP6/QAP1 supervisor.
2. Add external freshness/anti-rollback protection for the pending journal where operationally required; retain canonical QAP1 as settlement truth.
3. Qualify the CP-0586 Q6TI path on independently operated nodes over the NetBird overlay, then test crash/restart, reorg, duplicate submission and fresh-node synchronization across hosts.
4. Wire validated Genesis issuance, fees, miner rewards and the 10B supply cap into the canonical durable execution path.
5. Complete independent cryptographic review and a post-quantum transport design.
6. Only after those gates, launch a public Devnet, complete production security review, publish Mainnet/wallet/RPC/explorer endpoints, and then establish real market-maker/exchange liquidity and verifiable QZXB/USDT settlement.

No public Mainnet, public QZXB balance, public value-bearing transfer, miner payout or QZXB/USDT market is activated or claimed by CP-0586.
