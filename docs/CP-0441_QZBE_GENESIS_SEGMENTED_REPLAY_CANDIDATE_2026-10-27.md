# CP-0441 — Genesis-rooted segmented QZBE history replay

Date: 2026-10-27

Status: **Candidate implementation and focused/unit integration tests pass locally. Durable unbounded full-history retention and independent-operator qualification remain OPEN.**

## Change

The new `qzbe_history_replay_candidate` module replays canonical QZBE envelopes from the frozen monetary Genesis using a bounded in-memory fork-choice segment. It requires sequential heights and exact parent links, then passes every envelope through the existing QZBE decoder, PoW verifier, transaction authenticator, state-transition/reward checks, and cumulative-work fork choice.

At the configured segment boundary, the candidate derives a checkpoint from the just-replayed canonical state, binds it to the previous checkpoint commitment, and starts the next bounded segment from that derived checkpoint. Checkpoints are replay outputs, not an independently trusted local file. The result reports height, tip digest, state root, cumulative chainwork, block count and checkpoint rotations.

The QZBE candidate runtime's startup history check now reconstructs the canonical path from the stored envelopes, re-executes that sequence from Genesis through this segmented replay path, and compares the resulting height/tip/state root/cumulative work with the opened store. A mismatched result cannot be classified as a successful full-history replay.

## Local verification

- `cargo test --manifest-path src/native/pow_bench/Cargo.toml qzbe_history_replay_candidate --lib`: **3 passed**. Tests compare tip, state root and chainwork after 5 canonical blocks with segment size 2; reject reordered/gapped histories and invalid segment sizes; and verify empty history resolves to Genesis.
- `cargo test --manifest-path src/native/pow_bench/Cargo.toml --bin qzbe_v04_peer_node`: **24 passed**.
- `simulations/cp0414_qzbe_authenticated_transaction_loopback.ps1`: PASS. Two local nodes accepted a signed 2,500-atom candidate transaction, rejected an invalid signature atomically, converged on replay, and reported a two-confirmation receipt for the test chain.
- `simulations/cp0437_qzbe_fresh_node_archive_sync.ps1`: PASS. A third local node imported a three-block candidate history from two pinned local peers and matched height/tip/state root/chainwork.
- `cargo fmt --manifest-path src/native/pow_bench/Cargo.toml --all`: PASS.

The integration exercises are zero-value, same-host testnet candidates. They do not prove Internet reachability, independently operated peers, security audit completion, or Mainnet readiness.

## Remaining boundaries

This change improves the correctness of startup replay for the currently retained canonical path. It does **not** itself remove the existing archive bound: the QZBE candidate's envelope archive is capped at 4,096 entries / 64 MiB and each fork-choice segment is limited to 1,024 heights. The bounded peer-sync protocol and durable store are not yet an unbounded, paginated, restart-safe full-history source from Genesis.

Before Gate 8 can close, durable multi-segment history retention/serving must be integrated; stale whole-directory restore, deep reorg, crash/commit interruption, competing branches, network partition/rejoin and wrong-network history must be exercised; and an independent operator/reviewer must verify the threat model and evidence. Peer agreement on one host is not independence. The node continues to report `mainnet=false` and `public_launch_approved=false`; public zero-value devnet qualification, canonical production runtime activation, Mainnet key ceremony/security review and the live market/liquidity path remain separate open requirements.

No real QZXB/USDT pool, reserves, liquidity or authentic market candles are created by this change.
