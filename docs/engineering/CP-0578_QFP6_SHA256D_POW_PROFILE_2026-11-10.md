# CP-0578 - QFP6 v0.6 SHA-256d consensus profile candidate

**Date:** 2026-11-10
**Status:** Implementation candidate; not a frozen Mainnet profile or launch authorization
**Parent:** CP-0577 / QFP6 checkpoint-segment read-only audit

## Decision boundary

The QFP6 v0.6 consensus candidate now uses SHA-256d proof of work. The prior implementation exposed only Argon2id in PowAlgorithm, and the Q6CP v1 profile encoded only that algorithm. This change gives v0.6 an explicit SHA-256d profile without silently reinterpreting prior Q6CP bytes.

SHA-256d means SHA256(SHA256(canonical_pow_header_bytes)). It is a proof-of-work hash selection; it is **not** a post-quantum signature scheme and must not be advertised as quantum-resistant.

## Implemented in this candidate

- Adds PowAlgorithm::Sha256d and deterministic double-SHA-256 over canonical QFP6 PoW header bytes.
- Keeps Argon2id available for legacy, research, and devnet profiles.
- Adds ConsensusParameters::qrun_v06_sha256d_candidate() with protocol version 6 and SHA-256d parameters. Its target is inherited from the easy candidate-testnet fixture and is **not** a calibrated production target.
- Bumps Q6CP from version 1 to version 2. Q6CP v2 uses algorithm ID 2 for SHA-256d and requires the Argon2-only memory, iteration, and lane fields to be zero. Q6CP v1 is rejected rather than reinterpreted.
- Requires SHA-256d when constructing or decoding the QFP6 v0.6 Q6CP profile.
- Updates consensus fingerprints and algorithm-ID encoders so the selected PoW algorithm is committed consistently.
- Makes QFP6 bootstrap preflight report SHA-256d.
- Updates the QFP6 preflight test fixture to build a valid Q6CP v2 SHA-256d profile.

## v0.5 compatibility check

- The v0.5 calibrated candidate remains Argon2id with 64 MiB memory, one iteration, one lane, and a 32-byte output.
- The v0.5 calibrated profile remains fee-only: its initial block subsidy is zero. The v0.5 production-intent mode selector continues to choose this Argon2id profile for Public Alpha and Mainnet modes.
- The legacy v0.5 Genesis candidate credits the full 10B supply cap to a single selected owner account. Combined with its zero post-Genesis subsidy, this is **not** the revised multi-bucket economics or a 3B mining-emission model; the v0.5 Genesis must not be reused as the current intended Mainnet Genesis.
- QFP5 wire, checkpoint, Genesis, history archive, Noise transport, fork/reorg, restart, and v0.5 runtime tests were exercised. The standalone qrun_v05_pow_local_node target passed all 43 tests.
- The generic algorithm fingerprint encoders now have an explicit identifier for SHA-256d, while the existing Argon2id identifier remains unchanged. The v0.5 calibrated runtime profile itself was not migrated to SHA-256d.

## Verification observed on 2026-11-10

- SHA-256d golden-vector and parameter-validation tests passed.
- The first full run completed all 1,305 library tests successfully before entering binary targets.
- Q6CP v2 codec and identity tests passed; Q6CP v1 and Argon2id v0.6 profiles are rejected.
- QFP6 miner output was imported by fork choice using the same SHA-256d profile.
- qrun_v06_node: 17/17 binary tests passed after updating the stale preflight fixture to Q6CP v2.
- qrun_v05_pow_local_node: 43/43 binary tests passed.
- cargo fmt --all -- --check passed.
- cargo check --all-targets --locked --offline passed.
- git diff --check passed.

The first full cargo test --all-targets attempt exposed a stale Argon2id preflight fixture in qrun_v06_node. The fixture was corrected and the complete `cargo test --all-targets --locked --offline` command was rerun end-to-end on 2026-11-10; it completed with exit code 0 (all test targets passed). The run took approximately 347.61 seconds. `cargo fmt --all -- --check`, `cargo check --all-targets --locked --offline`, and `git diff --check` were also verified in this candidate worktree.

## Not claimed / still required

- The candidate-testnet target is not suitable for a public Mainnet. SHA-256d difficulty, target spacing, retarget bounds, expected hashrate, hardware economics, and attack-cost assumptions require independent calibration and review.
- The SHA-256d path must be independently reimplemented and cross-client vectors checked before any consensus freeze.
- QFP6 producer, importer, fork choice, durable store, recovery, snapshots, and independent peers must all consume the same Q6CP v2 profile on an actual separately operated Devnet.
- The node executable remains preflight/probe-only. This change does not enable --run, create a Genesis, start public P2P, issue coins, or authorize Mainnet.
- ML-DSA-65 remains candidate-only in the current node preflight. SHA-256d does not make the chain post-quantum; production signature verification, wallet key migration, and independent cryptographic review remain separate gates.
- The existing 10B eight-bucket policy and CP-0566E mining-dust/burn-reserve decision are not changed by this work.
