# CP-0592 ? Permissionless Q6TI, durable mempool and bounded mining service

## Scope
- Expose an immutable fork-choice snapshot from the Genesis-pinned permissionless runtime.
- Add a permissionless service adapter that restores and revalidates Q6MJ pending transactions against the recovered canonical state.
- Route authenticated-session Q6TI submissions through the existing Q6HA transaction authenticator, per-session replay guard, bounded native mempool and durable journal. Q6TA Accepted is sent only after the pending snapshot is installed.
- Select deterministic native-transfer batches, mine on the exact canonical parent with the existing bounded QFP6 Argon2id miner, and submit the resulting envelope through the permissionless durable store. Remove included pending transactions only when the exact mined block becomes canonical.

## Safety boundaries
- This does not create a public listener, peer discovery, full-history network synchronization, miner payout daemon, public RPC/explorer, or Mainnet launcher.
- Candidate timestamp remains an explicit caller input; no consensus or host clock policy is silently invented.
- A durable local block commit is not network-wide finality. A pending Q6TI acceptance is not a block confirmation.
- Quote-asset operations remain excluded from this native-only base service.
- The production Genesis/network/profile identity and difficulty calibration remain unapproved/unfrozen.

## Validation
- `cargo fmt --manifest-path src/native/pow_bench/Cargo.toml -- --check`: passed.
- `cargo check --manifest-path src/native/pow_bench/Cargo.toml --all-targets --locked --offline`: passed.
- `cargo test --manifest-path src/native/pow_bench/Cargo.toml --all-targets --locked --offline`: passed; 1,340 library tests, plus all binary and integration targets, zero failures.
- Focused service tests cover exact-canonical-tip pruning and non-wrapping post-commit revalidation time.
- `git diff --check`: passed.
- Exact-head GitHub Actions CI is required before this candidate is CI-qualified.
