# CP-0365 — PMT4 Overclaimed Reward Import Atomicity

Date: 2026-10-21
Base: current public `main` after PRs #20 and #21
Scope: test-only change to the PMT4/PFM4 import regression suite; no production transition code changed.

## What this closes in the test suite

Extended `signed_identity_runtime_tests::monetary_v4_import_refuses_pmt3_and_overclaimed_reward_without_mutation_then_commits_pmt4_idempotently` in `src/native/pow_bench/src/bin/private_testnet_node.rs`.

The test now:
1. Captures the initial canonical height, manifest anchor, archive length, and exact encoded monetary state snapshot.
2. Confirms a legacy PMT3 payload is rejected without advancing canonical height or changing the manifest anchor.
3. Creates a PMT4 block whose claimed subsidy is one atom above the scheduled value while keeping the original decoded header/state-root fields.
4. Confirms import rejects the overclaimed reward at the reward-schedule boundary.
5. Asserts rejection is atomic: canonical height stays zero; manifest anchor and archive length stay unchanged; encoded monetary snapshot is byte-for-byte unchanged.
6. Imports the valid PMT4 block and checks accepted status, canonical height 1, and startup archive snapshot invalidation/refresh.
7. Retains the existing PMT4 profile-bound ACK assertions and idempotent duplicate-import checks.

## Validation on the Windows checkout

- Focused test:
  `cargo test --manifest-path src/native/pow_bench/Cargo.toml --bin private_testnet_node --locked --offline signed_identity_runtime_tests::monetary_v4_import_refuses_pmt3_and_overclaimed_reward_without_mutation_then_commits_pmt4_idempotently -- --exact --nocapture`
  - Result: 1 passed, 0 failed.
- Entire `private_testnet_node` test target:
  `cargo test --manifest-path src/native/pow_bench/Cargo.toml --bin private_testnet_node --locked --offline -- --test-threads=1`
  - Result: 36 passed, 0 failed.
- `cargo fmt --manifest-path src/native/pow_bench/Cargo.toml --all -- --check`: passed.
- `cargo check --manifest-path src/native/pow_bench/Cargo.toml --all-targets --locked --offline`: passed.
- Existing unused/dead-code warnings in surrounding modules remain; they are not newly introduced by this test.
- Full regression: `cargo test --manifest-path src/native/pow_bench/Cargo.toml --all-targets --locked --offline -- --test-threads=1`: PASS, exit code 0, runtime 562.85 seconds.
  - Library: 738 passed, 0 failed.
  - `devnet_node`: 36 passed, 0 failed.
  - `private_testnet_node`: 36 passed, 0 failed.
  - Remaining binary, integration and example targets also completed without failures.
- Full Linux GitHub Actions CI remains required before merge; local Windows validation does not substitute for independent hosted Linux verification.

## Release boundary

This is regression coverage for a candidate PMT4/PFM4 import path. It does not alter consensus or runtime behavior and does not establish the production canonical Genesis/issuance path. Gate 2 and Gate 8 remain OPEN; production mining parameters, public transaction admission/RPC, independent multi-node agreement, independent audit, public offer/legal review and real paired-asset liquidity are separate requirements.

No native QZXB Mainnet launch, public issuance, market/liquidity, listing, audit or revenue is claimed.
