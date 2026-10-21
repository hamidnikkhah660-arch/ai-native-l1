# Monetary Genesis Allocation Boundary Tests — CP-0360

Date: 2026-10-21
Branch: `public/monetary-genesis-invariants` (based on public `main`)
Scope: test-only hardening; no production consensus or issuance behavior changed.

## What the tests cover

- A zero Network ID must be rejected.
- A zero founder account ID or zero public-goods account ID must be rejected.
- A zero-value public-goods allocation must be rejected.
- Duplicate public-goods account IDs must be rejected even when the duplicate entries sum to the stated budget.
- Public-goods allocations that exceed the configured budget must be rejected.
- The exact public-goods budget may be split across two distinct accounts; the total ledger value and both individual balances are asserted.

## Validation evidence on this branch

- Focused command: `cargo test --manifest-path src/native/pow_bench/Cargo.toml --all-targets --locked --offline monetary_genesis_`
  - Result: 3 matching tests passed, 0 failed. This includes the existing exact-budget Genesis test and both new tests.
- Format command: `cargo fmt --manifest-path src/native/pow_bench/Cargo.toml --all -- --check`
  - Result: exit code 0.
- Full command: `cargo test --manifest-path src/native/pow_bench/Cargo.toml --all-targets --locked --offline`
  - Result: exit code 0; completed in 334.37 seconds.
  - Library suite: 737 passed, 0 failed.
  - `devnet_node`: 36 passed, 0 failed.
  - `private_testnet_node`: 36 passed, 0 failed.
  - Remaining binary and integration-test targets also completed without a reported failure.
- The run emitted existing unused-import/dead-code warnings in other modules; no test failures were reported.

## Explicit release boundary

These tests exercise the candidate `MonetaryLedgerState::genesis` constructor. They do **not** wire the candidate into the production node's canonical Genesis/issuance/transaction-validation path; they do not close Gate 2, Gate 8, G9–G12, or the legal/offer gate S1. They are not evidence of a launched native QZXB coin, mainnet, public liquidity, exchange listing, or received funding.

## Review request

Please review the test scope and the exact constructor invariants against the canonical monetary profile. Merge only after the repository's applicable CI/review checks complete. No mainnet or value-bearing action is proposed by this change.
