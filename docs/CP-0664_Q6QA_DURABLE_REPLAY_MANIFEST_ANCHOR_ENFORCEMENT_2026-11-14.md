# CP-0664 — Q6QA/Q6TS durable market-history replay and anchor enforcement

Date: 2026-11-14
Branch: `feat/cp0600-bootstrap-sync-startup`
State: targeted local restart/replay qualification PASS; source changes remain in the pre-existing dirty worktree.

## Scope

Closed the final restart assertion in the local Q6PB Noise listener integration test:

`qfp6_noise_q6pb_listener_rejects_unqualified_quote_then_accepts_height_bound_q6qa`

The test exercises the Q6PN v2 profile commitment, a dual-signed Q6TS trust-floor record, and a height-bound Q6QA authorization for the test quote asset. The listener rejects the unqualified quote path and admits the Q6QA-authorized block. It then closes the first runtime and reopens the same durable store.

## Restart and fail-closed assertions

- A reopen attempt with no independently supplied manifest anchor returns an error.
- The Q6TS recovery source read counter remains exactly zero after that rejection, proving the durable history is not replayed/trusted before the anchor requirement is satisfied.
- Reopening with the captured nonzero manifest anchor succeeds.
- The recovery path freshly reloads the Q6TS source exactly once and re-runs Q6TS/Q6QA verification.
- The recovered runtime preserves the pre-restart height, tip, state root, manifest generation, and manifest anchor.

## Validation

Targeted command:

```powershell
cargo fmt --manifest-path src/native/pow_bench/Cargo.toml
cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib qfp6_noise_q6pb_listener_rejects_unqualified_quote_then_accepts_height_bound_q6qa --locked --offline
cargo fmt --manifest-path src/native/pow_bench/Cargo.toml -- --check
```

Result: **1 passed, 0 failed**. The test includes both the unanchored-reopen rejection assertion and the subsequent anchored-recovery assertions.

Additional checks:

- `git diff --check`: PASS.
- `cargo fmt --manifest-path src/native/pow_bench/Cargo.toml -- --check`: PASS.

The broader regression set was previously qualified with CP-0662/CP-0663 and the recorded CP-0664 pre-final-assertion validation run; this checkpoint does not claim that the entire suite was rerun after the last assertion was added.

## Qualification boundary

This is a deterministic local integration test using test keys, test trust fixtures, and a local socket/store. The test does not establish independently administered public nodes, production trust-floor governance, live AWS/DynamoDB IAM separation, publicly reachable seed hosts, external inbound TCP, production quote-asset reserves, exchange liquidity, or real-value trading. The test quote asset is not USDT.

No Public Testnet launch, public mining, mainnet operation, or trading authorization is implied by this checkpoint.

## Repository handling

Only this checkpoint document is intended for the CP-0664 documentation commit. The listener source and other working-tree changes remain unstaged because the worktree contains substantial pre-existing modifications and untracked project artifacts. No push or deployment is part of this checkpoint.
