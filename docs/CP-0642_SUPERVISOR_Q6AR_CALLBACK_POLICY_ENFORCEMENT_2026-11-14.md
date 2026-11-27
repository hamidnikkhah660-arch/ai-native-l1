# CP-0642 — Supervisor Q6AR Callback Policy Enforcement

Date: 2026-11-14  
Project: AI-NATIVE L1 / QRUN-QFP6  
Depends on: CP-0640A, CP-0640B, CP-0641  
Status: implementation and targeted callback-policy validation complete; local working tree only

## Objective

Verify that the supervisor callback does not merely carry an operator trust policy in its function signature, but actually invokes the strict Q6AR Address Book ingestion path with that exact bound policy.

## Implementation

The supervisor's Q6AR callback now delegates persistence to the single helper `persist_pinned_q6ar_with_operator_policy`. The callback still ignores anonymous/unpinned relay sessions without trust escalation. For a pinned relay, the helper passes the received advertisement, current monotonic wall-clock-derived millisecond value, and the exact `BootstrapTrustDomainPolicy` supplied to the supervisor into `ingest_pinned_q6ar_with_trust_domains`.

This avoids a second policy-free persistence path in the callback.

## Regression test

Added `supervisor_q6ar_callback_enforces_shared_operator_domain_candidate_quota`.

The test:
1. Creates a local Q6PA Address Book and binds a two-relay operator registry.
2. Gives both distinct relay static keys the same trust-domain ID with `max_candidates_per_domain = 1`.
3. Submits one candidate through the production callback helper and verifies it is persisted.
4. Submits another candidate from the second pinned relay in the same domain and verifies it is rejected while the stored record set remains unchanged.
5. Submits a candidate from a pinned key absent from the operator registry and verifies rejection and no record growth.

Targeted command:

```powershell
cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib supervisor_q6ar_callback_enforces_shared_operator_domain_candidate_quota --locked --offline
```

Result: **1 passed, 0 failed**.

The same command chain also passed:
- `cargo fmt --manifest-path src/native/pow_bench/Cargo.toml -- --check`
- `git diff --check`

## Scope and limitations

This is a local unit/integration test of the exact persistence helper used by the supervisor callback. It does not perform a live Noise handshake, bind a network listener, run multiple operating-system nodes, or demonstrate independent real-world ownership of trust domains. Those remain separate test and audit gates.

No node process was launched, no listener/port was opened, and no Public Testnet activity occurred. No commit or push was made.
