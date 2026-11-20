# CP-0643 — Loopback Noise/Q6AR Supervisor Domain Enforcement

Date: 2026-11-14  
Project: AI-NATIVE L1 / QRUN-QFP6  
Depends on: CP-0640A, CP-0640B, CP-0641, CP-0642  
Status: loopback transport integration test passed; local working tree only

## Objective

Exercise the complete local ingress seam from an actual encrypted Noise session through the Q6AR-aware supervisor listener round and into the persistent Q6PA Address Book under the operator-bound trust-domain policy.

## Test topology

The test `supervisor_q6ar_pinned_noise_listener_persists_only_under_bound_operator_policy`:

1. Binds a temporary TCP listener to `127.0.0.1:0` (ephemeral loopback port only).
2. Generates local Noise XX server and client keypairs.
3. Uses the client's exact Noise static public key as both the listener's pinned Q6AR relay key and the relay key assigned in the operator trust-domain registry.
4. Opens a temporary Q6PA Address Book and binds the operator registry before accepting the test session.
5. Sends an encoded Q6AR advertisement as an encrypted Noise record.
6. Runs the same supervisor listener-round function and strict callback persistence helper used by the permissionless runtime path.
7. Verifies that the Address Book contains exactly one record with the advertised endpoint and peer static key, the exact pinned relay static key, and pinned provenance.

## Validation

Command:

```powershell
cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib supervisor_q6ar_pinned_noise_listener_persists_only_under_bound_operator_policy --locked --offline
```

Result: **1 passed, 0 failed**.

The test command also completed:
- `cargo fmt --manifest-path src/native/pow_bench/Cargo.toml -- --check`: passed.
- `git diff --check`: passed.

## What this proves—and does not prove

It proves the local encrypted Noise XX -> pinned relay provenance -> Q6AR decode -> supervisor callback -> strict operator-policy ingestion -> persistent Address Book path works as one loopback integration test.

It does not prove:
- operation across multiple independently provisioned physical nodes;
- real-world organizational independence of trust domains;
- resilience to adaptive Sybil/eclipsing/bootstrap-poisoning campaigns;
- public Internet reachability, NAT traversal, or production availability;
- PQ-secure Noise transport key agreement;
- readiness for Public Testnet, production, or Mainnet.

The test's TCP listener used an ephemeral loopback port and was closed when the test thread joined. No node or production listener was launched. No commit, push, deployment, or Public Testnet activity occurred.
