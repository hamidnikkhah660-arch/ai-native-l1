# CP-0646 — Independent Trust-Domain Noise Budget Isolation

Date: 2026-11-14  
Project: AI-NATIVE L1 / QRUN-QFP6  
Depends on: CP-0640B, CP-0642, CP-0643, CP-0644  
Status: loopback multi-session transport integration test passed; local working tree only

## Objective

Prove that one trust domain's candidate consumption does not consume another domain's independently provisioned budget, through separate pinned Noise sessions and the actual supervisor listener-round callback.

## Test topology

The test supervisor_q6ar_noise_listener_preserves_independent_domain_budgets:

1. Binds one temporary TCP listener to 127.0.0.1:0.
2. Creates two different Noise XX client static keys and pins both at the listener.
3. Maps relay one to domain one and relay two to domain two.
4. Sets both per-domain candidate limits to one and both per-domain relay limits to one.
5. Binds the local Q6PA Address Book to that registry.
6. Sends one Q6AR advertisement over each of two separate Noise sessions.
7. Verifies each callback is accepted and both relay/endpoint records are stored with the correct pinned provenance.

## Validation

Command:

```powershell
cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib supervisor_q6ar_noise_listener_preserves_independent_domain_budgets --locked --offline
```

Result: **1 passed, 0 failed**.

Assertions confirm:
- two authenticated Noise sessions and two Q6AR requests;
- zero Q6AR rejections and zero application handler failures;
- both callbacks accepted despite each domain having a one-candidate limit;
- exactly two stored candidates with the expected endpoint and the corresponding pinned relay key.

Paired with CP-0644, this verifies both sides of the quota boundary over loopback Noise sessions:
- different relay keys in the same domain share one budget and overflow is rejected;
- relay keys in different domains have independent budgets and are both admitted.

The command chain also passed:
- cargo fmt --manifest-path src/native/pow_bench/Cargo.toml -- --check
- git diff --check

## Scope and limitations

This is a two-session local TCP/Noise XX/Q6AR/supervisor/Q6PA integration test. Domain identities and their independent administrative ownership are test fixtures. It does not prove real-world organizational independence, multi-machine behavior, adaptive Sybil/eclipse resistance, public Internet readiness, or PQ-secure transport key agreement.

The listener used only an ephemeral loopback port and closed after the two sessions. No production node/public listener was launched. No commit, push, deployment, or Public Testnet activity occurred.
