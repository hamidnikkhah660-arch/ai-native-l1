# CP-0644 — Multi-Relay Noise Same-Domain Quota Enforcement

Date: 2026-11-14  
Project: AI-NATIVE L1 / QRUN-QFP6  
Depends on: CP-0640A, CP-0640B, CP-0642, CP-0643  
Status: loopback multi-session transport integration test passed; local working tree only

## Objective

Verify that the trust-domain quota is shared across distinct pinned relay keys when Q6AR advertisements arrive through separate authenticated Noise sessions—not merely when the persistence helper is called directly.

## Test topology

The test `supervisor_q6ar_noise_listener_rejects_second_relay_in_same_operator_domain`:

1. Binds a temporary TCP listener to `127.0.0.1:0`.
2. Generates one local Noise XX server key and two different Noise XX client static keys.
3. Pins both client keys at the listener and maps both keys to the same operator trust-domain ID.
4. Sets the shared domain candidate quota to one, with a two-relay allowance.
5. Opens and binds a Q6PA Address Book before serving the sessions.
6. Runs the supervisor listener round with a two-session limit.
7. Sends the first Q6AR advertisement over client session one and confirms the candidate was persisted.
8. Sends a second Q6AR advertisement over client session two, using a different pinned relay key but the same trust domain.
9. Confirms the second callback is rejected and the original record set remains unchanged.

## Validation

Command:

```powershell
cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib supervisor_q6ar_noise_listener_rejects_second_relay_in_same_operator_domain --locked --offline
```

Result: **1 passed, 0 failed**.

The test asserts:
- two authenticated Noise sessions;
- two Q6AR requests received;
- exactly one Q6AR rejection (the second relay's over-quota candidate);
- zero application handler failures;
- exactly one persisted candidate, from relay one;
- the persisted relay key matches relay one's pinned Noise static key.

The command chain also passed:
- `cargo fmt --manifest-path src/native/pow_bench/Cargo.toml -- --check`
- `git diff --check`

## Scope and limitations

This is a real local TCP/Noise XX/Q6AR/supervisor/Q6PA integration test across two sessions. Both relay identities and their common trust-domain assignment are test fixtures. It does not prove independent real-world ownership, resilience against a determined operator controlling both relays, Internet-scale Sybil/eclipsing resistance, multi-machine behavior, NAT traversal, or PQ-secure transport key agreement.

The listener used only an ephemeral loopback port and closed after the two test sessions. No production node or public listener was launched. No commit, push, deployment, or Public Testnet activity occurred.
