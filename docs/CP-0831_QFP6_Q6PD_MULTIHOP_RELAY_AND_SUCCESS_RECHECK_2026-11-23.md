# CP-0831 — QFP6 Q6PD multi-hop relay and candidate success recheck

Date: 2026-11-23
Status: SOURCE CHANGES APPLIED; TWO FOCUSED TESTS PASS; LIVE RUNTIME UNCHANGED
Scope: zero-value public-testnet candidate only

## Changes

### 1. Multi-hop signed-record relay coverage
File: `src/native/pow_bench/src/qrun_v06_peer_discovery_store_candidate.rs`

Added `signed_records_relay_across_multiple_candidate_stores`:
- Origin ingests one Ed25519-signed Q6PD peer record.
- Relay obtains the record through the bounded Q6PG/Q6PS pull response and ingests it into its own independent store.
- Downstream obtains the same record from Relay and ingests it into a third store.
- The test verifies the stable peer ID, sequence 7, and durable sequence watermark at the downstream store.

This covers the store-level three-hop relay path. It does not constitute a live, independent-host, public-network interoperability test.

### 2. Successful candidate contact cooldown
File: `src/native/pow_bench/src/qrun_v06_node_supervisor_candidate.rs`

- Added `QRUN_V06_Q6PD_CANDIDATE_SUCCESS_RECHECK_INTERVAL = 300s`.
- After a successful signed-record exchange over a Noise session whose remote static key matches the signed candidate record, the scheduler now records a five-minute success recheck time instead of deleting the candidate's retry-map entry.
- This prevents repeatedly redialing the same successfully contacted candidate every 30-second scheduler cycle.
- Renamed the success event from `QFP6_Q6PD_AUTO_DIAL_CONNECTED` to `QFP6_Q6PD_AUTO_DIAL_AUTHENTICATED`; the bounded helper closes its socket on return, so this event does not claim a long-lived connection.
- Existing failure exponential backoff remains unchanged.
- Auto-trust remains false. A signed candidate is not promoted to an operator-approved peer or consensus authority.

## Verification

Both focused offline tests passed on Windows host heymed:

1. `cargo test --manifest-path src/native/pow_bench/Cargo.toml --locked --offline --lib signed_records_relay_across_multiple_candidate_stores -j 1`
   - 1 passed; 0 failed.
2. `cargo test --manifest-path src/native/pow_bench/Cargo.toml --locked --offline --lib q6pd_discovery_refresh_waits_for_five_minute_interval -j 1`
   - 1 passed; 0 failed.

Formatting and whitespace:
- `rustfmt --check --edition 2021` passed for both edited Rust files.
- `git diff --check` passed for both edited Rust files.

Existing warnings in unrelated AWS DynamoDB code remain; no build error was reported by either focused test.

## Source hashes

- `qrun_v06_node_supervisor_candidate.rs`: `3D82324B28B28DFCCFAC336A6F16769077A932D4E142FD9622CACA89AB9A0520`
- `qrun_v06_peer_discovery_store_candidate.rs`: `6FB5F82F47509607293CA1272D6B6F29481450BE119D730D2F984F80050F7568`

File-specific pre-change backups:
- `qrun_v06_node_supervisor_candidate.rs.pre-cp0831-q6pd-success-cooldown-20261123.bak`
- `qrun_v06_peer_discovery_store_candidate.rs.pre-cp0831-multihop-relay-test-20261123.bak`

## Runtime safety / deployment state

No runtime binary, configuration, identity key, TPM binding, bootstrap pin, firewall rule, Funnel setting, or live Q6PD store was modified by this checkpoint. No Seed or Joiner was stopped or restarted.

Listener ports were read-only verified as still listening:
- 30336 — PID 21460 (CP-0830 primary Seed)
- 30337 — PID 5800 (backup Seed)
- 31434 — PID 19720 (Joiner)

## Remaining limitations

- The current Q6PD auto-dial path performs a bounded, short-lived Noise exchange and then a separate bounded history-sync connection. It does not yet retain a long-lived peer socket.
- The existing application listener has a 30-second session cap and dispatches application sessions serially. Increasing that cap alone could monopolize the listener; it is not a safe way to create persistent sessions.
- A production-grade persistent session manager still needs bounded concurrent Q6PD session workers, a safe shared-store ownership/locking strategy, active-session tracking, ping/idle expiry, disconnect handling, and reconnect scheduling without weakening exact Noise-key checks.
- No independent external peer has yet joined. The only live processes and local verification remain on the same heymed Windows host.
- Public network status remains ZERO_VALUE_CANDIDATE_ONLY. Mainnet and market authorization are NOT_GRANTED.

## Next engineering gate

Design and implement a separate bounded persistent-peer session service, with isolated resource budgets and explicit session lifecycle, while preserving the existing signed-record, network/profile, TTL, replay and Noise-key checks. Do not weaken trust policy to manufacture peer counts or claim a persistent mesh before independent-host verification.
