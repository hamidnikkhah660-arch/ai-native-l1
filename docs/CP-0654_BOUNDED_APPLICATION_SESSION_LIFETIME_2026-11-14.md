# CP-0654 — Bounded QFP6 Application-Session Lifetime

Date: 2026-11-14  
Project: AI-NATIVE L1 / QRUN-QFP6  
Branch: `feat/cp0600-bootstrap-sync-startup`  
Observed base HEAD: `df673d07050688a64b26822d97e6ea609b68ce88`  
Depends on: CP-0653  
Status: **implemented in local candidate worktree; local checks passed; public listener remains unqualified**

## 1. Objective

CP-0653 bounded the unauthenticated Noise XX handshake stage, but a peer that completed a handshake could still occupy the single canonical application-processing path by sending authenticated records slowly. This checkpoint places an absolute wall-clock limit on each established application session while retaining a per-record I/O deadline.

## 2. Rules applied

- Maximum lifetime of one established inbound application session: **30 seconds**.
- Maximum time spent waiting for one encrypted application record: **5 seconds**.
- Each record read receives the smaller of the remaining session lifetime and the five-second record budget.
- When the absolute session deadline expires, the listener closes that session and returns to the outer accept/completion loop.
- The per-session request count, replay guard, Q6AR restrictions, history egress limit and canonical callback serialization remain in place.
- This does not create parallel application-state writers. All Q6TI/Q6TA, Q6HI/Q6HR/Q6HS, Q6AR persistence and canonical state callbacks still run on the listener thread.

The bounded read budget is enforced in the Noise transport's existing deadline-aware record reader. The absolute deadline is measured with `Instant`, not wall-clock time.

## 3. Verification

- `application_session_has_absolute_lifetime_and_per_record_read_budget` — **PASS, 1/1**.
  - A long session receives at most the five-second per-record budget.
  - A session with only two seconds remaining receives a two-second read budget.
  - An expired session receives no further read budget.
- QFP6 listener regression family `qfp6_listener_` — **PASS, 9/9**.
- Bounded handshake worker tests `bounded_handshake_worker` — **PASS, 2/2**.
- Two independent Noise sources with matching history — **PASS, 1/1**.
- Two independent Noise sources with divergent valid histories — **PASS, 1/1** (rejected by agreement gate).
- Pinned Noise history sync, heavier competing branch import and restart recovery — **PASS, 1/1**.
- `cargo check --manifest-path src/native/pow_bench/Cargo.toml --bins --locked --offline` — **PASS**, exit code 0.
- `cargo fmt --manifest-path src/native/pow_bench/Cargo.toml -- --check` and `git diff --check` — **PASS** in the final candidate-tree hygiene pass.

Pre-existing unused-import/dead-code warnings remain in unrelated legacy modules and binaries.

## 4. Limits

- The main application-processing path is still single-session-at-a-time. CP-0654 limits a single peer's occupancy to at most 30 seconds of session wall time (apart from a callback already executing); it does not establish fully concurrent or fair round-robin application processing.
- The 30-second/5-second limits are candidate defaults, not values calibrated by public Internet load testing.
- A callback's own external I/O or durable-store operation must still have a bounded deadline. This session deadline is checked before each record read and cannot preempt a callback already executing.
- Anonymous inbound Noise XX remains unauthenticated and uses classical X25519. Peer identity/authentication, post-quantum transport, public peer discovery, NAT fairness and distributed DoS qualification remain open.
- No external multi-host public listener test is implied by local loopback tests.

The release manifest records:
- `application_state_processing_serialized=true`
- `application_session_max_duration_seconds=30`
- `application_record_read_timeout_seconds=5`

It deliberately keeps `public_listener_qualified=false`, `inbound_peer_identity_authenticated=false`, `public_peer_discovery_qualified=false`, `public_mining_authorized=false` and `production_authorized=false`.

## 5. Operational boundary

- No QFP6 node was launched.
- No public listener or port 30333 was opened.
- No firewall/router/port-forward was changed.
- No commit, push, merge, tag, release or public Testnet deployment was created.
- Existing uncommitted project changes were preserved.

## 6. Decision

The candidate now bounds both the pre-authentication Noise handshake stage (CP-0653) and the post-handshake idle/application-session stage (CP-0654), while preserving serialized canonical state access. This reduces one-node session monopolization risks but does not prove public DoS resistance or Internet-scale readiness.

**Public Testnet remains NO-GO until real protected operator identities, final signed CP-0651 Genesis/Q6GD/Q6CP/Q6PN artifacts, independent seed hosts/pins, external multi-host replay/restart convergence, and independent security/consensus/economics reviews are completed.**
