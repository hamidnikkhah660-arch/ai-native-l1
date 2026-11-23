# CP-0832 — QFP6 Persistent Q6PD Peer Session Manager

Date: 2026-11-23
Status: SOURCE IMPLEMENTED; FOCUSED TESTS PASS; NODE BINARY BUILT AND STAGED; LIVE DEPLOYMENT NOT PERFORMED
Scope: ZERO_VALUE_CANDIDATE_ONLY

## Objective

Add a bounded long-lived Q6PD Noise liveness channel so a publicly reachable QFP6 node can keep a candidate/peer transport session open, detect disconnects, and reconnect automatically. The persistent channel is deliberately separate from Q6PD record pulls, chain history synchronization, consensus validation, and operator trust.

## Implementation

### 1. New session protocol and manager

New file:
- `src/native/pow_bench/src/qrun_v06_q6pd_session_candidate.rs`

Declared from:
- `src/native/pow_bench/src/lib.rs`

The Q6PD session controls are versioned and network/profile-bound:
- `Q6SO` — session open
- `Q6SA` — open acknowledgement / capacity rejection
- `Q6SP` — heartbeat ping
- `Q6SR` — matching heartbeat pong
- `Q6SC` — orderly close

The session is liveness-only. It grants no transaction, history, consensus, or operator privilege.

### 2. Signed identity gate before persistent admission

A long-lived slot is not granted just because a remote peer completed anonymous Noise XX.

Before opening a persistent session, the peer must:
1. Complete the QFP6 Noise handshake bound to the exact network/profile.
2. Send a Q6PD signed-record announcement.
3. Pass Ed25519 signature, network/profile, endpoint and TTL verification.
4. Present a Q6PD record whose declared Noise static public key exactly equals the remote static key in that live Noise session.
5. Receive the Q6PD announcement acknowledgement, then submit the Q6SO open control.

The existing Q6PD store remains responsible for replay/high-water enforcement and durable candidate persistence. Candidate records remain hints; this does not auto-trust them or grant consensus authority. The listener now applies the exact Noise-key/record binding to Q6PA announcements generally, not just the persistent-open path.

### 3. Bounded inbound worker handoff

Files:
- `qrun_v06_peer_listener_candidate.rs`
- `qrun_v06_q6pd_session_candidate.rs`

After signed-record validation and open acceptance, the serial listener transfers the established socket and Noise state to a dedicated worker, then returns to accepting other peers.

Bounds:
- Maximum 8 persistent inbound sessions per process.
- One dedicated worker per admitted inbound session.
- Heartbeat interval: 10 seconds.
- Server read budget: 20 seconds; three missed reads close the session.
- Hard session lifetime: 6 hours.
- An RAII slot counter releases capacity when a session closes or its worker exits.

The listener's normal session budget is not increased; persistent sockets do not occupy its serial application-frame loop.

### 4. Outbound reconnect manager

Files:
- `qrun_v06_q6pd_session_candidate.rs`
- `qrun_v06_node_supervisor_candidate.rs`
- `qrun_v06_history_sync_service_candidate.rs`

Outbound persistent workers use the existing bounded TLS/SNI-or-TCP connection setup and exact Noise static-key pin. Every reconnect repeats the Noise handshake and local signed Q6PD announcement before asking for a persistent slot.

Reconnect backoff:
- Starts at 5 seconds.
- Exponential increase.
- Capped at 300 seconds.
- Shutdown-aware waits and orderly close.

The worker obtains its current signed self-record from a shared read/write slot. Supervisor self-announcement refreshes update that record, so future reconnects announce the newest signed sequence. A node without a current public signed self-record does not open long-lived outbound sessions; this intentionally excludes the present local-only Joiner configuration.

The supervisor keeps a bounded set of outbound persistent workers (at most 8) and stops them cleanly when its scoped run ends, without altering the process-wide shutdown flag.

### 5. Session-only responsibilities

The persistent session carries only open, heartbeat, pong and close controls. Existing Q6PD pull/announcement exchanges and bounded history synchronization continue using their existing helpers and budgets. A successfully contacted candidate is still rechecked on the CP-0831 five-minute success cooldown. No persistent session is treated as a vote or as proof that downloaded blockchain history is valid.

## Focused verification

All commands used Cargo offline and locked dependencies on Windows host heymed.

1. `cargo test --manifest-path src/native/pow_bench/Cargo.toml --locked --offline --lib q6pd_persistent_session_is_handed_off_and_survives_listener_round -j 1`
   - 1 passed; 0 failed.
   - Exercises a real local Noise session, a valid Ed25519 Q6PD record bound to the live Noise key, Q6PA acknowledgement, Q6SO open, listener handoff, three ping/pong cycles, Q6SC close, and capacity release.

2. `cargo test --manifest-path src/native/pow_bench/Cargo.toml --locked --offline --lib q6pd_records_are_pulled_over_pinned_noise_and_persisted_as_candidates -j 1`
   - 1 passed; 0 failed.
   - Confirms the existing pinned Q6PD record exchange still works.

3. `cargo test --manifest-path src/native/pow_bench/Cargo.toml --locked --offline --lib qrun_v06_q6pd_session_candidate::tests -j 1`
   - 3 passed; 0 failed.
   - Covers network/profile binding, request matching/replay rejection, and bounded slot capacity/release.

4. Formatting and whitespace:
   - `rustfmt --check --edition 2021` passed for all five changed Rust files.
   - `git diff --check` passed for all five changed Rust files.

5. Binary:
   - `cargo build --manifest-path src/native/pow_bench/Cargo.toml --locked --offline --bin qrun_v06_node -j 1`
   - Exit code 0.
   - Existing unrelated unused/dead-code warnings remain; no build errors.

## Source hashes (SHA-256)

- `qrun_v06_q6pd_session_candidate.rs`: `B9AB2E8368561E8F2E0AC88DCE6CDC996BE0E747D85398A75BC182D5C2757E5F`
- `qrun_v06_peer_listener_candidate.rs`: `692B6F521A639A3967A6BD3D385F6DCECFA8AE4ED6FC46385804B14A435DFB7C`
- `qrun_v06_history_sync_service_candidate.rs`: `C20D5781672AF46A721EA83CAA5D3C7BA9FA2899406ACDDE81944B89CC4317E3`
- `qrun_v06_node_supervisor_candidate.rs`: `9601A4AD4D426FA7A50AA71C3683B007FAB7ACE479CDB2D63050837017C6935A`
- `lib.rs`: `34CECD52EE3D426792DDFD8CC45260F1BE7890D59339072DBD752A89AB945E64`

File-specific pre-change backups:
- `qrun_v06_peer_listener_candidate.rs.pre-cp0832-persistent-q6pd-sessions-20261123.bak`
- `qrun_v06_history_sync_service_candidate.rs.pre-cp0832-persistent-q6pd-sessions-20261123.bak`
- `qrun_v06_node_supervisor_candidate.rs.pre-cp0832-persistent-q6pd-sessions-20261123.bak`
- `lib.rs.pre-cp0832-persistent-q6pd-sessions-20261123.bak`

The new `qrun_v06_q6pd_session_candidate.rs` is a new source file.

## Binary artifact

Built executable SHA-256:
`19B1C6199D7DCF6256EA25B16FD1626CBE520A57F8602E3BED5F7F4AF8B1A827`

Staged, not deployed:
`D:\QJ6\CP0832_QFP6_PERSISTENT_Q6PD_SESSION_CANDIDATE_20261123\qrun_v06_node_CP0832_PERSISTENT_Q6PD_SESSIONS.exe`

The staged copy's SHA-256 was independently checked and matches the built executable.

## Live runtime safety check

No existing Seed or Joiner process, runtime config, Q6PD store, TPM/identity key, bootstrap pin, firewall, NAT, or Funnel setting was changed. No node was restarted.

Read-only check after the build:
- 30336 — PID 21460 — LISTENING
- 30337 — PID 5800 — LISTENING
- 31434 — PID 19720 — LISTENING

## Explicit limits

- No independently operated external host has yet joined or maintained a public session. The successful persistent-session test is local Noise/TCP interoperability on this Windows host, not a public multi-host mesh test.
- Current live Joiner still has self-announcement disabled and no independently verified public endpoint, so the new manager intentionally does not originate persistent sessions from that Joiner.
- Current live Seed configuration still has Q6PD peer pull disabled; it serves inbound Q6PD records but does not initiate outbound persistent sessions.
- Existing running executables remain CP-0830 / earlier artifacts; CP-0832 is a built candidate only.
- Persistent Q6PD liveness is not consensus authority, not chain-history validation, and not Mainnet authorization.
- Network status remains `ZERO_VALUE_CANDIDATE_ONLY`; Mainnet and market authorization remain NOT_GRANTED.

## Next gate

Roll out the candidate only to a controlled, independently reachable node with a protected Noise identity and valid signed public Q6PD self-record. Then verify bidirectional persistent-session interoperability, reconnect after peer/process/network interruption, replay/flood/capacity behavior, and independent-host address gossip before any broader public testnet claim.
