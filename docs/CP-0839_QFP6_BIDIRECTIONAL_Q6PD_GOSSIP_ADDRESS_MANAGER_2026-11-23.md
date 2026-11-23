# CP-0839 — QFP6 Bidirectional Q6PD Gossip and Durable Address Manager

Date: 2026-11-23
Scope: ZERO_VALUE_PUBLIC_TESTNET_CANDIDATE_ONLY
Status: SOURCE IMPLEMENTED; FOCUSED TESTS PASS; BIDIRECTIONAL NOISE INTEGRATION PASS; NODE BINARY BUILT; LIVE RUNTIME NOT DEPLOYED

## Objective

Continue from CP-0831 through CP-0838 without repeating the earlier store-only relay, persistent-session, root auto-dial, DNS failover, or outbound-only topology work.

The remaining protocol gap was that Q6PD had signed self-announcement and inventory pull, but no separate bounded message for forwarding third-party signed peer records over an established outbound Noise session. Candidate dial retry state was also primarily in-memory rather than a persistent new/tried address manager.

## 1. Bidirectional signed-record Gossip

New message pair in `qrun_v06_peer_discovery_candidate.rs`:

- `Q6PX`: bounded third-party signed-record push request.
- `Q6PY`: correlated acknowledgement with inserted/updated/duplicate/rejected counts.

The request is network/profile-bound and has a request ID. It contains a canonical peer-ID-sorted batch of up to 16 independently signed Q6PD records. The encoder and decoder check:

- Ed25519 self-signature, peer-ID derivation, Noise static key presence, endpoint and TTL;
- exact Network ID and Profile ID;
- non-expired record TTL;
- unique, strictly ordered peer IDs;
- bounded record count and frame length;
- matching request ID, domain and counts in the acknowledgement.

The receiver accepts at most one Gossip Push batch per Noise application session. It applies the existing Q6PD durable per-peer sequence high-water checks before retaining any record. A relayed record remains an untrusted address hint; it never becomes an operator pin, trusted identity, consensus vote or validator authority merely because it arrived over Noise.

The existing pinned-peer pull helper now performs both directions on the same exact-Noise-key-pinned session:

1. send `Q6PG` and receive `Q6PS`;
2. verify and persist the received records locally;
3. choose a rotating bounded batch from the local signed-record store;
4. send `Q6PX` and validate the correlated `Q6PY` acknowledgement.

The rotating batch selection ensures records beyond the first 16 are eventually offered instead of remaining permanently starved by sorted peer-ID order. A legacy peer that does not understand `Q6PX` is treated as lacking this optional capability: the successful pull is retained and the push is logged as unavailable. It does not silently upgrade that legacy peer or weaken any trust check.

This enables an outbound-only/NAT client to forward third-party peer records over an outbound Noise connection without advertising an unreachable local endpoint. Inbound reachability is only required for a node that chooses to act as a public relay.

## 2. Durable Q6PD Address Manager

New module: `qrun_v06_q6pd_address_manager_candidate.rs`.

The supervisor opens a separate persistent Address Manager beside the Q6PD signed-record store. The Q6PD record store remains the signed-record/high-water source of truth; the Address Manager stores connection-management metadata only.

Persisted entries include peer ID, signed endpoint/key snapshot, first/last seen, last attempt, last success, attempts, successes, failures, retry-after time, and last signed sequence. The file is network/profile-bound, checksummed, capacity-bounded, protected by a separate exclusive lock, and written through the Q6PD store's existing atomic-write primitive.

Selection adopts the Bitcoin AddrMan concepts of new and tried candidates:

- when both pools exist, approximately half the selections come from new candidates and half from previously successful candidates;
- selections are randomized and spread across IPv4 /16 and IPv6 /32 address groups;
- local peer ID and local Noise key are excluded;
- an endpoint/key change resets the old route's connection history;
- failed candidates receive exponential backoff starting at 30 seconds and capped at 6 hours;
- successful contacts receive a 5-minute recheck cooldown;
- the manager is bounded to 256 entries and 128 KiB.

The manager never approves or mutates a signed Noise key. A candidate is dialed only after its Q6PD record passes signature, network/profile, endpoint, TTL and replay/high-water checks; the live Noise handshake must then match the exact static key contained in that signed record.

The supervisor now records attempt/success/failure through this persistent manager rather than relying on the earlier process-local candidate backoff map.

## 3. Listener and storage integration

- `qrun_v06_peer_listener_candidate.rs` recognises `Q6PX`, enforces the frame/session bounds, verifies the batch, applies the replay guard, calls the Q6PD store handler and sends `Q6PY`.
- `qrun_v06_node_supervisor_candidate.rs` ingests each verified third-party record in the durable Q6PD store and mirrors it into the Address Manager as a candidate only.
- Q6PA self-announcements also update the Address Manager after their signed record is verified and persisted.
- `qrun_v06_peer_discovery_store_candidate.rs` exposes a bounded, rotating current-record batch for gossip and a separate path for the Address Manager. The existing atomic file writer is shared with the manager.

## 4. Focused verification

All commands ran on Windows host heymed using locked offline Cargo dependencies.

- `rustfmt --check --edition 2021` on all changed Rust source files: PASS.
- `cargo test --locked --offline --lib qrun_v06_q6pd_address_manager_candidate::tests -j 1`: 3 passed, 0 failed.
  - durable restart/reload and exponential failure backoff;
  - tried-pool success cooldown;
  - self-exclusion and exact signed Noise-key preservation.
- `cargo test --locked --offline --lib qrun_v06_peer_discovery_candidate::tests::q6pd_gossip_push_round_trips_signed_records_and_ack_counts -j 1`: 1 passed, 0 failed. Also verifies tampered-record rejection.
- `cargo test --locked --offline --bin qrun_v06_node public_testnet_seed_and_joining_topology_are_enforced -j 1`: 1 passed, 0 failed. Existing Seed/Relay rules remain, and the NAT-friendly joining branch remains loopback-only and requires pinned public bootstrap plus Q6PD discovery/pull.
- `cargo test --locked --offline --lib q6pd_pull_and_bidirectional_gossip_push_run_over_one_pinned_noise_session -j 1`: 1 passed, 0 failed.

### Bidirectional Noise integration test

The upgraded integration test uses one real local Noise session between a client and a listening relay:

1. Relay Store A begins with signed peer record A.
2. Client Store begins with independently signed third-party record C.
3. Client pulls A over Q6PG/Q6PS.
4. Client pushes its now-two-record inventory over Q6PX on the same Noise session.
5. Relay Store sees A as duplicate and persists C as a new record.
6. Listener confirms two requests/two responses and zero handler failures.

The test verifies that the peer record C is present in the receiver's durable Store after the session. This is protocol-level bidirectional interoperability in the local test harness. It is **not** an independent-host Internet test and does not claim a live three-host mesh.

- `cargo build --locked --offline --bin qrun_v06_node -j 1`: PASS, exit code 0.
- `git diff --check`: PASS (Git printed only existing LF-to-CRLF working-copy warnings).
- New node binary SHA-256: `63f026cd8163558a84ee518fe90eb7ecac011fe0413b0171eb1a60ddf3f04b2d`.

### Source hashes (SHA-256)

- `lib.rs`: `3cedc965fca9730a7865cc6bee8be8cee38e5a0bf1030e6f6570c697e6871d5b`
- `qrun_v06_q6pd_address_manager_candidate.rs`: `c545d9228e61454412c2dba04cac576bd1e7060189689785fd7d1dad2f780f34`
- `qrun_v06_peer_discovery_candidate.rs`: `720c2e1aa8fae506622839a40a6d7084b521fc76f068ada3e89eed46f8969733`
- `qrun_v06_peer_discovery_store_candidate.rs`: `1e97a6d4532a866f248ff494987135f49f3cbe12a6601fda0f7488e3e4918eb7`
- `qrun_v06_peer_listener_candidate.rs`: `eb89d1c38c6929a07660345cf607267474ea128298c95d2159df9e2dde0e372b`
- `qrun_v06_history_sync_service_candidate.rs`: `d7601a8e98ac9f15670e3cdc92384c290473f5cdfdf83d5a0b597add9913c290`
- `qrun_v06_node_supervisor_candidate.rs`: `6f3eeb24d886ca0815bf278e463347002f8e33334ae71ae33a64a4cce42aace2`

## 5. Live runtime and rollout status

No live process, configuration, private key, TPM binding, Seed endpoint, Funnel mapping, firewall setting, or Q6PD live store was changed. The primary Seed (30336), backup Seed (30337) and local QA Joiner (31434) were not stopped or restarted.

The newly built binary is local at:

`src/native/pow_bench/target-v6/debug/qrun_v06_node.exe`

It has not been deployed to the live Seed processes or repackaged into the CP-0838 operator ZIP. The public GitHub Release ZIP remains a separate distribution gate.

No independent external QFP6 identity was observed during this checkpoint. Therefore:
- no external multi-host A→B→C propagation is claimed;
- no Internet-wide peer scan is claimed;
- no peer count has been fabricated from local processes;
- Mainnet, real-value activity and market authorization remain NOT_GRANTED.

## 6. Bitcoin comparison and remaining qualification

This implementation now has QFP6-native equivalents of the key AddrMan/address-gossip behaviors: request/response inventory exchange in both directions, forwarding third-party signed addresses, persistent candidate metadata, new/tried pools, address-group diversity, attempt/success tracking and exponential retry backoff.

It is inspired by Bitcoin's peer discovery/AddrMan approach, but it is not wire-compatible with Bitcoin's `addr/addrv2/getaddr` protocol and is not a byte-for-byte reproduction of Bitcoin Core's complete bucket, feeler, privacy and anti-Sybil policies.

The remaining external qualification is that an independently administered QFP6 node must run this updated build. Once at least two genuinely independent public-relay-capable nodes exchange signed records, an outbound-only joining node can pull from one and push its inventory to another. The actual public multi-host topology, restart/reconnect and history convergence still require independent participants; this local laptop alone cannot prove them.

Scope remains ZERO_VALUE_PUBLIC_TESTNET_CANDIDATE_ONLY. Noise XX inbound remains anonymous before Q6PD application checks and the transport remains classical X25519, not post-quantum.
