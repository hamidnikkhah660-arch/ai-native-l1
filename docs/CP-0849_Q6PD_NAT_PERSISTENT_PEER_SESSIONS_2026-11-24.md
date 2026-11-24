# CP-0849 — NAT-friendly persistent Q6PD peer sessions

Date: 2026-11-24
Branch: feat/cp0849-nat-persistent-peer-sessions
Base: CP-0848 NAT-friendly public-alpha Joiner

## Scope

This checkpoint completes one missing part of the existing QFP6 discovery path. It does not create a new network, consensus protocol, or peer-address wire format. It reuses Q6PD signed records, the existing Q6PD AddrMan, pinned Noise transport, bootstrap list, and Q6PD persistent-session controls.

## Change

- A Joiner that has no globally reachable endpoint can now keep an outbound persistent session to an operator-pinned bootstrap peer without publishing a fictitious local endpoint.
- A node with a public Q6PD identity still has to provide a current signed record bound to its exact local Noise static key before it announces itself.
- After a signed candidate is pulled and its Noise static key is verified, the supervisor can start the same persistent outbound session even when the local node is behind NAT.
- The existing heartbeat, six-hour session lifetime, bounded reconnect backoff, and remote-key pin check remain in place.
- The persisted per-node Q6PD candidate inventory is increased to 16,384 records, with 32,768 sequence watermarks and a 32 MiB store ceiling.

## Security and scale boundaries

A signed Q6PD record is a self-asserted peer identity and address claim, not third-party reputation, consensus authority, or a guarantee that the endpoint is honest. The dialer pins the exact Noise static key from the signed record; block validity, fork choice, and transaction execution continue to be verified locally. Peer count is never a consensus vote.

The inventory and eight persistent-session slots are per-node resource/DoS bounds. They do not impose a network-wide node-count limit. A node needs only its bootstrap material and then learns further signed candidates through peer-to-peer pulls/relay. NAT-only nodes maintain outbound reachability but do not advertise an unrouteable address.

## Validation status

- Rust formatting (cargo fmt) completed.
- git diff --check completed successfully before this note was added.
- Unit tests were added for NAT-only session eligibility and strict public-announcement material handling.
- The existing Q6PD store tests already cover multi-hop signed-record relay across origin, relay, and downstream stores.
- A full local Cargo build/test was deliberately not run on the laptop because available RAM was under 1 GiB. Hosted CI and an independent multi-operator mesh test remain required.

## Required network qualification before calling P2P complete

1. Start at least three independently keyed nodes; at least one must be NAT-only and at least two must be independently administered.
2. Bootstrap one node from the pinned seed; verify that it learns another peer's signed record through the relay, then learns a third peer transitively.
3. Confirm outbound Noise static-key pinning, active persistent heartbeat, retry/reconnect after a controlled disconnect, and address-book persistence after process restart.
4. Confirm expired, replayed, tampered, wrong-network, and wrong-profile records are rejected.
5. Confirm locally invalid blocks remain rejected regardless of peer count.

No production process, listener, firewall, or live node was restarted or reconfigured by this checkpoint.
