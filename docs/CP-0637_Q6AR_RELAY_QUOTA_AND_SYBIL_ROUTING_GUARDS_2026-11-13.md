# CP-0637 — Q6AR Relay Quota and Sybil Routing Guards
Date: 2026-11-13
Project: QRun / QZXB / QFP6
Branch: feat/cp0600-bootstrap-sync-startup
Observed base HEAD: df673d07050688a64b26822d97e6ea609b68ce88

## Scope
Continue targeted Sybil candidate-book and peer-selection hardening. No previously completed independent multi-host or listener-resilience campaign was repeated.

## New finding: one pinned relay could monopolize candidate metadata
Q6AR accepts up to 32 advertised endpoints per frame. The address book had a global cap of 256, but no per-relay quota across successive, individually valid advertisements. A single operator-pinned relay could therefore fill the entire candidate table over multiple messages. These records were not automatically trusted or connected, but saturation could deny candidate capacity to other relays.

## Change: per-relay candidate quota
In `qrun_v06_peer_address_manager_candidate.rs`:
- Added `MAX_GOSSIP_PEERS_PER_RELAY = 32`.
- Counted live Gossip candidate records attributed to the authenticated, operator-pinned relay key.
- Rejected an advertisement that would add a 33rd distinct candidate for that relay with `PeerAddressBookError::RelayCapacity`.
- Preserved the existing global 256-record bound.
- Preserved manual/bootstrap records outside the Gossip candidate quota.
- Preserved stale, unapproved Gossip reclamation from CP-0635.
- Preserved transactional rollback: a quota or global-capacity rejection restores the prior record set.
- Candidate advertisements still never auto-populate operator-approved outbound trust pins.

Regression:
`one_pinned_relay_cannot_fill_the_candidate_book_across_repeated_advertisements`
A pinned relay successfully advertises 32 candidates; its next advertisement adding a 33rd distinct endpoint is rejected and the book remains unchanged.

## Peer identity selection hardening
In `peer_policy.rs`:
- Added selected-identity deduplication in both established-peer and general candidate selection passes.
- Added regression `duplicate_peer_identity_cannot_consume_multiple_routing_slots`.
- This module remains isolated: repository-wide search found no production/runtime call sites for `select_peers`. Do not count its policy as active live-network protection until correctly integrated with authenticated identity and canonical prefix/source attribution.

## Validation
- Q6PA manager tests: PASS — 11 passed, 0 failed. Includes relay quota, stale-entry reclamation, existing Sybil flood, migration, persistence, approval and backoff tests.
- Peer policy tests: PASS — 6 passed, 0 failed.
- `cargo fmt --manifest-path src/native/pow_bench/Cargo.toml -- --check`: PASS.
- `git diff --check`: PASS.
- No full library suite or unrelated multi-host/listener tests rerun.

## Remaining Sybil/Eclipse limitations
- 32 candidates per pinned relay is a per-relay bound, not proof of global diversity. Multiple pinned relays can still fill the global table with live candidate records.
- The peer-selection policy is not wired into the live QRun runtime.
- No adaptive churn, bootstrap concentration, sustained Eclipse, or multi-relay collusion simulation has been qualified in this step.
- Candidate addresses/keys are not identities and remain untrusted until operator approval and pinned handshake.
- Peer count must never become consensus weight; the relevant consensus path uses cumulative work, but a dedicated end-to-end Sybil-count invariance test remains to be designed against the canonical live runtime.

## Release boundary
No node launch, listener bind, port/firewall/router change, public testnet launch, commit, or push. Public release remains NOT AUTHORIZED. All pre-existing unrelated working-tree changes are preserved.

## Next steps
1. Design global candidate admission across relay diversity without pretending IP prefix is a unique identity.
2. Integrate peer selection only after authenticated peer identity and canonical prefix attribution are defined.
3. Test bootstrap relay concentration, relay collusion, churn, restart behavior, and Eclipse scenarios.
4. Resolve PQ transport and dependency-audit blockers recorded in CP-0634.
5. Complete independent cryptographic, consensus/economic and release-manifest reviews before any public launch.
