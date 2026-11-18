# CP-0636 — Peer Selection Duplicate-Identity Sybil Guard
Date: 2026-11-13
Project: QRun / QZXB / QFP6
Branch: feat/cp0600-bootstrap-sync-startup
Observed base HEAD: df673d07050688a64b26822d97e6ea609b68ce88

## Scope
Audit and harden the existing peer-routing selection policy against duplicate peer identity records. Do not claim this policy protects the live QRun node until it is wired into the runtime and its identity/prefix/source inputs are authenticated.

## Finding
The existing `peer_policy::select_peers` routing selector enforces per-prefix and per-source limits and protects a configured number of established peers from a fresh-candidate flood. However, its established-peer pass previously could select the same `peer_id` more than once when duplicate records for that identity carried different prefix/source metadata. That could let duplicate representations consume multiple routing slots.

A repository-wide search found no production/runtime call sites for `select_peers`; the function is currently used only by its own unit tests. The module is declared in `lib.rs`, but this is not evidence of live peer-selection enforcement.

## Change
In `src/native/pow_bench/src/peer_policy.rs`:
- Track selected `peer_id` values for the entire selection operation.
- Reject a repeated identity in both the established-peer protection pass and the general candidate pass.
- Preserve existing per-prefix and per-source caps and deterministic ordering.

Added regression test:
`duplicate_peer_identity_cannot_consume_multiple_routing_slots`
It supplies two records with the same peer ID but different prefix/source values and confirms that identity 77 occupies exactly one slot while an independent peer remains selectable.

## Validation
- Targeted regression test: PASS — 1 passed, 0 failed.
- Complete `peer_policy::tests` filter: PASS — 6 passed, 0 failed.
- `cargo fmt --manifest-path src/native/pow_bench/Cargo.toml -- --check`: PASS.
- `git diff --check`: PASS.
- No full test suite rerun.

## Critical limitation
This is a tested correction in an isolated routing-policy module, not an active live-network Sybil defense. The runtime does not currently call `select_peers`. Before integration:
- peer identity must be derived from a cryptographically authenticated and stable identity, not a caller-supplied arbitrary integer;
- network prefix/source attribution must be canonical and resistant to attacker-controlled labels;
- selection behavior must be tested against bootstrap concentration, long-lived/adaptive Sybil churn, and eclipse scenarios;
- operator-approved trust pins and manual/bootstrap policy must retain explicit precedence and recovery semantics.

## Release boundary
No node launch, listener bind, port/firewall/router change, public testnet launch, commit, or push. Public release remains NOT AUTHORIZED. Existing working-tree changes from CP-0631 through CP-0635 are preserved.
