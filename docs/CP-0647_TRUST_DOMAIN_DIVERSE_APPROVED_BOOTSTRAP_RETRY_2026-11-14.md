# CP-0647 — Trust-Domain-Diverse Approved Bootstrap Retry

Date: 2026-11-14  
Project: AI-NATIVE L1 / QRUN-QFP6  
Branch: feat/cp0600-bootstrap-sync-startup  
Observed HEAD: df673d07050688a64b26822d97e6ea609b68ce88  
Status: implemented and locally validated; working tree only

## Objective

Reduce avoidable dependence on one operator-assigned bootstrap trust domain when approved outbound peer synchronization has a bounded retry budget.

This checkpoint addresses retry ordering only. It does not claim Byzantine-source resistance, consensus safety from peer diversity, or Eclipse resistance.

## Previously verified gap

The approved outbound path obtained peers using `approved_peer_pins(now_ms, max_approved_attempts)`. The address-book method also had an unconditional eight-peer ceiling. As a result, candidate inventory was truncated before trust-domain policy could diversify the actual bounded attempt set. Lexicographically earlier endpoint records from one domain could occupy the entire retry set even when other operator-assigned domains were available.

The generic `peer_policy.rs::select_peers` remains a research policy and is not called from production runtime paths. CP-0647 does not pretend otherwise.

## Implementation

1. `approved_peer_pins` now returns up to the address book's actual `MAX_PEERS = 256` limit, while still respecting the caller's requested limit and returning only currently eligible, explicitly operator-approved endpoint/key pins. Gossip candidates do not become approved through this change.
2. `BootstrapTrustDomainPolicy::order_relays_by_domain` validates each relay key against the local operator registry, rejects duplicate and unknown keys, and produces deterministic round-robin ordering across trust-domain IDs. Within each domain, original candidate order is preserved.
3. The approved bootstrap launcher first inventories the complete bounded approved set, loads the independently SHA-256-pinned trust registry against that set, and only then applies `max_approved_peer_sync_attempts`. The same complete registry object is reused for Q6PA fingerprint binding, so its identity is not derived from a transient selected subset.
4. The actual supervisor receives the ordered, attempt-bounded peer list. Its existing retry loop therefore tries one candidate per available trust domain before retrying a second candidate from an already represented domain.
5. Existing bounds are unchanged: `max_approved_peer_sync_attempts` remains 1..=4 and defaults to 1. A budget of one cannot provide multi-domain retry diversity; operators must explicitly configure a larger budget to use this protection.

## Focused tests

- `cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib bootstrap_peer_order_ --locked --offline` — **2 passed, 0 failed**.
  - Interleaves three domains before reusing a domain.
  - Rejects unknown and duplicate relay keys.
- `cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib approved_peer_inventory_is_not_truncated_before_domain_diversification --locked --offline` — **1 passed, 0 failed**.
  - Verifies ten approved pins are visible to a 256-entry inventory request; caller limits still apply.
- `cargo test --manifest-path src/native/pow_bench/Cargo.toml --bin qrun_v06_node approved_bootstrap_attempts_cover_distinct_domains_before_reusing_one --locked --offline` — **1 passed, 0 failed**.
  - With five peers across three domains and a four-attempt budget, selection is A1, B1, C1, A2.
  - With a two-attempt budget, selection is A1, B1.

## Build and hygiene

- `cargo check --manifest-path src/native/pow_bench/Cargo.toml --bins --locked --offline` — PASS.
- `cargo fmt --manifest-path src/native/pow_bench/Cargo.toml -- --check` — PASS.
- `git diff --check` — PASS.
- Cargo emitted existing unused-import/dead-code warnings in unrelated modules/binaries; no build errors.

## Security interpretation and remaining limitations

- Trust-domain IDs and relay-to-domain mappings remain local operator assertions. This change does not independently verify corporate ownership, hosting control, ASN independence, or common control.
- It improves retry diversity only when multiple assigned domains are represented in the approved candidate inventory and the operator sets an attempt budget greater than one.
- The default attempt budget remains one. A single available domain, a single configured attempt, or inaccurate operator domain assignments defeats multi-domain diversity.
- The supervisor still accepts the first bootstrap source that completes the existing bounded history synchronization. CP-0647 does not add cross-source state comparison, a quorum, or a Byzantine source-consistency proof.
- It does not integrate the separate research `peer_policy.rs` into live session selection and does not affect consensus or fork choice.
- It is not an Eclipse-resistance proof and does not establish public Internet readiness.

## Release boundary

No production node was launched. No public listener, firewall, router, or port was opened. No Public Testnet, deployment, commit, or push was performed. Existing local working-tree modifications remain preserved.
