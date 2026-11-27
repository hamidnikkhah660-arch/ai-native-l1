# CP-0638 — Multi-Relay Sybil Candidate Saturation Test
Date: 2026-11-13
Project: QRun / QZXB / QFP6
Branch: feat/cp0600-bootstrap-sync-startup
Observed HEAD: df673d07050688a64b26822d97e6ea609b68ce88

## Purpose
Quantify the remaining candidate-book saturation risk after CP-0637 introduced a 32-candidate quota per pinned relay.

## Adversarial scenario
A controlled unit test models eight distinct operator-pinned relay keys. Each relay advertises 32 distinct endpoint/key candidates in one valid Q6AR message. All candidates are still untrusted metadata; no operator outbound approval is created.

Observed:
- Each relay can contribute at most 32 candidate records.
- Eight pinned relays can collectively occupy all 256 global candidate slots.
- A ninth relay attempting to add a new candidate is rejected by the existing global capacity guard.
- The candidate book remains at exactly 256 records.
- `approved_peer_pins` remains empty throughout; candidate saturation does not create trust.

Test:
`multiple_pinned_relays_can_reach_but_not_exceed_global_candidate_capacity`

## Validation
- Complete Q6PA peer address manager test filter: PASS — 12 passed, 0 failed.
- Peer routing policy test filter: PASS — 6 passed, 0 failed (CP-0636 change).
- Single-relay 33rd-candidate regression: PASS.
- Multi-relay global saturation regression: PASS.
- Formatting and `git diff --check`: PASS.
- No full library suite rerun.

## Security interpretation
The per-relay quota prevents one pinned relay from monopolizing all 256 slots, but it does not prevent collusion or compromise of multiple pinned relays. Eight pinned relays can fill the candidate table. These entries are not trusted peers, but the saturation can deny admission of other candidate metadata and reduce discovery resilience.

This is a verified limitation, not a reason to claim the network is Eclipse-resistant. More policy is required at the trust-domain/bootstrap provisioning layer. Prefix diversity alone is not a Sybil identity solution; source diversity must be grounded in operator-controlled, independently verifiable trust domains and carefully tested against legitimate network concentration.

## Runtime integration warning
The peer-selection policy in `peer_policy.rs` remains unreferenced by production/runtime call sites. Its prefix/source limits and established-peer protections are not active live-network controls. CP-0636 fixes duplicate peer-ID slot consumption in that isolated policy only.

## Release boundary
No node launched; no public listener/port/firewall/router changes; no public testnet launch; no commit or push. Public release remains NOT AUTHORIZED. Existing project modifications are preserved.

## Next work
1. Define an operator-verifiable bootstrap trust-domain model and safe global candidate admission policy.
2. Simulate multi-relay collusion, compromised bootstrap relays, candidate churn, restart and Eclipse behavior.
3. Integrate selection only after peer identity, source and prefix attribution are authenticated/canonical.
4. Keep consensus influence work-based; verify peer identity count cannot influence fork choice.
5. Resolve PQ transport and audited dependency vulnerabilities, then complete independent reviews and release authorization.
