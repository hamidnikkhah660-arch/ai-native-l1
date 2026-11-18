# CP-0639 — Operator-Provisioned Bootstrap Trust-Domain Policy
Date: 2026-11-13
Project: QRun / QZXB / QFP6
Branch: feat/cp0600-bootstrap-sync-startup
Observed HEAD: df673d07050688a64b26822d97e6ea609b68ce88

## Purpose
Define a fail-closed quota policy that prevents multiple pinned relay keys belonging to one operator/trust domain from multiplying that domain's candidate-book budget.

## Security finding
Q6AR identifies the relay session by its Noise static public key and whether that key was pinned by the local node. It does not carry independently verifiable operator ownership or trust-domain identity. A remote relay must never be allowed to self-assert a trust-domain label.

## Change
Added `qrun_v06_bootstrap_trust_domain_candidate.rs` and exported it from the pow_bench library.

The policy:
- Maps pinned relay static keys to trust-domain IDs using operator-provisioned, out-of-band assignments.
- Rejects zero keys, zero domain IDs, duplicate relay-key assignments, invalid limits and unknown relay keys.
- Applies a shared candidate-record ceiling across all keys assigned to the same domain.
- Applies a distinct-relay ceiling per domain, so an operator cannot multiply its domain allowance merely by rotating relay keys.
- Fails closed if any existing candidate record cannot be attributed to a configured domain.
- Does not consume any remote-supplied domain metadata.

Default limits are intentionally not hard-coded as production network parameters; the caller supplies bounded limits. The module currently caps configured domain candidates at 256 and relay keys at 32.

## Validation
Targeted command:
`cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib qrun_v06_bootstrap_trust_domain_candidate::tests --locked --offline`

Result: PASS — 5 passed, 0 failed, 1,406 filtered out.

Covered:
1. Multiple relay keys share one domain candidate budget.
2. A domain cannot exceed its configured distinct-relay count.
3. Independently assigned domains have independent budgets.
4. Unknown incoming and unattributable existing relays fail closed.
5. Invalid or ambiguous operator registries are rejected.

## Critical limitations
- This is a pure policy candidate. It is not yet called by Q6AR ingestion, the peer address book, listener, supervisor or node runtime.
- The local operator mapping is only as trustworthy as the independent provisioning/verification process. Multiple keys must not be assigned different domains unless their administrative independence is genuinely established.
- The policy does not establish geographic, ASN, hosting-provider or legal-operator independence by itself.
- It does not prove Sybil or Eclipse resistance and does not influence consensus/fork choice.
- Existing CP-0637 per-relay quotas and CP-0638 global saturation finding remain in force.

## Release boundary
No node launched; no listener bind, public port, firewall or router changes; no public testnet launch; no commit or push. Existing working-tree changes are preserved. Public release remains NOT AUTHORIZED.

## Next required engineering step
Integrate the registry into Q6AR candidate ingestion with atomic batch accounting, restart-safe policy-version handling and explicit operator configuration. Then test same-domain multi-key floods, key rotation, domain reassignment, restart/replay, candidate expiry and legitimate bootstrap concentration. Only after those pass should runtime wiring be considered.
