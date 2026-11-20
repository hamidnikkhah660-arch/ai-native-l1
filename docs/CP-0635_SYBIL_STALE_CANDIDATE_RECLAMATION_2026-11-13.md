# CP-0635 — Sybil Candidate Stale-Entry Reclamation
Date: 2026-11-13
Project: QRun / QZXB / QFP6
Repository: D:\Temp\ASUS\QRUN_QFP6_CP0596_20261111
Branch: feat/cp0600-bootstrap-sync-startup
Base HEAD observed before this change: df673d07050688a64b26822d97e6ea609b68ce88

## Scope
Continue the Sybil/P2P hardening work without repeating previously completed independent multi-host or listener-resilience campaigns. Preserve all pre-existing working-tree changes.

## Verified existing controls
- Q6PA address book is globally bounded at 256 records and 256 KiB.
- Q6AR advertisements are network/profile bound, time-limited, capped at 32 endpoints, and reject duplicate endpoints/keys.
- Candidate advertisements relayed by an operator-pinned Noise key remain candidates; they do not become outbound trust pins automatically.
- Outbound peer pins require explicit operator approval; approval can be revoked.
- Existing Sybil candidate-flood test verifies global capacity and no automatic trust promotion.

## Finding
Before this checkpoint, expired Q6AR gossip candidate records remained in the bounded address book. A full book could therefore continue rejecting new candidates even after old unapproved advertisements had expired. This is a stale-entry resource-exhaustion / long-lived Sybil persistence gap. It is distinct from consensus influence and does not imply that candidate records were trusted.

## Change
In `src/native/pow_bench/src/qrun_v06_peer_address_manager_candidate.rs`, Q6AR ingestion now reclaims records that meet all of these conditions before enforcing global capacity:
- source is Gossip;
- no operator-approved Noise key exists;
- advertisement expiry is nonzero and is at or before the current time.

Operator-approved records and non-gossip records are retained. The existing transactional rollback path restores the pre-ingestion record set if capacity validation or persistence fails.

Added targeted regression test:
`expired_unapproved_gossip_is_reclaimed_before_candidate_capacity_rejects_new_peers`
The test fills the 256-record book, marks one unapproved gossip record expired, ingests a fresh pinned-relay advertisement, and verifies the stale entry is reclaimed, the new candidate is admitted, capacity remains bounded, and no peer is automatically trusted.

## Validation
- Targeted cargo test: PASS — 1 passed, 0 failed.
- `cargo fmt --manifest-path src/native/pow_bench/Cargo.toml -- --check`: PASS.
- `git diff --check`: PASS.
- No full suite rerun; no unrelated previously completed multi-host/listener tests rerun.

## Explicitly unresolved
- No per-prefix or autonomous-system peer diversity quota has been implemented or qualified. Global capacity alone does not prevent a single relay or coordinated sources from saturating the candidate table with live entries.
- No sustained adaptive Sybil/Eclipse simulation has been run in this step.
- P2P transport remains Noise_XX_25519_ChaChaPoly_SHA256; transport key establishment is classical, not post-quantum.
- Public inbound Noise XX sessions remain anonymous unless a separately pinned identity is applied.
- Dependency audit findings recorded in CP-0634 remain unresolved; do not upgrade cryptographic dependencies blindly.
- Independent cryptographic review, canonical production artifacts, consensus/economic review, and final release-manifest authorization remain pending.

## Operational boundary
No node was launched. No listener/port/firewall/router settings were changed. No public testnet or mainnet launch occurred. No commit or push was made. Existing unrelated working-tree modifications were preserved. Public release remains NOT AUTHORIZED.

## Next focused work
1. Design and test live-candidate saturation resistance, including relay-origin concentration and prefix diversity, without treating IP diversity as proof of identity.
2. Test adaptive Sybil churn, restart persistence, bootstrap poisoning, and Eclipse resistance using controlled simulations.
3. Verify that peer count or Sybil identity count cannot increase PoW cumulative-work/fork-choice weight.
4. Continue PQ transport migration and resolve the audited Libcrux advisories with version/API review and targeted cryptographic regression tests.
