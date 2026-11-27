# CP-0648 — Independent Bootstrap Snapshot Agreement

Date: 2026-11-14  
Project: AI-NATIVE L1 / QRUN-QFP6  
Depends on: CP-0640B, CP-0643, CP-0644, CP-0646, CP-0647  
Branch: feat/cp0600-bootstrap-sync-startup  
Observed HEAD: df673d07050688a64b26822d97e6ea609b68ce88  
Status: implemented and locally validated; working tree only

## Objective

Do not enter the permissionless peer/mining service after a multi-domain bootstrap attempt merely because the first pinned source completed history synchronization. Compare completed snapshots from independent operator-assigned trust domains against the local validated fork-choice archive.

Peer count is not a vote and is never used to select consensus.

## Implementation

1. `QRunV06HistorySyncClientReport` now preserves the source's consensus tip and source execution tip together with the reported height. Both the permissionless and QAP1 sync constructors populate the execution-tip field from the authenticated Q6HR snapshot.
2. Fork choice exposes `is_ancestor_tip`. It returns true only when both hashes are retained in the validated graph and the first hash is on the second tip's parent chain. Unknown hashes fail closed.
3. The Q6AR/bootstrap supervisor now attempts the configured bounded peer list instead of stopping at the first successful source.
4. A successful source is counted once per operator trust-domain ID. A second relay from a domain already represented by a successful source is skipped. A second relay in that domain remains eligible as a fallback if the first relay did not complete sync.
5. When the effective attempt set contains at least two distinct trust domains, startup requires at least two successful completed syncs from distinct domains. Otherwise startup fails closed.
6. Each report is checked against the local fork-choice archive:
   - its consensus tip must exist in the locally validated graph;
   - the retained branch height must equal the reported source height;
   - the retained execution state's tip hash must equal the independently observed source execution tip.
7. All counted source tips must lie on one ancestry chain: equal tips or one tip being an ancestor of the other are accepted. Two divergent tips fail closed and prevent entering the listener/mining supervisor.
8. A single-domain/single-source bootstrap retains the previous behavior. Multi-source agreement is required only when the effective peer-attempt set actually contains at least two distinct operator-assigned domains.

## Focused tests

- `cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib bootstrap_source_snapshots_require_distinct_domains_and_one_ancestry_chain --locked --offline` — **1 passed, 0 failed**.
  - Consistent ancestor/descendant source tips are accepted.
  - Divergent tips, duplicate domains, and fewer than two domains are rejected.
- `cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib bootstrap_source_snapshot_metadata_must_match_local_fork_archive --locked --offline` — **1 passed, 0 failed**.
  - Equal independent snapshots at the retained base are accepted.
  - A mismatched source execution tip is rejected.
- `cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib qfp6_fork_choice_keeps_branch_states_isolated_and_reorgs_to_heavier_work --locked --offline` — **1 passed, 0 failed**.
  - Real fork-choice branches prove common ancestry and sibling divergence through `is_ancestor_tip`.
- `cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib pinned_noise_sync_imports_a_heavier_competing_branch_and_recovers_after_restart --locked --offline` — **1 passed, 0 failed**.
  - Existing authenticated Noise history sync, competing-branch import and restart recovery regression remains green.

## Build and hygiene

- `cargo check --manifest-path src/native/pow_bench/Cargo.toml --bins --locked --offline` — PASS.
- `cargo fmt --manifest-path src/native/pow_bench/Cargo.toml -- --check` — PASS.
- `git diff --check` — PASS.
- Existing unused-import/dead-code warnings remain in unrelated modules and binaries; no build errors.

## Security interpretation and limitations

- Trust-domain independence is still based on operator-provisioned assignments. The software cannot independently prove common corporate ownership, hosting control, ASN ownership, or hidden coordination.
- If the effective attempt set contains only one trust domain, this checkpoint cannot establish independent source agreement. In the approved-peer launcher the attempt budget remains bounded (1..=4) and defaults to one; operators must configure a budget that actually includes at least two independently provisioned domains.
- Ancestry agreement proves that the observed snapshots are on one validated chain segment; it is not a Byzantine quorum, a consensus vote, or proof that the shared source data is honest.
- Distinct but valid branches can arise during a real network fork. This bootstrap gate deliberately refuses to proceed when independent domains report divergent branches; it does not automatically prefer the heavier one in this multi-source agreement mode. The operator must investigate/retry with consistent sources.
- Source chains are still validated by existing PoW/consensus/execution import rules. This checkpoint does not replace or modify fork-choice consensus.
- The result is not an Eclipse-resistance proof, an independent security audit, or evidence of public Internet readiness.

## Release boundary

No production node was launched. No public listener, firewall, router, or port was opened. No Public Testnet, deployment, commit, or push was performed. Existing local working-tree modifications remain preserved.
