# CP-0640A — Atomic Trust-Domain-Aware Q6AR Ingestion
Date: 2026-11-13
Project: AI-NATIVE L1 / QRUN-QFP6
Status: IMPLEMENTED AND TARGETED TESTS PASS; NOT RUNTIME-WIRED

## Baseline and preservation
- Branch: feat/cp0600-bootstrap-sync-startup
- HEAD at start and end of this checkpoint: df673d07050688a64b26822d97e6ea609b68ce88
- Upstream branch was aligned with this HEAD at start.
- Existing dirty worktree was preserved; no reset, clean, stash, checkout, rebase, commit, or push was performed.
- Pre-change snapshot: D:\Temp\QRUN_CP0640A_PRECHANGE_20261113
  - tracked working-tree patch: tracked-working-tree.patch
  - all 9 pre-existing untracked files copied under the snapshot directory
  - original git status saved in git-status.txt

## Verified integration finding
The permissionless supervisor callback still invokes QRunV06PeerAddressBookCandidate::ingest_pinned_q6ar.
The CP-0639 BootstrapTrustDomainPolicy module was not previously connected to that ingestion path. This checkpoint adds a strict manager API, but deliberately does not change the supervisor callback or claim an active runtime defense.

## Implementation
File changed:
- src/native/pow_bench/src/qrun_v06_peer_address_manager_candidate.rs

Changes:
1. Added ingest_pinned_q6ar_with_trust_domains(..., &BootstrapTrustDomainPolicy), while preserving the original API for compatibility.
2. Routed both APIs through one internal ingestion implementation.
3. In strict mode, counts one relay-key attribution per live, unapproved Q6AR Gossip candidate record.
4. Shares a candidate budget across relay keys mapped by the operator to the same trust domain.
5. Enforces the domain relay-count limit and retains the existing per-relay (32) and global address-book (256) limits.
6. Treats duplicate updates to an already-attributed endpoint as updates, not additional candidate slots.
7. When a candidate endpoint is re-attributed to another pinned relay, moves its one accounting slot rather than double-counting it.
8. Rejects unattributable legacy Gossip records and unknown historical relay keys in strict mode.
9. Makes expiry reclamation, batch mutation, quota checks, and persistence one rollback boundary. Any failed admission or persist restores the pre-ingestion in-memory record map.
10. Test Temp paths now include a process-local AtomicU64 sequence. This prevents parallel tests from colliding on Windows when timestamp resolution produces identical directory names.

## Focused regression coverage
Command:
cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib qrun_v06_peer_address_manager_candidate::tests --locked --offline

Result:
17 passed; 0 failed; 0 ignored; 1399 filtered out.
Test execution time: 74.35s.

The five new tests verify:
- shared domain candidate budget across multiple pinned relay keys;
- atomic rollback of a multi-address batch, including restoration of expired records reclaimed during the failed batch;
- duplicate advertisement update without consuming another candidate slot;
- key rotation when old and new keys remain assigned to the same domain, plus fail-closed behavior when a key with live historical records is removed from the registry;
- fail-closed behavior for unattributable legacy Gossip records.

The complete existing Address Book target also passed, including persistence/restart, replay, global/per-relay capacity, expiry reclamation, approval, and Sybil candidate-bound tests.

## Policy lifecycle constraints and remaining gaps
- Trust-domain assignments remain operator-supplied local policy; a peer cannot self-assert its domain.
- The caller must keep relay-to-domain assignments stable while records for those relay keys remain in the address book.
- A rotated relay key must be added under the same verified domain while the old key remains mapped until its candidate records expire or are explicitly migrated. Removing a key with live records fails closed.
- Domain reassignment is not yet protected by a persisted registry generation/hash or an explicit migration workflow. CP-0640B must address immutable configuration identity and safe migration semantics before production wiring.
- The operator registry is not yet loaded from persistent runtime configuration.
- The supervisor callback is still on the compatibility ingest_pinned_q6ar method. Therefore these Trust-Domain controls are not an active network defense yet.
- No multi-relay collusion resistance is proven by these unit tests. Trust-domain independence still depends on out-of-band operator verification and governance.

## Release boundary
- No node process was started.
- No 30333 listener was opened.
- No firewall changes were made.
- No commit or push was performed.
- Public Testnet remains NOT AUTHORIZED.

## Next checkpoint
CP-0640B — Persistent Operator Registry, Registry Identity/Rotation Rules, and Permissionless Supervisor Runtime Wiring.
Must include config validation, immutable registry identity or explicit migration, supervisor wiring through the strict ingestion API, fail-closed startup behavior, and end-to-end regression tests. Until that work is complete, CP-0640A is only the safe ingestion primitive and tests, not an enabled defense.
