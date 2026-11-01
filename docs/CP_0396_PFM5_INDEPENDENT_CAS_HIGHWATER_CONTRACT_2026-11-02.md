# CP-0396 - PFM5 independent External-CAS high-water contract

Date: 2026-11-02

Status: **Candidate contract and caller-side gates implemented; nine focused tests pass. No independent authority service or production adapter is deployed.**

## Purpose

CP-0395 provides a crash-safe local PFJ1 journal, but a local journal can be rolled back with its disk image. CP-0396 defines the missing boundary between that journal and an independently administered monotonic trust authority.

The high-water state binds four dimensions together: the independent authority identity, External-CAS provider/network/Genesis identity, journal sequence, exact ECR1 record, and immutable-object generation. A sequence-only counter is insufficient because it would not say which chain state the counter protects.

## API and transition rules

The candidate module exposes:

- `Pfm5ExternalCasHighWaterAuthorityPin`: nonzero, separately provisioned authority identifier.
- `Pfm5ExternalCasHighWaterState`: authority/provider/network/Genesis identity plus journal sequence, exact ECR1 record and object generation.
- `Pfm5ExternalCasHighWaterProvider`: adapter contract for authenticated reads and linearizable atomic compare-and-advance.
- `verify_ready_snapshot`: requires a local Ready journal to match the authenticated authority state exactly before a new intent is staged.
- `advance_prepared_snapshot`: after PFJ1 has durably recorded the exact intent, advances the independent sequence floor by exactly one while keeping the predecessor record/object generation unchanged. This must succeed or be resolved by authenticated reread before CP-0394 is allowed to publish any object or ECR1 successor.
- `advance_finalized_snapshot`: after PFJ1 records a verified exact successor, advances sequence, ECR1 record and object generation together.
- `observe_finalized_floor_for_prepared_intent`: detects the disk-rollback/recovery case where PFJ1 is Prepared but the independently retained floor already records the exact finalized successor.

Only two authority transitions are accepted: Prepared (sequence +1, unchanged record and object generation) and Finalized (sequence +1, exact ECR1 successor, strictly advanced object generation). Stale, competing, skipped, wrong-domain or non-successor states fail closed.

For an ambiguous compare-and-advance reply, the client performs an authenticated reread. The exact requested successor is classified as committed after an ambiguous reply; the unchanged predecessor returns the provider error; any third state is a conflict. There is no blind retry with a new sequence or intent.

## Security contract for an adapter

A production adapter must authenticate every read using authority trust material pinned out of band; retain state outside the node/journal rollback and failure domain; serialize all writers with linearizable atomic compare-and-advance; reject stale expected state, sequence skips, identity changes and invalid successor records; and durably commit before reporting success.

A second file, directory, partition or volume on the same machine is not an independent trust domain. The Rust trait cannot make an untrusted implementation secure: adapter review, key management, remote service configuration and independent-host tests are still required.

No file-backed adapter, local-disk fallback, cloud credentials, remote witness, HSM/TPM integration or production trust key is created in CP-0396. The test-only in-memory provider is only a contract conformance double.

## Ordering required by callers

1. Obtain and authenticate the current ECR1 read and object-generation observation.
2. Initialize PFJ1 explicitly from that verified predecessor; initialize the independent authority from the same identity/state through its separately controlled bootstrap procedure.
3. Call `verify_ready_snapshot` before preparing a new transition.
4. Persist the exact PFM5 intent in PFJ1 Prepared.
5. Call `advance_prepared_snapshot`. Do not publish immutable objects or invoke ECR1 CAS until the exact Prepared floor is confirmed.
6. Run CP-0394 with the same intent. On RetrySameIntent, retain Prepared and retry only that exact intent.
7. After a verified commit or authenticated recovery read, finalize PFJ1 with the exact ECR1 successor and observed object generation.
8. Call `advance_finalized_snapshot`; on restart, use the independent floor and signed ECR1 state to reconcile exact interrupted windows.

If the independent authority is unavailable, stale, ambiguous without a conclusive authenticated reread, or inconsistent with PFJ1, the caller must fail closed. No remote side effect is authorized.

## Tests and local validation

Nine focused tests cover:
- exact Ready-state matching and stale-floor rejection;
- Prepared sequence advance and idempotency;
- stale/competing floor rejection without overwrite;
- lost reply after atomic commit and authenticated reread classification;
- failed update with unchanged floor blocks authorization;
- Finalized record/object-generation advance and idempotent replay;
- reconciliation of a rolled-back Prepared journal from a finalized independent floor;
- wrong authority or CAS domain rejection;
- malformed Prepared transition rejection before any write.

The tests use an in-memory conformance double. They do not qualify any real provider.

- Full library suite: **816 passed, 0 failed**.
- `cargo test --all-targets --locked --offline -- --test-threads=4`: **PASS**; library 816/816, `devnet_node` 36/36, `private_testnet_node` 36/36, and all other binary/integration/example targets completed successfully.
- `cargo check --all-targets --locked --offline`: **PASS**. Existing warnings remain in unrelated legacy/probe modules; CP-0396 adds no warning.
- `cargo fmt --all -- --check`: **PASS**.
- `git diff --check`: **PASS**.
- Public docs preflight and Git-index checksum validation: **PASS**, 348 entries.

## Explicitly not completed

- No deployed independent authority service and no concrete production adapter.
- No authenticated authority-signature format or independently managed trust-key lifecycle bound into a concrete implementation.
- No node caller orchestration or runtime/Devnet/Mainnet wiring.
- No real immutable-object store or ECR1 production endpoint.
- No two-host race, partition, crash, power-loss, backup-restore or whole-disk rollback qualification.
- No independent protocol/cryptographic/economic audit.

Gate 8 therefore remains **OPEN**. Gate 2 and public Mainnet status are unchanged. This candidate does not establish public Devnet, production consensus, token issuance, public mining, QZXB trading, or launch approval.

## Local validation

- CP-0396 focused tests: **9 passed, 0 failed**.
- The full library suite and all-target validation are pending final PR validation.
