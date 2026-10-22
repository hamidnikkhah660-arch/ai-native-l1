# CP-0368 — Gate 8 External CAS Trust-Pin Consistency Checkpoint

Date: 2026-10-22
Project: QuantumZXB / AI-Native L1
Base commit: `863f43fbd8bb3cf1c99a55d4bc16ce9bdf58f20c`
Working branch: `fix/gate8-cas-pin-consistency`

## Scope and finding

This checkpoint closes one bounded client-configuration defect in the PFM4 external-CAS candidate; it does not close Gate 8.

The PFM4 store entry points accepted an explicit `ExternalCasPin`, while `VerifiedExternalCasClient` independently retained the pin used to verify signed receipts. Before this change, the caller-supplied pin and the receipt-verification pin were not required to be exactly equal. Those configuration inputs could therefore disagree in `receipt_key_id` or the receipt public key while some store checks still used the other pin. A trust boundary must not silently combine these two configurations.

## Change

- Added `VerifiedExternalCasClient::is_pinned_to`, which compares the complete `ExternalCasPin` (provider, network, genesis, receipt key ID and public key).
- `PrivateTestnetV4HybridForkStore::open_with_external_cas` now rejects a mismatched pin before performing the provider read or local recovery.
- `PrivateTestnetV4HybridForkStore::submit_with_external_anchor` now rejects a mismatched pin before touching pending-manifest state or attempting CAS.
- Added negative regression coverage for a receipt-key-ID mismatch at both entry points. The submit path asserts that no pending manifest is created; recovery asserts the pending candidate is not changed/promoted by a mismatched configuration.

## Evidence

Baseline main and PR #32:
- Main/PR #32 merge SHA: `863f43fbd8bb3cf1c99a55d4bc16ce9bdf58f20c`.
- Rust validation run `39714555490`: completed successfully on that exact SHA. The all-target check/test and independent Genesis snapshot and issuance oracle steps passed; Windows PMT4/TXN4 loopback and paged PFM4 inter-page reorg/stale-cursor steps also passed.
- Pages workflow run `39714554872`: build, deploy and status-report jobs completed successfully.

Local validation for this change:
- `cargo fmt --all -- --check`: passed.
- `cargo test -p ai_native_l1_pow_bench --locked --offline pfm4_external_cas_is_committed_after_pending_manifest_is_durable`: passed (1 passed).
- `cargo test -p ai_native_l1_pow_bench --locked --offline pfm4_open_with_signed_successor_recovers_commit_before_local_manifest_replace`: passed (1 passed).
- `cargo check --all-targets --locked --offline`: passed.
- `cargo test --lib --locked --offline`: passed, 749 passed / 0 failed / 0 ignored; the slowest PFM3/PFM4 durable reorg/crash-window tests also completed successfully (126.95s test runtime).

## Still required for Gate 8

This code is a fail-closed improvement to a candidate client/store boundary. It does **not** supply or prove:
- a deployed authenticated HTTPS provider with true server-side atomic generation CAS;
- an independently administered provider/operator and trust domain outside the node host/disk/VM rollback boundary;
- an independently provisioned and reviewed receipt-key pin, including rotation/revocation and recovery procedure;
- multi-host rollback, concurrent-writer, timeout ambiguity, VM restore, storage and actual sudden-power-loss evidence;
- integration of this candidate into a frozen canonical production runtime; or
- an independent external security review with no unresolved Critical/High findings.

No paid service, new credential, production key, public listener, value-bearing transaction or mainnet action was created. The owner spend limit remains USD 0. Gate 8 remains **OPEN** until the independent infrastructure, durability and audit exit criteria are evidenced.
