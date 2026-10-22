# CP-0374 — PFM4 Invalid-PoW Atomicity Regression

Date: 2026-10-22
Project: QuantumZXB / AI-Native L1
Base commit: `b8a4ecc5326e45a9999ec557fa7be570a49ff1f4`
Branch: `test/gate2-pfm4-invalid-pow-atomicity`
Scope: additional PFM4 store regression test plus bounded Windows smoke timeout correction; no consensus/runtime/economic profile changes.

## Motivation

The PMT4/PFM4 end-to-end peer smoke deliberately uses `initial_target = Uint256::MAX` and 8 MiB Argon2 for speed. That is appropriate for loopback plumbing, but almost any nonce meets the target. The library already has lower-level invalid-PoW tests; this checkpoint adds a test at the durable PFM4 store boundary to make sure an otherwise valid MBK4 body cannot be published when its bound PoW header fails.

## Regression test

Added `pfm4_rejects_bad_pow_without_publishing_manifest_or_branch` in `private_testnet_v4_hybrid_fork_store_candidate.rs`.

- Builds a valid Genesis-parent MBK4 body and state root under an explicit non-zero but extremely difficult target (`1`) and `pow_limit = Uint256::MAX`.
- Searches a bounded deterministic nonce range and encodes a PMT4 envelope whose header/body/profile/target bindings are intact but whose PoW digest is strictly above the declared target.
- Asserts PFM4 rejects the envelope, canonical height/tip and archive length remain unchanged, the committed manifest anchor remains byte-for-byte equivalent by commitment, and no branch file is published.
- Drops and reopens the store and checks the same Genesis tip, empty archive and unchanged manifest anchor.

This test complements the existing local smoke; it does not claim that public-network difficulty has been frozen or that a Mainnet profile exists.

## Windows cursor-reorg smoke timeout correction

The post-merge Rust validation on `main` (`b8a4ecc...`) had one Windows integration failure: the `cp0362_pfm4_page2_cursor_reorg.ps1` client C used `--run-seconds 8`. On the CI host it imported the first two pages and the source correctly rejected the stale continuation after a reorg, but the client deadline expired before the rejection was surfaced as `monetary_v4_archive_range_sync_failed`; the smoke therefore failed at the assertion for observing the rejection. The existing protocol tests and Rust job passed.

Raised client C's bounded run to 60 seconds and its graceful-exit wait to 65 seconds so the end-to-end test has enough time to observe the stale-cursor response under slower Windows CI scheduling. Ran the complete script locally after the change; it printed `CP-0362 INFLIGHT_CURSOR_REORG_PASS`, `CP-0362 HEIGHTS_PASS`, and `CP-0362 REORG_REPLAY_PASS`, and exited with code 0. This is a test-harness timing correction, not a protocol deadline or production setting change.

## Local validation on Windows (locked/offline)

- `cargo fmt --all -- --check` — PASS.
- `cargo test --lib --locked --offline private_testnet_v4_hybrid_fork_store_candidate::tests::pfm4_rejects_bad_pow_without_publishing_manifest_or_branch` — PASS (1 passed, 0 failed).
- `cargo check --all-targets --locked --offline` — PASS (exit code 0); existing unused/dead-code warnings in diagnostic/test targets remain.
- `cargo test --lib --locked --offline` — PASS (750 passed, 0 failed, 0 ignored; test runtime 233.49s), including the new invalid-PoW durability regression.
- `./simulations/cp0362_pfm4_page2_cursor_reorg.ps1` — PASS after increasing client C's run bound; observed page-2 reorg, stale-cursor rejection, final heights source=4/client=2, and matching replay on both nodes.
- `python simulations/rebuild_release_checksums.py` — PASS (300 entries before adding the script change; regenerated again for this PR).
- `python simulations/public_docs_refresh_checker.py` — PASS (README links and manifest validation; rerun after final staging).

## Gate boundary

This is additional defensive test coverage for the existing PFM4 candidate store. It does not wire the store to a public listener, add a remote production peer mode, deploy external CAS, change issuance/economics, or establish external review. Gate 2 and Gate 8 remain OPEN. Owner-funded spend remains USD 0.
