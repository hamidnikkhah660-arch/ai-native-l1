# CP-0376 — PFM4 Expected-Target Binding Atomicity Regression

Date: 2026-10-22
Project: QuantumZXB / AI-Native L1
Base commit: `642026628deb6672ad90283bf836664dff945281`
Branch: `test/gate2-pfm4-target-mismatch-atomicity`
Scope: PFM4 negative test only; no consensus/economic runtime parameters changed.

## Motivation

A test that submits a nonce whose digest exceeds the target proves insufficient work is rejected (CP-0374), but does not independently prove that the active network profile's expected target is bound to the header. A malicious peer could choose an easier header target and produce a digest that meets that self-selected value. This regression checks the other side of the rule at the durable PFM4 store boundary.

## Regression test

Added `pfm4_rejects_valid_pow_under_wrong_target_without_publishing_manifest_or_branch` in `src/native/pow_bench/src/private_testnet_v4_hybrid_fork_store_candidate.rs`.

- Starts from the real PFM4 store test's valid Genesis and candidate MBK4 body, state root, ancestry and header.
- Changes only the PMT4 header target from the profile's expected `Uint256::MAX` to a lower target `[0x7F; 32]`, still within the configured pow limit.
- Searches a bounded deterministic nonce range until the header digest is at or below the forged target, and asserts that this PoW check succeeds under the peer-supplied target while the target differs from the active network's expected target.
- Submits the envelope through `PrivateTestnetV4HybridForkStore::submit`; admission rejects the mismatched expected target.
- Asserts canonical height remains 0, tip remains Genesis, branch archive remains empty, manifest anchor is unchanged, and no branch file is published.
- Reopens the durable store and checks the same height, tip, archive and manifest anchor again.

This isolates expected-target binding from invalid PoW and wrong miner reward, which have separate tests in CP-0374 and CP-0375.

## Local validation on the authorized Windows host

- `cargo fmt --all -- --check` — PASS.
- `cargo check --all-targets --locked --offline` — PASS (exit code 0; pre-existing unused/dead-code warnings in diagnostic targets remain).
- Focused regression — PASS (1 passed, 0 failed).
- `cargo test --all-targets --locked --offline -- --test-threads=1` — PASS (752 library tests passed, 0 failed/ignored; `devnet_node` 36/36; `private_testnet_node` 36/36; all remaining binaries, examples and integration vectors passed; exit code 0, runtime 620.32s).
- `python simulations/rebuild_release_checksums.py` — PASS (canonical Git-index blob bytes; manifest self-hash excluded).
- `python simulations/public_docs_refresh_checker.py` — PASS on the staged pre-rebase document set (14 HTML IDs, 24 README relative links, candidate issuance arithmetic and 307 checksums). Counts will be recalculated after rebasing onto current main.

## Gate boundary

This test hardens the current loopback-only PMT4/PFM4 candidate store. It does not define production difficulty/retargeting rules, freeze a Mainnet profile, deploy a public listener, add an external CAS provider, or constitute a security audit. Gate 2 and Gate 8 remain **OPEN**. Owner-funded spend remains USD 0.
