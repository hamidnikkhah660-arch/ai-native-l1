# CP-0377 — PFM4 Archive-Replay Expected-Target Binding

Date: 2026-10-22
Project: QuantumZXB / AI-Native L1
Base commit: `0d773559c93ddc6744e0cdef4aa85481221eb43c`
Branch: `test/gate2-pfm4-replay-target-binding`
Scope: fork-choice replay negative test only; no production runtime parameters changed.

## Motivation

CP-0376 covers live admission at the durable PFM4 store boundary. Recovery is a separate trust boundary: an archive envelope can be rewritten along with a locally recomputed filename/checksum, so replay must recompute expected consensus rules from the configured chain profile rather than trust the header's own target.

## Regression test

Added `archive_rebuild_rejects_pow_that_only_meets_a_peer_forged_target` in `src/native/pow_bench/src/private_testnet_v4_hybrid_fork_choice_candidate.rs`.

- Construct a valid Genesis-parent MBK4 candidate with valid body/state-root binding and active-network target.
- Change the header target to a different, easier value `[0x7F; 32]` that remains within the configured proof-of-work limit.
- Search a bounded deterministic nonce range and prove the resulting digest really meets the self-selected target.
- Call `PrivateTestnetV4HybridForkChoice::rebuild_from_envelopes`, the same historical replay path used to reconstruct candidate fork choice from saved archive envelopes.
- Assert replay fails with `ExpectedTargetMismatch` rather than accepting a block based on its peer-selected target.

This complements CP-0374 (insufficient work), CP-0375 (incorrect miner reward), and CP-0376 (live store expected-target binding). It tests the historical archive reconstruction boundary, not a production Mainnet difficulty profile.

## Local validation on the authorized Windows host

- Focused `archive_rebuild_rejects_pow_that_only_meets_a_peer_forged_target`: PASS (1 passed, 0 failed).
- `cargo fmt --all -- --check`: PASS.
- `cargo check --all-targets --locked --offline`: PASS (exit code 0; pre-existing unused/dead-code warnings remain in diagnostic targets).
- `cargo test --all-targets --locked --offline -- --test-threads=1`: PASS (753 library tests passed, 0 failed/ignored; `devnet_node` 36/36; `private_testnet_node` 36/36; all remaining binary, example and integration-vector targets passed; exit code 0, runtime 557.76 seconds).
- `python simulations/rebuild_release_checksums.py`: PASS (311 canonical Git-index blob entries; manifest self-hash excluded).
- `python simulations/public_docs_refresh_checker.py`: PASS (14 HTML IDs, 25 README relative links, direct-contact validation, candidate issuance arithmetic and all 311 checksum entries).

GitHub Rust and Windows workflows for the exact PR head must also pass before merge.

## Gate boundary

This does not freeze production target/retarget rules, activate a public listener, provide an external anti-rollback CAS service, or constitute a security audit. Gate 2 and Gate 8 remain **OPEN**. Owner-funded spend remains USD 0.
