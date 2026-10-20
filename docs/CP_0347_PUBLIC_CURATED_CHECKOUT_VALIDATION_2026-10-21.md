# CP-0347 — Public Curated Checkout Verification
Date: 2026-10-21
Tested source commit: c3a5474aea60d3925f45ccc5f964f1229e4565e8
Checkout: `AI_NATIVE_L1_PUBLIC_REFRESH_20261020`, the curated public repository (not the owner's larger working repository).
Environment: Windows; rustc 1.82.0; Cargo 1.82.0.
Scope: verification only; no consensus/runtime source changes.

## Results

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | PASS, exit 0 |
| `cargo check --all-targets --locked --offline` | PASS, exit 0; finished in 50.76 seconds |
| `cargo test --all-targets --locked --offline` | PASS, exit 0 |
| Rust library test suite | 735 passed, 0 failed, 0 ignored; 205.78 seconds |
| Remaining binary/integration/example targets | All completed without a failure; the `devnet_node` and `private_testnet_node` test targets each passed 36/36 |
| `python simulations/public_docs_refresh_checker.py` on the preceding public baseline | PASS: HTML/tag checks, 7 unique IDs, 9 README relative links, contact mailto, candidate emission arithmetic and 274 Git-blob checksums |
| `python simulations/sponsor_allocation_checker.py` | PASS on the reviewed maintenance checkout; total-cap and founder-envelope arithmetic preserved |
| `npm test` in the owner's complete `contracts/launch-asset` checkout | Previously recorded PASS in CP-0346; this is a separate workspace and is not reported as a newly rerun test of the curated public checkout |

The full `cargo test --all-targets` process finished with exit code 0 after 491.60 seconds. The output includes several deliberately long-running process/fork/recovery tests; these eventually passed. Existing compiler warnings about unused imports/dead code remain. They are not build failures, but should be triaged separately rather than hidden.

## Evidence boundary

These results establish reproducible regression success for the curated source commit identified above. They do **not** establish a live native Mainnet, public multi-operator devnet, independent audit, end-to-end production post-quantum security, production EVM integration, or measured end-to-end native TPS/latency.

The 10B cap and 4B/3B/3B allocation envelopes remain design terms until Gate 2 closes. The candidate Argon2id/halving parameters documented by CP-0346 are not yet fully integrated through canonical Genesis, block creation/import, reorg, persistence, replay, snapshots and state roots. Gate 8 and native EVM integration also remain open.

## Release integrity

CP-0346 introduced the public founder contact, candidate mining/halving profile, limited benchmark record and benchmark methodology. CP-0347 adds exact curated-checkout regression evidence without changing runtime/consensus code. The current public release manifest v0.5 and `RELEASE_SHA256SUMS.txt` should be checked with the public documentation preflight before merge.

No production keys, value-bearing transaction, service payment, public listener, sponsor award, token listing or Mainnet activation was performed by this checkpoint.
