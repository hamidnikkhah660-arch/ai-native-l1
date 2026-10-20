# QuantumZXB Public Documentation Release Manifest v0.5
Prepared: 2026-10-21
Release type: Curated public checkout verification and claim-precision refresh; no consensus/runtime source changes.
Repository: https://github.com/hamidnikkhah660-arch/ai-native-l1
Website: https://hamidnikkhah660-arch.github.io/ai-native-l1/

## Purpose

This release records a fresh locked/offline all-target verification of the curated public checkout, distinct from the owner's larger maintainer workspace. It makes the source and documentation claims easier to reproduce and preserves the clear boundary between candidate research and production activation.

## Current verified source checkout

Tested commit: `c3a5474aea60d3925f45ccc5f964f1229e4565e8` (the public code tree before this documentation-only checkpoint).
Environment: Windows; Rust/Cargo 1.82.0.

- `cargo fmt --all -- --check`: PASS, exit 0.
- `cargo check --all-targets --locked --offline`: PASS, exit 0, 50.76 seconds.
- `cargo test --all-targets --locked --offline`: PASS, exit 0.
- Library tests: 735 passed, zero failures.
- Remaining binary/integration/example targets: zero test failures; `devnet_node` and `private_testnet_node` test groups each passed 36/36.
- Overall all-target test process runtime: 491.60 seconds, reflecting many targets and deliberately long process-level recovery/fork scenarios.
- Compiler warnings about unused imports/dead code remain and should be addressed separately.

The owner's distinct, larger working checkout has previously recorded 736/736 library tests. Do not merge the two counts: 735 belongs to the curated public source checkout and 736 to the larger maintainer checkout.

## Public docs/site verification

The preflight on the v0.4 public baseline passed HTML nesting/tag validation, seven unique in-page IDs, nine README relative links, founder contact checks, integer candidate emission arithmetic, and all 274 Git-blob SHA-256 entries. The live GitHub Pages document returned HTTP 200 and contained the founder contact and mining/halving section. This v0.5 manifest accompanies the follow-up public-checkout verification checkpoint.

## What is implemented versus candidate

The curated repository includes a Rust-native research/runtime candidate, deterministic state and replay candidates, fork/reorg and persistence work, bounded networking components, ML-DSA-65 verification tests and hybrid-identity candidates, a separate EVM/revm laboratory, and a distinct QX Sepolia/testnet asset experiment.

The 10,000,000,000-coin native design cap and 4B founder / 3B mining-security / 3B public-goods allocation envelopes are not a claim of active production issuance. The candidate 30-second block target, 2,016-block difficulty window, Argon2id v1.3 parameters, 4,204,800-block halving interval and 356.73515981-coin initial subsidy remain unratified production parameters. The 3B mining envelope does not mean those coins have already been mined or issued.

No comparable end-to-end native multi-node TPS, public-network p50/p95/p99 latency, production uptime, mining profitability or independent audit is established by this evidence. The EVM lab is not yet the canonical VM dependency of the native node. Native Genesis/issuance integration (Gate 2), independently operated anti-rollback trust/recovery qualification (Gate 8), canonical EVM integration, multi-operator public devnet and external protocol/cryptography review remain open.

## Files in this checkpoint

- `docs/CP_0347_PUBLIC_CURATED_CHECKOUT_VALIDATION_2026-10-21.md`: exact clean curated-checkout command results and limitations.
- `README.md`: public curated-checkout verification, separated from the larger maintainer-checkout count.
- `index.html`: public test metric updated to the latest verified curated source count, with the distinct maintainer-checkout count explained.
- `RELEASE_SHA256SUMS.txt`: recalculated against the canonical Git index blobs, excluding itself.
- This manifest provides the next versioned documentation baseline.

This remains a documentation/verification release. It does not change consensus or runtime behaviour, close any Mainnet gate, create revenue or sponsor commitments, or imply any exchange listing or token market.
