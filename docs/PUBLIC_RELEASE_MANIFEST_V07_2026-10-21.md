# QuantumZXB Public Documentation Release Manifest v0.7

Prepared: 2026-10-21
Release type: Candidate halving visualization and reproducible emission data; no consensus/runtime source changes.
Repository: https://github.com/hamidnikkhah660-arch/ai-native-l1
Website: https://hamidnikkhah660-arch.github.io/ai-native-l1/

## Purpose

This docs-only increment adds an accessible, responsive SVG visualization of the candidate miner-emission/halving profile and reproducible per-era CSV data. It builds on the founder profile, direct contact route, platform readiness report and mining benchmark evidence in the preceding public documentation release.

## Added / updated files

- index.html - generated two-chart SVG section for candidate block subsidy and cumulative mining-budget emission.
- simulations/candidate_halving_curve.py - integer-only emission-schedule CSV generator and HTML consistency checker.
- simulations/candidate_halving_curve.csv - all 36 non-zero candidate halving eras and cumulative modelled issuance.
- simulations/public_docs_refresh_checker.py - preflight now also validates the generated chart/data pair.
- README.md - links to the generated chart source and CSV.
- docs/MINING_HALVING_PERFORMANCE_AND_SCALING_V01.md - reproduction instructions and limits on interpreting the chart.
- docs/CP_0349_REPRODUCIBLE_CANDIDATE_HALVING_VISUALIZATION_2026-10-21.md - change record and validation evidence.
- RELEASE_SHA256SUMS.txt - refreshed for canonical Git-index blobs; this checksum file excludes itself.

## What the model shows

- Design cap: 10,000,000,000 native coins, with a 3B mining/security allocation envelope.
- Candidate subsidy: 35,673,515,981 atomic units = 356.73515981 coins per valid block at height epoch zero.
- Candidate halving interval: 4,204,800 blocks, equivalent to four target-years only if the 30-second average target is met.
- Total modelled subsidy across integer halving eras: 299,999,999,913,926,400 atoms = 2,999,999,999.139264 coins.
- Unused remainder caused by integer shifting: 86,073,600 atoms = 0.860736 coins.
- The curve is not yet integrated into every canonical production path. Gate 2 remains open.

## Claim boundaries

The charts are labelled as candidate simulations. They are not live block data, live circulating supply, native TPS, an asset price chart, profitability guidance or a return forecast. Native Mainnet, a public multi-operator devnet, native EVM integration, independent security review, public liquidity and market-data listing acceptance remain unestablished in the public evidence. The QX Sepolia ERC-20 experiment remains distinct from the native QZXB coin.

## Verification

- Candidate chart generator and checker validate the 36-era CSV, HTML block and total-emission / remainder arithmetic.
- General public-doc preflight checks HTML structure and links, direct contact consistency, the founder credential and platform-readiness section, candidate emission arithmetic, generated chart, and every checksum entry against canonical Git-index blobs.
- Native/runtime source code is unchanged by this documentation increment. The prior full curated source regression is recorded in CP-0347.
