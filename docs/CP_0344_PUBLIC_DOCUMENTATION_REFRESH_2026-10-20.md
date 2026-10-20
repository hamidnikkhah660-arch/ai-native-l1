# CP-0344 - Public White Paper, Roadmap and Website Refresh
Date: 2026-10-20
Parent: local CP-0343 technical source review.
Status: HISTORICAL planning checkpoint. The publication was subsequently merged and independently verified in CP-0345; this file preserves the intended scope, not the current publication status.

## Owner allocation direction reflected

- 4B founder allocation inside the 10B coin design cap remains founder-controlled and has no protocol lock or time vesting.
- Potential sponsor allocation: up to 1B coins / 10% of total cap, inside the 4B founder tranche, conditional on written milestones and verified delivery. No sponsor is represented as already selected or contracted.
- Potential contributor/professional pool: 0.1B to 1B coins / 1%-10% of total cap from the same founder tranche, only for accepted and documented work.
- At least 2B coins / 20% of total cap remain the founder's direct discretionary allocation if both proposed pools reach 1B; all unawarded remainder remains founder-controlled.
- No coin is newly minted, transferred or locked by these documents.

## Public branch changes prepared

- Rebuilt index.html as a responsive project page covering native Layer-1 engineering, ML-DSA/hybrid-signature work, EVM/revm lab, the distinct Sepolia QX asset, ecosystem direction and engineering roadmap.
- Rewrote README.md to point to the current public white paper, roadmap, technical review and sponsor policy.
- Added docs/QUANTUMZXB_NATIVE_COIN_WHITEPAPER_V02.md.
- Added docs/QUANTUMZXB_MASTER_ROADMAP_V02.md.
- Added docs/FOUNDER_SPONSOR_CONTRIBUTOR_ALLOCATION_POLICY_V03.md.
- Added docs/CP_0343_TECHNICAL_REVIEW_AND_TEST_RESULTS.md.
- Added docs/PUBLIC_RELEASE_MANIFEST_V03_2026-10-20.md.
- Added simulations/sponsor_allocation_checker.py.
- Root RELEASE_SHA256SUMS.txt will be recalculated for the updated curated tree, excluding itself.

## Regression evidence from the maintainer checkout

- cargo fmt --all -- --check: PASS.
- cargo check --all-targets --locked --offline: PASS.
- cargo test --all-targets --locked --offline: PASS; 736/736 library tests and no failures in the other targets.
- npm test in contracts/launch-asset: PASS for local fixed-supply EVM, wallet-console and loopback-server groups.
- Python sponsor allocation checker: PASS for 10B total, 4B founder envelope, 1B sponsor ceiling, 0.1B-1B contributor pool and 2B minimum direct discretionary founder amount in the maximum-award scenario.

No native consensus/runtime source changes were made. The separate revm lab wasn't rerun in this session due to the workstation toolchain mismatch. No legal filing, sponsor engagement, Mainnet launch, native-market activity or revenue was claimed.

## Publication details

The public source baseline is curated and distinct from the complete maintainer checkout. This update does not change the already published v0.1.1-source tag or its attached release artifact; it updates main and the GitHub Pages source when merged. The manifest and current-tree checksums make this next public source/doc state separately auditable.
