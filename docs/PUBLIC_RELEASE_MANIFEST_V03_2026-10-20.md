# QuantumZXB Public Documentation Release Manifest v0.2
Prepared: 2026-10-20
Release type: Documentation and public-site refresh; no consensus/runtime source code changes.
Repository: https://github.com/hamidnikkhah660-arch/ai-native-l1
Website: https://hamidnikkhah660-arch.github.io/ai-native-l1/

## Purpose

This release package expands the public-facing technical description of QuantumZXB while preserving the distinction between the native coin design, candidate engineering components, and separate EVM testnet artefacts. The previous v0.1.1-source release remains an immutable historical source/docs release; this manifest covers the following documentation/site update to main.

## Included documents and site changes

- README.md - project overview, capability summary, review-scope test counts and links to the new documents.
- index.html - refreshed global project page with responsive engineering/capability/roadmap sections and sponsor call.
- docs/QUANTUMZXB_NATIVE_COIN_WHITEPAPER_V02.md - public technical white paper for the native coin and wider ecosystem.
- docs/QUANTUMZXB_MASTER_ROADMAP_V02.md - staged engineering, EVM, hybrid-signature, devnet and ecosystem roadmap.
- docs/FOUNDER_SPONSOR_CONTRIBUTOR_ALLOCATION_POLICY_V03.md - 4B founder allocation, conditional sponsor proposal and contributor pool.
- docs/CP_0343_TECHNICAL_REVIEW_AND_TEST_RESULTS.md - source-level review and explicit local-test scope.
- simulations/sponsor_allocation_checker.py - arithmetic checks that sponsor/contributor allocations stay within the original 4B founder tranche and 10B total design cap.
- RELEASE_SHA256SUMS.txt - refreshed manifest for the current curated tree; the checksum file does not hash itself.

## Capability summary

The curated repository includes native Rust protocol research, state and persistence candidates, bounded networking work, hybrid-signature/post-quantum experiments, a separate EVM/revm laboratory, and an EVM testnet asset. The full maintainer working checkout passed 736 library tests and the remaining Rust test targets, locked/offline all-target check and format check; the separate launch-asset package tests passed. These are regression results for the identified working checkout, not an independent audit or performance benchmark.

## Allocation policy represented in this release

- Founder tranche: 4,000,000,000 native coins (40% of the proposed 10B cap), controlled by the founder with no protocol lock or time vesting under the current owner direction.
- Potential sponsor: up to 1,000,000,000 coins (10% of total cap, equal to 25% of the founder tranche), only after an actual written milestone agreement and verified delivery.
- Potential contributors/professionals: 100,000,000 to 1,000,000,000 coins (1%-10% of total cap) from the same founder tranche, only for accepted work.
- If both sponsor and contributor allocations reach 1B, at least 2B (20% of total cap) remains as the founder's direct discretionary allocation. Any unawarded founder-tranche remainder remains founder-controlled.
- These are conditional allocation proposals. No sponsor award, market value, return or new issuance is implied.

## Verification notes

The site source was checked for UTF-8/ASCII-safe content and HTML structure. The sponsor-allocation checker runs offline. Native Rust and EVM regression commands were run against the maintainer checkout during the technical review. The separate revm lab was not rerun in this review because the available workstation toolchain did not match the lab's documented requirement.

The release leaves the native production profile/Genesis, canonical issuance integration, independent anti-rollback provider, native EVM execution integration, multi-operator public devnet and independent security review as roadmap acceptance tasks. This is an engineering-documentation release, not a Mainnet activation or a claim that future integrations are already live.
