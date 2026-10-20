# CP-0346 - Founder Contact, Mining/Halving and Performance Transparency Refresh

Date: 2026-10-20
Parent public baseline: 4df2b6ff6de3e48f91b539426bb58de3f331ff19 (v0.2.0-docs)
Release type: Documentation and static site only; no consensus/runtime source changes.

## Changes in this increment

- Added a founder research profile grounded in the current CV and public repository, with direct contact email hamidnikkhah660@gmail.com.
- Added public site sections for miner/emission candidate parameters, limited measured candidate results, a transparent performance boundary, founder background and collaboration proposals.
- Added a dedicated mining/halving/performance report with exact candidate emission arithmetic, the Argon2id screen results, a candidate state-size baseline and a repeatable TPS/latency/resource benchmark protocol.
- Updated README discoverability for direct sponsor, developer, research and platform inquiries.
- Corrected the README's stale manifest path and amended CP-0344 to identify it as a historical planning checkpoint superseded by the verified publication record.
- Prepared a new public release manifest v0.4 and regenerated the curated source tree's Git-blob SHA-256 manifest.

## Candidate monetary profile in scope

The latest shared monetary-policy candidate recorded by CP-0338 and the full working-tree state uses:
- 10,000,000,000 lifetime design cap.
- 4B founder / 3B mining-security / 3B public-goods allocation envelopes.
- 8 decimal places.
- Candidate 30-second target block interval and 2,016-block difficulty window.
- Argon2id v1.3 candidate: 64 MiB memory, one iteration, one lane, 32-byte output.
- 4,204,800-block halving candidate and initial subsidy 35,673,515,981 atomic units (356.73515981 coins).
- Simulated aggregate miner subsidy 299,999,999,913,926,400 atomic units; 86,073,600 atoms (0.860736 coins) remain within the 3B budget as integer-rounding remainder.

This is arithmetic/candidate evidence, not active consensus. The profile is not fully wired through canonical Genesis, block production, validation/import, fork-choice/reorg, persistence, replay, snapshots and state roots. Gate 2 remains open. No live Mainnet, production miners, market, listing or revenue claim follows from this record.

## Benchmark record and claim boundary

- Current maintainer-checkout Rust regression recorded 736/736 library tests and no failures in remaining all-target tests; format and locked/offline check passed.
- Separate local QX launch-asset EVM/console/loopback-server suites passed.
- Single-host Rust Argon2id screen: 13.395 H/s at 64 MiB on an Intel Core i7-8565U Windows machine. A separate host/implementation screen reports 15.956 H/s at the same nominal memory setting. No energy/hash, GPU/ASIC comparison, total network hashrate or miner profitability is established.
- Candidate asset-state screen: 16,384 assets / 32,768 holdings; 6,280,432-byte snapshot; approximately 12.07 seconds for the repeated candidate block-plus-full-state-root metric on the same CPU class. This is candidate-only and not whole-node TPS.
- No native end-to-end multi-node TPS, public-network p50/p95/p99 latency, production block-time, Mainnet uptime or independent security-audit result is claimed.

## Public contact

The site contains mailto links directing proposals to the founder. Suggested scopes include milestone-based research/engineering sponsorship, Rust/protocol development, cryptography/security review, EVM integration, AI/LLM research prototypes, academic/grant collaboration, infrastructure, and future technical-readiness discussions with exchanges or market-data providers. No platform listing is represented as live or guaranteed.

## Validation performed / required after merge

- The full maintainer checkout was rerun locally: cargo fmt --all -- --check; cargo check --all-targets --locked --offline; cargo test --all-targets --locked --offline; npm test in contracts/launch-asset; simulations/sponsor_allocation_checker.py.
- Added simulations/public_docs_refresh_checker.py for HTML nesting/anchor validation, README relative links, candidate emission arithmetic and exact Git-blob SHA-256 manifest verification.
- GitHub Pages publication status must be checked after merge, and the merge SHA recorded in the final release checkpoint.
- The separate revm lab was not rerun because the workstation toolchain requirement differs from the available Rust/Cargo version.
- Native production profile/Genesis, anti-rollback Gate 8, canonical EVM integration, public multi-operator devnet, independent security review and network TPS qualification remain open.

This checkpoint makes the project easier to evaluate and contact, without elevating candidate research to production status.
