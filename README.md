# AI-Native L1 — Quantum ZX Open Research Source

**Globally accessible open-source research release — not a production network, investment offer, or authorization to use real funds.**

“Quantum ZX” is a provisional working codename only. The public brand and ticker have not been cleared. A preliminary search found existing use of **ZX** in Zeta X's Solana rollup/trading project, and **QZX** in already-deployed BNB Chain token listings. Do not treat either as an available/unique market ticker. “Quantum” is not a claim that the native protocol is quantum-resistant or post-quantum secure. See `docs/PUBLIC_SOURCE_SCOPE_AND_RELEASE_STATUS_V01_2026-10-20.md`.

## What is in this release

- `src/native/pow_bench`: Rust proof-of-work, authenticated-transport and related research/benchmark harnesses.
- `src/prototype`: small Python network/chain models.
- `contracts/launch-asset`: a separate fixed-supply ERC-20 research candidate and tests.
- `tools/evm_testnet_wallet*.html`: browser-console source for isolated testnet experiments.
- `docs/TESTNET_DEPLOYMENT_STATUS.md`: factual status of the historical Sepolia deployment for the distinct EVM candidate.

This is a **curated public release tree** from the owner's larger working repository. Public access is unrestricted: anyone worldwide can browse, clone, fork and review it without login once the repository is public. It excludes the broad historical simulation/VM corpus beyond exact fixtures referenced by this crate, project logo/brand artwork, owner-only notes, deployment secrets/private keys, and the original full commit history. The specific ASERT and Wycheproof vector files required for local verification are included with source/license notices. Nothing here grants rights in excluded material.

## Critical network and asset distinction

The EVM ERC-20 in `contracts/launch-asset` is **not** the native L1 coin. Its recorded deployment is on Ethereum Sepolia only; all initial 40/30/30 allocation tranches are transferable and have no contract-enforced vesting. It is not approved for mainnet, a sale, liquidity, or real-value use.

The native L1 is a research prototype, not a verified public network. Canonical issuance/Genesis/transaction-runtime integration (Gate 2), independently trusted anti-rollback storage and recovery (Gate 8), independent protocol/security review, and public-offer analysis have not been completed. Local test suites do not by themselves close those gates.

The presence of ML-DSA in a research/benchmark dependency graph does not prove end-to-end post-quantum protection for transaction signatures, wallet keys, consensus, networking, or the native protocol. Do not market this project as “quantum-proof” or “quantum-resistant” until the actual protocol integration is specified, implemented, independently tested, and reviewed against suitable post-quantum standards.

## Reproduce local checks

Rust research crate (locked dependencies; Rust 1.82-compatible):

```powershell
Set-Location .\src\native\pow_bench
cargo fmt --all -- --check
cargo check --all-targets --locked --offline
```

Separate EVM candidate (Node.js/npm):

```powershell
Set-Location .\contracts\launch-asset
npm ci
npm run compile
npm test
```

The EVM tests use an ephemeral local development chain and do not contact a public network. Do not run a deployment script as part of routine verification.

## License scope

Original project-authored content in this curated preview is offered under Apache-2.0 to the extent the project owner has authority to license it. `contracts/launch-asset/contracts/FixedSupplyLaunchAsset.sol` explicitly carries its own MIT license and remains MIT. Package dependencies keep their own licenses and notices; their source distributions are not bundled here. The root `LICENSE` and `LICENSES/README.md` state the scope and exceptions.

No trademark, ticker, domain, token-name, or logo license is granted. This preview intentionally contains no logo artwork.

## Software bill of materials (SBOM)

Machine-readable CycloneDX dependency inventories are in `sbom/`: one for the Rust native research crate and one for the separate EVM candidate. Their exact scope and metadata limitations are documented in `docs/DEPENDENCY_SBOM_STATUS_V01_2026-10-20.md`. They are not a full SBOM for the owner's entire workstation or a legal compatibility opinion.

## Status

This is an invitation for technical review and collaboration, not an announcement of a native mainnet, public token sale, listing, liquidity, price, revenue, completed audit, regulatory approval, or sponsor commitment. Real-money operation requires separate verified engineering, security, custody, and activity-specific compliance work.
