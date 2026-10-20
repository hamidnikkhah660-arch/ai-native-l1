# Public Source Release Manifest — AI-Native L1 Research Preview

Prepared: 2026-10-20  
Intended channel: globally accessible public GitHub repository  
Repository slug: `ai-native-l1-research-preview`  
Working phrase: “Quantum ZX” (not a cleared trademark or ticker)  
Version label: `v0.1.0-preview`

## Contents and licensing

This repository is intended for anyone worldwide to browse, clone, fork and review without login once public. It contains the native research/benchmark crate, its source-referenced test fixtures, the Python prototype models, a separate EVM ERC-20 candidate with isolated local tests, a testnet status record, contributor/security templates and two CycloneDX SBOMs.

The root Apache-2.0 license applies only to project-authored materials within the curated tree and to the extent the project owner has authority to license them. The Solidity contract preserves its separate MIT header. The upstream ASERT vector set preserves its source/hash record and MIT notice. The selected Wycheproof vectors preserve an Apache-2.0 attribution notice; the original upstream revision/hash was not available in the inherited record and that limitation is disclosed. Package dependencies retain their own terms; package-manager source distributions are not bundled.

This repository does **not** contain the full owner workspace, original repository history, unreviewed brand artwork, private owner vault records, deployment secrets, or broad unrelated historical experiment corpora. Public access is unrestricted; the uploaded source contents are a deliberate release tree to avoid publishing unrelated/private or unverified material. This is not represented as a full dump of all local files.

## Verification checklist

- [x] Root LICENSE and explicit file-level exceptions included.
- [x] Name/ticker wording avoids claims that ZX, QZX, QX or “Quantum ZX” is globally cleared.
- [x] README differentiates the native L1 from the Ethereum Sepolia EVM test token.
- [x] Privacy scan finds no owner workstation path, private-key block marker, common GitHub token pattern or AWS access-key pattern in the curated non-build source.
- [x] Rust `cargo fmt --all -- --check` passed.
- [x] Rust `cargo check --all-targets --locked --offline` passed, warnings only.
- [x] Full Rust `cargo test --all-targets --locked --offline` final execution exit code 0; library 735/735 and every binary/integration test target reported zero failures. Run used only locked dependencies and no public network.
- [x] EVM `npm ci --offline` completed; package-manager audit reported zero vulnerabilities among 74 audited packages.
- [x] EVM compile passed on Solidity 0.8.37.
- [x] EVM local-only package tests passed; output states `public_network=not_contacted`.
- [x] CycloneDX 1.6 SBOM produced for the native Cargo lockfile; CycloneDX 1.5 SBOM produced for the EVM npm lockfile.
- [ ] Independent external protocol/cryptographic audit.
- [ ] Native mainnet canonical issuance/Genesis/transaction integration (Gate 2).
- [ ] Independent anti-rollback trust and power-loss/recovery qualification (Gate 8).
- [ ] Public zero-value devnet/operator qualification.
- [ ] Public-offer/activity-by-jurisdiction review prior to value-bearing distribution (Gate S1).

## Honest release boundary

Publishing this repository is a public source-code release and invitation to collaborate; it is not a public native-chain launch. The current native prototype has no verified public mainnet and no independent public devnet/operator qualification. The Sepolia ERC-20 is a separate testnet token and not approved for sale or real value. “Quantum” is a project codename only; ML-DSA experiments do not establish end-to-end post-quantum security. No price, return, revenue, listing, liquidity, sponsorship or audit is claimed.

## Revenue and support

The repository invites independent developers, technical reviewers, potential research sponsors and community contributors to open issues or propose pull requests. The repository itself does not automatically generate income, and no payment method, sponsor contract or token sale has been set up by this release. Do not solicit funds using implied guarantees or fabricated market activity.

## File-integrity manifest

`RELEASE_SHA256SUMS.txt` contains SHA-256 hashes of release files at packaging time, excluding the hash manifest itself and generated build/dependency cache directories. Regenerate it after any source change.
