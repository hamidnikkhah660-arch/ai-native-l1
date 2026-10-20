# Dependency Inventory and CycloneDX SBOMs — Public Source Release

Date: 2026-10-20

## Artifacts

- `sbom/native-pow-bench.cdx.json`: CycloneDX 1.6 generated from `src/native/pow_bench/Cargo.lock` and cross-referenced against the project's dated, manifest-derived Cargo license metadata inventory. It describes 103 locked package records: one root research crate and 102 dependency components. In that inventory cross-reference, no component lacked a license expression. This is still metadata, not independent examination of every upstream license file.
- `sbom/npm-launch-asset.cdx.json`: CycloneDX 1.5 emitted by npm for `contracts/launch-asset/package-lock.json`. The raw npm output contained 105 component entries but repeated the same `bom-ref` for three identical `@noble/hashes@1.8.0` package copies in different install paths. A normalization pass merged these only after verifying that content hashes/licenses matched and retained all three paths in a property. The final BOM has 103 unique component references, 104 dependency nodes, and no dangling references.
- `src/native/pow_bench/Cargo.lock` and `contracts/launch-asset/package-lock.json` are the version-lock sources.
- `docs/THIRD_PARTY_NOTICES_AND_LICENSES.md`, `LICENSES/README.md`, and `LICENSES/WYCHEPROOF-NOTICE.md` explain scope and known source-level exceptions.

## Verification recorded during preview preparation

- `npm ci --offline` completed and reported zero vulnerabilities across the 74 packages it audited. This is the package manager's audit result for that npm install; it is not a code audit or a guarantee of zero vulnerabilities.
- Native build metadata is based directly on Cargo.lock because this workstation's Cargo 1.82.0 can compile the locked crate, but `cargo metadata` attempted to resolve target-specific `wit-bindgen` 0.57.1, which requires a newer Cargo edition-2024 parser. The SBOM generator therefore parses the checked-in Cargo lockfile and uses the separate reviewed manifest inventory for license-expression metadata.
- SBOM files list dependencies and available license metadata; they do not prove that all third-party license terms are mutually compatible, nor that every component has been legally cleared for every distribution context.
- The broader owner working tree has additional manifests and package families not present in this curated preview. These two SBOMs cover only the native Rust research crate and the separate EVM launch-asset package included here, not every artifact in the original workspace.

## Scope warning

Do not describe these files as an independent legal opinion, exhaustive all-project SBOM, source-code provenance audit, or approval for a value-bearing launch.
