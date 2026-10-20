# Third-Party Notices — Curated Public Technical Preview

Date: 2026-10-20

## File-level licenses and upstream test data

| Material | License/status | Handling |
|---|---|---|
| Original project-authored Rust/Python prototype, tests, scripts and docs in this curated preview | Apache-2.0, as scoped in LICENSES/README.md | Root LICENSE applies only to material the project owner has authority to license |
| contracts/launch-asset/contracts/FixedSupplyLaunchAsset.sol | MIT SPDX header in source | Preserve the MIT header and MIT terms; Apache-2.0 does not override it |
| simulations/asert_upstream_vectors/run01 through run12 | Upstream Bitcoin Cash Node ASERT test vectors; MIT | SOURCE.md and LICENSES/BITCOIN-CASH-NODE-COPYING.txt are retained with the required vector subset |
| simulations/crypto_vectors/ml_dsa_65_wycheproof_selected.tsv | Selected/adapted ML-DSA test vector data attributed to C2SP Project Wycheproof | Upstream project identifies Apache-2.0 licensing: https://github.com/C2SP/wycheproof. See LICENSES/WYCHEPROOF-NOTICE.md. Exact upstream revision/hash for this selected TSV was not recorded in the original file; the notice states this limitation |
| Cargo/npm dependencies named in lockfiles | Their respective package licenses | Dependencies are not bundled as source here; users must obtain and respect each package's license/notice obligations |

## Limits

This is a file-level notice index, not a complete SBOM or independent license-compatibility opinion. The broader repository's logos, unrelated historical fixtures, checkpoint history and wider dependency manifests are outside this curated release. No trademark, logo, token-name, ticker or domain rights are granted.
