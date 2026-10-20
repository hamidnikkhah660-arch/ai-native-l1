# License Scope — Public Source Release

This repository's root Apache-2.0 license applies to original project-authored software and documentation included in this curated preview, only to the extent the project owner has authority to license those materials.

## Explicit exceptions and upstream data

- `contracts/launch-asset/contracts/FixedSupplyLaunchAsset.sol` contains `SPDX-License-Identifier: MIT`; its license remains MIT.
- The subset of `simulations/asert_upstream_vectors/run01` through `run12` needed by the Rust crate retains its upstream MIT license. `simulations/asert_upstream_vectors/SOURCE.md` and `LICENSES/BITCOIN-CASH-NODE-COPYING.txt` are included.
- `simulations/crypto_vectors/ml_dsa_65_wycheproof_selected.tsv` is attributed to C2SP Project Wycheproof, whose upstream project states Apache-2.0 terms. See `LICENSES/WYCHEPROOF-NOTICE.md`. The exact original upstream revision/hash for this selected TSV was not recorded; this is disclosed instead of guessed.
- Packages named in `Cargo.lock` and `contracts/launch-asset/package-lock.json` retain their own licenses and notice requirements. Their source distributions are not bundled here.
- The wider repository's identity artwork, unrelated historical simulation corpus and full checkpoint/continuation history are intentionally excluded. The ASERT and Wycheproof vector files needed for this curated source tree are included with the corresponding source/license notices. This file grants no rights in excluded material.
- No trademark, project name, ticker, domain or logo license is granted. QuantumZXB is the current working identity and QZXB is only a proposed ticker; neither has been legally cleared or reserved.

This scope note is not a complete SBOM, independent third-party compatibility opinion, trademark clearance, security audit, or authorization for a financial offering.
