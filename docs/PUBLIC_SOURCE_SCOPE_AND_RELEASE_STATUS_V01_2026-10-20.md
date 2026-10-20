# Public Source Scope and Release Status — V01

Date: 2026-10-20  
Artifact: globally accessible public source release (curated file set)  
Historical identity at initial v0.1.0 source release: “Quantum ZX”. This is superseded as the current working name by `docs/BRAND_IDENTITY_DECISION_V02_2026-10-20.md`, which selects QuantumZXB with QZXB as an un-cleared ticker proposal.

## Release contents

This repository contains the Rust native research/benchmark crate, small Python prototype models, a separate EVM launch-asset experiment and its tests, testnet wallet-console source, contributor/security policy files, license text and a concise testnet status report.

## Name/ticker screen

A preliminary open-web search found:
- **ZX** used in Zeta X documentation for a planned Solana rollup/trading project: https://docs.zeta.markets/zeta-x/zeta-x-litepaper/zx
- **ZX** used by an existing BNB Chain token pool: https://dexscreener.com/bsc/0x7a8f9d8f9eb8e6dd4b02fa68bbb13d103d0f17de
- **QZX** used by already-deployed BNB Chain token listings, including: https://coinranking.com/coin/oFKJgOySDl0r%2B-qzx and https://apespace.io/bsc/0x3b055dba74fe8617c5c6d7c94a2388673156618d
- Qubic uses the related Qx/QX designation for a decentralized exchange: https://docs.qubic.org/learn/qx/

These facts do not establish that every possible use of ZX or QZX is infringing. They are sufficient to reject a claim that either ticker is unique or obviously collision-free. “Quantum ZX” remains a provisional codename, not an officially cleared global mark.

## Explicit exclusions

The original full repository history; broad historical simulation/VM trees beyond exact fixtures used by this release's tests; unreviewed project logo/brand SVGs; full checkpoint/continuation history; owner-local vault/security records; and deployment credentials/private keys were not copied. The specific ASERT and Wycheproof vector files required by the Rust test suite are included with available provenance/license notices. The EVM and Cargo dependencies are represented by lockfile entries, not by bundled dependency source trees.

## Technical status / no false launch claims

- Native canonical issuance + Genesis + transaction/runtime integration (Gate 2): OPEN.
- Independent anti-rollback trust and rollback/recovery qualification (Gate 8): OPEN.
- Independent external protocol/cryptographic audit: not completed.
- Native public zero-value devnet/operator qualification: not completed.
- Public offer/value-bearing launch approval: not established.
- The historical Ethereum Sepolia ERC-20 is separate from the native L1; it is not a production launch.
- The presence of ML-DSA as a dependency/research harness does not prove end-to-end post-quantum security.
- No sale, market, pool, listing, price, revenue, audit, approval or sponsor relationship is represented as live.

## Quality evidence

From this clean source tree, `cargo fmt --all -- --check` and `cargo check --all-targets --locked --offline` passed. Final `cargo test --all-targets --locked --offline` returned exit code 0 (735/735 library tests and all binary/integration targets passed). The EVM candidate compiled with Solidity 0.8.37; its local-EVM, wallet-console and loopback server tests passed after offline npm install. These checks do not substitute for independent validation, cross-client consensus review, production-network qualification, power-loss testing or an external security audit.

## Third-party rights and license

The root Apache-2.0 grant is limited as described in LICENSES/README.md; the Solidity source retains its file-level MIT license. Dependencies retain their own license and notice terms. Unrelated broad source corpora and unreviewed brand artwork are excluded; only the test vectors required for this source tree are included with the notices described in LICENSES/README.md and docs/THIRD_PARTY_NOTICES_AND_LICENSES.md.

Public access to the uploaded repository is intended to be unrestricted worldwide. The content is still a curated release tree, not every file in the owner's working tree. These SBOMs do not cover every manifest in the original workspace and this document is not a legal opinion, trademark clearance or authority to sell tokens. Any later source expansion requires a separate provenance and dependency/license review.
