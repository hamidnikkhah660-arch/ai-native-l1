# CP-0605 - CP-0604 Genesis bootstrap preflight compatibility

Date: 2026-11-12
Status: local implementation and targeted validation passed; production bootstrap remains preflight-only.

## Changes

- Updated the QFP6 read-only node preflight Genesis verifier to accept the CP-0604 founder-controlled supply policy in addition to the legacy CP-0528 policy.
- CP-0604 verification binds the founder account and policy fingerprint to the independently pinned Q6GD descriptor, requires zero mining issuance at Genesis, requires the exact 7B founder balance, and checks the Ledger total against CP-0604 gross issuance.
- Retained CP-0528 verification as an explicit compatibility branch; no old allocation is silently reinterpreted as CP-0604.
- Fixed a canonical execution invariant guard that previously rejected any descriptor-backed state without CP-0528 tokenomics, even when a valid CP-0604 supply policy was present.
- Added a CP-0604 full Genesis snapshot test alongside the existing CP-0528 compatibility coverage.

## Validation

- `cargo test --manifest-path src/native/pow_bench/Cargo.toml --locked --offline --bin qrun_v06_node`: 17 passed.
- `cargo check --manifest-path src/native/pow_bench/Cargo.toml --all-targets --locked --offline`: passed.
- `cargo fmt --manifest-path src/native/pow_bench/Cargo.toml -- --check`: passed.
- `git diff --check`: passed.

## Remaining boundary

This only makes the read-only preflight understand the CP-0604 Genesis snapshot. It does not start a production node, create or sign the final Mainnet Genesis, activate public listeners/mining, prove independent-host sync or reorg recovery, or create market liquidity. Mainnet remains inactive and PR #194 remains unmerged.
