# CP-0581 — QFP6 hybrid BIP39 wallet candidate

**Date:** 2026-11-10  
**Parent:** CP-0580 / Q6HA v1 hybrid transaction authentication  
**Status:** Windows DPAPI wallet candidate and local validation only; not a production wallet release

## Implementation

- Preserves QZKW1 v1 and its legacy Ed25519 BIP39 derivation / QZTS/1 submission path.
- Adds QZKW2 v2 for QFP6 Q6HA v1 / suite 1. It stores both public keys, the hybrid account ID and a Windows CurrentUser-DPAPI protected 64-byte pair of secret seeds.
- Reuses standard 12-word English BIP39 recovery. The Ed25519 half uses the existing QZKW1 derivation domain; ML-DSA-65 uses a distinct QFP6 derivation domain.
- Restoring the same phrase reconstructs the same QZKW2 identity. The Q6HA account ID is deliberately different from the QZKW1 Ed25519-only address.
- Detects QZKW2 in sign-transfer and creates both signatures over the same TXN2 digest using the QFP6-specific 8 KiB bound. It refuses --submit-to: Q6HA must not be sent through legacy QZTS/1.

## Local verification on Windows host

- QZKW2 BIP39 derivation is deterministic, derives distinct Ed25519 and ML-DSA-65 seeds, and produces a different account ID from legacy QZKW1.
- QZKW2 DPAPI create/load round-trip passed; modifying the stored ML-DSA public key is rejected by the protected-blob/public-identity binding.
- A real Libcrux ML-DSA-65 + Ed25519 Q6HA signature was generated and verified; QFP6 8 KiB native-transfer encoding and transaction-ID derivation passed.
- Legacy TXN2 4 KiB encoder rejected the hybrid signature; the wallet refuses to broadcast it through legacy QZTS/1.
- cargo test --manifest-path src/native/pow_bench/Cargo.toml --bin qzxb_wallet --locked --offline: 10 passed, 0 failed.
- cargo check --manifest-path src/native/pow_bench/Cargo.toml --all-targets --locked --offline: PASS.
- cargo fmt --manifest-path src/native/pow_bench/Cargo.toml -- --check and git diff --check: PASS.
- Existing unrelated compiler warnings remain in older candidate/test code.

## Commands

- qzxb_wallet create-qfp6-hybrid --output ABSOLUTE_PATH
- qzxb_wallet restore-qfp6-hybrid --output ABSOLUTE_PATH
- qzxb_wallet address-qfp6-hybrid --wallet ABSOLUTE_PATH
- qzxb_wallet sign-transfer --wallet QZKW2_PATH ...

## Boundaries

- CurrentUser DPAPI is local Windows user/machine-bound custody, not portable cross-device custody, HSM/KMS or hardware wallet support.
- QZKW2 is a new identity, not an in-place migration of QZKW1. Existing QZKW1 balances/keys are not reinterpreted.
- The Libcrux ML-DSA-65 adapter remains candidate-only pending independent cryptographic review.
- No production mnemonic passphrase support, hardware key isolation, audited wallet UX or external restore drill is claimed.
- QFP6 node executable, Q6PA transaction ingress, public RPC/mempool and Genesis founder identity do not yet select Q6HA/QZKW2. Offline signing is not broadcasting and does not create a balance.
- No public Mainnet, issuance, public QZXB balance, real-value transaction or QZXB/USDT liquidity is created by CP-0581.

Keep this change on a Draft PR until exact-head Windows/Linux CI and independent wallet/cryptography review pass. Do not merge or activate it as Mainnet policy.
