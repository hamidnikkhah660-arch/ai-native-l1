# CP-0781 — Q6GA v3 Mainnet-Native Authorization Primitive

Date: 2026-11-19
Worktree: D:\Temp\ASUS\QRUN_QFP6_UNIFIED_20261118
Branch: feat/q6ga-v3-mainnet-scope-20261119
Base commit: fd8c5527b272b1784c03d41797dd8a0b4d13f403

## Purpose

Implement the cryptographic envelope primitive for a distinct owner authorization scope for native value-bearing Mainnet operation, separate from local-only Q6GA v1 and zero-value Public Testnet Q6GA v2.

This is a protocol engineering primitive only. It is not a Mainnet launch, a production signature, a wallet command, a runtime launch mode, an exchange/market authorization, or an independent security review.

## Change

File: src/native/pow_bench/src/qrun_v06_genesis_approval_candidate.rs

Added:
- Q6GA version 3 and an explicit Mainnet-native scope.
- A distinct Mainnet-native signing domain.
- sign_mainnet_native(), using the existing Ed25519 + ML-DSA-65 owner identity and refusing a zero bootstrap-peer commitment.
- verify_mainnet_native_bindings(), checking the exact Genesis descriptor, Q6GD, Q6CP, Q6PN, Genesis snapshot and bootstrap-peer-set SHA-256 bindings.
- Version-3 encode/decode support while preserving existing v1/v2 wire length and scope checks.
- Tests for v3 round-trip/signature verification, exact peer-set binding, v1/v2 verifier rejection, and refusal of an absent peer-set commitment.

The v3 owner scope does not grant a quote asset, market, exchange, custody, listing, external liquidity, public mining subsidy or other issuance authority. CP-0651 economics remain a 7B gross ceiling, 1B owner Genesis allocation, zero block subsidy and fee-only producer compensation.

## Validation

Command:

cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib qrun_v06_genesis_approval_candidate::tests::q6ga_v3 --locked --offline -- --nocapture

Result: 2 passed, 0 failed, exit code 0.

cargo +stable fmt was run; cargo fmt --check and git diff --check are to be revalidated after this documentation update.

## Explicit non-claims and remaining integration

- The permissionless node launcher still has no Mainnet runtime mode and does not accept Q6GA v3.
- The qzxb_wallet CLI has no Mainnet authorization signing command.
- The Mainnet package builder, non-empty approved peer-set acquisition, authenticated operator/Noise identity admission, and runtime verifier wiring are not implemented by this checkpoint.
- No owner/private wallet material was read, copied, exported or used. No real Q6GA v3 authorization was generated.
- The 1B Genesis audit remains a height-0 snapshot audit, not proof of spendability in a live Mainnet.
- No node process, durable runtime database, network listener, firewall, DNS or external service was changed. Existing PID 20244 / TCP 30333 remains untouched.
- No public network, production coin, live value transfer, exchange or market is claimed.

## Next engineering gate

1. Wire Q6GA v3 into a dedicated Mainnet launch path, not through the Public Testnet boolean or acknowledgement.
2. Require exact non-empty approved bootstrap-peer bytes and authenticated peer identities; fail closed on anonymous Noise XX ingress.
3. Bind the Mainnet runner to the exact v3 authorization and the same Genesis/Q6GD/Q6CP/Q6PN/peer-set bytes.
4. Add a separate owner-local wallet signing flow only after the runtime verifier and package builder are complete and tested.
5. Test the actual 1B Genesis owner balance in disposable two-node Mainnet-mode stores, including signed transfer, canonical inclusion, restart/replay and rejection of reused v1/v2 approvals.
6. Only after those pass, freeze and review the launch package. Market authorization remains a separate later decision.

Disposition: Q6GA v3 cryptographic primitive implemented and two focused unit tests passed. Mainnet runtime integration and end-to-end value-transfer qualification remain open.