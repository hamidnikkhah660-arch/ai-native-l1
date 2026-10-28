# CP-0450 — QRun v0.5 identity and Genesis commitment candidate

**Date:** 2026-10-28
**Status:** Proposed identity and Genesis commitment are pinned for continued engineering; Mainnet remains **not activated**.

## Fixed candidate values

- Native network / asset: QRun / QZXB.
- Decimal places: 8; total supply and Genesis owner allocation: exactly 10,000,000,000 QZXB = 1,000,000,000,000,000,000 atoms.
- Network ID is the SHA-256 digest of the domain-separated label `QUANTUMZXB-QRUN-MAINNET-NETWORK-ID-V05\0`.
- Owner account is the public account ID previously read from the owner's persistent QZXB wallet; no private key or recovery phrase is embedded.
- Network ID: `70fdcdbe6f0afa1edb0c4fb4a85252831376f7b9ecf2a13a86dcf61979cdcad7`.
- Genesis state root: `9d8ab7e2c415e83990a63274e7851e6ebd891868a74422a6e6ed418895f27887`.
- Genesis commitment: `0815c01a85373caf7f50b53aaeb7a269ef4a151f2a3ba3171acc8ee2b52f8908`.
- Later minting and block subsidy are both fixed to zero under this full-supply direction.

Machine-readable values are in `profiles/qrun_v05_mainnet_identity_candidate.json`. The Rust candidate module and independent Python oracle verify the Genesis state root and commitment formulas. This freezes identity inputs only; it does not make the runtime production-ready.

## Explicitly unresolved launch gates

1. The production consensus/difficulty/timestamp/profile fingerprint is not frozen or wired through producer, importer, replay, fork choice, and restart.
2. The current PoW block envelope does not commit a fee beneficiary. The ledger accumulates fees in `fee_pool` but has no canonical fee-only producer payout. A production block format and replay rule must commit the beneficiary and settle fees without increasing total supply.
3. Full-history validation or an independently verifiable, automatically rolling checkpoint trust model is not integrated; a caller-supplied local anchor is not an external anti-rollback provider.
4. Production peer bootstrap/churn, transaction relay limits and independent multi-host restart/fork testing are unfinished.
5. Independent security review and owner-side verification of the final manifest remain required before public activation.

## Decision

Keep public listeners and Mainnet activation disabled. Do not reuse the test-only loopback binary or its easy PoW parameters. The 10B balance represented here is a deterministic candidate Genesis commitment, not spendable public coins and not evidence of a market price or trade. The release must fail closed until every gate above is addressed and independently verified.