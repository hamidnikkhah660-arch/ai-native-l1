# CP-0450 — QRun v0.5 identity and Genesis commitment candidate

**Date:** 2026-10-28
**Status:** Candidate identity is aligned to the currently installed owner wallet for continued engineering; Mainnet remains **not activated**.

## Fixed candidate values

- Native network / asset: QRun / QZXB.
- Decimal places: 8; total supply and Genesis owner allocation: exactly 10,000,000,000 QZXB = 1,000,000,000,000,000,000 atoms.
- Network ID is the SHA-256 digest of the domain-separated label `QUANTUMZXB-QRUN-MAINNET-NETWORK-ID-V05\0`.
- Owner account is the public account ID read from the currently installed persistent QZXB wallet (eee2e72882d770ab6fd7815c905b49e39650c74e8f121b26cbd49e333a3715c8); the account ID was checked via the wallet CLI address command. No private key or recovery phrase is embedded.
- Network ID: `70fdcdbe6f0afa1edb0c4fb4a85252831376f7b9ecf2a13a86dcf61979cdcad7`.
- Genesis state root: 4064e1dafec1c18ed5fb035f17b515e11d5ab314dea0a20e2294f230470ff440.
- Genesis commitment: 613bb4f36c8e57e73dd04308809b9decdd1b4411e0838f948ee2aa7eaacbab97.
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