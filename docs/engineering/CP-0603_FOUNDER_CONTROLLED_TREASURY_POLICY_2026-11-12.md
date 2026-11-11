# CP-0603 — Founder-controlled Treasury policy candidate
Date: 2026-11-12

- Maximum gross supply: 10B QZXB.
- Genesis credits 7B to one QFP6 founder account: 1B direct + 6B discretionary Treasury.
- Six 1B priority ceilings (Community, Exchange/Liquidity, Marketing, Developers/Security, Strategic Supporters, Conditional Burn) are earmarks inside the same 6B account balance, not additional Genesis recipients or issuance.
- 3B is the maximum mining/security issuance envelope.
- The founder alone decides whether, when, and how much to transfer to recipients. Transfers debit the founder balance and do not mint.
- The 1B conditional-burn earmark stays founder-controlled until the founder authorizes irreversible burn; no automatic burn.
- The canonical executor must verify the founder's hybrid signature before these deterministic candidate transitions. Signature verification is not implemented here.
- This candidate is NOT wired into canonical QFB6 Genesis, Ledger, block execution/import/replay, fork choice, checkpoint, snapshot codec, or QFP6 runtime. No QZXB has been issued; no Mainnet balance exists.

## Required integration
1. Replace CP-0528's 1B Founder Genesis policy with versioned 7B-founder policy/fingerprint and 3B mining cap.
2. Integrate atomically with canonical Ledger transfers, issuance and burns; verify hybrid signatures in executor.
3. Version and encode monetary state in Genesis snapshot, state root, importer/replay, fork choice, store, checkpoint and anti-rollback.
4. Reject CP-0528/CP-0566D monetary snapshots under the new Mainnet profile without rewriting historical data.
5. Add cross-path tests and regenerate/pin Q6GD/Q6CP/Q6PN/Q6TS/QFP6.
