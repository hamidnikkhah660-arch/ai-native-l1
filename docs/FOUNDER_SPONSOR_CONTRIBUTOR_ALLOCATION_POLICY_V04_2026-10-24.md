# QuantumZXB Tokenomics and Distribution Policy v0.4

> **Superseded for the future QRun Mainnet target by CP-0437 (2026-10-28).** This document preserves the prior v0.4 decision for audit/history; it is not the current Genesis target.

**Date:** 2026-10-24
**Status:** Owner-directed allocation policy; not yet encoded in canonical production Genesis/runtime, not an on-chain balance statement, and not a market or investment promise. This policy supersedes the former 40% / 30% / 30% framework for current planning. The v0.3 policy and CP-0343 sponsor calculator are historical only. The binding owner decision and migration requirements are recorded in [CP-0422](CP-0422_CANONICAL_TOKENOMICS_DECISION_2026-10-26.md).

## 1. Total cap and planned allocation

The proposed maximum native QZXB supply is **10,000,000,000 coins**. These eight buckets total exactly 100%. The cap and allocations remain design terms until one canonical production monetary profile, Genesis, issuance path and all state/supply invariants are frozen and tested.

| Allocation bucket | Share | Planned amount | Release / use principle |
|---|---:|---:|---|
| Mining / network security | 30% | 3,000,000,000 | Earned only under the eventual published consensus/reward schedule; not pre-mined or currently available to miners. |
| Community airdrop | 10% | 1,000,000,000 | Publish eligibility, anti-Sybil rules, claim window and any vesting before distribution; no guaranteed value or return. |
| Exchange, market-integration and liquidity partnerships | 10% | 1,000,000,000 | Conditional reserve for documented integrations/services or bona fide liquidity partnerships. Not a payment-for-listing promise; exchanges decide independently and no listing is guaranteed. |
| Major marketing and promotional partners | 10% | 1,000,000,000 | Written scopes, measurable deliverables, compliant disclosures and staged release; no misleading price or return claims. |
| Developers and security contributors | 10% | 1,000,000,000 | Reward accepted code, audit, testing or scoped work against recorded acceptance criteria; rewards do not replace independent audits. |
| Financial and strategic supporters | 10% | 1,000,000,000 | Prospective pool conditional on written agreements and verified cash, infrastructure or other agreed support. No supporter is implied to be secured. |
| Protocol burn reserve | 10% | 1,000,000,000 | Designated for a transparent, pre-published burn mechanism. Not described as burned until a verifiable burn occurs. No price-support promise. |
| Owner allocation | 10% | 1,000,000,000 | Explicit owner-controlled allocation. Ownership does not authorize hidden issuance, cap changes, bypassing consensus or misrepresenting circulating supply. |
| **Total** | **100%** | **10,000,000,000** | One inclusive cap; no extra issuance above it. |

## 2. Operating rules

1. A planned allocation is not minted supply, circulating supply, cash raised, a signed award, completed airdrop or completed burn. Disclose maximum cap, issuance, reserves, circulating-supply methodology and actual burns separately.
2. The 3B mining/security envelope must be emitted by the tested native consensus/reward path. Gate 2 remains open, so no live miner payout is claimed.
3. The exchange reserve is not a listing guarantee or a default fee. Any award requires a documented counterparty, permitted arrangement, defined services, milestones, disclosures and legal review. Unused tokens remain unawarded.
4. Marketing awards require written scopes, transparent paid-promotion disclosure and performance-based release; do not promise returns or encourage artificial trading volume.
5. Sponsor and contributor awards require recorded terms, recipient/wallet verification, deliverable evidence, amount, timing and approval. A proposal or expression of interest is not a secured sponsor.
6. Only already-issued tokens may be burned; a verified burn is irreversible, reduces live supply, does not reduce cumulative gross issuance and never restores mint headroom. Define eligible source balances, authorization, trigger and transaction evidence. The 1B protocol burn reserve is a category cap, not a claim that 1B is already burned or a source of additive supply. Do not advertise burns as price support.
7. The founder allocation is fixed at 1B / 10% of the 10B cap, with no protocol lock or time vesting under the latest owner direction. Public documentation must not expose private keys or recovery material. Founder control remains subject to ordinary transaction authentication and published consensus rules; it does not create a hidden mint or consensus override.
8. Any later percentage change requires a versioned policy, checked arithmetic, updated public docs and review before production deployment.

## 3. Zero-personal-budget financing

Pursue ecosystem grants, voluntary open-source donations, milestone-based strategic sponsorship, in-kind engineering/security contributions, and scoped paid protocol/developer-tooling services that the project can genuinely deliver. These are avenues to pursue, not committed income. Tokens are not cash and an allocation does not prove liquidity. Do not promise or spend funds that have not actually been received or secured contractually.

## 4. Launch gates and stop conditions

- **Gate 2 — open:** freeze and integrate canonical native Genesis, supply cap and mining/reward profile through block production, validation/import, fork-choice/reorganisation, persistence, replay and snapshots/state roots; pass deterministic supply and adversarial tests.
- **Gate 8 — open pending independent evidence:** qualify monotonic anti-rollback trust and crash/recovery across independently operated hosts/storage, with the external trust boundary and failure behaviour documented and tested.
- Complete native RPC, wallet, explorer and a zero-value public devnet; verify production identity; obtain independent protocol/cryptography/security review and address material findings.
- Complete jurisdiction-specific legal review and required disclosures before any public sale/distribution or market activity. A token allocation table is not legal clearance.
- Describe live price, trading, supply or market-data integration only when backed by actual on-chain/exchange data. This policy does not claim a launched native QZXB mainnet or liquid native-coin market.

## 5. Non-claims

This policy does not state that a mainnet, token sale, exchange listing, liquid market, sponsor, marketing agreement, cash receipt, airdrop, mining payout or burn is already active. It promises no price appreciation, minimum price, profitability or investment return. The Sepolia QX ERC-20 experiment is a separate test asset and not the native QZXB launch.
