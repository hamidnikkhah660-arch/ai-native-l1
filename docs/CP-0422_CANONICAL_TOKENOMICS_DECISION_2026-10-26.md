# CP-0422 — Canonical Tokenomics Decision and Runtime Reconciliation

> **Superseded for the future QRun Mainnet target by CP-0437 (2026-10-28).** This document preserves the prior v0.4 decision for audit/history; it is not the current Genesis target.

**Date:** 2026-10-26
**Status:** Founder economic decision recorded. Repository reconciliation is in progress; this document does not claim production integration or network launch.

## 1. Canonical founder decision

The latest owner direction supersedes older conflicting allocation proposals:

- Maximum native QZXB supply ceiling: **10,000,000,000 QZXB**.
- Precision: **8 decimal places**; 1 QZXB = 100,000,000 base units; cap = 1,000,000,000,000,000,000 base units.
- Founder allocation: **1,000,000,000 QZXB (10% of the maximum cap)**.
- The historical 4B founder / 3B mining / 3B public-goods proposal is retired for current allocation planning.
- Historical sponsor/contributor shares carved from the former 4B founder tranche do not carry forward. Any sponsor or contributor award must come from the dedicated v0.4 category cap and cannot add supply.
- The former owner direction that the founder tranche has no protocol lock or time vesting remains in force for the new 1B tranche. It is still subject to standard transaction authentication and consensus rules.

## 2. Exclusive maximum allocation envelopes

| Bucket | Maximum QZXB | Share |
|---|---:|---:|
| Mining / network security | 3,000,000,000 | 30% |
| Community airdrop | 1,000,000,000 | 10% |
| Exchange / market integrations / liquidity partnerships | 1,000,000,000 | 10% |
| Marketing and promotional partners | 1,000,000,000 | 10% |
| Developers and security contributors | 1,000,000,000 | 10% |
| Financial and strategic supporters | 1,000,000,000 | 10% |
| Protocol burn reserve | 1,000,000,000 | 10% |
| Founder | 1,000,000,000 | 10% |
| **Total** | **10,000,000,000** | **100%** |

These are ceilings, not current balances, guaranteed awards, circulating supply or market liquidity. No bucket may overdraw its own cap or the global cap.

### Burn semantics

Only already-issued tokens can be burned. A valid burn permanently reduces live supply but never reduces cumulative gross issuance and never restores mint headroom. The 1B protocol burn-reserve bucket is a separate category ceiling: it is not already burned at Genesis and is not an extra source of supply. Any mint/release from that bucket must be authorized by the deterministic, versioned protocol policy and count toward the 10B global cap.

## 3. Mining parameters selected for the v0.4 design target

The project README currently records these as candidates; this decision adopts them as the design target, but production activation remains blocked until the canonical implementation and oracle vectors prove them:

- 30-second target block interval.
- Difficulty adjustment window: 2,016 blocks.
- Candidate PoW: Argon2id v1.3, 64 MiB, one iteration, one lane.
- Initial subsidy: 356.73515981 QZXB.
- Halving interval: 4,204,800 blocks.
- Subsidy calculations use integer base units and deterministic integer division at each halving. Actual reward is clamped to the remaining 3B mining envelope. No discretionary top-up occurs if rounding leaves a small remainder; no new subsidy is issued once the mining envelope is exhausted.

With 8-decimal integer halving, the current candidate values total **2,999,999,999.139264 QZXB** over the nonzero eras, leaving **0.860736 QZXB** unissued in the mining envelope. The independent oracle and Rust implementation must reproduce this exact result before production use.

## 4. Genesis and non-mining pool release

The current v0.4 Genesis candidate records only the 1B founder balance. Other category caps are not Genesis balances. This is a useful candidate state, but it does not complete future distribution rules.

- Do not silently place 4B in the founder account or reinterpret historical v3 state.
- For an initial release, only the 1B founder Genesis balance and consensus-calculated mining subsidy may be issued unless explicit, deterministic release rules for another category are integrated and committed to the production Genesis/profile.
- Airdrop eligibility, market-integration awards, marketing awards, developer/security awards, sponsor awards and protocol-reserve release require versioned rules, category caps, recipient verification/authorization, and reproducible accounting.
- No private keys, treasury addresses, recipients or sponsor contracts are invented by this decision.
- Gross cumulative issuance, current live balances and cumulative burns must remain separate accounting quantities.

## 5. Version boundary: preserve history, do not silently downgrade

The old v3 policy/state machine and v0.3 sponsor calculator may retain 4B/40% arithmetic only as historical protocol/test material. They must be marked **historical v0.3 only** and must not be presented as current v0.4 policy. Do not rewrite old policy fingerprints or snapshots in place. The current v0.4 tokenomics checker is the active policy arithmetic check.

## 6. Required reconciliation before a production Genesis

1. Link this decision from the current README, roadmap and v0.4 tokenomics policy.
2. Mark the v0.3 sponsor/contributor calculator as historical-only and keep its original behavior for historical reproduction.
3. Extend the current tokenomics checker to assert the 10B total, all eight caps, founder 1B/10%, and the historical-checker separation.
4. Recompute release manifest hashes after all changes.
5. Prove the chosen monetary profile through the actual canonical producer, importer, fork choice, durable store, replay, reorg and state-root paths; add legacy downgrade and wrong-profile rejection.
6. Run formatting, checks, all relevant monetary tests/oracles, and exact-head CI.
7. Before calling any network public/live, run the actual zero-value devnet node using its documented CLI, prove two-node connectivity, matching canonical tip/state root, invalid-signature rejection, restart and controlled-reorg behavior. Mainnet/value-bearing activation remains separately gated.

## 7. Execution status

This decision resolves the founder's intended allocation: 10B maximum, founder 1B/10%, and the seven other allocation envelopes shown above. It does **not** state that the policy is integrated into canonical consensus, the native mainnet is safe, a security audit is complete, or a public network is running. Those need separate code/test/run evidence.
