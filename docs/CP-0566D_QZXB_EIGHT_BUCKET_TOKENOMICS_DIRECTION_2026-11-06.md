# CP-0566D — QZXB eight-bucket tokenomics owner direction

**Date:** 2026-11-06
**Status:** Owner-confirmed monetary policy direction for the future QRun production profile. This versioned decision supersedes CP-0437's later 100%-to-owner Genesis direction for future production design. It does not activate a Genesis, issue coins, freeze production consensus or authorize a public launch.

## 1. Canonical supply target

- Network: **QRun Blockchain** (independent native Layer-1).
- Native asset: **QZXB**.
- Maximum gross issuance: **10,000,000,000 QZXB**.
- Precision: **8 decimal places** (100,000,000 base units per QZXB).
- Eight exclusive allocation ceilings sum exactly to 100% of the single 10B cap.
- The 1B owner allocation is the intended Genesis balance. The 3B mining/security envelope is released only through the frozen native proof-of-work reward schedule. The six 1B category reserves are ceilings, not balances already distributed or automatically available at Genesis.
- No hidden issuance, allocation outside the eight buckets, or supply-cap increase is authorized.

## 2. Eight allocation buckets

| Bucket | Share | Maximum amount | Release principle |
|---|---:|---:|---|
| Mining / network security | 30% | 3,000,000,000 QZXB | Earned only through the canonical, deterministic proof-of-work reward schedule; no pre-mined miner balance. |
| Community airdrop | 10% | 1,000,000,000 QZXB | Eligibility, anti-Sybil controls, claim window, recipient verification and any vesting must be published before release. |
| Exchange, market-integration and liquidity partnerships | 10% | 1,000,000,000 QZXB | Conditional on genuine, documented integrations or bona fide liquidity arrangements; never a promise that an exchange will list QZXB. |
| Major marketing and promotional partners | 10% | 1,000,000,000 QZXB | Written scope, measurable delivery, transparent promotion disclosures and staged acceptance. No artificial volume or price promotion. |
| Developers and security contributors | 10% | 1,000,000,000 QZXB | Accepted code, review, audit, testing or scoped engineering milestones with recorded evidence. Token awards do not replace independent security review. |
| Financial and strategic supporters | 10% | 1,000,000,000 QZXB | Conditional on a real written agreement and verified cash, infrastructure or other agreed support. No supporter or funding is implied to be secured. |
| Protocol burn reserve | 10% | 1,000,000,000 QZXB | Governed by a separate, public, irreversible burn rule. A reserve is not described as burned until a verifiable on-chain burn occurs; no price floor or appreciation is promised. |
| Owner / founder allocation | 10% | 1,000,000,000 QZXB | Intended to be credited to the owner account at Genesis and remains subject to ordinary transaction authentication and network consensus. Ownership confers no hidden mint or consensus override. |
| **Total** | **100%** | **10,000,000,000 QZXB** | **One inclusive hard cap.** |

## 3. Issuance and accounting semantics

1. **Genesis:** the intended initial owner credit is 1B QZXB. The exact owner account, Network ID, profile ID, Genesis timestamp and commitment must be bound into one frozen manifest and independently verified.
2. **Mining:** up to 3B QZXB may be issued only by the canonical proof-of-work reward path. The schedule must be identical in producer, block importer, fork-choice, replay, persistence, snapshots and recovery. No second reward source may duplicate issuance.
3. **Category reserves:** the six other 1B ceilings are not six additional Genesis balances. They remain unissued until a permitted, signed, recipient-accepted and evidence-backed release is applied by the canonical state transition. Unused allocations remain unissued.
4. **Burns:** a burn reduces live supply but never reopens gross issuance headroom. The reserve's custody, eligibility, authorization, ledger debit and proof must be specified and verified; burning must be irreversible under the production trust model.
5. **Supply invariants:** cumulative gross issuance across Genesis, mining and category release must never exceed 10B. State roots, snapshots, checkpoint imports, reorgs, restarts and history replay must reproduce the same issuance counters and live balances.
6. **Public disclosure:** distinguish maximum supply, gross issued, circulating supply, restricted/reserved balances, actual burns and unissued ceilings. A planned allocation is not proof of an issued or transferable balance.

## 4. Mining schedule qualification

The QFP6 CP-0528 candidate currently carries the inherited research values of 35.673515981 QZXB initial subsidy and 4,204,800 blocks per halving. Its deterministic integer-halving test totals 2,999,999,999.139264 QZXB, leaving **0.860736 QZXB** of the 3B ceiling unissued because rewards are rounded down to base units. Before a production profile is frozen, explicitly choose either:

- retain the 3B amount as a **maximum ceiling**, with the 0.860736 QZXB dust permanently unissued and documented; or
- revise the deterministic schedule and independent reference vectors so the intended issuance amount is reached exactly without exceeding the ceiling.

The halving interval must also be evaluated against the final block-time target, network difficulty and long-term miner/operator economics. A 3B envelope alone does not prove adequate network security or sustainable participation.

## 5. Release and governance safeguards

- Category releases require a domain-separated authorization, recipient acceptance, unique nonce/replay protection, expiry, explicit purpose, evidence and milestone policy. A hash of a document binds bytes; it does not prove the off-chain claim is true.
- The five recipient-facing categories (community, market integrations, marketing, developers/security, financial/strategic supporters) must be released only under their specific documented conditions.
- Mining is consensus-issued. The burn reserve follows a separate one-way protocol rule. Founder allocation is not a discretionary reserve for additional issuance.
- No marketing, exchange or supporter allocation is guaranteed. No listing, minimum price, future return, $1 price or liquidity is promised.
- Any later change requires a new owner-authorized versioned policy, exact arithmetic, new policy/profile fingerprints, updated public materials and independent review before activation.

## 6. Historical policy boundary

- CP-0391 / CP-0422 and v0.4 documents described the earlier eight-bucket 10B model. PR #59 merged the public v0.4 allocation table on 2026-10-24.
- CP-0437 (2026-10-28) later recorded a different 10B-to-one-owner / zero-subsidy direction. This 2026-11-06 owner decision now supersedes that direction for future QRun production design. Preserve CP-0437 and all old snapshots/commits as historical records; do not silently rewrite history.
- The QFP6 CP-0528 source currently implements candidate accounting for this eight-bucket model. Its own source labels the inherited mining schedule as candidate input, not frozen production consensus. Candidate implementation and CI do not by themselves close production integration or launch gates.

## 7. Acceptance gates before any production claim

- Freeze and pin a single QRun production Network ID, profile ID, Genesis descriptor and CP-0566D policy fingerprint.
- Ensure QFP6/QFB6 producer, importer, fork-choice, store, replay, reorg, checkpoint, snapshot and external-anchor paths all enforce the same 1B Genesis / 3B mining / six 1B reserve model.
- Resolve the mining-schedule remainder choice and independently verify the entire reward curve, cap boundary and end-of-emission behaviour.
- Test category authorization, recipient acceptance, evidence/milestone policy, replay/nonce rejection, wrong-network and wrong-policy rejection, forks/reorgs and crash recovery.
- Independently review proof-of-work security economics, issuance accounting, cryptography, recovery trust and release artifacts.
- Operate a separately qualified public zero-value Devnet with independent operators before a value-bearing Mainnet decision.

Until those gates pass, CP-0566D is the owner-confirmed economic target, not a statement that any QZXB has been issued on a public Mainnet or is available to buy or trade.
