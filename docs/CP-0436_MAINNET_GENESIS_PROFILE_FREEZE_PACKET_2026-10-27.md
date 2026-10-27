# CP-0436 — Mainnet Genesis and Issuance Freeze Packet (v0.4 candidate)

Date: 2026-10-27
Status: Candidate freeze packet — not an activated Mainnet profile.
Economic decision source: [CP-0422 canonical tokenomics decision](CP-0422_CANONICAL_TOKENOMICS_DECISION_2026-10-26.md).

## 1. Decisions already recorded

The founder-directed v0.4 design fixes these design rules:

- Maximum gross native issuance: 10,000,000,000 QZXB; 8 decimal places (100,000,000 base units per QZXB).
- Eight exclusive category ceilings: 3B QZXB mining/network security (30%); and seven 1B QZXB (10%) ceilings for community airdrop, exchange/market-integration/liquidity partnerships, marketing/promotional partners, developers/security contributors, financial/strategic supporters, protocol burn reserve, and founder.
- Initial Genesis candidate credits only the 1B founder allocation. The other seven buckets are ceilings, not balances and not pre-issued coins.
- Mining candidate parameters: 30-second target block interval; 2,016-block difficulty-adjustment window; Argon2id v1.3 with 64 MiB, one iteration, one lane; 356.73515981 QZXB initial subsidy; 4,204,800-block halving interval.
- Subsidy calculation uses integer base units and deterministic division at each halving, is clamped to the remaining 3B mining envelope, and stops when that envelope is exhausted. The checked candidate schedule issues 2,999,999,999.139264 QZXB across nonzero eras, leaving 0.860736 QZXB unissued due to integer rounding.
- Gross issuance, live supply, and cumulative burns are distinct counters. A burn cannot restore issuance headroom.
- Unsupported profile versions and legacy downgrade must fail closed.

These figures pass the repository v0.4 tokenomics arithmetic checker and independent schedule/Genesis test vectors. Passing arithmetic and candidate unit tests does not establish canonical runtime activation.

## 2. Inputs that cannot be invented or silently defaulted

The following must be supplied, frozen, or independently verified before a public Mainnet Genesis hash is published:

1. Owner account identity: an owner-controlled public account/address or public key whose account ID is computed canonically. Do not commit a private key, seed phrase, or custody secret. The current Genesis constructor rejects a zero owner account and credits the configured owner account with the 1B allocation.
2. Stable network ID and Genesis bytes: the exact 32-byte network ID and resulting canonical Genesis-manifest hash, tied to the selected profile fingerprint and owner account. Test-only fixture IDs are not production values.
3. Full consensus profile: exact initial target, timestamp and median-time rules, chainwork/fork-choice policy, transaction/block/body/snapshot versions, max block/body resource limits, fee rules, activation height and legacy compatibility boundary. These must agree across producer, validator/importer, replay, reorg and store.
4. Transaction authorization profile: exact production signing algorithm(s), address-to-key binding and migration/revocation rules. Loopback evidence does not establish the default production wallet/custody path or end-to-end post-quantum activation.
5. Independent conformance evidence: a second implementation or independent oracle must match Genesis bytes/hash, reward boundaries, 10B cap, bucket accounting, balances and state roots, including invalid profile, overflow, wrong-network, reorg, restart and snapshot adversarial cases.
6. Independent review and release decision: review economic transitions and compatibility behavior, fix all critical/high findings, then record the exact source SHA, reproducible build artifacts, configuration, Genesis hash and explicit activation decision.

No production private key is generated or committed by this packet. If an owner-controlled public account identity is not available, a reproducible final Genesis hash cannot honestly be published.

## 3. Runtime integration exit checklist (Gate 2)

- [ ] One canonical profile/version is selected and wired through block production and mining.
- [ ] Block admission/import derives the only valid reward locally; peer-supplied rewards are never authoritative.
- [ ] Every accepted transfer, fee, reward, burn and category release preserves per-bucket caps and the 10B gross-issuance cap atomically.
- [ ] Fork choice/reorg, durable commit, restart/replay, checkpoint/archive handling and state-root computation use the exact same transition and profile.
- [ ] Unknown versions and unsupported legacy downgrades are rejected without mutating state.
- [ ] Independent cross-language vectors and multi-node state-root/tip comparisons pass from the exact release commit.
- [ ] Independent security review and owner activation decision are attached to the same release commit.

## 4. Current honest state

The v0.4 economic intent is recorded and its arithmetic is checked; public documentation has been reconciled to that intent. Gate 2 remains OPEN because the selected profile is still candidate-only and is not integrated as the one canonical production runtime end-to-end. This document does not authorize value-bearing mining, Mainnet activation, a token sale, or a QZXB/USDT market.
