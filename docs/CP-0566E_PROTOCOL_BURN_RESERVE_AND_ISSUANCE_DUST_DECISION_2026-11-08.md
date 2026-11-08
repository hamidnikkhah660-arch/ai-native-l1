# CP-0566E — QZXB Protocol Burn-Reserve Retirement and Mining Dust Decision

**Date:** 2026-11-08
**Authority:** Owner-authorized implementation decision under the explicit project-owner direction in this conversation.
**Status:** Versioned design decision for QFP6 candidate implementation. It does not activate Mainnet, issue public QZXB, authorize a sale, or approve a production monetary profile.

## 1. Burn-reserve rule

The 1,000,000,000 QZXB ProtocolBurnReserve remains an unissued ceiling at Genesis. It is not a wallet, treasury balance, founder balance, or freely transferable reserve.

A reserve retirement is authorized only by a signature from the Founder account already bound into the CP-0528/QFP6 Genesis state. The signed operation binds:
- Network ID and the exact CP-0528 policy fingerprint;
- the expected current cumulative burned-reserve counter (compare-and-swap replay guard);
- exact amount and expiry timestamp;
- nonzero purpose and evidence digests.

No recipient, beneficiary, external destination, or second signer exists because the operation is a one-way retirement, not a grant. Purpose/evidence digests bind supplied records but do not independently prove off-chain claims. The operation is bounded by the remaining ProtocolBurnReserve ceiling. It cannot touch the Founder, Mining, Community, Market, Marketing, Developer, or Strategic buckets, and cannot debit any user's existing balance.

## 2. Canonical atomic transition

The new QFB6 ProtocolBurnReserveRetirement operation:
1. verifies the Founder signature, Network ID, policy fingerprint, expiry, expected burned counter and remaining reserve ceiling;
2. increases gross issuance only in the ProtocolBurnReserve bucket;
3. derives a deterministic sink account from Network ID and policy fingerprint;
4. credits the exact amount to that sink and debits the same amount from Ledger within the same staged transition;
5. increments cumulative burned atoms by the exact same amount;
6. commits only if Ledger supply, tokenomics live supply, account mirrors, state root and all invariants agree.

The sink must be empty before the operation and empty after it. A global QFP6 invariant also rejects any state in which this sink account exists, including credits through ordinary transfers, category release, fee settlement or mining rewards; the block producer cannot be the sink. A failed operation leaves both Ledger and tokenomics unchanged. The expected prior burned counter prevents reusing the same signed authorization after a successful retirement. The cumulative burned value and per-bucket issuance are already committed in Q6TM snapshots/state roots; no extra local-only counter or key store is introduced.

**Economic interpretation:** this specific operation retires *unissued issuance capacity*. Gross issued and burned counters increase equally, so live supply and existing user balances do not change. It is not represented as a reduction of circulating supply or a market buyback. A future voluntary burn of already-circulating coins would be a separate holder-signed operation and is outside this decision.

## 3. Mining schedule remainder

Retain the existing CP-0422 research schedule values unchanged for candidate qualification. The 0.860736 QZXB remainder is permanently unissued; 3,000,000,000 QZXB remains a maximum mining/security ceiling, not a promise that exactly 3B will be emitted. Do not change subsidy, halving interval, historical vectors or existing snapshots to consume the remainder.

This decision resolves the owner choice in CP-0566D section 4 with the lower-risk alternative: preserve deterministic arithmetic and never exceed the cap.

## 4. Wire and compatibility

The new QFB6 operation receives tag 7 and bumps QFB6 wire encoding to version 5. The enclosing QFP6 PoW envelope bumps to wire version 4 and uses a new domain-separated commitment version. QFP5/QFB5 bytes remain unchanged. QFP6/QFB6 are still candidates; no production network has been activated, so the new candidate wire version must be reviewed and qualified before any future Genesis/profile freeze. Do not silently reinterpret old QFB6 v4 or QFP6 v3 bytes as the new format.

## 5. Required tests

- real Ed25519 Founder signature success and wrong-signature rejection;
- round-trip canonical Q6BR and QFB6 tag-7 codecs;
- wrong Network ID, wrong policy fingerprint, expiry, zero amount, over-ceiling amount, stale expected-burn counter and replay rejection;
- atomic Ledger credit/debit, sink-empty postcondition, unchanged user balances and unchanged live supply;
- gross/burned counters and reserve-ceiling decrement committed into state roots and snapshots;
- preview/apply equality, failed-operation state-root invariance;
- QFP6 PoW commitment binds the QFB6 v5 bytes;
- fork-choice, durable-store reopen/replay, reorg and checkpoint restoration preserve the same counters.

## 6. Launch boundary

Passing these candidate tests does not close Gate 2 or Gate 8 and does not approve Mainnet. Independent operators, production Network/Profile/Genesis freeze, production consensus/PoW calibration, external anti-rollback trust, full-history recovery and independent security review remain separate gates. No user keys, balances, real assets, bridges, liquidity pools, or deployments are touched by this implementation.
