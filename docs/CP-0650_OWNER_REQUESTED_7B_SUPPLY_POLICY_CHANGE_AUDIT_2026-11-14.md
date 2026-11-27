# CP-0650 — Owner-Requested 7B Supply Policy Change: Source Audit

Date: 2026-11-14  
Project: AI-NATIVE L1 / QRUN-QFP6  
Status: owner direction recorded; consensus implementation intentionally held pending the mining/reward interpretation

## New owner direction received

The project owner has requested a **7,000,000,000 QZXB maximum supply**, with:

- **1,000,000,000 QZXB** for the owner account;
- **six additional accounting labels** for the remaining **6,000,000,000 QZXB**.

The new request changes the prior CP-0566D 10B supply target. It is not a request to increase the supply or to issue the six labelled amounts immediately. The six labels are accounting ceilings/reserves unless a separately authorized canonical release is defined.

## Exact current-source findings

### 1. CP-0566D remains the prior owner-authorized 10B policy

`docs/CP-0566D_QZXB_EIGHT_BUCKET_TOKENOMICS_DIRECTION_2026-11-06.md` sets:

- 1B owner Genesis allocation;
- up to 3B PoW mining/security issuance;
- six additional 1B conditional category ceilings:
  1. Community airdrop;
  2. Exchange/market/liquidity partnerships;
  3. Marketing partners;
  4. Developers/security contributors;
  5. Financial/strategic supporters;
  6. Protocol burn reserve.

Those eight buckets sum to 10B. CP-0566E preserves the 3B mining ceiling and documents the mining-schedule remainder. Both are prior policy records and must remain unchanged as history.

### 2. CP-0528 QFP6 tokenomics candidate implements that same 10B arithmetic

`src/native/pow_bench/src/qrun_v06_tokenomics_candidate.rs` currently declares:

- `QRUN_V06_MAX_GROSS_ISSUANCE_ATOMS = 10B`;
- `QRUN_V06_FOUNDER_GENESIS_ATOMS = 1B`;
- `QRUN_V06_MINING_SECURITY_BUDGET_ATOMS = 3B`;
- eight buckets: one 3B mining bucket, six 1B category reserves, and one 1B Founder bucket.

Genesis initializes only the 1B Founder bucket. The six other 1B category reserves are not automatically credited at Genesis; recipient-facing release uses signed Founder authorization, recipient acceptance, nonce/replay protection, expiry, purpose/evidence/milestone digests. Burn reserve follows its separate CP-0566E one-way retirement rule.

This source is a candidate consensus/state module; its current arithmetic is 10B, not the newly requested 7B.

### 3. The current permissionless launcher enforces a different, older CP-0604 model

`src/native/pow_bench/src/qrun_v06_cp0604_supply_candidate.rs` declares:

- `CP0604_MAX_GROSS_ATOMS = 10B`;
- `CP0604_FOUNDER_GENESIS_ATOMS = 7B`;
- `CP0604_MINING_CAP_ATOMS = 3B`.

More importantly, `src/native/pow_bench/src/bin/qrun_v06_node_runtime_launch/permissionless.rs` calls `validate_permissionless_cp0604_genesis` before opening the store/listener. Its source comments and checks explicitly require a 7B Founder Genesis plus 3B mining policy and reject the CP-0528 1B-Founder tokenomics path.

Therefore the current permissionless launcher is not aligned with CP-0566D's prior 1B-Founder/3B-mining/six-reserve model, and neither model matches the new requested 7B-total / 1B-owner / six-label direction.

### 4. Other legacy accounting code is also 10B and not runtime-integrated

`monetary_allocation_v04_candidate.rs` still has a 10B cap, a 3B mining/security ceiling, six 1B category ceilings and a 1B owner ceiling. Its module header explicitly says it is not connected to canonical QFP6 Genesis/runtime state transitions. It must not be presented as production accounting.

## Arithmetic consequence requiring an explicit mining decision

If the six labels are the six existing CP-0566D category reserves and each remains capped at 1B, then:

`1B owner + 6 × 1B accounting reserves = 7B total`.

There is no separate 3B mining issuance room under that 7B hard cap. The new policy must therefore choose one of these mutually exclusive interpretations before protocol implementation:

1. **Fee-only mining:** set additional block subsidy/mining issuance to zero; miner revenue is limited to canonical transaction fees. Keep the six existing 1B accounting labels unchanged. This preserves the requested 7B total, but the network's security economics and bootstrapping incentives must be independently assessed.
2. **Mining inside the six labels:** reserve part of the 6B labelled total for network security/mining rewards. This requires changing the six bucket names/ceilings and identifying which prior category or categories are reduced or removed. The six labels would no longer be the six existing CP-0566D 1B reserves.

The request does not yet specify which interpretation is intended. Do not silently keep a 3B subsidy, because it would make the total 10B; do not silently remove the reward schedule or repurpose one of the six categories without recording the policy choice.

## Safe implementation boundary

Before any monetary source edit:

1. Issue a new versioned tokenomics policy and exact fingerprint; do not rewrite CP-0566D/0566E or old snapshots.
2. Define the seven accounting ceilings and whether mining issuance is zero or funded within one or more of the six labels.
3. Reconcile Genesis, founder balance, gross issuance, bucket counters, burn semantics, reward calculation, fee treatment, state roots, QFB6 snapshots, QFP6 envelopes, fork-choice replay, reorg, checkpoint and restart.
4. Remove the current CP-0604 7B-Founder permissionless gate from the new launch path and bind startup to the new policy fingerprint; reject both the old 7B-Founder profile and any unapproved 10B CP-0528 profile for the new production network.
5. Add deterministic vectors for cap boundaries, no hidden issuance, all six label ceilings, fee/subsidy accounting, state roots, fork/reorg/replay and restart.
6. Keep all old policy formats readable only where explicit legacy replay compatibility requires them. Never reinterpret their bytes as the new 7B policy.

## Current decision state

- New 7B / 1B owner / six-label direction: **received and recorded**.
- Exact six labels if unchanged from CP-0566D: **identified**.
- Mining reward treatment under the 7B total: **not yet specified**.
- Monetary consensus implementation: **not changed in this checkpoint**.
- Public launch authorization: **not granted by this record**.

No coin has been issued or transferred by recording this direction. No Genesis profile, owner address, wallet seed, or public balance is created by this document.
