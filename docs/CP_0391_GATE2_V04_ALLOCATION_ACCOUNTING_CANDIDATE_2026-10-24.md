# CP-0391 — Gate 2 v0.4 Allocation-Accounting Candidate

**Date:** 2026-10-24
**Status:** Candidate code and test evidence only. Gate 2 remains **OPEN**; Gate 8 remains **OPEN**. This change does not authorize Genesis activation, public mining, a value-bearing launch, or market activity.

## Scope of this increment

Adds `monetary_allocation_v04_candidate.rs`, exported from the Rust research crate. It records the owner-directed v0.4 eight-bucket ceilings in atomic units, provides a stable policy fingerprint, encodes cumulative per-bucket gross issuance plus cumulative burns, and enforces local arithmetic invariants. Mutations are transactional: rejected issuance/burn attempts leave the original accounting state unchanged.

The eight ceilings are:

| Bucket | Coins | Share |
|---|---:|---:|
| Mining / network security | 3,000,000,000 | 30% |
| Community airdrop | 1,000,000,000 | 10% |
| Exchange, market integration and liquidity partnerships | 1,000,000,000 | 10% |
| Major marketing partners | 1,000,000,000 | 10% |
| Developers and security contributors | 1,000,000,000 | 10% |
| Financial and strategic supporters | 1,000,000,000 | 10% |
| Protocol burn reserve | 1,000,000,000 | 10% |
| Owner allocation | 1,000,000,000 | 10% |
| **Total** | **10,000,000,000** | **100%** |

A budget ceiling is not proof of issued supply, a credited balance, a completed airdrop, a paid partner, or a completed burn. The accounting model keeps gross issuance distinct from burns; live supply is derived as gross issued minus proven burned. This candidate only accepts burn counters against previously issued tokens recorded in the burn-reserve bucket. The integrated runtime must additionally prove the actual source-account balance, authorization and atomic state transition.

## Source findings that remain blockers

1. The existing `state_machine.rs` monetary candidate still encodes the superseded 4B founder / 3B miner / 3B public-goods scheme in its constants, policy fingerprint and `MonetaryLedgerState::genesis`. It must not be silently treated as the v0.4 profile.
2. The ordinary `ZeroValueDevnet` runtime is explicitly a candidate/devnet profile. Its MBK4/PFM4 peer and local flows are dispatched as opt-in smoke modes; those modes are not a production-selected canonical monetary runtime.
3. The new v0.4 accounting candidate is not yet wired to the block producer, validator/importer, Genesis, fork choice/reorg, durable store, PFM5 checkpoint/replay, snapshots, or the live node runtime. It does not by itself close any Gate 2 acceptance row.
4. The external-CAS module provides a provider-independent transport contract and a receipt-verifying client. The reviewed source does not establish a production independently administered provider, provider-side atomic CAS, isolated signing/key custody, or a live runtime callsite. Unit/provider-model tests cannot close Gate 8.

## Tests added in this increment

- Exact 10B / 100% sum for all eight buckets.
- Per-bucket issue ceilings and atomic rejection on over-issuance.
- Burn accounting requires prior issuance in the designated reserve and keeps gross issuance unchanged.
- Fixed-width serialization round-trip and rejection of malformed or over-cap state.
- State commitment changes when issuance or burn counters change.

## Required continuation

1. Ratify how each of the six non-miner/non-owner reserves is represented in Genesis and how it is released; do not infer that a planned allocation is already minted.
2. Bind the v0.4 policy fingerprint and all accounting counters into a single canonical manifest, Genesis hash and state root.
3. Replace or isolate legacy 4/3/3 monetary candidates with explicit version boundaries; exercise the same allocation rules through production-selected block production, import, reorg, persistence, snapshots and replay.
4. Add independent golden vectors and a call-site audit proving that no alternative mint/credit path bypasses the per-bucket budgets.
5. For Gate 8, implement the provider adapter using a real server-side atomic conditional write, provision receipt keys out-of-band, and test stale restore, cloned disks/VMs, races, retries, ambiguous replies and multi-host recovery against an operator-independent service.
6. Run the targeted test, formatting, all-target check and full offline regression; then require independent review before considering a gate closed.

**Disposition:** This increment is a bounded step toward Gate 2 supply accounting. Gate 2 and Gate 8 remain OPEN. Mainnet and real-money trading remain NO-GO until the full acceptance evidence exists.
