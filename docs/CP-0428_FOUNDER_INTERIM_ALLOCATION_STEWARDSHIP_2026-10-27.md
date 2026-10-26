# CP-0428 ? Founder interim stewardship of unassigned allocation envelopes (2026-10-27)

## Recorded direction and current state

The Founder requests interim authority over undistributed non-mining allocation envelopes until specific recipients are selected. This note records the intended policy direction; it is **not** evidence that such authority is currently encoded in a production Genesis or enforced by a live Mainnet.

The previously recorded CP-0422 maximum supply is 10,000,000,000 QZXB with the Founder allocation capped at 1,000,000,000 QZXB (10%). The other category amounts are allocation ceilings, not Founder property or issued balances. The persistent wallet on the Windows developer host is a local signing identity only; it has not received a Mainnet Founder balance because no production Mainnet Genesis has been activated.

## Interim authority model to freeze before production Genesis

1. **Founder balance stays capped at 1B QZXB.** No unassigned community, liquidity/market integration, marketing, developer/security, or strategic-support amount is silently credited to the Founder account. The Founder wallet cannot spend these reserves as if they were personal coins.
2. **Temporary release authority:** until a recipient, wallet, documented purpose, and amount are approved, undistributed non-mining envelopes remain unissued. A versioned, auditable allocation authorization identifies the category, recipient account, maximum amount, reason/evidence, and approving Founder key. Each release is atomic and cannot exceed that category ceiling or the global 10B cap.
3. **When a recipient is found:** publish the category/recipient/milestone policy first, record recipient-key verification and any vesting/lock rules, then execute a deterministic release transaction through the canonical consensus path. Unused amounts remain unissued; expiry of an award does not automatically transfer it into the Founder balance.
4. **Mining/security (3B):** not controlled by discretionary Founder allocation authority. It is issued only by the frozen consensus reward schedule to valid miners.
5. **Burn reserve (1B):** not available for personal or discretionary spending. It remains an allocation ceiling until a specific, deterministic burn/reserve mechanism is approved and verifiably executed. Only already-issued balances can be burned.
6. **No hidden mint or override:** all non-mining releases must be represented in canonical state/supply counters and state roots; any policy change requires a versioned rule and a new genesis/profile before activation, never a silent post-launch edit.

## Required implementation before launch

- Add allocation-steward authorization and category-restricted release events to the actual versioned monetary transition, producer/importer, fork choice/reorg, durable store, replay, and state-root path; test unauthorized, duplicate, over-cap, wrong-category, wrong-recipient, crash/restart, and competing-branch cases.
- Link the Founder public key to the production Genesis only through a reviewed key ceremony. The existing DPAPI wallet is host-bound and does not have a portable production recovery workflow; do not expose or copy its protected blob as a substitute for backup/recovery design.
- Publish the exact Genesis hash, all category caps, issued versus unissued counters, Founder account ID, release policy, and recovery/rotation process before value-bearing activation.

Until these steps are implemented and verified in the production consensus runtime, the temporary-stewardship direction is documented but not live protocol authority, and all category envelopes remain planning/state-candidate values rather than Mainnet spendable balances.
