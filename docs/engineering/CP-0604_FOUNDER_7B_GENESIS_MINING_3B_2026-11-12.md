# CP-0604 — Founder-controlled 7B Genesis / 3B mining supply candidate

Status: wired into the QFB6 canonical execution candidate and Q6SN v6 snapshot path; not activated by the production QFP6 node/runtime, not a signed Mainnet Genesis, and not Mainnet-ready.

## Monetary model

- Gross issuance ceiling: 10,000,000,000 QZXB.
- Genesis founder balance: 7,000,000,000 QZXB, credited once to the founder account.
- Mining/security issuance ceiling: 3,000,000,000 QZXB, released only by the selected consensus mining schedule.
- The six 1B planning labels (Community, Exchange/Liquidity, Marketing, Developers/Security, Strategic Supporters, Conditional Burn Reserve) are off-chain bookkeeping labels over the founder's 7B balance. They are not consensus buckets, independent wallets, recipient approvals, or mint permissions.
- Founder spending uses ordinary native transfers. A transfer changes account balances, not gross issuance.
- No automatic burn, reserve retirement, category-release mint, or re-opening of issuance capacity is implemented in this policy.

## Compatibility and safety

CP-0604 does not alter CP-0528 constants or its historical Q6TM encoding. The canonical execution state now supports a mutually exclusive CP-0604 policy path, including Genesis constructors with and without a profile-bound Genesis descriptor. The descriptor binding commits the CP-0604 policy fingerprint. The canonical Ledger Genesis credits exactly 7B to the founder; the 3B mining cap is not pre-minted.

Canonical block application derives mining rewards from the selected schedule and advances the CP-0604 height/cumulative counter in the same cloned state transition as the Ledger credit. A failed block transition is discarded atomically. Legacy CP-0528 category-release and burn-reserve mint operations fail closed under CP-0604. Native transfers remain ordinary Ledger transfers and do not alter gross issuance.

The aggregate execution snapshot is now Q6SN v6 and includes a bounded, checksummed Q604 policy component. The reader retains Q6SN v4/v5 compatibility; the historical state-root calculation is unchanged when CP-0604 is absent. Tests cover 7B Genesis credit, a native transfer, block-derived mining reward, snapshot restore and continuation, legacy mint-operation rejection, and legacy snapshot decoding.

This is still a canonical execution **candidate**, not production runtime activation. Remaining gates include wiring the CP-0604 Genesis descriptor/profile into the actual QFP6 node bootstrap and consensus configuration, confirming the production hybrid authenticator at the node callsite, and exercising independent-node sync, fork-choice/reorg, persistent restart, and public Devnet recovery. No signed Mainnet Genesis was modified or published.
