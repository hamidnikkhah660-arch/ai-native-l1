# CP-0604 — Founder-controlled 7B Genesis / 3B mining supply candidate

Status: candidate-only; not wired to canonical QFP6 execution, Genesis descriptor, Ledger block application, or Mainnet.

## Monetary model

- Gross issuance ceiling: 10,000,000,000 QZXB.
- Genesis founder balance: 7,000,000,000 QZXB, credited once to the founder account.
- Mining/security issuance ceiling: 3,000,000,000 QZXB, released only by the selected consensus mining schedule.
- The six 1B planning labels (Community, Exchange/Liquidity, Marketing, Developers/Security, Strategic Supporters, Conditional Burn Reserve) are off-chain bookkeeping labels over the founder's 7B balance. They are not consensus buckets, independent wallets, recipient approvals, or mint permissions.
- Founder spending uses ordinary native transfers. A transfer changes account balances, not gross issuance.
- No automatic burn, reserve retirement, category-release mint, or re-opening of issuance capacity is implemented in this policy.

## Compatibility and safety

CP-0604 is a new versioned candidate and does not alter CP-0528 constants or its Q6TM/Q6SN historical snapshot encoding. Its Q604 snapshot binds the network, founder account, 10B/7B/3B limits, mining schedule, cumulative mining issuance, height, policy fingerprint, and checksum. The state root is domain-separated.

The module deliberately does not claim canonical runtime activation. Before any Mainnet use, a separate reviewed integration must add a CP-0604 Genesis descriptor/profile pin, credit exactly 7B to the founder in the canonical Ledger, atomically couple mining reward credits with this issuance counter, enforce hybrid founder authorization on native transfers, and add snapshot/replay/fork-choice compatibility tests. Until then this code is an isolated candidate only.
