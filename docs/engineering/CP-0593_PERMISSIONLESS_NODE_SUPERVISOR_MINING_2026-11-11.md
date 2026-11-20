# CP-0593 ? Permissionless peer ingress and mining supervisor

## Scope
- Dispatch Q6TI and Q6PB frames from authenticated QFP6 Noise sessions into the permissionless Genesis-rooted runtime.
- Q6TI receives Q6TA only after validation and durable Q6MJ journal installation; Q6PB receives Q6PA only after local durable block admission.
- Reconcile the pending pool after peer-driven canonical changes/reorgs.
- Add a bounded supervisor alternating finite peer windows with one finite SHA-256d QFP6 mining job. Empty blocks are permitted so height-derived consensus issuance does not depend on a user transaction arriving.
- Restore and revalidate the pending journal against the runtime's durable canonical state before opening the listener.

## Safety boundaries
- The runtime and profile pin must already be independently provisioned and verified; no Genesis or trust pin is invented.
- Noise remote keys remain explicitly pinned; listener bind policy remains restricted to loopback/private LAN/overlay addresses. Public Internet binding, peer discovery, and full-history network synchronization are not part of this change.
- Candidate timestamp is derived by the node's local clock policy and remains separate from deterministic branch-local MTP consensus.
- Local durable block commit is not network-wide finality. No miner payout wallet, RPC/explorer, Mainnet identity, or exchange integration is created.

## Validation
- Pending exact-head local and GitHub Actions validation.
