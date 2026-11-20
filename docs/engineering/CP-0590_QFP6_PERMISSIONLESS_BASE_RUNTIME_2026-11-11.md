# CP-0590 — Permissionless QFP6 base-runtime seam

## Implemented in this candidate

- Adds `QRunV06PermissionlessNodeRuntime`, separate from the existing Q6EA/QAP1-gated runtime.
- Startup requires a caller-supplied `QRunV06VerifiedProfilePin`, immutable Genesis execution state, consensus parameters, and an optional independently pinned local manifest anchor.
- Opens the durable QFP6 store through `open_with_verified_profile_pin`, which checks profile/Genesis/tokenomics/consensus identity before durable-store use and replays the retained archive.
- Provides native-envelope admission via the durable fork store and a status snapshot (network/profile IDs, canonical height/tip/state root, manifest generation/anchor, consensus fingerprint).
- Has no mandatory Q6EA, Provider, Q6TS, or QAP1 dependency. An unresolved QAP1 intent is rejected and must be recovered by the anchored recovery path.

## Explicit limitations

This is an admission/runtime seam, not yet a standalone permissionless node process. It does not provide P2P peer discovery, full-history network synchronization, public listeners, a mempool, miner lifecycle, RPC, explorer, or public Mainnet activation. Native-only admission is intentional: quote-asset operations still require their separate authorization provider. A verified profile pin and trusted manifest anchor must come from an independent provisioning channel; this code does not invent them.

## Qualification

- Local `cargo check --all-targets --locked --offline` passed on the CP-0590 working tree.
- Focused runtime unit tests and the full exact-head CI run remain required.
- This candidate does not close the Mainnet Genesis/profile, difficulty calibration, public multi-host, or market-liquidity gates.
