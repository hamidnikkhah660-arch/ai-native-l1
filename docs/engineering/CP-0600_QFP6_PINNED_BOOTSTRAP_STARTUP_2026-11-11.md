# CP-0600 - pinned-peer bootstrap before permissionless mining

Date: 2026-11-11
Status: startup orchestration API candidate; exact-head CI pending.

## What is connected

- Add a typed operator-supplied bootstrap peer list containing numeric socket addresses and pinned Noise static public keys.
- Validate the peer list is non-empty, bounded to 64 peers, and contains no zero keys, duplicate addresses, duplicate keys, unspecified IPs or multicast IPs.
- Add a permissionless launch wrapper that checks the already-opened runtime's network/profile, then tries the pinned peers in order using the CP-0599 bounded Q6HI/Q6HR + Q6HS/Q6HC sync client.
- The wrapper refuses to start the mining supervisor unless one peer reaches the advertised canonical height, consensus tip and execution tip through CP-0594 durable history import.
- The same validated static-key set is passed to the inbound permissionless Noise supervisor after bootstrap; mempool restoration and mining happen only after the sync step returns complete.
- Failed peers are recorded and the next operator-pinned peer is tried. Partial durable imports remain on disk and the next peer resumes from the current local durable tip.

## Local validation

- Pinned-peer validation tests cover empty list, duplicate address/key and zero key rejection.
- cargo fmt --manifest-path src/native/pow_bench/Cargo.toml -- --check: run before commit.
- cargo check --manifest-path src/native/pow_bench/Cargo.toml --all-targets --locked --offline: run before commit.
- Exact-head GitHub Actions is pending.

## Explicit remaining gaps

- The runtime must already be opened from a locally verified Genesis and profile pin; this wrapper does not finalize Genesis or provision keys.
- The API is not yet invoked by a standalone production CLI/Windows service; the existing qrun_v06_node binary remains a read-only preflight executable.
- Bootstrap peers are static operator inputs; no public peer discovery, address book, trust bootstrap, peer rotation service or automatic endpoint enrollment.
- A source reorg below an imported prefix fails closed; canonical rollback/reorg synchronization is not implemented.
- The current listener still restricts binds to loopback/private/LAN/overlay; no public bind or public abuse-control review.
- No independent-host deployment qualification, finalized production economics/Genesis, public Mainnet, public mining, RPC/Explorer, wallet release or real QZXB/USDT liquidity.
