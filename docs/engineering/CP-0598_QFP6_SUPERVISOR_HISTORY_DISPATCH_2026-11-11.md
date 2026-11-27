# CP-0598 - QFP6 history dispatch on the permissionless node supervisor

Date: 2026-11-11
Status: local supervisor integration candidate; exact-head CI pending.

## What is connected

- Add a combined Q6PB/Q6TI/Q6HS authenticated Noise listener. All request families share one pinned session, one monotonic per-session replay guard, the same connection/request ceilings and the same listener socket.
- Preserve Q6PA/Q6TA as exactly one fixed-width 128-byte response record.
- Serve Q6HS/Q6HC canonical-history pages as an ordered multi-record response sequence. The full sequence is validated before the first response record is written.
- Preserve the 64 MiB per-session history egress ceiling and private/loopback/LAN/overlay bind restriction.
- The permissionless mining supervisor now owns a bounded QFP6 history responder for its lifetime and dispatches Q6HS requests on the same socket used for Q6PB block admission and Q6TI transaction ingress.
- The responder retains one immutable canonical snapshot across listener rounds, so multiple Q6HS page requests can reference the same tip while mining continues.
- Existing Q6PB/Q6TI admission logic and mempool/mining sequencing remain on the same supervisor path.

## Local validation

- cargo fmt --manifest-path src/native/pow_bench/Cargo.toml -- --check: passed.
- git diff --check: passed.
- Two combined-listener tests passed: pinned Noise Q6HS request/page transfer and a 100,000-byte page carried as three separate Noise records.
- cargo check --manifest-path src/native/pow_bench/Cargo.toml --all-targets --locked --offline: passed.
- Exact-head GitHub Actions validation is pending.

## Remaining gaps

- The node supervisor serves history but does not yet dial peers or automatically import remote history.
- No authenticated Q6 status/hello exchange provides a remote snapshot tip to a new sync client.
- No multi-peer discovery/address book, retry/backoff, persistent cursor, restart-resumable download scheduler, or independent-host sync qualification yet.
- The listener still rejects public bind addresses; public-facing abuse controls, public bind policy and threat review remain open.
- No finalized production Genesis, public Mainnet, public mining release, public RPC/Explorer, wallet release or real QZXB/USDT liquidity is established by this change.
