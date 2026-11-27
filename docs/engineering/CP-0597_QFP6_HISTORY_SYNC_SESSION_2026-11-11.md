# CP-0597 - QFP6 history synchronization over authenticated Noise sessions

Date: 2026-11-11
Status: bounded session integration candidate; not public Mainnet activation.

## What is connected

- A dedicated Q6HS history listener accepts only requests matching its configured network and profile over the existing pinned Noise XX session.
- It applies per-session request-ID replay rejection and the existing listener connection, handshake and request budgets.
- It writes each Q6HC response as an individual Noise application record, enforcing the 48 KiB chunk framing, request ID, snapshot tip, complete ordered sequence, maximum chunk count and transport record bound before the first response byte is sent.
- Per-session history egress is capped at 64 MiB; the listener remains serial and bounded.
- The listener is separate from the existing fixed-width Q6PA/Q6TA listener, so transaction/block ACK behavior remains unchanged.
- A permissionless-runtime adapter wires the Q6HS listener to the durable QFP6 fork store.
- The responder retains at most one immutable fork-choice snapshot. Further page requests must name that exact tip; a new snapshot is captured only when the request names the live canonical tip. Requests for an unavailable/old snapshot fail closed.
- A client helper sends Q6HS and assembles Q6HC records through the CP-0596 checksum, height, network/profile, parent-link and pinned-tip validation.
- A request builder binds the next page to the destination's current durable consensus tip and execution-state tip. The source snapshot tip must be supplied from an independently authenticated observation; this module does not invent remote status.
- A page-import helper prechecks page range/completion and final snapshot digest, then routes blocks through CP-0594 durable history import. PoW, consensus, execution, state roots and persistence remain authoritative in the durable store.

## Local validation

- cargo fmt --manifest-path src/native/pow_bench/Cargo.toml -- --check: passed.
- git diff --check: passed.
- Full library suite: 1,349 passed, 0 failed; the two new final transport-sequence tests were then run separately.
- Focused tests: pinned Noise history transfer, multi-chunk Noise response and Q6HC truncation/mixed-metadata rejection all passed.
- cargo check --manifest-path src/native/pow_bench/Cargo.toml --all-targets --locked --offline: passed after the final page-import preflight changes.
- Exact-head GitHub Actions validation is required before this candidate is CI-qualified.

## Explicit remaining gaps

- The history responder is not yet attached to the standalone QFP6 node supervisor/production launcher.
- Snapshot retention is process-memory-only and limited to one snapshot; it is not durable across restart.
- No authenticated Q6 status/hello exchange advertises the source's current canonical tip; the destination needs a trusted source-tip observation to build Q6HS.
- No outbound peer dialer, peer discovery, address book, retry/backoff, resumable multi-page scheduler, or independent-host qualification is included.
- This is not yet a public listener: the existing listener safety policy still restricts bind addresses to loopback/private/LAN/overlay. Public bind policy, abuse controls and threat review remain open.
- No finalized production Genesis, independently reviewed economics, public mining release, public RPC/Explorer, wallet release, or QZXB/USDT market liquidity is established by this change.
