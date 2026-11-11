# CP-0596 - QFP6 history-sync request and chunked response wire codec

Date: 2026-11-11
Status: codec candidate; not yet connected to the peer listener or sync daemon.

## Purpose

CP-0596 defines the bounded application protocol that will carry CP-0595 canonical history
pages over the already-authenticated QFP6 Noise session. It avoids assuming that a large
history page can fit in one Noise message.

## Wire contract

- Q6HS is a fixed-width 192-byte request binding request ID, network, profile, pinned
  canonical snapshot tip, expected local consensus parent, expected local execution parent,
  starting height, maximum block count and maximum envelope bytes.
- Q6HP is the canonical page payload. It binds the request ID, snapshot tip and height,
  start/next heights, completion flag, entry count and bounded envelope section.
- Q6HC splits the Q6HP payload into ordered 48 KiB chunks. Each chunk carries the request ID,
  sequence index/count, total page length, snapshot tip and SHA-256 commitment to the complete
  page payload.
- The assembler rejects out-of-order, inconsistent, oversized, wrong-request and tampered
  chunks before returning a page.
- Page decoding verifies network/profile identity, expected first parent, subsequent
  consensus-parent and execution-parent continuity, exact heights, snapshot completion and
  the pinned final tip. Durable CP-0594 import remains the final consensus/PoW/execution
  authority.

## Validation

- Fixed-width Q6HS roundtrip and malformed/reserved/limit rejection.
- Q6HC length and ordering rejection before payload acceptance.
- End-to-end codec test builds a 500-operation block plus its successor, forces a multi-chunk
  page, verifies parent-first continuity and exact snapshot tip, then detects payload tampering.
- Targeted Q6HS/Q6HC tests and all-target compilation pass locally.

## Explicit non-goals

This change does not wire Q6HS/Q6HC into serve_qfp6_noise_listener, implement the remote
history-page responder or downloader, manage per-session snapshot retention, discover public
peers, bootstrap trust pins, persist sync cursors, handle cross-host recovery, or activate
Mainnet. It also does not finalize Genesis, difficulty calibration, public mining, RPC,
Explorer, wallet release, or QZXB/USDT liquidity.
