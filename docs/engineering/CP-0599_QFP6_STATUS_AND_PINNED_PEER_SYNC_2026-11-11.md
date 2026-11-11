# CP-0599 - Q6HI/Q6HR status handshake and pinned-peer history sync client

Date: 2026-11-11
Status: bounded one-peer bootstrap/sync candidate; exact-head CI pending.

## Protocol and responder

- Add fixed-width Q6HI status requests and Q6HR status responses, binding request ID, network/profile, canonical height, consensus tip and execution tip.
- Q6HI/Q6HR is carried inside the authenticated pinned Noise session and shares the same monotonic per-session replay guard with Q6HS/Q6HC, Q6TI and Q6PB.
- The permissionless supervisor pins one immutable fork-choice snapshot before advertising Q6HR. Later Q6HS pages are served from that exact snapshot even while live mining advances.
- Q6HS requests and Q6HC responses continue to use bounded pages/chunks and CP-0594 durable validation.

## Outbound client

- Add a static-address/static-key pinned-peer client; it does not infer trust or discover peers.
- It authenticates Q6HR, requests the next page from the local durable consensus/execution parents, verifies the pinned source snapshot, and imports pages only through CP-0594.
- Each Noise session is bounded to one status request plus at most 15 page requests; the combined listener permits up to 256 MiB history egress per session.
- The higher-level sync loop reconnects and obtains a fresh Q6HR snapshot after each bounded batch, with a configurable maximum of 64 rounds. This permits bounded multi-session bootstrap without exceeding per-session limits.
- If a source reorg invalidates the already-imported local prefix, the append-only importer fails closed; this candidate does not implement canonical rollback/reorg synchronization.

## Local validation

- Q6HI/Q6HR fixed-width codec roundtrip and request-ID binding test passed.
- Combined Noise listener test exercises Q6HR status, Q6HS page response, and duplicate request rejection in one authenticated session.
- Multi-chunk Q6HC transport test covers a 100,000-byte page across three Noise records.
- cargo fmt --manifest-path src/native/pow_bench/Cargo.toml -- --check: passed.
- git diff --check: passed.
- cargo check --manifest-path src/native/pow_bench/Cargo.toml --all-targets --locked --offline: passed before the final Q6HI reserved-field canonicalization; rerun after that small wire edit is required.

## Remaining gaps

- Static peer address/key must be supplied by an operator; no peer discovery/address book or trust bootstrap exists.
- The sync client is not yet invoked automatically by the node supervisor at startup; it is an explicit API for a caller to run.
- No independent-host qualification, public bind policy, public abuse controls, or public listener approval.
- No finalized production Genesis/economics, public Mainnet activation, public mining release, RPC/Explorer, wallet release or real QZXB/USDT liquidity.
