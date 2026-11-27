# CP-0661 — Q6QA-aware Q6PB admission over the authenticated Noise listener

Date: 2026-11-14  
Branch: `feat/cp0600-bootstrap-sync-startup`  
State: local deterministic listener qualification PASS; source changes remain uncommitted/unpushed.

## Test added

Added `qfp6_noise_q6pb_listener_rejects_unqualified_quote_then_accepts_height_bound_q6qa` in `qrun_v06_peer_listener_candidate.rs`.

The test constructs a CP-0651 fee-only Genesis and a committed candidate Q6PN profile pin, creates two test assets and a signed OrderBook pair whose quote is external to native QZXB, mines a valid QFP6 PoW envelope, then sends that exact Q6PB envelope through a real loopback TCP socket and authenticated Noise XX session.

Within one session it submits the same envelope twice with strictly increasing request IDs:
1. The compatibility Q6PB handler, with no Q6QA provider, returns `Rejected`.
2. The quote-aware Q6PB listener handler supplies a synthetic test authorization bound to the exact quote asset and height 1; it returns `Accepted` and commits the block.

Assertions verify one authenticated Noise session, two requests, two responses, resulting local height 1, and exactly one quote-authorization callback (the first rejected request does not invoke it).

## Validation

- New local Noise/Q6PB/Q6QA socket test: 1/1 PASS.
- Full `qrun_v06_peer_listener_candidate` test module: 18/18 PASS.
- `cargo fmt -- --check`: PASS.
- `cargo check --bins --locked --offline`: PASS.
- `git diff --check`: PASS.

## Explicit limits

This is a deterministic loopback listener test, not an independent-host or public-Internet qualification. The test uses a Q6PN v1 candidate pin and a synthetic `QRunV06TrustAuthorizedQuoteAsset` fixture injected through the provider callback. It validates the Q6PB/Noise/listener/store seam and the fail-closed behavior, but it does not prove the real launcher’s Q6PN v2 + dual-signed Q6TS + separately provisioned read-only trust-floor + signed Q6QA path on a production listener.

The independent-host qualification remains outstanding. It requires the final, independently committed Q6PN v2, signed Q6QA bundle, current dual-signed Q6TS envelope, pinned authority public keys/keyset, independently administered read-only monotonic trust floor, and a separately administered remote node with protected Noise key custody. Current public inbound networking and Ubuntu protected-key provisioning are separate open gates.

No production trust material, private key, mnemonic, Genesis owner signature, token transfer, public deployment or live trade was created or used.
