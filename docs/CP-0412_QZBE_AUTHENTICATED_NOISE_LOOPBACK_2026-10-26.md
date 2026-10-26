# CP-0412 — QZBE authenticated Noise loopback regression

Date: 2026-10-26
Status: **test-only candidate composition evidence; not canonical-node integration**

## Change

The QZBE persistent-store regression `independent_qzbe_stores_exchange_loopback_blocks_and_replay_identically` no longer moves candidate envelopes with an ad-hoc, length-prefixed plaintext TCP helper. It now transfers the exact encoded envelope through `DevnetNoiseSession`, using the bounded `Noise_XX_25519_ChaChaPoly_SHA256` transport, a Network ID bound into the Noise prologue, and explicit pinning of both peers' test-generated static public keys.

The existing regression still exercises three transfers between independently opened QZBE candidate stores: a valid QZB4 v2 block, a candidate carrying an invalid transaction signature, and a valid successor. The receiver verifies/imports each received envelope through ordinary QZBE submission, rejects the invalid candidate without changing canonical tip/height/state root/manifest generation, then converges with the sender. Both stores are reopened independently and replay to the same canonical tip and state root.

## Validation evidence

- `cargo +stable fmt --all -- --check`: passed on the CP-0412 working tree.
- `cargo +stable check --all-targets --locked --offline`: passed; existing unused/dead-code warnings remain in unrelated candidate modules.
- Focused test `monetary_pow_v04_store_candidate::tests::independent_qzbe_stores_exchange_loopback_blocks_and_replay_identically`: **1 passed, 0 failed**.
- The initial full `cargo +stable test --all-targets --locked --offline` run exposed a load-sensitive fixture in the archive total-deadline regression. The original server sent one partial chunk and slept, so the tight wall-clock assertion could fail under parallel scheduling without testing a sustained slow trickle. The fixture was changed to send small response fragments every 15 ms (inside the 35 ms timeout), distinguishing one absolute request deadline from a per-read timeout reset. The revised test passed both in isolation (1/1) and in the complete all-target run.

## Safety and limitations

This is a localhost test harness, not a node listener or a public/private Devnet deployment. Test keys are freshly generated for the test and pinned directly by the opposite endpoint; this does not exercise operator provisioning, persistent identity, key rotation/revocation, bootstrap trust, public peer discovery, production ingress/worker budgets, or long-lived session management. Noise here uses classical X25519/ChaChaPoly and makes no post-quantum or hybrid-security claim. QZBE still has no canonical producer/importer/runtime call site, and the production external-CAS provider remains absent. Gate 2, Gate 8, and Gate 12 remain open. No network, issuance, trading, or public launch is authorized by this checkpoint.

## Next gates

1. Publish this checkpoint on a separate reviewable Draft PR and run exact-head GitHub CI.
2. Keep this test-only scope separate from canonical node integration. The next runtime change must be independently reviewable and zero-value, and must dispatch QZBE symmetrically across production, import, fork choice, persistence/replay, authenticated peer lifecycle, and transaction admission.
3. Independently operated anti-rollback CAS and external security review remain mandatory before any value-bearing launch.
