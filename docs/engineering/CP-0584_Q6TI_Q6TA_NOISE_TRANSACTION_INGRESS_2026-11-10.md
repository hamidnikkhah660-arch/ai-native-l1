# CP-0584 — Q6TI/Q6TA transaction submission over authenticated QFP6 Noise

**Date:** 2026-11-10
**Parent:** CP-0583 / bounded Q6HA-aware QFP6 transaction mempool
**Status:** Committed and pushed as CP-0584; exact-head CI and independent review pending; candidate integration only, not a production node service

## Protocol and listener

- Adds Q6TI v1 NativeTransfer request frames with explicit version, message type, request ID and payload length, bounded at 16 KiB.
- Uses the QFP6 8 KiB NativeTransfer codec and transaction-ID path for the 5,365-byte Q6HA dual-signature envelope. Common/legacy TXN2 remains capped at 4 KiB.
- Adds a fixed 128-byte Q6TA response containing Accepted, Duplicate or Rejected, transaction ID, mempool count/bytes, and canonical height/tip/state root.
- Adds `process_q6ti_transaction_frame`: validates and replay-guards the request, then submits through the bounded canonical-execution-backed QFP6 mempool.
- Extends the bounded QFP6 Noise listener to dispatch Q6TI versus Q6PB frames and validate Q6TA versus Q6PA responses. The listener remains a library service candidate and receives its application handler as a callback.
- Noise is `Noise_XX_25519_ChaChaPoly_SHA256` with a QFP6 network/profile prologue and explicit pinned static keys. This is classical X25519 transport security, **not post-quantum transport security**.

## QZKW2 wallet submission

- Adds a separate Q6NK1 Noise identity file. Its X25519 private key is protected using Windows CurrentUser DPAPI; it is distinct from the QZKW2 Ed25519/ML-DSA-65 spending seeds.
- Adds wallet commands to create/show the Noise identity and QZKW2 submission options for a private/loopback/NetBird endpoint, network profile, local identity file and pinned remote static public key.
- QZKW2 signs with Q6HA and submits Q6TI over the pinned Noise session, then validates the matching Q6TA request ID and TXID. QZKW1 remains on its legacy route; QZKW2 refuses legacy QZTS/1 submission.
- Wallet reports `accepted_pending_mempool` and `not confirmed`; it does not report mempool admission as block confirmation or settlement.

## Local verification on Windows

The following completed successfully on `heymed`, using the locked offline dependency set:

- QZKW2 wallet and Q6NK/DPAPI/Noise identity tests: **11 passed**.
- Q6TI frame and real mempool ingress tests: **4 passed**.
- QFP6 pinned Noise listener tests: **7 passed**, including a signed Q6HA request routed through the listener into the actual in-process mempool; a second request with a fresh request ID returns Duplicate.
- Q6HA transaction → Q6TI mempool admission → deterministic mempool block template → PoW → Q6PB/QAP1 durable-store candidate test: **1 passed**. The QAP1 provider/anchor are test fixtures, not live independent services.
- `cargo fmt --check`: passed.
- `cargo check --all-targets --locked --offline`: passed.
- `git diff --check`: passed.

These are same-host local TCP/loopback and candidate runtime tests. They do **not** prove a two-machine NetBird run, external Provider/Q6EA availability, production node lifecycle, or public-network availability.

## Acceptance semantics

Q6TA Accepted means hybrid signature verification and canonical mempool preview succeeded; the transaction is pending in a process-local pool. It is **not** a mined/confirmed transaction, durable QAP1 finality, or external settlement. The QAP1 path produces a positive block ACK only after the candidate canonical block is admitted and the configured anchor fixture acknowledges it.

## Remaining production gates

- No QFP6 node executable currently composes the production Genesis/Q6PN/Q6TS trust material, independent Provider and Q6EA services, long-running Q6TI listener, persistent mempool policy, PoW miner and QAP1 coordinator. The current `qrun_v06_node` executable is still preflight/probe-only.
- No second independent NetBird host or production node endpoint has been qualified in this CP-0584 run. The localhost tests must not be represented as cross-host qualification.
- The Q6HA Libcrux ML-DSA-65 verifier remains a candidate pending independent cryptographic/security review. The Noise transport is classical X25519.
- Exact-head GitHub CI and independent cryptographic/security review are still pending.
- No public Devnet/Mainnet, genesis issuance, public QZXB balance, public transaction, miner payout or QZXB/USDT liquidity is active or verified.
