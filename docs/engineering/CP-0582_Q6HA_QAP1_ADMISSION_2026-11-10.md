# CP-0582 — Q6HA transaction admission through QFP6/QAP1

**Date:** 2026-11-10  
**Parent:** CP-0581 / QZKW2 hybrid wallet candidate  
**Status:** Integration test candidate; not production node activation

## Scope

The existing QFP6 transaction-authenticator injection point is exercised with the CP-0580 QRunV06HybridTransactionAuthenticator<LibcruxMlDsa65VerifierCandidate> in the actual Q6PB peer-block → canonical QFP6 validation → QAP1 Provider/Q6EA Anchor finalization → Q6PA response path.

The new integration regression constructs a disposable QFP6 Genesis whose founder account is the Q6HA-derived hybrid identity, signs a native transfer with both Ed25519 and ML-DSA-65, constructs a PoW/QFB6 envelope and submits it through process_qrun_v06_peer_block_frame_with_qap1.

The test requires:
- the hybrid signature and QFP6 transaction encoding to verify;
- Q6PB admission to return Accepted only after the signed Provider and Q6EA transitions/finalization complete;
- canonical ledger balance/nonce, manifest generation and external anchor state to agree;
- replay to return Rejected without a second generation or balance change.

## Limits

- The test uses in-memory test Provider/Anchor models and deterministic test-only keys. It is not a public or independently administered service.
- The runtime and supervisor are candidate library components. qrun_v06_node remains preflight/probe-only; there is no production node start mode or live Q6PA network ingress.
- The verifier adapter remains candidate-only pending independent cryptographic review.
- QZKW2 still refuses network submission; a production wallet-to-node Q6PA submit protocol and canonical node composition remain separate gates.
- No Mainnet, real issuance, balance, mining payout, public peer service or QZXB/USDT market is activated.
