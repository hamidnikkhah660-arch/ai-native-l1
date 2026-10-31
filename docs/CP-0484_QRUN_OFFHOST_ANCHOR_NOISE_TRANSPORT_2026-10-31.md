# CP-0484 — QRun Off-Host Anchor Authenticated Noise/TCP Transport Candidate

Date: 2026-10-31

Status: **Candidate transport client and one-connection server handler implemented and locally tested. No production Anchor daemon, listener service, AWS account/table, KMS Anchor key, independently administered operator domain, or QRun node integration is deployed.**

## Scope

New module:
- \`src/native/pow_bench/src/external_cas_offhost_anchor_noise_transport_candidate.rs\`

The module supplies:
- \`NoiseTcpOffhostAnchorTransport\` for challenge-bound Read and provider-proof CAS requests;
- \`serve_offhost_anchor_noise_connection\` for one authenticated request per TCP connection;
- a Noise profile binding Anchor ID, Provider ID, Network ID, wallet-bound Genesis digest, Provider receipt key ID/public-key hash, and Anchor receipt key ID/public-key hash.

It composes the CP-0481 Provider-proof validator, CP-0482 signed receipt protocol, and injectable CP-0483 storage contract. It does not provision AWS or start a listener process.

## Authentication and wire boundary

- Noise XX authenticates the client static key against an explicit server allowlist; the client independently pins the server Noise static public key.
- The prologue is domain-separated and binds both independent ML-DSA receipt authorities plus the complete Provider/Network/Genesis identity. A Noise session from another identity domain cannot be reused.
- Noise transport keys and ML-DSA receipt keys are distinct trust anchors. Every returned QAR1 receipt must still be verified by the caller against the out-of-band Anchor ML-DSA-65 pin and the exact request challenge/precondition.
- There is no plaintext fallback and no public/anonymous Noise mode for Anchor access.
- Each connection accepts exactly one bounded application request: Read (96-byte request payload) or CAS (fixed 168-byte precondition plus canonical ECR1 and signed ECS1 bytes). Oversized, malformed, wrong-version, unauthenticated, or wrong-domain requests fail closed.
- Connect and record I/O timeouts are bounded. The handler delegates every authoritative read/write to the Anchor model and its injected storage adapter; it has no local QCF1 fallback.

## Focused local tests

Four end-to-end loopback tests cover:
1. authenticated Read returns the exact challenge-bound, ML-DSA-signed Anchor state;
2. authenticated CAS independently verifies the Provider ECS1 proof, atomically advances the model, and returns a verifiable Anchor receipt;
3. a client whose Noise static key is not in the service allowlist is rejected before any Anchor state change;
4. profile derivation changes with the pinned Anchor identity and rejects provider-domain mismatch.

These tests use local loopback sockets and deterministic in-memory ML-DSA fixtures. They do **not** prove public-network deployment, AWS connectivity, production KMS behavior, independent operator custody, service availability, or node startup integration.

## Validation on 2026-10-31

On the dependent bootstrap-provisioning branch:
- \`cargo test --lib --locked --offline\`: PASS, 1012 passed, 0 failed
- \`cargo check --all-targets --locked --offline\`: PASS (existing unused-import/dead-code warnings in unrelated modules remain)
- \`cargo fmt --all -- --check\`: PASS
- \`git diff --check\`: PASS

The four focused Anchor Noise tests are included in the 1012-test library run.

## Production gates still open

- Implement an Anchor-specific AWS KMS ML-DSA-65 signer that pins the distinct Anchor key, verifies key metadata/SPKI, and locally verifies every signature; then qualify it with a real, separately administered KMS key.
- Build a deployable Anchor daemon around the connection handler with bounded concurrent sessions, admission/backpressure, graceful shutdown, health/metrics, secret loading, structured audit, and operational key rotation/recovery.
- Provision a disposable, separately administered AWS staging account, DynamoDB table, KMS Anchor key, IAM/SCP and backup/restore guardrails; run live consistency, CAS-race, response-loss, partition, crash, restore and audit drills.
- Wire the remote Anchor into QRun startup and the QAP1/Provider ECS1/Anchor/QCF1/PFS2 commit/recovery order. Startup and block acceptance must fail closed when the required remote Anchor cannot be verified.
- Run independent multi-host and security review before any Mainnet release decision.

## Release boundary

This transport candidate does not close the off-host anti-rollback gate. Mainnet approval remains false; public mint and public listener settings remain unchanged. No Genesis, Network ID, token supply, wallet allocation, firewall, or market/trading configuration is changed. QZXB/USDT trading must not be described as live.
