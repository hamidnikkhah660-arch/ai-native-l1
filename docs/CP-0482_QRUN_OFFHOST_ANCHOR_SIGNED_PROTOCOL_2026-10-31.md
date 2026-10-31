# CP-0482 — QRun Off-Host Anchor Signed Read/CAS Protocol

Date: 2026-10-31

Status: **The challenge-bound receipt codec, separate Anchor-key pin, verification API and process-local concurrency model are implemented as candidate code. This is not a production storage adapter or deployed off-host service.**

## Scope

CP-0480 defined the service design. CP-0481 added independent verification of Provider-signed ECR1/ECS1 commit evidence. CP-0482 adds the next protocol layer:
- a separately pinned Anchor ML-DSA-65 receipt key, required to differ from the Provider receipt key;
- a fixed-width, canonical signed Anchor receipt carrying the complete high-water state;
- challenge-bound Read and CAS requests;
- explicit Observed, Applied, AlreadyApplied and Conflict outcomes;
- an in-memory, mutex-serialized state machine for adversarial protocol tests.

New module:
- src/native/pow_bench/src/external_cas_offhost_anchor_protocol_candidate.rs

The module has no network listener, AWS SDK, durable database, persistent challenge/idempotency journal, cloud key provisioning, node startup integration or consensus callsite.

## Canonical receipt and state format

The Anchor receipt uses:
- magic QAR1, version 1;
- kind and outcome, with reserved bytes required to be zero;
- client challenge, Anchor ID, Provider ID, Network ID, Genesis digest and Anchor receipt-key ID;
- operation ID and request digest;
- expected Anchor sequence, expected predecessor-state digest and requested target-state digest;
- digest of the returned state and the full canonical state bytes;
- a distinct ML-DSA-65 signature over a domain-separated SHA-256 digest of the complete payload.

The receipt payload is 796 bytes and the complete receipt is 4,105 bytes including the 3,309-byte ML-DSA-65 signature. The embedded state is 424 bytes and contains:
- Anchor sequence and Provider object generation;
- canonical ECR1 record;
- last operation ID, Provider request digest and first accepted signed ECS1 receipt digest;
- exact predecessor Anchor sequence and predecessor Anchor state digest used for the last successful CAS.

Every one of these fields is covered by the Anchor state digest. The first accepted Provider receipt digest is retained and never overwritten by an idempotent retry.

The Anchor key pin binds Anchor ID and Provider/Network/Genesis domain and explicitly rejects reuse of the Provider receipt key ID or public key. The node/operator must provision both key pins independently out of band.

## Read protocol

The client supplies a fresh, unpredictable, nonzero challenge plus nonzero operation/request identifiers. The Anchor returns a signed Observed receipt covering the challenge and complete current high-water state.

The client:
1. verifies the out-of-band Anchor pin and distinct key identity;
2. verifies the Anchor ML-DSA-65 signature;
3. checks the exact challenge, operation and request identifiers;
4. decodes and validates the full ECR1/domain/state metadata;
5. recomputes the complete state digest.

A response from an older challenge is rejected. Fresh challenge generation belongs to the caller and must use a cryptographically secure random source. The current candidate accepts a caller-provided challenge; it does not yet implement an OS CSPRNG or an authenticated network session.

## CAS protocol

The request binds:
- fresh challenge;
- exact Provider operation ID and Provider request digest;
- expected Anchor sequence and expected predecessor-state digest;
- exact target-state digest.

The Anchor service must independently verify the Provider ECR1/ECS1 proof using CP-0481 before changing the state. Its backing store must then atomically compare the expected sequence and full state digest and install the exact one-step successor.

The signed response echoes every CAS precondition and the target digest:
- Applied: the target was atomically installed;
- AlreadyApplied: the exact same operation, payload and original predecessor already produced the current target;
- Conflict: the expected predecessor did not match; the receipt authenticates the current state but is not success.

The client API returns the explicit outcome together with the returned state. It never flattens Conflict into a successful state read. Successful outcomes must have sequence exactly expected_sequence + 1, target digest match, operation/request identifiers match, and stored predecessor sequence/digest match the request.

For a retry, the Anchor checks the last operation, request digest, target, and original predecessor sequence/digest before it returns AlreadyApplied. Reuse of an operation ID under a different target or predecessor does not become a second advance.

## Process-local state-machine model

ExternalCasOffhostAnchorMemoryModel serializes reads and CAS with a mutex and uses the CP-0481 Provider proof verifier before install. It is intentionally only an in-memory model and does not provide rollback resistance, multi-process linearizability, crash durability or independent administration.

A signing error after the state update models the ambiguous lost-response window: the state remains committed, and the caller must issue a new challenge-bound Read to discover the exact committed state. It must not infer abort from a missing response.

## Focused tests

The protocol test module covers:
1. signed Read encode/decode and rejection of a receipt replayed against a new challenge;
2. wrong Anchor domain and altered state rejection;
3. explicit distinction of Provider and Anchor receipt keys;
4. signed CAS, exact idempotent retry and fresh Read reconciliation after an omitted response;
5. one successful response and one signed Conflict in two concurrent successor attempts;
6. committed CAS surviving an injected Anchor response-signing failure, then recovery by a fresh signed Read.

The full suite additionally retains CP-0481 adversarial Provider-proof tests and the paired Provider/QCF1 rollback-boundary tests.

## Remaining qualification

Not implemented:
- AWS/DynamoDB or another durable off-host monotonic storage adapter;
- server-side durable atomic conditional update, durable operation/idempotency record and restore controls;
- separate-account IAM/KMS provisioning and independent security administration;
- production client CSPRNG, authenticated transport/session identity, wire framing and deadlines;
- daemon, service health/availability handling and key rotation/revocation;
- node startup and QAP1/QCF1/PFS2 integration;
- cross-process, multi-host, crash, network-partition, restore, failover and independent security tests.

The in-memory mutex is not evidence of DynamoDB conditional-write behavior or production anti-rollback. The off-host release gate remains open.

## Validation

Exact-branch validation on 2026-10-31:
- `cargo fmt --all -- --check`: PASS
- `cargo test --lib --locked --offline`: PASS, 990 passed, 0 failed, 0 ignored
- `cargo check --all-targets --locked --offline`: PASS (pre-existing unused-import/dead-code warnings in unrelated modules remain)
- `git diff --check`: PASS

Focused candidate command:
`cargo test --lib --locked --offline external_cas_offhost_anchor_protocol_candidate`

## Release boundary

CP-0482 does not enable public provider deployment, Mainnet, public mint, firewall changes or QZXB/USDT trading. No consensus, Genesis, Network ID or 10B QZXB supply setting is changed.
