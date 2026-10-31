# CP-0481 — QRun Off-Host Anchor Provider-Proof Validator

Date: 2026-10-31

Status: **The QRun-specific service-side Provider-proof validator is implemented as candidate code and has six focused tests. It is not a remote service, durable monotonic store, signed Anchor protocol, or runtime integration.**

## Scope

CP-0480 defines the off-host Anchor architecture. CP-0481 implements the first narrow security primitive needed by that service: independently verifying a Provider ECR1 successor and its ECS1 commit receipt against the Anchor's trusted current high-water state.

New module:
- \`src/native/pow_bench/src/external_cas_offhost_anchor_candidate.rs\`

It is explicitly registered as a candidate module in \`lib.rs\`. It has no network listener, cloud SDK, persistence backend, Anchor signing key, node startup callsite, or consensus callsite.

## Implemented contract

- \`ExternalCasOffhostAnchorState\` binds an independent Anchor sequence, the exact canonical ECR1 record, Provider object generation, last accepted operation ID, request digest and first accepted signed ECS1 receipt digest.
- Bootstrap is explicit and accepts only generation-zero ECR1 at Provider object generation one; operation/receipt metadata must be zero only in this bootstrap state.
- State validation binds Provider ID, Network ID and wallet-bound Genesis digest to the pinned \`ExternalCasPin\`.
- The Anchor sequence and Provider object generation must both track the exact one-step successor of the ECR1 logical generation. This version intentionally models one anchor sequence increment per Provider CAS.
- \`verify_provider_commit_for_offhost_anchor\` reconstructs the Provider write precondition from the trusted Anchor state for a first-time transition; it does not trust predecessor-generation or object-generation claims supplied by the caller.
- For an exact retry after the Anchor already advanced, it reconstructs the original predecessor from the canonical ECR1 predecessor links and requires the operation ID and request digest to match current high-water metadata before returning \`AlreadyApplied\`.
- The reconstructed \`ExternalCasWriteRequest\` is checked by the existing ECR1/ECS1 contract, including its request digest, Provider/Network/Genesis/key pins, exact record/state links and ML-DSA-65 receipt signature.
- A verified first-time transition requires both logical generation and Provider object generation to advance exactly one. A skipped object generation is rejected even when a Provider receipt is correctly signed.
- The result includes a domain-separated digest of the complete proposed Anchor state and a digest of the signed Provider receipt for a future atomic storage adapter. The first accepted receipt digest is persisted in the high-water state and is not overwritten by a later idempotent retry receipt.

## Focused adversarial tests

The seven tests cover:
1. acceptance of a valid Provider-signed exact successor;
2. rejection of a tampered Provider ML-DSA-65 signature;
3. rejection of a skipped Provider object generation;
4. idempotent exact retry after the Anchor state already equals the target;
5. wrong Genesis/domain rejection and rejection of a competing same-generation sibling after the first sibling has become the anchored state;
6. rejection of high-water state with mismatched last-operation metadata;
7. binding of the Anchor state digest to its sequence, object generation, complete ECR1 bytes and last-operation metadata.

The same-generation sibling test does not claim to detect every instance of Provider equivocation before a branch is anchored. It proves that once a high-water branch has been accepted, a sibling based on an older predecessor is not accepted as a successor of the current Anchor.

## Remaining work

This validator is only the proof-checking core. The following are still unimplemented:
- an Anchor receipt format signed by a distinct, separately pinned ML-DSA-65 key;
- fresh challenge-bound Anchor read and compare-and-swap wire operations;
- durable, server-side idempotency and atomic high-water storage;
- a separately administered off-host backend (the CP-0480 AWS/DynamoDB profile is a proposal, not a provisioned resource);
- Anchor daemon, transport, service authentication, key lifecycle and operational audit;
- node integration that requires the remote Anchor before startup/block acceptance and orders Provider CAS, remote Anchor CAS, local QCF1 cache and PFS2 publication safely;
- staging-account, multi-host, crash, network-partition, restore, key-rotation and independent security qualification.

A local file implementation of this new validator would not satisfy the off-host trust requirement. The future storage adapter must compare the exact previously read Anchor sequence and state digest atomically, return a signed challenge-bound receipt, and fail closed on unavailable/ambiguous state. The off-host service must independently verify ECS1; it must not accept a node assertion that the Provider commit was valid.

## Validation

Focused candidate test command:
\`cargo test --lib --locked --offline external_cas_offhost_anchor_candidate\`

Exact-branch validation after the final metadata-binding update: \`cargo fmt --all -- --check\`: PASS; \`cargo test --lib --locked --offline\`: PASS, 984 passed, 0 failed; \`cargo check --all-targets --locked --offline\`: PASS (existing unused-import/dead-code warnings in other modules remain); \`git diff --check\`: PASS.

## Release decision

CP-0481 does not close the off-host anti-rollback gate, does not authorize public provider deployment, does not alter consensus or monetary behavior, and does not change Genesis, Network ID or the 10B QZXB supply cap. Keep Mainnet release approval false, public mint disabled and public firewall configuration unchanged.
