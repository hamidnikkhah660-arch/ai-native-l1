# CP-0483 — QRun Off-Host Anchor Atomic Storage Contract

Date: 2026-10-31

Status: **A storage-adapter contract and process-local conformance model are implemented. No durable or off-host storage adapter is implemented or deployed.**

## Scope

CP-0480 defines the separate-admin-domain architecture. CP-0481 verifies Provider ECR1/ECS1 commit evidence. CP-0482 defines challenge-bound signed Read/CAS receipts. CP-0483 removes the direct mutex dependency from protocol logic and introduces an injectable atomic storage boundary.

The new public contract is in:
- src/native/pow_bench/src/external_cas_offhost_anchor_protocol_candidate.rs

It defines:
- ExternalCasOffhostAnchorStore;
- ExternalCasOffhostAnchorStoreError;
- ExternalCasOffhostAnchorStoreCasOutcome;
- ExternalCasOffhostAnchorMemoryStore, a process-local test implementation;
- ExternalCasOffhostAnchorMemoryModel::with_store, allowing protocol service tests to inject another implementation.

## Required adapter semantics

An implementation MUST provide:

1. load_consistent:
   - return the authoritative, complete Anchor item;
   - use a strongly consistent/authoritative read;
   - validate canonical state bytes and fail closed on missing, malformed or corrupt state;
   - never silently initialize or reset the anchor during a read.

2. compare_and_swap_atomic(expected_sequence, expected_state_digest, next_state):
   - perform ONE atomic server-side conditional operation;
   - compare BOTH the expected Anchor sequence and digest of the complete predecessor state;
   - atomically write the entire next state, including ECR1, Provider object generation, last operation ID, Provider request digest, first accepted Provider receipt digest, and predecessor Anchor sequence/digest;
   - return Applied only after the conditional update is committed;
   - on a stale predecessor, return Conflict with the complete current state;
   - return Unavailable or Corrupt as errors, never as conflict or success.

A local read followed by an unconditional write is explicitly forbidden. Sequence-only compare is also insufficient because the same sequence with a different state digest is equivocation/corruption.

The protocol service verifies the Provider receipt and exact successor BEFORE calling the store. The store still verifies the predecessor condition atomically; this second boundary closes the race between protocol read and backend write.

## Service ordering and race resolution

1. Load current authoritative state with load_consistent.
2. If the state exactly equals the requested target and last-operation metadata binds the same operation, request digest, predecessor sequence and predecessor digest, verify the Provider proof and return signed AlreadyApplied.
3. If sequence or full predecessor digest differs, return a signed Conflict carrying the authoritative current state.
4. Independently verify the Provider ECR1/ECS1 evidence and construct the exact next Anchor state.
5. Call compare_and_swap_atomic using the exact expected sequence and full predecessor digest.
6. If Applied, sign an Applied receipt for the exact target.
7. If the store reports Conflict, inspect the returned current state. If it is the exact same operation/target/predecessor (another identical request won), verify the Provider proof and return AlreadyApplied. Otherwise return signed Conflict.
8. If the store is unavailable, return a storage error and fail closed. Never fall back to the process-local test store or local QCF1.

If the durable write succeeds but Anchor response signing fails or the network response is lost, the caller performs a new challenge-bound Read. It must not infer abort or generate a new operation.

## Candidate implementation and tests

ExternalCasOffhostAnchorMemoryStore implements the contract using a process-local Mutex solely for deterministic tests. Its CAS checks:
- expected sequence and exact digest;
- exactly one sequence increment;
- exactly one Provider object-generation increment;
- exact ECR1 successor linkage;
- persisted operation/request IDs and predecessor Anchor sequence/digest linkage.

The focused protocol suite now has eight tests, including:
- atomic compare against both sequence and full digest;
- competing same-predecessor successors: one Applied, one Conflict;
- unavailable store fails closed and preserves the bootstrap;
- signed retry and ambiguous response recovery;
- response-signing failure after commit followed by fresh Read recovery.

This implementation is a conformance model, not a durable store. The Mutex only serializes operations inside one process.

## Next adapter qualification

A separate staging adapter must prove:
- the exact server API performs conditional writes rather than a client-side read/put sequence;
- strong read-after-write and conflict responses return a complete authoritative item;
- concurrent clients/processes with identical predecessor have exactly one winner;
- timeout after accepted write is resolved by a fresh signed Read;
- malformed/missing/corrupt items and service unavailability fail closed;
- backup restore cannot reduce the off-host high-water state;
- routine service role cannot delete, restore or rewrite historical anchor state;
- separate administrator/account/recovery domain, separate Anchor key and independent audit controls are effective;
- crash, partition, failover, key rotation and recovery are tested against the real staging service.

The CP-0480 AWS/DynamoDB profile remains a proposal until a separately administered staging account is provisioned and tested. This CP does not provision cloud resources and does not claim that a remote floor exists.

## Validation

Focused candidate tests after the final Store-interface update: eight passed, zero failed.

Exact-branch validation on 2026-10-31:
- `cargo fmt --all -- --check`: PASS
- `cargo test --lib --locked --offline`: PASS, 992 passed, 0 failed, 0 ignored
- `cargo check --all-targets --locked --offline`: PASS (pre-existing unused-import/dead-code warnings in unrelated modules remain)
- `git diff --check`: PASS

Focused command:
`cargo test --lib --locked --offline external_cas_offhost_anchor_protocol_candidate`

## Release boundary

No AWS resource, daemon, remote endpoint, production signer, or node/runtime integration is included. The off-host anti-rollback gate remains open. Mainnet stays blocked, public mint disabled, public firewall unchanged and QZXB/USDT trading must not be described as live. Genesis, Network ID and the 10B QZXB supply cap are unchanged.
