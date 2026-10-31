# CP-0482 — QRun Off-Host Anchor Signed Protocol and Atomic Store Contract

Date: 2026-10-31

Status: **Signed protocol, injectable atomic-store contract, process-local test adapter, AWS DynamoDB CLI adapter candidate and explicit conditional bootstrap insert implemented. No AWS account/table, live AWS request, Anchor KMS key, independent operator domain, network service or node integration is deployed or qualified.**

## Scope

CP-0480 specifies the AWS-first off-host monotonic Anchor architecture. CP-0481 implements independent verification of Provider ECR1/ECS1 commit evidence. CP-0482 adds a QRun-specific challenge-bound Anchor receipt protocol and a storage-adapter contract.

Module:
- \`src/native/pow_bench/src/external_cas_offhost_anchor_protocol_candidate.rs\`

The module has no cloud SDK, network listener, Anchor private key storage, AWS account/table, node startup integration, or consensus callsite. The storage contract includes an explicit one-time bootstrap operation, but it is not a deployed Anchor service.

## Trust and domain separation

- Provider and Anchor use distinct ML-DSA-65 receipt key IDs and public keys. The Anchor pin is independently configured and bound to the same Provider ID, Network ID and wallet-bound Genesis digest.
- Receipt signing uses the \`QRUN-OFFHOST-ANCHOR-RECEIPT-V1\` domain.
- Every receipt binds Anchor ID, Provider ID, Network ID, Genesis digest, Anchor receipt key ID, fresh client challenge, operation ID, request digest, expected predecessor sequence/state digest, target state digest, resulting state digest and the complete canonical Anchor state.
- The state wire encoding includes the independent Anchor sequence, Provider object generation, canonical ECR1 bytes, last Provider operation ID, request digest, first accepted ECS1 receipt digest, and exact Anchor predecessor sequence/state digest used by the last successful CAS.
- The full-state digest covers all of those fields. Decoding enforces exact lengths, fixed magic/version/reserved bytes and canonical re-encoding.
- The canonical state is 424 bytes; the signed receipt payload is 796 bytes; with the 3,309-byte ML-DSA-65 signature, the complete QAR1 receipt is 4,105 bytes.

## Read protocol

A Read request carries a nonzero unpredictable challenge, operation ID and request digest. The Anchor service loads the authoritative state using \`load_consistent\`, revalidates the Provider/Network/Genesis pin and state invariants, and returns a signed \`Read/Observed\` receipt. The response includes the exact state, not only a digest. The client verifies the pinned independent Anchor ML-DSA-65 key, domain, challenge, request identifiers and state digest.

A receipt signed for one challenge is rejected when replayed against a different challenge. The client is responsible for generating unpredictable fresh challenges; the protocol never treats a reused or stale receipt as a response to a different request.

## CAS protocol

The client sends:
- a fresh challenge, operation ID and request digest;
- expected Anchor sequence and full expected state digest;
- target state digest;
- canonical next ECR1 bytes and the Provider's signed ECS1 commit receipt.

The Anchor service independently verifies the Provider proof using CP-0481. It accepts only the exact one-step successor of the trusted Anchor state. It calls a single \`compare_and_swap_atomic(expected_sequence, expected_state_digest, next_state)\` operation.

Outcomes:
- \`Applied\`: the adapter conditionally installed the exact complete target; the service performs a fresh authoritative read-back and requires field-exact equality before signing success.
- \`AlreadyApplied\`: the exact operation/request/target/predecessor metadata is already the high-water state and the same Provider proof verifies; the service returns an idempotent signed response without a second sequence advance.
- \`Conflict\`: the authoritative state differs from the requested predecessor. The signed conflict includes the full current state and cannot be interpreted as success. A state below the expected sequence, or a conflict-shaped response naming the exact requested committed operation, is rejected by the client.

If the Anchor CAS commits but signing its response fails, the state remains committed. The caller must use a fresh challenge-bound Read, then retry the exact immutable operation only when the authoritative state proves the expected outcome. There is no fallback to local QCF1.

## Storage adapter contract

\`ExternalCasOffhostAnchorStore\` requires:
- \`load_consistent\`: authoritative strongly consistent read;
- \`compare_and_swap_atomic\`: one server-side conditional update comparing both expected sequence and full state digest and atomically installing the complete next state.

A client-side read followed by an unconditional write is explicitly forbidden. The adapter returns the full authoritative current state on a precondition conflict. Storage errors, unavailable state, corrupt data or an ambiguous write are fail-closed.

The included \`ExternalCasOffhostAnchorMemoryStore\` is only a process-local test implementation. It is neither durable nor off-host and does not protect against process/host rollback. CP-0483 adds an \`AwsDynamoDbOffhostAnchorStore\` candidate using AWS CLI v2 without a shell, strongly consistent base-table GetItem and a conditional PutItem that compares both expected sequence and full-state digest. Its six tests use a scripted CLI runner only; the AWS CLI is not installed in this environment and no live AWS request/table/account has been tested or provisioned.

## Tests

Twelve focused protocol tests cover:
1. challenge-bound signed Read wire roundtrip and rejection when replayed against a different challenge;
2. signed CAS, idempotent retry and fresh Read reconciliation after an ambiguous/lost response;
3. two concurrent successors against the same predecessor, with exactly one Applied and one Conflict result;
4. rejection when the Anchor key ID or public key is the Provider receipt key;
5. rejection of altered full state and wrong Anchor ID/domain;
6. rejection of an adapter which claims Applied without changing the authoritative state (read-back mismatch);
7. rejection of unavailable atomic storage without fallback or publishing the target;
8. rejection of a Conflict receipt that certifies the expected old state or a rolled-back sequence;
9. proof that the atomic store contract compares sequence and the complete state digest in one CAS;
10. revalidation of every loaded state observation after service construction;
11. commit persistence despite Anchor response-signing failure, resolved only by a fresh signed Read;
12. rejection of a stale adapter Conflict payload unless a fresh authoritative read confirms the current high-water state.

## Validation

Exact local validation on 2026-10-31, on the dependent atomic-store-contract branch:
- `cargo fmt --all -- --check`: PASS
- `cargo test --lib --locked --offline`: PASS, 1002 passed, 0 failed
- `cargo check --all-targets --locked --offline`: PASS (existing unused-import/dead-code warnings in unrelated modules remain)
- `git diff --check`: PASS

The 12 focused protocol tests and 6 scripted DynamoDB adapter tests are included in the 1002-test library run. The AWS adapter test runner simulates CLI responses and does not contact AWS.

## Remaining production gates

Still not implemented or qualified:
- live qualification and deployment of the AWS DynamoDB adapter in a separately administered staging account/recovery domain, including actual CLI execution, IAM/SCP, backup/restore and concurrency behavior;
- the deployable Anchor daemon, authenticated transport and operational configuration;
- production KMS signer integration using a distinct Anchor key and independently governed key lifecycle;
- explicit bootstrap provisioning ceremony and restore/delete/policy separation in a separate account;
- staging tests for actual consistency, conditional-write behavior, permissions, backups/restores, concurrency, partitions, crashes, key rotation, regional behavior and audit;
- independent administrative and recovery custodians;
- QRun node integration into startup, block acceptance, QAP1/QCF1/PFS2 ordering and recovery;
- end-to-end multi-host qualification and independent security review.

No AWS resources or independent operators have been provisioned or verified. This protocol/model does not close the off-host anti-rollback release gate.

## Release decision

No changes to consensus, monetary rules, Genesis, Network ID, 10B QZXB supply, public listener, firewall or mint settings. Mainnet release approval remains false and public mint remains disabled.
