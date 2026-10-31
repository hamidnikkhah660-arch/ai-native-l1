# CP-0483 — QRun AWS DynamoDB Off-Host Anchor Adapter Candidate

Date: 2026-10-31

Status: **AWS CLI-backed adapter candidate now includes explicit one-time bootstrap insertion, strongly consistent read-back and conflict classification. It has not been executed against AWS: AWS CLI is not installed in the current development environment, and no AWS account, DynamoDB table, Anchor KMS key or independent operator has been provisioned.**

## Scope

New module:
- \`src/native/pow_bench/src/external_cas_offhost_anchor_aws_dynamodb_candidate.rs\`

Type:
- \`AwsDynamoDbOffhostAnchorStore\`, implementing \`ExternalCasOffhostAnchorStore\`.
- \`provision_bootstrap_if_absent\`, a separate administrator-only operation that performs a conditional one-time bootstrap insert; normal reads never initialize an absent anchor.

This is the first concrete cloud-storage adapter candidate for CP-0482's injectable Anchor store contract. It does not create AWS resources or credentials, provision the Anchor public/private key, expose a network service, or wire the node to a remote Anchor.

## Execution boundary

- Uses AWS CLI v2 through \`std::process::Command\` with an argument vector; it does not invoke a shell or concatenate a shell command.
- Accepts an explicit CLI executable path or the \`aws\` executable resolved by the host PATH.
- Uses AWS CLI's configured credential provider chain; credentials are not copied into source, logged or included in Debug output.
- Uses explicit Region, table name, JSON output and bounded CLI connect/read timeouts.
- The adapter does not create, delete, migrate or restore the table.

## Read path

\`load_consistent\` issues DynamoDB \`GetItem\` against the base table with \`--consistent-read\`. It does not use a GSI, stream, cache or eventually consistent replica.

The returned item is rejected as corrupt unless it matches the configured:
- Anchor ID;
- Provider ID, Network ID and wallet-bound Genesis digest;
- Provider receipt key ID and SHA-256 public-key hash;
- Anchor receipt key ID and SHA-256 public-key hash;
- policy version.

It then decodes the exact base64 QAS1 state wire, validates canonical fixed length/re-encoding and checks that the stored sequence, Provider object generation and state digest equal values recomputed from the complete decoded state. A missing item is corruption/unprovisioned state; it is never silently initialized from a Provider response.

## Explicit one-time bootstrap

`provision_bootstrap_if_absent` accepts only a validated generation-zero ECR1 bootstrap at Anchor sequence one and Provider object generation one. It issues one DynamoDB `PutItem` guarded by `attribute_not_exists(anchor_id)`, so concurrent provisioners cannot replace an existing anchor. A successful insert is followed by a fresh strongly consistent read and exact full-state equality check before returning `Provisioned`. A conditional-write loser performs a new strongly consistent read and returns `AlreadyExists(current)`; the caller must compare that authoritative state with the reviewed ceremony record. Any malformed, missing or unreadable item fails closed. No first-read or first-write fallback is permitted.

This method is a storage primitive, not an authenticated public endpoint. A deployment must expose it only through a separately authorized, audited provisioning ceremony; routine Anchor runtime credentials must not receive table-create, delete, restore or bootstrap-administration authority.

## Atomic write path

\`compare_and_swap_atomic\` issues one DynamoDB \`PutItem\` with a ConditionExpression equivalent to:

\`attribute_exists(anchor_id) AND sequence = expected_sequence AND state_digest = expected_state_digest\`

The expression checks both the expected Anchor sequence and the digest of the complete predecessor state in one server-side conditional write. The replacement item carries the complete next QAS1 state and all domain/key/policy metadata.

A ConditionalCheckFailed response triggers a new strongly consistent base-table read and returns that observed state as Conflict. Any other CLI failure is Unavailable, not Conflict or success. The CP-0482 service performs its own fresh authoritative read after conflict before signing the client-facing Conflict receipt, and performs an exact strong read-back after an Applied write before signing success.

## Focused tests

Twelve tests use an injected scripted CLI runner, without AWS network access:
1. explicit bootstrap uses `attribute_not_exists(anchor_id)` and an exact strongly consistent read-back;
2. a concurrent bootstrap loser reads and returns the authoritative existing state;
3. nonzero-generation bootstrap input is rejected before any AWS call;
4. nonconditional bootstrap failure is Unavailable;
5. a successful PutItem with mismatching read-back is rejected;
6. a conditional bootstrap failure with no valid item fails closed;
7. GetItem requests a strongly consistent base-table read and validates configured pins;
8. missing item fails closed rather than silently bootstrapping;
9. altered domain, key IDs, public-key hashes or state digest are rejected;
10. PutItem's CAS condition checks sequence and full-state digest in one server-side write;
11. conditional-write failure returns a fresh strongly consistent Conflict observation;
12. nonconditional CLI failure is Unavailable and is never reported as a conflict.

The tests validate argument construction and response parsing. They do **not** prove the AWS service's live behavior, IAM policy, account separation, credentials, backup/restore restrictions or network availability.

## Production qualification still required

- Install and pin a reviewed AWS CLI v2 build in the staging runtime; test actual process execution and error classification.
- Provision a disposable single-Region DynamoDB table in a separately administered AWS account/recovery domain.
- Exercise the conditional generation-zero bootstrap insert under two live concurrent provisioners; verify exactly one insert wins, then compare the strong read-back with the reviewed ceremony record.
- Verify live strongly consistent reads, conditional PutItem concurrency, read-after-conflict and response-loss behavior.
- Apply and independently review IAM/SCP policies that separate service runtime from table deletion, backup restore, policy changes, account recovery and key administration.
- Provision a distinct Anchor ML-DSA-65 KMS key and test sign/verify, rotation, revocation and recovery under a separate security role.
- Perform concurrent multi-process/multi-host, crash, timeout, partition, restore and incident-recovery drills.
- Complete independent security review and QRun node integration before block production/import.

The AWS adapter candidate plus its scripted tests do not establish an independent administrative domain. A different Region, table, hostname or IAM role alone is insufficient if the Provider, node and Anchor can still be restored by the same administrator.

## Validation

Exact local validation on the branch containing this adapter:
- \`cargo fmt --all -- --check\`: PASS
- \`cargo test --lib --locked --offline\`: PASS, 1008 passed, 0 failed (includes six additional bootstrap tests)
- \`cargo check --all-targets --locked --offline\`: PASS (existing unused-import/dead-code warnings in unrelated modules remain)
- \`git diff --check\`: PASS

No AWS CLI was installed, so no live AWS request was attempted.

## Release decision

CP-0483 advances the implementation to a real adapter candidate but does not qualify a production off-host monotonic authority. Mainnet release approval remains false; public mint remains disabled; public firewall/listeners remain unchanged. No Genesis, Network ID or 10B QZXB supply setting is changed.
