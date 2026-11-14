# CP-0663 — Q6TS DynamoDB read-only trust-floor adapter qualification

Date: 2026-11-14  
Branch: `feat/cp0600-bootstrap-sync-startup`  
State: local adapter unit qualification PASS; no live AWS account or table accessed.

## Adapter boundary verified

Reviewed `qrun_v06_profile_trust_dynamodb_floor_candidate.rs` and the permissionless launcher wiring.

- AWS CLI is invoked directly through `std::process::Command` with argument vectors; no shell command string is constructed.
- Node startup uses `AwsDynamoDbQ6tsReadOnlyProfileTrustFloorStore`, whose `load` path uses DynamoDB `GetItem --consistent-read`.
- The node-side wrapper refuses `compare_and_swap` locally and does not invoke AWS CLI for that method. The node path therefore has no DynamoDB write path through this adapter.
- The publisher-side adapter is separate. Its CAS uses a conditional `PutItem` comparing network/profile, epoch, status, previous record/envelope IDs and policy version, followed by a strongly consistent read-back.
- Missing floor rows, malformed/non-canonical fields, wrong network/profile, conditional conflicts, read-back mismatch, unavailable read-back, and attempts to reactivate a revoked floor fail closed.
- One-time empty-floor provisioning is a separate publisher operation and cannot overwrite an existing row. A node read never auto-bootstraps a missing floor.
- Production independence still depends on separate operator/account governance and IAM: node role should be granted GetItem only and denied PutItem/UpdateItem/DeleteItem and table-management actions.

## Tests

Command:
`cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib qrun_v06_profile_trust_dynamodb_floor_candidate --locked --offline`

Result: **11 passed, 0 failed**.

Coverage includes strongly consistent reads, exact domain validation, missing-floor fail-closed behavior, malformed row rejection, CAS tuple conditions, conditional conflicts, read-back mismatch/unavailability, no-overwrite provisioning, terminal revocation, and an explicit assertion that the read-only node wrapper never invokes a write operation.

## Qualification boundary

These are deterministic tests using an injected scripted CLI runner. No AWS CLI call was made against a real account, no credentials were loaded, no DynamoDB table was read or written, and no IAM policy was inspected. The adapter's cloud integration, operator/account separation, IAM enforcement, table durability/backup, and independently administered trust service remain unqualified. No production Q6TS floor was provisioned or advanced.

The local Q6PN v2 + dual-signed Q6TS + signed Q6QA Noise/Q6PB integration test remains a local deterministic socket test with a memory floor fixture. Independent-host/public qualification remains open.
