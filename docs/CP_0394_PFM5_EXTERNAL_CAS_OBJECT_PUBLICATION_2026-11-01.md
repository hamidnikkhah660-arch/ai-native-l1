# CP-0394 — PFM5 immutable publication and signed ECR1 CAS orchestration

Date: 2026-11-01

Status: **Local orchestration candidate implemented and tested against in-memory object and signed ECR1 provider doubles. No live provider, independent provider administration, Devnet runtime wiring, or production transaction has been performed.**

## Purpose

CP-0392 introduced a durable local PFM5/PCP4/PMT4 store. CP-0393 introduced immutable object publication/fetch with byte-exact read-back and complete replay. CP-0394 coordinates those objects with the existing pinned ML-DSA-65 signed ECR1 compare-and-swap contract.

A manifest commitment is not advanced in ECR1 until the referenced checkpoint and all branch objects have been published and read back successfully. The ECR1 predecessor is read and receipt-verified before object publication; a competing logical successor is rejected before object publication begins.

## Intent and replay contract

`Pfm5ExternalCasIntent` records:
- exact expected ECR1 predecessor record;
- exact immutable-provider object-generation precondition;
- deterministic operation ID, write nonce and exact CAS request;
- exact successor record that commits to the PFM5 manifest commitment.

The intent is fixed-width and checksummed. It is a replay input, not a replacement for trust: callers must persist the exact encoded intent and predecessor/object-generation high-water marks in storage outside the provider/local rollback domain before invoking execution. An ambiguous result must be retried using that same serialized intent, not a newly prepared request.

Before side effects, execution validates the intent and independently reconstructs it from the supplied bundle and predecessor. An altered intent cannot be accepted merely because its checksum is internally consistent.

## PFM4-compatible ECR1 Genesis pin

The existing External-CAS PFM4 store derives its pinned Genesis digest from the network, consensus/profile fingerprint and canonical Genesis tip under its own domain separator. PCP4/PFM5 uses a separate trusted-Genesis fingerprint.

CP-0394 deliberately reuses the exact PFM4 External-CAS Genesis derivation for the ECR1 pin; it does not substitute the PCP4/PFM5 fingerprint. This preserves compatibility with the existing signed ECR1 domain contract.

## Execution order

1. Validate pin, exact predecessor, object-generation floor, manifest parent commitment and independently derived PFM4-compatible Genesis pin.
2. Issue a fresh challenge-bound signed ECR1 read and verify the exact predecessor and object-generation floor. If the exact successor is already committed, re-publish/read-back the immutable bundle idempotently and classify it as already committed. A competing successor fails closed before object upload.
3. Publish PCP4, each PMT4 branch, then PFM5 manifest through CP-0393. Every object is bounded, read back byte-for-byte and checked against its typed commitment before proceeding.
4. Submit the exact ECR1 successor CAS using the persisted request identity and object-generation precondition.
5. If the commit response is ambiguous, issue a new signed read challenge and classify only:
   - exact intended successor with advanced object generation: committed after ambiguous reply;
   - exact unchanged predecessor and unchanged object generation: retry the same intent;
   - any competing successor or inconsistent observation: fail closed.

A signed CAS conflict is not treated as success. When a fresh signed read proves the predecessor is still unchanged, the outcome is `RetrySameIntent`; the caller may retry that same intent after resolving the transient conflict. Immutable-object conflicts prevent any ECR1 CAS call.

## Tests

The CP-0394 local tests cover:
- fixed-width intent encode/decode, checksum mutation and pin binding;
- object read-back preceding the signed ECR1 commit;
- lost CAS reply after remote commit, resolved by a fresh signed read;
- signed conflict while predecessor is unchanged, followed by retry of the exact same intent;
- already-committed exact successor idempotency;
- competing successor rejection before object upload;
- immutable object conflict preventing any ECR1 CAS;
- PFM4-compatible Genesis pin and parent-manifest binding checks.

The test providers use local in-memory state and test signing keys. They do not establish real cloud provider atomicity, external service authentication, two-host behavior or production availability.

## Explicitly not implemented

- No concrete S3, GCS, Azure or other object-store adapter.
- No concrete independently administered External-CAS service or cloud conditional-write adapter.
- No production key provisioning/rotation, service identity authentication or network deployment.
- No durable intent journal implementation; the caller must persist the exact intent and anti-rollback floors outside the rollback domain.
- No garbage collection of orphaned immutable objects after partial publication.
- No integration into `private_testnet_node`, default startup, public Devnet or Mainnet runtime.
- No consensus/PoW, Genesis, network identity, issuance, token allocation, Mainnet approval or QZXB trading policy change.

Next gate: implement concrete provider adapters with independently pinned service identities and durable caller-side intent/floor storage, then conduct a two-host restart/partition/stale-writer campaign against those real adapters before any runtime wiring.

## Local validation

Observed on the Windows development machine:
- CP-0394 module tests: 8 passed, 0 failed.
- Complete Rust library suite: `cargo test --lib --locked --offline -- --test-threads=4` — **799 passed, 0 failed**.
- `cargo check --all-targets --locked --offline`: passed.
- `cargo fmt --all -- --check`: passed.
- `git diff --check`: passed.

The suite includes actual child-process crash/restart and writer-race tests. CP-0394 provider tests remain in-memory doubles and do not count as external-provider or two-host evidence.
