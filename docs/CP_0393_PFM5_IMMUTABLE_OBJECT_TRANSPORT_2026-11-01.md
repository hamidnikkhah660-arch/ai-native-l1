# CP-0393 — PFM5 immutable object transport candidate

Date: 2026-11-01

Status: **A provider-neutral immutable-object transport contract and local in-memory conformance tests are implemented. No cloud/object-store adapter, external provider identity authentication, External-CAS write, independent-host deployment or runtime wiring is included.**

## Purpose

CP-0392 made the PFM5/PCP4/PMT4 branch set durable on one host. A signed ECR1 record can commit to the exact PFM5 manifest commitment, but that commitment alone does not make the referenced PCP4 checkpoint or PMT4 branch envelopes available to another host.

CP-0393 introduces a separate provider boundary for publishing and fetching those immutable objects. The provider is treated as an untrusted byte store. Content identity and chain validity are checked by QRun before a successful publication report or fetched bundle is returned.

## Typed object keys

Every object key is encoded with the domain separator:

AIN1-PFM5-IMMUTABLE-OBJECT-KEY-V1\0

The canonical key binds:
- object kind: Manifest, Checkpoint or Branch;
- network ID;
- trusted Genesis fingerprint;
- typed content digest: PFM5 manifest commitment, PCP4 checkpoint record commitment or PMT4 proof-of-work digest.

Keys are fixed-shape, reject zero bindings, and are not caller-provided filesystem paths.

## Provider contract

Pfm5ImmutableObjectProviderTransport exposes only:
- put_immutable(key, bytes): MUST be an atomic server-side create-if-absent operation; existing bytes must never be overwritten;
- get(key): return the exact stored object bytes.

A read followed by an unconditional write does not meet the contract. This module does not implement a cloud adapter or prove that a provider is independently administered.
## Publication ordering and validation

A Pfm5ImmutableObjectBundle can be constructed only after:
1. decoding and validating the PFM5 manifest and PCP4 checkpoint against the caller's configured network, trusted Genesis, consensus profile and transaction manifest;
2. matching the complete supplied PMT4 digest set to the exact digest set in PFM5, with duplicate and unlisted branches rejected;
3. checking bounded per-object and aggregate byte limits;
4. replaying the complete retained branch graph from the trusted checkpoint with the existing fork-choice validator.

Publication order is strict:
1. PCP4 checkpoint;
2. each PMT4 branch object in canonical manifest order;
3. PFM5 manifest last.

Each object is fetched back immediately, size-checked, compared byte-for-byte and checked against its typed key before publication proceeds. Therefore a manifest object is never published by this client after an earlier object fails read-back validation. Already published immutable objects may remain as harmless unreferenced objects after a partial failure; garbage collection is outside this candidate.

The returned manifest commitment is eligible to be proposed as ECR1 next_state_digest only after every object has been read back and verified. This module itself never performs that CAS.

## Fetch and trust boundary

Fetch starts from a nonzero manifest commitment obtained by the caller from a separately authenticated signed ECR1 read. It retrieves the manifest, obtains the checkpoint commitment and branch digests from that manifest, retrieves all referenced objects, validates every typed key and object, then invokes full PCP4/PMT4 replay again.

The object provider is not authenticated by this module. The trusted ECR1 read, provider pin, signed receipt verification and independently protected anti-rollback floors remain responsibilities of the caller. A manifest hash comparison alone is not proof of provider identity, freshness or rollback resistance.
## Tests and validation

The module's local in-memory provider tests cover:
- canonical, domain-separated object keys and invalid key encodings;
- exact publication order: checkpoint, branches, then manifest;
- idempotent repeat publication without overwriting existing data;
- fetch and full replay of a branch-bearing snapshot;
- immutable-key conflict: old bytes remain unchanged and manifest is not published;
- corruption of a referenced branch is rejected even when the manifest commitment is correct;
- zero anchor and missing objects fail closed.

The provider test double models atomic create-if-absent semantics. It is not evidence of real object-store concurrency or cross-host consistency.

## Explicitly not implemented

- No S3, GCS, Azure, filesystem gateway or other real object-provider adapter.
- No provider authentication or TLS/Noise client binding in this module.
- No External-CAS record publication, signed receipt, CAS conflict/rebase or ambiguous-reply recovery in this module.
- No atomic multi-object transaction; partial publication can leave unreferenced immutable objects.
- No independently deployed second host, partition test, cross-host stale-writer race or provider durability/SLA test.
- Not wired into private_testnet_node, ordinary startup, Devnet or Mainnet.
- No Genesis, Network ID, consensus/PoW, issuance, Mainnet approval or QZXB trading policy change.

The next step is a concrete independently administered provider adapter plus an orchestration layer that performs signed ECR1 read, immutable-object publication/read-back, atomic ECR1 CAS, and fresh signed-read recovery on ambiguous outcomes. Only then should a two-host restart/partition test be attempted.

## Local validation

Observed on the Windows development machine:
- CP-0393 module tests: 5 passed, 0 failed.
- Complete Rust library suite after CP-0393: 791 passed, 0 failed.
- cargo check --all-targets --locked --offline: passed.
- cargo fmt --all -- --check: passed.
- git diff --check: passed.

These are local candidate tests with an in-memory provider double. They do not establish real provider atomicity, independent-host behavior, provider durability, or production readiness.
