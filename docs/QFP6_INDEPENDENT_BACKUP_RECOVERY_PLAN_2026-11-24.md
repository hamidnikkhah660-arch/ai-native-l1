# QFP6 independent backup and recovery engineering plan

**Status:** engineering plan / design gate only. This document does not claim that a backup has been taken, that a restore path is implemented, or that the public testnet is operational.

## Objective

Provide a verifiable, recoverable backup path for each QFP6 zero-value testnet node without weakening consensus, trust-anchor, key-custody, or durable-history guarantees.

## Current verified blockers

- The three Railway services (seed, relay, joiner) each have a distinct 500 MB persistent volume mounted at `/data`.
- Their latest observed startup logs report a fail-closed preflight refusal: existing durable history requires an independently pinned `permissionless_runtime.trusted_manifest_anchor`.
- A successful Railway deployment status is not evidence that the blockchain process completed startup.
- Repository documentation for CP-0388 and CP-0389 explicitly states that checkpoint/archive replay and externally anchored restore primitives are not yet wired into the live PFM4 store/runtime.
- The archive range sync candidate describes itself as research-only and not wired into the node or public wire.
- No verified live node export/snapshot endpoint or operator backup/restore interface has been identified.
- Railway volume UI inspection did not expose a verified manual backup/snapshot/restore workflow. Wipe-volume UI wording mentioning backups does not establish backup availability or restore capability.

## Non-negotiable safety rules

1. Never wipe, detach, resize, replace, or reinitialize existing volumes as part of backup work.
2. Never copy an actively-mutating database directory as if a raw filesystem copy were a consistent snapshot.
3. Never export private keys, service secrets, signing material, or credentials into backup artifacts, logs, Git, or a third-party bucket.
4. Preserve the existing independent trust anchor and monotonic anti-rollback state outside the node disk's rollback domain.
5. Do not treat a locally generated checksum or a manifest stored beside the data as an independent trust anchor.
6. No deploy, restart, service-variable change, volume mutation, or production cutover without a separate explicit approval and a reviewed rollback plan.
7. No new paid storage or infrastructure unless costs and retention are disclosed and approved.

## Required architecture

### A. Application-consistent snapshot contract

Implement a node-owned snapshot operation that obtains a stable logical snapshot while the node is running. The operation must coordinate with the durable writer and capture a consistent generation boundary. If the existing store cannot guarantee a stable snapshot, fail closed; do not fall back to copying live files.

The snapshot must identify:
- network ID and protocol/profile version;
- genesis and trusted-manifest identity;
- durable store format/version;
- snapshot generation and monotonic height floor;
- canonical tip digest and height;
- archive/branch inventory commitment and required replay boundary;
- exact file/object inventory, lengths, and SHA-256 digests;
- creation time and software build/commit identity.

### B. Restore verification

Restore must occur into a new, isolated data directory or disposable test environment, never over the source volume. Before accepting restored state:
- verify the signed or independently pinned manifest commitment from a trust source outside the backup;
- verify network, genesis, profile, format, generation, and monotonic floors;
- verify every object hash and expected length;
- replay all post-checkpoint archive entries through consensus before selecting the canonical tip;
- reject missing ancestry, stale generations, rollback, malformed records, or mismatched identities;
- compare the restored canonical tip and state commitment with the snapshot manifest.

### C. Independent storage and custody

Support an operator-selected destination outside the Railway volume and outside the node's rollback domain. Encryption must be client-side with keys held outside the service and never uploaded with the archive. Do not assume a Railway bucket or other paid service is available. A user-controlled offline disk is an acceptable initial destination if the export format is portable and documented.

### D. Three-node separation

Create independently identified backup sets for seed, relay, and joiner. Record each node role, network identity, generation, canonical tip, and volume identity. Do not assume the three volumes contain identical state. Compare them and report divergence rather than overwriting one with another.

### E. Operational evidence

A backup is not complete until all of the following evidence exists:
- snapshot operation reports a stable generation and completion;
- manifest signature/anchor verification succeeds using an independent trust source;
- every artifact passes hash and length verification after transfer;
- a restore drill succeeds in isolation;
- consensus replay reaches the expected canonical tip;
- the restored node starts without bypassing trust checks;
- the restore report records software version, test date, and limitations.

## Implementation sequence

1. **Read-only inventory:** identify the exact live binary, command line, data layout, storage engine, writer lifecycle, and trust-anchor source. Do not inspect or print secret values.
2. **Storage API review:** map the actual PFM4/PMT4 durable write path and determine whether a consistent logical snapshot can be exposed safely. Do not infer that standalone snapshot candidates are integrated.
3. **Design and tests:** implement snapshot manifest schema, deterministic encoding, writer coordination, failure atomicity, and hostile-input tests in a separate branch.
4. **Export path:** implement bounded streaming export with no secret material and explicit destination selection.
5. **Restore path:** implement isolated restore, external anchor verification, monotonic floors, full archive replay, and canonical-tip equality checks.
6. **CI:** add deterministic round-trip, crash/fault-injection, truncation, corruption, rollback, stale-anchor, missing-ancestry, and cross-node divergence tests.
7. **Operator drill:** run against synthetic test data first; then request explicit approval for any live read/snapshot operation that may affect resource use.
8. **Deployment gate:** only after independent review, passing CI, verified trust-anchor provisioning, and a separate explicit deployment approval.

## Current gate decision

**NO-GO for live backup/export and NO-GO for deployment at this stage.** The runtime is currently refusing startup because the independent trusted manifest anchor is absent. The safe next engineering step is to trace the actual durable storage and anchor-loading path and implement/test an application-consistent snapshot contract offline. No claim of a usable backup should be made until a complete isolated restore drill passes.
