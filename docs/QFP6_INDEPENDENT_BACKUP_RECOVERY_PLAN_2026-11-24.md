# QFP6 independent backup and recovery engineering plan

**Status:** engineering plan / design gate only. This document does not claim that a backup has been taken, that a restore path is implemented, or that the public testnet is operational.

## Objective

Provide a verifiable, recoverable backup path for each QFP6 zero-value testnet node without weakening consensus, trust-anchor, key-custody, or durable-history guarantees.

## Current verified blockers

- The three Railway services (seed, relay, joiner) each have a distinct 500 MB persistent volume mounted at `/data`.
- Their latest observed startup logs report a fail-closed preflight refusal: existing durable history requires an independently pinned `permissionless_runtime.trusted_manifest_anchor`.
- A successful Railway deployment status is not evidence that the blockchain process completed startup.
- Railway volume UI inspection did not expose a verified manual backup/snapshot/restore workflow. Wipe-volume UI wording mentioning backups does not establish backup availability or restore capability.
- No verified live node export/snapshot endpoint or operator backup/restore interface has been identified.

## Exact deployed runtime trace (read-only inspection, 2026-11-24)

- Railway's seed service uses image tag `1c2edc459093`, which resolves to repository commit `1c2edc45909329157b97d364c77666fbf19bf541`. Relay and joiner use `6fbbd98f4730`, resolving to `6fbbd98f47309f1deb5883b8bc6a6955f9e1702c`.
- The seed image's entrypoint uses v3 role directories (`node-data-<role>-v3`, `mempool-<role>-v3`, `q6pd-<role>-v3`, `anchor-vault-<role>-v3`); the relay/joiner image refresh uses the corresponding v4 directories. A unified image refresh must preserve each role's existing layout or explicitly refuse ambiguous v3/v4 state; it must not silently switch the seed to an empty v4 directory.
- The latter image is an entrypoint-only refresh over base image `66468e2b3667`; its Dockerfile copies a Python entrypoint and does not rebuild or replace the Rust binary.
- The base Dockerfile builds `qrun_v06_node` using `cargo build --release --locked --bin qrun_v06_node`. The Railway entrypoint executes that binary with `--public-testnet-run`. Therefore the deployed target is the QRun v0.6 public-testnet candidate runtime, not `devnet_node` and not `private_testnet_node`.
- The separate `devnet_node` / `private_testnet_node` sources are explicitly loopback-only harnesses. They are not the Railway executable.
- The entrypoint builds a config with a `trusted_manifest_anchor_vault_path` but does not populate `trusted_manifest_anchor`. The Rust startup gate requires that independent root value whenever the node data directory already contains manifest entries; otherwise it returns the exact fail-closed error shown in Railway logs.
- The entrypoint's v4 paths place the data directory at `/data/node-data-<role>-v4`, mempool at `/data/mempool-<role>-v4`, and anchor vault at `/data/anchor-vault-<role>-v4`. These are separate directories, but all are under the same Railway `/data` volume. Lexical path separation does not make the anchor vault independent of rollback or loss of that volume.
- The fresh-Genesis Joiner path is intentionally limited to a generation-zero, height-zero store with no existing history. It refuses to adopt existing history automatically. The current logs show that this condition is not met for the deployed services.
- The runtime's public-testnet mode explicitly acknowledges anonymous Noise XX inbound security and labels itself a zero-value candidate. Deployment of the container image does not establish that a listener successfully opened or that Internet peers synchronized.

## Non-negotiable safety rules

1. Never wipe, detach, resize, replace, or reinitialize existing volumes as part of backup work.
2. Never copy an actively-mutating database directory as if a raw filesystem copy were a consistent snapshot.
3. Never export private keys, service secrets, signing material, or credentials into backup artifacts, logs, Git, or a third-party bucket.
4. Preserve an independently provisioned trust anchor and monotonic anti-rollback state outside the node disk's rollback domain.
5. Do not treat a locally generated checksum, a manifest stored beside the data, or a second directory on the same volume as an independent trust anchor.
6. Do not fabricate or infer the existing trusted manifest anchor from local history. It must be obtained and verified through an independent provisioning channel, then matched against the existing manifest chain and vault.
7. No deploy, restart, service-variable change, volume mutation, or production cutover without a separate explicit approval and a reviewed rollback plan.
8. No new paid storage or infrastructure unless costs and retention are disclosed and approved.

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
2. **Trust-anchor recovery:** independently provision the exact root anchor for each existing node and verify the matching local vault and manifest chain. Do not restart or change service variables until the value and rollback domain are independently validated.
3. **Rollback-domain correction:** move monotonic high-water protection outside the Railway data volume (or integrate a genuinely independent, strongly consistent anchor service). A sibling directory under `/data` is not sufficient.
4. **Storage API review:** map the actual QRun v0.6 durable write path and determine whether a consistent logical snapshot can be exposed safely. Do not infer that standalone snapshot candidates are integrated.
5. **Design and tests:** implement snapshot manifest schema, deterministic encoding, writer coordination, failure atomicity, and hostile-input tests in a separate branch.
6. **Export and restore:** implement bounded streaming export with no secret material, isolated restore, external anchor verification, monotonic floors, full archive replay, and canonical-tip equality checks.
7. **CI:** add deterministic round-trip, crash/fault-injection, truncation, corruption, rollback, stale-anchor, missing-ancestry, and cross-node divergence tests.
8. **Operator drill:** run against synthetic test data first; then request explicit approval for any live read/snapshot operation that may affect resource use.
9. **Deployment gate:** only after independent review, passing CI, verified trust-anchor provisioning, and a separate explicit deployment approval.

## Current gate decision

**NO-GO for live backup/export and NO-GO for deployment at this stage.** The deployed QRun v0.6 process refuses startup because existing durable manifests are present but the independent `trusted_manifest_anchor` is not supplied. The current entrypoint does not supply it, and the local anchor vault is colocated on the same Railway volume as the node data. Do not solve this by deleting history, silently enabling fresh-Genesis mode, or weakening the gate.

The next safe engineering step is to obtain a read-only inventory of each existing volume's manifest/vault metadata and canonical tip, then independently establish the exact root anchor and a real external anti-rollback domain. Only after that should a consistent snapshot/export implementation be built and tested. No claim of a usable backup or operational public network should be made until a complete isolated restore and network synchronization drill passes.
