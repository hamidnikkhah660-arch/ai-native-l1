# CP-0491 ? QRun v0.5 Genesis-to-Checkpoint Migration Executor

Date: 2026-11-01

Status: **A consuming migration API and end-to-end local integration test pass. This is a candidate maintenance operation; it is not wired to ordinary node startup/CLI and does not activate Mainnet or a production provider.**

## Purpose

QRA1 archive creation/replay, QRM1 exact migration intent, signed External-CAS recovery, QCF1 floor advancement and checkpoint-rooted PFS2 installation previously existed as separate primitives. This checkpoint adds one consuming method to `QRunV05ExternalCasForkStore`:

`migrate_genesis_rooted_store_to_checkpoint(...)`

It coordinates the first migration of an already initialized **Genesis-rooted** QRun v0.5 fee-only PFS2 store to a QFP5 checkpoint while preserving writer-lock and trust ordering. The Store API itself derives the only valid height-zero QRCP parent commitment from the pinned network, Genesis commitment, actual Genesis ledger and active consensus parameters; it never treats a caller-provided parent hash as trust-on-first-use.

## Execution ordering

1. Consume the open external-CAS store, retaining its verified provider client, identity pin and attached QCF1 floor.
2. Fail closed if the floor is missing/write-blocked, the store is not QRun v0.5 fee-only, or the source is not Genesis-rooted.
3. Derive the deterministic height-zero QRCP commitment from the pinned network ID, pinned Genesis digest, actual height-zero Genesis ledger and active consensus parameters. Require an exact match with the caller-supplied parent commitment; reject any other lineage before the migration executor reads its QCF1 snapshot, issues a fresh provider read, creates QRA1/QRCP/QRM1 or performs CAS.
4. Canonicalize the independent QCF1 floor and QRA1 archive roots and reject overlap before taking the floor snapshot or making the fresh provider request. The QRCP output parent is canonicalized too; output under source PFS2, the full archive root or QCF1 floor is refused, including traversal aliases.
5. Require the QCF1 snapshot, PFS2 manifest anchor and pinned provider record to agree. Perform a fresh signed provider read immediately before creating the migration plan; cached state alone cannot authorize the operation.
6. While the source PFS2 writer lock is held, create-or-verify the QRA1 archive and replay it from the original wallet-bound Genesis. The replay checks the exact archive identity/profile/Genesis/manifest bindings and reconstructs the canonical QFP5 tip.
7. Prepare the exact QRM1 migration intent from the verified replay and exact current ECR1 successor.
8. Persist the bounded QRCP bytes to a separate caller-supplied absolute path using create-once semantics. Existing identical bytes are idempotent; different bytes, symlinks/reparse points and paths inside PFS2, the complete QRA1 archive root or QCF1 floor are refused. The file and parent directory are synced where supported.
9. Persist QRM1 while the source PFS2 lock is still held, then drop the source store lock.
10. Invoke the existing recovery executor only after the lock is released. It performs exact provider CAS reconciliation, signed receipt verification, QCF1 advancement and checkpoint-rooted PFS2 manifest installation; QRM1 is cleared only after successful recovery.
11. Verify the recovered QRCP commitment and bytes exactly match the pre-persisted checkpoint file before returning a report.

The API deliberately does not initialize a provider, replace a trust pin, reset a floor, infer a provider state or fall back to a local store. The caller must already hold a correctly provisioned, independently pinned External-CAS client and QCF1 floor.

## Integration test

`qrun_genesis_rooted_migration_executor_archives_commits_and_reopens_checkpoint` exercises the consuming API with:

- the QRun v0.5 fee-only wallet-bound test Genesis and one QFP5 block in PFS2;
- a QRA1 history archive and full replay;
- a test External-CAS provider with ML-DSA-65 signed receipts and a QCF1 floor;
- a direct-Store negative attempt with a deliberately wrong Genesis parent commitment, which must return `GenesisCheckpointParentMismatch` without creating an archive, QRCP or QRM1, changing the PFS2 manifest/QCF1 floor, or applying a provider CAS;
- a provider that commits the exact successor but intentionally loses its first CAS response;
- QRM1 recovery and QCF1 advancement to object generation 2;
- verification that the QRA1 archive and QRCP file exist, QRM1/QAP1 are absent after success, and floor/provider records match;
- a fresh verified provider client and reopened floor reopening the checkpoint-rooted PFS2 store at the same height, canonical tip and state root.

This test uses an in-memory provider implementation and disposable local directories. The wrong-parent case checks that the consumed executor leaves its external-CAS successor and local history unmodified before the same fixture runs the valid parent. It is not a test of a remote cloud operator or a production Anchor deployment.

## Validation on this branch

- Focused executor integration test: **1 passed, 0 failed**.
- Full Rust library suite: **1,037 passed, 0 failed** (`cargo test --lib --locked --offline`).
- All-target compile check: **PASS** (`cargo check --all-targets --locked --offline`).
- Rust formatting check: **PASS**.
- `git diff --check`: **PASS**.
- Existing warnings are unrelated unused-import/dead-code/unused-mut warnings in other candidate modules; no compile errors were observed.

The parent permissionless-first PR #118 was independently validated by both exact-head GitHub Actions runs: push [41262530793](https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/41262530793) and pull request [41262546659](https://github.com/hamidnikkhah660-arch/ai-native-l1/actions/runs/41262546659), each completed successfully.

## Explicit limitations

- **First migration only:** this API accepts a Genesis-rooted store and creates the first non-Genesis checkpoint. Repeated checkpoint-to-checkpoint rollover requires a linked multi-segment history/archive design and is not inferred here.
- **No node CLI/startup wiring:** ordinary `qrun_v05_pow_local_node` startup does not invoke this operation automatically. An operator-facing command, signed maintenance authorization, checkpoint output-path policy and restart orchestration remain to be added and reviewed.
- **No production provider:** no AWS account/table/KMS resource, independent provider host, independent administrative/backup domain or production Noise endpoint was provisioned or contacted.
- **No public network:** this does not expose P2P/RPC/TX listeners, change firewall rules or prove multi-host sync/recovery.
- **Mainnet remains disabled:** `QRUN_MAINNET_RELEASE_APPROVED` remains false; Genesis, Network ID, owner identity, supply, consensus/PoW and mint settings are unchanged.

This checkpoint closes one local implementation gap in the initial Genesis-to-checkpoint transaction. It does not close the overall full-history/repeated-rollover, independent-provider or public-network launch gates.
