# CP-0479 — QRun v0.5 Live External-CAS Checkpoint Manifest Rebase Design

Date: 2026-10-31

Status: **Design proposal only; not implemented, not CI-validated as code, and not a Mainnet approval.** This document specifies a conservative migration from an already initialized Genesis-rooted QFP5 External-CAS provider manifest to a checkpoint-rooted QFP5 suffix manifest. It deliberately does not claim that current checkpoint bootstrap performs this transition.

## 1. Decision and safety boundary

The current node checkpoint mode bootstraps a new local store only when the provider's generation-zero ECR1 already commits to the exact empty checkpoint-rooted PFS2 manifest. It does not rebase an initialized provider whose ECR1 and PFS2 manifest already refer to a Genesis-rooted archive.

The first migration implementation MUST be an offline, explicitly requested maintenance operation. It must not run implicitly during ordinary node startup, peer sync, block import, or mining. It must not silently reset or reinitialize ECR1/QCF1, and it must not turn a failed migration into local-only operation.

The migration is a **storage-root transition at an unchanged canonical chain tip**. It does not create blocks, alter balances, change the 10B supply, change Network ID or Genesis, change consensus parameters, or activate Mainnet.

## 2. Conservative v1 acceptance rule: exact current tip only

A QRCP checksum and externally retained QRCP commitment prove the identity of the supplied checkpoint bytes. A parent-checkpoint commitment proves only the declared checkpoint-link value. Neither fact, by itself, proves that the checkpoint descends from the currently active provider's canonical history.

Therefore v1 MUST accept only a checkpoint that independently replays and exactly matches the currently opened canonical store at the instant migration is prepared. The following values must all match:

- Network ID, original wallet-bound Genesis commitment, owner and QRun v0.5 fee-only consensus profile.
- Absolute height and canonical consensus tip digest.
- Ledger tip hash, state root and total supply.
- Cumulative chainwork.
- Canonical target-history checkpoint, including logical height, start height, entry order, target values and timestamps.
- The checkpoint's parent-checkpoint commitment against the operator's separately retained expected parent commitment.

The checkpoint height MUST equal the current canonical height. The checkpoint tip MUST equal the current canonical tip. A checkpoint ahead of or behind the current tip is rejected in v1. A future checkpoint may be supported only by a later design that proves the complete intervening canonical ancestry and reconciles it against the provider and independent floor. No caller-supplied height, checksum or parent hash may substitute for that proof.

This exact-tip restriction makes the first migration a re-rooting of already validated state, not a way to select an alternative chain or skip unvalidated history.

## 3. Preserve pre-checkpoint history; do not silently prune

A checkpoint-rooted PFS2 suffix contains the checkpoint base and post-checkpoint blocks. The existing PFS2 branch catalog may also contain pre-checkpoint blocks and noncanonical branches. Replacing the active manifest can cause the existing orphan-cleanup path to remove branch files no longer listed by the new suffix manifest.

Before any provider CAS, v1 MUST create and verify a deterministic history archive of the complete old PFS2 view:

1. Copy the exact old PFS2 manifest and every branch file referenced by its digest catalog into a dedicated archive location outside the active PFS2 store directory.
2. Validate each copied file as a regular non-symlink file; recompute its canonical block/PoW digest and require it to match its filename and old manifest entry.
3. Verify that the archive contains every referenced digest exactly once, with no missing entries, duplicates, unlisted files or unexpected subdirectories.
4. Flush file contents and directory metadata; publish the completed archive atomically under a deterministic identifier derived from the old manifest commitment.
5. Compute an archive commitment over a domain-separated canonical descriptor containing the exact old manifest bytes and sorted (block_digest, file_length, file_content_digest) entries.

The QRun node's ordinary active-store cleanup must never traverse or delete the archive. Archive integrity must be independently rechecked during migration recovery. The archive is retained after migration; deletion or external archival is a separate, explicit retention decision. A same-host archive is useful for local history preservation but is not an independent availability or anti-rollback domain. Before a public release, operators must replicate and verify it in a separately administered storage domain.

If a complete verified archive cannot be prepared, migration MUST stop before the provider CAS. V1 does not provide an implicit "prune history and continue" mode.

## 4. New migration journal; keep QAP1 semantics unchanged

Do not overload QAP1. QAP1 records one ordinary block-manifest CAS commit and its exact successor. A checkpoint rebase changes the replay base and profile fingerprint, so it needs a distinct bounded journal, provisionally named **QRM1** (QRun Rebase Migration), with its own version and domain-separated checksum.

The QRM1 record must bind at least:

- The exact previous ECR1 record and its digest.
- The exact next ECR1 successor record, including operation ID and request digest.
- The previous and next provider object generations.
- The exact old PFS2 manifest bytes or an equally strong exact commitment, and the exact new checkpoint-rooted PFS2 manifest bytes.
- The exact QRCP bytes, bounded by MAX_QRCP_BYTES, so recovery does not depend on a mutable operator path remaining unchanged; also bind its commitment, parent-checkpoint commitment, minimum accepted height, checkpoint height, consensus tip digest, ledger tip hash, state root, supply, cumulative work, base consensus-profile fingerprint and derived checkpoint-store profile fingerprint.
- A hard QRM1 total-size bound derived from the maximum QRCP and the two maximum PFS2 manifest sizes, plus fixed metadata; all variable lengths must be checked before allocation.
- The old-history archive commitment and deterministic archive identifier.
- The unchanged provider, Network ID, original Genesis commitment, receipt-key pin domain and owner identity needed to recompute the expected QRun Genesis.
- A format version, bounded lengths and canonical field ordering.

The encoder/decoder must reject truncation, trailing bytes, unsupported versions, unknown flags, oversized fields, noncanonical order, wrong domains, inconsistent record links, mismatched manifest commitments, mismatched checkpoint metadata and invalid checksums before touching provider or floor state. The checksum is corruption detection, not authentication; trust still comes from the independently pinned QRCP commitment, signed ECR1/ECRS observations, and separately retained QCF1 floor.

A QRM1 migration journal and a QAP1 block-commit journal MUST NOT coexist in the same active store. Migration holds an exclusive maintenance lock and blocks block submission/import for its duration.

## 5. Prepare and commit order

All preparation is performed while the node is stopped or in a strict maintenance state that prevents concurrent writes:

1. Open the existing Genesis-rooted PFS2 store and verify its complete archive using the configured production candidate rules.
2. Open QCF1 and obtain its exact trusted ECR1 record and minimum provider object generation. Require the local PFS2 manifest anchor to equal that record's state digest.
3. Perform a fresh signed provider read. Require the provider record and object generation to equal the floor exactly; v1 migration does not reconcile an unobserved provider successor as part of preparation.
4. Decode the QRCP against the original Network ID, Genesis, consensus profile, expected commitment, minimum height and expected parent commitment. Restore/replay it and compare every field in Section 2 against the current canonical chain.
5. Build the deterministic checkpoint-rooted empty QFP5 suffix and its PFS2 manifest. The new manifest's checkpoint-specific profile fingerprint and checkpoint-rooted base tip must be derived by the existing canonical constructors, not caller supplied.
6. Build, fsync and verify the history archive from Section 3.
7. Construct the exact one-generation ECR1 successor. Its previous_record_digest and previous_state_digest must bind the old ECR1; its next_state_digest must equal the commitment of the new PFS2 manifest. Bind the migration operation ID and request digest using the existing CAS request contract.
8. Write and fsync QRM1 before sending any provider write. The old active PFS2 manifest remains installed.
9. Execute exactly one atomic server-side provider compare-and-swap from the exact old ECR1/object generation to the exact new successor. A filesystem read followed by an unconditional write is not acceptable.
10. Verify the signed CAS receipt. If the response is ambiguous, use a fresh challenged signed provider read and accept only the exact old ECR1 or the exact prepared successor.
11. Advance QCF1 from the exact previous record/object generation to the exact successor/object generation. The advance must be idempotent if QCF1 already equals the successor and must reject any other generation or digest.
12. Atomically install the exact new PFS2 manifest. Do not synthesize a replacement manifest during recovery.
13. Reopen the checkpoint-rooted store through the same strict constructor, verify the new local manifest anchor, checkpoint profile, canonical base tip, archive commitment, signed provider observation and QCF1 snapshot all agree.
14. Only after all checks succeed, remove QRM1 and fsync the active store directory. The verified history archive remains intact.

The ECR1 generation and provider object generation each advance exactly once for this migration. No generation jump, second CAS, fallback provider or implicit floor initialization is permitted.

## 6. Crash-recovery decision table

Recovery must classify durable evidence, not infer intent from file presence or process exit codes. It must decode QRM1, verify the QRCP and archive commitments, verify original Genesis and pin bindings, then obtain a fresh signed provider read and a QCF1 snapshot.

| Provider signed record | QCF1 floor | Active PFS2 manifest | Permitted recovery |
|---|---|---|---|
| Exact old record | Exact old record | Exact old manifest | Migration did not commit. Abort the prepared migration, retain the old store/archive, and remove QRM1 only after all old-state checks pass. |
| Exact new successor | Exact old record | Exact old manifest | Provider committed. Advance QCF1 to the exact successor, then install the exact new manifest from QRM1. |
| Exact new successor | Exact new successor | Exact old manifest | Floor committed. Verify the exact successor and install the exact new manifest from QRM1. |
| Exact new successor | Exact new successor | Exact new manifest | Verify/open the checkpoint-rooted store, revalidate archive and all identities, then remove QRM1. |
| Exact new successor | Exact old record | Exact new manifest | This is impossible under the required floor-before-manifest order. Fail closed and quarantine; do not repair this mixed state. |
| Any other record, skipped generation, conflicting digest, stale checkpoint, missing/corrupt QRM1, mismatched archive, old provider with a new floor, or impossible mixed state | Any | Any | Fail closed and quarantine. Never roll back the floor, invent an intermediate record, recreate a generation-zero floor, or replace the local manifest with a guessed value. |

The exact-old/exact-old/exact-old recovery may abort because the provider CAS is the sole remote commit point. The exact-new recovery paths may finish only the one successor encoded in QRM1. If QCF1 is already at the successor, reconciliation is idempotent; if it is ahead by anything else, migration is rejected.

## 7. Required implementation and adversarial tests

No migration code may be enabled until tests cover all of the following:

- Exact-tip acceptance and mismatch rejection for height, consensus tip, ledger tip, state root, supply, cumulative work and every target-history entry.
- Wrong Network ID, Genesis, owner, profile, checkpoint commitment and parent-checkpoint commitment.
- Checkpoints below/above the current tip and checkpoints with a valid checksum but unrelated ancestry.
- Complete archive creation, every referenced branch copied, wrong filename digest, missing/extra/duplicate file, symlink, non-regular file, truncated file, archive tampering and archive path overlap with active PFS2/QCF1/provider directories.
- QRM1 canonical codec, bounded decoding, reserved fields, checksum, exact old/new manifest binding and exact ECR1 successor binding.
- Concurrent writer/CAS conflict, stale object generation, signed rollback, equivocation, skipped generation, replayed receipt, ambiguous/lost CAS response and signer failure after provider commit.
- Real process termination after archive publication, QRM1 fsync, provider CAS, receipt verification, QCF1 advance, PFS2 manifest replacement and before QRM1 deletion.
- Recovery at every crash point must reach only the exact old state or exact new state; all other states must fail closed.
- Restart through the actual node CLI, with the original Genesis identity preserved and no fallback to the local-only store.
- Windows, macOS and Linux filesystem replacement/directory-sync semantics, including documented platform limitations.

The migration test provider may run on loopback, but that only validates protocol/state-machine correctness. Production qualification still requires a separately operated atomic provider, an off-host anti-rollback floor, independent multi-host sync/reorg/restart tests and an independent security review.

## 8. Explicit non-goals and release gates

This proposal does not deploy AWS/KMS, provision a cloud provider, expose public sockets, alter firewall rules, enable public mint, change issuance, or set QRUN_MAINNET_RELEASE_APPROVED=true.

A successful local migration test would prove only that the code can re-root one already validated current tip while preserving its prior archive and recovering across the enumerated local crash boundaries. It would not prove provider/operator independence, whole-host rollback resistance, public reachability, full-history verification by an independent node, production consensus calibration, or market liquidity.

The live-provider manifest rebase remains **not implemented** until the QRM1 codec, migration transaction, archive retention, recovery matrix and exact-head CI are all complete.
