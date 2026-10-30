# CP-0477 — QRun v0.5 Node Checkpoint Bootstrap

Date: 2026-10-31

## Status

Implemented in the checkpoint-recovery working branch and covered by the Windows node integration test. This is a **checkpoint bootstrap for a new local node store**, not a live provider manifest rebase/rollover and not a Mainnet release approval.

## Startup trust inputs

The optional external-CAS checkpoint mode requires all four operator-supplied values:

- `--external-cas-checkpoint-file`: bounded QRCP regular file; symbolic links and empty/oversized/non-regular files are rejected.
- `--external-cas-checkpoint-commitment-hex`: exact independently retained commitment to the QRCP bytes.
- `--external-cas-checkpoint-min-height`: positive minimum checkpoint height.
- `--external-cas-checkpoint-parent-commitment-hex`: exact independently retained parent checkpoint commitment.

These options are all-or-none and are accepted only with the complete external-CAS provider pin, ECR1 bootstrap, receipt key, Noise credentials, and separate QCF1 floor configuration. Partial or zero trust tuples fail during CLI parsing.

## Startup sequence

1. Recompute the wallet-bound height-zero Genesis from the configured Network ID and owner. Require its commitment to equal the pinned external-CAS Genesis.
2. Read the QRCP using a bounded, non-symlink regular-file check.
3. Validate QRCP checksum, exact commitment, network, Genesis, consensus profile, supply, state metadata, target-history height, minimum height, and independently supplied parent commitment.
4. Only after QRCP validation, read and validate the external-CAS ECR1 bootstrap and remaining receipt/Noise configuration.
5. For a new node directory with no pre-existing QCF1 floor, create the deterministic empty QFP5 PFS2 suffix manifest rooted at the supplied checkpoint and compare its exact manifest commitment with the generation-zero ECR1 `next_state_digest`. If a failed first boot left only that empty manifest, a retry must still match it to ECR1 before any floor initialization.
6. If QCF1 does not exist but a PFS2 directory remains from a failed first boot, require its manifest to match the generation-zero ECR1 anchor before initializing QCF1. Once QCF1 exists, do not pre-stage or compare a potentially newer PFS2 manifest to the old ECR1 digest. ECR1 is never rewritten after later CAS commits.
7. With an existing QCF1 floor, hand the validated QRCP, floor, and local store to the external-CAS opener. A QAP1 journal is accepted only when its previous or next ECR1 record equals the independently retained QCF1 record; the fresh signed provider read may show only that record or its exact one-generation successor. If recovery proves the successor, its digest becomes the manifest anchor for this startup, and the floor is reconciled only after the exact local manifest is opened. This handles crashes before or after floor advancement without permitting a jump or rollback. If QCF1 exists while the PFS2 directory/manifest is missing and no valid pending journal can restore it, startup fails closed rather than creating a new empty suffix.
8. On first boot, initialize QCF1 from the generation-zero ECR1 only after the staged empty PFS2 manifest matches it. On restart, reopen the existing floor; never reinitialize it from ECR1 or roll its digest backward.
9. Construct the QRun runtime only after verifying the original height-zero Genesis identity and the checkpoint-specific profile fingerprint. A checkpoint-backed replay base is not substituted for the original Genesis identity.
10. Writes continue through the existing external compare-and-swap path; the integration test confirms the signed provider generation and QCF1 object-generation floor advance together, followed by a successful restart.

## Failure behavior and tests

The Windows integration test exercises:

- A wrong parent checkpoint commitment: rejected before local node-store or QCF1-floor creation.
- A wrong QRCP commitment: rejected before local node-store or QCF1-floor creation.
- An ECR1 digest that does not match the deterministic checkpoint-rooted PFS2 manifest: rejected before QCF1 initialization.
- Retrying the same bad ECR1 against the already staged empty manifest: rejected again without creating QCF1; restoring the correct ECR1 then permits first boot.
- A valid checkpoint with its exact parent and ECR1 manifest anchor: node starts at checkpoint height, mines/submits the next block through the authenticated external-CAS provider, advances the QCF1 floor, and restarts with identical canonical tip and state root.

The shared QFP5 external-CAS store regression separately simulates a crash after the provider CAS and QCF1 floor have advanced but before the local PFS2 manifest is published. The QAP1 journal installs only its exact signed successor, the independent floor reconciles to that record, and reopening exposes the recovered canonical state.

The wallet-bound checkpoint-specific regression also simulates a later CAS successor committed at the provider while QCF1 and PFS2 still name the predecessor. Restart accepts only the exact QAP1 successor linked to the independent floor, installs its manifest, reconciles QCF1, and reopens at the recovered canonical height and state root. It also replays the recovery step in isolation and stops after PFS2 publication but before QCF1 reconciliation: QAP1 must remain present, must match the exact published manifest byte-for-byte, and QCF1 must remain on the predecessor. A second restart then repeats the signed provider read, reconciles QCF1, and only afterward removes QAP1. The directory cleanup path allows this one retained journal only when its decoded next-state digest and embedded manifest exactly match the recovered PFS2 manifest. The regression also simulates a crash after QCF1 has advanced but before QAP1 deletion; a further restart must treat the already-advanced floor idempotently, verify the same signed successor, and then remove the exact retained journal.

The CLI parser test verifies the four checkpoint flags are all-or-none, have nonzero/positive values, and cannot be supplied without the full external-CAS pin configuration.

## Explicit limitations

This mode supports a new node bootstrapping from an independently anchored checkpoint **when the provider's generation-zero ECR1 is already provisioned with the exact checkpoint-rooted empty PFS2 manifest digest**.

It does **not** yet implement an atomic transition from an existing provider state/manifest to a new checkpoint-rooted manifest. It does not autonomously rotate checkpoints, rebase the provider's current CAS manifest, accept peer-supplied checkpoints during ordinary sync, or prove full historical recovery across a production multi-operator network. The bounded peer sync path still requires an independently authenticated checkpoint when the peer's trusted base is ahead of local height.

The QRun Mainnet release gate remains disabled. Public mint remains disabled. This change is not evidence of a public Mainnet deployment, independent production provider operations, or a QZXB/USDT market listing.
