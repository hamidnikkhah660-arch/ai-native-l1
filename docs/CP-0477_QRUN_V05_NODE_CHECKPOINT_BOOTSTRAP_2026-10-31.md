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
5. For a **new** node data directory only, create the deterministic empty QFP5 PFS2 suffix manifest rooted at the supplied checkpoint. Compare its exact manifest commitment with ECR1 `next_state_digest`. Existing directories are not silently recreated or repaired.
6. Initialize or reopen the separate QCF1 monotonic floor from the ECR1 bootstrap. The regular external-CAS opener then performs its pinned Noise/TCP provider read, verifies the signed receipt and exact manifest digest, and reconciles the floor.
7. Construct the QRun runtime only after verifying the original height-zero Genesis identity and the checkpoint-specific profile fingerprint. A checkpoint-backed replay base is not substituted for the original Genesis identity.
8. Writes continue through the existing external compare-and-swap path; the integration test confirms the signed provider generation and QCF1 object-generation floor advance together, followed by a successful restart.

## Failure behavior and tests

The Windows integration test exercises:

- A wrong parent checkpoint commitment: rejected before local node-store or QCF1-floor creation.
- A wrong QRCP commitment: rejected before local node-store or QCF1-floor creation.
- An ECR1 digest that does not match the deterministic checkpoint-rooted PFS2 manifest: rejected before QCF1 initialization.
- A valid checkpoint with its exact parent and ECR1 manifest anchor: node starts at checkpoint height, mines/submits the next block through the authenticated external-CAS provider, advances the QCF1 floor, and restarts with identical canonical tip and state root.

The CLI parser test verifies the four checkpoint flags are all-or-none, have nonzero/positive values, and cannot be supplied without the full external-CAS pin configuration.

## Explicit limitations

This mode supports a new node bootstrapping from an independently anchored checkpoint **when the provider's generation-zero ECR1 is already provisioned with the exact checkpoint-rooted empty PFS2 manifest digest**.

It does **not** yet implement an atomic transition from an existing provider state/manifest to a new checkpoint-rooted manifest. It does not autonomously rotate checkpoints, rebase the provider's current CAS manifest, accept peer-supplied checkpoints during ordinary sync, or prove full historical recovery across a production multi-operator network. The bounded peer sync path still requires an independently authenticated checkpoint when the peer's trusted base is ahead of local height.

The QRun Mainnet release gate remains disabled. Public mint remains disabled. This change is not evidence of a public Mainnet deployment, independent production provider operations, or a QZXB/USDT market listing.
