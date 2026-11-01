# CP-0392 — PFM5 durable checkpoint-rooted branch store

Date: 2026-11-01

## Goal

Add a bounded local durable store for the PFM5/PCP4 checkpoint-rooted PMT4 fork-choice candidate. This closes the gap between the PFM5 replay/rebase primitives from CP-0390/CP-0391 and a restartable local archive.

## Storage layout

A dedicated store directory contains:
- checkpoint-forkstore.pcp4: immutable canonical PCP4 checkpoint bytes;
- checkpoint-forkstore.pfm5: the currently published canonical PFM5 manifest;
- checkpoint-branch-<lowercase PoW digest>.pmt4: content-addressed PMT4 branch envelopes;
- checkpoint-forkstore.lock: exclusive single-writer OS lock.

PCP4 is synced before the generation-1 PFM5 manifest is atomically published. A retry after a process interruption between those writes is accepted only when the existing checkpoint is byte-for-byte identical to the requested checkpoint. Branch envelopes are synced before the successor manifest is published. On reopen, every manifest-listed branch is loaded, its PoW digest and network are checked, and the full retained graph is replayed from the PCP4 checkpoint. Orphan branch files and stale manifest temp files are removed only after successful replay.

Limits are inherited from the PFM5/PMT4 codec and fork archive: manifest/checkpoint/envelope byte limits, at most 4,096 retained branch envelopes, and at most 64 MiB aggregate envelope bytes. Store entry names are canonical and symlinks/non-files are rejected before reading the store.

## API and trust boundary

PrivateTestnetPfm5ForkStoreCandidate currently exposes:
- initialize: initialize a local unanchored candidate store;
- open_local_unanchored: reopen with complete local validation but no rollback guarantee;
- open_with_manifest_anchor: compare local manifest bytes with an exact commitment supplied by the caller after an independent authenticated read;
- manifest_anchor: verify the local checkpoint, manifest, and all retained envelope bytes against the in-memory replayed archive;
- submit_local: validate on a cloned fork-choice object, persist new branch bytes, and atomically publish the next PFM5 manifest.

Opening with a manifest anchor does not perform provider I/O or verify a provider receipt; it only matches the exact supplied commitment. The caller remains responsible for obtaining that value from a separately verified source and for keeping generation/checkpoint floors outside the local rollback domain. Local-only submit is disabled for stores opened with an external anchor.

## Crash/recovery and regression tests

The module tests cover:
- initialization, local branch submit, generation advancement, close/reopen, deterministic replay, and expected-manifest-anchor match/mismatch;
- rejecting local-only writes after opening against an external anchor;
- rejecting corrupted referenced branch bytes before replay;
- refusing to initialize in a directory containing unrelated operator data without modifying that data;
- rejecting symlinked and hard-linked writer-lock entries before initialization or reopen can write their PID header, while preserving external target bytes;
- retrying initialization after the PCP4 checkpoint was durably written but before the PFM5 manifest was published;
- cleaning an unreferenced branch file and stale manifest temp file after successful replay/reopen.

## Validation

Observed on the Windows development machine from `src/native/pow_bench`:

- CP-0392 module tests: 8 passed, 0 failed, including symlinked and hard-linked writer-lock rejection before open and initialize.
- Complete library suite: `cargo test --lib --locked --offline` ? 786 passed, 0 failed.
- `cargo fmt --all -- --check` ? passed.
- `git diff --check` ? passed.

These are local candidate tests. They do not establish provider interoperability, independent-host convergence, public Devnet readiness, or production security.

## Explicitly not implemented

This candidate module is not wired into private_testnet_node or any public/devnet runtime. It does not publish PFM5 manifests or PMT4 envelopes to a remote object store. It does not write a PFM5 record through VerifiedExternalCasClient, provide a cross-host blob transport, or close a two-host stale-writer race. A CAS record that commits a PFM5 manifest hash alone cannot make the referenced checkpoint and PMT4 envelopes available to another host.

The next bounded step must define immutable remote object publication/fetch semantics for the manifest, checkpoint and every referenced envelope, then bind an exact PFM5 manifest commitment into the existing External-CAS receipt protocol. Crash windows, CAS conflict/rebase, lost replies, provider object-generation floors, and cross-host replays must be tested before runtime wiring.

No consensus profile, Genesis, network identity, PoW or issuance policy is changed. No merge, deployment, production/mainnet approval, live provider transaction, or QZXB trade is part of CP-0392.
