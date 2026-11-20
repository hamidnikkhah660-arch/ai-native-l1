# CP-0683 — QFP6 Checkpoint Segment Rollover and Release Capacity Gate

Date: 2026-11-15
Project: AI-NATIVE L1 / QRun / QZXB / QFP6
Branch: feat/cp0600-bootstrap-sync-startup
Repository: D:\Temp\ASUS\QRUN_QFP6_CP0596_20261111
Status: ROOT CAUSE IDENTIFIED; IMPLEMENTATION GATE OPEN; NO PUBLIC NETWORK CHANGE.

## 1. Verified result

After CP-0682 source edits, the following were rerun locally:
- Rust formatting: PASS.
- Anchor Vault module tests: 3/3.
- Exact historical-ancestor/full replay test: 1/1.
- Per-commit anchor/recovery test: 1/1.
- QFP6 node launcher tests: 44/44.
- Release build of `qrun_v06_node`: PASS.

A fresh scratch copy with a copied anchor vault passed vault verification. The Release node verified Q6GA and reached `QFP6 PERMISSIONLESS BASE RUNTIME: STARTING (candidate qualification only)`. It then stopped with `QFP6 in-memory fork archive reached its block limit` when the supervisor attempted to continue mining.

The runtime had reached STARTING; therefore the Genesis-rooted replay and local-vault reconciliation had completed. The failure is the next-block capacity boundary, not a failed replay.

## 2. Root cause

`qrun_v06_pow_fork_choice_candidate.rs` currently defines:
- `MAX_QRUN_V06_FORK_ARCHIVE_BLOCKS = 1_024`
- `MAX_QRUN_V06_FORK_BRANCH_HEIGHT = 1_024`

The local package has 1,025 manifests (generation 0 through 1024) and 1,024 branch files. The bounded in-memory graph has no capacity for the next block.

Checkpoint primitives already exist: canonical checkpoint export, checkpoint-rooted store open APIs, immutable segment directories, and tests for restart/retarget across 1,024-block segments. The current permissionless runtime path still opens the Genesis-rooted store and does not coordinate a segment transition.

## 3. Why a limit increase is not the fix

Raising the cap would only postpone the same failure. A safe transition must preserve:
- independently witnessed checkpoint bytes and checkpoint anchor;
- exact network, profile, Genesis descriptor and consensus fingerprint;
- monotonic global manifest/anchor generation across segments;
- append-before-success ordering in the C: vault;
- deterministic recovery at every interruption point;
- immutable retention of the prior segment.

The current C: vault record binds sequence, network/profile, manifest generation/anchor and previous record digest, but does not yet bind checkpoint anchor or segment identity. The checkpoint-rooted store starts a new local manifest segment independently, so the existing vault's strict consecutive-generation rule cannot simply consume its local generation values.

## 4. Required implementation

1. Define a checkpoint witness record/event and bind the exact checkpoint digest, absolute base height/tip, network/profile/Genesis and consensus identity.
2. Define global generation semantics across segment boundaries without weakening the current append-only vault validation.
3. Add a runtime transition that exports the canonical checkpoint, creates a new immutable segment, validates its base, durably witnesses the transition, then switches the active runtime store.
4. Preserve the previous segment read-only; do not delete or rewrite Genesis history.
5. Specify and test interruption recovery before/after checkpoint write, before/after witness append and before/after active-segment switch.

## 5. Acceptance tests

- Boundary: current 1,024-block history transitions and admits block 1,025.
- Restart: checkpoint segment reopens and reproduces exact tip, state root, cumulative work and target-history tail.
- Anchor: global vault sequence/generation remains monotonic; wrong or stale checkpoint anchors fail closed.
- Fault injection: all transition windows either recover deterministically or stop without modifying evidence.
- Tamper/reorg: wrong checkpoint bytes, profile, Genesis, consensus fingerprint, segment base and invalid reorgs are rejected.
- Release: scratch Release node mines/commits beyond height 1,024, shuts down cleanly and restarts from the new segment.

## 6. Safety state

The original package and real C: vault were not modified by the Release experiment. They remain at 1,025 manifests / 1,024 branches and Vault sequence 1 / generation 1024. Scratch package and scratch vault are separate. No QRun process or TCP 30333 listener remains. Public listener, outbound sync, bootstrap peers, public Testnet and Mainnet authorization remain disabled.

Next milestone: implement checkpoint-segment rollover with durable checkpoint witnessing and global anchor continuity; do not raise the archive cap as a shortcut.

## 7. CP-0683 implementation protocol (design locked before source edits)

### 7.1 Two generation domains

A checkpoint-rooted store has a segment-local manifest generation beginning at zero. The C: anchor vault remains the global monotonic generation authority. Do not compare these counters directly.

For a new segment:
- predecessor_global_generation is the generation at the current C: vault tip before rollover.
- segment_global_generation_base = predecessor_global_generation + 1.
- The checkpoint segment's generation-0 root manifest maps to segment_global_generation_base.
- Every later segment-local manifest generation L maps to global_generation = segment_global_generation_base + L.
- The existing vault manifest_generation field continues to store this global generation. Its anchor field stores the exact manifest anchor for the active segment's corresponding local generation.

The offset is derived only from the independently verified C: witness chain; it must never be inferred from a D: directory name or local manifest.

### 7.2 Rollover ordering

1. Export the canonical checkpoint from the active store. Capture exact checkpoint bytes, checkpoint commitment, absolute base height, canonical tip, state root, cumulative chainwork, network/profile, Genesis descriptor commitment and consensus fingerprint.
2. Create a fresh, inactive, immutable-by-policy segment directory. Open it from the checkpoint using the independently verified Q6PN/profile pin and exact checkpoint commitment. This creates and validates the segment-local generation-0 root manifest. Read back its exact anchor and verify its canonical base state against the exported source.
3. Append a separate hash-chained checkpoint-segment witness under the C: vault. The witness binds the predecessor C: vault sequence/generation/anchor/record digest, exact checkpoint commitment, segment-root manifest anchor, absolute base state, network/profile/Genesis/consensus identity, and previous witness digest. This is a distinct witness sequence; it does not consume a manifest generation.
4. Append the segment-root manifest anchor to the existing C: vault at predecessor_global_generation + 1. This is the first global generation of the new segment and corresponds to local generation zero.
5. Only after the witness and C: root-anchor successor are durable may the runtime switch to the new segment. The latest validated witness plus C: vault tip selects the active segment; a mutable pointer is not a trust source.
6. Keep the previous segment intact and never reopen it as the active writable store after successful rollover.

### 7.3 Crash recovery rules

- Before the checkpoint/root manifest exists: previous segment remains active.
- After checkpoint/root manifest but before C: witness: treat the new directory as an untrusted orphan; do not promote it automatically.
- After witness but before the C: root-anchor successor: verify the witness, exact checkpoint bytes and root manifest, then append exactly the one expected global successor. Any mismatch stops startup.
- After the C: root-anchor successor but before runtime switch: derive the active segment from the latest witness and vault tip; reopen it and verify exact generation/anchor mapping.
- After any post-rollover block commit: map the local commit generation through the witness offset before appending to C: vault. A successful runtime commit is not reported until the mapped global successor is durably present.
- A vault tip behind the witness-derived segment generation, ahead by more than one unanchored successor, or carrying a different manifest anchor is a hard failure requiring audit.

### 7.4 Witness-ledger requirements

The witness ledger is a separate append-only subdirectory under the existing C: vault so legacy CP-0681/0682 anchor records are not rewritten. Each witness must be create-new, bounded, hash-chained, identity-bound and validated on every vault open. It must reference a real prior C: record by sequence and record digest. Sequence gaps, duplicate/conflicting segment witnesses, symlinks, malformed JSON, wrong network/profile, stale predecessor records, wrong checkpoint bytes, wrong segment root, or wrong consensus identity fail closed.

### 7.5 Acceptance gates

In addition to Section 5:
- Prove local generation 0 maps to predecessor global generation + 1 and local generation 1 maps to predecessor global generation + 2.
- Inject process termination after every step in 7.2 and verify the recovery rules in 7.3.
- Verify the previous segment's manifest and branch-file hashes remain unchanged after rollover and subsequent commits.
- Verify the checkpoint's absolute base height/tip/state root/chainwork and target-history tail survive restart exactly.
- Verify the runtime's 1,025th absolute block is admitted in Release without changing either 1,024 capacity constant.


## 8. CP-0683 implementation status (2026-11-15)

### 8.1 Implemented locally

The checkpoint-segment witness and rollover path is now implemented in the dirty working tree:

- `qrun_v06_local_anchor_vault_candidate.rs`
  - Adds the append-only `checkpoint-segment-witnesses` ledger.
  - Each witness is bounded, create-new, SHA-256 hash chained, network/profile bound, and references the exact predecessor C: vault record sequence, global generation, manifest anchor and record digest.
  - Vault open validates the complete witness sequence and rejects gaps, symlinks, tampering, profile mismatch and predecessor mismatch.
  - Adds `append_checkpoint_segment_witness`, `reconcile_checkpoint_segment_root` and `append_segment_successor`.
  - Global mapping: `global_generation = predecessor_global_generation + 1 + segment_local_generation`.

- `qrun_v06_pow_fork_store_candidate.rs`
  - Adds `manifest_anchor_at_generation`.
  - Adds checkpoint-store reopen from an exact trusted manifest ancestor, while still replaying the complete later local manifest/branch history.
  - Exposes the canonical checkpoint filename for the launcher.

- `qrun_v06_permissionless_runtime_candidate.rs`
  - Adds checkpoint-rooted startup against the latest C: witness.
  - Adds `rotate_to_checkpoint_segment`: export and self-validate the canonical checkpoint, create a fresh segment, append the witness, publish the root anchor, then switch the active store.
  - Retains the prior segment writer lock for the active Runtime lifetime.
  - Maps each post-rollover local commit into the global C: vault generation.
  - Adds automatic rollover before a submission that would exceed the 1,024-block segment archive capacity.
  - Rollover fails closed if noncanonical/competing branches remain; a canonical-only checkpoint is not allowed to discard fork-choice candidates.

- `bin/qrun_v06_node_runtime_launch/permissionless.rs`
  - When a validated witness exists, startup selects the segment by witness sequence, reads the bounded checkpoint file, and opens the checkpoint-rooted Runtime.
  - Configures automatic rollover only on the local C: vault path. The Q6TS/Q6QA-authorized quote-asset path is not silently treated as supported by this rollover implementation.

### 8.2 Verification results

- `cargo fmt --check`: PASS.
- Checkpoint-segment/store suite: 5 passed, 0 failed. Includes exact ancestor replay and the existing 1,024-segment / 2,016-retarget boundary test.
- Local anchor-vault suite: 5 passed, 0 failed. Includes witness tampering rejection and witness-before-root recovery.
- End-to-end Runtime test: 1 passed, 0 failed. It creates a 1,024-block Genesis-rooted history, submits the 1,025th absolute block through automatic rollover, verifies the global C: generation mapping, simulates a D: segment commit without its C: append, then reopens and catches up exactly one missing global successor.
- Release node build `cargo build --release --bin qrun_v06_node`: PASS after launcher integration. Existing unrelated warnings remain.

### 8.3 Exact demonstrated boundary

The integration test proves the 1,024 -> 1,025 transition without changing either 1,024 capacity constant:
- Before rollover: Genesis-rooted D: local/global generation 1,024.
- New checkpoint segment root: global generation 1,025, segment-local generation 0.
- Absolute block 1,025: segment-local generation 1, global generation 1,026.
- Simulated unanchored D: block 1,026: restart replays the segment and appends exactly global generation 1,027 to C:.

### 8.4 Still not qualified

- The test uses deterministic restart/reopen simulations; process-kill fault injection at every individual filesystem ordering point is still outstanding.
- Windows directory-entry durability and power-loss semantics for the separate witness ledger still require dedicated crash/fault qualification; do not describe the whole sequence as power-loss proven yet.
- At the time this section was recorded, the Release executable was built but the full 1,025th-block launcher scenario had not yet been run. Its later execution and recovery are recorded in Section 10.
- No real C: Vault, production package, live listener, firewall rule, bootstrap peer or public-network authorization was changed by these tests.
- Public Testnet and Mainnet remain NO-GO pending the remaining independent network, consensus, identity and operational gates.
- No commit or push was performed.


## 9. Revalidation after CP-0683 integration (2026-11-15)

### 9.1 Confirmed passing checks

- `cargo fmt --manifest-path src/native/pow_bench/Cargo.toml -- --check`: PASS.
- `cargo test --lib qrun_v06_local_anchor_vault_candidate --locked --offline -j 1`: 5 passed, 0 failed.
- `cargo test --lib qrun_v06_pow_fork_store_candidate --locked --offline -j 1 -- --test-threads=1`: 28 passed, 0 failed.
- Both Store tests that failed during the first parallel test invocation were rerun individually and passed:
  - `checkpoint_segment_ambiguous_commit_recovers_from_checkpoint_base`
  - `cp0528_monetary_state_survives_durable_checkpoint_rollover_and_restart`
- The first parallel Store run reported 26 passed / 2 failed, with `WriterLockHeld` and a missing temporary path. Root cause was the test-only `TestDir::new` naming scheme: process ID plus Windows `SystemTime` nanoseconds could collide between concurrent tests. It now adds a process-local `AtomicU64` suffix and uses exclusive `create_dir`.
- Re-ran the complete Store suite under default parallel scheduling after this test-fixture fix: 28 passed, 0 failed. The `hard_process_crash_at_durable_commit_boundaries_is_reconciled_or_fails_closed` test also passed in this run (98.46 seconds for the test suite).
- `cargo test --bin qrun_v06_node --locked --offline -j 1`: 44 passed, 0 failed.
- The targeted end-to-end automatic 1,024 -> 1,025 runtime rollover/recovery test: 1 passed, 0 failed.
- `cargo build --release --bin qrun_v06_node`: PASS, exit code 0. Nine existing warnings; no build failure.
- `git diff --check`: PASS, exit code 0. Git emitted only LF/CRLF normalization warnings.
 
### 9.2 Read-only owner-package baseline before Release rollover (historical; later superseded by Section 10)

- Python owner-vault verification: PASS.
- PowerShell runner `-VerifyOnly`: PASS.
- Actual C: vault remains sequence 1, global generation 1024.
- Actual C: record digest remains `6543b518a53a3c66979f369484002d16f7231b9d2b51362ad754ccde5afe4ab4`.
- Actual trusted anchor remains `652ad475a0646e285329d690f493b9b10bf89d44f6ff1cf381c96b7d83ed25b0`.
- Canonical package remains 1,025 manifest files and 1,024 branch files.
- No `qrun_v06_node` process and no TCP 30333 listener were present after validation.
- Both capacity constants remain exactly 1,024.

### 9.3 Remaining Release qualification

At the time of this revalidation, the Release binary was built and the debug end-to-end test proved the absolute 1,025th-block transition, while the full Release launcher scenario remained outstanding. Section 10 records its later execution and recovery. Process-kill injection at each rollover ordering boundary and Windows power-loss/directory-entry durability qualification remain outstanding. No live package or real Vault mutation is authorized by this checkpoint.

### 9.4 Website publication status (read-only GitHub check)

- PR #195 remains OPEN and UNMERGED: https://github.com/hamidnikkhah660-arch/ai-native-l1/pull/195
- PR head remains `3168c04a401874febaeeebf59afc023627400aff`; three GitHub checks are completed/successful.
- No requested reviewers and no submitted reviews are present.
- The public `main` branch still serves the legacy 10B economics copy on the homepage/economics page. The PR contains the CP-0651 7B candidate economics and the correct explicit non-Mainnet/no-live-market boundary, but it has not been published to `main`.
- No reviewer was invented, no review request was sent, and no merge was performed.

### 9.5 Change-control

No commit, push, merge, real C: Vault write, canonical runtime start, firewall change, public listener, bootstrap peer or public-network authorization was performed during this revalidation.


## 10. Release rollover execution, recovery and verifier integration (2026-11-15)

### 10.1 Release execution result and incident disclosure

The Release `qrun_v06_node.exe --permissionless-run` was executed from the 1,024-generation candidate state. It successfully created checkpoint segment witness sequence 1, published the segment root at global generation 1,025, and continued committing into the new segment. The resulting first-run state was:
- Base Genesis-rooted data: 1,025 manifests / 1,024 branches (unchanged).
- Segment 1: 164 manifests (local generations 0..163) and 163 branches.
- C: Vault: 165 records, global generation 1,188.
- Witness ledger: one validated checkpoint-segment witness, bound to predecessor record sequence 1 / generation 1,024.
- Segment tip maps exactly: global generation = 1,024 + 1 + 163 = 1,188.

Incident: the first disposable Release config placed `trusted_manifest_anchor_vault_path` at the JSON top level. The launcher passes the nested `permissionless_runtime` object to `local_anchor_vault_directory`, so that test-only override was ignored and the first run used the real default C: Vault. This was an execution-configuration error. The Node was stopped; no old Vault record was deleted or rewritten. The actual C: Vault now has sequence 165 / generation 1,188 and is intentionally retained append-only.

The generated D: segment was initially in the disposable package. A second Release restart was performed against a copy of the C: Vault with the override correctly placed inside `permissionless_runtime`; it reopened the witnessed segment and reached the candidate-runtime STARTING/listener state. Additional mining on disposable copies was stopped and preserved separately.

### 10.2 Canonical package reconciliation

The exact D: segment state corresponding to the actual C: Vault generation 1,188 was reconstructed without guessing:
- The first 164 segment manifests (local 0..163) were selected.
- 207 branch files from the later disposable segment were intersected with the branch set after a successful open/replay; exactly 163 common branch files remained, and all 163 SHA-256 values matched.
- The exact 164-manifest / 163-branch segment was validated by the Release launcher against a copied 165-record Vault at generation 1,188; startup reached the candidate-runtime STARTING state.
- That exact segment was then added to the canonical package at `runtime/after-fix/data.checkpoint-segments/segment-00000000000000000001`.
- The earlier ahead-of-tip overlay was moved, not deleted, to `D:\Temp\QFP6_CP0683_CANONICAL_SEGMENT_OVERLAY_1200` for preservation.
- Canonical package base data remains 1,025 manifests / 1,024 branches. Canonical segment data is 164 manifests / 163 branches. Actual C: Vault remains 165 records / global generation 1,188.
- No active Node or TCP 30333 listener remains.

### 10.3 Python Vault verifier now understands checkpoint segments

`tools/qfp6_anchor_vault.py` now verifies the witnessed segmented layout instead of comparing the C: high-water only with the Genesis-rooted manifest directory. It checks:
- Witness filename/sequence continuity, JSON bounds, schema, network/profile identity, previous-witness hash chain and exact Rust-compatible witness digest.
- Exact predecessor C: record sequence, generation, anchor and record digest for every witness.
- Q6CP checkpoint magic/version, bounded size, checksum, domain-separated commitment, network/profile, consensus fingerprint, Genesis descriptor, base height, tip hash, state root and cumulative work against the witness.
- Segment directory identity, contiguous local manifest generations, generation-zero root anchor, bounded regular manifest/branch files, and each local-to-global generation/anchor mapping against its exact C: Vault record.
- The final segment tip must equal the final C: Vault high-water exactly. Legacy non-segmented packages retain their original verification path.

### 10.4 Verification after reconciliation

- Python syntax compilation: PASS.
- Canonical package + actual C: Vault verification: PASS; sequence 165, global generation 1,188, anchor `b4dd74d78094995675ebf16b73db1c0eb40cfa13ae8ef6bf6fd3275ba10ede64`.
- Disposable later segment state + its copied Vault at generation 1,208: PASS.
- Legacy non-segmented package + original one-record Vault at generation 1,024: PASS.
- Tampered witness digest: rejected, exit 2.
- Tampered segment-local manifest: rejected because its local/global C: record mapping no longer matches, exit 2.
- `qfp6-local-run-and-rotate.ps1 -VerifyOnly`: PASS against the canonical package and actual C: Vault.
- `cargo fmt --check`: PASS.
- `git diff --check`: PASS (only LF/CRLF normalization warnings).

### 10.5 Remaining qualification and change control

- Full process-kill injection at every individual rollover ordering boundary and Windows power-loss/directory-entry durability testing remain outstanding.
- The Python verifier now validates the witness/manifest/anchor mapping; full checkpoint semantic validation remains authoritative in the Rust Release launcher.
- The real C: Vault is append-only at generation 1,188. Do not attempt to reset it to 1,024. The canonical D: package now contains the matching witnessed segment.
- Public Testnet and Mainnet remain NO-GO. This remains a local candidate-only runtime with loopback listener, no bootstrap peers and no external quote-asset authorization.
- No commit, push or merge was performed.


## 11. Final verifier hardening (2026-11-15)

- `command_init` now refuses to provision a fresh Vault from a package that already contains checkpoint-segment data. This prevents silently re-rooting a segmented history at the Genesis-only manifest tip.
- Negative test: `init` on the canonical segmented package returned exit code 2 and did not create the requested new Vault directory.
- Final `py_compile`, canonical `verify`, and PowerShell runner `-VerifyOnly` all passed against the actual C: Vault and canonical D: segment at global generation 1,188.
- No Node process or TCP 30333 listener remains. No commit, push or merge was performed.

