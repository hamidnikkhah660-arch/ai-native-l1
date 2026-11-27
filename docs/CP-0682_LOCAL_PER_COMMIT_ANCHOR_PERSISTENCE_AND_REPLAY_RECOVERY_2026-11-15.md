# CP-0682 - Per-Commit Local Anchor Persistence and One-Generation Replay Recovery

Date: 2026-11-15
Project: AI-NATIVE L1 / QRun / QZXB / QFP6
Branch: feat/cp0600-bootstrap-sync-startup
Repository: D:\Temp\ASUS\QRUN_QFP6_CP0596_20261111
Supersedes the operational gaps in CP-0681; CP-0681 remains the historical record of the initial vault rollout.

Status: CODE PATH INTEGRATED; UNIT / LAUNCHER / RUNTIME RECOVERY TESTS PASS; RELEASE BUILD PASS; SCRATCH RELEASE REACHED RUNTIME STARTING BUT MINING STOPPED AT THE 1,024-BLOCK ARCHIVE CAP; LIVE PACKAGE AND REAL C: VAULT LEFT UNCHANGED.

## 1. Scope and owner constraints

This checkpoint continues the owner's one-existing-laptop, sole-operator, local-first plan. It does not add a VPS, a second machine, another operator, public bootstrap peers or a public listener.

The design is a local two-physical-disk rollback witness:
- QFP6 durable chain and branch archive remain on D: (Toshiba HDD).
- The append-only owner-controlled high-water anchor vault remains on C: (Kingston SSD).
- They are separate physical drives, but remain under the same Windows administrator and on one laptop.

This is not an independent public trust domain, TPM monotonic counter, public Testnet or Mainnet safety claim.

## 2. Commit path: D: durable first, C: witness before success

New Rust module:
src/native/pow_bench/src/qrun_v06_local_anchor_vault_candidate.rs

The module implements QRunV06LocalAnchorVault and QRunV06LocalAnchorVaultTip using the existing Python vault record format:
- schema qfp6-local-anchor-vault/v1;
- record digest domain QFP6-LOCAL-ANCHOR-VAULT-RECORD-V1 followed by a null byte;
- monotonic record sequence;
- exact network/profile IDs;
- manifest generation and canonical manifest anchor;
- previous-record digest and record digest;
- create-new append, file flush, complete chain re-open and tip verification.

One record is required for every consecutive QFP6 manifest generation. Sequence gaps, generation gaps, wrong identity, checksum changes, broken predecessor links, symlinks and non-regular files are rejected.

QRunV06PermissionlessNodeRuntime now owns an optional local vault. Both base and quote-aware envelope admission paths persist the returned durable commit to C: before returning success:
1. QFP6 store commits the D: branch/manifest using its existing durable commit path.
2. Runtime appends the exact (generation, manifest_anchor) successor to C:.
3. Vault reopens and validates its complete chain and the exact new tip.
4. Only then does the runtime return the successful commit to the caller.

If the C: append fails, the runtime marks the local anchor path as failed, returns an error instead of a successful commit acknowledgement, and refuses subsequent envelope admissions through that runtime instance. The mining/sync service path propagates the admission error.

This is deliberately not described as a cross-volume atomic transaction. D: commits before C:; the recovery rule below closes the single-generation interruption window.

## 3. Immutable root pin and historical-ancestor replay

The package's permissionless_runtime.trusted_manifest_anchor is now treated as the immutable sequence-1 vault root, not rewritten after every block. The Python owner tool verify checks this root binding and checks the latest vault record against the current D: manifest tip. The legacy advance command now performs final-stop verification only; it does not append records or rewrite either config/manifest digest.

The launcher:
- validates every C: record, sequence, contiguous manifest generation, network/profile identity, previous-record link and checksum;
- verifies the configured root pin equals the sequence-1 C: anchor;
- refuses if the C: tip is ahead of D:;
- passes the exact C: tip (generation, anchor) to the local runtime.

A new opt-in store constructor accepts a historical anchor only when that exact anchor is present at that exact generation in the fully loaded, contiguous manifest chain. The normal store open path remains strict and still requires its configured anchor to equal the latest manifest anchor.

For the local dual-disk path, successful startup then:
1. opens the store only if the current C: tip is an exact manifest ancestor;
2. validates all manifest parents/identity/commitments;
3. loads and verifies the latest manifest's referenced branch entries;
4. replays the complete Genesis-rooted history and validates the rebuilt graph;
5. compares the replayed D: tip with the C: tip.

Allowed outcomes:
- D: and C: at the same generation and anchor: continue without modifying the vault;
- D: exactly one manifest generation ahead: after full replay has proved the C: anchor is an exact ancestor, append that one validated successor to C: before runtime startup completes;
- D: behind C:, more than one generation ahead, a different anchor at the pinned generation, missing vault, malformed vault or tampered history: refuse startup.

The one-generation bound follows from the acknowledgement barrier: an acknowledged local commit has already been anchored on C:. A crash between the D: durable commit and C: append can leave one outstanding successor, but that runtime does not acknowledge it and is blocked from further commits.

## 4. Stop evidence and operator runner

Files updated:
- tools/qfp6_anchor_vault.py
- tools/qfp6-local-run-and-rotate.ps1
- src/native/pow_bench/src/bin/qrun_v06_node_runtime_launch/permissionless.rs

Runtime shutdown output no longer reports the old EXPORT_ONLY_REQUIRES_OUT_OF_BAND_OWNER_PIN status for the local-vault path. It emits:
- anchor_persistence_status=LOCAL_C_VAULT_PER_COMMIT_PERSISTED when the C: vault is active and healthy;
- anchor_persistence_status=NOT_CONFIGURED when no local vault is active;
- anchor_persistence_status=REOPEN_REQUIRED after a persistence failure.

When available, it also emits the final local vault sequence, generation and anchor. The runner and Python final-stop verifier require the positive per-commit marker plus Q6GA verification, exact final generation/anchor, zero node exit and runtime_status=STOPPED. They verify the final tip; they do not rotate or rewrite the immutable root pin.

The final-status text is still operator evidence, not cryptographic proof that Ctrl+C reached the process. Real interactive Ctrl+C/SIGTERM behavior remains an integration test item.

## 5. Validation evidence in this checkpoint

Rust formatting:
cargo fmt --all -- --check - PASS after the current source edits before the latest status-output change; re-run is required after all final edits.

Focused tests:
- cargo test --lib qrun_v06_local_anchor_vault_candidate --locked --offline -j 1 - 3 passed.
- cargo test --lib local_vault_trusted_manifest_ancestor_is_exact_and_replays_full_tip --locked --offline -j 1 - 1 passed. Verifies a real generated manifest root, exact root generation/anchor, full replay to the newer tip, rejection of the old latest-only open path, and rejection of wrong generation/anchor pins.
- cargo test --lib local_dual_disk_runtime_persists_each_commit_and_recovers_one_unanchored_generation --locked --offline -j 1 - 1 passed. On disposable test directories, verifies a runtime commit is already present in C: before its success is returned, then simulates interruption after a D: commit but before C: append; reopening the local runtime replays the complete chain and reconciles exactly one generation.

Launcher regression:
cargo test --bin qrun_v06_node --locked --offline -j 1 - 44 passed, 0 failed (before the final status-label-only source edit; must re-run).

Actual owner vault read-only checks:
- python tools/qfp6_anchor_vault.py --package-dir release/qfp6-local-single-operator-devnet-2026-11-15 verify - PASS.
- powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools/qfp6-local-run-and-rotate.ps1 -VerifyOnly - PASS.
- Real C: vault remains sequence 1, generation 1024, anchor 652ad475a0646e285329d690f493b9b10bf89d44f6ff1cf381c96b7d83ed25b0.
- Real package config SHA-256 remains 89e7048fe36a326d7cd8d9f0c76ad1f695601400d373b795ac419e4c0e74978c.

No QRun process was started on the canonical original data directory in this checkpoint. The real C: vault was not advanced. The user package/config, live QFP6 manifests and branches were not modified by the runtime recovery test.

## 6. Explicit limitations / next gates

1. The Rust Release build and Release startup/recovery against a fresh scratch copy still need validation after final source changes.
2. A real OS process crash / Ctrl+C / SIGTERM integration test has not been run. The current runtime test simulates the D-commit/C-append interruption boundary by closing a disposable store after a D: commit.
3. Vault record append writes a create-new final record then flushes it. If power loss interrupts that write and leaves a partial JSON file, startup correctly fails closed; automated repair of a partial C: record is not implemented. Preserve evidence and perform an explicit audit rather than deleting/re-writing records blindly.
4. Catch-up is intentionally limited to exactly one generation. Larger gaps require a manual, read-only full audit.
5. C: and D: are separate physical disks but one laptop/admin domain. Reverting both disks, a hostile Administrator, firmware compromise or full-machine restoration is outside this design.
6. TPM 2.0 was detected but TPM key/NV management was unavailable without elevated access; no TPM changes were made.
7. This does not add remote QAP1 Provider/Q6EA attestations. The local QFP6 path is separate from the off-host QAP1 protocol.
8. The local package remains loopback-only, with public listener/outbound peer sync disabled and no bootstrap peers. It is not a public Testnet or Mainnet.
9. The public website remains on its legacy content because PR #195 is still open/unmerged. Its Rust validation workflow completed successfully, but no website deployment occurred.

## 7. Next execution order

- finish the focused Rust tests and latest 44-test launcher regression after status-marker changes;
- build the Release binary;
- run startup/replay only against an isolated scratch copy that uses the real C: vault read-only;
- re-run read-only owner verify, runner -VerifyOnly, git diff --check and inspect the complete changed-file list;
- retain the original live package and C: vault untouched until all scratch checks pass and the owner explicitly approves a live run.

## 8. Post-checkpoint Release validation (2026-11-15)

- `cargo fmt --all -- --check` — PASS.
- Anchor Vault module tests — 3 passed.
- Exact historical-ancestor/full replay test — 1 passed.
- Per-commit local runtime/recovery test — 1 passed.
- `cargo test --bin qrun_v06_node --locked --offline -j 1` — 44 passed, 0 failed.
- `cargo build --release --bin qrun_v06_node --locked --offline -j 1` — PASS (9 warnings, no build failure).

A fresh scratch copy at `D:\Temp\QFP6_CP0682_FINAL_20261115` was built from the local package and a copy of the C: vault. Its config explicitly referenced the scratch vault and its manifest config digest was recomputed. Scratch vault verification passed at sequence 1 / generation 1024 / the expected anchor.

The Release binary verified Q6GA and printed `QFP6 PERMISSIONLESS BASE RUNTIME: STARTING (candidate qualification only)`, expected network/profile/Genesis identifiers, loopback listener address and zero bootstrap peers. It then exited with code 1 because the supervisor attempted to mine beyond the in-memory fork archive limit: `QFP6 in-memory fork archive reached its block limit`.

Interpretation: the runtime reached STARTING, so Genesis-rooted store open/replay and local-vault reconciliation had completed. The failure was at the next mining/admission step beyond the 1,024-block bound, not during replay.

Post-run checks: original package remained at 1,025 manifests / 1,024 branches; original C: vault remained sequence 1 / generation 1024 / same record digest; scratch package remained 1,025 manifests / 1,024 branches; scratch vault remained one record; no QRun process and no TCP 30333 listener remained.

The code currently sets both `MAX_QRUN_V06_FORK_ARCHIVE_BLOCKS` and `MAX_QRUN_V06_FORK_BRANCH_HEIGHT` to 1,024. Checkpoint-rooted store APIs and segment tests exist, but the local permissionless runtime path still opens the Genesis-rooted store and does not orchestrate checkpoint rollover. Simply raising the limit is not an acceptable fix; segment trust and global anchor continuity must be integrated first.