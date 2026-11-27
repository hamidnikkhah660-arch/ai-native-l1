# CP-0681 - Local Dual-Disk Anchor Vault and Startup Enforcement

Date: 2026-11-15
Project: AI-NATIVE L1 / QRun / QZXB / QFP6
Branch: feat/cp0600-bootstrap-sync-startup
Worktree: D:\Temp\ASUS\QRUN_QFP6_CP0596_20261111
Depends on: CP-0678, CP-0679, CP-0680
Status: LOCAL C:-DRIVE VAULT PROVISIONED; STARTUP VAULT ENFORCEMENT IMPLEMENTED; 41/41 LAUNCHER TESTS PASS; RELEASE REPLAY STARTUP PASS ON COPY; FULL PER-COMMIT / CRASH-SAFE ROTATION NOT COMPLETE.

## 1. Owner operating constraints

The owner explicitly chose:
- one existing laptop;
- owner remains sole administrator/operator;
- no second laptop;
- no VPS/hosting spend at this stage;
- local-first and no reliance on a second operator.

This checkpoint advances the local solo-node path. It does not claim independent public seeds, independent public operators, or public Testnet readiness. Multiple VMs/accounts on the same laptop remain one failure domain and one operator.

## 2. Hardware fact used for the local design

Physical Windows inventory previously confirmed:
- C: resides on physical Kingston SSD KINGSTON RBUSNS8154P3256GJ3, about 238.5 GB.
- D: and E: are partitions of physical Toshiba HDD TOSHIBA MQ04ABF100, about 931.5 GB.
- C: and D: are separate physical drives; D: and E: are not separate drives.
- At CP-0680 inspection C: had about 46.7 GB free and D: about 217.1 GB free.

The QFP6 durable history remains on D:. The local anchor vault now resides on C:, below:
`C:\Users\ASUS\AppData\Local\AI_NATIVE_L1\QFP6\anchor-vault\`

This can detect a D:-only data-volume rollback while C: remains intact. It cannot defeat a complete-machine image restore, simultaneous rollback/replacement of both drives, administrator-level tampering with both volumes, TPM clear, or malicious firmware. It is a local dual-disk rollback detector, NOT a hardware monotonic counter or independent remote witness.

## 3. New local tooling

Added:
`tools/qfp6_anchor_vault.py`

Commands:
- `init`: one-time provision of an initial owner vault record from a package whose configured anchor exactly matches the latest local QFP6 manifest commitment.
- `verify`: checks package/config/manifest/Q6GA binding, complete local manifest generation naming continuity, exact latest QFP6 domain-separated anchor, the full append-only vault record chain and matching network/profile/generation/anchor.
- `advance`: requires explicit `--confirm-clean-shutdown`, a final generation and a 64-character anchor. It appends the new vault record only when the supplied value equals the commitment derived from the exact latest local manifest bytes, then updates config and local package manifest digest with backups. It includes an idempotent repair path if the vault record was persisted but config/manifest rebinding was interrupted.

Vault record fields:
- schema `qfp6-local-anchor-vault/v1`;
- monotonically increasing local sequence;
- network ID and profile ID;
- manifest generation and exact QFP6 canonical anchor;
- previous record digest;
- domain-separated SHA-256 record digest.

Record path at current provisioning:
`C:\Users\ASUS\AppData\Local\AI_NATIVE_L1\QFP6\anchor-vault\records\q6av-00000000000000000001.json`

Initial record:
- sequence: 1
- generation: 1024
- QFP6 canonical anchor: `652ad475a0646e285329d690f493b9b10bf89d44f6ff1cf381c96b7d83ed25b0`
- vault record SHA-256: `6543b518a53a3c66979f369484002d16f7231b9d2b51362ad754ccde5afe4ab4`

The vault is local filesystem data. Its record checksum/hash chain detects accidental modification and provides a separate D:/C: high-water copy; an attacker with control over both disks can still rewrite it. Do not call this cryptographically hardware-backed anti-rollback.

## 4. Launcher startup enforcement

Modified:
`src/native/pow_bench/src/bin/qrun_v06_node_runtime_launch/permissionless.rs`

For existing QFP6 manifest history, before opening/replaying the durable store, the launcher now:
1. reads the configured `trusted_manifest_anchor`;
2. resolves the owner vault under LOCALAPPDATA by default (or an explicit absolute override);
3. rejects missing/symlinked/non-directory vault paths;
4. reads only bounded regular record files and rejects unexpected names;
5. checks contiguous sequence numbers starting at one;
6. validates every record schema, sequence, exact predecessor digest, checksum and strictly increasing manifest generation;
7. binds each record to the Q6GD/Q6PN network and profile identity;
8. compares final vault generation and anchor with current local manifest count and config anchor;
9. refuses startup if the vault is missing, stale, corrupt, for another profile/network, or inconsistent with local history.

The QFP6 store still performs its own manifest-chain, checksum, branch, consensus, execution and complete-history replay checks after this vault gate. The vault is not substituted for canonical replay.

New launcher tests:
- matching vault allows a correctly anchored existing history;
- missing anchor for existing history is refused;
- missing/mismatched/stale vault is refused;
- wrong network/profile is refused;
- predecessor-chain tampering and invalid record checksums/sequence gaps are refused.

## 5. Test and build evidence

Formatting:
`cargo fmt --all -- --check`: PASS.

Launcher unit tests:
`cargo test --bin qrun_v06_node --locked --offline -j 1`
- 41 passed
- 0 failed
- includes 4 new local vault/startup gate tests.

Release build:
`cargo build --release --bin qrun_v06_node --locked --offline -j 1`: PASS.

Existing unrelated library unused-import/dead-code warnings remain.

Local Python helper was exercised against a disposable test package and vault, not the real QFP6 data:
- initial record provision and verification passed;
- synthetic successor generation/anchor advance passed (the test-only Q6MF file was synthetic invalid content and never used by QRun);
- wrong supplied anchor rejected with exit 2 and vault remained valid;
- interrupted package-rebind simulation recovered idempotently;
- simulated D:-only rollback was rejected due generation mismatch.
The synthetic files and test vault were under D:\Temp and are not the real chain or real C: vault.

## 6. Release startup integration using actual C: vault, isolated D: history copy

The actual C: vault was created and verified against the original package at generation 1024.

A scratch package at:
`D:\Temp\QFP6_CP0677_REPLAY_TEST_20261115`
contained a copy of the 1,025 manifest / 1,024 branch history. The Release QFP6 node was run against this scratch copy, with the actual C: vault selected by default LOCALAPPDATA path.

Observed Release output:
- `owner_genesis_approval=Q6GA_ED25519_MLDSA65_VERIFIED`
- `QFP6 PERMISSIONLESS BASE RUNTIME: STARTING (candidate qualification only)`
- `listener=127.0.0.1:30333`
- `bootstrap_peer_count=0`
- Q6TS/Q6QA not configured; external quote admission denied fail-closed.
This proves the actual C: vault record was accepted by the Release startup gate when replaying the matching isolated data copy.

The test node process was then terminated after startup evidence was captured; it was NOT verified through graceful Ctrl-C shutdown. No new scratch blocks were committed (manifest/branch counts remained 1,025/1,024). Afterward:
- qrun_v06_node process count: 0
- listener count on port 30333: 0

## 7. Original data integrity after integration

The canonical package remains:
`release/qfp6-local-single-operator-devnet-2026-11-15`

Verified after the isolated startup test:
- original manifests: 1,025
- original branches: 1,024
- original generation: 1024
- correct QFP6 canonical anchor remains `652ad475a0646e285329d690f493b9b10bf89d44f6ff1cf381c96b7d83ed25b0`
- config SHA-256 remains `89e7048fe36a326d7cd8d9f0c76ad1f695601400d373b795ac419e4c0e74978c`
- local-devnet-manifest config digest matches config bytes
- Python `verify` reports `LOCAL_QFP6_ANCHOR_VAULT=PASS`
- no original QFP6 node process or 30333 listener remains active.

## 8. What is still incomplete - do not overstate rotation

CP-0679 added post-shutdown status output for generation/anchor/tip/state root. CP-0681 has added local C: record persistence and startup enforcement. Together these form a useful dual-disk restart/rollback check.

However, the complete Anchor Persistence / Rotation lifecycle is still NOT complete:
- the canonical QFP6 block commit path still does not atomically prepare/persist a successor C: vault record before publishing every new D: manifest;
- the C: vault is rotated after a verified clean shutdown, not after every block commit;
- the `advance` helper's `--confirm-clean-shutdown` is an explicit operator assertion, not cryptographic evidence that Ctrl-C/SIGTERM occurred;
- it has not yet been integration-tested with genuine OS Ctrl-C/SIGTERM output from the node;
- unexpected power loss after one or more new D: commits but before a clean rotation leaves the C: vault stale; startup deliberately refuses to proceed until full QFP6 replay/audit and an explicitly approved recovery process reconcile the state;
- crash-injection coverage for every data-manifest/vault/config rebind ordering point is still required;
- TPM 2.0 is present, but management and Microsoft Platform Crypto Provider key enumeration were denied in the current non-elevated session. No TPM key or NV index was created or modified.

Do NOT start long-running mining on the canonical original data directory yet. Do NOT call the vault TPM-backed, undefeatable, or complete per-commit anti-rollback.

## 9. Next engineering order

1. Add crash-safe commit integration so every QFP6 prepared/published manifest and C: vault transition has one recoverable, idempotent protocol with a durable intent record. Do not allow a manifest to publish if the required anchor state cannot be safely reconciled.
2. Add crash-injection tests before/after prepare, vault append, manifest publication, package rebind and clear-intent.
3. Test true Ctrl-C/SIGTERM on a disposable copy and verify CP-0679 final generation/anchor output.
4. Implement an explicit recovery/audit path for unexpected crashes: full replay/validation must precede accepting a newly advanced manifest; otherwise quarantine.
5. Only when all the above pass, operate the original canonical local node. Keep public listener, external networking and public Testnet paths disabled under the one-laptop/one-owner scope.

## 10. Scope and revenue

This checkpoint improves local owner control and rollback detection; it does not create cash flow. The CP-0651 local Genesis owner allocation is not by itself a spendable public QZXB balance. No native QZXB transfer, real market liquidity, exchange listing, or revenue stream is created by this vault or local node. No income/return is guaranteed.

Decision: a free sole-owner, dual-physical-disk local rollback-detection layer is now provisioned and enforced at startup. Full crash-safe per-commit Anchor Persistence / Rotation remains an open engineering gate.

## 11. Follow-up hardening - rotation requires captured successful-stop output

The Python helper `tools/qfp6_anchor_vault.py advance` now additionally requires `--final-status-file` containing the captured stdout from the same Release-node run. Before writing any vault record it requires exact lines:
- `QFP6 PERMISSIONLESS BASE RUNTIME: STARTING (candidate qualification only)`
- `owner_genesis_approval=Q6GA_ED25519_MLDSA65_VERIFIED`
- exact requested `final_manifest_generation`
- exact requested `final_manifest_anchor`
- `anchor_rotation_status=EXPORT_ONLY_REQUIRES_OUT_OF_BAND_OWNER_PIN`
- `runtime_status=STOPPED`

The status file must be a bounded regular non-symlink file no larger than 1 MiB. This reduces accidental use after a failed/forced stop; it does not cryptographically prove that the output file is authentic or that Windows delivered Ctrl-C. The operator must still verify the actual process exit code is zero and must not use a forced-termination log as a graceful-stop receipt.

Updated script test evidence on a disposable synthetic package:
- valid captured-stop file: vault advance and verify passed;
- status file changed to `runtime_status=RUNNING`: rejected with exit 2;
- vault remained at the valid sequence-2 test record after rejection.
The synthetic Q6MF fixture remained test-only and was not used by QRun.

## 12. Single-owner PowerShell runner

Added:
`tools/qfp6-local-run-and-rotate.ps1`

Behavior:
- defaults its repository root from its own file location;
- `-VerifyOnly` checks the current local vault without starting a node;
- validates the exact loopback-only config and QFP6 local vault before node launch;
- calculates the exact config SHA-256 automatically;
- runs the Release `--permissionless-run` synchronously and captures stdout to a timestamped log;
- refuses rotation on nonzero exit or missing final generation/anchor, Q6GA verification, rotation-scope or STOPPED markers;
- extracts only those six lines to a small UTF-8-no-BOM status receipt;
- calls `qfp6_anchor_vault.py advance` with that receipt, then re-verifies the vault;
- does not automatically restart the node.

PowerShell parse/VerifyOnly smoke test:
`powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\qfp6-local-run-and-rotate.ps1 -VerifyOnly`
- exit 0
- actual C: vault verification passed.
The normal long-running wrapper path and real Ctrl-C delivery are not yet end-to-end tested; do not claim graceful-stop integration complete. If PowerShell itself is interrupted or the node exits nonzero, do not rotate the vault.

## 13. Final launcher regression result after additional negative cases

Two more fail-closed tests were added:
- existing durable history with a configured anchor but no local vault directory is rejected;
- a vault with correctly hashed records but a skipped sequence number is rejected.

Final command:
`cargo test --bin qrun_v06_node --locked --offline -j 1`
- 43 passed
- 0 failed

`cargo fmt --all -- --check` remains PASS. Release build for the startup-vault implementation passed before these two `#[cfg(test)]`-only additions; no runtime source changed in this last test-only edit.
