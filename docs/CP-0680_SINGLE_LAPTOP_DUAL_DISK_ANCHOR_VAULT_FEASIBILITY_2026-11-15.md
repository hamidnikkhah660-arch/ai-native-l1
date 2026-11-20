# CP-0680 - Single-Laptop, Dual-Disk Anchor Vault Feasibility

Date: 2026-11-15
Project: AI-NATIVE L1 / QRun / QZXB / QFP6
Worktree: D:\Temp\ASUS\QRUN_QFP6_CP0596_20261111
Depends on: CP-0678, CP-0679
Status: FEASIBILITY VERIFIED; FULL ANCHOR PERSISTENCE / ROTATION NOT YET IMPLEMENTED.

## 1. Owner's operating constraints

The owner has explicitly requested:
- one existing Windows laptop only;
- the owner remains the sole operator/administrator;
- no second laptop, no rented VPS, no external seed operator;
- free/local-first infrastructure;
- minimize further delays and avoid claiming revenue or network readiness that does not exist.

The engineering plan must honor these constraints for the local development/solo-node profile. It must not relabel a single-host setup as independent public seeds or public multi-operator consensus.

## 2. Actual hardware/storage inventory observed

Physical disk mapping from Windows:
- Disk 1: KINGSTON RBUSNS8154P3256GJ3, about 238.5 GB; contains C: (Windows/system SSD).
- Disk 0: TOSHIBA MQ04ABF100, about 931.5 GB; contains D: and E: partitions.
- D: has about 217.1 GB free at this inspection.
- E: has about 322.3 GB free at this inspection.
- C: has about 46.7 GB free at this inspection.
- `LOCALAPPDATA` resolves to `C:\Users\ASUS\AppData\Local`.

Consequently C: and D: are physically separate storage devices; D: and E: are partitions on the same physical Toshiba disk and must not be counted as two independent disks.

This gives a free, laptop-local separation option:
- canonical QFP6 data stays on D: (Toshiba);
- a small owner-controlled anchor vault may live on C: (Kingston SSD).

This separation can detect/reject a rollback or restoration of the D: data volume when the C: vault remains intact. It does NOT protect against an administrator restoring/compromising both drives, a complete-machine snapshot rollback, TPM clear, or a hostile administrator. It is not a substitute for an independent remote monotonic witness.

## 3. TPM / virtualization capability observed

Read-only checks:
- TPM is present: Intel TPM 2.0.
- `tpmtool getdeviceinformation` reports initialized, ready for storage, ready for attestation, not locked out, and no vulnerable firmware flag.
- `Get-Tpm` and TPM WMI queries returned Administrator-required / Access Denied.
- `certutil -csp "Microsoft Platform Crypto Provider" -key` returned NTE_PERM / Access denied.
- No TPM key was created; no TPM NV index was defined, incremented or changed; no TPM clear, BitLocker or firmware/security configuration was changed.
- CPU reports virtualization firmware disabled; WSL reports the current machine configuration does not support WSL1 and Kali WSL2 is not usable in this state.

TPM-backed key/NV-counter support is therefore not yet qualified from the current non-elevated session. Any later TPM NV experiment requires a separate review of exact commands and explicit owner approval; never clear the TPM or alter BitLocker/security settings as a shortcut.

## 4. Exact Anchor Persistence / Rotation status

Completed:
- QFP6 durable store computes its canonical domain-separated manifest anchor.
- runtime status API returns manifest generation and manifest anchor.
- CP-0679 changed the launcher to print generation, anchor, canonical height, tip and state root after a successful supervisor shutdown.
- CP-0679 launcher tests: 38 passed, 0 failed.
- CP-0679 Release build: passed.
- The CP-0678 Release replay/startup test passed on a scratch copy.
- The canonical data directory still has 1,025 manifests and 1,024 branches; its generation-1024 anchor remains `652ad475a0646e285329d690f493b9b10bf89d44f6ff1cf381c96b7d83ed25b0`.
- No QRun node process or TCP 30333 listener is running.

Not yet completed:
- an append-only local anchor vault on C:;
- a startup check that compares the C: vault against the D: manifest/config before replay;
- a controlled, idempotent rotation utility that updates the vault and config/manifest bindings;
- a crash-safe commit protocol that couples prepared D: manifest publication with C: anchor advancement;
- integration tests for every power-loss point in that two-volume protocol;
- a genuine OS Ctrl-C/SIGTERM end-to-end run that proves the final anchor output (the previous Release test was stopped by process termination, so it did not validate a graceful-stop rotation).

**Therefore Anchor Persistence / Rotation is still PARTIAL, not DONE.** The CP-0679 final-status output is a prerequisite, not the completed lifecycle.

## 5. Recommended zero-cost local design

Create an owner-controlled append-only vault below:
`C:\Users\ASUS\AppData\Local\AI_NATIVE_L1\QFP6\anchor-vault\`

Store the QFP6 full history on D: as it is today. The vault records should bind:
- schema/version and monotonically increasing local sequence;
- network ID and profile ID;
- manifest generation and exact QFP6 domain-separated anchor;
- digest of the prior vault record;
- record checksum/digest.

Required behavior:
1. Append records with create-new semantics, bounded regular-file reads, symlink rejection, flush/fsync and atomic metadata handling.
2. Startup must fail closed when the C: vault is missing, corrupt, out of sequence, bound to another network/profile, or inconsistent with the config/manifest.
3. The launcher must also reject a D: store whose latest generation/anchor is older than or conflicts with the C: vault.
4. Rotation must be idempotent. If the vault advances but config rebinding is interrupted, re-running the tool must repair the config only when the exact latest manifest and vault record match.
5. A D: commit that is not yet anchored on C: must never be silently adopted on restart. It must be fully revalidated and explicitly reconciled; otherwise quarantine.
6. Crash injection must cover prepared-but-unpublished, anchor-pending, anchor-advanced, manifest-published and intent-cleared states before the canonical data directory is used.

The existing `anti_rollback_commit_transition_model.rs` describes a two-domain prepare -> anchor advance -> local publish -> clear-intent lifecycle, but it is a test-only classifier, not an implemented storage protocol. The QFP6 Q6EA APIs also require a true atomic monotonic backing store; the local file adapter explicitly disclaims protection from complete-host/filesystem rollback.

## 6. Solo operation vs public network

A single owner can administer the laptop, local vault, local node and all local development VMs. Such a setup remains a local/single-operator test environment.

It cannot honestly satisfy CP-0655's two independently administered public seed requirement by using two VMs, two Windows user accounts, or two IP addresses on this same laptop. A public node hosted on the laptop also depends on inbound reachability, power, ISP/router policy and continuous uptime; no public listener should be enabled until these gates are actually tested and approved.

No VPS purchase is required for the current local engineering work. Public Testnet and Mainnet remain NO-GO under the current one-laptop/one-operator constraints.

## 7. Revenue / real-value boundary

The local Genesis owner allocation is a candidate policy amount, not a spendable QZXB wallet balance. The six 1B accounting labels are not minted or circulating funds. No native QZXB transfer, confirmed exchange liquidity, market listing or revenue stream is established in CP-0670/CP-0678. Running a local node or printing a token allocation cannot by itself create cash flow.

The cost-free near-term path is to finish a verifiable local demo/release and package real engineering deliverables for legitimate product/service revenue. No return, valuation, buyer, listing or immediate cash flow is guaranteed.

## 8. Next implementation gate

Implement the C:-vault record format and rotation/verify utility first; then integrate fail-closed vault verification in the launcher; then wire a proper prepared-commit/anchor-advance/publish protocol with crash-injection tests. Work against a disposable copy until all tests pass. Do not start the original canonical store or open public ports during this work.

Decision: proceed with a free, sole-owner, dual-physical-disk local design as a bounded rollback-detection layer; do not claim it is hardware-monotonic or independently administered. Full Anchor Persistence / Rotation is not yet complete.
