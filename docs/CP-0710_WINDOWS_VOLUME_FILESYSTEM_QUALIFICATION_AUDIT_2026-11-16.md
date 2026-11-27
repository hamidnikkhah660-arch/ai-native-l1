# CP-0710 — Windows Volume and Filesystem Qualification Audit

Date: 2026-11-16
Branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`
Worktree: `D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116`
Base: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`
Status: **READ-ONLY AUDIT / DESIGN ONLY — NOT PRODUCTION QUALIFIED**

## 1. Scope and safety boundary

This checkpoint audits the CP-0706/0707/0709 peer-identity anchor and high-water storage paths, Windows filesystem trust assumptions, and the next qualification design. It does not open, initialize, enumerate, modify, or repair the production C: anchor-vault or D: identity-store directories. No ACL, owner, reparse-point, partition, TPM, or volume configuration is changed. No production identity, private key, node, listener, or network process is accessed. No commit, push, merge, PR update, or release is performed.

## 2. Code facts verified in the isolated worktree

### 2.1 Peer Identity Anchor Vault

`peer_identity_anchor_vault.rs`:
- `open()` requires an absolute root and calls `symlink_metadata()` on the final root component; it rejects a non-directory or final-component symlink.
- It then acquires the stable writer lock by pathname, enumerates the directory by pathname, checks event entries with `symlink_metadata()`, and subsequently opens event files with `File::open(path)`.
- The staged append path writes a same-directory temporary file, flushes and syncs it, rereads and validates bytes, then publishes with no-overwrite semantics on Windows using `MoveFileExW(..., MOVEFILE_WRITE_THROUGH)`.
- No handle-based verification of every ancestor, no final-path-by-handle verification, no physical-volume identity check, and no ACL/owner policy enforcement are present in this module.

### 2.2 D-side IdentityGenerationStateStore

`identity_generation_store.rs`:
- `open()` checks that the parent directory is a directory and derives a sibling lock path.
- Existing state and lock files are opened by pathname; state creation uses a sibling temporary file and Windows `MoveFileExW(REPLACE_EXISTING | WRITE_THROUGH)`.
- No reparse-chain validation, handle-bound final path validation, volume identity pin, or ACL/owner verification is implemented in this module.
- The D-side store's `open()` can initialize an empty state only when both state and stable lock are absent; this behavior must never be used to reconstruct a missing C-side anchor.

### 2.3 Shared writer lock

Both stores use `SnapshotWriterLock` from `snapshot_store.rs`. `acquire()` checks the final snapshot pathname with `symlink_metadata()`, canonicalizes an existing target (or canonicalizes the parent for a not-yet-created target), derives a sibling `.writer.lock` pathname, then opens that lock with `OpenOptions(create=true)` and takes a Windows `LockFileEx` exclusive byte-range lock.

This is stronger than a plain in-process mutex and canonicalizes existing aliases, but it remains pathname-based. Canonicalization and lock-file open are separate operations; the lock file is not opened relative to a retained validated directory handle; and there is no explicit handle-level reparse-tag, final-path, file-ID, volume, or ACL verification. A race or pre-planted lock-file reparse entry therefore remains part of the threat model. The C vault calls this API with its stable `peer-identity-vault.lockstate` path; the D generation store uses a sibling lock derived from its state path.

Path-based locking does not itself establish that the lock file and protected state file resolve through a trusted, stable directory chain. The lock implementation must be upgraded/qualified together with both data stores before startup integration.

## 3. Existing hardware inventory facts — reuse, do not re-run needlessly

CP-0681 / CP-0705 records identify C: as a Kingston SSD and D: as a separate Toshiba HDD; D: and E: are partitions of the same physical disk, not independent disks. Therefore C:/D: can serve as a two-physical-disk local rollback detector only after current device/volume mapping is revalidated at the time of qualification. These facts do not establish immutable device identity, hardware-backed monotonicity, or protection from an administrator or full-machine rollback.

The prior non-elevated TPM capability check was inconclusive: `Get-Tpm` required Administrator privilege and CIM `Win32_Tpm` access was denied. No TPM NV counter has been provisioned or qualified.

## 4. Findings

1. **Ancestor reparse exposure:** checking only the final root component does not reject junctions/symlinks/reparse points in earlier path components.
2. **Check/open race:** metadata checks and later path-based opens are separate operations. A directory entry or ancestor could change between them; the code does not bind validation to the exact handles subsequently used.
3. **File reparse exposure:** checking an event entry and then calling `File::open(path)` does not guarantee that the opened handle refers to the exact object previously checked.
4. **No volume binding:** absolute paths and drive letters do not prove that the directory is on the expected physical device. Volume serial alone is not a sufficient immutable physical-device identity.
5. **No ACL policy enforcement:** current code does not inspect owner, DACL, inherited ACEs, or effective write permissions for the root, records, and stable lock files.
6. **Lock dependency:** stable lock semantics are present, but path/handle identity and lock-file reparse/ACL protection need independent qualification.
7. **Durability qualification remains bounded:** `MOVEFILE_WRITE_THROUGH` is used, but this alone is not proof of universal power-loss durability across filesystems, storage controllers, caches, drivers, and hardware.
8. **No cross-volume transaction:** C and D cannot be treated as one atomic transaction. Reconciliation must continue to use exact digests and explicit states, never generation-only inference.

## 5. Proposed Windows qualification architecture (design; not implemented)

### 5.1 Handle-first path resolution

- Start from a trusted volume/root handle and walk each path component using Windows handle-relative opens where supported, requesting `FILE_FLAG_OPEN_REPARSE_POINT` and rejecting any component with `FILE_ATTRIBUTE_REPARSE_POINT` unless an explicitly reviewed policy permits it.
- Open directories/files with the minimum required access and sharing flags; keep validated handles alive for the operation rather than validating a pathname and reopening it later.
- Query `FILE_ATTRIBUTE_TAG_INFO` / `FileAttributeTagInfo` on each opened handle; reject unexpected reparse tags.
- Query the final normalized path with `GetFinalPathNameByHandleW` and compare it against the configured canonical namespace without using that comparison as a substitute for handle identity.
- For event records, verify regular-file type, size, and file identity from the opened handle, then read from that same handle.
- For publication, create staging and final entries relative to the already-qualified directory handle where a supported API permits; preserve no-overwrite semantics and quarantine unexpected staging artifacts.

### 5.2 Volume and physical-device binding

- Resolve the opened directory handle to its volume using handle-based volume APIs, not only a drive-letter string.
- Record and compare volume GUID path, filesystem type, volume serial, and storage device number obtained through the volume/device handle (for example `IOCTL_STORAGE_GET_DEVICE_NUMBER`).
- Where device properties are available, collect storage descriptor identity (vendor/product/serial) as corroborating evidence, not as a cryptographic trust anchor.
- Reject unexpected network, removable, substituted, or unsupported filesystems unless explicitly qualified.
- Treat device-number/serial changes, missing identifiers, ambiguous mappings, or changed partition-to-disk relationships as `VolumeIdentityUnqualified`; fail closed.
- Revalidate the C and D mapping during every controlled qualification and at startup; do not hard-code a drive letter as physical identity.

### 5.3 ACL and owner policy

- Read owner and DACL from the opened object using handle-based security APIs (`GetSecurityInfo` where supported); inspect inheritance and ACEs.
- Define a reviewed allowlist for SYSTEM, Administrators, and the dedicated service/operator SID(s); reject unexpected principals with write/delete/ownership/DACL-change rights.
- Check directory rights as well as file rights, including create/delete-child, delete, write-DAC, write-owner, and inherited permissions.
- Do not automatically repair ACLs. Any remediation must be a separately reviewed, explicit operation with before/after security-descriptor evidence.
- Do not infer effective access from a simplistic `icacls` text parse alone; use a security-descriptor-aware implementation and, where needed, an access-check evaluation under the relevant token.

### 5.4 Error model

Introduce distinct typed failures for `ReparsePoint`, `PathIdentityChanged`, `VolumeIdentityUnqualified`, `FilesystemUnsupported`, `AclUnqualified`, `HandleIdentityMismatch`, and `SecurityQueryFailed`. Any such failure blocks opening either store for trusted startup; it must not trigger auto-enrollment, ACL repair, path rewrite, or fallback to the other volume.

## 6. Required test plan before implementation can be considered qualified

Use isolated temporary directories and synthetic files only:
- Reject a reparse point at the root and at each ancestor component.
- Reject a reparse-point event file and a path swap between enumeration and open; assert validation and read use the same handle.
- Verify handle final path and file identity remain stable through read and publication.
- Reject an unexpected volume mapping and unsupported filesystem using injectable API adapters; unit tests must not require changing real partitions.
- Test ACL allowlist/denylist fixtures, inherited write ACEs, delete-child, write-DAC, write-owner, and owner mismatch. Do not change the user's real ACLs.
- Inject failure before/after staging sync, publication, and directory metadata operations; reopen must either recover the exact committed event or quarantine without auto-repair.
- Test writer-lock path substitution and lock-file reparse rejection.
- Run Windows-specific integration tests on disposable test volumes or VHDs only after a separate approval; no destructive disk test on the user's live C:/D: drives.

## 7. Acceptance gates

CP-0710 is an audit/design checkpoint, not a qualification pass. Implementation may proceed only after:
1. The supported Windows API and minimum OS version are pinned.
2. A handle-based path-walk design is reviewed for all ancestors and files.
3. A physical-volume identity policy is agreed, including behavior when device identity cannot be read.
4. An ACL/owner allowlist is explicitly approved; no guessed SID policy is enforced.
5. Fault-injection tests cover the path/handle, publication, and lock boundaries.
6. Independent review confirms that no path-based reopen bypasses the validated handle chain.

## 8. Current safety status

- Original checkout remains separate and untouched by this checkpoint.
- All CP-0703 through CP-0710 artifacts remain uncommitted in the isolated CP-0704 worktree.
- No production C:/D: store paths were opened or changed.
- No ACL, volume, partition, TPM, identity, private key, node, listener, or network state was changed.
- No commit, push, merge, PR update, or release was performed.

## 9. Next engineering step

Design a small Windows-only, injectable `WindowsStorePathQualifier` that returns an owned qualified directory/file handle plus evidence (final path, file attributes, volume identity, security descriptor digest). Start with unit-testable policy and API boundaries; do not wire it into production stores until its behavior is tested on synthetic fixtures and independently reviewed. In parallel, inspect and qualify `SnapshotWriterLock` so the lock and data paths share the same validated directory identity.

