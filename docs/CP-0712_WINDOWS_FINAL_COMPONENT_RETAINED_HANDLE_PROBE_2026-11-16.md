# CP-0712 — Windows Final-Component Retained-Handle Probe

Date: 2026-11-16  
Worktree: `D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116`  
Branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`  
Base HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`

## Scope

Implemented a Windows-only Win32 probe in `src/native/pow_bench/src/windows_store_handle_probe.rs`, exported from `lib.rs` as `windows_store_handle_probe`.

`open_final_component(path)`:

- Calls `CreateFileW` with `FILE_READ_ATTRIBUTES`, read/write/delete sharing, `OPEN_EXISTING`, `FILE_FLAG_OPEN_REPARSE_POINT`, and `FILE_FLAG_BACKUP_SEMANTICS`.
- Transfers the returned handle into `std::fs::File` immediately so it is RAII-owned and retained by `WindowsStoreHandleProbe`.
- Uses `GetFileType` to reject non-disk handles.
- Uses `GetFileInformationByHandleEx(FileAttributeTagInfo)` on that same retained handle; rejects device objects and final-component reparse points.
- Uses `GetFinalPathNameByHandleW(FILE_NAME_NORMALIZED | VOLUME_NAME_GUID)` on the same handle.
- Exposes the retained handle, final path, and observed object kind. The handle is opened for attributes only, not for store data I/O.
- `is_complete_for_store_policy()` intentionally returns `false` unconditionally.

## Tests and verification

On the connected Windows host:

- `cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib windows_store_handle_probe::tests -- --nocapture` — 4 passed.
- The four probe tests cover ordinary file, directory, final file symlink rejection, and final directory junction rejection. The symlink-creation path may be skipped if Windows does not grant the symlink privilege; the directory-junction test ran successfully on this host and confirmed rejection of the final reparse point.
- `cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib windows_store_path_qualifier::tests -- --nocapture` — 11 passed.
- `cargo check --manifest-path src/native/pow_bench/Cargo.toml --lib` — passed after the Win32 probe and disk-object checks were added; existing unrelated warnings remain.
- `cargo fmt --manifest-path src/native/pow_bench/Cargo.toml --all` — passed.
- `git diff --check` — passed.

## Explicit limitations — NOT production-qualified

This probe inspects only the final component. Win32 path parsing can traverse ancestors before the final handle is opened; ancestor handles are not walked or retained. It does not establish:

1. handle-relative, race-resistant traversal of every ancestor;
2. physical volume identity (`volume GUID`, storage device number, device instance identity) from a fully handle-bound volume provider;
3. owner SID, DACL, inherited/deny ACEs, group membership, privileges, or effective mutation rights;
4. that a store's later reads/writes use this exact handle (the handle is attributes-only and this module is not wired into either store).

Consequently, this probe cannot populate trusted `WindowsStorePathEvidence`, cannot set `complete_handle_walk`, `io_uses_qualified_handle`, or `acl_complete` to true, and cannot authorize store startup or mutation. It is a narrow verified Win32 primitive, not a security boundary or complete qualifier.

## Safety / repository state

- Only isolated CP-0704 worktree files were changed.
- No C:/D: production store paths, ACLs, partitions, TPM, keys, identity state, node, listener, public network, or transfers were touched.
- No startup integration, commit, push, merge, PR update, or release was performed.
- Original checkout remains separate and untouched by this CP-0712 change.

## Next engineering gate

CP-0713 should implement a genuinely handle-relative ancestor walk (or prove an equivalent race-resistant Windows mechanism) with retained directory handles and explicit reparse rejection. Then implement handle-bound volume identity and complete ACL evaluation behind injectable interfaces. Until those are independently tested, do not wire this probe into production stores.
