# CP-0713 — NtCreateFile Relative-Open and Rename-Escape Experiment

Date: 2026-11-16  
Worktree: `D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116`  
Branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`  
Base HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`

## Scope and isolation

Added `src/native/pow_bench/src/windows_relative_open_experiment.rs` as a test-only module (`#[cfg(all(windows, test))]` in `lib.rs`). It is not compiled into normal library builds, not exported as a production API, and not connected to either durable store.

The experiment uses `NtCreateFile` from `ntdll` with:

- `OBJECT_ATTRIBUTES.RootDirectory` set to a retained directory handle;
- a single validated child component as `ObjectName`;
- `OBJ_DONT_REPARSE` (without `OBJ_CASE_INSENSITIVE`, because the public user-mode NtCreateFile page does not clearly reconcile every `OBJECT_ATTRIBUTES` flag);
- `FILE_DIRECTORY_FILE` or `FILE_NON_DIRECTORY_FILE` with `FILE_SYNCHRONOUS_IO_NONALERT`;
- `FILE_OPEN` and caller-selected share flags.

## Windows-host experiment results

Command:

`cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib windows_relative_open_experiment::tests -- --nocapture`

Result: 5 passed, 0 failed.

Observed cases:

1. A directory handle obtained through the CP-0712 `CreateFileW` probe was accepted as `RootDirectory` on this Windows host.
2. Opening an existing directory by one child component relative to that handle succeeded.
3. Opening a regular file by one child component relative to that handle succeeded.
4. A directory junction encountered during component-relative open was rejected with `STATUS_REPARSE_POINT_ENCOUNTERED` (`0xC000050B`).
5. Multi-component names (`..` and separators) were rejected by the helper before calling Win32.
6. **Critical negative result:** a child directory was opened relative to its root handle with share-delete omitted. While the child handle remained open, `std::fs::rename` successfully moved that directory outside the original root. A subsequent component-relative open of `marker.bin` through the retained child handle also succeeded. The test printed this exact observation.

This is empirical behavior on the current host/configuration, not a universal claim about all Windows versions or filesystems. It demonstrates that the tested no-share-delete handle configuration did not pin the directory's namespace location here. Therefore, keeping ancestor handles and using relative opens does not, by itself, establish permanent containment beneath the original root.

## Documentation findings

- Microsoft `NtCreateFile` documents `RootDirectory`-relative name resolution and `FILE_OPEN_REPARSE_POINT` behavior: https://learn.microsoft.com/windows/win32/api/winternl/nf-winternl-ntcreatefile
- Microsoft `OBJECT_ATTRIBUTES` documents `OBJ_DONT_REPARSE` as failing with `STATUS_REPARSE_POINT_ENCOUNTERED` when reparse points are encountered: https://learn.microsoft.com/windows/win32/api/ntdef/ns-ntdef-_object_attributes
- A Microsoft Learn Q&A response dated 2026-11-03 by a Microsoft External Staff moderator states that the public documentation does not establish an atomic containment guarantee for concurrent rename/replacement interleavings, and that trusted-root acquisition remains a separate unresolved issue: https://learn.microsoft.com/en-us/answers/questions/6059091/is-ntcreatefile-with-rootdirectory-race-safe-again
- A separate Microsoft Learn discussion dated 2026-10-20 cautions that `FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT` is not documented as a supported user-mode combination; this experiment deliberately does not combine those flags: https://learn.microsoft.com/en-us/answers/questions/6042972/is-file-directory-file-compatible-with-file-open-r

## Security decision

Do NOT promote this experiment to a production path qualifier. `OBJ_DONT_REPARSE` is useful for rejecting reparse traversal during an individual open, but the observed rename escape and the absence of a published end-to-end concurrency guarantee mean the root-containment property is not established.

The next design gate must establish a threat model and a supported namespace immutability mechanism, including:

- trusted volume-root acquisition and volume identity;
- complete owner/DACL/inherited/deny ACE and effective-rights analysis;
- who can rename/delete/reparent each directory and who can change its ACL/owner;
- whether the deployment service identity can be isolated from untrusted principals;
- explicit handling of privileged administrators and filesystem filters;
- independent review of the exact Windows API contract and supported OS/filesystem matrix.

Do not assume share-mode omission blocks directory rename; this host's experiment disproved that assumption for the tested path. Do not wire this code into production stores or use it to certify containment until the above is resolved and independently reviewed.

## Safety / repository state

- Tests used only synthetic temporary directories/files under the OS temp directory and cleaned them up.
- No real C:/D: project data, ACLs, partitions, TPM, keys, identity state, node, listener, network, or transfers were touched.
- No startup integration, commit, push, merge, PR update, or release was performed.
- Original checkout remains separate. Its provisioner SHA-256 remains `DDD2BBB6D320986CA0DB1A796B3B9DECF14BAD22B9F7D4E7212D6FB9DE451E8F`.
