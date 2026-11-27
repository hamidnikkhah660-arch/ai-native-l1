# CP-0755 - Windows Handle-Relative STB1 Publication Experiment

Date: 2026-11-17  
Status: **TEST-ONLY HANDLE-RELATIVE PUBLISH PROTOTYPE PASSED ON THIS WINDOWS HOST / NOT PRODUCTION QUALIFIED**

Worktree: D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116  
Branch: feat/cp0704-dual-attestation-rotation-gate-20261116  
Base HEAD (unchanged): 5aba5f69d24fce03af742fd1bebf13ad00e5d9c3

## 1. Objective and isolation

CP-0755 tests whether a staged state file can be published by operating on the already-open source file handle and a retained destination-directory handle, rather than reopening source and destination through full path strings for the final rename.

The implementation is in:
src/native/pow_bench/src/windows_handle_relative_replace_experiment.rs

It is declared only under #[cfg(all(windows, test))] in lib.rs. It is not a public runtime API and is not connected to SignerTrustBundleStateStore, the DPC1/DCS1 paths, peer identity stores, provisioners, or node startup.

All tests used synthetic data under the host's temporary directory. No production C:/D: trust path, real signer, key, wallet, node, listener, network, partition, or production ACL was opened or changed. No dependency was added. No commit, push, merge, PR, release, or launch action occurred.

## 2. Prototype design

1. The final test directory component is opened using CreateFileW and retained as a File handle. The probe requests directory traversal and child-file creation rights, rejects a final-component reparse point, and deliberately omits FILE_SHARE_DELETE.
2. The staged source file is created relative to that retained directory handle with NtCreateFile, a one-component name, OBJ_DONT_REPARSE, and FILE_CREATE. Names with path separators, traversal components, alternate-stream delimiters, trailing dot/space, NUL, or control characters are rejected before the native call.
3. The staged data is written and flushed through the retained source handle, including sync_all().
4. Publication calls NtSetInformationFile on the already-open source handle with Native FileRenameInformation class 10. RootDirectory is set to the retained destination-directory handle; the destination is a single validated filename component. No source-path or destination-path lookup is performed by this final rename operation.
5. The test reads FILE_ID_INFO (volume serial plus 128-bit file ID) from the source handle before publication, then opens the published target relative to the same directory handle and reads the same identity from that target handle.

The native API's FileRenameInformation class and the relative RootDirectory field are distinct from the Win32 FILE_INFO_BY_HANDLE_CLASS enum values. The prototype uses the Native API class value 10, not Win32's FileRenameInfo value 3. The source handle is opened with DELETE access for this operation. See the Microsoft WDK contracts cited in the project notes.

## 3. Focused test results

Command:
cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib windows_handle_relative_replace_experiment::tests -- --nocapture --test-threads=1

Result: **3 passed, 0 failed**.

Coverage:
- **Exact source-object publication:** replacement of an existing synthetic target succeeds. FILE_ID_INFO (volume serial and 128-bit file ID) read from the source handle equals the identity read from the target reopened relative to the retained directory handle; target bytes and retained-source bytes both match the new payload.
- **No-overwrite path:** with replace_if_exists = false, an existing target is not replaced and the operation returns the exact Native status STATUS_OBJECT_NAME_COLLISION (0xC0000035). Existing target bytes and staged source bytes remain unchanged.
- **Name validation:** empty, dot, dot-dot, path traversal/separators, and alternate data stream names are rejected before the native rename operation; staged contents remain unchanged.

The earlier full Windows qualification run, with this same three-test prototype, completed **52 passed, 0 failed**:
cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib windows_ -- --nocapture --test-threads=1
This included the handle-relative prototype, the path/reparse/ACL/volume experiments, and both subprocess crash-window tests (142.57 seconds).

The focused regressions also passed:
- STB1: **18 passed, 0 failed**.
- Shared snapshot store: **10 passed, 0 failed**.
- cargo fmt --all -- --check: PASS.
- git diff --check: PASS; Git emitted only pre-existing LF-to-CRLF working-copy notices.

The existing symbolic-link writer-lock test still cannot create its symlink fixture under this token (Win32 error 1314); that particular case is skipped by the existing test. Junction and other path tests passed.

## 4. Boundary experiments and observed limits

- An exploratory attempt to rename the final destination directory while its retained handle was open failed with Win32 sharing violation (error 32). In this implementation, the directory handle intentionally does not grant FILE_SHARE_DELETE. This is an observation on the current host/configuration, not a general containment guarantee.
- A separate attempt to rename an unopened ancestor directory failed with AccessDenied on this host before the publication step. That attempt is inconclusive about ancestor-handle containment and is not counted as a passing test. No ACL was altered to force the operation.
- Earlier CP-0713 experiments with a different handle/share configuration observed that a retained child-directory handle did not by itself prevent the child's namespace entry from being moved outside the original root. The behavior depends on the precise handle/share/ACL configuration and must not be generalized from one test.
- This prototype does not walk and retain every ancestor component from a trusted volume root. The directory itself is initially opened by pathname, and only its final component is inspected.
- It does not retrieve or qualify the destination directory's complete DACL, owner, inherited ACEs, effective rights for all principals, or privileged namespace mutation routes.
- It does not pin physical-volume identity, protect against hostile Administrator or full-volume/VM rollback, or prove crash/power-loss durability of the directory-entry transition. sync_all() on the staged file is not proof that all relevant directory metadata and storage-controller caches are power-loss durable.
- The stable writer lock and all STH1 state-store reads/writes remain pathname-based. The prototype is not used by SignerTrustBundleStateStore and does not yet prove that startup, size checks, locking, reading, and publication all use the same qualified namespace and handle identities.

## 5. Gate disposition

**CP-0755 proves one narrow behavior on this host:** the already-open staged source object can be renamed to a one-component target name relative to a retained destination-directory handle, and the published target handle reports the same volume/file identity as the source handle.

It does **not** qualify STH1 for production. Gate 8 remains **OPEN**. Do not use this prototype for real signer enrollment, production provisioning, node startup, or public-network operation.

## 6. Next gate

CP-0756 should define the complete handle-bound adapter contract before any runtime wiring:
- establish a trusted root and a reviewed strategy for every ancestor component; fail closed when namespace containment cannot be established;
- bind the stable writer lock and data-file operations to the same qualified directory/file identities;
- retrieve and evaluate the full owner/DACL/inheritance and mutation-capable principal policy against the intended service/operator identities;
- add independent CAS or witness state for full-volume rollback resistance;
- design injectable crash/recovery tests that cover lock, read, replace, reopen, and directory-entry failure windows.

Keep the provider detached until the Win32/Native FFI, directory/ancestor policy, ACL model, volume evidence, and independent rollback design have each been reviewed and tested.
