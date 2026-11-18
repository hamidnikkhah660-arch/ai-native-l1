# CP-0727 — Windows OBJECT_INHERIT / CONTAINER_INHERIT File-vs-Directory Experiment

Date: 2026-11-16
Worktree: `D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116`
Branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`
Base HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`
Scope: Windows-only, test-only, disposable parent/child directory and file objects with synthetic DACLs. No production store, ACL, identity, key, node, listener, network or user data was modified.

## Purpose

Complete the next inheritance-scope distinction left open by CP-0726: test `OBJECT_INHERIT_ACE` and `CONTAINER_INHERIT_ACE` separately against direct file children, direct directory children, and files below a child directory.

## Implementation

- Added `set_inheritance_object_container_probe_dacl_for_temp_test(handle, deny_flags)`.
- The helper installs an Everyone (`S-1-1-0`) deny ACE for `DELETE` with the selected inheritance flags, followed by an inheritable allow ACE. The allow ACE includes `DELETE` and the directory/file creation and traversal rights required by the disposable test tree.
- Added `object_and_container_inherit_flags_separate_file_and_directory_children`.
- The OBJECT_INHERIT case uses an OI-only deny ACE (`0x01`) and checks the parent, a child directory, a direct file, and a file below the child directory.
- The CONTAINER_INHERIT case uses a CI-only deny ACE (`0x02`) and checks the parent, a child directory, a direct file, and a file below the child directory.
- Each tested object is inspected with the ACL snapshot parser and current-token `AccessCheck`. Temporary DACLs are reset before handles are closed and paths are removed.

## Result

Command:

```powershell
cargo test --lib object_and_container_inherit_flags_separate_file_and_directory_children -- --nocapture
```

Result: **1 passed, 0 failed, 0 ignored; 1456 filtered out; exit code 0.**

Observed output:

```text
OBJECT_INHERIT probe: parent_allowed=false, directory_deny_flags=0x19, directory_allowed=true, direct_file_allowed=false, nested_file_allowed=false
CONTAINER_INHERIT probe: parent_allowed=false, directory_allowed=false, direct_file_deny_count=0, direct_file_allowed=true, nested_file_deny_count=0, nested_file_allowed=true
test windows_acl_snapshot_probe::tests::object_and_container_inherit_flags_separate_file_and_directory_children ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 1456 filtered out
```

## Interpretation

### OBJECT_INHERIT only (`0x01`)

- The parent itself was denied `DELETE`.
- The child directory received the deny ACE as inherited + inherit-only (`0x19`); therefore that deny did not apply to the directory itself, and its `AccessCheck` allowed `DELETE`.
- The direct file inherited an effective deny and its `AccessCheck` denied `DELETE`.
- The file below the child directory also inherited the OI deny and its `AccessCheck` denied `DELETE`.

### CONTAINER_INHERIT only (`0x02`)

- The parent itself was denied `DELETE`.
- The child directory inherited an effective deny and its `AccessCheck` denied `DELETE`.
- Neither the direct file nor the file below the child directory contained a matching inherited Everyone deny ACE; both `AccessCheck` calls allowed `DELETE`.

These results distinguish file inheritance from directory inheritance on this Windows host for the tested standard deny ACE and disposable tree. They are not a complete inheritance conformance test or a production namespace-security guarantee.

## Validation

- Focused CP-0727 test: passed as above.
- `cargo fmt --all -- --check`: passed.
- `git diff --check`: passed. Git emitted only existing LF-to-CRLF working-copy notices for tracked project files.
- No broad test suite was rerun.

## Limitations

- `AccessCheck` evaluated only the current process token. It does not prove access for every principal, group composition, restricted/deny-only SID, privilege or impersonation context.
- The experiment is limited to standard allow/deny ACEs and the tested local Windows filesystem/host. It does not cover object/callback/conditional ACEs, protected DACLs, every reparse/namespace behavior, or other filesystems.
- The test does not establish that the parent/child ACL configuration alone blocks every rename route; CP-0721 through CP-0723 remain separate rename-path evidence and limitations.
- No production ACL/store paths were changed. No private keys were read or used. No node, listener or network was started. No website change, commit, push, merge or release was performed.

## Evidence

- `windows_acl_snapshot_probe.rs` SHA-256: `ADA0FD453F91D2F84DB2CA4824E3B90E2E7A4C112CF63FA3C8EE849B4C830E74`
- Worktree branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`
- Worktree HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`

## Next bounded step

Use these inheritance observations to build one disposable inherited-ACL rename experiment: combine inherited parent `FILE_DELETE_CHILD` denial with inherited child `DELETE` denial, query both rights, and attempt the exact directory rename used by the earlier path-chain experiments. Keep the result test-only and host-specific.
