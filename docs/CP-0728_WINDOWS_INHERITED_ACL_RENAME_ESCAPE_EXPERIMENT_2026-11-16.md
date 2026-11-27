# CP-0728 — Windows Inherited ACL Rename Escape Experiment

Date: 2026-11-16
Worktree: `D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116`
Branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`
Base HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`
Scope: Windows-only, test-only, disposable source/destination directories and synthetic inherited DACL. No production store, ACL, identity, key, node, listener, network or user data was modified.

## Purpose

Carry the CP-0722/0723 rename-authorization question into the inherited-ACL model established by CP-0725 through CP-0727. The test installs the source-parent DACL before creating the child, so the child receives its DELETE deny by inheritance. It then checks both authorization routes and attempts the same path-based directory rename while retaining a component-relative child handle opened without `FILE_SHARE_DELETE`.

## Implementation

- Added `set_inherited_rename_route_denies_for_temp_test` to the Windows-only ACL probe.
- The helper installs:
  - an explicit Everyone (`S-1-1-0`) deny for parent `FILE_DELETE_CHILD`;
  - an Everyone `DELETE` deny with `CONTAINER_INHERIT_ACE`, so child directories inherit it;
  - an allow ACE with only the additional rights needed to create/open the disposable test tree and reset the temporary DACLs.
- Added `inherited_parent_and_child_rename_denies_block_retained_handle_escape` to `windows_relative_open_experiment`.
- The child directory is created only after the parent's synthetic DACL is installed. The child ACL snapshot is checked for exactly one inherited Everyone `DELETE` deny ACE.
- The exact relative-open path uses `open_child_experimental(root_handle, "child", Directory, false)`, retaining the no-share-delete handle while the test attempts the same `fs::rename(&child, &moved)` operation used by CP-0722/0723.
- The test records current-token `AccessCheck` results for parent `FILE_DELETE_CHILD` and child `DELETE`, then resets the temporary DACLs, drops handles and removes the temporary directories.

## Result

Command:

```powershell
cargo test --lib inherited_parent_and_child_rename_denies_block_retained_handle_escape -- --nocapture
```

Result: **1 passed, 0 failed, 0 ignored; 1457 filtered out; exit code 0.**

Observed output:

```text
Inherited rename ACL probe: parent_FILE_DELETE_CHILD=Ok(false), child_DELETE=Ok(false), child_inherited_delete_aces=1, child_ace_flags=[18], rename_error=Some(Os { code: 5, kind: PermissionDenied, message: "Access is denied." }), moved_outside=false
test windows_relative_open_experiment::tests::inherited_parent_and_child_rename_denies_block_retained_handle_escape ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 1457 filtered out
```

## Interpretation

- The source parent denied the current process token `FILE_DELETE_CHILD`.
- The child had exactly one inherited Everyone `DELETE` deny ACE; flags `0x12` represent `CONTAINER_INHERIT_ACE | INHERITED_ACE`.
- The child denied the current process token `DELETE`.
- With both authorization routes denied, the same rename attempt failed with Win32 error 5 (`ERROR_ACCESS_DENIED`), and the child was not moved outside the source parent.
- The child handle was retained without `FILE_SHARE_DELETE` during the rename attempt.

This result is consistent with the combined inherited parent/child policy blocking this tested rename on this Windows host. It does not establish universal namespace containment or replace principal-wide access analysis.

## Cleanup correction

The first CP-0728 harness draft created a marker file after installing a container-inherit-only DACL. That file did not inherit the CI-only ACE; its resulting security descriptor prevented recursive cleanup. The marker was unnecessary for the directory rename and was removed from the test. The corrected test uses an empty child directory; the final run reset both temporary DACLs and removed both temporary directories successfully. The abandoned empty outside directory from the first attempt was separately removed after verifying it was empty.

## Validation

- Focused CP-0728 test: passed as above, including successful temporary-tree cleanup.
- `cargo fmt --all -- --check`: passed.
- `git diff --check`: passed. Git emitted only existing LF-to-CRLF working-copy notices for tracked project files.
- No broad test suite was rerun.

## Limitations

- `AccessCheck` evaluated only the current process token. It does not prove access for every service principal, group composition, restricted/deny-only SID, privilege, impersonation context, or concurrent ACL mutation.
- The DACL is synthetic and temporary. This test is limited to the tested host, filesystem, directory shape and standard ACE types.
- It does not cover all rename APIs, kernel/system mutators, reparse-point races, filesystem filter drivers, alternate volumes, or every parent/destination authorization edge.
- CP-0721's observation that retained handles and no-share-delete alone do not prevent rename remains valid. CP-0728 shows only that this tested combined inherited deny policy stopped this particular rename operation.
- No production ACL/store paths were changed. No private keys were read or used. No node, listener or network was started. No website change, commit, push, merge or release was performed.

## Evidence

- `windows_acl_snapshot_probe.rs` SHA-256: `5EEAEECB7DE6A3664BE9E2DE3722C77921210F4BD87D63DF714C24AE5CC61161`
- `windows_relative_open_experiment.rs` SHA-256: `7CADA6C55989D762F2C0B1AAC83667889770DBF74BDE084D7C0524AA19E55A39`
- Worktree branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`
- Worktree HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`

## Next bounded step

Probe alternate rename APIs/destination authorization only if the threat model requires them. Before broadening, preserve the established limits: current-token-only `AccessCheck`, synthetic DACLs, host-specific results, and no production use. A further useful bounded test is whether an untrusted process can mutate the relevant parent DACL via `WRITE_DAC` or ownership semantics after the combined deny policy is installed; do not infer resistance to policy administrators from the deny ACEs alone.
