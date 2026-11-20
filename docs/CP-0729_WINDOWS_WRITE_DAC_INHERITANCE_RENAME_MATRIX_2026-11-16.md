# CP-0729 — Windows WRITE_DAC, Inherited ACL Refresh and Rename Matrix

Date: 2026-11-16
Worktree: `D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116`
Branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`
Base HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`
Scope: Windows-only, test-only, disposable source/destination directories and synthetic ACLs. No production store, ACL, identity, key, node, listener, network or user data was modified.

## Purpose

Build on CP-0728 by checking whether a process that has fresh `WRITE_DAC` access to the parent and child can modify only one security descriptor and reopen a rename route. The test distinguishes three cases:
1. Set the parent to a NULL DACL while leaving the child descriptor to inheritance refresh.
2. Replace the parent DACL with the explicit `FILE_DELETE_CHILD` allow policy used in CP-0723.
3. Set only the child to a NULL DACL while the parent's `FILE_DELETE_CHILD` deny remains.

The child is created only after the initial combined deny policy is applied, so the child initially receives the container-inherited `DELETE` deny.

## Implementation

- Reuses CP-0728's `set_inherited_rename_route_denies_for_temp_test`; no duplicate helper or new production policy was added.
- Added `write_dac_mutations_expose_parent_inheritance_and_child_rename_routes` to `windows_relative_open_experiment.rs`.
- The test applies the combined parent/child deny policy, then opens *fresh* parent and child ACL handles after the DACLs are installed. It queries `WRITE_DAC` on both handles with `AccessCheck` before changing either descriptor.
- It retains the component-relative child handle opened with `FILE_SHARE_DELETE` omitted and executes the same `fs::rename` path as CP-0722/0723.
- After each row, it resets both DACLs, restores any moved directory, drops handles and removes the disposable trees.

## Result

Command:

```powershell
cargo test --lib write_dac_mutations_expose_parent_inheritance_and_child_rename_routes -- --nocapture
```

Result: **1 passed, 0 failed, 0 ignored; 1458 filtered out; exit code 0.**

Observed output:

```text
WRITE_DAC rename matrix: case=parent-null-only, parent_WRITE_DAC=true, child_WRITE_DAC=true, parent_FDC_after=true, child_DELETE_after=false, child_DACL_state=Present, child_ACE_count=0, child_inherited_DELETE_denies_after=0, rename_succeeded=false, moved_outside=false
WRITE_DAC rename matrix: case=parent-allow-refreshes-inheritance, parent_WRITE_DAC=true, child_WRITE_DAC=true, parent_FDC_after=true, child_DELETE_after=true, child_DACL_state=Present, child_ACE_count=8, child_inherited_DELETE_denies_after=0, rename_succeeded=true, moved_outside=true
WRITE_DAC rename matrix: case=child-null-only, parent_WRITE_DAC=true, child_WRITE_DAC=true, parent_FDC_after=false, child_DELETE_after=true, child_DACL_state=Null, child_ACE_count=0, child_inherited_DELETE_denies_after=0, rename_succeeded=true, moved_outside=true
test windows_relative_open_experiment::tests::write_dac_mutations_expose_parent_inheritance_and_child_rename_routes ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 1458 filtered out
```

## Interpretation

### Case 1 — parent NULL DACL only

- Parent `AccessCheck(FILE_DELETE_CHILD)` became allowed.
- The child did **not** become allowed: `AccessCheck(DELETE)` remained denied.
- The child snapshot reported `DaclState::Present` with zero ACEs; it had neither an inherited Everyone DELETE deny nor any allow ACE in the parsed ACE stream.
- Rename still failed with Windows error 5 (`ERROR_ACCESS_DENIED`).

This is an important distinction: a NULL DACL on the parent did not make the child's DACL a NULL DACL. The child's resulting *present but empty* DACL denied the current token. Therefore parent `AccessCheck` alone did not predict that rename would succeed in this row.

### Case 2 — parent DACL replaced with explicit FILE_DELETE_CHILD allow

- The parent `FILE_DELETE_CHILD` check became allowed.
- Windows refreshed the child's inherited DACL: the child snapshot contained 8 ACEs and no matching inherited Everyone DELETE deny.
- Child `AccessCheck(DELETE)` also became allowed.
- Rename succeeded and the child was moved outside the source parent.

This row does **not** isolate parent `FILE_DELETE_CHILD` as the sole authorization route: the parent's DACL replacement also changed the child's inherited DACL, making child DELETE allowed. The measured result is parent DACL mutation plus inheritance refresh.

### Case 3 — child NULL DACL only

- Parent `AccessCheck(FILE_DELETE_CHILD)` remained denied.
- Child became `DaclState::Null`, and `AccessCheck(DELETE)` became allowed.
- Rename succeeded and the child was moved outside the source parent.

This row demonstrates that changing only the child DACL was sufficient to reopen the rename operation on this host even while the parent `FILE_DELETE_CHILD` deny remained.

## Security significance

- Fresh parent and child handles both passed `AccessCheck(WRITE_DAC)` after the combined deny policy was installed. The test therefore confirms that the current process could acquire DACL-modification rights under this synthetic policy.
- Deny ACEs are not a durable containment boundary when a principal can obtain `WRITE_DAC` on the relevant objects.
- Parent DACL changes may refresh inherited child ACEs; a reviewer must inspect the resulting child DACL rather than assume inherited denies remain unchanged.
- A parent's NULL DACL and a child's NULL DACL are not equivalent states. In this run, the former left the child with a present but empty DACL; the latter made the child access check allow DELETE.

These results are specific to the tested Windows host, current token, synthetic Everyone ACL, and filesystem operation. They are not a universal Windows authorization rule or production containment proof.

## Validation

- Focused CP-0729 test: passed as above, including all three branches and successful temporary-tree cleanup.
- `cargo fmt --all -- --check`: passed.
- `git diff --check`: passed. Git emitted only existing LF-to-CRLF working-copy notices for tracked files.
- No broad test suite was rerun.

## Limitations

- `AccessCheck` used only the current process token. It does not prove access for all principals, groups, restricted/deny-only SIDs, privileges, impersonation contexts or concurrent ACL changes.
- This test uses a Everyone ACE and deliberately grants `WRITE_DAC` in the synthetic ACL. It does not yet isolate owner-implicit `WRITE_DAC`, `WRITE_OWNER`, privilege-based ownership changes, or an untrusted process lacking those rights.
- The test does not cover all rename APIs, destination ACL combinations, filesystem filter drivers, reparse-point races, other filesystems or alternate volumes.
- No production ACL/store paths were changed. No private keys were read or used. No node, listener or network was started. No website change, commit, push, merge or release was performed.

## Evidence

- `windows_relative_open_experiment.rs` SHA-256: `6202CD34661D4D1860504BCC88E03A8C2CABE1D52DD380BD6EEE0705E3BB136F`
- Worktree branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`
- Worktree HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`

## Next bounded step

Test owner-implicit `WRITE_DAC` separately: install the same disposable deny policy but omit any explicit `WRITE_DAC` allow ACE, read the parent and child owner SIDs, compare them with the current process token, and test whether freshly opened handles can still change the DACL. Keep `WRITE_OWNER` and privilege-based ownership changes as separate questions.
