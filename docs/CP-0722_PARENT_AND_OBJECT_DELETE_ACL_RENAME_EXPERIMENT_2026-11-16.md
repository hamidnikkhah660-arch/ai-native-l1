# CP-0722 — Parent and Object DELETE ACL Rename Experiment

Date: 2026-11-16  
Worktree: `D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116`  
Branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`  
Base HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`

## Implementation

Extended the Windows test-only ACL probe with two disposable-object DACL helpers:

- `set_parent_deny_delete_child_for_temp_test`: installs an Everyone deny ACE for directory `FILE_DELETE_CHILD`, followed by the minimum read/list/traverse rights required for the probe.
- `set_object_deny_delete_for_temp_test`: installs an Everyone deny ACE for `DELETE` on the child directory, followed by the minimum read/list/traverse rights required for the probe.

Added `parent_delete_child_and_object_delete_denies_block_directory_rename_escape` to the relative-open experiment. It:

1. Creates a disposable parent, sibling destination, and child directory.
2. Opens and retains the child directory handle without `FILE_SHARE_DELETE`.
3. Confirms the baseline rename succeeds and moves the same child back.
4. Queries `AccessCheck` for parent `FILE_DELETE_CHILD` and child `DELETE`.
5. Installs explicit parent `FILE_DELETE_CHILD` deny and child `DELETE` deny ACEs.
6. Re-checks both rights and attempts the same rename.
7. Resets both temporary DACLs to NULL DACL before cleanup.

## Windows-host result

Command:

`cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib parent_delete_child_and_object_delete_denies_block_directory_rename_escape -- --nocapture`

Result: 1 passed, 0 failed.

Observed on this host:

- Baseline rename succeeded while the child handle was retained without `FILE_SHARE_DELETE`.
- Before the explicit test DACL, parent `FILE_DELETE_CHILD` was already denied to the current process token (`AccessCheck=false`), while child `DELETE` was allowed (`AccessCheck=true`).
- After explicit deny ACEs, both parent `FILE_DELETE_CHILD` and child `DELETE` evaluated denied (`AccessCheck=false`).
- The rename then failed with Win32 error 5 (`ERROR_ACCESS_DENIED`).

This narrows the earlier CP-0721 finding: the observed successful baseline rename occurred despite parent `FILE_DELETE_CHILD` being denied, while child `DELETE` was allowed. Denying both rights blocked the tested rename. The evidence is consistent with the rename being authorized through child-object `DELETE` on this host; the next experiment tests the alternate parent `FILE_DELETE_CHILD` authorization route explicitly.

## Limits

- `AccessCheck` evaluates only the current process token and the tested descriptor snapshot. It is not an all-principal effective-rights proof.
- The synthetic DACL uses Everyone ACEs only; it does not model inherited ACEs, owner rights, groups, privileges, callback/object ACEs, or conditional ACEs comprehensively.
- This does not prove every Windows filesystem uses the same rename authorization path.
- The test resets temporary DACLs before removing its temporary directories.
- No project ACL, production path, store content, partition, TPM, key, identity state, node, listener, network, or transfer was touched.
- No production integration, commit, push, merge, PR update, or release.

## Next gate

CP-0723 should test the alternate authorization path: explicitly allow parent `FILE_DELETE_CHILD` while denying child `DELETE`, then determine whether rename succeeds. If so, a robust namespace policy must deny both rights to every untrusted mutator on the relevant parent and child objects, while separately accounting for `WRITE_DAC`, ownership, privileges, and inherited/group ACEs. Keep this test-only.
