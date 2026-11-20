# CP-0726 — Windows INHERIT_ONLY / NO_PROPAGATE Scope Experiment

Date: 2026-11-16
Worktree: `D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116`
Branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`
Base HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`
Scope: Windows-only, test-only, disposable parent/child/grandchild directories and synthetic DACLs. No production store, ACL, identity, key, node, listener, network or user data was modified.

## Purpose

Extend CP-0725's directory-inheritance matrix to distinguish the effects of `INHERIT_ONLY_ACE` and `NO_PROPAGATE_INHERIT_ACE`: whether a deny ACE applies to its parent, whether it applies to a direct child, and whether it reaches a grandchild.

## Implementation

- Added `set_inheritance_scope_probe_dacl_for_temp_test(handle, deny_flags)` to the Windows-only ACL probe.
- The helper installs an Everyone (`S-1-1-0`) deny ACE for `FILE_WRITE_DATA` using caller-selected inheritance flags, followed by an inheritable allow ACE that permits the disposable tree to be created and inspected.
- Added `inherit_only_and_no_propagate_flags_bound_child_inheritance_scope`.
- The first case uses `OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE` (`0x0B`) and checks the parent and one child.
- The second case uses `OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | NO_PROPAGATE_INHERIT_ACE` (`0x07`) and checks the parent, child and grandchild.
- The test snapshots inherited ACE flags and checks the current process token with `AccessCheck`. Temporary DACLs are reset before handles are closed and directories are removed.

## Result

Command:

```powershell
cargo test --lib inherit_only_and_no_propagate_flags_bound_child_inheritance_scope -- --nocapture
```

Result: **1 passed, 0 failed, 0 ignored; 1455 filtered out; exit code 0.**

Observed output:

```text
INHERIT_ONLY probe: parent_allowed=true, child_ace_flags=0x13, child_allowed=false
NO_PROPAGATE probe: parent_allowed=false, child_allowed=false, child_deny_flags=0x10, grandchild_deny_count=0, grandchild_allowed=true
test windows_acl_snapshot_probe::tests::inherit_only_and_no_propagate_flags_bound_child_inheritance_scope ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 1455 filtered out
```

## Interpretation

### INHERIT_ONLY

- Parent `AccessCheck` allowed `FILE_WRITE_DATA`: the `INHERIT_ONLY` deny did not apply to the parent object.
- The child received the deny ACE with flags `0x13` (`OBJECT_INHERIT | CONTAINER_INHERIT | INHERITED`); the `INHERIT_ONLY` bit was no longer present on the inherited copy.
- Child `AccessCheck` denied `FILE_WRITE_DATA`: the inherited ACE applied to the child.

### NO_PROPAGATE

- Parent `AccessCheck` denied `FILE_WRITE_DATA`.
- The direct child received the deny ACE with flags `0x10` (`INHERITED_ACE` only); the object/container inheritance bits had been cleared.
- Child `AccessCheck` remained denied.
- The grandchild had no matching inherited Everyone deny ACE, and its `AccessCheck` allowed `FILE_WRITE_DATA` through the remaining inherited allow ACE.

These are observed results for the tested Windows host and synthetic directory tree. They are not a universal ACL conformance proof or production namespace-security guarantee.

## Validation

- Focused CP-0726 test: passed as above.
- `cargo fmt --all -- --check`: passed.
- `git diff --check`: passed. Git emitted only existing LF-to-CRLF working-copy notices for tracked project files.
- No broad test suite was rerun.

## Limitations

- `AccessCheck` evaluated only the current process token; it does not prove access for all principals, groups, restricted/deny-only SIDs, privileges or impersonation contexts.
- This experiment tests directory children only. It does not yet qualify file-child behavior or distinguish object-inherit-only from container-inherit-only behavior.
- The DACLs are synthetic and temporary. This does not cover every ACE type, owner-rights semantics, conditional ACEs, filter drivers, other filesystems, or concurrent namespace mutation.
- No production ACL/store paths were changed. No private keys were read or used. No node, listener or network was started. No website change, commit, push, merge or release was performed.

## Evidence

- `windows_acl_snapshot_probe.rs` SHA-256: `E6E10C5FFA81F5A045BA844106FD7A702904F21E9C10B0D8F0E260E4233F0CB0`
- Worktree branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`
- Worktree HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`

## Next bounded step

Test `OBJECT_INHERIT_ACE` and `CONTAINER_INHERIT_ACE` separately against disposable file and directory children. Preserve the current-token and synthetic-DACL limits, and do not promote the probes into production authorization.
