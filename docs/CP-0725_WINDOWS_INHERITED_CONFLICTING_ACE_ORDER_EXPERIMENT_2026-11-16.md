# CP-0725 — Windows Inherited Conflicting ACE Order Experiment

Date: 2026-11-16
Worktree: `D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116`
Branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`
Base HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`
Scope: Windows-only, test-only, disposable parent/child directories and synthetic DACLs. No production store, ACL, identity, key, node, listener, network or user data was modified.

## Purpose

Extend CP-0724's explicit ACE-order observation to inherited ACEs. The experiment installs a conflicting deny/allow pair on a disposable parent directory with both object-inherit and container-inherit flags, creates a child directory afterwards, then snapshots the child's DACL and runs `AccessCheck` for the current process token.

## Implementation

- Added `set_conflicting_inheritable_write_dacl_for_temp_test(handle, deny_first)` to the Windows-only ACL probe.
- The helper installs two Everyone (`S-1-1-0`) ACEs with `OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE`: a deny for `FILE_WRITE_DATA`, and an allow that includes `FILE_WRITE_DATA` plus the directory rights needed to create and inspect the child.
- Added `inherited_conflicting_ace_order_is_preserved_and_applied_to_child`.
- The test runs two independent disposable parent/child cases: deny-first and allow-first. It verifies that the two matching ACEs exist on the child, both carry the inherited flag, their order matches the parent's order, and current-token `AccessCheck` follows the first matching ACE for `FILE_WRITE_DATA`.
- Both child and parent temporary DACLs are reset to NULL DACL before handles are closed and directories are removed.

## Diagnostic refinement

The first test draft filtered for an exact allow-mask value and found only one ACE. The raw child snapshot showed that Windows had inherited both ACEs; the allow mask also contained directory creation/list/traverse/read-control bits. The filter was corrected to select ACEs whose mask contains the `FILE_WRITE_DATA` bit. This was a test-filter issue, not an observed inheritance failure.

## Result

Command:

```powershell
cargo test --lib inherited_conflicting_ace_order_is_preserved_and_applied_to_child -- --nocapture
```

Result: **1 passed, 0 failed, 0 ignored; 1454 filtered out; exit code 0.**

Observed output:

```text
Inherited ACE probe: parent_deny_first=true, child_ace_order=[1, 0], child_write_allowed=false
Inherited ACE probe: parent_deny_first=false, child_ace_order=[0, 1], child_write_allowed=true
test windows_acl_snapshot_probe::tests::inherited_conflicting_ace_order_is_preserved_and_applied_to_child ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 1454 filtered out
```

Interpretation: on this Windows host and for the tested directory-inheritance case, the child DACL preserved the parent ACE order: deny/allow remained `[1, 0]`, and allow/deny remained `[0, 1]`. The current process token's `AccessCheck` decision for `FILE_WRITE_DATA` tracked that order. This is a host- and scenario-specific observation, not a universal Windows ACL or namespace-security guarantee.

## Validation

- Focused CP-0725 test: passed as above.
- `cargo fmt --all -- --check`: passed after removal of a nonfunctional unused test-local constant.
- `git diff --check`: passed. Git emitted only existing LF-to-CRLF working-copy notices for tracked project files.
- No broad test suite was rerun. The final constant cleanup did not alter test logic; the focused test had passed immediately before it.

## Limitations

- `AccessCheck` evaluated only the current process token. It does not prove access for every principal, group composition, restricted/deny-only SID, privilege, or impersonation context.
- The experiment covers inherited standard allow/deny ACEs on child directories with object- and container-inherit flags. It does not cover file children, `INHERIT_ONLY_ACE`, `NO_PROPAGATE_INHERIT_ACE`, owner-rights ACEs, callback/object/conditional ACEs, or every filesystem.
- The DACLs are synthetic and temporary. This is not a complete ACL evaluator, a proof of race-free namespace containment, or production authorization.
- No production ACL/store paths were changed. No private keys were read or used. No node, listener or network was started. No website change, commit, push, merge or release was performed.

## Evidence

- `windows_acl_snapshot_probe.rs` SHA-256: `39D04EF69AEB0BE4416298BF869FE1E6286D27F1B1EC95C113A805CA4D648820`
- CP-0724 checkpoint SHA-256: `D969872E73F20F7FEFC0FDC6E7B524E60F4CBF5B05D3EF7C43DEB53129EDBE76`
- Worktree branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`
- Worktree HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`

## Next bounded step

Probe inheritance-flag scope separately: distinguish whether an ACE is effective on its parent versus inherited by child directories and files, including `INHERIT_ONLY_ACE` and `NO_PROPAGATE_INHERIT_ACE`. Keep the test matrix disposable and test-only; do not infer production containment from the current-token observations.
