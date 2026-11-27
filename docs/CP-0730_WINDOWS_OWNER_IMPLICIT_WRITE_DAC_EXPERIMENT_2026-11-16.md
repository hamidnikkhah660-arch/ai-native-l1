# CP-0730 — Windows Owner-Implicit WRITE_DAC Experiment

Date: 2026-11-16
Worktree: `D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116`
Branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`
Base HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`
Scope: Windows-only, test-only, disposable parent/child directories and protected synthetic DACLs. No production store, ACL, identity, key, node, listener, network or user data was modified.

## Purpose

Isolate owner-implicit `WRITE_DAC` from explicit and inherited allow ACEs. CP-0729 had shown that the synthetic rename DACL explicitly granted `WRITE_DAC` to Everyone, so it could not answer whether object ownership alone was sufficient. The CP-0730 test removes outer inherited ACEs, creates the child after the controlled parent policy is installed, and verifies the owner SID, ACE stream, current-token `AccessCheck`, and a fresh post-policy handle request.

## Implementation

- Added `current_process_default_owner_sid()`, which queries the current process token's `TokenOwner` information and returns its owner SID.
- Added `set_inherited_rename_route_denies_without_write_dac_for_temp_test`. It installs the parent `FILE_DELETE_CHILD` deny and container-inherited child `DELETE` deny, with the minimum additional allow mask used by the disposable test. It does **not** add `WRITE_DAC` or `WRITE_OWNER` to any explicit allow mask.
- The helper applies `PROTECTED_DACL_SECURITY_INFORMATION` with the DACL update, preventing the test directory from inheriting unrelated ACEs from its external `D:\Temp` ancestor.
- Added `current_owner_can_reopen_write_dac_without_explicit_allow_ace`.
- The test creates the parent, opens one pre-policy cleanup handle, installs the protected synthetic DACL, and only then creates the child so it inherits the controlled policy.
- It snapshots both objects, compares both owner SIDs to the token's default owner SID, checks that neither DACL contains any standard allow ACE with the `WRITE_DAC` bit, and calls current-token `AccessCheck(WRITE_DAC)` on both objects.
- It then opens fresh parent and child handles requesting `WRITE_DAC`, changes both temporary DACLs to NULL through those fresh handles, closes all handles, and removes the temporary tree.

## Result

Command:

```powershell
cargo test --lib current_owner_can_reopen_write_dac_without_explicit_allow_ace -- --nocapture
```

Result: **1 passed, 0 failed, 0 ignored; 1459 filtered out; exit code 0.**

Observed output:

```text
Owner WRITE_DAC probe: token_default_owner=S-1-5-21-2927852697-1555830555-231538280-1001, parent_owner=S-1-5-21-2927852697-1555830555-231538280-1001, child_owner=S-1-5-21-2927852697-1555830555-231538280-1001, parent_owner_match=true, child_owner_match=true, explicit_parent_WRITE_DAC_ACE=false, explicit_child_WRITE_DAC_ACE=false, parent_WRITE_DAC_ACES=[], child_WRITE_DAC_ACES=[], parent_AccessCheck=true, child_AccessCheck=true, parent_fresh_handle=true, child_fresh_handle=true
test windows_acl_snapshot_probe::tests::current_owner_can_reopen_write_dac_without_explicit_allow_ace ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 1459 filtered out
```

## Interpretation

- The parent and child owner SIDs both matched the current token's default owner SID.
- Neither snapshot contained a standard allow ACE whose access mask included `WRITE_DAC`; the test also protected the synthetic parent DACL against unrelated inherited ACEs.
- `AccessCheck` allowed `WRITE_DAC` on both objects.
- Fresh post-policy handles requesting `WRITE_DAC` were successfully opened for both objects.
- The test then successfully changed both temporary DACLs through those handles and cleaned up the temporary directory tree.

This provides focused evidence that the current owner token received owner-implicit `WRITE_DAC` on these owned file-system objects in this Windows environment, even without an explicit `WRITE_DAC` allow ACE. It also shows why a mutation-rights model must account for the owner separately from ACE grants.

## Diagnostic history

The first test draft failed because it created the child before applying the parent DACL and did not protect the parent DACL from external inheritance. The snapshot contained inherited `BUILTIN\\Administrators` and `SYSTEM` allow ACEs whose masks included `WRITE_DAC`; the original broad filter reported those as explicit grants. The diagnostic output showed both ACEs had the inherited flag and were not grants to the token owner SID. The test was corrected to protect the parent DACL and create the child after policy installation. The corrected run reported empty `WRITE_DAC` allow-ACE lists for both objects and passed.

## Validation

- Focused CP-0730 test: passed as above, including fresh post-policy handle opens, DACL mutation, and temporary-tree cleanup.
- `cargo fmt --all -- --check`: passed.
- `git diff --check`: passed. Git emitted only existing LF-to-CRLF working-copy notices for tracked files.
- No broad test suite was rerun.

## Limitations

- `AccessCheck` evaluated only the current process token. The result does not prove that every user, group, service principal, restricted/deny-only SID, privilege or impersonation context has the same access.
- The test evaluates the token's default owner SID and the owner assigned to these newly created test directories. It does not cover explicit owner reassignment, `WRITE_OWNER`, `SeTakeOwnershipPrivilege`, `SeRestorePrivilege`, or ownership changes made by another principal.
- It does not test `OWNER RIGHTS` ACE semantics, protected/unprotected DACL transitions beyond this one case, every filesystem, or concurrent descriptor mutation.
- The result is host- and scenario-specific. It is not a production policy or universal namespace-security proof.
- No production ACL/store paths were changed. No private keys were read or used. No node, listener or network was started. No website change, commit, push, merge or release was performed.

## Evidence

- `windows_acl_snapshot_probe.rs` SHA-256: `E6FCAA1478DB5212F3DD6E83A5A632F90979D68B54234B7EB4CC07017EF7CC91`
- Worktree branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`
- Worktree HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`

## Next bounded step

Probe `OWNER RIGHTS` ACE semantics separately. Compare the current owner's implicit `WRITE_DAC` with and without a standard `OWNER RIGHTS` ACE for the owner SID, then verify whether the explicit ACE changes the decision. Keep `WRITE_OWNER` and privilege-based ownership changes as separate follow-up probes.
