# CP-0733 — Windows WRITE_OWNER / OWNER RIGHTS Experiment

Date: 2026-11-16
Worktree: `D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116`
Branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`
Base HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`
Scope: Windows-only, test-only, disposable directory and protected synthetic DACL. No production store, ACL, identity, key, node, listener, network or user data was modified. The test did not change the object's actual owner.

## Purpose

Keep `WRITE_OWNER` distinct from the owner-implicit `WRITE_DAC` behavior established in CP-0730 through CP-0732. This experiment compares a DACL with no OWNER RIGHTS ACE against one with an OWNER RIGHTS allow ACE for `WRITE_OWNER`. It queries `AccessCheck` and attempts to open a fresh handle requesting that right.

## Implementation

- Added `open_temp_handle_with_access(path, desired_access)`, preserving the existing `open_temp_handle(path, allow_write_dac)` wrapper while allowing tests to request an exact access mask.
- Added `set_owner_rights_write_owner_dacl_for_temp_test(handle, owner_rights_allow)`. It installs a protected DACL with an Everyone read-only ACE and, when requested, one OWNER RIGHTS (`S-1-3-4`) allow ACE for `WRITE_OWNER`. The helper does not grant `WRITE_OWNER` to Everyone or another SID.
- Added `write_owner_is_not_implicit_but_owner_rights_ace_can_grant_it`.
- The test retains a pre-policy handle for cleanup, verifies the owner SID, applies a protected DACL without an OWNER RIGHTS ACE, queries `AccessCheck(WRITE_OWNER)`, and attempts a fresh handle open requesting `WRITE_OWNER`.
- It then adds only the OWNER RIGHTS allow ACE, repeats the snapshot, `AccessCheck` and fresh handle open, resets the temporary DACL through the retained handle, and removes the test directory.

## Result

Command:

```powershell
cargo test --lib write_owner_is_not_implicit_but_owner_rights_ace_can_grant_it -- --nocapture
```

Result: **1 passed, 0 failed, 0 ignored; 1462 filtered out; exit code 0.**

Observed output:

```text
WRITE_OWNER probe: token_default_owner=S-1-5-21-2927852697-1555830555-231538280-1001, object_owner=S-1-5-21-2927852697-1555830555-231538280-1001, owner_match=true, baseline_AccessCheck=false, baseline_fresh_handle=false, baseline_fresh_error=Some("Access is denied. (os error 5)"), OWNER_RIGHTS_allow_count=1, other_WRITE_OWNER_allow_count=0, allowed_AccessCheck=true, allowed_fresh_handle=true, allowed_fresh_error=None
test windows_acl_snapshot_probe::tests::write_owner_is_not_implicit_but_owner_rights_ace_can_grant_it ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 1462 filtered out
```

## Interpretation

- The object's owner SID matched the current process token's default owner SID.
- With no OWNER RIGHTS ACE, `AccessCheck(WRITE_OWNER)` returned false and a fresh handle requesting `WRITE_OWNER` failed with Windows error 5 (`ERROR_ACCESS_DENIED`).
- After adding one OWNER RIGHTS allow ACE for `WRITE_OWNER`, with no other allow ACE containing that right, `AccessCheck` returned true and a fresh handle requesting `WRITE_OWNER` opened successfully.
- The object owner was not changed. This experiment validates access-check and handle-open authorization only; it does not validate a subsequent owner reassignment operation.

Together with CP-0730 through CP-0732, the results keep the rights separate:
- Owner-implicit `WRITE_DAC` was observed when no OWNER RIGHTS ACE was present (CP-0730).
- OWNER RIGHTS deny/allow ACEs suppressed or granted `WRITE_DAC` (CP-0731/0732).
- `WRITE_OWNER` was not implicitly granted by ownership alone in this test, but an OWNER RIGHTS allow ACE granted access to request it (CP-0733).

## Validation

- Focused CP-0733 test: passed as above, including denied and allowed fresh-handle cases, DACL reset and temporary directory cleanup.
- `cargo fmt --all -- --check`: passed.
- `git diff --check`: passed. Git emitted only existing LF-to-CRLF working-copy notices for tracked files.
- No broad test suite was rerun.

## Limitations

- `AccessCheck` evaluated only the current process token. It does not establish results for every user, group, restricted/deny-only SID, privilege or impersonation context.
- The test does not execute `SetSecurityInfo` to change the object's owner. A successful `WRITE_OWNER` handle request does not by itself show that an arbitrary target SID can be assigned.
- It does not cover `SeTakeOwnershipPrivilege`, `SeRestorePrivilege`, `WRITE_OWNER` to a SID not enabled in the token, ownership changes by another principal, or concurrent descriptor mutation.
- The result is host- and scenario-specific, not a production authorization guarantee.
- No production ACL/store paths were changed. No private keys were read or used. No node, listener or network was started. No website change, commit, push, merge or release was performed.

## Evidence

- `windows_acl_snapshot_probe.rs` SHA-256: `70BBC0C00105485ADC2DB4409C279D0C80DBFC901204DCA17CFAB8D4E366EF12`
- Worktree branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`
- Worktree HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`

## Next bounded step

Only if the threat model requires it, investigate whether the current token has `SeTakeOwnershipPrivilege` or `SeRestorePrivilege`, and separately test owner reassignment to a SID the token is permitted to assign. Do not infer ownership-change capability from this `WRITE_OWNER` handle-open result.
