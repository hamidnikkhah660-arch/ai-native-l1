# CP-0731 — Windows OWNER RIGHTS WRITE_DAC Deny Experiment

Date: 2026-11-16
Worktree: `D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116`
Branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`
Base HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`
Scope: Windows-only, test-only, disposable directory and protected synthetic DACL. No production store, ACL, identity, key, node, listener, network or user data was modified.

## Purpose

Follow CP-0730's evidence for owner-implicit `WRITE_DAC` with a test of the special `OWNER RIGHTS` SID (`S-1-3-4`). The experiment asks whether an explicit deny ACE for OWNER RIGHTS can suppress the current owner's otherwise implicit `WRITE_DAC` right.

## Implementation

- Added `set_owner_rights_write_dac_deny_for_temp_test`.
- The helper installs a protected DACL containing:
  - one standard deny ACE for SID `S-1-3-4` and `WRITE_DAC`;
  - one Everyone allow ACE containing only `READ_CONTROL`, `FILE_READ_ATTRIBUTES` and `SYNCHRONIZE`;
  - no standard allow ACE containing `WRITE_DAC`.
- Added `owner_rights_deny_can_remove_owner_implicit_write_dac`.
- The test creates a disposable directory and retains a pre-policy handle that already has `WRITE_DAC`, solely for cleanup.
- It applies the protected DACL, confirms the object's owner SID equals the current process token's default owner SID, inspects the DACL for exactly one OWNER RIGHTS deny and zero WRITE_DAC allow ACEs, then performs current-token `AccessCheck(WRITE_DAC)`.
- It also tries to open a fresh handle requesting `WRITE_DAC`. The retained pre-policy handle resets the DACL before the directory is removed.

## Result

Command:

```powershell
cargo test --lib owner_rights_deny_can_remove_owner_implicit_write_dac -- --nocapture
```

Result: **1 passed, 0 failed, 0 ignored; 1460 filtered out; exit code 0.**

Observed output:

```text
OWNER RIGHTS probe: token_default_owner=S-1-5-21-2927852697-1555830555-231538280-1001, object_owner=S-1-5-21-2927852697-1555830555-231538280-1001, owner_match=true, owner_rights_deny_count=1, owner_rights_deny_flags=[0], WRITE_DAC_allow_ACE_count=0, AccessCheck_WRITE_DAC=false, fresh_WRITE_DAC_handle=false, fresh_error=Some("Access is denied. (os error 5)")
test windows_acl_snapshot_probe::tests::owner_rights_deny_can_remove_owner_implicit_write_dac ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 1460 filtered out
```

## Interpretation

- The object's owner SID matched the token's default owner SID.
- Exactly one standard deny ACE for OWNER RIGHTS contained the `WRITE_DAC` bit.
- No standard allow ACE in the DACL contained the `WRITE_DAC` bit.
- Current-token `AccessCheck(WRITE_DAC)` returned false.
- A fresh file handle requesting `WRITE_DAC` failed with Windows error 5 (`ERROR_ACCESS_DENIED`).
- The retained pre-policy handle successfully reset the disposable DACL and allowed cleanup.

Together with CP-0730, this demonstrates on this Windows host that owner-implicit `WRITE_DAC` was available without an OWNER RIGHTS ACE, but a standard OWNER RIGHTS deny ACE suppressed it for the tested owner token.

## Validation

- Focused CP-0731 test: passed as above, including fresh-handle denial, DACL reset through the retained handle, and directory cleanup.
- `cargo fmt --all -- --check`: passed.
- `git diff --check`: passed. Git emitted only existing LF-to-CRLF working-copy notices for tracked files.
- No broad test suite was rerun.

## Limitations

- `AccessCheck` evaluated only the current process token. This does not prove the result for every owner, principal, group composition, restricted/deny-only SID, privilege or impersonation context.
- The test covers only an OWNER RIGHTS deny for `WRITE_DAC`. It does not test an OWNER RIGHTS allow ACE, `READ_CONTROL`, other rights, or complex inherited OWNER RIGHTS ACE placement.
- It does not cover `WRITE_OWNER`, ownership reassignment, `SeTakeOwnershipPrivilege`, `SeRestorePrivilege`, or concurrent descriptor changes.
- The result is host- and scenario-specific, not a general production authorization guarantee.
- No production ACL/store paths were changed. No private keys were read or used. No node, listener or network was started. No website change, commit, push, merge or release was performed.

## Evidence

- `windows_acl_snapshot_probe.rs` SHA-256: `95871143A71F860E0F5BCC8763DF1F1081CF6E067FEECAB81F205E4498BEA428`
- Worktree branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`
- Worktree HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`

## Next bounded step

Add the matching OWNER RIGHTS allow control, granting only `WRITE_DAC` to SID `S-1-3-4`, while retaining the protected DACL and no other WRITE_DAC allow. Confirm whether the current owner then passes `AccessCheck` and can open a fresh WRITE_DAC handle. Keep this separate from ownership-change privileges.
