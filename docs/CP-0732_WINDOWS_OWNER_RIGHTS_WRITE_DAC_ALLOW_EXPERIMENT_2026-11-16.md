# CP-0732 — Windows OWNER RIGHTS WRITE_DAC Allow Experiment

Date: 2026-11-16
Worktree: `D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116`
Branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`
Base HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`
Scope: Windows-only, test-only, disposable directory and protected synthetic DACL. No production store, ACL, identity, key, node, listener, network or user data was modified.

## Purpose

Provide the positive control paired with CP-0731. CP-0731 showed that an OWNER RIGHTS deny ACE can suppress owner-implicit `WRITE_DAC`; CP-0732 tests whether an OWNER RIGHTS allow ACE targeted to the same SID can grant `WRITE_DAC` when no other allow ACE contains that right.

## Implementation

- Added `set_owner_rights_write_dac_allow_for_temp_test`.
- The helper installs a protected DACL containing:
  - one standard allow ACE for SID `S-1-3-4` (OWNER RIGHTS) and `WRITE_DAC`;
  - one Everyone allow ACE containing only `READ_CONTROL`, `FILE_READ_ATTRIBUTES` and `SYNCHRONIZE`;
  - no other standard allow ACE containing `WRITE_DAC`.
- Added `owner_rights_allow_grants_write_dac_to_the_owner_token`.
- The test retains a pre-policy handle for cleanup, installs the protected DACL, compares the object owner SID to the token's default owner SID, inspects the ACE stream, calls current-token `AccessCheck(WRITE_DAC)`, and opens a fresh handle requesting `WRITE_DAC`.
- It resets the temporary DACL through the retained pre-policy handle before closing handles and removing the test directory.

## Result

Command:

```powershell
cargo test --lib owner_rights_allow_grants_write_dac_to_the_owner_token -- --nocapture
```

Result: **1 passed, 0 failed, 0 ignored; 1461 filtered out; exit code 0.**

Observed output:

```text
OWNER RIGHTS allow probe: token_default_owner=S-1-5-21-2927852697-1555830555-231538280-1001, object_owner=S-1-5-21-2927852697-1555830555-231538280-1001, owner_match=true, owner_rights_allow_count=1, other_WRITE_DAC_allow_count=0, AccessCheck_WRITE_DAC=true, fresh_WRITE_DAC_handle=true, fresh_error=None
test windows_acl_snapshot_probe::tests::owner_rights_allow_grants_write_dac_to_the_owner_token ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1461 filtered out
```

## Interpretation

- The object owner SID matched the token's default owner SID.
- Exactly one standard allow ACE for OWNER RIGHTS contained `WRITE_DAC`.
- No other standard allow ACE contained `WRITE_DAC`.
- Current-token `AccessCheck(WRITE_DAC)` returned true.
- A fresh post-policy handle requesting `WRITE_DAC` opened successfully.
- The retained pre-policy handle successfully reset the disposable DACL and allowed cleanup.

Paired with CP-0731, this establishes a controlled allow/deny comparison on this Windows host:
- OWNER RIGHTS deny `WRITE_DAC` → AccessCheck denied; fresh handle denied.
- OWNER RIGHTS allow `WRITE_DAC` → AccessCheck allowed; fresh handle opened.

Together with CP-0730, the three checkpoints show that owner-implicit `WRITE_DAC` was observed without an OWNER RIGHTS ACE, while explicit OWNER RIGHTS ACEs can restrict or grant this right for the tested owner token.

## Validation

- Focused CP-0732 test: passed as above, including successful DACL reset and temporary directory cleanup.
- `cargo fmt --all -- --check`: passed.
- `git diff --check`: passed. Git emitted only existing LF-to-CRLF working-copy notices for tracked files.
- No broad test suite was rerun.

## Limitations

- `AccessCheck` evaluated only the current process token. This does not establish behavior for every owner, principal, group composition, restricted/deny-only SID, privilege or impersonation context.
- The experiment is limited to a standard OWNER RIGHTS allow ACE for `WRITE_DAC`. It does not test every combination of OWNER RIGHTS deny/allow masks, inherited OWNER RIGHTS ACEs, object types, or other rights.
- It does not cover `WRITE_OWNER`, ownership reassignment, `SeTakeOwnershipPrivilege`, `SeRestorePrivilege`, or concurrent security-descriptor mutation.
- The result is host- and scenario-specific, not a universal production authorization guarantee.
- No production ACL/store paths were changed. No private keys were read or used. No node, listener or network was started. No website change, commit, push, merge or release was performed.

## Evidence

- `windows_acl_snapshot_probe.rs` SHA-256: `40ECD9886EEE01AD31DBF09D56293953A2C9263402F01D8EA172A93425313742`
- Worktree branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`
- Worktree HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`

## Next bounded step

Probe owner-related mutation rights that are distinct from DACL control: separate `WRITE_OWNER` authorization, ownership reassignment, and privilege-based ownership changes. Do not conflate those with the OWNER RIGHTS `WRITE_DAC` results above.
