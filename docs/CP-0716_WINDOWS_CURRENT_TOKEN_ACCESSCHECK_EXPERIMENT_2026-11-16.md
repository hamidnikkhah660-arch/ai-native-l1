# CP-0716 — Windows Current-Token AccessCheck Experiment

Date: 2026-11-16  
Worktree: `D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116`  
Branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`  
Base HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`

## Scope

Extended the test-only `windows_acl_snapshot_probe` with `access_check_current_process_token(handle, desired_access)`. It:

- retrieves owner, group, DACL and the security descriptor through `GetSecurityInfo` on the supplied handle;
- obtains the current process primary token, duplicates it as a queryable impersonation token at `SecurityImpersonation` level;
- invokes `AccessCheck` with file-object `GENERIC_MAPPING` and a bounded, aligned privilege-set buffer;
- returns desired/granted masks and the boolean access result;
- rejects generic access bits in the requested mask unless mapped by the caller first.

This API exists only inside the Windows test-only module. It is not production-integrated.

## Windows-host result

Command:

`cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib windows_acl_snapshot_probe::tests -- --nocapture`

Result: 4 passed, 0 failed.

The synthetic temporary-directory DACL denies `FILE_WRITE_DATA` to Everyone and allows `READ_CONTROL` to Everyone. `AccessCheck` against the current process token reported:

- `write_allowed=false`
- `read_control_allowed=true`

This confirms that the AccessCheck call path, impersonation-token duplication, descriptor acquisition including owner/group/DACL, and the tested deny/allow evaluation work on this host.

## Security limits

- This is a check for exactly one token: the current process token. It does not enumerate every account, group, logon SID, restricted token, deny-only SID, privilege, or possible future token that may mutate the object.
- It is not an effective-rights inventory for all principals and must not be represented as one.
- `AccessCheck` evaluates the supplied descriptor snapshot; `GetSecurityInfo` does not prevent concurrent security-descriptor changes.
- No production token, service account, owner SID, or mutation-principal allowlist has been selected.
- The helper does not prove namespace immutability or resolve CP-0713's observed rename escape.

## Verification / safety

- Tests use only disposable temporary directories and synthetic DACLs. The DACL mutations are confined to those temporary objects and cleaned up.
- The ACL probe module remains `#[cfg(all(windows, test))]`; it is not compiled into normal library builds.
- No project ACL, real C:/D: path, partition, TPM, key, identity state, node, listener, network, or transfer was touched.
- No startup integration, commit, push, merge, PR update, or release.

## Next gate

CP-0717 should define a conservative all-principal mutation model over raw ACE evidence and token/group semantics, including object/callback/conditional ACE handling, OWNER RIGHTS, generic mapping, parent-child delete/create rights, and privileged principals. A single current-token AccessCheck result is only one input. Do not authorize stores until a reviewed complete model and namespace immutability strategy exist.
