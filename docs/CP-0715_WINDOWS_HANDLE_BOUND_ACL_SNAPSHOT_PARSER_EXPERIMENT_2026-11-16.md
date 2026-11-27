# CP-0715 — Windows Handle-Bound ACL Snapshot Parser Experiment

Date: 2026-11-16  
Worktree: `D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116`  
Branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`  
Base HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`

## Scope

Added `src/native/pow_bench/src/windows_acl_snapshot_probe.rs`, included only under `#[cfg(all(windows, test))]`. It is a test-only Windows experiment, not a production API and not connected to the C/D stores.

The probe:

- Opens disposable test objects with `READ_CONTROL | FILE_READ_ATTRIBUTES` (and `WRITE_DAC` only for test setup) using a retained Win32 handle.
- Calls `GetSecurityInfo` for `SE_FILE_OBJECT` with owner and DACL information on that handle; releases the returned security descriptor with `LocalFree`.
- Reads DACL-present/null/absent and DACL-defaulted state through `GetSecurityDescriptorDacl`.
- Reads `ACL_SIZE_INFORMATION`, iterates ACEs with `GetAce`, validates ACE bounds against `AclBytesInUse`, and preserves each raw ACE byte sequence, type, flags, inherited bit, mask and trustee SID where understood.
- Parses standard `ACCESS_ALLOWED_ACE_TYPE` (0) and `ACCESS_DENIED_ACE_TYPE` (1) layouts. Any other ACE type is retained as raw bytes, listed in `unsupported_ace_types`, and makes `structurally_complete=false`.
- Detects NULL and absent DACLs and marks both incomplete/fail-closed.
- Preserves `dacl_defaulted` separately.

`structurally_complete` means only that this narrow ACE byte parser handled the DACL structure. It does NOT mean effective access has been calculated and must never be used as a substitute for `AccessCheck` or complete trustee analysis.

## Windows-host tests

Command:

`cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib windows_acl_snapshot_probe::tests -- --nocapture`

Result: 3 passed, 0 failed.

1. A temporary directory's handle-bound owner SID and default DACL were read; this host returned 8 standard ACEs, no unsupported ACE types, and a structurally complete parse.
2. A NULL DACL was set only on a disposable temporary directory, detected as `DaclState::Null`, and never marked complete. The temporary directory was removed after the test.
3. A synthetic temporary DACL with a deny ACE followed by an allow ACE was installed only on a disposable temporary directory. The parser preserved ACE order, masks, Everyone SID, and inherited ACE evidence. Parent-inherited ACEs were also present in the resulting descriptor; the test intentionally does not assume a fixed total ACE count.

## Explicit limitations — NOT production-qualified

- This parser understands only standard allow/deny ACEs. Object-specific, callback/conditional, audit/alarm and all other ACE types are preserved raw but not interpreted; any such type makes the result incomplete.
- It does not evaluate deny ordering, object GUID applicability, conditional expressions, group membership, enabled/deny-only token SIDs, restricted tokens, privileges, OWNER RIGHTS, or generic-right mappings into effective rights.
- It does not enumerate all principals who could mutate the object. A single `AccessCheck` against the service token would answer only for that token.
- It does not inspect parent and ancestor ACLs as a complete namespace policy. Parent `FILE_DELETE_CHILD`, create-child rights, and object `DELETE`/`WRITE_DAC`/`WRITE_OWNER` interactions still need to be modeled.
- `GetSecurityInfo` documentation explicitly says it does not handle races with concurrent security-descriptor changes. A snapshot is not a lock and does not prove ACL immutability.
- No production owner SID, service SID, or mutation-principal allowlist has been selected.

## Safety / repository state

- All ACL setup and mutation in tests occurred only on disposable temporary directories created by the tests. No ACLs on project paths or user data were read or changed.
- No C:/D: production path, partition, TPM, key, identity state, node, listener, public network, or transfer was touched.
- No startup integration, commit, push, merge, PR update, or release.
- `windows_acl_snapshot_probe` is test-only and is not compiled into normal library builds.

## Next gate

CP-0716 should add tests for unsupported/object/callback ACE forms and build a conservative rights-evidence model that keeps raw ACE order and generic masks. Only after a reviewed token/group/deny/privilege model exists should a separate `AccessCheck` provider be considered. Do not mark ACL evidence complete or authorize stores based on this parser.
