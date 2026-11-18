# CP-0717 — Conservative ACL Mutation-Rights Evidence Model

Date: 2026-11-16  
Worktree: `D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116`  
Branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`  
Base HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`

## Scope

Added a pure conservative evidence derivation function inside the Windows test-only ACL experiment:

`derive_conservative_mutation_evidence(&AclSnapshot)`

It is not a production API and is not connected to either store.

The model:

- Maps file-object `GENERIC_READ`, `GENERIC_WRITE`, `GENERIC_EXECUTE`, and `GENERIC_ALL` using the Windows file generic mapping values.
- Tracks potential namespace/data/security mutation bits: `DELETE`, `WRITE_DAC`, `WRITE_OWNER`, `ACCESS_SYSTEM_SECURITY`, `FILE_WRITE_DATA`/directory `FILE_ADD_FILE`, `FILE_APPEND_DATA`/directory `FILE_ADD_SUBDIRECTORY`, `FILE_WRITE_EA`, `FILE_DELETE_CHILD`, and `FILE_WRITE_ATTRIBUTES`.
- Conservatively treats the owner as having potential `WRITE_DAC`; `OWNER RIGHTS` semantics are not subtracted.
- Treats NULL/absent DACL as granting the Everyone SID (`S-1-1-0`) the entire mutation mask and marks evidence incomplete.
- Adds principals from standard allow ACEs after generic mapping.
- Preserves ACE order in the source snapshot; deny ACEs are never interpreted as grants and are not subtracted from the upper bound.
- Marks the result incomplete if the parser encountered unsupported ACE forms or incomplete structural evidence.
- Deduplicates principals by SID and records contributing allow-ACE indices.

## Tests

Command:

`cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib windows_acl_snapshot_probe::tests -- --nocapture`

Result: 6 passed, 0 failed.

Coverage includes:

1. Handle-bound owner/DACL snapshot and standard ACE parsing.
2. NULL DACL detection and fail-closed behavior.
3. Explicit deny/allow order, masks, trustee SID and inherited ACE evidence.
4. `AccessCheck` against the current process token: synthetic Everyone deny for `FILE_WRITE_DATA` and allow for `READ_CONTROL` produced `write_allowed=false`, `read_control_allowed=true`.
5. Generic-write mapping into data/append mutation rights; deny ACE alone does not create a mutator; owner is conservatively retained as potential DACL mutator.
6. NULL DACL upper-bound handling and unsupported object ACE type failing closed.

## Strict limitations

This is a conservative ACE-derived upper bound, not Windows effective-access evaluation:

- It does not resolve group membership, token attributes, deny-only/disabled groups, restricted tokens, logon SIDs, privileges, or all possible service/operator tokens.
- It does not evaluate ACE deny ordering or subtract denies; this intentionally over-reports potential mutators.
- It does not evaluate object-specific GUID applicability, callback/conditional ACE expressions, `OWNER RIGHTS`, SACL privilege semantics, or every filesystem-specific access right.
- The owner `WRITE_DAC` treatment is conservative and may over-report when `OWNER RIGHTS` ACE semantics apply.
- The `AccessCheck` helper checks exactly the current process token and is not an enumeration of all principals.
- `GetSecurityInfo` does not prevent concurrent security-descriptor changes; snapshots are not locks.
- Parent/ancestor `FILE_DELETE_CHILD`, create-child rights, object `DELETE`, and ACL changes over the entire namespace still require a reviewed model.
- No allowlist or deployment service identity has been selected.

Therefore, neither `structurally_complete` nor `ace_stream_understood` means `acl_complete` for the production policy. This module remains `#[cfg(all(windows, test))]` only.

## Safety / repository state

- ACL mutations were limited to disposable temporary test directories, which were cleaned up.
- No project ACL, real C:/D: path, partition, TPM, key, identity state, node, listener, network, or transfer was touched.
- No startup integration, commit, push, merge, PR update, or release.

## Next gate

CP-0718 should continue with the independent physical-volume identity probe and then return to the complete threat model. Do not infer immutable hardware identity from a volume serial, disk number, or drive letter alone. Do not wire any ACL evidence into startup until all-principal and namespace-mutation semantics are independently reviewed.
