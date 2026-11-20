# CP-0714 — Windows Handle-Bound ACL Evidence and Mutation-Rights Audit

Date: 2026-11-16  
Worktree: `D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116`  
Branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`  
Base HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`

## Purpose

CP-0713 established that reparse rejection during a relative open is useful but does not pin a directory's namespace location: the current host allowed a retained child directory to be moved outside its root, and a subsequent child open through that retained handle still succeeded. The next required control is not another path-string check; it is a trustworthy namespace-mutation policy based on owner, DACL, inherited ACEs, and effective rights.

This checkpoint is a documentation/API-contract audit only. No ACL provider or production policy was implemented.

## Verified Windows API contract

### Handle-bound security descriptor retrieval

`GetSecurityInfo` retrieves a security descriptor for an object identified by a handle, including owner and DACL. Reading owner/DACL requires `READ_CONTROL` on the opened handle; the returned descriptor buffer must be released with `LocalFree`.

Important limitation: Microsoft's `GetSecurityInfo` documentation explicitly says the function does not handle race conditions; a concurrent security-descriptor change can cause the call to fail. Therefore, a successful snapshot is evidence about the descriptor returned for that call, not proof that the ACL cannot change immediately afterward.

Reference: https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo

### Effective access checks

`AccessCheck` compares one security descriptor against one impersonation token and a `GENERIC_MAPPING`. It requires a token with `TOKEN_QUERY`; the requested mask must have generic bits mapped first. A NULL DACL grants the requested rights to all callers.

This is not an enumeration of every principal who could mutate an object. An AccessCheck against the current process/service token only answers for that token. Windows access checks consider user, group, and logon SIDs in the token; disabled and deny-only group SIDs have special semantics.

References:
- https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-accesscheck
- https://learn.microsoft.com/en-us/windows/win32/secauthz/how-dacls-control-access-to-an-object
- https://learn.microsoft.com/en-us/windows/win32/api/Winnt/ns-winnt-generic_mapping

### File and directory mutation surface

A complete namespace policy must consider, at minimum:

- `DELETE` on an object;
- `FILE_DELETE_CHILD` on its parent directory;
- `WRITE_DAC` and `WRITE_OWNER` (ability to change the security boundary);
- `FILE_ADD_FILE` and `FILE_ADD_SUBDIRECTORY` on directories;
- data-integrity rights where applicable: `FILE_WRITE_DATA`, `FILE_APPEND_DATA`, `FILE_WRITE_EA`, and `FILE_WRITE_ATTRIBUTES`;
- generic rights after correct file/directory `GENERIC_MAPPING`.

The ACL of a child alone is insufficient to decide whether it can be removed or replaced: the parent directory's delete-child and create-child rights matter. Every ancestor and the final object need their own handle-bound descriptor evidence. Inherited ACEs appear in the object's DACL and must not be silently ignored.

Reference: https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights

## Design decisions for a future provider

1. Open each object with `READ_CONTROL` and `FILE_READ_ATTRIBUTES` on the exact handle that is inspected. If `READ_CONTROL` cannot be obtained, return a typed fail-closed result.
2. Retrieve owner and DACL using `GetSecurityInfo(handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, ...)`; never use a second pathname lookup for the ACL.
3. Validate the security descriptor, owner SID, DACL-present flag, ACL header/count/size, each ACE size and SID bounds. Null DACL, absent DACL, malformed ACL, unsupported ACE forms, or incomplete enumeration must fail closed.
4. Preserve raw ACE type, flags, mask, trustee SID, and inherited status. Do not collapse the DACL to a list of allow ACEs without accounting for deny ordering, object-specific ACEs, callback/conditional ACEs, and group/token semantics.
5. Use `AccessCheck` only for explicit checks against the actual service/operator token. Do not present that single result as an enumeration of all principals.
6. Until object-specific, callback/conditional, restricted-token, group, deny-only, owner, and privilege semantics are completely handled, return `acl_complete = false` and never pass the policy gate.
7. Do not choose a production owner SID or mutation-principal allowlist from the current interactive laptop account. Deployment/service identity and threat model must be explicitly established first.
8. Do not automatically repair ACLs. A mismatch is a quarantine/diagnostic condition, not permission to change owner or DACL.
9. Because GetSecurityInfo does not lock the descriptor against concurrent changes, a production design must additionally establish how the namespace and its security descriptors are protected against untrusted mutation for the lifetime of use. A second snapshot/hash alone is not an atomicity guarantee.

## Current status

- No ACL APIs have been called against real C:/D: project paths.
- No owner, DACL, SACL, privilege, token, or account settings were changed.
- No production store integration.
- CP-0712 final-component probe remains a narrow primitive only.
- CP-0713 relative-open harness remains test-only; it is not compiled into normal library builds.
- No commit, push, merge, PR update, or release.

## Next gate

CP-0715 may implement a read-only ACL snapshot/parser against disposable temporary files/directories only. It must preserve raw ACE evidence, explicitly identify unsupported ACE forms, and fail closed. Tests should include NULL/absent DACL, allow/deny ordering, inherited ACEs, object ACEs, callback ACEs, owner changes, generic rights, and parent-vs-child delete/create rights. No real ACL changes or production allowlist selection are authorized by this checkpoint.
