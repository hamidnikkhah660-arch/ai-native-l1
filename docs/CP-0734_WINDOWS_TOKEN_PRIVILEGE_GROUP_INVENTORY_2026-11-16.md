# CP-0734 — Current Windows Token Privilege and Group Inventory

Date: 2026-11-16
Device: `heymed`
Worktree: `D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116`
Scope: read-only token inventory for the interactive PowerShell process used by the Windows experiments. No ACL, object owner, privilege state, key, node, listener, network or user data was changed.

## Purpose

Establish whether the current session can meaningfully test privilege-based ownership changes after CP-0733 separated `WRITE_OWNER` access from actual owner reassignment.

## Commands and observations

Commands:

```powershell
whoami /user
whoami /groups
whoami /priv
```

### User SID

```text
User Name   SID
heymed\asus S-1-5-21-2927852697-1555830555-231538280-1001
```

This matches the owner SID observed by the CP-0730 through CP-0733 test objects and by the current process token's default-owner query.

### Relevant groups

```text
Everyone                      S-1-1-0      Enabled
NT AUTHORITY\Local account and member of Administrators group
                              S-1-5-114    Deny only
BUILTIN\Administrators       S-1-5-32-544 Deny only
BUILTIN\Users                S-1-5-32-545 Enabled
Authenticated Users           S-1-5-11     Enabled
```

The Administrators group SIDs are present only as deny-only groups in this process token; they are not enabled grant groups for this token.

### Token privileges

The complete `whoami /priv` output listed:

- `SeLockMemoryPrivilege` — Disabled
- `SeShutdownPrivilege` — Disabled
- `SeChangeNotifyPrivilege` — Enabled
- `SeUndockPrivilege` — Disabled
- `SeIncreaseWorkingSetPrivilege` — Disabled
- `SeTimeZonePrivilege` — Disabled

Neither `SeTakeOwnershipPrivilege` nor `SeRestorePrivilege` appeared in the token's privilege list.

## Interpretation

- The current test process is running with a non-elevated token whose Administrators group SID is deny-only.
- `SeTakeOwnershipPrivilege` and `SeRestorePrivilege` are not present in this token. They cannot be enabled in this session by merely calling `AdjustTokenPrivileges`.
- Therefore, this session cannot provide a valid positive test of privilege-based ownership reassignment using those two privileges.
- CP-0733 remains a test of `WRITE_OWNER` access checks and handle acquisition only. It must not be promoted to a claim that the owner can assign arbitrary owners.
- Any future positive test of those privilege paths requires a separately authorized test token that actually contains the relevant privilege. Do not elevate the daily user session or modify machine policy just to complete this probe.

## Validation and safety

- Read-only commands completed successfully.
- No token privileges were enabled or adjusted.
- No ownership, ACL, or object descriptor was changed.
- No production path, key, asset, node, listener, public website, commit, push or release was touched.

## Next bounded step

Keep privilege-based owner reassignment marked **NOT TESTED — current token lacks required privileges**. Continue with model-level conservative-bound tests for OWNER RIGHTS semantics rather than attempting an unavailable privilege escalation in this session.
