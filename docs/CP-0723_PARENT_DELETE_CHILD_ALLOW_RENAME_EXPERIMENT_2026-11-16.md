# CP-0723 — Parent FILE_DELETE_CHILD Authorization Route Experiment

Date: 2026-11-16
Worktree: `D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116`
Branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`
Scope: Windows-only, test-only, disposable temporary directories. No production store, ACL, identity, key, node, listener, network or user data was modified.

## Purpose

Complete the paired rename-authorization experiment begun in CP-0722. CP-0722 established that denying both child `DELETE` and parent `FILE_DELETE_CHILD` blocked the tested rename. CP-0723 isolates the alternative route: allow parent `FILE_DELETE_CHILD` while denying child `DELETE`.

## Implementation

- Added `set_parent_allow_delete_child_for_temp_test` to the Windows-only ACL test probe.
- Exported the helper from `windows_acl_snapshot_probe` for the sibling Windows-only test module.
- Added `parent_delete_child_allow_authorizes_rename_even_when_child_delete_is_denied` to `windows_relative_open_experiment`.
- The test uses a disposable parent/child/sibling layout, applies synthetic test DACLs, checks the current process token, attempts the rename, resets the temporary DACLs, closes handles and cleans up the temporary directories.

## Result

Command:

```powershell
cargo test --lib parent_delete_child_allow_authorizes_rename_even_when_child_delete_is_denied -- --nocapture
```

Result: **1 passed, 0 failed, 0 ignored; 1452 filtered out; exit code 0.**

Observed output:

```text
Parent FILE_DELETE_CHILD route: parent_access=Ok(true), child_DELETE_access=Ok(false), rename_succeeded=true
test windows_relative_open_experiment::tests::parent_delete_child_allow_authorizes_rename_even_when_child_delete_is_denied ... ok
```

Interpretation: on this Windows host and for the current process token and tested filesystem/path, parent `FILE_DELETE_CHILD` authorization permits the rename even when the child object's `DELETE` right is denied. Therefore, a namespace containment policy must control both relevant authorization paths; denying only one is insufficient for this tested case.

## Validation

- `cargo fmt --all -- --check`: passed.
- `git diff --check`: passed (Git emitted only existing LF-to-CRLF working-copy notices for tracked project files).
- Targeted CP-0723 test: passed as above.
- No broad test suite was rerun; CP-0723 used one targeted test only.

## Limitations

- `AccessCheck` evaluates the current process token only; it does not prove access for all service principals, groups, restricted/deny-only SIDs, privileges or impersonation contexts.
- DACLs are synthetic and temporary. This does not model every inherited ACE, owner-right, conditional/object ACE, callback ACE, filesystem, filter driver or namespace race.
- This experiment does not establish a complete Windows security boundary and is not production-integrated.
- No production ACLs or store directories were changed. No private keys were read or used. No node, listener or network was started. No commit, push, merge or release was performed.

## Hashes

- `windows_acl_snapshot_probe.rs` SHA-256: `4B64D61B6D9F856BBE6524D5CEE4C2828C4491C8B50148F89EB4F61646CEB33F`
- `windows_relative_open_experiment.rs` SHA-256: `8E986AF2F1B4E143B6A4065122306DC98A03F2EDC40A4627A16AA5EFDD27956C`
- Original checkout `devnet_trust_provisioner.rs` SHA-256 remains `DDD2BBB6D320986CA0DB1A796B3B9DECF14BAD22B9F7D4E7212D6FB9DE451E8F`.

## Next bounded step

Continue with a narrowly scoped, test-only authorization matrix covering ACE ordering and parent/child rights combinations. Preserve the CP-0721/0722/0723 negative and positive observations. Do not infer universal namespace safety from these host-specific tests.
