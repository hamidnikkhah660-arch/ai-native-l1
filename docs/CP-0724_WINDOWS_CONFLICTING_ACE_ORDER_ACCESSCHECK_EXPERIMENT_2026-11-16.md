# CP-0724 — Windows Conflicting ACE Order / AccessCheck Experiment

Date: 2026-11-16
Worktree: `D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116`
Branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`
Scope: Windows-only, test-only, disposable temporary directory and synthetic DACL. No production store, ACL, identity, key, node, listener, network or user data was modified.

## Purpose

Extend the CP-0715/0716 ACL snapshot and current-token AccessCheck probes with a controlled conflict: the same trustee receives both a deny and an allow ACE for `FILE_WRITE_DATA`. The only variable is ACE order. This is a distinct experiment from CP-0721/0722/0723, which exercised path-chain and parent/child delete authorization.

## Implementation

- Added `set_conflicting_write_dacl_for_temp_test(handle, deny_first)` to the Windows-only ACL probe.
- The helper installs two explicit ACEs for Everyone (`S-1-1-0`): a deny ACE for `FILE_WRITE_DATA`, and an allow ACE for `FILE_WRITE_DATA | READ_CONTROL`. The boolean selects their insertion order.
- Exported the helper under `cfg(windows)` for the test module.
- Added `conflicting_ace_order_changes_current_token_access_check_result`.
- The test applies deny-first, calls `AccessCheck` for the current process token, and snapshots the DACL; it then repeats with allow-first. It asserts the resulting ACE type order and expected access decision.
- The test resets the disposable directory to a NULL DACL before closing the handle and removing the temporary directory.

## Result

Command:

```powershell
cargo test --lib conflicting_ace_order_changes_current_token_access_check_result -- --nocapture
```

Result: **1 passed, 0 failed, 0 ignored; 1453 filtered out; exit code 0.**

Observed output:

```text
ACE order probe: deny_first_allowed=false, allow_first_allowed=true
test windows_acl_snapshot_probe::tests::conflicting_ace_order_changes_current_token_access_check_result ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 1453 filtered out
```

Interpretation: on this Windows host, for the current process token and the synthetic DACL used here, deny-first rejects the requested write right, while allow-first grants it before the later conflicting deny ACE is reached. The snapshot assertions also confirm that the tested DACL order is observed as installed. This is a host- and scenario-specific result, not a universal security-boundary proof.

## Validation

- `cargo fmt --all`: completed successfully before the focused test.
- `cargo fmt --all -- --check`: passed after the test.
- `git diff --check`: passed. Git emitted only existing LF-to-CRLF working-copy notices for tracked project files.
- Focused CP-0724 test: passed as above.
- No broad test suite was rerun.

## Limitations

- `AccessCheck` evaluated only the current process token. It does not prove access for every service principal, group composition, restricted/deny-only SID, privilege, or impersonation context.
- The DACL is synthetic and temporary. This test does not qualify inherited/object/callback/conditional ACE combinations, all filesystem implementations, filter drivers, concurrent descriptor changes, or namespace races.
- The test demonstrates one concrete ACE-order interaction for one requested right; it is not a complete Windows ACL evaluator or production policy.
- No production ACL/store paths were changed. No private keys were read or used. No node, listener or network was started. No website change, commit, push, merge or release was performed.

## Evidence

- `windows_acl_snapshot_probe.rs` SHA-256: `117D2A4B0BBBCD769811ED50A15540F0A0E271A9231AA97C6CD25BEE41969CF7`
- Worktree branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`
- Worktree HEAD at checkpoint creation: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`

## Next bounded step

Continue the authorization matrix without rerunning CP-0721/0722/0723 or CP-0724. Investigate whether inherited ACE placement and explicit ACE order produce a distinct, measurable result in a disposable parent/child layout. Preserve the current-token and synthetic-test-DACL limitations, and do not infer universal namespace safety from these experiments.
