# CP-0735 — Conservative Owner-Rights Upper-Bound Model Test

Date: 2026-11-16
Worktree: `D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116`
Branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`
Base HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`
Scope: pure model/unit test over a synthetic ACL snapshot. No Windows security descriptor, production ACL, object owner, key, node, listener, network or user data was changed by this test.

## Purpose

Lock in the documented conservative behavior of `derive_conservative_mutation_evidence` after CP-0731 through CP-0733 established that Windows OWNER RIGHTS ACEs can alter effective owner access.

The model already documents that OWNER RIGHTS ACE semantics are not implemented and that its owner-write estimate is an upper bound. CP-0735 adds a regression test so that a future refactor does not accidentally subtract the owner's potential `WRITE_DAC` capability based on a narrow interpretation of OWNER RIGHTS deny ACEs.

## Implementation

- Added `conservative_owner_write_dac_upper_bound_is_not_reduced_by_owner_rights_deny`.
- The synthetic snapshot has a present, structurally complete DACL with one standard deny ACE for SID `S-1-3-4` (OWNER RIGHTS), mask `WRITE_DAC`.
- The test runs `derive_conservative_mutation_evidence` and asserts:
  - the owner principal remains represented;
  - `owner_implicit_write_dac` remains true;
  - the conservative potential mutation mask still includes `WRITE_DAC`;
  - the deny ACE is not turned into an allow principal;
  - the ACE stream remains structurally understood.

## Result

Command:

```powershell
cargo test --lib conservative_owner_write_dac_upper_bound_is_not_reduced_by_owner_rights_deny -- --nocapture
```

Result: **1 passed, 0 failed, 0 ignored; 1463 filtered out; exit code 0.**

Observed output:

```text
test windows_acl_snapshot_probe::tests::conservative_owner_write_dac_upper_bound_is_not_reduced_by_owner_rights_deny ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 1463 filtered out
```

## Interpretation

- CP-0731 demonstrated that an OWNER RIGHTS deny ACE suppressed the current owner's effective `WRITE_DAC` on the tested Windows object.
- CP-0735 does **not** contradict that runtime result. It verifies the separate conservative model contract: the model is an upper bound, not OWNER RIGHTS-aware effective access evaluation.
- The model may therefore conservatively retain a potential owner mutation right even when a runtime OWNER RIGHTS deny removes that right for a particular token/object combination. This is an intentional false-positive bias, not a claim of effective access.

## Validation

- Focused CP-0735 model test: passed as above.
- `cargo fmt --all -- --check`: passed.
- `git diff --check`: passed. Git emitted only existing LF-to-CRLF working-copy notices for tracked files.
- No broad test suite was rerun.

## Limitations

- This test validates only the documented conservative upper-bound behavior. It does not call Windows `AccessCheck` or resolve OWNER RIGHTS semantics.
- The model still does not calculate complete effective access across every ACE type, token group, restricted/deny-only SID, privilege, impersonation context, or concurrent security-descriptor change.
- The model output must not be interpreted as an authorization decision or a claim that OWNER RIGHTS deny is ineffective.
- No production ACL/store paths were changed. No private keys were read or used. No node, listener or network was started. No website change, commit, push, merge or release was performed.

## Evidence

- `windows_acl_snapshot_probe.rs` SHA-256: `A3C136878894063F8516588C6F65EED851A6AEAC8998DBA8CF96BAB52390FCEC`
- Worktree branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`
- Worktree HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`

## Next bounded step

Stop the owner-rights micro-matrix here unless the implementation is being promoted to an effective-access evaluator. Privilege-based owner reassignment remains `NOT TESTED` because the current token did not contain `SeTakeOwnershipPrivilege` or `SeRestorePrivilege` (CP-0734). Keep that limitation explicit; do not infer it from the `WRITE_OWNER` handle-open test.
