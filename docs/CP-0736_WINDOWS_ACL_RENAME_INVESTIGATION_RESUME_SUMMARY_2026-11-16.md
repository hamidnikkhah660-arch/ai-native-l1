# CP-0736 — Windows ACL / Rename Investigation Resume Summary

Date: 2026-11-16
Project worktree: `D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116`
Protected main checkout: `C:\Users\ASUS\Desktop\AI_NATIVE_L1_G2_G8_20261024` (not modified by this investigation)
Branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`
HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`
Resume point: **CP-0735 complete**

## Why this summary exists

The user experienced a ChatGPT stream interruption during the CP-0730 owner-implicit WRITE_DAC test. The remote process itself completed; its output was recovered and work continued. This document is a durable index of the bounded Windows ACL/rename experiments completed in this isolated worktree so the next session can resume without rerunning them.

## Verified checkpoint index

| Checkpoint | Topic | Result |
|---|---|---|
| CP-0724 | Explicit conflicting ACE order: Deny→Allow vs Allow→Deny | PASS — 1 focused test |
| CP-0725 | Conflicting ACE order inherited by child directory | PASS — 1 focused test |
| CP-0726 | INHERIT_ONLY and NO_PROPAGATE scope | PASS — 1 focused test |
| CP-0727 | OBJECT_INHERIT vs CONTAINER_INHERIT for files/directories | PASS — 1 focused test |
| CP-0728 | Inherited parent FILE_DELETE_CHILD + child DELETE denies vs retained-handle rename | PASS — 1 focused test, after removing an unnecessary marker file that initially prevented cleanup |
| CP-0729 | WRITE_DAC mutation matrix: parent NULL DACL, parent allow + inheritance refresh, child NULL DACL | PASS — 1 focused test, 3 matrix rows |
| CP-0730 | Owner-implicit WRITE_DAC without an explicit allow ACE | PASS — 1 focused test |
| CP-0731 | OWNER RIGHTS deny suppresses owner-implicit WRITE_DAC | PASS — 1 focused test |
| CP-0732 | OWNER RIGHTS allow grants WRITE_DAC to owner token | PASS — 1 focused test |
| CP-0733 | WRITE_OWNER is not implicit from ownership; OWNER RIGHTS allow can grant access | PASS — 1 focused test; object owner was not changed |
| CP-0734 | Read-only token user/group/privilege inventory | COMPLETE — SeTakeOwnershipPrivilege and SeRestorePrivilege absent; Administrators SID is deny-only |
| CP-0735 | Conservative mutation model keeps owner WRITE_DAC upper bound despite OWNER RIGHTS deny | PASS — 1 focused model test |

Detailed evidence is in the correspondingly named files under `docs/`:
- `CP-0724_WINDOWS_CONFLICTING_ACE_ORDER_ACCESSCHECK_EXPERIMENT_2026-11-16.md`
- `CP-0725_WINDOWS_INHERITED_CONFLICTING_ACE_ORDER_EXPERIMENT_2026-11-16.md`
- `CP-0726_WINDOWS_INHERIT_ONLY_NO_PROPAGATE_SCOPE_EXPERIMENT_2026-11-16.md`
- `CP-0727_WINDOWS_OBJECT_CONTAINER_INHERIT_FILE_DIRECTORY_EXPERIMENT_2026-11-16.md`
- `CP-0728_WINDOWS_INHERITED_ACL_RENAME_ESCAPE_EXPERIMENT_2026-11-16.md`
- `CP-0729_WINDOWS_WRITE_DAC_INHERITANCE_RENAME_MATRIX_2026-11-16.md`
- `CP-0730_WINDOWS_OWNER_IMPLICIT_WRITE_DAC_EXPERIMENT_2026-11-16.md`
- `CP-0731_WINDOWS_OWNER_RIGHTS_WRITE_DAC_DENY_EXPERIMENT_2026-11-16.md`
- `CP-0732_WINDOWS_OWNER_RIGHTS_WRITE_DAC_ALLOW_EXPERIMENT_2026-11-16.md`
- `CP-0733_WINDOWS_WRITE_OWNER_OWNER_RIGHTS_EXPERIMENT_2026-11-16.md`
- `CP-0734_WINDOWS_TOKEN_PRIVILEGE_GROUP_INVENTORY_2026-11-16.md`
- `CP-0735_CONSERVATIVE_OWNER_RIGHTS_UPPER_BOUND_TEST_2026-11-16.md`

## Consolidated findings

1. **ACE ordering:** The current Windows host's `AccessCheck` followed the first matching standard allow/deny ACE for the tested requested right. The same conflicting order survived inheritance to the child.
2. **Inheritance scopes:** `INHERIT_ONLY`, `NO_PROPAGATE`, `OBJECT_INHERIT`, and `CONTAINER_INHERIT` produced distinct observed file/directory behaviors. OI-only ACEs propagated to file descendants; CI-only ACEs applied to directory descendants, not file descendants in the tested cases.
3. **Rename path:** The combined inherited parent `FILE_DELETE_CHILD` deny and child `DELETE` deny blocked the tested path-based rename while a child handle was retained without `FILE_SHARE_DELETE`. This is specific to this host, filesystem, token and operation.
4. **WRITE_DAC mutability:** A principal with `WRITE_DAC` on the parent or child could alter one descriptor and reopen a rename path in the tested matrix. Parent DACL replacement refreshed child inherited ACEs in one case. Parent NULL DACL and child NULL DACL were not equivalent.
5. **Owner rights:** Without an OWNER RIGHTS ACE, the current owner token could obtain `WRITE_DAC` implicitly on the tested objects. OWNER RIGHTS deny suppressed that right; OWNER RIGHTS allow granted it. `WRITE_OWNER` was not implicitly granted solely because the token owned the object; an OWNER RIGHTS allow ACE granted the tested handle access.
6. **Model boundary:** `derive_conservative_mutation_evidence` is an upper-bound model, not effective Windows authorization evaluation. It intentionally retains owner `WRITE_DAC` potential when OWNER RIGHTS deny semantics are not interpreted, avoiding a false-negative at the cost of conservative false positives.
7. **Privilege boundary:** The current token did not contain `SeTakeOwnershipPrivilege` or `SeRestorePrivilege`. The Administrators group was present as deny-only. Privilege-based ownership reassignment is therefore **NOT TESTED** in this session.

## Current code / artifact state

- Main code touched by this investigation: `src/native/pow_bench/src/windows_acl_snapshot_probe.rs`.
- Rename test file extended in CP-0728/0729: `src/native/pow_bench/src/windows_relative_open_experiment.rs`.
- Latest `windows_acl_snapshot_probe.rs` SHA-256 after CP-0735:
  `A3C136878894063F8516588C6F65EED851A6AEAC8998DBA8CF96BAB52390FCEC`.
- Latest `windows_relative_open_experiment.rs` SHA-256 from CP-0729:
  `6202CD34661D4D1860504BCC88E03A8C2CABE1D52DD380BD6EEE0705E3BB136F`.
- `cargo fmt --all -- --check`: passed after the latest CP-0735 change.
- `git diff --check`: passed; only pre-existing LF→CRLF working-copy notices appeared.
- No files are staged; no commit or push was made.
- The CP-0704 worktree had many pre-existing untracked checkpoint documents and modifications before this bounded work. Preserve them; do not clean, reset, stage, commit, or push blindly.
- Main checkout remains separate and untouched.
- Public website / GitHub Pages was not changed in this investigation; PR #195 was already merged and the Pages deployment was already verified in the earlier handoff.
- No private keys, wallet material, live node, listener, mainnet, or real asset data were accessed or modified.

## Important interpretation limits

All runtime results are from one Windows host and the current process token, using synthetic DACLs on disposable temporary objects. They are not proof of universal Windows behavior, all-principal authorization, race-free namespace containment, production policy, every rename API, or every filesystem/filter-driver combination. The tests must remain experiments until a full threat model, principal matrix, volume/filesystem coverage, race analysis and production design review are complete.

## Next resume action

Do **not** repeat CP-0724 through CP-0735. Treat the ACL/rename micro-matrix as complete for the current token and host.

The privilege-based owner-reassignment branch is blocked by the current token's missing privileges. Continue only if a separate authorized test token with the required privilege is available. Otherwise, return to the higher-level CP-0703 onward dual-attestation / identity-anchor / rotation-gate plan and inspect its existing checkpoint/design docs before adding more Windows ACL experiments.

## Safety / change control

Continue in this isolated worktree only. Preserve all prior working-tree state. Do not modify main checkout, public site, production store ACLs, private keys, wallet assets, or live network state. Any future changes must have an evidence-backed checkpoint and must not be marked PASS without the actual test output.
