# CP-0721 — Component-Relative Path Chain Experiment

Date: 2026-11-16  
Worktree: `D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116`  
Branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`  
Base HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`

## Implementation

Extended the Windows test-only `windows_relative_open_experiment` module with:

- `open_path_chain_experimental(root, components, final_kind)`: opens one validated path component at a time using `NtCreateFile` and the preceding retained directory handle as `OBJECT_ATTRIBUTES.RootDirectory`.
- Intermediate components are opened as directories; the final component uses the requested directory/file kind.
- Every component is a single name; empty names, `.`, `..`, slash/backslash, NUL, and overlong names are rejected.
- Each child open sets `OBJ_DONT_REPARSE`, omits `FILE_SHARE_DELETE`, and requests only read-attributes/synchronize access.
- `RelativePathHandleChain` retains a cloned root handle and every successfully opened component handle for the chain lifetime.
- Added tests for a three-component path, intermediate junction rejection, empty/traversal rejection, and retained-handle behavior.

The experiment is still `#[cfg(all(windows, test))]`, not linked into production stores.

## Windows-host test results

Targeted path-chain command:

`cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib windows_relative_open_experiment::tests -- --nocapture`

Result: 8 passed, 0 failed.

Volume/PnP correlation regression:

`cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib windows_volume_identity_probe::tests -- --nocapture`

Result: 4 passed, 0 failed.

Combined Windows-focused regression:

`cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib windows_ -- --nocapture`

Result: 36 passed, 0 failed. This also exercised existing anti-rollback and store crash-window tests selected by the `windows_` filter.

## Critical observed limitation — rename escape persists

The retained-child experiment on this host produced:

`rename outside root succeeded while child handle remained open without FILE_SHARE_DELETE; descendant open through retained handle also succeeded`

This is a direct negative result. Component-relative `NtCreateFile`, retained parent/child handles, `OBJ_DONT_REPARSE`, and omission of `FILE_SHARE_DELETE` do **not** establish containment against concurrent directory rename on this host/filesystem configuration. A retained handle continues to address the moved directory object after its pathname has been moved outside the original root.

Consequences:

- Do not call this a race-free path walk or a root-containment guarantee.
- Do not use the chain to authorize production store reads/writes.
- A production design must additionally control namespace mutation at the parent/root level (including `FILE_DELETE_CHILD` and rename-capable principals), use an independently protected namespace/volume, or adopt another reviewed mechanism. A current-token-only ACL check is not enough.
- Any ACL/oplock/namespace-lock mitigation must be tested against the exact observed rename operation and its parent-directory rights; do not assume child share mode blocks parent-mediated rename.

## Safety / repository state

- All tests used disposable temporary directories and synthetic payloads/junctions. No project store contents were read.
- No real C:/D: store root, ACL, partition, TPM, key, identity state, node, listener, network, or transfer was touched.
- No startup integration, commit, push, merge, PR update, or release.

## Next gate

CP-0722 should isolate the rename path and test parent-directory namespace controls, especially `FILE_DELETE_CHILD`, with a synthetic DACL and a disposable parent directory. It must determine which principal/handle actually performs the rename and whether parent ACL denial blocks it. Keep the test-only boundary. If Windows/filesystem behavior still permits a rename escape, record that limitation and do not promote this API to production.
