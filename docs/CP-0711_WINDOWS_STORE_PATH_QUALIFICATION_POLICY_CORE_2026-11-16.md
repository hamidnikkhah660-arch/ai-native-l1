# CP-0711 — Windows Store Path Qualification Policy Core

Date: 2026-11-16
Status: **POLICY CORE IMPLEMENTED / TESTED; NO NATIVE WINDOWS PROVIDER; NOT PRODUCTION QUALIFIED**
Worktree: `D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116`
Branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`
Base HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`

## 1. Scope

Implemented a platform-neutral, injectable policy core in `src/native/pow_bench/src/windows_store_path_qualifier.rs` and exported it from `lib.rs`. It validates evidence that a future Windows provider must collect from the exact retained OS handles used for subsequent I/O.

This is intentionally not a Win32 implementation. It performs no filesystem or OS calls, does not open any real store path, and is not wired into `PeerIdentityAnchorVault`, `IdentityGenerationStateStore`, or startup. Passing unit tests prove policy behavior over supplied evidence only; they do not prove that a real provider can collect truthful evidence.

## 2. Implemented policy surface

- `PhysicalVolumeIdentity`: volume GUID path, filesystem, volume serial, storage device number, and storage device-instance identifier.
- `WindowsStorePathEvidence`: final handle path, complete ancestor/final-component handle walk, reparse-free result, proof that subsequent I/O uses the qualified handle, object kind, physical-volume evidence, owner SID, ACL completeness, and effective mutation-capable principals.
- `WindowsStorePathPolicy`: expected final-path prefix, expected volume identity, expected owner SID, and explicit mutation-principal allowlist.
- `QualificationFailure`: distinct fail-closed results for incomplete handle walk, reparse point, handle/I/O mismatch, wrong object kind, path escape, volume mismatch, unsupported filesystem, owner/ACL failure, unexpected mutation principal, and invalid policy configuration.

The path-prefix comparison is case-insensitive and enforces a component boundary (so `Identity-evil` is not accepted as a child of `Identity`). Policy configuration must itself place its expected path prefix under the expected volume-GUID root. Volume matching checks all supplied identity fields; volume serial alone is not treated as sufficient.

The current policy permits NTFS and ReFS only. This is a conservative policy default, not a statement that all NTFS/ReFS configurations are safe. Mutation-principal SID comparisons are case-insensitive.

## 3. Test results

Command:
`cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib windows_store_path_qualifier::tests -- --nocapture`

Result: **11 passed, 0 failed**.

Coverage includes valid evidence, incomplete ancestor walk, reparse detection, evidence/I/O handle mismatch, path-prefix boundary confusion, changed device identity, unsupported filesystem, incomplete ACL, unexpected mutation principal, owner/object-kind mismatch, invalid policy prefix, and case-insensitive SID allowlist matching.

Also passed:
- `cargo fmt --manifest-path src/native/pow_bench/Cargo.toml --all`
- `git diff --check`

## 4. Explicit limitations

- No Windows API provider exists yet. In particular, there is no implementation of `CreateFileW`/handle-relative path traversal, `FILE_FLAG_OPEN_REPARSE_POINT`, `FileAttributeTagInfo`, `GetFinalPathNameByHandleW`, storage-device IOCTLs, or handle-based security descriptor retrieval.
- Evidence fields are provider assertions. A malicious, buggy, or pathname-based provider could lie; the policy core cannot establish provenance by itself.
- The `device_instance_id` and storage-device number are corroborating device-stack identity signals, not cryptographic hardware attestation. Their stability and interpretation must be tested on the actual supported Windows/storage stack.
- Effective ACL calculation must correctly account for inherited ACEs, deny ACEs, group membership, privileges, and directory-child rights. The policy core trusts the provider's `acl_complete` and effective-principal result.
- No actual C:/D: production directory, ACL, partition, TPM, key, identity, node, or network state was accessed or changed.
- No startup integration, commit, push, merge, PR update, or release occurred.

## 5. Next gate — CP-0712

Implement a Windows-only evidence provider behind a narrow trait, using retained handles throughout the operation. Before production wiring, test it against disposable temporary directories and (only with separate authorization) a disposable VHD/test volume. Include reparse-point ancestors, file substitution races, path identity changes, volume mapping, ACL inheritance/deny ACEs, and lock-file qualification. Independently review the unsafe Win32 FFI and ensure no validated object is reopened by pathname.

Do not select or enforce the real store owner/ACL allowlist until the intended service/operator SIDs and deployment model are confirmed. Do not connect this policy to production stores until CP-0712 provider tests and independent review pass.

## 6. Repository integrity

All work remains in the isolated CP-0704 worktree. The original checkout's `devnet_trust_provisioner.rs` SHA-256 remains `DDD2BBB6D320986CA0DB1A796B3B9DECF14BAD22B9F7D4E7212D6FB9DE451E8F`. No commit was created; the branch HEAD remains the original base commit.
