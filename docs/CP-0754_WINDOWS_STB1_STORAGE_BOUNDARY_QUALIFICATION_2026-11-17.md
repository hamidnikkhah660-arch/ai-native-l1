# CP-0754 - Windows STB1 Storage Boundary Qualification

Date: 2026-11-17  
Status: **ISOLATED WINDOWS TEST QUALIFICATION PASS / PRODUCTION STORAGE PATH NOT QUALIFIED**

Worktree: D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116  
Branch: feat/cp0704-dual-attestation-rotation-gate-20261116  
Base HEAD (unchanged): 5aba5f69d24fce03af742fd1bebf13ad00e5d9c3

## 1. Scope and safety

CP-0754 re-qualified the Windows-only storage experiments relevant to the STB1 local high-water store and checked the exact STH1 and shared atomic-store regressions. Work was restricted to test fixtures below the host temporary directory. No production C:/D: trust-store path, provisioned signer, private key, wallet, node, listener, network, partition, or production ACL was read or changed.

The host temporary root observed for tests was D:\Temp\ASUS. Its inherited ACL includes Modify for Authenticated Users; it is therefore treated as an untrusted scratch root only. It is not an acceptable trust root for signer pins, identity state, or other security-critical material. Individual temporary test directories were used for synthetic data and disposable ACL experiments.

No dependency was added. No runtime caller was wired to the Windows probes. No commit, push, merge, PR, release, or mainnet action occurred.

## 2. Harness correction

The first parallel Windows qualification run reported 48 passed / 1 failed. The sole failure occurred before the test body, while creating its temporary root, with Win32 error 183 (AlreadyExists). The exact test then passed alone (1/1), confirming that the ACL/rename assertion itself was valid but the timestamp-only temporary-name helper could collide under parallel execution on this Windows host.

The test-only windows_relative_open_experiment::tests::temp_root helper now appends a process-local atomic AtomicU64 sequence to the process ID. It does not alter store implementation or security policy. The complete Windows filter was then rerun single-threaded to avoid fixture interference with the intentional subprocess crash tests.

## 3. Verification results

All commands were run from the isolated worktree against the Windows host.

| Check | Result |
|---|---:|
| cargo fmt --manifest-path src/native/pow_bench/Cargo.toml --all -- --check | PASS |
| cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib signer_trust_bundle:: -- --nocapture --test-threads=1 | 18 passed, 0 failed |
| cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib snapshot_store:: -- --nocapture --test-threads=1 | 10 passed, 0 failed |
| cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib windows_ -- --nocapture --test-threads=1 | 49 passed, 0 failed (143.01 s) |

STB1 tests cover strict bundle verification, explicit checkpoint bootstrap, restart persistence, replay/sequence rollback rejection, same-sequence conflict rejection, corrupt/missing state fail-closed behavior, and signer lifecycle transitions.

Snapshot-store tests cover atomic first-write/replace/load, pre-commit fault behavior, post-replace recovery, competing writer locks, junction alias canonicalization, and process reopen. The final-symlink test was counted as passed by the existing harness but emitted a skip because this Windows token lacks the privilege to create a symbolic link (error 1314); this specific symlink case was not exercised in that run.

The 49 Windows-filtered tests cover the policy-core fail-closed cases, final-component handle probing, intermediate reparse rejection in the experimental relative walk, retained-handle path experiments, owner/DACL/ACE parsing, current-token AccessCheck, inherited ACE ordering, rename/delete-child and WRITE_DAC mutation scenarios, volume/file identity collection, disk-extent/PnP correlation, and the two subprocess manifest crash-window tests. Both crash-window tests completed successfully in the serial run.

## 4. Host observations and security significance

- The temporary test path resolved to NTFS and the read-only retained-handle probe returned one disk extent. The volume/file and disk/PnP evidence is useful correlation, but it is not an immutable device identity or hardware attestation.
- The experimental relative-open tests confirmed that a retained child-directory handle, even when opened without delete sharing, did not by itself prevent the child namespace entry from being renamed outside the original root on this host. A subsequent relative open through the retained handle still succeeded.
- Synthetic parent FILE_DELETE_CHILD and child DELETE denies blocked the tested rename. A parent grant for FILE_DELETE_CHILD, or the tested parent/child WRITE_DAC mutations, could restore a rename route in other matrix cases. This demonstrates why checking only the leaf DACL is insufficient.
- The policy core correctly rejects supplied evidence for incomplete ancestor walks, reparse points, mismatched handles, unsupported filesystems, wrong volume/owner, incomplete ACL data, and unexpected mutators. Those are policy tests over synthetic evidence, not proof that a native provider can collect complete and truthful evidence.
- The volume probe intentionally reports physical_identity_complete = false; disk number, PnP instance, descriptor data, volume serial and file ID are OS-reported correlation evidence, not cryptographic trust anchors.

## 5. Explicit limits - Gate 8 remains open

1. SignerTrustBundleStateStore::open and the shared writer continue to use pathname-based operations. The Windows probes are not integrated into STH1 reads/writes or the writer lock; there is no guarantee that the file inspected and the object later read/replaced are the same retained handle.
2. The STH1 state file and its sibling lock remain local filesystem state. A full-volume, VM, or host snapshot rollback is not detected by an external monotonic witness. No TPM NV counter or independent remote CAS/witness was provisioned or qualified.
3. The current ACL experiments exercise a subset of standard ACE structures and the current process token. They do not enumerate every possible principal, privilege, conditional/callback/object ACE, service token, or all effective access combinations. No real operator/owner SID allowlist has been selected.
4. The temporary volume observation does not qualify the actual intended trust-store roots or establish separate physical-device independence. No production C:/D: path was opened for this checkpoint.
5. The crash tests exercise application-level failpoints and process termination. They do not simulate physical power loss, controller cache loss, filesystem corruption, disk removal/failure, or whole-machine rollback.

Accordingly, **STB1 is not authorized for real signer enrollment, production provisioning, node startup, or public-network use.** Do not copy test state into C:/D: production stores and do not repair live ACLs automatically.

## 6. Next gate

CP-0755 keeps the boundary detached and focuses on an injectable, handle-bound storage adapter design for STH1:
- prove that state-file reads, size checks, and replacement all refer to the exact qualified object/parent identity, without reopening by untrusted path;
- bind the stable writer lock to the same validated directory and object namespace;
- define explicit fail-closed Windows ACL/owner policy only after the real service/operator identity model is independently specified;
- design an external monotonic witness or multi-store CAS protocol for full-volume rollback, then test only with synthetic stores and disposable media.

Do not wire the existing experimental provider into runtime until its ancestor-walk, namespace-mutation, volume, ACL, and handle-I/O guarantees have an independent review.