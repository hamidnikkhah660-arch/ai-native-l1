# CP-0758 — Windows handle-bound store adapter composition probe

Date: 2026-11-17  
Parent: CP-0757 — Windows handle-bound store adapter harness  
Status: **TEST-ONLY COMPOSITION PROBE PASSED / PRODUCTION PROVIDER NOT QUALIFIED / GATE 8 OPEN**

Worktree: D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116  
Branch: feat/cp0704-dual-attestation-rotation-gate-20261116  
Base HEAD (unchanged): 5aba5f69d24fce03af742fd1bebf13ad00e5d9c3

## 1. Objective and isolation

CP-0756 defined a synthetic policy contract; CP-0757 added a Windows handle/ACL evidence harness. CP-0758 composes the main file operations into one test-only sequence using the same retained writer-directory handle: open the state, acquire an exclusive OS lock, read and bound the state, create and sync a staged successor, atomically publish it, reopen the published target and revalidate object identity and ACL evidence.

All operations run only inside disposable temporary test fixtures under `#[cfg(all(windows, test))]`. No production C:/D: trust-store path, real signer, private key, wallet, node, listener, network, account balance, live ACL or operator identity was read or modified. No runtime store or provisioning callsite was changed. No commit, push, merge, PR, release or launch action occurred.

## 2. One retained writer-directory handle

The test obtains a writer-directory handle by opening the `Identity` component relative to the retained `QRun` handle. It compares that handle's `FILE_ID_INFO` identity with the fixture's previously pinned store-directory identity.

The exact writer-directory handle is then used as the `RootDirectory` for all CP-0758 operation opens:
- `state.stb1` is reopened for reading with delete sharing so existing readers can continue to refer to the old object across replacement.
- `writer.lock` is opened relative to the same handle.
- The unique staging file is created relative to the same handle.
- The destination of `NtSetInformationFile` is relative to the same handle.
- The published target is reopened relative to the same handle.

Before and after publication, the test captures store-directory, lock, state and staging observations from those exact handles. It validates parent identities, same-volume identity, ACL completeness, mutation principals and same-handle state-read/size observations against the fixture policy.
## 3. Exclusive writer lock and same-handle read/size check

The test opens the persistent `writer.lock` object relative to the retained writer-directory handle and acquires a nonblocking exclusive byte-range lock through `LockFileEx` (`LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY`). A second open/lock attempt returns `WouldBlock` while the first lock is held. After release, a new lock acquisition succeeds. The lock path is not deleted or replaced.

The state reader records the file identity and size before reading, enforces a maximum byte limit, reads through the same retained file handle, and then checks identity and size again. A file larger than the configured ceiling is rejected before staging or publication.

## 4. Stage, sync, POSIX replacement and reopen

The test creates a uniquely named staging file relative to the pinned writer-directory handle, writes the exact successor bytes, flushes the Rust writer and calls `sync_all` on the writable staging handle before publication. It checks the staging object's identity and size after the write.

The original state remains open for read, so the test uses the documented Windows `FileRenameInformationEx` information class (65) with:
- `FILE_RENAME_REPLACE_IF_EXISTS` (`0x00000001`)
- `FILE_RENAME_POSIX_SEMANTICS` (`0x00000002`)

This is required because legacy `FileRenameInformation` class 10 rejects replacement while the destination has open handles. POSIX semantics allow the old readers to retain the old file object while a new open of the destination name resolves to the staged object. The test verifies both sides: the old state handle still reports the original file ID; the stage handle and reopened published target report the same new file ID; the reopened target contains the exact successor bytes.

The stage bytes are synced before rename. The test does not claim that the parent-directory metadata has been power-loss flushed or that directory-entry durability across sudden power failure has been proven.

## 5. Adversarial and rejection tests

Four CP-0758 tests were added:
1. A second process-local open of the same lock object cannot acquire the exclusive range while the first lock is held; acquisition succeeds again after release.
2. Same-handle read/size, staging, sync, replacement with an existing open reader, published-target reopen and object-ID/content comparison all succeed.
3. An oversized state is rejected before staging/publication, and the original state identity and bytes remain unchanged.
4. A parent `FILE_DELETE_CHILD` mutation injected after staging is detected by handle-bound ACL evidence; the successor is not published and the old state identity/content remain unchanged.

The code does not request `FILE_DELETE_CHILD` on the writer directory for ordinary publication. It opens the existing target with a separate DELETE-capable handle and uses the POSIX replacement semantics for open readers.
## 6. Independent verification on the Windows host

Device: `heymed` (Windows). The combined run was performed after the final same-handle changes, in the isolated worktree.

| Check | Result |
|---|---:|
| CP-0758 focused tests | **4 passed, 0 failed** |
| Combined Windows `windows_` library suite (CP-0756 + CP-0757 + CP-0758) | **78 passed, 0 failed** |
| Filtered out by the targeted command | 1,468 |
| `cargo fmt --manifest-path src/native/pow_bench/Cargo.toml --all -- --check` | PASS |
| `cargo check --manifest-path src/native/pow_bench/Cargo.toml --bins` | PASS; existing unused/dead-code warnings remain |
| `git diff --check` | PASS; existing LF-to-CRLF working-copy notices only |

The 78-test run includes both existing PFM3/PFM4 process-crash-window tests, CP-0756/0757 ACL and namespace probes, and all four CP-0758 tests. This is the targeted Windows suite, not the complete 1,546-test library suite.

The host's volume probe reported NTFS. The POSIX rename operation uses `FileRenameInformationEx` (information class 65), available on Windows 10 version 1709 and later. The operation is fail-closed if the filesystem or OS does not support the required information class; there is no fallback to legacy class 10 when an existing state reader remains open.

Microsoft contracts:
- [FILE_RENAME_INFORMATION and POSIX replacement flags](https://learn.microsoft.com/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_rename_information)
- [FILE_INFORMATION_CLASS values, including FileRenameInformationEx = 65](https://learn.microsoft.com/windows-hardware/drivers/ddi/wdm/ne-wdm-_file_information_class)

## 7. Explicit limitations — not production qualified

1. **Root enrollment remains a fixture.** The initial temporary root is opened by path and the identity obtained from that handle is pinned for the test. It is not an independently provisioned root handle or an external enrollment ceremony.
2. **The operator/SID allowlist remains synthetic.** The harness derives its fixture policy from disposable test ACLs. The real Windows service identity, operator principals, SID allowlist and token/privilege threat model have not been independently specified.
3. **ACL semantics remain partial.** The snapshot parser handles the supported standard ACE subset. It is not a complete evaluator for callback, object, conditional, service-token, group, privilege, OWNER RIGHTS and all Windows access-policy interactions. Unknown or incomplete evidence must continue to fail closed.
4. **Race/ABA resistance is not proven.** Before/after snapshots catch persistent ACL and identity changes. They do not rule out a transient namespace or ACL change that is reversed between observations, or every concurrent interleaving on every filesystem.
5. **This is still not the production STB1 provider.** `SignerTrustBundleStateStore` remains pathname-based. The test-only adapter sequence is not connected to signer enrollment, signer rotation, PIV2, node startup, the provisioner or any production writer.
6. **Power-loss durability is not qualified.** The staged file is flushed and synced before rename, but this test does not prove parent-directory metadata durability, storage-controller cache flush behavior, abrupt power-loss recovery, disk failure or filesystem corruption.
7. **No independent anti-rollback root exists yet.** `FILE_ID_INFO` and the volume serial are local filesystem identity evidence, not hardware attestation, an independent monotonic counter or a remote CAS witness. Whole-volume, VM and host-snapshot rollback remain unresolved.
8. **No independent security review has occurred.** The tests are local evidence only; they are not a substitute for independent review or production qualification.

Accordingly, **Gate 8 remains OPEN**. CP-0758 does not authorize real signer enrollment, production provisioning, node startup, public-network use, mainnet activation, or launch of the QZXB asset.

## 8. Next checkpoint

CP-0759 should specify and qualify the independent root-enrollment channel, real service/operator SID policy and complete effective-access threat model. Only after those inputs are independently pinned should the test-only sequence be promoted into a production Windows store provider. The provider must keep the same-handle invariant, fail closed on unsupported filesystems/ACL semantics, and be reviewed independently before any STB1 runtime callsite is wired.

No production data, live ACLs, signer keys, provider services or external infrastructure were changed by CP-0758. No commit or push was made. Gate 8 remains **OPEN**.
