# CP-0756 - Windows Handle-Bound Store Adapter Contract

Date: 2026-11-17  
Status: **TEST-ONLY CONTRACT AND PROBES PASSED / NATIVE STORE PROVIDER NOT PRODUCTION QUALIFIED / GATE 8 OPEN**

Worktree: D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116  
Branch: feat/cp0704-dual-attestation-rotation-gate-20261116  
Base HEAD (unchanged): 5aba5f69d24fce03af742fd1bebf13ad00e5d9c3

## 1. Objective and isolation

CP-0756 advances the Windows storage boundary from a single retained final-directory handle to a fail-closed adapter contract that describes the identities and relationships required across the root, every ancestor, the STB1 state directory, writer lock, state read, size check, staged file and publication target.

All new contract and provider work remains test-only. No production C:/D: trust-store path, provisioned signer, private key, wallet, node, listener, live network, production ACL, or operational state was read or changed. Test fixtures used synthetic files under the host temporary directory. No dependency was added. No runtime store or provisioner was wired to these experiments. No commit, push, merge, PR, release, or launch action occurred.

## 2. Relative component open: reparse-point handling and name rules

File changed:
src/native/pow_bench/src/windows_relative_open_experiment.rs

The experimental relative-open path no longer relies on OBJ_DONT_REPARSE in OBJECT_ATTRIBUTES. The user-mode NtCreateFile documentation does not clearly establish that flag as a supported contract for this call path. Instead, each child component is opened with FILE_OPEN_REPARSE_POINT, then FILE_ATTRIBUTE_TAG_INFO is queried from that exact returned handle. The open is rejected if the handle identifies a reparse point. The same handle metadata is used to verify that a requested directory is a directory and a requested regular file is not a directory.

Component validation now rejects empty names, dot and dot-dot, separators, colon / alternate data streams, trailing dots or spaces, control characters, names longer than 255 UTF-16 code units, and reserved Windows device names such as CON, PRN, AUX, NUL, COM1-9 and LPT1-9.

The existing relative chain retains the supplied root and each opened component handle and opens each child relative to its preceding parent handle. Every child handle omits FILE_SHARE_DELETE. This remains an experiment: it does not prove the caller supplied a trusted root or that the directory namespace cannot be changed through rights held on an ancestor.

## 3. Root handle identity probe and an important negative result

File changed:
src/native/pow_bench/src/windows_store_handle_probe.rs

The retained final-component probe now opens with FILE_SHARE_READ | FILE_SHARE_WRITE, deliberately omitting FILE_SHARE_DELETE. It also exposes an identity read from the exact retained handle using FILE_ID_INFO: the volume serial number and 128-bit file ID.

The new root test opens the same temporary directory through two independent retained handles and confirms the returned identities match. It then attempts to rename the directory while both no-share-delete handles remain open.

**Observed result on this Windows host:** the directory rename succeeded despite both handles omitting FILE_SHARE_DELETE. The test then opened the renamed directory and confirmed that its FILE_ID_INFO still matched the identity obtained from the original retained handles. The test log records:

OBSERVED: parent FILE_DELETE_CHILD route renamed the root despite retained no-share-delete handles

This is a critical negative security finding, not evidence that the root is protected. A parent directory can authorize a rename through FILE_DELETE_CHILD even when the target directory handle omits FILE_SHARE_DELETE. Earlier CP-0714/CP-0754 ACL experiments also demonstrated that parent and child WRITE_DAC rights, inherited ACE refresh and parent FILE_DELETE_CHILD grants can restore rename routes.

Therefore, share-mode restrictions on a leaf or root handle are insufficient. A native adapter must inspect and constrain mutation-capable rights on every relevant parent and ancestor, including FILE_DELETE_CHILD, DELETE, WRITE_DAC and ownership-changing routes. It must also establish that no unapproved principal can rewrite those ACLs during the operation. No ACL was modified to force the result in this test.

FILE_ID_INFO is useful to correlate the same filesystem object across rename on this host. It does not pin a pathname, prove ancestor containment, authenticate the device, or provide anti-rollback protection.

## 4. Pure handle-bound adapter contract

New file:
src/native/pow_bench/src/windows_store_adapter_contract.rs

Module declaration in lib.rs is gated under cfg(test). The module performs no operating-system I/O and is not connected to production code. It defines a testable evidence contract with:

- an independently pinned root object identity and an independently pinned STB1 store-directory identity;
- an ordered parent-to-child identity chain for every directory component;
- explicit reparse, retained-handle and share-delete facts for each directory;
- complete ACL, owner and mutation-principal evidence for the root, every directory, lock, state and staging objects;
- parent identity for each lock/state/staging file;
- proof that the writer lock is held and that its handle is the exact lock object;
- one exact state-file handle for read and size validation;
- relative-to-store-directory opening for lock, state and staging;
- publication through the staged source handle, followed by reopening the target relative to the same store-directory handle;
- equality of the staged source identity and published target identity.

The validator rejects a mismatched independently pinned root, broken parent-child links, reparse points, unretained or delete-shareable ancestors, incomplete ACL evidence, owner omission, unapproved mutation principals, cross-volume objects, mismatched parents for lock/state/staging, an unlocked writer, path-based or differently bound operations, a size check on a different handle, and publication source/target identity mismatches.

The evidence used by unit tests is synthetic. Passing these policy tests means the contract rejects inconsistent evidence; it does not mean a production provider already collects every field truthfully from native handles.

## 5. Verification results

All commands below ran in the isolated Windows worktree.

| Check | Result |
|---|---:|
| cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib windows_ -- --nocapture --test-threads=1 | **66 passed, 0 failed** (191.36 s) |
| Relative-open experiment suite | **14 passed, 0 failed** |
| Adapter contract suite | **11 passed, 0 failed** |
| Root handle probe suite | **5 passed, 0 failed** |
| Handle-relative publication prototype suite | **3 passed, 0 failed** |
| STB1 regression suite | **18 passed, 0 failed** |
| Shared snapshot-store regression suite | **10 passed, 0 failed** |
| cargo check --manifest-path src/native/pow_bench/Cargo.toml --bins | PASS, with existing unused/dead-code warnings |
| cargo fmt --manifest-path src/native/pow_bench/Cargo.toml --all -- --check | PASS |
| git diff --check | PASS; only existing LF-to-CRLF working-copy notices |

The 66-test Windows run included both subprocess crash-window tests, ACL/ACE and WRITE_DAC experiments, parent FILE_DELETE_CHILD rename tests, reparse/junction checks, component-chain opens, root identity and rename observation, volume/file identity probes, the handle-relative publication prototype and the new adapter contract.

The snapshot-store suite's final-component symbolic-link case remains skipped because this host token lacks the privilege to create the test symlink (Win32 error 1314). The existing junction alias and other snapshot-store tests passed.

The binary check completed without compile errors. It emitted warnings from existing candidate modules and binaries, primarily unused imports and dead code. This checkpoint did not attempt unrelated warning cleanup.

## 6. Explicit limitations and gate disposition

1. The root handle probe initially accepts a path string and inspects only its final component. It does not independently establish the trustworthiness of the ancestors used by the Win32 path parser. The root identity must be pinned by an independent provisioning/enrollment channel before a provider can trust it.
2. The observed parent FILE_DELETE_CHILD route proves that no-share-delete on the directory handle alone does not pin namespace location. All ancestor objects and their effective mutation rights must be obtained from the exact retained handles, and the ACLs must not be rewriteable by unapproved actors.
3. Current ACL probes parse a subset of standard ACEs and exercise the current process token. They do not cover every conditional, callback, object, service-token, privilege or policy combination. The real service/operator SID allowlist has not been independently specified.
4. FILE_ID_INFO correlates filesystem objects on this host but is not a cryptographic trust anchor, hardware attestation, immutable physical-device identity or external monotonic counter.
5. The adapter contract is a synthetic pure-policy model. There is no integrated native provider that binds the writer lock, state reads, size checks, staging, publication and reopen to the same qualified root/ancestor/store-directory handle set.
6. SignerTrustBundleStateStore remains pathname-based. CP-0756 does not connect the handle experiments to STH1 runtime.
7. There is still no independently provisioned remote CAS/witness or TPM monotonic state for whole-volume, VM or host snapshot rollback. Crash-window tests remain application-level process termination tests; they do not simulate power loss, storage-controller cache loss, filesystem corruption or disk failure.

Accordingly, **Gate 8 remains OPEN**. STB1 is not authorized for real signer enrollment, production provisioning, node startup or public-network use. Do not copy test state to production C:/D: directories and do not alter live ACLs based on these experiments.

## 7. Next checkpoint: CP-0757

Keep the provider detached. The next checkpoint should implement an injectable Windows adapter harness around an externally pinned root handle, retain and qualify every ancestor, and retrieve handle-bound owner/DACL/inheritance evidence for each namespace object. It should explicitly test parent FILE_DELETE_CHILD, child DELETE, WRITE_DAC, WRITE_OWNER, ACL mutation races and namespace replacement while lock/read/size/stage/publish operations are in flight.

Only after that evidence can the lock, state read and size-check handles be proven to refer to the same objects in the pinned store directory. Independent remote CAS or a separately protected monotonic witness remains a separate required line of defense against full-volume rollback. Require independent security review before runtime wiring.