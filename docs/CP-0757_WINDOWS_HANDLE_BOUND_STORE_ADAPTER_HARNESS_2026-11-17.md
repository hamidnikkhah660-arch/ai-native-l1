# CP-0757 — Windows handle-bound store adapter harness

**Date:** 2026-11-17  
**Parent:** CP-0756 — Windows Handle-Bound Store Adapter Contract  
**Status:** Test-only Windows adapter harness implemented and qualified on the current Windows host. Not a production provider, not wired to STB1 runtime, and not a Gate 8 closure.

## 1. Objective

CP-0756 established that a retained root handle and omission of `FILE_SHARE_DELETE` are not sufficient namespace protections: a parent directory's `FILE_DELETE_CHILD` right can still permit a child directory to be renamed. CP-0757 turns the policy contract into an executable, injectable harness that retains the root/ancestor/store-directory objects, reads identity and ACL evidence from the exact handles, and rejects changed namespace or mutation-right evidence.

The implementation is isolated behind `#[cfg(all(windows, test))]` in `windows_store_adapter_harness.rs`. It does not execute during ordinary builds or node startup.

## 2. Implemented harness

- The fixture obtains one retained root directory handle. A production implementation must replace this test fixture's initial path open with an independently provisioned and pinned root handle.
- Each descendant is opened as one validated path component relative to the preceding retained directory handle through `NtCreateFile(RootDirectory=parent)`. Traversal, alternate streams, reserved components, reparse points and file/directory-kind mismatches are rejected.
- Root, each ancestor, the store directory, writer-lock object, state object and staging object retain separate handles. Each object's volume serial and 128-bit file ID are queried from its own retained handle.
- Owner, DACL state, raw ACEs, trustee SID, ACE mask, inheritance flags and supported-ACE completeness are read from the exact retained handle. Unknown ACE types and NULL/absent DACLs remain incomplete and fail closed.
- A conservative mutation-right upper bound is derived for DELETE, WRITE_DAC, WRITE_OWNER, ACCESS_SYSTEM_SECURITY, FILE_WRITE_DATA, FILE_APPEND_DATA, FILE_WRITE_EA, FILE_DELETE_CHILD and FILE_WRITE_ATTRIBUTES. Policy checks every retained namespace object against an explicit SID allowlist.
- The state read and size observation use the same retained state handle; the object ID is sampled around the size observation to detect accidental handle rebinding.
- The baseline and later observations can be compared between operation phases. A persistent ACL or object-identity change is rejected.

## 3. Adversarial cases exercised

The CP-0757 harness includes eight Windows tests:

1. Accepts a valid retained root → ancestor → store-directory chain and confirms lock/state/stage parent identity and same-handle state read/size evidence.
2. Detects an injected Everyone `FILE_DELETE_CHILD` grant on the parent.
3. Detects OWNER RIGHTS `WRITE_DAC` added to the state object's DACL.
4. Detects OWNER RIGHTS `WRITE_OWNER` added to the state object's DACL.
5. Detects a persistent ACL change between adapter phases.
6. Reproduces the parent-mediated rename route in a disposable tree: after dropping the target-directory handle but retaining its parent, the test grants the parent `FILE_DELETE_CHILD`, renames `Identity`, creates a replacement directory under the same name, and verifies the replacement's file ID differs from the pinned original.
7. Records an inherited mutation ACE on the descendant directory and checks the descendant object itself against the tightened policy.
8. Rejects NULL/incomplete ACL evidence.

## 4. Validation evidence on 2026-11-17

Windows device: `heymed`.

| Validation | Result |
|---|---:|
| CP-0757 focused harness | 8 passed, 0 failed |
| Combined Windows `windows_` library suite (CP-0756 + CP-0757) | **74 passed, 0 failed** |
| `cargo fmt --manifest-path src/native/pow_bench/Cargo.toml --all -- --check` | PASS |
| `cargo check --manifest-path src/native/pow_bench/Cargo.toml --bins` | PASS; existing unused/dead-code warnings remain |
| `git diff --check` | PASS; Git emitted existing LF-to-CRLF working-copy notices |

The 74-test suite includes the prior ACL/ACE and AccessCheck experiments, parent `FILE_DELETE_CHILD` and child `DELETE` cases, inherited ACE behavior, retained-handle rename observations, relative component-chain opens, reparse/junction checks, handle-relative publication prototype, volume/file identity probes, and both existing process-crash-window tests.

## 5. Explicit limitations — do not promote this to production

1. **Root enrollment is still a fixture.** The test opens the root by path and pins the ID obtained from that handle. It does not provide an independent provisioning channel or a trust anchor for the configured root and ancestors.
2. **The allowlist is synthetic.** The test policy derives expected principals from disposable fixture ACLs and tightens them in adversarial tests. The real service/operator SID allowlist and token/privilege threat model have not been independently specified.
3. **ACL semantics are partial.** The parser understands standard allow/deny ACEs. It is not a complete Windows effective-access evaluator for callback, object, conditional, service-token, group, privilege, OWNER RIGHTS and every policy interaction. Unsupported/incomplete evidence must continue to fail closed.
4. **Race/ABA resistance is not proved.** Before/after snapshots catch persistent changes. They do not rule out a transient ACL or namespace change that is reversed between observations, nor do they establish a documented filesystem guarantee for every concurrent rename/replacement interleaving.
5. **This is not a full store adapter.** The harness opens and identifies a writer-lock object but does not acquire a real exclusive OS lock. It binds test state and staging handles, but does not yet compose the production writer-lock acquisition, size limits, complete STB1 state read, stage creation, flush/durability, atomic publication and reopen into one adapter using the same qualified handle set.
6. **No production runtime callsite is wired.** `SignerTrustBundleStateStore` remains pathname-based. CP-0757 does not connect these test-only handles to STB1 enrollment, signer rotation, node startup or a production writer.
7. **No independent anti-rollback root exists yet.** FILE_ID_INFO and volume serial are local filesystem identity evidence, not physical-device attestation, an independent monotonic counter, TPM-backed state or a remote CAS witness. Whole-volume/VM/host snapshot rollback remains a separate Gate 8 threat.
8. **Crash qualification remains bounded.** Existing subprocess crash-window tests are application-level process termination tests, not power-loss, controller-cache loss, disk failure or filesystem-corruption tests.

## 6. Gate disposition and next step

CP-0757 closes the *design-to-test-harness step* for retained-handle identity/ACL observation and proves the parent `FILE_DELETE_CHILD` namespace-rebinding case on this Windows host. It does **not** close Gate 8 and does not authorize real signer enrollment, production provisioning, node startup or public-network use.

Next checkpoint should compose a real Windows store adapter around an independently provisioned root handle and a separately defined operator/SID allowlist. It must acquire and hold the real writer lock, perform state read/size-check/stage/publish/reopen through the same retained root/ancestor/store handles, revalidate the pinned IDs at every phase, and run concurrent namespace/ACL replacement and crash/recovery tests. Independently administered remote CAS or a separately protected monotonic witness, plus independent security review, remain mandatory before runtime wiring.

No production data, live ACLs, signer keys, real balances, provider services or external infrastructure were changed by CP-0757. Gate 8 remains **OPEN**.
