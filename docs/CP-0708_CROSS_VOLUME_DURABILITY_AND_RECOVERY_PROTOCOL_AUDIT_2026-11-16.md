# CP-0708 - Cross-Volume Durability and Recovery Protocol Audit

Date: 2026-11-16
Project: AI-NATIVE L1 / QRun / QZXB / QFP6
Branch: feat/cp0704-dual-attestation-rotation-gate-20261116
Worktree: D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116
Base commit: 5aba5f69d24fce03af742fd1bebf13ad00e5d9c3
Status: SOURCE AUDIT / DESIGN ONLY; NO STARTUP INTEGRATION; NO PRODUCTION PATHS TOUCHED

## 1. Purpose

CP-0708 audits the actual CP-0706 peer-identity anchor persistence primitive, the D-side IdentityGenerationStateStore persistence path, and the CP-0707 read-only comparator. It defines the work that must precede any startup gate or cross-volume recovery writer.

This is not a claim that the local two-disk design is hardware-backed or resistant to full-device rollback. C: and D: are separate physical disks per the prior hardware inventory, but both remain under the same local machine/admin trust boundary.

## 2. Confirmed implementation facts

### 2.1 C-side PeerIdentityAnchorVault

Source: src/native/pow_bench/src/peer_identity_anchor_vault.rs.

- `open()` requires an absolute root path, checks the final root component with `symlink_metadata`, acquires a stable `SnapshotWriterLock`, enumerates `event-*` files, checks each event file as regular/non-symlink, and validates sequence, scope digest, predecessor digest, record digest, and state transition across the complete chain.
- `append()` assigns the next sequence, seals the record, validates the transition, opens the final `event-<sequence>.piv1` path with `create_new(true)`, writes the complete wire record, calls `sync_all()`, then adds the event to the in-memory chain.
- `prepare_rotation()` enforces a single pending successor, exact next generation, previous generation/digest binding, distinct nonzero owner/operator pins, and nonce uniqueness against prior PREPARED events. Exact retry of the currently pending identical event is idempotent.
- `activate_prepared()` accepts only the nonce of the latest PREPARED event and appends an exact copy with kind changed to ROTATION_ACTIVE. It does not itself verify signatures, NPI1/NRT1, independent pin provenance, process reload, or session drain; those remain caller obligations.
- The event chain retains PREPARED history after activation, so historical nonce reuse remains detectable.

### 2.2 D-side IdentityGenerationStateStore

Source: src/native/pow_bench/src/identity_generation_store.rs.

- The store holds a stable writer lock for its lifetime and persists a fixed-size state through a uniquely named temporary file opened with `create_new(true)`.
- It writes, flushes, and `sync_all()`s the temporary file before atomic replacement.
- On Windows, replacement uses `MoveFileExW` with `REPLACE_EXISTING | WRITE_THROUGH`; on Unix, it uses rename and syncs the parent directory.
- The persisted tuple binds generation, exact KeyRecord digest, identity projection digest, and lifecycle. Advancing generation requires the exact issuer-signed NRT1 successor statement.
- Opening an absent state file and absent stable lock initializes an empty high-water state. That is not identity enrollment; CP-0707 correctly reports it as uninitialized.

### 2.3 CP-0707 comparator

- It is read-only and never repairs either store.
- It recognizes exact synchronization, C-side PREPARED while D remains at the exact prior active tuple, D advanced to the pending generation before C activation, and other generation/digest/lifecycle mismatches.
- When C has already recorded ROTATION_ACTIVE but D is still exactly one generation behind, the current comparator returns a generic generation mismatch. It does not classify this as a recoverable state and must not be changed to silently synchronize it.

## 3. Durability and filesystem findings

### F-01 - C event is written directly to its final pathname (HIGH)

`append()` creates the final event filename before writing the complete record. A process crash, power loss, or disk-full condition during `write_all()` can leave a truncated final event. On reopen, the full-chain validator rejects the vault, which is fail-closed, but there is no bounded recovery procedure for distinguishing an incomplete tail from tampering. Do not delete or truncate the tail automatically.

Required design: stage a uniquely named temporary record in the same directory, write and sync it, validate its exact bytes, then publish it atomically to the final sequence name with no-overwrite semantics. Define exact Windows and Unix publication/durability behavior and test crash points before and after publication. A pre-existing final sequence path is a hard conflict, never an overwrite.

### F-02 - C directory-entry durability is not qualified (HIGH)

The C append path calls `sync_all()` on the event file but does not explicitly sync/flush the containing directory after creating the final pathname. File-content durability and directory-entry durability are distinct. The D store has stronger explicit Windows write-through replacement and Unix parent-directory sync behavior. Do not assume the C append has equivalent power-loss semantics.

Required design: select and document platform-specific directory metadata durability primitives; test on the actual Windows filesystem and storage stack. If the platform cannot provide a defensible guarantee, state the limitation and require post-crash full-chain verification without claiming atomic durable commit.

### F-03 - Path and volume trust are not established by `open()` (HIGH)

The C vault checks the final root component for symlink status but does not establish the physical volume identity, verify the full ancestor path against reparse points, or qualify ACL ownership/inheritance. Event files are checked with `symlink_metadata` and then opened by path, leaving a possible check/open race. The D high-water path likewise relies on its configured path and lock behavior rather than a completed C/D volume-identity and ACL qualification ceremony.

Required design: provision explicit absolute paths; verify expected physical disk identity and filesystem; verify ACLs and inherited permissions; reject reparse points across all relevant path components; use handle-based open semantics where supported to avoid path-swap races; and revalidate file identity/attributes after opening. No production path may be opened until this qualification is designed and separately authorized.

### F-04 - Pin provenance and pin rotation are not implemented (HIGH)

CP-0704 validates a caller-supplied public key against a caller-supplied fingerprint. This proves consistency of the supplied pair, not who supplied or authorized the pin. The C vault primitive stores owner/operator pin fingerprints but does not establish their provenance. In addition, `validate_transition()` requires both fingerprints to remain identical to the preceding active event, so the current schema intentionally has no pin-change ceremony.

Required design: provision initial pins out-of-band into separately protected trust configuration; define an explicit dual-authorized pin-rotation event with old-pin and new-pin binding, rollback/replay protection, and recovery rules. Until then, treat the pin set as immutable and do not claim that caller-supplied pins authenticate the owner/operator.

### F-05 - Activation API is a low-level append primitive, not an activation gate (HIGH)

`activate_prepared(nonce)` checks only that the latest event is PREPARED and the nonce matches, then appends ROTATION_ACTIVE. It does not verify the prepared artifact against NPI1/NRT1, check that the D store still matches the predecessor, prove that the new trust configuration is installed, enforce session drain/bounded lifetime, or prove that a reload succeeded.

Required design: keep this method inaccessible to production startup/rotation callers until a higher-level activation coordinator verifies every artifact and precondition, performs the required reload/session policy, and records a durable activation decision. An API accepting only a nonce is insufficient as the trust boundary.

### F-06 - C-ACTIVE / D-behind recovery needs a distinct typed decision (HIGH)

The proposed safe ordering writes C ROTATION_ACTIVE before advancing D high-water. A crash between those steps leaves C one generation ahead. CP-0707 currently reports generic `IdentityGenerationMismatch` for this state. It must remain fail-closed, but a future read-only classifier may distinguish an exact one-generation C-anchored successor from rollback or arbitrary divergence only after verifying the C event's predecessor digest, NRT1 digest, artifact digest, generation, identity scope, and issuer signature. A separate recovery writer may then advance D only with the exact C-anchored successor. The comparator itself must remain read-only.

Required design: expose enough immutable metadata from the latest C ACTIVE event to verify the exact predecessor-to-successor relation. Do not classify C-ahead as recoverable based on generation numbers alone. Gaps greater than one, same-generation digest/lifecycle conflicts, missing anchors, and any failed signature/evidence check remain quarantined.

## 4. Required cross-volume state machine

The future state machine must distinguish at least:

1. `D_ACTIVE(n), C_ACTIVE(n)` - synchronized baseline.
2. `D_ACTIVE(n), C_PREPARED(n+1)` - candidate prepared, old identity remains active; startup may continue only under an explicit old-identity policy and must never load the candidate as active.
3. `D_ACTIVE(n), C_ACTIVE(n+1)` - C activation committed, D is exactly one authorized successor behind; startup remains closed until the exact signed C-anchored artifact advances D and both stores reopen in exact sync.
4. `D_ACTIVE(n+1), C_ACTIVE(n)` - D advanced before C activation; reject and quarantine.
5. Any missing C enrollment, missing/empty D state after enrollment, gap greater than one, same-generation digest/lifecycle mismatch, wrong scope, invalid chain, invalid ACL/volume identity, or invalid NPI1/NRT1 - reject and quarantine.

No cross-volume atomicity is claimed. Every transition must be idempotent only for exact byte-identical artifacts and exact nonce/intent/generation bindings. Conflicting retries are hard failures.

## 5. Crash-injection matrix required before integration

Inject termination or simulated I/O failure at each boundary:

- D candidate temporary file create/write/flush/sync/publish;
- C event temporary file create/write/flush/sync/validate/publish;
- C directory metadata flush;
- C PREPARED reopen/full-chain validation;
- artifact installation and trust reload;
- C ROTATION_ACTIVE event publish and reopen;
- D NRT1 verification and high-water temp write/sync/atomic replacement;
- both stores reopen and exact comparison;
- session drain/expiry boundary.

For every crash point, specify which identity is permitted to start, which artifact is quarantined, whether an exact retry is allowed, and which states require operator recovery. Never auto-delete a possibly committed event or recreate C from D.

## 6. Next engineering sequence

1. Design the C event temp-write/atomic-publish protocol and Windows directory durability qualification.
2. Design physical-volume, path/reparse, ACL, and handle-based file-open qualification.
3. Define immutable initial pin provisioning and explicit pin-rotation ceremony.
4. Design a typed read-only C-ACTIVE/D-behind classifier carrying exact predecessor and successor bindings.
5. Only then design a separate recovery writer and activation coordinator with crash-injection tests.
6. Startup/listener integration remains blocked until all of the above pass independent review and receives separate explicit authorization.

## 7. Safety and repository boundary

- This checkpoint is an audit/design artifact only; no Rust source changed for CP-0708.
- No real C: or D: production store was opened, initialized, or modified.
- No production/user private key or identity was accessed.
- No node, listener, testnet, or mainnet was started or activated.
- No commit, push, merge, PR update, or release was performed.
- Original checkout remains separate and untouched; CP-0704 changes remain isolated in this worktree.