# CP-0709 - C Anchor Staged Atomic Publication

Date: 2026-11-16
Project: AI-NATIVE L1 / QRun / QZXB / QFP6
Branch: feat/cp0704-dual-attestation-rotation-gate-20261116
Worktree: D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116
Base commit: 5aba5f69d24fce03af742fd1bebf13ad00e5d9c3
Status: LOCAL PERSISTENCE PRIMITIVE UPDATE / TARGETED TESTS PASS / NOT STARTUP-INTEGRATED

## 1. Change summary

Updated `src/native/pow_bench/src/peer_identity_anchor_vault.rs` so C-side event publication no longer writes directly to the final `event-<sequence>.piv1` pathname.

New append sequence:
1. Validate the event transition in memory before touching disk.
2. Allocate a unique same-directory staging pathname beginning `.peer-identity-event-` using process ID and an atomic process-local counter.
3. Create staging file with `create_new(true)`; write the complete encoded record, flush, and call `sync_all()`.
4. Re-open the staged file, read its exact bytes, decode/check its wire format and digest, and verify exact equality with the intended encoded record, sequence, scope digest, and predecessor digest.
5. Publish to the final sequence name using a platform-specific no-replace operation.
6. Only after publication succeeds, add the event to the in-memory chain.

Windows publication:
- Uses `MoveFileExW` with `MOVEFILE_WRITE_THROUGH`.
- Deliberately omits `MOVEFILE_REPLACE_EXISTING`; an existing final sequence name is a hard failure and cannot be overwritten.
- The staging file is in the same directory, avoiding cross-volume move behavior.

Non-Windows publication:
- Uses a same-directory hard link to create the final name without replacing an existing destination, then attempts to remove the staging name and syncs the parent directory.
- This fallback has not been qualified on every supported filesystem/platform and must not be represented as universally power-loss safe.

## 2. Interrupted staging behavior

On `open()`, any filename beginning `.peer-identity-event-` causes `PeerAnchorError::Corrupt`.

- The vault does not auto-promote, delete, truncate, or ignore an interrupted staging file.
- The staged bytes remain available for explicit forensic/recovery review.
- A final event filename collision is not overwritten.
- This is intentionally fail-closed; no automatic recovery semantics are claimed.

## 3. Tests

Targeted command:
`cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib peer_identity_anchor_vault::tests -- --nocapture`

Result: 11 passed, 0 failed.

New tests:
- `interrupted_staging_file_quarantines_vault_without_auto_repair`: a partial staged file causes open to return Corrupt; bytes remain unchanged.
- `final_event_publication_never_overwrites_existing_sequence`: publication against an existing final filename fails; both existing destination bytes and staged source bytes remain unchanged.

The nine pre-existing vault tests also passed with the staged publication path.

## 4. Important limits / open findings

- This change does not prove full power-loss atomicity or directory-entry durability for every Windows filesystem, storage controller, or removable/network volume. `MOVEFILE_WRITE_THROUGH` is used, but the exact hardware/filesystem durability guarantee still requires qualification.
- The C root path's full ancestor/reparse-point chain, physical volume identity, ACL ownership/inheritance, and handle-based no-follow opens remain unqualified.
- A staging file is treated as a quarantine condition. No operator recovery tool or signed recovery ceremony exists yet.
- No crash-injection matrix has been executed at every write/flush/publish boundary.
- D-side high-water atomic replacement has not been changed by CP-0709.
- Independent provenance for owner/operator public-key pins remains unresolved.
- `activate_prepared(nonce)` remains a low-level append primitive, not a production activation coordinator.
- CP-0707 comparator remains read-only and must not be wired into startup as an automatic repair path.

## 5. Safety and repository boundary

- Only the isolated CP-0704 worktree was changed.
- No real C: or D: production store was opened, initialized, or modified.
- No production/user private keys or identities were accessed.
- Tests used isolated temporary directories and synthetic fixtures.
- No node, listener, testnet, or mainnet was started or activated.
- No commit, push, merge, PR update, or release was performed.
- Original checkout remains separate and untouched.

## 6. Next step

Design the explicit Windows filesystem/volume qualification and handle-based path validation, then build fault-injection tests for stage create/write/flush/sync, staged-byte validation, no-replace publication, and reopen behavior. Do not claim production durability or wire into startup until independent review and separate explicit authorization.