# CP-0720 — Read-Only Batch Store-Root Correlation and Runtime Path Provenance

Date: 2026-11-16  
Worktree: `D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116`  
Branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`  
Base HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`

## Implementation

Added `correlate_store_roots()` to the Windows-only test probe. It accepts explicitly supplied `(label, path)` pairs and produces a bounded metadata report:

- Opens each final component through the retained-handle probe.
- Rejects non-directory root objects.
- Queries volume GUID/filesystem and all volume disk extents.
- Correlates each extent to a present SetupAPI disk interface by exact `STORAGE_DEVICE_NUMBER` match.
- Records product metadata and whether each PnP instance ID is present, without emitting the identifier itself.
- Marks correlation complete only if every extent has one matching interface, a nonempty PnP ID, successful descriptor query, vendor/product metadata, and bus type.
- Always sets `hardware_identity_attested=false`; Windows-reported metadata is not a hardware trust anchor.
- Returns per-path stage/error information without creating, repairing, or deleting paths.

This function is compiled and re-exported only from the `#[cfg(all(windows, test))]` probe module. It is not a production CLI, startup hook, or store API.

## Runtime path provenance audit

The source audit found no fixed C:/D: production store root to safely probe:

- `private_testnet_node` derives peer high-water state under `config.data_dir/peer_identity_highwater`; `config.data_dir` is supplied by the runtime `--data-dir` argument.
- `chain_import_node` receives the peer identity state file through the explicit `--peer-noise-identity-state-file` runtime argument and passes that path to `IdentityGenerationStateStore::open`.
- The peer identity anchor vault primitive has no direct production `PeerIdentityAnchorVault::open` callsite in the scanned source tree; it remains a separately implemented primitive and is not wired into node startup.

Therefore, guessing that the production anchor and high-water stores are currently on C: and D: would be incorrect. Actual runtime arguments/configuration must be resolved before any real store-root correlation can be claimed. CP-0720 deliberately probes only disposable test directories.

## Tests

Command:

`cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib windows_volume_identity_probe::tests -- --nocapture`

Result: 4 passed, 0 failed.

Coverage:

1. Valid local volume GUID parsing and rejection of UNC/malformed GUID paths.
2. Retained-handle volume/file metadata and disk-extent to PnP/storage-descriptor correlation.
3. Batch correlation of two disposable sibling roots on the same volume; identical volume GUID and disk set; every extent fully correlated; no file contents read and both test directories remain empty.
4. Missing path produces a typed failure record without creating the path.

Observed test metadata: NTFS, one extent, matched disk interface, PnP ID present, product label `TOSHIBA MQ04ABF100`, bus type `8`. No hardware serial or full PnP identifier is emitted.

## Strict limits

- The handle probe still validates only the final component. Ancestor traversal and namespace replacement races remain unresolved.
- The volume and disk interface are separate handles; the disk-number extent is the explicit correlation bridge.
- PnP ID, product string, bus type, volume serial, and disk number are OS/driver-reported identifiers, not immutable or cryptographically authenticated hardware identity.
- Multi-extent volumes are represented, but no production volume was probed.
- No store contents, production C:/D: paths, ACLs, partitions, TPM, keys, identities, node, listener, network, or transfers were touched.
- No startup/store integration, commit, push, merge, PR update, or release.

## Next gate

CP-0721 should address the remaining ancestor traversal and path-substitution race with a retained directory-handle-relative open prototype (e.g. a carefully reviewed `NtCreateFile`/`RootDirectory` experiment). It must stay test-only, use disposable directories, reject reparse ancestors, and demonstrate that the final object is opened relative to the retained parent handle. Do not wire it into production stores until the NT API contract, object lifetime, sharing, reparse behavior, and crash/error semantics are independently reviewed.
