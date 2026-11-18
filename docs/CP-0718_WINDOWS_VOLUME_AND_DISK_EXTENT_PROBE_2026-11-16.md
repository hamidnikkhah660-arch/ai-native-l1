# CP-0718 — Windows Volume and Disk-Extent Probe

Date: 2026-11-16  
Worktree: `D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116`  
Branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`  
Base HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`

## Scope

Added `windows_volume_identity_probe.rs`, compiled only for Windows unit tests. It performs read-only evidence collection:

- `GetFileInformationByHandleEx(FileIdInfo)` on the retained directory handle to capture the 128-bit file ID and volume serial from that same handle.
- `GetVolumeInformationByHandleW` on that handle to capture filesystem, volume label, serial, and flags.
- Derives and strictly parses the local volume GUID path from the handle's final path.
- Opens that volume GUID path with zero desired access and queries `IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS`; validates the returned extent count and bounds before reading disk numbers.
- Captures whether the second volume-handle serial corroborates the retained file handle serial.
- Explicitly reports `physical_identity_complete=false`: this probe does not collect a PnP device-instance identity, storage descriptor identity, or hardware attestation.
- Rejects network/non-local final paths and malformed GUIDs rather than silently treating them as local volumes.

The disk-extent query is a separate volume-handle query. It is useful corroborating metadata, not proof that the retained object handle is cryptographically or immutably tied to a particular physical device.

## Host test result

Command:

`cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib windows_volume_identity_probe::tests -- --nocapture`

Result: 2 passed, 0 failed.

Observed on this host's disposable temp directory:

- Filesystem: NTFS
- Volume GUID: `\\?\Volume{6940d5ce-0646-4a0e-bda2-9d6e1092232c}\`
- Volume serial: `520BBB08`
- File-ID volume serial: `08520BC9520BBB08`
- Disk extents: `[0]`
- Extent query: successful
- Independent volume-handle serial corroboration: unavailable (`None`), so no equality claim is made.

Tests also reject a network UNC path and a malformed GUID.

## Compile correction during this run

The first combined test attempt encountered two compile errors in the adjacent test-only ACL probe. The volume probe was then corrected and re-run; the final volume-probe command completed successfully with exit code 0 and the two passing tests above. The earlier failed attempt is not represented as a passing run.

## Limits / safety

- Disk number and volume serial are not immutable physical identity. No PnP device-instance ID, storage descriptor, TPM counter, or independent hardware witness was obtained.
- `physical_identity_complete` is intentionally hard-coded false.
- No real C:/D: store path, ACL, partition, TPM, key, identity state, node, listener, network, or transfer was touched. Tests use only a disposable temp directory.
- No production integration, startup integration, commit, push, merge, PR update, or release.

## Next gate

CP-0719 should collect the PnP/storage descriptor identity from the disk number(s), correlate it with the volume GUID and retained file-handle evidence, and explicitly model multi-extent volumes. It must remain read-only and test-only. Do not use a disk number or serial alone as a hardware trust anchor.
