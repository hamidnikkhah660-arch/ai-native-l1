# CP-0719 — PnP Disk Interface and Storage Descriptor Correlation

Date: 2026-11-16  
Worktree: `D:\Temp\ASUS\QRUN_CP0704_DUAL_ATTESTATION_20261116`  
Branch: `feat/cp0704-dual-attestation-rotation-gate-20261116`  
Base HEAD: `5aba5f69d24fce03af742fd1bebf13ad00e5d9c3`

## Scope

Extended the Windows test-only volume probe to correlate every disk number returned by `IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS` with an actual present disk interface:

1. Enumerate `GUID_DEVINTERFACE_DISK` interfaces through SetupAPI (`SetupDiGetClassDevsW`, `SetupDiEnumDeviceInterfaces`, `SetupDiGetDeviceInterfaceDetailW`).
2. Open each interface read-only (zero desired access) and query `IOCTL_STORAGE_GET_DEVICE_NUMBER`.
3. Accept an interface only when its returned device number exactly matches the volume extent's disk number.
4. Obtain the matched interface's PnP device-instance ID with `SetupDiGetDeviceInstanceIdW`.
5. Query `IOCTL_STORAGE_QUERY_PROPERTY` / `StorageDeviceProperty` on the same matched disk-interface handle and parse the bounded `STORAGE_DEVICE_DESCRIPTOR` fields for vendor, product, revision, and bus type.
6. Validate descriptor header size, every string offset, and NUL termination against the actual returned byte count.
7. Preserve multi-extent results as one `PhysicalDiskEvidence` entry per disk number; no assumption that a volume has only one physical extent.

The test probe intentionally does not retrieve or log the physical disk serial number. The PnP ID is checked for presence but not printed. The volume/file serials and file ID are also not printed in the test output.

## Windows-host result

Command:

`cargo test --manifest-path src/native/pow_bench/Cargo.toml --lib windows_volume_identity_probe::tests -- --nocapture`

Result: 2 passed, 0 failed.

Observed on the disposable test directory:

- One disk extent was returned.
- The SetupAPI disk interface matched the extent's device number.
- A PnP device-instance ID was successfully retrieved.
- A storage descriptor was successfully parsed.
- The descriptor identified product `TOSHIBA MQ04ABF100`, bus type `8` (SCSI enum value).
- The test asserts every returned extent has exactly one matched disk evidence entry, a nonempty PnP instance ID, at least one vendor/product descriptor field, and no descriptor-query error.
- Test output is minimized to filesystem, extent count, matched flag, PnP-ID-present boolean, product label, and bus type; no hardware serial or full PnP identifier is emitted.

The probe test is a host qualification experiment. It does not prove that the PnP ID or descriptor values are immutable, authentic, or resistant to device/firmware spoofing.

## Implementation / ABI notes

- SetupAPI declarations are linked to `setupapi`; kernel and storage I/O declarations are linked to `kernel32`.
- `GUID_DEVINTERFACE_DISK` is represented as a properly laid-out `repr(C)` GUID, avoiding reliance on a byte-array's alignment.
- `SP_DEVICE_INTERFACE_DATA`, `SP_DEVINFO_DATA`, `SP_DEVICE_INTERFACE_DETAIL_DATA_W`, `STORAGE_DEVICE_NUMBER`, `STORAGE_PROPERTY_QUERY`, and the fixed storage descriptor header use explicit C layouts.
- All interface and descriptor reads are bounded; descriptor offsets cannot point into the fixed header or beyond the returned descriptor size.
- `physical_identity_complete` remains hard-coded false.

## Limitations / security boundary

- Disk number is an OS enumeration index, not a durable device identity.
- PnP instance IDs and storage descriptor strings are OS/driver-reported metadata; they can change, be virtualized, or be spoofed. They are corroborating signals only.
- No independent hardware attestation, TPM monotonic counter, signed device identity, or remote witness exists here.
- The volume handle and disk interface handle are different handles. The disk number returned by the volume extent IOCTL is the explicit correlation bridge; this is not a kernel-level proof that all namespace changes are impossible.
- No physical-device ACL, partition, filesystem, volume, or configuration was changed.
- No production path, key, identity state, node, listener, network, or transfer was touched.
- Module remains `#[cfg(all(windows, test))]`; no startup/store integration, commit, push, merge, PR update, or release.

## Next gate

CP-0720 should build a read-only correlation matrix for the known store roots using retained handles and the same volume/PnP evidence pipeline, without opening or mutating any identity-vault contents. It must distinguish C: and D: by resolved volume GUID and full device evidence, detect multi-disk extents, and fail closed on incomplete PnP/descriptor data. Do not convert observed metadata into an immutable hardware trust anchor or wire it into production until independent review and a stronger hardware/remote witness design exist.
