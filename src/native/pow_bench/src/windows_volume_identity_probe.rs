//! Read-only volume metadata and disk-extent probe, test-only.
//!
//! Volume metadata is queried by the retained file handle. Disk extents are
//! queried through a second volume handle opened by the GUID path derived from
//! that file handle. This does not establish immutable physical-device identity:
//! no PnP device-instance ID or hardware attestation is collected.

#[cfg(windows)]
mod imp {
    use crate::windows_store_handle_probe::{open_final_component, WindowsStoreHandleProbe};
    use std::ffi::c_void;
    use std::fs::File;
    use std::io;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};
    use std::path::Path;

    type Handle = *mut c_void;
    const FILE_ID_INFO_CLASS: i32 = 18;
    const OPEN_EXISTING: u32 = 3;
    const FILE_SHARE_READ_WRITE: u32 = 0x3;
    const IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS: u32 = 0x0056_0000;
    const IOCTL_STORAGE_GET_DEVICE_NUMBER: u32 = 0x002D_1080;
    const IOCTL_STORAGE_QUERY_PROPERTY: u32 = 0x002D_1400;
    const DIGCF_PRESENT: u32 = 0x2;
    const DIGCF_DEVICEINTERFACE: u32 = 0x10;
    const ERROR_NO_MORE_ITEMS: i32 = 259;
    const ERROR_INSUFFICIENT_BUFFER: i32 = 122;

    #[repr(C)]
    struct FileIdInfo {
        volume_serial_number: u64,
        file_id: [u8; 16],
    }

    #[repr(C)]
    struct StorageDeviceNumber {
        device_type: u32,
        device_number: u32,
        partition_number: u32,
    }
    #[repr(C)]
    struct StoragePropertyQuery {
        property_id: u32,
        query_type: u32,
        additional_parameters: [u8; 1],
    }
    #[repr(C)]
    struct StorageDeviceDescriptorHeader {
        version: u32,
        size: u32,
        device_type: u8,
        device_type_modifier: u8,
        removable_media: u8,
        command_queueing: u8,
        vendor_id_offset: u32,
        product_id_offset: u32,
        product_revision_offset: u32,
        serial_number_offset: u32,
        bus_type: u32,
        raw_properties_length: u32,
    }
    #[repr(C)]
    struct Guid {
        data1: u32,
        data2: u16,
        data3: u16,
        data4: [u8; 8],
    }

    #[repr(C)]
    struct SpDeviceInterfaceData {
        cb_size: u32,
        interface_class_guid: [u8; 16],
        flags: u32,
        reserved: usize,
    }
    #[repr(C)]
    struct SpDevinfoData {
        cb_size: u32,
        class_guid: [u8; 16],
        dev_inst: u32,
        reserved: usize,
    }
    #[repr(C)]
    struct DiskExtent {
        disk_number: u32,
        alignment: u32,
        starting_offset: i64,
        extent_length: i64,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetFileInformationByHandleEx(
            file: Handle,
            class: i32,
            info: *mut c_void,
            size: u32,
        ) -> i32;
        fn GetVolumeInformationByHandleW(
            file: Handle,
            volume_name: *mut u16,
            volume_name_size: u32,
            volume_serial: *mut u32,
            maximum_component_length: *mut u32,
            filesystem_flags: *mut u32,
            filesystem_name: *mut u16,
            filesystem_name_size: u32,
        ) -> i32;
        fn CreateFileW(
            file_name: *const u16,
            desired_access: u32,
            share_mode: u32,
            security_attributes: *mut c_void,
            creation_disposition: u32,
            flags_and_attributes: u32,
            template_file: Handle,
        ) -> Handle;
        fn DeviceIoControl(
            device: Handle,
            control_code: u32,
            input_buffer: *mut c_void,
            input_buffer_size: u32,
            output_buffer: *mut c_void,
            output_buffer_size: u32,
            bytes_returned: *mut u32,
            overlapped: *mut c_void,
        ) -> i32;
    }

    #[link(name = "setupapi")]
    unsafe extern "system" {
        fn SetupDiGetClassDevsW(
            class_guid: *const Guid,
            enumerator: *const u16,
            hwnd_parent: Handle,
            flags: u32,
        ) -> Handle;
        fn SetupDiEnumDeviceInterfaces(
            device_info_set: Handle,
            device_info_data: *const SpDevinfoData,
            interface_class_guid: *const Guid,
            member_index: u32,
            device_interface_data: *mut SpDeviceInterfaceData,
        ) -> i32;
        fn SetupDiGetDeviceInterfaceDetailW(
            device_info_set: Handle,
            device_interface_data: *const SpDeviceInterfaceData,
            detail_data: *mut c_void,
            detail_data_size: u32,
            required_size: *mut u32,
            device_info_data: *mut SpDevinfoData,
        ) -> i32;
        fn SetupDiGetDeviceInstanceIdW(
            device_info_set: Handle,
            device_info_data: *const SpDevinfoData,
            device_instance_id: *mut u16,
            device_instance_id_size: u32,
            required_size: *mut u32,
        ) -> i32;
        fn SetupDiDestroyDeviceInfoList(device_info_set: Handle) -> i32;
    }
    #[derive(Debug, Clone, Eq, PartialEq)]
    pub struct WindowsVolumeEvidence {
        pub disk_devices: Vec<PhysicalDiskEvidence>,
        pub volume_guid_path: String,
        pub volume_name: String,
        pub filesystem_name: String,
        pub volume_serial_number: u32,
        pub file_id_volume_serial_number: u64,
        pub file_id_128: [u8; 16],
        pub filesystem_flags: u32,
        pub disk_numbers: Option<Vec<u32>>,
        pub disk_extent_error: Option<i32>,
        pub volume_handle_serial_matches: Option<bool>,
        /// Always false: a PnP device-instance identifier and hardware attestation are absent.
        pub physical_identity_complete: bool,
    }

    #[derive(Debug, Clone, Eq, PartialEq)]
    pub struct PhysicalDiskEvidence {
        pub disk_number: u32,
        pub device_instance_id: Option<String>,
        pub vendor_id: Option<String>,
        pub product_id: Option<String>,
        pub product_revision: Option<String>,
        pub bus_type: Option<u32>,
        pub descriptor_version: Option<u32>,
        pub descriptor_error: Option<i32>,
        pub enumerated_interfaces: u32,
        pub matched_disk_number: bool,
        pub setupapi_error: Option<i32>,
        pub detail_error: Option<i32>,
    }

    pub fn probe_volume(probe: &WindowsStoreHandleProbe) -> io::Result<WindowsVolumeEvidence> {
        let volume_guid_path = extract_volume_guid_path(probe.final_path())?;
        let mut file_id = FileIdInfo {
            volume_serial_number: 0,
            file_id: [0; 16],
        };
        // SAFETY: file_id is correctly sized/writable; the exact inspected handle is retained by probe.
        let ok = unsafe {
            GetFileInformationByHandleEx(
                probe.handle().as_raw_handle(),
                FILE_ID_INFO_CLASS,
                (&mut file_id as *mut FileIdInfo).cast(),
                std::mem::size_of::<FileIdInfo>() as u32,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }

        let (volume_name, filesystem_name, volume_serial_number, filesystem_flags) =
            volume_info_by_handle(probe.handle())?;

        // Naming-a-Volume contract: CreateFile opens a volume GUID path without
        // its trailing slash; the trailing slash would open the volume root directory.
        let volume_device_path = volume_guid_path.trim_end_matches('\\');
        let wide: Vec<u16> = volume_device_path
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: wide is NUL-terminated; desired access is zero (metadata query only).
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                0,
                FILE_SHARE_READ_WRITE,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };
        let (disk_numbers, disk_extent_error, volume_handle_serial_matches) =
            if raw == -1isize as Handle {
                (
                    None,
                    Some(io::Error::last_os_error().raw_os_error().unwrap_or(-1)),
                    None,
                )
            } else {
                // SAFETY: raw is a new valid volume handle owned by this function.
                let volume_handle = unsafe { File::from_raw_handle(raw as RawHandle) };
                let serial_match = volume_info_by_handle(&volume_handle)
                    .map(|(_, _, serial, _)| serial == volume_serial_number)
                    .ok();
                match query_disk_numbers(volume_handle.as_raw_handle()) {
                    Ok(numbers) => (Some(numbers), None, serial_match),
                    Err(error) => (None, Some(error.raw_os_error().unwrap_or(-1)), serial_match),
                }
            };

        let disk_devices = match &disk_numbers {
            Some(numbers) => probe_disk_devices(numbers),
            None => Vec::new(),
        };

        Ok(WindowsVolumeEvidence {
            disk_devices,
            volume_guid_path,
            volume_name,
            filesystem_name,
            volume_serial_number,
            file_id_volume_serial_number: file_id.volume_serial_number,
            file_id_128: file_id.file_id,
            filesystem_flags,
            disk_numbers,
            disk_extent_error,
            volume_handle_serial_matches,
            physical_identity_complete: false,
        })
    }

    fn volume_info_by_handle(handle: &File) -> io::Result<(String, String, u32, u32)> {
        let mut volume_name = vec![0u16; 261];
        let mut filesystem_name = vec![0u16; 261];
        let mut serial = 0u32;
        let mut maximum_component_length = 0u32;
        let mut filesystem_flags = 0u32;
        // SAFETY: output buffers and scalar pointers are valid; handle is live.
        let ok = unsafe {
            GetVolumeInformationByHandleW(
                handle.as_raw_handle(),
                volume_name.as_mut_ptr(),
                volume_name.len() as u32,
                &mut serial,
                &mut maximum_component_length,
                &mut filesystem_flags,
                filesystem_name.as_mut_ptr(),
                filesystem_name.len() as u32,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((
            wide_to_string(&volume_name)?,
            wide_to_string(&filesystem_name)?,
            serial,
            filesystem_flags,
        ))
    }

    fn wide_to_string(buffer: &[u16]) -> io::Result<String> {
        let length = buffer.iter().position(|value| *value == 0).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "Win32 string not terminated")
        })?;
        String::from_utf16(&buffer[..length]).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "Win32 returned invalid UTF-16")
        })
    }

    pub(super) fn extract_volume_guid_path(final_path: &str) -> io::Result<String> {
        let prefix = "\\\\?\\Volume{";
        if !final_path.starts_with(prefix) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "final handle path has no local volume GUID (network/unsupported namespace)",
            ));
        }
        let close = final_path.find('}').ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "malformed volume GUID path")
        })?;
        let guid_text = &final_path[prefix.len()..close];
        let valid_guid = guid_text.len() == 36
            && [8usize, 13, 18, 23]
                .iter()
                .all(|index| guid_text.as_bytes()[*index] == b'-')
            && guid_text.bytes().enumerate().all(|(index, byte)| {
                [8usize, 13, 18, 23].contains(&index) || byte.is_ascii_hexdigit()
            });
        if !valid_guid {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid volume GUID path",
            ));
        }
        let guid = &final_path[..=close];
        Ok(format!("{guid}\\"))
    }

    fn probe_disk_devices(disk_numbers: &[u32]) -> Vec<PhysicalDiskEvidence> {
        let mut result = Vec::new();
        for number in disk_numbers {
            result.push(probe_one_disk(*number));
        }
        result
    }

    fn probe_one_disk(disk_number: u32) -> PhysicalDiskEvidence {
        const GUID_DEVINTERFACE_DISK: Guid = Guid {
            data1: 0x53F56307,
            data2: 0xB6BF,
            data3: 0x11D0,
            data4: [0x94, 0xF2, 0x00, 0xA0, 0xC9, 0x1E, 0xFB, 0x8B],
        };
        let mut evidence = PhysicalDiskEvidence {
            disk_number,
            device_instance_id: None,
            vendor_id: None,
            product_id: None,
            product_revision: None,
            bus_type: None,
            descriptor_version: None,
            descriptor_error: None,
            enumerated_interfaces: 0,
            matched_disk_number: false,
            setupapi_error: None,
            detail_error: None,
        };
        let set = unsafe {
            SetupDiGetClassDevsW(
                &GUID_DEVINTERFACE_DISK,
                std::ptr::null(),
                std::ptr::null_mut(),
                DIGCF_PRESENT | DIGCF_DEVICEINTERFACE,
            )
        };
        if set == -1isize as Handle {
            evidence.descriptor_error =
                Some(io::Error::last_os_error().raw_os_error().unwrap_or(-1));
            return evidence;
        }
        let mut index = 0u32;
        loop {
            let mut interface = SpDeviceInterfaceData {
                cb_size: std::mem::size_of::<SpDeviceInterfaceData>() as u32,
                interface_class_guid: [0; 16],
                flags: 0,
                reserved: 0,
            };
            let ok = unsafe {
                SetupDiEnumDeviceInterfaces(
                    set,
                    std::ptr::null(),
                    &GUID_DEVINTERFACE_DISK,
                    index,
                    &mut interface,
                )
            };
            if ok == 0 {
                let code = io::Error::last_os_error().raw_os_error().unwrap_or(-1);
                if code != ERROR_NO_MORE_ITEMS {
                    evidence.descriptor_error = Some(code);
                }
                break;
            }
            index = index.saturating_add(1);
            evidence.enumerated_interfaces = index;
            let mut required = 0u32;
            unsafe {
                SetupDiGetDeviceInterfaceDetailW(
                    set,
                    &interface,
                    std::ptr::null_mut(),
                    0,
                    &mut required,
                    std::ptr::null_mut(),
                );
            }
            if required < 8 || required > 65536 {
                evidence.descriptor_error = Some(ERROR_INSUFFICIENT_BUFFER);
                continue;
            }
            let mut detail = vec![0u64; (required as usize + 7) / 8];
            let detail_ptr = detail.as_mut_ptr().cast::<u8>();
            // SP_DEVICE_INTERFACE_DETAIL_DATA_W.cbSize is 8 on 64-bit Windows and 6 on 32-bit Windows.
            unsafe {
                std::ptr::write_unaligned(
                    detail_ptr.cast::<u32>(),
                    if cfg!(target_pointer_width = "64") {
                        8
                    } else {
                        6
                    },
                );
            }
            let mut devinfo = SpDevinfoData {
                cb_size: std::mem::size_of::<SpDevinfoData>() as u32,
                class_guid: [0; 16],
                dev_inst: 0,
                reserved: 0,
            };
            let detail_ok = unsafe {
                SetupDiGetDeviceInterfaceDetailW(
                    set,
                    &interface,
                    detail_ptr.cast(),
                    required,
                    &mut required,
                    &mut devinfo,
                )
            };
            if detail_ok == 0 {
                continue;
            }
            let path_ptr = unsafe { detail_ptr.add(4).cast::<u16>() };
            let max_units = (required as usize - 4) / 2;
            let path_slice = unsafe { std::slice::from_raw_parts(path_ptr, max_units) };
            let path_len = match path_slice.iter().position(|v| *v == 0) {
                Some(v) => v,
                None => continue,
            };
            let path = String::from_utf16_lossy(&path_slice[..path_len]);
            let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
            let raw = unsafe {
                CreateFileW(
                    wide.as_ptr(),
                    0,
                    FILE_SHARE_READ_WRITE,
                    std::ptr::null_mut(),
                    OPEN_EXISTING,
                    0,
                    std::ptr::null_mut(),
                )
            };
            if raw == -1isize as Handle {
                continue;
            }
            let disk_file = unsafe { File::from_raw_handle(raw as RawHandle) };
            let mut number_info = StorageDeviceNumber {
                device_type: 0,
                device_number: 0,
                partition_number: 0,
            };
            let mut bytes = 0u32;
            let number_ok = unsafe {
                DeviceIoControl(
                    disk_file.as_raw_handle(),
                    IOCTL_STORAGE_GET_DEVICE_NUMBER,
                    std::ptr::null_mut(),
                    0,
                    (&mut number_info as *mut StorageDeviceNumber).cast(),
                    std::mem::size_of::<StorageDeviceNumber>() as u32,
                    &mut bytes,
                    std::ptr::null_mut(),
                )
            };
            if number_ok == 0
                || bytes < std::mem::size_of::<StorageDeviceNumber>() as u32
                || number_info.device_number != disk_number
            {
                continue;
            }
            evidence.matched_disk_number = true;
            let mut instance_buf = vec![0u16; 2048];
            let mut instance_required = 0u32;
            if unsafe {
                SetupDiGetDeviceInstanceIdW(
                    set,
                    &devinfo,
                    instance_buf.as_mut_ptr(),
                    instance_buf.len() as u32,
                    &mut instance_required,
                )
            } != 0
            {
                if let Some(end) = instance_buf.iter().position(|v| *v == 0) {
                    evidence.device_instance_id =
                        Some(String::from_utf16_lossy(&instance_buf[..end]));
                }
            }
            match query_storage_descriptor(disk_file.as_raw_handle()) {
                Ok((version, vendor, product, revision, bus)) => {
                    evidence.descriptor_version = Some(version);
                    evidence.vendor_id = vendor;
                    evidence.product_id = product;
                    evidence.product_revision = revision;
                    evidence.bus_type = Some(bus);
                }
                Err(error) => evidence.descriptor_error = Some(error.raw_os_error().unwrap_or(-1)),
            }
            break;
        }
        unsafe {
            SetupDiDestroyDeviceInfoList(set);
        }
        evidence
    }

    fn query_storage_descriptor(
        handle: Handle,
    ) -> io::Result<(u32, Option<String>, Option<String>, Option<String>, u32)> {
        let query = StoragePropertyQuery {
            property_id: 0,
            query_type: 0,
            additional_parameters: [0],
        };
        let mut buffer = vec![0u64; 8192];
        let mut bytes = 0u32;
        let ok = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_STORAGE_QUERY_PROPERTY,
                (&query as *const StoragePropertyQuery).cast_mut().cast(),
                std::mem::size_of::<StoragePropertyQuery>() as u32,
                buffer.as_mut_ptr().cast(),
                (buffer.len() * 8) as u32,
                &mut bytes,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        if bytes < std::mem::size_of::<StorageDeviceDescriptorHeader>() as u32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "storage descriptor header truncated",
            ));
        }
        let base = buffer.as_ptr().cast::<u8>();
        let header =
            unsafe { std::ptr::read_unaligned(base.cast::<StorageDeviceDescriptorHeader>()) };
        if header.size < std::mem::size_of::<StorageDeviceDescriptorHeader>() as u32
            || header.size > bytes
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "storage descriptor size outside returned buffer",
            ));
        }
        let read_field = |offset: u32| -> io::Result<Option<String>> {
            if offset == 0 {
                return Ok(None);
            }
            let offset = offset as usize;
            if offset < std::mem::size_of::<StorageDeviceDescriptorHeader>()
                || offset >= header.size as usize
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "storage descriptor string offset invalid",
                ));
            }
            let bytes = unsafe {
                std::slice::from_raw_parts(base.add(offset), header.size as usize - offset)
            };
            let end = bytes.iter().position(|v| *v == 0).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "storage descriptor string is unterminated",
                )
            })?;
            let value = String::from_utf8_lossy(&bytes[..end]).trim().to_string();
            if value.is_empty() {
                Ok(None)
            } else {
                Ok(Some(value))
            }
        };
        Ok((
            header.version,
            read_field(header.vendor_id_offset)?,
            read_field(header.product_id_offset)?,
            read_field(header.product_revision_offset)?,
            header.bus_type,
        ))
    }

    #[derive(Debug, Clone, Eq, PartialEq)]
    pub struct StoreRootObservation {
        pub label: String,
        pub final_path: String,
        pub object_kind: crate::windows_store_path_qualifier::StoreObjectKind,
        pub volume_guid_path: String,
        pub filesystem_name: String,
        pub disk_numbers: Vec<u32>,
        pub disk_products: Vec<Option<String>>,
        pub pnp_instance_ids_present: Vec<bool>,
        /// True only when every extent is correlated to a PnP interface and descriptor.
        pub correlation_complete: bool,
        /// Always false: these OS-reported identifiers are not hardware attestation.
        pub hardware_identity_attested: bool,
    }

    #[derive(Debug, Clone, Eq, PartialEq)]
    pub struct StoreRootFailure {
        pub label: String,
        pub stage: String,
        pub error_kind: String,
        pub raw_os_error: Option<i32>,
    }

    #[derive(Debug, Clone, Eq, PartialEq, Default)]
    pub struct StoreRootCorrelationReport {
        pub observations: Vec<StoreRootObservation>,
        pub failures: Vec<StoreRootFailure>,
    }

    /// Read-only batch correlation for explicitly supplied store-root paths.
    /// It checks only each final component; ancestor traversal remains unqualified.
    /// No store files are opened or read, and no production state is modified.
    pub fn correlate_store_roots(paths: &[(&str, &Path)]) -> StoreRootCorrelationReport {
        let mut report = StoreRootCorrelationReport::default();
        for (label, path) in paths {
            let probe = match open_final_component(path) {
                Ok(value) => value,
                Err(error) => {
                    report.failures.push(StoreRootFailure {
                        label: (*label).to_string(),
                        stage: "final-component-handle".to_string(),
                        error_kind: format!("{:?}", error.kind()),
                        raw_os_error: error.raw_os_error(),
                    });
                    continue;
                }
            };
            if probe.object_kind()
                != crate::windows_store_path_qualifier::StoreObjectKind::Directory
            {
                report.failures.push(StoreRootFailure {
                    label: (*label).to_string(),
                    stage: "store-root-object-kind".to_string(),
                    error_kind: "NotDirectory".to_string(),
                    raw_os_error: None,
                });
                continue;
            }
            let volume = match probe_volume(&probe) {
                Ok(value) => value,
                Err(error) => {
                    report.failures.push(StoreRootFailure {
                        label: (*label).to_string(),
                        stage: "volume-and-device-correlation".to_string(),
                        error_kind: format!("{:?}", error.kind()),
                        raw_os_error: error.raw_os_error(),
                    });
                    continue;
                }
            };
            let disk_numbers = volume.disk_numbers.clone().unwrap_or_default();
            let disk_products: Vec<_> = volume
                .disk_devices
                .iter()
                .map(|disk| disk.product_id.clone())
                .collect();
            let pnp_instance_ids_present: Vec<_> = volume
                .disk_devices
                .iter()
                .map(|disk| {
                    disk.device_instance_id
                        .as_ref()
                        .is_some_and(|id| !id.is_empty())
                })
                .collect();
            let correlation_complete = !disk_numbers.is_empty()
                && volume.disk_devices.len() == disk_numbers.len()
                && volume.disk_devices.iter().all(|disk| {
                    disk.matched_disk_number
                        && disk
                            .device_instance_id
                            .as_ref()
                            .is_some_and(|id| !id.is_empty())
                        && disk.descriptor_error.is_none()
                        && (disk.vendor_id.is_some() || disk.product_id.is_some())
                        && disk.bus_type.is_some()
                });
            report.observations.push(StoreRootObservation {
                label: (*label).to_string(),
                final_path: probe.final_path().to_string(),
                object_kind: probe.object_kind(),
                volume_guid_path: volume.volume_guid_path,
                filesystem_name: volume.filesystem_name,
                disk_numbers,
                disk_products,
                pnp_instance_ids_present,
                correlation_complete,
                hardware_identity_attested: false,
            });
        }
        report
    }
    fn query_disk_numbers(volume_handle: Handle) -> io::Result<Vec<u32>> {
        // Large bounded buffer; multi-extent results are validated against bytes returned.
        let mut storage = vec![0u64; 8192];
        let mut bytes_returned = 0u32;
        // SAFETY: volume handle is live; output buffer is aligned and writable.
        let ok = unsafe {
            DeviceIoControl(
                volume_handle,
                IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                std::ptr::null_mut(),
                0,
                storage.as_mut_ptr().cast(),
                (storage.len() * std::mem::size_of::<u64>()) as u32,
                &mut bytes_returned,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        if bytes_returned < 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "volume extent header truncated",
            ));
        }
        let base = storage.as_ptr().cast::<u8>();
        // SAFETY: bytes_returned proves the 4-byte count lies in the output buffer.
        let count = unsafe { std::ptr::read_unaligned(base.cast::<u32>()) } as usize;
        let required = 8usize
            .checked_add(
                count
                    .checked_mul(std::mem::size_of::<DiskExtent>())
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "extent count overflow")
                    })?,
            )
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "extent buffer size overflow")
            })?;
        if required > bytes_returned as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "volume extent array truncated",
            ));
        }
        let mut disks = Vec::with_capacity(count);
        for index in 0..count {
            let offset = 8 + index * std::mem::size_of::<DiskExtent>();
            // SAFETY: validated array bounds; DISK_EXTENT starts at byte offset 8.
            let extent = unsafe { std::ptr::read_unaligned(base.add(offset).cast::<DiskExtent>()) };
            disks.push(extent.disk_number);
        }
        disks.sort_unstable();
        disks.dedup();
        if disks.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "volume returned zero disk extents",
            ));
        }
        Ok(disks)
    }
}

#[cfg(windows)]
pub use imp::{correlate_store_roots, probe_volume};

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root() -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("qrun-volume-probe-{}-{nonce}", std::process::id()))
    }

    #[test]
    fn reads_volume_and_file_identity_from_a_retained_temp_directory_handle() {
        let root = temp_root();
        fs::create_dir(&root).unwrap();
        let handle_probe = crate::windows_store_handle_probe::open_final_component(&root).unwrap();
        let evidence = probe_volume(&handle_probe).unwrap();
        assert!(evidence.volume_guid_path.starts_with("\\\\?\\Volume{"));
        assert!(evidence.volume_guid_path.ends_with("}\\"));
        assert!(!evidence.filesystem_name.is_empty());
        assert!(!evidence.file_id_128.iter().all(|byte| *byte == 0));
        assert!(!evidence.physical_identity_complete);
        if let Some(numbers) = &evidence.disk_numbers {
            assert_eq!(evidence.disk_devices.len(), numbers.len());
            for disk in &evidence.disk_devices {
                assert!(
                    disk.matched_disk_number,
                    "PnP interface must match the volume extent disk number"
                );
                assert!(
                    disk.device_instance_id
                        .as_deref()
                        .is_some_and(|id| !id.is_empty()),
                    "PnP device instance ID must be present for a matched disk"
                );
                assert!(
                    disk.product_id.is_some() || disk.vendor_id.is_some(),
                    "at least one storage descriptor identity field must be present"
                );
                assert!(
                    disk.descriptor_error.is_none(),
                    "storage descriptor query should succeed for matched disk"
                );
            }
        }
        let disk_summary: Vec<_> = evidence
            .disk_devices
            .iter()
            .map(|disk| {
                (
                    disk.disk_number,
                    disk.matched_disk_number,
                    disk.device_instance_id.is_some(),
                    disk.product_id.as_deref(),
                    disk.bus_type,
                )
            })
            .collect();
        eprintln!(
            "Volume evidence: filesystem={}, extent_count={}, disk_summary={:?}",
            evidence.filesystem_name,
            evidence.disk_numbers.as_ref().map_or(0, Vec::len),
            disk_summary
        );
        drop(handle_probe);
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn rejects_network_or_non_guid_final_paths() {
        assert!(imp::extract_volume_guid_path("\\\\server\\share\\folder").is_err());
        assert!(imp::extract_volume_guid_path("\\\\?\\Volume{not-a-guid}\\file").is_err());
    }
    #[test]
    fn batch_store_root_correlation_is_read_only_and_matches_shared_volume() {
        let root = temp_root();
        let first = root.join("anchor-root");
        let second = root.join("identity-root");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();
        let report =
            correlate_store_roots(&[("anchor", first.as_path()), ("identity", second.as_path())]);
        assert!(
            report.failures.is_empty(),
            "unexpected failures: {:?}",
            report.failures
        );
        assert_eq!(report.observations.len(), 2);
        let a = &report.observations[0];
        let b = &report.observations[1];
        assert!(a.correlation_complete);
        assert!(b.correlation_complete);
        assert_eq!(a.volume_guid_path, b.volume_guid_path);
        assert_eq!(a.disk_numbers, b.disk_numbers);
        assert!(!a.hardware_identity_attested);
        assert!(!b.hardware_identity_attested);
        assert!(a.pnp_instance_ids_present.iter().all(|present| *present));
        assert!(b.pnp_instance_ids_present.iter().all(|present| *present));
        // The probe is metadata-only: the directories remain empty.
        assert_eq!(fs::read_dir(&first).unwrap().count(), 0);
        assert_eq!(fs::read_dir(&second).unwrap().count(), 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn batch_store_root_correlation_records_missing_paths_without_mutation() {
        let missing = temp_root().join("does-not-exist");
        let report = correlate_store_roots(&[("missing", missing.as_path())]);
        assert!(report.observations.is_empty());
        assert_eq!(report.failures.len(), 1);
        assert_eq!(report.failures[0].label, "missing");
        assert_eq!(report.failures[0].stage, "final-component-handle");
        assert!(!missing.exists());
    }
}
