//! Windows DPAPI-backed custody for local Noise static private keys.
//!
//! NPK1 stores a bounded CurrentUser-DPAPI ciphertext, never plaintext key bytes. The network ID
//! is present in the envelope and also included in DPAPI optional entropy, preventing accidental
//! cross-network use. This protects at rest for the current Windows user; it is not an HSM and does
//! not protect a running process from that same user's debugger or memory inspection.
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};

const MAGIC: &[u8; 4] = b"NPK1";
const VERSION: u16 = 1;
const HEADER_LEN: usize = 42;
const MAX_PROTECTED_BLOB: usize = 64 * 1024;
const MAX_FILE_LEN: usize = HEADER_LEN + MAX_PROTECTED_BLOB;
const DOMAIN: &[u8] = b"AIN1-NOISE-STATIC-KEY-DPAPI-V1\0";
const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;
static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoiseKeyProvisioningError {
    Io,
    InvalidPath,
    Malformed,
    UnsupportedVersion,
    NetworkMismatch,
    InvalidKey,
    DpapiUnavailable,
    DpapiFailure(u32),
}

impl std::fmt::Display for NoiseKeyProvisioningError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io => write!(f, "protected Noise key file I/O failed"),
            Self::InvalidPath => write!(
                f,
                "protected Noise key path must be a regular file in an existing directory"
            ),
            Self::Malformed => write!(f, "protected Noise key envelope is malformed"),
            Self::UnsupportedVersion => {
                write!(f, "protected Noise key envelope version is unsupported")
            }
            Self::NetworkMismatch => write!(
                f,
                "protected Noise key envelope is bound to another network"
            ),
            Self::InvalidKey => write!(f, "Noise private key must be exactly 32 nonzero bytes"),
            Self::DpapiUnavailable => write!(f, "CurrentUser DPAPI is only supported on Windows"),
            Self::DpapiFailure(code) => {
                write!(f, "Windows DPAPI operation failed (Win32 error {code})")
            }
        }
    }
}

impl std::error::Error for NoiseKeyProvisioningError {}

/// Protect a 32-byte static private key with Windows CurrentUser DPAPI and atomically replace the
/// NPK1 envelope. Provisioning callers must not pass the raw key on a command line.
pub fn store_protected_noise_private_key(
    path: impl AsRef<Path>,
    network_id: &[u8; 32],
    private_key: &[u8; 32],
) -> Result<(), NoiseKeyProvisioningError> {
    if private_key.iter().all(|byte| *byte == 0) {
        return Err(NoiseKeyProvisioningError::InvalidKey);
    }
    let protected = dpapi_protect(private_key, network_id)?;
    if protected.is_empty() || protected.len() > MAX_PROTECTED_BLOB {
        return Err(NoiseKeyProvisioningError::Malformed);
    }
    let mut envelope = Vec::with_capacity(HEADER_LEN + protected.len());
    envelope.extend_from_slice(MAGIC);
    envelope.extend_from_slice(&VERSION.to_be_bytes());
    envelope.extend_from_slice(network_id);
    envelope.extend_from_slice(&(protected.len() as u32).to_be_bytes());
    envelope.extend_from_slice(&protected);
    persist_atomic(path.as_ref(), &envelope)
}

/// Load and authenticate an NPK1 file. Plaintext is returned only after DPAPI, network binding and
/// exact length/nonzero checks have passed. The caller must clear its resulting key copy.
pub fn load_protected_noise_private_key(
    path: impl AsRef<Path>,
    expected_network_id: &[u8; 32],
) -> Result<[u8; 32], NoiseKeyProvisioningError> {
    let path = path.as_ref();
    let metadata = fs::symlink_metadata(path).map_err(|_| NoiseKeyProvisioningError::Io)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(NoiseKeyProvisioningError::InvalidPath);
    }
    if metadata.len() < (HEADER_LEN + 1) as u64 || metadata.len() > MAX_FILE_LEN as u64 {
        return Err(NoiseKeyProvisioningError::Malformed);
    }
    let file = File::open(path).map_err(|_| NoiseKeyProvisioningError::Io)?;
    let mut envelope = Vec::with_capacity(metadata.len() as usize);
    file.take((MAX_FILE_LEN + 1) as u64)
        .read_to_end(&mut envelope)
        .map_err(|_| NoiseKeyProvisioningError::Io)?;
    if envelope.len() < HEADER_LEN + 1 || envelope.len() > MAX_FILE_LEN || &envelope[..4] != MAGIC {
        return Err(NoiseKeyProvisioningError::Malformed);
    }
    let version = u16::from_be_bytes(
        envelope[4..6]
            .try_into()
            .map_err(|_| NoiseKeyProvisioningError::Malformed)?,
    );
    if version != VERSION {
        return Err(NoiseKeyProvisioningError::UnsupportedVersion);
    }
    let network_id: [u8; 32] = envelope[6..38]
        .try_into()
        .map_err(|_| NoiseKeyProvisioningError::Malformed)?;
    if &network_id != expected_network_id {
        return Err(NoiseKeyProvisioningError::NetworkMismatch);
    }
    let blob_len = u32::from_be_bytes(
        envelope[38..42]
            .try_into()
            .map_err(|_| NoiseKeyProvisioningError::Malformed)?,
    ) as usize;
    if blob_len == 0
        || blob_len > MAX_PROTECTED_BLOB
        || HEADER_LEN.checked_add(blob_len) != Some(envelope.len())
    {
        return Err(NoiseKeyProvisioningError::Malformed);
    }
    let mut plaintext = dpapi_unprotect(&envelope[HEADER_LEN..], expected_network_id)?;
    if plaintext.len() != 32 || plaintext.iter().all(|byte| *byte == 0) {
        plaintext.fill(0);
        return Err(NoiseKeyProvisioningError::InvalidKey);
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&plaintext);
    plaintext.fill(0);
    Ok(key)
}

fn entropy(network_id: &[u8; 32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(DOMAIN.len() + network_id.len());
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(network_id);
    bytes
}

fn persist_atomic(path: &Path, bytes: &[u8]) -> Result<(), NoiseKeyProvisioningError> {
    let parent = parent_directory(path);
    let name = path
        .file_name()
        .ok_or(NoiseKeyProvisioningError::InvalidPath)?
        .to_string_lossy();
    if !parent.is_dir() {
        return Err(NoiseKeyProvisioningError::InvalidPath);
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(NoiseKeyProvisioningError::InvalidPath)
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(NoiseKeyProvisioningError::Io),
    }
    let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(".{name}.npk1.{}.{}.tmp", std::process::id(), id));
    let result = (|| -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.flush()?;
        file.sync_all()?;
        drop(file);
        atomic_replace(&temporary, path)?;
        #[cfg(unix)]
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(|_| NoiseKeyProvisioningError::Io)
}

fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[cfg(windows)]
fn atomic_replace(source: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;
    let from: Vec<u16> = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let to: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    #[link(name = "Kernel32")]
    extern "system" {
        fn MoveFileExW(existing: *const u16, new_name: *const u16, flags: u32) -> i32;
    }
    let ok = unsafe {
        MoveFileExW(
            from.as_ptr(),
            to.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn atomic_replace(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(windows)]
#[repr(C)]
struct DataBlob {
    cb_data: u32,
    pb_data: *mut u8,
}

#[cfg(windows)]
#[link(name = "Crypt32")]
extern "system" {
    fn CryptProtectData(
        input: *const DataBlob,
        description: *const u16,
        optional_entropy: *const DataBlob,
        reserved: *mut std::ffi::c_void,
        prompt: *mut std::ffi::c_void,
        flags: u32,
        output: *mut DataBlob,
    ) -> i32;
    fn CryptUnprotectData(
        input: *const DataBlob,
        description: *mut *mut u16,
        optional_entropy: *const DataBlob,
        reserved: *mut std::ffi::c_void,
        prompt: *mut std::ffi::c_void,
        flags: u32,
        output: *mut DataBlob,
    ) -> i32;
}

#[cfg(windows)]
#[link(name = "Kernel32")]
extern "system" {
    fn LocalFree(memory: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
    fn GetLastError() -> u32;
}

#[cfg(windows)]
fn dpapi_protect(
    input: &[u8],
    network_id: &[u8; 32],
) -> Result<Vec<u8>, NoiseKeyProvisioningError> {
    if input.len() > u32::MAX as usize {
        return Err(NoiseKeyProvisioningError::Malformed);
    }
    let entropy_bytes = entropy(network_id);
    let input_blob = DataBlob {
        cb_data: input.len() as u32,
        pb_data: input.as_ptr() as *mut u8,
    };
    let entropy_blob = DataBlob {
        cb_data: entropy_bytes.len() as u32,
        pb_data: entropy_bytes.as_ptr() as *mut u8,
    };
    let mut output = DataBlob {
        cb_data: 0,
        pb_data: std::ptr::null_mut(),
    };
    let ok = unsafe {
        CryptProtectData(
            &input_blob,
            std::ptr::null(),
            &entropy_blob,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(NoiseKeyProvisioningError::DpapiFailure(unsafe {
            GetLastError()
        }));
    }
    if output.pb_data.is_null()
        || output.cb_data == 0
        || output.cb_data as usize > MAX_PROTECTED_BLOB
    {
        if !output.pb_data.is_null() {
            unsafe {
                LocalFree(output.pb_data as *mut std::ffi::c_void);
            }
        }
        return Err(NoiseKeyProvisioningError::Malformed);
    }
    let protected =
        unsafe { std::slice::from_raw_parts(output.pb_data, output.cb_data as usize).to_vec() };
    unsafe {
        LocalFree(output.pb_data as *mut std::ffi::c_void);
    }
    Ok(protected)
}

#[cfg(windows)]
fn dpapi_unprotect(
    input: &[u8],
    network_id: &[u8; 32],
) -> Result<Vec<u8>, NoiseKeyProvisioningError> {
    if input.len() > u32::MAX as usize {
        return Err(NoiseKeyProvisioningError::Malformed);
    }
    let entropy_bytes = entropy(network_id);
    let input_blob = DataBlob {
        cb_data: input.len() as u32,
        pb_data: input.as_ptr() as *mut u8,
    };
    let entropy_blob = DataBlob {
        cb_data: entropy_bytes.len() as u32,
        pb_data: entropy_bytes.as_ptr() as *mut u8,
    };
    let mut output = DataBlob {
        cb_data: 0,
        pb_data: std::ptr::null_mut(),
    };
    let ok = unsafe {
        CryptUnprotectData(
            &input_blob,
            std::ptr::null_mut(),
            &entropy_blob,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(NoiseKeyProvisioningError::DpapiFailure(unsafe {
            GetLastError()
        }));
    }
    if output.pb_data.is_null()
        || output.cb_data == 0
        || output.cb_data as usize > MAX_PROTECTED_BLOB
    {
        if !output.pb_data.is_null() {
            unsafe {
                std::ptr::write_bytes(output.pb_data, 0, output.cb_data as usize);
                LocalFree(output.pb_data as *mut std::ffi::c_void);
            }
        }
        return Err(NoiseKeyProvisioningError::Malformed);
    }
    let mut plaintext =
        unsafe { std::slice::from_raw_parts(output.pb_data, output.cb_data as usize).to_vec() };
    unsafe {
        std::ptr::write_bytes(output.pb_data, 0, output.cb_data as usize);
        LocalFree(output.pb_data as *mut std::ffi::c_void);
    }
    Ok(std::mem::take(&mut plaintext))
}

#[cfg(not(windows))]
fn dpapi_protect(
    _input: &[u8],
    _network_id: &[u8; 32],
) -> Result<Vec<u8>, NoiseKeyProvisioningError> {
    Err(NoiseKeyProvisioningError::DpapiUnavailable)
}

#[cfg(not(windows))]
fn dpapi_unprotect(
    _input: &[u8],
    _network_id: &[u8; 32],
) -> Result<Vec<u8>, NoiseKeyProvisioningError> {
    Err(NoiseKeyProvisioningError::DpapiUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn temp_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "ain1-noise-key-{label}-{}-{nonce}.npk",
            std::process::id()
        ))
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_envelope_roundtrips_and_is_network_bound() {
        let path = temp_path("roundtrip");
        let network = [0x37; 32];
        let key = [0x62; 32];
        store_protected_noise_private_key(&path, &network, &key).unwrap();
        let stored = fs::read(&path).unwrap();
        assert!(stored.starts_with(MAGIC));
        assert!(!stored.windows(key.len()).any(|window| window == key));
        assert_eq!(
            load_protected_noise_private_key(&path, &network).unwrap(),
            key
        );
        assert_eq!(
            load_protected_noise_private_key(&path, &[0x38; 32]).unwrap_err(),
            NoiseKeyProvisioningError::NetworkMismatch
        );
        let mut tampered = stored.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x80;
        fs::write(&path, tampered).unwrap();
        assert!(load_protected_noise_private_key(&path, &network).is_err());
        let _ = fs::remove_file(&path);
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_state_refuses_zero_key_and_rejects_corrupt_envelopes() {
        let path = temp_path("invalid");
        assert_eq!(
            store_protected_noise_private_key(&path, &[0x11; 32], &[0; 32]).unwrap_err(),
            NoiseKeyProvisioningError::InvalidKey
        );
        fs::write(&path, [0x42u8; 32]).unwrap();
        assert_eq!(
            load_protected_noise_private_key(&path, &[0x11; 32]).unwrap_err(),
            NoiseKeyProvisioningError::Malformed
        );
        fs::write(&path, b"NPK1").unwrap();
        assert_eq!(
            load_protected_noise_private_key(&path, &[0x11; 32]).unwrap_err(),
            NoiseKeyProvisioningError::Malformed
        );
        let _ = fs::remove_file(&path);
    }

    #[cfg(not(windows))]
    #[test]
    fn dpapi_is_fail_closed_off_windows() {
        assert_eq!(
            dpapi_protect(&[0x42; 32], &[0x44; 32]).unwrap_err(),
            NoiseKeyProvisioningError::DpapiUnavailable
        );
        assert_eq!(
            dpapi_unprotect(&[0x42; 32], &[0x44; 32]).unwrap_err(),
            NoiseKeyProvisioningError::DpapiUnavailable
        );
    }
}
