//! Role- and network-bound DPAPI custody for offline Ed25519 signing seeds.
//!
//! This is an operator candidate for offline Windows use, not an HSM. The encrypted seed is
//! bound to the current Windows user and machine by CurrentUser DPAPI, and to a role and network
//! by optional entropy. Keep role keys on a dedicated, offline Windows account/device. DPAPI files
//! are not portable backups; recovery requires a separately designed offline backup ceremony.
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::Path,
};

const MAGIC: &[u8; 4] = b"ASK1";
const VERSION: u16 = 1;
const HEADER_LEN: usize = 46;
const MAX_PROTECTED_BLOB: usize = 16 * 1024;
const MAX_FILE_LEN: usize = HEADER_LEN + MAX_PROTECTED_BLOB;
const DOMAIN: &[u8] = b"AIN1-OFFLINE-ED25519-SIGNING-SEED-V1\0";
const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SigningKeyRole {
    DeploymentAuthority = 1,
    GovernanceRoot = 2,
    OfflineRecovery = 3,
    PeerIssuer = 4,
}

impl SigningKeyRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DeploymentAuthority => "deployment-authority",
            Self::GovernanceRoot => "governance-root",
            Self::OfflineRecovery => "offline-recovery",
            Self::PeerIssuer => "peer-issuer",
        }
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "deployment-authority" => Ok(Self::DeploymentAuthority),
            "governance-root" => Ok(Self::GovernanceRoot),
            "offline-recovery" => Ok(Self::OfflineRecovery),
            "peer-issuer" => Ok(Self::PeerIssuer),
            _ => Err("unknown signing-key role".into()),
        }
    }

    fn from_byte(value: u8) -> Result<Self, String> {
        match value {
            1 => Ok(Self::DeploymentAuthority),
            2 => Ok(Self::GovernanceRoot),
            3 => Ok(Self::OfflineRecovery),
            4 => Ok(Self::PeerIssuer),
            _ => Err("protected signing-key role is invalid".into()),
        }
    }
}

pub fn store_protected_signing_seed(
    path: impl AsRef<Path>,
    network_id: &[u8; 32],
    role: SigningKeyRole,
    seed: &[u8; 32],
) -> Result<(), String> {
    if network_id.iter().all(|b| *b == 0) || seed.iter().all(|b| *b == 0) {
        return Err("network ID and signing seed must be nonzero".into());
    }
    let path = path.as_ref();
    let parent = parent_directory(path);
    if path.file_name().is_none() || !parent.is_dir() {
        return Err("protected signing-key output must be in an existing directory".into());
    }
    match fs::symlink_metadata(path) {
        Ok(_) => {
            return Err("protected signing-key output already exists; refusing overwrite".into())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err("cannot inspect protected signing-key output path".into()),
    }

    let protected = dpapi_protect(seed, network_id, role)?;
    if protected.is_empty() || protected.len() > MAX_PROTECTED_BLOB {
        return Err("protected signing-key payload length is invalid".into());
    }
    let mut envelope = Vec::with_capacity(HEADER_LEN + protected.len());
    envelope.extend_from_slice(MAGIC);
    envelope.extend_from_slice(&VERSION.to_be_bytes());
    envelope.extend_from_slice(network_id);
    envelope.push(role as u8);
    envelope.extend_from_slice(&[0; 3]);
    envelope.extend_from_slice(&(protected.len() as u32).to_be_bytes());
    envelope.extend_from_slice(&protected);

    // create_new is intentional: signing authority key files may never be silently replaced.
    let mut created_by_this_call = false;
    let result = (|| -> io::Result<()> {
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        created_by_this_call = true;
        file.write_all(&envelope)?;
        file.flush()?;
        file.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        // Never delete a pre-existing destination if create_new loses a race.
        if created_by_this_call {
            let _ = fs::remove_file(path);
        }
        return Err("cannot durably write protected signing-key file".into());
    }
    Ok(())
}

pub fn load_protected_signing_seed(
    path: impl AsRef<Path>,
    expected_network_id: &[u8; 32],
    expected_role: SigningKeyRole,
) -> Result<[u8; 32], String> {
    let path = path.as_ref();
    let metadata =
        fs::symlink_metadata(path).map_err(|_| "cannot inspect protected signing-key file")?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() < (HEADER_LEN + 1) as u64
        || metadata.len() > MAX_FILE_LEN as u64
    {
        return Err("protected signing-key file is malformed".into());
    }
    let mut envelope = Vec::with_capacity(metadata.len() as usize);
    OpenOptions::new()
        .read(true)
        .open(path)
        .and_then(|f| f.take((MAX_FILE_LEN + 1) as u64).read_to_end(&mut envelope))
        .map_err(|_| "cannot read protected signing-key file")?;
    if envelope.len() < HEADER_LEN + 1 || envelope.len() > MAX_FILE_LEN || &envelope[..4] != MAGIC {
        return Err("protected signing-key file is malformed".into());
    }
    if u16::from_be_bytes([envelope[4], envelope[5]]) != VERSION {
        return Err("protected signing-key version is unsupported".into());
    }
    let network_id: [u8; 32] = envelope[6..38]
        .try_into()
        .map_err(|_| "protected signing-key file is malformed")?;
    if &network_id != expected_network_id {
        return Err("protected signing key belongs to another network".into());
    }
    let role = SigningKeyRole::from_byte(envelope[38])?;
    if role != expected_role {
        return Err("protected signing key has the wrong role".into());
    }
    if envelope[39..42] != [0; 3] {
        return Err("protected signing-key reserved bytes are invalid".into());
    }
    let blob_len = u32::from_be_bytes(
        envelope[42..46]
            .try_into()
            .map_err(|_| "protected signing-key file is malformed")?,
    ) as usize;
    if blob_len == 0
        || blob_len > MAX_PROTECTED_BLOB
        || HEADER_LEN.checked_add(blob_len) != Some(envelope.len())
    {
        return Err("protected signing-key file is malformed".into());
    }
    let mut plaintext = dpapi_unprotect(&envelope[HEADER_LEN..], expected_network_id, role)?;
    if plaintext.len() != 32 || plaintext.iter().all(|b| *b == 0) {
        plaintext.fill(0);
        return Err("protected signing-key plaintext is invalid".into());
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&plaintext);
    plaintext.fill(0);
    Ok(seed)
}

fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn entropy(network_id: &[u8; 32], role: SigningKeyRole) -> Vec<u8> {
    let mut result = Vec::with_capacity(DOMAIN.len() + network_id.len() + 1);
    result.extend_from_slice(DOMAIN);
    result.extend_from_slice(network_id);
    result.push(role as u8);
    result
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
    role: SigningKeyRole,
) -> Result<Vec<u8>, String> {
    let entropy_bytes = entropy(network_id, role);
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
        return Err(format!(
            "Windows CurrentUser DPAPI protect failed (Win32 error {})",
            unsafe { GetLastError() }
        ));
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
        return Err("Windows DPAPI returned an invalid protected payload".into());
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
    role: SigningKeyRole,
) -> Result<Vec<u8>, String> {
    let entropy_bytes = entropy(network_id, role);
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
        return Err(format!(
            "Windows CurrentUser DPAPI unprotect failed (Win32 error {})",
            unsafe { GetLastError() }
        ));
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
        return Err("Windows DPAPI returned an invalid plaintext payload".into());
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
    _role: SigningKeyRole,
) -> Result<Vec<u8>, String> {
    Err("offline signing-key provisioner requires Windows CurrentUser DPAPI".into())
}

#[cfg(not(windows))]
fn dpapi_unprotect(
    _input: &[u8],
    _network_id: &[u8; 32],
    _role: SigningKeyRole,
) -> Result<Vec<u8>, String> {
    Err("offline signing-key provisioner requires Windows CurrentUser DPAPI".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_names_are_explicit_and_unknown_roles_fail_closed() {
        assert_eq!(
            SigningKeyRole::parse("deployment-authority").unwrap(),
            SigningKeyRole::DeploymentAuthority
        );
        assert_eq!(
            SigningKeyRole::parse("governance-root").unwrap(),
            SigningKeyRole::GovernanceRoot
        );
        assert_eq!(
            SigningKeyRole::parse("offline-recovery").unwrap(),
            SigningKeyRole::OfflineRecovery
        );
        assert_eq!(
            SigningKeyRole::parse("peer-issuer").unwrap(),
            SigningKeyRole::PeerIssuer
        );
        assert!(SigningKeyRole::parse("admin").is_err());
    }

    #[test]
    fn protected_file_is_bound_to_role_and_network_before_unprotect() {
        // Header-level checks are portable, even though decrypting DPAPI is Windows-only.
        let path =
            std::env::temp_dir().join(format!("ain1-ask1-invalid-{}.bin", std::process::id()));
        let network = [0x41; 32];
        let mut envelope = Vec::new();
        envelope.extend_from_slice(MAGIC);
        envelope.extend_from_slice(&VERSION.to_be_bytes());
        envelope.extend_from_slice(&network);
        envelope.push(SigningKeyRole::PeerIssuer as u8);
        envelope.extend_from_slice(&[0; 3]);
        envelope.extend_from_slice(&16u32.to_be_bytes());
        envelope.extend_from_slice(&[0x55; 16]);
        fs::write(&path, envelope).unwrap();
        assert!(
            load_protected_signing_seed(&path, &[0x42; 32], SigningKeyRole::PeerIssuer)
                .unwrap_err()
                .contains("another network")
        );
        assert!(
            load_protected_signing_seed(&path, &network, SigningKeyRole::GovernanceRoot)
                .unwrap_err()
                .contains("wrong role")
        );
        let _ = fs::remove_file(path);
    }

    #[cfg(not(windows))]
    #[test]
    fn dpapi_is_fail_closed_outside_windows() {
        assert!(dpapi_protect(&[0x42; 32], &[0x44; 32], SigningKeyRole::PeerIssuer).is_err());
        assert!(dpapi_unprotect(&[0x42; 32], &[0x44; 32], SigningKeyRole::PeerIssuer).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_roundtrip_is_role_and_network_bound_and_never_persists_seed_bytes() {
        let path =
            std::env::temp_dir().join(format!("ain1-ask1-roundtrip-{}.bin", std::process::id()));
        let network = [0x44; 32];
        let seed = [0x62; 32];
        store_protected_signing_seed(&path, &network, SigningKeyRole::PeerIssuer, &seed).unwrap();
        let stored = fs::read(&path).unwrap();
        assert!(stored.starts_with(MAGIC));
        assert!(!stored.windows(seed.len()).any(|window| window == seed));
        assert_eq!(
            load_protected_signing_seed(&path, &network, SigningKeyRole::PeerIssuer).unwrap(),
            seed
        );
        assert!(
            load_protected_signing_seed(&path, &[0x45; 32], SigningKeyRole::PeerIssuer).is_err()
        );
        assert!(
            load_protected_signing_seed(&path, &network, SigningKeyRole::GovernanceRoot).is_err()
        );
        let _ = fs::remove_file(path);
    }

    #[cfg(windows)]
    #[test]
    fn failed_create_new_never_deletes_an_existing_signing_key_file() {
        let path =
            std::env::temp_dir().join(format!("ain1-ask1-existing-{}.bin", std::process::id()));
        let sentinel = b"existing file must survive";
        fs::write(&path, sentinel).unwrap();
        let result = store_protected_signing_seed(
            &path,
            &[0x46; 32],
            SigningKeyRole::PeerIssuer,
            &[0x62; 32],
        );
        assert!(result.is_err());
        assert_eq!(fs::read(&path).unwrap(), sentinel);
        let _ = fs::remove_file(path);
    }
}
