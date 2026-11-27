//! OS-backed custody for local Noise static private keys.
//!
//! Windows retains NPK1 with CurrentUser DPAPI and network-bound optional entropy. Linux uses NPK2
//! encrypted by systemd-creds with an explicit host+TPM2 key requirement and loads it only from the
//! service's LoadCredentialEncrypted credential directory. Neither provider protects a running
//! process from compromise of the service identity or memory.
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};
use zeroize::Zeroize;

#[cfg(target_os = "linux")]
use std::{
    ffi::CString,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    process::{Command, Stdio},
};

#[cfg(windows)]
const MAGIC: &[u8; 4] = b"NPK1";
#[cfg(windows)]
const VERSION: u16 = 1;
#[cfg(windows)]
const HEADER_LEN: usize = 42;
const MAX_PROTECTED_BLOB: usize = 64 * 1024;
#[cfg(windows)]
const MAX_FILE_LEN: usize = HEADER_LEN + MAX_PROTECTED_BLOB;
#[cfg(windows)]
const DOMAIN: &[u8] = b"AIN1-NOISE-STATIC-KEY-DPAPI-V1\0";
#[cfg(any(target_os = "linux", test))]
const SYSTEMD_MAGIC: &[u8; 4] = b"NPK2";
#[cfg(any(target_os = "linux", test))]
const SYSTEMD_VERSION: u16 = 1;
#[cfg(any(target_os = "linux", test))]
const SYSTEMD_PAYLOAD_LEN: usize = 4 + 2 + 32 + 32;
#[cfg(any(target_os = "linux", test))]
const SYSTEMD_REFERENCE_PREFIX: &str = "/systemd-credential/";
#[cfg(target_os = "linux")]
const SYSTEMD_CREDS_PATH: &str = "/usr/bin/systemd-creds";
#[cfg(windows)]
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
    SystemdCredsUnavailable,
    SystemdCredsFailure,
    SystemdCredentialUnavailable,
    InvalidCredentialName,
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
            Self::SystemdCredsUnavailable => {
                write!(f, "systemd-creds is unavailable at /usr/bin/systemd-creds")
            }
            Self::SystemdCredsFailure => {
                write!(f, "systemd-creds host+TPM2 credential encryption failed")
            }
            Self::SystemdCredentialUnavailable => {
                write!(
                    f,
                    "systemd service credential directory or credential is unavailable"
                )
            }
            Self::InvalidCredentialName => {
                write!(
                    f,
                    "systemd credential name must be a short safe ASCII filename"
                )
            }
        }
    }
}

impl std::error::Error for NoiseKeyProvisioningError {}

/// Protect a 32-byte static Noise key using the native OS custody provider.
///
/// Windows keeps the existing CurrentUser-DPAPI NPK1 format. Linux writes a systemd-creds
/// host+TPM2 encrypted NPK2 credential; the unit must expose it through LoadCredentialEncrypted.
/// Raw private-key bytes are never accepted through process arguments or written to a plaintext file.
pub fn store_protected_noise_private_key(
    path: impl AsRef<Path>,
    network_id: &[u8; 32],
    private_key: &[u8; 32],
) -> Result<(), NoiseKeyProvisioningError> {
    if private_key.iter().all(|byte| *byte == 0) {
        return Err(NoiseKeyProvisioningError::InvalidKey);
    }

    #[cfg(windows)]
    {
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

    #[cfg(target_os = "linux")]
    {
        let path = path.as_ref();
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or(NoiseKeyProvisioningError::InvalidCredentialName)?;
        validate_systemd_credential_name(name)?;
        validate_systemd_credential_output_path(path)?;

        let mut payload = Vec::with_capacity(SYSTEMD_PAYLOAD_LEN);
        payload.extend_from_slice(SYSTEMD_MAGIC);
        payload.extend_from_slice(&SYSTEMD_VERSION.to_be_bytes());
        payload.extend_from_slice(network_id);
        payload.extend_from_slice(private_key);

        let encrypted = systemd_creds_encrypt(name, &payload);
        payload.zeroize();
        let encrypted = encrypted?;
        if encrypted.is_empty() || encrypted.len() > MAX_PROTECTED_BLOB {
            return Err(NoiseKeyProvisioningError::Malformed);
        }
        persist_atomic(path, &encrypted)
    }

    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = (path, network_id, private_key);
        Err(NoiseKeyProvisioningError::DpapiUnavailable)
    }
}

/// Load a platform-protected Noise key. Windows uses the existing NPK1/DPAPI path. Linux
/// requires an explicit /systemd-credential/<id> reference populated by LoadCredentialEncrypted.
pub fn load_protected_noise_private_key(
    path: impl AsRef<Path>,
    expected_network_id: &[u8; 32],
) -> Result<[u8; 32], NoiseKeyProvisioningError> {
    let path = path.as_ref();

    #[cfg(windows)]
    {
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
        if envelope.len() < HEADER_LEN + 1
            || envelope.len() > MAX_FILE_LEN
            || &envelope[..4] != MAGIC
        {
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
            plaintext.zeroize();
            return Err(NoiseKeyProvisioningError::InvalidKey);
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&plaintext);
        plaintext.zeroize();
        Ok(key)
    }

    #[cfg(target_os = "linux")]
    {
        let name = systemd_credential_reference_name(path)?;
        load_systemd_credential(name, expected_network_id)
    }

    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = (path, expected_network_id);
        Err(NoiseKeyProvisioningError::DpapiUnavailable)
    }
}

#[cfg(any(target_os = "linux", test))]
fn validate_systemd_credential_name(name: &str) -> Result<(), NoiseKeyProvisioningError> {
    if name.is_empty()
        || name.len() > 64
        || name == "."
        || name == ".."
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        || !name.as_bytes()[0].is_ascii_alphanumeric()
    {
        return Err(NoiseKeyProvisioningError::InvalidCredentialName);
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn systemd_credential_reference_name(path: &Path) -> Result<&str, NoiseKeyProvisioningError> {
    let value = path
        .to_str()
        .ok_or(NoiseKeyProvisioningError::InvalidCredentialName)?;
    let name = value
        .strip_prefix(SYSTEMD_REFERENCE_PREFIX)
        .ok_or(NoiseKeyProvisioningError::InvalidPath)?;
    validate_systemd_credential_name(name)?;
    Ok(name)
}

#[cfg(any(target_os = "linux", test))]
fn decode_systemd_credential_payload(
    payload: &mut [u8],
    expected_network_id: &[u8; 32],
) -> Result<[u8; 32], NoiseKeyProvisioningError> {
    if payload.len() != SYSTEMD_PAYLOAD_LEN || &payload[..4] != SYSTEMD_MAGIC {
        return Err(NoiseKeyProvisioningError::Malformed);
    }
    let version = u16::from_be_bytes(
        payload[4..6]
            .try_into()
            .map_err(|_| NoiseKeyProvisioningError::Malformed)?,
    );
    if version != SYSTEMD_VERSION {
        return Err(NoiseKeyProvisioningError::UnsupportedVersion);
    }
    if &payload[6..38] != expected_network_id {
        return Err(NoiseKeyProvisioningError::NetworkMismatch);
    }
    if payload[38..].iter().all(|byte| *byte == 0) {
        return Err(NoiseKeyProvisioningError::InvalidKey);
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&payload[38..]);
    payload.zeroize();
    Ok(key)
}

#[cfg(target_os = "linux")]
fn validate_systemd_credential_output_path(path: &Path) -> Result<(), NoiseKeyProvisioningError> {
    if !path.is_absolute() || unsafe { libc::geteuid() } != 0 {
        return Err(NoiseKeyProvisioningError::InvalidPath);
    }
    let parent = parent_directory(path);
    let canonical_parent =
        fs::canonicalize(parent).map_err(|_| NoiseKeyProvisioningError::InvalidPath)?;
    if canonical_parent != parent {
        return Err(NoiseKeyProvisioningError::InvalidPath);
    }

    // Check the complete path chain, not just the final directory. A root-owned leaf beneath
    // an untrusted writable ancestor could otherwise be renamed/replaced after validation.
    let mut current = std::path::PathBuf::from("/");
    for component in parent.components() {
        match component {
            std::path::Component::RootDir | std::path::Component::CurDir => continue,
            std::path::Component::Normal(name) => current.push(name),
            std::path::Component::ParentDir | std::path::Component::Prefix(_) => {
                return Err(NoiseKeyProvisioningError::InvalidPath)
            }
        }
        let metadata =
            fs::symlink_metadata(&current).map_err(|_| NoiseKeyProvisioningError::InvalidPath)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
        {
            return Err(NoiseKeyProvisioningError::InvalidPath);
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn systemd_creds_encrypt(
    credential_name: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, NoiseKeyProvisioningError> {
    if !Path::new(SYSTEMD_CREDS_PATH).is_file() {
        return Err(NoiseKeyProvisioningError::SystemdCredsUnavailable);
    }
    let mut child = Command::new(SYSTEMD_CREDS_PATH)
        .arg("encrypt")
        .arg("--with-key=host+tpm2")
        .arg("--tpm2-pcrs=7")
        .arg(format!("--name={credential_name}"))
        .arg("-")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                NoiseKeyProvisioningError::SystemdCredsUnavailable
            } else {
                NoiseKeyProvisioningError::Io
            }
        })?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or(NoiseKeyProvisioningError::SystemdCredsFailure)?;
    let write_result = stdin.write_all(plaintext);
    drop(stdin);
    if write_result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
        return Err(NoiseKeyProvisioningError::SystemdCredsFailure);
    }

    let output = child
        .wait_with_output()
        .map_err(|_| NoiseKeyProvisioningError::Io)?;
    if !output.status.success()
        || output.stdout.is_empty()
        || output.stdout.len() > MAX_PROTECTED_BLOB
    {
        return Err(NoiseKeyProvisioningError::SystemdCredsFailure);
    }
    Ok(output.stdout)
}

#[cfg(target_os = "linux")]
fn read_posix_access_acl(
    fd: std::os::fd::RawFd,
) -> Result<Option<Vec<u8>>, NoiseKeyProvisioningError> {
    const ACL_XATTR_NAME: &[u8] = b"system.posix_acl_access\0";
    let size =
        unsafe { libc::fgetxattr(fd, ACL_XATTR_NAME.as_ptr().cast(), std::ptr::null_mut(), 0) };
    if size < 0 {
        let error = io::Error::last_os_error();
        let code = error.raw_os_error();
        if code == Some(libc::ENODATA)
            || code == Some(libc::ENOTSUP)
            || code == Some(libc::EOPNOTSUPP)
        {
            return Ok(None);
        }
        return Err(NoiseKeyProvisioningError::InvalidPath);
    }
    let size = usize::try_from(size).map_err(|_| NoiseKeyProvisioningError::InvalidPath)?;
    if size == 0 || size > 4096 {
        return Err(NoiseKeyProvisioningError::InvalidPath);
    }
    let mut bytes = vec![0u8; size];
    let read = unsafe {
        libc::fgetxattr(
            fd,
            ACL_XATTR_NAME.as_ptr().cast(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    };
    if read < 0 || read as usize != size {
        return Err(NoiseKeyProvisioningError::InvalidPath);
    }
    Ok(Some(bytes))
}

#[cfg(any(target_os = "linux", test))]
fn posix_acl_grants_only_service_uid(
    bytes: &[u8],
    service_uid: u32,
    owner_permissions: u16,
    service_permissions: u16,
) -> bool {
    const ACL_VERSION: u32 = 2;
    const ACL_USER_OBJ: u16 = 0x01;
    const ACL_USER: u16 = 0x02;
    const ACL_GROUP_OBJ: u16 = 0x04;
    const ACL_MASK: u16 = 0x10;
    const ACL_OTHER: u16 = 0x20;
    const ACL_UNDEFINED_ID: u32 = u32::MAX;

    // Linux POSIX ACL xattrs contain a little-endian v2 header followed by 8-byte entries.
    // Accept only systemd's minimal ACL: owner, exactly one named service UID, empty owning
    // group, a mask equal to that UID's intended access, and no permissions for "other".
    if bytes.len() != 4 + 5 * 8
        || u32::from_le_bytes(bytes[0..4].try_into().unwrap()) != ACL_VERSION
    {
        return false;
    }

    let mut owner = false;
    let mut service = false;
    let mut group = false;
    let mut mask = false;
    let mut other = false;

    for entry in bytes[4..].chunks_exact(8) {
        let tag = u16::from_le_bytes([entry[0], entry[1]]);
        let permissions = u16::from_le_bytes([entry[2], entry[3]]);
        let id = u32::from_le_bytes(entry[4..8].try_into().unwrap());
        match tag {
            ACL_USER_OBJ
                if !owner && id == ACL_UNDEFINED_ID && permissions == owner_permissions =>
            {
                owner = true;
            }
            ACL_USER if !service && id == service_uid && permissions == service_permissions => {
                service = true;
            }
            ACL_GROUP_OBJ if !group && id == ACL_UNDEFINED_ID && permissions == 0 => {
                group = true;
            }
            ACL_MASK if !mask && id == ACL_UNDEFINED_ID && permissions == service_permissions => {
                mask = true;
            }
            ACL_OTHER if !other && id == ACL_UNDEFINED_ID && permissions == 0 => {
                other = true;
            }
            _ => return false,
        }
    }

    owner && service && group && mask && other
}

#[cfg(target_os = "linux")]
fn validate_systemd_directory_access(
    metadata: &fs::Metadata,
    fd: std::os::fd::RawFd,
    effective_uid: u32,
) -> Result<(), NoiseKeyProvisioningError> {
    let mode = metadata.mode() & 0o7777;
    if metadata.uid() == effective_uid && mode == 0o500 {
        return if read_posix_access_acl(fd)?.is_none() {
            Ok(())
        } else {
            Err(NoiseKeyProvisioningError::InvalidPath)
        };
    }

    // systemd 255 keeps the credential directory root-owned when POSIX ACLs are supported.
    // It grants the service UID r-x, removes write from USER_OBJ/MASK/OTHER, and leaves group
    // and other entries empty. The resulting mode is 0550 because stat's group bits reflect ACL_MASK.
    if effective_uid != 0
        && metadata.uid() == 0
        && mode == 0o550
        && read_posix_access_acl(fd)?
            .is_some_and(|acl| posix_acl_grants_only_service_uid(&acl, effective_uid, 0o5, 0o5))
    {
        return Ok(());
    }
    Err(NoiseKeyProvisioningError::InvalidPath)
}

#[cfg(target_os = "linux")]
fn validate_systemd_file_access(
    metadata: &fs::Metadata,
    fd: std::os::fd::RawFd,
    effective_uid: u32,
) -> Result<(), NoiseKeyProvisioningError> {
    let mode = metadata.mode() & 0o7777;
    if metadata.uid() == effective_uid && mode == 0o400 {
        return if read_posix_access_acl(fd)?.is_none() {
            Ok(())
        } else {
            Err(NoiseKeyProvisioningError::InvalidPath)
        };
    }

    // With ACL support, systemd keeps the file root-owned and grants only the unit UID r--.
    // ACL_MASK appears as the group-read bits in st_mode, hence the expected 0440 mode.
    if effective_uid != 0
        && metadata.uid() == 0
        && mode == 0o440
        && read_posix_access_acl(fd)?
            .is_some_and(|acl| posix_acl_grants_only_service_uid(&acl, effective_uid, 0o4, 0o4))
    {
        return Ok(());
    }
    Err(NoiseKeyProvisioningError::InvalidPath)
}

#[cfg(target_os = "linux")]
fn load_systemd_credential(
    credential_name: &str,
    expected_network_id: &[u8; 32],
) -> Result<[u8; 32], NoiseKeyProvisioningError> {
    let directory = std::env::var_os("CREDENTIALS_DIRECTORY")
        .map(std::path::PathBuf::from)
        .ok_or(NoiseKeyProvisioningError::SystemdCredentialUnavailable)?;
    load_systemd_credential_from_directory(&directory, credential_name, expected_network_id)
}

#[cfg(target_os = "linux")]
fn load_systemd_credential_from_directory(
    directory: &Path,
    credential_name: &str,
    expected_network_id: &[u8; 32],
) -> Result<[u8; 32], NoiseKeyProvisioningError> {
    validate_systemd_credential_name(credential_name)?;
    if !directory.is_absolute()
        || fs::canonicalize(directory).map_err(|_| NoiseKeyProvisioningError::InvalidPath)?
            != directory
    {
        return Err(NoiseKeyProvisioningError::InvalidPath);
    }

    // Open the credential directory itself without following the final path component, then
    // validate the opened inode and ACL. On systemd 255, ACL-capable filesystems commonly keep
    // the directory root-owned and grant only the service UID r-x; the no-ACL fallback instead
    // chowns it to the service UID and leaves it mode 0500.
    let directory_before = fs::symlink_metadata(directory)
        .map_err(|_| NoiseKeyProvisioningError::SystemdCredentialUnavailable)?;
    if !directory_before.is_dir() || directory_before.file_type().is_symlink() {
        return Err(NoiseKeyProvisioningError::InvalidPath);
    }
    let mut directory_options = OpenOptions::new();
    directory_options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let directory_file = directory_options
        .open(directory)
        .map_err(|_| NoiseKeyProvisioningError::SystemdCredentialUnavailable)?;
    let directory_metadata = directory_file
        .metadata()
        .map_err(|_| NoiseKeyProvisioningError::SystemdCredentialUnavailable)?;
    if directory_metadata.dev() != directory_before.dev()
        || directory_metadata.ino() != directory_before.ino()
        || !directory_metadata.is_dir()
    {
        return Err(NoiseKeyProvisioningError::InvalidPath);
    }

    let effective_uid = unsafe { libc::geteuid() };
    validate_systemd_directory_access(
        &directory_metadata,
        directory_file.as_raw_fd(),
        effective_uid,
    )?;

    // The ID was validated as a single safe ASCII filename, so openat keeps resolution rooted
    // at the already-validated directory inode and O_NOFOLLOW rejects a swapped symlink.
    let credential_name_c = CString::new(credential_name)
        .map_err(|_| NoiseKeyProvisioningError::InvalidCredentialName)?;
    let credential_fd = unsafe {
        libc::openat(
            directory_file.as_raw_fd(),
            credential_name_c.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if credential_fd < 0 {
        let error = io::Error::last_os_error();
        return Err(if error.raw_os_error() == Some(libc::ELOOP) {
            NoiseKeyProvisioningError::InvalidPath
        } else {
            NoiseKeyProvisioningError::SystemdCredentialUnavailable
        });
    }
    let file = unsafe { File::from_raw_fd(credential_fd) };
    let metadata = file
        .metadata()
        .map_err(|_| NoiseKeyProvisioningError::SystemdCredentialUnavailable)?;
    if !metadata.is_file() || metadata.len() != SYSTEMD_PAYLOAD_LEN as u64 || metadata.nlink() != 1
    {
        return Err(NoiseKeyProvisioningError::InvalidPath);
    }
    validate_systemd_file_access(&metadata, file.as_raw_fd(), effective_uid)?;

    let mut payload = zeroize::Zeroizing::new(Vec::with_capacity(SYSTEMD_PAYLOAD_LEN));
    file.take((SYSTEMD_PAYLOAD_LEN + 1) as u64)
        .read_to_end(&mut payload)
        .map_err(|_| NoiseKeyProvisioningError::SystemdCredentialUnavailable)?;
    decode_systemd_credential_payload(&mut payload, expected_network_id)
}

#[cfg(windows)]
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
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(target_os = "linux")]
        options.mode(0o600);
        let mut file = options.open(&temporary)?;
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
    fn dpapi_protected_noise_key_survives_process_restart() {
        const CHILD_PATH_ENV: &str = "AIN1_TEST_DPAPI_NOISE_KEY_CHILD_PATH";

        // The child test process reopens only the protected envelope. The synthetic test key
        // remains compiled into the test and is never passed in an argument or environment value.
        if let Some(path) = std::env::var_os(CHILD_PATH_ENV) {
            let path = PathBuf::from(path);
            let network = [0x37; 32];
            assert_eq!(
                load_protected_noise_private_key(&path, &network).unwrap(),
                [0x62; 32]
            );
            assert_eq!(
                load_protected_noise_private_key(&path, &[0x38; 32]).unwrap_err(),
                NoiseKeyProvisioningError::NetworkMismatch
            );
            return;
        }

        let path = temp_path("process-reload");
        let network = [0x37; 32];
        store_protected_noise_private_key(&path, &network, &[0x62; 32]).unwrap();

        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(
                "noise_key_provisioning::tests::dpapi_protected_noise_key_survives_process_restart",
            )
            .arg("--nocapture")
            .env(CHILD_PATH_ENV, &path)
            .status()
            .unwrap();

        let _ = fs::remove_file(&path);
        assert!(
            child.success(),
            "fresh test process could not reload protected Noise identity"
        );
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_protected_noise_key_rotation_reloads_new_key_in_child_process() {
        const CHILD_PATH_ENV: &str = "AIN1_TEST_DPAPI_NOISE_KEY_ROTATION_CHILD_PATH";

        // The child process receives only the protected-file path. Test key bytes stay in
        // compiled test code and are never placed in arguments or environment variables.
        if let Some(path) = std::env::var_os(CHILD_PATH_ENV) {
            let path = PathBuf::from(path);
            let network = [0x47; 32];
            assert_eq!(
                load_protected_noise_private_key(&path, &network).unwrap(),
                [0x63; 32]
            );
            assert_eq!(
                load_protected_noise_private_key(&path, &[0x48; 32]).unwrap_err(),
                NoiseKeyProvisioningError::NetworkMismatch
            );
            return;
        }

        let path = temp_path("rotation-process-reload");
        let network = [0x47; 32];
        let old_key = [0x62; 32];
        let new_key = [0x63; 32];

        store_protected_noise_private_key(&path, &network, &old_key).unwrap();
        let old_envelope = fs::read(&path).unwrap();
        assert!(!old_envelope
            .windows(old_key.len())
            .any(|window| window == old_key));
        assert_eq!(
            load_protected_noise_private_key(&path, &network).unwrap(),
            old_key
        );

        // A rejected replacement must leave the previously protected identity intact.
        assert_eq!(
            store_protected_noise_private_key(&path, &network, &[0; 32]).unwrap_err(),
            NoiseKeyProvisioningError::InvalidKey
        );
        assert_eq!(
            load_protected_noise_private_key(&path, &network).unwrap(),
            old_key
        );

        // The valid replacement uses the existing atomic protected-file persistence path.
        store_protected_noise_private_key(&path, &network, &new_key).unwrap();
        let new_envelope = fs::read(&path).unwrap();
        assert_ne!(old_envelope, new_envelope);
        assert!(!new_envelope
            .windows(new_key.len())
            .any(|window| window == new_key));
        assert_eq!(
            load_protected_noise_private_key(&path, &network).unwrap(),
            new_key
        );

        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("noise_key_provisioning::tests::dpapi_protected_noise_key_rotation_reloads_new_key_in_child_process")
            .arg("--nocapture")
            .env(CHILD_PATH_ENV, &path)
            .status()
            .unwrap();

        let _ = fs::remove_file(&path);
        assert!(
            child.success(),
            "fresh test process could not reload the rotated protected Noise key"
        );
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

    #[test]
    fn systemd_credential_reference_requires_explicit_safe_id() {
        assert_eq!(
            systemd_credential_reference_name(Path::new(
                "/systemd-credential/qfp6-noise-static-key"
            ))
            .unwrap(),
            "qfp6-noise-static-key"
        );
        for invalid in [
            "/systemd-credential/../noise-key",
            "/systemd-credential/nested/key",
            "/systemd-credential/",
            "/systemd-credential/.hidden",
            "/systemd-credential/with space",
            "/ordinary/path",
        ] {
            assert!(
                systemd_credential_reference_name(Path::new(invalid)).is_err(),
                "must reject {invalid}"
            );
        }
    }

    #[test]
    fn systemd_posix_acl_accepts_only_the_exact_service_uid_grant() {
        fn entry(tag: u16, permissions: u16, id: u32) -> [u8; 8] {
            let mut bytes = [0u8; 8];
            bytes[0..2].copy_from_slice(&tag.to_le_bytes());
            bytes[2..4].copy_from_slice(&permissions.to_le_bytes());
            bytes[4..8].copy_from_slice(&id.to_le_bytes());
            bytes
        }
        fn acl(uid: u32, owner: u16, service: u16, group: u16, mask: u16, other: u16) -> Vec<u8> {
            let mut bytes = 2u32.to_le_bytes().to_vec();
            bytes.extend_from_slice(&entry(0x01, owner, u32::MAX));
            bytes.extend_from_slice(&entry(0x02, service, uid));
            bytes.extend_from_slice(&entry(0x04, group, u32::MAX));
            bytes.extend_from_slice(&entry(0x10, mask, u32::MAX));
            bytes.extend_from_slice(&entry(0x20, other, u32::MAX));
            bytes
        }

        let uid = 1207;
        let directory_acl = acl(uid, 0o5, 0o5, 0, 0o5, 0);
        let file_acl = acl(uid, 0o4, 0o4, 0, 0o4, 0);
        assert!(posix_acl_grants_only_service_uid(
            &directory_acl,
            uid,
            0o5,
            0o5
        ));
        assert!(posix_acl_grants_only_service_uid(&file_acl, uid, 0o4, 0o4));

        assert!(!posix_acl_grants_only_service_uid(
            &directory_acl,
            uid + 1,
            0o5,
            0o5
        ));
        assert!(!posix_acl_grants_only_service_uid(
            &acl(uid, 0o7, 0o5, 0, 0o5, 0),
            uid,
            0o5,
            0o5
        ));
        assert!(!posix_acl_grants_only_service_uid(
            &acl(uid, 0o5, 0o7, 0, 0o7, 0),
            uid,
            0o5,
            0o5
        ));
        assert!(!posix_acl_grants_only_service_uid(
            &acl(uid, 0o5, 0o5, 0o1, 0o5, 0),
            uid,
            0o5,
            0o5
        ));
        assert!(!posix_acl_grants_only_service_uid(
            &acl(uid, 0o5, 0o5, 0, 0o5, 0o1),
            uid,
            0o5,
            0o5
        ));

        let mut bad_version = directory_acl.clone();
        bad_version[0] = 1;
        assert!(!posix_acl_grants_only_service_uid(
            &bad_version,
            uid,
            0o5,
            0o5
        ));
        let mut truncated = file_acl.clone();
        truncated.pop();
        assert!(!posix_acl_grants_only_service_uid(
            &truncated, uid, 0o4, 0o4
        ));
        let mut extra_entry = directory_acl.clone();
        extra_entry.extend_from_slice(&entry(0x08, 0o7, uid));
        assert!(!posix_acl_grants_only_service_uid(
            &extra_entry,
            uid,
            0o5,
            0o5
        ));
    }

    #[test]
    fn systemd_credential_payload_is_network_bound_and_zeroized() {
        let network = [0x31; 32];
        let key = [0x62; 32];
        let mut payload = Vec::with_capacity(SYSTEMD_PAYLOAD_LEN);
        payload.extend_from_slice(SYSTEMD_MAGIC);
        payload.extend_from_slice(&SYSTEMD_VERSION.to_be_bytes());
        payload.extend_from_slice(&network);
        payload.extend_from_slice(&key);

        assert_eq!(
            decode_systemd_credential_payload(&mut payload, &network).unwrap(),
            key
        );
        assert!(payload.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn systemd_credential_payload_rejects_wrong_network_version_and_zero_key() {
        let network = [0x31; 32];
        let mut payload = Vec::with_capacity(SYSTEMD_PAYLOAD_LEN);
        payload.extend_from_slice(SYSTEMD_MAGIC);
        payload.extend_from_slice(&SYSTEMD_VERSION.to_be_bytes());
        payload.extend_from_slice(&network);
        payload.extend_from_slice(&[0x62; 32]);
        assert_eq!(
            decode_systemd_credential_payload(&mut payload.clone(), &[0x32; 32]).unwrap_err(),
            NoiseKeyProvisioningError::NetworkMismatch
        );

        let mut bad_version = payload.clone();
        bad_version[5] = 2;
        assert_eq!(
            decode_systemd_credential_payload(&mut bad_version, &network).unwrap_err(),
            NoiseKeyProvisioningError::UnsupportedVersion
        );

        let mut zero_key = payload.clone();
        zero_key[38..].fill(0);
        assert_eq!(
            decode_systemd_credential_payload(&mut zero_key, &network).unwrap_err(),
            NoiseKeyProvisioningError::InvalidKey
        );

        let mut wrong_magic = payload.clone();
        wrong_magic[0] ^= 0x80;
        assert_eq!(
            decode_systemd_credential_payload(&mut wrong_magic, &network).unwrap_err(),
            NoiseKeyProvisioningError::Malformed
        );

        let mut truncated = payload.clone();
        truncated.truncate(SYSTEMD_PAYLOAD_LEN - 1);
        assert_eq!(
            decode_systemd_credential_payload(&mut truncated, &network).unwrap_err(),
            NoiseKeyProvisioningError::Malformed
        );
    }

    #[test]
    fn systemd_posix_acl_accepts_only_root_and_one_service_identity() {
        const USER_OBJ: u16 = 0x01;
        const USER: u16 = 0x02;
        const GROUP_OBJ: u16 = 0x04;
        const MASK: u16 = 0x10;
        const OTHER: u16 = 0x20;
        const UNDEFINED: u32 = u32::MAX;
        const SERVICE_UID: u32 = 23_456;

        fn encoded_acl(entries: &[(u16, u16, u32)]) -> Vec<u8> {
            let mut bytes = Vec::with_capacity(4 + entries.len() * 8);
            bytes.extend_from_slice(&2u32.to_le_bytes());
            for (tag, permissions, id) in entries {
                bytes.extend_from_slice(&tag.to_le_bytes());
                bytes.extend_from_slice(&permissions.to_le_bytes());
                bytes.extend_from_slice(&id.to_le_bytes());
            }
            bytes
        }

        let directory_acl = encoded_acl(&[
            (USER_OBJ, 0o5, UNDEFINED),
            (USER, 0o5, SERVICE_UID),
            (GROUP_OBJ, 0, UNDEFINED),
            (MASK, 0o5, UNDEFINED),
            (OTHER, 0, UNDEFINED),
        ]);
        let file_acl = encoded_acl(&[
            (USER_OBJ, 0o4, UNDEFINED),
            (USER, 0o4, SERVICE_UID),
            (GROUP_OBJ, 0, UNDEFINED),
            (MASK, 0o4, UNDEFINED),
            (OTHER, 0, UNDEFINED),
        ]);

        assert!(posix_acl_grants_only_service_uid(
            &directory_acl,
            SERVICE_UID,
            0o5,
            0o5
        ));
        assert!(posix_acl_grants_only_service_uid(
            &file_acl,
            SERVICE_UID,
            0o4,
            0o4
        ));

        let reject = |mut acl: Vec<u8>| {
            assert!(!posix_acl_grants_only_service_uid(
                &acl,
                SERVICE_UID,
                0o5,
                0o5
            ));
            acl.zeroize();
        };

        let mut group_read = directory_acl.clone();
        group_read[4 + 2 * 8 + 2..4 + 2 * 8 + 4].copy_from_slice(&0o4u16.to_le_bytes());
        reject(group_read);

        let mut excessive_mask = directory_acl.clone();
        excessive_mask[4 + 3 * 8 + 2..4 + 3 * 8 + 4].copy_from_slice(&0o7u16.to_le_bytes());
        reject(excessive_mask);

        let mut other_read = directory_acl.clone();
        other_read[4 + 4 * 8 + 2..4 + 4 * 8 + 4].copy_from_slice(&0o4u16.to_le_bytes());
        reject(other_read);

        let mut wrong_uid = directory_acl.clone();
        wrong_uid[4 + 1 * 8 + 4..4 + 1 * 8 + 8].copy_from_slice(&(SERVICE_UID + 1).to_le_bytes());
        reject(wrong_uid);

        let mut extra_user = directory_acl.clone();
        extra_user.extend_from_slice(&USER.to_le_bytes());
        extra_user.extend_from_slice(&0o7u16.to_le_bytes());
        extra_user.extend_from_slice(&(SERVICE_UID + 1).to_le_bytes());
        reject(extra_user);

        let mut wrong_version = directory_acl.clone();
        wrong_version[..4].copy_from_slice(&1u32.to_le_bytes());
        reject(wrong_version);

        let mut truncated = directory_acl.clone();
        truncated.pop();
        reject(truncated);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "must run inside a systemd service with LoadCredential="]
    fn systemd_credential_loader_accepts_actual_systemd_credentials_directory() {
        assert_eq!(
            load_systemd_credential("qfp6-noise-static-key", &[0x31; 32]).unwrap(),
            [0x62; 32]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires a root-owned POSIX ACL credential fixture prepared by the Linux test harness"]
    fn systemd_credential_loader_accepts_root_owned_posix_acl_delivery() {
        let directory = std::env::var_os("QFP6_SYSTEMD_ACL_TEST_DIR")
            .map(std::path::PathBuf::from)
            .expect("QFP6_SYSTEMD_ACL_TEST_DIR must point at the prepared fixture");
        let metadata = fs::symlink_metadata(&directory).unwrap();
        assert_eq!(metadata.uid(), 0);
        assert_eq!(metadata.mode() & 0o7777, 0o550);

        let credential = directory.join("qfp6-noise-static-key");
        let metadata = fs::symlink_metadata(&credential).unwrap();
        assert_eq!(metadata.uid(), 0);
        assert_eq!(metadata.mode() & 0o7777, 0o440);
        assert_eq!(metadata.nlink(), 1);

        assert_eq!(
            load_systemd_credential_from_directory(
                &directory,
                "qfp6-noise-static-key",
                &[0x31; 32]
            )
            .unwrap(),
            [0x62; 32]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn systemd_credential_loader_accepts_only_private_single_link_service_files() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let network = [0x31; 32];
        let key = [0x62; 32];
        let mut payload = Vec::with_capacity(SYSTEMD_PAYLOAD_LEN);
        payload.extend_from_slice(SYSTEMD_MAGIC);
        payload.extend_from_slice(&SYSTEMD_VERSION.to_be_bytes());
        payload.extend_from_slice(&network);
        payload.extend_from_slice(&key);

        let directory = temp_path("systemd-loader");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let credential = directory.join("qfp6-noise-static-key");
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o400);
        let mut file = options.open(&credential).unwrap();
        file.write_all(&payload).unwrap();
        drop(file);
        fs::set_permissions(&credential, fs::Permissions::from_mode(0o400)).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o500)).unwrap();

        assert_eq!(
            load_systemd_credential_from_directory(&directory, "qfp6-noise-static-key", &network)
                .unwrap(),
            key
        );
        assert_eq!(
            load_systemd_credential_from_directory(
                &directory,
                "qfp6-noise-static-key",
                &[0x32; 32]
            )
            .unwrap_err(),
            NoiseKeyProvisioningError::NetworkMismatch
        );

        let alias = directory.join("hardlink");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        fs::hard_link(&credential, &alias).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o500)).unwrap();
        assert_eq!(
            load_systemd_credential_from_directory(&directory, "qfp6-noise-static-key", &network)
                .unwrap_err(),
            NoiseKeyProvisioningError::InvalidPath
        );
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_file(alias).unwrap();

        let symlink_path = directory.join("symlink");
        symlink(&credential, &symlink_path).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o500)).unwrap();
        assert_eq!(
            load_systemd_credential_from_directory(&directory, "symlink", &network).unwrap_err(),
            NoiseKeyProvisioningError::InvalidPath
        );
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_file(symlink_path).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o500)).unwrap();

        fs::set_permissions(&credential, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            load_systemd_credential_from_directory(&directory, "qfp6-noise-static-key", &network)
                .unwrap_err(),
            NoiseKeyProvisioningError::InvalidPath
        );
        fs::set_permissions(&credential, fs::Permissions::from_mode(0o400)).unwrap();

        fs::set_permissions(&directory, fs::Permissions::from_mode(0o550)).unwrap();
        assert_eq!(
            load_systemd_credential_from_directory(&directory, "qfp6-noise-static-key", &network)
                .unwrap_err(),
            NoiseKeyProvisioningError::InvalidPath
        );
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();

        fs::remove_file(credential).unwrap();
        fs::remove_dir(directory).unwrap();
    }
}
