//! Read-only loader for QZKW1 Windows CurrentUser-DPAPI wallets.
//! The secret is never written to a file or emitted by this module. This is local Windows custody,
//! not a portable backup, HSM, or production-wallet certification.
#[cfg(windows)]
use crate::transaction_auth::Ed25519TransactionSigner;
use std::path::Path;
#[cfg(windows)]
use std::{
    fs::{self, File},
    io::Read,
};

#[cfg(windows)]
const MAGIC: &[u8; 4] = b"QZKW";
#[cfg(windows)]
const VERSION: u16 = 1;
#[cfg(windows)]
const HEADER_LEN: usize = 4 + 2 + 32 + 32 + 4;
#[cfg(windows)]
const MAX_PROTECTED_BLOB: usize = 64 * 1024;
#[cfg(windows)]
const MAX_FILE_LEN: usize = HEADER_LEN + MAX_PROTECTED_BLOB;
#[cfg(windows)]
const WALLET_DOMAIN: &[u8] = b"QUANTUMZXB-ED25519-WALLET-DPAPI-V1\0";

struct SecretSeed([u8; 32]);
impl Drop for SecretSeed {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// An authenticated QZKW1 wallet decoded for local signing.
pub struct ProtectedWallet {
    seed: SecretSeed,
    public_key: [u8; 32],
    account_id: [u8; 32],
}
impl ProtectedWallet {
    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }
    pub fn account_id(&self) -> [u8; 32] {
        self.account_id
    }
    /// Consumes this protected wallet to produce the signer without returning raw seed bytes.
    #[cfg(windows)]
    pub fn into_signer(self) -> Ed25519TransactionSigner {
        Ed25519TransactionSigner::from_seed(self.seed.0)
    }
}

/// Loads a QZKW1 wallet protected for the current Windows user and re-derives both public IDs.
/// On non-Windows platforms, the function fails closed instead of accepting an unprotected key.
pub fn load_current_user_wallet(path: impl AsRef<Path>) -> Result<ProtectedWallet, String> {
    #[cfg(windows)]
    {
        load_windows_wallet(path.as_ref())
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err("QZKW1 CurrentUser-DPAPI wallet loading is available only on Windows".into())
    }
}

#[cfg(windows)]
fn load_windows_wallet(path: &Path) -> Result<ProtectedWallet, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| "wallet file could not be inspected".to_string())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("wallet path must be a regular non-symlink file".into());
    }
    if metadata.len() < (HEADER_LEN + 1) as u64 || metadata.len() > MAX_FILE_LEN as u64 {
        return Err("wallet file length is invalid".into());
    }
    let file = File::open(path).map_err(|_| "wallet file could not be opened".to_string())?;
    let mut envelope = Vec::with_capacity(metadata.len() as usize);
    file.take((MAX_FILE_LEN + 1) as u64)
        .read_to_end(&mut envelope)
        .map_err(|_| "wallet file could not be read".to_string())?;
    if envelope.len() < HEADER_LEN + 1 || envelope.len() > MAX_FILE_LEN || &envelope[..4] != MAGIC {
        return Err("wallet envelope magic, length, or format is invalid".into());
    }
    let version = u16::from_be_bytes([envelope[4], envelope[5]]);
    if version != VERSION {
        return Err(format!("unsupported wallet version: {version}"));
    }
    let public_key: [u8; 32] = envelope[6..38]
        .try_into()
        .map_err(|_| "wallet public key is malformed")?;
    let account_id: [u8; 32] = envelope[38..70]
        .try_into()
        .map_err(|_| "wallet account ID is malformed")?;
    if public_key.iter().all(|byte| *byte == 0) || account_id.iter().all(|byte| *byte == 0) {
        return Err("wallet public identifiers must be nonzero".into());
    }
    let protected_len = u32::from_be_bytes(
        envelope[70..74]
            .try_into()
            .map_err(|_| "wallet length is malformed")?,
    ) as usize;
    if protected_len == 0
        || protected_len > MAX_PROTECTED_BLOB
        || HEADER_LEN.checked_add(protected_len) != Some(envelope.len())
    {
        return Err("wallet protected payload length is invalid".into());
    }
    let mut raw = dpapi_unprotect(&envelope[HEADER_LEN..], &public_key, &account_id)?;
    if raw.len() != 32 || raw.iter().all(|byte| *byte == 0) {
        raw.fill(0);
        return Err("wallet seed is invalid".into());
    }
    let mut seed_bytes = [0u8; 32];
    seed_bytes.copy_from_slice(&raw);
    raw.fill(0);
    let seed = SecretSeed(seed_bytes);
    let signer = Ed25519TransactionSigner::from_seed(seed.0);
    if signer.public_key() != public_key || signer.account_id() != account_id {
        return Err("wallet seed does not match the stored public identity".into());
    }
    Ok(ProtectedWallet {
        seed,
        public_key,
        account_id,
    })
}

#[cfg(windows)]
fn dpapi_unprotect(
    blob: &[u8],
    public_key: &[u8; 32],
    account_id: &[u8; 32],
) -> Result<Vec<u8>, String> {
    use std::{ffi::c_void, ptr};
    #[repr(C)]
    struct DataBlob {
        cb_data: u32,
        pb_data: *mut u8,
    }
    #[link(name = "Crypt32")]
    extern "system" {
        fn CryptUnprotectData(
            input: *const DataBlob,
            description: *mut *mut u16,
            optional_entropy: *const DataBlob,
            reserved: *mut c_void,
            prompt: *mut c_void,
            flags: u32,
            output: *mut DataBlob,
        ) -> i32;
    }
    #[link(name = "Kernel32")]
    extern "system" {
        fn LocalFree(memory: *mut c_void) -> *mut c_void;
        fn GetLastError() -> u32;
    }

    if blob.len() > u32::MAX as usize {
        return Err("protected wallet blob is too large".into());
    }
    let mut entropy = Vec::with_capacity(WALLET_DOMAIN.len() + 64);
    entropy.extend_from_slice(WALLET_DOMAIN);
    entropy.extend_from_slice(public_key);
    entropy.extend_from_slice(account_id);
    let input = DataBlob {
        cb_data: blob.len() as u32,
        pb_data: blob.as_ptr() as *mut u8,
    };
    let optional_entropy = DataBlob {
        cb_data: entropy.len() as u32,
        pb_data: entropy.as_ptr() as *mut u8,
    };
    let mut output = DataBlob {
        cb_data: 0,
        pb_data: ptr::null_mut(),
    };
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            ptr::null_mut(),
            &optional_entropy,
            ptr::null_mut(),
            ptr::null_mut(),
            0x1,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(format!(
            "wallet could not be unprotected for the current Windows user (Win32 error {})",
            unsafe { GetLastError() }
        ));
    }
    if output.pb_data.is_null() || output.cb_data != 32 {
        if !output.pb_data.is_null() {
            unsafe {
                ptr::write_bytes(output.pb_data, 0, output.cb_data as usize);
                LocalFree(output.pb_data as *mut c_void);
            }
        }
        return Err("unprotected wallet seed has an invalid length".into());
    }
    let mut seed =
        unsafe { std::slice::from_raw_parts(output.pb_data, output.cb_data as usize).to_vec() };
    unsafe {
        ptr::write_bytes(output.pb_data, 0, output.cb_data as usize);
        LocalFree(output.pb_data as *mut c_void);
    }
    Ok(std::mem::take(&mut seed))
}
