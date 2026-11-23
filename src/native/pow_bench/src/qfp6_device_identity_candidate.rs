//! CP-0801 QFP6 TPM-backed Noise identity binding candidate.
//!
//! This module keeps the existing DPAPI/NPK1 Noise key intact. A TPM-backed ECDSA-P256
//! Device Root signs a domain-separated statement binding that exact X25519 public key
//! to the QFP6 NetworkId/ProfileId. Startup verification reopens the named Windows CNG
//! key, checks its TPM public coordinates against the local metadata, verifies the
//! binding signature, and performs a fresh private-key operation. Nothing is published.
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snow::{
    params::DHChoice,
    resolvers::{CryptoResolver, DefaultResolver},
};
use std::{fs, path::Path};
use zeroize::Zeroizing;

const META_SCHEMA: &str = "QFP6_DEVICE_ROOT_V1";
const BINDING_SCHEMA: &str = "QFP6_NOISE_DEVICE_BINDING_V1";
const DEVICE_ROOT_DOMAIN: &[u8] = b"QFP6-DEVICE-ROOT-V1\0";
const BINDING_DOMAIN: &[u8] = b"QFP6-NOISE-DEVICE-BINDING-V1\0";
const PROBE_DOMAIN: &[u8] = b"QFP6-DEVICE-ROOT-RUNTIME-PROBE-V1\0";
const MAX_METADATA_BYTES: u64 = 16 * 1024;
const MAX_BINDING_BYTES: u64 = 8 * 1024;
const P256_SIGNATURE_BYTES: usize = 64;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceRootMetadata {
    schema: String,
    key_name: String,
    provider: String,
    algorithm: String,
    export_policy: String,
    private_key_exportable: bool,
    network_id: String,
    profile_id: String,
    device_id: String,
    public_key_x_base64: String,
    public_key_y_base64: String,
    scope: String,
    key_scope: String,
    created_at_utc: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceRootBinding {
    schema: String,
    key_version: u32,
    key_name: String,
    network_id: String,
    profile_id: String,
    device_id: String,
    noise_static_public_key_hex: String,
    signature_base64: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDeviceRootBinding {
    pub device_id: String,
    pub noise_static_public_key: [u8; 32],
    pub network_id: [u8; 32],
    pub profile_id: [u8; 32],
}

fn parse_hex32(label: &str, value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("{label} must be exactly 32 bytes of hexadecimal"));
    }
    let mut out = [0u8; 32];
    for (i, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(pair).map_err(|_| format!("{label} is not ASCII"))?;
        out[i] = u8::from_str_radix(text, 16).map_err(|_| format!("{label} is malformed"))?;
    }
    Ok(out)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

fn read_bounded_regular_file(path: &Path, max: u64, label: &str) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("{label} metadata could not be read: {error}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > max
    {
        return Err(format!(
            "{label} must be a non-empty regular non-symlink file no larger than {max} bytes"
        ));
    }
    let bytes = fs::read(path).map_err(|error| format!("{label} could not be read: {error}"))?;
    if bytes.is_empty() || bytes.len() as u64 > max {
        return Err(format!("{label} length is outside the allowed bound"));
    }
    Ok(bytes)
}

fn metadata_public_coordinates(meta: &DeviceRootMetadata) -> Result<([u8; 32], [u8; 32]), String> {
    if meta.schema != META_SCHEMA
        || meta.key_name.is_empty()
        || meta.key_name.len() > 128
        || meta.provider != "Microsoft Platform Crypto Provider"
        || meta.algorithm != "ECDSA_P256"
        || meta.export_policy != "NONE"
        || meta.private_key_exportable
        || meta.scope != "LOCAL_ONLY_NOT_PUBLISHED"
        || meta.key_scope != "CURRENT_USER_CNG"
        || meta.created_at_utc.is_empty()
    {
        return Err(
            "TPM Device Root metadata does not match the supported local-only P-256 schema".into(),
        );
    }
    let network_id = parse_hex32("metadata NetworkId", &meta.network_id)?;
    let profile_id = parse_hex32("metadata ProfileId", &meta.profile_id)?;
    let x = BASE64
        .decode(&meta.public_key_x_base64)
        .map_err(|_| "TPM public X coordinate is invalid Base64".to_string())?;
    let y = BASE64
        .decode(&meta.public_key_y_base64)
        .map_err(|_| "TPM public Y coordinate is invalid Base64".to_string())?;
    let x: [u8; 32] = x
        .try_into()
        .map_err(|_| "TPM public X coordinate must be 32 bytes".to_string())?;
    let y: [u8; 32] = y
        .try_into()
        .map_err(|_| "TPM public Y coordinate must be 32 bytes".to_string())?;
    let mut id_preimage = Vec::with_capacity(DEVICE_ROOT_DOMAIN.len() + 128);
    id_preimage.extend_from_slice(DEVICE_ROOT_DOMAIN);
    id_preimage.extend_from_slice(&network_id);
    id_preimage.extend_from_slice(&profile_id);
    id_preimage.extend_from_slice(&x);
    id_preimage.extend_from_slice(&y);
    let expected_device_id = hex(&Sha256::digest(&id_preimage));
    if meta.device_id != expected_device_id {
        return Err(
            "TPM Device Root device_id does not match NetworkId/ProfileId/public key".into(),
        );
    }
    Ok((x, y))
}

pub fn derive_noise_static_public_key(private_key: &[u8; 32]) -> Result<[u8; 32], String> {
    if private_key.iter().all(|byte| *byte == 0) {
        return Err("Noise private key is all zero".into());
    }
    let resolver = DefaultResolver::default();
    let mut dh = resolver
        .resolve_dh(&DHChoice::Curve25519)
        .ok_or("Noise Curve25519 implementation is unavailable")?;
    dh.set(private_key);
    dh.pubkey()
        .try_into()
        .map_err(|_| "Noise Curve25519 public key has an unexpected length".into())
}

fn binding_preimage(
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
    device_id: &[u8; 32],
    noise_public: &[u8; 32],
    key_version: u32,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(BINDING_DOMAIN.len() + 32 * 4 + 4);
    out.extend_from_slice(BINDING_DOMAIN);
    out.extend_from_slice(network_id);
    out.extend_from_slice(profile_id);
    out.extend_from_slice(device_id);
    out.extend_from_slice(noise_public);
    out.extend_from_slice(&key_version.to_be_bytes());
    out
}

fn binding_digest(
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
    device_id: &[u8; 32],
    noise_public: &[u8; 32],
    key_version: u32,
) -> [u8; 32] {
    Sha256::digest(binding_preimage(
        network_id,
        profile_id,
        device_id,
        noise_public,
        key_version,
    ))
    .into()
}

fn parse_metadata(path: &Path) -> Result<(DeviceRootMetadata, [u8; 32], [u8; 32]), String> {
    let bytes = read_bounded_regular_file(path, MAX_METADATA_BYTES, "TPM Device Root metadata")?;
    // The original PowerShell provisioner writes UTF-8 with a BOM; accept that exact
    // Windows convention while keeping the JSON schema strict after the prefix.
    let json_bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(&bytes);
    let meta: DeviceRootMetadata = serde_json::from_slice(json_bytes)
        .map_err(|error| format!("TPM Device Root metadata JSON rejected: {error}"))?;
    let (x, y) = metadata_public_coordinates(&meta)?;
    Ok((meta, x, y))
}

/// Create a local binding record for the existing DPAPI-protected Noise key.
/// The Noise private key is decrypted only in this process and is never written or printed.
pub fn create_device_root_binding_record(
    metadata_path: &Path,
    noise_private_key_path: &Path,
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let (meta, x, y) = parse_metadata(metadata_path)?;
    if parse_hex32("metadata NetworkId", &meta.network_id)? != *network_id
        || parse_hex32("metadata ProfileId", &meta.profile_id)? != *profile_id
    {
        return Err("TPM Device Root metadata belongs to another QFP6 network/profile".into());
    }
    let noise_private = Zeroizing::new(
        crate::noise_key_provisioning::load_protected_noise_private_key(
            noise_private_key_path,
            network_id,
        )
        .map_err(|error| format!("existing protected Noise key could not be loaded: {error}"))?,
    );
    let noise_public = derive_noise_static_public_key(&noise_private)?;

    #[cfg(windows)]
    {
        let (provider_handle, key_handle) = cng::open_key(&meta.provider, &meta.key_name)?;
        let result = (|| {
            cng::assert_public_key_matches(key_handle, &x, &y)?;
            let device_id = parse_hex32("metadata device_id", &meta.device_id)?;
            let digest = binding_digest(network_id, profile_id, &device_id, &noise_public, 1);
            let signature = cng::sign_digest(key_handle, &digest)?;
            if signature.len() != P256_SIGNATURE_BYTES {
                return Err("TPM returned an unexpected ECDSA-P256 signature length".into());
            }
            let record = DeviceRootBinding {
                schema: BINDING_SCHEMA.into(),
                key_version: 1,
                key_name: meta.key_name.clone(),
                network_id: hex(network_id),
                profile_id: hex(profile_id),
                device_id: meta.device_id.clone(),
                noise_static_public_key_hex: hex(&noise_public),
                signature_base64: BASE64.encode(signature),
            };
            serde_json::to_vec_pretty(&record)
                .map_err(|error| format!("binding JSON serialization failed: {error}"))
        })();
        cng::close_key(provider_handle, key_handle);
        result
    }
    #[cfg(not(windows))]
    {
        let _ = (x, y, noise_public);
        Err("TPM Device Root binding creation is supported only on Windows CNG".into())
    }
}

/// Verify the TPM-signed binding and prove the same CurrentUser TPM key is present now.
pub fn verify_device_root_binding(
    metadata_path: &Path,
    binding_path: &Path,
    actual_noise_public_key: &[u8; 32],
    expected_network_id: &[u8; 32],
    expected_profile_id: &[u8; 32],
) -> Result<VerifiedDeviceRootBinding, String> {
    let (meta, x, y) = parse_metadata(metadata_path)?;
    let bytes =
        read_bounded_regular_file(binding_path, MAX_BINDING_BYTES, "TPM Noise binding record")?;
    let record: DeviceRootBinding = serde_json::from_slice(&bytes)
        .map_err(|error| format!("TPM Noise binding JSON rejected: {error}"))?;
    if record.schema != BINDING_SCHEMA
        || record.key_version != 1
        || record.key_name != meta.key_name
    {
        return Err("TPM Noise binding schema, key version, or key name mismatch".into());
    }
    let network_id = parse_hex32("binding NetworkId", &record.network_id)?;
    let profile_id = parse_hex32("binding ProfileId", &record.profile_id)?;
    let device_id = parse_hex32("binding device_id", &record.device_id)?;
    let noise_public = parse_hex32(
        "binding Noise public key",
        &record.noise_static_public_key_hex,
    )?;
    if network_id != *expected_network_id
        || profile_id != *expected_profile_id
        || network_id != parse_hex32("metadata NetworkId", &meta.network_id)?
        || profile_id != parse_hex32("metadata ProfileId", &meta.profile_id)?
        || record.device_id != meta.device_id
        || noise_public != *actual_noise_public_key
    {
        return Err(
            "TPM Noise binding does not match this node's Noise key and QFP6 network/profile"
                .into(),
        );
    }
    let signature = BASE64
        .decode(&record.signature_base64)
        .map_err(|_| "TPM Noise binding signature is invalid Base64".to_string())?;
    if signature.len() != P256_SIGNATURE_BYTES {
        return Err("TPM Noise binding signature must be fixed-width ECDSA-P256".into());
    }
    let digest = binding_digest(
        &network_id,
        &profile_id,
        &device_id,
        &noise_public,
        record.key_version,
    );

    #[cfg(windows)]
    {
        let (provider_handle, key_handle) = cng::open_key(&meta.provider, &meta.key_name)?;
        let result = (|| {
            cng::assert_public_key_matches(key_handle, &x, &y)?;
            cng::verify_digest(key_handle, &digest, &signature)?;
            cng::prove_private_key_usable(key_handle)?;
            Ok(VerifiedDeviceRootBinding {
                device_id: record.device_id,
                noise_static_public_key: noise_public,
                network_id,
                profile_id,
            })
        })();
        cng::close_key(provider_handle, key_handle);
        result
    }
    #[cfg(not(windows))]
    {
        let _ = (x, y, digest, signature);
        Err("TPM Device Root binding verification is supported only on Windows CNG".into())
    }
}

const Q6PD_IDENTITY_BINDING_SCHEMA: &str = "QFP6_Q6PD_IDENTITY_BINDING_V1";
const Q6PD_IDENTITY_BINDING_DOMAIN: &[u8] = b"QFP6-Q6PD-IDENTITY-DEVICE-BINDING-V1\0";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Q6pdIdentityDeviceBinding {
    schema: String,
    key_version: u32,
    key_name: String,
    network_id: String,
    profile_id: String,
    device_id: String,
    identity_public_key_hex: String,
    noise_static_public_key_hex: String,
    signature_base64: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedQ6pdIdentityDeviceBinding {
    pub device_id: String,
    pub identity_public_key: [u8; 32],
    pub noise_static_public_key: [u8; 32],
    pub network_id: [u8; 32],
    pub profile_id: [u8; 32],
}

fn q6pd_identity_binding_digest(
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
    device_id: &[u8; 32],
    identity_public_key: &[u8; 32],
    noise_public_key: &[u8; 32],
    key_version: u32,
) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(Q6PD_IDENTITY_BINDING_DOMAIN.len() + 32 * 5 + 4);
    preimage.extend_from_slice(Q6PD_IDENTITY_BINDING_DOMAIN);
    preimage.extend_from_slice(network_id);
    preimage.extend_from_slice(profile_id);
    preimage.extend_from_slice(device_id);
    preimage.extend_from_slice(identity_public_key);
    preimage.extend_from_slice(noise_public_key);
    preimage.extend_from_slice(&key_version.to_be_bytes());
    Sha256::digest(preimage).into()
}

/// Ask the existing non-exportable TPM Device Root to bind the Q6PD Ed25519 identity
/// and this node's exact Noise static public key to one QFP6 network/profile.
/// The returned JSON contains public keys and a TPM signature only.
pub fn create_q6pd_identity_device_binding_record(
    metadata_path: &Path,
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
    identity_public_key: &[u8; 32],
    noise_public_key: &[u8; 32],
) -> Result<Vec<u8>, String> {
    if identity_public_key.iter().all(|byte| *byte == 0)
        || noise_public_key.iter().all(|byte| *byte == 0)
    {
        return Err("Q6PD identity and Noise public keys must be nonzero".into());
    }
    let (meta, x, y) = parse_metadata(metadata_path)?;
    if parse_hex32("metadata NetworkId", &meta.network_id)? != *network_id
        || parse_hex32("metadata ProfileId", &meta.profile_id)? != *profile_id
    {
        return Err("TPM Device Root metadata belongs to another QFP6 network/profile".into());
    }
    let device_id = parse_hex32("metadata device_id", &meta.device_id)?;

    #[cfg(windows)]
    {
        let (provider_handle, key_handle) = cng::open_key(&meta.provider, &meta.key_name)?;
        let result = (|| {
            cng::assert_public_key_matches(key_handle, &x, &y)?;
            let digest = q6pd_identity_binding_digest(
                network_id,
                profile_id,
                &device_id,
                identity_public_key,
                noise_public_key,
                1,
            );
            let signature = cng::sign_digest(key_handle, &digest)?;
            if signature.len() != P256_SIGNATURE_BYTES {
                return Err(
                    "TPM returned an unexpected Q6PD identity binding signature length".into(),
                );
            }
            let record = Q6pdIdentityDeviceBinding {
                schema: Q6PD_IDENTITY_BINDING_SCHEMA.into(),
                key_version: 1,
                key_name: meta.key_name.clone(),
                network_id: hex(network_id),
                profile_id: hex(profile_id),
                device_id: meta.device_id.clone(),
                identity_public_key_hex: hex(identity_public_key),
                noise_static_public_key_hex: hex(noise_public_key),
                signature_base64: BASE64.encode(signature),
            };
            serde_json::to_vec_pretty(&record).map_err(|error| {
                format!("Q6PD identity binding JSON serialization failed: {error}")
            })
        })();
        cng::close_key(provider_handle, key_handle);
        result
    }
    #[cfg(not(windows))]
    {
        let _ = (x, y, device_id, meta);
        Err("TPM Q6PD identity binding creation is supported only on Windows CNG".into())
    }
}

/// Verify that the Q6PD Ed25519 public key and Noise key are both bound to the same
/// current non-exportable TPM Device Root, network and profile.
pub fn verify_q6pd_identity_device_binding(
    metadata_path: &Path,
    binding_path: &Path,
    actual_identity_public_key: &[u8; 32],
    actual_noise_public_key: &[u8; 32],
    expected_network_id: &[u8; 32],
    expected_profile_id: &[u8; 32],
) -> Result<VerifiedQ6pdIdentityDeviceBinding, String> {
    let (meta, x, y) = parse_metadata(metadata_path)?;
    let bytes = read_bounded_regular_file(
        binding_path,
        MAX_BINDING_BYTES,
        "TPM Q6PD identity binding record",
    )?;
    let record: Q6pdIdentityDeviceBinding = serde_json::from_slice(&bytes)
        .map_err(|error| format!("TPM Q6PD identity binding JSON rejected: {error}"))?;
    if record.schema != Q6PD_IDENTITY_BINDING_SCHEMA
        || record.key_version != 1
        || record.key_name != meta.key_name
    {
        return Err("TPM Q6PD identity binding schema, version, or key name mismatch".into());
    }

    let network_id = parse_hex32("binding NetworkId", &record.network_id)?;
    let profile_id = parse_hex32("binding ProfileId", &record.profile_id)?;
    let device_id = parse_hex32("binding device_id", &record.device_id)?;
    let identity_public_key = parse_hex32(
        "binding Q6PD identity public key",
        &record.identity_public_key_hex,
    )?;
    let noise_public_key = parse_hex32(
        "binding Noise public key",
        &record.noise_static_public_key_hex,
    )?;
    if network_id != *expected_network_id
        || profile_id != *expected_profile_id
        || network_id != parse_hex32("metadata NetworkId", &meta.network_id)?
        || profile_id != parse_hex32("metadata ProfileId", &meta.profile_id)?
        || record.device_id != meta.device_id
        || identity_public_key != *actual_identity_public_key
        || noise_public_key != *actual_noise_public_key
    {
        return Err(
            "TPM Q6PD identity binding does not match this node's keys/network/profile".into(),
        );
    }

    let signature = BASE64
        .decode(&record.signature_base64)
        .map_err(|_| "TPM Q6PD identity binding signature is invalid Base64".to_string())?;
    if signature.len() != P256_SIGNATURE_BYTES {
        return Err("TPM Q6PD identity binding signature must be fixed-width ECDSA-P256".into());
    }
    let digest = q6pd_identity_binding_digest(
        &network_id,
        &profile_id,
        &device_id,
        &identity_public_key,
        &noise_public_key,
        record.key_version,
    );

    #[cfg(windows)]
    {
        let (provider_handle, key_handle) = cng::open_key(&meta.provider, &meta.key_name)?;
        let result = (|| {
            cng::assert_public_key_matches(key_handle, &x, &y)?;
            cng::verify_digest(key_handle, &digest, &signature)?;
            cng::prove_private_key_usable(key_handle)?;
            Ok(VerifiedQ6pdIdentityDeviceBinding {
                device_id: record.device_id,
                identity_public_key,
                noise_static_public_key: noise_public_key,
                network_id,
                profile_id,
            })
        })();
        cng::close_key(provider_handle, key_handle);
        result
    }
    #[cfg(not(windows))]
    {
        let _ = (x, y, digest, signature, record);
        Err("TPM Q6PD identity binding verification is supported only on Windows CNG".into())
    }
}

#[cfg(windows)]
mod cng {
    use sha2::{Digest, Sha256};
    use std::{ffi::c_void, ptr};
    use zeroize::Zeroize;

    const NCRYPT_SILENT_FLAG: u32 = 0x00000040;
    const NTE_BUFFER_TOO_SMALL: u32 = 0x80090028;
    const BCRYPT_ECDSA_PUBLIC_P256_MAGIC: u32 = 0x31534345;
    const ECC_PUBLIC_BLOB: &str = "ECCPUBLICBLOB";

    #[link(name = "ncrypt")]
    extern "system" {
        fn NCryptOpenStorageProvider(
            provider: *mut usize,
            provider_name: *const u16,
            flags: u32,
        ) -> i32;
        fn NCryptOpenKey(
            provider: usize,
            key: *mut usize,
            key_name: *const u16,
            legacy_key_spec: u32,
            flags: u32,
        ) -> i32;
        fn NCryptExportKey(
            key: usize,
            export_key: usize,
            blob_type: *const u16,
            parameters: *mut c_void,
            output: *mut u8,
            output_len: u32,
            result_len: *mut u32,
            flags: u32,
        ) -> i32;
        fn NCryptSignHash(
            key: usize,
            padding_info: *mut c_void,
            hash: *const u8,
            hash_len: u32,
            signature: *mut u8,
            signature_len: u32,
            result_len: *mut u32,
            flags: u32,
        ) -> i32;
        fn NCryptVerifySignature(
            key: usize,
            padding_info: *mut c_void,
            hash: *const u8,
            hash_len: u32,
            signature: *const u8,
            signature_len: u32,
            flags: u32,
        ) -> i32;
        fn NCryptFreeObject(handle: usize) -> i32;
    }

    fn wide(value: &str) -> Result<Vec<u16>, String> {
        if value.is_empty() || value.contains('\0') {
            return Err("CNG provider/key name is invalid".into());
        }
        Ok(value.encode_utf16().chain(std::iter::once(0)).collect())
    }

    pub fn open_key(provider_name: &str, key_name: &str) -> Result<(usize, usize), String> {
        let provider_name = wide(provider_name)?;
        let key_name = wide(key_name)?;
        let mut provider = 0usize;
        let status = unsafe { NCryptOpenStorageProvider(&mut provider, provider_name.as_ptr(), 0) };
        if status != 0 || provider == 0 {
            return Err(format!(
                "Microsoft CNG could not open the TPM storage provider (status 0x{:08x})",
                status as u32
            ));
        }
        let mut key = 0usize;
        let status =
            unsafe { NCryptOpenKey(provider, &mut key, key_name.as_ptr(), 0, NCRYPT_SILENT_FLAG) };
        if status != 0 || key == 0 {
            unsafe {
                NCryptFreeObject(provider);
            }
            return Err(format!("Microsoft CNG could not reopen the persistent TPM Device Root key (status 0x{:08x})", status as u32));
        }
        Ok((provider, key))
    }

    pub fn close_key(provider: usize, key: usize) {
        unsafe {
            if key != 0 {
                NCryptFreeObject(key);
            }
            if provider != 0 {
                NCryptFreeObject(provider);
            }
        }
    }

    pub fn exported_public_coordinates(key: usize) -> Result<([u8; 32], [u8; 32]), String> {
        let blob_name = wide(ECC_PUBLIC_BLOB)?;
        let mut required = 0u32;
        let first = unsafe {
            NCryptExportKey(
                key,
                0,
                blob_name.as_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
                0,
                &mut required,
                NCRYPT_SILENT_FLAG,
            )
        };
        if first != 0 && first as u32 != NTE_BUFFER_TOO_SMALL {
            return Err(format!(
                "TPM public-key export size query failed (status 0x{:08x})",
                first as u32
            ));
        }
        if required != 8 + 64 {
            return Err(format!(
                "TPM public-key blob has an unexpected size ({required})"
            ));
        }
        let mut blob = vec![0u8; required as usize];
        let status = unsafe {
            NCryptExportKey(
                key,
                0,
                blob_name.as_ptr(),
                ptr::null_mut(),
                blob.as_mut_ptr(),
                required,
                &mut required,
                NCRYPT_SILENT_FLAG,
            )
        };
        if status != 0 || required as usize != blob.len() {
            return Err(format!(
                "TPM public-key export failed (status 0x{:08x})",
                status as u32
            ));
        }
        let magic = u32::from_le_bytes(blob[0..4].try_into().unwrap());
        let cb_key = u32::from_le_bytes(blob[4..8].try_into().unwrap());
        if magic != BCRYPT_ECDSA_PUBLIC_P256_MAGIC || cb_key != 32 {
            return Err("TPM key is not an ECDSA-P256 public key".into());
        }
        let x: [u8; 32] = blob[8..40].try_into().unwrap();
        let y: [u8; 32] = blob[40..72].try_into().unwrap();
        blob.fill(0);
        Ok((x, y))
    }

    pub fn assert_public_key_matches(key: usize, x: &[u8; 32], y: &[u8; 32]) -> Result<(), String> {
        let (observed_x, observed_y) = exported_public_coordinates(key)?;
        if &observed_x != x || &observed_y != y {
            return Err("TPM public key does not match the local Device Root metadata".into());
        }
        Ok(())
    }

    pub fn sign_digest(key: usize, digest: &[u8; 32]) -> Result<Vec<u8>, String> {
        let mut required = 0u32;
        let first = unsafe {
            NCryptSignHash(
                key,
                ptr::null_mut(),
                digest.as_ptr(),
                digest.len() as u32,
                ptr::null_mut(),
                0,
                &mut required,
                NCRYPT_SILENT_FLAG,
            )
        };
        if first != 0 && first as u32 != NTE_BUFFER_TOO_SMALL {
            return Err(format!(
                "TPM ECDSA-P256 signing size query failed (status 0x{:08x})",
                first as u32
            ));
        }
        if required as usize != super::P256_SIGNATURE_BYTES {
            return Err(format!(
                "TPM returned an unexpected ECDSA-P256 signature size ({required})"
            ));
        }
        let mut signature = vec![0u8; required as usize];
        let status = unsafe {
            NCryptSignHash(
                key,
                ptr::null_mut(),
                digest.as_ptr(),
                digest.len() as u32,
                signature.as_mut_ptr(),
                required,
                &mut required,
                NCRYPT_SILENT_FLAG,
            )
        };
        if status != 0 || required as usize != signature.len() {
            signature.fill(0);
            return Err(format!(
                "TPM ECDSA-P256 signing failed (status 0x{:08x})",
                status as u32
            ));
        }
        Ok(signature)
    }

    pub fn verify_digest(key: usize, digest: &[u8; 32], signature: &[u8]) -> Result<(), String> {
        let status = unsafe {
            NCryptVerifySignature(
                key,
                ptr::null_mut(),
                digest.as_ptr(),
                digest.len() as u32,
                signature.as_ptr(),
                signature.len() as u32,
                NCRYPT_SILENT_FLAG,
            )
        };
        if status != 0 {
            return Err(format!(
                "TPM Device Root binding signature verification failed (status 0x{:08x})",
                status as u32
            ));
        }
        Ok(())
    }

    pub fn prove_private_key_usable(key: usize) -> Result<(), String> {
        let mut challenge = [0u8; 32];
        getrandom::getrandom(&mut challenge)
            .map_err(|error| format!("fresh TPM challenge generation failed: {error}"))?;
        let mut preimage = Vec::with_capacity(super::PROBE_DOMAIN.len() + challenge.len());
        preimage.extend_from_slice(super::PROBE_DOMAIN);
        preimage.extend_from_slice(&challenge);
        let digest: [u8; 32] = Sha256::digest(&preimage).into();
        challenge.fill(0);
        preimage.fill(0);
        let signature = sign_digest(key, &digest)?;
        let result = verify_digest(key, &digest, &signature);
        let mut signature = signature;
        signature.zeroize();
        result
    }
}

#[cfg(not(windows))]
mod cng {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_preimage_is_domain_and_context_separated() {
        let network = [1u8; 32];
        let profile = [2u8; 32];
        let device = [3u8; 32];
        let noise = [4u8; 32];
        let base = binding_digest(&network, &profile, &device, &noise, 1);
        assert_ne!(
            base,
            binding_digest(&[9u8; 32], &profile, &device, &noise, 1)
        );
        assert_ne!(
            base,
            binding_digest(&network, &[9u8; 32], &device, &noise, 1)
        );
        assert_ne!(
            base,
            binding_digest(&network, &profile, &device, &[9u8; 32], 1)
        );
        assert_ne!(base, binding_digest(&network, &profile, &device, &noise, 2));
    }

    #[test]
    fn q6pd_identity_binding_digest_covers_network_profile_device_both_keys_and_version() {
        let network = [0x11; 32];
        let profile = [0x22; 32];
        let device = [0x33; 32];
        let identity = [0x44; 32];
        let noise = [0x55; 32];
        let base = q6pd_identity_binding_digest(&network, &profile, &device, &identity, &noise, 1);
        assert_ne!(
            base,
            q6pd_identity_binding_digest(&[0x91; 32], &profile, &device, &identity, &noise, 1,)
        );
        assert_ne!(
            base,
            q6pd_identity_binding_digest(&network, &[0x92; 32], &device, &identity, &noise, 1,)
        );
        assert_ne!(
            base,
            q6pd_identity_binding_digest(&network, &profile, &[0x93; 32], &identity, &noise, 1,)
        );
        assert_ne!(
            base,
            q6pd_identity_binding_digest(&network, &profile, &device, &[0x94; 32], &noise, 1,)
        );
        assert_ne!(
            base,
            q6pd_identity_binding_digest(&network, &profile, &device, &identity, &[0x95; 32], 1,)
        );
        assert_ne!(
            base,
            q6pd_identity_binding_digest(&network, &profile, &device, &identity, &noise, 2,)
        );
    }

    #[test]
    fn metadata_identity_derivation_matches_current_qfp6_schema() {
        let network = parse_hex32(
            "network",
            "633b5dfc16fb2ec1825baf924ae7f7f16bf2006f8b64441a57692a3531722712",
        )
        .unwrap();
        let profile = parse_hex32(
            "profile",
            "a0a057d72c11253386bfe90d428bccbc44ebc86fc84e04e3682193a99d8805c4",
        )
        .unwrap();
        let x = BASE64
            .decode("eBaCkZCDQvC9UZd5/njU0ahOo/FHC8mF/HEmSSCMH10=")
            .unwrap();
        let y = BASE64
            .decode("st11whhSH3jun8mXm0IBQEk7H8ati0eNHV9WxfpyXVk=")
            .unwrap();
        let mut preimage = Vec::new();
        preimage.extend_from_slice(DEVICE_ROOT_DOMAIN);
        preimage.extend_from_slice(&network);
        preimage.extend_from_slice(&profile);
        preimage.extend_from_slice(&x);
        preimage.extend_from_slice(&y);
        assert_eq!(
            hex(&Sha256::digest(preimage)),
            "b3798ae60faebbc37af085bd62624fc7355eea4fde307e18dee362ed526b687f"
        );
    }
}
