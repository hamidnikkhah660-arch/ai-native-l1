//! Q6PD node identity custody and TPM binding.
//!
//! The Ed25519 node identity uses its own DPAPI role, distinct from peer-issuer,
//! deployment, governance and recovery keys. The non-exportable TPM Device Root
//! separately binds the Ed25519 public key and the node's exact Noise public key
//! to one QFP6 network/profile. This module does not select or publish an endpoint,
//! approve peers, or enable automatic dialing.
use crate::{
    noise_key_provisioning::load_protected_noise_private_key,
    offline_signing_key_store::{
        load_protected_signing_seed, store_protected_signing_seed, SigningKeyRole,
    },
    qfp6_device_identity_candidate::{
        create_q6pd_identity_device_binding_record, derive_noise_static_public_key,
        verify_q6pd_identity_device_binding,
    },
    qrun_v06_peer_discovery_candidate::{
        q6pd_peer_id_for_identity_public_key, sign_q6pd_peer_record_with_tls_server_name, Q6pdError,
    },
};
use ed25519_dalek::SigningKey;
use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    net::SocketAddr,
    path::Path,
};
use zeroize::Zeroizing;

const NODE_IDENTITY_ROLE: SigningKeyRole = SigningKeyRole::PeerNodeIdentity;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Q6pdPeerIdentityInfo {
    pub peer_id: [u8; 32],
    pub identity_public_key: [u8; 32],
    pub noise_static_public_key: [u8; 32],
    pub device_id: String,
    pub network_id: [u8; 32],
    pub profile_id: [u8; 32],
}

/// Loaded signing authority is intentionally non-Clone and has no Debug/serialization surface.
pub struct Q6pdNodeIdentity {
    signing_key: SigningKey,
    info: Q6pdPeerIdentityInfo,
}

impl Q6pdNodeIdentity {
    pub fn info(&self) -> &Q6pdPeerIdentityInfo {
        &self.info
    }

    /// Produce one signed self-announcement. Endpoint validation and TTL bounds are
    /// enforced by the canonical Q6PD codec before any bytes are returned.
    pub fn sign_announcement(
        &self,
        endpoint: SocketAddr,
        sequence: u64,
        issued_at_secs: u64,
        ttl_secs: u32,
    ) -> Result<Vec<u8>, Q6pdError> {
        self.sign_announcement_with_tls_server_name(
            endpoint,
            None,
            sequence,
            issued_at_secs,
            ttl_secs,
        )
    }

    pub fn sign_announcement_with_tls_server_name(
        &self,
        endpoint: SocketAddr,
        tls_server_name: Option<&str>,
        sequence: u64,
        issued_at_secs: u64,
        ttl_secs: u32,
    ) -> Result<Vec<u8>, Q6pdError> {
        sign_q6pd_peer_record_with_tls_server_name(
            self.info.network_id,
            self.info.profile_id,
            self.info.noise_static_public_key,
            endpoint,
            tls_server_name,
            sequence,
            issued_at_secs,
            ttl_secs,
            &self.signing_key,
        )
    }
}

fn inspect_regular_file(path: &Path, label: &str) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(format!("{label} must be a regular non-symlink file"));
            }
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(format!("{label} path could not be inspected")),
    }
}

fn load_node_noise_public_key(
    noise_private_key_path: &Path,
    network_id: &[u8; 32],
) -> Result<[u8; 32], String> {
    let private_key = Zeroizing::new(
        load_protected_noise_private_key(noise_private_key_path, network_id)
            .map_err(|error| format!("protected Noise identity could not be loaded: {error}"))?,
    );
    derive_noise_static_public_key(&private_key)
}

fn persist_binding_create_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if path.file_name().is_none() || !parent.is_dir() {
        return Err("Q6PD TPM binding output must be inside an existing directory".into());
    }
    let mut created_by_this_call = false;
    let result = (|| -> io::Result<()> {
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        created_by_this_call = true;
        file.write_all(bytes)?;
        file.flush()?;
        file.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        if created_by_this_call {
            let _ = fs::remove_file(path);
        }
        return Err("Q6PD TPM binding could not be durably created without overwrite".into());
    }
    Ok(())
}

fn build_info(
    identity_public_key: [u8; 32],
    noise_static_public_key: [u8; 32],
    device_id: String,
    network_id: [u8; 32],
    profile_id: [u8; 32],
) -> Q6pdPeerIdentityInfo {
    Q6pdPeerIdentityInfo {
        peer_id: q6pd_peer_id_for_identity_public_key(&identity_public_key),
        identity_public_key,
        noise_static_public_key,
        device_id,
        network_id,
        profile_id,
    }
}

/// Load the existing role-bound DPAPI Ed25519 node identity and require a matching live
/// TPM Device Root signature before returning a signer.
pub fn load_q6pd_node_identity(
    identity_key_path: &Path,
    tpm_binding_path: &Path,
    device_root_metadata_path: &Path,
    noise_private_key_path: &Path,
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
) -> Result<Q6pdNodeIdentity, String> {
    if *network_id == [0; 32] || *profile_id == [0; 32] {
        return Err("Q6PD identity requires nonzero network and profile IDs".into());
    }
    let seed = Zeroizing::new(
        load_protected_signing_seed(identity_key_path, network_id, NODE_IDENTITY_ROLE)
            .map_err(|error| format!("Q6PD node identity key could not be loaded: {error}"))?,
    );
    let signing_key = SigningKey::from_bytes(&seed);
    let identity_public_key = signing_key.verifying_key().to_bytes();
    let noise_static_public_key = load_node_noise_public_key(noise_private_key_path, network_id)?;
    let verified = verify_q6pd_identity_device_binding(
        device_root_metadata_path,
        tpm_binding_path,
        &identity_public_key,
        &noise_static_public_key,
        network_id,
        profile_id,
    )?;
    let info = build_info(
        identity_public_key,
        noise_static_public_key,
        verified.device_id,
        *network_id,
        *profile_id,
    );
    Ok(Q6pdNodeIdentity { signing_key, info })
}

/// Provision once, or complete a previously interrupted two-file provisioning operation.
/// Existing key or binding files are never overwritten. If a binding already exists, it must
/// verify against the protected key or provisioning fails closed; silent key rotation is barred.
pub fn provision_q6pd_node_identity(
    identity_key_path: &Path,
    tpm_binding_path: &Path,
    device_root_metadata_path: &Path,
    noise_private_key_path: &Path,
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
) -> Result<Q6pdPeerIdentityInfo, String> {
    if *network_id == [0; 32] || *profile_id == [0; 32] {
        return Err("Q6PD identity provisioning requires nonzero network and profile IDs".into());
    }
    if identity_key_path == tpm_binding_path {
        return Err("Q6PD identity key and TPM binding must use separate files".into());
    }

    let key_exists = inspect_regular_file(identity_key_path, "Q6PD identity key")?;
    let binding_exists = inspect_regular_file(tpm_binding_path, "Q6PD TPM binding")?;
    if !key_exists && binding_exists {
        return Err("TPM Q6PD binding exists but the protected identity key is missing; refusing replacement".into());
    }

    let noise_static_public_key = load_node_noise_public_key(noise_private_key_path, network_id)?;

    let signing_key = if key_exists {
        let seed = Zeroizing::new(
            load_protected_signing_seed(identity_key_path, network_id, NODE_IDENTITY_ROLE)
                .map_err(|error| format!("existing Q6PD node identity key is invalid: {error}"))?,
        );
        SigningKey::from_bytes(&seed)
    } else {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(&mut *seed)
            .map_err(|error| format!("cryptographic node-identity generation failed: {error}"))?;
        if seed.iter().all(|byte| *byte == 0) {
            return Err("cryptographic node-identity generator returned an invalid seed".into());
        }
        SigningKey::from_bytes(&seed)
    };
    let identity_public_key = signing_key.verifying_key().to_bytes();

    if binding_exists {
        let verified = verify_q6pd_identity_device_binding(
            device_root_metadata_path,
            tpm_binding_path,
            &identity_public_key,
            &noise_static_public_key,
            network_id,
            profile_id,
        )?;
        return Ok(build_info(
            identity_public_key,
            noise_static_public_key,
            verified.device_id,
            *network_id,
            *profile_id,
        ));
    }

    // TPM signs the exact public-key tuple before the secret is committed. If the process
    // stops after the key write, a retry loads the same key and can safely finish the binding.
    let binding_wire = create_q6pd_identity_device_binding_record(
        device_root_metadata_path,
        network_id,
        profile_id,
        &identity_public_key,
        &noise_static_public_key,
    )?;

    if !key_exists {
        let seed = signing_key.to_bytes();
        let protected_seed = Zeroizing::new(seed);
        store_protected_signing_seed(
            identity_key_path,
            network_id,
            NODE_IDENTITY_ROLE,
            &protected_seed,
        )?;
    }

    match persist_binding_create_new(tpm_binding_path, &binding_wire) {
        Ok(()) => {}
        Err(_error) if inspect_regular_file(tpm_binding_path, "Q6PD TPM binding")? => {
            // Concurrent provisioners may have won create_new. Accept only the same bound key.
            let verified = verify_q6pd_identity_device_binding(
                device_root_metadata_path,
                tpm_binding_path,
                &identity_public_key,
                &noise_static_public_key,
                network_id,
                profile_id,
            )?;
            return Ok(build_info(
                identity_public_key,
                noise_static_public_key,
                verified.device_id,
                *network_id,
                *profile_id,
            ));
        }
        Err(error) => return Err(error),
    }

    let loaded = load_q6pd_node_identity(
        identity_key_path,
        tpm_binding_path,
        device_root_metadata_path,
        noise_private_key_path,
        network_id,
        profile_id,
    )?;
    Ok(loaded.info().clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qrun_v06_peer_discovery_candidate::verify_q6pd_peer_record;

    #[test]
    fn q6pd_node_identity_signs_a_network_and_profile_bound_self_announcement() {
        let seed = [0x6d; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let identity_public_key = signing_key.verifying_key().to_bytes();
        let network_id = [0x51; 32];
        let profile_id = [0x52; 32];
        let noise_static_public_key = [0x53; 32];
        let info = build_info(
            identity_public_key,
            noise_static_public_key,
            "test-device".into(),
            network_id,
            profile_id,
        );
        let identity = Q6pdNodeIdentity { signing_key, info };
        let now = 1_800_000_000u64;
        let wire = identity
            .sign_announcement("8.8.8.8:30336".parse().unwrap(), 1, now, 3600)
            .unwrap();
        let verified = verify_q6pd_peer_record(&wire, &network_id, &profile_id, now).unwrap();
        assert_eq!(verified.peer_id, identity.info().peer_id);
        assert_eq!(
            verified.identity_public_key,
            identity.info().identity_public_key
        );
        assert_eq!(verified.noise_static_public_key, noise_static_public_key);
        assert_eq!(verified.sequence, 1);
    }

    #[test]
    fn self_announcement_rejects_non_public_endpoint_and_invalid_sequence() {
        let signing_key = SigningKey::from_bytes(&[0x6e; 32]);
        let identity_public_key = signing_key.verifying_key().to_bytes();
        let identity = Q6pdNodeIdentity {
            signing_key,
            info: build_info(
                identity_public_key,
                [0x53; 32],
                "test-device".into(),
                [0x51; 32],
                [0x52; 32],
            ),
        };
        assert_eq!(
            identity.sign_announcement("127.0.0.1:30336".parse().unwrap(), 1, 1_800_000_000, 3600),
            Err(Q6pdError::InvalidEndpoint)
        );
        assert_eq!(
            identity.sign_announcement("8.8.8.8:30336".parse().unwrap(), 0, 1_800_000_000, 3600),
            Err(Q6pdError::InvalidSequence)
        );
    }

    #[test]
    fn node_identity_role_is_distinct_from_peer_issuer() {
        assert_ne!(
            SigningKeyRole::PeerNodeIdentity as u8,
            SigningKeyRole::PeerIssuer as u8
        );
        assert_eq!(
            SigningKeyRole::PeerNodeIdentity.as_str(),
            "peer-node-identity"
        );
    }
}
