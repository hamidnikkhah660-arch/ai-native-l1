//! Bounded, signed peer-identity envelope for the loopback Devnet candidate.
//!
//! This authenticates an issuer-signed NoiseX25519/PeerAuth KeyRecord with a network- and
//! credential-bound envelope. It reports, rather than authorizes, the time-window result so the
//! runtime can persist signed lifecycle/generation state before refusing an expired or revoked key.
//! The issuer Ed25519 public key is still supplied out of band; this is not a replacement for signed
//! deployment/issuer registry bootstrap or an external monotonic trust anchor. The live node must
//! stay loopback-only until broader trust lifecycle and cross-host tests pass.
use crate::identity_policy::{decode, encode, KeyAlgorithm, KeyPurpose, KeyRecord, HEADER_LEN};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::fmt;

const MAGIC: &[u8; 4] = b"NPI1";
const VERSION: u16 = 1;
const HEADER_LEN_WIRE: usize = 4 + 2 + 32 + 16 + 4 + 2 + 2;
const SIGNATURE_LEN: usize = 64;
const SIGNING_DOMAIN: &[u8] = b"AIN1-DEVNET-SIGNED-PEER-IDENTITY-V1\0";
const NOISE_PUBLIC_KEY_LEN: usize = 32;
const MAX_RECORD_LEN: usize = HEADER_LEN + NOISE_PUBLIC_KEY_LEN;
const ROTATION_WIRE_LEN: usize = crate::identity_generation_store::ROTATION_WIRE_LEN;
pub const MAX_SIGNED_PEER_IDENTITY_LEN: usize =
    HEADER_LEN_WIRE + MAX_RECORD_LEN + ROTATION_WIRE_LEN + SIGNATURE_LEN;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignedPeerIdentityError {
    Malformed,
    UnsupportedVersion,
    NetworkMismatch,
    CredentialMismatch,
    IssuerMismatch,
    InvalidIssuerKey,
    InvalidSignature,
    InvalidRecord,
    InvalidRotation,
}

impl fmt::Display for SignedPeerIdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => write!(f, "signed peer identity is malformed"),
            Self::UnsupportedVersion => write!(f, "signed peer identity version is unsupported"),
            Self::NetworkMismatch => write!(f, "signed peer identity belongs to another network"),
            Self::CredentialMismatch => write!(f, "signed peer identity credential is invalid"),
            Self::IssuerMismatch => {
                write!(f, "signed peer identity issuer does not match bootstrap")
            }
            Self::InvalidIssuerKey => write!(f, "peer identity issuer key is invalid"),
            Self::InvalidSignature => write!(f, "peer identity signature is invalid"),
            Self::InvalidRecord => write!(f, "peer identity record is not a valid Noise peer key"),
            Self::InvalidRotation => {
                write!(f, "peer identity rotation payload has an invalid length")
            }
        }
    }
}
impl std::error::Error for SignedPeerIdentityError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSignedNoisePeerIdentity {
    pub network_id: [u8; 32],
    pub credential_id: u128,
    pub issuer_id: u32,
    pub record: KeyRecord,
    pub record_bytes: Vec<u8>,
    pub rotation_wire: Option<Vec<u8>>,
    pub noise_public_key: [u8; 32],
    /// Whether the record's declared validity window includes the verification epoch.
    /// Callers must still persist its signed lifecycle/generation state before admitting it.
    pub time_valid_at_epoch: bool,
}

/// Wire format: NPI1, version, NetworkId, credential ID, issuer ID, record length,
/// rotation length, encoded KeyRecord, optional NRT1 rotation statement, detached signature.
/// Ed25519 signs SIGNING_DOMAIN || every byte before the signature.
pub fn verify_signed_peer_identity(
    wire: &[u8],
    expected_network_id: &[u8; 32],
    expected_issuer_id: u32,
    issuer_public_key: &[u8; 32],
    epoch: u64,
) -> Result<VerifiedSignedNoisePeerIdentity, SignedPeerIdentityError> {
    if wire.len() < HEADER_LEN_WIRE + HEADER_LEN + NOISE_PUBLIC_KEY_LEN + SIGNATURE_LEN
        || wire.len() > MAX_SIGNED_PEER_IDENTITY_LEN
        || &wire[..4] != MAGIC
    {
        return Err(SignedPeerIdentityError::Malformed);
    }
    let version = u16::from_be_bytes(
        wire[4..6]
            .try_into()
            .map_err(|_| SignedPeerIdentityError::Malformed)?,
    );
    if version != VERSION {
        return Err(SignedPeerIdentityError::UnsupportedVersion);
    }
    let network_id: [u8; 32] = wire[6..38]
        .try_into()
        .map_err(|_| SignedPeerIdentityError::Malformed)?;
    if &network_id != expected_network_id {
        return Err(SignedPeerIdentityError::NetworkMismatch);
    }
    let credential_id = u128::from_be_bytes(
        wire[38..54]
            .try_into()
            .map_err(|_| SignedPeerIdentityError::Malformed)?,
    );
    if credential_id == 0 {
        return Err(SignedPeerIdentityError::CredentialMismatch);
    }
    let issuer_id = u32::from_be_bytes(
        wire[54..58]
            .try_into()
            .map_err(|_| SignedPeerIdentityError::Malformed)?,
    );
    if issuer_id == 0 || issuer_id != expected_issuer_id {
        return Err(SignedPeerIdentityError::IssuerMismatch);
    }
    let record_len = usize::from(u16::from_be_bytes(
        wire[58..60]
            .try_into()
            .map_err(|_| SignedPeerIdentityError::Malformed)?,
    ));
    let rotation_len = usize::from(u16::from_be_bytes(
        wire[60..62]
            .try_into()
            .map_err(|_| SignedPeerIdentityError::Malformed)?,
    ));
    if !(HEADER_LEN + NOISE_PUBLIC_KEY_LEN..=MAX_RECORD_LEN).contains(&record_len) {
        return Err(SignedPeerIdentityError::Malformed);
    }
    if rotation_len != 0 && rotation_len != ROTATION_WIRE_LEN {
        return Err(SignedPeerIdentityError::InvalidRotation);
    }
    let expected_len = HEADER_LEN_WIRE
        .checked_add(record_len)
        .and_then(|n| n.checked_add(rotation_len))
        .and_then(|n| n.checked_add(SIGNATURE_LEN))
        .ok_or(SignedPeerIdentityError::Malformed)?;
    if wire.len() != expected_len {
        return Err(SignedPeerIdentityError::Malformed);
    }
    let signature_offset = wire.len() - SIGNATURE_LEN;
    let signer = VerifyingKey::from_bytes(issuer_public_key)
        .map_err(|_| SignedPeerIdentityError::InvalidIssuerKey)?;
    let signature = Signature::from_slice(&wire[signature_offset..])
        .map_err(|_| SignedPeerIdentityError::InvalidSignature)?;
    let mut preimage = Vec::with_capacity(SIGNING_DOMAIN.len() + signature_offset);
    preimage.extend_from_slice(SIGNING_DOMAIN);
    preimage.extend_from_slice(&wire[..signature_offset]);
    signer
        .verify_strict(&preimage, &signature)
        .map_err(|_| SignedPeerIdentityError::InvalidSignature)?;

    let record_start = HEADER_LEN_WIRE;
    let record_end = record_start + record_len;
    let record_bytes = wire[record_start..record_end].to_vec();
    let record = decode(&record_bytes).map_err(|_| SignedPeerIdentityError::InvalidRecord)?;
    if record.validate_shape().is_err()
        || record.key_id == 0
        || record.generation == 0
        || record.algorithm != KeyAlgorithm::NoiseX25519
        || record.purpose != KeyPurpose::PeerAuth
        || record.public_key.len() != NOISE_PUBLIC_KEY_LEN
        || record.public_key.iter().all(|byte| *byte == 0)
    {
        return Err(SignedPeerIdentityError::InvalidRecord);
    }
    // Signature verification and authorization are separate: return authenticated lifecycle
    // metadata even if time has expired so the runtime can persist revocation/high-water first.
    let time_valid_at_epoch = record.not_before <= epoch && epoch <= record.not_after;
    let noise_public_key: [u8; 32] = record
        .public_key
        .as_slice()
        .try_into()
        .map_err(|_| SignedPeerIdentityError::InvalidRecord)?;
    if noise_public_key.iter().all(|byte| *byte == 0) {
        return Err(SignedPeerIdentityError::InvalidRecord);
    }
    let rotation_wire = (rotation_len != 0).then(|| wire[record_end..signature_offset].to_vec());
    Ok(VerifiedSignedNoisePeerIdentity {
        network_id,
        credential_id,
        issuer_id,
        record,
        record_bytes,
        rotation_wire,
        noise_public_key,
        time_valid_at_epoch,
    })
}

/// Create an NPI1 signed identity using the canonical encoder and immediately verify its signature
/// and shape. The signing seed remains owned by the caller and is never serialized.
pub fn sign_signed_peer_identity(
    network_id: [u8; 32],
    credential_id: u128,
    issuer_id: u32,
    record: &KeyRecord,
    rotation_wire: Option<&[u8]>,
    signing_key: &SigningKey,
) -> Result<Vec<u8>, SignedPeerIdentityError> {
    if network_id.iter().all(|b| *b == 0) || credential_id == 0 {
        return Err(SignedPeerIdentityError::CredentialMismatch);
    }
    if issuer_id == 0 {
        return Err(SignedPeerIdentityError::IssuerMismatch);
    }
    if record.validate_shape().is_err()
        || record.key_id == 0
        || record.generation == 0
        || record.algorithm != KeyAlgorithm::NoiseX25519
        || record.purpose != KeyPurpose::PeerAuth
        || record.public_key.len() != NOISE_PUBLIC_KEY_LEN
        || record.public_key.iter().all(|byte| *byte == 0)
    {
        return Err(SignedPeerIdentityError::InvalidRecord);
    }
    let record_bytes = encode(record).map_err(|_| SignedPeerIdentityError::InvalidRecord)?;
    let rotation = rotation_wire.unwrap_or_default();
    if !rotation.is_empty() && rotation.len() != ROTATION_WIRE_LEN {
        return Err(SignedPeerIdentityError::InvalidRotation);
    }
    let mut wire =
        Vec::with_capacity(HEADER_LEN_WIRE + record_bytes.len() + rotation.len() + SIGNATURE_LEN);
    wire.extend_from_slice(MAGIC);
    wire.extend_from_slice(&VERSION.to_be_bytes());
    wire.extend_from_slice(&network_id);
    wire.extend_from_slice(&credential_id.to_be_bytes());
    wire.extend_from_slice(&issuer_id.to_be_bytes());
    wire.extend_from_slice(&(record_bytes.len() as u16).to_be_bytes());
    wire.extend_from_slice(&(rotation.len() as u16).to_be_bytes());
    wire.extend_from_slice(&record_bytes);
    wire.extend_from_slice(rotation);
    let mut preimage = Vec::with_capacity(SIGNING_DOMAIN.len() + wire.len());
    preimage.extend_from_slice(SIGNING_DOMAIN);
    preimage.extend_from_slice(&wire);
    wire.extend_from_slice(&signing_key.sign(&preimage).to_bytes());
    verify_signed_peer_identity(
        &wire,
        &network_id,
        issuer_id,
        &signing_key.verifying_key().to_bytes(),
        record.not_before,
    )?;
    Ok(wire)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity_policy::{encode, KeyState};
    use ed25519_dalek::{Signer, SigningKey};

    fn record(algorithm: KeyAlgorithm, state: KeyState, public_key: Vec<u8>) -> KeyRecord {
        KeyRecord {
            key_id: 700,
            generation: 1,
            algorithm,
            purpose: KeyPurpose::PeerAuth,
            state,
            not_before: 100,
            not_after: 900,
            public_key,
        }
    }

    fn envelope(
        network: [u8; 32],
        credential_id: u128,
        issuer_id: u32,
        record: &KeyRecord,
        issuer: &SigningKey,
    ) -> Vec<u8> {
        let record_bytes = encode(record).unwrap();
        let mut wire = Vec::new();
        wire.extend_from_slice(MAGIC);
        wire.extend_from_slice(&VERSION.to_be_bytes());
        wire.extend_from_slice(&network);
        wire.extend_from_slice(&credential_id.to_be_bytes());
        wire.extend_from_slice(&issuer_id.to_be_bytes());
        wire.extend_from_slice(&(record_bytes.len() as u16).to_be_bytes());
        wire.extend_from_slice(&0u16.to_be_bytes());
        wire.extend_from_slice(&record_bytes);
        let mut preimage = SIGNING_DOMAIN.to_vec();
        preimage.extend_from_slice(&wire);
        wire.extend_from_slice(&issuer.sign(&preimage).to_bytes());
        wire
    }

    #[test]
    fn verifies_network_bound_active_noise_peer_identity() {
        let network = [0x42; 32];
        let issuer = SigningKey::from_bytes(&[0x91; 32]);
        let record = record(KeyAlgorithm::NoiseX25519, KeyState::Active, vec![0x31; 32]);
        let wire = envelope(network, 99, 17, &record, &issuer);
        let verified = verify_signed_peer_identity(
            &wire,
            &network,
            17,
            &issuer.verifying_key().to_bytes(),
            200,
        )
        .unwrap();
        assert_eq!(verified.noise_public_key, [0x31; 32]);
        assert_eq!(verified.record.generation, 1);
        assert_eq!(verified.credential_id, 99);
    }

    #[test]
    fn rejects_wrong_network_issuer_and_tampered_signature() {
        let network = [0x42; 32];
        let issuer = SigningKey::from_bytes(&[0x91; 32]);
        let record = record(KeyAlgorithm::NoiseX25519, KeyState::Active, vec![0x31; 32]);
        let wire = envelope(network, 99, 17, &record, &issuer);
        assert_eq!(
            verify_signed_peer_identity(
                &wire,
                &[0x43; 32],
                17,
                &issuer.verifying_key().to_bytes(),
                200
            )
            .unwrap_err(),
            SignedPeerIdentityError::NetworkMismatch
        );
        assert_eq!(
            verify_signed_peer_identity(
                &wire,
                &network,
                18,
                &issuer.verifying_key().to_bytes(),
                200
            )
            .unwrap_err(),
            SignedPeerIdentityError::IssuerMismatch
        );
        let mut tampered = wire.clone();
        tampered[65] ^= 1;
        assert_eq!(
            verify_signed_peer_identity(
                &tampered,
                &network,
                17,
                &issuer.verifying_key().to_bytes(),
                200
            )
            .unwrap_err(),
            SignedPeerIdentityError::InvalidSignature
        );
    }

    #[test]
    fn reports_expiry_and_revocation_but_rejects_non_noise_and_invalid_keys() {
        let network = [0x42; 32];
        let issuer = SigningKey::from_bytes(&[0x91; 32]);
        let expired = envelope(
            network,
            99,
            17,
            &record(KeyAlgorithm::NoiseX25519, KeyState::Active, vec![0x31; 32]),
            &issuer,
        );
        let verified_expired = verify_signed_peer_identity(
            &expired,
            &network,
            17,
            &issuer.verifying_key().to_bytes(),
            901,
        )
        .expect("signature and record must still be verifiable after the time window");
        assert!(!verified_expired.time_valid_at_epoch);
        let revoked = envelope(
            network,
            99,
            17,
            &record(KeyAlgorithm::NoiseX25519, KeyState::Revoked, vec![0x31; 32]),
            &issuer,
        );
        let verified_revocation = verify_signed_peer_identity(
            &revoked,
            &network,
            17,
            &issuer.verifying_key().to_bytes(),
            200,
        )
        .expect("signed revocation must be verified so runtime can persist it");
        assert_eq!(verified_revocation.record.state, KeyState::Revoked);
        let other = envelope(
            network,
            99,
            17,
            &record(KeyAlgorithm::Ed25519, KeyState::Active, vec![0x31; 32]),
            &issuer,
        );
        assert_eq!(
            verify_signed_peer_identity(
                &other,
                &network,
                17,
                &issuer.verifying_key().to_bytes(),
                200
            )
            .unwrap_err(),
            SignedPeerIdentityError::InvalidRecord
        );
        let zero_key = envelope(
            network,
            99,
            17,
            &record(KeyAlgorithm::NoiseX25519, KeyState::Active, vec![0; 32]),
            &issuer,
        );
        assert_eq!(
            verify_signed_peer_identity(
                &zero_key,
                &network,
                17,
                &issuer.verifying_key().to_bytes(),
                200
            )
            .unwrap_err(),
            SignedPeerIdentityError::InvalidRecord
        );
    }

    #[test]
    fn rejects_trailing_truncated_oversized_and_zero_credential() {
        let network = [0x42; 32];
        let issuer = SigningKey::from_bytes(&[0x91; 32]);
        let record = record(KeyAlgorithm::NoiseX25519, KeyState::Active, vec![0x31; 32]);
        let wire = envelope(network, 99, 17, &record, &issuer);
        let mut trailing = wire.clone();
        trailing.push(0);
        assert_eq!(
            verify_signed_peer_identity(
                &trailing,
                &network,
                17,
                &issuer.verifying_key().to_bytes(),
                200
            )
            .unwrap_err(),
            SignedPeerIdentityError::Malformed
        );
        assert_eq!(
            verify_signed_peer_identity(
                &wire[..wire.len() - 1],
                &network,
                17,
                &issuer.verifying_key().to_bytes(),
                200
            )
            .unwrap_err(),
            SignedPeerIdentityError::Malformed
        );
        let zero_credential = envelope(network, 0, 17, &record, &issuer);
        assert_eq!(
            verify_signed_peer_identity(
                &zero_credential,
                &network,
                17,
                &issuer.verifying_key().to_bytes(),
                200
            )
            .unwrap_err(),
            SignedPeerIdentityError::CredentialMismatch
        );
    }
}
