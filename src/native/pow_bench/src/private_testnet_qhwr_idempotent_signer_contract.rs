//! CP-0410 provider-neutral durable signer contract.
//!
//! This module defines the semantic boundary only. It contains no signing key,
//! signer implementation, durable storage, authenticated transport, or HSM
//! integration. Implementors must satisfy the documented atomicity and
//! retention contract; implementing this trait alone is not proof.

use sha2::{Digest, Sha256};
use std::fmt;

const OPERATION_KEY_DOMAIN: &[u8] = b"AIN1-QHWR-SIGNER-OPERATION-KEY-V1\0";
const ARTIFACT_DIGEST_DOMAIN: &[u8] = b"AIN1-QHWR-SIGNER-ARTIFACT-V1\0";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct QhwrSignerOperationKey(pub [u8; 32]);

/// The request is immutable for the lifetime of an operation key.
/// qhwr_identity_digest must be recomputed/verified from canonical CP-0403 identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QhwrSignerRequest {
    pub operation_key: QhwrSignerOperationKey,
    pub qhwr_identity_digest: [u8; 32],
    pub signer_key_id: [u8; 32],
    pub signer_key_generation: u64,
    pub signing_digest: [u8; 32],
}

impl QhwrSignerRequest {
    pub fn from_identity_digest(
        qhwr_identity_digest: [u8; 32],
        signer_key_id: [u8; 32],
        signer_key_generation: u64,
        signing_digest: [u8; 32],
    ) -> Result<Self, QhwrSignerContractError> {
        if qhwr_identity_digest.iter().all(|byte| *byte == 0)
            || signer_key_id.iter().all(|byte| *byte == 0)
            || signer_key_generation == 0
            || signing_digest.iter().all(|byte| *byte == 0)
        {
            return Err(QhwrSignerContractError::InvalidRequest);
        }
        Ok(Self {
            operation_key: derive_operation_key(&qhwr_identity_digest),
            qhwr_identity_digest,
            signer_key_id,
            signer_key_generation,
            signing_digest,
        })
    }

    /// Revalidate public fields before an adapter sends the request to a signer.
    pub fn validate(&self) -> Result<(), QhwrSignerContractError> {
        if self.qhwr_identity_digest.iter().all(|byte| *byte == 0)
            || self.signer_key_id.iter().all(|byte| *byte == 0)
            || self.signer_key_generation == 0
            || self.signing_digest.iter().all(|byte| *byte == 0)
            || self.operation_key != derive_operation_key(&self.qhwr_identity_digest)
        {
            return Err(QhwrSignerContractError::InvalidRequest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QhwrSignerArtifact {
    pub signature_bytes: Vec<u8>,
    pub artifact_digest: [u8; 32],
}

impl QhwrSignerArtifact {
    pub fn new(signature_bytes: Vec<u8>) -> Result<Self, QhwrSignerContractError> {
        if signature_bytes.is_empty() {
            return Err(QhwrSignerContractError::EmptyArtifact);
        }
        let artifact_digest = digest_artifact(&signature_bytes);
        Ok(Self {
            signature_bytes,
            artifact_digest,
        })
    }

    pub fn validate(&self) -> Result<(), QhwrSignerContractError> {
        if self.signature_bytes.is_empty() {
            return Err(QhwrSignerContractError::EmptyArtifact);
        }
        if digest_artifact(&self.signature_bytes) != self.artifact_digest {
            return Err(QhwrSignerContractError::ArtifactDigestMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QhwrSignerLookupResult {
    NotFound,
    Pending,
    Completed(QhwrSignerArtifact),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QhwrSignerContractError {
    InvalidRequest,
    EmptyArtifact,
    ArtifactDigestMismatch,
    IdentityConflict,
    Unavailable,
    OutcomeUnknown,
    Rejected,
    IntegrityFailure,
}

impl fmt::Display for QhwrSignerContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest => f.write_str("QHWR signer request identity is invalid"),
            Self::EmptyArtifact => f.write_str("QHWR signer returned an empty artifact"),
            Self::ArtifactDigestMismatch => f.write_str("QHWR signer artifact digest mismatch"),
            Self::IdentityConflict => f.write_str("QHWR signer operation identity conflict"),
            Self::Unavailable => f.write_str("QHWR signer authority unavailable"),
            Self::OutcomeUnknown => f.write_str("QHWR signer operation outcome is unknown"),
            Self::Rejected => f.write_str("QHWR signer rejected the operation"),
            Self::IntegrityFailure => f.write_str("QHWR signer result integrity failure"),
        }
    }
}
impl std::error::Error for QhwrSignerContractError {}

/// Implementations must be linearizable across all replicas in their claimed
/// failure domain. Operation key and request fields must be atomically bound
/// before signing. Exact retries return exact retained bytes; conflicts fail
/// closed. Records survive restart/failover and remain queryable for QHWR v1
/// retention (indefinite; there is no server-issued expiry lease).
///
/// Lookup must be authenticated by the adapter transport and strongly
/// consistent. A stale or rollback-prone NotFound is not acceptable.
/// The shared-reference API permits concurrent callers to race on one key.
pub trait QhwrIdempotentSigner: Send + Sync {
    fn sign_once(
        &self,
        request: &QhwrSignerRequest,
    ) -> Result<QhwrSignerArtifact, QhwrSignerContractError>;

    fn lookup_result(
        &self,
        request: &QhwrSignerRequest,
    ) -> Result<QhwrSignerLookupResult, QhwrSignerContractError>;
}

/// The input must be the digest of the complete canonical CP-0403 identity.
pub fn derive_operation_key(identity_digest: &[u8; 32]) -> QhwrSignerOperationKey {
    let mut hasher = Sha256::new();
    hasher.update(OPERATION_KEY_DOMAIN);
    hasher.update(identity_digest);
    QhwrSignerOperationKey(hasher.finalize().into())
}

pub fn digest_artifact(signature_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ARTIFACT_DIGEST_DOMAIN);
    hasher.update((signature_bytes.len() as u64).to_be_bytes());
    hasher.update(signature_bytes);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> QhwrSignerRequest {
        QhwrSignerRequest::from_identity_digest([0x19; 32], [0x29; 32], 3, [0x39; 32]).unwrap()
    }

    #[test]
    fn operation_key_is_stable_and_domain_separated() {
        let identity = [0x11; 32];
        assert_eq!(
            derive_operation_key(&identity),
            derive_operation_key(&identity)
        );
        assert_ne!(
            derive_operation_key(&identity),
            QhwrSignerOperationKey(identity)
        );
        assert_ne!(
            derive_operation_key(&identity),
            derive_operation_key(&[0x12; 32])
        );
    }

    #[test]
    fn request_rejects_zero_identity_key_generation_and_digest() {
        assert_eq!(
            QhwrSignerRequest::from_identity_digest([0; 32], [1; 32], 1, [2; 32]),
            Err(QhwrSignerContractError::InvalidRequest)
        );
        assert_eq!(
            QhwrSignerRequest::from_identity_digest([1; 32], [0; 32], 1, [2; 32]),
            Err(QhwrSignerContractError::InvalidRequest)
        );
        assert_eq!(
            QhwrSignerRequest::from_identity_digest([1; 32], [2; 32], 0, [3; 32]),
            Err(QhwrSignerContractError::InvalidRequest)
        );
        assert_eq!(
            QhwrSignerRequest::from_identity_digest([1; 32], [2; 32], 1, [0; 32]),
            Err(QhwrSignerContractError::InvalidRequest)
        );
    }

    #[test]
    fn request_validation_rejects_mutated_operation_key() {
        let mut changed = request();
        changed.operation_key.0[0] ^= 1;
        assert_eq!(
            changed.validate(),
            Err(QhwrSignerContractError::InvalidRequest)
        );
    }

    #[test]
    fn request_pins_key_generation_and_signing_digest() {
        let original = request();
        let mut changed = original.clone();
        changed.signer_key_generation += 1;
        assert_ne!(original, changed);
        let mut changed = original.clone();
        changed.signing_digest[0] ^= 1;
        assert_ne!(original, changed);
        let mut changed = original.clone();
        changed.signer_key_id[0] ^= 1;
        assert_ne!(original, changed);
    }

    #[test]
    fn artifact_constructor_and_validation_bind_exact_bytes() {
        let artifact = QhwrSignerArtifact::new(b"stable-signature".to_vec()).unwrap();
        assert_eq!(artifact.validate(), Ok(()));
        let mut tampered = artifact;
        tampered.signature_bytes[0] ^= 1;
        assert_eq!(
            tampered.validate(),
            Err(QhwrSignerContractError::ArtifactDigestMismatch)
        );
    }

    #[test]
    fn artifact_rejects_empty_bytes() {
        assert_eq!(
            QhwrSignerArtifact::new(Vec::new()),
            Err(QhwrSignerContractError::EmptyArtifact)
        );
    }
}
