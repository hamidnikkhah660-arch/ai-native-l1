//! Credential-to-transport binding metadata. No biometric or secret material is stored.
use crate::identity_policy::{KeyAlgorithm, KeyRecord, KeyState, SecurityClass};
use sha2::{Digest, Sha256};

pub const VERSION: u16 = 1;
pub const BINDING_HEADER: usize = 80;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialBinding {
    pub credential_id: u128,
    pub issuer_id: u32,
    pub key_id: u32,
    pub key_generation: u32,
    pub algorithm: KeyAlgorithm,
    pub transport_key_digest: [u8; 32],
    pub not_before: u64,
    pub not_after: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindingPolicy {
    pub max_validity: u64,
    pub pq_required_after: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingError {
    ZeroIssuer,
    KeyMismatch,
    GenerationMismatch,
    AlgorithmMismatch,
    RevokedKey,
    InvalidWindow,
    ValidityTooLong,
    PqRequiredAfterLock,
    Malformed,
    Version(u16),
}

pub fn transport_key_digest(algorithm: KeyAlgorithm, public_key: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"AIN1-PEER-KEY\0");
    h.update((algorithm as u16).to_be_bytes());
    h.update(public_key);
    h.finalize().into()
}

pub fn identity_context(b: &CredentialBinding) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"AIN1-IDENTITY\0");
    h.update(b.credential_id.to_be_bytes());
    h.update(b.issuer_id.to_be_bytes());
    h.update(b.key_id.to_be_bytes());
    h.update(b.key_generation.to_be_bytes());
    h.update((b.algorithm as u16).to_be_bytes());
    h.update(b.transport_key_digest);
    h.finalize().into()
}

pub fn session_identity_context(binding: &CredentialBinding, handshake_hash: &[u8]) -> [u8; 32] {
    let identity = identity_context(binding);
    let mut h = Sha256::new();
    h.update(b"AIN1-IDENTITY-SESSION\0");
    h.update(identity);
    h.update(handshake_hash);
    h.finalize().into()
}

impl CredentialBinding {
    pub fn from_key(
        credential_id: u128,
        issuer_id: u32,
        key: &KeyRecord,
        transport_public_key: &[u8],
    ) -> Self {
        Self {
            credential_id,
            issuer_id,
            key_id: key.key_id,
            key_generation: key.generation,
            algorithm: key.algorithm,
            transport_key_digest: transport_key_digest(
                KeyAlgorithm::NoiseX25519,
                transport_public_key,
            ),
            not_before: key.not_before,
            not_after: key.not_after,
        }
    }

    pub fn validate(
        &self,
        key: &KeyRecord,
        epoch: u64,
        policy: BindingPolicy,
        transport_public_key: &[u8],
    ) -> Result<(), BindingError> {
        if self.issuer_id == 0 {
            return Err(BindingError::ZeroIssuer);
        }
        if key.state == KeyState::Revoked {
            return Err(BindingError::RevokedKey);
        }
        if self.key_id != key.key_id {
            return Err(BindingError::KeyMismatch);
        }
        if self.key_generation != key.generation {
            return Err(BindingError::GenerationMismatch);
        }
        if self.algorithm != key.algorithm {
            return Err(BindingError::AlgorithmMismatch);
        }
        if self.not_before > self.not_after || epoch < self.not_before || epoch > self.not_after {
            return Err(BindingError::InvalidWindow);
        }
        if self.not_after - self.not_before > policy.max_validity {
            return Err(BindingError::ValidityTooLong);
        }
        if let Some(lock) = policy.pq_required_after {
            if epoch >= lock && self.algorithm.security_class() < SecurityClass::Pq {
                return Err(BindingError::PqRequiredAfterLock);
            }
        }
        if self.transport_key_digest
            != transport_key_digest(KeyAlgorithm::NoiseX25519, transport_public_key)
        {
            return Err(BindingError::KeyMismatch);
        }
        Ok(())
    }
}

pub fn encode(b: &CredentialBinding) -> Vec<u8> {
    let mut o = Vec::with_capacity(BINDING_HEADER);
    o.extend_from_slice(&VERSION.to_be_bytes());
    o.extend_from_slice(&b.credential_id.to_be_bytes());
    o.extend_from_slice(&b.issuer_id.to_be_bytes());
    o.extend_from_slice(&b.key_id.to_be_bytes());
    o.extend_from_slice(&b.key_generation.to_be_bytes());
    o.extend_from_slice(&(b.algorithm as u16).to_be_bytes());
    o.extend_from_slice(&b.transport_key_digest);
    o.extend_from_slice(&b.not_before.to_be_bytes());
    o.extend_from_slice(&b.not_after.to_be_bytes());
    o
}

pub fn decode(x: &[u8]) -> Result<CredentialBinding, BindingError> {
    if x.len() != BINDING_HEADER {
        return Err(BindingError::Malformed);
    }
    let v = u16::from_be_bytes(x[0..2].try_into().unwrap());
    if v != VERSION {
        return Err(BindingError::Version(v));
    }
    let credential_id = u128::from_be_bytes(x[2..18].try_into().unwrap());
    let issuer_id = u32::from_be_bytes(x[18..22].try_into().unwrap());
    let key_id = u32::from_be_bytes(x[22..26].try_into().unwrap());
    let key_generation = u32::from_be_bytes(x[26..30].try_into().unwrap());
    let algorithm = KeyAlgorithm::try_from(u16::from_be_bytes(x[30..32].try_into().unwrap()))
        .map_err(|_| BindingError::Malformed)?;
    let digest = x[32..64].try_into().unwrap();
    let not_before = u64::from_be_bytes(x[64..72].try_into().unwrap());
    let not_after = u64::from_be_bytes(x[72..80].try_into().unwrap());
    Ok(CredentialBinding {
        credential_id,
        issuer_id,
        key_id,
        key_generation,
        algorithm,
        transport_key_digest: digest,
        not_before,
        not_after,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity_policy::KeyPurpose;

    fn key(alg: KeyAlgorithm, state: KeyState) -> KeyRecord {
        KeyRecord {
            key_id: 7,
            generation: 2,
            algorithm: alg,
            purpose: KeyPurpose::PeerAuth,
            state,
            not_before: 10,
            not_after: 100,
            public_key: vec![1, 2, 3],
        }
    }
    fn policy() -> BindingPolicy {
        BindingPolicy {
            max_validity: 200,
            pq_required_after: Some(50),
        }
    }

    #[test]
    fn binding_roundtrip_and_context() {
        let k = key(KeyAlgorithm::MlDsa65, KeyState::Active);
        let b = CredentialBinding::from_key(99, 5, &k, &[8, 9]);
        assert_eq!(decode(&encode(&b)).unwrap(), b);
        assert_ne!(identity_context(&b), [0u8; 32]);
    }
    #[test]
    fn transport_key_mismatch_rejected() {
        let k = key(KeyAlgorithm::MlDsa65, KeyState::Active);
        let b = CredentialBinding::from_key(99, 5, &k, &[8, 9]);
        assert_eq!(
            b.validate(&k, 20, policy(), &[8, 10]),
            Err(BindingError::KeyMismatch)
        );
    }

    #[test]
    fn generation_revocation_and_pq_guards() {
        let k = key(KeyAlgorithm::MlDsa65, KeyState::Active);
        let b = CredentialBinding::from_key(99, 5, &k, &[8, 9]);
        let mut newer = k.clone();
        newer.generation = 3;
        assert_eq!(
            b.validate(&newer, 20, policy(), &[8, 9]),
            Err(BindingError::GenerationMismatch)
        );
        let rk = key(KeyAlgorithm::MlDsa65, KeyState::Revoked);
        assert_eq!(
            b.validate(&rk, 20, policy(), &[8, 9]),
            Err(BindingError::RevokedKey)
        );
        let ck = key(KeyAlgorithm::Ed25519, KeyState::Active);
        let cb = CredentialBinding::from_key(99, 5, &ck, &[8, 9]);
        assert_eq!(
            cb.validate(&ck, 50, policy(), &[8, 9]),
            Err(BindingError::PqRequiredAfterLock)
        );
    }
    #[test]
    fn validity_issuer_and_truncation_guards() {
        let k = key(KeyAlgorithm::MlDsa65, KeyState::Active);
        let mut b = CredentialBinding::from_key(99, 5, &k, &[8, 9]);
        assert_eq!(
            b.validate(&k, 9, policy(), &[8, 9]),
            Err(BindingError::InvalidWindow)
        );
        b.not_after = 400;
        assert_eq!(
            b.validate(&k, 20, policy(), &[8, 9]),
            Err(BindingError::ValidityTooLong)
        );
        b.not_after = 100;
        b.issuer_id = 0;
        assert_eq!(
            b.validate(&k, 20, policy(), &[8, 9]),
            Err(BindingError::ZeroIssuer)
        );
        assert_eq!(decode(&[0u8; 79]), Err(BindingError::Malformed));
    }

    #[test]
    fn session_context_binds_identity_to_transcript() {
        let k = key(KeyAlgorithm::MlDsa65, KeyState::Active);
        let b = CredentialBinding::from_key(99, 5, &k, &[8, 9]);
        let h = [7u8; 32];
        assert_eq!(
            session_identity_context(&b, &h),
            session_identity_context(&b, &h)
        );
        assert_ne!(
            session_identity_context(&b, &h),
            session_identity_context(&b, &[8u8; 32])
        );
        let mut other = b.clone();
        other.credential_id += 1;
        assert_ne!(
            session_identity_context(&b, &h),
            session_identity_context(&other, &h)
        );
    }
}
