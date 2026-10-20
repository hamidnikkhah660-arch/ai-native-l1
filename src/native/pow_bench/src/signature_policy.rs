//! Signature metadata/policy layer. Actual signature primitives remain external and must be supplied by reviewed libraries.
use crate::identity_policy::{KeyAlgorithm, KeyPurpose, SecurityClass};

pub const MAX_SIGNATURE: usize = 64 * 1024;
pub const SIG_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SignatureSuite {
    Ed25519 = 1,
    MlDsa65 = 100,
    SlhDsa128s = 101,
    HybridEd25519MlDsa65 = 200,
}
impl SignatureSuite {
    pub fn security_class(self) -> SecurityClass {
        match self {
            Self::Ed25519 => SecurityClass::Classical,
            Self::MlDsa65 | Self::SlhDsa128s | Self::HybridEd25519MlDsa65 => SecurityClass::Pq,
        }
    }
    pub fn key_algorithm(self) -> KeyAlgorithm {
        match self {
            Self::Ed25519 => KeyAlgorithm::Ed25519,
            Self::MlDsa65 | Self::HybridEd25519MlDsa65 => KeyAlgorithm::MlDsa65,
            Self::SlhDsa128s => KeyAlgorithm::SlhDsa128s,
        }
    }
}
impl TryFrom<u16> for SignatureSuite {
    type Error = SigPolicyError;
    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(Self::Ed25519),
            100 => Ok(Self::MlDsa65),
            101 => Ok(Self::SlhDsa128s),
            200 => Ok(Self::HybridEd25519MlDsa65),
            _ => Err(SigPolicyError::UnknownSuite(v)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigPolicy {
    pub min_class: SecurityClass,
    pub pq_activation_epoch: Option<u64>,
    pub require_hybrid_until: Option<u64>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigPolicyError {
    UnknownSuite(u16),
    Oversize(usize),
    EmptySignature,
    Version(u16),
    Malformed,
    AlgorithmMismatch,
    PurposeMismatch,
    DowngradeBlocked,
    HybridRequired,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureEnvelope {
    pub suite: SignatureSuite,
    pub key_id: u32,
    pub generation: u32,
    pub purpose: KeyPurpose,
    pub domain: u16,
    pub signature: Vec<u8>,
}

impl SignatureEnvelope {
    pub fn validate(
        &self,
        signer_alg: KeyAlgorithm,
        signer_purpose: KeyPurpose,
        epoch: u64,
        policy: SigPolicy,
    ) -> Result<(), SigPolicyError> {
        if self.signature.is_empty() {
            return Err(SigPolicyError::EmptySignature);
        }
        if self.signature.len() > MAX_SIGNATURE {
            return Err(SigPolicyError::Oversize(self.signature.len()));
        }
        if self.purpose != signer_purpose {
            return Err(SigPolicyError::PurposeMismatch);
        }
        if self.suite.key_algorithm() != signer_alg {
            return Err(SigPolicyError::AlgorithmMismatch);
        }
        if let Some(lock) = policy.pq_activation_epoch {
            if epoch >= lock && self.suite.security_class() < policy.min_class {
                return Err(SigPolicyError::DowngradeBlocked);
            }
        }
        if let Some(until) = policy.require_hybrid_until {
            if epoch <= until && self.suite != SignatureSuite::HybridEd25519MlDsa65 {
                return Err(SigPolicyError::HybridRequired);
            }
        }
        Ok(())
    }
}

pub fn encode(s: &SignatureEnvelope) -> Result<Vec<u8>, SigPolicyError> {
    if s.signature.is_empty() {
        return Err(SigPolicyError::EmptySignature);
    }
    if s.signature.len() > MAX_SIGNATURE {
        return Err(SigPolicyError::Oversize(s.signature.len()));
    }
    if s.generation == 0 {
        return Err(SigPolicyError::Malformed);
    }
    let mut b = Vec::with_capacity(22 + s.signature.len());
    b.extend_from_slice(&SIG_VERSION.to_be_bytes());
    b.extend_from_slice(&(s.suite as u16).to_be_bytes());
    b.extend_from_slice(&s.key_id.to_be_bytes());
    b.extend_from_slice(&s.generation.to_be_bytes());
    b.push(s.purpose as u8);
    b.extend_from_slice(&s.domain.to_be_bytes());
    b.extend_from_slice(&(s.signature.len() as u32).to_be_bytes());
    b.extend_from_slice(&s.signature);
    Ok(b)
}
pub fn decode(b: &[u8]) -> Result<SignatureEnvelope, SigPolicyError> {
    if b.len() < 19 {
        return Err(SigPolicyError::Malformed);
    }
    let v = u16::from_be_bytes(b[0..2].try_into().unwrap());
    if v != SIG_VERSION {
        return Err(SigPolicyError::Version(v));
    }
    let suite = SignatureSuite::try_from(u16::from_be_bytes(b[2..4].try_into().unwrap()))?;
    let key_id = u32::from_be_bytes(b[4..8].try_into().unwrap());
    let generation = u32::from_be_bytes(b[8..12].try_into().unwrap());
    let purpose = KeyPurpose::try_from(b[12]).map_err(|_| SigPolicyError::Malformed)?;
    let domain = u16::from_be_bytes(b[13..15].try_into().unwrap());
    let len = u32::from_be_bytes(b[15..19].try_into().unwrap()) as usize;
    if len == 0 || len > MAX_SIGNATURE || b.len() != 19 + len {
        return Err(SigPolicyError::Malformed);
    }
    Ok(SignatureEnvelope {
        suite,
        key_id,
        generation,
        purpose,
        domain,
        signature: b[19..].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn s(suite: SignatureSuite) -> SignatureEnvelope {
        SignatureEnvelope {
            suite,
            key_id: 9,
            generation: 1,
            purpose: KeyPurpose::AccountAuth,
            domain: 7,
            signature: vec![1, 2, 3],
        }
    }
    fn p() -> SigPolicy {
        SigPolicy {
            min_class: SecurityClass::Pq,
            pq_activation_epoch: Some(20),
            require_hybrid_until: None,
        }
    }
    #[test]
    fn metadata_vector_roundtrip() {
        let x = s(SignatureSuite::MlDsa65);
        assert_eq!(decode(&encode(&x).unwrap()).unwrap(), x);
    }
    #[test]
    fn unknown_suite_rejected() {
        let mut b = encode(&s(SignatureSuite::Ed25519)).unwrap();
        b[2] = 0x7f;
        b[3] = 0xfe;
        assert_eq!(decode(&b), Err(SigPolicyError::UnknownSuite(32766)));
    }
    #[test]
    fn algorithm_and_purpose_binding() {
        let x = s(SignatureSuite::MlDsa65);
        assert_eq!(
            x.validate(KeyAlgorithm::Ed25519, KeyPurpose::AccountAuth, 10, p()),
            Err(SigPolicyError::AlgorithmMismatch)
        );
        assert_eq!(
            x.validate(KeyAlgorithm::MlDsa65, KeyPurpose::PeerAuth, 10, p()),
            Err(SigPolicyError::PurposeMismatch)
        );
    }
    #[test]
    fn pq_lock_blocks_classical_downgrade() {
        let x = s(SignatureSuite::Ed25519);
        assert_eq!(
            x.validate(KeyAlgorithm::Ed25519, KeyPurpose::AccountAuth, 20, p()),
            Err(SigPolicyError::DowngradeBlocked)
        );
    }
    #[test]
    fn hybrid_window_is_explicit() {
        let x = s(SignatureSuite::MlDsa65);
        let q = SigPolicy {
            require_hybrid_until: Some(50),
            ..p()
        };
        assert_eq!(
            x.validate(KeyAlgorithm::MlDsa65, KeyPurpose::AccountAuth, 20, q),
            Err(SigPolicyError::HybridRequired)
        );
    }
    #[test]
    fn truncation_is_rejected() {
        assert_eq!(decode(&[0u8; 18]), Err(SigPolicyError::Malformed));
    }
    #[test]
    fn empty_signature_is_rejected() {
        assert_eq!(
            encode(&SignatureEnvelope {
                signature: vec![],
                ..s(SignatureSuite::Ed25519)
            }),
            Err(SigPolicyError::EmptySignature)
        );
    }
}
