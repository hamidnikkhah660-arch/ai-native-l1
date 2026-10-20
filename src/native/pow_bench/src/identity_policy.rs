//! Cryptographic identity and key-lifecycle policy, without private-key material.
use std::convert::TryFrom;

pub const ENVELOPE_VERSION: u16 = 1;
pub const MAX_PUBLIC_KEY: usize = 16 * 1024;
pub const HEADER_LEN: usize = 34;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum KeyAlgorithm {
    Ed25519 = 1,
    NoiseX25519 = 2,
    MlDsa65 = 100,
    SlhDsa128s = 101,
}
impl KeyAlgorithm {
    pub fn security_class(self) -> SecurityClass {
        match self {
            Self::MlDsa65 | Self::SlhDsa128s => SecurityClass::Pq,
            Self::Ed25519 | Self::NoiseX25519 => SecurityClass::Classical,
        }
    }
}
impl TryFrom<u16> for KeyAlgorithm {
    type Error = IdentityError;
    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(Self::Ed25519),
            2 => Ok(Self::NoiseX25519),
            100 => Ok(Self::MlDsa65),
            101 => Ok(Self::SlhDsa128s),
            _ => Err(IdentityError::UnknownAlgorithm(v)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityClass {
    Classical = 0,
    Pq = 2,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KeyPurpose {
    PeerAuth = 1,
    AccountAuth = 2,
    Governance = 3,
    Recovery = 4,
}
impl TryFrom<u8> for KeyPurpose {
    type Error = IdentityError;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(Self::PeerAuth),
            2 => Ok(Self::AccountAuth),
            3 => Ok(Self::Governance),
            4 => Ok(Self::Recovery),
            _ => Err(IdentityError::UnknownPurpose(v)),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KeyState {
    Active = 1,
    Retired = 2,
    Revoked = 3,
}
impl TryFrom<u8> for KeyState {
    type Error = IdentityError;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(Self::Active),
            2 => Ok(Self::Retired),
            3 => Ok(Self::Revoked),
            _ => Err(IdentityError::UnknownState(v)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRecord {
    pub key_id: u32,
    pub generation: u32,
    pub algorithm: KeyAlgorithm,
    pub purpose: KeyPurpose,
    pub state: KeyState,
    pub not_before: u64,
    pub not_after: u64,
    pub public_key: Vec<u8>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoPolicy {
    pub min_class: SecurityClass,
    pub pq_lock_epoch: Option<u64>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    UnknownAlgorithm(u16),
    UnknownPurpose(u8),
    UnknownState(u8),
    BadVersion(u16),
    Oversize(usize),
    InvalidWindow,
    InvalidStateTransition,
    GenerationRollback,
    DowngradeBlocked,
    Malformed,
    KeyBindingMissing,
}

impl KeyRecord {
    pub fn validate_shape(&self) -> Result<(), IdentityError> {
        if self.public_key.len() > MAX_PUBLIC_KEY {
            return Err(IdentityError::Oversize(self.public_key.len()));
        }
        if self.not_before > self.not_after {
            return Err(IdentityError::InvalidWindow);
        }
        if self.generation == 0 {
            return Err(IdentityError::GenerationRollback);
        }
        Ok(())
    }
    pub fn is_valid_at(&self, epoch: u64) -> bool {
        self.state == KeyState::Active && self.not_before <= epoch && epoch <= self.not_after
    }
    pub fn rotate_from(old: &Self, new: &Self, policy: CryptoPolicy) -> Result<(), IdentityError> {
        old.validate_shape()?;
        new.validate_shape()?;
        if old.key_id != new.key_id || old.purpose != new.purpose {
            return Err(IdentityError::KeyBindingMissing);
        }
        if new.generation <= old.generation {
            return Err(IdentityError::GenerationRollback);
        }
        if old.state == KeyState::Revoked {
            return Err(IdentityError::InvalidStateTransition);
        }
        if let Some(lock) = policy.pq_lock_epoch {
            if new.not_before >= lock && new.algorithm.security_class() < policy.min_class {
                return Err(IdentityError::DowngradeBlocked);
            }
        }
        Ok(())
    }
    pub fn revoke(old: &Self) -> Result<Self, IdentityError> {
        if old.state == KeyState::Revoked {
            return Err(IdentityError::InvalidStateTransition);
        }
        let mut n = old.clone();
        n.state = KeyState::Revoked;
        Ok(n)
    }
}

pub fn encode(record: &KeyRecord) -> Result<Vec<u8>, IdentityError> {
    record.validate_shape()?;
    let mut o = Vec::with_capacity(HEADER_LEN + record.public_key.len());
    o.extend_from_slice(&ENVELOPE_VERSION.to_be_bytes());
    o.extend_from_slice(&(record.algorithm as u16).to_be_bytes());
    o.push(record.purpose as u8);
    o.push(record.state as u8);
    o.extend_from_slice(&record.key_id.to_be_bytes());
    o.extend_from_slice(&record.generation.to_be_bytes());
    o.extend_from_slice(&record.not_before.to_be_bytes());
    o.extend_from_slice(&record.not_after.to_be_bytes());
    o.extend_from_slice(&(record.public_key.len() as u32).to_be_bytes());
    o.extend_from_slice(&record.public_key);
    Ok(o)
}
pub fn decode(bytes: &[u8]) -> Result<KeyRecord, IdentityError> {
    if bytes.len() < HEADER_LEN {
        return Err(IdentityError::Malformed);
    }
    let v = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
    if v != ENVELOPE_VERSION {
        return Err(IdentityError::BadVersion(v));
    }
    let alg = KeyAlgorithm::try_from(u16::from_be_bytes(bytes[2..4].try_into().unwrap()))?;
    let purpose = KeyPurpose::try_from(bytes[4])?;
    let state = KeyState::try_from(bytes[5])?;
    let key_id = u32::from_be_bytes(bytes[6..10].try_into().unwrap());
    let generation = u32::from_be_bytes(bytes[10..14].try_into().unwrap());
    let nb = u64::from_be_bytes(bytes[14..22].try_into().unwrap());
    let na = u64::from_be_bytes(bytes[22..30].try_into().unwrap());
    let len = u32::from_be_bytes(bytes[30..34].try_into().unwrap()) as usize;
    if len > MAX_PUBLIC_KEY || bytes.len() != 34 + len {
        return Err(IdentityError::Malformed);
    }
    let r = KeyRecord {
        key_id,
        generation,
        algorithm: alg,
        purpose,
        state,
        not_before: nb,
        not_after: na,
        public_key: bytes[34..].to_vec(),
    };
    r.validate_shape()?;
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn r(alg: KeyAlgorithm, g: u32, state: KeyState) -> KeyRecord {
        KeyRecord {
            key_id: 7,
            generation: g,
            algorithm: alg,
            purpose: KeyPurpose::PeerAuth,
            state,
            not_before: 10,
            not_after: 100,
            public_key: vec![1, 2, 3],
        }
    }
    #[test]
    fn roundtrip_public_envelope() {
        let x = r(KeyAlgorithm::MlDsa65, 1, KeyState::Active);
        assert_eq!(decode(&encode(&x).unwrap()).unwrap(), x);
    }
    #[test]
    fn no_private_key_field_and_bound() {
        let x = r(KeyAlgorithm::Ed25519, 1, KeyState::Active);
        let b = encode(&x).unwrap();
        assert!(b.len() < HEADER_LEN + MAX_PUBLIC_KEY);
        assert!(!b.windows(4).any(|w| w == [0xAA, 0xBB, 0xCC, 0xDD]));
    }
    #[test]
    fn unknown_algorithm_rejected() {
        let mut b = encode(&r(KeyAlgorithm::Ed25519, 1, KeyState::Active)).unwrap();
        b[2] = 0x7f;
        b[3] = 0xff;
        assert_eq!(decode(&b), Err(IdentityError::UnknownAlgorithm(32767)));
    }
    #[test]
    fn generation_rollback_rejected() {
        let old = r(KeyAlgorithm::Ed25519, 3, KeyState::Active);
        let new = r(KeyAlgorithm::MlDsa65, 2, KeyState::Active);
        assert_eq!(
            KeyRecord::rotate_from(
                &old,
                &new,
                CryptoPolicy {
                    min_class: SecurityClass::Pq,
                    pq_lock_epoch: Some(20)
                }
            ),
            Err(IdentityError::GenerationRollback)
        );
    }
    #[test]
    fn pq_downgrade_after_lock_rejected() {
        let old = r(KeyAlgorithm::MlDsa65, 1, KeyState::Active);
        let mut new = r(KeyAlgorithm::Ed25519, 2, KeyState::Active);
        new.not_before = 20;
        assert_eq!(
            KeyRecord::rotate_from(
                &old,
                &new,
                CryptoPolicy {
                    min_class: SecurityClass::Pq,
                    pq_lock_epoch: Some(20)
                }
            ),
            Err(IdentityError::DowngradeBlocked)
        );
    }
    #[test]
    fn revocation_is_terminal() {
        let old = r(KeyAlgorithm::Ed25519, 1, KeyState::Active);
        let revoked = KeyRecord::revoke(&old).unwrap();
        assert_eq!(revoked.state, KeyState::Revoked);
        assert_eq!(
            KeyRecord::revoke(&revoked),
            Err(IdentityError::InvalidStateTransition)
        );
    }
    #[test]
    fn truncated_envelope_rejected_without_panic() {
        assert_eq!(decode(&[0u8; 33]), Err(IdentityError::Malformed));
    }
    #[test]
    fn validity_window_is_enforced() {
        let x = r(KeyAlgorithm::Ed25519, 1, KeyState::Active);
        assert!(!x.is_valid_at(9));
        assert!(x.is_valid_at(10));
        assert!(x.is_valid_at(100));
        assert!(!x.is_valid_at(101));
    }
}
