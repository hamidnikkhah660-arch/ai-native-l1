//! Public-key provider abstraction. Private keys are intentionally out of scope.
use crate::identity_policy::{CryptoPolicy, IdentityError, KeyPurpose, KeyRecord, KeyState};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderError {
    NotFound,
    PurposeMismatch,
    InvalidKey(IdentityError),
    RotationRejected(IdentityError),
    IdentityState(String),
}

pub trait PublicKeyProvider {
    fn resolve(
        &self,
        key_id: u32,
        generation: u32,
        purpose: KeyPurpose,
    ) -> Result<KeyRecord, ProviderError>;
    fn current(&self, key_id: u32, purpose: KeyPurpose) -> Result<KeyRecord, ProviderError>;
    fn authorize(
        &self,
        key_id: u32,
        generation: u32,
        purpose: KeyPurpose,
        epoch: u64,
        policy: CryptoPolicy,
    ) -> Result<KeyRecord, ProviderError>;
}

#[derive(Debug, Clone, Default)]
pub struct InMemoryPublicKeyProvider {
    records: Vec<KeyRecord>,
}

impl InMemoryPublicKeyProvider {
    pub fn new(records: Vec<KeyRecord>) -> Result<Self, ProviderError> {
        for r in &records {
            r.validate_shape().map_err(ProviderError::InvalidKey)?;
            if r.state == KeyState::Revoked && r.not_before > r.not_after {
                return Err(ProviderError::InvalidKey(IdentityError::InvalidWindow));
            }
        }
        Ok(Self { records })
    }

    pub fn provision_rotation(
        &mut self,
        old: &KeyRecord,
        new: KeyRecord,
        policy: CryptoPolicy,
    ) -> Result<(), ProviderError> {
        KeyRecord::rotate_from(old, &new, policy).map_err(ProviderError::RotationRejected)?;
        self.records
            .retain(|r| !(r.key_id == old.key_id && r.generation == old.generation));
        self.records.push(new);
        Ok(())
    }

    pub fn revoke(
        &mut self,
        key_id: u32,
        generation: u32,
        purpose: KeyPurpose,
    ) -> Result<(), ProviderError> {
        let idx = self
            .records
            .iter()
            .position(|r| r.key_id == key_id && r.generation == generation);
        let Some(i) = idx else {
            return Err(ProviderError::NotFound);
        };
        if self.records[i].purpose != purpose {
            return Err(ProviderError::PurposeMismatch);
        }
        let revoked = KeyRecord::revoke(&self.records[i]).map_err(ProviderError::InvalidKey)?;
        self.records[i] = revoked;
        Ok(())
    }

    fn find(&self, key_id: u32, generation: u32) -> Option<&KeyRecord> {
        self.records
            .iter()
            .find(|r| r.key_id == key_id && r.generation == generation)
    }
}

impl PublicKeyProvider for InMemoryPublicKeyProvider {
    fn resolve(
        &self,
        key_id: u32,
        generation: u32,
        purpose: KeyPurpose,
    ) -> Result<KeyRecord, ProviderError> {
        let r = self
            .find(key_id, generation)
            .ok_or(ProviderError::NotFound)?;
        if r.purpose != purpose {
            return Err(ProviderError::PurposeMismatch);
        }
        Ok(r.clone())
    }

    fn current(&self, key_id: u32, purpose: KeyPurpose) -> Result<KeyRecord, ProviderError> {
        self.records
            .iter()
            .filter(|r| r.key_id == key_id && r.purpose == purpose)
            .filter(|r| r.state != KeyState::Revoked)
            .max_by_key(|r| r.generation)
            .cloned()
            .ok_or(ProviderError::NotFound)
    }

    fn authorize(
        &self,
        key_id: u32,
        generation: u32,
        purpose: KeyPurpose,
        epoch: u64,
        policy: CryptoPolicy,
    ) -> Result<KeyRecord, ProviderError> {
        let r = self.resolve(key_id, generation, purpose)?;
        if !r.is_valid_at(epoch) {
            return Err(ProviderError::InvalidKey(IdentityError::InvalidWindow));
        }
        if let Some(lock) = policy.pq_lock_epoch {
            if epoch >= lock && r.algorithm.security_class() < policy.min_class {
                return Err(ProviderError::InvalidKey(IdentityError::DowngradeBlocked));
            }
        }
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity_policy::{KeyAlgorithm, KeyPurpose, SecurityClass};

    fn k(alg: KeyAlgorithm, generation: u32, state: KeyState) -> KeyRecord {
        KeyRecord {
            key_id: 7,
            generation,
            algorithm: alg,
            purpose: KeyPurpose::PeerAuth,
            state,
            not_before: 10,
            not_after: 100,
            public_key: vec![1, 2, 3],
        }
    }
    fn policy() -> CryptoPolicy {
        CryptoPolicy {
            min_class: SecurityClass::Pq,
            pq_lock_epoch: Some(50),
        }
    }

    #[test]
    fn resolve_and_current_are_public_metadata_only() {
        let p = InMemoryPublicKeyProvider::new(vec![
            k(KeyAlgorithm::MlDsa65, 1, KeyState::Active),
            k(KeyAlgorithm::MlDsa65, 2, KeyState::Active),
        ])
        .unwrap();
        assert_eq!(p.resolve(7, 1, KeyPurpose::PeerAuth).unwrap().generation, 1);
        assert_eq!(p.current(7, KeyPurpose::PeerAuth).unwrap().generation, 2);
    }

    #[test]
    fn purpose_mismatch_and_unknown_key_reject() {
        let p = InMemoryPublicKeyProvider::new(vec![k(KeyAlgorithm::MlDsa65, 1, KeyState::Active)])
            .unwrap();
        assert_eq!(
            p.resolve(7, 1, KeyPurpose::Governance),
            Err(ProviderError::PurposeMismatch)
        );
        assert_eq!(
            p.resolve(8, 1, KeyPurpose::PeerAuth),
            Err(ProviderError::NotFound)
        );
    }

    #[test]
    fn rotation_requires_monotonic_generation() {
        let old = k(KeyAlgorithm::Ed25519, 1, KeyState::Active);
        let mut p = InMemoryPublicKeyProvider::new(vec![old.clone()]).unwrap();
        let bad = k(KeyAlgorithm::MlDsa65, 1, KeyState::Active);
        assert!(matches!(
            p.provision_rotation(&old, bad, policy()),
            Err(ProviderError::RotationRejected(
                IdentityError::GenerationRollback
            ))
        ));
        let good = k(KeyAlgorithm::MlDsa65, 2, KeyState::Active);
        assert!(p.provision_rotation(&old, good, policy()).is_ok());
    }

    #[test]
    fn revoke_removes_key_from_current_and_authorize() {
        let mut p =
            InMemoryPublicKeyProvider::new(vec![k(KeyAlgorithm::MlDsa65, 2, KeyState::Active)])
                .unwrap();
        p.revoke(7, 2, KeyPurpose::PeerAuth).unwrap();
        assert_eq!(
            p.current(7, KeyPurpose::PeerAuth),
            Err(ProviderError::NotFound)
        );
        assert_eq!(
            p.authorize(7, 2, KeyPurpose::PeerAuth, 20, policy()),
            Err(ProviderError::InvalidKey(IdentityError::InvalidWindow))
        );
    }

    #[test]
    fn pq_lock_blocks_classical_authorization() {
        let p = InMemoryPublicKeyProvider::new(vec![k(KeyAlgorithm::Ed25519, 2, KeyState::Active)])
            .unwrap();
        assert_eq!(
            p.authorize(7, 2, KeyPurpose::PeerAuth, 50, policy()),
            Err(ProviderError::InvalidKey(IdentityError::DowngradeBlocked))
        );
    }

    #[test]
    fn window_is_enforced() {
        let p = InMemoryPublicKeyProvider::new(vec![k(KeyAlgorithm::MlDsa65, 2, KeyState::Active)])
            .unwrap();
        assert!(p
            .authorize(7, 2, KeyPurpose::PeerAuth, 10, policy())
            .is_ok());
        assert_eq!(
            p.authorize(7, 2, KeyPurpose::PeerAuth, 101, policy()),
            Err(ProviderError::InvalidKey(IdentityError::InvalidWindow))
        );
    }
}
