//! Canonical-byte PublicKeyProvider adapter for interoperability testing.
//! This intentionally uses serialized public metadata rather than InMemoryPublicKeyProvider.

use crate::identity_policy::{
    decode, CryptoPolicy, IdentityError, KeyPurpose, KeyRecord, KeyState,
};
use crate::key_provider::{ProviderError, PublicKeyProvider};

#[derive(Debug, Clone, Default)]
pub struct CanonicalPublicKeyProvider {
    records: Vec<Vec<u8>>,
}

impl CanonicalPublicKeyProvider {
    pub fn from_records(records: Vec<KeyRecord>) -> Result<Self, ProviderError> {
        let mut encoded = Vec::with_capacity(records.len());
        for record in records {
            encoded
                .push(crate::identity_policy::encode(&record).map_err(ProviderError::InvalidKey)?);
        }
        Ok(Self { records: encoded })
    }

    pub fn from_encoded(records: Vec<Vec<u8>>) -> Result<Self, ProviderError> {
        for raw in &records {
            decode(raw).map_err(ProviderError::InvalidKey)?;
        }
        Ok(Self { records })
    }

    fn decoded(&self) -> impl Iterator<Item = KeyRecord> + '_ {
        self.records.iter().filter_map(|raw| decode(raw).ok())
    }

    pub fn provision_rotation(
        &mut self,
        old: &KeyRecord,
        new: KeyRecord,
        policy: CryptoPolicy,
    ) -> Result<(), ProviderError> {
        KeyRecord::rotate_from(old, &new, policy).map_err(ProviderError::RotationRejected)?;
        self.records.retain(|raw| {
            decode(raw).map_or(true, |r| {
                !(r.key_id == old.key_id && r.generation == old.generation)
            })
        });
        self.records
            .push(crate::identity_policy::encode(&new).map_err(ProviderError::InvalidKey)?);
        Ok(())
    }

    pub fn revoke(
        &mut self,
        key_id: u32,
        generation: u32,
        purpose: KeyPurpose,
    ) -> Result<(), ProviderError> {
        let mut found = false;
        for raw in &mut self.records {
            let record = decode(raw).map_err(ProviderError::InvalidKey)?;
            if record.key_id == key_id && record.generation == generation {
                if record.purpose != purpose {
                    return Err(ProviderError::PurposeMismatch);
                }
                *raw = crate::identity_policy::encode(
                    &KeyRecord::revoke(&record).map_err(ProviderError::InvalidKey)?,
                )
                .map_err(ProviderError::InvalidKey)?;
                found = true;
            }
        }
        if found {
            Ok(())
        } else {
            Err(ProviderError::NotFound)
        }
    }
}
impl PublicKeyProvider for CanonicalPublicKeyProvider {
    fn resolve(
        &self,
        key_id: u32,
        generation: u32,
        purpose: KeyPurpose,
    ) -> Result<KeyRecord, ProviderError> {
        let record = self
            .decoded()
            .find(|r| r.key_id == key_id && r.generation == generation)
            .ok_or(ProviderError::NotFound)?;
        if record.purpose != purpose {
            return Err(ProviderError::PurposeMismatch);
        }
        Ok(record)
    }

    fn current(&self, key_id: u32, purpose: KeyPurpose) -> Result<KeyRecord, ProviderError> {
        self.decoded()
            .filter(|r| r.key_id == key_id && r.purpose == purpose)
            .filter(|r| r.state != KeyState::Revoked)
            .max_by_key(|r| r.generation)
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
        let record = self.resolve(key_id, generation, purpose)?;
        if !record.is_valid_at(epoch) {
            return Err(ProviderError::InvalidKey(IdentityError::InvalidWindow));
        }
        if let Some(lock) = policy.pq_lock_epoch {
            if epoch >= lock && record.algorithm.security_class() < policy.min_class {
                return Err(ProviderError::InvalidKey(IdentityError::DowngradeBlocked));
            }
        }
        Ok(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity_policy::{KeyAlgorithm, SecurityClass};

    fn key(generation: u32, state: KeyState) -> KeyRecord {
        KeyRecord {
            key_id: 7,
            generation,
            algorithm: KeyAlgorithm::MlDsa65,
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
    fn canonical_provider_matches_expected_generation() {
        let p = CanonicalPublicKeyProvider::from_records(vec![
            key(2, KeyState::Active),
            key(3, KeyState::Active),
        ])
        .unwrap();
        assert_eq!(p.current(7, KeyPurpose::PeerAuth).unwrap().generation, 3);
        assert_eq!(
            p.authorize(7, 3, KeyPurpose::PeerAuth, 20, policy())
                .unwrap()
                .generation,
            3
        );
    }

    #[test]
    fn canonical_provider_rejects_revocation_and_pq_downgrade() {
        let mut p =
            CanonicalPublicKeyProvider::from_records(vec![key(2, KeyState::Active)]).unwrap();
        p.revoke(7, 2, KeyPurpose::PeerAuth).unwrap();
        assert_eq!(
            p.current(7, KeyPurpose::PeerAuth),
            Err(ProviderError::NotFound)
        );

        let classical = KeyRecord {
            algorithm: KeyAlgorithm::Ed25519,
            ..key(3, KeyState::Active)
        };
        let q = CanonicalPublicKeyProvider::from_records(vec![classical]).unwrap();
        assert_eq!(
            q.authorize(7, 3, KeyPurpose::PeerAuth, 50, policy()),
            Err(ProviderError::InvalidKey(IdentityError::DowngradeBlocked))
        );
    }

    #[test]
    fn canonical_rotation_is_monotonic_and_revokes_current() {
        let old = key(2, KeyState::Active);
        let mut p = CanonicalPublicKeyProvider::from_records(vec![old.clone()]).unwrap();
        let new = key(3, KeyState::Active);
        p.provision_rotation(&old, new, policy()).unwrap();
        assert_eq!(p.current(7, KeyPurpose::PeerAuth).unwrap().generation, 3);
        p.revoke(7, 3, KeyPurpose::PeerAuth).unwrap();
        assert_eq!(
            p.current(7, KeyPurpose::PeerAuth),
            Err(ProviderError::NotFound)
        );
    }

    #[test]
    fn encoded_and_structured_construction_are_equivalent() {
        let r = key(2, KeyState::Active);
        let a = CanonicalPublicKeyProvider::from_records(vec![r.clone()]).unwrap();
        let b = CanonicalPublicKeyProvider::from_encoded(vec![
            crate::identity_policy::encode(&r).unwrap()
        ])
        .unwrap();
        assert_eq!(
            a.current(7, KeyPurpose::PeerAuth).unwrap(),
            b.current(7, KeyPurpose::PeerAuth).unwrap()
        );
    }
}
