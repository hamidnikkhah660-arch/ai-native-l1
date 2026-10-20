//! Provider-backed session lifecycle for identity-aware transports.
use crate::{
    identity_policy::{CryptoPolicy, KeyPurpose, KeyRecord, KeyState},
    key_provider::{ProviderError, PublicKeyProvider},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Active,
    RefreshRequired { current_generation: u32 },
    Revoked,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    RefreshRequired { current_generation: u32 },
    Revoked,
    Closed,
    Provider(ProviderError),
    ContextMismatch,
    KeyBindingMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundSession {
    key_id: u32,
    generation: u32,
    purpose: KeyPurpose,
    context: [u8; 32],
    state: SessionState,
}

impl BoundSession {
    pub fn bind(record: &KeyRecord, context: [u8; 32]) -> Result<Self, SessionError> {
        if record.state != KeyState::Active {
            return Err(SessionError::Revoked);
        }
        Ok(Self {
            key_id: record.key_id,
            generation: record.generation,
            purpose: record.purpose,
            context,
            state: SessionState::Active,
        })
    }

    pub fn key_id(&self) -> u32 {
        self.key_id
    }

    pub fn generation(&self) -> u32 {
        self.generation
    }

    pub fn purpose(&self) -> KeyPurpose {
        self.purpose
    }

    pub fn context(&self) -> [u8; 32] {
        self.context
    }

    pub fn state(&self) -> SessionState {
        self.state
    }

    pub fn context_matches(&self, candidate: &[u8]) -> bool {
        candidate == self.context
    }

    pub fn close(&mut self) {
        self.state = SessionState::Closed;
    }

    pub fn revalidate<P: PublicKeyProvider>(
        &mut self,
        provider: &P,
        epoch: u64,
        policy: CryptoPolicy,
    ) -> Result<(), SessionError> {
        match self.state {
            SessionState::Closed => return Err(SessionError::Closed),
            SessionState::Revoked => return Err(SessionError::Revoked),
            SessionState::RefreshRequired { current_generation } => {
                return Err(SessionError::RefreshRequired { current_generation })
            }
            SessionState::Active => {}
        }

        match provider.current(self.key_id, self.purpose) {
            Ok(current) if current.generation > self.generation => {
                self.state = SessionState::RefreshRequired {
                    current_generation: current.generation,
                };
                return Err(SessionError::RefreshRequired {
                    current_generation: current.generation,
                });
            }
            Ok(current) if current.generation == self.generation => {
                match provider.authorize(self.key_id, self.generation, self.purpose, epoch, policy)
                {
                    Ok(_) => return Ok(()),
                    Err(e) => {
                        self.state = SessionState::Closed;
                        return Err(SessionError::Provider(e));
                    }
                }
            }
            Ok(_) => {
                self.state = SessionState::Closed;
                return Err(SessionError::KeyBindingMismatch);
            }
            Err(ProviderError::NotFound) => {}
            Err(e) => {
                self.state = SessionState::Closed;
                return Err(SessionError::Provider(e));
            }
        }

        match provider.resolve(self.key_id, self.generation, self.purpose) {
            Ok(record) if record.state == KeyState::Revoked => {
                self.state = SessionState::Revoked;
                Err(SessionError::Revoked)
            }
            Ok(_) => {
                self.state = SessionState::Closed;
                Err(SessionError::Provider(ProviderError::NotFound))
            }
            Err(e) => {
                self.state = SessionState::Closed;
                Err(SessionError::Provider(e))
            }
        }
    }

    pub fn refresh(
        &mut self,
        record: &KeyRecord,
        new_context: [u8; 32],
    ) -> Result<(), SessionError> {
        match self.state {
            SessionState::Revoked => return Err(SessionError::Revoked),
            SessionState::Closed => return Err(SessionError::Closed),
            SessionState::Active | SessionState::RefreshRequired { .. } => {}
        }
        if record.key_id != self.key_id || record.purpose != self.purpose {
            return Err(SessionError::KeyBindingMismatch);
        }
        if record.generation <= self.generation {
            return Err(SessionError::KeyBindingMismatch);
        }
        if record.state != KeyState::Active {
            return Err(SessionError::Revoked);
        }
        self.generation = record.generation;
        self.context = new_context;
        self.state = SessionState::Active;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity_policy::{KeyAlgorithm, SecurityClass};
    use crate::key_provider::InMemoryPublicKeyProvider;

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
    fn active_session_revalidates_against_provider() {
        let provider = InMemoryPublicKeyProvider::new(vec![key(2, KeyState::Active)]).unwrap();
        let mut s = BoundSession::bind(&key(2, KeyState::Active), [9; 32]).unwrap();
        assert_eq!(s.revalidate(&provider, 20, policy()), Ok(()));
        assert_eq!(s.state(), SessionState::Active);
    }

    #[test]
    fn rotation_marks_existing_session_refresh_required() {
        let old = key(2, KeyState::Active);
        let mut provider = InMemoryPublicKeyProvider::new(vec![old.clone()]).unwrap();
        let mut s = BoundSession::bind(&old, [9; 32]).unwrap();
        provider
            .provision_rotation(&old, key(3, KeyState::Active), policy())
            .unwrap();
        assert_eq!(
            s.revalidate(&provider, 20, policy()),
            Err(SessionError::RefreshRequired {
                current_generation: 3
            })
        );
        assert_eq!(
            s.state(),
            SessionState::RefreshRequired {
                current_generation: 3
            }
        );
        assert_eq!(
            s.revalidate(&provider, 20, policy()),
            Err(SessionError::RefreshRequired {
                current_generation: 3
            })
        );
    }

    #[test]
    fn refresh_requires_strictly_new_active_generation() {
        let old = key(2, KeyState::Active);
        let mut s = BoundSession::bind(&old, [1; 32]).unwrap();
        assert_eq!(
            s.refresh(&old, [2; 32]),
            Err(SessionError::KeyBindingMismatch)
        );
        assert_eq!(s.refresh(&key(3, KeyState::Active), [3; 32]), Ok(()));
        assert_eq!(s.generation(), 3);
        assert_eq!(s.context(), [3; 32]);
        assert_eq!(s.state(), SessionState::Active);
    }

    #[test]
    fn revocation_is_terminal_for_the_bound_session() {
        let old = key(2, KeyState::Active);
        let mut provider = InMemoryPublicKeyProvider::new(vec![old.clone()]).unwrap();
        let mut s = BoundSession::bind(&old, [7; 32]).unwrap();
        provider.revoke(7, 2, KeyPurpose::PeerAuth).unwrap();
        assert_eq!(
            s.revalidate(&provider, 20, policy()),
            Err(SessionError::Revoked)
        );
        assert_eq!(s.state(), SessionState::Revoked);
        assert_eq!(
            s.revalidate(&provider, 20, policy()),
            Err(SessionError::Revoked)
        );
        assert_eq!(
            s.refresh(&key(3, KeyState::Active), [8; 32]),
            Err(SessionError::Revoked)
        );
    }

    #[test]
    fn rollback_and_closed_states_cannot_recover() {
        let old = key(2, KeyState::Active);
        let mut provider = InMemoryPublicKeyProvider::new(vec![old.clone()]).unwrap();
        assert!(provider
            .provision_rotation(&old, key(1, KeyState::Active), policy())
            .is_err());
        let mut s = BoundSession::bind(&old, [4; 32]).unwrap();
        s.close();
        assert_eq!(
            s.revalidate(&provider, 20, policy()),
            Err(SessionError::Closed)
        );
        assert_eq!(
            s.refresh(&key(3, KeyState::Active), [8; 32]),
            Err(SessionError::Closed)
        );
    }

    #[test]
    fn context_never_contains_or_exposes_credential_id() {
        let s = BoundSession::bind(&key(2, KeyState::Active), [5; 32]).unwrap();
        assert_eq!(s.context(), [5; 32]);
        assert!(!format!("{:?}", s).contains("credential"));
    }

    #[test]
    fn refresh_required_blocks_old_session_until_refresh() {
        let old = key(2, KeyState::Active);
        let mut provider = InMemoryPublicKeyProvider::new(vec![old.clone()]).unwrap();
        let mut s = BoundSession::bind(&old, [1; 32]).unwrap();
        provider
            .provision_rotation(&old, key(3, KeyState::Active), policy())
            .unwrap();
        assert!(matches!(
            s.revalidate(&provider, 20, policy()),
            Err(SessionError::RefreshRequired {
                current_generation: 3
            })
        ));
        assert!(matches!(
            s.revalidate(&provider, 20, policy()),
            Err(SessionError::RefreshRequired {
                current_generation: 3
            })
        ));
        s.refresh(&key(3, KeyState::Active), [2; 32]).unwrap();
        assert_eq!(s.state(), SessionState::Active);
    }

    #[test]
    fn revoke_after_rotation_still_blocks_old_bound_session() {
        let old = key(2, KeyState::Active);
        let mut provider = InMemoryPublicKeyProvider::new(vec![old.clone()]).unwrap();
        let mut s = BoundSession::bind(&old, [3; 32]).unwrap();
        provider
            .provision_rotation(&old, key(3, KeyState::Active), policy())
            .unwrap();
        provider.revoke(7, 3, KeyPurpose::PeerAuth).unwrap();
        let result = s.revalidate(&provider, 20, policy());
        assert!(matches!(result, Err(SessionError::Provider(_))));
        assert_eq!(s.state(), SessionState::Closed);
        assert_eq!(
            s.refresh(&key(3, KeyState::Revoked), [4; 32]),
            Err(SessionError::Closed)
        );
    }

    #[test]
    fn close_is_terminal_after_refresh_required() {
        let old = key(2, KeyState::Active);
        let mut provider = InMemoryPublicKeyProvider::new(vec![old.clone()]).unwrap();
        let mut s = BoundSession::bind(&old, [5; 32]).unwrap();
        provider
            .provision_rotation(&old, key(3, KeyState::Active), policy())
            .unwrap();
        let _ = s.revalidate(&provider, 20, policy());
        s.close();
        assert_eq!(s.state(), SessionState::Closed);
        assert_eq!(
            s.refresh(&key(3, KeyState::Active), [6; 32]),
            Err(SessionError::Closed)
        );
    }

    #[test]
    fn refreshed_generation_requires_new_context() {
        let old = key(2, KeyState::Active);
        let mut s = BoundSession::bind(&old, [7; 32]).unwrap();
        s.refresh(&key(3, KeyState::Active), [8; 32]).unwrap();
        assert_eq!(s.generation(), 3);
        assert_eq!(s.context(), [8; 32]);
        assert_ne!(s.context(), [7; 32]);
    }
}
