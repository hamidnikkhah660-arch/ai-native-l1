//! CP-0407 pure QHWR operation-recovery transition model.
//!
//! This module is an in-memory specification model for transition and identity tests only.
//! It is not a durable journal, replay authority, signer, or production dispatcher adapter.
//! In particular, cloning/restarting this model does not provide persistence or linearizability.

use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationPins {
    pub operation_key: [u8; 32],
    pub request_digest: [u8; 32],
    pub provider_id: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedPayload {
    /// Exact canonical provider snapshot bytes to be signed/replayed.
    pub snapshot_bytes: Vec<u8>,
    pub signer_key_id: [u8; 32],
    pub signer_key_generation: u64,
    pub signing_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletedPayload {
    /// Exact encoded response bytes; callers must replay these bytes, not re-encode.
    pub response_bytes: Vec<u8>,
    pub response_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OperationState {
    Absent,
    Reserved {
        pins: OperationPins,
    },
    Prepared {
        pins: OperationPins,
        payload: PreparedPayload,
    },
    Completed {
        pins: OperationPins,
        prepared: PreparedPayload,
        completed: CompletedPayload,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransitionError {
    IdentityConflict,
    InvalidTransition,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QhwrOperationRecoveryModel {
    state: OperationState,
}

impl Default for QhwrOperationRecoveryModel {
    fn default() -> Self {
        Self::new()
    }
}

impl QhwrOperationRecoveryModel {
    pub fn new() -> Self {
        Self {
            state: OperationState::Absent,
        }
    }

    pub fn state(&self) -> &OperationState {
        &self.state
    }

    /// Returns true only when the model advances Absent -> Reserved.
    /// An exact retry is accepted as an idempotent no-op; changed pins fail closed.
    pub fn reserve(&mut self, pins: OperationPins) -> Result<bool, TransitionError> {
        match &self.state {
            OperationState::Absent => {
                self.state = OperationState::Reserved { pins };
                Ok(true)
            }
            OperationState::Reserved { pins: existing }
            | OperationState::Prepared { pins: existing, .. }
            | OperationState::Completed { pins: existing, .. } => {
                if existing == &pins {
                    Ok(false)
                } else {
                    Err(TransitionError::IdentityConflict)
                }
            }
        }
    }

    /// Persists the immutable snapshot/signing pins in the model before signing.
    pub fn prepare(&mut self, payload: PreparedPayload) -> Result<bool, TransitionError> {
        match &self.state {
            OperationState::Reserved { pins } => {
                self.state = OperationState::Prepared {
                    pins: pins.clone(),
                    payload,
                };
                Ok(true)
            }
            OperationState::Prepared {
                payload: existing, ..
            } => {
                if existing == &payload {
                    Ok(false)
                } else {
                    Err(TransitionError::IdentityConflict)
                }
            }
            OperationState::Absent | OperationState::Completed { .. } => {
                Err(TransitionError::InvalidTransition)
            }
        }
    }

    /// Completes only from Prepared and verifies the digest of exact response bytes.
    pub fn complete(&mut self, response_bytes: Vec<u8>) -> Result<bool, TransitionError> {
        let response_digest: [u8; 32] = Sha256::digest(&response_bytes).into();
        let completed = CompletedPayload {
            response_bytes,
            response_digest,
        };
        match &self.state {
            OperationState::Prepared { pins, payload } => {
                self.state = OperationState::Completed {
                    pins: pins.clone(),
                    prepared: payload.clone(),
                    completed,
                };
                Ok(true)
            }
            OperationState::Completed {
                completed: existing,
                ..
            } => {
                if existing == &completed {
                    Ok(false)
                } else {
                    Err(TransitionError::IdentityConflict)
                }
            }
            OperationState::Absent | OperationState::Reserved { .. } => {
                Err(TransitionError::InvalidTransition)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pins() -> OperationPins {
        OperationPins {
            operation_key: [1; 32],
            request_digest: [2; 32],
            provider_id: [3; 32],
        }
    }

    fn prepared() -> PreparedPayload {
        PreparedPayload {
            snapshot_bytes: b"canonical-provider-snapshot-v1".to_vec(),
            signer_key_id: [4; 32],
            signer_key_generation: 7,
            signing_digest: [5; 32],
        }
    }

    #[test]
    fn reserve_is_idempotent_but_pins_are_immutable() {
        let mut model = QhwrOperationRecoveryModel::new();
        assert_eq!(model.reserve(pins()), Ok(true));
        assert_eq!(model.reserve(pins()), Ok(false));
        let mut changed = pins();
        changed.request_digest[0] ^= 1;
        assert_eq!(
            model.reserve(changed),
            Err(TransitionError::IdentityConflict)
        );
    }

    #[test]
    fn signer_preparation_requires_reserved_and_is_immutable() {
        let mut model = QhwrOperationRecoveryModel::new();
        assert_eq!(
            model.prepare(prepared()),
            Err(TransitionError::InvalidTransition)
        );
        model.reserve(pins()).unwrap();
        assert_eq!(model.prepare(prepared()), Ok(true));
        assert_eq!(model.prepare(prepared()), Ok(false));
        let mut changed = prepared();
        changed.signer_key_generation += 1;
        assert_eq!(
            model.prepare(changed),
            Err(TransitionError::IdentityConflict)
        );
    }

    #[test]
    fn completion_is_only_from_prepared_and_response_bytes_are_immutable() {
        let mut model = QhwrOperationRecoveryModel::new();
        model.reserve(pins()).unwrap();
        assert_eq!(
            model.complete(b"signed-response".to_vec()),
            Err(TransitionError::InvalidTransition)
        );
        model.prepare(prepared()).unwrap();
        assert_eq!(model.complete(b"signed-response".to_vec()), Ok(true));
        assert_eq!(model.complete(b"signed-response".to_vec()), Ok(false));
        assert_eq!(
            model.complete(b"different-response".to_vec()),
            Err(TransitionError::IdentityConflict)
        );
    }

    #[test]
    fn completed_state_retains_exact_response_and_digest() {
        let mut model = QhwrOperationRecoveryModel::new();
        model.reserve(pins()).unwrap();
        model.prepare(prepared()).unwrap();
        let bytes = b"byte-identical-response".to_vec();
        let expected: [u8; 32] = Sha256::digest(&bytes).into();
        model.complete(bytes.clone()).unwrap();
        match model.state() {
            OperationState::Completed { completed, .. } => {
                assert_eq!(completed.response_bytes, bytes);
                assert_eq!(completed.response_digest, expected);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    #[test]
    fn completed_cannot_regress_or_be_reprepared() {
        let mut model = QhwrOperationRecoveryModel::new();
        model.reserve(pins()).unwrap();
        model.prepare(prepared()).unwrap();
        model.complete(b"response".to_vec()).unwrap();
        assert_eq!(
            model.prepare(prepared()),
            Err(TransitionError::InvalidTransition)
        );
        assert_eq!(model.reserve(pins()), Ok(false));
    }
}
