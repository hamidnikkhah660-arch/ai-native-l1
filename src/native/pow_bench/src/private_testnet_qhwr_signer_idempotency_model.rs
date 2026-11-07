//! CP-0409 reference model: signer-side idempotency state transitions.
//!
//! This is an in-memory behavioral model only. It is NOT a production signer,
//! durable store, authenticated lookup service, HSM adapter, distributed
//! consensus mechanism, or proof of exactly-once signing across restarts.
//! Production requires atomic durable reservation, exact artifact retention,
//! full-identity binding, authenticated lookup, and rollback resistance.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SignerOperationKey(pub [u8; 32]);

/// Digest of the canonical, domain-separated full CP-0403/QHWR identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignerRequest {
    pub operation_key: SignerOperationKey,
    pub qhwr_identity_digest: [u8; 32],
    pub signer_key_id: String,
    pub signer_key_generation: u64,
    pub signing_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StableSignedArtifact {
    /// Exact opaque signature/artifact bytes; this model never rewrites them.
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignerOperationState {
    Reserved,
    OutcomeUnknown,
    Completed(StableSignedArtifact),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReserveOutcome {
    Acquired,
    AlreadyReserved,
    OutcomeUnknown,
    AlreadyCompleted(StableSignedArtifact),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignerModelError {
    IdentityConflict,
    NotReserved,
    ArtifactConflict,
    EmptyArtifact,
    PoisonedLock,
}

#[derive(Clone, Debug)]
struct Record {
    request: SignerRequest,
    state: SignerOperationState,
}

/// Shared process-local model. Mutex linearizes threads in this process only;
/// it does not provide multi-process/host coordination or crash durability.
#[derive(Clone, Default)]
pub struct InMemorySignerIdempotencyModel {
    records: Arc<Mutex<HashMap<SignerOperationKey, Record>>>,
}

impl InMemorySignerIdempotencyModel {
    /// Exactly one caller gets Acquired. Retries never obtain a second claim.
    pub fn reserve(&self, request: SignerRequest) -> Result<ReserveOutcome, SignerModelError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| SignerModelError::PoisonedLock)?;
        match records.get(&request.operation_key) {
            Some(record) if record.request != request => Err(SignerModelError::IdentityConflict),
            Some(record) => match &record.state {
                SignerOperationState::Reserved => Ok(ReserveOutcome::AlreadyReserved),
                SignerOperationState::OutcomeUnknown => Ok(ReserveOutcome::OutcomeUnknown),
                SignerOperationState::Completed(artifact) => {
                    Ok(ReserveOutcome::AlreadyCompleted(artifact.clone()))
                }
            },
            None => {
                records.insert(
                    request.operation_key,
                    Record {
                        request,
                        state: SignerOperationState::Reserved,
                    },
                );
                Ok(ReserveOutcome::Acquired)
            }
        }
    }

    /// Quarantine an ambiguous signer result (e.g. accepted request, lost RPC reply).
    /// This state cannot be reacquired; only an authoritative lookup may resolve it.
    pub fn mark_outcome_unknown(
        &self,
        request: &SignerRequest,
    ) -> Result<SignerOperationState, SignerModelError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| SignerModelError::PoisonedLock)?;
        let record = records
            .get_mut(&request.operation_key)
            .ok_or(SignerModelError::NotReserved)?;
        if record.request != *request {
            return Err(SignerModelError::IdentityConflict);
        }
        match &record.state {
            SignerOperationState::Reserved => {
                record.state = SignerOperationState::OutcomeUnknown;
                Ok(SignerOperationState::OutcomeUnknown)
            }
            SignerOperationState::OutcomeUnknown => Ok(SignerOperationState::OutcomeUnknown),
            SignerOperationState::Completed(artifact) => {
                Ok(SignerOperationState::Completed(artifact.clone()))
            }
        }
    }

    /// Store exact bytes obtained from an authoritative, authenticated signer lookup.
    /// Authentication/provenance is a caller obligation and is NOT proved by this model.
    pub fn complete_from_authoritative_result(
        &self,
        request: &SignerRequest,
        artifact: StableSignedArtifact,
    ) -> Result<SignerOperationState, SignerModelError> {
        if artifact.bytes.is_empty() {
            return Err(SignerModelError::EmptyArtifact);
        }
        let mut records = self
            .records
            .lock()
            .map_err(|_| SignerModelError::PoisonedLock)?;
        let record = records
            .get_mut(&request.operation_key)
            .ok_or(SignerModelError::NotReserved)?;
        if record.request != *request {
            return Err(SignerModelError::IdentityConflict);
        }
        match &record.state {
            SignerOperationState::Reserved | SignerOperationState::OutcomeUnknown => {
                record.state = SignerOperationState::Completed(artifact.clone());
                Ok(SignerOperationState::Completed(artifact))
            }
            SignerOperationState::Completed(existing) if existing == &artifact => {
                Ok(SignerOperationState::Completed(existing.clone()))
            }
            SignerOperationState::Completed(_) => Err(SignerModelError::ArtifactConflict),
        }
    }

    /// Read state while checking every pinned request field.
    pub fn lookup_result(
        &self,
        request: &SignerRequest,
    ) -> Result<Option<SignerOperationState>, SignerModelError> {
        let records = self
            .records
            .lock()
            .map_err(|_| SignerModelError::PoisonedLock)?;
        match records.get(&request.operation_key) {
            None => Ok(None),
            Some(record) if record.request != *request => Err(SignerModelError::IdentityConflict),
            Some(record) => Ok(Some(record.state.clone())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

    fn request() -> SignerRequest {
        SignerRequest {
            operation_key: SignerOperationKey([0x41; 32]),
            qhwr_identity_digest: [0x19; 32],
            signer_key_id: "qrun-test-key".into(),
            signer_key_generation: 7,
            signing_digest: [0xA5; 32],
        }
    }
    fn artifact(bytes: &[u8]) -> StableSignedArtifact {
        StableSignedArtifact {
            bytes: bytes.to_vec(),
        }
    }

    #[test]
    fn exact_retry_does_not_grant_a_second_signing_claim() {
        let model = InMemorySignerIdempotencyModel::default();
        let req = request();
        assert_eq!(model.reserve(req.clone()), Ok(ReserveOutcome::Acquired));
        assert_eq!(model.reserve(req), Ok(ReserveOutcome::AlreadyReserved));
    }

    #[test]
    fn all_signer_inputs_and_qhwr_identity_are_immutable() {
        let model = InMemorySignerIdempotencyModel::default();
        let req = request();
        model.reserve(req.clone()).unwrap();
        let mut changed = req.clone();
        changed.qhwr_identity_digest[0] ^= 1;
        assert_eq!(
            model.reserve(changed),
            Err(SignerModelError::IdentityConflict)
        );
        let mut changed = req.clone();
        changed.signer_key_id.push_str("-other");
        assert_eq!(
            model.reserve(changed),
            Err(SignerModelError::IdentityConflict)
        );
        let mut changed = req.clone();
        changed.signer_key_generation += 1;
        assert_eq!(
            model.reserve(changed),
            Err(SignerModelError::IdentityConflict)
        );
        let mut changed = req.clone();
        changed.signing_digest[0] ^= 1;
        assert_eq!(
            model.reserve(changed),
            Err(SignerModelError::IdentityConflict)
        );
    }

    #[test]
    fn lost_reply_is_quarantined_then_recovered_by_authoritative_result() {
        let model = InMemorySignerIdempotencyModel::default();
        let req = request();
        let stable = artifact(b"opaque-exact-signature-artifact");
        model.reserve(req.clone()).unwrap();
        assert_eq!(
            model.mark_outcome_unknown(&req),
            Ok(SignerOperationState::OutcomeUnknown)
        );
        assert_eq!(
            model.reserve(req.clone()),
            Ok(ReserveOutcome::OutcomeUnknown)
        );
        assert_eq!(
            model.complete_from_authoritative_result(&req, stable.clone()),
            Ok(SignerOperationState::Completed(stable.clone()))
        );
        assert_eq!(
            model.reserve(req),
            Ok(ReserveOutcome::AlreadyCompleted(stable))
        );
    }

    #[test]
    fn completed_artifact_is_immutable_and_exactly_replayed() {
        let model = InMemorySignerIdempotencyModel::default();
        let req = request();
        let stable = artifact(b"signature-A");
        model.reserve(req.clone()).unwrap();
        model
            .complete_from_authoritative_result(&req, stable.clone())
            .unwrap();
        assert_eq!(
            model.complete_from_authoritative_result(&req, stable.clone()),
            Ok(SignerOperationState::Completed(stable.clone()))
        );
        assert_eq!(
            model.complete_from_authoritative_result(&req, artifact(b"signature-B")),
            Err(SignerModelError::ArtifactConflict)
        );
        assert_eq!(
            model.lookup_result(&req),
            Ok(Some(SignerOperationState::Completed(stable)))
        );
    }

    #[test]
    fn distinct_operation_keys_are_independent() {
        let model = InMemorySignerIdempotencyModel::default();
        let first = request();
        let mut second = first.clone();
        second.operation_key = SignerOperationKey([0x42; 32]);
        second.qhwr_identity_digest = [0x20; 32];
        assert_eq!(model.reserve(first.clone()), Ok(ReserveOutcome::Acquired));
        assert_eq!(model.reserve(second.clone()), Ok(ReserveOutcome::Acquired));
        model
            .complete_from_authoritative_result(&first, artifact(b"sig-1"))
            .unwrap();
        assert_eq!(
            model.lookup_result(&second),
            Ok(Some(SignerOperationState::Reserved))
        );
    }

    #[test]
    fn concurrent_reserve_has_exactly_one_in_process_winner() {
        const THREADS: usize = 16;
        let model = InMemorySignerIdempotencyModel::default();
        let barrier = Arc::new(Barrier::new(THREADS));
        let workers: Vec<_> = (0..THREADS)
            .map(|_| {
                let model = model.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    model.reserve(request())
                })
            })
            .collect();
        let mut acquired = 0;
        let mut reserved = 0;
        for worker in workers {
            match worker.join().unwrap().unwrap() {
                ReserveOutcome::Acquired => acquired += 1,
                ReserveOutcome::AlreadyReserved => reserved += 1,
                other => panic!("unexpected result: {other:?}"),
            }
        }
        assert_eq!(acquired, 1);
        assert_eq!(reserved, THREADS - 1);
    }

    #[test]
    fn empty_artifact_is_rejected_and_ambiguous_state_stays_quarantined() {
        let model = InMemorySignerIdempotencyModel::default();
        let req = request();
        model.reserve(req.clone()).unwrap();
        assert_eq!(
            model.complete_from_authoritative_result(&req, artifact(b"")),
            Err(SignerModelError::EmptyArtifact)
        );
        model.mark_outcome_unknown(&req).unwrap();
        assert_eq!(
            model.reserve(req.clone()),
            Ok(ReserveOutcome::OutcomeUnknown)
        );
        assert_eq!(
            model.lookup_result(&req),
            Ok(Some(SignerOperationState::OutcomeUnknown))
        );
    }
}
