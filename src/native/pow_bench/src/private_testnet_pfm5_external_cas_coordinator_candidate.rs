//! CP-0399 candidate: one ordered coordinator for a fresh PFM5/ECR1 transition.
//!
//! This layer is deliberately a candidate API. It enforces Ready -> durable Prepared ->
//! independent High-Water Prepared -> CP-0394 execution -> local Finalized -> independent
//! High-Water Finalized (the independent floor is committed before local finalization so that
//! a crash can be recovered using the exact Prepared-intent authorization path). It does not
//! provide a concrete independent High-Water or CAS adapter,
//! node-runtime wiring, or production deployment approval.

use crate::{
    external_cas_anchor_candidate::{
        ExternalCasPin, ExternalCasProviderTransport, VerifiedExternalCasClient,
    },
    private_testnet_checkpoint_candidate::Pcp4ValidationContext,
    private_testnet_pfm5_external_cas_candidate::{
        execute_intent, Pfm5ExternalCasIntent, Pfm5ExternalCasOutcome,
    },
    private_testnet_pfm5_external_cas_highwater_candidate::{
        advance_finalized_snapshot, advance_prepared_snapshot, verify_ready_snapshot,
        Pfm5ExternalCasHighWaterAdvance, Pfm5ExternalCasHighWaterAuthorityPin,
        Pfm5ExternalCasHighWaterError, Pfm5ExternalCasHighWaterProvider,
    },
    private_testnet_pfm5_external_cas_journal_candidate::{
        Pfm5ExternalCasJournalError, Pfm5ExternalCasJournalSnapshot, Pfm5ExternalCasJournalStore,
    },
    private_testnet_pfm5_immutable_object_candidate::{
        Pfm5ImmutableObjectBundle, Pfm5ImmutableObjectClient, Pfm5ImmutableObjectProviderTransport,
    },
    v4_fat1_trust_candidate::MlDsa65Verifier as CasMlDsa65Verifier,
};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pfm5ExternalCasCoordinatorError {
    Journal(Pfm5ExternalCasJournalError),
    HighWater(Pfm5ExternalCasHighWaterError),
    Execute(String),
    SequenceOverflow,
}
impl fmt::Display for Pfm5ExternalCasCoordinatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Pfm5ExternalCasCoordinatorError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pfm5ExternalCasCoordinatorOutcome {
    /// The exact intent remains durably Prepared. A later attempt must reuse it unchanged.
    RetrySameIntent {
        prepared: Pfm5ExternalCasJournalSnapshot,
    },
    /// Local and independent High-Water state both reached the exact finalized successor.
    Finalized {
        snapshot: Pfm5ExternalCasJournalSnapshot,
        highwater: Pfm5ExternalCasHighWaterAdvance,
    },
}

/// Execute one new intent only after proving the local Ready snapshot matches independent state.
///
/// The order is security-critical: if Ready verification, durable staging, or the independent
/// Prepared advance fails, CP-0394 is never called. A RetrySameIntent result leaves the exact
/// intent pending; callers must not construct a replacement intent.
pub fn execute_ready_intent<HP, OP, CP, V>(
    journal: &Pfm5ExternalCasJournalStore,
    highwater: &mut HP,
    authority: &Pfm5ExternalCasHighWaterAuthorityPin,
    pin: &ExternalCasPin,
    context: &Pcp4ValidationContext<'_>,
    intent: &Pfm5ExternalCasIntent,
    bundle: &Pfm5ImmutableObjectBundle,
    object_client: &mut Pfm5ImmutableObjectClient<OP>,
    cas_client: &mut VerifiedExternalCasClient<CP, V>,
    minimum_sequence: u64,
    minimum_record_generation: u64,
    minimum_object_generation: u64,
) -> Result<Pfm5ExternalCasCoordinatorOutcome, Pfm5ExternalCasCoordinatorError>
where
    HP: Pfm5ExternalCasHighWaterProvider,
    OP: Pfm5ImmutableObjectProviderTransport,
    CP: ExternalCasProviderTransport,
    V: CasMlDsa65Verifier,
{
    let ready = journal
        .load_checked(
            pin,
            minimum_sequence,
            minimum_record_generation,
            minimum_object_generation,
        )
        .map_err(Pfm5ExternalCasCoordinatorError::Journal)?;
    verify_ready_snapshot(highwater, authority, pin, &ready)
        .map_err(Pfm5ExternalCasCoordinatorError::HighWater)?;

    let prepared = journal
        .stage_intent(
            pin,
            intent,
            minimum_sequence,
            minimum_record_generation,
            minimum_object_generation,
        )
        .map_err(Pfm5ExternalCasCoordinatorError::Journal)?;
    advance_prepared_snapshot(highwater, authority, pin, &prepared)
        .map_err(Pfm5ExternalCasCoordinatorError::HighWater)?;

    let execution = execute_intent(object_client, cas_client, pin, context, intent, bundle)
        .map_err(|error| Pfm5ExternalCasCoordinatorError::Execute(error.to_string()))?;
    let committed_object_generation = match execution {
        Pfm5ExternalCasOutcome::RetrySameIntent { .. } => {
            return Ok(Pfm5ExternalCasCoordinatorOutcome::RetrySameIntent { prepared });
        }
        Pfm5ExternalCasOutcome::Committed { ref receipt, .. } => receipt.object_generation,
        Pfm5ExternalCasOutcome::AlreadyCommitted {
            object_generation, ..
        }
        | Pfm5ExternalCasOutcome::CommittedAfterAmbiguousReply {
            object_generation, ..
        } => object_generation,
    };

    // Commit the independent rollback-resistant floor first. If the process dies before the
    // local journal finalization, CP-0398 recovery can authorize only this exact one-step stale
    // Prepared intent from the authenticated finalized floor; it will not issue a second CAS.
    let finalization_candidate = Pfm5ExternalCasJournalSnapshot {
        sequence: prepared
            .sequence
            .checked_add(1)
            .ok_or(Pfm5ExternalCasCoordinatorError::SequenceOverflow)?,
        last_record: intent.write_request.next_record.clone(),
        object_generation: committed_object_generation,
        pending_intent: None,
    };
    let highwater_advance =
        advance_finalized_snapshot(highwater, authority, pin, intent, &finalization_candidate)
            .map_err(Pfm5ExternalCasCoordinatorError::HighWater)?;

    let finalized = journal
        .mark_committed(
            pin,
            intent,
            intent.write_request.next_record.clone(),
            committed_object_generation,
            prepared.sequence,
            minimum_record_generation,
            minimum_object_generation,
        )
        .map_err(Pfm5ExternalCasCoordinatorError::Journal)?;
    verify_ready_snapshot(highwater, authority, pin, &finalized)
        .map_err(Pfm5ExternalCasCoordinatorError::HighWater)?;

    Ok(Pfm5ExternalCasCoordinatorOutcome::Finalized {
        snapshot: finalized,
        highwater: highwater_advance,
    })
}
