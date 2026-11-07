//! CP-0396 contract and caller-side gates for an independent PFM5/ECR1 high-water authority.
//!
//! No local production adapter is provided. The authority must live outside the journal/node
//! rollback domain, authenticate reads against an out-of-band pinned identity, and perform a
//! linearizable atomic compare-and-advance. An adapter that does not satisfy those properties
//! is not a production implementation.
//!
//! Ordering: verify Ready floor; durably stage exact intent in PFJ1; advance independent sequence;
//! only then invoke CP-0394; durably finalize PFJ1 after verified commit; finally advance record
//! and object-generation floors. Ambiguous writes are classified by authenticated reread.

use crate::{
    external_cas_anchor_candidate::{ExternalCasPin, ExternalCasRecord},
    private_testnet_pfm5_external_cas_candidate::Pfm5ExternalCasIntent,
    private_testnet_pfm5_external_cas_journal_candidate::{
        Pfm5ExternalCasJournalRecoveryAuthorization, Pfm5ExternalCasJournalSnapshot,
    },
};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pfm5ExternalCasHighWaterAuthorityPin {
    /// Independently provisioned identity for the authority that stores monotonic state.
    pub authority_id: [u8; 32],
}
impl Pfm5ExternalCasHighWaterAuthorityPin {
    pub fn validate(&self) -> Result<(), Pfm5ExternalCasHighWaterError> {
        if self.authority_id == [0; 32] {
            return Err(Pfm5ExternalCasHighWaterError::InvalidAuthorityPin);
        }
        Ok(())
    }
}

/// Authenticated monotonic state retained outside the node/journal rollback domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pfm5ExternalCasHighWaterState {
    pub authority_id: [u8; 32],
    pub provider_id: [u8; 32],
    pub network_id: [u8; 32],
    pub genesis_digest: [u8; 32],
    pub journal_sequence: u64,
    pub record: ExternalCasRecord,
    pub object_generation: u64,
}
impl Pfm5ExternalCasHighWaterState {
    pub fn from_snapshot(
        authority: &Pfm5ExternalCasHighWaterAuthorityPin,
        pin: &ExternalCasPin,
        snapshot: &Pfm5ExternalCasJournalSnapshot,
    ) -> Result<Self, Pfm5ExternalCasHighWaterError> {
        let state = Self {
            authority_id: authority.authority_id,
            provider_id: pin.provider_id,
            network_id: pin.network_id,
            genesis_digest: pin.genesis_digest,
            journal_sequence: snapshot.sequence,
            record: snapshot.last_record.clone(),
            object_generation: snapshot.object_generation,
        };
        state.validate(authority, pin)?;
        Ok(state)
    }

    pub fn validate(
        &self,
        authority: &Pfm5ExternalCasHighWaterAuthorityPin,
        pin: &ExternalCasPin,
    ) -> Result<(), Pfm5ExternalCasHighWaterError> {
        authority.validate()?;
        if self.authority_id != authority.authority_id
            || self.provider_id != pin.provider_id
            || self.network_id != pin.network_id
            || self.genesis_digest != pin.genesis_digest
            || self.record.provider_id != pin.provider_id
            || self.record.network_id != pin.network_id
            || self.record.genesis_digest != pin.genesis_digest
        {
            return Err(Pfm5ExternalCasHighWaterError::IdentityMismatch);
        }
        if self.journal_sequence == 0 || self.object_generation == 0 {
            return Err(Pfm5ExternalCasHighWaterError::InvalidState);
        }
        self.record
            .digest()
            .map_err(|_| Pfm5ExternalCasHighWaterError::InvalidState)?;
        Ok(())
    }
}

/// Adapter security contract.
///
/// Implementations MUST authenticate every read against authority identity/trust material
/// pinned out of band; keep state outside the node/journal disk rollback domain; provide
/// linearizable atomic compare-and-advance across all writers/replicas; reject stale expected
/// states, decreases, skipped sequences, identity changes and non-successor records; and make a
/// successful update durable before returning. A second local file/directory/volume on the same
/// rollback domain does not qualify. Test doubles are not production adapters.
pub trait Pfm5ExternalCasHighWaterProvider {
    type Error: fmt::Display;

    fn read_authenticated(
        &mut self,
        authority: &Pfm5ExternalCasHighWaterAuthorityPin,
        pin: &ExternalCasPin,
    ) -> Result<Pfm5ExternalCasHighWaterState, Self::Error>;

    fn compare_and_advance(
        &mut self,
        authority: &Pfm5ExternalCasHighWaterAuthorityPin,
        pin: &ExternalCasPin,
        expected: &Pfm5ExternalCasHighWaterState,
        next: &Pfm5ExternalCasHighWaterState,
    ) -> Result<(), Self::Error>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pfm5ExternalCasHighWaterError {
    InvalidAuthorityPin,
    IdentityMismatch,
    InvalidState,
    ReadySnapshotRequired,
    PreparedSnapshotRequired,
    IntentMismatch,
    InvalidTransition,
    HighWaterUnavailable(String),
    HighWaterCompareFailed(String),
    HighWaterConflict,
    ReadbackMismatch,
}
impl fmt::Display for Pfm5ExternalCasHighWaterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Pfm5ExternalCasHighWaterError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pfm5ExternalCasHighWaterAdvance {
    Advanced,
    AlreadyAdvanced,
    AdvancedAfterAmbiguousReply,
}

/// Call before staging an intent. A Ready journal must exactly match the authenticated floor.
pub fn verify_ready_snapshot<P>(
    provider: &mut P,
    authority: &Pfm5ExternalCasHighWaterAuthorityPin,
    pin: &ExternalCasPin,
    snapshot: &Pfm5ExternalCasJournalSnapshot,
) -> Result<Pfm5ExternalCasHighWaterState, Pfm5ExternalCasHighWaterError>
where
    P: Pfm5ExternalCasHighWaterProvider,
{
    if snapshot.is_prepared() {
        return Err(Pfm5ExternalCasHighWaterError::ReadySnapshotRequired);
    }
    let expected = Pfm5ExternalCasHighWaterState::from_snapshot(authority, pin, snapshot)?;
    let observed = read_checked(provider, authority, pin)?;
    if observed != expected {
        return Err(Pfm5ExternalCasHighWaterError::HighWaterConflict);
    }
    Ok(observed)
}

/// Call after PFJ1 has durably staged the exact intent and before any CP-0394 side effect.
pub fn advance_prepared_snapshot<P>(
    provider: &mut P,
    authority: &Pfm5ExternalCasHighWaterAuthorityPin,
    pin: &ExternalCasPin,
    snapshot: &Pfm5ExternalCasJournalSnapshot,
) -> Result<Pfm5ExternalCasHighWaterAdvance, Pfm5ExternalCasHighWaterError>
where
    P: Pfm5ExternalCasHighWaterProvider,
{
    let intent = snapshot
        .pending_intent
        .as_ref()
        .ok_or(Pfm5ExternalCasHighWaterError::PreparedSnapshotRequired)?;
    if snapshot.sequence <= 1
        || snapshot.last_record != intent.expected_current
        || snapshot.object_generation != intent.expected_object_generation
    {
        return Err(Pfm5ExternalCasHighWaterError::IntentMismatch);
    }
    let next = Pfm5ExternalCasHighWaterState::from_snapshot(authority, pin, snapshot)?;
    let mut expected = next.clone();
    expected.journal_sequence = snapshot.sequence - 1;
    advance_exact(
        provider,
        authority,
        pin,
        &expected,
        &next,
        Transition::Prepared,
    )
}

/// Call after PFJ1 is durably finalized with the verified ECR1 successor.
pub fn advance_finalized_snapshot<P>(
    provider: &mut P,
    authority: &Pfm5ExternalCasHighWaterAuthorityPin,
    pin: &ExternalCasPin,
    intent: &Pfm5ExternalCasIntent,
    snapshot: &Pfm5ExternalCasJournalSnapshot,
) -> Result<Pfm5ExternalCasHighWaterAdvance, Pfm5ExternalCasHighWaterError>
where
    P: Pfm5ExternalCasHighWaterProvider,
{
    if snapshot.is_prepared()
        || snapshot.sequence < 3
        || snapshot.last_record != intent.write_request.next_record
        || snapshot.object_generation <= intent.expected_object_generation
    {
        return Err(Pfm5ExternalCasHighWaterError::IntentMismatch);
    }
    intent
        .validate(pin)
        .map_err(|_| Pfm5ExternalCasHighWaterError::IntentMismatch)?;
    let next = Pfm5ExternalCasHighWaterState::from_snapshot(authority, pin, snapshot)?;
    let expected = Pfm5ExternalCasHighWaterState {
        authority_id: authority.authority_id,
        provider_id: pin.provider_id,
        network_id: pin.network_id,
        genesis_digest: pin.genesis_digest,
        journal_sequence: snapshot.sequence - 1,
        record: intent.expected_current.clone(),
        object_generation: intent.expected_object_generation,
    };
    expected.validate(authority, pin)?;
    advance_exact(
        provider,
        authority,
        pin,
        &expected,
        &next,
        Transition::Finalized,
    )
}

/// Detect disk rollback where PFJ1 is still Prepared but the independent floor already records
/// the exact finalized successor. This is valid commit evidence only if the caller advances the
/// floor after a verified CP-0394 outcome, never before.
pub fn observe_finalized_floor_for_prepared_intent<P>(
    provider: &mut P,
    authority: &Pfm5ExternalCasHighWaterAuthorityPin,
    pin: &ExternalCasPin,
    prepared: &Pfm5ExternalCasJournalSnapshot,
) -> Result<Pfm5ExternalCasHighWaterState, Pfm5ExternalCasHighWaterError>
where
    P: Pfm5ExternalCasHighWaterProvider,
{
    let intent = prepared
        .pending_intent
        .as_ref()
        .ok_or(Pfm5ExternalCasHighWaterError::PreparedSnapshotRequired)?;
    if prepared.sequence <= 1
        || prepared.last_record != intent.expected_current
        || prepared.object_generation != intent.expected_object_generation
    {
        return Err(Pfm5ExternalCasHighWaterError::IntentMismatch);
    }
    intent
        .validate(pin)
        .map_err(|_| Pfm5ExternalCasHighWaterError::IntentMismatch)?;
    let expected_sequence = prepared
        .sequence
        .checked_add(1)
        .ok_or(Pfm5ExternalCasHighWaterError::InvalidTransition)?;
    let observed = read_checked(provider, authority, pin)?;
    if observed.journal_sequence != expected_sequence
        || observed.record != intent.write_request.next_record
        || observed.object_generation <= intent.expected_object_generation
    {
        return Err(Pfm5ExternalCasHighWaterError::HighWaterConflict);
    }
    Ok(observed)
}

/// Authorize the journal's narrowly scoped one-step recovery read. This performs a fresh
/// authenticated High-Water read and binds the resulting authorization to the exact Prepared
/// intent's finalized successor, domain, sequence, and advanced object generation.
pub fn authorize_prepared_journal_recovery<P>(
    provider: &mut P,
    authority: &Pfm5ExternalCasHighWaterAuthorityPin,
    pin: &ExternalCasPin,
    prepared: &Pfm5ExternalCasJournalSnapshot,
) -> Result<Pfm5ExternalCasJournalRecoveryAuthorization, Pfm5ExternalCasHighWaterError>
where
    P: Pfm5ExternalCasHighWaterProvider,
{
    let intent = prepared
        .pending_intent
        .as_ref()
        .ok_or(Pfm5ExternalCasHighWaterError::PreparedSnapshotRequired)?;
    if prepared.sequence <= 1
        || prepared.last_record != intent.expected_current
        || prepared.object_generation != intent.expected_object_generation
    {
        return Err(Pfm5ExternalCasHighWaterError::IntentMismatch);
    }
    intent
        .validate(pin)
        .map_err(|_| Pfm5ExternalCasHighWaterError::IntentMismatch)?;
    let expected_sequence = prepared
        .sequence
        .checked_add(1)
        .ok_or(Pfm5ExternalCasHighWaterError::InvalidTransition)?;
    let observed = read_checked(provider, authority, pin)?;
    if observed.journal_sequence != expected_sequence
        || observed.record != intent.write_request.next_record
        || observed.object_generation <= intent.expected_object_generation
    {
        return Err(Pfm5ExternalCasHighWaterError::HighWaterConflict);
    }
    Ok(
        Pfm5ExternalCasJournalRecoveryAuthorization::from_authenticated_finalized_floor(
            observed.authority_id,
            pin,
            observed.journal_sequence,
            observed.record,
            observed.object_generation,
            intent,
        )
        .map_err(|_| Pfm5ExternalCasHighWaterError::HighWaterConflict)?,
    )
}

#[derive(Debug, Clone, Copy)]
enum Transition {
    Prepared,
    Finalized,
}

fn advance_exact<P>(
    provider: &mut P,
    authority: &Pfm5ExternalCasHighWaterAuthorityPin,
    pin: &ExternalCasPin,
    expected: &Pfm5ExternalCasHighWaterState,
    next: &Pfm5ExternalCasHighWaterState,
    transition: Transition,
) -> Result<Pfm5ExternalCasHighWaterAdvance, Pfm5ExternalCasHighWaterError>
where
    P: Pfm5ExternalCasHighWaterProvider,
{
    expected.validate(authority, pin)?;
    next.validate(authority, pin)?;
    validate_transition(expected, next, transition)?;

    let current = read_checked(provider, authority, pin)?;
    if current == *next {
        return Ok(Pfm5ExternalCasHighWaterAdvance::AlreadyAdvanced);
    }
    if current != *expected {
        return Err(Pfm5ExternalCasHighWaterError::HighWaterConflict);
    }

    let write_result = provider.compare_and_advance(authority, pin, expected, next);
    // Always reread after CAS: a timeout can occur after the remote authority committed.
    let observed = read_checked(provider, authority, pin)?;
    if observed == *next {
        return Ok(match write_result {
            Ok(()) => Pfm5ExternalCasHighWaterAdvance::Advanced,
            Err(_) => Pfm5ExternalCasHighWaterAdvance::AdvancedAfterAmbiguousReply,
        });
    }
    if observed != *expected {
        return Err(Pfm5ExternalCasHighWaterError::HighWaterConflict);
    }
    match write_result {
        Err(error) => Err(Pfm5ExternalCasHighWaterError::HighWaterCompareFailed(
            error.to_string(),
        )),
        Ok(()) => Err(Pfm5ExternalCasHighWaterError::ReadbackMismatch),
    }
}

fn validate_transition(
    expected: &Pfm5ExternalCasHighWaterState,
    next: &Pfm5ExternalCasHighWaterState,
    transition: Transition,
) -> Result<(), Pfm5ExternalCasHighWaterError> {
    if expected.authority_id != next.authority_id
        || expected.provider_id != next.provider_id
        || expected.network_id != next.network_id
        || expected.genesis_digest != next.genesis_digest
        || expected.journal_sequence.checked_add(1) != Some(next.journal_sequence)
    {
        return Err(Pfm5ExternalCasHighWaterError::InvalidTransition);
    }
    match transition {
        Transition::Prepared => {
            if expected.record != next.record
                || expected.object_generation != next.object_generation
            {
                return Err(Pfm5ExternalCasHighWaterError::InvalidTransition);
            }
        }
        Transition::Finalized => {
            if next.object_generation <= expected.object_generation
                || expected.record.validate_successor(&next.record).is_err()
            {
                return Err(Pfm5ExternalCasHighWaterError::InvalidTransition);
            }
        }
    }
    Ok(())
}

fn read_checked<P>(
    provider: &mut P,
    authority: &Pfm5ExternalCasHighWaterAuthorityPin,
    pin: &ExternalCasPin,
) -> Result<Pfm5ExternalCasHighWaterState, Pfm5ExternalCasHighWaterError>
where
    P: Pfm5ExternalCasHighWaterProvider,
{
    authority.validate()?;
    let observed = provider
        .read_authenticated(authority, pin)
        .map_err(|error| Pfm5ExternalCasHighWaterError::HighWaterUnavailable(error.to_string()))?;
    observed.validate(authority, pin)?;
    Ok(observed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        external_cas_anchor_candidate::ExternalCasWriteRequest,
        private_testnet_pfm5_external_cas_journal_candidate::Pfm5ExternalCasJournalStore,
        v4_fat1_trust_candidate::ML_DSA_65_PUBLIC_KEY_BYTES,
    };

    struct MemoryAuthority {
        state: Pfm5ExternalCasHighWaterState,
        lose_reply_after_commit: bool,
        fail_without_commit: bool,
        reads: usize,
        writes: usize,
        fail_read_on_call: Option<usize>,
        compete_before_compare: bool,
        succeed_without_commit: bool,
    }
    impl Pfm5ExternalCasHighWaterProvider for MemoryAuthority {
        type Error = &'static str;
        fn read_authenticated(
            &mut self,
            _authority: &Pfm5ExternalCasHighWaterAuthorityPin,
            _pin: &ExternalCasPin,
        ) -> Result<Pfm5ExternalCasHighWaterState, Self::Error> {
            self.reads += 1;
            if self.fail_read_on_call == Some(self.reads) {
                return Err("read unavailable");
            }
            Ok(self.state.clone())
        }
        fn compare_and_advance(
            &mut self,
            _authority: &Pfm5ExternalCasHighWaterAuthorityPin,
            _pin: &ExternalCasPin,
            expected: &Pfm5ExternalCasHighWaterState,
            next: &Pfm5ExternalCasHighWaterState,
        ) -> Result<(), Self::Error> {
            self.writes += 1;
            if self.compete_before_compare {
                self.compete_before_compare = false;
                self.state.journal_sequence += 1;
                self.state.record.operation_id = [0x9A; 32];
                self.state.object_generation += 1;
                return Err("concurrent writer advanced floor");
            }
            if self.state != *expected {
                return Err("compare conflict");
            }
            if self.fail_without_commit {
                return Err("unavailable before commit");
            }
            if self.succeed_without_commit {
                return Ok(());
            }
            self.state = next.clone();
            if self.lose_reply_after_commit {
                return Err("reply lost after commit");
            }
            Ok(())
        }
    }

    struct Fixture {
        authority_pin: Pfm5ExternalCasHighWaterAuthorityPin,
        cas_pin: ExternalCasPin,
        ready: Pfm5ExternalCasJournalSnapshot,
        prepared: Pfm5ExternalCasJournalSnapshot,
        finalized: Pfm5ExternalCasJournalSnapshot,
        intent: Pfm5ExternalCasIntent,
        provider: MemoryAuthority,
    }

    fn fixture() -> Fixture {
        let authority_pin = Pfm5ExternalCasHighWaterAuthorityPin {
            authority_id: [0xA1; 32],
        };
        let cas_pin = ExternalCasPin {
            provider_id: [0x11; 32],
            network_id: [0x22; 32],
            genesis_digest: [0x33; 32],
            receipt_key_id: [0x44; 32],
            receipt_public_key: [0x55; ML_DSA_65_PUBLIC_KEY_BYTES],
        };
        let current = ExternalCasRecord {
            generation: 7,
            provider_id: cas_pin.provider_id,
            network_id: cas_pin.network_id,
            genesis_digest: cas_pin.genesis_digest,
            previous_record_digest: [0x61; 32],
            previous_state_digest: [0x62; 32],
            next_state_digest: [0x63; 32],
            operation_id: [0x64; 32],
            request_digest: [0x65; 32],
        };
        let operation_id = [0x72; 32];
        let mut write_request = ExternalCasWriteRequest {
            request_nonce: [0x71; 32],
            operation_id,
            request_digest: [0; 32],
            expected_generation: current.generation,
            expected_object_generation: 40,
            expected_record_digest: current.digest().unwrap(),
            expected_state_digest: current.next_state_digest,
            next_record: ExternalCasRecord {
                generation: current.generation + 1,
                provider_id: cas_pin.provider_id,
                network_id: cas_pin.network_id,
                genesis_digest: cas_pin.genesis_digest,
                previous_record_digest: current.digest().unwrap(),
                previous_state_digest: current.next_state_digest,
                next_state_digest: [0x73; 32],
                operation_id,
                request_digest: [0; 32],
            },
        };
        write_request.bind_request_digest(&cas_pin).unwrap();
        let intent = Pfm5ExternalCasIntent {
            expected_current: current.clone(),
            expected_object_generation: 40,
            write_request,
        };
        intent.validate(&cas_pin).unwrap();
        let ready = Pfm5ExternalCasJournalSnapshot {
            sequence: 9,
            last_record: current.clone(),
            object_generation: 40,
            pending_intent: None,
        };
        let prepared = Pfm5ExternalCasJournalSnapshot {
            sequence: 10,
            last_record: current.clone(),
            object_generation: 40,
            pending_intent: Some(intent.clone()),
        };
        let finalized = Pfm5ExternalCasJournalSnapshot {
            sequence: 11,
            last_record: intent.write_request.next_record.clone(),
            object_generation: 41,
            pending_intent: None,
        };
        let initial =
            Pfm5ExternalCasHighWaterState::from_snapshot(&authority_pin, &cas_pin, &ready).unwrap();
        Fixture {
            authority_pin,
            cas_pin,
            ready,
            prepared,
            finalized,
            intent,
            provider: MemoryAuthority {
                state: initial,
                lose_reply_after_commit: false,
                fail_without_commit: false,
                reads: 0,
                writes: 0,
                fail_read_on_call: None,
                compete_before_compare: false,
                succeed_without_commit: false,
            },
        }
    }

    #[test]
    fn ready_snapshot_must_match_authenticated_floor_exactly() {
        let mut f = fixture();
        assert_eq!(
            verify_ready_snapshot(&mut f.provider, &f.authority_pin, &f.cas_pin, &f.ready).unwrap(),
            f.provider.state
        );
        let mut stale = f.ready.clone();
        stale.object_generation -= 1;
        assert_eq!(
            verify_ready_snapshot(&mut f.provider, &f.authority_pin, &f.cas_pin, &stale),
            Err(Pfm5ExternalCasHighWaterError::HighWaterConflict)
        );
        assert_eq!(
            advance_prepared_snapshot(&mut f.provider, &f.authority_pin, &f.cas_pin, &f.ready),
            Err(Pfm5ExternalCasHighWaterError::PreparedSnapshotRequired)
        );
    }

    #[test]
    fn prepared_floor_advances_exactly_once_and_is_idempotent() {
        let mut f = fixture();
        assert_eq!(
            advance_prepared_snapshot(&mut f.provider, &f.authority_pin, &f.cas_pin, &f.prepared)
                .unwrap(),
            Pfm5ExternalCasHighWaterAdvance::Advanced
        );
        assert_eq!(f.provider.state.journal_sequence, f.prepared.sequence);
        assert_eq!(f.provider.state.record, f.ready.last_record);
        assert_eq!(
            f.provider.state.object_generation,
            f.ready.object_generation
        );
        assert_eq!(
            advance_prepared_snapshot(&mut f.provider, &f.authority_pin, &f.cas_pin, &f.prepared)
                .unwrap(),
            Pfm5ExternalCasHighWaterAdvance::AlreadyAdvanced
        );
        assert_eq!(f.provider.writes, 1);
    }

    #[test]
    fn stale_or_competing_floor_fails_closed_without_overwrite() {
        let mut f = fixture();
        f.provider.state.journal_sequence += 1;
        f.provider.state.record.operation_id = [0x99; 32];
        let changed = f.provider.state.clone();
        assert_eq!(
            advance_prepared_snapshot(&mut f.provider, &f.authority_pin, &f.cas_pin, &f.prepared),
            Err(Pfm5ExternalCasHighWaterError::HighWaterConflict)
        );
        assert_eq!(f.provider.state, changed);
        assert_eq!(f.provider.writes, 0);
    }

    #[test]
    fn lost_reply_after_atomic_advance_is_resolved_by_authenticated_reread() {
        let mut f = fixture();
        f.provider.lose_reply_after_commit = true;
        assert_eq!(
            advance_prepared_snapshot(&mut f.provider, &f.authority_pin, &f.cas_pin, &f.prepared)
                .unwrap(),
            Pfm5ExternalCasHighWaterAdvance::AdvancedAfterAmbiguousReply
        );
        assert_eq!(f.provider.state.journal_sequence, f.prepared.sequence);
    }

    #[test]
    fn failed_compare_with_unchanged_floor_blocks_remote_authorization() {
        let mut f = fixture();
        f.provider.fail_without_commit = true;
        assert_eq!(
            advance_prepared_snapshot(&mut f.provider, &f.authority_pin, &f.cas_pin, &f.prepared),
            Err(Pfm5ExternalCasHighWaterError::HighWaterCompareFailed(
                "unavailable before commit".to_owned()
            ))
        );
        assert_eq!(f.provider.state.journal_sequence, f.ready.sequence);
    }

    #[test]
    fn finalized_floor_advances_record_and_object_generation_after_journal() {
        let mut f = fixture();
        advance_prepared_snapshot(&mut f.provider, &f.authority_pin, &f.cas_pin, &f.prepared)
            .unwrap();
        assert_eq!(
            advance_finalized_snapshot(
                &mut f.provider,
                &f.authority_pin,
                &f.cas_pin,
                &f.intent,
                &f.finalized
            )
            .unwrap(),
            Pfm5ExternalCasHighWaterAdvance::Advanced
        );
        assert_eq!(f.provider.state.journal_sequence, f.finalized.sequence);
        assert_eq!(f.provider.state.record, f.finalized.last_record);
        assert_eq!(
            f.provider.state.object_generation,
            f.finalized.object_generation
        );
        assert_eq!(
            advance_finalized_snapshot(
                &mut f.provider,
                &f.authority_pin,
                &f.cas_pin,
                &f.intent,
                &f.finalized
            )
            .unwrap(),
            Pfm5ExternalCasHighWaterAdvance::AlreadyAdvanced
        );
    }

    #[test]
    fn recovery_authorization_is_issued_only_from_exact_authenticated_finalized_floor() {
        let mut f = fixture();
        f.provider.state = Pfm5ExternalCasHighWaterState::from_snapshot(
            &f.authority_pin,
            &f.cas_pin,
            &f.finalized,
        )
        .unwrap();
        let _authorization = authorize_prepared_journal_recovery(
            &mut f.provider,
            &f.authority_pin,
            &f.cas_pin,
            &f.prepared,
        )
        .unwrap();
        assert_eq!(f.provider.reads, 1);
        assert_eq!(f.provider.writes, 0);

        let reads_before = f.provider.reads;
        let writes_before = f.provider.writes;
        let mut wrong_intent = f.prepared.clone();
        wrong_intent
            .pending_intent
            .as_mut()
            .unwrap()
            .write_request
            .request_nonce = [0xFE; 32];
        assert_eq!(
            authorize_prepared_journal_recovery(
                &mut f.provider,
                &f.authority_pin,
                &f.cas_pin,
                &wrong_intent,
            ),
            Err(Pfm5ExternalCasHighWaterError::IntentMismatch)
        );
        assert_eq!(f.provider.reads, reads_before);
        assert_eq!(f.provider.writes, writes_before);
    }

    #[test]
    fn authenticated_highwater_authorizes_reopened_disk_rollback_without_weakening_normal_load() {
        use std::{
            fs,
            sync::atomic::{AtomicU64, Ordering},
        };
        static NEXT_DIR: AtomicU64 = AtomicU64::new(1);

        let mut f = fixture();
        let dir = std::env::temp_dir().join(format!(
            "ain1-pfm5-recovery-integration-{}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("intent.pfj1");
        let journal = Pfm5ExternalCasJournalStore::new(&path);

        let initialized = journal
            .initialize(
                &f.cas_pin,
                f.ready.last_record.clone(),
                f.ready.object_generation,
            )
            .unwrap();
        assert_eq!(initialized.sequence, 1);
        let prepared = journal
            .stage_intent(&f.cas_pin, &f.intent, 1, 0, f.ready.object_generation)
            .unwrap();
        assert_eq!(prepared.sequence, 2);

        // Simulate the crash window: the independent authority durably reached the exact
        // finalized successor, while the reopened local PFJ1 file still contains Prepared N.
        let finalized = Pfm5ExternalCasJournalSnapshot {
            sequence: 3,
            last_record: f.intent.write_request.next_record.clone(),
            object_generation: 41,
            pending_intent: None,
        };
        f.provider.state =
            Pfm5ExternalCasHighWaterState::from_snapshot(&f.authority_pin, &f.cas_pin, &finalized)
                .unwrap();

        let reopened = Pfm5ExternalCasJournalStore::new(&path);
        assert!(matches!(
            reopened.load_checked(&f.cas_pin, 3, 0, 40),
            Err(crate::private_testnet_pfm5_external_cas_journal_candidate::Pfm5ExternalCasJournalError::SequenceRollback {
                observed: 2,
                minimum: 3,
            })
        ));

        // The authorization is derived from the provider's authenticated read, not from a
        // caller-constructed journal proof. Reopen accepts only the exact one-step rollback.
        let authorization = authorize_prepared_journal_recovery(
            &mut f.provider,
            &f.authority_pin,
            &f.cas_pin,
            &prepared,
        )
        .unwrap();
        let recovered = reopened
            .load_prepared_for_recovery(&f.cas_pin, f.authority_pin.authority_id, &authorization)
            .unwrap();
        assert_eq!(recovered.sequence, 2);
        assert_eq!(recovered.pending_intent, Some(f.intent.clone()));
        assert_eq!(f.provider.reads, 1);
        assert_eq!(f.provider.writes, 0);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn finalized_floor_can_reconcile_a_rolled_back_prepared_journal() {
        let mut f = fixture();
        f.provider.state = Pfm5ExternalCasHighWaterState::from_snapshot(
            &f.authority_pin,
            &f.cas_pin,
            &f.finalized,
        )
        .unwrap();
        assert_eq!(
            observe_finalized_floor_for_prepared_intent(
                &mut f.provider,
                &f.authority_pin,
                &f.cas_pin,
                &f.prepared
            )
            .unwrap(),
            f.provider.state
        );
    }

    #[test]
    fn prepared_recovery_rejects_mismatched_predecessor_generation_and_sequence() {
        let mut f = fixture();
        f.provider.state = Pfm5ExternalCasHighWaterState::from_snapshot(
            &f.authority_pin,
            &f.cas_pin,
            &f.finalized,
        )
        .unwrap();

        let mut wrong_predecessor = f.prepared.clone();
        wrong_predecessor.last_record.operation_id = [0x99; 32];
        assert_eq!(
            observe_finalized_floor_for_prepared_intent(
                &mut f.provider,
                &f.authority_pin,
                &f.cas_pin,
                &wrong_predecessor
            ),
            Err(Pfm5ExternalCasHighWaterError::IntentMismatch)
        );

        let mut wrong_generation = f.prepared.clone();
        wrong_generation.object_generation += 1;
        assert_eq!(
            observe_finalized_floor_for_prepared_intent(
                &mut f.provider,
                &f.authority_pin,
                &f.cas_pin,
                &wrong_generation
            ),
            Err(Pfm5ExternalCasHighWaterError::IntentMismatch)
        );

        let mut invalid_sequence = f.prepared.clone();
        invalid_sequence.sequence = 1;
        assert_eq!(
            observe_finalized_floor_for_prepared_intent(
                &mut f.provider,
                &f.authority_pin,
                &f.cas_pin,
                &invalid_sequence
            ),
            Err(Pfm5ExternalCasHighWaterError::IntentMismatch)
        );
        assert_eq!(f.provider.reads, 0);
        assert_eq!(f.provider.writes, 0);
    }

    #[test]
    fn prepared_recovery_rejects_mismatched_finalized_floor_components() {
        let mut wrong_sequence = fixture();
        wrong_sequence.provider.state = Pfm5ExternalCasHighWaterState::from_snapshot(
            &wrong_sequence.authority_pin,
            &wrong_sequence.cas_pin,
            &wrong_sequence.finalized,
        )
        .unwrap();
        wrong_sequence.provider.state.journal_sequence += 1;
        assert_eq!(
            observe_finalized_floor_for_prepared_intent(
                &mut wrong_sequence.provider,
                &wrong_sequence.authority_pin,
                &wrong_sequence.cas_pin,
                &wrong_sequence.prepared,
            ),
            Err(Pfm5ExternalCasHighWaterError::HighWaterConflict)
        );
        assert_eq!(wrong_sequence.provider.reads, 1);
        assert_eq!(wrong_sequence.provider.writes, 0);

        let mut wrong_record = fixture();
        wrong_record.provider.state = Pfm5ExternalCasHighWaterState::from_snapshot(
            &wrong_record.authority_pin,
            &wrong_record.cas_pin,
            &wrong_record.finalized,
        )
        .unwrap();
        wrong_record.provider.state.record.operation_id = [0xAB; 32];
        assert_eq!(
            observe_finalized_floor_for_prepared_intent(
                &mut wrong_record.provider,
                &wrong_record.authority_pin,
                &wrong_record.cas_pin,
                &wrong_record.prepared,
            ),
            Err(Pfm5ExternalCasHighWaterError::HighWaterConflict)
        );
        assert_eq!(wrong_record.provider.reads, 1);
        assert_eq!(wrong_record.provider.writes, 0);

        let mut stale_generation = fixture();
        stale_generation.provider.state = Pfm5ExternalCasHighWaterState::from_snapshot(
            &stale_generation.authority_pin,
            &stale_generation.cas_pin,
            &stale_generation.finalized,
        )
        .unwrap();
        stale_generation.provider.state.object_generation =
            stale_generation.intent.expected_object_generation;
        assert_eq!(
            observe_finalized_floor_for_prepared_intent(
                &mut stale_generation.provider,
                &stale_generation.authority_pin,
                &stale_generation.cas_pin,
                &stale_generation.prepared,
            ),
            Err(Pfm5ExternalCasHighWaterError::HighWaterConflict)
        );
        assert_eq!(stale_generation.provider.reads, 1);
        assert_eq!(stale_generation.provider.writes, 0);
    }

    #[test]
    fn prepared_recovery_validates_the_exact_intent_before_observing_floor() {
        let mut f = fixture();
        f.provider.state = Pfm5ExternalCasHighWaterState::from_snapshot(
            &f.authority_pin,
            &f.cas_pin,
            &f.finalized,
        )
        .unwrap();

        let mut malformed = f.prepared.clone();
        malformed
            .pending_intent
            .as_mut()
            .unwrap()
            .write_request
            .next_record
            .next_state_digest = [0xA9; 32];
        assert_eq!(
            observe_finalized_floor_for_prepared_intent(
                &mut f.provider,
                &f.authority_pin,
                &f.cas_pin,
                &malformed
            ),
            Err(Pfm5ExternalCasHighWaterError::IntentMismatch)
        );
        assert_eq!(f.provider.reads, 0);
        assert_eq!(f.provider.writes, 0);
    }

    #[test]
    fn wrong_authority_or_cas_domain_is_rejected() {
        let mut f = fixture();
        let wrong_authority = Pfm5ExternalCasHighWaterAuthorityPin {
            authority_id: [0xB2; 32],
        };
        assert_eq!(
            verify_ready_snapshot(&mut f.provider, &wrong_authority, &f.cas_pin, &f.ready),
            Err(Pfm5ExternalCasHighWaterError::IdentityMismatch)
        );
        let mut wrong_snapshot = f.ready.clone();
        wrong_snapshot.last_record.network_id = [0xBA; 32];
        assert_eq!(
            Pfm5ExternalCasHighWaterState::from_snapshot(
                &f.authority_pin,
                &f.cas_pin,
                &wrong_snapshot
            ),
            Err(Pfm5ExternalCasHighWaterError::IdentityMismatch)
        );
    }

    #[test]
    fn missing_prepared_intent_is_rejected_before_authority_read() {
        let mut f = fixture();
        assert_eq!(
            observe_finalized_floor_for_prepared_intent(
                &mut f.provider,
                &f.authority_pin,
                &f.cas_pin,
                &f.ready
            ),
            Err(Pfm5ExternalCasHighWaterError::PreparedSnapshotRequired)
        );
        assert_eq!(f.provider.reads, 0);
        assert_eq!(f.provider.writes, 0);
    }

    #[test]
    fn concurrent_floor_advance_between_read_and_cas_fails_closed() {
        let mut f = fixture();
        f.provider.compete_before_compare = true;
        assert_eq!(
            advance_prepared_snapshot(&mut f.provider, &f.authority_pin, &f.cas_pin, &f.prepared),
            Err(Pfm5ExternalCasHighWaterError::HighWaterConflict)
        );
        assert_eq!(f.provider.reads, 2);
        assert_eq!(f.provider.writes, 1);
        assert_ne!(f.provider.state.journal_sequence, f.ready.sequence);
    }

    #[test]
    fn successful_cas_without_durable_readback_is_rejected() {
        let mut f = fixture();
        f.provider.succeed_without_commit = true;
        assert_eq!(
            advance_prepared_snapshot(&mut f.provider, &f.authority_pin, &f.cas_pin, &f.prepared),
            Err(Pfm5ExternalCasHighWaterError::ReadbackMismatch)
        );
        assert_eq!(f.provider.state.journal_sequence, f.ready.sequence);
        assert_eq!(f.provider.reads, 2);
        assert_eq!(f.provider.writes, 1);
    }

    #[test]
    fn unavailable_readback_after_commit_does_not_claim_success() {
        let mut f = fixture();
        f.provider.fail_read_on_call = Some(2);
        assert_eq!(
            advance_prepared_snapshot(&mut f.provider, &f.authority_pin, &f.cas_pin, &f.prepared),
            Err(Pfm5ExternalCasHighWaterError::HighWaterUnavailable(
                "read unavailable".to_owned()
            ))
        );
        assert_eq!(f.provider.state.journal_sequence, f.prepared.sequence);
        assert_eq!(f.provider.reads, 2);
        assert_eq!(f.provider.writes, 1);
    }

    #[test]
    fn malformed_prepared_transition_is_rejected_before_write() {
        let mut f = fixture();
        let mut malformed = f.prepared.clone();
        malformed.last_record.next_state_digest = [0xDD; 32];
        assert_eq!(
            advance_prepared_snapshot(&mut f.provider, &f.authority_pin, &f.cas_pin, &malformed),
            Err(Pfm5ExternalCasHighWaterError::IntentMismatch)
        );
        assert_eq!(f.provider.writes, 0);
    }
}
