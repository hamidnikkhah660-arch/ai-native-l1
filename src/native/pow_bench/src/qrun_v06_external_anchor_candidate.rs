//! QFP6 adapter for the independently administered External CAS anchor contract.
//!
//! The state digest binds the complete local durable-store position (network, genesis,
//! profile, consensus fingerprint, segment base/checkpoint, manifest and canonical tip).
//! The coordinator advances the existing signed ECR1/ECS1 provider record only after the
//! QFP6 manifest is durable. Callers must withhold block ACKs until advance succeeds or
//! reconcile_committed_state proves that an ambiguous CAS already committed the exact state.
//!
//! This module is a candidate integration surface. It does not provision a remote provider,
//! deploy an off-host Anchor, or wire itself into a QFP6 node runtime.

use crate::{
    external_cas_anchor_candidate::{
        ExternalCasClientError, ExternalCasError, ExternalCasPin, ExternalCasProviderTransport,
        ExternalCasReadRequest, ExternalCasRecord, ExternalCasWriteRequest,
        VerifiedExternalCasClient, VerifiedExternalCasRead,
    },
    external_cas_floor_store_candidate::{ExternalCasFloorError, ExternalCasFloorStore},
    qrun_v06_pow_fork_store_candidate::{QRunV06DurableForkStore, QRunV06ForkStoreError},
    v4_fat1_trust_candidate::MlDsa65Verifier,
};
use sha2::{Digest, Sha256};

const STATE_MAGIC: &[u8; 4] = b"Q6EA";
const STATE_VERSION: u16 = 2;
const STATE_DOMAIN: &[u8] = b"QRUN-V06-EXTERNAL-ANCHOR-STATE-V2\0";
const STATE_BYTES: usize = 384;
type Digest32 = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QRunV06ExternalAnchorError {
    InvalidState,
    InvalidStateEncoding,
    WrongPin,
    StateMismatch,
    InvalidTransition,
    PendingDifferentTransition,
    GenerationOverflow,
    RandomnessUnavailable,
    ExternalCas(String),
    ExternalClient(String),
    ExternalFloor(String),
    ForkStore(String),
}

impl std::fmt::Display for QRunV06ExternalAnchorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "QFP6 external anchor error: {self:?}")
    }
}
impl std::error::Error for QRunV06ExternalAnchorError {}

impl From<ExternalCasError> for QRunV06ExternalAnchorError {
    fn from(value: ExternalCasError) -> Self {
        Self::ExternalCas(value.to_string())
    }
}
impl From<ExternalCasClientError> for QRunV06ExternalAnchorError {
    fn from(value: ExternalCasClientError) -> Self {
        Self::ExternalClient(value.to_string())
    }
}
impl From<ExternalCasFloorError> for QRunV06ExternalAnchorError {
    fn from(value: ExternalCasFloorError) -> Self {
        Self::ExternalFloor(format!("{value:?}"))
    }
}
impl From<QRunV06ForkStoreError> for QRunV06ExternalAnchorError {
    fn from(value: QRunV06ForkStoreError) -> Self {
        Self::ForkStore(value.to_string())
    }
}

/// Canonical trust payload for one QFP6 durable segment tip.
/// A zero checkpoint_anchor denotes a Genesis-rooted segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06ExternalAnchorState {
    pub network_id: Digest32,
    pub genesis_digest: Digest32,
    /// Immutable Q6GD descriptor commitment, independently pinned by the QFP6 anchor config.
    pub genesis_descriptor_commitment: Digest32,
    pub profile_id: Digest32,
    pub consensus_fingerprint: Digest32,
    pub segment_base_height: u64,
    pub segment_base_tip: Digest32,
    pub checkpoint_anchor: Digest32,
    pub manifest_generation: u64,
    pub manifest_anchor: Digest32,
    pub canonical_height: u64,
    pub canonical_tip: Digest32,
    pub canonical_state_root: Digest32,
    /// Unsigned big-endian cumulative work, matching Uint256's canonical representation.
    pub cumulative_chainwork: Digest32,
}

impl QRunV06ExternalAnchorState {
    pub fn validate(&self) -> Result<(), QRunV06ExternalAnchorError> {
        if self.network_id == [0; 32]
            || self.genesis_digest == [0; 32]
            || self.genesis_descriptor_commitment == [0; 32]
            || self.profile_id == [0; 32]
            || self.consensus_fingerprint == [0; 32]
            || self.manifest_anchor == [0; 32]
            || self.canonical_height < self.segment_base_height
            || (self.segment_base_height > 0 && self.checkpoint_anchor == [0; 32])
            || (self.canonical_height == self.segment_base_height
                && self.canonical_tip != self.segment_base_tip)
        {
            return Err(QRunV06ExternalAnchorError::InvalidState);
        }
        Ok(())
    }

    /// Fixed-width, big-endian Q6EA v2 state binding. This payload is hashed into ECR1;
    /// it is not a replacement for the manifest or checkpoint files.
    pub fn encode(&self) -> Result<[u8; STATE_BYTES], QRunV06ExternalAnchorError> {
        self.validate()?;
        let mut out = Vec::with_capacity(STATE_BYTES);
        out.extend_from_slice(STATE_MAGIC);
        out.extend_from_slice(&STATE_VERSION.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&self.network_id);
        out.extend_from_slice(&self.genesis_digest);
        out.extend_from_slice(&self.genesis_descriptor_commitment);
        out.extend_from_slice(&self.profile_id);
        out.extend_from_slice(&self.consensus_fingerprint);
        out.extend_from_slice(&self.segment_base_height.to_be_bytes());
        out.extend_from_slice(&self.segment_base_tip);
        out.extend_from_slice(&self.checkpoint_anchor);
        out.extend_from_slice(&self.manifest_generation.to_be_bytes());
        out.extend_from_slice(&self.manifest_anchor);
        out.extend_from_slice(&self.canonical_height.to_be_bytes());
        out.extend_from_slice(&self.canonical_tip);
        out.extend_from_slice(&self.canonical_state_root);
        out.extend_from_slice(&self.cumulative_chainwork);
        out.try_into()
            .map_err(|_| QRunV06ExternalAnchorError::InvalidStateEncoding)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, QRunV06ExternalAnchorError> {
        if bytes.len() != STATE_BYTES
            || &bytes[..4] != STATE_MAGIC
            || u16::from_be_bytes([bytes[4], bytes[5]]) != STATE_VERSION
            || bytes[6..8] != [0, 0]
        {
            return Err(QRunV06ExternalAnchorError::InvalidStateEncoding);
        }
        let mut cursor = 8usize;
        let network_id = take_array::<32>(bytes, &mut cursor)?;
        let genesis_digest = take_array::<32>(bytes, &mut cursor)?;
        let genesis_descriptor_commitment = take_array::<32>(bytes, &mut cursor)?;
        let profile_id = take_array::<32>(bytes, &mut cursor)?;
        let consensus_fingerprint = take_array::<32>(bytes, &mut cursor)?;
        let segment_base_height = take_u64(bytes, &mut cursor)?;
        let segment_base_tip = take_array::<32>(bytes, &mut cursor)?;
        let checkpoint_anchor = take_array::<32>(bytes, &mut cursor)?;
        let manifest_generation = take_u64(bytes, &mut cursor)?;
        let manifest_anchor = take_array::<32>(bytes, &mut cursor)?;
        let canonical_height = take_u64(bytes, &mut cursor)?;
        let canonical_tip = take_array::<32>(bytes, &mut cursor)?;
        let canonical_state_root = take_array::<32>(bytes, &mut cursor)?;
        let cumulative_chainwork = take_array::<32>(bytes, &mut cursor)?;
        if cursor != STATE_BYTES {
            return Err(QRunV06ExternalAnchorError::InvalidStateEncoding);
        }
        let state = Self {
            network_id,
            genesis_digest,
            genesis_descriptor_commitment,
            profile_id,
            consensus_fingerprint,
            segment_base_height,
            segment_base_tip,
            checkpoint_anchor,
            manifest_generation,
            manifest_anchor,
            canonical_height,
            canonical_tip,
            canonical_state_root,
            cumulative_chainwork,
        };
        state.validate()?;
        Ok(state)
    }

    pub fn digest(&self) -> Result<Digest32, QRunV06ExternalAnchorError> {
        let encoded = self.encode()?;
        let mut hasher = Sha256::new();
        hasher.update(STATE_DOMAIN);
        hasher.update(encoded);
        Ok(hasher.finalize().into())
    }

    /// Derive the exact payload from a validated durable store. Genesis identity is supplied
    /// by the caller from the pinned network configuration and must match ExternalCasPin.
    pub fn from_store(
        store: &QRunV06DurableForkStore,
        genesis_digest: Digest32,
    ) -> Result<Self, QRunV06ExternalAnchorError> {
        let graph = store.graph()?;
        let tip = graph.canonical_tip();
        let cumulative_chainwork = graph
            .branch_work(&tip.tip_hash)
            .ok_or(QRunV06ExternalAnchorError::InvalidState)?
            .to_be_bytes();
        let genesis_descriptor_commitment = graph
            .canonical_state()
            .genesis_descriptor_commitment()
            .ok_or(QRunV06ExternalAnchorError::InvalidState)?;
        let state = Self {
            network_id: graph.network_id(),
            genesis_digest,
            genesis_descriptor_commitment,
            profile_id: graph.profile_id(),
            consensus_fingerprint: store.consensus_fingerprint()?,
            segment_base_height: graph.base_height(),
            segment_base_tip: graph.base_tip(),
            checkpoint_anchor: store.checkpoint_anchor()?.unwrap_or([0; 32]),
            manifest_generation: store.generation()?,
            manifest_anchor: store.manifest_anchor()?,
            canonical_height: tip.height,
            canonical_tip: tip.tip_hash,
            canonical_state_root: store.canonical_state_root()?,
            cumulative_chainwork,
        };
        state.validate()?;
        Ok(state)
    }

    /// The only valid durable-store transitions: one next manifest in the same segment, or
    /// a new generation-zero segment rooted at the exact previous canonical checkpoint.
    pub fn validate_successor(&self, next: &Self) -> Result<(), QRunV06ExternalAnchorError> {
        self.validate()?;
        next.validate()?;
        if self.network_id != next.network_id
            || self.genesis_digest != next.genesis_digest
            || self.genesis_descriptor_commitment != next.genesis_descriptor_commitment
            || self.profile_id != next.profile_id
            || self.consensus_fingerprint != next.consensus_fingerprint
        {
            return Err(QRunV06ExternalAnchorError::WrongPin);
        }

        let same_segment = self.segment_base_height == next.segment_base_height
            && self.segment_base_tip == next.segment_base_tip
            && self.checkpoint_anchor == next.checkpoint_anchor;

        if same_segment {
            if self.manifest_generation.checked_add(1) != Some(next.manifest_generation)
                || next.cumulative_chainwork < self.cumulative_chainwork
            {
                return Err(QRunV06ExternalAnchorError::InvalidTransition);
            }
        } else if next.segment_base_height != self.canonical_height
            || next.segment_base_tip != self.canonical_tip
            || next.checkpoint_anchor == [0; 32]
            || next.manifest_generation != 0
            || next.canonical_height != self.canonical_height
            || next.canonical_tip != self.canonical_tip
            || next.canonical_state_root != self.canonical_state_root
            || next.cumulative_chainwork != self.cumulative_chainwork
        {
            return Err(QRunV06ExternalAnchorError::InvalidTransition);
        }
        Ok(())
    }

    /// Create the explicitly provisioned generation-zero ECR1 record for this QFP6 state.
    /// Provisioning must happen out-of-band; a node must never silently bootstrap a missing pin.
    pub fn bootstrap_record(
        &self,
        pin: &QRunV06ExternalAnchorPin,
    ) -> Result<ExternalCasRecord, QRunV06ExternalAnchorError> {
        self.validate()?;
        validate_pin_for_state(pin, self)?;
        let provider_pin = pin.external_cas_pin();
        Ok(ExternalCasRecord {
            generation: 0,
            provider_id: provider_pin.provider_id,
            network_id: provider_pin.network_id,
            genesis_digest: provider_pin.genesis_digest,
            previous_record_digest: [0; 32],
            previous_state_digest: [0; 32],
            next_state_digest: self.digest()?,
            operation_id: random_digest()?,
            request_digest: random_digest()?,
        })
    }
}

/// QFP6-specific pin: the existing provider/key/network/genesis pin plus the exact Q6GD
/// commitment. This prevents a valid generic CAS pin from silently authorizing another
/// QFP6 Genesis descriptor in the same legacy network/genesis namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06ExternalAnchorPin {
    external_cas_pin: ExternalCasPin,
    genesis_descriptor_commitment: Digest32,
}

impl QRunV06ExternalAnchorPin {
    pub fn new(
        external_cas_pin: ExternalCasPin,
        genesis_descriptor_commitment: Digest32,
    ) -> Result<Self, QRunV06ExternalAnchorError> {
        external_cas_pin.validate()?;
        if genesis_descriptor_commitment == [0; 32] {
            return Err(QRunV06ExternalAnchorError::WrongPin);
        }
        Ok(Self {
            external_cas_pin,
            genesis_descriptor_commitment,
        })
    }

    pub fn external_cas_pin(&self) -> &ExternalCasPin {
        &self.external_cas_pin
    }

    pub fn genesis_descriptor_commitment(&self) -> Digest32 {
        self.genesis_descriptor_commitment
    }
}

/// Coordinates a signed ECR1/ECS1 provider with the existing local monotonic floor.
/// The QFP6 caller must call advance_after_durable_commit after local manifest publication
/// and before any network/application ACK.
pub struct QRunV06ExternalAnchorCoordinator<P, V> {
    client: VerifiedExternalCasClient<P, V>,
    floor: ExternalCasFloorStore,
    pin: QRunV06ExternalAnchorPin,
    /// A local manifest is already durable but its external CAS result is unresolved.
    pending: Option<(Digest32, Digest32)>,
}

impl<P, V> QRunV06ExternalAnchorCoordinator<P, V>
where
    P: ExternalCasProviderTransport,
    V: MlDsa65Verifier,
{
    pub fn new(
        client: VerifiedExternalCasClient<P, V>,
        floor: ExternalCasFloorStore,
        pin: QRunV06ExternalAnchorPin,
    ) -> Result<Self, QRunV06ExternalAnchorError> {
        pin.external_cas_pin().validate()?;
        if !client.is_pinned_to(pin.external_cas_pin()) || floor.pin() != pin.external_cas_pin() {
            return Err(QRunV06ExternalAnchorError::WrongPin);
        }
        Ok(Self {
            client,
            floor,
            pin,
            pending: None,
        })
    }

    /// Verify that the independently signed provider tip binds this exact durable QFP6 state.
    /// A single already-applied successor may reconcile a stale local floor; larger jumps fail.
    pub fn verify_state(
        &mut self,
        state: &QRunV06ExternalAnchorState,
    ) -> Result<VerifiedExternalCasRead, QRunV06ExternalAnchorError> {
        self.reconcile_committed_state(state)
    }

    /// Advance the signed external high-water record after the QFP6 manifest is durable.
    /// A returned error must prevent ACK. After an ambiguous provider response, call
    /// reconcile_committed_state(next) before retrying or accepting further blocks.
    pub fn advance_after_durable_commit(
        &mut self,
        current: &QRunV06ExternalAnchorState,
        next: &QRunV06ExternalAnchorState,
    ) -> Result<ExternalCasRecord, QRunV06ExternalAnchorError> {
        current.validate_successor(next)?;
        validate_pin_for_state(&self.pin, current)?;
        validate_pin_for_state(&self.pin, next)?;
        let current_digest = current.digest()?;
        let next_digest = next.digest()?;
        if let Some((pending_current, pending_next)) = self.pending {
            if pending_current != current_digest || pending_next != next_digest {
                return Err(QRunV06ExternalAnchorError::PendingDifferentTransition);
            }
            match self.read_and_reconcile(next) {
                Ok(observed) => {
                    self.pending = None;
                    return Ok(observed.record);
                }
                Err(QRunV06ExternalAnchorError::StateMismatch) => {}
                Err(error) => return Err(error),
            }
        } else {
            self.pending = Some((current_digest, next_digest));
        }
        let observed = self.read_and_reconcile(current)?;
        let operation_id = random_digest()?;
        let request_nonce = random_digest()?;
        let next_record = prepare_successor_record(
            &self.pin,
            &observed.record,
            next,
            operation_id,
            request_nonce,
            observed.object_generation,
        )?;
        let mut request = ExternalCasWriteRequest {
            request_nonce,
            operation_id: next_record.operation_id,
            request_digest: next_record.request_digest,
            expected_generation: observed.record.generation,
            expected_object_generation: observed.object_generation,
            expected_record_digest: observed.record.digest()?,
            expected_state_digest: observed.record.next_state_digest,
            next_record,
        };
        request.bind_request_digest(self.pin.external_cas_pin())?;
        let next_record = request.next_record.clone();
        let receipt = self.client.compare_and_swap(&request)?;
        self.floor.advance(
            &observed.record,
            observed.object_generation,
            &next_record,
            receipt.object_generation,
        )?;
        self.pending = None;
        Ok(next_record)
    }

    /// Resolve a lost/ambiguous CAS response only if a fresh signed read reports this exact
    /// QFP6 state as the current record or its one permitted successor.
    pub fn reconcile_committed_state(
        &mut self,
        committed: &QRunV06ExternalAnchorState,
    ) -> Result<VerifiedExternalCasRead, QRunV06ExternalAnchorError> {
        let digest = committed.digest()?;
        if let Some((_, pending_digest)) = self.pending {
            if pending_digest != digest {
                return Err(QRunV06ExternalAnchorError::PendingDifferentTransition);
            }
        }
        let observed = self.read_and_reconcile(committed)?;
        self.pending = None;
        Ok(observed)
    }

    fn read_and_reconcile(
        &mut self,
        state: &QRunV06ExternalAnchorState,
    ) -> Result<VerifiedExternalCasRead, QRunV06ExternalAnchorError> {
        state.validate()?;
        validate_pin_for_state(&self.pin, state)?;
        let floor = self.floor.snapshot()?;
        let operation_id = random_digest()?;
        let request_digest = state.digest()?;
        let request: ExternalCasReadRequest = self
            .client
            .fresh_read_request(operation_id, request_digest)?;
        let observed = self.client.read_current(
            &request,
            floor.trusted_record.generation,
            floor.minimum_object_generation,
            Some(&floor.trusted_record),
        )?;
        if observed.record.next_state_digest != state.digest()? {
            return Err(QRunV06ExternalAnchorError::StateMismatch);
        }
        if observed.record != floor.trusted_record
            || observed.object_generation != floor.minimum_object_generation
        {
            self.floor
                .reconcile_verified_observation(&observed.record, observed.object_generation)?;
        }
        Ok(observed)
    }
}

fn prepare_successor_record(
    pin: &QRunV06ExternalAnchorPin,
    current: &ExternalCasRecord,
    next_state: &QRunV06ExternalAnchorState,
    operation_id: Digest32,
    request_nonce: Digest32,
    expected_object_generation: u64,
) -> Result<ExternalCasRecord, QRunV06ExternalAnchorError> {
    validate_pin_for_state(pin, next_state)?;
    if expected_object_generation == 0 || operation_id == [0; 32] || request_nonce == [0; 32] {
        return Err(QRunV06ExternalAnchorError::InvalidState);
    }
    let provider_pin = pin.external_cas_pin();
    Ok(ExternalCasRecord {
        generation: current
            .generation
            .checked_add(1)
            .ok_or(QRunV06ExternalAnchorError::GenerationOverflow)?,
        provider_id: provider_pin.provider_id,
        network_id: provider_pin.network_id,
        genesis_digest: provider_pin.genesis_digest,
        previous_record_digest: current.digest()?,
        previous_state_digest: current.next_state_digest,
        next_state_digest: next_state.digest()?,
        operation_id,
        request_digest: [0; 32],
    })
}

fn validate_pin_for_state(
    pin: &QRunV06ExternalAnchorPin,
    state: &QRunV06ExternalAnchorState,
) -> Result<(), QRunV06ExternalAnchorError> {
    let provider_pin = pin.external_cas_pin();
    if provider_pin.network_id != state.network_id
        || provider_pin.genesis_digest != state.genesis_digest
        || pin.genesis_descriptor_commitment() != state.genesis_descriptor_commitment
    {
        return Err(QRunV06ExternalAnchorError::WrongPin);
    }
    Ok(())
}

fn random_digest() -> Result<Digest32, QRunV06ExternalAnchorError> {
    let mut value = [0u8; 32];
    getrandom::getrandom(&mut value)
        .map_err(|_| QRunV06ExternalAnchorError::RandomnessUnavailable)?;
    if value == [0; 32] {
        return Err(QRunV06ExternalAnchorError::RandomnessUnavailable);
    }
    Ok(value)
}

fn take_array<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], QRunV06ExternalAnchorError> {
    let end = cursor
        .checked_add(N)
        .ok_or(QRunV06ExternalAnchorError::InvalidStateEncoding)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(QRunV06ExternalAnchorError::InvalidStateEncoding)?
        .try_into()
        .map_err(|_| QRunV06ExternalAnchorError::InvalidStateEncoding)?;
    *cursor = end;
    Ok(value)
}

fn take_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64, QRunV06ExternalAnchorError> {
    Ok(u64::from_be_bytes(take_array::<8>(bytes, cursor)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        consensus::{ConsensusParameters, PowAlgorithm, PowParameters, Uint256},
        external_cas_anchor_candidate::{
            ExternalCasReceipt, ExternalCasReceiptKind, ExternalCasReceiptOutcome,
            EXTERNAL_CAS_RECEIPT_PAYLOAD_BYTES,
        },
        qrun_v06_canonical_execution_candidate::QRunV06CanonicalExecutionState,
        qrun_v06_genesis_descriptor_candidate::QRunV06GenesisDescriptor,
        qrun_v06_tokenomics_candidate::{
            QRunV06MiningScheduleCandidate, QRunV06TokenomicsState, QRUN_V06_FOUNDER_GENESIS_ATOMS,
        },
        qrun_v06_unified_asset_candidate::QRunV06UnifiedAssetState,
        qzxb_amm_candidate::QzxbAmmStateCandidate,
        state_machine::{AccountId, LedgerState, TransactionAuthenticator},
        v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate,
        v4_fat1_trust_candidate::{ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SIGNATURE_BYTES},
    };
    use libcrux_ml_dsa::ml_dsa_65::portable;
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    const STORE_NETWORK: [u8; 32] = [0x71; 32];
    const STORE_PROFILE: [u8; 32] = [0x72; 32];
    const STORE_OWNER: [u8; 32] = [0x73; 32];

    struct EmptyAuthenticator;
    impl TransactionAuthenticator for EmptyAuthenticator {
        fn verify(&self, _: &AccountId, _: &[u8; 32], _: &[u8]) -> Result<(), ()> {
            Err(())
        }
    }

    fn store_params() -> ConsensusParameters {
        let mut params = ConsensusParameters::candidate_testnet().unwrap();
        params.protocol_version = 6;
        params.target_block_time_secs = 30;
        params.difficulty_window_blocks = 2;
        params.difficulty_min_ratio_divisor = 4;
        params.difficulty_max_ratio = 4;
        params.initial_target = Uint256::from_be_bytes([0x7F; 32]);
        params.pow_limit = Uint256::MAX;
        params.pow = PowParameters {
            algorithm: PowAlgorithm::Argon2id,
            memory_kib: 8,
            iterations: 1,
            lanes: 1,
            output_bytes: 32,
        };
        params.validate().unwrap();
        params
    }

    fn store_genesis() -> QRunV06CanonicalExecutionState {
        let consensus = store_params();
        let schedule = QRunV06MiningScheduleCandidate::cp0422_research_candidate();
        let tokenomics =
            QRunV06TokenomicsState::genesis(STORE_NETWORK, STORE_OWNER, schedule).unwrap();
        let descriptor = QRunV06GenesisDescriptor::new(
            STORE_NETWORK,
            STORE_PROFILE,
            STORE_OWNER,
            1,
            crate::qrun_v06_checkpoint_candidate::qrun_v06_consensus_fingerprint(&consensus)
                .unwrap(),
            tokenomics.policy_fingerprint(),
        )
        .unwrap();
        QRunV06CanonicalExecutionState::cp0528_genesis_candidate_with_descriptor(
            descriptor, schedule,
        )
        .unwrap()
    }

    fn cp0528_store_genesis() -> QRunV06CanonicalExecutionState {
        store_genesis()
    }

    #[test]
    fn from_store_binds_the_actual_genesis_segment_and_consensus_profile() {
        let dir = TestDir::new();
        let authenticator = EmptyAuthenticator;
        let genesis = store_genesis();
        let expected_genesis_descriptor_commitment =
            genesis.genesis_descriptor_commitment().unwrap();
        let store = QRunV06DurableForkStore::open_with_expected_genesis_descriptor_commitment(
            &dir.0,
            genesis,
            store_params(),
            &authenticator,
            None,
            expected_genesis_descriptor_commitment,
        )
        .unwrap();
        let state = QRunV06ExternalAnchorState::from_store(&store, [0x81; 32]).unwrap();
        assert_eq!(state.network_id, STORE_NETWORK);
        assert_eq!(state.genesis_digest, [0x81; 32]);
        assert_eq!(state.profile_id, STORE_PROFILE);
        assert_ne!(state.consensus_fingerprint, [0; 32]);
        assert_eq!(state.segment_base_height, 0);
        assert_eq!(state.canonical_height, 0);
        assert_eq!(state.manifest_generation, 0);
        assert_eq!(state.manifest_anchor, store.manifest_anchor().unwrap());
        assert_eq!(
            state.canonical_state_root,
            store.canonical_state_root().unwrap()
        );
        assert_eq!(
            state.cumulative_chainwork,
            store
                .graph()
                .unwrap()
                .branch_work(&store.canonical_tip().unwrap())
                .unwrap()
                .to_be_bytes()
        );
        let pin = QRunV06ExternalAnchorPin::new(
            ExternalCasPin {
                provider_id: [0x91; 32],
                network_id: STORE_NETWORK,
                genesis_digest: [0x82; 32],
                receipt_key_id: [0x92; 32],
                receipt_public_key: [0x93; ML_DSA_65_PUBLIC_KEY_BYTES],
            },
            state.genesis_descriptor_commitment,
        )
        .unwrap();
        assert!(matches!(
            state.bootstrap_record(&pin),
            Err(QRunV06ExternalAnchorError::WrongPin)
        ));
    }

    fn sample_state() -> QRunV06ExternalAnchorState {
        QRunV06ExternalAnchorState {
            network_id: [0x11; 32],
            genesis_digest: [0x12; 32],
            genesis_descriptor_commitment: [0x18; 32],
            profile_id: [0x13; 32],
            consensus_fingerprint: [0x14; 32],
            segment_base_height: 0,
            segment_base_tip: [0x15; 32],
            checkpoint_anchor: [0; 32],
            manifest_generation: 0,
            manifest_anchor: [0x16; 32],
            canonical_height: 0,
            canonical_tip: [0x15; 32],
            canonical_state_root: [0x17; 32],
            cumulative_chainwork: {
                let mut work = [0; 32];
                work[31] = 1;
                work
            },
        }
    }

    fn sample_pin() -> QRunV06ExternalAnchorPin {
        QRunV06ExternalAnchorPin::new(
            ExternalCasPin {
                provider_id: [0x21; 32],
                network_id: [0x11; 32],
                genesis_digest: [0x12; 32],
                receipt_key_id: [0x22; 32],
                receipt_public_key: [0x23;
                    crate::v4_fat1_trust_candidate::ML_DSA_65_PUBLIC_KEY_BYTES],
            },
            [0x18; 32],
        )
        .unwrap()
    }

    fn same_segment_next(current: &QRunV06ExternalAnchorState) -> QRunV06ExternalAnchorState {
        let mut next = current.clone();
        next.manifest_generation += 1;
        next.manifest_anchor = [0x31; 32];
        next.canonical_height += 1;
        next.canonical_tip = [0x32; 32];
        next.canonical_state_root = [0x33; 32];
        next.cumulative_chainwork[31] = 2;
        next
    }

    #[test]
    fn q6ea_external_payload_commits_the_cp0528_monetary_execution_root() {
        let dir = TestDir::new();
        let authenticator = EmptyAuthenticator;
        let genesis = cp0528_store_genesis();
        assert_eq!(
            genesis.unified().ledger().total_value().unwrap(),
            QRUN_V06_FOUNDER_GENESIS_ATOMS
        );
        let expected_genesis_descriptor_commitment =
            genesis.genesis_descriptor_commitment().unwrap();
        let store = QRunV06DurableForkStore::open_with_expected_genesis_descriptor_commitment(
            &dir.0,
            genesis.clone(),
            store_params(),
            &authenticator,
            None,
            expected_genesis_descriptor_commitment,
        )
        .unwrap();
        let anchored = QRunV06ExternalAnchorState::from_store(&store, [0x82; 32]).unwrap();
        assert_eq!(anchored.canonical_state_root, genesis.state_root().unwrap());
        let encoded = anchored.encode().unwrap();
        assert_eq!(
            QRunV06ExternalAnchorState::decode(&encoded).unwrap(),
            anchored
        );

        // The same Ledger/AMM without the CP-0528 accounting component has a different root.
        let baseline_ledger = LedgerState::genesis(
            STORE_NETWORK,
            vec![(STORE_OWNER, QRUN_V06_FOUNDER_GENESIS_ATOMS as u64)],
        )
        .unwrap();
        let baseline_amm = QzxbAmmStateCandidate::new(STORE_NETWORK, 32, 64, 512).unwrap();
        let baseline_unified =
            QRunV06UnifiedAssetState::new(baseline_ledger, baseline_amm).unwrap();
        let baseline =
            QRunV06CanonicalExecutionState::new(baseline_unified, STORE_PROFILE).unwrap();
        assert_ne!(
            anchored.canonical_state_root,
            baseline.state_root().unwrap()
        );

        let original_digest = anchored.digest().unwrap();
        let mut altered = anchored.clone();
        altered.canonical_state_root[0] ^= 1;
        assert_ne!(altered.digest().unwrap(), original_digest);
    }

    #[test]
    fn q6ea_codec_is_fixed_width_canonical_and_binds_every_field() {
        let state = sample_state();
        let bytes = state.encode().unwrap();
        assert_eq!(bytes.len(), STATE_BYTES);
        assert_eq!(&bytes[..4], b"Q6EA");
        assert_eq!(u16::from_be_bytes([bytes[4], bytes[5]]), 2);
        assert_eq!(QRunV06ExternalAnchorState::decode(&bytes).unwrap(), state);
        let original = state.digest().unwrap();

        let mut changed = state.clone();
        changed.profile_id[0] ^= 1;
        assert_ne!(changed.digest().unwrap(), original);
        changed = state.clone();
        changed.checkpoint_anchor[0] ^= 1;
        assert_ne!(changed.digest().unwrap(), original);
        changed = state.clone();
        changed.genesis_descriptor_commitment[0] ^= 1;
        assert_ne!(changed.digest().unwrap(), original);

        let mut malformed = bytes.to_vec();
        malformed[6] = 1;
        assert!(matches!(
            QRunV06ExternalAnchorState::decode(&malformed),
            Err(QRunV06ExternalAnchorError::InvalidStateEncoding)
        ));
    }

    #[test]
    fn same_segment_transition_requires_exact_manifest_successor_and_non_decreasing_work() {
        let current = sample_state();
        let next = same_segment_next(&current);
        current.validate_successor(&next).unwrap();

        let mut skipped = next.clone();
        skipped.manifest_generation += 1;
        assert!(matches!(
            current.validate_successor(&skipped),
            Err(QRunV06ExternalAnchorError::InvalidTransition)
        ));

        let mut work_rollback = next;
        work_rollback.cumulative_chainwork = [0; 32];
        assert!(matches!(
            current.validate_successor(&work_rollback),
            Err(QRunV06ExternalAnchorError::InvalidTransition)
        ));
    }

    #[test]
    fn rollover_must_checkpoint_exact_previous_tip_without_resetting_chainwork() {
        let current = same_segment_next(&sample_state());
        let mut rollover = current.clone();
        rollover.segment_base_height = current.canonical_height;
        rollover.segment_base_tip = current.canonical_tip;
        rollover.checkpoint_anchor = [0x41; 32];
        rollover.manifest_generation = 0;
        rollover.manifest_anchor = [0x42; 32];
        current.validate_successor(&rollover).unwrap();

        let mut wrong_base = rollover.clone();
        wrong_base.segment_base_height -= 1;
        assert!(matches!(
            current.validate_successor(&wrong_base),
            Err(QRunV06ExternalAnchorError::InvalidTransition)
        ));

        let mut lost_work = rollover;
        lost_work.cumulative_chainwork[31] = 0;
        assert!(matches!(
            current.validate_successor(&lost_work),
            Err(QRunV06ExternalAnchorError::InvalidTransition)
        ));
    }

    #[test]
    fn bootstrap_record_binds_qfp6_state_to_external_provider_pin() {
        let state = sample_state();
        let pin = sample_pin();
        let record = state.bootstrap_record(&pin).unwrap();
        assert_eq!(record.generation, 0);
        assert_eq!(record.next_state_digest, state.digest().unwrap());
        assert_eq!(record.network_id, state.network_id);
        assert_eq!(record.genesis_digest, state.genesis_digest);
        assert_ne!(record.operation_id, [0; 32]);
        assert_ne!(record.request_digest, [0; 32]);

        // The generic CAS domain may stay identical, but QFP6 must reject another Q6GD pin.
        let wrong_descriptor_pin =
            QRunV06ExternalAnchorPin::new(pin.external_cas_pin().clone(), [0x19; 32]).unwrap();
        assert!(matches!(
            state.bootstrap_record(&wrong_descriptor_pin),
            Err(QRunV06ExternalAnchorError::WrongPin)
        ));

        let mut wrong_descriptor_state = state.clone();
        wrong_descriptor_state.genesis_descriptor_commitment[0] ^= 1;
        assert!(matches!(
            state.validate_successor(&wrong_descriptor_state),
            Err(QRunV06ExternalAnchorError::WrongPin)
        ));

        let mut wrong_provider_pin = pin.external_cas_pin().clone();
        wrong_provider_pin.genesis_digest = [0x99; 32];
        let wrong_pin =
            QRunV06ExternalAnchorPin::new(wrong_provider_pin, pin.genesis_descriptor_commitment())
                .unwrap();
        assert!(matches!(
            state.bootstrap_record(&wrong_pin),
            Err(QRunV06ExternalAnchorError::WrongPin)
        ));
    }

    #[test]
    fn prepared_cas_successor_links_exact_ecr1_predecessor_and_qfp6_state() {
        let pin = sample_pin();
        let current_state = sample_state();
        let next_state = same_segment_next(&current_state);
        current_state.validate_successor(&next_state).unwrap();
        let current_record = current_state.bootstrap_record(&pin).unwrap();
        let next_record = prepare_successor_record(
            &pin,
            &current_record,
            &next_state,
            [0x51; 32],
            [0x52; 32],
            1,
        )
        .unwrap();
        let mut request = ExternalCasWriteRequest {
            request_nonce: [0x52; 32],
            operation_id: next_record.operation_id,
            request_digest: next_record.request_digest,
            expected_generation: current_record.generation,
            expected_object_generation: 1,
            expected_record_digest: current_record.digest().unwrap(),
            expected_state_digest: current_record.next_state_digest,
            next_record,
        };
        request.bind_request_digest(pin.external_cas_pin()).unwrap();
        request.validate(pin.external_cas_pin()).unwrap();
        current_record
            .validate_successor(&request.next_record)
            .unwrap();
        assert_eq!(
            request.next_record.next_state_digest,
            next_state.digest().unwrap()
        );
        assert_eq!(
            request.next_record.previous_record_digest,
            current_record.digest().unwrap()
        );
    }

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "qrun_v06_external_anchor_{}_{}",
                std::process::id(),
                nonce
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct MemoryCasProvider<F> {
        pin: ExternalCasPin,
        current: ExternalCasRecord,
        object_generation: u64,
        fail_after_apply_once: bool,
        sign: F,
    }

    fn signed_receipt<F>(
        sign: &F,
        pin: &ExternalCasPin,
        record: &ExternalCasRecord,
        kind: ExternalCasReceiptKind,
        outcome: ExternalCasReceiptOutcome,
        object_generation: u64,
        request_nonce: Digest32,
        operation_id: Digest32,
        request_digest: Digest32,
    ) -> ExternalCasReceipt
    where
        F: Fn(ExternalCasReceipt) -> ExternalCasReceipt,
    {
        let receipt = ExternalCasReceipt {
            kind,
            outcome,
            generation: record.generation,
            object_generation,
            provider_id: pin.provider_id,
            network_id: pin.network_id,
            genesis_digest: pin.genesis_digest,
            receipt_key_id: pin.receipt_key_id,
            request_nonce,
            record_digest: record.digest().unwrap(),
            previous_record_digest: record.previous_record_digest,
            previous_state_digest: record.previous_state_digest,
            state_digest: record.next_state_digest,
            operation_id,
            request_digest,
            signature: [0; ML_DSA_65_SIGNATURE_BYTES],
        };
        assert_eq!(
            receipt.signing_digest().unwrap().len(),
            32,
            "receipt payload digest must be SHA-256"
        );
        assert_eq!(EXTERNAL_CAS_RECEIPT_PAYLOAD_BYTES, 380);
        sign(receipt)
    }

    impl<F> ExternalCasProviderTransport for MemoryCasProvider<F>
    where
        F: Fn(ExternalCasReceipt) -> ExternalCasReceipt,
    {
        type Error = String;

        fn read_current(
            &mut self,
            request: &ExternalCasReadRequest,
        ) -> Result<(ExternalCasRecord, ExternalCasReceipt), Self::Error> {
            let receipt = signed_receipt(
                &self.sign,
                &self.pin,
                &self.current,
                ExternalCasReceiptKind::Read,
                ExternalCasReceiptOutcome::Observed,
                self.object_generation,
                request.request_nonce,
                request.operation_id,
                request.request_digest,
            );
            Ok((self.current.clone(), receipt))
        }

        fn compare_and_swap(
            &mut self,
            request: &ExternalCasWriteRequest,
        ) -> Result<ExternalCasReceipt, Self::Error> {
            request
                .validate(&self.pin)
                .map_err(|error| error.to_string())?;
            let already_applied = self.current.digest().map_err(|e| e.to_string())?
                == request.next_record.digest().map_err(|e| e.to_string())?
                && self.current.operation_id == request.operation_id
                && self.current.request_digest == request.request_digest;
            let can_apply = self.current.generation == request.expected_generation
                && self.object_generation == request.expected_object_generation
                && self.current.digest().map_err(|e| e.to_string())?
                    == request.expected_record_digest
                && self.current.next_state_digest == request.expected_state_digest;

            let outcome = if already_applied {
                ExternalCasReceiptOutcome::AlreadyApplied
            } else if can_apply {
                self.current = request.next_record.clone();
                self.object_generation += 1;
                if self.fail_after_apply_once {
                    self.fail_after_apply_once = false;
                    return Err("simulated lost response after provider CAS applied".into());
                }
                ExternalCasReceiptOutcome::Applied
            } else {
                ExternalCasReceiptOutcome::Conflict
            };
            Ok(signed_receipt(
                &self.sign,
                &self.pin,
                &self.current,
                ExternalCasReceiptKind::Commit,
                outcome,
                self.object_generation,
                request.request_nonce,
                request.operation_id,
                request.request_digest,
            ))
        }
    }

    #[test]
    fn coordinator_reconciles_exact_provider_commit_after_lost_response_before_floor_advance() {
        let keys = portable::generate_key_pair([0x91u8; 32]);
        let public_key: [u8; ML_DSA_65_PUBLIC_KEY_BYTES] = *keys.verification_key.as_ref();
        let provider_pin = ExternalCasPin {
            provider_id: [0x21; 32],
            network_id: [0x11; 32],
            genesis_digest: [0x12; 32],
            receipt_key_id: [0x22; 32],
            receipt_public_key: public_key,
        };
        let pin = QRunV06ExternalAnchorPin::new(provider_pin.clone(), [0x18; 32]).unwrap();
        let current = sample_state();
        let bootstrap = current.bootstrap_record(&pin).unwrap();
        let directory = TestDir::new();
        let floor = ExternalCasFloorStore::initialize(
            &directory.0,
            provider_pin.clone(),
            bootstrap.clone(),
            1,
        )
        .unwrap();

        let signing_key = keys.signing_key;
        let sign = move |mut receipt: ExternalCasReceipt| {
            let digest = receipt.signing_digest().unwrap();
            receipt.signature = *portable::sign(&signing_key, &digest, &[], [0x71u8; 32])
                .unwrap()
                .as_ref();
            receipt
        };
        let provider = MemoryCasProvider {
            pin: provider_pin.clone(),
            current: bootstrap,
            object_generation: 1,
            fail_after_apply_once: true,
            sign,
        };
        let client =
            VerifiedExternalCasClient::new(provider_pin, provider, LibcruxMlDsa65VerifierCandidate)
                .unwrap();
        let mut coordinator = QRunV06ExternalAnchorCoordinator::new(client, floor, pin).unwrap();
        let next = same_segment_next(&current);

        assert!(matches!(
            coordinator.advance_after_durable_commit(&current, &next),
            Err(QRunV06ExternalAnchorError::ExternalClient(_))
        ));

        let mut competing = next.clone();
        competing.canonical_tip = [0x77; 32];
        assert!(matches!(
            coordinator.advance_after_durable_commit(&current, &competing),
            Err(QRunV06ExternalAnchorError::PendingDifferentTransition)
        ));

        let retried = coordinator
            .advance_after_durable_commit(&current, &next)
            .unwrap();
        assert_eq!(retried.generation, 1);
        let reconciled = coordinator.reconcile_committed_state(&next).unwrap();
        assert_eq!(reconciled.record.generation, 1);
        assert_eq!(reconciled.object_generation, 2);
        assert_eq!(reconciled.record.next_state_digest, next.digest().unwrap());
        assert_eq!(
            coordinator.verify_state(&next).unwrap().record,
            reconciled.record
        );
    }
}
