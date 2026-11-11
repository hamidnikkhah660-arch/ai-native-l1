//! Isolated QFP6 branch graph with QFB6 branch-local execution and cumulative-work selection.
//!
//! This candidate deliberately does not reuse the QFP5 PrivateTestnetForkChoice or PFS2 store.
//! Every accepted QFP6 block owns a cloned canonical execution state and an immutable,
//! branch-specific target/timestamp history. Checkpoint encoding/anchor validation and a
//! separate durable segment store are candidate modules; node ingress, network sync, mining and
//! node-binary integration remain separate follow-up gates.

use crate::{
    consensus::{
        block_work, compare_chain_tips, pow_digest, ChainTip, ConsensusError, ConsensusParameters,
        Uint256,
    },
    private_testnet_consensus::{target_for_next_block, PrivateConsensusError},
    qrun_v06_canonical_execution_candidate::{
        QRunV06Block, QRunV06CanonicalExecutionState, QRunV06ExecutionError,
    },
    qrun_v06_checkpoint_candidate::{
        QRunV06CheckpointCandidate, QRunV06CheckpointError, QRunV06TargetHistoryEntry,
    },
    qrun_v06_pow_wire_candidate::{
        decode_qrun_v06_pow_block, verify_qrun_v06_pow_block, QRunV06PowWireError,
    },
    qrun_v06_profile_trust_candidate::QRunV06TrustAuthorizedQuoteAsset,
    state_machine::TransactionAuthenticator,
};
use std::{collections::BTreeMap, sync::Arc};

pub const MAX_QRUN_V06_FORK_ARCHIVE_BLOCKS: usize = 1_024;
pub const MAX_QRUN_V06_FORK_BRANCH_HEIGHT: u64 = 1_024;
pub const MAX_QRUN_V06_DIFFICULTY_WINDOW: u64 = 65_536;

/// A caller must obtain a new Q6TS/Q6QA authorization for every external-quote block.
/// The provider receives the exact parent state, block and required quote asset ID; it
/// may consult the trust source and independently administered monotonic floor. Returning
/// an error aborts the candidate before any branch is published.
pub type QRunV06QuoteAssetAuthorizationProvider<'a> = dyn FnMut(
        &QRunV06CanonicalExecutionState,
        &QRunV06Block,
        [u8; 32],
    ) -> Result<QRunV06TrustAuthorizedQuoteAsset, String>
    + 'a;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QRunV06ForkChoiceError {
    BaseMustBeGenesis,
    InvalidProfile,
    InvalidConsensusProfile,
    MissingGenesisDescriptor,
    GenesisDescriptorMismatch,
    InvalidDifficultyWindow,
    Wire(QRunV06PowWireError),
    Execution(QRunV06ExecutionError),
    Consensus(ConsensusError),
    Retarget(PrivateConsensusError),
    WrongNetwork,
    WrongProfile,
    UnknownParent,
    PreviousConsensusHashMismatch,
    ExpectedTargetMismatch { expected: Uint256, actual: Uint256 },
    DuplicateDigestConflict,
    ArchiveCapacityExceeded,
    BranchHeightExceeded,
    ChainworkOverflow,
    RetargetHistoryUnavailable,
    TimestampNotAboveMedian { median: u64, actual: u64 },
    ReplayIncomplete,
    ArchiveExportLimitExceeded,
    Checkpoint(QRunV06CheckpointError),
    QuoteAssetAuthorizationProvider(String),
}

impl From<QRunV06CheckpointError> for QRunV06ForkChoiceError {
    fn from(value: QRunV06CheckpointError) -> Self {
        Self::Checkpoint(value)
    }
}

impl From<QRunV06PowWireError> for QRunV06ForkChoiceError {
    fn from(value: QRunV06PowWireError) -> Self {
        Self::Wire(value)
    }
}
impl From<QRunV06ExecutionError> for QRunV06ForkChoiceError {
    fn from(value: QRunV06ExecutionError) -> Self {
        Self::Execution(value)
    }
}
impl From<ConsensusError> for QRunV06ForkChoiceError {
    fn from(value: ConsensusError) -> Self {
        Self::Consensus(value)
    }
}
impl From<PrivateConsensusError> for QRunV06ForkChoiceError {
    fn from(value: PrivateConsensusError) -> Self {
        Self::Retarget(value)
    }
}

impl std::fmt::Display for QRunV06ForkChoiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BaseMustBeGenesis => f.write_str(
                "QFP6 in-memory fork choice requires a verified Genesis execution state",
            ),
            Self::InvalidProfile => f.write_str("QFP6 fork-choice profile ID cannot be zero"),
            Self::InvalidConsensusProfile => f.write_str(
                "QFP6 fork choice requires protocol version 6 and valid consensus parameters",
            ),
            Self::MissingGenesisDescriptor => {
                f.write_str("QFP6 fork choice requires an immutable Genesis descriptor")
            }
            Self::GenesisDescriptorMismatch => {
                f.write_str("QFP6 Genesis descriptor differs from the pinned profile commitment")
            }
            Self::InvalidDifficultyWindow => {
                f.write_str("QFP6 difficulty window exceeds the bounded target-history policy")
            }
            Self::Wire(error) => write!(f, "QFP6 envelope rejected: {error}"),
            Self::Execution(error) => write!(f, "QFB6 execution rejected: {error:?}"),
            Self::Consensus(error) => write!(f, "QFP6 consensus validation failed: {error}"),
            Self::Retarget(error) => write!(f, "QFP6 branch retarget validation failed: {error}"),
            Self::WrongNetwork => f.write_str("QFP6 candidate belongs to a different network"),
            Self::WrongProfile => {
                f.write_str("QFP6 candidate belongs to a different execution profile")
            }
            Self::UnknownParent => {
                f.write_str("QFP6 candidate references an unknown parent branch")
            }
            Self::PreviousConsensusHashMismatch => f.write_str(
                "QFP6 previous-consensus hash does not link to the selected parent branch",
            ),
            Self::ExpectedTargetMismatch { .. } => {
                f.write_str("QFP6 target differs from this branch's retarget history")
            }
            Self::DuplicateDigestConflict => {
                f.write_str("one QFP6 PoW digest was presented with different envelope bytes")
            }
            Self::ArchiveCapacityExceeded => {
                f.write_str("QFP6 in-memory fork archive reached its block limit")
            }
            Self::BranchHeightExceeded => {
                f.write_str("QFP6 in-memory fork segment exceeded its height limit")
            }
            Self::ChainworkOverflow => {
                f.write_str("QFP6 cumulative chain work overflowed 256 bits")
            }
            Self::RetargetHistoryUnavailable => {
                f.write_str("QFP6 branch does not retain the timestamps required for retarget")
            }
            Self::TimestampNotAboveMedian { median, actual } => write!(
                f,
                "QFP6 timestamp {actual} is not above branch median-time-past {median}"
            ),
            Self::ReplayIncomplete => {
                f.write_str("QFP6 archive replay did not restore every accepted block")
            }
            Self::ArchiveExportLimitExceeded => {
                f.write_str("QFP6 archive export exceeded its block or byte budget")
            }
            Self::Checkpoint(error) => write!(f, "QFP6 checkpoint rejected: {error}"),
            Self::QuoteAssetAuthorizationProvider(error) => {
                write!(
                    f,
                    "QFP6 quote-asset authorization provider rejected block: {error}"
                )
            }
        }
    }
}
impl std::error::Error for QRunV06ForkChoiceError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QRunV06ForkChoiceOutcome {
    pub block_digest: [u8; 32],
    pub previous_canonical_tip: [u8; 32],
    pub canonical_tip: [u8; 32],
    pub previous_height: u64,
    pub canonical_height: u64,
    pub canonical_changed: bool,
    pub reorg_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TargetHistoryNode {
    height: u64,
    target: Uint256,
    timestamp: Option<u64>,
    parent: Option<Arc<TargetHistoryNode>>,
}

impl TargetHistoryNode {
    fn genesis_at(params: &ConsensusParameters, timestamp: u64) -> Arc<Self> {
        Self::genesis_with_timestamp(params, Some(timestamp))
    }

    fn genesis_with_timestamp(params: &ConsensusParameters, timestamp: Option<u64>) -> Arc<Self> {
        Arc::new(Self {
            height: 0,
            target: params.initial_target,
            timestamp,
            parent: None,
        })
    }

    fn validate_mtp(parent: &Arc<Self>, timestamp: u64) -> Result<(), QRunV06ForkChoiceError> {
        let mut ancestors = Vec::with_capacity(
            crate::qrun_v06_time_consensus_candidate::QFP6_MEDIAN_TIME_PAST_WINDOW,
        );
        let mut cursor = Some(Arc::clone(parent));
        while ancestors.len()
            < crate::qrun_v06_time_consensus_candidate::QFP6_MEDIAN_TIME_PAST_WINDOW
        {
            let Some(node) = cursor else { break };
            let value = node
                .timestamp
                .ok_or(QRunV06ForkChoiceError::RetargetHistoryUnavailable)?;
            ancestors.push(value);
            cursor = node.parent.as_ref().map(Arc::clone);
        }
        crate::qrun_v06_time_consensus_candidate::validate_candidate_timestamp(&ancestors, timestamp)
            .map_err(|error| match error {
                crate::qrun_v06_time_consensus_candidate::QRunV06TimeConsensusError::TimestampNotAboveMedian { median, actual } => QRunV06ForkChoiceError::TimestampNotAboveMedian { median, actual },
                crate::qrun_v06_time_consensus_candidate::QRunV06TimeConsensusError::EmptyHistory => QRunV06ForkChoiceError::RetargetHistoryUnavailable,
            })
    }
    fn expected_next_target(
        parent: &Arc<Self>,
        next_height: u64,
        params: &ConsensusParameters,
    ) -> Result<Uint256, QRunV06ForkChoiceError> {
        let expected_height = parent
            .height
            .checked_add(1)
            .ok_or(QRunV06ForkChoiceError::BranchHeightExceeded)?;
        if next_height != expected_height {
            return Err(QRunV06ForkChoiceError::RetargetHistoryUnavailable);
        }

        let window = params.difficulty_window_blocks;
        if next_height <= window || (next_height - 1) % window != 0 {
            return Ok(parent.target);
        }

        let first_height = next_height
            .checked_sub(window)
            .ok_or(QRunV06ForkChoiceError::RetargetHistoryUnavailable)?;
        let mut first = Arc::clone(parent);
        while first.height > first_height {
            first = Arc::clone(
                first
                    .parent
                    .as_ref()
                    .ok_or(QRunV06ForkChoiceError::RetargetHistoryUnavailable)?,
            );
        }
        if first.height != first_height {
            return Err(QRunV06ForkChoiceError::RetargetHistoryUnavailable);
        }

        let first_timestamp = first
            .timestamp
            .ok_or(QRunV06ForkChoiceError::RetargetHistoryUnavailable)?;
        let last_timestamp = parent
            .timestamp
            .ok_or(QRunV06ForkChoiceError::RetargetHistoryUnavailable)?;
        let observed = last_timestamp
            .checked_sub(first_timestamp)
            .ok_or(QRunV06ForkChoiceError::RetargetHistoryUnavailable)?;
        let elapsed = observed.checked_add(params.target_block_time_secs).ok_or(
            QRunV06ForkChoiceError::Consensus(ConsensusError::DifficultyOverflow),
        )?;
        Ok(target_for_next_block(
            parent.target,
            next_height,
            Some(elapsed),
            params,
        )?)
    }

    fn append(
        parent: &Arc<Self>,
        height: u64,
        target: Uint256,
        timestamp: u64,
        params: &ConsensusParameters,
    ) -> Result<Arc<Self>, QRunV06ForkChoiceError> {
        let expected_height = parent
            .height
            .checked_add(1)
            .ok_or(QRunV06ForkChoiceError::BranchHeightExceeded)?;
        if height != expected_height {
            return Err(QRunV06ForkChoiceError::BranchHeightExceeded);
        }
        if target.is_zero() || target > params.pow_limit {
            return Err(QRunV06ForkChoiceError::Consensus(
                ConsensusError::InvalidTarget,
            ));
        }
        if parent
            .timestamp
            .is_some_and(|previous| timestamp <= previous)
        {
            return Err(QRunV06ForkChoiceError::RetargetHistoryUnavailable);
        }
        Self::validate_mtp(parent, timestamp)?;
        let expected_target = Self::expected_next_target(parent, height, params)?;
        if target != expected_target {
            return Err(QRunV06ForkChoiceError::ExpectedTargetMismatch {
                expected: expected_target,
                actual: target,
            });
        }
        Ok(Arc::new(Self {
            height,
            target,
            timestamp: Some(timestamp),
            parent: Some(Arc::clone(parent)),
        }))
    }

    fn from_checkpoint_entries(
        entries: &[QRunV06TargetHistoryEntry],
        height: u64,
        params: &ConsensusParameters,
        genesis_timestamp: u64,
    ) -> Result<Arc<Self>, QRunV06ForkChoiceError> {
        if height == 0 {
            return if entries.is_empty() {
                Ok(Self::genesis_at(params, genesis_timestamp))
            } else {
                Err(QRunV06ForkChoiceError::RetargetHistoryUnavailable)
            };
        }
        if entries.is_empty() {
            return Err(QRunV06ForkChoiceError::RetargetHistoryUnavailable);
        }
        let entry_count = u64::try_from(entries.len())
            .map_err(|_| QRunV06ForkChoiceError::RetargetHistoryUnavailable)?;
        let expected_first_height = height
            .checked_sub(entry_count)
            .and_then(|first| first.checked_add(1))
            .ok_or(QRunV06ForkChoiceError::RetargetHistoryUnavailable)?;

        let mut previous: Option<Arc<Self>> = if expected_first_height == 1 {
            Some(Self::genesis_at(params, genesis_timestamp))
        } else {
            None
        };
        let mut previous_height = expected_first_height.saturating_sub(1);
        let mut previous_timestamp = genesis_timestamp;
        for entry in entries {
            let expected_height = previous_height
                .checked_add(1)
                .ok_or(QRunV06ForkChoiceError::RetargetHistoryUnavailable)?;
            if entry.height != expected_height
                || entry.target.is_zero()
                || entry.target > params.pow_limit
                || entry.timestamp <= previous_timestamp
            {
                return Err(QRunV06ForkChoiceError::RetargetHistoryUnavailable);
            }
            let node = Arc::new(Self {
                height: entry.height,
                target: entry.target,
                timestamp: Some(entry.timestamp),
                parent: previous.clone(),
            });
            previous_height = entry.height;
            previous_timestamp = entry.timestamp;
            previous = Some(node);
        }
        let latest = previous.ok_or(QRunV06ForkChoiceError::RetargetHistoryUnavailable)?;
        if latest.height != height {
            return Err(QRunV06ForkChoiceError::RetargetHistoryUnavailable);
        }
        Ok(latest)
    }
}

fn export_target_history_tail(
    history: &Arc<TargetHistoryNode>,
    max_entries: usize,
) -> Vec<QRunV06TargetHistoryEntry> {
    let mut reverse = Vec::new();
    let mut cursor = Some(Arc::clone(history));
    while let Some(node) = cursor {
        if node.height > 0 {
            if let Some(timestamp) = node.timestamp {
                reverse.push(QRunV06TargetHistoryEntry {
                    height: node.height,
                    target: node.target,
                    timestamp,
                });
            }
        }
        cursor = node.parent.as_ref().map(Arc::clone);
    }
    reverse.reverse();
    if reverse.len() > max_entries {
        reverse.drain(0..reverse.len() - max_entries);
    }
    reverse
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredQRunV06Branch {
    envelope: Vec<u8>,
    state: QRunV06CanonicalExecutionState,
    target_history: Arc<TargetHistoryNode>,
    cumulative_work: Uint256,
}

/// One bounded parent-first page from a pinned canonical fork-choice snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06CanonicalHistoryPage {
    pub start_height: u64,
    /// The next height the caller should request; unchanged only for an empty completed page.
    pub next_height: u64,
    pub snapshot_height: u64,
    pub snapshot_tip: [u8; 32],
    pub complete: bool,
    pub envelopes: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06PowForkChoice {
    network_id: [u8; 32],
    profile_id: [u8; 32],
    params: ConsensusParameters,
    base_state: QRunV06CanonicalExecutionState,
    base_tip: [u8; 32],
    base_work: Uint256,
    base_history: Arc<TargetHistoryNode>,
    canonical_tip: [u8; 32],
    branches: BTreeMap<[u8; 32], StoredQRunV06Branch>,
    reorg_count: u64,
}

impl QRunV06PowForkChoice {
    /// Module-private graph constructor. External callers must use
    /// `new_with_expected_genesis_descriptor_commitment` and provide the profile pin.
    /// This keeps self-describing Genesis data from becoming its own trust anchor.
    fn new(
        genesis_state: QRunV06CanonicalExecutionState,
        params: ConsensusParameters,
    ) -> Result<Self, QRunV06ForkChoiceError> {
        params.validate()?;
        if params.protocol_version != 6 {
            return Err(QRunV06ForkChoiceError::InvalidConsensusProfile);
        }
        if genesis_state.tokenomics().is_none()
            || genesis_state
                .validate_consensus_parameters(&params)
                .is_err()
        {
            return Err(QRunV06ForkChoiceError::InvalidConsensusProfile);
        }
        if params.difficulty_window_blocks == 0
            || params.difficulty_window_blocks > MAX_QRUN_V06_DIFFICULTY_WINDOW
        {
            return Err(QRunV06ForkChoiceError::InvalidDifficultyWindow);
        }
        if genesis_state.height() != 0 {
            return Err(QRunV06ForkChoiceError::BaseMustBeGenesis);
        }
        let descriptor = genesis_state
            .genesis_descriptor()
            .ok_or(QRunV06ForkChoiceError::MissingGenesisDescriptor)?;
        if genesis_state.last_timestamp() != descriptor.genesis_timestamp() {
            return Err(QRunV06ForkChoiceError::BaseMustBeGenesis);
        }
        let profile_id = genesis_state.profile_id();
        let network_id = genesis_state.network_id();
        if profile_id == [0; 32] {
            return Err(QRunV06ForkChoiceError::InvalidProfile);
        }
        if network_id == [0; 32] {
            return Err(QRunV06ForkChoiceError::WrongNetwork);
        }
        genesis_state.verify_invariants()?;
        let base_tip = genesis_state.tip_hash();
        let base_history = TargetHistoryNode::genesis_at(&params, descriptor.genesis_timestamp());

        Ok(Self {
            network_id,
            profile_id,
            params,
            base_state: genesis_state,
            base_tip,
            base_work: Uint256::ZERO,
            base_history,
            canonical_tip: base_tip,
            branches: BTreeMap::new(),
            reorg_count: 0,
        })
    }

    /// Require an exact externally pinned Genesis descriptor commitment before opening
    /// the graph. Node/profile bootstraps should use this instead of self-describing state.
    pub fn new_with_expected_genesis_descriptor_commitment(
        genesis_state: QRunV06CanonicalExecutionState,
        params: ConsensusParameters,
        expected_genesis_descriptor_commitment: [u8; 32],
    ) -> Result<Self, QRunV06ForkChoiceError> {
        if expected_genesis_descriptor_commitment == [0; 32]
            || genesis_state.genesis_descriptor_commitment()
                != Some(expected_genesis_descriptor_commitment)
        {
            return Err(QRunV06ForkChoiceError::GenesisDescriptorMismatch);
        }
        Self::new(genesis_state, params)
    }

    /// Module-private restore core. External callers must use
    /// `from_checkpoint_with_expected_genesis_descriptor_commitment` with the
    /// independently pinned Genesis descriptor commitment.
    fn from_checkpoint(
        checkpoint: QRunV06CheckpointCandidate,
        params: ConsensusParameters,
    ) -> Result<Self, QRunV06ForkChoiceError> {
        params.validate()?;
        if params.protocol_version != 6 {
            return Err(QRunV06ForkChoiceError::InvalidConsensusProfile);
        }
        if params.difficulty_window_blocks == 0
            || params.difficulty_window_blocks > MAX_QRUN_V06_DIFFICULTY_WINDOW
        {
            return Err(QRunV06ForkChoiceError::InvalidDifficultyWindow);
        }
        checkpoint.validate(&params)?;
        let base_state = checkpoint.execution_state().clone();
        if base_state.tokenomics().is_none() {
            return Err(QRunV06ForkChoiceError::InvalidConsensusProfile);
        }
        let descriptor = base_state
            .genesis_descriptor()
            .ok_or(QRunV06ForkChoiceError::MissingGenesisDescriptor)?;
        if base_state.validate_consensus_parameters(&params).is_err() {
            return Err(QRunV06ForkChoiceError::InvalidConsensusProfile);
        }
        let base_history = TargetHistoryNode::from_checkpoint_entries(
            checkpoint.target_history(),
            checkpoint.height(),
            &params,
            descriptor.genesis_timestamp(),
        )?;
        let base_tip = checkpoint.consensus_tip_digest();
        Ok(Self {
            network_id: checkpoint.network_id(),
            profile_id: checkpoint.profile_id(),
            params,
            base_state,
            base_tip,
            base_work: checkpoint.cumulative_work(),
            base_history,
            canonical_tip: base_tip,
            branches: BTreeMap::new(),
            reorg_count: 0,
        })
    }

    /// Require the expected Genesis descriptor to match a checkpoint before resuming.
    pub fn from_checkpoint_with_expected_genesis_descriptor_commitment(
        checkpoint: QRunV06CheckpointCandidate,
        params: ConsensusParameters,
        expected_genesis_descriptor_commitment: [u8; 32],
    ) -> Result<Self, QRunV06ForkChoiceError> {
        if expected_genesis_descriptor_commitment == [0; 32]
            || checkpoint.genesis_descriptor_commitment() != expected_genesis_descriptor_commitment
        {
            return Err(QRunV06ForkChoiceError::GenesisDescriptorMismatch);
        }
        Self::from_checkpoint(checkpoint, params)
    }

    pub fn network_id(&self) -> [u8; 32] {
        self.network_id
    }

    pub fn profile_id(&self) -> [u8; 32] {
        self.profile_id
    }

    /// The exact consensus parameters pinned when this branch graph was constructed.
    pub fn consensus_parameters(&self) -> &ConsensusParameters {
        &self.params
    }

    pub fn base_tip(&self) -> [u8; 32] {
        self.base_tip
    }

    pub fn reorg_count(&self) -> u64 {
        self.reorg_count
    }

    pub fn archive_len(&self) -> usize {
        self.branches.len()
    }

    pub fn canonical_state(&self) -> &QRunV06CanonicalExecutionState {
        self.state_for_tip(&self.canonical_tip)
            .expect("canonical tip is always the base or a retained branch")
    }

    pub fn state_for_tip(&self, tip: &[u8; 32]) -> Option<&QRunV06CanonicalExecutionState> {
        if *tip == self.base_tip {
            Some(&self.base_state)
        } else {
            self.branches.get(tip).map(|branch| &branch.state)
        }
    }

    pub fn canonical_tip(&self) -> ChainTip {
        self.tip_for_hash(&self.canonical_tip)
            .expect("canonical tip is always the base or a retained branch")
    }

    pub fn tip_for_hash(&self, tip: &[u8; 32]) -> Option<ChainTip> {
        if *tip == self.base_tip {
            return Some(ChainTip {
                height: self.base_state.height(),
                cumulative_work: self.base_work,
                tip_hash: self.base_tip,
            });
        }
        self.branches.get(tip).map(|branch| ChainTip {
            height: branch.state.height(),
            cumulative_work: branch.cumulative_work,
            tip_hash: *tip,
        })
    }

    /// Derive the next target from the exact history of the requested parent branch.
    /// Mining code must call this for the parent it is extending, never for the current
    /// canonical tip unless it is actually mining on that tip.
    pub fn expected_next_target(
        &self,
        parent_tip: &[u8; 32],
    ) -> Result<Uint256, QRunV06ForkChoiceError> {
        let (parent_state, history) = if *parent_tip == self.base_tip {
            (&self.base_state, Arc::clone(&self.base_history))
        } else {
            let branch = self
                .branches
                .get(parent_tip)
                .ok_or(QRunV06ForkChoiceError::UnknownParent)?;
            (&branch.state, Arc::clone(&branch.target_history))
        };
        let next_height = parent_state
            .height()
            .checked_add(1)
            .ok_or(QRunV06ForkChoiceError::BranchHeightExceeded)?;
        TargetHistoryNode::expected_next_target(&history, next_height, &self.params)
    }

    pub fn branch_work(&self, tip: &[u8; 32]) -> Option<Uint256> {
        if *tip == self.base_tip {
            Some(self.base_work)
        } else {
            self.branches.get(tip).map(|branch| branch.cumulative_work)
        }
    }

    pub fn base_height(&self) -> u64 {
        self.base_state.height()
    }

    pub fn base_work(&self) -> Uint256 {
        self.base_work
    }

    /// Export a full-state checkpoint for any retained branch tip.
    /// The returned commitment must be persisted outside the archive before this checkpoint
    /// is accepted by another process as a new fork-choice base.
    pub fn checkpoint_at_tip(
        &self,
        tip: &[u8; 32],
    ) -> Result<QRunV06CheckpointCandidate, QRunV06ForkChoiceError> {
        let state = self
            .state_for_tip(tip)
            .ok_or(QRunV06ForkChoiceError::UnknownParent)?;
        let work = self
            .branch_work(tip)
            .ok_or(QRunV06ForkChoiceError::UnknownParent)?;
        let history = if *tip == self.base_tip {
            Arc::clone(&self.base_history)
        } else {
            Arc::clone(
                &self
                    .branches
                    .get(tip)
                    .ok_or(QRunV06ForkChoiceError::UnknownParent)?
                    .target_history,
            )
        };
        let entries = export_target_history_tail(
            &history,
            self.params.difficulty_window_blocks.max(
                (crate::qrun_v06_time_consensus_candidate::QFP6_MEDIAN_TIME_PAST_WINDOW + 1) as u64,
            ) as usize,
        );
        Ok(QRunV06CheckpointCandidate::from_validated_branch(
            state.clone(),
            *tip,
            work,
            entries,
            &self.params,
        )?)
    }

    pub fn canonical_checkpoint(
        &self,
    ) -> Result<QRunV06CheckpointCandidate, QRunV06ForkChoiceError> {
        self.checkpoint_at_tip(&self.canonical_tip)
    }

    pub fn archive_envelopes(&self) -> Vec<Vec<u8>> {
        self.branches
            .values()
            .map(|branch| branch.envelope.clone())
            .collect()
    }

    pub fn archive_envelopes_bounded(
        &self,
        max_blocks: usize,
        max_bytes: usize,
    ) -> Result<Vec<Vec<u8>>, QRunV06ForkChoiceError> {
        if max_blocks == 0 || self.branches.len() > max_blocks {
            return Err(QRunV06ForkChoiceError::ArchiveExportLimitExceeded);
        }
        let mut total = 0usize;
        for branch in self.branches.values() {
            total = total
                .checked_add(branch.envelope.len())
                .ok_or(QRunV06ForkChoiceError::ArchiveExportLimitExceeded)?;
            if total > max_bytes {
                return Err(QRunV06ForkChoiceError::ArchiveExportLimitExceeded);
            }
        }
        Ok(self.archive_envelopes())
    }

    /// Export the selected canonical path in parent-to-tip order.
    pub fn canonical_envelopes(&self) -> Result<Vec<Vec<u8>>, QRunV06ForkChoiceError> {
        let mut reverse = Vec::new();
        let mut tip = self.canonical_tip;
        while tip != self.base_tip {
            if reverse.len() >= MAX_QRUN_V06_FORK_BRANCH_HEIGHT as usize {
                return Err(QRunV06ForkChoiceError::ReplayIncomplete);
            }
            let branch = self
                .branches
                .get(&tip)
                .ok_or(QRunV06ForkChoiceError::UnknownParent)?;
            let decoded = decode_qrun_v06_pow_block(&branch.envelope)?;
            let digest = pow_digest(&decoded.header, self.params.pow)?;
            if digest != tip {
                return Err(QRunV06ForkChoiceError::ReplayIncomplete);
            }
            tip = decoded.header.previous_consensus_hash;
            reverse.push(branch.envelope.clone());
        }
        reverse.reverse();
        Ok(reverse)
    }

    /// Export a bounded parent-first page from an immutable fork-choice snapshot.
    ///
    /// Pass a clone returned by the permissionless runtime's fork_choice_snapshot and keep
    /// it for the whole sync. This pins one canonical tip while the live node continues
    /// mining or accepting peers. The method retains at most max_blocks envelopes and
    /// never exports side branches.
    pub fn canonical_history_page(
        &self,
        start_height: u64,
        max_blocks: usize,
        max_bytes: usize,
    ) -> Result<QRunV06CanonicalHistoryPage, QRunV06ForkChoiceError> {
        const MAX_PAGE_BLOCKS: usize = 128;
        const MAX_PAGE_BYTES: usize = 16 * 1024 * 1024;

        if max_blocks == 0
            || max_blocks > MAX_PAGE_BLOCKS
            || max_bytes == 0
            || max_bytes > MAX_PAGE_BYTES
        {
            return Err(QRunV06ForkChoiceError::ArchiveExportLimitExceeded);
        }

        let snapshot_tip = self.canonical_tip();
        let first_height = self
            .base_state
            .height()
            .checked_add(1)
            .ok_or(QRunV06ForkChoiceError::ArchiveExportLimitExceeded)?;
        let after_tip = snapshot_tip
            .height
            .checked_add(1)
            .ok_or(QRunV06ForkChoiceError::ArchiveExportLimitExceeded)?;
        if start_height < first_height || start_height > after_tip {
            return Err(QRunV06ForkChoiceError::ArchiveExportLimitExceeded);
        }

        let mut selected_reverse: Vec<(u64, usize, Vec<u8>)> = Vec::with_capacity(max_blocks);
        let mut selected_bytes = 0usize;
        let mut tip = self.canonical_tip;
        while tip != self.base_tip {
            if selected_reverse.len() >= MAX_QRUN_V06_FORK_BRANCH_HEIGHT as usize {
                return Err(QRunV06ForkChoiceError::ReplayIncomplete);
            }
            let branch = self
                .branches
                .get(&tip)
                .ok_or(QRunV06ForkChoiceError::UnknownParent)?;
            let decoded = decode_qrun_v06_pow_block(&branch.envelope)?;
            let digest = pow_digest(&decoded.header, self.params.pow)?;
            if digest != tip {
                return Err(QRunV06ForkChoiceError::ReplayIncomplete);
            }
            let height = decoded.header.height;
            if height < start_height {
                break;
            }
            let encoded_len = branch.envelope.len();
            if encoded_len > max_bytes {
                return Err(QRunV06ForkChoiceError::ArchiveExportLimitExceeded);
            }
            while selected_reverse.len() >= max_blocks
                || selected_bytes
                    .checked_add(encoded_len)
                    .is_none_or(|total| total > max_bytes)
            {
                if selected_reverse.is_empty() {
                    return Err(QRunV06ForkChoiceError::ArchiveExportLimitExceeded);
                }
                let (_, removed_len, _) = selected_reverse.remove(0);
                selected_bytes = selected_bytes
                    .checked_sub(removed_len)
                    .ok_or(QRunV06ForkChoiceError::ArchiveExportLimitExceeded)?;
            }
            selected_bytes = selected_bytes
                .checked_add(encoded_len)
                .ok_or(QRunV06ForkChoiceError::ArchiveExportLimitExceeded)?;
            selected_reverse.push((height, encoded_len, branch.envelope.clone()));
            tip = decoded.header.previous_consensus_hash;
        }

        selected_reverse.reverse();
        let mut envelopes = Vec::with_capacity(selected_reverse.len());
        for (_, _, envelope) in selected_reverse {
            envelopes.push(envelope);
        }
        let next_height = if let Some(last) = envelopes.last() {
            decode_qrun_v06_pow_block(last)?
                .header
                .height
                .checked_add(1)
                .ok_or(QRunV06ForkChoiceError::ArchiveExportLimitExceeded)?
        } else {
            start_height
        };
        Ok(QRunV06CanonicalHistoryPage {
            start_height,
            next_height,
            snapshot_height: snapshot_tip.height,
            snapshot_tip: snapshot_tip.tip_hash,
            complete: next_height > snapshot_tip.height,
            envelopes,
        })
    }

    /// Validate and import one QFP6 block on its exact parent branch.
    ///
    /// The candidate is applied to a clone of that parent's QFB6 execution state. The branch
    /// is published to the graph only after link, target, PoW, execution, state-root and
    /// chainwork checks all succeed.
    pub fn insert_encoded<A: TransactionAuthenticator>(
        &mut self,
        envelope: &[u8],
        authenticator: &A,
    ) -> Result<QRunV06ForkChoiceOutcome, QRunV06ForkChoiceError> {
        self.insert_encoded_inner(envelope, authenticator, None)
    }

    /// Import a block only after obtaining a fresh quote-asset authorization for its
    /// exact height and parent state. Reorg branches use the same provider path; a token
    /// from another height is refused by QFB6 before the branch can be published.
    pub fn insert_encoded_with_quote_asset_authorization<A: TransactionAuthenticator>(
        &mut self,
        envelope: &[u8],
        authenticator: &A,
        provider: &mut QRunV06QuoteAssetAuthorizationProvider<'_>,
    ) -> Result<QRunV06ForkChoiceOutcome, QRunV06ForkChoiceError> {
        self.insert_encoded_inner(envelope, authenticator, Some(provider))
    }

    fn insert_encoded_inner<A: TransactionAuthenticator>(
        &mut self,
        envelope: &[u8],
        authenticator: &A,
        mut provider: Option<&mut QRunV06QuoteAssetAuthorizationProvider<'_>>,
    ) -> Result<QRunV06ForkChoiceOutcome, QRunV06ForkChoiceError> {
        let decoded = decode_qrun_v06_pow_block(envelope)?;
        if decoded.header.network_id != self.network_id
            || decoded.block.network_id != self.network_id
        {
            return Err(QRunV06ForkChoiceError::WrongNetwork);
        }
        if decoded.block.profile_id != self.profile_id {
            return Err(QRunV06ForkChoiceError::WrongProfile);
        }

        let digest = pow_digest(&decoded.header, self.params.pow)?;
        if let Some(existing) = self.branches.get(&digest) {
            if existing.envelope.as_slice() != envelope {
                return Err(QRunV06ForkChoiceError::DuplicateDigestConflict);
            }
            let height = self.canonical_state().height();
            return Ok(QRunV06ForkChoiceOutcome {
                block_digest: digest,
                previous_canonical_tip: self.canonical_tip,
                canonical_tip: self.canonical_tip,
                previous_height: height,
                canonical_height: height,
                canonical_changed: false,
                reorg_count: self.reorg_count,
            });
        }
        if self.branches.len() >= MAX_QRUN_V06_FORK_ARCHIVE_BLOCKS {
            return Err(QRunV06ForkChoiceError::ArchiveCapacityExceeded);
        }

        let parent_tip = decoded.header.previous_consensus_hash;
        let (mut next_state, parent_history, parent_work) = if parent_tip == self.base_tip {
            (
                self.base_state.clone(),
                Arc::clone(&self.base_history),
                self.base_work,
            )
        } else {
            let parent = self
                .branches
                .get(&parent_tip)
                .ok_or(QRunV06ForkChoiceError::UnknownParent)?;
            (
                parent.state.clone(),
                Arc::clone(&parent.target_history),
                parent.cumulative_work,
            )
        };

        let maximum_height = self
            .base_state
            .height()
            .saturating_add(MAX_QRUN_V06_FORK_BRANCH_HEIGHT);
        if decoded.block.height > maximum_height {
            return Err(QRunV06ForkChoiceError::BranchHeightExceeded);
        }
        if decoded.header.previous_consensus_hash != parent_tip {
            return Err(QRunV06ForkChoiceError::PreviousConsensusHashMismatch);
        }

        let expected_target = TargetHistoryNode::expected_next_target(
            &parent_history,
            decoded.block.height,
            &self.params,
        )?;
        if decoded.header.target != expected_target {
            return Err(QRunV06ForkChoiceError::ExpectedTargetMismatch {
                expected: expected_target,
                actual: decoded.header.target,
            });
        }

        // QFP6 header/body bindings and actual PoW are verified before executing QFB6.
        let _ = verify_qrun_v06_pow_block(&decoded, &self.params)
            .map_err(QRunV06ForkChoiceError::Wire)?;

        // A separate parent-consensus link is required in addition to QFB6's parent state hash.
        if decoded.header.previous_consensus_hash != parent_tip {
            return Err(QRunV06ForkChoiceError::PreviousConsensusHashMismatch);
        }
        if decoded.block.parent_hash != next_state.tip_hash() {
            return Err(QRunV06ForkChoiceError::Execution(
                QRunV06ExecutionError::ParentHashMismatch,
            ));
        }

        let next_history = TargetHistoryNode::append(
            &parent_history,
            decoded.block.height,
            decoded.header.target,
            decoded.block.timestamp,
            &self.params,
        )?;

        let required_quote_asset = next_state.required_quote_asset_for_block(&decoded.block)?;
        let quote_authorization = match required_quote_asset {
            Some(asset_id) => {
                let authorize =
                    provider
                        .as_deref_mut()
                        .ok_or(QRunV06ForkChoiceError::Execution(
                            QRunV06ExecutionError::MissingQuoteAssetAuthorization,
                        ))?;
                Some(
                    authorize(&next_state, &decoded.block, asset_id).map_err(|error| {
                        QRunV06ForkChoiceError::QuoteAssetAuthorizationProvider(error)
                    })?,
                )
            }
            None => None,
        };
        next_state.apply_block_with_quote_asset_authorization(
            &decoded.block,
            authenticator,
            quote_authorization.as_ref(),
        )?;
        let work = block_work(decoded.header.target)?;
        let cumulative_work = parent_work
            .checked_add(work)
            .ok_or(QRunV06ForkChoiceError::ChainworkOverflow)?;

        let previous_canonical_tip = self.canonical_tip;
        let previous_height = self.canonical_state().height();

        self.branches.insert(
            digest,
            StoredQRunV06Branch {
                envelope: envelope.to_vec(),
                state: next_state,
                target_history: next_history,
                cumulative_work,
            },
        );

        let (best_tip, _) = self.select_best_tip();
        if best_tip != previous_canonical_tip {
            if !self.is_ancestor(previous_canonical_tip, best_tip) {
                self.reorg_count = self.reorg_count.saturating_add(1);
            }
            self.canonical_tip = best_tip;
        }

        let canonical_height = self.canonical_state().height();
        Ok(QRunV06ForkChoiceOutcome {
            block_digest: digest,
            previous_canonical_tip,
            canonical_tip: self.canonical_tip,
            previous_height,
            canonical_height,
            canonical_changed: previous_canonical_tip != self.canonical_tip,
            reorg_count: self.reorg_count,
        })
    }

    fn select_best_tip(&self) -> ([u8; 32], ChainTip) {
        let mut best = ChainTip {
            height: self.base_state.height(),
            cumulative_work: self.base_work,
            tip_hash: self.base_tip,
        };
        for (digest, branch) in &self.branches {
            let candidate = ChainTip {
                height: branch.state.height(),
                cumulative_work: branch.cumulative_work,
                tip_hash: *digest,
            };
            if compare_chain_tips(candidate, best).is_gt() {
                best = candidate;
            }
        }
        (best.tip_hash, best)
    }

    fn is_ancestor(&self, ancestor: [u8; 32], mut tip: [u8; 32]) -> bool {
        if ancestor == self.base_tip {
            return true;
        }
        for _ in 0..=MAX_QRUN_V06_FORK_BRANCH_HEIGHT {
            if tip == ancestor {
                return true;
            }
            if tip == self.base_tip {
                return false;
            }
            let Some(branch) = self.branches.get(&tip) else {
                return false;
            };
            let Ok(decoded) = decode_qrun_v06_pow_block(&branch.envelope) else {
                return false;
            };
            tip = decoded.header.previous_consensus_hash;
        }
        false
    }

    /// Rebuild a post-checkpoint segment on this exact trusted base. The supplied archive
    /// must contain only descendants of the current base consensus digest.
    pub fn rebuild_from_current_base<A: TransactionAuthenticator>(
        &self,
        envelopes: impl IntoIterator<Item = Vec<u8>>,
        authenticator: &A,
    ) -> Result<Self, QRunV06ForkChoiceError> {
        self.rebuild_from_current_base_inner(envelopes, authenticator, None)
    }

    pub fn rebuild_from_current_base_with_quote_asset_authorization<A: TransactionAuthenticator>(
        &self,
        envelopes: impl IntoIterator<Item = Vec<u8>>,
        authenticator: &A,
        provider: &mut QRunV06QuoteAssetAuthorizationProvider<'_>,
    ) -> Result<Self, QRunV06ForkChoiceError> {
        self.rebuild_from_current_base_inner(envelopes, authenticator, Some(provider))
    }

    fn rebuild_from_current_base_inner<A: TransactionAuthenticator>(
        &self,
        envelopes: impl IntoIterator<Item = Vec<u8>>,
        authenticator: &A,
        mut provider: Option<&mut QRunV06QuoteAssetAuthorizationProvider<'_>>,
    ) -> Result<Self, QRunV06ForkChoiceError> {
        let mut ordered = Vec::new();
        for envelope in envelopes {
            let decoded = decode_qrun_v06_pow_block(&envelope)?;
            let digest = pow_digest(&decoded.header, self.params.pow)?;
            ordered.push((decoded.block.height, digest, envelope));
        }
        ordered.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
        let expected_count = ordered.len();
        if expected_count > MAX_QRUN_V06_FORK_ARCHIVE_BLOCKS {
            return Err(QRunV06ForkChoiceError::ArchiveCapacityExceeded);
        }
        let mut graph = self.clone();
        graph.branches.clear();
        graph.canonical_tip = graph.base_tip;
        graph.reorg_count = 0;
        for (_, _, envelope) in ordered {
            if let Some(authorize) = provider.as_deref_mut() {
                graph.insert_encoded_with_quote_asset_authorization(
                    &envelope,
                    authenticator,
                    authorize,
                )?;
            } else {
                graph.insert_encoded(&envelope, authenticator)?;
            }
        }
        if graph.archive_len() != expected_count {
            return Err(QRunV06ForkChoiceError::ReplayIncomplete);
        }
        Ok(graph)
    }

    /// Rebuild a Genesis-rooted archive only after matching its Genesis descriptor
    /// against the commitment pinned by the selected Network/Profile configuration.
    pub fn rebuild_from_envelopes_with_expected_genesis_descriptor_commitment<
        A: TransactionAuthenticator,
    >(
        genesis_state: QRunV06CanonicalExecutionState,
        params: ConsensusParameters,
        envelopes: impl IntoIterator<Item = Vec<u8>>,
        authenticator: &A,
        expected_genesis_descriptor_commitment: [u8; 32],
    ) -> Result<Self, QRunV06ForkChoiceError> {
        if expected_genesis_descriptor_commitment == [0; 32]
            || genesis_state.genesis_descriptor_commitment()
                != Some(expected_genesis_descriptor_commitment)
        {
            return Err(QRunV06ForkChoiceError::GenesisDescriptorMismatch);
        }
        Self::rebuild_from_envelopes(genesis_state, params, envelopes, authenticator)
    }

    pub fn rebuild_from_envelopes_with_quote_asset_authorization<A: TransactionAuthenticator>(
        genesis_state: QRunV06CanonicalExecutionState,
        params: ConsensusParameters,
        envelopes: impl IntoIterator<Item = Vec<u8>>,
        authenticator: &A,
        expected_genesis_descriptor_commitment: [u8; 32],
        provider: &mut QRunV06QuoteAssetAuthorizationProvider<'_>,
    ) -> Result<Self, QRunV06ForkChoiceError> {
        if expected_genesis_descriptor_commitment == [0; 32]
            || genesis_state.genesis_descriptor_commitment()
                != Some(expected_genesis_descriptor_commitment)
        {
            return Err(QRunV06ForkChoiceError::GenesisDescriptorMismatch);
        }
        let mut ordered = Vec::new();
        for envelope in envelopes {
            let decoded = decode_qrun_v06_pow_block(&envelope)?;
            let digest = pow_digest(&decoded.header, params.pow)?;
            ordered.push((decoded.block.height, digest, envelope));
        }
        ordered.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
        let expected_count = ordered.len();
        if expected_count > MAX_QRUN_V06_FORK_ARCHIVE_BLOCKS {
            return Err(QRunV06ForkChoiceError::ArchiveCapacityExceeded);
        }
        let mut graph = Self::new(genesis_state, params)?;
        for (_, _, envelope) in ordered {
            graph.insert_encoded_with_quote_asset_authorization(
                &envelope,
                authenticator,
                provider,
            )?;
        }
        if graph.archive_len() != expected_count {
            return Err(QRunV06ForkChoiceError::ReplayIncomplete);
        }
        Ok(graph)
    }

    /// Module-private archive replay core. External callers must use the
    /// commitment-pinned `rebuild_from_envelopes_with_expected_genesis_descriptor_commitment`.
    fn rebuild_from_envelopes<A: TransactionAuthenticator>(
        genesis_state: QRunV06CanonicalExecutionState,
        params: ConsensusParameters,
        envelopes: impl IntoIterator<Item = Vec<u8>>,
        authenticator: &A,
    ) -> Result<Self, QRunV06ForkChoiceError> {
        let mut ordered = Vec::new();
        for envelope in envelopes {
            let decoded = decode_qrun_v06_pow_block(&envelope)?;
            let digest = pow_digest(&decoded.header, params.pow)?;
            ordered.push((decoded.block.height, digest, envelope));
        }
        ordered.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));

        let expected_count = ordered.len();
        if expected_count > MAX_QRUN_V06_FORK_ARCHIVE_BLOCKS {
            return Err(QRunV06ForkChoiceError::ArchiveCapacityExceeded);
        }
        let mut graph = Self::new(genesis_state, params)?;
        for (_, _, envelope) in ordered {
            graph.insert_encoded(&envelope, authenticator)?;
        }
        if graph.archive_len() != expected_count {
            return Err(QRunV06ForkChoiceError::ReplayIncomplete);
        }
        Ok(graph)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        consensus::{PowAlgorithm, PowParameters},
        issuance_schedule::IssuanceParameters,
        qrun_v06_canonical_execution_candidate::{
            QRunV06Block, QRunV06BlockOperation, QRunV06CanonicalExecutionState,
        },
        qrun_v06_pow_wire_candidate::{encode_qrun_v06_pow_block, qrun_v06_pow_state_commitment},
        qrun_v06_tokenomics_candidate::QRunV06MiningScheduleCandidate,
        qrun_v06_unified_asset_candidate::QRunV06UnifiedAssetState,
        qzxb_amm_candidate::QzxbAmmStateCandidate,
        state_machine::{
            transaction_signing_digest, AccountId, LedgerState, Transaction,
            TransactionAuthenticator,
        },
    };

    const NETWORK: [u8; 32] = [0x61; 32];
    const PROFILE: [u8; 32] = [0x62; 32];
    const ALICE: [u8; 32] = [0x63; 32];
    const BOB: [u8; 32] = [0x64; 32];
    const PRODUCER: [u8; 32] = [0x65; 32];

    struct DigestAuthenticator;
    impl TransactionAuthenticator for DigestAuthenticator {
        fn verify(
            &self,
            sender: &AccountId,
            digest: &[u8; 32],
            signature: &[u8],
        ) -> Result<(), ()> {
            if sender.iter().any(|byte| *byte != 0) && signature == digest {
                Ok(())
            } else {
                Err(())
            }
        }
    }

    fn params(window: u64) -> ConsensusParameters {
        let mut params = ConsensusParameters::candidate_testnet().unwrap();
        params.protocol_version = 6;
        params.target_block_time_secs = 30;
        params.difficulty_window_blocks = window;
        params.difficulty_min_ratio_divisor = 4;
        params.difficulty_max_ratio = 4;
        params.pow_limit = Uint256::MAX;
        params.initial_target = Uint256::from_be_bytes([0x7F; 32]);
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

    fn genesis_state_for_profile(
        profile: [u8; 32],
        params: &ConsensusParameters,
    ) -> QRunV06CanonicalExecutionState {
        let schedule = QRunV06MiningScheduleCandidate::cp0422_research_candidate();
        let tokenomics = crate::qrun_v06_tokenomics_candidate::QRunV06TokenomicsState::genesis(
            NETWORK, ALICE, schedule,
        )
        .unwrap();
        let descriptor =
            crate::qrun_v06_genesis_descriptor_candidate::QRunV06GenesisDescriptor::new(
                NETWORK,
                profile,
                ALICE,
                1,
                crate::qrun_v06_checkpoint_candidate::qrun_v06_consensus_fingerprint(params)
                    .unwrap(),
                tokenomics.policy_fingerprint(),
            )
            .unwrap();
        QRunV06CanonicalExecutionState::cp0528_genesis_candidate_with_descriptor(
            descriptor, schedule,
        )
        .unwrap()
    }

    fn genesis_state(params: &ConsensusParameters) -> QRunV06CanonicalExecutionState {
        genesis_state_for_profile(PROFILE, params)
    }

    fn signed_transfer(amount: u64) -> QRunV06BlockOperation {
        let mut tx = Transaction {
            network_id: NETWORK,
            sender: ALICE,
            recipient: BOB,
            nonce: 1,
            amount,
            fee: 0,
            expires_at: 100_000,
            signature: Vec::new(),
        };
        tx.signature = transaction_signing_digest(&tx).unwrap().to_vec();
        QRunV06BlockOperation::NativeTransfer(tx)
    }

    fn signed_category_release(
        nonce: u64,
        recipient: AccountId,
        amount_atoms: u128,
    ) -> QRunV06BlockOperation {
        use crate::qrun_v06_tokenomics_candidate::{
            QRunV06AllocationBucket, QRunV06SignedCategoryRelease,
        };
        let mut release = QRunV06SignedCategoryRelease {
            network_id: NETWORK,
            bucket: QRunV06AllocationBucket::CommunityAirdrop,
            nonce,
            recipient,
            amount_atoms,
            valid_until_timestamp: 100_000,
            purpose_digest: [0xD1; 32],
            evidence_digest: [0xD2; 32],
            milestone_policy_digest: [0xD3; 32],
            founder_signature: Vec::new(),
            recipient_acceptance_signature: Vec::new(),
        };
        release.founder_signature = release.signing_digest().unwrap().to_vec();
        release.recipient_acceptance_signature =
            release.recipient_acceptance_digest().unwrap().to_vec();
        QRunV06BlockOperation::CategoryRelease(release)
    }

    fn make_candidate(
        parent: &QRunV06CanonicalExecutionState,
        previous_consensus_hash: [u8; 32],
        timestamp: u64,
        target: Uint256,
        operations: Vec<QRunV06BlockOperation>,
        params: &ConsensusParameters,
    ) -> (Vec<u8>, [u8; 32]) {
        let mut block = QRunV06Block {
            network_id: NETWORK,
            profile_id: parent.profile_id(),
            height: parent.height() + 1,
            timestamp,
            parent_hash: parent.tip_hash(),
            state_root: [0; 32],
            producer: PRODUCER,
            operations,
        };
        block.state_root = parent
            .preview_state_root_after(&block, &DigestAuthenticator)
            .unwrap();

        let mut header = crate::consensus::PowHeader {
            protocol_version: 6,
            network_id: NETWORK,
            height: block.height,
            timestamp,
            parent_hash: block.parent_hash,
            previous_consensus_hash,
            state_root: qrun_v06_pow_state_commitment(&block).unwrap(),
            target,
            nonce: 0,
        };

        for nonce in 0..4_096u64 {
            header.nonce = nonce;
            let digest = pow_digest(&header, params.pow).unwrap();
            if Uint256::from_be_bytes(digest) <= target {
                let envelope = encode_qrun_v06_pow_block(&header, &block).unwrap();
                return (envelope, digest);
            }
        }
        panic!("test PoW nonce search exhausted");
    }

    fn make_quote_authorized_candidate(
        parent: &QRunV06CanonicalExecutionState,
        previous_consensus_hash: [u8; 32],
        timestamp: u64,
        target: Uint256,
        quote_authorization: &crate::qrun_v06_profile_trust_candidate::QRunV06TrustAuthorizedQuoteAsset,
        params: &ConsensusParameters,
    ) -> (Vec<u8>, [u8; 32]) {
        let mut block = QRunV06Block {
            network_id: NETWORK,
            profile_id: parent.profile_id(),
            height: parent.height() + 1,
            timestamp,
            parent_hash: parent.tip_hash(),
            state_root: [0; 32],
            producer: PRODUCER,
            operations: Vec::new(),
        };
        block.state_root = parent
            .preview_state_root_after_with_quote_asset_authorization(
                &block,
                &DigestAuthenticator,
                Some(quote_authorization),
            )
            .unwrap();
        let mut header = crate::consensus::PowHeader {
            protocol_version: 6,
            network_id: NETWORK,
            height: block.height,
            timestamp,
            parent_hash: block.parent_hash,
            previous_consensus_hash,
            state_root: qrun_v06_pow_state_commitment(&block).unwrap(),
            target,
            nonce: 0,
        };
        for nonce in 0..4_096u64 {
            header.nonce = nonce;
            let digest = pow_digest(&header, params.pow).unwrap();
            if Uint256::from_be_bytes(digest) <= target {
                return (encode_qrun_v06_pow_block(&header, &block).unwrap(), digest);
            }
        }
        panic!("test quote-authorized PoW nonce search exhausted");
    }

    #[test]
    fn qfp6_fork_choice_requires_fresh_quote_authorization_per_block_and_replay() {
        let params = params(8);
        let mut genesis = genesis_state(&params);
        let quote_asset = [0xE1; 32];
        let q6qa_commitment = [0xE2; 32];
        let q6pn_commitment = [0xE3; 32];
        genesis.install_test_quote_asset_authorization(
            quote_asset,
            q6qa_commitment,
            q6pn_commitment,
            7,
            1,
            100,
            4,
        );
        let mut graph = QRunV06PowForkChoice::new(genesis.clone(), params.clone()).unwrap();

        let first_authorization =
            crate::qrun_v06_profile_trust_candidate::test_trust_authorized_quote_asset_candidate(
                NETWORK,
                PROFILE,
                quote_asset,
                q6qa_commitment,
                q6pn_commitment,
                7,
                1,
                100,
                4,
                1,
            );
        let (block1, _tip1) = make_quote_authorized_candidate(
            &genesis,
            graph.base_tip(),
            100,
            params.initial_target,
            &first_authorization,
            &params,
        );

        let mut legacy_graph = graph.clone();
        assert!(matches!(
            legacy_graph.insert_encoded(&block1, &DigestAuthenticator),
            Err(QRunV06ForkChoiceError::Execution(
                QRunV06ExecutionError::MissingQuoteAssetAuthorization
            ))
        ));
        assert_eq!(legacy_graph.archive_len(), 0);

        let mut stale_provider = |_: &QRunV06CanonicalExecutionState,
                                  block: &QRunV06Block,
                                  asset_id: [u8; 32]| {
            assert_eq!(asset_id, quote_asset);
            Ok(crate::qrun_v06_profile_trust_candidate::test_trust_authorized_quote_asset_candidate(
                NETWORK,
                PROFILE,
                asset_id,
                q6qa_commitment,
                q6pn_commitment,
                7,
                1,
                100,
                4,
                block.height.saturating_sub(1),
            ))
        };
        assert!(matches!(
            graph.insert_encoded_with_quote_asset_authorization(
                &block1,
                &DigestAuthenticator,
                &mut stale_provider,
            ),
            Err(QRunV06ForkChoiceError::Execution(
                QRunV06ExecutionError::QuoteAssetAuthorizationMismatch
            ))
        ));
        assert_eq!(
            graph.archive_len(),
            0,
            "failed authorization must not publish a branch"
        );

        let observed_heights = std::cell::RefCell::new(Vec::new());
        let mut provider = |state: &QRunV06CanonicalExecutionState,
                            block: &QRunV06Block,
                            asset_id: [u8; 32]| {
            assert_eq!(state.network_id(), NETWORK);
            assert_eq!(state.profile_id(), PROFILE);
            assert_eq!(asset_id, quote_asset);
            observed_heights.borrow_mut().push(block.height);
            Ok(crate::qrun_v06_profile_trust_candidate::test_trust_authorized_quote_asset_candidate(
                NETWORK,
                PROFILE,
                asset_id,
                q6qa_commitment,
                q6pn_commitment,
                7,
                1,
                100,
                4,
                block.height,
            ))
        };
        graph
            .insert_encoded_with_quote_asset_authorization(
                &block1,
                &DigestAuthenticator,
                &mut provider,
            )
            .unwrap();
        assert_eq!(observed_heights.borrow().as_slice(), &[1]);
        assert_eq!(graph.archive_len(), 1);

        let parent = graph.canonical_state().clone();
        let second_authorization =
            crate::qrun_v06_profile_trust_candidate::test_trust_authorized_quote_asset_candidate(
                NETWORK,
                PROFILE,
                quote_asset,
                q6qa_commitment,
                q6pn_commitment,
                7,
                1,
                100,
                4,
                2,
            );
        let (block2, _tip2) = make_quote_authorized_candidate(
            &parent,
            graph.canonical_tip().tip_hash,
            130,
            params.initial_target,
            &second_authorization,
            &params,
        );
        graph
            .insert_encoded_with_quote_asset_authorization(
                &block2,
                &DigestAuthenticator,
                &mut provider,
            )
            .unwrap();
        assert_eq!(observed_heights.borrow().as_slice(), &[1, 2]);
        assert_eq!(graph.canonical_state().height(), 2);

        let envelopes = graph.canonical_envelopes().unwrap();
        let replay_base = QRunV06PowForkChoice::new(genesis, params.clone()).unwrap();
        let replayed_heights = std::cell::RefCell::new(Vec::new());
        let mut replay_provider = |_state: &QRunV06CanonicalExecutionState,
                                   block: &QRunV06Block,
                                   asset_id: [u8; 32]| {
            assert_eq!(asset_id, quote_asset);
            replayed_heights.borrow_mut().push(block.height);
            Ok(crate::qrun_v06_profile_trust_candidate::test_trust_authorized_quote_asset_candidate(
                NETWORK,
                PROFILE,
                asset_id,
                q6qa_commitment,
                q6pn_commitment,
                7,
                1,
                100,
                4,
                block.height,
            ))
        };
        let replayed = QRunV06PowForkChoice::rebuild_from_envelopes_with_quote_asset_authorization(
            replay_base.canonical_state().clone(),
            params,
            envelopes,
            &DigestAuthenticator,
            replay_base
                .canonical_state()
                .genesis_descriptor_commitment()
                .unwrap(),
            &mut replay_provider,
        )
        .unwrap();
        assert_eq!(replayed_heights.borrow().as_slice(), &[1, 2]);
        assert_eq!(
            replayed.canonical_state().state_root().unwrap(),
            graph.canonical_state().state_root().unwrap()
        );
    }

    #[test]
    fn qfp6_mtp_is_computed_from_the_exact_parent_branch() {
        let params = params(2);
        let build = |start: u64| {
            let mut parent = TargetHistoryNode::genesis_at(&params, 1);
            for offset in 0..11u64 {
                parent = Arc::new(TargetHistoryNode {
                    height: parent.height + 1,
                    target: params.initial_target,
                    timestamp: Some(start + offset * 10),
                    parent: Some(parent),
                });
            }
            parent
        };
        let branch_a = build(10);
        let branch_b = build(20);
        assert_eq!(TargetHistoryNode::validate_mtp(&branch_a, 65), Ok(()));
        assert_eq!(
            TargetHistoryNode::validate_mtp(&branch_b, 65),
            Err(QRunV06ForkChoiceError::TimestampNotAboveMedian {
                median: 70,
                actual: 65
            })
        );
    }
    #[test]
    fn qfp6_difficulty_retarget_remains_branch_local_across_siblings() {
        let mut params = params(2);
        params.initial_target = Uint256::from_be_bytes([0x1F; 32]);
        params.validate().unwrap();

        let genesis = TargetHistoryNode::genesis_at(&params, 1_000);
        let fast_first =
            TargetHistoryNode::append(&genesis, 1, params.initial_target, 1_005, &params).unwrap();
        let fast_parent =
            TargetHistoryNode::append(&fast_first, 2, params.initial_target, 1_010, &params)
                .unwrap();

        let slow_first =
            TargetHistoryNode::append(&genesis, 1, params.initial_target, 1_030, &params).unwrap();
        let slow_parent =
            TargetHistoryNode::append(&slow_first, 2, params.initial_target, 1_090, &params)
                .unwrap();

        let fast_target =
            TargetHistoryNode::expected_next_target(&fast_parent, 3, &params).unwrap();
        let slow_target =
            TargetHistoryNode::expected_next_target(&slow_parent, 3, &params).unwrap();

        assert!(fast_target < params.initial_target);
        assert!(slow_target > params.initial_target);
        assert_ne!(fast_target, slow_target);

        let fast_checkpoint_tail = export_target_history_tail(
            &fast_parent,
            params.difficulty_window_blocks.max(
                (crate::qrun_v06_time_consensus_candidate::QFP6_MEDIAN_TIME_PAST_WINDOW + 1) as u64,
            ) as usize,
        );
        let slow_checkpoint_tail = export_target_history_tail(
            &slow_parent,
            params.difficulty_window_blocks.max(
                (crate::qrun_v06_time_consensus_candidate::QFP6_MEDIAN_TIME_PAST_WINDOW + 1) as u64,
            ) as usize,
        );
        let fast_restored =
            TargetHistoryNode::from_checkpoint_entries(&fast_checkpoint_tail, 2, &params, 1_000)
                .unwrap();
        let slow_restored =
            TargetHistoryNode::from_checkpoint_entries(&slow_checkpoint_tail, 2, &params, 1_000)
                .unwrap();
        assert_eq!(
            TargetHistoryNode::expected_next_target(&fast_restored, 3, &params).unwrap(),
            fast_target
        );
        assert_eq!(
            TargetHistoryNode::expected_next_target(&slow_restored, 3, &params).unwrap(),
            slow_target
        );

        assert!(matches!(
            TargetHistoryNode::append(&fast_parent, 3, slow_target, 1_020, &params),
            Err(QRunV06ForkChoiceError::ExpectedTargetMismatch { .. })
        ));
        assert!(matches!(
            TargetHistoryNode::append(&slow_parent, 3, fast_target, 1_100, &params),
            Err(QRunV06ForkChoiceError::ExpectedTargetMismatch { .. })
        ));
    }
    #[test]
    fn qfp6_first_retarget_accepts_unanchored_stale_epoch_and_eases_to_max_clamp() {
        let mut params = params(8);
        // Keep 4x within the 256-bit range so the exact configured clamp is observable.
        params.initial_target = Uint256::from_be_bytes([0x1F; 32]);
        params.validate().unwrap();

        // This directly preserves the unanchored-history reproducer. Production QFP6
        // constructors now reject a missing Genesis descriptor; this fixture models the
        // former legacy history shape to prove why that route must remain inadmissible.
        let mut history = TargetHistoryNode::genesis_at(&params, 0);
        let timestamps = [1, 2, 3, 4, 5, 6, 7, 1_000_330];
        for (index, timestamp) in timestamps.into_iter().enumerate() {
            history = TargetHistoryNode::append(
                &history,
                index as u64 + 1,
                params.initial_target,
                timestamp,
                &params,
            )
            .unwrap();
        }

        let next_target = TargetHistoryNode::expected_next_target(&history, 9, &params).unwrap();
        let maximum_eased_target = params.initial_target.mul_div_u64(4, 1).unwrap();
        assert_eq!(next_target, maximum_eased_target);
        assert_eq!(history.height, 8);
        assert_eq!(history.timestamp, Some(1_000_330));
    }

    #[test]
    fn qfp6_anchored_genesis_enforces_first_block_lower_bound_and_nominal_full_window_retarget() {
        const PRODUCTION_WINDOW: u64 = 2_016;
        const GENESIS_TIMESTAMP: u64 = 1_800_000_000;
        let mut params = params(PRODUCTION_WINDOW);
        params.initial_target = Uint256::from_be_bytes([0x1F; 32]);
        params.validate().unwrap();

        let genesis = TargetHistoryNode::genesis_at(&params, GENESIS_TIMESTAMP);
        assert_eq!(
            TargetHistoryNode::append(
                &genesis,
                1,
                params.initial_target,
                GENESIS_TIMESTAMP - 1,
                &params,
            ),
            Err(QRunV06ForkChoiceError::RetargetHistoryUnavailable),
            "the first timestamp must be strictly greater than the immutable Genesis timestamp"
        );

        let mut history = genesis;
        for height in 1..=PRODUCTION_WINDOW {
            let timestamp = GENESIS_TIMESTAMP
                .checked_add(height * params.target_block_time_secs)
                .unwrap();
            history = TargetHistoryNode::append(
                &history,
                height,
                params.initial_target,
                timestamp,
                &params,
            )
            .unwrap();
        }

        assert_eq!(history.height, PRODUCTION_WINDOW);
        assert_eq!(
            history.timestamp,
            Some(GENESIS_TIMESTAMP + PRODUCTION_WINDOW * params.target_block_time_secs)
        );
        let next_target =
            TargetHistoryNode::expected_next_target(&history, PRODUCTION_WINDOW + 1, &params)
                .unwrap();
        assert_eq!(
            next_target, params.initial_target,
            "a nominal 2,016-block window must preserve the target when anchored Genesis ordering is respected"
        );
    }

    #[test]
    fn qfp6_production_window_accepts_unanchored_stale_first_timestamp_and_max_eases() {
        const PRODUCTION_WINDOW: u64 = 2_016;
        let mut params = params(PRODUCTION_WINDOW);
        // Keep the exact 4x clamp representable in Uint256.
        params.initial_target = Uint256::from_be_bytes([0x1F; 32]);
        params.validate().unwrap();

        // The candidate history API has no trusted-time input. Genesis itself has no
        // timestamp, so this first admitted block can be arbitrarily old.
        let mut history = TargetHistoryNode::genesis_at(&params, 0);
        for height in 1..=PRODUCTION_WINDOW {
            let timestamp = if height == PRODUCTION_WINDOW {
                1_000_330
            } else {
                1 + (height - 1) * params.target_block_time_secs
            };
            history = TargetHistoryNode::append(
                &history,
                height,
                params.initial_target,
                timestamp,
                &params,
            )
            .unwrap();
        }

        assert_eq!(history.height, PRODUCTION_WINDOW);
        assert_eq!(
            history.parent.as_ref().unwrap().height,
            PRODUCTION_WINDOW - 1
        );
        let first = {
            let mut cursor = Arc::clone(&history);
            while cursor.height > 1 {
                cursor = Arc::clone(cursor.parent.as_ref().unwrap());
            }
            cursor
        };
        assert_eq!(first.timestamp, Some(1));
        assert_eq!(history.timestamp, Some(1_000_330));

        let next_target =
            TargetHistoryNode::expected_next_target(&history, PRODUCTION_WINDOW + 1, &params)
                .unwrap();
        let maximum_eased_target = params.initial_target.mul_div_u64(4, 1).unwrap();
        assert_eq!(
            next_target, maximum_eased_target,
            "the full 2,016-block window accepts an unanchored stale first timestamp and reaches the maximum 4x easing clamp"
        );
    }

    #[test]
    fn qfp6_checkpoint_restore_preserves_work_and_retargets_across_repeated_rollovers() {
        let params = params(2);
        let genesis = genesis_state(&params);
        let mut uninterrupted = QRunV06PowForkChoice::new(genesis.clone(), params.clone()).unwrap();
        let base0 = uninterrupted.base_tip();

        let target1 = uninterrupted.expected_next_target(&base0).unwrap();
        let (block1, tip1) = make_candidate(&genesis, base0, 100, target1, Vec::new(), &params);
        uninterrupted
            .insert_encoded(&block1, &DigestAuthenticator)
            .unwrap();
        let state1 = uninterrupted.state_for_tip(&tip1).unwrap().clone();

        let target2 = uninterrupted.expected_next_target(&tip1).unwrap();
        let (block2, tip2) = make_candidate(&state1, tip1, 110, target2, Vec::new(), &params);
        uninterrupted
            .insert_encoded(&block2, &DigestAuthenticator)
            .unwrap();
        let state2 = uninterrupted.state_for_tip(&tip2).unwrap().clone();
        let work2 = uninterrupted.branch_work(&tip2).unwrap();

        let checkpoint1 = uninterrupted.checkpoint_at_tip(&tip2).unwrap();
        assert_eq!(checkpoint1.height(), 2);
        assert_eq!(checkpoint1.target_history().len(), 2);
        let checkpoint1_bytes = checkpoint1.encode_snapshot().unwrap();
        let checkpoint1_anchor = checkpoint1.commitment().unwrap();
        let decoded_checkpoint1 = QRunV06CheckpointCandidate::decode_snapshot(
            &checkpoint1_bytes,
            &params,
            &NETWORK,
            &PROFILE,
            checkpoint1_anchor,
        )
        .unwrap();
        assert_eq!(decoded_checkpoint1, checkpoint1);
        assert_eq!(
            QRunV06CheckpointCandidate::decode_snapshot(
                &checkpoint1_bytes,
                &params,
                &NETWORK,
                &PROFILE,
                [0xEE; 32],
            ),
            Err(QRunV06CheckpointError::CheckpointAnchorMismatch)
        );

        let mut after_checkpoint1 =
            QRunV06PowForkChoice::from_checkpoint(decoded_checkpoint1, params.clone()).unwrap();
        assert_eq!(after_checkpoint1.base_tip(), tip2);
        assert_eq!(after_checkpoint1.base_height(), 2);
        assert_eq!(after_checkpoint1.base_work(), work2);
        assert_eq!(
            after_checkpoint1.canonical_state().state_root().unwrap(),
            state2.state_root().unwrap()
        );

        // The next height is the retarget boundary for this 2-block test window.
        let target3_original = uninterrupted.expected_next_target(&tip2).unwrap();
        let target3_restored = after_checkpoint1.expected_next_target(&tip2).unwrap();
        assert_eq!(target3_restored, target3_original);
        let (block3, tip3) =
            make_candidate(&state2, tip2, 150, target3_original, Vec::new(), &params);
        uninterrupted
            .insert_encoded(&block3, &DigestAuthenticator)
            .unwrap();
        after_checkpoint1
            .insert_encoded(&block3, &DigestAuthenticator)
            .unwrap();
        let state3 = uninterrupted.state_for_tip(&tip3).unwrap().clone();
        assert_eq!(
            after_checkpoint1.canonical_state().state_root().unwrap(),
            state3.state_root().unwrap()
        );

        let target4 = uninterrupted.expected_next_target(&tip3).unwrap();
        let (block4, tip4) = make_candidate(&state3, tip3, 170, target4, Vec::new(), &params);
        uninterrupted
            .insert_encoded(&block4, &DigestAuthenticator)
            .unwrap();
        after_checkpoint1
            .insert_encoded(&block4, &DigestAuthenticator)
            .unwrap();
        let state4 = uninterrupted.state_for_tip(&tip4).unwrap().clone();
        let work4 = uninterrupted.branch_work(&tip4).unwrap();

        // A second checkpoint retains the difficulty window and the MTP ancestry tail.
        let checkpoint2 = uninterrupted.checkpoint_at_tip(&tip4).unwrap();
        assert_eq!(
            checkpoint2
                .target_history()
                .iter()
                .map(|entry| entry.height)
                .collect::<Vec<_>>(),
            vec![1, 2, 3, 4]
        );
        let checkpoint2_bytes = checkpoint2.encode_snapshot().unwrap();
        let checkpoint2_anchor = checkpoint2.commitment().unwrap();
        let decoded_checkpoint2 = QRunV06CheckpointCandidate::decode_snapshot(
            &checkpoint2_bytes,
            &params,
            &NETWORK,
            &PROFILE,
            checkpoint2_anchor,
        )
        .unwrap();
        let mut after_checkpoint2 =
            QRunV06PowForkChoice::from_checkpoint(decoded_checkpoint2, params.clone()).unwrap();
        assert_eq!(after_checkpoint2.base_tip(), tip4);
        assert_eq!(after_checkpoint2.base_work(), work4);
        assert_eq!(
            after_checkpoint2.canonical_state().state_root().unwrap(),
            state4.state_root().unwrap()
        );

        // Height 5 retargets against height 3, the oldest retained checkpoint observation.
        let target5_original = uninterrupted.expected_next_target(&tip4).unwrap();
        let target5_restored = after_checkpoint2.expected_next_target(&tip4).unwrap();
        assert_eq!(target5_restored, target5_original);
        let (block5, tip5) =
            make_candidate(&state4, tip4, 220, target5_original, Vec::new(), &params);
        uninterrupted
            .insert_encoded(&block5, &DigestAuthenticator)
            .unwrap();
        after_checkpoint2
            .insert_encoded(&block5, &DigestAuthenticator)
            .unwrap();
        assert_eq!(after_checkpoint2.canonical_tip().tip_hash, tip5);
        assert_eq!(
            uninterrupted.canonical_tip(),
            after_checkpoint2.canonical_tip()
        );
        assert_eq!(
            uninterrupted.canonical_state().state_root().unwrap(),
            after_checkpoint2.canonical_state().state_root().unwrap()
        );
        assert_eq!(
            uninterrupted.branch_work(&tip5),
            after_checkpoint2.branch_work(&tip5)
        );
    }

    #[test]
    fn qfp6_fork_choice_keeps_branch_states_isolated_and_reorgs_to_heavier_work() {
        let params = params(2);
        let genesis = genesis_state(&params);
        let mut graph = QRunV06PowForkChoice::new(genesis.clone(), params.clone()).unwrap();
        let genesis_tip = graph.base_tip();

        let first_target = graph.expected_next_target(&genesis_tip).unwrap();
        let (first_envelope, first_tip) = make_candidate(
            &genesis,
            genesis_tip,
            100,
            first_target,
            Vec::new(),
            &params,
        );
        graph
            .insert_encoded(&first_envelope, &DigestAuthenticator)
            .unwrap();
        let first_state = graph.state_for_tip(&first_tip).unwrap().clone();

        // Two height-2 siblings share a parent but execute different transfers and timestamp
        // histories. Their ledger and target-history views must remain branch-local.
        let second_target_a = graph.expected_next_target(&first_tip).unwrap();
        let second_target_b = graph.expected_next_target(&first_tip).unwrap();
        assert_eq!(second_target_a, second_target_b);

        let (branch_a_2, tip_a_2) = make_candidate(
            &first_state,
            first_tip,
            110,
            second_target_a,
            vec![signed_transfer(10), signed_category_release(1, BOB, 777)],
            &params,
        );
        let (branch_b_2, tip_b_2) = make_candidate(
            &first_state,
            first_tip,
            160,
            second_target_b,
            vec![signed_transfer(20)],
            &params,
        );
        graph
            .insert_encoded(&branch_a_2, &DigestAuthenticator)
            .unwrap();
        graph
            .insert_encoded(&branch_b_2, &DigestAuthenticator)
            .unwrap();
        let expected_tie_tip = tip_a_2.min(tip_b_2);
        assert_eq!(graph.canonical_tip().tip_hash, expected_tie_tip);

        let state_a_2 = graph.state_for_tip(&tip_a_2).unwrap().clone();
        let state_b_2 = graph.state_for_tip(&tip_b_2).unwrap().clone();
        assert_eq!(
            state_a_2
                .unified()
                .ledger()
                .account(&ALICE)
                .unwrap()
                .balance,
            crate::qrun_v06_tokenomics_candidate::QRUN_V06_FOUNDER_GENESIS_ATOMS as u64 - 10
        );
        assert_eq!(
            state_b_2
                .unified()
                .ledger()
                .account(&ALICE)
                .unwrap()
                .balance,
            crate::qrun_v06_tokenomics_candidate::QRUN_V06_FOUNDER_GENESIS_ATOMS as u64 - 20
        );
        // Only branch A carries the CP-0528 release. Its nonce, bucket counter and
        // recipient balance must not leak into branch B before or after reorganization.
        let community =
            crate::qrun_v06_tokenomics_candidate::QRunV06AllocationBucket::CommunityAirdrop;
        assert_eq!(state_a_2.tokenomics().unwrap().founder_release_nonce(), 1);
        assert_eq!(
            state_a_2
                .tokenomics()
                .unwrap()
                .issued_by_bucket_atoms(community),
            777
        );
        assert_eq!(
            state_a_2.unified().ledger().account(&BOB).unwrap().balance,
            787
        );
        assert_eq!(state_b_2.tokenomics().unwrap().founder_release_nonce(), 0);
        assert_eq!(
            state_b_2
                .tokenomics()
                .unwrap()
                .issued_by_bucket_atoms(community),
            0
        );
        assert_eq!(
            state_b_2.unified().ledger().account(&BOB).unwrap().balance,
            20
        );

        // Height 3 is a retarget boundary. The faster branch receives a harder target and
        // therefore more work per block; the slower sibling receives an easier target.
        let target_a_3 = graph.expected_next_target(&tip_a_2).unwrap();
        let target_b_3 = graph.expected_next_target(&tip_b_2).unwrap();
        let work_a_3 = block_work(target_a_3).unwrap();
        let work_b_3 = block_work(target_b_3).unwrap();
        assert!(target_a_3 < target_b_3);
        assert!(work_a_3 > work_b_3);

        let (branch_b_3, tip_b_3) =
            make_candidate(&state_b_2, tip_b_2, 190, target_b_3, Vec::new(), &params);
        graph
            .insert_encoded(&branch_b_3, &DigestAuthenticator)
            .unwrap();
        assert_eq!(graph.canonical_tip().tip_hash, tip_b_3);

        let (branch_a_3, tip_a_3) =
            make_candidate(&state_a_2, tip_a_2, 140, target_a_3, Vec::new(), &params);
        let outcome = graph
            .insert_encoded(&branch_a_3, &DigestAuthenticator)
            .unwrap();

        assert_eq!(outcome.canonical_tip, tip_a_3);
        assert_eq!(outcome.canonical_height, 3);
        assert!(outcome.canonical_changed);
        assert!(outcome.reorg_count >= 1);
        assert!(graph.branch_work(&tip_a_3).unwrap() > graph.branch_work(&tip_b_3).unwrap());
        assert_eq!(
            graph
                .canonical_state()
                .unified()
                .ledger()
                .account(&ALICE)
                .unwrap()
                .balance,
            crate::qrun_v06_tokenomics_candidate::QRUN_V06_FOUNDER_GENESIS_ATOMS as u64 - 10
        );
        assert_eq!(
            graph
                .state_for_tip(&tip_b_3)
                .unwrap()
                .unified()
                .ledger()
                .account(&ALICE)
                .unwrap()
                .balance,
            crate::qrun_v06_tokenomics_candidate::QRUN_V06_FOUNDER_GENESIS_ATOMS as u64 - 20
        );
        assert_eq!(
            graph
                .canonical_state()
                .tokenomics()
                .unwrap()
                .founder_release_nonce(),
            1
        );
        assert_eq!(
            graph
                .canonical_state()
                .tokenomics()
                .unwrap()
                .issued_by_bucket_atoms(community),
            777
        );
        assert_eq!(
            graph
                .state_for_tip(&tip_b_3)
                .unwrap()
                .tokenomics()
                .unwrap()
                .founder_release_nonce(),
            0
        );
        assert_eq!(
            graph
                .state_for_tip(&tip_b_3)
                .unwrap()
                .tokenomics()
                .unwrap()
                .issued_by_bucket_atoms(community),
            0
        );
    }

    #[test]
    fn qfp6_rejects_unknown_consensus_parent_and_wrong_branch_target_without_mutation() {
        let params = params(2);
        let genesis = genesis_state(&params);
        let mut graph = QRunV06PowForkChoice::new(genesis.clone(), params.clone()).unwrap();
        let base_tip = graph.base_tip();
        let target = graph.expected_next_target(&base_tip).unwrap();
        let (valid, _) = make_candidate(&genesis, base_tip, 100, target, Vec::new(), &params);

        let mut unknown_parent = valid.clone();
        // QFP6 fixed header: previous_consensus_hash occupies bytes 88..120.
        unknown_parent[88] ^= 0x80;
        let before = graph.clone();
        assert_eq!(
            graph.insert_encoded(&unknown_parent, &DigestAuthenticator),
            Err(QRunV06ForkChoiceError::UnknownParent)
        );
        assert_eq!(graph, before);

        let mut wrong_target = valid;
        // QFP6 fixed header: target occupies bytes 152..184.
        wrong_target[152..184].copy_from_slice(&Uint256::MAX.to_be_bytes());
        assert!(matches!(
            graph.insert_encoded(&wrong_target, &DigestAuthenticator),
            Err(QRunV06ForkChoiceError::ExpectedTargetMismatch { .. })
        ));
        assert_eq!(graph, before);
    }

    #[test]
    fn qfp6_duplicate_import_is_idempotent_and_rebuild_replays_all_siblings() {
        let params = params(2);
        let genesis = genesis_state(&params);
        let mut graph = QRunV06PowForkChoice::new(genesis.clone(), params.clone()).unwrap();
        let base_tip = graph.base_tip();
        let target = graph.expected_next_target(&base_tip).unwrap();
        let (first, first_tip) =
            make_candidate(&genesis, base_tip, 100, target, Vec::new(), &params);
        graph.insert_encoded(&first, &DigestAuthenticator).unwrap();
        let before_duplicate = graph.clone();
        let duplicate = graph.insert_encoded(&first, &DigestAuthenticator).unwrap();
        assert!(!duplicate.canonical_changed);
        assert_eq!(graph, before_duplicate);

        let parent = graph.state_for_tip(&first_tip).unwrap().clone();
        let child_target = graph.expected_next_target(&first_tip).unwrap();
        let (child_a, _) = make_candidate(
            &parent,
            first_tip,
            120,
            child_target,
            vec![signed_transfer(5)],
            &params,
        );
        let (child_b, _) = make_candidate(
            &parent,
            first_tip,
            130,
            child_target,
            vec![signed_transfer(7)],
            &params,
        );
        graph
            .insert_encoded(&child_a, &DigestAuthenticator)
            .unwrap();
        graph
            .insert_encoded(&child_b, &DigestAuthenticator)
            .unwrap();

        let exported = graph.archive_envelopes_bounded(3, usize::MAX).unwrap();
        let expected_genesis_descriptor_commitment =
            genesis.genesis_descriptor_commitment().unwrap();
        assert_eq!(
            QRunV06PowForkChoice::rebuild_from_envelopes_with_expected_genesis_descriptor_commitment(
                genesis.clone(),
                params.clone(),
                exported.clone(),
                &DigestAuthenticator,
                [0xEF; 32],
            ),
            Err(QRunV06ForkChoiceError::GenesisDescriptorMismatch),
            "archive replay must reject a descriptor pin that differs from the original Genesis profile"
        );
        let rebuilt =
            QRunV06PowForkChoice::rebuild_from_envelopes_with_expected_genesis_descriptor_commitment(
                genesis,
                params,
                exported,
                &DigestAuthenticator,
                expected_genesis_descriptor_commitment,
            )
            .unwrap();

        assert_eq!(rebuilt.archive_len(), 3);
        assert_eq!(rebuilt.canonical_tip(), graph.canonical_tip());
        assert_eq!(
            rebuilt.canonical_state().state_root().unwrap(),
            graph.canonical_state().state_root().unwrap()
        );
        assert_eq!(
            rebuilt.canonical_envelopes().unwrap(),
            graph.canonical_envelopes().unwrap()
        );
    }

    #[test]
    fn qfp6_canonical_history_pages_are_bounded_parent_first_and_snapshot_pinned() {
        let params = params(2);
        let genesis = genesis_state(&params);
        let mut graph = QRunV06PowForkChoice::new(genesis, params.clone()).unwrap();

        for height in 1..=5u64 {
            let parent = graph.canonical_state().clone();
            let parent_tip = graph.canonical_tip().tip_hash;
            let target = graph.expected_next_target(&parent_tip).unwrap();
            let (envelope, _) = make_candidate(
                &parent,
                parent_tip,
                100 + height * 30,
                target,
                Vec::new(),
                &params,
            );
            graph
                .insert_encoded(&envelope, &DigestAuthenticator)
                .unwrap();
        }

        let snapshot = graph.clone();
        let pinned_tip = snapshot.canonical_tip().tip_hash;
        let first = snapshot.canonical_history_page(1, 2, 1024 * 1024).unwrap();
        assert_eq!(first.start_height, 1);
        assert_eq!(first.next_height, 3);
        assert_eq!(first.snapshot_height, 5);
        assert_eq!(first.snapshot_tip, pinned_tip);
        assert!(!first.complete);
        assert_eq!(
            first
                .envelopes
                .iter()
                .map(|bytes| decode_qrun_v06_pow_block(bytes).unwrap().header.height)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );

        let second = snapshot
            .canonical_history_page(first.next_height, 2, 1024 * 1024)
            .unwrap();
        assert_eq!(second.next_height, 5);
        assert!(!second.complete);
        assert_eq!(
            second
                .envelopes
                .iter()
                .map(|bytes| decode_qrun_v06_pow_block(bytes).unwrap().header.height)
                .collect::<Vec<_>>(),
            vec![3, 4]
        );

        let third = snapshot
            .canonical_history_page(second.next_height, 2, 1024 * 1024)
            .unwrap();
        assert_eq!(third.next_height, 6);
        assert!(third.complete);
        assert_eq!(
            third
                .envelopes
                .iter()
                .map(|bytes| decode_qrun_v06_pow_block(bytes).unwrap().header.height)
                .collect::<Vec<_>>(),
            vec![5]
        );

        assert_eq!(
            snapshot.canonical_history_page(1, 129, 1024 * 1024),
            Err(QRunV06ForkChoiceError::ArchiveExportLimitExceeded)
        );
        assert_eq!(
            snapshot.canonical_history_page(1, 2, 16 * 1024 * 1024 + 1),
            Err(QRunV06ForkChoiceError::ArchiveExportLimitExceeded)
        );
        assert_eq!(
            snapshot.canonical_history_page(0, 2, 1024 * 1024),
            Err(QRunV06ForkChoiceError::ArchiveExportLimitExceeded)
        );
    }

    #[test]
    fn qfp6_checkpoint_restore_preserves_cp0528_issuance_and_continues_mining() {
        let params = params(2);
        let genesis = genesis_state(&params);
        let expected_genesis_commitment = genesis.genesis_descriptor_commitment().unwrap();
        let mut graph = QRunV06PowForkChoice::new_with_expected_genesis_descriptor_commitment(
            genesis.clone(),
            params.clone(),
            expected_genesis_commitment,
        )
        .unwrap();
        let base = graph.base_tip();
        let target = graph.expected_next_target(&base).unwrap();
        let (block1, tip1) = make_candidate(&genesis, base, 100, target, Vec::new(), &params);
        graph.insert_encoded(&block1, &DigestAuthenticator).unwrap();

        let state1 = graph.state_for_tip(&tip1).unwrap().clone();
        assert_eq!(
            state1.tokenomics().unwrap().issued_by_bucket_atoms(
                crate::qrun_v06_tokenomics_candidate::QRunV06AllocationBucket::MiningNetworkSecurity
            ),
            35_673_515_981
        );

        let checkpoint = graph.checkpoint_at_tip(&tip1).unwrap();
        let checkpoint_bytes = checkpoint.encode_snapshot().unwrap();
        let anchor = checkpoint.commitment().unwrap();
        let decoded = QRunV06CheckpointCandidate::decode_snapshot(
            &checkpoint_bytes,
            &params,
            &NETWORK,
            &PROFILE,
            anchor,
        )
        .unwrap();
        let mut resumed =
            QRunV06PowForkChoice::from_checkpoint_with_expected_genesis_descriptor_commitment(
                decoded,
                params.clone(),
                expected_genesis_commitment,
            )
            .unwrap();
        assert_eq!(
            resumed.canonical_state().state_root().unwrap(),
            state1.state_root().unwrap()
        );
        assert_eq!(
            resumed
                .canonical_state()
                .tokenomics()
                .unwrap()
                .issued_by_bucket_atoms(
                    crate::qrun_v06_tokenomics_candidate::QRunV06AllocationBucket::MiningNetworkSecurity
                ),
            35_673_515_981
        );

        let target2 = resumed.expected_next_target(&tip1).unwrap();
        let (block2, tip2) = make_candidate(
            resumed.canonical_state(),
            tip1,
            110,
            target2,
            Vec::new(),
            &params,
        );
        resumed
            .insert_encoded(&block2, &DigestAuthenticator)
            .unwrap();
        let state2 = resumed.state_for_tip(&tip2).unwrap();
        assert_eq!(
            state2
                .tokenomics()
                .unwrap()
                .issued_by_bucket_atoms(
                    crate::qrun_v06_tokenomics_candidate::QRunV06AllocationBucket::MiningNetworkSecurity
                ),
            71_347_031_962
        );
        assert_eq!(
            state2.unified().ledger().total_value().unwrap(),
            crate::qrun_v06_tokenomics_candidate::QRUN_V06_FOUNDER_GENESIS_ATOMS + 71_347_031_962
        );
    }

    #[test]
    fn qfp6_genesis_time_anchor_survives_snapshot_zero_checkpoint_and_first_block_admission() {
        let params = params(2);
        let genesis = genesis_state(&params);
        let expected_commitment = genesis.genesis_descriptor_commitment().unwrap();
        assert_eq!(genesis.genesis_timestamp(), Some(1));
        assert_eq!(genesis.last_timestamp(), 1);

        let genesis_root = genesis.state_root().unwrap();
        let snapshot = genesis.encode_snapshot().unwrap();
        let restored_genesis =
            QRunV06CanonicalExecutionState::decode_snapshot(&snapshot, &NETWORK, &PROFILE).unwrap();
        assert_eq!(restored_genesis.genesis_timestamp(), Some(1));
        assert_eq!(
            restored_genesis.genesis_descriptor_commitment(),
            Some(expected_commitment)
        );
        assert_eq!(restored_genesis.state_root().unwrap(), genesis_root);

        let graph = QRunV06PowForkChoice::new_with_expected_genesis_descriptor_commitment(
            restored_genesis.clone(),
            params.clone(),
            expected_commitment,
        )
        .unwrap();

        let zero_checkpoint = graph.canonical_checkpoint().unwrap();
        assert_eq!(zero_checkpoint.height(), 0);
        assert_eq!(zero_checkpoint.timestamp(), 1);
        assert_eq!(
            zero_checkpoint.genesis_descriptor_commitment(),
            expected_commitment
        );
        let zero_bytes = zero_checkpoint.encode_snapshot().unwrap();
        let zero_anchor = zero_checkpoint.commitment().unwrap();
        let decoded_zero = QRunV06CheckpointCandidate::decode_snapshot(
            &zero_bytes,
            &params,
            &NETWORK,
            &PROFILE,
            zero_anchor,
        )
        .unwrap();
        assert_eq!(decoded_zero.execution_state().genesis_timestamp(), Some(1));
        let mut resumed =
            QRunV06PowForkChoice::from_checkpoint_with_expected_genesis_descriptor_commitment(
                decoded_zero,
                params.clone(),
                expected_commitment,
            )
            .unwrap();

        assert_eq!(
            QRunV06PowForkChoice::new_with_expected_genesis_descriptor_commitment(
                restored_genesis.clone(),
                params.clone(),
                [0xFE; 32],
            ),
            Err(QRunV06ForkChoiceError::GenesisDescriptorMismatch)
        );

        let base_tip = resumed.base_tip();
        let target = resumed.expected_next_target(&base_tip).unwrap();
        let mut equal_time_block = QRunV06Block {
            network_id: NETWORK,
            profile_id: PROFILE,
            height: 1,
            timestamp: 1,
            parent_hash: restored_genesis.tip_hash(),
            state_root: [0; 32],
            producer: PRODUCER,
            operations: Vec::new(),
        };
        assert_eq!(
            restored_genesis.preview_state_root_after(&equal_time_block, &DigestAuthenticator,),
            Err(QRunV06ExecutionError::TimestampNotIncreasing {
                previous: 1,
                actual: 1,
            })
        );

        equal_time_block.timestamp = 2;
        let (first_block, first_tip) = make_candidate(
            &restored_genesis,
            base_tip,
            equal_time_block.timestamp,
            target,
            Vec::new(),
            &params,
        );
        resumed
            .insert_encoded(&first_block, &DigestAuthenticator)
            .unwrap();
        let first_state = resumed.state_for_tip(&first_tip).unwrap();
        assert_eq!(first_state.genesis_timestamp(), Some(1));
        assert_eq!(first_state.last_timestamp(), 2);

        let first_checkpoint = resumed.checkpoint_at_tip(&first_tip).unwrap();
        assert_eq!(
            first_checkpoint.genesis_descriptor_commitment(),
            expected_commitment
        );
        let first_bytes = first_checkpoint.encode_snapshot().unwrap();
        let first_anchor = first_checkpoint.commitment().unwrap();
        let decoded_first = QRunV06CheckpointCandidate::decode_snapshot(
            &first_bytes,
            &params,
            &NETWORK,
            &PROFILE,
            first_anchor,
        )
        .unwrap();
        assert_eq!(decoded_first.execution_state().genesis_timestamp(), Some(1));
        assert_eq!(decoded_first.timestamp(), 2);
    }

    #[test]
    fn qfp6_nonzero_checkpoint_tail_preserves_genesis_floor_after_genesis_leaves_history_window() {
        let params = params(2);
        let genesis_timestamp = 1_000;

        let valid_tail = [
            QRunV06TargetHistoryEntry {
                height: 100,
                target: params.initial_target,
                timestamp: 1_001,
            },
            QRunV06TargetHistoryEntry {
                height: 101,
                target: params.initial_target,
                timestamp: 1_031,
            },
        ];
        let restored = TargetHistoryNode::from_checkpoint_entries(
            &valid_tail,
            101,
            &params,
            genesis_timestamp,
        )
        .unwrap();
        assert_eq!(restored.height, 101);
        assert_eq!(restored.timestamp, Some(1_031));
        assert_eq!(
            restored
                .parent
                .as_ref()
                .map(|parent| (parent.height, parent.timestamp)),
            Some((100, Some(1_001)))
        );

        let mut before_genesis = valid_tail;
        before_genesis[0].timestamp = genesis_timestamp - 1;
        assert_eq!(
            TargetHistoryNode::from_checkpoint_entries(
                &before_genesis,
                101,
                &params,
                genesis_timestamp,
            ),
            Err(QRunV06ForkChoiceError::RetargetHistoryUnavailable),
            "the first retained timestamp must remain strictly after Genesis even when height zero is outside the checkpoint tail"
        );

        let mut equal_to_genesis = valid_tail;
        equal_to_genesis[0].timestamp = genesis_timestamp;
        assert_eq!(
            TargetHistoryNode::from_checkpoint_entries(
                &equal_to_genesis,
                101,
                &params,
                genesis_timestamp,
            ),
            Err(QRunV06ForkChoiceError::RetargetHistoryUnavailable)
        );

        let mut non_contiguous = valid_tail;
        non_contiguous[1].height = 102;
        assert_eq!(
            TargetHistoryNode::from_checkpoint_entries(
                &non_contiguous,
                101,
                &params,
                genesis_timestamp,
            ),
            Err(QRunV06ForkChoiceError::RetargetHistoryUnavailable)
        );
    }

    #[test]
    fn qfp6_rejects_market_only_genesis_without_cp0528_monetary_state() {
        let ledger =
            LedgerState::genesis(NETWORK, vec![(ALICE, 50_000), (BOB, 1_000), (PRODUCER, 0)])
                .unwrap();
        let amm = QzxbAmmStateCandidate::new(NETWORK, 32, 64, 512).unwrap();
        let unified = QRunV06UnifiedAssetState::new(ledger, amm).unwrap();
        let market_only = QRunV06CanonicalExecutionState::new(unified, PROFILE).unwrap();
        assert!(market_only.tokenomics().is_none());
        assert_eq!(
            QRunV06PowForkChoice::new(market_only, params(2)),
            Err(QRunV06ForkChoiceError::InvalidConsensusProfile)
        );
    }

    #[test]
    fn qfp6_refuses_cp0528_genesis_when_mining_schedule_differs_from_consensus() {
        let mut consensus = params(2);
        let genesis = genesis_state(&consensus);
        QRunV06PowForkChoice::new(genesis.clone(), consensus.clone()).unwrap();

        consensus.issuance = IssuanceParameters::new(
            consensus.issuance.maximum_supply(),
            consensus.issuance.initial_subsidy() + 1,
            consensus.issuance.blocks_per_halving(),
        )
        .unwrap();
        assert!(matches!(
            QRunV06PowForkChoice::new(genesis, consensus),
            Err(QRunV06ForkChoiceError::InvalidConsensusProfile)
        ));
    }

    #[test]
    fn qfp6_rejects_wrong_profile_and_non_protocol_six_parameters() {
        let profile_params = params(2);
        let genesis = genesis_state(&profile_params);
        let mut wrong_params = profile_params.clone();
        wrong_params.protocol_version = 5;
        assert_eq!(
            QRunV06PowForkChoice::new(genesis.clone(), wrong_params),
            Err(QRunV06ForkChoiceError::InvalidConsensusProfile)
        );

        let wrong_genesis = QRunV06CanonicalExecutionState::new(
            QRunV06UnifiedAssetState::new(
                LedgerState::genesis(NETWORK, vec![(ALICE, 1_000)]).unwrap(),
                QzxbAmmStateCandidate::new(NETWORK, 32, 64, 512).unwrap(),
            )
            .unwrap(),
            [0; 32],
        );
        assert!(matches!(
            wrong_genesis,
            Err(QRunV06ExecutionError::InvalidProfile)
        ));

        let wrong_profile_state = genesis_state_for_profile([0x66; 32], &profile_params);
        let (wrong_profile_envelope, _) = make_candidate(
            &wrong_profile_state,
            wrong_profile_state.tip_hash(),
            100,
            profile_params.initial_target,
            Vec::new(),
            &profile_params,
        );
        let mut graph = QRunV06PowForkChoice::new(genesis, profile_params).unwrap();
        assert_eq!(
            graph.insert_encoded(&wrong_profile_envelope, &DigestAuthenticator),
            Err(QRunV06ForkChoiceError::WrongProfile)
        );
    }
}
