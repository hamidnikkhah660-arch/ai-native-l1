//! Private-testnet consensus chain driver for CP-W.
//!
//! This driver keeps target history, cumulative work, and canonical state together without
//! changing the legacy BLK2 body encoding. It is deliberately small and explicit so a later
//! network implementation can adopt the exact tested behavior instead of duplicating rules.

use crate::{
    chain_admission::{BlockAdmissionReceipt, ChainAdmissionBoundary, ReferenceTimeProvider},
    consensus::{
        block_work, compare_chain_tips, ChainTip, ConsensusError, ConsensusParameters, Uint256,
    },
    private_testnet_checkpoint_candidate::{Pcp4CheckpointRecord, Pcp4ValidationContext},
    private_testnet_consensus::{
        admit_live as admit_candidate_live, CandidateConsensusBlock, PrivateConsensusError,
    },
    private_testnet_pfm5_manifest_candidate::Pfm5CheckpointManifest,
    state_machine::{
        Block, LedgerState, MonetaryBlock, MonetaryLedgerState, TransactionAuthenticator,
    },
};
use std::collections::VecDeque;

/// Candidate safety ceiling for serialized checkpoint target-history entries. This is a
/// parser/resource guard, not a consensus parameter or a production profile selection.
pub const MAX_TARGET_HISTORY_CHECKPOINT_ENTRIES: usize = 65_536;
fn checked_cumulative_work_after_block(
    current: Uint256,
    target: Uint256,
) -> Result<Uint256, PrivateConsensusError> {
    let work = block_work(target)?;
    current
        .checked_add(work)
        .ok_or(PrivateConsensusError::Consensus(
            ConsensusError::ChainworkOverflow,
        ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetHistoryCheckpointEntry {
    pub height: u64,
    pub target: Uint256,
    pub timestamp: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetHistoryCheckpoint {
    pub logical_height: u64,
    pub start_height: u64,
    pub entries: Vec<TargetHistoryCheckpointEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetHistoryCheckpointError {
    InvalidProfile,
    EntryBudgetExceeded,
    NonCanonicalRange,
    EntryHeightMismatch,
    InvalidGenesisEntry,
    InvalidTarget,
    MissingTimestamp,
    TimestampNotMonotonic,
    RetargetHistoryInvalid,
}

impl std::fmt::Display for TargetHistoryCheckpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidProfile => "checkpoint target history has invalid consensus parameters",
            Self::EntryBudgetExceeded => "checkpoint target history exceeds its entry budget",
            Self::NonCanonicalRange => "checkpoint target history has a noncanonical height range",
            Self::EntryHeightMismatch => "checkpoint target history entries are not contiguous",
            Self::InvalidGenesisEntry => "checkpoint genesis target/timestamp entry is invalid",
            Self::InvalidTarget => "checkpoint target is zero or above the proof-of-work limit",
            Self::MissingTimestamp => "checkpoint target history is missing a block timestamp",
            Self::TimestampNotMonotonic => {
                "checkpoint target timestamps are not strictly increasing"
            }
            Self::RetargetHistoryInvalid => {
                "checkpoint target history does not match the retarget rules"
            }
        };
        f.write_str(message)
    }
}

impl std::error::Error for TargetHistoryCheckpointError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetHistory {
    params: ConsensusParameters,
    /// First logical height represented by both vectors. This is nonzero after restore from a
    /// bounded checkpoint; vector offsets must never be confused with chain heights.
    start_height: u64,
    /// Current logical height, independent of retained vector length after checkpoint restore.
    logical_height: u64,
    /// Contiguous target/timestamp records; the front is dropped after each complete window.
    targets: VecDeque<Uint256>,
    /// Height zero deliberately has no timestamp; every accepted block height has one.
    timestamps: VecDeque<Option<u64>>,
}

impl TargetHistory {
    pub fn new(params: ConsensusParameters) -> Result<Self, ConsensusError> {
        params.validate()?;
        let initial_target = params.initial_target;
        Ok(Self {
            params,
            start_height: 0,
            logical_height: 0,
            targets: VecDeque::from([initial_target]),
            timestamps: VecDeque::from([None]),
        })
    }

    pub fn params(&self) -> ConsensusParameters {
        self.params.clone()
    }

    pub fn height(&self) -> u64 {
        self.logical_height
    }

    pub fn target_at(&self, height: u64) -> Option<Uint256> {
        let offset = height.checked_sub(self.start_height)?;
        let index = usize::try_from(offset).ok()?;
        self.targets.get(index).copied()
    }

    fn timestamp_at(&self, height: u64) -> Option<Option<u64>> {
        let offset = height.checked_sub(self.start_height)?;
        let index = usize::try_from(offset).ok()?;
        self.timestamps.get(index).copied()
    }

    /// Return the canonical bounded target/timestamp suffix needed to resume this consensus
    /// profile. It does not mutate live history or authenticate a checkpoint by itself.
    pub fn checkpoint_snapshot(
        &self,
    ) -> Result<TargetHistoryCheckpoint, TargetHistoryCheckpointError> {
        self.params
            .validate()
            .map_err(|_| TargetHistoryCheckpointError::InvalidProfile)?;
        let window = self.params.difficulty_window_blocks;
        if window > MAX_TARGET_HISTORY_CHECKPOINT_ENTRIES as u64 {
            return Err(TargetHistoryCheckpointError::EntryBudgetExceeded);
        }
        let start_height = if self.logical_height >= window {
            self.logical_height - window + 1
        } else {
            0
        };
        let entry_count = self
            .logical_height
            .checked_sub(start_height)
            .and_then(|span| span.checked_add(1))
            .ok_or(TargetHistoryCheckpointError::NonCanonicalRange)?;
        if entry_count > MAX_TARGET_HISTORY_CHECKPOINT_ENTRIES as u64 {
            return Err(TargetHistoryCheckpointError::EntryBudgetExceeded);
        }
        let entry_count = usize::try_from(entry_count)
            .map_err(|_| TargetHistoryCheckpointError::EntryBudgetExceeded)?;
        let mut entries = Vec::with_capacity(entry_count);
        for offset in 0..entry_count {
            let height = start_height
                .checked_add(offset as u64)
                .ok_or(TargetHistoryCheckpointError::NonCanonicalRange)?;
            let target = self
                .target_at(height)
                .ok_or(TargetHistoryCheckpointError::NonCanonicalRange)?;
            let timestamp = self
                .timestamp_at(height)
                .ok_or(TargetHistoryCheckpointError::NonCanonicalRange)?;
            entries.push(TargetHistoryCheckpointEntry {
                height,
                target,
                timestamp,
            });
        }
        Ok(TargetHistoryCheckpoint {
            logical_height: self.logical_height,
            start_height,
            entries,
        })
    }

    /// Restore only the bounded target/timestamp history. Callers must independently authenticate
    /// the enclosing checkpoint, state root, tip digest, chainwork and profile before using it.
    pub fn from_checkpoint_snapshot(
        params: ConsensusParameters,
        snapshot: &TargetHistoryCheckpoint,
    ) -> Result<Self, TargetHistoryCheckpointError> {
        params
            .validate()
            .map_err(|_| TargetHistoryCheckpointError::InvalidProfile)?;
        let window = params.difficulty_window_blocks;
        if window > MAX_TARGET_HISTORY_CHECKPOINT_ENTRIES as u64 {
            return Err(TargetHistoryCheckpointError::EntryBudgetExceeded);
        }
        let expected_start = if snapshot.logical_height >= window {
            snapshot.logical_height - window + 1
        } else {
            0
        };
        if snapshot.start_height != expected_start {
            return Err(TargetHistoryCheckpointError::NonCanonicalRange);
        }
        let expected_count = snapshot
            .logical_height
            .checked_sub(expected_start)
            .and_then(|span| span.checked_add(1))
            .ok_or(TargetHistoryCheckpointError::NonCanonicalRange)?;
        if expected_count > MAX_TARGET_HISTORY_CHECKPOINT_ENTRIES as u64
            || usize::try_from(expected_count).ok() != Some(snapshot.entries.len())
        {
            return Err(TargetHistoryCheckpointError::EntryBudgetExceeded);
        }

        let mut previous_timestamp = None;
        for (offset, entry) in snapshot.entries.iter().enumerate() {
            let expected_height = expected_start
                .checked_add(offset as u64)
                .ok_or(TargetHistoryCheckpointError::NonCanonicalRange)?;
            if entry.height != expected_height {
                return Err(TargetHistoryCheckpointError::EntryHeightMismatch);
            }
            if entry.target.is_zero() || entry.target > params.pow_limit {
                return Err(TargetHistoryCheckpointError::InvalidTarget);
            }
            if entry.height == 0 {
                if snapshot.start_height != 0
                    || entry.timestamp.is_some()
                    || entry.target != params.initial_target
                {
                    return Err(TargetHistoryCheckpointError::InvalidGenesisEntry);
                }
            } else {
                let timestamp = entry
                    .timestamp
                    .ok_or(TargetHistoryCheckpointError::MissingTimestamp)?;
                if previous_timestamp.is_some_and(|previous| timestamp <= previous) {
                    return Err(TargetHistoryCheckpointError::TimestampNotMonotonic);
                }
                previous_timestamp = Some(timestamp);
            }
        }

        // Before the first retarget, the checkpoint still carries the complete prefix from
        // genesis, so it can be independently checked against the selected rules. Once the
        // prefix has been pruned, authenticating the checkpoint is an external caller duty.
        if expected_start == 0 {
            let mut restored =
                Self::new(params).map_err(|_| TargetHistoryCheckpointError::InvalidProfile)?;
            for entry in snapshot.entries.iter().skip(1) {
                let timestamp = entry
                    .timestamp
                    .ok_or(TargetHistoryCheckpointError::MissingTimestamp)?;
                let expected = restored
                    .expected_target(entry.height, None)
                    .map_err(|_| TargetHistoryCheckpointError::RetargetHistoryInvalid)?;
                if entry.target != expected {
                    return Err(TargetHistoryCheckpointError::RetargetHistoryInvalid);
                }
                restored
                    .record_next(entry.height, entry.target, timestamp)
                    .map_err(|_| TargetHistoryCheckpointError::RetargetHistoryInvalid)?;
            }
            return Ok(restored);
        }

        Ok(Self {
            params,
            start_height: snapshot.start_height,
            logical_height: snapshot.logical_height,
            targets: snapshot.entries.iter().map(|entry| entry.target).collect(),
            timestamps: snapshot
                .entries
                .iter()
                .map(|entry| entry.timestamp)
                .collect(),
        })
    }

    pub fn expected_target(
        &self,
        next_height: u64,
        measured_window_elapsed_secs: Option<u64>,
    ) -> Result<Uint256, PrivateConsensusError> {
        let previous_target = self.target_at(next_height.saturating_sub(1)).ok_or(
            PrivateConsensusError::Consensus(ConsensusError::InvalidNextBlockHeight),
        )?;
        let branch_elapsed = self.observed_window_elapsed_secs(next_height)?;
        let effective_elapsed = match (branch_elapsed, measured_window_elapsed_secs) {
            (Some(derived), Some(supplied)) if derived != supplied => {
                return Err(PrivateConsensusError::RetargetObservationMismatch);
            }
            (Some(derived), _) => Some(derived),
            (None, supplied) => supplied,
        };
        crate::private_testnet_consensus::target_for_next_block(
            previous_target,
            next_height,
            effective_elapsed,
            &self.params,
        )
    }

    /// Derive the retarget observation exclusively from this branch's accepted block timestamps.
    ///
    /// At a boundary for next_height=N, the window covers heights N-window..=N-1. The
    /// timestamp difference contains window-1 intervals, so one configured target interval is
    /// added to obtain the window's window-block duration without relying on a node-local clock
    /// or an operator-supplied elapsed value. For the first 2,016-block window, this is
    /// timestamp[2,016] - timestamp[1] + target_block_time_secs.
    fn observed_window_elapsed_secs(
        &self,
        next_height: u64,
    ) -> Result<Option<u64>, PrivateConsensusError> {
        let window = self.params.difficulty_window_blocks;
        if next_height <= window || (next_height - 1) % window != 0 {
            return Ok(None);
        }

        let first_height =
            next_height
                .checked_sub(window)
                .ok_or(PrivateConsensusError::Consensus(
                    ConsensusError::InvalidNextBlockHeight,
                ))?;
        let last_height = next_height
            .checked_sub(1)
            .ok_or(PrivateConsensusError::Consensus(
                ConsensusError::InvalidNextBlockHeight,
            ))?;
        let first_timestamp =
            self.timestamp_at(first_height)
                .flatten()
                .ok_or(PrivateConsensusError::Consensus(
                    ConsensusError::MissingRetargetObservation,
                ))?;
        let last_timestamp =
            self.timestamp_at(last_height)
                .flatten()
                .ok_or(PrivateConsensusError::Consensus(
                    ConsensusError::MissingRetargetObservation,
                ))?;
        let observed = last_timestamp
            .checked_sub(first_timestamp)
            .ok_or(PrivateConsensusError::InvalidRetargetTimestampRange)?;
        let elapsed = observed
            .checked_add(self.params.target_block_time_secs)
            .ok_or(PrivateConsensusError::Consensus(
                ConsensusError::DifficultyOverflow,
            ))?;
        Ok(Some(elapsed))
    }

    /// Validate the next history record before a state transition is applied. Keeping this
    /// check separate prevents a rejected timestamp/height/target from leaving chain state
    /// advanced while target history and the consensus tip remain at the parent.
    fn validate_next(
        &self,
        height: u64,
        target: Uint256,
        timestamp: u64,
    ) -> Result<(), PrivateConsensusError> {
        let expected_height =
            self.height()
                .checked_add(1)
                .ok_or(PrivateConsensusError::Consensus(
                    ConsensusError::InvalidNextBlockHeight,
                ))?;
        if height != expected_height {
            return Err(PrivateConsensusError::HeaderBodyMismatch(
                "target_history_height",
            ));
        }
        if target.is_zero() {
            return Err(PrivateConsensusError::Consensus(
                ConsensusError::InvalidTarget,
            ));
        }
        if target > self.params.pow_limit {
            return Err(PrivateConsensusError::Consensus(
                ConsensusError::TargetAbovePowLimit,
            ));
        }
        if self
            .timestamps
            .back()
            .copied()
            .flatten()
            .is_some_and(|previous| timestamp <= previous)
        {
            return Err(PrivateConsensusError::InvalidRetargetTimestampRange);
        }
        Ok(())
    }

    fn record_next(
        &mut self,
        height: u64,
        target: Uint256,
        timestamp: u64,
    ) -> Result<(), PrivateConsensusError> {
        self.validate_next(height, target, timestamp)?;
        self.targets.push_back(target);
        self.timestamps.push_back(Some(timestamp));
        self.logical_height = height;
        // Keep enough accepted records for the next retarget window, but don't grow the
        // per-chain history forever. Retain W entries at heights H-W+1..=H once H >= W.
        if self.targets.len() as u64 > self.params.difficulty_window_blocks {
            self.targets.pop_front();
            self.timestamps.pop_front();
            self.start_height =
                self.start_height
                    .checked_add(1)
                    .ok_or(PrivateConsensusError::Consensus(
                        ConsensusError::InvalidNextBlockHeight,
                    ))?;
        }
        Ok(())
    }
}

/// Fail-closed errors when restoring a chain baseline from an externally anchored PFM5 manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pfm5CheckpointRestoreError {
    MissingTrustedManifestAnchor,
    ManifestAnchorMismatch,
    ManifestGenerationRollback,
    CheckpointHeightRollback,
    ManifestRequiresArchiveReplay,
    InvalidManifest(String),
    InvalidCheckpoint(String),
    InvalidMonetarySnapshot(String),
    InvalidTargetHistory(String),
}

impl std::fmt::Display for Pfm5CheckpointRestoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingTrustedManifestAnchor => f.write_str("PFM5 restore requires a nonzero manifest commitment from an independently protected trust source"),
            Self::ManifestAnchorMismatch => f.write_str("PFM5 manifest commitment does not match the trusted external anchor"),
            Self::ManifestGenerationRollback => f.write_str("PFM5 manifest generation is below the trusted monotonic floor"),
            Self::CheckpointHeightRollback => f.write_str("PFM5 checkpoint height is below the trusted monotonic floor"),
            Self::ManifestRequiresArchiveReplay => f.write_str("PFM5 manifest describes post-checkpoint branches; replay and validate them before selecting its canonical tip"),
            Self::InvalidManifest(error) => write!(f, "PFM5 manifest rejected: {error}"),
            Self::InvalidCheckpoint(error) => write!(f, "PCP4 checkpoint rejected: {error}"),
            Self::InvalidMonetarySnapshot(error) => write!(f, "PCP4 monetary snapshot rejected: {error}"),
            Self::InvalidTargetHistory(error) => write!(f, "PCP4 target-history checkpoint rejected: {error}"),
        }
    }
}

impl std::error::Error for Pfm5CheckpointRestoreError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateTestnetChain {
    /// Public legacy-state view retained for existing PTB2 callers. On a monetary
    /// chain this mirrors the ledger stored inside monetary_state; all monetary writes
    /// must go through append_monetary_live and cannot use the legacy append method.
    state: LedgerState,
    monetary_state: Option<MonetaryLedgerState>,
    target_history: TargetHistory,
    cumulative_work: Uint256,
    /// Consensus tip identifier. This includes PoW-header uniqueness; BLK2 state tip hashes
    /// intentionally do not include nonce/target and therefore cannot identify PoW forks alone.
    tip_consensus_hash: [u8; 32],
}

impl PrivateTestnetChain {
    pub fn new(state: LedgerState, params: ConsensusParameters) -> Result<Self, ConsensusError> {
        let tip_consensus_hash = state.tip_hash();
        Ok(Self {
            state,
            monetary_state: None,
            target_history: TargetHistory::new(params)?,
            cumulative_work: Uint256::ZERO,
            tip_consensus_hash,
        })
    }

    /// Construct a PoW-driven chain over the versioned MBK3/MST3 monetary transition.
    /// This reuses the shared target history/work logic, but archive/wire/runtime persistence
    /// must still be integrated separately before this can be a production chain.
    /// Restore a checkpoint baseline only when the exact canonical PFM5 commitment is anchored
    /// outside the rollback domain and meets the caller's monotonic generation/height floors.
    ///
    /// This method intentionally refuses manifests with retained post-checkpoint branch digests:
    /// those envelopes must first be loaded, authenticated, replayed and compared with fork choice.
    /// It restores a baseline; it is not by itself a full PFM5 durable-store or runtime integration.
    pub fn restore_from_pfm5_checkpoint(
        manifest: &Pfm5CheckpointManifest,
        checkpoint: &Pcp4CheckpointRecord,
        context: &Pcp4ValidationContext<'_>,
        expected_manifest_commitment: [u8; 32],
        minimum_generation: u64,
        minimum_checkpoint_height: u64,
    ) -> Result<Self, Pfm5CheckpointRestoreError> {
        if expected_manifest_commitment == [0; 32] || minimum_generation == 0 {
            return Err(Pfm5CheckpointRestoreError::MissingTrustedManifestAnchor);
        }
        let commitment = manifest
            .commitment()
            .map_err(|error| Pfm5CheckpointRestoreError::InvalidManifest(error.to_string()))?;
        if commitment != expected_manifest_commitment {
            return Err(Pfm5CheckpointRestoreError::ManifestAnchorMismatch);
        }
        if manifest.generation < minimum_generation {
            return Err(Pfm5CheckpointRestoreError::ManifestGenerationRollback);
        }
        if manifest.checkpoint_height < minimum_checkpoint_height {
            return Err(Pfm5CheckpointRestoreError::CheckpointHeightRollback);
        }
        manifest
            .validate_checkpoint(checkpoint, context)
            .map_err(|error| Pfm5CheckpointRestoreError::InvalidCheckpoint(error.to_string()))?;
        if !manifest.branch_digests.is_empty()
            || manifest.canonical_tip_height != checkpoint.logical_height
            || manifest.canonical_tip_digest != checkpoint.consensus_tip_digest
        {
            return Err(Pfm5CheckpointRestoreError::ManifestRequiresArchiveReplay);
        }
        let state =
            MonetaryLedgerState::decode_snapshot(&checkpoint.monetary_snapshot, context.network_id)
                .map_err(|error| {
                    Pfm5CheckpointRestoreError::InvalidMonetarySnapshot(format!("{error:?}"))
                })?;
        if state.height() != checkpoint.logical_height
            || state.tip_hash() != checkpoint.ledger_tip_hash
            || state.state_root() != checkpoint.monetary_state_root
            || state.total_mined_atoms() != checkpoint.total_mined_atoms
        {
            return Err(Pfm5CheckpointRestoreError::InvalidMonetarySnapshot(
                "decoded state does not match PCP4 summary fields".into(),
            ));
        }
        let target_history = TargetHistory::from_checkpoint_snapshot(
            context.params.clone(),
            &checkpoint.target_history,
        )
        .map_err(|error| Pfm5CheckpointRestoreError::InvalidTargetHistory(error.to_string()))?;
        if target_history.height() != checkpoint.logical_height {
            return Err(Pfm5CheckpointRestoreError::InvalidTargetHistory(
                "restored target history height differs from checkpoint height".into(),
            ));
        }
        Ok(Self {
            state: state.ledger().clone(),
            monetary_state: Some(state),
            target_history,
            cumulative_work: checkpoint.cumulative_chainwork,
            tip_consensus_hash: checkpoint.consensus_tip_digest,
        })
    }

    pub fn new_monetary(
        state: MonetaryLedgerState,
        params: ConsensusParameters,
    ) -> Result<Self, ConsensusError> {
        // State transitions currently consume the frozen candidate constants in state_machine;
        // reject a PoW profile that would claim different issuance economics in its fingerprint.
        params.validate_monetary_execution_compatibility()?;
        let ledger_view = state.ledger().clone();
        let tip_consensus_hash = state.tip_hash();
        Ok(Self {
            state: ledger_view,
            monetary_state: Some(state),
            target_history: TargetHistory::new(params)?,
            cumulative_work: Uint256::ZERO,
            tip_consensus_hash,
        })
    }

    pub fn monetary_state(&self) -> Option<&MonetaryLedgerState> {
        self.monetary_state.as_ref()
    }

    pub fn state(&self) -> &LedgerState {
        &self.state
    }

    pub fn target_history(&self) -> &TargetHistory {
        &self.target_history
    }

    pub fn cumulative_work(&self) -> Uint256 {
        self.cumulative_work
    }

    pub fn chain_tip(&self) -> ChainTip {
        ChainTip {
            height: self.state.height(),
            cumulative_work: self.cumulative_work,
            tip_hash: self.tip_consensus_hash,
        }
    }

    pub fn fork(&self) -> Self {
        self.clone()
    }

    pub fn compare_to(&self, other: &Self) -> std::cmp::Ordering {
        compare_chain_tips(self.chain_tip(), other.chain_tip())
    }

    pub fn expected_target(
        &self,
        measured_window_elapsed_secs: Option<u64>,
    ) -> Result<Uint256, PrivateConsensusError> {
        self.target_history.expected_target(
            self.state.height().saturating_add(1),
            measured_window_elapsed_secs,
        )
    }

    pub fn append_live<A: TransactionAuthenticator>(
        &mut self,
        block: &Block,
        pow_header: &crate::consensus::PowHeader,
        measured_window_elapsed_secs: Option<u64>,
        authenticator: &A,
        clock: &dyn ReferenceTimeProvider,
    ) -> Result<(BlockAdmissionReceipt, [u8; 32]), PrivateConsensusError> {
        if self.monetary_state.is_some() {
            return Err(PrivateConsensusError::LegacyBlockOnMonetaryChain);
        }
        let next_height = self.state.height().saturating_add(1);
        let expected_target = self
            .target_history
            .expected_target(next_height, measured_window_elapsed_secs)?;

        if pow_header.target != expected_target {
            return Err(PrivateConsensusError::ExpectedTargetMismatch);
        }
        self.target_history
            .validate_next(next_height, pow_header.target, pow_header.timestamp)?;

        let next_cumulative_work =
            checked_cumulative_work_after_block(self.cumulative_work, pow_header.target)?;
        let (receipt, digest) = admit_candidate_live(
            &mut self.state,
            CandidateConsensusBlock { block, pow_header },
            self.tip_consensus_hash,
            expected_target,
            &self.target_history.params,
            authenticator,
            clock,
        )?;

        self.target_history
            .record_next(next_height, pow_header.target, pow_header.timestamp)?;
        self.cumulative_work = next_cumulative_work;
        self.tip_consensus_hash = digest;

        Ok((receipt, digest))
    }

    /// Validate and append a PoW candidate using exact scheduled monetary issuance.
    /// The legacy PTB2/block-body path and monetary MBK3 path are mutually exclusive.
    pub fn append_monetary_live<A: TransactionAuthenticator>(
        &mut self,
        block: &MonetaryBlock,
        pow_header: &crate::consensus::PowHeader,
        measured_window_elapsed_secs: Option<u64>,
        authenticator: &A,
        clock: &dyn ReferenceTimeProvider,
    ) -> Result<(BlockAdmissionReceipt, [u8; 32]), PrivateConsensusError> {
        let Some(monetary_state) = self.monetary_state.as_mut() else {
            return Err(PrivateConsensusError::MonetaryBlockOnLegacyChain);
        };
        let next_height =
            monetary_state
                .height()
                .checked_add(1)
                .ok_or(PrivateConsensusError::Consensus(
                    ConsensusError::InvalidNextBlockHeight,
                ))?;
        let expected_target = self
            .target_history
            .expected_target(next_height, measured_window_elapsed_secs)?;

        if pow_header.network_id != monetary_state.ledger().network_id() {
            return Err(PrivateConsensusError::NetworkMismatch);
        }
        if pow_header.protocol_version != self.target_history.params.protocol_version {
            return Err(PrivateConsensusError::HeaderBodyMismatch(
                "protocol_version",
            ));
        }
        if pow_header.height != block.body.height {
            return Err(PrivateConsensusError::HeaderBodyMismatch("height"));
        }
        if pow_header.timestamp != block.body.timestamp {
            return Err(PrivateConsensusError::HeaderBodyMismatch("timestamp"));
        }
        if pow_header.parent_hash != block.body.parent_hash {
            return Err(PrivateConsensusError::HeaderBodyMismatch("parent_hash"));
        }
        if pow_header.previous_consensus_hash != self.tip_consensus_hash {
            return Err(PrivateConsensusError::HeaderBodyMismatch(
                "previous_consensus_hash",
            ));
        }
        if pow_header.state_root != block.body.state_root {
            return Err(PrivateConsensusError::HeaderBodyMismatch("state_root"));
        }
        if pow_header.target != expected_target {
            return Err(PrivateConsensusError::ExpectedTargetMismatch);
        }
        self.target_history
            .validate_next(next_height, pow_header.target, pow_header.timestamp)?;

        let next_cumulative_work =
            checked_cumulative_work_after_block(self.cumulative_work, pow_header.target)?;
        let digest = crate::consensus::verify_pow(pow_header, &self.target_history.params)?;
        let receipt = ChainAdmissionBoundary::testnet()
            .admit_live_monetary(monetary_state, block, authenticator, clock)
            .map_err(PrivateConsensusError::Admission)?;

        self.state = self
            .monetary_state
            .as_ref()
            .expect("monetary state checked before admission")
            .ledger()
            .clone();
        self.target_history
            .record_next(next_height, pow_header.target, pow_header.timestamp)?;
        self.cumulative_work = next_cumulative_work;
        self.tip_consensus_hash = digest;
        Ok((receipt, digest))
    }

    /// Deterministic monetary replay does not sample wall-clock time. It still validates
    /// network/header/parent/height, expected difficulty, PoW and the complete monetary
    /// state transition; historical timestamps must increase but are not checked against
    /// a present-day future window.
    pub fn append_monetary_historical<A: TransactionAuthenticator>(
        &mut self,
        block: &MonetaryBlock,
        pow_header: &crate::consensus::PowHeader,
        measured_window_elapsed_secs: Option<u64>,
        authenticator: &A,
    ) -> Result<(BlockAdmissionReceipt, [u8; 32]), PrivateConsensusError> {
        let Some(monetary_state) = self.monetary_state.as_mut() else {
            return Err(PrivateConsensusError::MonetaryBlockOnLegacyChain);
        };
        let next_height =
            monetary_state
                .height()
                .checked_add(1)
                .ok_or(PrivateConsensusError::Consensus(
                    ConsensusError::InvalidNextBlockHeight,
                ))?;
        let expected_target = self
            .target_history
            .expected_target(next_height, measured_window_elapsed_secs)?;

        if pow_header.network_id != monetary_state.ledger().network_id() {
            return Err(PrivateConsensusError::NetworkMismatch);
        }
        if pow_header.protocol_version != self.target_history.params.protocol_version {
            return Err(PrivateConsensusError::HeaderBodyMismatch(
                "protocol_version",
            ));
        }
        if pow_header.height != block.body.height {
            return Err(PrivateConsensusError::HeaderBodyMismatch("height"));
        }
        if pow_header.timestamp != block.body.timestamp {
            return Err(PrivateConsensusError::HeaderBodyMismatch("timestamp"));
        }
        if pow_header.parent_hash != block.body.parent_hash {
            return Err(PrivateConsensusError::HeaderBodyMismatch("parent_hash"));
        }
        if pow_header.previous_consensus_hash != self.tip_consensus_hash {
            return Err(PrivateConsensusError::HeaderBodyMismatch(
                "previous_consensus_hash",
            ));
        }
        if pow_header.state_root != block.body.state_root {
            return Err(PrivateConsensusError::HeaderBodyMismatch("state_root"));
        }
        if pow_header.target != expected_target {
            return Err(PrivateConsensusError::ExpectedTargetMismatch);
        }
        self.target_history
            .validate_next(next_height, pow_header.target, pow_header.timestamp)?;

        let next_cumulative_work =
            checked_cumulative_work_after_block(self.cumulative_work, pow_header.target)?;
        let digest = crate::consensus::verify_pow(pow_header, &self.target_history.params)?;
        let receipt = ChainAdmissionBoundary::testnet()
            .replay_monetary(monetary_state, block, authenticator)
            .map_err(PrivateConsensusError::Admission)?;

        self.state = self
            .monetary_state
            .as_ref()
            .expect("monetary state checked before replay")
            .ledger()
            .clone();
        self.target_history
            .record_next(next_height, pow_header.target, pow_header.timestamp)?;
        self.cumulative_work = next_cumulative_work;
        self.tip_consensus_hash = digest;
        Ok((receipt, digest))
    }

    /// Validate and append a PoW candidate using canonical MBK4/TXN4 hybrid authorization.
    /// This remains a separate candidate chain path until PMT4/PFM4 node wiring is complete.
    pub fn append_v4_hybrid_monetary_live<
        V: crate::v4_account_identity_candidate::MlDsa65Verifier,
    >(
        &mut self,
        block: &crate::state_machine::V4HybridMonetaryBlock,
        pow_header: &crate::consensus::PowHeader,
        measured_window_elapsed_secs: Option<u64>,
        expected_manifest_id: &[u8; 32],
        verifier: &V,
        clock: &dyn ReferenceTimeProvider,
    ) -> Result<(BlockAdmissionReceipt, [u8; 32]), PrivateConsensusError> {
        let Some(monetary_state) = self.monetary_state.as_mut() else {
            return Err(PrivateConsensusError::MonetaryBlockOnLegacyChain);
        };
        let next_height =
            monetary_state
                .height()
                .checked_add(1)
                .ok_or(PrivateConsensusError::Consensus(
                    ConsensusError::InvalidNextBlockHeight,
                ))?;
        let expected_target = self
            .target_history
            .expected_target(next_height, measured_window_elapsed_secs)?;

        if pow_header.network_id != monetary_state.ledger().network_id() {
            return Err(PrivateConsensusError::NetworkMismatch);
        }
        if pow_header.protocol_version != self.target_history.params.protocol_version {
            return Err(PrivateConsensusError::HeaderBodyMismatch(
                "protocol_version",
            ));
        }
        if pow_header.height != block.height {
            return Err(PrivateConsensusError::HeaderBodyMismatch("height"));
        }
        if pow_header.timestamp != block.timestamp {
            return Err(PrivateConsensusError::HeaderBodyMismatch("timestamp"));
        }
        if pow_header.parent_hash != block.parent_hash {
            return Err(PrivateConsensusError::HeaderBodyMismatch("parent_hash"));
        }
        if pow_header.previous_consensus_hash != self.tip_consensus_hash {
            return Err(PrivateConsensusError::HeaderBodyMismatch(
                "previous_consensus_hash",
            ));
        }
        if pow_header.state_root != block.state_root {
            return Err(PrivateConsensusError::HeaderBodyMismatch("state_root"));
        }
        if block
            .transactions
            .iter()
            .any(|tx| tx.authorization.network_id != pow_header.network_id)
        {
            return Err(PrivateConsensusError::HeaderBodyMismatch(
                "transaction.network_id",
            ));
        }
        if pow_header.target != expected_target {
            return Err(PrivateConsensusError::ExpectedTargetMismatch);
        }
        self.target_history
            .validate_next(next_height, pow_header.target, pow_header.timestamp)?;

        let next_cumulative_work =
            checked_cumulative_work_after_block(self.cumulative_work, pow_header.target)?;
        let digest = crate::consensus::verify_pow(pow_header, &self.target_history.params)?;
        let receipt = ChainAdmissionBoundary::testnet()
            .admit_live_v4_hybrid_monetary(
                monetary_state,
                block,
                expected_manifest_id,
                verifier,
                clock,
            )
            .map_err(PrivateConsensusError::Admission)?;

        self.state = self
            .monetary_state
            .as_ref()
            .expect("monetary state checked before V4 admission")
            .ledger()
            .clone();
        self.target_history
            .record_next(next_height, pow_header.target, pow_header.timestamp)?;
        self.cumulative_work = next_cumulative_work;
        self.tip_consensus_hash = digest;
        Ok((receipt, digest))
    }

    /// Deterministic historical append for replaying a canonical MBK4/TXN4 branch.
    /// It verifies PoW and ancestry but deliberately does not sample present-day time.
    pub fn append_v4_hybrid_monetary_historical<
        V: crate::v4_account_identity_candidate::MlDsa65Verifier,
    >(
        &mut self,
        block: &crate::state_machine::V4HybridMonetaryBlock,
        pow_header: &crate::consensus::PowHeader,
        measured_window_elapsed_secs: Option<u64>,
        expected_manifest_id: &[u8; 32],
        verifier: &V,
    ) -> Result<(BlockAdmissionReceipt, [u8; 32]), PrivateConsensusError> {
        let Some(monetary_state) = self.monetary_state.as_mut() else {
            return Err(PrivateConsensusError::MonetaryBlockOnLegacyChain);
        };
        let next_height =
            monetary_state
                .height()
                .checked_add(1)
                .ok_or(PrivateConsensusError::Consensus(
                    ConsensusError::InvalidNextBlockHeight,
                ))?;
        let expected_target = self
            .target_history
            .expected_target(next_height, measured_window_elapsed_secs)?;

        if pow_header.network_id != monetary_state.ledger().network_id() {
            return Err(PrivateConsensusError::NetworkMismatch);
        }
        if pow_header.protocol_version != self.target_history.params.protocol_version {
            return Err(PrivateConsensusError::HeaderBodyMismatch(
                "protocol_version",
            ));
        }
        if pow_header.height != block.height {
            return Err(PrivateConsensusError::HeaderBodyMismatch("height"));
        }
        if pow_header.timestamp != block.timestamp {
            return Err(PrivateConsensusError::HeaderBodyMismatch("timestamp"));
        }
        if pow_header.parent_hash != block.parent_hash {
            return Err(PrivateConsensusError::HeaderBodyMismatch("parent_hash"));
        }
        if pow_header.previous_consensus_hash != self.tip_consensus_hash {
            return Err(PrivateConsensusError::HeaderBodyMismatch(
                "previous_consensus_hash",
            ));
        }
        if pow_header.state_root != block.state_root {
            return Err(PrivateConsensusError::HeaderBodyMismatch("state_root"));
        }
        if block
            .transactions
            .iter()
            .any(|tx| tx.authorization.network_id != pow_header.network_id)
        {
            return Err(PrivateConsensusError::HeaderBodyMismatch(
                "transaction.network_id",
            ));
        }
        if pow_header.target != expected_target {
            return Err(PrivateConsensusError::ExpectedTargetMismatch);
        }
        self.target_history
            .validate_next(next_height, pow_header.target, pow_header.timestamp)?;

        let next_cumulative_work =
            checked_cumulative_work_after_block(self.cumulative_work, pow_header.target)?;
        let digest = crate::consensus::verify_pow(pow_header, &self.target_history.params)?;
        let receipt = ChainAdmissionBoundary::testnet()
            .replay_v4_hybrid_monetary(monetary_state, block, expected_manifest_id, verifier)
            .map_err(PrivateConsensusError::Admission)?;

        self.state = self
            .monetary_state
            .as_ref()
            .expect("monetary state checked before V4 replay")
            .ledger()
            .clone();
        self.target_history
            .record_next(next_height, pow_header.target, pow_header.timestamp)?;
        self.cumulative_work = next_cumulative_work;
        self.tip_consensus_hash = digest;
        Ok((receipt, digest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chain_admission::{ChainAdmissionError, ReferenceTimeProvenance, ReferenceTimeSample},
        consensus::PowHeader,
        state_machine::{AccountId, StateError},
    };

    struct EmptyAuthenticator;
    impl TransactionAuthenticator for EmptyAuthenticator {
        fn verify(&self, _: &AccountId, _: &[u8; 32], _: &[u8]) -> Result<(), ()> {
            Ok(())
        }
    }

    struct FixedClock;
    impl ReferenceTimeProvider for FixedClock {
        fn sample(
            &self,
        ) -> Result<ReferenceTimeSample, crate::chain_admission::ReferenceTimeError> {
            Ok(ReferenceTimeSample {
                unix_seconds: 100,
                provenance: ReferenceTimeProvenance::ConfiguredProvider,
                source_id: "private-testnet-driver-clock",
            })
        }
    }

    fn params() -> ConsensusParameters {
        let mut params = ConsensusParameters::candidate_testnet().unwrap();
        params.initial_target = Uint256::MAX;
        params.pow_limit = Uint256::MAX;
        params
    }

    fn state() -> LedgerState {
        LedgerState::genesis([0xA7; 32], vec![([1; 32], 1_000)]).unwrap()
    }

    fn monetary_state() -> MonetaryLedgerState {
        MonetaryLedgerState::genesis(
            [0xA7; 32],
            [1; 32],
            vec![(
                [2; 32],
                crate::state_machine::MONETARY_PUBLIC_GOODS_BUDGET_ATOMS as u64,
            )],
        )
        .unwrap()
    }

    fn monetary_block(
        state: &MonetaryLedgerState,
        timestamp: u64,
        miner: AccountId,
    ) -> MonetaryBlock {
        let mut block = MonetaryBlock {
            body: Block {
                height: state.height() + 1,
                timestamp,
                parent_hash: state.tip_hash(),
                state_root: [0; 32],
                transactions: Vec::new(),
            },
            miner,
            claimed_subsidy_atoms: state.expected_miner_reward().unwrap(),
        };
        block.body.state_root = state
            .preview_state_root_after(&block, &EmptyAuthenticator)
            .unwrap();
        block
    }

    fn monetary_header(
        chain: &PrivateTestnetChain,
        block: &MonetaryBlock,
        params: &ConsensusParameters,
        nonce: u64,
    ) -> PowHeader {
        PowHeader {
            protocol_version: params.protocol_version,
            network_id: chain
                .monetary_state()
                .expect("monetary fixture")
                .ledger()
                .network_id(),
            height: block.body.height,
            timestamp: block.body.timestamp,
            parent_hash: block.body.parent_hash,
            previous_consensus_hash: chain.chain_tip().tip_hash,
            state_root: block.body.state_root,
            target: params.initial_target,
            nonce,
        }
    }

    fn body(state: &LedgerState, timestamp: u64) -> Block {
        let mut block = Block {
            height: state.height() + 1,
            timestamp,
            parent_hash: state.tip_hash(),
            state_root: [0; 32],
            transactions: Vec::new(),
        };
        block.state_root = state
            .preview_state_root_after(&block, &EmptyAuthenticator)
            .unwrap();
        block
    }

    fn header(
        state: &LedgerState,
        block: &Block,
        params: &ConsensusParameters,
        target: Uint256,
        nonce: u64,
    ) -> PowHeader {
        PowHeader {
            protocol_version: params.protocol_version,
            network_id: state.network_id(),
            height: block.height,
            timestamp: block.timestamp,
            parent_hash: block.parent_hash,
            previous_consensus_hash: state.tip_hash(),
            state_root: block.state_root,
            target,
            nonce,
        }
    }

    #[test]
    fn driver_tracks_target_and_work_after_each_block() {
        let params = params();
        let mut chain = PrivateTestnetChain::new(state(), params.clone()).unwrap();
        let block = body(chain.state(), 100);
        let header = header(chain.state(), &block, &params, params.initial_target, 0);

        chain
            .append_live(&block, &header, None, &EmptyAuthenticator, &FixedClock)
            .unwrap();

        assert_eq!(chain.state().height(), 1);
        assert_eq!(
            chain.target_history().target_at(1),
            Some(params.initial_target)
        );
        assert_eq!(
            chain.cumulative_work(),
            block_work(params.initial_target).unwrap()
        );
    }

    #[test]
    fn driver_rejects_cumulative_work_overflow_before_mutating_state() {
        let params = params();
        let mut chain = PrivateTestnetChain::new(state(), params.clone()).unwrap();
        chain.cumulative_work = Uint256::MAX;
        let block = body(chain.state(), 100);
        let candidate_header = header(chain.state(), &block, &params, params.initial_target, 0);
        let before = chain.clone();

        assert_eq!(
            chain.append_live(
                &block,
                &candidate_header,
                None,
                &EmptyAuthenticator,
                &FixedClock
            ),
            Err(PrivateConsensusError::Consensus(
                ConsensusError::ChainworkOverflow
            ))
        );
        assert_eq!(
            chain, before,
            "overflow must fail before state, history, or tip mutation"
        );
    }
    #[test]
    fn second_block_must_link_the_accepted_pow_digest_not_just_the_body_parent() {
        let params = params();
        let mut chain = PrivateTestnetChain::new(state(), params.clone()).unwrap();
        let first = body(chain.state(), 100);
        let first_header = header(chain.state(), &first, &params, params.initial_target, 1);
        chain
            .append_live(
                &first,
                &first_header,
                None,
                &EmptyAuthenticator,
                &FixedClock,
            )
            .unwrap();

        let second = body(chain.state(), 101);
        let mut wrong_link = header(chain.state(), &second, &params, params.initial_target, 2);
        // The helper defaults to the BLK2 state tip; this is not necessarily the accepted PoW digest.
        assert_ne!(
            wrong_link.previous_consensus_hash,
            chain.chain_tip().tip_hash
        );
        let before = chain.clone();
        assert_eq!(
            chain.append_live(&second, &wrong_link, None, &EmptyAuthenticator, &FixedClock),
            Err(PrivateConsensusError::HeaderBodyMismatch(
                "previous_consensus_hash"
            ))
        );
        assert_eq!(chain, before);

        wrong_link.previous_consensus_hash = chain.chain_tip().tip_hash;
        chain
            .append_live(&second, &wrong_link, None, &EmptyAuthenticator, &FixedClock)
            .unwrap();
        assert_eq!(chain.state().height(), 2);
    }

    #[test]
    fn driver_derives_retarget_duration_from_branch_timestamps_and_rejects_override() {
        let params = params();
        let initial_target = params.initial_target;
        let target_block_time = params.target_block_time_secs;
        let window = params.difficulty_window_blocks;
        let expected = target_block_time * window;
        let mut history = TargetHistory::new(params).unwrap();
        for height in 1..=window {
            history
                .record_next(height, initial_target, height * target_block_time)
                .unwrap();
        }
        assert_eq!(
            history.expected_target(window + 1, None),
            Ok(initial_target)
        );
        assert_eq!(
            history.expected_target(window + 1, Some(expected)),
            Ok(initial_target)
        );
        assert_eq!(
            history.expected_target(window + 1, Some(expected / 2)),
            Err(PrivateConsensusError::RetargetObservationMismatch)
        );

        // A missing timestamp in the branch history must not be overridden by an operator's
        // supplied elapsed value, even if that value would otherwise be a valid duration.
        let mut incomplete = history.clone();
        incomplete.timestamps[0] = None;
        assert_eq!(
            incomplete.expected_target(window + 1, Some(expected)),
            Err(PrivateConsensusError::Consensus(
                ConsensusError::MissingRetargetObservation
            ))
        );
    }

    #[test]
    fn driver_retargets_from_branch_timestamp_window_deterministically() {
        let mut params = params();
        let initial_target = Uint256::from_be_bytes([0x7F; 32]);
        params.initial_target = initial_target;
        params.pow_limit = Uint256::MAX;
        let target_block_time = params.target_block_time_secs;
        let window = params.difficulty_window_blocks;
        let first_epoch = 10_000u64;
        let timestamp_step = target_block_time / 2;
        let mut history = TargetHistory::new(params.clone()).unwrap();

        for height in 1..=window {
            history
                .record_next(
                    height,
                    initial_target,
                    first_epoch + height * timestamp_step,
                )
                .unwrap();
        }

        // Window N..=1 + the configured virtual initial interval gives exactly N intervals.
        let first_timestamp = first_epoch + timestamp_step;
        let last_timestamp = first_epoch + window * timestamp_step;
        let elapsed = last_timestamp
            .checked_sub(first_timestamp)
            .unwrap()
            .checked_add(target_block_time)
            .unwrap();
        assert_eq!(elapsed, (window - 1) * timestamp_step + target_block_time);

        let independent_expected =
            crate::consensus::retarget_target(initial_target, elapsed, &params).unwrap();
        let derived = history.expected_target(window + 1, None).unwrap();
        assert_eq!(derived, independent_expected);
        assert_ne!(derived, initial_target);
        assert_eq!(
            history.expected_target(window + 1, Some(elapsed)),
            Ok(independent_expected)
        );
        assert_eq!(
            history.expected_target(window + 1, Some(elapsed + 1)),
            Err(PrivateConsensusError::RetargetObservationMismatch)
        );

        // Each branch must retain monotonically increasing timestamps in its own history.
        let mut malformed = history.clone();
        malformed.timestamps[window as usize - 1] = Some(first_timestamp - 1);
        assert_eq!(
            malformed.expected_target(window + 1, None),
            Err(PrivateConsensusError::InvalidRetargetTimestampRange)
        );

        // Once H=W, live history itself is bounded to logical heights 1..=W.
        assert_eq!(history.start_height, 1);
        assert_eq!(history.targets.len(), window as usize);
        assert_eq!(history.timestamps[0], Some(first_timestamp));
        assert_eq!(
            history.timestamps[window as usize - 1],
            Some(last_timestamp)
        );

        // A bounded checkpoint at H=W retains logical heights 1..=W. Restore must
        // preserve absolute heights, including the first default retarget at W+1.
        let checkpoint = history.checkpoint_snapshot().unwrap();
        assert_eq!(checkpoint.logical_height, window);
        assert_eq!(checkpoint.start_height, 1);
        assert_eq!(checkpoint.entries.len(), window as usize);
        assert_eq!(checkpoint.entries.first().unwrap().height, 1);
        assert_eq!(checkpoint.entries.last().unwrap().height, window);
        let mut restored =
            TargetHistory::from_checkpoint_snapshot(params.clone(), &checkpoint).unwrap();
        assert_eq!(restored.height(), window);
        assert_eq!(restored.target_at(window), history.target_at(window));
        assert_eq!(
            restored.expected_target(window + 1, None),
            history.expected_target(window + 1, None)
        );

        // Continue both timelines with identical accepted timestamps; target decisions must
        // remain equal through the second default retarget boundary after another restore.
        for height in (window + 1)..=(2 * window) {
            let expected_original = history.expected_target(height, None).unwrap();
            let expected_restored = restored.expected_target(height, None).unwrap();
            assert_eq!(expected_restored, expected_original, "height {height}");
            let timestamp = first_epoch + height * timestamp_step;
            history
                .record_next(height, expected_original, timestamp)
                .unwrap();
            restored
                .record_next(height, expected_restored, timestamp)
                .unwrap();
        }
        assert_eq!(restored.start_height, window + 1);
        assert_eq!(restored.targets.len(), window as usize);
        assert_eq!(restored.timestamps.len(), window as usize);
        let second_checkpoint = restored.checkpoint_snapshot().unwrap();
        assert_eq!(second_checkpoint.start_height, window + 1);
        assert_eq!(second_checkpoint.entries.len(), window as usize);
        let restored_again =
            TargetHistory::from_checkpoint_snapshot(params.clone(), &second_checkpoint).unwrap();
        assert_eq!(restored_again.height(), 2 * window);
        assert_eq!(
            restored_again.expected_target(2 * window + 1, None),
            history.expected_target(2 * window + 1, None)
        );
    }

    #[test]
    fn target_history_checkpoint_rejects_noncanonical_or_malformed_entries() {
        let mut params = params();
        params.difficulty_window_blocks = 8;

        // Before the first window is complete, keep the genesis entry and independently
        // replay the complete prefix when restoring. A forged historical target must reject.
        let mut short_history = TargetHistory::new(params.clone()).unwrap();
        for height in 1..=3 {
            let expected = short_history.expected_target(height, None).unwrap();
            short_history
                .record_next(height, expected, 10 + height)
                .unwrap();
        }
        let short_checkpoint = short_history.checkpoint_snapshot().unwrap();
        assert_eq!(short_checkpoint.start_height, 0);
        assert_eq!(short_checkpoint.entries.len(), 4);
        let restored_short =
            TargetHistory::from_checkpoint_snapshot(params.clone(), &short_checkpoint).unwrap();
        assert_eq!(restored_short.height(), 3);
        assert_eq!(restored_short.target_at(3), short_history.target_at(3));
        let mut forged_prefix = short_checkpoint.clone();
        forged_prefix.entries[1].target = Uint256::from_be_bytes([0x01; 32]);
        assert_eq!(
            TargetHistory::from_checkpoint_snapshot(params.clone(), &forged_prefix),
            Err(TargetHistoryCheckpointError::RetargetHistoryInvalid)
        );

        let mut history = TargetHistory::new(params.clone()).unwrap();
        for height in 1..=8 {
            let expected = history.expected_target(height, None).unwrap();
            history.record_next(height, expected, 100 + height).unwrap();
        }
        let good = history.checkpoint_snapshot().unwrap();
        assert_eq!(good.start_height, 1);

        let mut wrong_start = good.clone();
        wrong_start.start_height = 0;
        assert_eq!(
            TargetHistory::from_checkpoint_snapshot(params.clone(), &wrong_start),
            Err(TargetHistoryCheckpointError::NonCanonicalRange)
        );

        let mut wrong_height = good.clone();
        wrong_height.entries[0].height += 1;
        assert_eq!(
            TargetHistory::from_checkpoint_snapshot(params.clone(), &wrong_height),
            Err(TargetHistoryCheckpointError::EntryHeightMismatch)
        );

        let mut missing_timestamp = good.clone();
        missing_timestamp.entries[0].timestamp = None;
        assert_eq!(
            TargetHistory::from_checkpoint_snapshot(params.clone(), &missing_timestamp),
            Err(TargetHistoryCheckpointError::MissingTimestamp)
        );

        let mut zero_target = good.clone();
        zero_target.entries[0].target = Uint256::ZERO;
        assert_eq!(
            TargetHistory::from_checkpoint_snapshot(params.clone(), &zero_target),
            Err(TargetHistoryCheckpointError::InvalidTarget)
        );

        let mut nonmonotonic = good.clone();
        nonmonotonic.entries[1].timestamp = nonmonotonic.entries[0].timestamp;
        assert_eq!(
            TargetHistory::from_checkpoint_snapshot(params.clone(), &nonmonotonic),
            Err(TargetHistoryCheckpointError::TimestampNotMonotonic)
        );

        params.difficulty_window_blocks = (MAX_TARGET_HISTORY_CHECKPOINT_ENTRIES as u64) + 1;
        assert_eq!(
            TargetHistory::from_checkpoint_snapshot(params, &good),
            Err(TargetHistoryCheckpointError::EntryBudgetExceeded)
        );
    }

    #[test]
    fn v4_historical_timestamp_history_rejection_is_atomic_before_state_replay() {
        let mut params = params();
        params.pow.memory_kib = 8;
        let manifest = [0xC4; 32];
        let verifier = crate::v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate;
        let mut chain =
            PrivateTestnetChain::new_monetary(monetary_state(), params.clone()).unwrap();

        let first_state = chain.monetary_state().unwrap().clone();
        let mut first_block = crate::state_machine::V4HybridMonetaryBlock {
            height: 1,
            timestamp: 100,
            parent_hash: first_state.tip_hash(),
            state_root: [0; 32],
            transactions: Vec::new(),
            miner: [3; 32],
            claimed_subsidy_atoms: first_state.expected_miner_reward().unwrap(),
        };
        first_block.state_root = first_state
            .preview_v4_hybrid_state_root_after(&first_block, &manifest, &verifier)
            .unwrap();
        let first_header = crate::consensus::PowHeader {
            protocol_version: params.protocol_version,
            network_id: first_state.ledger().network_id(),
            height: 1,
            timestamp: first_block.timestamp,
            parent_hash: first_block.parent_hash,
            previous_consensus_hash: chain.chain_tip().tip_hash,
            state_root: first_block.state_root,
            target: params.initial_target,
            nonce: 0,
        };
        chain
            .append_v4_hybrid_monetary_historical(
                &first_block,
                &first_header,
                None,
                &manifest,
                &verifier,
            )
            .unwrap();

        // Simulate a recovered/corrupted target-history timestamp that disagrees with the
        // accepted ledger tip. The next body timestamp is valid and increasing for the ledger
        // (100 -> 150), but it must be rejected against the branch history (200 -> 150) before
        // replay mutates the ledger. This protects the chain even if its history invariant is
        // damaged by a future restore/import path.
        chain.target_history.timestamps[1] = Some(200);
        let before_chain_tip = chain.chain_tip();
        let before_work = chain.cumulative_work();
        let before_state_tip = chain.monetary_state().unwrap().tip_hash();
        let before_state_height = chain.monetary_state().unwrap().height();
        let before_history = chain.target_history.clone();

        let second_state = chain.monetary_state().unwrap().clone();
        let mut second_block = crate::state_machine::V4HybridMonetaryBlock {
            height: 2,
            timestamp: 150,
            parent_hash: second_state.tip_hash(),
            state_root: [0; 32],
            transactions: Vec::new(),
            miner: [3; 32],
            claimed_subsidy_atoms: second_state.expected_miner_reward().unwrap(),
        };
        second_block.state_root = second_state
            .preview_v4_hybrid_state_root_after(&second_block, &manifest, &verifier)
            .unwrap();
        let second_header = crate::consensus::PowHeader {
            protocol_version: params.protocol_version,
            network_id: second_state.ledger().network_id(),
            height: 2,
            timestamp: second_block.timestamp,
            parent_hash: second_block.parent_hash,
            previous_consensus_hash: chain.chain_tip().tip_hash,
            state_root: second_block.state_root,
            target: chain.expected_target(None).unwrap(),
            nonce: 0,
        };
        assert!(
            Uint256::from_be_bytes(
                crate::consensus::pow_digest(&second_header, params.pow).unwrap()
            ) <= second_header.target
        );
        assert!(
            second_block.timestamp > second_state.ledger().last_timestamp(),
            "body timestamp passes the ledger's ordinary monotonic timestamp rule"
        );

        assert_eq!(
            chain.append_v4_hybrid_monetary_historical(
                &second_block,
                &second_header,
                None,
                &manifest,
                &verifier,
            ),
            Err(PrivateConsensusError::InvalidRetargetTimestampRange)
        );
        assert_eq!(chain.chain_tip(), before_chain_tip);
        assert_eq!(chain.cumulative_work(), before_work);
        assert_eq!(chain.monetary_state().unwrap().tip_hash(), before_state_tip);
        assert_eq!(
            chain.monetary_state().unwrap().height(),
            before_state_height
        );
        assert_eq!(chain.target_history, before_history);
    }

    #[test]
    fn v4_hybrid_historical_chain_retargets_at_first_window_boundary_from_branch_timestamps() {
        let mut params = params();
        // Fork-choice replay has a candidate archive-height bound of 1,024. Use a smaller
        // explicit window here to test full envelope replay within that independent bound; the
        // preceding TargetHistory test covers the configured 2,016-block arithmetic directly.
        params.difficulty_window_blocks = 32;
        params.pow.memory_kib = 8;
        let manifest = [0xC4; 32];
        let verifier = crate::v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate;
        let mut chain =
            PrivateTestnetChain::new_monetary(monetary_state(), params.clone()).unwrap();

        let window = params.difficulty_window_blocks;
        let target_block_time = params.target_block_time_secs;
        let step = target_block_time / 2;
        let first_epoch = 100_000u64;
        let mut envelopes = Vec::with_capacity((window + 1) as usize);
        for height in 1..=window {
            let state = chain.monetary_state().unwrap().clone();
            let timestamp = first_epoch + height * step;
            let mut block = crate::state_machine::V4HybridMonetaryBlock {
                height,
                timestamp,
                parent_hash: state.tip_hash(),
                state_root: [0; 32],
                transactions: Vec::new(),
                miner: [3; 32],
                claimed_subsidy_atoms: state.expected_miner_reward().unwrap(),
            };
            block.state_root = state
                .preview_v4_hybrid_state_root_after(&block, &manifest, &verifier)
                .unwrap();
            let target = chain.expected_target(None).unwrap();
            assert_eq!(
                target,
                Uint256::MAX,
                "retarget must not occur before height window + 1"
            );
            let header = crate::consensus::PowHeader {
                protocol_version: params.protocol_version,
                network_id: state.ledger().network_id(),
                height,
                timestamp,
                parent_hash: block.parent_hash,
                previous_consensus_hash: chain.chain_tip().tip_hash,
                state_root: block.state_root,
                target,
                nonce: 0,
            };
            envelopes.push(
                crate::private_testnet_monetary_wire::encode_candidate_v4_hybrid_monetary_network_block(
                    &header,
                    &block,
                )
                .unwrap(),
            );
            chain
                .append_v4_hybrid_monetary_historical(&block, &header, None, &manifest, &verifier)
                .unwrap();
        }

        assert_eq!(chain.chain_tip().height, window);
        let first_timestamp = first_epoch + step;
        let last_timestamp = first_epoch + window * step;
        let branch_elapsed = last_timestamp - first_timestamp + target_block_time;
        assert_eq!(branch_elapsed, (window - 1) * step + target_block_time);
        let independent_expected =
            crate::consensus::retarget_target(Uint256::MAX, branch_elapsed, &params).unwrap();
        let actual = chain.expected_target(None).unwrap();
        assert_eq!(actual, independent_expected);
        assert_ne!(actual, Uint256::MAX);
        assert_eq!(chain.expected_target(Some(branch_elapsed)), Ok(actual));
        assert_eq!(
            chain.expected_target(Some(branch_elapsed + 1)),
            Err(PrivateConsensusError::RetargetObservationMismatch)
        );

        // Cross the boundary with an actual V4 MBK4 block whose nonce satisfies the
        // newly derived target, not the easier pre-retarget target.
        let next_state = chain.monetary_state().unwrap().clone();
        let next_height = window + 1;
        let next_timestamp = first_epoch + next_height * step;
        let mut next_block = crate::state_machine::V4HybridMonetaryBlock {
            height: next_height,
            timestamp: next_timestamp,
            parent_hash: next_state.tip_hash(),
            state_root: [0; 32],
            transactions: Vec::new(),
            miner: [3; 32],
            claimed_subsidy_atoms: next_state.expected_miner_reward().unwrap(),
        };
        next_block.state_root = next_state
            .preview_v4_hybrid_state_root_after(&next_block, &manifest, &verifier)
            .unwrap();
        let mut next_header = crate::consensus::PowHeader {
            protocol_version: params.protocol_version,
            network_id: next_state.ledger().network_id(),
            height: next_height,
            timestamp: next_timestamp,
            parent_hash: next_block.parent_hash,
            previous_consensus_hash: chain.chain_tip().tip_hash,
            state_root: next_block.state_root,
            target: actual,
            nonce: 0,
        };
        let mined_header = (0..256u64)
            .find_map(|nonce| {
                next_header.nonce = nonce;
                let digest = crate::consensus::pow_digest(&next_header, params.pow).unwrap();
                (Uint256::from_be_bytes(digest) <= actual).then_some(next_header)
            })
            .expect("bounded mining search should find a nonce for the retargeted target");
        envelopes.push(
            crate::private_testnet_monetary_wire::encode_candidate_v4_hybrid_monetary_network_block(
                &mined_header,
                &next_block,
            )
            .unwrap(),
        );
        chain
            .append_v4_hybrid_monetary_historical(
                &next_block,
                &mined_header,
                None,
                &manifest,
                &verifier,
            )
            .unwrap();
        assert_eq!(chain.chain_tip().height, next_height);
        assert_eq!(chain.expected_target(None), Ok(actual));

        // Archive rebuild must reconstruct the branch-derived target across the configured window boundary.
        let rebuilt =
            crate::private_testnet_v4_hybrid_fork_choice_candidate::PrivateTestnetV4HybridForkChoice::rebuild_from_envelopes(
                monetary_state(),
                params,
                manifest,
                envelopes,
                &verifier,
            )
            .unwrap();
        assert_eq!(rebuilt.archive_len(), (window + 1) as usize);
        assert_eq!(rebuilt.canonical_chain().chain_tip().height, next_height);
        assert_eq!(
            rebuilt.canonical_chain().chain_tip().tip_hash,
            chain.chain_tip().tip_hash
        );
        assert_eq!(rebuilt.canonical_chain().expected_target(None), Ok(actual));
    }

    #[test]
    fn fork_clones_state_and_work_then_deterministically_compares() {
        let params = params();
        let mut left = PrivateTestnetChain::new(state(), params.clone()).unwrap();
        let mut right = left.fork();

        let left_block = body(left.state(), 100);
        let left_header = header(left.state(), &left_block, &params, params.initial_target, 0);
        left.append_live(
            &left_block,
            &left_header,
            None,
            &EmptyAuthenticator,
            &FixedClock,
        )
        .unwrap();

        let right_block = body(right.state(), 100);
        let right_header = header(
            right.state(),
            &right_block,
            &params,
            params.initial_target,
            1,
        );
        right
            .append_live(
                &right_block,
                &right_header,
                None,
                &EmptyAuthenticator,
                &FixedClock,
            )
            .unwrap();

        // Same work/height; hash tie-break must be deterministic.
        assert_ne!(left.chain_tip().tip_hash, right.chain_tip().tip_hash);
        assert!(matches!(
            left.compare_to(&right),
            std::cmp::Ordering::Less | std::cmp::Ordering::Greater
        ));
    }

    #[test]
    fn rejected_candidate_does_not_mutate_driver_state() {
        let params = params();
        let mut chain = PrivateTestnetChain::new(state(), params.clone()).unwrap();
        let block = body(chain.state(), 100);
        let mut bad = header(chain.state(), &block, &params, params.initial_target, 0);
        bad.state_root[0] ^= 1;
        let before = chain.clone();

        assert!(matches!(
            chain.append_live(&block, &bad, None, &EmptyAuthenticator, &FixedClock,),
            Err(PrivateConsensusError::HeaderBodyMismatch("state_root"))
        ));
        assert_eq!(chain, before);
    }

    #[test]
    fn state_error_remains_the_final_body_gate() {
        let params = params();
        let mut chain = PrivateTestnetChain::new(state(), params.clone()).unwrap();
        let mut block = body(chain.state(), 100);
        block.timestamp = 0;
        let header = header(chain.state(), &block, &params, params.initial_target, 0);
        let before = chain.clone();

        assert_eq!(
            chain.append_live(&block, &header, None, &EmptyAuthenticator, &FixedClock,),
            Err(PrivateConsensusError::Admission(
                ChainAdmissionError::State(StateError::InvalidBlockTimestamp)
            ))
        );
        assert_eq!(chain, before);
    }

    #[test]
    fn monetary_chain_validates_pow_and_credits_the_exact_scheduled_reward() {
        let params = params();
        let genesis = monetary_state();
        let mut chain = PrivateTestnetChain::new_monetary(genesis, params.clone()).unwrap();
        let before_work = chain.cumulative_work();
        let state_before = chain.monetary_state().unwrap().clone();
        let block = monetary_block(&state_before, 100, [3; 32]);
        let header = monetary_header(&chain, &block, &params, 7);

        let (receipt, digest) = chain
            .append_monetary_live(&block, &header, None, &EmptyAuthenticator, &FixedClock)
            .unwrap();

        assert_eq!(receipt.summary.height, 1);
        assert_eq!(receipt.summary.state_root, block.body.state_root);
        assert_eq!(chain.state().height(), 1);
        assert_eq!(chain.chain_tip().tip_hash, digest);
        assert_eq!(
            chain.cumulative_work(),
            before_work
                .checked_add(block_work(params.initial_target).unwrap())
                .unwrap()
        );
        let monetary = chain.monetary_state().unwrap();
        assert_eq!(
            monetary.total_mined_atoms(),
            block.claimed_subsidy_atoms as u128
        );
        assert_eq!(
            monetary.ledger().account(&[3; 32]).unwrap().balance,
            block.claimed_subsidy_atoms
        );
        assert_eq!(
            monetary.total_value().unwrap(),
            monetary.ledger().total_value().unwrap()
        );
    }

    #[test]
    fn monetary_and_legacy_block_paths_cannot_be_mixed() {
        let params = params();
        let monetary_genesis = monetary_state();
        let mut monetary_chain =
            PrivateTestnetChain::new_monetary(monetary_genesis.clone(), params.clone()).unwrap();
        let candidate = monetary_block(&monetary_genesis, 100, [3; 32]);
        let legacy_block = Block {
            height: 1,
            timestamp: 100,
            parent_hash: monetary_genesis.tip_hash(),
            state_root: [0; 32],
            transactions: Vec::new(),
        };
        let legacy_header = monetary_header(&monetary_chain, &candidate, &params, 0);
        let before_monetary = monetary_chain.clone();
        assert_eq!(
            monetary_chain.append_live(
                &legacy_block,
                &legacy_header,
                None,
                &EmptyAuthenticator,
                &FixedClock,
            ),
            Err(PrivateConsensusError::LegacyBlockOnMonetaryChain)
        );
        assert_eq!(monetary_chain, before_monetary);

        let mut legacy_chain = PrivateTestnetChain::new(state(), params.clone()).unwrap();
        let before_legacy = legacy_chain.clone();
        assert_eq!(
            legacy_chain.append_monetary_live(
                &candidate,
                &legacy_header,
                None,
                &EmptyAuthenticator,
                &FixedClock,
            ),
            Err(PrivateConsensusError::MonetaryBlockOnLegacyChain)
        );
        assert_eq!(legacy_chain, before_legacy);
    }
}
