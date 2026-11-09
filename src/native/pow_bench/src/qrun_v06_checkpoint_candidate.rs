//! Authenticated QFP6 execution checkpoint candidate.
//!
//! A checkpoint combines the full canonical QFB6 execution snapshot with its PoW consensus
//! tip, cumulative work, consensus fingerprint and the exact bounded target/timestamp history
//! needed for the next retarget. Its commitment must be retained outside the checkpoint store.
//! The checksum is corruption detection only and is never treated as anti-rollback authority.

use crate::{
    consensus::{ConsensusError, ConsensusParameters, PowAlgorithm, Uint256},
    qrun_v06_canonical_execution_candidate::{
        QRunV06CanonicalExecutionState, QRunV06ExecutionError,
        MAX_QRUN_V06_EXECUTION_SNAPSHOT_BYTES,
    },
};
use sha2::{Digest, Sha256};
use std::io::{Cursor, Read};

const CHECKPOINT_MAGIC: [u8; 4] = *b"Q6CP";
const CHECKPOINT_VERSION: u16 = 2;
const CHECKPOINT_CHECKSUM_DOMAIN: &[u8] = b"QRUN-V06-CHECKPOINT-CHECKSUM-V2\0";
const CHECKPOINT_COMMITMENT_DOMAIN: &[u8] = b"QRUN-V06-CHECKPOINT-COMMITMENT-V2\0";
const CHECKPOINT_CONSENSUS_DOMAIN: &[u8] = b"QRUN-V06-CHECKPOINT-CONSENSUS-V1\0";
const CHECKSUM_BYTES: usize = 32;
const FIXED_HEADER_BYTES: usize = 4 + 2 + 32 + 32 + 32 + 32 + 8 + 8 + 32 + 32 + 32 + 4;
const HISTORY_ENTRY_BYTES: usize = 8 + 32 + 8;
pub const MAX_QRUN_V06_CHECKPOINT_HISTORY_ENTRIES: usize = 65_536;
pub const MAX_QRUN_V06_CHECKPOINT_BYTES: usize = 72 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QRunV06TargetHistoryEntry {
    pub height: u64,
    pub target: Uint256,
    pub timestamp: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QRunV06CheckpointError {
    Io(String),
    Execution(QRunV06ExecutionError),
    Consensus(ConsensusError),
    WrongProtocolVersion,
    WrongNetwork,
    WrongProfile,
    WrongConsensusParameters,
    MissingGenesisDescriptor,
    GenesisDescriptorMismatch,
    InvalidTrustedAnchor,
    MissingTrustedAnchor,
    CheckpointAnchorMismatch,
    CheckpointMalformed,
    CheckpointChecksumMismatch,
    CheckpointNonCanonical,
    CheckpointOversize,
    CheckpointHistoryMismatch,
    InvalidConsensusTip,
    InvalidChainwork,
}

impl From<QRunV06ExecutionError> for QRunV06CheckpointError {
    fn from(value: QRunV06ExecutionError) -> Self {
        Self::Execution(value)
    }
}
impl From<ConsensusError> for QRunV06CheckpointError {
    fn from(value: ConsensusError) -> Self {
        Self::Consensus(value)
    }
}
impl std::fmt::Display for QRunV06CheckpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "QFP6 checkpoint I/O error: {error}"),
            Self::Execution(error) => {
                write!(f, "QFP6 checkpoint execution snapshot rejected: {error:?}")
            }
            Self::Consensus(error) => {
                write!(f, "QFP6 checkpoint consensus profile rejected: {error}")
            }
            Self::WrongProtocolVersion => {
                f.write_str("QFP6 checkpoint requires protocol version 6")
            }
            Self::WrongNetwork => f.write_str("QFP6 checkpoint belongs to another network"),
            Self::WrongProfile => {
                f.write_str("QFP6 checkpoint belongs to another execution profile")
            }
            Self::WrongConsensusParameters => {
                f.write_str("QFP6 checkpoint consensus fingerprint differs from the active profile")
            }
            Self::MissingGenesisDescriptor => {
                f.write_str("QFP6 checkpoint requires an immutable Genesis descriptor")
            }
            Self::GenesisDescriptorMismatch => {
                f.write_str("QFP6 checkpoint Genesis descriptor does not match its execution state or consensus profile")
            }
            Self::InvalidTrustedAnchor => {
                f.write_str("trusted QFP6 checkpoint anchor must be nonzero")
            }
            Self::MissingTrustedAnchor => {
                f.write_str("QFP6 checkpoint restore requires an independently protected anchor")
            }
            Self::CheckpointAnchorMismatch => f.write_str(
                "QFP6 checkpoint commitment differs from the independently supplied anchor",
            ),
            Self::CheckpointMalformed => f.write_str("QFP6 checkpoint is malformed or truncated"),
            Self::CheckpointChecksumMismatch => f.write_str("QFP6 checkpoint checksum mismatch"),
            Self::CheckpointNonCanonical => {
                f.write_str("QFP6 checkpoint encoding is not canonical")
            }
            Self::CheckpointOversize => f.write_str("QFP6 checkpoint exceeds its bounded size"),
            Self::CheckpointHistoryMismatch => f.write_str(
                "QFP6 checkpoint target/timestamp history is incomplete or inconsistent",
            ),
            Self::InvalidConsensusTip => {
                f.write_str("QFP6 checkpoint has an invalid consensus tip digest")
            }
            Self::InvalidChainwork => {
                f.write_str("QFP6 checkpoint has invalid cumulative chain work")
            }
        }
    }
}
impl std::error::Error for QRunV06CheckpointError {}

/// A validated checkpoint. Fields are private so callers must obtain one from a live
/// fork graph or decode one against an independently retained commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06CheckpointCandidate {
    network_id: [u8; 32],
    profile_id: [u8; 32],
    consensus_fingerprint: [u8; 32],
    genesis_descriptor_commitment: [u8; 32],
    height: u64,
    timestamp: u64,
    execution_tip_hash: [u8; 32],
    consensus_tip_digest: [u8; 32],
    cumulative_work: Uint256,
    execution_state_root: [u8; 32],
    target_history: Vec<QRunV06TargetHistoryEntry>,
    execution_state: QRunV06CanonicalExecutionState,
}

impl QRunV06CheckpointCandidate {
    /// Build a candidate from an already validated branch tip. This is crate-private:
    /// only fork-choice code should bind chainwork and target history to an execution state.
    pub(crate) fn from_validated_branch(
        execution_state: QRunV06CanonicalExecutionState,
        consensus_tip_digest: [u8; 32],
        cumulative_work: Uint256,
        target_history: Vec<QRunV06TargetHistoryEntry>,
        params: &ConsensusParameters,
    ) -> Result<Self, QRunV06CheckpointError> {
        params.validate()?;
        if params.protocol_version != 6 {
            return Err(QRunV06CheckpointError::WrongProtocolVersion);
        }
        let execution_state_root = execution_state.state_root()?;
        let checkpoint = Self {
            network_id: execution_state.network_id(),
            profile_id: execution_state.profile_id(),
            consensus_fingerprint: qrun_v06_consensus_fingerprint(params)?,
            genesis_descriptor_commitment: execution_state
                .genesis_descriptor_commitment()
                .ok_or(QRunV06CheckpointError::MissingGenesisDescriptor)?,
            height: execution_state.height(),
            timestamp: execution_state.last_timestamp(),
            execution_tip_hash: execution_state.tip_hash(),
            consensus_tip_digest,
            cumulative_work,
            execution_state_root,
            target_history,
            execution_state,
        };
        checkpoint.validate(params)?;
        Ok(checkpoint)
    }

    /// Restore only when the complete checkpoint commitment matches an anchor held outside
    /// this file/store. A valid checksum without this external anchor is not trusted.
    pub fn decode_snapshot(
        bytes: &[u8],
        params: &ConsensusParameters,
        expected_network_id: &[u8; 32],
        expected_profile_id: &[u8; 32],
        trusted_checkpoint_anchor: [u8; 32],
    ) -> Result<Self, QRunV06CheckpointError> {
        if trusted_checkpoint_anchor == [0; 32] {
            return Err(QRunV06CheckpointError::InvalidTrustedAnchor);
        }
        if bytes.len() > MAX_QRUN_V06_CHECKPOINT_BYTES {
            return Err(QRunV06CheckpointError::CheckpointOversize);
        }
        if checkpoint_commitment(bytes) != trusted_checkpoint_anchor {
            return Err(QRunV06CheckpointError::CheckpointAnchorMismatch);
        }
        if params.protocol_version != 6 {
            return Err(QRunV06CheckpointError::WrongProtocolVersion);
        }
        params.validate()?;
        if expected_network_id == &[0; 32] || expected_profile_id == &[0; 32] {
            return Err(QRunV06CheckpointError::CheckpointMalformed);
        }
        if bytes.len() < FIXED_HEADER_BYTES + CHECKSUM_BYTES + 4 {
            return Err(QRunV06CheckpointError::CheckpointMalformed);
        }
        let payload_len = bytes.len() - CHECKSUM_BYTES;
        let mut checksum = Sha256::new();
        checksum.update(CHECKPOINT_CHECKSUM_DOMAIN);
        checksum.update(&bytes[..payload_len]);
        if checksum.finalize().as_slice() != &bytes[payload_len..] {
            return Err(QRunV06CheckpointError::CheckpointChecksumMismatch);
        }

        let payload = &bytes[..payload_len];
        let mut cursor = Cursor::new(payload);
        if checkpoint_read::<4>(&mut cursor)? != CHECKPOINT_MAGIC {
            return Err(QRunV06CheckpointError::CheckpointMalformed);
        }
        if checkpoint_u16(&mut cursor)? != CHECKPOINT_VERSION {
            return Err(QRunV06CheckpointError::CheckpointNonCanonical);
        }
        let network_id = checkpoint_read::<32>(&mut cursor)?;
        let profile_id = checkpoint_read::<32>(&mut cursor)?;
        let consensus_fingerprint = checkpoint_read::<32>(&mut cursor)?;
        let genesis_descriptor_commitment = checkpoint_read::<32>(&mut cursor)?;
        if &network_id != expected_network_id {
            return Err(QRunV06CheckpointError::WrongNetwork);
        }
        if &profile_id != expected_profile_id {
            return Err(QRunV06CheckpointError::WrongProfile);
        }
        if consensus_fingerprint != qrun_v06_consensus_fingerprint(params)? {
            return Err(QRunV06CheckpointError::WrongConsensusParameters);
        }

        let height = checkpoint_u64(&mut cursor)?;
        let timestamp = checkpoint_u64(&mut cursor)?;
        let execution_tip_hash = checkpoint_read::<32>(&mut cursor)?;
        let consensus_tip_digest = checkpoint_read::<32>(&mut cursor)?;
        let cumulative_work = Uint256::from_be_bytes(checkpoint_read::<32>(&mut cursor)?);
        let execution_state_root = checkpoint_read::<32>(&mut cursor)?;
        let history_count = checkpoint_u32(&mut cursor)? as usize;
        let expected_history_count = checkpoint_history_count(height, params)?;
        if history_count != expected_history_count
            || history_count > MAX_QRUN_V06_CHECKPOINT_HISTORY_ENTRIES
        {
            return Err(QRunV06CheckpointError::CheckpointHistoryMismatch);
        }
        let expected_history_bytes = history_count
            .checked_mul(HISTORY_ENTRY_BYTES)
            .ok_or(QRunV06CheckpointError::CheckpointOversize)?;
        let minimum_remaining = expected_history_bytes
            .checked_add(4)
            .ok_or(QRunV06CheckpointError::CheckpointOversize)?;
        if payload.len().saturating_sub(cursor.position() as usize) < minimum_remaining {
            return Err(QRunV06CheckpointError::CheckpointMalformed);
        }
        let mut target_history = Vec::with_capacity(history_count);
        for _ in 0..history_count {
            target_history.push(QRunV06TargetHistoryEntry {
                height: checkpoint_u64(&mut cursor)?,
                target: Uint256::from_be_bytes(checkpoint_read::<32>(&mut cursor)?),
                timestamp: checkpoint_u64(&mut cursor)?,
            });
        }
        let snapshot_length = checkpoint_u32(&mut cursor)? as usize;
        if snapshot_length == 0
            || snapshot_length > MAX_QRUN_V06_EXECUTION_SNAPSHOT_BYTES
            || snapshot_length != payload.len().saturating_sub(cursor.position() as usize)
        {
            return Err(QRunV06CheckpointError::CheckpointMalformed);
        }
        let execution_snapshot = checkpoint_read_vec(&mut cursor, snapshot_length)?;
        if cursor.position() as usize != payload.len() {
            return Err(QRunV06CheckpointError::CheckpointNonCanonical);
        }
        let execution_state = QRunV06CanonicalExecutionState::decode_snapshot(
            &execution_snapshot,
            expected_network_id,
            expected_profile_id,
        )?;
        let checkpoint = Self {
            network_id,
            profile_id,
            consensus_fingerprint,
            genesis_descriptor_commitment,
            height,
            timestamp,
            execution_tip_hash,
            consensus_tip_digest,
            cumulative_work,
            execution_state_root,
            target_history,
            execution_state,
        };
        checkpoint.validate(params)?;
        if checkpoint.encode_snapshot()?.as_slice() != bytes {
            return Err(QRunV06CheckpointError::CheckpointNonCanonical);
        }
        Ok(checkpoint)
    }

    pub fn encode_snapshot(&self) -> Result<Vec<u8>, QRunV06CheckpointError> {
        self.validate_profile_only()?;
        let execution_snapshot = self.execution_state.encode_snapshot()?;
        let mut out = Vec::with_capacity(
            FIXED_HEADER_BYTES
                .saturating_add(
                    self.target_history
                        .len()
                        .saturating_mul(HISTORY_ENTRY_BYTES),
                )
                .saturating_add(4)
                .saturating_add(execution_snapshot.len())
                .saturating_add(CHECKSUM_BYTES),
        );
        out.extend_from_slice(&CHECKPOINT_MAGIC);
        out.extend_from_slice(&CHECKPOINT_VERSION.to_be_bytes());
        out.extend_from_slice(&self.network_id);
        out.extend_from_slice(&self.profile_id);
        out.extend_from_slice(&self.consensus_fingerprint);
        out.extend_from_slice(&self.genesis_descriptor_commitment);
        out.extend_from_slice(&self.height.to_be_bytes());
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&self.execution_tip_hash);
        out.extend_from_slice(&self.consensus_tip_digest);
        out.extend_from_slice(&self.cumulative_work.to_be_bytes());
        out.extend_from_slice(&self.execution_state_root);
        checkpoint_put_u32(&mut out, self.target_history.len())?;
        for entry in &self.target_history {
            out.extend_from_slice(&entry.height.to_be_bytes());
            out.extend_from_slice(&entry.target.to_be_bytes());
            out.extend_from_slice(&entry.timestamp.to_be_bytes());
        }
        checkpoint_put_u32(&mut out, execution_snapshot.len())?;
        out.extend_from_slice(&execution_snapshot);
        if out.len().saturating_add(CHECKSUM_BYTES) > MAX_QRUN_V06_CHECKPOINT_BYTES {
            return Err(QRunV06CheckpointError::CheckpointOversize);
        }
        let mut checksum = Sha256::new();
        checksum.update(CHECKPOINT_CHECKSUM_DOMAIN);
        checksum.update(&out);
        out.extend_from_slice(&checksum.finalize());
        Ok(out)
    }

    /// Domain-separated commitment to the exact canonical checkpoint bytes. Save this value
    /// in an external CAS or monotonic trust provider before using the checkpoint as a base.
    pub fn commitment(&self) -> Result<[u8; 32], QRunV06CheckpointError> {
        Ok(checkpoint_commitment(&self.encode_snapshot()?))
    }

    pub fn validate(&self, params: &ConsensusParameters) -> Result<(), QRunV06CheckpointError> {
        params.validate()?;
        if params.protocol_version != 6 {
            return Err(QRunV06CheckpointError::WrongProtocolVersion);
        }
        if self.consensus_fingerprint != qrun_v06_consensus_fingerprint(params)? {
            return Err(QRunV06CheckpointError::WrongConsensusParameters);
        }
        let descriptor = self
            .execution_state
            .genesis_descriptor()
            .ok_or(QRunV06CheckpointError::MissingGenesisDescriptor)?;
        if descriptor.commitment() != self.genesis_descriptor_commitment
            || descriptor.consensus_fingerprint() != self.consensus_fingerprint
        {
            return Err(QRunV06CheckpointError::GenesisDescriptorMismatch);
        }
        self.validate_profile_only()?;
        let expected_count = checkpoint_history_count(self.height, params)?;
        if self.target_history.len() != expected_count {
            return Err(QRunV06CheckpointError::CheckpointHistoryMismatch);
        }
        let genesis_timestamp = descriptor.genesis_timestamp();
        if self.height == 0 {
            if self.timestamp != genesis_timestamp
                || self.execution_tip_hash != [0; 32]
                || self.consensus_tip_digest != [0; 32]
                || self.cumulative_work != Uint256::ZERO
                || !self.target_history.is_empty()
            {
                return Err(QRunV06CheckpointError::CheckpointNonCanonical);
            }
        } else {
            if self.timestamp <= genesis_timestamp
                || self.execution_tip_hash == [0; 32]
                || self.consensus_tip_digest == [0; 32]
                || self.cumulative_work == Uint256::ZERO
            {
                return Err(QRunV06CheckpointError::InvalidConsensusTip);
            }
            let first_height = self
                .height
                .checked_sub(expected_count as u64)
                .and_then(|height| height.checked_add(1))
                .ok_or(QRunV06CheckpointError::CheckpointHistoryMismatch)?;
            let mut previous_timestamp = genesis_timestamp;
            for (index, entry) in self.target_history.iter().enumerate() {
                let expected_height = first_height
                    .checked_add(index as u64)
                    .ok_or(QRunV06CheckpointError::CheckpointHistoryMismatch)?;
                if entry.height != expected_height
                    || entry.timestamp == 0
                    || entry.timestamp <= previous_timestamp
                    || entry.target.is_zero()
                    || entry.target > params.pow_limit
                {
                    return Err(QRunV06CheckpointError::CheckpointHistoryMismatch);
                }
                previous_timestamp = entry.timestamp;
            }
            let latest = self
                .target_history
                .last()
                .ok_or(QRunV06CheckpointError::CheckpointHistoryMismatch)?;
            if latest.height != self.height || latest.timestamp != self.timestamp {
                return Err(QRunV06CheckpointError::CheckpointHistoryMismatch);
            }
        }
        Ok(())
    }

    fn validate_profile_only(&self) -> Result<(), QRunV06CheckpointError> {
        if self.network_id == [0; 32] || self.profile_id == [0; 32] {
            return Err(QRunV06CheckpointError::CheckpointMalformed);
        }
        if self.execution_state.network_id() != self.network_id {
            return Err(QRunV06CheckpointError::WrongNetwork);
        }
        if self.execution_state.profile_id() != self.profile_id {
            return Err(QRunV06CheckpointError::WrongProfile);
        }
        let descriptor_commitment = self
            .execution_state
            .genesis_descriptor_commitment()
            .ok_or(QRunV06CheckpointError::MissingGenesisDescriptor)?;
        if descriptor_commitment != self.genesis_descriptor_commitment {
            return Err(QRunV06CheckpointError::GenesisDescriptorMismatch);
        }
        if self.execution_state.height() != self.height
            || self.execution_state.last_timestamp() != self.timestamp
            || self.execution_state.tip_hash() != self.execution_tip_hash
        {
            return Err(QRunV06CheckpointError::CheckpointNonCanonical);
        }
        if self.execution_state.state_root()? != self.execution_state_root {
            return Err(QRunV06CheckpointError::Execution(
                QRunV06ExecutionError::StateRootMismatch,
            ));
        }
        Ok(())
    }

    pub fn network_id(&self) -> [u8; 32] {
        self.network_id
    }
    pub fn profile_id(&self) -> [u8; 32] {
        self.profile_id
    }
    pub fn height(&self) -> u64 {
        self.height
    }
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }
    pub fn execution_tip_hash(&self) -> [u8; 32] {
        self.execution_tip_hash
    }
    pub fn consensus_tip_digest(&self) -> [u8; 32] {
        self.consensus_tip_digest
    }
    pub fn cumulative_work(&self) -> Uint256 {
        self.cumulative_work
    }
    pub fn target_history(&self) -> &[QRunV06TargetHistoryEntry] {
        &self.target_history
    }
    pub fn execution_state(&self) -> &QRunV06CanonicalExecutionState {
        &self.execution_state
    }
    pub fn consensus_fingerprint(&self) -> [u8; 32] {
        self.consensus_fingerprint
    }
    pub fn genesis_descriptor_commitment(&self) -> [u8; 32] {
        self.genesis_descriptor_commitment
    }
}

fn checkpoint_history_count(
    height: u64,
    params: &ConsensusParameters,
) -> Result<usize, QRunV06CheckpointError> {
    if params.difficulty_window_blocks == 0
        || params.difficulty_window_blocks > MAX_QRUN_V06_CHECKPOINT_HISTORY_ENTRIES as u64
    {
        return Err(QRunV06CheckpointError::CheckpointHistoryMismatch);
    }
    usize::try_from(height.min(params.difficulty_window_blocks))
        .map_err(|_| QRunV06CheckpointError::CheckpointHistoryMismatch)
}

pub(crate) fn qrun_v06_consensus_fingerprint(
    params: &ConsensusParameters,
) -> Result<[u8; 32], QRunV06CheckpointError> {
    params.validate()?;
    let mut hash = Sha256::new();
    hash.update(CHECKPOINT_CONSENSUS_DOMAIN);
    hash.update(params.protocol_version.to_be_bytes());
    hash.update(params.target_block_time_secs.to_be_bytes());
    hash.update(params.difficulty_window_blocks.to_be_bytes());
    hash.update(params.difficulty_min_ratio_divisor.to_be_bytes());
    hash.update(params.difficulty_max_ratio.to_be_bytes());
    hash.update(params.pow_limit.to_be_bytes());
    hash.update(params.initial_target.to_be_bytes());
    match params.pow.algorithm {
        PowAlgorithm::Argon2id => hash.update([1]),
    }
    hash.update(params.pow.memory_kib.to_be_bytes());
    hash.update(params.pow.iterations.to_be_bytes());
    hash.update(params.pow.lanes.to_be_bytes());
    hash.update([params.pow.output_bytes]);
    hash.update(params.issuance.maximum_supply().to_be_bytes());
    hash.update(params.issuance.initial_subsidy().to_be_bytes());
    hash.update(params.issuance.blocks_per_halving().to_be_bytes());
    Ok(hash.finalize().into())
}

fn checkpoint_commitment(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(CHECKPOINT_COMMITMENT_DOMAIN);
    hash.update(bytes);
    hash.finalize().into()
}

fn checkpoint_put_u32(out: &mut Vec<u8>, value: usize) -> Result<(), QRunV06CheckpointError> {
    let value = u32::try_from(value).map_err(|_| QRunV06CheckpointError::CheckpointOversize)?;
    out.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

fn checkpoint_read<const N: usize>(
    cursor: &mut Cursor<&[u8]>,
) -> Result<[u8; N], QRunV06CheckpointError> {
    let mut output = [0u8; N];
    cursor
        .read_exact(&mut output)
        .map_err(|_| QRunV06CheckpointError::CheckpointMalformed)?;
    Ok(output)
}

fn checkpoint_read_vec(
    cursor: &mut Cursor<&[u8]>,
    length: usize,
) -> Result<Vec<u8>, QRunV06CheckpointError> {
    let mut output = vec![0u8; length];
    cursor
        .read_exact(&mut output)
        .map_err(|_| QRunV06CheckpointError::CheckpointMalformed)?;
    Ok(output)
}

fn checkpoint_u16(cursor: &mut Cursor<&[u8]>) -> Result<u16, QRunV06CheckpointError> {
    Ok(u16::from_be_bytes(checkpoint_read(cursor)?))
}
fn checkpoint_u32(cursor: &mut Cursor<&[u8]>) -> Result<u32, QRunV06CheckpointError> {
    Ok(u32::from_be_bytes(checkpoint_read(cursor)?))
}
fn checkpoint_u64(cursor: &mut Cursor<&[u8]>) -> Result<u64, QRunV06CheckpointError> {
    Ok(u64::from_be_bytes(checkpoint_read(cursor)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        consensus::Uint256,
        qrun_v06_genesis_descriptor_candidate::QRunV06GenesisDescriptor,
        qrun_v06_tokenomics_candidate::{
            QRunV06MiningScheduleCandidate, QRunV06TokenomicsState, QRUN_V06_FOUNDER_GENESIS_ATOMS,
        },
        qrun_v06_unified_asset_candidate::QRunV06UnifiedAssetState,
        qzxb_amm_candidate::QzxbAmmStateCandidate,
        state_machine::LedgerState,
    };

    const NETWORK: [u8; 32] = [0xE1; 32];
    const PROFILE: [u8; 32] = [0xE2; 32];
    const OWNER: [u8; 32] = [0xE3; 32];

    fn params() -> ConsensusParameters {
        let mut params = ConsensusParameters::candidate_testnet().unwrap();
        params.protocol_version = 6;
        params.difficulty_window_blocks = 2;
        params.pow_limit = Uint256::MAX;
        params.validate().unwrap();
        params
    }

    fn genesis() -> QRunV06CanonicalExecutionState {
        let schedule = QRunV06MiningScheduleCandidate::cp0422_research_candidate();
        let tokenomics = QRunV06TokenomicsState::genesis(NETWORK, OWNER, schedule).unwrap();
        let consensus = params();
        let descriptor = QRunV06GenesisDescriptor::new(
            NETWORK,
            PROFILE,
            OWNER,
            1,
            qrun_v06_consensus_fingerprint(&consensus).unwrap(),
            tokenomics.policy_fingerprint(),
        )
        .unwrap();
        let ledger = LedgerState::genesis_at(
            NETWORK,
            vec![(OWNER, QRUN_V06_FOUNDER_GENESIS_ATOMS as u64)],
            descriptor.genesis_timestamp(),
        )
        .unwrap();
        let amm = QzxbAmmStateCandidate::new(NETWORK, 32, 64, 512).unwrap();
        let unified = QRunV06UnifiedAssetState::new(ledger, amm).unwrap();
        QRunV06CanonicalExecutionState::new_with_genesis_descriptor(
            unified, PROFILE, tokenomics, descriptor,
        )
        .unwrap()
    }

    #[test]
    fn consensus_fingerprint_binds_every_current_consensus_parameter() {
        let baseline = params();
        let baseline_fingerprint = qrun_v06_consensus_fingerprint(&baseline).unwrap();
        let mut variants = Vec::new();

        let mut changed = baseline.clone();
        changed.protocol_version += 1;
        variants.push(changed);

        let mut changed = baseline.clone();
        changed.target_block_time_secs += 1;
        variants.push(changed);

        let mut changed = baseline.clone();
        changed.difficulty_window_blocks += 1;
        variants.push(changed);

        let mut changed = baseline.clone();
        changed.difficulty_min_ratio_divisor += 1;
        variants.push(changed);

        let mut changed = baseline.clone();
        changed.difficulty_max_ratio += 1;
        variants.push(changed);

        let mut changed = baseline.clone();
        let mut pow_limit = changed.pow_limit.to_be_bytes();
        pow_limit[31] -= 1;
        changed.pow_limit = Uint256::from_be_bytes(pow_limit);
        variants.push(changed);

        let mut changed = baseline.clone();
        changed.initial_target = Uint256::from_be_bytes([0x01; 32]);
        variants.push(changed);

        let mut changed = baseline.clone();
        changed.pow.memory_kib += 1;
        variants.push(changed);

        let mut changed = baseline.clone();
        changed.pow.iterations += 1;
        variants.push(changed);

        let mut changed = baseline.clone();
        changed.pow.lanes += 1;
        variants.push(changed);

        let mut changed = baseline.clone();
        changed.issuance = crate::issuance_schedule::IssuanceParameters::new(
            baseline.issuance.maximum_supply() + 1,
            baseline.issuance.initial_subsidy(),
            baseline.issuance.blocks_per_halving(),
        )
        .unwrap();
        variants.push(changed);

        let mut changed = baseline.clone();
        changed.issuance = crate::issuance_schedule::IssuanceParameters::new(
            baseline.issuance.maximum_supply(),
            baseline.issuance.initial_subsidy() + 1,
            baseline.issuance.blocks_per_halving(),
        )
        .unwrap();
        variants.push(changed);

        let mut changed = baseline.clone();
        changed.issuance = crate::issuance_schedule::IssuanceParameters::new(
            baseline.issuance.maximum_supply(),
            baseline.issuance.initial_subsidy(),
            baseline.issuance.blocks_per_halving() + 1,
        )
        .unwrap();
        variants.push(changed);

        assert_eq!(variants.len(), 13);
        for (index, variant) in variants.iter().enumerate() {
            variant.validate().unwrap();
            let fingerprint = qrun_v06_consensus_fingerprint(variant).unwrap();
            assert_ne!(
                fingerprint, baseline_fingerprint,
                "consensus parameter mutation at index {index} was not fingerprinted"
            );
        }

        let mut invalid_output = baseline;
        invalid_output.pow.output_bytes -= 1;
        assert!(matches!(
            qrun_v06_consensus_fingerprint(&invalid_output),
            Err(QRunV06CheckpointError::Consensus(
                crate::consensus::ConsensusError::InvalidPowParameters
            ))
        ));
    }
    #[test]
    fn checkpoint_requires_external_anchor_and_rejects_cross_profile_or_corruption() {
        let params = params();
        let checkpoint = QRunV06CheckpointCandidate::from_validated_branch(
            genesis(),
            [0; 32],
            Uint256::ZERO,
            Vec::new(),
            &params,
        )
        .unwrap();
        let bytes = checkpoint.encode_snapshot().unwrap();
        let anchor = checkpoint.commitment().unwrap();

        let decoded = QRunV06CheckpointCandidate::decode_snapshot(
            &bytes, &params, &NETWORK, &PROFILE, anchor,
        )
        .unwrap();
        assert_eq!(decoded, checkpoint);

        assert_eq!(
            QRunV06CheckpointCandidate::decode_snapshot(
                &bytes, &params, &NETWORK, &PROFILE, [0; 32],
            ),
            Err(QRunV06CheckpointError::InvalidTrustedAnchor)
        );
        assert_eq!(
            QRunV06CheckpointCandidate::decode_snapshot(
                &bytes,
                &params,
                &[0xE4; 32],
                &PROFILE,
                anchor,
            ),
            Err(QRunV06CheckpointError::WrongNetwork)
        );
        assert_eq!(
            QRunV06CheckpointCandidate::decode_snapshot(
                &bytes,
                &params,
                &NETWORK,
                &[0xE5; 32],
                anchor,
            ),
            Err(QRunV06CheckpointError::WrongProfile)
        );

        let mut different_params = params.clone();
        different_params.target_block_time_secs += 1;
        assert_eq!(
            QRunV06CheckpointCandidate::decode_snapshot(
                &bytes,
                &different_params,
                &NETWORK,
                &PROFILE,
                anchor,
            ),
            Err(QRunV06CheckpointError::WrongConsensusParameters)
        );

        let mut corrupt = bytes.clone();
        let index = corrupt.len() / 2;
        corrupt[index] ^= 1;
        let corrupt_anchor = checkpoint_commitment(&corrupt);
        assert_eq!(
            QRunV06CheckpointCandidate::decode_snapshot(
                &corrupt,
                &params,
                &NETWORK,
                &PROFILE,
                corrupt_anchor,
            ),
            Err(QRunV06CheckpointError::CheckpointChecksumMismatch)
        );
    }
}
