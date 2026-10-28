//! QRun v0.5 canonical checkpoint candidate for long-running PoW history.
//!
//! This record binds the ledger snapshot, bounded retarget history, consensus tip, cumulative
//! work, network, Genesis, and consensus profile into one canonical byte string. A checksum detects
//! accidental corruption; only an independently supplied commitment and monotonic height floor
//! make a checkpoint admissible as a trust anchor. This codec alone does not prune or compact the
//! durable fork store and therefore is not, by itself, a long-term storage implementation.

use crate::{
    consensus::{ConsensusParameters, PowAlgorithm, Uint256},
    private_testnet_driver::{
        PrivateTestnetChain, TargetHistory, TargetHistoryCheckpoint,
        MAX_TARGET_HISTORY_CHECKPOINT_ENTRIES,
    },
    state_machine::{LedgerState, NetworkId, MAX_ENCODED_SNAPSHOT_BYTES, MAX_TOTAL_SUPPLY_ATOMS},
};
use sha2::{Digest, Sha256};

pub const QRCP_MAGIC: [u8; 4] = *b"QRCP";
pub const QRCP_VERSION: u16 = 1;
pub const QRCP_CHECKSUM_DOMAIN: &[u8] = b"QUANTUMZXB-QRUN-POW-CHECKPOINT-CHECKSUM-V1\0";
pub const QRCP_COMMITMENT_DOMAIN: &[u8] = b"QUANTUMZXB-QRUN-POW-CHECKPOINT-COMMITMENT-V1\0";
const QRCP_PROFILE_DOMAIN: &[u8] = b"QUANTUMZXB-QRUN-POW-CHECKPOINT-PROFILE-V1\0";
const CHECKSUM_BYTES: usize = 32;
const HISTORY_ENTRY_BYTES: usize = 49;
pub const MAX_QRCP_BYTES: usize = 9 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QRunCheckpointError {
    InvalidProfile,
    InvalidIdentifier,
    WrongNetwork,
    WrongGenesis,
    ProfileMismatch,
    Malformed,
    UnsupportedVersion(u16),
    Oversize,
    ChecksumMismatch,
    CommitmentMismatch,
    HeightRollback,
    MissingParentCheckpoint,
    StateSnapshot(String),
    StateMetadataMismatch,
    SupplyMismatch,
    TargetHistory(String),
    TargetHistoryHeightMismatch,
}

impl std::fmt::Display for QRunCheckpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidProfile => f.write_str("QRCP consensus profile is invalid"),
            Self::InvalidIdentifier => {
                f.write_str("QRCP network, Genesis, and tip IDs must be nonzero")
            }
            Self::WrongNetwork => f.write_str("QRCP checkpoint belongs to another network"),
            Self::WrongGenesis => {
                f.write_str("QRCP checkpoint is not bound to the configured Genesis")
            }
            Self::ProfileMismatch => f.write_str("QRCP consensus profile fingerprint mismatch"),
            Self::Malformed => f.write_str("QRCP checkpoint is malformed or noncanonical"),
            Self::UnsupportedVersion(v) => write!(f, "QRCP checkpoint version {v} is unsupported"),
            Self::Oversize => {
                f.write_str("QRCP checkpoint exceeds the configured size/count limit")
            }
            Self::ChecksumMismatch => f.write_str("QRCP checkpoint checksum mismatch"),
            Self::CommitmentMismatch => {
                f.write_str("QRCP checkpoint differs from the trusted external commitment")
            }
            Self::HeightRollback => {
                f.write_str("QRCP checkpoint height is below the trusted monotonic floor")
            }
            Self::MissingParentCheckpoint => {
                f.write_str("non-Genesis QRCP checkpoint requires a parent checkpoint commitment")
            }
            Self::StateSnapshot(e) => write!(f, "QRCP ledger snapshot rejected: {e}"),
            Self::StateMetadataMismatch => {
                f.write_str("QRCP ledger metadata does not match the decoded snapshot")
            }
            Self::SupplyMismatch => {
                f.write_str("QRCP checkpoint violates the fixed full-supply invariant")
            }
            Self::TargetHistory(e) => write!(f, "QRCP target-history record rejected: {e}"),
            Self::TargetHistoryHeightMismatch => {
                f.write_str("QRCP target history does not end at the checkpoint height")
            }
        }
    }
}
impl std::error::Error for QRunCheckpointError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV05PowCheckpoint {
    pub network_id: NetworkId,
    pub genesis_commitment: [u8; 32],
    pub consensus_profile_fingerprint: [u8; 32],
    pub height: u64,
    pub consensus_tip_digest: [u8; 32],
    pub ledger_tip_hash: [u8; 32],
    pub state_root: [u8; 32],
    pub total_supply_atoms: u128,
    pub cumulative_work: Uint256,
    pub parent_checkpoint_commitment: [u8; 32],
    pub state_snapshot: Vec<u8>,
    pub target_history: TargetHistoryCheckpoint,
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    hash.finalize().into()
}

pub fn qrun_consensus_profile_fingerprint(
    params: &ConsensusParameters,
) -> Result<[u8; 32], QRunCheckpointError> {
    params
        .validate()
        .map_err(|_| QRunCheckpointError::InvalidProfile)?;
    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(&params.protocol_version.to_be_bytes());
    bytes.extend_from_slice(&params.target_block_time_secs.to_be_bytes());
    bytes.extend_from_slice(&params.difficulty_window_blocks.to_be_bytes());
    bytes.extend_from_slice(&params.difficulty_min_ratio_divisor.to_be_bytes());
    bytes.extend_from_slice(&params.difficulty_max_ratio.to_be_bytes());
    bytes.extend_from_slice(&params.pow_limit.to_be_bytes());
    bytes.extend_from_slice(&params.initial_target.to_be_bytes());
    bytes.push(match params.pow.algorithm {
        PowAlgorithm::Argon2id => 1,
    });
    bytes.extend_from_slice(&params.pow.memory_kib.to_be_bytes());
    bytes.extend_from_slice(&params.pow.iterations.to_be_bytes());
    bytes.extend_from_slice(&params.pow.lanes.to_be_bytes());
    bytes.push(params.pow.output_bytes);
    bytes.extend_from_slice(&params.issuance.maximum_supply().to_be_bytes());
    bytes.extend_from_slice(&params.issuance.initial_subsidy().to_be_bytes());
    bytes.extend_from_slice(&params.issuance.blocks_per_halving().to_be_bytes());
    Ok(domain_hash(QRCP_PROFILE_DOMAIN, &bytes))
}

impl QRunV05PowCheckpoint {
    pub fn capture(
        network_id: NetworkId,
        genesis_commitment: [u8; 32],
        params: &ConsensusParameters,
        chain: &PrivateTestnetChain,
        parent_checkpoint_commitment: [u8; 32],
    ) -> Result<Self, QRunCheckpointError> {
        let height = chain.state().height();
        if network_id.iter().all(|byte| *byte == 0)
            || genesis_commitment.iter().all(|byte| *byte == 0)
            || (height > 0 && chain.chain_tip().tip_hash.iter().all(|byte| *byte == 0))
        {
            return Err(QRunCheckpointError::InvalidIdentifier);
        }
        if chain.state().network_id() != network_id {
            return Err(QRunCheckpointError::WrongNetwork);
        }
        if (height > 0 && parent_checkpoint_commitment == [0; 32])
            || (height == 0 && parent_checkpoint_commitment != [0; 32])
        {
            return Err(QRunCheckpointError::MissingParentCheckpoint);
        }
        let state_snapshot = chain
            .state()
            .encode_snapshot()
            .map_err(|error| QRunCheckpointError::StateSnapshot(format!("{error:?}")))?;
        let target_history = chain
            .target_history()
            .checkpoint_snapshot()
            .map_err(|error| QRunCheckpointError::TargetHistory(error.to_string()))?;
        let record = Self {
            network_id,
            genesis_commitment,
            consensus_profile_fingerprint: qrun_consensus_profile_fingerprint(params)?,
            height,
            consensus_tip_digest: chain.chain_tip().tip_hash,
            ledger_tip_hash: chain.state().tip_hash(),
            state_root: chain.state().state_root(),
            total_supply_atoms: chain
                .state()
                .total_value()
                .map_err(|error| QRunCheckpointError::StateSnapshot(format!("{error:?}")))?,
            cumulative_work: chain.cumulative_work(),
            parent_checkpoint_commitment,
            state_snapshot,
            target_history,
        };
        record.validate(params)?;
        Ok(record)
    }

    fn validate(&self, params: &ConsensusParameters) -> Result<(), QRunCheckpointError> {
        let profile = qrun_consensus_profile_fingerprint(params)?;
        if self.consensus_profile_fingerprint != profile {
            return Err(QRunCheckpointError::ProfileMismatch);
        }
        if self.network_id.iter().all(|byte| *byte == 0)
            || self.genesis_commitment.iter().all(|byte| *byte == 0)
            || (self.height > 0 && self.consensus_tip_digest.iter().all(|byte| *byte == 0))
        {
            return Err(QRunCheckpointError::InvalidIdentifier);
        }
        if (self.height > 0 && self.parent_checkpoint_commitment == [0; 32])
            || (self.height == 0 && self.parent_checkpoint_commitment != [0; 32])
        {
            return Err(QRunCheckpointError::MissingParentCheckpoint);
        }
        if self.state_snapshot.is_empty() || self.state_snapshot.len() > MAX_ENCODED_SNAPSHOT_BYTES
        {
            return Err(QRunCheckpointError::Oversize);
        }
        if self.total_supply_atoms != MAX_TOTAL_SUPPLY_ATOMS
            || params.issuance.maximum_supply() != MAX_TOTAL_SUPPLY_ATOMS
        {
            return Err(QRunCheckpointError::SupplyMismatch);
        }
        let state = LedgerState::decode_snapshot(&self.state_snapshot, &self.network_id)
            .map_err(|error| QRunCheckpointError::StateSnapshot(format!("{error:?}")))?;
        if state.height() != self.height
            || state.tip_hash() != self.ledger_tip_hash
            || state.state_root() != self.state_root
            || state
                .total_value()
                .map_err(|error| QRunCheckpointError::StateSnapshot(format!("{error:?}")))?
                != self.total_supply_atoms
        {
            return Err(QRunCheckpointError::StateMetadataMismatch);
        }
        let target_history =
            TargetHistory::from_checkpoint_snapshot(params.clone(), &self.target_history)
                .map_err(|error| QRunCheckpointError::TargetHistory(error.to_string()))?;
        if target_history.height() != self.height {
            return Err(QRunCheckpointError::TargetHistoryHeightMismatch);
        }
        Ok(())
    }

    pub fn encode(&self, params: &ConsensusParameters) -> Result<Vec<u8>, QRunCheckpointError> {
        self.validate(params)?;
        let snapshot_len =
            u32::try_from(self.state_snapshot.len()).map_err(|_| QRunCheckpointError::Oversize)?;
        let count = u32::try_from(self.target_history.entries.len())
            .map_err(|_| QRunCheckpointError::Oversize)?;
        if self.target_history.entries.len() > MAX_TARGET_HISTORY_CHECKPOINT_ENTRIES {
            return Err(QRunCheckpointError::Oversize);
        }
        let estimated = 4
            + 2
            + 32 * 8
            + 8 * 3
            + 16
            + 4
            + 4
            + self.state_snapshot.len()
            + self.target_history.entries.len() * HISTORY_ENTRY_BYTES
            + CHECKSUM_BYTES;
        if estimated > MAX_QRCP_BYTES {
            return Err(QRunCheckpointError::Oversize);
        }
        let mut out = Vec::with_capacity(estimated);
        out.extend_from_slice(&QRCP_MAGIC);
        out.extend_from_slice(&QRCP_VERSION.to_be_bytes());
        out.extend_from_slice(&self.network_id);
        out.extend_from_slice(&self.genesis_commitment);
        out.extend_from_slice(&self.consensus_profile_fingerprint);
        out.extend_from_slice(&self.height.to_be_bytes());
        out.extend_from_slice(&self.consensus_tip_digest);
        out.extend_from_slice(&self.ledger_tip_hash);
        out.extend_from_slice(&self.state_root);
        out.extend_from_slice(&self.total_supply_atoms.to_be_bytes());
        out.extend_from_slice(&self.cumulative_work.to_be_bytes());
        out.extend_from_slice(&self.parent_checkpoint_commitment);
        out.extend_from_slice(&snapshot_len.to_be_bytes());
        out.extend_from_slice(&self.state_snapshot);
        out.extend_from_slice(&self.target_history.logical_height.to_be_bytes());
        out.extend_from_slice(&self.target_history.start_height.to_be_bytes());
        out.extend_from_slice(&count.to_be_bytes());
        for entry in &self.target_history.entries {
            out.extend_from_slice(&entry.height.to_be_bytes());
            out.extend_from_slice(&entry.target.to_be_bytes());
            match entry.timestamp {
                Some(timestamp) => {
                    out.push(1);
                    out.extend_from_slice(&timestamp.to_be_bytes());
                }
                None => {
                    out.push(0);
                    out.extend_from_slice(&0u64.to_be_bytes());
                }
            }
        }
        if out.len().saturating_add(CHECKSUM_BYTES) != estimated {
            return Err(QRunCheckpointError::Malformed);
        }
        let checksum = domain_hash(QRCP_CHECKSUM_DOMAIN, &out);
        out.extend_from_slice(&checksum);
        Ok(out)
    }

    pub fn decode(
        bytes: &[u8],
        expected_network_id: &NetworkId,
        expected_genesis_commitment: &[u8; 32],
        params: &ConsensusParameters,
    ) -> Result<Self, QRunCheckpointError> {
        if bytes.len() > MAX_QRCP_BYTES
            || bytes.len() < 4 + 2 + 32 * 8 + 8 + 16 + 4 + 8 + 8 + 4 + CHECKSUM_BYTES
        {
            return Err(QRunCheckpointError::Oversize);
        }
        if bytes.get(..4) != Some(QRCP_MAGIC.as_slice()) {
            return Err(QRunCheckpointError::Malformed);
        }
        let version = u16::from_be_bytes(
            bytes
                .get(4..6)
                .ok_or(QRunCheckpointError::Malformed)?
                .try_into()
                .map_err(|_| QRunCheckpointError::Malformed)?,
        );
        if version != QRCP_VERSION {
            return Err(QRunCheckpointError::UnsupportedVersion(version));
        }
        let payload_len = bytes
            .len()
            .checked_sub(CHECKSUM_BYTES)
            .ok_or(QRunCheckpointError::Malformed)?;
        if domain_hash(QRCP_CHECKSUM_DOMAIN, &bytes[..payload_len]) != bytes[payload_len..] {
            return Err(QRunCheckpointError::ChecksumMismatch);
        }
        let mut cursor = 6usize;
        let network_id = take_array::<32>(bytes, &mut cursor)?;
        let genesis_commitment = take_array::<32>(bytes, &mut cursor)?;
        let consensus_profile_fingerprint = take_array::<32>(bytes, &mut cursor)?;
        let height = take_u64(bytes, &mut cursor)?;
        let consensus_tip_digest = take_array::<32>(bytes, &mut cursor)?;
        let ledger_tip_hash = take_array::<32>(bytes, &mut cursor)?;
        let state_root = take_array::<32>(bytes, &mut cursor)?;
        let total_supply_atoms = take_u128(bytes, &mut cursor)?;
        let cumulative_work = Uint256::from_be_bytes(take_array::<32>(bytes, &mut cursor)?);
        let parent_checkpoint_commitment = take_array::<32>(bytes, &mut cursor)?;
        let snapshot_len = take_u32(bytes, &mut cursor)? as usize;
        if snapshot_len == 0 || snapshot_len > MAX_ENCODED_SNAPSHOT_BYTES {
            return Err(QRunCheckpointError::Oversize);
        }
        let state_snapshot = take_slice(bytes, &mut cursor, snapshot_len)?.to_vec();
        let logical_height = take_u64(bytes, &mut cursor)?;
        let start_height = take_u64(bytes, &mut cursor)?;
        let count = take_u32(bytes, &mut cursor)? as usize;
        if count > MAX_TARGET_HISTORY_CHECKPOINT_ENTRIES {
            return Err(QRunCheckpointError::Oversize);
        }
        let entries_len = count
            .checked_mul(HISTORY_ENTRY_BYTES)
            .ok_or(QRunCheckpointError::Oversize)?;
        if cursor.checked_add(entries_len) != Some(payload_len) {
            return Err(QRunCheckpointError::Malformed);
        }
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            let entry_height = take_u64(bytes, &mut cursor)?;
            let target = Uint256::from_be_bytes(take_array::<32>(bytes, &mut cursor)?);
            let present = take_slice(bytes, &mut cursor, 1)?[0];
            let timestamp_value = take_u64(bytes, &mut cursor)?;
            let timestamp = match present {
                0 if timestamp_value == 0 => None,
                1 => Some(timestamp_value),
                _ => return Err(QRunCheckpointError::Malformed),
            };
            entries.push(
                crate::private_testnet_driver::TargetHistoryCheckpointEntry {
                    height: entry_height,
                    target,
                    timestamp,
                },
            );
        }
        if cursor != payload_len {
            return Err(QRunCheckpointError::Malformed);
        }
        let record = Self {
            network_id,
            genesis_commitment,
            consensus_profile_fingerprint,
            height,
            consensus_tip_digest,
            ledger_tip_hash,
            state_root,
            total_supply_atoms,
            cumulative_work,
            parent_checkpoint_commitment,
            state_snapshot,
            target_history: TargetHistoryCheckpoint {
                logical_height,
                start_height,
                entries,
            },
        };
        if &record.network_id != expected_network_id {
            return Err(QRunCheckpointError::WrongNetwork);
        }
        if &record.genesis_commitment != expected_genesis_commitment {
            return Err(QRunCheckpointError::WrongGenesis);
        }
        record.validate(params)?;
        Ok(record)
    }

    /// Decode only when an independently protected anchor matches the exact record commitment.
    pub fn decode_anchored(
        bytes: &[u8],
        expected_network_id: &NetworkId,
        expected_genesis_commitment: &[u8; 32],
        params: &ConsensusParameters,
        expected_commitment: [u8; 32],
        minimum_height: u64,
    ) -> Result<Self, QRunCheckpointError> {
        if expected_commitment == [0; 32] {
            return Err(QRunCheckpointError::InvalidIdentifier);
        }
        let actual_commitment = Self::commitment_for_bytes(bytes);
        if actual_commitment != expected_commitment {
            return Err(QRunCheckpointError::CommitmentMismatch);
        }
        let record = Self::decode(
            bytes,
            expected_network_id,
            expected_genesis_commitment,
            params,
        )?;
        if record.height < minimum_height {
            return Err(QRunCheckpointError::HeightRollback);
        }
        Ok(record)
    }

    pub fn commitment(
        &self,
        params: &ConsensusParameters,
    ) -> Result<[u8; 32], QRunCheckpointError> {
        Ok(Self::commitment_for_bytes(&self.encode(params)?))
    }

    pub fn commitment_for_bytes(bytes: &[u8]) -> [u8; 32] {
        domain_hash(QRCP_COMMITMENT_DOMAIN, bytes)
    }
}

fn take_slice<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> Result<&'a [u8], QRunCheckpointError> {
    let end = cursor
        .checked_add(length)
        .ok_or(QRunCheckpointError::Malformed)?;
    let part = bytes
        .get(*cursor..end)
        .ok_or(QRunCheckpointError::Malformed)?;
    *cursor = end;
    Ok(part)
}
fn take_array<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], QRunCheckpointError> {
    take_slice(bytes, cursor, N)?
        .try_into()
        .map_err(|_| QRunCheckpointError::Malformed)
}
fn take_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, QRunCheckpointError> {
    Ok(u32::from_be_bytes(take_array::<4>(bytes, cursor)?))
}
fn take_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64, QRunCheckpointError> {
    Ok(u64::from_be_bytes(take_array::<8>(bytes, cursor)?))
}
fn take_u128(bytes: &[u8], cursor: &mut usize) -> Result<u128, QRunCheckpointError> {
    Ok(u128::from_be_bytes(take_array::<16>(bytes, cursor)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{consensus::Uint256, qrun_v05_genesis_candidate::QRunGenesisV05};

    #[test]
    fn qrun_checkpoint_is_bound_to_state_history_profile_and_external_anchor() {
        let network = [0x51; 32];
        let owner = [0x2a; 32];
        let genesis = QRunGenesisV05::new(network, owner).unwrap();
        let params = ConsensusParameters::candidate_testnet().unwrap();
        let chain = PrivateTestnetChain::new(genesis.ledger().clone(), params.clone()).unwrap();
        let record =
            QRunV05PowCheckpoint::capture(network, genesis.commitment(), &params, &chain, [0; 32])
                .unwrap();
        let bytes = record.encode(&params).unwrap();
        let commitment = QRunV05PowCheckpoint::commitment_for_bytes(&bytes);
        let decoded = QRunV05PowCheckpoint::decode_anchored(
            &bytes,
            &network,
            &genesis.commitment(),
            &params,
            commitment,
            0,
        )
        .unwrap();
        assert_eq!(decoded, record);
        assert_eq!(decoded.total_supply_atoms, MAX_TOTAL_SUPPLY_ATOMS);
        assert_eq!(
            QRunV05PowCheckpoint::decode_anchored(
                &bytes,
                &network,
                &genesis.commitment(),
                &params,
                commitment,
                1,
            ),
            Err(QRunCheckpointError::HeightRollback)
        );
        let mut corrupt = bytes.clone();
        let index = corrupt.len() / 2;
        corrupt[index] ^= 1;
        assert_eq!(
            QRunV05PowCheckpoint::decode(&corrupt, &network, &genesis.commitment(), &params,),
            Err(QRunCheckpointError::ChecksumMismatch)
        );
        let mut wrong_params = params.clone();
        wrong_params.initial_target = Uint256::from_be_bytes([0x11; 32]);
        assert_eq!(
            QRunV05PowCheckpoint::decode(&bytes, &network, &genesis.commitment(), &wrong_params,),
            Err(QRunCheckpointError::ProfileMismatch)
        );
    }
}
