//! Candidate-only canonical PCP4 checkpoint record codec.
//!
//! This module validates byte structure and consistency with a caller-supplied trusted
//! genesis/profile context. A PCP4 checksum detects corruption; it does not authenticate a
//! checkpoint, prove a pruned suffix's ancestry, or provide anti-rollback freshness. This
//! codec is not connected to PFM4/PFM5 durable storage, node startup, fork choice, or reorg.

use crate::{
    consensus::{ConsensusParameters, PowAlgorithm, Uint256},
    private_testnet_driver::{
        TargetHistory, TargetHistoryCheckpoint, TargetHistoryCheckpointEntry,
        MAX_TARGET_HISTORY_CHECKPOINT_ENTRIES,
    },
    state_machine::{
        AccountId, Block, MonetaryBlock, MonetaryLedgerState, NetworkId, TransactionAuthenticator,
        ATOMS_PER_COIN, MAX_ENCODED_SNAPSHOT_BYTES, MAX_TOTAL_SUPPLY_ATOMS,
        MONETARY_BLOCKS_PER_HALVING, MONETARY_FOUNDER_ALLOCATION_ATOMS,
        MONETARY_INITIAL_SUBSIDY_ATOMS, MONETARY_MINER_BUDGET_ATOMS,
        MONETARY_PUBLIC_GOODS_BUDGET_ATOMS,
    },
};
use sha2::{Digest, Sha256};

pub const PCP4_MAGIC: [u8; 4] = *b"PCP4";
pub const PCP4_SCHEMA_VERSION: u16 = 1;
pub const PCP4_CHECKSUM_DOMAIN: &[u8] = b"AIN1-PMT4-CHECKPOINT-CHECKSUM-V1\0";
pub const PCP4_COMMITMENT_DOMAIN: &[u8] = b"AIN1-PMT4-CHECKPOINT-COMMITMENT-V1\0";
const PCP4_PROFILE_DOMAIN: &[u8] = b"AIN1-PMT4-CHECKPOINT-PROFILE-V1\0";
const PCP4_GENESIS_DOMAIN: &[u8] = b"AIN1-PMT4-CHECKPOINT-GENESIS-V1\0";
const CHECKSUM_BYTES: usize = 32;
const TARGET_HISTORY_ENTRY_BYTES: usize = 49;
const MONETARY_SNAPSHOT_OVERHEAD: usize = 4 + 2 + 32 + 16 + 4 + 32;
pub const MAX_PCP4_MONETARY_SNAPSHOT_BYTES: usize =
    MAX_ENCODED_SNAPSHOT_BYTES + MONETARY_SNAPSHOT_OVERHEAD;
pub const MAX_PCP4_RECORD_BYTES: usize = 9 * 1024 * 1024;
// Includes header, all fixed metadata, variable snapshot/history, and trailing checksum.
pub const PCP4_FIXED_RECORD_BYTES: usize = 372;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pcp4CheckpointError {
    InvalidContext,
    InvalidProfile,
    InvalidIdentifier,
    WrongNetwork,
    ProfileFingerprintMismatch,
    GenesisFingerprintMismatch,
    TransactionManifestMismatch,
    MonetarySnapshotInvalid,
    MonetaryMetadataMismatch,
    HistoryInvalid,
    InvalidGenesisCheckpoint,
    InvalidParentCommitment,
    InvalidChainwork,
    Malformed,
    UnsupportedVersion(u16),
    Oversize,
    ChecksumMismatch,
    NonCanonical,
}

impl std::fmt::Display for Pcp4CheckpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidContext => write!(f, "PCP4 validation context is invalid"),
            Self::InvalidProfile => write!(f, "PCP4 consensus/monetary profile is invalid"),
            Self::InvalidIdentifier => write!(f, "PCP4 identifier must be non-zero"),
            Self::WrongNetwork => write!(f, "PCP4 network ID does not match configured network"),
            Self::ProfileFingerprintMismatch => {
                write!(f, "PCP4 consensus profile fingerprint mismatch")
            }
            Self::GenesisFingerprintMismatch => {
                write!(f, "PCP4 trusted Genesis fingerprint mismatch")
            }
            Self::TransactionManifestMismatch => write!(
                f,
                "PCP4 transaction manifest does not match active manifest"
            ),
            Self::MonetarySnapshotInvalid => write!(f, "PCP4 monetary snapshot is invalid"),
            Self::MonetaryMetadataMismatch => {
                write!(f, "PCP4 metadata does not match decoded monetary state")
            }
            Self::HistoryInvalid => write!(
                f,
                "PCP4 target history is invalid for the configured profile"
            ),
            Self::InvalidGenesisCheckpoint => {
                write!(f, "PCP4 Genesis checkpoint fields are inconsistent")
            }
            Self::InvalidParentCommitment => write!(
                f,
                "PCP4 parent checkpoint commitment is inconsistent with height"
            ),
            Self::InvalidChainwork => write!(
                f,
                "PCP4 cumulative chainwork is inconsistent with checkpoint height"
            ),
            Self::Malformed => write!(f, "PCP4 record is malformed"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported PCP4 schema version {version}")
            }
            Self::Oversize => write!(f, "PCP4 record exceeds a hard size/count limit"),
            Self::ChecksumMismatch => write!(f, "PCP4 checksum mismatch"),
            Self::NonCanonical => write!(f, "PCP4 record is not canonically encoded"),
        }
    }
}

impl std::error::Error for Pcp4CheckpointError {}

/// Caller-provided validation context. `trusted_genesis` must come from a configured/trusted
/// origin, not from the checkpoint being decoded. The manifest ID must be the currently active
/// transaction manifest. `params` must be the selected consensus profile, not a profile parsed
/// from the untrusted checkpoint itself.
pub struct Pcp4ValidationContext<'a> {
    pub network_id: &'a NetworkId,
    pub trusted_genesis: &'a MonetaryLedgerState,
    pub params: &'a ConsensusParameters,
    pub active_transaction_manifest_id: &'a [u8; 32],
}

/// Canonical version-1 PCP4 fields. The record serializes the monetary snapshot and bounded
/// target-history suffix; it does not carry a signature or anti-rollback receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pcp4CheckpointRecord {
    pub network_id: NetworkId,
    pub genesis_fingerprint: [u8; 32],
    pub consensus_profile_fingerprint: [u8; 32],
    pub transaction_manifest_id: [u8; 32],
    pub logical_height: u64,
    pub consensus_tip_digest: [u8; 32],
    pub ledger_tip_hash: [u8; 32],
    pub monetary_state_root: [u8; 32],
    pub total_mined_atoms: u128,
    pub cumulative_chainwork: Uint256,
    pub parent_checkpoint_commitment: [u8; 32],
    pub monetary_snapshot: Vec<u8>,
    pub target_history: TargetHistoryCheckpoint,
}

/// Compute the profile fingerprint from the configured candidate consensus parameters and the
/// monetary-state policy constants. It does not select or authorize a production profile.
pub fn consensus_profile_fingerprint(
    params: &ConsensusParameters,
) -> Result<[u8; 32], Pcp4CheckpointError> {
    params
        .validate_monetary_execution_compatibility()
        .map_err(|_| Pcp4CheckpointError::InvalidProfile)?;

    let mut bytes = Vec::with_capacity(2 + 8 * 5 + 32 * 2 + 1 + 4 * 3 + 1 + 16 * 5 + 8 * 2);
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
    bytes.extend_from_slice(&ATOMS_PER_COIN.to_be_bytes());
    bytes.extend_from_slice(&MAX_TOTAL_SUPPLY_ATOMS.to_be_bytes());
    bytes.extend_from_slice(&MONETARY_FOUNDER_ALLOCATION_ATOMS.to_be_bytes());
    bytes.extend_from_slice(&MONETARY_MINER_BUDGET_ATOMS.to_be_bytes());
    bytes.extend_from_slice(&MONETARY_PUBLIC_GOODS_BUDGET_ATOMS.to_be_bytes());
    bytes.extend_from_slice(&MONETARY_INITIAL_SUBSIDY_ATOMS.to_be_bytes());
    bytes.extend_from_slice(&MONETARY_BLOCKS_PER_HALVING.to_be_bytes());
    Ok(domain_hash(PCP4_PROFILE_DOMAIN, &[&bytes]))
}

/// Compute the expected Genesis fingerprint from independently supplied trusted Genesis bytes,
/// the active transaction manifest and the configured consensus/monetary profile.
pub fn trusted_genesis_fingerprint(
    context: &Pcp4ValidationContext<'_>,
) -> Result<[u8; 32], Pcp4CheckpointError> {
    validate_context(context)?;
    let profile = consensus_profile_fingerprint(context.params)?;
    let snapshot = context
        .trusted_genesis
        .encode_snapshot()
        .map_err(|_| Pcp4CheckpointError::InvalidContext)?;
    let snapshot_len = u32::try_from(snapshot.len()).map_err(|_| Pcp4CheckpointError::Oversize)?;
    Ok(domain_hash(
        PCP4_GENESIS_DOMAIN,
        &[
            context.network_id,
            &profile,
            context.active_transaction_manifest_id,
            &snapshot_len.to_be_bytes(),
            &snapshot,
        ],
    ))
}

impl Pcp4CheckpointRecord {
    /// Encode the canonical PCP4 v1 representation after checking all currently checkable
    /// metadata and history invariants against caller-supplied configured context.
    pub fn encode(
        &self,
        context: &Pcp4ValidationContext<'_>,
    ) -> Result<Vec<u8>, Pcp4CheckpointError> {
        self.validate_against(context)?;
        let snapshot_len = u32::try_from(self.monetary_snapshot.len())
            .map_err(|_| Pcp4CheckpointError::Oversize)?;
        let entry_count = u32::try_from(self.target_history.entries.len())
            .map_err(|_| Pcp4CheckpointError::Oversize)?;
        let history_bytes = self
            .target_history
            .entries
            .len()
            .checked_mul(TARGET_HISTORY_ENTRY_BYTES)
            .ok_or(Pcp4CheckpointError::Oversize)?;
        let record_len = PCP4_FIXED_RECORD_BYTES
            .checked_add(self.monetary_snapshot.len())
            .and_then(|value| value.checked_add(history_bytes))
            .filter(|value| *value <= MAX_PCP4_RECORD_BYTES && *value <= u32::MAX as usize)
            .ok_or(Pcp4CheckpointError::Oversize)?;

        let mut out = Vec::with_capacity(record_len);
        out.extend_from_slice(&PCP4_MAGIC);
        out.extend_from_slice(&PCP4_SCHEMA_VERSION.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes()); // v1 flags are reserved and must be zero.
        out.extend_from_slice(&(record_len as u32).to_be_bytes());
        out.extend_from_slice(&self.network_id);
        out.extend_from_slice(&self.genesis_fingerprint);
        out.extend_from_slice(&self.consensus_profile_fingerprint);
        out.extend_from_slice(&self.transaction_manifest_id);
        out.extend_from_slice(&self.logical_height.to_be_bytes());
        out.extend_from_slice(&self.consensus_tip_digest);
        out.extend_from_slice(&self.ledger_tip_hash);
        out.extend_from_slice(&self.monetary_state_root);
        out.extend_from_slice(&self.total_mined_atoms.to_be_bytes());
        out.extend_from_slice(&self.cumulative_chainwork.to_be_bytes());
        out.extend_from_slice(&self.parent_checkpoint_commitment);
        out.extend_from_slice(&snapshot_len.to_be_bytes());
        out.extend_from_slice(&self.monetary_snapshot);
        out.extend_from_slice(&self.target_history.start_height.to_be_bytes());
        out.extend_from_slice(&entry_count.to_be_bytes());
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
        if out.len().checked_add(CHECKSUM_BYTES) != Some(record_len) {
            return Err(Pcp4CheckpointError::NonCanonical);
        }
        let checksum = domain_hash(PCP4_CHECKSUM_DOMAIN, &[&out]);
        out.extend_from_slice(&checksum);
        Ok(out)
    }

    /// Decode, verify canonical byte layout/checksum, then validate metadata against the trusted
    /// Genesis/profile/manifest context. A successful decode is not a trust/anti-rollback proof.
    pub fn decode(
        bytes: &[u8],
        context: &Pcp4ValidationContext<'_>,
    ) -> Result<Self, Pcp4CheckpointError> {
        if bytes.len() > MAX_PCP4_RECORD_BYTES {
            return Err(Pcp4CheckpointError::Oversize);
        }
        if bytes.len() < PCP4_FIXED_RECORD_BYTES {
            return Err(Pcp4CheckpointError::Malformed);
        }
        if bytes.get(..4) != Some(PCP4_MAGIC.as_slice()) {
            return Err(Pcp4CheckpointError::Malformed);
        }
        let declared_len = u32::from_be_bytes(
            bytes
                .get(8..12)
                .ok_or(Pcp4CheckpointError::Malformed)?
                .try_into()
                .map_err(|_| Pcp4CheckpointError::Malformed)?,
        ) as usize;
        if declared_len != bytes.len() {
            return Err(Pcp4CheckpointError::Malformed);
        }
        let payload_len = bytes
            .len()
            .checked_sub(CHECKSUM_BYTES)
            .ok_or(Pcp4CheckpointError::Malformed)?;
        let expected_checksum = domain_hash(PCP4_CHECKSUM_DOMAIN, &[&bytes[..payload_len]]);
        if bytes[payload_len..] != expected_checksum {
            return Err(Pcp4CheckpointError::ChecksumMismatch);
        }

        let mut reader = Reader::new(&bytes[..payload_len]);
        if reader.read_array::<4>()? != PCP4_MAGIC {
            return Err(Pcp4CheckpointError::Malformed);
        }
        let version = reader.read_u16()?;
        if version != PCP4_SCHEMA_VERSION {
            return Err(Pcp4CheckpointError::UnsupportedVersion(version));
        }
        if reader.read_u16()? != 0 {
            return Err(Pcp4CheckpointError::NonCanonical);
        }
        if reader.read_u32()? as usize != bytes.len() {
            return Err(Pcp4CheckpointError::Malformed);
        }
        let network_id = reader.read_array::<32>()?;
        let genesis_fingerprint = reader.read_array::<32>()?;
        let consensus_profile_fingerprint = reader.read_array::<32>()?;
        let transaction_manifest_id = reader.read_array::<32>()?;
        let logical_height = reader.read_u64()?;
        let consensus_tip_digest = reader.read_array::<32>()?;
        let ledger_tip_hash = reader.read_array::<32>()?;
        let monetary_state_root = reader.read_array::<32>()?;
        let total_mined_atoms = reader.read_u128()?;
        let cumulative_chainwork = Uint256::from_be_bytes(reader.read_array::<32>()?);
        let parent_checkpoint_commitment = reader.read_array::<32>()?;
        let snapshot_len = reader.read_u32()? as usize;
        if snapshot_len == 0 || snapshot_len > MAX_PCP4_MONETARY_SNAPSHOT_BYTES {
            return Err(Pcp4CheckpointError::Oversize);
        }
        let snapshot_slice = reader.take(snapshot_len)?;
        let start_height = reader.read_u64()?;
        let entry_count = reader.read_u32()? as usize;
        if entry_count == 0 || entry_count > MAX_TARGET_HISTORY_CHECKPOINT_ENTRIES {
            return Err(Pcp4CheckpointError::Oversize);
        }
        validate_canonical_history_range(
            logical_height,
            start_height,
            entry_count,
            context.params,
        )?;
        let expected_history_bytes = entry_count
            .checked_mul(TARGET_HISTORY_ENTRY_BYTES)
            .ok_or(Pcp4CheckpointError::Oversize)?;
        if reader.remaining() != expected_history_bytes {
            return Err(Pcp4CheckpointError::Malformed);
        }
        let mut entries = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            let height = reader.read_u64()?;
            let target = Uint256::from_be_bytes(reader.read_array::<32>()?);
            let timestamp_present = reader.read_u8()?;
            let timestamp_value = reader.read_u64()?;
            let timestamp = match timestamp_present {
                0 if height == 0 && timestamp_value == 0 => None,
                1 if height > 0 && timestamp_value > 0 => Some(timestamp_value),
                0 | 1 => return Err(Pcp4CheckpointError::NonCanonical),
                _ => return Err(Pcp4CheckpointError::NonCanonical),
            };
            entries.push(TargetHistoryCheckpointEntry {
                height,
                target,
                timestamp,
            });
        }
        if !reader.is_finished() {
            return Err(Pcp4CheckpointError::Malformed);
        }
        let record = Self {
            network_id,
            genesis_fingerprint,
            consensus_profile_fingerprint,
            transaction_manifest_id,
            logical_height,
            consensus_tip_digest,
            ledger_tip_hash,
            monetary_state_root,
            total_mined_atoms,
            cumulative_chainwork,
            parent_checkpoint_commitment,
            monetary_snapshot: snapshot_slice.to_vec(),
            target_history: TargetHistoryCheckpoint {
                logical_height,
                start_height,
                entries,
            },
        };
        record.validate_against(context)?;
        Ok(record)
    }

    /// Domain-separated commitment for parent linkage or a future manifest. Call only after
    /// validating/encoding this record under the expected context; the commitment itself does
    /// not authorize it.
    pub fn commitment(
        &self,
        context: &Pcp4ValidationContext<'_>,
    ) -> Result<[u8; 32], Pcp4CheckpointError> {
        let encoded = self.encode(context)?;
        Ok(domain_hash(PCP4_COMMITMENT_DOMAIN, &[&encoded]))
    }

    fn validate_against(
        &self,
        context: &Pcp4ValidationContext<'_>,
    ) -> Result<(), Pcp4CheckpointError> {
        validate_context(context)?;
        if self.network_id != *context.network_id {
            return Err(Pcp4CheckpointError::WrongNetwork);
        }
        if self.transaction_manifest_id != *context.active_transaction_manifest_id {
            return Err(Pcp4CheckpointError::TransactionManifestMismatch);
        }
        let expected_profile = consensus_profile_fingerprint(context.params)?;
        if self.consensus_profile_fingerprint != expected_profile {
            return Err(Pcp4CheckpointError::ProfileFingerprintMismatch);
        }
        let expected_genesis = trusted_genesis_fingerprint_unchecked(context, &expected_profile)?;
        if self.genesis_fingerprint != expected_genesis {
            return Err(Pcp4CheckpointError::GenesisFingerprintMismatch);
        }
        if self.monetary_snapshot.is_empty()
            || self.monetary_snapshot.len() > MAX_PCP4_MONETARY_SNAPSHOT_BYTES
        {
            return Err(Pcp4CheckpointError::Oversize);
        }
        let state =
            MonetaryLedgerState::decode_snapshot(&self.monetary_snapshot, context.network_id)
                .map_err(|_| Pcp4CheckpointError::MonetarySnapshotInvalid)?;
        if state.ledger().network_id() != *context.network_id
            || state.height() != self.logical_height
            || state.tip_hash() != self.ledger_tip_hash
            || state.state_root() != self.monetary_state_root
            || state.total_mined_atoms() != self.total_mined_atoms
            || self.target_history.logical_height != self.logical_height
        {
            return Err(Pcp4CheckpointError::MonetaryMetadataMismatch);
        }
        validate_canonical_history_range(
            self.logical_height,
            self.target_history.start_height,
            self.target_history.entries.len(),
            context.params,
        )?;
        let _restored_history =
            TargetHistory::from_checkpoint_snapshot(context.params.clone(), &self.target_history)
                .map_err(|_| Pcp4CheckpointError::HistoryInvalid)?;

        if self.logical_height == 0 {
            if state != *context.trusted_genesis
                || self.ledger_tip_hash != context.trusted_genesis.tip_hash()
                || self.consensus_tip_digest != context.trusted_genesis.tip_hash()
                || self.cumulative_chainwork != Uint256::ZERO
                || self.parent_checkpoint_commitment != [0; 32]
            {
                return Err(Pcp4CheckpointError::InvalidGenesisCheckpoint);
            }
        } else {
            if self.parent_checkpoint_commitment == [0; 32] {
                return Err(Pcp4CheckpointError::InvalidParentCommitment);
            }
            if self.cumulative_chainwork.is_zero() {
                return Err(Pcp4CheckpointError::InvalidChainwork);
            }
        }
        Ok(())
    }
}

fn validate_canonical_history_range(
    logical_height: u64,
    start_height: u64,
    entry_count: usize,
    params: &ConsensusParameters,
) -> Result<(), Pcp4CheckpointError> {
    let window = usize::try_from(params.difficulty_window_blocks)
        .map_err(|_| Pcp4CheckpointError::Oversize)?;
    if window == 0 || window > MAX_TARGET_HISTORY_CHECKPOINT_ENTRIES {
        return Err(Pcp4CheckpointError::Oversize);
    }
    let (expected_start, expected_count) = if logical_height == 0 {
        (0, 1)
    } else if logical_height < window as u64 {
        (
            0,
            usize::try_from(logical_height + 1).map_err(|_| Pcp4CheckpointError::Oversize)?,
        )
    } else {
        (logical_height - window as u64 + 1, window)
    };
    if start_height != expected_start || entry_count != expected_count {
        return Err(Pcp4CheckpointError::NonCanonical);
    }
    Ok(())
}
fn validate_context(context: &Pcp4ValidationContext<'_>) -> Result<(), Pcp4CheckpointError> {
    if *context.network_id == [0; 32]
        || *context.active_transaction_manifest_id == [0; 32]
        || context.trusted_genesis.height() != 0
        || context.trusted_genesis.ledger().network_id() != *context.network_id
        || context.trusted_genesis.total_mined_atoms() != 0
        || context.trusted_genesis.total_value().is_err()
    {
        return Err(Pcp4CheckpointError::InvalidContext);
    }
    context
        .params
        .validate_monetary_execution_compatibility()
        .map_err(|_| Pcp4CheckpointError::InvalidProfile)?;
    Ok(())
}

fn trusted_genesis_fingerprint_unchecked(
    context: &Pcp4ValidationContext<'_>,
    profile_fingerprint: &[u8; 32],
) -> Result<[u8; 32], Pcp4CheckpointError> {
    let snapshot = context
        .trusted_genesis
        .encode_snapshot()
        .map_err(|_| Pcp4CheckpointError::InvalidContext)?;
    let snapshot_len = u32::try_from(snapshot.len()).map_err(|_| Pcp4CheckpointError::Oversize)?;
    Ok(domain_hash(
        PCP4_GENESIS_DOMAIN,
        &[
            context.network_id,
            profile_fingerprint,
            context.active_transaction_manifest_id,
            &snapshot_len.to_be_bytes(),
            &snapshot,
        ],
    ))
}

fn domain_hash(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], Pcp4CheckpointError> {
        let end = self
            .position
            .checked_add(count)
            .ok_or(Pcp4CheckpointError::Malformed)?;
        let slice = self
            .bytes
            .get(self.position..end)
            .ok_or(Pcp4CheckpointError::Malformed)?;
        self.position = end;
        Ok(slice)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], Pcp4CheckpointError> {
        self.take(N)?
            .try_into()
            .map_err(|_| Pcp4CheckpointError::Malformed)
    }

    fn read_u8(&mut self) -> Result<u8, Pcp4CheckpointError> {
        Ok(self.read_array::<1>()?[0])
    }

    fn read_u16(&mut self) -> Result<u16, Pcp4CheckpointError> {
        Ok(u16::from_be_bytes(self.read_array::<2>()?))
    }

    fn read_u32(&mut self) -> Result<u32, Pcp4CheckpointError> {
        Ok(u32::from_be_bytes(self.read_array::<4>()?))
    }

    fn read_u64(&mut self) -> Result<u64, Pcp4CheckpointError> {
        Ok(u64::from_be_bytes(self.read_array::<8>()?))
    }

    fn read_u128(&mut self) -> Result<u128, Pcp4CheckpointError> {
        Ok(u128::from_be_bytes(self.read_array::<16>()?))
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }

    fn is_finished(&self) -> bool {
        self.position == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestAuthenticator;

    impl TransactionAuthenticator for TestAuthenticator {
        fn verify(&self, _: &AccountId, _: &[u8; 32], _: &[u8]) -> Result<(), ()> {
            Ok(())
        }
    }

    fn monetary_child_state(genesis: &MonetaryLedgerState) -> MonetaryLedgerState {
        let mut state = genesis.clone();
        let mut block = MonetaryBlock {
            body: Block {
                height: 1,
                timestamp: 1,
                parent_hash: genesis.tip_hash(),
                state_root: [0; 32],
                transactions: Vec::new(),
            },
            miner: [0x23; 32],
            claimed_subsidy_atoms: genesis.expected_miner_reward().unwrap(),
        };
        block.body.state_root = genesis
            .preview_state_root_after(&block, &TestAuthenticator)
            .unwrap();
        state.apply_block(&block, &TestAuthenticator).unwrap();
        state
    }
    fn genesis(network_id: NetworkId) -> MonetaryLedgerState {
        MonetaryLedgerState::genesis(
            network_id,
            [0x11; 32],
            vec![([0x22; 32], MONETARY_PUBLIC_GOODS_BUDGET_ATOMS as u64)],
        )
        .unwrap()
    }

    fn context<'a>(
        network_id: &'a NetworkId,
        trusted_genesis: &'a MonetaryLedgerState,
        params: &'a ConsensusParameters,
        manifest: &'a [u8; 32],
    ) -> Pcp4ValidationContext<'a> {
        Pcp4ValidationContext {
            network_id,
            trusted_genesis,
            params,
            active_transaction_manifest_id: manifest,
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
    fn genesis_record(ctx: &Pcp4ValidationContext<'_>) -> Pcp4CheckpointRecord {
        let profile = consensus_profile_fingerprint(ctx.params).unwrap();
        let genesis = trusted_genesis_fingerprint(ctx).unwrap();
        let snapshot = ctx.trusted_genesis.encode_snapshot().unwrap();
        Pcp4CheckpointRecord {
            network_id: *ctx.network_id,
            genesis_fingerprint: genesis,
            consensus_profile_fingerprint: profile,
            transaction_manifest_id: *ctx.active_transaction_manifest_id,
            logical_height: 0,
            consensus_tip_digest: ctx.trusted_genesis.tip_hash(),
            ledger_tip_hash: ctx.trusted_genesis.tip_hash(),
            monetary_state_root: ctx.trusted_genesis.state_root(),
            total_mined_atoms: ctx.trusted_genesis.total_mined_atoms(),
            cumulative_chainwork: Uint256::ZERO,
            parent_checkpoint_commitment: [0; 32],
            monetary_snapshot: snapshot,
            target_history: TargetHistoryCheckpoint {
                logical_height: 0,
                start_height: 0,
                entries: vec![TargetHistoryCheckpointEntry {
                    height: 0,
                    target: ctx.params.initial_target,
                    timestamp: None,
                }],
            },
        }
    }

    fn refresh_checksum(bytes: &mut [u8]) {
        let payload_len = bytes.len() - CHECKSUM_BYTES;
        let checksum = domain_hash(PCP4_CHECKSUM_DOMAIN, &[&bytes[..payload_len]]);
        bytes[payload_len..].copy_from_slice(&checksum);
    }

    #[test]
    fn genesis_record_roundtrips_and_has_domain_separated_commitment() {
        let network = [0x81; 32];
        let genesis = genesis(network);
        let params = ConsensusParameters::candidate_testnet().unwrap();
        let manifest = [0x44; 32];
        let ctx = context(&network, &genesis, &params, &manifest);
        let record = genesis_record(&ctx);
        let encoded = record.encode(&ctx).unwrap();
        assert_eq!(
            hex(&encoded),
            include_str!("../tests/fixtures/cp0384_pcp4_genesis_vector.hex").trim()
        );
        assert_eq!(&encoded[..4], b"PCP4");
        assert_eq!(u16::from_be_bytes([encoded[4], encoded[5]]), 1);
        assert_eq!(u16::from_be_bytes([encoded[6], encoded[7]]), 0);
        assert_eq!(
            u32::from_be_bytes(encoded[8..12].try_into().unwrap()) as usize,
            encoded.len()
        );
        assert!(encoded.len() <= MAX_PCP4_RECORD_BYTES);
        assert_eq!(
            Pcp4CheckpointRecord::decode(&encoded, &ctx).unwrap(),
            record
        );
        assert_eq!(
            record.commitment(&ctx).unwrap(),
            domain_hash(PCP4_COMMITMENT_DOMAIN, &[&encoded])
        );
    }

    #[test]
    fn non_genesis_record_roundtrips_and_binds_monetary_metadata_to_snapshot() {
        let network = [0x87; 32];
        let trusted_genesis = genesis(network);
        let child = monetary_child_state(&trusted_genesis);
        let params = ConsensusParameters::candidate_testnet().unwrap();
        let manifest = [0x4a; 32];
        let ctx = context(&network, &trusted_genesis, &params, &manifest);
        let record = Pcp4CheckpointRecord {
            network_id: network,
            genesis_fingerprint: trusted_genesis_fingerprint(&ctx).unwrap(),
            consensus_profile_fingerprint: consensus_profile_fingerprint(&params).unwrap(),
            transaction_manifest_id: manifest,
            logical_height: child.height(),
            consensus_tip_digest: [0x59; 32],
            ledger_tip_hash: child.tip_hash(),
            monetary_state_root: child.state_root(),
            total_mined_atoms: child.total_mined_atoms(),
            cumulative_chainwork: Uint256::ONE,
            parent_checkpoint_commitment: [0x5a; 32],
            monetary_snapshot: child.encode_snapshot().unwrap(),
            target_history: TargetHistoryCheckpoint {
                logical_height: 1,
                start_height: 0,
                entries: vec![
                    TargetHistoryCheckpointEntry {
                        height: 0,
                        target: params.initial_target,
                        timestamp: None,
                    },
                    TargetHistoryCheckpointEntry {
                        height: 1,
                        target: params.initial_target,
                        timestamp: Some(1),
                    },
                ],
            },
        };

        let encoded = record.encode(&ctx).unwrap();
        assert_eq!(Pcp4CheckpointRecord::decode(&encoded, &ctx), Ok(record));

        // The total-mined field lives at bytes 244..260. Mutating the metadata and
        // refreshing only the checksum must not detach it from the embedded state snapshot.
        let mut mismatched_metadata = encoded;
        mismatched_metadata[259] ^= 1;
        refresh_checksum(&mut mismatched_metadata);
        assert_eq!(
            Pcp4CheckpointRecord::decode(&mismatched_metadata, &ctx),
            Err(Pcp4CheckpointError::MonetaryMetadataMismatch)
        );
    }
    #[test]
    fn decoder_rejects_truncation_trailing_bytes_bad_version_flags_and_checksum() {
        let network = [0x82; 32];
        let genesis = genesis(network);
        let params = ConsensusParameters::candidate_testnet().unwrap();
        let manifest = [0x45; 32];
        let ctx = context(&network, &genesis, &params, &manifest);
        let encoded = genesis_record(&ctx).encode(&ctx).unwrap();

        assert_eq!(
            Pcp4CheckpointRecord::decode(&encoded[..encoded.len() - 1], &ctx),
            Err(Pcp4CheckpointError::Malformed)
        );
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            Pcp4CheckpointRecord::decode(&trailing, &ctx),
            Err(Pcp4CheckpointError::Malformed)
        );

        let mut wrong_version = encoded.clone();
        wrong_version[5] = 2;
        refresh_checksum(&mut wrong_version);
        assert_eq!(
            Pcp4CheckpointRecord::decode(&wrong_version, &ctx),
            Err(Pcp4CheckpointError::UnsupportedVersion(2))
        );

        let mut flags = encoded.clone();
        flags[7] = 1;
        refresh_checksum(&mut flags);
        assert_eq!(
            Pcp4CheckpointRecord::decode(&flags, &ctx),
            Err(Pcp4CheckpointError::NonCanonical)
        );

        let mut bad_checksum = encoded;
        let last = bad_checksum.len() - 1;
        bad_checksum[last] ^= 0x80;
        assert_eq!(
            Pcp4CheckpointRecord::decode(&bad_checksum, &ctx),
            Err(Pcp4CheckpointError::ChecksumMismatch)
        );
    }

    #[test]
    fn decoder_binds_network_manifest_profile_and_trusted_genesis() {
        let network = [0x83; 32];
        let genesis = genesis(network);
        let params = ConsensusParameters::candidate_testnet().unwrap();
        let manifest = [0x46; 32];
        let ctx = context(&network, &genesis, &params, &manifest);
        let encoded = genesis_record(&ctx).encode(&ctx).unwrap();

        let other_network = [0x84; 32];
        let other_network_genesis = MonetaryLedgerState::genesis(
            other_network,
            [0x11; 32],
            vec![([0x22; 32], MONETARY_PUBLIC_GOODS_BUDGET_ATOMS as u64)],
        )
        .unwrap();
        let wrong_network_ctx = context(&other_network, &other_network_genesis, &params, &manifest);
        assert_eq!(
            Pcp4CheckpointRecord::decode(&encoded, &wrong_network_ctx),
            Err(Pcp4CheckpointError::WrongNetwork)
        );

        let other_manifest = [0x47; 32];
        let wrong_manifest_ctx = context(&network, &genesis, &params, &other_manifest);
        assert_eq!(
            Pcp4CheckpointRecord::decode(&encoded, &wrong_manifest_ctx),
            Err(Pcp4CheckpointError::TransactionManifestMismatch)
        );

        let mut other_params = params.clone();
        other_params.difficulty_window_blocks += 1;
        let wrong_profile_ctx = context(&network, &genesis, &other_params, &manifest);
        assert_eq!(
            Pcp4CheckpointRecord::decode(&encoded, &wrong_profile_ctx),
            Err(Pcp4CheckpointError::ProfileFingerprintMismatch)
        );

        let alternate_genesis = MonetaryLedgerState::genesis(
            network,
            [0x12; 32],
            vec![([0x23; 32], MONETARY_PUBLIC_GOODS_BUDGET_ATOMS as u64)],
        )
        .unwrap();
        let wrong_genesis_ctx = context(&network, &alternate_genesis, &params, &manifest);
        assert_eq!(
            Pcp4CheckpointRecord::decode(&encoded, &wrong_genesis_ctx),
            Err(Pcp4CheckpointError::GenesisFingerprintMismatch)
        );
    }

    #[test]
    fn decoder_rejects_noncanonical_history_range_before_allocating_entries() {
        let network = [0x86; 32];
        let trusted_genesis = genesis(network);
        let params = ConsensusParameters::candidate_testnet().unwrap();
        let manifest = [0x49; 32];
        let ctx = context(&network, &trusted_genesis, &params, &manifest);
        let encoded = genesis_record(&ctx).encode(&ctx).unwrap();
        let snapshot_len = genesis_record(&ctx).monetary_snapshot.len();
        let history_start_offset = 328 + snapshot_len;
        let history_count_offset = history_start_offset + 8;

        let mut wrong_start = encoded.clone();
        wrong_start[history_start_offset + 7] = 1;
        refresh_checksum(&mut wrong_start);
        assert_eq!(
            Pcp4CheckpointRecord::decode(&wrong_start, &ctx),
            Err(Pcp4CheckpointError::NonCanonical)
        );

        // Below the global count ceiling, but impossible at logical height zero.
        // It must fail the profile-derived range check before Vec::with_capacity.
        let mut impossible_genesis_count = encoded.clone();
        impossible_genesis_count[history_count_offset..history_count_offset + 4]
            .copy_from_slice(&(65_536u32).to_be_bytes());
        refresh_checksum(&mut impossible_genesis_count);
        assert_eq!(
            Pcp4CheckpointRecord::decode(&impossible_genesis_count, &ctx),
            Err(Pcp4CheckpointError::NonCanonical)
        );

        let mut over_global_limit = encoded;
        over_global_limit[history_count_offset..history_count_offset + 4]
            .copy_from_slice(&(65_537u32).to_be_bytes());
        refresh_checksum(&mut over_global_limit);
        assert_eq!(
            Pcp4CheckpointRecord::decode(&over_global_limit, &ctx),
            Err(Pcp4CheckpointError::Oversize)
        );
    }
    #[test]
    fn decoder_rejects_noncanonical_history_and_inconsistent_genesis_parent() {
        let network = [0x85; 32];
        let genesis = genesis(network);
        let params = ConsensusParameters::candidate_testnet().unwrap();
        let manifest = [0x48; 32];
        let ctx = context(&network, &genesis, &params, &manifest);
        let encoded = genesis_record(&ctx).encode(&ctx).unwrap();

        // The Genesis history target is the final fixed-width 49-byte entry before the checksum.
        let mut zero_target = encoded.clone();
        let target_start = zero_target.len() - CHECKSUM_BYTES - TARGET_HISTORY_ENTRY_BYTES + 8;
        zero_target[target_start..target_start + 32].fill(0);
        refresh_checksum(&mut zero_target);
        assert_eq!(
            Pcp4CheckpointRecord::decode(&zero_target, &ctx),
            Err(Pcp4CheckpointError::HistoryInvalid)
        );

        // PCP4 fixed prefix offset for the parent commitment is 292..324.
        let mut parent_at_genesis = encoded;
        parent_at_genesis[292] = 1;
        refresh_checksum(&mut parent_at_genesis);
        assert_eq!(
            Pcp4CheckpointRecord::decode(&parent_at_genesis, &ctx),
            Err(Pcp4CheckpointError::InvalidGenesisCheckpoint)
        );
    }
}
