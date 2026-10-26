//! CP-0419 candidate QZBE checkpoint record.
//!
//! This record binds a profile-bound QZP4 monetary snapshot, QZBE consensus tip/chainwork, and the
//! bounded target/timestamp suffix required to continue difficulty validation. Its checksum and
//! commitment provide canonical encoding/integrity, not authenticity or anti-rollback. The caller
//! must independently establish a trusted checkpoint and replay/verify the ancestry or use an
//! explicitly trusted checkpoint certificate before pruning or continuing from it.

use crate::{
    consensus::{ConsensusParameters, Uint256},
    monetary_genesis_v04_candidate::{GenesisManifestError, GenesisManifestV04},
    monetary_pow_v04_candidate::pow_consensus_profile_fingerprint,
    monetary_transition_v04_candidate::{
        MonetaryLedgerStateV04TransitionCandidate, V04ConsensusProfileCandidate,
        V04TransitionError, MAX_ENCODED_V04_PROFILE_BOUND_SNAPSHOT_BYTES,
    },
    private_testnet_driver::{
        TargetHistory, TargetHistoryCheckpoint, TargetHistoryCheckpointEntry,
        TargetHistoryCheckpointError, MAX_TARGET_HISTORY_CHECKPOINT_ENTRIES,
    },
};
use sha2::{Digest, Sha256};

pub const QZBE_CHECKPOINT_MAGIC: [u8; 4] = *b"QZCP";
pub const QZBE_CHECKPOINT_SCHEMA_VERSION: u16 = 1;
pub const QZBE_CHECKPOINT_CHECKSUM_DOMAIN: &[u8] = b"QUANTUMZXB-QZBE-CHECKPOINT-CHECKSUM-V1\0";
pub const QZBE_CHECKPOINT_COMMITMENT_DOMAIN: &[u8] = b"QUANTUMZXB-QZBE-CHECKPOINT-COMMITMENT-V1\0";
pub const QZBE_CHECKPOINT_HISTORY_ENTRY_BYTES: usize = 49;
pub const QZBE_CHECKPOINT_FIXED_PREFIX_BYTES: usize = 340;
const CHECKSUM_BYTES: usize = 32;
pub const MAX_QZBE_CHECKPOINT_RECORD_BYTES: usize = QZBE_CHECKPOINT_FIXED_PREFIX_BYTES
    + MAX_ENCODED_V04_PROFILE_BOUND_SNAPSHOT_BYTES
    + MAX_TARGET_HISTORY_CHECKPOINT_ENTRIES * QZBE_CHECKPOINT_HISTORY_ENTRY_BYTES
    + CHECKSUM_BYTES;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QzbeCheckpointError {
    InvalidContext,
    GenesisManifest(GenesisManifestError),
    Transition(V04TransitionError),
    History(TargetHistoryCheckpointError),
    WrongMagic,
    UnsupportedVersion(u16),
    NonCanonical,
    Malformed,
    Oversize,
    ChecksumMismatch,
    WrongNetwork,
    GenesisMismatch,
    ProfileMismatch,
    ConsensusMismatch,
    StateMetadataMismatch,
    InvalidGenesisCheckpoint,
    InvalidParentCommitment,
    InvalidChainwork,
}

impl From<GenesisManifestError> for QzbeCheckpointError {
    fn from(value: GenesisManifestError) -> Self {
        Self::GenesisManifest(value)
    }
}
impl From<V04TransitionError> for QzbeCheckpointError {
    fn from(value: V04TransitionError) -> Self {
        Self::Transition(value)
    }
}
impl From<TargetHistoryCheckpointError> for QzbeCheckpointError {
    fn from(value: TargetHistoryCheckpointError) -> Self {
        Self::History(value)
    }
}

impl std::fmt::Display for QzbeCheckpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for QzbeCheckpointError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QzbeCheckpointValidationContext<'a> {
    pub manifest: &'a GenesisManifestV04,
    pub profile: &'a V04ConsensusProfileCandidate,
    pub params: &'a ConsensusParameters,
}

/// Fixed-schema QZBE checkpoint. The consensus tip digest is the QZBE body-bound PoW/fork-choice
/// digest; the ledger tip hash is the execution state's internal ledger tip and is stored separately.
/// A non-Genesis checkpoint requires a parent checkpoint commitment and nonzero cumulative chainwork,
/// but this codec cannot prove either from a local digest alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QzbeCheckpointRecord {
    pub network_id: [u8; 32],
    pub genesis_manifest_hash: [u8; 32],
    pub profile_fingerprint: [u8; 32],
    pub consensus_profile_fingerprint: [u8; 32],
    pub logical_height: u64,
    pub consensus_tip_digest: [u8; 32],
    pub ledger_tip_hash: [u8; 32],
    pub state_root: [u8; 32],
    pub total_mined_atoms: u128,
    pub cumulative_chainwork: Uint256,
    pub parent_checkpoint_commitment: [u8; 32],
    pub state_snapshot: Vec<u8>,
    pub target_history: TargetHistoryCheckpoint,
}

impl QzbeCheckpointRecord {
    /// Build an integrity-checked checkpoint from a state and its branch-derived bounded history.
    /// The caller supplies QZBE consensus tip and cumulative work from a previously verified branch.
    pub fn from_state(
        context: &QzbeCheckpointValidationContext<'_>,
        state: &MonetaryLedgerStateV04TransitionCandidate,
        consensus_tip_digest: [u8; 32],
        cumulative_chainwork: Uint256,
        parent_checkpoint_commitment: [u8; 32],
        target_history: TargetHistoryCheckpoint,
    ) -> Result<Self, QzbeCheckpointError> {
        let state_root = state.state_root()?;
        let record = Self {
            network_id: *context.manifest.network_id(),
            genesis_manifest_hash: context.manifest.manifest_hash()?,
            profile_fingerprint: *context.profile.profile_fingerprint(),
            consensus_profile_fingerprint: pow_consensus_profile_fingerprint(context.params)
                .map_err(|_| QzbeCheckpointError::ConsensusMismatch)?,
            logical_height: state.ledger().height(),
            consensus_tip_digest,
            ledger_tip_hash: state.ledger().tip_hash(),
            state_root,
            total_mined_atoms: state.total_mined_atoms(),
            cumulative_chainwork,
            parent_checkpoint_commitment,
            state_snapshot: state.encode_snapshot()?,
            target_history,
        };
        record.validate(context)?;
        Ok(record)
    }

    pub fn validate(
        &self,
        context: &QzbeCheckpointValidationContext<'_>,
    ) -> Result<(), QzbeCheckpointError> {
        context.manifest.validate()?;
        context
            .profile
            .validate_for_manifest(context.manifest)
            .map_err(|_| QzbeCheckpointError::ProfileMismatch)?;
        context
            .params
            .validate()
            .map_err(|_| QzbeCheckpointError::ConsensusMismatch)?;

        if self.network_id.iter().all(|byte| *byte == 0) {
            return Err(QzbeCheckpointError::InvalidContext);
        }
        if self.network_id != *context.manifest.network_id()
            || self.network_id != *context.profile.network_id()
        {
            return Err(QzbeCheckpointError::WrongNetwork);
        }
        if self.genesis_manifest_hash != context.manifest.manifest_hash()? {
            return Err(QzbeCheckpointError::GenesisMismatch);
        }
        if self.profile_fingerprint != *context.profile.profile_fingerprint() {
            return Err(QzbeCheckpointError::ProfileMismatch);
        }
        if self.consensus_profile_fingerprint
            != pow_consensus_profile_fingerprint(context.params)
                .map_err(|_| QzbeCheckpointError::ConsensusMismatch)?
        {
            return Err(QzbeCheckpointError::ConsensusMismatch);
        }
        if self.state_snapshot.is_empty()
            || self.state_snapshot.len() > MAX_ENCODED_V04_PROFILE_BOUND_SNAPSHOT_BYTES
        {
            return Err(QzbeCheckpointError::Oversize);
        }
        let state = MonetaryLedgerStateV04TransitionCandidate::decode_snapshot(
            &self.state_snapshot,
            context.manifest,
            context.profile,
        )?;
        if state.encode_snapshot()?.as_slice() != self.state_snapshot.as_slice()
            || state.ledger().network_id() != self.network_id
            || state.ledger().height() != self.logical_height
            || state.ledger().tip_hash() != self.ledger_tip_hash
            || state.state_root()? != self.state_root
            || state.total_mined_atoms() != self.total_mined_atoms
            || self.target_history.logical_height != self.logical_height
        {
            return Err(QzbeCheckpointError::StateMetadataMismatch);
        }

        let restored_history =
            TargetHistory::from_checkpoint_snapshot(context.params.clone(), &self.target_history)?;
        if restored_history.height() != self.logical_height {
            return Err(QzbeCheckpointError::StateMetadataMismatch);
        }

        if self.logical_height == 0 {
            let trusted_genesis = MonetaryLedgerStateV04TransitionCandidate::from_genesis_manifest(
                context.manifest,
                context.profile,
            )?;
            if state != trusted_genesis
                || self.consensus_tip_digest != self.ledger_tip_hash
                || self.cumulative_chainwork != Uint256::ZERO
                || self.parent_checkpoint_commitment != [0; 32]
            {
                return Err(QzbeCheckpointError::InvalidGenesisCheckpoint);
            }
        } else {
            if self.parent_checkpoint_commitment == [0; 32] {
                return Err(QzbeCheckpointError::InvalidParentCommitment);
            }
            if self.cumulative_chainwork.is_zero() {
                return Err(QzbeCheckpointError::InvalidChainwork);
            }
            if self.consensus_tip_digest == [0; 32] || self.ledger_tip_hash == [0; 32] {
                return Err(QzbeCheckpointError::StateMetadataMismatch);
            }
        }
        Ok(())
    }

    pub fn encode(
        &self,
        context: &QzbeCheckpointValidationContext<'_>,
    ) -> Result<Vec<u8>, QzbeCheckpointError> {
        self.validate(context)?;
        let snapshot_len =
            u32::try_from(self.state_snapshot.len()).map_err(|_| QzbeCheckpointError::Oversize)?;
        let history_count = u32::try_from(self.target_history.entries.len())
            .map_err(|_| QzbeCheckpointError::Oversize)?;
        let history_bytes_len = self
            .target_history
            .entries
            .len()
            .checked_mul(QZBE_CHECKPOINT_HISTORY_ENTRY_BYTES)
            .ok_or(QzbeCheckpointError::Oversize)?;
        let capacity = QZBE_CHECKPOINT_FIXED_PREFIX_BYTES
            .checked_add(self.state_snapshot.len())
            .and_then(|len| len.checked_add(history_bytes_len))
            .and_then(|len| len.checked_add(CHECKSUM_BYTES))
            .ok_or(QzbeCheckpointError::Oversize)?;
        let mut bytes = Vec::with_capacity(capacity);
        bytes.extend_from_slice(&QZBE_CHECKPOINT_MAGIC);
        bytes.extend_from_slice(&QZBE_CHECKPOINT_SCHEMA_VERSION.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes()); // patched canonical total length
        bytes.extend_from_slice(&self.network_id);
        bytes.extend_from_slice(&self.genesis_manifest_hash);
        bytes.extend_from_slice(&self.profile_fingerprint);
        bytes.extend_from_slice(&self.consensus_profile_fingerprint);
        bytes.extend_from_slice(&self.logical_height.to_be_bytes());
        bytes.extend_from_slice(&self.consensus_tip_digest);
        bytes.extend_from_slice(&self.ledger_tip_hash);
        bytes.extend_from_slice(&self.state_root);
        bytes.extend_from_slice(&self.total_mined_atoms.to_be_bytes());
        bytes.extend_from_slice(&self.cumulative_chainwork.to_be_bytes());
        bytes.extend_from_slice(&self.parent_checkpoint_commitment);
        bytes.extend_from_slice(&snapshot_len.to_be_bytes());
        bytes.extend_from_slice(&self.target_history.start_height.to_be_bytes());
        bytes.extend_from_slice(&history_count.to_be_bytes());
        if bytes.len() != QZBE_CHECKPOINT_FIXED_PREFIX_BYTES {
            return Err(QzbeCheckpointError::NonCanonical);
        }
        bytes.extend_from_slice(&self.state_snapshot);
        for entry in &self.target_history.entries {
            bytes.extend_from_slice(&entry.height.to_be_bytes());
            bytes.extend_from_slice(&entry.target.to_be_bytes());
            match entry.timestamp {
                Some(timestamp) => {
                    bytes.push(1);
                    bytes.extend_from_slice(&timestamp.to_be_bytes());
                }
                None => {
                    bytes.push(0);
                    bytes.extend_from_slice(&0u64.to_be_bytes());
                }
            }
        }
        let total_len = bytes
            .len()
            .checked_add(CHECKSUM_BYTES)
            .ok_or(QzbeCheckpointError::Oversize)?;
        if total_len > MAX_QZBE_CHECKPOINT_RECORD_BYTES {
            return Err(QzbeCheckpointError::Oversize);
        }
        let total_len_u32 = u32::try_from(total_len).map_err(|_| QzbeCheckpointError::Oversize)?;
        bytes[8..12].copy_from_slice(&total_len_u32.to_be_bytes());
        let checksum = domain_hash(QZBE_CHECKPOINT_CHECKSUM_DOMAIN, &[&bytes]);
        bytes.extend_from_slice(&checksum);
        Ok(bytes)
    }

    pub fn decode(
        bytes: &[u8],
        context: &QzbeCheckpointValidationContext<'_>,
    ) -> Result<Self, QzbeCheckpointError> {
        if bytes.len() > MAX_QZBE_CHECKPOINT_RECORD_BYTES {
            return Err(QzbeCheckpointError::Oversize);
        }
        if bytes.len() < QZBE_CHECKPOINT_FIXED_PREFIX_BYTES + CHECKSUM_BYTES {
            return Err(QzbeCheckpointError::Malformed);
        }
        if bytes[..4] != QZBE_CHECKPOINT_MAGIC {
            return Err(QzbeCheckpointError::WrongMagic);
        }
        let version = read_u16(bytes, 4)?;
        if version != QZBE_CHECKPOINT_SCHEMA_VERSION {
            return Err(QzbeCheckpointError::UnsupportedVersion(version));
        }
        if read_u16(bytes, 6)? != 0 {
            return Err(QzbeCheckpointError::NonCanonical);
        }
        if read_u32(bytes, 8)? as usize != bytes.len() {
            return Err(QzbeCheckpointError::Malformed);
        }
        let checksum_start = bytes.len() - CHECKSUM_BYTES;
        if bytes[checksum_start..]
            != domain_hash(QZBE_CHECKPOINT_CHECKSUM_DOMAIN, &[&bytes[..checksum_start]])
        {
            return Err(QzbeCheckpointError::ChecksumMismatch);
        }

        let network_id = read_array::<32>(bytes, 12)?;
        let genesis_manifest_hash = read_array::<32>(bytes, 44)?;
        let profile_fingerprint = read_array::<32>(bytes, 76)?;
        let consensus_profile_fingerprint = read_array::<32>(bytes, 108)?;
        let logical_height = read_u64(bytes, 140)?;
        let consensus_tip_digest = read_array::<32>(bytes, 148)?;
        let ledger_tip_hash = read_array::<32>(bytes, 180)?;
        let state_root = read_array::<32>(bytes, 212)?;
        let total_mined_atoms = read_u128(bytes, 244)?;
        let cumulative_chainwork = Uint256::from_be_bytes(read_array::<32>(bytes, 260)?);
        let parent_checkpoint_commitment = read_array::<32>(bytes, 292)?;
        let snapshot_len = read_u32(bytes, 324)? as usize;
        let history_start_height = read_u64(bytes, 328)?;
        let history_count = read_u32(bytes, 336)? as usize;

        let expected_history_count = canonical_history_count(logical_height, context.params)?;
        if history_count != expected_history_count
            || history_count > MAX_TARGET_HISTORY_CHECKPOINT_ENTRIES
        {
            return Err(QzbeCheckpointError::NonCanonical);
        }
        let history_bytes = history_count
            .checked_mul(QZBE_CHECKPOINT_HISTORY_ENTRY_BYTES)
            .ok_or(QzbeCheckpointError::Oversize)?;
        let expected_total = QZBE_CHECKPOINT_FIXED_PREFIX_BYTES
            .checked_add(snapshot_len)
            .and_then(|len| len.checked_add(history_bytes))
            .and_then(|len| len.checked_add(CHECKSUM_BYTES))
            .ok_or(QzbeCheckpointError::Oversize)?;
        if expected_total != bytes.len()
            || snapshot_len == 0
            || snapshot_len > MAX_ENCODED_V04_PROFILE_BOUND_SNAPSHOT_BYTES
        {
            return Err(QzbeCheckpointError::Malformed);
        }

        let snapshot_start = QZBE_CHECKPOINT_FIXED_PREFIX_BYTES;
        let snapshot_end = snapshot_start
            .checked_add(snapshot_len)
            .ok_or(QzbeCheckpointError::Oversize)?;
        let state_snapshot = bytes[snapshot_start..snapshot_end].to_vec();
        let mut entries = Vec::with_capacity(history_count);
        let mut offset = snapshot_end;
        for _ in 0..history_count {
            let height = read_u64(bytes, offset)?;
            offset += 8;
            let target = Uint256::from_be_bytes(read_array::<32>(bytes, offset)?);
            offset += 32;
            let flag = *bytes.get(offset).ok_or(QzbeCheckpointError::Malformed)?;
            offset += 1;
            let timestamp_value = read_u64(bytes, offset)?;
            offset += 8;
            let timestamp = match flag {
                0 if timestamp_value == 0 => None,
                1 => Some(timestamp_value),
                0 => return Err(QzbeCheckpointError::NonCanonical),
                _ => return Err(QzbeCheckpointError::NonCanonical),
            };
            entries.push(TargetHistoryCheckpointEntry {
                height,
                target,
                timestamp,
            });
        }
        if offset != checksum_start {
            return Err(QzbeCheckpointError::Malformed);
        }

        let record = Self {
            network_id,
            genesis_manifest_hash,
            profile_fingerprint,
            consensus_profile_fingerprint,
            logical_height,
            consensus_tip_digest,
            ledger_tip_hash,
            state_root,
            total_mined_atoms,
            cumulative_chainwork,
            parent_checkpoint_commitment,
            state_snapshot,
            target_history: TargetHistoryCheckpoint {
                logical_height,
                start_height: history_start_height,
                entries,
            },
        };
        record.validate(context)?;
        if record.encode(context)?.as_slice() != bytes {
            return Err(QzbeCheckpointError::NonCanonical);
        }
        Ok(record)
    }

    pub fn commitment(
        &self,
        context: &QzbeCheckpointValidationContext<'_>,
    ) -> Result<[u8; 32], QzbeCheckpointError> {
        let encoded = self.encode(context)?;
        Ok(domain_hash(QZBE_CHECKPOINT_COMMITMENT_DOMAIN, &[&encoded]))
    }
}

fn canonical_history_count(
    logical_height: u64,
    params: &ConsensusParameters,
) -> Result<usize, QzbeCheckpointError> {
    params
        .validate()
        .map_err(|_| QzbeCheckpointError::ConsensusMismatch)?;
    let window = params.difficulty_window_blocks;
    if window == 0 || window > MAX_TARGET_HISTORY_CHECKPOINT_ENTRIES as u64 {
        return Err(QzbeCheckpointError::Oversize);
    }
    let count = if logical_height >= window {
        window
    } else {
        logical_height
            .checked_add(1)
            .ok_or(QzbeCheckpointError::Oversize)?
    };
    usize::try_from(count).map_err(|_| QzbeCheckpointError::Oversize)
}

fn domain_hash(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    for part in parts {
        hash.update(part);
    }
    hash.finalize().into()
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], QzbeCheckpointError> {
    bytes
        .get(
            offset
                ..offset
                    .checked_add(N)
                    .ok_or(QzbeCheckpointError::Malformed)?,
        )
        .ok_or(QzbeCheckpointError::Malformed)?
        .try_into()
        .map_err(|_| QzbeCheckpointError::Malformed)
}
fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, QzbeCheckpointError> {
    Ok(u16::from_be_bytes(read_array(bytes, offset)?))
}
fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, QzbeCheckpointError> {
    Ok(u32::from_be_bytes(read_array(bytes, offset)?))
}
fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, QzbeCheckpointError> {
    Ok(u64::from_be_bytes(read_array(bytes, offset)?))
}
fn read_u128(bytes: &[u8], offset: usize) -> Result<u128, QzbeCheckpointError> {
    Ok(u128::from_be_bytes(read_array(bytes, offset)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        monetary_issuance_v04_candidate::V04MiningIssuanceScheduleCandidate,
        monetary_transition_v04_candidate::V04ConsensusProfileCandidate,
    };

    const NETWORK: [u8; 32] = [0x31; 32];
    const OWNER: [u8; 32] = [0xA7; 32];
    const SUBSIDY: u128 = 35_673_515_981;
    const HALVING: u64 = 4_204_800;

    fn fixture() -> (
        GenesisManifestV04,
        V04ConsensusProfileCandidate,
        ConsensusParameters,
        MonetaryLedgerStateV04TransitionCandidate,
    ) {
        let manifest = GenesisManifestV04::new(NETWORK, OWNER).unwrap();
        let schedule = V04MiningIssuanceScheduleCandidate::new(SUBSIDY, HALVING).unwrap();
        let profile =
            V04ConsensusProfileCandidate::from_manifest_and_schedule(&manifest, schedule).unwrap();
        let params = ConsensusParameters::candidate_testnet().unwrap();
        let state =
            MonetaryLedgerStateV04TransitionCandidate::from_genesis_manifest(&manifest, &profile)
                .unwrap();
        (manifest, profile, params, state)
    }

    fn context<'a>(
        manifest: &'a GenesisManifestV04,
        profile: &'a V04ConsensusProfileCandidate,
        params: &'a ConsensusParameters,
    ) -> QzbeCheckpointValidationContext<'a> {
        QzbeCheckpointValidationContext {
            manifest,
            profile,
            params,
        }
    }

    fn genesis_record(
        context: &QzbeCheckpointValidationContext<'_>,
        state: &MonetaryLedgerStateV04TransitionCandidate,
    ) -> QzbeCheckpointRecord {
        let history = TargetHistory::new(context.params.clone())
            .unwrap()
            .checkpoint_snapshot()
            .unwrap();
        QzbeCheckpointRecord::from_state(
            context,
            state,
            state.ledger().tip_hash(),
            Uint256::ZERO,
            [0; 32],
            history,
        )
        .unwrap()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn refresh_checksum(bytes: &mut [u8]) {
        let offset = bytes.len() - CHECKSUM_BYTES;
        let checksum = domain_hash(QZBE_CHECKPOINT_CHECKSUM_DOMAIN, &[&bytes[..offset]]);
        bytes[offset..].copy_from_slice(&checksum);
    }

    #[test]
    fn genesis_checkpoint_roundtrips_and_binds_profile_state_and_empty_chainwork() {
        let (manifest, profile, params, state) = fixture();
        let ctx = context(&manifest, &profile, &params);
        let record = genesis_record(&ctx, &state);
        let encoded = record.encode(&ctx).unwrap();
        assert_eq!(
            hex(&encoded),
            include_str!("../tests/fixtures/cp0419_qzbe_genesis_checkpoint.hex").trim()
        );
        assert_eq!(&encoded[..4], b"QZCP");
        assert_eq!(read_u16(&encoded, 4).unwrap(), 1);
        assert_eq!(read_u16(&encoded, 6).unwrap(), 0);
        assert_eq!(read_u32(&encoded, 8).unwrap() as usize, encoded.len());
        assert!(encoded.len() <= MAX_QZBE_CHECKPOINT_RECORD_BYTES);
        assert_eq!(
            QzbeCheckpointRecord::decode(&encoded, &ctx),
            Ok(record.clone())
        );
        assert_eq!(
            record.commitment(&ctx).unwrap(),
            domain_hash(QZBE_CHECKPOINT_COMMITMENT_DOMAIN, &[&encoded])
        );
    }

    #[test]
    fn non_genesis_checkpoint_roundtrips_after_a_profile_bound_mining_transition() {
        let (manifest, profile, params, genesis) = fixture();
        let ctx = context(&manifest, &profile, &params);
        let block = genesis.build_next_block(1_800_000_000, [0x23; 32]).unwrap();
        let mut child = genesis.clone();
        child.apply_block(&block).unwrap();

        let mut history = TargetHistory::new(params.clone()).unwrap();
        history
            .record_next(1, params.initial_target, 1_800_000_000)
            .unwrap();
        let record = QzbeCheckpointRecord::from_state(
            &ctx,
            &child,
            [0x91; 32],
            Uint256::ONE,
            [0x42; 32],
            history.checkpoint_snapshot().unwrap(),
        )
        .unwrap();
        let encoded = record.encode(&ctx).unwrap();
        assert_eq!(QzbeCheckpointRecord::decode(&encoded, &ctx), Ok(record));
    }

    #[test]
    fn decoder_rejects_versions_flags_checksum_trailing_and_truncated_bytes() {
        let (manifest, profile, params, state) = fixture();
        let ctx = context(&manifest, &profile, &params);
        let encoded = genesis_record(&ctx, &state).encode(&ctx).unwrap();
        assert_eq!(
            QzbeCheckpointRecord::decode(&encoded[..encoded.len() - 1], &ctx),
            Err(QzbeCheckpointError::Malformed)
        );
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            QzbeCheckpointRecord::decode(&trailing, &ctx),
            Err(QzbeCheckpointError::Malformed)
        );
        let mut version = encoded.clone();
        version[5] = 2;
        refresh_checksum(&mut version);
        assert_eq!(
            QzbeCheckpointRecord::decode(&version, &ctx),
            Err(QzbeCheckpointError::UnsupportedVersion(2))
        );
        let mut flags = encoded.clone();
        flags[7] = 1;
        refresh_checksum(&mut flags);
        assert_eq!(
            QzbeCheckpointRecord::decode(&flags, &ctx),
            Err(QzbeCheckpointError::NonCanonical)
        );
        let mut checksum = encoded;
        let last = checksum.len() - 1;
        checksum[last] ^= 1;
        assert_eq!(
            QzbeCheckpointRecord::decode(&checksum, &ctx),
            Err(QzbeCheckpointError::ChecksumMismatch)
        );
    }

    #[test]
    fn decoder_rejects_metadata_profile_and_target_history_mismatch() {
        let (manifest, profile, params, state) = fixture();
        let ctx = context(&manifest, &profile, &params);
        let encoded = genesis_record(&ctx, &state).encode(&ctx).unwrap();

        let mut wrong_root = encoded.clone();
        wrong_root[212] ^= 1;
        refresh_checksum(&mut wrong_root);
        assert_eq!(
            QzbeCheckpointRecord::decode(&wrong_root, &ctx),
            Err(QzbeCheckpointError::StateMetadataMismatch)
        );

        let mut impossible_history_count = encoded.clone();
        impossible_history_count[336..340].copy_from_slice(&2u32.to_be_bytes());
        refresh_checksum(&mut impossible_history_count);
        assert_eq!(
            QzbeCheckpointRecord::decode(&impossible_history_count, &ctx),
            Err(QzbeCheckpointError::NonCanonical)
        );

        let mut bad_history_timestamp = encoded.clone();
        let history_offset =
            QZBE_CHECKPOINT_FIXED_PREFIX_BYTES + state.encode_snapshot().unwrap().len();
        bad_history_timestamp[history_offset + 40] = 1;
        refresh_checksum(&mut bad_history_timestamp);
        assert!(matches!(
            QzbeCheckpointRecord::decode(&bad_history_timestamp, &ctx),
            Err(QzbeCheckpointError::History(_)) | Err(QzbeCheckpointError::NonCanonical)
        ));
    }

    #[test]
    fn bounded_history_checkpoint_restores_exact_default_retarget_at_height_2017() {
        let params = ConsensusParameters::candidate_testnet().unwrap();
        assert_eq!(params.difficulty_window_blocks, 2_016);
        let mut history = TargetHistory::new(params.clone()).unwrap();
        for height in 1..=2_016u64 {
            let target = history.expected_target(height, None).unwrap();
            let timestamp = height * params.target_block_time_secs;
            history.record_next(height, target, timestamp).unwrap();
        }

        let expected_next_target = history.expected_target(2_017, None).unwrap();
        assert_eq!(expected_next_target, params.initial_target);
        let checkpoint = history.checkpoint_snapshot().unwrap();
        assert_eq!(checkpoint.logical_height, 2_016);
        assert_eq!(checkpoint.start_height, 1);
        assert_eq!(checkpoint.entries.len(), 2_016);

        let restored =
            TargetHistory::from_checkpoint_snapshot(params.clone(), &checkpoint).unwrap();
        assert_eq!(restored.height(), 2_016);
        assert_eq!(
            restored.expected_target(2_017, None).unwrap(),
            expected_next_target
        );
    }

    #[test]
    fn non_genesis_checkpoint_requires_parent_commitment_and_chainwork() {
        let (manifest, profile, params, genesis) = fixture();
        let ctx = context(&manifest, &profile, &params);
        let block = genesis.build_next_block(1_800_000_000, [0x23; 32]).unwrap();
        let mut child = genesis.clone();
        child.apply_block(&block).unwrap();
        let mut history = TargetHistory::new(params.clone()).unwrap();
        history
            .record_next(1, params.initial_target, 1_800_000_000)
            .unwrap();
        let target_history = history.checkpoint_snapshot().unwrap();

        assert_eq!(
            QzbeCheckpointRecord::from_state(
                &ctx,
                &child,
                [0x91; 32],
                Uint256::ONE,
                [0; 32],
                target_history.clone()
            ),
            Err(QzbeCheckpointError::InvalidParentCommitment)
        );
        assert_eq!(
            QzbeCheckpointRecord::from_state(
                &ctx,
                &child,
                [0x91; 32],
                Uint256::ZERO,
                [0x42; 32],
                target_history
            ),
            Err(QzbeCheckpointError::InvalidChainwork)
        );
    }
}
