//! Candidate-only canonical PFM5 manifest codec for checkpoint-referenced monetary archives.
//!
//! PFM5 is not wired into the PFM4 durable store, node startup, archive replay, fork choice, or
//! reorg. Its record commitments and checksums detect mismatch/corruption but do not establish
//! freshness or anti-rollback without an independently pinned monotonic trust source. The listed
//! branch digests are a canonical set, not a proof of ancestry; archive replay must validate the
//! actual envelopes against the referenced PCP4 checkpoint before trusting the selected tip.

use crate::{
    consensus::Uint256,
    private_testnet_checkpoint_candidate::{
        consensus_profile_fingerprint, Pcp4CheckpointError, Pcp4CheckpointRecord,
        Pcp4ValidationContext, MAX_PCP4_RECORD_BYTES, PCP4_FIXED_RECORD_BYTES,
    },
    private_testnet_v4_hybrid_fork_choice_candidate::MAX_V4_HYBRID_FORK_ARCHIVE_BLOCKS,
};
use sha2::{Digest, Sha256};

pub const PFM5_MAGIC: [u8; 4] = *b"PFM5";
pub const PFM5_SCHEMA_VERSION: u16 = 1;
pub const PFM5_CHECKSUM_DOMAIN: &[u8] = b"AIN1-PFM5-CHECKPOINT-MANIFEST-CHECKSUM-V1\0";
pub const PFM5_COMMITMENT_DOMAIN: &[u8] = b"AIN1-PFM5-CHECKPOINT-MANIFEST-COMMITMENT-V1\0";
const CHECKSUM_BYTES: usize = 32;
/// Includes every fixed-width field, including the branch-digest count, but not branch entries
/// or trailing checksum.
pub const PFM5_FIXED_PREFIX_BYTES: usize = 380;
pub const MAX_PFM5_MANIFEST_BYTES: usize =
    PFM5_FIXED_PREFIX_BYTES + MAX_V4_HYBRID_FORK_ARCHIVE_BLOCKS * 32 + CHECKSUM_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pfm5ManifestError {
    InvalidIdentifier,
    InvalidGeneration,
    InvalidParentLink,
    InvalidCheckpointMetadata,
    CanonicalTipMismatch,
    DuplicateBranchDigest,
    NonCanonical,
    Malformed,
    UnsupportedVersion(u16),
    Oversize,
    ChecksumMismatch,
    Checkpoint(Pcp4CheckpointError),
}

impl std::fmt::Display for Pfm5ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidIdentifier => write!(
                f,
                "PFM5 required network/profile/checkpoint identity is zero"
            ),
            Self::InvalidGeneration => write!(f, "PFM5 generation must be positive"),
            Self::InvalidParentLink => write!(
                f,
                "PFM5 parent manifest commitment is inconsistent with generation"
            ),
            Self::InvalidCheckpointMetadata => write!(
                f,
                "PFM5 checkpoint metadata does not match the referenced PCP4 record"
            ),
            Self::CanonicalTipMismatch => write!(
                f,
                "PFM5 canonical tip does not match checkpoint height or listed branch digests"
            ),
            Self::DuplicateBranchDigest => write!(
                f,
                "PFM5 branch digest set is duplicated or not strictly sorted"
            ),
            Self::NonCanonical => write!(f, "PFM5 record is not canonically encoded"),
            Self::Malformed => write!(f, "PFM5 record is malformed"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported PFM5 schema version {version}")
            }
            Self::Oversize => write!(f, "PFM5 manifest exceeds a hard byte/count limit"),
            Self::ChecksumMismatch => write!(f, "PFM5 checksum mismatch"),
            Self::Checkpoint(error) => write!(f, "referenced PCP4 checkpoint is invalid: {error}"),
        }
    }
}

impl std::error::Error for Pfm5ManifestError {}

impl From<Pcp4CheckpointError> for Pfm5ManifestError {
    fn from(value: Pcp4CheckpointError) -> Self {
        Self::Checkpoint(value)
    }
}

/// Metadata that a future PFM5 durable-store implementation must reconcile against an actual
/// PCP4 record and replayed branch archive before publishing/restoring it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pfm5CheckpointManifest {
    pub network_id: [u8; 32],
    pub consensus_profile_fingerprint: [u8; 32],
    pub genesis_fingerprint: [u8; 32],
    /// Monotonic generation requested by the caller. This field alone does not prevent rollback.
    pub generation: u64,
    /// Zero only for the first manifest (generation 1); otherwise references the prior manifest.
    pub parent_manifest_commitment: [u8; 32],
    pub checkpoint_height: u64,
    pub checkpoint_record_commitment: [u8; 32],
    pub checkpoint_record_len: u32,
    pub checkpoint_consensus_tip_digest: [u8; 32],
    pub checkpoint_ledger_tip_hash: [u8; 32],
    pub checkpoint_state_root: [u8; 32],
    pub checkpoint_total_mined_atoms: u128,
    pub checkpoint_cumulative_chainwork: Uint256,
    pub canonical_tip_height: u64,
    pub canonical_tip_digest: [u8; 32],
    /// Sorted set of retained post-checkpoint envelope PoW digests. This is not ancestry proof.
    pub branch_digests: Vec<[u8; 32]>,
}

impl Pfm5CheckpointManifest {
    /// Validate the canonical structural invariants and emit a deterministic big-endian record.
    pub fn encode(&self) -> Result<Vec<u8>, Pfm5ManifestError> {
        self.validate_shape()?;
        let count =
            u32::try_from(self.branch_digests.len()).map_err(|_| Pfm5ManifestError::Oversize)?;
        let branch_bytes = self
            .branch_digests
            .len()
            .checked_mul(32)
            .ok_or(Pfm5ManifestError::Oversize)?;
        let record_len = PFM5_FIXED_PREFIX_BYTES
            .checked_add(branch_bytes)
            .and_then(|len| len.checked_add(CHECKSUM_BYTES))
            .filter(|len| *len <= MAX_PFM5_MANIFEST_BYTES && *len <= u32::MAX as usize)
            .ok_or(Pfm5ManifestError::Oversize)?;

        let mut bytes = Vec::with_capacity(record_len);
        bytes.extend_from_slice(&PFM5_MAGIC);
        bytes.extend_from_slice(&PFM5_SCHEMA_VERSION.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes()); // Version 1 reserved flags must remain zero.
        bytes.extend_from_slice(&(record_len as u32).to_be_bytes());
        bytes.extend_from_slice(&self.network_id);
        bytes.extend_from_slice(&self.consensus_profile_fingerprint);
        bytes.extend_from_slice(&self.genesis_fingerprint);
        bytes.extend_from_slice(&self.generation.to_be_bytes());
        bytes.extend_from_slice(&self.parent_manifest_commitment);
        bytes.extend_from_slice(&self.checkpoint_height.to_be_bytes());
        bytes.extend_from_slice(&self.checkpoint_record_commitment);
        bytes.extend_from_slice(&self.checkpoint_record_len.to_be_bytes());
        bytes.extend_from_slice(&self.checkpoint_consensus_tip_digest);
        bytes.extend_from_slice(&self.checkpoint_ledger_tip_hash);
        bytes.extend_from_slice(&self.checkpoint_state_root);
        bytes.extend_from_slice(&self.checkpoint_total_mined_atoms.to_be_bytes());
        bytes.extend_from_slice(&self.checkpoint_cumulative_chainwork.to_be_bytes());
        bytes.extend_from_slice(&self.canonical_tip_height.to_be_bytes());
        bytes.extend_from_slice(&self.canonical_tip_digest);
        bytes.extend_from_slice(&count.to_be_bytes());
        for digest in &self.branch_digests {
            bytes.extend_from_slice(digest);
        }
        if bytes.len().checked_add(CHECKSUM_BYTES) != Some(record_len) {
            return Err(Pfm5ManifestError::NonCanonical);
        }
        let checksum = domain_hash(PFM5_CHECKSUM_DOMAIN, &[&bytes]);
        bytes.extend_from_slice(&checksum);
        Ok(bytes)
    }

    /// Decode with size, declared length, checksum, count and canonical-order checks before trusting
    /// the metadata. This does not establish ancestry, provider freshness or anti-rollback.
    pub fn decode(bytes: &[u8]) -> Result<Self, Pfm5ManifestError> {
        if bytes.len() > MAX_PFM5_MANIFEST_BYTES {
            return Err(Pfm5ManifestError::Oversize);
        }
        if bytes.len() < PFM5_FIXED_PREFIX_BYTES + CHECKSUM_BYTES {
            return Err(Pfm5ManifestError::Malformed);
        }
        if bytes.get(..4) != Some(PFM5_MAGIC.as_slice()) {
            return Err(Pfm5ManifestError::Malformed);
        }
        let version = read_u16_at(bytes, 4)?;
        if version != PFM5_SCHEMA_VERSION {
            return Err(Pfm5ManifestError::UnsupportedVersion(version));
        }
        if read_u16_at(bytes, 6)? != 0 {
            return Err(Pfm5ManifestError::NonCanonical);
        }
        if read_u32_at(bytes, 8)? as usize != bytes.len() {
            return Err(Pfm5ManifestError::Malformed);
        }
        let checksum_offset = bytes
            .len()
            .checked_sub(CHECKSUM_BYTES)
            .ok_or(Pfm5ManifestError::Malformed)?;
        let expected_checksum = domain_hash(PFM5_CHECKSUM_DOMAIN, &[&bytes[..checksum_offset]]);
        if bytes[checksum_offset..] != expected_checksum {
            return Err(Pfm5ManifestError::ChecksumMismatch);
        }

        let mut reader = Reader::new(&bytes[..checksum_offset]);
        if reader.read_array::<4>()? != PFM5_MAGIC {
            return Err(Pfm5ManifestError::Malformed);
        }
        let version = reader.read_u16()?;
        if version != PFM5_SCHEMA_VERSION {
            return Err(Pfm5ManifestError::UnsupportedVersion(version));
        }
        if reader.read_u16()? != 0 || reader.read_u32()? as usize != bytes.len() {
            return Err(Pfm5ManifestError::NonCanonical);
        }
        let network_id = reader.read_array::<32>()?;
        let consensus_profile_fingerprint = reader.read_array::<32>()?;
        let genesis_fingerprint = reader.read_array::<32>()?;
        let generation = reader.read_u64()?;
        let parent_manifest_commitment = reader.read_array::<32>()?;
        let checkpoint_height = reader.read_u64()?;
        let checkpoint_record_commitment = reader.read_array::<32>()?;
        let checkpoint_record_len = reader.read_u32()?;
        let checkpoint_consensus_tip_digest = reader.read_array::<32>()?;
        let checkpoint_ledger_tip_hash = reader.read_array::<32>()?;
        let checkpoint_state_root = reader.read_array::<32>()?;
        let checkpoint_total_mined_atoms = reader.read_u128()?;
        let checkpoint_cumulative_chainwork = Uint256::from_be_bytes(reader.read_array::<32>()?);
        let canonical_tip_height = reader.read_u64()?;
        let canonical_tip_digest = reader.read_array::<32>()?;
        let count = reader.read_u32()? as usize;

        if count > MAX_V4_HYBRID_FORK_ARCHIVE_BLOCKS {
            return Err(Pfm5ManifestError::Oversize);
        }
        let expected_len = PFM5_FIXED_PREFIX_BYTES
            .checked_add(count.checked_mul(32).ok_or(Pfm5ManifestError::Oversize)?)
            .and_then(|len| len.checked_add(CHECKSUM_BYTES))
            .ok_or(Pfm5ManifestError::Oversize)?;
        if expected_len != bytes.len() || reader.remaining() != count * 32 {
            return Err(Pfm5ManifestError::Malformed);
        }
        let mut branch_digests = Vec::with_capacity(count);
        for _ in 0..count {
            branch_digests.push(reader.read_array::<32>()?);
        }
        if !reader.is_finished() {
            return Err(Pfm5ManifestError::Malformed);
        }
        let manifest = Self {
            network_id,
            consensus_profile_fingerprint,
            genesis_fingerprint,
            generation,
            parent_manifest_commitment,
            checkpoint_height,
            checkpoint_record_commitment,
            checkpoint_record_len,
            checkpoint_consensus_tip_digest,
            checkpoint_ledger_tip_hash,
            checkpoint_state_root,
            checkpoint_total_mined_atoms,
            checkpoint_cumulative_chainwork,
            canonical_tip_height,
            canonical_tip_digest,
            branch_digests,
        };
        manifest.validate_shape()?;
        Ok(manifest)
    }

    /// Domain-separated identifier for parent-manifest linkage. This is a content commitment,
    /// not an independent trusted high-water mark or signed provider receipt.
    pub fn commitment(&self) -> Result<[u8; 32], Pfm5ManifestError> {
        let encoded = self.encode()?;
        Ok(domain_hash(PFM5_COMMITMENT_DOMAIN, &[&encoded]))
    }

    /// Bind all checkpoint summary fields to the canonical PCP4 record and caller-supplied
    /// configured context. This verifies data correspondence, not proof-of-work ancestry or
    /// whether the checkpoint is the newest trusted generation.
    pub fn validate_checkpoint(
        &self,
        checkpoint: &Pcp4CheckpointRecord,
        context: &Pcp4ValidationContext<'_>,
    ) -> Result<(), Pfm5ManifestError> {
        self.validate_shape()?;
        let checkpoint_bytes = checkpoint.encode(context)?;
        let commitment = checkpoint.commitment(context)?;
        let configured_profile = consensus_profile_fingerprint(context.params)?;
        if self.network_id != *context.network_id
            || self.consensus_profile_fingerprint != configured_profile
            || self.genesis_fingerprint != checkpoint.genesis_fingerprint
            || checkpoint.network_id != self.network_id
            || checkpoint.consensus_profile_fingerprint != self.consensus_profile_fingerprint
            || checkpoint.logical_height != self.checkpoint_height
            || commitment != self.checkpoint_record_commitment
            || checkpoint_bytes.len() != self.checkpoint_record_len as usize
            || checkpoint.consensus_tip_digest != self.checkpoint_consensus_tip_digest
            || checkpoint.ledger_tip_hash != self.checkpoint_ledger_tip_hash
            || checkpoint.monetary_state_root != self.checkpoint_state_root
            || checkpoint.total_mined_atoms != self.checkpoint_total_mined_atoms
            || checkpoint.cumulative_chainwork != self.checkpoint_cumulative_chainwork
        {
            return Err(Pfm5ManifestError::InvalidCheckpointMetadata);
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), Pfm5ManifestError> {
        if self.network_id == [0; 32]
            || self.consensus_profile_fingerprint == [0; 32]
            || self.genesis_fingerprint == [0; 32]
            || self.checkpoint_record_commitment == [0; 32]
        {
            return Err(Pfm5ManifestError::InvalidIdentifier);
        }
        if self.generation == 0 {
            return Err(Pfm5ManifestError::InvalidGeneration);
        }
        if (self.generation == 1) != (self.parent_manifest_commitment == [0; 32]) {
            return Err(Pfm5ManifestError::InvalidParentLink);
        }
        if self.checkpoint_record_len as usize > MAX_PCP4_RECORD_BYTES
            || (self.checkpoint_record_len as usize) < PCP4_FIXED_RECORD_BYTES
            || self.branch_digests.len() > MAX_V4_HYBRID_FORK_ARCHIVE_BLOCKS
        {
            return Err(Pfm5ManifestError::Oversize);
        }
        if self.canonical_tip_height < self.checkpoint_height {
            return Err(Pfm5ManifestError::CanonicalTipMismatch);
        }
        if self
            .branch_digests
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(Pfm5ManifestError::DuplicateBranchDigest);
        }
        if self.canonical_tip_height == self.checkpoint_height {
            if self.canonical_tip_digest != self.checkpoint_consensus_tip_digest {
                return Err(Pfm5ManifestError::CanonicalTipMismatch);
            }
        } else if self
            .branch_digests
            .binary_search(&self.canonical_tip_digest)
            .is_err()
        {
            return Err(Pfm5ManifestError::CanonicalTipMismatch);
        }
        if self
            .branch_digests
            .contains(&self.checkpoint_consensus_tip_digest)
        {
            return Err(Pfm5ManifestError::CanonicalTipMismatch);
        }
        if self
            .branch_digests
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(Pfm5ManifestError::DuplicateBranchDigest);
        }
        Ok(())
    }
}

fn domain_hash(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn read_u16_at(bytes: &[u8], offset: usize) -> Result<u16, Pfm5ManifestError> {
    let field = bytes
        .get(offset..offset + 2)
        .ok_or(Pfm5ManifestError::Malformed)?;
    Ok(u16::from_be_bytes(
        field.try_into().map_err(|_| Pfm5ManifestError::Malformed)?,
    ))
}

fn read_u32_at(bytes: &[u8], offset: usize) -> Result<u32, Pfm5ManifestError> {
    let field = bytes
        .get(offset..offset + 4)
        .ok_or(Pfm5ManifestError::Malformed)?;
    Ok(u32::from_be_bytes(
        field.try_into().map_err(|_| Pfm5ManifestError::Malformed)?,
    ))
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], Pfm5ManifestError> {
        let end = self
            .position
            .checked_add(count)
            .ok_or(Pfm5ManifestError::Malformed)?;
        let slice = self
            .bytes
            .get(self.position..end)
            .ok_or(Pfm5ManifestError::Malformed)?;
        self.position = end;
        Ok(slice)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], Pfm5ManifestError> {
        self.take(N)?
            .try_into()
            .map_err(|_| Pfm5ManifestError::Malformed)
    }

    fn read_u16(&mut self) -> Result<u16, Pfm5ManifestError> {
        Ok(u16::from_be_bytes(self.read_array::<2>()?))
    }

    fn read_u32(&mut self) -> Result<u32, Pfm5ManifestError> {
        Ok(u32::from_be_bytes(self.read_array::<4>()?))
    }

    fn read_u64(&mut self) -> Result<u64, Pfm5ManifestError> {
        Ok(u64::from_be_bytes(self.read_array::<8>()?))
    }

    fn read_u128(&mut self) -> Result<u128, Pfm5ManifestError> {
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
    use crate::{
        consensus::ConsensusParameters,
        private_testnet_checkpoint_candidate::{trusted_genesis_fingerprint, Pcp4CheckpointRecord},
        private_testnet_driver::{PrivateTestnetChain, TargetHistoryCheckpoint},
        state_machine::{MonetaryLedgerState, MONETARY_PUBLIC_GOODS_BUDGET_ATOMS},
    };

    fn genesis(network: [u8; 32]) -> MonetaryLedgerState {
        MonetaryLedgerState::genesis(
            network,
            [0x11; 32],
            vec![([0x22; 32], MONETARY_PUBLIC_GOODS_BUDGET_ATOMS as u64)],
        )
        .unwrap()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
    fn manifest_and_context() -> (
        Pfm5CheckpointManifest,
        Pcp4CheckpointRecord,
        [u8; 32],
        MonetaryLedgerState,
        ConsensusParameters,
        [u8; 32],
    ) {
        let network = [0x81; 32];
        let genesis = genesis(network);
        let params = ConsensusParameters::candidate_testnet().unwrap();
        let manifest_id = [0x44; 32];
        let context = Pcp4ValidationContext {
            network_id: &network,
            trusted_genesis: &genesis,
            params: &params,
            active_transaction_manifest_id: &manifest_id,
        };
        let checkpoint = Pcp4CheckpointRecord {
            network_id: network,
            genesis_fingerprint: trusted_genesis_fingerprint(&context).unwrap(),
            consensus_profile_fingerprint: consensus_profile_fingerprint(&params).unwrap(),
            transaction_manifest_id: manifest_id,
            logical_height: 0,
            consensus_tip_digest: genesis.tip_hash(),
            ledger_tip_hash: genesis.tip_hash(),
            monetary_state_root: genesis.state_root(),
            total_mined_atoms: 0,
            cumulative_chainwork: Uint256::ZERO,
            parent_checkpoint_commitment: [0; 32],
            monetary_snapshot: genesis.encode_snapshot().unwrap(),
            target_history: TargetHistoryCheckpoint {
                logical_height: 0,
                start_height: 0,
                entries: vec![
                    crate::private_testnet_driver::TargetHistoryCheckpointEntry {
                        height: 0,
                        target: params.initial_target,
                        timestamp: None,
                    },
                ],
            },
        };
        let encoded = checkpoint.encode(&context).unwrap();
        let commitment = checkpoint.commitment(&context).unwrap();
        let manifest = Pfm5CheckpointManifest {
            network_id: network,
            consensus_profile_fingerprint: checkpoint.consensus_profile_fingerprint,
            genesis_fingerprint: checkpoint.genesis_fingerprint,
            generation: 1,
            parent_manifest_commitment: [0; 32],
            checkpoint_height: 0,
            checkpoint_record_commitment: commitment,
            checkpoint_record_len: encoded.len() as u32,
            checkpoint_consensus_tip_digest: checkpoint.consensus_tip_digest,
            checkpoint_ledger_tip_hash: checkpoint.ledger_tip_hash,
            checkpoint_state_root: checkpoint.monetary_state_root,
            checkpoint_total_mined_atoms: checkpoint.total_mined_atoms,
            checkpoint_cumulative_chainwork: checkpoint.cumulative_chainwork,
            canonical_tip_height: 0,
            canonical_tip_digest: checkpoint.consensus_tip_digest,
            branch_digests: Vec::new(),
        };
        (manifest, checkpoint, network, genesis, params, manifest_id)
    }

    #[test]
    fn pfm5_checkpoint_restore_requires_external_anchor_and_restores_genesis_baseline() {
        let (manifest, checkpoint, network, genesis, params, manifest_id) = manifest_and_context();
        let context = Pcp4ValidationContext {
            network_id: &network,
            trusted_genesis: &genesis,
            params: &params,
            active_transaction_manifest_id: &manifest_id,
        };
        let anchor = manifest.commitment().unwrap();
        let restored = PrivateTestnetChain::restore_from_pfm5_checkpoint(
            &manifest,
            &checkpoint,
            &context,
            anchor,
            1,
            0,
        )
        .unwrap();
        assert_eq!(restored.chain_tip().height, checkpoint.logical_height);
        assert_eq!(
            restored.chain_tip().tip_hash,
            checkpoint.consensus_tip_digest
        );
        assert_eq!(restored.cumulative_work(), checkpoint.cumulative_chainwork);
        assert_eq!(
            restored.monetary_state().unwrap().state_root(),
            checkpoint.monetary_state_root
        );
        assert_eq!(
            restored.target_history().checkpoint_snapshot().unwrap(),
            checkpoint.target_history
        );

        assert_eq!(
            PrivateTestnetChain::restore_from_pfm5_checkpoint(
                &manifest, &checkpoint, &context, [0; 32], 1, 0,
            ),
            Err(crate::private_testnet_driver::Pfm5CheckpointRestoreError::MissingTrustedManifestAnchor)
        );
        assert_eq!(
            PrivateTestnetChain::restore_from_pfm5_checkpoint(
                &manifest,
                &checkpoint,
                &context,
                [0x55; 32],
                1,
                0,
            ),
            Err(crate::private_testnet_driver::Pfm5CheckpointRestoreError::ManifestAnchorMismatch)
        );
        assert_eq!(
            PrivateTestnetChain::restore_from_pfm5_checkpoint(
                &manifest, &checkpoint, &context, anchor, 2, 0,
            ),
            Err(crate::private_testnet_driver::Pfm5CheckpointRestoreError::ManifestGenerationRollback)
        );
        assert_eq!(
            PrivateTestnetChain::restore_from_pfm5_checkpoint(
                &manifest,
                &checkpoint,
                &context,
                anchor,
                1,
                1,
            ),
            Err(
                crate::private_testnet_driver::Pfm5CheckpointRestoreError::CheckpointHeightRollback
            )
        );
    }

    #[test]
    fn pfm5_checkpoint_restore_refuses_manifests_that_need_post_checkpoint_replay() {
        let (mut manifest, checkpoint, network, genesis, params, manifest_id) =
            manifest_and_context();
        let context = Pcp4ValidationContext {
            network_id: &network,
            trusted_genesis: &genesis,
            params: &params,
            active_transaction_manifest_id: &manifest_id,
        };
        manifest.canonical_tip_height = 1;
        manifest.canonical_tip_digest = [0x37; 32];
        manifest.branch_digests = vec![[0x37; 32]];
        let anchor = manifest.commitment().unwrap();
        assert_eq!(
            PrivateTestnetChain::restore_from_pfm5_checkpoint(
                &manifest, &checkpoint, &context, anchor, 1, 0,
            ),
            Err(crate::private_testnet_driver::Pfm5CheckpointRestoreError::ManifestRequiresArchiveReplay)
        );
    }

    #[test]
    fn pfm5_genesis_manifest_roundtrips_and_binds_checkpoint_record() {
        let (manifest, checkpoint, network, genesis, params, manifest_id) = manifest_and_context();
        let context = Pcp4ValidationContext {
            network_id: &network,
            trusted_genesis: &genesis,
            params: &params,
            active_transaction_manifest_id: &manifest_id,
        };
        let encoded = manifest.encode().unwrap();
        assert_eq!(
            hex(&encoded),
            include_str!("../tests/fixtures/cp0386_pfm5_genesis_manifest.hex").trim()
        );
        assert_eq!(&encoded[..4], b"PFM5");
        assert_eq!(
            Pfm5CheckpointManifest::decode(&encoded),
            Ok(manifest.clone())
        );
        assert_eq!(manifest.validate_checkpoint(&checkpoint, &context), Ok(()));
        assert_eq!(
            manifest.commitment().unwrap(),
            domain_hash(PFM5_COMMITMENT_DOMAIN, &[&encoded])
        );
    }

    #[test]
    fn pfm5_descendant_tip_requires_listed_digest_and_monotonic_parent_link() {
        let (mut manifest, _, _, _, _, _) = manifest_and_context();
        let original = manifest.clone();
        manifest.generation = 2;
        manifest.parent_manifest_commitment = [0x77; 32];
        manifest.canonical_tip_height = 2;
        manifest.canonical_tip_digest = [0x33; 32];
        manifest.branch_digests = vec![[0x22; 32], [0x33; 32]];
        assert!(manifest.encode().is_ok());
        let mut missing_tip = manifest.clone();
        missing_tip.branch_digests.pop();
        assert_eq!(
            missing_tip.encode(),
            Err(Pfm5ManifestError::CanonicalTipMismatch)
        );
        let mut bad_parent = manifest.clone();
        bad_parent.parent_manifest_commitment = [0; 32];
        assert_eq!(
            bad_parent.encode(),
            Err(Pfm5ManifestError::InvalidParentLink)
        );
        assert_eq!(original.generation, 1);
    }

    #[test]
    fn pfm5_rejects_malformed_versions_flags_checksums_and_trailing_data() {
        let (manifest, _, _, _, _, _) = manifest_and_context();
        let encoded = manifest.encode().unwrap();
        assert_eq!(
            Pfm5CheckpointManifest::decode(&encoded[..encoded.len() - 1]),
            Err(Pfm5ManifestError::Malformed)
        );
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            Pfm5CheckpointManifest::decode(&trailing),
            Err(Pfm5ManifestError::Malformed)
        );
        let mut version = encoded.clone();
        version[5] = 2;
        refresh_checksum(&mut version);
        assert_eq!(
            Pfm5CheckpointManifest::decode(&version),
            Err(Pfm5ManifestError::UnsupportedVersion(2))
        );
        let mut flags = encoded.clone();
        flags[7] = 1;
        refresh_checksum(&mut flags);
        assert_eq!(
            Pfm5CheckpointManifest::decode(&flags),
            Err(Pfm5ManifestError::NonCanonical)
        );
        let mut checksum = encoded;
        let last = checksum.len() - 1;
        checksum[last] ^= 0x80;
        assert_eq!(
            Pfm5CheckpointManifest::decode(&checksum),
            Err(Pfm5ManifestError::ChecksumMismatch)
        );
    }

    #[test]
    fn pfm5_rejects_noncanonical_digest_sets_and_oversized_count_before_allocation() {
        let (manifest, _, _, _, _, _) = manifest_and_context();
        let mut duplicate = manifest.clone();
        duplicate.branch_digests = vec![[0x21; 32], [0x21; 32]];
        duplicate.canonical_tip_height = 1;
        duplicate.canonical_tip_digest = [0x21; 32];
        assert_eq!(
            duplicate.encode(),
            Err(Pfm5ManifestError::DuplicateBranchDigest)
        );
        let mut unsorted = manifest.clone();
        unsorted.branch_digests = vec![[0x22; 32], [0x11; 32]];
        unsorted.canonical_tip_height = 1;
        unsorted.canonical_tip_digest = [0x22; 32];
        assert_eq!(
            unsorted.encode(),
            Err(Pfm5ManifestError::DuplicateBranchDigest)
        );

        let encoded = manifest.encode().unwrap();
        // The branch count sits at the end of the 380-byte fixed prefix.
        let mut oversized = encoded;
        oversized[376..380]
            .copy_from_slice(&((MAX_V4_HYBRID_FORK_ARCHIVE_BLOCKS as u32) + 1).to_be_bytes());
        refresh_checksum(&mut oversized);
        assert_eq!(
            Pfm5CheckpointManifest::decode(&oversized),
            Err(Pfm5ManifestError::Oversize)
        );
    }

    #[test]
    fn pfm5_checkpoint_binding_rejects_mutated_root_total_or_record_commitment() {
        let (manifest, checkpoint, network, genesis, params, manifest_id) = manifest_and_context();
        let context = Pcp4ValidationContext {
            network_id: &network,
            trusted_genesis: &genesis,
            params: &params,
            active_transaction_manifest_id: &manifest_id,
        };
        let mut bad_root = manifest.clone();
        bad_root.checkpoint_state_root[0] ^= 1;
        assert_eq!(
            bad_root.validate_checkpoint(&checkpoint, &context),
            Err(Pfm5ManifestError::InvalidCheckpointMetadata)
        );
        let mut bad_total = manifest.clone();
        bad_total.checkpoint_total_mined_atoms = 1;
        assert_eq!(
            bad_total.validate_checkpoint(&checkpoint, &context),
            Err(Pfm5ManifestError::InvalidCheckpointMetadata)
        );
        let mut bad_commitment = manifest;
        bad_commitment.checkpoint_record_commitment[0] ^= 1;
        assert_eq!(
            bad_commitment.validate_checkpoint(&checkpoint, &context),
            Err(Pfm5ManifestError::InvalidCheckpointMetadata)
        );
    }

    fn refresh_checksum(bytes: &mut [u8]) {
        let offset = bytes.len() - CHECKSUM_BYTES;
        let checksum = domain_hash(PFM5_CHECKSUM_DOMAIN, &[&bytes[..offset]]);
        bytes[offset..].copy_from_slice(&checksum);
    }
}
