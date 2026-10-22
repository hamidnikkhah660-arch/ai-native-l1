//! Candidate-only binding checks between a PFM5 manifest and a fully replayed PMT4 archive.
//!
//! This validator deliberately supports only a Genesis (height-zero) PCP4 checkpoint with the
//! complete unpruned archive available. It does not prove ancestry from a pruned checkpoint and is
//! not wired into the PFM4 durable store or node startup. It requires a fork-choice archive that
//! has already been reconstructed by consensus replay; a digest set by itself is not ancestry proof.

use crate::{
    consensus::pow_digest,
    private_testnet_checkpoint_candidate::{
        consensus_profile_fingerprint, Pcp4CheckpointRecord, Pcp4ValidationContext,
    },
    private_testnet_monetary_wire::decode_candidate_v4_hybrid_monetary_network_block,
    private_testnet_pfm5_manifest_candidate::{Pfm5CheckpointManifest, Pfm5ManifestError},
    private_testnet_v4_hybrid_fork_choice_candidate::{
        PrivateTestnetV4HybridForkChoice, MAX_V4_HYBRID_FORK_ARCHIVE_BLOCKS,
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pfm5ArchiveBindingError {
    Manifest(Pfm5ManifestError),
    GenesisCheckpointRequired,
    ArchiveTooLarge,
    InvalidArchiveEnvelope,
    ManifestIdentityMismatch,
    BranchSetMismatch,
    CanonicalTipMismatch,
    ProfileMismatch,
}

impl std::fmt::Display for Pfm5ArchiveBindingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Manifest(error) => write!(f, "PFM5 manifest validation failed: {error}"),
            Self::GenesisCheckpointRequired => write!(
                f,
                "candidate PFM5 archive binding currently requires a Genesis checkpoint and full archive"
            ),
            Self::ArchiveTooLarge => write!(f, "replayed PFM5 archive exceeds its block budget"),
            Self::InvalidArchiveEnvelope => {
                write!(f, "replayed PFM5 archive contains an invalid PMT4 envelope")
            }
            Self::ManifestIdentityMismatch => write!(
                f,
                "PFM5 checkpoint identity does not match the replayed archive Genesis"
            ),
            Self::BranchSetMismatch => write!(
                f,
                "PFM5 branch digest set does not exactly match the replayed PMT4 archive"
            ),
            Self::CanonicalTipMismatch => write!(
                f,
                "PFM5 canonical tip does not match the replayed fork-choice result"
            ),
            Self::ProfileMismatch => write!(
                f,
                "PFM5 manifest profile does not match the archive's configured consensus parameters"
            ),
        }
    }
}

impl std::error::Error for Pfm5ArchiveBindingError {}

impl From<Pfm5ManifestError> for Pfm5ArchiveBindingError {
    fn from(value: Pfm5ManifestError) -> Self {
        Self::Manifest(value)
    }
}

/// Validate a PFM5 manifest against a PCP4 Genesis checkpoint and a full, replayed PMT4 archive.
///
/// The manifest's sorted digest list is compared to hashes recomputed from every archive envelope.
/// The checkpoint must decode against the trusted Genesis/profile context, and the canonical tip
/// must equal the result selected by cumulative-work fork choice after replay. The function rejects
/// a non-Genesis checkpoint rather than implying that branch digests prove a pruned suffix's ancestry.
pub fn validate_replayed_genesis_archive(
    manifest: &Pfm5CheckpointManifest,
    checkpoint: &Pcp4CheckpointRecord,
    context: &Pcp4ValidationContext<'_>,
    archive: &PrivateTestnetV4HybridForkChoice,
) -> Result<(), Pfm5ArchiveBindingError> {
    // Reject checkpoint formats needing pruned-ancestry proof before inspecting any dependent
    // manifest metadata. Digest membership cannot authenticate a suffix above a checkpoint.
    if manifest.checkpoint_height != 0 || checkpoint.logical_height != 0 {
        return Err(Pfm5ArchiveBindingError::GenesisCheckpointRequired);
    }
    // encode() checks PFM5 schema, canonical ordering, declared lengths, and manifest shape.
    let _canonical_bytes = manifest.encode()?;
    manifest.validate_checkpoint(checkpoint, context)?;
    if consensus_profile_fingerprint(context.params)
        .map_err(|_| Pfm5ArchiveBindingError::ProfileMismatch)?
        != checkpoint.consensus_profile_fingerprint
        || archive
            .profile_fingerprint()
            .map_err(|_| Pfm5ArchiveBindingError::ProfileMismatch)?
            != checkpoint.consensus_profile_fingerprint
    {
        return Err(Pfm5ArchiveBindingError::ProfileMismatch);
    }
    if archive.expected_manifest_id() != checkpoint.transaction_manifest_id
        || archive.genesis_tip() != checkpoint.consensus_tip_digest
    {
        return Err(Pfm5ArchiveBindingError::ManifestIdentityMismatch);
    }
    if archive.archive_len() > MAX_V4_HYBRID_FORK_ARCHIVE_BLOCKS {
        return Err(Pfm5ArchiveBindingError::ArchiveTooLarge);
    }

    let mut actual_digests = Vec::with_capacity(archive.archive_len());
    for envelope in archive.archive_envelopes_iter() {
        let decoded = decode_candidate_v4_hybrid_monetary_network_block(envelope)
            .map_err(|_| Pfm5ArchiveBindingError::InvalidArchiveEnvelope)?;
        if decoded.header.network_id != *context.network_id || decoded.header.height == 0 {
            return Err(Pfm5ArchiveBindingError::InvalidArchiveEnvelope);
        }
        let digest = pow_digest(&decoded.header, context.params.pow)
            .map_err(|_| Pfm5ArchiveBindingError::InvalidArchiveEnvelope)?;
        actual_digests.push(digest);
    }
    if actual_digests.len() != archive.archive_len() {
        return Err(Pfm5ArchiveBindingError::ArchiveTooLarge);
    }
    actual_digests.sort_unstable();
    if actual_digests.windows(2).any(|pair| pair[0] >= pair[1])
        || actual_digests != manifest.branch_digests
    {
        return Err(Pfm5ArchiveBindingError::BranchSetMismatch);
    }

    let replayed_tip = archive.canonical_chain().chain_tip();
    if manifest.canonical_tip_height != replayed_tip.height
        || manifest.canonical_tip_digest != replayed_tip.tip_hash
    {
        return Err(Pfm5ArchiveBindingError::CanonicalTipMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        consensus::{ConsensusParameters, Uint256},
        private_testnet_checkpoint_candidate::{trusted_genesis_fingerprint, Pcp4CheckpointRecord},
        private_testnet_driver::{TargetHistoryCheckpoint, TargetHistoryCheckpointEntry},
        private_testnet_v4_hybrid_fork_choice_candidate::PrivateTestnetV4HybridForkChoice,
        state_machine::{MonetaryLedgerState, MONETARY_PUBLIC_GOODS_BUDGET_ATOMS},
    };

    fn fixture() -> (
        Pfm5CheckpointManifest,
        Pcp4CheckpointRecord,
        Pcp4ValidationContext<'static>,
        MonetaryLedgerState,
        ConsensusParameters,
        [u8; 32],
    ) {
        let network = Box::leak(Box::new([0x81; 32]));
        let manifest_id = Box::leak(Box::new([0x44; 32]));
        let genesis = MonetaryLedgerState::genesis(
            *network,
            [0x11; 32],
            vec![([0x22; 32], MONETARY_PUBLIC_GOODS_BUDGET_ATOMS as u64)],
        )
        .unwrap();
        let params = ConsensusParameters::candidate_testnet().unwrap();
        let trusted_genesis = Box::leak(Box::new(genesis.clone()));
        let params_ref = Box::leak(Box::new(params.clone()));
        let context = Pcp4ValidationContext {
            network_id: network,
            trusted_genesis,
            params: params_ref,
            active_transaction_manifest_id: manifest_id,
        };
        let checkpoint = Pcp4CheckpointRecord {
            network_id: *network,
            genesis_fingerprint: trusted_genesis_fingerprint(&context).unwrap(),
            consensus_profile_fingerprint: consensus_profile_fingerprint(&params).unwrap(),
            transaction_manifest_id: *manifest_id,
            logical_height: 0,
            consensus_tip_digest: genesis.tip_hash(),
            ledger_tip_hash: genesis.tip_hash(),
            monetary_state_root: genesis.state_root(),
            total_mined_atoms: genesis.total_mined_atoms(),
            cumulative_chainwork: Uint256::ZERO,
            parent_checkpoint_commitment: [0; 32],
            monetary_snapshot: genesis.encode_snapshot().unwrap(),
            target_history: TargetHistoryCheckpoint {
                logical_height: 0,
                start_height: 0,
                entries: vec![TargetHistoryCheckpointEntry {
                    height: 0,
                    target: params.initial_target,
                    timestamp: None,
                }],
            },
        };
        let encoded_checkpoint = checkpoint.encode(&context).unwrap();
        let manifest = Pfm5CheckpointManifest {
            network_id: *network,
            consensus_profile_fingerprint: checkpoint.consensus_profile_fingerprint,
            genesis_fingerprint: checkpoint.genesis_fingerprint,
            generation: 1,
            parent_manifest_commitment: [0; 32],
            checkpoint_height: 0,
            checkpoint_record_commitment: checkpoint.commitment(&context).unwrap(),
            checkpoint_record_len: encoded_checkpoint.len() as u32,
            checkpoint_consensus_tip_digest: checkpoint.consensus_tip_digest,
            checkpoint_ledger_tip_hash: checkpoint.ledger_tip_hash,
            checkpoint_state_root: checkpoint.monetary_state_root,
            checkpoint_total_mined_atoms: checkpoint.total_mined_atoms,
            checkpoint_cumulative_chainwork: checkpoint.cumulative_chainwork,
            canonical_tip_height: 0,
            canonical_tip_digest: checkpoint.consensus_tip_digest,
            branch_digests: Vec::new(),
        };
        (manifest, checkpoint, context, genesis, params, *manifest_id)
    }

    #[test]
    fn pfm5_replay_binding_accepts_matching_full_genesis_archive() {
        let (manifest, checkpoint, context, genesis, params, manifest_id) = fixture();
        let archive = PrivateTestnetV4HybridForkChoice::new(genesis, params, manifest_id).unwrap();
        assert_eq!(
            validate_replayed_genesis_archive(&manifest, &checkpoint, &context, &archive),
            Ok(())
        );
    }

    #[test]
    fn pfm5_replay_binding_rejects_unbacked_branch_digest_and_tip() {
        let (mut manifest, checkpoint, context, genesis, params, manifest_id) = fixture();
        let archive = PrivateTestnetV4HybridForkChoice::new(genesis, params, manifest_id).unwrap();
        manifest.canonical_tip_height = 1;
        manifest.canonical_tip_digest = [0x99; 32];
        manifest.branch_digests = vec![[0x99; 32]];
        assert_eq!(
            validate_replayed_genesis_archive(&manifest, &checkpoint, &context, &archive),
            Err(Pfm5ArchiveBindingError::BranchSetMismatch)
        );
    }

    #[test]
    fn pfm5_replay_binding_rejects_non_genesis_checkpoint_without_ancestry_proof() {
        let (mut manifest, checkpoint, context, genesis, params, manifest_id) = fixture();
        let archive = PrivateTestnetV4HybridForkChoice::new(genesis, params, manifest_id).unwrap();
        manifest.checkpoint_height = 1;
        assert_eq!(
            validate_replayed_genesis_archive(&manifest, &checkpoint, &context, &archive),
            Err(Pfm5ArchiveBindingError::GenesisCheckpointRequired)
        );
    }
}
