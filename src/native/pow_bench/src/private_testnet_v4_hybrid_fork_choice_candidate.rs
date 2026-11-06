//! Separate candidate-only MBK4/TXN4 fork choice and deterministic replay.
//! PMT3/MBK3 archives remain strictly separate; activation still requires a PFM4 durable store
//! and standard-node integration. The active manifest and ML-DSA verifier are explicit inputs.
use crate::{
    chain_admission::ReferenceTimeProvider,
    consensus::{pow_digest, ConsensusError, ConsensusParameters},
    private_testnet_checkpoint_candidate::{Pcp4CheckpointRecord, Pcp4ValidationContext},
    private_testnet_driver::{Pfm5CheckpointRestoreError, PrivateTestnetChain},
    private_testnet_monetary_wire::{
        decode_candidate_v4_hybrid_monetary_network_block, V4HybridMonetaryWireError,
        MAX_PRIVATE_TESTNET_V4_HYBRID_MONETARY_ENVELOPE_BYTES,
    },
    private_testnet_pfm5_manifest_candidate::{Pfm5CheckpointManifest, Pfm5ManifestError},
    state_machine::MonetaryLedgerState,
    v4_account_identity_candidate::MlDsa65Verifier,
};
use std::{cmp::Ordering, collections::BTreeMap};

pub const MAX_V4_HYBRID_FORK_ARCHIVE_BLOCKS: usize = 4_096;
/// Maximum retained/reorgable depth relative to a trusted Genesis or checkpoint baseline.
pub const MAX_V4_HYBRID_FORK_BRANCH_DEPTH: u64 = 1_024;
/// Compatibility alias; this now means branch depth relative to the selected baseline.
pub const MAX_V4_HYBRID_FORK_ARCHIVE_HEIGHT: u64 = MAX_V4_HYBRID_FORK_BRANCH_DEPTH;
/// Aggregate hard ceiling for retained PMT4 branch envelopes in this candidate store.
pub const MAX_V4_HYBRID_FORK_ARCHIVE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum V4HybridForkChoiceError {
    Wire(V4HybridMonetaryWireError),
    Consensus(crate::private_testnet_consensus::PrivateConsensusError),
    InvalidPow(ConsensusError),
    UnknownParent,
    DuplicateDigestConflict,
    DigestMismatch,
    ArchiveCapacityExceeded,
    ArchiveExportLimitExceeded,
    BranchHeightExceeded,
    ReplayIncomplete,
    ManifestMismatch,
    ArchiveByteLimitExceeded,
    CheckpointRestore(Pfm5CheckpointRestoreError),
    Pfm5Manifest(Pfm5ManifestError),
    BranchSetMismatch,
    CanonicalTipMismatch,
}

impl std::fmt::Display for V4HybridForkChoiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Wire(error) => write!(f, "PMT4 hybrid candidate rejected: {error}"),
            Self::Consensus(error) => write!(f, "MBK4 hybrid consensus failed: {error}"),
            Self::InvalidPow(error) => write!(f, "PMT4 proof of work rejected: {error}"),
            Self::UnknownParent => {
                write!(f, "PMT4 candidate references an unknown consensus parent")
            }
            Self::DuplicateDigestConflict => {
                write!(f, "same V4 PoW digest has different PMT4 bytes")
            }
            Self::DigestMismatch => {
                write!(f, "replayed MBK4 branch tip differs from its PoW digest")
            }
            Self::ArchiveCapacityExceeded => {
                write!(f, "V4 hybrid fork archive block limit exceeded")
            }
            Self::ArchiveExportLimitExceeded => {
                write!(f, "V4 hybrid archive export budget exceeded")
            }
            Self::BranchHeightExceeded => write!(f, "V4 hybrid branch height limit exceeded"),
            Self::ReplayIncomplete => {
                write!(f, "PMT4 replay did not consume every persisted block")
            }
            Self::ManifestMismatch => write!(f, "PMT4 branch does not match the active manifest"),
            Self::ArchiveByteLimitExceeded => {
                write!(
                    f,
                    "PMT4 retained branch archive exceeds its aggregate byte budget"
                )
            }
            Self::CheckpointRestore(error) => {
                write!(f, "PFM5 checkpoint restore rejected: {error}")
            }
            Self::Pfm5Manifest(error) => write!(f, "PFM5 manifest rejected: {error}"),
            Self::BranchSetMismatch => write!(
                f,
                "PFM5 branch digest set differs from the exact replay input"
            ),
            Self::CanonicalTipMismatch => {
                write!(f, "PFM5 canonical tip differs from checkpoint-based replay")
            }
        }
    }
}
impl std::error::Error for V4HybridForkChoiceError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V4HybridForkChoiceOutcome {
    pub block_digest: [u8; 32],
    pub previous_canonical_tip: [u8; 32],
    pub canonical_tip: [u8; 32],
    pub previous_height: u64,
    pub canonical_height: u64,
    pub canonical_changed: bool,
    pub reorg_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredV4HybridBranch {
    envelope: Vec<u8>,
    chain: PrivateTestnetChain,
}

/// Bounded PMT4 branch graph; no PMT3 envelope is accepted here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateTestnetV4HybridForkChoice {
    /// State at the trusted branch-graph base (Genesis for the original path, PCP4 for checkpoint replay).
    genesis: MonetaryLedgerState,
    base_chain: PrivateTestnetChain,
    params: ConsensusParameters,
    expected_manifest_id: [u8; 32],
    /// Consensus digest at the branch-graph base, not necessarily logical height zero.
    genesis_tip: [u8; 32],
    canonical: PrivateTestnetChain,
    branches: BTreeMap<[u8; 32], StoredV4HybridBranch>,
    archive_bytes: usize,
    reorg_count: u64,
}

impl PrivateTestnetV4HybridForkChoice {
    pub fn new(
        genesis: MonetaryLedgerState,
        params: ConsensusParameters,
        expected_manifest_id: [u8; 32],
    ) -> Result<Self, V4HybridForkChoiceError> {
        params
            .validate_monetary_execution_compatibility()
            .map_err(V4HybridForkChoiceError::InvalidPow)?;
        if expected_manifest_id.iter().all(|byte| *byte == 0) {
            return Err(V4HybridForkChoiceError::ReplayIncomplete);
        }
        let canonical = PrivateTestnetChain::new_monetary(genesis.clone(), params.clone())
            .map_err(V4HybridForkChoiceError::InvalidPow)?;
        let genesis_tip = canonical.chain_tip().tip_hash;
        Ok(Self {
            genesis,
            base_chain: canonical.clone(),
            params,
            expected_manifest_id,
            genesis_tip,
            canonical,
            branches: BTreeMap::new(),
            archive_bytes: 0,
            reorg_count: 0,
        })
    }

    pub fn expected_manifest_id(&self) -> [u8; 32] {
        self.expected_manifest_id
    }

    /// Configured consensus parameters used to validate every replayed branch.
    pub fn params(&self) -> &ConsensusParameters {
        &self.params
    }

    /// Fingerprint of the configured consensus profile for checkpoint/archive binding.
    pub fn profile_fingerprint(
        &self,
    ) -> Result<[u8; 32], crate::private_testnet_checkpoint_candidate::Pcp4CheckpointError> {
        crate::private_testnet_checkpoint_candidate::consensus_profile_fingerprint(&self.params)
    }
    pub fn canonical_chain(&self) -> &PrivateTestnetChain {
        &self.canonical
    }
    /// Consensus tip that roots this graph. In checkpoint mode this is the authenticated PCP4 tip,
    /// not the original height-zero Genesis digest.
    pub fn base_tip(&self) -> [u8; 32] {
        self.genesis_tip
    }

    /// Compatibility accessor for older Genesis-rooted callers; checkpoint mode returns its base tip.
    pub fn genesis_tip(&self) -> [u8; 32] {
        self.base_tip()
    }
    pub fn reorg_count(&self) -> u64 {
        self.reorg_count
    }
    pub fn archive_len(&self) -> usize {
        self.branches.len()
    }

    pub fn archive_envelopes(&self) -> Vec<Vec<u8>> {
        self.branches
            .values()
            .map(|branch| branch.envelope.clone())
            .collect()
    }

    pub fn archive_envelopes_iter(&self) -> impl Iterator<Item = &[u8]> + '_ {
        self.branches
            .values()
            .map(|branch| branch.envelope.as_slice())
    }

    pub fn archive_envelopes_bounded(
        &self,
        max_blocks: usize,
        max_bytes: usize,
    ) -> Result<Vec<Vec<u8>>, V4HybridForkChoiceError> {
        if self.branches.len() > max_blocks {
            return Err(V4HybridForkChoiceError::ArchiveExportLimitExceeded);
        }
        let mut total = 0usize;
        for branch in self.branches.values() {
            total = total
                .checked_add(branch.envelope.len())
                .ok_or(V4HybridForkChoiceError::ArchiveExportLimitExceeded)?;
            if total > max_bytes {
                return Err(V4HybridForkChoiceError::ArchiveExportLimitExceeded);
            }
        }
        Ok(self.archive_envelopes())
    }

    pub fn branch_chain(&self, tip: &[u8; 32]) -> Option<&PrivateTestnetChain> {
        self.branches.get(tip).map(|branch| &branch.chain)
    }

    pub fn insert_encoded<V: MlDsa65Verifier>(
        &mut self,
        envelope: &[u8],
        verifier: &V,
        clock: &dyn ReferenceTimeProvider,
    ) -> Result<V4HybridForkChoiceOutcome, V4HybridForkChoiceError> {
        self.insert_encoded_inner(envelope, verifier, Some(clock))
    }

    fn insert_encoded_inner<V: MlDsa65Verifier>(
        &mut self,
        envelope: &[u8],
        verifier: &V,
        live_clock: Option<&dyn ReferenceTimeProvider>,
    ) -> Result<V4HybridForkChoiceOutcome, V4HybridForkChoiceError> {
        let candidate = decode_candidate_v4_hybrid_monetary_network_block(envelope)
            .map_err(V4HybridForkChoiceError::Wire)?;
        let base_height = self.base_chain.chain_tip().height;
        let branch_depth = candidate
            .header
            .height
            .checked_sub(base_height)
            .ok_or(V4HybridForkChoiceError::BranchHeightExceeded)?;
        if branch_depth == 0 || branch_depth > MAX_V4_HYBRID_FORK_BRANCH_DEPTH {
            return Err(V4HybridForkChoiceError::BranchHeightExceeded);
        }
        if candidate
            .block
            .transactions
            .iter()
            .any(|tx| tx.authorization.manifest_id != self.expected_manifest_id)
        {
            return Err(V4HybridForkChoiceError::ManifestMismatch);
        }
        let digest = pow_digest(&candidate.header, self.params.pow)
            .map_err(V4HybridForkChoiceError::InvalidPow)?;
        if let Some(existing) = self.branches.get(&digest) {
            if existing.envelope.as_slice() != envelope {
                return Err(V4HybridForkChoiceError::DuplicateDigestConflict);
            }
            let tip = self.canonical.chain_tip();
            return Ok(V4HybridForkChoiceOutcome {
                block_digest: digest,
                previous_canonical_tip: tip.tip_hash,
                canonical_tip: tip.tip_hash,
                previous_height: tip.height,
                canonical_height: tip.height,
                canonical_changed: false,
                reorg_count: self.reorg_count,
            });
        }
        if self.branches.len() >= MAX_V4_HYBRID_FORK_ARCHIVE_BLOCKS {
            return Err(V4HybridForkChoiceError::ArchiveCapacityExceeded);
        }
        if envelope.len() > MAX_PRIVATE_TESTNET_V4_HYBRID_MONETARY_ENVELOPE_BYTES {
            return Err(V4HybridForkChoiceError::Wire(
                V4HybridMonetaryWireError::Oversize,
            ));
        }
        let next_archive_bytes = self
            .archive_bytes
            .checked_add(envelope.len())
            .filter(|bytes| *bytes <= MAX_V4_HYBRID_FORK_ARCHIVE_BYTES)
            .ok_or(V4HybridForkChoiceError::ArchiveByteLimitExceeded)?;

        let parent_tip = candidate.header.previous_consensus_hash;
        let mut parent_chain = if parent_tip == self.genesis_tip {
            self.base_chain.clone()
        } else {
            self.branches
                .get(&parent_tip)
                .map(|branch| branch.chain.clone())
                .ok_or(V4HybridForkChoiceError::UnknownParent)?
        };
        let result = match live_clock {
            Some(clock) => parent_chain.append_v4_hybrid_monetary_live(
                &candidate.block,
                &candidate.header,
                None,
                &self.expected_manifest_id,
                verifier,
                clock,
            ),
            None => parent_chain.append_v4_hybrid_monetary_historical(
                &candidate.block,
                &candidate.header,
                None,
                &self.expected_manifest_id,
                verifier,
            ),
        };
        result.map_err(V4HybridForkChoiceError::Consensus)?;
        if parent_chain.chain_tip().tip_hash != digest {
            return Err(V4HybridForkChoiceError::DigestMismatch);
        }

        let previous = self.canonical.chain_tip();
        self.branches.insert(
            digest,
            StoredV4HybridBranch {
                envelope: envelope.to_vec(),
                chain: parent_chain,
            },
        );
        self.archive_bytes = next_archive_bytes;
        let (best_tip, best_chain) = self.select_best_tip();
        if best_tip != previous.tip_hash {
            if previous.tip_hash != self.genesis_tip
                && !self.is_ancestor(previous.tip_hash, best_tip)
            {
                self.reorg_count = self.reorg_count.saturating_add(1);
            }
            self.canonical = best_chain;
        }
        let tip = self.canonical.chain_tip();
        Ok(V4HybridForkChoiceOutcome {
            block_digest: digest,
            previous_canonical_tip: previous.tip_hash,
            canonical_tip: tip.tip_hash,
            previous_height: previous.height,
            canonical_height: tip.height,
            canonical_changed: previous.tip_hash != tip.tip_hash,
            reorg_count: self.reorg_count,
        })
    }

    fn select_best_tip(&self) -> ([u8; 32], PrivateTestnetChain) {
        let mut best_tip = self.genesis_tip;
        let mut best_chain = self.base_chain.clone();
        for (digest, branch) in &self.branches {
            if branch.chain.compare_to(&best_chain) == Ordering::Greater {
                best_tip = *digest;
                best_chain = branch.chain.clone();
            }
        }
        (best_tip, best_chain)
    }

    fn is_ancestor(&self, ancestor: [u8; 32], mut tip: [u8; 32]) -> bool {
        if ancestor == self.genesis_tip {
            return true;
        }
        for _ in 0..=MAX_V4_HYBRID_FORK_ARCHIVE_HEIGHT {
            if tip == ancestor {
                return true;
            }
            if tip == self.genesis_tip {
                return false;
            }
            let Some(branch) = self.branches.get(&tip) else {
                return false;
            };
            tip = decode_candidate_v4_hybrid_monetary_network_block(&branch.envelope)
                .map(|decoded| decoded.header.previous_consensus_hash)
                .unwrap_or([0; 32]);
        }
        false
    }

    pub fn rebuild_from_envelopes<V: MlDsa65Verifier>(
        genesis: MonetaryLedgerState,
        params: ConsensusParameters,
        expected_manifest_id: [u8; 32],
        envelopes: impl IntoIterator<Item = Vec<u8>>,
        verifier: &V,
    ) -> Result<Self, V4HybridForkChoiceError> {
        let mut ordered = Vec::new();
        let mut total_bytes = 0usize;
        for envelope in envelopes {
            if ordered.len() >= MAX_V4_HYBRID_FORK_ARCHIVE_BLOCKS
                || envelope.len() > MAX_PRIVATE_TESTNET_V4_HYBRID_MONETARY_ENVELOPE_BYTES
            {
                return Err(V4HybridForkChoiceError::ArchiveExportLimitExceeded);
            }
            total_bytes = total_bytes
                .checked_add(envelope.len())
                .filter(|bytes| *bytes <= MAX_V4_HYBRID_FORK_ARCHIVE_BYTES)
                .ok_or(V4HybridForkChoiceError::ArchiveByteLimitExceeded)?;
            let decoded = decode_candidate_v4_hybrid_monetary_network_block(&envelope)
                .map_err(V4HybridForkChoiceError::Wire)?;
            let digest = pow_digest(&decoded.header, params.pow)
                .map_err(V4HybridForkChoiceError::InvalidPow)?;
            ordered.push((decoded.header.height, digest, envelope));
        }
        ordered.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        let expected_count = ordered.len();
        let mut archive = Self::new(genesis, params, expected_manifest_id)?;
        for (_, _, envelope) in ordered {
            archive.insert_encoded_inner(&envelope, verifier, None)?;
        }
        if archive.archive_len() != expected_count {
            return Err(V4HybridForkChoiceError::ReplayIncomplete);
        }
        Ok(archive)
    }

    /// Rebuild a PFM5 checkpoint-rooted PMT4 branch graph from every retained envelope.
    ///
    /// The authenticated checkpoint is a hard branch-history boundary: forks below it are not
    /// reconsidered by this pruned archive. All post-checkpoint envelopes are bounded, sorted by
    /// height/digest and consensus-replayed; their recomputed digest set and the selected canonical
    /// tip must exactly match PFM5 before this object is returned.
    pub fn rebuild_from_pfm5_checkpoint<V: MlDsa65Verifier>(
        manifest: &Pfm5CheckpointManifest,
        checkpoint: &Pcp4CheckpointRecord,
        context: &Pcp4ValidationContext<'_>,
        expected_manifest_commitment: [u8; 32],
        minimum_generation: u64,
        minimum_checkpoint_height: u64,
        envelopes: impl IntoIterator<Item = Vec<u8>>,
        verifier: &V,
    ) -> Result<Self, V4HybridForkChoiceError> {
        let base_chain = PrivateTestnetChain::restore_pfm5_checkpoint_baseline_for_replay(
            manifest,
            checkpoint,
            context,
            expected_manifest_commitment,
            minimum_generation,
            minimum_checkpoint_height,
        )
        .map_err(V4HybridForkChoiceError::CheckpointRestore)?;
        let base_state = base_chain
            .monetary_state()
            .cloned()
            .ok_or(V4HybridForkChoiceError::ReplayIncomplete)?;
        let base_height = checkpoint.logical_height;
        let mut ordered = Vec::new();
        let mut actual_digests = Vec::new();
        let mut total_bytes = 0usize;
        for envelope in envelopes {
            if ordered.len() >= MAX_V4_HYBRID_FORK_ARCHIVE_BLOCKS
                || envelope.len() > MAX_PRIVATE_TESTNET_V4_HYBRID_MONETARY_ENVELOPE_BYTES
            {
                return Err(V4HybridForkChoiceError::ArchiveExportLimitExceeded);
            }
            total_bytes = total_bytes
                .checked_add(envelope.len())
                .filter(|bytes| *bytes <= MAX_V4_HYBRID_FORK_ARCHIVE_BYTES)
                .ok_or(V4HybridForkChoiceError::ArchiveByteLimitExceeded)?;
            let decoded = decode_candidate_v4_hybrid_monetary_network_block(&envelope)
                .map_err(V4HybridForkChoiceError::Wire)?;
            if decoded.header.network_id != *context.network_id {
                return Err(V4HybridForkChoiceError::Wire(
                    V4HybridMonetaryWireError::InvalidNetworkId,
                ));
            }
            let depth = decoded
                .header
                .height
                .checked_sub(base_height)
                .ok_or(V4HybridForkChoiceError::BranchHeightExceeded)?;
            if depth == 0 || depth > MAX_V4_HYBRID_FORK_BRANCH_DEPTH {
                return Err(V4HybridForkChoiceError::BranchHeightExceeded);
            }
            let digest = pow_digest(&decoded.header, context.params.pow)
                .map_err(V4HybridForkChoiceError::InvalidPow)?;
            actual_digests.push(digest);
            ordered.push((decoded.header.height, digest, envelope));
        }
        if actual_digests.len() != manifest.branch_digests.len() {
            return Err(V4HybridForkChoiceError::BranchSetMismatch);
        }
        actual_digests.sort_unstable();
        if actual_digests != manifest.branch_digests {
            return Err(V4HybridForkChoiceError::BranchSetMismatch);
        }
        ordered.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        let mut archive = Self {
            genesis: base_state,
            base_chain: base_chain.clone(),
            params: context.params.clone(),
            expected_manifest_id: checkpoint.transaction_manifest_id,
            genesis_tip: checkpoint.consensus_tip_digest,
            canonical: base_chain,
            branches: BTreeMap::new(),
            archive_bytes: 0,
            reorg_count: 0,
        };
        for (_, _, envelope) in ordered {
            archive.insert_encoded_inner(&envelope, verifier, None)?;
        }
        if archive.archive_len() != manifest.branch_digests.len() {
            return Err(V4HybridForkChoiceError::ReplayIncomplete);
        }
        let replayed_tip = archive.canonical_chain().chain_tip();
        if replayed_tip.height != manifest.canonical_tip_height
            || replayed_tip.tip_hash != manifest.canonical_tip_digest
        {
            return Err(V4HybridForkChoiceError::CanonicalTipMismatch);
        }
        Ok(archive)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chain_admission::{ReferenceTimeError, ReferenceTimeProvenance, ReferenceTimeSample},
        consensus::{PowHeader, Uint256},
        private_testnet_checkpoint_candidate::{
            consensus_profile_fingerprint, trusted_genesis_fingerprint, Pcp4CheckpointRecord,
            Pcp4ValidationContext,
        },
        private_testnet_monetary_wire::{
            decode_candidate_v4_hybrid_monetary_network_block,
            encode_candidate_v4_hybrid_monetary_network_block,
        },
        private_testnet_pfm5_manifest_candidate::Pfm5CheckpointManifest,
        state_machine::MONETARY_PUBLIC_GOODS_BUDGET_ATOMS,
        v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate,
    };

    const NETWORK: [u8; 32] = [0xB7; 32];
    const MANIFEST: [u8; 32] = [0xC4; 32];
    struct FixedClock;
    impl ReferenceTimeProvider for FixedClock {
        fn sample(&self) -> Result<ReferenceTimeSample, ReferenceTimeError> {
            Ok(ReferenceTimeSample {
                unix_seconds: 200,
                provenance: ReferenceTimeProvenance::ConfiguredProvider,
                source_id: "v4-fork-choice-test-clock",
            })
        }
    }
    fn params() -> ConsensusParameters {
        let mut p = ConsensusParameters::candidate_testnet().unwrap();
        p.initial_target = Uint256::MAX;
        p.pow_limit = Uint256::MAX;
        // Test-only inexpensive but structurally valid Argon2id parameters. This keeps
        // the 2,016-block retarget reachability test practical and is not a launch profile.
        p.pow.memory_kib = 8;
        p.pow.iterations = 1;
        p.pow.lanes = 1;
        p
    }
    fn genesis() -> MonetaryLedgerState {
        MonetaryLedgerState::genesis(
            NETWORK,
            [1; 32],
            vec![([2; 32], MONETARY_PUBLIC_GOODS_BUDGET_ATOMS as u64)],
        )
        .unwrap()
    }
    fn checkpoint_record_for_chain(
        chain: &PrivateTestnetChain,
        context: &Pcp4ValidationContext<'_>,
        parent_checkpoint_commitment: [u8; 32],
    ) -> Pcp4CheckpointRecord {
        let state = chain.monetary_state().unwrap();
        Pcp4CheckpointRecord {
            network_id: *context.network_id,
            genesis_fingerprint: trusted_genesis_fingerprint(context).unwrap(),
            consensus_profile_fingerprint: consensus_profile_fingerprint(context.params).unwrap(),
            transaction_manifest_id: *context.active_transaction_manifest_id,
            logical_height: state.height(),
            consensus_tip_digest: chain.chain_tip().tip_hash,
            ledger_tip_hash: state.tip_hash(),
            monetary_state_root: state.state_root(),
            total_mined_atoms: state.total_mined_atoms(),
            cumulative_chainwork: chain.cumulative_work(),
            parent_checkpoint_commitment,
            monetary_snapshot: state.encode_snapshot().unwrap(),
            target_history: chain.target_history().checkpoint_snapshot().unwrap(),
        }
    }

    #[test]
    fn fork_choice_refuses_issuance_profile_not_bound_to_monetary_state_machine() {
        let mut mismatched = params();
        mismatched.issuance = crate::issuance_schedule::IssuanceParameters::new(
            mismatched.issuance.maximum_supply(),
            mismatched.issuance.initial_subsidy() + 1,
            mismatched.issuance.blocks_per_halving(),
        )
        .unwrap();

        assert_eq!(
            PrivateTestnetV4HybridForkChoice::new(genesis(), mismatched, MANIFEST).unwrap_err(),
            V4HybridForkChoiceError::InvalidPow(ConsensusError::MonetaryIssuanceProfileMismatch)
        );
    }

    fn candidate_block(
        state: &MonetaryLedgerState,
        timestamp: u64,
        miner: [u8; 32],
    ) -> crate::state_machine::V4HybridMonetaryBlock {
        let v = LibcruxMlDsa65VerifierCandidate;
        let mut b = crate::state_machine::V4HybridMonetaryBlock {
            height: state.height() + 1,
            timestamp,
            parent_hash: state.tip_hash(),
            state_root: [0; 32],
            transactions: vec![],
            miner,
            claimed_subsidy_atoms: state.expected_miner_reward().unwrap(),
        };
        b.state_root = state
            .preview_v4_hybrid_state_root_after(&b, &MANIFEST, &v)
            .unwrap();
        b
    }
    fn envelope(
        parent: &PrivateTestnetChain,
        b: &crate::state_machine::V4HybridMonetaryBlock,
        p: &ConsensusParameters,
        nonce: u64,
    ) -> Vec<u8> {
        let h = PowHeader {
            protocol_version: p.protocol_version,
            network_id: NETWORK,
            height: b.height,
            timestamp: b.timestamp,
            parent_hash: b.parent_hash,
            previous_consensus_hash: parent.chain_tip().tip_hash,
            state_root: b.state_root,
            target: parent.expected_target(None).unwrap(),
            nonce,
        };
        encode_candidate_v4_hybrid_monetary_network_block(&h, b).unwrap()
    }

    #[test]
    fn archive_rebuild_rejects_pow_that_only_meets_a_peer_forged_target() {
        let p = params();
        let g = genesis();
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let parent = PrivateTestnetChain::new_monetary(g.clone(), p.clone()).unwrap();
        let block = candidate_block(&g, 100, [3; 32]);
        let valid = envelope(&parent, &block, &p, 11);
        let candidate =
            crate::private_testnet_monetary_wire::decode_candidate_v4_hybrid_monetary_network_block(
                &valid,
            )
            .unwrap();
        let forged_target = Uint256::from_be_bytes([0x7F; 32]);
        assert_ne!(forged_target, parent.expected_target(None).unwrap());
        assert!(forged_target <= p.pow_limit);

        // This envelope models a persisted archive entry that a peer/disk editor rewrote:
        // the nonce really meets its easier target, but the header target isn't the chain's
        // consensus-derived target. Recovery must replay consensus, not trust the self-described
        // target or a locally recomputed block digest/checksum.
        let forged = (0..256u64)
            .find_map(|nonce| {
                let mut header = candidate.header;
                header.target = forged_target;
                header.nonce = nonce;
                let digest = crate::consensus::pow_digest(&header, p.pow).unwrap();
                (Uint256::from_be_bytes(digest) <= forged_target).then(|| {
                    encode_candidate_v4_hybrid_monetary_network_block(&header, &candidate.block)
                        .unwrap()
                })
            })
            .expect("a nonce meeting the half-range forged target should be found");

        let replay_candidate =
            crate::private_testnet_monetary_wire::decode_candidate_v4_hybrid_monetary_network_block(
                &forged,
            )
            .unwrap();
        assert_eq!(replay_candidate.header.target, forged_target);
        assert!(
            Uint256::from_be_bytes(
                crate::consensus::pow_digest(&replay_candidate.header, p.pow).unwrap()
            ) <= replay_candidate.header.target
        );

        let replay = PrivateTestnetV4HybridForkChoice::rebuild_from_envelopes(
            g,
            p,
            MANIFEST,
            vec![forged],
            &verifier,
        );
        assert!(matches!(
            replay,
            Err(V4HybridForkChoiceError::Consensus(
                crate::private_testnet_consensus::PrivateConsensusError::ExpectedTargetMismatch
            ))
        ));
    }

    #[test]
    fn pmt4_fork_choice_selects_heavier_branch_and_deterministically_replays_archive() {
        let p = params();
        let g = genesis();
        let v = LibcruxMlDsa65VerifierCandidate;
        let mut fc = PrivateTestnetV4HybridForkChoice::new(g.clone(), p.clone(), MANIFEST).unwrap();
        let gc = PrivateTestnetChain::new_monetary(g.clone(), p.clone()).unwrap();
        let a = candidate_block(&g, 100, [3; 32]);
        let ea = envelope(&gc, &a, &p, 11);
        let oa = fc.insert_encoded(&ea, &v, &FixedClock).unwrap();
        assert_eq!(oa.canonical_height, 1);
        let b = candidate_block(&g, 101, [4; 32]);
        let eb = envelope(&gc, &b, &p, 22);
        fc.insert_encoded(&eb, &v, &FixedClock).unwrap();
        assert_eq!(fc.archive_len(), 2);
        let cb = fc.branch_chain(&oa.block_digest).unwrap().clone();
        let sb = cb.monetary_state().unwrap().clone();
        let b2 = candidate_block(&sb, 102, [5; 32]);
        let eb2 = envelope(&cb, &b2, &p, 33);
        let ob2 = fc.insert_encoded(&eb2, &v, &FixedClock).unwrap();
        assert_eq!(ob2.canonical_height, 2);
        let rebuilt = PrivateTestnetV4HybridForkChoice::rebuild_from_envelopes(
            g,
            p,
            MANIFEST,
            fc.archive_envelopes(),
            &v,
        )
        .unwrap();
        assert_eq!(rebuilt.archive_len(), 3);
        assert_eq!(
            rebuilt.canonical_chain().chain_tip(),
            fc.canonical_chain().chain_tip()
        );
        assert_eq!(
            rebuilt.canonical_chain().monetary_state(),
            fc.canonical_chain().monetary_state()
        );
    }

    #[test]
    fn pfm5_checkpoint_replay_crosses_default_retarget_and_reconciles_sibling_forks() {
        const RETARGET_HEIGHT: u64 = 2_017;
        let p = params();
        let g = genesis();
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let context = Pcp4ValidationContext {
            network_id: &NETWORK,
            trusted_genesis: &g,
            params: &p,
            active_transaction_manifest_id: &MANIFEST,
        };
        let mut chain = PrivateTestnetChain::new_monetary(g.clone(), p.clone()).unwrap();

        // Produce a real candidate chain through every height of the default 2,016-block
        // difficulty window. This is intentionally not the 32-block fast test fixture.
        for height in 1..RETARGET_HEIGHT {
            let state = chain.monetary_state().unwrap().clone();
            let block = candidate_block(&state, 10_000 + height * 120, [3; 32]);
            let bytes = envelope(&chain, &block, &p, height);
            let decoded = decode_candidate_v4_hybrid_monetary_network_block(&bytes).unwrap();
            chain
                .append_v4_hybrid_monetary_historical(
                    &decoded.block,
                    &decoded.header,
                    None,
                    &MANIFEST,
                    &verifier,
                )
                .unwrap();
        }
        assert_eq!(chain.chain_tip().height, RETARGET_HEIGHT - 1);
        let checkpoint_state = chain.monetary_state().unwrap().clone();
        let genesis_chain = PrivateTestnetChain::new_monetary(g.clone(), p.clone()).unwrap();
        let genesis_checkpoint = checkpoint_record_for_chain(&genesis_chain, &context, [0; 32]);
        let genesis_checkpoint_commitment = genesis_checkpoint.commitment(&context).unwrap();
        let checkpoint =
            checkpoint_record_for_chain(&chain, &context, genesis_checkpoint_commitment);
        let checkpoint_bytes = checkpoint.encode(&context).unwrap();
        let checkpoint_commitment = checkpoint.commitment(&context).unwrap();
        assert_eq!(checkpoint.logical_height, 2_016);
        assert_eq!(checkpoint.target_history.start_height, 1);
        assert_eq!(checkpoint.target_history.entries.len(), 2_016);

        // Two competing valid blocks at the first default retarget height are built from the
        // checkpoint chain. The selected tip must be deterministic after checkpoint-based replay.
        let next_timestamp = 10_000 + RETARGET_HEIGHT * 120;
        let branch_a = candidate_block(&checkpoint_state, next_timestamp, [4; 32]);
        let branch_b = candidate_block(&checkpoint_state, next_timestamp, [5; 32]);
        let bytes_a = envelope(&chain, &branch_a, &p, 0xAA);
        let bytes_b = envelope(&chain, &branch_b, &p, 0xBB);
        let decoded_a = decode_candidate_v4_hybrid_monetary_network_block(&bytes_a).unwrap();
        let decoded_b = decode_candidate_v4_hybrid_monetary_network_block(&bytes_b).unwrap();
        let expected_retarget = chain.expected_target(None).unwrap();
        assert_eq!(decoded_a.header.height, RETARGET_HEIGHT);
        assert_eq!(decoded_b.header.height, RETARGET_HEIGHT);
        assert_eq!(decoded_a.header.target, expected_retarget);
        assert_eq!(decoded_b.header.target, expected_retarget);
        let digest_a = pow_digest(&decoded_a.header, p.pow).unwrap();
        let digest_b = pow_digest(&decoded_b.header, p.pow).unwrap();
        let selected_tip = std::cmp::min(digest_a, digest_b);
        let mut branch_digests = vec![digest_a, digest_b];
        branch_digests.sort_unstable();

        let previous_manifest = Pfm5CheckpointManifest {
            network_id: NETWORK,
            consensus_profile_fingerprint: checkpoint.consensus_profile_fingerprint,
            genesis_fingerprint: checkpoint.genesis_fingerprint,
            generation: 1,
            parent_manifest_commitment: [0; 32],
            checkpoint_height: checkpoint.logical_height,
            checkpoint_record_commitment: checkpoint_commitment,
            checkpoint_record_len: checkpoint_bytes.len() as u32,
            checkpoint_consensus_tip_digest: checkpoint.consensus_tip_digest,
            checkpoint_ledger_tip_hash: checkpoint.ledger_tip_hash,
            checkpoint_state_root: checkpoint.monetary_state_root,
            checkpoint_total_mined_atoms: checkpoint.total_mined_atoms,
            checkpoint_cumulative_chainwork: checkpoint.cumulative_chainwork,
            canonical_tip_height: checkpoint.logical_height,
            canonical_tip_digest: checkpoint.consensus_tip_digest,
            branch_digests: Vec::new(),
        };
        let manifest = Pfm5CheckpointManifest {
            generation: 2,
            parent_manifest_commitment: previous_manifest.commitment().unwrap(),
            canonical_tip_height: RETARGET_HEIGHT,
            canonical_tip_digest: selected_tip,
            branch_digests,
            ..previous_manifest
        };
        let manifest_commitment = manifest.commitment().unwrap();

        let restored = PrivateTestnetV4HybridForkChoice::rebuild_from_pfm5_checkpoint(
            &manifest,
            &checkpoint,
            &context,
            manifest_commitment,
            2,
            2_016,
            vec![bytes_b.clone(), bytes_a.clone()],
            &verifier,
        )
        .unwrap();
        assert_eq!(
            restored.canonical_chain().chain_tip().height,
            RETARGET_HEIGHT
        );
        assert_eq!(
            restored.canonical_chain().chain_tip().tip_hash,
            selected_tip
        );
        assert_eq!(restored.archive_len(), 2);
        assert_eq!(restored.archive_envelopes().len(), 2);
        assert_eq!(
            restored.canonical_chain().cumulative_work(),
            checkpoint
                .cumulative_chainwork
                .checked_add(crate::consensus::block_work(expected_retarget).unwrap())
                .unwrap()
        );

        assert_eq!(
            PrivateTestnetV4HybridForkChoice::rebuild_from_pfm5_checkpoint(
                &manifest,
                &checkpoint,
                &context,
                manifest_commitment,
                2,
                2_016,
                vec![bytes_a],
                &verifier,
            ),
            Err(V4HybridForkChoiceError::BranchSetMismatch)
        );
    }

    #[test]
    fn pmt3_magic_is_rejected_by_the_v4_fork_choice_codec() {
        assert_eq!(
            decode_candidate_v4_hybrid_monetary_network_block(b"PMT3"),
            Err(V4HybridMonetaryWireError::Incomplete)
        );
    }
}
