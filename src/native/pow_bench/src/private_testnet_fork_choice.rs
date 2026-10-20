//! Candidate-only fork archive and deterministic cumulative-work selection for PTB2.
//!
//! The archive is intentionally bounded and in-memory in this increment. It reuses the real
//! PrivateTestnetChain admission path for every branch and reconstructs its selected state from
//! stored envelopes on replay. It is not a production persistent block database or public P2P
//! implementation; those still require independent durability and adversarial-network testing.

use crate::{
    chain_admission::ReferenceTimeProvider,
    consensus::{pow_digest, ConsensusError, ConsensusParameters},
    private_testnet_consensus::PrivateConsensusError,
    private_testnet_driver::PrivateTestnetChain,
    private_testnet_wire::{decode_candidate_network_block, PrivateTestnetWireError},
    state_machine::{LedgerState, TransactionAuthenticator},
};
use std::{cmp::Ordering, collections::BTreeMap};

pub const MAX_FORK_ARCHIVE_BLOCKS: usize = 4_096;
pub const MAX_FORK_ARCHIVE_HEIGHT: u64 = 1_024;

#[derive(Debug, PartialEq, Eq)]
pub enum ForkChoiceError {
    Wire(PrivateTestnetWireError),
    Consensus(PrivateConsensusError),
    InvalidPow(ConsensusError),
    UnknownParent,
    DuplicateDigestConflict,
    DigestMismatch,
    ArchiveCapacityExceeded,
    ArchiveExportLimitExceeded,
    BranchHeightExceeded,
    ReplayIncomplete,
}

impl std::fmt::Display for ForkChoiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Wire(error) => write!(f, "candidate envelope rejected: {error}"),
            Self::Consensus(error) => write!(f, "candidate consensus validation failed: {error}"),
            Self::InvalidPow(error) => write!(f, "candidate PoW digest failed: {error}"),
            Self::UnknownParent => write!(f, "candidate references an unknown consensus parent"),
            Self::DuplicateDigestConflict => write!(f, "same PoW digest has different PTB2 bytes"),
            Self::DigestMismatch => write!(
                f,
                "replayed branch tip digest differs from computed PoW digest"
            ),
            Self::ArchiveCapacityExceeded => write!(f, "fork archive block limit exceeded"),
            Self::ArchiveExportLimitExceeded => write!(f, "fork archive export budget exceeded"),
            Self::BranchHeightExceeded => write!(f, "fork archive height limit exceeded"),
            Self::ReplayIncomplete => write!(f, "fork archive replay did not consume every block"),
        }
    }
}

impl std::error::Error for ForkChoiceError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForkChoiceOutcome {
    pub block_digest: [u8; 32],
    pub previous_canonical_tip: [u8; 32],
    pub canonical_tip: [u8; 32],
    pub previous_height: u64,
    pub canonical_height: u64,
    pub canonical_changed: bool,
    pub reorg_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredBranch {
    envelope: Vec<u8>,
    chain: PrivateTestnetChain,
}

/// Bounded branch graph keyed by the digest of each accepted PoW header.
/// Every stored node owns the fully validated chain state at that branch tip. A later
/// persistence layer can store archive_envelopes() and call rebuild_from_envelopes()
/// before opening the node to peers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateTestnetForkChoice {
    genesis: LedgerState,
    params: ConsensusParameters,
    genesis_tip: [u8; 32],
    canonical: PrivateTestnetChain,
    branches: BTreeMap<[u8; 32], StoredBranch>,
    reorg_count: u64,
}

impl PrivateTestnetForkChoice {
    pub fn new(genesis: LedgerState, params: ConsensusParameters) -> Result<Self, ConsensusError> {
        let canonical = PrivateTestnetChain::new(genesis.clone(), params.clone())?;
        let genesis_tip = canonical.chain_tip().tip_hash;
        Ok(Self {
            genesis,
            params,
            genesis_tip,
            canonical,
            branches: BTreeMap::new(),
            reorg_count: 0,
        })
    }

    pub fn canonical_chain(&self) -> &PrivateTestnetChain {
        &self.canonical
    }

    pub fn genesis_tip(&self) -> [u8; 32] {
        self.genesis_tip
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
    pub fn archive_envelopes_bounded(
        &self,
        max_blocks: usize,
        max_bytes: usize,
    ) -> Result<Vec<Vec<u8>>, ForkChoiceError> {
        if self.branches.len() > max_blocks {
            return Err(ForkChoiceError::ArchiveExportLimitExceeded);
        }

        let mut total_bytes = 0usize;
        for branch in self.branches.values() {
            total_bytes = total_bytes
                .checked_add(branch.envelope.len())
                .ok_or(ForkChoiceError::ArchiveExportLimitExceeded)?;
            if total_bytes > max_bytes {
                return Err(ForkChoiceError::ArchiveExportLimitExceeded);
            }
        }

        // Validate the complete export budget before cloning any envelope bytes.
        Ok(self.archive_envelopes())
    }

    pub fn branch_chain(&self, tip: &[u8; 32]) -> Option<&PrivateTestnetChain> {
        self.branches.get(tip).map(|branch| &branch.chain)
    }

    pub fn insert_encoded<A: TransactionAuthenticator>(
        &mut self,
        envelope: &[u8],
        authenticator: &A,
        clock: &dyn ReferenceTimeProvider,
    ) -> Result<ForkChoiceOutcome, ForkChoiceError> {
        let candidate = decode_candidate_network_block(envelope).map_err(ForkChoiceError::Wire)?;
        if candidate.header.height > MAX_FORK_ARCHIVE_HEIGHT {
            return Err(ForkChoiceError::BranchHeightExceeded);
        }
        let digest =
            pow_digest(&candidate.header, self.params.pow).map_err(ForkChoiceError::InvalidPow)?;
        if let Some(existing) = self.branches.get(&digest) {
            if existing.envelope.as_slice() != envelope {
                return Err(ForkChoiceError::DuplicateDigestConflict);
            }
            return Ok(ForkChoiceOutcome {
                block_digest: digest,
                previous_canonical_tip: self.canonical.chain_tip().tip_hash,
                canonical_tip: self.canonical.chain_tip().tip_hash,
                previous_height: self.canonical.state().height(),
                canonical_height: self.canonical.state().height(),
                canonical_changed: false,
                reorg_count: self.reorg_count,
            });
        }

        if self.branches.len() >= MAX_FORK_ARCHIVE_BLOCKS {
            return Err(ForkChoiceError::ArchiveCapacityExceeded);
        }

        let parent_tip = candidate.header.previous_consensus_hash;
        let mut parent_chain = if parent_tip == self.genesis_tip {
            PrivateTestnetChain::new(self.genesis.clone(), self.params.clone())
                .map_err(ForkChoiceError::InvalidPow)?
        } else {
            self.branches
                .get(&parent_tip)
                .map(|branch| branch.chain.clone())
                .ok_or(ForkChoiceError::UnknownParent)?
        };

        parent_chain
            .append_live(
                &candidate.block,
                &candidate.header,
                None,
                authenticator,
                clock,
            )
            .map_err(ForkChoiceError::Consensus)?;
        if parent_chain.chain_tip().tip_hash != digest {
            return Err(ForkChoiceError::DigestMismatch);
        }

        let previous_canonical_tip = self.canonical.chain_tip().tip_hash;
        let previous_height = self.canonical.state().height();

        self.branches.insert(
            digest,
            StoredBranch {
                envelope: envelope.to_vec(),
                chain: parent_chain,
            },
        );

        let (best_tip, best_chain) = self.select_best_tip();
        if best_tip != previous_canonical_tip {
            if previous_canonical_tip != self.genesis_tip
                && !self.is_ancestor(previous_canonical_tip, best_tip)
            {
                self.reorg_count = self.reorg_count.saturating_add(1);
            }
            self.canonical = best_chain;
        }

        Ok(ForkChoiceOutcome {
            block_digest: digest,
            previous_canonical_tip,
            canonical_tip: self.canonical.chain_tip().tip_hash,
            previous_height,
            canonical_height: self.canonical.state().height(),
            canonical_changed: previous_canonical_tip != self.canonical.chain_tip().tip_hash,
            reorg_count: self.reorg_count,
        })
    }

    fn select_best_tip(&self) -> ([u8; 32], PrivateTestnetChain) {
        let mut best_tip = self.genesis_tip;
        let mut best_chain = PrivateTestnetChain::new(self.genesis.clone(), self.params.clone())
            .expect("fork store parameters were validated at construction");

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
        for _ in 0..=MAX_FORK_ARCHIVE_HEIGHT {
            if tip == ancestor {
                return true;
            }
            if tip == self.genesis_tip {
                return false;
            }
            let Some(branch) = self.branches.get(&tip) else {
                return false;
            };
            tip = decode_candidate_network_block(&branch.envelope)
                .map(|decoded| decoded.header.previous_consensus_hash)
                .unwrap_or([0; 32]);
        }
        false
    }

    /// Construct a fresh candidate archive by replaying all known PTB2 envelopes in
    /// height order. This is a restart/replay simulation; durable file I/O is not yet part
    /// of this type. Missing parents and invalid persisted candidates fail the whole replay.
    pub fn rebuild_from_envelopes<A: TransactionAuthenticator>(
        genesis: LedgerState,
        params: ConsensusParameters,
        envelopes: impl IntoIterator<Item = Vec<u8>>,
        authenticator: &A,
        clock: &dyn ReferenceTimeProvider,
    ) -> Result<Self, ForkChoiceError> {
        let mut ordered = Vec::new();
        for envelope in envelopes {
            let decoded =
                decode_candidate_network_block(&envelope).map_err(ForkChoiceError::Wire)?;
            let digest =
                pow_digest(&decoded.header, params.pow).map_err(ForkChoiceError::InvalidPow)?;
            ordered.push((decoded.header.height, digest, envelope));
        }
        ordered.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));

        let expected_count = ordered.len();
        let mut archive = Self::new(genesis, params).map_err(ForkChoiceError::InvalidPow)?;
        for (_, _, envelope) in ordered {
            archive.insert_encoded(&envelope, authenticator, clock)?;
        }
        if archive.archive_len() != expected_count {
            return Err(ForkChoiceError::ReplayIncomplete);
        }
        Ok(archive)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chain_admission::{ReferenceTimeProvenance, ReferenceTimeSample},
        consensus::{block_work, ConsensusParameters, PowHeader, Uint256},
        private_testnet_wire::encode_candidate_network_block,
        state_machine::{AccountId, Block, TransactionAuthenticator},
    };

    struct EmptyAuthenticator;

    impl TransactionAuthenticator for EmptyAuthenticator {
        fn verify(&self, _: &AccountId, _: &[u8; 32], _: &[u8]) -> Result<(), ()> {
            Err(())
        }
    }

    struct FixedClock;

    impl ReferenceTimeProvider for FixedClock {
        fn sample(
            &self,
        ) -> Result<ReferenceTimeSample, crate::chain_admission::ReferenceTimeError> {
            Ok(ReferenceTimeSample {
                unix_seconds: 1_000_000,
                provenance: ReferenceTimeProvenance::ConfiguredProvider,
                source_id: "fork-choice-test-clock",
            })
        }
    }

    fn params() -> ConsensusParameters {
        let mut params = ConsensusParameters::candidate_testnet().unwrap();
        params.initial_target = Uint256::MAX;
        params.pow_limit = Uint256::MAX;
        params
    }

    fn genesis() -> LedgerState {
        LedgerState::genesis([0xC7; 32], vec![([1; 32], 1_000)]).unwrap()
    }

    fn candidate(
        chain: &PrivateTestnetChain,
        params: &ConsensusParameters,
        timestamp: u64,
        nonce: u64,
    ) -> (Vec<u8>, [u8; 32]) {
        let mut block = Block {
            height: chain.state().height() + 1,
            timestamp,
            parent_hash: chain.state().tip_hash(),
            state_root: [0; 32],
            transactions: Vec::new(),
        };
        block.state_root = chain
            .state()
            .preview_state_root_after(&block, &EmptyAuthenticator)
            .unwrap();

        let header = PowHeader {
            protocol_version: params.protocol_version,
            network_id: chain.state().network_id(),
            height: block.height,
            timestamp: block.timestamp,
            parent_hash: block.parent_hash,
            previous_consensus_hash: chain.chain_tip().tip_hash,
            state_root: block.state_root,
            target: chain.expected_target(None).unwrap(),
            nonce,
        };
        let digest = pow_digest(&header, params.pow).unwrap();
        (
            encode_candidate_network_block(&header, &block).unwrap(),
            digest,
        )
    }

    fn append_for_branch(
        chain: &mut PrivateTestnetChain,
        envelope: &[u8],
        params: &ConsensusParameters,
    ) {
        let candidate = decode_candidate_network_block(envelope).unwrap();
        chain
            .append_live(
                &candidate.block,
                &candidate.header,
                None,
                &EmptyAuthenticator,
                &FixedClock,
            )
            .unwrap();
        assert_eq!(
            chain.cumulative_work(),
            block_work(params.initial_target)
                .unwrap()
                .mul_div_u64(chain.state().height(), 1)
                .unwrap()
        );
    }

    #[test]
    fn competing_ptb2_branches_reorg_to_more_work_and_replay_identically() {
        let params = params();
        let genesis = genesis();
        let genesis_chain = PrivateTestnetChain::new(genesis.clone(), params.clone()).unwrap();
        let (first_zero, digest_zero) = candidate(&genesis_chain, &params, 100, 0);
        let (first_one, digest_one) = candidate(&genesis_chain, &params, 100, 1);
        assert_ne!(digest_zero, digest_one);

        let (low_envelope, low_digest, high_envelope, high_digest) = if digest_zero < digest_one {
            (first_zero, digest_zero, first_one, digest_one)
        } else {
            (first_one, digest_one, first_zero, digest_zero)
        };

        let mut archive = PrivateTestnetForkChoice::new(genesis.clone(), params.clone()).unwrap();
        let first_outcome = archive
            .insert_encoded(&high_envelope, &EmptyAuthenticator, &FixedClock)
            .unwrap();
        assert_eq!(archive.canonical_chain().state().height(), 1);
        assert_eq!(first_outcome.canonical_tip, high_digest);

        let tie_outcome = archive
            .insert_encoded(&low_envelope, &EmptyAuthenticator, &FixedClock)
            .unwrap();
        // Equal work and height deterministically prefer the lexicographically smaller digest.
        assert_eq!(tie_outcome.canonical_tip, low_digest);
        assert!(tie_outcome.canonical_changed);
        assert_eq!(tie_outcome.reorg_count, 1);

        // Extend the previously losing branch. Greater cumulative work must replace the
        // tie-break winner, even though its height-1 ancestor was no longer canonical.
        let mut high_branch = genesis_chain.clone();
        append_for_branch(&mut high_branch, &high_envelope, &params);
        let (high_child, high_child_digest) = candidate(&high_branch, &params, 101, 2);
        let winning_outcome = archive
            .insert_encoded(&high_child, &EmptyAuthenticator, &FixedClock)
            .unwrap();
        assert_eq!(winning_outcome.canonical_tip, high_child_digest);
        assert_eq!(winning_outcome.canonical_height, 2);
        assert!(winning_outcome.canonical_changed);
        assert_eq!(winning_outcome.reorg_count, 2);
        append_for_branch(&mut high_branch, &high_child, &params);
        assert_eq!(high_branch.state().height(), 2);
        assert_eq!(
            archive.canonical_chain().state().state_root(),
            high_branch.state().state_root()
        );

        // Simulate a fresh node rebuilding every branch in deterministic height order.
        let replayed = PrivateTestnetForkChoice::rebuild_from_envelopes(
            genesis,
            params,
            archive.archive_envelopes(),
            &EmptyAuthenticator,
            &FixedClock,
        )
        .unwrap();
        assert_eq!(
            replayed.canonical_chain().chain_tip(),
            archive.canonical_chain().chain_tip()
        );
        assert_eq!(
            replayed.canonical_chain().state().state_root(),
            archive.canonical_chain().state().state_root()
        );
        assert_eq!(replayed.archive_len(), 3);
        assert_eq!(replayed.reorg_count(), 1);
    }

    #[test]
    fn unknown_parent_and_conflicting_duplicate_fail_closed_without_mutation() {
        let params = params();
        let genesis = genesis();
        let genesis_chain = PrivateTestnetChain::new(genesis.clone(), params.clone()).unwrap();
        let (valid, valid_digest) = candidate(&genesis_chain, &params, 100, 0);
        let mut archive = PrivateTestnetForkChoice::new(genesis.clone(), params.clone()).unwrap();
        archive
            .insert_encoded(&valid, &EmptyAuthenticator, &FixedClock)
            .unwrap();
        let before = archive.clone();

        assert!(
            !archive
                .insert_encoded(&valid, &EmptyAuthenticator, &FixedClock)
                .unwrap()
                .canonical_changed
        );
        assert_eq!(archive.archive_len(), before.archive_len());

        let decoded = decode_candidate_network_block(&valid).unwrap();
        let mut disconnected = decoded.header;
        disconnected.previous_consensus_hash = [0xFE; 32];
        let unlinked = encode_candidate_network_block(&disconnected, &decoded.block).unwrap();
        assert_eq!(
            archive.insert_encoded(&unlinked, &EmptyAuthenticator, &FixedClock),
            Err(ForkChoiceError::UnknownParent)
        );
        assert_eq!(archive.canonical_chain(), before.canonical_chain());
        assert_eq!(archive.archive_len(), before.archive_len());
        assert_eq!(archive.canonical_chain().chain_tip().tip_hash, valid_digest);
    }

    #[test]
    fn bounded_archive_export_enforces_block_and_byte_limits() {
        let params = params();
        let genesis = genesis();
        let chain = PrivateTestnetChain::new(genesis.clone(), params.clone()).unwrap();
        let (envelope, _) = candidate(&chain, &params, 100, 0);
        let envelope_bytes = envelope.len();
        let mut archive = PrivateTestnetForkChoice::new(genesis, params).unwrap();
        archive
            .insert_encoded(&envelope, &EmptyAuthenticator, &FixedClock)
            .unwrap();

        assert_eq!(
            archive
                .archive_envelopes_bounded(1, envelope_bytes)
                .unwrap(),
            vec![envelope.clone()]
        );
        assert_eq!(
            archive.archive_envelopes_bounded(0, envelope_bytes),
            Err(ForkChoiceError::ArchiveExportLimitExceeded)
        );
        assert_eq!(
            archive.archive_envelopes_bounded(1, envelope_bytes - 1),
            Err(ForkChoiceError::ArchiveExportLimitExceeded)
        );
    }
}
