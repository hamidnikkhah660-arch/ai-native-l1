//! Candidate-only bounded MBK3 monetary fork choice and deterministic replay.
//!
//! This reuses the shared PoW target/work driver, but remains separate from PFS2/PTB2 storage
//! and the live Devnet node. Every branch is replayed through the same monetary state transition;
//! no branch may fall back to the legacy BLK2 admission path.

use crate::{
    chain_admission::ReferenceTimeProvider,
    consensus::{pow_digest, ConsensusError, ConsensusParameters},
    private_testnet_driver::PrivateTestnetChain,
    private_testnet_monetary_wire::{decode_candidate_monetary_network_block, MonetaryWireError},
    state_machine::{MonetaryLedgerState, TransactionAuthenticator},
};
use std::{cmp::Ordering, collections::BTreeMap};

pub const MAX_MONETARY_FORK_ARCHIVE_BLOCKS: usize = 4_096;
pub const MAX_MONETARY_FORK_ARCHIVE_HEIGHT: u64 = 1_024;

#[derive(Debug, PartialEq, Eq)]
pub enum MonetaryForkChoiceError {
    Wire(MonetaryWireError),
    Consensus(crate::private_testnet_consensus::PrivateConsensusError),
    InvalidPow(ConsensusError),
    UnknownParent,
    DuplicateDigestConflict,
    DigestMismatch,
    ArchiveCapacityExceeded,
    ArchiveExportLimitExceeded,
    BranchHeightExceeded,
    ReplayIncomplete,
}

impl std::fmt::Display for MonetaryForkChoiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Wire(error) => write!(f, "monetary candidate envelope rejected: {error}"),
            Self::Consensus(error) => write!(f, "monetary consensus validation failed: {error}"),
            Self::InvalidPow(error) => write!(f, "monetary candidate PoW failed: {error}"),
            Self::UnknownParent => write!(
                f,
                "monetary candidate references an unknown consensus parent"
            ),
            Self::DuplicateDigestConflict => {
                write!(f, "same monetary PoW digest has different PMT3 bytes")
            }
            Self::DigestMismatch => write!(
                f,
                "replayed monetary branch tip differs from its PoW digest"
            ),
            Self::ArchiveCapacityExceeded => {
                write!(f, "monetary fork archive block limit exceeded")
            }
            Self::ArchiveExportLimitExceeded => {
                write!(f, "monetary fork archive export budget exceeded")
            }
            Self::BranchHeightExceeded => write!(f, "monetary fork branch height limit exceeded"),
            Self::ReplayIncomplete => write!(
                f,
                "monetary fork archive replay did not consume every block"
            ),
        }
    }
}

impl std::error::Error for MonetaryForkChoiceError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MonetaryForkChoiceOutcome {
    pub block_digest: [u8; 32],
    pub previous_canonical_tip: [u8; 32],
    pub canonical_tip: [u8; 32],
    pub previous_height: u64,
    pub canonical_height: u64,
    pub canonical_changed: bool,
    pub reorg_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredMonetaryBranch {
    envelope: Vec<u8>,
    chain: PrivateTestnetChain,
}

/// A bounded branch graph for PMT3/MBK3 candidates. Persistence and socket integration are
/// intentionally separate so a candidate monetary transition cannot silently change PTB2 storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateTestnetMonetaryForkChoice {
    genesis: MonetaryLedgerState,
    params: ConsensusParameters,
    genesis_tip: [u8; 32],
    canonical: PrivateTestnetChain,
    branches: BTreeMap<[u8; 32], StoredMonetaryBranch>,
    reorg_count: u64,
}

impl PrivateTestnetMonetaryForkChoice {
    pub fn new(
        genesis: MonetaryLedgerState,
        params: ConsensusParameters,
    ) -> Result<Self, MonetaryForkChoiceError> {
        let canonical = PrivateTestnetChain::new_monetary(genesis.clone(), params.clone())
            .map_err(MonetaryForkChoiceError::InvalidPow)?;
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

    /// Borrow the committed PMT3 envelopes without cloning the archive payloads.
    ///
    /// Use this when constructing metadata indexes or validating ancestry so an archive
    /// lookup does not transiently duplicate every persisted envelope in memory.
    pub fn archive_envelopes_iter(&self) -> impl Iterator<Item = &[u8]> + '_ {
        self.branches
            .values()
            .map(|branch| branch.envelope.as_slice())
    }

    pub fn archive_envelopes_bounded(
        &self,
        max_blocks: usize,
        max_bytes: usize,
    ) -> Result<Vec<Vec<u8>>, MonetaryForkChoiceError> {
        if self.branches.len() > max_blocks {
            return Err(MonetaryForkChoiceError::ArchiveExportLimitExceeded);
        }
        let mut total_bytes = 0usize;
        for branch in self.branches.values() {
            total_bytes = total_bytes
                .checked_add(branch.envelope.len())
                .ok_or(MonetaryForkChoiceError::ArchiveExportLimitExceeded)?;
            if total_bytes > max_bytes {
                return Err(MonetaryForkChoiceError::ArchiveExportLimitExceeded);
            }
        }
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
    ) -> Result<MonetaryForkChoiceOutcome, MonetaryForkChoiceError> {
        self.insert_encoded_inner(envelope, authenticator, Some(clock))
    }

    fn insert_encoded_inner<A: TransactionAuthenticator>(
        &mut self,
        envelope: &[u8],
        authenticator: &A,
        live_clock: Option<&dyn ReferenceTimeProvider>,
    ) -> Result<MonetaryForkChoiceOutcome, MonetaryForkChoiceError> {
        let candidate = decode_candidate_monetary_network_block(envelope)
            .map_err(MonetaryForkChoiceError::Wire)?;
        if candidate.header.height > MAX_MONETARY_FORK_ARCHIVE_HEIGHT {
            return Err(MonetaryForkChoiceError::BranchHeightExceeded);
        }
        let digest = pow_digest(&candidate.header, self.params.pow)
            .map_err(MonetaryForkChoiceError::InvalidPow)?;
        if let Some(existing) = self.branches.get(&digest) {
            if existing.envelope.as_slice() != envelope {
                return Err(MonetaryForkChoiceError::DuplicateDigestConflict);
            }
            return Ok(MonetaryForkChoiceOutcome {
                block_digest: digest,
                previous_canonical_tip: self.canonical.chain_tip().tip_hash,
                canonical_tip: self.canonical.chain_tip().tip_hash,
                previous_height: self.canonical.state().height(),
                canonical_height: self.canonical.state().height(),
                canonical_changed: false,
                reorg_count: self.reorg_count,
            });
        }
        if self.branches.len() >= MAX_MONETARY_FORK_ARCHIVE_BLOCKS {
            return Err(MonetaryForkChoiceError::ArchiveCapacityExceeded);
        }

        let parent_tip = candidate.header.previous_consensus_hash;
        let mut parent_chain = if parent_tip == self.genesis_tip {
            PrivateTestnetChain::new_monetary(self.genesis.clone(), self.params.clone())
                .map_err(MonetaryForkChoiceError::InvalidPow)?
        } else {
            self.branches
                .get(&parent_tip)
                .map(|branch| branch.chain.clone())
                .ok_or(MonetaryForkChoiceError::UnknownParent)?
        };

        let admission = match live_clock {
            Some(clock) => parent_chain.append_monetary_live(
                &candidate.block,
                &candidate.header,
                None,
                authenticator,
                clock,
            ),
            None => parent_chain.append_monetary_historical(
                &candidate.block,
                &candidate.header,
                None,
                authenticator,
            ),
        };
        admission.map_err(MonetaryForkChoiceError::Consensus)?;
        if parent_chain.chain_tip().tip_hash != digest {
            return Err(MonetaryForkChoiceError::DigestMismatch);
        }

        let previous_canonical_tip = self.canonical.chain_tip().tip_hash;
        let previous_height = self.canonical.state().height();
        self.branches.insert(
            digest,
            StoredMonetaryBranch {
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
        Ok(MonetaryForkChoiceOutcome {
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
        let mut best_chain =
            PrivateTestnetChain::new_monetary(self.genesis.clone(), self.params.clone())
                .expect("monetary fork parameters were validated at construction");

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
        for _ in 0..=MAX_MONETARY_FORK_ARCHIVE_HEIGHT {
            if tip == ancestor {
                return true;
            }
            if tip == self.genesis_tip {
                return false;
            }
            let Some(branch) = self.branches.get(&tip) else {
                return false;
            };
            tip = decode_candidate_monetary_network_block(&branch.envelope)
                .map(|decoded| decoded.header.previous_consensus_hash)
                .unwrap_or([0; 32]);
        }
        false
    }

    /// Rebuild a fresh bounded monetary fork graph from PMT3 bytes in parent-first order.
    pub fn rebuild_from_envelopes<A: TransactionAuthenticator>(
        genesis: MonetaryLedgerState,
        params: ConsensusParameters,
        envelopes: impl IntoIterator<Item = Vec<u8>>,
        authenticator: &A,
    ) -> Result<Self, MonetaryForkChoiceError> {
        let mut ordered = Vec::new();
        for envelope in envelopes {
            let decoded = decode_candidate_monetary_network_block(&envelope)
                .map_err(MonetaryForkChoiceError::Wire)?;
            let digest = pow_digest(&decoded.header, params.pow)
                .map_err(MonetaryForkChoiceError::InvalidPow)?;
            ordered.push((decoded.header.height, digest, envelope));
        }
        ordered.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));

        let expected_count = ordered.len();
        let mut archive = Self::new(genesis, params)?;
        for (_, _, envelope) in ordered {
            archive.insert_encoded_inner(&envelope, authenticator, None)?;
        }
        if archive.archive_len() != expected_count {
            return Err(MonetaryForkChoiceError::ReplayIncomplete);
        }
        Ok(archive)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chain_admission::{ReferenceTimeError, ReferenceTimeProvenance, ReferenceTimeSample},
        consensus::{ConsensusParameters, PowHeader, Uint256},
        private_testnet_monetary_wire::encode_candidate_monetary_network_block,
        state_machine::{
            AccountId, Block, MonetaryBlock, TransactionAuthenticator,
            MONETARY_INITIAL_SUBSIDY_ATOMS, MONETARY_PUBLIC_GOODS_BUDGET_ATOMS,
        },
    };

    struct EmptyAuthenticator;
    impl TransactionAuthenticator for EmptyAuthenticator {
        fn verify(&self, _: &AccountId, _: &[u8; 32], _: &[u8]) -> Result<(), ()> {
            Ok(())
        }
    }

    struct FixedClock;
    impl ReferenceTimeProvider for FixedClock {
        fn sample(&self) -> Result<ReferenceTimeSample, ReferenceTimeError> {
            Ok(ReferenceTimeSample {
                unix_seconds: 100,
                provenance: ReferenceTimeProvenance::ConfiguredProvider,
                source_id: "monetary-fork-choice-test-clock",
            })
        }
    }

    fn params() -> ConsensusParameters {
        let mut params = ConsensusParameters::candidate_testnet().unwrap();
        params.initial_target = Uint256::MAX;
        params.pow_limit = Uint256::MAX;
        params
    }

    fn genesis() -> MonetaryLedgerState {
        MonetaryLedgerState::genesis(
            [0xB6; 32],
            [1; 32],
            vec![([2; 32], MONETARY_PUBLIC_GOODS_BUDGET_ATOMS as u64)],
        )
        .unwrap()
    }

    fn candidate(
        chain: &PrivateTestnetChain,
        params: &ConsensusParameters,
        miner: AccountId,
        timestamp: u64,
        nonce: u64,
    ) -> Vec<u8> {
        let state = chain.monetary_state().unwrap();
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
        let header = PowHeader {
            protocol_version: params.protocol_version,
            network_id: state.ledger().network_id(),
            height: block.body.height,
            timestamp,
            parent_hash: block.body.parent_hash,
            previous_consensus_hash: chain.chain_tip().tip_hash,
            state_root: block.body.state_root,
            target: params.initial_target,
            nonce,
        };
        encode_candidate_monetary_network_block(&header, &block).unwrap()
    }

    #[test]
    fn accepts_monetary_candidate_and_rebuilds_the_same_selected_tip() {
        let genesis = genesis();
        let params = params();
        let seed_chain =
            PrivateTestnetChain::new_monetary(genesis.clone(), params.clone()).unwrap();
        let envelope = candidate(&seed_chain, &params, [3; 32], 100, 1);
        let mut archive =
            PrivateTestnetMonetaryForkChoice::new(genesis.clone(), params.clone()).unwrap();
        let outcome = archive
            .insert_encoded(&envelope, &EmptyAuthenticator, &FixedClock)
            .unwrap();
        assert_eq!(outcome.canonical_height, 1);
        let mined = archive
            .canonical_chain()
            .monetary_state()
            .unwrap()
            .total_mined_atoms();
        assert_eq!(mined, crate::state_machine::MONETARY_INITIAL_SUBSIDY_ATOMS);

        let parent_chain = archive.branch_chain(&outcome.block_digest).unwrap().clone();
        // Simulate a long-delayed historical block whose timestamp is far beyond the
        // replay test clock. Replay must be deterministic and must not consult wall time.
        let delayed_second = candidate(&parent_chain, &params, [4; 32], 10_000, 2);
        let rebuilt = PrivateTestnetMonetaryForkChoice::rebuild_from_envelopes(
            genesis,
            params,
            vec![envelope, delayed_second],
            &EmptyAuthenticator,
        )
        .unwrap();
        assert_eq!(rebuilt.archive_len(), 2);
        assert_eq!(rebuilt.canonical_chain().state().height(), 2);
        assert_eq!(
            rebuilt
                .canonical_chain()
                .monetary_state()
                .unwrap()
                .total_mined_atoms(),
            2 * MONETARY_INITIAL_SUBSIDY_ATOMS as u128
        );
    }

    #[test]
    fn longer_competing_branch_reorganizes_and_uses_height_scheduled_issuance() {
        let genesis = genesis();
        let params = params();
        let seed_chain =
            PrivateTestnetChain::new_monetary(genesis.clone(), params.clone()).unwrap();
        let env_a = candidate(&seed_chain, &params, [3; 32], 100, 11);
        let env_b = candidate(&seed_chain, &params, [4; 32], 100, 12);
        let digest_a = pow_digest(
            &decode_candidate_monetary_network_block(&env_a)
                .unwrap()
                .header,
            params.pow,
        )
        .unwrap();
        let digest_b = pow_digest(
            &decode_candidate_monetary_network_block(&env_b)
                .unwrap()
                .header,
            params.pow,
        )
        .unwrap();

        let mut archive = PrivateTestnetMonetaryForkChoice::new(genesis, params.clone()).unwrap();
        archive
            .insert_encoded(&env_a, &EmptyAuthenticator, &FixedClock)
            .unwrap();
        archive
            .insert_encoded(&env_b, &EmptyAuthenticator, &FixedClock)
            .unwrap();
        let canonical = archive.canonical_chain().chain_tip().tip_hash;
        let extension_parent = if canonical == digest_a {
            digest_b
        } else {
            digest_a
        };
        let parent_chain = archive.branch_chain(&extension_parent).unwrap().clone();
        let env_extension = candidate(&parent_chain, &params, [5; 32], 101, 13);
        let extension_digest = pow_digest(
            &decode_candidate_monetary_network_block(&env_extension)
                .unwrap()
                .header,
            params.pow,
        )
        .unwrap();

        let outcome = archive
            .insert_encoded(&env_extension, &EmptyAuthenticator, &FixedClock)
            .unwrap();
        assert_eq!(outcome.previous_canonical_tip, canonical);
        assert_eq!(outcome.canonical_tip, extension_digest);
        assert_eq!(outcome.canonical_height, 2);
        assert!(outcome.canonical_changed);
        assert_eq!(outcome.reorg_count, 1);
        let monetary = archive.canonical_chain().monetary_state().unwrap();
        assert_eq!(
            monetary.total_mined_atoms(),
            2 * MONETARY_INITIAL_SUBSIDY_ATOMS as u128,
        );
        assert_eq!(
            monetary.ledger().account(&[5; 32]).unwrap().balance,
            monetary.expected_miner_reward().unwrap()
        );
    }

    #[test]
    fn invalid_reward_is_rejected_without_changing_the_archive() {
        let genesis = genesis();
        let params = params();
        let seed_chain =
            PrivateTestnetChain::new_monetary(genesis.clone(), params.clone()).unwrap();
        let envelope = candidate(&seed_chain, &params, [3; 32], 100, 1);
        let mut decoded = decode_candidate_monetary_network_block(&envelope).unwrap();
        decoded.block.claimed_subsidy_atoms += 1;
        let invalid =
            encode_candidate_monetary_network_block(&decoded.header, &decoded.block).unwrap();
        let mut archive = PrivateTestnetMonetaryForkChoice::new(genesis, params).unwrap();
        let before = archive.clone();
        assert!(matches!(
            archive.insert_encoded(&invalid, &EmptyAuthenticator, &FixedClock),
            Err(MonetaryForkChoiceError::Consensus(_))
        ));
        assert_eq!(archive, before);
        assert!(matches!(
            archive.insert_encoded(&envelope, &EmptyAuthenticator, &FixedClock),
            Ok(_)
        ));
        assert_eq!(archive.archive_len(), 1);
    }
}
