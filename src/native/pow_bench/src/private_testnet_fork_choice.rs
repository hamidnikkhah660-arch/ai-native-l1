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
    CanonicalRangeBeforeBase,
    ExecutionModeMismatch,
    GenesisProfileMismatch,
    ConsensusProfileMismatch,
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
            Self::CanonicalRangeBeforeBase => write!(
                f,
                "requested canonical range predates this checkpoint-rooted archive segment"
            ),
            Self::ExecutionModeMismatch => write!(
                f,
                "candidate envelope execution mode does not match the chain's frozen profile"
            ),
            Self::GenesisProfileMismatch => write!(
                f,
                "QRun fee-only mode requires the exact frozen 10B Genesis identity and state root"
            ),
            Self::ConsensusProfileMismatch => write!(
                f,
                "QRun v0.5 fee-only mode requires protocol version 5; production consensus parameters remain a separate release gate"
            ),
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ForkChoiceExecutionMode {
    LegacyPtb2,
    QRunV05FeeOnly,
    QRunV05FeeCheckpoint([u8; 32]),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateTestnetForkChoice {
    genesis: LedgerState,
    params: ConsensusParameters,
    /// Trusted base chain for this bounded fork segment (Genesis or an anchored checkpoint).
    base_chain: PrivateTestnetChain,
    genesis_tip: [u8; 32],
    canonical: PrivateTestnetChain,
    branches: BTreeMap<[u8; 32], StoredBranch>,
    reorg_count: u64,
    execution_mode: ForkChoiceExecutionMode,
}

impl PrivateTestnetForkChoice {
    pub fn new(genesis: LedgerState, params: ConsensusParameters) -> Result<Self, ConsensusError> {
        let canonical = PrivateTestnetChain::new(genesis.clone(), params.clone())?;
        let genesis_tip = canonical.chain_tip().tip_hash;
        Ok(Self {
            genesis,
            params,
            base_chain: canonical.clone(),
            genesis_tip,
            canonical,
            branches: BTreeMap::new(),
            reorg_count: 0,
            execution_mode: ForkChoiceExecutionMode::LegacyPtb2,
        })
    }

    /// Genesis-rooted QRun profile: QFP5/QFB5 only. The exact 10B Genesis is frozen.
    pub fn new_qrun_v05_fee_only(
        genesis: LedgerState,
        params: ConsensusParameters,
    ) -> Result<Self, ForkChoiceError> {
        if params.protocol_version != 5 {
            return Err(ForkChoiceError::ConsensusProfileMismatch);
        }
        let frozen = crate::qrun_v05_profile_identity_candidate::build_candidate_genesis()
            .map_err(|_| ForkChoiceError::GenesisProfileMismatch)?;
        if genesis.height() != 0
            || genesis.network_id()
                != crate::qrun_v05_profile_identity_candidate::PROPOSED_QRUN_V05_NETWORK_ID
            || genesis.state_root()
                != crate::qrun_v05_profile_identity_candidate::PROPOSED_GENESIS_STATE_ROOT
            || frozen.state_root() != genesis.state_root()
            || frozen.commitment()
                != crate::qrun_v05_profile_identity_candidate::PROPOSED_GENESIS_COMMITMENT
        {
            return Err(ForkChoiceError::GenesisProfileMismatch);
        }
        let mut choice = Self::new(genesis, params).map_err(ForkChoiceError::InvalidPow)?;
        choice.execution_mode = ForkChoiceExecutionMode::QRunV05FeeOnly;
        Ok(choice)
    }

    /// Start a new bounded fork segment from a previously validated QRun checkpoint chain.
    /// The caller must independently authenticate the checkpoint before calling this method.
    pub fn from_base_chain(
        base_state: LedgerState,
        params: ConsensusParameters,
        base_chain: PrivateTestnetChain,
    ) -> Result<Self, ConsensusError> {
        params.validate()?;
        let base_tip = base_chain.chain_tip().tip_hash;
        Ok(Self {
            genesis: base_state,
            params,
            base_chain: base_chain.clone(),
            genesis_tip: base_tip,
            canonical: base_chain,
            branches: BTreeMap::new(),
            reorg_count: 0,
            execution_mode: ForkChoiceExecutionMode::LegacyPtb2,
        })
    }

    /// Restore a QFP5 suffix only from a previously decoded QRCP checkpoint. The caller must
    /// authenticate the QRCP bytes/commitment against an independent anchor before using this API.
    pub fn new_qrun_v05_fee_only_from_checkpoint(
        base_state: LedgerState,
        params: ConsensusParameters,
        base_chain: PrivateTestnetChain,
        checkpoint_commitment: [u8; 32],
    ) -> Result<Self, ForkChoiceError> {
        if params.protocol_version != 5 {
            return Err(ForkChoiceError::ConsensusProfileMismatch);
        }
        if checkpoint_commitment == [0; 32]
            || base_state.network_id()
                != crate::qrun_v05_profile_identity_candidate::PROPOSED_QRUN_V05_NETWORK_ID
            || base_chain.state() != &base_state
            || base_state.height() == 0
            || base_state.total_value().ok() != Some(crate::state_machine::MAX_TOTAL_SUPPLY_ATOMS)
            || !base_chain.uses_qrun_v05_fee_only_execution()
            || crate::qrun_v05_checkpoint_candidate::qrun_consensus_profile_fingerprint(&params)
                .is_err()
        {
            return Err(ForkChoiceError::GenesisProfileMismatch);
        }
        let frozen = crate::qrun_v05_profile_identity_candidate::build_candidate_genesis()
            .map_err(|_| ForkChoiceError::GenesisProfileMismatch)?;
        if frozen.commitment()
            != crate::qrun_v05_profile_identity_candidate::PROPOSED_GENESIS_COMMITMENT
        {
            return Err(ForkChoiceError::GenesisProfileMismatch);
        }
        let mut choice = Self::from_base_chain(base_state, params, base_chain)
            .map_err(ForkChoiceError::InvalidPow)?;
        choice.execution_mode =
            ForkChoiceExecutionMode::QRunV05FeeCheckpoint(checkpoint_commitment);
        Ok(choice)
    }

    pub fn canonical_chain(&self) -> &PrivateTestnetChain {
        &self.canonical
    }

    pub fn genesis_tip(&self) -> [u8; 32] {
        self.genesis_tip
    }

    /// Height of the authenticated base state (zero for a Genesis-rooted archive).
    pub fn base_height(&self) -> u64 {
        self.base_chain.state().height()
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

    /// Return only the selected canonical path, ordered from its first block to the tip.
    /// The method walks authenticated parent digests; archive insertion/replay has already
    /// validated every envelope, but the bounded walk still fails closed if invariants drift.
    pub fn canonical_envelopes(&self) -> Result<Vec<Vec<u8>>, ForkChoiceError> {
        let mut reversed = Vec::new();
        let mut tip = self.canonical.chain_tip().tip_hash;
        while tip != self.genesis_tip {
            if reversed.len() >= MAX_FORK_ARCHIVE_HEIGHT as usize {
                return Err(ForkChoiceError::ReplayIncomplete);
            }
            let branch = self
                .branches
                .get(&tip)
                .ok_or(ForkChoiceError::UnknownParent)?;
            let candidate =
                decode_candidate_network_block(&branch.envelope).map_err(ForkChoiceError::Wire)?;
            let digest = pow_digest(&candidate.header, self.params.pow)
                .map_err(ForkChoiceError::InvalidPow)?;
            if digest != tip {
                return Err(ForkChoiceError::DigestMismatch);
            }
            tip = candidate.header.previous_consensus_hash;
            reversed.push(branch.envelope.clone());
        }
        reversed.reverse();
        Ok(reversed)
    }

    /// Export a bounded canonical block range beginning at an absolute block height.
    /// The returned blocks are ordered by height and no more than the requested block
    /// and byte budgets are cloned into the response. A checkpoint-rooted segment cannot
    /// serve historical heights at/below its base height; callers must obtain that
    /// checkpoint through an independently authenticated channel.
    pub fn canonical_envelopes_range(
        &self,
        start_height: u64,
        max_blocks: usize,
        max_bytes: usize,
    ) -> Result<Vec<Vec<u8>>, ForkChoiceError> {
        if start_height == 0
            || max_blocks == 0
            || max_blocks > MAX_FORK_ARCHIVE_BLOCKS
            || max_bytes == 0
        {
            return Err(ForkChoiceError::ArchiveExportLimitExceeded);
        }
        if self.base_height() > 0 && start_height <= self.base_height() {
            return Err(ForkChoiceError::CanonicalRangeBeforeBase);
        }

        let mut selected_reversed: Vec<&[u8]> = Vec::new();
        let mut tip = self.canonical.chain_tip().tip_hash;
        while tip != self.genesis_tip {
            if selected_reversed.len() >= MAX_FORK_ARCHIVE_HEIGHT as usize {
                return Err(ForkChoiceError::ReplayIncomplete);
            }
            let branch = self
                .branches
                .get(&tip)
                .ok_or(ForkChoiceError::UnknownParent)?;
            let candidate =
                decode_candidate_network_block(&branch.envelope).map_err(ForkChoiceError::Wire)?;
            let digest = pow_digest(&candidate.header, self.params.pow)
                .map_err(ForkChoiceError::InvalidPow)?;
            if digest != tip {
                return Err(ForkChoiceError::DigestMismatch);
            }
            if candidate.block.height < start_height {
                break;
            }
            selected_reversed.push(&branch.envelope);
            tip = candidate.header.previous_consensus_hash;
        }

        selected_reversed.reverse();
        let mut output = Vec::new();
        let mut total_bytes = 0usize;
        for envelope in selected_reversed {
            if output.len() >= max_blocks {
                break;
            }
            let next_bytes = total_bytes
                .checked_add(envelope.len())
                .ok_or(ForkChoiceError::ArchiveExportLimitExceeded)?;
            if next_bytes > max_bytes {
                if output.is_empty() {
                    return Err(ForkChoiceError::ArchiveExportLimitExceeded);
                }
                break;
            }
            output.push(envelope.to_vec());
            total_bytes = next_bytes;
        }
        Ok(output)
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
        self.insert_encoded_internal(envelope, authenticator, clock, false)
    }

    /// Historical QFP5 replay does not sample wall-clock time, but still verifies PoW, ancestry,
    /// difficulty, canonical fee execution and the frozen execution mode.
    fn insert_encoded_internal<A: TransactionAuthenticator>(
        &mut self,
        envelope: &[u8],
        authenticator: &A,
        clock: &dyn ReferenceTimeProvider,
        historical_replay: bool,
    ) -> Result<ForkChoiceOutcome, ForkChoiceError> {
        let candidate = decode_candidate_network_block(envelope).map_err(ForkChoiceError::Wire)?;
        let qrun_mode = matches!(
            self.execution_mode,
            ForkChoiceExecutionMode::QRunV05FeeOnly
                | ForkChoiceExecutionMode::QRunV05FeeCheckpoint(_)
        );
        if candidate.fee_block.is_some() != qrun_mode {
            return Err(ForkChoiceError::ExecutionModeMismatch);
        }
        let maximum_segment_height = self
            .base_chain
            .state()
            .height()
            .saturating_add(MAX_FORK_ARCHIVE_HEIGHT);
        if candidate.header.height > maximum_segment_height {
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
            self.base_chain.clone()
        } else {
            self.branches
                .get(&parent_tip)
                .map(|branch| branch.chain.clone())
                .ok_or(ForkChoiceError::UnknownParent)?
        };

        match (&candidate.fee_block, self.execution_mode, historical_replay) {
            (Some(fee_block), ForkChoiceExecutionMode::QRunV05FeeOnly, true)
            | (Some(fee_block), ForkChoiceExecutionMode::QRunV05FeeCheckpoint(_), true) => {
                parent_chain
                    .append_qrun_v05_fee_historical(
                        fee_block,
                        &candidate.header,
                        None,
                        authenticator,
                    )
                    .map_err(ForkChoiceError::Consensus)?;
            }
            (Some(fee_block), ForkChoiceExecutionMode::QRunV05FeeOnly, false)
            | (Some(fee_block), ForkChoiceExecutionMode::QRunV05FeeCheckpoint(_), false) => {
                parent_chain
                    .append_qrun_v05_fee_live(
                        fee_block,
                        &candidate.header,
                        None,
                        authenticator,
                        clock,
                    )
                    .map_err(ForkChoiceError::Consensus)?;
            }
            (None, ForkChoiceExecutionMode::LegacyPtb2, _) => {
                parent_chain
                    .append_live(
                        &candidate.block,
                        &candidate.header,
                        None,
                        authenticator,
                        clock,
                    )
                    .map_err(ForkChoiceError::Consensus)?;
            }
            _ => return Err(ForkChoiceError::ExecutionModeMismatch),
        }
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

    /// Rebuild a Genesis-rooted QRun QFP5 archive using deterministic historical replay.
    /// QFP5 state-root commitments and fee-only execution are checked through the same chain path.
    pub fn rebuild_qrun_v05_fee_from_envelopes<A: TransactionAuthenticator>(
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
            if decoded.fee_block.is_none() {
                return Err(ForkChoiceError::ExecutionModeMismatch);
            }
            let digest =
                pow_digest(&decoded.header, params.pow).map_err(ForkChoiceError::InvalidPow)?;
            ordered.push((decoded.header.height, digest, envelope));
        }
        ordered.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
        let expected_count = ordered.len();
        let mut archive = Self::new_qrun_v05_fee_only(genesis, params)?;
        for (_, _, envelope) in ordered {
            archive.insert_encoded_internal(&envelope, authenticator, clock, true)?;
        }
        if archive.archive_len() != expected_count {
            return Err(ForkChoiceError::ReplayIncomplete);
        }
        Ok(archive)
    }

    /// Rebuild an externally anchored QRun QRCP checkpoint suffix with QFP5 fee-only replay.
    pub fn rebuild_qrun_v05_fee_from_checkpoint<A: TransactionAuthenticator>(
        base_state: LedgerState,
        params: ConsensusParameters,
        base_chain: PrivateTestnetChain,
        checkpoint_commitment: [u8; 32],
        envelopes: impl IntoIterator<Item = Vec<u8>>,
        authenticator: &A,
        clock: &dyn ReferenceTimeProvider,
    ) -> Result<Self, ForkChoiceError> {
        let mut ordered = Vec::new();
        for envelope in envelopes {
            let decoded =
                decode_candidate_network_block(&envelope).map_err(ForkChoiceError::Wire)?;
            if decoded.fee_block.is_none() || decoded.header.height <= base_state.height() {
                return Err(ForkChoiceError::ExecutionModeMismatch);
            }
            let digest =
                pow_digest(&decoded.header, params.pow).map_err(ForkChoiceError::InvalidPow)?;
            ordered.push((decoded.header.height, digest, envelope));
        }
        ordered.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
        let expected_count = ordered.len();
        let mut archive = Self::new_qrun_v05_fee_only_from_checkpoint(
            base_state,
            params,
            base_chain,
            checkpoint_commitment,
        )?;
        for (_, _, envelope) in ordered {
            archive.insert_encoded_internal(&envelope, authenticator, clock, true)?;
        }
        if archive.archive_len() != expected_count {
            return Err(ForkChoiceError::ReplayIncomplete);
        }
        Ok(archive)
    }

    /// Rebuild a checkpoint-rooted suffix archive in deterministic height/digest order.
    pub fn rebuild_from_base_chain<A: TransactionAuthenticator>(
        base_state: LedgerState,
        params: ConsensusParameters,
        base_chain: PrivateTestnetChain,
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
        let mut archive = Self::from_base_chain(base_state, params, base_chain)
            .map_err(ForkChoiceError::InvalidPow)?;
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

    fn qrun_fee_candidate(
        chain: &PrivateTestnetChain,
        params: &ConsensusParameters,
        timestamp: u64,
        producer: [u8; 32],
        nonce: u64,
    ) -> (Vec<u8>, [u8; 32]) {
        let mut block = crate::state_machine::QRunV05FeeBlock {
            body: Block {
                height: chain.state().height() + 1,
                timestamp,
                parent_hash: chain.state().tip_hash(),
                state_root: [0; 32],
                transactions: Vec::new(),
            },
            producer,
        };
        block.body.state_root = chain
            .state()
            .preview_qrun_v05_fee_state_root_after(&block, &EmptyAuthenticator)
            .unwrap();
        let header = PowHeader {
            protocol_version: params.protocol_version,
            network_id: chain.state().network_id(),
            height: block.body.height,
            timestamp,
            parent_hash: block.body.parent_hash,
            previous_consensus_hash: chain.chain_tip().tip_hash,
            state_root: crate::qrun_v05_fee_pow_wire_candidate::qrun_v05_fee_pow_state_commitment(
                &block,
            )
            .unwrap(),
            target: chain.expected_target(None).unwrap(),
            nonce,
        };
        let digest = pow_digest(&header, params.pow).unwrap();
        let envelope =
            crate::qrun_v05_fee_pow_wire_candidate::encode_qrun_v05_fee_pow_block(&header, &block)
                .unwrap();
        (envelope, digest)
    }

    #[test]
    fn qrun_fee_only_fork_choice_rejects_noncanonical_genesis_and_protocol_version() {
        let mut params = params();
        params.protocol_version = 5;
        assert_eq!(
            PrivateTestnetForkChoice::new_qrun_v05_fee_only(genesis(), params.clone()),
            Err(ForkChoiceError::GenesisProfileMismatch)
        );
        let genesis = crate::qrun_v05_profile_identity_candidate::build_candidate_genesis()
            .unwrap()
            .ledger()
            .clone();
        params.protocol_version = 1;
        assert_eq!(
            PrivateTestnetForkChoice::new_qrun_v05_fee_only(genesis, params),
            Err(ForkChoiceError::ConsensusProfileMismatch)
        );
    }

    #[test]
    fn qfp5_fork_choice_replays_fee_only_blocks_and_rejects_mode_mixing() {
        let mut params = params();
        params.protocol_version = 5;
        params.pow.memory_kib = 8;
        params.pow.iterations = 1;
        params.pow.lanes = 1;
        let genesis = crate::qrun_v05_profile_identity_candidate::build_candidate_genesis()
            .unwrap()
            .ledger()
            .clone();
        let genesis_chain = PrivateTestnetChain::new(genesis.clone(), params.clone()).unwrap();
        let (fee_envelope, fee_digest) =
            qrun_fee_candidate(&genesis_chain, &params, 100, [0x77; 32], 0);

        let mut qrun_archive =
            PrivateTestnetForkChoice::new_qrun_v05_fee_only(genesis.clone(), params.clone())
                .unwrap();
        let outcome = qrun_archive
            .insert_encoded(&fee_envelope, &EmptyAuthenticator, &FixedClock)
            .unwrap();
        assert_eq!(outcome.block_digest, fee_digest);
        assert_eq!(qrun_archive.canonical_chain().state().height(), 1);
        assert_eq!(
            qrun_archive
                .canonical_chain()
                .state()
                .total_value()
                .unwrap(),
            crate::state_machine::MAX_TOTAL_SUPPLY_ATOMS
        );

        let rebuilt = PrivateTestnetForkChoice::rebuild_qrun_v05_fee_from_envelopes(
            genesis.clone(),
            params.clone(),
            vec![fee_envelope.clone()],
            &EmptyAuthenticator,
            &FixedClock,
        )
        .unwrap();
        assert_eq!(
            rebuilt.canonical_chain().chain_tip(),
            qrun_archive.canonical_chain().chain_tip()
        );
        assert_eq!(
            rebuilt.canonical_chain().state().state_root(),
            qrun_archive.canonical_chain().state().state_root()
        );

        let legacy_archive =
            PrivateTestnetForkChoice::new(genesis.clone(), params.clone()).unwrap();
        assert_eq!(
            legacy_archive
                .clone()
                .insert_encoded(&fee_envelope, &EmptyAuthenticator, &FixedClock),
            Err(ForkChoiceError::ExecutionModeMismatch)
        );

        let (legacy_envelope, _) = candidate(&genesis_chain, &params, 100, 9);
        assert_eq!(
            qrun_archive
                .clone()
                .insert_encoded(&legacy_envelope, &EmptyAuthenticator, &FixedClock),
            Err(ForkChoiceError::ExecutionModeMismatch)
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

    #[test]
    fn canonical_range_export_is_ordered_bounded_and_respects_checkpoint_base() {
        let params = params();
        let genesis = genesis();
        let mut archive = PrivateTestnetForkChoice::new(genesis.clone(), params.clone()).unwrap();

        let mut accepted = Vec::new();
        for (timestamp, nonce) in [(100, 10), (101, 11), (102, 12)] {
            let parent = archive.canonical_chain().clone();
            let (envelope, _) = candidate(&parent, &params, timestamp, nonce);
            archive
                .insert_encoded(&envelope, &EmptyAuthenticator, &FixedClock)
                .unwrap();
            accepted.push(envelope);
        }

        let page = archive.canonical_envelopes_range(1, 2, usize::MAX).unwrap();
        assert_eq!(page, accepted[..2]);
        let last_page = archive.canonical_envelopes_range(3, 2, usize::MAX).unwrap();
        assert_eq!(last_page, vec![accepted[2].clone()]);
        assert_eq!(
            archive.canonical_envelopes_range(1, 2, accepted[0].len() - 1),
            Err(ForkChoiceError::ArchiveExportLimitExceeded)
        );
        assert_eq!(
            archive.canonical_envelopes_range(0, 1, usize::MAX),
            Err(ForkChoiceError::ArchiveExportLimitExceeded)
        );
        assert_eq!(
            archive.canonical_envelopes_range(1, 0, usize::MAX),
            Err(ForkChoiceError::ArchiveExportLimitExceeded)
        );

        let checkpoint_chain = {
            let mut chain = PrivateTestnetChain::new(genesis.clone(), params.clone()).unwrap();
            let first = decode_candidate_network_block(&accepted[0]).unwrap();
            chain
                .append_live(
                    &first.block,
                    &first.header,
                    None,
                    &EmptyAuthenticator,
                    &FixedClock,
                )
                .unwrap();
            chain
        };
        let checkpoint_state = checkpoint_chain.state().clone();
        let mut suffix = PrivateTestnetForkChoice::from_base_chain(
            checkpoint_state,
            params.clone(),
            checkpoint_chain,
        )
        .unwrap();
        assert_eq!(
            suffix.canonical_envelopes_range(1, 1, usize::MAX),
            Err(ForkChoiceError::CanonicalRangeBeforeBase)
        );
        let base = suffix.canonical_chain().clone();
        let (child, _) = candidate(&base, &params, 101, 21);
        suffix
            .insert_encoded(&child, &EmptyAuthenticator, &FixedClock)
            .unwrap();
        assert_eq!(
            suffix.canonical_envelopes_range(1, 1, usize::MAX),
            Err(ForkChoiceError::CanonicalRangeBeforeBase)
        );
        assert_eq!(
            suffix.canonical_envelopes_range(2, 1, usize::MAX).unwrap(),
            vec![child]
        );
    }

    #[test]
    fn qrun_full_supply_survives_pow_fork_choice_and_archive_replay() {
        let qrun_genesis =
            crate::qrun_v05_genesis_candidate::QRunGenesisV05::new([0x51; 32], [0x2a; 32]).unwrap();
        let genesis = qrun_genesis.ledger().clone();
        let expected_supply = crate::state_machine::MAX_TOTAL_SUPPLY_ATOMS;
        assert_eq!(genesis.total_value().unwrap(), expected_supply);

        let params = params();
        let chain = PrivateTestnetChain::new(genesis.clone(), params.clone()).unwrap();
        let (envelope, _) = candidate(&chain, &params, 100, 0);
        let mut archive = PrivateTestnetForkChoice::new(genesis.clone(), params.clone()).unwrap();
        archive
            .insert_encoded(&envelope, &EmptyAuthenticator, &FixedClock)
            .unwrap();

        assert_eq!(
            archive.canonical_chain().state().total_value().unwrap(),
            expected_supply
        );
        let replayed = PrivateTestnetForkChoice::rebuild_from_envelopes(
            genesis,
            params,
            archive.archive_envelopes(),
            &EmptyAuthenticator,
            &FixedClock,
        )
        .unwrap();
        assert_eq!(
            replayed.canonical_chain().state().total_value().unwrap(),
            expected_supply
        );
        assert_eq!(
            replayed.canonical_chain().chain_tip(),
            archive.canonical_chain().chain_tip()
        );
    }
}
