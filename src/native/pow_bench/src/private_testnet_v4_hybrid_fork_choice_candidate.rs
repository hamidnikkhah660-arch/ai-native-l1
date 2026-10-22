//! Separate candidate-only MBK4/TXN4 fork choice and deterministic replay.
//! PMT3/MBK3 archives remain strictly separate; activation still requires a PFM4 durable store
//! and standard-node integration. The active manifest and ML-DSA verifier are explicit inputs.
use crate::{
    chain_admission::ReferenceTimeProvider,
    consensus::{pow_digest, ConsensusError, ConsensusParameters},
    private_testnet_driver::PrivateTestnetChain,
    private_testnet_monetary_wire::{
        decode_candidate_v4_hybrid_monetary_network_block, V4HybridMonetaryWireError,
    },
    state_machine::MonetaryLedgerState,
    v4_account_identity_candidate::MlDsa65Verifier,
};
use std::{cmp::Ordering, collections::BTreeMap};

pub const MAX_V4_HYBRID_FORK_ARCHIVE_BLOCKS: usize = 4_096;
pub const MAX_V4_HYBRID_FORK_ARCHIVE_HEIGHT: u64 = 1_024;

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
    genesis: MonetaryLedgerState,
    params: ConsensusParameters,
    expected_manifest_id: [u8; 32],
    genesis_tip: [u8; 32],
    canonical: PrivateTestnetChain,
    branches: BTreeMap<[u8; 32], StoredV4HybridBranch>,
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
            params,
            expected_manifest_id,
            genesis_tip,
            canonical,
            branches: BTreeMap::new(),
            reorg_count: 0,
        })
    }

    pub fn expected_manifest_id(&self) -> [u8; 32] {
        self.expected_manifest_id
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
        if candidate.header.height > MAX_V4_HYBRID_FORK_ARCHIVE_HEIGHT {
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

        let parent_tip = candidate.header.previous_consensus_hash;
        let mut parent_chain = if parent_tip == self.genesis_tip {
            PrivateTestnetChain::new_monetary(self.genesis.clone(), self.params.clone())
                .map_err(V4HybridForkChoiceError::InvalidPow)?
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
        let mut best_chain =
            PrivateTestnetChain::new_monetary(self.genesis.clone(), self.params.clone())
                .expect("V4 hybrid fork parameters were validated at construction");
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
        for envelope in envelopes {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chain_admission::{ReferenceTimeError, ReferenceTimeProvenance, ReferenceTimeSample},
        consensus::{PowHeader, Uint256},
        private_testnet_monetary_wire::encode_candidate_v4_hybrid_monetary_network_block,
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
    fn pmt3_magic_is_rejected_by_the_v4_fork_choice_codec() {
        assert_eq!(
            decode_candidate_v4_hybrid_monetary_network_block(b"PMT3"),
            Err(V4HybridMonetaryWireError::Incomplete)
        );
    }
}
