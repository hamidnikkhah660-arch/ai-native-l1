//! CP-0405 candidate QZB4 v2 + PoW envelope and branch-local fork choice.
//!
//! This is deliberately separate from PMT3/PMT4 and the canonical node runtime. The QZBE
//! envelope binds the transaction-bearing QZB4 v2 body to the existing PoW header, target-history,
//! chainwork and replay rules. A caller must supply the exact monetary profile and consensus
//! parameters; this module has no Mainnet defaults and is not a persistent branch store.

use crate::{
    consensus::{
        block_work, compare_chain_tips, pow_digest, verify_pow, ChainTip, ConsensusError,
        ConsensusParameters, PowHeader, Uint256,
    },
    monetary_transition_v04_candidate::{
        MonetaryLedgerStateV04TransitionCandidate, V04ConsensusProfileCandidate,
        V04ExecutionBlockCandidate, V04TransitionError, MAX_ENCODED_V04_EXECUTION_BLOCK_BYTES,
    },
    private_testnet_consensus::PrivateConsensusError,
    private_testnet_driver::TargetHistory,
    state_machine::{Transaction, TransactionAuthenticator},
};
use sha2::{Digest, Sha256};
use std::{cmp::Ordering, collections::BTreeMap};

pub const V04_EXECUTION_POW_ENVELOPE_MAGIC: [u8; 4] = *b"QZBE";
pub const V04_EXECUTION_POW_ENVELOPE_VERSION: u16 = 1;
const ENVELOPE_HEADER_BYTES: usize = 228;
const POW_PROFILE_FINGERPRINT_DOMAIN: &[u8] =
    b"QUANTUMZXB-V04-POW-CONSENSUS-PROFILE-CANDIDATE-V1\0";
pub const MAX_ENCODED_V04_EXECUTION_POW_ENVELOPE_BYTES: usize =
    ENVELOPE_HEADER_BYTES + MAX_ENCODED_V04_EXECUTION_BLOCK_BYTES;
pub const MAX_V04_EXECUTION_FORK_ARCHIVE_BLOCKS: usize = 4_096;
pub const MAX_V04_EXECUTION_FORK_ARCHIVE_HEIGHT: u64 = 1_024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V04ExecutionPowError {
    Transition(V04TransitionError),
    Consensus(ConsensusError),
    History(PrivateConsensusError),
    BadMagic,
    UnsupportedEnvelopeVersion(u16),
    MalformedEnvelope,
    HeaderBodyMismatch(&'static str),
    ProfileMismatch,
    ConsensusProfileMismatch,
    UnknownParent,
    DuplicateDigestConflict,
    ArchiveCapacityExceeded,
    BranchHeightExceeded,
}

impl std::fmt::Display for V04ExecutionPowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for V04ExecutionPowError {}
impl From<V04TransitionError> for V04ExecutionPowError {
    fn from(value: V04TransitionError) -> Self {
        Self::Transition(value)
    }
}
impl From<ConsensusError> for V04ExecutionPowError {
    fn from(value: ConsensusError) -> Self {
        Self::Consensus(value)
    }
}
impl From<PrivateConsensusError> for V04ExecutionPowError {
    fn from(value: PrivateConsensusError) -> Self {
        Self::History(value)
    }
}

/// Canonical QZBE v1 envelope containing exactly one canonical QZB4 v2 execution body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V04ExecutionPowEnvelope {
    /// Fingerprints every configured PoW/difficulty parameter used to validate this header.
    pub consensus_profile_fingerprint: [u8; 32],
    pub header: PowHeader,
    pub block: V04ExecutionBlockCandidate,
}

impl V04ExecutionPowEnvelope {
    pub fn encode(
        &self,
        profile: &V04ConsensusProfileCandidate,
        consensus_params: &ConsensusParameters,
    ) -> Result<Vec<u8>, V04ExecutionPowError> {
        let expected_consensus_fingerprint = pow_consensus_profile_fingerprint(consensus_params)?;
        if self.consensus_profile_fingerprint != expected_consensus_fingerprint {
            return Err(V04ExecutionPowError::ConsensusProfileMismatch);
        }
        if self.header.protocol_version != consensus_params.protocol_version {
            return Err(V04ExecutionPowError::HeaderBodyMismatch("protocol_version"));
        }
        validate_header_body_binding(&self.header, &self.block, profile)?;
        let body = self.block.encode()?;
        if body.len() > MAX_ENCODED_V04_EXECUTION_BLOCK_BYTES {
            return Err(V04ExecutionPowError::MalformedEnvelope);
        }
        let body_len =
            u32::try_from(body.len()).map_err(|_| V04ExecutionPowError::MalformedEnvelope)?;
        let mut bytes = Vec::with_capacity(ENVELOPE_HEADER_BYTES + body.len());
        bytes.extend_from_slice(&V04_EXECUTION_POW_ENVELOPE_MAGIC);
        bytes.extend_from_slice(&V04_EXECUTION_POW_ENVELOPE_VERSION.to_be_bytes());
        bytes.extend_from_slice(&self.consensus_profile_fingerprint);
        bytes.extend_from_slice(&self.header.protocol_version.to_be_bytes());
        bytes.extend_from_slice(&self.header.network_id);
        bytes.extend_from_slice(&self.header.height.to_be_bytes());
        bytes.extend_from_slice(&self.header.timestamp.to_be_bytes());
        bytes.extend_from_slice(&self.header.parent_hash);
        bytes.extend_from_slice(&self.header.previous_consensus_hash);
        bytes.extend_from_slice(&self.header.state_root);
        bytes.extend_from_slice(&self.header.target.to_be_bytes());
        bytes.extend_from_slice(&self.header.nonce.to_be_bytes());
        bytes.extend_from_slice(&body_len.to_be_bytes());
        bytes.extend_from_slice(&body);
        if bytes.len() > MAX_ENCODED_V04_EXECUTION_POW_ENVELOPE_BYTES
            || bytes.len() != ENVELOPE_HEADER_BYTES + body.len()
        {
            return Err(V04ExecutionPowError::MalformedEnvelope);
        }
        Ok(bytes)
    }

    pub fn decode(
        bytes: &[u8],
        profile: &V04ConsensusProfileCandidate,
        consensus_params: &ConsensusParameters,
    ) -> Result<Self, V04ExecutionPowError> {
        if bytes.len() > MAX_ENCODED_V04_EXECUTION_POW_ENVELOPE_BYTES
            || bytes.len() < ENVELOPE_HEADER_BYTES
        {
            return Err(V04ExecutionPowError::MalformedEnvelope);
        }
        if bytes[..4] != V04_EXECUTION_POW_ENVELOPE_MAGIC {
            return Err(V04ExecutionPowError::BadMagic);
        }
        let version = u16::from_be_bytes([bytes[4], bytes[5]]);
        if version != V04_EXECUTION_POW_ENVELOPE_VERSION {
            return Err(V04ExecutionPowError::UnsupportedEnvelopeVersion(version));
        }
        let mut cursor = 6usize;
        let consensus_profile_fingerprint = take_array::<32>(bytes, &mut cursor)?;
        if consensus_profile_fingerprint != pow_consensus_profile_fingerprint(consensus_params)? {
            return Err(V04ExecutionPowError::ConsensusProfileMismatch);
        }
        let protocol_version = take_u16(bytes, &mut cursor)?;
        let network_id = take_array::<32>(bytes, &mut cursor)?;
        let height = take_u64(bytes, &mut cursor)?;
        let timestamp = take_u64(bytes, &mut cursor)?;
        let parent_hash = take_array::<32>(bytes, &mut cursor)?;
        let previous_consensus_hash = take_array::<32>(bytes, &mut cursor)?;
        let state_root = take_array::<32>(bytes, &mut cursor)?;
        let target = Uint256::from_be_bytes(take_array::<32>(bytes, &mut cursor)?);
        let nonce = take_u64(bytes, &mut cursor)?;
        let body_len = take_u32(bytes, &mut cursor)? as usize;
        if cursor != ENVELOPE_HEADER_BYTES
            || body_len > MAX_ENCODED_V04_EXECUTION_BLOCK_BYTES
            || bytes.len() != ENVELOPE_HEADER_BYTES.saturating_add(body_len)
        {
            return Err(V04ExecutionPowError::MalformedEnvelope);
        }
        let block = V04ExecutionBlockCandidate::decode(&bytes[ENVELOPE_HEADER_BYTES..])?;
        let envelope = Self {
            consensus_profile_fingerprint,
            header: PowHeader {
                protocol_version,
                network_id,
                height,
                timestamp,
                parent_hash,
                previous_consensus_hash,
                state_root,
                target,
                nonce,
            },
            block,
        };
        validate_header_body_binding(&envelope.header, &envelope.block, profile)?;
        if envelope.encode(profile, consensus_params)?.as_slice() != bytes {
            return Err(V04ExecutionPowError::MalformedEnvelope);
        }
        Ok(envelope)
    }
}

/// Fingerprint only consensus/PoW fields that govern header validation and target derivation.
/// The old generic issuance field is intentionally excluded: QZB4 v2 derives rewards exclusively
/// from its separately pinned V04ConsensusProfileCandidate schedule.
pub fn pow_consensus_profile_fingerprint(
    params: &ConsensusParameters,
) -> Result<[u8; 32], V04ExecutionPowError> {
    params.validate()?;
    let mut hash = Sha256::new();
    hash.update(POW_PROFILE_FINGERPRINT_DOMAIN);
    hash.update(params.protocol_version.to_be_bytes());
    hash.update(params.target_block_time_secs.to_be_bytes());
    hash.update(params.difficulty_window_blocks.to_be_bytes());
    hash.update(params.difficulty_min_ratio_divisor.to_be_bytes());
    hash.update(params.difficulty_max_ratio.to_be_bytes());
    hash.update(params.pow_limit.to_be_bytes());
    hash.update(params.initial_target.to_be_bytes());
    match params.pow.algorithm {
        crate::consensus::PowAlgorithm::Argon2id => hash.update([1]),
    }
    hash.update(params.pow.memory_kib.to_be_bytes());
    hash.update(params.pow.iterations.to_be_bytes());
    hash.update(params.pow.lanes.to_be_bytes());
    hash.update([params.pow.output_bytes]);
    Ok(hash.finalize().into())
}

fn validate_header_body_binding(
    header: &PowHeader,
    block: &V04ExecutionBlockCandidate,
    profile: &V04ConsensusProfileCandidate,
) -> Result<(), V04ExecutionPowError> {
    if header.network_id.iter().all(|byte| *byte == 0) {
        return Err(V04ExecutionPowError::HeaderBodyMismatch("network_id"));
    }
    if header.network_id != *profile.network_id() {
        return Err(V04ExecutionPowError::ProfileMismatch);
    }
    if header.protocol_version == 0 {
        return Err(V04ExecutionPowError::HeaderBodyMismatch("protocol_version"));
    }
    if header.height != block.height {
        return Err(V04ExecutionPowError::HeaderBodyMismatch("height"));
    }
    if header.timestamp != block.timestamp {
        return Err(V04ExecutionPowError::HeaderBodyMismatch("timestamp"));
    }
    if header.parent_hash != block.parent_hash {
        return Err(V04ExecutionPowError::HeaderBodyMismatch("parent_hash"));
    }
    if header.state_root != block.state_root {
        return Err(V04ExecutionPowError::HeaderBodyMismatch("state_root"));
    }
    if header.target.is_zero() {
        return Err(V04ExecutionPowError::HeaderBodyMismatch("target"));
    }
    if block.profile_fingerprint != *profile.profile_fingerprint() {
        return Err(V04ExecutionPowError::ProfileMismatch);
    }
    if block
        .transactions
        .iter()
        .any(|tx| tx.network_id != header.network_id)
    {
        return Err(V04ExecutionPowError::HeaderBodyMismatch(
            "transaction.network_id",
        ));
    }
    Ok(())
}

fn take_slice<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> Result<&'a [u8], V04ExecutionPowError> {
    let end = cursor
        .checked_add(length)
        .ok_or(V04ExecutionPowError::MalformedEnvelope)?;
    if end > bytes.len() {
        return Err(V04ExecutionPowError::MalformedEnvelope);
    }
    let value = &bytes[*cursor..end];
    *cursor = end;
    Ok(value)
}
fn take_array<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], V04ExecutionPowError> {
    take_slice(bytes, cursor, N)?
        .try_into()
        .map_err(|_| V04ExecutionPowError::MalformedEnvelope)
}
fn take_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16, V04ExecutionPowError> {
    Ok(u16::from_be_bytes(take_array(bytes, cursor)?))
}
fn take_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, V04ExecutionPowError> {
    Ok(u32::from_be_bytes(take_array(bytes, cursor)?))
}
fn take_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64, V04ExecutionPowError> {
    Ok(u64::from_be_bytes(take_array(bytes, cursor)?))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V04ExecutionForkChoiceOutcome {
    pub block_digest: [u8; 32],
    pub previous_canonical_tip: [u8; 32],
    pub canonical_tip: [u8; 32],
    pub previous_height: u64,
    pub canonical_height: u64,
    pub canonical_changed: bool,
    pub reorg_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredV04ExecutionBranch {
    envelope: Vec<u8>,
    state: MonetaryLedgerStateV04TransitionCandidate,
    target_history: TargetHistory,
    cumulative_work: Uint256,
    parent_tip: [u8; 32],
}

impl StoredV04ExecutionBranch {
    fn chain_tip(&self, digest: [u8; 32]) -> ChainTip {
        ChainTip {
            height: self.state.ledger().height(),
            cumulative_work: self.cumulative_work,
            tip_hash: digest,
        }
    }
}

/// Bounded in-memory branch graph for QZBE/QZB4 v2.
///
/// Each branch stores its own fully re-executed v0.4 state, difficulty history and cumulative work.
/// No branch is selected by height alone. This is a fork-choice/replay candidate only: durable
/// branch storage, external anti-rollback anchoring and canonical node listener wiring remain open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V04ExecutionForkChoiceCandidate {
    genesis: MonetaryLedgerStateV04TransitionCandidate,
    profile: V04ConsensusProfileCandidate,
    params: ConsensusParameters,
    genesis_tip: [u8; 32],
    canonical_tip: [u8; 32],
    branches: BTreeMap<[u8; 32], StoredV04ExecutionBranch>,
    reorg_count: u64,
}

impl V04ExecutionForkChoiceCandidate {
    pub fn new(
        genesis: MonetaryLedgerStateV04TransitionCandidate,
        params: ConsensusParameters,
    ) -> Result<Self, V04ExecutionPowError> {
        genesis.validate()?;
        params.validate()?;
        let genesis_tip = genesis.ledger().tip_hash();
        let profile = genesis.profile().clone();
        Ok(Self {
            genesis,
            profile,
            params,
            genesis_tip,
            canonical_tip: genesis_tip,
            branches: BTreeMap::new(),
            reorg_count: 0,
        })
    }

    pub fn profile(&self) -> &V04ConsensusProfileCandidate {
        &self.profile
    }

    pub fn canonical_tip(&self) -> [u8; 32] {
        self.canonical_tip
    }

    pub fn genesis_tip(&self) -> [u8; 32] {
        self.genesis_tip
    }

    pub fn canonical_height(&self) -> u64 {
        self.canonical_state().ledger().height()
    }

    pub fn canonical_state(&self) -> &MonetaryLedgerStateV04TransitionCandidate {
        if self.canonical_tip == self.genesis_tip {
            &self.genesis
        } else {
            &self.branches[&self.canonical_tip].state
        }
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
    ) -> Result<Vec<Vec<u8>>, V04ExecutionPowError> {
        if self.branches.len() > max_blocks {
            return Err(V04ExecutionPowError::ArchiveCapacityExceeded);
        }
        let total = self.branches.values().try_fold(0usize, |total, branch| {
            total.checked_add(branch.envelope.len())
        });
        if total.is_none_or(|total| total > max_bytes) {
            return Err(V04ExecutionPowError::ArchiveCapacityExceeded);
        }
        Ok(self.archive_envelopes())
    }

    /// Build the next body/header candidate on a specific known branch. The nonce is supplied by
    /// the caller's mining loop; this method does not claim the resulting nonce satisfies PoW.
    pub fn build_candidate_on<A: TransactionAuthenticator>(
        &self,
        parent_tip: [u8; 32],
        timestamp: u64,
        miner: [u8; 32],
        transactions: Vec<Transaction>,
        nonce: u64,
        authenticator: &A,
    ) -> Result<Vec<u8>, V04ExecutionPowError> {
        let (parent_state, parent_history) = if parent_tip == self.genesis_tip {
            (&self.genesis, TargetHistory::new(self.params.clone())?)
        } else {
            let branch = self
                .branches
                .get(&parent_tip)
                .ok_or(V04ExecutionPowError::UnknownParent)?;
            (&branch.state, branch.target_history.clone())
        };
        let block = parent_state.build_next_execution_block(
            timestamp,
            miner,
            transactions,
            authenticator,
        )?;
        let next_height = block.height;
        let target = parent_history.expected_target(next_height, None)?;
        let envelope = V04ExecutionPowEnvelope {
            consensus_profile_fingerprint: pow_consensus_profile_fingerprint(&self.params)?,
            header: PowHeader {
                protocol_version: self.params.protocol_version,
                network_id: *self.profile.network_id(),
                height: block.height,
                timestamp: block.timestamp,
                parent_hash: block.parent_hash,
                previous_consensus_hash: parent_tip,
                state_root: block.state_root,
                target,
                nonce,
            },
            block,
        };
        Ok(envelope.encode(&self.profile, &self.params)?)
    }

    /// Validate and execute an envelope on its referenced parent, retain it as a branch, then
    /// choose the best tip by exact cumulative work with the repository's deterministic tie-break.
    /// Any invalid header, PoW proof, body, authorization, reward or root leaves the graph unchanged.
    pub fn insert_encoded<A: TransactionAuthenticator>(
        &mut self,
        bytes: &[u8],
        authenticator: &A,
    ) -> Result<V04ExecutionForkChoiceOutcome, V04ExecutionPowError> {
        let envelope = V04ExecutionPowEnvelope::decode(bytes, &self.profile, &self.params)?;
        if envelope.header.height > MAX_V04_EXECUTION_FORK_ARCHIVE_HEIGHT {
            return Err(V04ExecutionPowError::BranchHeightExceeded);
        }
        let digest = verify_pow(&envelope.header, &self.params)?;
        if let Some(existing) = self.branches.get(&digest) {
            if existing.envelope.as_slice() != bytes {
                return Err(V04ExecutionPowError::DuplicateDigestConflict);
            }
            return Ok(V04ExecutionForkChoiceOutcome {
                block_digest: digest,
                previous_canonical_tip: self.canonical_tip,
                canonical_tip: self.canonical_tip,
                previous_height: self.canonical_height(),
                canonical_height: self.canonical_height(),
                canonical_changed: false,
                reorg_count: self.reorg_count,
            });
        }
        if self.branches.len() >= MAX_V04_EXECUTION_FORK_ARCHIVE_BLOCKS {
            return Err(V04ExecutionPowError::ArchiveCapacityExceeded);
        }

        let parent_tip = envelope.header.previous_consensus_hash;
        let (mut staged_state, mut staged_history, parent_work, expected_parent_ledger_tip) =
            if parent_tip == self.genesis_tip {
                (
                    self.genesis.clone(),
                    TargetHistory::new(self.params.clone())?,
                    Uint256::ZERO,
                    self.genesis.ledger().tip_hash(),
                )
            } else {
                let parent = self
                    .branches
                    .get(&parent_tip)
                    .ok_or(V04ExecutionPowError::UnknownParent)?;
                (
                    parent.state.clone(),
                    parent.target_history.clone(),
                    parent.cumulative_work,
                    parent.state.ledger().tip_hash(),
                )
            };

        if envelope.header.network_id != *staged_state.profile().network_id() {
            return Err(V04ExecutionPowError::ProfileMismatch);
        }
        if envelope.header.protocol_version != self.params.protocol_version {
            return Err(V04ExecutionPowError::HeaderBodyMismatch("protocol_version"));
        }
        if envelope.header.parent_hash != expected_parent_ledger_tip {
            return Err(V04ExecutionPowError::HeaderBodyMismatch(
                "parent_ledger_tip",
            ));
        }
        let expected_height =
            staged_state
                .ledger()
                .height()
                .checked_add(1)
                .ok_or(V04ExecutionPowError::History(
                    PrivateConsensusError::Consensus(ConsensusError::InvalidNextBlockHeight),
                ))?;
        if envelope.header.height != expected_height {
            return Err(V04ExecutionPowError::HeaderBodyMismatch("height"));
        }
        let expected_target = staged_history.expected_target(expected_height, None)?;
        if envelope.header.target != expected_target {
            return Err(V04ExecutionPowError::History(
                PrivateConsensusError::ExpectedTargetMismatch,
            ));
        }
        staged_history.validate_next(
            expected_height,
            envelope.header.target,
            envelope.header.timestamp,
        )?;
        let next_work = parent_work
            .checked_add(block_work(envelope.header.target)?)
            .ok_or(V04ExecutionPowError::Consensus(
                ConsensusError::ChainworkOverflow,
            ))?;

        staged_state.apply_execution_block(&envelope.block, authenticator)?;
        staged_history.record_next(
            expected_height,
            envelope.header.target,
            envelope.header.timestamp,
        )?;
        let previous_canonical_tip = self.canonical_tip;
        let previous_height = self.canonical_height();
        self.branches.insert(
            digest,
            StoredV04ExecutionBranch {
                envelope: bytes.to_vec(),
                state: staged_state,
                target_history: staged_history,
                cumulative_work: next_work,
                parent_tip,
            },
        );

        let (best_tip, best_chain_tip) = self.select_best_tip();
        let _best_height = best_chain_tip.height;
        if best_tip != previous_canonical_tip {
            if previous_canonical_tip != self.genesis_tip
                && !self.is_ancestor(previous_canonical_tip, best_tip)
            {
                self.reorg_count = self.reorg_count.saturating_add(1);
            }
            self.canonical_tip = best_tip;
        }
        Ok(V04ExecutionForkChoiceOutcome {
            block_digest: digest,
            previous_canonical_tip,
            canonical_tip: self.canonical_tip,
            previous_height,
            canonical_height: self.canonical_height(),
            canonical_changed: self.canonical_tip != previous_canonical_tip,
            reorg_count: self.reorg_count,
        })
    }

    fn select_best_tip(&self) -> ([u8; 32], ChainTip) {
        let genesis_chain_tip = ChainTip {
            height: self.genesis.ledger().height(),
            cumulative_work: Uint256::ZERO,
            tip_hash: self.genesis_tip,
        };
        let mut best_digest = self.genesis_tip;
        let mut best_tip = genesis_chain_tip;
        for (digest, branch) in &self.branches {
            let chain_tip = branch.chain_tip(*digest);
            if compare_chain_tips(chain_tip, best_tip) == Ordering::Greater {
                best_digest = *digest;
                best_tip = chain_tip;
            }
        }
        (best_digest, best_tip)
    }

    fn is_ancestor(&self, ancestor: [u8; 32], mut tip: [u8; 32]) -> bool {
        if ancestor == self.genesis_tip {
            return true;
        }
        for _ in 0..=MAX_V04_EXECUTION_FORK_ARCHIVE_HEIGHT {
            if tip == ancestor {
                return true;
            }
            if tip == self.genesis_tip {
                return false;
            }
            let Some(branch) = self.branches.get(&tip) else {
                return false;
            };
            tip = branch.parent_tip;
        }
        false
    }

    /// Rebuild a graph by replaying canonical QZBE envelopes from Genesis in height order.
    /// Unknown/missing parents, invalid PoW or state transitions abort the rebuild.
    pub fn rebuild_from_envelopes<A: TransactionAuthenticator>(
        genesis: MonetaryLedgerStateV04TransitionCandidate,
        params: ConsensusParameters,
        envelopes: impl IntoIterator<Item = Vec<u8>>,
        authenticator: &A,
    ) -> Result<Self, V04ExecutionPowError> {
        let profile = genesis.profile().clone();
        let mut ordered = envelopes
            .into_iter()
            .map(|bytes| {
                let envelope = V04ExecutionPowEnvelope::decode(&bytes, &profile, &params)?;
                let digest = pow_digest(&envelope.header, params.pow)?;
                Ok::<_, V04ExecutionPowError>((envelope.header.height, digest, bytes))
            })
            .collect::<Result<Vec<_>, _>>()?;
        ordered.sort_by_key(|(height, digest, _)| (*height, *digest));
        let mut fork_choice = Self::new(genesis, params)?;
        for (_, _, bytes) in ordered {
            fork_choice.insert_encoded(&bytes, authenticator)?;
        }
        Ok(fork_choice)
    }

    pub fn branch_state(
        &self,
        tip: &[u8; 32],
    ) -> Option<&MonetaryLedgerStateV04TransitionCandidate> {
        if *tip == self.genesis_tip {
            Some(&self.genesis)
        } else {
            self.branches.get(tip).map(|branch| &branch.state)
        }
    }

    pub fn branch_work(&self, tip: &[u8; 32]) -> Option<Uint256> {
        if *tip == self.genesis_tip {
            Some(Uint256::ZERO)
        } else {
            self.branches.get(tip).map(|branch| branch.cumulative_work)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        monetary_genesis_v04_candidate::GenesisManifestV04,
        monetary_issuance_v04_candidate::V04MiningIssuanceScheduleCandidate,
        state_machine::{AccountId, Transaction},
    };

    const NETWORK: [u8; 32] = [0x31; 32];
    const OWNER: [u8; 32] = [0xA7; 32];
    const RECIPIENT: [u8; 32] = [0xB2; 32];
    const MINER_A: [u8; 32] = [0xC4; 32];
    const MINER_B: [u8; 32] = [0xD5; 32];

    struct TestAuthenticator;
    impl TransactionAuthenticator for TestAuthenticator {
        fn verify(&self, _: &AccountId, _: &[u8; 32], signature: &[u8]) -> Result<(), ()> {
            if signature == [0x5A] {
                Ok(())
            } else {
                Err(())
            }
        }
    }

    fn profile(initial_subsidy_atoms: u128) -> (GenesisManifestV04, V04ConsensusProfileCandidate) {
        let manifest = GenesisManifestV04::new(NETWORK, OWNER).unwrap();
        let schedule = V04MiningIssuanceScheduleCandidate::new(initial_subsidy_atoms, 2).unwrap();
        let profile =
            V04ConsensusProfileCandidate::from_manifest_and_schedule(&manifest, schedule).unwrap();
        (manifest, profile)
    }

    fn params() -> ConsensusParameters {
        let mut parameters = ConsensusParameters::candidate_testnet().unwrap();
        parameters.initial_target = Uint256::MAX;
        parameters.pow_limit = Uint256::MAX;
        parameters
    }

    fn genesis(
        profile: &V04ConsensusProfileCandidate,
    ) -> MonetaryLedgerStateV04TransitionCandidate {
        MonetaryLedgerStateV04TransitionCandidate::from_genesis_manifest(
            &GenesisManifestV04::new(NETWORK, OWNER).unwrap(),
            profile,
        )
        .unwrap()
    }

    fn transfer() -> Transaction {
        Transaction {
            network_id: NETWORK,
            sender: OWNER,
            recipient: RECIPIENT,
            nonce: 1,
            amount: 2_500,
            fee: 7,
            expires_at: 100,
            signature: vec![0x5A],
        }
    }

    #[test]
    fn qzbe_envelope_roundtrips_and_rejects_implicit_family_or_version_fallback() {
        let (_, profile) = profile(10_000);
        let state = genesis(&profile);
        let graph = V04ExecutionForkChoiceCandidate::new(state, params()).unwrap();
        let encoded = graph
            .build_candidate_on(
                graph.genesis_tip(),
                1,
                MINER_A,
                vec![transfer()],
                7,
                &TestAuthenticator,
            )
            .unwrap();
        let decoded = V04ExecutionPowEnvelope::decode(&encoded, &profile, &params()).unwrap();
        assert_eq!(decoded.block.transactions.len(), 1);
        assert_eq!(decoded.encode(&profile, &params()).unwrap(), encoded);
        let mut alternate_consensus_params = params();
        alternate_consensus_params.target_block_time_secs += 1;
        assert!(matches!(
            V04ExecutionPowEnvelope::decode(&encoded, &profile, &alternate_consensus_params),
            Err(V04ExecutionPowError::ConsensusProfileMismatch)
        ));
        assert!(matches!(
            V04ExecutionPowEnvelope::decode(&encoded[..encoded.len() - 1], &profile, &params()),
            Err(V04ExecutionPowError::MalformedEnvelope)
        ));
        let mut trailing_bytes = encoded.clone();
        trailing_bytes.push(0);
        assert!(matches!(
            V04ExecutionPowEnvelope::decode(&trailing_bytes, &profile, &params()),
            Err(V04ExecutionPowError::MalformedEnvelope)
        ));

        let mut wrong_version = encoded.clone();
        wrong_version[4..6].copy_from_slice(&2u16.to_be_bytes());
        assert!(matches!(
            V04ExecutionPowEnvelope::decode(&wrong_version, &profile, &params()),
            Err(V04ExecutionPowError::UnsupportedEnvelopeVersion(2))
        ));
        assert!(matches!(
            V04ExecutionPowEnvelope::decode(&decoded.block.encode().unwrap(), &profile, &params()),
            Err(V04ExecutionPowError::BadMagic)
        ));
        assert!(matches!(
            V04ExecutionPowEnvelope::decode(b"PMT4\0\x04", &profile, &params()),
            Err(V04ExecutionPowError::MalformedEnvelope | V04ExecutionPowError::BadMagic)
        ));

        let mut changed_header_root = decoded.clone();
        changed_header_root.header.state_root[0] ^= 1;
        assert!(matches!(
            changed_header_root.encode(&profile, &params()),
            Err(V04ExecutionPowError::HeaderBodyMismatch("state_root"))
        ));
    }

    #[test]
    fn branch_local_execution_fork_choice_reorg_and_archive_replay_are_deterministic() {
        let (_, profile) = profile(10_000);
        let genesis = genesis(&profile);
        let mut graph = V04ExecutionForkChoiceCandidate::new(genesis.clone(), params()).unwrap();
        let genesis_tip = graph.genesis_tip();

        let branch_a = graph
            .build_candidate_on(
                genesis_tip,
                1,
                MINER_A,
                vec![transfer()],
                1,
                &TestAuthenticator,
            )
            .unwrap();
        let outcome_a = graph.insert_encoded(&branch_a, &TestAuthenticator).unwrap();
        assert_eq!(outcome_a.canonical_height, 1);

        let branch_b = graph
            .build_candidate_on(genesis_tip, 2, MINER_B, vec![], 2, &TestAuthenticator)
            .unwrap();
        let outcome_b = graph.insert_encoded(&branch_b, &TestAuthenticator).unwrap();
        assert_eq!(outcome_b.canonical_height, 1);
        assert_eq!(graph.archive_len(), 2);

        let digest_a = pow_digest(
            &V04ExecutionPowEnvelope::decode(&branch_a, &profile, &params())
                .unwrap()
                .header,
            params().pow,
        )
        .unwrap();
        let digest_b = pow_digest(
            &V04ExecutionPowEnvelope::decode(&branch_b, &profile, &params())
                .unwrap()
                .header,
            params().pow,
        )
        .unwrap();
        let losing_tip = if graph.canonical_tip() == digest_a {
            digest_b
        } else {
            digest_a
        };
        let extension = graph
            .build_candidate_on(losing_tip, 3, MINER_B, vec![], 3, &TestAuthenticator)
            .unwrap();
        let extension_result = graph
            .insert_encoded(&extension, &TestAuthenticator)
            .unwrap();
        assert_eq!(extension_result.canonical_height, 2);
        assert!(extension_result.canonical_changed);
        assert_eq!(graph.reorg_count(), 1);
        assert_eq!(graph.canonical_state().ledger().height(), 2);
        assert_eq!(
            graph.canonical_state().state_root().unwrap(),
            graph
                .branch_state(&extension_result.canonical_tip)
                .unwrap()
                .state_root()
                .unwrap()
        );

        // Exact replay from the Genesis baseline must select the same cumulative-work tip and state.
        let replayed = V04ExecutionForkChoiceCandidate::rebuild_from_envelopes(
            genesis,
            params(),
            graph.archive_envelopes(),
            &TestAuthenticator,
        )
        .unwrap();
        assert_eq!(replayed.canonical_tip(), graph.canonical_tip());
        assert_eq!(replayed.canonical_height(), graph.canonical_height());
        assert_eq!(
            replayed.canonical_state().state_root().unwrap(),
            graph.canonical_state().state_root().unwrap()
        );
        assert_eq!(
            replayed.branch_work(&replayed.canonical_tip()),
            graph.branch_work(&graph.canonical_tip())
        );
    }

    #[test]
    fn wrong_parent_pow_target_profile_and_state_root_reject_without_graph_mutation() {
        let (manifest, configured_profile) = profile(10_000);
        let mut graph =
            V04ExecutionForkChoiceCandidate::new(genesis(&configured_profile), params()).unwrap();
        let initial_tip = graph.canonical_tip();
        let initial_root = graph.canonical_state().state_root().unwrap();

        let valid = graph
            .build_candidate_on(initial_tip, 1, MINER_A, vec![], 1, &TestAuthenticator)
            .unwrap();

        let mut unknown_parent = valid.clone();
        unknown_parent[120] ^= 0x80; // previous_consensus_hash is bound into the PoW header.
        assert!(matches!(
            graph.insert_encoded(&unknown_parent, &TestAuthenticator),
            Err(V04ExecutionPowError::UnknownParent)
        ));

        let mut wrong_target = valid.clone();
        wrong_target[184] ^= 1;
        assert!(matches!(
            graph.insert_encoded(&wrong_target, &TestAuthenticator),
            Err(V04ExecutionPowError::History(
                PrivateConsensusError::ExpectedTargetMismatch
            ))
        ));

        let mut bad_root = valid.clone();
        bad_root[152] ^= 1; // QZBE header state root.
        let body_len = bad_root.len() - ENVELOPE_HEADER_BYTES;
        bad_root[ENVELOPE_HEADER_BYTES + body_len - 32] ^= 1; // QZB4 body state root.
        assert!(matches!(
            graph.insert_encoded(&bad_root, &TestAuthenticator),
            Err(V04ExecutionPowError::Transition(_))
        ));

        let (_, alternate_profile) = profile(20_000);
        let alternate = V04ExecutionForkChoiceCandidate::new(
            MonetaryLedgerStateV04TransitionCandidate::from_genesis_manifest(
                &manifest,
                &alternate_profile,
            )
            .unwrap(),
            params(),
        )
        .unwrap();
        let cross_profile = alternate
            .build_candidate_on(
                alternate.genesis_tip(),
                1,
                MINER_B,
                vec![],
                9,
                &TestAuthenticator,
            )
            .unwrap();
        assert!(matches!(
            graph.insert_encoded(&cross_profile, &TestAuthenticator),
            Err(V04ExecutionPowError::ProfileMismatch)
        ));

        assert_eq!(graph.archive_len(), 0);
        assert_eq!(graph.canonical_tip(), initial_tip);
        assert_eq!(graph.canonical_state().state_root().unwrap(), initial_root);
    }
}
