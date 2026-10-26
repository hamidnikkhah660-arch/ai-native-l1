//! CP-0405 candidate QZB4 v2 + PoW envelope and branch-local fork choice.
//!
//! This is deliberately separate from PMT3/PMT4 and the canonical node runtime. The QZBE
//! envelope binds the transaction-bearing QZB4 v2 body to the existing PoW header, target-history,
//! chainwork and replay rules. A caller must supply the exact monetary profile and consensus
//! parameters; this module has no Mainnet defaults and is not a persistent branch store.

use crate::{
    consensus::{
        block_work, compare_chain_tips, pow_digest, ChainTip, ConsensusError, ConsensusParameters,
        PowHeader, Uint256,
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
/// Version 2 binds the canonical QZB4 v2 body into the digest used for PoW and fork choice.
/// Version 1 was a local-only candidate and is intentionally not accepted by this candidate.
pub const V04_EXECUTION_POW_ENVELOPE_VERSION: u16 = 2;
const ENVELOPE_HEADER_BYTES: usize = 228;
const POW_PROFILE_FINGERPRINT_DOMAIN: &[u8] =
    b"QUANTUMZXB-V04-POW-CONSENSUS-PROFILE-CANDIDATE-V2\0";
const QZBE_BODY_BOUND_POW_DOMAIN: &[u8] = b"QUANTUMZXB-QZBE-BODY-BOUND-POW-V2\0";
pub const MAX_ENCODED_V04_EXECUTION_POW_ENVELOPE_BYTES: usize =
    ENVELOPE_HEADER_BYTES + MAX_ENCODED_V04_EXECUTION_BLOCK_BYTES;
pub const MAX_V04_EXECUTION_FORK_ARCHIVE_BLOCKS: usize = 4_096;
pub const MAX_V04_EXECUTION_FORK_ARCHIVE_HEIGHT: u64 = 1_024;
/// Hard cap on work performed by one candidate-mining call. Callers can use the cancellation
/// predicate for a stricter wall-clock or operator policy.
pub const MAX_QZBE_MINING_ATTEMPTS: u32 = 256;

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
    MiningAttemptsInvalid,
    MiningCancelled,
    MiningExhausted,
    MiningNonceOverflow,
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

/// Canonical QZBE v2 envelope containing exactly one canonical QZB4 v2 execution body.
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

/// QZBE v2 digest. The memory-hard header digest is additionally committed to the canonical
/// transaction-bearing QZB4 v2 block ID. This binds all transactions/body bytes into PoW identity,
/// fork choice, branch filenames and parent links without changing the legacy PMT3/PMT4 digest.
pub fn qzbe_pow_digest(
    header: &PowHeader,
    block: &V04ExecutionBlockCandidate,
    params: &ConsensusParameters,
) -> Result<[u8; 32], V04ExecutionPowError> {
    let header_digest = pow_digest(header, params.pow)?;
    let block_id = block.block_id()?;
    let mut hash = Sha256::new();
    hash.update(QZBE_BODY_BOUND_POW_DOMAIN);
    hash.update(header_digest);
    hash.update(block_id);
    Ok(hash.finalize().into())
}

/// Verify QZBE v2 using the body-bound digest rather than the legacy header-only digest.
fn verify_qzbe_pow(
    envelope: &V04ExecutionPowEnvelope,
    params: &ConsensusParameters,
) -> Result<[u8; 32], V04ExecutionPowError> {
    params.validate()?;
    if envelope.header.target.is_zero() {
        return Err(V04ExecutionPowError::Consensus(
            ConsensusError::InvalidTarget,
        ));
    }
    if envelope.header.target > params.pow_limit {
        return Err(V04ExecutionPowError::Consensus(
            ConsensusError::TargetAbovePowLimit,
        ));
    }
    if envelope.header.protocol_version != params.protocol_version {
        return Err(V04ExecutionPowError::Consensus(
            ConsensusError::InvalidProtocolVersion,
        ));
    }
    let digest = qzbe_pow_digest(&envelope.header, &envelope.block, params)?;
    if Uint256::from_be_bytes(digest) <= envelope.header.target {
        Ok(digest)
    } else {
        Err(V04ExecutionPowError::Consensus(
            ConsensusError::PowHashFailed,
        ))
    }
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

    /// Mine a body-bound QZBE v2 candidate using a hard-bounded nonce loop.
    ///
    /// This helper does not mutate the fork graph: callers must still submit the returned bytes
    /// through the normal validation path. The target is derived from the selected parent's
    /// target history, and each attempt hashes the exact block body ID together with its header.
    /// `max_attempts` must be in 1..=MAX_QZBE_MINING_ATTEMPTS; `cancelled` is checked before
    /// every memory-hard hash so the caller can enforce a wall-clock/resource policy.
    pub fn mine_candidate_on<A, F>(
        &self,
        parent_tip: [u8; 32],
        timestamp: u64,
        miner: [u8; 32],
        transactions: Vec<Transaction>,
        first_nonce: u64,
        max_attempts: u32,
        authenticator: &A,
        mut cancelled: F,
    ) -> Result<Vec<u8>, V04ExecutionPowError>
    where
        A: TransactionAuthenticator,
        F: FnMut() -> bool,
    {
        if max_attempts == 0 || max_attempts > MAX_QZBE_MINING_ATTEMPTS {
            return Err(V04ExecutionPowError::MiningAttemptsInvalid);
        }
        let encoded = self.build_candidate_on(
            parent_tip,
            timestamp,
            miner,
            transactions,
            first_nonce,
            authenticator,
        )?;
        let mut envelope = V04ExecutionPowEnvelope::decode(&encoded, &self.profile, &self.params)?;
        if envelope.header.target.is_zero() || envelope.header.target > self.params.pow_limit {
            return Err(V04ExecutionPowError::Consensus(
                if envelope.header.target.is_zero() {
                    ConsensusError::InvalidTarget
                } else {
                    ConsensusError::TargetAbovePowLimit
                },
            ));
        }
        for attempt in 0..max_attempts {
            if cancelled() {
                return Err(V04ExecutionPowError::MiningCancelled);
            }
            let digest = qzbe_pow_digest(&envelope.header, &envelope.block, &self.params)?;
            if Uint256::from_be_bytes(digest) <= envelope.header.target {
                let mined = envelope.encode(&self.profile, &self.params)?;
                // Round-trip the successful candidate through the same consensus verifier so
                // changes to the mining loop cannot silently diverge from import validation.
                verify_qzbe_pow(
                    &V04ExecutionPowEnvelope::decode(&mined, &self.profile, &self.params)?,
                    &self.params,
                )?;
                return Ok(mined);
            }
            if attempt + 1 < max_attempts {
                envelope.header.nonce = envelope
                    .header
                    .nonce
                    .checked_add(1)
                    .ok_or(V04ExecutionPowError::MiningNonceOverflow)?;
            }
        }
        Err(V04ExecutionPowError::MiningExhausted)
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
        let digest = verify_qzbe_pow(&envelope, &self.params)?;
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
                let digest = qzbe_pow_digest(&envelope.header, &envelope.block, &params)?;
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
        // Unit tests need only exercise hashing/binding/target logic, not a production cost profile.
        parameters.initial_target = Uint256::MAX;
        parameters.pow_limit = Uint256::MAX;
        parameters.pow.memory_kib = 8 * 1024;
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

        let mut legacy_version = encoded.clone();
        legacy_version[4..6].copy_from_slice(&1u16.to_be_bytes());
        assert!(matches!(
            V04ExecutionPowEnvelope::decode(&legacy_version, &profile, &params()),
            Err(V04ExecutionPowError::UnsupportedEnvelopeVersion(1))
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

        let envelope_a = V04ExecutionPowEnvelope::decode(&branch_a, &profile, &params()).unwrap();
        let digest_a = qzbe_pow_digest(&envelope_a.header, &envelope_a.block, &params()).unwrap();
        let envelope_b = V04ExecutionPowEnvelope::decode(&branch_b, &profile, &params()).unwrap();
        let digest_b = qzbe_pow_digest(&envelope_b.header, &envelope_b.block, &params()).unwrap();
        let losing_tip = if graph.canonical_tip() == digest_a {
            digest_b
        } else {
            digest_a
        };
        let reorgs_before_extension = graph.reorg_count();
        let extension = graph
            .build_candidate_on(losing_tip, 3, MINER_B, vec![], 3, &TestAuthenticator)
            .unwrap();
        let extension_result = graph
            .insert_encoded(&extension, &TestAuthenticator)
            .unwrap();
        assert_eq!(extension_result.canonical_height, 2);
        assert!(extension_result.canonical_changed);
        assert_eq!(graph.reorg_count(), reorgs_before_extension + 1);
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
    fn bounded_miner_finds_body_bound_pow_under_a_non_max_target() {
        let (_, profile) = profile(10_000);
        let genesis = genesis(&profile);
        let mut parameters = params();
        parameters.initial_target = Uint256::from_be_bytes([0xEF; 32]);
        parameters.pow_limit = Uint256::MAX;
        let mut graph = V04ExecutionForkChoiceCandidate::new(genesis, parameters.clone()).unwrap();

        let encoded = graph
            .mine_candidate_on(
                graph.genesis_tip(),
                1,
                MINER_A,
                vec![transfer()],
                0,
                64,
                &TestAuthenticator,
                || false,
            )
            .unwrap();
        let envelope = V04ExecutionPowEnvelope::decode(&encoded, &profile, &parameters).unwrap();
        assert_ne!(envelope.header.target, Uint256::MAX);
        let digest = qzbe_pow_digest(&envelope.header, &envelope.block, &parameters).unwrap();
        assert!(Uint256::from_be_bytes(digest) <= envelope.header.target);
        assert_eq!(
            graph.archive_len(),
            0,
            "mining must not mutate the branch graph"
        );

        let outcome = graph.insert_encoded(&encoded, &TestAuthenticator).unwrap();
        assert_eq!(outcome.block_digest, digest);
        assert_eq!(outcome.canonical_height, 1);
    }

    #[test]
    fn bounded_miner_honors_cancellation_attempt_limits_and_exhaustion() {
        let (_, profile) = profile(10_000);
        let genesis = genesis(&profile);

        let parameters = params();
        let graph =
            V04ExecutionForkChoiceCandidate::new(genesis.clone(), parameters.clone()).unwrap();
        assert_eq!(
            graph.mine_candidate_on(
                graph.genesis_tip(),
                1,
                MINER_A,
                vec![transfer()],
                0,
                0,
                &TestAuthenticator,
                || false,
            ),
            Err(V04ExecutionPowError::MiningAttemptsInvalid)
        );
        assert_eq!(
            graph.mine_candidate_on(
                graph.genesis_tip(),
                1,
                MINER_A,
                vec![transfer()],
                0,
                MAX_QZBE_MINING_ATTEMPTS + 1,
                &TestAuthenticator,
                || false,
            ),
            Err(V04ExecutionPowError::MiningAttemptsInvalid)
        );
        assert_eq!(
            graph.mine_candidate_on(
                graph.genesis_tip(),
                1,
                MINER_A,
                vec![transfer()],
                0,
                4,
                &TestAuthenticator,
                || true,
            ),
            Err(V04ExecutionPowError::MiningCancelled)
        );
        assert_eq!(graph.archive_len(), 0);

        let mut impossible_target = params();
        impossible_target.initial_target = Uint256::ONE;
        impossible_target.pow_limit = Uint256::MAX;
        let graph = V04ExecutionForkChoiceCandidate::new(genesis, impossible_target).unwrap();
        assert_eq!(
            graph.mine_candidate_on(
                graph.genesis_tip(),
                1,
                MINER_A,
                vec![transfer()],
                0,
                1,
                &TestAuthenticator,
                || false,
            ),
            Err(V04ExecutionPowError::MiningExhausted)
        );
        assert_eq!(graph.archive_len(), 0);
    }

    #[test]
    fn body_permutations_with_same_state_root_have_distinct_pow_identity_and_replay() {
        let (_, profile) = profile(10_000);
        let genesis = genesis(&profile);
        let parameters = params();
        let mut graph =
            V04ExecutionForkChoiceCandidate::new(genesis.clone(), parameters.clone()).unwrap();

        // Give two independent senders funds and establish each sender's nonce.
        let mut fund_a = transfer();
        fund_a.amount = 1_000;
        let mut fund_b = transfer();
        fund_b.recipient = [0xB3; 32];
        fund_b.nonce = 2;
        fund_b.amount = 1_000;
        let funding = graph
            .build_candidate_on(
                graph.genesis_tip(),
                1,
                MINER_A,
                vec![fund_a, fund_b],
                1,
                &TestAuthenticator,
            )
            .unwrap();
        graph.insert_encoded(&funding, &TestAuthenticator).unwrap();
        let parent = graph.canonical_tip();

        // These transactions are independent. Reordering them changes canonical body bytes and
        // block ID, while balances, per-account nonces, and therefore pre-tip state root agree.
        let mut spend_a = transfer();
        spend_a.sender = RECIPIENT;
        spend_a.recipient = OWNER;
        spend_a.amount = 400;
        let mut spend_b = transfer();
        spend_b.sender = [0xB3; 32];
        spend_b.recipient = OWNER;
        spend_b.amount = 400;

        let candidate_a = graph
            .build_candidate_on(
                parent,
                2,
                MINER_A,
                vec![spend_a.clone(), spend_b.clone()],
                2,
                &TestAuthenticator,
            )
            .unwrap();
        let candidate_b = graph
            .build_candidate_on(
                parent,
                2,
                MINER_A,
                vec![spend_b, spend_a],
                2,
                &TestAuthenticator,
            )
            .unwrap();
        let envelope_a =
            V04ExecutionPowEnvelope::decode(&candidate_a, &profile, &parameters).unwrap();
        let envelope_b =
            V04ExecutionPowEnvelope::decode(&candidate_b, &profile, &parameters).unwrap();
        assert_eq!(envelope_a.header, envelope_b.header);
        assert_eq!(envelope_a.block.state_root, envelope_b.block.state_root);
        assert_ne!(
            envelope_a.block.block_id().unwrap(),
            envelope_b.block.block_id().unwrap()
        );

        // Reproduce the old failure explicitly: identical headers had identical old-style digests.
        let legacy_digest_a = pow_digest(&envelope_a.header, parameters.pow).unwrap();
        let legacy_digest_b = pow_digest(&envelope_b.header, parameters.pow).unwrap();
        assert_eq!(legacy_digest_a, legacy_digest_b);

        let digest_a = qzbe_pow_digest(&envelope_a.header, &envelope_a.block, &parameters).unwrap();
        let digest_b = qzbe_pow_digest(&envelope_b.header, &envelope_b.block, &parameters).unwrap();
        assert_ne!(
            digest_a, digest_b,
            "PoW/fork-choice identity must bind the full body"
        );

        graph
            .insert_encoded(&candidate_a, &TestAuthenticator)
            .unwrap();
        graph
            .insert_encoded(&candidate_b, &TestAuthenticator)
            .unwrap();
        assert_eq!(graph.archive_len(), 3);
        let state_a = graph.branch_state(&digest_a).unwrap();
        let state_b = graph.branch_state(&digest_b).unwrap();
        assert_eq!(state_a.state_root().unwrap(), state_b.state_root().unwrap());
        assert_ne!(state_a.ledger().tip_hash(), state_b.ledger().tip_hash());

        let replayed = V04ExecutionForkChoiceCandidate::rebuild_from_envelopes(
            genesis,
            parameters,
            graph.archive_envelopes(),
            &TestAuthenticator,
        )
        .unwrap();
        assert_eq!(replayed.archive_len(), graph.archive_len());
        assert_eq!(replayed.canonical_tip(), graph.canonical_tip());
        assert_eq!(
            replayed.canonical_state().state_root().unwrap(),
            graph.canonical_state().state_root().unwrap()
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
