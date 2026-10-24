//! CP-0398 candidate-only profile-bound atomic v0.4 mining transition.
//!
//! This module deliberately does not connect to a node, PoW admission, transaction execution,
//! fork choice, durable storage or a network runtime. It defines a strict, separately versioned
//! profile envelope and an issuance-only transition so those semantics can be tested before any
//! runtime wiring is considered. Existing QZGM/QZL4 and MBK3/MBK4 bytes are not reinterpreted.
//!
//! A profile requires an explicitly constructed mining schedule. There is no consensus default.
//! Blocks bind the profile fingerprint and miner reward; the importer derives the reward from the
//! local parent state and commits ledger balances, accounting and mining counters atomically.

use sha2::{Digest, Sha256};

use crate::{
    monetary_allocation_v04_candidate::{
        policy_fingerprint, AllocationAccounting, AllocationAccountingError, AllocationBucket,
        MAX_TOTAL_SUPPLY_ATOMS,
    },
    monetary_genesis_v04_candidate::{GenesisManifestError, GenesisManifestV04},
    monetary_issuance_v04_candidate::{V04MiningIssuanceScheduleCandidate, V04MiningScheduleError},
    monetary_ledger_v04_candidate::{MonetaryLedgerStateV04Candidate, V04LedgerGenesisError},
    state_machine::{LedgerState, StateError},
};

pub const V04_CONSENSUS_PROFILE_MAGIC: [u8; 4] = *b"QZCP";
pub const V04_CONSENSUS_PROFILE_VERSION: u16 = 1;
pub const V04_MINING_BLOCK_MAGIC: [u8; 4] = *b"QZB4";
pub const V04_MINING_BLOCK_VERSION: u16 = 1;
pub const V04_CONSENSUS_PROFILE_BYTES: usize = 254;
pub const V04_MINING_BLOCK_BYTES: usize = 166;

const PROFILE_FINGERPRINT_DOMAIN: &[u8] =
    b"QUANTUMZXB-V04-CONSENSUS-PROFILE-FINGERPRINT-CANDIDATE-V1\0";
const PROFILE_CHECKSUM_DOMAIN: &[u8] = b"QUANTUMZXB-V04-CONSENSUS-PROFILE-CHECK-CANDIDATE-V1\0";
const TRANSITION_STATE_ROOT_DOMAIN: &[u8] =
    b"QUANTUMZXB-V04-PROFILE-MONETARY-STATE-ROOT-CANDIDATE-V1\0";
const MINING_BLOCK_ID_DOMAIN: &[u8] = b"QUANTUMZXB-V04-MINING-BLOCK-ID-CANDIDATE-V1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V04TransitionError {
    GenesisManifest(GenesisManifestError),
    LedgerGenesis(V04LedgerGenesisError),
    State(StateError),
    Allocation(AllocationAccountingError),
    Schedule(V04MiningScheduleError),
    WrongProfileMagic,
    UnsupportedProfileVersion(u16),
    WrongProfileLength,
    ProfileChecksumMismatch,
    ProfileBindingMismatch,
    ProfileFingerprintMismatch,
    MalformedMiningBlock,
    WrongMiningBlockMagic,
    UnsupportedMiningBlockVersion(u16),
    MiningBlockProfileMismatch,
    MinerRewardMismatch { expected: u128, actual: u128 },
    MiningCounterOverflow,
    MiningCounterMismatch,
    ScheduleCounterMismatch,
    LiveSupplyMismatch,
    SupplyCapExceeded,
    StateRootMismatch,
}

impl From<GenesisManifestError> for V04TransitionError {
    fn from(value: GenesisManifestError) -> Self {
        Self::GenesisManifest(value)
    }
}

impl From<V04LedgerGenesisError> for V04TransitionError {
    fn from(value: V04LedgerGenesisError) -> Self {
        Self::LedgerGenesis(value)
    }
}

impl From<StateError> for V04TransitionError {
    fn from(value: StateError) -> Self {
        Self::State(value)
    }
}

impl From<AllocationAccountingError> for V04TransitionError {
    fn from(value: AllocationAccountingError) -> Self {
        Self::Allocation(value)
    }
}

impl From<V04MiningScheduleError> for V04TransitionError {
    fn from(value: V04MiningScheduleError) -> Self {
        Self::Schedule(value)
    }
}

/// Separate versioned extension to a canonical QZGM v0.4 Genesis manifest.
///
/// The QZGM bytes stay unchanged. This QZCP envelope binds the exact QZGM manifest hash, network,
/// original Genesis root, allocation-policy fingerprint, explicit schedule parameters, schedule
/// fingerprint, and the resulting profile fingerprint. Decode always requires the expected
/// Genesis manifest; a profile cannot be accepted without proving which Genesis it extends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V04ConsensusProfileCandidate {
    network_id: [u8; 32],
    genesis_manifest_hash: [u8; 32],
    genesis_manifest_root: [u8; 32],
    policy_fingerprint: [u8; 32],
    schedule: V04MiningIssuanceScheduleCandidate,
    schedule_fingerprint: [u8; 32],
    profile_fingerprint: [u8; 32],
}

impl V04ConsensusProfileCandidate {
    /// Build a profile only when the caller explicitly supplies a schedule.
    pub fn from_manifest_and_schedule(
        manifest: &GenesisManifestV04,
        schedule: V04MiningIssuanceScheduleCandidate,
    ) -> Result<Self, V04TransitionError> {
        manifest.validate()?;
        let expected_policy = policy_fingerprint();
        if manifest.policy_digest() != &expected_policy {
            return Err(V04TransitionError::ProfileBindingMismatch);
        }
        let genesis_manifest_hash = manifest.manifest_hash()?;
        let schedule_fingerprint = schedule.schedule_fingerprint();
        let mut profile = Self {
            network_id: *manifest.network_id(),
            genesis_manifest_hash,
            genesis_manifest_root: *manifest.initial_state_root(),
            policy_fingerprint: expected_policy,
            schedule,
            schedule_fingerprint,
            profile_fingerprint: [0; 32],
        };
        profile.profile_fingerprint = profile.compute_profile_fingerprint();
        profile.validate_internal()?;
        Ok(profile)
    }

    pub fn network_id(&self) -> &[u8; 32] {
        &self.network_id
    }

    pub fn genesis_manifest_hash(&self) -> &[u8; 32] {
        &self.genesis_manifest_hash
    }

    pub fn genesis_manifest_root(&self) -> &[u8; 32] {
        &self.genesis_manifest_root
    }

    pub fn schedule(&self) -> &V04MiningIssuanceScheduleCandidate {
        &self.schedule
    }

    pub fn schedule_fingerprint(&self) -> &[u8; 32] {
        &self.schedule_fingerprint
    }

    pub fn profile_fingerprint(&self) -> &[u8; 32] {
        &self.profile_fingerprint
    }

    fn compute_profile_fingerprint(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(PROFILE_FINGERPRINT_DOMAIN);
        hash.update(V04_CONSENSUS_PROFILE_VERSION.to_be_bytes());
        hash.update(self.network_id);
        hash.update(self.genesis_manifest_hash);
        hash.update(self.genesis_manifest_root);
        hash.update(self.policy_fingerprint);
        hash.update(self.schedule.initial_subsidy_atoms().to_be_bytes());
        hash.update(self.schedule.blocks_per_halving().to_be_bytes());
        hash.update(self.schedule_fingerprint);
        hash.finalize().into()
    }

    fn validate_internal(&self) -> Result<(), V04TransitionError> {
        if self.policy_fingerprint != policy_fingerprint()
            || self.schedule_fingerprint != self.schedule.schedule_fingerprint()
        {
            return Err(V04TransitionError::ProfileFingerprintMismatch);
        }
        if self.profile_fingerprint != self.compute_profile_fingerprint() {
            return Err(V04TransitionError::ProfileFingerprintMismatch);
        }
        Ok(())
    }

    fn validate_for_manifest(
        &self,
        manifest: &GenesisManifestV04,
    ) -> Result<(), V04TransitionError> {
        manifest.validate()?;
        self.validate_internal()?;
        if self.network_id != *manifest.network_id()
            || self.genesis_manifest_hash != manifest.manifest_hash()?
            || self.genesis_manifest_root != *manifest.initial_state_root()
            || self.policy_fingerprint != *manifest.policy_digest()
        {
            return Err(V04TransitionError::ProfileBindingMismatch);
        }
        Ok(())
    }

    /// Canonical fixed-length profile extension. This is a new format and does not alter QZGM.
    pub fn encode(&self) -> Result<[u8; V04_CONSENSUS_PROFILE_BYTES], V04TransitionError> {
        self.validate_internal()?;
        let mut bytes = Vec::with_capacity(V04_CONSENSUS_PROFILE_BYTES);
        bytes.extend_from_slice(&V04_CONSENSUS_PROFILE_MAGIC);
        bytes.extend_from_slice(&V04_CONSENSUS_PROFILE_VERSION.to_be_bytes());
        bytes.extend_from_slice(&self.network_id);
        bytes.extend_from_slice(&self.genesis_manifest_hash);
        bytes.extend_from_slice(&self.genesis_manifest_root);
        bytes.extend_from_slice(&self.policy_fingerprint);
        bytes.extend_from_slice(&self.schedule.initial_subsidy_atoms().to_be_bytes());
        bytes.extend_from_slice(&self.schedule.blocks_per_halving().to_be_bytes());
        bytes.extend_from_slice(&self.schedule_fingerprint);
        bytes.extend_from_slice(&self.profile_fingerprint);
        let checksum = profile_checksum(&bytes);
        bytes.extend_from_slice(&checksum);
        if bytes.len() != V04_CONSENSUS_PROFILE_BYTES {
            return Err(V04TransitionError::WrongProfileLength);
        }
        bytes
            .try_into()
            .map_err(|_| V04TransitionError::WrongProfileLength)
    }

    /// Decode only against the expected Genesis. Unknown versions, corrupt bytes, a different
    /// manifest, or a mismatching schedule fingerprint fail closed.
    pub fn decode(
        bytes: &[u8],
        expected_manifest: &GenesisManifestV04,
    ) -> Result<Self, V04TransitionError> {
        if bytes.len() != V04_CONSENSUS_PROFILE_BYTES {
            return Err(V04TransitionError::WrongProfileLength);
        }
        if bytes[..4] != V04_CONSENSUS_PROFILE_MAGIC {
            return Err(V04TransitionError::WrongProfileMagic);
        }
        let version = u16::from_be_bytes([bytes[4], bytes[5]]);
        if version != V04_CONSENSUS_PROFILE_VERSION {
            return Err(V04TransitionError::UnsupportedProfileVersion(version));
        }
        let checksum_offset = V04_CONSENSUS_PROFILE_BYTES - 32;
        if bytes[checksum_offset..] != profile_checksum(&bytes[..checksum_offset]) {
            return Err(V04TransitionError::ProfileChecksumMismatch);
        }

        // Offsets are fixed by QZCP v1. Other bound fields are re-derived from the expected
        // manifest and the explicit parameters; exact re-encoding rejects non-canonical bytes.
        let initial_subsidy_atoms =
            u128::from_be_bytes(bytes[134..150].try_into().expect("fixed profile length"));
        let blocks_per_halving =
            u64::from_be_bytes(bytes[150..158].try_into().expect("fixed profile length"));
        let schedule =
            V04MiningIssuanceScheduleCandidate::new(initial_subsidy_atoms, blocks_per_halving)?;
        let profile = Self::from_manifest_and_schedule(expected_manifest, schedule)?;
        if profile.encode()?.as_slice() != bytes {
            return Err(V04TransitionError::ProfileBindingMismatch);
        }
        Ok(profile)
    }
}

fn profile_checksum(preimage: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(PROFILE_CHECKSUM_DOMAIN);
    hash.update(preimage);
    hash.finalize().into()
}

/// Fixed-width candidate mining block. This envelope represents mining issuance only: it does
/// not include transactions or a PoW proof and is not accepted by the live PMT3/PMT4 runtimes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V04MiningBlockCandidate {
    pub profile_fingerprint: [u8; 32],
    pub height: u64,
    pub timestamp: u64,
    pub parent_hash: [u8; 32],
    pub miner: [u8; 32],
    pub claimed_subsidy_atoms: u128,
    pub state_root: [u8; 32],
}

impl V04MiningBlockCandidate {
    pub fn encode(&self) -> Result<[u8; V04_MINING_BLOCK_BYTES], V04TransitionError> {
        if self.height == 0
            || self.timestamp == 0
            || self.profile_fingerprint.iter().all(|byte| *byte == 0)
            || self.miner.iter().all(|byte| *byte == 0)
        {
            return Err(V04TransitionError::MalformedMiningBlock);
        }
        let mut bytes = Vec::with_capacity(V04_MINING_BLOCK_BYTES);
        bytes.extend_from_slice(&V04_MINING_BLOCK_MAGIC);
        bytes.extend_from_slice(&V04_MINING_BLOCK_VERSION.to_be_bytes());
        bytes.extend_from_slice(&self.profile_fingerprint);
        bytes.extend_from_slice(&self.height.to_be_bytes());
        bytes.extend_from_slice(&self.timestamp.to_be_bytes());
        bytes.extend_from_slice(&self.parent_hash);
        bytes.extend_from_slice(&self.miner);
        bytes.extend_from_slice(&self.claimed_subsidy_atoms.to_be_bytes());
        bytes.extend_from_slice(&self.state_root);
        if bytes.len() != V04_MINING_BLOCK_BYTES {
            return Err(V04TransitionError::MalformedMiningBlock);
        }
        bytes
            .try_into()
            .map_err(|_| V04TransitionError::MalformedMiningBlock)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, V04TransitionError> {
        if bytes.len() != V04_MINING_BLOCK_BYTES {
            return Err(V04TransitionError::MalformedMiningBlock);
        }
        if bytes[..4] != V04_MINING_BLOCK_MAGIC {
            return Err(V04TransitionError::WrongMiningBlockMagic);
        }
        let version = u16::from_be_bytes([bytes[4], bytes[5]]);
        if version != V04_MINING_BLOCK_VERSION {
            return Err(V04TransitionError::UnsupportedMiningBlockVersion(version));
        }
        let block = Self {
            profile_fingerprint: bytes[6..38].try_into().expect("fixed block length"),
            height: u64::from_be_bytes(bytes[38..46].try_into().expect("fixed block length")),
            timestamp: u64::from_be_bytes(bytes[46..54].try_into().expect("fixed block length")),
            parent_hash: bytes[54..86].try_into().expect("fixed block length"),
            miner: bytes[86..118].try_into().expect("fixed block length"),
            claimed_subsidy_atoms: u128::from_be_bytes(
                bytes[118..134].try_into().expect("fixed block length"),
            ),
            state_root: bytes[134..166].try_into().expect("fixed block length"),
        };
        if block.encode()?.as_slice() != bytes {
            return Err(V04TransitionError::MalformedMiningBlock);
        }
        Ok(block)
    }

    pub fn block_id(&self) -> Result<[u8; 32], V04TransitionError> {
        let canonical = self.encode()?;
        let mut hash = Sha256::new();
        hash.update(MINING_BLOCK_ID_DOMAIN);
        hash.update(canonical);
        Ok(hash.finalize().into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V04MiningApplySummary {
    pub height: u64,
    pub block_id: [u8; 32],
    pub state_root: [u8; 32],
    pub reward_atoms: u128,
    pub total_mined_atoms: u128,
}

/// Profile-bound v0.4 state. All transitions are staged on clones and published only after the
/// locally derived subsidy, allocation caps, live supply, and post-state root validate together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonetaryLedgerStateV04TransitionCandidate {
    ledger: LedgerState,
    allocation_accounting: AllocationAccounting,
    total_mined_atoms: u128,
    profile: V04ConsensusProfileCandidate,
}

impl MonetaryLedgerStateV04TransitionCandidate {
    pub fn from_genesis_manifest(
        manifest: &GenesisManifestV04,
        profile: &V04ConsensusProfileCandidate,
    ) -> Result<Self, V04TransitionError> {
        profile.validate_for_manifest(manifest)?;
        let genesis = MonetaryLedgerStateV04Candidate::from_genesis_manifest(manifest)?;
        let state = Self {
            ledger: genesis.ledger().clone(),
            allocation_accounting: genesis.allocation_accounting().clone(),
            total_mined_atoms: genesis.total_mined_atoms(),
            profile: profile.clone(),
        };
        state.validate()?;
        Ok(state)
    }

    pub fn ledger(&self) -> &LedgerState {
        &self.ledger
    }

    pub fn allocation_accounting(&self) -> &AllocationAccounting {
        &self.allocation_accounting
    }

    pub fn total_mined_atoms(&self) -> u128 {
        self.total_mined_atoms
    }

    pub fn profile(&self) -> &V04ConsensusProfileCandidate {
        &self.profile
    }

    pub fn total_value_atoms(&self) -> Result<u128, V04TransitionError> {
        Ok(self.ledger.total_value()?)
    }

    fn compute_state_root(&self) -> Result<[u8; 32], V04TransitionError> {
        let allocation_commitment = self.allocation_accounting.commitment()?;
        let mut hash = Sha256::new();
        hash.update(TRANSITION_STATE_ROOT_DOMAIN);
        hash.update(self.profile.profile_fingerprint);
        hash.update(self.ledger.state_root());
        hash.update(allocation_commitment);
        hash.update(self.total_mined_atoms.to_be_bytes());
        Ok(hash.finalize().into())
    }

    pub fn state_root(&self) -> Result<[u8; 32], V04TransitionError> {
        self.validate()?;
        self.compute_state_root()
    }

    pub fn validate(&self) -> Result<(), V04TransitionError> {
        self.profile.validate_internal()?;
        if self.ledger.network_id() != self.profile.network_id {
            return Err(V04TransitionError::ProfileBindingMismatch);
        }
        self.allocation_accounting.validate()?;
        if self.total_mined_atoms
            != self
                .allocation_accounting
                .issued_by_bucket_atoms(AllocationBucket::MiningNetworkSecurity)
        {
            return Err(V04TransitionError::MiningCounterMismatch);
        }
        if self.total_mined_atoms
            > self
                .profile
                .schedule
                .cumulative_issuance_after_blocks(self.ledger.height())
        {
            return Err(V04TransitionError::ScheduleCounterMismatch);
        }
        let gross_issued = self.allocation_accounting.gross_issued_atoms()?;
        if gross_issued > MAX_TOTAL_SUPPLY_ATOMS {
            return Err(V04TransitionError::SupplyCapExceeded);
        }
        let live_supply = self.allocation_accounting.live_supply_atoms()?;
        if self.ledger.total_value()? != live_supply {
            return Err(V04TransitionError::LiveSupplyMismatch);
        }
        Ok(())
    }

    /// Produce a mining-only block from local parent state. The reward is derived locally; no
    /// caller-supplied subsidy is accepted by this builder.
    pub fn build_next_block(
        &self,
        timestamp: u64,
        miner: [u8; 32],
    ) -> Result<V04MiningBlockCandidate, V04TransitionError> {
        self.validate()?;
        let height = self
            .ledger
            .height()
            .checked_add(1)
            .ok_or(V04TransitionError::State(StateError::InvalidHeight))?;
        let parent_hash = self.ledger.tip_hash();
        let reward = self
            .profile
            .schedule
            .reward_for_height(height, self.total_mined_atoms)?;
        let next_ledger = self.ledger.stage_v04_mining_reward_transition(
            height,
            timestamp,
            &parent_hash,
            &miner,
            reward,
        )?;
        let mut next_accounting = self.allocation_accounting.clone();
        if reward != 0 {
            next_accounting.record_issuance(AllocationBucket::MiningNetworkSecurity, reward)?;
        }
        let next_total_mined = self
            .total_mined_atoms
            .checked_add(reward)
            .ok_or(V04TransitionError::MiningCounterOverflow)?;
        let next = Self {
            ledger: next_ledger,
            allocation_accounting: next_accounting,
            total_mined_atoms: next_total_mined,
            profile: self.profile.clone(),
        };
        next.validate()?;
        Ok(V04MiningBlockCandidate {
            profile_fingerprint: *self.profile.profile_fingerprint(),
            height,
            timestamp,
            parent_hash,
            miner,
            claimed_subsidy_atoms: reward,
            state_root: next.compute_state_root()?,
        })
    }

    /// Verify a peer block against this exact parent/profile and atomically publish the resulting
    /// state. Any error leaves the receiver byte-for-byte equivalent to its prior state.
    pub fn apply_block(
        &mut self,
        block: &V04MiningBlockCandidate,
    ) -> Result<V04MiningApplySummary, V04TransitionError> {
        self.validate()?;
        block.encode()?;
        if block.profile_fingerprint != *self.profile.profile_fingerprint() {
            return Err(V04TransitionError::MiningBlockProfileMismatch);
        }
        let expected_height = self
            .ledger
            .height()
            .checked_add(1)
            .ok_or(V04TransitionError::State(StateError::InvalidHeight))?;
        if block.height != expected_height {
            return Err(V04TransitionError::State(StateError::HeightMismatch {
                expected: expected_height,
                actual: block.height,
            }));
        }
        let expected_reward = self
            .profile
            .schedule
            .reward_for_height(block.height, self.total_mined_atoms)?;
        if block.claimed_subsidy_atoms != expected_reward {
            return Err(V04TransitionError::MinerRewardMismatch {
                expected: expected_reward,
                actual: block.claimed_subsidy_atoms,
            });
        }

        let mut candidate_ledger = self.ledger.stage_v04_mining_reward_transition(
            block.height,
            block.timestamp,
            &block.parent_hash,
            &block.miner,
            expected_reward,
        )?;
        let mut candidate_accounting = self.allocation_accounting.clone();
        if expected_reward != 0 {
            candidate_accounting
                .record_issuance(AllocationBucket::MiningNetworkSecurity, expected_reward)?;
        }
        let candidate_total_mined = self
            .total_mined_atoms
            .checked_add(expected_reward)
            .ok_or(V04TransitionError::MiningCounterOverflow)?;
        let mut candidate = Self {
            ledger: candidate_ledger.clone(),
            allocation_accounting: candidate_accounting,
            total_mined_atoms: candidate_total_mined,
            profile: self.profile.clone(),
        };
        candidate.validate()?;
        if candidate.compute_state_root()? != block.state_root {
            return Err(V04TransitionError::StateRootMismatch);
        }

        let block_id = block.block_id()?;
        candidate_ledger.commit_v04_mining_tip_hash(&block.parent_hash, block_id)?;
        candidate.ledger = candidate_ledger;
        candidate.validate()?;
        let summary = V04MiningApplySummary {
            height: block.height,
            block_id,
            state_root: block.state_root,
            reward_atoms: expected_reward,
            total_mined_atoms: candidate.total_mined_atoms,
        };
        *self = candidate;
        Ok(summary)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NETWORK: [u8; 32] = [0x31; 32];
    const OWNER: [u8; 32] = [0xA7; 32];
    const OTHER_OWNER: [u8; 32] = [0xA8; 32];
    const MINER: [u8; 32] = [0xC4; 32];
    const VECTORS: &str =
        include_str!("../../../../simulations/quantumzxb_v04_transition_profile_vectors.txt");

    fn vector_value(name: &str) -> &str {
        VECTORS
            .lines()
            .filter(|line| !line.starts_with('#'))
            .find_map(|line| {
                let (key, value) = line.split_once('=')?;
                (key == name).then_some(value)
            })
            .expect("required CP-0398 independent Python vector")
    }

    fn from_hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let text = std::str::from_utf8(pair).unwrap();
                u8::from_str_radix(text, 16).unwrap()
            })
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            output.push(HEX[(byte >> 4) as usize] as char);
            output.push(HEX[(byte & 0x0f) as usize] as char);
        }
        output
    }

    fn manifest() -> GenesisManifestV04 {
        GenesisManifestV04::new(NETWORK, OWNER).unwrap()
    }

    fn profile(
        manifest: &GenesisManifestV04,
        initial_subsidy_atoms: u128,
        blocks_per_halving: u64,
    ) -> V04ConsensusProfileCandidate {
        let schedule =
            V04MiningIssuanceScheduleCandidate::new(initial_subsidy_atoms, blocks_per_halving)
                .unwrap();
        V04ConsensusProfileCandidate::from_manifest_and_schedule(manifest, schedule).unwrap()
    }

    fn state() -> MonetaryLedgerStateV04TransitionCandidate {
        let genesis = manifest();
        let profile = profile(&genesis, 10_000, 2);
        MonetaryLedgerStateV04TransitionCandidate::from_genesis_manifest(&genesis, &profile)
            .unwrap()
    }

    #[test]
    fn qzcp_profile_roundtrips_and_binds_exact_genesis_and_schedule() {
        let genesis = manifest();
        let profile = profile(&genesis, 10_000, 2);
        let bytes = profile.encode().unwrap();
        assert_eq!(bytes.len(), V04_CONSENSUS_PROFILE_BYTES);
        assert_eq!(&bytes[..4], &V04_CONSENSUS_PROFILE_MAGIC);
        assert_eq!(
            hex(&profile.profile_fingerprint),
            vector_value("profile_fingerprint")
        );
        assert_eq!(
            hex(&profile.schedule_fingerprint),
            vector_value("schedule_fingerprint")
        );
        assert_eq!(
            hex(genesis.initial_state_root()),
            vector_value("qzgm_initial_state_root")
        );
        assert_eq!(
            hex(&genesis.manifest_hash().unwrap()),
            vector_value("qzgm_manifest_hash")
        );
        assert_eq!(
            bytes.as_slice(),
            from_hex(vector_value("qzcp_profile_bytes")).as_slice()
        );
        assert_eq!(
            V04ConsensusProfileCandidate::decode(&genesis.encode().unwrap(), &genesis),
            Err(V04TransitionError::WrongProfileLength)
        );
        assert_eq!(
            V04ConsensusProfileCandidate::decode(&bytes, &genesis).unwrap(),
            profile
        );

        let other_genesis = GenesisManifestV04::new(NETWORK, OTHER_OWNER).unwrap();
        assert_eq!(
            V04ConsensusProfileCandidate::decode(&bytes, &other_genesis),
            Err(V04TransitionError::ProfileBindingMismatch)
        );

        let mut corrupt = bytes;
        corrupt[140] ^= 1;
        assert_eq!(
            V04ConsensusProfileCandidate::decode(&corrupt, &genesis),
            Err(V04TransitionError::ProfileChecksumMismatch)
        );

        let mut wrong_version = bytes;
        wrong_version[5] = 2;
        assert_eq!(
            V04ConsensusProfileCandidate::decode(&wrong_version, &genesis),
            Err(V04TransitionError::UnsupportedProfileVersion(2))
        );

        assert_ne!(profile.profile_fingerprint(), &[0; 32]);
        assert_ne!(
            profile.schedule_fingerprint(),
            profile.profile_fingerprint()
        );
    }

    #[test]
    fn qzb4_block_codec_is_fixed_width_and_canonical() {
        let state = state();
        let block = state.build_next_block(1, MINER).unwrap();
        let bytes = block.encode().unwrap();
        assert_eq!(bytes.len(), V04_MINING_BLOCK_BYTES);
        assert_eq!(&bytes[..4], &V04_MINING_BLOCK_MAGIC);
        assert_eq!(V04MiningBlockCandidate::decode(&bytes).unwrap(), block);

        assert_eq!(
            V04MiningBlockCandidate::decode(&bytes[..bytes.len() - 1]),
            Err(V04TransitionError::MalformedMiningBlock)
        );
        let mut wrong_magic = bytes;
        wrong_magic[0] ^= 0x01;
        assert_eq!(
            V04MiningBlockCandidate::decode(&wrong_magic),
            Err(V04TransitionError::WrongMiningBlockMagic)
        );
        let mut wrong_version = bytes;
        wrong_version[5] = 2;
        assert_eq!(
            V04MiningBlockCandidate::decode(&wrong_version),
            Err(V04TransitionError::UnsupportedMiningBlockVersion(2))
        );
    }

    #[test]
    fn producer_and_importer_derive_identical_reward_roots_and_tip_across_halving() {
        let genesis = manifest();
        let profile = profile(&genesis, 10_000, 2);
        let mut producer =
            MonetaryLedgerStateV04TransitionCandidate::from_genesis_manifest(&genesis, &profile)
                .unwrap();
        assert_eq!(
            hex(&producer.state_root().unwrap()),
            vector_value("transition_genesis_state_root")
        );
        let mut importer = producer.clone();

        for (timestamp, expected_reward) in [(1, 10_000u128), (2, 10_000), (3, 5_000)] {
            let block = producer.build_next_block(timestamp, MINER).unwrap();
            assert_eq!(block.claimed_subsidy_atoms, expected_reward);
            let encoded_block = block.encode().unwrap();
            if timestamp == 1 {
                assert_eq!(hex(&encoded_block), vector_value("qzb4_block1_bytes"));
                assert_eq!(hex(&block.state_root), vector_value("block1_state_root"));
                assert_eq!(
                    hex(&block.block_id().unwrap()),
                    vector_value("qzb4_block1_id")
                );
            }
            let decoded = V04MiningBlockCandidate::decode(&encoded_block).unwrap();
            let imported = importer.apply_block(&decoded).unwrap();
            let produced = producer.apply_block(&block).unwrap();
            assert_eq!(produced, imported);
            assert_eq!(producer, importer);
            assert_eq!(producer.ledger.height(), timestamp);
            assert_eq!(producer.ledger.tip_hash(), block.block_id().unwrap());
            assert_eq!(producer.state_root().unwrap(), block.state_root);
            if timestamp == 1 {
                assert_eq!(
                    hex(&producer.ledger.state_root()),
                    vector_value("block1_ledger_state_root")
                );
                assert_eq!(
                    hex(&producer.allocation_accounting.encode().unwrap()),
                    vector_value("block1_accounting_hex")
                );
            }
        }
        assert_eq!(producer.total_mined_atoms(), 25_000);
        assert_eq!(
            producer
                .allocation_accounting()
                .issued_by_bucket_atoms(AllocationBucket::MiningNetworkSecurity),
            25_000
        );
        assert_eq!(producer.ledger().account(&MINER).unwrap().balance, 25_000);
        producer.validate().unwrap();
    }

    #[test]
    fn forged_reward_wrong_profile_parent_and_root_fail_without_mutating_state() {
        let mut receiver = state();
        let original = receiver.clone();
        let block = receiver.build_next_block(1, MINER).unwrap();

        let mut forged_reward = block.clone();
        forged_reward.claimed_subsidy_atoms += 1;
        assert_eq!(
            receiver.apply_block(&forged_reward),
            Err(V04TransitionError::MinerRewardMismatch {
                expected: 10_000,
                actual: 10_001,
            })
        );
        assert_eq!(receiver, original);

        let mut wrong_profile = block.clone();
        wrong_profile.profile_fingerprint[0] ^= 1;
        assert_eq!(
            receiver.apply_block(&wrong_profile),
            Err(V04TransitionError::MiningBlockProfileMismatch)
        );
        assert_eq!(receiver, original);

        let mut wrong_parent = block.clone();
        wrong_parent.parent_hash[0] ^= 1;
        assert_eq!(
            receiver.apply_block(&wrong_parent),
            Err(V04TransitionError::State(StateError::ParentHashMismatch))
        );
        assert_eq!(receiver, original);

        let mut wrong_root = block.clone();
        wrong_root.state_root[0] ^= 1;
        assert_eq!(
            receiver.apply_block(&wrong_root),
            Err(V04TransitionError::StateRootMismatch)
        );
        assert_eq!(receiver, original);
    }

    #[test]
    fn changed_schedule_is_a_distinct_profile_and_cannot_import_same_block() {
        let genesis = manifest();
        let profile_a = profile(&genesis, 10_000, 2);
        let profile_b = profile(&genesis, 10_001, 2);
        assert_ne!(
            profile_a.profile_fingerprint(),
            profile_b.profile_fingerprint()
        );
        let mut receiver =
            MonetaryLedgerStateV04TransitionCandidate::from_genesis_manifest(&genesis, &profile_b)
                .unwrap();
        let sender =
            MonetaryLedgerStateV04TransitionCandidate::from_genesis_manifest(&genesis, &profile_a)
                .unwrap();
        let block = sender.build_next_block(1, MINER).unwrap();
        let before = receiver.clone();
        assert_eq!(
            receiver.apply_block(&block),
            Err(V04TransitionError::MiningBlockProfileMismatch)
        );
        assert_eq!(receiver, before);
    }

    #[test]
    fn rejected_timestamp_zero_account_and_wrong_height_are_atomic() {
        let state = state();
        let original = state.clone();
        assert_eq!(
            state.build_next_block(0, MINER),
            Err(V04TransitionError::State(StateError::InvalidBlockTimestamp))
        );
        assert_eq!(
            state.build_next_block(1, [0; 32]),
            Err(V04TransitionError::State(StateError::InvalidAccountId))
        );
        let mut wrong_height = state.build_next_block(1, MINER).unwrap();
        wrong_height.height += 1;
        let mut receiver = state.clone();
        assert_eq!(
            receiver.apply_block(&wrong_height),
            Err(V04TransitionError::State(StateError::HeightMismatch {
                expected: 1,
                actual: 2,
            }))
        );
        assert_eq!(receiver, original);
    }
}
