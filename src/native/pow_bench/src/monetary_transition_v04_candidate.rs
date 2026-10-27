//! CP-0398/CP-0403 candidate-only profile-bound v0.4 transition contract.
//!
//! QZB4 v1 remains a fixed-width mining-only candidate. QZB4 v2 adds a bounded transaction list and
//! stages transfers, fees, locally derived miner issuance, allocation accounting and the combined
//! state root atomically. This module remains separate from node producer/importer, PoW admission,
//! fork choice, durable stores, and network runtime; it is not a production activation.
//!
//! A QZCP profile requires an explicitly constructed mining schedule. There is no consensus
//! default. Existing QZGM/QZL4, BLK2 and MBK3/MBK4 bytes are not reinterpreted.

use sha2::{Digest, Sha256};

use crate::{
    monetary_allocation_v04_candidate::{
        policy_fingerprint, AllocationAccounting, AllocationAccountingError, AllocationBucket,
        MAX_TOTAL_SUPPLY_ATOMS,
    },
    monetary_genesis_v04_candidate::{GenesisManifestError, GenesisManifestV04},
    monetary_issuance_v04_candidate::{V04MiningIssuanceScheduleCandidate, V04MiningScheduleError},
    monetary_ledger_v04_candidate::{
        MonetaryLedgerStateV04Candidate, V04LedgerGenesisError, V04LedgerSnapshotError,
        MAX_ENCODED_V04_LEDGER_SNAPSHOT_BYTES,
    },
    qzxb_amm_candidate::{
        qzxb_native_asset_id, AmmAssetId, AmmError, AmmOperation, AmmSignedOperation,
        QzxbAmmStateCandidate, SwapReceipt, MAX_AMM_SIGNED_OPERATION_BYTES, MAX_AMM_SNAPSHOT_BYTES,
    },
    state_machine::{
        decode_transaction, encode_transaction, LedgerState, StateError, Transaction,
        TransactionAuthenticator, MAX_ENCODED_BLOCK_BYTES, MAX_TRANSACTIONS_PER_BLOCK,
        MAX_TRANSACTION_BYTES,
    },
};

pub const V04_CONSENSUS_PROFILE_MAGIC: [u8; 4] = *b"QZCP";
pub const V04_CONSENSUS_PROFILE_VERSION: u16 = 1;
pub const V04_MINING_BLOCK_MAGIC: [u8; 4] = *b"QZB4";
pub const V04_MINING_BLOCK_VERSION: u16 = 1;
pub const V04_CONSENSUS_PROFILE_BYTES: usize = 254;
pub const V04_MINING_BLOCK_BYTES: usize = 166;
/// QZB4 v2 carries native transfers; QZB4 v3 adds signed AMM operations.
pub const V04_EXECUTION_BLOCK_VERSION: u16 = 2;
pub const V04_EXECUTION_BLOCK_AMM_VERSION: u16 = 3;
pub const MAX_AMM_OPERATIONS_PER_BLOCK: usize = 128;
const MAX_ENCODED_AMM_SIGNED_OPERATION_BYTES: usize = MAX_AMM_SIGNED_OPERATION_BYTES;
const V04_EXECUTION_BLOCK_FIXED_BYTES: usize = 4 + 2 + 32 + 8 + 8 + 32 + 32 + 16 + 4 + 32;
const V04_EXECUTION_BLOCK_AMM_FIXED_BYTES: usize = V04_EXECUTION_BLOCK_FIXED_BYTES + 4;
// BLK2 transactions are bounded at MAX_ENCODED_BLOCK_BYTES with an 88-byte header.
// QZB4 v2 retains its 170-byte fixed header; v3 adds a bounded AMM-operation count/batch.
pub const MAX_ENCODED_V04_EXECUTION_BLOCK_BYTES: usize = MAX_ENCODED_BLOCK_BYTES
    + (V04_EXECUTION_BLOCK_AMM_FIXED_BYTES - 88)
    + MAX_AMM_OPERATIONS_PER_BLOCK * (4 + MAX_ENCODED_AMM_SIGNED_OPERATION_BYTES);
const EXECUTION_BLOCK_ID_DOMAIN: &[u8] = b"QUANTUMZXB-V04-EXECUTION-BLOCK-ID-CANDIDATE-V1\0";
/// Profile-bound restart envelope; separate from the unprofiled QZL4 format.
pub const V04_PROFILE_BOUND_SNAPSHOT_MAGIC: [u8; 4] = *b"QZP4";
pub const V04_PROFILE_BOUND_SNAPSHOT_VERSION: u16 = 2;
const PROFILE_BOUND_SNAPSHOT_CHECKSUM_DOMAIN: &[u8] =
    b"QUANTUMZXB-V04-PROFILE-BOUND-SNAPSHOT-CHECK-CANDIDATE-V1\0";
const PROFILE_BOUND_SNAPSHOT_HEADER_BYTES: usize = 4 + 2 + 32 + V04_CONSENSUS_PROFILE_BYTES + 4;
const PROFILE_BOUND_SNAPSHOT_FIXED_OVERHEAD: usize = PROFILE_BOUND_SNAPSHOT_HEADER_BYTES + 32 + 32;
pub const MAX_ENCODED_V04_PROFILE_BOUND_SNAPSHOT_BYTES: usize =
    MAX_ENCODED_V04_LEDGER_SNAPSHOT_BYTES
        + MAX_AMM_SNAPSHOT_BYTES
        + PROFILE_BOUND_SNAPSHOT_FIXED_OVERHEAD
        + 4;

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
    MalformedExecutionBlock,
    UnsupportedExecutionBlockVersion(u16),
    ExecutionBlockProfileMismatch,
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
    ProfileBoundSnapshotIncomplete,
    ProfileBoundSnapshotTooLarge,
    WrongProfileBoundSnapshotMagic,
    UnsupportedProfileBoundSnapshotVersion(u16),
    ProfileBoundSnapshotChecksumMismatch,
    ProfileBoundSnapshotWrongLength,
    ProfileBoundSnapshotLengthOverflow,
    ProfileBoundSnapshotNetworkMismatch,
    ProfileBoundSnapshotProfileMismatch,
    ProfileBoundSnapshotStateRootMismatch,
    NonCanonicalProfileBoundSnapshot,
    LedgerSnapshot(V04LedgerSnapshotError),
    Amm(AmmError),
    AmmLedgerBalanceMismatch,
    AmmNativeBalanceOverflow,
    AmmPoolAccountCollision,
    UnsupportedAmmBlockVersion(u16),
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

impl From<V04LedgerSnapshotError> for V04TransitionError {
    fn from(value: V04LedgerSnapshotError) -> Self {
        Self::LedgerSnapshot(value)
    }
}

impl From<AmmError> for V04TransitionError {
    fn from(value: AmmError) -> Self {
        Self::Amm(value)
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

    pub(crate) fn validate_for_manifest(
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

fn profile_bound_snapshot_checksum(preimage: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(PROFILE_BOUND_SNAPSHOT_CHECKSUM_DOMAIN);
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

/// Canonical transaction-bearing v0.4 block. The v1 QZB4 mining-only wire stays intact;
/// this v2 encoding binds the same profile, locally derived issuance and post-execution state root
/// around a bounded list of canonical `Transaction` envelopes. Transaction authorization is
/// delegated to the injected authenticator; the final production signature/key scheme is not chosen here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V04ExecutionBlockCandidate {
    /// Exact wire/consensus version, retained when decoding historical blocks.
    pub wire_version: u16,
    pub profile_fingerprint: [u8; 32],
    pub height: u64,
    pub timestamp: u64,
    pub parent_hash: [u8; 32],
    pub miner: [u8; 32],
    pub claimed_subsidy_atoms: u128,
    pub transactions: Vec<Transaction>,
    pub amm_operations: Vec<AmmSignedOperation>,
    pub state_root: [u8; 32],
}

impl V04ExecutionBlockCandidate {
    pub fn encode(&self) -> Result<Vec<u8>, V04TransitionError> {
        if self.height == 0
            || self.timestamp == 0
            || self.profile_fingerprint.iter().all(|byte| *byte == 0)
            || self.miner.iter().all(|byte| *byte == 0)
            || self.transactions.len() > MAX_TRANSACTIONS_PER_BLOCK
            || self.amm_operations.len() > MAX_AMM_OPERATIONS_PER_BLOCK
            || !matches!(
                self.wire_version,
                V04_EXECUTION_BLOCK_VERSION | V04_EXECUTION_BLOCK_AMM_VERSION
            )
            || (self.wire_version == V04_EXECUTION_BLOCK_VERSION && !self.amm_operations.is_empty())
        {
            return Err(V04TransitionError::MalformedExecutionBlock);
        }
        let mut bytes = Vec::with_capacity(V04_EXECUTION_BLOCK_FIXED_BYTES);
        bytes.extend_from_slice(&V04_MINING_BLOCK_MAGIC);
        bytes.extend_from_slice(&self.wire_version.to_be_bytes());
        bytes.extend_from_slice(&self.profile_fingerprint);
        bytes.extend_from_slice(&self.height.to_be_bytes());
        bytes.extend_from_slice(&self.timestamp.to_be_bytes());
        bytes.extend_from_slice(&self.parent_hash);
        bytes.extend_from_slice(&self.miner);
        bytes.extend_from_slice(&self.claimed_subsidy_atoms.to_be_bytes());
        bytes.extend_from_slice(
            &u32::try_from(self.transactions.len())
                .map_err(|_| V04TransitionError::MalformedExecutionBlock)?
                .to_be_bytes(),
        );
        for transaction in &self.transactions {
            let encoded = encode_transaction(transaction)?;
            if encoded.len() > MAX_TRANSACTION_BYTES {
                return Err(V04TransitionError::MalformedExecutionBlock);
            }
            bytes.extend_from_slice(
                &u32::try_from(encoded.len())
                    .map_err(|_| V04TransitionError::MalformedExecutionBlock)?
                    .to_be_bytes(),
            );
            bytes.extend_from_slice(&encoded);
            if bytes.len().saturating_add(32) > MAX_ENCODED_V04_EXECUTION_BLOCK_BYTES {
                return Err(V04TransitionError::MalformedExecutionBlock);
            }
        }
        if self.wire_version == V04_EXECUTION_BLOCK_AMM_VERSION {
            bytes.extend_from_slice(
                &u32::try_from(self.amm_operations.len())
                    .map_err(|_| V04TransitionError::MalformedExecutionBlock)?
                    .to_be_bytes(),
            );
            for operation in &self.amm_operations {
                let encoded = operation.encode()?;
                if encoded.len() > MAX_ENCODED_AMM_SIGNED_OPERATION_BYTES {
                    return Err(V04TransitionError::MalformedExecutionBlock);
                }
                bytes.extend_from_slice(
                    &u32::try_from(encoded.len())
                        .map_err(|_| V04TransitionError::MalformedExecutionBlock)?
                        .to_be_bytes(),
                );
                bytes.extend_from_slice(&encoded);
                if bytes.len().saturating_add(32) > MAX_ENCODED_V04_EXECUTION_BLOCK_BYTES {
                    return Err(V04TransitionError::MalformedExecutionBlock);
                }
            }
        }
        bytes.extend_from_slice(&self.state_root);
        if bytes.len() > MAX_ENCODED_V04_EXECUTION_BLOCK_BYTES {
            return Err(V04TransitionError::MalformedExecutionBlock);
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, V04TransitionError> {
        if bytes.len() > MAX_ENCODED_V04_EXECUTION_BLOCK_BYTES {
            return Err(V04TransitionError::MalformedExecutionBlock);
        }
        if bytes.len() < 6 {
            return Err(V04TransitionError::MalformedExecutionBlock);
        }
        if bytes[..4] != V04_MINING_BLOCK_MAGIC {
            return Err(V04TransitionError::WrongMiningBlockMagic);
        }
        let version = u16::from_be_bytes([bytes[4], bytes[5]]);
        if !matches!(
            version,
            V04_EXECUTION_BLOCK_VERSION | V04_EXECUTION_BLOCK_AMM_VERSION
        ) {
            return Err(V04TransitionError::UnsupportedExecutionBlockVersion(
                version,
            ));
        }
        let minimum_length = if version == V04_EXECUTION_BLOCK_AMM_VERSION {
            V04_EXECUTION_BLOCK_AMM_FIXED_BYTES
        } else {
            V04_EXECUTION_BLOCK_FIXED_BYTES
        };
        if bytes.len() < minimum_length {
            return Err(V04TransitionError::MalformedExecutionBlock);
        }
        let mut cursor = 6usize;
        let profile_fingerprint = take_v04_execution_array::<32>(bytes, &mut cursor)?;
        let height = take_v04_execution_u64(bytes, &mut cursor)?;
        let timestamp = take_v04_execution_u64(bytes, &mut cursor)?;
        let parent_hash = take_v04_execution_array::<32>(bytes, &mut cursor)?;
        let miner = take_v04_execution_array::<32>(bytes, &mut cursor)?;
        let claimed_subsidy_atoms =
            u128::from_be_bytes(take_v04_execution_array::<16>(bytes, &mut cursor)?);
        let transaction_count = take_v04_execution_u32(bytes, &mut cursor)? as usize;
        if transaction_count > MAX_TRANSACTIONS_PER_BLOCK {
            return Err(V04TransitionError::MalformedExecutionBlock);
        }
        let mut transactions = Vec::with_capacity(transaction_count);
        for _ in 0..transaction_count {
            let length = take_v04_execution_u32(bytes, &mut cursor)? as usize;
            if length == 0 || length > MAX_TRANSACTION_BYTES {
                return Err(V04TransitionError::MalformedExecutionBlock);
            }
            let transaction_bytes = take_v04_execution_slice(bytes, &mut cursor, length)?;
            transactions.push(decode_transaction(transaction_bytes)?);
        }
        let mut amm_operations = Vec::new();
        if version == V04_EXECUTION_BLOCK_AMM_VERSION {
            let operation_count = take_v04_execution_u32(bytes, &mut cursor)? as usize;
            if operation_count > MAX_AMM_OPERATIONS_PER_BLOCK {
                return Err(V04TransitionError::MalformedExecutionBlock);
            }
            amm_operations.reserve(operation_count);
            for _ in 0..operation_count {
                let length = take_v04_execution_u32(bytes, &mut cursor)? as usize;
                if length == 0 || length > MAX_ENCODED_AMM_SIGNED_OPERATION_BYTES {
                    return Err(V04TransitionError::MalformedExecutionBlock);
                }
                let operation_bytes = take_v04_execution_slice(bytes, &mut cursor, length)?;
                amm_operations.push(AmmSignedOperation::decode(operation_bytes)?);
            }
        }
        let state_root = take_v04_execution_array::<32>(bytes, &mut cursor)?;
        if cursor != bytes.len() {
            return Err(V04TransitionError::MalformedExecutionBlock);
        }
        let block = Self {
            wire_version: version,
            profile_fingerprint,
            height,
            timestamp,
            parent_hash,
            miner,
            claimed_subsidy_atoms,
            transactions,
            amm_operations,
            state_root,
        };
        if block.encode()?.as_slice() != bytes {
            return Err(V04TransitionError::MalformedExecutionBlock);
        }
        Ok(block)
    }

    pub fn block_id(&self) -> Result<[u8; 32], V04TransitionError> {
        let canonical = self.encode()?;
        let mut hash = Sha256::new();
        hash.update(EXECUTION_BLOCK_ID_DOMAIN);
        hash.update(canonical);
        Ok(hash.finalize().into())
    }
}

fn take_v04_execution_slice<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> Result<&'a [u8], V04TransitionError> {
    let end = cursor
        .checked_add(length)
        .ok_or(V04TransitionError::MalformedExecutionBlock)?;
    if end > bytes.len() {
        return Err(V04TransitionError::MalformedExecutionBlock);
    }
    let part = &bytes[*cursor..end];
    *cursor = end;
    Ok(part)
}

fn take_v04_execution_array<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], V04TransitionError> {
    take_v04_execution_slice(bytes, cursor, N)?
        .try_into()
        .map_err(|_| V04TransitionError::MalformedExecutionBlock)
}

fn take_v04_execution_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, V04TransitionError> {
    Ok(u32::from_be_bytes(take_v04_execution_array(bytes, cursor)?))
}

fn take_v04_execution_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64, V04TransitionError> {
    Ok(u64::from_be_bytes(take_v04_execution_array(bytes, cursor)?))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V04ExecutionApplySummary {
    pub height: u64,
    pub block_id: [u8; 32],
    pub state_root: [u8; 32],
    pub reward_atoms: u128,
    pub total_mined_atoms: u128,
    pub fees_collected: u64,
    pub transactions_applied: usize,
    pub amm_operations_applied: usize,
    /// Receipts from native swaps in this block; consumers must wait for canonical confirmation policy before indexing candles.
    pub amm_swaps: Vec<SwapReceipt>,
    /// Zero-based AMM-operation positions corresponding one-to-one with amm_swaps.
    pub amm_swap_operation_indices: Vec<usize>,
    pub live_supply_atoms: u128,
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
    amm: QzxbAmmStateCandidate,
    profile: V04ConsensusProfileCandidate,
}

impl MonetaryLedgerStateV04TransitionCandidate {
    pub fn from_genesis_manifest(
        manifest: &GenesisManifestV04,
        profile: &V04ConsensusProfileCandidate,
    ) -> Result<Self, V04TransitionError> {
        profile.validate_for_manifest(manifest)?;
        let genesis = MonetaryLedgerStateV04Candidate::from_genesis_manifest(manifest)?;
        let amm = QzxbAmmStateCandidate::new(profile.network_id, 4_096, 4_096, 65_536)?;
        let state = Self {
            ledger: genesis.ledger().clone(),
            allocation_accounting: genesis.allocation_accounting().clone(),
            total_mined_atoms: genesis.total_mined_atoms(),
            amm,
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

    pub fn amm_state(&self) -> &QzxbAmmStateCandidate {
        &self.amm
    }

    #[cfg(test)]
    pub(crate) fn amm_state_mut_for_test(&mut self) -> &mut QzxbAmmStateCandidate {
        &mut self.amm
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
        if self.amm.has_state() {
            hash.update(b"QZXB-AMM-CONSENSUS-STATE-V1\0");
            hash.update(self.amm.state_root()?);
        }
        Ok(hash.finalize().into())
    }

    pub fn state_root(&self) -> Result<[u8; 32], V04TransitionError> {
        self.validate()?;
        self.compute_state_root()
    }

    pub fn validate(&self) -> Result<(), V04TransitionError> {
        self.profile.validate_internal()?;
        if self.ledger.network_id() != self.profile.network_id
            || self.amm.network_id() != self.profile.network_id
        {
            return Err(V04TransitionError::ProfileBindingMismatch);
        }
        self.amm.verify_invariants()?;
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
            amm: self.amm.clone(),
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
            amm: self.amm.clone(),
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

    /// Encode state and its exact consensus profile in a separate QZP4 envelope.
    /// The inner QZL4 snapshot remains byte-compatible and is not reinterpreted.
    /// The checksums detect corruption, not authenticity or anti-rollback.
    pub fn encode_snapshot(&self) -> Result<Vec<u8>, V04TransitionError> {
        self.validate()?;
        let profile_bytes = self.profile.encode()?;
        let ledger_snapshot = MonetaryLedgerStateV04Candidate::from_transition_parts(
            self.ledger.clone(),
            self.allocation_accounting.clone(),
            self.total_mined_atoms,
        )?
        .encode_snapshot()?;
        let ledger_length = u32::try_from(ledger_snapshot.len())
            .map_err(|_| V04TransitionError::ProfileBoundSnapshotLengthOverflow)?;
        let amm_snapshot = self.amm.encode_snapshot()?;
        let amm_length = u32::try_from(amm_snapshot.len())
            .map_err(|_| V04TransitionError::ProfileBoundSnapshotLengthOverflow)?;
        let committed_root = self.state_root()?;

        let mut bytes = Vec::with_capacity(
            PROFILE_BOUND_SNAPSHOT_FIXED_OVERHEAD
                .checked_add(ledger_snapshot.len())
                .and_then(|value| value.checked_add(4))
                .and_then(|value| value.checked_add(amm_snapshot.len()))
                .ok_or(V04TransitionError::ProfileBoundSnapshotLengthOverflow)?,
        );
        bytes.extend_from_slice(&V04_PROFILE_BOUND_SNAPSHOT_MAGIC);
        bytes.extend_from_slice(&V04_PROFILE_BOUND_SNAPSHOT_VERSION.to_be_bytes());
        bytes.extend_from_slice(self.profile.network_id());
        bytes.extend_from_slice(&profile_bytes);
        bytes.extend_from_slice(&ledger_length.to_be_bytes());
        bytes.extend_from_slice(&ledger_snapshot);
        bytes.extend_from_slice(&amm_length.to_be_bytes());
        bytes.extend_from_slice(&amm_snapshot);
        bytes.extend_from_slice(&committed_root);

        let total_length = bytes
            .len()
            .checked_add(32)
            .ok_or(V04TransitionError::ProfileBoundSnapshotLengthOverflow)?;
        if total_length > MAX_ENCODED_V04_PROFILE_BOUND_SNAPSHOT_BYTES {
            return Err(V04TransitionError::ProfileBoundSnapshotTooLarge);
        }
        let checksum = profile_bound_snapshot_checksum(&bytes);
        bytes.extend_from_slice(&checksum);
        Ok(bytes)
    }

    /// Restore only when both the expected Genesis and explicitly configured profile match.
    /// Unknown versions, profile changes, corrupt nested snapshots and root mismatches fail closed.
    pub fn decode_snapshot(
        bytes: &[u8],
        expected_manifest: &GenesisManifestV04,
        expected_profile: &V04ConsensusProfileCandidate,
    ) -> Result<Self, V04TransitionError> {
        if bytes.len() > MAX_ENCODED_V04_PROFILE_BOUND_SNAPSHOT_BYTES {
            return Err(V04TransitionError::ProfileBoundSnapshotTooLarge);
        }
        if bytes.len() < PROFILE_BOUND_SNAPSHOT_FIXED_OVERHEAD {
            return Err(V04TransitionError::ProfileBoundSnapshotIncomplete);
        }
        expected_profile.validate_for_manifest(expected_manifest)?;

        let checksum_start = bytes.len() - 32;
        if bytes[checksum_start..] != profile_bound_snapshot_checksum(&bytes[..checksum_start]) {
            return Err(V04TransitionError::ProfileBoundSnapshotChecksumMismatch);
        }
        let payload = &bytes[..checksum_start];
        if payload[..4] != V04_PROFILE_BOUND_SNAPSHOT_MAGIC {
            return Err(V04TransitionError::WrongProfileBoundSnapshotMagic);
        }
        let version = u16::from_be_bytes([payload[4], payload[5]]);
        if !matches!(version, 1 | V04_PROFILE_BOUND_SNAPSHOT_VERSION) {
            return Err(V04TransitionError::UnsupportedProfileBoundSnapshotVersion(
                version,
            ));
        }

        let network_id: [u8; 32] = payload[6..38]
            .try_into()
            .map_err(|_| V04TransitionError::ProfileBoundSnapshotWrongLength)?;
        if network_id.iter().all(|byte| *byte == 0)
            || &network_id != expected_profile.network_id()
            || &network_id != expected_manifest.network_id()
        {
            return Err(V04TransitionError::ProfileBoundSnapshotNetworkMismatch);
        }

        let profile_start = 38;
        let profile_end = profile_start + V04_CONSENSUS_PROFILE_BYTES;
        let restored_profile = V04ConsensusProfileCandidate::decode(
            &payload[profile_start..profile_end],
            expected_manifest,
        )?;
        if restored_profile != *expected_profile {
            return Err(V04TransitionError::ProfileBoundSnapshotProfileMismatch);
        }

        let length_start = profile_end;
        let ledger_length = u32::from_be_bytes(
            payload[length_start..length_start + 4]
                .try_into()
                .map_err(|_| V04TransitionError::ProfileBoundSnapshotWrongLength)?,
        ) as usize;
        let ledger_start = PROFILE_BOUND_SNAPSHOT_HEADER_BYTES;
        let ledger_end = ledger_start
            .checked_add(ledger_length)
            .ok_or(V04TransitionError::ProfileBoundSnapshotLengthOverflow)?;
        let ledger_snapshot = &payload[ledger_start..ledger_end];
        let restored_ledger =
            MonetaryLedgerStateV04Candidate::decode_snapshot(ledger_snapshot, &network_id)?;
        if restored_ledger.encode_snapshot()?.as_slice() != ledger_snapshot {
            return Err(V04TransitionError::NonCanonicalProfileBoundSnapshot);
        }

        let (restored_amm, root_start) = if version == 1 {
            // Historical QZP4 v1 snapshots predate the AMM. They are compatible only with
            // the original empty AMM state; the root check below prevents upgrading an active
            // AMM state from a v1 snapshot that cannot represent it.
            (
                QzxbAmmStateCandidate::new(network_id, 4_096, 4_096, 65_536)?,
                ledger_end,
            )
        } else {
            let amm_length_end = ledger_end
                .checked_add(4)
                .ok_or(V04TransitionError::ProfileBoundSnapshotLengthOverflow)?;
            if amm_length_end > payload.len() {
                return Err(V04TransitionError::ProfileBoundSnapshotWrongLength);
            }
            let amm_length = u32::from_be_bytes(
                payload[ledger_end..amm_length_end]
                    .try_into()
                    .map_err(|_| V04TransitionError::ProfileBoundSnapshotWrongLength)?,
            ) as usize;
            let amm_end = amm_length_end
                .checked_add(amm_length)
                .ok_or(V04TransitionError::ProfileBoundSnapshotLengthOverflow)?;
            let expected_payload_length = amm_end
                .checked_add(32)
                .ok_or(V04TransitionError::ProfileBoundSnapshotLengthOverflow)?;
            if payload.len() != expected_payload_length || amm_length == 0 {
                return Err(V04TransitionError::ProfileBoundSnapshotWrongLength);
            }
            let amm_bytes = &payload[amm_length_end..amm_end];
            let amm = QzxbAmmStateCandidate::decode_snapshot(amm_bytes)?;
            if amm.network_id() != network_id || amm.encode_snapshot()?.as_slice() != amm_bytes {
                return Err(V04TransitionError::NonCanonicalProfileBoundSnapshot);
            }
            (amm, amm_end)
        };
        if root_start
            .checked_add(32)
            .ok_or(V04TransitionError::ProfileBoundSnapshotLengthOverflow)?
            != payload.len()
        {
            return Err(V04TransitionError::ProfileBoundSnapshotWrongLength);
        }
        let committed_root: [u8; 32] = payload[root_start..root_start + 32]
            .try_into()
            .map_err(|_| V04TransitionError::ProfileBoundSnapshotWrongLength)?;
        let restored = Self {
            ledger: restored_ledger.ledger().clone(),
            allocation_accounting: restored_ledger.allocation_accounting().clone(),
            total_mined_atoms: restored_ledger.total_mined_atoms(),
            amm: restored_amm,
            profile: restored_profile,
        };
        restored.validate()?;
        if restored.state_root()? != committed_root {
            return Err(V04TransitionError::ProfileBoundSnapshotStateRootMismatch);
        }
        if version == V04_PROFILE_BOUND_SNAPSHOT_VERSION
            && restored.encode_snapshot()?.as_slice() != bytes
        {
            return Err(V04TransitionError::NonCanonicalProfileBoundSnapshot);
        }
        Ok(restored)
    }
}

impl MonetaryLedgerStateV04TransitionCandidate {
    fn reconcile_amm_user_balance(
        amm: &mut QzxbAmmStateCandidate,
        ledger: &LedgerState,
        native_asset: AmmAssetId,
        account: [u8; 32],
    ) -> Result<(), V04TransitionError> {
        if amm.is_pool_account_id(&account) {
            return Err(V04TransitionError::AmmPoolAccountCollision);
        }
        let balance = ledger
            .account(&account)
            .map_or(0, |state| state.balance as u128);
        amm.reconcile_external_balance(native_asset, account, balance)?;
        Ok(())
    }

    fn native_balance_updates(
        amm: &QzxbAmmStateCandidate,
        native_asset: AmmAssetId,
        accounts: &[[u8; 32]],
    ) -> Result<Vec<([u8; 32], u64)>, V04TransitionError> {
        let mut updates = Vec::with_capacity(accounts.len());
        for account in accounts {
            if updates.iter().any(|(existing, _)| existing == account) {
                continue;
            }
            let amount = u64::try_from(amm.balance_of(&native_asset, account))
                .map_err(|_| V04TransitionError::AmmNativeBalanceOverflow)?;
            updates.push((*account, amount));
        }
        Ok(updates)
    }

    fn stage_execution_candidate<A: TransactionAuthenticator>(
        &self,
        height: u64,
        timestamp: u64,
        parent_hash: &[u8; 32],
        miner: &[u8; 32],
        reward_atoms: u128,
        transactions: Vec<Transaction>,
        amm_operations: Vec<AmmSignedOperation>,
        authenticator: &A,
    ) -> Result<(Self, u64, Vec<SwapReceipt>, Vec<usize>), V04TransitionError> {
        let mut amm = self.amm.clone();
        let amm_active = amm.has_state() || !amm_operations.is_empty();
        let native_asset = qzxb_native_asset_id(self.profile.network_id)?;
        if amm_active && !amm.is_asset_registered(&native_asset) {
            amm.register_asset(native_asset)?;
        }

        if amm_active {
            for transaction in &transactions {
                if amm.is_pool_account_id(&transaction.sender)
                    || amm.is_pool_account_id(&transaction.recipient)
                {
                    return Err(V04TransitionError::AmmPoolAccountCollision);
                }
            }
        }

        let (mut ledger, fees_collected) = self.ledger.stage_v04_execution_transition(
            height,
            timestamp,
            parent_hash,
            miner,
            reward_atoms,
            transactions.clone(),
            authenticator,
        )?;

        // QZXB balances in the AMM state are a mirror of the canonical native ledger.
        // Refresh every touched ordinary account after the block's TXN4 transfers.
        if amm_active {
            for transaction in &transactions {
                Self::reconcile_amm_user_balance(
                    &mut amm,
                    &ledger,
                    native_asset,
                    transaction.sender,
                )?;
                Self::reconcile_amm_user_balance(
                    &mut amm,
                    &ledger,
                    native_asset,
                    transaction.recipient,
                )?;
            }
        }

        let mut swap_receipts = Vec::new();
        let mut swap_operation_indices = Vec::new();
        for (operation_index, signed) in amm_operations.iter().enumerate() {
            let sender = signed.sender;
            let current_account = ledger.account(&sender);
            let expected_nonce = current_account
                .map_or(0, |account| account.nonce)
                .checked_add(1)
                .ok_or(V04TransitionError::State(StateError::InvalidNonce(
                    current_account.map_or(0, |account| account.nonce),
                )))?;
            Self::reconcile_amm_user_balance(&mut amm, &ledger, native_asset, sender)?;

            let mut recipient_to_sync = None;
            let mut pool_to_sync = None;
            match &signed.operation {
                AmmOperation::RegisterAsset { .. } => {}
                AmmOperation::MintTestQuote { .. } => {}
                AmmOperation::CreatePair { token_a, token_b } => {
                    let pair_id = QzxbAmmStateCandidate::pair_id_for_assets(*token_a, *token_b)?;
                    if ledger
                        .account(&pair_id)
                        .is_some_and(|account| account.balance != 0 || account.nonce != 0)
                    {
                        return Err(V04TransitionError::AmmPoolAccountCollision);
                    }
                    if *token_a == native_asset || *token_b == native_asset {
                        pool_to_sync = Some(pair_id);
                    }
                }
                AmmOperation::TransferAsset {
                    asset_id,
                    recipient,
                    ..
                } => {
                    if *asset_id == native_asset {
                        Self::reconcile_amm_user_balance(
                            &mut amm,
                            &ledger,
                            native_asset,
                            *recipient,
                        )?;
                        recipient_to_sync = Some(*recipient);
                    }
                }
                AmmOperation::AddLiquidity { pair_id, .. }
                | AmmOperation::RemoveLiquidity { pair_id, .. } => {
                    let (token0, token1) = amm.pair_assets(pair_id)?;
                    if token0 == native_asset || token1 == native_asset {
                        pool_to_sync = Some(*pair_id);
                    }
                }
                AmmOperation::SwapExactIn {
                    token_in,
                    token_out,
                    ..
                } => {
                    let pair_id = QzxbAmmStateCandidate::pair_id_for_assets(*token_in, *token_out)?;
                    let (token0, token1) = amm.pair_assets(&pair_id)?;
                    if token0 == native_asset || token1 == native_asset {
                        pool_to_sync = Some(pair_id);
                    }
                }
            }
            if let Some(pair_id) = pool_to_sync {
                if amm.is_pool_account_id(&pair_id) {
                    let amm_balance = u64::try_from(amm.balance_of(&native_asset, &pair_id))
                        .map_err(|_| V04TransitionError::AmmNativeBalanceOverflow)?;
                    let ledger_balance = ledger
                        .account(&pair_id)
                        .map_or(0, |account| account.balance);
                    if amm_balance != ledger_balance {
                        return Err(V04TransitionError::AmmLedgerBalanceMismatch);
                    }
                }
            }

            let receipt = amm.apply_signed_operation_with_expected_nonce(
                signed,
                timestamp,
                expected_nonce,
                authenticator,
            )?;
            if let Some(receipt) = receipt {
                swap_receipts.push(receipt);
                swap_operation_indices.push(operation_index);
            }

            let mut affected = vec![sender];
            if let Some(recipient) = recipient_to_sync {
                affected.push(recipient);
            }
            if let Some(pair_id) = pool_to_sync {
                affected.push(pair_id);
            }
            let balance_updates = Self::native_balance_updates(&amm, native_asset, &affected)?;
            ledger.apply_amm_account_updates(sender, signed.nonce, &balance_updates)?;
        }

        let mut allocation_accounting = self.allocation_accounting.clone();
        if reward_atoms != 0 {
            allocation_accounting
                .record_issuance(AllocationBucket::MiningNetworkSecurity, reward_atoms)?;
        }
        let total_mined_atoms = self
            .total_mined_atoms
            .checked_add(reward_atoms)
            .ok_or(V04TransitionError::MiningCounterOverflow)?;
        let candidate = Self {
            ledger,
            allocation_accounting,
            total_mined_atoms,
            amm,
            profile: self.profile.clone(),
        };
        candidate.validate()?;
        Ok((
            candidate,
            fees_collected,
            swap_receipts,
            swap_operation_indices,
        ))
    }

    /// Build the next candidate with legacy transactions only. Once the AMM is activated,
    /// the builder emits QZB4 v3 even for blocks that contain no AMM operation.
    pub fn build_next_execution_block<A: TransactionAuthenticator>(
        &self,
        timestamp: u64,
        miner: [u8; 32],
        transactions: Vec<Transaction>,
        authenticator: &A,
    ) -> Result<V04ExecutionBlockCandidate, V04TransitionError> {
        self.build_next_execution_block_with_amm(
            timestamp,
            miner,
            transactions,
            Vec::new(),
            authenticator,
        )
    }

    /// Build a deterministic v3 block carrying both legacy transfers and signed native AMM operations.
    pub fn build_next_execution_block_with_amm<A: TransactionAuthenticator>(
        &self,
        timestamp: u64,
        miner: [u8; 32],
        transactions: Vec<Transaction>,
        amm_operations: Vec<AmmSignedOperation>,
        authenticator: &A,
    ) -> Result<V04ExecutionBlockCandidate, V04TransitionError> {
        self.validate()?;
        if amm_operations.len() > MAX_AMM_OPERATIONS_PER_BLOCK {
            return Err(V04TransitionError::MalformedExecutionBlock);
        }
        let height = self
            .ledger
            .height()
            .checked_add(1)
            .ok_or(V04TransitionError::State(StateError::InvalidHeight))?;
        let parent_hash = self.ledger.tip_hash();
        let reward_atoms = self
            .profile
            .schedule
            .reward_for_height(height, self.total_mined_atoms)?;
        let wire_version = if self.amm.has_state() || !amm_operations.is_empty() {
            V04_EXECUTION_BLOCK_AMM_VERSION
        } else {
            V04_EXECUTION_BLOCK_VERSION
        };
        let (candidate, _, _, _) = self.stage_execution_candidate(
            height,
            timestamp,
            &parent_hash,
            &miner,
            reward_atoms,
            transactions.clone(),
            amm_operations.clone(),
            authenticator,
        )?;
        Ok(V04ExecutionBlockCandidate {
            wire_version,
            profile_fingerprint: *self.profile.profile_fingerprint(),
            height,
            timestamp,
            parent_hash,
            miner,
            claimed_subsidy_atoms: reward_atoms,
            transactions,
            amm_operations,
            state_root: candidate.compute_state_root()?,
        })
    }

    /// Independently execute transactions and derive reward from the local parent/profile.
    /// Accounts, fee pool, allocation counters, cumulative issuance and state root publish together
    /// only after every validation succeeds. The outer block ID is committed last.
    pub fn apply_execution_block<A: TransactionAuthenticator>(
        &mut self,
        block: &V04ExecutionBlockCandidate,
        authenticator: &A,
    ) -> Result<V04ExecutionApplySummary, V04TransitionError> {
        block.encode()?;
        self.validate()?;
        if block.profile_fingerprint != *self.profile.profile_fingerprint() {
            return Err(V04TransitionError::ExecutionBlockProfileMismatch);
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
        if block.wire_version == V04_EXECUTION_BLOCK_VERSION
            && (self.amm.has_state() || !block.amm_operations.is_empty())
        {
            return Err(V04TransitionError::UnsupportedAmmBlockVersion(
                block.wire_version,
            ));
        }
        if block.wire_version == V04_EXECUTION_BLOCK_AMM_VERSION
            && !self.amm.has_state()
            && block.amm_operations.is_empty()
        {
            return Err(V04TransitionError::UnsupportedAmmBlockVersion(
                block.wire_version,
            ));
        }
        let (mut candidate, _fees_collected, amm_swaps, amm_swap_operation_indices) = self
            .stage_execution_candidate(
                block.height,
                block.timestamp,
                &block.parent_hash,
                &block.miner,
                expected_reward,
                block.transactions.clone(),
                block.amm_operations.clone(),
                authenticator,
            )?;
        if candidate.compute_state_root()? != block.state_root {
            return Err(V04TransitionError::StateRootMismatch);
        }
        let block_id = block.block_id()?;
        candidate
            .ledger
            .commit_v04_mining_tip_hash(&block.parent_hash, block_id)?;
        candidate.validate()?;
        let live_supply_atoms = candidate.allocation_accounting.live_supply_atoms()?;
        let summary = V04ExecutionApplySummary {
            height: block.height,
            block_id,
            state_root: block.state_root,
            reward_atoms: expected_reward,
            total_mined_atoms: candidate.total_mined_atoms,
            fees_collected: block.transactions.iter().try_fold(0u64, |sum, tx| {
                sum.checked_add(tx.fee)
                    .ok_or(V04TransitionError::State(StateError::FeeOverflow))
            })?,
            transactions_applied: block.transactions.len(),
            amm_operations_applied: block.amm_operations.len(),
            amm_swaps,
            amm_swap_operation_indices,
            live_supply_atoms,
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

    #[derive(Clone, Copy)]
    struct TestTransactionAuthenticator {
        reject: bool,
    }

    impl TransactionAuthenticator for TestTransactionAuthenticator {
        fn verify(
            &self,
            _sender: &[u8; 32],
            _digest: &[u8; 32],
            signature: &[u8],
        ) -> Result<(), ()> {
            if self.reject || signature.is_empty() {
                Err(())
            } else {
                Ok(())
            }
        }
    }

    fn valid_transfer() -> Transaction {
        Transaction {
            network_id: NETWORK,
            sender: OWNER,
            recipient: [0xB2; 32],
            nonce: 1,
            amount: 2_500,
            fee: 7,
            expires_at: 100,
            signature: vec![0x5A],
        }
    }

    #[test]
    fn qzb4_v3_authenticated_amm_operations_bind_state_root_and_snapshot() {
        use crate::transaction_auth::{
            AccountPublicKey, Ed25519TransactionAuthenticator, Ed25519TransactionSigner,
            TransactionAuthenticatorKind,
        };

        let signer = Ed25519TransactionSigner::from_seed([0x4D; 32]);
        let genesis = GenesisManifestV04::new(NETWORK, signer.account_id()).unwrap();
        let configured_profile = profile(&genesis, 10_000, 2);
        let mut producer = MonetaryLedgerStateV04TransitionCandidate::from_genesis_manifest(
            &genesis,
            &configured_profile,
        )
        .unwrap();
        let mut importer = producer.clone();
        let authenticator = Ed25519TransactionAuthenticator::select(
            TransactionAuthenticatorKind::Ed25519V1,
            [AccountPublicKey {
                account_id: signer.account_id(),
                public_key: signer.public_key(),
            }],
        )
        .unwrap();

        let quote_asset = [0x55; 32];
        let sign = |nonce: u64, operation: AmmOperation| {
            let mut signed = AmmSignedOperation {
                network_id: NETWORK,
                sender: signer.account_id(),
                nonce,
                expires_at: 1_000,
                operation,
                signature: Vec::new(),
            };
            signed.signature = signer.sign_digest(&signed.signing_digest().unwrap());
            signed
        };

        let register_asset = sign(
            1,
            AmmOperation::RegisterAsset {
                asset_id: quote_asset,
            },
        );
        let block1 = producer
            .build_next_execution_block_with_amm(
                1,
                MINER,
                Vec::new(),
                vec![register_asset],
                &authenticator,
            )
            .unwrap();
        assert_eq!(block1.wire_version, V04_EXECUTION_BLOCK_AMM_VERSION);
        let wire1 = block1.encode().unwrap();
        assert_eq!(V04ExecutionBlockCandidate::decode(&wire1).unwrap(), block1);
        let applied1 = importer
            .apply_execution_block(
                &V04ExecutionBlockCandidate::decode(&wire1).unwrap(),
                &authenticator,
            )
            .unwrap();
        producer
            .apply_execution_block(&block1, &authenticator)
            .unwrap();
        assert_eq!(applied1.amm_operations_applied, 1);
        assert!(importer.amm_state().is_asset_registered(&quote_asset));
        let native_asset = qzxb_native_asset_id(NETWORK).unwrap();
        assert!(importer.amm_state().is_asset_registered(&native_asset));
        assert_eq!(
            importer
                .amm_state()
                .balance_of(&native_asset, &signer.account_id()),
            importer
                .ledger()
                .account(&signer.account_id())
                .unwrap()
                .balance as u128
        );

        let pair_id = QzxbAmmStateCandidate::pair_id_for_assets(native_asset, quote_asset).unwrap();
        let create_pair = sign(
            2,
            AmmOperation::CreatePair {
                token_a: native_asset,
                token_b: quote_asset,
            },
        );
        let block2 = producer
            .build_next_execution_block_with_amm(
                2,
                MINER,
                Vec::new(),
                vec![create_pair],
                &authenticator,
            )
            .unwrap();
        let decoded2 = V04ExecutionBlockCandidate::decode(&block2.encode().unwrap()).unwrap();
        importer
            .apply_execution_block(&decoded2, &authenticator)
            .unwrap();
        producer
            .apply_execution_block(&block2, &authenticator)
            .unwrap();
        assert_eq!(producer.amm_state().pair_count(), 1);
        assert_eq!(producer.amm_state().pair_assets(&pair_id).unwrap(), {
            if native_asset < quote_asset {
                (native_asset, quote_asset)
            } else {
                (quote_asset, native_asset)
            }
        });

        // A corrupted signature is rejected before any pool, nonce, ledger or block-tip state publishes.
        let create_other_asset = sign(
            3,
            AmmOperation::RegisterAsset {
                asset_id: [0x66; 32],
            },
        );
        let valid_block3 = producer
            .build_next_execution_block_with_amm(
                3,
                MINER,
                Vec::new(),
                vec![create_other_asset],
                &authenticator,
            )
            .unwrap();
        let mut tampered_block3 = valid_block3.clone();
        tampered_block3.amm_operations[0].signature[0] ^= 1;
        let before = importer.encode_snapshot().unwrap();
        assert_eq!(
            importer.apply_execution_block(&tampered_block3, &authenticator),
            Err(V04TransitionError::Amm(AmmError::InvalidSignature))
        );
        assert_eq!(importer.encode_snapshot().unwrap(), before);

        let applied3 = importer
            .apply_execution_block(&valid_block3, &authenticator)
            .unwrap();
        producer
            .apply_execution_block(&valid_block3, &authenticator)
            .unwrap();
        assert_eq!(applied3.amm_operations_applied, 1);
        assert!(applied3.amm_swaps.is_empty());
        assert_eq!(importer, producer);

        let snapshot = producer.encode_snapshot().unwrap();
        let restored = MonetaryLedgerStateV04TransitionCandidate::decode_snapshot(
            &snapshot,
            &genesis,
            &configured_profile,
        )
        .unwrap();
        assert_eq!(restored, producer);
        assert_eq!(
            restored.state_root().unwrap(),
            producer.state_root().unwrap()
        );
    }

    #[test]
    fn qzb4_v3_native_swap_updates_canonical_ledger_and_emits_receipt() {
        use crate::transaction_auth::{
            AccountPublicKey, Ed25519TransactionAuthenticator, Ed25519TransactionSigner,
            TransactionAuthenticatorKind,
        };

        // This is explicitly a test-only second-asset Genesis fixture. It proves execution and
        // accounting end-to-end, not that a real USDT bridge or external liquidity exists.
        let signer = Ed25519TransactionSigner::from_seed([0x4E; 32]);
        let genesis = GenesisManifestV04::new(NETWORK, signer.account_id()).unwrap();
        let configured_profile = profile(&genesis, 10_000, 2);
        let mut producer = MonetaryLedgerStateV04TransitionCandidate::from_genesis_manifest(
            &genesis,
            &configured_profile,
        )
        .unwrap();
        let native_asset = qzxb_native_asset_id(NETWORK).unwrap();
        let quote_asset = [0x55; 32];
        producer.amm.register_asset(native_asset).unwrap();
        producer.amm.register_asset(quote_asset).unwrap();
        producer
            .amm
            .credit_genesis_balance(quote_asset, signer.account_id(), 100_000_000_000)
            .unwrap();
        let mut importer = producer.clone();
        let authenticator = Ed25519TransactionAuthenticator::select(
            TransactionAuthenticatorKind::Ed25519V1,
            [AccountPublicKey {
                account_id: signer.account_id(),
                public_key: signer.public_key(),
            }],
        )
        .unwrap();

        let sign = |nonce: u64, operation: AmmOperation| {
            let mut signed = AmmSignedOperation {
                network_id: NETWORK,
                sender: signer.account_id(),
                nonce,
                expires_at: 1_000,
                operation,
                signature: Vec::new(),
            };
            signed.signature = signer.sign_digest(&signed.signing_digest().unwrap());
            signed
        };

        let pair_id = QzxbAmmStateCandidate::pair_id_for_assets(native_asset, quote_asset).unwrap();
        let create_pair = sign(
            1,
            AmmOperation::CreatePair {
                token_a: native_asset,
                token_b: quote_asset,
            },
        );
        let create_block = producer
            .build_next_execution_block_with_amm(
                1,
                MINER,
                Vec::new(),
                vec![create_pair],
                &authenticator,
            )
            .unwrap();
        importer
            .apply_execution_block(
                &V04ExecutionBlockCandidate::decode(&create_block.encode().unwrap()).unwrap(),
                &authenticator,
            )
            .unwrap();
        producer
            .apply_execution_block(&create_block, &authenticator)
            .unwrap();

        let (token0, _) = producer.amm.pair_assets(&pair_id).unwrap();
        let native_deposit = 10_000_000_000u128;
        let quote_deposit = 20_000_000_000u128;
        let (amount0_desired, amount1_desired) = if token0 == native_asset {
            (native_deposit, quote_deposit)
        } else {
            (quote_deposit, native_deposit)
        };
        let add_liquidity = sign(
            2,
            AmmOperation::AddLiquidity {
                pair_id,
                amount0_desired,
                amount1_desired,
                min_lp_shares: 1,
            },
        );
        let liquidity_block = producer
            .build_next_execution_block_with_amm(
                2,
                MINER,
                Vec::new(),
                vec![add_liquidity],
                &authenticator,
            )
            .unwrap();
        let liquidity_summary = importer
            .apply_execution_block(
                &V04ExecutionBlockCandidate::decode(&liquidity_block.encode().unwrap()).unwrap(),
                &authenticator,
            )
            .unwrap();
        producer
            .apply_execution_block(&liquidity_block, &authenticator)
            .unwrap();
        assert_eq!(liquidity_summary.amm_operations_applied, 1);
        assert!(producer.amm.reserves(&pair_id).unwrap().1 > 0);
        assert!(producer.amm.reserves(&pair_id).unwrap().3 > 0);

        let sender_before = producer
            .ledger
            .account(&signer.account_id())
            .unwrap()
            .balance;
        let swap = sign(
            3,
            AmmOperation::SwapExactIn {
                token_in: native_asset,
                token_out: quote_asset,
                amount_in: 1_000_000,
                min_amount_out: 1,
            },
        );
        let swap_block = producer
            .build_next_execution_block_with_amm(3, MINER, Vec::new(), vec![swap], &authenticator)
            .unwrap();
        let swap_summary = importer
            .apply_execution_block(
                &V04ExecutionBlockCandidate::decode(&swap_block.encode().unwrap()).unwrap(),
                &authenticator,
            )
            .unwrap();
        producer
            .apply_execution_block(&swap_block, &authenticator)
            .unwrap();

        assert_eq!(swap_summary.amm_operations_applied, 1);
        assert_eq!(swap_summary.amm_swaps.len(), 1);
        assert_eq!(swap_summary.amm_swap_operation_indices, vec![0]);
        let receipt = &swap_summary.amm_swaps[0];
        assert_eq!(receipt.pair_id, pair_id);
        assert_eq!(receipt.token_in, native_asset);
        assert_eq!(receipt.token_out, quote_asset);
        assert_eq!(receipt.amount_in, 1_000_000);
        assert!(receipt.amount_out > 0);
        assert!(receipt.fee_atoms > 0);
        assert!(
            producer
                .ledger
                .account(&signer.account_id())
                .unwrap()
                .balance
                < sender_before
        );
        assert_eq!(
            producer.amm.balance_of(&native_asset, &signer.account_id()),
            producer
                .ledger
                .account(&signer.account_id())
                .unwrap()
                .balance as u128
        );
        assert_eq!(
            producer.amm.balance_of(&native_asset, &pair_id),
            producer
                .ledger
                .account(&pair_id)
                .map_or(0, |account| account.balance) as u128
        );
        assert_eq!(producer, importer);

        let snapshot = producer.encode_snapshot().unwrap();
        let restored = MonetaryLedgerStateV04TransitionCandidate::decode_snapshot(
            &snapshot,
            &genesis,
            &configured_profile,
        )
        .unwrap();
        assert_eq!(restored, producer);
        assert_eq!(
            restored.state_root().unwrap(),
            producer.state_root().unwrap()
        );
    }

    #[test]
    fn qzb4_v2_execution_producer_importer_and_profile_snapshot_agree() {
        let genesis = manifest();
        let configured_profile = profile(&genesis, 10_000, 2);
        let mut producer = MonetaryLedgerStateV04TransitionCandidate::from_genesis_manifest(
            &genesis,
            &configured_profile,
        )
        .unwrap();
        let mut importer = producer.clone();
        let owner_before = producer.ledger().account(&OWNER).unwrap().balance;
        let transfer = valid_transfer();
        let authenticator = TestTransactionAuthenticator { reject: false };
        let block = producer
            .build_next_execution_block(1, MINER, vec![transfer.clone()], &authenticator)
            .unwrap();
        let encoded = block.encode().unwrap();

        assert_eq!(&encoded[..4], &V04_MINING_BLOCK_MAGIC);
        assert_eq!(
            u16::from_be_bytes([encoded[4], encoded[5]]),
            V04_EXECUTION_BLOCK_VERSION
        );
        assert_eq!(V04ExecutionBlockCandidate::decode(&encoded).unwrap(), block);
        assert!(V04MiningBlockCandidate::decode(&encoded).is_err());
        assert_eq!(
            encoded.len().to_string(),
            vector_value("qzb4_execution_block1_length")
        );
        assert_eq!(hex(&encoded), vector_value("qzb4_execution_block1_hex"));
        assert_eq!(
            hex(&block.state_root),
            vector_value("qzb4_execution_block1_state_root")
        );
        assert_eq!(
            hex(&block.block_id().unwrap()),
            vector_value("qzb4_execution_block1_id")
        );
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            V04ExecutionBlockCandidate::decode(&trailing),
            Err(V04TransitionError::MalformedExecutionBlock)
        );
        assert_eq!(
            V04ExecutionBlockCandidate::decode(&encoded[..encoded.len() - 1]),
            Err(V04TransitionError::MalformedExecutionBlock)
        );
        let mut excessive_count = encoded.clone();
        excessive_count[134..138].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(
            V04ExecutionBlockCandidate::decode(&excessive_count),
            Err(V04TransitionError::MalformedExecutionBlock)
        );
        let v1_block = producer.build_next_block(1, MINER).unwrap();
        assert_eq!(
            V04ExecutionBlockCandidate::decode(&v1_block.encode().unwrap()),
            Err(V04TransitionError::UnsupportedExecutionBlockVersion(
                V04_MINING_BLOCK_VERSION
            ))
        );

        let producer_summary = producer
            .apply_execution_block(&block, &authenticator)
            .unwrap();
        let importer_summary = importer
            .apply_execution_block(&block, &authenticator)
            .unwrap();
        assert_eq!(producer_summary, importer_summary);
        assert_eq!(producer, importer);
        assert_eq!(producer_summary.transactions_applied, 1);
        assert_eq!(producer_summary.fees_collected, transfer.fee);
        assert_eq!(
            producer.ledger().account(&OWNER).unwrap().balance,
            owner_before - transfer.amount - transfer.fee
        );
        assert_eq!(
            producer
                .ledger()
                .account(&transfer.recipient)
                .unwrap()
                .balance,
            transfer.amount
        );
        assert_eq!(
            producer.ledger().account(&MINER).unwrap().balance,
            producer_summary.reward_atoms as u64
        );
        assert_eq!(producer.ledger().fee_pool(), transfer.fee);
        assert_eq!(producer.total_mined_atoms(), producer_summary.reward_atoms);
        assert_eq!(
            producer
                .allocation_accounting()
                .issued_by_bucket_atoms(AllocationBucket::MiningNetworkSecurity),
            producer_summary.reward_atoms
        );
        assert_eq!(
            producer.ledger().total_value().unwrap(),
            producer
                .allocation_accounting()
                .live_supply_atoms()
                .unwrap()
        );
        assert_eq!(producer.ledger().tip_hash(), block.block_id().unwrap());

        let snapshot = producer.encode_snapshot().unwrap();
        let restored = MonetaryLedgerStateV04TransitionCandidate::decode_snapshot(
            &snapshot,
            &genesis,
            &configured_profile,
        )
        .unwrap();
        assert_eq!(restored, producer);
    }

    #[test]
    fn qzb4_v2_execution_rejections_are_atomic_for_bad_signature_reward_profile_and_root() {
        let genesis = manifest();
        let configured_profile = profile(&genesis, 10_000, 2);
        let mut producer = MonetaryLedgerStateV04TransitionCandidate::from_genesis_manifest(
            &genesis,
            &configured_profile,
        )
        .unwrap();
        let valid_authenticator = TestTransactionAuthenticator { reject: false };
        let rejecting_authenticator = TestTransactionAuthenticator { reject: true };
        let block = producer
            .build_next_execution_block(1, MINER, vec![valid_transfer()], &valid_authenticator)
            .unwrap();

        let other_profile = profile(&genesis, 10_001, 2);
        let mut wrong_profile_state =
            MonetaryLedgerStateV04TransitionCandidate::from_genesis_manifest(
                &genesis,
                &other_profile,
            )
            .unwrap();
        let wrong_profile_before = wrong_profile_state.encode_snapshot().unwrap();
        assert_eq!(
            wrong_profile_state.apply_execution_block(&block, &valid_authenticator),
            Err(V04TransitionError::ExecutionBlockProfileMismatch)
        );
        assert_eq!(
            wrong_profile_state.encode_snapshot().unwrap(),
            wrong_profile_before
        );

        let before = producer.encode_snapshot().unwrap();
        let mut forged_reward = block.clone();
        forged_reward.claimed_subsidy_atoms += 1;
        assert!(producer
            .apply_execution_block(&forged_reward, &valid_authenticator)
            .is_err());
        assert_eq!(producer.encode_snapshot().unwrap(), before);

        let mut forged_root = block.clone();
        forged_root.state_root[0] ^= 1;
        assert_eq!(
            producer.apply_execution_block(&forged_root, &valid_authenticator),
            Err(V04TransitionError::StateRootMismatch)
        );
        assert_eq!(producer.encode_snapshot().unwrap(), before);

        assert!(producer
            .apply_execution_block(&block, &rejecting_authenticator)
            .is_err());
        assert_eq!(producer.encode_snapshot().unwrap(), before);

        let mut wrong_parent = block.clone();
        wrong_parent.parent_hash[0] ^= 1;
        assert!(producer
            .apply_execution_block(&wrong_parent, &valid_authenticator)
            .is_err());
        assert_eq!(producer.encode_snapshot().unwrap(), before);

        let mut expired_transfer = block.clone();
        expired_transfer.timestamp = 100;
        expired_transfer.transactions[0].expires_at = 100;
        let mut expected_time_state = producer.clone();
        // The timestamp/expiry rejection must happen before state publication.
        assert!(expected_time_state
            .apply_execution_block(&expired_transfer, &valid_authenticator)
            .is_err());
        assert_eq!(expected_time_state.encode_snapshot().unwrap(), before);
    }

    #[test]
    fn qzp4_profile_bound_snapshot_matches_independent_python_vector_and_roundtrips() {
        let genesis = manifest();
        let profile = profile(&genesis, 10_000, 2);
        let state =
            MonetaryLedgerStateV04TransitionCandidate::from_genesis_manifest(&genesis, &profile)
                .unwrap();
        let bytes = state.encode_snapshot().unwrap();

        assert_eq!(&bytes[..4], &V04_PROFILE_BOUND_SNAPSHOT_MAGIC);
        assert_eq!(
            u16::from_be_bytes([bytes[4], bytes[5]]),
            V04_PROFILE_BOUND_SNAPSHOT_VERSION
        );
        assert_eq!(
            bytes.len().to_string(),
            vector_value("qzp4_genesis_snapshot_length")
        );
        assert_eq!(hex(&bytes), vector_value("qzp4_genesis_snapshot_hex"));
        assert_eq!(
            hex(&Sha256::digest(&bytes)),
            vector_value("qzp4_genesis_snapshot_sha256")
        );

        let restored =
            MonetaryLedgerStateV04TransitionCandidate::decode_snapshot(&bytes, &genesis, &profile)
                .unwrap();
        assert_eq!(restored, state);
        assert_eq!(restored.state_root().unwrap(), state.state_root().unwrap());
    }

    #[test]
    fn qzp4_snapshot_restores_after_mining_with_same_profile_and_tip() {
        let genesis = manifest();
        let profile = profile(&genesis, 10_000, 2);
        let mut state =
            MonetaryLedgerStateV04TransitionCandidate::from_genesis_manifest(&genesis, &profile)
                .unwrap();
        let block = state.build_next_block(1, MINER).unwrap();
        state.apply_block(&block).unwrap();

        let bytes = state.encode_snapshot().unwrap();
        let restored =
            MonetaryLedgerStateV04TransitionCandidate::decode_snapshot(&bytes, &genesis, &profile)
                .unwrap();
        assert_eq!(restored, state);
        assert_eq!(restored.ledger().tip_hash(), state.ledger().tip_hash());
        assert_eq!(restored.state_root().unwrap(), state.state_root().unwrap());
    }

    #[test]
    fn qzp4_snapshot_rejects_wrong_manifest_network_and_schedule() {
        let genesis = manifest();
        let configured_profile = profile(&genesis, 10_000, 2);
        let state = MonetaryLedgerStateV04TransitionCandidate::from_genesis_manifest(
            &genesis,
            &configured_profile,
        )
        .unwrap();
        let bytes = state.encode_snapshot().unwrap();

        let other_schedule = profile(&genesis, 12_000, 2);
        assert_eq!(
            MonetaryLedgerStateV04TransitionCandidate::decode_snapshot(
                &bytes,
                &genesis,
                &other_schedule,
            ),
            Err(V04TransitionError::ProfileBoundSnapshotProfileMismatch)
        );

        let other_genesis = GenesisManifestV04::new(NETWORK, OTHER_OWNER).unwrap();
        let other_profile = profile(&other_genesis, 10_000, 2);
        assert!(matches!(
            MonetaryLedgerStateV04TransitionCandidate::decode_snapshot(
                &bytes,
                &other_genesis,
                &other_profile
            ),
            Err(V04TransitionError::ProfileBindingMismatch)
        ));

        let other_network_genesis = GenesisManifestV04::new([0x77; 32], OWNER).unwrap();
        let other_network_profile = profile(&other_network_genesis, 10_000, 2);
        assert_eq!(
            MonetaryLedgerStateV04TransitionCandidate::decode_snapshot(
                &bytes,
                &other_network_genesis,
                &other_network_profile
            ),
            Err(V04TransitionError::ProfileBoundSnapshotNetworkMismatch)
        );
    }

    #[test]
    fn qzp4_snapshot_rejects_corruption_unknown_version_and_truncation() {
        let genesis = manifest();
        let profile = profile(&genesis, 10_000, 2);
        let state =
            MonetaryLedgerStateV04TransitionCandidate::from_genesis_manifest(&genesis, &profile)
                .unwrap();
        let bytes = state.encode_snapshot().unwrap();

        let mut corrupt = bytes.clone();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert_eq!(
            MonetaryLedgerStateV04TransitionCandidate::decode_snapshot(
                &corrupt, &genesis, &profile
            ),
            Err(V04TransitionError::ProfileBoundSnapshotChecksumMismatch)
        );

        let mut wrong_version = bytes.clone();
        wrong_version[4..6].copy_from_slice(&3u16.to_be_bytes());
        let checksum_start = wrong_version.len() - 32;
        let checksum = profile_bound_snapshot_checksum(&wrong_version[..checksum_start]);
        wrong_version[checksum_start..].copy_from_slice(&checksum);
        assert_eq!(
            MonetaryLedgerStateV04TransitionCandidate::decode_snapshot(
                &wrong_version,
                &genesis,
                &profile
            ),
            Err(V04TransitionError::UnsupportedProfileBoundSnapshotVersion(
                3
            ))
        );

        assert_eq!(
            MonetaryLedgerStateV04TransitionCandidate::decode_snapshot(
                &bytes[..PROFILE_BOUND_SNAPSHOT_FIXED_OVERHEAD - 1],
                &genesis,
                &profile
            ),
            Err(V04TransitionError::ProfileBoundSnapshotIncomplete)
        );
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
