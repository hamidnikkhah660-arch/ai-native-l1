//! CP-0222-GMR: isolated Rust codec candidate for the CP-0221 GNV4 manifest format.
//!
//! This module is research-only and is not connected to node startup, Genesis creation,
//! block admission, consensus, or migration. Test key bytes are synthetic fixtures and
//! do not represent valid cryptographic public keys. No signature verification occurs.

use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt;

pub const MANIFEST_VERSION: u16 = 4;
pub const PROTOCOL_VERSION: u16 = 4;
pub const STATE_VERSION: u16 = 4;
pub const AUTH_SUITE_HYBRID: u16 = 3;
pub const POW_ALGORITHM_ARGON2ID: u16 = 1;
pub const FEE_POLICY_TRANSFER_TO_PROPOSER: u16 = 1;
pub const ATOM_DECIMALS: u8 = 8;

pub const ED25519_PK_BYTES: usize = 32;
pub const ML_DSA_65_PK_BYTES: usize = 1_952;
pub const ROSTER_ENTRY_BYTES: usize = 2_016;
pub const SIGNER_COUNT: usize = 7;
pub const GUARDIAN_COUNT: usize = 3;

pub const HEADER_BYTES: usize = 53;
pub const SUPPLY_BYTES: usize = 80;
pub const SCHEDULE_BYTES: usize = 42;
pub const GOVERNANCE_HEADER_BYTES: usize = 58;
pub const GOVERNANCE_BYTES: usize = GOVERNANCE_HEADER_BYTES + SIGNER_COUNT * ROSTER_ENTRY_BYTES;
pub const RECOVERY_HEADER_BYTES: usize = 58;
pub const RECOVERY_BYTES: usize = RECOVERY_HEADER_BYTES + GUARDIAN_COUNT * ROSTER_ENTRY_BYTES;
pub const RESOURCE_BYTES: usize = 22;
pub const POW_PROFILE_BYTES: usize = 96;
pub const ARGON_PROFILE_BYTES: usize = 14;
pub const FOUNDER_KEYS_BYTES: usize = 1_984;
pub const MIGRATION_DESCRIPTOR_BYTES: usize = 234;
pub const PREIMAGE_BYTES: usize = HEADER_BYTES
    + SUPPLY_BYTES
    + SCHEDULE_BYTES
    + GOVERNANCE_BYTES
    + RECOVERY_BYTES
    + RESOURCE_BYTES
    + POW_PROFILE_BYTES
    + ARGON_PROFILE_BYTES
    + FOUNDER_KEYS_BYTES
    + MIGRATION_DESCRIPTOR_BYTES;
pub const FULL_MANIFEST_BYTES: usize = PREIMAGE_BYTES + 64;

pub const NETWORK_ID_OFFSET: usize = PREIMAGE_BYTES;
pub const MANIFEST_ID_OFFSET: usize = PREIMAGE_BYTES + 32;
pub const GOVERNANCE_HASH_OFFSET: usize = 201;
pub const RECOVERY_OFFSET: usize = HEADER_BYTES + SUPPLY_BYTES + SCHEDULE_BYTES + GOVERNANCE_BYTES;
pub const RECOVERY_HASH_OFFSET: usize = RECOVERY_OFFSET + 26;
pub const ROSTER_OFFSET: usize = 233;
pub const GUARDIANS_OFFSET: usize = RECOVERY_OFFSET + RECOVERY_HEADER_BYTES;
pub const MIGRATION_OFFSET: usize = PREIMAGE_BYTES - MIGRATION_DESCRIPTOR_BYTES;

const MODE_FRESH: u8 = 1;
const MODE_FORK: u8 = 2;
const ROSTER_THRESHOLD: u8 = 4;
const GUARDIAN_THRESHOLD: u8 = 2;
const NORMAL_ROTATION_DELAY: u64 = 20_160;
const RECOVERY_ROTATION_DELAY: u64 = 80_640;
const ACTIVATION_WINDOW: u64 = 86_400;
const FOUNDER_VESTING_EPOCHS: u16 = 0;

const NETWORK_ID_DOMAIN: &[u8] = b"AIN1-NETWORK-ID-V4\0";
const MANIFEST_ID_DOMAIN: &[u8] = b"AIN1-MANIFEST-V4\0";
const GENESIS_ID_DOMAIN: &[u8] = b"AIN1-GENESIS-V4\0";
const MIGRATION_PLAN_ID_DOMAIN: &[u8] = b"AIN1-MIGRATION-PLAN-ID-V4\0";
const FORK_TRUST_RECORD_DOMAIN: &[u8] = b"AIN1-FORK-ACTIVATION-TRUST-RECORD-ID-V1\0";
const GOV_CONFIG_DOMAIN: &[u8] = b"AIN1-GOV-CONFIG-V4\0";
const RECOVERY_POLICY_DOMAIN: &[u8] = b"AIN1-GOV-RECOVERY-POLICY-V1\0";
const SIGNER_ID_DOMAIN: &[u8] = b"AIN1-GOV-SIGNER-ID-V3\0";
const GUARDIAN_ID_DOMAIN: &[u8] = b"AIN1-GOV-RECOVERY-GUARDIAN-ID-V1\0";

const SUPPLY_FIELDS: [u64; 10] = [
    1_000_000_000_000_000_000,
    400_000_000_000_000_000,
    300_000_000_000_000_000,
    300_000_000_000_000_000,
    30_000_000_000_000_000,
    90_000_000_000_000_000,
    60_000_000_000_000_000,
    30_000_000_000_000_000,
    30_000_000_000_000_000,
    60_000_000_000_000_000,
];
const SCHEDULE_FIELDS: [u64; 5] = [35_673_515_981, 4_204_800, 1, 0, 0];
const MAX_ACCOUNTS: u32 = 100_000;
const MAX_TRANSACTIONS: u16 = 1_024;
const MAX_ACTIONS: u16 = 64;
const MAX_TXN_BYTES: u32 = 8_192;
const MAX_BLOCK_BYTES: u32 = 8_388_608;
const MAX_SNAPSHOT_BYTES: u32 = 8_388_608;
const MAX_PENDING_PROPOSALS: u16 = 4_096;
const TARGET_BLOCK_TIME_SECS: u64 = 30;
const DIFFICULTY_WINDOW_BLOCKS: u64 = 2_016;
const MIN_RETARGET_DIVISOR: u64 = 4;
const MAX_RETARGET_MULTIPLIER: u64 = 4;
const POW_MEMORY_KIB: u32 = 65_536;
const POW_ITERATIONS: u32 = 1;
const POW_LANES: u32 = 1;
const POW_OUTPUT_BYTES: u16 = 32;

const POW_LIMIT: [u8; 32] = [0xff; 32];
const INITIAL_TARGET: [u8; 32] = [
    0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeploymentMode {
    Fresh = MODE_FRESH,
    Fork = MODE_FORK,
}

impl TryFrom<u8> for DeploymentMode {
    type Error = ManifestCodecError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            MODE_FRESH => Ok(Self::Fresh),
            MODE_FORK => Ok(Self::Fork),
            _ => Err(ManifestCodecError::UnknownDeploymentMode),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestCodecError {
    WrongManifestLength,
    Truncated,
    TrailingBytes,
    WrongMagic,
    UnsupportedManifestVersion,
    UnsupportedProtocolVersion,
    UnsupportedStateVersion,
    UnknownDeploymentMode,
    UnsupportedAuthSuite,
    UnsupportedPowAlgorithm,
    UnsupportedFeePolicy,
    InvalidPrecisionOrReservedBytes,
    UnsupportedEconomicProfile,
    UnsupportedScheduleProfile,
    InvalidRosterEpoch,
    InvalidRecoveryEpoch,
    UnsupportedGovernancePolicy,
    UnsupportedRecoveryPolicy,
    NoncanonicalGovernanceRoster,
    NoncanonicalRecoveryRoster,
    SignerIdMismatch,
    GuardianIdMismatch,
    RoleKeyOverlap,
    InvalidFounderKey,
    ZeroIdentitySeed,
    FreshModeHasMigrationAnchor,
    ForkModeIdentitySeedNonzero,
    IncompleteForkAnchor,
    MigrationPlanIdMismatch,
    NetworkIdMismatch,
    GovernanceConfigHashMismatch,
    RecoveryPolicyHashMismatch,
    ManifestIdMismatch,
    UnsupportedResourceProfile,
    UnsupportedPowProfile,
    UnsupportedArgon2idProfile,
    InternalLengthInvariant,
    InvalidGenesisHashInput,
    InvalidForkCommitmentInput,
}

impl fmt::Display for ManifestCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ManifestCodecError {}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn hash_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update(part);
    }
    hash.finalize().into()
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn read_u16(data: &[u8], pos: &mut usize) -> Result<u16, ManifestCodecError> {
    Ok(u16::from_be_bytes(read_array::<2>(data, pos)?))
}

fn read_u32(data: &[u8], pos: &mut usize) -> Result<u32, ManifestCodecError> {
    Ok(u32::from_be_bytes(read_array::<4>(data, pos)?))
}

fn read_u64(data: &[u8], pos: &mut usize) -> Result<u64, ManifestCodecError> {
    Ok(u64::from_be_bytes(read_array::<8>(data, pos)?))
}

fn read_array<const N: usize>(data: &[u8], pos: &mut usize) -> Result<[u8; N], ManifestCodecError> {
    let end = pos.checked_add(N).ok_or(ManifestCodecError::Truncated)?;
    let bytes = data.get(*pos..end).ok_or(ManifestCodecError::Truncated)?;
    *pos = end;
    bytes.try_into().map_err(|_| ManifestCodecError::Truncated)
}

fn expect_u16(
    data: &[u8],
    pos: &mut usize,
    expected: u16,
    error: ManifestCodecError,
) -> Result<(), ManifestCodecError> {
    if read_u16(data, pos)? != expected {
        return Err(error);
    }
    Ok(())
}

fn expect_u32(
    data: &[u8],
    pos: &mut usize,
    expected: u32,
    error: ManifestCodecError,
) -> Result<(), ManifestCodecError> {
    if read_u32(data, pos)? != expected {
        return Err(error);
    }
    Ok(())
}

fn expect_u64(
    data: &[u8],
    pos: &mut usize,
    expected: u64,
    error: ManifestCodecError,
) -> Result<(), ManifestCodecError> {
    if read_u64(data, pos)? != expected {
        return Err(error);
    }
    Ok(())
}

pub fn derive_signer_id(
    ed25519_pk: &[u8; ED25519_PK_BYTES],
    mldsa65_pk: &[u8; ML_DSA_65_PK_BYTES],
) -> [u8; 32] {
    hash_parts(&[SIGNER_ID_DOMAIN, ed25519_pk, mldsa65_pk])
}

pub fn derive_guardian_id(
    ed25519_pk: &[u8; ED25519_PK_BYTES],
    mldsa65_pk: &[u8; ML_DSA_65_PK_BYTES],
) -> [u8; 32] {
    hash_parts(&[
        GUARDIAN_ID_DOMAIN,
        &AUTH_SUITE_HYBRID.to_be_bytes(),
        ed25519_pk,
        mldsa65_pk,
    ])
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerEntry {
    pub signer_id: [u8; 32],
    pub ed25519_pk: [u8; ED25519_PK_BYTES],
    pub mldsa65_pk: [u8; ML_DSA_65_PK_BYTES],
}

impl SignerEntry {
    pub fn from_public_keys(
        ed25519_pk: [u8; ED25519_PK_BYTES],
        mldsa65_pk: [u8; ML_DSA_65_PK_BYTES],
    ) -> Result<Self, ManifestCodecError> {
        if is_zero(&ed25519_pk) || is_zero(&mldsa65_pk) {
            return Err(ManifestCodecError::InvalidFounderKey);
        }
        let signer_id = derive_signer_id(&ed25519_pk, &mldsa65_pk);
        Ok(Self {
            signer_id,
            ed25519_pk,
            mldsa65_pk,
        })
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.signer_id);
        out.extend_from_slice(&self.ed25519_pk);
        out.extend_from_slice(&self.mldsa65_pk);
    }

    fn decode_from(data: &[u8], pos: &mut usize) -> Result<Self, ManifestCodecError> {
        Ok(Self {
            signer_id: read_array(data, pos)?,
            ed25519_pk: read_array(data, pos)?,
            mldsa65_pk: read_array(data, pos)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardianEntry {
    pub guardian_id: [u8; 32],
    pub ed25519_pk: [u8; ED25519_PK_BYTES],
    pub mldsa65_pk: [u8; ML_DSA_65_PK_BYTES],
}

impl GuardianEntry {
    pub fn from_public_keys(
        ed25519_pk: [u8; ED25519_PK_BYTES],
        mldsa65_pk: [u8; ML_DSA_65_PK_BYTES],
    ) -> Result<Self, ManifestCodecError> {
        if is_zero(&ed25519_pk) || is_zero(&mldsa65_pk) {
            return Err(ManifestCodecError::InvalidFounderKey);
        }
        let guardian_id = derive_guardian_id(&ed25519_pk, &mldsa65_pk);
        Ok(Self {
            guardian_id,
            ed25519_pk,
            mldsa65_pk,
        })
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.guardian_id);
        out.extend_from_slice(&self.ed25519_pk);
        out.extend_from_slice(&self.mldsa65_pk);
    }

    fn decode_from(data: &[u8], pos: &mut usize) -> Result<Self, ManifestCodecError> {
        Ok(Self {
            guardian_id: read_array(data, pos)?,
            ed25519_pk: read_array(data, pos)?,
            mldsa65_pk: read_array(data, pos)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MigrationAnchor {
    pub legacy_network_id: [u8; 32],
    pub legacy_manifest_id: [u8; 32],
    pub legacy_genesis_id: [u8; 32],
    pub activation_height: u64,
    pub parent_block_id: [u8; 32],
    pub pre_migration_stv3_root: [u8; 32],
    pub migration_algorithm_id: u16,
    pub migration_policy_hash: [u8; 32],
    pub migration_plan_id: [u8; 32],
}

impl MigrationAnchor {
    fn plan_preimage(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MIGRATION_DESCRIPTOR_BYTES - 32);
        out.extend_from_slice(&self.legacy_network_id);
        out.extend_from_slice(&self.legacy_manifest_id);
        out.extend_from_slice(&self.legacy_genesis_id);
        push_u64(&mut out, self.activation_height);
        out.extend_from_slice(&self.parent_block_id);
        out.extend_from_slice(&self.pre_migration_stv3_root);
        push_u16(&mut out, self.migration_algorithm_id);
        out.extend_from_slice(&self.migration_policy_hash);
        out
    }

    pub fn expected_plan_id(&self) -> [u8; 32] {
        let preimage = self.plan_preimage();
        hash_parts(&[MIGRATION_PLAN_ID_DOMAIN, &preimage])
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.plan_preimage();
        out.extend_from_slice(&self.migration_plan_id);
        out
    }

    fn decode(data: &[u8], pos: &mut usize) -> Result<Self, ManifestCodecError> {
        Ok(Self {
            legacy_network_id: read_array(data, pos)?,
            legacy_manifest_id: read_array(data, pos)?,
            legacy_genesis_id: read_array(data, pos)?,
            activation_height: read_u64(data, pos)?,
            parent_block_id: read_array(data, pos)?,
            pre_migration_stv3_root: read_array(data, pos)?,
            migration_algorithm_id: read_u16(data, pos)?,
            migration_policy_hash: read_array(data, pos)?,
            migration_plan_id: read_array(data, pos)?,
        })
    }

    fn is_zero(&self) -> bool {
        is_zero(&self.encode())
    }

    fn validate_fork(&self) -> Result<(), ManifestCodecError> {
        if is_zero(&self.legacy_network_id)
            || is_zero(&self.legacy_manifest_id)
            || is_zero(&self.legacy_genesis_id)
            || self.activation_height == 0
            || is_zero(&self.parent_block_id)
            || is_zero(&self.pre_migration_stv3_root)
            || self.migration_algorithm_id == 0
            || is_zero(&self.migration_policy_hash)
            || is_zero(&self.migration_plan_id)
        {
            return Err(ManifestCodecError::IncompleteForkAnchor);
        }
        if self.migration_plan_id != self.expected_plan_id() {
            return Err(ManifestCodecError::MigrationPlanIdMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gnv4Manifest {
    pub mode: DeploymentMode,
    pub identity_seed: [u8; 32],
    pub roster_epoch: u64,
    pub recovery_policy_epoch: u64,
    pub founder_ed25519_pk: [u8; ED25519_PK_BYTES],
    pub founder_mldsa65_pk: [u8; ML_DSA_65_PK_BYTES],
    pub roster: Vec<SignerEntry>,
    pub guardians: Vec<GuardianEntry>,
    pub migration: MigrationAnchor,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedGnv4Manifest {
    pub manifest: Gnv4Manifest,
    pub network_id: [u8; 32],
    pub manifest_id: [u8; 32],
    pub bytes: Vec<u8>,
}

impl Gnv4Manifest {
    pub fn network_id(&self) -> Result<[u8; 32], ManifestCodecError> {
        match self.mode {
            DeploymentMode::Fresh => {
                if is_zero(&self.identity_seed) {
                    return Err(ManifestCodecError::ZeroIdentitySeed);
                }
                Ok(hash_parts(&[
                    NETWORK_ID_DOMAIN,
                    &[MODE_FRESH],
                    &self.identity_seed,
                    &PROTOCOL_VERSION.to_be_bytes(),
                    &STATE_VERSION.to_be_bytes(),
                ]))
            }
            DeploymentMode::Fork => {
                self.migration.validate_fork()?;
                Ok(self.migration.legacy_network_id)
            }
        }
    }

    pub fn governance_config_hash(
        &self,
        network_id: &[u8; 32],
    ) -> Result<[u8; 32], ManifestCodecError> {
        if self.roster_epoch == 0 {
            return Err(ManifestCodecError::InvalidRosterEpoch);
        }
        validate_roster(&self.roster)?;
        let mut hash = Sha256::new();
        hash.update(GOV_CONFIG_DOMAIN);
        hash.update(network_id);
        hash.update(self.roster_epoch.to_be_bytes());
        hash.update([ROSTER_THRESHOLD, SIGNER_COUNT as u8]);
        hash.update(NORMAL_ROTATION_DELAY.to_be_bytes());
        hash.update(ACTIVATION_WINDOW.to_be_bytes());
        for entry in &self.roster {
            let mut bytes = Vec::with_capacity(ROSTER_ENTRY_BYTES);
            entry.encode_into(&mut bytes);
            hash.update(bytes);
        }
        Ok(hash.finalize().into())
    }

    pub fn recovery_policy_hash(
        &self,
        network_id: &[u8; 32],
    ) -> Result<[u8; 32], ManifestCodecError> {
        if self.recovery_policy_epoch == 0 {
            return Err(ManifestCodecError::InvalidRecoveryEpoch);
        }
        validate_guardians(&self.guardians)?;
        let mut hash = Sha256::new();
        hash.update(RECOVERY_POLICY_DOMAIN);
        hash.update(network_id);
        hash.update(self.recovery_policy_epoch.to_be_bytes());
        hash.update([GUARDIAN_THRESHOLD, GUARDIAN_COUNT as u8]);
        hash.update(RECOVERY_ROTATION_DELAY.to_be_bytes());
        hash.update(ACTIVATION_WINDOW.to_be_bytes());
        for entry in &self.guardians {
            let mut bytes = Vec::with_capacity(ROSTER_ENTRY_BYTES);
            entry.encode_into(&mut bytes);
            hash.update(bytes);
        }
        Ok(hash.finalize().into())
    }

    fn validate_roles(&self) -> Result<(), ManifestCodecError> {
        if is_zero(&self.founder_ed25519_pk) || is_zero(&self.founder_mldsa65_pk) {
            return Err(ManifestCodecError::InvalidFounderKey);
        }
        let mut components: HashSet<Vec<u8>> = HashSet::new();
        for key in [&self.founder_ed25519_pk[..], &self.founder_mldsa65_pk[..]] {
            if !components.insert(key.to_vec()) {
                return Err(ManifestCodecError::RoleKeyOverlap);
            }
        }
        for entry in &self.roster {
            for key in [&entry.ed25519_pk[..], &entry.mldsa65_pk[..]] {
                if !components.insert(key.to_vec()) {
                    return Err(ManifestCodecError::RoleKeyOverlap);
                }
            }
        }
        for entry in &self.guardians {
            for key in [&entry.ed25519_pk[..], &entry.mldsa65_pk[..]] {
                if !components.insert(key.to_vec()) {
                    return Err(ManifestCodecError::RoleKeyOverlap);
                }
            }
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), ManifestCodecError> {
        if self.roster_epoch == 0 {
            return Err(ManifestCodecError::InvalidRosterEpoch);
        }
        if self.recovery_policy_epoch == 0 {
            return Err(ManifestCodecError::InvalidRecoveryEpoch);
        }
        validate_roster(&self.roster)?;
        validate_guardians(&self.guardians)?;
        self.validate_roles()?;

        match self.mode {
            DeploymentMode::Fresh => {
                if is_zero(&self.identity_seed) {
                    return Err(ManifestCodecError::ZeroIdentitySeed);
                }
                if !self.migration.is_zero() {
                    return Err(ManifestCodecError::FreshModeHasMigrationAnchor);
                }
            }
            DeploymentMode::Fork => {
                if !is_zero(&self.identity_seed) {
                    return Err(ManifestCodecError::ForkModeIdentitySeedNonzero);
                }
                self.migration.validate_fork()?;
            }
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, ManifestCodecError> {
        self.validate()?;
        let network_id = self.network_id()?;
        if is_zero(&network_id) {
            return Err(ManifestCodecError::NetworkIdMismatch);
        }
        let governance_hash = self.governance_config_hash(&network_id)?;
        let recovery_hash = self.recovery_policy_hash(&network_id)?;
        let mut preimage = Vec::with_capacity(PREIMAGE_BYTES);

        preimage.extend_from_slice(b"GNV4");
        push_u16(&mut preimage, MANIFEST_VERSION);
        push_u16(&mut preimage, PROTOCOL_VERSION);
        push_u16(&mut preimage, STATE_VERSION);
        preimage.push(self.mode as u8);
        push_u16(&mut preimage, AUTH_SUITE_HYBRID);
        push_u16(&mut preimage, POW_ALGORITHM_ARGON2ID);
        push_u16(&mut preimage, FEE_POLICY_TRANSFER_TO_PROPOSER);
        preimage.push(ATOM_DECIMALS);
        preimage.extend_from_slice(&[0, 0, 0]);
        preimage.extend_from_slice(&self.identity_seed);

        for value in SUPPLY_FIELDS {
            push_u64(&mut preimage, value);
        }
        for value in SCHEDULE_FIELDS {
            push_u64(&mut preimage, value);
        }
        push_u16(&mut preimage, FOUNDER_VESTING_EPOCHS);

        push_u64(&mut preimage, self.roster_epoch);
        preimage.push(ROSTER_THRESHOLD);
        preimage.push(SIGNER_COUNT as u8);
        push_u64(&mut preimage, NORMAL_ROTATION_DELAY);
        push_u64(&mut preimage, ACTIVATION_WINDOW);
        preimage.extend_from_slice(&governance_hash);
        for entry in &self.roster {
            entry.encode_into(&mut preimage);
        }

        push_u64(&mut preimage, self.recovery_policy_epoch);
        preimage.push(GUARDIAN_THRESHOLD);
        preimage.push(GUARDIAN_COUNT as u8);
        push_u64(&mut preimage, RECOVERY_ROTATION_DELAY);
        push_u64(&mut preimage, ACTIVATION_WINDOW);
        preimage.extend_from_slice(&recovery_hash);
        for entry in &self.guardians {
            entry.encode_into(&mut preimage);
        }

        push_u32(&mut preimage, MAX_ACCOUNTS);
        push_u16(&mut preimage, MAX_TRANSACTIONS);
        push_u16(&mut preimage, MAX_ACTIONS);
        push_u32(&mut preimage, MAX_TXN_BYTES);
        push_u32(&mut preimage, MAX_BLOCK_BYTES);
        push_u32(&mut preimage, MAX_SNAPSHOT_BYTES);
        push_u16(&mut preimage, MAX_PENDING_PROPOSALS);

        push_u64(&mut preimage, TARGET_BLOCK_TIME_SECS);
        push_u64(&mut preimage, DIFFICULTY_WINDOW_BLOCKS);
        push_u64(&mut preimage, MIN_RETARGET_DIVISOR);
        push_u64(&mut preimage, MAX_RETARGET_MULTIPLIER);
        preimage.extend_from_slice(&POW_LIMIT);
        preimage.extend_from_slice(&INITIAL_TARGET);

        push_u32(&mut preimage, POW_MEMORY_KIB);
        push_u32(&mut preimage, POW_ITERATIONS);
        push_u32(&mut preimage, POW_LANES);
        push_u16(&mut preimage, POW_OUTPUT_BYTES);

        preimage.extend_from_slice(&self.founder_ed25519_pk);
        preimage.extend_from_slice(&self.founder_mldsa65_pk);
        preimage.extend_from_slice(&self.migration.encode());

        if preimage.len() != PREIMAGE_BYTES {
            return Err(ManifestCodecError::InternalLengthInvariant);
        }
        let manifest_id = hash_parts(&[MANIFEST_ID_DOMAIN, &preimage, &network_id]);
        let mut output = preimage;
        output.extend_from_slice(&network_id);
        output.extend_from_slice(&manifest_id);
        if output.len() != FULL_MANIFEST_BYTES {
            return Err(ManifestCodecError::InternalLengthInvariant);
        }
        Ok(output)
    }

    pub fn decode(data: &[u8]) -> Result<DecodedGnv4Manifest, ManifestCodecError> {
        if data.len() != FULL_MANIFEST_BYTES {
            return Err(ManifestCodecError::WrongManifestLength);
        }
        let mut pos = 0usize;
        if read_array::<4>(data, &mut pos)? != *b"GNV4" {
            return Err(ManifestCodecError::WrongMagic);
        }
        expect_u16(
            data,
            &mut pos,
            MANIFEST_VERSION,
            ManifestCodecError::UnsupportedManifestVersion,
        )?;
        expect_u16(
            data,
            &mut pos,
            PROTOCOL_VERSION,
            ManifestCodecError::UnsupportedProtocolVersion,
        )?;
        expect_u16(
            data,
            &mut pos,
            STATE_VERSION,
            ManifestCodecError::UnsupportedStateVersion,
        )?;
        let mode = DeploymentMode::try_from(read_array::<1>(data, &mut pos)?[0])?;
        expect_u16(
            data,
            &mut pos,
            AUTH_SUITE_HYBRID,
            ManifestCodecError::UnsupportedAuthSuite,
        )?;
        expect_u16(
            data,
            &mut pos,
            POW_ALGORITHM_ARGON2ID,
            ManifestCodecError::UnsupportedPowAlgorithm,
        )?;
        expect_u16(
            data,
            &mut pos,
            FEE_POLICY_TRANSFER_TO_PROPOSER,
            ManifestCodecError::UnsupportedFeePolicy,
        )?;
        if read_array::<1>(data, &mut pos)?[0] != ATOM_DECIMALS
            || read_array::<3>(data, &mut pos)? != [0, 0, 0]
        {
            return Err(ManifestCodecError::InvalidPrecisionOrReservedBytes);
        }
        let identity_seed = read_array::<32>(data, &mut pos)?;

        for expected in SUPPLY_FIELDS {
            expect_u64(
                data,
                &mut pos,
                expected,
                ManifestCodecError::UnsupportedEconomicProfile,
            )?;
        }
        for expected in SCHEDULE_FIELDS {
            expect_u64(
                data,
                &mut pos,
                expected,
                ManifestCodecError::UnsupportedScheduleProfile,
            )?;
        }
        expect_u16(
            data,
            &mut pos,
            FOUNDER_VESTING_EPOCHS,
            ManifestCodecError::UnsupportedScheduleProfile,
        )?;

        let roster_epoch = read_u64(data, &mut pos)?;
        if roster_epoch == 0 {
            return Err(ManifestCodecError::InvalidRosterEpoch);
        }
        if read_array::<1>(data, &mut pos)?[0] != ROSTER_THRESHOLD
            || read_array::<1>(data, &mut pos)?[0] != SIGNER_COUNT as u8
            || read_u64(data, &mut pos)? != NORMAL_ROTATION_DELAY
            || read_u64(data, &mut pos)? != ACTIVATION_WINDOW
        {
            return Err(ManifestCodecError::UnsupportedGovernancePolicy);
        }
        let claimed_governance_hash = read_array::<32>(data, &mut pos)?;
        let mut roster = Vec::with_capacity(SIGNER_COUNT);
        for _ in 0..SIGNER_COUNT {
            roster.push(SignerEntry::decode_from(data, &mut pos)?);
        }

        let recovery_policy_epoch = read_u64(data, &mut pos)?;
        if recovery_policy_epoch == 0 {
            return Err(ManifestCodecError::InvalidRecoveryEpoch);
        }
        if read_array::<1>(data, &mut pos)?[0] != GUARDIAN_THRESHOLD
            || read_array::<1>(data, &mut pos)?[0] != GUARDIAN_COUNT as u8
            || read_u64(data, &mut pos)? != RECOVERY_ROTATION_DELAY
            || read_u64(data, &mut pos)? != ACTIVATION_WINDOW
        {
            return Err(ManifestCodecError::UnsupportedRecoveryPolicy);
        }
        let claimed_recovery_hash = read_array::<32>(data, &mut pos)?;
        let mut guardians = Vec::with_capacity(GUARDIAN_COUNT);
        for _ in 0..GUARDIAN_COUNT {
            guardians.push(GuardianEntry::decode_from(data, &mut pos)?);
        }

        expect_u32(
            data,
            &mut pos,
            MAX_ACCOUNTS,
            ManifestCodecError::UnsupportedResourceProfile,
        )?;
        expect_u16(
            data,
            &mut pos,
            MAX_TRANSACTIONS,
            ManifestCodecError::UnsupportedResourceProfile,
        )?;
        expect_u16(
            data,
            &mut pos,
            MAX_ACTIONS,
            ManifestCodecError::UnsupportedResourceProfile,
        )?;
        expect_u32(
            data,
            &mut pos,
            MAX_TXN_BYTES,
            ManifestCodecError::UnsupportedResourceProfile,
        )?;
        expect_u32(
            data,
            &mut pos,
            MAX_BLOCK_BYTES,
            ManifestCodecError::UnsupportedResourceProfile,
        )?;
        expect_u32(
            data,
            &mut pos,
            MAX_SNAPSHOT_BYTES,
            ManifestCodecError::UnsupportedResourceProfile,
        )?;
        expect_u16(
            data,
            &mut pos,
            MAX_PENDING_PROPOSALS,
            ManifestCodecError::UnsupportedResourceProfile,
        )?;

        expect_u64(
            data,
            &mut pos,
            TARGET_BLOCK_TIME_SECS,
            ManifestCodecError::UnsupportedPowProfile,
        )?;
        expect_u64(
            data,
            &mut pos,
            DIFFICULTY_WINDOW_BLOCKS,
            ManifestCodecError::UnsupportedPowProfile,
        )?;
        expect_u64(
            data,
            &mut pos,
            MIN_RETARGET_DIVISOR,
            ManifestCodecError::UnsupportedPowProfile,
        )?;
        expect_u64(
            data,
            &mut pos,
            MAX_RETARGET_MULTIPLIER,
            ManifestCodecError::UnsupportedPowProfile,
        )?;
        if read_array::<32>(data, &mut pos)? != POW_LIMIT
            || read_array::<32>(data, &mut pos)? != INITIAL_TARGET
        {
            return Err(ManifestCodecError::UnsupportedPowProfile);
        }
        expect_u32(
            data,
            &mut pos,
            POW_MEMORY_KIB,
            ManifestCodecError::UnsupportedArgon2idProfile,
        )?;
        expect_u32(
            data,
            &mut pos,
            POW_ITERATIONS,
            ManifestCodecError::UnsupportedArgon2idProfile,
        )?;
        expect_u32(
            data,
            &mut pos,
            POW_LANES,
            ManifestCodecError::UnsupportedArgon2idProfile,
        )?;
        expect_u16(
            data,
            &mut pos,
            POW_OUTPUT_BYTES,
            ManifestCodecError::UnsupportedArgon2idProfile,
        )?;

        let founder_ed25519_pk = read_array::<ED25519_PK_BYTES>(data, &mut pos)?;
        let founder_mldsa65_pk = read_array::<ML_DSA_65_PK_BYTES>(data, &mut pos)?;
        let migration = MigrationAnchor::decode(data, &mut pos)?;
        let claimed_network_id = read_array::<32>(data, &mut pos)?;
        let claimed_manifest_id = read_array::<32>(data, &mut pos)?;
        if pos != data.len() {
            return Err(ManifestCodecError::TrailingBytes);
        }

        let manifest = Gnv4Manifest {
            mode,
            identity_seed,
            roster_epoch,
            recovery_policy_epoch,
            founder_ed25519_pk,
            founder_mldsa65_pk,
            roster,
            guardians,
            migration,
        };
        manifest.validate()?;
        let computed_network_id = manifest.network_id()?;
        if claimed_network_id != computed_network_id {
            return Err(ManifestCodecError::NetworkIdMismatch);
        }
        let computed_governance_hash = manifest.governance_config_hash(&computed_network_id)?;
        if claimed_governance_hash != computed_governance_hash {
            return Err(ManifestCodecError::GovernanceConfigHashMismatch);
        }
        let computed_recovery_hash = manifest.recovery_policy_hash(&computed_network_id)?;
        if claimed_recovery_hash != computed_recovery_hash {
            return Err(ManifestCodecError::RecoveryPolicyHashMismatch);
        }
        let canonical = manifest.encode()?;
        let computed_manifest_id: [u8; 32] = canonical[MANIFEST_ID_OFFSET..]
            .try_into()
            .map_err(|_| ManifestCodecError::InternalLengthInvariant)?;
        if claimed_manifest_id != computed_manifest_id {
            return Err(ManifestCodecError::ManifestIdMismatch);
        }
        if canonical != data {
            return Err(ManifestCodecError::ManifestIdMismatch);
        }
        Ok(DecodedGnv4Manifest {
            manifest,
            network_id: computed_network_id,
            manifest_id: computed_manifest_id,
            bytes: canonical,
        })
    }
}

fn validate_roster(roster: &[SignerEntry]) -> Result<(), ManifestCodecError> {
    if roster.len() != SIGNER_COUNT {
        return Err(ManifestCodecError::NoncanonicalGovernanceRoster);
    }
    for entry in roster {
        if is_zero(&entry.ed25519_pk) || is_zero(&entry.mldsa65_pk) {
            return Err(ManifestCodecError::SignerIdMismatch);
        }
        if entry.signer_id != derive_signer_id(&entry.ed25519_pk, &entry.mldsa65_pk) {
            return Err(ManifestCodecError::SignerIdMismatch);
        }
    }
    if roster.windows(2).any(|w| w[0].signer_id >= w[1].signer_id) {
        return Err(ManifestCodecError::NoncanonicalGovernanceRoster);
    }
    Ok(())
}

fn validate_guardians(guardians: &[GuardianEntry]) -> Result<(), ManifestCodecError> {
    if guardians.len() != GUARDIAN_COUNT {
        return Err(ManifestCodecError::NoncanonicalRecoveryRoster);
    }
    for entry in guardians {
        if is_zero(&entry.ed25519_pk) || is_zero(&entry.mldsa65_pk) {
            return Err(ManifestCodecError::GuardianIdMismatch);
        }
        if entry.guardian_id != derive_guardian_id(&entry.ed25519_pk, &entry.mldsa65_pk) {
            return Err(ManifestCodecError::GuardianIdMismatch);
        }
    }
    if guardians
        .windows(2)
        .any(|w| w[0].guardian_id >= w[1].guardian_id)
    {
        return Err(ManifestCodecError::NoncanonicalRecoveryRoster);
    }
    Ok(())
}

pub fn genesis_id(
    network_id: &[u8; 32],
    manifest_id: &[u8; 32],
    genesis_state_root: &[u8; 32],
) -> Result<[u8; 32], ManifestCodecError> {
    if is_zero(network_id) || is_zero(manifest_id) || is_zero(genesis_state_root) {
        return Err(ManifestCodecError::InvalidGenesisHashInput);
    }
    Ok(hash_parts(&[
        GENESIS_ID_DOMAIN,
        network_id,
        manifest_id,
        genesis_state_root,
    ]))
}

pub fn encode_fork_activation_trust_record(
    network_id: &[u8; 32],
    manifest_id: &[u8; 32],
    anchor: &MigrationAnchor,
    expected_post_migration_stv4_root: &[u8; 32],
    trust_epoch: u64,
) -> Result<Vec<u8>, ManifestCodecError> {
    if is_zero(network_id)
        || is_zero(manifest_id)
        || is_zero(expected_post_migration_stv4_root)
        || trust_epoch == 0
    {
        return Err(ManifestCodecError::InvalidForkCommitmentInput);
    }
    anchor.validate_fork()?;
    let mut out = Vec::with_capacity(248);
    out.extend_from_slice(b"FAT1");
    push_u16(&mut out, 1);
    push_u64(&mut out, trust_epoch);
    out.extend_from_slice(network_id);
    out.extend_from_slice(manifest_id);
    out.extend_from_slice(&anchor.migration_plan_id);
    push_u64(&mut out, anchor.activation_height);
    out.extend_from_slice(&anchor.parent_block_id);
    out.extend_from_slice(&anchor.pre_migration_stv3_root);
    push_u16(&mut out, anchor.migration_algorithm_id);
    out.extend_from_slice(&anchor.migration_policy_hash);
    out.extend_from_slice(expected_post_migration_stv4_root);
    if out.len() != 248 {
        return Err(ManifestCodecError::InternalLengthInvariant);
    }
    Ok(out)
}

pub fn fork_activation_trust_record_id(
    network_id: &[u8; 32],
    manifest_id: &[u8; 32],
    anchor: &MigrationAnchor,
    expected_post_migration_stv4_root: &[u8; 32],
    trust_epoch: u64,
) -> Result<[u8; 32], ManifestCodecError> {
    let record = encode_fork_activation_trust_record(
        network_id,
        manifest_id,
        anchor,
        expected_post_migration_stv4_root,
        trust_epoch,
    )?;
    Ok(hash_parts(&[FORK_TRUST_RECORD_DOMAIN, &record]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const FRESH_FIXTURE: &[u8] =
        include_bytes!("../../../../simulations/cp0221_fresh_structural_fixture.bin");
    const FORK_FIXTURE: &[u8] =
        include_bytes!("../../../../simulations/cp0221_fork_structural_fixture.bin");
    const VECTORS: &str = include_str!("../../../../simulations/cp0221_gnv4_manifest_vectors.tsv");

    fn vector_map() -> HashMap<String, String> {
        VECTORS
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| {
                let (key, value) = line.split_once('\t').expect("canonical TSV row");
                (key.to_owned(), value.to_owned())
            })
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }

    fn from_hex_32(value: &str) -> [u8; 32] {
        assert_eq!(value.len(), 64);
        let mut out = [0u8; 32];
        for (idx, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
            let text = std::str::from_utf8(chunk).expect("ASCII hex");
            out[idx] = u8::from_str_radix(text, 16).expect("hex byte");
        }
        out
    }

    #[test]
    fn fixed_sizes_and_offsets_match_cp0221_spec() {
        assert_eq!(PREIMAGE_BYTES, 22_801);
        assert_eq!(FULL_MANIFEST_BYTES, 22_865);
        assert_eq!(MIGRATION_DESCRIPTOR_BYTES, 234);
        assert_eq!(NETWORK_ID_OFFSET, 22_801);
        assert_eq!(MANIFEST_ID_OFFSET, 22_833);
        assert_eq!(GOVERNANCE_HASH_OFFSET, 201);
        assert_eq!(RECOVERY_HASH_OFFSET, 14_371);
        assert_eq!(ROSTER_OFFSET, 233);
        assert_eq!(GUARDIANS_OFFSET, 14_403);
        assert_eq!(MIGRATION_OFFSET, 22_567);
    }

    #[test]
    fn fresh_synthetic_fixture_decodes_and_reencodes_exactly() {
        let decoded = Gnv4Manifest::decode(FRESH_FIXTURE).expect("fresh fixture must decode");
        assert_eq!(decoded.manifest.mode, DeploymentMode::Fresh);
        assert_eq!(decoded.bytes.as_slice(), FRESH_FIXTURE);
        assert_eq!(
            decoded.manifest.encode().expect("encode").as_slice(),
            FRESH_FIXTURE
        );
        assert_eq!(
            decoded.network_id,
            from_hex_32(&vector_map()["fresh.network_id"])
        );
        assert_eq!(
            decoded.manifest_id,
            from_hex_32(&vector_map()["fresh.manifest_id"])
        );
    }

    #[test]
    fn fork_synthetic_fixture_carries_legacy_network_id_and_roundtrips() {
        let decoded = Gnv4Manifest::decode(FORK_FIXTURE).expect("fork fixture must decode");
        assert_eq!(decoded.manifest.mode, DeploymentMode::Fork);
        assert_eq!(
            decoded.network_id,
            decoded.manifest.migration.legacy_network_id
        );
        assert_eq!(decoded.bytes.as_slice(), FORK_FIXTURE);
        assert_eq!(
            decoded.manifest.encode().expect("encode").as_slice(),
            FORK_FIXTURE
        );
        assert_eq!(decoded.manifest.migration.activation_height, 50_000);
    }

    #[test]
    fn all_24_cross_language_golden_values_match_rust() {
        let vectors = vector_map();
        assert_eq!(vectors.len(), 24);
        let fresh = Gnv4Manifest::decode(FRESH_FIXTURE).expect("fresh fixture");
        let fork = Gnv4Manifest::decode(FORK_FIXTURE).expect("fork fixture");
        let state_root = from_hex_32(&vectors["fresh.genesis_state_root_fixture"]);
        let mut observed = HashMap::new();

        observed.insert("fresh.network_id".to_owned(), hex(&fresh.network_id));
        observed.insert(
            "fresh.governance_config_hash".to_owned(),
            hex(&fresh
                .manifest
                .governance_config_hash(&fresh.network_id)
                .unwrap()),
        );
        observed.insert(
            "fresh.recovery_policy_hash".to_owned(),
            hex(&fresh
                .manifest
                .recovery_policy_hash(&fresh.network_id)
                .unwrap()),
        );
        observed.insert(
            "fresh.preimage_length".to_owned(),
            PREIMAGE_BYTES.to_string(),
        );
        observed.insert(
            "fresh.preimage_sha256".to_owned(),
            hex(&hash_parts(&[&fresh.bytes[..PREIMAGE_BYTES]])),
        );
        observed.insert("fresh.manifest_id".to_owned(), hex(&fresh.manifest_id));
        observed.insert(
            "fresh.full_manifest_length".to_owned(),
            fresh.bytes.len().to_string(),
        );
        observed.insert(
            "fresh.full_manifest_sha256".to_owned(),
            hex(&hash_parts(&[&fresh.bytes])),
        );
        observed.insert(
            "fresh.genesis_state_root_fixture".to_owned(),
            hex(&state_root),
        );
        observed.insert(
            "fresh.genesis_id".to_owned(),
            hex(&genesis_id(&fresh.network_id, &fresh.manifest_id, &state_root).unwrap()),
        );
        observed.insert("fork.network_id_carried".to_owned(), hex(&fork.network_id));
        observed.insert(
            "fork.governance_config_hash".to_owned(),
            hex(&fork
                .manifest
                .governance_config_hash(&fork.network_id)
                .unwrap()),
        );
        observed.insert(
            "fork.recovery_policy_hash".to_owned(),
            hex(&fork
                .manifest
                .recovery_policy_hash(&fork.network_id)
                .unwrap()),
        );
        observed.insert(
            "fork.preimage_length".to_owned(),
            PREIMAGE_BYTES.to_string(),
        );
        observed.insert(
            "fork.preimage_sha256".to_owned(),
            hex(&hash_parts(&[&fork.bytes[..PREIMAGE_BYTES]])),
        );
        observed.insert("fork.manifest_id".to_owned(), hex(&fork.manifest_id));
        observed.insert(
            "fork.full_manifest_length".to_owned(),
            fork.bytes.len().to_string(),
        );
        observed.insert(
            "fork.full_manifest_sha256".to_owned(),
            hex(&hash_parts(&[&fork.bytes])),
        );
        observed.insert(
            "fork.legacy_genesis_id".to_owned(),
            hex(&fork.manifest.migration.legacy_genesis_id),
        );
        observed.insert(
            "fork.activation_height".to_owned(),
            fork.manifest.migration.activation_height.to_string(),
        );
        observed.insert(
            "fork.migration_plan_id".to_owned(),
            hex(&fork.manifest.migration.migration_plan_id),
        );
        let external_root = from_hex_32(&vectors["fork.expected_post_stv4_root_external"]);
        observed.insert(
            "fork.expected_post_stv4_root_external".to_owned(),
            hex(&external_root),
        );
        let trust_record = encode_fork_activation_trust_record(
            &fork.network_id,
            &fork.manifest_id,
            &fork.manifest.migration,
            &external_root,
            1,
        )
        .unwrap();
        observed.insert(
            "fork.activation_trust_record_length".to_owned(),
            trust_record.len().to_string(),
        );
        observed.insert(
            "fork.activation_trust_record_id".to_owned(),
            hex(&fork_activation_trust_record_id(
                &fork.network_id,
                &fork.manifest_id,
                &fork.manifest.migration,
                &external_root,
                1,
            )
            .unwrap()),
        );

        for (key, expected) in vectors {
            if key == "fresh.full_manifest_length" || key == "fork.full_manifest_length" {
                assert_eq!(expected, FULL_MANIFEST_BYTES.to_string(), "{key}");
            } else {
                assert_eq!(observed.get(&key), Some(&expected), "{key}");
            }
        }
    }

    #[test]
    fn decoder_rejects_wrong_length_magic_versions_mode_and_reserved_bytes() {
        assert_eq!(
            Gnv4Manifest::decode(&FRESH_FIXTURE[..FRESH_FIXTURE.len() - 1]),
            Err(ManifestCodecError::WrongManifestLength)
        );
        let mut data = FRESH_FIXTURE.to_vec();
        data[0] ^= 1;
        assert_eq!(
            Gnv4Manifest::decode(&data),
            Err(ManifestCodecError::WrongMagic)
        );
        let mut data = FRESH_FIXTURE.to_vec();
        data[5] = 3;
        assert_eq!(
            Gnv4Manifest::decode(&data),
            Err(ManifestCodecError::UnsupportedManifestVersion)
        );
        let mut data = FRESH_FIXTURE.to_vec();
        data[10] = 3;
        assert_eq!(
            Gnv4Manifest::decode(&data),
            Err(ManifestCodecError::UnknownDeploymentMode)
        );
        let mut data = FRESH_FIXTURE.to_vec();
        data[20] = 1;
        assert_eq!(
            Gnv4Manifest::decode(&data),
            Err(ManifestCodecError::InvalidPrecisionOrReservedBytes)
        );
    }

    #[test]
    fn decoder_rejects_network_config_and_manifest_hash_mutations() {
        let mut data = FRESH_FIXTURE.to_vec();
        data[NETWORK_ID_OFFSET] ^= 1;
        assert_eq!(
            Gnv4Manifest::decode(&data),
            Err(ManifestCodecError::NetworkIdMismatch)
        );
        let mut data = FRESH_FIXTURE.to_vec();
        data[GOVERNANCE_HASH_OFFSET] ^= 1;
        assert_eq!(
            Gnv4Manifest::decode(&data),
            Err(ManifestCodecError::GovernanceConfigHashMismatch)
        );
        let mut data = FRESH_FIXTURE.to_vec();
        data[RECOVERY_HASH_OFFSET] ^= 1;
        assert_eq!(
            Gnv4Manifest::decode(&data),
            Err(ManifestCodecError::RecoveryPolicyHashMismatch)
        );
        let mut data = FRESH_FIXTURE.to_vec();
        data[MANIFEST_ID_OFFSET] ^= 1;
        assert_eq!(
            Gnv4Manifest::decode(&data),
            Err(ManifestCodecError::ManifestIdMismatch)
        );
    }

    #[test]
    fn decoder_rejects_changed_economics_resource_and_pow_profiles() {
        let mut data = FRESH_FIXTURE.to_vec();
        data[HEADER_BYTES + 7] ^= 1;
        assert_eq!(
            Gnv4Manifest::decode(&data),
            Err(ManifestCodecError::UnsupportedEconomicProfile)
        );
        let resource_offset =
            HEADER_BYTES + SUPPLY_BYTES + SCHEDULE_BYTES + GOVERNANCE_BYTES + RECOVERY_BYTES;
        let mut data = FRESH_FIXTURE.to_vec();
        data[resource_offset] ^= 1;
        assert_eq!(
            Gnv4Manifest::decode(&data),
            Err(ManifestCodecError::UnsupportedResourceProfile)
        );
        let pow_offset = resource_offset + RESOURCE_BYTES;
        let mut data = FRESH_FIXTURE.to_vec();
        data[pow_offset] ^= 1;
        assert_eq!(
            Gnv4Manifest::decode(&data),
            Err(ManifestCodecError::UnsupportedPowProfile)
        );
    }

    #[test]
    fn decoder_rejects_noncanonical_roster_order_and_wrong_signer_id() {
        let mut data = FRESH_FIXTURE.to_vec();
        let first = data[ROSTER_OFFSET..ROSTER_OFFSET + ROSTER_ENTRY_BYTES].to_vec();
        let second_offset = ROSTER_OFFSET + ROSTER_ENTRY_BYTES;
        let second = data[second_offset..second_offset + ROSTER_ENTRY_BYTES].to_vec();
        data[ROSTER_OFFSET..ROSTER_OFFSET + ROSTER_ENTRY_BYTES].copy_from_slice(&second);
        data[second_offset..second_offset + ROSTER_ENTRY_BYTES].copy_from_slice(&first);
        assert_eq!(
            Gnv4Manifest::decode(&data),
            Err(ManifestCodecError::NoncanonicalGovernanceRoster)
        );

        let mut data = FRESH_FIXTURE.to_vec();
        data[ROSTER_OFFSET] ^= 1;
        assert_eq!(
            Gnv4Manifest::decode(&data),
            Err(ManifestCodecError::SignerIdMismatch)
        );
    }

    #[test]
    fn decoder_rejects_noncanonical_guardian_order_and_wrong_guardian_id() {
        let first_offset = GUARDIANS_OFFSET;
        let second_offset = GUARDIANS_OFFSET + ROSTER_ENTRY_BYTES;
        let mut data = FRESH_FIXTURE.to_vec();
        let first = data[first_offset..first_offset + ROSTER_ENTRY_BYTES].to_vec();
        let second = data[second_offset..second_offset + ROSTER_ENTRY_BYTES].to_vec();
        data[first_offset..first_offset + ROSTER_ENTRY_BYTES].copy_from_slice(&second);
        data[second_offset..second_offset + ROSTER_ENTRY_BYTES].copy_from_slice(&first);
        assert_eq!(
            Gnv4Manifest::decode(&data),
            Err(ManifestCodecError::NoncanonicalRecoveryRoster)
        );

        let mut data = FRESH_FIXTURE.to_vec();
        data[GUARDIANS_OFFSET] ^= 1;
        assert_eq!(
            Gnv4Manifest::decode(&data),
            Err(ManifestCodecError::GuardianIdMismatch)
        );
    }

    #[test]
    fn decoder_rejects_partial_public_key_reuse_across_roles() {
        let mut manifest = Gnv4Manifest::decode(FRESH_FIXTURE)
            .expect("fixture")
            .manifest;
        let reused_ed = manifest.roster[0].ed25519_pk;
        let new_guardian =
            GuardianEntry::from_public_keys(reused_ed, [0xe1; ML_DSA_65_PK_BYTES]).unwrap();
        manifest.guardians[0] = new_guardian;
        manifest.guardians.sort_by_key(|entry| entry.guardian_id);
        assert_eq!(manifest.encode(), Err(ManifestCodecError::RoleKeyOverlap));
    }

    #[test]
    fn encoder_rejects_invalid_mode_seed_anchor_and_epochs() {
        let decoded = Gnv4Manifest::decode(FRESH_FIXTURE).expect("fixture");
        let mut m = decoded.manifest.clone();
        m.identity_seed = [0; 32];
        assert_eq!(m.encode(), Err(ManifestCodecError::ZeroIdentitySeed));

        let mut m = Gnv4Manifest::decode(FORK_FIXTURE).expect("fork").manifest;
        m.identity_seed = [9; 32];
        assert_eq!(
            m.encode(),
            Err(ManifestCodecError::ForkModeIdentitySeedNonzero)
        );

        let mut m = Gnv4Manifest::decode(FRESH_FIXTURE)
            .expect("fixture")
            .manifest;
        m.migration.legacy_manifest_id = [1; 32];
        assert_eq!(
            m.encode(),
            Err(ManifestCodecError::FreshModeHasMigrationAnchor)
        );

        let mut m = Gnv4Manifest::decode(FRESH_FIXTURE)
            .expect("fixture")
            .manifest;
        m.roster_epoch = 0;
        assert_eq!(m.encode(), Err(ManifestCodecError::InvalidRosterEpoch));
    }

    #[test]
    fn fork_manifest_rejects_migration_plan_id_tampering() {
        let mut data = FORK_FIXTURE.to_vec();
        data[MIGRATION_OFFSET + 202] ^= 1;
        assert_eq!(
            Gnv4Manifest::decode(&data),
            Err(ManifestCodecError::MigrationPlanIdMismatch)
        );
    }

    #[test]
    fn genesis_and_fork_trust_record_are_domain_separated_and_bound() {
        let fresh = Gnv4Manifest::decode(FRESH_FIXTURE).expect("fresh");
        let vectors = vector_map();
        let root = from_hex_32(&vectors["fresh.genesis_state_root_fixture"]);
        assert_eq!(
            hex(&genesis_id(&fresh.network_id, &fresh.manifest_id, &root).unwrap()),
            vectors["fresh.genesis_id"]
        );
        let fork = Gnv4Manifest::decode(FORK_FIXTURE).expect("fork");
        let external_root = from_hex_32(&vectors["fork.expected_post_stv4_root_external"]);
        let record = encode_fork_activation_trust_record(
            &fork.network_id,
            &fork.manifest_id,
            &fork.manifest.migration,
            &external_root,
            1,
        )
        .unwrap();
        assert_eq!(record.len(), 248);
        assert_eq!(
            hex(&fork_activation_trust_record_id(
                &fork.network_id,
                &fork.manifest_id,
                &fork.manifest.migration,
                &external_root,
                1,
            )
            .unwrap()),
            vectors["fork.activation_trust_record_id"]
        );
        let other_root = [0x77; 32];
        assert_ne!(
            fork_activation_trust_record_id(
                &fork.network_id,
                &fork.manifest_id,
                &fork.manifest.migration,
                &external_root,
                1,
            )
            .unwrap(),
            fork_activation_trust_record_id(
                &fork.network_id,
                &fork.manifest_id,
                &fork.manifest.migration,
                &other_root,
                1,
            )
            .unwrap()
        );
        let manifest_bytes = fork.manifest.encode().unwrap();
        assert!(!manifest_bytes.windows(32).any(|w| w == external_root));
    }

    #[test]
    fn genesis_and_fork_trust_record_reject_zero_inputs() {
        assert_eq!(
            genesis_id(&[0; 32], &[1; 32], &[2; 32]),
            Err(ManifestCodecError::InvalidGenesisHashInput)
        );
        let fork = Gnv4Manifest::decode(FORK_FIXTURE).expect("fork");
        let external_root = from_hex_32(&vector_map()["fork.expected_post_stv4_root_external"]);
        assert_eq!(
            fork_activation_trust_record_id(
                &[0; 32],
                &fork.manifest_id,
                &fork.manifest.migration,
                &external_root,
                1,
            ),
            Err(ManifestCodecError::InvalidForkCommitmentInput)
        );
        assert_eq!(
            encode_fork_activation_trust_record(
                &fork.network_id,
                &fork.manifest_id,
                &fork.manifest.migration,
                &[0; 32],
                1,
            ),
            Err(ManifestCodecError::InvalidForkCommitmentInput)
        );
    }

    #[test]
    fn decoded_manifests_are_exactly_canonical_and_have_no_trailing_bytes() {
        let mut data = FRESH_FIXTURE.to_vec();
        data.extend_from_slice(&[0]);
        assert_eq!(
            Gnv4Manifest::decode(&data),
            Err(ManifestCodecError::WrongManifestLength)
        );
        assert_eq!(
            Gnv4Manifest::decode(&[]),
            Err(ManifestCodecError::WrongManifestLength)
        );
    }
}
