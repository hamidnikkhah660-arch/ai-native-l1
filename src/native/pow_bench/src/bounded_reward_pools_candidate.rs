//! Candidate bounded reward-pool ledger and Ed25519 threshold-claim verifier.
//!
//! RESEARCH ONLY: this module is not wired into canonical state transitions, Genesis,
//! issuance_schedule, or consensus. Its threshold configuration is supplied at construction;
//! production configuration must be committed to an audited network/Genesis profile.
//! The model checks accounting/claim semantics, not off-chain eligibility or legal compliance.

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const CLAIM_DOMAIN: &[u8] = b"AIN1-REWARD-CLAIM-V1\0";
const REQUIRED_POOL_COUNT: usize = 4;
const SNAPSHOT_MAGIC: &[u8] = b"AIN1-POOL-SNAPSHOT-V1\0";
const SNAPSHOT_CHECKSUM_DOMAIN: &[u8] = b"AIN1-POOL-SNAPSHOT-CHECKSUM-V1\0";
const SNAPSHOT_CHECKSUM_LEN: usize = 32;
/// Candidate limit only; not a canonical persistent-state or consensus limit.
const MAX_SNAPSHOT_BYTES: usize = 8 * 1024 * 1024;
const MAX_SNAPSHOT_ENTRIES: usize = 100_000;
/// Candidate-model bound; do not treat as a frozen network wire limit.
const MAX_CLAIM_SIGNERS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum RewardPool {
    Adoption = 1,
    DeveloperEcosystem = 2,
    Security = 3,
    CommunityInfrastructure = 4,
}

impl RewardPool {
    pub const ALL: [Self; REQUIRED_POOL_COUNT] = [
        Self::Adoption,
        Self::DeveloperEcosystem,
        Self::Security,
        Self::CommunityInfrastructure,
    ];

    pub const fn id(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimSignature {
    pub signer_public_key: [u8; 32],
    pub signature: [u8; 64],
}

/// Every field is covered by signing_bytes; signatures are kept separately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewardClaim {
    pub network_id: [u8; 32],
    pub pool: RewardPool,
    pub amount_atoms: u128,
    pub recipient: [u8; 32],
    pub claim_id: [u8; 32],
    pub valid_from_epoch: u64,
    pub expires_at_epoch: u64,
    pub signatures: Vec<ClaimSignature>,
}

impl RewardClaim {
    /// Canonical fixed-width big-endian message. Signature list order is not signed.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CLAIM_DOMAIN.len() + 32 + 1 + 16 + 32 + 32 + 8 + 8);
        out.extend_from_slice(CLAIM_DOMAIN);
        out.extend_from_slice(&self.network_id);
        out.push(self.pool.id());
        out.extend_from_slice(&self.amount_atoms.to_be_bytes());
        out.extend_from_slice(&self.recipient);
        out.extend_from_slice(&self.claim_id);
        out.extend_from_slice(&self.valid_from_epoch.to_be_bytes());
        out.extend_from_slice(&self.expires_at_epoch.to_be_bytes());
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewardPoolConfig {
    pub network_id: [u8; 32],
    pub maximum_supply_atoms: u128,
    /// Total issued at Genesis (owner allocation is included here if/when Genesis is ratified).
    pub initially_issued_atoms: u128,
    pub miner_budget_atoms: u128,
    pub pool_ceilings_atoms: BTreeMap<RewardPool, u128>,
    pub authorized_signers: BTreeSet<[u8; 32]>,
    pub signature_threshold: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoolError {
    InvalidConfiguration,
    InvalidNetworkId,
    InvalidSignerKey,
    WrongNetwork,
    ZeroAmount,
    InvalidClaimId,
    InvalidRecipient,
    InvalidClaimWindow,
    ClaimNotYetValid,
    ClaimExpired,
    DuplicateClaim,
    UnknownSigner,
    DuplicateSigner,
    TooManySignatures,
    SnapshotTooLarge,
    SnapshotMalformed,
    SnapshotChecksumMismatch,
    SnapshotConfigMismatch,
    SnapshotInvariantViolation,
    InvalidSignature,
    InsufficientThreshold,
    PoolBudgetExceeded,
    MiningBudgetExceeded,
    SupplyCapExceeded,
    ArithmeticOverflow,
}

impl std::fmt::Display for PoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfiguration => write!(f, "reward-pool configuration is invalid"),
            Self::InvalidNetworkId => write!(f, "network ID must be non-zero"),
            Self::InvalidSignerKey => write!(f, "configured signer public key is invalid"),
            Self::WrongNetwork => write!(f, "claim belongs to a different network"),
            Self::ZeroAmount => write!(f, "claim amount must be non-zero"),
            Self::InvalidClaimId => write!(f, "claim ID must be non-zero"),
            Self::InvalidRecipient => write!(f, "recipient must be non-zero"),
            Self::InvalidClaimWindow => write!(f, "claim validity window is invalid"),
            Self::ClaimNotYetValid => write!(f, "claim validity window has not started"),
            Self::ClaimExpired => write!(f, "claim has expired"),
            Self::DuplicateClaim => write!(f, "claim ID has already been applied"),
            Self::UnknownSigner => write!(f, "claim contains an unapproved signer"),
            Self::DuplicateSigner => write!(f, "claim repeats a signer"),
            Self::TooManySignatures => write!(f, "claim signature count exceeds configured bounds"),
            Self::SnapshotTooLarge => {
                write!(f, "reward-pool snapshot exceeds candidate size limits")
            }
            Self::SnapshotMalformed => write!(f, "reward-pool snapshot is malformed"),
            Self::SnapshotChecksumMismatch => {
                write!(f, "reward-pool snapshot checksum does not match")
            }
            Self::SnapshotConfigMismatch => write!(
                f,
                "reward-pool snapshot belongs to a different configuration"
            ),
            Self::SnapshotInvariantViolation => {
                write!(f, "reward-pool snapshot violates accounting invariants")
            }
            Self::InvalidSignature => write!(f, "claim signature is invalid"),
            Self::InsufficientThreshold => write!(f, "claim does not meet the signature threshold"),
            Self::PoolBudgetExceeded => write!(f, "claim exceeds the pool's remaining ceiling"),
            Self::MiningBudgetExceeded => {
                write!(f, "mining reward exceeds the remaining miner budget")
            }
            Self::SupplyCapExceeded => write!(f, "issuance would exceed the maximum supply"),
            Self::ArithmeticOverflow => write!(f, "accounting arithmetic overflow"),
        }
    }
}

impl std::error::Error for PoolError {}

/// Candidate accounting model. Balances here contain program recipients only; the owner Genesis
/// balance is represented in issued_atoms until a canonical ledger/address is selected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolAccounting {
    config: RewardPoolConfig,
    issued_atoms: u128,
    miner_issued_atoms: u128,
    pool_awarded_atoms: BTreeMap<RewardPool, u128>,
    recipient_balances: BTreeMap<[u8; 32], u128>,
    applied_claim_ids: BTreeSet<[u8; 32]>,
}

fn snapshot_checksum(payload: &[u8]) -> [u8; SNAPSHOT_CHECKSUM_LEN] {
    let mut digest = Sha256::new();
    digest.update(SNAPSHOT_CHECKSUM_DOMAIN);
    digest.update(payload);
    let result = digest.finalize();
    let mut out = [0u8; SNAPSHOT_CHECKSUM_LEN];
    out.copy_from_slice(&result);
    out
}

fn snapshot_config_fingerprint(config: &RewardPoolConfig) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(256 + config.authorized_signers.len() * 32);
    bytes.extend_from_slice(b"AIN1-POOL-CONFIG-FINGERPRINT-V1\0");
    bytes.extend_from_slice(&config.network_id);
    bytes.extend_from_slice(&config.maximum_supply_atoms.to_be_bytes());
    bytes.extend_from_slice(&config.initially_issued_atoms.to_be_bytes());
    bytes.extend_from_slice(&config.miner_budget_atoms.to_be_bytes());
    bytes.extend_from_slice(&(config.signature_threshold as u32).to_be_bytes());
    for pool in RewardPool::ALL {
        bytes.push(pool.id());
        bytes.extend_from_slice(&config.pool_ceilings_atoms[&pool].to_be_bytes());
    }
    bytes.extend_from_slice(&(config.authorized_signers.len() as u32).to_be_bytes());
    for signer in &config.authorized_signers {
        bytes.extend_from_slice(signer);
    }
    let result = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

fn take_snapshot_bytes<'a>(
    input: &'a [u8],
    cursor: &mut usize,
    count: usize,
) -> Result<&'a [u8], PoolError> {
    let end = cursor
        .checked_add(count)
        .ok_or(PoolError::SnapshotMalformed)?;
    let result = input
        .get(*cursor..end)
        .ok_or(PoolError::SnapshotMalformed)?;
    *cursor = end;
    Ok(result)
}

fn read_snapshot_u32(input: &[u8], cursor: &mut usize) -> Result<u32, PoolError> {
    let bytes = take_snapshot_bytes(input, cursor, 4)?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_snapshot_u128(input: &[u8], cursor: &mut usize) -> Result<u128, PoolError> {
    let bytes = take_snapshot_bytes(input, cursor, 16)?;
    let mut value = [0u8; 16];
    value.copy_from_slice(bytes);
    Ok(u128::from_be_bytes(value))
}

fn read_snapshot_array32(input: &[u8], cursor: &mut usize) -> Result<[u8; 32], PoolError> {
    let bytes = take_snapshot_bytes(input, cursor, 32)?;
    let mut value = [0u8; 32];
    value.copy_from_slice(bytes);
    Ok(value)
}

fn validate_snapshot_accounting(accounting: &PoolAccounting) -> Result<(), PoolError> {
    if accounting.pool_awarded_atoms.len() != REQUIRED_POOL_COUNT
        || accounting.miner_issued_atoms > accounting.config.miner_budget_atoms
        || accounting.recipient_balances.len() > MAX_SNAPSHOT_ENTRIES
        || accounting.applied_claim_ids.len() > MAX_SNAPSHOT_ENTRIES
    {
        return Err(PoolError::SnapshotInvariantViolation);
    }

    let mut pool_total = 0u128;
    for pool in RewardPool::ALL {
        let awarded = accounting
            .pool_awarded_atoms
            .get(&pool)
            .copied()
            .ok_or(PoolError::SnapshotInvariantViolation)?;
        if awarded > accounting.config.pool_ceilings_atoms[&pool] {
            return Err(PoolError::SnapshotInvariantViolation);
        }
        pool_total = pool_total
            .checked_add(awarded)
            .ok_or(PoolError::SnapshotInvariantViolation)?;
    }

    let expected_issued = accounting
        .config
        .initially_issued_atoms
        .checked_add(accounting.miner_issued_atoms)
        .and_then(|value| value.checked_add(pool_total))
        .ok_or(PoolError::SnapshotInvariantViolation)?;
    if accounting.issued_atoms != expected_issued
        || accounting.issued_atoms > accounting.config.maximum_supply_atoms
    {
        return Err(PoolError::SnapshotInvariantViolation);
    }

    let mut recipient_total = 0u128;
    for (recipient, amount) in &accounting.recipient_balances {
        if recipient.iter().all(|byte| *byte == 0) || *amount == 0 {
            return Err(PoolError::SnapshotInvariantViolation);
        }
        recipient_total = recipient_total
            .checked_add(*amount)
            .ok_or(PoolError::SnapshotInvariantViolation)?;
    }
    if recipient_total != pool_total
        || accounting
            .applied_claim_ids
            .iter()
            .any(|claim_id| claim_id.iter().all(|byte| *byte == 0))
    {
        return Err(PoolError::SnapshotInvariantViolation);
    }
    Ok(())
}

impl PoolAccounting {
    pub fn new(config: RewardPoolConfig) -> Result<Self, PoolError> {
        if config.network_id.iter().all(|byte| *byte == 0) {
            return Err(PoolError::InvalidNetworkId);
        }
        if config.maximum_supply_atoms == 0
            || config.initially_issued_atoms > config.maximum_supply_atoms
            || config.signature_threshold == 0
            || config.signature_threshold > config.authorized_signers.len()
            || config.authorized_signers.len() > MAX_CLAIM_SIGNERS
            || config.pool_ceilings_atoms.len() != REQUIRED_POOL_COUNT
        {
            return Err(PoolError::InvalidConfiguration);
        }
        for pool in RewardPool::ALL {
            if !config.pool_ceilings_atoms.contains_key(&pool) {
                return Err(PoolError::InvalidConfiguration);
            }
        }
        for key in &config.authorized_signers {
            VerifyingKey::from_bytes(key).map_err(|_| PoolError::InvalidSignerKey)?;
        }

        let mut total_ceiling = config
            .initially_issued_atoms
            .checked_add(config.miner_budget_atoms)
            .ok_or(PoolError::ArithmeticOverflow)?;
        for amount in config.pool_ceilings_atoms.values() {
            total_ceiling = total_ceiling
                .checked_add(*amount)
                .ok_or(PoolError::ArithmeticOverflow)?;
        }
        if total_ceiling > config.maximum_supply_atoms {
            return Err(PoolError::SupplyCapExceeded);
        }

        let pool_awarded_atoms = RewardPool::ALL.into_iter().map(|p| (p, 0)).collect();
        Ok(Self {
            issued_atoms: config.initially_issued_atoms,
            miner_issued_atoms: 0,
            pool_awarded_atoms,
            recipient_balances: BTreeMap::new(),
            applied_claim_ids: BTreeSet::new(),
            config,
        })
    }

    pub fn issued_atoms(&self) -> u128 {
        self.issued_atoms
    }

    pub fn miner_issued_atoms(&self) -> u128 {
        self.miner_issued_atoms
    }

    pub fn pool_awarded_atoms(&self, pool: RewardPool) -> u128 {
        self.pool_awarded_atoms.get(&pool).copied().unwrap_or(0)
    }

    pub fn recipient_balance_atoms(&self, recipient: &[u8; 32]) -> u128 {
        self.recipient_balances.get(recipient).copied().unwrap_or(0)
    }

    pub fn remaining_pool_atoms(&self, pool: RewardPool) -> u128 {
        self.config.pool_ceilings_atoms[&pool] - self.pool_awarded_atoms(pool)
    }

    pub fn remaining_miner_budget_atoms(&self) -> u128 {
        self.config.miner_budget_atoms - self.miner_issued_atoms
    }

    pub fn applied_claim_count(&self) -> usize {
        self.applied_claim_ids.len()
    }

    /// Serializes this research model's accounting/replay state in deterministic order.
    ///
    /// The trailing SHA-256 checksum detects accidental corruption only; it is not an
    /// authenticator and does not prevent an attacker from rewriting state or rolling it back.
    /// This format is not a canonical ledger snapshot or a production persistence contract.
    pub fn snapshot_bytes(&self) -> Result<Vec<u8>, PoolError> {
        validate_snapshot_accounting(self)?;
        if self.recipient_balances.len() > MAX_SNAPSHOT_ENTRIES
            || self.applied_claim_ids.len() > MAX_SNAPSHOT_ENTRIES
        {
            return Err(PoolError::SnapshotTooLarge);
        }

        let fixed = SNAPSHOT_MAGIC.len()
            + 32
            + 16
            + 16
            + 1
            + REQUIRED_POOL_COUNT * 17
            + 4
            + 4
            + SNAPSHOT_CHECKSUM_LEN;
        let balances_len = self
            .recipient_balances
            .len()
            .checked_mul(48)
            .ok_or(PoolError::SnapshotTooLarge)?;
        let claims_len = self
            .applied_claim_ids
            .len()
            .checked_mul(32)
            .ok_or(PoolError::SnapshotTooLarge)?;
        let estimated_len = fixed
            .checked_add(balances_len)
            .and_then(|value| value.checked_add(claims_len))
            .ok_or(PoolError::SnapshotTooLarge)?;
        if estimated_len > MAX_SNAPSHOT_BYTES {
            return Err(PoolError::SnapshotTooLarge);
        }

        let mut payload = Vec::with_capacity(estimated_len - SNAPSHOT_CHECKSUM_LEN);
        payload.extend_from_slice(SNAPSHOT_MAGIC);
        payload.extend_from_slice(&snapshot_config_fingerprint(&self.config));
        payload.extend_from_slice(&self.issued_atoms.to_be_bytes());
        payload.extend_from_slice(&self.miner_issued_atoms.to_be_bytes());
        payload.push(REQUIRED_POOL_COUNT as u8);
        for pool in RewardPool::ALL {
            payload.push(pool.id());
            payload.extend_from_slice(&self.pool_awarded_atoms(pool).to_be_bytes());
        }

        payload.extend_from_slice(&(self.recipient_balances.len() as u32).to_be_bytes());
        for (recipient, balance) in &self.recipient_balances {
            payload.extend_from_slice(recipient);
            payload.extend_from_slice(&balance.to_be_bytes());
        }
        payload.extend_from_slice(&(self.applied_claim_ids.len() as u32).to_be_bytes());
        for claim_id in &self.applied_claim_ids {
            payload.extend_from_slice(claim_id);
        }

        let checksum = snapshot_checksum(&payload);
        payload.extend_from_slice(&checksum);
        debug_assert_eq!(payload.len(), estimated_len);
        Ok(payload)
    }

    /// Restores a candidate model snapshot under an independently supplied, matching config.
    /// Parsing is bounded; malformed, corrupt, mismatched and inconsistent snapshots fail closed.
    pub fn restore_snapshot(config: RewardPoolConfig, bytes: &[u8]) -> Result<Self, PoolError> {
        // Validate the supplied configuration even if the snapshot bytes are untrusted.
        let _empty_baseline = Self::new(config.clone())?;
        if bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err(PoolError::SnapshotTooLarge);
        }
        let minimum_len = SNAPSHOT_MAGIC.len()
            + 32
            + 16
            + 16
            + 1
            + REQUIRED_POOL_COUNT * 17
            + 4
            + 4
            + SNAPSHOT_CHECKSUM_LEN;
        if bytes.len() < minimum_len {
            return Err(PoolError::SnapshotMalformed);
        }

        let payload_len = bytes
            .len()
            .checked_sub(SNAPSHOT_CHECKSUM_LEN)
            .ok_or(PoolError::SnapshotMalformed)?;
        let (payload, supplied_checksum) = bytes.split_at(payload_len);
        if snapshot_checksum(payload).as_slice() != supplied_checksum {
            return Err(PoolError::SnapshotChecksumMismatch);
        }

        let mut cursor = 0usize;
        if take_snapshot_bytes(payload, &mut cursor, SNAPSHOT_MAGIC.len())? != SNAPSHOT_MAGIC {
            return Err(PoolError::SnapshotMalformed);
        }
        let fingerprint = read_snapshot_array32(payload, &mut cursor)?;
        if fingerprint != snapshot_config_fingerprint(&config) {
            return Err(PoolError::SnapshotConfigMismatch);
        }

        let issued_atoms = read_snapshot_u128(payload, &mut cursor)?;
        let miner_issued_atoms = read_snapshot_u128(payload, &mut cursor)?;
        let pool_count = *take_snapshot_bytes(payload, &mut cursor, 1)?
            .first()
            .ok_or(PoolError::SnapshotMalformed)? as usize;
        if pool_count != REQUIRED_POOL_COUNT {
            return Err(PoolError::SnapshotMalformed);
        }

        let mut pool_awarded_atoms = BTreeMap::new();
        for pool in RewardPool::ALL {
            let pool_id = *take_snapshot_bytes(payload, &mut cursor, 1)?
                .first()
                .ok_or(PoolError::SnapshotMalformed)?;
            if pool_id != pool.id() {
                return Err(PoolError::SnapshotMalformed);
            }
            let awarded = read_snapshot_u128(payload, &mut cursor)?;
            if pool_awarded_atoms.insert(pool, awarded).is_some() {
                return Err(PoolError::SnapshotMalformed);
            }
        }

        let balance_count = read_snapshot_u32(payload, &mut cursor)? as usize;
        if balance_count > MAX_SNAPSHOT_ENTRIES {
            return Err(PoolError::SnapshotTooLarge);
        }
        let mut recipient_balances = BTreeMap::new();
        let mut previous_recipient: Option<[u8; 32]> = None;
        for _ in 0..balance_count {
            let recipient = read_snapshot_array32(payload, &mut cursor)?;
            let balance = read_snapshot_u128(payload, &mut cursor)?;
            if previous_recipient.is_some_and(|previous| previous >= recipient) {
                return Err(PoolError::SnapshotMalformed);
            }
            previous_recipient = Some(recipient);
            if recipient_balances.insert(recipient, balance).is_some() {
                return Err(PoolError::SnapshotMalformed);
            }
        }

        let claim_count = read_snapshot_u32(payload, &mut cursor)? as usize;
        if claim_count > MAX_SNAPSHOT_ENTRIES {
            return Err(PoolError::SnapshotTooLarge);
        }
        let mut applied_claim_ids = BTreeSet::new();
        let mut previous_claim_id: Option<[u8; 32]> = None;
        for _ in 0..claim_count {
            let claim_id = read_snapshot_array32(payload, &mut cursor)?;
            if previous_claim_id.is_some_and(|previous| previous >= claim_id) {
                return Err(PoolError::SnapshotMalformed);
            }
            previous_claim_id = Some(claim_id);
            if !applied_claim_ids.insert(claim_id) {
                return Err(PoolError::SnapshotMalformed);
            }
        }
        if cursor != payload.len() {
            return Err(PoolError::SnapshotMalformed);
        }

        let restored = Self {
            config,
            issued_atoms,
            miner_issued_atoms,
            pool_awarded_atoms,
            recipient_balances,
            applied_claim_ids,
        };
        validate_snapshot_accounting(&restored)?;
        Ok(restored)
    }

    /// Records a valid block subsidy in the same supply accounting domain as program awards.
    /// Caller must invoke this only after canonical block/subsidy validation.
    pub fn record_mining_reward(&mut self, amount_atoms: u128) -> Result<(), PoolError> {
        if amount_atoms == 0 {
            return Err(PoolError::ZeroAmount);
        }
        let next_miner = self
            .miner_issued_atoms
            .checked_add(amount_atoms)
            .ok_or(PoolError::ArithmeticOverflow)?;
        if next_miner > self.config.miner_budget_atoms {
            return Err(PoolError::MiningBudgetExceeded);
        }
        let next_issued = self
            .issued_atoms
            .checked_add(amount_atoms)
            .ok_or(PoolError::ArithmeticOverflow)?;
        if next_issued > self.config.maximum_supply_atoms {
            return Err(PoolError::SupplyCapExceeded);
        }
        self.miner_issued_atoms = next_miner;
        self.issued_atoms = next_issued;
        Ok(())
    }

    /// Atomically validates and applies one threshold-authorized program issuance claim.
    /// All counters and recipient balances change only after every check has passed.
    pub fn apply_claim(
        &mut self,
        claim: &RewardClaim,
        current_epoch: u64,
    ) -> Result<(), PoolError> {
        if claim.network_id != self.config.network_id {
            return Err(PoolError::WrongNetwork);
        }
        if claim.amount_atoms == 0 {
            return Err(PoolError::ZeroAmount);
        }
        if claim.claim_id.iter().all(|byte| *byte == 0) {
            return Err(PoolError::InvalidClaimId);
        }
        if claim.recipient.iter().all(|byte| *byte == 0) {
            return Err(PoolError::InvalidRecipient);
        }
        if claim.expires_at_epoch < claim.valid_from_epoch {
            return Err(PoolError::InvalidClaimWindow);
        }
        if current_epoch < claim.valid_from_epoch {
            return Err(PoolError::ClaimNotYetValid);
        }
        if current_epoch > claim.expires_at_epoch {
            return Err(PoolError::ClaimExpired);
        }
        if self.applied_claim_ids.contains(&claim.claim_id) {
            return Err(PoolError::DuplicateClaim);
        }

        // Bound verification work before walking a caller-provided signature vector.
        if claim.signatures.len() > self.config.authorized_signers.len()
            || claim.signatures.len() > MAX_CLAIM_SIGNERS
        {
            return Err(PoolError::TooManySignatures);
        }

        let message = claim.signing_bytes();
        let mut signers_seen = BTreeSet::new();
        let mut valid_signatures = 0usize;
        for item in &claim.signatures {
            if !self
                .config
                .authorized_signers
                .contains(&item.signer_public_key)
            {
                return Err(PoolError::UnknownSigner);
            }
            if !signers_seen.insert(item.signer_public_key) {
                return Err(PoolError::DuplicateSigner);
            }
            let key = VerifyingKey::from_bytes(&item.signer_public_key)
                .map_err(|_| PoolError::InvalidSignerKey)?;
            let signature = Signature::from_bytes(&item.signature);
            key.verify_strict(&message, &signature)
                .map_err(|_| PoolError::InvalidSignature)?;
            valid_signatures += 1;
        }
        if valid_signatures < self.config.signature_threshold {
            return Err(PoolError::InsufficientThreshold);
        }

        let next_pool_awarded = self
            .pool_awarded_atoms(claim.pool)
            .checked_add(claim.amount_atoms)
            .ok_or(PoolError::ArithmeticOverflow)?;
        if next_pool_awarded > self.config.pool_ceilings_atoms[&claim.pool] {
            return Err(PoolError::PoolBudgetExceeded);
        }
        let next_issued = self
            .issued_atoms
            .checked_add(claim.amount_atoms)
            .ok_or(PoolError::ArithmeticOverflow)?;
        if next_issued > self.config.maximum_supply_atoms {
            return Err(PoolError::SupplyCapExceeded);
        }
        let next_recipient_balance = self
            .recipient_balance_atoms(&claim.recipient)
            .checked_add(claim.amount_atoms)
            .ok_or(PoolError::ArithmeticOverflow)?;

        // Commit mutations only after every validation and checked-arithmetic operation succeeds.
        self.issued_atoms = next_issued;
        self.pool_awarded_atoms
            .insert(claim.pool, next_pool_awarded);
        self.recipient_balances
            .insert(claim.recipient, next_recipient_balance);
        self.applied_claim_ids.insert(claim.claim_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const NETWORK: [u8; 32] = [0xA1; 32];

    fn signing_keys() -> [SigningKey; 3] {
        [
            SigningKey::from_bytes(&[11; 32]),
            SigningKey::from_bytes(&[22; 32]),
            SigningKey::from_bytes(&[33; 32]),
        ]
    }

    fn config_with(
        adoption_ceiling: u128,
        maximum_supply: u128,
    ) -> (RewardPoolConfig, [SigningKey; 3]) {
        let keys = signing_keys();
        let authorized_signers = keys.iter().map(|k| k.verifying_key().to_bytes()).collect();
        let pool_ceilings_atoms = [
            (RewardPool::Adoption, adoption_ceiling),
            (RewardPool::DeveloperEcosystem, 100),
            (RewardPool::Security, 50),
            (RewardPool::CommunityInfrastructure, 50),
        ]
        .into_iter()
        .collect();
        let config = RewardPoolConfig {
            network_id: NETWORK,
            maximum_supply_atoms: maximum_supply,
            initially_issued_atoms: 100,
            miner_budget_atoms: 600,
            pool_ceilings_atoms,
            authorized_signers,
            signature_threshold: 2,
        };
        (config, keys)
    }

    fn unsigned_claim(pool: RewardPool, amount: u128, claim_id_byte: u8) -> RewardClaim {
        RewardClaim {
            network_id: NETWORK,
            pool,
            amount_atoms: amount,
            recipient: [0x77; 32],
            claim_id: [claim_id_byte; 32],
            valid_from_epoch: 5,
            expires_at_epoch: 10,
            signatures: vec![],
        }
    }

    fn signed_claim(mut claim: RewardClaim, keys: &[SigningKey], indices: &[usize]) -> RewardClaim {
        let message = claim.signing_bytes();
        claim.signatures = indices
            .iter()
            .map(|index| ClaimSignature {
                signer_public_key: keys[*index].verifying_key().to_bytes(),
                signature: keys[*index].sign(&message).to_bytes(),
            })
            .collect();
        claim
    }

    fn ledger(adoption_ceiling: u128, maximum_supply: u128) -> (PoolAccounting, [SigningKey; 3]) {
        let (config, keys) = config_with(adoption_ceiling, maximum_supply);
        (PoolAccounting::new(config).unwrap(), keys)
    }

    fn refresh_snapshot_checksum(bytes: &mut [u8]) {
        let payload_len = bytes.len() - SNAPSHOT_CHECKSUM_LEN;
        let checksum = snapshot_checksum(&bytes[..payload_len]);
        bytes[payload_len..].copy_from_slice(&checksum);
    }

    #[test]
    fn valid_threshold_claim_mints_once_and_updates_pool_and_balance_atomically() {
        let (mut ledger, keys) = ledger(100, 1_000);
        let claim = signed_claim(unsigned_claim(RewardPool::Adoption, 25, 1), &keys, &[0, 2]);
        ledger.apply_claim(&claim, 6).unwrap();
        assert_eq!(ledger.issued_atoms(), 125);
        assert_eq!(ledger.pool_awarded_atoms(RewardPool::Adoption), 25);
        assert_eq!(ledger.remaining_pool_atoms(RewardPool::Adoption), 75);
        assert_eq!(ledger.recipient_balance_atoms(&[0x77; 32]), 25);
        assert_eq!(ledger.applied_claim_count(), 1);
    }

    #[test]
    fn duplicate_claim_is_rejected_without_mutation() {
        let (mut ledger, keys) = ledger(100, 1_000);
        let claim = signed_claim(unsigned_claim(RewardPool::Adoption, 25, 2), &keys, &[0, 1]);
        ledger.apply_claim(&claim, 5).unwrap();
        let before = ledger.clone();
        assert_eq!(
            ledger.apply_claim(&claim, 5),
            Err(PoolError::DuplicateClaim)
        );
        assert_eq!(ledger, before);
    }

    #[test]
    fn wrong_network_rejected_without_mutation_even_if_claim_is_signed() {
        let (mut ledger, keys) = ledger(100, 1_000);
        let mut claim = unsigned_claim(RewardPool::Adoption, 25, 3);
        claim.network_id = [0xB2; 32];
        let claim = signed_claim(claim, &keys, &[0, 1]);
        let before = ledger.clone();
        assert_eq!(ledger.apply_claim(&claim, 6), Err(PoolError::WrongNetwork));
        assert_eq!(ledger, before);
    }

    #[test]
    fn insufficient_threshold_is_rejected_without_mutation() {
        let (mut ledger, keys) = ledger(100, 1_000);
        let claim = signed_claim(unsigned_claim(RewardPool::Adoption, 25, 4), &keys, &[0]);
        let before = ledger.clone();
        assert_eq!(
            ledger.apply_claim(&claim, 6),
            Err(PoolError::InsufficientThreshold)
        );
        assert_eq!(ledger, before);
    }

    #[test]
    fn duplicate_signer_is_rejected_without_mutation() {
        let (mut ledger, keys) = ledger(100, 1_000);
        let claim = signed_claim(unsigned_claim(RewardPool::Adoption, 25, 5), &keys, &[0, 0]);
        let before = ledger.clone();
        assert_eq!(
            ledger.apply_claim(&claim, 6),
            Err(PoolError::DuplicateSigner)
        );
        assert_eq!(ledger, before);
    }

    #[test]
    fn modified_amount_invalidates_signature_without_mutation() {
        let (mut ledger, keys) = ledger(100, 1_000);
        let mut claim = signed_claim(unsigned_claim(RewardPool::Adoption, 25, 6), &keys, &[0, 1]);
        claim.amount_atoms = 26;
        let before = ledger.clone();
        assert_eq!(
            ledger.apply_claim(&claim, 6),
            Err(PoolError::InvalidSignature)
        );
        assert_eq!(ledger, before);
    }

    #[test]
    fn expired_claim_is_rejected_without_mutation() {
        let (mut ledger, keys) = ledger(100, 1_000);
        let claim = signed_claim(unsigned_claim(RewardPool::Adoption, 25, 7), &keys, &[0, 1]);
        let before = ledger.clone();
        assert_eq!(ledger.apply_claim(&claim, 11), Err(PoolError::ClaimExpired));
        assert_eq!(ledger, before);
    }

    #[test]
    fn not_yet_valid_claim_is_rejected_without_mutation() {
        let (mut ledger, keys) = ledger(100, 1_000);
        let claim = signed_claim(unsigned_claim(RewardPool::Adoption, 25, 8), &keys, &[0, 1]);
        let before = ledger.clone();
        assert_eq!(
            ledger.apply_claim(&claim, 4),
            Err(PoolError::ClaimNotYetValid)
        );
        assert_eq!(ledger, before);
    }

    #[test]
    fn pool_budget_overrun_is_rejected_without_mutation() {
        let (mut ledger, keys) = ledger(20, 1_000);
        let claim = signed_claim(unsigned_claim(RewardPool::Adoption, 25, 9), &keys, &[0, 1]);
        let before = ledger.clone();
        assert_eq!(
            ledger.apply_claim(&claim, 6),
            Err(PoolError::PoolBudgetExceeded)
        );
        assert_eq!(ledger, before);
    }

    #[test]
    fn mining_budget_and_global_supply_are_bounded() {
        let (mut ledger, _) = ledger(100, 1_000);
        ledger.record_mining_reward(500).unwrap();
        assert_eq!(ledger.issued_atoms(), 600);
        assert_eq!(ledger.remaining_miner_budget_atoms(), 100);
        let before = ledger.clone();
        assert_eq!(
            ledger.record_mining_reward(101),
            Err(PoolError::MiningBudgetExceeded)
        );
        assert_eq!(ledger, before);
        ledger.record_mining_reward(100).unwrap();
        assert_eq!(ledger.issued_atoms(), 700);
        assert_eq!(
            ledger.record_mining_reward(1),
            Err(PoolError::MiningBudgetExceeded)
        );
    }

    #[test]
    fn invalid_configuration_cannot_overbook_cap_or_omit_pool() {
        let (config, _) = config_with(100, 999);
        assert_eq!(
            PoolAccounting::new(config),
            Err(PoolError::SupplyCapExceeded)
        );

        let (mut config, _) = config_with(100, 1_000);
        config.pool_ceilings_atoms.remove(&RewardPool::Security);
        assert_eq!(
            PoolAccounting::new(config),
            Err(PoolError::InvalidConfiguration)
        );
    }

    #[test]
    fn unauthorized_signer_is_rejected_without_mutation() {
        let (mut ledger, _) = ledger(100, 1_000);
        let outsider = SigningKey::from_bytes(&[44; 32]);
        let claim = signed_claim(
            unsigned_claim(RewardPool::Adoption, 25, 12),
            &[outsider],
            &[0],
        );
        let before = ledger.clone();
        assert_eq!(ledger.apply_claim(&claim, 6), Err(PoolError::UnknownSigner));
        assert_eq!(ledger, before);
    }

    #[test]
    fn invalid_claim_window_and_zero_claim_id_are_rejected_without_mutation() {
        let (mut ledger, keys) = ledger(100, 1_000);
        let mut invalid_window = unsigned_claim(RewardPool::Adoption, 25, 13);
        invalid_window.expires_at_epoch = invalid_window.valid_from_epoch - 1;
        let invalid_window = signed_claim(invalid_window, &keys, &[0, 1]);
        let before = ledger.clone();
        assert_eq!(
            ledger.apply_claim(&invalid_window, 6),
            Err(PoolError::InvalidClaimWindow)
        );
        assert_eq!(ledger, before);

        let mut zero_id = unsigned_claim(RewardPool::Adoption, 25, 14);
        zero_id.claim_id = [0; 32];
        let zero_id = signed_claim(zero_id, &keys, &[0, 1]);
        assert_eq!(
            ledger.apply_claim(&zero_id, 6),
            Err(PoolError::InvalidClaimId)
        );
        assert_eq!(ledger, before);
    }

    #[test]
    fn different_program_pools_have_independent_counters() {
        let (mut ledger, keys) = ledger(100, 1_000);
        let adoption = signed_claim(unsigned_claim(RewardPool::Adoption, 40, 15), &keys, &[0, 1]);
        let security = signed_claim(unsigned_claim(RewardPool::Security, 20, 16), &keys, &[1, 2]);
        ledger.apply_claim(&adoption, 6).unwrap();
        ledger.apply_claim(&security, 6).unwrap();
        assert_eq!(ledger.issued_atoms(), 160);
        assert_eq!(ledger.pool_awarded_atoms(RewardPool::Adoption), 40);
        assert_eq!(ledger.remaining_pool_atoms(RewardPool::Adoption), 60);
        assert_eq!(ledger.pool_awarded_atoms(RewardPool::Security), 20);
        assert_eq!(ledger.remaining_pool_atoms(RewardPool::Security), 30);
        assert_eq!(ledger.recipient_balance_atoms(&[0x77; 32]), 60);
    }

    #[test]
    fn zero_amount_and_zero_recipient_are_rejected_without_mutation() {
        let (mut ledger, keys) = ledger(100, 1_000);
        let zero_amount = signed_claim(unsigned_claim(RewardPool::Adoption, 0, 10), &keys, &[0, 1]);
        let before = ledger.clone();
        assert_eq!(
            ledger.apply_claim(&zero_amount, 6),
            Err(PoolError::ZeroAmount)
        );
        assert_eq!(ledger, before);

        let mut claim = unsigned_claim(RewardPool::Adoption, 25, 11);
        claim.recipient = [0; 32];
        let claim = signed_claim(claim, &keys, &[0, 1]);
        assert_eq!(
            ledger.apply_claim(&claim, 6),
            Err(PoolError::InvalidRecipient)
        );
        assert_eq!(ledger, before);
    }

    #[test]
    fn too_many_signatures_are_rejected_before_signature_verification() {
        let (mut ledger, keys) = ledger(100, 1_000);
        let claim = signed_claim(
            unsigned_claim(RewardPool::Adoption, 25, 17),
            &keys,
            &[0, 1, 2, 0],
        );
        let before = ledger.clone();
        assert_eq!(
            ledger.apply_claim(&claim, 6),
            Err(PoolError::TooManySignatures)
        );
        assert_eq!(ledger, before);
    }

    #[test]
    fn deterministic_randomized_sequences_preserve_global_and_per_pool_invariants() {
        let (mut ledger, keys) = ledger(100, 1_000);
        ledger.record_mining_reward(17).unwrap();
        let mut state = 0x9E37_79B9_7F4A_7C15u64;

        for claim_no in 1..=96u8 {
            // Fixed-seed xorshift: deterministic stress coverage, not cryptographic randomness.
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let pool = match claim_no % 4 {
                0 => RewardPool::Adoption,
                1 => RewardPool::DeveloperEcosystem,
                2 => RewardPool::Security,
                _ => RewardPool::CommunityInfrastructure,
            };
            let amount = (state % 27 + 1) as u128;
            let claim = signed_claim(unsigned_claim(pool, amount, claim_no), &keys, &[0, 1]);
            let before = ledger.clone();
            match ledger.apply_claim(&claim, 6) {
                Ok(()) => {}
                Err(PoolError::PoolBudgetExceeded) => assert_eq!(ledger, before),
                Err(other) => panic!("unexpected randomized claim result: {other:?}"),
            }

            let total_pools: u128 = RewardPool::ALL
                .into_iter()
                .map(|item| ledger.pool_awarded_atoms(item))
                .sum();
            assert_eq!(
                ledger.issued_atoms(),
                100 + ledger.miner_issued_atoms() + total_pools
            );
            assert!(ledger.issued_atoms() <= ledger.config.maximum_supply_atoms);
            for item in RewardPool::ALL {
                assert!(
                    ledger.pool_awarded_atoms(item) <= ledger.config.pool_ceilings_atoms[&item]
                );
            }
            assert_eq!(ledger.recipient_balance_atoms(&[0x77; 32]), total_pools);
            if claim_no % 8 == 0 {
                let snapshot = ledger.snapshot_bytes().unwrap();
                let restored =
                    PoolAccounting::restore_snapshot(ledger.config.clone(), &snapshot).unwrap();
                assert_eq!(restored, ledger);
            }
        }
    }

    #[test]
    fn snapshot_round_trip_preserves_accounting_and_replay_guard() {
        let (mut ledger, keys) = ledger(100, 1_000);
        ledger.record_mining_reward(8).unwrap();
        let claim = signed_claim(unsigned_claim(RewardPool::Adoption, 25, 18), &keys, &[0, 1]);
        ledger.apply_claim(&claim, 6).unwrap();

        let bytes = ledger.snapshot_bytes().unwrap();
        let restored = PoolAccounting::restore_snapshot(ledger.config.clone(), &bytes).unwrap();
        assert_eq!(restored, ledger);
        assert_eq!(restored.issued_atoms(), 133);
        assert_eq!(restored.miner_issued_atoms(), 8);
        assert_eq!(restored.pool_awarded_atoms(RewardPool::Adoption), 25);
        assert_eq!(restored.recipient_balance_atoms(&[0x77; 32]), 25);
        assert_eq!(restored.applied_claim_count(), 1);

        let mut replay_attempt = restored.clone();
        assert_eq!(
            replay_attempt.apply_claim(&claim, 6),
            Err(PoolError::DuplicateClaim)
        );
        assert_eq!(replay_attempt, restored);
    }

    #[test]
    fn snapshot_rejects_corruption_truncation_and_appended_data() {
        let (ledger, _) = ledger(100, 1_000);
        let good = ledger.snapshot_bytes().unwrap();

        let mut corrupted = good.clone();
        corrupted[SNAPSHOT_MAGIC.len() + 3] ^= 0x40;
        assert_eq!(
            PoolAccounting::restore_snapshot(ledger.config.clone(), &corrupted),
            Err(PoolError::SnapshotChecksumMismatch)
        );

        let truncated = &good[..good.len() - 2];
        assert!(matches!(
            PoolAccounting::restore_snapshot(ledger.config.clone(), truncated),
            Err(PoolError::SnapshotChecksumMismatch | PoolError::SnapshotMalformed)
        ));

        let mut appended = good.clone();
        appended.push(0x42);
        // Even with a recomputed unkeyed checksum, non-canonical trailing data is rejected.
        refresh_snapshot_checksum(&mut appended);
        assert_eq!(
            PoolAccounting::restore_snapshot(ledger.config.clone(), &appended),
            Err(PoolError::SnapshotMalformed)
        );
    }

    #[test]
    fn snapshot_restore_rejects_other_configuration_and_oversized_input() {
        let (ledger, _) = ledger(100, 1_000);
        let snapshot = ledger.snapshot_bytes().unwrap();
        let mut other_config = ledger.config.clone();
        other_config.network_id = [0xB2; 32];
        assert_eq!(
            PoolAccounting::restore_snapshot(other_config, &snapshot),
            Err(PoolError::SnapshotConfigMismatch)
        );

        let oversized = vec![0u8; MAX_SNAPSHOT_BYTES + 1];
        assert_eq!(
            PoolAccounting::restore_snapshot(ledger.config.clone(), &oversized),
            Err(PoolError::SnapshotTooLarge)
        );
    }

    #[test]
    fn snapshot_rejects_checksum_valid_but_inconsistent_issuance() {
        let (ledger, _) = ledger(100, 1_000);
        let mut bytes = ledger.snapshot_bytes().unwrap();
        let issued_offset = SNAPSHOT_MAGIC.len() + 32;
        bytes[issued_offset..issued_offset + 16].fill(0);
        bytes[issued_offset + 15] = 1;
        refresh_snapshot_checksum(&mut bytes);
        assert_eq!(
            PoolAccounting::restore_snapshot(ledger.config.clone(), &bytes),
            Err(PoolError::SnapshotInvariantViolation)
        );
    }

    #[test]
    fn snapshot_parser_bounds_untrusted_entry_counts_before_allocating() {
        let (ledger, _) = ledger(100, 1_000);
        let mut bytes = ledger.snapshot_bytes().unwrap();
        let balance_count_offset =
            SNAPSHOT_MAGIC.len() + 32 + 16 + 16 + 1 + REQUIRED_POOL_COUNT * 17;
        bytes[balance_count_offset..balance_count_offset + 4]
            .copy_from_slice(&u32::MAX.to_be_bytes());
        refresh_snapshot_checksum(&mut bytes);
        assert_eq!(
            PoolAccounting::restore_snapshot(ledger.config.clone(), &bytes),
            Err(PoolError::SnapshotTooLarge)
        );
    }

    #[test]
    fn every_single_byte_corruption_in_small_snapshot_is_rejected() {
        let (ledger, _) = ledger(100, 1_000);
        let snapshot = ledger.snapshot_bytes().unwrap();
        for offset in 0..snapshot.len() {
            let mut corrupted = snapshot.clone();
            corrupted[offset] ^= 1;
            assert!(
                PoolAccounting::restore_snapshot(ledger.config.clone(), &corrupted).is_err(),
                "single-byte corruption at offset {offset} was unexpectedly accepted"
            );
        }
    }
}
