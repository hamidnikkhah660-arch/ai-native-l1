//! CP-0528 QFP6 native-token monetary policy and issuance accounting candidate.
//!
//! This module defines the eight exclusive issuance ceilings, a 1B-Founder Genesis,
//! a 3B mining/security envelope and deterministic candidate halving arithmetic.
//! It is intended to become part of the canonical QFB6 state root and snapshot.
//! The inherited CP-0422 schedule is explicit candidate input, not frozen production
//! consensus. Category releases and burn execution still require signed QFB6 operations.

use sha2::{Digest, Sha256};

pub type Digest32 = [u8; 32];
pub type AccountId = [u8; 32];

pub const QZXB_ATOMS_PER_COIN: u128 = 100_000_000;
pub const QRUN_V06_MAX_GROSS_ISSUANCE_ATOMS: u128 = 10_000_000_000u128 * QZXB_ATOMS_PER_COIN;
pub const QRUN_V06_FOUNDER_GENESIS_ATOMS: u128 = 1_000_000_000u128 * QZXB_ATOMS_PER_COIN;
pub const QRUN_V06_MINING_SECURITY_BUDGET_ATOMS: u128 = 3_000_000_000u128 * QZXB_ATOMS_PER_COIN;
pub const QRUN_V06_TOKENOMICS_BUCKETS: usize = 8;
pub const QRUN_V06_TOKENOMICS_SNAPSHOT_BYTES: usize = 360;

const SNAPSHOT_MAGIC: &[u8; 4] = b"Q6TM";
const SNAPSHOT_VERSION: u16 = 2;
const SNAPSHOT_CHECKSUM_DOMAIN: &[u8] = b"QRUN-V06-TOKENOMICS-SNAPSHOT-CHECKSUM-V2\0";
const POLICY_FINGERPRINT_DOMAIN: &[u8] = b"QRUN-V06-CP0528-TOKENOMICS-POLICY-V2\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum QRunV06AllocationBucket {
    MiningNetworkSecurity = 0,
    CommunityAirdrop = 1,
    ExchangeMarketLiquidity = 2,
    MarketingPartners = 3,
    DeveloperSecurityContributors = 4,
    FinancialStrategicSupporters = 5,
    ProtocolBurnReserve = 6,
    FounderAllocation = 7,
}

impl QRunV06AllocationBucket {
    pub const ALL: [Self; QRUN_V06_TOKENOMICS_BUCKETS] = [
        Self::MiningNetworkSecurity,
        Self::CommunityAirdrop,
        Self::ExchangeMarketLiquidity,
        Self::MarketingPartners,
        Self::DeveloperSecurityContributors,
        Self::FinancialStrategicSupporters,
        Self::ProtocolBurnReserve,
        Self::FounderAllocation,
    ];

    pub const fn index(self) -> usize {
        self as usize
    }

    pub const fn budget_atoms(self) -> u128 {
        match self {
            Self::MiningNetworkSecurity => QRUN_V06_MINING_SECURITY_BUDGET_ATOMS,
            Self::CommunityAirdrop
            | Self::ExchangeMarketLiquidity
            | Self::MarketingPartners
            | Self::DeveloperSecurityContributors
            | Self::FinancialStrategicSupporters
            | Self::ProtocolBurnReserve
            | Self::FounderAllocation => 1_000_000_000u128 * QZXB_ATOMS_PER_COIN,
        }
    }

    /// Founder stewardship may release only these five recipient-facing reserves.
    /// Mining is consensus-issued, burn reserve has a separate protocol rule, and
    /// FounderAllocation is never a discretionary release bucket.
    pub const fn is_founder_releasable(self) -> bool {
        matches!(
            self,
            Self::CommunityAirdrop
                | Self::ExchangeMarketLiquidity
                | Self::MarketingPartners
                | Self::DeveloperSecurityContributors
                | Self::FinancialStrategicSupporters
        )
    }

    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::MiningNetworkSecurity),
            1 => Some(Self::CommunityAirdrop),
            2 => Some(Self::ExchangeMarketLiquidity),
            3 => Some(Self::MarketingPartners),
            4 => Some(Self::DeveloperSecurityContributors),
            5 => Some(Self::FinancialStrategicSupporters),
            6 => Some(Self::ProtocolBurnReserve),
            7 => Some(Self::FounderAllocation),
            _ => None,
        }
    }
}

pub const MAX_QRUN_V06_CATEGORY_RELEASE_SIGNATURE_BYTES: usize = 4 * 1024;
pub const MAX_QRUN_V06_CATEGORY_RELEASE_BYTES: usize = 16 * 1024;
const CATEGORY_RELEASE_MAGIC: [u8; 4] = *b"Q6RL";
const CATEGORY_RELEASE_VERSION: u16 = 1;

/// Founder-authorized, recipient-accepted release of one unissued CP-0528 reserve.
/// The three digests bind a purpose statement, supporting evidence and milestone/
/// eligibility terms. Hashes bind supplied records; they do not prove off-chain facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06SignedCategoryRelease {
    pub network_id: Digest32,
    pub bucket: QRunV06AllocationBucket,
    pub nonce: u64,
    pub recipient: AccountId,
    pub amount_atoms: u128,
    pub valid_until_timestamp: u64,
    pub purpose_digest: Digest32,
    pub evidence_digest: Digest32,
    pub milestone_policy_digest: Digest32,
    pub founder_signature: Vec<u8>,
    pub recipient_acceptance_signature: Vec<u8>,
}

impl QRunV06SignedCategoryRelease {
    /// Domain-separated Founder authorization digest. Signatures are excluded.
    pub fn signing_digest(&self) -> Result<Digest32, QRunV06TokenomicsError> {
        if self.network_id == [0; 32]
            || self.nonce == 0
            || self.recipient == [0; 32]
            || self.amount_atoms == 0
            || self.valid_until_timestamp == 0
            || !self.bucket.is_founder_releasable()
            || self.purpose_digest == [0; 32]
            || self.evidence_digest == [0; 32]
            || self.milestone_policy_digest == [0; 32]
        {
            return Err(QRunV06TokenomicsError::InvalidCategoryRelease);
        }
        let mut hash = Sha256::new();
        hash.update(b"QRUN-V06-CP0528-CATEGORY-RELEASE-AUTH-V1\\0");
        hash.update(self.network_id);
        hash.update([self.bucket as u8]);
        hash.update(self.nonce.to_be_bytes());
        hash.update(self.recipient);
        hash.update(self.amount_atoms.to_be_bytes());
        hash.update(self.valid_until_timestamp.to_be_bytes());
        hash.update(self.purpose_digest);
        hash.update(self.evidence_digest);
        hash.update(self.milestone_policy_digest);
        Ok(hash.finalize().into())
    }

    /// The recipient separately proves control of the destination account and
    /// acceptance of the exact release terms before issuance can occur.
    pub fn recipient_acceptance_digest(&self) -> Result<Digest32, QRunV06TokenomicsError> {
        let authorization = self.signing_digest()?;
        let mut hash = Sha256::new();
        hash.update(b"QRUN-V06-CP0528-CATEGORY-RELEASE-RECIPIENT-ACCEPT-V1\\0");
        hash.update(self.network_id);
        hash.update(self.recipient);
        hash.update(authorization);
        Ok(hash.finalize().into())
    }

    pub fn release_id(&self) -> Result<Digest32, QRunV06TokenomicsError> {
        self.signing_digest()
    }

    /// Canonical Q6RL operation body. Both signatures are part of the block bytes.
    pub fn encode(&self) -> Result<Vec<u8>, QRunV06TokenomicsError> {
        let _ = self.signing_digest()?;
        let _ = self.recipient_acceptance_digest()?;
        if self.founder_signature.is_empty()
            || self.founder_signature.len() > MAX_QRUN_V06_CATEGORY_RELEASE_SIGNATURE_BYTES
            || self.recipient_acceptance_signature.is_empty()
            || self.recipient_acceptance_signature.len()
                > MAX_QRUN_V06_CATEGORY_RELEASE_SIGNATURE_BYTES
        {
            return Err(QRunV06TokenomicsError::InvalidCategoryRelease);
        }
        let founder_len = u16::try_from(self.founder_signature.len())
            .map_err(|_| QRunV06TokenomicsError::InvalidCategoryRelease)?;
        let recipient_len = u16::try_from(self.recipient_acceptance_signature.len())
            .map_err(|_| QRunV06TokenomicsError::InvalidCategoryRelease)?;
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(&CATEGORY_RELEASE_MAGIC);
        out.extend_from_slice(&CATEGORY_RELEASE_VERSION.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&self.network_id);
        out.push(self.bucket as u8);
        out.extend_from_slice(&self.nonce.to_be_bytes());
        out.extend_from_slice(&self.recipient);
        out.extend_from_slice(&self.amount_atoms.to_be_bytes());
        out.extend_from_slice(&self.valid_until_timestamp.to_be_bytes());
        out.extend_from_slice(&self.purpose_digest);
        out.extend_from_slice(&self.evidence_digest);
        out.extend_from_slice(&self.milestone_policy_digest);
        out.extend_from_slice(&founder_len.to_be_bytes());
        out.extend_from_slice(&self.founder_signature);
        out.extend_from_slice(&recipient_len.to_be_bytes());
        out.extend_from_slice(&self.recipient_acceptance_signature);
        if out.len() > MAX_QRUN_V06_CATEGORY_RELEASE_BYTES {
            return Err(QRunV06TokenomicsError::InvalidCategoryRelease);
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, QRunV06TokenomicsError> {
        if bytes.len() < 4 + 2 + 2 + 32 + 1 + 8 + 32 + 16 + 8 + 96 + 2 + 1 + 2 + 1
            || bytes.len() > MAX_QRUN_V06_CATEGORY_RELEASE_BYTES
        {
            return Err(QRunV06TokenomicsError::InvalidCategoryRelease);
        }
        let mut cursor = 0usize;
        if take_array::<4>(bytes, &mut cursor)? != CATEGORY_RELEASE_MAGIC
            || take_u16(bytes, &mut cursor)? != CATEGORY_RELEASE_VERSION
            || take_u16(bytes, &mut cursor)? != 0
        {
            return Err(QRunV06TokenomicsError::InvalidCategoryRelease);
        }
        let network_id = take_array::<32>(bytes, &mut cursor)?;
        let bucket_tag = take_array::<1>(bytes, &mut cursor)?[0];
        let bucket = QRunV06AllocationBucket::from_tag(bucket_tag)
            .ok_or(QRunV06TokenomicsError::InvalidCategoryRelease)?;
        let nonce = take_u64(bytes, &mut cursor)?;
        let recipient = take_array::<32>(bytes, &mut cursor)?;
        let amount_atoms = take_u128(bytes, &mut cursor)?;
        let valid_until_timestamp = take_u64(bytes, &mut cursor)?;
        let purpose_digest = take_array::<32>(bytes, &mut cursor)?;
        let evidence_digest = take_array::<32>(bytes, &mut cursor)?;
        let milestone_policy_digest = take_array::<32>(bytes, &mut cursor)?;
        let founder_signature = take_signature(bytes, &mut cursor)?;
        let recipient_acceptance_signature = take_signature(bytes, &mut cursor)?;
        if cursor != bytes.len() {
            return Err(QRunV06TokenomicsError::InvalidCategoryRelease);
        }
        let release = Self {
            network_id,
            bucket,
            nonce,
            recipient,
            amount_atoms,
            valid_until_timestamp,
            purpose_digest,
            evidence_digest,
            milestone_policy_digest,
            founder_signature,
            recipient_acceptance_signature,
        };
        let _ = release.signing_digest()?;
        if release.encode()?.as_slice() != bytes {
            return Err(QRunV06TokenomicsError::SnapshotNonCanonical);
        }
        Ok(release)
    }
}

fn take_signature(bytes: &[u8], cursor: &mut usize) -> Result<Vec<u8>, QRunV06TokenomicsError> {
    let length = take_u16(bytes, cursor)? as usize;
    if length == 0 || length > MAX_QRUN_V06_CATEGORY_RELEASE_SIGNATURE_BYTES {
        return Err(QRunV06TokenomicsError::InvalidCategoryRelease);
    }
    let end = cursor
        .checked_add(length)
        .ok_or(QRunV06TokenomicsError::InvalidCategoryRelease)?;
    let signature = bytes
        .get(*cursor..end)
        .ok_or(QRunV06TokenomicsError::InvalidCategoryRelease)?
        .to_vec();
    *cursor = end;
    Ok(signature)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QRunV06MiningScheduleCandidate {
    pub initial_subsidy_atoms: u128,
    pub blocks_per_halving: u64,
}

impl QRunV06MiningScheduleCandidate {
    /// CP-0422 inherited candidate arithmetic. This is deliberately not a frozen
    /// production consensus profile; profile governance must approve exact values.
    pub const fn cp0422_research_candidate() -> Self {
        Self {
            initial_subsidy_atoms: 35_673_515_981,
            blocks_per_halving: 4_204_800,
        }
    }

    pub fn new(
        initial_subsidy_atoms: u128,
        blocks_per_halving: u64,
    ) -> Result<Self, QRunV06TokenomicsError> {
        let schedule = Self {
            initial_subsidy_atoms,
            blocks_per_halving,
        };
        schedule.validate()?;
        Ok(schedule)
    }

    pub fn validate(self) -> Result<(), QRunV06TokenomicsError> {
        if self.initial_subsidy_atoms == 0 || self.blocks_per_halving == 0 {
            return Err(QRunV06TokenomicsError::InvalidMiningSchedule);
        }
        if self.initial_subsidy_atoms > QRUN_V06_MINING_SECURITY_BUDGET_ATOMS {
            return Err(QRunV06TokenomicsError::InvalidMiningSchedule);
        }
        Ok(())
    }

    pub fn reward_for_height(self, height: u64) -> Result<u128, QRunV06TokenomicsError> {
        self.validate()?;
        if height == 0 {
            return Err(QRunV06TokenomicsError::InvalidHeight);
        }
        let era = (height - 1) / self.blocks_per_halving;
        if era >= u128::BITS as u64 {
            return Ok(0);
        }
        Ok(self.initial_subsidy_atoms >> era)
    }
}

pub const MAX_QRUN_V06_BURN_RESERVE_SIGNATURE_BYTES: usize = 4 * 1024;
pub const MAX_QRUN_V06_BURN_RESERVE_RETIREMENT_BYTES: usize = 16 * 1024;
const BURN_RESERVE_RETIREMENT_MAGIC: [u8; 4] = *b"Q6BR";
const BURN_RESERVE_RETIREMENT_VERSION: u16 = 1;

/// Founder-authorized, one-way retirement of unissued ProtocolBurnReserve capacity.
///
/// This does not debit user balances or burn circulating coins. In one canonical
/// transition the reserve bucket is issued to a network/policy-derived sink and
/// immediately removed from Ledger; gross issuance and burned counters rise equally,
/// so live supply is unchanged and future issuance headroom is reduced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06SignedBurnReserveRetirement {
    pub network_id: Digest32,
    pub policy_fingerprint: Digest32,
    /// Compare-and-swap guard: must equal the current cumulative reserve-burn counter.
    pub expected_burned_atoms: u128,
    pub amount_atoms: u128,
    pub valid_until_timestamp: u64,
    pub purpose_digest: Digest32,
    pub evidence_digest: Digest32,
    pub founder_signature: Vec<u8>,
}

impl QRunV06SignedBurnReserveRetirement {
    pub fn signing_digest(&self) -> Result<Digest32, QRunV06TokenomicsError> {
        if self.network_id == [0; 32]
            || self.policy_fingerprint == [0; 32]
            || self.amount_atoms == 0
            || self.valid_until_timestamp == 0
            || self.purpose_digest == [0; 32]
            || self.evidence_digest == [0; 32]
        {
            return Err(QRunV06TokenomicsError::InvalidProtocolBurn);
        }
        let mut hash = Sha256::new();
        hash.update(b"QRUN-V06-CP0566E-BURN-RESERVE-RETIREMENT-V1\0");
        hash.update(self.network_id);
        hash.update(self.policy_fingerprint);
        hash.update(self.expected_burned_atoms.to_be_bytes());
        hash.update(self.amount_atoms.to_be_bytes());
        hash.update(self.valid_until_timestamp.to_be_bytes());
        hash.update(self.purpose_digest);
        hash.update(self.evidence_digest);
        Ok(hash.finalize().into())
    }

    pub fn encode(&self) -> Result<Vec<u8>, QRunV06TokenomicsError> {
        let _ = self.signing_digest()?;
        if self.founder_signature.is_empty()
            || self.founder_signature.len() > MAX_QRUN_V06_BURN_RESERVE_SIGNATURE_BYTES
        {
            return Err(QRunV06TokenomicsError::InvalidProtocolBurn);
        }
        let signature_len = u16::try_from(self.founder_signature.len())
            .map_err(|_| QRunV06TokenomicsError::InvalidProtocolBurn)?;
        let mut out = Vec::with_capacity(192 + self.founder_signature.len());
        out.extend_from_slice(&BURN_RESERVE_RETIREMENT_MAGIC);
        out.extend_from_slice(&BURN_RESERVE_RETIREMENT_VERSION.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&self.network_id);
        out.extend_from_slice(&self.policy_fingerprint);
        out.extend_from_slice(&self.expected_burned_atoms.to_be_bytes());
        out.extend_from_slice(&self.amount_atoms.to_be_bytes());
        out.extend_from_slice(&self.valid_until_timestamp.to_be_bytes());
        out.extend_from_slice(&self.purpose_digest);
        out.extend_from_slice(&self.evidence_digest);
        out.extend_from_slice(&signature_len.to_be_bytes());
        out.extend_from_slice(&self.founder_signature);
        if out.len() > MAX_QRUN_V06_BURN_RESERVE_RETIREMENT_BYTES {
            return Err(QRunV06TokenomicsError::InvalidProtocolBurn);
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, QRunV06TokenomicsError> {
        const MIN_LEN: usize = 4 + 2 + 2 + 32 + 32 + 16 + 16 + 8 + 32 + 32 + 2 + 1;
        if bytes.len() < MIN_LEN || bytes.len() > MAX_QRUN_V06_BURN_RESERVE_RETIREMENT_BYTES {
            return Err(QRunV06TokenomicsError::InvalidProtocolBurn);
        }
        let mut cursor = 0usize;
        if take_array::<4>(bytes, &mut cursor)? != BURN_RESERVE_RETIREMENT_MAGIC
            || take_u16(bytes, &mut cursor)? != BURN_RESERVE_RETIREMENT_VERSION
            || take_u16(bytes, &mut cursor)? != 0
        {
            return Err(QRunV06TokenomicsError::InvalidProtocolBurn);
        }
        let network_id = take_array::<32>(bytes, &mut cursor)?;
        let policy_fingerprint = take_array::<32>(bytes, &mut cursor)?;
        let expected_burned_atoms = take_u128(bytes, &mut cursor)?;
        let amount_atoms = take_u128(bytes, &mut cursor)?;
        let valid_until_timestamp = take_u64(bytes, &mut cursor)?;
        let purpose_digest = take_array::<32>(bytes, &mut cursor)?;
        let evidence_digest = take_array::<32>(bytes, &mut cursor)?;
        let signature_len = take_u16(bytes, &mut cursor)? as usize;
        if signature_len == 0
            || signature_len > MAX_QRUN_V06_BURN_RESERVE_SIGNATURE_BYTES
            || cursor.checked_add(signature_len) != Some(bytes.len())
        {
            return Err(QRunV06TokenomicsError::InvalidProtocolBurn);
        }
        let value = Self {
            network_id,
            policy_fingerprint,
            expected_burned_atoms,
            amount_atoms,
            valid_until_timestamp,
            purpose_digest,
            evidence_digest,
            founder_signature: bytes[cursor..].to_vec(),
        };
        let _ = value.signing_digest()?;
        if value.encode()?.as_slice() != bytes {
            return Err(QRunV06TokenomicsError::InvalidProtocolBurn);
        }
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QRunV06TokenomicsError {
    InvalidNetwork,
    InvalidFounder,
    InvalidMiningSchedule,
    InvalidHeight,
    InvalidAmount,
    InvalidCategoryRelease,
    InvalidProtocolBurn,
    BurnCounterMismatch { expected: u128, actual: u128 },
    InvalidReleaseNonce { expected: u64, actual: u64 },
    ReleaseNonceOverflow,
    ArithmeticOverflow,
    BucketBudgetExceeded(QRunV06AllocationBucket),
    GlobalSupplyCapExceeded,
    FounderGenesisMismatch,
    BurnExceedsIssuedReserve,
    BurnExceedsGrossIssued,
    LedgerSupplyMismatch { expected: u128, actual: u128 },
    WrongNetwork,
    SnapshotMalformed,
    SnapshotChecksumMismatch,
    SnapshotNonCanonical,
}

impl std::fmt::Display for QRunV06TokenomicsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "QFP6 tokenomics error: {self:?}")
    }
}
impl std::error::Error for QRunV06TokenomicsError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06TokenomicsState {
    network_id: Digest32,
    founder_account: AccountId,
    schedule: QRunV06MiningScheduleCandidate,
    issued_by_bucket_atoms: [u128; QRUN_V06_TOKENOMICS_BUCKETS],
    burned_atoms: u128,
    founder_release_nonce: u64,
    last_release_id: Digest32,
}

impl QRunV06TokenomicsState {
    /// Construct a CP-0528 Genesis accounting state. Only the 1B Founder ceiling
    /// is initially issued. All other envelopes, including mining, begin unissued.
    pub fn genesis(
        network_id: Digest32,
        founder_account: AccountId,
        schedule: QRunV06MiningScheduleCandidate,
    ) -> Result<Self, QRunV06TokenomicsError> {
        if network_id == [0; 32] {
            return Err(QRunV06TokenomicsError::InvalidNetwork);
        }
        if founder_account == [0; 32] {
            return Err(QRunV06TokenomicsError::InvalidFounder);
        }
        schedule.validate()?;
        let mut issued_by_bucket_atoms = [0u128; QRUN_V06_TOKENOMICS_BUCKETS];
        issued_by_bucket_atoms[QRunV06AllocationBucket::FounderAllocation.index()] =
            QRUN_V06_FOUNDER_GENESIS_ATOMS;
        let state = Self {
            network_id,
            founder_account,
            schedule,
            issued_by_bucket_atoms,
            burned_atoms: 0,
            founder_release_nonce: 0,
            last_release_id: [0; 32],
        };
        state.validate()?;
        Ok(state)
    }

    pub fn network_id(&self) -> Digest32 {
        self.network_id
    }

    pub fn founder_account(&self) -> AccountId {
        self.founder_account
    }

    pub fn mining_schedule(&self) -> QRunV06MiningScheduleCandidate {
        self.schedule
    }

    pub fn issued_by_bucket_atoms(&self, bucket: QRunV06AllocationBucket) -> u128 {
        self.issued_by_bucket_atoms[bucket.index()]
    }

    pub fn burned_atoms(&self) -> u128 {
        self.burned_atoms
    }

    pub fn founder_release_nonce(&self) -> u64 {
        self.founder_release_nonce
    }

    pub fn last_release_id(&self) -> Digest32 {
        self.last_release_id
    }

    pub fn gross_issued_atoms(&self) -> Result<u128, QRunV06TokenomicsError> {
        self.issued_by_bucket_atoms
            .iter()
            .try_fold(0u128, |sum, issued| {
                sum.checked_add(*issued)
                    .ok_or(QRunV06TokenomicsError::ArithmeticOverflow)
            })
    }

    pub fn live_supply_atoms(&self) -> Result<u128, QRunV06TokenomicsError> {
        self.validate()?;
        self.gross_issued_atoms()?
            .checked_sub(self.burned_atoms)
            .ok_or(QRunV06TokenomicsError::BurnExceedsGrossIssued)
    }

    pub fn unissued_by_bucket_atoms(
        &self,
        bucket: QRunV06AllocationBucket,
    ) -> Result<u128, QRunV06TokenomicsError> {
        bucket
            .budget_atoms()
            .checked_sub(self.issued_by_bucket_atoms(bucket))
            .ok_or(QRunV06TokenomicsError::BucketBudgetExceeded(bucket))
    }

    /// Deterministic reward after budget/global-cap clamping. The caller must
    /// credit exactly this amount to the block producer in the canonical Ledger.
    pub fn expected_mining_reward_atoms(
        &self,
        height: u64,
    ) -> Result<u128, QRunV06TokenomicsError> {
        let scheduled = self.schedule.reward_for_height(height)?;
        let mining_remaining =
            self.unissued_by_bucket_atoms(QRunV06AllocationBucket::MiningNetworkSecurity)?;
        let global_remaining = QRUN_V06_MAX_GROSS_ISSUANCE_ATOMS
            .checked_sub(self.gross_issued_atoms()?)
            .ok_or(QRunV06TokenomicsError::GlobalSupplyCapExceeded)?;
        Ok(scheduled.min(mining_remaining).min(global_remaining))
    }

    /// Record only the exact deterministic reward for the given next block height.
    /// This counter must be committed atomically with the corresponding Ledger credit.
    pub(crate) fn record_mining_reward(
        &mut self,
        height: u64,
        amount_atoms: u128,
    ) -> Result<(), QRunV06TokenomicsError> {
        if amount_atoms == 0 || amount_atoms != self.expected_mining_reward_atoms(height)? {
            return Err(QRunV06TokenomicsError::InvalidAmount);
        }
        self.record_issuance(QRunV06AllocationBucket::MiningNetworkSecurity, amount_atoms)
    }

    /// Internal primitive for future deterministic category-release transitions.
    /// It is not a public mint authority; callers must prove category-specific approval.
    pub(crate) fn record_issuance(
        &mut self,
        bucket: QRunV06AllocationBucket,
        amount_atoms: u128,
    ) -> Result<(), QRunV06TokenomicsError> {
        if amount_atoms == 0 {
            return Err(QRunV06TokenomicsError::InvalidAmount);
        }
        let mut next = self.clone();
        let index = bucket.index();
        next.issued_by_bucket_atoms[index] = next.issued_by_bucket_atoms[index]
            .checked_add(amount_atoms)
            .ok_or(QRunV06TokenomicsError::ArithmeticOverflow)?;
        next.validate()?;
        *self = next;
        Ok(())
    }

    /// Apply the monotonic Founder release counter and bucket issuance only after
    /// the QFB6 executor has verified the Founder and recipient signatures.
    pub(crate) fn record_category_release(
        &mut self,
        bucket: QRunV06AllocationBucket,
        amount_atoms: u128,
        nonce: u64,
        release_id: Digest32,
    ) -> Result<(), QRunV06TokenomicsError> {
        if !bucket.is_founder_releasable() || amount_atoms == 0 || release_id == [0; 32] {
            return Err(QRunV06TokenomicsError::InvalidCategoryRelease);
        }
        let expected = self
            .founder_release_nonce
            .checked_add(1)
            .ok_or(QRunV06TokenomicsError::ReleaseNonceOverflow)?;
        if nonce != expected {
            return Err(QRunV06TokenomicsError::InvalidReleaseNonce {
                expected,
                actual: nonce,
            });
        }
        let mut next = self.clone();
        next.record_issuance(bucket, amount_atoms)?;
        next.founder_release_nonce = nonce;
        next.last_release_id = release_id;
        next.validate()?;
        *self = next;
        Ok(())
    }

    /// Retire unissued burn-reserve capacity under a founder-signed QFB6 operation.
    /// The enclosing executor debits the same amount from the deterministic sink in Ledger.
    pub(crate) fn record_protocol_burn_reserve_retirement(
        &mut self,
        amount_atoms: u128,
        expected_burned_atoms: u128,
    ) -> Result<(), QRunV06TokenomicsError> {
        if amount_atoms == 0 {
            return Err(QRunV06TokenomicsError::InvalidAmount);
        }
        if self.burned_atoms != expected_burned_atoms {
            return Err(QRunV06TokenomicsError::BurnCounterMismatch {
                expected: self.burned_atoms,
                actual: expected_burned_atoms,
            });
        }
        let mut next = self.clone();
        next.record_issuance(QRunV06AllocationBucket::ProtocolBurnReserve, amount_atoms)?;
        next.record_burn_from_reserve(amount_atoms)?;
        *self = next;
        Ok(())
    }

    /// Internal cumulative burn counter; call only after the matching Ledger debit.
    pub(crate) fn record_burn_from_reserve(
        &mut self,
        amount_atoms: u128,
    ) -> Result<(), QRunV06TokenomicsError> {
        if amount_atoms == 0 {
            return Err(QRunV06TokenomicsError::InvalidAmount);
        }
        let mut next = self.clone();
        next.burned_atoms = next
            .burned_atoms
            .checked_add(amount_atoms)
            .ok_or(QRunV06TokenomicsError::ArithmeticOverflow)?;
        next.validate()?;
        *self = next;
        Ok(())
    }

    pub fn validate_against_ledger(
        &self,
        ledger_total_value: u128,
    ) -> Result<(), QRunV06TokenomicsError> {
        let expected = self.live_supply_atoms()?;
        if ledger_total_value != expected {
            return Err(QRunV06TokenomicsError::LedgerSupplyMismatch {
                expected,
                actual: ledger_total_value,
            });
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), QRunV06TokenomicsError> {
        if self.network_id == [0; 32] {
            return Err(QRunV06TokenomicsError::InvalidNetwork);
        }
        if self.founder_account == [0; 32] {
            return Err(QRunV06TokenomicsError::InvalidFounder);
        }
        self.schedule.validate()?;
        if self.issued_by_bucket_atoms[QRunV06AllocationBucket::FounderAllocation.index()]
            != QRUN_V06_FOUNDER_GENESIS_ATOMS
        {
            return Err(QRunV06TokenomicsError::FounderGenesisMismatch);
        }
        for bucket in QRunV06AllocationBucket::ALL {
            if self.issued_by_bucket_atoms[bucket.index()] > bucket.budget_atoms() {
                return Err(QRunV06TokenomicsError::BucketBudgetExceeded(bucket));
            }
        }
        let gross = self.gross_issued_atoms()?;
        if gross > QRUN_V06_MAX_GROSS_ISSUANCE_ATOMS {
            return Err(QRunV06TokenomicsError::GlobalSupplyCapExceeded);
        }
        if self.burned_atoms > gross {
            return Err(QRunV06TokenomicsError::BurnExceedsGrossIssued);
        }
        if (self.founder_release_nonce == 0) != (self.last_release_id == [0; 32]) {
            return Err(QRunV06TokenomicsError::InvalidCategoryRelease);
        }
        if self.burned_atoms
            > self.issued_by_bucket_atoms[QRunV06AllocationBucket::ProtocolBurnReserve.index()]
        {
            return Err(QRunV06TokenomicsError::BurnExceedsIssuedReserve);
        }
        Ok(())
    }

    /// Domain-separated commitment binds the policy schedule and all cumulative counters.
    pub fn state_root(&self) -> Result<Digest32, QRunV06TokenomicsError> {
        self.validate()?;
        let policy = self.policy_fingerprint();
        let mut hash = Sha256::new();
        hash.update(b"QRUN-V06-TOKENOMICS-STATE-ROOT-V2\0");
        hash.update(self.network_id);
        hash.update(self.founder_account);
        hash.update(policy);
        for issued in self.issued_by_bucket_atoms {
            hash.update(issued.to_be_bytes());
        }
        hash.update(self.burned_atoms.to_be_bytes());
        hash.update(self.founder_release_nonce.to_be_bytes());
        hash.update(self.last_release_id);
        Ok(hash.finalize().into())
    }

    pub fn policy_fingerprint(&self) -> Digest32 {
        let mut hash = Sha256::new();
        hash.update(POLICY_FINGERPRINT_DOMAIN);
        hash.update(QRUN_V06_MAX_GROSS_ISSUANCE_ATOMS.to_be_bytes());
        hash.update(QRUN_V06_FOUNDER_GENESIS_ATOMS.to_be_bytes());
        for bucket in QRunV06AllocationBucket::ALL {
            hash.update([bucket as u8]);
            hash.update(bucket.budget_atoms().to_be_bytes());
        }
        hash.update(self.schedule.initial_subsidy_atoms.to_be_bytes());
        hash.update(self.schedule.blocks_per_halving.to_be_bytes());
        hash.finalize().into()
    }

    pub fn encode_snapshot(
        &self,
    ) -> Result<[u8; QRUN_V06_TOKENOMICS_SNAPSHOT_BYTES], QRunV06TokenomicsError> {
        self.validate()?;
        let mut out = Vec::with_capacity(QRUN_V06_TOKENOMICS_SNAPSHOT_BYTES);
        out.extend_from_slice(SNAPSHOT_MAGIC);
        out.extend_from_slice(&SNAPSHOT_VERSION.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&self.network_id);
        out.extend_from_slice(&self.founder_account);
        out.extend_from_slice(&QRUN_V06_MAX_GROSS_ISSUANCE_ATOMS.to_be_bytes());
        out.extend_from_slice(&QRUN_V06_FOUNDER_GENESIS_ATOMS.to_be_bytes());
        out.extend_from_slice(&QRUN_V06_MINING_SECURITY_BUDGET_ATOMS.to_be_bytes());
        out.extend_from_slice(&self.schedule.initial_subsidy_atoms.to_be_bytes());
        out.extend_from_slice(&self.schedule.blocks_per_halving.to_be_bytes());
        for issued in self.issued_by_bucket_atoms {
            out.extend_from_slice(&issued.to_be_bytes());
        }
        out.extend_from_slice(&self.burned_atoms.to_be_bytes());
        out.extend_from_slice(&self.founder_release_nonce.to_be_bytes());
        out.extend_from_slice(&self.last_release_id);
        let payload_len = QRUN_V06_TOKENOMICS_SNAPSHOT_BYTES - 32;
        if out.len() != payload_len {
            return Err(QRunV06TokenomicsError::SnapshotMalformed);
        }
        let mut checksum = Sha256::new();
        checksum.update(SNAPSHOT_CHECKSUM_DOMAIN);
        checksum.update(&out);
        out.extend_from_slice(&checksum.finalize());
        out.try_into()
            .map_err(|_| QRunV06TokenomicsError::SnapshotMalformed)
    }

    pub fn decode_snapshot(
        bytes: &[u8],
        expected_network_id: &Digest32,
    ) -> Result<Self, QRunV06TokenomicsError> {
        if bytes.len() != QRUN_V06_TOKENOMICS_SNAPSHOT_BYTES
            || &bytes[..4] != SNAPSHOT_MAGIC
            || u16::from_be_bytes([bytes[4], bytes[5]]) != SNAPSHOT_VERSION
            || bytes[6..8] != [0, 0]
        {
            return Err(QRunV06TokenomicsError::SnapshotMalformed);
        }
        if bytes[8..40] != expected_network_id[..] {
            return Err(QRunV06TokenomicsError::WrongNetwork);
        }
        let payload_len = bytes.len() - 32;
        let mut checksum = Sha256::new();
        checksum.update(SNAPSHOT_CHECKSUM_DOMAIN);
        checksum.update(&bytes[..payload_len]);
        if checksum.finalize().as_slice() != &bytes[payload_len..] {
            return Err(QRunV06TokenomicsError::SnapshotChecksumMismatch);
        }
        let mut cursor = 40usize;
        let founder_account = take_array::<32>(bytes, &mut cursor)?;
        if take_u128(bytes, &mut cursor)? != QRUN_V06_MAX_GROSS_ISSUANCE_ATOMS
            || take_u128(bytes, &mut cursor)? != QRUN_V06_FOUNDER_GENESIS_ATOMS
            || take_u128(bytes, &mut cursor)? != QRUN_V06_MINING_SECURITY_BUDGET_ATOMS
        {
            return Err(QRunV06TokenomicsError::SnapshotNonCanonical);
        }
        let initial_subsidy_atoms = take_u128(bytes, &mut cursor)?;
        let blocks_per_halving = take_u64(bytes, &mut cursor)?;
        let schedule =
            QRunV06MiningScheduleCandidate::new(initial_subsidy_atoms, blocks_per_halving)?;
        let mut issued_by_bucket_atoms = [0u128; QRUN_V06_TOKENOMICS_BUCKETS];
        for issued in &mut issued_by_bucket_atoms {
            *issued = take_u128(bytes, &mut cursor)?;
        }
        let burned_atoms = take_u128(bytes, &mut cursor)?;
        let founder_release_nonce = take_u64(bytes, &mut cursor)?;
        let last_release_id = take_array::<32>(bytes, &mut cursor)?;
        if cursor != payload_len {
            return Err(QRunV06TokenomicsError::SnapshotNonCanonical);
        }
        let state = Self {
            network_id: *expected_network_id,
            founder_account,
            schedule,
            issued_by_bucket_atoms,
            burned_atoms,
            founder_release_nonce,
            last_release_id,
        };
        state.validate()?;
        if state.encode_snapshot()?.as_slice() != bytes {
            return Err(QRunV06TokenomicsError::SnapshotNonCanonical);
        }
        Ok(state)
    }
}

fn take_array<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], QRunV06TokenomicsError> {
    let end = cursor
        .checked_add(N)
        .ok_or(QRunV06TokenomicsError::SnapshotMalformed)?;
    let result = bytes
        .get(*cursor..end)
        .ok_or(QRunV06TokenomicsError::SnapshotMalformed)?
        .try_into()
        .map_err(|_| QRunV06TokenomicsError::SnapshotMalformed)?;
    *cursor = end;
    Ok(result)
}

fn take_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16, QRunV06TokenomicsError> {
    Ok(u16::from_be_bytes(take_array::<2>(bytes, cursor)?))
}

fn take_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64, QRunV06TokenomicsError> {
    Ok(u64::from_be_bytes(take_array::<8>(bytes, cursor)?))
}

fn take_u128(bytes: &[u8], cursor: &mut usize) -> Result<u128, QRunV06TokenomicsError> {
    Ok(u128::from_be_bytes(take_array::<16>(bytes, cursor)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NETWORK: Digest32 = [0xA1; 32];
    const FOUNDER: AccountId = [0xA2; 32];

    fn state() -> QRunV06TokenomicsState {
        QRunV06TokenomicsState::genesis(
            NETWORK,
            FOUNDER,
            QRunV06MiningScheduleCandidate::cp0422_research_candidate(),
        )
        .unwrap()
    }

    #[test]
    fn cp0528_genesis_issues_only_one_billion_to_founder() {
        let state = state();
        assert_eq!(
            state.issued_by_bucket_atoms(QRunV06AllocationBucket::FounderAllocation),
            QRUN_V06_FOUNDER_GENESIS_ATOMS
        );
        assert_eq!(
            state.gross_issued_atoms().unwrap(),
            QRUN_V06_FOUNDER_GENESIS_ATOMS
        );
        assert_eq!(
            state.live_supply_atoms().unwrap(),
            QRUN_V06_FOUNDER_GENESIS_ATOMS
        );
        for bucket in QRunV06AllocationBucket::ALL {
            if bucket != QRunV06AllocationBucket::FounderAllocation {
                assert_eq!(state.issued_by_bucket_atoms(bucket), 0);
            }
        }
        assert_eq!(
            state
                .unissued_by_bucket_atoms(QRunV06AllocationBucket::MiningNetworkSecurity)
                .unwrap(),
            QRUN_V06_MINING_SECURITY_BUDGET_ATOMS
        );
    }

    #[test]
    fn candidate_mining_schedule_is_height_deterministic_and_stays_within_three_billion() {
        let mut state = state();
        let schedule = state.mining_schedule();
        assert_eq!(schedule.reward_for_height(1).unwrap(), 35_673_515_981);
        assert_eq!(
            schedule
                .reward_for_height(schedule.blocks_per_halving)
                .unwrap(),
            35_673_515_981
        );
        assert_eq!(
            schedule
                .reward_for_height(schedule.blocks_per_halving + 1)
                .unwrap(),
            17_836_757_990
        );

        let mut total = 0u128;
        let mut era = 0u64;
        loop {
            let first_height = era * schedule.blocks_per_halving + 1;
            let reward = schedule.reward_for_height(first_height).unwrap();
            if reward == 0 {
                break;
            }
            total += reward * schedule.blocks_per_halving as u128;
            era += 1;
        }
        assert_eq!(total, 299_999_999_913_926_400);
        assert_eq!(QRUN_V06_MINING_SECURITY_BUDGET_ATOMS - total, 86_073_600);
        state
            .record_mining_reward(1, state.expected_mining_reward_atoms(1).unwrap())
            .unwrap();
        state
            .record_mining_reward(2, state.expected_mining_reward_atoms(2).unwrap())
            .unwrap();
        assert_eq!(
            state.issued_by_bucket_atoms(QRunV06AllocationBucket::MiningNetworkSecurity),
            2 * 35_673_515_981
        );
        assert_eq!(
            state.gross_issued_atoms().unwrap(),
            QRUN_V06_FOUNDER_GENESIS_ATOMS + 2 * 35_673_515_981
        );
        let mut capped = state.clone();
        let issued = capped.issued_by_bucket_atoms(QRunV06AllocationBucket::MiningNetworkSecurity);
        capped
            .record_issuance(
                QRunV06AllocationBucket::MiningNetworkSecurity,
                QRUN_V06_MINING_SECURITY_BUDGET_ATOMS - issued,
            )
            .unwrap();
        assert_eq!(capped.expected_mining_reward_atoms(3).unwrap(), 0);
    }

    #[test]
    fn mining_counter_rejects_wrong_reward_and_bucket_cap_overrun_atomically() {
        let mut state = state();
        let before = state.clone();
        assert_eq!(
            state.record_mining_reward(1, 1),
            Err(QRunV06TokenomicsError::InvalidAmount)
        );
        assert_eq!(state, before);
    }

    #[test]
    fn bucket_ceilings_and_global_cap_are_exact() {
        let total = QRunV06AllocationBucket::ALL
            .iter()
            .map(|bucket| bucket.budget_atoms())
            .sum::<u128>();
        assert_eq!(total, QRUN_V06_MAX_GROSS_ISSUANCE_ATOMS);
        assert_eq!(
            QRunV06AllocationBucket::FounderAllocation.budget_atoms(),
            QRUN_V06_FOUNDER_GENESIS_ATOMS
        );
        assert_eq!(
            QRunV06AllocationBucket::MiningNetworkSecurity.budget_atoms(),
            QRUN_V06_MINING_SECURITY_BUDGET_ATOMS
        );
        assert_eq!(
            QRunV06AllocationBucket::ALL
                .iter()
                .filter(
                    |bucket| **bucket != QRunV06AllocationBucket::MiningNetworkSecurity
                        && **bucket != QRunV06AllocationBucket::FounderAllocation
                )
                .count(),
            6
        );
    }

    #[test]
    fn tokenomics_snapshot_roundtrips_and_binds_network_and_policy() {
        let mut state = state();
        state
            .record_category_release(
                QRunV06AllocationBucket::CommunityAirdrop,
                123,
                1,
                [0xB3; 32],
            )
            .unwrap();
        let encoded = state.encode_snapshot().unwrap();
        assert_eq!(encoded.len(), QRUN_V06_TOKENOMICS_SNAPSHOT_BYTES);
        let decoded = QRunV06TokenomicsState::decode_snapshot(&encoded, &NETWORK).unwrap();
        assert_eq!(decoded, state);
        assert_eq!(decoded.state_root().unwrap(), state.state_root().unwrap());
        assert_ne!(state.policy_fingerprint(), [0; 32]);
        assert!(matches!(
            QRunV06TokenomicsState::decode_snapshot(&encoded, &[0xB1; 32]),
            Err(QRunV06TokenomicsError::WrongNetwork)
        ));
        let mut corrupt = encoded;
        corrupt[200] ^= 0x80;
        assert!(matches!(
            QRunV06TokenomicsState::decode_snapshot(&corrupt, &NETWORK),
            Err(QRunV06TokenomicsError::SnapshotChecksumMismatch)
        ));
    }

    #[test]
    fn burn_accounting_cannot_consume_unissued_or_other_category_supply() {
        let mut state = state();
        let before = state.clone();
        assert_eq!(
            state.record_burn_from_reserve(1),
            Err(QRunV06TokenomicsError::BurnExceedsIssuedReserve)
        );
        assert_eq!(state, before);
    }

    #[test]
    fn protocol_burn_reserve_retirement_is_monotonic_bounded_and_keeps_live_supply_constant() {
        let mut state = state();
        let amount = 123_456u128;
        let expected_burned = state.burned_atoms();
        state
            .record_protocol_burn_reserve_retirement(amount, expected_burned)
            .unwrap();

        assert_eq!(
            state.issued_by_bucket_atoms(QRunV06AllocationBucket::ProtocolBurnReserve),
            amount
        );
        assert_eq!(state.burned_atoms(), amount);
        assert_eq!(
            state.gross_issued_atoms().unwrap(),
            QRUN_V06_FOUNDER_GENESIS_ATOMS + amount
        );
        assert_eq!(
            state.live_supply_atoms().unwrap(),
            QRUN_V06_FOUNDER_GENESIS_ATOMS
        );
        assert_eq!(
            state
                .unissued_by_bucket_atoms(QRunV06AllocationBucket::ProtocolBurnReserve)
                .unwrap(),
            QRunV06AllocationBucket::ProtocolBurnReserve.budget_atoms() - amount
        );

        let before_replay = state.clone();
        assert_eq!(
            state.record_protocol_burn_reserve_retirement(amount, expected_burned),
            Err(QRunV06TokenomicsError::BurnCounterMismatch {
                expected: amount,
                actual: expected_burned,
            })
        );
        assert_eq!(state, before_replay);

        let snapshot = state.encode_snapshot().unwrap();
        let restored = QRunV06TokenomicsState::decode_snapshot(&snapshot, &NETWORK).unwrap();
        assert_eq!(restored, state);
        assert_eq!(restored.state_root().unwrap(), state.state_root().unwrap());
    }

    #[test]
    fn founder_category_release_enforces_allowed_bucket_cap_nonce_and_audit_id() {
        let mut state = state();
        let release_id = [0xB5; 32];
        state
            .record_category_release(
                QRunV06AllocationBucket::CommunityAirdrop,
                100,
                1,
                release_id,
            )
            .unwrap();
        assert_eq!(state.founder_release_nonce(), 1);
        assert_eq!(state.last_release_id(), release_id);
        assert_eq!(
            state.issued_by_bucket_atoms(QRunV06AllocationBucket::CommunityAirdrop),
            100
        );

        let before = state.clone();
        assert_eq!(
            state.record_category_release(
                QRunV06AllocationBucket::CommunityAirdrop,
                1,
                1,
                [0xB6; 32],
            ),
            Err(QRunV06TokenomicsError::InvalidReleaseNonce {
                expected: 2,
                actual: 1,
            })
        );
        assert_eq!(state, before);
        assert_eq!(
            state.record_category_release(
                QRunV06AllocationBucket::ProtocolBurnReserve,
                1,
                2,
                [0xB7; 32],
            ),
            Err(QRunV06TokenomicsError::InvalidCategoryRelease)
        );
        assert_eq!(state, before);
        assert_eq!(
            state.record_category_release(
                QRunV06AllocationBucket::MiningNetworkSecurity,
                1,
                2,
                [0xB8; 32],
            ),
            Err(QRunV06TokenomicsError::InvalidCategoryRelease)
        );
        assert_eq!(state, before);

        let remaining = state
            .unissued_by_bucket_atoms(QRunV06AllocationBucket::CommunityAirdrop)
            .unwrap();
        assert!(matches!(
            state.record_category_release(
                QRunV06AllocationBucket::CommunityAirdrop,
                remaining + 1,
                2,
                [0xB9; 32],
            ),
            Err(QRunV06TokenomicsError::BucketBudgetExceeded(
                QRunV06AllocationBucket::CommunityAirdrop
            ))
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn signed_category_release_payload_is_canonical_and_rejects_missing_commitments() {
        let mut release = QRunV06SignedCategoryRelease {
            network_id: NETWORK,
            bucket: QRunV06AllocationBucket::CommunityAirdrop,
            nonce: 1,
            recipient: [0xA3; 32],
            amount_atoms: 123,
            valid_until_timestamp: 500,
            purpose_digest: [0x11; 32],
            evidence_digest: [0x12; 32],
            milestone_policy_digest: [0x13; 32],
            founder_signature: vec![0x21; 64],
            recipient_acceptance_signature: vec![0x22; 64],
        };
        let encoded = release.encode().unwrap();
        assert_eq!(
            QRunV06SignedCategoryRelease::decode(&encoded).unwrap(),
            release
        );
        let mut malformed = release.clone();
        malformed.evidence_digest = [0; 32];
        assert_eq!(
            malformed.signing_digest(),
            Err(QRunV06TokenomicsError::InvalidCategoryRelease)
        );
        malformed = release.clone();
        malformed.bucket = QRunV06AllocationBucket::ProtocolBurnReserve;
        assert_eq!(
            malformed.encode(),
            Err(QRunV06TokenomicsError::InvalidCategoryRelease)
        );
        release.founder_signature.clear();
        assert_eq!(
            release.encode(),
            Err(QRunV06TokenomicsError::InvalidCategoryRelease)
        );
    }

    #[test]
    fn ledger_total_must_equal_gross_issued_minus_burns() {
        let state = state();
        state
            .validate_against_ledger(QRUN_V06_FOUNDER_GENESIS_ATOMS)
            .unwrap();
        assert!(matches!(
            state.validate_against_ledger(QRUN_V06_FOUNDER_GENESIS_ATOMS - 1),
            Err(QRunV06TokenomicsError::LedgerSupplyMismatch { .. })
        ));
    }
}
