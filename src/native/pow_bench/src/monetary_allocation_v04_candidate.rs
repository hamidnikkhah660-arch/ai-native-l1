//! CP-0391: tokenomics v0.4 allocation-ledger candidate.
//!
//! This module encodes the owner-directed eight-bucket *budget caps* and a deterministic
//! supply-accounting record. It is not wired into the legacy MBK3/MBK4 state transition,
//! the node runtime, Genesis, the durable fork store, or external anti-rollback. It is
//! deliberately a candidate boundary: passing these tests is not a Gate 2 closure claim.
//!
//! Important accounting distinctions:
//! - a bucket cap is not proof that coins have been issued or distributed;
//! - gross issued supply never decreases when coins are burnt;
//! - live supply = gross issued - verifiably burnt;
//! - this API only permits burn accounting against tokens already issued under the dedicated
//!   burn-reserve bucket. The runtime must additionally prove the source balance and authorization
//!   before invoking it.

use sha2::{Digest, Sha256};

pub const ATOMS_PER_COIN: u128 = 100_000_000;
pub const MAX_TOTAL_SUPPLY_ATOMS: u128 = 10_000_000_000 * ATOMS_PER_COIN;
pub const POLICY_VERSION: u16 = 4;
pub const POLICY_ID: &[u8] = b"QUANTUMZXB-TOKENOMICS-V04-2026-10-24\0";
pub const ACCOUNTING_MAGIC: [u8; 4] = *b"QZAL";
pub const ACCOUNTING_VERSION: u16 = 1;
pub const ACCOUNTING_BYTES: usize = 4 + 2 + 8 * 16 + 16;
const POLICY_FINGERPRINT_DOMAIN: &[u8] = b"QUANTUMZXB-ALLOCATION-POLICY-FINGERPRINT-V04\0";
const ACCOUNTING_COMMITMENT_DOMAIN: &[u8] = b"QUANTUMZXB-ALLOCATION-ACCOUNTING-STATE-V01\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AllocationBucket {
    MiningNetworkSecurity = 0,
    CommunityAirdrop = 1,
    ExchangeMarketLiquidity = 2,
    MarketingPartners = 3,
    DeveloperSecurityContributors = 4,
    FinancialStrategicSupporters = 5,
    ProtocolBurnReserve = 6,
    OwnerAllocation = 7,
}

impl AllocationBucket {
    pub const ALL: [Self; 8] = [
        Self::MiningNetworkSecurity,
        Self::CommunityAirdrop,
        Self::ExchangeMarketLiquidity,
        Self::MarketingPartners,
        Self::DeveloperSecurityContributors,
        Self::FinancialStrategicSupporters,
        Self::ProtocolBurnReserve,
        Self::OwnerAllocation,
    ];

    pub const fn index(self) -> usize {
        self as usize
    }

    pub const fn budget(self) -> AllocationBudget {
        ALLOCATION_BUDGETS[self.index()]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllocationBudget {
    pub bucket: AllocationBucket,
    pub coins: u128,
    pub share_basis_points: u16,
}

impl AllocationBudget {
    pub const fn atoms(self) -> u128 {
        self.coins * ATOMS_PER_COIN
    }
}

/// Fixed ordering is part of the policy fingerprint and accounting serialization.
/// Buckets are planned ceilings; they are not Genesis balances and do not imply current issuance.
pub const ALLOCATION_BUDGETS: [AllocationBudget; 8] = [
    AllocationBudget {
        bucket: AllocationBucket::MiningNetworkSecurity,
        coins: 3_000_000_000,
        share_basis_points: 3_000,
    },
    AllocationBudget {
        bucket: AllocationBucket::CommunityAirdrop,
        coins: 1_000_000_000,
        share_basis_points: 1_000,
    },
    AllocationBudget {
        bucket: AllocationBucket::ExchangeMarketLiquidity,
        coins: 1_000_000_000,
        share_basis_points: 1_000,
    },
    AllocationBudget {
        bucket: AllocationBucket::MarketingPartners,
        coins: 1_000_000_000,
        share_basis_points: 1_000,
    },
    AllocationBudget {
        bucket: AllocationBucket::DeveloperSecurityContributors,
        coins: 1_000_000_000,
        share_basis_points: 1_000,
    },
    AllocationBudget {
        bucket: AllocationBucket::FinancialStrategicSupporters,
        coins: 1_000_000_000,
        share_basis_points: 1_000,
    },
    AllocationBudget {
        bucket: AllocationBucket::ProtocolBurnReserve,
        coins: 1_000_000_000,
        share_basis_points: 1_000,
    },
    AllocationBudget {
        bucket: AllocationBucket::OwnerAllocation,
        coins: 1_000_000_000,
        share_basis_points: 1_000,
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocationAccountingError {
    ZeroAmount,
    ArithmeticOverflow,
    BucketBudgetExceeded(AllocationBucket),
    TotalSupplyCapExceeded,
    BurnExceedsGrossIssued,
    BurnExceedsIssuedBurnReserve,
    WrongLength,
    WrongMagic,
    UnsupportedVersion,
    InvalidState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllocationAccounting {
    /// Gross, cumulative issuance by policy bucket. Transfers do not change these counters.
    issued_by_bucket_atoms: [u128; 8],
    /// Cumulative proven burns. Burns do not reduce gross issuance counters.
    burned_atoms: u128,
}

impl Default for AllocationAccounting {
    fn default() -> Self {
        Self::new()
    }
}

impl AllocationAccounting {
    pub const fn new() -> Self {
        Self {
            issued_by_bucket_atoms: [0; 8],
            burned_atoms: 0,
        }
    }

    pub fn issued_by_bucket_atoms(&self, bucket: AllocationBucket) -> u128 {
        self.issued_by_bucket_atoms[bucket.index()]
    }

    pub fn burned_atoms(&self) -> u128 {
        self.burned_atoms
    }

    pub fn gross_issued_atoms(&self) -> Result<u128, AllocationAccountingError> {
        self.issued_by_bucket_atoms
            .iter()
            .try_fold(0u128, |sum, value| {
                sum.checked_add(*value)
                    .ok_or(AllocationAccountingError::ArithmeticOverflow)
            })
    }

    pub fn live_supply_atoms(&self) -> Result<u128, AllocationAccountingError> {
        self.validate()?;
        self.gross_issued_atoms()?
            .checked_sub(self.burned_atoms)
            .ok_or(AllocationAccountingError::BurnExceedsGrossIssued)
    }

    /// Record issuance only after the calling consensus transition has authorized the credit.
    /// The mutation is atomic: an error leaves the original accounting state unchanged.
    pub fn record_issuance(
        &mut self,
        bucket: AllocationBucket,
        amount_atoms: u128,
    ) -> Result<(), AllocationAccountingError> {
        if amount_atoms == 0 {
            return Err(AllocationAccountingError::ZeroAmount);
        }

        let mut candidate = self.clone();
        let index = bucket.index();
        let next = candidate.issued_by_bucket_atoms[index]
            .checked_add(amount_atoms)
            .ok_or(AllocationAccountingError::ArithmeticOverflow)?;
        if next > bucket.budget().atoms() {
            return Err(AllocationAccountingError::BucketBudgetExceeded(bucket));
        }
        candidate.issued_by_bucket_atoms[index] = next;
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    /// Record a burn from the designated burn-reserve source only. The caller must separately
    /// verify the actual reserve-account balance and authorization before committing this counter.
    pub fn record_burn_from_reserve(
        &mut self,
        amount_atoms: u128,
    ) -> Result<(), AllocationAccountingError> {
        if amount_atoms == 0 {
            return Err(AllocationAccountingError::ZeroAmount);
        }
        let mut candidate = self.clone();
        candidate.burned_atoms = candidate
            .burned_atoms
            .checked_add(amount_atoms)
            .ok_or(AllocationAccountingError::ArithmeticOverflow)?;
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    pub fn validate(&self) -> Result<(), AllocationAccountingError> {
        for bucket in AllocationBucket::ALL {
            if self.issued_by_bucket_atoms[bucket.index()] > bucket.budget().atoms() {
                return Err(AllocationAccountingError::BucketBudgetExceeded(bucket));
            }
        }
        let gross = self.gross_issued_atoms()?;
        if gross > MAX_TOTAL_SUPPLY_ATOMS {
            return Err(AllocationAccountingError::TotalSupplyCapExceeded);
        }
        if self.burned_atoms > gross {
            return Err(AllocationAccountingError::BurnExceedsGrossIssued);
        }
        if self.burned_atoms
            > self.issued_by_bucket_atoms[AllocationBucket::ProtocolBurnReserve.index()]
        {
            return Err(AllocationAccountingError::BurnExceedsIssuedBurnReserve);
        }
        Ok(())
    }

    /// Encode the accounting counters using fixed-width big-endian integers and a versioned
    /// magic. The state-root/manifest integration must bind this encoding and the policy digest.
    pub fn encode(&self) -> Result<[u8; ACCOUNTING_BYTES], AllocationAccountingError> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(ACCOUNTING_BYTES);
        bytes.extend_from_slice(&ACCOUNTING_MAGIC);
        bytes.extend_from_slice(&ACCOUNTING_VERSION.to_be_bytes());
        for issued in self.issued_by_bucket_atoms {
            bytes.extend_from_slice(&issued.to_be_bytes());
        }
        bytes.extend_from_slice(&self.burned_atoms.to_be_bytes());
        bytes
            .try_into()
            .map_err(|_| AllocationAccountingError::WrongLength)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, AllocationAccountingError> {
        if bytes.len() != ACCOUNTING_BYTES {
            return Err(AllocationAccountingError::WrongLength);
        }
        if bytes[..4] != ACCOUNTING_MAGIC {
            return Err(AllocationAccountingError::WrongMagic);
        }
        if u16::from_be_bytes([bytes[4], bytes[5]]) != ACCOUNTING_VERSION {
            return Err(AllocationAccountingError::UnsupportedVersion);
        }
        let mut issued_by_bucket_atoms = [0u128; 8];
        let mut cursor = 6;
        for issued in &mut issued_by_bucket_atoms {
            let raw: [u8; 16] = bytes[cursor..cursor + 16]
                .try_into()
                .map_err(|_| AllocationAccountingError::WrongLength)?;
            *issued = u128::from_be_bytes(raw);
            cursor += 16;
        }
        let burned: [u8; 16] = bytes[cursor..cursor + 16]
            .try_into()
            .map_err(|_| AllocationAccountingError::WrongLength)?;
        let accounting = Self {
            issued_by_bucket_atoms,
            burned_atoms: u128::from_be_bytes(burned),
        };
        accounting.validate()?;
        if accounting.encode()?.as_slice() != bytes {
            return Err(AllocationAccountingError::InvalidState);
        }
        Ok(accounting)
    }

    pub fn commitment(&self) -> Result<[u8; 32], AllocationAccountingError> {
        let encoded = self.encode()?;
        let mut hash = Sha256::new();
        hash.update(ACCOUNTING_COMMITMENT_DOMAIN);
        hash.update(encoded);
        Ok(hash.finalize().into())
    }
}

/// Stable SHA-256 fingerprint intended to be bound into a future canonical Genesis and manifest.
pub fn policy_fingerprint() -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(POLICY_FINGERPRINT_DOMAIN);
    hash.update(POLICY_ID);
    hash.update(POLICY_VERSION.to_be_bytes());
    hash.update(ATOMS_PER_COIN.to_be_bytes());
    hash.update(MAX_TOTAL_SUPPLY_ATOMS.to_be_bytes());
    for budget in ALLOCATION_BUDGETS {
        hash.update([budget.bucket as u8]);
        hash.update(budget.coins.to_be_bytes());
        hash.update(budget.share_basis_points.to_be_bytes());
    }
    hash.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v04_eight_buckets_sum_to_exact_cap_and_one_hundred_percent() {
        let coins = ALLOCATION_BUDGETS.iter().map(|b| b.coins).sum::<u128>();
        let shares = ALLOCATION_BUDGETS
            .iter()
            .map(|b| b.share_basis_points as u32)
            .sum::<u32>();
        assert_eq!(coins, 10_000_000_000);
        assert_eq!(shares, 10_000);
        assert_eq!(
            ALLOCATION_BUDGETS.iter().map(|b| b.atoms()).sum::<u128>(),
            MAX_TOTAL_SUPPLY_ATOMS
        );
        assert_eq!(
            AllocationBucket::OwnerAllocation.budget().coins,
            1_000_000_000
        );
        assert_eq!(
            AllocationBucket::MiningNetworkSecurity.budget().coins,
            3_000_000_000
        );
        assert_ne!(policy_fingerprint(), [0; 32]);
    }

    #[test]
    fn bucket_caps_and_failed_issuance_are_atomic() {
        let mut state = AllocationAccounting::new();
        state
            .record_issuance(
                AllocationBucket::OwnerAllocation,
                1_000_000_000 * ATOMS_PER_COIN,
            )
            .unwrap();
        let before = state.clone();
        assert_eq!(
            state.record_issuance(AllocationBucket::OwnerAllocation, 1),
            Err(AllocationAccountingError::BucketBudgetExceeded(
                AllocationBucket::OwnerAllocation
            ))
        );
        assert_eq!(state, before);
        assert_eq!(
            state.gross_issued_atoms(),
            Ok(1_000_000_000 * ATOMS_PER_COIN)
        );
        assert_eq!(
            state.live_supply_atoms(),
            Ok(1_000_000_000 * ATOMS_PER_COIN)
        );
    }

    #[test]
    fn burn_requires_prior_issuance_in_the_designated_reserve() {
        let mut state = AllocationAccounting::new();
        state
            .record_issuance(
                AllocationBucket::OwnerAllocation,
                1_000_000_000 * ATOMS_PER_COIN,
            )
            .unwrap();
        assert_eq!(
            state.record_burn_from_reserve(1),
            Err(AllocationAccountingError::BurnExceedsIssuedBurnReserve)
        );
        state
            .record_issuance(
                AllocationBucket::ProtocolBurnReserve,
                400_000_000 * ATOMS_PER_COIN,
            )
            .unwrap();
        state
            .record_burn_from_reserve(250_000_000 * ATOMS_PER_COIN)
            .unwrap();
        assert_eq!(
            state.gross_issued_atoms(),
            Ok(1_400_000_000 * ATOMS_PER_COIN)
        );
        assert_eq!(state.burned_atoms(), 250_000_000 * ATOMS_PER_COIN);
        assert_eq!(
            state.live_supply_atoms(),
            Ok(1_150_000_000 * ATOMS_PER_COIN)
        );
        let before = state.clone();
        assert_eq!(
            state.record_burn_from_reserve(200_000_000 * ATOMS_PER_COIN),
            Err(AllocationAccountingError::BurnExceedsIssuedBurnReserve)
        );
        assert_eq!(state, before);
    }

    #[test]
    fn accounting_serialization_roundtrips_and_rejects_invalid_caps() {
        let mut state = AllocationAccounting::new();
        state
            .record_issuance(AllocationBucket::MiningNetworkSecurity, 2 * ATOMS_PER_COIN)
            .unwrap();
        state
            .record_issuance(AllocationBucket::ProtocolBurnReserve, ATOMS_PER_COIN)
            .unwrap();
        state.record_burn_from_reserve(ATOMS_PER_COIN / 2).unwrap();
        let bytes = state.encode().unwrap();
        assert_eq!(bytes.len(), ACCOUNTING_BYTES);
        assert_eq!(AllocationAccounting::decode(&bytes), Ok(state.clone()));
        assert_eq!(
            AllocationAccounting::decode(&bytes[..bytes.len() - 1]),
            Err(AllocationAccountingError::WrongLength)
        );

        let mut cap_corrupt = bytes;
        let owner_offset = 6 + AllocationBucket::OwnerAllocation.index() * 16;
        cap_corrupt[owner_offset..owner_offset + 16]
            .copy_from_slice(&(1_000_000_000 * ATOMS_PER_COIN + 1).to_be_bytes());
        assert_eq!(
            AllocationAccounting::decode(&cap_corrupt),
            Err(AllocationAccountingError::BucketBudgetExceeded(
                AllocationBucket::OwnerAllocation
            ))
        );
    }

    #[test]
    fn accounting_state_commitment_changes_with_each_bucket_counter_and_burns() {
        let empty = AllocationAccounting::new();
        let empty_hash = empty.commitment().unwrap();
        let mut issued = empty.clone();
        issued
            .record_issuance(AllocationBucket::CommunityAirdrop, 1)
            .unwrap();
        assert_ne!(empty_hash, issued.commitment().unwrap());
        issued
            .record_issuance(AllocationBucket::ProtocolBurnReserve, 1)
            .unwrap();
        let before_burn = issued.commitment().unwrap();
        issued.record_burn_from_reserve(1).unwrap();
        assert_ne!(before_burn, issued.commitment().unwrap());
    }
}
