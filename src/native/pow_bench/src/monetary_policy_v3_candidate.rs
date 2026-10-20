//! CP-0213 delegated monetary-policy arithmetic candidate.
//! This module is not used by block admission, block production, fork choice, Genesis,
//! wire encoding or state-root computation. It is a pre-integration conformance model only.
pub const ATOMS_PER_COIN: u128 = 100_000_000;
pub const MAX_SUPPLY_ATOMS: u128 = 1_000_000_000_000_000_000;
pub const FOUNDER_BUDGET_ATOMS: u128 = 400_000_000_000_000_000;
pub const MINER_BUDGET_ATOMS: u128 = 300_000_000_000_000_000;
pub const PUBLIC_GOODS_BUDGET_ATOMS: u128 = 300_000_000_000_000_000;
pub const INITIAL_MINER_SUBSIDY_ATOMS: u128 = 35_673_515_981;
pub const BLOCKS_PER_HALVING: u64 = 4_204_800;
pub const FIRST_ELIGIBLE_HEIGHT: u64 = 1;
pub const FOUNDER_CLIFF_BLOCKS: u64 = 1_051_200;
pub const FOUNDER_VESTING_EPOCH_BLOCKS: u64 = 87_600;
pub const FOUNDER_VESTING_EPOCHS: u64 = 48;
pub const PUBLIC_RELEASE_TIMELOCK_BLOCKS: u64 = 20_160;

pub const PUBLIC_GOODS_BUCKET_BUDGETS: [u128; 6] = [
    30_000_000_000_000_000, // gifts
    90_000_000_000_000_000, // developer grants
    60_000_000_000_000_000, // infrastructure/testnet
    30_000_000_000_000_000, // bug bounty
    30_000_000_000_000_000, // education/docs
    60_000_000_000_000_000, // operations/security
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicGoodsBucket {
    Gifts,
    DeveloperGrants,
    InfrastructureTestnet,
    BugBounty,
    EducationDocs,
    OperationsSecurity,
}

impl PublicGoodsBucket {
    const fn index(self) -> usize {
        match self {
            Self::Gifts => 0,
            Self::DeveloperGrants => 1,
            Self::InfrastructureTestnet => 2,
            Self::BugBounty => 3,
            Self::EducationDocs => 4,
            Self::OperationsSecurity => 5,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyError {
    CounterAboveBudget,
    CounterSumMismatch,
    BurnAboveLiveSupply,
    ReleaseAmountZero,
    ArithmeticOverflow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IssuanceCounters {
    pub total_issued_atoms: u128,
    pub miner_issued_atoms: u128,
    pub founder_issued_atoms: u128,
    pub public_goods_issued_atoms: [u128; 6],
    pub total_burned_atoms: u128,
}

impl IssuanceCounters {
    /// Gross-issued counters never decrease when live value is burned.
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.total_issued_atoms > MAX_SUPPLY_ATOMS
            || self.miner_issued_atoms > MINER_BUDGET_ATOMS
            || self.founder_issued_atoms > FOUNDER_BUDGET_ATOMS
            || self.total_burned_atoms > self.total_issued_atoms
        {
            return Err(PolicyError::CounterAboveBudget);
        }
        let mut sum = self
            .miner_issued_atoms
            .checked_add(self.founder_issued_atoms)
            .ok_or(PolicyError::ArithmeticOverflow)?;
        for (issued, budget) in self
            .public_goods_issued_atoms
            .iter()
            .zip(PUBLIC_GOODS_BUCKET_BUDGETS)
        {
            if *issued > budget {
                return Err(PolicyError::CounterAboveBudget);
            }
            sum = sum
                .checked_add(*issued)
                .ok_or(PolicyError::ArithmeticOverflow)?;
        }
        if sum != self.total_issued_atoms {
            return Err(PolicyError::CounterSumMismatch);
        }
        Ok(())
    }

    pub fn live_supply_atoms(&self) -> Result<u128, PolicyError> {
        self.validate()?;
        self.total_issued_atoms
            .checked_sub(self.total_burned_atoms)
            .ok_or(PolicyError::BurnAboveLiveSupply)
    }

    /// Validator-side candidate calculation. Not called from production consensus.
    pub fn issue_miner_at_height(&mut self, height: u64) -> Result<u128, PolicyError> {
        self.validate()?;
        let issued = nominal_miner_subsidy_at_height(height)
            .min(MINER_BUDGET_ATOMS - self.miner_issued_atoms)
            .min(MAX_SUPPLY_ATOMS - self.total_issued_atoms);
        self.miner_issued_atoms = self
            .miner_issued_atoms
            .checked_add(issued)
            .ok_or(PolicyError::ArithmeticOverflow)?;
        self.total_issued_atoms = self
            .total_issued_atoms
            .checked_add(issued)
            .ok_or(PolicyError::ArithmeticOverflow)?;
        self.validate()?;
        Ok(issued)
    }

    /// Issue only the as-yet-unissued cumulative founder entitlement for this schedule index.
    pub fn issue_founder_vesting_at_index(&mut self, index: u64) -> Result<u128, PolicyError> {
        self.validate()?;
        let due = founder_cumulative_due_atoms(index);
        if self.founder_issued_atoms > due {
            return Err(PolicyError::CounterAboveBudget);
        }
        let issued = due - self.founder_issued_atoms;
        if issued > MAX_SUPPLY_ATOMS - self.total_issued_atoms {
            return Err(PolicyError::CounterAboveBudget);
        }
        self.founder_issued_atoms = self
            .founder_issued_atoms
            .checked_add(issued)
            .ok_or(PolicyError::ArithmeticOverflow)?;
        self.total_issued_atoms = self
            .total_issued_atoms
            .checked_add(issued)
            .ok_or(PolicyError::ArithmeticOverflow)?;
        self.validate()?;
        Ok(issued)
    }

    /// Candidate release accounting only. Governance signatures/timelock/replay are separate.
    pub fn issue_public_goods_release(
        &mut self,
        bucket: PublicGoodsBucket,
        amount: u128,
    ) -> Result<(), PolicyError> {
        self.validate()?;
        if amount == 0 {
            return Err(PolicyError::ReleaseAmountZero);
        }
        let index = bucket.index();
        let next_bucket = self.public_goods_issued_atoms[index]
            .checked_add(amount)
            .ok_or(PolicyError::ArithmeticOverflow)?;
        let next_total = self
            .total_issued_atoms
            .checked_add(amount)
            .ok_or(PolicyError::ArithmeticOverflow)?;
        if next_bucket > PUBLIC_GOODS_BUCKET_BUDGETS[index] || next_total > MAX_SUPPLY_ATOMS {
            return Err(PolicyError::CounterAboveBudget);
        }
        self.public_goods_issued_atoms[index] = next_bucket;
        self.total_issued_atoms = next_total;
        self.validate()
    }

    /// Simulated burn lowers live value but cannot replenish an issuance bucket.
    pub fn burn_from_live_supply(&mut self, amount: u128) -> Result<(), PolicyError> {
        if amount > self.live_supply_atoms()? {
            return Err(PolicyError::BurnAboveLiveSupply);
        }
        self.total_burned_atoms = self
            .total_burned_atoms
            .checked_add(amount)
            .ok_or(PolicyError::ArithmeticOverflow)?;
        self.validate()
    }
}

/// Height convention: Genesis=0; height 1 has schedule index zero.
pub fn nominal_miner_subsidy_at_height(height: u64) -> u128 {
    if height < FIRST_ELIGIBLE_HEIGHT {
        return 0;
    }
    let era = (height - FIRST_ELIGIBLE_HEIGHT) / BLOCKS_PER_HALVING;
    if era >= u128::BITS as u64 {
        0
    } else {
        INITIAL_MINER_SUBSIDY_ATOMS >> era
    }
}

/// Cumulative candidate miner issuance after N eligible blocks, from schedule index zero.
/// The loop is bounded by the 128 possible u128 right shifts, not by block count.
pub fn cumulative_miner_issuance_after_blocks(blocks_mined: u64) -> u128 {
    let mut remaining = blocks_mined;
    let mut total = 0u128;
    for era in 0..u128::BITS {
        if remaining == 0 || total == MINER_BUDGET_ATOMS {
            break;
        }
        let subsidy = INITIAL_MINER_SUBSIDY_ATOMS >> era;
        if subsidy == 0 {
            break;
        }
        let blocks = remaining.min(BLOCKS_PER_HALVING) as u128;
        let budget_remaining = MINER_BUDGET_ATOMS - total;
        if subsidy > budget_remaining / blocks {
            return MINER_BUDGET_ATOMS;
        }
        total += subsidy * blocks;
        remaining -= blocks as u64;
    }
    total
}

/// Completed founder vesting epochs. No tranche releases during the cliff itself.
pub fn founder_vested_periods(index: u64) -> u64 {
    let first_epoch = FOUNDER_CLIFF_BLOCKS + FOUNDER_VESTING_EPOCH_BLOCKS;
    if index < first_epoch {
        0
    } else {
        ((index - FOUNDER_CLIFF_BLOCKS) / FOUNDER_VESTING_EPOCH_BLOCKS).min(FOUNDER_VESTING_EPOCHS)
    }
}

/// Cumulative founder amount due; at epoch 48 the entire budget is unlocked exactly.
pub fn founder_cumulative_due_atoms(index: u64) -> u128 {
    FOUNDER_BUDGET_ATOMS * founder_vested_periods(index) as u128 / FOUNDER_VESTING_EPOCHS as u128
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTORS: &str =
        include_str!("../../../../simulations/cp0214_policy_arithmetic_vectors.tsv");

    #[test]
    fn shared_language_neutral_vectors_match_rust_arithmetic() {
        let mut count = 0;
        for line in VECTORS.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fields: Vec<_> = line.split('|').collect();
            assert_eq!(fields.len(), 3, "bad vector: {line}");
            let input: u64 = fields[1].parse().expect("integer input");
            let expected: u128 = fields[2].parse().expect("integer expected value");
            let actual = match fields[0] {
                "subsidy" => nominal_miner_subsidy_at_height(input),
                "miner_cumulative" => cumulative_miner_issuance_after_blocks(input),
                "founder_periods" => founder_vested_periods(input) as u128,
                "founder_due" => founder_cumulative_due_atoms(input),
                other => panic!("unknown vector kind: {other}"),
            };
            assert_eq!(actual, expected, "vector mismatch: {line}");
            count += 1;
        }
        assert_eq!(
            count, 24,
            "shared vector count changed; review both implementations"
        );
    }

    #[test]
    fn all_budget_envelopes_sum_exactly_to_ten_billion_coins() {
        assert_eq!(
            FOUNDER_BUDGET_ATOMS
                + MINER_BUDGET_ATOMS
                + PUBLIC_GOODS_BUCKET_BUDGETS.iter().sum::<u128>(),
            MAX_SUPPLY_ATOMS
        );
        assert_eq!(
            PUBLIC_GOODS_BUCKET_BUDGETS.iter().sum::<u128>(),
            PUBLIC_GOODS_BUDGET_ATOMS
        );
        IssuanceCounters::default().validate().unwrap();
    }

    #[test]
    fn miner_schedule_applies_height_offset_and_both_caps() {
        let mut counters = IssuanceCounters::default();
        assert_eq!(nominal_miner_subsidy_at_height(0), 0);
        assert_eq!(
            counters.issue_miner_at_height(1),
            Ok(INITIAL_MINER_SUBSIDY_ATOMS)
        );
        let mut nearly_full = IssuanceCounters {
            total_issued_atoms: MAX_SUPPLY_ATOMS - 5,
            miner_issued_atoms: MINER_BUDGET_ATOMS - 5,
            founder_issued_atoms: FOUNDER_BUDGET_ATOMS,
            public_goods_issued_atoms: PUBLIC_GOODS_BUCKET_BUDGETS,
            total_burned_atoms: 0,
        };
        assert_eq!(nearly_full.issue_miner_at_height(1), Ok(5));
        assert_eq!(nearly_full.total_issued_atoms, MAX_SUPPLY_ATOMS);
        assert_eq!(nearly_full.issue_miner_at_height(2), Ok(0));
        let mut miner_full = IssuanceCounters {
            total_issued_atoms: FOUNDER_BUDGET_ATOMS + MINER_BUDGET_ATOMS,
            miner_issued_atoms: MINER_BUDGET_ATOMS,
            founder_issued_atoms: FOUNDER_BUDGET_ATOMS,
            ..IssuanceCounters::default()
        };
        assert_eq!(miner_full.issue_miner_at_height(1), Ok(0));
    }

    #[test]
    fn founder_vesting_has_cliff_and_exact_final_tranche() {
        let mut counters = IssuanceCounters::default();
        assert_eq!(counters.issue_founder_vesting_at_index(1_138_799), Ok(0));
        assert_eq!(
            counters.issue_founder_vesting_at_index(1_138_800),
            Ok(FOUNDER_BUDGET_ATOMS / 48)
        );
        assert_eq!(counters.issue_founder_vesting_at_index(1_138_800), Ok(0));
        assert_eq!(
            counters.issue_founder_vesting_at_index(5_256_000),
            Ok(FOUNDER_BUDGET_ATOMS - FOUNDER_BUDGET_ATOMS / 48)
        );
        assert_eq!(counters.founder_issued_atoms, FOUNDER_BUDGET_ATOMS);
        assert_eq!(counters.total_issued_atoms, FOUNDER_BUDGET_ATOMS);
    }

    #[test]
    fn public_goods_subcaps_are_independent_and_burn_does_not_refill_them() {
        let mut counters = IssuanceCounters::default();
        counters
            .issue_public_goods_release(PublicGoodsBucket::Gifts, 300_000_000 * ATOMS_PER_COIN)
            .unwrap();
        assert_eq!(
            counters.issue_public_goods_release(PublicGoodsBucket::Gifts, 1),
            Err(PolicyError::CounterAboveBudget)
        );
        let gross_before_burn = counters.total_issued_atoms;
        counters.burn_from_live_supply(100).unwrap();
        assert_eq!(counters.total_issued_atoms, gross_before_burn);
        assert_eq!(counters.total_burned_atoms, 100);
        assert_eq!(counters.live_supply_atoms(), Ok(gross_before_burn - 100));
        assert_eq!(
            counters.issue_public_goods_release(PublicGoodsBucket::Gifts, 1),
            Err(PolicyError::CounterAboveBudget)
        );
    }

    #[test]
    fn inconsistent_counters_zero_release_and_excess_burn_fail_closed() {
        let inconsistent = IssuanceCounters {
            total_issued_atoms: 10,
            miner_issued_atoms: 9,
            ..IssuanceCounters::default()
        };
        assert_eq!(
            inconsistent.validate(),
            Err(PolicyError::CounterSumMismatch)
        );
        let mut counters = IssuanceCounters::default();
        assert_eq!(
            counters.burn_from_live_supply(1),
            Err(PolicyError::BurnAboveLiveSupply)
        );
        assert_eq!(
            counters.issue_public_goods_release(PublicGoodsBucket::EducationDocs, 0),
            Err(PolicyError::ReleaseAmountZero)
        );
    }
}
