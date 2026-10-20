//! Research-only, single-source economics comparison for the 10B maximum-supply design.
//!
//! This module compares allocation envelopes and 1-year/4-year block-based halving candidates.
//! It does not mint coins, assign a Genesis balance, activate a consensus rule, or release a
//! public-goods reserve. Fixed vectors are shared with an independent Python arbitrary-precision
//! checker. All allocations and schedules here remain recommendations until reviewed/frozen.

pub const ATOMS_PER_COIN: u128 = 100_000_000;
pub const MAX_SUPPLY_ATOMS: u128 = 1_000_000_000_000_000_000;
pub const FOUNDER_ALLOCATION_BPS: u32 = 4_000;
pub const BPS_DENOMINATOR: u32 = 10_000;
pub const TARGET_BLOCK_SECONDS: u64 = 30;
pub const BLOCKS_PER_YEAR: u64 = 365 * 24 * 60 * 60 / TARGET_BLOCK_SECONDS;
pub const ONE_YEAR_HALVING_BLOCKS: u64 = BLOCKS_PER_YEAR;
pub const FOUR_YEAR_HALVING_BLOCKS: u64 = 4 * BLOCKS_PER_YEAR;
pub const MINER_BUDGET_OPTIONS_BPS: [u32; 9] = [
    2_000, 2_500, 3_000, 3_500, 4_000, 4_500, 5_000, 5_500, 6_000,
];
pub const RECOMMENDED_MINER_BUDGET_BPS: u32 = 3_000;
pub const RECOMMENDED_HALVING_BLOCKS: u64 = FOUR_YEAR_HALVING_BLOCKS;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EconomicScenarioError {
    InvalidMinerBudget,
    ZeroHalvingInterval,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EconomicDesignScenario {
    miner_budget_bps: u32,
    blocks_per_halving: u64,
    founder_allocation_atoms: u128,
    miner_budget_atoms: u128,
    public_goods_budget_atoms: u128,
    initial_subsidy_atoms: u128,
}

impl EconomicDesignScenario {
    pub fn new(
        miner_budget_bps: u32,
        blocks_per_halving: u64,
    ) -> Result<Self, EconomicScenarioError> {
        if miner_budget_bps == 0 || miner_budget_bps > BPS_DENOMINATOR - FOUNDER_ALLOCATION_BPS {
            return Err(EconomicScenarioError::InvalidMinerBudget);
        }
        if blocks_per_halving == 0 {
            return Err(EconomicScenarioError::ZeroHalvingInterval);
        }

        let founder_allocation_atoms =
            MAX_SUPPLY_ATOMS * FOUNDER_ALLOCATION_BPS as u128 / BPS_DENOMINATOR as u128;
        let miner_budget_atoms =
            MAX_SUPPLY_ATOMS * miner_budget_bps as u128 / BPS_DENOMINATOR as u128;
        let public_goods_budget_atoms =
            MAX_SUPPLY_ATOMS - founder_allocation_atoms - miner_budget_atoms;
        // Nominally issue one-half of the candidate miner budget in the first era. Atomic-unit
        // floor rounding deliberately leaves a tiny unissued remainder rather than overminting.
        let initial_subsidy_atoms = miner_budget_atoms / (2 * blocks_per_halving as u128);

        Ok(Self {
            miner_budget_bps,
            blocks_per_halving,
            founder_allocation_atoms,
            miner_budget_atoms,
            public_goods_budget_atoms,
            initial_subsidy_atoms,
        })
    }

    pub fn miner_budget_bps(&self) -> u32 {
        self.miner_budget_bps
    }

    pub fn blocks_per_halving(&self) -> u64 {
        self.blocks_per_halving
    }

    pub fn founder_allocation_atoms(&self) -> u128 {
        self.founder_allocation_atoms
    }

    pub fn miner_budget_atoms(&self) -> u128 {
        self.miner_budget_atoms
    }

    pub fn public_goods_budget_atoms(&self) -> u128 {
        self.public_goods_budget_atoms
    }

    pub fn initial_subsidy_atoms(&self) -> u128 {
        self.initial_subsidy_atoms
    }

    pub fn nominal_subsidy_at_height(&self, block_height: u64) -> u128 {
        let era = block_height / self.blocks_per_halving;
        if era >= u128::BITS as u64 {
            0
        } else {
            self.initial_subsidy_atoms >> era
        }
    }

    /// Cumulative nominal miner emission in block heights 0..blocks_mined, capped at the
    /// scenario's miner budget. The loop is bounded by the 128 possible non-zero shifts.
    pub fn cumulative_mined_after_blocks(&self, blocks_mined: u64) -> u128 {
        let mut remaining_blocks = blocks_mined;
        let mut total = 0u128;
        for era in 0..u128::BITS {
            if remaining_blocks == 0 || total == self.miner_budget_atoms {
                break;
            }
            let reward = self.initial_subsidy_atoms >> era;
            if reward == 0 {
                break;
            }
            let blocks_in_era = remaining_blocks.min(self.blocks_per_halving) as u128;
            let remaining_budget = self.miner_budget_atoms - total;
            if reward > remaining_budget / blocks_in_era {
                return self.miner_budget_atoms;
            }
            total += reward * blocks_in_era;
            remaining_blocks -= blocks_in_era as u64;
        }
        total
    }

    /// Total protocol allocation envelope is exactly the cap. This is not a claim that the
    /// public-goods bucket is minted at Genesis or that it may be spent without governance rules.
    pub fn allocation_envelope_atoms(&self) -> u128 {
        self.founder_allocation_atoms + self.miner_budget_atoms + self.public_goods_budget_atoms
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTORS: &str =
        include_str!("../../../../simulations/cp0139_ai_economic_design_vectors.txt");

    #[test]
    fn shared_cross_language_vectors_match_exact_integer_results() {
        let mut count = 0usize;
        for line in VECTORS.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let f: Vec<&str> = line.split('|').collect();
            assert_eq!(f.len(), 9, "malformed vector: {line}");
            assert_eq!(f[0], "V");
            let miner_bps = f[2].parse::<u32>().unwrap();
            let interval = f[3].parse::<u64>().unwrap();
            let height = f[4].parse::<u64>().unwrap();
            let blocks = f[5].parse::<u64>().unwrap();
            let expected_subsidy = f[6].parse::<u128>().unwrap();
            let expected_cumulative = f[7].parse::<u128>().unwrap();
            let expected_reserve = f[8].parse::<u128>().unwrap();

            let scenario = EconomicDesignScenario::new(miner_bps, interval).unwrap();
            assert_eq!(
                scenario.nominal_subsidy_at_height(height),
                expected_subsidy,
                "{}",
                f[1]
            );
            assert_eq!(
                scenario.cumulative_mined_after_blocks(blocks),
                expected_cumulative,
                "{}",
                f[1]
            );
            assert_eq!(
                scenario.public_goods_budget_atoms(),
                expected_reserve,
                "{}",
                f[1]
            );
            assert!(
                scenario.cumulative_mined_after_blocks(blocks) <= scenario.miner_budget_atoms()
            );
            assert_eq!(scenario.allocation_envelope_atoms(), MAX_SUPPLY_ATOMS);
            count += 1;
        }
        assert_eq!(count, 126, "expected 126 shared vectors, got {count}");
    }

    #[test]
    fn all_candidate_allocation_envelopes_conserve_exactly_ten_billion_coins() {
        for miner_bps in MINER_BUDGET_OPTIONS_BPS {
            let scenario =
                EconomicDesignScenario::new(miner_bps, FOUR_YEAR_HALVING_BLOCKS).unwrap();
            assert_eq!(scenario.founder_allocation_atoms(), 400_000_000_000_000_000);
            assert_eq!(
                scenario.public_goods_budget_atoms(),
                MAX_SUPPLY_ATOMS
                    - scenario.founder_allocation_atoms()
                    - scenario.miner_budget_atoms()
            );
            assert_eq!(scenario.allocation_envelope_atoms(), MAX_SUPPLY_ATOMS);
        }
    }

    #[test]
    fn recommended_candidate_allocates_40_percent_founder_30_percent_miners_and_30_percent_public_goods(
    ) {
        let scenario =
            EconomicDesignScenario::new(RECOMMENDED_MINER_BUDGET_BPS, RECOMMENDED_HALVING_BLOCKS)
                .unwrap();
        assert_eq!(scenario.founder_allocation_atoms(), 400_000_000_000_000_000);
        assert_eq!(scenario.miner_budget_atoms(), 300_000_000_000_000_000);
        assert_eq!(
            scenario.public_goods_budget_atoms(),
            300_000_000_000_000_000
        );
        assert_eq!(scenario.allocation_envelope_atoms(), MAX_SUPPLY_ATOMS);
    }

    #[test]
    fn four_year_candidate_spreads_emission_more_slowly_than_one_year_candidate() {
        let annual =
            EconomicDesignScenario::new(RECOMMENDED_MINER_BUDGET_BPS, ONE_YEAR_HALVING_BLOCKS)
                .unwrap();
        let four_year =
            EconomicDesignScenario::new(RECOMMENDED_MINER_BUDGET_BPS, FOUR_YEAR_HALVING_BLOCKS)
                .unwrap();
        assert_eq!(
            four_year.blocks_per_halving(),
            annual.blocks_per_halving() * 4
        );
        assert!(annual.initial_subsidy_atoms() > four_year.initial_subsidy_atoms());
        assert!(
            annual.cumulative_mined_after_blocks(BLOCKS_PER_YEAR)
                > four_year.cumulative_mined_after_blocks(BLOCKS_PER_YEAR)
        );
        assert_eq!(
            annual.nominal_subsidy_at_height(annual.blocks_per_halving()),
            annual.initial_subsidy_atoms() / 2
        );
        assert_eq!(
            four_year.nominal_subsidy_at_height(four_year.blocks_per_halving()),
            four_year.initial_subsidy_atoms() / 2
        );
    }

    #[test]
    fn invalid_miner_budgets_and_intervals_fail_closed() {
        assert_eq!(
            EconomicDesignScenario::new(0, FOUR_YEAR_HALVING_BLOCKS),
            Err(EconomicScenarioError::InvalidMinerBudget)
        );
        assert_eq!(
            EconomicDesignScenario::new(6_001, FOUR_YEAR_HALVING_BLOCKS),
            Err(EconomicScenarioError::InvalidMinerBudget)
        );
        assert_eq!(
            EconomicDesignScenario::new(u32::MAX, FOUR_YEAR_HALVING_BLOCKS),
            Err(EconomicScenarioError::InvalidMinerBudget)
        );
        assert_eq!(
            EconomicDesignScenario::new(RECOMMENDED_MINER_BUDGET_BPS, 0),
            Err(EconomicScenarioError::ZeroHalvingInterval)
        );
    }

    #[test]
    fn long_horizon_never_exceeds_supply_or_miner_budget() {
        for miner_bps in MINER_BUDGET_OPTIONS_BPS {
            for interval in [ONE_YEAR_HALVING_BLOCKS, FOUR_YEAR_HALVING_BLOCKS] {
                let scenario = EconomicDesignScenario::new(miner_bps, interval).unwrap();
                let emitted = scenario.cumulative_mined_after_blocks(u64::MAX);
                assert!(emitted <= scenario.miner_budget_atoms());
                assert!(scenario.founder_allocation_atoms() + emitted <= MAX_SUPPLY_ATOMS);
                assert_eq!(scenario.nominal_subsidy_at_height(u64::MAX), 0);
            }
        }
    }
}
