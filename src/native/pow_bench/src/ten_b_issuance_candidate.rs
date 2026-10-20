//! Ten-billion-cap miner-emission comparison candidate; not active consensus code.
//!
//! Matches the latest proposed 10B envelope: 40% founder, 30% miner/security rewards, and 30%
//! public-goods/bonus/treasury allocations. The schedule is parameterized so 6-month, 12-month,
//! and 4-year halvings can be compared. Nothing here mints coins or is wired to canonical consensus.

pub const ATOMS_PER_COIN: u128 = 100_000_000;
pub const MAX_SUPPLY_ATOMS: u128 = 1_000_000_000_000_000_000;
pub const OWNER_ALLOCATION_ATOMS: u128 = 400_000_000_000_000_000;
pub const MINER_REWARD_BUDGET_ATOMS: u128 = 300_000_000_000_000_000;
pub const PUBLIC_GOODS_BUDGET_ATOMS: u128 =
    MAX_SUPPLY_ATOMS - OWNER_ALLOCATION_ATOMS - MINER_REWARD_BUDGET_ATOMS;
pub const TARGET_BLOCK_SECONDS: u64 = 30;
pub const BLOCKS_PER_YEAR: u64 = 365 * 24 * 60 * 60 / TARGET_BLOCK_SECONDS;
pub const SIX_MONTH_CANDIDATE_BLOCKS: u64 = BLOCKS_PER_YEAR / 2;
pub const TWELVE_MONTH_CANDIDATE_BLOCKS: u64 = BLOCKS_PER_YEAR;
pub const FOUR_YEAR_COMPARATOR_BLOCKS: u64 = 4 * BLOCKS_PER_YEAR;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MiningScheduleError {
    ZeroHalvingInterval,
    ZeroInitialSubsidy,
    MinerIssuanceAboveBudget,
}

/// A mathematical emission schedule with a caller-selected halving interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CandidateEmissionSchedule {
    blocks_per_halving: u64,
    initial_subsidy_atoms: u128,
}

impl CandidateEmissionSchedule {
    /// Derive initial subsidy so an era nominally distributes one-half of the miner budget.
    /// Integer floor-rounding means a small remainder will remain unissued after all eras.
    pub fn new(blocks_per_halving: u64) -> Result<Self, MiningScheduleError> {
        if blocks_per_halving == 0 {
            return Err(MiningScheduleError::ZeroHalvingInterval);
        }
        let initial_subsidy_atoms = MINER_REWARD_BUDGET_ATOMS / (2 * blocks_per_halving as u128);
        if initial_subsidy_atoms == 0 {
            return Err(MiningScheduleError::ZeroInitialSubsidy);
        }
        Ok(Self {
            blocks_per_halving,
            initial_subsidy_atoms,
        })
    }

    pub fn blocks_per_halving(&self) -> u64 {
        self.blocks_per_halving
    }

    pub fn initial_subsidy_atoms(&self) -> u128 {
        self.initial_subsidy_atoms
    }

    /// Nominal subsidy for a zero-based block height, before remaining-budget truncation.
    pub fn nominal_subsidy_at_height(&self, block_height: u64) -> u128 {
        let era = block_height / self.blocks_per_halving;
        if era >= u128::BITS as u64 {
            0
        } else {
            self.initial_subsidy_atoms >> era
        }
    }

    /// Capped reward at a block, from validated canonical miner-issuance state.
    /// This pure calculation does not itself credit a balance.
    pub fn reward_for_block(
        &self,
        block_height: u64,
        already_mined_atoms: u128,
    ) -> Result<u128, MiningScheduleError> {
        if already_mined_atoms > MINER_REWARD_BUDGET_ATOMS {
            return Err(MiningScheduleError::MinerIssuanceAboveBudget);
        }
        Ok(self
            .nominal_subsidy_at_height(block_height)
            .min(MINER_REWARD_BUDGET_ATOMS - already_mined_atoms))
    }

    /// Cumulative miner subsidy over block heights 0..blocks_mined, bounded by the miner budget.
    pub fn cumulative_mined_after_blocks(&self, blocks_mined: u64) -> u128 {
        let mut remaining_blocks = blocks_mined;
        let mut total = 0u128;
        for era in 0..u128::BITS {
            if remaining_blocks == 0 || total == MINER_REWARD_BUDGET_ATOMS {
                break;
            }
            let subsidy = self.initial_subsidy_atoms >> era;
            if subsidy == 0 {
                break;
            }
            let blocks_in_era = remaining_blocks.min(self.blocks_per_halving) as u128;
            let remaining_budget = MINER_REWARD_BUDGET_ATOMS - total;
            if subsidy > remaining_budget / blocks_in_era {
                return MINER_REWARD_BUDGET_ATOMS;
            }
            total += subsidy * blocks_in_era;
            remaining_blocks -= blocks_in_era as u64;
        }
        total.min(MINER_REWARD_BUDGET_ATOMS)
    }

    /// Theoretical total, assuming the proposed owner allocation is credited at Genesis.
    pub fn total_issued_after_blocks(&self, blocks_mined: u64) -> u128 {
        OWNER_ALLOCATION_ATOMS + self.cumulative_mined_after_blocks(blocks_mined)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTORS: &str =
        include_str!("../../../../simulations/cpw_10b_issuance_candidate_vectors.txt");

    #[test]
    fn shared_fixed_vectors_match_exact_integer_results() {
        let mut count = 0usize;
        for line in VECTORS.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let f: Vec<&str> = line.split('|').collect();
            assert_eq!(f.len(), 7, "malformed vector: {line}");
            assert_eq!(f[0], "V");
            let interval = f[2].parse::<u64>().unwrap();
            let height = f[3].parse::<u64>().unwrap();
            let blocks = f[4].parse::<u64>().unwrap();
            let expected_reward = f[5].parse::<u128>().unwrap();
            let expected_cumulative = f[6].parse::<u128>().unwrap();
            let schedule = CandidateEmissionSchedule::new(interval).unwrap();
            assert_eq!(
                schedule.nominal_subsidy_at_height(height),
                expected_reward,
                "{}",
                f[1]
            );
            assert_eq!(
                schedule.cumulative_mined_after_blocks(blocks),
                expected_cumulative,
                "{}",
                f[1]
            );
            assert!(expected_cumulative <= MINER_REWARD_BUDGET_ATOMS);
            assert!(schedule.total_issued_after_blocks(blocks) <= MAX_SUPPLY_ATOMS);
            count += 1;
        }
        assert!(count >= 14, "too few shared vectors: {count}");
    }

    #[test]
    fn exact_candidate_subsidies_are_derived_not_guessed() {
        let six = CandidateEmissionSchedule::new(SIX_MONTH_CANDIDATE_BLOCKS).unwrap();
        let twelve = CandidateEmissionSchedule::new(TWELVE_MONTH_CANDIDATE_BLOCKS).unwrap();
        let four_year = CandidateEmissionSchedule::new(FOUR_YEAR_COMPARATOR_BLOCKS).unwrap();
        assert_eq!(BLOCKS_PER_YEAR, 1_051_200);
        assert_eq!(six.initial_subsidy_atoms(), 285_388_127_853);
        assert_eq!(twelve.initial_subsidy_atoms(), 142_694_063_926);
        assert_eq!(four_year.initial_subsidy_atoms(), 35_673_515_981);
        assert_eq!(OWNER_ALLOCATION_ATOMS, 400_000_000_000_000_000);
        assert_eq!(MINER_REWARD_BUDGET_ATOMS, 300_000_000_000_000_000);
        assert_eq!(PUBLIC_GOODS_BUDGET_ATOMS, 300_000_000_000_000_000);
        assert_eq!(
            OWNER_ALLOCATION_ATOMS + MINER_REWARD_BUDGET_ATOMS + PUBLIC_GOODS_BUDGET_ATOMS,
            MAX_SUPPLY_ATOMS
        );
    }

    #[test]
    fn first_year_issuance_shows_the_speed_tradeoff() {
        let six = CandidateEmissionSchedule::new(SIX_MONTH_CANDIDATE_BLOCKS).unwrap();
        let twelve = CandidateEmissionSchedule::new(TWELVE_MONTH_CANDIDATE_BLOCKS).unwrap();
        let four_year = CandidateEmissionSchedule::new(FOUR_YEAR_COMPARATOR_BLOCKS).unwrap();
        assert_eq!(
            six.cumulative_mined_after_blocks(BLOCKS_PER_YEAR),
            224_999_999_999_042_400
        );
        assert_eq!(
            twelve.cumulative_mined_after_blocks(BLOCKS_PER_YEAR),
            149_999_999_999_011_200
        );
        assert_eq!(
            four_year.cumulative_mined_after_blocks(BLOCKS_PER_YEAR),
            37_499_999_999_227_200
        );
    }

    #[test]
    fn invalid_intervals_and_over_budget_state_fail_closed() {
        assert_eq!(
            CandidateEmissionSchedule::new(0),
            Err(MiningScheduleError::ZeroHalvingInterval)
        );
        let s = CandidateEmissionSchedule::new(TWELVE_MONTH_CANDIDATE_BLOCKS).unwrap();
        assert_eq!(
            s.reward_for_block(0, MINER_REWARD_BUDGET_ATOMS - 10),
            Ok(10)
        );
        assert_eq!(s.reward_for_block(0, MINER_REWARD_BUDGET_ATOMS), Ok(0));
        assert_eq!(
            s.reward_for_block(0, MINER_REWARD_BUDGET_ATOMS + 1),
            Err(MiningScheduleError::MinerIssuanceAboveBudget)
        );
    }

    #[test]
    fn subsidy_halves_at_exact_block_boundaries() {
        let s = CandidateEmissionSchedule::new(TWELVE_MONTH_CANDIDATE_BLOCKS).unwrap();
        assert_eq!(
            s.nominal_subsidy_at_height(TWELVE_MONTH_CANDIDATE_BLOCKS - 1),
            s.initial_subsidy_atoms()
        );
        assert_eq!(
            s.nominal_subsidy_at_height(TWELVE_MONTH_CANDIDATE_BLOCKS),
            s.initial_subsidy_atoms() / 2
        );
    }

    #[test]
    fn long_horizon_never_exceeds_total_cap() {
        for interval in [
            SIX_MONTH_CANDIDATE_BLOCKS,
            TWELVE_MONTH_CANDIDATE_BLOCKS,
            FOUR_YEAR_COMPARATOR_BLOCKS,
        ] {
            let s = CandidateEmissionSchedule::new(interval).unwrap();
            assert!(s.total_issued_after_blocks(u64::MAX) <= MAX_SUPPLY_ATOMS);
            assert_eq!(s.nominal_subsidy_at_height(u64::MAX), 0);
            assert!(s.cumulative_mined_after_blocks(u64::MAX) <= MINER_REWARD_BUDGET_ATOMS);
        }
    }
}
