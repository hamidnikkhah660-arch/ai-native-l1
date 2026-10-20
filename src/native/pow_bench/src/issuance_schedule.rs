//! Parameterized, deterministic block-subsidy schedule for economics research.
//!
//! The current design direction uses a hard 10-billion-coin total cap. The initial subsidy and
//! halving interval remain candidate parameters, not frozen production consensus rules. This
//! module accepts them through explicit configuration and is not wired into canonical block
//! production, block admission, fork choice, or mainnet configuration.
pub const PROVISIONAL_MAX_SUPPLY_HYPOTHESIS: u128 = 10_000_000_000;
pub const PROVISIONAL_MACRO_HALVING_YEARS: u64 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IssuanceParameters {
    maximum_supply: u128,
    initial_subsidy: u128,
    blocks_per_halving: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssuanceError {
    ZeroMaximumSupply,
    ZeroInitialSubsidy,
    ZeroHalvingInterval,
    CurrentSupplyAboveMaximum,
}

impl std::fmt::Display for IssuanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroMaximumSupply => write!(f, "maximum supply must be positive"),
            Self::ZeroInitialSubsidy => write!(f, "initial block subsidy must be positive"),
            Self::ZeroHalvingInterval => write!(f, "blocks per halving must be positive"),
            Self::CurrentSupplyAboveMaximum => {
                write!(f, "current supply exceeds the configured maximum")
            }
        }
    }
}

impl std::error::Error for IssuanceError {}

impl IssuanceParameters {
    pub fn new(
        maximum_supply: u128,
        initial_subsidy: u128,
        blocks_per_halving: u64,
    ) -> Result<Self, IssuanceError> {
        if maximum_supply == 0 {
            return Err(IssuanceError::ZeroMaximumSupply);
        }
        if initial_subsidy == 0 {
            return Err(IssuanceError::ZeroInitialSubsidy);
        }
        if blocks_per_halving == 0 {
            return Err(IssuanceError::ZeroHalvingInterval);
        }
        Ok(Self {
            maximum_supply,
            initial_subsidy,
            blocks_per_halving,
        })
    }

    pub fn maximum_supply(&self) -> u128 {
        self.maximum_supply
    }

    pub fn initial_subsidy(&self) -> u128 {
        self.initial_subsidy
    }

    pub fn blocks_per_halving(&self) -> u64 {
        self.blocks_per_halving
    }

    /// Nominal subsidy for block height, before applying the remaining-supply cap.
    ///
    /// The right shift defines exact integer rounding: each halving floors at the smallest whole
    /// accounting unit. Subsidy eventually reaches zero; unissued remainder stays unissued rather
    /// than being minted by a special terminal rule.
    pub fn nominal_subsidy_at_height(&self, block_height: u64) -> u128 {
        let era = block_height / self.blocks_per_halving;
        if era >= u128::BITS as u64 {
            0
        } else {
            self.initial_subsidy >> era
        }
    }

    /// Return the valid reward for a candidate block given authenticated current total supply.
    /// A caller must derive current_supply from validated chain state, never from peer input.
    pub fn reward_for_block(
        &self,
        block_height: u64,
        current_supply: u128,
    ) -> Result<u128, IssuanceError> {
        if current_supply > self.maximum_supply {
            return Err(IssuanceError::CurrentSupplyAboveMaximum);
        }
        let remaining = self.maximum_supply - current_supply;
        Ok(self.nominal_subsidy_at_height(block_height).min(remaining))
    }

    /// Compute the maximum cumulative subsidy after blocks_mined blocks, for heights
    /// 0..blocks_mined. Work is bounded by the 128 possible non-zero integer halvings, not by the
    /// requested block count, so it can safely evaluate very large heights in tests or simulations.
    pub fn cumulative_issuance_after_blocks(&self, blocks_mined: u64) -> u128 {
        let mut remaining_blocks = blocks_mined;
        let mut total = 0u128;
        for era in 0..u128::BITS {
            if remaining_blocks == 0 || total == self.maximum_supply {
                break;
            }
            let subsidy = self.initial_subsidy >> era;
            if subsidy == 0 {
                break;
            }
            let blocks_in_era = remaining_blocks.min(self.blocks_per_halving) as u128;
            let remaining_supply = self.maximum_supply - total;
            // Check by division first; multiplication cannot overflow and issuance never exceeds
            // the cap even if the whole era's nominal reward is larger than remaining supply.
            if subsidy > remaining_supply / blocks_in_era {
                return self.maximum_supply;
            }
            total += subsidy * blocks_in_era;
            remaining_blocks -= blocks_in_era as u64;
        }
        total
    }

    pub fn remaining_supply(&self, current_supply: u128) -> Result<u128, IssuanceError> {
        if current_supply > self.maximum_supply {
            return Err(IssuanceError::CurrentSupplyAboveMaximum);
        }
        Ok(self.maximum_supply - current_supply)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_halving_has_exact_inclusive_boundaries() {
        let params = IssuanceParameters::new(10_000, 100, 4).unwrap();
        assert_eq!(params.nominal_subsidy_at_height(0), 100);
        assert_eq!(params.nominal_subsidy_at_height(3), 100);
        assert_eq!(params.nominal_subsidy_at_height(4), 50);
        assert_eq!(params.nominal_subsidy_at_height(7), 50);
        assert_eq!(params.nominal_subsidy_at_height(8), 25);
        assert_eq!(params.nominal_subsidy_at_height(12), 12);
        assert_eq!(params.nominal_subsidy_at_height(u64::MAX), 0);
    }

    #[test]
    fn block_reward_is_capped_by_remaining_supply() {
        let params = IssuanceParameters::new(250, 100, 8).unwrap();
        assert_eq!(params.reward_for_block(0, 0), Ok(100));
        assert_eq!(params.reward_for_block(1, 200), Ok(50));
        assert_eq!(params.reward_for_block(2, 250), Ok(0));
        assert_eq!(
            params.reward_for_block(2, 251),
            Err(IssuanceError::CurrentSupplyAboveMaximum)
        );
        assert_eq!(params.remaining_supply(200), Ok(50));
        assert_eq!(
            params.remaining_supply(251),
            Err(IssuanceError::CurrentSupplyAboveMaximum)
        );
    }

    #[test]
    fn cumulative_schedule_matches_independent_naive_sum() {
        let params = IssuanceParameters::new(10_000, 100, 3).unwrap();
        let mut expected = 0u128;
        for blocks_mined in 0u64..100 {
            assert_eq!(
                params.cumulative_issuance_after_blocks(blocks_mined),
                expected
            );
            if expected < params.maximum_supply {
                expected = expected
                    .saturating_add(params.nominal_subsidy_at_height(blocks_mined))
                    .min(params.maximum_supply);
            }
        }
    }

    #[test]
    fn cap_is_never_exceeded_and_last_block_is_truncated() {
        let params = IssuanceParameters::new(250, 100, 8).unwrap();
        assert_eq!(params.cumulative_issuance_after_blocks(0), 0);
        assert_eq!(params.cumulative_issuance_after_blocks(1), 100);
        assert_eq!(params.cumulative_issuance_after_blocks(2), 200);
        assert_eq!(params.cumulative_issuance_after_blocks(3), 250);
        assert_eq!(params.cumulative_issuance_after_blocks(4), 250);
        assert_eq!(params.reward_for_block(2, 200), Ok(50));
        assert_eq!(params.reward_for_block(3, 250), Ok(0));
    }

    #[test]
    fn huge_block_count_is_bounded_and_overflow_safe() {
        let params = IssuanceParameters::new(u128::MAX, u128::MAX, 1).unwrap();
        assert_eq!(params.cumulative_issuance_after_blocks(u64::MAX), u128::MAX);
    }

    #[test]
    fn zero_parameters_fail_closed() {
        assert_eq!(
            IssuanceParameters::new(0, 1, 1),
            Err(IssuanceError::ZeroMaximumSupply)
        );
        assert_eq!(
            IssuanceParameters::new(1, 0, 1),
            Err(IssuanceError::ZeroInitialSubsidy)
        );
        assert_eq!(
            IssuanceParameters::new(1, 1, 0),
            Err(IssuanceError::ZeroHalvingInterval)
        );
    }
}
