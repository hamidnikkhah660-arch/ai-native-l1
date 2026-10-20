//! SUPERSEDED HISTORICAL EXPERIMENT — rejected by owner on 2026-10-10 in CP-0058-F.
//! The proposed linear/cliff vesting must not be used or linked into current code.
//!
//! This old module computes a maximum vested entitlement only. It does NOT mint, transfer, fund,
//! or credit coins, and it is not wired into canonical transaction/state/consensus paths.
//! Production block counts, funding source, cliff semantics, and activation remain unratified.

pub const RATIFIED_MAX_SUPPLY_ATOMS: u128 = 300_000_000_000_000_000;
pub const RATIFIED_FOUNDER_ALLOCATION_ATOMS: u128 = 60_000_000_000_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VestingError {
    ZeroMaximumSupply,
    ZeroAllocation,
    AllocationExceedsMaximum,
    ZeroLinearVestingDuration,
    EndHeightOverflow,
    ClaimedAboveVested,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FounderVestingSchedule {
    allocation_atoms: u128,
    maximum_supply_atoms: u128,
    schedule_start_height: u64,
    cliff_blocks: u64,
    linear_vesting_blocks: u64,
    cliff_end_height: u64,
    fully_vested_height: u64,
}

impl FounderVestingSchedule {
    /// Constructs an experimental schedule. All heights/durations must be explicit.
    ///
    /// Candidate cliff semantics: zero units unlock through and including the cliff-end height;
    /// linear vesting begins on the next block and reaches the full allocation at the configured
    /// fully-vested height. This semantic choice is not ratified for mainnet.
    pub fn new(
        allocation_atoms: u128,
        maximum_supply_atoms: u128,
        schedule_start_height: u64,
        cliff_blocks: u64,
        linear_vesting_blocks: u64,
    ) -> Result<Self, VestingError> {
        if maximum_supply_atoms == 0 {
            return Err(VestingError::ZeroMaximumSupply);
        }
        if allocation_atoms == 0 {
            return Err(VestingError::ZeroAllocation);
        }
        if allocation_atoms > maximum_supply_atoms {
            return Err(VestingError::AllocationExceedsMaximum);
        }
        if linear_vesting_blocks == 0 {
            return Err(VestingError::ZeroLinearVestingDuration);
        }
        let cliff_end_height = schedule_start_height
            .checked_add(cliff_blocks)
            .ok_or(VestingError::EndHeightOverflow)?;
        let fully_vested_height = cliff_end_height
            .checked_add(linear_vesting_blocks)
            .ok_or(VestingError::EndHeightOverflow)?;

        Ok(Self {
            allocation_atoms,
            maximum_supply_atoms,
            schedule_start_height,
            cliff_blocks,
            linear_vesting_blocks,
            cliff_end_height,
            fully_vested_height,
        })
    }

    pub fn allocation_atoms(&self) -> u128 {
        self.allocation_atoms
    }

    pub fn maximum_supply_atoms(&self) -> u128 {
        self.maximum_supply_atoms
    }

    pub fn schedule_start_height(&self) -> u64 {
        self.schedule_start_height
    }

    pub fn cliff_blocks(&self) -> u64 {
        self.cliff_blocks
    }

    pub fn linear_vesting_blocks(&self) -> u64 {
        self.linear_vesting_blocks
    }

    pub fn cliff_end_height(&self) -> u64 {
        self.cliff_end_height
    }

    pub fn fully_vested_height(&self) -> u64 {
        self.fully_vested_height
    }

    /// Maximum vested entitlement at a height, rounded down in atomic units.
    ///
    /// This is pure arithmetic, not a balance or authorization check. A caller cannot transfer
    /// these units unless a separately approved canonical mechanism has funded and authorized them.
    pub fn vested_entitlement_atoms(&self, block_height: u64) -> u128 {
        if block_height <= self.cliff_end_height {
            return 0;
        }
        if block_height >= self.fully_vested_height {
            return self.allocation_atoms;
        }
        let elapsed = (block_height - self.cliff_end_height) as u128;
        let duration = self.linear_vesting_blocks as u128;
        mul_div_floor(self.allocation_atoms, elapsed, duration)
    }

    /// Unclaimed portion of the mathematical vested entitlement, if prior claims are valid.
    ///
    /// The caller must enforce durable claim tracking and funding in canonical state. Replaying
    /// this pure calculation must never itself perform a transfer or allow a duplicate claim.
    pub fn unclaimed_vested_entitlement_atoms(
        &self,
        block_height: u64,
        already_claimed_atoms: u128,
    ) -> Result<u128, VestingError> {
        let vested = self.vested_entitlement_atoms(block_height);
        if already_claimed_atoms > vested {
            return Err(VestingError::ClaimedAboveVested);
        }
        Ok(vested - already_claimed_atoms)
    }
}

/// Computes floor(a*b/d) without forming a potentially overflowing a*b product.
/// Preconditions: d > 0 and b <= d. The caller keeps b < d for the partial-vesting path.
fn mul_div_floor(a: u128, b: u128, d: u128) -> u128 {
    debug_assert!(d > 0);
    debug_assert!(b <= d);
    let whole = (a / d) * b;
    let remainder = ((a % d) * b) / d;
    whole + remainder
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTORS: &str =
        include_str!("../../../../simulations/cpw_founder_vesting_candidate_vectors.txt");

    #[test]
    fn shared_fixed_vectors_match_vested_and_unclaimed_amounts() {
        let mut seen = 0usize;
        for line in VECTORS.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let f: Vec<&str> = line.split('|').collect();
            assert_eq!(f[0], "V", "unexpected vector kind: {line}");
            assert_eq!(f.len(), 11, "bad vector field count: {line}");
            let amount = f[2].parse::<u128>().unwrap();
            let maximum = f[3].parse::<u128>().unwrap();
            let start = f[4].parse::<u64>().unwrap();
            let cliff = f[5].parse::<u64>().unwrap();
            let duration = f[6].parse::<u64>().unwrap();
            let height = f[7].parse::<u64>().unwrap();
            let claimed = f[8].parse::<u128>().unwrap();
            let expected_vested = f[9].parse::<u128>().unwrap();
            let expected_unclaimed = f[10].parse::<u128>().unwrap();

            let schedule =
                FounderVestingSchedule::new(amount, maximum, start, cliff, duration).unwrap();
            assert_eq!(
                schedule.vested_entitlement_atoms(height),
                expected_vested,
                "vested mismatch in vector {}",
                f[1]
            );
            assert_eq!(
                schedule.unclaimed_vested_entitlement_atoms(height, claimed),
                Ok(expected_unclaimed),
                "unclaimed mismatch in vector {}",
                f[1]
            );
            assert!(schedule.vested_entitlement_atoms(height) <= schedule.allocation_atoms);
            assert!(schedule.allocation_atoms <= schedule.maximum_supply_atoms);
            seen += 1;
        }
        assert!(
            seen >= 14,
            "expected shared regression vectors, found {seen}"
        );
    }

    #[test]
    fn rejects_invalid_parameters_and_height_overflow() {
        assert_eq!(
            FounderVestingSchedule::new(1, 0, 0, 1, 1),
            Err(VestingError::ZeroMaximumSupply)
        );
        assert_eq!(
            FounderVestingSchedule::new(0, 10, 0, 1, 1),
            Err(VestingError::ZeroAllocation)
        );
        assert_eq!(
            FounderVestingSchedule::new(11, 10, 0, 1, 1),
            Err(VestingError::AllocationExceedsMaximum)
        );
        assert_eq!(
            FounderVestingSchedule::new(1, 10, 0, 1, 0),
            Err(VestingError::ZeroLinearVestingDuration)
        );
        assert_eq!(
            FounderVestingSchedule::new(1, 10, u64::MAX - 2, 2, 1),
            Err(VestingError::EndHeightOverflow)
        );
    }

    #[test]
    fn rejects_claimed_amount_above_vested_entitlement() {
        let s = FounderVestingSchedule::new(1_000, 5_000, 100, 10, 40).unwrap();
        assert_eq!(
            s.unclaimed_vested_entitlement_atoms(130, 501),
            Err(VestingError::ClaimedAboveVested)
        );
    }

    #[test]
    fn large_ratified_allocation_never_overflows_partial_arithmetic() {
        let s = FounderVestingSchedule::new(
            RATIFIED_FOUNDER_ALLOCATION_ATOMS,
            RATIFIED_MAX_SUPPLY_ATOMS,
            0,
            12,
            48,
        )
        .unwrap();
        assert_eq!(s.vested_entitlement_atoms(36), 30_000_000_000_000_000);
        assert_eq!(
            s.vested_entitlement_atoms(60),
            RATIFIED_FOUNDER_ALLOCATION_ATOMS
        );
        assert_eq!(
            s.unclaimed_vested_entitlement_atoms(60, RATIFIED_FOUNDER_ALLOCATION_ATOMS),
            Ok(0)
        );
    }

    #[test]
    fn configuration_is_explicit_and_does_not_assume_month_to_block_mapping() {
        let s = FounderVestingSchedule::new(1_000, 5_000, 100, 10, 40).unwrap();
        assert_eq!(s.schedule_start_height(), 100);
        assert_eq!(s.cliff_blocks(), 10);
        assert_eq!(s.linear_vesting_blocks(), 40);
        assert_eq!(s.cliff_end_height(), 110);
        assert_eq!(s.fully_vested_height(), 150);
    }
}
