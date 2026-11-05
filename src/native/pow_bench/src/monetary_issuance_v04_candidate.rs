//! CP-0397 candidate-only height-based miner issuance for allocation policy v0.4.
//!
//! This is a parameterized arithmetic contract used by the separate QZB4 v2 transition,
//! fork-choice, persistent-store and loopback-node candidate. It is not connected to the default
//! PTB2/PFS2 node runtime and does not by itself authorize a public Mainnet launch. Callers supply
//! explicit parameters; the named v0.4 launch-candidate validator below rejects schedule drift.
//!
//! Consensus-sensitive rules in this candidate:
//! - Genesis height is zero and the first reward-eligible block is height one;
//! - integer right shifts floor each halving in atom units;
//! - a reward is capped to the remaining mining allocation;
//! - no special terminal mint tops up the final rounding remainder.
//!
//! QZGM Genesis bytes remain unchanged; the versioned QZCP consensus-profile extension binds this
//! schedule fingerprint alongside the Genesis manifest, network, allocation policy and parameters.
//! QZB4 v2 execution snapshots bind the resulting profile fingerprint. The separate profile still
//! must be integrated into the default node runtime before a public Mainnet launch.

use sha2::{Digest, Sha256};

use crate::{
    issuance_schedule::{IssuanceError, IssuanceParameters},
    monetary_allocation_v04_candidate::{policy_fingerprint, AllocationBucket},
};

pub const V04_MINING_SCHEDULE_VERSION: u16 = 1;
pub const V04_FIRST_ELIGIBLE_HEIGHT: u64 = 1;
pub const V04_MINING_BUDGET_ATOMS: u128 = AllocationBucket::MiningNetworkSecurity.budget().atoms();

/// Frozen mining parameters for the v0.4 launch candidate, expressed in atomic units.
pub const QZXB_V04_INITIAL_SUBSIDY_ATOMS: u128 = 35_673_515_981;
pub const QZXB_V04_BLOCKS_PER_HALVING: u64 = 4_204_800;

const SCHEDULE_FINGERPRINT_DOMAIN: &[u8] =
    b"QUANTUMZXB-V04-MINING-SCHEDULE-FINGERPRINT-CANDIDATE-V1\0";
const SCHEDULE_RULES_TAG: &[u8] =
    b"HEIGHT-ONE-BASED;INTEGER-RIGHT-SHIFT-FLOOR;REWARD-CAPPED-TO-REMAINING-MINING-BUDGET;NO-TERMINAL-TOP-UP\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V04MiningScheduleError {
    ZeroInitialSubsidy,
    ZeroHalvingInterval,
    InvalidBlockHeight,
    MiningIssuanceAboveBudget,
    NonCanonicalLaunchParameters,
    InvalidParameters,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V04MiningIssuanceScheduleCandidate {
    initial_subsidy_atoms: u128,
    blocks_per_halving: u64,
    parameters: IssuanceParameters,
}

impl V04MiningIssuanceScheduleCandidate {
    /// Build a candidate schedule from explicit values. This API deliberately has no implicit
    /// v0.4 default: the consensus profile must choose and bind both parameters.
    pub fn new(
        initial_subsidy_atoms: u128,
        blocks_per_halving: u64,
    ) -> Result<Self, V04MiningScheduleError> {
        if initial_subsidy_atoms == 0 {
            return Err(V04MiningScheduleError::ZeroInitialSubsidy);
        }
        if blocks_per_halving == 0 {
            return Err(V04MiningScheduleError::ZeroHalvingInterval);
        }
        let parameters = IssuanceParameters::new(
            V04_MINING_BUDGET_ATOMS,
            initial_subsidy_atoms,
            blocks_per_halving,
        )
        .map_err(|error| match error {
            IssuanceError::ZeroInitialSubsidy => V04MiningScheduleError::ZeroInitialSubsidy,
            IssuanceError::ZeroHalvingInterval => V04MiningScheduleError::ZeroHalvingInterval,
            _ => V04MiningScheduleError::InvalidParameters,
        })?;
        Ok(Self {
            initial_subsidy_atoms,
            blocks_per_halving,
            parameters,
        })
    }

    /// Refuse schedule drift in the node-launch candidate while keeping the arithmetic type
    /// parameterized for independent vectors and non-launch simulations.
    pub fn validate_canonical_v04_launch_parameters(&self) -> Result<(), V04MiningScheduleError> {
        if self.initial_subsidy_atoms != QZXB_V04_INITIAL_SUBSIDY_ATOMS
            || self.blocks_per_halving != QZXB_V04_BLOCKS_PER_HALVING
        {
            return Err(V04MiningScheduleError::NonCanonicalLaunchParameters);
        }
        Ok(())
    }

    pub fn initial_subsidy_atoms(&self) -> u128 {
        self.initial_subsidy_atoms
    }

    pub fn blocks_per_halving(&self) -> u64 {
        self.blocks_per_halving
    }

    pub fn mining_budget_atoms(&self) -> u128 {
        V04_MINING_BUDGET_ATOMS
    }

    /// Derive the untruncated nominal reward for a 1-based block height.
    /// Height zero is Genesis, not a reward-eligible block.
    pub fn nominal_subsidy_at_height(
        &self,
        block_height: u64,
    ) -> Result<u128, V04MiningScheduleError> {
        if block_height < V04_FIRST_ELIGIBLE_HEIGHT {
            return Err(V04MiningScheduleError::InvalidBlockHeight);
        }
        Ok(self
            .parameters
            .nominal_subsidy_at_height(block_height - V04_FIRST_ELIGIBLE_HEIGHT))
    }

    /// Derive the permitted reward from a trusted, already-validated mining counter.
    /// Never pass peer-declared supply or use this method as a substitute for atomic ledger
    /// mutation and allocation-accounting updates.
    pub fn reward_for_height(
        &self,
        block_height: u64,
        already_mined_atoms: u128,
    ) -> Result<u128, V04MiningScheduleError> {
        if block_height < V04_FIRST_ELIGIBLE_HEIGHT {
            return Err(V04MiningScheduleError::InvalidBlockHeight);
        }
        if already_mined_atoms > V04_MINING_BUDGET_ATOMS {
            return Err(V04MiningScheduleError::MiningIssuanceAboveBudget);
        }
        self.parameters
            .reward_for_block(
                block_height - V04_FIRST_ELIGIBLE_HEIGHT,
                already_mined_atoms,
            )
            .map_err(|error| match error {
                IssuanceError::CurrentSupplyAboveMaximum => {
                    V04MiningScheduleError::MiningIssuanceAboveBudget
                }
                _ => V04MiningScheduleError::InvalidParameters,
            })
    }

    /// Maximum cumulative schedule issuance for N eligible blocks, capped at the mining bucket.
    /// This reports schedule arithmetic only and does not prove issuance on any live chain.
    pub fn cumulative_issuance_after_blocks(&self, blocks_mined: u64) -> u128 {
        self.parameters
            .cumulative_issuance_after_blocks(blocks_mined)
    }

    /// Candidate-only fingerprint for a later versioned consensus profile. It is deliberately
    /// separate from the current allocation-policy fingerprint and is not yet bound into Genesis.
    pub fn schedule_fingerprint(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(SCHEDULE_FINGERPRINT_DOMAIN);
        hash.update(V04_MINING_SCHEDULE_VERSION.to_be_bytes());
        hash.update(policy_fingerprint());
        hash.update(V04_FIRST_ELIGIBLE_HEIGHT.to_be_bytes());
        hash.update(V04_MINING_BUDGET_ATOMS.to_be_bytes());
        hash.update(self.initial_subsidy_atoms.to_be_bytes());
        hash.update(self.blocks_per_halving.to_be_bytes());
        hash.update(SCHEDULE_RULES_TAG);
        hash.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTORS: &str =
        include_str!("../../../../simulations/quantumzxb_v04_issuance_schedule_vectors.txt");

    fn vector_value(key: &str) -> &str {
        VECTORS
            .lines()
            .filter(|line| !line.starts_with('#'))
            .find_map(|line| {
                let (name, value) = line.split_once('=')?;
                (name == key).then_some(value)
            })
            .expect("required CP-0397 Python reference vector")
    }

    fn reference_schedule() -> V04MiningIssuanceScheduleCandidate {
        V04MiningIssuanceScheduleCandidate::new(
            vector_value("initial_subsidy_atoms").parse().unwrap(),
            vector_value("blocks_per_halving").parse().unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn launch_candidate_schedule_is_pinned_to_v04_tokenomics() {
        let canonical = V04MiningIssuanceScheduleCandidate::new(
            QZXB_V04_INITIAL_SUBSIDY_ATOMS,
            QZXB_V04_BLOCKS_PER_HALVING,
        )
        .unwrap();
        canonical
            .validate_canonical_v04_launch_parameters()
            .unwrap();
        assert_eq!(canonical.initial_subsidy_atoms(), 35_673_515_981);
        assert_eq!(canonical.blocks_per_halving(), 4_204_800);
        assert_eq!(canonical.reward_for_height(1, 0).unwrap(), 35_673_515_981);
        assert_eq!(
            canonical.reward_for_height(4_204_801, 0).unwrap(),
            17_836_757_990
        );

        let altered = V04MiningIssuanceScheduleCandidate::new(1_000_000, 1_000).unwrap();
        assert_eq!(
            altered.validate_canonical_v04_launch_parameters(),
            Err(V04MiningScheduleError::NonCanonicalLaunchParameters)
        );
    }

    #[test]
    fn explicit_schedule_matches_independent_python_vectors() {
        let schedule = reference_schedule();
        assert_eq!(
            schedule.mining_budget_atoms().to_string(),
            vector_value("mining_budget_atoms")
        );
        assert_eq!(
            policy_fingerprint_for_test(),
            vector_value("policy_fingerprint")
        );
        for (height, key) in [
            (1, "reward_height_1"),
            (4_204_800, "reward_height_4204800"),
            (4_204_801, "reward_height_4204801"),
            (8_409_600, "reward_height_8409600"),
            (8_409_601, "reward_height_8409601"),
            (u64::MAX, "reward_height_u64_max"),
        ] {
            assert_eq!(
                schedule.reward_for_height(height, 0).unwrap().to_string(),
                vector_value(key),
                "height {height}"
            );
        }
        assert_eq!(
            schedule
                .reward_for_height(1, V04_MINING_BUDGET_ATOMS - 1)
                .unwrap()
                .to_string(),
            vector_value("reward_with_one_atom_left")
        );
        assert_eq!(
            schedule
                .reward_for_height(1, V04_MINING_BUDGET_ATOMS)
                .unwrap()
                .to_string(),
            vector_value("reward_at_budget")
        );
        let all_nonzero_eras = schedule
            .cumulative_issuance_after_blocks(schedule.blocks_per_halving().saturating_mul(128));
        assert_eq!(
            all_nonzero_eras.to_string(),
            vector_value("cumulative_issuance_after_all_nonzero_eras_atoms")
        );
        assert_eq!(
            (V04_MINING_BUDGET_ATOMS - all_nonzero_eras).to_string(),
            vector_value("unissued_mining_budget_atoms")
        );
        assert_eq!(
            hex(&schedule.schedule_fingerprint()),
            vector_value("schedule_fingerprint")
        );
    }

    #[test]
    fn genesis_height_is_not_reward_eligible_and_boundaries_are_one_based() {
        let schedule = reference_schedule();
        assert_eq!(
            schedule.nominal_subsidy_at_height(0),
            Err(V04MiningScheduleError::InvalidBlockHeight)
        );
        assert_eq!(
            schedule.reward_for_height(0, 0),
            Err(V04MiningScheduleError::InvalidBlockHeight)
        );
        assert_eq!(
            schedule.nominal_subsidy_at_height(4_204_800).unwrap(),
            schedule.initial_subsidy_atoms()
        );
        assert_eq!(
            schedule.nominal_subsidy_at_height(4_204_801).unwrap(),
            schedule.initial_subsidy_atoms() >> 1
        );
    }

    #[test]
    fn mining_budget_is_hard_cap_and_never_gets_a_terminal_top_up() {
        let schedule = reference_schedule();
        assert_eq!(
            schedule.reward_for_height(1, V04_MINING_BUDGET_ATOMS - 1),
            Ok(1)
        );
        assert_eq!(
            schedule.reward_for_height(1, V04_MINING_BUDGET_ATOMS),
            Ok(0)
        );
        assert_eq!(
            schedule.reward_for_height(1, V04_MINING_BUDGET_ATOMS + 1),
            Err(V04MiningScheduleError::MiningIssuanceAboveBudget)
        );
        let cumulative = schedule
            .cumulative_issuance_after_blocks(schedule.blocks_per_halving().saturating_mul(128));
        assert!(cumulative < V04_MINING_BUDGET_ATOMS);
        assert_eq!(
            V04_MINING_BUDGET_ATOMS - cumulative,
            vector_value("unissued_mining_budget_atoms")
                .parse()
                .unwrap()
        );
    }

    #[test]
    fn schedule_fingerprint_binds_parameters_and_is_not_the_policy_fingerprint() {
        let schedule = reference_schedule();
        let altered = V04MiningIssuanceScheduleCandidate::new(
            schedule.initial_subsidy_atoms() + 1,
            schedule.blocks_per_halving(),
        )
        .unwrap();
        assert_ne!(
            schedule.schedule_fingerprint(),
            altered.schedule_fingerprint()
        );
        assert_ne!(
            hex(&schedule.schedule_fingerprint()),
            vector_value("policy_fingerprint")
        );
    }

    #[test]
    fn zero_schedule_parameters_fail_closed() {
        assert_eq!(
            V04MiningIssuanceScheduleCandidate::new(0, 1),
            Err(V04MiningScheduleError::ZeroInitialSubsidy)
        );
        assert_eq!(
            V04MiningIssuanceScheduleCandidate::new(1, 0),
            Err(V04MiningScheduleError::ZeroHalvingInterval)
        );
    }

    fn policy_fingerprint_for_test() -> String {
        hex(&policy_fingerprint())
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
}
