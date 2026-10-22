//! Parameterized consensus primitives for CP-W.
//!
//! This module is deliberately separate from the existing state-machine block wire format.
//! It provides deterministic PoW hashing/verification, bounded difficulty retargeting,
//! cumulative-work fork choice, and issuance wiring behind explicit parameters.
//!
//! IMPORTANT: candidate testnet values are not mainnet-frozen parameters. The module is not yet
//! wired into canonical block admission or block production; cross-client conformance is still
//! required before those rules can become consensus-critical.

use argon2::{Algorithm, Argon2, Params, Version};
use std::cmp::Ordering;

use crate::issuance_schedule::{IssuanceError, IssuanceParameters};

const POW_DOMAIN: &[u8] = b"AIN1-POW-V1\0";
const POW_SALT: &[u8] = b"AIN1-POW-SALT-V1";
const POW_OUTPUT_BYTES: usize = 32;
const ATOMS_PER_COIN: u128 = 100_000_000;
const PROVISIONAL_MAX_SUPPLY_COINS: u128 = 10_000_000_000;
// Research-only 30% miner budget over a four-year halving era; not a frozen mainnet subsidy.
const PROVISIONAL_INITIAL_SUBSIDY_ATOMS: u128 = 35_673_515_981;
const PROVISIONAL_BLOCKS_PER_HALVING: u64 = 4_204_800;
const PROVISIONAL_TARGET_BLOCK_TIME_SECS: u64 = 30;
const PROVISIONAL_DIFFICULTY_WINDOW_BLOCKS: u64 = 2_016;
const PROVISIONAL_MEMORY_KIB: u32 = 64 * 1024;
const PROVISIONAL_ARGON2_ITERATIONS: u32 = 1;
const PROVISIONAL_ARGON2_LANES: u32 = 1;

/// Unsigned 256-bit integer in big-endian limb order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Uint256([u64; 4]);

impl Uint256 {
    pub const ZERO: Self = Self([0, 0, 0, 0]);
    pub const ONE: Self = Self([0, 0, 0, 1]);
    pub const MAX: Self = Self([u64::MAX; 4]);

    pub fn from_be_bytes(bytes: [u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        for (index, limb) in limbs.iter_mut().enumerate() {
            let start = index * 8;
            *limb = u64::from_be_bytes(bytes[start..start + 8].try_into().unwrap());
        }
        Self(limbs)
    }

    pub fn to_be_bytes(self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for (index, limb) in self.0.iter().enumerate() {
            let start = index * 8;
            bytes[start..start + 8].copy_from_slice(&limb.to_be_bytes());
        }
        bytes
    }

    pub fn is_zero(self) -> bool {
        self == Self::ZERO
    }

    fn bit_msb(self, index: usize) -> bool {
        debug_assert!(index < 256);
        let limb = index / 64;
        let bit = 63 - (index % 64);
        ((self.0[limb] >> bit) & 1) == 1
    }

    fn set_bit_msb(&mut self, index: usize) {
        debug_assert!(index < 256);
        let limb = index / 64;
        let bit = 63 - (index % 64);
        self.0[limb] |= 1u64 << bit;
    }

    fn add_one(self) -> Option<Self> {
        let mut out = self.0;
        for index in (0..4).rev() {
            let (value, overflow) = out[index].overflowing_add(1);
            out[index] = value;
            if !overflow {
                return Some(Self(out));
            }
        }
        None
    }

    fn power_of_two_exponent(self) -> Option<usize> {
        if self.is_zero() {
            return None;
        }
        let mut found = None;
        for index in 0..256 {
            if self.bit_msb(index) {
                if found.is_some() {
                    return None;
                }
                found = Some(index);
            }
        }
        found.map(|index| 255usize.saturating_sub(index))
    }

    /// Exact floor(self * numerator / denominator), with saturation at 2^256-1.
    pub fn mul_div_u64(self, numerator: u64, denominator: u64) -> Result<Self, ConsensusError> {
        if denominator == 0 {
            return Err(ConsensusError::ZeroDifficultyDenominator);
        }

        let mut product = [0u64; 5];
        let mut carry = 0u128;
        for index in (0..4).rev() {
            let value = self.0[index] as u128 * numerator as u128 + carry;
            product[index + 1] = value as u64;
            carry = value >> 64;
        }
        product[0] = carry as u64;

        let mut quotient = [0u64; 5];
        let mut remainder = 0u128;
        for index in 0..5 {
            let current = (remainder << 64) | product[index] as u128;
            quotient[index] = (current / denominator as u128) as u64;
            remainder = current % denominator as u128;
        }

        if quotient[0] != 0 {
            Ok(Self::MAX)
        } else {
            Ok(Self([quotient[1], quotient[2], quotient[3], quotient[4]]))
        }
    }

    /// Exact floor(self / divisor) for a non-zero 256-bit divisor.
    ///
    /// The remainder is kept in five 64-bit limbs so the intermediate left shift is
    /// mathematically 257 bits wide and cannot silently overflow.
    pub fn div(self, divisor: Self) -> Result<Self, ConsensusError> {
        if divisor.is_zero() {
            return Err(ConsensusError::DivisionByZero);
        }

        let mut quotient = Self::ZERO;
        let mut remainder = [0u64; 5];
        let divisor_ext = [0, divisor.0[0], divisor.0[1], divisor.0[2], divisor.0[3]];

        for index in 0..256 {
            let mut carry = u64::from(self.bit_msb(index));
            for limb in (0..5).rev() {
                let value = remainder[limb];
                let next_carry = value >> 63;
                remainder[limb] = (value << 1) | carry;
                carry = next_carry;
            }

            if remainder >= divisor_ext {
                let mut borrow = 0u64;
                for limb in (0..5).rev() {
                    let (a, b1) = remainder[limb].overflowing_sub(divisor_ext[limb]);
                    let (b, b2) = a.overflowing_sub(borrow);
                    remainder[limb] = b;
                    borrow = u64::from(b1 || b2);
                }
                debug_assert_eq!(borrow, 0);
                quotient.set_bit_msb(index);
            }
        }

        Ok(quotient)
    }

    /// Add two unsigned 256-bit values, returning None rather than wrapping on overflow.
    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        let mut out = [0u64; 4];
        let mut carry = 0u64;
        for index in (0..4).rev() {
            let (first, carry_first) = self.0[index].overflowing_add(rhs.0[index]);
            let (sum, carry_second) = first.overflowing_add(carry);
            out[index] = sum;
            carry = u64::from(carry_first || carry_second);
        }
        if carry == 1 {
            None
        } else {
            Some(Self(out))
        }
    }
    pub fn saturating_add(self, rhs: Self) -> Self {
        let mut out = [0u64; 4];
        let mut carry = 0u64;
        for index in (0..4).rev() {
            let (a, c1) = self.0[index].overflowing_add(rhs.0[index]);
            let (b, c2) = a.overflowing_add(carry);
            out[index] = b;
            carry = u64::from(c1 || c2);
        }
        if carry == 1 {
            Self::MAX
        } else {
            Self(out)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowAlgorithm {
    Argon2id,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PowParameters {
    pub algorithm: PowAlgorithm,
    pub memory_kib: u32,
    pub iterations: u32,
    pub lanes: u32,
    pub output_bytes: u8,
}

impl PowParameters {
    pub fn validate(self) -> Result<(), ConsensusError> {
        if self.memory_kib < 8 {
            return Err(ConsensusError::InvalidPowMemory);
        }
        if self.iterations == 0 || self.lanes == 0 {
            return Err(ConsensusError::InvalidPowParameters);
        }
        if self.output_bytes as usize != POW_OUTPUT_BYTES {
            return Err(ConsensusError::InvalidPowParameters);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusParameters {
    pub protocol_version: u16,
    pub target_block_time_secs: u64,
    pub difficulty_window_blocks: u64,
    pub difficulty_min_ratio_divisor: u64,
    pub difficulty_max_ratio: u64,
    pub pow_limit: Uint256,
    pub initial_target: Uint256,
    pub pow: PowParameters,
    pub issuance: IssuanceParameters,
}

impl ConsensusParameters {
    /// Candidate public-testnet profile derived from the current CP-W evidence.
    /// No value here is a mainnet authorization.
    pub fn candidate_testnet() -> Result<Self, ConsensusError> {
        let mut target_bytes = [0xffu8; 32];
        target_bytes[0] = 0x00;
        target_bytes[1] = 0x7f;
        let initial_target = Uint256::from_be_bytes(target_bytes);

        let issuance = IssuanceParameters::new(
            PROVISIONAL_MAX_SUPPLY_COINS * ATOMS_PER_COIN,
            PROVISIONAL_INITIAL_SUBSIDY_ATOMS,
            PROVISIONAL_BLOCKS_PER_HALVING,
        )
        .map_err(ConsensusError::Issuance)?;

        Ok(Self {
            protocol_version: 1,
            target_block_time_secs: PROVISIONAL_TARGET_BLOCK_TIME_SECS,
            difficulty_window_blocks: PROVISIONAL_DIFFICULTY_WINDOW_BLOCKS,
            difficulty_min_ratio_divisor: 4,
            difficulty_max_ratio: 4,
            // The easiest allowed target must be above the starting target; otherwise the
            // retarget function's upper clamp prevents difficulty easing after a hashrate drop.
            pow_limit: Uint256::MAX,
            initial_target,
            pow: PowParameters {
                algorithm: PowAlgorithm::Argon2id,
                memory_kib: PROVISIONAL_MEMORY_KIB,
                iterations: PROVISIONAL_ARGON2_ITERATIONS,
                lanes: PROVISIONAL_ARGON2_LANES,
                output_bytes: POW_OUTPUT_BYTES as u8,
            },
            issuance,
        })
    }

    pub fn validate(&self) -> Result<(), ConsensusError> {
        if self.protocol_version == 0 {
            return Err(ConsensusError::InvalidProtocolVersion);
        }
        if self.target_block_time_secs == 0 {
            return Err(ConsensusError::ZeroTargetBlockTime);
        }
        if self.difficulty_window_blocks == 0 {
            return Err(ConsensusError::ZeroDifficultyWindow);
        }
        if self.difficulty_min_ratio_divisor == 0 || self.difficulty_max_ratio == 0 {
            return Err(ConsensusError::InvalidDifficultyClamp);
        }
        if self.pow_limit.is_zero() || self.initial_target.is_zero() {
            return Err(ConsensusError::InvalidTarget);
        }
        if self.initial_target > self.pow_limit {
            return Err(ConsensusError::TargetAbovePowLimit);
        }
        self.pow.validate()?;
        Ok(())
    }

    /// Fail closed when a monetary runtime profile would execute a different issuance schedule
    /// from the compile-time state-machine policy. The generic PoW/testnet model can still
    /// explore arbitrary issuance parameters, but MBK3/MBK4 runtime candidates cannot silently
    /// advertise one schedule while executing another.
    pub fn validate_monetary_execution_compatibility(&self) -> Result<(), ConsensusError> {
        self.validate()?;
        if self.issuance.maximum_supply() != crate::state_machine::MAX_TOTAL_SUPPLY_ATOMS
            || self.issuance.initial_subsidy()
                != crate::state_machine::MONETARY_INITIAL_SUBSIDY_ATOMS
            || self.issuance.blocks_per_halving()
                != crate::state_machine::MONETARY_BLOCKS_PER_HALVING
        {
            return Err(ConsensusError::MonetaryIssuanceProfileMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PowHeader {
    pub protocol_version: u16,
    pub network_id: [u8; 32],
    pub height: u64,
    pub timestamp: u64,
    /// Canonical BLK2/body parent hash.
    pub parent_hash: [u8; 32],
    /// Previous PoW consensus-tip digest (genesis starts from the genesis state tip).
    /// This is separate from parent_hash, which binds the body/state chain.
    pub previous_consensus_hash: [u8; 32],
    pub state_root: [u8; 32],
    pub target: Uint256,
    pub nonce: u64,
}

impl PowHeader {
    fn canonical_bytes(&self) -> Result<Vec<u8>, ConsensusError> {
        if self.network_id.iter().all(|byte| *byte == 0) {
            return Err(ConsensusError::InvalidNetworkId);
        }
        if self.protocol_version == 0 {
            return Err(ConsensusError::InvalidProtocolVersion);
        }
        let mut bytes = Vec::with_capacity(4 + 2 + 32 + 8 + 8 + 32 + 32 + 32 + 32 + 8);
        bytes.extend_from_slice(POW_DOMAIN);
        bytes.extend_from_slice(&self.protocol_version.to_be_bytes());
        bytes.extend_from_slice(&self.network_id);
        bytes.extend_from_slice(&self.height.to_be_bytes());
        bytes.extend_from_slice(&self.timestamp.to_be_bytes());
        bytes.extend_from_slice(&self.parent_hash);
        bytes.extend_from_slice(&self.previous_consensus_hash);
        bytes.extend_from_slice(&self.state_root);
        bytes.extend_from_slice(&self.target.to_be_bytes());
        bytes.extend_from_slice(&self.nonce.to_be_bytes());
        Ok(bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsensusError {
    InvalidProtocolVersion,
    InvalidNetworkId,
    InvalidTarget,
    InvalidBlockHeight,
    TargetAbovePowLimit,
    InvalidPowMemory,
    InvalidPowParameters,
    InvalidDifficultyClamp,
    ZeroTargetBlockTime,
    ZeroDifficultyWindow,
    InvalidNextBlockHeight,
    MissingRetargetObservation,
    ZeroDifficultyDenominator,
    DifficultyOverflow,
    ChainworkOverflow,
    DivisionByZero,
    PowHashFailed,
    UnsupportedPowAlgorithm,
    Issuance(IssuanceError),
    MonetaryIssuanceProfileMismatch,
}

impl std::fmt::Display for ConsensusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidProtocolVersion => write!(f, "protocol version must be non-zero"),
            Self::InvalidNetworkId => write!(f, "network ID must be non-zero"),
            Self::InvalidTarget => write!(f, "target must be non-zero"),
            Self::InvalidBlockHeight => write!(f, "native block height must be positive"),
            Self::TargetAbovePowLimit => write!(f, "target exceeds the configured PoW limit"),
            Self::InvalidPowMemory => write!(f, "PoW memory parameter is below the minimum"),
            Self::InvalidPowParameters => write!(f, "PoW parameters are invalid"),
            Self::InvalidDifficultyClamp => write!(f, "difficulty clamp parameters are invalid"),
            Self::ZeroTargetBlockTime => write!(f, "target block time must be positive"),
            Self::ZeroDifficultyWindow => write!(f, "difficulty window must be positive"),
            Self::InvalidNextBlockHeight => write!(f, "next block height must be positive"),
            Self::MissingRetargetObservation => {
                write!(f, "retarget boundary requires a measured window duration")
            }
            Self::ZeroDifficultyDenominator => write!(f, "difficulty denominator must be positive"),
            Self::DifficultyOverflow => write!(f, "difficulty timing arithmetic overflowed"),
            Self::ChainworkOverflow => write!(f, "cumulative chain work exceeds the 256-bit range"),
            Self::DivisionByZero => write!(f, "division by zero"),
            Self::PowHashFailed => write!(f, "PoW hashing failed"),
            Self::UnsupportedPowAlgorithm => write!(f, "unsupported PoW algorithm"),
            Self::Issuance(error) => write!(f, "issuance parameters invalid: {error}"),
            Self::MonetaryIssuanceProfileMismatch => write!(
                f,
                "monetary runtime issuance profile does not match the state-machine candidate policy"
            ),
        }
    }
}

impl std::error::Error for ConsensusError {}

/// Hash a complete candidate block header with the selected memory-hard PoW construction.
pub fn pow_digest(header: &PowHeader, pow: PowParameters) -> Result<[u8; 32], ConsensusError> {
    pow.validate()?;
    let preimage = header.canonical_bytes()?;

    match pow.algorithm {
        PowAlgorithm::Argon2id => {
            let params = Params::new(
                pow.memory_kib,
                pow.iterations,
                pow.lanes,
                Some(pow.output_bytes as usize),
            )
            .map_err(|_| ConsensusError::InvalidPowParameters)?;
            let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            let mut output = [0u8; 32];
            argon
                .hash_password_into(&preimage, POW_SALT, &mut output)
                .map_err(|_| ConsensusError::PowHashFailed)?;
            Ok(output)
        }
    }
}

/// Verify a proof using a target encoded as an unsigned 256-bit integer.
pub fn verify_pow(
    header: &PowHeader,
    params: &ConsensusParameters,
) -> Result<[u8; 32], ConsensusError> {
    params.validate()?;
    if header.target.is_zero() {
        return Err(ConsensusError::InvalidTarget);
    }
    if header.target > params.pow_limit {
        return Err(ConsensusError::TargetAbovePowLimit);
    }
    if header.protocol_version != params.protocol_version {
        return Err(ConsensusError::InvalidProtocolVersion);
    }

    let digest = pow_digest(header, params.pow)?;
    let value = Uint256::from_be_bytes(digest);
    if value <= header.target {
        Ok(digest)
    } else {
        Err(ConsensusError::PowHashFailed)
    }
}

/// Compute the next target from an observed epoch duration.
/// The adjustment ratio is clamped to [1/divisor, max_ratio] to avoid abrupt jumps.
pub fn retarget_target(
    previous_target: Uint256,
    actual_elapsed_secs: u64,
    params: &ConsensusParameters,
) -> Result<Uint256, ConsensusError> {
    params.validate()?;
    if previous_target.is_zero() {
        return Err(ConsensusError::InvalidTarget);
    }
    if previous_target > params.pow_limit {
        return Err(ConsensusError::TargetAbovePowLimit);
    }

    let expected = params
        .target_block_time_secs
        .checked_mul(params.difficulty_window_blocks)
        .ok_or(ConsensusError::DifficultyOverflow)?;
    if expected == 0 {
        return Err(ConsensusError::DifficultyOverflow);
    }

    let minimum = (expected / params.difficulty_min_ratio_divisor).max(1);
    let maximum = expected
        .checked_mul(params.difficulty_max_ratio)
        .ok_or(ConsensusError::DifficultyOverflow)?;
    let bounded_actual = actual_elapsed_secs.clamp(minimum, maximum);

    let adjusted = previous_target.mul_div_u64(bounded_actual, expected)?;
    Ok(adjusted.min(params.pow_limit))
}

/// Expected subsidy for a 1-based native block height and validated pre-block total supply.
///
/// The shared schedule indexes its first era at height 0, while native blocks begin at height 1
/// after Genesis. Convert exactly once here so halving boundaries align with MonetaryLedgerState.
pub fn expected_block_subsidy(
    block_height: u64,
    current_supply_atoms: u128,
    params: &ConsensusParameters,
) -> Result<u128, ConsensusError> {
    params.validate()?;
    let schedule_height = block_height
        .checked_sub(1)
        .ok_or(ConsensusError::InvalidBlockHeight)?;
    params
        .issuance
        .reward_for_block(schedule_height, current_supply_atoms)
        .map_err(ConsensusError::Issuance)
}

/// Exact per-block chain work approximation defined by floor(2^256 / (target + 1)).
pub fn block_work(target: Uint256) -> Result<Uint256, ConsensusError> {
    if target.is_zero() {
        return Err(ConsensusError::InvalidTarget);
    }
    if target == Uint256::MAX {
        return Ok(Uint256::ONE);
    }
    let divisor = target.add_one().ok_or(ConsensusError::InvalidTarget)?;
    if let Some(exponent) = divisor.power_of_two_exponent() {
        // divisor = 2^k, so 2^256 / divisor = 2^(256-k). For k=256 the result is 1.
        if exponent == 0 {
            return Ok(Uint256::ONE);
        }
        let mut work = Uint256::ZERO;
        work.set_bit_msb(exponent - 1);
        return Ok(work);
    }
    // For non-powers of two, floor((2^256 - 1)/d) == floor(2^256/d).
    Uint256::MAX.div(divisor)
}

pub fn cumulative_chain_work(targets: &[Uint256]) -> Result<Uint256, ConsensusError> {
    let mut total = Uint256::ZERO;
    for target in targets {
        total = total
            .checked_add(block_work(*target)?)
            .ok_or(ConsensusError::ChainworkOverflow)?;
    }
    Ok(total)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainTip {
    pub height: u64,
    pub cumulative_work: Uint256,
    pub tip_hash: [u8; 32],
}

/// Heavier cumulative work wins; height then lexicographically smaller tip hash break an exact tie.
pub fn compare_chain_tips(left: ChainTip, right: ChainTip) -> Ordering {
    match left.cumulative_work.cmp(&right.cumulative_work) {
        Ordering::Equal => match left.height.cmp(&right.height) {
            Ordering::Equal => right.tip_hash.cmp(&left.tip_hash),
            ordering => ordering,
        },
        ordering => ordering,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_header(target: Uint256, nonce: u64) -> PowHeader {
        PowHeader {
            protocol_version: 1,
            network_id: [0xA1; 32],
            height: 1,
            timestamp: 100,
            parent_hash: [0xB2; 32],
            previous_consensus_hash: [0xD4; 32],
            state_root: [0xC3; 32],
            target,
            nonce,
        }
    }

    #[test]
    fn uint256_checked_add_reports_overflow_without_wrapping() {
        assert_eq!(Uint256::ZERO.checked_add(Uint256::ONE), Some(Uint256::ONE));
        assert_eq!(Uint256::MAX.checked_add(Uint256::ZERO), Some(Uint256::MAX));
        assert_eq!(Uint256::MAX.checked_add(Uint256::ONE), None);

        let mut low_limb_max = [0u8; 32];
        low_limb_max[24..].fill(0xff);
        let mut carried_value = [0u8; 32];
        carried_value[23] = 1;
        assert_eq!(
            Uint256::from_be_bytes(low_limb_max).checked_add(Uint256::ONE),
            Some(Uint256::from_be_bytes(carried_value))
        );
    }
    #[test]
    fn uint256_roundtrip_and_division_are_exact() {
        let value = Uint256::from_be_bytes([0x12; 32]);
        assert_eq!(value.to_be_bytes(), [0x12; 32]);
        assert_eq!(Uint256::MAX.div(Uint256::MAX).unwrap(), Uint256::ONE);
        assert_eq!(
            Uint256::from_be_bytes({
                let mut bytes = [0u8; 32];
                bytes[31] = 100;
                bytes
            })
            .div(Uint256::from_be_bytes({
                let mut bytes = [0u8; 32];
                bytes[31] = 4;
                bytes
            }))
            .unwrap()
            .to_be_bytes()[31],
            25
        );

        let mut high = [0u8; 32];
        high[0] = 0x80;
        let mut divisor = [0u8; 32];
        divisor[0] = 0x80;
        assert_eq!(
            Uint256::from_be_bytes(high)
                .div(Uint256::from_be_bytes(divisor))
                .unwrap(),
            Uint256::ONE
        );
    }

    #[test]
    fn candidate_testnet_parameters_validate() {
        let params = ConsensusParameters::candidate_testnet().unwrap();
        params.validate().unwrap();
        assert_eq!(params.protocol_version, 1);
        assert_eq!(params.target_block_time_secs, 30);
        assert_eq!(params.difficulty_window_blocks, 2_016);
        assert_eq!(params.pow_limit, Uint256::MAX);
        assert!(params.initial_target < params.pow_limit);
        assert_eq!(params.pow.memory_kib, 64 * 1024);
        assert_eq!(params.pow.iterations, 1);
        assert_eq!(params.pow.lanes, 1);
        assert_eq!(params.issuance.maximum_supply(), 1_000_000_000_000_000_000);
        assert_eq!(params.issuance.initial_subsidy(), 35_673_515_981);
        assert_eq!(params.issuance.blocks_per_halving(), 4_204_800);
    }

    #[test]
    fn monetary_runtime_rejects_issuance_parameters_that_state_machine_would_ignore() {
        let baseline = ConsensusParameters::candidate_testnet().unwrap();
        baseline
            .validate_monetary_execution_compatibility()
            .unwrap();

        let wrong_total_cap = IssuanceParameters::new(
            baseline.issuance.maximum_supply() - 1,
            baseline.issuance.initial_subsidy(),
            baseline.issuance.blocks_per_halving(),
        )
        .unwrap();
        let wrong_subsidy = IssuanceParameters::new(
            baseline.issuance.maximum_supply(),
            baseline.issuance.initial_subsidy() + 1,
            baseline.issuance.blocks_per_halving(),
        )
        .unwrap();
        let wrong_halving = IssuanceParameters::new(
            baseline.issuance.maximum_supply(),
            baseline.issuance.initial_subsidy(),
            baseline.issuance.blocks_per_halving() + 1,
        )
        .unwrap();

        for issuance in [wrong_total_cap, wrong_subsidy, wrong_halving] {
            let mut incompatible = baseline.clone();
            incompatible.issuance = issuance;
            // The generic PoW research model remains parameterizable; the monetary execution
            // path must reject a profile whose economics are not actually wired into the state.
            incompatible.validate().unwrap();
            assert_eq!(
                incompatible.validate_monetary_execution_compatibility(),
                Err(ConsensusError::MonetaryIssuanceProfileMismatch)
            );
        }
    }

    #[test]
    fn maximum_target_accepts_any_digest_but_zero_target_fails_closed() {
        let mut params = ConsensusParameters::candidate_testnet().unwrap();
        params.pow_limit = Uint256::MAX;
        let header = test_header(Uint256::MAX, 7);
        assert!(verify_pow(&header, &params).is_ok());

        let zero_header = test_header(Uint256::ZERO, 7);
        assert_eq!(
            verify_pow(&zero_header, &params),
            Err(ConsensusError::InvalidTarget)
        );
    }

    #[test]
    fn pow_digest_changes_when_nonce_changes() {
        let params = ConsensusParameters::candidate_testnet().unwrap();
        let left = pow_digest(&test_header(params.initial_target, 0), params.pow).unwrap();
        let right = pow_digest(&test_header(params.initial_target, 1), params.pow).unwrap();
        assert_ne!(left, right);
    }

    #[test]
    fn pow_digest_commits_to_the_previous_consensus_header() {
        let params = ConsensusParameters::candidate_testnet().unwrap();
        let header = test_header(params.initial_target, 7);
        let original = pow_digest(&header, params.pow).unwrap();
        let mut detached = header;
        detached.previous_consensus_hash[0] ^= 1;
        let changed = pow_digest(&detached, params.pow).unwrap();
        assert_ne!(original, changed);
    }

    #[test]
    fn pow_golden_vector_is_stable_for_external_reimplementation() {
        let params = ConsensusParameters::candidate_testnet().unwrap();
        let digest = pow_digest(&test_header(params.initial_target, 0), params.pow).unwrap();
        assert_eq!(
            digest,
            [
                0xff, 0x1e, 0xc6, 0x46, 0x1f, 0x9d, 0x27, 0x89, 0x9a, 0x9e, 0xd9, 0xd0, 0xa6, 0x91,
                0xd3, 0x65, 0x1f, 0x1f, 0x41, 0x7e, 0x5e, 0xc3, 0x50, 0xa8, 0xa3, 0xe6, 0x80, 0x3b,
                0x73, 0xe7, 0x8c, 0x41,
            ]
        );
        assert!(Uint256::from_be_bytes(digest) > params.initial_target);
    }

    #[test]
    fn retarget_scales_and_clamps_deterministically() {
        let params = ConsensusParameters::candidate_testnet().unwrap();
        let previous = Uint256::from_be_bytes({
            let mut bytes = [0u8; 32];
            bytes[31] = 100;
            bytes
        });

        let expected = 30 * 2_016;
        assert_eq!(
            retarget_target(previous, expected / 2, &params)
                .unwrap()
                .to_be_bytes()[31],
            50
        );
        assert_eq!(
            retarget_target(previous, expected / 100, &params)
                .unwrap()
                .to_be_bytes()[31],
            25
        );
        let bounded_high = retarget_target(previous, expected * 100, &params)
            .unwrap()
            .to_be_bytes();
        assert_eq!(
            u16::from_be_bytes([bounded_high[30], bounded_high[31]]),
            400
        );
    }

    #[test]
    fn candidate_profile_can_ease_difficulty_after_a_hashrate_drop() {
        let params = ConsensusParameters::candidate_testnet().unwrap();
        let expected = params.target_block_time_secs * params.difficulty_window_blocks;
        let easier = retarget_target(params.initial_target, expected * 2, &params).unwrap();
        assert_eq!(easier, params.initial_target.mul_div_u64(2, 1).unwrap());
        assert!(easier > params.initial_target);
        assert!(easier <= params.pow_limit);
    }

    #[test]
    fn retarget_recovers_after_a_ninety_percent_hashrate_drop_with_bounded_windows() {
        let params = ConsensusParameters::candidate_testnet().unwrap();
        let expected = params.target_block_time_secs * params.difficulty_window_blocks;
        let initial = params.initial_target;

        // Constant 10% hash rate means a 10x longer first window. The existing 4x clamp
        // lowers difficulty by at most 4x on the first retarget; a second window observes
        // the residual 2.5x lag. Restore full hash rate and verify bounded adjustments return
        // the target to within one atomic target unit after two more retargets.
        let after_drop_1 = retarget_target(initial, expected * 10, &params).unwrap();
        assert_eq!(after_drop_1, initial.mul_div_u64(4, 1).unwrap());

        let after_drop_2 = retarget_target(after_drop_1, expected * 5 / 2, &params).unwrap();
        assert_eq!(after_drop_2, initial.mul_div_u64(10, 1).unwrap());

        let after_restore_1 = retarget_target(after_drop_2, expected / 10, &params).unwrap();
        assert_eq!(after_restore_1, initial.mul_div_u64(5, 2).unwrap());

        let after_restore_2 = retarget_target(after_restore_1, expected * 2 / 5, &params).unwrap();
        let start = initial.to_be_bytes();
        let end = after_restore_2.to_be_bytes();
        assert_eq!(&end[..31], &start[..31]);
        assert!(end[31] <= start[31]);
        assert!(start[31] - end[31] <= 1);
    }

    #[test]
    fn retarget_eases_a_ninety_nine_percent_hashrate_drop_within_four_windows() {
        let params = ConsensusParameters::candidate_testnet().unwrap();
        let expected = params.target_block_time_secs * params.difficulty_window_blocks;
        let initial = params.initial_target;

        // Idealized constant 1% hash rate: observed windows are 100x, 25x, 6.25x,
        // then 1.5625x nominal, given the preceding target multipliers. The 4x clamp
        // therefore needs four complete windows to restore the nominal interval.
        let r1 = retarget_target(initial, expected * 100, &params).unwrap();
        assert_eq!(r1, initial.mul_div_u64(4, 1).unwrap());
        let r2 = retarget_target(r1, expected * 25, &params).unwrap();
        assert_eq!(r2, initial.mul_div_u64(16, 1).unwrap());
        let r3 = retarget_target(r2, expected * 25 / 4, &params).unwrap();
        assert_eq!(r3, initial.mul_div_u64(64, 1).unwrap());
        let r4 = retarget_target(r3, expected * 25 / 16, &params).unwrap();
        assert_eq!(r4, initial.mul_div_u64(100, 1).unwrap());
        assert!(r4 < params.pow_limit);
    }

    #[test]
    fn retarget_respects_pow_limit() {
        let params = ConsensusParameters::candidate_testnet().unwrap();
        let expected = params.target_block_time_secs * params.difficulty_window_blocks;
        assert_eq!(
            retarget_target(params.pow_limit, expected * 100, &params).unwrap(),
            params.pow_limit
        );
    }

    #[test]
    fn block_work_prefers_lower_targets_and_chain_work_accumulates() {
        let hard = Uint256::from_be_bytes({
            let mut bytes = [0u8; 32];
            bytes[31] = 10;
            bytes
        });
        let easy = Uint256::from_be_bytes({
            let mut bytes = [0u8; 32];
            bytes[31] = 100;
            bytes
        });
        assert!(block_work(hard).unwrap() > block_work(easy).unwrap());
        assert_eq!(
            block_work(Uint256::from_be_bytes({
                let mut bytes = [0u8; 32];
                bytes[31] = 3;
                bytes
            }))
            .unwrap()
            .to_be_bytes()[0],
            0x40
        );
        assert_eq!(
            block_work(Uint256::ZERO),
            Err(ConsensusError::InvalidTarget)
        );
        assert_eq!(block_work(Uint256::MAX).unwrap(), Uint256::ONE);
        let total = cumulative_chain_work(&[hard, hard, easy]).unwrap();
        assert_eq!(
            total,
            block_work(hard)
                .unwrap()
                .checked_add(block_work(hard).unwrap())
                .unwrap()
                .checked_add(block_work(easy).unwrap())
                .unwrap()
        );
    }

    #[test]
    fn cumulative_chain_work_rejects_overflow_instead_of_saturating() {
        assert_eq!(
            cumulative_chain_work(&[Uint256::ONE, Uint256::ONE]),
            Err(ConsensusError::ChainworkOverflow)
        );
        assert_eq!(cumulative_chain_work(&[Uint256::MAX]), Ok(Uint256::ONE));
    }
    #[test]
    fn fork_choice_has_deterministic_work_height_and_hash_ties() {
        let low_hash = ChainTip {
            height: 10,
            cumulative_work: Uint256::from_be_bytes({
                let mut bytes = [0u8; 32];
                bytes[31] = 20;
                bytes
            }),
            tip_hash: [0x01; 32],
        };
        let high_hash = ChainTip {
            tip_hash: [0x02; 32],
            ..low_hash
        };
        assert_eq!(compare_chain_tips(low_hash, high_hash), Ordering::Greater);

        let more_work = ChainTip {
            cumulative_work: Uint256::from_be_bytes({
                let mut bytes = [0u8; 32];
                bytes[31] = 21;
                bytes
            }),
            ..high_hash
        };
        assert_eq!(compare_chain_tips(more_work, low_hash), Ordering::Greater);
    }

    #[test]
    fn issuance_is_wired_to_one_based_native_heights_and_exact_halving_boundaries() {
        let params = ConsensusParameters::candidate_testnet().unwrap();
        let genesis_supply = crate::state_machine::MONETARY_FOUNDER_ALLOCATION_ATOMS
            + crate::state_machine::MONETARY_PUBLIC_GOODS_BUDGET_ATOMS;
        let initial = crate::state_machine::MONETARY_INITIAL_SUBSIDY_ATOMS;
        let halving = crate::state_machine::MONETARY_BLOCKS_PER_HALVING;

        // Height 1 is the first block after Genesis. Height H still belongs to era 0;
        // the first halved reward belongs to height H+1.
        assert_eq!(
            expected_block_subsidy(1, genesis_supply, &params),
            Ok(initial)
        );
        let supply_before_last_full_reward = genesis_supply + initial * (halving as u128 - 1);
        assert_eq!(
            expected_block_subsidy(halving, supply_before_last_full_reward, &params),
            Ok(initial)
        );
        let supply_after_first_era = genesis_supply + initial * halving as u128;
        assert_eq!(
            expected_block_subsidy(halving + 1, supply_after_first_era, &params),
            Ok(initial / 2)
        );
        assert_eq!(
            expected_block_subsidy(1, params.issuance.maximum_supply(), &params),
            Ok(0)
        );
        assert_eq!(
            expected_block_subsidy(0, genesis_supply, &params),
            Err(ConsensusError::InvalidBlockHeight)
        );
    }

    #[test]
    fn provisional_issuance_schedule_fits_miner_budget_and_total_allocation() {
        // Test-only budget arithmetic from the current 40/30/30 research proposal. These are
        // not Genesis balances, canonical consensus parameters, or an issuance activation decision.
        const MAX_SUPPLY_ATOMS: u128 = 1_000_000_000_000_000_000;
        const FOUNDER_ALLOCATION_ATOMS: u128 = 400_000_000_000_000_000;
        const MINER_BUDGET_ATOMS: u128 = 300_000_000_000_000_000;
        const PUBLIC_GOODS_BUDGET_ATOMS: u128 = 300_000_000_000_000_000;

        let params = ConsensusParameters::candidate_testnet().unwrap();
        let mined = params.issuance.cumulative_issuance_after_blocks(u64::MAX);

        assert_eq!(params.issuance.maximum_supply(), MAX_SUPPLY_ATOMS);
        assert_eq!(mined, 299_999_999_913_926_400);
        assert!(mined <= MINER_BUDGET_ATOMS);
        assert_eq!(
            FOUNDER_ALLOCATION_ATOMS + MINER_BUDGET_ATOMS + PUBLIC_GOODS_BUDGET_ATOMS,
            MAX_SUPPLY_ATOMS
        );
        assert!(
            FOUNDER_ALLOCATION_ATOMS + mined + PUBLIC_GOODS_BUDGET_ATOMS <= MAX_SUPPLY_ATOMS,
            "provisional founder plus actual miner emission plus public-goods budget must fit the hard cap"
        );

        println!(
            "CP0208_PROVISIONAL_ISSUANCE_FIXTURE={}:{}:{}:{}:{}:{}:{}",
            params.issuance.maximum_supply(),
            params.issuance.initial_subsidy(),
            params.issuance.blocks_per_halving(),
            FOUNDER_ALLOCATION_ATOMS,
            MINER_BUDGET_ATOMS,
            PUBLIC_GOODS_BUDGET_ATOMS,
            mined
        );
    }
}
