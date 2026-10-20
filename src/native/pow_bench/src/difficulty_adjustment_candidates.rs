//! Research-only ASERT-style target adjustment candidate.
//!
//! The compact-target helper applies the integer-only Q16 formula and compact nBits semantics from
//! the public aserti3-2d specification. It is tested against all 14,000 rows in upstream's 12
//! official test-vector files. The raw-Uint256 helper remains available for edge-case tests.
//! No caller in canonical block admission/production uses this module; MTP/anchor selection,
//! timestamp policy, cross-client integration and launch authorization remain separate gates.

use crate::consensus::Uint256;

const Q16: i128 = 1 << 16;
const ASERT_MIN_FACTOR_Q16: u64 = 1 << 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsertCandidateError {
    InvalidTarget,
    AnchorTargetAbovePowLimit,
    InvalidCompactBits,
    InvalidHeightDelta,
    ZeroTargetSpacing,
    ZeroHalfLife,
    ArithmeticOverflow,
}

fn target_to_limbs(target: Uint256) -> [u64; 4] {
    let bytes = target.to_be_bytes();
    let mut limbs = [0u64; 4];
    for (index, limb) in limbs.iter_mut().enumerate() {
        let start = index * 8;
        *limb = u64::from_be_bytes(bytes[start..start + 8].try_into().unwrap());
    }
    limbs
}

fn wide_from_target_factor(target: Uint256, factor: u64) -> [u64; 5] {
    let limbs = target_to_limbs(target);
    let mut wide = [0u64; 5];
    let mut carry = 0u128;
    for index in (0..4).rev() {
        let product = limbs[index] as u128 * factor as u128 + carry;
        wide[index + 1] = product as u64;
        carry = product >> 64;
    }
    wide[0] = carry as u64;
    wide
}

fn wide_shift_left(mut value: [u64; 5], bits: u32) -> Option<[u64; 5]> {
    for _ in 0..bits {
        let mut carry = 0u64;
        for index in (0..5).rev() {
            let next_carry = value[index] >> 63;
            value[index] = (value[index] << 1) | carry;
            carry = next_carry;
        }
        if carry != 0 {
            return None;
        }
    }
    Some(value)
}

fn wide_shift_right(mut value: [u64; 5], bits: u32) -> [u64; 5] {
    if bits >= 320 {
        return [0; 5];
    }
    for _ in 0..bits {
        let mut carry = 0u64;
        for limb in value.iter_mut() {
            let next_carry = *limb & 1;
            *limb = (*limb >> 1) | (carry << 63);
            carry = next_carry;
        }
    }
    value
}

fn wide_to_target(value: [u64; 5]) -> Option<Uint256> {
    if value[0] != 0 {
        return None;
    }
    let mut bytes = [0u8; 32];
    for index in 0..4 {
        let start = index * 8;
        bytes[start..start + 8].copy_from_slice(&value[index + 1].to_be_bytes());
    }
    Some(Uint256::from_be_bytes(bytes))
}

/// Calculate the next target using an ASERT-style anchor formula.
///
/// height_delta is current/evaluation height minus anchor height. time_delta is the signed
/// number of seconds from the anchor-parent timestamp to the evaluation-block timestamp.
/// Unlike upstream aserti3-2d, the output target is not converted to/from compact nBits.
pub fn asert_target_candidate(
    anchor_target: Uint256,
    height_delta: u64,
    time_delta: i128,
    target_block_time_secs: u64,
    half_life_secs: u64,
    pow_limit: Uint256,
) -> Result<Uint256, AsertCandidateError> {
    if anchor_target.is_zero() || pow_limit.is_zero() {
        return Err(AsertCandidateError::InvalidTarget);
    }
    if anchor_target > pow_limit {
        return Err(AsertCandidateError::AnchorTargetAbovePowLimit);
    }
    if target_block_time_secs == 0 {
        return Err(AsertCandidateError::ZeroTargetSpacing);
    }
    if half_life_secs == 0 {
        return Err(AsertCandidateError::ZeroHalfLife);
    }

    let expected = (target_block_time_secs as i128)
        .checked_mul(
            (height_delta as i128)
                .checked_add(1)
                .ok_or(AsertCandidateError::ArithmeticOverflow)?,
        )
        .ok_or(AsertCandidateError::ArithmeticOverflow)?;
    let time_error = time_delta
        .checked_sub(expected)
        .ok_or(AsertCandidateError::ArithmeticOverflow)?;
    let numerator = time_error
        .checked_mul(Q16)
        .ok_or(AsertCandidateError::ArithmeticOverflow)?;
    let exponent_q16 = numerator / half_life_secs as i128;
    let num_shifts = exponent_q16 >> 16;
    let fraction = exponent_q16 - num_shifts * Q16;
    debug_assert!((0..Q16).contains(&fraction));

    // Published ASERT cubic approximation to 2^fraction (Q16 fixed point). Use u128 because
    // the polynomial intentionally exceeds signed 64-bit range for the highest fractional bits.
    let f = fraction as u128;
    let polynomial = 195_766_423_245_049u128 * f
        + 971_821_376u128 * f * f
        + 5_127u128 * f * f * f
        + (1u128 << 47);
    let factor = ((polynomial >> 48) + ASERT_MIN_FACTOR_Q16 as u128) as u64;

    let mut wide = wide_from_target_factor(anchor_target, factor);
    if num_shifts < 0 {
        // P >> (-num_shifts) >> 16 == P >> (16 - num_shifts).
        // Very large negative exponents yield zero, which ASERT clamps to target 1.
        if num_shifts <= -304 {
            return Ok(Uint256::ONE.min(pow_limit));
        }
        let right_bits = (16 - num_shifts) as u32;
        wide = wide_shift_right(wide, right_bits);
    } else if num_shifts >= 16 {
        // P << num_shifts >> 16 == P << (num_shifts - 16).
        if num_shifts >= 256 {
            return Ok(pow_limit);
        }
        wide = match wide_shift_left(wide, (num_shifts - 16) as u32) {
            Some(value) => value,
            None => return Ok(pow_limit),
        };
    } else {
        wide = wide_shift_left(wide, num_shifts as u32)
            .ok_or(AsertCandidateError::ArithmeticOverflow)?;
        wide = wide_shift_right(wide, 16);
    }

    let candidate = match wide_to_target(wide) {
        Some(value) if !value.is_zero() => value,
        Some(_) => Uint256::ONE,
        None => return Ok(pow_limit),
    };
    Ok(candidate.min(pow_limit))
}

/// Decode a Bitcoin-style compact target (nBits) into a raw Uint256 target.
pub fn compact_bits_to_target(bits: u32) -> Result<Uint256, AsertCandidateError> {
    let size = (bits >> 24) as usize;
    let mut word = bits & 0x007f_ffff;
    if bits & 0x0080_0000 != 0 && word != 0 {
        return Err(AsertCandidateError::InvalidCompactBits);
    }
    if word == 0 {
        return Err(AsertCandidateError::InvalidTarget);
    }

    if size <= 3 {
        word >>= 8 * (3 - size);
        if word == 0 {
            return Err(AsertCandidateError::InvalidTarget);
        }
        let mut bytes = [0u8; 32];
        bytes[28..].copy_from_slice(&word.to_be_bytes());
        return Ok(Uint256::from_be_bytes(bytes));
    }

    let shift_bytes = size - 3;
    let word_bits = (u32::BITS - word.leading_zeros()) as usize;
    if word_bits + shift_bytes * 8 > 256 {
        return Err(AsertCandidateError::InvalidCompactBits);
    }
    let word_len = (word_bits + 7) / 8;
    let total_len = word_len + shift_bytes;
    if total_len > 32 {
        return Err(AsertCandidateError::InvalidCompactBits);
    }
    let start = 32 - total_len;
    let word_bytes = word.to_be_bytes();
    let word_start = 4 - word_len;
    let mut bytes = [0u8; 32];
    bytes[start..start + word_len].copy_from_slice(&word_bytes[word_start..]);
    Ok(Uint256::from_be_bytes(bytes))
}

/// Encode a raw Uint256 target to its canonical compact nBits representation.
pub fn target_to_compact_bits(target: Uint256) -> u32 {
    if target.is_zero() {
        return 0;
    }
    let bytes = target.to_be_bytes();
    let first_nonzero = bytes.iter().position(|byte| *byte != 0).unwrap();
    let mut size = 32 - first_nonzero;
    let mut compact_word: u32;
    if size <= 3 {
        let mut value = 0u32;
        for byte in &bytes[first_nonzero..] {
            value = (value << 8) | *byte as u32;
        }
        compact_word = value << (8 * (3 - size));
    } else {
        compact_word = ((bytes[first_nonzero] as u32) << 16)
            | ((bytes[first_nonzero + 1] as u32) << 8)
            | bytes[first_nonzero + 2] as u32;
    }
    if compact_word & 0x0080_0000 != 0 {
        compact_word >>= 8;
        size += 1;
    }
    ((size as u32) << 24) | (compact_word & 0x007f_ffff)
}

/// Upstream-shaped aserti3-2d target calculation from compact anchor bits.
///
/// This uses the same integer-only Q16 cubic and compact target semantics as the public spec. It
/// is still exposed only for research/testing; activation, MTP anchor selection and consensus
/// call-site integration are deliberately absent.
pub fn asert_next_compact_bits_candidate(
    anchor_height: u64,
    anchor_parent_time: i128,
    anchor_bits: u32,
    evaluation_height: u64,
    evaluation_time: i128,
    target_block_time_secs: u64,
    half_life_secs: u64,
    max_bits: u32,
) -> Result<u32, AsertCandidateError> {
    if anchor_height == 0 || evaluation_height < anchor_height {
        return Err(AsertCandidateError::InvalidHeightDelta);
    }
    let anchor_target = compact_bits_to_target(anchor_bits)?;
    let pow_limit = compact_bits_to_target(max_bits)?;
    let time_delta = evaluation_time
        .checked_sub(anchor_parent_time)
        .ok_or(AsertCandidateError::ArithmeticOverflow)?;
    let target = asert_target_candidate(
        anchor_target,
        evaluation_height - anchor_height,
        time_delta,
        target_block_time_secs,
        half_life_secs,
        pow_limit,
    )?;
    Ok(target_to_compact_bits(target))
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTORS: &str = include_str!("../../../../simulations/cp0115_k_asert_fixed_vectors.txt");
    const ASERT_UPSTREAM_RUNS: [&str; 12] = [
        include_str!("../../../../simulations/asert_upstream_vectors/run01"),
        include_str!("../../../../simulations/asert_upstream_vectors/run02"),
        include_str!("../../../../simulations/asert_upstream_vectors/run03"),
        include_str!("../../../../simulations/asert_upstream_vectors/run04"),
        include_str!("../../../../simulations/asert_upstream_vectors/run05"),
        include_str!("../../../../simulations/asert_upstream_vectors/run06"),
        include_str!("../../../../simulations/asert_upstream_vectors/run07"),
        include_str!("../../../../simulations/asert_upstream_vectors/run08"),
        include_str!("../../../../simulations/asert_upstream_vectors/run09"),
        include_str!("../../../../simulations/asert_upstream_vectors/run10"),
        include_str!("../../../../simulations/asert_upstream_vectors/run11"),
        include_str!("../../../../simulations/asert_upstream_vectors/run12"),
    ];

    fn parse_target(hex: &str) -> Uint256 {
        assert_eq!(hex.len(), 64);
        let mut bytes = [0u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap();
        }
        Uint256::from_be_bytes(bytes)
    }

    #[test]
    fn shared_python_integer_vectors_match_asert_target_candidate() {
        let mut count = 0usize;
        for line in VECTORS.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fields: Vec<&str> = line.split('|').collect();
            assert_eq!(fields.len(), 9, "malformed vector: {line}");
            assert_eq!(fields[0], "V");
            let anchor = parse_target(fields[2]);
            let height_delta = fields[3].parse::<u64>().unwrap();
            let time_delta = fields[4].parse::<i128>().unwrap();
            let spacing = fields[5].parse::<u64>().unwrap();
            let half_life = fields[6].parse::<u64>().unwrap();
            let pow_limit = parse_target(fields[7]);
            let expected = parse_target(fields[8]);
            let actual = asert_target_candidate(
                anchor,
                height_delta,
                time_delta,
                spacing,
                half_life,
                pow_limit,
            )
            .unwrap();
            assert_eq!(actual, expected, "{}", fields[1]);
            count += 1;
        }
        assert!(count >= 16, "too few shared ASERT vectors: {count}");
    }

    fn upstream_metadata_value<'a>(run: &'a str, keys: &[&str]) -> &'a str {
        for line in run.lines() {
            for key in keys {
                let prefix = format!("##   {key}:");
                if let Some(value) = line.strip_prefix(&prefix) {
                    return value.trim();
                }
            }
        }
        panic!("missing ASERT upstream metadata key; accepted keys: {keys:?}");
    }

    fn parse_bits(value: &str) -> u32 {
        u32::from_str_radix(value.trim().trim_start_matches("0x"), 16).unwrap()
    }

    #[test]
    fn compact_bits_roundtrip_matches_canonical_examples() {
        for bits in [
            0x1d00ffff, 0x1a2b3c4d, 0x01010000, 0x1802aee8, 0x02008000, 0x1d008000,
        ] {
            let target = compact_bits_to_target(bits).unwrap();
            assert_eq!(target_to_compact_bits(target), bits, "nBits={bits:#010x}");
        }
        assert_eq!(
            compact_bits_to_target(0x1d80ffff),
            Err(AsertCandidateError::InvalidCompactBits)
        );
    }

    #[test]
    fn all_official_aserti3_2d_upstream_vectors_match_compact_bits() {
        let mut total_vectors = 0usize;
        let target_spacing = 600u64;
        let half_life = 2 * 24 * 60 * 60u64;
        let max_bits = 0x1d00ffffu32;

        for (run_index, run) in ASERT_UPSTREAM_RUNS.iter().enumerate() {
            let anchor_height = upstream_metadata_value(run, &["anchor height"])
                .parse::<u64>()
                .unwrap();
            let anchor_parent_time =
                upstream_metadata_value(run, &["anchor ancestor time", "anchor parent time"])
                    .parse::<i128>()
                    .unwrap();
            let anchor_bits = parse_bits(upstream_metadata_value(run, &["anchor nBits"]));
            let expected_iterations = upstream_metadata_value(run, &["iterations"])
                .parse::<usize>()
                .unwrap();
            let mut run_vectors = 0usize;

            for line in run.lines().map(str::trim) {
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let fields: Vec<&str> = line.split_whitespace().collect();
                assert_eq!(
                    fields.len(),
                    4,
                    "run {} malformed row: {line}",
                    run_index + 1
                );
                let _iteration = fields[0].parse::<usize>().unwrap();
                let evaluation_height = fields[1].parse::<u64>().unwrap();
                let evaluation_time = fields[2].parse::<i128>().unwrap();
                let expected_bits = parse_bits(fields[3]);
                let actual_bits = asert_next_compact_bits_candidate(
                    anchor_height,
                    anchor_parent_time,
                    anchor_bits,
                    evaluation_height,
                    evaluation_time,
                    target_spacing,
                    half_life,
                    max_bits,
                )
                .unwrap_or_else(|error| {
                    panic!(
                        "run {} height {}: {error:?}",
                        run_index + 1,
                        evaluation_height
                    )
                });
                assert_eq!(
                    actual_bits,
                    expected_bits,
                    "upstream ASERT mismatch: run={} height={} timestamp={}",
                    run_index + 1,
                    evaluation_height,
                    evaluation_time
                );
                run_vectors += 1;
            }

            assert_eq!(
                run_vectors,
                expected_iterations,
                "official run {} declared {} iterations",
                run_index + 1,
                expected_iterations
            );
            total_vectors += run_vectors;
        }

        assert_eq!(total_vectors, 14_000);
    }

    #[test]
    fn zero_schedule_error_preserves_anchor_target() {
        let anchor =
            parse_target("0000007fffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        let actual = asert_target_candidate(anchor, 10, 330, 30, 172_800, Uint256::MAX).unwrap();
        assert_eq!(actual, anchor);
    }

    #[test]
    fn half_life_lateness_doubles_target_and_half_life_earliness_halves_it() {
        let anchor =
            parse_target("0000007fffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        let expected = 30i128 * 101i128;
        let later =
            asert_target_candidate(anchor, 100, expected + 172_800, 30, 172_800, Uint256::MAX)
                .unwrap();
        let earlier =
            asert_target_candidate(anchor, 100, expected - 172_800, 30, 172_800, Uint256::MAX)
                .unwrap();
        assert_eq!(later, anchor.mul_div_u64(2, 1).unwrap());
        assert_eq!(earlier, anchor.mul_div_u64(1, 2).unwrap());
    }

    #[test]
    fn target_eases_are_capped_and_target_underflow_fails_to_minimum_target() {
        let anchor =
            parse_target("0000007fffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        let ease = asert_target_candidate(anchor, 10, 30 * 11 + 172_800 * 20, 30, 172_800, anchor)
            .unwrap();
        assert_eq!(ease, anchor);
        let harder = asert_target_candidate(
            anchor,
            10,
            30 * 11 - 172_800 * 400,
            30,
            172_800,
            Uint256::MAX,
        )
        .unwrap();
        assert_eq!(harder, Uint256::ONE);
    }

    #[test]
    fn invalid_parameters_fail_closed() {
        assert_eq!(
            asert_target_candidate(Uint256::ZERO, 0, 30, 30, 172_800, Uint256::MAX),
            Err(AsertCandidateError::InvalidTarget)
        );
        assert_eq!(
            asert_target_candidate(Uint256::ONE, 0, 30, 0, 172_800, Uint256::MAX),
            Err(AsertCandidateError::ZeroTargetSpacing)
        );
        assert_eq!(
            asert_target_candidate(Uint256::ONE, 0, 30, 30, 0, Uint256::MAX),
            Err(AsertCandidateError::ZeroHalfLife)
        );
    }
}
