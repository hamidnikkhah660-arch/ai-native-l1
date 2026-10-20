//! Research-only ASERT anchor and median-time-past policy candidate.
//!
//! This module composes branch-linked header samples into MTP checks and a fixed-height ASERT
//! anchor. It is not called by canonical block admission. Inputs must represent one complete,
//! contiguous branch prefix beginning at height zero. The future-time guard remains a separate
//! node-local admission policy because it depends on a local reference clock.
use crate::difficulty_adjustment_candidates::{compact_bits_to_target, AsertCandidateError};

pub const MEDIAN_TIME_PAST_WINDOW: usize = 11;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderTimeSample {
    pub height: u64,
    pub timestamp: i128,
    /// Compact target used by this block.
    pub bits: u32,
    pub parent_hash: [u8; 32],
    pub block_hash: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AsertAnchor {
    /// First height evaluated by the ASERT rule; the target at this height is anchor_bits.
    pub height: u64,
    /// Timestamp of the anchor block's parent, as required by upstream ASERT semantics.
    pub parent_timestamp: i128,
    pub bits: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorPolicyError {
    EmptyHistory,
    HistoryMustStartAtGenesis,
    HeightDiscontinuity,
    BrokenParentLink,
    NegativeTimestamp,
    InvalidNextHeight,
    WrongCandidateParent,
    TimestampNotAboveMedian { median: i128, actual: i128 },
    InvalidAnchorHeight,
    InvalidAnchorTarget(AsertCandidateError),
    AnchorTargetAbovePowLimit,
}

fn validate_history(history: &[HeaderTimeSample]) -> Result<(), AnchorPolicyError> {
    if history.is_empty() {
        return Err(AnchorPolicyError::EmptyHistory);
    }
    if history[0].height != 0 {
        return Err(AnchorPolicyError::HistoryMustStartAtGenesis);
    }
    for sample in history {
        if sample.timestamp < 0 {
            return Err(AnchorPolicyError::NegativeTimestamp);
        }
    }
    for pair in history.windows(2) {
        if pair[0].height.checked_add(1) != Some(pair[1].height) {
            return Err(AnchorPolicyError::HeightDiscontinuity);
        }
        if pair[1].parent_hash != pair[0].block_hash {
            return Err(AnchorPolicyError::BrokenParentLink);
        }
    }
    Ok(())
}

/// Return the median of the last at most 11 timestamps on a validated branch prefix.
///
/// Only prior blocks belong in history; the candidate block must not influence its own MTP.
pub fn median_time_past(history: &[HeaderTimeSample]) -> Result<i128, AnchorPolicyError> {
    validate_history(history)?;
    let start = history.len().saturating_sub(MEDIAN_TIME_PAST_WINDOW);
    let mut timestamps: Vec<i128> = history[start..]
        .iter()
        .map(|sample| sample.timestamp)
        .collect();
    timestamps.sort_unstable();
    Ok(timestamps[timestamps.len() / 2])
}

/// Validate deterministic chain-time rules for a proposed next block.
///
/// Unlike a simple parent-timestamp monotonicity check, this requires the new timestamp to be
/// strictly greater than the median of up to 11 ancestors. Local future-time rejection is
/// intentionally separate and must not silently define canonical cross-node validity.
pub fn validate_candidate_mtp(
    history: &[HeaderTimeSample],
    candidate_height: u64,
    candidate_parent_hash: [u8; 32],
    candidate_timestamp: i128,
) -> Result<(), AnchorPolicyError> {
    validate_history(history)?;
    if candidate_timestamp < 0 {
        return Err(AnchorPolicyError::NegativeTimestamp);
    }
    let parent = history.last().ok_or(AnchorPolicyError::EmptyHistory)?;
    if parent.height.checked_add(1) != Some(candidate_height) {
        return Err(AnchorPolicyError::InvalidNextHeight);
    }
    if parent.block_hash != candidate_parent_hash {
        return Err(AnchorPolicyError::WrongCandidateParent);
    }
    let median = median_time_past(history)?;
    if candidate_timestamp <= median {
        return Err(AnchorPolicyError::TimestampNotAboveMedian {
            median,
            actual: candidate_timestamp,
        });
    }
    Ok(())
}

/// Select ASERT's immutable anchor from a specific branch's complete header prefix.
///
/// The anchor target is read from the block at anchor_height; parent_timestamp is read from
/// the block at anchor_height - 1. Passing mixed/stale branch history is rejected by the height
/// and parent-link checks. The selected target is checked against max_bits.
pub fn select_asert_anchor(
    history: &[HeaderTimeSample],
    anchor_height: u64,
    max_bits: u32,
) -> Result<AsertAnchor, AnchorPolicyError> {
    validate_history(history)?;
    if anchor_height == 0 {
        return Err(AnchorPolicyError::InvalidAnchorHeight);
    }
    let index =
        usize::try_from(anchor_height).map_err(|_| AnchorPolicyError::InvalidAnchorHeight)?;
    let parent_index = index
        .checked_sub(1)
        .ok_or(AnchorPolicyError::InvalidAnchorHeight)?;
    let anchor_block = history
        .get(index)
        .filter(|block| block.height == anchor_height)
        .ok_or(AnchorPolicyError::InvalidAnchorHeight)?;
    let parent = history
        .get(parent_index)
        .filter(|block| block.height.checked_add(1) == Some(anchor_height))
        .ok_or(AnchorPolicyError::InvalidAnchorHeight)?;

    let anchor_target = compact_bits_to_target(anchor_block.bits)
        .map_err(AnchorPolicyError::InvalidAnchorTarget)?;
    let pow_limit =
        compact_bits_to_target(max_bits).map_err(AnchorPolicyError::InvalidAnchorTarget)?;
    if anchor_target > pow_limit {
        return Err(AnchorPolicyError::AnchorTargetAbovePowLimit);
    }

    Ok(AsertAnchor {
        height: anchor_height,
        parent_timestamp: parent.timestamp,
        bits: anchor_block.bits,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const EASY_BITS: u32 = 0x1d00ffff;
    const MAX_BITS: u32 = 0x207fffff;
    const SHARED_VECTORS: &str =
        include_str!("../../../../simulations/cp0118_n_mtp_anchor_shared_vectors.txt");

    fn sample(
        height: u64,
        timestamp: i128,
        bits: u32,
        parent_hash: [u8; 32],
        marker: u8,
    ) -> HeaderTimeSample {
        HeaderTimeSample {
            height,
            timestamp,
            bits,
            parent_hash,
            block_hash: [marker; 32],
        }
    }

    fn history_with_bits(timestamps: &[i128], bits: &[u32]) -> Vec<HeaderTimeSample> {
        assert_eq!(timestamps.len(), bits.len());
        let mut output = Vec::with_capacity(timestamps.len());
        for (height, (timestamp, compact_bits)) in timestamps.iter().zip(bits.iter()).enumerate() {
            let parent_hash = output
                .last()
                .map_or([0; 32], |prev: &HeaderTimeSample| prev.block_hash);
            output.push(sample(
                height as u64,
                *timestamp,
                *compact_bits,
                parent_hash,
                (height + 1) as u8,
            ));
        }
        output
    }

    fn history(timestamps: &[i128]) -> Vec<HeaderTimeSample> {
        history_with_bits(timestamps, &vec![EASY_BITS; timestamps.len()])
    }

    #[test]
    fn mtp_sorts_only_the_latest_eleven_ancestor_timestamps() {
        let mut times = vec![9_000i128, 8_000, 7_000, 6_000];
        times.extend((4..=14).map(|height| height * 10));
        let chain = history(&times);
        assert_eq!(median_time_past(&chain), Ok(90));
    }

    #[test]
    fn candidate_timestamp_must_be_strictly_greater_than_branch_mtp() {
        let chain = history(&[100, 10, 90, 40, 80, 60, 70]);
        let tip = chain.last().unwrap();
        assert_eq!(
            validate_candidate_mtp(&chain, 7, tip.block_hash, 60),
            Err(AnchorPolicyError::TimestampNotAboveMedian {
                median: 70,
                actual: 60
            })
        );
        assert_eq!(
            validate_candidate_mtp(&chain, 7, tip.block_hash, 70),
            Err(AnchorPolicyError::TimestampNotAboveMedian {
                median: 70,
                actual: 70
            })
        );
        assert_eq!(
            validate_candidate_mtp(&chain, 7, tip.block_hash, 71),
            Ok(())
        );
    }

    #[test]
    fn candidate_must_extend_the_exact_height_and_parent_of_the_selected_branch() {
        let chain = history(&[100, 101, 102]);
        let tip = chain.last().unwrap();
        assert_eq!(
            validate_candidate_mtp(&chain, 4, [0xFF; 32], 103),
            Err(AnchorPolicyError::InvalidNextHeight)
        );
        assert_eq!(
            validate_candidate_mtp(&chain, 3, [0xFF; 32], 103),
            Err(AnchorPolicyError::WrongCandidateParent)
        );
        assert_eq!(
            validate_candidate_mtp(&chain, 3, tip.block_hash, -1),
            Err(AnchorPolicyError::NegativeTimestamp)
        );
    }

    #[test]
    fn rejects_discontinuous_or_parent_mismatched_history() {
        let mut chain = history(&[100, 101, 102]);
        chain[2].height = 4;
        assert_eq!(
            median_time_past(&chain),
            Err(AnchorPolicyError::HeightDiscontinuity)
        );
        let mut chain = history(&[100, 101, 102]);
        chain[2].parent_hash = [0xAB; 32];
        assert_eq!(
            median_time_past(&chain),
            Err(AnchorPolicyError::BrokenParentLink)
        );
    }

    #[test]
    fn anchor_uses_anchor_block_bits_and_parent_timestamp() {
        let mut chain = history(&[100, 110, 120, 145, 170]);
        chain[3].bits = 0x1c00ffff;
        let anchor = select_asert_anchor(&chain, 3, MAX_BITS).unwrap();
        assert_eq!(
            anchor,
            AsertAnchor {
                height: 3,
                parent_timestamp: 120,
                bits: 0x1c00ffff
            }
        );
    }

    #[test]
    fn reorg_branch_recomputes_anchor_from_its_own_linked_history() {
        let shared = history(&[100, 110]);
        let mut left = shared.clone();
        left.push(sample(2, 120, EASY_BITS, left[1].block_hash, 0xA2));
        left.push(sample(3, 130, 0x1c00ffff, left[2].block_hash, 0xA3));

        let mut right = shared;
        right.push(sample(2, 150, EASY_BITS, right[1].block_hash, 0xB2));
        right.push(sample(3, 160, 0x1b00ffff, right[2].block_hash, 0xB3));

        let left_anchor = select_asert_anchor(&left, 3, MAX_BITS).unwrap();
        let right_anchor = select_asert_anchor(&right, 3, MAX_BITS).unwrap();
        assert_eq!(left_anchor.parent_timestamp, 120);
        assert_eq!(right_anchor.parent_timestamp, 150);
        assert_ne!(left_anchor.bits, right_anchor.bits);
    }

    #[test]
    fn replayed_header_prefix_reproduces_mtp_and_anchor_exactly() {
        let chain = history(&[100, 110, 125, 141, 155, 176, 199, 220, 245, 270, 290, 310]);
        let replayed = chain.iter().copied().collect::<Vec<_>>();
        assert_eq!(median_time_past(&chain), median_time_past(&replayed));
        assert_eq!(
            select_asert_anchor(&chain, 8, MAX_BITS),
            select_asert_anchor(&replayed, 8, MAX_BITS)
        );
    }

    #[test]
    fn rejects_anchor_zero_missing_height_and_target_above_pow_limit() {
        let chain = history(&[100, 110, 120]);
        assert_eq!(
            select_asert_anchor(&chain, 0, MAX_BITS),
            Err(AnchorPolicyError::InvalidAnchorHeight)
        );
        assert_eq!(
            select_asert_anchor(&chain, 9, MAX_BITS),
            Err(AnchorPolicyError::InvalidAnchorHeight)
        );

        let mut excessive = history(&[100, 110, 120]);
        excessive[2].bits = MAX_BITS;
        assert_eq!(
            select_asert_anchor(&excessive, 2, EASY_BITS),
            Err(AnchorPolicyError::AnchorTargetAbovePowLimit)
        );
    }

    #[test]
    fn shared_mtp_vectors_match_rust_policy() {
        let mut count = 0usize;
        for line in SHARED_VECTORS.lines().map(str::trim) {
            if !line.starts_with("M|") {
                continue;
            }
            let fields: Vec<&str> = line.split('|').collect();
            assert_eq!(fields.len(), 6, "bad MTP vector: {line}");
            let timestamps = fields[2]
                .split(',')
                .map(|value| value.parse::<i128>().unwrap())
                .collect::<Vec<_>>();
            let candidate_timestamp = fields[3].parse::<i128>().unwrap();
            let chain = history(&timestamps);
            let expected_status = fields[5];

            match median_time_past(&chain) {
                Ok(median) => {
                    assert_eq!(fields[4], median.to_string(), "MTP median {}", fields[1]);
                    match expected_status {
                        "ACCEPT" => assert_eq!(
                            validate_candidate_mtp(
                                &chain,
                                chain.len() as u64,
                                chain.last().unwrap().block_hash,
                                candidate_timestamp,
                            ),
                            Ok(()),
                            "MTP candidate {}",
                            fields[1]
                        ),
                        "REJECT_MTP" => assert!(
                            matches!(
                                validate_candidate_mtp(
                                    &chain,
                                    chain.len() as u64,
                                    chain.last().unwrap().block_hash,
                                    candidate_timestamp,
                                ),
                                Err(AnchorPolicyError::TimestampNotAboveMedian { .. })
                            ),
                            "MTP candidate {}",
                            fields[1]
                        ),
                        "REJECT_NEGATIVE_TIMESTAMP" => assert_eq!(
                            validate_candidate_mtp(
                                &chain,
                                chain.len() as u64,
                                chain.last().unwrap().block_hash,
                                candidate_timestamp,
                            ),
                            Err(AnchorPolicyError::NegativeTimestamp),
                            "MTP candidate {}",
                            fields[1]
                        ),
                        other => panic!("unknown MTP vector status {other}"),
                    }
                }
                Err(AnchorPolicyError::NegativeTimestamp) => {
                    assert_eq!(fields[4], "-");
                    assert_eq!(expected_status, "REJECT_NEGATIVE_TIMESTAMP");
                    assert_eq!(
                        validate_candidate_mtp(
                            &chain,
                            chain.len() as u64,
                            chain.last().unwrap().block_hash,
                            candidate_timestamp,
                        ),
                        Err(AnchorPolicyError::NegativeTimestamp),
                        "MTP candidate {}",
                        fields[1]
                    );
                }
                other => panic!("unexpected MTP vector error for {}: {other:?}", fields[1]),
            }
            count += 1;
        }
        assert_eq!(count, 8);
    }

    #[test]
    fn shared_anchor_vectors_match_rust_policy() {
        let mut count = 0usize;
        for line in SHARED_VECTORS.lines().map(str::trim) {
            if !line.starts_with("A|") {
                continue;
            }
            let fields: Vec<&str> = line.split('|').collect();
            assert_eq!(fields.len(), 9, "bad anchor vector: {line}");
            let timestamps = fields[2]
                .split(',')
                .map(|value| value.parse::<i128>().unwrap())
                .collect::<Vec<_>>();
            let bits = fields[3]
                .split(',')
                .map(|value| u32::from_str_radix(value, 16).unwrap())
                .collect::<Vec<_>>();
            let anchor_height = fields[4].parse::<u64>().unwrap();
            let max_bits = u32::from_str_radix(fields[5], 16).unwrap();
            let chain = history_with_bits(&timestamps, &bits);
            let result = select_asert_anchor(&chain, anchor_height, max_bits);

            match fields[8] {
                "OK" => {
                    let anchor = result.unwrap_or_else(|error| {
                        panic!(
                            "anchor vector {} unexpectedly rejected: {error:?}",
                            fields[1]
                        )
                    });
                    assert_eq!(
                        anchor.parent_timestamp.to_string(),
                        fields[6],
                        "{}",
                        fields[1]
                    );
                    assert_eq!(
                        anchor.bits,
                        u32::from_str_radix(fields[7], 16).unwrap(),
                        "{}",
                        fields[1]
                    );
                }
                "REJECT_ANCHOR_HEIGHT" => {
                    assert_eq!(
                        result,
                        Err(AnchorPolicyError::InvalidAnchorHeight),
                        "{}",
                        fields[1]
                    );
                }
                "REJECT_POW_LIMIT" => {
                    assert_eq!(
                        result,
                        Err(AnchorPolicyError::AnchorTargetAbovePowLimit),
                        "{}",
                        fields[1]
                    );
                }
                "REJECT_INVALID_BITS" => {
                    assert_eq!(
                        result,
                        Err(AnchorPolicyError::InvalidAnchorTarget(
                            AsertCandidateError::InvalidCompactBits
                        )),
                        "{}",
                        fields[1]
                    );
                }
                other => panic!("unknown anchor vector status {other}"),
            }
            count += 1;
        }
        assert_eq!(count, 7);
    }
}
