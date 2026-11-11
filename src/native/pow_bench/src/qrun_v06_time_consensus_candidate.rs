//! Deterministic QFP6 branch-local median-time-past policy.
//!
//! The candidate timestamp is compared with the median of up to the previous 11
//! timestamps on its exact parent branch. This rule is independent of local wall time.
pub const QFP6_MEDIAN_TIME_PAST_WINDOW: usize = 11;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QRunV06TimeConsensusError {
    EmptyHistory,
    TimestampNotAboveMedian { median: u64, actual: u64 },
}

/// Median of the last at most 11 ancestor timestamps (candidate excluded).
pub fn median_time_past(ancestor_timestamps: &[u64]) -> Result<u64, QRunV06TimeConsensusError> {
    if ancestor_timestamps.is_empty() {
        return Err(QRunV06TimeConsensusError::EmptyHistory);
    }
    let start = ancestor_timestamps
        .len()
        .saturating_sub(QFP6_MEDIAN_TIME_PAST_WINDOW);
    let mut values = ancestor_timestamps[start..].to_vec();
    values.sort_unstable();
    Ok(values[values.len() / 2])
}

/// Require a candidate to be strictly later than the median of its branch ancestors.
pub fn validate_candidate_timestamp(
    ancestor_timestamps: &[u64],
    candidate_timestamp: u64,
) -> Result<(), QRunV06TimeConsensusError> {
    let median = median_time_past(ancestor_timestamps)?;
    if candidate_timestamp <= median {
        return Err(QRunV06TimeConsensusError::TimestampNotAboveMedian {
            median,
            actual: candidate_timestamp,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn median_uses_all_short_history_and_upper_middle_for_even_count() {
        assert_eq!(median_time_past(&[9, 1, 5, 3]), Ok(5));
        assert_eq!(median_time_past(&[9, 1, 5]), Ok(5));
    }

    #[test]
    fn median_uses_only_last_eleven_ancestors() {
        let mut values = vec![u64::MAX];
        values.extend(1..=11);
        assert_eq!(median_time_past(&values), Ok(6));
    }

    #[test]
    fn candidate_must_be_strictly_above_median() {
        let history = [10, 20, 30, 40, 50];
        assert_eq!(
            validate_candidate_timestamp(&history, 30),
            Err(QRunV06TimeConsensusError::TimestampNotAboveMedian {
                median: 30,
                actual: 30
            })
        );
        assert_eq!(validate_candidate_timestamp(&history, 31), Ok(()));
    }

    #[test]
    fn empty_history_fails_closed() {
        assert_eq!(
            median_time_past(&[]),
            Err(QRunV06TimeConsensusError::EmptyHistory)
        );
    }
}
