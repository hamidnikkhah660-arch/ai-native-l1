//! Node-local future-time admission policy for live QFP6 peer blocks.
//!
//! This mirrors Bitcoin's two-hour future-time rule as a local relay/admission guard.
//! It is deliberately NOT part of deterministic consensus and must never be used during
//! Genesis replay, archive import, or fork-choice reconstruction. Branch-local MTP remains
//! the deterministic consensus timestamp rule.

/// Live peers' blocks may be at most two hours ahead of this node's wall clock.
pub const QFP6_MAX_FUTURE_BLOCK_TIME_SECS: u64 = 2 * 60 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QRunV06LiveTimestampError {
    TooFarInFuture { latest_allowed: u64, actual: u64 },
}

/// Reject only timestamps too far ahead of this node's reference clock.
///
/// Old blocks remain eligible for deterministic historical replay; their ancestry and MTP are
/// checked by fork choice. `saturating_add` keeps the upper bound well-defined near `u64::MAX`.
pub fn validate_live_block_timestamp(
    candidate_timestamp: u64,
    reference_time: u64,
) -> Result<(), QRunV06LiveTimestampError> {
    let latest_allowed = reference_time.saturating_add(QFP6_MAX_FUTURE_BLOCK_TIME_SECS);
    if candidate_timestamp > latest_allowed {
        return Err(QRunV06LiveTimestampError::TooFarInFuture {
            latest_allowed,
            actual: candidate_timestamp,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_peer_timestamp_accepts_exact_two_hour_boundary_and_rejects_one_second_beyond() {
        let now = 1_900_000_000;
        assert_eq!(
            validate_live_block_timestamp(now + QFP6_MAX_FUTURE_BLOCK_TIME_SECS, now),
            Ok(())
        );
        assert_eq!(
            validate_live_block_timestamp(now + QFP6_MAX_FUTURE_BLOCK_TIME_SECS + 1, now),
            Err(QRunV06LiveTimestampError::TooFarInFuture {
                latest_allowed: now + QFP6_MAX_FUTURE_BLOCK_TIME_SECS,
                actual: now + QFP6_MAX_FUTURE_BLOCK_TIME_SECS + 1,
            })
        );
    }

    #[test]
    fn live_time_guard_does_not_reject_old_timestamps_needed_for_history_replay() {
        assert_eq!(validate_live_block_timestamp(1, 1_900_000_000), Ok(()));
    }

    #[test]
    fn live_time_upper_bound_saturates_without_integer_overflow() {
        assert_eq!(validate_live_block_timestamp(u64::MAX, u64::MAX), Ok(()));
    }
}
