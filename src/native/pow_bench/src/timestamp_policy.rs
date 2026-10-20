//! Explicit block-timestamp admission policy for the CP-0026 research chain.
//!
//! The state transition never reads the system clock. Callers pass a reference time
//! and a policy so timestamp acceptance is reproducible for fixed inputs. The
//! 120-second testnet window is provisional, not a mainnet/consensus parameter.

pub const MAX_FUTURE_DRIFT_TESTNET_SECS: u64 = 120;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimestampPolicy {
    pub max_future_drift_secs: u64,
}

impl TimestampPolicy {
    pub const fn new(max_future_drift_secs: u64) -> Self {
        Self {
            max_future_drift_secs,
        }
    }

    pub const fn testnet() -> Self {
        Self::new(MAX_FUTURE_DRIFT_TESTNET_SECS)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampPolicyError {
    ZeroTimestamp,
    NotIncreasing { previous: u64, actual: u64 },
    TooFarInFuture { latest_allowed: u64, actual: u64 },
}

impl TimestampPolicyError {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::ZeroTimestamp => "ZeroTimestamp",
            Self::NotIncreasing { .. } => "TimestampNotIncreasing",
            Self::TooFarInFuture { .. } => "TimestampTooFarInFuture",
        }
    }
}

/// Validate a candidate block timestamp without consulting wall-clock globals.
///
/// Ordering matters: zero is invalid even for the first block; otherwise the
/// timestamp must strictly exceed the parent timestamp. The upper bound is
/// inclusive (reference_time + max_future_drift_secs) and saturates at u64::MAX
/// rather than wrapping on arithmetic overflow.
pub fn validate_block_timestamp(
    previous_timestamp: u64,
    candidate_timestamp: u64,
    reference_time: u64,
    policy: TimestampPolicy,
) -> Result<(), TimestampPolicyError> {
    if candidate_timestamp == 0 {
        return Err(TimestampPolicyError::ZeroTimestamp);
    }
    if candidate_timestamp <= previous_timestamp {
        return Err(TimestampPolicyError::NotIncreasing {
            previous: previous_timestamp,
            actual: candidate_timestamp,
        });
    }
    let latest_allowed = reference_time.saturating_add(policy.max_future_drift_secs);
    if candidate_timestamp > latest_allowed {
        return Err(TimestampPolicyError::TooFarInFuture {
            latest_allowed,
            actual: candidate_timestamp,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::BTreeMap, path::PathBuf};

    fn fields_to_result(fields: &BTreeMap<String, String>) -> (&'static str, &'static str) {
        let previous = fields["PREVIOUS_TIMESTAMP"].parse().unwrap();
        let candidate = fields["CANDIDATE_TIMESTAMP"].parse().unwrap();
        let reference = fields["REFERENCE_TIME"].parse().unwrap();
        let drift = fields["MAX_FUTURE_DRIFT_SECS"].parse().unwrap();
        match validate_block_timestamp(previous, candidate, reference, TimestampPolicy::new(drift))
        {
            Ok(()) => ("ACCEPT", "None"),
            Err(error) => ("REJECT", error.reason_code()),
        }
    }

    #[test]
    fn shared_cp0026f_timestamp_vectors_match_rust_policy() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../simulations/cp0026f_timestamp_vectors.txt");
        let text = std::fs::read_to_string(path).expect("read shared CP-0026-F vectors");
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(lines.first(), Some(&"CP0026F_TIMESTAMP_POLICY_V1"));
        assert_eq!(lines.last(), Some(&"END"));

        let mut cases = Vec::<BTreeMap<String, String>>::new();
        let mut current = BTreeMap::<String, String>::new();
        for line in lines.iter().skip(1).take_while(|line| **line != "END") {
            let (key, value) = line.split_once('=').expect("key=value vector record");
            if key == "CASE" && !current.is_empty() {
                cases.push(std::mem::take(&mut current));
            }
            assert!(
                current.insert(key.to_string(), value.to_string()).is_none(),
                "duplicate field {key}"
            );
        }
        if !current.is_empty() {
            cases.push(current);
        }
        assert!(
            cases.len() >= 12,
            "timestamp boundary vectors unexpectedly small"
        );

        for case in &cases {
            let name = &case["CASE"];
            let expected = (&case["EXPECTED"][..], &case["REASON"][..]);
            let actual = fields_to_result(case);
            assert_eq!(actual, expected, "timestamp vector case {name}");
        }
    }

    #[test]
    fn testnet_timestamp_window_is_explicit_and_overflow_safe() {
        assert_eq!(TimestampPolicy::testnet().max_future_drift_secs, 120);
        assert_eq!(
            validate_block_timestamp(
                u64::MAX - 1,
                u64::MAX,
                u64::MAX - 50,
                TimestampPolicy::testnet()
            ),
            Ok(())
        );
        assert_eq!(
            validate_block_timestamp(
                u64::MAX - 1,
                u64::MAX,
                u64::MAX - 1,
                TimestampPolicy::new(0)
            ),
            Err(TimestampPolicyError::TooFarInFuture {
                latest_allowed: u64::MAX - 1,
                actual: u64::MAX
            })
        );
    }
}
