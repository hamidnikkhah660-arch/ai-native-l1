//! Explicit block-timestamp admission policy for the CP-0026 research chain.
//!
//! The state transition never reads the system clock. Callers pass a reference time
//! and a policy so timestamp acceptance is reproducible for fixed inputs. The
//! 120-second testnet window is provisional, not a mainnet/consensus parameter.

pub const MAX_FUTURE_DRIFT_TESTNET_SECS: u64 = 120;
// QRun v0.5 candidate mining uses 64 MiB Argon2id and may take materially longer than
// 120 seconds on modest hosts. CP-0503 raises only the local live-admission past bound;
// future-drift remains 120 seconds. This is not a frozen consensus or Mainnet parameter.
pub const MAX_PAST_DRIFT_QRUN_V05_LIVE_SECS: u64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimestampPolicy {
    pub max_future_drift_secs: u64,
    /// Optional lower freshness bound relative to the caller's reference clock.
    /// None preserves explicit future-only compatibility for legacy fixtures.
    pub max_past_drift_secs: Option<u64>,
}

impl TimestampPolicy {
    /// Construct the future-only compatibility policy used by legacy testnet paths.
    pub const fn new(max_future_drift_secs: u64) -> Self {
        Self {
            max_future_drift_secs,
            max_past_drift_secs: None,
        }
    }

    pub const fn with_max_past_drift_secs(mut self, max_past_drift_secs: u64) -> Self {
        self.max_past_drift_secs = Some(max_past_drift_secs);
        self
    }

    /// Existing generic testnet policy: inclusive future bound only.
    pub const fn testnet() -> Self {
        Self::new(MAX_FUTURE_DRIFT_TESTNET_SECS)
    }

    /// QRun v0.5 live-only local freshness policy. The past allowance accommodates
    /// measured 64 MiB Argon2id mining/propagation latency; future drift remains narrow.
    /// Historical replay must not use it against the present-day wall clock.
    pub const fn qrun_v05_live() -> Self {
        Self::new(MAX_FUTURE_DRIFT_TESTNET_SECS)
            .with_max_past_drift_secs(MAX_PAST_DRIFT_QRUN_V05_LIVE_SECS)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampPolicyError {
    ZeroTimestamp,
    NotIncreasing { previous: u64, actual: u64 },
    TooFarInPast { earliest_allowed: u64, actual: u64 },
    TooFarInFuture { latest_allowed: u64, actual: u64 },
}

impl TimestampPolicyError {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::ZeroTimestamp => "ZeroTimestamp",
            Self::NotIncreasing { .. } => "TimestampNotIncreasing",
            Self::TooFarInPast { .. } => "TimestampTooFarInPast",
            Self::TooFarInFuture { .. } => "TimestampTooFarInFuture",
        }
    }
}

/// Validate a candidate block timestamp without consulting wall-clock globals.
///
/// Ordering matters: zero and non-increasing timestamps are rejected first. When configured,
/// the lower freshness bound is inclusive (reference_time - max_past_drift_secs), saturating at
/// zero. The upper bound is inclusive (reference_time + max_future_drift_secs), saturating at
/// u64::MAX. These local-clock freshness checks apply to live admission only; historical replay
/// must use trusted history/checkpoint provenance rather than the current wall clock.
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
    if let Some(max_past_drift_secs) = policy.max_past_drift_secs {
        let earliest_allowed = reference_time.saturating_sub(max_past_drift_secs);
        if candidate_timestamp < earliest_allowed {
            return Err(TimestampPolicyError::TooFarInPast {
                earliest_allowed,
                actual: candidate_timestamp,
            });
        }
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
    fn qrun_v05_live_timestamp_window_bounds_mining_latency_and_keeps_future_guard_strict() {
        assert_eq!(
            TimestampPolicy::testnet().max_past_drift_secs,
            None,
            "legacy generic testnet policy remains future-only"
        );
        let policy = TimestampPolicy::qrun_v05_live();
        assert_eq!(policy.max_future_drift_secs, 120);
        assert_eq!(policy.max_past_drift_secs, Some(300));

        assert_eq!(
            validate_block_timestamp(699, 700, 1_000, policy),
            Ok(()),
            "the inclusive 300-second mining-latency boundary is accepted"
        );
        assert_eq!(
            validate_block_timestamp(698, 699, 1_000, policy),
            Err(TimestampPolicyError::TooFarInPast {
                earliest_allowed: 700,
                actual: 699
            })
        );
        assert_eq!(
            validate_block_timestamp(0, 849, 1_000, policy),
            Ok(()),
            "a block mined 151 seconds after its timestamp remains admissible"
        );
        assert_eq!(
            validate_block_timestamp(999, 1_120, 1_000, policy),
            Ok(()),
            "the inclusive future boundary remains accepted"
        );
        assert_eq!(
            validate_block_timestamp(999, 1_121, 1_000, policy),
            Err(TimestampPolicyError::TooFarInFuture {
                latest_allowed: 1_120,
                actual: 1_121
            })
        );

        // Both arithmetic bounds saturate instead of wrapping near u64 limits.
        assert_eq!(
            validate_block_timestamp(u64::MAX - 1, u64::MAX, u64::MAX - 50, policy),
            Ok(())
        );
        assert_eq!(
            validate_block_timestamp(0, 1, 50, policy),
            Ok(()),
            "the past lower bound saturates at zero"
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
            }),
            "legacy future-only policy remains explicit"
        );
    }
}
