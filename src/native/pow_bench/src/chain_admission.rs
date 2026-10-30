//! Single public boundary for live block admission and historical replay.
//!
//! Research/testnet integration point, not a complete node-consensus layer. Reference-time
//! provenance is caller-supplied metadata, not cryptographic attestation. Operators must
//! coordinate clock source semantics and the candidate future-drift policy.

use crate::{
    state_machine::{
        Block, BlockApplySummary, LedgerState, MonetaryBlock, MonetaryLedgerState, QRunV05FeeBlock,
        StateError, TransactionAuthenticator, V4HybridMonetaryBlock,
    },
    timestamp_policy::TimestampPolicy,
};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferenceTimeProvenance {
    LocalSystemClock,
    ConfiguredProvider,
    DeterministicTestFixture,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReferenceTimeSample {
    pub unix_seconds: u64,
    pub provenance: ReferenceTimeProvenance,
    /// Stable operator-visible label; metadata only, not proof of trust.
    pub source_id: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferenceTimeError {
    ClockBeforeUnixEpoch,
    ProviderUnavailable,
    PolicyMalformed,
    PolicySignatureInvalid,
    PolicyNetworkMismatch,
    PolicyRollback,
    AttestationMalformed,
    AuthoritySignatureInvalid,
    ChallengeMismatch,
    StaleResponse,
    SequenceRollback,
    ClockSkewExceeded,
    StateMalformed,
    StatePersistence,
    StateLocked,
}

/// Caller-selected source of normalized Unix seconds.
pub trait ReferenceTimeProvider {
    fn sample(&self) -> Result<ReferenceTimeSample, ReferenceTimeError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClockReferenceTime;

impl ReferenceTimeProvider for SystemClockReferenceTime {
    fn sample(&self) -> Result<ReferenceTimeSample, ReferenceTimeError> {
        let unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ReferenceTimeError::ClockBeforeUnixEpoch)?
            .as_secs();
        Ok(ReferenceTimeSample {
            unix_seconds,
            provenance: ReferenceTimeProvenance::LocalSystemClock,
            source_id: "os-system-clock",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferenceTimeSourcePolicy {
    /// Candidate testnet default: system clock or configured provider; no fixtures.
    SystemClockOrConfiguredProvider,
    /// Require an external, operator-configured implementation.
    ConfiguredProviderOnly,
    /// Require both an injected provider and the exact operator-configured source label.
    /// The label is a consistency guard, not an authenticated time attestation.
    RequireConfiguredSourceId(&'static str),
    /// Explicit test/research override that permits deterministic fixtures.
    AllowTestFixtures,
}

impl ReferenceTimeSourcePolicy {
    fn accepts(self, source: ReferenceTimeProvenance) -> bool {
        match self {
            Self::SystemClockOrConfiguredProvider => {
                source != ReferenceTimeProvenance::DeterministicTestFixture
            }
            Self::ConfiguredProviderOnly | Self::RequireConfiguredSourceId(_) => {
                source == ReferenceTimeProvenance::ConfiguredProvider
            }
            Self::AllowTestFixtures => true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainAdmissionConfig {
    pub timestamp_policy: TimestampPolicy,
    pub reference_time_source_policy: ReferenceTimeSourcePolicy,
}

impl ChainAdmissionConfig {
    pub const fn new(
        timestamp_policy: TimestampPolicy,
        reference_time_source_policy: ReferenceTimeSourcePolicy,
    ) -> Self {
        Self {
            timestamp_policy,
            reference_time_source_policy,
        }
    }

    /// Explicit candidate configuration for local testnet; not a Mainnet default.
    pub const fn testnet() -> Self {
        Self::new(
            TimestampPolicy::testnet(),
            ReferenceTimeSourcePolicy::SystemClockOrConfiguredProvider,
        )
    }

    /// Must be deliberately selected for deterministic test fixtures.
    pub const fn with_test_fixtures_enabled(mut self) -> Self {
        self.reference_time_source_policy = ReferenceTimeSourcePolicy::AllowTestFixtures;
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockApplicationMode {
    LiveAdmission,
    HistoricalReplay,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockAdmissionReceipt {
    pub summary: BlockApplySummary,
    pub mode: BlockApplicationMode,
    /// None for replay: replay never samples current time.
    pub reference_time: Option<ReferenceTimeSample>,
    /// None for replay: current-time future-window checks do not apply.
    pub timestamp_policy: Option<TimestampPolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainAdmissionError {
    ReferenceTimeUnavailable(ReferenceTimeError),
    ReferenceTimeRejected(ReferenceTimeError),
    ReferenceTimeSourceDisallowed(ReferenceTimeProvenance),
    ReferenceTimeSourceUnlabeled(ReferenceTimeProvenance),
    ReferenceTimeSourceMismatch {
        expected_source_id: &'static str,
        actual_source_id: &'static str,
    },
    State(StateError),
}

/// Public entry point for applying candidate blocks. Raw state-transition mutators
/// are crate-private so downstream runtime integrations go through this boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainAdmissionBoundary {
    config: ChainAdmissionConfig,
}

impl ChainAdmissionBoundary {
    pub const fn new(config: ChainAdmissionConfig) -> Self {
        Self { config }
    }
    pub const fn testnet() -> Self {
        Self::new(ChainAdmissionConfig::testnet())
    }
    pub const fn config(&self) -> ChainAdmissionConfig {
        self.config
    }

    /// Apply a live candidate with an explicit time sample and validated provenance.
    /// The sample is diagnostic context, not committed into the canonical block/state root.
    pub fn admit_live<A: TransactionAuthenticator>(
        &self,
        state: &mut LedgerState,
        block: &Block,
        authenticator: &A,
        clock: &dyn ReferenceTimeProvider,
    ) -> Result<BlockAdmissionReceipt, ChainAdmissionError> {
        let reference_time = clock.sample().map_err(|error| match error {
            ReferenceTimeError::ClockBeforeUnixEpoch | ReferenceTimeError::ProviderUnavailable => {
                ChainAdmissionError::ReferenceTimeUnavailable(error)
            }
            other => ChainAdmissionError::ReferenceTimeRejected(other),
        })?;
        if !self
            .config
            .reference_time_source_policy
            .accepts(reference_time.provenance)
        {
            return Err(ChainAdmissionError::ReferenceTimeSourceDisallowed(
                reference_time.provenance,
            ));
        }
        if reference_time.source_id.trim().is_empty() {
            return Err(ChainAdmissionError::ReferenceTimeSourceUnlabeled(
                reference_time.provenance,
            ));
        }
        if let ReferenceTimeSourcePolicy::RequireConfiguredSourceId(expected_source_id) =
            self.config.reference_time_source_policy
        {
            if reference_time.source_id != expected_source_id {
                return Err(ChainAdmissionError::ReferenceTimeSourceMismatch {
                    expected_source_id,
                    actual_source_id: reference_time.source_id,
                });
            }
        }
        let summary = state
            .apply_block_with_timestamp_policy(
                block,
                authenticator,
                reference_time.unix_seconds,
                self.config.timestamp_policy,
            )
            .map_err(ChainAdmissionError::State)?;
        Ok(BlockAdmissionReceipt {
            summary,
            mode: BlockApplicationMode::LiveAdmission,
            reference_time: Some(reference_time),
            timestamp_policy: Some(self.config.timestamp_policy),
        })
    }

    /// Live admission for QRun QFB5 blocks. Uses the same clock provenance and timestamp guards
    /// as the legacy path, but executes the fee-only transition instead of a plain BLK2 transition.
    pub fn admit_live_qrun_v05_fee<A: TransactionAuthenticator>(
        &self,
        state: &mut LedgerState,
        block: &QRunV05FeeBlock,
        authenticator: &A,
        clock: &dyn ReferenceTimeProvider,
    ) -> Result<BlockAdmissionReceipt, ChainAdmissionError> {
        let reference_time = clock.sample().map_err(|error| match error {
            ReferenceTimeError::ClockBeforeUnixEpoch | ReferenceTimeError::ProviderUnavailable => {
                ChainAdmissionError::ReferenceTimeUnavailable(error)
            }
            other => ChainAdmissionError::ReferenceTimeRejected(other),
        })?;
        if !self
            .config
            .reference_time_source_policy
            .accepts(reference_time.provenance)
        {
            return Err(ChainAdmissionError::ReferenceTimeSourceDisallowed(
                reference_time.provenance,
            ));
        }
        if reference_time.source_id.trim().is_empty() {
            return Err(ChainAdmissionError::ReferenceTimeSourceUnlabeled(
                reference_time.provenance,
            ));
        }
        if let ReferenceTimeSourcePolicy::RequireConfiguredSourceId(expected_source_id) =
            self.config.reference_time_source_policy
        {
            if reference_time.source_id != expected_source_id {
                return Err(ChainAdmissionError::ReferenceTimeSourceMismatch {
                    expected_source_id,
                    actual_source_id: reference_time.source_id,
                });
            }
        }
        let summary = state
            .apply_qrun_v05_fee_block_with_timestamp_policy(
                block,
                authenticator,
                reference_time.unix_seconds,
                self.config.timestamp_policy,
            )
            .map_err(ChainAdmissionError::State)?;
        Ok(BlockAdmissionReceipt {
            summary,
            mode: BlockApplicationMode::LiveAdmission,
            reference_time: Some(reference_time),
            timestamp_policy: Some(self.config.timestamp_policy),
        })
    }

    /// Deterministic historical replay for QRun QFB5. It does not sample wall-clock time or use
    /// a moving future-window; the fee transition and parent/height checks still run in full.
    pub fn replay_qrun_v05_fee<A: TransactionAuthenticator>(
        &self,
        state: &mut LedgerState,
        block: &QRunV05FeeBlock,
        authenticator: &A,
    ) -> Result<BlockAdmissionReceipt, ChainAdmissionError> {
        let summary = state
            .apply_qrun_v05_fee_block(block, authenticator)
            .map_err(ChainAdmissionError::State)?;
        Ok(BlockAdmissionReceipt {
            summary,
            mode: BlockApplicationMode::HistoricalReplay,
            reference_time: None,
            timestamp_policy: None,
        })
    }

    /// Live admission for the explicit monetary-block candidate path. It shares the same
    /// clock provenance and timestamp guards as legacy BLK2 admission.
    pub fn admit_live_monetary<A: TransactionAuthenticator>(
        &self,
        state: &mut MonetaryLedgerState,
        block: &MonetaryBlock,
        authenticator: &A,
        clock: &dyn ReferenceTimeProvider,
    ) -> Result<BlockAdmissionReceipt, ChainAdmissionError> {
        let reference_time = clock.sample().map_err(|error| match error {
            ReferenceTimeError::ClockBeforeUnixEpoch | ReferenceTimeError::ProviderUnavailable => {
                ChainAdmissionError::ReferenceTimeUnavailable(error)
            }
            other => ChainAdmissionError::ReferenceTimeRejected(other),
        })?;
        if !self
            .config
            .reference_time_source_policy
            .accepts(reference_time.provenance)
        {
            return Err(ChainAdmissionError::ReferenceTimeSourceDisallowed(
                reference_time.provenance,
            ));
        }
        if reference_time.source_id.trim().is_empty() {
            return Err(ChainAdmissionError::ReferenceTimeSourceUnlabeled(
                reference_time.provenance,
            ));
        }
        if let ReferenceTimeSourcePolicy::RequireConfiguredSourceId(expected_source_id) =
            self.config.reference_time_source_policy
        {
            if reference_time.source_id != expected_source_id {
                return Err(ChainAdmissionError::ReferenceTimeSourceMismatch {
                    expected_source_id,
                    actual_source_id: reference_time.source_id,
                });
            }
        }
        let summary = state
            .apply_block_with_timestamp_policy(
                block,
                authenticator,
                reference_time.unix_seconds,
                self.config.timestamp_policy,
            )
            .map_err(ChainAdmissionError::State)?;
        Ok(BlockAdmissionReceipt {
            summary,
            mode: BlockApplicationMode::LiveAdmission,
            reference_time: Some(reference_time),
            timestamp_policy: Some(self.config.timestamp_policy),
        })
    }

    /// Live admission for the separate MBK4/TXN4 hybrid candidate. The active manifest and
    /// real ML-DSA verifier are injected explicitly; neither is inferred from transaction bytes.
    /// This remains a candidate admission API until PMT4/PFM4 and node runtime dispatch exist.
    pub fn admit_live_v4_hybrid_monetary<
        V: crate::v4_account_identity_candidate::MlDsa65Verifier,
    >(
        &self,
        state: &mut MonetaryLedgerState,
        block: &V4HybridMonetaryBlock,
        expected_manifest_id: &[u8; 32],
        verifier: &V,
        clock: &dyn ReferenceTimeProvider,
    ) -> Result<BlockAdmissionReceipt, ChainAdmissionError> {
        let reference_time = clock.sample().map_err(|error| match error {
            ReferenceTimeError::ClockBeforeUnixEpoch | ReferenceTimeError::ProviderUnavailable => {
                ChainAdmissionError::ReferenceTimeUnavailable(error)
            }
            other => ChainAdmissionError::ReferenceTimeRejected(other),
        })?;
        if !self
            .config
            .reference_time_source_policy
            .accepts(reference_time.provenance)
        {
            return Err(ChainAdmissionError::ReferenceTimeSourceDisallowed(
                reference_time.provenance,
            ));
        }
        if reference_time.source_id.trim().is_empty() {
            return Err(ChainAdmissionError::ReferenceTimeSourceUnlabeled(
                reference_time.provenance,
            ));
        }
        if let ReferenceTimeSourcePolicy::RequireConfiguredSourceId(expected_source_id) =
            self.config.reference_time_source_policy
        {
            if reference_time.source_id != expected_source_id {
                return Err(ChainAdmissionError::ReferenceTimeSourceMismatch {
                    expected_source_id,
                    actual_source_id: reference_time.source_id,
                });
            }
        }
        let summary = state
            .apply_v4_hybrid_block_with_timestamp_policy(
                block,
                expected_manifest_id,
                verifier,
                reference_time.unix_seconds,
                self.config.timestamp_policy,
            )
            .map_err(ChainAdmissionError::State)?;
        Ok(BlockAdmissionReceipt {
            summary,
            mode: BlockApplicationMode::LiveAdmission,
            reference_time: Some(reference_time),
            timestamp_policy: Some(self.config.timestamp_policy),
        })
    }

    /// Deterministic historical replay: validates canonical chain/state rules but does
    /// not sample current time or impose a moving future-window on already recorded data.
    pub fn replay_historical<A: TransactionAuthenticator>(
        &self,
        state: &mut LedgerState,
        block: &Block,
        authenticator: &A,
    ) -> Result<BlockAdmissionReceipt, ChainAdmissionError> {
        let summary = state
            .apply_block(block, authenticator)
            .map_err(ChainAdmissionError::State)?;
        Ok(BlockAdmissionReceipt {
            summary,
            mode: BlockApplicationMode::HistoricalReplay,
            reference_time: None,
            timestamp_policy: None,
        })
    }

    /// Deterministic historical replay for the versioned MBK3 monetary-block candidate.
    pub fn replay_monetary<A: TransactionAuthenticator>(
        &self,
        state: &mut MonetaryLedgerState,
        block: &MonetaryBlock,
        authenticator: &A,
    ) -> Result<BlockAdmissionReceipt, ChainAdmissionError> {
        let summary = state
            .apply_block(block, authenticator)
            .map_err(ChainAdmissionError::State)?;
        Ok(BlockAdmissionReceipt {
            summary,
            mode: BlockApplicationMode::HistoricalReplay,
            reference_time: None,
            timestamp_policy: None,
        })
    }

    /// Deterministic replay for a canonical MBK4/TXN4 branch. The active manifest and
    /// ML-DSA verifier remain explicit inputs; historic replay does not consult wall-clock time.
    pub fn replay_v4_hybrid_monetary<V: crate::v4_account_identity_candidate::MlDsa65Verifier>(
        &self,
        state: &mut MonetaryLedgerState,
        block: &V4HybridMonetaryBlock,
        expected_manifest_id: &[u8; 32],
        verifier: &V,
    ) -> Result<BlockAdmissionReceipt, ChainAdmissionError> {
        let summary = state
            .apply_v4_hybrid_block_candidate(block, expected_manifest_id, verifier)
            .map_err(ChainAdmissionError::State)?;
        Ok(BlockAdmissionReceipt {
            summary,
            mode: BlockApplicationMode::HistoricalReplay,
            reference_time: None,
            timestamp_policy: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{ConsensusParameters, PowHeader};
    use crate::private_testnet_monetary_wire::{
        decode_candidate_v4_hybrid_monetary_network_block,
        encode_candidate_v4_hybrid_monetary_network_block,
    };
    use crate::state_machine::{AccountId, NetworkId, MONETARY_PUBLIC_GOODS_BUDGET_ATOMS};
    use crate::v4_account_identity_candidate::{
        native_v4_account_id, AccountIdentityScheme, V4HybridAuthorization, V4HybridSignature,
        V4HybridTransaction, ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SIGNATURE_BYTES,
    };
    use crate::v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate;
    use ed25519_dalek::{Signer, SigningKey};
    use libcrux_ml_dsa::ml_dsa_65::portable;

    const NETWORK: NetworkId = [0xA7; 32];

    struct AcceptAllForEmptyBlock;
    impl TransactionAuthenticator for AcceptAllForEmptyBlock {
        fn verify(&self, _: &AccountId, _: &[u8; 32], _: &[u8]) -> Result<(), ()> {
            Ok(())
        }
    }

    struct FixedClock(ReferenceTimeSample);
    impl ReferenceTimeProvider for FixedClock {
        fn sample(&self) -> Result<ReferenceTimeSample, ReferenceTimeError> {
            Ok(self.0)
        }
    }

    struct FailingClock;
    impl ReferenceTimeProvider for FailingClock {
        fn sample(&self) -> Result<ReferenceTimeSample, ReferenceTimeError> {
            Err(ReferenceTimeError::ProviderUnavailable)
        }
    }

    fn state() -> LedgerState {
        LedgerState::genesis(NETWORK, vec![([1; 32], 1_000)]).unwrap()
    }

    fn clock(
        seconds: u64,
        provenance: ReferenceTimeProvenance,
        source_id: &'static str,
    ) -> FixedClock {
        FixedClock(ReferenceTimeSample {
            unix_seconds: seconds,
            provenance,
            source_id,
        })
    }

    fn empty_block(state: &LedgerState, timestamp: u64) -> Block {
        let mut block = Block {
            height: state.height() + 1,
            timestamp,
            parent_hash: state.tip_hash(),
            state_root: [0; 32],
            transactions: Vec::new(),
        };
        block.state_root = state
            .preview_state_root_after(&block, &AcceptAllForEmptyBlock)
            .unwrap();
        block
    }

    fn monetary_state() -> MonetaryLedgerState {
        MonetaryLedgerState::genesis(
            NETWORK,
            [1; 32],
            vec![([2; 32], MONETARY_PUBLIC_GOODS_BUDGET_ATOMS as u64)],
        )
        .unwrap()
    }

    fn empty_monetary_block(state: &MonetaryLedgerState, timestamp: u64) -> MonetaryBlock {
        let mut block = MonetaryBlock {
            body: Block {
                height: state.height() + 1,
                timestamp,
                parent_hash: state.tip_hash(),
                state_root: [0; 32],
                transactions: Vec::new(),
            },
            miner: [3; 32],
            claimed_subsidy_atoms: state.expected_miner_reward().unwrap(),
        };
        block.body.state_root = state
            .preview_state_root_after(&block, &AcceptAllForEmptyBlock)
            .unwrap();
        block
    }

    #[test]
    fn live_boundary_records_source_and_accepts_inclusive_future_limit() {
        let mut state = state();
        let block = empty_block(&state, 220);
        let receipt = ChainAdmissionBoundary::testnet()
            .admit_live(
                &mut state,
                &block,
                &AcceptAllForEmptyBlock,
                &clock(
                    100,
                    ReferenceTimeProvenance::ConfiguredProvider,
                    "operator-clock-a",
                ),
            )
            .unwrap();
        assert_eq!(receipt.mode, BlockApplicationMode::LiveAdmission);
        assert_eq!(
            receipt.reference_time.unwrap().source_id,
            "operator-clock-a"
        );
        assert_eq!(receipt.timestamp_policy.unwrap().max_future_drift_secs, 120);
        assert_eq!(state.height(), 1);
    }

    #[test]
    fn over_future_candidate_rejects_atomically() {
        let mut state = state();
        let before = state.encode_snapshot().unwrap();
        let block = empty_block(&state, 221);
        let error = ChainAdmissionBoundary::testnet()
            .admit_live(
                &mut state,
                &block,
                &AcceptAllForEmptyBlock,
                &clock(
                    100,
                    ReferenceTimeProvenance::LocalSystemClock,
                    "local-test-clock",
                ),
            )
            .unwrap_err();
        assert_eq!(
            error,
            ChainAdmissionError::State(StateError::TimestampTooFarInFuture {
                latest_allowed: 220,
                actual: 221,
            })
        );
        assert_eq!(state.encode_snapshot().unwrap(), before);
    }

    #[test]
    fn deterministic_fixture_requires_explicit_opt_in() {
        let mut state = state();
        let before = state.encode_snapshot().unwrap();
        let block = empty_block(&state, 100);
        let fixture = clock(
            100,
            ReferenceTimeProvenance::DeterministicTestFixture,
            "fixture",
        );
        assert_eq!(
            ChainAdmissionBoundary::testnet().admit_live(
                &mut state,
                &block,
                &AcceptAllForEmptyBlock,
                &fixture,
            ),
            Err(ChainAdmissionError::ReferenceTimeSourceDisallowed(
                ReferenceTimeProvenance::DeterministicTestFixture
            ))
        );
        assert_eq!(state.encode_snapshot().unwrap(), before);

        ChainAdmissionBoundary::new(ChainAdmissionConfig::testnet().with_test_fixtures_enabled())
            .admit_live(&mut state, &block, &AcceptAllForEmptyBlock, &fixture)
            .unwrap();
    }

    #[test]
    fn configured_provider_only_rejects_local_clock() {
        let mut state = state();
        let block = empty_block(&state, 100);
        let boundary = ChainAdmissionBoundary::new(ChainAdmissionConfig::new(
            TimestampPolicy::testnet(),
            ReferenceTimeSourcePolicy::ConfiguredProviderOnly,
        ));
        assert_eq!(
            boundary.admit_live(
                &mut state,
                &block,
                &AcceptAllForEmptyBlock,
                &clock(100, ReferenceTimeProvenance::LocalSystemClock, "os")
            ),
            Err(ChainAdmissionError::ReferenceTimeSourceDisallowed(
                ReferenceTimeProvenance::LocalSystemClock
            ))
        );
        assert_eq!(state.height(), 0);
    }

    #[test]
    fn historical_replay_ignores_moving_clock_policy_but_keeps_chain_rules() {
        let mut state = state();
        // This timestamp is far beyond any present reference time but valid historical data.
        let block = empty_block(&state, 10_000);
        let receipt = ChainAdmissionBoundary::testnet()
            .replay_historical(&mut state, &block, &AcceptAllForEmptyBlock)
            .unwrap();
        assert_eq!(receipt.mode, BlockApplicationMode::HistoricalReplay);
        assert_eq!(receipt.reference_time, None);
        assert_eq!(receipt.timestamp_policy, None);
        assert_eq!(state.height(), 1);
    }

    #[test]
    fn reference_source_policy_matches_shared_cp0026g_vectors() {
        use std::collections::BTreeMap;
        use std::path::PathBuf;

        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../simulations/cp0026g_reference_time_source_vectors.txt");
        let contents = std::fs::read_to_string(path).expect("read CP-0026-G vectors");
        let lines: Vec<_> = contents.lines().collect();
        assert_eq!(
            lines.first(),
            Some(&"CP0026G_REFERENCE_TIME_SOURCE_POLICY_V1")
        );
        assert_eq!(lines.last(), Some(&"END"));
        let mut cases = Vec::<BTreeMap<String, String>>::new();
        let mut current = BTreeMap::<String, String>::new();
        for line in lines.iter().skip(1).take_while(|line| **line != "END") {
            let (key, value) = line.split_once('=').expect("key=value vector record");
            if key == "CASE" && !current.is_empty() {
                cases.push(std::mem::take(&mut current));
            }
            assert!(current.insert(key.to_string(), value.to_string()).is_none());
        }
        if !current.is_empty() {
            cases.push(current);
        }
        assert_eq!(cases.len(), 9);
        for case in cases {
            let policy = match case["POLICY"].as_str() {
                "SystemClockOrConfiguredProvider" => {
                    ReferenceTimeSourcePolicy::SystemClockOrConfiguredProvider
                }
                "ConfiguredProviderOnly" => ReferenceTimeSourcePolicy::ConfiguredProviderOnly,
                "AllowTestFixtures" => ReferenceTimeSourcePolicy::AllowTestFixtures,
                other => panic!("unknown policy {other}"),
            };
            let provenance = match case["PROVENANCE"].as_str() {
                "LocalSystemClock" => ReferenceTimeProvenance::LocalSystemClock,
                "ConfiguredProvider" => ReferenceTimeProvenance::ConfiguredProvider,
                "DeterministicTestFixture" => ReferenceTimeProvenance::DeterministicTestFixture,
                other => panic!("unknown provenance {other}"),
            };
            let expected = case["EXPECTED"] == "ACCEPT";
            assert_eq!(policy.accepts(provenance), expected, "{}", case["CASE"]);
        }
    }

    #[test]
    fn configured_reference_source_requires_a_nonempty_label() {
        let mut state = state();
        let before = state.encode_snapshot().unwrap();
        let block = empty_block(&state, 100);
        let unlabeled = clock(100, ReferenceTimeProvenance::ConfiguredProvider, "");
        assert_eq!(
            ChainAdmissionBoundary::testnet().admit_live(
                &mut state,
                &block,
                &AcceptAllForEmptyBlock,
                &unlabeled,
            ),
            Err(ChainAdmissionError::ReferenceTimeSourceUnlabeled(
                ReferenceTimeProvenance::ConfiguredProvider
            ))
        );
        assert_eq!(state.encode_snapshot().unwrap(), before);
    }

    #[test]
    fn authenticated_time_policy_rejection_is_not_reported_as_plain_outage() {
        struct BadAttestation;
        impl ReferenceTimeProvider for BadAttestation {
            fn sample(&self) -> Result<ReferenceTimeSample, ReferenceTimeError> {
                Err(ReferenceTimeError::AuthoritySignatureInvalid)
            }
        }
        let mut state = state();
        let before = state.encode_snapshot().unwrap();
        let block = empty_block(&state, 100);
        assert_eq!(
            ChainAdmissionBoundary::testnet().admit_live(
                &mut state,
                &block,
                &AcceptAllForEmptyBlock,
                &BadAttestation,
            ),
            Err(ChainAdmissionError::ReferenceTimeRejected(
                ReferenceTimeError::AuthoritySignatureInvalid
            ))
        );
        assert_eq!(state.encode_snapshot().unwrap(), before);
    }

    #[test]
    fn provider_failure_rejects_without_state_mutation() {
        let mut state = state();
        let before = state.encode_snapshot().unwrap();
        let block = empty_block(&state, 100);
        assert_eq!(
            ChainAdmissionBoundary::testnet().admit_live(
                &mut state,
                &block,
                &AcceptAllForEmptyBlock,
                &FailingClock,
            ),
            Err(ChainAdmissionError::ReferenceTimeUnavailable(
                ReferenceTimeError::ProviderUnavailable
            ))
        );
        assert_eq!(state.encode_snapshot().unwrap(), before);
    }

    #[test]
    fn monetary_live_admission_uses_same_clock_source_and_timestamp_guards() {
        let mut state = monetary_state();
        let block = empty_monetary_block(&state, 220);
        let receipt = ChainAdmissionBoundary::testnet()
            .admit_live_monetary(
                &mut state,
                &block,
                &AcceptAllForEmptyBlock,
                &clock(
                    100,
                    ReferenceTimeProvenance::ConfiguredProvider,
                    "operator-clock-monetary",
                ),
            )
            .unwrap();
        assert_eq!(receipt.mode, BlockApplicationMode::LiveAdmission);
        assert_eq!(
            receipt.reference_time.unwrap().source_id,
            "operator-clock-monetary"
        );
        assert_eq!(state.height(), 1);
        assert_eq!(
            state.total_mined_atoms(),
            state.ledger().account(&[3; 32]).unwrap().balance as u128
        );
    }

    #[test]
    fn monetary_live_admission_rejects_over_future_timestamp_atomically() {
        let mut state = monetary_state();
        let before = state.encode_snapshot().unwrap();
        let block = empty_monetary_block(&state, 221);
        let error = ChainAdmissionBoundary::testnet()
            .admit_live_monetary(
                &mut state,
                &block,
                &AcceptAllForEmptyBlock,
                &clock(
                    100,
                    ReferenceTimeProvenance::LocalSystemClock,
                    "local-test-clock",
                ),
            )
            .unwrap_err();
        assert_eq!(
            error,
            ChainAdmissionError::State(StateError::TimestampTooFarInFuture {
                latest_allowed: 220,
                actual: 221,
            })
        );
        assert_eq!(state.encode_snapshot().unwrap(), before);
    }

    fn signed_v4_transaction(manifest_id: [u8; 32]) -> V4HybridTransaction {
        let ed_signer = SigningKey::from_bytes(&[0x31; 32]);
        let ed_public_key = ed_signer.verifying_key().to_bytes();
        let pq_pair = portable::generate_key_pair([0x42; 32]);
        let mldsa65_public_key: [u8; ML_DSA_65_PUBLIC_KEY_BYTES] =
            *pq_pair.verification_key.as_ref();
        let authorization = V4HybridAuthorization {
            network_id: NETWORK,
            manifest_id,
            sender_id: native_v4_account_id(&ed_public_key, &mldsa65_public_key),
            recipient_id: [0xCC; 32],
            nonce: 1,
            amount_atoms: 500,
            fee_atoms: 7,
            expires_at: 1_000,
            identity_scheme: AccountIdentityScheme::NativeV4Hybrid,
            ed25519_public_key: ed_public_key,
            mldsa65_public_key,
        };
        let digest = authorization.signing_digest().unwrap();
        let ed25519_signature = ed_signer.sign(&digest).to_bytes();
        let mldsa65_signature: [u8; ML_DSA_65_SIGNATURE_BYTES] =
            *portable::sign(&pq_pair.signing_key, &digest, &[], [0x53; 32])
                .unwrap()
                .as_ref();
        V4HybridTransaction {
            authorization,
            signature: V4HybridSignature {
                ed25519_signature,
                mldsa65_signature,
            },
        }
    }

    fn v4_monetary_state(tx: &V4HybridTransaction) -> MonetaryLedgerState {
        let sender_allocation = 1_000_000u64;
        MonetaryLedgerState::genesis(
            NETWORK,
            [1; 32],
            vec![
                (tx.authorization.sender_id, sender_allocation),
                (
                    [2; 32],
                    (MONETARY_PUBLIC_GOODS_BUDGET_ATOMS - u128::from(sender_allocation)) as u64,
                ),
            ],
        )
        .unwrap()
    }

    fn v4_monetary_block(
        state: &MonetaryLedgerState,
        tx: V4HybridTransaction,
        timestamp: u64,
        manifest_id: &[u8; 32],
    ) -> V4HybridMonetaryBlock {
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let mut block = V4HybridMonetaryBlock {
            height: state.height() + 1,
            timestamp,
            parent_hash: state.tip_hash(),
            state_root: [0; 32],
            transactions: vec![tx],
            miner: [3; 32],
            claimed_subsidy_atoms: state.expected_miner_reward().unwrap(),
        };
        block.state_root = state
            .preview_v4_hybrid_state_root_after(&block, manifest_id, &verifier)
            .unwrap();
        block
    }

    #[test]
    fn mbk4_live_admission_uses_clock_policy_and_commits_real_hybrid_transfer() {
        let manifest_id = [0xB2; 32];
        let tx = signed_v4_transaction(manifest_id);
        let sender = tx.authorization.sender_id;
        let mut state = v4_monetary_state(&tx);
        let initial_sender_balance = state.ledger().account(&sender).unwrap().balance;
        let block = v4_monetary_block(&state, tx, 220, &manifest_id);
        let params = ConsensusParameters::candidate_testnet().unwrap();
        let header = PowHeader {
            protocol_version: params.protocol_version,
            network_id: NETWORK,
            height: block.height,
            timestamp: block.timestamp,
            parent_hash: block.parent_hash,
            previous_consensus_hash: state.tip_hash(),
            state_root: block.state_root,
            target: params.initial_target,
            nonce: 0x0102_0304_0506_0708,
        };
        let wire = encode_candidate_v4_hybrid_monetary_network_block(&header, &block).unwrap();
        let decoded = decode_candidate_v4_hybrid_monetary_network_block(&wire).unwrap();
        assert_eq!(decoded.header, header);
        assert_eq!(decoded.block, block);
        let block = decoded.block;

        let receipt = ChainAdmissionBoundary::testnet()
            .admit_live_v4_hybrid_monetary(
                &mut state,
                &block,
                &manifest_id,
                &LibcruxMlDsa65VerifierCandidate,
                &clock(
                    100,
                    ReferenceTimeProvenance::ConfiguredProvider,
                    "operator-clock-mbk4",
                ),
            )
            .unwrap();
        assert_eq!(receipt.mode, BlockApplicationMode::LiveAdmission);
        assert_eq!(
            receipt.reference_time.unwrap().source_id,
            "operator-clock-mbk4"
        );
        assert_eq!(state.height(), 1);
        assert_eq!(
            state.ledger().account(&sender).unwrap().balance,
            initial_sender_balance - 507
        );
        assert_eq!(state.ledger().account(&[0xCC; 32]).unwrap().balance, 500);
    }

    #[test]
    fn mbk4_live_admission_rejects_future_timestamp_atomically() {
        let manifest_id = [0xB2; 32];
        let tx = signed_v4_transaction(manifest_id);
        let mut state = v4_monetary_state(&tx);
        let before = state.encode_snapshot().unwrap();
        let block = v4_monetary_block(&state, tx, 221, &manifest_id);

        assert_eq!(
            ChainAdmissionBoundary::testnet().admit_live_v4_hybrid_monetary(
                &mut state,
                &block,
                &manifest_id,
                &LibcruxMlDsa65VerifierCandidate,
                &clock(
                    100,
                    ReferenceTimeProvenance::LocalSystemClock,
                    "local-test-clock",
                ),
            ),
            Err(ChainAdmissionError::State(
                StateError::TimestampTooFarInFuture {
                    latest_allowed: 220,
                    actual: 221,
                }
            ))
        );
        assert_eq!(state.encode_snapshot().unwrap(), before);
    }

    #[test]
    fn monetary_historical_replay_uses_deterministic_transition_without_clock() {
        let mut state = monetary_state();
        let block = empty_monetary_block(&state, 10_000);
        let receipt = ChainAdmissionBoundary::testnet()
            .replay_monetary(&mut state, &block, &AcceptAllForEmptyBlock)
            .unwrap();
        assert_eq!(receipt.mode, BlockApplicationMode::HistoricalReplay);
        assert_eq!(receipt.reference_time, None);
        assert_eq!(receipt.timestamp_policy, None);
        assert_eq!(state.height(), 1);
    }
}
