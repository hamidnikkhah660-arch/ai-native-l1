//! CP-0441 candidate: replay canonical QZBE history in bounded-height segments.
//!
//! The caller supplies envelopes in canonical height order immediately after the frozen Genesis.
//! Each checkpoint is derived from the prior validated segment, never trusted from disk. This
//! bounds in-memory fork choice while retaining end-to-end replay from Genesis. Durable full-history
//! retention, independent peer qualification and Mainnet activation remain separate requirements.

use crate::{
    consensus::{ConsensusParameters, Uint256},
    monetary_pow_v04_candidate::{
        V04ExecutionForkChoiceCandidate, V04ExecutionPowEnvelope, V04ExecutionPowError,
        MAX_V04_EXECUTION_FORK_ARCHIVE_HEIGHT,
    },
    monetary_pow_v04_checkpoint_candidate::QzbeCheckpointValidationContext,
    monetary_transition_v04_candidate::MonetaryLedgerStateV04TransitionCandidate,
    state_machine::TransactionAuthenticator,
};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QzbeHistoryReplaySummary {
    pub height: u64,
    pub tip: [u8; 32],
    pub state_root: [u8; 32],
    pub cumulative_chainwork: Uint256,
    pub blocks_replayed: u64,
    pub checkpoint_rotations: u64,
}

#[derive(Debug)]
pub enum QzbeHistoryReplayError {
    InvalidSegmentLimit,
    Decode(String),
    NonCanonicalHeight { expected: u64, actual: u64 },
    NonCanonicalParent,
    Replay(String),
    Checkpoint(String),
    StateRoot(String),
}

impl fmt::Display for QzbeHistoryReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for QzbeHistoryReplayError {}

/// Validate and execute canonical history from Genesis using a bounded in-memory fork-choice
/// segment. max_segment_blocks must be in 1..=MAX_V04_EXECUTION_FORK_ARCHIVE_HEIGHT.
///
/// Checkpoints are generated solely from the executed state and supplied only to the next
/// in-memory segment. A caller must retain the complete source archive and reconcile the replay
/// result with pinned peers before treating recovery as READY.
pub fn replay_canonical_history_from_genesis<'a, I, A>(
    context: &QzbeCheckpointValidationContext<'_>,
    params: &ConsensusParameters,
    envelopes: I,
    authenticator: &A,
    max_segment_blocks: u64,
) -> Result<QzbeHistoryReplaySummary, QzbeHistoryReplayError>
where
    I: IntoIterator<Item = &'a [u8]>,
    A: TransactionAuthenticator,
{
    if max_segment_blocks == 0
        || max_segment_blocks > MAX_V04_EXECUTION_FORK_ARCHIVE_HEIGHT
        || context.params != params
    {
        return Err(QzbeHistoryReplayError::InvalidSegmentLimit);
    }

    let genesis = MonetaryLedgerStateV04TransitionCandidate::from_genesis_manifest(
        context.manifest,
        context.profile,
    )
    .map_err(|error| QzbeHistoryReplayError::Replay(format!("{error:?}")))?;
    let mut fork = V04ExecutionForkChoiceCandidate::new(genesis, params.clone())
        .map_err(|error| QzbeHistoryReplayError::Replay(error.to_string()))?;

    // Bind each derived checkpoint to the exact Genesis checkpoint commitment.
    let genesis_checkpoint = fork
        .canonical_checkpoint_record(context, [0; 32])
        .map_err(|error| QzbeHistoryReplayError::Checkpoint(error.to_string()))?;
    let mut parent_checkpoint_commitment = genesis_checkpoint
        .commitment(context)
        .map_err(|error| QzbeHistoryReplayError::Checkpoint(error.to_string()))?;

    let mut blocks_replayed = 0u64;
    let mut segment_blocks = 0u64;
    let mut checkpoint_rotations = 0u64;

    for encoded in envelopes {
        let envelope = V04ExecutionPowEnvelope::decode(encoded, context.profile, params)
            .map_err(|error| QzbeHistoryReplayError::Decode(error.to_string()))?;
        let expected_height = fork.canonical_height().checked_add(1).ok_or(
            QzbeHistoryReplayError::NonCanonicalHeight {
                expected: u64::MAX,
                actual: envelope.header.height,
            },
        )?;
        if envelope.header.height != expected_height {
            return Err(QzbeHistoryReplayError::NonCanonicalHeight {
                expected: expected_height,
                actual: envelope.header.height,
            });
        }
        if envelope.header.previous_consensus_hash != fork.canonical_tip() {
            return Err(QzbeHistoryReplayError::NonCanonicalParent);
        }

        let outcome = fork.insert_encoded(encoded, authenticator).map_err(
            |error: V04ExecutionPowError| QzbeHistoryReplayError::Replay(error.to_string()),
        )?;
        if !outcome.canonical_changed
            || outcome.canonical_tip != fork.canonical_tip()
            || fork.canonical_height() != expected_height
        {
            return Err(QzbeHistoryReplayError::Replay(
                "envelope did not become the next canonical block".into(),
            ));
        }

        blocks_replayed = blocks_replayed
            .checked_add(1)
            .ok_or_else(|| QzbeHistoryReplayError::Replay("block counter overflow".into()))?;
        segment_blocks = segment_blocks
            .checked_add(1)
            .ok_or_else(|| QzbeHistoryReplayError::Replay("segment counter overflow".into()))?;

        if segment_blocks == max_segment_blocks {
            let checkpoint = fork
                .canonical_checkpoint_record(context, parent_checkpoint_commitment)
                .map_err(|error| QzbeHistoryReplayError::Checkpoint(error.to_string()))?;
            parent_checkpoint_commitment = checkpoint
                .commitment(context)
                .map_err(|error| QzbeHistoryReplayError::Checkpoint(error.to_string()))?;
            fork = V04ExecutionForkChoiceCandidate::from_checkpoint_record(
                &checkpoint,
                context,
                params.clone(),
            )
            .map_err(|error| QzbeHistoryReplayError::Checkpoint(error.to_string()))?;
            segment_blocks = 0;
            checkpoint_rotations = checkpoint_rotations.checked_add(1).ok_or_else(|| {
                QzbeHistoryReplayError::Replay("checkpoint counter overflow".into())
            })?;
        }
    }

    let state_root = fork
        .canonical_state()
        .state_root()
        .map_err(|error| QzbeHistoryReplayError::StateRoot(format!("{error:?}")))?;
    Ok(QzbeHistoryReplaySummary {
        height: fork.canonical_height(),
        tip: fork.canonical_tip(),
        state_root,
        cumulative_chainwork: fork.canonical_cumulative_work(),
        blocks_replayed,
        checkpoint_rotations,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        monetary_genesis_v04_candidate::GenesisManifestV04,
        monetary_issuance_v04_candidate::V04MiningIssuanceScheduleCandidate,
        monetary_pow_v04_candidate::{
            V04ExecutionForkChoiceCandidate, MAX_V04_EXECUTION_FORK_ARCHIVE_HEIGHT,
        },
        monetary_transition_v04_candidate::V04ConsensusProfileCandidate,
        state_machine::{AccountId, TransactionAuthenticator},
    };

    const NETWORK: [u8; 32] = [0x31; 32];
    const OWNER: [u8; 32] = [0xA7; 32];

    struct NoTransactionAuth;
    impl TransactionAuthenticator for NoTransactionAuth {
        fn verify(&self, _: &AccountId, _: &[u8; 32], _: &[u8]) -> Result<(), ()> {
            Err(())
        }
    }

    fn fixture() -> (
        GenesisManifestV04,
        V04ConsensusProfileCandidate,
        ConsensusParameters,
    ) {
        let manifest = GenesisManifestV04::new(NETWORK, OWNER).unwrap();
        let schedule = V04MiningIssuanceScheduleCandidate::new(35_673_515_981, 4_204_800).unwrap();
        let profile =
            V04ConsensusProfileCandidate::from_manifest_and_schedule(&manifest, schedule).unwrap();
        let mut params = ConsensusParameters::candidate_testnet().unwrap();
        params.initial_target = Uint256::MAX;
        params.pow_limit = Uint256::MAX;
        params.pow.memory_kib = 8 * 1024;
        (manifest, profile, params)
    }

    fn canonical_fixture_history(
        manifest: &GenesisManifestV04,
        profile: &V04ConsensusProfileCandidate,
        params: &ConsensusParameters,
        block_count: u64,
    ) -> (Vec<Vec<u8>>, V04ExecutionForkChoiceCandidate) {
        let genesis =
            MonetaryLedgerStateV04TransitionCandidate::from_genesis_manifest(manifest, profile)
                .unwrap();
        let mut fork = V04ExecutionForkChoiceCandidate::new(genesis, params.clone()).unwrap();
        let auth = NoTransactionAuth;
        let mut history = Vec::new();
        for height in 1..=block_count {
            let encoded = fork
                .mine_candidate_on(
                    fork.canonical_tip(),
                    height * params.target_block_time_secs,
                    [height as u8; 32],
                    Vec::new(),
                    1,
                    1,
                    &auth,
                    || false,
                )
                .unwrap();
            let outcome = fork.insert_encoded(&encoded, &auth).unwrap();
            assert!(outcome.canonical_changed);
            history.push(encoded);
        }
        (history, fork)
    }

    #[test]
    fn segmented_genesis_replay_matches_tip_root_and_chainwork() {
        let (manifest, profile, params) = fixture();
        let (history, source) = canonical_fixture_history(&manifest, &profile, &params, 5);
        let context = QzbeCheckpointValidationContext {
            manifest: &manifest,
            profile: &profile,
            params: &params,
        };
        let summary = replay_canonical_history_from_genesis(
            &context,
            &params,
            history.iter().map(Vec::as_slice),
            &NoTransactionAuth,
            2,
        )
        .unwrap();

        assert_eq!(summary.height, source.canonical_height());
        assert_eq!(summary.tip, source.canonical_tip());
        assert_eq!(
            summary.state_root,
            source.canonical_state().state_root().unwrap()
        );
        assert_eq!(
            summary.cumulative_chainwork,
            source.canonical_cumulative_work()
        );
        assert_eq!(summary.blocks_replayed, 5);
        assert_eq!(summary.checkpoint_rotations, 2);
    }

    #[test]
    fn segmented_replay_rejects_gaps_reordering_and_bad_segment_limits() {
        let (manifest, profile, params) = fixture();
        let (history, _) = canonical_fixture_history(&manifest, &profile, &params, 4);
        let context = QzbeCheckpointValidationContext {
            manifest: &manifest,
            profile: &profile,
            params: &params,
        };
        let reordered = vec![
            history[1].as_slice(),
            history[0].as_slice(),
            history[2].as_slice(),
            history[3].as_slice(),
        ];
        assert!(replay_canonical_history_from_genesis(
            &context,
            &params,
            reordered,
            &NoTransactionAuth,
            2,
        )
        .is_err());
        assert!(replay_canonical_history_from_genesis(
            &context,
            &params,
            history.iter().map(Vec::as_slice),
            &NoTransactionAuth,
            0,
        )
        .is_err());
        assert!(replay_canonical_history_from_genesis(
            &context,
            &params,
            history.iter().map(Vec::as_slice),
            &NoTransactionAuth,
            MAX_V04_EXECUTION_FORK_ARCHIVE_HEIGHT + 1,
        )
        .is_err());
    }

    #[test]
    fn replay_of_empty_history_returns_genesis_state() {
        let (manifest, profile, params) = fixture();
        let context = QzbeCheckpointValidationContext {
            manifest: &manifest,
            profile: &profile,
            params: &params,
        };
        let summary = replay_canonical_history_from_genesis(
            &context,
            &params,
            std::iter::empty(),
            &NoTransactionAuth,
            2,
        )
        .unwrap();
        assert_eq!(summary.height, 0);
        assert_eq!(summary.blocks_replayed, 0);
        assert_eq!(summary.checkpoint_rotations, 0);
        assert_eq!(summary.cumulative_chainwork, Uint256::ZERO);
    }
}
