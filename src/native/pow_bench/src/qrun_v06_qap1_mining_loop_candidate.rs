//! CP-0569/0568 integration: bounded local block production through QAP1 durable admission.
//!
//! This is a single-writer, sequential mining loop. Every candidate is mined on the exact
//! retained parent branch, independently replayed into a staged fork-choice copy, and submitted
//! through the already-recovered QAP1 runtime. The staged in-memory view is advanced only after
//! QAP1 returns an ACK-safe admission. The template callback owns transaction selection and
//! block-time pacing; this module does not invent rewards, wallet keys, quote-asset trust or
//! transaction fees. It is not a public listener/broadcast daemon or Mainnet launcher.

use crate::{
    external_cas_anchor_candidate::ExternalCasProviderTransport,
    qrun_v06_canonical_execution_candidate::{
        QRunV06BlockOperation, QRunV06CanonicalExecutionState,
    },
    qrun_v06_miner_candidate::{
        mine_qfp6_block_on_tip_with_quote_asset_authorization, QRunV06MinedBlock,
        QRunV06MiningError, QRUN_V06_MAX_NONCE_ATTEMPTS_PER_JOB,
    },
    qrun_v06_node_runtime_candidate::{
        QRunV06NodeAdmission, QRunV06NodeAnchorGate, QRunV06NodeRuntime,
    },
    qrun_v06_pow_fork_choice_candidate::{
        QRunV06PowForkChoice, QRunV06QuoteAssetAuthorizationProvider,
    },
    qrun_v06_qap1_coordinator_candidate::{
        QRunV06Qap1AnchorTransport, QRunV06Qap1ExternalCoordinator,
    },
    state_machine::TransactionAuthenticator,
    v4_fat1_trust_candidate::MlDsa65Verifier,
};
use std::sync::atomic::AtomicBool;

pub const QRUN_V06_QAP1_MINING_MAX_BLOCKS_PER_RUN: u64 = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QRunV06Qap1MiningLoopConfig {
    /// Finite process-run budget. Restart only after the runtime has completed QAP1 recovery.
    pub max_blocks_per_run: u64,
    /// Finite Argon2id nonce search budget for each candidate.
    pub max_nonce_attempts_per_block: u64,
}

impl Default for QRunV06Qap1MiningLoopConfig {
    fn default() -> Self {
        Self {
            max_blocks_per_run: 16,
            max_nonce_attempts_per_block: QRUN_V06_MAX_NONCE_ATTEMPTS_PER_JOB,
        }
    }
}

impl QRunV06Qap1MiningLoopConfig {
    pub fn validate(&self) -> Result<(), QRunV06Qap1MiningLoopError> {
        if !(1..=QRUN_V06_QAP1_MINING_MAX_BLOCKS_PER_RUN).contains(&self.max_blocks_per_run)
            || self.max_nonce_attempts_per_block == 0
            || self.max_nonce_attempts_per_block > QRUN_V06_MAX_NONCE_ATTEMPTS_PER_JOB
        {
            return Err(QRunV06Qap1MiningLoopError::InvalidConfiguration);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QRunV06Qap1MiningLoopError {
    InvalidConfiguration,
    RuntimeNotQap1Recovered,
    RuntimeRequiresReopen,
    PendingExternalAnchor,
    ForkChoiceAnchorMismatch,
    Template(String),
    Mining(String),
    ForkChoice(String),
    Admission(String),
    AdmissionNotAcknowledged,
    StatisticsOverflow,
}

impl std::fmt::Display for QRunV06Qap1MiningLoopError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "QFP6 QAP1 mining loop refused/stopped: {self:?}")
    }
}
impl std::error::Error for QRunV06Qap1MiningLoopError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06Qap1MiningStep {
    pub mined: QRunV06MinedBlock,
    pub admission: QRunV06NodeAdmission,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QRunV06Qap1MiningStopReason {
    ShutdownRequested,
    BlockBudgetReached,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QRunV06Qap1MiningLoopReport {
    pub blocks_acknowledged: u64,
    pub starting_height: u64,
    pub ending_height: u64,
    pub ending_tip: [u8; 32],
    pub last_block_digest: Option<[u8; 32]>,
    pub stop_reason: QRunV06Qap1MiningStopReason,
}

fn validate_runtime_ready<A: QRunV06NodeAnchorGate>(
    runtime: &QRunV06NodeRuntime<A>,
) -> Result<(), QRunV06Qap1MiningLoopError> {
    if !runtime.requires_qap1() || !runtime.qap1_recovery_verified() {
        return Err(QRunV06Qap1MiningLoopError::RuntimeNotQap1Recovered);
    }
    if runtime.requires_reopen() {
        return Err(QRunV06Qap1MiningLoopError::RuntimeRequiresReopen);
    }
    if runtime.has_pending_external_anchor() {
        return Err(QRunV06Qap1MiningLoopError::PendingExternalAnchor);
    }
    Ok(())
}

/// Verify that the independently anchored Q6EA view and supplied in-memory fork-choice graph
/// describe the same QFP6 canonical state before mining or after a QAP1 commit.
fn validate_anchor_graph(
    anchor: &crate::qrun_v06_external_anchor_candidate::QRunV06ExternalAnchorState,
    fork_choice: &QRunV06PowForkChoice,
) -> Result<(), QRunV06Qap1MiningLoopError> {
    let params = fork_choice.consensus_parameters();
    params
        .validate()
        .map_err(|error| QRunV06Qap1MiningLoopError::ForkChoice(error.to_string()))?;
    // Q6EA/Manifest intentionally use the Store fingerprint domain. The separate
    // Checkpoint fingerprint domain must not be substituted here.
    let fingerprint = crate::qrun_v06_pow_fork_store_candidate::consensus_fingerprint(params)
        .map_err(|error| QRunV06Qap1MiningLoopError::ForkChoice(error.to_string()))?;
    let tip = fork_choice.canonical_tip();
    let state = fork_choice.canonical_state();
    let descriptor_commitment = state
        .genesis_descriptor_commitment()
        .ok_or(QRunV06Qap1MiningLoopError::ForkChoiceAnchorMismatch)?;
    let state_root = state
        .state_root()
        .map_err(|error| QRunV06Qap1MiningLoopError::ForkChoice(format!("{error:?}")))?;
    let chainwork = fork_choice
        .branch_work(&tip.tip_hash)
        .ok_or(QRunV06Qap1MiningLoopError::ForkChoiceAnchorMismatch)?
        .to_be_bytes();

    if anchor.network_id != fork_choice.network_id()
        || anchor.profile_id != fork_choice.profile_id()
        || anchor.consensus_fingerprint != fingerprint
        || anchor.genesis_descriptor_commitment != descriptor_commitment
        || anchor.segment_base_height != fork_choice.base_height()
        || anchor.segment_base_tip != fork_choice.base_tip()
        || anchor.canonical_height != tip.height
        || anchor.canonical_tip != tip.tip_hash
        || anchor.canonical_state_root != state_root
        || anchor.cumulative_chainwork != chainwork
    {
        return Err(QRunV06Qap1MiningLoopError::ForkChoiceAnchorMismatch);
    }
    Ok(())
}

/// Mine exactly one block and submit it through QAP1. The in-memory fork-choice copy is staged
/// first, but is replaced only after an ACK-safe durable QAP1 admission succeeds.
#[allow(clippy::too_many_arguments)]
pub fn mine_and_admit_qap1_block<A, T, P, PV, AV, Q>(
    runtime: &mut QRunV06NodeRuntime<A>,
    fork_choice: &mut QRunV06PowForkChoice,
    timestamp: u64,
    producer: [u8; 32],
    operations: Vec<QRunV06BlockOperation>,
    authenticator: &T,
    quote_authorizer: &mut QRunV06QuoteAssetAuthorizationProvider<'_>,
    coordinator: &mut QRunV06Qap1ExternalCoordinator<P, PV, AV, Q>,
    max_nonce_attempts: u64,
    shutdown: &AtomicBool,
) -> Result<QRunV06Qap1MiningStep, QRunV06Qap1MiningLoopError>
where
    A: QRunV06NodeAnchorGate,
    T: TransactionAuthenticator,
    P: ExternalCasProviderTransport,
    PV: MlDsa65Verifier + Clone,
    AV: MlDsa65Verifier,
    Q: QRunV06Qap1AnchorTransport,
{
    validate_runtime_ready(runtime)?;
    validate_anchor_graph(runtime.committed_anchor_state(), fork_choice)?;

    let parent_tip = fork_choice.canonical_tip().tip_hash;
    let mined = mine_qfp6_block_on_tip_with_quote_asset_authorization(
        fork_choice,
        &parent_tip,
        timestamp,
        producer,
        operations,
        authenticator,
        quote_authorizer,
        max_nonce_attempts,
        shutdown,
    )
    .map_err(|error: QRunV06MiningError| QRunV06Qap1MiningLoopError::Mining(error.to_string()))?;

    // Prove the candidate is importable on the same branch before external QAP1 writes begin.
    let mut staged = fork_choice.clone();
    staged
        .insert_encoded_with_quote_asset_authorization(
            &mined.envelope,
            authenticator,
            quote_authorizer,
        )
        .map_err(|error| QRunV06Qap1MiningLoopError::ForkChoice(error.to_string()))?;

    let admission = runtime
        .submit_envelope_with_qap1(
            &mined.envelope,
            authenticator,
            quote_authorizer,
            coordinator,
        )
        .map_err(|error| QRunV06Qap1MiningLoopError::Admission(error.to_string()))?;
    if !admission.is_acknowledged() {
        return Err(QRunV06Qap1MiningLoopError::AdmissionNotAcknowledged);
    }

    // A successful durable admission must produce exactly the state staged above. If not,
    // stop the worker: the QAP1 store is committed and the in-memory graph must be rebuilt.
    validate_anchor_graph(runtime.committed_anchor_state(), &staged)?;
    *fork_choice = staged;

    Ok(QRunV06Qap1MiningStep { mined, admission })
}

/// Execute a bounded, sequential mining loop. The callback supplies a timestamp and canonical
/// operations for the current parent state; it must enforce block-time policy, transaction
/// selection and reward/fee rules. The same QAP1 runtime and fork-choice view are retained across
/// iterations. Shutdown is checked between blocks and by the nonce loop.
#[allow(clippy::too_many_arguments)]
pub fn run_qfp6_qap1_mining_loop<A, T, P, PV, AV, Q, F>(
    runtime: &mut QRunV06NodeRuntime<A>,
    fork_choice: &mut QRunV06PowForkChoice,
    producer: [u8; 32],
    authenticator: &T,
    quote_authorizer: &mut QRunV06QuoteAssetAuthorizationProvider<'_>,
    coordinator: &mut QRunV06Qap1ExternalCoordinator<P, PV, AV, Q>,
    config: QRunV06Qap1MiningLoopConfig,
    shutdown: &AtomicBool,
    mut next_template: F,
) -> Result<QRunV06Qap1MiningLoopReport, QRunV06Qap1MiningLoopError>
where
    A: QRunV06NodeAnchorGate,
    T: TransactionAuthenticator,
    P: ExternalCasProviderTransport,
    PV: MlDsa65Verifier + Clone,
    AV: MlDsa65Verifier,
    Q: QRunV06Qap1AnchorTransport,
    F: FnMut(&QRunV06CanonicalExecutionState) -> Result<(u64, Vec<QRunV06BlockOperation>), String>,
{
    config.validate()?;
    validate_runtime_ready(runtime)?;
    validate_anchor_graph(runtime.committed_anchor_state(), fork_choice)?;

    let starting_height = fork_choice.canonical_tip().height;
    let mut blocks_acknowledged = 0u64;
    let mut last_block_digest = None;
    let mut stop_reason = QRunV06Qap1MiningStopReason::BlockBudgetReached;

    while blocks_acknowledged < config.max_blocks_per_run {
        if shutdown.load(std::sync::atomic::Ordering::Acquire) {
            stop_reason = QRunV06Qap1MiningStopReason::ShutdownRequested;
            break;
        }
        let parent = fork_choice.canonical_state().clone();
        let (timestamp, operations) =
            next_template(&parent).map_err(QRunV06Qap1MiningLoopError::Template)?;
        let step = match mine_and_admit_qap1_block(
            runtime,
            fork_choice,
            timestamp,
            producer,
            operations,
            authenticator,
            quote_authorizer,
            coordinator,
            config.max_nonce_attempts_per_block,
            shutdown,
        ) {
            Ok(step) => step,
            Err(QRunV06Qap1MiningLoopError::Mining(_))
                if shutdown.load(std::sync::atomic::Ordering::Acquire) =>
            {
                stop_reason = QRunV06Qap1MiningStopReason::ShutdownRequested;
                break;
            }
            Err(error) => return Err(error),
        };
        if !step.admission.is_acknowledged() {
            return Err(QRunV06Qap1MiningLoopError::AdmissionNotAcknowledged);
        }
        blocks_acknowledged = blocks_acknowledged
            .checked_add(1)
            .ok_or(QRunV06Qap1MiningLoopError::StatisticsOverflow)?;
        last_block_digest = Some(step.mined.block_digest);
    }

    let tip = fork_choice.canonical_tip();
    Ok(QRunV06Qap1MiningLoopReport {
        blocks_acknowledged,
        starting_height,
        ending_height: tip.height,
        ending_tip: tip.tip_hash,
        last_block_digest,
        stop_reason,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        consensus::{ConsensusParameters, PowAlgorithm, PowParameters, Uint256},
        qrun_v06_genesis_descriptor_candidate::QRunV06GenesisDescriptor,
        qrun_v06_tokenomics_candidate::{QRunV06MiningScheduleCandidate, QRunV06TokenomicsState},
    };

    const NETWORK: [u8; 32] = [0xC1; 32];
    const PROFILE: [u8; 32] = [0xC2; 32];
    const OWNER: [u8; 32] = [0xC3; 32];

    fn setup() -> (
        ConsensusParameters,
        QRunV06CanonicalExecutionState,
        QRunV06PowForkChoice,
    ) {
        let mut params = ConsensusParameters::candidate_testnet().unwrap();
        params.protocol_version = 6;
        params.target_block_time_secs = 30;
        params.difficulty_window_blocks = 2;
        params.difficulty_min_ratio_divisor = 4;
        params.difficulty_max_ratio = 4;
        params.initial_target = Uint256::MAX;
        params.pow_limit = Uint256::MAX;
        params.pow = PowParameters {
            algorithm: PowAlgorithm::Argon2id,
            memory_kib: 8,
            iterations: 1,
            lanes: 1,
            output_bytes: 32,
        };
        params.validate().unwrap();

        let schedule = QRunV06MiningScheduleCandidate::cp0422_research_candidate();
        let tokenomics = QRunV06TokenomicsState::genesis(NETWORK, OWNER, schedule).unwrap();
        let descriptor = QRunV06GenesisDescriptor::new(
            NETWORK,
            PROFILE,
            OWNER,
            1,
            crate::qrun_v06_checkpoint_candidate::qrun_v06_consensus_fingerprint(&params).unwrap(),
            tokenomics.policy_fingerprint(),
        )
        .unwrap();
        let genesis = QRunV06CanonicalExecutionState::cp0528_genesis_candidate_with_descriptor(
            descriptor, schedule,
        )
        .unwrap();
        let commitment = genesis.genesis_descriptor_commitment().unwrap();
        let graph = QRunV06PowForkChoice::new_with_expected_genesis_descriptor_commitment(
            genesis.clone(),
            params.clone(),
            commitment,
        )
        .unwrap();
        (params, genesis, graph)
    }

    fn anchor_for(
        params: &ConsensusParameters,
        genesis: &QRunV06CanonicalExecutionState,
        graph: &QRunV06PowForkChoice,
    ) -> crate::qrun_v06_external_anchor_candidate::QRunV06ExternalAnchorState {
        let tip = graph.canonical_tip();
        crate::qrun_v06_external_anchor_candidate::QRunV06ExternalAnchorState {
            network_id: NETWORK,
            genesis_digest: [0xC4; 32],
            genesis_descriptor_commitment: genesis.genesis_descriptor_commitment().unwrap(),
            profile_id: PROFILE,
            consensus_fingerprint: crate::qrun_v06_pow_fork_store_candidate::consensus_fingerprint(
                params,
            )
            .unwrap(),
            segment_base_height: graph.base_height(),
            segment_base_tip: graph.base_tip(),
            checkpoint_anchor: [0; 32],
            manifest_generation: 0,
            manifest_anchor: [0xC5; 32],
            canonical_height: tip.height,
            canonical_tip: tip.tip_hash,
            canonical_state_root: graph.canonical_state().state_root().unwrap(),
            cumulative_chainwork: graph.branch_work(&tip.tip_hash).unwrap().to_be_bytes(),
        }
    }

    #[test]
    fn anchor_binding_requires_exact_genesis_consensus_tip_and_chainwork() {
        let (params, genesis, graph) = setup();
        let anchor = anchor_for(&params, &genesis, &graph);
        // Store/Q6EA and Checkpoint are separately domain-separated commitments.
        assert_ne!(
            crate::qrun_v06_pow_fork_store_candidate::consensus_fingerprint(&params).unwrap(),
            crate::qrun_v06_checkpoint_candidate::qrun_v06_consensus_fingerprint(&params).unwrap()
        );
        assert!(validate_anchor_graph(&anchor, &graph).is_ok());

        let mut wrong_tip = anchor.clone();
        wrong_tip.canonical_tip[0] ^= 1;
        assert_eq!(
            validate_anchor_graph(&wrong_tip, &graph),
            Err(QRunV06Qap1MiningLoopError::ForkChoiceAnchorMismatch)
        );

        let mut wrong_work = anchor.clone();
        wrong_work.cumulative_chainwork[31] ^= 1;
        assert_eq!(
            validate_anchor_graph(&wrong_work, &graph),
            Err(QRunV06Qap1MiningLoopError::ForkChoiceAnchorMismatch)
        );

        let mut wrong_descriptor = anchor;
        wrong_descriptor.genesis_descriptor_commitment[0] ^= 1;
        assert_eq!(
            validate_anchor_graph(&wrong_descriptor, &graph),
            Err(QRunV06Qap1MiningLoopError::ForkChoiceAnchorMismatch)
        );
    }

    #[test]
    fn mining_loop_configuration_is_finite_and_fail_closed() {
        assert!(QRunV06Qap1MiningLoopConfig::default().validate().is_ok());
        assert_eq!(
            QRunV06Qap1MiningLoopConfig {
                max_blocks_per_run: 0,
                max_nonce_attempts_per_block: 1,
            }
            .validate(),
            Err(QRunV06Qap1MiningLoopError::InvalidConfiguration)
        );
        assert_eq!(
            QRunV06Qap1MiningLoopConfig {
                max_blocks_per_run: 1,
                max_nonce_attempts_per_block: QRUN_V06_MAX_NONCE_ATTEMPTS_PER_JOB + 1,
            }
            .validate(),
            Err(QRunV06Qap1MiningLoopError::InvalidConfiguration)
        );
    }
}
