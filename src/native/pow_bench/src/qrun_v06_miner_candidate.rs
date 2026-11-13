//! CP-0569 QFP6 branch-local block-template construction and bounded Argon2id mining.
//!
//! Mining always derives its target from the exact parent branch retained by QFP6 fork choice.
//! The resulting QFP6/QFB6 envelope is decoded and verified again before it is returned.
//! This module does not mutate fork choice or durable storage: callers must submit the returned
//! envelope through QFP6 admission and QAP1 before advertising or acknowledging it.
//!
//! The nonce loop is deliberately bounded and cooperatively cancellable. It is a single-threaded
//! mining primitive, not yet a production miner pool, fee/mempool selector or node event loop.

use crate::{
    consensus::{pow_digest, ConsensusError, PowHeader, Uint256},
    qrun_v06_canonical_execution_candidate::{
        QRunV06Block, QRunV06BlockOperation, QRunV06CanonicalExecutionState, QRunV06ExecutionError,
    },
    qrun_v06_pow_fork_choice_candidate::{
        QRunV06ForkChoiceError, QRunV06PowForkChoice, QRunV06QuoteAssetAuthorizationProvider,
    },
    qrun_v06_pow_wire_candidate::{
        decode_qrun_v06_pow_block, encode_qrun_v06_pow_block, qrun_v06_pow_state_commitment,
        verify_qrun_v06_pow_block, QRunV06PowWireError,
    },
    state_machine::TransactionAuthenticator,
};
use std::sync::atomic::{AtomicBool, Ordering};

pub const QRUN_V06_MAX_NONCE_ATTEMPTS_PER_JOB: u64 = 1_000_000;
pub const QRUN_V06_PROTOCOL_VERSION: u16 = 6;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QRunV06MiningError {
    InvalidNonceBudget,
    InvalidProducer,
    InvalidTimestamp,
    WrongProtocolVersion,
    InvalidTarget,
    HeightOverflow,
    Cancelled,
    NonceBudgetExhausted { next_nonce: u64 },
    NonceSpaceExhausted,
    MissingQuoteAssetAuthorization,
    QuoteAssetAuthorizationProvider(String),
    Execution(QRunV06ExecutionError),
    Consensus(ConsensusError),
    ForkChoice(QRunV06ForkChoiceError),
    Wire(QRunV06PowWireError),
}

impl std::fmt::Display for QRunV06MiningError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "QFP6 candidate miner rejected/exhausted work: {self:?}")
    }
}
impl std::error::Error for QRunV06MiningError {}

impl From<QRunV06ExecutionError> for QRunV06MiningError {
    fn from(value: QRunV06ExecutionError) -> Self {
        Self::Execution(value)
    }
}
impl From<ConsensusError> for QRunV06MiningError {
    fn from(value: ConsensusError) -> Self {
        Self::Consensus(value)
    }
}
impl From<QRunV06ForkChoiceError> for QRunV06MiningError {
    fn from(value: QRunV06ForkChoiceError) -> Self {
        Self::ForkChoice(value)
    }
}
impl From<QRunV06PowWireError> for QRunV06MiningError {
    fn from(value: QRunV06PowWireError) -> Self {
        Self::Wire(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06MinedBlock {
    pub height: u64,
    pub nonce: u64,
    pub target: Uint256,
    pub block_digest: [u8; 32],
    /// Canonical QFB6 state root computed from the parent state and candidate operations.
    pub execution_state_root: [u8; 32],
    /// Complete QFP6 envelope. It is not yet durably admitted or externally anchored.
    pub envelope: Vec<u8>,
}

/// Construct and mine one block on the exact requested QFP6 parent branch.
///
/// The function reads consensus parameters and target history from the supplied fork-choice
/// instance. A caller cannot pass a different target/profile alongside the same branch graph.
/// After success, the caller must submit the envelope to the durable runtime; this function
/// never updates the canonical tip or publishes a Q6PA acknowledgement.
pub fn mine_qfp6_block_on_tip_from_nonce<A: TransactionAuthenticator>(
    fork_choice: &QRunV06PowForkChoice,
    parent_consensus_tip: &[u8; 32],
    timestamp: u64,
    producer: [u8; 32],
    operations: Vec<QRunV06BlockOperation>,
    authenticator: &A,
    nonce_start: u64,
    max_nonce_attempts: u64,
    cancellation: &AtomicBool,
) -> Result<QRunV06MinedBlock, QRunV06MiningError> {
    mine_qfp6_block_on_tip_inner(
        fork_choice,
        parent_consensus_tip,
        timestamp,
        producer,
        operations,
        authenticator,
        nonce_start,
        max_nonce_attempts,
        cancellation,
        None,
    )
}

/// Mine one bounded batch from nonce zero. This compatibility wrapper preserves the original API.
pub fn mine_qfp6_block_on_tip<A: TransactionAuthenticator>(
    fork_choice: &QRunV06PowForkChoice,
    parent_consensus_tip: &[u8; 32],
    timestamp: u64,
    producer: [u8; 32],
    operations: Vec<QRunV06BlockOperation>,
    authenticator: &A,
    max_nonce_attempts: u64,
    cancellation: &AtomicBool,
) -> Result<QRunV06MinedBlock, QRunV06MiningError> {
    mine_qfp6_block_on_tip_from_nonce(
        fork_choice,
        parent_consensus_tip,
        timestamp,
        producer,
        operations,
        authenticator,
        0,
        max_nonce_attempts,
        cancellation,
    )
}

/// Quote-aware variant for a block that uses an externally authorized non-native market asset.
/// The provider must obtain a fresh height-bound Q6TS/Q6QA authorization for the exact parent,
/// block and asset. The caller must obtain a fresh authorization again during fork-choice import
/// and subsequent QAP1 durable admission; the preview token is not embedded in the wire block.
pub fn mine_qfp6_block_on_tip_with_quote_asset_authorization<A: TransactionAuthenticator>(
    fork_choice: &QRunV06PowForkChoice,
    parent_consensus_tip: &[u8; 32],
    timestamp: u64,
    producer: [u8; 32],
    operations: Vec<QRunV06BlockOperation>,
    authenticator: &A,
    quote_authorizer: &mut QRunV06QuoteAssetAuthorizationProvider<'_>,
    max_nonce_attempts: u64,
    cancellation: &AtomicBool,
) -> Result<QRunV06MinedBlock, QRunV06MiningError> {
    mine_qfp6_block_on_tip_inner(
        fork_choice,
        parent_consensus_tip,
        timestamp,
        producer,
        operations,
        authenticator,
        0,
        max_nonce_attempts,
        cancellation,
        Some(quote_authorizer),
    )
}

fn mine_qfp6_block_on_tip_inner<A: TransactionAuthenticator>(
    fork_choice: &QRunV06PowForkChoice,
    parent_consensus_tip: &[u8; 32],
    timestamp: u64,
    producer: [u8; 32],
    operations: Vec<QRunV06BlockOperation>,
    authenticator: &A,
    nonce_start: u64,
    max_nonce_attempts: u64,
    cancellation: &AtomicBool,
    mut quote_authorizer: Option<&mut QRunV06QuoteAssetAuthorizationProvider<'_>>,
) -> Result<QRunV06MinedBlock, QRunV06MiningError> {
    if max_nonce_attempts == 0 || max_nonce_attempts > QRUN_V06_MAX_NONCE_ATTEMPTS_PER_JOB {
        return Err(QRunV06MiningError::InvalidNonceBudget);
    }
    let nonce_end = nonce_start
        .checked_add(max_nonce_attempts)
        .ok_or(QRunV06MiningError::NonceSpaceExhausted)?;
    if producer == [0; 32] {
        return Err(QRunV06MiningError::InvalidProducer);
    }

    let params = fork_choice.consensus_parameters();
    params.validate()?;
    if params.protocol_version != QRUN_V06_PROTOCOL_VERSION {
        return Err(QRunV06MiningError::WrongProtocolVersion);
    }
    if cancellation.load(Ordering::Acquire) {
        return Err(QRunV06MiningError::Cancelled);
    }

    let parent_state: &QRunV06CanonicalExecutionState = fork_choice
        .state_for_tip(parent_consensus_tip)
        .ok_or(QRunV06MiningError::ForkChoice(
            QRunV06ForkChoiceError::UnknownParent,
        ))?;
    if timestamp <= parent_state.last_timestamp() {
        return Err(QRunV06MiningError::InvalidTimestamp);
    }
    let height = parent_state
        .height()
        .checked_add(1)
        .ok_or(QRunV06MiningError::HeightOverflow)?;
    let target = fork_choice.expected_next_target(parent_consensus_tip)?;
    if target.is_zero() || target > params.pow_limit {
        return Err(QRunV06MiningError::InvalidTarget);
    }

    let mut block = QRunV06Block {
        network_id: parent_state.network_id(),
        profile_id: parent_state.profile_id(),
        height,
        timestamp,
        parent_hash: parent_state.tip_hash(),
        state_root: [0; 32],
        producer,
        operations,
    };
    let quote_authorization = match parent_state.required_quote_asset_for_block(&block)? {
        Some(asset_id) => {
            let authorize = quote_authorizer
                .as_deref_mut()
                .ok_or(QRunV06MiningError::MissingQuoteAssetAuthorization)?;
            Some(
                authorize(parent_state, &block, asset_id)
                    .map_err(QRunV06MiningError::QuoteAssetAuthorizationProvider)?,
            )
        }
        None => None,
    };
    block.state_root = parent_state.preview_state_root_after_with_quote_asset_authorization(
        &block,
        authenticator,
        quote_authorization.as_ref(),
    )?;
    let execution_state_root = block.state_root;
    let mut header = PowHeader {
        protocol_version: QRUN_V06_PROTOCOL_VERSION,
        network_id: block.network_id,
        height: block.height,
        timestamp: block.timestamp,
        parent_hash: block.parent_hash,
        previous_consensus_hash: *parent_consensus_tip,
        state_root: qrun_v06_pow_state_commitment(&block)?,
        target,
        nonce: nonce_start,
    };

    for nonce in nonce_start..nonce_end {
        if cancellation.load(Ordering::Acquire) {
            return Err(QRunV06MiningError::Cancelled);
        }
        header.nonce = nonce;
        let digest = pow_digest(&header, params.pow)?;
        if Uint256::from_be_bytes(digest) <= target {
            let envelope = encode_qrun_v06_pow_block(&header, &block)?;
            let decoded = decode_qrun_v06_pow_block(&envelope)?;
            let verified_digest = verify_qrun_v06_pow_block(&decoded, params)?;
            if verified_digest != digest {
                return Err(QRunV06MiningError::Wire(
                    QRunV06PowWireError::HeaderBodyMismatch("mined_digest"),
                ));
            }
            return Ok(QRunV06MinedBlock {
                height,
                nonce,
                target,
                block_digest: digest,
                execution_state_root,
                envelope,
            });
        }
    }

    Err(QRunV06MiningError::NonceBudgetExhausted {
        next_nonce: nonce_end,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        consensus::{ConsensusParameters, PowAlgorithm, PowParameters},
        qrun_v06_asset_registry_candidate::{
            AssetRegistration, AssetSupplyPolicy, AssetTrustPolicy,
        },
        qrun_v06_canonical_execution_candidate::QRunV06BlockOperation,
        qrun_v06_genesis_descriptor_candidate::QRunV06GenesisDescriptor,
        qrun_v06_pow_fork_choice_candidate::QRunV06PowForkChoice,
        qrun_v06_profile_trust_candidate::test_trust_authorized_quote_asset_candidate,
        qrun_v06_tokenomics_candidate::{QRunV06MiningScheduleCandidate, QRunV06TokenomicsState},
        qzxb_amm_candidate::{qzxb_native_asset_id, AmmOperation, AmmSignedOperation},
        state_machine::AccountId,
    };
    use std::sync::atomic::AtomicBool;

    const NETWORK: [u8; 32] = [0xA1; 32];
    const PROFILE: [u8; 32] = [0xA2; 32];
    const OWNER: [u8; 32] = [0xA3; 32];
    const PRODUCER: [u8; 32] = [0xA4; 32];

    struct EmptyAuthenticator;
    impl TransactionAuthenticator for EmptyAuthenticator {
        fn verify(&self, _: &AccountId, _: &[u8; 32], _: &[u8]) -> Result<(), ()> {
            Err(())
        }
    }

    struct DigestAuthenticator;
    impl TransactionAuthenticator for DigestAuthenticator {
        fn verify(
            &self,
            sender: &AccountId,
            digest: &[u8; 32],
            signature: &[u8],
        ) -> Result<(), ()> {
            if *sender != [0; 32] && signature == digest {
                Ok(())
            } else {
                Err(())
            }
        }
    }

    fn params(initial_target: Uint256) -> ConsensusParameters {
        let mut params = ConsensusParameters::candidate_testnet().unwrap();
        params.protocol_version = QRUN_V06_PROTOCOL_VERSION;
        params.target_block_time_secs = 30;
        params.difficulty_window_blocks = 2;
        params.difficulty_min_ratio_divisor = 4;
        params.difficulty_max_ratio = 4;
        params.initial_target = initial_target;
        params.pow_limit = Uint256::MAX;
        params.pow = PowParameters {
            algorithm: PowAlgorithm::Argon2id,
            memory_kib: 8,
            iterations: 1,
            lanes: 1,
            output_bytes: 32,
        };
        params.validate().unwrap();
        params
    }

    fn setup(
        initial_target: Uint256,
    ) -> (
        ConsensusParameters,
        QRunV06CanonicalExecutionState,
        QRunV06PowForkChoice,
    ) {
        setup_with_params(params(initial_target))
    }

    fn setup_with_params(
        params: ConsensusParameters,
    ) -> (
        ConsensusParameters,
        QRunV06CanonicalExecutionState,
        QRunV06PowForkChoice,
    ) {
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

    #[test]
    fn miner_builds_a_branch_local_qfp6_envelope_that_fork_choice_accepts() {
        let (params, _genesis, mut graph) = setup(Uint256::MAX);
        let parent_tip = graph.canonical_tip().tip_hash;
        let cancellation = AtomicBool::new(false);
        let mined = mine_qfp6_block_on_tip(
            &graph,
            &parent_tip,
            31,
            PRODUCER,
            Vec::<QRunV06BlockOperation>::new(),
            &EmptyAuthenticator,
            1,
            &cancellation,
        )
        .unwrap();

        assert_eq!(mined.height, 1);
        assert_eq!(mined.nonce, 0);
        assert_eq!(mined.target, params.initial_target);
        let imported = graph
            .insert_encoded(&mined.envelope, &EmptyAuthenticator)
            .unwrap();
        assert_eq!(imported.canonical_height, 1);
        assert_eq!(imported.canonical_tip, mined.block_digest);
        assert_eq!(graph.canonical_state().height(), 1);
    }

    #[test]
    fn qfp6_miner_and_fork_choice_use_the_sha256d_v06_profile() {
        let mut sha256d_params = params(Uint256::MAX);
        sha256d_params.pow = PowParameters {
            algorithm: PowAlgorithm::Sha256d,
            memory_kib: 0,
            iterations: 0,
            lanes: 0,
            output_bytes: 32,
        };
        sha256d_params.validate().unwrap();
        let (params, _genesis, mut graph) = setup_with_params(sha256d_params);
        let parent_tip = graph.canonical_tip().tip_hash;
        let cancellation = AtomicBool::new(false);
        let mined = mine_qfp6_block_on_tip(
            &graph,
            &parent_tip,
            31,
            PRODUCER,
            Vec::<QRunV06BlockOperation>::new(),
            &EmptyAuthenticator,
            1,
            &cancellation,
        )
        .unwrap();
        let imported = graph
            .insert_encoded(&mined.envelope, &EmptyAuthenticator)
            .unwrap();
        assert_eq!(imported.canonical_height, 1);
        assert_eq!(imported.canonical_tip, mined.block_digest);
        assert_eq!(graph.canonical_state().height(), 1);
        assert_eq!(params.pow.algorithm, PowAlgorithm::Sha256d);
    }

    #[test]
    fn miner_cancels_before_nonce_work_and_rejects_unbounded_budgets() {
        let (_params, _genesis, graph) = setup(Uint256::MAX);
        let parent_tip = graph.canonical_tip().tip_hash;
        let cancelled = AtomicBool::new(true);
        assert_eq!(
            mine_qfp6_block_on_tip(
                &graph,
                &parent_tip,
                31,
                PRODUCER,
                Vec::new(),
                &EmptyAuthenticator,
                1,
                &cancelled,
            ),
            Err(QRunV06MiningError::Cancelled)
        );
        let not_cancelled = AtomicBool::new(false);
        assert_eq!(
            mine_qfp6_block_on_tip(
                &graph,
                &parent_tip,
                31,
                PRODUCER,
                Vec::new(),
                &EmptyAuthenticator,
                0,
                &not_cancelled,
            ),
            Err(QRunV06MiningError::InvalidNonceBudget)
        );
        assert_eq!(
            mine_qfp6_block_on_tip(
                &graph,
                &parent_tip,
                31,
                PRODUCER,
                Vec::new(),
                &EmptyAuthenticator,
                QRUN_V06_MAX_NONCE_ATTEMPTS_PER_JOB + 1,
                &not_cancelled,
            ),
            Err(QRunV06MiningError::InvalidNonceBudget)
        );
    }

    #[test]
    fn miner_enforces_a_finite_nonce_budget_without_publishing_a_candidate() {
        let (_params, _genesis, graph) = setup(Uint256::from_be_bytes([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ]));
        let parent_tip = graph.canonical_tip().tip_hash;
        let not_cancelled = AtomicBool::new(false);
        assert_eq!(
            mine_qfp6_block_on_tip(
                &graph,
                &parent_tip,
                31,
                PRODUCER,
                Vec::new(),
                &EmptyAuthenticator,
                1,
                &not_cancelled,
            ),
            Err(QRunV06MiningError::NonceBudgetExhausted { next_nonce: 1 })
        );
        assert_eq!(graph.canonical_state().height(), 0);
    }

    #[test]
    fn miner_fails_closed_instead_of_wrapping_the_nonce_space() {
        let (_params, _genesis, graph) = setup(Uint256::MAX);
        let parent_tip = graph.canonical_tip().tip_hash;
        let cancellation = AtomicBool::new(false);
        assert_eq!(
            mine_qfp6_block_on_tip_from_nonce(
                &graph,
                &parent_tip,
                31,
                PRODUCER,
                Vec::new(),
                &EmptyAuthenticator,
                u64::MAX,
                1,
                &cancellation,
            ),
            Err(QRunV06MiningError::NonceSpaceExhausted)
        );
    }

    #[test]
    fn miner_starts_at_the_requested_nonce_instead_of_restarting_at_zero() {
        let (_params, _genesis, graph) = setup(Uint256::MAX);
        let parent_tip = graph.canonical_tip().tip_hash;
        let cancellation = AtomicBool::new(false);
        let mined = mine_qfp6_block_on_tip_from_nonce(
            &graph,
            &parent_tip,
            31,
            PRODUCER,
            Vec::new(),
            &EmptyAuthenticator,
            123,
            1,
            &cancellation,
        )
        .unwrap();
        assert_eq!(mined.nonce, 123);
    }

    #[test]
    fn quote_aware_miner_requires_fresh_authorization_and_builds_importable_amm_block() {
        const Q6QA_COMMITMENT: [u8; 32] = [0xB1; 32];
        const Q6PN_COMMITMENT: [u8; 32] = [0xB2; 32];

        let (_params, _genesis, mut graph) = setup(Uint256::MAX);
        let cancellation = AtomicBool::new(false);
        let genesis_tip = graph.canonical_tip().tip_hash;
        let mut registration = AssetRegistration {
            network_id: NETWORK,
            issuer: OWNER,
            issuer_nonce: 1,
            salt: [0xB3; 32],
            name: "QRun quote asset fixture".to_string(),
            symbol: "QRTST".to_string(),
            decimals: 6,
            supply_policy: AssetSupplyPolicy::Fixed {
                total_supply: 1_000,
            },
            initial_supply: 1_000,
            initial_recipient: OWNER,
            trust_policy: AssetTrustPolicy::Unverified,
            expires_at: 10_000,
            signature: Vec::new(),
        };
        registration.signature = registration.signing_digest().unwrap().to_vec();
        let quote_asset = registration.asset_id();

        let registration_block = mine_qfp6_block_on_tip(
            &graph,
            &genesis_tip,
            31,
            PRODUCER,
            vec![QRunV06BlockOperation::AssetRegistration(registration)],
            &DigestAuthenticator,
            1,
            &cancellation,
        )
        .unwrap();
        graph
            .insert_encoded(&registration_block.envelope, &DigestAuthenticator)
            .unwrap();

        let parent_tip = graph.canonical_tip().tip_hash;
        let native_asset = qzxb_native_asset_id(NETWORK).unwrap();
        let mut create_pair = AmmSignedOperation {
            network_id: NETWORK,
            sender: OWNER,
            nonce: 1,
            expires_at: 10_000,
            operation: AmmOperation::CreatePair {
                token_a: native_asset,
                token_b: quote_asset,
            },
            signature: Vec::new(),
        };
        create_pair.signature = create_pair.signing_digest().unwrap().to_vec();
        let operations = vec![QRunV06BlockOperation::Amm(create_pair)];

        assert_eq!(
            mine_qfp6_block_on_tip(
                &graph,
                &parent_tip,
                62,
                PRODUCER,
                operations.clone(),
                &DigestAuthenticator,
                1,
                &cancellation,
            ),
            Err(QRunV06MiningError::MissingQuoteAssetAuthorization)
        );

        let mut mine_authorizer =
            |_: &QRunV06CanonicalExecutionState, block: &QRunV06Block, asset_id: [u8; 32]| {
                Ok(test_trust_authorized_quote_asset_candidate(
                    NETWORK,
                    PROFILE,
                    asset_id,
                    Q6QA_COMMITMENT,
                    Q6PN_COMMITMENT,
                    3,
                    1,
                    100,
                    1,
                    block.height,
                ))
            };
        let mined = mine_qfp6_block_on_tip_with_quote_asset_authorization(
            &graph,
            &parent_tip,
            62,
            PRODUCER,
            operations,
            &DigestAuthenticator,
            &mut mine_authorizer,
            1,
            &cancellation,
        )
        .unwrap();
        let mut import_authorizer =
            |_: &QRunV06CanonicalExecutionState, block: &QRunV06Block, asset_id: [u8; 32]| {
                Ok(test_trust_authorized_quote_asset_candidate(
                    NETWORK,
                    PROFILE,
                    asset_id,
                    Q6QA_COMMITMENT,
                    Q6PN_COMMITMENT,
                    3,
                    1,
                    100,
                    1,
                    block.height,
                ))
            };
        graph
            .insert_encoded_with_quote_asset_authorization(
                &mined.envelope,
                &DigestAuthenticator,
                &mut import_authorizer,
            )
            .unwrap();
        assert_eq!(graph.canonical_state().height(), 2);
        assert_eq!(
            graph
                .canonical_state()
                .quote_asset_authorization_commitment(),
            Some(Q6QA_COMMITMENT)
        );
        assert_eq!(graph.canonical_state().unified().amm().pair_count(), 1);
    }

    #[test]
    fn miner_refuses_unknown_parent_and_non_increasing_timestamp() {
        let (_params, _genesis, graph) = setup(Uint256::MAX);
        let not_cancelled = AtomicBool::new(false);
        assert!(matches!(
            mine_qfp6_block_on_tip(
                &graph,
                &[0xFF; 32],
                31,
                PRODUCER,
                Vec::new(),
                &EmptyAuthenticator,
                1,
                &not_cancelled,
            ),
            Err(QRunV06MiningError::ForkChoice(
                QRunV06ForkChoiceError::UnknownParent
            ))
        ));
        let tip = graph.canonical_tip().tip_hash;
        assert_eq!(
            mine_qfp6_block_on_tip(
                &graph,
                &tip,
                1,
                PRODUCER,
                Vec::new(),
                &EmptyAuthenticator,
                1,
                &not_cancelled,
            ),
            Err(QRunV06MiningError::InvalidTimestamp)
        );
    }
}
