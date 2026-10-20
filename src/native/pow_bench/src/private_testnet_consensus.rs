//! Candidate private-testnet consensus admission for CP-W.
//!
//! This layer deliberately composes the existing canonical state-machine block body with
//! the candidate PoW header without changing the legacy Block wire format. It is the bridge
//! for private-testnet experiments; it is not yet canonical network consensus.

use crate::{
    chain_admission::{
        BlockAdmissionReceipt, ChainAdmissionBoundary, ChainAdmissionError, ReferenceTimeProvider,
    },
    consensus::{verify_pow, ConsensusError, ConsensusParameters, PowHeader, Uint256},
    state_machine::{Block, LedgerState, TransactionAuthenticator},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivateConsensusError {
    Consensus(ConsensusError),
    Admission(ChainAdmissionError),
    HeaderBodyMismatch(&'static str),
    NetworkMismatch,
    ExpectedTargetMismatch,
    LegacyBlockOnMonetaryChain,
    MonetaryBlockOnLegacyChain,
}

impl std::fmt::Display for PrivateConsensusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Consensus(error) => write!(f, "consensus validation failed: {error}"),
            Self::Admission(error) => write!(f, "state admission failed: {error:?}"),
            Self::HeaderBodyMismatch(field) => {
                write!(f, "PoW header does not match block body field {field}")
            }
            Self::NetworkMismatch => write!(f, "PoW network ID does not match chain state"),
            Self::ExpectedTargetMismatch => write!(f, "PoW target does not match expected target"),
            Self::LegacyBlockOnMonetaryChain => {
                write!(f, "legacy BLK2 block is forbidden on a monetary chain")
            }
            Self::MonetaryBlockOnLegacyChain => {
                write!(f, "MBK3 monetary block is forbidden on a legacy chain")
            }
        }
    }
}

impl std::error::Error for PrivateConsensusError {}

impl From<ConsensusError> for PrivateConsensusError {
    fn from(error: ConsensusError) -> Self {
        Self::Consensus(error)
    }
}

impl From<ChainAdmissionError> for PrivateConsensusError {
    fn from(error: ChainAdmissionError) -> Self {
        Self::Admission(error)
    }
}

/// Candidate block validation inputs. The existing Block remains the canonical body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CandidateConsensusBlock<'a> {
    pub block: &'a Block,
    pub pow_header: &'a PowHeader,
}

/// Check body bindings and the expected previous PoW consensus digest before state execution.
pub fn validate_header_binding(
    state: &LedgerState,
    candidate: CandidateConsensusBlock<'_>,
    expected_previous_consensus_hash: [u8; 32],
    expected_target: Uint256,
    params: &ConsensusParameters,
) -> Result<(), PrivateConsensusError> {
    params.validate()?;

    let block = candidate.block;
    let header = candidate.pow_header;

    if header.network_id != state.network_id() {
        return Err(PrivateConsensusError::NetworkMismatch);
    }
    if header.protocol_version != params.protocol_version {
        return Err(PrivateConsensusError::HeaderBodyMismatch(
            "protocol_version",
        ));
    }
    if header.height != block.height {
        return Err(PrivateConsensusError::HeaderBodyMismatch("height"));
    }
    if header.timestamp != block.timestamp {
        return Err(PrivateConsensusError::HeaderBodyMismatch("timestamp"));
    }
    if header.parent_hash != block.parent_hash {
        return Err(PrivateConsensusError::HeaderBodyMismatch("parent_hash"));
    }
    if header.previous_consensus_hash != expected_previous_consensus_hash {
        return Err(PrivateConsensusError::HeaderBodyMismatch(
            "previous_consensus_hash",
        ));
    }
    if header.state_root != block.state_root {
        return Err(PrivateConsensusError::HeaderBodyMismatch("state_root"));
    }
    if header.target != expected_target {
        return Err(PrivateConsensusError::ExpectedTargetMismatch);
    }

    Ok(())
}

/// Validate PoW and then pass the body through the existing timestamp/state admission boundary.
///
/// The explicit expected_target is intentional: a future testnet driver will derive it from
/// the frozen difficulty history rules. This function therefore cannot accidentally invent a
/// second target-selection algorithm.
pub fn admit_live<A: TransactionAuthenticator>(
    state: &mut LedgerState,
    candidate: CandidateConsensusBlock<'_>,
    expected_previous_consensus_hash: [u8; 32],
    expected_target: Uint256,
    params: &ConsensusParameters,
    authenticator: &A,
    clock: &dyn ReferenceTimeProvider,
) -> Result<(BlockAdmissionReceipt, [u8; 32]), PrivateConsensusError> {
    validate_header_binding(
        state,
        candidate,
        expected_previous_consensus_hash,
        expected_target,
        params,
    )?;
    let digest = verify_pow(candidate.pow_header, params)?;
    let receipt = ChainAdmissionBoundary::testnet().admit_live(
        state,
        candidate.block,
        authenticator,
        clock,
    )?;
    Ok((receipt, digest))
}

/// Candidate target selection policy for a testnet driver.
///
/// Before a retarget boundary the previous target is carried forward. At a boundary, the
/// caller supplies the measured elapsed duration for the configured difficulty window and
/// this function applies the exact clamped integer retarget rule.
pub fn target_for_next_block(
    previous_target: Uint256,
    next_height: u64,
    measured_window_elapsed_secs: Option<u64>,
    params: &ConsensusParameters,
) -> Result<Uint256, PrivateConsensusError> {
    params.validate()?;
    if next_height == 0 {
        return Err(PrivateConsensusError::Consensus(
            ConsensusError::InvalidNextBlockHeight,
        ));
    }
    if previous_target.is_zero() {
        return Err(PrivateConsensusError::Consensus(
            ConsensusError::InvalidTarget,
        ));
    }
    if previous_target > params.pow_limit {
        return Err(PrivateConsensusError::Consensus(
            ConsensusError::TargetAbovePowLimit,
        ));
    }

    let window = params.difficulty_window_blocks;
    // The first window consists of blocks 1..=window. The retarget therefore
    // determines the target for the following block, window+1.
    if next_height <= window || (next_height - 1) % window != 0 {
        return Ok(previous_target);
    }

    let elapsed = measured_window_elapsed_secs.ok_or(PrivateConsensusError::Consensus(
        ConsensusError::MissingRetargetObservation,
    ))?;
    Ok(crate::consensus::retarget_target(
        previous_target,
        elapsed,
        params,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chain_admission::{ReferenceTimeProvenance, ReferenceTimeSample},
        consensus::PowHeader,
        state_machine::StateError,
    };

    struct EmptyBlockAuthenticator;

    impl TransactionAuthenticator for EmptyBlockAuthenticator {
        fn verify(&self, _: &[u8; 32], _: &[u8; 32], _: &[u8]) -> Result<(), ()> {
            Ok(())
        }
    }

    struct FixedClock;

    impl ReferenceTimeProvider for FixedClock {
        fn sample(
            &self,
        ) -> Result<ReferenceTimeSample, crate::chain_admission::ReferenceTimeError> {
            Ok(ReferenceTimeSample {
                unix_seconds: 100,
                provenance: ReferenceTimeProvenance::ConfiguredProvider,
                source_id: "private-testnet-fixed-clock",
            })
        }
    }

    fn state() -> LedgerState {
        LedgerState::genesis([0xA7; 32], vec![([1; 32], 1_000)]).unwrap()
    }

    fn body(state: &LedgerState, timestamp: u64) -> Block {
        let mut block = Block {
            height: state.height() + 1,
            timestamp,
            parent_hash: state.tip_hash(),
            state_root: [0; 32],
            transactions: Vec::new(),
        };
        block.state_root = state
            .preview_state_root_after(&block, &EmptyBlockAuthenticator)
            .unwrap();
        block
    }

    fn header_for(
        state: &LedgerState,
        block: &Block,
        params: &ConsensusParameters,
        target: Uint256,
        nonce: u64,
    ) -> PowHeader {
        PowHeader {
            protocol_version: params.protocol_version,
            network_id: state.network_id(),
            height: block.height,
            timestamp: block.timestamp,
            parent_hash: block.parent_hash,
            previous_consensus_hash: state.tip_hash(),
            state_root: block.state_root,
            target,
            nonce,
        }
    }

    #[test]
    fn valid_private_testnet_candidate_checks_pow_then_state() {
        let mut params = ConsensusParameters::candidate_testnet().unwrap();
        params.pow_limit = Uint256::MAX;
        let target = Uint256::MAX;

        let mut state = state();
        let block = body(&state, 100);
        let header = header_for(&state, &block, &params, target, 0);
        let expected_previous = state.tip_hash();
        let (receipt, digest) = admit_live(
            &mut state,
            CandidateConsensusBlock {
                block: &block,
                pow_header: &header,
            },
            expected_previous,
            target,
            &params,
            &EmptyBlockAuthenticator,
            &FixedClock,
        )
        .unwrap();

        assert_eq!(receipt.summary.height, 1);
        assert_eq!(state.height(), 1);
        assert!(Uint256::from_be_bytes(digest) <= target);
    }

    #[test]
    fn mismatched_header_rejects_without_mutating_state() {
        let params = ConsensusParameters::candidate_testnet().unwrap();
        let state = state();
        let block = body(&state, 100);
        let mut header = header_for(&state, &block, &params, params.initial_target, 0);
        header.state_root[0] ^= 1;

        let before = state.encode_snapshot().unwrap();
        assert_eq!(
            validate_header_binding(
                &state,
                CandidateConsensusBlock {
                    block: &block,
                    pow_header: &header,
                },
                state.tip_hash(),
                params.initial_target,
                &params,
            ),
            Err(PrivateConsensusError::HeaderBodyMismatch("state_root"))
        );
        assert_eq!(state.encode_snapshot().unwrap(), before);
    }

    #[test]
    fn mismatched_previous_consensus_hash_rejects_without_mutating_state() {
        let params = ConsensusParameters::candidate_testnet().unwrap();
        let state = state();
        let block = body(&state, 100);
        let mut header = header_for(&state, &block, &params, params.initial_target, 0);
        header.previous_consensus_hash[0] ^= 1;
        let expected_previous = state.tip_hash();
        let before = state.encode_snapshot().unwrap();
        assert_eq!(
            validate_header_binding(
                &state,
                CandidateConsensusBlock {
                    block: &block,
                    pow_header: &header
                },
                expected_previous,
                params.initial_target,
                &params,
            ),
            Err(PrivateConsensusError::HeaderBodyMismatch(
                "previous_consensus_hash"
            ))
        );
        assert_eq!(state.encode_snapshot().unwrap(), before);
    }

    #[test]
    fn bad_pow_rejects_before_state_execution() {
        let mut params = ConsensusParameters::candidate_testnet().unwrap();
        params.pow_limit = Uint256::MAX;
        let permissive_target = Uint256::MAX;
        let mut state = state();
        let block = body(&state, 100);
        // Force a known rejection by using target zero while binding it as the expected target.
        let zero_target = Uint256::ZERO;
        let header = header_for(&state, &block, &params, zero_target, 0);
        let expected_previous = state.tip_hash();
        let before = state.encode_snapshot().unwrap();

        assert_eq!(
            admit_live(
                &mut state,
                CandidateConsensusBlock {
                    block: &block,
                    pow_header: &header,
                },
                expected_previous,
                zero_target,
                &params,
                &EmptyBlockAuthenticator,
                &FixedClock,
            ),
            Err(PrivateConsensusError::Consensus(
                ConsensusError::InvalidTarget
            ))
        );
        assert_eq!(state.encode_snapshot().unwrap(), before);
        let _ = permissive_target;
    }

    #[test]
    fn target_must_equal_driver_expectation() {
        let params = ConsensusParameters::candidate_testnet().unwrap();
        let state = state();
        let block = body(&state, 100);
        let header = header_for(&state, &block, &params, params.initial_target, 0);
        assert_eq!(
            validate_header_binding(
                &state,
                CandidateConsensusBlock {
                    block: &block,
                    pow_header: &header,
                },
                state.tip_hash(),
                Uint256::from_be_bytes([
                    0x00, 0x80, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0
                ]),
                &params,
            ),
            Err(PrivateConsensusError::ExpectedTargetMismatch)
        );
    }

    #[test]
    fn target_driver_carries_target_between_boundaries_and_retargets_at_boundary() {
        let params = ConsensusParameters::candidate_testnet().unwrap();
        let previous = Uint256::from_be_bytes({
            let mut bytes = [0u8; 32];
            bytes[31] = 100;
            bytes
        });
        let expected = params.target_block_time_secs * params.difficulty_window_blocks;

        assert_eq!(
            target_for_next_block(previous, 1, None, &params).unwrap(),
            previous
        );
        assert_eq!(
            target_for_next_block(previous, 2_015, None, &params).unwrap(),
            previous
        );
        assert_eq!(
            target_for_next_block(previous, 2_016, None, &params).unwrap(),
            previous
        );
        assert_eq!(
            target_for_next_block(previous, 2_017, Some(expected / 2), &params)
                .unwrap()
                .to_be_bytes()[31],
            50
        );
        assert_eq!(
            target_for_next_block(previous, 2_017, None, &params),
            Err(PrivateConsensusError::Consensus(
                ConsensusError::MissingRetargetObservation
            ))
        );
        assert_eq!(
            target_for_next_block(Uint256::ZERO, 2, None, &params),
            Err(PrivateConsensusError::Consensus(
                ConsensusError::InvalidTarget
            ))
        );
        assert_eq!(
            target_for_next_block(previous, 0, None, &params),
            Err(PrivateConsensusError::Consensus(
                ConsensusError::InvalidNextBlockHeight
            ))
        );
    }

    #[test]
    fn malformed_block_timestamp_still_reaches_state_admission() {
        let mut state = state();
        let block = body(&state, 100);
        let mut malformed = block;
        malformed.timestamp = 0;
        let before = state.encode_snapshot().unwrap();
        let mut params = ConsensusParameters::candidate_testnet().unwrap();
        params.pow_limit = Uint256::MAX;
        let header = header_for(&state, &malformed, &params, Uint256::MAX, 0);
        let expected_previous = state.tip_hash();
        assert_eq!(
            admit_live(
                &mut state,
                CandidateConsensusBlock {
                    block: &malformed,
                    pow_header: &header,
                },
                expected_previous,
                Uint256::MAX,
                &params,
                &EmptyBlockAuthenticator,
                &FixedClock,
            ),
            Err(PrivateConsensusError::Admission(
                ChainAdmissionError::State(StateError::InvalidBlockTimestamp)
            ))
        );
        assert_eq!(state.encode_snapshot().unwrap(), before);
    }
}
