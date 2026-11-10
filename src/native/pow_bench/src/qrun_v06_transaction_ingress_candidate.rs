//! QFP6 bounded transaction-submit frame for authenticated Noise sessions.
//! Q6TI/Q6TA is distinct from the Q6PB/Q6PA block-admission protocol:
//! Q6TA means mempool submission only, never block confirmation or QAP1 finality.
use crate::{
    qrun_v06_canonical_execution_candidate::QRunV06CanonicalExecutionState,
    qrun_v06_node_runtime_candidate::QRunV06PeerReplayGuard,
    qrun_v06_transaction_mempool_candidate::{
        QRunV06MempoolError, QRunV06NativeTransactionMempool,
    },
    state_machine::{
        decode_transaction_with_signature_limit, encode_transaction_with_signature_limit,
        transaction_id_with_signature_limit, AccountId, StateError, Transaction,
        TransactionAuthenticator, QRUN_V06_MAX_NATIVE_TX_SIGNATURE_BYTES,
    },
};
pub const Q6TI_MAGIC: [u8; 4] = *b"Q6TI";
pub const Q6TA_MAGIC: [u8; 4] = *b"Q6TA";
pub const Q6TI_VERSION: u16 = 1;
pub const Q6TI_NATIVE_TRANSFER_MESSAGE: u16 = 1;
pub const Q6TI_HEADER_BYTES: usize = 20;
pub const Q6TA_RESPONSE_BYTES: usize = 128;
pub const Q6TI_MAX_TRANSACTION_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QRunV06TransactionIngressError {
    Incomplete,
    BadMagic,
    UnsupportedVersion(u16),
    WrongMessageType,
    Oversize,
    LengthMismatch,
    State(StateError),
}

impl From<StateError> for QRunV06TransactionIngressError {
    fn from(value: StateError) -> Self {
        Self::State(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum QRunV06TransactionSubmitStatus {
    Accepted = 1,
    Duplicate = 2,
    Rejected = 3,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06TransactionSubmitRequest {
    pub request_id: u64,
    pub transaction: Transaction,
}

pub fn encode_q6ti_transaction_request(
    request_id: u64,
    transaction: &Transaction,
) -> Result<Vec<u8>, QRunV06TransactionIngressError> {
    if request_id == 0 {
        return Err(QRunV06TransactionIngressError::Incomplete);
    }
    let wire = encode_transaction_with_signature_limit(
        transaction,
        QRUN_V06_MAX_NATIVE_TX_SIGNATURE_BYTES,
    )?;
    if wire.is_empty() || wire.len() > Q6TI_MAX_TRANSACTION_BYTES {
        return Err(QRunV06TransactionIngressError::Oversize);
    }
    let length = u32::try_from(wire.len()).map_err(|_| QRunV06TransactionIngressError::Oversize)?;
    let mut frame = Vec::with_capacity(Q6TI_HEADER_BYTES + wire.len());
    frame.extend_from_slice(&Q6TI_MAGIC);
    frame.extend_from_slice(&Q6TI_VERSION.to_be_bytes());
    frame.extend_from_slice(&Q6TI_NATIVE_TRANSFER_MESSAGE.to_be_bytes());
    frame.extend_from_slice(&request_id.to_be_bytes());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&wire);
    Ok(frame)
}

pub fn decode_q6ti_transaction_request(
    frame: &[u8],
) -> Result<QRunV06TransactionSubmitRequest, QRunV06TransactionIngressError> {
    if frame.len() < Q6TI_HEADER_BYTES {
        return Err(QRunV06TransactionIngressError::Incomplete);
    }
    if frame[..4] != Q6TI_MAGIC {
        return Err(QRunV06TransactionIngressError::BadMagic);
    }
    let version = u16::from_be_bytes([frame[4], frame[5]]);
    if version != Q6TI_VERSION {
        return Err(QRunV06TransactionIngressError::UnsupportedVersion(version));
    }
    if frame[6..8] != Q6TI_NATIVE_TRANSFER_MESSAGE.to_be_bytes() {
        return Err(QRunV06TransactionIngressError::WrongMessageType);
    }
    let request_id = u64::from_be_bytes(frame[8..16].try_into().unwrap());
    if request_id == 0 {
        return Err(QRunV06TransactionIngressError::Incomplete);
    }
    let declared = u32::from_be_bytes(frame[16..20].try_into().unwrap()) as usize;
    if declared == 0 || declared > Q6TI_MAX_TRANSACTION_BYTES {
        return Err(QRunV06TransactionIngressError::Oversize);
    }
    if frame.len() != Q6TI_HEADER_BYTES + declared {
        return Err(QRunV06TransactionIngressError::LengthMismatch);
    }
    let transaction = decode_transaction_with_signature_limit(
        &frame[Q6TI_HEADER_BYTES..],
        QRUN_V06_MAX_NATIVE_TX_SIGNATURE_BYTES,
    )?;
    Ok(QRunV06TransactionSubmitRequest {
        request_id,
        transaction,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06TransactionSubmitResponse {
    pub request_id: u64,
    pub status: QRunV06TransactionSubmitStatus,
    pub transaction_id: [u8; 32],
    pub mempool_count: u32,
    pub mempool_bytes: u32,
    pub canonical_height: u64,
    pub canonical_tip: [u8; 32],
    pub canonical_state_root: [u8; 32],
}

impl QRunV06TransactionSubmitResponse {
    pub fn encode(&self) -> [u8; Q6TA_RESPONSE_BYTES] {
        let mut bytes = [0u8; Q6TA_RESPONSE_BYTES];
        bytes[..4].copy_from_slice(&Q6TA_MAGIC);
        bytes[4..6].copy_from_slice(&Q6TI_VERSION.to_be_bytes());
        bytes[6..8].copy_from_slice(&(self.status as u16).to_be_bytes());
        bytes[8..16].copy_from_slice(&self.request_id.to_be_bytes());
        bytes[16..48].copy_from_slice(&self.transaction_id);
        bytes[48..52].copy_from_slice(&self.mempool_count.to_be_bytes());
        bytes[52..56].copy_from_slice(&self.mempool_bytes.to_be_bytes());
        bytes[56..64].copy_from_slice(&self.canonical_height.to_be_bytes());
        bytes[64..96].copy_from_slice(&self.canonical_tip);
        bytes[96..128].copy_from_slice(&self.canonical_state_root);
        bytes
    }
}

pub fn decode_q6ta_response(
    bytes: &[u8],
    expected_request_id: u64,
) -> Result<QRunV06TransactionSubmitResponse, QRunV06TransactionIngressError> {
    if bytes.len() != Q6TA_RESPONSE_BYTES {
        return Err(QRunV06TransactionIngressError::LengthMismatch);
    }
    if bytes[..4] != Q6TA_MAGIC {
        return Err(QRunV06TransactionIngressError::BadMagic);
    }
    let version = u16::from_be_bytes([bytes[4], bytes[5]]);
    if version != Q6TI_VERSION {
        return Err(QRunV06TransactionIngressError::UnsupportedVersion(version));
    }
    let status = match u16::from_be_bytes([bytes[6], bytes[7]]) {
        1 => QRunV06TransactionSubmitStatus::Accepted,
        2 => QRunV06TransactionSubmitStatus::Duplicate,
        3 => QRunV06TransactionSubmitStatus::Rejected,
        _ => return Err(QRunV06TransactionIngressError::WrongMessageType),
    };
    let request_id = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
    if request_id != expected_request_id {
        return Err(QRunV06TransactionIngressError::WrongMessageType);
    }
    Ok(QRunV06TransactionSubmitResponse {
        request_id,
        status,
        transaction_id: bytes[16..48].try_into().unwrap(),
        mempool_count: u32::from_be_bytes(bytes[48..52].try_into().unwrap()),
        mempool_bytes: u32::from_be_bytes(bytes[52..56].try_into().unwrap()),
        canonical_height: u64::from_be_bytes(bytes[56..64].try_into().unwrap()),
        canonical_tip: bytes[64..96].try_into().unwrap(),
        canonical_state_root: bytes[96..128].try_into().unwrap(),
    })
}

fn response(
    request_id: u64,
    status: QRunV06TransactionSubmitStatus,
    transaction_id: [u8; 32],
    pool: &QRunV06NativeTransactionMempool,
    state: &QRunV06CanonicalExecutionState,
) -> QRunV06TransactionSubmitResponse {
    QRunV06TransactionSubmitResponse {
        request_id,
        status,
        transaction_id,
        mempool_count: u32::try_from(pool.len()).unwrap_or(u32::MAX),
        mempool_bytes: u32::try_from(pool.total_bytes()).unwrap_or(u32::MAX),
        canonical_height: state.height(),
        canonical_tip: state.tip_hash(),
        canonical_state_root: state.state_root().unwrap_or([0; 32]),
    }
}

/// Handle one Q6TI frame from an already-authenticated QFP6 Noise session.
/// Accepted means only pending in this process-local pool, never mined or QAP1-final.
pub fn process_q6ti_transaction_frame<A: TransactionAuthenticator>(
    frame: &[u8],
    replay_guard: &mut QRunV06PeerReplayGuard,
    pool: &mut QRunV06NativeTransactionMempool,
    state: &QRunV06CanonicalExecutionState,
    authenticator: &A,
    producer: AccountId,
    candidate_timestamp: u64,
) -> Result<[u8; Q6TA_RESPONSE_BYTES], QRunV06TransactionIngressError> {
    let request = decode_q6ti_transaction_request(frame)?;
    let txid = transaction_id_with_signature_limit(
        &request.transaction,
        QRUN_V06_MAX_NATIVE_TX_SIGNATURE_BYTES,
    )?;
    if replay_guard.accept(request.request_id).is_err() {
        return Ok(response(
            request.request_id,
            QRunV06TransactionSubmitStatus::Rejected,
            txid,
            pool,
            state,
        )
        .encode());
    }
    let status = match pool.submit(
        request.transaction,
        state,
        authenticator,
        producer,
        candidate_timestamp,
    ) {
        Ok(_) => QRunV06TransactionSubmitStatus::Accepted,
        Err(QRunV06MempoolError::Duplicate) => QRunV06TransactionSubmitStatus::Duplicate,
        Err(_) => QRunV06TransactionSubmitStatus::Rejected,
    };
    Ok(response(request.request_id, status, txid, pool, state).encode())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        consensus::{ConsensusParameters, PowAlgorithm, PowParameters, Uint256},
        qrun_v06_genesis_descriptor_candidate::QRunV06GenesisDescriptor,
        qrun_v06_hybrid_auth_candidate::{
            QRunV06HybridTransactionAuthenticator, QRunV06HybridTransactionSigner,
        },
        qrun_v06_tokenomics_candidate::{QRunV06MiningScheduleCandidate, QRunV06TokenomicsState},
        qrun_v06_transaction_mempool_candidate::{
            QRunV06MempoolLimits, QRunV06NativeTransactionMempool,
        },
        state_machine::{transaction_signing_digest, Transaction},
        v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate,
    };
    use ed25519_dalek::Signer;

    const NETWORK: [u8; 32] = [0xA1; 32];
    const PROFILE: [u8; 32] = [0xA2; 32];
    const PRODUCER: [u8; 32] = [0xA3; 32];
    const RECIPIENT: [u8; 32] = [0xA4; 32];

    fn params() -> ConsensusParameters {
        let mut p = ConsensusParameters::candidate_testnet().unwrap();
        p.protocol_version = 6;
        p.target_block_time_secs = 30;
        p.difficulty_window_blocks = 2;
        p.difficulty_min_ratio_divisor = 4;
        p.difficulty_max_ratio = 4;
        p.initial_target = Uint256::from_be_bytes([0x7F; 32]);
        p.pow_limit = Uint256::MAX;
        p.pow = PowParameters {
            algorithm: PowAlgorithm::Argon2id,
            memory_kib: 8,
            iterations: 1,
            lanes: 1,
            output_bytes: 32,
        };
        p.validate().unwrap();
        p
    }

    fn genesis(founder: [u8; 32]) -> QRunV06CanonicalExecutionState {
        let p = params();
        let schedule = QRunV06MiningScheduleCandidate::cp0422_research_candidate();
        let economics = QRunV06TokenomicsState::genesis(NETWORK, founder, schedule).unwrap();
        let descriptor = QRunV06GenesisDescriptor::new(
            NETWORK,
            PROFILE,
            founder,
            1,
            crate::qrun_v06_checkpoint_candidate::qrun_v06_consensus_fingerprint(&p).unwrap(),
            economics.policy_fingerprint(),
        )
        .unwrap();
        QRunV06CanonicalExecutionState::cp0528_genesis_candidate_with_descriptor(
            descriptor, schedule,
        )
        .unwrap()
    }

    fn hybrid_tx(signer: &QRunV06HybridTransactionSigner, nonce: u64) -> Transaction {
        let mut tx = Transaction {
            network_id: NETWORK,
            sender: signer.account_id(),
            recipient: RECIPIENT,
            nonce,
            amount: 1_000,
            fee: 10,
            expires_at: 20_000,
            signature: Vec::new(),
        };
        signer.sign_transaction(&mut tx).unwrap();
        tx
    }

    fn pool() -> QRunV06NativeTransactionMempool {
        QRunV06NativeTransactionMempool::new(QRunV06MempoolLimits::default()).unwrap()
    }

    #[test]
    fn q6ti_accepts_q6ha_through_authenticated_session_handler_into_mempool() {
        let signer = QRunV06HybridTransactionSigner::from_seeds([0xB1; 32], [0xB2; 32]).unwrap();
        let state = genesis(signer.account_id());
        let auth = QRunV06HybridTransactionAuthenticator::new(LibcruxMlDsa65VerifierCandidate);
        let mut pool = pool();
        let tx = hybrid_tx(&signer, 1);
        assert_eq!(tx.signature.len(), 5_365);
        let frame = encode_q6ti_transaction_request(41, &tx).unwrap();
        let mut replay = QRunV06PeerReplayGuard::new();
        let ack = process_q6ti_transaction_frame(
            &frame,
            &mut replay,
            &mut pool,
            &state,
            &auth,
            PRODUCER,
            state.last_timestamp() + 60,
        )
        .unwrap();
        let decoded = decode_q6ta_response(&ack, 41).unwrap();
        assert_eq!(decoded.status, QRunV06TransactionSubmitStatus::Accepted);
        assert_eq!(decoded.mempool_count, 1);
        assert!(decoded.mempool_bytes > 4 * 1024);
        assert_eq!(decoded.canonical_height, 0);
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn q6ti_replay_and_duplicate_are_not_reported_as_new_acceptance() {
        let signer = QRunV06HybridTransactionSigner::from_seeds([0xC1; 32], [0xC2; 32]).unwrap();
        let state = genesis(signer.account_id());
        let auth = QRunV06HybridTransactionAuthenticator::new(LibcruxMlDsa65VerifierCandidate);
        let mut pool = pool();
        let tx = hybrid_tx(&signer, 1);
        let frame = encode_q6ti_transaction_request(51, &tx).unwrap();
        let mut replay = QRunV06PeerReplayGuard::new();
        let ts = state.last_timestamp() + 60;
        let first = process_q6ti_transaction_frame(
            &frame,
            &mut replay,
            &mut pool,
            &state,
            &auth,
            PRODUCER,
            ts,
        )
        .unwrap();
        assert_eq!(
            decode_q6ta_response(&first, 51).unwrap().status,
            QRunV06TransactionSubmitStatus::Accepted
        );

        let replayed = process_q6ti_transaction_frame(
            &frame,
            &mut replay,
            &mut pool,
            &state,
            &auth,
            PRODUCER,
            ts,
        )
        .unwrap();
        assert_eq!(
            decode_q6ta_response(&replayed, 51).unwrap().status,
            QRunV06TransactionSubmitStatus::Rejected
        );

        let duplicate_frame = encode_q6ti_transaction_request(52, &tx).unwrap();
        let duplicate = process_q6ti_transaction_frame(
            &duplicate_frame,
            &mut replay,
            &mut pool,
            &state,
            &auth,
            PRODUCER,
            ts,
        )
        .unwrap();
        assert_eq!(
            decode_q6ta_response(&duplicate, 52).unwrap().status,
            QRunV06TransactionSubmitStatus::Duplicate
        );
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn q6ti_rejects_ed25519_only_signature_for_hybrid_sender() {
        let signer = QRunV06HybridTransactionSigner::from_seeds([0xD1; 32], [0xD2; 32]).unwrap();
        let state = genesis(signer.account_id());
        let auth = QRunV06HybridTransactionAuthenticator::new(LibcruxMlDsa65VerifierCandidate);
        let mut pool = pool();
        let mut tx = hybrid_tx(&signer, 1);
        let digest = transaction_signing_digest(&tx).unwrap();
        tx.signature = ed25519_dalek::SigningKey::from_bytes(&[0xD3; 32])
            .sign(&digest)
            .to_bytes()
            .to_vec();
        let frame = encode_q6ti_transaction_request(61, &tx).unwrap();
        let mut replay = QRunV06PeerReplayGuard::new();
        let ack = process_q6ti_transaction_frame(
            &frame,
            &mut replay,
            &mut pool,
            &state,
            &auth,
            PRODUCER,
            state.last_timestamp() + 60,
        )
        .unwrap();
        assert_eq!(
            decode_q6ta_response(&ack, 61).unwrap().status,
            QRunV06TransactionSubmitStatus::Rejected
        );
        assert!(pool.is_empty());
    }

    #[test]
    fn q6ti_frame_rejects_length_extension_and_wrong_request_id_ack() {
        let signer = QRunV06HybridTransactionSigner::from_seeds([0xE1; 32], [0xE2; 32]).unwrap();
        let tx = hybrid_tx(&signer, 1);
        let mut frame = encode_q6ti_transaction_request(71, &tx).unwrap();
        frame.push(0);
        assert_eq!(
            decode_q6ti_transaction_request(&frame),
            Err(QRunV06TransactionIngressError::LengthMismatch)
        );

        let state = genesis(signer.account_id());
        let auth = QRunV06HybridTransactionAuthenticator::new(LibcruxMlDsa65VerifierCandidate);
        let mut pool = pool();
        let mut replay = QRunV06PeerReplayGuard::new();
        let clean = encode_q6ti_transaction_request(72, &tx).unwrap();
        let ack = process_q6ti_transaction_frame(
            &clean,
            &mut replay,
            &mut pool,
            &state,
            &auth,
            PRODUCER,
            state.last_timestamp() + 60,
        )
        .unwrap();
        assert_eq!(
            decode_q6ta_response(&ack, 73),
            Err(QRunV06TransactionIngressError::WrongMessageType)
        );
    }
}
