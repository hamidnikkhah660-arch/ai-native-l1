//! CP-0659 Q6MO/Q6MA wire protocol for authenticated market-operation ingress.
//!
//! This module defines bounded framing and canonical operation identity only. It does not
//! grant admission or finality: the service must validate the operation against the current
//! canonical parent plus both native and market pending operations, then durably journal it
//! before returning Q6MA Accepted.
use crate::qrun_v06_canonical_execution_candidate::{
    decode_qrun_v06_market_operation, encode_qrun_v06_market_operation, QRunV06Block,
    QRunV06BlockOperation, QRunV06CanonicalExecutionState, QRunV06ExecutionError,
    MAX_QRUN_V06_BLOCK_OPERATIONS, MAX_QRUN_V06_MARKET_OPERATION_BYTES,
};
use crate::qrun_v06_pow_fork_choice_candidate::QRunV06QuoteAssetAuthorizationProvider;
use crate::state_machine::{
    transaction_id_with_signature_limit, AccountId, Transaction, TransactionAuthenticator,
    QRUN_V06_MAX_NATIVE_TX_SIGNATURE_BYTES,
};
use sha2::{Digest, Sha256};

pub const Q6MO_MAGIC: [u8; 4] = *b"Q6MO";
pub const Q6MA_MAGIC: [u8; 4] = *b"Q6MA";
pub const Q6MO_VERSION: u16 = 1;
pub const Q6MO_MARKET_OPERATION_MESSAGE: u16 = 1;
pub const Q6MO_HEADER_BYTES: usize = 20;
pub const Q6MA_RESPONSE_BYTES: usize = 128;
pub const Q6MO_MAX_FRAME_BYTES: usize = Q6MO_HEADER_BYTES + MAX_QRUN_V06_MARKET_OPERATION_BYTES;
const MARKET_OPERATION_ID_DOMAIN: &[u8] = b"QRUN-V06-Q6MO-MARKET-OPERATION-ID-V1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QRunV06MarketIngressError {
    Incomplete,
    BadMagic,
    UnsupportedVersion(u16),
    WrongMessageType,
    Oversize,
    LengthMismatch,
    ForbiddenOperation,
    InvalidCandidateTimestamp,
    CandidateHeightOverflow,
    TooManyOperations,
    WrongNetwork,
    Expired,
    NativeTransaction(String),
    QuoteAuthorizationProvider(String),
    Canonical(QRunV06ExecutionError),
}

impl From<QRunV06ExecutionError> for QRunV06MarketIngressError {
    fn from(value: QRunV06ExecutionError) -> Self {
        Self::Canonical(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum QRunV06MarketSubmitStatus {
    Accepted = 1,
    Duplicate = 2,
    Rejected = 3,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06MarketSubmitRequest {
    pub request_id: u64,
    pub operation: QRunV06BlockOperation,
}

pub fn market_operation_sender_nonce(
    operation: &QRunV06BlockOperation,
) -> Option<(AccountId, u64)> {
    match operation {
        QRunV06BlockOperation::Amm(value)
            if matches!(
                &value.operation,
                crate::qzxb_amm_candidate::AmmOperation::CreatePair { .. }
                    | crate::qzxb_amm_candidate::AmmOperation::SwapExactIn { .. }
                    | crate::qzxb_amm_candidate::AmmOperation::AddLiquidity { .. }
                    | crate::qzxb_amm_candidate::AmmOperation::RemoveLiquidity { .. }
            ) =>
        {
            Some((value.sender, value.nonce))
        }
        QRunV06BlockOperation::OrderBook(value) => Some((value.sender, value.nonce)),
        QRunV06BlockOperation::Amm(_)
        | QRunV06BlockOperation::AssetRegistration(_)
        | QRunV06BlockOperation::AssetAdmin(_)
        | QRunV06BlockOperation::NativeTransfer(_)
        | QRunV06BlockOperation::CategoryRelease(_)
        | QRunV06BlockOperation::ProtocolBurnReserveRetirement(_) => None,
    }
}

fn market_operation_network_expiry(operation: &QRunV06BlockOperation) -> Option<([u8; 32], u64)> {
    match operation {
        QRunV06BlockOperation::Amm(value) => Some((value.network_id, value.expires_at)),
        QRunV06BlockOperation::OrderBook(value) => Some((value.network_id, value.expires_at)),
        _ => None,
    }
}

/// Construct and canonically preview the combined Q6TI + Q6MO pending set. Operations
/// are ordered by (account, shared nonce, operation ID), so the canonical ledger validates
/// one nonce sequence across transfers, AMM and OrderBook. External quote activity remains
/// fail-closed unless a fresh per-block Q6QA authorizer is explicitly supplied.
pub fn build_qrun_v06_combined_candidate_block<A: TransactionAuthenticator>(
    state: &QRunV06CanonicalExecutionState,
    native_transactions: &[Transaction],
    market_operations: &[QRunV06BlockOperation],
    producer: AccountId,
    candidate_timestamp: u64,
    authenticator: &A,
) -> Result<QRunV06Block, QRunV06MarketIngressError> {
    build_qrun_v06_combined_candidate_block_with_quote_asset_authorization(
        state,
        native_transactions,
        market_operations,
        producer,
        candidate_timestamp,
        authenticator,
        None,
    )
}

pub fn build_qrun_v06_combined_candidate_block_with_quote_asset_authorization<
    A: TransactionAuthenticator,
>(
    state: &QRunV06CanonicalExecutionState,
    native_transactions: &[Transaction],
    market_operations: &[QRunV06BlockOperation],
    producer: AccountId,
    candidate_timestamp: u64,
    authenticator: &A,
    mut quote_authorizer: Option<&mut QRunV06QuoteAssetAuthorizationProvider<'_>>,
) -> Result<QRunV06Block, QRunV06MarketIngressError> {
    if candidate_timestamp <= state.last_timestamp() {
        return Err(QRunV06MarketIngressError::InvalidCandidateTimestamp);
    }
    let height = state
        .height()
        .checked_add(1)
        .ok_or(QRunV06MarketIngressError::CandidateHeightOverflow)?;
    let mut ordered: Vec<(AccountId, u64, [u8; 32], QRunV06BlockOperation)> =
        Vec::with_capacity(native_transactions.len() + market_operations.len());
    for transaction in native_transactions {
        let id = transaction_id_with_signature_limit(
            transaction,
            QRUN_V06_MAX_NATIVE_TX_SIGNATURE_BYTES,
        )
        .map_err(|error| QRunV06MarketIngressError::NativeTransaction(format!("{error:?}")))?;
        ordered.push((
            transaction.sender,
            transaction.nonce,
            id,
            QRunV06BlockOperation::NativeTransfer(transaction.clone()),
        ));
    }
    for operation in market_operations {
        let (sender, nonce) = market_operation_sender_nonce(operation)
            .ok_or(QRunV06MarketIngressError::ForbiddenOperation)?;
        let (network_id, expires_at) = market_operation_network_expiry(operation)
            .ok_or(QRunV06MarketIngressError::ForbiddenOperation)?;
        if network_id != state.network_id() {
            return Err(QRunV06MarketIngressError::WrongNetwork);
        }
        if candidate_timestamp >= expires_at {
            return Err(QRunV06MarketIngressError::Expired);
        }
        let id = market_operation_id(operation)?;
        ordered.push((sender, nonce, id, operation.clone()));
    }
    if ordered.len() > MAX_QRUN_V06_BLOCK_OPERATIONS {
        return Err(QRunV06MarketIngressError::TooManyOperations);
    }
    ordered.sort_by_key(|(sender, nonce, id, _)| (*sender, *nonce, *id));
    let operations = ordered
        .into_iter()
        .map(|(_, _, _, operation)| operation)
        .collect();
    let mut block = QRunV06Block {
        network_id: state.network_id(),
        profile_id: state.profile_id(),
        height,
        timestamp: candidate_timestamp,
        parent_hash: state.tip_hash(),
        state_root: [0; 32],
        producer,
        operations,
    };
    let quote_authorization = match state
        .required_quote_asset_for_block(&block)
        .map_err(QRunV06MarketIngressError::Canonical)?
    {
        Some(asset_id) => {
            let authorize =
                quote_authorizer
                    .as_deref_mut()
                    .ok_or(QRunV06MarketIngressError::Canonical(
                        QRunV06ExecutionError::MissingQuoteAssetAuthorization,
                    ))?;
            Some(
                authorize(state, &block, asset_id)
                    .map_err(QRunV06MarketIngressError::QuoteAuthorizationProvider)?,
            )
        }
        None => None,
    };
    block.state_root = state
        .preview_state_root_after_with_quote_asset_authorization(
            &block,
            authenticator,
            quote_authorization.as_ref(),
        )
        .map_err(QRunV06MarketIngressError::Canonical)?;
    Ok(block)
}

pub fn market_operation_id(
    operation: &QRunV06BlockOperation,
) -> Result<[u8; 32], QRunV06MarketIngressError> {
    if market_operation_sender_nonce(operation).is_none() {
        return Err(QRunV06MarketIngressError::ForbiddenOperation);
    }
    let encoded = encode_qrun_v06_market_operation(operation)?;
    let mut hash = Sha256::new();
    hash.update(MARKET_OPERATION_ID_DOMAIN);
    hash.update((encoded.len() as u32).to_be_bytes());
    hash.update(encoded);
    Ok(hash.finalize().into())
}

pub fn encode_q6mo_market_operation_request(
    request_id: u64,
    operation: &QRunV06BlockOperation,
) -> Result<Vec<u8>, QRunV06MarketIngressError> {
    if request_id == 0 {
        return Err(QRunV06MarketIngressError::Incomplete);
    }
    let wire = encode_qrun_v06_market_operation(operation)?;
    if wire.is_empty() || wire.len() > MAX_QRUN_V06_MARKET_OPERATION_BYTES {
        return Err(QRunV06MarketIngressError::Oversize);
    }
    let length = u32::try_from(wire.len()).map_err(|_| QRunV06MarketIngressError::Oversize)?;
    let mut frame = Vec::with_capacity(Q6MO_HEADER_BYTES + wire.len());
    frame.extend_from_slice(&Q6MO_MAGIC);
    frame.extend_from_slice(&Q6MO_VERSION.to_be_bytes());
    frame.extend_from_slice(&Q6MO_MARKET_OPERATION_MESSAGE.to_be_bytes());
    frame.extend_from_slice(&request_id.to_be_bytes());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&wire);
    Ok(frame)
}

pub fn decode_q6mo_market_operation_request(
    frame: &[u8],
) -> Result<QRunV06MarketSubmitRequest, QRunV06MarketIngressError> {
    if frame.len() < Q6MO_HEADER_BYTES {
        return Err(QRunV06MarketIngressError::Incomplete);
    }
    if frame[..4] != Q6MO_MAGIC {
        return Err(QRunV06MarketIngressError::BadMagic);
    }
    let version = u16::from_be_bytes([frame[4], frame[5]]);
    if version != Q6MO_VERSION {
        return Err(QRunV06MarketIngressError::UnsupportedVersion(version));
    }
    if frame[6..8] != Q6MO_MARKET_OPERATION_MESSAGE.to_be_bytes() {
        return Err(QRunV06MarketIngressError::WrongMessageType);
    }
    let request_id = u64::from_be_bytes(
        frame[8..16]
            .try_into()
            .map_err(|_| QRunV06MarketIngressError::Incomplete)?,
    );
    if request_id == 0 {
        return Err(QRunV06MarketIngressError::Incomplete);
    }
    let declared = u32::from_be_bytes(
        frame[16..20]
            .try_into()
            .map_err(|_| QRunV06MarketIngressError::Incomplete)?,
    ) as usize;
    if declared == 0 || declared > MAX_QRUN_V06_MARKET_OPERATION_BYTES {
        return Err(QRunV06MarketIngressError::Oversize);
    }
    if frame.len() != Q6MO_HEADER_BYTES + declared {
        return Err(QRunV06MarketIngressError::LengthMismatch);
    }
    let operation = decode_qrun_v06_market_operation(&frame[Q6MO_HEADER_BYTES..])?;
    if market_operation_sender_nonce(&operation).is_none() {
        return Err(QRunV06MarketIngressError::ForbiddenOperation);
    }
    Ok(QRunV06MarketSubmitRequest {
        request_id,
        operation,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06MarketSubmitResponse {
    pub request_id: u64,
    pub status: QRunV06MarketSubmitStatus,
    pub operation_id: [u8; 32],
    pub mempool_count: u32,
    pub mempool_bytes: u32,
    pub canonical_height: u64,
    pub canonical_tip: [u8; 32],
    pub canonical_state_root: [u8; 32],
}

impl QRunV06MarketSubmitResponse {
    pub fn encode(&self) -> [u8; Q6MA_RESPONSE_BYTES] {
        let mut bytes = [0u8; Q6MA_RESPONSE_BYTES];
        bytes[..4].copy_from_slice(&Q6MA_MAGIC);
        bytes[4..6].copy_from_slice(&Q6MO_VERSION.to_be_bytes());
        bytes[6..8].copy_from_slice(&(self.status as u16).to_be_bytes());
        bytes[8..16].copy_from_slice(&self.request_id.to_be_bytes());
        bytes[16..48].copy_from_slice(&self.operation_id);
        bytes[48..52].copy_from_slice(&self.mempool_count.to_be_bytes());
        bytes[52..56].copy_from_slice(&self.mempool_bytes.to_be_bytes());
        bytes[56..64].copy_from_slice(&self.canonical_height.to_be_bytes());
        bytes[64..96].copy_from_slice(&self.canonical_tip);
        bytes[96..128].copy_from_slice(&self.canonical_state_root);
        bytes
    }
}

pub fn decode_q6ma_response(
    bytes: &[u8],
    expected_request_id: u64,
) -> Result<QRunV06MarketSubmitResponse, QRunV06MarketIngressError> {
    if bytes.len() != Q6MA_RESPONSE_BYTES {
        return Err(QRunV06MarketIngressError::LengthMismatch);
    }
    if bytes[..4] != Q6MA_MAGIC {
        return Err(QRunV06MarketIngressError::BadMagic);
    }
    let version = u16::from_be_bytes([bytes[4], bytes[5]]);
    if version != Q6MO_VERSION {
        return Err(QRunV06MarketIngressError::UnsupportedVersion(version));
    }
    let status = match u16::from_be_bytes([bytes[6], bytes[7]]) {
        1 => QRunV06MarketSubmitStatus::Accepted,
        2 => QRunV06MarketSubmitStatus::Duplicate,
        3 => QRunV06MarketSubmitStatus::Rejected,
        _ => return Err(QRunV06MarketIngressError::WrongMessageType),
    };
    let request_id = u64::from_be_bytes(
        bytes[8..16]
            .try_into()
            .map_err(|_| QRunV06MarketIngressError::Incomplete)?,
    );
    if request_id != expected_request_id {
        return Err(QRunV06MarketIngressError::WrongMessageType);
    }
    Ok(QRunV06MarketSubmitResponse {
        request_id,
        status,
        operation_id: bytes[16..48].try_into().unwrap(),
        mempool_count: u32::from_be_bytes(bytes[48..52].try_into().unwrap()),
        mempool_bytes: u32::from_be_bytes(bytes[52..56].try_into().unwrap()),
        canonical_height: u64::from_be_bytes(bytes[56..64].try_into().unwrap()),
        canonical_tip: bytes[64..96].try_into().unwrap(),
        canonical_state_root: bytes[96..128].try_into().unwrap(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qrun_v06_asset_registry_candidate::{
        AssetRegistration, AssetSupplyPolicy, AssetTrustPolicy,
    };
    use crate::qrun_v06_orderbook_candidate::{
        QRunV06OrderBookOperation, QRunV06SignedOrderBookOperation,
    };
    use crate::qzxb_amm_candidate::{AmmOperation, AmmSignedOperation, QzxbAmmStateCandidate};
    use crate::{
        qrun_v06_canonical_execution_candidate::QRunV06Block,
        qrun_v06_unified_asset_candidate::QRunV06UnifiedAssetState,
        state_machine::{transaction_signing_digest, LedgerState},
    };

    const TEST_NETWORK: [u8; 32] = [0xA1; 32];
    const TEST_PROFILE: [u8; 32] = [0xA2; 32];
    const TEST_ALICE: [u8; 32] = [0xA3; 32];
    const TEST_BOB: [u8; 32] = [0xA4; 32];
    const TEST_PRODUCER: [u8; 32] = [0xA5; 32];

    struct DigestAuthenticator;
    impl crate::state_machine::TransactionAuthenticator for DigestAuthenticator {
        fn verify(
            &self,
            sender: &AccountId,
            digest: &[u8; 32],
            signature: &[u8],
        ) -> Result<(), ()> {
            if sender.iter().any(|byte| *byte != 0) && signature == digest {
                Ok(())
            } else {
                Err(())
            }
        }
    }

    fn fixture() -> QRunV06CanonicalExecutionState {
        let ledger = LedgerState::genesis(TEST_NETWORK, vec![(TEST_ALICE, 20_000)]).unwrap();
        let amm = QzxbAmmStateCandidate::new(TEST_NETWORK, 32, 64, 512).unwrap();
        let unified = QRunV06UnifiedAssetState::new(ledger, amm).unwrap();
        QRunV06CanonicalExecutionState::new(unified, TEST_PROFILE).unwrap()
    }

    fn amm_operation(nonce: u64) -> QRunV06BlockOperation {
        QRunV06BlockOperation::Amm(AmmSignedOperation {
            network_id: [0xA1; 32],
            sender: [0xB2; 32],
            nonce,
            expires_at: 1_000,
            operation: AmmOperation::CreatePair {
                token_a: [0xC3; 32],
                token_b: [0xC4; 32],
            },
            signature: vec![0xD4; 64],
        })
    }

    fn orderbook_operation(nonce: u64) -> QRunV06BlockOperation {
        QRunV06BlockOperation::OrderBook(QRunV06SignedOrderBookOperation {
            network_id: [0xA1; 32],
            sender: [0xB2; 32],
            nonce,
            expires_at: 1_000,
            operation: QRunV06OrderBookOperation::Cancel {
                order_id: [0xE5; 32],
            },
            signature: vec![0xF6; 64],
        })
    }

    #[test]
    fn q6mo_market_operation_roundtrips_and_binds_request_id() {
        for operation in [amm_operation(1), orderbook_operation(2)] {
            let frame = encode_q6mo_market_operation_request(41, &operation).unwrap();
            let decoded = decode_q6mo_market_operation_request(&frame).unwrap();
            assert_eq!(decoded.request_id, 41);
            assert_eq!(decoded.operation, operation);
            assert_eq!(
                market_operation_id(&decoded.operation).unwrap(),
                market_operation_id(&operation).unwrap()
            );
        }
    }

    #[test]
    fn q6mo_rejects_wrong_request_id_length_extension_and_version() {
        let operation = amm_operation(1);
        let mut frame = encode_q6mo_market_operation_request(42, &operation).unwrap();
        assert_eq!(
            decode_q6mo_market_operation_request(&frame)
                .unwrap()
                .request_id,
            42
        );
        frame.push(0);
        assert_eq!(
            decode_q6mo_market_operation_request(&frame),
            Err(QRunV06MarketIngressError::LengthMismatch)
        );
        let mut unsupported = encode_q6mo_market_operation_request(43, &operation).unwrap();
        unsupported[4..6].copy_from_slice(&2u16.to_be_bytes());
        assert_eq!(
            decode_q6mo_market_operation_request(&unsupported),
            Err(QRunV06MarketIngressError::UnsupportedVersion(2))
        );
    }

    #[test]
    fn q6mo_does_not_accept_native_transfer_or_supply_governance_operations() {
        use crate::state_machine::Transaction;
        let transfer = QRunV06BlockOperation::NativeTransfer(Transaction {
            network_id: [0xA1; 32],
            sender: [0xB2; 32],
            recipient: [0xC3; 32],
            nonce: 1,
            amount: 1,
            fee: 1,
            expires_at: 1_000,
            signature: vec![0xD4; 64],
        });
        assert_eq!(
            encode_qrun_v06_market_operation(&transfer),
            Err(QRunV06ExecutionError::Malformed)
        );
        assert_eq!(market_operation_sender_nonce(&transfer), None);
    }

    #[test]
    fn q6mo_rejects_amm_asset_control_and_test_quote_operations() {
        let forbidden = [
            AmmOperation::RegisterAsset {
                asset_id: [0xC7; 32],
            },
            AmmOperation::TransferAsset {
                asset_id: [0xC8; 32],
                recipient: [0xC9; 32],
                amount: 1,
            },
            AmmOperation::MintTestQuote { amount: 1 },
        ];
        for amm_operation in forbidden {
            let operation = QRunV06BlockOperation::Amm(AmmSignedOperation {
                network_id: TEST_NETWORK,
                sender: TEST_ALICE,
                nonce: 1,
                expires_at: 10_000,
                operation: amm_operation,
                signature: vec![0xCC; 64],
            });
            assert_eq!(
                encode_qrun_v06_market_operation(&operation),
                Err(QRunV06ExecutionError::Malformed)
            );
            assert_eq!(market_operation_sender_nonce(&operation), None);
        }
    }

    fn signed_native_transfer(nonce: u64) -> Transaction {
        let mut transaction = Transaction {
            network_id: TEST_NETWORK,
            sender: TEST_ALICE,
            recipient: TEST_BOB,
            nonce,
            amount: 10,
            fee: 1,
            expires_at: 10_000,
            signature: Vec::new(),
        };
        transaction.signature = transaction_signing_digest(&transaction).unwrap().to_vec();
        transaction
    }

    fn registered_market_state() -> (QRunV06CanonicalExecutionState, [u8; 32]) {
        let mut state = fixture();
        let mut registration = AssetRegistration {
            network_id: TEST_NETWORK,
            issuer: TEST_ALICE,
            issuer_nonce: 1,
            salt: [0xB5; 32],
            name: "Q6MO Base Asset".to_string(),
            symbol: "Q6MB".to_string(),
            decimals: 8,
            supply_policy: AssetSupplyPolicy::Fixed {
                total_supply: 1_000,
            },
            initial_supply: 1_000,
            initial_recipient: TEST_ALICE,
            trust_policy: AssetTrustPolicy::Unverified,
            expires_at: 10_000,
            signature: Vec::new(),
        };
        registration.signature = registration.signing_digest().unwrap().to_vec();
        let asset_id = registration.asset_id();
        let mut block = QRunV06Block {
            network_id: TEST_NETWORK,
            profile_id: TEST_PROFILE,
            height: 1,
            timestamp: 100,
            parent_hash: state.tip_hash(),
            state_root: [0; 32],
            producer: TEST_PRODUCER,
            operations: vec![QRunV06BlockOperation::AssetRegistration(registration)],
        };
        block.state_root = state
            .preview_state_root_after(&block, &DigestAuthenticator)
            .unwrap();
        state.apply_block(&block, &DigestAuthenticator).unwrap();
        (state, asset_id)
    }

    fn signed_orderbook_pair(nonce: u64, base_asset: [u8; 32]) -> QRunV06BlockOperation {
        let mut operation = QRunV06SignedOrderBookOperation {
            network_id: TEST_NETWORK,
            sender: TEST_ALICE,
            nonce,
            expires_at: 10_000,
            operation: QRunV06OrderBookOperation::CreatePair {
                base: base_asset,
                quote: crate::qzxb_amm_candidate::qzxb_native_asset_id(TEST_NETWORK).unwrap(),
                base_lot_atoms: 1,
                quote_tick_atoms: 1,
                max_price_ticks: 1_000,
                max_quantity_lots: 1_000,
                min_notional: 1,
                maker_fee_bps: 10,
                taker_fee_bps: 20,
                fee_collector: TEST_BOB,
            },
            signature: Vec::new(),
        };
        operation.signature = operation.signing_digest().unwrap().to_vec();
        QRunV06BlockOperation::OrderBook(operation)
    }

    #[test]
    fn q6mo_and_q6ti_share_one_canonical_account_nonce_sequence() {
        let (state, base_asset) = registered_market_state();
        let market = signed_orderbook_pair(1, base_asset);
        let native = signed_native_transfer(2);
        let block = build_qrun_v06_combined_candidate_block(
            &state,
            &[native.clone()],
            &[market.clone()],
            TEST_PRODUCER,
            200,
            &DigestAuthenticator,
        )
        .unwrap();

        assert_eq!(block.operations.len(), 2);
        assert!(matches!(
            &block.operations[0],
            QRunV06BlockOperation::OrderBook(_)
        ));
        assert!(matches!(
            &block.operations[1],
            QRunV06BlockOperation::NativeTransfer(_)
        ));
        assert_eq!(
            block.state_root,
            state
                .preview_state_root_after(&block, &DigestAuthenticator)
                .unwrap()
        );

        let duplicate_nonce = build_qrun_v06_combined_candidate_block(
            &state,
            &[signed_native_transfer(1)],
            &[market],
            TEST_PRODUCER,
            200,
            &DigestAuthenticator,
        );
        assert!(duplicate_nonce.is_err());
    }

    fn registered_external_quote_state() -> (QRunV06CanonicalExecutionState, [u8; 32], [u8; 32]) {
        let mut state = fixture();
        let mut base = AssetRegistration {
            network_id: TEST_NETWORK,
            issuer: TEST_ALICE,
            issuer_nonce: 1,
            salt: [0xB6; 32],
            name: "Q6MO Base".to_string(),
            symbol: "Q6MB".to_string(),
            decimals: 8,
            supply_policy: AssetSupplyPolicy::Fixed {
                total_supply: 1_000,
            },
            initial_supply: 1_000,
            initial_recipient: TEST_ALICE,
            trust_policy: AssetTrustPolicy::Unverified,
            expires_at: 10_000,
            signature: Vec::new(),
        };
        base.signature = base.signing_digest().unwrap().to_vec();
        let base_id = base.asset_id();

        let mut quote = AssetRegistration {
            network_id: TEST_NETWORK,
            issuer: TEST_ALICE,
            issuer_nonce: 2,
            salt: [0xB7; 32],
            name: "Q6MO Qualified Quote".to_string(),
            symbol: "Q6MQ".to_string(),
            decimals: 6,
            supply_policy: AssetSupplyPolicy::Fixed {
                total_supply: 1_000,
            },
            initial_supply: 1_000,
            initial_recipient: TEST_ALICE,
            trust_policy: AssetTrustPolicy::Unverified,
            expires_at: 10_000,
            signature: Vec::new(),
        };
        quote.signature = quote.signing_digest().unwrap().to_vec();
        let quote_id = quote.asset_id();

        let mut registration_block = QRunV06Block {
            network_id: TEST_NETWORK,
            profile_id: TEST_PROFILE,
            height: 1,
            timestamp: 100,
            parent_hash: state.tip_hash(),
            state_root: [0; 32],
            producer: TEST_PRODUCER,
            operations: vec![
                QRunV06BlockOperation::AssetRegistration(base),
                QRunV06BlockOperation::AssetRegistration(quote),
            ],
        };
        registration_block.state_root = state
            .preview_state_root_after(&registration_block, &DigestAuthenticator)
            .unwrap();
        state
            .apply_block(&registration_block, &DigestAuthenticator)
            .unwrap();
        (state, base_id, quote_id)
    }

    #[test]
    fn q6mo_external_quote_requires_fresh_height_bound_q6qa_before_candidate_acceptance() {
        let (state, base_asset, quote_asset) = registered_external_quote_state();
        let mut pair = QRunV06SignedOrderBookOperation {
            network_id: TEST_NETWORK,
            sender: TEST_ALICE,
            nonce: 1,
            expires_at: 10_000,
            operation: QRunV06OrderBookOperation::CreatePair {
                base: base_asset,
                quote: quote_asset,
                base_lot_atoms: 1,
                quote_tick_atoms: 1,
                max_price_ticks: 1_000,
                max_quantity_lots: 1_000,
                min_notional: 1,
                maker_fee_bps: 10,
                taker_fee_bps: 20,
                fee_collector: TEST_BOB,
            },
            signature: Vec::new(),
        };
        pair.signature = pair.signing_digest().unwrap().to_vec();
        let market_operation = QRunV06BlockOperation::OrderBook(pair);

        assert_eq!(
            build_qrun_v06_combined_candidate_block(
                &state,
                &[],
                std::slice::from_ref(&market_operation),
                TEST_PRODUCER,
                200,
                &DigestAuthenticator,
            ),
            Err(QRunV06MarketIngressError::Canonical(
                QRunV06ExecutionError::MissingQuoteAssetAuthorization,
            ))
        );

        let authorization =
            crate::qrun_v06_profile_trust_candidate::test_trust_authorized_quote_asset_candidate_with_decimals(
                TEST_NETWORK,
                TEST_PROFILE,
                quote_asset,
                [0xD7; 32],
                [0xD8; 32],
                3,
                1,
                10,
                1,
                2,
                6,
            );
        let calls = std::cell::Cell::new(0u8);
        let mut quote_authorizer = |parent: &QRunV06CanonicalExecutionState,
                                    block: &QRunV06Block,
                                    requested_asset: [u8; 32]| {
            assert_eq!(parent.network_id(), TEST_NETWORK);
            assert_eq!(parent.profile_id(), TEST_PROFILE);
            assert_eq!(block.height, 2);
            assert_eq!(requested_asset, quote_asset);
            calls.set(calls.get() + 1);
            Ok(authorization.clone())
        };
        let candidate = build_qrun_v06_combined_candidate_block_with_quote_asset_authorization(
            &state,
            &[],
            &[market_operation],
            TEST_PRODUCER,
            200,
            &DigestAuthenticator,
            Some(&mut quote_authorizer),
        )
        .unwrap();

        assert_eq!(calls.get(), 1);
        assert_eq!(candidate.height, 2);
        assert_eq!(
            candidate.state_root,
            state
                .preview_state_root_after_with_quote_asset_authorization(
                    &candidate,
                    &DigestAuthenticator,
                    Some(&authorization),
                )
                .unwrap()
        );
    }

    #[test]
    fn q6ma_response_roundtrips_pending_not_finality_status() {
        let response = QRunV06MarketSubmitResponse {
            request_id: 73,
            status: QRunV06MarketSubmitStatus::Accepted,
            operation_id: [0x11; 32],
            mempool_count: 2,
            mempool_bytes: 512,
            canonical_height: 9,
            canonical_tip: [0x22; 32],
            canonical_state_root: [0x33; 32],
        };
        let encoded = response.encode();
        let decoded = decode_q6ma_response(&encoded, 73).unwrap();
        assert_eq!(decoded, response);
        assert_eq!(
            decode_q6ma_response(&encoded, 74),
            Err(QRunV06MarketIngressError::WrongMessageType)
        );
    }
}
