//! CP-0659 bounded process-local Q6MO market-operation mempool.
//!
//! Operations are admitted only after the exact combined native-transfer + market candidate
//! passes canonical QFP6 execution. Durable persistence is intentionally a separate Q6MM
//! journal responsibility; this pool alone must never be exposed as durable acceptance.
use crate::qrun_v06_canonical_execution_candidate::{
    encode_qrun_v06_market_operation, QRunV06Block, QRunV06BlockOperation,
    QRunV06CanonicalExecutionState,
};
use crate::qrun_v06_market_ingress_candidate::{
    build_qrun_v06_combined_candidate_block_with_quote_asset_authorization, market_operation_id,
    market_operation_sender_nonce, QRunV06MarketIngressError,
};
use crate::qrun_v06_pow_fork_choice_candidate::QRunV06QuoteAssetAuthorizationProvider;
use crate::qrun_v06_transaction_mempool_candidate::{
    QRunV06MempoolLimits, QRunV06NativeTransactionMempool,
};
use crate::state_machine::{Transaction, TransactionAuthenticator};
use std::collections::BTreeMap;

pub const QRUN_V06_MAX_PENDING_MARKET_OPERATIONS_PER_ACCOUNT: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QRunV06MarketMempoolError {
    InvalidLimits,
    InvalidOperation,
    WrongNetwork,
    Expired,
    Duplicate,
    TransactionLimit,
    PerAccountLimit,
    ByteLimit,
    Candidate(String),
}

impl std::fmt::Display for QRunV06MarketMempoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "QFP6 market mempool rejected operation: {self:?}")
    }
}
impl std::error::Error for QRunV06MarketMempoolError {}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct QRunV06MarketMempoolReconcileSummary {
    pub kept: usize,
    pub dropped_confirmed: usize,
    pub dropped_invalid_or_stale: usize,
}

#[derive(Debug, Clone)]
struct Entry {
    operation: QRunV06BlockOperation,
    encoded_len: usize,
}

/// Bounded, deterministic market-operation queue. It deliberately does not persist data;
/// callers must install accepted entries in Q6MM before acknowledging Q6MA Accepted.
#[derive(Debug, Clone)]
pub struct QRunV06MarketOperationMempool {
    limits: QRunV06MempoolLimits,
    entries: BTreeMap<[u8; 32], Entry>,
    total_bytes: usize,
}

impl QRunV06MarketOperationMempool {
    pub fn new(limits: QRunV06MempoolLimits) -> Result<Self, QRunV06MarketMempoolError> {
        QRunV06NativeTransactionMempool::new(limits)
            .map_err(|_| QRunV06MarketMempoolError::InvalidLimits)?;
        Ok(Self {
            limits,
            entries: BTreeMap::new(),
            total_bytes: 0,
        })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    pub fn limits(&self) -> QRunV06MempoolLimits {
        self.limits
    }

    pub fn ordered_operations(&self) -> Vec<QRunV06BlockOperation> {
        let mut operations: Vec<_> = self
            .entries
            .iter()
            .map(|(id, entry)| (*id, entry.operation.clone()))
            .collect();
        operations.sort_by_key(|(id, operation)| {
            let (sender, nonce) = market_operation_sender_nonce(operation).unwrap_or(([0; 32], 0));
            (sender, nonce, *id)
        });
        operations
            .into_iter()
            .map(|(_, operation)| operation)
            .collect()
    }

    /// Validate a new operation against the entire candidate set before mutating the pool.
    /// The native transactions slice is the current Q6TI pool, ensuring nonce sequencing
    /// and balances are checked jointly rather than by two independent mempools.
    pub fn submit<A: TransactionAuthenticator>(
        &mut self,
        operation: QRunV06BlockOperation,
        state: &QRunV06CanonicalExecutionState,
        authenticator: &A,
        producer: [u8; 32],
        candidate_timestamp: u64,
        native_transactions: &[Transaction],
    ) -> Result<[u8; 32], QRunV06MarketMempoolError> {
        self.submit_with_quote_asset_authorization(
            operation,
            state,
            authenticator,
            producer,
            candidate_timestamp,
            native_transactions,
            None,
        )
    }

    pub fn submit_with_quote_asset_authorization<A: TransactionAuthenticator>(
        &mut self,
        operation: QRunV06BlockOperation,
        state: &QRunV06CanonicalExecutionState,
        authenticator: &A,
        producer: [u8; 32],
        candidate_timestamp: u64,
        native_transactions: &[Transaction],
        mut quote_authorizer: Option<&mut QRunV06QuoteAssetAuthorizationProvider<'_>>,
    ) -> Result<[u8; 32], QRunV06MarketMempoolError> {
        let (sender, _) = market_operation_sender_nonce(&operation)
            .ok_or(QRunV06MarketMempoolError::InvalidOperation)?;
        let (network_id, expires_at) = match &operation {
            QRunV06BlockOperation::Amm(value) => (value.network_id, value.expires_at),
            QRunV06BlockOperation::OrderBook(value) => (value.network_id, value.expires_at),
            _ => return Err(QRunV06MarketMempoolError::InvalidOperation),
        };
        if network_id != state.network_id() {
            return Err(QRunV06MarketMempoolError::WrongNetwork);
        }
        if candidate_timestamp >= expires_at {
            return Err(QRunV06MarketMempoolError::Expired);
        }
        let encoded = encode_qrun_v06_market_operation(&operation)
            .map_err(|_| QRunV06MarketMempoolError::InvalidOperation)?;
        let id = market_operation_id(&operation)
            .map_err(|_| QRunV06MarketMempoolError::InvalidOperation)?;
        if self.entries.contains_key(&id) {
            return Err(QRunV06MarketMempoolError::Duplicate);
        }
        if self.entries.len() >= self.limits.max_transactions {
            return Err(QRunV06MarketMempoolError::TransactionLimit);
        }
        let sender_pending = self
            .entries
            .values()
            .filter(|entry| {
                market_operation_sender_nonce(&entry.operation).is_some_and(|v| v.0 == sender)
            })
            .count();
        if sender_pending >= QRUN_V06_MAX_PENDING_MARKET_OPERATIONS_PER_ACCOUNT {
            return Err(QRunV06MarketMempoolError::PerAccountLimit);
        }
        let next_bytes = self
            .total_bytes
            .checked_add(encoded.len())
            .ok_or(QRunV06MarketMempoolError::ByteLimit)?;
        if next_bytes > self.limits.max_bytes {
            return Err(QRunV06MarketMempoolError::ByteLimit);
        }

        let mut proposed = self.ordered_operations();
        proposed.push(operation.clone());
        build_qrun_v06_combined_candidate_block_with_quote_asset_authorization(
            state,
            native_transactions,
            &proposed,
            producer,
            candidate_timestamp,
            authenticator,
            quote_authorizer.as_deref_mut(),
        )
        .map_err(map_candidate_error)?;

        self.entries.insert(
            id,
            Entry {
                operation,
                encoded_len: encoded.len(),
            },
        );
        self.total_bytes = next_bytes;
        Ok(id)
    }

    pub fn build_block<A: TransactionAuthenticator>(
        &self,
        state: &QRunV06CanonicalExecutionState,
        authenticator: &A,
        producer: [u8; 32],
        candidate_timestamp: u64,
        native_transactions: &[Transaction],
    ) -> Result<QRunV06Block, QRunV06MarketMempoolError> {
        self.build_block_with_quote_asset_authorization(
            state,
            authenticator,
            producer,
            candidate_timestamp,
            native_transactions,
            None,
        )
    }

    pub fn build_block_with_quote_asset_authorization<A: TransactionAuthenticator>(
        &self,
        state: &QRunV06CanonicalExecutionState,
        authenticator: &A,
        producer: [u8; 32],
        candidate_timestamp: u64,
        native_transactions: &[Transaction],
        mut quote_authorizer: Option<&mut QRunV06QuoteAssetAuthorizationProvider<'_>>,
    ) -> Result<QRunV06Block, QRunV06MarketMempoolError> {
        build_qrun_v06_combined_candidate_block_with_quote_asset_authorization(
            state,
            native_transactions,
            &self.ordered_operations(),
            producer,
            candidate_timestamp,
            authenticator,
            quote_authorizer.as_deref_mut(),
        )
        .map_err(map_candidate_error)
    }

    /// Remove market operations only after their exact containing block becomes canonical.
    pub fn remove_included(&mut self, included: &[QRunV06BlockOperation]) -> usize {
        let mut removed = 0usize;
        for operation in included {
            let Ok(id) = market_operation_id(operation) else {
                continue;
            };
            if let Some(entry) = self.entries.remove(&id) {
                self.total_bytes = self.total_bytes.saturating_sub(entry.encoded_len);
                removed += 1;
            }
        }
        removed
    }

    /// Revalidate pending market operations after a canonical-tip change. Existing Q6TI
    /// entries are kept as a fixed prefix for this pass; invalid/stale operations are dropped.
    pub fn reconcile_after_canonical_change<A: TransactionAuthenticator>(
        &mut self,
        state: &QRunV06CanonicalExecutionState,
        authenticator: &A,
        producer: [u8; 32],
        candidate_timestamp: u64,
        native_transactions: &[Transaction],
        confirmed_ids: &[[u8; 32]],
    ) -> QRunV06MarketMempoolReconcileSummary {
        self.reconcile_after_canonical_change_with_quote_asset_authorization(
            state,
            authenticator,
            producer,
            candidate_timestamp,
            native_transactions,
            confirmed_ids,
            None,
        )
    }

    pub fn reconcile_after_canonical_change_with_quote_asset_authorization<
        A: TransactionAuthenticator,
    >(
        &mut self,
        state: &QRunV06CanonicalExecutionState,
        authenticator: &A,
        producer: [u8; 32],
        candidate_timestamp: u64,
        native_transactions: &[Transaction],
        confirmed_ids: &[[u8; 32]],
        mut quote_authorizer: Option<&mut QRunV06QuoteAssetAuthorizationProvider<'_>>,
    ) -> QRunV06MarketMempoolReconcileSummary {
        let confirmed: std::collections::HashSet<[u8; 32]> =
            confirmed_ids.iter().copied().collect();
        let prior = self.ordered_operations();
        self.entries.clear();
        self.total_bytes = 0;
        let mut summary = QRunV06MarketMempoolReconcileSummary::default();
        for operation in prior {
            let id = market_operation_id(&operation).unwrap_or([0; 32]);
            if confirmed.contains(&id) {
                summary.dropped_confirmed += 1;
                continue;
            }
            if self
                .submit_with_quote_asset_authorization(
                    operation,
                    state,
                    authenticator,
                    producer,
                    candidate_timestamp,
                    native_transactions,
                    quote_authorizer.as_deref_mut(),
                )
                .is_ok()
            {
                summary.kept += 1;
            } else {
                summary.dropped_invalid_or_stale += 1;
            }
        }
        summary
    }
}

fn map_candidate_error(error: QRunV06MarketIngressError) -> QRunV06MarketMempoolError {
    match error {
        QRunV06MarketIngressError::WrongNetwork => QRunV06MarketMempoolError::WrongNetwork,
        QRunV06MarketIngressError::Expired => QRunV06MarketMempoolError::Expired,
        QRunV06MarketIngressError::QuoteAuthorizationProvider(error) => {
            QRunV06MarketMempoolError::Candidate(format!("Q6QA authorization provider: {error}"))
        }
        other => QRunV06MarketMempoolError::Candidate(format!("{other:?}")),
    }
}
