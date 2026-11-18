//! CP-0592 service adapter joining the permissionless base runtime to native transaction ingress,
//! durable pending-transaction journal, deterministic mempool selection and bounded PoW mining.
//!
//! Q6TA Accepted means only that a signed native transfer is in the local bounded mempool and
//! its journal snapshot was installed. A mined block is reported only after the permissionless
//! runtime durably commits its QFP6 envelope. This is not peer discovery, public listener,
//! full-history network sync, payout finality, or a production miner supervisor.

use crate::{
    qrun_v06_market_ingress_candidate::{
        build_qrun_v06_combined_candidate_block_with_quote_asset_authorization,
        decode_q6mo_market_operation_request, market_operation_id, QRunV06MarketSubmitResponse,
        QRunV06MarketSubmitStatus,
    },
    qrun_v06_market_journal_candidate::{
        QRunV06MarketJournalError, QRunV06MarketJournalRestoreSummary,
        QRunV06MarketOperationJournal,
    },
    qrun_v06_market_mempool_candidate::{QRunV06MarketMempoolError, QRunV06MarketOperationMempool},
    qrun_v06_miner_candidate::{
        mine_qfp6_block_on_tip_from_nonce,
        mine_qfp6_block_on_tip_from_nonce_with_quote_asset_authorization, QRunV06MinedBlock,
        QRunV06MiningError,
    },
    qrun_v06_node_runtime_candidate::QRunV06PeerReplayGuard,
    qrun_v06_permissionless_runtime_candidate::{
        QRunV06PermissionlessNodeRuntime, QRunV06PermissionlessRuntimeError,
    },
    qrun_v06_pow_fork_choice_candidate::QRunV06QuoteAssetAuthorizationProvider,
    qrun_v06_pow_fork_store_candidate::QRunV06DurableCommit,
    qrun_v06_transaction_ingress_candidate::{
        decode_q6ta_response, decode_q6ti_transaction_request,
        process_q6ti_transaction_frame_with_market_operations_and_quote_asset_authorization,
        QRunV06TransactionSubmitStatus,
    },
    qrun_v06_transaction_journal_candidate::{
        QRunV06TransactionJournal, QRunV06TransactionJournalError,
        QRunV06TransactionJournalRestoreSummary,
    },
    qrun_v06_transaction_mempool_candidate::{
        QRunV06MempoolLimits, QRunV06NativeTransactionMempool,
    },
    state_machine::{AccountId, TransactionAuthenticator},
};
use std::sync::atomic::AtomicBool;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QRunV06PermissionlessServiceError {
    Runtime(String),
    Ingress(String),
    Journal(String),
    MarketJournal(String),
    Mining(String),
    MiningNonceBudgetExhausted { next_nonce: u64 },
    MiningCancelled,
}

impl std::fmt::Display for QRunV06PermissionlessServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "QFP6 permissionless service failed: {self:?}")
    }
}
impl std::error::Error for QRunV06PermissionlessServiceError {}

impl From<QRunV06PermissionlessRuntimeError> for QRunV06PermissionlessServiceError {
    fn from(value: QRunV06PermissionlessRuntimeError) -> Self {
        Self::Runtime(value.to_string())
    }
}
impl From<QRunV06TransactionJournalError> for QRunV06PermissionlessServiceError {
    fn from(value: QRunV06TransactionJournalError) -> Self {
        Self::Journal(value.to_string())
    }
}
impl From<QRunV06MarketJournalError> for QRunV06PermissionlessServiceError {
    fn from(value: QRunV06MarketJournalError) -> Self {
        Self::MarketJournal(value.to_string())
    }
}

pub struct QRunV06PermissionlessMempool {
    pool: QRunV06NativeTransactionMempool,
    journal: QRunV06TransactionJournal,
    market_pool: QRunV06MarketOperationMempool,
    market_journal: QRunV06MarketOperationJournal,
    last_market_restore_summary: QRunV06MarketJournalRestoreSummary,
    /// In-memory continuation cursor for bounded PoW batches; resets on process restart.
    next_pow_nonce: u64,
}

impl QRunV06PermissionlessMempool {
    /// Open a pending-transaction journal. Call `restore` against recovered canonical state
    /// before accepting any Q6TI frames.
    pub fn open(
        directory: impl AsRef<std::path::Path>,
        limits: QRunV06MempoolLimits,
    ) -> Result<Self, QRunV06PermissionlessServiceError> {
        let directory = directory.as_ref();
        let pool = QRunV06NativeTransactionMempool::new(limits).map_err(|error| {
            QRunV06PermissionlessServiceError::Journal(format!("invalid mempool limits: {error:?}"))
        })?;
        let market_pool = QRunV06MarketOperationMempool::new(limits).map_err(|error| {
            QRunV06PermissionlessServiceError::MarketJournal(format!(
                "invalid mempool limits: {error:?}"
            ))
        })?;
        let journal = QRunV06TransactionJournal::open(directory, limits)?;
        // Q6MJ intentionally rejects unknown entries in its directory. Keep the Q6MM journal
        // as a sibling path so the legacy Q6MJ snapshot scanner remains strictly compatible.
        let market_directory = directory.with_extension("market-operations");
        let market_journal = QRunV06MarketOperationJournal::open(market_directory, limits)?;
        Ok(Self {
            pool,
            journal,
            market_pool,
            market_journal,
            last_market_restore_summary: QRunV06MarketJournalRestoreSummary::default(),
            next_pow_nonce: 0,
        })
    }

    pub fn pending_count(&self) -> usize {
        self.pool.len()
    }
    pub fn pending_bytes(&self) -> usize {
        self.pool.total_bytes()
    }
    pub fn pending_market_count(&self) -> usize {
        self.market_pool.len()
    }
    pub fn pending_market_bytes(&self) -> usize {
        self.market_pool.total_bytes()
    }
    pub fn journal_generation(&self) -> u64 {
        self.journal.generation()
    }
    pub fn market_journal_generation(&self) -> u64 {
        self.market_journal.generation()
    }
    pub fn market_restore_summary(&self) -> QRunV06MarketJournalRestoreSummary {
        self.last_market_restore_summary
    }
    pub fn next_pow_nonce(&self) -> u64 {
        self.next_pow_nonce
    }

    /// Revalidate pending native/market operations after a peer-admitted canonical change.
    /// The compatibility path is native-quote only; external quote operations fail closed.
    pub fn reconcile_after_canonical_change<A: TransactionAuthenticator>(
        &mut self,
        runtime: &QRunV06PermissionlessNodeRuntime,
        authenticator: &A,
        producer: AccountId,
        candidate_timestamp: u64,
    ) -> Result<(), QRunV06PermissionlessServiceError> {
        self.reconcile_after_canonical_change_with_quote_asset_authorization(
            runtime,
            authenticator,
            producer,
            candidate_timestamp,
            None,
        )
    }

    pub fn reconcile_after_canonical_change_with_quote_asset_authorization<
        A: TransactionAuthenticator,
    >(
        &mut self,
        runtime: &QRunV06PermissionlessNodeRuntime,
        authenticator: &A,
        producer: AccountId,
        candidate_timestamp: u64,
        mut quote_authorizer: Option<&mut QRunV06QuoteAssetAuthorizationProvider<'_>>,
    ) -> Result<(), QRunV06PermissionlessServiceError> {
        let graph = runtime.fork_choice_snapshot()?;
        let _ = self.pool.reconcile_after_canonical_change(
            graph.canonical_state(),
            authenticator,
            producer,
            candidate_timestamp,
            &[],
        );
        let _market_summary = self
            .market_pool
            .reconcile_after_canonical_change_with_quote_asset_authorization(
                graph.canonical_state(),
                authenticator,
                producer,
                candidate_timestamp,
                &self.pool.ordered_transactions(),
                &[],
                quote_authorizer.as_deref_mut(),
            );
        self.journal.persist_pool(&self.pool)?;
        self.market_journal.persist_pool(&self.market_pool)?;
        Ok(())
    }

    /// Restore the native Q6MJ pool first, then restore Q6MM against that exact Q6TI pending set.
    /// The method returns the historical native-journal summary; the market summary is exposed
    /// through the market_restore_summary accessor.
    pub fn restore<A: TransactionAuthenticator>(
        &mut self,
        runtime: &QRunV06PermissionlessNodeRuntime,
        authenticator: &A,
        producer: AccountId,
        candidate_timestamp: u64,
    ) -> Result<QRunV06TransactionJournalRestoreSummary, QRunV06PermissionlessServiceError> {
        self.restore_with_quote_asset_authorization(
            runtime,
            authenticator,
            producer,
            candidate_timestamp,
            None,
        )
    }

    pub fn restore_with_quote_asset_authorization<A: TransactionAuthenticator>(
        &mut self,
        runtime: &QRunV06PermissionlessNodeRuntime,
        authenticator: &A,
        producer: AccountId,
        candidate_timestamp: u64,
        mut quote_authorizer: Option<&mut QRunV06QuoteAssetAuthorizationProvider<'_>>,
    ) -> Result<QRunV06TransactionJournalRestoreSummary, QRunV06PermissionlessServiceError> {
        let graph = runtime.fork_choice_snapshot()?;
        let native_summary = self.journal.restore_into_pool(
            &mut self.pool,
            graph.canonical_state(),
            authenticator,
            producer,
            candidate_timestamp,
        )?;
        self.last_market_restore_summary = self
            .market_journal
            .restore_into_pool_with_quote_asset_authorization(
                &mut self.market_pool,
                graph.canonical_state(),
                authenticator,
                producer,
                candidate_timestamp,
                &self.pool.ordered_transactions(),
                quote_authorizer.as_deref_mut(),
            )?;
        Ok(native_summary)
    }

    /// Process one Q6TI frame from an already-authenticated Noise peer session. The replay guard
    /// must be unique to that session. Accepted is returned only after the Q6MJ journal snapshot
    /// is durable; it is never a block-confirmation acknowledgement.
    pub fn submit_q6ti<A: TransactionAuthenticator>(
        &mut self,
        runtime: &QRunV06PermissionlessNodeRuntime,
        replay_guard: &mut QRunV06PeerReplayGuard,
        frame: &[u8],
        authenticator: &A,
        producer: AccountId,
        candidate_timestamp: u64,
    ) -> Result<Vec<u8>, QRunV06PermissionlessServiceError> {
        self.submit_q6ti_with_quote_asset_authorization(
            runtime,
            replay_guard,
            frame,
            authenticator,
            producer,
            candidate_timestamp,
            None,
        )
    }

    pub fn submit_q6ti_with_quote_asset_authorization<A: TransactionAuthenticator>(
        &mut self,
        runtime: &QRunV06PermissionlessNodeRuntime,
        replay_guard: &mut QRunV06PeerReplayGuard,
        frame: &[u8],
        authenticator: &A,
        producer: AccountId,
        candidate_timestamp: u64,
        mut quote_authorizer: Option<&mut QRunV06QuoteAssetAuthorizationProvider<'_>>,
    ) -> Result<Vec<u8>, QRunV06PermissionlessServiceError> {
        let request = decode_q6ti_transaction_request(frame)
            .map_err(|error| QRunV06PermissionlessServiceError::Ingress(format!("{error:?}")))?;
        let graph = runtime.fork_choice_snapshot()?;
        let before = self.pool.clone();
        let response =
            process_q6ti_transaction_frame_with_market_operations_and_quote_asset_authorization(
                frame,
                replay_guard,
                &mut self.pool,
                &self.market_pool.ordered_operations(),
                graph.canonical_state(),
                authenticator,
                producer,
                candidate_timestamp,
                quote_authorizer.as_deref_mut(),
            )
            .map_err(|error| QRunV06PermissionlessServiceError::Ingress(format!("{error:?}")))?;
        let decoded = decode_q6ta_response(&response, request.request_id)
            .map_err(|error| QRunV06PermissionlessServiceError::Ingress(format!("{error:?}")))?;
        if decoded.status == QRunV06TransactionSubmitStatus::Accepted {
            if let Err(error) = self.journal.persist_pool(&self.pool) {
                self.pool = before;
                return Err(QRunV06PermissionlessServiceError::Journal(
                    error.to_string(),
                ));
            }
        }
        Ok(response.to_vec())
    }

    /// Process Q6MO from an authenticated peer. The operation is validated jointly with the
    /// current Q6TI pool and durably installed in Q6MM before Q6MA Accepted is returned.
    /// Accepted is a pending/journaled acknowledgement, never trade finality.
    pub fn submit_q6mo<A: TransactionAuthenticator>(
        &mut self,
        runtime: &QRunV06PermissionlessNodeRuntime,
        replay_guard: &mut QRunV06PeerReplayGuard,
        frame: &[u8],
        authenticator: &A,
        producer: AccountId,
        candidate_timestamp: u64,
    ) -> Result<Vec<u8>, QRunV06PermissionlessServiceError> {
        self.submit_q6mo_with_quote_asset_authorization(
            runtime,
            replay_guard,
            frame,
            authenticator,
            producer,
            candidate_timestamp,
            None,
        )
    }

    pub fn submit_q6mo_with_quote_asset_authorization<A: TransactionAuthenticator>(
        &mut self,
        runtime: &QRunV06PermissionlessNodeRuntime,
        replay_guard: &mut QRunV06PeerReplayGuard,
        frame: &[u8],
        authenticator: &A,
        producer: AccountId,
        candidate_timestamp: u64,
        mut quote_authorizer: Option<&mut QRunV06QuoteAssetAuthorizationProvider<'_>>,
    ) -> Result<Vec<u8>, QRunV06PermissionlessServiceError> {
        let request = decode_q6mo_market_operation_request(frame)
            .map_err(|error| QRunV06PermissionlessServiceError::Ingress(format!("{error:?}")))?;
        let operation_id = market_operation_id(&request.operation)
            .map_err(|error| QRunV06PermissionlessServiceError::Ingress(format!("{error:?}")))?;
        let graph = runtime.fork_choice_snapshot()?;
        let before = self.market_pool.clone();
        let status = match replay_guard.accept(request.request_id) {
            Err(_) => QRunV06MarketSubmitStatus::Rejected,
            Ok(()) => match self.market_pool.submit_with_quote_asset_authorization(
                request.operation,
                graph.canonical_state(),
                authenticator,
                producer,
                candidate_timestamp,
                &self.pool.ordered_transactions(),
                quote_authorizer.as_deref_mut(),
            ) {
                Ok(_) => QRunV06MarketSubmitStatus::Accepted,
                Err(QRunV06MarketMempoolError::Duplicate) => QRunV06MarketSubmitStatus::Duplicate,
                Err(_) => QRunV06MarketSubmitStatus::Rejected,
            },
        };

        if status == QRunV06MarketSubmitStatus::Accepted {
            if let Err(error) = self.market_journal.persist_pool(&self.market_pool) {
                self.market_pool = before;
                return Err(QRunV06PermissionlessServiceError::MarketJournal(
                    error.to_string(),
                ));
            }
        }

        let canonical_state = graph.canonical_state();
        let canonical_state_root = canonical_state
            .state_root()
            .map_err(|error| QRunV06PermissionlessServiceError::Runtime(format!("{error:?}")))?;
        let response = QRunV06MarketSubmitResponse {
            request_id: request.request_id,
            status,
            operation_id,
            mempool_count: u32::try_from(self.market_pool.len()).unwrap_or(u32::MAX),
            mempool_bytes: u32::try_from(self.market_pool.total_bytes()).unwrap_or(u32::MAX),
            canonical_height: canonical_state.height(),
            canonical_tip: canonical_state.tip_hash(),
            canonical_state_root,
        };
        Ok(response.encode().to_vec())
    }

    /// Mine one bounded block (with zero or more pending native transfers) on the exact current
    /// canonical parent and submit its QFP6 envelope to the durable permissionless store. Pending
    /// transactions are removed only if this exact mined block becomes canonical. The journal is
    /// then refreshed. Empty blocks still execute the height-derived consensus issuance schedule.
    pub fn mine_one_batch<A: TransactionAuthenticator>(
        &mut self,
        runtime: &mut QRunV06PermissionlessNodeRuntime,
        authenticator: &A,
        producer: AccountId,
        candidate_timestamp: u64,
        max_nonce_attempts: u64,
        cancellation: &AtomicBool,
    ) -> Result<Option<QRunV06PermissionlessMiningCommit>, QRunV06PermissionlessServiceError> {
        self.mine_one_batch_with_quote_asset_authorization(
            runtime,
            authenticator,
            producer,
            candidate_timestamp,
            max_nonce_attempts,
            cancellation,
            None,
        )
    }

    pub fn mine_one_batch_with_quote_asset_authorization<A: TransactionAuthenticator>(
        &mut self,
        runtime: &mut QRunV06PermissionlessNodeRuntime,
        authenticator: &A,
        producer: AccountId,
        candidate_timestamp: u64,
        max_nonce_attempts: u64,
        cancellation: &AtomicBool,
        mut quote_authorizer: Option<&mut QRunV06QuoteAssetAuthorizationProvider<'_>>,
    ) -> Result<Option<QRunV06PermissionlessMiningCommit>, QRunV06PermissionlessServiceError> {
        // Empty templates are valid PoW blocks too: issuance is height-derived by consensus,
        // not conditional on a mempool transaction being present.
        let graph = runtime.fork_choice_snapshot()?;
        let parent_tip = graph.canonical_tip().tip_hash;
        let transactions = self.pool.ordered_transactions();
        let market_operations = self.market_pool.ordered_operations();
        let combined_candidate =
            build_qrun_v06_combined_candidate_block_with_quote_asset_authorization(
                graph.canonical_state(),
                &transactions,
                &market_operations,
                producer,
                candidate_timestamp,
                authenticator,
                quote_authorizer.as_deref_mut(),
            )
            .map_err(|error| {
                QRunV06PermissionlessServiceError::Ingress(format!(
                    "combined Q6TI/Q6MO candidate rejected: {error:?}"
                ))
            })?;
        let operations = combined_candidate.operations;
        let mined_result = match quote_authorizer.as_deref_mut() {
            Some(provider) => mine_qfp6_block_on_tip_from_nonce_with_quote_asset_authorization(
                &graph,
                &parent_tip,
                candidate_timestamp,
                producer,
                operations,
                authenticator,
                provider,
                self.next_pow_nonce,
                max_nonce_attempts,
                cancellation,
            ),
            None => mine_qfp6_block_on_tip_from_nonce(
                &graph,
                &parent_tip,
                candidate_timestamp,
                producer,
                operations,
                authenticator,
                self.next_pow_nonce,
                max_nonce_attempts,
                cancellation,
            ),
        };
        let mined = match mined_result {
            Ok(mined) => mined,
            Err(QRunV06MiningError::NonceBudgetExhausted { next_nonce }) => {
                return Err(record_nonce_budget_exhaustion(
                    &mut self.next_pow_nonce,
                    next_nonce,
                ));
            }
            Err(QRunV06MiningError::Cancelled) => {
                return Err(QRunV06PermissionlessServiceError::MiningCancelled);
            }
            Err(error) => {
                return Err(QRunV06PermissionlessServiceError::Mining(error.to_string()));
            }
        };
        // The authorization token used by mining is not persisted in the envelope. Re-read
        // Q6TS/floor and re-authorize Q6QA at durable admission of the exact mined block.
        let durable_commit = match quote_authorizer.as_deref_mut() {
            Some(provider) => runtime.submit_envelope_with_quote_asset_authorization(
                &mined.envelope,
                authenticator,
                provider,
            )?,
            None => runtime.submit_envelope(&mined.envelope, authenticator)?,
        };
        let updated_graph = runtime.fork_choice_snapshot()?;
        let became_canonical =
            exact_mined_block_became_canonical(&durable_commit, mined.block_digest);
        self.next_pow_nonce = if became_canonical {
            0
        } else {
            mined.nonce.checked_add(1).unwrap_or(0)
        };
        let removed_transactions = if became_canonical {
            self.pool.remove_included(&transactions)
        } else {
            0
        };
        let removed_market_operations = if became_canonical {
            self.market_pool.remove_included(&market_operations)
        } else {
            0
        };
        let revalidation_base = updated_graph
            .canonical_state()
            .last_timestamp()
            .max(candidate_timestamp);
        let next_timestamp = revalidation_base.saturating_add(1);
        let _ = self.pool.reconcile_after_canonical_change(
            updated_graph.canonical_state(),
            authenticator,
            producer,
            next_timestamp,
            &[],
        );
        let _market_reconcile = self
            .market_pool
            .reconcile_after_canonical_change_with_quote_asset_authorization(
                updated_graph.canonical_state(),
                authenticator,
                producer,
                next_timestamp,
                &self.pool.ordered_transactions(),
                &[],
                quote_authorizer.as_deref_mut(),
            );
        let journal_generation = self.journal.persist_pool(&self.pool).map_err(|error| {
            QRunV06PermissionlessServiceError::Journal(format!(
                "block is already durably committed; pending-journal refresh failed: {error}"
            ))
        })?;
        let market_journal_generation = self
            .market_journal
            .persist_pool(&self.market_pool)
            .map_err(|error| {
                QRunV06PermissionlessServiceError::MarketJournal(format!(
                    "block is already durably committed; Q6MM refresh failed: {error}"
                ))
            })?;
        Ok(Some(QRunV06PermissionlessMiningCommit {
            mined,
            durable_commit,
            removed_transactions,
            removed_market_operations,
            journal_generation,
            market_journal_generation,
            became_canonical,
        }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06PermissionlessMiningCommit {
    pub mined: QRunV06MinedBlock,
    pub durable_commit: QRunV06DurableCommit,
    pub removed_transactions: usize,
    pub removed_market_operations: usize,
    pub journal_generation: u64,
    pub market_journal_generation: u64,
    pub became_canonical: bool,
}

fn record_nonce_budget_exhaustion(
    cursor: &mut u64,
    next_nonce: u64,
) -> QRunV06PermissionlessServiceError {
    *cursor = next_nonce;
    QRunV06PermissionlessServiceError::MiningNonceBudgetExhausted { next_nonce }
}

fn exact_mined_block_became_canonical(
    commit: &QRunV06DurableCommit,
    block_digest: [u8; 32],
) -> bool {
    commit.outcome.canonical_changed && commit.outcome.canonical_tip == block_digest
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qrun_v06_pow_fork_choice_candidate::QRunV06ForkChoiceOutcome;

    fn commit(canonical_changed: bool, canonical_tip: [u8; 32]) -> QRunV06DurableCommit {
        QRunV06DurableCommit {
            outcome: QRunV06ForkChoiceOutcome {
                block_digest: [7; 32],
                previous_canonical_tip: [6; 32],
                canonical_tip,
                previous_height: 10,
                canonical_height: 11,
                canonical_changed,
                reorg_count: 0,
            },
            generation: 12,
            manifest_anchor: [8; 32],
        }
    }

    #[test]
    fn pending_transactions_are_pruned_only_for_the_exact_new_canonical_tip() {
        assert!(exact_mined_block_became_canonical(
            &commit(true, [7; 32]),
            [7; 32]
        ));
        assert!(!exact_mined_block_became_canonical(
            &commit(false, [7; 32]),
            [7; 32]
        ));
        assert!(!exact_mined_block_became_canonical(
            &commit(true, [9; 32]),
            [7; 32]
        ));
    }

    #[test]
    fn exhausted_nonce_batches_advance_the_in_memory_cursor_across_listener_rounds() {
        let mut cursor = 0u64;
        assert_eq!(
            record_nonce_budget_exhaustion(&mut cursor, 1_000_000),
            QRunV06PermissionlessServiceError::MiningNonceBudgetExhausted {
                next_nonce: 1_000_000,
            }
        );
        assert_eq!(cursor, 1_000_000);
        assert_eq!(
            record_nonce_budget_exhaustion(&mut cursor, 2_000_000),
            QRunV06PermissionlessServiceError::MiningNonceBudgetExhausted {
                next_nonce: 2_000_000,
            }
        );
        assert_eq!(cursor, 2_000_000);
    }

    #[test]
    fn post_commit_revalidation_timestamp_never_wraps() {
        assert_eq!(u64::MAX.saturating_add(1), u64::MAX);
        assert_eq!(41u64.max(40).saturating_add(1), 42);
    }

    /// End-to-end local service proof: Q6MO frame -> durable Q6MM ACK -> restart restore
    /// -> combined miner candidate -> exact canonical inclusion -> Q6MM pruning.
    /// The digest authenticator and candidate PoW settings are test fixtures, not production
    /// cryptography or network qualification.
    #[test]
    fn q6mo_is_durably_accepted_restored_mined_and_pruned_only_after_canonical_commit() {
        use crate::{
            consensus::{ConsensusParameters, Uint256},
            external_cas_anchor_candidate::ExternalCasPin,
            qrun_v06_asset_registry_candidate::{
                AssetRegistration, AssetSupplyPolicy, AssetTrustPolicy,
            },
            qrun_v06_canonical_execution_candidate::{
                QRunV06BlockOperation, QRunV06CanonicalExecutionState,
            },
            qrun_v06_checkpoint_candidate::qrun_v06_consensus_fingerprint,
            qrun_v06_cp0651_supply_candidate::Cp0651FixedSupply,
            qrun_v06_genesis_descriptor_candidate::QRunV06GenesisDescriptor,
            qrun_v06_market_ingress_candidate::{
                decode_q6ma_response, encode_q6mo_market_operation_request,
                QRunV06MarketSubmitStatus,
            },
            qrun_v06_miner_candidate::mine_qfp6_block_on_tip_from_nonce,
            qrun_v06_node_supervisor_candidate::process_qfp6_application_frame_with_permissionless_runtime,
            qrun_v06_noise_transport_candidate::QRunV06NoiseSession,
            qrun_v06_orderbook_candidate::{
                QRunV06OrderBookOperation, QRunV06SignedOrderBookOperation,
            },
            qrun_v06_peer_listener_candidate::{
                serve_qfp6_noise_listener_with_history, QRunV06PeerListenerConfig,
                QRunV06PeerListenerStopReason,
            },
            qrun_v06_permissionless_runtime_candidate::QRunV06PermissionlessNodeRuntime,
            qrun_v06_profile_pin_candidate::{
                QRunV06ProfilePinCandidate, QRunV06VerifiedProfilePin,
            },
            qzxb_amm_candidate::qzxb_native_asset_id,
            state_machine::{AccountId, TransactionAuthenticator},
            v4_fat1_trust_candidate::ML_DSA_65_PUBLIC_KEY_BYTES,
        };
        use std::{
            fs,
            net::{TcpListener, TcpStream},
            thread,
            time::{Duration, SystemTime, UNIX_EPOCH},
        };

        const NETWORK: [u8; 32] = [0xE1; 32];
        const PROFILE: [u8; 32] = [0xE2; 32];
        const FOUNDER: [u8; 32] = [0xE3; 32];
        const PRODUCER: [u8; 32] = [0xE4; 32];
        const BASE_SALT: [u8; 32] = [0xE5; 32];

        struct DigestAuthenticator;
        impl TransactionAuthenticator for DigestAuthenticator {
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

        let mut params = ConsensusParameters::qrun_v06_cp0651_fee_only_candidate().unwrap();
        params.target_block_time_secs = 30;
        params.difficulty_window_blocks = 2;
        params.difficulty_min_ratio_divisor = 4;
        params.difficulty_max_ratio = 4;
        params.initial_target = Uint256::MAX;
        params.pow_limit = Uint256::MAX;
        params.validate().unwrap();

        let supply = Cp0651FixedSupply::genesis(NETWORK, FOUNDER).unwrap();
        let descriptor = QRunV06GenesisDescriptor::new(
            NETWORK,
            PROFILE,
            FOUNDER,
            1,
            qrun_v06_consensus_fingerprint(&params).unwrap(),
            supply.policy_fingerprint(),
        )
        .unwrap();
        let genesis = QRunV06CanonicalExecutionState::cp0651_genesis_candidate_with_descriptor(
            descriptor.clone(),
        )
        .unwrap();
        let bundle = QRunV06ProfilePinCandidate::new(
            descriptor,
            ExternalCasPin {
                provider_id: [0xE6; 32],
                network_id: NETWORK,
                genesis_digest: [0xE7; 32],
                receipt_key_id: [0xE8; 32],
                receipt_public_key: [0xE9; ML_DSA_65_PUBLIC_KEY_BYTES],
            },
        )
        .unwrap();
        let pin_bytes = bundle.encode().unwrap();
        let verified_pin =
            QRunV06VerifiedProfilePin::decode(&pin_bytes, bundle.commitment().unwrap()).unwrap();

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("qfp6-q6mo-e2e-{}-{nonce}", std::process::id()));
        let store_dir = root.join("store");
        let mempool_dir = root.join("mempool");
        let _ = fs::remove_dir_all(&root);
        let authenticator = DigestAuthenticator;
        let mut runtime = QRunV06PermissionlessNodeRuntime::open(
            &store_dir,
            genesis,
            params,
            &authenticator,
            None,
            &verified_pin,
        )
        .unwrap();

        // Register the base asset on the canonical chain through the separately governed
        // AssetRegistration operation path. Q6MO itself cannot perform asset issuance/control.
        let mut registration = AssetRegistration {
            network_id: NETWORK,
            issuer: FOUNDER,
            issuer_nonce: 1,
            salt: BASE_SALT,
            name: "Q6MO Integration Base".to_string(),
            symbol: "Q6IB".to_string(),
            decimals: 8,
            supply_policy: AssetSupplyPolicy::Fixed {
                total_supply: 10_000,
            },
            initial_supply: 10_000,
            initial_recipient: FOUNDER,
            trust_policy: AssetTrustPolicy::Unverified,
            expires_at: 10_000,
            signature: Vec::new(),
        };
        registration.signature = registration.signing_digest().unwrap().to_vec();
        let base_asset = registration.asset_id();
        let graph = runtime.fork_choice_snapshot().unwrap();
        let registration_block = mine_qfp6_block_on_tip_from_nonce(
            &graph,
            &graph.canonical_tip().tip_hash,
            100,
            PRODUCER,
            vec![QRunV06BlockOperation::AssetRegistration(registration)],
            &authenticator,
            0,
            10_000,
            &AtomicBool::new(false),
        )
        .unwrap();
        let registration_commit = runtime
            .submit_envelope(&registration_block.envelope, &authenticator)
            .unwrap();
        assert_eq!(
            registration_commit.outcome.canonical_tip,
            registration_block.block_digest
        );

        let mut mempool =
            QRunV06PermissionlessMempool::open(&mempool_dir, QRunV06MempoolLimits::default())
                .unwrap();
        mempool
            .restore(&runtime, &authenticator, FOUNDER, 200)
            .unwrap();

        let mut order = QRunV06SignedOrderBookOperation {
            network_id: NETWORK,
            sender: FOUNDER,
            nonce: 1,
            // The supervisor dispatcher uses the real wall-clock candidate time.
            expires_at: u64::MAX,
            operation: QRunV06OrderBookOperation::CreatePair {
                base: base_asset,
                quote: qzxb_native_asset_id(NETWORK).unwrap(),
                base_lot_atoms: 1,
                quote_tick_atoms: 1,
                max_price_ticks: 1_000,
                max_quantity_lots: 1_000,
                min_notional: 1,
                maker_fee_bps: 10,
                taker_fee_bps: 20,
                fee_collector: PRODUCER,
            },
            signature: Vec::new(),
        };
        order.signature = order.signing_digest().unwrap().to_vec();
        let operation = QRunV06BlockOperation::OrderBook(order);
        let frame = encode_q6mo_market_operation_request(1, &operation).unwrap();
        let noise_params = "Noise_XX_25519_ChaChaPoly_SHA256".parse().unwrap();
        let server_pair = snow::Builder::new(noise_params).generate_keypair().unwrap();
        let client_pair = snow::Builder::new("Noise_XX_25519_ChaChaPoly_SHA256".parse().unwrap())
            .generate_keypair()
            .unwrap();
        let server_private: [u8; 32] = server_pair.private.as_slice().try_into().unwrap();
        let server_public: [u8; 32] = server_pair.public.as_slice().try_into().unwrap();
        let client_private: [u8; 32] = client_pair.private.as_slice().try_into().unwrap();
        let client_public: [u8; 32] = client_pair.public.as_slice().try_into().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_address = listener.local_addr().unwrap();

        // Exercise the production combined listener, including its bounded Noise handshake
        // worker pool, Q6MO frame dispatch and strict Q6MA response validation.
        let response = thread::scope(|scope| {
            let server = scope.spawn(|| -> Result<crate::qrun_v06_peer_listener_candidate::QRunV06PeerListenerReport, String> {
                let shutdown = AtomicBool::new(false);
                let mut handler = |guard: &mut QRunV06PeerReplayGuard, received: &[u8]| {
                    let response = process_qfp6_application_frame_with_permissionless_runtime(
                        &mut runtime,
                        guard,
                        &mut mempool,
                        received,
                        &authenticator,
                        PRODUCER,
                    )?;
                    Ok(vec![response.to_vec()])
                };
                let report = serve_qfp6_noise_listener_with_history(
                    &listener,
                    QRunV06PeerListenerConfig {
                        max_sessions: 1,
                        max_requests_per_session: 1,
                        max_failed_handshakes: 1,
                        accept_poll_interval: Duration::from_millis(10),
                    },
                    &server_private,
                    &[client_public],
                    &NETWORK,
                    &PROFILE,
                    &shutdown,
                    &mut handler,
                )
                .map_err(|error| format!("production QFP6 listener failed: {error:?}"))?;
                Ok(report)
            });

            let mut stream = TcpStream::connect(listen_address).unwrap();
            stream.set_nodelay(true).unwrap();
            let mut session = QRunV06NoiseSession::connect(
                &mut stream,
                &client_private,
                &server_public,
                &NETWORK,
                &PROFILE,
            )
            .unwrap();
            session.write_record(&mut stream, &frame).unwrap();
            let response = session.read_record(&mut stream).unwrap();
            let report = server.join().unwrap().unwrap();
            assert_eq!(
                report.stop_reason,
                QRunV06PeerListenerStopReason::SessionLimitReached
            );
            assert_eq!(report.stats.accepted_connections, 1);
            assert_eq!(report.stats.authenticated_sessions, 1);
            assert_eq!(report.stats.requests_received, 1);
            assert_eq!(report.stats.responses_written, 1);
            assert_eq!(report.stats.handler_failures, 0);
            assert_eq!(report.stats.malformed_responses, 0);
            assert_eq!(report.stats.handshake_queue_rejections, 0);
            response
        });
        let acknowledgement = decode_q6ma_response(&response, 1).unwrap();
        assert_eq!(acknowledgement.status, QRunV06MarketSubmitStatus::Accepted);
        assert_eq!(mempool.pending_market_count(), 1);
        assert_eq!(mempool.market_journal_generation(), 2);
        drop(mempool);

        // A second process restores the pending signed order from Q6MM, not from chat memory.
        let mut recovered =
            QRunV06PermissionlessMempool::open(&mempool_dir, QRunV06MempoolLimits::default())
                .unwrap();
        let restore = recovered
            .restore(&runtime, &authenticator, FOUNDER, 201)
            .unwrap();
        assert_eq!(restore.restored, 0);
        assert_eq!(recovered.market_restore_summary().restored, 1);
        assert_eq!(recovered.pending_market_count(), 1);

        let mined = recovered
            .mine_one_batch(
                &mut runtime,
                &authenticator,
                PRODUCER,
                300,
                10_000,
                &AtomicBool::new(false),
            )
            .unwrap()
            .unwrap();
        assert!(mined.became_canonical);
        assert_eq!(mined.removed_market_operations, 1);
        assert_eq!(recovered.pending_market_count(), 0);
        assert_eq!(
            runtime.status().unwrap().height,
            registration_commit.outcome.canonical_height + 1
        );
        drop(recovered);

        // A fresh process must not resurrect the operation after exact canonical inclusion.
        let mut final_mempool =
            QRunV06PermissionlessMempool::open(&mempool_dir, QRunV06MempoolLimits::default())
                .unwrap();
        final_mempool
            .restore(&runtime, &authenticator, FOUNDER, 301)
            .unwrap();
        assert_eq!(final_mempool.pending_market_count(), 0);
        drop(final_mempool);
        drop(runtime);
        fs::remove_dir_all(root).unwrap();
    }
}
