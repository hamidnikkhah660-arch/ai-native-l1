//! CP-0592 service adapter joining the permissionless base runtime to native transaction ingress,
//! durable pending-transaction journal, deterministic mempool selection and bounded PoW mining.
//!
//! Q6TA Accepted means only that a signed native transfer is in the local bounded mempool and
//! its journal snapshot was installed. A mined block is reported only after the permissionless
//! runtime durably commits its QFP6 envelope. This is not peer discovery, public listener,
//! full-history network sync, payout finality, or a production miner supervisor.

use crate::{
    qrun_v06_canonical_execution_candidate::QRunV06BlockOperation,
    qrun_v06_miner_candidate::{
        mine_qfp6_block_on_tip_from_nonce, QRunV06MinedBlock, QRunV06MiningError,
    },
    qrun_v06_node_runtime_candidate::QRunV06PeerReplayGuard,
    qrun_v06_permissionless_runtime_candidate::{
        QRunV06PermissionlessNodeRuntime, QRunV06PermissionlessRuntimeError,
    },
    qrun_v06_pow_fork_store_candidate::QRunV06DurableCommit,
    qrun_v06_transaction_ingress_candidate::{
        decode_q6ta_response, decode_q6ti_transaction_request, process_q6ti_transaction_frame,
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

pub struct QRunV06PermissionlessMempool {
    pool: QRunV06NativeTransactionMempool,
    journal: QRunV06TransactionJournal,
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
        let pool = QRunV06NativeTransactionMempool::new(limits).map_err(|error| {
            QRunV06PermissionlessServiceError::Journal(format!("invalid mempool limits: {error:?}"))
        })?;
        let journal = QRunV06TransactionJournal::open(directory, limits)?;
        Ok(Self {
            pool,
            journal,
            next_pow_nonce: 0,
        })
    }

    pub fn pending_count(&self) -> usize {
        self.pool.len()
    }
    pub fn pending_bytes(&self) -> usize {
        self.pool.total_bytes()
    }
    pub fn journal_generation(&self) -> u64 {
        self.journal.generation()
    }
    pub fn next_pow_nonce(&self) -> u64 {
        self.next_pow_nonce
    }

    /// Revalidate pending native transfers after a peer-admitted canonical block/reorg and
    /// durably install the resulting journal generation before the next mining round.
    pub fn reconcile_after_canonical_change<A: TransactionAuthenticator>(
        &mut self,
        runtime: &QRunV06PermissionlessNodeRuntime,
        authenticator: &A,
        producer: AccountId,
        candidate_timestamp: u64,
    ) -> Result<(), QRunV06PermissionlessServiceError> {
        let graph = runtime.fork_choice_snapshot()?;
        let _ = self.pool.reconcile_after_canonical_change(
            graph.canonical_state(),
            authenticator,
            producer,
            candidate_timestamp,
            &[],
        );
        self.journal.persist_pool(&self.pool)?;
        Ok(())
    }

    /// Restore and revalidate pending transactions against the exact durable canonical state.
    /// Candidate time is supplied by the node's clock policy; this module does not invent it.
    pub fn restore<A: TransactionAuthenticator>(
        &mut self,
        runtime: &QRunV06PermissionlessNodeRuntime,
        authenticator: &A,
        producer: AccountId,
        candidate_timestamp: u64,
    ) -> Result<QRunV06TransactionJournalRestoreSummary, QRunV06PermissionlessServiceError> {
        let graph = runtime.fork_choice_snapshot()?;
        Ok(self.journal.restore_into_pool(
            &mut self.pool,
            graph.canonical_state(),
            authenticator,
            producer,
            candidate_timestamp,
        )?)
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
        let request = decode_q6ti_transaction_request(frame)
            .map_err(|error| QRunV06PermissionlessServiceError::Ingress(format!("{error:?}")))?;
        let graph = runtime.fork_choice_snapshot()?;
        let before = self.pool.clone();
        let response = process_q6ti_transaction_frame(
            frame,
            replay_guard,
            &mut self.pool,
            graph.canonical_state(),
            authenticator,
            producer,
            candidate_timestamp,
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
        // Empty templates are valid PoW blocks too: issuance is height-derived by consensus,
        // not conditional on a mempool transaction being present.
        let graph = runtime.fork_choice_snapshot()?;
        let parent_tip = graph.canonical_tip().tip_hash;
        let transactions = self.pool.ordered_transactions();
        let operations = transactions
            .iter()
            .cloned()
            .map(QRunV06BlockOperation::NativeTransfer)
            .collect();
        let mined = match mine_qfp6_block_on_tip_from_nonce(
            &graph,
            &parent_tip,
            candidate_timestamp,
            producer,
            operations,
            authenticator,
            self.next_pow_nonce,
            max_nonce_attempts,
            cancellation,
        ) {
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
        let durable_commit = runtime.submit_envelope(&mined.envelope, authenticator)?;
        let updated_graph = runtime.fork_choice_snapshot()?;
        let became_canonical =
            exact_mined_block_became_canonical(&durable_commit, mined.block_digest);
        // A canonical block changes the parent/template, so its successor may start at nonce 0.
        // A side-branch commit leaves the same canonical template eligible and advances instead.
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
        let revalidation_base = updated_graph
            .canonical_state()
            .last_timestamp()
            .max(candidate_timestamp);
        // Saturate at the timestamp ceiling: never fail after the block is already committed.
        let next_timestamp = revalidation_base.saturating_add(1);
        let _ = self.pool.reconcile_after_canonical_change(
            updated_graph.canonical_state(),
            authenticator,
            producer,
            next_timestamp,
            &[],
        );
        let journal_generation = self.journal.persist_pool(&self.pool).map_err(|error| {
            QRunV06PermissionlessServiceError::Journal(format!(
                "block is already durably committed; pending-journal refresh failed: {error}"
            ))
        })?;
        Ok(Some(QRunV06PermissionlessMiningCommit {
            mined,
            durable_commit,
            removed_transactions,
            journal_generation,
            became_canonical,
        }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06PermissionlessMiningCommit {
    pub mined: QRunV06MinedBlock,
    pub durable_commit: QRunV06DurableCommit,
    pub removed_transactions: usize,
    pub journal_generation: u64,
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
}
