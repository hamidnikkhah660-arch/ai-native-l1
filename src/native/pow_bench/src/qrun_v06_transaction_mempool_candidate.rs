//! Candidate-only bounded QFP6 native transaction pool.
//! Uses the QFP6 8 KiB NativeTransfer codec for Q6HA envelopes; legacy TXN2 remains 4 KiB.
//! Process-local only: no RPC, P2P, disk persistence or production node lifecycle.
use crate::{
    qrun_v06_canonical_execution_candidate::{
        encode_qrun_v06_block, QRunV06Block, QRunV06BlockOperation, QRunV06CanonicalExecutionState,
        QRunV06ExecutionError, MAX_QRUN_V06_BLOCK_BYTES, MAX_QRUN_V06_BLOCK_OPERATIONS,
    },
    state_machine::{
        encode_transaction_with_signature_limit, transaction_id_with_signature_limit, AccountId,
        StateError, Transaction, TransactionAuthenticator, QRUN_V06_MAX_NATIVE_TX_SIGNATURE_BYTES,
    },
};
use std::collections::BTreeMap;

pub const DEFAULT_QRUN_V06_MEMPOOL_TRANSACTIONS: usize = 128;
pub const DEFAULT_QRUN_V06_MEMPOOL_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QRunV06MempoolLimits {
    pub max_transactions: usize,
    pub max_bytes: usize,
}

impl Default for QRunV06MempoolLimits {
    fn default() -> Self {
        Self {
            max_transactions: DEFAULT_QRUN_V06_MEMPOOL_TRANSACTIONS,
            max_bytes: DEFAULT_QRUN_V06_MEMPOOL_BYTES,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QRunV06MempoolError {
    InvalidLimits,
    WrongNetwork,
    Expired {
        expires_at: u64,
        candidate_timestamp: u64,
    },
    TimestampNotIncreasing {
        previous: u64,
        candidate: u64,
    },
    InvalidProducer,
    Duplicate,
    TransactionLimit,
    ByteLimit,
    Empty,
    HeightOverflow,
    State(StateError),
    Execution(QRunV06ExecutionError),
    Wire(QRunV06ExecutionError),
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct QRunV06MempoolReconcileSummary {
    pub kept: usize,
    pub dropped_confirmed: usize,
    pub dropped_expired: usize,
    pub dropped_invalid: usize,
}

#[derive(Debug, Clone)]
struct Entry {
    transaction: Transaction,
    encoded_len: usize,
}

/// A bounded pool whose admission preview uses the exact QFP6 canonical execution engine.
/// The full proposed block is checked before the pool mutates, so nonce, balance, fee,
/// expiry, network, signature and state-root rules match subsequent canonical execution.
#[derive(Debug, Clone)]
pub struct QRunV06NativeTransactionMempool {
    limits: QRunV06MempoolLimits,
    entries: BTreeMap<[u8; 32], Entry>,
    total_bytes: usize,
}

impl QRunV06NativeTransactionMempool {
    pub fn new(limits: QRunV06MempoolLimits) -> Result<Self, QRunV06MempoolError> {
        if limits.max_transactions == 0
            || limits.max_transactions > MAX_QRUN_V06_BLOCK_OPERATIONS
            || limits.max_bytes == 0
            || limits.max_bytes > MAX_QRUN_V06_BLOCK_BYTES
        {
            return Err(QRunV06MempoolError::InvalidLimits);
        }
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

    pub fn ordered_transactions(&self) -> Vec<Transaction> {
        let mut transactions: Vec<_> = self
            .entries
            .values()
            .map(|entry| entry.transaction.clone())
            .collect();
        transactions.sort_by_key(|tx| {
            let id =
                transaction_id_with_signature_limit(tx, QRUN_V06_MAX_NATIVE_TX_SIGNATURE_BYTES)
                    .unwrap_or([0; 32]);
            (tx.sender, tx.nonce, id)
        });
        transactions
    }

    fn candidate_block(
        state: &QRunV06CanonicalExecutionState,
        transactions: Vec<Transaction>,
        producer: AccountId,
        candidate_timestamp: u64,
    ) -> Result<QRunV06Block, QRunV06MempoolError> {
        if transactions.is_empty() {
            return Err(QRunV06MempoolError::Empty);
        }
        if producer.iter().all(|b| *b == 0) {
            return Err(QRunV06MempoolError::InvalidProducer);
        }
        if candidate_timestamp <= state.last_timestamp() {
            return Err(QRunV06MempoolError::TimestampNotIncreasing {
                previous: state.last_timestamp(),
                candidate: candidate_timestamp,
            });
        }
        let height = state
            .height()
            .checked_add(1)
            .ok_or(QRunV06MempoolError::HeightOverflow)?;
        if transactions.len() > MAX_QRUN_V06_BLOCK_OPERATIONS {
            return Err(QRunV06MempoolError::TransactionLimit);
        }
        Ok(QRunV06Block {
            network_id: state.network_id(),
            profile_id: state.profile_id(),
            height,
            timestamp: candidate_timestamp,
            parent_hash: state.tip_hash(),
            state_root: [0; 32],
            producer,
            operations: transactions
                .into_iter()
                .map(QRunV06BlockOperation::NativeTransfer)
                .collect(),
        })
    }

    /// Admit only after the entire ordered candidate block passes canonical QFP6 execution.
    /// Rejected transactions leave both the entries and byte accounting unchanged.
    pub fn submit<A: TransactionAuthenticator>(
        &mut self,
        transaction: Transaction,
        state: &QRunV06CanonicalExecutionState,
        authenticator: &A,
        producer: AccountId,
        candidate_timestamp: u64,
    ) -> Result<[u8; 32], QRunV06MempoolError> {
        if transaction.network_id != state.network_id() {
            return Err(QRunV06MempoolError::WrongNetwork);
        }
        if candidate_timestamp >= transaction.expires_at {
            return Err(QRunV06MempoolError::Expired {
                expires_at: transaction.expires_at,
                candidate_timestamp,
            });
        }
        let encoded = encode_transaction_with_signature_limit(
            &transaction,
            QRUN_V06_MAX_NATIVE_TX_SIGNATURE_BYTES,
        )
        .map_err(QRunV06MempoolError::State)?;
        let txid = transaction_id_with_signature_limit(
            &transaction,
            QRUN_V06_MAX_NATIVE_TX_SIGNATURE_BYTES,
        )
        .map_err(QRunV06MempoolError::State)?;
        if self.entries.contains_key(&txid) {
            return Err(QRunV06MempoolError::Duplicate);
        }
        if self.entries.len() >= self.limits.max_transactions {
            return Err(QRunV06MempoolError::TransactionLimit);
        }
        let next_bytes = self
            .total_bytes
            .checked_add(encoded.len())
            .ok_or(QRunV06MempoolError::ByteLimit)?;
        if next_bytes > self.limits.max_bytes {
            return Err(QRunV06MempoolError::ByteLimit);
        }

        let mut proposed = self.ordered_transactions();
        proposed.push(transaction.clone());
        proposed.sort_by_key(|tx| {
            let id =
                transaction_id_with_signature_limit(tx, QRUN_V06_MAX_NATIVE_TX_SIGNATURE_BYTES)
                    .unwrap_or([0; 32]);
            (tx.sender, tx.nonce, id)
        });
        let mut block = Self::candidate_block(state, proposed, producer, candidate_timestamp)?;
        block.state_root = state
            .preview_state_root_after(&block, authenticator)
            .map_err(QRunV06MempoolError::Execution)?;
        encode_qrun_v06_block(&block).map_err(QRunV06MempoolError::Wire)?;

        self.entries.insert(
            txid,
            Entry {
                transaction,
                encoded_len: encoded.len(),
            },
        );
        self.total_bytes = next_bytes;
        Ok(txid)
    }

    /// Produce the deterministic QFB6 NativeTransfer body without clearing pending entries.
    /// The caller still must mine/validate PoW and durably admit it through QAP1.
    pub fn build_block<A: TransactionAuthenticator>(
        &self,
        state: &QRunV06CanonicalExecutionState,
        authenticator: &A,
        producer: AccountId,
        candidate_timestamp: u64,
    ) -> Result<QRunV06Block, QRunV06MempoolError> {
        let mut block = Self::candidate_block(
            state,
            self.ordered_transactions(),
            producer,
            candidate_timestamp,
        )?;
        block.state_root = state
            .preview_state_root_after(&block, authenticator)
            .map_err(QRunV06MempoolError::Execution)?;
        encode_qrun_v06_block(&block).map_err(QRunV06MempoolError::Wire)?;
        Ok(block)
    }

    /// Remove transactions only after their containing block is canonically acknowledged.
    pub fn remove_included(&mut self, included: &[Transaction]) -> usize {
        let mut removed = 0usize;
        for tx in included {
            let Ok(id) =
                transaction_id_with_signature_limit(tx, QRUN_V06_MAX_NATIVE_TX_SIGNATURE_BYTES)
            else {
                continue;
            };
            if let Some(entry) = self.entries.remove(&id) {
                self.total_bytes = self.total_bytes.saturating_sub(entry.encoded_len);
                removed += 1;
            }
        }
        removed
    }

    /// Revalidate after a canonical-tip change or reorg. Confirmed entries are removed;
    /// expired and now-invalid/non-executable entries are dropped.
    pub fn reconcile_after_canonical_change<A: TransactionAuthenticator>(
        &mut self,
        state: &QRunV06CanonicalExecutionState,
        authenticator: &A,
        producer: AccountId,
        candidate_timestamp: u64,
        confirmed_ids: &[[u8; 32]],
    ) -> QRunV06MempoolReconcileSummary {
        let confirmed: std::collections::HashSet<[u8; 32]> =
            confirmed_ids.iter().copied().collect();
        let prior = self.ordered_transactions();
        self.entries.clear();
        self.total_bytes = 0;
        let mut result = QRunV06MempoolReconcileSummary::default();
        for tx in prior {
            let id =
                transaction_id_with_signature_limit(&tx, QRUN_V06_MAX_NATIVE_TX_SIGNATURE_BYTES)
                    .unwrap_or([0; 32]);
            if confirmed.contains(&id) {
                result.dropped_confirmed += 1;
            } else if candidate_timestamp >= tx.expires_at {
                result.dropped_expired += 1;
            } else if self
                .submit(tx, state, authenticator, producer, candidate_timestamp)
                .is_ok()
            {
                result.kept += 1;
            } else {
                result.dropped_invalid += 1;
            }
        }
        result
    }
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
        state_machine::{transaction_signing_digest, Transaction},
        v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate,
    };
    use ed25519_dalek::{Signer, SigningKey};

    const NETWORK: [u8; 32] = [0x91; 32];
    const PROFILE: [u8; 32] = [0x92; 32];
    const PRODUCER: [u8; 32] = [0x93; 32];
    const RECIPIENT: [u8; 32] = [0x94; 32];

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

    fn tx(signer: &QRunV06HybridTransactionSigner, nonce: u64) -> Transaction {
        let mut t = Transaction {
            network_id: NETWORK,
            sender: signer.account_id(),
            recipient: RECIPIENT,
            nonce,
            amount: 10_000,
            fee: 10,
            expires_at: 10_000,
            signature: Vec::new(),
        };
        signer.sign_transaction(&mut t).unwrap();
        t
    }

    #[test]
    fn q6ha_hybrid_transfer_fits_mempool_and_builds_qfb6_native_transfer() {
        let signer = QRunV06HybridTransactionSigner::from_seeds([0xA1; 32], [0xA2; 32]).unwrap();
        let state = genesis(signer.account_id());
        let auth = QRunV06HybridTransactionAuthenticator::new(LibcruxMlDsa65VerifierCandidate);
        let mut pool =
            QRunV06NativeTransactionMempool::new(QRunV06MempoolLimits::default()).unwrap();
        let ts = state.last_timestamp() + 60;
        let id = pool
            .submit(tx(&signer, 1), &state, &auth, PRODUCER, ts)
            .unwrap();
        assert_eq!(pool.len(), 1);
        assert!(pool.total_bytes() > 4 * 1024);
        let block = pool.build_block(&state, &auth, PRODUCER, ts).unwrap();
        assert_eq!(block.operations.len(), 1);
        match &block.operations[0] {
            QRunV06BlockOperation::NativeTransfer(t) => {
                assert_eq!(t.signature.len(), 5_365);
                assert_eq!(
                    transaction_id_with_signature_limit(t, QRUN_V06_MAX_NATIVE_TX_SIGNATURE_BYTES)
                        .unwrap(),
                    id
                );
            }
            _ => panic!("expected native transfer"),
        }
        let included = pool.ordered_transactions();
        assert_eq!(pool.remove_included(&included), 1);
        assert!(pool.is_empty());
    }

    #[test]
    fn q6ha_mempool_rejects_legacy_ed25519_only_signature_atomically() {
        let signer = QRunV06HybridTransactionSigner::from_seeds([0xB1; 32], [0xB2; 32]).unwrap();
        let state = genesis(signer.account_id());
        let auth = QRunV06HybridTransactionAuthenticator::new(LibcruxMlDsa65VerifierCandidate);
        let mut pool =
            QRunV06NativeTransactionMempool::new(QRunV06MempoolLimits::default()).unwrap();
        let mut bad = tx(&signer, 1);
        let digest = transaction_signing_digest(&bad).unwrap();
        bad.signature = SigningKey::from_bytes(&[0xB3; 32])
            .sign(&digest)
            .to_bytes()
            .to_vec();
        assert!(pool
            .submit(bad, &state, &auth, PRODUCER, state.last_timestamp() + 60)
            .is_err());
        assert!(pool.is_empty());
        assert_eq!(pool.total_bytes(), 0);
    }

    #[test]
    fn q6ha_mempool_orders_nonce_chain_and_retains_successor_after_confirmation() {
        let signer = QRunV06HybridTransactionSigner::from_seeds([0xC1; 32], [0xC2; 32]).unwrap();
        let mut state = genesis(signer.account_id());
        let auth = QRunV06HybridTransactionAuthenticator::new(LibcruxMlDsa65VerifierCandidate);
        let mut pool =
            QRunV06NativeTransactionMempool::new(QRunV06MempoolLimits::default()).unwrap();
        let ts = state.last_timestamp() + 60;
        pool.submit(tx(&signer, 1), &state, &auth, PRODUCER, ts)
            .unwrap();
        pool.submit(tx(&signer, 2), &state, &auth, PRODUCER, ts)
            .unwrap();
        let txs = pool.ordered_transactions();
        assert_eq!(txs.iter().map(|t| t.nonce).collect::<Vec<_>>(), vec![1, 2]);
        // Confirm only nonce 1. Nonce 2 remains pending and must stay executable
        // against the successor canonical state.
        let mut first_only =
            QRunV06NativeTransactionMempool::new(QRunV06MempoolLimits::default()).unwrap();
        first_only
            .submit(txs[0].clone(), &state, &auth, PRODUCER, ts)
            .unwrap();
        let block = first_only.build_block(&state, &auth, PRODUCER, ts).unwrap();
        state.apply_block(&block, &auth).unwrap();
        let confirmed =
            [
                transaction_id_with_signature_limit(
                    &txs[0],
                    QRUN_V06_MAX_NATIVE_TX_SIGNATURE_BYTES,
                )
                .unwrap(),
            ];
        let summary = pool.reconcile_after_canonical_change(
            &state,
            &auth,
            PRODUCER,
            state.last_timestamp() + 60,
            &confirmed,
        );
        assert_eq!(summary.dropped_confirmed, 1);
        assert_eq!(summary.kept, 1);
        assert_eq!(pool.ordered_transactions()[0].nonce, 2);
    }
}
