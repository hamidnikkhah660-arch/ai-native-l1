//! Candidate-only bounded admission pool for canonical TXN4 hybrid transactions.
//!
//! This module is not wired into the node CLI, peer protocol, RPC, or production runtime.
//! Admission validates the complete prospective pool against the canonical V4 monetary
//! state-transition preview before mutating membership. It uses deterministic sender/nonce
//! ordering and hard count/byte bounds, but it is not a frozen fee market, replacement,
//! anti-spam, persistence, or peer-relay policy.
use crate::state_machine::{AccountId, MonetaryLedgerState, StateError, V4HybridMonetaryBlock};
use crate::v4_account_identity_candidate::{
    IdentityContinuityError, MlDsa65Verifier, V4HybridTransaction,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const DEFAULT_MAX_V4_MEMPOOL_TRANSACTIONS: usize = 128;
pub const DEFAULT_MAX_V4_MEMPOOL_BYTES: usize = 1024 * 1024;
const MEMPOOL_TX_ID_DOMAIN: &[u8] = b"AIN1-V4-MEMPOOL-TX-ID-V1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V4HybridMempoolLimits {
    pub max_transactions: usize,
    pub max_bytes: usize,
}

impl Default for V4HybridMempoolLimits {
    fn default() -> Self {
        Self {
            max_transactions: DEFAULT_MAX_V4_MEMPOOL_TRANSACTIONS,
            max_bytes: DEFAULT_MAX_V4_MEMPOOL_BYTES,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V4HybridMempoolError {
    InvalidLimits,
    WrongNetwork,
    ManifestMismatch,
    Expired {
        expires_at: u64,
        candidate_timestamp: u64,
    },
    InvalidTimestamp,
    Duplicate,
    TransactionLimit,
    ByteLimit,
    Identity(IdentityContinuityError),
    State(StateError),
    HeightOverflow,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct V4HybridMempoolReconcileSummary {
    pub kept: usize,
    pub dropped_expired: usize,
    pub dropped_invalid: usize,
}

#[derive(Debug, Clone)]
struct Entry {
    transaction: V4HybridTransaction,
    encoded_len: usize,
}

/// Per-process candidate admission pool. It performs no network or disk side effects.
#[derive(Debug, Clone)]
pub struct V4HybridMempoolCandidate {
    network_id: [u8; 32],
    manifest_id: [u8; 32],
    limits: V4HybridMempoolLimits,
    entries: BTreeMap<[u8; 32], Entry>,
    total_bytes: usize,
}

impl V4HybridMempoolCandidate {
    pub fn new(
        network_id: [u8; 32],
        manifest_id: [u8; 32],
        limits: V4HybridMempoolLimits,
    ) -> Result<Self, V4HybridMempoolError> {
        if network_id.iter().all(|byte| *byte == 0)
            || manifest_id.iter().all(|byte| *byte == 0)
            || limits.max_transactions == 0
            || limits.max_bytes == 0
        {
            return Err(V4HybridMempoolError::InvalidLimits);
        }
        Ok(Self {
            network_id,
            manifest_id,
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

    pub fn limits(&self) -> V4HybridMempoolLimits {
        self.limits
    }

    /// Admit a transaction only if the whole proposed pool forms a valid next-block
    /// transaction sequence against the supplied canonical state. Rejection never mutates
    /// the pool. The timestamp and miner identify the block context used for validation.
    pub fn submit<V: MlDsa65Verifier>(
        &mut self,
        transaction: V4HybridTransaction,
        state: &MonetaryLedgerState,
        verifier: &V,
        candidate_timestamp: u64,
        miner: AccountId,
    ) -> Result<[u8; 32], V4HybridMempoolError> {
        if state.ledger().network_id() != self.network_id
            || transaction.authorization.network_id != self.network_id
        {
            return Err(V4HybridMempoolError::WrongNetwork);
        }
        if transaction.authorization.manifest_id != self.manifest_id {
            return Err(V4HybridMempoolError::ManifestMismatch);
        }
        if candidate_timestamp <= state.ledger().last_timestamp() {
            return Err(V4HybridMempoolError::InvalidTimestamp);
        }
        if candidate_timestamp >= transaction.authorization.expires_at {
            return Err(V4HybridMempoolError::Expired {
                expires_at: transaction.authorization.expires_at,
                candidate_timestamp,
            });
        }

        let encoded = transaction
            .encode()
            .map_err(V4HybridMempoolError::Identity)?;
        let id = mempool_transaction_id(&encoded);
        if self.entries.contains_key(&id) {
            return Err(V4HybridMempoolError::Duplicate);
        }
        if self.entries.len() >= self.limits.max_transactions {
            return Err(V4HybridMempoolError::TransactionLimit);
        }
        let new_total_bytes = self
            .total_bytes
            .checked_add(encoded.len())
            .ok_or(V4HybridMempoolError::ByteLimit)?;
        if new_total_bytes > self.limits.max_bytes {
            return Err(V4HybridMempoolError::ByteLimit);
        }

        let mut proposed = self.ordered_transactions();
        proposed.push(transaction.clone());
        sort_transactions(&mut proposed);

        let height = state
            .height()
            .checked_add(1)
            .ok_or(V4HybridMempoolError::HeightOverflow)?;
        let block = V4HybridMonetaryBlock {
            height,
            timestamp: candidate_timestamp,
            parent_hash: state.tip_hash(),
            state_root: [0; 32],
            transactions: proposed,
            miner,
            claimed_subsidy_atoms: state
                .expected_miner_reward()
                .map_err(V4HybridMempoolError::State)?,
        };
        state
            .preview_v4_hybrid_state_root_after(&block, &self.manifest_id, verifier)
            .map_err(V4HybridMempoolError::State)?;

        self.entries.insert(
            id,
            Entry {
                transaction,
                encoded_len: encoded.len(),
            },
        );
        self.total_bytes = new_total_bytes;
        Ok(id)
    }

    /// Stable candidate selection order is AccountId, nonce, then local canonical-wire ID.
    /// This is a local pool policy, not a consensus ordering rule.
    pub fn ordered_transactions(&self) -> Vec<V4HybridTransaction> {
        let mut keyed: Vec<_> = self
            .entries
            .iter()
            .map(|(id, entry)| {
                (
                    (
                        entry.transaction.authorization.sender_id,
                        entry.transaction.authorization.nonce,
                        *id,
                    ),
                    entry.transaction.clone(),
                )
            })
            .collect();
        keyed.sort_by_key(|(key, _)| *key);
        keyed
            .into_iter()
            .map(|(_, transaction)| transaction)
            .collect()
    }

    /// Prune expired transactions and revalidate the remaining nonce/balance sequence against
    /// current canonical state. Dropping an expired nonce predecessor can invalidate successors,
    /// so expiry-only retention without this replay is unsafe for block selection.
    pub fn prune_expired<V: MlDsa65Verifier>(
        &mut self,
        canonical_state: &MonetaryLedgerState,
        verifier: &V,
        candidate_timestamp: u64,
        miner: AccountId,
    ) -> V4HybridMempoolReconcileSummary {
        self.reconcile_after_state_change(canonical_state, verifier, candidate_timestamp, miner)
    }

    /// Remove transactions confirmed by the selected canonical chain.
    pub fn remove_included(&mut self, included: &[V4HybridTransaction]) -> usize {
        let mut removed = 0;
        for transaction in included {
            let Ok(encoded) = transaction.encode() else {
                continue;
            };
            let id = mempool_transaction_id(&encoded);
            if let Some(entry) = self.entries.remove(&id) {
                self.total_bytes = self.total_bytes.saturating_sub(entry.encoded_len);
                removed += 1;
            }
        }
        removed
    }

    /// Rebuild the pool against a changed canonical state (including after reorg). Transactions
    /// confirmed on the new chain, expired, unaffordable, or nonce-incompatible are dropped;
    /// valid successors are revalidated in deterministic order before publication.
    pub fn reconcile_after_state_change<V: MlDsa65Verifier>(
        &mut self,
        canonical_state: &MonetaryLedgerState,
        verifier: &V,
        candidate_timestamp: u64,
        miner: AccountId,
    ) -> V4HybridMempoolReconcileSummary {
        let pending = self.ordered_transactions();
        let mut rebuilt = match Self::new(self.network_id, self.manifest_id, self.limits) {
            Ok(pool) => pool,
            Err(_) => {
                return V4HybridMempoolReconcileSummary {
                    kept: 0,
                    dropped_expired: 0,
                    dropped_invalid: pending.len(),
                }
            }
        };
        let mut summary = V4HybridMempoolReconcileSummary::default();
        for transaction in pending {
            if candidate_timestamp >= transaction.authorization.expires_at {
                summary.dropped_expired += 1;
                continue;
            }
            match rebuilt.submit(
                transaction,
                canonical_state,
                verifier,
                candidate_timestamp,
                miner,
            ) {
                Ok(_) => summary.kept += 1,
                Err(_) => summary.dropped_invalid += 1,
            }
        }
        *self = rebuilt;
        summary
    }
}

fn sort_transactions(transactions: &mut [V4HybridTransaction]) {
    transactions.sort_by_key(|transaction| {
        (
            transaction.authorization.sender_id,
            transaction.authorization.nonce,
            transaction
                .encode()
                .map(|bytes| mempool_transaction_id(&bytes))
                .unwrap_or([0xff; 32]),
        )
    });
}

/// This pool-local identifier hashes the exact canonical TXN4 bytes. It is not a consensus block
/// ID and does not replace any transaction identifier frozen by the protocol specification.
fn mempool_transaction_id(encoded: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(MEMPOOL_TX_ID_DOMAIN);
    hash.update(encoded);
    hash.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_machine::{MonetaryLedgerState, MONETARY_PUBLIC_GOODS_BUDGET_ATOMS};
    use crate::v4_account_identity_candidate::{
        native_v4_account_id, AccountIdentityScheme, V4HybridAuthorization, V4HybridSignature,
    };
    use crate::v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate;
    use ed25519_dalek::{Signer, SigningKey};
    use libcrux_ml_dsa::ml_dsa_65::portable;
    use std::time::{SystemTime, UNIX_EPOCH};

    const NETWORK: [u8; 32] = [0x61; 32];
    const MANIFEST: [u8; 32] = [0x72; 32];
    const RECIPIENT: [u8; 32] = [0xAA; 32];
    const PUBLIC_GOODS: [u8; 32] = [0x88; 32];
    const MINER: [u8; 32] = [0x99; 32];

    fn timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn signing_material() -> (SigningKey, [u8; 32]) {
        let ed = SigningKey::from_bytes(&[0x31; 32]);
        let pq = portable::generate_key_pair([0x42; 32]);
        let ed_public = ed.verifying_key().to_bytes();
        let pq_public = *pq.verification_key.as_ref();
        let sender = native_v4_account_id(&ed_public, &pq_public);
        (ed, sender)
    }

    fn genesis() -> (MonetaryLedgerState, [u8; 32]) {
        let (_, sender) = signing_material();
        let public_goods_budget = u64::try_from(MONETARY_PUBLIC_GOODS_BUDGET_ATOMS).unwrap();
        let state = MonetaryLedgerState::genesis(
            NETWORK,
            sender,
            vec![(PUBLIC_GOODS, public_goods_budget)],
        )
        .unwrap();
        (state, sender)
    }

    fn signed_transaction(
        nonce: u64,
        amount_atoms: u64,
        fee_atoms: u64,
        expires_at: u64,
        network_id: [u8; 32],
        manifest_id: [u8; 32],
    ) -> V4HybridTransaction {
        let (ed, sender_id) = signing_material();
        let pq = portable::generate_key_pair([0x42; 32]);
        let ed_public = ed.verifying_key().to_bytes();
        let pq_public = *pq.verification_key.as_ref();
        let authorization = V4HybridAuthorization {
            network_id,
            manifest_id,
            sender_id,
            recipient_id: RECIPIENT,
            nonce,
            amount_atoms,
            fee_atoms,
            expires_at,
            identity_scheme: AccountIdentityScheme::NativeV4Hybrid,
            ed25519_public_key: ed_public,
            mldsa65_public_key: pq_public,
        };
        let digest = authorization.signing_digest().unwrap();
        let signature = portable::sign(&pq.signing_key, &digest, &[], [0x53; 32]).unwrap();
        V4HybridTransaction {
            authorization,
            signature: V4HybridSignature {
                ed25519_signature: ed.sign(&digest).to_bytes(),
                mldsa65_signature: *signature.as_ref(),
            },
        }
    }

    fn pool(limits: V4HybridMempoolLimits) -> V4HybridMempoolCandidate {
        V4HybridMempoolCandidate::new(NETWORK, MANIFEST, limits).unwrap()
    }

    #[test]
    fn nonce_sequence_duplicate_rejection_and_deterministic_order() {
        let (state, _) = genesis();
        let now = timestamp();
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let mut pool = pool(V4HybridMempoolLimits::default());
        let tx1 = signed_transaction(1, 1_000, 17, now + 3_600, NETWORK, MANIFEST);
        let tx2 = signed_transaction(2, 2_000, 17, now + 3_600, NETWORK, MANIFEST);

        assert!(pool
            .submit(tx2.clone(), &state, &verifier, now, MINER)
            .is_err());
        assert!(pool.is_empty());
        pool.submit(tx1.clone(), &state, &verifier, now, MINER)
            .unwrap();
        assert_eq!(
            pool.submit(tx1.clone(), &state, &verifier, now, MINER),
            Err(V4HybridMempoolError::Duplicate)
        );
        pool.submit(tx2.clone(), &state, &verifier, now, MINER)
            .unwrap();
        let ordered = pool.ordered_transactions();
        assert_eq!(ordered.len(), 2);
        assert_eq!(ordered[0].authorization.nonce, 1);
        assert_eq!(ordered[1].authorization.nonce, 2);
        assert!(pool.total_bytes() > 0);
    }

    #[test]
    fn invalid_signature_wrong_network_manifest_and_expiry_fail_closed() {
        let (state, _) = genesis();
        let now = timestamp();
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let mut pool = pool(V4HybridMempoolLimits::default());

        let mut invalid = signed_transaction(1, 1_000, 17, now + 3_600, NETWORK, MANIFEST);
        invalid.signature.mldsa65_signature[0] ^= 1;
        assert!(pool.submit(invalid, &state, &verifier, now, MINER).is_err());
        assert!(pool.is_empty());

        let wrong_network = signed_transaction(1, 1_000, 17, now + 3_600, [0x62; 32], MANIFEST);
        assert_eq!(
            pool.submit(wrong_network, &state, &verifier, now, MINER),
            Err(V4HybridMempoolError::WrongNetwork)
        );
        let wrong_manifest = signed_transaction(1, 1_000, 17, now + 3_600, NETWORK, [0x73; 32]);
        assert_eq!(
            pool.submit(wrong_manifest, &state, &verifier, now, MINER),
            Err(V4HybridMempoolError::ManifestMismatch)
        );
        let expired = signed_transaction(1, 1_000, 17, now, NETWORK, MANIFEST);
        assert!(matches!(
            pool.submit(expired, &state, &verifier, now, MINER),
            Err(V4HybridMempoolError::Expired { .. })
        ));
        assert!(pool.is_empty());
        assert_eq!(pool.total_bytes(), 0);
    }

    #[test]
    fn limits_reject_without_partial_pool_mutation() {
        let (state, _) = genesis();
        let now = timestamp();
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let one = signed_transaction(1, 1_000, 17, now + 3_600, NETWORK, MANIFEST);
        let two = signed_transaction(2, 1_000, 17, now + 3_600, NETWORK, MANIFEST);
        let mut count_limited = pool(V4HybridMempoolLimits {
            max_transactions: 1,
            max_bytes: DEFAULT_MAX_V4_MEMPOOL_BYTES,
        });
        count_limited
            .submit(one.clone(), &state, &verifier, now, MINER)
            .unwrap();
        let before_bytes = count_limited.total_bytes();
        assert_eq!(
            count_limited.submit(two, &state, &verifier, now, MINER),
            Err(V4HybridMempoolError::TransactionLimit)
        );
        assert_eq!(count_limited.len(), 1);
        assert_eq!(count_limited.total_bytes(), before_bytes);

        let mut byte_limited = pool(V4HybridMempoolLimits {
            max_transactions: 4,
            max_bytes: one.encode().unwrap().len() - 1,
        });
        assert_eq!(
            byte_limited.submit(one, &state, &verifier, now, MINER),
            Err(V4HybridMempoolError::ByteLimit)
        );
        assert!(byte_limited.is_empty());
    }

    #[test]
    fn reconciliation_after_inclusion_keeps_valid_nonce_successor() {
        let (mut state, sender) = genesis();
        let now = timestamp();
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let mut pool = pool(V4HybridMempoolLimits::default());
        let tx1 = signed_transaction(1, 1_000, 17, now + 3_600, NETWORK, MANIFEST);
        let tx2 = signed_transaction(2, 2_000, 17, now + 3_600, NETWORK, MANIFEST);
        pool.submit(tx1.clone(), &state, &verifier, now, MINER)
            .unwrap();
        pool.submit(tx2.clone(), &state, &verifier, now, MINER)
            .unwrap();

        let mut block = V4HybridMonetaryBlock {
            height: state.height() + 1,
            timestamp: now,
            parent_hash: state.tip_hash(),
            state_root: [0; 32],
            transactions: vec![tx1.clone()],
            miner: MINER,
            claimed_subsidy_atoms: state.expected_miner_reward().unwrap(),
        };
        block.state_root = state
            .preview_v4_hybrid_state_root_after(&block, &MANIFEST, &verifier)
            .unwrap();
        state
            .apply_v4_hybrid_block_candidate(&block, &MANIFEST, &verifier)
            .unwrap();
        assert_eq!(state.ledger().account(&sender).unwrap().nonce, 1);

        let summary = pool.reconcile_after_state_change(&state, &verifier, now + 1, MINER);
        assert_eq!(summary.kept, 1);
        assert_eq!(summary.dropped_invalid, 1);
        assert_eq!(summary.dropped_expired, 0);
        assert_eq!(pool.len(), 1);
        assert_eq!(pool.ordered_transactions()[0].authorization.nonce, 2);
    }

    #[test]
    fn expiry_pruning_drops_nonce_successors_that_are_no_longer_executable() {
        let (state, _) = genesis();
        let now = timestamp();
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let first = signed_transaction(1, 1_000, 17, now + 1, NETWORK, MANIFEST);
        let second = signed_transaction(2, 2_000, 17, now + 3_600, NETWORK, MANIFEST);
        let mut pool = pool(V4HybridMempoolLimits::default());
        pool.submit(first, &state, &verifier, now, MINER).unwrap();
        pool.submit(second, &state, &verifier, now, MINER).unwrap();
        assert_eq!(pool.len(), 2);

        let summary = pool.prune_expired(&state, &verifier, now + 1, MINER);
        assert_eq!(summary.dropped_expired, 1);
        assert_eq!(summary.dropped_invalid, 1);
        assert!(pool.is_empty());
        assert_eq!(pool.total_bytes(), 0);
    }
}
