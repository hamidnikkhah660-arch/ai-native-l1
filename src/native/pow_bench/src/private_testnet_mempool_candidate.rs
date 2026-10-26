//! Bounded, deterministic transaction-pool candidate.
//!
//! This module is wired only into the opt-in, loopback-only QZBE transaction-ingress candidate.
//! It is not wired into the legacy PTB2/PFS2 private node, public peer transaction gossip, or
//! the canonical production node runtime.
//! It delegates transaction/network/expiry/nonce/balance/signature checks to the
//! canonical ledger preview path and adds local resource limits and deterministic policy.
//! Current conflict-policy candidate: regular admission is no-replacement/first-valid-accepted;
//! after reorg, an existing valid pending entry beats a re-admission alternative, while two or
//! more valid re-admission candidates sharing a sender/nonce are all rejected. Invalid candidates
//! are filtered before conflict grouping so unauthenticated input cannot poison a valid group.
//! None of these local choices is a frozen consensus rule or a production fee policy.
use crate::state_machine::{
    encode_transaction, transaction_id, transaction_signing_digest, AccountId, Block, LedgerState,
    StateError, Transaction, TransactionAuthenticator, MAX_TRANSACTIONS_PER_BLOCK,
};
use std::collections::{BTreeMap, HashSet};

pub const DEFAULT_MAX_MEMPOOL_TRANSACTIONS: usize = 256;
pub const DEFAULT_MAX_MEMPOOL_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MempoolLimits {
    pub max_transactions: usize,
    pub max_bytes: usize,
}

impl Default for MempoolLimits {
    fn default() -> Self {
        Self {
            max_transactions: DEFAULT_MAX_MEMPOOL_TRANSACTIONS,
            max_bytes: DEFAULT_MAX_MEMPOOL_BYTES,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MempoolError {
    State(StateError),
    WrongNetwork,
    Expired {
        expires_at: u64,
        candidate_timestamp: u64,
    },
    Duplicate,
    TransactionLimit,
    ByteLimit,
    HeightOverflow,
}

/// Counts how reconciliation handled old pending entries and explicit re-admission candidates.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MempoolReconciliationSummary {
    pub kept: usize,
    pub readmitted: usize,
    pub skipped_confirmed: usize,
    pub dropped_expired: usize,
    pub dropped_invalid: usize,
}

#[derive(Debug, Clone)]
struct Entry {
    transaction: Transaction,
    encoded_len: usize,
    signing_digest: [u8; 32],
}

/// Delegates to the active authenticator except for signatures cached under the pool's
/// exact, current verifier fingerprint. The referenced set is not mutated during preview.
struct ScopedCacheAuthenticator<'a, A: TransactionAuthenticator> {
    inner: &'a A,
    trusted: &'a HashSet<(AccountId, [u8; 32], Vec<u8>)>,
}

impl<A: TransactionAuthenticator> TransactionAuthenticator for ScopedCacheAuthenticator<'_, A> {
    fn verify(
        &self,
        sender: &AccountId,
        signing_digest: &[u8; 32],
        signature: &[u8],
    ) -> Result<(), ()> {
        if self
            .trusted
            .contains(&(*sender, *signing_digest, signature.to_vec()))
        {
            return Ok(());
        }
        self.inner.verify(sender, signing_digest, signature)
    }

    fn verification_cache_scope(&self) -> Option<[u8; 32]> {
        self.inner.verification_cache_scope()
    }
}

/// A per-process candidate pool. No network or disk side effects are performed.
#[derive(Debug, Clone)]
pub struct BoundedMempool {
    limits: MempoolLimits,
    entries: BTreeMap<[u8; 32], Entry>,
    total_bytes: usize,
    verification_cache_scope: Option<[u8; 32]>,
    verified_signatures: HashSet<(AccountId, [u8; 32], Vec<u8>)>,
}

impl BoundedMempool {
    pub fn new(limits: MempoolLimits) -> Result<Self, MempoolError> {
        if limits.max_transactions == 0
            || limits.max_transactions > MAX_TRANSACTIONS_PER_BLOCK
            || limits.max_bytes == 0
        {
            return Err(MempoolError::TransactionLimit);
        }
        Ok(Self {
            limits,
            entries: BTreeMap::new(),
            total_bytes: 0,
            verification_cache_scope: None,
            verified_signatures: HashSet::new(),
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

    pub fn limits(&self) -> MempoolLimits {
        self.limits
    }

    /// Validate the entire prospective pool against one deterministic block ordering
    /// before committing the new entry. Rejected submissions leave the pool unchanged.
    pub fn submit<A: TransactionAuthenticator>(
        &mut self,
        tx: Transaction,
        state: &LedgerState,
        authenticator: &A,
        candidate_timestamp: u64,
    ) -> Result<[u8; 32], MempoolError> {
        if tx.network_id != state.network_id() {
            return Err(MempoolError::WrongNetwork);
        }
        if candidate_timestamp >= tx.expires_at {
            return Err(MempoolError::Expired {
                expires_at: tx.expires_at,
                candidate_timestamp,
            });
        }
        let encoded = encode_transaction(&tx).map_err(MempoolError::State)?;
        let id = transaction_id(&tx).map_err(MempoolError::State)?;
        let signing_digest = transaction_signing_digest(&tx).map_err(MempoolError::State)?;
        let scope = authenticator.verification_cache_scope();
        let scope_changed = self.verification_cache_scope != scope;
        // Only a new, explicitly fingerprinted scope can authorize temporary reuse of successful
        // incumbent checks while building the prospective preview. None remains strictly no-cache.
        let rebuild_for_new_scope = scope.is_some() && scope_changed;

        // When verifier scope changes, stage a fresh pool containing only incumbent signatures
        // accepted by the new verifier. Do not mutate the live pool unless the new candidate and
        // the staged pool both pass the canonical ledger preview. This prevents a revoked key's
        // pending transaction from permanently blocking all future admissions under the new scope.
        let mut staged_entries = BTreeMap::new();
        let mut preverified_signatures = HashSet::new();
        if rebuild_for_new_scope {
            for (entry_id, entry) in &self.entries {
                if authenticator
                    .verify(
                        &entry.transaction.sender,
                        &entry.signing_digest,
                        &entry.transaction.signature,
                    )
                    .is_ok()
                {
                    preverified_signatures.insert((
                        entry.transaction.sender,
                        entry.signing_digest,
                        entry.transaction.signature.clone(),
                    ));
                    staged_entries.insert(*entry_id, entry.clone());
                }
            }
        }
        let staged_bytes = if rebuild_for_new_scope {
            staged_entries
                .values()
                .map(|entry| entry.encoded_len)
                .sum::<usize>()
        } else {
            self.total_bytes
        };
        let duplicate_exists = if rebuild_for_new_scope {
            staged_entries.contains_key(&id)
        } else {
            self.entries.contains_key(&id)
        };
        if duplicate_exists {
            return Err(MempoolError::Duplicate);
        }
        let staged_count = if rebuild_for_new_scope {
            staged_entries.len()
        } else {
            self.entries.len()
        };
        if staged_count >= self.limits.max_transactions {
            return Err(MempoolError::TransactionLimit);
        }
        let new_total = staged_bytes
            .checked_add(encoded.len())
            .ok_or(MempoolError::ByteLimit)?;
        if new_total > self.limits.max_bytes {
            return Err(MempoolError::ByteLimit);
        }

        let mut proposed: Vec<_> = if rebuild_for_new_scope {
            staged_entries
                .values()
                .map(|entry| entry.transaction.clone())
                .collect()
        } else {
            self.ordered_transactions()
        };
        proposed.push(tx.clone());
        sort_transactions(&mut proposed)?;
        let height = state
            .height()
            .checked_add(1)
            .ok_or(MempoolError::HeightOverflow)?;
        let block = Block {
            height,
            timestamp: candidate_timestamp,
            parent_hash: state.tip_hash(),
            state_root: [0; 32],
            transactions: proposed,
        };

        let empty_cache = HashSet::new();
        let trusted = if rebuild_for_new_scope {
            &preverified_signatures
        } else if scope.is_some() {
            &self.verified_signatures
        } else {
            &empty_cache
        };
        let cached_authenticator = ScopedCacheAuthenticator {
            inner: authenticator,
            trusted,
        };
        let preview = state.preview_state_root_after(&block, &cached_authenticator);
        drop(cached_authenticator);
        preview.map_err(MempoolError::State)?;

        // Commit staged membership and cache metadata only after canonical validation succeeds.
        if rebuild_for_new_scope {
            self.entries = staged_entries;
            self.total_bytes = staged_bytes;
            self.verified_signatures.clear();
            self.verification_cache_scope = None;
        }
        if let Some(scope) = scope {
            if rebuild_for_new_scope {
                for entry in self.entries.values() {
                    self.verified_signatures.insert((
                        entry.transaction.sender,
                        entry.signing_digest,
                        entry.transaction.signature.clone(),
                    ));
                }
            }
            self.verified_signatures
                .insert((tx.sender, signing_digest, tx.signature.clone()));
            self.verification_cache_scope = Some(scope);
        } else {
            // Generic/dynamic authenticators without a stable fingerprint never reuse cache.
            self.verified_signatures.clear();
            self.verification_cache_scope = None;
        }

        self.entries.insert(
            id,
            Entry {
                transaction: tx,
                encoded_len: encoded.len(),
                signing_digest,
            },
        );
        self.total_bytes = new_total;
        Ok(id)
    }

    /// Revalidate pending transactions after canonical-tip replacement.
    ///
    /// Transactions confirmed by the newly selected chain are skipped. Existing pending
    /// entries and explicit losing-branch re-admission candidates are then replayed in a
    /// deterministic order into a fresh bounded pool against the new canonical state.
    /// Any candidate that no longer validates (nonce, balance, signature, network, expiry,
    /// or limits) is dropped. This is a local policy candidate, not live node integration.
    pub fn reconcile_after_reorg<A: TransactionAuthenticator>(
        &mut self,
        canonical_state: &LedgerState,
        authenticator: &A,
        candidate_timestamp: u64,
        newly_included: &[Transaction],
        re_admission_candidates: &[Transaction],
    ) -> MempoolReconciliationSummary {
        let confirmed_ids: std::collections::BTreeSet<[u8; 32]> = newly_included
            .iter()
            .filter_map(|tx| transaction_id(tx).ok())
            .collect();
        let queue: Vec<(bool, Transaction)> = self
            .ordered_transactions()
            .into_iter()
            .map(|tx| (true, tx))
            .chain(
                re_admission_candidates
                    .iter()
                    .cloned()
                    .map(|tx| (false, tx)),
            )
            .collect();
        let mut rebuilt = match Self::new(self.limits) {
            Ok(pool) => pool,
            Err(_) => {
                return MempoolReconciliationSummary {
                    kept: 0,
                    readmitted: 0,
                    skipped_confirmed: 0,
                    dropped_expired: 0,
                    dropped_invalid: queue.len(),
                };
            }
        };
        let mut summary = MempoolReconciliationSummary::default();
        let mut grouped: BTreeMap<([u8; 32], u64), Vec<(bool, Transaction)>> = BTreeMap::new();

        // Filter canonical inclusions and expiry before conflict grouping so a dead entry
        // cannot cause a live competing transaction to be discarded.
        for (was_pending, tx) in queue {
            let id = match transaction_id(&tx) {
                Ok(id) => id,
                Err(_) => {
                    summary.dropped_invalid += 1;
                    continue;
                }
            };
            if confirmed_ids.contains(&id) {
                summary.skipped_confirmed += 1;
                continue;
            }
            if candidate_timestamp >= tx.expires_at {
                summary.dropped_expired += 1;
                continue;
            }
            if tx.network_id != canonical_state.network_id() {
                summary.dropped_invalid += 1;
                continue;
            }
            let signing_digest = match transaction_signing_digest(&tx) {
                Ok(digest) => digest,
                Err(_) => {
                    summary.dropped_invalid += 1;
                    continue;
                }
            };
            if authenticator
                .verify(&tx.sender, &signing_digest, &tx.signature)
                .is_err()
            {
                // Never let an unauthenticated same-nonce input poison a valid candidate group.
                summary.dropped_invalid += 1;
                continue;
            }
            grouped
                .entry((tx.sender, tx.nonce))
                .or_default()
                .push((was_pending, tx));
        }

        let mut to_validate = Vec::new();
        for (_, mut contenders) in grouped {
            contenders.sort_by_key(|(was_pending, tx)| {
                (!*was_pending, transaction_id(tx).unwrap_or([0xff; 32]))
            });
            let pending_count = contenders
                .iter()
                .filter(|(was_pending, _)| *was_pending)
                .count();
            if contenders.len() > 1 {
                if pending_count == 1 {
                    // A still-valid transaction already in the pending pool keeps priority.
                    // Re-admission alternatives for its sender/nonce are rejected.
                    let dropped = contenders.len() - 1;
                    if let Some(existing) =
                        contenders.into_iter().find(|(was_pending, _)| *was_pending)
                    {
                        to_validate.push(existing);
                        summary.dropped_invalid += dropped;
                    }
                } else {
                    // Without an incumbent, reject all competing re-admission candidates for
                    // this sender/nonce rather than letting transaction-ID grinding pick one.
                    summary.dropped_invalid += contenders.len();
                }
            } else {
                to_validate.extend(contenders);
            }
        }

        // BTreeMap group order is sender then nonce, so valid sequential nonce chains replay
        // before their successors. Competing same-nonce candidates were handled above.
        for (was_pending, tx) in to_validate {
            match rebuilt.submit(tx, canonical_state, authenticator, candidate_timestamp) {
                Ok(_) if was_pending => summary.kept += 1,
                Ok(_) => summary.readmitted += 1,
                Err(_) => summary.dropped_invalid += 1,
            }
        }
        *self = rebuilt;
        summary
    }

    /// Stable selection order: sender AccountId, nonce, then canonical transaction ID.
    /// This ordering is a candidate policy, not a finalized consensus rule.
    pub fn ordered_transactions(&self) -> Vec<Transaction> {
        let mut keyed: Vec<_> = self
            .entries
            .iter()
            .map(|(id, entry)| {
                (
                    (entry.transaction.sender, entry.transaction.nonce, *id),
                    entry.transaction.clone(),
                )
            })
            .collect();
        keyed.sort_by_key(|(key, _)| *key);
        keyed.into_iter().map(|(_, tx)| tx).collect()
    }

    fn invalidate_verification_cache(&mut self) {
        self.verified_signatures.clear();
        self.verification_cache_scope = None;
    }

    /// Explicit time-based cleanup. Expiry is exclusive: expires_at <= timestamp is removed.
    pub fn prune_expired(&mut self, candidate_timestamp: u64) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|_, entry| entry.transaction.expires_at > candidate_timestamp);
        self.total_bytes = self.entries.values().map(|entry| entry.encoded_len).sum();
        let removed = before - self.entries.len();
        if removed > 0 {
            self.invalidate_verification_cache();
        }
        removed
    }

    /// Remove transactions confirmed in the currently chosen chain.
    pub fn remove_included(&mut self, included: &[Transaction]) -> usize {
        let mut removed = 0usize;
        for tx in included {
            if let Ok(id) = transaction_id(tx) {
                if let Some(entry) = self.entries.remove(&id) {
                    self.total_bytes -= entry.encoded_len;
                    removed += 1;
                }
            }
        }
        if removed > 0 {
            // Conservative whole-cache invalidation avoids stale entries and keeps the cache
            // bounded by the active pool after confirmed transactions are removed.
            self.invalidate_verification_cache();
        }
        removed
    }
}

fn sort_transactions(transactions: &mut [Transaction]) -> Result<(), MempoolError> {
    let mut keyed = transactions
        .iter()
        .cloned()
        .map(|tx| transaction_id(&tx).map(|id| ((tx.sender, tx.nonce, id), tx)))
        .collect::<Result<Vec<_>, _>>()
        .map_err(MempoolError::State)?;
    keyed.sort_by_key(|(key, _)| *key);
    for (destination, (_, tx)) in transactions.iter_mut().zip(keyed) {
        *destination = tx;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_machine::{AccountId, TransactionAuthenticator};
    use crate::transaction_auth::{
        AccountPublicKey, Ed25519TransactionAuthenticator, Ed25519TransactionSigner,
        TransactionAuthenticatorKind,
    };
    use std::cell::Cell;

    struct TestAuthenticator;
    impl TransactionAuthenticator for TestAuthenticator {
        fn verify(
            &self,
            sender: &AccountId,
            _digest: &[u8; 32],
            signature: &[u8],
        ) -> Result<(), ()> {
            if signature == [sender[0]] {
                Ok(())
            } else {
                Err(())
            }
        }
    }

    struct UnscopedCountingAuthenticator {
        calls: Cell<usize>,
    }

    impl TransactionAuthenticator for UnscopedCountingAuthenticator {
        fn verify(
            &self,
            sender: &AccountId,
            _digest: &[u8; 32],
            signature: &[u8],
        ) -> Result<(), ()> {
            self.calls.set(self.calls.get() + 1);
            if signature == [sender[0]] {
                Ok(())
            } else {
                Err(())
            }
        }
        // Deliberately inherits verification_cache_scope() = None.
    }

    struct RejectingUnscopedAuthenticator {
        calls: Cell<usize>,
        revoked: AccountId,
    }

    impl TransactionAuthenticator for RejectingUnscopedAuthenticator {
        fn verify(
            &self,
            sender: &AccountId,
            _digest: &[u8; 32],
            signature: &[u8],
        ) -> Result<(), ()> {
            self.calls.set(self.calls.get() + 1);
            if sender == &self.revoked || signature != [sender[0]] {
                return Err(());
            }
            Ok(())
        }
        // Deliberately inherits verification_cache_scope() = None.
    }

    struct ScopedCountingAuthenticator {
        calls: Cell<usize>,
        scope: Cell<[u8; 32]>,
    }

    impl TransactionAuthenticator for ScopedCountingAuthenticator {
        fn verify(
            &self,
            sender: &AccountId,
            _digest: &[u8; 32],
            signature: &[u8],
        ) -> Result<(), ()> {
            self.calls.set(self.calls.get() + 1);
            if signature == [sender[0]] {
                Ok(())
            } else {
                Err(())
            }
        }

        fn verification_cache_scope(&self) -> Option<[u8; 32]> {
            Some(self.scope.get())
        }
    }

    fn tx(
        network_id: [u8; 32],
        sender: AccountId,
        recipient: AccountId,
        nonce: u64,
        amount: u64,
        expiry: u64,
    ) -> Transaction {
        Transaction {
            network_id,
            sender,
            recipient,
            nonce,
            amount,
            fee: 1,
            expires_at: expiry,
            signature: vec![sender[0]],
        }
    }

    fn state() -> LedgerState {
        LedgerState::genesis(
            [0xA1; 32],
            vec![([1; 32], 100_000), ([2; 32], 100_000), ([3; 32], 0)],
        )
        .unwrap()
    }

    fn state_after_block(
        before: &LedgerState,
        transactions: Vec<Transaction>,
        timestamp: u64,
        auth: &TestAuthenticator,
    ) -> LedgerState {
        let mut block = Block {
            height: before.height() + 1,
            timestamp,
            parent_hash: before.tip_hash(),
            state_root: [0; 32],
            transactions,
        };
        block.state_root = before.preview_state_root_after(&block, auth).unwrap();
        let mut after = before.clone();
        after.apply_block(&block, auth).unwrap();
        after
    }

    #[test]
    fn accepts_sequential_nonce_and_returns_deterministic_order() {
        let state = state();
        let auth = TestAuthenticator;
        let mut pool = BoundedMempool::new(MempoolLimits {
            max_transactions: 4,
            max_bytes: 16_384,
        })
        .unwrap();
        pool.submit(
            tx([0xA1; 32], [2; 32], [3; 32], 1, 50, 5_000),
            &state,
            &auth,
            1_000,
        )
        .unwrap();
        pool.submit(
            tx([0xA1; 32], [1; 32], [3; 32], 1, 10, 5_000),
            &state,
            &auth,
            1_000,
        )
        .unwrap();
        pool.submit(
            tx([0xA1; 32], [1; 32], [3; 32], 2, 20, 5_000),
            &state,
            &auth,
            1_000,
        )
        .unwrap();
        let ordered = pool.ordered_transactions();
        assert_eq!(
            ordered
                .iter()
                .map(|t| (t.sender[0], t.nonce))
                .collect::<Vec<_>>(),
            vec![(1, 1), (1, 2), (2, 1)]
        );
        assert_eq!(pool.len(), 3);
        assert!(pool.total_bytes() > 0);
    }

    #[test]
    fn rejects_exact_duplicate_transaction_id() {
        let state = state();
        let auth = TestAuthenticator;
        let mut pool = BoundedMempool::new(MempoolLimits::default()).unwrap();
        let transaction = tx([0xA1; 32], [1; 32], [3; 32], 1, 10, 5_000);
        pool.submit(transaction.clone(), &state, &auth, 1_000)
            .unwrap();
        let before_bytes = pool.total_bytes();
        assert_eq!(
            pool.submit(transaction, &state, &auth, 1_000),
            Err(MempoolError::Duplicate)
        );
        assert_eq!(pool.len(), 1);
        assert_eq!(pool.total_bytes(), before_bytes);
    }

    #[test]
    fn rejects_nonce_replay_and_leaves_pool_unchanged() {
        let state = state();
        let auth = TestAuthenticator;
        let mut pool = BoundedMempool::new(MempoolLimits::default()).unwrap();
        pool.submit(
            tx([0xA1; 32], [1; 32], [3; 32], 1, 10, 5_000),
            &state,
            &auth,
            1_000,
        )
        .unwrap();
        let before_len = pool.len();
        let before_bytes = pool.total_bytes();
        let result = pool.submit(
            tx([0xA1; 32], [1; 32], [2; 32], 1, 11, 5_000),
            &state,
            &auth,
            1_000,
        );
        assert!(matches!(
            result,
            Err(MempoolError::State(StateError::NonceMismatch { .. }))
        ));
        assert_eq!(pool.len(), before_len);
        assert_eq!(pool.total_bytes(), before_bytes);
    }

    #[test]
    fn rejects_wrong_network_expiry_and_invalid_signature() {
        let state = state();
        let auth = TestAuthenticator;
        let mut pool = BoundedMempool::new(MempoolLimits::default()).unwrap();
        assert_eq!(
            pool.submit(
                tx([0xB2; 32], [1; 32], [3; 32], 1, 1, 5_000),
                &state,
                &auth,
                1_000
            ),
            Err(MempoolError::WrongNetwork)
        );
        assert!(matches!(
            pool.submit(
                tx([0xA1; 32], [1; 32], [3; 32], 1, 1, 1_000),
                &state,
                &auth,
                1_000
            ),
            Err(MempoolError::Expired { .. })
        ));
        let mut bad_signature = tx([0xA1; 32], [1; 32], [3; 32], 1, 1, 5_000);
        bad_signature.signature = vec![0xff];
        assert_eq!(
            pool.submit(bad_signature, &state, &auth, 1_000),
            Err(MempoolError::State(StateError::Unauthorized))
        );
        assert!(pool.is_empty());
    }

    #[test]
    fn enforces_count_and_byte_limits_without_partial_admission() {
        let state = state();
        let auth = TestAuthenticator;
        let mut count_limited = BoundedMempool::new(MempoolLimits {
            max_transactions: 1,
            max_bytes: 16_384,
        })
        .unwrap();
        count_limited
            .submit(
                tx([0xA1; 32], [1; 32], [3; 32], 1, 1, 5_000),
                &state,
                &auth,
                1_000,
            )
            .unwrap();
        assert_eq!(
            count_limited.submit(
                tx([0xA1; 32], [2; 32], [3; 32], 1, 1, 5_000),
                &state,
                &auth,
                1_000
            ),
            Err(MempoolError::TransactionLimit)
        );

        let mut byte_limited = BoundedMempool::new(MempoolLimits {
            max_transactions: 4,
            max_bytes: 1,
        })
        .unwrap();
        assert_eq!(
            byte_limited.submit(
                tx([0xA1; 32], [1; 32], [3; 32], 1, 1, 5_000),
                &state,
                &auth,
                1_000
            ),
            Err(MempoolError::ByteLimit)
        );
        assert!(byte_limited.is_empty());
    }

    #[test]
    fn expiry_pruning_and_confirmed_removal_keep_byte_accounting_exact() {
        let state = state();
        let auth = ScopedCountingAuthenticator {
            calls: Cell::new(0),
            scope: Cell::new([0xC0; 32]),
        };
        let mut pool = BoundedMempool::new(MempoolLimits::default()).unwrap();
        let first = tx([0xA1; 32], [1; 32], [3; 32], 1, 1, 2_000);
        pool.submit(first.clone(), &state, &auth, 1_000).unwrap();
        let size = pool.total_bytes();
        assert_eq!(pool.verification_cache_scope, Some([0xC0; 32]));
        assert_eq!(pool.verified_signatures.len(), 1);

        assert_eq!(pool.prune_expired(2_000), 1);
        assert_eq!(pool.total_bytes(), 0);
        assert_eq!(pool.verification_cache_scope, None);
        assert!(pool.verified_signatures.is_empty());

        pool.submit(first.clone(), &state, &auth, 1_000).unwrap();
        assert_eq!(pool.verification_cache_scope, Some([0xC0; 32]));
        assert_eq!(pool.remove_included(&[first]), 1);
        assert!(pool.is_empty());
        assert_eq!(pool.total_bytes(), 0);
        assert_eq!(pool.verification_cache_scope, None);
        assert!(pool.verified_signatures.is_empty());
        assert!(size > 0);
    }

    #[test]
    fn reorg_readmits_losing_branch_transaction_and_preserves_sequential_nonce_chain() {
        let base = state();
        let auth = TestAuthenticator;
        let first = tx([0xA1; 32], [1; 32], [3; 32], 1, 10, 5_000);
        let second = tx([0xA1; 32], [1; 32], [3; 32], 2, 20, 5_000);
        let mut pool = BoundedMempool::new(MempoolLimits::default()).unwrap();
        pool.submit(first.clone(), &base, &auth, 1_000).unwrap();
        pool.submit(second.clone(), &base, &auth, 1_000).unwrap();

        // The old canonical branch confirmed tx1, so the pool had removed it.
        assert_eq!(pool.remove_included(&[first.clone()]), 1);
        assert_eq!(pool.len(), 1);

        // The new canonical branch does not contain tx1; replay the remaining queue
        // against that branch and offer the losing-branch tx back for re-admission.
        let new_canonical = state_after_block(&base, vec![], 1_500, &auth);
        let summary =
            pool.reconcile_after_reorg(&new_canonical, &auth, 2_000, &[], &[first.clone()]);

        assert_eq!(
            summary,
            MempoolReconciliationSummary {
                kept: 1,
                readmitted: 1,
                skipped_confirmed: 0,
                dropped_expired: 0,
                dropped_invalid: 0,
            }
        );
        assert_eq!(
            pool.ordered_transactions()
                .iter()
                .map(|transaction| transaction.nonce)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert!(pool.total_bytes() > 0);
    }

    #[test]
    fn reorg_drops_expired_and_nonce_conflicting_transactions_without_losing_valid_pending_tx() {
        let base = state();
        let auth = TestAuthenticator;
        let confirmed = tx([0xA1; 32], [1; 32], [3; 32], 1, 30, 5_000);
        let pending_next = tx([0xA1; 32], [1; 32], [3; 32], 2, 20, 5_000);
        let expires_during_reorg = tx([0xA1; 32], [2; 32], [3; 32], 1, 5, 1_800);
        let losing_conflict = tx([0xA1; 32], [1; 32], [2; 32], 1, 10, 5_000);
        let mut pool = BoundedMempool::new(MempoolLimits::default()).unwrap();

        pool.submit(confirmed.clone(), &base, &auth, 1_000).unwrap();
        pool.submit(pending_next.clone(), &base, &auth, 1_000)
            .unwrap();
        pool.submit(expires_during_reorg, &base, &auth, 1_000)
            .unwrap();

        let new_canonical = state_after_block(&base, vec![confirmed.clone()], 1_500, &auth);
        let summary = pool.reconcile_after_reorg(
            &new_canonical,
            &auth,
            2_000,
            &[confirmed],
            &[losing_conflict],
        );

        assert_eq!(
            summary,
            MempoolReconciliationSummary {
                kept: 1,
                readmitted: 0,
                skipped_confirmed: 1,
                dropped_expired: 1,
                dropped_invalid: 1,
            }
        );
        assert_eq!(pool.ordered_transactions(), vec![pending_next]);
        assert_eq!(pool.len(), 1);
        assert!(pool.total_bytes() > 0);
    }

    #[test]
    fn byte_quota_accepts_exact_encoded_size_and_rejects_one_byte_less() {
        let state = state();
        let auth = TestAuthenticator;
        let transaction = tx([0xA1; 32], [1; 32], [3; 32], 1, 10, 5_000);
        let encoded_len = encode_transaction(&transaction).unwrap().len();

        let mut exact = BoundedMempool::new(MempoolLimits {
            max_transactions: 1,
            max_bytes: encoded_len,
        })
        .unwrap();
        exact
            .submit(transaction.clone(), &state, &auth, 1_000)
            .unwrap();
        assert_eq!(exact.total_bytes(), encoded_len);

        let mut undersized = BoundedMempool::new(MempoolLimits {
            max_transactions: 1,
            max_bytes: encoded_len - 1,
        })
        .unwrap();
        assert_eq!(
            undersized.submit(transaction, &state, &auth, 1_000),
            Err(MempoolError::ByteLimit)
        );
        assert!(undersized.is_empty());
        assert_eq!(undersized.total_bytes(), 0);
    }

    #[test]
    fn reorg_reconciliation_is_independent_of_candidate_input_permutation() {
        let base = state();
        let auth = TestAuthenticator;
        let first = tx([0xA1; 32], [1; 32], [3; 32], 1, 10, 5_000);
        let second = tx([0xA1; 32], [1; 32], [3; 32], 2, 20, 5_000);
        let other_first = tx([0xA1; 32], [2; 32], [3; 32], 1, 30, 5_000);
        let other_second = tx([0xA1; 32], [2; 32], [3; 32], 2, 40, 5_000);

        let mut pool_a = BoundedMempool::new(MempoolLimits::default()).unwrap();
        pool_a.submit(first.clone(), &base, &auth, 1_000).unwrap();
        pool_a.submit(second.clone(), &base, &auth, 1_000).unwrap();
        pool_a
            .submit(other_first.clone(), &base, &auth, 1_000)
            .unwrap();

        let mut pool_b = BoundedMempool::new(MempoolLimits::default()).unwrap();
        pool_b
            .submit(other_first.clone(), &base, &auth, 1_000)
            .unwrap();
        pool_b.submit(first.clone(), &base, &auth, 1_000).unwrap();
        pool_b.submit(second.clone(), &base, &auth, 1_000).unwrap();

        // Simulate the old branch confirming first, then being removed from the pool.
        assert_eq!(pool_a.remove_included(&[first.clone()]), 1);
        assert_eq!(pool_b.remove_included(&[first.clone()]), 1);
        let new_canonical = state_after_block(&base, vec![], 1_500, &auth);
        let summary_a = pool_a.reconcile_after_reorg(
            &new_canonical,
            &auth,
            2_000,
            &[],
            &[first.clone(), other_second.clone()],
        );
        let summary_b =
            pool_b.reconcile_after_reorg(&new_canonical, &auth, 2_000, &[], &[other_second, first]);

        assert_eq!(summary_a, summary_b);
        assert_eq!(
            summary_a,
            MempoolReconciliationSummary {
                kept: 2,
                readmitted: 2,
                skipped_confirmed: 0,
                dropped_expired: 0,
                dropped_invalid: 0,
            }
        );
        assert_eq!(pool_a.ordered_transactions(), pool_b.ordered_transactions());
        assert_eq!(pool_a.total_bytes(), pool_b.total_bytes());
    }

    #[test]
    fn existing_pending_transaction_keeps_priority_over_same_nonce_readmission() {
        let base = state();
        let auth = TestAuthenticator;
        let incumbent = tx([0xA1; 32], [1; 32], [3; 32], 1, 10, 5_000);
        let conflicting_re_admission = tx([0xA1; 32], [1; 32], [2; 32], 1, 11, 5_000);
        let mut pool = BoundedMempool::new(MempoolLimits::default()).unwrap();
        pool.submit(incumbent.clone(), &base, &auth, 1_000).unwrap();

        let summary =
            pool.reconcile_after_reorg(&base, &auth, 2_000, &[], &[conflicting_re_admission]);

        assert_eq!(
            summary,
            MempoolReconciliationSummary {
                kept: 1,
                readmitted: 0,
                skipped_confirmed: 0,
                dropped_expired: 0,
                dropped_invalid: 1,
            }
        );
        assert_eq!(pool.ordered_transactions(), vec![incumbent]);
    }

    #[test]
    fn competing_readmission_same_nonce_is_rejected_as_a_group_independent_of_input_order() {
        let base = state();
        let auth = TestAuthenticator;
        let conflict_a = tx([0xA1; 32], [1; 32], [2; 32], 1, 11, 5_000);
        let conflict_b = tx([0xA1; 32], [1; 32], [3; 32], 1, 12, 5_000);
        let independent = tx([0xA1; 32], [2; 32], [3; 32], 1, 25, 5_000);

        let mut pool_a = BoundedMempool::new(MempoolLimits::default()).unwrap();
        let summary_a = pool_a.reconcile_after_reorg(
            &base,
            &auth,
            2_000,
            &[],
            &[conflict_a.clone(), independent.clone(), conflict_b.clone()],
        );

        let mut pool_b = BoundedMempool::new(MempoolLimits::default()).unwrap();
        let summary_b = pool_b.reconcile_after_reorg(
            &base,
            &auth,
            2_000,
            &[],
            &[conflict_b, independent.clone(), conflict_a],
        );

        let expected = MempoolReconciliationSummary {
            kept: 0,
            readmitted: 1,
            skipped_confirmed: 0,
            dropped_expired: 0,
            dropped_invalid: 2,
        };
        assert_eq!(summary_a, expected);
        assert_eq!(summary_b, expected);
        assert_eq!(pool_a.ordered_transactions(), vec![independent.clone()]);
        assert_eq!(pool_b.ordered_transactions(), vec![independent]);
        assert_eq!(pool_a.total_bytes(), pool_b.total_bytes());
    }

    #[test]
    fn invalid_signature_cannot_poison_a_valid_same_nonce_re_admission() {
        let base = state();
        let auth = TestAuthenticator;
        let valid = tx([0xA1; 32], [1; 32], [3; 32], 1, 15, 5_000);
        let mut invalid = tx([0xA1; 32], [1; 32], [2; 32], 1, 16, 5_000);
        invalid.signature = vec![0xff];
        let mut pool = BoundedMempool::new(MempoolLimits::default()).unwrap();

        let summary =
            pool.reconcile_after_reorg(&base, &auth, 2_000, &[], &[invalid, valid.clone()]);

        assert_eq!(
            summary,
            MempoolReconciliationSummary {
                kept: 0,
                readmitted: 1,
                skipped_confirmed: 0,
                dropped_expired: 0,
                dropped_invalid: 1,
            }
        );
        assert_eq!(pool.ordered_transactions(), vec![valid]);
    }

    #[test]
    fn scoped_cache_reuses_success_only_under_same_scope_and_invalidates_on_scope_change() {
        let base = state();
        let auth = ScopedCountingAuthenticator {
            calls: Cell::new(0),
            scope: Cell::new([0xC1; 32]),
        };
        let mut pool = BoundedMempool::new(MempoolLimits::default()).unwrap();

        for nonce in 1..=3 {
            pool.submit(
                tx([0xA1; 32], [1; 32], [3; 32], nonce, 1, 5_000),
                &base,
                &auth,
                1_000,
            )
            .unwrap();
        }
        assert_eq!(auth.calls.get(), 3);

        // A changed verifier-policy fingerprint forces all incumbents to be rechecked once.
        auth.scope.set([0xC2; 32]);
        pool.submit(
            tx([0xA1; 32], [1; 32], [3; 32], 4, 1, 5_000),
            &base,
            &auth,
            1_000,
        )
        .unwrap();
        assert_eq!(auth.calls.get(), 7);

        // Under the same updated scope, the now-confirmed local verification records are reusable.
        pool.submit(
            tx([0xA1; 32], [1; 32], [3; 32], 5, 1, 5_000),
            &base,
            &auth,
            1_000,
        )
        .unwrap();
        assert_eq!(auth.calls.get(), 8);
    }

    #[test]
    fn cached_signatures_do_not_bypass_nonce_validation_or_cache_failed_candidate() {
        let base = state();
        let auth = ScopedCountingAuthenticator {
            calls: Cell::new(0),
            scope: Cell::new([0xC3; 32]),
        };
        let mut pool = BoundedMempool::new(MempoolLimits::default()).unwrap();

        for nonce in 1..=3 {
            pool.submit(
                tx([0xA1; 32], [1; 32], [3; 32], nonce, 1, 5_000),
                &base,
                &auth,
                1_000,
            )
            .unwrap();
        }
        assert_eq!(auth.calls.get(), 3);
        let bytes_before = pool.total_bytes();

        // The existing signatures hit cache, but canonical nonce/state rules still run.
        let rejected = pool.submit(
            tx([0xA1; 32], [1; 32], [3; 32], 5, 1, 5_000),
            &base,
            &auth,
            1_000,
        );
        assert!(matches!(
            rejected,
            Err(MempoolError::State(StateError::NonceMismatch { .. }))
        ));
        assert_eq!(auth.calls.get(), 4);
        assert_eq!(pool.len(), 3);
        assert_eq!(pool.total_bytes(), bytes_before);
        assert_eq!(pool.verified_signatures.len(), 3);

        pool.submit(
            tx([0xA1; 32], [1; 32], [3; 32], 4, 1, 5_000),
            &base,
            &auth,
            1_000,
        )
        .unwrap();
        assert_eq!(auth.calls.get(), 5);
        assert_eq!(pool.len(), 4);
    }

    #[test]
    fn failed_admission_does_not_retag_existing_verifications() {
        let base = state();
        let auth = ScopedCountingAuthenticator {
            calls: Cell::new(0),
            scope: Cell::new([0xD1; 32]),
        };
        let mut pool = BoundedMempool::new(MempoolLimits::default()).unwrap();

        for nonce in 1..=3 {
            pool.submit(
                tx([0xA1; 32], [1; 32], [3; 32], nonce, 1, 5_000),
                &base,
                &auth,
                1_000,
            )
            .unwrap();
        }
        assert_eq!(auth.calls.get(), 3);
        let before_ids: Vec<_> = pool.entries.keys().copied().collect();
        let before_bytes = pool.total_bytes();

        // Scope D2 forces incumbent revalidation, but nonce 5 creates a gap after nonce 3.
        auth.scope.set([0xD2; 32]);
        let rejected = pool.submit(
            tx([0xA1; 32], [1; 32], [3; 32], 5, 1, 5_000),
            &base,
            &auth,
            1_000,
        );
        assert!(matches!(
            rejected,
            Err(MempoolError::State(StateError::NonceMismatch { .. }))
        ));
        assert_eq!(pool.entries.keys().copied().collect::<Vec<_>>(), before_ids);
        assert_eq!(pool.total_bytes(), before_bytes);
        assert_eq!(pool.verification_cache_scope, Some([0xD1; 32]));
        assert_eq!(pool.verified_signatures.len(), 3);
        assert_eq!(auth.calls.get(), 7);

        // Returning to D1 must reuse the untouched D1 verification records; only nonce 4 verifies.
        auth.scope.set([0xD1; 32]);
        pool.submit(
            tx([0xA1; 32], [1; 32], [3; 32], 4, 1, 5_000),
            &base,
            &auth,
            1_000,
        )
        .unwrap();
        assert_eq!(auth.calls.get(), 8);
    }

    #[test]
    fn verifier_scope_rotation_prunes_revoked_pending_signature_and_admits_new_scope_tx() {
        let signer_a = Ed25519TransactionSigner::from_seed([0x31; 32]);
        let signer_b = Ed25519TransactionSigner::from_seed([0x42; 32]);
        let kind = TransactionAuthenticatorKind::Ed25519V1;
        let registry = |signers: &[&Ed25519TransactionSigner]| {
            Ed25519TransactionAuthenticator::select(
                kind,
                signers
                    .iter()
                    .map(|signer| AccountPublicKey {
                        account_id: signer.account_id(),
                        public_key: signer.public_key(),
                    })
                    .collect::<Vec<_>>(),
            )
            .unwrap()
        };
        let old_auth = registry(&[&signer_a, &signer_b]);
        let rotated_auth = registry(&[&signer_b]);
        assert_ne!(
            old_auth.verification_cache_scope(),
            rotated_auth.verification_cache_scope()
        );

        let recipient = [0x77; 32];
        let state = LedgerState::genesis(
            [0xA1; 32],
            vec![
                (signer_a.account_id(), 10_000),
                (signer_b.account_id(), 10_000),
                (recipient, 0),
            ],
        )
        .unwrap();
        let signed_transfer = |signer: &Ed25519TransactionSigner| {
            let mut transaction = Transaction {
                network_id: [0xA1; 32],
                sender: signer.account_id(),
                recipient,
                nonce: 1,
                amount: 100,
                fee: 1,
                expires_at: 5_000,
                signature: Vec::new(),
            };
            signer.sign_transaction(&mut transaction).unwrap();
            transaction
        };
        let revoked_pending = signed_transfer(&signer_a);
        let valid_under_rotated_scope = signed_transfer(&signer_b);
        let mut pool = BoundedMempool::new(MempoolLimits::default()).unwrap();
        pool.submit(revoked_pending.clone(), &state, &old_auth, 1_000)
            .unwrap();
        assert_eq!(pool.len(), 1);
        assert_eq!(
            pool.verification_cache_scope,
            old_auth.verification_cache_scope()
        );

        // A scope change must not let an incumbent from a revoked registry entry block every
        // subsequent admission. The stale entry is staged out, and the pool only commits that
        // pruning together with a candidate accepted by the canonical ledger preview.
        pool.submit(
            valid_under_rotated_scope.clone(),
            &state,
            &rotated_auth,
            1_000,
        )
        .unwrap();
        assert_eq!(pool.len(), 1);
        assert_eq!(
            pool.ordered_transactions(),
            vec![valid_under_rotated_scope.clone()]
        );
        assert_eq!(
            pool.total_bytes(),
            encode_transaction(&valid_under_rotated_scope)
                .unwrap()
                .len()
        );
        assert_eq!(
            pool.verification_cache_scope,
            rotated_auth.verification_cache_scope()
        );
        assert_eq!(pool.verified_signatures.len(), 1);
        assert!(!pool
            .entries
            .values()
            .any(|entry| entry.transaction == revoked_pending));
    }

    #[test]
    fn unscoped_rejection_does_not_bypass_old_scope_cache_or_mutate_pool() {
        let base = state();
        let scoped = ScopedCountingAuthenticator {
            calls: Cell::new(0),
            scope: Cell::new([0xE2; 32]),
        };
        let first = tx([0xA1; 32], [1; 32], [3; 32], 1, 1, 5_000);
        let second = tx([0xA1; 32], [2; 32], [3; 32], 1, 1, 5_000);
        let mut pool = BoundedMempool::new(MempoolLimits::default()).unwrap();
        pool.submit(first, &base, &scoped, 1_000).unwrap();

        let before_transactions = pool.ordered_transactions();
        let before_ids: Vec<_> = pool.entries.keys().copied().collect();
        let before_bytes = pool.total_bytes();
        let before_cache = pool.verified_signatures.clone();
        let before_scope = pool.verification_cache_scope;
        let unscoped = RejectingUnscopedAuthenticator {
            calls: Cell::new(0),
            revoked: [1; 32],
        };

        // The old cached incumbent is rejected by the unscoped verifier. A cached shortcut would
        // incorrectly admit the second transaction; correct None-scope handling invokes verify.
        assert_eq!(
            pool.submit(second, &base, &unscoped, 1_000),
            Err(MempoolError::State(StateError::Unauthorized))
        );
        assert_eq!(unscoped.calls.get(), 1);
        assert_eq!(pool.ordered_transactions(), before_transactions);
        assert_eq!(pool.entries.keys().copied().collect::<Vec<_>>(), before_ids);
        assert_eq!(pool.total_bytes(), before_bytes);
        assert_eq!(pool.verified_signatures, before_cache);
        assert_eq!(pool.verification_cache_scope, before_scope);
        assert_eq!(pool.verification_cache_scope, Some([0xE2; 32]));
    }

    #[test]
    fn verifier_scope_rotation_rejected_candidate_keeps_pool_atomic_until_valid_retry() {
        let signer_a = Ed25519TransactionSigner::from_seed([0x51; 32]);
        let signer_b = Ed25519TransactionSigner::from_seed([0x62; 32]);
        let kind = TransactionAuthenticatorKind::Ed25519V1;
        let registry = |signers: &[&Ed25519TransactionSigner]| {
            Ed25519TransactionAuthenticator::select(
                kind,
                signers
                    .iter()
                    .map(|signer| AccountPublicKey {
                        account_id: signer.account_id(),
                        public_key: signer.public_key(),
                    })
                    .collect::<Vec<_>>(),
            )
            .unwrap()
        };
        let old_auth = registry(&[&signer_a, &signer_b]);
        let rotated_auth = registry(&[&signer_b]);
        let recipient = [0x79; 32];
        let state = LedgerState::genesis(
            [0xA1; 32],
            vec![
                (signer_a.account_id(), 10_000),
                (signer_b.account_id(), 10_000),
                (recipient, 0),
            ],
        )
        .unwrap();
        let signed_transfer = |signer: &Ed25519TransactionSigner, nonce: u64| {
            let mut transaction = Transaction {
                network_id: [0xA1; 32],
                sender: signer.account_id(),
                recipient,
                nonce,
                amount: 100,
                fee: 1,
                expires_at: 5_000,
                signature: Vec::new(),
            };
            signer.sign_transaction(&mut transaction).unwrap();
            transaction
        };
        let revoked_pending = signed_transfer(&signer_a, 1);
        let invalid_nonce_candidate = signed_transfer(&signer_b, 2);
        let valid_candidate = signed_transfer(&signer_b, 1);
        let mut pool = BoundedMempool::new(MempoolLimits::default()).unwrap();
        pool.submit(revoked_pending.clone(), &state, &old_auth, 1_000)
            .unwrap();

        let before_transactions = pool.ordered_transactions();
        let before_ids: Vec<_> = pool.entries.keys().copied().collect();
        let before_bytes = pool.total_bytes();
        let before_cache = pool.verified_signatures.clone();
        let before_scope = pool.verification_cache_scope;
        assert_eq!(before_scope, old_auth.verification_cache_scope());

        // The rotated registry revokes A, but B's correctly signed nonce-2 candidate is invalid
        // against canonical state. Neither staged pruning nor the new scope/cache may be committed.
        assert!(matches!(
            pool.submit(invalid_nonce_candidate, &state, &rotated_auth, 1_000),
            Err(MempoolError::State(StateError::NonceMismatch { .. }))
        ));
        assert_eq!(pool.ordered_transactions(), before_transactions);
        assert_eq!(pool.entries.keys().copied().collect::<Vec<_>>(), before_ids);
        assert_eq!(pool.total_bytes(), before_bytes);
        assert_eq!(pool.verified_signatures, before_cache);
        assert_eq!(pool.verification_cache_scope, before_scope);
        assert!(pool
            .entries
            .values()
            .any(|entry| entry.transaction == revoked_pending));

        // A later canonical-valid candidate commits pruning and scope rotation atomically.
        pool.submit(valid_candidate.clone(), &state, &rotated_auth, 1_000)
            .unwrap();
        assert_eq!(pool.ordered_transactions(), vec![valid_candidate.clone()]);
        assert_eq!(
            pool.total_bytes(),
            encode_transaction(&valid_candidate).unwrap().len()
        );
        assert_eq!(
            pool.verification_cache_scope,
            rotated_auth.verification_cache_scope()
        );
        assert_eq!(pool.verified_signatures.len(), 1);
        assert!(!pool
            .entries
            .values()
            .any(|entry| entry.transaction == revoked_pending));
    }

    #[test]
    fn transition_to_unscoped_authenticator_preserves_incumbents_without_any_cache() {
        let base = state();
        let scoped = ScopedCountingAuthenticator {
            calls: Cell::new(0),
            scope: Cell::new([0xE1; 32]),
        };
        let unscoped = UnscopedCountingAuthenticator {
            calls: Cell::new(0),
        };
        let mut pool = BoundedMempool::new(MempoolLimits::default()).unwrap();
        let first = tx([0xA1; 32], [1; 32], [3; 32], 1, 1, 5_000);
        let second = tx([0xA1; 32], [2; 32], [3; 32], 1, 1, 5_000);
        pool.submit(first.clone(), &base, &scoped, 1_000).unwrap();
        assert_eq!(pool.verification_cache_scope, Some([0xE1; 32]));

        // A None scope is deliberately not cached and must not be mistaken for an empty staged
        // registry. Both incumbent and new transaction remain under the canonical full preview.
        pool.submit(second.clone(), &base, &unscoped, 1_000)
            .unwrap();
        assert_eq!(pool.len(), 2);
        assert!(pool.ordered_transactions().contains(&first));
        assert!(pool.ordered_transactions().contains(&second));
        assert_eq!(pool.verification_cache_scope, None);
        assert!(pool.verified_signatures.is_empty());
        assert_eq!(unscoped.calls.get(), 2);
    }

    #[test]
    fn unscoped_authenticator_keeps_default_no_cache_behavior() {
        let base = state();
        let auth = UnscopedCountingAuthenticator {
            calls: Cell::new(0),
        };
        let mut pool = BoundedMempool::new(MempoolLimits::default()).unwrap();

        for nonce in 1..=3 {
            pool.submit(
                tx([0xA1; 32], [1; 32], [3; 32], nonce, 1, 5_000),
                &base,
                &auth,
                1_000,
            )
            .unwrap();
        }
        // A None cache scope deliberately re-verifies 1 + 2 + 3 transactions.
        assert_eq!(auth.calls.get(), 6);
        assert_eq!(pool.verification_cache_scope, None);
        assert!(pool.verified_signatures.is_empty());
    }
}
