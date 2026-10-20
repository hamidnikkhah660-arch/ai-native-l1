//! Bounded, thread-safe ingress budget candidate.
//!
//! This research-only component limits caller-defined work units with both a global
//! token bucket and a per-peer token bucket. Its peer table is bounded, failed admissions
//! consume neither bucket, and a peer slot is reclaimable only after its bucket is fully
//! replenished. It is intentionally not wired into node/RPC/P2P ingress.
//!
//! Callers must supply an authenticated, stable peer identifier and independently computed
//! costs; never trust a requester-supplied cost. Apply cheap raw-frame/byte limits before any
//! expensive decode. This module does not implement identity authentication, scheduling, queues,
//! network timeouts or a production rate policy.
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::sync::{Mutex, MutexGuard};

pub type IngressPeerId = [u8; 32];
const MILLIS_PER_SECOND: u128 = 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngressBudgetConfig {
    /// Maximum number of distinct peer records retained at once.
    pub max_peers: usize,
    /// Reject a single admission request whose trusted cost exceeds this limit.
    pub max_cost_per_request: u64,
    pub global_capacity: u64,
    /// Refill rate in work units per second. Zero means no refill.
    pub global_refill_per_second: u64,
    pub per_peer_capacity: u64,
    /// Refill rate in work units per second. Zero means no refill.
    pub per_peer_refill_per_second: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressBudgetConfigError {
    ZeroPeerCapacity,
    ZeroRequestCostLimit,
    ZeroGlobalCapacity,
    ZeroPerPeerCapacity,
    MaxRequestCostExceedsGlobalCapacity,
    MaxRequestCostExceedsPerPeerCapacity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressLimitScope {
    Global,
    PerPeer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressBudgetError {
    InvalidCost,
    CostExceedsRequestLimit,
    PeerTableFull,
    RateLimited(IngressLimitScope),
    ClockRegressed,
    LockPoisoned,
}

#[derive(Debug, PartialEq, Eq)]
pub enum IngressBudgetTransactionError<E> {
    Budget(IngressBudgetError),
    Commit(E),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngressBudgetSnapshot {
    pub global_tokens: u64,
    pub tracked_peers: usize,
    pub last_observed_ms: u64,
}

#[derive(Debug, Clone, Copy)]
struct TokenBucket {
    tokens: u64,
    last_refill_ms: u64,
    /// Fractional refill numerator remainder, in thousandths of a work unit.
    refill_remainder: u16,
}

impl TokenBucket {
    fn full(capacity: u64, now_ms: u64) -> Self {
        Self {
            tokens: capacity,
            last_refill_ms: now_ms,
            refill_remainder: 0,
        }
    }

    fn refilled(
        self,
        now_ms: u64,
        capacity: u64,
        refill_per_second: u64,
    ) -> Result<Self, IngressBudgetError> {
        if now_ms < self.last_refill_ms {
            return Err(IngressBudgetError::ClockRegressed);
        }
        let elapsed_ms = (now_ms - self.last_refill_ms) as u128;
        let numerator = elapsed_ms * (refill_per_second as u128) + (self.refill_remainder as u128);
        let refill_units = numerator / MILLIS_PER_SECOND;
        let free_capacity = capacity - self.tokens;
        if refill_units >= (free_capacity as u128) {
            Ok(Self {
                tokens: capacity,
                last_refill_ms: now_ms,
                // Do not accumulate credit beyond a full bucket.
                refill_remainder: 0,
            })
        } else {
            Ok(Self {
                tokens: self.tokens + refill_units as u64,
                last_refill_ms: now_ms,
                refill_remainder: (numerator % MILLIS_PER_SECOND) as u16,
            })
        }
    }

    fn try_spend(mut self, cost: u64) -> Option<Self> {
        if self.tokens < cost {
            return None;
        }
        self.tokens -= cost;
        Some(self)
    }
}

#[derive(Debug)]
struct BudgetState {
    global: TokenBucket,
    peers: BTreeMap<IngressPeerId, TokenBucket>,
    last_observed_ms: u64,
}

/// A bounded, mutex-serialized admission budget. The mutex covers both buckets so one request
/// cannot spend global credit but fail to spend its corresponding per-peer credit (or vice versa).
pub struct IngressBudget {
    config: IngressBudgetConfig,
    state: Mutex<BudgetState>,
}

impl IngressBudget {
    pub fn new(
        config: IngressBudgetConfig,
        initial_time_ms: u64,
    ) -> Result<Self, IngressBudgetConfigError> {
        if config.max_peers == 0 {
            return Err(IngressBudgetConfigError::ZeroPeerCapacity);
        }
        if config.global_capacity == 0 {
            return Err(IngressBudgetConfigError::ZeroGlobalCapacity);
        }
        if config.per_peer_capacity == 0 {
            return Err(IngressBudgetConfigError::ZeroPerPeerCapacity);
        }
        if config.max_cost_per_request == 0 {
            return Err(IngressBudgetConfigError::ZeroRequestCostLimit);
        }
        if config.max_cost_per_request > config.global_capacity {
            return Err(IngressBudgetConfigError::MaxRequestCostExceedsGlobalCapacity);
        }
        if config.max_cost_per_request > config.per_peer_capacity {
            return Err(IngressBudgetConfigError::MaxRequestCostExceedsPerPeerCapacity);
        }
        Ok(Self {
            config,
            state: Mutex::new(BudgetState {
                global: TokenBucket::full(config.global_capacity, initial_time_ms),
                peers: BTreeMap::new(),
                last_observed_ms: initial_time_ms,
            }),
        })
    }

    /// Atomically charge `cost_units` to both the global and peer buckets.
    pub fn admit(
        &self,
        peer_id: IngressPeerId,
        now_ms: u64,
        cost_units: u64,
    ) -> Result<(), IngressBudgetError> {
        match self.admit_with_commit(peer_id, now_ms, cost_units, || Ok::<(), Infallible>(())) {
            Ok(()) => Ok(()),
            Err(IngressBudgetTransactionError::Budget(error)) => Err(error),
            Err(IngressBudgetTransactionError::Commit(never)) => match never {},
        }
    }

    /// Atomically check both token buckets, run a bounded atomic admission closure, then commit
    /// both bucket updates only when that closure succeeds. The closure must leave its target
    /// unchanged on `Err`, must be bounded/non-blocking, and must not re-enter this budget. This
    /// supports a queue+budget composition where queue rejection spends no budget tokens.
    pub fn admit_with_commit<T, E, F>(
        &self,
        peer_id: IngressPeerId,
        now_ms: u64,
        cost_units: u64,
        commit: F,
    ) -> Result<T, IngressBudgetTransactionError<E>>
    where
        F: FnOnce() -> Result<T, E>,
    {
        if cost_units == 0 {
            return Err(IngressBudgetTransactionError::Budget(
                IngressBudgetError::InvalidCost,
            ));
        }
        if cost_units > self.config.max_cost_per_request {
            return Err(IngressBudgetTransactionError::Budget(
                IngressBudgetError::CostExceedsRequestLimit,
            ));
        }

        let mut state = self
            .lock_state()
            .map_err(IngressBudgetTransactionError::Budget)?;
        if now_ms < state.last_observed_ms {
            return Err(IngressBudgetTransactionError::Budget(
                IngressBudgetError::ClockRegressed,
            ));
        }
        let known_peer = state.peers.contains_key(&peer_id);
        if !known_peer && state.peers.len() >= self.config.max_peers {
            return Err(IngressBudgetTransactionError::Budget(
                IngressBudgetError::PeerTableFull,
            ));
        }

        let global_refilled = state
            .global
            .refilled(
                now_ms,
                self.config.global_capacity,
                self.config.global_refill_per_second,
            )
            .map_err(IngressBudgetTransactionError::Budget)?;
        let global_spent =
            global_refilled
                .try_spend(cost_units)
                .ok_or(IngressBudgetTransactionError::Budget(
                    IngressBudgetError::RateLimited(IngressLimitScope::Global),
                ))?;

        let peer_bucket = state
            .peers
            .get(&peer_id)
            .copied()
            .unwrap_or_else(|| TokenBucket::full(self.config.per_peer_capacity, now_ms));
        let peer_refilled = peer_bucket
            .refilled(
                now_ms,
                self.config.per_peer_capacity,
                self.config.per_peer_refill_per_second,
            )
            .map_err(IngressBudgetTransactionError::Budget)?;
        let peer_spent =
            peer_refilled
                .try_spend(cost_units)
                .ok_or(IngressBudgetTransactionError::Budget(
                    IngressBudgetError::RateLimited(IngressLimitScope::PerPeer),
                ))?;

        // The operation is bounded and externally atomic. If it fails without mutation, no tokens,
        // peer record or committed timestamp are changed.
        let value = commit().map_err(IngressBudgetTransactionError::Commit)?;
        state.global = global_spent;
        state.peers.insert(peer_id, peer_spent);
        state.last_observed_ms = now_ms;
        Ok(value)
    }
    /// Refill buckets at a trusted monotonic time and release only peer slots whose quota has
    /// completely refilled. Resetting a depleted peer bucket on reconnect would defeat fairness;
    /// this method therefore cannot evict a still-depleted bucket.
    pub fn reap_refilled_peers(&self, now_ms: u64) -> Result<usize, IngressBudgetError> {
        let mut state = self.lock_state()?;
        if now_ms < state.last_observed_ms {
            return Err(IngressBudgetError::ClockRegressed);
        }

        let global = state.global.refilled(
            now_ms,
            self.config.global_capacity,
            self.config.global_refill_per_second,
        )?;
        let mut reaped = Vec::new();
        for (peer_id, bucket) in state.peers.iter_mut() {
            let refilled = bucket.refilled(
                now_ms,
                self.config.per_peer_capacity,
                self.config.per_peer_refill_per_second,
            )?;
            *bucket = refilled;
            if refilled.tokens == self.config.per_peer_capacity {
                reaped.push(*peer_id);
            }
        }
        for peer_id in &reaped {
            state.peers.remove(peer_id);
        }
        state.global = global;
        state.last_observed_ms = now_ms;
        Ok(reaped.len())
    }

    pub fn snapshot(&self) -> Result<IngressBudgetSnapshot, IngressBudgetError> {
        let state = self.lock_state()?;
        Ok(IngressBudgetSnapshot {
            global_tokens: state.global.tokens,
            tracked_peers: state.peers.len(),
            last_observed_ms: state.last_observed_ms,
        })
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, BudgetState>, IngressBudgetError> {
        self.state
            .lock()
            .map_err(|_| IngressBudgetError::LockPoisoned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    fn config(
        max_peers: usize,
        global_capacity: u64,
        per_peer_capacity: u64,
    ) -> IngressBudgetConfig {
        IngressBudgetConfig {
            max_peers,
            max_cost_per_request: 8.min(global_capacity).min(per_peer_capacity),
            global_capacity,
            global_refill_per_second: 0,
            per_peer_capacity,
            per_peer_refill_per_second: 0,
        }
    }

    fn peer(last: u8) -> IngressPeerId {
        [last; 32]
    }

    #[test]
    fn rejects_zero_or_oversized_cost_without_claiming_peer_slot() {
        let budget = IngressBudget::new(config(1, 10, 10), 100).unwrap();
        assert_eq!(
            budget.admit(peer(1), 100, 0),
            Err(IngressBudgetError::InvalidCost)
        );
        assert_eq!(
            budget.admit(peer(1), 100, 9),
            Err(IngressBudgetError::CostExceedsRequestLimit)
        );
        assert_eq!(
            budget.snapshot().unwrap(),
            IngressBudgetSnapshot {
                global_tokens: 10,
                tracked_peers: 0,
                last_observed_ms: 100,
            }
        );
    }

    #[test]
    fn per_peer_limit_and_global_limit_are_enforced_independently() {
        let budget = IngressBudget::new(config(4, 10, 2), 0).unwrap();
        budget.admit(peer(1), 0, 1).unwrap();
        budget.admit(peer(1), 0, 1).unwrap();
        assert_eq!(
            budget.admit(peer(1), 0, 1),
            Err(IngressBudgetError::RateLimited(IngressLimitScope::PerPeer))
        );
        // A different peer has its own allowance, but global credit is shared.
        budget.admit(peer(2), 0, 1).unwrap();
        assert_eq!(budget.snapshot().unwrap().tracked_peers, 2);
        assert_eq!(budget.snapshot().unwrap().global_tokens, 7);
    }

    #[test]
    fn global_rejection_does_not_reserve_peer_or_spend_partial_credit() {
        let budget = IngressBudget::new(config(4, 2, 2), 0).unwrap();
        budget.admit(peer(1), 0, 1).unwrap();
        budget.admit(peer(2), 0, 1).unwrap();
        assert_eq!(
            budget.admit(peer(3), 0, 1),
            Err(IngressBudgetError::RateLimited(IngressLimitScope::Global))
        );
        let snapshot = budget.snapshot().unwrap();
        assert_eq!(snapshot.global_tokens, 0);
        assert_eq!(snapshot.tracked_peers, 2);
        assert_eq!(snapshot.last_observed_ms, 0);
    }

    #[test]
    fn bounded_peer_table_fails_closed_for_unseen_peer_ids() {
        let budget = IngressBudget::new(config(2, 10, 10), 0).unwrap();
        budget.admit(peer(1), 0, 1).unwrap();
        budget.admit(peer(2), 0, 1).unwrap();
        assert_eq!(
            budget.admit(peer(3), 0, 1),
            Err(IngressBudgetError::PeerTableFull)
        );
        assert_eq!(budget.snapshot().unwrap().tracked_peers, 2);
        assert_eq!(budget.snapshot().unwrap().global_tokens, 8);
    }

    #[test]
    fn rejected_clock_regression_leaves_all_state_unchanged() {
        let budget = IngressBudget::new(config(3, 10, 10), 100).unwrap();
        budget.admit(peer(1), 200, 1).unwrap();
        let before = budget.snapshot().unwrap();
        assert_eq!(
            budget.admit(peer(1), 199, 1),
            Err(IngressBudgetError::ClockRegressed)
        );
        assert_eq!(budget.snapshot().unwrap(), before);
        assert_eq!(
            budget.reap_refilled_peers(199),
            Err(IngressBudgetError::ClockRegressed)
        );
        assert_eq!(budget.snapshot().unwrap(), before);
    }

    #[test]
    fn refilled_peer_slot_can_be_reaped_but_depleted_slot_cannot() {
        let mut cfg = config(1, 10, 2);
        cfg.per_peer_refill_per_second = 1;
        let budget = IngressBudget::new(cfg, 0).unwrap();
        budget.admit(peer(1), 0, 2).unwrap();
        assert_eq!(budget.reap_refilled_peers(1_999).unwrap(), 0);
        assert_eq!(budget.snapshot().unwrap().tracked_peers, 1);
        assert_eq!(budget.reap_refilled_peers(2_000).unwrap(), 1);
        assert_eq!(budget.snapshot().unwrap().tracked_peers, 0);
        // The global bucket still has room and a reclaimed slot does not inherit a depleted peer's
        // allowance: the new record starts full only because a full per-peer refill elapsed.
        budget.admit(peer(2), 2_000, 2).unwrap();
        assert_eq!(budget.snapshot().unwrap().tracked_peers, 1);
    }

    #[test]
    fn fractional_refill_is_preserved_across_maintenance_sweeps() {
        let mut cfg = config(2, 20, 1);
        cfg.per_peer_refill_per_second = 1;
        let budget = IngressBudget::new(cfg, 0).unwrap();
        budget.admit(peer(1), 0, 1).unwrap();
        for now in (100..1_000).step_by(100) {
            assert_eq!(budget.reap_refilled_peers(now).unwrap(), 0);
        }
        assert_eq!(budget.reap_refilled_peers(1_000).unwrap(), 1);
        assert_eq!(budget.snapshot().unwrap().tracked_peers, 0);
    }

    #[test]
    fn concurrent_requests_cannot_overspend_global_or_per_peer_budget() {
        let mut cfg = config(4, 100, 100);
        cfg.max_cost_per_request = 1;
        let budget = Arc::new(IngressBudget::new(cfg, 0).unwrap());
        let mut workers = Vec::new();
        for _ in 0..16 {
            let shared = Arc::clone(&budget);
            workers.push(thread::spawn(move || {
                let mut accepted = 0usize;
                let mut limited = 0usize;
                for _ in 0..20 {
                    match shared.admit(peer(9), 0, 1) {
                        Ok(()) => accepted += 1,
                        Err(IngressBudgetError::RateLimited(_)) => limited += 1,
                        other => panic!("unexpected admission result: {other:?}"),
                    }
                }
                (accepted, limited)
            }));
        }
        let (accepted, limited) = workers
            .into_iter()
            .map(|w| w.join().unwrap())
            .fold((0usize, 0usize), |(accepted, limited), (a, l)| {
                (accepted + a, limited + l)
            });
        assert_eq!(accepted, 100);
        assert_eq!(limited, 220);
        assert_eq!(budget.snapshot().unwrap().global_tokens, 0);
        assert_eq!(budget.snapshot().unwrap().tracked_peers, 1);
    }

    #[test]
    fn concurrent_distinct_peers_remain_within_shared_global_cap_and_table_bound() {
        let mut cfg = config(8, 75, 75);
        cfg.max_cost_per_request = 1;
        // Reserve one initial token for every peer so table coverage is deterministic before
        // racing for the remaining shared global budget.
        let seeded = IngressBudget::new(cfg, 0).unwrap();
        for id in 1..=8u8 {
            seeded.admit(peer(id), 0, 1).unwrap();
        }
        let budget = Arc::new(seeded);
        let mut workers = Vec::new();
        for id in 1..=8u8 {
            let shared = Arc::clone(&budget);
            workers.push(thread::spawn(move || {
                let mut accepted = 0usize;
                for _ in 0..20 {
                    match shared.admit(peer(id), 0, 1) {
                        Ok(()) => accepted += 1,
                        Err(IngressBudgetError::RateLimited(_)) => {}
                        other => panic!("unexpected admission result: {other:?}"),
                    }
                }
                accepted
            }));
        }
        let accepted: usize = workers.into_iter().map(|w| w.join().unwrap()).sum();
        assert_eq!(accepted, 67);
        let snapshot = budget.snapshot().unwrap();
        assert_eq!(snapshot.global_tokens, 0);
        assert_eq!(snapshot.tracked_peers, 8);
    }

    #[test]
    fn transactional_commit_failure_spends_no_tokens_or_peer_slot() {
        let budget = IngressBudget::new(config(4, 20, 10), 100).unwrap();
        let mut commit_called = false;
        let result = budget.admit_with_commit(peer(7), 100, 3, || {
            commit_called = true;
            Err::<(), _>("queue backpressure")
        });
        assert_eq!(
            result,
            Err(IngressBudgetTransactionError::Commit("queue backpressure"))
        );
        assert!(commit_called);
        assert_eq!(
            budget.snapshot().unwrap(),
            IngressBudgetSnapshot {
                global_tokens: 20,
                tracked_peers: 0,
                last_observed_ms: 100,
            }
        );
    }

    #[test]
    fn transactional_commit_success_spends_global_and_peer_tokens_after_commit() {
        let budget = IngressBudget::new(config(4, 20, 10), 100).unwrap();
        let mut committed = false;
        let result = budget
            .admit_with_commit(peer(7), 100, 3, || {
                committed = true;
                Ok::<_, &'static str>(42u8)
            })
            .unwrap();
        assert_eq!(result, 42);
        assert!(committed);
        assert_eq!(
            budget.snapshot().unwrap(),
            IngressBudgetSnapshot {
                global_tokens: 17,
                tracked_peers: 1,
                last_observed_ms: 100,
            }
        );
    }
    #[test]
    fn rejects_invalid_configuration() {
        assert!(matches!(
            IngressBudget::new(config(0, 1, 1), 0),
            Err(IngressBudgetConfigError::ZeroPeerCapacity)
        ));
        assert!(matches!(
            IngressBudget::new(config(1, 0, 1), 0),
            Err(IngressBudgetConfigError::ZeroGlobalCapacity)
        ));
        assert!(matches!(
            IngressBudget::new(config(1, 1, 0), 0),
            Err(IngressBudgetConfigError::ZeroPerPeerCapacity)
        ));
        let mut cfg = config(1, 1, 1);
        cfg.max_cost_per_request = 0;
        assert!(matches!(
            IngressBudget::new(cfg, 0),
            Err(IngressBudgetConfigError::ZeroRequestCostLimit)
        ));
        let mut cfg = config(1, 10, 10);
        cfg.max_cost_per_request = 11;
        assert!(matches!(
            IngressBudget::new(cfg, 0),
            Err(IngressBudgetConfigError::MaxRequestCostExceedsGlobalCapacity)
        ));
        let mut cfg = config(1, 10, 5);
        cfg.max_cost_per_request = 6;
        assert!(matches!(
            IngressBudget::new(cfg, 0),
            Err(IngressBudgetConfigError::MaxRequestCostExceedsPerPeerCapacity)
        ));
    }
}
