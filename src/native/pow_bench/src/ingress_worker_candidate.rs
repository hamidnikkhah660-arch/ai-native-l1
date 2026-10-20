//! Research-only bounded worker admission and cooperative deadline/cancellation propagation.
//!
//! This module coordinates leases; it does not spawn threads or forcibly abort blocking work.
//! Callers must claim a lease before dispatching work, check it before expensive/irreversible
//! steps, and drop/finish the lease on every exit path. Cancellation is cooperative. Peer IDs must
//! already be authenticated, clocks must come from one trusted monotonic source, and this model is
//! not wired into sockets, an async runtime, the node, RPC, P2P or persistence.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};

pub type WorkerRequestId = [u8; 32];
pub type WorkerPeerId = [u8; 32];

const CONTROL_NONE: u8 = 0;
const CONTROL_CANCELLED: u8 = 1;
const CONTROL_DEADLINE: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkerCoordinatorConfig {
    pub max_active_workers: usize,
    pub max_queued_items: usize,
    pub max_deadline_horizon_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerCoordinatorConfigError {
    ZeroActiveWorkers,
    ZeroQueuedCapacity,
    ZeroDeadlineHorizon,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerCoordinatorError {
    ClockRegressed,
    DeadlineAlreadyExpired,
    DeadlineTooFar,
    DuplicateRequestId,
    QueueFull,
    RequestNotFound,
    LockPoisoned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerCancelOutcome {
    CancelledQueued,
    CancellationSignalledRunning,
    ExpiredQueued,
    DeadlineSignalledRunning,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerCheckError {
    ClockRegressed { previous_ms: u64, current_ms: u64 },
    DeadlineExceeded,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkerPoolSnapshot {
    pub queued_items: usize,
    pub active_workers: usize,
    pub max_queued_items: usize,
    pub max_active_workers: usize,
    pub last_observed_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WorkerExpiryReport {
    pub queued_removed: usize,
    pub running_signalled: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkPhase {
    Queued,
    Running,
}

struct WorkEntry {
    peer_id: WorkerPeerId,
    deadline_ms: u64,
    phase: WorkPhase,
    control: Arc<AtomicU8>,
}

struct WorkerState {
    entries: HashMap<WorkerRequestId, WorkEntry>,
    fifo: VecDeque<WorkerRequestId>,
    last_observed_ms: u64,
}

struct WorkerInner {
    config: WorkerCoordinatorConfig,
    state: Mutex<WorkerState>,
}

/// A bounded admission coordinator. Clones share the same limits and FIFO.
#[derive(Clone)]
pub struct BoundedWorkerCoordinator {
    inner: Arc<WorkerInner>,
}

/// A non-cloneable active-worker lease. Dropping it releases the active slot.
pub struct WorkerLease {
    request_id: WorkerRequestId,
    peer_id: WorkerPeerId,
    deadline_ms: u64,
    control: Arc<AtomicU8>,
    last_check_ms: AtomicU64,
    inner: Weak<WorkerInner>,
}

impl BoundedWorkerCoordinator {
    pub fn new(
        config: WorkerCoordinatorConfig,
        initial_time_ms: u64,
    ) -> Result<Self, WorkerCoordinatorConfigError> {
        if config.max_active_workers == 0 {
            return Err(WorkerCoordinatorConfigError::ZeroActiveWorkers);
        }
        if config.max_queued_items == 0 {
            return Err(WorkerCoordinatorConfigError::ZeroQueuedCapacity);
        }
        if config.max_deadline_horizon_ms == 0 {
            return Err(WorkerCoordinatorConfigError::ZeroDeadlineHorizon);
        }
        Ok(Self {
            inner: Arc::new(WorkerInner {
                config,
                state: Mutex::new(WorkerState {
                    entries: HashMap::new(),
                    fifo: VecDeque::new(),
                    last_observed_ms: initial_time_ms,
                }),
            }),
        })
    }

    /// Admit a bounded request. A worker must call claim_next before starting work.
    /// Expired queued requests are pruned first, so they cannot pin queue capacity indefinitely.
    pub fn submit(
        &self,
        peer_id: WorkerPeerId,
        request_id: WorkerRequestId,
        now_ms: u64,
        deadline_ms: u64,
    ) -> Result<WorkerPoolSnapshot, WorkerCoordinatorError> {
        let mut state = self.lock_state()?;
        Self::observe_time(&mut state, now_ms)?;
        let _ = Self::expire_due_locked(&mut state, now_ms);

        if deadline_ms <= now_ms {
            return Err(WorkerCoordinatorError::DeadlineAlreadyExpired);
        }
        if deadline_ms - now_ms > self.inner.config.max_deadline_horizon_ms {
            return Err(WorkerCoordinatorError::DeadlineTooFar);
        }
        if state.entries.contains_key(&request_id) {
            return Err(WorkerCoordinatorError::DuplicateRequestId);
        }
        if state.fifo.len() >= self.inner.config.max_queued_items {
            return Err(WorkerCoordinatorError::QueueFull);
        }

        state.entries.insert(
            request_id,
            WorkEntry {
                peer_id,
                deadline_ms,
                phase: WorkPhase::Queued,
                control: Arc::new(AtomicU8::new(CONTROL_NONE)),
            },
        );
        state.fifo.push_back(request_id);
        Ok(self.snapshot_locked(&state))
    }

    /// Reserve one worker slot for the next live FIFO request. Expired queued work is removed.
    pub fn claim_next(&self, now_ms: u64) -> Result<Option<WorkerLease>, WorkerCoordinatorError> {
        let mut state = self.lock_state()?;
        Self::observe_time(&mut state, now_ms)?;
        let _ = Self::expire_due_locked(&mut state, now_ms);

        if Self::active_count(&state) >= self.inner.config.max_active_workers {
            return Ok(None);
        }

        while let Some(request_id) = state.fifo.pop_front() {
            let Some(entry) = state.entries.get_mut(&request_id) else {
                continue;
            };
            if entry.deadline_ms <= now_ms {
                continue;
            }
            entry.phase = WorkPhase::Running;
            let lease = WorkerLease {
                request_id,
                peer_id: entry.peer_id,
                deadline_ms: entry.deadline_ms,
                control: Arc::clone(&entry.control),
                last_check_ms: AtomicU64::new(now_ms),
                inner: Arc::downgrade(&self.inner),
            };
            return Ok(Some(lease));
        }
        Ok(None)
    }

    /// Request cancellation. Running work receives a cooperative signal and keeps its slot until
    /// the worker checks the lease and exits (or otherwise drops it).
    pub fn cancel(
        &self,
        request_id: WorkerRequestId,
        now_ms: u64,
    ) -> Result<WorkerCancelOutcome, WorkerCoordinatorError> {
        let mut state = self.lock_state()?;
        Self::observe_time(&mut state, now_ms)?;
        let Some((phase, deadline_ms, control)) = state
            .entries
            .get(&request_id)
            .map(|entry| (entry.phase, entry.deadline_ms, Arc::clone(&entry.control)))
        else {
            return Err(WorkerCoordinatorError::RequestNotFound);
        };

        if deadline_ms <= now_ms {
            control.store(CONTROL_DEADLINE, Ordering::Release);
            match phase {
                WorkPhase::Queued => {
                    state.entries.remove(&request_id);
                    state.fifo.retain(|id| *id != request_id);
                    Ok(WorkerCancelOutcome::ExpiredQueued)
                }
                WorkPhase::Running => Ok(WorkerCancelOutcome::DeadlineSignalledRunning),
            }
        } else {
            match phase {
                WorkPhase::Queued => {
                    let _ = control.compare_exchange(
                        CONTROL_NONE,
                        CONTROL_CANCELLED,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    );
                    state.entries.remove(&request_id);
                    state.fifo.retain(|id| *id != request_id);
                    Ok(WorkerCancelOutcome::CancelledQueued)
                }
                WorkPhase::Running => {
                    let _ = control.compare_exchange(
                        CONTROL_NONE,
                        CONTROL_CANCELLED,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    );
                    Ok(WorkerCancelOutcome::CancellationSignalledRunning)
                }
            }
        }
    }

    /// Remove expired queued requests and signal running work whose deadline has elapsed.
    /// Signalled running leases continue occupying a worker slot until dropped.
    pub fn expire_due(&self, now_ms: u64) -> Result<WorkerExpiryReport, WorkerCoordinatorError> {
        let mut state = self.lock_state()?;
        Self::observe_time(&mut state, now_ms)?;
        Ok(Self::expire_due_locked(&mut state, now_ms))
    }

    pub fn snapshot(&self) -> Result<WorkerPoolSnapshot, WorkerCoordinatorError> {
        let state = self.lock_state()?;
        Ok(self.snapshot_locked(&state))
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, WorkerState>, WorkerCoordinatorError> {
        self.inner
            .state
            .lock()
            .map_err(|_| WorkerCoordinatorError::LockPoisoned)
    }

    fn observe_time(state: &mut WorkerState, now_ms: u64) -> Result<(), WorkerCoordinatorError> {
        if now_ms < state.last_observed_ms {
            return Err(WorkerCoordinatorError::ClockRegressed);
        }
        state.last_observed_ms = now_ms;
        Ok(())
    }

    fn active_count(state: &WorkerState) -> usize {
        state
            .entries
            .values()
            .filter(|entry| entry.phase == WorkPhase::Running)
            .count()
    }

    fn snapshot_locked(&self, state: &WorkerState) -> WorkerPoolSnapshot {
        WorkerPoolSnapshot {
            queued_items: state.fifo.len(),
            active_workers: Self::active_count(state),
            max_queued_items: self.inner.config.max_queued_items,
            max_active_workers: self.inner.config.max_active_workers,
            last_observed_ms: state.last_observed_ms,
        }
    }

    fn expire_due_locked(state: &mut WorkerState, now_ms: u64) -> WorkerExpiryReport {
        let expired_queued: Vec<WorkerRequestId> = state
            .entries
            .iter()
            .filter_map(|(id, entry)| {
                (entry.phase == WorkPhase::Queued && entry.deadline_ms <= now_ms).then_some(*id)
            })
            .collect();
        let expired_set: HashSet<WorkerRequestId> = expired_queued.iter().copied().collect();
        for id in &expired_queued {
            if let Some(entry) = state.entries.remove(id) {
                entry.control.store(CONTROL_DEADLINE, Ordering::Release);
            }
        }
        state.fifo.retain(|id| !expired_set.contains(id));

        let mut running_signalled = 0;
        for entry in state.entries.values() {
            if entry.phase == WorkPhase::Running && entry.deadline_ms <= now_ms {
                let prior = entry.control.swap(CONTROL_DEADLINE, Ordering::AcqRel);
                if prior != CONTROL_DEADLINE {
                    running_signalled += 1;
                }
            }
        }
        WorkerExpiryReport {
            queued_removed: expired_queued.len(),
            running_signalled,
        }
    }
}

impl WorkerLease {
    pub fn request_id(&self) -> WorkerRequestId {
        self.request_id
    }

    pub fn peer_id(&self) -> WorkerPeerId {
        self.peer_id
    }

    pub fn deadline_ms(&self) -> u64 {
        self.deadline_ms
    }

    /// Check before beginning and between bounded chunks of work. A blocking/non-cooperative
    /// function cannot be forcibly interrupted by this token.
    pub fn check(&self, now_ms: u64) -> Result<(), WorkerCheckError> {
        loop {
            let previous_ms = self.last_check_ms.load(Ordering::Acquire);
            if now_ms < previous_ms {
                return Err(WorkerCheckError::ClockRegressed {
                    previous_ms,
                    current_ms: now_ms,
                });
            }
            match self.last_check_ms.compare_exchange_weak(
                previous_ms,
                now_ms,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(_) => continue,
            }
        }

        let control = self.control.load(Ordering::Acquire);
        if now_ms >= self.deadline_ms || control == CONTROL_DEADLINE {
            return Err(WorkerCheckError::DeadlineExceeded);
        }
        if control == CONTROL_CANCELLED {
            return Err(WorkerCheckError::Cancelled);
        }
        Ok(())
    }

    /// Check completion time, then release the worker slot as this lease is dropped.
    pub fn finish(self, now_ms: u64) -> Result<(), WorkerCheckError> {
        self.check(now_ms)
    }
}

impl Drop for WorkerLease {
    fn drop(&mut self) {
        let Some(inner) = self.inner.upgrade() else {
            return;
        };
        // Recover a poisoned mutex only for slot release: leaving a completed lease recorded as
        // active would permanently consume bounded capacity. Public operations remain fail-closed.
        let mut state = match inner.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if matches!(
            state.entries.get(&self.request_id),
            Some(entry) if entry.phase == WorkPhase::Running
        ) {
            state.entries.remove(&self.request_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Barrier;
    use std::thread;

    fn config(active: usize, queued: usize, horizon: u64) -> WorkerCoordinatorConfig {
        WorkerCoordinatorConfig {
            max_active_workers: active,
            max_queued_items: queued,
            max_deadline_horizon_ms: horizon,
        }
    }

    fn id(value: u8) -> [u8; 32] {
        [value; 32]
    }

    fn setup(active: usize, queued: usize) -> BoundedWorkerCoordinator {
        BoundedWorkerCoordinator::new(config(active, queued, 100), 0).unwrap()
    }

    fn submit(pool: &BoundedWorkerCoordinator, value: u8, deadline: u64) {
        pool.submit(id(value + 100), id(value), 2, deadline)
            .unwrap();
    }

    #[test]
    fn rejects_zero_worker_queue_and_deadline_limits() {
        assert!(matches!(
            BoundedWorkerCoordinator::new(config(0, 1, 1), 0),
            Err(WorkerCoordinatorConfigError::ZeroActiveWorkers)
        ));
        assert!(matches!(
            BoundedWorkerCoordinator::new(config(1, 0, 1), 0),
            Err(WorkerCoordinatorConfigError::ZeroQueuedCapacity)
        ));
        assert!(matches!(
            BoundedWorkerCoordinator::new(config(1, 1, 0), 0),
            Err(WorkerCoordinatorConfigError::ZeroDeadlineHorizon)
        ));
    }

    #[test]
    fn rejects_expired_and_far_future_deadlines_without_admission() {
        let pool = setup(1, 2);
        assert_eq!(
            pool.submit(id(1), id(2), 1, 1),
            Err(WorkerCoordinatorError::DeadlineAlreadyExpired)
        );
        assert_eq!(
            pool.submit(id(1), id(2), 1, 102),
            Err(WorkerCoordinatorError::DeadlineTooFar)
        );
        assert_eq!(pool.snapshot().unwrap().queued_items, 0);
    }

    #[test]
    fn enforces_queue_capacity_and_cancellation_releases_queued_capacity() {
        let pool = setup(1, 2);
        submit(&pool, 1, 50);
        submit(&pool, 2, 50);
        assert_eq!(
            pool.submit(id(103), id(3), 2, 50),
            Err(WorkerCoordinatorError::QueueFull)
        );
        assert_eq!(
            pool.cancel(id(1), 2).unwrap(),
            WorkerCancelOutcome::CancelledQueued
        );
        submit(&pool, 3, 50);
        assert_eq!(pool.snapshot().unwrap().queued_items, 2);
    }

    #[test]
    fn claims_fifo_and_never_exceeds_active_worker_limit() {
        let pool = setup(1, 4);
        submit(&pool, 1, 50);
        submit(&pool, 2, 50);
        let first = pool.claim_next(2).unwrap().unwrap();
        assert_eq!(first.request_id(), id(1));
        assert!(pool.claim_next(2).unwrap().is_none());
        assert_eq!(pool.snapshot().unwrap().active_workers, 1);
        drop(first);
        let second = pool.claim_next(2).unwrap().unwrap();
        assert_eq!(second.request_id(), id(2));
    }

    #[test]
    fn duplicate_id_is_rejected_while_queued_or_running() {
        let pool = setup(1, 3);
        submit(&pool, 1, 50);
        let lease = pool.claim_next(2).unwrap().unwrap();
        assert_eq!(
            pool.submit(id(9), id(1), 2, 50),
            Err(WorkerCoordinatorError::DuplicateRequestId)
        );
        drop(lease);
        submit(&pool, 1, 50);
        assert_eq!(pool.snapshot().unwrap().queued_items, 1);
    }

    #[test]
    fn running_cancellation_is_cooperative_and_slot_is_held_until_drop() {
        let pool = setup(1, 2);
        submit(&pool, 1, 50);
        let lease = pool.claim_next(2).unwrap().unwrap();
        assert_eq!(
            pool.cancel(id(1), 3).unwrap(),
            WorkerCancelOutcome::CancellationSignalledRunning
        );
        assert_eq!(lease.check(3), Err(WorkerCheckError::Cancelled));
        assert_eq!(pool.snapshot().unwrap().active_workers, 1);
        assert!(pool.claim_next(3).unwrap().is_none());
        drop(lease);
        assert_eq!(pool.snapshot().unwrap().active_workers, 0);
    }

    #[test]
    fn expiry_scans_behind_fifo_head_and_keeps_live_item_order() {
        let pool = setup(1, 4);
        submit(&pool, 1, 70);
        submit(&pool, 2, 20);
        submit(&pool, 3, 60);
        let report = pool.expire_due(20).unwrap();
        assert_eq!(report.queued_removed, 1);
        let first = pool.claim_next(20).unwrap().unwrap();
        assert_eq!(first.request_id(), id(1));
        drop(first);
        let second = pool.claim_next(20).unwrap().unwrap();
        assert_eq!(second.request_id(), id(3));
    }

    #[test]
    fn running_deadline_propagates_and_active_slot_waits_for_worker_exit() {
        let pool = setup(1, 2);
        submit(&pool, 1, 20);
        let lease = pool.claim_next(2).unwrap().unwrap();
        assert_eq!(
            pool.expire_due(20).unwrap(),
            WorkerExpiryReport {
                queued_removed: 0,
                running_signalled: 1
            }
        );
        assert_eq!(lease.check(19), Err(WorkerCheckError::DeadlineExceeded));
        assert_eq!(pool.snapshot().unwrap().active_workers, 1);
        drop(lease);
        assert_eq!(pool.snapshot().unwrap().active_workers, 0);
    }

    #[test]
    fn expiry_wins_over_user_cancellation_at_deadline() {
        let pool = setup(1, 2);
        submit(&pool, 1, 10);
        let lease = pool.claim_next(2).unwrap().unwrap();
        assert_eq!(
            pool.cancel(id(1), 10).unwrap(),
            WorkerCancelOutcome::DeadlineSignalledRunning
        );
        assert_eq!(lease.check(9), Err(WorkerCheckError::DeadlineExceeded));
    }

    #[test]
    fn cancelled_queued_id_can_be_reused_but_running_id_cannot() {
        let pool = setup(1, 3);
        submit(&pool, 1, 50);
        assert_eq!(
            pool.cancel(id(1), 2).unwrap(),
            WorkerCancelOutcome::CancelledQueued
        );
        submit(&pool, 1, 50);
        let lease = pool.claim_next(2).unwrap().unwrap();
        assert_eq!(
            pool.submit(id(9), id(1), 2, 50),
            Err(WorkerCoordinatorError::DuplicateRequestId)
        );
        drop(lease);
    }

    #[test]
    fn coordinator_and_lease_reject_clock_regression() {
        let pool = setup(1, 2);
        submit(&pool, 1, 50);
        assert!(matches!(
            pool.claim_next(0),
            Err(WorkerCoordinatorError::ClockRegressed)
        ));
        let lease = pool.claim_next(2).unwrap().unwrap();
        assert_eq!(
            lease.check(1),
            Err(WorkerCheckError::ClockRegressed {
                previous_ms: 2,
                current_ms: 1
            })
        );
    }

    #[test]
    fn finish_checks_deadline_and_drop_releases_capacity_even_on_error() {
        let pool = setup(1, 2);
        submit(&pool, 1, 20);
        let lease = pool.claim_next(2).unwrap().unwrap();
        assert_eq!(lease.finish(20), Err(WorkerCheckError::DeadlineExceeded));
        assert_eq!(pool.snapshot().unwrap().active_workers, 0);
    }

    #[test]
    fn concurrent_claims_never_oversubscribe_worker_slots() {
        let pool = setup(5, 64);
        for value in 1..=40 {
            submit(&pool, value, 90);
        }
        let threads = 24;
        let barrier = Arc::new(Barrier::new(threads + 1));
        let active = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));
        let claimed = Arc::new(AtomicUsize::new(0));
        let mut joins = Vec::new();

        for _ in 0..threads {
            let pool = pool.clone();
            let barrier = Arc::clone(&barrier);
            let active = Arc::clone(&active);
            let max_seen = Arc::clone(&max_seen);
            let claimed = Arc::clone(&claimed);
            joins.push(thread::spawn(move || {
                let lease = pool.claim_next(2).unwrap();
                if lease.is_some() {
                    claimed.fetch_add(1, Ordering::AcqRel);
                    let now = active.fetch_add(1, Ordering::AcqRel) + 1;
                    let mut seen = max_seen.load(Ordering::Acquire);
                    while now > seen {
                        match max_seen.compare_exchange_weak(
                            seen,
                            now,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        ) {
                            Ok(_) => break,
                            Err(updated) => seen = updated,
                        }
                    }
                }
                barrier.wait();
                drop(lease);
            }));
        }
        barrier.wait();
        for join in joins {
            join.join().unwrap();
        }

        assert_eq!(claimed.load(Ordering::Acquire), 5);
        assert_eq!(max_seen.load(Ordering::Acquire), 5);
        let snapshot = pool.snapshot().unwrap();
        assert_eq!(snapshot.active_workers, 0);
        assert_eq!(snapshot.queued_items, 35);
    }
}
