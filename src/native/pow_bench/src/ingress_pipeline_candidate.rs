//! Research-only composition of bounded ingress buffering and cooperative worker leases.
//!
//! This candidate is deliberately not connected to sockets or the private-testnet node. It
//! serializes cross-component admission/dispatch transitions, caps queued payload bytes and active
//! worker leases, and tracks IDs across queued and running phases. It does not spawn workers or
//! preempt blocking code. Callers must enforce raw-frame limits before allocating payloads, supply
//! authenticated stable peer IDs and one trusted monotonic clock, and protect canonical mutable
//! state separately before any future node integration.

use crate::ingress_budget_candidate::{
    IngressBudget, IngressBudgetConfig, IngressBudgetConfigError, IngressBudgetError,
    IngressBudgetSnapshot, IngressBudgetTransactionError,
};
use crate::ingress_queue_candidate::{
    IngressQueue, IngressQueueConfig, IngressQueueConfigError, IngressQueueError,
    IngressQueuePeerId, IngressQueueRequestId, IngressQueueSnapshot, QueuedIngressItem,
};
use crate::ingress_worker_candidate::{
    BoundedWorkerCoordinator, WorkerCancelOutcome, WorkerCheckError, WorkerCoordinatorConfig,
    WorkerCoordinatorConfigError, WorkerCoordinatorError, WorkerExpiryReport, WorkerLease,
    WorkerPoolSnapshot,
};
use std::collections::HashSet;
use std::sync::{Arc, Mutex, MutexGuard, Weak};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngressPipelineConfig {
    pub queue: IngressQueueConfig,
    pub budget: IngressBudgetConfig,
    /// Bytes per trusted cost unit, derived from bounded payload size (never requester-supplied).
    pub cost_bytes_per_unit: usize,
    pub max_active_workers: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressPipelineConfigError {
    ZeroActiveWorkers,
    ZeroCostBytesPerUnit,
    MaxPayloadCostExceedsBudgetLimit,
    Queue(IngressQueueConfigError),
    Budget(IngressBudgetConfigError),
    Worker(WorkerCoordinatorConfigError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressPipelineError {
    ClockRegressed,
    DuplicateRequestId,
    Queue(IngressQueueError),
    Budget(IngressBudgetError),
    Worker(WorkerCoordinatorError),
    LockPoisoned,
    InternalInvariant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveIngressWorkError {
    ClockRegressed { previous_ms: u64, current_ms: u64 },
    LockPoisoned,
    Worker(WorkerCheckError),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressPipelineCancelOutcome {
    CancelledQueued,
    Worker(WorkerCancelOutcome),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IngressPipelineExpiryReport {
    pub queued_expired: usize,
    pub running_signalled: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngressPipelineSnapshot {
    pub queue: IngressQueueSnapshot,
    pub budget: IngressBudgetSnapshot,
    pub workers: WorkerPoolSnapshot,
    /// Bounded by queued item capacity plus active worker capacity.
    pub tracked_requests: usize,
    pub max_tracked_requests: usize,
    /// Queue byte ceiling plus one maximum-size payload per active worker.
    pub max_retained_payload_bytes: usize,
    pub last_observed_ms: u64,
}

struct PipelineState {
    queue: IngressQueue,
    budget: IngressBudget,
    workers: BoundedWorkerCoordinator,
    known_requests: HashSet<IngressQueueRequestId>,
    last_observed_ms: u64,
    max_tracked_requests: usize,
    max_retained_payload_bytes: usize,
}

/// A bounded queue-to-worker admission model. All cross-component transitions are serialized by
/// one gate; individual queue/worker mutexes continue to protect their own invariants.
pub struct BoundedIngressPipeline {
    inner: Arc<Mutex<PipelineState>>,
    max_active_workers: usize,
    cost_bytes_per_unit: usize,
}

/// Payload plus a live worker lease. Its request ID remains reserved until this value is finished
/// or dropped, including when cancellation/deadline is signalled but worker code has not exited.
pub struct ActiveIngressWork {
    item: QueuedIngressItem,
    lease: Option<WorkerLease>,
    pipeline: Weak<Mutex<PipelineState>>,
}

impl BoundedIngressPipeline {
    pub fn new(
        config: IngressPipelineConfig,
        initial_time_ms: u64,
    ) -> Result<Self, IngressPipelineConfigError> {
        if config.max_active_workers == 0 {
            return Err(IngressPipelineConfigError::ZeroActiveWorkers);
        }
        if config.cost_bytes_per_unit == 0 {
            return Err(IngressPipelineConfigError::ZeroCostBytesPerUnit);
        }
        let max_payload_cost =
            1 + (config.queue.max_item_bytes.saturating_sub(1) / config.cost_bytes_per_unit);
        if u64::try_from(max_payload_cost).unwrap_or(u64::MAX) > config.budget.max_cost_per_request
        {
            return Err(IngressPipelineConfigError::MaxPayloadCostExceedsBudgetLimit);
        }
        let budget = IngressBudget::new(config.budget, initial_time_ms)
            .map_err(IngressPipelineConfigError::Budget)?;
        let queue = IngressQueue::new(config.queue, initial_time_ms)
            .map_err(IngressPipelineConfigError::Queue)?;
        let workers = BoundedWorkerCoordinator::new(
            WorkerCoordinatorConfig {
                max_active_workers: config.max_active_workers,
                // The pipeline moves a head into the worker coordinator and claims it while holding
                // the outer gate, so this internal queue has at most one transient request.
                max_queued_items: 1,
                max_deadline_horizon_ms: config.queue.max_deadline_horizon_ms,
            },
            initial_time_ms,
        )
        .map_err(IngressPipelineConfigError::Worker)?;
        let max_tracked_requests = config
            .queue
            .max_items
            .saturating_add(config.max_active_workers);
        let max_retained_payload_bytes = config.queue.max_bytes.saturating_add(
            config
                .queue
                .max_item_bytes
                .saturating_mul(config.max_active_workers),
        );
        Ok(Self {
            inner: Arc::new(Mutex::new(PipelineState {
                queue,
                budget,
                workers,
                known_requests: HashSet::new(),
                last_observed_ms: initial_time_ms,
                max_tracked_requests,
                max_retained_payload_bytes,
            })),
            max_active_workers: config.max_active_workers,
            cost_bytes_per_unit: config.cost_bytes_per_unit,
        })
    }

    /// Enqueue a fully framed payload after the caller has authenticated its peer and enforced a
    /// pre-allocation raw-frame ceiling. Work cost is derived internally from payload byte length.
    /// Budget tokens commit only if queue admission succeeds; a rejected queue operation spends none.
    pub fn enqueue(
        &self,
        peer_id: IngressQueuePeerId,
        request_id: IngressQueueRequestId,
        payload: Vec<u8>,
        now_ms: u64,
        deadline_ms: u64,
    ) -> Result<IngressQueueSnapshot, IngressPipelineError> {
        let mut state = self.lock_state()?;
        Self::advance_locked(&mut state, now_ms)?;
        if state.known_requests.contains(&request_id) {
            return Err(IngressPipelineError::DuplicateRequestId);
        }
        let payload_len = payload.len();
        state
            .queue
            .validate_enqueue(request_id, payload_len, now_ms, deadline_ms)
            .map_err(IngressPipelineError::Queue)?;
        let cost_units = if payload_len == 0 {
            0
        } else {
            1 + (payload_len - 1) / self.cost_bytes_per_unit
        };
        let cost_units = u64::try_from(cost_units).unwrap_or(u64::MAX);
        let (budget, queue) = (&state.budget, &state.queue);
        let result = budget
            .admit_with_commit(peer_id, now_ms, cost_units, || {
                queue
                    .enqueue(peer_id, request_id, payload, now_ms, deadline_ms)
                    .map_err(IngressPipelineError::Queue)
            })
            .map_err(|error| match error {
                IngressBudgetTransactionError::Budget(error) => IngressPipelineError::Budget(error),
                IngressBudgetTransactionError::Commit(error) => error,
            })?;
        state.known_requests.insert(request_id);
        Ok(result)
    }
    /// Move at most one FIFO item into an available worker lease. If worker capacity is full, the
    /// item remains queued. No thread is spawned; the caller must run bounded/cooperative work and
    /// finish/drop the returned lease on every exit path.
    pub fn dispatch_next(
        &self,
        now_ms: u64,
    ) -> Result<Option<ActiveIngressWork>, IngressPipelineError> {
        let mut state = self.lock_state()?;
        Self::advance_locked(&mut state, now_ms)?;
        let pool = state
            .workers
            .snapshot()
            .map_err(IngressPipelineError::Worker)?;
        if pool.active_workers >= self.max_active_workers {
            return Ok(None);
        }
        let Some(head) = state
            .queue
            .peek_next()
            .map_err(IngressPipelineError::Queue)?
        else {
            return Ok(None);
        };

        // Reserve the worker slot before removing the payload. Under the outer gate, no competing
        // dispatcher can claim capacity between the snapshot and this claim; lease drop rolls back
        // the active slot if queue removal unexpectedly fails.
        state
            .workers
            .submit(head.peer_id, head.request_id, now_ms, head.deadline_ms)
            .map_err(IngressPipelineError::Worker)?;
        let lease = match state.workers.claim_next(now_ms) {
            Ok(Some(lease)) => lease,
            Ok(None) => {
                let _ = state.workers.cancel(head.request_id, now_ms);
                return Err(IngressPipelineError::InternalInvariant);
            }
            Err(error) => {
                let _ = state.workers.cancel(head.request_id, now_ms);
                return Err(IngressPipelineError::Worker(error));
            }
        };
        let popped = match state.queue.pop_next(now_ms) {
            Ok(popped) => popped,
            Err(error) => {
                drop(lease);
                return Err(IngressPipelineError::Queue(error));
            }
        };
        let Some(item) = popped.item else {
            drop(lease);
            state.known_requests.remove(&head.request_id);
            return Err(IngressPipelineError::InternalInvariant);
        };
        if item.request_id != head.request_id || item.peer_id != head.peer_id {
            drop(lease);
            state.known_requests.remove(&head.request_id);
            state.known_requests.remove(&item.request_id);
            return Err(IngressPipelineError::InternalInvariant);
        }
        Ok(Some(ActiveIngressWork {
            item,
            lease: Some(lease),
            pipeline: Arc::downgrade(&self.inner),
        }))
    }

    /// Cancel a queued request immediately or cooperatively signal a running worker. Active slots
    /// and request IDs remain reserved until signalled worker code actually exits.
    pub fn cancel(
        &self,
        request_id: IngressQueueRequestId,
        now_ms: u64,
    ) -> Result<IngressPipelineCancelOutcome, IngressPipelineError> {
        let mut state = self.lock_state()?;
        Self::advance_locked(&mut state, now_ms)?;
        if state
            .queue
            .cancel(request_id)
            .map_err(IngressPipelineError::Queue)?
        {
            state.known_requests.remove(&request_id);
            return Ok(IngressPipelineCancelOutcome::CancelledQueued);
        }
        let outcome = state
            .workers
            .cancel(request_id, now_ms)
            .map_err(IngressPipelineError::Worker)?;
        if matches!(
            outcome,
            WorkerCancelOutcome::CancelledQueued | WorkerCancelOutcome::ExpiredQueued
        ) {
            state.known_requests.remove(&request_id);
        }
        Ok(IngressPipelineCancelOutcome::Worker(outcome))
    }

    /// Reconcile expired queued IDs and signal expired running leases. Running code remains counted
    /// as active until it checks/exits and drops its lease.
    pub fn maintain(
        &self,
        now_ms: u64,
    ) -> Result<IngressPipelineExpiryReport, IngressPipelineError> {
        let mut state = self.lock_state()?;
        Self::advance_locked(&mut state, now_ms)
    }

    pub fn snapshot(&self) -> Result<IngressPipelineSnapshot, IngressPipelineError> {
        let state = self.lock_state()?;
        let queue = state
            .queue
            .snapshot()
            .map_err(IngressPipelineError::Queue)?;
        let budget = state
            .budget
            .snapshot()
            .map_err(IngressPipelineError::Budget)?;
        let workers = state
            .workers
            .snapshot()
            .map_err(IngressPipelineError::Worker)?;
        Ok(IngressPipelineSnapshot {
            queue,
            budget,
            workers,
            tracked_requests: state.known_requests.len(),
            max_tracked_requests: state.max_tracked_requests,
            max_retained_payload_bytes: state.max_retained_payload_bytes,
            last_observed_ms: state.last_observed_ms,
        })
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, PipelineState>, IngressPipelineError> {
        self.inner
            .lock()
            .map_err(|_| IngressPipelineError::LockPoisoned)
    }

    fn advance_locked(
        state: &mut PipelineState,
        now_ms: u64,
    ) -> Result<IngressPipelineExpiryReport, IngressPipelineError> {
        if now_ms < state.last_observed_ms {
            return Err(IngressPipelineError::ClockRegressed);
        }
        let expired_ids = state
            .queue
            .reap_expired_ids(now_ms)
            .map_err(IngressPipelineError::Queue)?;
        for request_id in &expired_ids {
            state.known_requests.remove(request_id);
        }
        let _reaped_peers = state
            .budget
            .reap_refilled_peers(now_ms)
            .map_err(IngressPipelineError::Budget)?;
        let worker_expiry: WorkerExpiryReport = state
            .workers
            .expire_due(now_ms)
            .map_err(IngressPipelineError::Worker)?;
        state.last_observed_ms = now_ms;
        Ok(IngressPipelineExpiryReport {
            queued_expired: expired_ids.len(),
            running_signalled: worker_expiry.running_signalled,
        })
    }
}

impl ActiveIngressWork {
    pub fn item(&self) -> &QueuedIngressItem {
        &self.item
    }

    pub fn request_id(&self) -> IngressQueueRequestId {
        self.item.request_id
    }

    pub fn check(&self, now_ms: u64) -> Result<(), ActiveIngressWorkError> {
        self.observe_pipeline_clock(now_ms)?;
        match self.lease.as_ref() {
            Some(lease) => lease.check(now_ms).map_err(ActiveIngressWorkError::Worker),
            None => Ok(()),
        }
    }

    /// Check completion time and release the worker slot and cross-phase request ID on every path.
    pub fn finish(mut self, now_ms: u64) -> Result<(), ActiveIngressWorkError> {
        let clock_result = self.observe_pipeline_clock(now_ms);
        let outcome = match self.lease.take() {
            Some(lease) => match clock_result {
                Ok(()) => lease.finish(now_ms).map_err(ActiveIngressWorkError::Worker),
                Err(error) => {
                    drop(lease);
                    Err(error)
                }
            },
            None => clock_result,
        };
        self.unregister_request_id();
        outcome
    }

    fn observe_pipeline_clock(&self, now_ms: u64) -> Result<(), ActiveIngressWorkError> {
        let Some(inner) = self.pipeline.upgrade() else {
            return Ok(());
        };
        let mut state = inner
            .lock()
            .map_err(|_| ActiveIngressWorkError::LockPoisoned)?;
        if now_ms < state.last_observed_ms {
            return Err(ActiveIngressWorkError::ClockRegressed {
                previous_ms: state.last_observed_ms,
                current_ms: now_ms,
            });
        }
        state.last_observed_ms = now_ms;
        Ok(())
    }

    fn unregister_request_id(&mut self) {
        let Some(inner) = self.pipeline.upgrade() else {
            return;
        };
        let mut state = match inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.known_requests.remove(&self.item.request_id);
    }
}

impl Drop for ActiveIngressWork {
    fn drop(&mut self) {
        // Release the worker-coordinator mutex before taking the outer gate to avoid lock inversion.
        drop(self.lease.take());
        self.unregister_request_id();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingress_queue_candidate::IngressBackpressure;
    use std::sync::{mpsc, Arc, Barrier};
    use std::thread;

    fn id(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn queue_config() -> IngressQueueConfig {
        IngressQueueConfig {
            max_items: 8,
            max_bytes: 256,
            max_item_bytes: 32,
            max_deadline_horizon_ms: 1_000,
            high_watermark_items: 4,
            low_watermark_items: 1,
            high_watermark_bytes: 128,
            low_watermark_bytes: 16,
        }
    }

    fn budget_config() -> IngressBudgetConfig {
        IngressBudgetConfig {
            max_peers: 32,
            max_cost_per_request: 8,
            global_capacity: 128,
            global_refill_per_second: 0,
            per_peer_capacity: 32,
            per_peer_refill_per_second: 0,
        }
    }
    fn setup(max_active_workers: usize) -> BoundedIngressPipeline {
        BoundedIngressPipeline::new(
            IngressPipelineConfig {
                queue: queue_config(),
                budget: budget_config(),
                cost_bytes_per_unit: 16,
                max_active_workers,
            },
            0,
        )
        .unwrap()
    }

    fn enqueue(pipeline: &BoundedIngressPipeline, n: u8, now: u64, deadline: u64) {
        pipeline
            .enqueue(id(n.wrapping_add(100)), id(n), vec![n; 8], now, deadline)
            .unwrap();
    }

    #[test]
    fn rejects_zero_worker_capacity() {
        assert!(matches!(
            BoundedIngressPipeline::new(
                IngressPipelineConfig {
                    queue: queue_config(),
                    budget: budget_config(),
                    cost_bytes_per_unit: 16,
                    max_active_workers: 0,
                },
                0,
            ),
            Err(IngressPipelineConfigError::ZeroActiveWorkers)
        ));
    }

    #[test]
    fn dispatch_respects_worker_ceiling_and_preserves_fifo_order() {
        let pipeline = setup(2);
        for n in 1..=4 {
            enqueue(&pipeline, n, 1, 100);
        }
        let first = pipeline.dispatch_next(2).unwrap().unwrap();
        let second = pipeline.dispatch_next(2).unwrap().unwrap();
        assert_eq!(first.request_id(), id(1));
        assert_eq!(second.request_id(), id(2));
        assert!(pipeline.dispatch_next(2).unwrap().is_none());
        assert_eq!(pipeline.snapshot().unwrap().workers.active_workers, 2);
        assert_eq!(pipeline.snapshot().unwrap().queue.queued_items, 2);
        first.finish(3).unwrap();
        let third = pipeline.dispatch_next(3).unwrap().unwrap();
        assert_eq!(third.request_id(), id(3));
        drop(second);
        drop(third);
        let last = pipeline.dispatch_next(4).unwrap().unwrap();
        assert_eq!(last.request_id(), id(4));
    }

    #[test]
    fn request_ids_stay_reserved_across_queued_and_running_phases() {
        let pipeline = setup(1);
        enqueue(&pipeline, 7, 1, 100);
        let work = pipeline.dispatch_next(2).unwrap().unwrap();
        assert_eq!(
            pipeline.enqueue(id(107), id(7), vec![7; 8], 3, 100),
            Err(IngressPipelineError::DuplicateRequestId)
        );
        work.finish(3).unwrap();
        pipeline
            .enqueue(id(107), id(7), vec![7; 8], 4, 100)
            .unwrap();
        assert_eq!(pipeline.snapshot().unwrap().tracked_requests, 1);
    }

    #[test]
    fn queued_cancel_releases_capacity_and_running_cancel_is_cooperative() {
        let pipeline = setup(1);
        enqueue(&pipeline, 1, 1, 100);
        enqueue(&pipeline, 2, 1, 100);
        let active = pipeline.dispatch_next(2).unwrap().unwrap();
        assert_eq!(
            pipeline.cancel(id(2), 3).unwrap(),
            IngressPipelineCancelOutcome::CancelledQueued
        );
        assert_eq!(
            pipeline.cancel(id(1), 3).unwrap(),
            IngressPipelineCancelOutcome::Worker(WorkerCancelOutcome::CancellationSignalledRunning)
        );
        assert_eq!(
            active.check(4),
            Err(ActiveIngressWorkError::Worker(WorkerCheckError::Cancelled))
        );
        assert_eq!(pipeline.snapshot().unwrap().workers.active_workers, 1);
        assert_eq!(pipeline.snapshot().unwrap().tracked_requests, 1);
        drop(active);
        assert_eq!(pipeline.snapshot().unwrap().workers.active_workers, 0);
        assert_eq!(pipeline.snapshot().unwrap().tracked_requests, 0);
    }

    #[test]
    fn expiry_reconciles_queued_ids_but_running_lease_holds_slot_until_exit() {
        let pipeline = setup(1);
        enqueue(&pipeline, 1, 1, 5);
        enqueue(&pipeline, 2, 1, 50);
        let active = pipeline.dispatch_next(2).unwrap().unwrap();
        let report = pipeline.maintain(5).unwrap();
        assert_eq!(report.queued_expired, 0);
        assert_eq!(report.running_signalled, 1);
        assert_eq!(
            active.check(5),
            Err(ActiveIngressWorkError::Worker(
                WorkerCheckError::DeadlineExceeded
            ))
        );
        assert_eq!(pipeline.snapshot().unwrap().workers.active_workers, 1);
        // The still-live queued request remains tracked; the running one has not exited yet.
        assert_eq!(pipeline.snapshot().unwrap().tracked_requests, 2);
        drop(active);
        assert_eq!(pipeline.snapshot().unwrap().workers.active_workers, 0);
        assert_eq!(pipeline.snapshot().unwrap().tracked_requests, 1);
        assert_eq!(pipeline.maintain(50).unwrap().queued_expired, 1);
        assert_eq!(pipeline.snapshot().unwrap().tracked_requests, 0);
        pipeline
            .enqueue(id(101), id(1), vec![1; 8], 50, 100)
            .unwrap();
        assert_eq!(pipeline.snapshot().unwrap().tracked_requests, 1);
    }

    #[test]
    fn rejects_clock_regression_without_admission_mutation() {
        let pipeline = setup(1);
        enqueue(&pipeline, 1, 10, 100);
        assert_eq!(
            pipeline.enqueue(id(102), id(2), vec![2; 8], 9, 100),
            Err(IngressPipelineError::ClockRegressed)
        );
        assert_eq!(pipeline.snapshot().unwrap().queue.queued_items, 1);
        assert_eq!(pipeline.snapshot().unwrap().tracked_requests, 1);
    }

    #[test]
    fn concurrent_dispatch_never_exceeds_active_worker_cap() {
        // Keep watermark above this fixture's six queued requests; this test isolates dispatch
        // concurrency. Backpressure activation under concurrent admission is tested separately.
        let mut config = queue_config();
        config.high_watermark_items = 8;
        config.high_watermark_bytes = 256;
        let pipeline = Arc::new(
            BoundedIngressPipeline::new(
                IngressPipelineConfig {
                    queue: config,
                    budget: budget_config(),
                    cost_bytes_per_unit: 16,
                    max_active_workers: 3,
                },
                0,
            )
            .unwrap(),
        );
        for n in 1..=6 {
            enqueue(&pipeline, n, 1, 100);
        }
        let barrier = Arc::new(Barrier::new(9));
        let (tx, rx) = mpsc::channel();
        let mut threads = Vec::new();
        for _ in 0..8 {
            let p = Arc::clone(&pipeline);
            let b = Arc::clone(&barrier);
            let tx = tx.clone();
            threads.push(thread::spawn(move || {
                b.wait();
                tx.send(p.dispatch_next(2).unwrap()).unwrap();
            }));
        }
        barrier.wait();
        drop(tx);
        let mut active = Vec::new();
        for result in rx {
            if let Some(work) = result {
                active.push(work);
            }
        }
        for handle in threads {
            handle.join().unwrap();
        }
        assert_eq!(active.len(), 3);
        let snapshot = pipeline.snapshot().unwrap();
        assert_eq!(snapshot.workers.active_workers, 3);
        assert_eq!(snapshot.queue.queued_items, 3);
        assert!(snapshot.tracked_requests <= snapshot.max_tracked_requests);
        assert_eq!(snapshot.max_retained_payload_bytes, 256 + 3 * 32);
        drop(active);
    }

    #[test]
    fn concurrent_admission_stops_at_high_watermark_and_never_exceeds_bounds() {
        let mut config = queue_config();
        config.max_items = 128;
        config.max_bytes = 4_096;
        config.max_item_bytes = 16;
        config.high_watermark_items = 64;
        config.low_watermark_items = 16;
        config.high_watermark_bytes = 2_048;
        config.low_watermark_bytes = 256;
        let pipeline = Arc::new(
            BoundedIngressPipeline::new(
                IngressPipelineConfig {
                    queue: config,
                    budget: budget_config(),
                    cost_bytes_per_unit: 16,
                    max_active_workers: 4,
                },
                0,
            )
            .unwrap(),
        );
        let barrier = Arc::new(Barrier::new(17));
        let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut threads = Vec::new();
        for thread_id in 0..16u8 {
            let p = Arc::clone(&pipeline);
            let b = Arc::clone(&barrier);
            let a = Arc::clone(&accepted);
            threads.push(thread::spawn(move || {
                b.wait();
                for n in 0..20u8 {
                    let mut request_id = [0u8; 32];
                    request_id[0] = thread_id;
                    request_id[1] = n;
                    let mut peer_id = [0u8; 32];
                    peer_id[0] = 200;
                    peer_id[1] = thread_id;
                    if p.enqueue(peer_id, request_id, vec![1], 1, 100).is_ok() {
                        a.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            }));
        }
        barrier.wait();
        for handle in threads {
            handle.join().unwrap();
        }
        let snapshot = pipeline.snapshot().unwrap();
        assert_eq!(accepted.load(std::sync::atomic::Ordering::Relaxed), 64);
        assert_eq!(snapshot.queue.queued_items, 64);
        assert_eq!(snapshot.queue.queued_bytes, 64);
        assert_eq!(snapshot.queue.backpressure, IngressBackpressure::Active);
        assert_eq!(snapshot.tracked_requests, 64);
        assert!(snapshot.tracked_requests <= snapshot.max_tracked_requests);
    }

    #[test]
    fn active_work_checks_advance_the_shared_monotonic_clock_and_finish_fails_closed() {
        let pipeline = setup(1);
        enqueue(&pipeline, 1, 1, 100);
        let work = pipeline.dispatch_next(2).unwrap().unwrap();
        work.check(10).unwrap();
        assert_eq!(
            pipeline.maintain(9),
            Err(IngressPipelineError::ClockRegressed)
        );
        assert_eq!(
            work.finish(9),
            Err(ActiveIngressWorkError::ClockRegressed {
                previous_ms: 10,
                current_ms: 9,
            })
        );
        let snapshot = pipeline.snapshot().unwrap();
        assert_eq!(snapshot.workers.active_workers, 0);
        assert_eq!(snapshot.tracked_requests, 0);
    }
    #[test]
    fn per_peer_and_global_budgets_apply_before_queue_retains_work() {
        let mut queue = queue_config();
        queue.max_item_bytes = 16;
        queue.high_watermark_items = 7;
        queue.low_watermark_items = 2;
        queue.high_watermark_bytes = 224;
        queue.low_watermark_bytes = 64;
        let budget = IngressBudgetConfig {
            max_peers: 4,
            max_cost_per_request: 2,
            global_capacity: 3,
            global_refill_per_second: 0,
            per_peer_capacity: 2,
            per_peer_refill_per_second: 0,
        };
        let pipeline = BoundedIngressPipeline::new(
            IngressPipelineConfig {
                queue,
                budget,
                cost_bytes_per_unit: 8,
                max_active_workers: 1,
            },
            0,
        )
        .unwrap();
        pipeline.enqueue(id(1), id(11), vec![1; 8], 1, 100).unwrap();
        pipeline.enqueue(id(1), id(12), vec![1; 8], 1, 100).unwrap();
        assert_eq!(
            pipeline.enqueue(id(1), id(13), vec![1; 8], 1, 100),
            Err(IngressPipelineError::Budget(
                IngressBudgetError::RateLimited(
                    crate::ingress_budget_candidate::IngressLimitScope::PerPeer
                )
            ))
        );
        assert_eq!(pipeline.snapshot().unwrap().queue.queued_items, 2);
        assert_eq!(pipeline.snapshot().unwrap().budget.global_tokens, 1);
        pipeline.enqueue(id(2), id(14), vec![2; 8], 1, 100).unwrap();
        assert_eq!(
            pipeline.enqueue(id(3), id(15), vec![3; 8], 1, 100),
            Err(IngressPipelineError::Budget(
                IngressBudgetError::RateLimited(
                    crate::ingress_budget_candidate::IngressLimitScope::Global
                )
            ))
        );
        let snapshot = pipeline.snapshot().unwrap();
        assert_eq!(snapshot.queue.queued_items, 3);
        assert_eq!(snapshot.budget.global_tokens, 0);
        assert_eq!(snapshot.budget.tracked_peers, 2);
    }

    #[test]
    fn rejected_queue_preflight_spends_no_budget_tokens() {
        let mut queue = queue_config();
        queue.high_watermark_items = 1;
        queue.low_watermark_items = 0;
        queue.high_watermark_bytes = 128;
        queue.low_watermark_bytes = 0;
        let pipeline = BoundedIngressPipeline::new(
            IngressPipelineConfig {
                queue,
                budget: IngressBudgetConfig {
                    max_peers: 4,
                    max_cost_per_request: 8,
                    global_capacity: 10,
                    global_refill_per_second: 0,
                    per_peer_capacity: 10,
                    per_peer_refill_per_second: 0,
                },
                cost_bytes_per_unit: 16,
                max_active_workers: 1,
            },
            0,
        )
        .unwrap();
        pipeline.enqueue(id(1), id(1), vec![1; 8], 1, 100).unwrap();
        let before = pipeline.snapshot().unwrap();
        assert_eq!(before.budget.global_tokens, 9);
        assert_eq!(before.budget.tracked_peers, 1);
        assert_eq!(
            pipeline.enqueue(id(2), id(2), vec![2; 8], 1, 100),
            Err(IngressPipelineError::Queue(
                IngressQueueError::BackpressureActive
            ))
        );
        let after = pipeline.snapshot().unwrap();
        assert_eq!(after.budget, before.budget);
        assert_eq!(after.queue, before.queue);
    }

    #[test]
    fn queued_cancellation_does_not_refund_per_peer_ingress_budget() {
        let pipeline = BoundedIngressPipeline::new(
            IngressPipelineConfig {
                queue: queue_config(),
                budget: IngressBudgetConfig {
                    max_peers: 4,
                    max_cost_per_request: 2,
                    global_capacity: 10,
                    global_refill_per_second: 0,
                    per_peer_capacity: 2,
                    per_peer_refill_per_second: 0,
                },
                cost_bytes_per_unit: 16,
                max_active_workers: 1,
            },
            0,
        )
        .unwrap();
        pipeline.enqueue(id(1), id(21), vec![1; 8], 1, 100).unwrap();
        pipeline.enqueue(id(1), id(22), vec![2; 8], 1, 100).unwrap();
        assert_eq!(pipeline.snapshot().unwrap().budget.global_tokens, 8);
        assert_eq!(
            pipeline.cancel(id(21), 2).unwrap(),
            IngressPipelineCancelOutcome::CancelledQueued
        );
        assert_eq!(pipeline.snapshot().unwrap().queue.queued_items, 1);
        assert_eq!(
            pipeline.enqueue(id(1), id(23), vec![3; 8], 2, 100),
            Err(IngressPipelineError::Budget(
                IngressBudgetError::RateLimited(
                    crate::ingress_budget_candidate::IngressLimitScope::PerPeer
                )
            ))
        );
        assert_eq!(pipeline.snapshot().unwrap().budget.global_tokens, 8);
        assert_eq!(pipeline.snapshot().unwrap().queue.queued_items, 1);
    }
    #[test]
    fn payload_cost_uses_ceil_byte_units_not_a_requester_supplied_cost() {
        let pipeline = setup(1);
        pipeline.enqueue(id(8), id(8), vec![8; 17], 1, 100).unwrap();
        let snapshot = pipeline.snapshot().unwrap();
        assert_eq!(snapshot.budget.global_tokens, 126);
        assert_eq!(snapshot.budget.tracked_peers, 1);
    }

    #[test]
    fn cost_budget_configuration_cannot_be_impossible_or_zero_unit() {
        assert!(matches!(
            BoundedIngressPipeline::new(
                IngressPipelineConfig {
                    queue: queue_config(),
                    budget: budget_config(),
                    cost_bytes_per_unit: 0,
                    max_active_workers: 1,
                },
                0,
            ),
            Err(IngressPipelineConfigError::ZeroCostBytesPerUnit)
        ));
        let mut budget = budget_config();
        budget.max_cost_per_request = 1;
        assert!(matches!(
            BoundedIngressPipeline::new(
                IngressPipelineConfig {
                    queue: queue_config(),
                    budget,
                    cost_bytes_per_unit: 8,
                    max_active_workers: 1,
                },
                0,
            ),
            Err(IngressPipelineConfigError::MaxPayloadCostExceedsBudgetLimit)
        ));
    }
    #[test]
    fn queue_metadata_peek_does_not_remove_or_duplicate_payload() {
        let pipeline = setup(1);
        enqueue(&pipeline, 3, 1, 100);
        let snapshot_before = pipeline.snapshot().unwrap();
        let work = pipeline.dispatch_next(2).unwrap().unwrap();
        assert_eq!(work.item().payload, vec![3; 8]);
        assert_eq!(snapshot_before.queue.queued_items, 1);
        assert_eq!(pipeline.snapshot().unwrap().queue.queued_items, 0);
    }
}
