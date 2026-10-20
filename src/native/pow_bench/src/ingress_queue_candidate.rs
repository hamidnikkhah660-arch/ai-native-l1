//! Bounded FIFO ingress queue with byte budgets, deadlines, cancellation and backpressure.
//!
//! Research-only in-memory model. It is intentionally not wired into a socket, async runtime,
//! node, RPC, P2P or persistence. A caller must check raw-frame size before allocating/copying a
//! payload and authenticate peer identity before enqueueing. The queue bounds retained memory,
//! not memory already allocated by the caller.
use std::collections::{HashSet, VecDeque};
use std::sync::{Mutex, MutexGuard};

pub type IngressQueuePeerId = [u8; 32];
pub type IngressQueueRequestId = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngressQueueConfig {
    pub max_items: usize,
    pub max_bytes: usize,
    pub max_item_bytes: usize,
    pub max_deadline_horizon_ms: u64,
    pub high_watermark_items: usize,
    pub low_watermark_items: usize,
    pub high_watermark_bytes: usize,
    pub low_watermark_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressQueueConfigError {
    ZeroItemCapacity,
    ZeroByteCapacity,
    ZeroItemBytes,
    ItemBytesExceedQueueBytes,
    ZeroDeadlineHorizon,
    InvalidItemWatermarks,
    InvalidByteWatermarks,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressQueueError {
    EmptyPayload,
    ItemTooLarge,
    DeadlineAlreadyExpired,
    DeadlineTooFar,
    DuplicateRequestId,
    ItemCapacityReached,
    ByteCapacityReached,
    BackpressureActive,
    ClockRegressed,
    LockPoisoned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressBackpressure {
    Open,
    Active,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedIngressItem {
    pub peer_id: IngressQueuePeerId,
    pub request_id: IngressQueueRequestId,
    pub payload: Vec<u8>,
    pub enqueued_at_ms: u64,
    pub deadline_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngressQueueSnapshot {
    pub queued_items: usize,
    pub queued_bytes: usize,
    pub backpressure: IngressBackpressure,
    pub last_observed_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngressQueueHead {
    pub peer_id: IngressQueuePeerId,
    pub request_id: IngressQueueRequestId,
    pub deadline_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngressQueuePop {
    pub item: Option<QueuedIngressItem>,
    pub expired_items: usize,
    pub backpressure: IngressBackpressure,
}

#[derive(Debug)]
struct QueueState {
    fifo: VecDeque<QueuedIngressItem>,
    request_ids: HashSet<IngressQueueRequestId>,
    queued_bytes: usize,
    backpressure: IngressBackpressure,
    last_observed_ms: u64,
}

/// Strictly bounded FIFO with high/low watermark hysteresis. Once pressure activates, new
/// enqueue attempts are refused until both queue depth and byte usage are at/below low watermarks.
pub struct IngressQueue {
    config: IngressQueueConfig,
    state: Mutex<QueueState>,
}

impl IngressQueue {
    pub fn new(
        config: IngressQueueConfig,
        initial_time_ms: u64,
    ) -> Result<Self, IngressQueueConfigError> {
        if config.max_items == 0 {
            return Err(IngressQueueConfigError::ZeroItemCapacity);
        }
        if config.max_bytes == 0 {
            return Err(IngressQueueConfigError::ZeroByteCapacity);
        }
        if config.max_item_bytes == 0 {
            return Err(IngressQueueConfigError::ZeroItemBytes);
        }
        if config.max_item_bytes > config.max_bytes {
            return Err(IngressQueueConfigError::ItemBytesExceedQueueBytes);
        }
        if config.max_deadline_horizon_ms == 0 {
            return Err(IngressQueueConfigError::ZeroDeadlineHorizon);
        }
        if config.high_watermark_items == 0
            || config.high_watermark_items > config.max_items
            || config.low_watermark_items >= config.high_watermark_items
        {
            return Err(IngressQueueConfigError::InvalidItemWatermarks);
        }
        if config.high_watermark_bytes == 0
            || config.high_watermark_bytes > config.max_bytes
            || config.low_watermark_bytes >= config.high_watermark_bytes
        {
            return Err(IngressQueueConfigError::InvalidByteWatermarks);
        }
        Ok(Self {
            config,
            state: Mutex::new(QueueState {
                fifo: VecDeque::new(),
                request_ids: HashSet::new(),
                queued_bytes: 0,
                backpressure: IngressBackpressure::Open,
                last_observed_ms: initial_time_ms,
            }),
        })
    }

    /// Validate an enqueue without mutation. Coordinators may use this as a cheap preflight before
    /// charging another bounded resource; enqueue always rechecks the same rules under its mutex.
    pub fn validate_enqueue(
        &self,
        request_id: IngressQueueRequestId,
        payload_len: usize,
        now_ms: u64,
        deadline_ms: u64,
    ) -> Result<IngressQueueSnapshot, IngressQueueError> {
        if payload_len == 0 {
            return Err(IngressQueueError::EmptyPayload);
        }
        if payload_len > self.config.max_item_bytes {
            return Err(IngressQueueError::ItemTooLarge);
        }
        if deadline_ms <= now_ms {
            return Err(IngressQueueError::DeadlineAlreadyExpired);
        }
        if deadline_ms - now_ms > self.config.max_deadline_horizon_ms {
            return Err(IngressQueueError::DeadlineTooFar);
        }

        let state = self.lock_state()?;
        if now_ms < state.last_observed_ms {
            return Err(IngressQueueError::ClockRegressed);
        }
        if state.request_ids.contains(&request_id) {
            return Err(IngressQueueError::DuplicateRequestId);
        }
        if state.fifo.len() >= self.config.max_items {
            return Err(IngressQueueError::ItemCapacityReached);
        }
        if payload_len > self.config.max_bytes - state.queued_bytes {
            return Err(IngressQueueError::ByteCapacityReached);
        }
        if state.backpressure == IngressBackpressure::Active {
            return Err(IngressQueueError::BackpressureActive);
        }
        Ok(Self::snapshot_of(&state))
    }
    /// Enqueue only already-framed payloads with authenticated peer IDs and a trusted deadline.
    /// All rejection checks occur before mutating queue membership/bytes/watermarks.
    pub fn enqueue(
        &self,
        peer_id: IngressQueuePeerId,
        request_id: IngressQueueRequestId,
        payload: Vec<u8>,
        now_ms: u64,
        deadline_ms: u64,
    ) -> Result<IngressQueueSnapshot, IngressQueueError> {
        if payload.is_empty() {
            return Err(IngressQueueError::EmptyPayload);
        }
        if payload.len() > self.config.max_item_bytes {
            return Err(IngressQueueError::ItemTooLarge);
        }
        if deadline_ms <= now_ms {
            return Err(IngressQueueError::DeadlineAlreadyExpired);
        }
        if deadline_ms - now_ms > self.config.max_deadline_horizon_ms {
            return Err(IngressQueueError::DeadlineTooFar);
        }

        let mut state = self.lock_state()?;
        if now_ms < state.last_observed_ms {
            return Err(IngressQueueError::ClockRegressed);
        }
        if state.request_ids.contains(&request_id) {
            return Err(IngressQueueError::DuplicateRequestId);
        }
        // Report hard resource ceilings precisely even while the soft watermark is active.
        if state.fifo.len() >= self.config.max_items {
            return Err(IngressQueueError::ItemCapacityReached);
        }
        if payload.len() > self.config.max_bytes - state.queued_bytes {
            return Err(IngressQueueError::ByteCapacityReached);
        }
        if state.backpressure == IngressBackpressure::Active {
            return Err(IngressQueueError::BackpressureActive);
        }

        state.queued_bytes += payload.len();
        state.request_ids.insert(request_id);
        state.fifo.push_back(QueuedIngressItem {
            peer_id,
            request_id,
            payload,
            enqueued_at_ms: now_ms,
            deadline_ms,
        });
        state.last_observed_ms = now_ms;
        Self::refresh_backpressure(&self.config, &mut state);
        Ok(Self::snapshot_of(&state))
    }

    /// Cancel a queued request by its stable request ID. No item/byte counter changes occur if the
    /// ID is absent. Linear search is bounded by `max_items` and avoids a second mutable index.
    pub fn cancel(&self, request_id: IngressQueueRequestId) -> Result<bool, IngressQueueError> {
        let mut state = self.lock_state()?;
        let Some(index) = state
            .fifo
            .iter()
            .position(|entry| entry.request_id == request_id)
        else {
            return Ok(false);
        };
        let removed = state.fifo.remove(index).expect("located queue item exists");
        state.queued_bytes -= removed.payload.len();
        state.request_ids.remove(&request_id);
        Self::refresh_backpressure(&self.config, &mut state);
        Ok(true)
    }

    /// Remove every expired item, including expired entries behind the FIFO head. The queue is
    /// bounded, so the scan has a strict upper bound. A clock regression changes nothing.
    pub fn reap_expired(&self, now_ms: u64) -> Result<usize, IngressQueueError> {
        Ok(self.reap_expired_ids(now_ms)?.len())
    }

    /// Remove all expired items and return their IDs so a coordinating admission layer can
    /// reconcile cross-component duplicate-ID tracking without retaining tombstones forever.
    pub fn reap_expired_ids(
        &self,
        now_ms: u64,
    ) -> Result<Vec<IngressQueueRequestId>, IngressQueueError> {
        let mut state = self.lock_state()?;
        if now_ms < state.last_observed_ms {
            return Err(IngressQueueError::ClockRegressed);
        }
        let mut expired_ids = Vec::new();
        let mut retained = VecDeque::with_capacity(state.fifo.len());
        while let Some(item) = state.fifo.pop_front() {
            if item.deadline_ms <= now_ms {
                state.queued_bytes -= item.payload.len();
                state.request_ids.remove(&item.request_id);
                expired_ids.push(item.request_id);
            } else {
                retained.push_back(item);
            }
        }
        state.fifo = retained;
        state.last_observed_ms = now_ms;
        Self::refresh_backpressure(&self.config, &mut state);
        Ok(expired_ids)
    }

    /// Return immutable scheduling metadata for the current head without removing its payload.
    /// The coordinating caller serializes `peek_next` and `pop_next` with its own admission gate.
    pub fn peek_next(&self) -> Result<Option<IngressQueueHead>, IngressQueueError> {
        let state = self.lock_state()?;
        Ok(state.fifo.front().map(|item| IngressQueueHead {
            peer_id: item.peer_id,
            request_id: item.request_id,
            deadline_ms: item.deadline_ms,
        }))
    }

    /// Expire overdue items first, then return the next live FIFO item.
    pub fn pop_next(&self, now_ms: u64) -> Result<IngressQueuePop, IngressQueueError> {
        let mut state = self.lock_state()?;
        if now_ms < state.last_observed_ms {
            return Err(IngressQueueError::ClockRegressed);
        }
        let mut expired = 0usize;
        let mut retained = VecDeque::with_capacity(state.fifo.len());
        while let Some(item) = state.fifo.pop_front() {
            if item.deadline_ms <= now_ms {
                state.queued_bytes -= item.payload.len();
                state.request_ids.remove(&item.request_id);
                expired += 1;
            } else {
                retained.push_back(item);
            }
        }
        state.fifo = retained;
        let item = state.fifo.pop_front();
        if let Some(ref item) = item {
            state.queued_bytes -= item.payload.len();
            state.request_ids.remove(&item.request_id);
        }
        state.last_observed_ms = now_ms;
        Self::refresh_backpressure(&self.config, &mut state);
        Ok(IngressQueuePop {
            item,
            expired_items: expired,
            backpressure: state.backpressure,
        })
    }

    pub fn snapshot(&self) -> Result<IngressQueueSnapshot, IngressQueueError> {
        let state = self.lock_state()?;
        Ok(Self::snapshot_of(&state))
    }

    fn snapshot_of(state: &QueueState) -> IngressQueueSnapshot {
        IngressQueueSnapshot {
            queued_items: state.fifo.len(),
            queued_bytes: state.queued_bytes,
            backpressure: state.backpressure,
            last_observed_ms: state.last_observed_ms,
        }
    }

    fn refresh_backpressure(config: &IngressQueueConfig, state: &mut QueueState) {
        match state.backpressure {
            IngressBackpressure::Open
                if state.fifo.len() >= config.high_watermark_items
                    || state.queued_bytes >= config.high_watermark_bytes =>
            {
                state.backpressure = IngressBackpressure::Active;
            }
            IngressBackpressure::Active
                if state.fifo.len() <= config.low_watermark_items
                    && state.queued_bytes <= config.low_watermark_bytes =>
            {
                state.backpressure = IngressBackpressure::Open;
            }
            _ => {}
        }
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, QueueState>, IngressQueueError> {
        self.state
            .lock()
            .map_err(|_| IngressQueueError::LockPoisoned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    fn config() -> IngressQueueConfig {
        IngressQueueConfig {
            max_items: 8,
            max_bytes: 128,
            max_item_bytes: 32,
            max_deadline_horizon_ms: 1_000,
            high_watermark_items: 4,
            low_watermark_items: 1,
            high_watermark_bytes: 64,
            low_watermark_bytes: 16,
        }
    }

    fn id(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn enqueue(
        queue: &IngressQueue,
        n: u8,
        len: usize,
        now: u64,
        deadline: u64,
    ) -> Result<IngressQueueSnapshot, IngressQueueError> {
        queue.enqueue(id(1), id(n), vec![n; len], now, deadline)
    }

    #[test]
    fn config_rejects_zero_limits_and_invalid_hysteresis() {
        let mut cfg = config();
        cfg.max_items = 0;
        assert!(matches!(
            IngressQueue::new(cfg, 0),
            Err(IngressQueueConfigError::ZeroItemCapacity)
        ));
        let mut cfg = config();
        cfg.max_item_bytes = cfg.max_bytes + 1;
        assert!(matches!(
            IngressQueue::new(cfg, 0),
            Err(IngressQueueConfigError::ItemBytesExceedQueueBytes)
        ));
        let mut cfg = config();
        cfg.low_watermark_items = cfg.high_watermark_items;
        assert!(matches!(
            IngressQueue::new(cfg, 0),
            Err(IngressQueueConfigError::InvalidItemWatermarks)
        ));
        let mut cfg = config();
        cfg.low_watermark_bytes = cfg.high_watermark_bytes;
        assert!(matches!(
            IngressQueue::new(cfg, 0),
            Err(IngressQueueConfigError::InvalidByteWatermarks)
        ));
    }

    #[test]
    fn rejects_empty_oversized_expired_and_far_deadline_without_mutating_queue() {
        let queue = IngressQueue::new(config(), 10).unwrap();
        assert_eq!(
            queue.enqueue(id(1), id(1), vec![], 10, 20),
            Err(IngressQueueError::EmptyPayload)
        );
        assert_eq!(
            enqueue(&queue, 1, 33, 10, 20),
            Err(IngressQueueError::ItemTooLarge)
        );
        assert_eq!(
            enqueue(&queue, 1, 1, 10, 10),
            Err(IngressQueueError::DeadlineAlreadyExpired)
        );
        assert_eq!(
            enqueue(&queue, 1, 1, 10, 1_011),
            Err(IngressQueueError::DeadlineTooFar)
        );
        assert_eq!(
            queue.snapshot().unwrap(),
            IngressQueueSnapshot {
                queued_items: 0,
                queued_bytes: 0,
                backpressure: IngressBackpressure::Open,
                last_observed_ms: 10
            }
        );
    }

    #[test]
    fn count_and_byte_limits_reject_atomically() {
        let mut cfg = config();
        cfg.high_watermark_items = 8;
        cfg.low_watermark_items = 0;
        cfg.max_item_bytes = 64;
        cfg.high_watermark_bytes = 128;
        cfg.low_watermark_bytes = 0;
        let queue = IngressQueue::new(cfg, 0).unwrap();
        enqueue(&queue, 1, 32, 0, 500).unwrap();
        enqueue(&queue, 2, 32, 0, 500).unwrap();
        enqueue(&queue, 3, 32, 0, 500).unwrap();
        assert_eq!(
            enqueue(&queue, 4, 40, 0, 500),
            Err(IngressQueueError::ByteCapacityReached)
        );
        assert_eq!(queue.snapshot().unwrap().queued_items, 3);
        assert_eq!(queue.snapshot().unwrap().queued_bytes, 96);

        let mut cfg = config();
        cfg.max_items = 4;
        cfg.max_bytes = 256;
        cfg.max_item_bytes = 32;
        cfg.high_watermark_items = 4;
        cfg.low_watermark_items = 0;
        cfg.high_watermark_bytes = 256;
        cfg.low_watermark_bytes = 0;
        let queue = IngressQueue::new(cfg, 0).unwrap();
        for n in 1..=4 {
            enqueue(&queue, n, 1, 0, 500).unwrap();
        }
        assert_eq!(
            enqueue(&queue, 5, 1, 0, 500),
            Err(IngressQueueError::ItemCapacityReached)
        );
        assert_eq!(queue.snapshot().unwrap().queued_items, 4);
        assert_eq!(queue.snapshot().unwrap().queued_bytes, 4);
    }

    #[test]
    fn backpressure_uses_high_low_hysteresis_and_resumes_only_below_both_low_marks() {
        let queue = IngressQueue::new(config(), 0).unwrap();
        enqueue(&queue, 1, 16, 0, 900).unwrap();
        enqueue(&queue, 2, 16, 0, 900).unwrap();
        enqueue(&queue, 3, 16, 0, 900).unwrap();
        assert_eq!(
            enqueue(&queue, 4, 16, 0, 900).unwrap().backpressure,
            IngressBackpressure::Active
        );
        assert_eq!(
            enqueue(&queue, 5, 1, 0, 900),
            Err(IngressQueueError::BackpressureActive)
        );
        // Remove two items: depth becomes 2, which is above low item watermark 1.
        assert!(queue.cancel(id(1)).unwrap());
        assert!(queue.cancel(id(2)).unwrap());
        assert_eq!(
            queue.snapshot().unwrap().backpressure,
            IngressBackpressure::Active
        );
        // One more item reaches low item watermark 1, and bytes are <= low byte watermark 16.
        assert!(queue.cancel(id(3)).unwrap());
        assert_eq!(
            queue.snapshot().unwrap().backpressure,
            IngressBackpressure::Open
        );
        enqueue(&queue, 5, 1, 0, 900).unwrap();
    }

    #[test]
    fn duplicate_id_and_missing_cancellation_do_not_change_state() {
        let queue = IngressQueue::new(config(), 0).unwrap();
        enqueue(&queue, 1, 7, 0, 900).unwrap();
        let before = queue.snapshot().unwrap();
        assert_eq!(
            enqueue(&queue, 1, 8, 0, 900),
            Err(IngressQueueError::DuplicateRequestId)
        );
        assert!(!queue.cancel(id(2)).unwrap());
        assert_eq!(queue.snapshot().unwrap(), before);
    }

    #[test]
    fn expired_non_head_items_are_removed_and_bytes_reconciled() {
        let queue = IngressQueue::new(config(), 0).unwrap();
        enqueue(&queue, 1, 10, 0, 500).unwrap();
        enqueue(&queue, 2, 20, 0, 100).unwrap();
        enqueue(&queue, 3, 30, 0, 700).unwrap();
        assert_eq!(queue.reap_expired(100).unwrap(), 1);
        assert_eq!(queue.snapshot().unwrap().queued_items, 2);
        assert_eq!(queue.snapshot().unwrap().queued_bytes, 40);
        let popped = queue.pop_next(100).unwrap();
        assert_eq!(popped.item.unwrap().request_id, id(1));
        assert_eq!(popped.expired_items, 0);
        assert_eq!(queue.snapshot().unwrap().queued_bytes, 30);
    }

    #[test]
    fn pop_skips_deadlines_and_returns_next_live_fifo_entry() {
        let queue = IngressQueue::new(config(), 0).unwrap();
        enqueue(&queue, 1, 10, 0, 10).unwrap();
        enqueue(&queue, 2, 20, 0, 100).unwrap();
        let result = queue.pop_next(10).unwrap();
        assert_eq!(result.expired_items, 1);
        assert_eq!(result.item.unwrap().request_id, id(2));
        assert_eq!(queue.snapshot().unwrap().queued_items, 0);
        assert_eq!(queue.snapshot().unwrap().queued_bytes, 0);
    }

    #[test]
    fn clock_regression_rejection_preserves_queue_state() {
        let queue = IngressQueue::new(config(), 10).unwrap();
        enqueue(&queue, 1, 8, 20, 100).unwrap();
        let before = queue.snapshot().unwrap();
        assert_eq!(
            enqueue(&queue, 2, 8, 19, 100),
            Err(IngressQueueError::ClockRegressed)
        );
        assert_eq!(
            queue.reap_expired(19),
            Err(IngressQueueError::ClockRegressed)
        );
        assert_eq!(queue.pop_next(19), Err(IngressQueueError::ClockRegressed));
        assert_eq!(queue.snapshot().unwrap(), before);
    }

    #[test]
    fn concurrent_enqueue_never_exceeds_count_or_byte_bound_and_activates_backpressure() {
        let mut cfg = config();
        cfg.max_items = 64;
        cfg.max_bytes = 4096;
        cfg.max_item_bytes = 64;
        cfg.high_watermark_items = 64;
        cfg.low_watermark_items = 0;
        cfg.high_watermark_bytes = 4096;
        cfg.low_watermark_bytes = 0;
        let queue = Arc::new(IngressQueue::new(cfg, 0).unwrap());
        let mut workers = Vec::new();
        for worker in 0..16u8 {
            let shared = Arc::clone(&queue);
            workers.push(thread::spawn(move || {
                let mut accepted = 0;
                let mut rejected = 0;
                for attempt in 0..20u8 {
                    let mut rid = [0u8; 32];
                    rid[0] = worker;
                    rid[1] = attempt;
                    match shared.enqueue(id(worker), rid, vec![worker; 1], 0, 500) {
                        Ok(_) => accepted += 1,
                        Err(
                            IngressQueueError::BackpressureActive
                            | IngressQueueError::ItemCapacityReached,
                        ) => rejected += 1,
                        other => panic!("unexpected queue result: {other:?}"),
                    }
                }
                (accepted, rejected)
            }));
        }
        let (accepted, rejected) = workers
            .into_iter()
            .map(|w| w.join().unwrap())
            .fold((0, 0), |(a, r), (x, y)| (a + x, r + y));
        assert_eq!(accepted, 64);
        assert_eq!(rejected, 256);
        let snapshot = queue.snapshot().unwrap();
        assert_eq!(snapshot.queued_items, 64);
        assert_eq!(snapshot.queued_bytes, 64);
        assert_eq!(snapshot.backpressure, IngressBackpressure::Active);
    }

    #[test]
    fn cancellation_and_expiry_release_pressure_only_after_both_low_watermarks() {
        let queue = IngressQueue::new(config(), 0).unwrap();
        for n in 1..=4u8 {
            enqueue(&queue, n, 16, 0, 100).unwrap();
        }
        assert_eq!(
            queue.snapshot().unwrap().backpressure,
            IngressBackpressure::Active
        );
        assert_eq!(queue.reap_expired(100).unwrap(), 4);
        let snapshot = queue.snapshot().unwrap();
        assert_eq!(snapshot.queued_items, 0);
        assert_eq!(snapshot.queued_bytes, 0);
        assert_eq!(snapshot.backpressure, IngressBackpressure::Open);
    }
}
