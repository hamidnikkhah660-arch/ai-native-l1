//! Research-only immutable payload range server and bounded session/global serving budgets.
//!
//! The runtime candidate may expose this immutable snapshot only after authenticating a peer
//! through the existing Noise layer. Cursor/session keys remain caller-supplied and this API cannot
//! itself authenticate peers, prevent Sybil identities, or make in-memory quotas survive restart.
//! Returned pages are bounded and shared by `Arc`; callers must serialize/write them under their
//! own absolute deadline and promptly drop their references.
use crate::private_testnet_archive_sync_candidate::{
    ArchiveEntryMeta, ArchiveSyncError, ArchiveSyncIndex, ArchiveSyncLimits, ArchiveSyncPage,
    MAX_CANDIDATE_ENVELOPE_BYTES, MAX_CANDIDATE_PAGES, MAX_CANDIDATE_TOTAL_BYTES,
    MAX_CANDIDATE_TOTAL_ITEMS,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

pub const MAX_CANDIDATE_SERVING_SESSIONS: usize = 16;
pub const MAX_CANDIDATE_GLOBAL_SERVE_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_CANDIDATE_GLOBAL_SERVE_ITEMS: u64 = 1_048_576;
pub const MAX_CANDIDATE_GLOBAL_SERVE_PAGES: u64 = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveRangeServerError {
    Archive(ArchiveSyncError),
    EmptyPayload,
    PayloadTooLarge,
    PayloadLengthMismatch,
    PayloadHashMismatch,
    PayloadCountMismatch,
    PayloadMetadataMismatch,
    SessionTableFull,
    SessionAlreadyRegistered,
    SessionBindingMismatch,
    InvalidCursorKey,
    SessionNotRegistered,
    SessionAlreadyStarted,
    ReplayRejected,
    SessionQuotaExceeded,
    GlobalQuotaExceeded,
    CounterOverflow,
    IncompleteArchiveIndex,
    LockPoisoned,
}

impl From<ArchiveSyncError> for ArchiveRangeServerError {
    fn from(value: ArchiveSyncError) -> Self {
        Self::Archive(value)
    }
}

/// One immutable, exact encoded block envelope. `payload_sha256` is checked against metadata;
/// `meta.digest` remains the chain/block digest and must be independently verified by consensus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveSyncPayload {
    meta: ArchiveEntryMeta,
    encoded: Vec<u8>,
}

impl ArchiveSyncPayload {
    pub fn new(meta: ArchiveEntryMeta, encoded: Vec<u8>) -> Result<Self, ArchiveRangeServerError> {
        if encoded.is_empty() {
            return Err(ArchiveRangeServerError::EmptyPayload);
        }
        let encoded_len =
            u64::try_from(encoded.len()).map_err(|_| ArchiveRangeServerError::PayloadTooLarge)?;
        if encoded_len > MAX_CANDIDATE_ENVELOPE_BYTES {
            return Err(ArchiveRangeServerError::PayloadTooLarge);
        }
        if encoded_len != meta.encoded_len {
            return Err(ArchiveRangeServerError::PayloadLengthMismatch);
        }
        let payload_hash: [u8; 32] = Sha256::digest(&encoded).into();
        if payload_hash != meta.payload_sha256 {
            return Err(ArchiveRangeServerError::PayloadHashMismatch);
        }
        Ok(Self { meta, encoded })
    }

    pub fn metadata(&self) -> &ArchiveEntryMeta {
        &self.meta
    }

    pub fn encoded_len(&self) -> usize {
        self.encoded.len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchiveRangeBudgetConfig {
    pub max_sessions: usize,
    pub per_session_max_pages: u64,
    pub per_session_max_items: u64,
    pub per_session_max_bytes: u64,
    pub global_max_pages: u64,
    pub global_max_items: u64,
    pub global_max_bytes: u64,
}

impl ArchiveRangeBudgetConfig {
    pub fn validate(&self, limits: ArchiveSyncLimits) -> Result<(), ArchiveRangeServerError> {
        limits.validate()?;
        if self.max_sessions == 0
            || self.max_sessions > MAX_CANDIDATE_SERVING_SESSIONS
            || self.per_session_max_pages == 0
            || self.per_session_max_pages > u64::from(MAX_CANDIDATE_PAGES)
            || self.per_session_max_items == 0
            || self.per_session_max_items > MAX_CANDIDATE_TOTAL_ITEMS
            || self.per_session_max_bytes == 0
            || self.per_session_max_bytes > MAX_CANDIDATE_TOTAL_BYTES
            || self.global_max_pages == 0
            || self.global_max_pages > MAX_CANDIDATE_GLOBAL_SERVE_PAGES
            || self.global_max_items == 0
            || self.global_max_items > MAX_CANDIDATE_GLOBAL_SERVE_ITEMS
            || self.global_max_bytes == 0
            || self.global_max_bytes > MAX_CANDIDATE_GLOBAL_SERVE_BYTES
            || self.global_max_pages < self.per_session_max_pages
            || self.global_max_items < self.per_session_max_items
            || self.global_max_bytes < self.per_session_max_bytes
        {
            return Err(ArchiveRangeServerError::Archive(
                ArchiveSyncError::InvalidLimits,
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveSyncServedEntry {
    pub metadata: ArchiveEntryMeta,
    pub encoded: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveSyncServedPage {
    pub plan: ArchiveSyncPage,
    /// Counts and bytes in the immutable source snapshot, not just this page.
    pub archive_total_items: u64,
    pub archive_total_bytes: u64,
    pub snapshot_commitment: [u8; 32],
    pub entries: Vec<ArchiveSyncServedEntry>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ArchiveServeUsage {
    /// Counts response attempts, including exact retries of the most recent page.
    pub pages: u64,
    /// Counts entries in all response attempts, including retries.
    pub items: u64,
    /// Counts bytes in all response attempts, including retries.
    pub bytes: u64,
}

#[derive(Debug, Clone)]
struct SessionState {
    cursor_key: [u8; 32],
    started: bool,
    next_offset: usize,
    usage: ArchiveServeUsage,
    last_request_cursor: Option<Vec<u8>>,
    last_response: Option<Arc<ArchiveSyncServedPage>>,
}

#[derive(Debug, Default)]
struct ServerState {
    global_usage: ArchiveServeUsage,
    sessions: BTreeMap<[u8; 32], SessionState>,
}

/// Immutable archive payload snapshot with one bounded session table and aggregate response budget.
/// This candidate is intended for one finite snapshot lifecycle; persistent, cross-restart quotas
/// and session expiration/revocation are deliberately not claimed here.
pub struct ArchiveRangeServerCandidate {
    index: ArchiveSyncIndex,
    payloads: Vec<ArchiveSyncPayload>,
    limits: ArchiveSyncLimits,
    budget: ArchiveRangeBudgetConfig,
    state: Mutex<ServerState>,
}

impl ArchiveRangeServerCandidate {
    pub fn new(
        index: ArchiveSyncIndex,
        mut payloads: Vec<ArchiveSyncPayload>,
        limits: ArchiveSyncLimits,
        budget: ArchiveRangeBudgetConfig,
    ) -> Result<Self, ArchiveRangeServerError> {
        limits.validate()?;
        index.check_limits(&limits)?;
        budget.validate(limits)?;
        if payloads.len() != index.len() {
            return Err(ArchiveRangeServerError::PayloadCountMismatch);
        }
        payloads.sort_unstable_by(|a, b| {
            a.meta
                .height
                .cmp(&b.meta.height)
                .then_with(|| a.meta.digest.cmp(&b.meta.digest))
        });
        let metadata = index.entries();
        for (expected, payload) in metadata.iter().zip(payloads.iter()) {
            if expected != &payload.meta {
                return Err(ArchiveRangeServerError::PayloadMetadataMismatch);
            }
            let actual_len = u64::try_from(payload.encoded.len())
                .map_err(|_| ArchiveRangeServerError::PayloadTooLarge)?;
            if actual_len != expected.encoded_len {
                return Err(ArchiveRangeServerError::PayloadLengthMismatch);
            }
            if actual_len == 0 {
                return Err(ArchiveRangeServerError::EmptyPayload);
            }
            if actual_len > limits.max_envelope_bytes {
                return Err(ArchiveRangeServerError::PayloadTooLarge);
            }
            let actual_hash: [u8; 32] = Sha256::digest(&payload.encoded).into();
            if actual_hash != expected.payload_sha256 {
                return Err(ArchiveRangeServerError::PayloadHashMismatch);
            }
        }

        // Prove that the whole immutable index can be paged within max_pages before accepting
        // sessions. This is metadata-only: no encoded payload is cloned during preflight.
        let preflight_session = [0xA5; 32];
        let preflight_key = [0x5A; 32];
        let mut page = index.first_page(limits, preflight_session, &preflight_key)?;
        while !page.complete {
            let cursor = page
                .next_cursor
                .as_ref()
                .ok_or(ArchiveRangeServerError::IncompleteArchiveIndex)?;
            page = index.continue_page(cursor, limits, preflight_session, &preflight_key)?;
        }

        Ok(Self {
            index,
            payloads,
            limits,
            budget,
            state: Mutex::new(ServerState::default()),
        })
    }

    /// Must be called only by a trusted authentication/session layer. `session_binding` should
    /// identify a stable authenticated principal/session; do not accept arbitrary values directly
    /// from unauthenticated wire input. The key must be a dedicated random 32-byte cursor MAC key.
    pub fn register_authenticated_session(
        &self,
        session_binding: [u8; 32],
        cursor_key: [u8; 32],
    ) -> Result<(), ArchiveRangeServerError> {
        if cursor_key.iter().all(|byte| *byte == 0) {
            return Err(ArchiveRangeServerError::InvalidCursorKey);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| ArchiveRangeServerError::LockPoisoned)?;
        if state.sessions.contains_key(&session_binding) {
            return Err(ArchiveRangeServerError::SessionAlreadyRegistered);
        }
        if state.sessions.len() >= self.budget.max_sessions {
            return Err(ArchiveRangeServerError::SessionTableFull);
        }
        state.sessions.insert(
            session_binding,
            SessionState {
                cursor_key,
                started: false,
                next_offset: 0,
                usage: ArchiveServeUsage::default(),
                last_request_cursor: None,
                last_response: None,
            },
        );
        Ok(())
    }

    /// Idempotently establish a session for a previously authenticated principal/snapshot.
    /// Reconnects must derive the same binding and key; a mismatching key fails closed.
    pub fn ensure_authenticated_session(
        &self,
        session_binding: [u8; 32],
        cursor_key: [u8; 32],
    ) -> Result<(), ArchiveRangeServerError> {
        if cursor_key.iter().all(|byte| *byte == 0) {
            return Err(ArchiveRangeServerError::InvalidCursorKey);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| ArchiveRangeServerError::LockPoisoned)?;
        if let Some(existing) = state.sessions.get(&session_binding) {
            return if existing.cursor_key == cursor_key {
                Ok(())
            } else {
                Err(ArchiveRangeServerError::SessionBindingMismatch)
            };
        }
        if state.sessions.len() >= self.budget.max_sessions {
            return Err(ArchiveRangeServerError::SessionTableFull);
        }
        state.sessions.insert(
            session_binding,
            SessionState {
                cursor_key,
                started: false,
                next_offset: 0,
                usage: ArchiveServeUsage::default(),
                last_request_cursor: None,
                last_response: None,
            },
        );
        Ok(())
    }

    pub fn serve_first_page(
        &self,
        session_binding: [u8; 32],
    ) -> Result<Arc<ArchiveSyncServedPage>, ArchiveRangeServerError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ArchiveRangeServerError::LockPoisoned)?;
        let (key, started, last_response, session_usage) = {
            let session = state
                .sessions
                .get(&session_binding)
                .ok_or(ArchiveRangeServerError::SessionNotRegistered)?;
            (
                session.cursor_key,
                session.started,
                session.last_response.clone(),
                session.usage,
            )
        };
        if started {
            // A reconnect without a cursor asks for the most recent cached page. This permits
            // the receiver to recover after losing a response or restarting the client. The
            // caller advances only with the authenticated next cursor from that cached page.
            let response = last_response.ok_or(ArchiveRangeServerError::ReplayRejected)?;
            let (new_global, new_session) = self.charge(
                state.global_usage,
                session_usage,
                response
                    .plan
                    .end_index
                    .saturating_sub(response.plan.start_index) as u64,
                response.plan.page_bytes,
            )?;
            state.global_usage = new_global;
            state
                .sessions
                .get_mut(&session_binding)
                .ok_or(ArchiveRangeServerError::SessionNotRegistered)?
                .usage = new_session;
            return Ok(response);
        }

        let plan = self.index.first_page(self.limits, session_binding, &key)?;
        let (new_global, new_session) = self.charge(
            state.global_usage,
            session_usage,
            plan.end_index.saturating_sub(plan.start_index) as u64,
            plan.page_bytes,
        )?;
        let response = Arc::new(self.materialize(&plan)?);
        state.global_usage = new_global;
        let session = state
            .sessions
            .get_mut(&session_binding)
            .ok_or(ArchiveRangeServerError::SessionNotRegistered)?;
        session.usage = new_session;
        session.started = true;
        session.next_offset = plan.end_index;
        session.last_request_cursor = None;
        session.last_response = Some(Arc::clone(&response));
        Ok(response)
    }

    pub fn serve_next_page(
        &self,
        session_binding: [u8; 32],
        encoded_cursor: &[u8],
    ) -> Result<Arc<ArchiveSyncServedPage>, ArchiveRangeServerError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ArchiveRangeServerError::LockPoisoned)?;
        let (key, started, next_offset, usage, last_request, last_response) = {
            let session = state
                .sessions
                .get(&session_binding)
                .ok_or(ArchiveRangeServerError::SessionNotRegistered)?;
            (
                session.cursor_key,
                session.started,
                session.next_offset,
                session.usage,
                session.last_request_cursor.clone(),
                session.last_response.clone(),
            )
        };
        if !started {
            return Err(ArchiveRangeServerError::SessionAlreadyStarted);
        }
        if last_request.as_deref() == Some(encoded_cursor) {
            let response = last_response.ok_or(ArchiveRangeServerError::ReplayRejected)?;
            let (new_global, new_session) = self.charge(
                state.global_usage,
                usage,
                response
                    .plan
                    .end_index
                    .saturating_sub(response.plan.start_index) as u64,
                response.plan.page_bytes,
            )?;
            state.global_usage = new_global;
            state
                .sessions
                .get_mut(&session_binding)
                .ok_or(ArchiveRangeServerError::SessionNotRegistered)?
                .usage = new_session;
            return Ok(response);
        }

        let plan = self
            .index
            .continue_page(encoded_cursor, self.limits, session_binding, &key)?;
        if plan.start_index != next_offset {
            return Err(ArchiveRangeServerError::ReplayRejected);
        }
        let (new_global, new_session) = self.charge(
            state.global_usage,
            usage,
            plan.end_index.saturating_sub(plan.start_index) as u64,
            plan.page_bytes,
        )?;
        let response = Arc::new(self.materialize(&plan)?);
        state.global_usage = new_global;
        let session = state
            .sessions
            .get_mut(&session_binding)
            .ok_or(ArchiveRangeServerError::SessionNotRegistered)?;
        session.usage = new_session;
        session.next_offset = plan.end_index;
        session.last_request_cursor = Some(encoded_cursor.to_vec());
        session.last_response = Some(Arc::clone(&response));
        Ok(response)
    }

    fn charge(
        &self,
        global: ArchiveServeUsage,
        session: ArchiveServeUsage,
        items: u64,
        bytes: u64,
    ) -> Result<(ArchiveServeUsage, ArchiveServeUsage), ArchiveRangeServerError> {
        let global_next = add_usage(global, items, bytes)?;
        if global_next.pages > self.budget.global_max_pages
            || global_next.items > self.budget.global_max_items
            || global_next.bytes > self.budget.global_max_bytes
        {
            return Err(ArchiveRangeServerError::GlobalQuotaExceeded);
        }
        let session_next = add_usage(session, items, bytes)?;
        if session_next.pages > self.budget.per_session_max_pages
            || session_next.items > self.budget.per_session_max_items
            || session_next.bytes > self.budget.per_session_max_bytes
        {
            return Err(ArchiveRangeServerError::SessionQuotaExceeded);
        }
        Ok((global_next, session_next))
    }

    fn materialize(
        &self,
        plan: &ArchiveSyncPage,
    ) -> Result<ArchiveSyncServedPage, ArchiveRangeServerError> {
        if plan.start_index > plan.end_index || plan.end_index > self.payloads.len() {
            return Err(ArchiveRangeServerError::PayloadCountMismatch);
        }
        let mut actual_bytes = 0u64;
        let mut entries = Vec::with_capacity(plan.end_index - plan.start_index);
        for index in plan.start_index..plan.end_index {
            let payload = self
                .payloads
                .get(index)
                .ok_or(ArchiveRangeServerError::PayloadCountMismatch)?;
            if self.index.entries().get(index) != Some(&payload.meta) {
                return Err(ArchiveRangeServerError::PayloadMetadataMismatch);
            }
            actual_bytes = actual_bytes
                .checked_add(payload.meta.encoded_len)
                .ok_or(ArchiveRangeServerError::CounterOverflow)?;
            entries.push(ArchiveSyncServedEntry {
                metadata: payload.meta.clone(),
                encoded: payload.encoded.clone(),
            });
        }
        if actual_bytes != plan.page_bytes {
            return Err(ArchiveRangeServerError::PayloadLengthMismatch);
        }
        if actual_bytes > self.limits.max_page_bytes
            || entries.len() > self.limits.max_page_items as usize
        {
            return Err(ArchiveRangeServerError::Archive(
                ArchiveSyncError::PageTooLarge,
            ));
        }
        Ok(ArchiveSyncServedPage {
            plan: plan.clone(),
            archive_total_items: self.index.len() as u64,
            archive_total_bytes: self.index.total_bytes(),
            snapshot_commitment: self.index.snapshot_commitment(),
            entries,
        })
    }

    pub fn snapshot_commitment(&self) -> [u8; 32] {
        self.index.snapshot_commitment()
    }

    pub fn global_usage(&self) -> Result<ArchiveServeUsage, ArchiveRangeServerError> {
        self.state
            .lock()
            .map(|state| state.global_usage)
            .map_err(|_| ArchiveRangeServerError::LockPoisoned)
    }

    pub fn session_usage(
        &self,
        session_binding: &[u8; 32],
    ) -> Result<ArchiveServeUsage, ArchiveRangeServerError> {
        self.state
            .lock()
            .map_err(|_| ArchiveRangeServerError::LockPoisoned)?
            .sessions
            .get(session_binding)
            .map(|session| session.usage)
            .ok_or(ArchiveRangeServerError::SessionNotRegistered)
    }

    pub fn registered_session_count(&self) -> Result<usize, ArchiveRangeServerError> {
        self.state
            .lock()
            .map(|state| state.sessions.len())
            .map_err(|_| ArchiveRangeServerError::LockPoisoned)
    }
}

fn add_usage(
    current: ArchiveServeUsage,
    items: u64,
    bytes: u64,
) -> Result<ArchiveServeUsage, ArchiveRangeServerError> {
    Ok(ArchiveServeUsage {
        pages: current
            .pages
            .checked_add(1)
            .ok_or(ArchiveRangeServerError::CounterOverflow)?,
        items: current
            .items
            .checked_add(items)
            .ok_or(ArchiveRangeServerError::CounterOverflow)?,
        bytes: current
            .bytes
            .checked_add(bytes)
            .ok_or(ArchiveRangeServerError::CounterOverflow)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> ArchiveSyncLimits {
        ArchiveSyncLimits {
            max_page_items: 2,
            max_page_bytes: 8,
            max_envelope_bytes: 8,
            max_total_items: 5,
            max_total_bytes: 32,
            max_pages: 3,
        }
    }

    fn meta(height: u64, block_digest: u8, data: &[u8]) -> ArchiveEntryMeta {
        ArchiveEntryMeta {
            height,
            digest: [block_digest; 32],
            encoded_len: data.len() as u64,
            payload_sha256: Sha256::digest(data).into(),
        }
    }

    fn make_server(
        budget: ArchiveRangeBudgetConfig,
    ) -> Result<ArchiveRangeServerCandidate, ArchiveRangeServerError> {
        make_server_with_snapshot(budget, [0xA1; 32], 44)
    }

    fn make_server_with_snapshot(
        budget: ArchiveRangeBudgetConfig,
        profile_id: [u8; 32],
        generation: u64,
    ) -> Result<ArchiveRangeServerCandidate, ArchiveRangeServerError> {
        let specs = vec![
            (2, 2, b"bbb".to_vec()),
            (1, 1, b"aaaa".to_vec()),
            (3, 3, b"ccccc".to_vec()),
            (4, 4, b"dd".to_vec()),
            (5, 5, b"e".to_vec()),
        ];
        let records = specs
            .iter()
            .map(|(height, digest, data)| meta(*height, *digest, data))
            .collect::<Vec<_>>();
        let idx = ArchiveSyncIndex::new([0xC0; 32], profile_id, generation, records, limits())?;
        let payloads = specs
            .into_iter()
            .map(|(height, digest, data)| {
                ArchiveSyncPayload::new(meta(height, digest, &data), data)
            })
            .collect::<Result<Vec<_>, _>>()?;
        ArchiveRangeServerCandidate::new(idx, payloads, limits(), budget)
    }

    fn budget() -> ArchiveRangeBudgetConfig {
        ArchiveRangeBudgetConfig {
            max_sessions: 3,
            per_session_max_pages: 3,
            per_session_max_items: 10,
            per_session_max_bytes: 32,
            global_max_pages: 8,
            global_max_items: 12,
            global_max_bytes: 64,
        }
    }

    const A: [u8; 32] = [0x11; 32];
    const B: [u8; 32] = [0x22; 32];
    const KA: [u8; 32] = [0x31; 32];
    const KB: [u8; 32] = [0x32; 32];

    #[test]
    fn serves_bounded_payload_ranges_in_metadata_order() {
        let server = make_server(budget()).unwrap();
        server.register_authenticated_session(A, KA).unwrap();
        let first = server.serve_first_page(A).unwrap();
        assert_eq!(first.entries.len(), 2);
        assert_eq!(first.entries[0].metadata.height, 1);
        assert_eq!(first.entries[0].encoded, b"aaaa");
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(&first.entries[0].encoded)),
            first.entries[0].metadata.payload_sha256
        );
        assert_eq!(first.entries[1].metadata.height, 2);
        assert_eq!(first.entries[1].encoded, b"bbb");
        assert_eq!(first.plan.page_bytes, 7);
        let cursor = first.plan.next_cursor.unwrap();
        let second = server.serve_next_page(A, &cursor).unwrap();
        assert_eq!(second.entries.len(), 2);
        assert_eq!(second.entries[0].metadata.height, 3);
        assert_eq!(second.entries[1].metadata.height, 4);
        assert!(!second.plan.complete);
        assert_eq!(second.plan.page_bytes, 7);
        let third = server
            .serve_next_page(A, &second.plan.next_cursor.unwrap())
            .unwrap();
        assert!(third.plan.complete);
        assert_eq!(third.entries.len(), 1);
        assert_eq!(third.entries[0].encoded, b"e");
        assert_eq!(third.plan.page_bytes, 1);
        assert!(third.plan.next_cursor.is_none());
    }

    #[test]
    fn rejects_payload_length_and_hash_mismatch_before_server_start() {
        let bytes = b"real bytes".to_vec();
        let wrong_len_meta = meta(1, 1, b"xxx");
        assert_eq!(
            ArchiveSyncPayload::new(wrong_len_meta, bytes.clone()).unwrap_err(),
            ArchiveRangeServerError::PayloadLengthMismatch
        );
        let mut wrong_hash_meta = meta(1, 1, &bytes);
        wrong_hash_meta.payload_sha256 = [0xEF; 32];
        assert_eq!(
            ArchiveSyncPayload::new(wrong_hash_meta, bytes).unwrap_err(),
            ArchiveRangeServerError::PayloadHashMismatch
        );
        assert_eq!(
            ArchiveSyncPayload::new(meta(1, 1, b""), Vec::new()).unwrap_err(),
            ArchiveRangeServerError::EmptyPayload
        );
    }

    #[test]
    fn rejects_reordered_metadata_substitution_even_with_same_lengths() {
        let specs = vec![(1, 1, b"aaaa".to_vec()), (2, 2, b"bbbb".to_vec())];
        let metas = specs.iter().map(|(h, d, b)| meta(*h, *d, b)).collect();
        let idx = ArchiveSyncIndex::new([1; 32], [2; 32], 9, metas, limits()).unwrap();
        let payloads = vec![
            ArchiveSyncPayload::new(meta(1, 99, b"aaaa"), b"aaaa".to_vec()).unwrap(),
            ArchiveSyncPayload::new(meta(2, 2, b"bbbb"), b"bbbb".to_vec()).unwrap(),
        ];
        assert!(matches!(
            ArchiveRangeServerCandidate::new(idx, payloads, limits(), budget()),
            Err(ArchiveRangeServerError::PayloadMetadataMismatch)
        ));
    }

    #[test]
    fn exact_last_cursor_retry_is_idempotent_in_content_but_charged_as_egress() {
        let server = make_server(budget()).unwrap();
        server.register_authenticated_session(A, KA).unwrap();
        let p1 = server.serve_first_page(A).unwrap();
        let cursor = p1.plan.next_cursor.unwrap();
        let p2 = server.serve_next_page(A, &cursor).unwrap();
        let once = server.global_usage().unwrap();
        let replay = server.serve_next_page(A, &cursor).unwrap();
        assert!(Arc::ptr_eq(&p2, &replay));
        assert_eq!(p2, replay);
        let twice = server.global_usage().unwrap();
        assert_eq!(twice.pages, once.pages + 1);
        assert_eq!(twice.bytes, once.bytes + p2.plan.page_bytes);
        assert_eq!(twice.items, once.items + p2.entries.len() as u64);
    }

    #[test]
    fn reconnect_without_cursor_replays_last_page_but_old_cursor_is_rejected() {
        let mut cfg = budget();
        cfg.per_session_max_pages = 4;
        let server = make_server(cfg).unwrap();
        server.register_authenticated_session(A, KA).unwrap();
        let p1 = server.serve_first_page(A).unwrap();
        let c1 = p1.plan.next_cursor.unwrap();
        let p2 = server.serve_next_page(A, &c1).unwrap();
        let c2 = p2.plan.next_cursor.unwrap();
        let p3 = server.serve_next_page(A, &c2).unwrap();
        assert!(p3.plan.complete);
        assert_eq!(
            server.serve_next_page(A, &c1).unwrap_err(),
            ArchiveRangeServerError::ReplayRejected
        );
        let replay = server.serve_first_page(A).unwrap();
        assert!(Arc::ptr_eq(&p3, &replay));
        assert_eq!(p3, replay);
        assert_eq!(server.session_usage(&A).unwrap().pages, 4);
    }

    #[test]
    fn per_session_quota_rejects_without_partial_global_or_session_debit() {
        let mut cfg = budget();
        cfg.per_session_max_bytes = 8;
        cfg.global_max_bytes = 32;
        let server = make_server(cfg).unwrap();
        server.register_authenticated_session(A, KA).unwrap();
        let first = server.serve_first_page(A).unwrap();
        assert_eq!(first.plan.page_bytes, 7);
        let before_global = server.global_usage().unwrap();
        let before_session = server.session_usage(&A).unwrap();
        let cursor = first.plan.next_cursor.unwrap();
        assert_eq!(
            server.serve_next_page(A, &cursor).unwrap_err(),
            ArchiveRangeServerError::SessionQuotaExceeded
        );
        assert_eq!(server.global_usage().unwrap(), before_global);
        assert_eq!(server.session_usage(&A).unwrap(), before_session);
    }

    #[test]
    fn aggregate_global_quota_is_shared_between_registered_sessions() {
        let mut cfg = budget();
        cfg.per_session_max_bytes = 8;
        cfg.global_max_bytes = 13;
        let server = make_server(cfg).unwrap();
        server.register_authenticated_session(A, KA).unwrap();
        server.register_authenticated_session(B, KB).unwrap();
        server.serve_first_page(A).unwrap();
        let before = server.global_usage().unwrap();
        assert_eq!(
            server.serve_first_page(B).unwrap_err(),
            ArchiveRangeServerError::GlobalQuotaExceeded
        );
        assert_eq!(server.global_usage().unwrap(), before);
        assert_eq!(
            server.session_usage(&B).unwrap(),
            ArchiveServeUsage::default()
        );
    }

    #[test]
    fn authentication_layer_must_register_bounded_sessions() {
        let mut cfg = budget();
        cfg.max_sessions = 1;
        let server = make_server(cfg).unwrap();
        assert_eq!(
            server.serve_first_page(A).unwrap_err(),
            ArchiveRangeServerError::SessionNotRegistered
        );
        assert_eq!(
            server
                .register_authenticated_session(A, [0; 32])
                .unwrap_err(),
            ArchiveRangeServerError::InvalidCursorKey
        );
        server.register_authenticated_session(A, KA).unwrap();
        assert_eq!(
            server.register_authenticated_session(A, KA).unwrap_err(),
            ArchiveRangeServerError::SessionAlreadyRegistered
        );
        assert_eq!(
            server.register_authenticated_session(B, KB).unwrap_err(),
            ArchiveRangeServerError::SessionTableFull
        );
        assert_eq!(server.registered_session_count().unwrap(), 1);
    }

    #[test]
    fn reconnect_session_registration_is_idempotent_and_key_bound() {
        let server = make_server(budget()).unwrap();
        server.ensure_authenticated_session(A, KA).unwrap();
        let first = server.serve_first_page(A).unwrap();
        server.ensure_authenticated_session(A, KA).unwrap();
        assert_eq!(server.registered_session_count().unwrap(), 1);
        assert_eq!(
            server.ensure_authenticated_session(A, KB).unwrap_err(),
            ArchiveRangeServerError::SessionBindingMismatch
        );
        let next = server
            .serve_next_page(A, &first.plan.next_cursor.unwrap())
            .unwrap();
        assert_eq!(next.plan.start_index, first.plan.end_index);
    }

    #[test]
    fn old_snapshot_cursor_mac_mismatch_in_active_session_is_rejected_without_quota_debit() {
        let old_server = make_server_with_snapshot(budget(), [0xA1; 32], 44).unwrap();
        let new_server = make_server_with_snapshot(budget(), [0xA2; 32], 45).unwrap();
        assert_ne!(
            old_server.snapshot_commitment(),
            new_server.snapshot_commitment()
        );

        // Both sessions are registered and actively started. The old continuation is signed
        // with the old snapshot-derived key, while the active server session uses the new key.
        old_server.register_authenticated_session(A, KA).unwrap();
        new_server.register_authenticated_session(A, KB).unwrap();
        let old_first = old_server.serve_first_page(A).unwrap();
        let old_cursor = old_first.plan.next_cursor.unwrap();
        let new_first = new_server.serve_first_page(A).unwrap();
        assert!(new_first.plan.next_cursor.is_some());

        let global_before = new_server.global_usage().unwrap();
        let session_before = new_server.session_usage(&A).unwrap();
        assert_eq!(
            new_server.serve_next_page(A, &old_cursor).unwrap_err(),
            ArchiveRangeServerError::Archive(ArchiveSyncError::CursorAuthenticationFailed)
        );
        assert_eq!(new_server.global_usage().unwrap(), global_before);
        assert_eq!(new_server.session_usage(&A).unwrap(), session_before);
        assert_eq!(new_server.session_usage(&A).unwrap().pages, 1);
    }

    #[test]
    fn malformed_or_wrong_session_cursor_cannot_advance_a_session() {
        let server = make_server(budget()).unwrap();
        server.register_authenticated_session(A, KA).unwrap();
        server.register_authenticated_session(B, KB).unwrap();
        let p1 = server.serve_first_page(A).unwrap();
        let c1 = p1.plan.next_cursor.unwrap();
        server.serve_first_page(B).unwrap();
        let b_usage_before = server.session_usage(&B).unwrap();
        assert!(matches!(
            server.serve_next_page(B, &c1),
            Err(ArchiveRangeServerError::Archive(
                ArchiveSyncError::CursorAuthenticationFailed
            )) | Err(ArchiveRangeServerError::Archive(
                ArchiveSyncError::WrongSession
            ))
        ));
        assert_eq!(server.session_usage(&A).unwrap().pages, 1);
        assert_eq!(server.session_usage(&B).unwrap(), b_usage_before);
        let mut damaged = c1;
        damaged[17] ^= 0x40;
        assert!(matches!(
            server.serve_next_page(A, &damaged),
            Err(ArchiveRangeServerError::Archive(
                ArchiveSyncError::CursorAuthenticationFailed
            ))
        ));
        assert_eq!(server.session_usage(&A).unwrap().pages, 1);
    }

    #[test]
    fn rejects_budget_configuration_above_candidate_hard_ceilings() {
        let mut cfg = budget();
        cfg.max_sessions = MAX_CANDIDATE_SERVING_SESSIONS + 1;
        assert!(cfg.validate(limits()).is_err());
        let mut cfg = budget();
        cfg.global_max_items = MAX_CANDIDATE_GLOBAL_SERVE_ITEMS + 1;
        assert!(cfg.validate(limits()).is_err());
    }

    #[test]
    fn concurrent_sessions_cannot_overspend_shared_global_byte_budget() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let mut cfg = budget();
        cfg.per_session_max_pages = 3;
        cfg.per_session_max_items = 5;
        cfg.per_session_max_bytes = 7;
        cfg.global_max_pages = 3;
        cfg.global_max_items = 5;
        cfg.global_max_bytes = 7;
        cfg.max_sessions = 2;
        let server = Arc::new(make_server(cfg).unwrap());
        server.register_authenticated_session(A, KA).unwrap();
        server.register_authenticated_session(B, KB).unwrap();
        let barrier = Arc::new(Barrier::new(3));
        let mut handles = Vec::new();
        for id in [A, B] {
            let server = Arc::clone(&server);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                server.serve_first_page(id)
            }));
        }
        barrier.wait();
        let outcomes = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            outcomes
                .iter()
                .filter(|result| **result == Err(ArchiveRangeServerError::GlobalQuotaExceeded))
                .count(),
            1
        );
        let usage = server.global_usage().unwrap();
        assert_eq!((usage.pages, usage.items, usage.bytes), (1, 2, 7));
        let a_usage = server.session_usage(&A).unwrap();
        let b_usage = server.session_usage(&B).unwrap();
        assert_eq!(a_usage.pages + b_usage.pages, 1);
        assert_eq!(a_usage.bytes + b_usage.bytes, 7);
    }
}
