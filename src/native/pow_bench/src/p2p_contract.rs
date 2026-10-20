//! Base P2P control-contract primitives for the current testnet profile.
//! This module intentionally freezes only the schemas and lifecycle rules that
//! have deterministic tests; broader application schemas remain provisional.

use crate::protocol_profile::{
    CAPS_COUNT_LEN, CAPS_ENTRY_LEN, ERROR_PAYLOAD_LEN, MAX_CAPABILITIES_TESTNET,
    MAX_OUTSTANDING_REQUEST_BYTES_TESTNET, MAX_REQUESTS_PER_PEER_TESTNET, PING_PAYLOAD_LEN,
    PONG_PAYLOAD_LEN,
};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum Capability {
    ChainHeaders = 1,
    Blocks = 2,
    TxRelay = 3,
    AddrRelay = 4,
    IdentityAware = 5,
}

impl Capability {
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::ChainHeaders),
            2 => Some(Self::Blocks),
            3 => Some(Self::TxRelay),
            4 => Some(Self::AddrRelay),
            5 => Some(Self::IdentityAware),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ErrorCode {
    BadRequest = 1,
    UnsupportedVersion = 2,
    UnsupportedType = 3,
    InvalidPayload = 4,
    DuplicateRequest = 5,
    LateResponse = 6,
    CapabilityMalformed = 7,
    ResourceLimit = 8,
}

impl ErrorCode {
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::BadRequest),
            2 => Some(Self::UnsupportedVersion),
            3 => Some(Self::UnsupportedType),
            4 => Some(Self::InvalidPayload),
            5 => Some(Self::DuplicateRequest),
            6 => Some(Self::LateResponse),
            7 => Some(Self::CapabilityMalformed),
            8 => Some(Self::ResourceLimit),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlContractError {
    WrongLength { expected: usize, actual: usize },
    CountTooLarge { declared: usize, limit: usize },
    UnknownCapability(u16),
    DuplicateCapability(u16),
    NonCanonicalCapabilities,
    UnknownErrorCode(u16),
    InvalidOffendingType,
    PongNonceMismatch { expected: u64, actual: u64 },
    WrongResponseType { expected: u16, actual: u16 },
    ResponseTooLarge { received: usize, limit: usize },
    ZeroRequestId,
    DuplicateRequest,
    UnknownRequest,
    LateResponse,
    RequestLimit,
    OutstandingBytesLimit,
}

pub fn encode_ping(nonce: u64) -> [u8; PING_PAYLOAD_LEN] {
    nonce.to_be_bytes()
}

pub fn decode_ping(payload: &[u8]) -> Result<u64, ControlContractError> {
    if payload.len() != PING_PAYLOAD_LEN {
        return Err(ControlContractError::WrongLength {
            expected: PING_PAYLOAD_LEN,
            actual: payload.len(),
        });
    }
    Ok(u64::from_be_bytes(payload.try_into().unwrap()))
}

pub fn encode_pong(nonce: u64) -> [u8; PONG_PAYLOAD_LEN] {
    nonce.to_be_bytes()
}

pub fn decode_pong(payload: &[u8]) -> Result<u64, ControlContractError> {
    if payload.len() != PONG_PAYLOAD_LEN {
        return Err(ControlContractError::WrongLength {
            expected: PONG_PAYLOAD_LEN,
            actual: payload.len(),
        });
    }
    Ok(u64::from_be_bytes(payload.try_into().unwrap()))
}

pub fn verify_pong_echo(expected_nonce: u64, payload: &[u8]) -> Result<(), ControlContractError> {
    let actual = decode_pong(payload)?;
    if actual != expected_nonce {
        return Err(ControlContractError::PongNonceMismatch {
            expected: expected_nonce,
            actual,
        });
    }
    Ok(())
}

pub fn encode_capabilities(capabilities: &[Capability]) -> Result<Vec<u8>, ControlContractError> {
    if capabilities.len() > MAX_CAPABILITIES_TESTNET {
        return Err(ControlContractError::CountTooLarge {
            declared: capabilities.len(),
            limit: MAX_CAPABILITIES_TESTNET,
        });
    }

    let mut ids: Vec<u16> = capabilities.iter().map(|x| *x as u16).collect();
    let mut canonical = ids.clone();
    canonical.sort_unstable();
    canonical.dedup();

    if canonical.len() != ids.len() {
        return Err(ControlContractError::NonCanonicalCapabilities);
    }
    if canonical != ids {
        return Err(ControlContractError::NonCanonicalCapabilities);
    }

    let mut out = Vec::with_capacity(CAPS_COUNT_LEN + ids.len() * CAPS_ENTRY_LEN);
    out.extend_from_slice(&(ids.len() as u16).to_be_bytes());
    for id in ids.drain(..) {
        out.extend_from_slice(&id.to_be_bytes());
    }
    Ok(out)
}

pub fn decode_capabilities(payload: &[u8]) -> Result<Vec<Capability>, ControlContractError> {
    if payload.len() < CAPS_COUNT_LEN {
        return Err(ControlContractError::WrongLength {
            expected: CAPS_COUNT_LEN,
            actual: payload.len(),
        });
    }

    let count = u16::from_be_bytes([payload[0], payload[1]]) as usize;
    if count > MAX_CAPABILITIES_TESTNET {
        return Err(ControlContractError::CountTooLarge {
            declared: count,
            limit: MAX_CAPABILITIES_TESTNET,
        });
    }

    let expected = CAPS_COUNT_LEN + count * CAPS_ENTRY_LEN;
    if payload.len() != expected {
        return Err(ControlContractError::WrongLength {
            expected,
            actual: payload.len(),
        });
    }

    let mut out = Vec::with_capacity(count);
    let mut previous = None;
    for i in 0..count {
        let offset = CAPS_COUNT_LEN + i * CAPS_ENTRY_LEN;
        let id = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        let cap = Capability::from_u16(id).ok_or(ControlContractError::UnknownCapability(id))?;
        if let Some(p) = previous {
            if p == id {
                return Err(ControlContractError::DuplicateCapability(id));
            }
            if p > id {
                return Err(ControlContractError::NonCanonicalCapabilities);
            }
        }
        previous = Some(id);
        out.push(cap);
    }
    Ok(out)
}

pub fn encode_error(
    code: ErrorCode,
    offending_type: u16,
) -> Result<[u8; ERROR_PAYLOAD_LEN], ControlContractError> {
    if offending_type == 0 {
        return Err(ControlContractError::InvalidOffendingType);
    }
    let mut out = [0u8; ERROR_PAYLOAD_LEN];
    out[..2].copy_from_slice(&(code as u16).to_be_bytes());
    out[2..].copy_from_slice(&offending_type.to_be_bytes());
    Ok(out)
}

pub fn decode_error(payload: &[u8]) -> Result<(ErrorCode, u16), ControlContractError> {
    if payload.len() != ERROR_PAYLOAD_LEN {
        return Err(ControlContractError::WrongLength {
            expected: ERROR_PAYLOAD_LEN,
            actual: payload.len(),
        });
    }
    let code = u16::from_be_bytes([payload[0], payload[1]]);
    let error = ErrorCode::from_u16(code).ok_or(ControlContractError::UnknownErrorCode(code))?;
    let offending_type = u16::from_be_bytes([payload[2], payload[3]]);
    if offending_type == 0 {
        return Err(ControlContractError::InvalidOffendingType);
    }
    Ok((error, offending_type))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestEntry {
    pub request_id: u64,
    pub expected_response_type: u16,
    pub deadline_ms: u64,
    pub max_response_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct RequestTracker {
    entries: BTreeMap<u64, RequestEntry>,
    outstanding_bytes: usize,
    max_requests: usize,
    max_outstanding_bytes: usize,
}

impl RequestTracker {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            outstanding_bytes: 0,
            max_requests: MAX_REQUESTS_PER_PEER_TESTNET,
            max_outstanding_bytes: MAX_OUTSTANDING_REQUEST_BYTES_TESTNET,
        }
    }

    pub fn open(
        &mut self,
        request_id: u64,
        expected_response_type: u16,
        deadline_ms: u64,
        max_response_bytes: usize,
    ) -> Result<(), ControlContractError> {
        if request_id == 0 {
            return Err(ControlContractError::ZeroRequestId);
        }
        if self.entries.contains_key(&request_id) {
            return Err(ControlContractError::DuplicateRequest);
        }
        if self.entries.len() >= self.max_requests {
            return Err(ControlContractError::RequestLimit);
        }
        let next = self
            .outstanding_bytes
            .checked_add(max_response_bytes)
            .ok_or(ControlContractError::OutstandingBytesLimit)?;
        if next > self.max_outstanding_bytes {
            return Err(ControlContractError::OutstandingBytesLimit);
        }
        self.entries.insert(
            request_id,
            RequestEntry {
                request_id,
                expected_response_type,
                deadline_ms,
                max_response_bytes,
            },
        );
        self.outstanding_bytes = next;
        Ok(())
    }

    pub fn complete(
        &mut self,
        request_id: u64,
        response_type: u16,
        response_bytes: usize,
        now_ms: u64,
    ) -> Result<RequestEntry, ControlContractError> {
        let Some(entry) = self.entries.get(&request_id).copied() else {
            return Err(ControlContractError::UnknownRequest);
        };
        if now_ms > entry.deadline_ms {
            self.remove(request_id);
            return Err(ControlContractError::LateResponse);
        }
        if response_type != entry.expected_response_type {
            return Err(ControlContractError::WrongResponseType {
                expected: entry.expected_response_type,
                actual: response_type,
            });
        }
        if response_bytes > entry.max_response_bytes {
            self.remove(request_id);
            return Err(ControlContractError::ResponseTooLarge {
                received: response_bytes,
                limit: entry.max_response_bytes,
            });
        }
        self.remove(request_id);
        Ok(entry)
    }

    /// Completes a tracked request with a terminal ERROR response.
    /// The caller validates the fixed ERROR payload and its offending-type field.
    pub fn complete_error(
        &mut self,
        request_id: u64,
        response_bytes: usize,
        now_ms: u64,
    ) -> Result<RequestEntry, ControlContractError> {
        let Some(entry) = self.entries.get(&request_id).copied() else {
            return Err(ControlContractError::UnknownRequest);
        };
        if now_ms > entry.deadline_ms {
            self.remove(request_id);
            return Err(ControlContractError::LateResponse);
        }
        if response_bytes > entry.max_response_bytes {
            self.remove(request_id);
            return Err(ControlContractError::ResponseTooLarge {
                received: response_bytes,
                limit: entry.max_response_bytes,
            });
        }
        self.remove(request_id);
        Ok(entry)
    }

    pub fn expire(&mut self, now_ms: u64) -> usize {
        let expired: Vec<u64> = self
            .entries
            .iter()
            .filter_map(|(id, entry)| (now_ms > entry.deadline_ms).then_some(*id))
            .collect();
        let count = expired.len();
        for id in expired {
            self.remove(id);
        }
        count
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn outstanding_bytes(&self) -> usize {
        self.outstanding_bytes
    }

    fn remove(&mut self, request_id: u64) {
        if let Some(entry) = self.entries.remove(&request_id) {
            self.outstanding_bytes = self
                .outstanding_bytes
                .saturating_sub(entry.max_response_bytes);
        }
    }
}

impl Default for RequestTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessBudgetError {
    SessionLimit,
    OutstandingBytesLimit,
    ArithmeticOverflow,
    Poisoned,
}

#[derive(Debug, Default)]
struct ProcessBudgetState {
    active_sessions: usize,
    reserved_bytes: usize,
}

struct ProcessBudgetInner {
    max_sessions: usize,
    max_reserved_bytes: usize,
    state: Mutex<ProcessBudgetState>,
}

/// Shared process-wide budget. Each accepted session owns a guard; reserved
/// response bytes remain charged across concurrent connections until released
/// or the guard is dropped.
#[derive(Clone)]
pub struct ProcessResourceBudget {
    inner: Arc<ProcessBudgetInner>,
}

impl ProcessResourceBudget {
    pub fn new(max_sessions: usize, max_reserved_bytes: usize) -> Self {
        Self {
            inner: Arc::new(ProcessBudgetInner {
                max_sessions,
                max_reserved_bytes,
                state: Mutex::new(ProcessBudgetState::default()),
            }),
        }
    }

    pub fn acquire_session(&self) -> Result<ProcessSessionGuard, ProcessBudgetError> {
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| ProcessBudgetError::Poisoned)?;
        if state.active_sessions >= self.inner.max_sessions {
            return Err(ProcessBudgetError::SessionLimit);
        }
        state.active_sessions += 1;
        Ok(ProcessSessionGuard {
            inner: Arc::clone(&self.inner),
            reserved_bytes: 0,
        })
    }

    pub fn active_sessions(&self) -> Result<usize, ProcessBudgetError> {
        self.inner
            .state
            .lock()
            .map(|state| state.active_sessions)
            .map_err(|_| ProcessBudgetError::Poisoned)
    }

    pub fn reserved_bytes(&self) -> Result<usize, ProcessBudgetError> {
        self.inner
            .state
            .lock()
            .map(|state| state.reserved_bytes)
            .map_err(|_| ProcessBudgetError::Poisoned)
    }
}

pub struct ProcessSessionGuard {
    inner: Arc<ProcessBudgetInner>,
    reserved_bytes: usize,
}

impl ProcessSessionGuard {
    pub fn reserve_bytes(&mut self, bytes: usize) -> Result<(), ProcessBudgetError> {
        let session_total = self
            .reserved_bytes
            .checked_add(bytes)
            .ok_or(ProcessBudgetError::ArithmeticOverflow)?;
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| ProcessBudgetError::Poisoned)?;
        let process_total = state
            .reserved_bytes
            .checked_add(bytes)
            .ok_or(ProcessBudgetError::ArithmeticOverflow)?;
        if process_total > self.inner.max_reserved_bytes {
            return Err(ProcessBudgetError::OutstandingBytesLimit);
        }
        state.reserved_bytes = process_total;
        self.reserved_bytes = session_total;
        Ok(())
    }

    pub fn release_bytes(&mut self, bytes: usize) -> Result<(), ProcessBudgetError> {
        if bytes > self.reserved_bytes {
            return Err(ProcessBudgetError::ArithmeticOverflow);
        }
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| ProcessBudgetError::Poisoned)?;
        if bytes > state.reserved_bytes {
            return Err(ProcessBudgetError::ArithmeticOverflow);
        }
        self.reserved_bytes -= bytes;
        state.reserved_bytes -= bytes;
        Ok(())
    }

    pub fn reserved_bytes(&self) -> usize {
        self.reserved_bytes
    }
}

impl Drop for ProcessSessionGuard {
    fn drop(&mut self) {
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.active_sessions = state.active_sessions.saturating_sub(1);
        state.reserved_bytes = state.reserved_bytes.saturating_sub(self.reserved_bytes);
        self.reserved_bytes = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol_profile::{CAPS_TYPE, PING_TYPE, PONG_TYPE};

    #[test]
    fn process_budget_caps_sessions_and_releases_on_guard_drop() {
        let budget = ProcessResourceBudget::new(1, 100);
        let guard = budget.acquire_session().unwrap();
        assert_eq!(budget.active_sessions().unwrap(), 1);
        assert_eq!(
            budget.acquire_session().err(),
            Some(ProcessBudgetError::SessionLimit)
        );
        drop(guard);
        assert_eq!(budget.active_sessions().unwrap(), 0);
        assert!(budget.acquire_session().is_ok());
    }

    #[test]
    fn process_budget_accounts_bytes_across_sessions_atomically() {
        let budget = ProcessResourceBudget::new(3, 100);
        let mut first = budget.acquire_session().unwrap();
        let mut second = budget.acquire_session().unwrap();
        let mut third = budget.acquire_session().unwrap();

        first.reserve_bytes(60).unwrap();
        second.reserve_bytes(40).unwrap();
        assert_eq!(budget.reserved_bytes().unwrap(), 100);
        assert_eq!(
            third.reserve_bytes(1),
            Err(ProcessBudgetError::OutstandingBytesLimit)
        );
        assert_eq!(third.reserved_bytes(), 0);
        assert_eq!(budget.reserved_bytes().unwrap(), 100);

        second.release_bytes(40).unwrap();
        third.reserve_bytes(40).unwrap();
        assert_eq!(budget.reserved_bytes().unwrap(), 100);
        drop(first);
        assert_eq!(budget.reserved_bytes().unwrap(), 40);
        drop(second);
        assert_eq!(budget.active_sessions().unwrap(), 1);
        drop(third);
        assert_eq!(budget.active_sessions().unwrap(), 0);
        assert_eq!(budget.reserved_bytes().unwrap(), 0);
    }

    #[test]
    fn ping_pong_are_fixed_big_endian_values() {
        let p = encode_ping(0x0102_0304_0506_0708);
        assert_eq!(p, [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(decode_ping(&p).unwrap(), 0x0102_0304_0506_0708);
        assert_eq!(decode_pong(&encode_pong(9)).unwrap(), 9);
        assert_eq!(verify_pong_echo(9, &encode_pong(9)), Ok(()));
        assert_eq!(
            verify_pong_echo(9, &encode_pong(10)),
            Err(ControlContractError::PongNonceMismatch {
                expected: 9,
                actual: 10
            })
        );
        assert_eq!(
            decode_ping(&[0u8; 7]),
            Err(ControlContractError::WrongLength {
                expected: 8,
                actual: 7
            })
        );
    }

    #[test]
    fn capabilities_are_canonical_bounded_and_roundtrip() {
        let bytes = encode_capabilities(&[
            Capability::ChainHeaders,
            Capability::Blocks,
            Capability::IdentityAware,
        ])
        .unwrap();
        assert_eq!(bytes, [0, 3, 0, 1, 0, 2, 0, 5]);
        assert_eq!(
            decode_capabilities(&bytes).unwrap(),
            vec![
                Capability::ChainHeaders,
                Capability::Blocks,
                Capability::IdentityAware
            ]
        );
        assert_eq!(
            encode_capabilities(&[Capability::Blocks, Capability::ChainHeaders]),
            Err(ControlContractError::NonCanonicalCapabilities)
        );
        assert_eq!(
            decode_capabilities(&[0, 2, 0, 1, 0, 1]),
            Err(ControlContractError::DuplicateCapability(1))
        );
        assert_eq!(
            decode_capabilities(&[0, 1, 0, 9]),
            Err(ControlContractError::UnknownCapability(9))
        );
    }

    #[test]
    fn error_registry_is_fixed_width_and_bounded() {
        let bytes = encode_error(ErrorCode::LateResponse, PING_TYPE).unwrap();
        assert_eq!(bytes, [0, 6, 0, 2]);
        assert_eq!(
            encode_error(ErrorCode::LateResponse, 0),
            Err(ControlContractError::InvalidOffendingType)
        );
        assert_eq!(
            decode_error(&bytes).unwrap(),
            (ErrorCode::LateResponse, PING_TYPE)
        );
        assert_eq!(
            decode_error(&[0, 9, 0, 2]),
            Err(ControlContractError::UnknownErrorCode(9))
        );
        assert_eq!(
            decode_error(&[0, 6, 0, 0]),
            Err(ControlContractError::InvalidOffendingType)
        );
    }

    #[test]
    fn request_tracker_rejects_duplicates_and_late_responses() {
        let mut tracker = RequestTracker::new();
        tracker.open(7, PONG_TYPE, 100, 8).unwrap();
        assert_eq!(
            tracker.open(7, PONG_TYPE, 100, 8),
            Err(ControlContractError::DuplicateRequest)
        );
        assert_eq!(tracker.len(), 1);
        assert_eq!(
            tracker.complete(7, PONG_TYPE, 8, 101),
            Err(ControlContractError::LateResponse)
        );
        assert_eq!(tracker.len(), 0);
        assert_eq!(
            tracker.complete(7, PONG_TYPE, 8, 101),
            Err(ControlContractError::UnknownRequest)
        );
    }

    #[test]
    fn request_tracker_enforces_count_and_bytes() {
        let mut tracker = RequestTracker::new();
        for id in 1..=MAX_REQUESTS_PER_PEER_TESTNET as u64 {
            tracker.open(id, PONG_TYPE, 1000, 1024).unwrap();
        }
        assert_eq!(
            tracker.open(
                MAX_REQUESTS_PER_PEER_TESTNET as u64 + 1,
                PONG_TYPE,
                1000,
                1024
            ),
            Err(ControlContractError::RequestLimit)
        );
        assert_eq!(
            tracker.outstanding_bytes(),
            MAX_REQUESTS_PER_PEER_TESTNET * 1024
        );
    }

    #[test]
    fn request_tracker_enforces_aggregate_outstanding_byte_budget() {
        let mut tracker = RequestTracker::new();
        let max_frame_reservation = MAX_OUTSTANDING_REQUEST_BYTES_TESTNET / 2;
        tracker
            .open(1, PONG_TYPE, 100, max_frame_reservation)
            .unwrap();
        tracker
            .open(2, PONG_TYPE, 100, max_frame_reservation)
            .unwrap();
        assert_eq!(tracker.len(), 2);
        assert_eq!(
            tracker.outstanding_bytes(),
            MAX_OUTSTANDING_REQUEST_BYTES_TESTNET
        );
        assert_eq!(
            tracker.open(3, PONG_TYPE, 100, 1),
            Err(ControlContractError::OutstandingBytesLimit)
        );
        assert_eq!(tracker.len(), 2);
        assert_eq!(
            tracker.outstanding_bytes(),
            MAX_OUTSTANDING_REQUEST_BYTES_TESTNET
        );
    }

    #[test]
    fn request_tracker_supports_multiple_outstanding_out_of_order_completions() {
        let mut tracker = RequestTracker::new();
        tracker
            .open(101, crate::protocol_profile::HEADERS_TYPE, 800, 1602)
            .unwrap();
        tracker
            .open(102, crate::protocol_profile::HEADERS_TYPE, 800, 1602)
            .unwrap();
        assert_eq!(tracker.len(), 2);
        assert_eq!(tracker.outstanding_bytes(), 3204);

        let second = tracker
            .complete(102, crate::protocol_profile::HEADERS_TYPE, 102, 25)
            .unwrap();
        assert_eq!(second.request_id, 102);
        assert_eq!(tracker.len(), 1);
        assert_eq!(tracker.outstanding_bytes(), 1602);

        let first = tracker
            .complete(101, crate::protocol_profile::HEADERS_TYPE, 102, 30)
            .unwrap();
        assert_eq!(first.request_id, 101);
        assert_eq!(tracker.len(), 0);
        assert_eq!(tracker.outstanding_bytes(), 0);
    }

    #[test]
    fn request_tracker_batch_rejection_keeps_existing_reservations_atomic() {
        let mut tracker = RequestTracker::new();
        for id in 1..=MAX_REQUESTS_PER_PEER_TESTNET as u64 {
            tracker
                .open(id, crate::protocol_profile::HEADERS_TYPE, 800, 1602)
                .unwrap();
        }
        assert_eq!(
            tracker.open(
                MAX_REQUESTS_PER_PEER_TESTNET as u64 + 1,
                crate::protocol_profile::HEADERS_TYPE,
                800,
                1602
            ),
            Err(ControlContractError::RequestLimit)
        );
        assert_eq!(tracker.len(), MAX_REQUESTS_PER_PEER_TESTNET);
        assert_eq!(
            tracker.outstanding_bytes(),
            MAX_REQUESTS_PER_PEER_TESTNET * 1602
        );
        assert_eq!(tracker.expire(801), MAX_REQUESTS_PER_PEER_TESTNET);
        assert_eq!(tracker.len(), 0);
        assert_eq!(tracker.outstanding_bytes(), 0);
    }

    #[test]
    fn request_tracker_completes_bounded_error_response_and_releases_budget() {
        let mut tracker = RequestTracker::new();
        tracker
            .open(41, crate::protocol_profile::CAPS_TYPE, 100, 66)
            .unwrap();
        assert_eq!(tracker.outstanding_bytes(), 66);
        let entry = tracker.complete_error(41, ERROR_PAYLOAD_LEN, 25).unwrap();
        assert_eq!(entry.request_id, 41);
        assert_eq!(
            entry.expected_response_type,
            crate::protocol_profile::CAPS_TYPE
        );
        assert_eq!(tracker.len(), 0);
        assert_eq!(tracker.outstanding_bytes(), 0);
    }

    #[test]
    fn request_tracker_rejects_late_error_response_and_releases_budget() {
        let mut tracker = RequestTracker::new();
        tracker
            .open(42, crate::protocol_profile::CAPS_TYPE, 100, 66)
            .unwrap();
        assert_eq!(
            tracker.complete_error(42, ERROR_PAYLOAD_LEN, 101),
            Err(ControlContractError::LateResponse)
        );
        assert_eq!(tracker.len(), 0);
        assert_eq!(tracker.outstanding_bytes(), 0);
    }

    #[test]
    fn request_tracker_rejects_oversized_response_and_releases_budget() {
        let mut tracker = RequestTracker::new();
        tracker.open(8, PONG_TYPE, 100, 8).unwrap();
        assert_eq!(
            tracker.complete(8, PONG_TYPE, 9, 10),
            Err(ControlContractError::ResponseTooLarge {
                received: 9,
                limit: 8
            })
        );
        assert_eq!(tracker.len(), 0);
        assert_eq!(tracker.outstanding_bytes(), 0);
    }

    #[test]
    fn request_tracker_rejects_wrong_response_type_and_expiry() {
        let mut tracker = RequestTracker::new();
        tracker.open(3, PONG_TYPE, 10, 64).unwrap();
        assert_eq!(
            tracker.complete(3, CAPS_TYPE, 8, 9),
            Err(ControlContractError::WrongResponseType {
                expected: PONG_TYPE,
                actual: CAPS_TYPE
            })
        );
        assert_eq!(tracker.len(), 1);
        assert_eq!(tracker.expire(11), 1);
        assert_eq!(tracker.len(), 0);
        assert_eq!(tracker.outstanding_bytes(), 0);
    }

    #[test]
    fn shared_request_lifecycle_vectors_match_current_contract() {
        fn run(operations: &str) -> bool {
            let mut tracker = RequestTracker::new();
            for operation in operations.split(';') {
                let mut parts = operation.split(',');
                let Some(op) = parts.next() else {
                    return false;
                };
                let values: Result<Vec<u64>, _> = parts.map(str::parse::<u64>).collect();
                let Ok(v) = values else {
                    return false;
                };
                let result_ok = match (op, v.as_slice()) {
                    ("open", [id, expected, deadline, max_bytes]) => tracker
                        .open(*id, *expected as u16, *deadline, *max_bytes as usize)
                        .is_ok(),
                    ("complete", [id, response, response_bytes, now]) => tracker
                        .complete(*id, *response as u16, *response_bytes as usize, *now)
                        .is_ok(),
                    ("expire", [now]) => {
                        tracker.expire(*now);
                        true
                    }
                    _ => false,
                };
                if !result_ok {
                    return false;
                }
            }
            true
        }

        for line in
            include_str!("../../../../simulations/cp0025n_request_lifecycle_vectors.txt").lines()
        {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split('|');
            let name = parts.next().unwrap();
            let operations = parts.next().unwrap();
            let expected = parts.next().unwrap();
            assert_eq!(run(operations), expected == "accept", "vector={name}");
        }
    }

    #[test]
    fn shared_control_vectors_match_current_contract() {
        fn accepts(wire: &[u8]) -> bool {
            let Ok(frame) = crate::decode_frame(wire) else {
                return false;
            };
            if frame.request_id == 0 {
                return false;
            }
            match frame.message_type {
                PING_TYPE => decode_ping(&frame.payload).is_ok(),
                PONG_TYPE => decode_pong(&frame.payload).is_ok(),
                CAPS_TYPE => decode_capabilities(&frame.payload).is_ok(),
                crate::protocol_profile::ERROR_TYPE => decode_error(&frame.payload).is_ok(),
                _ => false,
            }
        }

        for line in
            include_str!("../../../../simulations/cp0025n_control_contract_vectors.txt").lines()
        {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split('|');
            let _name = parts.next().unwrap();
            let kind = parts.next().unwrap();
            let wire = parts.next().unwrap();
            let expected = parts.next().unwrap();
            assert_eq!(kind, "frame");
            let bytes: Vec<u8> = (0..wire.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&wire[i..i + 2], 16).unwrap())
                .collect();
            assert_eq!(accepts(&bytes), expected == "accept", "vector={_name}");
        }
    }
}
