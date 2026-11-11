//! CP-0555 bounded QFP6 authenticated peer-listener lifecycle candidate.
//!
//! This module provides a deliberately serial (one active peer at a time), bounded
//! TCP accept/session loop. It rejects wildcard/public bind addresses, authenticates
//! peers with the CP-0552 pinned Noise XX transport, creates one replay guard per
//! authenticated connection, caps accepted sessions and requests, validates fixed-width
//! Q6PA/Q6TA replies and ordered multi-record Q6HC history replies, and stops on shutdown.
//!
//! It is a library service candidate, not a node binary, production supervisor, miner,
//! RPC endpoint, mempool, or Mainnet release. External trust-provider callbacks must
//! enforce their own bounded network deadlines. Only private/overlay/loopback binding
//! is supported by this first operational qualification stage.

use crate::{
    external_cas_anchor_candidate::ExternalCasProviderTransport,
    qrun_v06_node_runtime_candidate::{
        decode_qrun_v06_peer_block_request, process_qrun_v06_peer_block_frame,
        process_qrun_v06_peer_block_frame_with_qap1,
        process_qrun_v06_permissionless_peer_block_frame, QRunV06NodeAnchorGate,
        QRunV06NodeRuntime, QRunV06PeerAdmissionResponse, QRunV06PeerAdmissionStatus,
        QRunV06PeerIngressError, QRunV06PeerReplayGuard, QRUN_V06_PEER_ADMISSION_MAGIC,
        QRUN_V06_PEER_ADMISSION_RESPONSE_BYTES, QRUN_V06_PEER_FRAME_VERSION,
    },
    qrun_v06_noise_transport_candidate::{QRunV06NoiseError, QRunV06NoiseSession},
    qrun_v06_permissionless_runtime_candidate::QRunV06PermissionlessNodeRuntime,
    qrun_v06_pow_fork_choice_candidate::QRunV06QuoteAssetAuthorizationProvider,
    qrun_v06_qap1_coordinator_candidate::{
        QRunV06Qap1AnchorTransport, QRunV06Qap1ExternalCoordinator,
    },
    state_machine::TransactionAuthenticator,
    v4_fat1_trust_candidate::MlDsa65Verifier,
};
use std::{
    net::{IpAddr, Ipv4Addr, TcpListener},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::Duration,
};

pub const QRUN_V06_LISTENER_MAX_SESSIONS: usize = 1024;
pub const QRUN_V06_LISTENER_MAX_REQUESTS_PER_SESSION: usize = 64;
pub const QRUN_V06_LISTENER_MAX_FAILED_HANDSHAKES: usize = 64;
pub const QRUN_V06_LISTENER_MAX_ACCEPT_POLL: Duration = Duration::from_millis(250);
pub const QRUN_V06_LISTENER_MIN_ACCEPT_POLL: Duration = Duration::from_millis(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QRunV06PeerListenerConfig {
    /// The number of TCP connections accepted before this supervised run returns.
    /// Each connection is handled serially; at most one peer session is active.
    pub max_sessions: usize,
    /// The maximum number of encrypted Q6PB/Q6PA, Q6TI/Q6TA or Q6HS/Q6HC exchanges on one authenticated session.
    pub max_requests_per_session: usize,
    /// Fail closed after this many unauthenticated/invalid Noise handshakes in one run.
    pub max_failed_handshakes: usize,
    /// Poll interval for nonblocking accept and shutdown observation.
    pub accept_poll_interval: Duration,
}

impl Default for QRunV06PeerListenerConfig {
    fn default() -> Self {
        Self {
            max_sessions: 128,
            max_requests_per_session: 16,
            max_failed_handshakes: 8,
            accept_poll_interval: Duration::from_millis(50),
        }
    }
}

impl QRunV06PeerListenerConfig {
    pub fn validate(&self) -> Result<(), QRunV06PeerListenerError> {
        if !(1..=QRUN_V06_LISTENER_MAX_SESSIONS).contains(&self.max_sessions)
            || !(1..=QRUN_V06_LISTENER_MAX_REQUESTS_PER_SESSION)
                .contains(&self.max_requests_per_session)
            || !(1..=QRUN_V06_LISTENER_MAX_FAILED_HANDSHAKES).contains(&self.max_failed_handshakes)
            || self.accept_poll_interval < QRUN_V06_LISTENER_MIN_ACCEPT_POLL
            || self.accept_poll_interval > QRUN_V06_LISTENER_MAX_ACCEPT_POLL
        {
            return Err(QRunV06PeerListenerError::InvalidConfiguration);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QRunV06PeerListenerError {
    InvalidConfiguration,
    UnsafeBindAddress(IpAddr),
    InvalidPeerTrustSet,
    Io(String),
}

impl std::fmt::Display for QRunV06PeerListenerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for QRunV06PeerListenerError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QRunV06PeerListenerStopReason {
    ShutdownRequested,
    SessionLimitReached,
    FailedHandshakeLimitReached,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QRunV06PeerListenerStats {
    pub accepted_connections: usize,
    pub authenticated_sessions: usize,
    pub rejected_handshakes: usize,
    pub requests_received: usize,
    pub responses_written: usize,
    pub handler_failures: usize,
    pub malformed_responses: usize,
    pub sessions_closed: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QRunV06PeerListenerReport {
    pub stats: QRunV06PeerListenerStats,
    pub stop_reason: QRunV06PeerListenerStopReason,
}

fn is_shared_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && (64..=127).contains(&octets[1])
}

fn is_safe_private_or_overlay_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(address) => {
            !address.is_unspecified()
                && (address.is_loopback()
                    || address.is_private()
                    || address.is_link_local()
                    || is_shared_ipv4(address))
        }
        IpAddr::V6(address) => {
            let octets = address.octets();
            let unique_local = octets[0] & 0xFE == 0xFC; // fc00::/7
            let link_local = octets[0] == 0xFE && octets[1] & 0xC0 == 0x80; // fe80::/10
            !address.is_unspecified() && (address.is_loopback() || unique_local || link_local)
        }
    }
}

fn validate_peer_pins(keys: &[[u8; 32]]) -> Result<(), QRunV06PeerListenerError> {
    if keys.is_empty() || keys.len() > 64 {
        return Err(QRunV06PeerListenerError::InvalidPeerTrustSet);
    }
    for (index, key) in keys.iter().enumerate() {
        if key.iter().all(|byte| *byte == 0)
            || keys.iter().skip(index + 1).any(|other| other == key)
        {
            return Err(QRunV06PeerListenerError::InvalidPeerTrustSet);
        }
    }
    Ok(())
}

fn validate_q6_application_response(
    response: &[u8; QRUN_V06_PEER_ADMISSION_RESPONSE_BYTES],
    expected_request_id: u64,
) -> bool {
    let is_block_ack = response[..4] == QRUN_V06_PEER_ADMISSION_MAGIC;
    let is_transaction_ack =
        response[..4] == crate::qrun_v06_transaction_ingress_candidate::Q6TA_MAGIC;
    if (!is_block_ack && !is_transaction_ack)
        || u16::from_be_bytes([response[4], response[5]]) != QRUN_V06_PEER_FRAME_VERSION
        || u64::from_be_bytes(response[8..16].try_into().unwrap()) != expected_request_id
        || !matches!(u16::from_be_bytes([response[6], response[7]]), 1..=3)
    {
        return false;
    }
    let status = u16::from_be_bytes([response[6], response[7]]);
    // Q6PA non-Accepted responses must not carry durable commit fields. Q6TA deliberately
    // carries TXID and mempool/canonical metadata for Accepted, Duplicate and Rejected.
    if is_block_ack
        && status != QRunV06PeerAdmissionStatus::Accepted as u16
        && response[16..].iter().any(|byte| *byte != 0)
    {
        return false;
    }
    true
}

/// Bridge the bounded listener to the existing QFP6 durable-runtime admission path.
///
/// Call this from the listener's frame callback. It decodes the Q6PB frame, enforces the
/// session-owned replay guard, performs durable admission plus external-anchor reconciliation,
/// and returns the fixed-width Q6PA response. Only the runtime's Accepted response is positive.
pub fn process_qfp6_peer_frame_with_runtime<A, T>(
    runtime: &mut QRunV06NodeRuntime<A>,
    replay_guard: &mut QRunV06PeerReplayGuard,
    frame: &[u8],
    authenticator: &T,
    quote_authorizer: &mut QRunV06QuoteAssetAuthorizationProvider<'_>,
) -> Result<[u8; QRUN_V06_PEER_ADMISSION_RESPONSE_BYTES], String>
where
    A: QRunV06NodeAnchorGate,
    T: TransactionAuthenticator,
{
    let response: QRunV06PeerAdmissionResponse = process_qrun_v06_peer_block_frame(
        runtime,
        replay_guard,
        frame,
        authenticator,
        quote_authorizer,
    )
    .map_err(|error: QRunV06PeerIngressError| error.to_string())?;
    Ok(response.encode())
}

/// Bridge one Q6PB frame to the permissionless Genesis-rooted runtime and encode Q6PA.
/// Use only after the Noise session has authenticated a pinned peer. The replay guard must
/// be owned by that session. Accepted confirms a local durable commit only, not global finality.
pub fn process_qfp6_peer_frame_with_permissionless_runtime<T: TransactionAuthenticator>(
    runtime: &mut QRunV06PermissionlessNodeRuntime,
    replay_guard: &mut QRunV06PeerReplayGuard,
    frame: &[u8],
    authenticator: &T,
) -> Result<[u8; QRUN_V06_PEER_ADMISSION_RESPONSE_BYTES], String> {
    let response = process_qrun_v06_permissionless_peer_block_frame(
        runtime,
        replay_guard,
        frame,
        authenticator,
    )
    .map_err(|error: QRunV06PeerIngressError| error.to_string())?;
    Ok(response.encode())
}

/// Bridge one Q6PB frame to QAP1-protected QFP6 admission and encode its Q6PA response.
/// Use this callback for a Runtime opened with recover_qap1_after_process_restart.
pub fn process_qfp6_peer_frame_with_qap1<A, T, P, PV, AV, Q>(
    runtime: &mut QRunV06NodeRuntime<A>,
    replay_guard: &mut QRunV06PeerReplayGuard,
    frame: &[u8],
    authenticator: &T,
    quote_authorizer: &mut QRunV06QuoteAssetAuthorizationProvider<'_>,
    coordinator: &mut QRunV06Qap1ExternalCoordinator<P, PV, AV, Q>,
) -> Result<[u8; QRUN_V06_PEER_ADMISSION_RESPONSE_BYTES], String>
where
    A: QRunV06NodeAnchorGate,
    T: TransactionAuthenticator,
    P: ExternalCasProviderTransport,
    PV: MlDsa65Verifier + Clone,
    AV: MlDsa65Verifier,
    Q: QRunV06Qap1AnchorTransport,
{
    let response = process_qrun_v06_peer_block_frame_with_qap1(
        runtime,
        replay_guard,
        frame,
        authenticator,
        quote_authorizer,
        coordinator,
    )
    .map_err(|error: QRunV06PeerIngressError| error.to_string())?;
    Ok(response.encode())
}

/// Run a bounded, serial QFP6 Noise XX accept loop over an already-bound TCP listener.
///
/// Requirements:
/// - Bind only to loopback, RFC1918/private LAN, IPv6 ULA/link-local, or NetBird/shared
///   100.64/10 overlay addresses. Wildcard and public addresses are rejected.
/// - Provide at least one explicit nonzero pinned remote static key.
/// - Set a finite session/request/rejection budget and pass an explicit shutdown flag.
/// - The callback must use `process_qfp6_peer_frame_with_runtime` (or an equivalent audited
///   admission path) and must have bounded external-provider calls.
///
/// The function is intentionally single-threaded: it serializes access to the one canonical
/// runtime/store and permits only one active peer. It does not yet provide parallel workers,
/// a process supervisor, automatic listener binding, public peer discovery, or node shutdown
/// orchestration. Noise handshake and record operations have their own internal deadlines.
pub fn serve_qfp6_noise_listener<F>(
    listener: &TcpListener,
    config: QRunV06PeerListenerConfig,
    local_static_private_key: &[u8; 32],
    trusted_remote_static_public_keys: &[[u8; 32]],
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
    shutdown: &AtomicBool,
    mut on_q6pb: F,
) -> Result<QRunV06PeerListenerReport, QRunV06PeerListenerError>
where
    F: FnMut(
        &mut QRunV06PeerReplayGuard,
        &[u8],
    ) -> Result<[u8; QRUN_V06_PEER_ADMISSION_RESPONSE_BYTES], String>,
{
    config.validate()?;
    validate_peer_pins(trusted_remote_static_public_keys)?;
    if local_static_private_key.iter().all(|byte| *byte == 0)
        || network_id.iter().all(|byte| *byte == 0)
        || profile_id.iter().all(|byte| *byte == 0)
    {
        return Err(QRunV06PeerListenerError::InvalidConfiguration);
    }

    let bind_ip = listener
        .local_addr()
        .map_err(|error| QRunV06PeerListenerError::Io(error.to_string()))?
        .ip();
    if !is_safe_private_or_overlay_ip(bind_ip) {
        return Err(QRunV06PeerListenerError::UnsafeBindAddress(bind_ip));
    }
    listener
        .set_nonblocking(true)
        .map_err(|error| QRunV06PeerListenerError::Io(error.to_string()))?;

    let mut stats = QRunV06PeerListenerStats::default();
    let stop_reason = loop {
        if shutdown.load(Ordering::Acquire) {
            break QRunV06PeerListenerStopReason::ShutdownRequested;
        }
        if stats.rejected_handshakes >= config.max_failed_handshakes {
            break QRunV06PeerListenerStopReason::FailedHandshakeLimitReached;
        }
        if stats.accepted_connections >= config.max_sessions {
            break QRunV06PeerListenerStopReason::SessionLimitReached;
        }

        let (mut stream, _) = match listener.accept() {
            Ok(connection) => connection,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(config.accept_poll_interval);
                continue;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(QRunV06PeerListenerError::Io(error.to_string())),
        };
        stats.accepted_connections += 1;
        if let Err(error) = stream.set_nodelay(true) {
            stats.handler_failures += 1;
            drop(stream);
            let _ = error;
            continue;
        }

        let mut noise = match QRunV06NoiseSession::accept(
            &mut stream,
            local_static_private_key,
            trusted_remote_static_public_keys,
            network_id,
            profile_id,
        ) {
            Ok(session) => session,
            Err(_error) => {
                stats.rejected_handshakes += 1;
                drop(stream);
                continue;
            }
        };
        stats.authenticated_sessions += 1;
        let mut replay_guard = QRunV06PeerReplayGuard::new();

        for _ in 0..config.max_requests_per_session {
            if shutdown.load(Ordering::Acquire) {
                break;
            }
            let frame = match noise.read_record(&mut stream) {
                Ok(frame) => frame,
                Err(QRunV06NoiseError::RecordTimeout)
                | Err(QRunV06NoiseError::Io(_))
                | Err(QRunV06NoiseError::MalformedRecord)
                | Err(QRunV06NoiseError::RecordAuthentication)
                | Err(QRunV06NoiseError::RecordTooLarge(_)) => break,
                Err(QRunV06NoiseError::HandshakeTimeout)
                | Err(QRunV06NoiseError::Handshake(_))
                | Err(QRunV06NoiseError::MalformedHandshake)
                | Err(QRunV06NoiseError::UntrustedPeer)
                | Err(QRunV06NoiseError::InvalidNetworkOrProfile)
                | Err(QRunV06NoiseError::InvalidPrivateKey)
                | Err(QRunV06NoiseError::EmptyTrustSet)
                | Err(QRunV06NoiseError::OversizedTrustSet)
                | Err(QRunV06NoiseError::DuplicateTrustedKey) => break,
            };
            // Dispatch by the application-frame magic before invoking the handler. Both
            // protocols share a request-ID field but have distinct codecs and ACK semantics.
            let request_id = if frame.get(..4)
                == Some(&crate::qrun_v06_transaction_ingress_candidate::Q6TI_MAGIC)
            {
                match crate::qrun_v06_transaction_ingress_candidate::decode_q6ti_transaction_request(
                    &frame,
                ) {
                    Ok(request) => request.request_id,
                    Err(_) => {
                        stats.handler_failures += 1;
                        break;
                    }
                }
            } else {
                match decode_qrun_v06_peer_block_request(&frame) {
                    Ok(request) => request.request_id,
                    Err(_) => {
                        stats.handler_failures += 1;
                        break;
                    }
                }
            };
            stats.requests_received += 1;
            let response = match on_q6pb(&mut replay_guard, &frame) {
                Ok(response) => response,
                Err(_) => {
                    stats.handler_failures += 1;
                    break;
                }
            };
            if !validate_q6_application_response(&response, request_id) {
                stats.malformed_responses += 1;
                break;
            }
            if noise.write_record(&mut stream, &response).is_err() {
                stats.handler_failures += 1;
                break;
            }
            stats.responses_written += 1;
        }
        stats.sessions_closed += 1;
    };

    Ok(QRunV06PeerListenerReport { stats, stop_reason })
}

/// Run the bounded authenticated Noise listener for Q6HS/Q6HC history synchronization.
/// Unlike the transaction/block listener, one request may produce multiple ordered response
/// records. The handler must return only chunks encoded for the exact request it received.
pub fn serve_qfp6_noise_history_listener<F>(
    listener: &TcpListener,
    config: QRunV06PeerListenerConfig,
    local_static_private_key: &[u8; 32],
    trusted_remote_static_public_keys: &[[u8; 32]],
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
    shutdown: &AtomicBool,
    mut on_q6hs: F,
) -> Result<QRunV06PeerListenerReport, QRunV06PeerListenerError>
where
    F: FnMut(
        &crate::qrun_v06_history_sync_wire_candidate::QRunV06HistorySyncRequest,
    ) -> Result<Vec<Vec<u8>>, String>,
{
    use crate::qrun_v06_history_sync_wire_candidate::{
        decode_q6hs_request, validate_q6hc_response_chunk, validate_q6hc_response_sequence,
        Q6_HISTORY_SYNC_MAX_CHUNKS,
    };
    use crate::qrun_v06_noise_transport_candidate::{
        QRunV06NoiseSession, MAX_QFP6_NOISE_RECORD_BYTES,
    };
    use std::collections::HashSet;

    config.validate()?;
    validate_peer_pins(trusted_remote_static_public_keys)?;
    if local_static_private_key.iter().all(|byte| *byte == 0)
        || network_id.iter().all(|byte| *byte == 0)
        || profile_id.iter().all(|byte| *byte == 0)
    {
        return Err(QRunV06PeerListenerError::InvalidConfiguration);
    }
    let bind_ip = listener
        .local_addr()
        .map_err(|error| QRunV06PeerListenerError::Io(error.to_string()))?
        .ip();
    if !is_safe_private_or_overlay_ip(bind_ip) {
        return Err(QRunV06PeerListenerError::UnsafeBindAddress(bind_ip));
    }
    listener
        .set_nonblocking(true)
        .map_err(|error| QRunV06PeerListenerError::Io(error.to_string()))?;

    let mut stats = QRunV06PeerListenerStats::default();
    const MAX_Q6HS_SESSION_EGRESS_BYTES: usize = 64 * 1024 * 1024;
    let stop_reason = loop {
        if shutdown.load(Ordering::Acquire) {
            break QRunV06PeerListenerStopReason::ShutdownRequested;
        }
        if stats.rejected_handshakes >= config.max_failed_handshakes {
            break QRunV06PeerListenerStopReason::FailedHandshakeLimitReached;
        }
        if stats.accepted_connections >= config.max_sessions {
            break QRunV06PeerListenerStopReason::SessionLimitReached;
        }
        let (mut stream, _) = match listener.accept() {
            Ok(connection) => connection,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(config.accept_poll_interval);
                continue;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(QRunV06PeerListenerError::Io(error.to_string())),
        };
        stats.accepted_connections += 1;
        if stream.set_nodelay(true).is_err() {
            stats.handler_failures += 1;
            continue;
        }
        let mut noise = match QRunV06NoiseSession::accept(
            &mut stream,
            local_static_private_key,
            trusted_remote_static_public_keys,
            network_id,
            profile_id,
        ) {
            Ok(session) => session,
            Err(_) => {
                stats.rejected_handshakes += 1;
                continue;
            }
        };
        stats.authenticated_sessions += 1;
        let mut seen_request_ids = HashSet::new();
        let mut session_egress_bytes = 0usize;
        for _ in 0..config.max_requests_per_session {
            if shutdown.load(Ordering::Acquire) {
                break;
            }
            let frame = match noise.read_record(&mut stream) {
                Ok(frame) => frame,
                Err(_) => break,
            };
            let request = match decode_q6hs_request(&frame) {
                Ok(request)
                    if request.network_id == *network_id
                        && request.profile_id == *profile_id
                        && seen_request_ids.insert(request.request_id) =>
                {
                    request
                }
                _ => {
                    stats.handler_failures += 1;
                    break;
                }
            };
            stats.requests_received += 1;
            let chunks = match on_q6hs(&request) {
                Ok(chunks)
                    if !chunks.is_empty()
                        && chunks.len() <= Q6_HISTORY_SYNC_MAX_CHUNKS
                        && validate_q6hc_response_sequence(
                            &chunks,
                            request.request_id,
                            &request.snapshot_tip,
                        )
                        .is_ok() =>
                {
                    chunks
                }
                _ => {
                    stats.handler_failures += 1;
                    break;
                }
            };
            let mut response_failed = false;
            for (index, chunk) in chunks.iter().enumerate() {
                let next_egress = session_egress_bytes.checked_add(chunk.len());
                if chunk.len() > MAX_QFP6_NOISE_RECORD_BYTES
                    || next_egress.is_none_or(|bytes| bytes > MAX_Q6HS_SESSION_EGRESS_BYTES)
                    || validate_q6hc_response_chunk(
                        chunk,
                        request.request_id,
                        &request.snapshot_tip,
                        index as u32,
                    )
                    .is_err()
                    || noise.write_record(&mut stream, chunk).is_err()
                {
                    response_failed = true;
                    break;
                }
                session_egress_bytes = next_egress.expect("egress checked before Noise write");
                stats.responses_written += 1;
            }
            if response_failed {
                stats.malformed_responses += 1;
                break;
            }
        }
        stats.sessions_closed += 1;
    };
    Ok(QRunV06PeerListenerReport { stats, stop_reason })
}

/// Combined Q6PB/Q6TI and Q6HS listener for the permissionless production supervisor.
/// Fixed-width admission replies remain exactly one Q6PA/Q6TA record; Q6HS replies are a
/// prevalidated ordered Q6HC sequence. All three request families share one Noise session,
/// replay guard, connection budget and listener socket.
pub fn serve_qfp6_noise_listener_with_history<F>(
    listener: &TcpListener,
    config: QRunV06PeerListenerConfig,
    local_static_private_key: &[u8; 32],
    trusted_remote_static_public_keys: &[[u8; 32]],
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
    shutdown: &AtomicBool,
    mut on_application_frame: F,
) -> Result<QRunV06PeerListenerReport, QRunV06PeerListenerError>
where
    F: FnMut(&mut QRunV06PeerReplayGuard, &[u8]) -> Result<Vec<Vec<u8>>, String>,
{
    use crate::qrun_v06_history_sync_wire_candidate::{
        decode_q6hi_request, decode_q6hr_status, decode_q6hs_request,
        validate_q6hc_response_sequence, Q6HI_REQUEST_MAGIC, Q6HS_REQUEST_MAGIC,
    };
    use crate::qrun_v06_noise_transport_candidate::MAX_QFP6_NOISE_RECORD_BYTES;
    use crate::qrun_v06_transaction_ingress_candidate::{
        decode_q6ti_transaction_request, Q6TI_MAGIC,
    };

    config.validate()?;
    validate_peer_pins(trusted_remote_static_public_keys)?;
    if local_static_private_key.iter().all(|byte| *byte == 0)
        || network_id.iter().all(|byte| *byte == 0)
        || profile_id.iter().all(|byte| *byte == 0)
    {
        return Err(QRunV06PeerListenerError::InvalidConfiguration);
    }
    let bind_ip = listener
        .local_addr()
        .map_err(|error| QRunV06PeerListenerError::Io(error.to_string()))?
        .ip();
    if !is_safe_private_or_overlay_ip(bind_ip) {
        return Err(QRunV06PeerListenerError::UnsafeBindAddress(bind_ip));
    }
    listener
        .set_nonblocking(true)
        .map_err(|error| QRunV06PeerListenerError::Io(error.to_string()))?;

    let mut stats = QRunV06PeerListenerStats::default();
    const MAX_HISTORY_SESSION_EGRESS_BYTES: usize = 256 * 1024 * 1024;
    let stop_reason = loop {
        if shutdown.load(Ordering::Acquire) {
            break QRunV06PeerListenerStopReason::ShutdownRequested;
        }
        if stats.rejected_handshakes >= config.max_failed_handshakes {
            break QRunV06PeerListenerStopReason::FailedHandshakeLimitReached;
        }
        if stats.accepted_connections >= config.max_sessions {
            break QRunV06PeerListenerStopReason::SessionLimitReached;
        }
        let (mut stream, _) = match listener.accept() {
            Ok(connection) => connection,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(config.accept_poll_interval);
                continue;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(QRunV06PeerListenerError::Io(error.to_string())),
        };
        stats.accepted_connections += 1;
        if stream.set_nodelay(true).is_err() {
            stats.handler_failures += 1;
            continue;
        }
        let mut noise = match QRunV06NoiseSession::accept(
            &mut stream,
            local_static_private_key,
            trusted_remote_static_public_keys,
            network_id,
            profile_id,
        ) {
            Ok(session) => session,
            Err(_) => {
                stats.rejected_handshakes += 1;
                continue;
            }
        };
        stats.authenticated_sessions += 1;
        let mut replay_guard = QRunV06PeerReplayGuard::new();
        let mut session_history_egress = 0usize;
        for _ in 0..config.max_requests_per_session {
            if shutdown.load(Ordering::Acquire) {
                break;
            }
            let frame = match noise.read_record(&mut stream) {
                Ok(frame) => frame,
                Err(_) => break,
            };
            let (request_id, is_history, is_info) = if frame.get(..4) == Some(&Q6HI_REQUEST_MAGIC) {
                match decode_q6hi_request(&frame) {
                    Ok(request)
                        if request.network_id == *network_id
                            && request.profile_id == *profile_id =>
                    {
                        (request.request_id, false, true)
                    }
                    _ => {
                        stats.handler_failures += 1;
                        break;
                    }
                }
            } else if frame.get(..4) == Some(&Q6HS_REQUEST_MAGIC) {
                match decode_q6hs_request(&frame) {
                    Ok(request)
                        if request.network_id == *network_id
                            && request.profile_id == *profile_id =>
                    {
                        (request.request_id, true, false)
                    }
                    _ => {
                        stats.handler_failures += 1;
                        break;
                    }
                }
            } else if frame.get(..4) == Some(&Q6TI_MAGIC) {
                match decode_q6ti_transaction_request(&frame) {
                    Ok(request) => (request.request_id, false, false),
                    Err(_) => {
                        stats.handler_failures += 1;
                        break;
                    }
                }
            } else {
                match decode_qrun_v06_peer_block_request(&frame) {
                    Ok(request) => (request.request_id, false, false),
                    Err(_) => {
                        stats.handler_failures += 1;
                        break;
                    }
                }
            };
            stats.requests_received += 1;
            if (is_history || is_info) && replay_guard.accept(request_id).is_err() {
                stats.handler_failures += 1;
                break;
            }
            let responses = match on_application_frame(&mut replay_guard, &frame) {
                Ok(responses) => responses,
                Err(_) => {
                    stats.handler_failures += 1;
                    break;
                }
            };
            if is_history {
                if validate_q6hc_response_sequence(
                    &responses,
                    request_id,
                    &decode_q6hs_request(&frame)
                        .map_err(|_| QRunV06PeerListenerError::InvalidConfiguration)?
                        .snapshot_tip,
                )
                .is_err()
                {
                    stats.malformed_responses += 1;
                    break;
                }
            } else if is_info {
                let valid_status = responses.len() == 1
                    && decode_q6hi_request(&frame)
                        .ok()
                        .and_then(|request| decode_q6hr_status(&responses[0], &request).ok())
                        .is_some();
                if !valid_status {
                    stats.malformed_responses += 1;
                    break;
                }
            } else if responses.len() != 1
                || responses[0].len() != QRUN_V06_PEER_ADMISSION_RESPONSE_BYTES
                || !responses[0].as_slice().try_into().ok().is_some_and(
                    |response: &[u8; QRUN_V06_PEER_ADMISSION_RESPONSE_BYTES]| {
                        validate_q6_application_response(response, request_id)
                    },
                )
            {
                stats.malformed_responses += 1;
                break;
            }
            let mut write_failed = false;
            for response in &responses {
                if response.len() > MAX_QFP6_NOISE_RECORD_BYTES {
                    write_failed = true;
                    break;
                }
                if is_history {
                    let next = session_history_egress.checked_add(response.len());
                    if next.is_none_or(|bytes| bytes > MAX_HISTORY_SESSION_EGRESS_BYTES) {
                        write_failed = true;
                        break;
                    }
                    session_history_egress = next.expect("history egress checked before write");
                }
                if noise.write_record(&mut stream, response).is_err() {
                    write_failed = true;
                    break;
                }
                stats.responses_written += 1;
            }
            if write_failed {
                stats.handler_failures += 1;
                break;
            }
        }
        stats.sessions_closed += 1;
    };
    Ok(QRunV06PeerListenerReport { stats, stop_reason })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        qrun_v06_canonical_execution_candidate::QRunV06CanonicalExecutionState,
        qrun_v06_node_runtime_candidate::{
            encode_qrun_v06_peer_block_request, QRUN_V06_PEER_ADMISSION_MAGIC,
        },
        qrun_v06_transaction_ingress_candidate::{
            decode_q6ta_response, encode_q6ti_transaction_request,
            QRunV06TransactionSubmitResponse, QRunV06TransactionSubmitStatus,
        },
        state_machine::Transaction,
    };
    use snow::Builder;
    use std::{
        net::{Ipv6Addr, SocketAddr, TcpStream},
        sync::atomic::AtomicBool,
        thread,
        time::{Duration, Instant},
    };

    const NETWORK: [u8; 32] = [0x91; 32];
    const PROFILE: [u8; 32] = [0x92; 32];

    fn keypair() -> ([u8; 32], [u8; 32]) {
        let params = "Noise_XX_25519_ChaChaPoly_SHA256".parse().unwrap();
        let mut pair = Builder::new(params).generate_keypair().unwrap();
        let mut private = [0u8; 32];
        let mut public = [0u8; 32];
        private.copy_from_slice(&pair.private);
        public.copy_from_slice(&pair.public);
        pair.private.fill(0);
        pair.public.fill(0);
        (private, public)
    }

    fn make_response(request_id: u64, status: u16) -> [u8; 128] {
        let mut response = [0u8; 128];
        response[..4].copy_from_slice(&QRUN_V06_PEER_ADMISSION_MAGIC);
        response[4..6].copy_from_slice(&QRUN_V06_PEER_FRAME_VERSION.to_be_bytes());
        response[6..8].copy_from_slice(&status.to_be_bytes());
        response[8..16].copy_from_slice(&request_id.to_be_bytes());
        response
    }

    fn connect_until(address: SocketAddr) -> TcpStream {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match TcpStream::connect(address) {
                Ok(stream) => return stream,
                Err(error) if Instant::now() < deadline => {
                    let _ = error;
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("listener did not accept local test connection: {error}"),
            }
        }
    }

    #[test]
    fn qfp6_listener_rejects_wildcard_and_public_bind_addresses() {
        assert!(!is_safe_private_or_overlay_ip(IpAddr::V4(
            Ipv4Addr::UNSPECIFIED
        )));
        assert!(!is_safe_private_or_overlay_ip(IpAddr::V4(Ipv4Addr::new(
            8, 8, 8, 8
        ))));
        assert!(is_safe_private_or_overlay_ip(IpAddr::V4(
            Ipv4Addr::LOCALHOST
        )));
        assert!(is_safe_private_or_overlay_ip(IpAddr::V4(Ipv4Addr::new(
            10, 1, 2, 3
        ))));
        assert!(is_safe_private_or_overlay_ip(IpAddr::V4(Ipv4Addr::new(
            100, 113, 4, 9
        ))));
        assert!(is_safe_private_or_overlay_ip(IpAddr::V6(
            Ipv6Addr::LOCALHOST
        )));
    }

    #[test]
    fn qfp6_listener_rejects_invalid_budgets_and_empty_or_duplicate_pins() {
        let mut config = QRunV06PeerListenerConfig::default();
        assert!(config.validate().is_ok());
        config.max_requests_per_session = 0;
        assert_eq!(
            config.validate(),
            Err(QRunV06PeerListenerError::InvalidConfiguration)
        );
        assert_eq!(
            validate_peer_pins(&[]),
            Err(QRunV06PeerListenerError::InvalidPeerTrustSet)
        );
        let (_, public) = keypair();
        assert_eq!(
            validate_peer_pins(&[public, public]),
            Err(QRunV06PeerListenerError::InvalidPeerTrustSet)
        );
        assert_eq!(
            validate_peer_pins(&[[0u8; 32]]),
            Err(QRunV06PeerListenerError::InvalidPeerTrustSet)
        );
    }

    #[test]
    fn qfp6_listener_accepts_two_pinned_sessions_and_resets_replay_guard_per_session() {
        let (server_private, server_public) = keypair();
        let (client_private, client_public) = keypair();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = AtomicBool::new(false);
        let server = thread::spawn(move || {
            let mut handler = |guard: &mut QRunV06PeerReplayGuard, frame: &[u8]| {
                let request = decode_qrun_v06_peer_block_request(frame).unwrap();
                let status = if guard.accept(request.request_id).is_ok() {
                    QRunV06PeerAdmissionStatus::Accepted as u16
                } else {
                    QRunV06PeerAdmissionStatus::Rejected as u16
                };
                Ok(make_response(request.request_id, status))
            };
            serve_qfp6_noise_listener(
                &listener,
                QRunV06PeerListenerConfig {
                    max_sessions: 2,
                    max_requests_per_session: 1,
                    max_failed_handshakes: 2,
                    accept_poll_interval: Duration::from_millis(10),
                },
                &server_private,
                &[client_public],
                &NETWORK,
                &PROFILE,
                &shutdown,
                &mut handler,
            )
            .unwrap()
        });

        for _ in 0..2 {
            let mut stream = connect_until(address);
            let mut noise = QRunV06NoiseSession::connect(
                &mut stream,
                &client_private,
                &server_public,
                &NETWORK,
                &PROFILE,
            )
            .unwrap();
            let frame = encode_qrun_v06_peer_block_request(1, b"candidate-test-frame").unwrap();
            noise.write_q6pb_request(&mut stream, &frame).unwrap();
            let response = noise.read_q6pa_response(&mut stream, 1).unwrap();
            assert_eq!(
                u16::from_be_bytes([response[6], response[7]]),
                QRunV06PeerAdmissionStatus::Accepted as u16
            );
        }

        let report = server.join().unwrap();
        assert_eq!(
            report.stop_reason,
            QRunV06PeerListenerStopReason::SessionLimitReached
        );
        assert_eq!(report.stats.accepted_connections, 2);
        assert_eq!(report.stats.authenticated_sessions, 2);
        assert_eq!(report.stats.requests_received, 2);
        assert_eq!(report.stats.responses_written, 2);
        assert_eq!(report.stats.sessions_closed, 2);
    }

    #[test]
    fn qfp6_listener_routes_signed_q6ha_over_noise_into_real_mempool() {
        use crate::{
            consensus::{ConsensusParameters, PowAlgorithm, PowParameters, Uint256},
            qrun_v06_genesis_descriptor_candidate::QRunV06GenesisDescriptor,
            qrun_v06_hybrid_auth_candidate::{
                QRunV06HybridTransactionAuthenticator, QRunV06HybridTransactionSigner,
            },
            qrun_v06_tokenomics_candidate::{
                QRunV06MiningScheduleCandidate, QRunV06TokenomicsState,
            },
            qrun_v06_transaction_ingress_candidate::process_q6ti_transaction_frame,
            qrun_v06_transaction_mempool_candidate::{
                QRunV06MempoolLimits, QRunV06NativeTransactionMempool,
            },
            v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate,
        };

        const PRODUCER: [u8; 32] = [0x93; 32];
        const RECIPIENT: [u8; 32] = [0x94; 32];
        let signer = QRunV06HybridTransactionSigner::from_seeds([0xB1; 32], [0xB2; 32]).unwrap();
        let mut params = ConsensusParameters::candidate_testnet().unwrap();
        params.protocol_version = 6;
        params.target_block_time_secs = 30;
        params.difficulty_window_blocks = 2;
        params.difficulty_min_ratio_divisor = 4;
        params.difficulty_max_ratio = 4;
        params.initial_target = Uint256::from_be_bytes([0x7F; 32]);
        params.pow_limit = Uint256::MAX;
        params.pow = PowParameters {
            algorithm: PowAlgorithm::Argon2id,
            memory_kib: 8,
            iterations: 1,
            lanes: 1,
            output_bytes: 32,
        };
        params.validate().unwrap();
        let schedule = QRunV06MiningScheduleCandidate::cp0422_research_candidate();
        let economics =
            QRunV06TokenomicsState::genesis(NETWORK, signer.account_id(), schedule).unwrap();
        let descriptor = QRunV06GenesisDescriptor::new(
            NETWORK,
            PROFILE,
            signer.account_id(),
            1,
            crate::qrun_v06_checkpoint_candidate::qrun_v06_consensus_fingerprint(&params).unwrap(),
            economics.policy_fingerprint(),
        )
        .unwrap();
        let state = QRunV06CanonicalExecutionState::cp0528_genesis_candidate_with_descriptor(
            descriptor, schedule,
        )
        .unwrap();
        let authenticator =
            QRunV06HybridTransactionAuthenticator::new(LibcruxMlDsa65VerifierCandidate);
        let candidate_timestamp = state.last_timestamp() + 60;
        let mut mempool =
            QRunV06NativeTransactionMempool::new(QRunV06MempoolLimits::default()).unwrap();

        let (server_private, server_public) = keypair();
        let (client_private, client_public) = keypair();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = AtomicBool::new(false);
        let server = thread::spawn(move || {
            let mut handler = |guard: &mut QRunV06PeerReplayGuard, frame: &[u8]| {
                process_q6ti_transaction_frame(
                    frame,
                    guard,
                    &mut mempool,
                    &state,
                    &authenticator,
                    PRODUCER,
                    candidate_timestamp,
                )
                .map_err(|error| format!("{error:?}"))
            };
            let report = serve_qfp6_noise_listener(
                &listener,
                QRunV06PeerListenerConfig {
                    max_sessions: 1,
                    max_requests_per_session: 2,
                    max_failed_handshakes: 1,
                    accept_poll_interval: Duration::from_millis(10),
                },
                &server_private,
                &[client_public],
                &NETWORK,
                &PROFILE,
                &shutdown,
                &mut handler,
            )
            .unwrap();
            (report, mempool.len(), mempool.total_bytes())
        });

        let mut transaction = Transaction {
            network_id: NETWORK,
            sender: signer.account_id(),
            recipient: RECIPIENT,
            nonce: 1,
            amount: 1_000,
            fee: 10,
            expires_at: 20_000,
            signature: Vec::new(),
        };
        signer.sign_transaction(&mut transaction).unwrap();
        assert_eq!(transaction.signature.len(), 5_365);
        let expected_txid = crate::state_machine::transaction_id_with_signature_limit(
            &transaction,
            crate::state_machine::QRUN_V06_MAX_NATIVE_TX_SIGNATURE_BYTES,
        )
        .unwrap();

        let mut stream = connect_until(address);
        let mut noise = QRunV06NoiseSession::connect(
            &mut stream,
            &client_private,
            &server_public,
            &NETWORK,
            &PROFILE,
        )
        .unwrap();
        let first = encode_q6ti_transaction_request(201, &transaction).unwrap();
        noise.write_record(&mut stream, &first).unwrap();
        let first_response = noise.read_record(&mut stream).unwrap();
        let accepted = decode_q6ta_response(&first_response, 201).unwrap();
        assert_eq!(accepted.status, QRunV06TransactionSubmitStatus::Accepted);
        assert_eq!(accepted.transaction_id, expected_txid);
        assert_eq!(accepted.mempool_count, 1);
        assert!(accepted.mempool_bytes > 4 * 1024);
        assert_eq!(accepted.canonical_height, 0);

        let second = encode_q6ti_transaction_request(202, &transaction).unwrap();
        noise.write_record(&mut stream, &second).unwrap();
        let second_response = noise.read_record(&mut stream).unwrap();
        let duplicate = decode_q6ta_response(&second_response, 202).unwrap();
        assert_eq!(duplicate.status, QRunV06TransactionSubmitStatus::Duplicate);
        assert_eq!(duplicate.transaction_id, expected_txid);
        assert_eq!(duplicate.mempool_count, 1);

        let (report, mempool_count, mempool_bytes) = server.join().unwrap();
        assert_eq!(
            report.stop_reason,
            QRunV06PeerListenerStopReason::SessionLimitReached
        );
        assert_eq!(report.stats.authenticated_sessions, 1);
        assert_eq!(report.stats.requests_received, 2);
        assert_eq!(report.stats.responses_written, 2);
        assert_eq!(report.stats.handler_failures, 0);
        assert_eq!(report.stats.malformed_responses, 0);
        assert_eq!(mempool_count, 1);
        assert!(mempool_bytes > 4 * 1024);
    }

    #[test]
    fn qfp6_listener_dispatches_q6ti_over_pinned_noise_and_returns_q6ta() {
        let (server_private, server_public) = keypair();
        let (client_private, client_public) = keypair();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = AtomicBool::new(false);
        let server = thread::spawn(move || {
            let mut handler =
                |guard: &mut QRunV06PeerReplayGuard, frame: &[u8]| {
                    let request = crate::qrun_v06_transaction_ingress_candidate::
                    decode_q6ti_transaction_request(frame).unwrap();
                    let status = if guard.accept(request.request_id).is_ok() {
                        QRunV06TransactionSubmitStatus::Accepted
                    } else {
                        QRunV06TransactionSubmitStatus::Rejected
                    };
                    Ok(QRunV06TransactionSubmitResponse {
                        request_id: request.request_id,
                        status,
                        transaction_id: [0xA5; 32],
                        mempool_count: 1,
                        mempool_bytes: 5_500,
                        canonical_height: 0,
                        canonical_tip: [0xB6; 32],
                        canonical_state_root: [0xC7; 32],
                    }
                    .encode())
                };
            serve_qfp6_noise_listener(
                &listener,
                QRunV06PeerListenerConfig {
                    max_sessions: 1,
                    max_requests_per_session: 2,
                    max_failed_handshakes: 1,
                    accept_poll_interval: Duration::from_millis(10),
                },
                &server_private,
                &[client_public],
                &NETWORK,
                &PROFILE,
                &shutdown,
                &mut handler,
            )
            .unwrap()
        });

        let mut stream = connect_until(address);
        let mut noise = QRunV06NoiseSession::connect(
            &mut stream,
            &client_private,
            &server_public,
            &NETWORK,
            &PROFILE,
        )
        .unwrap();
        let transaction = Transaction {
            network_id: NETWORK,
            sender: [0xD1; 32],
            recipient: [0xD2; 32],
            nonce: 1,
            amount: 100,
            fee: 1,
            expires_at: 10_000,
            signature: vec![0xE3; 5_365],
        };
        let first = encode_q6ti_transaction_request(101, &transaction).unwrap();
        noise.write_record(&mut stream, &first).unwrap();
        let response = noise.read_record(&mut stream).unwrap();
        assert_eq!(
            decode_q6ta_response(&response, 101).unwrap().status,
            QRunV06TransactionSubmitStatus::Accepted
        );

        let second = encode_q6ti_transaction_request(102, &transaction).unwrap();
        noise.write_record(&mut stream, &second).unwrap();
        let response = noise.read_record(&mut stream).unwrap();
        let decoded = decode_q6ta_response(&response, 102).unwrap();
        assert_eq!(decoded.status, QRunV06TransactionSubmitStatus::Accepted);
        assert_eq!(decoded.mempool_bytes, 5_500);

        let report = server.join().unwrap();
        assert_eq!(
            report.stop_reason,
            QRunV06PeerListenerStopReason::SessionLimitReached
        );
        assert_eq!(report.stats.authenticated_sessions, 1);
        assert_eq!(report.stats.requests_received, 2);
        assert_eq!(report.stats.responses_written, 2);
        assert_eq!(report.stats.handler_failures, 0);
        assert_eq!(report.stats.malformed_responses, 0);
    }

    #[test]
    fn qfp6_listener_rejects_unpinned_peer_without_calling_admission_handler() {
        let (server_private, server_public) = keypair();
        let (pinned_client_private, pinned_client_public) = keypair();
        let (unexpected_client_private, _) = keypair();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = AtomicBool::new(false);
        let server = thread::spawn(move || {
            let mut handler_calls = 0usize;
            let mut handler = |_guard: &mut QRunV06PeerReplayGuard, _frame: &[u8]| {
                handler_calls += 1;
                Ok(make_response(
                    1,
                    QRunV06PeerAdmissionStatus::Accepted as u16,
                ))
            };
            let report = serve_qfp6_noise_listener(
                &listener,
                QRunV06PeerListenerConfig {
                    max_sessions: 1,
                    max_requests_per_session: 1,
                    max_failed_handshakes: 1,
                    accept_poll_interval: Duration::from_millis(10),
                },
                &server_private,
                &[pinned_client_public],
                &NETWORK,
                &PROFILE,
                &shutdown,
                &mut handler,
            )
            .unwrap();
            (report, handler_calls)
        });

        let mut stream = connect_until(address);
        // The client pins the authentic server but is not present in the server's trust set.
        let _client_result = QRunV06NoiseSession::connect(
            &mut stream,
            &unexpected_client_private,
            &server_public,
            &NETWORK,
            &PROFILE,
        );
        drop(stream);

        let (report, handler_calls) = server.join().unwrap();
        assert_eq!(handler_calls, 0);
        assert_eq!(report.stats.accepted_connections, 1);
        assert_eq!(report.stats.authenticated_sessions, 0);
        assert_eq!(report.stats.rejected_handshakes, 1);
        assert_eq!(
            report.stop_reason,
            QRunV06PeerListenerStopReason::FailedHandshakeLimitReached
        );
        let _ = pinned_client_private;
    }

    #[test]
    fn qfp6_listener_shutdown_is_observed_without_accepting_connections() {
        let (private, public) = keypair();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let shutdown = AtomicBool::new(true);
        let mut handler = |_guard: &mut QRunV06PeerReplayGuard, _frame: &[u8]| {
            Ok(make_response(
                1,
                QRunV06PeerAdmissionStatus::Accepted as u16,
            ))
        };
        let report = serve_qfp6_noise_listener(
            &listener,
            QRunV06PeerListenerConfig::default(),
            &private,
            &[public],
            &NETWORK,
            &PROFILE,
            &shutdown,
            &mut handler,
        )
        .unwrap();
        assert_eq!(
            report.stop_reason,
            QRunV06PeerListenerStopReason::ShutdownRequested
        );
        assert_eq!(report.stats.accepted_connections, 0);
    }

    #[test]
    fn qfp6_history_listener_transfers_q6hc_chunks_over_pinned_noise_session() {
        use crate::qrun_v06_history_sync_wire_candidate::{
            decode_q6hi_request, decode_q6hs_request, encode_q6hp_page_chunks, encode_q6hr_status,
            QRunV06HistoryInfoRequest, QRunV06HistorySyncRequest,
        };
        use crate::qrun_v06_noise_transport_candidate::QRunV06NoiseSession;
        use crate::qrun_v06_pow_fork_choice_candidate::QRunV06CanonicalHistoryPage;

        let (server_private, server_public) = keypair();
        let (client_private, client_public) = keypair();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = std::sync::Arc::new(AtomicBool::new(false));
        let server_shutdown = shutdown.clone();
        let server = thread::spawn(move || {
            let mut config = QRunV06PeerListenerConfig::default();
            config.max_sessions = 1;
            config.max_requests_per_session = 3;
            let report = serve_qfp6_noise_listener_with_history(
                &listener,
                config,
                &server_private,
                &[client_public],
                &NETWORK,
                &PROFILE,
                &server_shutdown,
                |_guard, frame| {
                    if frame.get(..4)
                        == Some(&crate::qrun_v06_history_sync_wire_candidate::Q6HI_REQUEST_MAGIC)
                    {
                        let request =
                            decode_q6hi_request(frame).map_err(|error| error.to_string())?;
                        let status = encode_q6hr_status(&request, 0, [0x77; 32], [0x56; 32])
                            .map_err(|error| error.to_string())?;
                        Ok(vec![status.to_vec()])
                    } else {
                        let request =
                            decode_q6hs_request(frame).map_err(|error| error.to_string())?;
                        let page = QRunV06CanonicalHistoryPage {
                            start_height: 1,
                            next_height: 1,
                            snapshot_height: 0,
                            snapshot_tip: request.snapshot_tip,
                            complete: true,
                            envelopes: Vec::new(),
                        };
                        encode_q6hp_page_chunks(&request, &page).map_err(|error| error.to_string())
                    }
                },
            )
            .unwrap();
            report
        });

        let mut stream = TcpStream::connect(address).unwrap();
        stream.set_nodelay(true).unwrap();
        let mut noise = QRunV06NoiseSession::connect(
            &mut stream,
            &client_private,
            &server_public,
            &NETWORK,
            &PROFILE,
        )
        .unwrap();
        let info_request = QRunV06HistoryInfoRequest {
            request_id: 9000,
            network_id: NETWORK,
            profile_id: PROFILE,
        };
        noise
            .write_record(&mut stream, &info_request.encode().unwrap())
            .unwrap();
        let info_frame = noise.read_record(&mut stream).unwrap();
        let info = crate::qrun_v06_history_sync_wire_candidate::decode_q6hr_status(
            &info_frame,
            &info_request,
        )
        .unwrap();
        assert_eq!(info.height, 0);
        assert_eq!(info.consensus_tip, [0x77; 32]);
        assert_eq!(info.execution_tip, [0x56; 32]);

        let request = QRunV06HistorySyncRequest {
            request_id: 9001,
            network_id: NETWORK,
            profile_id: PROFILE,
            snapshot_tip: [0x77; 32],
            expected_parent_consensus_hash: [0x77; 32],
            expected_parent_execution_hash: [0x56; 32],
            start_height: 1,
            max_blocks: 1,
            max_bytes: 128,
        };
        let replay_request = request.clone();
        let page = crate::qrun_v06_history_sync_service_candidate::request_history_page_over_noise(
            &mut noise,
            &mut stream,
            request,
            crate::consensus::ConsensusParameters::candidate_testnet().unwrap(),
        )
        .unwrap();
        assert_eq!(page.snapshot_height, 0);
        assert!(page.complete);
        assert!(page.envelopes.is_empty());

        noise
            .write_record(&mut stream, &replay_request.encode().unwrap())
            .unwrap();
        assert!(noise.read_record(&mut stream).is_err());

        drop(stream);
        shutdown.store(true, std::sync::atomic::Ordering::Release);
        let report = server.join().unwrap();
        assert_eq!(report.stats.authenticated_sessions, 1);
        assert_eq!(report.stats.requests_received, 3);
        assert_eq!(report.stats.handler_failures, 1);
        assert_eq!(report.stats.responses_written, 2);
    }

    #[test]
    fn qfp6_history_listener_sends_multichunk_page_as_separate_noise_records() {
        use crate::qrun_v06_history_sync_wire_candidate::{
            decode_q6hs_request, encode_q6hp_page_chunks, validate_q6hc_response_chunk,
            QRunV06HistorySyncRequest,
        };
        use crate::qrun_v06_noise_transport_candidate::QRunV06NoiseSession;
        use crate::qrun_v06_pow_fork_choice_candidate::QRunV06CanonicalHistoryPage;

        let (server_private, server_public) = keypair();
        let (client_private, client_public) = keypair();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = std::sync::Arc::new(AtomicBool::new(false));
        let server_shutdown = shutdown.clone();
        let server = thread::spawn(move || {
            let mut config = QRunV06PeerListenerConfig::default();
            config.max_sessions = 1;
            config.max_requests_per_session = 1;
            serve_qfp6_noise_listener_with_history(
                &listener,
                config,
                &server_private,
                &[client_public],
                &NETWORK,
                &PROFILE,
                &server_shutdown,
                |_guard, frame| {
                    let request = decode_q6hs_request(frame).map_err(|error| error.to_string())?;
                    let page = QRunV06CanonicalHistoryPage {
                        start_height: 1,
                        next_height: 2,
                        snapshot_height: 1,
                        snapshot_tip: request.snapshot_tip,
                        complete: true,
                        envelopes: vec![vec![0xA5; 100_000]],
                    };
                    encode_q6hp_page_chunks(&request, &page).map_err(|error| error.to_string())
                },
            )
            .unwrap()
        });

        let mut stream = TcpStream::connect(address).unwrap();
        stream.set_nodelay(true).unwrap();
        let mut noise = QRunV06NoiseSession::connect(
            &mut stream,
            &client_private,
            &server_public,
            &NETWORK,
            &PROFILE,
        )
        .unwrap();
        let request = QRunV06HistorySyncRequest {
            request_id: 9002,
            network_id: NETWORK,
            profile_id: PROFILE,
            snapshot_tip: [0x78; 32],
            expected_parent_consensus_hash: [0x55; 32],
            expected_parent_execution_hash: [0x56; 32],
            start_height: 1,
            max_blocks: 1,
            max_bytes: 128 * 1024,
        };
        noise
            .write_record(&mut stream, &request.encode().unwrap())
            .unwrap();
        let mut lengths = Vec::new();
        for index in 0..3u32 {
            let frame = noise.read_record(&mut stream).unwrap();
            validate_q6hc_response_chunk(&frame, request.request_id, &request.snapshot_tip, index)
                .unwrap();
            lengths.push(frame.len());
        }
        assert_eq!(
            lengths[0],
            crate::qrun_v06_history_sync_wire_candidate::Q6HC_CHUNK_HEADER_BYTES + 48 * 1024
        );
        assert_eq!(lengths[1], lengths[0]);
        assert!(lengths[2] < lengths[0]);

        drop(stream);
        shutdown.store(true, std::sync::atomic::Ordering::Release);
        let report = server.join().unwrap();
        assert_eq!(report.stats.requests_received, 1);
        assert_eq!(report.stats.responses_written, 3);
    }
}
