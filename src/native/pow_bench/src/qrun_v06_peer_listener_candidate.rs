//! CP-0555 bounded QFP6 authenticated peer-listener lifecycle candidate.
//!
//! This module provides a deliberately serial (one active peer at a time), bounded
//! TCP accept/session loop. It rejects wildcard/public bind addresses, authenticates
//! peers with the CP-0552 pinned Noise XX transport, creates one replay guard per
//! authenticated connection, caps accepted sessions and requests, validates Q6PA
//! responses, and stops on an explicit shutdown flag.
//!
//! It is a library service candidate, not a node binary, production supervisor, miner,
//! RPC endpoint, mempool, or Mainnet release. External trust-provider callbacks must
//! enforce their own bounded network deadlines. Only private/overlay/loopback binding
//! is supported by this first operational qualification stage.

use crate::{
    external_cas_anchor_candidate::ExternalCasProviderTransport,
    qrun_v06_node_runtime_candidate::{
        decode_qrun_v06_peer_block_request, process_qrun_v06_peer_block_frame,
        process_qrun_v06_peer_block_frame_with_qap1, QRunV06NodeAnchorGate, QRunV06NodeRuntime,
        QRunV06PeerAdmissionResponse, QRunV06PeerAdmissionStatus, QRunV06PeerIngressError,
        QRunV06PeerReplayGuard, QRUN_V06_PEER_ADMISSION_MAGIC,
        QRUN_V06_PEER_ADMISSION_RESPONSE_BYTES, QRUN_V06_PEER_FRAME_VERSION,
    },
    qrun_v06_noise_transport_candidate::{QRunV06NoiseError, QRunV06NoiseSession},
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
    /// The maximum number of encrypted Q6PB/Q6PA exchanges on one authenticated session.
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

fn validate_q6pa_response(
    response: &[u8; QRUN_V06_PEER_ADMISSION_RESPONSE_BYTES],
    expected_request_id: u64,
) -> bool {
    if response[..4] != QRUN_V06_PEER_ADMISSION_MAGIC
        || u16::from_be_bytes([response[4], response[5]]) != QRUN_V06_PEER_FRAME_VERSION
        || u64::from_be_bytes(response[8..16].try_into().unwrap()) != expected_request_id
        || !matches!(u16::from_be_bytes([response[6], response[7]]), 1..=3)
    {
        return false;
    }
    let status = u16::from_be_bytes([response[6], response[7]]);
    if status != QRunV06PeerAdmissionStatus::Accepted as u16
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
            let request = match decode_qrun_v06_peer_block_request(&frame) {
                Ok(request) => request,
                Err(_) => {
                    stats.handler_failures += 1;
                    break;
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
            if !validate_q6pa_response(&response, request.request_id) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qrun_v06_node_runtime_candidate::{
        encode_qrun_v06_peer_block_request, QRUN_V06_PEER_ADMISSION_MAGIC,
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
}
