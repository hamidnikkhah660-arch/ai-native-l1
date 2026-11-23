//! CP-0597 one-snapshot QFP6 history responder and Noise page client.
//!
//! This module connects the CP-0596 bounded page codec to the permissionless durable runtime.
//! The responder retains at most one immutable fork-choice snapshot so subsequent page requests
//! can continue against the same canonical tip while the live node advances.

use crate::qrun_v06_peer_listener_candidate::{
    serve_qfp6_noise_listener_with_history, QRunV06PeerListenerConfig, QRunV06PeerListenerError,
    QRunV06PeerListenerReport,
};
use crate::{
    consensus::pow_digest,
    external_cas_anchor_candidate::ExternalCasProviderTransport,
    qrun_v06_history_sync_wire_candidate::{
        decode_q6hi_request, decode_q6hr_status, decode_q6hs_request, encode_q6hp_page_chunks,
        encode_q6hr_status, Q6HistorySyncWireError, QRunV06HistoryInfoRequest,
        QRunV06HistoryPageChunkAssembler, QRunV06HistorySyncRequest, Q6HI_REQUEST_MAGIC,
        Q6HS_REQUEST_MAGIC,
    },
    qrun_v06_node_runtime_candidate::{
        QRunV06NodeAdmission, QRunV06NodeRuntime, QRunV06NodeRuntimeError,
    },
    qrun_v06_noise_transport_candidate::{QRunV06NoiseError, QRunV06NoiseIo, QRunV06NoiseSession},
    qrun_v06_permissionless_runtime_candidate::{
        QRunV06HistorySyncError, QRunV06HistorySyncReport, QRunV06PermissionlessNodeRuntime,
        QRunV06PermissionlessRuntimeError,
    },
    qrun_v06_pow_fork_choice_candidate::{
        QRunV06CanonicalHistoryPage, QRunV06QuoteAssetAuthorizationProvider,
    },
    qrun_v06_pow_wire_candidate::decode_qrun_v06_pow_block,
    qrun_v06_qap1_coordinator_candidate::{
        QRunV06Qap1AnchorTransport, QRunV06Qap1ExternalCoordinator,
    },
    state_machine::TransactionAuthenticator,
    v4_fat1_trust_candidate::MlDsa65Verifier,
};
use rustls::{pki_types::ServerName, ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use std::{
    net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs},
    sync::{atomic::AtomicBool, Arc, OnceLock},
    time::Duration,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QRunV06HistorySyncServiceError {
    Runtime(String),
    Wire(String),
    Noise(String),
    SnapshotUnavailable,
    WrongNetwork,
    WrongProfile,
    PageDoesNotContinueLocalTip,
    PageDoesNotMatchSnapshot,
    EmptyPage,
    InvalidClientConfig,
    SourceBehind,
    SnapshotMismatch,
    NoProgress,
    PageBudgetExceeded,
    PeerDiscovery(String),
}

impl std::fmt::Display for QRunV06HistorySyncServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "QFP6 history-sync service failed: {self:?}")
    }
}
impl std::error::Error for QRunV06HistorySyncServiceError {}

fn public_relay_tls_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    Arc::clone(CONFIG.get_or_init(|| {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    }))
}

/// Open direct Noise/TCP or a certificate-verified TLS/SNI tunnel to a TCP/443 relay.
/// Funnel terminates outer TLS and forwards the unchanged inner Noise bytes.
fn connect_history_sync_stream(
    address: SocketAddr,
    tls_server_name: Option<&str>,
    config: QRunV06HistorySyncClientConfig,
) -> Result<Box<dyn QRunV06NoiseIo>, QRunV06HistorySyncServiceError> {
    let tls_config = tls_server_name.map(|_| public_relay_tls_config());
    connect_history_sync_stream_with_tls_config(address, tls_server_name, config, tls_config)
}

fn connect_history_sync_stream_with_tls_config(
    address: SocketAddr,
    tls_server_name: Option<&str>,
    config: QRunV06HistorySyncClientConfig,
    tls_config: Option<Arc<ClientConfig>>,
) -> Result<Box<dyn QRunV06NoiseIo>, QRunV06HistorySyncServiceError> {
    let mut tcp = TcpStream::connect_timeout(&address, config.connect_timeout)
        .map_err(|error| QRunV06HistorySyncServiceError::Noise(error.to_string()))?;
    tcp.set_read_timeout(Some(config.io_timeout))
        .map_err(|error| QRunV06HistorySyncServiceError::Noise(error.to_string()))?;
    tcp.set_write_timeout(Some(config.io_timeout))
        .map_err(|error| QRunV06HistorySyncServiceError::Noise(error.to_string()))?;
    tcp.set_nodelay(true)
        .map_err(|error| QRunV06HistorySyncServiceError::Noise(error.to_string()))?;
    match tls_server_name {
        None => Ok(Box::new(tcp)),
        Some(host) => {
            let server_name = ServerName::try_from(host.to_owned())
                .map_err(|error| QRunV06HistorySyncServiceError::Noise(error.to_string()))?;
            let tls_config =
                tls_config.ok_or(QRunV06HistorySyncServiceError::InvalidClientConfig)?;
            let mut connection = ClientConnection::new(tls_config, server_name)
                .map_err(|error| QRunV06HistorySyncServiceError::Noise(error.to_string()))?;
            // Complete the authenticated outer TLS/SNI tunnel before starting the inner
            // eight-second Noise XX handshake budget. Funnel terminates TLS and forwards
            // only the inner Noise byte stream to the Seed; keeping these phases separate
            // makes relay/TLS failures distinguishable from Noise handshake failures.
            let tls_started = std::time::Instant::now();
            while connection.is_handshaking() {
                connection.complete_io(&mut tcp).map_err(|error| {
                    QRunV06HistorySyncServiceError::Noise(format!(
                        "TLS relay handshake failed for {host}: {error}"
                    ))
                })?;
            }
            eprintln!(
                "QFP6_SYNC_DIAG tls_relay_handshake_established server_name={} elapsed_ms={}",
                host,
                tls_started.elapsed().as_millis()
            );
            Ok(Box::new(StreamOwned::new(connection, tcp)))
        }
    }
}

// Retry only a transient Noise handshake timeout. The public Seed listener is served in
// finite rounds; a Funnel connection arriving at a round boundary can be accepted too late
// for the 8-second Noise handshake budget. Trust, domain, and malformed-handshake failures
// remain immediate fail-closed errors.
const QFP6_HISTORY_SYNC_MAX_NOISE_HANDSHAKE_ATTEMPTS: usize = 8;

fn is_retryable_history_sync_noise_io_message(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("peer closed connection without sending tls close_notify")
        || message.contains("connection reset by peer")
        || message.contains("broken pipe")
        || message.contains("unexpected eof")
}

fn is_retryable_history_sync_handshake_error(error: &QRunV06NoiseError) -> bool {
    match error {
        QRunV06NoiseError::HandshakeTimeout => true,
        QRunV06NoiseError::Io(message) => is_retryable_history_sync_noise_io_message(message),
        _ => false,
    }
}

const QFP6_HISTORY_SYNC_MAX_TRANSIENT_TRANSPORT_RETRIES: usize = 8;

fn is_retryable_history_sync_transport_error(error: &QRunV06HistorySyncServiceError) -> bool {
    match error {
        QRunV06HistorySyncServiceError::Noise(message) => {
            is_retryable_history_sync_noise_io_message(message)
        }
        _ => false,
    }
}

fn history_sync_transport_retry_backoff(attempt: usize) -> Duration {
    match attempt {
        0 => Duration::from_millis(250),
        1 => Duration::from_millis(500),
        2 => Duration::from_secs(1),
        3 => Duration::from_secs(2),
        4 => Duration::from_secs(4),
        5 => Duration::from_secs(8),
        _ => Duration::from_secs(15),
    }
}

pub(crate) fn connect_history_sync_noise_session_with_bounded_retry(
    address: SocketAddr,
    tls_server_name: Option<&str>,
    config: QRunV06HistorySyncClientConfig,
    local_static_private_key: &[u8; 32],
    remote_static_public_key: &[u8; 32],
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
) -> Result<(Box<dyn QRunV06NoiseIo>, QRunV06NoiseSession), QRunV06HistorySyncServiceError> {
    for attempt in 0..QFP6_HISTORY_SYNC_MAX_NOISE_HANDSHAKE_ATTEMPTS {
        eprintln!(
            "QFP6_SYNC_DIAG noise_handshake_attempt address={} attempt={} max_attempts={}",
            address,
            attempt + 1,
            QFP6_HISTORY_SYNC_MAX_NOISE_HANDSHAKE_ATTEMPTS
        );
        let mut stream = match connect_history_sync_stream(address, tls_server_name, config) {
            Ok(stream) => stream,
            Err(error)
                if is_retryable_history_sync_transport_error(&error)
                    && attempt + 1 < QFP6_HISTORY_SYNC_MAX_NOISE_HANDSHAKE_ATTEMPTS =>
            {
                let backoff = history_sync_transport_retry_backoff(attempt);
                eprintln!(
                    "QFP6_SYNC_DIAG noise_handshake_connect_retry address={} attempt={} retry_backoff_ms={} error={error:?}",
                    address,
                    attempt + 1,
                    backoff.as_millis()
                );
                std::thread::sleep(backoff);
                continue;
            }
            Err(error) => return Err(error),
        };
        match QRunV06NoiseSession::connect(
            stream.as_mut(),
            local_static_private_key,
            remote_static_public_key,
            network_id,
            profile_id,
        ) {
            Ok(noise) => {
                eprintln!(
                    "QFP6_SYNC_DIAG noise_handshake_established address={} attempt={}",
                    address,
                    attempt + 1
                );
                return Ok((stream, noise));
            }
            Err(error)
                if is_retryable_history_sync_handshake_error(&error)
                    && attempt + 1 < QFP6_HISTORY_SYNC_MAX_NOISE_HANDSHAKE_ATTEMPTS =>
            {
                let backoff = history_sync_transport_retry_backoff(attempt);
                eprintln!(
                    "QFP6_SYNC_DIAG noise_handshake_retry address={} attempt={} retry_backoff_ms={} error={error:?}",
                    address,
                    attempt + 1,
                    backoff.as_millis()
                );
                std::thread::sleep(backoff);
            }
            Err(error) => {
                eprintln!(
                    "QFP6_SYNC_DIAG noise_handshake_failed address={} attempt={} error={error:?}",
                    address,
                    attempt + 1
                );
                return Err(error.into());
            }
        }
    }

    Err(QRunV06HistorySyncServiceError::Noise(
        "Noise handshake timed out after bounded retries".into(),
    ))
}

/// Bitcoin-style feeler: open one short-lived transport and complete the exact pinned Noise
/// handshake, then close without requesting history or changing the local chain state.
pub fn probe_q6pd_pinned_peer(
    address: SocketAddr,
    local_static_private_key: &[u8; 32],
    remote_static_public_key: &[u8; 32],
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
    tls_server_name: Option<&str>,
    config: QRunV06HistorySyncClientConfig,
) -> Result<(), QRunV06HistorySyncServiceError> {
    config.validate()?;
    let mut stream = connect_history_sync_stream(address, tls_server_name, config)?;
    let noise = crate::qrun_v06_noise_transport_candidate::QRunV06NoiseSession::connect(
        stream.as_mut(),
        local_static_private_key,
        remote_static_public_key,
        network_id,
        profile_id,
    )?;
    if !noise.remote_static_key_pinned()
        || noise.remote_static_public_key() != remote_static_public_key
    {
        return Err(QRunV06HistorySyncServiceError::PeerDiscovery(
            "Q6PD feeler did not authenticate the expected Noise peer pin".into(),
        ));
    }
    drop(noise);
    drop(stream);
    Ok(())
}

impl From<Q6HistorySyncWireError> for QRunV06HistorySyncServiceError {
    fn from(value: Q6HistorySyncWireError) -> Self {
        Self::Wire(value.to_string())
    }
}
impl From<QRunV06NoiseError> for QRunV06HistorySyncServiceError {
    fn from(value: QRunV06NoiseError) -> Self {
        Self::Noise(value.to_string())
    }
}
impl From<QRunV06PermissionlessRuntimeError> for QRunV06HistorySyncServiceError {
    fn from(value: QRunV06PermissionlessRuntimeError) -> Self {
        Self::Runtime(value.to_string())
    }
}
impl From<QRunV06HistorySyncError> for QRunV06HistorySyncServiceError {
    fn from(value: QRunV06HistorySyncError) -> Self {
        Self::Runtime(value.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06HistorySnapshotInfo {
    pub height: u64,
    pub consensus_tip: [u8; 32],
    pub execution_tip: [u8; 32],
    pub base_height: u64,
    pub base_consensus_tip: [u8; 32],
    pub base_execution_tip: [u8; 32],
}

/// One-peer responder state. At most one immutable fork-choice snapshot is retained.
/// A request for a different snapshot is accepted only if it names the node's current tip;
/// otherwise the peer must restart from a fresh status/tip observation.
#[derive(Default)]
pub struct QRunV06HistorySyncResponder {
    snapshot: Option<crate::qrun_v06_pow_fork_choice_candidate::QRunV06PowForkChoice>,
}

impl QRunV06HistorySyncResponder {
    /// Capture and pin the exact current canonical snapshot before advertising its tip.
    /// Subsequent Q6HS pages may continue against this immutable view while mining advances.
    pub fn pin_current_snapshot(
        &mut self,
        runtime: &QRunV06PermissionlessNodeRuntime,
    ) -> Result<QRunV06HistorySnapshotInfo, QRunV06HistorySyncServiceError> {
        // Retain one immutable source snapshot across the client's bounded reconnect windows.
        // A new mining block must not silently change Q6HR while a client is paging the old tip.
        if let Some(snapshot) = self.snapshot.as_ref() {
            let tip = snapshot.canonical_tip();
            let base_consensus_tip = snapshot.base_tip();
            let base_state = snapshot
                .state_for_tip(&base_consensus_tip)
                .ok_or(QRunV06HistorySyncServiceError::SnapshotUnavailable)?;
            return Ok(QRunV06HistorySnapshotInfo {
                height: tip.height,
                consensus_tip: tip.tip_hash,
                execution_tip: snapshot.canonical_state().tip_hash(),
                base_height: base_state.height(),
                base_consensus_tip,
                base_execution_tip: base_state.tip_hash(),
            });
        }
        let status = runtime.status()?;
        let snapshot = runtime.fork_choice_snapshot()?;
        let consensus_tip = snapshot.canonical_tip().tip_hash;
        if consensus_tip != status.tip {
            return Err(QRunV06HistorySyncServiceError::SnapshotUnavailable);
        }
        let base_consensus_tip = snapshot.base_tip();
        let base_state = snapshot
            .state_for_tip(&base_consensus_tip)
            .ok_or(QRunV06HistorySyncServiceError::SnapshotUnavailable)?;
        let base_height = base_state.height();
        let base_execution_tip = base_state.tip_hash();
        let execution_tip = snapshot.canonical_state().tip_hash();
        self.snapshot = Some(snapshot);
        Ok(QRunV06HistorySnapshotInfo {
            height: status.height,
            consensus_tip,
            execution_tip,
            base_height,
            base_consensus_tip,
            base_execution_tip,
        })
    }

    pub fn retained_snapshot_tip(&self) -> Option<[u8; 32]> {
        self.snapshot
            .as_ref()
            .map(|snapshot| snapshot.canonical_tip().tip_hash)
    }

    pub fn respond(
        &mut self,
        runtime: &QRunV06PermissionlessNodeRuntime,
        request: &QRunV06HistorySyncRequest,
    ) -> Result<Vec<Vec<u8>>, QRunV06HistorySyncServiceError> {
        request.validate()?;
        let status = runtime.status()?;
        if request.network_id != status.network_id {
            return Err(QRunV06HistorySyncServiceError::WrongNetwork);
        }
        if request.profile_id != status.profile_id {
            return Err(QRunV06HistorySyncServiceError::WrongProfile);
        }

        let retained_matches = self
            .snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot.canonical_tip().tip_hash == request.snapshot_tip);
        if !retained_matches {
            if status.tip != request.snapshot_tip {
                return Err(QRunV06HistorySyncServiceError::SnapshotUnavailable);
            }
            self.snapshot = Some(runtime.fork_choice_snapshot()?);
        }

        let snapshot = self
            .snapshot
            .as_ref()
            .ok_or(QRunV06HistorySyncServiceError::SnapshotUnavailable)?;
        if snapshot.canonical_tip().tip_hash != request.snapshot_tip {
            return Err(QRunV06HistorySyncServiceError::SnapshotUnavailable);
        }
        let page = snapshot
            .canonical_history_page(
                request.start_height,
                usize::from(request.max_blocks),
                request.max_bytes as usize,
            )
            .map_err(|error| QRunV06HistorySyncServiceError::Runtime(error.to_string()))?;
        let complete = page.complete;
        let chunks = encode_q6hp_page_chunks(request, &page)?;
        // Release only after the final page has been encoded. The next Q6HI then pins a fresh tip.
        if complete {
            self.clear_snapshot();
        }
        Ok(chunks)
    }

    pub fn clear_snapshot(&mut self) {
        self.snapshot = None;
    }
}

/// Bind the Q6HS/Q6HC listener directly to the permissionless durable runtime.
/// The responder and its one retained snapshot live for this listener invocation.
pub fn serve_permissionless_history_sync_listener(
    listener: &TcpListener,
    config: QRunV06PeerListenerConfig,
    local_static_private_key: &[u8; 32],
    trusted_remote_static_public_keys: &[[u8; 32]],
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
    shutdown: &AtomicBool,
    runtime: &QRunV06PermissionlessNodeRuntime,
) -> Result<QRunV06PeerListenerReport, QRunV06PeerListenerError> {
    let mut responder = QRunV06HistorySyncResponder::default();
    serve_qfp6_noise_listener_with_history(
        listener,
        config,
        local_static_private_key,
        trusted_remote_static_public_keys,
        network_id,
        profile_id,
        shutdown,
        |_replay_guard, frame| {
            if frame.get(..4) == Some(&Q6HI_REQUEST_MAGIC) {
                let request = decode_q6hi_request(frame)
                    .map_err(|error| format!("Q6HI request rejected: {error}"))?;
                let snapshot = responder
                    .pin_current_snapshot(runtime)
                    .map_err(|error| format!("cannot pin Q6HR source snapshot: {error}"))?;
                let status = encode_q6hr_status(
                    &request,
                    snapshot.height,
                    snapshot.consensus_tip,
                    snapshot.execution_tip,
                    snapshot.base_height,
                    snapshot.base_consensus_tip,
                    snapshot.base_execution_tip,
                )
                .map_err(|error| format!("cannot encode Q6HR status: {error}"))?;
                Ok(vec![status.to_vec()])
            } else if frame.get(..4) == Some(&Q6HS_REQUEST_MAGIC) {
                let request = decode_q6hs_request(frame)
                    .map_err(|error| format!("Q6HS request rejected: {error}"))?;
                responder
                    .respond(runtime, &request)
                    .map_err(|error| error.to_string())
            } else {
                Err("unsupported application frame on history-only listener".into())
            }
        },
    )
}

/// Build the next-page request from the destination node's exact durable tip.
/// The caller supplies the source's snapshot tip from an independently authenticated status
/// observation; this function never guesses or trusts an unpinned remote height.
pub fn make_next_history_request(
    runtime: &QRunV06PermissionlessNodeRuntime,
    request_id: u64,
    source_snapshot_tip: [u8; 32],
    max_blocks: u16,
    max_bytes: u32,
) -> Result<QRunV06HistorySyncRequest, QRunV06HistorySyncServiceError> {
    let status = runtime.status()?;
    let graph = runtime.fork_choice_snapshot()?;
    let request = QRunV06HistorySyncRequest {
        request_id,
        network_id: status.network_id,
        profile_id: status.profile_id,
        snapshot_tip: source_snapshot_tip,
        expected_parent_consensus_hash: status.tip,
        expected_parent_execution_hash: graph.canonical_state().tip_hash(),
        start_height: status.height.checked_add(1).ok_or_else(|| {
            QRunV06HistorySyncServiceError::Runtime("local height overflow".into())
        })?,
        max_blocks,
        max_bytes,
    };
    request.validate()?;
    Ok(request)
}

/// Exchange one Q6HS request for a complete, checksum-verified canonical page over an
/// already-authenticated Noise session. Every Q6HC chunk is read as a separate bounded record.
pub fn request_history_page_over_noise(
    noise: &mut QRunV06NoiseSession,
    stream: &mut dyn QRunV06NoiseIo,
    request: QRunV06HistorySyncRequest,
    params: crate::consensus::ConsensusParameters,
) -> Result<QRunV06CanonicalHistoryPage, QRunV06HistorySyncServiceError> {
    let request_id = request.request_id;
    let start_height = request.start_height;
    let max_blocks = request.max_blocks;
    let encoded = request.encode()?;
    eprintln!(
        "QFP6_SYNC_DIAG history_request_send request_id={} start_height={} max_blocks={} max_bytes={}",
        request_id,
        start_height,
        max_blocks,
        request.max_bytes
    );
    if let Err(error) = noise.write_record(stream, &encoded) {
        eprintln!(
            "QFP6_SYNC_DIAG history_request_write_failed request_id={} error={error:?}",
            request_id
        );
        return Err(error.into());
    }
    eprintln!(
        "QFP6_SYNC_DIAG history_request_sent request_id={} start_height={}",
        request_id, start_height
    );
    let mut assembler = QRunV06HistoryPageChunkAssembler::new(request, params)?;
    let mut received_chunks = 0usize;
    for _ in 0..crate::qrun_v06_history_sync_wire_candidate::Q6_HISTORY_SYNC_MAX_CHUNKS {
        let frame = match noise.read_record(stream) {
            Ok(frame) => frame,
            Err(error) => {
                eprintln!(
                    "QFP6_SYNC_DIAG history_chunk_read_failed request_id={} received_chunks={} error={error:?}",
                    request_id,
                    received_chunks
                );
                return Err(error.into());
            }
        };
        let frame_bytes = frame.len();
        eprintln!(
            "QFP6_SYNC_DIAG history_chunk_received request_id={} chunk_index={} bytes={} magic={:02x?}",
            request_id,
            received_chunks,
            frame_bytes,
            frame.get(..4).unwrap_or_default()
        );
        match assembler.push(&frame) {
            Ok(Some(page)) => {
                received_chunks += 1;
                eprintln!(
                    "QFP6_SYNC_DIAG history_page_verified request_id={} chunks={} start_height={} next_height={} snapshot_height={} blocks={} complete={}",
                    request_id,
                    received_chunks,
                    page.start_height,
                    page.next_height,
                    page.snapshot_height,
                    page.envelopes.len(),
                    page.complete
                );
                return Ok(page);
            }
            Ok(None) => received_chunks += 1,
            Err(error) => {
                eprintln!(
                    "QFP6_SYNC_DIAG history_chunk_rejected request_id={} chunk_index={} bytes={} error={error:?}",
                    request_id,
                    received_chunks,
                    frame_bytes
                );
                return Err(error.into());
            }
        }
    }
    eprintln!(
        "QFP6_SYNC_DIAG history_chunk_budget_exhausted request_id={} received_chunks={}",
        request_id, received_chunks
    );
    Err(QRunV06HistorySyncServiceError::Wire(
        "Q6HC chunk budget exhausted before a complete page arrived".into(),
    ))
}

/// Import one fully decoded page. The durable CP-0594 store independently rechecks PoW,
/// consensus, execution, state roots and persistence; this function does not bypass it.
pub fn import_history_page<A: TransactionAuthenticator>(
    runtime: &mut QRunV06PermissionlessNodeRuntime,
    page: &QRunV06CanonicalHistoryPage,
    authenticator: &A,
) -> Result<QRunV06HistorySyncReport, QRunV06HistorySyncServiceError> {
    if page.envelopes.is_empty() {
        return Err(QRunV06HistorySyncServiceError::EmptyPage);
    }
    let status = runtime.status()?;
    if page.start_height != status.height.saturating_add(1) || page.envelopes.first().is_none() {
        return Err(QRunV06HistorySyncServiceError::PageDoesNotContinueLocalTip);
    }
    let expected_next = page
        .start_height
        .checked_add(page.envelopes.len() as u64)
        .ok_or(QRunV06HistorySyncServiceError::PageDoesNotMatchSnapshot)?;
    let after_snapshot = page
        .snapshot_height
        .checked_add(1)
        .ok_or(QRunV06HistorySyncServiceError::PageDoesNotMatchSnapshot)?;
    if page.next_height != expected_next
        || page.complete != (page.next_height > page.snapshot_height)
        || (page.complete && page.next_height != after_snapshot)
        || (!page.complete && page.next_height > page.snapshot_height)
    {
        return Err(QRunV06HistorySyncServiceError::PageDoesNotMatchSnapshot);
    }
    if page.complete {
        let graph = runtime.fork_choice_snapshot()?;
        let last = decode_qrun_v06_pow_block(page.envelopes.last().unwrap())
            .map_err(|error| QRunV06HistorySyncServiceError::Wire(error.to_string()))?;
        let final_digest = pow_digest(&last.header, graph.consensus_parameters().pow)
            .map_err(|error| QRunV06HistorySyncServiceError::Wire(error.to_string()))?;
        if final_digest != page.snapshot_tip || page.snapshot_height != expected_next - 1 {
            return Err(QRunV06HistorySyncServiceError::PageDoesNotMatchSnapshot);
        }
    }
    let report = runtime.import_history_batch(&page.envelopes, authenticator)?;
    if page.complete
        && (report.resulting_height != page.snapshot_height
            || report.resulting_tip != page.snapshot_tip)
    {
        return Err(QRunV06HistorySyncServiceError::PageDoesNotMatchSnapshot);
    }
    Ok(report)
}

/// Import a page from a peer's canonical history onto the exact known parent branch.
/// This is the branch-aware counterpart to `import_history_page`, which only accepts an
/// extension of the current canonical tip.
pub fn import_history_branch_page<A: TransactionAuthenticator>(
    runtime: &mut QRunV06PermissionlessNodeRuntime,
    request: &QRunV06HistorySyncRequest,
    page: &QRunV06CanonicalHistoryPage,
    authenticator: &A,
) -> Result<QRunV06HistorySyncReport, QRunV06HistorySyncServiceError> {
    import_history_branch_page_with_quote_asset_authorization(
        runtime,
        request,
        page,
        authenticator,
        None,
    )
}

pub fn import_history_branch_page_with_quote_asset_authorization<A: TransactionAuthenticator>(
    runtime: &mut QRunV06PermissionlessNodeRuntime,
    request: &QRunV06HistorySyncRequest,
    page: &QRunV06CanonicalHistoryPage,
    authenticator: &A,
    mut quote_authorizer: Option<&mut QRunV06QuoteAssetAuthorizationProvider<'_>>,
) -> Result<QRunV06HistorySyncReport, QRunV06HistorySyncServiceError> {
    request.validate()?;
    if page.envelopes.is_empty() {
        return Err(QRunV06HistorySyncServiceError::EmptyPage);
    }
    let status = runtime.status()?;
    if request.network_id != status.network_id {
        return Err(QRunV06HistorySyncServiceError::WrongNetwork);
    }
    if request.profile_id != status.profile_id {
        return Err(QRunV06HistorySyncServiceError::WrongProfile);
    }
    let expected_next = page
        .start_height
        .checked_add(page.envelopes.len() as u64)
        .ok_or(QRunV06HistorySyncServiceError::PageDoesNotMatchSnapshot)?;
    let after_snapshot = page
        .snapshot_height
        .checked_add(1)
        .ok_or(QRunV06HistorySyncServiceError::PageDoesNotMatchSnapshot)?;
    if page.start_height != request.start_height
        || page.snapshot_tip != request.snapshot_tip
        || page.next_height != expected_next
        || page.complete != (page.next_height > page.snapshot_height)
        || (page.complete && page.next_height != after_snapshot)
        || (!page.complete && page.next_height > page.snapshot_height)
    {
        return Err(QRunV06HistorySyncServiceError::PageDoesNotMatchSnapshot);
    }
    if page.complete {
        let graph = runtime.fork_choice_snapshot()?;
        let last = decode_qrun_v06_pow_block(page.envelopes.last().unwrap())
            .map_err(|error| QRunV06HistorySyncServiceError::Wire(error.to_string()))?;
        let final_digest = pow_digest(&last.header, graph.consensus_parameters().pow)
            .map_err(|error| QRunV06HistorySyncServiceError::Wire(error.to_string()))?;
        if final_digest != page.snapshot_tip || page.snapshot_height != expected_next - 1 {
            return Err(QRunV06HistorySyncServiceError::PageDoesNotMatchSnapshot);
        }
    }
    runtime
        .import_history_branch_batch_with_quote_asset_authorization(
            request.start_height,
            request.expected_parent_consensus_hash,
            request.expected_parent_execution_hash,
            &page.envelopes,
            authenticator,
            quote_authorizer.as_deref_mut(),
        )
        .map_err(Into::into)
}

/// Import a verified Q6HS page through QAP1. Every block is committed and acknowledged by
/// Provider/Q6EA before the next block is attempted. A partial failure leaves the exact
/// acknowledged prefix durable and requires restart recovery before more admission.
#[allow(clippy::too_many_arguments)]
pub fn import_history_page_with_qap1<A, P, PV, AV, Q, T>(
    runtime: &mut QRunV06NodeRuntime<A>,
    page: &QRunV06CanonicalHistoryPage,
    authenticator: &T,
    quote_authorizer: &mut QRunV06QuoteAssetAuthorizationProvider<'_>,
    coordinator: &mut QRunV06Qap1ExternalCoordinator<P, PV, AV, Q>,
) -> Result<QRunV06HistorySyncReport, QRunV06HistorySyncServiceError>
where
    A: crate::qrun_v06_node_runtime_candidate::QRunV06NodeAnchorGate,
    P: ExternalCasProviderTransport,
    PV: MlDsa65Verifier + Clone,
    AV: MlDsa65Verifier,
    Q: QRunV06Qap1AnchorTransport,
    T: TransactionAuthenticator,
{
    if !runtime.requires_qap1()
        || !runtime.qap1_recovery_verified()
        || runtime.requires_reopen()
        || runtime.has_pending_external_anchor()
    {
        return Err(QRunV06HistorySyncServiceError::Runtime(
            "QAP1 recovery/anchor gate is not in an admission-ready state".into(),
        ));
    }
    if page.envelopes.is_empty() {
        return Err(QRunV06HistorySyncServiceError::EmptyPage);
    }
    let before = runtime.committed_anchor_state();
    if page.start_height != before.canonical_height.saturating_add(1) {
        return Err(QRunV06HistorySyncServiceError::PageDoesNotContinueLocalTip);
    }
    let expected_next = page
        .start_height
        .checked_add(page.envelopes.len() as u64)
        .ok_or(QRunV06HistorySyncServiceError::PageDoesNotMatchSnapshot)?;
    let after_snapshot = page
        .snapshot_height
        .checked_add(1)
        .ok_or(QRunV06HistorySyncServiceError::PageDoesNotMatchSnapshot)?;
    if page.next_height != expected_next
        || page.complete != (page.next_height > page.snapshot_height)
        || (page.complete && page.next_height != after_snapshot)
        || (!page.complete && page.next_height > page.snapshot_height)
    {
        return Err(QRunV06HistorySyncServiceError::PageDoesNotMatchSnapshot);
    }
    let graph = runtime
        .fork_choice_snapshot()
        .map_err(|error: QRunV06NodeRuntimeError| {
            QRunV06HistorySyncServiceError::Runtime(error.to_string())
        })?;
    if before.canonical_tip != graph.canonical_tip().tip_hash {
        return Err(QRunV06HistorySyncServiceError::SnapshotMismatch);
    }
    if page.complete {
        let last = decode_qrun_v06_pow_block(page.envelopes.last().unwrap())
            .map_err(|error| QRunV06HistorySyncServiceError::Wire(error.to_string()))?;
        let final_digest = pow_digest(&last.header, graph.consensus_parameters().pow)
            .map_err(|error| QRunV06HistorySyncServiceError::Wire(error.to_string()))?;
        if final_digest != page.snapshot_tip || page.snapshot_height != expected_next - 1 {
            return Err(QRunV06HistorySyncServiceError::PageDoesNotMatchSnapshot);
        }
    }
    for envelope in &page.envelopes {
        match runtime.submit_envelope_with_qap1(
            envelope,
            authenticator,
            quote_authorizer,
            coordinator,
        ) {
            Ok(QRunV06NodeAdmission::Acknowledged(_)) => {}
            Ok(QRunV06NodeAdmission::ExternalAnchorPending(_)) => {
                return Err(QRunV06HistorySyncServiceError::Runtime(
                    "QAP1 page import stopped: external anchor pending; no further block admitted"
                        .into(),
                ));
            }
            Err(error) => return Err(QRunV06HistorySyncServiceError::Runtime(error.to_string())),
        }
    }
    let after = runtime.committed_anchor_state();
    if page.complete
        && (after.canonical_height != page.snapshot_height
            || after.canonical_tip != page.snapshot_tip)
    {
        return Err(QRunV06HistorySyncServiceError::PageDoesNotMatchSnapshot);
    }
    Ok(QRunV06HistorySyncReport {
        imported_blocks: page.envelopes.len(),
        resulting_height: after.canonical_height,
        resulting_tip: after.canonical_tip,
        resulting_state_root: after.canonical_state_root,
    })
}
/// Bounds for one statically pinned peer bootstrap/synchronization attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QRunV06HistorySyncClientConfig {
    pub connect_timeout: Duration,
    pub io_timeout: Duration,
    pub max_blocks_per_page: u16,
    pub max_bytes_per_page: u32,
    /// Page requests per Noise session; one additional request is used for Q6HI status.
    pub max_pages: u32,
    /// Bounded reconnect rounds; each round obtains and pins a fresh Q6HR source snapshot.
    pub max_rounds: u32,
}

impl Default for QRunV06HistorySyncClientConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            io_timeout: Duration::from_secs(30),
            max_blocks_per_page: 128,
            max_bytes_per_page: 16 * 1024 * 1024,
            max_pages: 15,
            max_rounds: 64,
        }
    }
}

impl QRunV06HistorySyncClientConfig {
    pub fn validate(&self) -> Result<(), QRunV06HistorySyncServiceError> {
        if self.connect_timeout.is_zero()
            || self.io_timeout.is_zero()
            || self.max_blocks_per_page == 0
            || usize::from(self.max_blocks_per_page)
                > crate::qrun_v06_history_sync_wire_candidate::Q6_HISTORY_SYNC_MAX_BLOCKS
            || self.max_bytes_per_page == 0
            || self.max_bytes_per_page as usize
                > crate::qrun_v06_history_sync_wire_candidate::Q6_HISTORY_SYNC_MAX_BYTES
            || !(1..=15).contains(&self.max_pages)
            || !(1..=1024).contains(&self.max_rounds)
        {
            return Err(QRunV06HistorySyncServiceError::InvalidClientConfig);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06HistorySyncClientReport {
    pub source_height: u64,
    pub final_height: u64,
    pub pages_imported: u32,
    pub blocks_imported: u64,
    pub source_tip: [u8; 32],
    pub source_execution_tip: [u8; 32],
    pub complete: bool,
}

/// Pull one bounded peer-candidate inventory from an operator-pinned relay. The relay's
/// static key is verified by the Noise handshake and the address-book policy independently
/// enforces its assigned trust domain, replay protection, TTL and quotas. Advertised peer
/// keys remain untrusted candidates; this function never approves or connects them.
pub fn pull_q6ar_candidates_from_pinned_peer(
    address: SocketAddr,
    local_static_private_key: &[u8; 32],
    remote_static_public_key: &[u8; 32],
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
    config: QRunV06HistorySyncClientConfig,
    tls_server_name: Option<&str>,
    address_book: &mut crate::qrun_v06_peer_address_manager_candidate::QRunV06PeerAddressBookCandidate,
    trust_domains: &crate::qrun_v06_bootstrap_trust_domain_candidate::BootstrapTrustDomainPolicy,
) -> Result<usize, QRunV06HistorySyncServiceError> {
    use crate::qrun_v06_peer_address_relay_candidate::{
        decode_q6ar_pull_response, encode_q6ar_pull_request, Q6arPullRequest,
        Q6arReceivedAdvertisement, Q6arRelayOrigin, Q6AR_MAX_ADDRESSES,
    };
    if local_static_private_key == &[0; 32]
        || remote_static_public_key == &[0; 32]
        || network_id == &[0; 32]
        || profile_id == &[0; 32]
    {
        return Err(QRunV06HistorySyncServiceError::InvalidClientConfig);
    }
    config.validate()?;
    let (mut stream, mut noise) = connect_history_sync_noise_session_with_bounded_retry(
        address,
        tls_server_name,
        config,
        local_static_private_key,
        remote_static_public_key,
        network_id,
        profile_id,
    )?;
    if !noise.remote_static_key_pinned()
        || noise.remote_static_public_key() != remote_static_public_key
    {
        return Err(QRunV06HistorySyncServiceError::PeerDiscovery(
            "Noise session did not authenticate the configured relay pin".into(),
        ));
    }
    let now_ms: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| {
            QRunV06HistorySyncServiceError::PeerDiscovery(format!(
                "system clock invalid for Q6AR: {error}"
            ))
        })?
        .as_millis()
        .try_into()
        .map_err(|_| {
            QRunV06HistorySyncServiceError::PeerDiscovery(
                "system clock exceeds Q6AR millisecond range".into(),
            )
        })?;
    let request = Q6arPullRequest {
        request_id: now_ms.max(1),
        network_id: *network_id,
        profile_id: *profile_id,
        max_addresses: Q6AR_MAX_ADDRESSES as u16,
    };
    let encoded = encode_q6ar_pull_request(&request)
        .map_err(|error| QRunV06HistorySyncServiceError::PeerDiscovery(error.to_string()))?;
    noise.write_record(stream.as_mut(), &encoded)?;
    let response_frame = noise.read_record(stream.as_mut())?;
    let response = decode_q6ar_pull_response(&response_frame, &request, now_ms / 1_000)
        .map_err(|error| QRunV06HistorySyncServiceError::PeerDiscovery(error.to_string()))?;
    let Some(advertisement) = response.advertisement else {
        eprintln!(
            "QFP6_DISCOVERY pinned_relay={} candidates_received=0 candidates_persisted=0",
            address
        );
        return Ok(0);
    };
    let received = Q6arReceivedAdvertisement {
        advertisement,
        relay_origin: Q6arRelayOrigin {
            relay_static_public_key: *noise.remote_static_public_key(),
            relay_static_key_pinned: noise.remote_static_key_pinned(),
        },
    };
    let accepted = address_book
        .ingest_pinned_q6ar_with_trust_domains(&received, now_ms, trust_domains)
        .map_err(|error| {
            QRunV06HistorySyncServiceError::PeerDiscovery(format!(
                "candidate address-book admission failed: {error}"
            ))
        })?;
    eprintln!(
        "QFP6_DISCOVERY pinned_relay={} candidates_received={} candidates_persisted={}",
        address,
        received.advertisement.addresses.len(),
        accepted
    );
    Ok(accepted)
}

/// Bounded peer-record exchange with one operator-pinned QFP6 peer over an authenticated Noise
/// session. Every signed record is checked against the exact network/profile and persisted using
/// the local Q6PD sequence-watermark store. Gossip never grants operator approval or dial rights.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Q6pdPeerDiscoveryReport {
    pub records_received: usize,
    pub records_inserted: usize,
    pub records_updated: usize,
    pub records_duplicate: usize,
    pub records_rejected: usize,
    /// Verified records actually accepted by the durable store, for source-aware AddrMan ingest.
    pub accepted_records: Vec<crate::qrun_v06_peer_discovery_candidate::VerifiedQ6pdPeerRecord>,
}

pub fn pull_q6pd_peer_records_from_pinned_peer(
    address: SocketAddr,
    local_static_private_key: &[u8; 32],
    remote_static_public_key: &[u8; 32],
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
    config: QRunV06HistorySyncClientConfig,
    tls_server_name: Option<&str>,
    max_records: u16,
    store: &mut crate::qrun_v06_peer_discovery_store_candidate::Q6pdPeerRecordStore,
) -> Result<Q6pdPeerDiscoveryReport, QRunV06HistorySyncServiceError> {
    pull_q6pd_peer_records_from_pinned_peer_with_announcement(
        address,
        local_static_private_key,
        remote_static_public_key,
        network_id,
        profile_id,
        config,
        tls_server_name,
        max_records,
        None,
        store,
    )
}

pub fn pull_q6pd_peer_records_from_pinned_peer_with_announcement(
    address: SocketAddr,
    local_static_private_key: &[u8; 32],
    remote_static_public_key: &[u8; 32],
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
    config: QRunV06HistorySyncClientConfig,
    tls_server_name: Option<&str>,
    max_records: u16,
    announce_record: Option<&[u8]>,
    store: &mut crate::qrun_v06_peer_discovery_store_candidate::Q6pdPeerRecordStore,
) -> Result<Q6pdPeerDiscoveryReport, QRunV06HistorySyncServiceError> {
    use crate::qrun_v06_peer_discovery_candidate::{
        decode_q6pd_announce_response, decode_q6pd_pull_response, encode_q6pd_announce_request,
        encode_q6pd_pull_request, verify_q6pd_peer_record, Q6pdPullRequest,
        Q6PD_MAX_RECORDS_PER_FRAME,
    };
    use crate::qrun_v06_peer_discovery_store_candidate::{Q6pdIngestResult, Q6pdStoreError};

    if local_static_private_key == &[0; 32]
        || remote_static_public_key == &[0; 32]
        || network_id == &[0; 32]
        || profile_id == &[0; 32]
        || max_records == 0
        || max_records as usize > Q6PD_MAX_RECORDS_PER_FRAME
    {
        return Err(QRunV06HistorySyncServiceError::InvalidClientConfig);
    }
    config.validate()?;
    let (mut stream, mut noise) = connect_history_sync_noise_session_with_bounded_retry(
        address,
        tls_server_name,
        config,
        local_static_private_key,
        remote_static_public_key,
        network_id,
        profile_id,
    )?;
    if !noise.remote_static_key_pinned()
        || noise.remote_static_public_key() != remote_static_public_key
    {
        return Err(QRunV06HistorySyncServiceError::PeerDiscovery(
            "Q6PD Noise session did not authenticate the configured peer pin".into(),
        ));
    }
    let now_ms: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| {
            QRunV06HistorySyncServiceError::PeerDiscovery(format!(
                "system clock invalid for Q6PD: {error}"
            ))
        })?
        .as_millis()
        .try_into()
        .map_err(|_| {
            QRunV06HistorySyncServiceError::PeerDiscovery(
                "system clock exceeds Q6PD millisecond range".into(),
            )
        })?;
    if let Some(record_wire) = announce_record {
        let local_record =
            verify_q6pd_peer_record(record_wire, network_id, profile_id, now_ms / 1_000).map_err(
                |error| {
                    QRunV06HistorySyncServiceError::PeerDiscovery(format!(
                        "local Q6PD self-announcement is invalid: {error}"
                    ))
                },
            )?;
        let announce_frame = encode_q6pd_announce_request(record_wire)
            .map_err(|error| QRunV06HistorySyncServiceError::PeerDiscovery(error.to_string()))?;
        noise.write_record(stream.as_mut(), &announce_frame)?;
        let announce_ack = noise.read_record(stream.as_mut())?;
        decode_q6pd_announce_response(&announce_ack).map_err(|error| {
            QRunV06HistorySyncServiceError::PeerDiscovery(format!(
                "Q6PD peer rejected local announcement: {error}"
            ))
        })?;
        eprintln!(
            "QFP6_Q6PD_SELF_RECORD_ANNOUNCED peer={} peer_id_prefix={:02x?}",
            address,
            &local_record.peer_id[..4]
        );
    }

    let request = Q6pdPullRequest {
        request_id: now_ms.max(1),
        network_id: *network_id,
        profile_id: *profile_id,
        max_records,
    };
    let request_frame = encode_q6pd_pull_request(&request)
        .map_err(|error| QRunV06HistorySyncServiceError::PeerDiscovery(error.to_string()))?;
    noise.write_record(stream.as_mut(), &request_frame)?;
    let response_frame = noise.read_record(stream.as_mut())?;
    let response = decode_q6pd_pull_response(&response_frame, &request, now_ms / 1000)
        .map_err(|error| QRunV06HistorySyncServiceError::PeerDiscovery(error.to_string()))?;

    let mut report = Q6pdPeerDiscoveryReport {
        records_received: response.record_wires.len(),
        ..Q6pdPeerDiscoveryReport::default()
    };
    for (record, wire) in response.records.iter().zip(&response.record_wires) {
        match store.ingest(wire, now_ms) {
            Ok(Q6pdIngestResult::Inserted) => {
                report.records_inserted += 1;
                report.accepted_records.push(record.clone());
            }
            Ok(Q6pdIngestResult::Updated) => {
                report.records_updated += 1;
                report.accepted_records.push(record.clone());
            }
            Ok(Q6pdIngestResult::Duplicate) => {
                report.records_duplicate += 1;
                report.accepted_records.push(record.clone());
            }
            Err(Q6pdStoreError::Replay)
            | Err(Q6pdStoreError::InvalidRecord(
                crate::qrun_v06_peer_discovery_candidate::Q6pdError::Expired,
            )) => {
                report.records_rejected += 1;
            }
            Err(error) => {
                return Err(QRunV06HistorySyncServiceError::PeerDiscovery(format!(
                    "Q6PD candidate persistence failed: {error}"
                )));
            }
        }
    }

    // After pulling the remote inventory, push our own bounded inventory over the same
    // exact-key-pinned Noise session. Older peers may not know Q6PX yet; that is a
    // peer-local capability miss and does not discard the successful pull above.
    let gossip_wires = store.gossip_record_wires(
        now_ms,
        crate::qrun_v06_peer_discovery_candidate::Q6PD_MAX_RECORDS_PER_FRAME,
    );
    if !gossip_wires.is_empty() {
        if let Some(gossip_request_id) = request.request_id.checked_add(1) {
            match crate::qrun_v06_peer_discovery_candidate::encode_q6pd_gossip_push_request(
                gossip_request_id,
                network_id,
                profile_id,
                &gossip_wires,
                now_ms / 1_000,
            ) {
                Ok(gossip_frame) => {
                    if let Err(error) = noise.write_record(stream.as_mut(), &gossip_frame) {
                        eprintln!(
                            "QFP6_Q6PD_GOSSIP_PUSH_UNAVAILABLE peer={} stage=write error={error:?}",
                            address
                        );
                    } else {
                        match noise.read_record(stream.as_mut()) {
                            Ok(ack_frame) => {
                                let request = crate::qrun_v06_peer_discovery_candidate::decode_q6pd_gossip_push_request(
                                    &gossip_frame,
                                    network_id,
                                    profile_id,
                                    now_ms / 1_000,
                                )
                                .map_err(|error| QRunV06HistorySyncServiceError::PeerDiscovery(
                                    format!("locally generated Q6PD Gossip frame invalid: {error}")
                                ))?;
                                match crate::qrun_v06_peer_discovery_candidate::decode_q6pd_gossip_push_response(
                                    &ack_frame,
                                    &request,
                                ) {
                                    Ok(counts) => eprintln!(
                                        "QFP6_Q6PD_GOSSIP_PUSH peer={} sent={} inserted={} updated={} duplicate={} rejected={}",
                                        address,
                                        gossip_wires.len(),
                                        counts.inserted,
                                        counts.updated,
                                        counts.duplicate,
                                        counts.rejected
                                    ),
                                    Err(error) => eprintln!(
                                        "QFP6_Q6PD_GOSSIP_PUSH_UNAVAILABLE peer={} stage=ack error={error:?}",
                                        address
                                    ),
                                }
                            }
                            Err(error) => eprintln!(
                                "QFP6_Q6PD_GOSSIP_PUSH_UNAVAILABLE peer={} stage=read error={error:?}",
                                address
                            ),
                        }
                    }
                }
                Err(error) => eprintln!(
                    "QFP6_Q6PD_GOSSIP_PUSH_SKIPPED peer={} reason=local_encode error={error:?}",
                    address
                ),
            }
        }
    }

    eprintln!(
        "QFP6_Q6PD_PULL peer={} received={} inserted={} updated={} duplicate={} rejected={}",
        address,
        report.records_received,
        report.records_inserted,
        report.records_updated,
        report.records_duplicate,
        report.records_rejected,
    );
    Ok(report)
}

const Q6PD_DNS_SEED_MAX_ADDRESSES: usize = 16;

fn is_valid_q6pd_dns_seed_name(hostname: &str) -> bool {
    if hostname.is_empty()
        || hostname.len() > 253
        || !hostname.is_ascii()
        || hostname.bytes().any(|byte| byte.is_ascii_uppercase())
        || hostname.ends_with('.')
    {
        return false;
    }
    let labels: Vec<&str> = hostname.split('.').collect();
    labels.len() >= 2
        && !hostname.eq_ignore_ascii_case("localhost")
        && !hostname.ends_with(".localhost")
        && !hostname.ends_with(".local")
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

fn resolve_q6pd_dns_seed_addresses_with<F>(
    hostname: &str,
    port: u16,
    mut resolve: F,
) -> Result<Vec<SocketAddr>, String>
where
    F: FnMut(&str, u16) -> Result<Vec<SocketAddr>, String>,
{
    if port != 443 || !is_valid_q6pd_dns_seed_name(hostname) {
        return Err("Q6PD DNS seed must be a public FQDN on TCP port 443".into());
    }
    let mut addresses = resolve(hostname, port)
        .map_err(|error| format!("Q6PD DNS seed resolution failed: {error}"))?;
    if addresses.is_empty() || addresses.len() > Q6PD_DNS_SEED_MAX_ADDRESSES {
        return Err(format!(
            "Q6PD DNS seed must resolve to 1..={Q6PD_DNS_SEED_MAX_ADDRESSES} addresses"
        ));
    }
    // Preserve the resolver's route preference (Windows/Linux apply their
    // source-address policy, typically preferring a reachable IPv6 path). A global
    // SocketAddr sort forced IPv4 first and could make a Funnel seed time out before
    // its working IPv6 route was even attempted. Deduplicate without reordering.
    let mut seen_routes = std::collections::BTreeSet::new();
    addresses.retain(|address| seen_routes.insert(*address));
    if addresses.iter().any(|address| {
        address.port() != port
            || !crate::qrun_v06_peer_discovery_candidate::is_public_q6pd_endpoint(*address)
    }) {
        return Err("Q6PD DNS seed returned a non-public or wrong-port address".into());
    }
    Ok(addresses)
}

/// Bootstrap through one DNS seed with multiple public A/AAAA routes. Every route uses the
/// same out-of-band pinned Noise key and TLS SNI; DNS never supplies peer identity or trust.
/// Only a successful Noise handshake with the exact pin can deliver signed Q6PD records.
pub fn pull_q6pd_peer_records_from_dns_seed_with_announcement(
    hostname: &str,
    port: u16,
    local_static_private_key: &[u8; 32],
    remote_static_public_key: &[u8; 32],
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
    config: QRunV06HistorySyncClientConfig,
    max_records: u16,
    announce_record: Option<&[u8]>,
    store: &mut crate::qrun_v06_peer_discovery_store_candidate::Q6pdPeerRecordStore,
) -> Result<Q6pdPeerDiscoveryReport, QRunV06HistorySyncServiceError> {
    let addresses = resolve_q6pd_dns_seed_addresses_with(hostname, port, |host, port| {
        (host, port)
            .to_socket_addrs()
            .map(|items| items.collect())
            .map_err(|error| error.to_string())
    })
    .map_err(QRunV06HistorySyncServiceError::PeerDiscovery)?;
    eprintln!(
        "QFP6_Q6PD_DNS_SEED_RESOLVED hostname={} port={} public_routes={}",
        hostname,
        port,
        addresses.len()
    );
    let mut failures = Vec::new();
    for address in addresses {
        eprintln!(
            "QFP6_Q6PD_DNS_SEED_ROUTE_TRY hostname={} address={}",
            hostname, address
        );
        match pull_q6pd_peer_records_from_pinned_peer_with_announcement(
            address,
            local_static_private_key,
            remote_static_public_key,
            network_id,
            profile_id,
            config,
            Some(hostname),
            max_records,
            announce_record,
            store,
        ) {
            Ok(report) => {
                eprintln!(
                    "QFP6_Q6PD_DNS_SEED_ROUTE_OK hostname={} address={} records_received={}",
                    hostname, address, report.records_received
                );
                return Ok(report);
            }
            Err(error) => {
                eprintln!(
                    "QFP6_Q6PD_DNS_SEED_ROUTE_FAIL hostname={} address={} error={}",
                    hostname, address, error
                );
                failures.push(format!("{address}: {error}"));
            }
        }
    }
    Err(QRunV06HistorySyncServiceError::PeerDiscovery(format!(
        "all {} routes for pinned DNS seed {hostname} failed: {}",
        failures.len(),
        failures.join(" | ")
    )))
}

/// Connect to one statically pinned QFP6 peer, authenticate its Q6HR status over Noise,
/// download canonical pages on the same session, and import each page through CP-0594's
/// durable PoW/consensus/execution validator. No peer discovery or key trust is inferred.
pub fn sync_history_from_pinned_peer<A: TransactionAuthenticator>(
    address: SocketAddr,
    local_static_private_key: &[u8; 32],
    remote_static_public_key: &[u8; 32],
    runtime: &mut QRunV06PermissionlessNodeRuntime,
    authenticator: &A,
    config: QRunV06HistorySyncClientConfig,
) -> Result<QRunV06HistorySyncClientReport, QRunV06HistorySyncServiceError> {
    sync_history_from_pinned_peer_with_quote_asset_authorization(
        address,
        local_static_private_key,
        remote_static_public_key,
        runtime,
        authenticator,
        config,
        None,
        None,
    )
}

pub fn sync_history_from_pinned_peer_with_quote_asset_authorization<A: TransactionAuthenticator>(
    address: SocketAddr,
    local_static_private_key: &[u8; 32],
    remote_static_public_key: &[u8; 32],
    runtime: &mut QRunV06PermissionlessNodeRuntime,
    authenticator: &A,
    config: QRunV06HistorySyncClientConfig,
    quote_authorizer: Option<&mut QRunV06QuoteAssetAuthorizationProvider<'_>>,
    tls_server_name: Option<&str>,
) -> Result<QRunV06HistorySyncClientReport, QRunV06HistorySyncServiceError> {
    sync_history_from_pinned_peer_with_verified_session_callback(
        address,
        local_static_private_key,
        remote_static_public_key,
        runtime,
        authenticator,
        config,
        quote_authorizer,
        tls_server_name,
        |_| Ok(()),
    )
}

/// Same pinned history sync, with a callback after the Q6HR status proves that a live,
/// operator-pinned Noise session is carrying the expected network/profile. The callback is
/// invoked while that exact stream/session is still open; callers must remove ephemeral session
/// state when this function returns.
pub fn sync_history_from_pinned_peer_with_verified_session_callback<
    A: TransactionAuthenticator,
    F: FnMut(&QRunV06NoiseSession) -> Result<(), String>,
>(
    address: SocketAddr,
    local_static_private_key: &[u8; 32],
    remote_static_public_key: &[u8; 32],
    runtime: &mut QRunV06PermissionlessNodeRuntime,
    authenticator: &A,
    config: QRunV06HistorySyncClientConfig,
    mut quote_authorizer: Option<&mut QRunV06QuoteAssetAuthorizationProvider<'_>>,
    tls_server_name: Option<&str>,
    mut on_verified_session: F,
) -> Result<QRunV06HistorySyncClientReport, QRunV06HistorySyncServiceError> {
    config.validate()?;
    if local_static_private_key.iter().all(|byte| *byte == 0)
        || remote_static_public_key.iter().all(|byte| *byte == 0)
    {
        return Err(QRunV06HistorySyncServiceError::InvalidClientConfig);
    }

    let local_start = runtime.status()?;
    let base_graph = runtime.fork_choice_snapshot()?;
    let local_base_tip = base_graph.base_tip();
    let local_base_state = base_graph
        .state_for_tip(&local_base_tip)
        .ok_or(QRunV06HistorySyncServiceError::SnapshotUnavailable)?;
    let mut base_tip = local_base_tip;
    let mut base_height = local_base_state.height();
    let mut base_execution_tip = local_base_state.tip_hash();
    let mut next_height = base_height
        .checked_add(1)
        .ok_or(QRunV06HistorySyncServiceError::PageBudgetExceeded)?;
    let mut parent_consensus = base_tip;
    let mut parent_execution = base_execution_tip;
    // Pin both ends of the source snapshot and its compacted checkpoint base across
    // reconnects. The base tuple is authenticated by Noise and must be present locally
    // before requesting any history from a compacted source.
    let mut source_snapshot: Option<(u64, [u8; 32], [u8; 32], u64, [u8; 32], [u8; 32])> = None;
    let mut pages_imported = 0u32;
    let mut blocks_imported = 0u64;

    // Bounded reconnect windows resume the same source branch even when it is not canonical
    // locally. The durable fork-choice graph, not remote height, selects the canonical tip.
    let mut transient_transport_retries = 0usize;
    'sync_rounds: for _round in 0..config.max_rounds {
        if source_snapshot.is_some_and(|(height, _, _, _, _, _)| next_height > height) {
            break;
        }
        let info_request = QRunV06HistoryInfoRequest {
            request_id: 1,
            network_id: local_start.network_id,
            profile_id: local_start.profile_id,
        };
        let (mut stream, mut noise, source) = loop {
            let (mut stream, mut noise) = connect_history_sync_noise_session_with_bounded_retry(
                address,
                tls_server_name,
                config,
                local_static_private_key,
                remote_static_public_key,
                &local_start.network_id,
                &local_start.profile_id,
            )?;
            let status_result: Result<_, QRunV06HistorySyncServiceError> = (|| {
                let encoded = info_request.encode()?;
                noise
                    .write_record(stream.as_mut(), &encoded)
                    .map_err(QRunV06HistorySyncServiceError::from)?;
                eprintln!(
                    "QFP6_SYNC_DIAG history_info_request_sent address={} request_id=1",
                    address
                );
                let info_frame = noise
                    .read_record(stream.as_mut())
                    .map_err(QRunV06HistorySyncServiceError::from)?;
                decode_q6hr_status(&info_frame, &info_request)
                    .map_err(QRunV06HistorySyncServiceError::from)
            })();
            match status_result {
                Ok(source) => {
                    on_verified_session(&noise)
                        .map_err(QRunV06HistorySyncServiceError::PeerDiscovery)?;
                    eprintln!(
                        "QFP6_SYNC_DIAG history_info_status_received address={} source_height={} base_height={}",
                        address, source.height, source.base_height
                    );
                    break (stream, noise, source);
                }
                Err(error)
                    if is_retryable_history_sync_transport_error(&error)
                        && transient_transport_retries
                            < QFP6_HISTORY_SYNC_MAX_TRANSIENT_TRANSPORT_RETRIES =>
                {
                    let backoff = history_sync_transport_retry_backoff(transient_transport_retries);
                    transient_transport_retries += 1;
                    eprintln!(
                        "QFP6_SYNC_DIAG history_info_transport_retry address={} retry={} max_retries={} backoff_ms={} error={error:?}",
                        address,
                        transient_transport_retries,
                        QFP6_HISTORY_SYNC_MAX_TRANSIENT_TRANSPORT_RETRIES,
                        backoff.as_millis()
                    );
                    drop(noise);
                    drop(stream);
                    std::thread::sleep(backoff);
                }
                Err(error) => return Err(error),
            }
        };
        let observed = (
            source.height,
            source.consensus_tip,
            source.execution_tip,
            source.base_height,
            source.base_consensus_tip,
            source.base_execution_tip,
        );
        let mut pending_resume_page: Option<QRunV06CanonicalHistoryPage> = None;
        if let Some(previous) = source_snapshot {
            if observed != previous {
                return Err(QRunV06HistorySyncServiceError::SnapshotMismatch);
            }
        } else {
            // A compacted source can only export blocks after its own checkpoint base.
            // Accept that base only when the exact consensus and execution state is already
            // present in the local fork-choice graph. This lets a Joiner resume at a shared
            // newer checkpoint while preserving discovery/import of heavier competing branches
            // from a common older base; it never trusts height alone.
            let source_base_state = base_graph
                .state_for_tip(&source.base_consensus_tip)
                .ok_or(QRunV06HistorySyncServiceError::SnapshotMismatch)?;
            if source_base_state.height() != source.base_height
                || source_base_state.tip_hash() != source.base_execution_tip
            {
                return Err(QRunV06HistorySyncServiceError::SnapshotMismatch);
            }

            // Fast-resume only when this exact consensus tip is already in our validated
            // fork graph AND its execution state/height match the peer's authenticated Q6HR.
            // Unknown tips, mismatched execution hashes and competing branches continue through
            // the full common-base history path below.
            let known_source_tip = base_graph
                .tip_for_hash(&source.consensus_tip)
                .zip(base_graph.state_for_tip(&source.consensus_tip));
            if let Some((known_tip, known_state)) = known_source_tip {
                if known_tip.height == source.height
                    && known_state.height() == source.height
                    && known_state.tip_hash() == source.execution_tip
                {
                    let resume_height = source
                        .height
                        .checked_add(1)
                        .ok_or(QRunV06HistorySyncServiceError::PageBudgetExceeded)?;
                    let empty_request = QRunV06HistorySyncRequest {
                        request_id: 2,
                        network_id: local_start.network_id,
                        profile_id: local_start.profile_id,
                        snapshot_tip: source.consensus_tip,
                        expected_parent_consensus_hash: source.consensus_tip,
                        expected_parent_execution_hash: source.execution_tip,
                        start_height: resume_height,
                        max_blocks: config.max_blocks_per_page,
                        max_bytes: config.max_bytes_per_page,
                    };
                    empty_request.validate()?;
                    let empty_page = match request_history_page_over_noise(
                        &mut noise,
                        stream.as_mut(),
                        empty_request,
                        base_graph.consensus_parameters().clone(),
                    ) {
                        Ok(page) => page,
                        Err(error)
                            if is_retryable_history_sync_transport_error(&error)
                                && transient_transport_retries
                                    < QFP6_HISTORY_SYNC_MAX_TRANSIENT_TRANSPORT_RETRIES =>
                        {
                            let backoff =
                                history_sync_transport_retry_backoff(transient_transport_retries);
                            transient_transport_retries += 1;
                            eprintln!(
                                "QFP6_SYNC_DIAG history_fast_resume_release_retry address={} retry={} backoff_ms={} error={error:?}",
                                address,
                                transient_transport_retries,
                                backoff.as_millis()
                            );
                            std::thread::sleep(backoff);
                            continue 'sync_rounds;
                        }
                        Err(error) => return Err(error),
                    };
                    if !empty_page.envelopes.is_empty()
                        || !empty_page.complete
                        || empty_page.start_height != resume_height
                        || empty_page.next_height != resume_height
                        || empty_page.snapshot_height != source.height
                        || empty_page.snapshot_tip != source.consensus_tip
                    {
                        return Err(QRunV06HistorySyncServiceError::PageDoesNotMatchSnapshot);
                    }
                    eprintln!(
                        "QFP6_SYNC_DIAG history_fast_resume_known_tip address={} source_height={} consensus_tip={:02x?} execution_tip={:02x?} replayed_prefix_blocks=0",
                        address,
                        source.height,
                        source.consensus_tip,
                        source.execution_tip
                    );
                    source_snapshot = Some(observed);
                    next_height = resume_height;
                    break 'sync_rounds;
                }
            }

            // If the peer has extended the exact canonical tip already held locally, request
            // the next page from that validated parent instead of replaying the shared checkpoint
            // prefix on every periodic poll. Both consensus and execution parent hashes must match.
            let local_canonical_tip = base_graph.canonical_tip();
            let local_canonical_state = base_graph.canonical_state();
            if local_canonical_tip.height > source.base_height
                && local_canonical_tip.height < source.height
            {
                let resume_height = local_canonical_tip
                    .height
                    .checked_add(1)
                    .ok_or(QRunV06HistorySyncServiceError::PageBudgetExceeded)?;
                let resume_request = QRunV06HistorySyncRequest {
                    request_id: 2,
                    network_id: local_start.network_id,
                    profile_id: local_start.profile_id,
                    snapshot_tip: source.consensus_tip,
                    expected_parent_consensus_hash: local_canonical_tip.tip_hash,
                    expected_parent_execution_hash: local_canonical_state.tip_hash(),
                    start_height: resume_height,
                    max_blocks: config.max_blocks_per_page,
                    max_bytes: config.max_bytes_per_page,
                };
                resume_request.validate()?;
                let resume_page = request_history_page_over_noise(
                    &mut noise,
                    stream.as_mut(),
                    resume_request,
                    base_graph.consensus_parameters().clone(),
                )?;
                let first_block = resume_page
                    .envelopes
                    .first()
                    .map(|encoded| decode_qrun_v06_pow_block(encoded))
                    .transpose()
                    .map_err(|error| QRunV06HistorySyncServiceError::Wire(error.to_string()))?;
                let extends_local_tip = first_block.as_ref().is_some_and(|block| {
                    block.header.height == resume_height
                        && block.header.previous_consensus_hash == local_canonical_tip.tip_hash
                        && block.header.parent_hash == local_canonical_state.tip_hash()
                });
                if extends_local_tip
                    && resume_page.start_height == resume_height
                    && resume_page.snapshot_height == source.height
                    && resume_page.snapshot_tip == source.consensus_tip
                {
                    eprintln!(
                        "QFP6_SYNC_DIAG history_incremental_resume address={} local_height={} resume_height={} source_height={}",
                        address, local_canonical_tip.height, resume_height, source.height
                    );
                    parent_consensus = local_canonical_tip.tip_hash;
                    parent_execution = local_canonical_state.tip_hash();
                    next_height = resume_height;
                    source_snapshot = Some(observed);
                    pending_resume_page = Some(resume_page);
                } else {
                    eprintln!(
                        "QFP6_SYNC_DIAG history_incremental_resume_rejected address={} local_height={} source_height={} fallback=shared_checkpoint",
                        address, local_canonical_tip.height, source.height
                    );
                }
            }

            if pending_resume_page.is_none() {
                base_height = source.base_height;
                base_tip = source.base_consensus_tip;
                base_execution_tip = source.base_execution_tip;
                next_height = base_height
                    .checked_add(1)
                    .ok_or(QRunV06HistorySyncServiceError::PageBudgetExceeded)?;
                parent_consensus = base_tip;
                parent_execution = base_execution_tip;
                if source.height < base_height {
                    return Err(QRunV06HistorySyncServiceError::SourceBehind);
                }
                source_snapshot = Some(observed);
                if source.height == base_height {
                    if source.consensus_tip != base_tip
                        || source.execution_tip != base_execution_tip
                    {
                        return Err(QRunV06HistorySyncServiceError::SnapshotMismatch);
                    }
                    // Complete an empty Q6HS page at height tip+1 so the responder releases its
                    // retained snapshot. Without this sentinel, an already-current node would leave
                    // a stale snapshot pinned forever and miss later source-chain growth.
                    let empty_request = QRunV06HistorySyncRequest {
                        request_id: 2,
                        network_id: local_start.network_id,
                        profile_id: local_start.profile_id,
                        snapshot_tip: source.consensus_tip,
                        expected_parent_consensus_hash: base_tip,
                        expected_parent_execution_hash: base_execution_tip,
                        start_height: next_height,
                        max_blocks: config.max_blocks_per_page,
                        max_bytes: config.max_bytes_per_page,
                    };
                    empty_request.validate()?;
                    let empty_page = match request_history_page_over_noise(
                        &mut noise,
                        stream.as_mut(),
                        empty_request,
                        runtime
                            .fork_choice_snapshot()?
                            .consensus_parameters()
                            .clone(),
                    ) {
                        Ok(page) => page,
                        Err(error)
                            if is_retryable_history_sync_transport_error(&error)
                                && transient_transport_retries
                                    < QFP6_HISTORY_SYNC_MAX_TRANSIENT_TRANSPORT_RETRIES =>
                        {
                            let backoff =
                                history_sync_transport_retry_backoff(transient_transport_retries);
                            transient_transport_retries += 1;
                            eprintln!(
                            "QFP6_SYNC_DIAG empty_history_page_transport_retry address={} retry={} backoff_ms={} error={error:?}",
                            address,
                            transient_transport_retries,
                            backoff.as_millis()
                        );
                            std::thread::sleep(backoff);
                            continue 'sync_rounds;
                        }
                        Err(error) => return Err(error),
                    };
                    if !empty_page.envelopes.is_empty()
                        || !empty_page.complete
                        || empty_page.start_height != next_height
                        || empty_page.next_height != next_height
                        || empty_page.snapshot_height != source.height
                        || empty_page.snapshot_tip != source.consensus_tip
                    {
                        return Err(QRunV06HistorySyncServiceError::PageDoesNotMatchSnapshot);
                    }
                    break;
                }
            }
        }

        let mut pages_this_session = 0u32;
        let mut request_id = 2u64;
        while pages_this_session < config.max_pages
            && source_snapshot.is_some_and(|(height, _, _, _, _, _)| next_height <= height)
        {
            let request = QRunV06HistorySyncRequest {
                request_id,
                network_id: local_start.network_id,
                profile_id: local_start.profile_id,
                snapshot_tip: source.consensus_tip,
                expected_parent_consensus_hash: parent_consensus,
                expected_parent_execution_hash: parent_execution,
                start_height: next_height,
                max_blocks: config.max_blocks_per_page,
                max_bytes: config.max_bytes_per_page,
            };
            request.validate()?;
            let params = runtime
                .fork_choice_snapshot()?
                .consensus_parameters()
                .clone();
            let page = if let Some(page) = pending_resume_page.take() {
                page
            } else {
                match request_history_page_over_noise(
                    &mut noise,
                    stream.as_mut(),
                    request.clone(),
                    params.clone(),
                ) {
                    Ok(page) => page,
                    Err(error)
                        if is_retryable_history_sync_transport_error(&error)
                            && transient_transport_retries
                                < QFP6_HISTORY_SYNC_MAX_TRANSIENT_TRANSPORT_RETRIES =>
                    {
                        let backoff =
                            history_sync_transport_retry_backoff(transient_transport_retries);
                        transient_transport_retries += 1;
                        eprintln!(
                        "QFP6_SYNC_DIAG history_page_transport_retry address={} request_id={} start_height={} retry={} backoff_ms={} error={error:?}",
                        address,
                        request_id,
                        next_height,
                        transient_transport_retries,
                        backoff.as_millis()
                    );
                        std::thread::sleep(backoff);
                        // No block is imported until a complete Q6HC page verifies. The next
                        // bounded round re-pins the identical Q6HR snapshot and replays this page.
                        break;
                    }
                    Err(error) => return Err(error),
                }
            };
            if page.snapshot_height != source.height || page.snapshot_tip != source.consensus_tip {
                return Err(QRunV06HistorySyncServiceError::SnapshotMismatch);
            }
            if page.envelopes.is_empty() {
                return Err(QRunV06HistorySyncServiceError::NoProgress);
            }
            let page_blocks = page.envelopes.len() as u64;
            let complete = page.complete;
            let import_report = import_history_branch_page_with_quote_asset_authorization(
                runtime,
                &request,
                &page,
                authenticator,
                quote_authorizer.as_deref_mut(),
            )?;
            eprintln!(
                "QFP6_SYNC_DIAG history_page_imported request_id={} blocks={} start_height={} next_height={} resulting_canonical_height={} resulting_canonical_tip={:02x?} complete={}",
                request_id,
                page_blocks,
                page.start_height,
                page.next_height,
                import_report.resulting_height,
                import_report.resulting_tip,
                complete
            );
            let last = decode_qrun_v06_pow_block(page.envelopes.last().unwrap())
                .map_err(|error| QRunV06HistorySyncServiceError::Wire(error.to_string()))?;
            parent_consensus = pow_digest(&last.header, params.pow)
                .map_err(|error| QRunV06HistorySyncServiceError::Wire(error.to_string()))?;
            let imported_graph = runtime.fork_choice_snapshot()?;
            parent_execution = imported_graph
                .state_for_tip(&parent_consensus)
                .ok_or(QRunV06HistorySyncServiceError::SnapshotUnavailable)?
                .tip_hash();
            next_height = page.next_height;
            pages_imported = pages_imported
                .checked_add(1)
                .ok_or(QRunV06HistorySyncServiceError::PageBudgetExceeded)?;
            blocks_imported = blocks_imported
                .checked_add(page_blocks)
                .ok_or(QRunV06HistorySyncServiceError::PageBudgetExceeded)?;
            pages_this_session += 1;
            request_id = request_id
                .checked_add(1)
                .ok_or(QRunV06HistorySyncServiceError::PageBudgetExceeded)?;
            if complete {
                break;
            }
        }
    }

    let (source_height, source_tip, source_execution_tip, _, _, _) =
        source_snapshot.ok_or(QRunV06HistorySyncServiceError::SnapshotUnavailable)?;
    let complete = next_height > source_height;
    let final_graph = runtime.fork_choice_snapshot()?;
    if complete {
        let source_chain_tip = final_graph
            .tip_for_hash(&source_tip)
            .ok_or(QRunV06HistorySyncServiceError::SnapshotMismatch)?;
        let source_chain_state = final_graph
            .state_for_tip(&source_tip)
            .ok_or(QRunV06HistorySyncServiceError::SnapshotMismatch)?;
        if source_chain_tip.height != source_height
            || source_chain_state.tip_hash() != source_execution_tip
            || final_graph.canonical_tip().cumulative_work < source_chain_tip.cumulative_work
        {
            return Err(QRunV06HistorySyncServiceError::SnapshotMismatch);
        }
    }
    let final_status = runtime.status()?;
    Ok(QRunV06HistorySyncClientReport {
        source_height,
        final_height: final_status.height,
        pages_imported,
        blocks_imported,
        source_tip,
        source_execution_tip,
        complete,
    })
}

/// Synchronize history from one statically pinned Noise peer using the QAP1 runtime only.
/// Each received Q6HS page is imported through `import_history_page_with_qap1`; this function
/// never opens or falls back to the non-QAP1 runtime/import path.
#[allow(clippy::too_many_arguments)]
pub fn sync_history_from_pinned_peer_with_qap1<A, P, PV, AV, Q, T>(
    address: SocketAddr,
    local_static_private_key: &[u8; 32],
    remote_static_public_key: &[u8; 32],
    runtime: &mut QRunV06NodeRuntime<A>,
    authenticator: &T,
    quote_authorizer: &mut QRunV06QuoteAssetAuthorizationProvider<'_>,
    coordinator: &mut QRunV06Qap1ExternalCoordinator<P, PV, AV, Q>,
    config: QRunV06HistorySyncClientConfig,
    tls_server_name: Option<&str>,
) -> Result<QRunV06HistorySyncClientReport, QRunV06HistorySyncServiceError>
where
    A: crate::qrun_v06_node_runtime_candidate::QRunV06NodeAnchorGate,
    P: ExternalCasProviderTransport,
    PV: MlDsa65Verifier + Clone,
    AV: MlDsa65Verifier,
    Q: QRunV06Qap1AnchorTransport,
    T: TransactionAuthenticator,
{
    config.validate()?;
    if !runtime.requires_qap1()
        || !runtime.qap1_recovery_verified()
        || runtime.requires_reopen()
        || runtime.has_pending_external_anchor()
        || local_static_private_key.iter().all(|byte| *byte == 0)
        || remote_static_public_key.iter().all(|byte| *byte == 0)
    {
        return Err(QRunV06HistorySyncServiceError::InvalidClientConfig);
    }
    let anchor = runtime.committed_anchor_state();
    let network_id = anchor.network_id;
    let profile_id = anchor.profile_id;
    let local_height = anchor.canonical_height;
    let local_tip = anchor.canonical_tip;
    let local_graph = runtime
        .fork_choice_snapshot()
        .map_err(|error| QRunV06HistorySyncServiceError::Runtime(error.to_string()))?;
    if local_graph.canonical_tip().tip_hash != local_tip
        || local_graph
            .canonical_state()
            .state_root()
            .map_err(|error| QRunV06HistorySyncServiceError::Runtime(format!("{error:?}")))?
            != anchor.canonical_state_root
    {
        return Err(QRunV06HistorySyncServiceError::SnapshotMismatch);
    }
    let (mut stream, mut noise) = connect_history_sync_noise_session_with_bounded_retry(
        address,
        tls_server_name,
        config,
        local_static_private_key,
        remote_static_public_key,
        &network_id,
        &profile_id,
    )?;
    let info_request = QRunV06HistoryInfoRequest {
        request_id: 1,
        network_id,
        profile_id,
    };
    noise.write_record(stream.as_mut(), &info_request.encode()?)?;
    let info_frame = noise.read_record(stream.as_mut())?;
    let source = decode_q6hr_status(&info_frame, &info_request)?;
    if source.height < local_height {
        return Err(QRunV06HistorySyncServiceError::SourceBehind);
    }
    if source.height == local_height
        && (source.consensus_tip != local_tip
            || source.execution_tip != local_graph.canonical_state().tip_hash())
    {
        return Err(QRunV06HistorySyncServiceError::SnapshotMismatch);
    }

    let mut pages_imported = 0u32;
    let mut blocks_imported = 0u64;
    let mut request_id = 2u64;
    while runtime.committed_anchor_state().canonical_height < source.height {
        if pages_imported >= config.max_pages {
            return Err(QRunV06HistorySyncServiceError::PageBudgetExceeded);
        }
        if runtime.requires_reopen() || runtime.has_pending_external_anchor() {
            return Err(QRunV06HistorySyncServiceError::Runtime(
                "QAP1 anchor transition requires restart recovery before history sync continues"
                    .into(),
            ));
        }
        let anchor = runtime.committed_anchor_state();
        let graph = runtime
            .fork_choice_snapshot()
            .map_err(|error| QRunV06HistorySyncServiceError::Runtime(error.to_string()))?;
        if graph.canonical_tip().tip_hash != anchor.canonical_tip
            || graph
                .canonical_state()
                .state_root()
                .map_err(|error| QRunV06HistorySyncServiceError::Runtime(format!("{error:?}")))?
                != anchor.canonical_state_root
        {
            return Err(QRunV06HistorySyncServiceError::SnapshotMismatch);
        }
        let request = QRunV06HistorySyncRequest {
            request_id,
            network_id: anchor.network_id,
            profile_id: anchor.profile_id,
            snapshot_tip: source.consensus_tip,
            expected_parent_consensus_hash: anchor.canonical_tip,
            expected_parent_execution_hash: graph.canonical_state().tip_hash(),
            start_height: anchor.canonical_height.checked_add(1).ok_or_else(|| {
                QRunV06HistorySyncServiceError::Runtime("local height overflow".into())
            })?,
            max_blocks: config.max_blocks_per_page,
            max_bytes: config.max_bytes_per_page,
        };
        request.validate()?;
        let page = request_history_page_over_noise(
            &mut noise,
            stream.as_mut(),
            request,
            graph.consensus_parameters().clone(),
        )?;
        if page.snapshot_height != source.height || page.snapshot_tip != source.consensus_tip {
            return Err(QRunV06HistorySyncServiceError::SnapshotMismatch);
        }
        if page.envelopes.is_empty() {
            return Err(QRunV06HistorySyncServiceError::NoProgress);
        }
        let imported_count = page.envelopes.len() as u64;
        import_history_page_with_qap1(
            runtime,
            &page,
            authenticator,
            quote_authorizer,
            coordinator,
        )?;
        pages_imported = pages_imported
            .checked_add(1)
            .ok_or(QRunV06HistorySyncServiceError::PageBudgetExceeded)?;
        blocks_imported = blocks_imported
            .checked_add(imported_count)
            .ok_or(QRunV06HistorySyncServiceError::PageBudgetExceeded)?;
        request_id = request_id
            .checked_add(1)
            .ok_or(QRunV06HistorySyncServiceError::PageBudgetExceeded)?;
        if page.complete {
            break;
        }
    }
    let final_anchor = runtime.committed_anchor_state();
    if final_anchor.canonical_height > source.height {
        return Err(QRunV06HistorySyncServiceError::SnapshotMismatch);
    }
    let complete = final_anchor.canonical_height == source.height;
    if complete {
        let final_graph = runtime
            .fork_choice_snapshot()
            .map_err(|error| QRunV06HistorySyncServiceError::Runtime(error.to_string()))?;
        if final_anchor.canonical_tip != source.consensus_tip
            || final_graph.canonical_state().tip_hash() != source.execution_tip
            || final_graph
                .canonical_state()
                .state_root()
                .map_err(|error| QRunV06HistorySyncServiceError::Runtime(format!("{error:?}")))?
                != final_anchor.canonical_state_root
        {
            return Err(QRunV06HistorySyncServiceError::SnapshotMismatch);
        }
    } else if pages_imported != config.max_pages {
        return Err(QRunV06HistorySyncServiceError::NoProgress);
    }
    Ok(QRunV06HistorySyncClientReport {
        source_height: source.height,
        final_height: final_anchor.canonical_height,
        pages_imported,
        blocks_imported,
        source_tip: source.consensus_tip,
        source_execution_tip: source.execution_tip,
        complete,
    })
}

/// Repeat bounded QAP1-gated Q6HS sessions until the peer's canonical height and tips match.
/// A failed anchor transition must be reconciled by reopening the QAP1 runtime before retry.
#[allow(clippy::too_many_arguments)]
pub fn sync_history_from_pinned_peer_until_complete_with_qap1<A, P, PV, AV, Q, T>(
    address: SocketAddr,
    local_static_private_key: &[u8; 32],
    remote_static_public_key: &[u8; 32],
    runtime: &mut QRunV06NodeRuntime<A>,
    authenticator: &T,
    quote_authorizer: &mut QRunV06QuoteAssetAuthorizationProvider<'_>,
    coordinator: &mut QRunV06Qap1ExternalCoordinator<P, PV, AV, Q>,
    config: QRunV06HistorySyncClientConfig,
    tls_server_name: Option<&str>,
) -> Result<QRunV06HistorySyncClientReport, QRunV06HistorySyncServiceError>
where
    A: crate::qrun_v06_node_runtime_candidate::QRunV06NodeAnchorGate,
    P: ExternalCasProviderTransport,
    PV: MlDsa65Verifier + Clone,
    AV: MlDsa65Verifier,
    Q: QRunV06Qap1AnchorTransport,
    T: TransactionAuthenticator,
{
    config.validate()?;
    let mut total_pages = 0u32;
    let mut total_blocks = 0u64;
    for _ in 0..config.max_rounds {
        let mut report = sync_history_from_pinned_peer_with_qap1(
            address,
            local_static_private_key,
            remote_static_public_key,
            runtime,
            authenticator,
            quote_authorizer,
            coordinator,
            config,
            tls_server_name,
        )?;
        total_pages = total_pages
            .checked_add(report.pages_imported)
            .ok_or(QRunV06HistorySyncServiceError::PageBudgetExceeded)?;
        total_blocks = total_blocks
            .checked_add(report.blocks_imported)
            .ok_or(QRunV06HistorySyncServiceError::PageBudgetExceeded)?;
        if report.complete {
            report.pages_imported = total_pages;
            report.blocks_imported = total_blocks;
            return Ok(report);
        }
    }
    Err(QRunV06HistorySyncServiceError::PageBudgetExceeded)
}
/// Repeat bounded Q6HI/Q6HR + page sessions until the peer's canonical height/tips match
/// the local durable runtime. Each round is independently authenticated and pins a fresh
/// source snapshot; CP-0594 validates every imported page. A reorg below the imported prefix
/// fails closed rather than silently rolling back local history.
pub fn sync_history_from_pinned_peer_until_complete<A: TransactionAuthenticator>(
    address: SocketAddr,
    local_static_private_key: &[u8; 32],
    remote_static_public_key: &[u8; 32],
    runtime: &mut QRunV06PermissionlessNodeRuntime,
    authenticator: &A,
    config: QRunV06HistorySyncClientConfig,
) -> Result<QRunV06HistorySyncClientReport, QRunV06HistorySyncServiceError> {
    sync_history_from_pinned_peer_until_complete_with_quote_asset_authorization(
        address,
        local_static_private_key,
        remote_static_public_key,
        runtime,
        authenticator,
        config,
        None,
        None,
    )
}

pub fn sync_history_from_pinned_peer_until_complete_with_quote_asset_authorization<
    A: TransactionAuthenticator,
>(
    address: SocketAddr,
    local_static_private_key: &[u8; 32],
    remote_static_public_key: &[u8; 32],
    runtime: &mut QRunV06PermissionlessNodeRuntime,
    authenticator: &A,
    config: QRunV06HistorySyncClientConfig,
    mut quote_authorizer: Option<&mut QRunV06QuoteAssetAuthorizationProvider<'_>>,
    tls_server_name: Option<&str>,
) -> Result<QRunV06HistorySyncClientReport, QRunV06HistorySyncServiceError> {
    config.validate()?;
    let mut total_pages = 0u32;
    let mut total_blocks = 0u64;
    for _ in 0..config.max_rounds {
        let mut report = sync_history_from_pinned_peer_with_quote_asset_authorization(
            address,
            local_static_private_key,
            remote_static_public_key,
            runtime,
            authenticator,
            config,
            quote_authorizer.as_deref_mut(),
            tls_server_name,
        )?;
        total_pages = total_pages
            .checked_add(report.pages_imported)
            .ok_or(QRunV06HistorySyncServiceError::PageBudgetExceeded)?;
        total_blocks = total_blocks
            .checked_add(report.blocks_imported)
            .ok_or(QRunV06HistorySyncServiceError::PageBudgetExceeded)?;
        if report.complete {
            report.pages_imported = total_pages;
            report.blocks_imported = total_blocks;
            return Ok(report);
        }
        if report.pages_imported == 0 {
            return Err(QRunV06HistorySyncServiceError::NoProgress);
        }
    }
    Err(QRunV06HistorySyncServiceError::PageBudgetExceeded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        consensus::{ConsensusParameters, Uint256},
        external_cas_anchor_candidate::ExternalCasPin,
        qrun_v06_canonical_execution_candidate::QRunV06CanonicalExecutionState,
        qrun_v06_cp0604_supply_candidate::Cp0604FounderControlledSupply,
        qrun_v06_genesis_descriptor_candidate::QRunV06GenesisDescriptor,
        qrun_v06_hybrid_auth_candidate::QRunV06HybridTransactionAuthenticator,
        qrun_v06_permissionless_runtime_candidate::QRunV06PermissionlessNodeRuntime,
        qrun_v06_permissionless_service_candidate::QRunV06PermissionlessMempool,
        qrun_v06_profile_pin_candidate::{QRunV06ProfilePinCandidate, QRunV06VerifiedProfilePin},
        qrun_v06_tokenomics_candidate::QRunV06MiningScheduleCandidate,
        qrun_v06_transaction_mempool_candidate::QRunV06MempoolLimits,
        v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate,
        v4_fat1_trust_candidate::ML_DSA_65_PUBLIC_KEY_BYTES,
    };
    use std::{
        fs,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        thread,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    fn qfp6_test_tls_configs() -> (Arc<rustls::ClientConfig>, Arc<rustls::ServerConfig>) {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(
                include_bytes!("../tests/fixtures/qfp6_tls/test-root.der").to_vec(),
            ))
            .unwrap();
        let client = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let server = Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![CertificateDer::from(
                        include_bytes!("../tests/fixtures/qfp6_tls/test-server.der").to_vec(),
                    )],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                        include_bytes!("../tests/fixtures/qfp6_tls/test-server-key.pk8.der")
                            .to_vec(),
                    )),
                )
                .unwrap(),
        );
        (client, server)
    }

    fn qfp6_test_noise_keypair() -> ([u8; 32], [u8; 32]) {
        let params = "Noise_XX_25519_ChaChaPoly_SHA256".parse().unwrap();
        let pair = snow::Builder::new(params).generate_keypair().unwrap();
        (
            pair.private.as_slice().try_into().unwrap(),
            pair.public.as_slice().try_into().unwrap(),
        )
    }

    fn spawn_qfp6_tls_noise_server(
        listener: TcpListener,
        tls_config: Arc<rustls::ServerConfig>,
        server_private: [u8; 32],
        trusted_client_public: [u8; 32],
        expected_sni: Option<&'static str>,
    ) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let mut tls =
                rustls::StreamOwned::new(rustls::ServerConnection::new(tls_config).unwrap(), tcp);
            let session = QRunV06NoiseSession::accept(
                &mut tls,
                &server_private,
                &[trusted_client_public],
                &[0xC1; 32],
                &[0xC2; 32],
            );
            match expected_sni {
                Some(expected) => {
                    let mut noise = session.expect("verified TLS/SNI then pinned Noise handshake");
                    assert_eq!(tls.conn.server_name(), Some(expected));
                    let request = noise.read_record(&mut tls).unwrap();
                    noise.write_record(&mut tls, &request).unwrap();
                }
                None => assert!(
                    session.is_err(),
                    "a certificate for seed.tailnet.ts.net must not authenticate a different SNI"
                ),
            }
        })
    }

    #[test]
    fn public_relay_tls_verifies_sni_and_carries_pinned_noise_records() {
        let (client_tls, server_tls) = qfp6_test_tls_configs();
        let (server_private, server_public) = qfp6_test_noise_keypair();
        let (client_private, client_public) = qfp6_test_noise_keypair();
        let config = QRunV06HistorySyncClientConfig {
            connect_timeout: Duration::from_secs(3),
            io_timeout: Duration::from_secs(5),
            ..QRunV06HistorySyncClientConfig::default()
        };

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = spawn_qfp6_tls_noise_server(
            listener,
            Arc::clone(&server_tls),
            server_private,
            client_public,
            Some("seed.tailnet.ts.net"),
        );
        let mut stream = connect_history_sync_stream_with_tls_config(
            address,
            Some("seed.tailnet.ts.net"),
            config,
            Some(Arc::clone(&client_tls)),
        )
        .unwrap();
        let mut noise = QRunV06NoiseSession::connect(
            stream.as_mut(),
            &client_private,
            &server_public,
            &[0xC1; 32],
            &[0xC2; 32],
        )
        .unwrap();
        assert_eq!(noise.remote_static_public_key(), &server_public);
        let request = b"QFP6_TLS_SNI_NOISE_INTEGRATION";
        noise.write_record(stream.as_mut(), request).unwrap();
        assert_eq!(noise.read_record(stream.as_mut()).unwrap(), request);
        server.join().unwrap();

        // The same trusted CA must not allow a valid certificate to be reused under
        // an attacker-controlled hostname; TLS verification fails before Noise is exposed.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server =
            spawn_qfp6_tls_noise_server(listener, server_tls, server_private, client_public, None);
        let rejected = connect_history_sync_stream_with_tls_config(
            address,
            Some("attacker.tailnet.ts.net"),
            config,
            Some(client_tls),
        );
        assert!(
            rejected.is_err(),
            "a certificate for seed.tailnet.ts.net must be rejected for attacker.tailnet.ts.net before Noise begins"
        );
        server.join().unwrap();
    }

    #[test]
    fn pinned_noise_sync_imports_a_heavier_competing_branch_and_recovers_after_restart() {
        const NETWORK: [u8; 32] = [0xD1; 32];
        const PROFILE: [u8; 32] = [0xD2; 32];
        const FOUNDER: [u8; 32] = [0xD3; 32];

        let mut params = ConsensusParameters::qrun_v06_sha256d_candidate().unwrap();
        params.target_block_time_secs = 30;
        params.difficulty_window_blocks = 2;
        params.difficulty_min_ratio_divisor = 4;
        params.difficulty_max_ratio = 4;
        params.initial_target = Uint256::from_be_bytes([0x7F; 32]);
        params.pow_limit = Uint256::MAX;
        params.validate().unwrap();

        let schedule = QRunV06MiningScheduleCandidate::cp0422_research_candidate();
        let supply = Cp0604FounderControlledSupply::genesis(NETWORK, FOUNDER, schedule).unwrap();
        let descriptor = QRunV06GenesisDescriptor::new(
            NETWORK,
            PROFILE,
            FOUNDER,
            1,
            crate::qrun_v06_checkpoint_candidate::qrun_v06_consensus_fingerprint(&params).unwrap(),
            supply.policy_fingerprint(),
        )
        .unwrap();
        let genesis = QRunV06CanonicalExecutionState::cp0604_genesis_candidate_with_descriptor(
            descriptor.clone(),
            schedule,
        )
        .unwrap();
        let profile_bundle = QRunV06ProfilePinCandidate::new(
            descriptor,
            ExternalCasPin {
                provider_id: [0xD4; 32],
                network_id: NETWORK,
                genesis_digest: [0xD5; 32],
                receipt_key_id: [0xD6; 32],
                receipt_public_key: [0xD7; ML_DSA_65_PUBLIC_KEY_BYTES],
            },
        )
        .unwrap();
        let profile_pin_bytes = profile_bundle.encode().unwrap();
        let verified_pin = QRunV06VerifiedProfilePin::decode(
            &profile_pin_bytes,
            profile_bundle.commitment().unwrap(),
        )
        .unwrap();
        let authenticator =
            QRunV06HybridTransactionAuthenticator::new(LibcruxMlDsa65VerifierCandidate);

        let test_root = std::env::temp_dir().join(format!(
            "qfp6-branch-sync-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        let source_dir = test_root.join("source-store");
        let source_mempool_dir = test_root.join("source-mempool");
        let destination_dir = test_root.join("destination-store");
        let destination_mempool_dir = test_root.join("destination-mempool");
        fs::create_dir_all(&test_root).unwrap();

        let mut source_runtime = QRunV06PermissionlessNodeRuntime::open(
            &source_dir,
            genesis.clone(),
            params.clone(),
            &authenticator,
            None,
            &verified_pin,
        )
        .unwrap();
        let mut destination_runtime = QRunV06PermissionlessNodeRuntime::open(
            &destination_dir,
            genesis.clone(),
            params.clone(),
            &authenticator,
            None,
            &verified_pin,
        )
        .unwrap();
        let mut source_mempool = QRunV06PermissionlessMempool::open(
            &source_mempool_dir,
            QRunV06MempoolLimits::default(),
        )
        .unwrap();
        let mut destination_mempool = QRunV06PermissionlessMempool::open(
            &destination_mempool_dir,
            QRunV06MempoolLimits::default(),
        )
        .unwrap();
        let stop_mining = AtomicBool::new(false);
        let wall_clock = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let first_branch_timestamp = wall_clock.max(genesis.last_timestamp().saturating_add(60));
        destination_mempool
            .restore(
                &destination_runtime,
                &authenticator,
                FOUNDER,
                first_branch_timestamp,
            )
            .unwrap();
        source_mempool
            .restore(
                &source_runtime,
                &authenticator,
                FOUNDER,
                first_branch_timestamp,
            )
            .unwrap();

        // Both independent nodes mine the same deterministic first block from Genesis.
        let source_common = source_mempool
            .mine_one_batch(
                &mut source_runtime,
                &authenticator,
                FOUNDER,
                first_branch_timestamp,
                10_000,
                &stop_mining,
            )
            .unwrap()
            .unwrap();
        assert!(source_common.became_canonical);
        let destination_common = destination_mempool
            .mine_one_batch(
                &mut destination_runtime,
                &authenticator,
                FOUNDER,
                first_branch_timestamp,
                10_000,
                &stop_mining,
            )
            .unwrap()
            .unwrap();
        assert!(destination_common.became_canonical);
        let common_tip = source_runtime.status().unwrap().tip;
        assert_eq!(destination_runtime.status().unwrap().tip, common_tip);

        // The branches diverge at height two: destination has one block, source has two.
        let local_mined = destination_mempool
            .mine_one_batch(
                &mut destination_runtime,
                &authenticator,
                FOUNDER,
                first_branch_timestamp.saturating_add(120),
                10_000,
                &stop_mining,
            )
            .unwrap()
            .unwrap();
        assert!(local_mined.became_canonical);
        let local_tip = destination_runtime.status().unwrap().tip;
        for timestamp in [
            first_branch_timestamp.saturating_add(60),
            first_branch_timestamp.saturating_add(120),
        ] {
            let mined = source_mempool
                .mine_one_batch(
                    &mut source_runtime,
                    &authenticator,
                    FOUNDER,
                    timestamp,
                    10_000,
                    &stop_mining,
                )
                .unwrap()
                .unwrap();
            assert!(mined.became_canonical);
        }
        let source_status = source_runtime.status().unwrap();
        assert_eq!(source_status.height, 3);
        assert_ne!(source_status.tip, local_tip);
        let source_work = source_runtime
            .fork_choice_snapshot()
            .unwrap()
            .canonical_tip()
            .cumulative_work;
        let local_work = destination_runtime
            .fork_choice_snapshot()
            .unwrap()
            .canonical_tip()
            .cumulative_work;
        assert!(source_work > local_work);

        // The destination has only the authenticated source Noise key, not an anonymous peer.
        let noise_params = "Noise_XX_25519_ChaChaPoly_SHA256".parse().unwrap();
        let server_pair = snow::Builder::new(noise_params).generate_keypair().unwrap();
        let client_pair = snow::Builder::new("Noise_XX_25519_ChaChaPoly_SHA256".parse().unwrap())
            .generate_keypair()
            .unwrap();
        let server_private: [u8; 32] = server_pair.private.as_slice().try_into().unwrap();
        let server_public: [u8; 32] = server_pair.public.as_slice().try_into().unwrap();
        let client_private: [u8; 32] = client_pair.private.as_slice().try_into().unwrap();
        let client_public: [u8; 32] = client_pair.public.as_slice().try_into().unwrap();
        assert_ne!(server_private, [0; 32]);
        assert_ne!(client_private, [0; 32]);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let server_shutdown = shutdown.clone();
        let server = thread::spawn(move || {
            let mut listener_config = QRunV06PeerListenerConfig::default();
            listener_config.max_sessions = 8;
            listener_config.max_requests_per_session = 16;
            listener_config.accept_poll_interval = Duration::from_millis(10);
            serve_permissionless_history_sync_listener(
                &listener,
                listener_config,
                &server_private,
                &[client_public],
                &NETWORK,
                &PROFILE,
                server_shutdown.as_ref(),
                &source_runtime,
            )
        });

        // One page per Noise session forces reconnect and cursor resume mid-source-chain.
        let sync_config = QRunV06HistorySyncClientConfig {
            connect_timeout: Duration::from_secs(3),
            io_timeout: Duration::from_secs(5),
            max_blocks_per_page: 1,
            max_bytes_per_page: 1024 * 1024,
            max_pages: 1,
            max_rounds: 4,
        };
        let sync_result = sync_history_from_pinned_peer(
            address,
            &client_private,
            &server_public,
            &mut destination_runtime,
            &authenticator,
            sync_config,
        );
        let sync_report = sync_result.unwrap();

        // The exact same peer tip is now in the local graph with both authenticated hashes.
        // Fast-resume must release the responder snapshot without replaying its known prefix.
        let fast_resume_report = sync_history_from_pinned_peer(
            address,
            &client_private,
            &server_public,
            &mut destination_runtime,
            &authenticator,
            sync_config,
        )
        .unwrap();
        assert!(fast_resume_report.complete);
        assert_eq!(fast_resume_report.source_tip, sync_report.source_tip);
        assert_eq!(
            fast_resume_report.source_execution_tip,
            sync_report.source_execution_tip
        );
        assert_eq!(fast_resume_report.pages_imported, 0);
        assert_eq!(fast_resume_report.blocks_imported, 0);
        assert_eq!(fast_resume_report.final_height, sync_report.final_height);

        shutdown.store(true, Ordering::Release);
        let server_report = server.join().unwrap().unwrap();
        assert!(server_report.stats.accepted_connections >= 3);
        assert_eq!(sync_report.source_height, 3);
        assert_eq!(sync_report.pages_imported, 3);
        assert_eq!(sync_report.blocks_imported, 3);
        assert!(sync_report.complete);

        let synchronized = destination_runtime.status().unwrap();
        let graph = destination_runtime.fork_choice_snapshot().unwrap();
        assert_eq!(synchronized.tip, source_status.tip);
        assert_eq!(synchronized.height, source_status.height);
        assert_eq!(synchronized.state_root, source_status.state_root);
        assert!(graph.reorg_count() >= 1);
        assert!(
            graph.archive_len() >= 4,
            "the common block and both competing branch suffixes must remain in the fork archive"
        );
        let trusted_manifest_anchor = synchronized.manifest_anchor;
        drop(destination_runtime);
        drop(destination_mempool);

        // A restart must rebuild the same canonical branch and retain the competing branch set.
        let recovered = QRunV06PermissionlessNodeRuntime::open(
            &destination_dir,
            genesis,
            params,
            &authenticator,
            Some(trusted_manifest_anchor),
            &verified_pin,
        )
        .unwrap();
        let recovered_status = recovered.status().unwrap();
        let recovered_graph = recovered.fork_choice_snapshot().unwrap();
        assert_eq!(recovered_status.tip, source_status.tip);
        assert_eq!(recovered_status.height, source_status.height);
        assert_eq!(recovered_status.state_root, source_status.state_root);
        assert!(recovered_graph.archive_len() >= 4);
        drop(recovered);
        drop(source_mempool);
        let _ = fs::remove_dir_all(test_root);
    }

    fn two_independent_noise_sources_bootstrap_case(
        second_timestamp_offset: u64,
        expect_divergence: bool,
    ) {
        use crate::{
            consensus::ConsensusParameters, external_cas_anchor_candidate::ExternalCasPin,
            qrun_v06_checkpoint_candidate::qrun_v06_consensus_fingerprint,
            qrun_v06_node_supervisor_candidate::validate_bootstrap_source_snapshots,
        };

        const NETWORK: [u8; 32] = [0x91; 32];
        const PROFILE: [u8; 32] = [0x92; 32];
        const FOUNDER: [u8; 32] = [0x93; 32];
        const DOMAIN_ONE: [u8; 32] = [0xA1; 32];
        const DOMAIN_TWO: [u8; 32] = [0xA2; 32];

        let mut params = ConsensusParameters::qrun_v06_sha256d_candidate().unwrap();
        params.target_block_time_secs = 30;
        params.difficulty_window_blocks = 2;
        params.difficulty_min_ratio_divisor = 4;
        params.difficulty_max_ratio = 4;
        params.initial_target = Uint256::from_be_bytes([0x7F; 32]);
        params.pow_limit = Uint256::MAX;
        params.validate().unwrap();

        let schedule = QRunV06MiningScheduleCandidate::cp0422_research_candidate();
        let supply = Cp0604FounderControlledSupply::genesis(NETWORK, FOUNDER, schedule).unwrap();
        let descriptor = QRunV06GenesisDescriptor::new(
            NETWORK,
            PROFILE,
            FOUNDER,
            1,
            qrun_v06_consensus_fingerprint(&params).unwrap(),
            supply.policy_fingerprint(),
        )
        .unwrap();
        let genesis = QRunV06CanonicalExecutionState::cp0604_genesis_candidate_with_descriptor(
            descriptor.clone(),
            schedule,
        )
        .unwrap();
        let profile_bundle = QRunV06ProfilePinCandidate::new(
            descriptor,
            ExternalCasPin {
                provider_id: [0x94; 32],
                network_id: NETWORK,
                genesis_digest: [0x95; 32],
                receipt_key_id: [0x96; 32],
                receipt_public_key: [0x97; ML_DSA_65_PUBLIC_KEY_BYTES],
            },
        )
        .unwrap();
        let profile_pin_bytes = profile_bundle.encode().unwrap();
        let verified_pin = QRunV06VerifiedProfilePin::decode(
            &profile_pin_bytes,
            profile_bundle.commitment().unwrap(),
        )
        .unwrap();
        let authenticator =
            QRunV06HybridTransactionAuthenticator::new(LibcruxMlDsa65VerifierCandidate);

        let test_root = std::env::temp_dir().join(format!(
            "qfp6-cp0649-two-source-divergence-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        let source_one_dir = test_root.join("source-one");
        let source_two_dir = test_root.join("source-two");
        let destination_dir = test_root.join("destination");
        let source_one_pool_dir = test_root.join("source-one-pool");
        let source_two_pool_dir = test_root.join("source-two-pool");
        fs::create_dir_all(&test_root).unwrap();

        let wall_clock = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let first_timestamp = wall_clock.max(genesis.last_timestamp().saturating_add(60));
        let second_timestamp = first_timestamp.saturating_add(second_timestamp_offset);
        let stop_mining = AtomicBool::new(false);

        let build_source = |store: &std::path::Path, pool: &std::path::Path, timestamp: u64| {
            let mut runtime = QRunV06PermissionlessNodeRuntime::open(
                store,
                genesis.clone(),
                params.clone(),
                &authenticator,
                None,
                &verified_pin,
            )
            .unwrap();
            let mut mempool =
                QRunV06PermissionlessMempool::open(pool, QRunV06MempoolLimits::default()).unwrap();
            mempool
                .restore(&runtime, &authenticator, FOUNDER, timestamp)
                .unwrap();
            let mined = mempool
                .mine_one_batch(
                    &mut runtime,
                    &authenticator,
                    FOUNDER,
                    timestamp,
                    10_000,
                    &stop_mining,
                )
                .unwrap()
                .unwrap();
            assert!(mined.became_canonical);
            drop(mempool);
            runtime
        };

        // Both source nodes validate a first block from the same pinned Genesis. With a
        // zero offset they produce the same history; a nonzero offset creates sibling histories.
        let source_one = build_source(&source_one_dir, &source_one_pool_dir, first_timestamp);
        let source_two = build_source(&source_two_dir, &source_two_pool_dir, second_timestamp);
        if expect_divergence {
            assert_ne!(
                source_one.status().unwrap().tip,
                source_two.status().unwrap().tip,
                "independent source fixtures must actually contain divergent histories"
            );
        } else {
            assert_eq!(
                source_one.status().unwrap().tip,
                source_two.status().unwrap().tip,
                "independent source fixtures must contain the same history"
            );
        }

        let mut destination = QRunV06PermissionlessNodeRuntime::open(
            &destination_dir,
            genesis,
            params,
            &authenticator,
            None,
            &verified_pin,
        )
        .unwrap();

        let noise_params: snow::params::NoiseParams =
            "Noise_XX_25519_ChaChaPoly_SHA256".parse().unwrap();
        let server_one_pair = snow::Builder::new(noise_params.clone())
            .generate_keypair()
            .unwrap();
        let server_two_pair = snow::Builder::new(noise_params.clone())
            .generate_keypair()
            .unwrap();
        let client_one_pair = snow::Builder::new(noise_params.clone())
            .generate_keypair()
            .unwrap();
        let client_two_pair = snow::Builder::new(noise_params).generate_keypair().unwrap();

        let server_one_private: [u8; 32] = server_one_pair.private.as_slice().try_into().unwrap();
        let server_one_public: [u8; 32] = server_one_pair.public.as_slice().try_into().unwrap();
        let server_two_private: [u8; 32] = server_two_pair.private.as_slice().try_into().unwrap();
        let server_two_public: [u8; 32] = server_two_pair.public.as_slice().try_into().unwrap();
        let client_one_private: [u8; 32] = client_one_pair.private.as_slice().try_into().unwrap();
        let client_one_public: [u8; 32] = client_one_pair.public.as_slice().try_into().unwrap();
        let client_two_private: [u8; 32] = client_two_pair.private.as_slice().try_into().unwrap();
        let client_two_public: [u8; 32] = client_two_pair.public.as_slice().try_into().unwrap();

        let listener_one = TcpListener::bind("127.0.0.1:0").unwrap();
        let address_one = listener_one.local_addr().unwrap();
        let listener_two = TcpListener::bind("127.0.0.1:0").unwrap();
        let address_two = listener_two.local_addr().unwrap();

        let shutdown_one = Arc::new(AtomicBool::new(false));
        let shutdown_two = Arc::new(AtomicBool::new(false));
        let server_shutdown_one = shutdown_one.clone();
        let server_shutdown_two = shutdown_two.clone();

        let server_one = thread::spawn(move || {
            let mut listener_config = QRunV06PeerListenerConfig::default();
            listener_config.max_sessions = 1;
            listener_config.max_requests_per_session = 16;
            listener_config.accept_poll_interval = Duration::from_millis(10);
            serve_permissionless_history_sync_listener(
                &listener_one,
                listener_config,
                &server_one_private,
                &[client_one_public],
                &NETWORK,
                &PROFILE,
                server_shutdown_one.as_ref(),
                &source_one,
            )
        });
        let server_two = thread::spawn(move || {
            let mut listener_config = QRunV06PeerListenerConfig::default();
            listener_config.max_sessions = 1;
            listener_config.max_requests_per_session = 16;
            listener_config.accept_poll_interval = Duration::from_millis(10);
            serve_permissionless_history_sync_listener(
                &listener_two,
                listener_config,
                &server_two_private,
                &[client_two_public],
                &NETWORK,
                &PROFILE,
                server_shutdown_two.as_ref(),
                &source_two,
            )
        });

        let sync_config = QRunV06HistorySyncClientConfig {
            connect_timeout: Duration::from_secs(3),
            io_timeout: Duration::from_secs(5),
            max_blocks_per_page: 1,
            max_bytes_per_page: 1024 * 1024,
            max_pages: 1,
            max_rounds: 4,
        };
        let report_one = sync_history_from_pinned_peer(
            address_one,
            &client_one_private,
            &server_one_public,
            &mut destination,
            &authenticator,
            sync_config,
        )
        .unwrap();
        let report_two = sync_history_from_pinned_peer(
            address_two,
            &client_two_private,
            &server_two_public,
            &mut destination,
            &authenticator,
            sync_config,
        )
        .unwrap();

        let server_report_one = server_one.join().unwrap().unwrap();
        let server_report_two = server_two.join().unwrap().unwrap();
        assert!(server_report_one.stats.authenticated_sessions >= 1);
        assert!(server_report_two.stats.authenticated_sessions >= 1);
        assert!(report_one.complete && report_two.complete);
        if expect_divergence {
            assert_ne!(report_one.source_tip, report_two.source_tip);
            assert_ne!(
                report_one.source_execution_tip,
                report_two.source_execution_tip
            );
            assert!(
                report_two.blocks_imported > 0,
                "an unknown competing source tip must use the full common-base branch path"
            );
        } else {
            assert_eq!(report_one.source_tip, report_two.source_tip);
            assert_eq!(
                report_one.source_execution_tip,
                report_two.source_execution_tip
            );
            assert_eq!(
                report_two.blocks_imported, 0,
                "a previously known consensus+execution tip must use fast-resume"
            );
            assert_eq!(report_two.pages_imported, 0);
        }

        let graph = destination.fork_choice_snapshot().unwrap();
        assert!(graph.tip_for_hash(&report_one.source_tip).is_some());
        assert!(graph.tip_for_hash(&report_two.source_tip).is_some());
        let agreement = validate_bootstrap_source_snapshots(
            &graph,
            &[(DOMAIN_ONE, report_one), (DOMAIN_TWO, report_two)],
        );
        if expect_divergence {
            assert!(
                agreement.unwrap_err().contains("divergent histories"),
                "valid but divergent independently authenticated sources must fail the bootstrap gate"
            );
        } else {
            assert!(
                agreement.is_ok(),
                "two independent Noise sources reporting the same validated history must pass the bootstrap gate"
            );
        }

        drop(destination);
        let _ = fs::remove_dir_all(test_root);
    }

    #[test]
    fn two_independent_noise_sources_with_same_history_pass_bootstrap_agreement() {
        two_independent_noise_sources_bootstrap_case(0, false);
    }

    #[test]
    fn two_independent_noise_sources_with_divergent_histories_fail_bootstrap_agreement() {
        two_independent_noise_sources_bootstrap_case(60, true);
    }
}

#[cfg(test)]
mod qfp6_history_sync_handshake_retry_tests {
    use super::*;

    #[test]
    fn transient_handshake_io_errors_are_retryable_but_trust_and_protocol_errors_fail_closed() {
        assert!(is_retryable_history_sync_handshake_error(
            &QRunV06NoiseError::HandshakeTimeout
        ));
        for message in [
            "peer closed connection without sending TLS close_notify",
            "connection reset by peer",
            "broken pipe",
            "unexpected EOF",
        ] {
            assert!(
                is_retryable_history_sync_handshake_error(&QRunV06NoiseError::Io(message.into())),
                "expected transient I/O error to retry: {message}"
            );
        }
        assert!(!is_retryable_history_sync_handshake_error(
            &QRunV06NoiseError::Io("permission denied".into())
        ));
        assert!(!is_retryable_history_sync_handshake_error(
            &QRunV06NoiseError::UntrustedPeer
        ));
        assert!(!is_retryable_history_sync_handshake_error(
            &QRunV06NoiseError::MalformedHandshake
        ));
        assert!(!is_retryable_history_sync_handshake_error(
            &QRunV06NoiseError::InvalidNetworkOrProfile
        ));
        assert!(!is_retryable_history_sync_handshake_error(
            &QRunV06NoiseError::Handshake("cryptographic failure".into())
        ));
    }

    #[test]
    fn history_sync_handshake_retry_count_is_finite() {
        assert_eq!(QFP6_HISTORY_SYNC_MAX_NOISE_HANDSHAKE_ATTEMPTS, 8);
    }

    #[test]
    fn only_transient_transport_closures_are_retryable() {
        assert!(is_retryable_history_sync_transport_error(
            &QRunV06HistorySyncServiceError::Noise(
                "Noise(Io(\"peer closed connection without sending TLS close_notify\"))".into()
            )
        ));
        assert!(is_retryable_history_sync_transport_error(
            &QRunV06HistorySyncServiceError::Noise(
                "Noise(Io(\"connection reset by peer\"))".into()
            )
        ));
        assert!(!is_retryable_history_sync_transport_error(
            &QRunV06HistorySyncServiceError::Noise("UntrustedPeer".into())
        ));
        assert!(!is_retryable_history_sync_transport_error(
            &QRunV06HistorySyncServiceError::Wire("malformed Q6HR".into())
        ));
        assert!(!is_retryable_history_sync_transport_error(
            &QRunV06HistorySyncServiceError::SnapshotMismatch
        ));
        assert_eq!(QFP6_HISTORY_SYNC_MAX_TRANSIENT_TRANSPORT_RETRIES, 8);
    }
}

#[cfg(test)]
mod q6ar_pull_client_tests {
    use super::*;
    use crate::{
        qrun_v06_bootstrap_trust_domain_candidate::BootstrapTrustDomainPolicy,
        qrun_v06_noise_transport_candidate::QRunV06NoiseSession,
        qrun_v06_peer_address_manager_candidate::{
            PeerAddressSource, QRunV06PeerAddressBookCandidate,
        },
        qrun_v06_peer_address_relay_candidate::{
            decode_q6ar_pull_request, encode_q6ar_pull_response, Q6arAddress, Q6arAdvertisement,
        },
    };
    use std::{
        fs,
        net::TcpListener,
        thread,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    fn keypair() -> ([u8; 32], [u8; 32]) {
        let params = "Noise_XX_25519_ChaChaPoly_SHA256".parse().unwrap();
        let pair = snow::Builder::new(params).generate_keypair().unwrap();
        (
            pair.private.as_slice().try_into().unwrap(),
            pair.public.as_slice().try_into().unwrap(),
        )
    }

    #[test]
    fn pinned_relay_pull_client_persists_only_untrusted_candidate_metadata() {
        const NETWORK: [u8; 32] = [0xA1; 32];
        const PROFILE: [u8; 32] = [0xA2; 32];
        const DOMAIN: [u8; 32] = [0xA3; 32];

        let (server_private, server_public) = keypair();
        let (client_private, client_public) = keypair();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut noise = QRunV06NoiseSession::accept(
                &mut stream,
                &server_private,
                &[client_public],
                &NETWORK,
                &PROFILE,
            )
            .unwrap();
            let request_frame = noise.read_record(&mut stream).unwrap();
            let request = decode_q6ar_pull_request(&request_frame, &NETWORK, &PROFILE).unwrap();
            let issued_at_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let advertisement = Q6arAdvertisement {
                network_id: NETWORK,
                profile_id: PROFILE,
                issued_at_secs,
                ttl_secs: 600,
                addresses: vec![Q6arAddress {
                    endpoint: "8.8.8.8:8333".parse().unwrap(),
                    noise_static_public_key: [0xA4; 32],
                }],
            };
            let response = encode_q6ar_pull_response(&request, Some(&advertisement)).unwrap();
            noise.write_record(&mut stream, &response).unwrap();
        });

        let root = std::env::temp_dir().join(format!(
            "q6ar-pull-client-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        let mut book =
            QRunV06PeerAddressBookCandidate::open(root.join("peers.q6pa"), NETWORK, PROFILE)
                .unwrap();
        let trust_domains =
            BootstrapTrustDomainPolicy::new([(server_public, DOMAIN)], 8, 1).unwrap();
        let now_ms: u64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis()
            .try_into()
            .unwrap();
        book.bind_trust_domain_registry(&trust_domains, now_ms)
            .unwrap();

        let accepted = pull_q6ar_candidates_from_pinned_peer(
            address,
            &client_private,
            &server_public,
            &NETWORK,
            &PROFILE,
            QRunV06HistorySyncClientConfig {
                connect_timeout: Duration::from_secs(3),
                io_timeout: Duration::from_secs(5),
                ..QRunV06HistorySyncClientConfig::default()
            },
            None,
            &mut book,
            &trust_domains,
        )
        .unwrap();
        server.join().unwrap();

        assert_eq!(accepted, 1);
        assert_eq!(book.records().count(), 1);
        let candidate = book.records().next().unwrap();
        assert_eq!(candidate.address, "8.8.8.8:8333");
        assert_eq!(candidate.source, PeerAddressSource::Gossip);
        assert_eq!(candidate.advertised_noise_static_key, Some([0xA4; 32]));
        assert_eq!(candidate.relay_static_public_key, Some(server_public));
        assert!(candidate.relay_static_key_pinned);
        assert!(candidate.operator_approved_noise_static_key.is_none());
        assert!(
            book.approved_peer_pins(now_ms.saturating_add(1), 8)
                .is_empty(),
            "a pulled candidate must not enter the outbound trusted set automatically"
        );

        drop(book);
        let _ = fs::remove_dir_all(root);
    }
}

#[cfg(test)]
mod q6pd_pull_noise_integration_tests {
    use super::*;
    use crate::{
        qrun_v06_peer_discovery_candidate::{sign_q6pd_peer_record, Q6PD_MIN_RECORD_BYTES},
        qrun_v06_peer_discovery_store_candidate::{Q6pdIngestResult, Q6pdPeerRecordStore},
    };
    use ed25519_dalek::SigningKey;
    use std::{
        fs,
        net::TcpListener,
        thread,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    const NETWORK: [u8; 32] = [0xB1; 32];
    const PROFILE: [u8; 32] = [0xB2; 32];

    fn keypair() -> ([u8; 32], [u8; 32]) {
        let params = "Noise_XX_25519_ChaChaPoly_SHA256".parse().unwrap();
        let pair = snow::Builder::new(params).generate_keypair().unwrap();
        (
            pair.private.as_slice().try_into().unwrap(),
            pair.public.as_slice().try_into().unwrap(),
        )
    }

    #[test]
    fn q6pd_pull_and_bidirectional_gossip_push_run_over_one_pinned_noise_session() {
        let (server_private, server_public) = keypair();
        let (client_private, _) = keypair();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let root = std::env::temp_dir().join(format!(
            "q6pd-noise-pull-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        let now_ms: u64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis()
            .try_into()
            .unwrap();
        let now_secs = now_ms / 1000;
        let identity = SigningKey::from_bytes(&[0xB3; 32]);
        let record_wire = sign_q6pd_peer_record(
            NETWORK,
            PROFILE,
            [0xB4; 32],
            "8.8.4.4:30336".parse().unwrap(),
            1,
            now_secs,
            600,
            &identity,
        )
        .unwrap();
        assert_eq!(
            record_wire.len(),
            Q6PD_MIN_RECORD_BYTES + 2,
            "IPv4 Q6PD v2 without SNI must exercise the minimum wire length"
        );
        let mut source_store =
            Q6pdPeerRecordStore::open(root.join("source.q6pd"), NETWORK, PROFILE, now_ms).unwrap();
        assert_eq!(
            source_store.ingest(&record_wire, now_ms).unwrap(),
            Q6pdIngestResult::Inserted
        );

        // The client also knows a third-party peer C. After it pulls A from the
        // server, it must push C back over the same exact-key-pinned Noise session.
        let third_identity = SigningKey::from_bytes(&[0xB5; 32]);
        let third_wire = sign_q6pd_peer_record(
            NETWORK,
            PROFILE,
            [0xB6; 32],
            "1.0.0.1:30336".parse().unwrap(),
            1,
            now_secs,
            600,
            &third_identity,
        )
        .unwrap();

        let source_store = std::sync::Arc::new(std::sync::Mutex::new(source_store));
        let server_source_store = source_store.clone();
        let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let server_shutdown = shutdown.clone();
        let server = thread::spawn(move || {
            let mut listener_config =
                crate::qrun_v06_peer_listener_candidate::QRunV06PeerListenerConfig::default();
            listener_config.max_sessions = 1;
            listener_config.max_requests_per_session = 2;
            let report = crate::qrun_v06_peer_listener_candidate::serve_qfp6_noise_listener_with_history_and_q6ar_relay_pins(
                &listener,
                listener_config,
                &server_private,
                &[],
                &[],
                &NETWORK,
                &PROFILE,
                &server_shutdown,
                |_advertisement| Ok(()),
                move |_guard, request_frame| {
                    if request_frame.get(..4)
                        == Some(&crate::qrun_v06_peer_discovery_candidate::Q6PD_PULL_REQUEST_MAGIC)
                    {
                        let response = server_source_store
                            .lock()
                            .map_err(|_| "Q6PD source-store lock poisoned".to_string())?
                            .respond_to_pull_frame(request_frame, now_secs)
                            .map_err(|error| error.to_string())?;
                        return Ok(vec![response]);
                    }
                    if request_frame.get(..4)
                        == Some(&crate::qrun_v06_peer_discovery_candidate::Q6PD_GOSSIP_PUSH_REQUEST_MAGIC)
                    {
                        let request = crate::qrun_v06_peer_discovery_candidate::decode_q6pd_gossip_push_request(
                            request_frame,
                            &NETWORK,
                            &PROFILE,
                            now_secs,
                        )
                        .map_err(|error| error.to_string())?;
                        let mut counts = crate::qrun_v06_peer_discovery_candidate::Q6pdGossipPushCounts {
                            inserted: 0,
                            updated: 0,
                            duplicate: 0,
                            rejected: 0,
                        };
                        let mut source_store = server_source_store
                            .lock()
                            .map_err(|_| "Q6PD source-store lock poisoned".to_string())?;
                        for wire in &request.record_wires {
                            match source_store.ingest(wire, now_ms) {
                                Ok(Q6pdIngestResult::Inserted) => {
                                    counts.inserted = counts.inserted.saturating_add(1)
                                }
                                Ok(Q6pdIngestResult::Updated) => {
                                    counts.updated = counts.updated.saturating_add(1)
                                }
                                Ok(Q6pdIngestResult::Duplicate) => {
                                    counts.duplicate = counts.duplicate.saturating_add(1)
                                }
                                Err(_) => counts.rejected = counts.rejected.saturating_add(1),
                            }
                        }
                        let ack = crate::qrun_v06_peer_discovery_candidate::encode_q6pd_gossip_push_response(
                            &request,
                            counts,
                        );
                        return Ok(vec![ack.to_vec()]);
                    }
                    Err("unexpected Q6PD integration-test frame".into())
                },
            )
            .unwrap();
            (report, source_store)
        });

        let mut destination_store =
            Q6pdPeerRecordStore::open(root.join("destination.q6pd"), NETWORK, PROFILE, now_ms)
                .unwrap();
        assert_eq!(
            destination_store.ingest(&third_wire, now_ms).unwrap(),
            Q6pdIngestResult::Inserted
        );
        let report = pull_q6pd_peer_records_from_pinned_peer(
            address,
            &client_private,
            &server_public,
            &NETWORK,
            &PROFILE,
            QRunV06HistorySyncClientConfig {
                connect_timeout: Duration::from_secs(3),
                io_timeout: Duration::from_secs(5),
                ..QRunV06HistorySyncClientConfig::default()
            },
            None,
            8,
            &mut destination_store,
        )
        .unwrap();
        shutdown.store(true, std::sync::atomic::Ordering::Release);
        let (listener_report, relay_store) = server.join().unwrap();
        assert_eq!(listener_report.stats.requests_received, 2);
        assert_eq!(listener_report.stats.responses_written, 2);
        assert_eq!(listener_report.stats.handler_failures, 0);

        assert_eq!(report.records_received, 1);
        assert_eq!(report.records_inserted, 1);
        assert_eq!(report.records_rejected, 0);
        let candidates = destination_store.candidates(now_ms);
        assert_eq!(candidates.len(), 2);
        assert!(candidates.iter().any(|record| {
            record.endpoint == "8.8.4.4:30336".parse().unwrap()
                && record.noise_static_public_key == [0xB4; 32]
        }));
        assert!(candidates.iter().any(|record| {
            record.endpoint == "1.0.0.1:30336".parse().unwrap()
                && record.noise_static_public_key == [0xB6; 32]
        }));

        // A has already been on the relay; C came only from the joining client's
        // inventory. The receiver must mark A duplicate and persist C as a new peer.
        let relayed_candidates = relay_store.lock().unwrap().candidates(now_ms);
        assert_eq!(relayed_candidates.len(), 2);
        assert!(relayed_candidates.iter().any(|record| {
            record.endpoint == "1.0.0.1:30336".parse().unwrap()
                && record.noise_static_public_key == [0xB6; 32]
        }));

        drop(destination_store);
        drop(relay_store);
        let _ = fs::remove_dir_all(root);
    }
}

#[cfg(test)]
mod q6pd_dns_seed_failover_tests {
    use super::resolve_q6pd_dns_seed_addresses_with;
    use std::net::SocketAddr;

    #[test]
    fn dns_seed_preserves_resolver_preference_and_deduplicates_routes() {
        let preferred_ipv6 = "[2a00:dd80:3a::336]:443".parse::<SocketAddr>().unwrap();
        let first_ipv4 = "176.58.88.82:443".parse::<SocketAddr>().unwrap();
        let second_ipv4 = "176.58.92.199:443".parse::<SocketAddr>().unwrap();
        let resolved = vec![
            preferred_ipv6,
            first_ipv4,
            preferred_ipv6,
            second_ipv4,
            first_ipv4,
        ];
        let routes = resolve_q6pd_dns_seed_addresses_with(
            "heymed.tail2a756d.ts.net",
            443,
            move |host, port| {
                assert_eq!(host, "heymed.tail2a756d.ts.net");
                assert_eq!(port, 443);
                Ok(resolved.clone())
            },
        )
        .unwrap();
        assert_eq!(routes.len(), 3);
        assert_eq!(routes[0], preferred_ipv6);
        assert_eq!(routes[1], first_ipv4);
        assert_eq!(routes[2], second_ipv4);
        assert!(routes.iter().all(|route| route.port() == 443));
    }

    #[test]
    fn dns_seed_rejects_private_or_mixed_untrusted_routes() {
        let resolved = vec![
            "176.58.88.82:443".parse::<SocketAddr>().unwrap(),
            "10.0.0.4:443".parse::<SocketAddr>().unwrap(),
        ];
        let result = resolve_q6pd_dns_seed_addresses_with("seed.qfp6.example", 443, move |_, _| {
            Ok(resolved.clone())
        });
        assert!(result.is_err());
    }

    #[test]
    fn dns_seed_rejects_empty_oversized_and_non_public_names() {
        assert!(
            resolve_q6pd_dns_seed_addresses_with("seed.qfp6.example", 443, |_, _| {
                Ok(Vec::new())
            })
            .is_err()
        );

        let too_many = vec!["176.58.88.82:443".parse::<SocketAddr>().unwrap(); 17];
        assert!(
            resolve_q6pd_dns_seed_addresses_with("seed.qfp6.example", 443, move |_, _| Ok(
                too_many.clone()
            ),)
            .is_err()
        );

        assert!(
            resolve_q6pd_dns_seed_addresses_with("seed.qfp6.local", 443, |_, _| {
                Ok(vec!["176.58.88.82:443".parse().unwrap()])
            })
            .is_err()
        );
        assert!(
            resolve_q6pd_dns_seed_addresses_with("seed.qfp6.example", 30336, |_, _| {
                Ok(vec!["176.58.88.82:30336".parse().unwrap()])
            })
            .is_err()
        );
    }
}
