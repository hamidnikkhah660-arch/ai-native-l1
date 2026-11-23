//! CP-0555 bounded QFP6 authenticated peer-listener lifecycle candidate.
//!
//! This module provides a bounded TCP accept/session loop. The Noise XX handshake stage
//! uses a fixed four-worker pool and an eight-connection bounded queue; after handshake,
//! one authenticated application session at a time is dispatched on the listener thread.
//! It rejects unsafe private-mode binds, supports pinned or explicitly anonymous public
//! inbound sessions, creates one replay guard per connection, caps sessions/requests,
//! validates fixed-width Q6PA/Q6TA/Q6MA replies and ordered Q6HC history replies, and shuts down
//! with cancellable handshakes and joined workers.
//!
//! It is a library service candidate, not a node binary, production supervisor, miner,
//! RPC endpoint, mempool, or Mainnet release. Pinned mode permits private/overlay/loopback binds
//! and globally routable binds only with a non-empty static-key allow-list. Explicit anonymous-open
//! mode can serve candidate public binds, but remains unauthenticated and unqualified for broad
//! Internet exposure. External callbacks must enforce their own bounded network deadlines.

use crate::{
    external_cas_anchor_candidate::ExternalCasProviderTransport,
    qrun_v06_node_runtime_candidate::{
        decode_qrun_v06_peer_block_request, process_qrun_v06_peer_block_frame,
        process_qrun_v06_peer_block_frame_with_qap1,
        process_qrun_v06_permissionless_peer_block_frame,
        process_qrun_v06_permissionless_peer_block_frame_with_quote_asset_authorization,
        QRunV06NodeAnchorGate, QRunV06NodeRuntime, QRunV06PeerAdmissionResponse,
        QRunV06PeerAdmissionStatus, QRunV06PeerIngressError, QRunV06PeerReplayGuard,
        QRUN_V06_PEER_ADMISSION_MAGIC, QRUN_V06_PEER_ADMISSION_RESPONSE_BYTES,
        QRUN_V06_PEER_FRAME_VERSION,
    },
    qrun_v06_noise_transport_candidate::{QRunV06NoiseError, QRunV06NoiseSession},
    qrun_v06_permissionless_runtime_candidate::QRunV06PermissionlessNodeRuntime,
    qrun_v06_pow_fork_choice_candidate::QRunV06QuoteAssetAuthorizationProvider,
    qrun_v06_q6pd_session_candidate::{
        decode_q6pd_session_open, decode_q6pd_session_open_ack, encode_q6pd_session_open_ack,
        serve_q6pd_persistent_session, try_reserve_q6pd_persistent_session,
        Q6PD_SESSION_OPEN_MAGIC,
    },
    qrun_v06_qap1_coordinator_candidate::{
        QRunV06Qap1AnchorTransport, QRunV06Qap1ExternalCoordinator,
    },
    state_machine::TransactionAuthenticator,
    v4_fat1_trust_candidate::MlDsa65Verifier,
};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{sync_channel, Receiver, SyncSender, TryRecvError, TrySendError},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

pub const QRUN_V06_LISTENER_MAX_SESSIONS: usize = 1024;
pub const QRUN_V06_LISTENER_MAX_REQUESTS_PER_SESSION: usize = 64;
pub const QRUN_V06_LISTENER_MAX_FAILED_HANDSHAKES: usize = 64;
pub const QRUN_V06_LISTENER_MAX_ACCEPT_POLL: Duration = Duration::from_millis(250);
pub const QRUN_V06_LISTENER_MIN_ACCEPT_POLL: Duration = Duration::from_millis(10);

// Pre-authentication admission is bounded independently of peer identity and trust.
// IPv4 peers share a /24 bucket; IPv6 peers share a /56 bucket. A small global bucket
// also bounds work when an attacker rotates source prefixes.
const QRUN_V06_SOURCE_PREFIX_BUCKETS_MAX: usize = 4096;
const QRUN_V06_SOURCE_PREFIX_IDLE_TTL: Duration = Duration::from_secs(600);
const QRUN_V06_SOURCE_PREFIX_REFILL: Duration = Duration::from_secs(2);
const QRUN_V06_GLOBAL_HANDSHAKE_BURST: usize = 64;
const QRUN_V06_GLOBAL_HANDSHAKE_REFILL: Duration = Duration::from_millis(250);
const QRUN_V06_HANDSHAKE_WORKERS: usize = 4;
const QRUN_V06_HANDSHAKE_QUEUE_CAPACITY: usize = 8;
const QRUN_V06_MAX_APPLICATION_SESSION_DURATION: Duration = Duration::from_secs(30);
const QRUN_V06_MAX_APPLICATION_RECORD_READ_BUDGET: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
enum QRunV06PeerSourcePrefix {
    V4([u8; 3]),
    V6([u8; 7]),
}

impl QRunV06PeerSourcePrefix {
    fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(address) => {
                let octets = address.octets();
                Self::V4([octets[0], octets[1], octets[2]])
            }
            IpAddr::V6(address) => {
                let octets = address.octets();
                // Normalize IPv4-mapped IPv6 addresses to the same /24 as native IPv4.
                if octets[..10].iter().all(|byte| *byte == 0)
                    && octets[10] == 0xff
                    && octets[11] == 0xff
                {
                    Self::V4([octets[12], octets[13], octets[14]])
                } else {
                    let mut prefix = [0u8; 7];
                    prefix.copy_from_slice(&octets[..7]);
                    Self::V6(prefix)
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct QRunV06AdmissionBucket {
    tokens: usize,
    last_refill: Instant,
    last_seen: Instant,
}

impl QRunV06AdmissionBucket {
    fn new(capacity: usize, now: Instant) -> Self {
        Self {
            tokens: capacity,
            last_refill: now,
            last_seen: now,
        }
    }

    fn refill(&mut self, capacity: usize, interval: Duration, now: Instant) {
        let interval_nanos = interval.as_nanos();
        if interval_nanos == 0 {
            return;
        }
        let elapsed_nanos = now.saturating_duration_since(self.last_refill).as_nanos();
        let intervals = elapsed_nanos / interval_nanos;
        if intervals == 0 {
            return;
        }
        let refill = usize::try_from(intervals).unwrap_or(usize::MAX);
        self.tokens = self.tokens.saturating_add(refill).min(capacity);
        let advance_nanos = interval_nanos.saturating_mul(intervals);
        let advance = Duration::from_nanos(u64::try_from(advance_nanos).unwrap_or(u64::MAX));
        self.last_refill += advance;
    }
}

pub(crate) struct QRunV06PeerSourceRateLimiter {
    prefixes: HashMap<QRunV06PeerSourcePrefix, QRunV06AdmissionBucket>,
    global: QRunV06AdmissionBucket,
}

impl QRunV06PeerSourceRateLimiter {
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            prefixes: HashMap::new(),
            global: QRunV06AdmissionBucket::new(QRUN_V06_GLOBAL_HANDSHAKE_BURST, now),
        }
    }

    fn allow(&mut self, peer: SocketAddr, prefix_burst: usize, now: Instant) -> bool {
        self.prefixes.retain(|_, bucket| {
            now.saturating_duration_since(bucket.last_seen) < QRUN_V06_SOURCE_PREFIX_IDLE_TTL
        });
        self.global.refill(
            QRUN_V06_GLOBAL_HANDSHAKE_BURST,
            QRUN_V06_GLOBAL_HANDSHAKE_REFILL,
            now,
        );
        if self.global.tokens == 0 {
            return false;
        }

        let prefix = QRunV06PeerSourcePrefix::from_ip(peer.ip());
        if !self.prefixes.contains_key(&prefix) {
            if self.prefixes.len() >= QRUN_V06_SOURCE_PREFIX_BUCKETS_MAX {
                if let Some(oldest) = self
                    .prefixes
                    .iter()
                    .min_by_key(|(_, bucket)| bucket.last_seen)
                    .map(|(key, _)| *key)
                {
                    self.prefixes.remove(&oldest);
                }
            }
            self.prefixes
                .insert(prefix, QRunV06AdmissionBucket::new(prefix_burst, now));
        }

        let bucket = self
            .prefixes
            .get_mut(&prefix)
            .expect("source-prefix bucket inserted or retained");
        bucket.refill(prefix_burst, QRUN_V06_SOURCE_PREFIX_REFILL, now);
        bucket.last_seen = now;
        if bucket.tokens == 0 {
            return false;
        }

        bucket.tokens -= 1;
        self.global.tokens -= 1;
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QRunV06PeerListenerConfig {
    /// The number of successfully established Noise sessions before this supervised run returns.
    /// Failed or throttled unauthenticated connection attempts do not consume this session budget.
    pub max_sessions: usize,
    /// The maximum number of encrypted Q6PB/Q6PA, Q6TI/Q6TA, Q6MO/Q6MA or Q6HS/Q6HC exchanges on one authenticated session.
    pub max_requests_per_session: usize,
    /// Per-source-prefix initial handshake burst before temporary throttling.
    /// Buckets refill one token every two seconds; this no longer shuts down the listener.
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
    /// Established Noise sessions without an operator-pinned remote static key.
    pub unverified_peer_sessions: usize,
    pub rejected_handshakes: usize,
    /// Connections dropped before Noise because a bounded source/global admission bucket was empty.
    pub rate_limited_connections: usize,
    /// Connections dropped because the bounded handshake queue was full.
    pub handshake_queue_rejections: usize,
    /// Handshakes interrupted because the listener/supervisor was shutting down.
    pub cancelled_handshakes: usize,
    pub requests_received: usize,
    pub responses_written: usize,
    pub handler_failures: usize,
    pub malformed_responses: usize,
    /// Rejected Q6AR advertisements. These are peer input failures, not node-fatal handler errors.
    pub q6ar_rejections: usize,
    pub sessions_closed: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QRunV06PeerListenerReport {
    pub stats: QRunV06PeerListenerStats,
    pub stop_reason: QRunV06PeerListenerStopReason,
}

fn application_session_record_read_budget(
    session_deadline: Instant,
    now: Instant,
) -> Option<Duration> {
    let remaining = session_deadline.saturating_duration_since(now);
    if remaining.is_zero() {
        None
    } else {
        Some(remaining.min(QRUN_V06_MAX_APPLICATION_RECORD_READ_BUDGET))
    }
}

struct QRunV06HandshakeJob {
    stream: TcpStream,
    peer_addr: SocketAddr,
}

struct QRunV06HandshakeCompletion {
    stream: TcpStream,
    peer_addr: SocketAddr,
    result: Result<QRunV06NoiseSession, QRunV06NoiseError>,
}

/// Fixed-size handshake stage. Authenticated sessions are returned to the listener thread;
/// canonical runtime callbacks are never invoked by these workers.
struct QRunV06HandshakeWorkerPool {
    jobs: Option<SyncSender<QRunV06HandshakeJob>>,
    cancelled: Arc<AtomicBool>,
    workers: Vec<JoinHandle<()>>,
}

impl QRunV06HandshakeWorkerPool {
    fn new(
        local_static_private_key: &[u8; 32],
        trusted_remote_static_public_keys: &[[u8; 32]],
        q6ar_relay_static_public_key_pins: &[[u8; 32]],
        network_id: &[u8; 32],
        profile_id: &[u8; 32],
    ) -> (Self, Receiver<QRunV06HandshakeCompletion>) {
        let (jobs_tx, jobs_rx) =
            sync_channel::<QRunV06HandshakeJob>(QRUN_V06_HANDSHAKE_QUEUE_CAPACITY);
        let (completed_tx, completed_rx) =
            sync_channel::<QRunV06HandshakeCompletion>(QRUN_V06_HANDSHAKE_WORKERS);
        let shared_jobs = Arc::new(Mutex::new(jobs_rx));
        let cancelled = Arc::new(AtomicBool::new(false));
        let mut workers = Vec::with_capacity(QRUN_V06_HANDSHAKE_WORKERS);

        for _ in 0..QRUN_V06_HANDSHAKE_WORKERS {
            let jobs_rx = Arc::clone(&shared_jobs);
            let completed_tx = completed_tx.clone();
            let cancelled = Arc::clone(&cancelled);
            let local_key = zeroize::Zeroizing::new(*local_static_private_key);
            let trusted_keys = trusted_remote_static_public_keys.to_vec();
            let q6ar_pins = q6ar_relay_static_public_key_pins.to_vec();
            let network = *network_id;
            let profile = *profile_id;

            workers.push(thread::spawn(move || loop {
                let next_job = {
                    let receiver = match jobs_rx.lock() {
                        Ok(receiver) => receiver,
                        Err(_) => break,
                    };
                    receiver.recv()
                };
                let job = match next_job {
                    Ok(job) => job,
                    Err(_) => break,
                };
                if cancelled.load(Ordering::Acquire) {
                    drop(job.stream);
                    continue;
                }

                let mut stream = job.stream;
                let result = if trusted_keys.is_empty() {
                    QRunV06NoiseSession::accept_unpinned_with_optional_pins_and_shutdown(
                        &mut stream,
                        &local_key,
                        &network,
                        &profile,
                        &q6ar_pins,
                        &cancelled,
                    )
                } else {
                    QRunV06NoiseSession::accept_with_shutdown(
                        &mut stream,
                        &local_key,
                        &trusted_keys,
                        &network,
                        &profile,
                        &cancelled,
                    )
                };
                let completion = QRunV06HandshakeCompletion {
                    stream,
                    peer_addr: job.peer_addr,
                    result,
                };
                if completed_tx.send(completion).is_err() {
                    break;
                }
            }));
        }
        drop(completed_tx);

        (
            Self {
                jobs: Some(jobs_tx),
                cancelled,
                workers,
            },
            completed_rx,
        )
    }

    fn try_submit(
        &self,
        job: QRunV06HandshakeJob,
    ) -> Result<(), TrySendError<QRunV06HandshakeJob>> {
        match self.jobs.as_ref() {
            Some(sender) => sender.try_send(job),
            None => Err(TrySendError::Disconnected(job)),
        }
    }
}

impl Drop for QRunV06HandshakeWorkerPool {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        self.jobs.take();
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

fn is_shared_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && (64..=127).contains(&octets[1])
}

fn ipv4_in_prefix(address: Ipv4Addr, network: Ipv4Addr, prefix: u32) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (u32::from(address) & mask) == (u32::from(network) & mask)
}

fn ipv6_in_prefix(address: Ipv6Addr, network: Ipv6Addr, prefix: u32) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    (u128::from(address) & mask) == (u128::from(network) & mask)
}

fn is_publicly_routable_pinned_bind_ip(ip: IpAddr) -> bool {
    // A wildcard exposes all local interfaces, but only to the non-empty remote-key allow-list.
    if ip.is_unspecified() {
        return true;
    }
    match ip {
        IpAddr::V4(address) => {
            !address.is_loopback()
                && !address.is_private()
                && !address.is_link_local()
                && !address.is_multicast()
                && !address.is_broadcast()
                && !ipv4_in_prefix(address, Ipv4Addr::new(0, 0, 0, 0), 8)
                && !ipv4_in_prefix(address, Ipv4Addr::new(100, 64, 0, 0), 10)
                && !ipv4_in_prefix(address, Ipv4Addr::new(192, 0, 0, 0), 24)
                && !ipv4_in_prefix(address, Ipv4Addr::new(192, 0, 2, 0), 24)
                && !ipv4_in_prefix(address, Ipv4Addr::new(192, 88, 99, 0), 24)
                && !ipv4_in_prefix(address, Ipv4Addr::new(198, 18, 0, 0), 15)
                && !ipv4_in_prefix(address, Ipv4Addr::new(198, 51, 100, 0), 24)
                && !ipv4_in_prefix(address, Ipv4Addr::new(203, 0, 113, 0), 24)
                && !ipv4_in_prefix(address, Ipv4Addr::new(240, 0, 0, 0), 4)
        }
        IpAddr::V6(address) => {
            let octets = address.octets();
            let ipv4_mapped = octets[..10].iter().all(|byte| *byte == 0)
                && octets[10] == 0xff
                && octets[11] == 0xff;
            if ipv4_mapped {
                return is_publicly_routable_pinned_bind_ip(IpAddr::V4(Ipv4Addr::new(
                    octets[12], octets[13], octets[14], octets[15],
                )));
            }
            let unique_local = octets[0] & 0xfe == 0xfc;
            let link_local = octets[0] == 0xfe && octets[1] & 0xc0 == 0x80;
            !address.is_loopback()
                && !address.is_multicast()
                && !unique_local
                && !link_local
                && !ipv6_in_prefix(
                    address,
                    Ipv6Addr::from([0x00, 0x64, 0xff, 0x9b, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                    48,
                )
                && !ipv6_in_prefix(
                    address,
                    Ipv6Addr::from([0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                    64,
                )
                && !ipv6_in_prefix(
                    address,
                    Ipv6Addr::from([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                    32,
                )
                && !ipv6_in_prefix(
                    address,
                    Ipv6Addr::from([0x20, 0x01, 0, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                    48,
                )
                && !ipv6_in_prefix(
                    address,
                    Ipv6Addr::from([0x20, 0x01, 0, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                    28,
                )
                && !ipv6_in_prefix(
                    address,
                    Ipv6Addr::from([0x20, 0x01, 0, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                    28,
                )
                && !ipv6_in_prefix(
                    address,
                    Ipv6Addr::from([0x20, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                    16,
                )
                && !ipv6_in_prefix(
                    address,
                    Ipv6Addr::from([0x3f, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                    20,
                )
        }
    }
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

/// Q6QA-aware Q6PB listener callback. External quote blocks are accepted only after fresh
/// Q6TS/Q6QA authorization against the exact envelope height and independently pinned floor.
pub fn process_qfp6_peer_frame_with_permissionless_runtime_and_quote_asset_authorization<
    T: TransactionAuthenticator,
>(
    runtime: &mut QRunV06PermissionlessNodeRuntime,
    replay_guard: &mut QRunV06PeerReplayGuard,
    frame: &[u8],
    authenticator: &T,
    quote_authorizer: &mut QRunV06QuoteAssetAuthorizationProvider<'_>,
) -> Result<[u8; QRUN_V06_PEER_ADMISSION_RESPONSE_BYTES], String> {
    let response = process_qrun_v06_permissionless_peer_block_frame_with_quote_asset_authorization(
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

/// Run a bounded QFP6 Noise XX accept loop with fixed, bounded handshake concurrency
/// over an already-bound TCP listener.
///
/// Requirements:
/// - Bind only to loopback, RFC1918/private LAN, IPv6 ULA/link-local, or NetBird/shared
///   100.64/10 overlay addresses. Wildcard and public addresses are rejected.
/// - Provide at least one explicit nonzero pinned remote static key.
/// - Set a finite session/request/rejection budget and pass an explicit shutdown flag.
/// - The callback must use `process_qfp6_peer_frame_with_runtime` (or an equivalent audited
///   admission path) and must have bounded external-provider calls.
///
/// Only one established application session is processed at a time, preserving exclusive
/// access to the canonical runtime/store. The pre-session Noise handshake uses four fixed
/// workers and an eight-job queue; queue overflow drops the connection before handshake.
/// Each handshake has an eight-second absolute deadline and is cancellable during shutdown.
/// This function does not provide parallel application-state processing, a process supervisor,
/// automatic listener binding, public peer discovery, or node shutdown orchestration.
pub fn serve_qfp6_noise_listener<F>(
    listener: &TcpListener,
    config: QRunV06PeerListenerConfig,
    local_static_private_key: &[u8; 32],
    trusted_remote_static_public_keys: &[[u8; 32]],
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
    shutdown: &AtomicBool,
    on_q6pb: F,
) -> Result<QRunV06PeerListenerReport, QRunV06PeerListenerError>
where
    F: FnMut(
        &mut QRunV06PeerReplayGuard,
        &[u8],
    ) -> Result<[u8; QRUN_V06_PEER_ADMISSION_RESPONSE_BYTES], String>,
{
    let mut source_rate_limiter = QRunV06PeerSourceRateLimiter::new(Instant::now());
    serve_qfp6_noise_listener_with_rate_limiter(
        listener,
        config,
        local_static_private_key,
        trusted_remote_static_public_keys,
        network_id,
        profile_id,
        shutdown,
        on_q6pb,
        &mut source_rate_limiter,
    )
}

pub(crate) fn serve_qfp6_noise_listener_with_rate_limiter<F>(
    listener: &TcpListener,
    config: QRunV06PeerListenerConfig,
    local_static_private_key: &[u8; 32],
    trusted_remote_static_public_keys: &[[u8; 32]],
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
    shutdown: &AtomicBool,
    mut on_q6pb: F,
    source_rate_limiter: &mut QRunV06PeerSourceRateLimiter,
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
        if stats
            .authenticated_sessions
            .saturating_add(stats.unverified_peer_sessions)
            >= config.max_sessions
        {
            break QRunV06PeerListenerStopReason::SessionLimitReached;
        }

        let (mut stream, peer_addr) = match listener.accept() {
            Ok(connection) => connection,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(config.accept_poll_interval);
                continue;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(QRunV06PeerListenerError::Io(error.to_string())),
        };
        stats.accepted_connections = stats.accepted_connections.saturating_add(1);
        if !source_rate_limiter.allow(peer_addr, config.max_failed_handshakes, Instant::now()) {
            stats.rate_limited_connections = stats.rate_limited_connections.saturating_add(1);
            drop(stream);
            continue;
        }
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
                | Err(QRunV06NoiseError::DuplicateTrustedKey)
                | Err(QRunV06NoiseError::HandshakeCancelled) => break,
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
    let mut source_rate_limiter = QRunV06PeerSourceRateLimiter::new(Instant::now());
    const MAX_Q6HS_SESSION_EGRESS_BYTES: usize = 64 * 1024 * 1024;
    let stop_reason = loop {
        if shutdown.load(Ordering::Acquire) {
            break QRunV06PeerListenerStopReason::ShutdownRequested;
        }
        if stats
            .authenticated_sessions
            .saturating_add(stats.unverified_peer_sessions)
            >= config.max_sessions
        {
            break QRunV06PeerListenerStopReason::SessionLimitReached;
        }
        let (mut stream, peer_addr) = match listener.accept() {
            Ok(connection) => connection,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(config.accept_poll_interval);
                continue;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(QRunV06PeerListenerError::Io(error.to_string())),
        };
        stats.accepted_connections = stats.accepted_connections.saturating_add(1);
        if !source_rate_limiter.allow(peer_addr, config.max_failed_handshakes, Instant::now()) {
            stats.rate_limited_connections = stats.rate_limited_connections.saturating_add(1);
            drop(stream);
            continue;
        }
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

/// Combined Q6PB/Q6TI/Q6MO and Q6HS listener for the permissionless production supervisor.
/// Fixed-width admission replies remain exactly one Q6PA/Q6TA/Q6MA record; Q6HS replies are a
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
    on_application_frame: F,
) -> Result<QRunV06PeerListenerReport, QRunV06PeerListenerError>
where
    F: FnMut(&mut QRunV06PeerReplayGuard, &[u8]) -> Result<Vec<Vec<u8>>, String>,
{
    serve_qfp6_noise_listener_with_history_and_q6ar(
        listener,
        config,
        local_static_private_key,
        trusted_remote_static_public_keys,
        network_id,
        profile_id,
        shutdown,
        |_| Ok(()),
        on_application_frame,
    )
}

/// Q6AR-aware candidate listener. Advertisements are delivered with their session provenance;
/// the application must persist only pinned relays and must not treat advertised keys as pins.
pub fn serve_qfp6_noise_listener_with_history_and_q6ar<F, G>(
    listener: &TcpListener,
    config: QRunV06PeerListenerConfig,
    local_static_private_key: &[u8; 32],
    trusted_remote_static_public_keys: &[[u8; 32]],
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
    shutdown: &AtomicBool,
    on_q6ar: G,
    on_application_frame: F,
) -> Result<QRunV06PeerListenerReport, QRunV06PeerListenerError>
where
    F: FnMut(&mut QRunV06PeerReplayGuard, &[u8]) -> Result<Vec<Vec<u8>>, String>,
    G: FnMut(
        crate::qrun_v06_peer_address_relay_candidate::Q6arReceivedAdvertisement,
    ) -> Result<(), String>,
{
    serve_qfp6_noise_listener_with_history_and_q6ar_relay_pins(
        listener,
        config,
        local_static_private_key,
        trusted_remote_static_public_keys,
        &[],
        network_id,
        profile_id,
        shutdown,
        on_q6ar,
        on_application_frame,
    )
}

/// Q6AR-aware candidate listener with a separate optional relay-key allow-list. Inbound
/// permissionless sessions are still accepted anonymously; only sessions whose Noise static key
/// matches this allow-list are marked as pinned for Q6AR provenance.
pub fn serve_qfp6_noise_listener_with_history_and_q6ar_relay_pins<F, G>(
    listener: &TcpListener,
    config: QRunV06PeerListenerConfig,
    local_static_private_key: &[u8; 32],
    trusted_remote_static_public_keys: &[[u8; 32]],
    q6ar_relay_static_public_key_pins: &[[u8; 32]],
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
    shutdown: &AtomicBool,
    on_q6ar: G,
    mut on_application_frame: F,
) -> Result<QRunV06PeerListenerReport, QRunV06PeerListenerError>
where
    F: FnMut(&mut QRunV06PeerReplayGuard, &[u8]) -> Result<Vec<Vec<u8>>, String>,
    G: FnMut(
        crate::qrun_v06_peer_address_relay_candidate::Q6arReceivedAdvertisement,
    ) -> Result<(), String>,
{
    let mut source_rate_limiter = QRunV06PeerSourceRateLimiter::new(Instant::now());
    serve_qfp6_noise_listener_with_history_and_q6ar_relay_pins_with_rate_limiter(
        listener,
        config,
        local_static_private_key,
        trusted_remote_static_public_keys,
        q6ar_relay_static_public_key_pins,
        network_id,
        profile_id,
        shutdown,
        on_q6ar,
        move |_peer_addr, guard, frame| on_application_frame(guard, frame),
        &mut source_rate_limiter,
    )
}

pub(crate) fn serve_qfp6_noise_listener_with_history_and_q6ar_relay_pins_with_rate_limiter<F, G>(
    listener: &TcpListener,
    config: QRunV06PeerListenerConfig,
    local_static_private_key: &[u8; 32],
    trusted_remote_static_public_keys: &[[u8; 32]],
    q6ar_relay_static_public_key_pins: &[[u8; 32]],
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
    shutdown: &AtomicBool,
    mut on_q6ar: G,
    mut on_application_frame: F,
    source_rate_limiter: &mut QRunV06PeerSourceRateLimiter,
) -> Result<QRunV06PeerListenerReport, QRunV06PeerListenerError>
where
    F: FnMut(SocketAddr, &mut QRunV06PeerReplayGuard, &[u8]) -> Result<Vec<Vec<u8>>, String>,
    G: FnMut(
        crate::qrun_v06_peer_address_relay_candidate::Q6arReceivedAdvertisement,
    ) -> Result<(), String>,
{
    use crate::qrun_v06_history_sync_wire_candidate::{
        decode_q6hi_request, decode_q6hr_status, decode_q6hs_request,
        validate_q6hc_response_sequence, Q6HI_REQUEST_MAGIC, Q6HS_REQUEST_MAGIC,
    };
    use crate::qrun_v06_market_ingress_candidate::{
        decode_q6ma_response, decode_q6mo_market_operation_request, Q6MO_MAGIC,
    };
    use crate::qrun_v06_noise_transport_candidate::MAX_QFP6_NOISE_RECORD_BYTES;
    use crate::qrun_v06_peer_address_relay_candidate::{
        decode_q6ar_from_session, decode_q6ar_pull_request, decode_q6ar_pull_response, Q6AR_MAGIC,
        Q6AR_MAX_FRAME_BYTES, Q6AR_PULL_MAX_RESPONSE_BYTES, Q6AR_PULL_REQUEST_BYTES,
        Q6AR_PULL_REQUEST_MAGIC,
    };
    use crate::qrun_v06_peer_discovery_candidate::{
        decode_q6pd_announce_request, decode_q6pd_announce_response, decode_q6pd_pull_request,
        decode_q6pd_pull_response, verify_q6pd_peer_record, Q6PD_ANNOUNCE_HEADER_BYTES,
        Q6PD_ANNOUNCE_REQUEST_MAGIC, Q6PD_ANNOUNCE_RESPONSE_BYTES, Q6PD_MAX_PULL_FRAME_BYTES,
        Q6PD_MAX_RECORD_BYTES, Q6PD_PULL_REQUEST_BYTES, Q6PD_PULL_REQUEST_MAGIC,
    };
    use crate::qrun_v06_transaction_ingress_candidate::{
        decode_q6ti_transaction_request, Q6TI_MAGIC,
    };

    config.validate()?;
    if !trusted_remote_static_public_keys.is_empty() {
        validate_peer_pins(trusted_remote_static_public_keys)?;
    }
    if !q6ar_relay_static_public_key_pins.is_empty() {
        validate_peer_pins(q6ar_relay_static_public_key_pins)?;
    }
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
    if trusted_remote_static_public_keys.is_empty() {
        if bind_ip.is_multicast() {
            return Err(QRunV06PeerListenerError::UnsafeBindAddress(bind_ip));
        }
    } else if !is_safe_private_or_overlay_ip(bind_ip)
        && !is_publicly_routable_pinned_bind_ip(bind_ip)
    {
        return Err(QRunV06PeerListenerError::UnsafeBindAddress(bind_ip));
    }
    listener
        .set_nonblocking(true)
        .map_err(|error| QRunV06PeerListenerError::Io(error.to_string()))?;

    let mut stats = QRunV06PeerListenerStats::default();
    const MAX_HISTORY_SESSION_EGRESS_BYTES: usize = 256 * 1024 * 1024;
    let (handshake_workers, completed_handshakes) = QRunV06HandshakeWorkerPool::new(
        local_static_private_key,
        trusted_remote_static_public_keys,
        q6ar_relay_static_public_key_pins,
        network_id,
        profile_id,
    );
    let stop_reason = 'listener: loop {
        if shutdown.load(Ordering::Acquire) {
            break QRunV06PeerListenerStopReason::ShutdownRequested;
        }
        if stats
            .authenticated_sessions
            .saturating_add(stats.unverified_peer_sessions)
            >= config.max_sessions
        {
            break QRunV06PeerListenerStopReason::SessionLimitReached;
        }

        // Prefer completed handshakes. All application records and canonical callbacks remain
        // on this thread; workers only perform the bounded Noise XX authentication stage.
        let (mut stream, peer_addr, mut noise) = loop {
            if shutdown.load(Ordering::Acquire) {
                break 'listener QRunV06PeerListenerStopReason::ShutdownRequested;
            }
            if stats
                .authenticated_sessions
                .saturating_add(stats.unverified_peer_sessions)
                >= config.max_sessions
            {
                break 'listener QRunV06PeerListenerStopReason::SessionLimitReached;
            }

            match completed_handshakes.try_recv() {
                Ok(completion) => {
                    let stream = completion.stream;
                    let peer_addr = completion.peer_addr;
                    let noise = match completion.result {
                        Ok(session) => session,
                        Err(QRunV06NoiseError::HandshakeCancelled) => {
                            stats.cancelled_handshakes =
                                stats.cancelled_handshakes.saturating_add(1);
                            continue;
                        }
                        Err(error) => {
                            eprintln!("QFP6_DIAG noise_handshake_rejected source={peer_addr} error={error:?}");
                            stats.rejected_handshakes = stats.rejected_handshakes.saturating_add(1);
                            drop(stream);
                            continue;
                        }
                    };
                    break (stream, peer_addr, noise);
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => {
                    return Err(QRunV06PeerListenerError::Io(
                        "all QFP6 Noise handshake workers terminated".into(),
                    ));
                }
            }

            let (stream, peer_addr) = match listener.accept() {
                Ok(connection) => connection,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(config.accept_poll_interval);
                    continue;
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    return Err(QRunV06PeerListenerError::Io(error.to_string()));
                }
            };
            stats.accepted_connections = stats.accepted_connections.saturating_add(1);
            if !source_rate_limiter.allow(peer_addr, config.max_failed_handshakes, Instant::now()) {
                stats.rate_limited_connections = stats.rate_limited_connections.saturating_add(1);
                drop(stream);
                continue;
            }
            if stream.set_nodelay(true).is_err() {
                stats.handler_failures = stats.handler_failures.saturating_add(1);
                drop(stream);
                continue;
            }
            let job = QRunV06HandshakeJob { stream, peer_addr };
            match handshake_workers.try_submit(job) {
                Ok(()) => {}
                Err(TrySendError::Full(job)) => {
                    stats.handshake_queue_rejections =
                        stats.handshake_queue_rejections.saturating_add(1);
                    drop(job.stream);
                }
                Err(TrySendError::Disconnected(job)) => {
                    drop(job.stream);
                    return Err(QRunV06PeerListenerError::Io(
                        "QFP6 Noise handshake worker queue disconnected".into(),
                    ));
                }
            }
        };
        eprintln!(
            "QFP6_DIAG noise_session_established source={} remote_static_pinned={}",
            peer_addr,
            noise.remote_static_key_pinned()
        );
        if noise.remote_static_key_pinned() {
            stats.authenticated_sessions += 1;
        } else {
            stats.unverified_peer_sessions += 1;
        }
        let mut replay_guard = QRunV06PeerReplayGuard::new();
        let mut session_history_egress = 0usize;
        let mut q6ar_seen = false;
        let mut q6ar_pull_seen = false;
        // A persistent liveness slot is available only after an Ed25519 Q6PD record
        // proves that its declared Noise key equals the live session's remote static key.
        let mut q6pd_announcement_matches_noise = false;
        let mut q6pd_gossip_push_seen = false;
        let mut q6pd_session_handed_off = false;
        let session_deadline = Instant::now() + QRUN_V06_MAX_APPLICATION_SESSION_DURATION;
        for _ in 0..config.max_requests_per_session {
            if shutdown.load(Ordering::Acquire) {
                break;
            }
            let read_budget =
                match application_session_record_read_budget(session_deadline, Instant::now()) {
                    Some(budget) => budget,
                    None => break,
                };
            let frame = match noise.read_record_with_budget(&mut stream, read_budget) {
                Ok(frame) => frame,
                Err(error) => {
                    eprintln!(
                        "QFP6_DIAG noise_record_read_failed source={peer_addr} error={error:?}"
                    );
                    break;
                }
            };
            eprintln!(
                "QFP6_DIAG application_frame source={} magic={:02x?} bytes={}",
                peer_addr,
                frame.get(..4).unwrap_or_default(),
                frame.len()
            );
            if frame.get(..4) == Some(&Q6AR_MAGIC) {
                if q6ar_seen || frame.len() > Q6AR_MAX_FRAME_BYTES {
                    stats.q6ar_rejections += 1;
                    break;
                }
                q6ar_seen = true;
                let now_secs =
                    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                        Ok(duration) => duration.as_secs(),
                        Err(_) => {
                            stats.handler_failures += 1;
                            break;
                        }
                    };
                match decode_q6ar_from_session(&frame, &noise, now_secs) {
                    Ok(advertisement) => {
                        stats.requests_received += 1;
                        if on_q6ar(advertisement).is_err() {
                            stats.q6ar_rejections += 1;
                            break;
                        }
                        continue;
                    }
                    Err(_) => {
                        stats.q6ar_rejections += 1;
                        break;
                    }
                }
            }
            if frame.get(..4) == Some(&Q6AR_PULL_REQUEST_MAGIC) {
                if q6ar_pull_seen
                    || frame.len() != Q6AR_PULL_REQUEST_BYTES
                    || frame.len() > MAX_QFP6_NOISE_RECORD_BYTES
                {
                    stats.q6ar_rejections += 1;
                    break;
                }
                q6ar_pull_seen = true;
                let request = match decode_q6ar_pull_request(&frame, network_id, profile_id) {
                    Ok(request) => request,
                    Err(_) => {
                        stats.q6ar_rejections += 1;
                        break;
                    }
                };
                if replay_guard.accept(request.request_id).is_err() {
                    stats.q6ar_rejections += 1;
                    break;
                }
                stats.requests_received += 1;
                let responses = match on_application_frame(peer_addr, &mut replay_guard, &frame) {
                    Ok(responses) => responses,
                    Err(_) => {
                        stats.q6ar_rejections += 1;
                        break;
                    }
                };
                let now_secs =
                    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                        Ok(duration) => duration.as_secs(),
                        Err(_) => {
                            stats.handler_failures += 1;
                            break;
                        }
                    };
                if responses.len() != 1
                    || responses[0].len() > Q6AR_PULL_MAX_RESPONSE_BYTES
                    || decode_q6ar_pull_response(&responses[0], &request, now_secs).is_err()
                {
                    stats.malformed_responses += 1;
                    break;
                }
                if noise.write_record(&mut stream, &responses[0]).is_err() {
                    stats.handler_failures += 1;
                    break;
                }
                stats.responses_written += 1;
                continue;
            }
            // Persistent Q6PD liveness is handed to a separately bounded worker after
            // the Noise session and network/profile-bound open control are accepted. This
            // releases the serial listener immediately so other peers can be served.
            if frame.get(..4) == Some(&Q6PD_SESSION_OPEN_MAGIC) {
                if !q6pd_announcement_matches_noise {
                    let Some(open) = decode_q6pd_session_open(&frame, network_id, profile_id).ok()
                    else {
                        stats.handler_failures = stats.handler_failures.saturating_add(1);
                        break;
                    };
                    let rejected = encode_q6pd_session_open_ack(&open, false);
                    if noise.write_record(&mut stream, &rejected).is_err() {
                        stats.handler_failures = stats.handler_failures.saturating_add(1);
                    } else {
                        stats.responses_written = stats.responses_written.saturating_add(1);
                    }
                    eprintln!(
                        "QFP6_Q6PD_SESSION_OPEN_REJECTED source={peer_addr} reason=missing_signed_noise_bound_announcement"
                    );
                    break;
                }
                let open = match decode_q6pd_session_open(&frame, network_id, profile_id) {
                    Ok(open) => open,
                    Err(error) => {
                        eprintln!(
                            "QFP6_Q6PD_SESSION_OPEN_REJECTED source={peer_addr} error={error:?}"
                        );
                        stats.handler_failures = stats.handler_failures.saturating_add(1);
                        break;
                    }
                };
                if replay_guard.accept(open.request_id).is_err() {
                    stats.handler_failures = stats.handler_failures.saturating_add(1);
                    break;
                }
                stats.requests_received = stats.requests_received.saturating_add(1);

                let Some(slot) = try_reserve_q6pd_persistent_session() else {
                    let rejected = encode_q6pd_session_open_ack(&open, false);
                    if noise.write_record(&mut stream, &rejected).is_err() {
                        stats.handler_failures = stats.handler_failures.saturating_add(1);
                    } else {
                        stats.responses_written = stats.responses_written.saturating_add(1);
                    }
                    eprintln!(
                        "QFP6_Q6PD_SESSION_OPEN_REJECTED source={peer_addr} reason=session_capacity"
                    );
                    break;
                };

                let callback_response = match on_application_frame(
                    peer_addr,
                    &mut replay_guard,
                    &frame,
                ) {
                    Ok(responses) => responses,
                    Err(error) => {
                        eprintln!(
                            "QFP6_Q6PD_SESSION_OPEN_REJECTED source={peer_addr} reason=feature_disabled_or_handler error={error}"
                        );
                        let rejected = encode_q6pd_session_open_ack(&open, false);
                        if noise.write_record(&mut stream, &rejected).is_err() {
                            stats.handler_failures = stats.handler_failures.saturating_add(1);
                        } else {
                            stats.responses_written = stats.responses_written.saturating_add(1);
                        }
                        break;
                    }
                };
                let accepted = callback_response.len() == 1
                    && decode_q6pd_session_open_ack(&callback_response[0], &open) == Ok(true);
                if !accepted {
                    let rejected = encode_q6pd_session_open_ack(&open, false);
                    if noise.write_record(&mut stream, &rejected).is_err() {
                        stats.handler_failures = stats.handler_failures.saturating_add(1);
                    } else {
                        stats.responses_written = stats.responses_written.saturating_add(1);
                    }
                    break;
                }

                let accepted_ack = encode_q6pd_session_open_ack(&open, true);
                if let Err(error) = noise.write_record(&mut stream, &accepted_ack) {
                    eprintln!(
                        "QFP6_Q6PD_SESSION_OPEN_WRITE_FAILED source={peer_addr} error={error:?}"
                    );
                    stats.handler_failures = stats.handler_failures.saturating_add(1);
                    break;
                }
                stats.responses_written = stats.responses_written.saturating_add(1);
                let worker_stream = stream;
                let worker_noise = noise;
                match thread::Builder::new()
                    .name("q6pd-persistent-session".into())
                    .spawn(move || {
                        serve_q6pd_persistent_session(
                            worker_stream,
                            worker_noise,
                            open,
                            peer_addr,
                            slot,
                        );
                    }) {
                    Ok(_) => {
                        q6pd_session_handed_off = true;
                        eprintln!(
                            "QFP6_Q6PD_SESSION_HANDED_OFF source={peer_addr} request_id={} active={}",
                            open.request_id,
                            crate::qrun_v06_q6pd_session_candidate::active_q6pd_persistent_session_count()
                        );
                    }
                    Err(error) => {
                        eprintln!(
                            "QFP6_Q6PD_SESSION_WORKER_FAILED source={peer_addr} error={error}"
                        );
                        stats.handler_failures = stats.handler_failures.saturating_add(1);
                    }
                }
                break;
            }

            // Q6PD is a first-class Noise application protocol. Route the two signed-record
            // frames to the supervisor callback before the legacy Peer Block decoder; otherwise
            // valid Q6PG/Q6PA messages are rejected as malformed peer-block requests.
            if frame.get(..4) == Some(&Q6PD_ANNOUNCE_REQUEST_MAGIC) {
                if frame.len() > Q6PD_ANNOUNCE_HEADER_BYTES + Q6PD_MAX_RECORD_BYTES {
                    stats.handler_failures += 1;
                    break;
                }
                let record_wire = match decode_q6pd_announce_request(&frame) {
                    Ok(wire) => wire,
                    Err(error) => {
                        eprintln!(
                            "QFP6_Q6PD_ANNOUNCEMENT_REJECTED source={peer_addr} reason=frame_decode error={error:?}"
                        );
                        stats.handler_failures += 1;
                        break;
                    }
                };
                let now_secs =
                    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                        Ok(duration) => duration.as_secs(),
                        Err(_) => {
                            stats.handler_failures += 1;
                            break;
                        }
                    };
                let verified_record = match verify_q6pd_peer_record(
                    record_wire,
                    network_id,
                    profile_id,
                    now_secs,
                ) {
                    Ok(record) => record,
                    Err(error) => {
                        eprintln!(
                            "QFP6_Q6PD_ANNOUNCEMENT_REJECTED source={peer_addr} reason=signature_or_domain error={error:?}"
                        );
                        stats.handler_failures += 1;
                        break;
                    }
                };
                if verified_record.noise_static_public_key != *noise.remote_static_public_key() {
                    eprintln!(
                        "QFP6_Q6PD_ANNOUNCEMENT_REJECTED source={peer_addr} reason=noise_key_mismatch"
                    );
                    stats.handler_failures += 1;
                    break;
                }
                let responses = match on_application_frame(peer_addr, &mut replay_guard, &frame) {
                    Ok(responses) => responses,
                    Err(_) => {
                        stats.handler_failures += 1;
                        break;
                    }
                };
                if responses.len() != 1
                    || responses[0].len() != Q6PD_ANNOUNCE_RESPONSE_BYTES
                    || decode_q6pd_announce_response(&responses[0]).is_err()
                {
                    stats.malformed_responses += 1;
                    break;
                }
                stats.requests_received += 1;
                if noise.write_record(&mut stream, &responses[0]).is_err() {
                    stats.handler_failures += 1;
                    break;
                }
                stats.responses_written += 1;
                q6pd_announcement_matches_noise = true;
                continue;
            }
            if frame.get(..4) == Some(&Q6PD_PULL_REQUEST_MAGIC) {
                if frame.len() != Q6PD_PULL_REQUEST_BYTES
                    || frame.len() > MAX_QFP6_NOISE_RECORD_BYTES
                {
                    eprintln!("QFP6_DIAG q6pd_pull_rejected source={peer_addr} reason=invalid_frame_length bytes={}", frame.len());
                    stats.handler_failures += 1;
                    break;
                }
                let request = match decode_q6pd_pull_request(&frame, network_id, profile_id) {
                    Ok(request) => request,
                    Err(error) => {
                        eprintln!("QFP6_DIAG q6pd_pull_rejected source={peer_addr} reason=request_decode error={error:?}");
                        stats.handler_failures += 1;
                        break;
                    }
                };
                if let Err(error) = replay_guard.accept(request.request_id) {
                    eprintln!("QFP6_DIAG q6pd_pull_rejected source={peer_addr} reason=replay request_id={} error={error:?}", request.request_id);
                    stats.handler_failures += 1;
                    break;
                }
                let responses = match on_application_frame(peer_addr, &mut replay_guard, &frame) {
                    Ok(responses) => responses,
                    Err(error) => {
                        eprintln!("QFP6_DIAG q6pd_pull_handler_failed source={peer_addr} request_id={} error={error}", request.request_id);
                        stats.handler_failures += 1;
                        break;
                    }
                };
                let now_secs = match std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                {
                    Ok(duration) => duration.as_secs(),
                    Err(error) => {
                        eprintln!("QFP6_DIAG q6pd_pull_rejected source={peer_addr} reason=system_clock error={error}");
                        stats.handler_failures += 1;
                        break;
                    }
                };
                if responses.len() != 1 {
                    eprintln!("QFP6_DIAG q6pd_pull_response_rejected source={peer_addr} request_id={} reason=response_count count={}", request.request_id, responses.len());
                    stats.malformed_responses += 1;
                    break;
                }
                if responses[0].len() > Q6PD_MAX_PULL_FRAME_BYTES {
                    eprintln!("QFP6_DIAG q6pd_pull_response_rejected source={peer_addr} request_id={} reason=oversized bytes={}", request.request_id, responses[0].len());
                    stats.malformed_responses += 1;
                    break;
                }
                if let Err(error) = decode_q6pd_pull_response(&responses[0], &request, now_secs) {
                    eprintln!("QFP6_DIAG q6pd_pull_response_rejected source={peer_addr} request_id={} reason=response_decode error={error:?}", request.request_id);
                    stats.malformed_responses += 1;
                    break;
                }
                stats.requests_received += 1;
                if let Err(error) = noise.write_record(&mut stream, &responses[0]) {
                    eprintln!("QFP6_DIAG q6pd_pull_response_write_failed source={peer_addr} request_id={} error={error:?}", request.request_id);
                    stats.handler_failures += 1;
                    break;
                }
                eprintln!(
                    "QFP6_DIAG q6pd_pull_response_sent source={peer_addr} request_id={} records={}",
                    request.request_id,
                    responses[0].len()
                );
                stats.responses_written += 1;
                continue;
            }
            // Third-party Q6PD records are untrusted address hints. Each Ed25519
            // signature/domain/TTL is checked before ingestion; one bounded batch per
            // Noise session prevents anonymous peers from flooding the candidate store.
            if frame.get(..4)
                == Some(&crate::qrun_v06_peer_discovery_candidate::Q6PD_GOSSIP_PUSH_REQUEST_MAGIC)
            {
                if q6pd_gossip_push_seen
                    || frame.len()
                        > crate::qrun_v06_peer_discovery_candidate::Q6PD_MAX_GOSSIP_PUSH_FRAME_BYTES
                {
                    stats.handler_failures += 1;
                    break;
                }
                let now_secs =
                    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                        Ok(duration) => duration.as_secs(),
                        Err(_) => {
                            stats.handler_failures += 1;
                            break;
                        }
                    };
                let request =
                    match crate::qrun_v06_peer_discovery_candidate::decode_q6pd_gossip_push_request(
                        &frame, network_id, profile_id, now_secs,
                    ) {
                        Ok(request) => request,
                        Err(error) => {
                            eprintln!(
                                "QFP6_Q6PD_GOSSIP_PUSH_REJECTED source={peer_addr} error={error:?}"
                            );
                            stats.handler_failures += 1;
                            break;
                        }
                    };
                if replay_guard.accept(request.request_id).is_err() {
                    eprintln!(
                        "QFP6_Q6PD_GOSSIP_PUSH_REJECTED source={peer_addr} reason=replay request_id={}",
                        request.request_id
                    );
                    stats.handler_failures += 1;
                    break;
                }
                q6pd_gossip_push_seen = true;
                let responses = match on_application_frame(peer_addr, &mut replay_guard, &frame) {
                    Ok(responses) => responses,
                    Err(error) => {
                        eprintln!(
                            "QFP6_Q6PD_GOSSIP_PUSH_HANDLER_FAILED source={peer_addr} error={error}"
                        );
                        stats.handler_failures += 1;
                        break;
                    }
                };
                if responses.len() != 1
                    || crate::qrun_v06_peer_discovery_candidate::decode_q6pd_gossip_push_response(
                        &responses[0],
                        &request,
                    )
                    .is_err()
                {
                    stats.malformed_responses += 1;
                    break;
                }
                if noise.write_record(&mut stream, &responses[0]).is_err() {
                    stats.handler_failures += 1;
                    break;
                }
                stats.requests_received += 1;
                stats.responses_written += 1;
                eprintln!(
                    "QFP6_Q6PD_GOSSIP_PUSH_ACCEPTED source={peer_addr} records={}",
                    request.records.len()
                );
                continue;
            }
            let (request_id, is_history, is_info, is_market) =
                if frame.get(..4) == Some(&Q6HI_REQUEST_MAGIC) {
                    match decode_q6hi_request(&frame) {
                        Ok(request)
                            if request.network_id == *network_id
                                && request.profile_id == *profile_id =>
                        {
                            (request.request_id, false, true, false)
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
                            (request.request_id, true, false, false)
                        }
                        _ => {
                            stats.handler_failures += 1;
                            break;
                        }
                    }
                } else if frame.get(..4) == Some(&Q6MO_MAGIC) {
                    match decode_q6mo_market_operation_request(&frame) {
                        Ok(request) => (request.request_id, false, false, true),
                        Err(_) => {
                            stats.handler_failures += 1;
                            break;
                        }
                    }
                } else if frame.get(..4) == Some(&Q6TI_MAGIC) {
                    match decode_q6ti_transaction_request(&frame) {
                        Ok(request) => (request.request_id, false, false, false),
                        Err(_) => {
                            stats.handler_failures += 1;
                            break;
                        }
                    }
                } else {
                    match decode_qrun_v06_peer_block_request(&frame) {
                        Ok(request) => (request.request_id, false, false, false),
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
            let responses = match on_application_frame(peer_addr, &mut replay_guard, &frame) {
                Ok(responses) => responses,
                Err(error) => {
                    eprintln!(
                        "QFP6_DIAG application_handler_failed source={peer_addr} error={error}"
                    );
                    stats.handler_failures += 1;
                    break;
                }
            };
            if is_history {
                if let Err(error) = validate_q6hc_response_sequence(
                    &responses,
                    request_id,
                    &decode_q6hs_request(&frame)
                        .map_err(|_| QRunV06PeerListenerError::InvalidConfiguration)?
                        .snapshot_tip,
                ) {
                    eprintln!(
                        "QFP6_DIAG history_response_invalid source={peer_addr} error={error:?}"
                    );
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
            } else if is_market {
                if responses.len() != 1 || decode_q6ma_response(&responses[0], request_id).is_err()
                {
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
            if is_history {
                let response_bytes = responses.iter().map(Vec::len).sum::<usize>();
                eprintln!(
                    "QFP6_DIAG history_response_ready source={} request_id={} chunks={} bytes={}",
                    peer_addr,
                    request_id,
                    responses.len(),
                    response_bytes
                );
            }
            let mut write_failed = false;
            for (response_index, response) in responses.iter().enumerate() {
                if response.len() > MAX_QFP6_NOISE_RECORD_BYTES {
                    eprintln!(
                        "QFP6_DIAG history_response_record_oversized source={} request_id={} chunk_index={} bytes={}",
                        peer_addr,
                        request_id,
                        response_index,
                        response.len()
                    );
                    write_failed = true;
                    break;
                }
                if is_history {
                    let next = session_history_egress.checked_add(response.len());
                    if next.is_none_or(|bytes| bytes > MAX_HISTORY_SESSION_EGRESS_BYTES) {
                        eprintln!(
                            "QFP6_DIAG history_response_egress_budget_exceeded source={} request_id={} chunk_index={} bytes={}",
                            peer_addr,
                            request_id,
                            response_index,
                            response.len()
                        );
                        write_failed = true;
                        break;
                    }
                    session_history_egress = next.expect("history egress checked before write");
                }
                if let Err(error) = noise.write_record(&mut stream, response) {
                    eprintln!(
                        "QFP6_DIAG noise_record_write_failed source={peer_addr} error={error:?}"
                    );
                    if is_history {
                        eprintln!(
                            "QFP6_DIAG history_chunk_write_failed source={} request_id={} chunk_index={} bytes={} error={error:?}",
                            peer_addr,
                            request_id,
                            response_index,
                            response.len()
                        );
                    }
                    write_failed = true;
                    break;
                }
                stats.responses_written += 1;
                if is_history {
                    eprintln!(
                        "QFP6_DIAG history_chunk_written source={} request_id={} chunk_index={} chunks={} bytes={}",
                        peer_addr,
                        request_id,
                        response_index,
                        responses.len(),
                        response.len()
                    );
                }
            }
            if is_history && !write_failed {
                eprintln!(
                    "QFP6_DIAG history_response_sent source={} request_id={} chunks={}",
                    peer_addr,
                    request_id,
                    responses.len()
                );
            }
            if write_failed {
                stats.handler_failures += 1;
                break;
            }
        }
        if !q6pd_session_handed_off {
            stats.sessions_closed += 1;
        }
    };
    Ok(QRunV06PeerListenerReport { stats, stop_reason })
}

/// Public-network ingress variant. Noise XX is anonymous here: it provides transport
/// confidentiality and network/profile domain separation only. Consensus validation remains
/// authoritative; the remote static key is not treated as an authenticated identity.
pub fn serve_qfp6_noise_listener_with_history_open<F>(
    listener: &TcpListener,
    config: QRunV06PeerListenerConfig,
    local_static_private_key: &[u8; 32],
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
    shutdown: &AtomicBool,
    on_application_frame: F,
) -> Result<QRunV06PeerListenerReport, QRunV06PeerListenerError>
where
    F: FnMut(&mut QRunV06PeerReplayGuard, &[u8]) -> Result<Vec<Vec<u8>>, String>,
{
    serve_qfp6_noise_listener_with_history(
        listener,
        config,
        local_static_private_key,
        &[],
        network_id,
        profile_id,
        shutdown,
        on_application_frame,
    )
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
        sync::{atomic::AtomicBool, Arc},
        thread,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };

    const NETWORK: [u8; 32] = [0x91; 32];
    const PROFILE: [u8; 32] = [0x92; 32];

    #[test]
    fn public_pinned_bind_policy_requires_global_unicast_or_wildcard() {
        for address in [
            "0.0.0.0",
            "8.8.8.8",
            "2606:4700:4700::1111",
            "::",
            "::ffff:8.8.8.8",
        ] {
            assert!(
                is_publicly_routable_pinned_bind_ip(address.parse().unwrap()),
                "{address}"
            );
        }
        for address in [
            "127.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "169.254.1.1",
            "224.0.0.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            "2001:2::1",
            "2001:10::1",
            "2001:20::1",
            "2002::1",
            "3fff::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(
                !is_publicly_routable_pinned_bind_ip(address.parse().unwrap()),
                "{address}"
            );
        }
    }

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
    fn q6pd_persistent_session_is_handed_off_and_survives_listener_round() {
        use crate::qrun_v06_peer_discovery_candidate::{
            decode_q6pd_announce_request, decode_q6pd_announce_response,
            encode_q6pd_announce_request, encode_q6pd_announce_response, sign_q6pd_peer_record,
            Q6PD_ANNOUNCE_REQUEST_MAGIC,
        };
        use crate::qrun_v06_q6pd_session_candidate::{
            active_q6pd_persistent_session_count, decode_q6pd_session_open,
            decode_q6pd_session_pong, encode_q6pd_session_open_ack, encode_q6pd_session_ping,
            Q6pdSessionControl,
        };
        use ed25519_dalek::SigningKey;

        let (server_private, server_public) = keypair();
        let (client_private, client_public) = keypair();
        let identity_signing_key = SigningKey::from_bytes(&[0x55; 32]);
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let signed_record = sign_q6pd_peer_record(
            NETWORK,
            PROFILE,
            client_public,
            "8.8.8.8:30336".parse().unwrap(),
            1,
            now_secs,
            600,
            &identity_signing_key,
        )
        .unwrap();
        let announce_frame = encode_q6pd_announce_request(&signed_record).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = AtomicBool::new(false);
        let mut config = QRunV06PeerListenerConfig::default();
        config.max_sessions = 1;
        config.max_requests_per_session = 2;

        let server = thread::spawn(move || {
            serve_qfp6_noise_listener_with_history_and_q6ar_relay_pins(
                &listener,
                config,
                &server_private,
                &[],
                &[],
                &NETWORK,
                &PROFILE,
                &shutdown,
                |_received| Ok(()),
                |_guard, frame| {
                    if frame.get(..4) == Some(&Q6PD_ANNOUNCE_REQUEST_MAGIC) {
                        decode_q6pd_announce_request(frame).map_err(|error| error.to_string())?;
                        Ok(vec![encode_q6pd_announce_response(true).to_vec()])
                    } else {
                        let open = decode_q6pd_session_open(frame, &NETWORK, &PROFILE)
                            .map_err(|error| error.to_string())?;
                        Ok(vec![encode_q6pd_session_open_ack(&open, true)])
                    }
                },
            )
            .unwrap()
        });

        let mut stream = connect_until(address);
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut noise = QRunV06NoiseSession::connect(
            &mut stream,
            &client_private,
            &server_public,
            &NETWORK,
            &PROFILE,
        )
        .unwrap();
        noise.write_record(&mut stream, &announce_frame).unwrap();
        let announce_ack = noise.read_record(&mut stream).unwrap();
        decode_q6pd_announce_response(&announce_ack).unwrap();

        let open = Q6pdSessionControl {
            request_id: 10,
            network_id: NETWORK,
            profile_id: PROFILE,
        };
        noise
            .write_record(
                &mut stream,
                &crate::qrun_v06_q6pd_session_candidate::encode_q6pd_session_open(&open),
            )
            .unwrap();
        let ack = noise.read_record(&mut stream).unwrap();
        assert_eq!(
            crate::qrun_v06_q6pd_session_candidate::decode_q6pd_session_open_ack(&ack, &open),
            Ok(true)
        );

        let report = server.join().unwrap();
        assert_eq!(
            report.stop_reason,
            QRunV06PeerListenerStopReason::SessionLimitReached
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        while active_q6pd_persistent_session_count() != 1 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(active_q6pd_persistent_session_count(), 1);

        for request_id in 11..=13 {
            let ping = Q6pdSessionControl {
                request_id,
                network_id: NETWORK,
                profile_id: PROFILE,
            };
            noise
                .write_record(&mut stream, &encode_q6pd_session_ping(&ping))
                .unwrap();
            let pong = noise.read_record(&mut stream).unwrap();
            assert_eq!(decode_q6pd_session_pong(&pong, &ping), Ok(()));
        }

        let close = Q6pdSessionControl {
            request_id: 14,
            network_id: NETWORK,
            profile_id: PROFILE,
        };
        noise
            .write_record(
                &mut stream,
                &crate::qrun_v06_q6pd_session_candidate::encode_q6pd_session_close(&close),
            )
            .unwrap();
        drop(noise);
        drop(stream);

        let deadline = Instant::now() + Duration::from_secs(2);
        while active_q6pd_persistent_session_count() != 0 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(active_q6pd_persistent_session_count(), 0);
    }

    #[test]
    fn application_session_has_absolute_lifetime_and_per_record_read_budget() {
        let now = Instant::now();
        let long_session_deadline = now + Duration::from_secs(60);
        assert_eq!(
            application_session_record_read_budget(long_session_deadline, now),
            Some(QRUN_V06_MAX_APPLICATION_RECORD_READ_BUDGET)
        );

        let short_remaining = Duration::from_secs(2);
        assert_eq!(
            application_session_record_read_budget(now + short_remaining, now,),
            Some(short_remaining)
        );
        assert_eq!(
            application_session_record_read_budget(now, now + Duration::from_nanos(1),),
            None
        );
    }

    #[test]
    fn bounded_handshake_workers_allow_valid_peers_while_one_peer_stalls() {
        let (server_private, server_public) = keypair();
        let (client_a_private, client_a_public) = keypair();
        let (client_b_private, client_b_public) = keypair();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();

        let (workers, completed) = QRunV06HandshakeWorkerPool::new(
            &server_private,
            &[client_a_public, client_b_public],
            &[],
            &NETWORK,
            &PROFILE,
        );

        // This connection deliberately never sends the first Noise message. It occupies
        // one worker, but must not block the two other bounded handshake workers.
        let slow_stream = TcpStream::connect(address).unwrap();
        let client_a = thread::spawn(move || {
            let mut stream = TcpStream::connect(address).unwrap();
            QRunV06NoiseSession::connect(
                &mut stream,
                &client_a_private,
                &server_public,
                &NETWORK,
                &PROFILE,
            )
            .unwrap();
        });
        let client_b = thread::spawn(move || {
            let mut stream = TcpStream::connect(address).unwrap();
            QRunV06NoiseSession::connect(
                &mut stream,
                &client_b_private,
                &server_public,
                &NETWORK,
                &PROFILE,
            )
            .unwrap();
        });

        let mut accepted = 0usize;
        let accept_deadline = Instant::now() + Duration::from_secs(2);
        while accepted < 3 && Instant::now() < accept_deadline {
            match listener.accept() {
                Ok((stream, peer_addr)) => {
                    stream.set_nodelay(true).unwrap();
                    workers
                        .try_submit(QRunV06HandshakeJob { stream, peer_addr })
                        .unwrap();
                    accepted += 1;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("loopback accept failed: {error}"),
            }
        }
        assert_eq!(accepted, 3, "all three test sockets must be queued");

        let deadline = Instant::now() + Duration::from_secs(2);
        let mut completed_keys = Vec::new();
        while completed_keys.len() < 2 && Instant::now() < deadline {
            match completed.recv_timeout(Duration::from_millis(50)) {
                Ok(completion) => match completion.result {
                    Ok(session) => {
                        assert!(session.remote_static_key_pinned());
                        completed_keys.push(*session.remote_static_public_key());
                        drop(session);
                        drop(completion.stream);
                    }
                    Err(error) => panic!("valid peer handshake unexpectedly failed: {error:?}"),
                },
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(error) => panic!("handshake completion channel closed: {error}"),
            }
        }
        completed_keys.sort_unstable();
        let mut expected_keys = vec![client_a_public, client_b_public];
        expected_keys.sort_unstable();
        assert_eq!(completed_keys, expected_keys);

        client_a.join().unwrap();
        client_b.join().unwrap();
        drop(slow_stream);
        // Dropping the pool cancels its stalled worker and joins every fixed worker.
        drop(workers);
    }

    #[test]
    fn bounded_handshake_worker_queue_rejects_connections_above_fixed_capacity() {
        let (server_private, _) = keypair();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (workers, _completed) =
            QRunV06HandshakeWorkerPool::new(&server_private, &[], &[], &NETWORK, &PROFILE);

        let mut clients = Vec::new();
        for _ in 0..QRUN_V06_HANDSHAKE_WORKERS {
            let client = TcpStream::connect(address).unwrap();
            let (stream, peer_addr) = listener.accept().unwrap();
            assert!(workers
                .try_submit(QRunV06HandshakeJob { stream, peer_addr })
                .is_ok());
            clients.push(client);
        }

        // Let each fixed worker take one job and block on the incomplete Noise message.
        thread::sleep(Duration::from_millis(150));

        for _ in 0..QRUN_V06_HANDSHAKE_QUEUE_CAPACITY {
            let client = TcpStream::connect(address).unwrap();
            let (stream, peer_addr) = listener.accept().unwrap();
            assert!(workers
                .try_submit(QRunV06HandshakeJob { stream, peer_addr })
                .is_ok());
            clients.push(client);
        }

        let overflow_client = TcpStream::connect(address).unwrap();
        let (overflow_stream, overflow_peer) = listener.accept().unwrap();
        assert!(matches!(
            workers.try_submit(QRunV06HandshakeJob {
                stream: overflow_stream,
                peer_addr: overflow_peer,
            }),
            Err(TrySendError::Full(_))
        ));
        drop(overflow_client);

        // Worker-pool shutdown cancels active handshakes and discards queued jobs.
        drop(workers);
        drop(clients);
    }

    #[test]
    fn source_rate_limiter_groups_ipv4_and_ipv6_prefixes_and_refills() {
        let now = Instant::now();
        let mut limiter = QRunV06PeerSourceRateLimiter::new(now);
        let socket = |ip| SocketAddr::new(ip, 8333);

        assert!(limiter.allow(socket(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))), 2, now,));
        assert!(limiter.allow(socket(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 250))), 2, now,));
        assert!(!limiter.allow(socket(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 99))), 2, now,));
        assert!(limiter.allow(socket(IpAddr::V4(Ipv4Addr::new(198, 51, 101, 7))), 2, now,));

        // An IPv4-mapped IPv6 socket shares the native IPv4 /24 bucket.
        let mapped = "::ffff:198.51.100.9".parse::<Ipv6Addr>().unwrap();
        assert!(limiter.allow(socket(IpAddr::V6(mapped)), 2, now + Duration::from_secs(2),));

        let first_v6 = "2001:db8:abcd:0001::1".parse::<Ipv6Addr>().unwrap();
        let second_v6 = "2001:db8:abcd:00ff::2".parse::<Ipv6Addr>().unwrap();
        let third_v6 = "2001:db8:abcd:0080::3".parse::<Ipv6Addr>().unwrap();
        let v6_time = now + Duration::from_secs(3);
        assert!(limiter.allow(socket(IpAddr::V6(first_v6)), 2, v6_time));
        assert!(limiter.allow(socket(IpAddr::V6(second_v6)), 2, v6_time));
        assert!(!limiter.allow(socket(IpAddr::V6(third_v6)), 2, v6_time));
    }

    #[test]
    fn source_rate_limiter_applies_global_budget_and_bounds_prefix_state() {
        let now = Instant::now();
        let mut limiter = QRunV06PeerSourceRateLimiter::new(now);
        for index in 0..QRUN_V06_GLOBAL_HANDSHAKE_BURST {
            let ip = Ipv4Addr::new(11, index as u8, 1, 1);
            assert!(limiter.allow(
                SocketAddr::new(IpAddr::V4(ip), 8333),
                QRUN_V06_LISTENER_MAX_FAILED_HANDSHAKES,
                now,
            ));
        }
        assert!(!limiter.allow(
            "12.0.0.1:8333".parse().unwrap(),
            QRUN_V06_LISTENER_MAX_FAILED_HANDSHAKES,
            now,
        ));
        assert!(limiter.allow(
            "12.0.0.1:8333".parse().unwrap(),
            QRUN_V06_LISTENER_MAX_FAILED_HANDSHAKES,
            now + QRUN_V06_GLOBAL_HANDSHAKE_REFILL,
        ));

        let mut bounded = QRunV06PeerSourceRateLimiter::new(now);
        for index in 0..(QRUN_V06_SOURCE_PREFIX_BUCKETS_MAX + 8) {
            bounded.global.tokens = QRUN_V06_GLOBAL_HANDSHAKE_BURST;
            let ip = Ipv4Addr::new(10, (index >> 8) as u8, index as u8, 1);
            assert!(bounded.allow(
                SocketAddr::new(IpAddr::V4(ip), 8333),
                QRUN_V06_LISTENER_MAX_FAILED_HANDSHAKES,
                now + Duration::from_millis(index as u64),
            ));
        }
        assert_eq!(bounded.prefixes.len(), QRUN_V06_SOURCE_PREFIX_BUCKETS_MAX);
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
        let shutdown = Arc::new(AtomicBool::new(false));
        let server_shutdown = Arc::clone(&shutdown);
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
                &server_shutdown,
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
        thread::sleep(Duration::from_millis(100));
        shutdown.store(true, Ordering::Release);

        let (report, handler_calls) = server.join().unwrap();
        assert_eq!(handler_calls, 0);
        assert_eq!(report.stats.accepted_connections, 1);
        assert_eq!(report.stats.authenticated_sessions, 0);
        assert_eq!(report.stats.rejected_handshakes, 1);
        assert_eq!(
            report.stop_reason,
            QRunV06PeerListenerStopReason::ShutdownRequested
        );
        let _ = pinned_client_private;
    }

    #[test]
    fn qfp6_listener_keeps_running_after_prefix_flood_and_throttles_source() {
        let (server_private, server_public) = keypair();
        let (_pinned_client_private, pinned_client_public) = keypair();
        let (attacker_one_private, _) = keypair();
        let (attacker_two_private, _) = keypair();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let server_shutdown = Arc::clone(&shutdown);
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
                    max_sessions: 8,
                    max_requests_per_session: 1,
                    max_failed_handshakes: 2,
                    accept_poll_interval: Duration::from_millis(10),
                },
                &server_private,
                &[pinned_client_public],
                &NETWORK,
                &PROFILE,
                &server_shutdown,
                &mut handler,
            )
            .unwrap();
            (report, handler_calls)
        });

        for attacker_private in [attacker_one_private, attacker_two_private] {
            let mut stream = connect_until(address);
            let _ = QRunV06NoiseSession::connect(
                &mut stream,
                &attacker_private,
                &server_public,
                &NETWORK,
                &PROFILE,
            );
            drop(stream);
        }

        // The third connection is accepted by TCP but dropped before Noise by the /24 bucket.
        let throttled = connect_until(address);
        drop(throttled);
        thread::sleep(Duration::from_millis(100));
        shutdown.store(true, Ordering::Release);

        let (report, handler_calls) = server.join().unwrap();
        assert_eq!(handler_calls, 0);
        assert_eq!(report.stats.accepted_connections, 3);
        assert_eq!(report.stats.authenticated_sessions, 0);
        assert_eq!(report.stats.rejected_handshakes, 2);
        assert_eq!(report.stats.rate_limited_connections, 1);
        assert_eq!(
            report.stop_reason,
            QRunV06PeerListenerStopReason::ShutdownRequested
        );
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
                        let status = encode_q6hr_status(
                            &request, 0, [0x77; 32], [0x56; 32], 0, [0x77; 32], [0x56; 32],
                        )
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
    fn qfp6_listener_dispatches_one_q6ar_from_pinned_noise_session() {
        use crate::qrun_v06_noise_transport_candidate::QRunV06NoiseSession;
        use crate::qrun_v06_peer_address_relay_candidate::{
            encode_q6ar, Q6arAddress, Q6arAdvertisement,
        };
        let (server_private, server_public) = keypair();
        let (client_private, client_public) = keypair();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let received = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let server_received = received.clone();
        let shutdown = std::sync::Arc::new(AtomicBool::new(false));
        let server_shutdown = shutdown.clone();
        let server = thread::spawn(move || {
            let mut config = QRunV06PeerListenerConfig::default();
            config.max_sessions = 1;
            config.max_requests_per_session = 2;
            serve_qfp6_noise_listener_with_history_and_q6ar_relay_pins(
                &listener,
                config,
                &server_private,
                &[],
                &[client_public],
                &NETWORK,
                &PROFILE,
                &server_shutdown,
                move |advertisement| {
                    server_received.lock().unwrap().push(advertisement);
                    Ok(())
                },
                |_guard, _frame| {
                    Err("Q6AR must not reach the application transaction handler".into())
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
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let frame = encode_q6ar(&Q6arAdvertisement {
            network_id: NETWORK,
            profile_id: PROFILE,
            issued_at_secs: now,
            ttl_secs: 300,
            addresses: vec![Q6arAddress {
                endpoint: "8.8.8.8:8333".parse().unwrap(),
                noise_static_public_key: [0x44; 32],
            }],
        })
        .unwrap();
        noise.write_record(&mut stream, &frame).unwrap();
        for _ in 0..200 {
            if !received.lock().unwrap().is_empty() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(received.lock().unwrap().len(), 1);
        noise.write_record(&mut stream, &frame).unwrap();
        drop(stream);
        shutdown.store(true, std::sync::atomic::Ordering::Release);
        let report = server.join().unwrap();
        let records = received.lock().unwrap();
        assert_eq!(records.len(), 1);
        assert!(records[0].relay_origin.relay_static_key_pinned);
        assert_eq!(
            records[0].advertisement.addresses[0].noise_static_public_key,
            [0x44; 32]
        );
        assert_eq!(report.stats.requests_received, 1);
        assert_eq!(report.stats.q6ar_rejections, 1);
        assert_eq!(report.stats.handler_failures, 0);
    }

    #[test]
    fn qfp6_listener_answers_q6ar_pull_only_inside_pinned_noise_session() {
        use crate::qrun_v06_noise_transport_candidate::QRunV06NoiseSession;
        use crate::qrun_v06_peer_address_relay_candidate::{
            decode_q6ar_pull_response, encode_q6ar_pull_request, encode_q6ar_pull_response,
            Q6arAddress, Q6arAdvertisement, Q6arPullRequest, Q6AR_PULL_REQUEST_MAGIC,
        };
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
            serve_qfp6_noise_listener_with_history_and_q6ar_relay_pins(
                &listener,
                config,
                &server_private,
                &[],
                &[client_public],
                &NETWORK,
                &PROFILE,
                &server_shutdown,
                |_advertisement| Ok(()),
                move |_guard, frame| {
                    if frame.get(..4) != Some(&Q6AR_PULL_REQUEST_MAGIC) {
                        return Err("unexpected non-Q6AR pull frame".into());
                    }
                    let request =
                        crate::qrun_v06_peer_address_relay_candidate::decode_q6ar_pull_request(
                            frame, &NETWORK, &PROFILE,
                        )
                        .map_err(|error| error.to_string())?;
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_err(|error| error.to_string())?
                        .as_secs();
                    let advertisement = Q6arAdvertisement {
                        network_id: NETWORK,
                        profile_id: PROFILE,
                        issued_at_secs: now,
                        ttl_secs: 120,
                        addresses: vec![Q6arAddress {
                            endpoint: "8.8.8.8:8333".parse().unwrap(),
                            noise_static_public_key: [0x44; 32],
                        }],
                    };
                    let response = encode_q6ar_pull_response(&request, Some(&advertisement))
                        .map_err(|error| error.to_string())?;
                    Ok(vec![response])
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
        let request = Q6arPullRequest {
            request_id: 91,
            network_id: NETWORK,
            profile_id: PROFILE,
            max_addresses: 1,
        };
        let request_frame = encode_q6ar_pull_request(&request).unwrap();
        noise.write_record(&mut stream, &request_frame).unwrap();
        let response_frame = noise.read_record(&mut stream).unwrap();
        let response = decode_q6ar_pull_response(
            &response_frame,
            &request,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();
        let advertisement = response.advertisement.unwrap();
        assert_eq!(advertisement.addresses.len(), 1);
        assert_eq!(
            advertisement.addresses[0].noise_static_public_key,
            [0x44; 32]
        );

        drop(stream);
        shutdown.store(true, std::sync::atomic::Ordering::Release);
        let report = server.join().unwrap();
        assert_eq!(report.stats.authenticated_sessions, 1);
        assert_eq!(report.stats.requests_received, 1);
        assert_eq!(report.stats.responses_written, 1);
        assert_eq!(report.stats.q6ar_rejections, 0);
        assert_eq!(report.stats.handler_failures, 0);
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
    #[test]
    fn qfp6_noise_q6pb_listener_rejects_unqualified_quote_then_accepts_height_bound_q6qa() {
        use crate::{
            consensus::{ConsensusParameters, Uint256},
            external_cas_anchor_candidate::ExternalCasPin,
            qrun_v06_asset_registry_candidate::{
                AssetRegistration, AssetSupplyPolicy, AssetTrustPolicy,
            },
            qrun_v06_canonical_execution_candidate::{
                QRunV06BlockOperation, QRunV06CanonicalExecutionState,
            },
            qrun_v06_cp0651_supply_candidate::Cp0651FixedSupply,
            qrun_v06_genesis_descriptor_candidate::QRunV06GenesisDescriptor,
            qrun_v06_miner_candidate::mine_qfp6_block_on_tip_with_quote_asset_authorization,
            qrun_v06_node_runtime_candidate::encode_qrun_v06_peer_block_request,
            qrun_v06_orderbook_candidate::{
                QRunV06OrderBookOperation, QRunV06SignedOrderBookOperation,
            },
            qrun_v06_permissionless_runtime_candidate::QRunV06PermissionlessNodeRuntime,
            qrun_v06_profile_pin_candidate::{
                QRunV06ProfilePinCandidate, QRunV06QuoteAssetTrustPin,
            },
            qrun_v06_profile_trust_candidate::{
                authorize_qrun_v06_profile_pin, MonotonicQRunV06ProfileTrustFloorStore,
                PinnedQRunV06ProfileTrustAuthority, QRunV06FreshQuoteAssetAuthorizationProvider,
                QRunV06ProfileTrustError, QRunV06ProfileTrustRecord, QRunV06ProfileTrustSource,
                QRunV06ProfileTrustStatus, QRunV06SignedProfileTrustEnvelope,
                TrustedQRunV06ProfileTrustFloor,
            },
            qrun_v06_quote_asset_qualification_candidate::{
                CustodyModel, QRunV06QuoteAssetQualificationCandidate,
                QRunV06SignedQuoteAssetQualificationCandidate, QualificationStatus,
                RedemptionModel,
            },
            state_machine::{AccountId, TransactionAuthenticator},
            v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate,
            v4_fat1_trust_candidate::ML_DSA_65_PUBLIC_KEY_BYTES,
        };
        use ed25519_dalek::{Signature as Ed25519Signature, Signer, SigningKey, VerifyingKey};
        use libcrux_ml_dsa::ml_dsa_65::portable;
        use std::{
            fs,
            sync::atomic::{AtomicUsize, Ordering},
            time::{SystemTime, UNIX_EPOCH},
        };

        const OWNER: [u8; 32] = [0xA3; 32];
        const PRODUCER: [u8; 32] = [0xA4; 32];

        struct DigestAuthenticator;
        struct Q6QaEd25519Authenticator {
            account: AccountId,
            key: VerifyingKey,
        }
        impl TransactionAuthenticator for Q6QaEd25519Authenticator {
            fn verify(
                &self,
                sender: &AccountId,
                digest: &[u8; 32],
                signature: &[u8],
            ) -> Result<(), ()> {
                if sender != &self.account {
                    return Err(());
                }
                let signature = Ed25519Signature::from_slice(signature).map_err(|_| ())?;
                self.key.verify_strict(digest, &signature).map_err(|_| ())
            }
        }

        struct LocalTestTrustFloor {
            floor: TrustedQRunV06ProfileTrustFloor,
        }
        impl MonotonicQRunV06ProfileTrustFloorStore for LocalTestTrustFloor {
            fn load(
                &self,
                network_id: &[u8; 32],
                profile_id: &[u8; 32],
            ) -> Result<TrustedQRunV06ProfileTrustFloor, QRunV06ProfileTrustError> {
                if &self.floor.network_id != network_id || &self.floor.profile_id != profile_id {
                    return Err(QRunV06ProfileTrustError::WrongNetworkOrProfile);
                }
                Ok(self.floor.clone())
            }

            fn compare_and_swap(
                &mut self,
                expected: &TrustedQRunV06ProfileTrustFloor,
                next: &TrustedQRunV06ProfileTrustFloor,
            ) -> Result<(), QRunV06ProfileTrustError> {
                if &self.floor != expected {
                    return Err(QRunV06ProfileTrustError::FloorCasConflict);
                }
                self.floor = next.clone();
                Ok(())
            }
        }

        struct LocalTestTrustSource {
            envelope: Vec<u8>,
            reads: Arc<AtomicUsize>,
        }
        impl QRunV06ProfileTrustSource for LocalTestTrustSource {
            type Error = String;

            fn read_current_signed_record(
                &mut self,
                network_id: &[u8; 32],
                profile_id: &[u8; 32],
            ) -> Result<Vec<u8>, Self::Error> {
                if network_id != &NETWORK || profile_id != &PROFILE {
                    return Err("wrong test trust-source scope".into());
                }
                self.reads.fetch_add(1, Ordering::SeqCst);
                Ok(self.envelope.clone())
            }
        }
        impl TransactionAuthenticator for DigestAuthenticator {
            fn verify(
                &self,
                sender: &AccountId,
                digest: &[u8; 32],
                signature: &[u8],
            ) -> Result<(), ()> {
                if *sender != [0; 32] && signature == digest {
                    Ok(())
                } else {
                    Err(())
                }
            }
        }

        let mut params = ConsensusParameters::qrun_v06_cp0651_fee_only_candidate().unwrap();
        params.target_block_time_secs = 30;
        params.difficulty_window_blocks = 2;
        params.difficulty_min_ratio_divisor = 4;
        params.difficulty_max_ratio = 4;
        params.initial_target = Uint256::from_be_bytes([0x7F; 32]);
        params.pow_limit = Uint256::MAX;
        params.validate().unwrap();

        let cp0651_policy = Cp0651FixedSupply::genesis(NETWORK, OWNER).unwrap();
        let descriptor = QRunV06GenesisDescriptor::new(
            NETWORK,
            PROFILE,
            OWNER,
            1,
            crate::qrun_v06_checkpoint_candidate::qrun_v06_consensus_fingerprint(&params).unwrap(),
            cp0651_policy.policy_fingerprint(),
        )
        .unwrap();
        let genesis = QRunV06CanonicalExecutionState::cp0651_genesis_candidate_with_descriptor(
            descriptor.clone(),
        )
        .unwrap();
        // Keep an exact Genesis/consensus copy for a post-listener durable-store reopen.
        let genesis_for_recovery = genesis.clone();
        let params_for_recovery = params.clone();

        // Deterministic test-only authority keys. Q6TS is genuinely signed by Ed25519 and
        // ML-DSA-65; Q6QA is genuinely signed by its pinned Ed25519 authority key.
        let trust_ed_signing_key = SigningKey::from_bytes(&[0x61; 32]);
        let trust_pq_keypair = portable::generate_key_pair([0x62; 32]);
        let trust_authority = PinnedQRunV06ProfileTrustAuthority {
            ed25519_public_key: trust_ed_signing_key.verifying_key().to_bytes(),
            mldsa65_public_key: *trust_pq_keypair.verification_key.as_ref(),
        };
        let trust_pq_verifier = LibcruxMlDsa65VerifierCandidate;
        let quote_signing_key = SigningKey::from_bytes(&[0x71; 32]);
        let quote_authority_account = [0x95; 32];
        let quote_authority_key_id = [0x96; 32];
        let quote_authenticator = Q6QaEd25519Authenticator {
            account: quote_authority_account,
            key: quote_signing_key.verifying_key(),
        };

        let directory = std::env::temp_dir().join(format!(
            "qfp6-q6qa-noise-listener-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let authenticator = DigestAuthenticator;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut base_registration = AssetRegistration {
            network_id: NETWORK,
            issuer: OWNER,
            issuer_nonce: 1,
            salt: [0xC1; 32],
            name: "Q6QA Listener Base".into(),
            symbol: "Q6LB".into(),
            decimals: 8,
            supply_policy: AssetSupplyPolicy::Fixed {
                total_supply: 10_000,
            },
            initial_supply: 10_000,
            initial_recipient: OWNER,
            trust_policy: AssetTrustPolicy::Unverified,
            expires_at: timestamp + 3_600,
            signature: Vec::new(),
        };
        base_registration.signature = base_registration.signing_digest().unwrap().to_vec();
        let base_asset = base_registration.asset_id();

        let mut quote_registration = AssetRegistration {
            network_id: NETWORK,
            issuer: OWNER,
            issuer_nonce: 2,
            salt: [0xC2; 32],
            name: "Q6QA Listener External Quote".into(),
            symbol: "Q6LQ".into(),
            decimals: 6,
            supply_policy: AssetSupplyPolicy::Fixed {
                total_supply: 10_000,
            },
            initial_supply: 10_000,
            initial_recipient: OWNER,
            trust_policy: AssetTrustPolicy::Unverified,
            expires_at: timestamp + 3_600,
            signature: Vec::new(),
        };
        quote_registration.signature = quote_registration.signing_digest().unwrap().to_vec();
        let quote_asset = quote_registration.asset_id();

        let mut create_pair = QRunV06SignedOrderBookOperation {
            network_id: NETWORK,
            sender: OWNER,
            nonce: 1,
            expires_at: timestamp + 3_600,
            operation: QRunV06OrderBookOperation::CreatePair {
                base: base_asset,
                quote: quote_asset,
                base_lot_atoms: 1,
                quote_tick_atoms: 1,
                max_price_ticks: 1_000,
                max_quantity_lots: 1_000,
                min_notional: 1,
                maker_fee_bps: 10,
                taker_fee_bps: 20,
                fee_collector: PRODUCER,
            },
            signature: Vec::new(),
        };
        create_pair.signature = create_pair.signing_digest().unwrap().to_vec();
        let operations = vec![
            QRunV06BlockOperation::AssetRegistration(base_registration),
            QRunV06BlockOperation::AssetRegistration(quote_registration),
            QRunV06BlockOperation::OrderBook(create_pair),
        ];

        let q6qa_record = QRunV06QuoteAssetQualificationCandidate {
            network_id: NETWORK,
            profile_id: PROFILE,
            asset_id: quote_asset,
            external_chain_id: [0xC3; 32],
            issuer_id: [0xC4; 32],
            custodian_id: [0xC5; 32],
            bridge_id: [0; 32],
            reserve_evidence_digest: [0xC6; 32],
            redemption_evidence_digest: [0xC7; 32],
            control_risk_evidence_digest: [0xC8; 32],
            authority_key_id: quote_authority_key_id,
            authority_account: quote_authority_account,
            qualification_epoch: 1,
            valid_from_height: 1,
            valid_until_height: 100,
            decimals: 6,
            custody_model: CustodyModel::IndependentCustodian,
            redemption_model: RedemptionModel::CustodianRedemption,
            status: QualificationStatus::Approved,
            contract_address: vec![0xC9; 20],
            symbol: "TQ6A".into(),
            representation: "Test quote asset on isolated fixture chain".into(),
        };
        let q6qa_digest = q6qa_record.signing_digest().unwrap();
        let q6qa_signature = quote_signing_key.sign(&q6qa_digest).to_bytes().to_vec();
        let q6qa_bundle = QRunV06SignedQuoteAssetQualificationCandidate {
            record: q6qa_record,
            signature: q6qa_signature,
        };
        let q6qa_bytes = q6qa_bundle.encode().unwrap();
        let q6qa_commitment = q6qa_bundle.commitment().unwrap();

        let quote_pin = QRunV06QuoteAssetTrustPin::new(
            1,
            q6qa_commitment,
            quote_asset,
            quote_authority_key_id,
            quote_authority_account,
            1,
        )
        .unwrap();
        let profile_pin = QRunV06ProfilePinCandidate::new_with_quote_asset_trust_pin(
            descriptor.clone(),
            ExternalCasPin {
                provider_id: [0xB1; 32],
                network_id: NETWORK,
                genesis_digest: [0xB2; 32],
                receipt_key_id: [0xB3; 32],
                receipt_public_key: [0xB4; ML_DSA_65_PUBLIC_KEY_BYTES],
            },
            quote_pin,
        )
        .unwrap();
        let profile_pin_bytes = profile_pin.encode().unwrap();
        let profile_pin_commitment = profile_pin.commitment().unwrap();
        assert_eq!(
            u16::from_be_bytes([profile_pin_bytes[4], profile_pin_bytes[5]]),
            2,
            "Q6QA commitment must be carried by Q6PN v2"
        );
        let q6ts_record = QRunV06ProfileTrustRecord {
            trust_epoch: 1,
            status: QRunV06ProfileTrustStatus::Active,
            network_id: NETWORK,
            profile_id: PROFILE,
            profile_pin_commitment,
            previous_record_id: [0; 32],
        };
        let authority_keyset_id = trust_authority.keyset_id().unwrap();
        let q6ts_digest = q6ts_record.signing_digest(&authority_keyset_id).unwrap();
        let q6ts_ed25519_signature = trust_ed_signing_key.sign(&q6ts_digest).to_bytes();
        let q6ts_mldsa65_signature =
            portable::sign(&trust_pq_keypair.signing_key, &q6ts_digest, &[], [0x63; 32]).unwrap();
        let q6ts_envelope = QRunV06SignedProfileTrustEnvelope {
            record: q6ts_record.clone(),
            authority_keyset_id,
            ed25519_signature: q6ts_ed25519_signature,
            mldsa65_signature: *q6ts_mldsa65_signature.as_ref(),
        };
        let q6ts_bytes = q6ts_envelope.encode().unwrap().to_vec();
        let floor_seed = TrustedQRunV06ProfileTrustFloor::provisioned(
            NETWORK,
            PROFILE,
            1,
            QRunV06ProfileTrustStatus::Active,
            q6ts_record.record_id().unwrap(),
            q6ts_envelope.envelope_id().unwrap(),
        )
        .unwrap();

        // Startup requires the Q6TS profile commitment to be already pinned; node startup never
        // advances this floor. The floor implementation here is an in-memory test double only.
        let mut startup_floor = LocalTestTrustFloor {
            floor: floor_seed.clone(),
        };
        let authorized_profile = authorize_qrun_v06_profile_pin(
            Some(&profile_pin_bytes),
            &q6ts_bytes,
            &trust_authority,
            &trust_pq_verifier,
            &mut startup_floor,
            NETWORK,
            PROFILE,
        )
        .unwrap();
        let startup_reads = Arc::new(AtomicUsize::new(0));
        let mut startup_source = LocalTestTrustSource {
            envelope: q6ts_bytes.clone(),
            reads: startup_reads,
        };
        let mut startup_quote_provider = QRunV06FreshQuoteAssetAuthorizationProvider::new(
            &profile_pin_bytes,
            &q6qa_bytes,
            &trust_authority,
            &trust_pq_verifier,
            &mut startup_floor,
            &mut startup_source,
            &quote_authenticator,
        );
        let mut startup_authorizer =
            |parent: &QRunV06CanonicalExecutionState,
             block: &crate::qrun_v06_canonical_execution_candidate::QRunV06Block,
             asset_id: [u8; 32]| {
                startup_quote_provider
                    .authorize_for_block(
                        &parent.network_id(),
                        &parent.profile_id(),
                        &asset_id,
                        block.height,
                    )
                    .map_err(|error| format!("startup Q6TS/Q6QA verification failed: {error:?}"))
            };
        let runtime = QRunV06PermissionlessNodeRuntime::open_with_quote_asset_authorization(
            &directory,
            genesis,
            params,
            &authenticator,
            None,
            &authorized_profile,
            &mut startup_authorizer,
        )
        .unwrap();
        drop(startup_authorizer);
        drop(startup_quote_provider);

        let graph = runtime.fork_choice_snapshot().unwrap();
        let parent_tip = graph.canonical_tip().tip_hash;
        let mining_reads = Arc::new(AtomicUsize::new(0));
        let mut mining_source = LocalTestTrustSource {
            envelope: q6ts_bytes.clone(),
            reads: mining_reads.clone(),
        };
        let mut mining_floor = LocalTestTrustFloor {
            floor: floor_seed.clone(),
        };
        let mut mining_quote_provider = QRunV06FreshQuoteAssetAuthorizationProvider::new(
            &profile_pin_bytes,
            &q6qa_bytes,
            &trust_authority,
            &trust_pq_verifier,
            &mut mining_floor,
            &mut mining_source,
            &quote_authenticator,
        );
        let mut mining_authorizer =
            |parent: &QRunV06CanonicalExecutionState,
             block: &crate::qrun_v06_canonical_execution_candidate::QRunV06Block,
             asset_id: [u8; 32]| {
                mining_quote_provider
                    .authorize_for_block(
                        &parent.network_id(),
                        &parent.profile_id(),
                        &asset_id,
                        block.height,
                    )
                    .map_err(|error| format!("mining Q6TS/Q6QA verification failed: {error:?}"))
            };
        let mined = mine_qfp6_block_on_tip_with_quote_asset_authorization(
            &graph,
            &parent_tip,
            timestamp,
            PRODUCER,
            operations,
            &authenticator,
            &mut mining_authorizer,
            1_000_000,
            &AtomicBool::new(false),
        )
        .unwrap();
        assert!(!mined.envelope.is_empty());
        assert_eq!(mining_reads.load(Ordering::SeqCst), 1);
        drop(mining_authorizer);
        drop(mining_quote_provider);

        let (server_private, server_public) = keypair();
        let (client_private, client_public) = keypair();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let server_shutdown = shutdown.clone();
        let authorization_calls = Arc::new(AtomicUsize::new(0));
        let server_authorization_calls = authorization_calls.clone();
        let server_trust_reads = Arc::new(AtomicUsize::new(0));
        let server_trust_reads_for_source = server_trust_reads.clone();
        let server_q6ts_bytes = q6ts_bytes.clone();
        let server_floor_seed = floor_seed.clone();
        let server_profile_pin_bytes = profile_pin_bytes.clone();
        let server_q6qa_bytes = q6qa_bytes.clone();
        let server_trust_authority = trust_authority.clone();

        let server = thread::spawn(move || {
            let mut runtime = runtime;
            let mut server_floor = LocalTestTrustFloor {
                floor: server_floor_seed,
            };
            let mut server_source = LocalTestTrustSource {
                envelope: server_q6ts_bytes,
                reads: server_trust_reads_for_source,
            };
            let server_pq_verifier = LibcruxMlDsa65VerifierCandidate;
            let mut server_quote_provider = QRunV06FreshQuoteAssetAuthorizationProvider::new(
                &server_profile_pin_bytes,
                &server_q6qa_bytes,
                &server_trust_authority,
                &server_pq_verifier,
                &mut server_floor,
                &mut server_source,
                &quote_authenticator,
            );
            let mut quote_authorizer =
                |parent: &QRunV06CanonicalExecutionState,
                 block: &crate::qrun_v06_canonical_execution_candidate::QRunV06Block,
                 asset_id: [u8; 32]| {
                    assert_eq!(parent.height(), 0);
                    assert_eq!(block.height, 1);
                    assert_eq!(asset_id, quote_asset);
                    server_authorization_calls.fetch_add(1, Ordering::SeqCst);
                    server_quote_provider
                        .authorize_for_block(
                            &parent.network_id(),
                            &parent.profile_id(),
                            &asset_id,
                            block.height,
                        )
                        .map_err(|error| format!("fresh Q6TS/Q6QA verification failed: {error:?}"))
                };
            let mut config = QRunV06PeerListenerConfig::default();
            config.max_sessions = 1;
            config.max_requests_per_session = 2;
            config.max_failed_handshakes = 1;
            let report = serve_qfp6_noise_listener(
                &listener,
                config,
                &server_private,
                &[client_public],
                &NETWORK,
                &PROFILE,
                &server_shutdown,
                |guard, frame| {
                    let request = decode_qrun_v06_peer_block_request(frame)
                        .map_err(|error| error.to_string())?;
                    if request.request_id == 1 {
                        process_qfp6_peer_frame_with_permissionless_runtime(
                            &mut runtime,
                            guard,
                            frame,
                            &authenticator,
                        )
                    } else {
                        process_qfp6_peer_frame_with_permissionless_runtime_and_quote_asset_authorization(
                            &mut runtime,
                            guard,
                            frame,
                            &authenticator,
                            &mut quote_authorizer,
                        )
                    }
                },
            )
            .unwrap();
            let committed_status = runtime.status().unwrap();
            (
                report,
                committed_status.height,
                committed_status.tip,
                committed_status.state_root,
                committed_status.manifest_generation,
                committed_status.manifest_anchor,
                server_trust_reads.load(Ordering::SeqCst),
            )
        });

        let mut stream = connect_until(address);
        stream.set_nodelay(true).unwrap();
        let mut noise = QRunV06NoiseSession::connect(
            &mut stream,
            &client_private,
            &server_public,
            &NETWORK,
            &PROFILE,
        )
        .unwrap();

        let first_frame = encode_qrun_v06_peer_block_request(1, &mined.envelope).unwrap();
        noise.write_q6pb_request(&mut stream, &first_frame).unwrap();
        let rejected = noise.read_q6pa_response(&mut stream, 1).unwrap();
        assert_eq!(
            u16::from_be_bytes([rejected[6], rejected[7]]),
            crate::qrun_v06_node_runtime_candidate::QRunV06PeerAdmissionStatus::Rejected as u16
        );

        let second_frame = encode_qrun_v06_peer_block_request(2, &mined.envelope).unwrap();
        noise
            .write_q6pb_request(&mut stream, &second_frame)
            .unwrap();
        let accepted = noise.read_q6pa_response(&mut stream, 2).unwrap();
        assert_eq!(
            u16::from_be_bytes([accepted[6], accepted[7]]),
            crate::qrun_v06_node_runtime_candidate::QRunV06PeerAdmissionStatus::Accepted as u16
        );

        drop(stream);
        shutdown.store(true, Ordering::Release);
        let (
            report,
            ending_height,
            ending_tip,
            ending_state_root,
            ending_manifest_generation,
            ending_manifest_anchor,
            q6ts_source_reads,
        ) = server.join().unwrap();
        assert_eq!(report.stats.authenticated_sessions, 1);
        assert_eq!(report.stats.requests_received, 2);
        assert_eq!(report.stats.responses_written, 2);
        assert_eq!(ending_height, 1);
        assert_eq!(authorization_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            q6ts_source_reads, 1,
            "the listener must reload and verify the signed Q6TS record for this block"
        );

        // The listener runtime has now been dropped by its server thread. Reopen the same
        // durable store from Genesis and replay its external-quote block with fresh Q6TS/Q6QA.
        let recovery_reads = Arc::new(AtomicUsize::new(0));
        let mut recovery_source = LocalTestTrustSource {
            envelope: q6ts_bytes.clone(),
            reads: recovery_reads.clone(),
        };
        let mut recovery_floor = LocalTestTrustFloor {
            floor: floor_seed.clone(),
        };
        let recovery_pq_verifier = LibcruxMlDsa65VerifierCandidate;
        let recovery_quote_authenticator = Q6QaEd25519Authenticator {
            account: quote_authority_account,
            key: quote_signing_key.verifying_key(),
        };
        let mut recovery_quote_provider = QRunV06FreshQuoteAssetAuthorizationProvider::new(
            &profile_pin_bytes,
            &q6qa_bytes,
            &trust_authority,
            &recovery_pq_verifier,
            &mut recovery_floor,
            &mut recovery_source,
            &recovery_quote_authenticator,
        );
        let mut recovery_authorizer =
            |parent: &QRunV06CanonicalExecutionState,
             block: &crate::qrun_v06_canonical_execution_candidate::QRunV06Block,
             asset_id: [u8; 32]| {
                recovery_quote_provider
                    .authorize_for_block(
                        &parent.network_id(),
                        &parent.profile_id(),
                        &asset_id,
                        block.height,
                    )
                    .map_err(|error| format!("restart Q6TS/Q6QA verification failed: {error:?}"))
            };
        let recovery_authenticator = DigestAuthenticator;
        let unanchored_reopen =
            QRunV06PermissionlessNodeRuntime::open_with_quote_asset_authorization(
                &directory,
                genesis_for_recovery.clone(),
                params_for_recovery.clone(),
                &recovery_authenticator,
                None,
                &authorized_profile,
                &mut recovery_authorizer,
            );
        assert!(
            unanchored_reopen.is_err(),
            "existing durable market history must reject restart without an independent manifest anchor"
        );
        assert_eq!(
            recovery_reads.load(Ordering::SeqCst),
            0,
            "manifest-anchor rejection must happen before trusting/replaying quote-asset history"
        );

        let recovered_runtime =
            QRunV06PermissionlessNodeRuntime::open_with_quote_asset_authorization(
                &directory,
                genesis_for_recovery,
                params_for_recovery,
                &recovery_authenticator,
                Some(ending_manifest_anchor),
                &authorized_profile,
                &mut recovery_authorizer,
            )
            .unwrap();
        drop(recovery_authorizer);
        drop(recovery_quote_provider);
        let recovered_status = recovered_runtime.status().unwrap();
        assert_eq!(recovered_status.height, ending_height);
        assert_eq!(recovered_status.tip, ending_tip);
        assert_eq!(recovered_status.state_root, ending_state_root);
        assert_eq!(
            recovered_status.manifest_generation,
            ending_manifest_generation
        );
        assert_eq!(recovered_status.manifest_anchor, ending_manifest_anchor);
        assert_ne!(ending_manifest_anchor, [0; 32]);
        assert_eq!(
            recovery_reads.load(Ordering::SeqCst),
            1,
            "durable replay must freshly reload and verify Q6TS/Q6QA"
        );
        drop(recovered_runtime);

        let _ = fs::remove_dir_all(&directory);
    }

    #[test]
    fn qfp6_open_history_listener_accepts_anonymous_peer_on_wildcard_candidate_bind() {
        let (server_private, server_public) = keypair();
        let (client_private, _client_public) = keypair();
        let listener = TcpListener::bind("0.0.0.0:0").unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = AtomicBool::new(false);
        let server = thread::spawn(move || {
            serve_qfp6_noise_listener_with_history_open(
                &listener,
                QRunV06PeerListenerConfig {
                    max_sessions: 1,
                    max_requests_per_session: 1,
                    max_failed_handshakes: 2,
                    accept_poll_interval: Duration::from_millis(10),
                },
                &server_private,
                &NETWORK,
                &PROFILE,
                &shutdown,
                |_guard, frame| {
                    let request = decode_qrun_v06_peer_block_request(frame)
                        .map_err(|error| error.to_string())?;
                    Ok(vec![make_response(
                        request.request_id,
                        crate::qrun_v06_node_runtime_candidate::QRunV06PeerAdmissionStatus::Accepted
                            as u16,
                    )
                    .to_vec()])
                },
            )
            .unwrap()
        });

        let mut stream = connect_until(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            address.port(),
        ));
        let mut client = QRunV06NoiseSession::connect(
            &mut stream,
            &client_private,
            &server_public,
            &NETWORK,
            &PROFILE,
        )
        .unwrap();
        let frame = encode_qrun_v06_peer_block_request(0xA016, b"candidate-open-peer").unwrap();
        client.write_q6pb_request(&mut stream, &frame).unwrap();
        let ack = client.read_q6pa_response(&mut stream, 0xA016).unwrap();
        assert_eq!(
            u16::from_be_bytes([ack[6], ack[7]]),
            crate::qrun_v06_node_runtime_candidate::QRunV06PeerAdmissionStatus::Accepted as u16,
        );
        let report = server.join().unwrap();
        assert_eq!(report.stats.accepted_connections, 1);
        assert_eq!(report.stats.authenticated_sessions, 0);
        assert_eq!(report.stats.unverified_peer_sessions, 1);
        assert_eq!(report.stats.requests_received, 1);
        assert_eq!(
            report.stop_reason,
            QRunV06PeerListenerStopReason::SessionLimitReached
        );
    }
}
