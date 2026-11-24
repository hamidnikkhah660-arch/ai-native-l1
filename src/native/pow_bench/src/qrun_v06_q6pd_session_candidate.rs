//! Q6PD bounded persistent Noise peer-session controls.
//!
//! The persistent channel is transport liveness only. It does not promote a signed
//! discovery candidate to operator trust, consensus authority, or transaction privilege.
//! Candidate identity is checked on the dialing side against the exact Noise static-key pin.

use crate::{
    qrun_v06_node_runtime_candidate::QRunV06PeerReplayGuard,
    qrun_v06_noise_transport_candidate::{QRunV06NoiseError, QRunV06NoiseSession},
};
use std::{
    net::{SocketAddr, TcpStream},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, RwLock,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const Q6PD_SESSION_VERSION: u16 = 1;
pub const Q6PD_SESSION_OPEN_MAGIC: [u8; 4] = *b"Q6SO";
/// Explicit opt-in for a short-lived NAT-only liveness slot; it carries no peer record or trust.
pub const Q6PD_NAT_ONLY_SESSION_OPEN_MAGIC: [u8; 4] = *b"Q6NO";
pub const Q6PD_NAT_ONLY_SESSION_ACK_MAGIC: [u8; 4] = *b"Q6NA";
pub const Q6PD_SESSION_OPEN_ACK_MAGIC: [u8; 4] = *b"Q6SA";
pub const Q6PD_SESSION_PING_MAGIC: [u8; 4] = *b"Q6SP";
pub const Q6PD_SESSION_PONG_MAGIC: [u8; 4] = *b"Q6SR";
pub const Q6PD_SESSION_CLOSE_MAGIC: [u8; 4] = *b"Q6SC";
pub const Q6PD_SESSION_CONTROL_BYTES: usize = 78;
pub const Q6PD_SESSION_ACK_BYTES: usize = Q6PD_SESSION_CONTROL_BYTES + 1;

/// Hard process-local bound. Persistent sockets never consume more than this many
/// dedicated server threads, independently of the regular listener session budget.
pub const Q6PD_MAX_PERSISTENT_SESSIONS: usize = 8;
/// Unannounced NAT-only liveness sessions use a separate, much smaller resource pool.
pub const Q6PD_MAX_NAT_ONLY_SESSIONS: usize = 2;
pub const Q6PD_SESSION_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
const Q6PD_SERVER_READ_BUDGET: Duration = Duration::from_secs(20);
const Q6PD_MAX_MISSED_HEARTBEATS: u8 = 3;
const Q6PD_MAX_SESSION_LIFETIME: Duration = Duration::from_secs(6 * 60 * 60);
const Q6PD_MAX_NAT_ONLY_SESSION_LIFETIME: Duration = Duration::from_secs(2 * 60);
const Q6PD_CLIENT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const Q6PD_CLIENT_IO_TIMEOUT: Duration = Duration::from_secs(15);
const Q6PD_OPEN_ACK_BUDGET: Duration = Duration::from_secs(8);
const Q6PD_HEARTBEAT_ACK_BUDGET: Duration = Duration::from_secs(8);
const Q6PD_RECONNECT_BASE: Duration = Duration::from_secs(5);
const Q6PD_RECONNECT_MAX: Duration = Duration::from_secs(300);
const Q6PD_INTERRUPTIBLE_SLEEP: Duration = Duration::from_millis(100);

static ACTIVE_Q6PD_PERSISTENT_SESSIONS: AtomicUsize = AtomicUsize::new(0);
static ACTIVE_Q6PD_NAT_ONLY_SESSIONS: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Q6pdSessionControl {
    pub request_id: u64,
    pub network_id: [u8; 32],
    pub profile_id: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Q6pdSessionControlError {
    Malformed,
    UnsupportedVersion,
    WrongNetwork,
    WrongProfile,
    RequestMismatch,
    Rejected,
}

impl std::fmt::Display for Q6pdSessionControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Q6pdSessionControlError {}

fn encode_control(magic: [u8; 4], value: &Q6pdSessionControl) -> Vec<u8> {
    let mut out = Vec::with_capacity(Q6PD_SESSION_CONTROL_BYTES);
    out.extend_from_slice(&magic);
    out.extend_from_slice(&Q6PD_SESSION_VERSION.to_be_bytes());
    out.extend_from_slice(&value.network_id);
    out.extend_from_slice(&value.profile_id);
    out.extend_from_slice(&value.request_id.to_be_bytes());
    out
}

fn decode_control(
    frame: &[u8],
    magic: [u8; 4],
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
) -> Result<Q6pdSessionControl, Q6pdSessionControlError> {
    if frame.len() != Q6PD_SESSION_CONTROL_BYTES || frame.get(..4) != Some(&magic) {
        return Err(Q6pdSessionControlError::Malformed);
    }
    let version = u16::from_be_bytes(
        frame[4..6]
            .try_into()
            .map_err(|_| Q6pdSessionControlError::Malformed)?,
    );
    if version != Q6PD_SESSION_VERSION {
        return Err(Q6pdSessionControlError::UnsupportedVersion);
    }
    let received_network: [u8; 32] = frame[6..38]
        .try_into()
        .map_err(|_| Q6pdSessionControlError::Malformed)?;
    let received_profile: [u8; 32] = frame[38..70]
        .try_into()
        .map_err(|_| Q6pdSessionControlError::Malformed)?;
    if &received_network != network_id {
        return Err(Q6pdSessionControlError::WrongNetwork);
    }
    if &received_profile != profile_id {
        return Err(Q6pdSessionControlError::WrongProfile);
    }
    let request_id = u64::from_be_bytes(
        frame[70..78]
            .try_into()
            .map_err(|_| Q6pdSessionControlError::Malformed)?,
    );
    if request_id == 0 {
        return Err(Q6pdSessionControlError::Malformed);
    }
    Ok(Q6pdSessionControl {
        request_id,
        network_id: received_network,
        profile_id: received_profile,
    })
}

pub fn encode_q6pd_session_open(value: &Q6pdSessionControl) -> Vec<u8> {
    encode_control(Q6PD_SESSION_OPEN_MAGIC, value)
}

/// A NAT-only Joiner opts into an unverified, non-gossip liveness slot explicitly.
pub fn encode_q6pd_nat_only_session_open(value: &Q6pdSessionControl) -> Vec<u8> {
    encode_control(Q6PD_NAT_ONLY_SESSION_OPEN_MAGIC, value)
}

pub fn decode_q6pd_nat_only_session_open(
    frame: &[u8],
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
) -> Result<Q6pdSessionControl, Q6pdSessionControlError> {
    decode_control(
        frame,
        Q6PD_NAT_ONLY_SESSION_OPEN_MAGIC,
        network_id,
        profile_id,
    )
}

pub fn encode_q6pd_nat_only_session_ack(value: &Q6pdSessionControl, accepted: bool) -> Vec<u8> {
    let mut out = encode_control(Q6PD_NAT_ONLY_SESSION_ACK_MAGIC, value);
    out.push(u8::from(accepted));
    out
}

pub fn decode_q6pd_nat_only_session_ack(
    frame: &[u8],
    expected: &Q6pdSessionControl,
) -> Result<bool, Q6pdSessionControlError> {
    decode_control_ack(frame, Q6PD_NAT_ONLY_SESSION_ACK_MAGIC, expected)
}

pub fn decode_q6pd_session_open(
    frame: &[u8],
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
) -> Result<Q6pdSessionControl, Q6pdSessionControlError> {
    decode_control(frame, Q6PD_SESSION_OPEN_MAGIC, network_id, profile_id)
}

pub fn encode_q6pd_session_open_ack(value: &Q6pdSessionControl, accepted: bool) -> Vec<u8> {
    let mut out = encode_control(Q6PD_SESSION_OPEN_ACK_MAGIC, value);
    out.push(u8::from(accepted));
    out
}

pub fn decode_q6pd_session_open_ack(
    frame: &[u8],
    expected: &Q6pdSessionControl,
) -> Result<bool, Q6pdSessionControlError> {
    decode_control_ack(frame, Q6PD_SESSION_OPEN_ACK_MAGIC, expected)
}

fn decode_control_ack(
    frame: &[u8],
    magic: [u8; 4],
    expected: &Q6pdSessionControl,
) -> Result<bool, Q6pdSessionControlError> {
    if frame.len() != Q6PD_SESSION_ACK_BYTES || frame.get(..4) != Some(&magic) {
        return Err(Q6pdSessionControlError::Malformed);
    }
    let control = decode_control(
        &frame[..Q6PD_SESSION_CONTROL_BYTES],
        magic,
        &expected.network_id,
        &expected.profile_id,
    )?;
    if control != *expected {
        return Err(Q6pdSessionControlError::RequestMismatch);
    }
    match frame[Q6PD_SESSION_CONTROL_BYTES] {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(Q6pdSessionControlError::Malformed),
    }
}

pub fn encode_q6pd_session_ping(value: &Q6pdSessionControl) -> Vec<u8> {
    encode_control(Q6PD_SESSION_PING_MAGIC, value)
}
pub fn decode_q6pd_session_ping(
    frame: &[u8],
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
) -> Result<Q6pdSessionControl, Q6pdSessionControlError> {
    decode_control(frame, Q6PD_SESSION_PING_MAGIC, network_id, profile_id)
}

pub fn encode_q6pd_session_pong(value: &Q6pdSessionControl) -> Vec<u8> {
    encode_control(Q6PD_SESSION_PONG_MAGIC, value)
}
pub fn decode_q6pd_session_pong(
    frame: &[u8],
    expected: &Q6pdSessionControl,
) -> Result<(), Q6pdSessionControlError> {
    let actual = decode_control(
        frame,
        Q6PD_SESSION_PONG_MAGIC,
        &expected.network_id,
        &expected.profile_id,
    )?;
    if actual != *expected {
        return Err(Q6pdSessionControlError::RequestMismatch);
    }
    Ok(())
}

pub fn encode_q6pd_session_close(value: &Q6pdSessionControl) -> Vec<u8> {
    encode_control(Q6PD_SESSION_CLOSE_MAGIC, value)
}
pub fn decode_q6pd_session_close(
    frame: &[u8],
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
) -> Result<Q6pdSessionControl, Q6pdSessionControlError> {
    decode_control(frame, Q6PD_SESSION_CLOSE_MAGIC, network_id, profile_id)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Q6pdSessionSlotKind {
    SignedPeer,
    NatOnlyUnverified,
}

/// A reservation owns one bounded liveness slot. NAT-only slots are separate and short-lived.
pub struct Q6pdPersistentSessionSlot {
    kind: Q6pdSessionSlotKind,
}

impl Q6pdPersistentSessionSlot {
    fn max_lifetime(&self) -> Duration {
        match self.kind {
            Q6pdSessionSlotKind::SignedPeer => Q6PD_MAX_SESSION_LIFETIME,
            Q6pdSessionSlotKind::NatOnlyUnverified => Q6PD_MAX_NAT_ONLY_SESSION_LIFETIME,
        }
    }

    fn mode_name(&self) -> &'static str {
        match self.kind {
            Q6pdSessionSlotKind::SignedPeer => "signed_peer",
            Q6pdSessionSlotKind::NatOnlyUnverified => "nat_only_unverified",
        }
    }

    fn active_count(&self) -> usize {
        match self.kind {
            Q6pdSessionSlotKind::SignedPeer => active_q6pd_persistent_session_count(),
            Q6pdSessionSlotKind::NatOnlyUnverified => active_q6pd_nat_only_session_count(),
        }
    }
}

impl Drop for Q6pdPersistentSessionSlot {
    fn drop(&mut self) {
        match self.kind {
            Q6pdSessionSlotKind::SignedPeer => {
                ACTIVE_Q6PD_PERSISTENT_SESSIONS.fetch_sub(1, Ordering::AcqRel);
            }
            Q6pdSessionSlotKind::NatOnlyUnverified => {
                ACTIVE_Q6PD_NAT_ONLY_SESSIONS.fetch_sub(1, Ordering::AcqRel);
            }
        }
    }
}

fn try_reserve_slot(
    active: &AtomicUsize,
    limit: usize,
    kind: Q6pdSessionSlotKind,
) -> Option<Q6pdPersistentSessionSlot> {
    active
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
            (count < limit).then_some(count + 1)
        })
        .ok()
        .map(|_| Q6pdPersistentSessionSlot { kind })
}

pub fn try_reserve_q6pd_persistent_session() -> Option<Q6pdPersistentSessionSlot> {
    try_reserve_slot(
        &ACTIVE_Q6PD_PERSISTENT_SESSIONS,
        Q6PD_MAX_PERSISTENT_SESSIONS,
        Q6pdSessionSlotKind::SignedPeer,
    )
}

pub fn try_reserve_q6pd_nat_only_session() -> Option<Q6pdPersistentSessionSlot> {
    try_reserve_slot(
        &ACTIVE_Q6PD_NAT_ONLY_SESSIONS,
        Q6PD_MAX_NAT_ONLY_SESSIONS,
        Q6pdSessionSlotKind::NatOnlyUnverified,
    )
}

pub fn active_q6pd_persistent_session_count() -> usize {
    ACTIVE_Q6PD_PERSISTENT_SESSIONS.load(Ordering::Acquire)
}

pub fn active_q6pd_nat_only_session_count() -> usize {
    ACTIVE_Q6PD_NAT_ONLY_SESSIONS.load(Ordering::Acquire)
}

/// Serve only Q6PD liveness controls on a dedicated worker. Discovery pulls, announcements,
/// history sync and consensus application frames continue to use their existing bounded paths.
pub fn serve_q6pd_persistent_session(
    mut stream: TcpStream,
    mut noise: QRunV06NoiseSession,
    open_request: Q6pdSessionControl,
    peer_addr: SocketAddr,
    slot: Q6pdPersistentSessionSlot,
) {
    let started = Instant::now();
    let max_lifetime = slot.max_lifetime();
    let session_mode = slot.mode_name();
    let mut replay_guard = QRunV06PeerReplayGuard::new();
    if replay_guard.accept(open_request.request_id).is_err() {
        return;
    }
    let pinned = noise.remote_static_key_pinned();
    let remote_key = *noise.remote_static_public_key();
    let mut missed_heartbeats = 0u8;
    eprintln!(
        "QFP6_Q6PD_PERSISTENT_SESSION_STARTED endpoint={} mode={} remote_static_pinned={} active={}",
        peer_addr,
        session_mode,
        pinned,
        slot.active_count()
    );

    while started.elapsed() < max_lifetime {
        let frame = match noise.read_record_with_budget(&mut stream, Q6PD_SERVER_READ_BUDGET) {
            Ok(frame) => frame,
            Err(QRunV06NoiseError::RecordTimeout) => {
                missed_heartbeats = missed_heartbeats.saturating_add(1);
                if missed_heartbeats >= Q6PD_MAX_MISSED_HEARTBEATS {
                    eprintln!(
                        "QFP6_Q6PD_PERSISTENT_SESSION_IDLE_TIMEOUT endpoint={} missed={}",
                        peer_addr, missed_heartbeats
                    );
                    break;
                }
                continue;
            }
            Err(error) => {
                eprintln!(
                    "QFP6_Q6PD_PERSISTENT_SESSION_READ_CLOSED endpoint={} error={error:?}",
                    peer_addr
                );
                break;
            }
        };
        missed_heartbeats = 0;

        if let Ok(close) =
            decode_q6pd_session_close(&frame, &open_request.network_id, &open_request.profile_id)
        {
            if replay_guard.accept(close.request_id).is_ok() {
                break;
            }
            eprintln!(
                "QFP6_Q6PD_PERSISTENT_SESSION_REPLAY_REJECTED endpoint={} request_id={}",
                peer_addr, close.request_id
            );
            break;
        }

        let ping = match decode_q6pd_session_ping(
            &frame,
            &open_request.network_id,
            &open_request.profile_id,
        ) {
            Ok(ping) => ping,
            Err(error) => {
                eprintln!(
                    "QFP6_Q6PD_PERSISTENT_SESSION_PROTOCOL_CLOSED endpoint={} error={error:?}",
                    peer_addr
                );
                break;
            }
        };
        if replay_guard.accept(ping.request_id).is_err() {
            eprintln!(
                "QFP6_Q6PD_PERSISTENT_SESSION_REPLAY_REJECTED endpoint={} request_id={}",
                peer_addr, ping.request_id
            );
            break;
        }
        let pong = encode_q6pd_session_pong(&ping);
        if let Err(error) = noise.write_record(&mut stream, &pong) {
            eprintln!(
                "QFP6_Q6PD_PERSISTENT_SESSION_WRITE_CLOSED endpoint={} error={error:?}",
                peer_addr
            );
            break;
        }
    }

    eprintln!(
        "QFP6_Q6PD_PERSISTENT_SESSION_STOPPED endpoint={} mode={} lifetime_seconds={} remote_key_prefix={:02x?} active={}",
        peer_addr,
        session_mode,
        started.elapsed().as_secs(),
        &remote_key[..4],
        slot.active_count().saturating_sub(1)
    );
}

fn announce_local_q6pd_record(
    noise: &mut QRunV06NoiseSession,
    stream: &mut dyn crate::qrun_v06_noise_transport_candidate::QRunV06NoiseIo,
    record_wire: &[u8],
    local_noise_static_public_key: &[u8; 32],
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
) -> Result<(), String> {
    use crate::qrun_v06_peer_discovery_candidate::{
        decode_q6pd_announce_response, encode_q6pd_announce_request, verify_q6pd_peer_record,
    };

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock invalid for Q6PD session: {error}"))?
        .as_secs();
    let record = verify_q6pd_peer_record(record_wire, network_id, profile_id, now_secs)
        .map_err(|error| format!("local signed Q6PD record is invalid: {error}"))?;
    if record.noise_static_public_key != *local_noise_static_public_key
        || noise.network_id() != network_id
        || noise.profile_id() != profile_id
    {
        return Err(
            "local Q6PD record does not bind this Noise identity and network profile".into(),
        );
    }
    let frame = encode_q6pd_announce_request(record_wire)
        .map_err(|error| format!("local Q6PD announcement encode failed: {error}"))?;
    noise
        .write_record(stream, &frame)
        .map_err(|error| format!("local Q6PD announcement write failed: {error}"))?;
    let acknowledgement = noise
        .read_record(stream)
        .map_err(|error| format!("local Q6PD announcement acknowledgement failed: {error}"))?;
    decode_q6pd_announce_response(&acknowledgement)
        .map_err(|error| format!("remote peer rejected local signed announcement: {error}"))?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Q6pdLocalAnnouncementModeError {
    MissingRecordForPublicIdentity,
    RecordWithoutPublicIdentity,
    ZeroNoiseKey,
}

/// A NAT-only Joiner may maintain an authenticated outbound session without claiming
/// a publicly reachable endpoint. Publicly announcing nodes must still provide a signed
/// record bound to their exact local Noise static key.
fn select_local_announcement_mode(
    local_noise_static_public_key: Option<[u8; 32]>,
    record_wire: Option<Vec<u8>>,
) -> Result<Option<([u8; 32], Vec<u8>)>, Q6pdLocalAnnouncementModeError> {
    match (local_noise_static_public_key, record_wire) {
        (None, None) => Ok(None),
        (Some(key), Some(record)) if key != [0; 32] => Ok(Some((key, record))),
        (Some(_), Some(_)) => Err(Q6pdLocalAnnouncementModeError::ZeroNoiseKey),
        (Some(_), None) => Err(Q6pdLocalAnnouncementModeError::MissingRecordForPublicIdentity),
        (None, Some(_)) => Err(Q6pdLocalAnnouncementModeError::RecordWithoutPublicIdentity),
    }
}
/// Client worker for one exact endpoint/Noise-key pair. A publicly announcing node
/// presents a currently valid self-signed Q6PD record bound to its local Noise key. A
/// NAT-only Joiner may omit that local announcement while still pinning the remote key.
/// This worker never changes operator trust.
pub fn run_q6pd_persistent_peer_session_worker(
    address: SocketAddr,
    tls_server_name: Option<String>,
    local_static_private_key: [u8; 32],
    local_noise_static_public_key: Option<[u8; 32]>,
    remote_static_public_key: [u8; 32],
    network_id: [u8; 32],
    profile_id: [u8; 32],
    local_announcement: Arc<RwLock<Option<Vec<u8>>>>,
    shutdown: &std::sync::atomic::AtomicBool,
) {
    let mut failures = 0u32;
    let mut request_id = system_now_ms().unwrap_or(1).max(1);

    while !shutdown.load(Ordering::Acquire) {
        let announcement = local_announcement
            .read()
            .ok()
            .and_then(|guard| guard.clone());
        let announcement_mode = match select_local_announcement_mode(
            local_noise_static_public_key,
            announcement,
        ) {
            Ok(mode) => mode,
            Err(Q6pdLocalAnnouncementModeError::MissingRecordForPublicIdentity) => {
                eprintln!(
                    "QFP6_Q6PD_SESSION_WAITING_FOR_PUBLIC_SIGNED_RECORD endpoint={}",
                    address
                );
                let _ = sleep_interruptibly(Q6PD_RECONNECT_BASE, shutdown);
                continue;
            }
            Err(error) => {
                eprintln!(
                        "QFP6_Q6PD_SESSION_LOCAL_ANNOUNCEMENT_CONFIG_REJECTED endpoint={} error={error:?}",
                        address
                    );
                let _ = sleep_interruptibly(Q6PD_RECONNECT_MAX, shutdown);
                continue;
            }
        };
        let config =
            crate::qrun_v06_history_sync_service_candidate::QRunV06HistorySyncClientConfig {
                connect_timeout: Q6PD_CLIENT_CONNECT_TIMEOUT,
                io_timeout: Q6PD_CLIENT_IO_TIMEOUT,
                max_blocks_per_page: 1,
                max_bytes_per_page: 64 * 1024,
                max_pages: 1,
                max_rounds: 1,
            };
        let connect_result =
            crate::qrun_v06_history_sync_service_candidate::connect_history_sync_noise_session_with_bounded_retry(
                address,
                tls_server_name.as_deref(),
                config,
                &local_static_private_key,
                &remote_static_public_key,
                &network_id,
                &profile_id,
            );

        let mut active_since: Option<Instant> = None;
        match connect_result {
            Ok((mut stream, mut noise)) => {
                if !noise.remote_static_key_pinned()
                    || noise.remote_static_public_key() != &remote_static_public_key
                    || noise.network_id() != &network_id
                    || noise.profile_id() != &profile_id
                {
                    eprintln!(
                        "QFP6_Q6PD_SESSION_PIN_REJECTED endpoint={} action=drop_session",
                        address
                    );
                } else if let Err(error) = match announcement_mode.as_ref() {
                    Some((local_noise_key, local_record)) => announce_local_q6pd_record(
                        &mut noise,
                        stream.as_mut(),
                        local_record,
                        local_noise_key,
                        &network_id,
                        &profile_id,
                    ),
                    // No local public endpoint is a supported NAT client mode. The
                    // remote key is still pinned by the signed Q6PD record and Noise handshake.
                    None => (|| -> Result<(), String> {
                        request_id = request_id.saturating_add(1).max(1);
                        let opt_in = Q6pdSessionControl {
                            request_id,
                            network_id,
                            profile_id,
                        };
                        noise
                            .write_record(
                                stream.as_mut(),
                                &encode_q6pd_nat_only_session_open(&opt_in),
                            )
                            .map_err(|error| {
                                format!("NAT-only session opt-in write failed: {error}")
                            })?;
                        let ack = noise
                            .read_record_with_budget(stream.as_mut(), Q6PD_OPEN_ACK_BUDGET)
                            .map_err(|error| {
                                format!("NAT-only session opt-in acknowledgement failed: {error}")
                            })?;
                        match decode_q6pd_nat_only_session_ack(&ack, &opt_in) {
                            Ok(true) => {
                                eprintln!(
                                    "QFP6_Q6PD_SESSION_NAT_ONLY_OPT_IN=PASS endpoint={}",
                                    address
                                );
                                Ok(())
                            }
                            Ok(false) => {
                                Err("remote peer refused bounded NAT-only liveness mode".into())
                            }
                            Err(error) => Err(format!("NAT-only session opt-in rejected: {error}")),
                        }
                    })(),
                } {
                    if announcement_mode.is_none() {
                        eprintln!(
                            "QFP6_Q6PD_SESSION_NAT_ONLY_OPT_IN_FAILED endpoint={} error={error}",
                            address
                        );
                    } else {
                        eprintln!(
                            "QFP6_Q6PD_SESSION_LOCAL_ANNOUNCEMENT_REJECTED endpoint={} error={error}",
                            address
                        );
                    }
                } else {
                    request_id = request_id.saturating_add(1).max(1);
                    let open = Q6pdSessionControl {
                        request_id,
                        network_id,
                        profile_id,
                    };
                    let open_result = noise
                        .write_record(stream.as_mut(), &encode_q6pd_session_open(&open))
                        .and_then(|_| {
                            noise.read_record_with_budget(stream.as_mut(), Q6PD_OPEN_ACK_BUDGET)
                        });
                    match open_result {
                        Ok(ack_frame) => match decode_q6pd_session_open_ack(&ack_frame, &open) {
                            Ok(true) => {
                                active_since = Some(Instant::now());
                                failures = 0;
                                eprintln!(
                                    "QFP6_Q6PD_SESSION_ACTIVE endpoint={} remote_key_prefix={:02x?} heartbeat_seconds={}",
                                    address,
                                    &remote_static_public_key[..4],
                                    Q6PD_SESSION_HEARTBEAT_INTERVAL.as_secs()
                                );
                                let mut heartbeat_count = 0u64;
                                while !shutdown.load(Ordering::Acquire) {
                                    if sleep_interruptibly(
                                        Q6PD_SESSION_HEARTBEAT_INTERVAL,
                                        shutdown,
                                    ) {
                                        break;
                                    }
                                    request_id = match request_id.checked_add(1) {
                                        Some(value) if value > 0 => value,
                                        _ => break,
                                    };
                                    let ping = Q6pdSessionControl {
                                        request_id,
                                        network_id,
                                        profile_id,
                                    };
                                    if let Err(error) = noise.write_record(
                                        stream.as_mut(),
                                        &encode_q6pd_session_ping(&ping),
                                    ) {
                                        eprintln!(
                                            "QFP6_Q6PD_SESSION_PING_FAILED endpoint={} error={error:?}",
                                            address
                                        );
                                        break;
                                    }
                                    let pong = match noise.read_record_with_budget(
                                        stream.as_mut(),
                                        Q6PD_HEARTBEAT_ACK_BUDGET,
                                    ) {
                                        Ok(frame) => frame,
                                        Err(error) => {
                                            eprintln!(
                                                "QFP6_Q6PD_SESSION_PONG_TIMEOUT endpoint={} error={error:?}",
                                                address
                                            );
                                            break;
                                        }
                                    };
                                    if let Err(error) = decode_q6pd_session_pong(&pong, &ping) {
                                        eprintln!(
                                            "QFP6_Q6PD_SESSION_PONG_REJECTED endpoint={} error={error:?}",
                                            address
                                        );
                                        break;
                                    }
                                    heartbeat_count = heartbeat_count.saturating_add(1);
                                    if heartbeat_count % 6 == 0 {
                                        eprintln!(
                                            "QFP6_Q6PD_SESSION_HEALTHY endpoint={} heartbeats={}",
                                            address, heartbeat_count
                                        );
                                    }
                                }

                                if shutdown.load(Ordering::Acquire) {
                                    if let Some(close_id) = request_id.checked_add(1) {
                                        let close = Q6pdSessionControl {
                                            request_id: close_id,
                                            network_id,
                                            profile_id,
                                        };
                                        let _ = noise.write_record(
                                            stream.as_mut(),
                                            &encode_q6pd_session_close(&close),
                                        );
                                    }
                                }
                            }
                            Ok(false) => eprintln!(
                                "QFP6_Q6PD_SESSION_OPEN_REFUSED endpoint={} mode={}",
                                address,
                                if announcement_mode.is_some() {
                                    "signed_peer"
                                } else {
                                    "nat_only_unverified"
                                }
                            ),
                            Err(error) => eprintln!(
                                "QFP6_Q6PD_SESSION_OPEN_REJECTED endpoint={} error={error:?}",
                                address
                            ),
                        },
                        Err(error) => eprintln!(
                            "QFP6_Q6PD_SESSION_OPEN_FAILED endpoint={} error={error:?}",
                            address
                        ),
                    }
                }
            }
            Err(error) => eprintln!(
                "QFP6_Q6PD_SESSION_CONNECT_RETRY endpoint={} error={error}",
                address
            ),
        }

        if shutdown.load(Ordering::Acquire) {
            break;
        }
        if let Some(active_at) = active_since {
            if active_at.elapsed() >= Duration::from_secs(60) {
                failures = 0;
            } else {
                failures = failures.saturating_add(1);
            }
        } else {
            failures = failures.saturating_add(1);
        }
        let shift = failures.saturating_sub(1).min(6);
        let delay = Q6PD_RECONNECT_BASE
            .saturating_mul(1u32 << shift)
            .min(Q6PD_RECONNECT_MAX);
        eprintln!(
            "QFP6_Q6PD_SESSION_RECONNECTING endpoint={} failures={} retry_seconds={}",
            address,
            failures,
            delay.as_secs()
        );
        let _ = sleep_interruptibly(delay, shutdown);
    }
}

fn sleep_interruptibly(duration: Duration, shutdown: &std::sync::atomic::AtomicBool) -> bool {
    let deadline = Instant::now() + duration;
    while !shutdown.load(Ordering::Acquire) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        std::thread::sleep(remaining.min(Q6PD_INTERRUPTIBLE_SLEEP));
    }
    true
}

fn system_now_ms() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_millis()
        .try_into()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const NETWORK: [u8; 32] = [0x31; 32];
    const PROFILE: [u8; 32] = [0x42; 32];

    fn control(request_id: u64) -> Q6pdSessionControl {
        Q6pdSessionControl {
            request_id,
            network_id: NETWORK,
            profile_id: PROFILE,
        }
    }

    #[test]
    fn session_open_ack_ping_pong_and_close_are_network_profile_bound() {
        let open = control(100);
        assert_eq!(
            decode_q6pd_session_open(&encode_q6pd_session_open(&open), &NETWORK, &PROFILE),
            Ok(open)
        );
        assert_eq!(
            decode_q6pd_session_open_ack(&encode_q6pd_session_open_ack(&open, true), &open),
            Ok(true)
        );
        assert_eq!(
            decode_q6pd_session_open_ack(&encode_q6pd_session_open_ack(&open, false), &open),
            Ok(false)
        );
        assert_eq!(
            decode_q6pd_session_ping(&encode_q6pd_session_ping(&open), &NETWORK, &PROFILE),
            Ok(open)
        );
        assert_eq!(
            decode_q6pd_session_pong(&encode_q6pd_session_pong(&open), &open),
            Ok(())
        );
        assert_eq!(
            decode_q6pd_session_close(&encode_q6pd_session_close(&open), &NETWORK, &PROFILE),
            Ok(open)
        );
    }

    #[test]
    fn persistent_session_controls_reject_wrong_domains_and_replayed_ids() {
        let open = control(101);
        assert_eq!(
            decode_q6pd_session_open(&encode_q6pd_session_open(&open), &[0x99; 32], &PROFILE),
            Err(Q6pdSessionControlError::WrongNetwork)
        );
        assert_eq!(
            decode_q6pd_session_open(&encode_q6pd_session_open(&open), &NETWORK, &[0x98; 32]),
            Err(Q6pdSessionControlError::WrongProfile)
        );
        let other = control(102);
        assert_eq!(
            decode_q6pd_session_pong(&encode_q6pd_session_pong(&other), &open),
            Err(Q6pdSessionControlError::RequestMismatch)
        );
        let mut replay = QRunV06PeerReplayGuard::new();
        assert!(replay.accept(101).is_ok());
        assert!(replay.accept(102).is_ok());
        assert!(replay.accept(102).is_err());
    }

    #[test]
    fn persistent_session_capacity_is_bounded_and_released_by_guard() {
        let mut slots = Vec::new();
        for _ in 0..Q6PD_MAX_PERSISTENT_SESSIONS {
            slots.push(try_reserve_q6pd_persistent_session().unwrap());
        }
        assert!(try_reserve_q6pd_persistent_session().is_none());
        drop(slots.pop());
        assert!(try_reserve_q6pd_persistent_session().is_some());
        drop(slots);
    }

    #[test]
    fn nat_only_session_capacity_is_separate_bounded_and_short_lived() {
        let mut slots = Vec::new();
        for _ in 0..Q6PD_MAX_NAT_ONLY_SESSIONS {
            slots.push(try_reserve_q6pd_nat_only_session().unwrap());
        }
        assert!(try_reserve_q6pd_nat_only_session().is_none());
        assert!(try_reserve_q6pd_persistent_session().is_some());
        drop(slots.pop());
        assert!(try_reserve_q6pd_nat_only_session().is_some());
        drop(slots);
    }

    #[test]
    fn nat_only_session_control_is_domain_bound_and_carries_no_peer_record() {
        let opt_in = control(411);
        let request = encode_q6pd_nat_only_session_open(&opt_in);
        assert_eq!(
            decode_q6pd_nat_only_session_open(&request, &NETWORK, &PROFILE),
            Ok(opt_in)
        );
        assert_eq!(
            decode_q6pd_nat_only_session_open(&request, &[0x99; 32], &PROFILE),
            Err(Q6pdSessionControlError::WrongNetwork)
        );
        assert_eq!(
            decode_q6pd_nat_only_session_open(&request, &NETWORK, &[0x98; 32]),
            Err(Q6pdSessionControlError::WrongProfile)
        );
        assert_eq!(
            decode_q6pd_nat_only_session_ack(
                &encode_q6pd_nat_only_session_ack(&opt_in, true),
                &opt_in
            ),
            Ok(true)
        );
        assert_eq!(
            decode_q6pd_nat_only_session_ack(
                &encode_q6pd_nat_only_session_ack(&opt_in, false),
                &opt_in
            ),
            Ok(false)
        );
    }
    #[test]
    fn nat_joiner_can_open_persistent_session_without_public_self_announcement() {
        assert_eq!(select_local_announcement_mode(None, None), Ok(None));
    }

    #[test]
    fn publicly_announcing_peer_still_requires_matching_local_record_material() {
        let local_noise_key = [0x71; 32];
        assert_eq!(
            select_local_announcement_mode(Some(local_noise_key), Some(vec![1, 2, 3])),
            Ok(Some((local_noise_key, vec![1, 2, 3])))
        );
        assert_eq!(
            select_local_announcement_mode(Some(local_noise_key), None),
            Err(Q6pdLocalAnnouncementModeError::MissingRecordForPublicIdentity)
        );
        assert_eq!(
            select_local_announcement_mode(None, Some(vec![1, 2, 3])),
            Err(Q6pdLocalAnnouncementModeError::RecordWithoutPublicIdentity)
        );
        assert_eq!(
            select_local_announcement_mode(Some([0; 32]), Some(vec![1])),
            Err(Q6pdLocalAnnouncementModeError::ZeroNoiseKey)
        );
    }
}
