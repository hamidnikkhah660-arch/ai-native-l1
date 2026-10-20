use ai_native_l1_pow_bench::{
    canonical_provider::CanonicalPublicKeyProvider,
    chain_view::{client_a_best, Header},
    credential_binding::{session_identity_context, BindingPolicy, CredentialBinding},
    decode_frame, encode_frame,
    identity_policy::{CryptoPolicy, KeyAlgorithm, KeyPurpose, KeyRecord, KeyState, SecurityClass},
    identity_session::{BoundSession, SessionError},
    key_provider::{InMemoryPublicKeyProvider, ProviderError, PublicKeyProvider},
    p2p_contract::{
        decode_error, encode_error, ErrorCode, ProcessResourceBudget, ProcessSessionGuard,
        RequestTracker,
    },
    protocol_profile::{
        CHAIN_HEADER_WIRE_LEN, ERROR_TYPE, GET_HEADERS_TYPE, HEADERS_TYPE, IDENTITY_CONTEXT_LEN,
        IDENTITY_CORRELATED_RESPONSE_MARKER, IDENTITY_REQUEST_MARKER, IDENTITY_RESPONSE_MARKER,
        MAX_HEADERS_PAYLOAD_TESTNET, MAX_HEADERS_TESTNET, MAX_OUTSTANDING_REQUEST_BYTES_TESTNET,
        MAX_REQUESTS_PER_PEER_TESTNET,
        PROFILE_FEATURE_RESPONSE_CORRELATION as PROFILE_CORRELATION_FEATURE,
        PROFILE_NEGOTIATE_MARKER, PROFILE_NEGOTIATE_PAYLOAD_LEN, PROFILE_NEGOTIATE_TYPE,
        PROFILE_SELECTED_MARKER, PROFILE_SELECTED_PAYLOAD_LEN, PROFILE_SELECTED_TYPE,
        PROFILE_VERSION_C2, PROFILE_VERSION_C3, STATUS_TYPE, WIRE_VERSION,
    },
};
use snow::Builder;
use std::{
    collections::BTreeSet,
    env,
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc::{sync_channel, Receiver, SyncSender, TrySendError},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
const PATTERN: &str = "Noise_NNpsk0_25519_ChaChaPoly_SHA256";
const PROLOGUE: &[u8] = b"AI-NATIVE-L1/transport-v0.1";
const PSK: [u8; 32] = [0x61; 32];
const IO_MS: u64 = 1500;
const SESSION_ESTABLISHMENT_DEADLINE_MS: u64 = 2500;
const MAX_HANDSHAKE: usize = 1024;
const MAX_NOISE: usize = 4 * 1024 * 1024 + 128;
const MAX_CONCURRENT_SESSIONS_PROCESS_TESTNET: usize = 4;
const MAX_PROCESS_RESERVED_BYTES_TESTNET: usize = 2 * 8 * 1024 * 1024;
const MAX_BATCH_RECEIVE_WINDOW_MS: u64 = 2000;
const BATCH_READ_SLICE_MS: u64 = 100;
const MAX_WORKERS_PROCESS_TESTNET: usize = 16;
const MAX_ADMISSION_QUEUE_CAPACITY_TESTNET: usize = 128;
const DEFAULT_ADMISSION_QUEUE_CAPACITY_TESTNET: usize = 4;

#[derive(Clone)]
struct C {
    id: u64,
    listen: u16,
    peer: u16,
    server: bool,
    generation: u32,
    revoked: bool,
    rotate_before_request: bool,
    revoke_before_request: bool,
    rotate_then_revoke: bool,
    correlated_v2: bool,
    profile_negotiation: bool,
    profile_min_version: u16,
    profile_max_version: u16,
    rotate_after_profile_negotiate: bool,
    test_error: bool,
    test_response_fault: String,
    multi_request_count: u32,
    parallel_server: bool,
    max_concurrent_sessions: usize,
    max_process_reserved_bytes: usize,
    worker_count: usize,
    admission_queue_capacity: usize,
    test_session_hold_ms: u64,
    test_batch_hold_after_reserve_ms: u64,
    provider: String,
    connections: u32,
    duration: u64,
}
fn v(a: &[String], n: &str) -> Option<String> {
    a.windows(2).find(|x| x[0] == n).map(|x| x[1].clone())
}
fn num<T: std::str::FromStr>(a: &[String], n: &str, d: T) -> T {
    v(a, n).and_then(|x| x.parse().ok()).unwrap_or(d)
}
fn cfg() -> C {
    let a: Vec<String> = env::args().collect();
    C {
        id: num(&a, "--id", 1),
        listen: num(&a, "--listen", 44801),
        peer: num(&a, "--peer", 44801),
        server: a.iter().any(|x| x == "--server"),
        generation: num(&a, "--generation", 2),
        revoked: a.iter().any(|x| x == "--revoked"),
        rotate_before_request: a.iter().any(|x| x == "--rotate-before-request"),
        revoke_before_request: a.iter().any(|x| x == "--revoke-before-request"),
        rotate_then_revoke: a.iter().any(|x| x == "--rotate-then-revoke"),
        correlated_v2: a.iter().any(|x| x == "--correlated-v2"),
        profile_negotiation: a.iter().any(|x| x == "--profile-negotiation"),
        profile_min_version: num(
            &a,
            "--profile-min-version",
            if a.iter().any(|x| x == "--correlated-v2") {
                PROFILE_VERSION_C3
            } else {
                PROFILE_VERSION_C2
            },
        ),
        profile_max_version: num(
            &a,
            "--profile-max-version",
            if a.iter().any(|x| x == "--server") || a.iter().any(|x| x == "--correlated-v2") {
                PROFILE_VERSION_C3
            } else {
                PROFILE_VERSION_C2
            },
        ),
        rotate_after_profile_negotiate: a.iter().any(|x| x == "--rotate-after-profile-negotiation"),
        test_error: a.iter().any(|x| x == "--test-error"),
        test_response_fault: v(&a, "--test-response-fault").unwrap_or_default(),
        multi_request_count: num(&a, "--multi-request-count", 0),
        parallel_server: a.iter().any(|x| x == "--parallel-server"),
        max_concurrent_sessions: num(
            &a,
            "--max-concurrent-sessions",
            MAX_CONCURRENT_SESSIONS_PROCESS_TESTNET,
        ),
        max_process_reserved_bytes: num(
            &a,
            "--max-process-reserved-bytes",
            MAX_PROCESS_RESERVED_BYTES_TESTNET,
        ),
        worker_count: num(
            &a,
            "--worker-count",
            MAX_CONCURRENT_SESSIONS_PROCESS_TESTNET,
        ),
        admission_queue_capacity: num(
            &a,
            "--admission-queue-capacity",
            DEFAULT_ADMISSION_QUEUE_CAPACITY_TESTNET,
        ),
        test_session_hold_ms: num(&a, "--test-session-hold-ms", 0),
        test_batch_hold_after_reserve_ms: num(&a, "--test-batch-hold-after-reserve-ms", 0),
        provider: v(&a, "--provider").unwrap_or_else(|| "memory".to_string()),
        connections: num(&a, "--connections", 1),
        duration: num(&a, "--duration-ms", 4500),
    }
}
fn key(c: &C) -> KeyRecord {
    KeyRecord {
        key_id: 7,
        generation: c.generation,
        algorithm: KeyAlgorithm::MlDsa65,
        purpose: KeyPurpose::PeerAuth,
        state: if c.revoked {
            KeyState::Revoked
        } else {
            KeyState::Active
        },
        not_before: 10,
        not_after: 100,
        public_key: vec![1, 2, 3],
    }
}
enum ProviderBackend {
    Memory(InMemoryPublicKeyProvider),
    Canonical(CanonicalPublicKeyProvider),
}

impl ProviderBackend {
    fn seed(c: &C) -> Result<Self, ProviderError> {
        let record = key(c);
        match c.provider.as_str() {
            "memory" => InMemoryPublicKeyProvider::new(vec![record]).map(Self::Memory),
            "canonical" => {
                CanonicalPublicKeyProvider::from_records(vec![record]).map(Self::Canonical)
            }
            _ => Err(ProviderError::NotFound),
        }
    }

    fn provision_rotation(
        &mut self,
        old: &KeyRecord,
        new: KeyRecord,
        policy: CryptoPolicy,
    ) -> Result<(), ProviderError> {
        match self {
            Self::Memory(p) => p.provision_rotation(old, new, policy),
            Self::Canonical(p) => p.provision_rotation(old, new, policy),
        }
    }

    fn revoke(
        &mut self,
        key_id: u32,
        generation: u32,
        purpose: KeyPurpose,
    ) -> Result<(), ProviderError> {
        match self {
            Self::Memory(p) => p.revoke(key_id, generation, purpose),
            Self::Canonical(p) => p.revoke(key_id, generation, purpose),
        }
    }
}

impl PublicKeyProvider for ProviderBackend {
    fn resolve(
        &self,
        key_id: u32,
        generation: u32,
        purpose: KeyPurpose,
    ) -> Result<KeyRecord, ProviderError> {
        match self {
            Self::Memory(p) => p.resolve(key_id, generation, purpose),
            Self::Canonical(p) => p.resolve(key_id, generation, purpose),
        }
    }

    fn current(&self, key_id: u32, purpose: KeyPurpose) -> Result<KeyRecord, ProviderError> {
        match self {
            Self::Memory(p) => p.current(key_id, purpose),
            Self::Canonical(p) => p.current(key_id, purpose),
        }
    }

    fn authorize(
        &self,
        key_id: u32,
        generation: u32,
        purpose: KeyPurpose,
        epoch: u64,
        policy: CryptoPolicy,
    ) -> Result<KeyRecord, ProviderError> {
        match self {
            Self::Memory(p) => p.authorize(key_id, generation, purpose, epoch, policy),
            Self::Canonical(p) => p.authorize(key_id, generation, purpose, epoch, policy),
        }
    }
}

fn provider(c: &C) -> ProviderBackend {
    ProviderBackend::seed(c).unwrap_or_else(|e| panic!("provider seed rejected: {e:?}"))
}
fn bind(record: &KeyRecord) -> CredentialBinding {
    CredentialBinding::from_key(99, 5, record, &[8, 9])
}
fn pol() -> BindingPolicy {
    BindingPolicy {
        max_validity: 200,
        pq_required_after: Some(50),
    }
}
fn cpol() -> CryptoPolicy {
    CryptoPolicy {
        min_class: SecurityClass::Pq,
        pq_lock_epoch: Some(50),
    }
}

fn validate_profile_range(min_version: u16, max_version: u16) -> Result<(), &'static str> {
    if min_version < PROFILE_VERSION_C2
        || max_version > PROFILE_VERSION_C3
        || min_version > max_version
    {
        return Err("InvalidLocalProfileRange");
    }
    Ok(())
}

fn validate_profile_cli_values(args: &[String]) -> Result<(), &'static str> {
    for option in ["--profile-min-version", "--profile-max-version"] {
        if let Some(index) = args.iter().position(|arg| arg == option) {
            let raw = args.get(index + 1).ok_or("InvalidProfileVersionValue")?;
            raw.parse::<u16>()
                .map_err(|_| "InvalidProfileVersionValue")?;
        }
    }
    Ok(())
}

fn validate_local_profile_config(c: &C, args: &[String]) -> Result<(), &'static str> {
    let profile_config_was_supplied = c.profile_negotiation
        || args.iter().any(|arg| {
            matches!(
                arg.as_str(),
                "--profile-min-version" | "--profile-max-version" | "--correlated-v2"
            )
        });
    if !profile_config_was_supplied {
        return Ok(());
    }
    validate_profile_cli_values(args)?;
    validate_profile_range(c.profile_min_version, c.profile_max_version)
}

fn build(init: bool) -> snow::HandshakeState {
    let b = Builder::new(PATTERN.parse().unwrap())
        .prologue(PROLOGUE)
        .psk(0, &PSK);
    if init {
        b.build_initiator().unwrap()
    } else {
        b.build_responder().unwrap()
    }
}
fn full(s: &mut TcpStream, b: &mut [u8]) -> io::Result<()> {
    let d = Instant::now() + Duration::from_millis(IO_MS);
    let mut p = 0;
    while p < b.len() {
        if Instant::now() >= d {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "budget"));
        }
        match s.read(&mut b[p..]) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "closed")),
            Ok(n) => p += n,
            Err(e)
                if e.kind() == io::ErrorKind::TimedOut || e.kind() == io::ErrorKind::WouldBlock =>
            {
                thread::sleep(Duration::from_millis(1))
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
fn wb(s: &mut TcpStream, b: &[u8]) -> io::Result<()> {
    if b.len() > MAX_HANDSHAKE {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "oversize"));
    }
    s.write_all(&(b.len() as u16).to_be_bytes())?;
    s.write_all(b)
}
fn rb(s: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut h = [0u8; 2];
    full(s, &mut h)?;
    let n = u16::from_be_bytes(h) as usize;
    if n > MAX_HANDSHAKE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "oversize"));
    }
    let mut b = vec![0u8; n];
    full(s, &mut b)?;
    Ok(b)
}
fn wr(s: &mut TcpStream, b: &[u8]) -> io::Result<()> {
    if b.len() > MAX_NOISE {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "oversize"));
    }
    s.write_all(&(b.len() as u32).to_be_bytes())?;
    s.write_all(b)
}
fn rr(s: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut h = [0u8; 4];
    full(s, &mut h)?;
    let n = u32::from_be_bytes(h) as usize;
    if n > MAX_NOISE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "oversize"));
    }
    let mut b = vec![0u8; n];
    full(s, &mut b)?;
    Ok(b)
}

fn full_until(s: &mut TcpStream, b: &mut [u8], deadline: Instant) -> io::Result<()> {
    let mut p = 0usize;
    while p < b.len() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "deadline"));
        }
        // Poll in bounded slices, but never let one blocking read overrun the
        // absolute deadline by the normal per-I/O timeout.
        s.set_read_timeout(Some(
            remaining.min(Duration::from_millis(BATCH_READ_SLICE_MS)),
        ))?;
        match s.read(&mut b[p..]) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "closed")),
            Ok(n) => p += n,
            Err(e)
                if e.kind() == io::ErrorKind::TimedOut || e.kind() == io::ErrorKind::WouldBlock =>
            {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "deadline"));
                }
                thread::sleep(Duration::from_millis(1));
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn rb_until(s: &mut TcpStream, deadline: Instant) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 2];
    full_until(s, &mut header, deadline)?;
    let len = u16::from_be_bytes(header) as usize;
    if len > MAX_HANDSHAKE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "oversize"));
    }
    let mut message = vec![0u8; len];
    full_until(s, &mut message, deadline)?;
    Ok(message)
}

fn hs_responder_until(
    stream: &mut TcpStream,
    deadline: Instant,
) -> Result<(snow::TransportState, Vec<u8>), String> {
    let mut handshake = build(false);
    let message = rb_until(stream, deadline).map_err(|error| {
        if error.kind() == io::ErrorKind::TimedOut {
            "HandshakeDeadlineExceeded".to_string()
        } else {
            error.to_string()
        }
    })?;
    let mut buffer = [0u8; MAX_HANDSHAKE];
    handshake
        .read_message(&message, &mut buffer)
        .map_err(|error| error.to_string())?;
    let written = handshake
        .write_message(&[], &mut buffer)
        .map_err(|error| error.to_string())?;
    wb(stream, &buffer[..written]).map_err(|error| error.to_string())?;
    let hash = handshake.get_handshake_hash().to_vec();
    Ok((
        handshake
            .into_transport_mode()
            .map_err(|error| error.to_string())?,
        hash,
    ))
}

fn rr_until(s: &mut TcpStream, deadline: Instant) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 4];
    full_until(s, &mut header, deadline)?;
    let len = u32::from_be_bytes(header) as usize;
    if len > MAX_NOISE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "oversize"));
    }
    let mut record = vec![0u8; len];
    full_until(s, &mut record, deadline)?;
    Ok(record)
}

const TRACKED_REQUEST_TIMEOUT_MS: u64 = 800;

fn send_correlated_frame(
    stream: &mut TcpStream,
    transport: &mut snow::TransportState,
    context: &[u8; IDENTITY_CONTEXT_LEN],
    message_type: u16,
    request_id: u64,
    payload: &[u8],
) -> io::Result<()> {
    let frame = encode_frame(WIRE_VERSION, message_type, request_id, payload)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e:?}")))?;
    let mut app = Vec::with_capacity(1 + IDENTITY_CONTEXT_LEN + frame.len());
    app.push(IDENTITY_CORRELATED_RESPONSE_MARKER);
    app.extend_from_slice(context);
    app.extend_from_slice(&frame);
    let mut ciphertext = vec![0u8; app.len() + 64];
    let n = transport
        .write_message(&app, &mut ciphertext)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    wr(stream, &ciphertext[..n])
}

fn send_correlated_error(
    stream: &mut TcpStream,
    transport: &mut snow::TransportState,
    context: &[u8; IDENTITY_CONTEXT_LEN],
    request_id: u64,
    code: ErrorCode,
    offending_type: u16,
) -> io::Result<()> {
    let payload = encode_error(code, offending_type)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e:?}")))?;
    send_correlated_frame(stream, transport, context, ERROR_TYPE, request_id, &payload)
}

fn hs(s: &mut TcpStream, init: bool) -> Result<(snow::TransportState, Vec<u8>), String> {
    let mut h = build(init);
    let mut b = [0u8; MAX_HANDSHAKE];
    if init {
        let n = h.write_message(&[], &mut b).map_err(|e| e.to_string())?;
        wb(s, &b[..n]).map_err(|e| e.to_string())?;
        let m = rb(s).map_err(|e| e.to_string())?;
        h.read_message(&m, &mut b).map_err(|e| e.to_string())?;
    } else {
        let m = rb(s).map_err(|e| e.to_string())?;
        h.read_message(&m, &mut b).map_err(|e| e.to_string())?;
        let n = h.write_message(&[], &mut b).map_err(|e| e.to_string())?;
        wb(s, &b[..n]).map_err(|e| e.to_string())?
    }
    let hash = h.get_handshake_hash().to_vec();
    Ok((h.into_transport_mode().map_err(|e| e.to_string())?, hash))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProfileOffer {
    min_version: u16,
    max_version: u16,
    features: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProfileSelection {
    version: u16,
    features: u32,
}

fn expected_profile_features(version: u16) -> Option<u32> {
    match version {
        PROFILE_VERSION_C2 => Some(0),
        PROFILE_VERSION_C3 => Some(PROFILE_CORRELATION_FEATURE),
        _ => None,
    }
}

fn encode_profile_offer(offer: ProfileOffer) -> Result<Vec<u8>, &'static str> {
    if offer.min_version < PROFILE_VERSION_C2
        || offer.max_version > PROFILE_VERSION_C3
        || offer.min_version > offer.max_version
    {
        return Err("InvalidVersionRange");
    }
    if offer.features & !PROFILE_CORRELATION_FEATURE != 0 {
        return Err("UnknownFeatureBits");
    }
    if offer.max_version < PROFILE_VERSION_C3 && offer.features & PROFILE_CORRELATION_FEATURE != 0 {
        return Err("FeatureOutsideProfileRange");
    }
    if offer.max_version >= PROFILE_VERSION_C3 && offer.features & PROFILE_CORRELATION_FEATURE == 0
    {
        return Err("C3RequiresCorrelationFeature");
    }
    let mut payload = Vec::with_capacity(PROFILE_NEGOTIATE_PAYLOAD_LEN);
    payload.extend_from_slice(&offer.min_version.to_be_bytes());
    payload.extend_from_slice(&offer.max_version.to_be_bytes());
    payload.extend_from_slice(&offer.features.to_be_bytes());
    Ok(payload)
}

fn decode_profile_offer(payload: &[u8]) -> Result<ProfileOffer, &'static str> {
    if payload.len() != PROFILE_NEGOTIATE_PAYLOAD_LEN {
        return Err("InvalidOfferLength");
    }
    let offer = ProfileOffer {
        min_version: u16::from_be_bytes([payload[0], payload[1]]),
        max_version: u16::from_be_bytes([payload[2], payload[3]]),
        features: u32::from_be_bytes(payload[4..8].try_into().map_err(|_| "InvalidOfferLength")?),
    };
    // Reuse the canonical encoder's validation for decoded untrusted fields.
    encode_profile_offer(offer)?;
    Ok(offer)
}

fn encode_profile_selection(selection: ProfileSelection) -> Result<Vec<u8>, &'static str> {
    if expected_profile_features(selection.version) != Some(selection.features) {
        return Err("InvalidSelectedVersionOrFeatures");
    }
    let mut payload = Vec::with_capacity(PROFILE_SELECTED_PAYLOAD_LEN);
    payload.extend_from_slice(&selection.version.to_be_bytes());
    payload.extend_from_slice(&selection.features.to_be_bytes());
    Ok(payload)
}

fn decode_profile_selection(payload: &[u8]) -> Result<ProfileSelection, &'static str> {
    if payload.len() != PROFILE_SELECTED_PAYLOAD_LEN {
        return Err("InvalidSelectionLength");
    }
    let selection = ProfileSelection {
        version: u16::from_be_bytes([payload[0], payload[1]]),
        features: u32::from_be_bytes(
            payload[2..6]
                .try_into()
                .map_err(|_| "InvalidSelectionLength")?,
        ),
    };
    encode_profile_selection(selection)?;
    Ok(selection)
}

fn select_profile(
    offer: ProfileOffer,
    server_min_version: u16,
    server_max_version: u16,
) -> Result<ProfileSelection, &'static str> {
    // Validate both peer-controlled offer and the explicit local supported range.
    decode_profile_offer(&encode_profile_offer(offer)?)?;
    if server_min_version < PROFILE_VERSION_C2
        || server_max_version > PROFILE_VERSION_C3
        || server_min_version > server_max_version
    {
        return Err("InvalidServerProfileRange");
    }
    let highest_common = offer.max_version.min(server_max_version);
    if highest_common >= PROFILE_VERSION_C3
        && offer.min_version <= PROFILE_VERSION_C3
        && server_min_version <= PROFILE_VERSION_C3
        && offer.features & PROFILE_CORRELATION_FEATURE != 0
    {
        return Ok(ProfileSelection {
            version: PROFILE_VERSION_C3,
            features: PROFILE_CORRELATION_FEATURE,
        });
    }
    if offer.min_version <= PROFILE_VERSION_C2
        && offer.max_version >= PROFILE_VERSION_C2
        && server_min_version <= PROFILE_VERSION_C2
        && server_max_version >= PROFILE_VERSION_C2
    {
        return Ok(ProfileSelection {
            version: PROFILE_VERSION_C2,
            features: 0,
        });
    }
    Err("NoCommonProfile")
}

fn validate_profile_selection(
    offer: ProfileOffer,
    selection: ProfileSelection,
) -> Result<(), &'static str> {
    encode_profile_offer(offer)?;
    encode_profile_selection(selection)?;
    if selection.version < offer.min_version || selection.version > offer.max_version {
        return Err("ProfileDowngradeRejected");
    }
    if selection.features & !offer.features != 0 {
        return Err("UnrequestedProfileFeature");
    }
    if selection.version == PROFILE_VERSION_C3
        && selection.features & PROFILE_CORRELATION_FEATURE == 0
    {
        return Err("C3CorrelationFeatureMissing");
    }
    Ok(())
}

fn profile_envelope(
    marker: u8,
    context: &[u8; IDENTITY_CONTEXT_LEN],
    message_type: u16,
    request_id: u64,
    payload: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let frame =
        encode_frame(WIRE_VERSION, message_type, request_id, payload).map_err(|_| "FrameEncode")?;
    let mut app = Vec::with_capacity(1 + IDENTITY_CONTEXT_LEN + frame.len());
    app.push(marker);
    app.extend_from_slice(context);
    app.extend_from_slice(&frame);
    Ok(app)
}

fn decode_profile_envelope<'a>(
    app: &'a [u8],
    expected_marker: u8,
    expected_context: &[u8; IDENTITY_CONTEXT_LEN],
    expected_type: u16,
) -> Result<ai_native_l1_pow_bench::Frame, &'static str> {
    let prefix_len = 1 + IDENTITY_CONTEXT_LEN;
    if app.len() < prefix_len + 20 {
        return Err("ShortProfileEnvelope");
    }
    if app[0] != expected_marker {
        return Err("WrongProfileMarker");
    }
    if app[1..prefix_len] != expected_context[..] {
        return Err("ProfileContextMismatch");
    }
    let frame = decode_frame(&app[prefix_len..]).map_err(|_| "ProfileFrameMalformed")?;
    if frame.message_type != expected_type {
        return Err("WrongProfileMessageType");
    }
    if frame.request_id == 0 {
        return Err("ZeroProfileRequestId");
    }
    Ok(frame)
}

fn server_negotiate_profile(
    stream: &mut TcpStream,
    transport: &mut snow::TransportState,
    context: &[u8; IDENTITY_CONTEXT_LEN],
    server_min_version: u16,
    server_max_version: u16,
    test_fault: &str,
    deadline: Instant,
) -> Result<ProfileSelection, &'static str> {
    let record = rr_until(stream, deadline).map_err(|error| {
        if error.kind() == io::ErrorKind::TimedOut {
            "ProfileOfferDeadlineExceeded"
        } else {
            "ProfileOfferReadFailed"
        }
    })?;
    let mut plain = vec![0u8; MAX_NOISE];
    let n = transport
        .read_message(&record, &mut plain)
        .map_err(|_| "ProfileOfferDecryptFailed")?;
    let frame = decode_profile_envelope(
        &plain[..n],
        PROFILE_NEGOTIATE_MARKER,
        context,
        PROFILE_NEGOTIATE_TYPE,
    )?;
    let offer = decode_profile_offer(&frame.payload)?;
    let selection = select_profile(offer, server_min_version, server_max_version)?;
    let payload = match test_fault {
        "profile_downgrade" => encode_profile_selection(ProfileSelection {
            version: PROFILE_VERSION_C2,
            features: 0,
        })?,
        "profile_unknown_features" => vec![0, PROFILE_VERSION_C3 as u8, 0, 0, 0, 3],
        _ => encode_profile_selection(selection)?,
    };
    let response_request_id = if test_fault == "profile_wrong_id" {
        frame
            .request_id
            .checked_add(1)
            .ok_or("ProfileRequestIdOverflow")?
    } else {
        frame.request_id
    };
    let response = profile_envelope(
        PROFILE_SELECTED_MARKER,
        context,
        PROFILE_SELECTED_TYPE,
        response_request_id,
        &payload,
    )?;
    let mut ciphertext = vec![0u8; response.len() + 64];
    let written = transport
        .write_message(&response, &mut ciphertext)
        .map_err(|_| "ProfileSelectionEncryptFailed")?;
    wr(stream, &ciphertext[..written]).map_err(|_| "ProfileSelectionWriteFailed")?;
    if test_fault == "profile_replay" {
        // Deliberately re-send the same authenticated ciphertext record. A
        // Noise receiver must reject reuse of the already-consumed nonce.
        wr(stream, &ciphertext[..written]).map_err(|_| "ProfileReplayWriteFailed")?;
        eprintln!("event=profile_selection_test_fault fault=profile_replay");
    } else if test_fault.starts_with("profile_") {
        eprintln!("event=profile_selection_test_fault fault={test_fault}");
    }
    Ok(selection)
}

fn client_negotiate_profile(
    stream: &mut TcpStream,
    transport: &mut snow::TransportState,
    context: &[u8; IDENTITY_CONTEXT_LEN],
    offer: ProfileOffer,
) -> Result<ProfileSelection, &'static str> {
    let payload = encode_profile_offer(offer)?;
    let request_id = 1u64;
    let request = profile_envelope(
        PROFILE_NEGOTIATE_MARKER,
        context,
        PROFILE_NEGOTIATE_TYPE,
        request_id,
        &payload,
    )?;
    let mut ciphertext = vec![0u8; request.len() + 64];
    let written = transport
        .write_message(&request, &mut ciphertext)
        .map_err(|_| "ProfileOfferEncryptFailed")?;
    wr(stream, &ciphertext[..written]).map_err(|_| "ProfileOfferWriteFailed")?;

    let record = rr(stream).map_err(|_| "ProfileSelectionReadFailed")?;
    let mut plain = vec![0u8; MAX_NOISE];
    let n = transport
        .read_message(&record, &mut plain)
        .map_err(|_| "ProfileSelectionDecryptFailed")?;
    let frame = decode_profile_envelope(
        &plain[..n],
        PROFILE_SELECTED_MARKER,
        context,
        PROFILE_SELECTED_TYPE,
    )?;
    if frame.request_id != request_id {
        return Err("ProfileSelectionRequestIdMismatch");
    }
    let selection = decode_profile_selection(&frame.payload)?;
    validate_profile_selection(offer, selection)?;
    Ok(selection)
}

fn headers() -> Vec<Header> {
    vec![
        Header {
            id: 0,
            prev: None,
            work: 1,
            claimed_valid: true,
        },
        Header {
            id: 1,
            prev: Some(0),
            work: 5,
            claimed_valid: true,
        },
        Header {
            id: 2,
            prev: Some(1),
            work: 5,
            claimed_valid: true,
        },
        Header {
            id: 3,
            prev: Some(2),
            work: 5,
            claimed_valid: true,
        },
    ]
}
fn enc(h: &[Header]) -> Vec<u8> {
    let mut p = Vec::with_capacity(2 + h.len() * CHAIN_HEADER_WIRE_LEN);
    p.extend_from_slice(&(h.len() as u16).to_be_bytes());
    for x in h {
        p.extend_from_slice(&x.id.to_be_bytes());
        p.extend_from_slice(&x.prev.unwrap_or(u64::MAX).to_be_bytes());
        p.extend_from_slice(&x.work.to_be_bytes());
        p.push(u8::from(x.claimed_valid));
    }
    p
}
fn dec(p: &[u8]) -> Option<Vec<Header>> {
    if p.len() < 2 {
        return None;
    }
    let n = u16::from_be_bytes([p[0], p[1]]) as usize;
    if n > MAX_HEADERS_TESTNET || p.len() != 2 + n * CHAIN_HEADER_WIRE_LEN {
        return None;
    }
    let mut o = Vec::with_capacity(n);
    for i in 0..n {
        let z = 2 + i * CHAIN_HEADER_WIRE_LEN;
        let id = u64::from_be_bytes(p[z..z + 8].try_into().ok()?);
        let q = u64::from_be_bytes(p[z + 8..z + 16].try_into().ok()?);
        let w = u64::from_be_bytes(p[z + 16..z + 24].try_into().ok()?);
        if p[z + 24] > 1 {
            return None;
        }
        o.push(Header {
            id,
            prev: if q == u64::MAX { None } else { Some(q) },
            work: w,
            claimed_valid: p[z + 24] == 1,
        });
    }
    Some(o)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CorrelatedResponse {
    message_type: u16,
    request_id: u64,
    payload: Vec<u8>,
}

fn decode_correlated_response(
    app: &[u8],
    expected_context: &[u8; IDENTITY_CONTEXT_LEN],
) -> Result<CorrelatedResponse, &'static str> {
    let prefix_len = 1 + IDENTITY_CONTEXT_LEN;
    if app.len() < prefix_len + 20 {
        return Err("short envelope");
    }
    if app[0] != IDENTITY_CORRELATED_RESPONSE_MARKER {
        return Err("wrong response marker");
    }
    if app[1..prefix_len] != expected_context[..] {
        return Err("session context mismatch");
    }
    let frame = decode_frame(&app[prefix_len..]).map_err(|_| "bad inner AIN1 frame")?;
    match frame.message_type {
        HEADERS_TYPE => {
            if frame.request_id == 0 {
                return Err("zero HEADERS request ID");
            }
            // Schema validation follows RequestTracker's type/deadline/size
            // checks so an oversized reply is classified and closed first.
        }
        ERROR_TYPE => {
            let (code, _) = decode_error(&frame.payload).map_err(|_| "malformed ERROR payload")?;
            if frame.request_id == 0 && code != ErrorCode::BadRequest {
                return Err("zero ERROR request ID requires BadRequest");
            }
        }
        // Other framed types remain parseable so RequestTracker can enforce
        // the per-request expected-response type without losing correlation.
        _ => {}
    }
    Ok(CorrelatedResponse {
        message_type: frame.message_type,
        request_id: frame.request_id,
        payload: frame.payload,
    })
}

fn server_correlated_batch(
    stream: &mut TcpStream,
    transport: &mut snow::TransportState,
    context: &[u8; IDENTITY_CONTEXT_LEN],
    mut process_budget: Option<&mut ProcessSessionGuard>,
    hold_after_reserve_ms: u64,
    count: u32,
) {
    if !(2..=MAX_REQUESTS_PER_PEER_TESTNET as u32).contains(&count) {
        eprintln!(
            "event=identity_batch_budget_rejected reason=RequestLimit count={count} limit={MAX_REQUESTS_PER_PEER_TESTNET}"
        );
        return;
    }
    let Some(reserved_bytes) = (count as usize).checked_mul(MAX_HEADERS_PAYLOAD_TESTNET) else {
        eprintln!("event=identity_batch_budget_rejected reason=OutstandingBytesLimit");
        return;
    };
    if reserved_bytes > MAX_OUTSTANDING_REQUEST_BYTES_TESTNET {
        eprintln!(
            "event=identity_batch_budget_rejected reason=OutstandingBytesLimit requested={reserved_bytes} limit={MAX_OUTSTANDING_REQUEST_BYTES_TESTNET}"
        );
        return;
    }
    if let Some(permit) = process_budget.as_deref_mut() {
        if let Err(err) = permit.reserve_bytes(reserved_bytes) {
            eprintln!(
                "event=identity_batch_budget_rejected reason=Process{err:?} requested={reserved_bytes}"
            );
            return;
        }
        eprintln!("event=process_budget_reserved bytes={reserved_bytes}");
    }
    if hold_after_reserve_ms > 0 {
        thread::sleep(Duration::from_millis(hold_after_reserve_ms));
    }
    if let Err(err) = stream.set_read_timeout(Some(Duration::from_millis(BATCH_READ_SLICE_MS))) {
        eprintln!("event=identity_batch_request_rejected reason=read_timeout_setup:{err}");
        return;
    }
    let batch_deadline = Instant::now() + Duration::from_millis(MAX_BATCH_RECEIVE_WINDOW_MS);

    let mut ids = Vec::with_capacity(count as usize);
    let mut seen = BTreeSet::new();
    let mut plain = vec![0u8; MAX_NOISE];
    for _ in 0..count {
        let record = match rr_until(stream, batch_deadline) {
            Ok(record) => record,
            Err(err) if err.kind() == io::ErrorKind::TimedOut => {
                eprintln!(
                    "event=identity_batch_request_rejected reason=BatchReadDeadlineExceeded received={} expected={count}",
                    ids.len()
                );
                return;
            }
            Err(err) => {
                eprintln!("event=identity_batch_request_rejected reason=read:{err}");
                return;
            }
        };
        let n = match transport.read_message(&record, &mut plain) {
            Ok(n) => n,
            Err(err) => {
                eprintln!("event=identity_batch_request_rejected reason=decrypt:{err}");
                return;
            }
        };
        if n < 1 + IDENTITY_CONTEXT_LEN || plain[0] != IDENTITY_REQUEST_MARKER {
            eprintln!("event=identity_batch_request_rejected reason=envelope");
            return;
        }
        if &plain[1..1 + IDENTITY_CONTEXT_LEN] != context {
            eprintln!("event=identity_batch_request_rejected reason=context_mismatch");
            return;
        }
        let frame = match decode_frame(&plain[1 + IDENTITY_CONTEXT_LEN..n]) {
            Ok(frame) => frame,
            Err(err) => {
                eprintln!("event=identity_batch_request_rejected reason=frame:{err:?}");
                return;
            }
        };
        if frame.request_id == 0
            || frame.message_type != GET_HEADERS_TYPE
            || !frame.payload.is_empty()
        {
            eprintln!(
                "event=identity_batch_request_rejected reason=invalid_request request_id={} type={} payload_len={}",
                frame.request_id, frame.message_type, frame.payload.len()
            );
            return;
        }
        if !seen.insert(frame.request_id) {
            eprintln!(
                "event=identity_batch_request_rejected reason=DuplicateRequest request_id={}",
                frame.request_id
            );
            return;
        }
        ids.push(frame.request_id);
    }

    let payload = enc(&headers());
    for request_id in ids.iter().rev() {
        if send_correlated_frame(
            stream,
            transport,
            context,
            HEADERS_TYPE,
            *request_id,
            &payload,
        )
        .is_err()
        {
            eprintln!("event=identity_batch_response_rejected request_id={request_id}");
            return;
        }
    }
    eprintln!(
        "event=identity_sync_batch_ok requests={} response_order=reverse reserved_bytes={reserved_bytes}",
        ids.len()
    );
}

fn client_correlated_batch(
    stream: &mut TcpStream,
    transport: &mut snow::TransportState,
    context: &[u8; IDENTITY_CONTEXT_LEN],
    count: u32,
) -> bool {
    if count < 2 {
        eprintln!("event=identity_batch_open_rejected reason=InvalidCount count={count}");
        return false;
    }

    let mut tracker = RequestTracker::new();
    let clock = Instant::now();
    for request_id in 1..=count as u64 {
        if let Err(err) = tracker.open(
            request_id,
            HEADERS_TYPE,
            TRACKED_REQUEST_TIMEOUT_MS,
            MAX_HEADERS_PAYLOAD_TESTNET,
        ) {
            eprintln!(
                "event=identity_batch_open_rejected reason={err:?} request_id={request_id} outstanding={} reserved_bytes={}",
                tracker.len(),
                tracker.outstanding_bytes()
            );
            return false;
        }
    }
    eprintln!(
        "event=identity_batch_open count={} reserved_bytes={}",
        tracker.len(),
        tracker.outstanding_bytes()
    );

    for request_id in 1..=count as u64 {
        let frame = match encode_frame(WIRE_VERSION, GET_HEADERS_TYPE, request_id, &[]) {
            Ok(frame) => frame,
            Err(err) => {
                eprintln!("event=identity_batch_send_rejected reason=encode:{err:?}");
                return false;
            }
        };
        let mut app = Vec::with_capacity(1 + IDENTITY_CONTEXT_LEN + frame.len());
        app.push(IDENTITY_REQUEST_MARKER);
        app.extend_from_slice(context);
        app.extend_from_slice(&frame);
        let mut ciphertext = vec![0u8; app.len() + 64];
        let n = match transport.write_message(&app, &mut ciphertext) {
            Ok(n) => n,
            Err(err) => {
                eprintln!("event=identity_batch_send_rejected reason=encrypt:{err}");
                return false;
            }
        };
        if let Err(err) = wr(stream, &ciphertext[..n]) {
            eprintln!("event=identity_batch_send_rejected reason=write:{err}");
            return false;
        }
    }

    let mut completed = BTreeSet::new();
    let mut completion_order = Vec::with_capacity(count as usize);
    let mut plain = vec![0u8; MAX_NOISE];
    for _ in 0..count {
        let record = match rr(stream) {
            Ok(record) => record,
            Err(err) => {
                let expired = tracker.expire(clock.elapsed().as_millis() as u64);
                if expired > 0 {
                    eprintln!(
                        "event=identity_batch_timeout expired={expired} outstanding={}",
                        tracker.len()
                    );
                } else {
                    eprintln!("event=identity_batch_receive_rejected reason=read:{err}");
                }
                return false;
            }
        };
        let n = match transport.read_message(&record, &mut plain) {
            Ok(n) => n,
            Err(err) => {
                eprintln!("event=identity_batch_receive_rejected reason=decrypt:{err}");
                return false;
            }
        };
        let response = match decode_correlated_response(&plain[..n], context) {
            Ok(response) => response,
            Err(reason) => {
                eprintln!("event=identity_batch_receive_rejected reason={reason}");
                return false;
            }
        };
        let now_ms = clock.elapsed().as_millis() as u64;
        if response.message_type == ERROR_TYPE {
            match tracker.complete_error(response.request_id, response.payload.len(), now_ms) {
                Ok(_) => match decode_error(&response.payload) {
                    Ok((code, offending_type)) => eprintln!(
                        "event=identity_batch_error_handled code={code:?} offending_type={offending_type} request_id={}",
                        response.request_id
                    ),
                    Err(err) => eprintln!("event=identity_batch_error_rejected reason={err:?}"),
                },
                Err(err) => eprintln!("event=identity_batch_error_rejected reason={err:?}"),
            }
            return false;
        }
        if let Err(err) = tracker.complete(
            response.request_id,
            response.message_type,
            response.payload.len(),
            now_ms,
        ) {
            eprintln!(
                "event=identity_batch_response_rejected reason={err:?} request_id={}",
                response.request_id
            );
            return false;
        }
        if !completed.insert(response.request_id) {
            eprintln!("event=identity_batch_response_rejected reason=duplicate_response");
            return false;
        }
        completion_order.push(response.request_id);
        let Some(records) = dec(&response.payload) else {
            eprintln!("event=identity_batch_response_rejected reason=headers");
            return false;
        };
        if !client_a_best(&records, &[records.last().map(|x| x.id).unwrap_or(0)])
            .is_some_and(|x| x.tip == 3 && x.total_work == 16)
        {
            eprintln!("event=identity_batch_response_rejected reason=fork_choice");
            return false;
        }
    }

    if tracker.len() != 0 || tracker.outstanding_bytes() != 0 || completed.len() != count as usize {
        eprintln!(
            "event=identity_batch_incomplete outstanding={} reserved_bytes={} completed={}",
            tracker.len(),
            tracker.outstanding_bytes(),
            completed.len()
        );
        return false;
    }
    if completion_order.first().copied() != Some(count as u64)
        || completion_order.last().copied() != Some(1)
    {
        eprintln!("event=identity_batch_response_rejected reason=unexpected_order order={completion_order:?}");
        return false;
    }
    eprintln!(
        "event=identity_sync_batch_client_ok requests={} completion_order={:?} reserved_bytes=0",
        completed.len(),
        completion_order
    );
    true
}

fn server(
    mut s: TcpStream,
    mut c: C,
    provider: &mut ProviderBackend,
    process_budget: Option<&mut ProcessSessionGuard>,
) {
    let negotiation_deadline =
        Instant::now() + Duration::from_millis(SESSION_ESTABLISHMENT_DEADLINE_MS);
    if let Err(err) = s
        .set_read_timeout(Some(Duration::from_millis(IO_MS)))
        .and_then(|_| s.set_write_timeout(Some(Duration::from_millis(IO_MS))))
    {
        eprintln!("event=identity_session_io_setup_rejected reason={err}");
        return;
    }
    let record = match provider.current(7, KeyPurpose::PeerAuth) {
        Ok(x) => x,
        Err(_) => {
            eprintln!("event=provider_current_rejected");
            return;
        }
    };
    let b = bind(&record);
    if b.validate(&record, 20, pol(), &[8, 9]).is_err() {
        eprintln!("event=binding_rejected");
        return;
    }
    let handshake = if c.profile_negotiation {
        hs_responder_until(&mut s, negotiation_deadline)
    } else {
        hs(&mut s, false)
    };
    let (mut t, hash) = match handshake {
        Ok(x) => x,
        Err(e) => {
            eprintln!("event=noise_handshake_rejected reason={e}");
            return;
        }
    };
    let expected = session_identity_context(&b, &hash);
    let mut session = match BoundSession::bind(&record, expected) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("event=session_bind_rejected reason={e:?}");
            return;
        }
    };
    if c.profile_negotiation {
        match server_negotiate_profile(
            &mut s,
            &mut t,
            &expected,
            c.profile_min_version,
            c.profile_max_version,
            &c.test_response_fault,
            negotiation_deadline,
        ) {
            Ok(selection) => {
                c.correlated_v2 = selection.version == PROFILE_VERSION_C3;
                eprintln!(
                    "event=profile_selected version={} features={}",
                    selection.version, selection.features
                );
            }
            Err(reason) => {
                eprintln!("event=profile_negotiation_rejected reason={reason}");
                return;
            }
        }
    }
    if let Err(err) = s
        .set_read_timeout(Some(Duration::from_millis(IO_MS)))
        .and_then(|_| s.set_write_timeout(Some(Duration::from_millis(IO_MS))))
    {
        eprintln!("event=identity_session_io_reset_rejected reason={err}");
        return;
    }
    if c.rotate_before_request || c.rotate_then_revoke || c.rotate_after_profile_negotiate {
        let mut next = record.clone();
        next.generation += 1;
        match provider.provision_rotation(&record, next, cpol()) {
            Ok(()) => eprintln!(
                "event=provider_rotated generation={}",
                record.generation + 1
            ),
            Err(e) => {
                eprintln!("event=provider_rotation_rejected reason={e:?}");
                return;
            }
        }
        if c.rotate_then_revoke {
            match provider.revoke(record.key_id, record.generation + 1, record.purpose) {
                Ok(()) => eprintln!(
                    "event=provider_revoked generation={}",
                    record.generation + 1
                ),
                Err(e) => {
                    eprintln!("event=provider_revoke_rejected reason={e:?}");
                    return;
                }
            }
        }
    }
    if c.revoke_before_request && !c.rotate_then_revoke {
        match provider.revoke(record.key_id, record.generation, record.purpose) {
            Ok(()) => eprintln!("event=provider_revoked generation={}", record.generation),
            Err(e) => {
                eprintln!("event=provider_revoke_rejected reason={e:?}");
                return;
            }
        }
    }
    match session.revalidate(provider, 20, cpol()) {
        Ok(()) => {}
        Err(SessionError::RefreshRequired { current_generation }) => {
            eprintln!("event=session_refresh_required current_generation={current_generation}");
            return;
        }
        Err(SessionError::Revoked) => {
            eprintln!("event=session_revoked");
            return;
        }
        Err(e) => {
            eprintln!("event=session_revalidation_rejected reason={e:?}");
            return;
        }
    }
    if c.multi_request_count > 0 {
        if !c.correlated_v2 {
            eprintln!("event=identity_batch_rejected reason=requires_correlated_v2");
            return;
        }
        server_correlated_batch(
            &mut s,
            &mut t,
            &expected,
            process_budget,
            c.test_batch_hold_after_reserve_ms,
            c.multi_request_count,
        );
        return;
    }
    let rec = match rr(&mut s) {
        Ok(x) => x,
        Err(_) => return,
    };
    let mut plain = vec![0u8; MAX_NOISE];
    let n = match t.read_message(&rec, &mut plain) {
        Ok(x) => x,
        Err(_) => {
            eprintln!("event=identity_context_rejected reason=decrypt");
            return;
        }
    };
    if n < 1 + IDENTITY_CONTEXT_LEN || plain[0] != IDENTITY_REQUEST_MARKER {
        eprintln!("event=identity_context_rejected reason=format");
        return;
    }
    if !session.context_matches(&plain[1..1 + IDENTITY_CONTEXT_LEN]) {
        eprintln!("event=identity_context_rejected reason=context_mismatch");
        return;
    }
    let frame = match decode_frame(&plain[1 + IDENTITY_CONTEXT_LEN..n]) {
        Ok(x) => x,
        Err(_) => {
            eprintln!("event=identity_context_rejected reason=frame");
            return;
        }
    };
    if c.correlated_v2 && frame.request_id == 0 {
        let sent = if frame.message_type == 0 {
            false
        } else {
            send_correlated_error(
                &mut s,
                &mut t,
                &expected,
                frame.request_id,
                ErrorCode::BadRequest,
                frame.message_type,
            )
            .is_ok()
        };
        eprintln!(
            "event=identity_request_rejected reason=zero_request_id offending_type={} error_sent={sent}",
            frame.message_type
        );
        return;
    }
    if frame.message_type != GET_HEADERS_TYPE {
        if c.correlated_v2 && frame.message_type != 0 {
            if send_correlated_error(
                &mut s,
                &mut t,
                &expected,
                frame.request_id,
                ErrorCode::UnsupportedType,
                frame.message_type,
            )
            .is_ok()
            {
                eprintln!(
                    "event=identity_request_rejected reason=unsupported_type request_id={} type={}",
                    frame.request_id, frame.message_type
                );
            }
        } else {
            eprintln!("event=identity_context_rejected reason=message");
        }
        return;
    }
    if !frame.payload.is_empty() {
        if c.correlated_v2 {
            if send_correlated_error(
                &mut s,
                &mut t,
                &expected,
                frame.request_id,
                ErrorCode::InvalidPayload,
                GET_HEADERS_TYPE,
            )
            .is_ok()
            {
                eprintln!(
                    "event=identity_request_rejected reason=payload request_id={}",
                    frame.request_id
                );
            }
        } else {
            eprintln!("event=identity_context_rejected reason=payload");
        }
        return;
    }
    let headers_payload = enc(&headers());
    if c.correlated_v2 {
        match c.test_response_fault.as_str() {
            "wrong_id" => {
                if let Some(wrong_id) = frame.request_id.checked_add(1) {
                    let _ = send_correlated_frame(
                        &mut s,
                        &mut t,
                        &expected,
                        HEADERS_TYPE,
                        wrong_id,
                        &headers_payload,
                    );
                    eprintln!("event=identity_sync_test_fault fault=wrong_id");
                }
                return;
            }
            "wrong_type" => {
                let _ = send_correlated_frame(
                    &mut s,
                    &mut t,
                    &expected,
                    STATUS_TYPE,
                    frame.request_id,
                    &headers_payload,
                );
                eprintln!("event=identity_sync_test_fault fault=wrong_type");
                return;
            }
            "oversized" => {
                let oversized = vec![0u8; MAX_HEADERS_PAYLOAD_TESTNET + 1];
                let _ = send_correlated_frame(
                    &mut s,
                    &mut t,
                    &expected,
                    HEADERS_TYPE,
                    frame.request_id,
                    &oversized,
                );
                eprintln!("event=identity_sync_test_fault fault=oversized");
                return;
            }
            "late" => {
                eprintln!("event=identity_sync_test_fault fault=late");
                thread::sleep(Duration::from_millis(TRACKED_REQUEST_TIMEOUT_MS + 150));
            }
            "timeout" => {
                eprintln!("event=identity_sync_test_fault fault=timeout");
                thread::sleep(Duration::from_millis(TRACKED_REQUEST_TIMEOUT_MS + 150));
                return;
            }
            "partial_write" => {
                let frame = match encode_frame(
                    WIRE_VERSION,
                    HEADERS_TYPE,
                    frame.request_id,
                    &headers_payload,
                ) {
                    Ok(frame) => frame,
                    Err(_) => {
                        eprintln!(
                            "event=identity_response_send_rejected reason=partial_frame_encode"
                        );
                        return;
                    }
                };
                let mut app = Vec::with_capacity(1 + IDENTITY_CONTEXT_LEN + frame.len());
                app.push(IDENTITY_CORRELATED_RESPONSE_MARKER);
                app.extend_from_slice(&expected);
                app.extend_from_slice(&frame);
                let mut ciphertext = vec![0u8; app.len() + 64];
                let encrypted_len = match t.write_message(&app, &mut ciphertext) {
                    Ok(len) => len,
                    Err(_) => {
                        eprintln!("event=identity_response_send_rejected reason=partial_encrypt");
                        return;
                    }
                };
                let partial_len = (encrypted_len / 2).max(1).min(encrypted_len - 1);
                let length_prefix = (encrypted_len as u32).to_be_bytes();
                if s.write_all(&length_prefix).is_err()
                    || s.write_all(&ciphertext[..partial_len]).is_err()
                {
                    eprintln!("event=identity_response_send_rejected reason=partial_write_io");
                    return;
                }
                eprintln!(
                    "event=identity_sync_test_fault fault=partial_write bytes_sent={} encrypted_len={encrypted_len}",
                    partial_len
                );
                return;
            }
            _ => {}
        }
        if send_correlated_frame(
            &mut s,
            &mut t,
            &expected,
            HEADERS_TYPE,
            frame.request_id,
            &headers_payload,
        )
        .is_err()
        {
            eprintln!("event=identity_response_send_rejected");
            return;
        }
        eprintln!(
            "event=identity_sync_ok_correlated request_id={} headers={}",
            frame.request_id,
            headers().len()
        );
    } else {
        let mut app = vec![IDENTITY_RESPONSE_MARKER];
        app.extend_from_slice(&expected);
        app.extend_from_slice(&headers_payload);
        let mut cb = vec![0u8; app.len() + 64];
        let m = match t.write_message(&app, &mut cb) {
            Ok(n) => n,
            Err(_) => {
                eprintln!("event=identity_response_encrypt_rejected");
                return;
            }
        };
        if wr(&mut s, &cb[..m]).is_ok() {
            eprintln!("event=identity_sync_ok");
        }
    }
}

fn client(c: C) -> bool {
    let provider = provider(&c);
    let record = match provider.current(7, KeyPurpose::PeerAuth) {
        Ok(x) => x,
        Err(_) => {
            eprintln!("event=local_provider_current_rejected");
            return false;
        }
    };
    let b = bind(&record);
    if b.validate(&record, 20, pol(), &[8, 9]).is_err() {
        eprintln!("event=local_binding_rejected");
        return false;
    }
    let mut s = match TcpStream::connect(("127.0.0.1", c.peer)) {
        Ok(x) => x,
        Err(_) => {
            eprintln!("event=identity_sync_client_rejected reason=connect");
            return false;
        }
    };
    if let Err(err) = s
        .set_read_timeout(Some(Duration::from_millis(IO_MS)))
        .and_then(|_| s.set_write_timeout(Some(Duration::from_millis(IO_MS))))
    {
        eprintln!("event=identity_sync_client_rejected reason=io_setup:{err}");
        return false;
    }
    let (mut t, hash) = match hs(&mut s, true) {
        Ok(x) => x,
        Err(_) => {
            eprintln!("event=identity_sync_client_rejected reason=handshake");
            return false;
        }
    };
    let expected = session_identity_context(&b, &hash);
    let session = match BoundSession::bind(&record, expected) {
        Ok(x) => x,
        Err(_) => return false,
    };
    let mut correlated_v2 = c.correlated_v2;
    if c.profile_negotiation {
        let offer = ProfileOffer {
            min_version: c.profile_min_version,
            max_version: c.profile_max_version,
            features: if c.profile_max_version >= PROFILE_VERSION_C3 {
                PROFILE_CORRELATION_FEATURE
            } else {
                0
            },
        };
        match client_negotiate_profile(&mut s, &mut t, &expected, offer) {
            Ok(selection) => {
                correlated_v2 = selection.version == PROFILE_VERSION_C3;
                eprintln!(
                    "event=profile_negotiation_ok version={} features={}",
                    selection.version, selection.features
                );
            }
            Err(reason) => {
                eprintln!("event=profile_negotiation_rejected reason={reason}");
                return false;
            }
        }
    }
    if c.multi_request_count > 0 {
        if !correlated_v2 {
            eprintln!("event=identity_batch_rejected reason=requires_correlated_v2");
            return false;
        }
        return client_correlated_batch(&mut s, &mut t, &expected, c.multi_request_count);
    }
    let request_id = 1u64;
    let outgoing_type = if correlated_v2 && c.test_error {
        HEADERS_TYPE
    } else {
        GET_HEADERS_TYPE
    };
    let request_clock = Instant::now();
    let mut tracker = RequestTracker::new();
    if correlated_v2 {
        if let Err(err) = tracker.open(
            request_id,
            HEADERS_TYPE,
            TRACKED_REQUEST_TIMEOUT_MS,
            MAX_HEADERS_PAYLOAD_TESTNET,
        ) {
            eprintln!("event=identity_request_open_rejected reason={err:?}");
            return false;
        }
    }

    let frame = match encode_frame(WIRE_VERSION, outgoing_type, request_id, &[]) {
        Ok(frame) => frame,
        Err(err) => {
            eprintln!("event=identity_sync_client_rejected reason=encode:{err:?}");
            return false;
        }
    };
    let mut app = Vec::with_capacity(1 + IDENTITY_CONTEXT_LEN + frame.len());
    app.push(IDENTITY_REQUEST_MARKER);
    app.extend_from_slice(&expected);
    app.extend_from_slice(&frame);
    let mut cb = vec![0u8; app.len() + 64];
    let n = match t.write_message(&app, &mut cb) {
        Ok(n) => n,
        Err(err) => {
            eprintln!("event=identity_sync_client_rejected reason=encrypt:{err}");
            return false;
        }
    };
    if wr(&mut s, &cb[..n]).is_err() {
        eprintln!("event=identity_sync_client_rejected reason=send");
        return false;
    }

    let rec = match rr(&mut s) {
        Ok(x) => x,
        Err(_) => {
            if correlated_v2 && tracker.expire(request_clock.elapsed().as_millis() as u64) > 0 {
                eprintln!("event=identity_request_timeout request_id={request_id}");
            } else {
                eprintln!("event=identity_sync_client_rejected reason=receive");
            }
            return false;
        }
    };
    let mut plain = vec![0u8; MAX_NOISE];
    let n = match t.read_message(&rec, &mut plain) {
        Ok(x) => x,
        Err(_) => {
            eprintln!("event=identity_sync_client_rejected reason=decrypt");
            return false;
        }
    };
    if n < 1 + IDENTITY_CONTEXT_LEN || !session.context_matches(&plain[1..1 + IDENTITY_CONTEXT_LEN])
    {
        eprintln!("event=identity_sync_client_rejected reason=response_context");
        return false;
    }

    let header_payload = if correlated_v2 {
        let response_frame = match decode_correlated_response(&plain[..n], &expected) {
            Ok(frame) => frame,
            Err(reason) => {
                eprintln!("event=identity_sync_client_rejected reason=response_frame:{reason}");
                return false;
            }
        };
        let now_ms = request_clock.elapsed().as_millis() as u64;
        if response_frame.message_type == ERROR_TYPE {
            if let Err(err) = tracker.complete_error(
                response_frame.request_id,
                response_frame.payload.len(),
                now_ms,
            ) {
                eprintln!("event=identity_request_error_rejected reason={err:?}");
                return false;
            }
            match decode_error(&response_frame.payload) {
                Ok((code, offending_type)) if offending_type == outgoing_type => {
                    eprintln!(
                        "event=identity_request_error_handled code={code:?} offending_type={offending_type} request_id={request_id}"
                    );
                }
                Ok((_, offending_type)) => {
                    eprintln!(
                        "event=identity_request_error_rejected reason=OffendingTypeMismatch actual={offending_type}"
                    );
                }
                Err(err) => {
                    eprintln!("event=identity_request_error_rejected reason={err:?}");
                }
            }
            return false;
        }
        if let Err(err) = tracker.complete(
            response_frame.request_id,
            response_frame.message_type,
            response_frame.payload.len(),
            now_ms,
        ) {
            eprintln!("event=identity_response_rejected reason={err:?}");
            return false;
        }
        response_frame.payload
    } else {
        if plain[0] != IDENTITY_RESPONSE_MARKER {
            eprintln!("event=identity_sync_client_rejected reason=response_marker");
            return false;
        }
        plain[1 + IDENTITY_CONTEXT_LEN..n].to_vec()
    };

    let Some(h) = dec(&header_payload) else {
        eprintln!("event=identity_sync_client_rejected reason=headers");
        return false;
    };
    if client_a_best(&h, &[h.last().map(|x| x.id).unwrap_or(0)])
        .is_some_and(|x| x.tip == 3 && x.total_work == 16)
    {
        if correlated_v2 {
            eprintln!(
                "event=identity_sync_client_correlated_ok request_id={request_id} tip={}",
                h.last().map(|x| x.id).unwrap_or(0)
            );
        }
        true
    } else {
        eprintln!("event=identity_sync_client_rejected reason=fork_choice");
        false
    }
}

fn parallel_server(c: C) {
    if c.worker_count == 0 || c.worker_count > MAX_WORKERS_PROCESS_TESTNET {
        eprintln!(
            "event=identity_sync_server_rejected reason=InvalidWorkerCount count={} limit={MAX_WORKERS_PROCESS_TESTNET}",
            c.worker_count
        );
        return;
    }
    if c.admission_queue_capacity == 0
        || c.admission_queue_capacity > MAX_ADMISSION_QUEUE_CAPACITY_TESTNET
    {
        eprintln!(
            "event=identity_sync_server_rejected reason=InvalidAdmissionQueueCapacity capacity={} limit={MAX_ADMISSION_QUEUE_CAPACITY_TESTNET}",
            c.admission_queue_capacity
        );
        return;
    }
    let listener = match TcpListener::bind(("127.0.0.1", c.listen)) {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("event=identity_sync_server_rejected reason=bind:{err}");
            return;
        }
    };
    if let Err(err) = listener.set_nonblocking(true) {
        eprintln!("event=identity_sync_server_rejected reason=nonblocking:{err}");
        return;
    }

    let budget =
        ProcessResourceBudget::new(c.max_concurrent_sessions, c.max_process_reserved_bytes);
    let (sender, receiver): (SyncSender<(TcpStream, C)>, Receiver<(TcpStream, C)>) =
        sync_channel(c.admission_queue_capacity);
    let shared_receiver = Arc::new(Mutex::new(receiver));
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_cancelled = Arc::new(AtomicUsize::new(0));
    // Serializes "job becomes active" against the shutdown transition.
    let worker_start_gate = Arc::new(Mutex::new(()));
    eprintln!(
        "event=identity_sync_server id={} connections={} parallel=true workers={} queue_capacity={} max_sessions={} max_process_reserved_bytes={}",
        c.id,
        c.connections,
        c.worker_count,
        c.admission_queue_capacity,
        c.max_concurrent_sessions,
        c.max_process_reserved_bytes
    );

    let mut workers = Vec::with_capacity(c.worker_count);
    for worker_id in 0..c.worker_count {
        let worker_receiver = Arc::clone(&shared_receiver);
        let worker_budget = budget.clone();
        let worker_shutdown = Arc::clone(&shutdown);
        let worker_cancelled_count = Arc::clone(&shutdown_cancelled);
        let worker_start_gate = Arc::clone(&worker_start_gate);
        workers.push(thread::spawn(move || loop {
            let received = match worker_receiver.lock() {
                Ok(receiver) => receiver.recv(),
                Err(_) => {
                    eprintln!(
                        "event=worker_rejected reason=queue_lock_poisoned worker={worker_id}"
                    );
                    break;
                }
            };
            let (stream, session_cfg) = match received {
                Ok(job) => job,
                Err(_) => break,
            };

            let admission_guard = match worker_start_gate.lock() {
                Ok(guard) => guard,
                Err(_) => {
                    eprintln!("event=worker_job_cancelled reason=AdmissionGatePoisoned worker={worker_id}");
                    drop(stream);
                    continue;
                }
            };
            if worker_shutdown.load(Ordering::Acquire) {
                worker_cancelled_count.fetch_add(1, Ordering::AcqRel);
                eprintln!("event=worker_job_cancelled reason=ServerShuttingDown worker={worker_id}");
                drop(stream);
                drop(admission_guard);
                continue;
            }
            let mut permit = match worker_budget.acquire_session() {
                Ok(permit) => permit,
                Err(err) => {
                    eprintln!("event=process_budget_rejected reason={err:?} worker={worker_id}");
                    drop(stream);
                    drop(admission_guard);
                    continue;
                }
            };
            eprintln!(
                "event=process_session_admitted worker={worker_id} active_sessions={}",
                worker_budget.active_sessions().unwrap_or(usize::MAX)
            );
            drop(admission_guard);
            if session_cfg.test_session_hold_ms > 0 {
                thread::sleep(Duration::from_millis(session_cfg.test_session_hold_ms));
            }
            let mut peer_provider = match ProviderBackend::seed(&session_cfg) {
                Ok(provider) => provider,
                Err(err) => {
                    eprintln!("event=provider_seed_rejected reason={err:?} worker={worker_id}");
                    continue;
                }
            };
            server(stream, session_cfg, &mut peer_provider, Some(&mut permit));
        }));
    }

    let deadline = Instant::now() + Duration::from_millis(c.duration);
    let mut accepted = 0u32;
    let mut enqueued = 0u32;
    let mut queue_rejected = 0u32;
    while Instant::now() < deadline && accepted < c.connections.max(1) {
        match listener.accept() {
            Ok((stream, _)) => {
                accepted += 1;
                match sender.try_send((stream, c.clone())) {
                    Ok(()) => {
                        enqueued += 1;
                        eprintln!(
                            "event=admission_enqueued accepted={accepted} enqueued={enqueued}"
                        );
                    }
                    Err(TrySendError::Full((stream, _))) => {
                        queue_rejected += 1;
                        eprintln!(
                            "event=admission_queue_rejected reason=QueueFull accepted={accepted} enqueued={enqueued} rejected={queue_rejected}"
                        );
                        drop(stream);
                    }
                    Err(TrySendError::Disconnected((stream, _))) => {
                        queue_rejected += 1;
                        eprintln!(
                            "event=admission_queue_rejected reason=WorkersDisconnected accepted={accepted} enqueued={enqueued} rejected={queue_rejected}"
                        );
                        drop(stream);
                    }
                }
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(err) => {
                eprintln!("event=identity_sync_accept_rejected reason={err}");
                break;
            }
        }
    }
    {
        let _admission_guard = match worker_start_gate.lock() {
            Ok(guard) => guard,
            Err(_) => {
                eprintln!("event=server_shutdown_gate_rejected reason=Poisoned");
                return;
            }
        };
        shutdown.store(true, Ordering::Release);
    }
    eprintln!(
        "event=server_shutdown_started accepted={accepted} enqueued={enqueued} queue_rejected={queue_rejected}"
    );
    drop(sender);

    for worker in workers {
        if worker.join().is_err() {
            eprintln!("event=identity_sync_worker_rejected reason=panic");
        }
    }
    eprintln!(
        "event=process_budget_final active_sessions={} reserved_bytes={} accepted={} enqueued={} queue_rejected={} worker_count={} queue_capacity={} shutdown_cancelled={}",
        budget.active_sessions().unwrap_or(usize::MAX),
        budget.reserved_bytes().unwrap_or(usize::MAX),
        accepted,
        enqueued,
        queue_rejected,
        c.worker_count,
        c.admission_queue_capacity,
        shutdown_cancelled.load(Ordering::Acquire)
    );
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let c = cfg();
    if let Err(reason) = validate_local_profile_config(&c, &args) {
        eprintln!(
            "event=local_config_rejected reason={reason} profile_min={} profile_max={}",
            c.profile_min_version, c.profile_max_version
        );
        std::process::exit(2);
    }
    if c.server && c.parallel_server {
        parallel_server(c);
    } else if c.server {
        let mut provider = provider(&c);
        let l = TcpListener::bind(("127.0.0.1", c.listen)).unwrap();
        l.set_nonblocking(true).unwrap();
        // This event is the harness readiness contract: emit it only after the
        // socket is bound and configured, never merely when the process starts.
        eprintln!(
            "event=identity_sync_server id={} connections={}",
            c.id, c.connections
        );
        let d = Instant::now() + Duration::from_millis(c.duration);
        let mut accepted = 0u32;
        while Instant::now() < d && accepted < c.connections.max(1) {
            match l.accept() {
                Ok((s, _)) => {
                    accepted += 1;
                    let mut session_cfg = c.clone();
                    if accepted > 1 {
                        session_cfg.rotate_before_request = false;
                        session_cfg.revoke_before_request = false;
                        session_cfg.rotate_then_revoke = false;
                    }
                    server(s, session_cfg, &mut provider, None);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10))
                }
                Err(_) => break,
            }
        }
    } else if !client(c) {
        std::process::exit(2)
    } else {
        eprintln!("event=identity_sync_client_ok")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_profile_range_validation_fails_closed() {
        assert_eq!(validate_profile_range(1, 1), Ok(()));
        assert_eq!(validate_profile_range(1, 2), Ok(()));
        assert_eq!(
            validate_profile_range(0, 2),
            Err("InvalidLocalProfileRange")
        );
        assert_eq!(
            validate_profile_range(1, 3),
            Err("InvalidLocalProfileRange")
        );
        assert_eq!(
            validate_profile_range(2, 1),
            Err("InvalidLocalProfileRange")
        );
    }

    #[test]
    fn profile_version_cli_values_must_be_explicitly_parseable() {
        assert_eq!(
            validate_profile_cli_values(&["--profile-min-version".into(), "2".into()]),
            Ok(())
        );
        assert_eq!(
            validate_profile_cli_values(&["--profile-min-version".into(), "bad".into()]),
            Err("InvalidProfileVersionValue")
        );
        assert_eq!(
            validate_profile_cli_values(&["--profile-max-version".into()]),
            Err("InvalidProfileVersionValue")
        );
    }

    fn decode_vector_hex(value: &str) -> Result<Vec<u8>, String> {
        if value.len() % 2 != 0 {
            return Err("odd hex length".to_string());
        }
        (0..value.len())
            .step_by(2)
            .map(|index| {
                u8::from_str_radix(&value[index..index + 2], 16).map_err(|err| err.to_string())
            })
            .collect()
    }

    #[test]
    fn c4_c5_golden_profile_vectors_match_rust_validation() {
        let context = [0xA5u8; IDENTITY_CONTEXT_LEN];
        let mut accepted = 0usize;
        let mut rejected = 0usize;
        for line in include_str!("../../../../../simulations/cp0025w_profile_vectors.txt").lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fields: Vec<&str> = line.split('|').collect();
            assert_eq!(fields.len(), 5, "bad profile vector row: {line}");
            let (case, kind, envelope_hex, offer_hex, expected) =
                (fields[0], fields[1], fields[2], fields[3], fields[4]);

            let actual = (|| -> Result<(), String> {
                let app = decode_vector_hex(envelope_hex)?;
                let (marker, message_type) = match kind {
                    "offer" => (PROFILE_NEGOTIATE_MARKER, PROFILE_NEGOTIATE_TYPE),
                    "selection" => (PROFILE_SELECTED_MARKER, PROFILE_SELECTED_TYPE),
                    _ => return Err("unknown vector kind".to_string()),
                };
                let frame = decode_profile_envelope(&app, marker, &context, message_type)
                    .map_err(str::to_string)?;
                // Every selection vector echoes the offer's request ID 1.
                if frame.request_id != 1 {
                    return Err("profile request ID was not echoed".to_string());
                }
                match kind {
                    "offer" => decode_profile_offer(&frame.payload)
                        .map(|_| ())
                        .map_err(str::to_string),
                    "selection" => {
                        let offer_payload = decode_vector_hex(offer_hex)?;
                        let offer = decode_profile_offer(&offer_payload).map_err(str::to_string)?;
                        let selection =
                            decode_profile_selection(&frame.payload).map_err(str::to_string)?;
                        validate_profile_selection(offer, selection).map_err(str::to_string)
                    }
                    _ => Err("unknown vector kind".to_string()),
                }
            })();

            if expected == "ACCEPT" {
                assert!(actual.is_ok(), "vector {case} should accept: {actual:?}");
                accepted += 1;
            } else {
                assert!(actual.is_err(), "vector {case} should reject");
                rejected += 1;
            }
        }
        assert_eq!(accepted, 5);
        assert_eq!(rejected, 22);
    }

    #[test]
    fn context_has_no_direct_credential_transport_field() {
        let c = C {
            id: 1,
            listen: 1,
            peer: 1,
            server: false,
            generation: 2,
            revoked: false,
            rotate_before_request: false,
            revoke_before_request: false,
            rotate_then_revoke: false,
            correlated_v2: false,
            profile_negotiation: false,
            profile_min_version: PROFILE_VERSION_C2,
            profile_max_version: PROFILE_VERSION_C3,
            rotate_after_profile_negotiate: false,
            test_error: false,
            test_response_fault: String::new(),
            multi_request_count: 0,
            parallel_server: false,
            max_concurrent_sessions: MAX_CONCURRENT_SESSIONS_PROCESS_TESTNET,
            max_process_reserved_bytes: MAX_PROCESS_RESERVED_BYTES_TESTNET,
            worker_count: MAX_CONCURRENT_SESSIONS_PROCESS_TESTNET,
            admission_queue_capacity: DEFAULT_ADMISSION_QUEUE_CAPACITY_TESTNET,
            test_session_hold_ms: 0,
            test_batch_hold_after_reserve_ms: 0,
            provider: "memory".to_string(),
            connections: 1,
            duration: 1,
        };
        let b = bind(&key(&c));
        let ctx = session_identity_context(&b, &[7u8; 32]);
        assert_eq!(ctx.len(), 32);
        assert_ne!(ctx, [0u8; 32])
    }

    #[test]
    fn profile_offer_payload_is_strict_and_big_endian() {
        let offer = ProfileOffer {
            min_version: PROFILE_VERSION_C3,
            max_version: PROFILE_VERSION_C3,
            features: PROFILE_CORRELATION_FEATURE,
        };
        let bytes = encode_profile_offer(offer).unwrap();
        assert_eq!(
            bytes,
            vec![
                0,
                PROFILE_VERSION_C3 as u8,
                0,
                PROFILE_VERSION_C3 as u8,
                0,
                0,
                0,
                1
            ]
        );
        assert_eq!(decode_profile_offer(&bytes), Ok(offer));
        assert_eq!(decode_profile_offer(&bytes[..7]), Err("InvalidOfferLength"));

        let mut unknown = bytes.clone();
        unknown[7] = 3;
        assert_eq!(decode_profile_offer(&unknown), Err("UnknownFeatureBits"));

        let bad_range = ProfileOffer {
            min_version: PROFILE_VERSION_C3,
            max_version: PROFILE_VERSION_C2,
            features: PROFILE_CORRELATION_FEATURE,
        };
        assert_eq!(encode_profile_offer(bad_range), Err("InvalidVersionRange"));
        let c2_with_c3_feature = ProfileOffer {
            min_version: PROFILE_VERSION_C2,
            max_version: PROFILE_VERSION_C2,
            features: PROFILE_CORRELATION_FEATURE,
        };
        assert_eq!(
            encode_profile_offer(c2_with_c3_feature),
            Err("FeatureOutsideProfileRange")
        );
    }

    #[test]
    fn profile_selection_prefers_highest_common_version_without_implicit_downgrade() {
        let flexible = ProfileOffer {
            min_version: PROFILE_VERSION_C2,
            max_version: PROFILE_VERSION_C3,
            features: PROFILE_CORRELATION_FEATURE,
        };
        assert_eq!(
            select_profile(flexible, PROFILE_VERSION_C2, PROFILE_VERSION_C3),
            Ok(ProfileSelection {
                version: PROFILE_VERSION_C3,
                features: PROFILE_CORRELATION_FEATURE
            })
        );
        // A flexible offer explicitly permits C2 if the peer only supports it.
        assert_eq!(
            select_profile(flexible, PROFILE_VERSION_C2, PROFILE_VERSION_C2),
            Ok(ProfileSelection {
                version: PROFILE_VERSION_C2,
                features: 0
            })
        );

        let strict_c3 = ProfileOffer {
            min_version: PROFILE_VERSION_C3,
            max_version: PROFILE_VERSION_C3,
            features: PROFILE_CORRELATION_FEATURE,
        };
        assert_eq!(
            select_profile(strict_c3, PROFILE_VERSION_C2, PROFILE_VERSION_C2),
            Err("NoCommonProfile")
        );
        assert_eq!(
            select_profile(flexible, PROFILE_VERSION_C3, PROFILE_VERSION_C3),
            Ok(ProfileSelection {
                version: PROFILE_VERSION_C3,
                features: PROFILE_CORRELATION_FEATURE
            })
        );
        let strict_c2 = ProfileOffer {
            min_version: PROFILE_VERSION_C2,
            max_version: PROFILE_VERSION_C2,
            features: 0,
        };
        assert_eq!(
            select_profile(strict_c2, PROFILE_VERSION_C3, PROFILE_VERSION_C3),
            Err("NoCommonProfile")
        );
        assert_eq!(
            select_profile(flexible, PROFILE_VERSION_C3, PROFILE_VERSION_C2),
            Err("InvalidServerProfileRange")
        );
        assert_eq!(
            validate_profile_selection(
                strict_c3,
                ProfileSelection {
                    version: PROFILE_VERSION_C2,
                    features: 0
                }
            ),
            Err("ProfileDowngradeRejected")
        );
        assert_eq!(
            decode_profile_selection(&[0, PROFILE_VERSION_C2 as u8, 0, 0, 0, 0]),
            Ok(ProfileSelection {
                version: PROFILE_VERSION_C2,
                features: 0
            })
        );
        assert_eq!(
            decode_profile_selection(&[0, PROFILE_VERSION_C3 as u8, 0, 0, 0, 0]),
            Err("InvalidSelectedVersionOrFeatures")
        );
        assert_eq!(
            decode_profile_selection(&[0, PROFILE_VERSION_C2 as u8, 0, 0, 0]),
            Err("InvalidSelectionLength")
        );
    }

    #[test]
    fn profile_selection_envelope_binds_marker_context_type_and_request_id() {
        let context = [0xA5; IDENTITY_CONTEXT_LEN];
        let payload = encode_profile_selection(ProfileSelection {
            version: PROFILE_VERSION_C3,
            features: PROFILE_CORRELATION_FEATURE,
        })
        .unwrap();
        let app = profile_envelope(
            PROFILE_SELECTED_MARKER,
            &context,
            PROFILE_SELECTED_TYPE,
            1,
            &payload,
        )
        .unwrap();
        let frame = decode_profile_envelope(
            &app,
            PROFILE_SELECTED_MARKER,
            &context,
            PROFILE_SELECTED_TYPE,
        )
        .unwrap();
        assert_eq!(frame.request_id, 1);
        assert_eq!(
            decode_profile_selection(&frame.payload),
            Ok(ProfileSelection {
                version: PROFILE_VERSION_C3,
                features: PROFILE_CORRELATION_FEATURE
            })
        );
        assert_eq!(
            decode_profile_envelope(
                &app,
                PROFILE_NEGOTIATE_MARKER,
                &context,
                PROFILE_SELECTED_TYPE
            ),
            Err("WrongProfileMarker")
        );
        let wrong_context = [0x5A; IDENTITY_CONTEXT_LEN];
        assert_eq!(
            decode_profile_envelope(
                &app,
                PROFILE_SELECTED_MARKER,
                &wrong_context,
                PROFILE_SELECTED_TYPE
            ),
            Err("ProfileContextMismatch")
        );
    }

    #[test]
    fn correlated_v2_error_frame_preserves_request_correlation() {
        let payload = encode_error(ErrorCode::UnsupportedType, HEADERS_TYPE).unwrap();
        let frame = encode_frame(WIRE_VERSION, ERROR_TYPE, 42, &payload).unwrap();
        let decoded = decode_frame(&frame).unwrap();
        assert_eq!(decoded.message_type, ERROR_TYPE);
        assert_eq!(decoded.request_id, 42);
        assert_eq!(
            decode_error(&decoded.payload).unwrap(),
            (ErrorCode::UnsupportedType, HEADERS_TYPE)
        );

        let mut envelope = vec![IDENTITY_CORRELATED_RESPONSE_MARKER];
        envelope.extend_from_slice(&[7u8; IDENTITY_CONTEXT_LEN]);
        envelope.extend_from_slice(&frame);
        assert_eq!(envelope[0], 0xC3);
        assert_eq!(&envelope[1..33], &[7u8; IDENTITY_CONTEXT_LEN]);
        let round_trip = decode_frame(&envelope[33..]).unwrap();
        assert_eq!(round_trip.request_id, decoded.request_id);
        assert_eq!(round_trip.message_type, decoded.message_type);
        let parsed = decode_correlated_response(&envelope, &[7u8; IDENTITY_CONTEXT_LEN]).unwrap();
        assert_eq!(parsed.message_type, ERROR_TYPE);
        assert_eq!(parsed.request_id, 42);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn correlated_v2_headers_frame_respects_payload_reservation() {
        let payload = vec![0u8; MAX_HEADERS_PAYLOAD_TESTNET];
        let frame = encode_frame(WIRE_VERSION, HEADERS_TYPE, 9, &payload).unwrap();
        let decoded = decode_frame(&frame).unwrap();
        assert_eq!(decoded.request_id, 9);
        assert_eq!(decoded.message_type, HEADERS_TYPE);
        assert_eq!(decoded.payload.len(), MAX_HEADERS_PAYLOAD_TESTNET);

        let mut tracker = RequestTracker::new();
        tracker
            .open(
                9,
                HEADERS_TYPE,
                TRACKED_REQUEST_TIMEOUT_MS,
                MAX_HEADERS_PAYLOAD_TESTNET,
            )
            .unwrap();
        tracker
            .complete(9, decoded.message_type, decoded.payload.len(), 10)
            .unwrap();
        assert_eq!(tracker.len(), 0);
        assert_eq!(tracker.outstanding_bytes(), 0);
    }

    #[test]
    fn correlated_response_parser_fuzzes_malformed_bytes_without_panics() {
        let context = [0x5Au8; IDENTITY_CONTEXT_LEN];
        let headers_payload = enc(&headers());
        let good_frame = encode_frame(WIRE_VERSION, HEADERS_TYPE, 17, &headers_payload).unwrap();
        let mut good = vec![IDENTITY_CORRELATED_RESPONSE_MARKER];
        good.extend_from_slice(&context);
        good.extend_from_slice(&good_frame);
        let parsed = decode_correlated_response(&good, &context).unwrap();
        assert_eq!(parsed.message_type, HEADERS_TYPE);
        assert_eq!(parsed.request_id, 17);
        assert_eq!(parsed.payload, headers_payload);

        // Exercise every single-bit mutation of a valid C3 HEADERS envelope.
        for byte_index in 0..good.len() {
            for bit in 0..8 {
                let mut mutated = good.clone();
                mutated[byte_index] ^= 1u8 << bit;
                if let Ok(response) = decode_correlated_response(&mutated, &context) {
                    match response.message_type {
                        HEADERS_TYPE => {
                            assert_ne!(response.request_id, 0);
                            assert!(
                                response.payload.len()
                                    <= ai_native_l1_pow_bench::protocol_profile::WIRE_MAX_FRAME_TESTNET
                            );
                        }
                        ERROR_TYPE => {
                            let (code, offending_type) = decode_error(&response.payload).unwrap();
                            assert_ne!(offending_type, 0);
                            if response.request_id == 0 {
                                assert_eq!(code, ErrorCode::BadRequest);
                            }
                        }
                        _ => {
                            // A parseable unexpected type is rejected by RequestTracker.
                        }
                    }
                }
            }
        }

        // Deterministic pseudo-random arbitrary inputs, capped at 512 bytes.
        let mut rng = 0xA1B2_C3D4_E5F6_0718u64;
        for _case in 0..10_000 {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            let length = (rng as usize) % 513;
            let mut bytes = vec![0u8; length];
            for byte in &mut bytes {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                *byte = (rng >> 24) as u8;
            }
            if let Ok(response) = decode_correlated_response(&bytes, &context) {
                match response.message_type {
                    HEADERS_TYPE => {
                        assert_ne!(response.request_id, 0);
                        assert!(
                            response.payload.len()
                                <= ai_native_l1_pow_bench::protocol_profile::WIRE_MAX_FRAME_TESTNET
                        );
                    }
                    ERROR_TYPE => {
                        let (code, offending_type) = decode_error(&response.payload).unwrap();
                        assert_ne!(offending_type, 0);
                        if response.request_id == 0 {
                            assert_eq!(code, ErrorCode::BadRequest);
                        }
                    }
                    _ => {
                        // An unexpected-but-well-framed type is returned so the
                        // caller's RequestTracker can report WrongResponseType.
                    }
                }
            }
        }
    }
}
