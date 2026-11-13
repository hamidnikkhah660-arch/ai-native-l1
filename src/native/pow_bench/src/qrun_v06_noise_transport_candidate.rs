//! CP-0552 isolated, pinned Noise XX transport for QFP6 peer sessions.
//!
//! This is deliberately domain-separated from the QFP5/v0.5 transport. It uses classical
//! X25519/ChaChaPoly/SHA-256 Noise XX with explicit two-sided static-key pins and a prologue
//! binding the QFP6 network and profile. It is a local candidate transport, not a public listener,
//! peer-discovery service, post-quantum transport, or production node.

use snow::{params::NoiseParams, Builder, TransportState};
use std::{
    io::{self, Read, Write},
    net::TcpStream,
    time::{Duration, Instant},
};

const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
const PROLOGUE_DOMAIN: &[u8] = b"QRUN-V06-QFP6-PEER-NOISE-XX-V1\0";
const MAX_HANDSHAKE_MESSAGE: usize = 1024;
const HANDSHAKE_BUDGET: Duration = Duration::from_secs(8);
const RECORD_BUDGET: Duration = Duration::from_secs(5);
pub const QFP6_NOISE_RESPONSE_BUDGET: Duration = Duration::from_secs(30);
pub const MAX_QFP6_NOISE_RECORD_BYTES: usize =
    crate::qrun_v06_node_runtime_candidate::QRUN_V06_PEER_BLOCK_HEADER_BYTES
        + crate::qrun_v06_pow_wire_candidate::MAX_QRUN_V06_POW_ENVELOPE_BYTES;
const MIN_CIPHERTEXT_BYTES: usize = 16;
const MAX_CIPHERTEXT_BYTES: usize = MAX_QFP6_NOISE_RECORD_BYTES + 16;
const MAX_TRUSTED_PEERS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QRunV06NoiseError {
    InvalidNetworkOrProfile,
    InvalidPrivateKey,
    EmptyTrustSet,
    OversizedTrustSet,
    DuplicateTrustedKey,
    MalformedHandshake,
    HandshakeTimeout,
    Handshake(String),
    UntrustedPeer,
    MalformedRecord,
    RecordTimeout,
    RecordTooLarge(usize),
    RecordAuthentication,
    Io(String),
}

impl std::fmt::Display for QRunV06NoiseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for QRunV06NoiseError {}

/// One authenticated Noise transport bound to exactly one TCP connection.
/// Drop the session and connection after any framing or authentication error.
pub struct QRunV06NoiseSession {
    transport: TransportState,
    remote_static_public_key: [u8; 32],
    remote_static_key_pinned: bool,
    network_id: [u8; 32],
    profile_id: [u8; 32],
}

impl std::fmt::Debug for QRunV06NoiseSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QRunV06NoiseSession")
            .field("remote_static_public_key", &"<redacted>")
            .field("remote_static_key_pinned", &self.remote_static_key_pinned)
            .finish_non_exhaustive()
    }
}

impl QRunV06NoiseSession {
    pub fn remote_static_public_key(&self) -> &[u8; 32] {
        &self.remote_static_public_key
    }
    /// True only when the remote static key was checked against an operator-supplied pin.
    /// An unpinned session provides transport confidentiality and domain binding, not a
    /// verified peer identity.
    pub fn remote_static_key_pinned(&self) -> bool {
        self.remote_static_key_pinned
    }

    /// Network and profile bound into this Noise handshake's authenticated prologue.
    pub fn network_id(&self) -> &[u8; 32] {
        &self.network_id
    }
    pub fn profile_id(&self) -> &[u8; 32] {
        &self.profile_id
    }

    /// Initiator verifies the responder static key before exposing the session.
    pub fn connect(
        stream: &mut TcpStream,
        local_static_private_key: &[u8; 32],
        trusted_remote_static_public_key: &[u8; 32],
        network_id: &[u8; 32],
        profile_id: &[u8; 32],
    ) -> Result<Self, QRunV06NoiseError> {
        validate_context(local_static_private_key, network_id, profile_id)?;
        validate_pin(trusted_remote_static_public_key)?;
        let deadline = Instant::now() + HANDSHAKE_BUDGET;
        let mut handshake = Builder::new(noise_params()?)
            .prologue(&prologue(network_id, profile_id))
            .local_private_key(local_static_private_key)
            .build_initiator()
            .map_err(|error| QRunV06NoiseError::Handshake(error.to_string()))?;
        let mut payload = [0u8; MAX_HANDSHAKE_MESSAGE];
        let mut message = [0u8; MAX_HANDSHAKE_MESSAGE];

        let written = handshake
            .write_message(&[], &mut message)
            .map_err(|error| QRunV06NoiseError::Handshake(error.to_string()))?;
        write_handshake(stream, &message[..written], deadline)?;

        let second = read_handshake(stream, deadline)?;
        let read = handshake
            .read_message(&second, &mut payload)
            .map_err(|error| QRunV06NoiseError::Handshake(error.to_string()))?;
        if read != 0 {
            return Err(QRunV06NoiseError::MalformedHandshake);
        }
        let remote = handshake
            .get_remote_static()
            .ok_or(QRunV06NoiseError::MalformedHandshake)?;
        if remote != trusted_remote_static_public_key {
            return Err(QRunV06NoiseError::UntrustedPeer);
        }
        let mut remote_static_public_key = [0u8; 32];
        remote_static_public_key.copy_from_slice(remote);

        let written = handshake
            .write_message(&[], &mut message)
            .map_err(|error| QRunV06NoiseError::Handshake(error.to_string()))?;
        write_handshake(stream, &message[..written], deadline)?;
        let transport = handshake
            .into_transport_mode()
            .map_err(|error| QRunV06NoiseError::Handshake(error.to_string()))?;
        Ok(Self {
            transport,
            remote_static_public_key,
            remote_static_key_pinned: true,
            network_id: *network_id,
            profile_id: *profile_id,
        })
    }

    /// Responder verifies the initiator static key against an explicit bounded trust set.
    pub fn accept(
        stream: &mut TcpStream,
        local_static_private_key: &[u8; 32],
        trusted_remote_static_public_keys: &[[u8; 32]],
        network_id: &[u8; 32],
        profile_id: &[u8; 32],
    ) -> Result<Self, QRunV06NoiseError> {
        validate_context(local_static_private_key, network_id, profile_id)?;
        validate_trust_set(trusted_remote_static_public_keys)?;
        let deadline = Instant::now() + HANDSHAKE_BUDGET;
        let mut handshake = Builder::new(noise_params()?)
            .prologue(&prologue(network_id, profile_id))
            .local_private_key(local_static_private_key)
            .build_responder()
            .map_err(|error| QRunV06NoiseError::Handshake(error.to_string()))?;
        let mut payload = [0u8; MAX_HANDSHAKE_MESSAGE];
        let mut message = [0u8; MAX_HANDSHAKE_MESSAGE];

        let first = read_handshake(stream, deadline)?;
        let read = handshake
            .read_message(&first, &mut payload)
            .map_err(|error| QRunV06NoiseError::Handshake(error.to_string()))?;
        if read != 0 {
            return Err(QRunV06NoiseError::MalformedHandshake);
        }
        let written = handshake
            .write_message(&[], &mut message)
            .map_err(|error| QRunV06NoiseError::Handshake(error.to_string()))?;
        write_handshake(stream, &message[..written], deadline)?;

        let third = read_handshake(stream, deadline)?;
        let read = handshake
            .read_message(&third, &mut payload)
            .map_err(|error| QRunV06NoiseError::Handshake(error.to_string()))?;
        if read != 0 {
            return Err(QRunV06NoiseError::MalformedHandshake);
        }
        let remote = handshake
            .get_remote_static()
            .ok_or(QRunV06NoiseError::MalformedHandshake)?;
        if !trusted_remote_static_public_keys
            .iter()
            .any(|key| key.as_slice() == remote)
        {
            return Err(QRunV06NoiseError::UntrustedPeer);
        }
        let mut remote_static_public_key = [0u8; 32];
        remote_static_public_key.copy_from_slice(remote);
        let transport = handshake
            .into_transport_mode()
            .map_err(|error| QRunV06NoiseError::Handshake(error.to_string()))?;
        Ok(Self {
            transport,
            remote_static_public_key,
            remote_static_key_pinned: true,
            network_id: *network_id,
            profile_id: *profile_id,
        })
    }

    /// Responder accepts an anonymous Noise XX peer without treating its self-asserted static
    /// key as an identity or trust anchor. The prologue still binds the exact QFP6 network and
    /// profile. Consensus, signatures, replay guards, and bounded admission remain mandatory.
    /// This is unauthenticated Noise XX. The remote identity is unverified and an active MITM can
    /// terminate/re-encrypt the session; at best this protects against passive eavesdropping.
    /// It is not an authenticated transport or a post-quantum transport.
    pub fn accept_unpinned(
        stream: &mut TcpStream,
        local_static_private_key: &[u8; 32],
        network_id: &[u8; 32],
        profile_id: &[u8; 32],
    ) -> Result<Self, QRunV06NoiseError> {
        validate_context(local_static_private_key, network_id, profile_id)?;
        let deadline = Instant::now() + HANDSHAKE_BUDGET;
        let mut handshake = Builder::new(noise_params()?)
            .prologue(&prologue(network_id, profile_id))
            .local_private_key(local_static_private_key)
            .build_responder()
            .map_err(|error| QRunV06NoiseError::Handshake(error.to_string()))?;
        let mut payload = [0u8; MAX_HANDSHAKE_MESSAGE];
        let mut message = [0u8; MAX_HANDSHAKE_MESSAGE];

        let first = read_handshake(stream, deadline)?;
        let read = handshake
            .read_message(&first, &mut payload)
            .map_err(|error| QRunV06NoiseError::Handshake(error.to_string()))?;
        if read != 0 {
            return Err(QRunV06NoiseError::MalformedHandshake);
        }
        let written = handshake
            .write_message(&[], &mut message)
            .map_err(|error| QRunV06NoiseError::Handshake(error.to_string()))?;
        write_handshake(stream, &message[..written], deadline)?;

        let third = read_handshake(stream, deadline)?;
        let read = handshake
            .read_message(&third, &mut payload)
            .map_err(|error| QRunV06NoiseError::Handshake(error.to_string()))?;
        if read != 0 {
            return Err(QRunV06NoiseError::MalformedHandshake);
        }
        let remote = handshake
            .get_remote_static()
            .ok_or(QRunV06NoiseError::MalformedHandshake)?;
        let mut remote_static_public_key = [0u8; 32];
        remote_static_public_key.copy_from_slice(remote);
        let transport = handshake
            .into_transport_mode()
            .map_err(|error| QRunV06NoiseError::Handshake(error.to_string()))?;
        Ok(Self {
            transport,
            remote_static_public_key,
            remote_static_key_pinned: false,
            network_id: *network_id,
            profile_id: *profile_id,
        })
    }

    /// Accept an anonymous Noise XX peer while marking its static key as pinned only when it
    /// matches an operator-provided allow-list. Nonmatching peers remain accepted but unverified,
    /// so the caller can preserve permissionless ingress without granting trust to advertisements.
    pub fn accept_unpinned_with_optional_pins(
        stream: &mut TcpStream,
        local_static_private_key: &[u8; 32],
        network_id: &[u8; 32],
        profile_id: &[u8; 32],
        trusted_remote_static_public_keys: &[[u8; 32]],
    ) -> Result<Self, QRunV06NoiseError> {
        if !trusted_remote_static_public_keys.is_empty() {
            validate_trust_set(trusted_remote_static_public_keys)?;
        }
        let mut session =
            Self::accept_unpinned(stream, local_static_private_key, network_id, profile_id)?;
        session.remote_static_key_pinned = trusted_remote_static_public_keys
            .iter()
            .any(|key| key == &session.remote_static_public_key);
        Ok(session)
    }

    /// Encrypt one bounded QFP6 application record with a five-second absolute deadline.
    pub fn write_record(
        &mut self,
        stream: &mut TcpStream,
        plaintext: &[u8],
    ) -> Result<(), QRunV06NoiseError> {
        self.write_record_with_budget(stream, plaintext, RECORD_BUDGET)
    }

    /// Read and authenticate one bounded record with a five-second absolute deadline.
    pub fn read_record(&mut self, stream: &mut TcpStream) -> Result<Vec<u8>, QRunV06NoiseError> {
        self.read_record_with_budget(stream, RECORD_BUDGET)
    }

    /// Extended bounded read for a peer admission response after PoW and durable admission.
    pub fn read_admission_response(
        &mut self,
        stream: &mut TcpStream,
    ) -> Result<Vec<u8>, QRunV06NoiseError> {
        self.read_record_with_budget(stream, QFP6_NOISE_RESPONSE_BUDGET)
    }

    pub fn write_q6pb_request(
        &mut self,
        stream: &mut TcpStream,
        frame: &[u8],
    ) -> Result<(), QRunV06NoiseError> {
        crate::qrun_v06_node_runtime_candidate::decode_qrun_v06_peer_block_request(frame)
            .map_err(|_| QRunV06NoiseError::MalformedRecord)?;
        self.write_record(stream, frame)
    }

    pub fn read_q6pa_response(
        &mut self,
        stream: &mut TcpStream,
        expected_request_id: u64,
    ) -> Result<
        [u8; crate::qrun_v06_node_runtime_candidate::QRUN_V06_PEER_ADMISSION_RESPONSE_BYTES],
        QRunV06NoiseError,
    > {
        use crate::qrun_v06_node_runtime_candidate::{
            QRUN_V06_PEER_ADMISSION_MAGIC, QRUN_V06_PEER_ADMISSION_RESPONSE_BYTES,
            QRUN_V06_PEER_FRAME_VERSION,
        };
        let bytes = self.read_admission_response(stream)?;
        if bytes.len() != QRUN_V06_PEER_ADMISSION_RESPONSE_BYTES
            || bytes[..4] != QRUN_V06_PEER_ADMISSION_MAGIC
            || u16::from_be_bytes([bytes[4], bytes[5]]) != QRUN_V06_PEER_FRAME_VERSION
            || u64::from_be_bytes(bytes[8..16].try_into().unwrap()) != expected_request_id
            || !matches!(u16::from_be_bytes([bytes[6], bytes[7]]), 1..=3)
        {
            return Err(QRunV06NoiseError::MalformedRecord);
        }
        let status = u16::from_be_bytes([bytes[6], bytes[7]]);
        if status != 1 && bytes[16..].iter().any(|byte| *byte != 0) {
            return Err(QRunV06NoiseError::MalformedRecord);
        }
        Ok(bytes
            .try_into()
            .map_err(|_| QRunV06NoiseError::MalformedRecord)?)
    }

    fn write_record_with_budget(
        &mut self,
        stream: &mut TcpStream,
        plaintext: &[u8],
        budget: Duration,
    ) -> Result<(), QRunV06NoiseError> {
        if plaintext.is_empty() || plaintext.len() > MAX_QFP6_NOISE_RECORD_BYTES {
            return Err(QRunV06NoiseError::RecordTooLarge(plaintext.len()));
        }
        let deadline = Instant::now() + budget;
        let mut ciphertext = vec![0u8; plaintext.len() + 16];
        let length = self
            .transport
            .write_message(plaintext, &mut ciphertext)
            .map_err(|_| QRunV06NoiseError::RecordAuthentication)?;
        ciphertext.truncate(length);
        if !(MIN_CIPHERTEXT_BYTES..=MAX_CIPHERTEXT_BYTES).contains(&ciphertext.len()) {
            return Err(QRunV06NoiseError::MalformedRecord);
        }
        write_all_until(stream, &(ciphertext.len() as u32).to_be_bytes(), deadline)
            .and_then(|()| write_all_until(stream, &ciphertext, deadline))
            .map_err(map_record_io_error)
    }

    fn read_record_with_budget(
        &mut self,
        stream: &mut TcpStream,
        budget: Duration,
    ) -> Result<Vec<u8>, QRunV06NoiseError> {
        let deadline = Instant::now() + budget;
        let mut length = [0u8; 4];
        read_exact_until(stream, &mut length, deadline).map_err(map_record_io_error)?;
        let length = u32::from_be_bytes(length) as usize;
        if !(MIN_CIPHERTEXT_BYTES..=MAX_CIPHERTEXT_BYTES).contains(&length) {
            return Err(QRunV06NoiseError::MalformedRecord);
        }
        let mut ciphertext = vec![0u8; length];
        read_exact_until(stream, &mut ciphertext, deadline).map_err(map_record_io_error)?;
        let mut plaintext = vec![0u8; length];
        let plaintext_len = self
            .transport
            .read_message(&ciphertext, &mut plaintext)
            .map_err(|_| QRunV06NoiseError::RecordAuthentication)?;
        plaintext.truncate(plaintext_len);
        if plaintext.is_empty() || plaintext.len() > MAX_QFP6_NOISE_RECORD_BYTES {
            return Err(QRunV06NoiseError::RecordTooLarge(plaintext.len()));
        }
        Ok(plaintext)
    }
}

fn noise_params() -> Result<NoiseParams, QRunV06NoiseError> {
    NOISE_PATTERN
        .parse()
        .map_err(|error: snow::Error| QRunV06NoiseError::Handshake(error.to_string()))
}
fn prologue(network_id: &[u8; 32], profile_id: &[u8; 32]) -> Vec<u8> {
    let mut value = Vec::with_capacity(PROLOGUE_DOMAIN.len() + 64);
    value.extend_from_slice(PROLOGUE_DOMAIN);
    value.extend_from_slice(network_id);
    value.extend_from_slice(profile_id);
    value
}
fn validate_context(
    private_key: &[u8; 32],
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
) -> Result<(), QRunV06NoiseError> {
    if private_key.iter().all(|byte| *byte == 0) {
        return Err(QRunV06NoiseError::InvalidPrivateKey);
    }
    if network_id.iter().all(|byte| *byte == 0) || profile_id.iter().all(|byte| *byte == 0) {
        return Err(QRunV06NoiseError::InvalidNetworkOrProfile);
    }
    Ok(())
}
fn validate_pin(key: &[u8; 32]) -> Result<(), QRunV06NoiseError> {
    if key.iter().all(|byte| *byte == 0) {
        return Err(QRunV06NoiseError::UntrustedPeer);
    }
    Ok(())
}
fn validate_trust_set(keys: &[[u8; 32]]) -> Result<(), QRunV06NoiseError> {
    if keys.is_empty() {
        return Err(QRunV06NoiseError::EmptyTrustSet);
    }
    if keys.len() > MAX_TRUSTED_PEERS {
        return Err(QRunV06NoiseError::OversizedTrustSet);
    }
    for (index, key) in keys.iter().enumerate() {
        validate_pin(key)?;
        if keys.iter().skip(index + 1).any(|other| other == key) {
            return Err(QRunV06NoiseError::DuplicateTrustedKey);
        }
    }
    Ok(())
}
fn read_handshake(stream: &mut TcpStream, deadline: Instant) -> Result<Vec<u8>, QRunV06NoiseError> {
    let mut length = [0u8; 2];
    read_exact_until(stream, &mut length, deadline).map_err(map_handshake_io_error)?;
    let length = u16::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_HANDSHAKE_MESSAGE {
        return Err(QRunV06NoiseError::MalformedHandshake);
    }
    let mut bytes = vec![0u8; length];
    read_exact_until(stream, &mut bytes, deadline).map_err(map_handshake_io_error)?;
    Ok(bytes)
}
fn write_handshake(
    stream: &mut TcpStream,
    bytes: &[u8],
    deadline: Instant,
) -> Result<(), QRunV06NoiseError> {
    if bytes.is_empty() || bytes.len() > MAX_HANDSHAKE_MESSAGE || bytes.len() > u16::MAX as usize {
        return Err(QRunV06NoiseError::MalformedHandshake);
    }
    write_all_until(stream, &(bytes.len() as u16).to_be_bytes(), deadline)
        .and_then(|()| write_all_until(stream, bytes, deadline))
        .map_err(map_handshake_io_error)
}
fn read_exact_until(
    stream: &mut TcpStream,
    output: &mut [u8],
    deadline: Instant,
) -> io::Result<()> {
    let mut offset = 0usize;
    while offset < output.len() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "QFP6 Noise read deadline",
            ));
        }
        stream.set_read_timeout(Some(remaining.min(Duration::from_millis(100))))?;
        match stream.read(&mut output[offset..]) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "peer closed")),
            Ok(count) => offset += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error)
                if error.kind() == io::ErrorKind::TimedOut
                    || error.kind() == io::ErrorKind::WouldBlock =>
            {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "QFP6 Noise read deadline",
                    ));
                }
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
fn write_all_until(stream: &mut TcpStream, bytes: &[u8], deadline: Instant) -> io::Result<()> {
    let mut offset = 0usize;
    while offset < bytes.len() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "QFP6 Noise write deadline",
            ));
        }
        stream.set_write_timeout(Some(remaining.min(Duration::from_millis(100))))?;
        match stream.write(&bytes[offset..]) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "peer closed")),
            Ok(count) => offset += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error)
                if error.kind() == io::ErrorKind::TimedOut
                    || error.kind() == io::ErrorKind::WouldBlock =>
            {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "QFP6 Noise write deadline",
                    ));
                }
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
fn map_handshake_io_error(error: io::Error) -> QRunV06NoiseError {
    if error.kind() == io::ErrorKind::TimedOut || error.kind() == io::ErrorKind::WouldBlock {
        QRunV06NoiseError::HandshakeTimeout
    } else {
        QRunV06NoiseError::Io(error.to_string())
    }
}
fn map_record_io_error(error: io::Error) -> QRunV06NoiseError {
    if error.kind() == io::ErrorKind::TimedOut || error.kind() == io::ErrorKind::WouldBlock {
        QRunV06NoiseError::RecordTimeout
    } else {
        QRunV06NoiseError::Io(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snow::Builder;
    use std::{
        net::{SocketAddr, TcpListener},
        thread,
    };

    const NETWORK: [u8; 32] = [0x81; 32];
    const PROFILE: [u8; 32] = [0x82; 32];

    fn keypair() -> ([u8; 32], [u8; 32]) {
        let mut pair = Builder::new(noise_params().unwrap())
            .generate_keypair()
            .unwrap();
        let mut private = [0u8; 32];
        let mut public = [0u8; 32];
        private.copy_from_slice(&pair.private);
        public.copy_from_slice(&pair.public);
        pair.private.fill(0);
        pair.public.fill(0);
        (private, public)
    }

    fn listener() -> (TcpListener, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        (listener, address)
    }

    #[test]
    fn qfp6_noise_xx_pins_both_peers_and_encrypts_bounded_records() {
        let (server_private, server_public) = keypair();
        let (client_private, client_public) = keypair();
        let (listener, address) = listener();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut session = QRunV06NoiseSession::accept(
                &mut stream,
                &server_private,
                &[client_public],
                &NETWORK,
                &PROFILE,
            )
            .unwrap();
            assert_eq!(session.remote_static_public_key(), &client_public);
            assert_eq!(
                session.read_record(&mut stream).unwrap(),
                b"QFP6-encrypted-block"
            );
            session
                .write_record(&mut stream, b"QFP6-encrypted-ack")
                .unwrap();
        });

        let mut stream = TcpStream::connect(address).unwrap();
        let mut session = QRunV06NoiseSession::connect(
            &mut stream,
            &client_private,
            &server_public,
            &NETWORK,
            &PROFILE,
        )
        .unwrap();
        assert_eq!(session.remote_static_public_key(), &server_public);
        session
            .write_record(&mut stream, b"QFP6-encrypted-block")
            .unwrap();
        assert_eq!(
            session.read_record(&mut stream).unwrap(),
            b"QFP6-encrypted-ack"
        );
        server.join().unwrap();
    }

    #[test]
    fn qfp6_noise_prologue_mismatch_rejects_handshake() {
        let (server_private, server_public) = keypair();
        let (client_private, client_public) = keypair();
        let (listener, address) = listener();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            QRunV06NoiseSession::accept(
                &mut stream,
                &server_private,
                &[client_public],
                &NETWORK,
                &PROFILE,
            )
            .map(|_| ())
        });
        let mut stream = TcpStream::connect(address).unwrap();
        let wrong_network = [0x83; 32];
        let client = QRunV06NoiseSession::connect(
            &mut stream,
            &client_private,
            &server_public,
            &wrong_network,
            &PROFILE,
        );
        assert!(client.is_err());
        assert!(server.join().unwrap().is_err());
    }

    #[test]
    fn qfp6_noise_rejects_unpinned_and_duplicate_peer_keys() {
        assert_eq!(
            validate_pin(&[0u8; 32]),
            Err(QRunV06NoiseError::UntrustedPeer)
        );
        let (_, peer) = keypair();
        assert_eq!(
            validate_trust_set(&[]),
            Err(QRunV06NoiseError::EmptyTrustSet)
        );
        assert_eq!(
            validate_trust_set(&[peer, peer]),
            Err(QRunV06NoiseError::DuplicateTrustedKey)
        );
    }

    #[test]
    fn qfp6_noise_record_bound_rejects_before_ciphertext_write() {
        let (private, public) = keypair();
        let (peer_private, peer_public) = keypair();
        let (listener, address) = listener();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            QRunV06NoiseSession::accept(&mut stream, &peer_private, &[public], &NETWORK, &PROFILE)
                .unwrap()
        });
        let mut stream = TcpStream::connect(address).unwrap();
        let mut client =
            QRunV06NoiseSession::connect(&mut stream, &private, &peer_public, &NETWORK, &PROFILE)
                .unwrap();
        assert!(matches!(
            client.write_record(&mut stream, &vec![0xA5; MAX_QFP6_NOISE_RECORD_BYTES + 1]),
            Err(QRunV06NoiseError::RecordTooLarge(_))
        ));
        drop(client);
        drop(stream);
        drop(server.join().unwrap());
    }

    #[test]
    fn qfp6_noise_responder_rejects_unpinned_initiator_before_session_exposure() {
        let (server_private, server_public) = keypair();
        let (client_private, _client_public) = keypair();
        let (_, unexpected_client_public) = keypair();
        let (listener, address) = listener();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            QRunV06NoiseSession::accept(
                &mut stream,
                &server_private,
                &[unexpected_client_public],
                &NETWORK,
                &PROFILE,
            )
            .err()
        });

        let mut stream = TcpStream::connect(address).unwrap();
        // The initiator authenticates the responder and completes its final handshake write;
        // the responder must still reject the initiator whose static key is not pinned.
        let client = QRunV06NoiseSession::connect(
            &mut stream,
            &client_private,
            &server_public,
            &NETWORK,
            &PROFILE,
        );
        assert!(client.is_ok());
        assert!(matches!(
            server.join().unwrap(),
            Some(QRunV06NoiseError::UntrustedPeer)
        ));
    }

    #[test]
    fn qfp6_noise_rejects_oversized_inbound_ciphertext_length_before_reading_body() {
        let (server_private, server_public) = keypair();
        let (client_private, client_public) = keypair();
        let (listener, address) = listener();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut session = QRunV06NoiseSession::accept(
                &mut stream,
                &server_private,
                &[client_public],
                &NETWORK,
                &PROFILE,
            )
            .unwrap();
            session.read_record(&mut stream)
        });

        let mut stream = TcpStream::connect(address).unwrap();
        let _client = QRunV06NoiseSession::connect(
            &mut stream,
            &client_private,
            &server_public,
            &NETWORK,
            &PROFILE,
        )
        .unwrap();
        let oversized = (MAX_CIPHERTEXT_BYTES + 1) as u32;
        stream.write_all(&oversized.to_be_bytes()).unwrap();
        assert!(matches!(
            server.join().unwrap(),
            Err(QRunV06NoiseError::MalformedRecord)
        ));
    }
    #[test]
    fn qfp6_noise_unpinned_mode_encrypts_without_claiming_peer_identity() {
        let (server_private, server_public) = keypair();
        let (client_private, client_public) = keypair();
        let (listener, address) = listener();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut session = QRunV06NoiseSession::accept_unpinned_with_optional_pins(
                &mut stream,
                &server_private,
                &NETWORK,
                &PROFILE,
                &[[0x77; 32]],
            )
            .unwrap();
            assert!(!session.remote_static_key_pinned());
            assert_eq!(session.remote_static_public_key(), &client_public);
            assert_eq!(
                session.read_record(&mut stream).unwrap(),
                b"anonymous-peer-frame"
            );
            session
                .write_record(&mut stream, b"validated-domain-response")
                .unwrap();
        });

        let mut stream = TcpStream::connect(address).unwrap();
        let mut client = QRunV06NoiseSession::connect(
            &mut stream,
            &client_private,
            &server_public,
            &NETWORK,
            &PROFILE,
        )
        .unwrap();
        assert!(client.remote_static_key_pinned());
        client
            .write_record(&mut stream, b"anonymous-peer-frame")
            .unwrap();
        assert_eq!(
            client.read_record(&mut stream).unwrap(),
            b"validated-domain-response"
        );
        server.join().unwrap();
    }

    #[test]
    fn q6ar_relay_from_pinned_session_is_authenticated_and_profile_bound() {
        use crate::qrun_v06_peer_address_relay_candidate::{
            decode_q6ar_from_pinned_session, decode_q6ar_from_session, encode_q6ar, Q6arAddress,
            Q6arAdvertisement,
        };
        let wire = encode_q6ar(&Q6arAdvertisement {
            network_id: NETWORK,
            profile_id: PROFILE,
            issued_at_secs: 1_000,
            ttl_secs: 600,
            addresses: vec![Q6arAddress {
                endpoint: "8.8.8.8:8333".parse().unwrap(),
                noise_static_public_key: [0x44; 32],
            }],
        })
        .unwrap();
        let (server_private, server_public) = keypair();
        let (client_private, client_public) = keypair();
        let (listener, address) = listener();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut session = QRunV06NoiseSession::accept(
                &mut stream,
                &server_private,
                &[client_public],
                &NETWORK,
                &PROFILE,
            )
            .unwrap();
            let frame = session.read_record(&mut stream).unwrap();
            let received = decode_q6ar_from_session(&frame, &session, 1_100).unwrap();
            assert!(received.relay_origin.relay_static_key_pinned);
            assert_eq!(received.relay_origin.relay_static_public_key, client_public);
            assert_eq!(
                decode_q6ar_from_pinned_session(&frame, &session, 1_100).unwrap(),
                received.advertisement
            );
            assert_eq!(session.network_id(), &NETWORK);
            assert_eq!(session.profile_id(), &PROFILE);
        });
        let mut stream = TcpStream::connect(address).unwrap();
        let mut client = QRunV06NoiseSession::connect(
            &mut stream,
            &client_private,
            &server_public,
            &NETWORK,
            &PROFILE,
        )
        .unwrap();
        client.write_record(&mut stream, &wire).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn q6ar_relay_from_unpinned_session_is_only_an_untrusted_candidate() {
        use crate::qrun_v06_peer_address_relay_candidate::{
            decode_q6ar_from_pinned_session, decode_q6ar_from_session, encode_q6ar, Q6arAddress,
            Q6arAdvertisement, Q6arError,
        };
        let wire = encode_q6ar(&Q6arAdvertisement {
            network_id: NETWORK,
            profile_id: PROFILE,
            issued_at_secs: 1_000,
            ttl_secs: 600,
            addresses: vec![Q6arAddress {
                endpoint: "1.1.1.1:8333".parse().unwrap(),
                noise_static_public_key: [0x45; 32],
            }],
        })
        .unwrap();
        let (server_private, server_public) = keypair();
        let (client_private, client_public) = keypair();
        let (listener, address) = listener();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut session = QRunV06NoiseSession::accept_unpinned(
                &mut stream,
                &server_private,
                &NETWORK,
                &PROFILE,
            )
            .unwrap();
            let frame = session.read_record(&mut stream).unwrap();
            let received = decode_q6ar_from_session(&frame, &session, 1_100).unwrap();
            assert!(!received.relay_origin.relay_static_key_pinned);
            assert_eq!(received.relay_origin.relay_static_public_key, client_public);
            assert_eq!(
                decode_q6ar_from_pinned_session(&frame, &session, 1_100),
                Err(Q6arError::UnauthenticatedSession),
            );
        });
        let mut stream = TcpStream::connect(address).unwrap();
        let mut client = QRunV06NoiseSession::connect(
            &mut stream,
            &client_private,
            &server_public,
            &NETWORK,
            &PROFILE,
        )
        .unwrap();
        client.write_record(&mut stream, &wire).unwrap();
        server.join().unwrap();
    }
}
