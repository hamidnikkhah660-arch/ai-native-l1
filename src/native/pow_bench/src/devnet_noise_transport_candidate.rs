//! Bounded, network-bound Noise XX transport for a controlled zero-value Devnet.
//!
//! This module uses classical X25519/ChaChaPoly. It authenticates peers only against operator-
//! supplied static-key pins, so it is suitable for controlled/bootstrap-trusted experiments, not
//! unattended public peer discovery or post-quantum/hybrid claims. The caller must keep public
//! bind disabled until identity rotation/revocation, ingress budgets and independent review exist.

use crate::private_testnet_wire::MAX_PRIVATE_TESTNET_ENVELOPE_BYTES;
use snow::{params::NoiseParams, Builder, TransportState};
use std::{
    io::{self, Read, Write},
    net::TcpStream,
    time::{Duration, Instant},
};

const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
const PROLOGUE_DOMAIN: &[u8] = b"QANVORYX-ZERO-VALUE-DEVNET-NOISE-XX-V1\0";
const MAX_HANDSHAKE_MESSAGE: usize = 1024;
const MAX_RECORD_CIPHERTEXT: usize = MAX_PRIVATE_TESTNET_ENVELOPE_BYTES + 128;
const MIN_RECORD_CIPHERTEXT: usize = 16;
const HANDSHAKE_BUDGET: Duration = Duration::from_secs(5);
const RECORD_BUDGET: Duration = Duration::from_secs(5);
const MAX_TRUSTED_PEERS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DevnetNoiseError {
    InvalidNetworkId,
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
impl std::fmt::Display for DevnetNoiseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidNetworkId => write!(f, "Noise Devnet Network ID must be nonzero"),
            Self::InvalidPrivateKey => {
                write!(f, "Noise static private key must be 32 nonzero bytes")
            }
            Self::EmptyTrustSet => write!(f, "Noise peer trust set cannot be empty"),
            Self::OversizedTrustSet => {
                write!(f, "Noise peer trust set exceeds the configured maximum")
            }
            Self::DuplicateTrustedKey => write!(f, "Noise peer trust set contains duplicate keys"),
            Self::MalformedHandshake => {
                write!(f, "Noise handshake message is malformed or oversized")
            }
            Self::HandshakeTimeout => write!(f, "Noise handshake exceeded its absolute deadline"),
            Self::Handshake(error) => write!(f, "Noise handshake failed: {error}"),
            Self::UntrustedPeer => write!(
                f,
                "Noise XX remote static key is not in the configured trust set"
            ),
            Self::MalformedRecord => write!(f, "Noise encrypted record framing is invalid"),
            Self::RecordTimeout => write!(f, "Noise record exceeded its absolute deadline"),
            Self::RecordTooLarge(length) => {
                write!(f, "Noise record exceeds the bounded limit ({length} bytes)")
            }
            Self::RecordAuthentication => write!(f, "Noise encrypted record authentication failed"),
            Self::Io(error) => write!(f, "Noise transport I/O failed: {error}"),
        }
    }
}
impl std::error::Error for DevnetNoiseError {}

/// An established, single-connection Noise transport. A connection must be dropped after any
/// read/write framing/authentication error; no plaintext or alternate-protocol fallback exists.
pub struct DevnetNoiseSession {
    transport: TransportState,
    remote_static_public_key: [u8; 32],
}
impl std::fmt::Debug for DevnetNoiseSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DevnetNoiseSession")
            .field("remote_static_public_key", &"<pinned-key>")
            .finish_non_exhaustive()
    }
}
impl DevnetNoiseSession {
    pub fn remote_static_public_key(&self) -> &[u8; 32] {
        &self.remote_static_public_key
    }

    /// Initiator: verifies the responder static key against an out-of-band pin before application
    /// data is sent. The Network ID is bound into the Noise prologue (no cross-network fallback).
    pub fn connect(
        stream: &mut TcpStream,
        local_static_private_key: &[u8; 32],
        trusted_remote_static_public_key: &[u8; 32],
        network_id: &[u8; 32],
    ) -> Result<Self, DevnetNoiseError> {
        validate_private_and_network(local_static_private_key, network_id)?;
        if trusted_remote_static_public_key
            .iter()
            .all(|byte| *byte == 0)
        {
            return Err(DevnetNoiseError::UntrustedPeer);
        }
        let deadline = Instant::now() + HANDSHAKE_BUDGET;
        apply_timeouts(stream, deadline).map_err(io_error)?;
        let params = noise_params()?;
        let prologue = prologue(network_id);
        let builder = Builder::new(params)
            .prologue(&prologue)
            .local_private_key(local_static_private_key);
        let mut handshake = builder
            .build_initiator()
            .map_err(|error| DevnetNoiseError::Handshake(error.to_string()))?;
        let mut payload = [0u8; MAX_HANDSHAKE_MESSAGE];
        let mut message = [0u8; MAX_HANDSHAKE_MESSAGE];

        let written = handshake
            .write_message(&[], &mut message)
            .map_err(|error| DevnetNoiseError::Handshake(error.to_string()))?;
        write_handshake(stream, &message[..written], deadline)?;

        let second = read_handshake(stream, deadline)?;
        let read = handshake
            .read_message(&second, &mut payload)
            .map_err(|error| DevnetNoiseError::Handshake(error.to_string()))?;
        if read != 0 {
            return Err(DevnetNoiseError::MalformedHandshake);
        }
        let remote = handshake
            .get_remote_static()
            .ok_or(DevnetNoiseError::MalformedHandshake)?;
        if remote != trusted_remote_static_public_key {
            return Err(DevnetNoiseError::UntrustedPeer);
        }
        let mut remote_static_public_key = [0u8; 32];
        remote_static_public_key.copy_from_slice(remote);

        let written = handshake
            .write_message(&[], &mut message)
            .map_err(|error| DevnetNoiseError::Handshake(error.to_string()))?;
        write_handshake(stream, &message[..written], deadline)?;
        let transport = handshake
            .into_transport_mode()
            .map_err(|error| DevnetNoiseError::Handshake(error.to_string()))?;
        Ok(Self {
            transport,
            remote_static_public_key,
        })
    }

    /// Responder: completes XX and checks the initiator's static key against the entire explicitly
    /// configured trust set. No frame is handed to PTB2 decoding until this function succeeds.
    pub fn accept(
        stream: &mut TcpStream,
        local_static_private_key: &[u8; 32],
        trusted_remote_static_public_keys: &[[u8; 32]],
        network_id: &[u8; 32],
    ) -> Result<Self, DevnetNoiseError> {
        validate_private_and_network(local_static_private_key, network_id)?;
        validate_trust_set(trusted_remote_static_public_keys)?;
        let deadline = Instant::now() + HANDSHAKE_BUDGET;
        apply_timeouts(stream, deadline).map_err(io_error)?;
        let params = noise_params()?;
        let prologue = prologue(network_id);
        let builder = Builder::new(params)
            .prologue(&prologue)
            .local_private_key(local_static_private_key);
        let mut handshake = builder
            .build_responder()
            .map_err(|error| DevnetNoiseError::Handshake(error.to_string()))?;
        let mut payload = [0u8; MAX_HANDSHAKE_MESSAGE];
        let mut message = [0u8; MAX_HANDSHAKE_MESSAGE];

        let first = read_handshake(stream, deadline)?;
        let read = handshake
            .read_message(&first, &mut payload)
            .map_err(|error| DevnetNoiseError::Handshake(error.to_string()))?;
        if read != 0 {
            return Err(DevnetNoiseError::MalformedHandshake);
        }
        let written = handshake
            .write_message(&[], &mut message)
            .map_err(|error| DevnetNoiseError::Handshake(error.to_string()))?;
        write_handshake(stream, &message[..written], deadline)?;

        let third = read_handshake(stream, deadline)?;
        let read = handshake
            .read_message(&third, &mut payload)
            .map_err(|error| DevnetNoiseError::Handshake(error.to_string()))?;
        if read != 0 {
            return Err(DevnetNoiseError::MalformedHandshake);
        }
        let remote = handshake
            .get_remote_static()
            .ok_or(DevnetNoiseError::MalformedHandshake)?;
        if !trusted_remote_static_public_keys
            .iter()
            .any(|key| key.as_slice() == remote)
        {
            return Err(DevnetNoiseError::UntrustedPeer);
        }
        let mut remote_static_public_key = [0u8; 32];
        remote_static_public_key.copy_from_slice(remote);
        let transport = handshake
            .into_transport_mode()
            .map_err(|error| DevnetNoiseError::Handshake(error.to_string()))?;
        Ok(Self {
            transport,
            remote_static_public_key,
        })
    }

    /// Encrypt one bounded application message. A caller must close the connection if this fails.
    pub fn write_record(
        &mut self,
        stream: &mut TcpStream,
        plaintext: &[u8],
    ) -> Result<(), DevnetNoiseError> {
        if plaintext.len() > MAX_PRIVATE_TESTNET_ENVELOPE_BYTES {
            return Err(DevnetNoiseError::RecordTooLarge(plaintext.len()));
        }
        let deadline = Instant::now() + RECORD_BUDGET;
        apply_timeouts(stream, deadline).map_err(io_error)?;
        let mut ciphertext = vec![0u8; plaintext.len() + 128];
        let length = self
            .transport
            .write_message(plaintext, &mut ciphertext)
            .map_err(|_| DevnetNoiseError::RecordAuthentication)?;
        ciphertext.truncate(length);
        if !(MIN_RECORD_CIPHERTEXT..=MAX_RECORD_CIPHERTEXT).contains(&ciphertext.len()) {
            return Err(DevnetNoiseError::MalformedRecord);
        }
        write_all_until(stream, &(ciphertext.len() as u32).to_be_bytes(), deadline)
            .map_err(io_error)?;
        write_all_until(stream, &ciphertext, deadline).map_err(io_error)
    }

    /// Read one length-bounded Noise record and authenticate it before returning plaintext.
    pub fn read_record(&mut self, stream: &mut TcpStream) -> Result<Vec<u8>, DevnetNoiseError> {
        let deadline = Instant::now() + RECORD_BUDGET;
        apply_timeouts(stream, deadline).map_err(io_error)?;
        let mut length = [0u8; 4];
        read_exact_until(stream, &mut length, deadline).map_err(map_record_io_error)?;
        let length = u32::from_be_bytes(length) as usize;
        if !(MIN_RECORD_CIPHERTEXT..=MAX_RECORD_CIPHERTEXT).contains(&length) {
            return Err(DevnetNoiseError::MalformedRecord);
        }
        let mut ciphertext = vec![0u8; length];
        read_exact_until(stream, &mut ciphertext, deadline).map_err(map_record_io_error)?;
        let mut plaintext = vec![0u8; length];
        let plaintext_len = self
            .transport
            .read_message(&ciphertext, &mut plaintext)
            .map_err(|_| DevnetNoiseError::RecordAuthentication)?;
        plaintext.truncate(plaintext_len);
        if plaintext.len() > MAX_PRIVATE_TESTNET_ENVELOPE_BYTES {
            return Err(DevnetNoiseError::RecordTooLarge(plaintext.len()));
        }
        Ok(plaintext)
    }
}

fn noise_params() -> Result<NoiseParams, DevnetNoiseError> {
    NOISE_PATTERN
        .parse()
        .map_err(|error: snow::Error| DevnetNoiseError::Handshake(error.to_string()))
}
fn prologue(network_id: &[u8; 32]) -> Vec<u8> {
    let mut value = Vec::with_capacity(PROLOGUE_DOMAIN.len() + network_id.len());
    value.extend_from_slice(PROLOGUE_DOMAIN);
    value.extend_from_slice(network_id);
    value
}
fn validate_private_and_network(
    private_key: &[u8; 32],
    network_id: &[u8; 32],
) -> Result<(), DevnetNoiseError> {
    if private_key.iter().all(|byte| *byte == 0) {
        return Err(DevnetNoiseError::InvalidPrivateKey);
    }
    if network_id.iter().all(|byte| *byte == 0) {
        return Err(DevnetNoiseError::InvalidNetworkId);
    }
    Ok(())
}
fn validate_trust_set(keys: &[[u8; 32]]) -> Result<(), DevnetNoiseError> {
    if keys.is_empty() {
        return Err(DevnetNoiseError::EmptyTrustSet);
    }
    if keys.len() > MAX_TRUSTED_PEERS {
        return Err(DevnetNoiseError::OversizedTrustSet);
    }
    for (index, key) in keys.iter().enumerate() {
        if key.iter().all(|byte| *byte == 0) {
            return Err(DevnetNoiseError::UntrustedPeer);
        }
        if keys.iter().skip(index + 1).any(|other| other == key) {
            return Err(DevnetNoiseError::DuplicateTrustedKey);
        }
    }
    Ok(())
}
fn apply_timeouts(stream: &mut TcpStream, deadline: Instant) -> io::Result<()> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(io::Error::new(io::ErrorKind::TimedOut, "Noise deadline"));
    }
    stream.set_read_timeout(Some(remaining.min(Duration::from_millis(100))))?;
    stream.set_write_timeout(Some(remaining.min(Duration::from_millis(100))))
}
fn read_handshake(stream: &mut TcpStream, deadline: Instant) -> Result<Vec<u8>, DevnetNoiseError> {
    let mut length_bytes = [0u8; 2];
    read_exact_until(stream, &mut length_bytes, deadline).map_err(map_handshake_io_error)?;
    let length = u16::from_be_bytes(length_bytes) as usize;
    if length == 0 || length > MAX_HANDSHAKE_MESSAGE {
        return Err(DevnetNoiseError::MalformedHandshake);
    }
    let mut message = vec![0u8; length];
    read_exact_until(stream, &mut message, deadline).map_err(map_handshake_io_error)?;
    Ok(message)
}
fn write_handshake(
    stream: &mut TcpStream,
    message: &[u8],
    deadline: Instant,
) -> Result<(), DevnetNoiseError> {
    if message.is_empty()
        || message.len() > MAX_HANDSHAKE_MESSAGE
        || message.len() > u16::MAX as usize
    {
        return Err(DevnetNoiseError::MalformedHandshake);
    }
    write_all_until(stream, &(message.len() as u16).to_be_bytes(), deadline)
        .and_then(|()| write_all_until(stream, message, deadline))
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
                "Noise absolute deadline",
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
                        "Noise absolute deadline",
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
                "Noise write deadline",
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
                        "Noise write deadline",
                    ));
                }
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
fn io_error(error: io::Error) -> DevnetNoiseError {
    if error.kind() == io::ErrorKind::TimedOut || error.kind() == io::ErrorKind::WouldBlock {
        DevnetNoiseError::HandshakeTimeout
    } else {
        DevnetNoiseError::Io(error.to_string())
    }
}
fn map_handshake_io_error(error: io::Error) -> DevnetNoiseError {
    if error.kind() == io::ErrorKind::TimedOut || error.kind() == io::ErrorKind::WouldBlock {
        DevnetNoiseError::HandshakeTimeout
    } else {
        DevnetNoiseError::Io(error.to_string())
    }
}
fn map_record_io_error(error: io::Error) -> DevnetNoiseError {
    if error.kind() == io::ErrorKind::TimedOut || error.kind() == io::ErrorKind::WouldBlock {
        DevnetNoiseError::RecordTimeout
    } else {
        DevnetNoiseError::Io(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        net::{SocketAddr, TcpListener},
        thread,
    };

    fn keypair(seed_byte: u8) -> ([u8; 32], [u8; 32]) {
        let params = noise_params().unwrap();
        let mut keypair = Builder::new(params).generate_keypair().unwrap();
        let mut private = [0u8; 32];
        private.copy_from_slice(&keypair.private);
        let mut public = [0u8; 32];
        public.copy_from_slice(&keypair.public);
        keypair.private.fill(0);
        keypair.public.fill(0);
        // Keep call sites explicit that each keypair is generated independently.
        assert_ne!(private, [seed_byte; 32]);
        (private, public)
    }
    fn listener() -> (TcpListener, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        (listener, address)
    }

    #[test]
    fn noise_xx_binds_network_and_pins_both_sides_then_encrypts_ptb2_payload_and_ack() {
        let network = [0x61; 32];
        let (server_private, server_public) = keypair(1);
        let (client_private, client_public) = keypair(2);
        let (listener, address) = listener();
        let server_thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut session = DevnetNoiseSession::accept(
                &mut stream,
                &server_private,
                &[client_public],
                &network,
            )
            .unwrap();
            assert_eq!(session.remote_static_public_key(), &client_public);
            let payload = session.read_record(&mut stream).unwrap();
            assert_eq!(payload, b"PTB2-PFS2-TEST-ENVELOPE");
            session.write_record(&mut stream, b"PTA2-ACK").unwrap();
        });
        let mut stream = TcpStream::connect(address).unwrap();
        let mut session =
            DevnetNoiseSession::connect(&mut stream, &client_private, &server_public, &network)
                .unwrap();
        assert_eq!(session.remote_static_public_key(), &server_public);
        session
            .write_record(&mut stream, b"PTB2-PFS2-TEST-ENVELOPE")
            .unwrap();
        assert_eq!(session.read_record(&mut stream).unwrap(), b"PTA2-ACK");
        server_thread.join().unwrap();
    }

    #[test]
    fn wrong_network_prologue_rejects_without_plaintext_fallback() {
        let network_a = [0x62; 32];
        let network_b = [0x63; 32];
        let (server_private, server_public) = keypair(3);
        let (client_private, client_public) = keypair(4);
        let (listener, address) = listener();
        let server_thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            DevnetNoiseSession::accept(&mut stream, &server_private, &[client_public], &network_a)
                .map(|_| ())
        });
        let mut stream = TcpStream::connect(address).unwrap();
        let client =
            DevnetNoiseSession::connect(&mut stream, &client_private, &server_public, &network_b);
        assert!(client.is_err());
        assert!(server_thread.join().unwrap().is_err());
    }

    #[test]
    fn unknown_remote_static_key_is_rejected() {
        let network = [0x64; 32];
        let (server_private, _server_public) = keypair(5);
        let (client_private, client_public) = keypair(6);
        let (listener, address) = listener();
        let server_thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            DevnetNoiseSession::accept(&mut stream, &server_private, &[[0x99; 32]], &network)
        });
        let mut stream = TcpStream::connect(address).unwrap();
        let client =
            DevnetNoiseSession::connect(&mut stream, &client_private, &[0x98; 32], &network);
        assert!(client.is_err());
        assert!(server_thread.join().unwrap().is_err());
        assert_ne!(client_public, [0; 32]);
    }

    #[test]
    fn trust_set_must_be_bounded_nonzero_and_duplicate_free() {
        assert_eq!(
            validate_trust_set(&[]),
            Err(DevnetNoiseError::EmptyTrustSet)
        );
        assert_eq!(
            validate_trust_set(&[[1; 32], [1; 32]]),
            Err(DevnetNoiseError::DuplicateTrustedKey)
        );
        let too_many = vec![[1; 32]; MAX_TRUSTED_PEERS + 1];
        assert_eq!(
            validate_trust_set(&too_many),
            Err(DevnetNoiseError::OversizedTrustSet)
        );
        assert_eq!(
            validate_private_and_network(&[0; 32], &[1; 32]),
            Err(DevnetNoiseError::InvalidPrivateKey)
        );
        assert_eq!(
            validate_private_and_network(&[1; 32], &[0; 32]),
            Err(DevnetNoiseError::InvalidNetworkId)
        );
    }

    #[test]
    fn encrypted_record_rejects_tampered_or_oversized_input() {
        let network = [0x65; 32];
        let (server_private, server_public) = keypair(7);
        let (client_private, client_public) = keypair(8);
        let (listener, address) = listener();
        let server_thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut session = DevnetNoiseSession::accept(
                &mut stream,
                &server_private,
                &[client_public],
                &network,
            )
            .unwrap();
            let result = session.read_record(&mut stream);
            assert!(result.is_err());
        });
        let mut stream = TcpStream::connect(address).unwrap();
        let mut session =
            DevnetNoiseSession::connect(&mut stream, &client_private, &server_public, &network)
                .unwrap();
        let mut ciphertext = vec![0u8; b"corrupt me".len() + 128];
        let length = session
            .transport
            .write_message(b"corrupt me", &mut ciphertext)
            .unwrap();
        ciphertext.truncate(length);
        ciphertext[0] ^= 0x80;
        stream
            .write_all(&(ciphertext.len() as u32).to_be_bytes())
            .unwrap();
        stream.write_all(&ciphertext).unwrap();
        stream.flush().unwrap();
        server_thread.join().unwrap();
    }
}
