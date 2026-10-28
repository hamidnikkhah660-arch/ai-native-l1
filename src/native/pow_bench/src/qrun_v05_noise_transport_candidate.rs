//! Bounded, network-bound Noise XX transport for QRun v0.5 candidate peer links.
//!
//! Domain-separated from the zero-value Devnet transport; this module alone does not make the node production-ready.
//! This module uses classical X25519/ChaChaPoly. It authenticates peers only against operator-
//! supplied static-key pins, so it is suitable for controlled/bootstrap-trusted experiments, not
//! unattended public peer discovery or post-quantum/hybrid claims. The caller must keep public
//! bind disabled until identity rotation/revocation, ingress budgets and independent review exist.

use crate::{
    monetary_pow_v04_candidate::MAX_ENCODED_V04_EXECUTION_POW_ENVELOPE_BYTES,
    private_testnet_wire::{decode_candidate_network_block, MAX_CANDIDATE_NETWORK_ENVELOPE_BYTES},
};

/// Largest bounded application record for a PTB2 frame or a bounded sync response.
/// The sync response reserves space for metadata and fixed-width per-block length prefixes.
const QRUN_SYNC_RESPONSE_OVERHEAD_BYTES: usize = 256;
pub const MAX_NOISE_APPLICATION_RECORD_BYTES: usize =
    if MAX_CANDIDATE_NETWORK_ENVELOPE_BYTES > MAX_ENCODED_V04_EXECUTION_POW_ENVELOPE_BYTES {
        MAX_CANDIDATE_NETWORK_ENVELOPE_BYTES
    } else {
        MAX_ENCODED_V04_EXECUTION_POW_ENVELOPE_BYTES
    } + QRUN_SYNC_RESPONSE_OVERHEAD_BYTES;
use snow::{params::NoiseParams, Builder, TransportState};
use std::{
    io::{self, Read, Write},
    net::TcpStream,
    time::{Duration, Instant},
};

const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
const PROLOGUE_DOMAIN: &[u8] = b"QRUN-V05-VALUE-BEARING-CANDIDATE-NOISE-XX-V1\0";
const MAX_HANDSHAKE_MESSAGE: usize = 1024;
const MAX_RECORD_CIPHERTEXT: usize = MAX_NOISE_APPLICATION_RECORD_BYTES + 128;
const MIN_RECORD_CIPHERTEXT: usize = 16;
const HANDSHAKE_BUDGET: Duration = Duration::from_secs(5);
const RECORD_BUDGET: Duration = Duration::from_secs(5);
const MAX_TRUSTED_PEERS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QRunV05NoiseError {
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
    UnsupportedBlockEnvelopeMode,
    RecordAuthentication,
    Io(String),
}
impl std::fmt::Display for QRunV05NoiseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidNetworkId => write!(f, "Noise QRun v0.5 Network ID must be nonzero"),
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
            Self::UnsupportedBlockEnvelopeMode => write!(
                f,
                "Noise QRun block helper requires a canonical QFP5 fee-only envelope"
            ),
            Self::RecordAuthentication => write!(f, "Noise encrypted record authentication failed"),
            Self::Io(error) => write!(f, "Noise transport I/O failed: {error}"),
        }
    }
}
impl std::error::Error for QRunV05NoiseError {}

/// An established, single-connection Noise transport. A connection must be dropped after any
/// read/write framing/authentication error; no plaintext or alternate-protocol fallback exists.
pub struct QRunV05NoiseSession {
    transport: TransportState,
    remote_static_public_key: [u8; 32],
}
impl std::fmt::Debug for QRunV05NoiseSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QRunV05NoiseSession")
            .field("remote_static_public_key", &"<pinned-key>")
            .finish_non_exhaustive()
    }
}
impl QRunV05NoiseSession {
    pub fn remote_static_public_key(&self) -> &[u8; 32] {
        &self.remote_static_public_key
    }

    /// Initiator: verifies the responder static key and binds both network and consensus profile
    /// into the Noise prologue before application data is sent.
    pub fn connect(
        stream: &mut TcpStream,
        local_static_private_key: &[u8; 32],
        trusted_remote_static_public_key: &[u8; 32],
        network_id: &[u8; 32],
        profile_id: &[u8; 32],
    ) -> Result<Self, QRunV05NoiseError> {
        if trusted_remote_static_public_key
            .iter()
            .all(|byte| *byte == 0)
        {
            return Err(QRunV05NoiseError::UntrustedPeer);
        }
        Self::connect_with_policy(
            stream,
            local_static_private_key,
            Some(trusted_remote_static_public_key),
            network_id,
            profile_id,
        )
    }

    /// Bitcoin-style public-P2P initiator: establishes an encrypted Noise session bound to the
    /// exact network and consensus profile without requiring a preconfigured remote-key pin.
    /// The remote static key is learned from the Noise transcript, but without an out-of-band pin
    /// the remote identity is not independently authenticated. All received blocks must still pass
    /// normal consensus validation. Do not use this for RPC authorization or CAS receipts.
    pub fn connect_public(
        stream: &mut TcpStream,
        local_static_private_key: &[u8; 32],
        network_id: &[u8; 32],
        profile_id: &[u8; 32],
    ) -> Result<Self, QRunV05NoiseError> {
        Self::connect_with_policy(
            stream,
            local_static_private_key,
            None,
            network_id,
            profile_id,
        )
    }

    fn connect_with_policy(
        stream: &mut TcpStream,
        local_static_private_key: &[u8; 32],
        expected_remote_static_public_key: Option<&[u8; 32]>,
        network_id: &[u8; 32],
        profile_id: &[u8; 32],
    ) -> Result<Self, QRunV05NoiseError> {
        validate_private_and_network(local_static_private_key, network_id)?;
        validate_profile_id(profile_id)?;
        let deadline = Instant::now() + HANDSHAKE_BUDGET;
        apply_timeouts(stream, deadline).map_err(io_error)?;
        let params = noise_params()?;
        let prologue = prologue(network_id, profile_id);
        let builder = Builder::new(params)
            .prologue(&prologue)
            .local_private_key(local_static_private_key);
        let mut handshake = builder
            .build_initiator()
            .map_err(|error| QRunV05NoiseError::Handshake(error.to_string()))?;
        let mut payload = [0u8; MAX_HANDSHAKE_MESSAGE];
        let mut message = [0u8; MAX_HANDSHAKE_MESSAGE];

        let written = handshake
            .write_message(&[], &mut message)
            .map_err(|error| QRunV05NoiseError::Handshake(error.to_string()))?;
        write_handshake(stream, &message[..written], deadline)?;

        let second = read_handshake(stream, deadline)?;
        let read = handshake
            .read_message(&second, &mut payload)
            .map_err(|error| QRunV05NoiseError::Handshake(error.to_string()))?;
        if read != 0 {
            return Err(QRunV05NoiseError::MalformedHandshake);
        }
        let remote = handshake
            .get_remote_static()
            .ok_or(QRunV05NoiseError::MalformedHandshake)?;
        if let Some(expected) = expected_remote_static_public_key {
            if remote != expected {
                return Err(QRunV05NoiseError::UntrustedPeer);
            }
        }
        if remote.iter().all(|byte| *byte == 0) {
            return Err(QRunV05NoiseError::MalformedHandshake);
        }
        let mut remote_static_public_key = [0u8; 32];
        remote_static_public_key.copy_from_slice(remote);

        let written = handshake
            .write_message(&[], &mut message)
            .map_err(|error| QRunV05NoiseError::Handshake(error.to_string()))?;
        write_handshake(stream, &message[..written], deadline)?;
        let transport = handshake
            .into_transport_mode()
            .map_err(|error| QRunV05NoiseError::Handshake(error.to_string()))?;
        Ok(Self {
            transport,
            remote_static_public_key,
        })
    }

    /// Responder: completes XX and checks the initiator's static key and profile against explicit
    /// operator pins. No block frame is decoded until authentication succeeds.
    pub fn accept(
        stream: &mut TcpStream,
        local_static_private_key: &[u8; 32],
        trusted_remote_static_public_keys: &[[u8; 32]],
        network_id: &[u8; 32],
        profile_id: &[u8; 32],
    ) -> Result<Self, QRunV05NoiseError> {
        Self::accept_with_policy(
            stream,
            local_static_private_key,
            trusted_remote_static_public_keys,
            network_id,
            profile_id,
            true,
        )
    }

    /// Bitcoin-style inbound peer mode: establish an encrypted Noise session with network/profile
    /// context, without requiring an out-of-band identity pin for the remote node. The remote
    /// static key is learned from the transcript but its identity is not independently authenticated
    /// without an explicit pin. Use only for public PoW P2P whose blocks are fully validated by
    /// consensus; never use for RPC authorization or trusted checkpoint/CAS receipt signatures.
    pub fn accept_public(
        stream: &mut TcpStream,
        local_static_private_key: &[u8; 32],
        network_id: &[u8; 32],
        profile_id: &[u8; 32],
    ) -> Result<Self, QRunV05NoiseError> {
        Self::accept_with_policy(
            stream,
            local_static_private_key,
            &[],
            network_id,
            profile_id,
            false,
        )
    }

    fn accept_with_policy(
        stream: &mut TcpStream,
        local_static_private_key: &[u8; 32],
        trusted_remote_static_public_keys: &[[u8; 32]],
        network_id: &[u8; 32],
        profile_id: &[u8; 32],
        require_trusted_key: bool,
    ) -> Result<Self, QRunV05NoiseError> {
        validate_private_and_network(local_static_private_key, network_id)?;
        validate_profile_id(profile_id)?;
        if require_trusted_key {
            validate_trust_set(trusted_remote_static_public_keys)?;
        } else if trusted_remote_static_public_keys.len() > MAX_TRUSTED_PEERS {
            return Err(QRunV05NoiseError::OversizedTrustSet);
        }
        let deadline = Instant::now() + HANDSHAKE_BUDGET;
        apply_timeouts(stream, deadline).map_err(io_error)?;
        let params = noise_params()?;
        let prologue = prologue(network_id, profile_id);
        let builder = Builder::new(params)
            .prologue(&prologue)
            .local_private_key(local_static_private_key);
        let mut handshake = builder
            .build_responder()
            .map_err(|error| QRunV05NoiseError::Handshake(error.to_string()))?;
        let mut payload = [0u8; MAX_HANDSHAKE_MESSAGE];
        let mut message = [0u8; MAX_HANDSHAKE_MESSAGE];

        let first = read_handshake(stream, deadline)?;
        let read = handshake
            .read_message(&first, &mut payload)
            .map_err(|error| QRunV05NoiseError::Handshake(error.to_string()))?;
        if read != 0 {
            return Err(QRunV05NoiseError::MalformedHandshake);
        }
        let written = handshake
            .write_message(&[], &mut message)
            .map_err(|error| QRunV05NoiseError::Handshake(error.to_string()))?;
        write_handshake(stream, &message[..written], deadline)?;

        let third = read_handshake(stream, deadline)?;
        let read = handshake
            .read_message(&third, &mut payload)
            .map_err(|error| QRunV05NoiseError::Handshake(error.to_string()))?;
        if read != 0 {
            return Err(QRunV05NoiseError::MalformedHandshake);
        }
        let remote = handshake
            .get_remote_static()
            .ok_or(QRunV05NoiseError::MalformedHandshake)?;
        if require_trusted_key
            && !trusted_remote_static_public_keys
                .iter()
                .any(|key| key.as_slice() == remote)
        {
            return Err(QRunV05NoiseError::UntrustedPeer);
        }
        if remote.iter().all(|byte| *byte == 0) {
            return Err(QRunV05NoiseError::MalformedHandshake);
        }
        let mut remote_static_public_key = [0u8; 32];
        remote_static_public_key.copy_from_slice(remote);
        let transport = handshake
            .into_transport_mode()
            .map_err(|error| QRunV05NoiseError::Handshake(error.to_string()))?;
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
    ) -> Result<(), QRunV05NoiseError> {
        if plaintext.len() > MAX_NOISE_APPLICATION_RECORD_BYTES {
            return Err(QRunV05NoiseError::RecordTooLarge(plaintext.len()));
        }
        let deadline = Instant::now() + RECORD_BUDGET;
        apply_timeouts(stream, deadline).map_err(io_error)?;
        let mut ciphertext = vec![0u8; plaintext.len() + 128];
        let length = self
            .transport
            .write_message(plaintext, &mut ciphertext)
            .map_err(|_| QRunV05NoiseError::RecordAuthentication)?;
        ciphertext.truncate(length);
        if !(MIN_RECORD_CIPHERTEXT..=MAX_RECORD_CIPHERTEXT).contains(&ciphertext.len()) {
            return Err(QRunV05NoiseError::MalformedRecord);
        }
        write_all_until(stream, &(ciphertext.len() as u32).to_be_bytes(), deadline)
            .map_err(io_error)?;
        write_all_until(stream, &ciphertext, deadline).map_err(io_error)
    }

    /// Send a canonical QFP5/QFB5 block over the authenticated QRun session. This typed helper
    /// refuses legacy PTB2 envelopes and never downgrades to plaintext.
    pub fn write_qfp5_block_record(
        &mut self,
        stream: &mut TcpStream,
        envelope: &[u8],
    ) -> Result<(), QRunV05NoiseError> {
        let candidate = decode_candidate_network_block(envelope)
            .map_err(|_| QRunV05NoiseError::UnsupportedBlockEnvelopeMode)?;
        if candidate.fee_block.is_none() {
            return Err(QRunV05NoiseError::UnsupportedBlockEnvelopeMode);
        }
        self.write_record(stream, envelope)
    }

    /// Read an authenticated record and require QFP5/QFB5 before returning block bytes.
    /// Callers should discard the connection on any failure.
    pub fn read_qfp5_block_record(
        &mut self,
        stream: &mut TcpStream,
    ) -> Result<Vec<u8>, QRunV05NoiseError> {
        let envelope = self.read_record(stream)?;
        let candidate = decode_candidate_network_block(&envelope)
            .map_err(|_| QRunV05NoiseError::UnsupportedBlockEnvelopeMode)?;
        if candidate.fee_block.is_none() {
            return Err(QRunV05NoiseError::UnsupportedBlockEnvelopeMode);
        }
        Ok(envelope)
    }

    /// Read one length-bounded Noise record and authenticate it before returning plaintext.
    pub fn read_record(&mut self, stream: &mut TcpStream) -> Result<Vec<u8>, QRunV05NoiseError> {
        let deadline = Instant::now() + RECORD_BUDGET;
        apply_timeouts(stream, deadline).map_err(io_error)?;
        let mut length = [0u8; 4];
        read_exact_until(stream, &mut length, deadline).map_err(map_record_io_error)?;
        let length = u32::from_be_bytes(length) as usize;
        if !(MIN_RECORD_CIPHERTEXT..=MAX_RECORD_CIPHERTEXT).contains(&length) {
            return Err(QRunV05NoiseError::MalformedRecord);
        }
        let mut ciphertext = vec![0u8; length];
        read_exact_until(stream, &mut ciphertext, deadline).map_err(map_record_io_error)?;
        let mut plaintext = vec![0u8; length];
        let plaintext_len = self
            .transport
            .read_message(&ciphertext, &mut plaintext)
            .map_err(|_| QRunV05NoiseError::RecordAuthentication)?;
        plaintext.truncate(plaintext_len);
        if plaintext.len() > MAX_NOISE_APPLICATION_RECORD_BYTES {
            return Err(QRunV05NoiseError::RecordTooLarge(plaintext.len()));
        }
        Ok(plaintext)
    }
}

fn noise_params() -> Result<NoiseParams, QRunV05NoiseError> {
    NOISE_PATTERN
        .parse()
        .map_err(|error: snow::Error| QRunV05NoiseError::Handshake(error.to_string()))
}
fn prologue(network_id: &[u8; 32], profile_id: &[u8; 32]) -> Vec<u8> {
    let mut value = Vec::with_capacity(PROLOGUE_DOMAIN.len() + network_id.len() + profile_id.len());
    value.extend_from_slice(PROLOGUE_DOMAIN);
    value.extend_from_slice(network_id);
    value.extend_from_slice(profile_id);
    value
}

fn validate_profile_id(profile_id: &[u8; 32]) -> Result<(), QRunV05NoiseError> {
    if profile_id.iter().all(|byte| *byte == 0) {
        return Err(QRunV05NoiseError::InvalidNetworkId);
    }
    Ok(())
}
fn validate_private_and_network(
    private_key: &[u8; 32],
    network_id: &[u8; 32],
) -> Result<(), QRunV05NoiseError> {
    if private_key.iter().all(|byte| *byte == 0) {
        return Err(QRunV05NoiseError::InvalidPrivateKey);
    }
    if network_id.iter().all(|byte| *byte == 0) {
        return Err(QRunV05NoiseError::InvalidNetworkId);
    }
    Ok(())
}
fn validate_trust_set(keys: &[[u8; 32]]) -> Result<(), QRunV05NoiseError> {
    if keys.is_empty() {
        return Err(QRunV05NoiseError::EmptyTrustSet);
    }
    if keys.len() > MAX_TRUSTED_PEERS {
        return Err(QRunV05NoiseError::OversizedTrustSet);
    }
    for (index, key) in keys.iter().enumerate() {
        if key.iter().all(|byte| *byte == 0) {
            return Err(QRunV05NoiseError::UntrustedPeer);
        }
        if keys.iter().skip(index + 1).any(|other| other == key) {
            return Err(QRunV05NoiseError::DuplicateTrustedKey);
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
fn read_handshake(stream: &mut TcpStream, deadline: Instant) -> Result<Vec<u8>, QRunV05NoiseError> {
    let mut length_bytes = [0u8; 2];
    read_exact_until(stream, &mut length_bytes, deadline).map_err(map_handshake_io_error)?;
    let length = u16::from_be_bytes(length_bytes) as usize;
    if length == 0 || length > MAX_HANDSHAKE_MESSAGE {
        return Err(QRunV05NoiseError::MalformedHandshake);
    }
    let mut message = vec![0u8; length];
    read_exact_until(stream, &mut message, deadline).map_err(map_handshake_io_error)?;
    Ok(message)
}
fn write_handshake(
    stream: &mut TcpStream,
    message: &[u8],
    deadline: Instant,
) -> Result<(), QRunV05NoiseError> {
    if message.is_empty()
        || message.len() > MAX_HANDSHAKE_MESSAGE
        || message.len() > u16::MAX as usize
    {
        return Err(QRunV05NoiseError::MalformedHandshake);
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
fn io_error(error: io::Error) -> QRunV05NoiseError {
    if error.kind() == io::ErrorKind::TimedOut || error.kind() == io::ErrorKind::WouldBlock {
        QRunV05NoiseError::HandshakeTimeout
    } else {
        QRunV05NoiseError::Io(error.to_string())
    }
}
fn map_handshake_io_error(error: io::Error) -> QRunV05NoiseError {
    if error.kind() == io::ErrorKind::TimedOut || error.kind() == io::ErrorKind::WouldBlock {
        QRunV05NoiseError::HandshakeTimeout
    } else {
        QRunV05NoiseError::Io(error.to_string())
    }
}
fn map_record_io_error(error: io::Error) -> QRunV05NoiseError {
    if error.kind() == io::ErrorKind::TimedOut || error.kind() == io::ErrorKind::WouldBlock {
        QRunV05NoiseError::RecordTimeout
    } else {
        QRunV05NoiseError::Io(error.to_string())
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

    fn qfp5_test_envelope() -> ([u8; 32], Vec<u8>) {
        use crate::{
            consensus::{PowHeader, Uint256},
            qrun_v05_fee_pow_wire_candidate::{
                encode_qrun_v05_fee_pow_block, qrun_v05_fee_pow_state_commitment,
            },
            state_machine::{
                Block, LedgerState, QRunV05FeeBlock, TransactionAuthenticator,
                MAX_TOTAL_SUPPLY_ATOMS,
            },
        };
        struct EmptyAuth;
        impl TransactionAuthenticator for EmptyAuth {
            fn verify(&self, _: &[u8; 32], _: &[u8; 32], _: &[u8]) -> Result<(), ()> {
                Err(())
            }
        }

        let network = [0x61; 32];
        let owner = [0x42; 32];
        let genesis =
            LedgerState::genesis(network, vec![(owner, MAX_TOTAL_SUPPLY_ATOMS as u64)]).unwrap();
        let mut fee_block = QRunV05FeeBlock {
            body: Block {
                height: 1,
                timestamp: 1,
                parent_hash: genesis.tip_hash(),
                state_root: [0; 32],
                transactions: Vec::new(),
            },
            producer: [0x77; 32],
        };
        fee_block.body.state_root = genesis
            .preview_qrun_v05_fee_state_root_after(&fee_block, &EmptyAuth)
            .unwrap();
        let header = PowHeader {
            protocol_version: 5,
            network_id: network,
            height: 1,
            timestamp: 1,
            parent_hash: fee_block.body.parent_hash,
            previous_consensus_hash: genesis.tip_hash(),
            state_root: qrun_v05_fee_pow_state_commitment(&fee_block).unwrap(),
            target: Uint256::MAX,
            nonce: 7,
        };
        (
            network,
            encode_qrun_v05_fee_pow_block(&header, &fee_block).unwrap(),
        )
    }

    #[test]
    fn prologue_domain_is_qrun_specific_and_binds_network_and_profile_fingerprint() {
        let network = [0x52; 32];
        let profile = [0x72; 32];
        let actual = prologue(&network, &profile);
        assert!(actual.starts_with(b"QRUN-V05-VALUE-BEARING-CANDIDATE-NOISE-XX-V1\0"));
        assert!(actual.ends_with(&[network.as_slice(), profile.as_slice()].concat()));
        assert_ne!(
            actual,
            [
                b"QANVORYX-ZERO-VALUE-DEVNET-NOISE-XX-V1\0".as_slice(),
                &network
            ]
            .concat()
        );
    }

    #[test]
    fn application_record_budget_covers_the_largest_canonical_candidate_envelope() {
        assert_eq!(
            MAX_NOISE_APPLICATION_RECORD_BYTES,
            MAX_CANDIDATE_NETWORK_ENVELOPE_BYTES.max(MAX_ENCODED_V04_EXECUTION_POW_ENVELOPE_BYTES)
                + QRUN_SYNC_RESPONSE_OVERHEAD_BYTES
        );
        assert!(MAX_NOISE_APPLICATION_RECORD_BYTES >= MAX_ENCODED_V04_EXECUTION_POW_ENVELOPE_BYTES);
    }
    #[test]
    fn noise_qfp5_typed_record_roundtrips_and_refuses_legacy_block_payloads() {
        let (network, envelope) = qfp5_test_envelope();
        let profile = [0x71; 32];
        let (server_private, server_public) = keypair(11);
        let (client_private, client_public) = keypair(12);
        let (listener, address) = listener();

        let server_envelope = envelope.clone();
        let server_thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut session = QRunV05NoiseSession::accept(
                &mut stream,
                &server_private,
                &[client_public],
                &network,
                &profile,
            )
            .unwrap();
            let received = session.read_qfp5_block_record(&mut stream).unwrap();
            assert_eq!(received, server_envelope);
            session.write_record(&mut stream, b"QFP5-ACK").unwrap();
        });

        let mut stream = TcpStream::connect(address).unwrap();
        let mut session = QRunV05NoiseSession::connect(
            &mut stream,
            &client_private,
            &server_public,
            &network,
            &profile,
        )
        .unwrap();
        session
            .write_qfp5_block_record(&mut stream, &envelope)
            .unwrap();
        assert_eq!(session.read_record(&mut stream).unwrap(), b"QFP5-ACK");
        assert_eq!(
            session.write_qfp5_block_record(&mut stream, b"PTB2-legacy"),
            Err(QRunV05NoiseError::UnsupportedBlockEnvelopeMode)
        );
        server_thread.join().unwrap();
    }

    #[test]
    fn noise_qfp5_typed_reader_rejects_a_legacy_payload_after_authentication() {
        let (network, _) = qfp5_test_envelope();
        let profile = [0x72; 32];
        let (server_private, server_public) = keypair(13);
        let (client_private, client_public) = keypair(14);
        let (listener, address) = listener();

        let server_thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut session = QRunV05NoiseSession::accept(
                &mut stream,
                &server_private,
                &[client_public],
                &network,
                &profile,
            )
            .unwrap();
            session.read_qfp5_block_record(&mut stream)
        });

        let mut stream = TcpStream::connect(address).unwrap();
        let mut session = QRunV05NoiseSession::connect(
            &mut stream,
            &client_private,
            &server_public,
            &network,
            &profile,
        )
        .unwrap();
        session
            .write_record(&mut stream, b"PTB2-legacy-only")
            .unwrap();
        assert_eq!(
            server_thread.join().unwrap(),
            Err(QRunV05NoiseError::UnsupportedBlockEnvelopeMode)
        );
    }

    #[test]
    fn noise_xx_binds_network_and_pins_both_sides_then_encrypts_ptb2_payload_and_ack() {
        let network = [0x61; 32];
        let profile = [0x71; 32];
        let (server_private, server_public) = keypair(1);
        let (client_private, client_public) = keypair(2);
        let (listener, address) = listener();
        let server_thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut session = QRunV05NoiseSession::accept(
                &mut stream,
                &server_private,
                &[client_public],
                &network,
                &profile,
            )
            .unwrap();
            assert_eq!(session.remote_static_public_key(), &client_public);
            let payload = session.read_record(&mut stream).unwrap();
            assert_eq!(payload, b"PTB2-PFS2-TEST-ENVELOPE");
            session.write_record(&mut stream, b"PTA2-ACK").unwrap();
        });
        let mut stream = TcpStream::connect(address).unwrap();
        let mut session = QRunV05NoiseSession::connect(
            &mut stream,
            &client_private,
            &server_public,
            &network,
            &profile,
        )
        .unwrap();
        assert_eq!(session.remote_static_public_key(), &server_public);
        session
            .write_record(&mut stream, b"PTB2-PFS2-TEST-ENVELOPE")
            .unwrap();
        assert_eq!(session.read_record(&mut stream).unwrap(), b"PTA2-ACK");
        server_thread.join().unwrap();
    }

    #[test]
    fn public_inbound_noise_accepts_unpinned_peer_but_binds_network_and_profile() {
        let network = [0x62; 32];
        let profile = [0x72; 32];
        let (server_private, _server_public) = keypair(31);
        let (client_private, client_public) = keypair(32);
        let (listener, address) = listener();
        let server_thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut session = QRunV05NoiseSession::accept_public(
                &mut stream,
                &server_private,
                &network,
                &profile,
            )
            .unwrap();
            assert_eq!(session.remote_static_public_key(), &client_public);
            let request = session.read_record(&mut stream).unwrap();
            assert_eq!(request, b"public-alpha-block-frame");
            session
                .write_record(&mut stream, b"public-alpha-ack")
                .unwrap();
        });
        // Public P2P learns a peer's static key from the Noise transcript rather than needing
        // an operator to provision every remote public key in advance.
        let mut stream = TcpStream::connect(address).unwrap();
        let mut session =
            QRunV05NoiseSession::connect_public(&mut stream, &client_private, &network, &profile)
                .unwrap();
        session
            .write_record(&mut stream, b"public-alpha-block-frame")
            .unwrap();
        assert_eq!(
            session.read_record(&mut stream).unwrap(),
            b"public-alpha-ack"
        );
        server_thread.join().unwrap();
    }

    #[test]
    fn wrong_network_prologue_rejects_without_plaintext_fallback() {
        let network_a = [0x62; 32];
        let network_b = [0x63; 32];
        let profile = [0x73; 32];
        let (server_private, server_public) = keypair(3);
        let (client_private, client_public) = keypair(4);
        let (listener, address) = listener();
        let server_thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            QRunV05NoiseSession::accept(
                &mut stream,
                &server_private,
                &[client_public],
                &network_a,
                &profile,
            )
            .map(|_| ())
        });
        let mut stream = TcpStream::connect(address).unwrap();
        let client = QRunV05NoiseSession::connect(
            &mut stream,
            &client_private,
            &server_public,
            &network_b,
            &profile,
        );
        assert!(client.is_err());
        assert!(server_thread.join().unwrap().is_err());
    }

    #[test]
    fn wrong_profile_fingerprint_rejects_without_plaintext_fallback() {
        let network = [0x68; 32];
        let profile_a = [0x78; 32];
        let profile_b = [0x79; 32];
        let (server_private, server_public) = keypair(9);
        let (client_private, client_public) = keypair(10);
        let (listener, address) = listener();
        let server_thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            QRunV05NoiseSession::accept(
                &mut stream,
                &server_private,
                &[client_public],
                &network,
                &profile_a,
            )
            .map(|_| ())
        });
        let mut stream = TcpStream::connect(address).unwrap();
        let client = QRunV05NoiseSession::connect(
            &mut stream,
            &client_private,
            &server_public,
            &network,
            &profile_b,
        );
        assert!(client.is_err());
        assert!(server_thread.join().unwrap().is_err());
    }

    #[test]
    fn unknown_remote_static_key_is_rejected() {
        let network = [0x64; 32];
        let profile = [0x74; 32];
        let (server_private, _server_public) = keypair(5);
        let (client_private, client_public) = keypair(6);
        let (listener, address) = listener();
        let server_thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            QRunV05NoiseSession::accept(
                &mut stream,
                &server_private,
                &[[0x99; 32]],
                &network,
                &profile,
            )
        });
        let mut stream = TcpStream::connect(address).unwrap();
        let client = QRunV05NoiseSession::connect(
            &mut stream,
            &client_private,
            &[0x98; 32],
            &network,
            &profile,
        );
        assert!(client.is_err());
        assert!(server_thread.join().unwrap().is_err());
        assert_ne!(client_public, [0; 32]);
    }

    #[test]
    fn trust_set_must_be_bounded_nonzero_and_duplicate_free() {
        assert_eq!(
            validate_trust_set(&[]),
            Err(QRunV05NoiseError::EmptyTrustSet)
        );
        assert_eq!(
            validate_trust_set(&[[1; 32], [1; 32]]),
            Err(QRunV05NoiseError::DuplicateTrustedKey)
        );
        let too_many = vec![[1; 32]; MAX_TRUSTED_PEERS + 1];
        assert_eq!(
            validate_trust_set(&too_many),
            Err(QRunV05NoiseError::OversizedTrustSet)
        );
        assert_eq!(
            validate_private_and_network(&[0; 32], &[1; 32]),
            Err(QRunV05NoiseError::InvalidPrivateKey)
        );
        assert_eq!(
            validate_private_and_network(&[1; 32], &[0; 32]),
            Err(QRunV05NoiseError::InvalidNetworkId)
        );
        assert_eq!(
            validate_profile_id(&[0; 32]),
            Err(QRunV05NoiseError::InvalidNetworkId)
        );
    }

    #[test]
    fn encrypted_record_rejects_tampered_or_oversized_input() {
        let network = [0x65; 32];
        let profile = [0x75; 32];
        let (server_private, server_public) = keypair(7);
        let (client_private, client_public) = keypair(8);
        let (listener, address) = listener();
        let server_thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut session = QRunV05NoiseSession::accept(
                &mut stream,
                &server_private,
                &[client_public],
                &network,
                &profile,
            )
            .unwrap();
            let result = session.read_record(&mut stream);
            assert!(result.is_err());
        });
        let mut stream = TcpStream::connect(address).unwrap();
        let mut session = QRunV05NoiseSession::connect(
            &mut stream,
            &client_private,
            &server_public,
            &network,
            &profile,
        )
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
