//! Bounded TCP service for signing network-bound RTP1/TMA1 reference-time replies.
//!
//! The service has a single Ed25519 authority key and a durable per-network sequence store.
//! It signs exactly one TMA1 response per TCP connection. The authority host's OS clock is a
//! trust dependency; this service is not a distributed clock or a BFT time-consensus protocol.

use crate::{
    chain_admission::ReferenceTimeError,
    reference_time::{
        SignedReferenceTimeResponse, ATTESTATION_DOMAIN, ATTESTATION_WIRE_LEN, WIRE_VERSION,
    },
    reference_time_store::ReferenceTimeStateStore,
    reference_time_tcp::{REQUEST_BODY_LEN, REQUEST_MAGIC},
};
use ed25519_dalek::{Signer, SigningKey};
use std::{
    io::{self, Read, Write},
    net::TcpStream,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const FRAME_LENGTH_BYTES: usize = 4;
const MAX_AUTHORITY_IO: Duration = Duration::from_secs(2);

#[derive(Debug)]
pub enum ReferenceTimeAuthorityError {
    InvalidNetwork,
    InvalidSigningKey,
    RequestFrameLength,
    RequestMagic,
    RequestVersion,
    RequestNetwork,
    EmptyChallenge,
    ClockBeforeUnixEpoch,
    Sequence(ReferenceTimeError),
    Io(io::Error),
}
impl std::fmt::Display for ReferenceTimeAuthorityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidNetwork => {
                write!(f, "reference-time authority Network ID must be nonzero")
            }
            Self::InvalidSigningKey => write!(f, "reference-time authority signing key is invalid"),
            Self::RequestFrameLength => write!(f, "reference-time request frame length is invalid"),
            Self::RequestMagic => write!(f, "reference-time request magic is invalid"),
            Self::RequestVersion => write!(f, "reference-time request version is unsupported"),
            Self::RequestNetwork => write!(f, "reference-time request belongs to another network"),
            Self::EmptyChallenge => write!(f, "reference-time request challenge must be nonzero"),
            Self::ClockBeforeUnixEpoch => {
                write!(f, "authority host clock is before the Unix epoch")
            }
            Self::Sequence(error) => {
                write!(f, "reference-time sequence persistence failed: {error:?}")
            }
            Self::Io(error) => write!(f, "reference-time authority TCP I/O failed: {error}"),
        }
    }
}
impl std::error::Error for ReferenceTimeAuthorityError {}

const AUTHORITY_SEQUENCE_LEASE_SIZE: u64 = 64;

struct AuthoritySequenceLeaseState {
    next_sequence: Option<u64>,
    reserved_high_water: u64,
    last_allocated: u64,
}

/// One durable range is reserved at startup. Concurrent handlers claim individual values from
/// the shared in-memory lease; a process restart begins above the entire previous reserved range.
struct AuthoritySequenceAllocator {
    store: Arc<ReferenceTimeStateStore>,
    state: Mutex<AuthoritySequenceLeaseState>,
}

impl AuthoritySequenceAllocator {
    fn new(store: Arc<ReferenceTimeStateStore>) -> Result<Self, ReferenceTimeAuthorityError> {
        let (first, reserved_high_water) = store
            .reserve_authority_sequence_range(AUTHORITY_SEQUENCE_LEASE_SIZE)
            .map_err(ReferenceTimeAuthorityError::Sequence)?;
        Ok(Self {
            store,
            state: Mutex::new(AuthoritySequenceLeaseState {
                next_sequence: Some(first),
                reserved_high_water,
                // This is the last response allocated by this process, not the durable
                // reserved high-water inherited from an earlier process.
                last_allocated: 0,
            }),
        })
    }

    fn allocate_next(&self) -> Result<u64, ReferenceTimeAuthorityError> {
        let mut state = self.state.lock().map_err(|_| {
            ReferenceTimeAuthorityError::Sequence(ReferenceTimeError::StatePersistence)
        })?;
        let sequence = match state.next_sequence {
            Some(next) if next <= state.reserved_high_water => next,
            _ => {
                let (first, high_water) = self
                    .store
                    .reserve_authority_sequence_range(AUTHORITY_SEQUENCE_LEASE_SIZE)
                    .map_err(ReferenceTimeAuthorityError::Sequence)?;
                state.reserved_high_water = high_water;
                state.next_sequence = Some(first);
                first
            }
        };
        state.last_allocated = sequence;
        state.next_sequence = if sequence == state.reserved_high_water {
            None
        } else {
            Some(sequence + 1)
        };
        Ok(sequence)
    }

    fn last_allocated(&self) -> Result<u64, ReferenceTimeAuthorityError> {
        self.state
            .lock()
            .map(|state| state.last_allocated)
            .map_err(|_| {
                ReferenceTimeAuthorityError::Sequence(ReferenceTimeError::StatePersistence)
            })
    }

    fn reserved_high_water(&self) -> Result<u64, ReferenceTimeAuthorityError> {
        self.state
            .lock()
            .map(|state| state.reserved_high_water)
            .map_err(|_| {
                ReferenceTimeAuthorityError::Sequence(ReferenceTimeError::StatePersistence)
            })
    }
}

#[derive(Clone)]
pub struct ReferenceTimeAuthorityService {
    network_id: [u8; 32],
    signing_key: SigningKey,
    sequence_allocator: Arc<AuthoritySequenceAllocator>,
}
impl std::fmt::Debug for ReferenceTimeAuthorityService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReferenceTimeAuthorityService")
            .field("network_id", &self.network_id)
            .field("signing_key", &"<redacted>")
            .field(
                "last_allocated_sequence",
                &self.sequence_allocator.last_allocated().ok(),
            )
            .field(
                "reserved_sequence_high_water",
                &self.sequence_allocator.reserved_high_water().ok(),
            )
            .finish()
    }
}

impl ReferenceTimeAuthorityService {
    pub fn new(
        network_id: [u8; 32],
        signing_seed: [u8; 32],
        sequence_store: Arc<ReferenceTimeStateStore>,
    ) -> Result<Self, ReferenceTimeAuthorityError> {
        if network_id.iter().all(|byte| *byte == 0) {
            return Err(ReferenceTimeAuthorityError::InvalidNetwork);
        }
        if signing_seed.iter().all(|byte| *byte == 0) {
            return Err(ReferenceTimeAuthorityError::InvalidSigningKey);
        }
        let signing_key = SigningKey::from_bytes(&signing_seed);
        if signing_key.verifying_key().is_weak() {
            return Err(ReferenceTimeAuthorityError::InvalidSigningKey);
        }
        // Reserve and durably commit a bounded sequence lease before the service can answer.
        // The process can then serve concurrent clients without a storage fsync on every reply.
        let sequence_allocator = Arc::new(AuthoritySequenceAllocator::new(sequence_store)?);
        Ok(Self {
            network_id,
            signing_key,
            sequence_allocator,
        })
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Highest TMA1 sequence allocated by this running process (zero before its first reply).
    /// A restart begins a new lease; inspect reserved_sequence_high_water for the durable bound.
    pub fn last_issued_sequence(&self) -> Result<u64, ReferenceTimeAuthorityError> {
        self.sequence_allocator.last_allocated()
    }

    /// Durable upper bound of this process's current reserved lease.
    pub fn reserved_sequence_high_water(&self) -> Result<u64, ReferenceTimeAuthorityError> {
        self.sequence_allocator.reserved_high_water()
    }

    /// Read one bounded RTR1 request, durably allocate a never-reused sequence, then return its
    /// challenge-bound signed TMA1 response. Invalid requests consume no sequence.
    pub fn handle_connection(
        &self,
        stream: &mut TcpStream,
    ) -> Result<u64, ReferenceTimeAuthorityError> {
        stream
            .set_nonblocking(false)
            .map_err(ReferenceTimeAuthorityError::Io)?;
        stream
            .set_nodelay(true)
            .map_err(ReferenceTimeAuthorityError::Io)?;
        let deadline = Instant::now()
            .checked_add(MAX_AUTHORITY_IO)
            .ok_or(ReferenceTimeAuthorityError::RequestFrameLength)?;

        let mut prefix = [0u8; FRAME_LENGTH_BYTES];
        read_exact_deadline(stream, &mut prefix, deadline)?;
        if u32::from_be_bytes(prefix) as usize != REQUEST_BODY_LEN {
            return Err(ReferenceTimeAuthorityError::RequestFrameLength);
        }

        let mut request = [0u8; REQUEST_BODY_LEN];
        read_exact_deadline(stream, &mut request, deadline)?;
        if &request[..4] != REQUEST_MAGIC {
            return Err(ReferenceTimeAuthorityError::RequestMagic);
        }
        if u16::from_be_bytes(request[4..6].try_into().unwrap()) != WIRE_VERSION {
            return Err(ReferenceTimeAuthorityError::RequestVersion);
        }
        if request[6..38] != self.network_id {
            return Err(ReferenceTimeAuthorityError::RequestNetwork);
        }
        let challenge: [u8; 32] = request[38..70].try_into().unwrap();
        if challenge.iter().all(|byte| *byte == 0) {
            return Err(ReferenceTimeAuthorityError::EmptyChallenge);
        }

        // This sequence belongs to a range durably reserved before the service became ready.
        // Claiming it under the shared in-memory lease is unique across concurrent handlers. A
        // crash can skip the unused suffix but cannot cause any value in the range to be reused.
        let sequence = self.sequence_allocator.allocate_next()?;
        let unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ReferenceTimeAuthorityError::ClockBeforeUnixEpoch)?
            .as_secs();

        let mut body = Vec::with_capacity(86);
        body.extend_from_slice(b"TMA1");
        body.extend_from_slice(&WIRE_VERSION.to_be_bytes());
        body.extend_from_slice(&self.network_id);
        body.extend_from_slice(&challenge);
        body.extend_from_slice(&unix_seconds.to_be_bytes());
        body.extend_from_slice(&sequence.to_be_bytes());
        let mut signed_message = Vec::with_capacity(ATTESTATION_DOMAIN.len() + body.len());
        signed_message.extend_from_slice(ATTESTATION_DOMAIN);
        signed_message.extend_from_slice(&body);
        let signature = self.signing_key.sign(&signed_message).to_bytes();
        let response = SignedReferenceTimeResponse {
            network_id: self.network_id,
            challenge,
            unix_seconds,
            sequence,
            signature,
        }
        .encode();
        if response.len() != ATTESTATION_WIRE_LEN {
            return Err(ReferenceTimeAuthorityError::RequestFrameLength);
        }
        write_all_deadline(stream, &(response.len() as u32).to_be_bytes(), deadline)?;
        write_all_deadline(stream, &response, deadline)?;
        stream.flush().map_err(ReferenceTimeAuthorityError::Io)?;
        Ok(sequence)
    }
}

fn remaining(deadline: Instant) -> Result<Duration, ReferenceTimeAuthorityError> {
    let duration = deadline.saturating_duration_since(Instant::now());
    if duration.is_zero() {
        Err(ReferenceTimeAuthorityError::Io(io::Error::new(
            io::ErrorKind::TimedOut,
            "authority connection exceeded its total I/O deadline",
        )))
    } else {
        Ok(duration)
    }
}

fn read_exact_deadline(
    stream: &mut TcpStream,
    bytes: &mut [u8],
    deadline: Instant,
) -> Result<(), ReferenceTimeAuthorityError> {
    let mut offset = 0;
    while offset < bytes.len() {
        stream
            .set_read_timeout(Some(remaining(deadline)?))
            .map_err(ReferenceTimeAuthorityError::Io)?;
        match stream.read(&mut bytes[offset..]) {
            Ok(0) => {
                return Err(ReferenceTimeAuthorityError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated reference-time request",
                )))
            }
            Ok(count) => offset += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(ReferenceTimeAuthorityError::Io(error)),
        }
    }
    Ok(())
}

fn write_all_deadline(
    stream: &mut TcpStream,
    bytes: &[u8],
    deadline: Instant,
) -> Result<(), ReferenceTimeAuthorityError> {
    let mut offset = 0;
    while offset < bytes.len() {
        stream
            .set_write_timeout(Some(remaining(deadline)?))
            .map_err(ReferenceTimeAuthorityError::Io)?;
        match stream.write(&bytes[offset..]) {
            Ok(0) => {
                return Err(ReferenceTimeAuthorityError::Io(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "reference-time response write returned zero",
                )))
            }
            Ok(count) => offset += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(ReferenceTimeAuthorityError::Io(error)),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        reference_time::{ReferenceTimeExchange, ATTESTATION_BODY_LEN},
        reference_time_store::ReferenceTimeStateStore,
        reference_time_tcp::TcpReferenceTimeExchange,
    };
    use ed25519_dalek::VerifyingKey;
    use std::{
        fs,
        net::{TcpListener, TcpStream},
        path::PathBuf,
        thread,
        time::{SystemTime, UNIX_EPOCH},
    };

    const NETWORK: [u8; 32] = [0xD1; 32];
    const SEED: [u8; 32] = [0xD2; 32];

    fn unique_state_path() -> PathBuf {
        std::env::temp_dir().join(format!(
            "qrun-reference-authority-{}-{}.rts1",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn cleanup(path: &std::path::Path) {
        let _ = fs::remove_file(path);
        let lock = path.with_file_name(format!(
            "{}.writer.lock",
            path.file_name().unwrap().to_string_lossy()
        ));
        let _ = fs::remove_file(lock);
    }

    fn service(path: &std::path::Path) -> ReferenceTimeAuthorityService {
        let store = Arc::new(ReferenceTimeStateStore::open(path, &NETWORK).unwrap());
        ReferenceTimeAuthorityService::new(NETWORK, SEED, store).unwrap()
    }

    fn serve_one(
        service: ReferenceTimeAuthorityService,
    ) -> (
        std::net::SocketAddr,
        thread::JoinHandle<Result<u64, ReferenceTimeAuthorityError>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            service.handle_connection(&mut stream)
        });
        (address, handle)
    }

    #[test]
    fn authority_replies_with_signed_challenge_and_persists_sequence_before_return() {
        let path = unique_state_path();
        let authority = service(&path);
        let public_key = authority.public_key();
        let (address, server) = serve_one(authority.clone());
        let network = NETWORK;
        let challenge = [0xE1; 32];
        let bytes = TcpReferenceTimeExchange::new(address)
            .request(&network, &challenge, Duration::from_secs(2))
            .unwrap();
        let decoded = SignedReferenceTimeResponse::decode(&bytes).unwrap();
        assert_eq!(decoded.network_id, NETWORK);
        assert_eq!(decoded.challenge, challenge);
        assert_eq!(decoded.sequence, 1);
        assert!(decoded.unix_seconds > 0);
        let verifier = VerifyingKey::from_bytes(&public_key).unwrap();
        let mut signed = Vec::new();
        signed.extend_from_slice(ATTESTATION_DOMAIN);
        signed.extend_from_slice(&bytes[..ATTESTATION_BODY_LEN]);
        verifier
            .verify_strict(
                &signed,
                &ed25519_dalek::Signature::from_bytes(&decoded.signature),
            )
            .unwrap();
        assert_eq!(server.join().unwrap().unwrap(), 1);
        assert_eq!(authority.last_issued_sequence().unwrap(), 1);
        assert_eq!(authority.reserved_sequence_high_water().unwrap(), 64);
        drop(authority);

        let authority = service(&path);
        assert_eq!(authority.last_issued_sequence().unwrap(), 0);
        assert_eq!(authority.reserved_sequence_high_water().unwrap(), 128);
        let (address, server) = serve_one(authority.clone());
        let response = TcpReferenceTimeExchange::new(address)
            .request(&NETWORK, &[0xE2; 32], Duration::from_secs(2))
            .unwrap();
        assert_eq!(
            SignedReferenceTimeResponse::decode(&response)
                .unwrap()
                .sequence,
            AUTHORITY_SEQUENCE_LEASE_SIZE + 1
        );
        assert_eq!(
            server.join().unwrap().unwrap(),
            AUTHORITY_SEQUENCE_LEASE_SIZE + 1
        );
        drop(authority);
        cleanup(&path);
    }

    #[test]
    fn authority_rejects_wrong_network_and_malformed_requests_without_consuming_sequence() {
        let path = unique_state_path();
        let authority = service(&path);
        let (address, server) = serve_one(authority.clone());
        let result = TcpReferenceTimeExchange::new(address).request(
            &[0xD3; 32],
            &[0xE3; 32],
            Duration::from_secs(2),
        );
        assert!(result.is_err());
        assert!(server.join().unwrap().is_err());
        assert_eq!(authority.last_issued_sequence().unwrap(), 0);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server_authority = authority.clone();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            server_authority.handle_connection(&mut stream)
        });
        let mut stream = TcpStream::connect(address).unwrap();
        stream.write_all(&999u32.to_be_bytes()).unwrap();
        drop(stream);
        assert!(server.join().unwrap().is_err());
        assert_eq!(authority.last_issued_sequence().unwrap(), 0);
        drop(authority);
        cleanup(&path);
    }

    #[test]
    fn authority_allocates_unique_sequences_for_concurrent_clients() {
        let path = unique_state_path();
        let authority = service(&path);
        let listener = Arc::new(TcpListener::bind("127.0.0.1:0").unwrap());
        let address = listener.local_addr().unwrap();
        let mut workers = Vec::new();
        for _ in 0..8 {
            let server_authority = authority.clone();
            let listener = Arc::clone(&listener);
            workers.push(thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                server_authority.handle_connection(&mut stream)
            }));
        }
        // Independent accept workers share one loopback listener and one durable sequence store.
        let clients = (0..8)
            .map(|index| {
                let address = address;
                thread::spawn(move || {
                    TcpReferenceTimeExchange::new(address)
                        .request(&NETWORK, &[index as u8 + 1; 32], Duration::from_secs(2))
                        .unwrap()
                })
            })
            .collect::<Vec<_>>();
        let mut sequences = Vec::new();
        for client in clients {
            let response = client.join().unwrap();
            sequences.push(
                SignedReferenceTimeResponse::decode(&response)
                    .unwrap()
                    .sequence,
            );
        }
        for worker in workers {
            worker.join().unwrap().unwrap();
        }
        sequences.sort_unstable();
        assert_eq!(sequences, (1..=8).collect::<Vec<_>>());
        assert_eq!(authority.last_issued_sequence().unwrap(), 8);
        drop(authority);
        cleanup(&path);
    }
}
