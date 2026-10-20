//! Bounded TCP transport for the authenticated reference-time protocol.
//!
//! Wire format: u32-be payload length, then RTR1 | u16-be version | network_id[32] |
//! challenge[32]. The response is u32-be length (=150), followed by the fixed-size TMA1
//! attestation defined by reference_time.rs. Use a numeric SocketAddr so name resolution
//! cannot silently exceed this adapter's I/O deadline.
use crate::{
    chain_admission::ReferenceTimeError,
    reference_time::{ReferenceTimeExchange, ATTESTATION_WIRE_LEN, WIRE_VERSION},
};
use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    time::{Duration, Instant},
};

pub const REQUEST_MAGIC: &[u8; 4] = b"RTR1";
pub const REQUEST_BODY_LEN: usize = 4 + 2 + 32 + 32;
const FRAME_LENGTH_LEN: usize = 4;
const MAX_TIME_RESPONSE: usize = ATTESTATION_WIRE_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpReferenceTimeExchange {
    address: SocketAddr,
}

impl TcpReferenceTimeExchange {
    pub fn new(address: SocketAddr) -> Self {
        Self { address }
    }

    pub fn address(&self) -> SocketAddr {
        self.address
    }
}

impl ReferenceTimeExchange for TcpReferenceTimeExchange {
    fn request(
        &self,
        network_id: &[u8; 32],
        challenge: &[u8; 32],
        timeout: Duration,
    ) -> Result<Vec<u8>, ReferenceTimeError> {
        if timeout.is_zero() {
            return Err(ReferenceTimeError::StaleResponse);
        }
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(ReferenceTimeError::StaleResponse)?;
        let mut stream =
            TcpStream::connect_timeout(&self.address, timeout).map_err(map_io_error)?;
        stream.set_nodelay(true).map_err(map_io_error)?;
        write_deadline(
            &mut stream,
            &(REQUEST_BODY_LEN as u32).to_be_bytes(),
            deadline,
        )?;
        let mut request = Vec::with_capacity(REQUEST_BODY_LEN);
        request.extend_from_slice(REQUEST_MAGIC);
        request.extend_from_slice(&WIRE_VERSION.to_be_bytes());
        request.extend_from_slice(network_id);
        request.extend_from_slice(challenge);
        debug_assert_eq!(request.len(), REQUEST_BODY_LEN);
        write_deadline(&mut stream, &request, deadline)?;

        let mut frame_len = [0u8; FRAME_LENGTH_LEN];
        read_exact_deadline(&mut stream, &mut frame_len, deadline)?;
        let length = u32::from_be_bytes(frame_len) as usize;
        if length != MAX_TIME_RESPONSE {
            return Err(ReferenceTimeError::AttestationMalformed);
        }
        let mut response = vec![0u8; length];
        read_exact_deadline(&mut stream, &mut response, deadline)?;
        Ok(response)
    }
}

fn remaining(deadline: Instant) -> Result<Duration, ReferenceTimeError> {
    let duration = deadline.saturating_duration_since(Instant::now());
    if duration.is_zero() {
        Err(ReferenceTimeError::StaleResponse)
    } else {
        Ok(duration)
    }
}

fn write_deadline(
    stream: &mut TcpStream,
    bytes: &[u8],
    deadline: Instant,
) -> Result<(), ReferenceTimeError> {
    let mut offset = 0;
    while offset < bytes.len() {
        stream
            .set_write_timeout(Some(remaining(deadline)?))
            .map_err(map_io_error)?;
        match stream.write(&bytes[offset..]) {
            Ok(0) => return Err(ReferenceTimeError::ProviderUnavailable),
            Ok(n) => offset += n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(map_io_error(error)),
        }
    }
    Ok(())
}

fn read_exact_deadline(
    stream: &mut TcpStream,
    bytes: &mut [u8],
    deadline: Instant,
) -> Result<(), ReferenceTimeError> {
    let mut offset = 0;
    while offset < bytes.len() {
        stream
            .set_read_timeout(Some(remaining(deadline)?))
            .map_err(map_io_error)?;
        match stream.read(&mut bytes[offset..]) {
            Ok(0) => return Err(ReferenceTimeError::AttestationMalformed),
            Ok(n) => offset += n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(map_io_error(error)),
        }
    }
    Ok(())
}

fn map_io_error(error: io::Error) -> ReferenceTimeError {
    match error.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => ReferenceTimeError::StaleResponse,
        _ => ReferenceTimeError::ProviderUnavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chain_admission::ReferenceTimeProvider,
        reference_time::{
            AuthenticatedReferenceTimeProvider, VerifiedReferenceTimePolicy, ATTESTATION_BODY_LEN,
            ATTESTATION_DOMAIN, ATTESTATION_MAGIC, POLICY_BODY_LEN, POLICY_DOMAIN, POLICY_MAGIC,
        },
        reference_time_store::ReferenceTimeStateStore,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use std::{
        env, fs,
        net::TcpListener,
        process::{Command, Stdio},
        thread,
        time::{SystemTime, UNIX_EPOCH},
    };

    const NETWORK: [u8; 32] = [0xA5; 32];
    const ADMIN_SEED: [u8; 32] = [0x42; 32];
    const AUTHORITY_A: [u8; 32] = [0x24; 32];
    const AUTHORITY_B: [u8; 32] = [0x31; 32];
    const CHILD_FLAG: &str = "AIN1_CP0026K_AUTHORITY_CLIENT_CHILD";

    fn key(seed: [u8; 32]) -> SigningKey {
        SigningKey::from_bytes(&seed)
    }

    fn signed_policy(policy_sequence: u64, authority_seed: [u8; 32]) -> Vec<u8> {
        let admin = key(ADMIN_SEED);
        let mut body = Vec::with_capacity(POLICY_BODY_LEN);
        body.extend_from_slice(POLICY_MAGIC);
        body.extend_from_slice(&WIRE_VERSION.to_be_bytes());
        body.extend_from_slice(&NETWORK);
        body.extend_from_slice(&policy_sequence.to_be_bytes());
        body.extend_from_slice(&key(authority_seed).verifying_key().to_bytes());
        body.extend_from_slice(&500u32.to_be_bytes());
        body.extend_from_slice(&u64::MAX.to_be_bytes());
        let signed = [POLICY_DOMAIN, body.as_slice()].concat();
        body.extend_from_slice(&admin.sign(&signed).to_bytes());
        body
    }

    fn signed_response(
        authority_seed: [u8; 32],
        network: [u8; 32],
        challenge: [u8; 32],
        unix_seconds: u64,
        sequence: u64,
    ) -> Vec<u8> {
        let authority = key(authority_seed);
        let mut body = Vec::with_capacity(ATTESTATION_WIRE_LEN);
        body.extend_from_slice(ATTESTATION_MAGIC);
        body.extend_from_slice(&WIRE_VERSION.to_be_bytes());
        body.extend_from_slice(&network);
        body.extend_from_slice(&challenge);
        body.extend_from_slice(&unix_seconds.to_be_bytes());
        body.extend_from_slice(&sequence.to_be_bytes());
        assert_eq!(body.len(), ATTESTATION_BODY_LEN);
        let message = [ATTESTATION_DOMAIN, body.as_slice()].concat();
        body.extend_from_slice(&authority.sign(&message).to_bytes());
        body
    }

    fn temp_state_path() -> std::path::PathBuf {
        env::temp_dir().join(format!(
            "ain1-cp0026k-process-test-{}-{}.bin",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    /// Invoked by the current test process normally (no-op), and by its parent test as an
    /// independent OS process over TCP. The private test seeds are deterministic test fixtures.
    #[test]
    fn authority_client_subprocess_entry() {
        if env::var(CHILD_FLAG).as_deref() != Ok("1") {
            return;
        }
        let address: SocketAddr = env::var("AIN1_CP0026K_ADDRESS").unwrap().parse().unwrap();
        let state_path = env::var("AIN1_CP0026K_STATE").unwrap();
        let policy_sequence: u64 = env::var("AIN1_CP0026K_POLICY_SEQ")
            .unwrap()
            .parse()
            .unwrap();
        let authority_seed = match env::var("AIN1_CP0026K_AUTHORITY").unwrap().as_str() {
            "A" => AUTHORITY_A,
            "B" => AUTHORITY_B,
            _ => panic!("unknown test authority fixture"),
        };
        let expectation = env::var("AIN1_CP0026K_EXPECT").unwrap();
        let expected_response_sequence: u64 = env::var("AIN1_CP0026K_RESPONSE_SEQ")
            .unwrap()
            .parse()
            .unwrap();
        let store = ReferenceTimeStateStore::open(&state_path, &NETWORK).unwrap();
        let admin = key(ADMIN_SEED);
        let policy_wire = signed_policy(policy_sequence, authority_seed);
        let policy = VerifiedReferenceTimePolicy::verify(
            &policy_wire,
            &NETWORK,
            &admin.verifying_key().to_bytes(),
            &store.policy_trust_state().unwrap(),
        )
        .unwrap();
        let provider = AuthenticatedReferenceTimeProvider::new_persistent(
            policy,
            TcpReferenceTimeExchange::new(address),
            store,
        )
        .unwrap();
        match expectation.as_str() {
            "accept" => {
                let sample = provider.sample().unwrap();
                assert!(sample.unix_seconds > 0);
                assert_eq!(
                    provider.last_accepted_sequence(),
                    expected_response_sequence
                );
            }
            "rollback" => {
                assert_eq!(provider.sample(), Err(ReferenceTimeError::SequenceRollback));
                assert_eq!(provider.last_accepted_sequence(), 42);
            }
            _ => panic!("unknown child expectation"),
        }
    }

    fn spawn_authority_client(
        state_path: &std::path::Path,
        policy_sequence: u64,
        authority_label: &str,
        response_sequence: u64,
        expectation: &str,
        delayed: Duration,
    ) -> (std::process::Output, Result<(), String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(false).unwrap();
        let address = listener.local_addr().unwrap();
        let authority_seed = if authority_label == "A" {
            AUTHORITY_A
        } else {
            AUTHORITY_B
        };
        let server = thread::spawn(move || -> Result<(), String> {
            listener.set_nonblocking(true).map_err(|e| e.to_string())?;
            let until = Instant::now() + Duration::from_secs(5);
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(pair) => break pair,
                    Err(error)
                        if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < until =>
                    {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => return Err(format!("authority accept failed: {error}")),
                }
            };
            // Windows may carry the listener's nonblocking mode onto an accepted socket. Restore
            // blocking mode explicitly before relying on read/write timeouts and read_exact.
            stream.set_nonblocking(false).map_err(|e| e.to_string())?;
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .map_err(|e| e.to_string())?;
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .map_err(|e| e.to_string())?;
            let mut length = [0u8; 4];
            stream.read_exact(&mut length).map_err(|e| e.to_string())?;
            if u32::from_be_bytes(length) as usize != REQUEST_BODY_LEN {
                return Err("client request frame length invalid".into());
            }
            let mut request = vec![0; REQUEST_BODY_LEN];
            stream.read_exact(&mut request).map_err(|e| e.to_string())?;
            if &request[..4] != REQUEST_MAGIC
                || u16::from_be_bytes(request[4..6].try_into().unwrap()) != WIRE_VERSION
                || request[6..38] != NETWORK
            {
                return Err("client request header/network invalid".into());
            }
            let challenge: [u8; 32] = request[38..70].try_into().unwrap();
            if !delayed.is_zero() {
                thread::sleep(delayed);
            }
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| e.to_string())?
                .as_secs();
            let response =
                signed_response(authority_seed, NETWORK, challenge, now, response_sequence);
            stream
                .write_all(&(response.len() as u32).to_be_bytes())
                .map_err(|e| e.to_string())?;
            stream.write_all(&response).map_err(|e| e.to_string())?;
            stream.flush().map_err(|e| e.to_string())?;
            Ok(())
        });

        let executable = env::current_exe().unwrap();
        let output = Command::new(executable)
            .args([
                "--exact",
                "reference_time_tcp::tests::authority_client_subprocess_entry",
                "--nocapture",
            ])
            .env(CHILD_FLAG, "1")
            .env("AIN1_CP0026K_ADDRESS", address.to_string())
            .env("AIN1_CP0026K_STATE", state_path)
            .env("AIN1_CP0026K_POLICY_SEQ", policy_sequence.to_string())
            .env("AIN1_CP0026K_AUTHORITY", authority_label)
            .env("AIN1_CP0026K_EXPECT", expectation)
            .env("AIN1_CP0026K_RESPONSE_SEQ", response_sequence.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .unwrap();
        (output, server.join().unwrap())
    }

    #[test]
    fn signed_tcp_replies_persist_across_process_restart_and_authority_rotation() {
        let state_path = temp_state_path();

        let (first, server) =
            spawn_authority_client(&state_path, 1, "A", 42, "accept", Duration::ZERO);
        assert!(
            first.status.success(),
            "child process failed: {}; test server result: {:?}",
            String::from_utf8_lossy(&first.stderr),
            server
        );
        server.unwrap();
        {
            let store = ReferenceTimeStateStore::open(&state_path, &NETWORK).unwrap();
            assert_eq!(store.last_accepted_sequence().unwrap(), 42);
            assert_eq!(store.policy_trust_state().unwrap().highest_sequence(), 1);
        }

        let (replay, server) =
            spawn_authority_client(&state_path, 1, "A", 41, "rollback", Duration::ZERO);
        assert!(
            replay.status.success(),
            "rollback child failed: {}; test server result: {:?}",
            String::from_utf8_lossy(&replay.stderr),
            server
        );
        server.unwrap();
        {
            let store = ReferenceTimeStateStore::open(&state_path, &NETWORK).unwrap();
            assert_eq!(store.last_accepted_sequence().unwrap(), 42);
            assert_eq!(store.policy_trust_state().unwrap().highest_sequence(), 1);
        }

        let (rotated, server) =
            spawn_authority_client(&state_path, 2, "B", 43, "accept", Duration::ZERO);
        assert!(
            rotated.status.success(),
            "rotation child failed: {}; test server result: {:?}",
            String::from_utf8_lossy(&rotated.stderr),
            server
        );
        server.unwrap();
        {
            let store = ReferenceTimeStateStore::open(&state_path, &NETWORK).unwrap();
            assert_eq!(store.last_accepted_sequence().unwrap(), 43);
            assert_eq!(store.policy_trust_state().unwrap().highest_sequence(), 2);
        }
        cleanup_state_file(&state_path);
    }

    #[test]
    fn tcp_adapter_enforces_total_io_deadline_and_rejects_bad_frame_length() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut prefix = [0u8; 4];
            stream.read_exact(&mut prefix).unwrap();
            let mut request = vec![0; u32::from_be_bytes(prefix) as usize];
            stream.read_exact(&mut request).unwrap();
            thread::sleep(Duration::from_millis(100));
            let _ = stream.write_all(&(ATTESTATION_WIRE_LEN as u32).to_be_bytes());
        });
        let exchange = TcpReferenceTimeExchange::new(address);
        let result = exchange.request(&NETWORK, &[7; 32], Duration::from_millis(25));
        assert_eq!(result, Err(ReferenceTimeError::StaleResponse));
        server.join().unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut prefix = [0u8; 4];
            stream.read_exact(&mut prefix).unwrap();
            let mut request = vec![0; u32::from_be_bytes(prefix) as usize];
            stream.read_exact(&mut request).unwrap();
            stream.write_all(&999u32.to_be_bytes()).unwrap();
        });
        assert_eq!(
            TcpReferenceTimeExchange::new(address).request(
                &NETWORK,
                &[3; 32],
                Duration::from_millis(500)
            ),
            Err(ReferenceTimeError::AttestationMalformed)
        );
        server.join().unwrap();
    }

    fn cleanup_state_file(path: &std::path::Path) {
        let _ = fs::remove_file(path);
        let lock = path.with_file_name(format!(
            "{}.writer.lock",
            path.file_name().unwrap().to_string_lossy()
        ));
        let _ = fs::remove_file(lock);
    }
}
