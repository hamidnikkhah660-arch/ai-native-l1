//! Bounded, opt-in TCP daemon wrapper for the candidate off-host Anchor Noise handler.
//!
//! This module does not configure cloud storage, provision keys, or start a listener during node
//! startup. A caller must explicitly construct and run the daemon. Connections are bounded by a
//! fixed worker count plus a bounded queue; overload is handled by closing the excess socket.
use crate::{
    external_cas_anchor_candidate::ExternalCasPin,
    external_cas_offhost_anchor_noise_transport_candidate::{
        serve_offhost_anchor_noise_connection, OffhostAnchorNoiseError,
    },
    external_cas_offhost_anchor_protocol_candidate::{
        ExternalCasOffhostAnchorMemoryModel, ExternalCasOffhostAnchorPin,
        OffhostAnchorReceiptSigner,
    },
    v4_fat1_trust_candidate::MlDsa65Verifier,
};
use std::{
    collections::HashSet,
    fmt, io,
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{sync_channel, TrySendError},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(10);
const MIN_WORKERS: usize = 1;
const MAX_WORKERS: usize = 64;
const MIN_QUEUE_CAPACITY: usize = 1;
const MAX_QUEUE_CAPACITY: usize = 4096;
const MIN_TRUSTED_CLIENTS: usize = 1;
const MAX_TRUSTED_CLIENTS: usize = 256;

/// Explicit configuration for a single Anchor daemon listener.
///
/// The Noise static private key is intentionally omitted from Debug output and is zeroed when the
/// daemon's final shared reference is dropped. Constructing this value does not bind a socket.
pub struct OffhostAnchorNoiseDaemonConfig {
    pub bind_address: SocketAddr,
    pub local_static_private_key: [u8; 32],
    pub trusted_client_static_public_keys: Vec<[u8; 32]>,
    pub anchor_pin: ExternalCasOffhostAnchorPin,
    pub provider_pin: ExternalCasPin,
    pub max_workers: usize,
    pub queue_capacity: usize,
}

impl fmt::Debug for OffhostAnchorNoiseDaemonConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OffhostAnchorNoiseDaemonConfig")
            .field("bind_address", &self.bind_address)
            .field("local_static_private_key", &"<redacted>")
            .field(
                "trusted_client_static_public_keys",
                &format_args!(
                    "<{} pinned key(s)>",
                    self.trusted_client_static_public_keys.len()
                ),
            )
            .field("anchor_id", &self.anchor_pin.anchor_id)
            .field("provider_id", &self.provider_pin.provider_id)
            .field("network_id", &self.provider_pin.network_id)
            .field("genesis_digest", &self.provider_pin.genesis_digest)
            .field("max_workers", &self.max_workers)
            .field("queue_capacity", &self.queue_capacity)
            .finish()
    }
}

struct SecretNoiseKey([u8; 32]);

impl Drop for SecretNoiseKey {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Default)]
struct Counters {
    accepted: AtomicU64,
    overload_rejected: AtomicU64,
    completed: AtomicU64,
    failed: AtomicU64,
    active_connections: AtomicU64,
    worker_threads_started: AtomicU64,
}

/// Monotonic daemon counters. Accepted includes sockets rejected because the bounded queue was full.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OffhostAnchorNoiseDaemonStats {
    pub accepted_connections: u64,
    pub overload_rejected_connections: u64,
    pub completed_requests: u64,
    pub failed_requests: u64,
    /// Total fixed worker threads started by this daemon run.
    pub worker_threads_started: u64,
}

impl Counters {
    fn snapshot(&self) -> OffhostAnchorNoiseDaemonStats {
        OffhostAnchorNoiseDaemonStats {
            accepted_connections: self.accepted.load(Ordering::Relaxed),
            overload_rejected_connections: self.overload_rejected.load(Ordering::Relaxed),
            completed_requests: self.completed.load(Ordering::Relaxed),
            failed_requests: self.failed.load(Ordering::Relaxed),
            worker_threads_started: self.worker_threads_started.load(Ordering::Relaxed),
        }
    }
}

/// Explicitly bound Anchor service. No background threads are started until run_until_shutdown.
pub struct OffhostAnchorNoiseDaemon<S, V> {
    listener: TcpListener,
    local_static_private_key: Arc<SecretNoiseKey>,
    trusted_client_static_public_keys: Arc<Vec<[u8; 32]>>,
    anchor_pin: Arc<ExternalCasOffhostAnchorPin>,
    provider_pin: Arc<ExternalCasPin>,
    model: Arc<ExternalCasOffhostAnchorMemoryModel>,
    provider_verifier: Arc<V>,
    anchor_signer: Arc<S>,
    max_workers: usize,
    queue_capacity: usize,
    counters: Arc<Counters>,
}

impl<S, V> fmt::Debug for OffhostAnchorNoiseDaemon<S, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OffhostAnchorNoiseDaemon")
            .field("local_addr", &self.listener.local_addr().ok())
            .field("local_static_private_key", &"<redacted>")
            .field(
                "trusted_client_count",
                &self.trusted_client_static_public_keys.len(),
            )
            .field("anchor_id", &self.anchor_pin.anchor_id)
            .field("provider_id", &self.provider_pin.provider_id)
            .field("network_id", &self.provider_pin.network_id)
            .field("genesis_digest", &self.provider_pin.genesis_digest)
            .field("max_workers", &self.max_workers)
            .field("queue_capacity", &self.queue_capacity)
            .field("stats", &self.counters.snapshot())
            .finish()
    }
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn validate_limits(max_workers: usize, queue_capacity: usize) -> bool {
    (MIN_WORKERS..=MAX_WORKERS).contains(&max_workers)
        && (MIN_QUEUE_CAPACITY..=MAX_QUEUE_CAPACITY).contains(&queue_capacity)
}

fn validate_trusted_clients(keys: &[[u8; 32]]) -> bool {
    if !(MIN_TRUSTED_CLIENTS..=MAX_TRUSTED_CLIENTS).contains(&keys.len()) {
        return false;
    }
    let mut unique = HashSet::with_capacity(keys.len());
    keys.iter().all(|key| !is_zero(key) && unique.insert(*key))
}

impl<S, V> OffhostAnchorNoiseDaemon<S, V>
where
    S: OffhostAnchorReceiptSigner + Send + Sync + 'static,
    V: MlDsa65Verifier + Send + Sync + 'static,
{
    /// Validate the complete pin/worker policy and bind one explicit listener.
    ///
    /// The injected model, verifier, and signer are shared between a fixed number of workers.
    /// The model's store trait requires Send + Sync; the signer and verifier are constrained here.
    pub fn bind(
        mut config: OffhostAnchorNoiseDaemonConfig,
        model: Arc<ExternalCasOffhostAnchorMemoryModel>,
        provider_verifier: Arc<V>,
        anchor_signer: Arc<S>,
    ) -> Result<Self, OffhostAnchorNoiseError> {
        let valid = !is_zero(&config.local_static_private_key)
            && validate_trusted_clients(&config.trusted_client_static_public_keys)
            && validate_limits(config.max_workers, config.queue_capacity)
            && config.anchor_pin.validate(&config.provider_pin).is_ok()
            && model.matches_pins(&config.anchor_pin, &config.provider_pin);
        if !valid {
            config.local_static_private_key.fill(0);
            return Err(OffhostAnchorNoiseError::InvalidConfiguration);
        }

        let listener = match TcpListener::bind(config.bind_address) {
            Ok(listener) => listener,
            Err(error) => {
                config.local_static_private_key.fill(0);
                return Err(OffhostAnchorNoiseError::Io(error.to_string()));
            }
        };
        if let Err(error) = listener.set_nonblocking(true) {
            config.local_static_private_key.fill(0);
            return Err(OffhostAnchorNoiseError::Io(error.to_string()));
        }

        let secret = Arc::new(SecretNoiseKey(config.local_static_private_key));
        config.local_static_private_key.fill(0);
        Ok(Self {
            listener,
            local_static_private_key: secret,
            trusted_client_static_public_keys: Arc::new(config.trusted_client_static_public_keys),
            anchor_pin: Arc::new(config.anchor_pin),
            provider_pin: Arc::new(config.provider_pin),
            model,
            provider_verifier,
            anchor_signer,
            max_workers: config.max_workers,
            queue_capacity: config.queue_capacity,
            counters: Arc::new(Counters::default()),
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, OffhostAnchorNoiseError> {
        self.listener
            .local_addr()
            .map_err(|error| OffhostAnchorNoiseError::Io(error.to_string()))
    }

    pub fn stats(&self) -> OffhostAnchorNoiseDaemonStats {
        self.counters.snapshot()
    }

    /// Run until the caller sets shutdown with Release ordering.
    ///
    /// The bounded channel never holds more than queue_capacity sockets, and exactly max_workers
    /// worker threads are created. On shutdown no queued sockets are newly served; workers finish
    /// their in-flight request (subject to the handler's 20-second I/O deadlines) and then exit.
    /// Excess accepted sockets are immediately dropped instead of spawning unbounded threads.
    pub fn run_until_shutdown(
        self,
        shutdown: &AtomicBool,
    ) -> Result<OffhostAnchorNoiseDaemonStats, OffhostAnchorNoiseError> {
        let (sender, receiver) = sync_channel::<TcpStream>(self.queue_capacity);
        let shared_receiver = Arc::new(Mutex::new(receiver));
        let worker_stop = Arc::new(AtomicBool::new(false));

        // Scoped workers observe the caller's shutdown flag directly. This closes the race where
        // an in-flight handler returned before the accept loop had propagated shutdown to a
        // separate worker flag, allowing one queued socket to start after shutdown was requested.
        thread::scope(|scope| {
            let mut workers = Vec::with_capacity(self.max_workers);

            for worker_index in 0..self.max_workers {
                let receiver = Arc::clone(&shared_receiver);
                let stop = Arc::clone(&worker_stop);
                let caller_shutdown = shutdown;
                let key = Arc::clone(&self.local_static_private_key);
                let clients = Arc::clone(&self.trusted_client_static_public_keys);
                let anchor_pin = Arc::clone(&self.anchor_pin);
                let provider_pin = Arc::clone(&self.provider_pin);
                let model = Arc::clone(&self.model);
                let verifier = Arc::clone(&self.provider_verifier);
                let signer = Arc::clone(&self.anchor_signer);
                let counters = Arc::clone(&self.counters);
                let spawn = thread::Builder::new()
                    .name(format!("qrun-anchor-noise-{worker_index}"))
                    .spawn_scoped(scope, move || {
                        counters
                            .worker_threads_started
                            .fetch_add(1, Ordering::Relaxed);
                        loop {
                            let received = match receiver.lock() {
                                Ok(guard) => guard.recv(),
                                Err(_) => break,
                            };
                            let stream = match received {
                                Ok(stream) => stream,
                                Err(_) => break,
                            };
                            if stop.load(Ordering::Acquire)
                                || caller_shutdown.load(Ordering::Acquire)
                            {
                                drop(stream);
                                break;
                            }
                            let mut stream = stream;
                            counters.active_connections.fetch_add(1, Ordering::Relaxed);
                            let result = serve_offhost_anchor_noise_connection(
                                &mut stream,
                                &key.0,
                                clients.as_slice(),
                                &anchor_pin,
                                &provider_pin,
                                &model,
                                verifier.as_ref(),
                                signer.as_ref(),
                            );
                            counters.active_connections.fetch_sub(1, Ordering::Relaxed);
                            if result.is_ok() {
                                counters.completed.fetch_add(1, Ordering::Relaxed);
                            } else {
                                counters.failed.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    });
                match spawn {
                    Ok(worker) => workers.push(worker),
                    Err(error) => {
                        worker_stop.store(true, Ordering::Release);
                        drop(sender);
                        for worker in workers {
                            let _ = worker.join();
                        }
                        return Err(OffhostAnchorNoiseError::Io(error.to_string()));
                    }
                }
            }

            let mut accept_error: Option<io::Error> = None;
            while !shutdown.load(Ordering::Acquire) {
                match self.listener.accept() {
                    Ok((stream, _peer)) => {
                        self.counters.accepted.fetch_add(1, Ordering::Relaxed);
                        match sender.try_send(stream) {
                            Ok(()) => {}
                            Err(TrySendError::Full(stream)) => {
                                self.counters
                                    .overload_rejected
                                    .fetch_add(1, Ordering::Relaxed);
                                drop(stream);
                            }
                            Err(TrySendError::Disconnected(stream)) => {
                                self.counters.failed.fetch_add(1, Ordering::Relaxed);
                                drop(stream);
                                break;
                            }
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(ACCEPT_POLL_INTERVAL);
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => {
                        accept_error = Some(error);
                        break;
                    }
                }
            }

            worker_stop.store(true, Ordering::Release);
            drop(sender);
            let mut worker_panicked = false;
            for worker in workers {
                if worker.join().is_err() {
                    worker_panicked = true;
                }
            }

            if let Some(error) = accept_error {
                return Err(OffhostAnchorNoiseError::Io(error.to_string()));
            }
            if worker_panicked {
                return Err(OffhostAnchorNoiseError::Io(
                    "off-host Anchor worker thread panicked".to_owned(),
                ));
            }
            Ok(self.stats())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        external_cas_anchor_candidate::{
            ExternalCasPin, ExternalCasReceipt, ExternalCasReceiptKind, ExternalCasReceiptOutcome,
            ExternalCasRecord, ExternalCasWriteRequest,
        },
        external_cas_offhost_anchor_candidate::{
            verify_provider_commit_for_offhost_anchor, ExternalCasOffhostAnchorState,
        },
        external_cas_offhost_anchor_noise_transport_candidate::NoiseTcpOffhostAnchorTransport,
        external_cas_offhost_anchor_protocol_candidate::{
            ExternalCasOffhostAnchorCasRequest, ExternalCasOffhostAnchorReadRequest,
            ExternalCasOffhostAnchorReceiptOutcome,
        },
        v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate,
        v4_fat1_trust_candidate::ML_DSA_65_SIGNATURE_BYTES,
    };
    use libcrux_ml_dsa::ml_dsa_65::{portable, MLDSA65SigningKey};
    use snow::{params::NoiseParams, Builder};
    use std::{
        net::{SocketAddr, TcpListener, TcpStream},
        sync::atomic::AtomicBool,
        thread,
        time::{Duration, Instant},
    };

    #[derive(Clone)]
    struct TestSigner {
        key: Arc<MLDSA65SigningKey>,
    }

    impl OffhostAnchorReceiptSigner for TestSigner {
        fn sign_digest(
            &self,
            digest: &[u8; 32],
        ) -> Result<[u8; ML_DSA_65_SIGNATURE_BYTES], String> {
            let signature = portable::sign(&self.key, digest, &[], [0xD1; 32])
                .map_err(|error| format!("{error:?}"))?;
            Ok(*signature.as_ref())
        }
    }

    struct Fixture {
        provider_pin: ExternalCasPin,
        anchor_pin: ExternalCasOffhostAnchorPin,
        bootstrap_record: ExternalCasRecord,
        bootstrap_state: ExternalCasOffhostAnchorState,
        provider_signer: TestSigner,
        anchor_signer: TestSigner,
    }

    fn fixture() -> Fixture {
        let provider_keys = portable::generate_key_pair([0xA1; 32]);
        let anchor_keys = portable::generate_key_pair([0xB2; 32]);
        let provider_pin = ExternalCasPin {
            provider_id: [0x11; 32],
            network_id: [0x22; 32],
            genesis_digest: [0x33; 32],
            receipt_key_id: [0x44; 32],
            receipt_public_key: *provider_keys.verification_key.as_ref(),
        };
        let anchor_pin = ExternalCasOffhostAnchorPin {
            anchor_id: [0x91; 32],
            provider_id: provider_pin.provider_id,
            network_id: provider_pin.network_id,
            genesis_digest: provider_pin.genesis_digest,
            receipt_key_id: [0x92; 32],
            receipt_public_key: *anchor_keys.verification_key.as_ref(),
        };
        let bootstrap_record = ExternalCasRecord {
            generation: 0,
            provider_id: provider_pin.provider_id,
            network_id: provider_pin.network_id,
            genesis_digest: provider_pin.genesis_digest,
            previous_record_digest: [0; 32],
            previous_state_digest: [0; 32],
            next_state_digest: [0x55; 32],
            operation_id: [0x66; 32],
            request_digest: [0x77; 32],
        };
        let bootstrap_state = ExternalCasOffhostAnchorState::provision_bootstrap(
            &provider_pin,
            bootstrap_record.clone(),
            1,
        )
        .unwrap();
        Fixture {
            provider_pin,
            anchor_pin,
            bootstrap_record,
            bootstrap_state,
            provider_signer: TestSigner {
                key: Arc::new(provider_keys.signing_key),
            },
            anchor_signer: TestSigner {
                key: Arc::new(anchor_keys.signing_key),
            },
        }
    }

    fn noise_keypair() -> ([u8; 32], [u8; 32]) {
        let mut pair = Builder::new(
            "Noise_XX_25519_ChaChaPoly_SHA256"
                .parse::<NoiseParams>()
                .unwrap(),
        )
        .generate_keypair()
        .unwrap();
        let private = pair.private.as_slice().try_into().unwrap();
        let public = pair.public.as_slice().try_into().unwrap();
        pair.private.fill(0);
        pair.public.fill(0);
        (private, public)
    }

    fn model(f: &Fixture) -> Arc<ExternalCasOffhostAnchorMemoryModel> {
        Arc::new(
            ExternalCasOffhostAnchorMemoryModel::new(
                f.anchor_pin.clone(),
                f.provider_pin.clone(),
                f.bootstrap_state.clone(),
            )
            .unwrap(),
        )
    }

    fn daemon_config(
        bind_address: SocketAddr,
        anchor_pin: ExternalCasOffhostAnchorPin,
        provider_pin: ExternalCasPin,
        server_private: [u8; 32],
        trusted_client_public: [u8; 32],
        max_workers: usize,
        queue_capacity: usize,
    ) -> OffhostAnchorNoiseDaemonConfig {
        OffhostAnchorNoiseDaemonConfig {
            bind_address,
            local_static_private_key: server_private,
            trusted_client_static_public_keys: vec![trusted_client_public],
            anchor_pin,
            provider_pin,
            max_workers,
            queue_capacity,
        }
    }

    struct RunningDaemon {
        model: Arc<ExternalCasOffhostAnchorMemoryModel>,
        counters: Arc<Counters>,
        address: SocketAddr,
        server_public: [u8; 32],
        client_private: [u8; 32],
        shutdown: Arc<AtomicBool>,
        join: thread::JoinHandle<Result<OffhostAnchorNoiseDaemonStats, OffhostAnchorNoiseError>>,
    }

    fn start_daemon(f: &Fixture, max_workers: usize, queue_capacity: usize) -> RunningDaemon {
        let model = model(f);
        let (server_private, server_public) = noise_keypair();
        let (client_private, client_public) = noise_keypair();
        let config = daemon_config(
            "127.0.0.1:0".parse().unwrap(),
            f.anchor_pin.clone(),
            f.provider_pin.clone(),
            server_private,
            client_public,
            max_workers,
            queue_capacity,
        );
        let daemon = OffhostAnchorNoiseDaemon::bind(
            config,
            Arc::clone(&model),
            Arc::new(LibcruxMlDsa65VerifierCandidate),
            Arc::new(f.anchor_signer.clone()),
        )
        .unwrap();
        let address = daemon.local_addr().unwrap();
        let counters = Arc::clone(&daemon.counters);
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_shutdown = Arc::clone(&shutdown);
        let join = thread::spawn(move || daemon.run_until_shutdown(&worker_shutdown));
        RunningDaemon {
            model,
            counters,
            address,
            server_public,
            client_private,
            shutdown,
            join,
        }
    }

    fn client_transport(running: &RunningDaemon, f: &Fixture) -> NoiseTcpOffhostAnchorTransport {
        NoiseTcpOffhostAnchorTransport::new(
            running.address,
            running.client_private,
            running.server_public,
            f.anchor_pin.clone(),
            f.provider_pin.clone(),
        )
        .unwrap()
    }

    fn write_request(f: &Fixture) -> ExternalCasWriteRequest {
        let operation_id = [0xA2; 32];
        let mut request = ExternalCasWriteRequest {
            request_nonce: [0xA1; 32],
            operation_id,
            request_digest: [1; 32],
            expected_generation: 0,
            expected_object_generation: 1,
            expected_record_digest: f.bootstrap_record.digest().unwrap(),
            expected_state_digest: f.bootstrap_record.next_state_digest,
            next_record: ExternalCasRecord {
                generation: 1,
                provider_id: f.provider_pin.provider_id,
                network_id: f.provider_pin.network_id,
                genesis_digest: f.provider_pin.genesis_digest,
                previous_record_digest: f.bootstrap_record.digest().unwrap(),
                previous_state_digest: f.bootstrap_record.next_state_digest,
                next_state_digest: [0xA3; 32],
                operation_id,
                request_digest: [1; 32],
            },
        };
        request.bind_request_digest(&f.provider_pin).unwrap();
        request
    }

    fn provider_commit_receipt(
        f: &Fixture,
        request: &ExternalCasWriteRequest,
    ) -> ExternalCasReceipt {
        let mut receipt = ExternalCasReceipt {
            kind: ExternalCasReceiptKind::Commit,
            outcome: ExternalCasReceiptOutcome::Applied,
            generation: request.next_record.generation,
            object_generation: 2,
            provider_id: f.provider_pin.provider_id,
            network_id: f.provider_pin.network_id,
            genesis_digest: f.provider_pin.genesis_digest,
            receipt_key_id: f.provider_pin.receipt_key_id,
            request_nonce: request.request_nonce,
            record_digest: request.next_record.digest().unwrap(),
            previous_record_digest: request.next_record.previous_record_digest,
            previous_state_digest: request.next_record.previous_state_digest,
            state_digest: request.next_record.next_state_digest,
            operation_id: request.operation_id,
            request_digest: request.request_digest,
            signature: [0; ML_DSA_65_SIGNATURE_BYTES],
        };
        let digest = receipt.signing_digest().unwrap();
        let signature = portable::sign(&f.provider_signer.key, &digest, &[], [0xC3; 32]).unwrap();
        receipt.signature = *signature.as_ref();
        receipt
    }

    fn wait_until(mut predicate: impl FnMut() -> bool, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if predicate() {
                return true;
            }
            thread::sleep(Duration::from_millis(10));
        }
        predicate()
    }

    #[test]
    fn worker_and_queue_limits_are_bounded() {
        assert!(validate_limits(1, 1));
        assert!(validate_limits(MAX_WORKERS, MAX_QUEUE_CAPACITY));
        assert!(!validate_limits(0, 1));
        assert!(!validate_limits(MAX_WORKERS + 1, 1));
        assert!(!validate_limits(1, 0));
        assert!(!validate_limits(1, MAX_QUEUE_CAPACITY + 1));
    }

    #[test]
    fn trusted_client_keys_must_be_nonzero_and_unique() {
        assert!(validate_trusted_clients(&[[0x11; 32]]));
        assert!(validate_trusted_clients(&[[0x11; 32], [0x22; 32]]));
        assert!(!validate_trusted_clients(&[]));
        assert!(!validate_trusted_clients(&[[0; 32]]));
        assert!(!validate_trusted_clients(&[[0x11; 32], [0x11; 32]]));
    }

    #[test]
    fn bind_rejects_every_model_pin_mismatch_before_opening_listener() {
        let f = fixture();
        let model = model(&f);
        let (server_private, _) = noise_keypair();
        let (_, trusted_client_public) = noise_keypair();
        let mut cases = Vec::new();

        let mut anchor = f.anchor_pin.clone();
        anchor.anchor_id[0] ^= 1;
        cases.push(("anchor id", anchor, f.provider_pin.clone()));

        let mut anchor = f.anchor_pin.clone();
        let mut provider = f.provider_pin.clone();
        anchor.provider_id = [0x12; 32];
        provider.provider_id = [0x12; 32];
        cases.push(("provider id", anchor, provider));

        let mut anchor = f.anchor_pin.clone();
        let mut provider = f.provider_pin.clone();
        anchor.network_id = [0x23; 32];
        provider.network_id = [0x23; 32];
        cases.push(("network id", anchor, provider));

        let mut anchor = f.anchor_pin.clone();
        let mut provider = f.provider_pin.clone();
        anchor.genesis_digest = [0x34; 32];
        provider.genesis_digest = [0x34; 32];
        cases.push(("genesis digest", anchor, provider));

        let mut anchor = f.anchor_pin.clone();
        anchor.receipt_key_id = [0x93; 32];
        cases.push(("anchor receipt key id", anchor, f.provider_pin.clone()));

        let mut anchor = f.anchor_pin.clone();
        anchor.receipt_public_key[0] ^= 1;
        cases.push(("anchor receipt public key", anchor, f.provider_pin.clone()));

        let mut provider = f.provider_pin.clone();
        provider.receipt_key_id = [0x45; 32];
        cases.push(("provider receipt key id", f.anchor_pin.clone(), provider));

        let mut provider = f.provider_pin.clone();
        provider.receipt_public_key[0] ^= 1;
        cases.push((
            "provider receipt public key",
            f.anchor_pin.clone(),
            provider,
        ));

        for (label, anchor_pin, provider_pin) in cases {
            anchor_pin.validate(&provider_pin).unwrap();
            let reservation = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = reservation.local_addr().unwrap();
            drop(reservation);
            let config = daemon_config(
                address,
                anchor_pin,
                provider_pin,
                server_private,
                trusted_client_public,
                1,
                1,
            );
            let result = OffhostAnchorNoiseDaemon::bind(
                config,
                Arc::clone(&model),
                Arc::new(LibcruxMlDsa65VerifierCandidate),
                Arc::new(f.anchor_signer.clone()),
            );
            assert!(
                matches!(result, Err(OffhostAnchorNoiseError::InvalidConfiguration)),
                "mismatched {label} must fail closed"
            );
            let probe = TcpListener::bind(address)
                .unwrap_or_else(|error| panic!("listener unexpectedly bound for {label}: {error}"));
            drop(probe);
        }
    }

    #[test]
    fn daemon_serves_authenticated_read_cas_conflict_and_read_then_joins_workers() {
        let f = fixture();
        let running = start_daemon(&f, 3, 4);
        let transport = client_transport(&running, &f);
        let verifier = LibcruxMlDsa65VerifierCandidate;

        let read_before = ExternalCasOffhostAnchorReadRequest {
            challenge: [0xB1; 32],
            operation_id: [0xB2; 32],
            request_digest: [0xB3; 32],
        };
        let before_receipt = transport.read(&read_before).unwrap();
        let before = before_receipt
            .verify_read(&f.anchor_pin, &f.provider_pin, &read_before, &verifier)
            .unwrap();
        assert_eq!(before, f.bootstrap_state);

        let write = write_request(&f);
        let provider_receipt = provider_commit_receipt(&f, &write);
        let verified = verify_provider_commit_for_offhost_anchor(
            &f.provider_pin,
            &f.bootstrap_state,
            &write.next_record.encode().unwrap(),
            &provider_receipt.encode().unwrap(),
            &verifier,
        )
        .unwrap();
        let cas = ExternalCasOffhostAnchorCasRequest {
            challenge: [0xB4; 32],
            operation_id: write.operation_id,
            request_digest: write.request_digest,
            expected_sequence: f.bootstrap_state.sequence,
            expected_state_digest: f.bootstrap_state.digest().unwrap(),
            target_state_digest: verified.next_state.digest().unwrap(),
        };
        let applied_receipt = transport
            .compare_and_swap(
                &cas,
                &write.next_record.encode().unwrap(),
                &provider_receipt.encode().unwrap(),
            )
            .unwrap();
        let (outcome, accepted) = applied_receipt
            .verify_cas(&f.anchor_pin, &f.provider_pin, &cas, &verifier)
            .unwrap();
        assert_eq!(outcome, ExternalCasOffhostAnchorReceiptOutcome::Applied);
        assert_eq!(accepted, verified.next_state);
        assert_eq!(running.model.snapshot().unwrap(), accepted);

        let stale_cas = ExternalCasOffhostAnchorCasRequest {
            challenge: [0xC4; 32],
            operation_id: [0xC5; 32],
            request_digest: [0xC6; 32],
            expected_sequence: f.bootstrap_state.sequence,
            expected_state_digest: f.bootstrap_state.digest().unwrap(),
            target_state_digest: [0xC7; 32],
        };
        let conflict_receipt = transport
            .compare_and_swap(
                &stale_cas,
                &write.next_record.encode().unwrap(),
                &provider_receipt.encode().unwrap(),
            )
            .unwrap();
        let (conflict_outcome, conflict_state) = conflict_receipt
            .verify_cas(&f.anchor_pin, &f.provider_pin, &stale_cas, &verifier)
            .unwrap();
        assert_eq!(
            conflict_outcome,
            ExternalCasOffhostAnchorReceiptOutcome::Conflict
        );
        assert_eq!(conflict_state, accepted);
        assert_eq!(running.model.snapshot().unwrap(), accepted);

        let read_after = ExternalCasOffhostAnchorReadRequest {
            challenge: [0xD1; 32],
            operation_id: [0xD2; 32],
            request_digest: [0xD3; 32],
        };
        let after_receipt = transport.read(&read_after).unwrap();
        assert_eq!(
            after_receipt
                .verify_read(&f.anchor_pin, &f.provider_pin, &read_after, &verifier,)
                .unwrap(),
            accepted
        );

        running.shutdown.store(true, Ordering::Release);
        let stats = running.join.join().unwrap().unwrap();
        assert_eq!(stats.accepted_connections, 4);
        assert_eq!(stats.completed_requests, 4);
        assert_eq!(stats.failed_requests, 0);
        assert_eq!(stats.overload_rejected_connections, 0);
        assert_eq!(stats.worker_threads_started, 3);
        assert_eq!(running.model.snapshot().unwrap(), accepted);
    }

    #[test]
    fn daemon_rejects_unpinned_noise_client_and_preserves_anchor_state() {
        let f = fixture();
        let running = start_daemon(&f, 1, 1);
        let expected = f.bootstrap_state.clone();
        let (rogue_private, _) = noise_keypair();
        let transport = NoiseTcpOffhostAnchorTransport::new(
            running.address,
            rogue_private,
            running.server_public,
            f.anchor_pin.clone(),
            f.provider_pin.clone(),
        )
        .unwrap();
        let request = ExternalCasOffhostAnchorReadRequest {
            challenge: [0xE1; 32],
            operation_id: [0xE2; 32],
            request_digest: [0xE3; 32],
        };
        assert!(transport.read(&request).is_err());

        running.shutdown.store(true, Ordering::Release);
        let stats = running.join.join().unwrap().unwrap();
        assert_eq!(stats.accepted_connections, 1);
        assert_eq!(stats.completed_requests, 0);
        assert_eq!(stats.failed_requests, 1);
        assert_eq!(stats.worker_threads_started, 1);
        assert_eq!(running.model.snapshot().unwrap(), expected);
    }

    #[test]
    fn daemon_rejects_client_that_does_not_pin_the_server_noise_key() {
        let f = fixture();
        let running = start_daemon(&f, 1, 1);
        let expected = f.bootstrap_state.clone();
        let (wrong_server_private, wrong_server_public) = noise_keypair();
        let transport = NoiseTcpOffhostAnchorTransport::new(
            running.address,
            running.client_private,
            wrong_server_public,
            f.anchor_pin.clone(),
            f.provider_pin.clone(),
        )
        .unwrap();
        let request = ExternalCasOffhostAnchorReadRequest {
            challenge: [0xF1; 32],
            operation_id: [0xF2; 32],
            request_digest: [0xF3; 32],
        };
        assert!(transport.read(&request).is_err());
        let _ = wrong_server_private;

        running.shutdown.store(true, Ordering::Release);
        let stats = running.join.join().unwrap().unwrap();
        assert_eq!(stats.accepted_connections, 1);
        assert_eq!(stats.completed_requests, 0);
        assert_eq!(stats.failed_requests, 1);
        assert_eq!(stats.worker_threads_started, 1);
        assert_eq!(running.model.snapshot().unwrap(), expected);
    }

    #[test]
    fn daemon_times_out_incomplete_noise_handshake_and_shutdown_joins_worker() {
        let f = fixture();
        let running = start_daemon(&f, 1, 1);
        let socket = TcpStream::connect(running.address).unwrap();
        assert!(
            wait_until(
                || running.counters.snapshot().accepted_connections == 1
                    && running.counters.active_connections.load(Ordering::Relaxed) == 1,
                Duration::from_secs(2),
            ),
            "worker did not enter handler: {:?}, active={}",
            running.counters.snapshot(),
            running.counters.active_connections.load(Ordering::Relaxed)
        );
        // Keep the socket open beyond the Noise XX absolute handshake deadline (5 seconds).
        // A subsequent request can complete only if the worker timed out and returned to the
        // bounded receiver loop.
        assert!(
            wait_until(
                || running.counters.snapshot().failed_requests == 1,
                Duration::from_secs(7),
            ),
            "Noise read deadline did not release worker: {:?}, active={}",
            running.counters.snapshot(),
            running.counters.active_connections.load(Ordering::Relaxed)
        );
        let transport = client_transport(&running, &f);
        let request = ExternalCasOffhostAnchorReadRequest {
            challenge: [0xE4; 32],
            operation_id: [0xE5; 32],
            request_digest: [0xE6; 32],
        };
        let receipt = transport.read(&request).unwrap();
        assert_eq!(
            receipt
                .verify_read(
                    &f.anchor_pin,
                    &f.provider_pin,
                    &request,
                    &LibcruxMlDsa65VerifierCandidate,
                )
                .unwrap(),
            f.bootstrap_state
        );
        drop(socket);

        running.shutdown.store(true, Ordering::Release);
        let stats = running.join.join().unwrap().unwrap();
        assert_eq!(stats.accepted_connections, 2);
        assert_eq!(stats.completed_requests, 1);
        assert_eq!(stats.failed_requests, 1);
        assert_eq!(stats.worker_threads_started, 1);
    }

    #[test]
    fn queue_overload_is_rejected_without_exceeding_worker_limit_and_shutdown_drains_queue() {
        let f = fixture();
        let running = start_daemon(&f, 1, 1);
        let first = TcpStream::connect(running.address).unwrap();
        assert!(wait_until(
            || running.counters.snapshot().accepted_connections == 1
                && running.counters.active_connections.load(Ordering::Relaxed) == 1,
            Duration::from_secs(2),
        ));
        let second = TcpStream::connect(running.address).unwrap();
        assert!(wait_until(
            || running.counters.snapshot().accepted_connections == 2,
            Duration::from_secs(2),
        ));
        let third = TcpStream::connect(running.address).unwrap();
        // With one worker blocked in the first handshake and one queued socket, the third
        // accepted socket must be dropped as overload; no connection-specific thread is spawned.
        assert!(wait_until(
            || running.counters.snapshot().overload_rejected_connections == 1,
            Duration::from_secs(2),
        ));
        assert_eq!(running.counters.snapshot().worker_threads_started, 1);

        running.shutdown.store(true, Ordering::Release);
        drop(first);
        drop(second);
        drop(third);
        let stats = running.join.join().unwrap().unwrap();
        assert_eq!(stats.accepted_connections, 3);
        assert_eq!(stats.overload_rejected_connections, 1);
        assert_eq!(stats.completed_requests, 0);
        assert_eq!(stats.failed_requests, 1);
        assert_eq!(stats.worker_threads_started, 1);
    }
}
