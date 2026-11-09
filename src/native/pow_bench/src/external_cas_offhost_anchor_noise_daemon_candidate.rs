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
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{sync_channel, TrySendError},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};
use zeroize::Zeroize;

const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(10);
const MIN_WORKERS: usize = 1;
const MAX_WORKERS: usize = 64;
const MIN_QUEUE_CAPACITY: usize = 1;
const MAX_QUEUE_CAPACITY: usize = 4096;
const MIN_TRUSTED_CLIENTS: usize = 1;
const MAX_TRUSTED_CLIENTS: usize = 256;

/// Explicit configuration for a single Anchor daemon listener.
///
/// The Noise static private key is intentionally omitted from Debug output and is zeroized when
/// this configuration is dropped if it is not bound, or when the daemon's final shared key
/// reference is dropped. Constructing this value does not bind a socket.
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

impl Drop for OffhostAnchorNoiseDaemonConfig {
    fn drop(&mut self) {
        self.local_static_private_key.zeroize();
    }
}

struct SecretNoiseKey([u8; 32]);

impl Drop for SecretNoiseKey {
    fn drop(&mut self) {
        self.0.zeroize();
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
    active_worker_threads: AtomicU64,
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
    /// Worker threads that have not yet exited.
    pub active_worker_threads: u64,
}

impl Counters {
    fn snapshot(&self) -> OffhostAnchorNoiseDaemonStats {
        OffhostAnchorNoiseDaemonStats {
            accepted_connections: self.accepted.load(Ordering::Relaxed),
            overload_rejected_connections: self.overload_rejected.load(Ordering::Relaxed),
            completed_requests: self.completed.load(Ordering::Relaxed),
            failed_requests: self.failed.load(Ordering::Relaxed),
            worker_threads_started: self.worker_threads_started.load(Ordering::Relaxed),
            active_worker_threads: self.active_worker_threads.load(Ordering::Relaxed),
        }
    }
}

/// Accounts for one connection even if the handler unwinds unexpectedly.
struct ActiveConnectionGuard {
    counters: Arc<Counters>,
    completed: bool,
}

impl ActiveConnectionGuard {
    fn new(counters: Arc<Counters>) -> Self {
        counters.active_connections.fetch_add(1, Ordering::Relaxed);
        Self {
            counters,
            completed: false,
        }
    }

    fn mark_completed(&mut self) {
        self.completed = true;
        self.counters.completed.fetch_add(1, Ordering::Relaxed);
    }
}

impl Drop for ActiveConnectionGuard {
    fn drop(&mut self) {
        self.counters
            .active_connections
            .fetch_sub(1, Ordering::Relaxed);
        if !self.completed {
            self.counters.failed.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Tracks worker liveness independently of request/connection counters.
struct ActiveWorkerGuard(Arc<Counters>);

impl ActiveWorkerGuard {
    fn new(counters: Arc<Counters>) -> Self {
        counters
            .active_worker_threads
            .fetch_add(1, Ordering::Relaxed);
        Self(counters)
    }
}

impl Drop for ActiveWorkerGuard {
    fn drop(&mut self) {
        self.0.active_worker_threads.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Explicitly bound Anchor service. No background threads are started until run_until_shutdown or spawn.
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

/// Owner handle for a daemon running on a dedicated thread.
///
/// Dropping the handle requests graceful shutdown and joins the daemon thread. In-flight
/// handlers may run until their 20-second I/O deadline. No automatic restart is attempted: the
/// owner must explicitly provision a fresh, independently validated configuration before starting
/// a replacement service.
pub struct OffhostAnchorNoiseDaemonTask {
    shutdown: Arc<AtomicBool>,
    counters: Arc<Counters>,
    join:
        Option<thread::JoinHandle<Result<OffhostAnchorNoiseDaemonStats, OffhostAnchorNoiseError>>>,
}

impl fmt::Debug for OffhostAnchorNoiseDaemonTask {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OffhostAnchorNoiseDaemonTask")
            .field("shutdown_requested", &self.shutdown.load(Ordering::Acquire))
            .field("finished", &self.is_finished())
            .field("stats", &self.stats())
            .finish_non_exhaustive()
    }
}

impl OffhostAnchorNoiseDaemonTask {
    /// Request that the accept loop stop and all queued sockets be discarded.
    pub fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
    }

    /// Whether the daemon thread has returned, including after a worker failure.
    pub fn is_finished(&self) -> bool {
        self.join
            .as_ref()
            .is_none_or(thread::JoinHandle::is_finished)
    }

    /// Return a live snapshot of the daemon's monotonic counters.
    pub fn stats(&self) -> OffhostAnchorNoiseDaemonStats {
        self.counters.snapshot()
    }

    /// Join the daemon after a shutdown request (or after it exits due to failure).
    pub fn join(mut self) -> Result<OffhostAnchorNoiseDaemonStats, OffhostAnchorNoiseError> {
        let join = self.join.take().ok_or_else(|| {
            OffhostAnchorNoiseError::Io("off-host Anchor daemon task was already joined".into())
        })?;
        join.join().map_err(|_| {
            OffhostAnchorNoiseError::Io("off-host Anchor daemon supervisor thread panicked".into())
        })?
    }

    /// Request graceful shutdown and synchronously join the service and all its workers.
    pub fn shutdown_and_join(
        self,
    ) -> Result<OffhostAnchorNoiseDaemonStats, OffhostAnchorNoiseError> {
        self.request_shutdown();
        self.join()
    }
}

impl Drop for OffhostAnchorNoiseDaemonTask {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(join) = self.join.take() {
            // Drop cannot report a service error; callers that need it must use join() or
            // shutdown_and_join(). Joining here still guarantees the listener/workers are gone.
            let _ = join.join();
        }
    }
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
            return Err(OffhostAnchorNoiseError::InvalidConfiguration);
        }

        let listener = match TcpListener::bind(config.bind_address) {
            Ok(listener) => listener,
            Err(error) => return Err(OffhostAnchorNoiseError::Io(error.to_string())),
        };
        if let Err(error) = listener.set_nonblocking(true) {
            return Err(OffhostAnchorNoiseError::Io(error.to_string()));
        }

        let secret_key = std::mem::replace(&mut config.local_static_private_key, [0; 32]);
        let secret = Arc::new(SecretNoiseKey(secret_key));
        Ok(Self {
            listener,
            local_static_private_key: secret,
            trusted_client_static_public_keys: Arc::new(std::mem::take(
                &mut config.trusted_client_static_public_keys,
            )),
            anchor_pin: Arc::new(config.anchor_pin.clone()),
            provider_pin: Arc::new(config.provider_pin.clone()),
            model,
            provider_verifier,
            anchor_signer,
            max_workers: config.max_workers,
            queue_capacity: config.queue_capacity,
            counters: Arc::new(Counters::default()),
        })
    }

    /// Start the already-bound daemon under an owned shutdown/join handle.
    pub fn spawn(self) -> Result<OffhostAnchorNoiseDaemonTask, OffhostAnchorNoiseError> {
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_shutdown = Arc::clone(&shutdown);
        let counters = Arc::clone(&self.counters);
        let join = thread::Builder::new()
            .name("qrun-anchor-noise-daemon".into())
            .spawn(move || self.run_until_shutdown(worker_shutdown.as_ref()))
            .map_err(|error| OffhostAnchorNoiseError::Io(error.to_string()))?;
        Ok(OffhostAnchorNoiseDaemonTask {
            shutdown,
            counters,
            join: Some(join),
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
    /// A worker panic stops the accept loop, drains the queue without serving it, joins all workers,
    /// and returns an error so an owner can decide whether to provision and start a replacement.
    /// Excess accepted sockets are immediately dropped instead of spawning unbounded threads.
    pub fn run_until_shutdown(
        self,
        shutdown: &AtomicBool,
    ) -> Result<OffhostAnchorNoiseDaemonStats, OffhostAnchorNoiseError> {
        let (sender, receiver) = sync_channel::<TcpStream>(self.queue_capacity);
        let shared_receiver = Arc::new(Mutex::new(receiver));
        let worker_stop = Arc::new(AtomicBool::new(false));
        let worker_panic_signal = Arc::new(AtomicBool::new(false));

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
                let panic_stop = Arc::clone(&worker_panic_signal);
                let panic_signal = Arc::clone(&worker_panic_signal);
                let spawn = thread::Builder::new()
                    .name(format!("qrun-anchor-noise-{worker_index}"))
                    .spawn_scoped(scope, move || {
                        let worker_result = catch_unwind(AssertUnwindSafe(|| {
                            counters
                                .worker_threads_started
                                .fetch_add(1, Ordering::Relaxed);
                            let _active_worker = ActiveWorkerGuard::new(Arc::clone(&counters));
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
                                    || panic_stop.load(Ordering::Acquire)
                                {
                                    drop(stream);
                                    break;
                                }
                                let mut stream = stream;
                                let mut connection =
                                    ActiveConnectionGuard::new(Arc::clone(&counters));
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
                                if result.is_ok() {
                                    connection.mark_completed();
                                }
                            }
                        }));
                        if worker_result.is_err() {
                            panic_signal.store(true, Ordering::Release);
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
            while !shutdown.load(Ordering::Acquire) && !worker_panic_signal.load(Ordering::Acquire)
            {
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
            let mut worker_panicked = worker_panic_signal.load(Ordering::Acquire);
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
        external_cas_offhost_anchor_file_store_candidate::ExternalCasOffhostAnchorFileStore,
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
        panic_on_sign: bool,
    }

    impl OffhostAnchorReceiptSigner for TestSigner {
        fn sign_digest(
            &self,
            digest: &[u8; 32],
        ) -> Result<[u8; ML_DSA_65_SIGNATURE_BYTES], String> {
            assert!(!self.panic_on_sign, "injected signer panic");
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
                panic_on_sign: false,
            },
            anchor_signer: TestSigner {
                key: Arc::new(anchor_keys.signing_key),
                panic_on_sign: false,
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

    fn bind_daemon_at(
        f: &Fixture,
        bind_address: SocketAddr,
        anchor_signer: TestSigner,
        max_workers: usize,
        queue_capacity: usize,
    ) -> (
        OffhostAnchorNoiseDaemon<TestSigner, LibcruxMlDsa65VerifierCandidate>,
        [u8; 32],
        [u8; 32],
    ) {
        let (server_private, server_public) = noise_keypair();
        let (client_private, client_public) = noise_keypair();
        let config = daemon_config(
            bind_address,
            f.anchor_pin.clone(),
            f.provider_pin.clone(),
            server_private,
            client_public,
            max_workers,
            queue_capacity,
        );
        let daemon = OffhostAnchorNoiseDaemon::bind(
            config,
            model(f),
            Arc::new(LibcruxMlDsa65VerifierCandidate),
            Arc::new(anchor_signer),
        )
        .unwrap();
        (daemon, server_public, client_private)
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

    fn start_daemon_with_model(
        f: &Fixture,
        model: Arc<ExternalCasOffhostAnchorMemoryModel>,
        max_workers: usize,
        queue_capacity: usize,
    ) -> RunningDaemon {
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
    fn durable_file_q6ea_noise_cas_survives_daemon_restart() {
        let f = fixture();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "q6ea_noise_restart_{}_{}",
            std::process::id(),
            nonce
        ));
        std::fs::create_dir_all(&directory).unwrap();

        let (provisioned, outcome) = ExternalCasOffhostAnchorFileStore::provision(
            &directory,
            f.anchor_pin.clone(),
            f.provider_pin.clone(),
            f.bootstrap_state.clone(),
        )
        .unwrap();
        assert!(matches!(
            outcome,
            crate::external_cas_offhost_anchor_protocol_candidate::ExternalCasOffhostAnchorStoreProvisionOutcome::Provisioned
        ));
        drop(provisioned);

        let durable_store = Arc::new(
            ExternalCasOffhostAnchorFileStore::open(
                &directory,
                f.anchor_pin.clone(),
                f.provider_pin.clone(),
            )
            .unwrap(),
        );
        let model = Arc::new(
            ExternalCasOffhostAnchorMemoryModel::with_store(
                f.anchor_pin.clone(),
                f.provider_pin.clone(),
                durable_store,
            )
            .unwrap(),
        );
        let running = start_daemon_with_model(&f, Arc::clone(&model), 2, 4);
        let transport = client_transport(&running, &f);
        let verifier = LibcruxMlDsa65VerifierCandidate;

        let read_before = ExternalCasOffhostAnchorReadRequest {
            challenge: [0xB1; 32],
            operation_id: [0xB2; 32],
            request_digest: [0xB3; 32],
        };
        let before = transport
            .read(&read_before)
            .unwrap()
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
        let applied = transport
            .compare_and_swap(
                &cas,
                &write.next_record.encode().unwrap(),
                &provider_receipt.encode().unwrap(),
            )
            .unwrap();
        let (outcome, accepted) = applied
            .verify_cas(&f.anchor_pin, &f.provider_pin, &cas, &verifier)
            .unwrap();
        assert_eq!(outcome, ExternalCasOffhostAnchorReceiptOutcome::Applied);
        assert_eq!(accepted, verified.next_state);

        let conflict = ExternalCasOffhostAnchorCasRequest {
            challenge: [0xC4; 32],
            operation_id: [0xC5; 32],
            request_digest: [0xC6; 32],
            expected_sequence: f.bootstrap_state.sequence,
            expected_state_digest: f.bootstrap_state.digest().unwrap(),
            target_state_digest: [0xC7; 32],
        };
        let conflict_receipt = transport
            .compare_and_swap(
                &conflict,
                &write.next_record.encode().unwrap(),
                &provider_receipt.encode().unwrap(),
            )
            .unwrap();
        let (conflict_outcome, conflict_state) = conflict_receipt
            .verify_cas(&f.anchor_pin, &f.provider_pin, &conflict, &verifier)
            .unwrap();
        assert_eq!(
            conflict_outcome,
            ExternalCasOffhostAnchorReceiptOutcome::Conflict
        );
        assert_eq!(conflict_state, accepted);

        running.shutdown.store(true, Ordering::Release);
        let stats = running.join.join().unwrap().unwrap();
        assert_eq!(stats.accepted_connections, 3);
        assert_eq!(stats.completed_requests, 3);
        assert_eq!(stats.failed_requests, 0);
        drop(transport);
        drop(running.model);
        drop(running.counters);
        drop(running.shutdown);
        drop(model);

        // The old listener/model are gone. Reopen the disk state and bind a fresh daemon.
        let reopened_store = Arc::new(
            ExternalCasOffhostAnchorFileStore::open(
                &directory,
                f.anchor_pin.clone(),
                f.provider_pin.clone(),
            )
            .unwrap(),
        );
        let reopened_model = Arc::new(
            ExternalCasOffhostAnchorMemoryModel::with_store(
                f.anchor_pin.clone(),
                f.provider_pin.clone(),
                reopened_store,
            )
            .unwrap(),
        );
        assert_eq!(reopened_model.snapshot().unwrap(), accepted);
        let restarted = start_daemon_with_model(&f, Arc::clone(&reopened_model), 2, 4);
        let restarted_transport = client_transport(&restarted, &f);
        let read_after = ExternalCasOffhostAnchorReadRequest {
            challenge: [0xD1; 32],
            operation_id: [0xD2; 32],
            request_digest: [0xD3; 32],
        };
        let after_receipt = restarted_transport.read(&read_after).unwrap();
        assert_eq!(
            after_receipt
                .verify_read(&f.anchor_pin, &f.provider_pin, &read_after, &verifier)
                .unwrap(),
            accepted
        );

        restarted.shutdown.store(true, Ordering::Release);
        let restarted_stats = restarted.join.join().unwrap().unwrap();
        assert_eq!(restarted_stats.accepted_connections, 1);
        assert_eq!(restarted_stats.completed_requests, 1);
        drop(restarted_transport);
        drop(restarted.model);
        drop(restarted.counters);
        drop(restarted.shutdown);
        drop(reopened_model);
        std::fs::remove_dir_all(&directory).unwrap();
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

    #[test]
    fn config_and_daemon_debug_redact_noise_private_key() {
        let f = fixture();
        let (server_private, _) = noise_keypair();
        let (_, client_public) = noise_keypair();
        let config = daemon_config(
            "127.0.0.1:0".parse().unwrap(),
            f.anchor_pin.clone(),
            f.provider_pin.clone(),
            server_private,
            client_public,
            1,
            1,
        );
        let config_debug = format!("{config:?}");
        assert!(config_debug.contains("<redacted>"));
        assert!(!config_debug.contains(&format!("{server_private:?}")));

        let daemon = OffhostAnchorNoiseDaemon::bind(
            config,
            model(&f),
            Arc::new(LibcruxMlDsa65VerifierCandidate),
            Arc::new(f.anchor_signer.clone()),
        )
        .unwrap();
        let daemon_debug = format!("{daemon:?}");
        assert!(daemon_debug.contains("<redacted>"));
        assert!(!daemon_debug.contains(&format!("{server_private:?}")));
    }

    #[test]
    fn node_service_owner_explicit_shutdown_joins_the_attached_daemon() {
        use crate::external_cas_offhost_anchor_node_lifecycle_candidate::OffhostAnchorNodeServiceOwner;

        let f = fixture();
        let (daemon, _server_public, _client_private) = bind_daemon_at(
            &f,
            "127.0.0.1:0".parse().unwrap(),
            f.anchor_signer.clone(),
            2,
            1,
        );
        let counters = Arc::clone(&daemon.counters);
        let task = daemon.spawn().unwrap();
        let mut owner = OffhostAnchorNodeServiceOwner::disabled();
        owner.try_attach(task).unwrap();
        assert!(owner.is_attached());
        assert!(wait_until(
            || owner
                .stats()
                .is_some_and(|stats| stats.active_worker_threads == 2),
            Duration::from_secs(2),
        ));

        owner.request_shutdown();
        assert!(wait_until(
            || owner
                .stats()
                .is_some_and(|stats| stats.active_worker_threads == 0),
            Duration::from_secs(2),
        ));
        let stats = owner.shutdown_and_join().unwrap().unwrap();
        assert_eq!(stats.worker_threads_started, 2);
        assert_eq!(stats.active_worker_threads, 0);
        assert!(!owner.is_attached());
        assert_eq!(owner.shutdown_and_join().unwrap(), None);
        assert_eq!(counters.snapshot().active_worker_threads, 0);
    }

    #[test]
    fn node_service_owner_returns_a_second_task_without_consuming_it() {
        use crate::external_cas_offhost_anchor_node_lifecycle_candidate::OffhostAnchorNodeServiceOwner;

        let f = fixture();
        let (first_daemon, _first_server_public, _first_client_private) = bind_daemon_at(
            &f,
            "127.0.0.1:0".parse().unwrap(),
            f.anchor_signer.clone(),
            1,
            1,
        );
        let (second_daemon, _second_server_public, _second_client_private) = bind_daemon_at(
            &f,
            "127.0.0.1:0".parse().unwrap(),
            f.anchor_signer.clone(),
            1,
            1,
        );
        let first_counters = Arc::clone(&first_daemon.counters);
        let second_counters = Arc::clone(&second_daemon.counters);
        let mut owner = OffhostAnchorNodeServiceOwner::default();
        owner.try_attach(first_daemon.spawn().unwrap()).unwrap();
        let returned_task = owner
            .try_attach(second_daemon.spawn().unwrap())
            .unwrap_err();
        assert!(!returned_task.is_finished());
        assert!(wait_until(
            || returned_task.stats().active_worker_threads == 1
                && owner
                    .stats()
                    .is_some_and(|stats| stats.active_worker_threads == 1),
            Duration::from_secs(2),
        ));

        let returned_stats = returned_task.shutdown_and_join().unwrap();
        let owned_stats = owner.shutdown_and_join().unwrap().unwrap();
        assert_eq!(returned_stats.active_worker_threads, 0);
        assert_eq!(owned_stats.active_worker_threads, 0);
        assert_eq!(first_counters.snapshot().active_worker_threads, 0);
        assert_eq!(second_counters.snapshot().active_worker_threads, 0);
    }

    #[test]
    fn dropping_node_service_owner_joins_its_attached_daemon() {
        use crate::external_cas_offhost_anchor_node_lifecycle_candidate::OffhostAnchorNodeServiceOwner;

        let f = fixture();
        let (daemon, _server_public, _client_private) = bind_daemon_at(
            &f,
            "127.0.0.1:0".parse().unwrap(),
            f.anchor_signer.clone(),
            2,
            1,
        );
        let counters = Arc::clone(&daemon.counters);
        let task = daemon.spawn().unwrap();
        let mut owner = OffhostAnchorNodeServiceOwner::default();
        owner.try_attach(task).unwrap();
        assert!(wait_until(
            || owner
                .stats()
                .is_some_and(|stats| stats.active_worker_threads == 2),
            Duration::from_secs(2),
        ));

        drop(owner);
        assert_eq!(counters.snapshot().active_worker_threads, 0);
    }

    #[test]
    fn supervised_task_shutdown_joins_workers_and_reports_zero_active_threads() {
        let f = fixture();
        let (daemon, _server_public, _client_private) = bind_daemon_at(
            &f,
            "127.0.0.1:0".parse().unwrap(),
            f.anchor_signer.clone(),
            3,
            2,
        );
        assert_eq!(daemon.stats().worker_threads_started, 0);
        assert_eq!(daemon.stats().active_worker_threads, 0);
        let task = daemon.spawn().unwrap();
        assert!(wait_until(
            || task.stats().active_worker_threads == 3,
            Duration::from_secs(2),
        ));
        assert_eq!(task.stats().worker_threads_started, 3);
        assert!(!task.is_finished());

        task.request_shutdown();
        let stats = task.join().unwrap();
        assert_eq!(stats.worker_threads_started, 3);
        assert_eq!(stats.active_worker_threads, 0);
    }

    #[test]
    fn dropping_supervised_task_requests_shutdown_and_joins_workers() {
        let f = fixture();
        let (daemon, _server_public, _client_private) = bind_daemon_at(
            &f,
            "127.0.0.1:0".parse().unwrap(),
            f.anchor_signer.clone(),
            2,
            1,
        );
        let counters = Arc::clone(&daemon.counters);
        let task = daemon.spawn().unwrap();
        assert!(wait_until(
            || task.stats().active_worker_threads == 2,
            Duration::from_secs(2),
        ));

        drop(task);
        assert_eq!(counters.snapshot().active_worker_threads, 0);
    }

    #[test]
    fn supervised_worker_panic_fails_closed_and_owner_can_explicitly_rebind() {
        let f = fixture();
        let mut panic_signer = f.anchor_signer.clone();
        panic_signer.panic_on_sign = true;
        let (daemon, server_public, client_private) =
            bind_daemon_at(&f, "127.0.0.1:0".parse().unwrap(), panic_signer, 2, 1);
        let address = daemon.local_addr().unwrap();
        let counters = Arc::clone(&daemon.counters);
        let task = daemon.spawn().unwrap();
        assert!(wait_until(
            || task.stats().active_worker_threads == 2,
            Duration::from_secs(2),
        ));

        let transport = NoiseTcpOffhostAnchorTransport::new(
            address,
            client_private,
            server_public,
            f.anchor_pin.clone(),
            f.provider_pin.clone(),
        )
        .unwrap();
        let request = ExternalCasOffhostAnchorReadRequest {
            challenge: [0xEA; 32],
            operation_id: [0xEB; 32],
            request_digest: [0xEC; 32],
        };
        assert!(transport.read(&request).is_err());
        assert!(wait_until(|| task.is_finished(), Duration::from_secs(2)));
        assert!(matches!(
            task.join(),
            Err(OffhostAnchorNoiseError::Io(message))
                if message.contains("worker thread panicked")
        ));
        let failed_stats = counters.snapshot();
        assert_eq!(failed_stats.accepted_connections, 1);
        assert_eq!(failed_stats.failed_requests, 1);
        assert_eq!(failed_stats.active_worker_threads, 0);

        // Recovery is explicit: a fresh daemon with a newly constructed configuration must bind
        // successfully after the failed service has been joined and released its listener.
        let (replacement, _replacement_server_public, _replacement_client_private) =
            bind_daemon_at(&f, address, f.anchor_signer.clone(), 1, 1);
        assert_eq!(replacement.local_addr().unwrap(), address);
        let replacement_task = replacement.spawn().unwrap();
        assert!(wait_until(
            || replacement_task.stats().active_worker_threads == 1,
            Duration::from_secs(2),
        ));
        let replacement_stats = replacement_task.shutdown_and_join().unwrap();
        assert_eq!(replacement_stats.active_worker_threads, 0);
        assert_eq!(replacement_stats.worker_threads_started, 1);
    }

    #[test]
    fn worker_panic_releases_active_connection_counts_failure_and_is_reported() {
        let f = fixture();
        let (server_private, server_public) = noise_keypair();
        let (client_private, client_public) = noise_keypair();
        let config = daemon_config(
            "127.0.0.1:0".parse().unwrap(),
            f.anchor_pin.clone(),
            f.provider_pin.clone(),
            server_private,
            client_public,
            2,
            1,
        );
        let mut panic_signer = f.anchor_signer.clone();
        panic_signer.panic_on_sign = true;
        let daemon = OffhostAnchorNoiseDaemon::bind(
            config,
            model(&f),
            Arc::new(LibcruxMlDsa65VerifierCandidate),
            Arc::new(panic_signer),
        )
        .unwrap();
        let address = daemon.local_addr().unwrap();
        let counters = Arc::clone(&daemon.counters);
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_shutdown = Arc::clone(&shutdown);
        let join = thread::spawn(move || daemon.run_until_shutdown(&worker_shutdown));

        let transport = NoiseTcpOffhostAnchorTransport::new(
            address,
            client_private,
            server_public,
            f.anchor_pin.clone(),
            f.provider_pin.clone(),
        )
        .unwrap();
        let request = ExternalCasOffhostAnchorReadRequest {
            challenge: [0xE7; 32],
            operation_id: [0xE8; 32],
            request_digest: [0xE9; 32],
        };
        assert!(transport.read(&request).is_err());
        shutdown.store(true, Ordering::Release);

        let result = join.join().unwrap();
        assert!(matches!(
            result,
            Err(OffhostAnchorNoiseError::Io(message))
                if message.contains("worker thread panicked")
        ));
        let stats = counters.snapshot();
        assert_eq!(stats.accepted_connections, 1);
        assert_eq!(stats.completed_requests, 0);
        assert_eq!(stats.failed_requests, 1);
        assert_eq!(stats.worker_threads_started, 2);
        assert_eq!(stats.active_worker_threads, 0);
        assert_eq!(counters.active_connections.load(Ordering::Relaxed), 0);
    }

    const CP0489_CHILD_ENV: &str = "QRUN_CP0489_SIGNAL_CHILD";
    const CP0489_CHILD_READY: &str = "CP0489_CHILD_READY";
    const CP0489_DAEMON_JOINED: &str = "CP0489_ANCHOR_DAEMON_JOINED_ACTIVE_WORKERS=0";
    const CP0489_HANDLER_RESTORED: &str = "CP0489_SIGNAL_HANDLER_RESTORED=true";

    #[test]
    fn os_signal_child_probe_for_anchor_shutdown() {
        if std::env::var_os(CP0489_CHILD_ENV).is_none() {
            return;
        }

        use crate::external_cas_offhost_anchor_node_lifecycle_candidate::OffhostAnchorNodeServiceOwner;
        use crate::qrun_node_shutdown_signal_candidate::QRunNodeShutdownSignalCandidate;

        let signal = QRunNodeShutdownSignalCandidate::install().unwrap();
        let f = fixture();
        let (daemon, _server_public, _client_private) = bind_daemon_at(
            &f,
            "127.0.0.1:0".parse().unwrap(),
            f.anchor_signer.clone(),
            2,
            1,
        );
        let counters = Arc::clone(&daemon.counters);
        let task = daemon.spawn().unwrap();
        let mut owner = OffhostAnchorNodeServiceOwner::disabled();
        owner.try_attach(task).unwrap();
        assert!(wait_until(
            || owner
                .stats()
                .is_some_and(|stats| stats.active_worker_threads == 2),
            Duration::from_secs(3),
        ));

        println!("{CP0489_CHILD_READY}");
        while !signal.is_shutdown_requested() {
            thread::sleep(Duration::from_millis(5));
        }

        let stats = owner.shutdown_and_join().unwrap().unwrap();
        assert_eq!(stats.worker_threads_started, 2);
        assert_eq!(stats.active_worker_threads, 0);
        assert!(!owner.is_attached());
        assert_eq!(counters.snapshot().active_worker_threads, 0);

        signal.uninstall().unwrap();
        println!("{CP0489_DAEMON_JOINED}");
        println!("{CP0489_HANDLER_RESTORED}");
    }

    #[test]
    fn os_signal_in_child_process_joins_anchor_workers_and_restores_handler() {
        use std::{
            io::{BufRead, BufReader},
            process::{Command, Stdio},
            sync::mpsc,
        };

        fn forward_pipe<R: std::io::Read + Send + 'static>(
            pipe: R,
            label: &'static str,
            sender: mpsc::Sender<String>,
        ) -> thread::JoinHandle<()> {
            thread::spawn(move || {
                for line in BufReader::new(pipe).lines() {
                    match line {
                        Ok(line) => {
                            let _ = sender.send(format!("{label}: {line}"));
                        }
                        Err(error) => {
                            let _ = sender.send(format!("{label}: <read error: {error}>"));
                            break;
                        }
                    }
                }
            })
        }

        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .arg("os_signal_child_probe_for_anchor_shutdown")
            .arg("--nocapture")
            .env(CP0489_CHILD_ENV, "1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0000_0200); // CREATE_NEW_PROCESS_GROUP
        }

        let mut child = command
            .spawn()
            .expect("spawn isolated daemon lifecycle test");
        let (sender, receiver) = mpsc::channel();
        let stdout_thread = forward_pipe(child.stdout.take().unwrap(), "stdout", sender.clone());
        let stderr_thread = forward_pipe(child.stderr.take().unwrap(), "stderr", sender);
        let mut output = Vec::new();
        let ready_deadline = Instant::now() + Duration::from_secs(20);
        let mut ready = false;

        while Instant::now() < ready_deadline {
            if let Some(status) = child.try_wait().unwrap() {
                stdout_thread.join().unwrap();
                stderr_thread.join().unwrap();
                while let Ok(line) = receiver.try_recv() {
                    output.push(line);
                }
                panic!(
                    "signal child exited before daemon was ready; status={status:?}; output={output:#?}"
                );
            }
            if let Ok(line) = receiver.recv_timeout(Duration::from_millis(50)) {
                output.push(line);
                if output
                    .last()
                    .is_some_and(|line| line.contains(CP0489_CHILD_READY))
                {
                    ready = true;
                    break;
                }
            }
        }

        if !ready {
            let _ = child.kill();
            let status = child.wait().unwrap();
            stdout_thread.join().unwrap();
            stderr_thread.join().unwrap();
            while let Ok(line) = receiver.try_recv() {
                output.push(line);
            }
            panic!(
                "signal child did not start the supervised Anchor workers; status={status:?}; output={output:#?}"
            );
        }

        #[cfg(unix)]
        let signal_delivery = {
            let result = unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
            if result == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        };
        #[cfg(windows)]
        let signal_delivery = {
            #[link(name = "kernel32")]
            extern "system" {
                fn GenerateConsoleCtrlEvent(control_type: u32, process_group_id: u32) -> i32;
            }
            let result = unsafe { GenerateConsoleCtrlEvent(1, child.id()) }; // CTRL_BREAK_EVENT
            if result != 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        };

        if let Err(error) = signal_delivery {
            let _ = child.kill();
            let status = child.wait().unwrap();
            stdout_thread.join().unwrap();
            stderr_thread.join().unwrap();
            while let Ok(line) = receiver.try_recv() {
                output.push(line);
            }
            panic!(
                "failed to send process shutdown signal to daemon child; error={error}; status={status:?}; output={output:#?}"
            );
        }

        let shutdown_deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= shutdown_deadline {
                let _ = child.kill();
                let killed_status = child.wait().unwrap();
                stdout_thread.join().unwrap();
                stderr_thread.join().unwrap();
                while let Ok(line) = receiver.try_recv() {
                    output.push(line);
                }
                panic!(
                    "signal child failed to stop/join its Anchor daemon; status={killed_status:?}; output={output:#?}"
                );
            }
            if let Ok(line) = receiver.recv_timeout(Duration::from_millis(50)) {
                output.push(line);
            }
        };

        stdout_thread.join().unwrap();
        stderr_thread.join().unwrap();
        while let Ok(line) = receiver.try_recv() {
            output.push(line);
        }

        assert_eq!(
            status.code(),
            Some(0),
            "daemon signal child failed: {output:#?}"
        );
        assert!(
            output
                .iter()
                .any(|line| line.contains(CP0489_DAEMON_JOINED)),
            "Anchor daemon workers were not joined before child exit: {output:#?}"
        );
        assert!(
            output
                .iter()
                .any(|line| line.contains(CP0489_HANDLER_RESTORED)),
            "signal handler restoration was not verified by the child: {output:#?}"
        );
    }
}
