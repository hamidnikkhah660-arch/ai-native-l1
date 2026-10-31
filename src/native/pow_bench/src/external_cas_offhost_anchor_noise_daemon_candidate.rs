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
    thread::{self, JoinHandle},
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
}

/// Monotonic daemon counters. Accepted includes sockets rejected because the bounded queue was full.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OffhostAnchorNoiseDaemonStats {
    pub accepted_connections: u64,
    pub overload_rejected_connections: u64,
    pub completed_requests: u64,
    pub failed_requests: u64,
}

impl Counters {
    fn snapshot(&self) -> OffhostAnchorNoiseDaemonStats {
        OffhostAnchorNoiseDaemonStats {
            accepted_connections: self.accepted.load(Ordering::Relaxed),
            overload_rejected_connections: self.overload_rejected.load(Ordering::Relaxed),
            completed_requests: self.completed.load(Ordering::Relaxed),
            failed_requests: self.failed.load(Ordering::Relaxed),
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
            && config.anchor_pin.validate(&config.provider_pin).is_ok();
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
        let mut workers: Vec<JoinHandle<()>> = Vec::with_capacity(self.max_workers);

        for worker_index in 0..self.max_workers {
            let receiver = Arc::clone(&shared_receiver);
            let stop = Arc::clone(&worker_stop);
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
                .spawn(move || loop {
                    let received = match receiver.lock() {
                        Ok(guard) => guard.recv(),
                        Err(_) => break,
                    };
                    let stream = match received {
                        Ok(stream) => stream,
                        Err(_) => break,
                    };
                    if stop.load(Ordering::Acquire) {
                        drop(stream);
                        break;
                    }
                    let mut stream = stream;
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
                        counters.completed.fetch_add(1, Ordering::Relaxed);
                    } else {
                        counters.failed.fetch_add(1, Ordering::Relaxed);
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
