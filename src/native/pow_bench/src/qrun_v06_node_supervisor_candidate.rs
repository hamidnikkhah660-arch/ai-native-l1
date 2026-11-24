//! CP-0568 supervised QFP6 peer-service lifecycle candidate.
//!
//! Joins the existing QAP1 admission coordinator, authenticated QFP6 Noise listener and
//! process-shutdown signal bridge. It accepts an already-opened, QAP1-recovered runtime and
//! already-provisioned cryptographic dependencies; it never generates keys, bootstraps Genesis,
//! invents trust pins or provisions a cloud service.
//!
//! Startup fails closed unless the runtime is QAP1-required, matches the supplied network/profile,
//! has no unresolved anchor transition and does not require recovery. Only loopback/private/LAN/
//! overlay binding remains accepted by the underlying listener. The mining-supervisor variant
//! routes Q6TI submissions into a bounded pool, persists accepted pending transactions in an
//! immutable-generation journal, restores/revalidates them against recovered QAP1 state, and
//! selects them for QAP1 mining. This remains a candidate service seam, not a standalone
//! production launcher, RPC server, peer-discovery service or Mainnet. A separate permissionless
//! startup wrapper can complete bounded history sync from operator-pinned peers before mining.

use crate::{
    external_cas_anchor_candidate::{ExternalCasPin, ExternalCasProviderTransport},
    qrun_node_shutdown_signal_candidate::QRunNodeShutdownSignalCandidate,
    qrun_v06_canonical_execution_candidate::{
        QRunV06BlockOperation, QRunV06CanonicalExecutionState, MAX_QRUN_V06_BLOCK_OPERATIONS,
    },
    qrun_v06_external_anchor_candidate::{QRunV06ExternalAnchorPin, QRunV06ExternalAnchorState},
    qrun_v06_history_sync_service_candidate::{
        sync_history_from_pinned_peer_until_complete_with_qap1, QRunV06HistorySyncClientConfig,
        QRunV06HistorySyncClientReport, QRunV06HistorySyncResponder,
    },
    qrun_v06_history_sync_wire_candidate::{
        decode_q6hi_request, decode_q6hs_request, encode_q6hr_status, Q6HI_REQUEST_MAGIC,
        Q6HS_REQUEST_MAGIC,
    },
    qrun_v06_market_ingress_candidate::Q6MO_MAGIC,
    qrun_v06_miner_candidate::QRUN_V06_MAX_NONCE_ATTEMPTS_PER_JOB,
    qrun_v06_node_runtime_candidate::{
        QRunV06NodeAnchorGate, QRunV06NodeRuntime, QRunV06PeerReplayGuard,
    },
    qrun_v06_peer_address_relay_candidate::{
        decode_q6ar_pull_request, encode_q6ar_pull_response, Q6AR_MAX_ADDRESSES,
        Q6AR_PULL_REQUEST_MAGIC,
    },
    qrun_v06_peer_connection_manager_candidate::{
        QRunV06PeerConnectionManagerCandidate, QRunV06PeerTrustState,
    },
    qrun_v06_peer_discovery_candidate::{
        Q6PD_ANNOUNCE_REQUEST_MAGIC, Q6PD_MAX_TTL_SECS, Q6PD_PULL_REQUEST_MAGIC,
    },
    qrun_v06_peer_discovery_store_candidate::Q6pdPeerRecordStore,
    qrun_v06_peer_identity_candidate::Q6pdNodeIdentity,
    qrun_v06_peer_listener_candidate::{
        process_qfp6_peer_frame_with_permissionless_runtime,
        process_qfp6_peer_frame_with_permissionless_runtime_and_quote_asset_authorization,
        process_qfp6_peer_frame_with_qap1,
        serve_qfp6_noise_listener_with_history_and_q6ar_relay_pins_with_rate_limiter,
        serve_qfp6_noise_listener_with_rate_limiter, QRunV06PeerListenerConfig,
        QRunV06PeerListenerError, QRunV06PeerListenerStats, QRunV06PeerListenerStopReason,
        QRunV06PeerSourceRateLimiter,
    },
    qrun_v06_permissionless_runtime_candidate::QRunV06PermissionlessNodeRuntime,
    qrun_v06_permissionless_service_candidate::{
        QRunV06PermissionlessMempool, QRunV06PermissionlessServiceError,
    },
    qrun_v06_pow_fork_choice_candidate::{
        QRunV06PowForkChoice, QRunV06QuoteAssetAuthorizationProvider,
    },
    qrun_v06_qap1_coordinator_candidate::{
        QRunV06Qap1AnchorTransport, QRunV06Qap1ExternalCoordinator,
    },
    qrun_v06_qap1_mining_loop_candidate::{
        run_qfp6_qap1_mining_loop, QRunV06Qap1MiningLoopConfig, QRunV06Qap1MiningStopReason,
    },
    qrun_v06_transaction_ingress_candidate::{
        decode_q6ta_response, process_q6ti_transaction_frame, QRunV06TransactionSubmitStatus,
        Q6TI_MAGIC,
    },
    qrun_v06_transaction_journal_candidate::QRunV06TransactionJournal,
    qrun_v06_transaction_mempool_candidate::QRunV06NativeTransactionMempool,
    state_machine::TransactionAuthenticator,
    v4_fat1_trust_candidate::MlDsa65Verifier,
};
use std::{
    collections::HashSet,
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const QRUN_V06_SUPERVISOR_MAX_TOTAL_SESSIONS: usize = 1_000_000;
const SHUTDOWN_WATCH_INTERVAL: Duration = Duration::from_millis(10);
/// Reconnect to the operator-pinned bootstrap set so a joining node keeps tracking the chain
/// after its initial history import. Each refresh is deliberately bounded and reuses no session.
const QRUN_V06_OUTBOUND_BOOTSTRAP_RESYNC_INTERVAL: Duration = Duration::from_secs(30);
const QRUN_V06_OUTBOUND_BOOTSTRAP_RESYNC_PEERS_PER_CYCLE: usize = 1;
/// Periodically refresh candidate addresses from one operator-pinned Q6AR relay.
const QRUN_V06_Q6AR_DISCOVERY_PULL_INTERVAL: Duration = Duration::from_secs(300);
// Rapid Q6PD inventory exchange: signed addresses fan out through every
// successful peer exchange, so this cadence governs how quickly the graph learns.
const QRUN_V06_Q6PD_DISCOVERY_PULL_INTERVAL: Duration = Duration::from_secs(30);
const QRUN_V06_Q6PD_CANDIDATE_DIAL_INTERVAL: Duration = Duration::from_secs(5);
/// Determine whether the pinned-bootstrap history/resync cadence has elapsed.
fn outbound_bootstrap_resync_due(last_sync: Instant, now: Instant) -> bool {
    now.saturating_duration_since(last_sync) >= QRUN_V06_OUTBOUND_BOOTSTRAP_RESYNC_INTERVAL
}

fn q6ar_discovery_pull_due(last_pull: Instant, now: Instant) -> bool {
    now.saturating_duration_since(last_pull) >= QRUN_V06_Q6AR_DISCOVERY_PULL_INTERVAL
}

fn q6pd_discovery_pull_due(last_pull: Instant, now: Instant) -> bool {
    now.saturating_duration_since(last_pull) >= QRUN_V06_Q6PD_DISCOVERY_PULL_INTERVAL
}

fn q6pd_candidate_dial_due(last_dial: Instant, now: Instant) -> bool {
    now.saturating_duration_since(last_dial) >= QRUN_V06_Q6PD_CANDIDATE_DIAL_INTERVAL
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QRunV06NodeSupervisorConfig {
    /// Per-listener-round cap. The supervisor re-enters the listener after a full round.
    pub listener: QRunV06PeerListenerConfig,
    /// Hard process-lifetime cap on accepted TCP connections, including failed handshakes.
    pub max_total_sessions: usize,
    /// Install OS Ctrl-C/Ctrl-Break or SIGINT/SIGTERM handlers.
    /// Disable only when an embedding service manager owns the external shutdown flag.
    pub install_os_signal_handler: bool,
}

impl Default for QRunV06NodeSupervisorConfig {
    fn default() -> Self {
        Self {
            listener: QRunV06PeerListenerConfig::default(),
            max_total_sessions: QRUN_V06_SUPERVISOR_MAX_TOTAL_SESSIONS,
            install_os_signal_handler: true,
        }
    }
}

impl QRunV06NodeSupervisorConfig {
    pub fn validate(&self) -> Result<(), QRunV06NodeSupervisorError> {
        self.listener
            .validate()
            .map_err(|error| QRunV06NodeSupervisorError::Listener(error.to_string()))?;
        if !(1..=QRUN_V06_SUPERVISOR_MAX_TOTAL_SESSIONS).contains(&self.max_total_sessions) {
            return Err(QRunV06NodeSupervisorError::InvalidConfiguration);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QRunV06NodeSupervisorStopReason {
    ShutdownRequested,
    SessionBudgetReached,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QRunV06NodeSupervisorReport {
    pub listener_rounds: u64,
    pub stats: QRunV06PeerListenerStats,
    pub stop_reason: QRunV06NodeSupervisorStopReason,
}

/// Settings for the alternating peer-ingress and QAP1-mining lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QRunV06MiningSupervisorConfig {
    pub peer: QRunV06NodeSupervisorConfig,
    /// A peer accept window is finite even when no peers connect.
    pub listener_round_timeout: Duration,
    /// Finite block and nonce budgets applied after each listener window.
    pub mining: QRunV06Qap1MiningLoopConfig,
}

impl Default for QRunV06MiningSupervisorConfig {
    fn default() -> Self {
        let mining_defaults = QRunV06Qap1MiningLoopConfig::default();
        Self {
            peer: QRunV06NodeSupervisorConfig::default(),
            listener_round_timeout: Duration::from_millis(250),
            mining: QRunV06Qap1MiningLoopConfig {
                max_blocks_per_run: 1,
                max_nonce_attempts_per_block: mining_defaults.max_nonce_attempts_per_block,
            },
        }
    }
}

impl QRunV06MiningSupervisorConfig {
    pub fn validate(&self) -> Result<(), QRunV06NodeSupervisorError> {
        self.peer.validate()?;
        if self.listener_round_timeout < Duration::from_millis(20)
            || self.listener_round_timeout > Duration::from_secs(30)
        {
            return Err(QRunV06NodeSupervisorError::InvalidConfiguration);
        }
        self.mining
            .validate()
            .map_err(|error| QRunV06NodeSupervisorError::Mining(error.to_string()))?;
        Ok(())
    }
}

/// Settings for the permissionless Genesis-rooted peer-ingress and PoW-mining lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QRunV06PermissionlessMiningSupervisorConfig {
    pub peer: QRunV06NodeSupervisorConfig,
    pub listener_round_timeout: Duration,
    /// Maximum established Noise sessions served before the supervisor takes a mining slice.
    /// Defaults to one; public zero-value testnet may use a small bounded batch per 30-second round.
    pub max_sessions_per_listener_round: usize,
    pub max_nonce_attempts_per_block: u64,
}

impl Default for QRunV06PermissionlessMiningSupervisorConfig {
    fn default() -> Self {
        Self {
            peer: QRunV06NodeSupervisorConfig::default(),
            listener_round_timeout: Duration::from_millis(250),
            max_sessions_per_listener_round: 1,
            max_nonce_attempts_per_block: QRUN_V06_MAX_NONCE_ATTEMPTS_PER_JOB,
        }
    }
}

impl QRunV06PermissionlessMiningSupervisorConfig {
    pub fn validate(&self) -> Result<(), QRunV06NodeSupervisorError> {
        self.peer.validate()?;
        if !(Duration::from_millis(20)..=Duration::from_secs(30))
            .contains(&self.listener_round_timeout)
            || !(1..=crate::qrun_v06_peer_listener_candidate::QRUN_V06_LISTENER_MAX_SESSIONS)
                .contains(&self.max_sessions_per_listener_round)
            || self.max_nonce_attempts_per_block == 0
            || self.max_nonce_attempts_per_block > QRUN_V06_MAX_NONCE_ATTEMPTS_PER_JOB
        {
            return Err(QRunV06NodeSupervisorError::InvalidConfiguration);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QRunV06PermissionlessMiningSupervisorReport {
    pub listener_rounds: u64,
    pub mining_rounds: u64,
    pub blocks_durably_committed: u64,
    pub blocks_became_canonical: u64,
    pub ending_height: u64,
    pub pending_mempool_transactions: usize,
    pub pending_mempool_bytes: usize,
    pub mempool_journal_generation: u64,
    pub stats: QRunV06PeerListenerStats,
    pub stop_reason: QRunV06NodeSupervisorStopReason,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06PinnedBootstrapPeer {
    /// Numeric destination chosen from a hash-pinned bootstrap record at launch.
    pub address: SocketAddr,
    /// Static Noise identity pin; this remains the peer authentication authority.
    pub noise_static_public_key: [u8; 32],
    /// Optional TLS SNI for a public TCP/443 relay. None preserves direct Noise/TCP.
    pub tls_server_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06Qap1LaunchReport {
    pub bootstrap_sync: QRunV06HistorySyncClientReport,
    pub supervisor: QRunV06MiningSupervisorReport,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06PermissionlessLaunchReport {
    pub bootstrap_sync: QRunV06HistorySyncClientReport,
    pub supervisor: QRunV06PermissionlessMiningSupervisorReport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QRunV06MiningSupervisorReport {
    pub listener_rounds: u64,
    pub mining_rounds: u64,
    pub blocks_acknowledged: u64,
    pub ending_height: u64,
    /// Transactions still pending in the bounded pool when the supervisor stops.
    pub pending_mempool_transactions: usize,
    /// Encoded bytes still pending in the bounded pool when the supervisor stops.
    pub pending_mempool_bytes: usize,
    /// Durable pending-transaction journal generation installed before shutdown.
    pub mempool_journal_generation: u64,
    pub stats: QRunV06PeerListenerStats,
    pub stop_reason: QRunV06NodeSupervisorStopReason,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QRunV06NodeSupervisorError {
    InvalidConfiguration,
    InvalidIdentity,
    RuntimeNotQap1Recovered,
    RuntimeRequiresRecovery,
    PendingAnchorTransition,
    NetworkMismatch,
    ProfileMismatch,
    CoordinatorPinMismatch,
    Listener(String),
    HandshakeBudgetExceeded,
    StatisticsOverflow,
    ShutdownSignal(String),
    ShutdownWatcherPanicked,
    RuntimePoisoned,
    Runtime(String),
    Mempool(String),
    Journal(String),
    Mining(String),
    InvalidBootstrapPeers,
    BootstrapSync(String),
}

impl std::fmt::Display for QRunV06NodeSupervisorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "QFP6 node supervisor refused/ended service: {self:?}")
    }
}
impl std::error::Error for QRunV06NodeSupervisorError {}

fn add_counter(total: &mut usize, value: usize) -> Result<(), QRunV06NodeSupervisorError> {
    *total = total
        .checked_add(value)
        .ok_or(QRunV06NodeSupervisorError::StatisticsOverflow)?;
    Ok(())
}

fn add_stats(
    total: &mut QRunV06PeerListenerStats,
    next: QRunV06PeerListenerStats,
) -> Result<(), QRunV06NodeSupervisorError> {
    add_counter(&mut total.accepted_connections, next.accepted_connections)?;
    add_counter(
        &mut total.authenticated_sessions,
        next.authenticated_sessions,
    )?;
    add_counter(
        &mut total.unverified_peer_sessions,
        next.unverified_peer_sessions,
    )?;
    add_counter(&mut total.rejected_handshakes, next.rejected_handshakes)?;
    add_counter(
        &mut total.rate_limited_connections,
        next.rate_limited_connections,
    )?;
    add_counter(
        &mut total.handshake_queue_rejections,
        next.handshake_queue_rejections,
    )?;
    add_counter(&mut total.cancelled_handshakes, next.cancelled_handshakes)?;
    add_counter(&mut total.requests_received, next.requests_received)?;
    add_counter(&mut total.responses_written, next.responses_written)?;
    add_counter(&mut total.handler_failures, next.handler_failures)?;
    add_counter(&mut total.malformed_responses, next.malformed_responses)?;
    add_counter(&mut total.q6ar_rejections, next.q6ar_rejections)?;
    add_counter(&mut total.sessions_closed, next.sessions_closed)?;
    Ok(())
}

fn established_session_count(
    stats: &QRunV06PeerListenerStats,
) -> Result<usize, QRunV06NodeSupervisorError> {
    stats
        .authenticated_sessions
        .checked_add(stats.unverified_peer_sessions)
        .ok_or(QRunV06NodeSupervisorError::StatisticsOverflow)
}

fn system_now_ms() -> Result<u64, QRunV06NodeSupervisorError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            QRunV06NodeSupervisorError::Runtime(format!("system clock invalid: {error}"))
        })?
        .as_millis()
        .try_into()
        .map_err(|_| {
            QRunV06NodeSupervisorError::Runtime("system clock exceeds millisecond range".into())
        })
}

/// Build dial targets exclusively from durable operator approvals. Preserve TLS SNI only
/// for an exact configured endpoint/key pair; newly approved numeric endpoints use direct Noise/TCP.
fn address_book_approved_dial_targets(
    address_book: &crate::qrun_v06_peer_address_manager_candidate::QRunV06PeerAddressBookCandidate,
    configured_peers: &[QRunV06PinnedBootstrapPeer],
    operator_selected_noise_keys: &[[u8; 32]],
    now_ms: u64,
) -> Vec<QRunV06PinnedBootstrapPeer> {
    address_book
        .approved_peer_pins(
            now_ms,
            crate::qrun_v06_peer_address_manager_candidate::MAX_PEERS,
        )
        .into_iter()
        .filter(|(_, noise_static_public_key)| {
            operator_selected_noise_keys.contains(noise_static_public_key)
        })
        .map(|(address, noise_static_public_key)| {
            let tls_server_name = configured_peers
                .iter()
                .find(|peer| {
                    peer.address == address
                        && peer.noise_static_public_key == noise_static_public_key
                })
                .and_then(|peer| peer.tls_server_name.clone());
            QRunV06PinnedBootstrapPeer {
                address,
                noise_static_public_key,
                tls_server_name,
            }
        })
        .collect()
}

fn validate_identity_material(
    local_static_private_key: &[u8; 32],
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
) -> Result<(), QRunV06NodeSupervisorError> {
    if local_static_private_key.iter().all(|byte| *byte == 0)
        || network_id.iter().all(|byte| *byte == 0)
        || profile_id.iter().all(|byte| *byte == 0)
    {
        return Err(QRunV06NodeSupervisorError::InvalidIdentity);
    }
    Ok(())
}

fn validate_qap1_lifecycle(
    qap1_required: bool,
    qap1_recovered: bool,
) -> Result<(), QRunV06NodeSupervisorError> {
    if !qap1_required || !qap1_recovered {
        return Err(QRunV06NodeSupervisorError::RuntimeNotQap1Recovered);
    }
    Ok(())
}

fn validate_qap1_pin_bindings(
    state: &QRunV06ExternalAnchorState,
    provider_pin: &ExternalCasPin,
    qfp6_pin: &QRunV06ExternalAnchorPin,
) -> Result<(), QRunV06NodeSupervisorError> {
    if qfp6_pin.external_cas_pin() != provider_pin
        || provider_pin.network_id != state.network_id
        || provider_pin.genesis_digest != state.genesis_digest
        || qfp6_pin.genesis_descriptor_commitment() != state.genesis_descriptor_commitment
    {
        return Err(QRunV06NodeSupervisorError::CoordinatorPinMismatch);
    }
    Ok(())
}

fn validate_startup<A: QRunV06NodeAnchorGate>(
    runtime: &QRunV06NodeRuntime<A>,
    local_static_private_key: &[u8; 32],
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
) -> Result<(), QRunV06NodeSupervisorError> {
    validate_identity_material(local_static_private_key, network_id, profile_id)?;
    validate_qap1_lifecycle(runtime.requires_qap1(), runtime.qap1_recovery_verified())?;
    if runtime.requires_reopen() {
        return Err(QRunV06NodeSupervisorError::RuntimeRequiresRecovery);
    }
    if runtime.has_pending_external_anchor() {
        return Err(QRunV06NodeSupervisorError::PendingAnchorTransition);
    }
    let anchor = runtime.committed_anchor_state();
    if anchor.network_id != *network_id {
        return Err(QRunV06NodeSupervisorError::NetworkMismatch);
    }
    if anchor.profile_id != *profile_id {
        return Err(QRunV06NodeSupervisorError::ProfileMismatch);
    }
    Ok(())
}

fn current_candidate_timestamp(state: &QRunV06CanonicalExecutionState) -> Result<u64, String> {
    let wall_clock = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock is before the Unix epoch: {error}"))?
        .as_secs();
    let after_parent = state
        .last_timestamp()
        .checked_add(1)
        .ok_or_else(|| "canonical block timestamp overflow".to_string())?;
    Ok(wall_clock.max(after_parent))
}

fn append_pending_mempool_transfers<A: TransactionAuthenticator>(
    mempool: &mut QRunV06NativeTransactionMempool,
    parent: &QRunV06CanonicalExecutionState,
    authenticator: &A,
    producer: [u8; 32],
    timestamp: u64,
    operations: &mut Vec<QRunV06BlockOperation>,
) -> Result<usize, String> {
    if timestamp <= parent.last_timestamp() {
        return Err("mining template timestamp must advance the canonical parent".to_string());
    }
    let _ =
        mempool.reconcile_after_canonical_change(parent, authenticator, producer, timestamp, &[]);
    let capacity = MAX_QRUN_V06_BLOCK_OPERATIONS.saturating_sub(operations.len());
    let mut appended = 0usize;
    for transaction in mempool.ordered_transactions().into_iter().take(capacity) {
        operations.push(QRunV06BlockOperation::NativeTransfer(transaction));
        appended += 1;
    }
    Ok(appended)
}

/// Dispatch one authenticated QFP6 application frame to either Q6PB durable admission
/// or Q6TI transaction submission. Q6TA Accepted remains process-local mempool admission;
/// it is never represented as block confirmation or QAP1 finality.
#[allow(clippy::too_many_arguments)]
pub fn process_qfp6_application_frame_with_qap1<A, T, P, PV, AV, Q>(
    runtime: &mut QRunV06NodeRuntime<A>,
    replay_guard: &mut QRunV06PeerReplayGuard,
    mempool: &mut QRunV06NativeTransactionMempool,
    journal: &mut QRunV06TransactionJournal,
    frame: &[u8],
    authenticator: &T,
    producer: [u8; 32],
    quote_authorizer: &mut QRunV06QuoteAssetAuthorizationProvider<'_>,
    coordinator: &mut QRunV06Qap1ExternalCoordinator<P, PV, AV, Q>,
) -> Result<
    [u8; crate::qrun_v06_node_runtime_candidate::QRUN_V06_PEER_ADMISSION_RESPONSE_BYTES],
    String,
>
where
    A: QRunV06NodeAnchorGate,
    T: TransactionAuthenticator,
    P: ExternalCasProviderTransport,
    PV: MlDsa65Verifier + Clone,
    AV: MlDsa65Verifier,
    Q: QRunV06Qap1AnchorTransport,
{
    if frame.get(..4) == Some(&Q6TI_MAGIC) {
        let fork_choice = runtime
            .fork_choice_snapshot()
            .map_err(|error| format!("cannot snapshot canonical state for Q6TI: {error}"))?;
        let state = fork_choice.canonical_state();
        let candidate_timestamp = current_candidate_timestamp(state)?;
        let request =
            crate::qrun_v06_transaction_ingress_candidate::decode_q6ti_transaction_request(frame)
                .map_err(|error| format!("Q6TI request decode failed: {error:?}"))?;
        let before_submit = mempool.clone();
        let response = process_q6ti_transaction_frame(
            frame,
            replay_guard,
            mempool,
            state,
            authenticator,
            producer,
            candidate_timestamp,
        )
        .map_err(|error| format!("Q6TI transaction submission failed: {error:?}"))?;
        let decoded = decode_q6ta_response(&response, request.request_id)
            .map_err(|error| format!("Q6TA response decode failed: {error:?}"))?;
        if decoded.status == QRunV06TransactionSubmitStatus::Accepted {
            if let Err(error) = journal.persist_pool(mempool) {
                *mempool = before_submit;
                return Err(format!("Q6TI durable journal write failed: {error}"));
            }
        }
        return Ok(response);
    }

    let response = process_qfp6_peer_frame_with_qap1(
        runtime,
        replay_guard,
        frame,
        authenticator,
        quote_authorizer,
        coordinator,
    )
    .map_err(|error| error.to_string())?;

    // A peer block may advance or reorg the canonical state. Revalidate pending transfers
    // against the resulting state before they can be selected for local mining.
    let fork_choice = runtime
        .fork_choice_snapshot()
        .map_err(|error| format!("cannot refresh canonical state after Q6PB: {error}"))?;
    let state = fork_choice.canonical_state();
    let candidate_timestamp = current_candidate_timestamp(state)?;
    let _ = mempool.reconcile_after_canonical_change(
        state,
        authenticator,
        producer,
        candidate_timestamp,
        &[],
    );
    journal
        .persist_pool(mempool)
        .map_err(|error| format!("Q6TI journal update after Q6PB failed: {error}"))?;
    Ok(response)
}

/// Run the supervised QFP6 peer service using already-recovered, QAP1-required state.
///
/// The caller must verify Q6PN/profile pins, open the durable fork store and construct the runtime
/// with the QAP1 restart-recovery constructor before calling this function. Provider and Q6EA
/// transports/verifiers must already be pinned and independently provisioned. This function does
/// not bootstrap a new Genesis or infer an anchor from local disk.
#[allow(clippy::too_many_arguments)]
pub fn run_qfp6_node_supervisor<A, T, P, PV, AV, Q>(
    listener: &TcpListener,
    config: QRunV06NodeSupervisorConfig,
    local_static_private_key: &[u8; 32],
    trusted_remote_static_public_keys: &[[u8; 32]],
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
    shutdown_requested: &AtomicBool,
    runtime: &mut QRunV06NodeRuntime<A>,
    authenticator: &T,
    quote_authorizer: &mut QRunV06QuoteAssetAuthorizationProvider<'_>,
    coordinator: &mut QRunV06Qap1ExternalCoordinator<P, PV, AV, Q>,
) -> Result<QRunV06NodeSupervisorReport, QRunV06NodeSupervisorError>
where
    A: QRunV06NodeAnchorGate,
    T: TransactionAuthenticator,
    P: ExternalCasProviderTransport,
    PV: MlDsa65Verifier + Clone,
    AV: MlDsa65Verifier,
    Q: QRunV06Qap1AnchorTransport,
{
    config.validate()?;
    validate_startup(runtime, local_static_private_key, network_id, profile_id)?;
    validate_qap1_pin_bindings(
        runtime.committed_anchor_state(),
        coordinator.provider_pin(),
        coordinator.qfp6_pin(),
    )?;
    if trusted_remote_static_public_keys.is_empty()
        || trusted_remote_static_public_keys.len() > 64
        || trusted_remote_static_public_keys
            .iter()
            .any(|key| key.iter().all(|byte| *byte == 0))
    {
        return Err(QRunV06NodeSupervisorError::InvalidIdentity);
    }

    let signal = if config.install_os_signal_handler {
        Some(
            QRunNodeShutdownSignalCandidate::install()
                .map_err(|error| QRunV06NodeSupervisorError::ShutdownSignal(error.to_string()))?,
        )
    } else {
        None
    };
    let signal_ref = signal.as_ref();
    let watcher_stop = AtomicBool::new(false);

    let run_result = thread::scope(|scope| {
        let watcher = scope.spawn(|| {
            while !watcher_stop.load(Ordering::Acquire) {
                if signal_ref.is_some_and(|signal| signal.is_shutdown_requested()) {
                    shutdown_requested.store(true, Ordering::Release);
                    break;
                }
                thread::sleep(SHUTDOWN_WATCH_INTERVAL);
            }
        });

        let service_result = (|| {
            let mut aggregate = QRunV06PeerListenerStats::default();
            let mut source_rate_limiter = QRunV06PeerSourceRateLimiter::new(Instant::now());
            let mut rounds = 0u64;

            let stop_reason = loop {
                if shutdown_requested.load(Ordering::Acquire) {
                    break QRunV06NodeSupervisorStopReason::ShutdownRequested;
                }
                if established_session_count(&aggregate)? >= config.max_total_sessions {
                    break QRunV06NodeSupervisorStopReason::SessionBudgetReached;
                }
                if runtime.requires_reopen() || runtime.has_pending_external_anchor() {
                    return Err(QRunV06NodeSupervisorError::RuntimePoisoned);
                }

                let remaining = config
                    .max_total_sessions
                    .checked_sub(established_session_count(&aggregate)?)
                    .ok_or(QRunV06NodeSupervisorError::StatisticsOverflow)?;
                let mut round_config = config.listener;
                round_config.max_sessions = round_config.max_sessions.min(remaining);

                let mut on_q6pb = |guard: &mut QRunV06PeerReplayGuard, frame: &[u8]| {
                    if runtime.requires_reopen() || runtime.has_pending_external_anchor() {
                        shutdown_requested.store(true, Ordering::Release);
                        return Err(
                            "QFP6 runtime is poisoned; reconcile QAP1 before service".to_string()
                        );
                    }
                    let response = process_qfp6_peer_frame_with_qap1(
                        runtime,
                        guard,
                        frame,
                        authenticator,
                        quote_authorizer,
                        coordinator,
                    );
                    if runtime.requires_reopen() || runtime.has_pending_external_anchor() {
                        shutdown_requested.store(true, Ordering::Release);
                    }
                    response
                };

                let report = serve_qfp6_noise_listener_with_rate_limiter(
                    listener,
                    round_config,
                    local_static_private_key,
                    trusted_remote_static_public_keys,
                    network_id,
                    profile_id,
                    shutdown_requested,
                    &mut on_q6pb,
                    &mut source_rate_limiter,
                )
                .map_err(|error: QRunV06PeerListenerError| {
                    QRunV06NodeSupervisorError::Listener(error.to_string())
                })?;

                rounds = rounds
                    .checked_add(1)
                    .ok_or(QRunV06NodeSupervisorError::StatisticsOverflow)?;
                add_stats(&mut aggregate, report.stats)?;

                if runtime.requires_reopen() || runtime.has_pending_external_anchor() {
                    return Err(QRunV06NodeSupervisorError::RuntimePoisoned);
                }

                match report.stop_reason {
                    QRunV06PeerListenerStopReason::ShutdownRequested => {
                        break QRunV06NodeSupervisorStopReason::ShutdownRequested;
                    }
                    QRunV06PeerListenerStopReason::FailedHandshakeLimitReached => {
                        return Err(QRunV06NodeSupervisorError::HandshakeBudgetExceeded);
                    }
                    QRunV06PeerListenerStopReason::SessionLimitReached => {
                        if established_session_count(&aggregate)? >= config.max_total_sessions {
                            break QRunV06NodeSupervisorStopReason::SessionBudgetReached;
                        }
                    }
                }
            };

            Ok(QRunV06NodeSupervisorReport {
                listener_rounds: rounds,
                stats: aggregate,
                stop_reason,
            })
        })();

        watcher_stop.store(true, Ordering::Release);
        if watcher.join().is_err() {
            return Err(QRunV06NodeSupervisorError::ShutdownWatcherPanicked);
        }
        service_result
    });

    let uninstall_result = match signal {
        Some(signal) => signal
            .uninstall()
            .map_err(|error| QRunV06NodeSupervisorError::ShutdownSignal(error.to_string())),
        None => Ok(()),
    };

    match (run_result, uninstall_result) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Ok(report), Ok(())) => Ok(report),
    }
}

/// Run one finite listener window. The local stop flag ends an idle round without raising the
/// process-wide shutdown flag; the latter is observed separately and remains authoritative.
fn serve_qfp6_listener_round<F>(
    listener: &TcpListener,
    config: QRunV06PeerListenerConfig,
    local_static_private_key: &[u8; 32],
    trusted_remote_static_public_keys: &[[u8; 32]],
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
    process_shutdown: &AtomicBool,
    round_timeout: Duration,
    source_rate_limiter: &mut QRunV06PeerSourceRateLimiter,
    on_q6pb: F,
) -> Result<
    (
        crate::qrun_v06_peer_listener_candidate::QRunV06PeerListenerReport,
        bool,
    ),
    QRunV06NodeSupervisorError,
>
where
    F: FnMut(
        &mut QRunV06PeerReplayGuard,
        &[u8],
    ) -> Result<
        [u8; crate::qrun_v06_node_runtime_candidate::QRUN_V06_PEER_ADMISSION_RESPONSE_BYTES],
        String,
    >,
{
    let round_shutdown = AtomicBool::new(false);
    let watcher_stop = AtomicBool::new(false);
    thread::scope(|scope| {
        let watcher = scope.spawn(|| {
            let deadline = Instant::now() + round_timeout;
            while !watcher_stop.load(Ordering::Acquire) {
                if process_shutdown.load(Ordering::Acquire) || Instant::now() >= deadline {
                    round_shutdown.store(true, Ordering::Release);
                    break;
                }
                thread::sleep(SHUTDOWN_WATCH_INTERVAL);
            }
        });

        let report = serve_qfp6_noise_listener_with_rate_limiter(
            listener,
            config,
            local_static_private_key,
            trusted_remote_static_public_keys,
            network_id,
            profile_id,
            &round_shutdown,
            on_q6pb,
            source_rate_limiter,
        );
        watcher_stop.store(true, Ordering::Release);
        if watcher.join().is_err() {
            return Err(QRunV06NodeSupervisorError::ShutdownWatcherPanicked);
        }
        let process_stopped = process_shutdown.load(Ordering::Acquire);
        report
            .map(|report| (report, process_stopped))
            .map_err(|error| QRunV06NodeSupervisorError::Listener(error.to_string()))
    })
}

/// Run one finite combined Q6PB/Q6TI/Q6HS listener window. Q6PA/Q6TA replies remain
/// fixed-width; Q6HS pages are streamed as prevalidated Q6HC records on the same pinned session.
fn serve_qfp6_history_listener_round<F, G>(
    listener: &TcpListener,
    config: QRunV06PeerListenerConfig,
    local_static_private_key: &[u8; 32],
    trusted_remote_static_public_keys: &[[u8; 32]],
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
    process_shutdown: &AtomicBool,
    round_timeout: Duration,
    source_rate_limiter: &mut QRunV06PeerSourceRateLimiter,
    q6ar_relay_static_public_key_pins: &[[u8; 32]],
    on_q6ar: G,
    on_application_frame: F,
) -> Result<
    (
        crate::qrun_v06_peer_listener_candidate::QRunV06PeerListenerReport,
        bool,
    ),
    QRunV06NodeSupervisorError,
>
where
    F: FnMut(
        std::net::SocketAddr,
        &mut QRunV06PeerReplayGuard,
        &[u8],
    ) -> Result<Vec<Vec<u8>>, String>,
    G: FnMut(
        crate::qrun_v06_peer_address_relay_candidate::Q6arReceivedAdvertisement,
    ) -> Result<(), String>,
{
    let round_shutdown = AtomicBool::new(false);
    let watcher_stop = AtomicBool::new(false);
    thread::scope(|scope| {
        let watcher = scope.spawn(|| {
            let deadline = Instant::now() + round_timeout;
            while !watcher_stop.load(Ordering::Acquire) {
                if process_shutdown.load(Ordering::Acquire) || Instant::now() >= deadline {
                    round_shutdown.store(true, Ordering::Release);
                    break;
                }
                thread::sleep(SHUTDOWN_WATCH_INTERVAL);
            }
        });

        let report = serve_qfp6_noise_listener_with_history_and_q6ar_relay_pins_with_rate_limiter(
            listener,
            config,
            local_static_private_key,
            trusted_remote_static_public_keys,
            q6ar_relay_static_public_key_pins,
            network_id,
            profile_id,
            &round_shutdown,
            on_q6ar,
            on_application_frame,
            source_rate_limiter,
        );
        watcher_stop.store(true, Ordering::Release);
        if watcher.join().is_err() {
            return Err(QRunV06NodeSupervisorError::ShutdownWatcherPanicked);
        }
        let process_stopped = process_shutdown.load(Ordering::Acquire);
        report
            .map(|report| (report, process_stopped))
            .map_err(|error| QRunV06NodeSupervisorError::Listener(error.to_string()))
    })
}

/// Alternate a finite authenticated peer-ingress window with a bounded QFP6 mining batch.
///
/// Ingress and mining share one QAP1 Runtime/coordinator. Q6TI transactions are validated into
/// a bounded mempool, persisted in immutable journal snapshots and revalidated after canonical
/// changes before being appended to mining templates. Q6TA Accepted means pending and journaled,
/// not block confirmation or QAP1 finality. Startup revalidates snapshots against the recovered
/// canonical state; the journal stores pending transactions, not canonical chain history.
///
/// After each peer window the fork-choice view is refreshed from the Runtime's durable store
/// before mining, so a peer-admitted block cannot leave the miner extending a stale in-memory tip.
/// The miner publishes its staged graph only after the ACK-safe QAP1 path completes.
/// LAN/overlay/loopback bind policy remains enforced.
#[allow(clippy::too_many_arguments)]
pub fn run_qfp6_mining_supervisor<A, T, P, PV, AV, Q, F>(
    listener: &TcpListener,
    config: QRunV06MiningSupervisorConfig,
    local_static_private_key: &[u8; 32],
    trusted_remote_static_public_keys: &[[u8; 32]],
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
    shutdown_requested: &AtomicBool,
    runtime: &mut QRunV06NodeRuntime<A>,
    authenticator: &T,
    quote_authorizer: &mut QRunV06QuoteAssetAuthorizationProvider<'_>,
    coordinator: &mut QRunV06Qap1ExternalCoordinator<P, PV, AV, Q>,
    producer: [u8; 32],
    transaction_journal: &mut QRunV06TransactionJournal,
    mut next_template: F,
) -> Result<QRunV06MiningSupervisorReport, QRunV06NodeSupervisorError>
where
    A: QRunV06NodeAnchorGate,
    T: TransactionAuthenticator,
    P: ExternalCasProviderTransport,
    PV: MlDsa65Verifier + Clone,
    AV: MlDsa65Verifier,
    Q: QRunV06Qap1AnchorTransport,
    F: FnMut(&QRunV06CanonicalExecutionState) -> Result<(u64, Vec<QRunV06BlockOperation>), String>,
{
    config.validate()?;
    validate_startup(runtime, local_static_private_key, network_id, profile_id)?;
    validate_qap1_pin_bindings(
        runtime.committed_anchor_state(),
        coordinator.provider_pin(),
        coordinator.qfp6_pin(),
    )?;
    if trusted_remote_static_public_keys.is_empty()
        || trusted_remote_static_public_keys.len() > 64
        || trusted_remote_static_public_keys
            .iter()
            .any(|key| key.iter().all(|byte| *byte == 0))
    {
        return Err(QRunV06NodeSupervisorError::InvalidIdentity);
    }

    // Restore pending transactions only after QAP1 canonical recovery has completed.
    let mut mempool = QRunV06NativeTransactionMempool::new(transaction_journal.limits())
        .map_err(|error| QRunV06NodeSupervisorError::Mempool(format!("{error:?}")))?;
    let startup_fork_choice = runtime
        .fork_choice_snapshot()
        .map_err(|error| QRunV06NodeSupervisorError::Runtime(error.to_string()))?;
    let startup_state = startup_fork_choice.canonical_state();
    let startup_timestamp =
        current_candidate_timestamp(startup_state).map_err(QRunV06NodeSupervisorError::Journal)?;
    transaction_journal
        .restore_into_pool(
            &mut mempool,
            startup_state,
            authenticator,
            producer,
            startup_timestamp,
        )
        .map_err(|error| QRunV06NodeSupervisorError::Journal(error.to_string()))?;

    let signal = if config.peer.install_os_signal_handler {
        Some(
            QRunNodeShutdownSignalCandidate::install()
                .map_err(|error| QRunV06NodeSupervisorError::ShutdownSignal(error.to_string()))?,
        )
    } else {
        None
    };
    let signal_ref = signal.as_ref();
    let watcher_stop = AtomicBool::new(false);

    let run_result = thread::scope(|scope| {
        let watcher = scope.spawn(|| {
            while !watcher_stop.load(Ordering::Acquire) {
                if signal_ref.is_some_and(|signal| signal.is_shutdown_requested()) {
                    shutdown_requested.store(true, Ordering::Release);
                    break;
                }
                thread::sleep(SHUTDOWN_WATCH_INTERVAL);
            }
        });

        let service_result = (|| {
            let mut aggregate = QRunV06PeerListenerStats::default();
            let mut source_rate_limiter = QRunV06PeerSourceRateLimiter::new(Instant::now());
            let mut listener_rounds = 0u64;
            let mut mining_rounds = 0u64;
            let mut blocks_acknowledged = 0u64;
            let stop_reason;

            loop {
                if shutdown_requested.load(Ordering::Acquire) {
                    stop_reason = QRunV06NodeSupervisorStopReason::ShutdownRequested;
                    break;
                }
                if established_session_count(&aggregate)? >= config.peer.max_total_sessions {
                    stop_reason = QRunV06NodeSupervisorStopReason::SessionBudgetReached;
                    break;
                }
                if runtime.requires_reopen() || runtime.has_pending_external_anchor() {
                    return Err(QRunV06NodeSupervisorError::RuntimePoisoned);
                }

                let remaining = config
                    .peer
                    .max_total_sessions
                    .checked_sub(established_session_count(&aggregate)?)
                    .ok_or(QRunV06NodeSupervisorError::StatisticsOverflow)?;
                let mut round_config = config.peer.listener;
                // One established Noise session per round gives the miner a bounded scheduling point.
                round_config.max_sessions = round_config.max_sessions.min(remaining).min(1);

                let mut on_q6pb = |guard: &mut QRunV06PeerReplayGuard, frame: &[u8]| {
                    if runtime.requires_reopen() || runtime.has_pending_external_anchor() {
                        shutdown_requested.store(true, Ordering::Release);
                        return Err(
                            "QFP6 runtime is poisoned; reconcile QAP1 before service".to_string()
                        );
                    }
                    let response = process_qfp6_application_frame_with_qap1(
                        runtime,
                        guard,
                        &mut mempool,
                        transaction_journal,
                        frame,
                        authenticator,
                        producer,
                        quote_authorizer,
                        coordinator,
                    );
                    if response.is_err()
                        || runtime.requires_reopen()
                        || runtime.has_pending_external_anchor()
                    {
                        shutdown_requested.store(true, Ordering::Release);
                    }
                    response
                };

                let (listener_report, process_stopped) = serve_qfp6_listener_round(
                    listener,
                    round_config,
                    local_static_private_key,
                    trusted_remote_static_public_keys,
                    network_id,
                    profile_id,
                    shutdown_requested,
                    config.listener_round_timeout,
                    &mut source_rate_limiter,
                    &mut on_q6pb,
                )?;

                listener_rounds = listener_rounds
                    .checked_add(1)
                    .ok_or(QRunV06NodeSupervisorError::StatisticsOverflow)?;
                add_stats(&mut aggregate, listener_report.stats)?;

                if runtime.requires_reopen() || runtime.has_pending_external_anchor() {
                    return Err(QRunV06NodeSupervisorError::RuntimePoisoned);
                }
                if process_stopped || shutdown_requested.load(Ordering::Acquire) {
                    stop_reason = QRunV06NodeSupervisorStopReason::ShutdownRequested;
                    break;
                }
                if listener_report.stop_reason
                    == QRunV06PeerListenerStopReason::FailedHandshakeLimitReached
                    && !trusted_remote_static_public_keys.is_empty()
                {
                    return Err(QRunV06NodeSupervisorError::HandshakeBudgetExceeded);
                }

                // A peer may have advanced durable state during the just-finished round.
                // Never mine with the pre-ingress graph snapshot.
                let mut fork_choice = runtime
                    .fork_choice_snapshot()
                    .map_err(|error| QRunV06NodeSupervisorError::Runtime(error.to_string()))?;

                let mining_report = run_qfp6_qap1_mining_loop(
                    runtime,
                    &mut fork_choice,
                    producer,
                    authenticator,
                    quote_authorizer,
                    coordinator,
                    config.mining,
                    shutdown_requested,
                    |parent| {
                        let (timestamp, mut operations) = next_template(parent)?;
                        // The callback supplies protocol/system operations. Native transfers
                        // are selected from authenticated Q6TI submissions in the mempool.
                        let _ = append_pending_mempool_transfers(
                            &mut mempool,
                            parent,
                            authenticator,
                            producer,
                            timestamp,
                            &mut operations,
                        )?;
                        transaction_journal
                            .persist_pool(&mempool)
                            .map_err(|error| {
                                format!("Q6TI journal persistence before mining failed: {error}")
                            })?;
                        Ok((timestamp, operations))
                    },
                )
                .map_err(|error| QRunV06NodeSupervisorError::Mining(error.to_string()))?;

                mining_rounds = mining_rounds
                    .checked_add(1)
                    .ok_or(QRunV06NodeSupervisorError::StatisticsOverflow)?;
                blocks_acknowledged = blocks_acknowledged
                    .checked_add(mining_report.blocks_acknowledged)
                    .ok_or(QRunV06NodeSupervisorError::StatisticsOverflow)?;

                if runtime.requires_reopen() || runtime.has_pending_external_anchor() {
                    return Err(QRunV06NodeSupervisorError::RuntimePoisoned);
                }
                let latest_fork_choice = runtime
                    .fork_choice_snapshot()
                    .map_err(|error| QRunV06NodeSupervisorError::Runtime(error.to_string()))?;
                let latest_state = latest_fork_choice.canonical_state();
                let latest_timestamp = current_candidate_timestamp(latest_state)
                    .map_err(QRunV06NodeSupervisorError::Journal)?;
                let _ = mempool.reconcile_after_canonical_change(
                    latest_state,
                    authenticator,
                    producer,
                    latest_timestamp,
                    &[],
                );
                transaction_journal
                    .persist_pool(&mempool)
                    .map_err(|error| QRunV06NodeSupervisorError::Journal(error.to_string()))?;

                if mining_report.stop_reason == QRunV06Qap1MiningStopReason::ShutdownRequested
                    || shutdown_requested.load(Ordering::Acquire)
                {
                    stop_reason = QRunV06NodeSupervisorStopReason::ShutdownRequested;
                    break;
                }
            }

            Ok(QRunV06MiningSupervisorReport {
                listener_rounds,
                mining_rounds,
                blocks_acknowledged,
                ending_height: runtime
                    .canonical_height()
                    .map_err(|error| QRunV06NodeSupervisorError::Runtime(error.to_string()))?,
                pending_mempool_transactions: mempool.len(),
                pending_mempool_bytes: mempool.total_bytes(),
                mempool_journal_generation: transaction_journal.generation(),
                stats: aggregate,
                stop_reason,
            })
        })();

        watcher_stop.store(true, Ordering::Release);
        if watcher.join().is_err() {
            return Err(QRunV06NodeSupervisorError::ShutdownWatcherPanicked);
        }
        service_result
    });

    let uninstall_result = match signal {
        Some(signal) => signal
            .uninstall()
            .map_err(|error| QRunV06NodeSupervisorError::ShutdownSignal(error.to_string())),
        None => Ok(()),
    };

    match (run_result, uninstall_result) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Ok(report), Ok(())) => Ok(report),
    }
}

/// Dispatch Q6TI, Q6MO or Q6PB inside an already authenticated Noise session. The
/// compatibility path rejects external-quote activity unless it is native quote.
#[allow(clippy::too_many_arguments)]
pub fn process_qfp6_application_frame_with_permissionless_runtime<T: TransactionAuthenticator>(
    runtime: &mut QRunV06PermissionlessNodeRuntime,
    replay_guard: &mut QRunV06PeerReplayGuard,
    mempool: &mut QRunV06PermissionlessMempool,
    frame: &[u8],
    authenticator: &T,
    producer: [u8; 32],
) -> Result<
    [u8; crate::qrun_v06_node_runtime_candidate::QRUN_V06_PEER_ADMISSION_RESPONSE_BYTES],
    String,
> {
    process_qfp6_application_frame_with_permissionless_runtime_and_quote_asset_authorization(
        runtime,
        replay_guard,
        mempool,
        frame,
        authenticator,
        producer,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn process_qfp6_application_frame_with_permissionless_runtime_and_quote_asset_authorization<
    T: TransactionAuthenticator,
>(
    runtime: &mut QRunV06PermissionlessNodeRuntime,
    replay_guard: &mut QRunV06PeerReplayGuard,
    mempool: &mut QRunV06PermissionlessMempool,
    frame: &[u8],
    authenticator: &T,
    producer: [u8; 32],
    mut quote_authorizer: Option<&mut QRunV06QuoteAssetAuthorizationProvider<'_>>,
) -> Result<
    [u8; crate::qrun_v06_node_runtime_candidate::QRUN_V06_PEER_ADMISSION_RESPONSE_BYTES],
    String,
> {
    if frame.get(..4) == Some(&Q6TI_MAGIC) {
        let graph = runtime
            .fork_choice_snapshot()
            .map_err(|error| format!("cannot snapshot permissionless state for Q6TI: {error}"))?;
        let candidate_timestamp = current_candidate_timestamp(graph.canonical_state())?;
        let response = mempool
            .submit_q6ti_with_quote_asset_authorization(
                runtime,
                replay_guard,
                frame,
                authenticator,
                producer,
                candidate_timestamp,
                quote_authorizer.as_deref_mut(),
            )
            .map_err(|error: QRunV06PermissionlessServiceError| error.to_string())?;
        return response
            .try_into()
            .map_err(|_| "Q6TA response did not have the fixed 128-byte wire length".to_string());
    }

    if frame.get(..4) == Some(&Q6MO_MAGIC) {
        let graph = runtime
            .fork_choice_snapshot()
            .map_err(|error| format!("cannot snapshot permissionless state for Q6MO: {error}"))?;
        let candidate_timestamp = current_candidate_timestamp(graph.canonical_state())?;
        let response = mempool
            .submit_q6mo_with_quote_asset_authorization(
                runtime,
                replay_guard,
                frame,
                authenticator,
                producer,
                candidate_timestamp,
                quote_authorizer.as_deref_mut(),
            )
            .map_err(|error| error.to_string())?;
        return response
            .try_into()
            .map_err(|_| "Q6MA response did not have the fixed 128-byte wire length".to_string());
    }

    let response = match quote_authorizer.as_deref_mut() {
        Some(provider) => {
            process_qfp6_peer_frame_with_permissionless_runtime_and_quote_asset_authorization(
                runtime,
                replay_guard,
                frame,
                authenticator,
                provider,
            )?
        }
        None => process_qfp6_peer_frame_with_permissionless_runtime(
            runtime,
            replay_guard,
            frame,
            authenticator,
        )?,
    };
    let graph = runtime.fork_choice_snapshot().map_err(|error| {
        format!("cannot refresh permissionless canonical state after Q6PB: {error}")
    })?;
    let candidate_timestamp = current_candidate_timestamp(graph.canonical_state())?;
    mempool
        .reconcile_after_canonical_change_with_quote_asset_authorization(
            runtime,
            authenticator,
            producer,
            candidate_timestamp,
            quote_authorizer.as_deref_mut(),
        )
        .map_err(|error| error.to_string())?;
    Ok(response)
}

/// Run the authenticated QFP6 Noise listener and permissionless durable miner in alternating,
/// bounded windows. The runtime must already be opened from complete Genesis-rooted history with
/// an independently verified profile pin. The same pinned Noise listener serves bounded
/// Q6HS/Q6HC canonical-history export requests. This base supervisor does not discover or
/// auto-connect peers; the separate startup wrapper syncs only from operator-approved pins.
#[allow(clippy::too_many_arguments)]
pub fn run_qfp6_permissionless_mining_supervisor<T: TransactionAuthenticator>(
    listener: &TcpListener,
    config: QRunV06PermissionlessMiningSupervisorConfig,
    local_static_private_key: &[u8; 32],
    trusted_remote_static_public_keys: &[[u8; 32]],
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
    shutdown_requested: &AtomicBool,
    runtime: &mut QRunV06PermissionlessNodeRuntime,
    authenticator: &T,
    producer: [u8; 32],
    mempool: &mut QRunV06PermissionlessMempool,
) -> Result<QRunV06PermissionlessMiningSupervisorReport, QRunV06NodeSupervisorError> {
    run_qfp6_permissionless_mining_supervisor_inner(
        listener,
        config,
        local_static_private_key,
        trusted_remote_static_public_keys,
        network_id,
        profile_id,
        shutdown_requested,
        runtime,
        authenticator,
        producer,
        mempool,
        None,
        None,
        None,
        None,
        None,
        false,
        None,
    )
}

/// Run the permissionless listener/miner with a fresh, height-bound Q6TS/Q6QA provider.
/// The provider is used for startup Q6MM restore, Q6TI/Q6MO/Q6PB ingress, mining preview,
/// durable block admission and post-canonical revalidation.
#[allow(clippy::too_many_arguments)]
pub fn run_qfp6_permissionless_mining_supervisor_with_quote_asset_authorization<
    T: TransactionAuthenticator,
>(
    listener: &TcpListener,
    config: QRunV06PermissionlessMiningSupervisorConfig,
    local_static_private_key: &[u8; 32],
    trusted_remote_static_public_keys: &[[u8; 32]],
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
    shutdown_requested: &AtomicBool,
    runtime: &mut QRunV06PermissionlessNodeRuntime,
    authenticator: &T,
    producer: [u8; 32],
    mempool: &mut QRunV06PermissionlessMempool,
    quote_authorizer: &mut QRunV06QuoteAssetAuthorizationProvider<'_>,
) -> Result<QRunV06PermissionlessMiningSupervisorReport, QRunV06NodeSupervisorError> {
    run_qfp6_permissionless_mining_supervisor_inner(
        listener,
        config,
        local_static_private_key,
        trusted_remote_static_public_keys,
        network_id,
        profile_id,
        shutdown_requested,
        runtime,
        authenticator,
        producer,
        mempool,
        None,
        None,
        Some(quote_authorizer),
        None,
        None,
        false,
        None,
    )
}

/// Persist a Q6AR advertisement through the exact operator policy used by the runtime callback.
/// The caller must first establish that the session's static key is pinned.
fn persist_pinned_q6ar_with_operator_policy(
    address_book: &mut crate::qrun_v06_peer_address_manager_candidate::QRunV06PeerAddressBookCandidate,
    trust_domains: &crate::qrun_v06_bootstrap_trust_domain_candidate::BootstrapTrustDomainPolicy,
    received: &crate::qrun_v06_peer_address_relay_candidate::Q6arReceivedAdvertisement,
    now_ms: u64,
) -> Result<(), String> {
    address_book
        .ingest_pinned_q6ar_with_trust_domains(received, now_ms, trust_domains)
        .map(|_| ())
        .map_err(|error| format!("Q6AR address-book rejection: {error}"))
}

/// Candidate-only variant: persist Q6AR only when relayed by a bootstrap-pinned Noise identity.
#[allow(clippy::too_many_arguments)]
pub fn run_qfp6_permissionless_mining_supervisor_with_q6ar_candidate<
    T: TransactionAuthenticator,
>(
    listener: &TcpListener,
    config: QRunV06PermissionlessMiningSupervisorConfig,
    local_static_private_key: &[u8; 32],
    trusted_remote_static_public_keys: &[[u8; 32]],
    q6ar_relay_static_public_key_pins: &[[u8; 32]],
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
    shutdown_requested: &AtomicBool,
    runtime: &mut QRunV06PermissionlessNodeRuntime,
    authenticator: &T,
    producer: [u8; 32],
    mempool: &mut QRunV06PermissionlessMempool,
    address_book: &mut crate::qrun_v06_peer_address_manager_candidate::QRunV06PeerAddressBookCandidate,
    trust_domains: &crate::qrun_v06_bootstrap_trust_domain_candidate::BootstrapTrustDomainPolicy,
) -> Result<QRunV06PermissionlessMiningSupervisorReport, QRunV06NodeSupervisorError> {
    run_qfp6_permissionless_mining_supervisor_inner(
        listener,
        config,
        local_static_private_key,
        trusted_remote_static_public_keys,
        network_id,
        profile_id,
        shutdown_requested,
        runtime,
        authenticator,
        producer,
        mempool,
        None,
        Some((
            address_book,
            q6ar_relay_static_public_key_pins.to_vec(),
            q6ar_relay_static_public_key_pins.to_vec(),
            trust_domains,
        )),
        None,
        None,
        None,
        false,
        None,
    )
}

/// Q6AR candidate listener combined with fresh per-block Q6TS/Q6QA authorization.
#[allow(clippy::too_many_arguments)]
pub fn run_qfp6_permissionless_mining_supervisor_with_q6ar_candidate_and_quote_asset_authorization<
    T: TransactionAuthenticator,
>(
    listener: &TcpListener,
    config: QRunV06PermissionlessMiningSupervisorConfig,
    local_static_private_key: &[u8; 32],
    q6ar_relay_static_public_key_pins: &[[u8; 32]],
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
    shutdown_requested: &AtomicBool,
    runtime: &mut QRunV06PermissionlessNodeRuntime,
    authenticator: &T,
    producer: [u8; 32],
    mempool: &mut QRunV06PermissionlessMempool,
    address_book: &mut crate::qrun_v06_peer_address_manager_candidate::QRunV06PeerAddressBookCandidate,
    trust_domains: &crate::qrun_v06_bootstrap_trust_domain_candidate::BootstrapTrustDomainPolicy,
    quote_authorizer: &mut QRunV06QuoteAssetAuthorizationProvider<'_>,
) -> Result<QRunV06PermissionlessMiningSupervisorReport, QRunV06NodeSupervisorError> {
    let mut total = QRunV06PermissionlessMiningSupervisorReport {
        listener_rounds: 0,
        mining_rounds: 0,
        blocks_durably_committed: 0,
        blocks_became_canonical: 0,
        ending_height: 0,
        pending_mempool_transactions: 0,
        pending_mempool_bytes: 0,
        mempool_journal_generation: 0,
        stats: QRunV06PeerListenerStats::default(),
        stop_reason: QRunV06NodeSupervisorStopReason::ShutdownRequested,
    };
    loop {
        if shutdown_requested.load(Ordering::Acquire) {
            total.stop_reason = QRunV06NodeSupervisorStopReason::ShutdownRequested;
            return Ok(total);
        }
        let report = run_qfp6_permissionless_mining_supervisor_inner(
            listener,
            config,
            local_static_private_key,
            &[],
            network_id,
            profile_id,
            shutdown_requested,
            runtime,
            authenticator,
            producer,
            mempool,
            None,
            Some((
                address_book,
                q6ar_relay_static_public_key_pins.to_vec(),
                q6ar_relay_static_public_key_pins.to_vec(),
                trust_domains,
            )),
            Some(quote_authorizer),
            None,
            None,
            false,
            None,
        )?;
        total.listener_rounds = total
            .listener_rounds
            .checked_add(report.listener_rounds)
            .ok_or(QRunV06NodeSupervisorError::StatisticsOverflow)?;
        total.mining_rounds = total
            .mining_rounds
            .checked_add(report.mining_rounds)
            .ok_or(QRunV06NodeSupervisorError::StatisticsOverflow)?;
        total.blocks_durably_committed = total
            .blocks_durably_committed
            .checked_add(report.blocks_durably_committed)
            .ok_or(QRunV06NodeSupervisorError::StatisticsOverflow)?;
        total.blocks_became_canonical = total
            .blocks_became_canonical
            .checked_add(report.blocks_became_canonical)
            .ok_or(QRunV06NodeSupervisorError::StatisticsOverflow)?;
        add_stats(&mut total.stats, report.stats)?;
        total.ending_height = report.ending_height;
        total.pending_mempool_transactions = report.pending_mempool_transactions;
        total.pending_mempool_bytes = report.pending_mempool_bytes;
        total.mempool_journal_generation = report.mempool_journal_generation;
        total.stop_reason = report.stop_reason;
        if report.stop_reason == QRunV06NodeSupervisorStopReason::ShutdownRequested {
            return Ok(total);
        }
        thread::sleep(Duration::from_millis(100));
    }
}

#[allow(clippy::too_many_arguments)]
/// Read-only QFP6 HTTP API. Account values are tied to the exact canonical state root and tip.
/// This is not an account inclusion proof; independent verification requires full-node replay.
pub(crate) fn qfp6_read_api_response(
    method: &str,
    path: &str,
    runtime: &QRunV06PermissionlessNodeRuntime,
) -> (u16, Vec<u8>) {
    let (status, body) = if method != "GET" {
        (
            405,
            serde_json::json!({"error":"method_not_allowed","allowed_methods":["GET"]}),
        )
    } else if path == "/v1/status" {
        match runtime.status() {
            Ok(s) => (
                200,
                serde_json::json!({
                    "api_version":1,
                    "network_id":s.network_id.iter().map(|b|format!("{b:02x}")).collect::<String>(),
                    "profile_id":s.profile_id.iter().map(|b|format!("{b:02x}")).collect::<String>(),
                    "height":s.height.to_string(),
                    "tip":s.tip.iter().map(|b|format!("{b:02x}")).collect::<String>(),
                    "state_root":s.state_root.iter().map(|b|format!("{b:02x}")).collect::<String>(),
                    "manifest_generation":s.manifest_generation.to_string(),
                    "consensus_fingerprint":s.consensus_fingerprint.iter().map(|b|format!("{b:02x}")).collect::<String>(),
                    "verification":"canonical_full_node_replay_required",
                    "account_inclusion_proofs":false
                }),
            ),
            Err(_) => (
                503,
                serde_json::json!({"error":"canonical_state_unavailable"}),
            ),
        }
    } else if path == "/v1/supply" {
        match runtime.canonical_supply_read() {
            Ok(s) => (
                200,
                serde_json::json!({
                    "api_version":1,
                    "network_id":s.network_id.iter().map(|b|format!("{b:02x}")).collect::<String>(),
                    "profile_id":s.profile_id.iter().map(|b|format!("{b:02x}")).collect::<String>(),
                    "native_asset_id":s.native_asset_id.iter().map(|b|format!("{b:02x}")).collect::<String>(),
                    "ledger_total_atoms":s.ledger_total_atoms.to_string(),
                    "owner_genesis_atoms":s.owner_genesis_atoms.to_string(),
                    "maximum_supply_atoms":s.maximum_supply_atoms.to_string(),
                    "block_subsidy_atoms":s.block_subsidy_atoms.to_string(),
                    "accounting_labels_total_atoms":s.accounting_labels_total_atoms.to_string(),
                    "accounting_labels_are_minted":false,
                    "issuance_policy":"fee_only_no_subsidy",
                    "policy_fingerprint":s.policy_fingerprint.iter().map(|b|format!("{b:02x}")).collect::<String>(),
                    "height":s.height.to_string(),
                    "tip":s.tip.iter().map(|b|format!("{b:02x}")).collect::<String>(),
                    "state_root":s.state_root.iter().map(|b|format!("{b:02x}")).collect::<String>(),
                    "proof_type":"global_state_root_only",
                    "verification":"canonical_full_node_replay_required"
                }),
            ),
            Err(_) => (
                503,
                serde_json::json!({"error":"canonical_supply_unavailable"}),
            ),
        }
    } else if let Some(encoded_height) = path.strip_prefix("/v1/block/") {
        let parsed_height = if encoded_height.is_empty()
            || !encoded_height.bytes().all(|byte| byte.is_ascii_digit())
            || (encoded_height.len() > 1 && encoded_height.starts_with('0'))
        {
            None
        } else {
            encoded_height.parse::<u64>().ok()
        };
        match parsed_height {
            None => (
                400,
                serde_json::json!({"error":"invalid_block_height","expected":"canonical unsigned decimal height"}),
            ),
            Some(height) => match runtime.canonical_block_read(height) {
                Ok(Some(block)) => {
                    let operations = block
                        .operations
                        .iter()
                        .map(|operation| {
                            let mut value = serde_json::json!({
                                "index": operation.index.to_string(),
                                "type": operation.kind
                            });
                            if let Some(tx) = operation.transaction {
                                value["transaction"] = serde_json::json!({
                                    "transaction_id":tx.transaction_id.iter().map(|b|format!("{b:02x}")).collect::<String>(),
                                    "sender":tx.sender.iter().map(|b|format!("{b:02x}")).collect::<String>(),
                                    "recipient":tx.recipient.iter().map(|b|format!("{b:02x}")).collect::<String>(),
                                    "nonce":tx.nonce.to_string(),
                                    "amount_atoms":tx.amount_atoms.to_string(),
                                    "fee_atoms":tx.fee_atoms.to_string(),
                                    "expires_at":tx.expires_at.to_string()
                                });
                            }
                            value
                        })
                        .collect::<Vec<_>>();
                    (
                        200,
                        serde_json::json!({
                            "api_version":1,
                            "network_id":block.network_id.iter().map(|b|format!("{b:02x}")).collect::<String>(),
                            "profile_id":block.profile_id.iter().map(|b|format!("{b:02x}")).collect::<String>(),
                            "height":block.height.to_string(),
                            "timestamp":block.timestamp.to_string(),
                            "parent_execution_hash":block.parent_hash.iter().map(|b|format!("{b:02x}")).collect::<String>(),
                            "execution_block_id":block.execution_block_id.iter().map(|b|format!("{b:02x}")).collect::<String>(),
                            "consensus_tip":block.consensus_tip.iter().map(|b|format!("{b:02x}")).collect::<String>(),
                            "producer":block.producer.iter().map(|b|format!("{b:02x}")).collect::<String>(),
                            "state_root":block.state_root.iter().map(|b|format!("{b:02x}")).collect::<String>(),
                            "operation_count":block.operation_count.to_string(),
                            "operations":operations,
                            "canonical":true,
                            "canonical_height":block.canonical_height.to_string(),
                            "canonical_tip":block.canonical_tip.iter().map(|b|format!("{b:02x}")).collect::<String>(),
                            "canonical_state_root":block.canonical_state_root.iter().map(|b|format!("{b:02x}")).collect::<String>(),
                            "proof_type":"global_state_root_only",
                            "verification":"replay_and_recompute_with_trusted_genesis_or_checkpoint"
                        }),
                    )
                }
                Ok(None) => (
                    404,
                    serde_json::json!({
                        "error":"block_not_available",
                        "height":height.to_string(),
                        "reason":"height is outside the retained canonical block-body range"
                    }),
                ),
                Err(_) => (
                    503,
                    serde_json::json!({"error":"canonical_block_unavailable"}),
                ),
            },
        }
    } else if let Some(encoded_id) = path.strip_prefix("/v1/transaction/") {
        if encoded_id.len() != 64 || !encoded_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            (
                400,
                serde_json::json!({"error":"invalid_transaction_id","expected":"64 hexadecimal characters"}),
            )
        } else {
            let mut id = [0u8; 32];
            let decoded = (0..32).try_for_each(|index| {
                u8::from_str_radix(&encoded_id[index * 2..index * 2 + 2], 16)
                    .map(|value| id[index] = value)
            });
            if decoded.is_err() {
                (400, serde_json::json!({"error":"invalid_transaction_id"}))
            } else {
                match runtime.canonical_transaction_read(&id) {
                    Ok(Some(receipt)) => {
                        let tx = receipt.transaction;
                        (
                            200,
                            serde_json::json!({
                                "api_version":1,
                                "transaction_id":tx.transaction_id.iter().map(|b|format!("{b:02x}")).collect::<String>(),
                                "sender":tx.sender.iter().map(|b|format!("{b:02x}")).collect::<String>(),
                                "recipient":tx.recipient.iter().map(|b|format!("{b:02x}")).collect::<String>(),
                                "nonce":tx.nonce.to_string(),
                                "amount_atoms":tx.amount_atoms.to_string(),
                                "fee_atoms":tx.fee_atoms.to_string(),
                                "expires_at":tx.expires_at.to_string(),
                                "status":receipt.inclusion_status,
                                "lookup_scope":"retained_fork_archive",
                                "mempool_checked":false,
                                "block_height":receipt.block_height.to_string(),
                                "block_timestamp":receipt.block_timestamp.to_string(),
                                "execution_block_id":receipt.execution_block_id.iter().map(|b|format!("{b:02x}")).collect::<String>(),
                                "consensus_tip":receipt.consensus_tip.iter().map(|b|format!("{b:02x}")).collect::<String>(),
                                "block_state_root":receipt.block_state_root.iter().map(|b|format!("{b:02x}")).collect::<String>(),
                                "producer":receipt.producer.iter().map(|b|format!("{b:02x}")).collect::<String>(),
                                "confirmations":receipt.confirmations.to_string(),
                                "finality":"confirmation_depth_only",
                                "canonical_height":receipt.canonical_height.to_string(),
                                "canonical_tip":receipt.canonical_tip.iter().map(|b|format!("{b:02x}")).collect::<String>(),
                                "canonical_state_root":receipt.canonical_state_root.iter().map(|b|format!("{b:02x}")).collect::<String>()
                            }),
                        )
                    }
                    Ok(None) => (
                        404,
                        serde_json::json!({
                            "error":"transaction_not_found_in_retained_fork_archive",
                            "transaction_id":encoded_id.to_ascii_lowercase(),
                            "mempool_checked":false,
                            "pending_status":"not_available_from_this_endpoint"
                        }),
                    ),
                    Err(_) => (
                        503,
                        serde_json::json!({"error":"canonical_transaction_lookup_unavailable"}),
                    ),
                }
            }
        }
    } else if let Some(encoded) = path.strip_prefix("/v1/account/") {
        if encoded.len() != 64 || !encoded.bytes().all(|b| b.is_ascii_hexdigit()) {
            (
                400,
                serde_json::json!({"error":"invalid_account_id","expected":"64 hexadecimal characters"}),
            )
        } else {
            let mut id = [0u8; 32];
            let decoded = (0..32).try_for_each(|i| {
                u8::from_str_radix(&encoded[i * 2..i * 2 + 2], 16).map(|v| id[i] = v)
            });
            if decoded.is_err() {
                (400, serde_json::json!({"error":"invalid_account_id"}))
            } else {
                match runtime.canonical_account_read(&id) {
                    Ok(a) => (
                        200,
                        serde_json::json!({
                            "api_version":1,
                            "network_id":a.network_id.iter().map(|b|format!("{b:02x}")).collect::<String>(),
                            "profile_id":a.profile_id.iter().map(|b|format!("{b:02x}")).collect::<String>(),
                            "native_asset_id":a.native_asset_id.iter().map(|b|format!("{b:02x}")).collect::<String>(),
                            "account_id":a.account_id.iter().map(|b|format!("{b:02x}")).collect::<String>(),
                            "balance_atoms":a.balance_atoms.map(|value| value.to_string()),"nonce":a.nonce.map(|value| value.to_string()),"height":a.height.to_string(),
                            "tip":a.tip.iter().map(|b|format!("{b:02x}")).collect::<String>(),
                            "state_root":a.state_root.iter().map(|b|format!("{b:02x}")).collect::<String>(),
                            "proof_type":"global_state_root_only","account_inclusion_proof":null,
                            "verification":"canonical_full_node_replay_required"
                        }),
                    ),
                    Err(_) => (
                        503,
                        serde_json::json!({"error":"canonical_state_unavailable"}),
                    ),
                }
            }
        }
    } else {
        (
            404,
            serde_json::json!({"error":"not_found","supported_paths":["/v1/status","/v1/account/{64-hex-account-id}","/v1/supply","/v1/block/{height}","/v1/transaction/{64-hex-transaction-id}"]}),
        )
    };
    let body = serde_json::to_vec(&body)
        .unwrap_or_else(|_| b"{\"error\":\"serialization_failure\"}".to_vec());
    (status, body)
}

/// Handle one bounded request per supervisor tick on the runtime-owning thread.
pub(crate) fn serve_qfp6_read_api_once(
    listener: &TcpListener,
    runtime: &QRunV06PermissionlessNodeRuntime,
) -> Result<(), String> {
    let (mut stream, _) = match listener.accept() {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
        Err(e) => return Err(format!("read-only RPC accept failed: {e}")),
    };
    if stream
        .set_read_timeout(Some(Duration::from_millis(250)))
        .is_err()
    {
        return Ok(());
    }
    if stream
        .set_write_timeout(Some(Duration::from_millis(250)))
        .is_err()
    {
        return Ok(());
    }
    let mut reader = BufReader::new(&mut stream);
    let mut request = String::new();
    let read = match (&mut reader).take(513).read_line(&mut request) {
        Ok(value) => value,
        Err(_) => return Ok(()),
    };
    drop(reader);
    let (status, body) = if read == 0 || read > 512 || !request.ends_with("\r\n") {
        (400, b"{\"error\":\"invalid_request_line\"}".to_vec())
    } else {
        let mut fields = request.split_whitespace();
        let method = fields.next().unwrap_or("");
        let path = fields.next().unwrap_or("");
        let version = fields.next().unwrap_or("");
        if fields.next().is_some() || !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
            (400, b"{\"error\":\"invalid_http_request\"}".to_vec())
        } else {
            qfp6_read_api_response(method, path, runtime)
        }
    };
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        503 => "Service Unavailable",
        _ => "Error",
    };
    if write!(stream,"HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\r\n",body.len()).is_err() { return Ok(()); }
    if stream.write_all(&body).is_err() {
        return Ok(());
    }
    Ok(())
}
fn run_qfp6_permissionless_mining_supervisor_inner<T: TransactionAuthenticator>(
    listener: &TcpListener,
    config: QRunV06PermissionlessMiningSupervisorConfig,
    local_static_private_key: &[u8; 32],
    trusted_remote_static_public_keys: &[[u8; 32]],
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
    shutdown_requested: &AtomicBool,
    runtime: &mut QRunV06PermissionlessNodeRuntime,
    authenticator: &T,
    producer: [u8; 32],
    mempool: &mut QRunV06PermissionlessMempool,
    // Exact operator-pinned bootstrap peers used for periodic outbound tip/history refresh.
    outbound_sync_peers: Option<&[QRunV06PinnedBootstrapPeer]>,
    mut q6ar_candidate: Option<(
        &mut crate::qrun_v06_peer_address_manager_candidate::QRunV06PeerAddressBookCandidate,
        Vec<[u8; 32]>,
        Vec<[u8; 32]>,
        &crate::qrun_v06_bootstrap_trust_domain_candidate::BootstrapTrustDomainPolicy,
    )>,
    mut quote_authorizer: Option<&mut QRunV06QuoteAssetAuthorizationProvider<'_>>,
    read_api_listener: Option<&TcpListener>,
    mut q6pd_candidate: Option<&mut Q6pdPeerRecordStore>,
    q6pd_pull_enabled: bool,
    q6pd_self_announcement: Option<(&Q6pdNodeIdentity, SocketAddr, Option<String>)>,
) -> Result<QRunV06PermissionlessMiningSupervisorReport, QRunV06NodeSupervisorError> {
    config.validate()?;
    // This flag outlives the scoped supervisor threads and lets them close cleanly.
    let q6pd_workers_stop = AtomicBool::new(false);
    if q6pd_self_announcement.is_some() && q6pd_candidate.is_none() {
        return Err(QRunV06NodeSupervisorError::InvalidConfiguration);
    }
    validate_identity_material(local_static_private_key, network_id, profile_id)?;
    if producer == [0; 32] {
        return Err(QRunV06NodeSupervisorError::InvalidIdentity);
    }
    let startup = runtime
        .status()
        .map_err(|error| QRunV06NodeSupervisorError::Runtime(error.to_string()))?;
    if startup.network_id != *network_id {
        return Err(QRunV06NodeSupervisorError::NetworkMismatch);
    }
    if startup.profile_id != *profile_id {
        return Err(QRunV06NodeSupervisorError::ProfileMismatch);
    }
    let startup_graph = runtime
        .fork_choice_snapshot()
        .map_err(|error| QRunV06NodeSupervisorError::Runtime(error.to_string()))?;
    let startup_timestamp = current_candidate_timestamp(startup_graph.canonical_state())
        .map_err(QRunV06NodeSupervisorError::Journal)?;
    mempool
        .restore_with_quote_asset_authorization(
            runtime,
            authenticator,
            producer,
            startup_timestamp,
            quote_authorizer.as_deref_mut(),
        )
        .map_err(|error| QRunV06NodeSupervisorError::Journal(error.to_string()))?;

    let signal = if config.peer.install_os_signal_handler {
        Some(
            QRunNodeShutdownSignalCandidate::install()
                .map_err(|error| QRunV06NodeSupervisorError::ShutdownSignal(error.to_string()))?,
        )
    } else {
        None
    };
    let signal_ref = signal.as_ref();
    let watcher_stop = AtomicBool::new(false);
    let run_result = thread::scope(|scope| {
        let watcher = scope.spawn(|| {
            while !watcher_stop.load(Ordering::Acquire) {
                if signal_ref.is_some_and(|signal| signal.is_shutdown_requested()) {
                    shutdown_requested.store(true, Ordering::Release);
                    break;
                }
                thread::sleep(SHUTDOWN_WATCH_INTERVAL);
            }
        });

        let service_result = (|| {
            let mut aggregate = QRunV06PeerListenerStats::default();
            let mut source_rate_limiter = QRunV06PeerSourceRateLimiter::new(Instant::now());
            let mut listener_rounds = 0u64;
            let mut mining_rounds = 0u64;
            let mut blocks_durably_committed = 0u64;
            let mut blocks_became_canonical = 0u64;
            let mut history_responder = QRunV06HistorySyncResponder::default();
            let mut q6pd_address_manager = match q6pd_candidate.as_deref() {
                Some(store) => Some(
                    crate::qrun_v06_q6pd_address_manager_candidate::Q6pdAddressManager::open(
                        store.address_manager_path(),
                        *network_id,
                        *profile_id,
                    )
                    .map_err(|error| {
                        QRunV06NodeSupervisorError::BootstrapSync(format!(
                            "Q6PD Address Manager open failed: {error}"
                        ))
                    })?,
                ),
                None => None,
            };
            let mut last_outbound_sync = Instant::now();
            let mut next_outbound_peer_index = 0usize;
            let mut last_q6ar_candidate_pull = Instant::now();
            let mut next_q6ar_relay_index = 0usize;
            let mut last_q6pd_candidate_pull = Instant::now();
            let mut last_q6pd_self_announcement = Instant::now();
            let mut next_q6pd_peer_index = 0usize;
            // Q6PD records are self-signed address claims; verify the record first, then pin
            // its Noise key in the direct handshake. One candidate is contacted per 30s cycle.
            let mut last_q6pd_candidate_dial = Instant::now();
            // Persistent Q6PD sessions require our own current public signed record.
            // A node with no publicly reachable self-announcement (e.g. a local-only
            // Joiner) does not reserve a long-lived remote slot.
            let local_q6pd_noise_key = q6pd_self_announcement
                .as_ref()
                .map(|(identity, _, _)| identity.info().noise_static_public_key);
            let initial_local_q6pd_record =
                q6pd_self_announcement
                    .as_ref()
                    .and_then(|(identity, _, _)| {
                        let now_ms = system_now_ms().ok()?;
                        q6pd_candidate.as_deref().and_then(|store| {
                            store.record_wire_for_peer(&identity.info().peer_id, now_ms)
                        })
                    });
            let local_q6pd_announcement =
                std::sync::Arc::new(std::sync::RwLock::new(initial_local_q6pd_record));
            let mut q6pd_persistent_peer_keys = HashSet::new();
            // Persistent sessions are outbound and can be held by NAT-only Joiners.
            // A local signed public endpoint is optional; the remote seed remains key-pinned.
            if q6pd_pull_enabled && q6pd_candidate.is_some() {
                for peer in outbound_sync_peers
                    .unwrap_or(&[])
                    .iter()
                    .take(crate::qrun_v06_q6pd_session_candidate::Q6PD_MAX_PERSISTENT_SESSIONS)
                {
                    if !q6pd_persistent_peer_keys.insert(peer.noise_static_public_key) {
                        continue;
                    }
                    let address = peer.address;
                    let tls_server_name = peer.tls_server_name.clone();
                    let local_key = *local_static_private_key;
                    let local_noise_key = local_q6pd_noise_key;
                    let remote_key = peer.noise_static_public_key;
                    let network = *network_id;
                    let profile = *profile_id;
                    let announcement = std::sync::Arc::clone(&local_q6pd_announcement);
                    let shutdown = &q6pd_workers_stop;
                    eprintln!(
                        "QFP6_Q6PD_SESSION_MANAGER_START endpoint={} source=operator_pinned_bootstrap",
                        address
                    );
                    scope.spawn(move || {
                        crate::qrun_v06_q6pd_session_candidate::run_q6pd_persistent_peer_session_worker(
                            address,
                            tls_server_name,
                            local_key,
                            local_noise_key,
                            remote_key,
                            network,
                            profile,
                            announcement,
                            shutdown,
                        );
                    });
                }
            } else if q6pd_pull_enabled {
                eprintln!("QFP6_Q6PD_SESSION_MANAGER_SKIPPED reason=no_q6pd_record_store");
            }
            // The address book owns durable approval; live verified-session state is ephemeral.
            // Anonymous Q6AR candidates are never promoted or dialed by this manager.
            let mut peer_connection_manager = q6ar_candidate
                .as_ref()
                .map(|(book, _, _, _)| QRunV06PeerConnectionManagerCandidate::new(&**book));
            let stop_reason;

            loop {
                if let Some(api) = read_api_listener {
                    serve_qfp6_read_api_once(api, runtime)
                        .map_err(QRunV06NodeSupervisorError::Listener)?;
                }
                if shutdown_requested.load(Ordering::Acquire) {
                    stop_reason = QRunV06NodeSupervisorStopReason::ShutdownRequested;
                    break;
                }
                if established_session_count(&aggregate)? >= config.peer.max_total_sessions {
                    stop_reason = QRunV06NodeSupervisorStopReason::SessionBudgetReached;
                    break;
                }
                let remaining = config
                    .peer
                    .max_total_sessions
                    .checked_sub(established_session_count(&aggregate)?)
                    .ok_or(QRunV06NodeSupervisorError::StatisticsOverflow)?;
                let mut round_config = config.peer.listener;
                // Serve a bounded session batch, then yield to the miner. The default remains
                // one session; public zero-value testnet opts into a small batch so history sync
                // can cross reconnect boundaries without waiting through a mining slice each time.
                round_config.max_sessions = round_config
                    .max_sessions
                    .min(remaining)
                    .min(config.max_sessions_per_listener_round);
                let q6ar_advertisement = q6ar_candidate.as_ref().and_then(|(book, _, _, _)| {
                    system_now_ms().ok().and_then(|now_ms| {
                        book.current_gossip_advertisement(now_ms, Q6AR_MAX_ADDRESSES)
                    })
                });
                let mut on_application_frame =
                    |peer_addr: std::net::SocketAddr,
                     guard: &mut QRunV06PeerReplayGuard,
                     frame: &[u8]| {
                        if frame.get(..4)
                            == Some(
                                &crate::qrun_v06_q6pd_session_candidate::Q6PD_SESSION_OPEN_MAGIC,
                            )
                        {
                            let open =
                                crate::qrun_v06_q6pd_session_candidate::decode_q6pd_session_open(
                                    frame, network_id, profile_id,
                                )
                                .map_err(|error| {
                                    format!("Q6PD persistent session open rejected: {error}")
                                })?;
                            let accepted = q6pd_candidate.is_some();
                            Ok(vec![
                                crate::qrun_v06_q6pd_session_candidate::encode_q6pd_session_open_ack(
                                    &open,
                                    accepted,
                                ),
                            ])
                        } else if frame.get(..4) == Some(&Q6PD_ANNOUNCE_REQUEST_MAGIC) {
                            let now_ms = system_now_ms().map_err(|error| error.to_string())?;
                            let record_wire = crate::qrun_v06_peer_discovery_candidate::decode_q6pd_announce_request(frame)
                                .map_err(|error| format!("Q6PD announcement frame rejected: {error}"))?;
                            let store = q6pd_candidate
                                .as_deref_mut()
                                .ok_or("Q6PD peer-record exchange is disabled")?;
                            let verified = crate::qrun_v06_peer_discovery_candidate::verify_q6pd_peer_record(
                                record_wire,
                                network_id,
                                profile_id,
                                now_ms / 1_000,
                            )
                            .map_err(|error| format!("Q6PD peer announcement verification failed: {error}"))?;
                            let result = store.ingest(record_wire, now_ms).map_err(|error| {
                                format!("Q6PD peer announcement persistence failed: {error}")
                            })?;
                            if let Some(manager) = q6pd_address_manager.as_mut() {
                                manager.observe_from(&verified, peer_addr, now_ms).map_err(|error| {
                                    format!("Q6PD Address Manager update failed: {error}")
                                })?;
                            }
                            eprintln!(
                                "QFP6_Q6PD_PEER_ANNOUNCEMENT_ACCEPTED ingest_result={:?}",
                                result
                            );
                            let response = crate::qrun_v06_peer_discovery_candidate::encode_q6pd_announce_response(true);
                            Ok(vec![response.to_vec()])
                        } else if frame.get(..4)
                            == Some(&crate::qrun_v06_peer_discovery_candidate::Q6PD_GOSSIP_PUSH_REQUEST_MAGIC)
                        {
                            let now_ms = system_now_ms().map_err(|error| error.to_string())?;
                            let request = crate::qrun_v06_peer_discovery_candidate::decode_q6pd_gossip_push_request(
                                frame,
                                network_id,
                                profile_id,
                                now_ms / 1_000,
                            )
                            .map_err(|error| format!("Q6PD Gossip push rejected: {error}"))?;
                            let store = q6pd_candidate
                                .as_deref_mut()
                                .ok_or("Q6PD peer-record exchange is disabled")?;
                            let mut counts = crate::qrun_v06_peer_discovery_candidate::Q6pdGossipPushCounts {
                                inserted: 0,
                                updated: 0,
                                duplicate: 0,
                                rejected: 0,
                            };
                            for (record, wire) in request.records.iter().zip(&request.record_wires) {
                                match store.ingest(wire, now_ms) {
                                    Ok(crate::qrun_v06_peer_discovery_store_candidate::Q6pdIngestResult::Inserted) => {
                                        counts.inserted = counts.inserted.saturating_add(1);
                                        if let Some(manager) = q6pd_address_manager.as_mut() {
                                            manager.observe_from(record, peer_addr, now_ms).map_err(|error| {
                                                format!("Q6PD Address Manager update failed: {error}")
                                            })?;
                                        }
                                    }
                                    Ok(crate::qrun_v06_peer_discovery_store_candidate::Q6pdIngestResult::Updated) => {
                                        counts.updated = counts.updated.saturating_add(1);
                                        if let Some(manager) = q6pd_address_manager.as_mut() {
                                            manager.observe_from(record, peer_addr, now_ms).map_err(|error| {
                                                format!("Q6PD Address Manager update failed: {error}")
                                            })?;
                                        }
                                    }
                                    Ok(crate::qrun_v06_peer_discovery_store_candidate::Q6pdIngestResult::Duplicate) => {
                                        counts.duplicate = counts.duplicate.saturating_add(1);
                                        if let Some(manager) = q6pd_address_manager.as_mut() {
                                            manager.observe_from(record, peer_addr, now_ms).map_err(|error| {
                                                format!("Q6PD Address Manager update failed: {error}")
                                            })?;
                                        }
                                    }
                                    Err(crate::qrun_v06_peer_discovery_store_candidate::Q6pdStoreError::Replay)
                                    | Err(crate::qrun_v06_peer_discovery_store_candidate::Q6pdStoreError::Capacity)
                                    | Err(crate::qrun_v06_peer_discovery_store_candidate::Q6pdStoreError::InvalidRecord(
                                        crate::qrun_v06_peer_discovery_candidate::Q6pdError::Expired,
                                    )) => {
                                        counts.rejected = counts.rejected.saturating_add(1);
                                    }
                                    Err(error) => {
                                        return Err(format!("Q6PD Gossip store failed: {error}"));
                                    }
                                }
                            }
                            eprintln!(
                                "QFP6_Q6PD_GOSSIP_PUSH_STORED source_records={} inserted={} updated={} duplicate={} rejected={}",
                                request.records.len(), counts.inserted, counts.updated, counts.duplicate, counts.rejected
                            );
                            let response = crate::qrun_v06_peer_discovery_candidate::encode_q6pd_gossip_push_response(
                                &request,
                                counts,
                            );
                            Ok(vec![response.to_vec()])
                        } else if frame.get(..4) == Some(&Q6PD_PULL_REQUEST_MAGIC) {
                            let now_secs =
                                system_now_ms().map_err(|error| error.to_string())? / 1_000;
                            let store = q6pd_candidate
                                .as_deref()
                                .ok_or("Q6PD peer-record exchange is disabled")?;
                            let response = store
                                .respond_to_pull_frame(frame, now_secs)
                                .map_err(|error| format!("Q6PD pull request rejected: {error}"))?;
                            Ok(vec![response])
                        } else if frame.get(..4) == Some(&Q6AR_PULL_REQUEST_MAGIC) {
                            let request = decode_q6ar_pull_request(frame, network_id, profile_id)
                                .map_err(|error| {
                                format!("Q6AR pull request rejected: {error}")
                            })?;
                            let response =
                                encode_q6ar_pull_response(&request, q6ar_advertisement.as_ref())
                                    .map_err(|error| {
                                        format!("Q6AR pull response failed: {error}")
                                    })?;
                            Ok(vec![response])
                        } else if frame.get(..4) == Some(&Q6HI_REQUEST_MAGIC) {
                            let request =
                                decode_q6hi_request(frame).map_err(|error| error.to_string())?;
                            let snapshot = history_responder
                                .pin_current_snapshot(runtime)
                                .map_err(|error| error.to_string())?;
                            let response = encode_q6hr_status(
                                &request,
                                snapshot.height,
                                snapshot.consensus_tip,
                                snapshot.execution_tip,
                                snapshot.base_height,
                                snapshot.base_consensus_tip,
                                snapshot.base_execution_tip,
                            )
                            .map_err(|error| error.to_string())?;
                            Ok(vec![response.to_vec()])
                        } else if frame.get(..4) == Some(&Q6HS_REQUEST_MAGIC) {
                            let request =
                                decode_q6hs_request(frame).map_err(|error| error.to_string())?;
                            history_responder
                                .respond(runtime, &request)
                                .map_err(|error| error.to_string())
                        } else {
                            process_qfp6_application_frame_with_permissionless_runtime_and_quote_asset_authorization(
                                runtime,
                                guard,
                                mempool,
                                frame,
                                authenticator,
                                producer,
                                quote_authorizer.as_deref_mut(),
                            )
                            .map(|response| vec![response.to_vec()])
                        }
                    };
                let q6ar_relay_pins = q6ar_candidate
                    .as_ref()
                    .map(|(_, relay_pins, _, _)| relay_pins.clone())
                    .unwrap_or_default();
                let mut on_q6ar = |received: crate::qrun_v06_peer_address_relay_candidate::Q6arReceivedAdvertisement| {
                    match q6ar_candidate.as_mut() {
                        Some((book, relay_pins, _, trust_domains))
                            if received.relay_origin.relay_static_key_pinned
                                && relay_pins.contains(&received.relay_origin.relay_static_public_key) =>
                        {
                            let now_ms = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .map_err(|error| format!("system clock invalid for Q6AR: {error}"))?
                                .as_millis()
                                .try_into()
                                .map_err(|_| "system clock exceeds Q6AR millisecond range".to_string())?;
                            persist_pinned_q6ar_with_operator_policy(
                                book,
                                trust_domains,
                                &received,
                                now_ms,
                            )
                        }
                        _ => Ok(()), // Anonymous or non-pinned relay: ignore without trust escalation.
                    }
                };
                let (listener_report, process_stopped) = serve_qfp6_history_listener_round(
                    listener,
                    round_config,
                    local_static_private_key,
                    trusted_remote_static_public_keys,
                    network_id,
                    profile_id,
                    shutdown_requested,
                    config.listener_round_timeout,
                    &mut source_rate_limiter,
                    &q6ar_relay_pins,
                    &mut on_q6ar,
                    &mut on_application_frame,
                )?;
                // End callback borrows before the outbound client mutates runtime/mempool.
                drop(on_q6ar);
                drop(on_application_frame);
                listener_rounds = listener_rounds
                    .checked_add(1)
                    .ok_or(QRunV06NodeSupervisorError::StatisticsOverflow)?;
                add_stats(&mut aggregate, listener_report.stats)?;
                if listener_report.stop_reason
                    == QRunV06PeerListenerStopReason::FailedHandshakeLimitReached
                    && !trusted_remote_static_public_keys.is_empty()
                {
                    return Err(QRunV06NodeSupervisorError::HandshakeBudgetExceeded);
                }
                // A malformed or failed remote application session is peer-local.
                // Disconnect that session, record the failure and keep the public node serving.
                // Only a locally malformed response remains fatal because it indicates that
                // this node is about to emit an invalid protocol response.
                if listener_report.stats.handler_failures > 0 {
                    eprintln!(
                        "QFP6_DIAG listener_peer_sessions_rejected={} action=disconnect_session_continue_node",
                        listener_report.stats.handler_failures
                    );
                }
                if listener_report.stats.malformed_responses > 0 {
                    return Err(QRunV06NodeSupervisorError::Listener(
                        "local listener response failed protocol validation; supervisor stops before mining"
                            .into(),
                    ));
                }
                if process_stopped || shutdown_requested.load(Ordering::Acquire) {
                    stop_reason = QRunV06NodeSupervisorStopReason::ShutdownRequested;
                    break;
                }

                // Refresh address candidates periodically from one exact operator-pinned relay.
                // The received Noise keys remain unapproved candidates and are never dialed here.
                let discovery_now = Instant::now();
                let has_q6ar_relay = q6ar_candidate
                    .as_ref()
                    .is_some_and(|(_, relay_pins, _, _)| !relay_pins.is_empty());
                if has_q6ar_relay
                    && q6ar_discovery_pull_due(last_q6ar_candidate_pull, discovery_now)
                {
                    last_q6ar_candidate_pull = discovery_now;
                    if let Some((book, relay_pins, _, trust_domains)) = q6ar_candidate.as_mut() {
                        let now_ms = system_now_ms()?;
                        let configured = outbound_sync_peers.unwrap_or(&[]);
                        let relays = address_book_approved_dial_targets(
                            &**book, configured, relay_pins, now_ms,
                        );
                        if !relays.is_empty() {
                            let relay_index = next_q6ar_relay_index % relays.len();
                            next_q6ar_relay_index = (relay_index + 1) % relays.len();
                            let relay = &relays[relay_index];
                            let discovery_config = QRunV06HistorySyncClientConfig {
                                connect_timeout: Duration::from_secs(5),
                                io_timeout: Duration::from_secs(10),
                                max_blocks_per_page: 1,
                                max_bytes_per_page: 64 * 1024,
                                max_pages: 1,
                                max_rounds: 1,
                            };
                            match crate::qrun_v06_history_sync_service_candidate::pull_q6ar_candidates_from_pinned_peer(
                                relay.address,
                                local_static_private_key,
                                &relay.noise_static_public_key,
                                network_id,
                                profile_id,
                                discovery_config,
                                relay.tls_server_name.as_deref(),
                                &mut **book,
                                &**trust_domains,
                            ) {
                                Ok(count) => eprintln!(
                                    "QFP6_DISCOVERY_REFRESH relay={} candidates_persisted={} next_pull_seconds={}",
                                    relay.address,
                                    count,
                                    QRUN_V06_Q6AR_DISCOVERY_PULL_INTERVAL.as_secs()
                                ),
                                Err(error) => eprintln!(
                                    "QFP6_DISCOVERY_REFRESH_RETRY relay={} error={error}; next_pull_seconds={}",
                                    relay.address,
                                    QRUN_V06_Q6AR_DISCOVERY_PULL_INTERVAL.as_secs()
                                ),
                            }
                        } else {
                            eprintln!(
                                "QFP6_DISCOVERY_REFRESH_SKIPPED reason=no_eligible_pinned_relay"
                            );
                        }
                    }
                }

                // Periodically exchange signed Q6PD records with one exact operator-pinned
                // bootstrap peer. Received records are signature-verified and persisted as
                // candidate hints only; this path never expands the trusted or dialable set.
                if let Some((identity, endpoint, tls_server_name)) = q6pd_self_announcement.as_ref()
                {
                    if q6pd_candidate.is_some()
                        && q6pd_discovery_pull_due(last_q6pd_self_announcement, discovery_now)
                    {
                        last_q6pd_self_announcement = discovery_now;
                        let now_ms = system_now_ms()?;
                        let store = q6pd_candidate
                            .as_deref_mut()
                            .ok_or(QRunV06NodeSupervisorError::InvalidConfiguration)?;
                        let sequence = store
                            .sequence_for_peer(&identity.info().peer_id)
                            .unwrap_or(0)
                            .checked_add(1)
                            .ok_or_else(|| {
                                QRunV06NodeSupervisorError::BootstrapSync(
                                    "Q6PD self-announcement sequence exhausted".into(),
                                )
                            })?;
                        let wire = identity
                            .sign_announcement_with_tls_server_name(
                                *endpoint,
                                tls_server_name.as_deref(),
                                sequence,
                                now_ms / 1_000,
                                Q6PD_MAX_TTL_SECS,
                            )
                            .map_err(|error| {
                                QRunV06NodeSupervisorError::BootstrapSync(format!(
                                    "Q6PD self-announcement signing failed: {error}"
                                ))
                            })?;
                        match store.ingest(&wire, now_ms) {
                            Ok(result) => {
                                if let Ok(mut shared_record) = local_q6pd_announcement.write() {
                                    *shared_record = Some(wire.clone());
                                }
                                eprintln!(
                                    "QFP6_Q6PD_SELF_ANNOUNCEMENT_REFRESH endpoint={} sequence={} ttl_seconds={} store_result={:?} persistent_sessions_record_refreshed=true",
                                    endpoint, sequence, Q6PD_MAX_TTL_SECS, result
                                );
                            }
                            Err(error) => eprintln!(
                                "QFP6_Q6PD_SELF_ANNOUNCEMENT_REFRESH_REJECTED endpoint={} sequence={} error={error}",
                                endpoint, sequence
                            ),
                        }
                    }
                }

                if q6pd_pull_enabled
                    && q6pd_candidate.is_some()
                    && q6pd_discovery_pull_due(last_q6pd_candidate_pull, discovery_now)
                {
                    last_q6pd_candidate_pull = discovery_now;
                    let configured_peers = outbound_sync_peers.unwrap_or(&[]);
                    if configured_peers.is_empty() {
                        eprintln!(
                            "QFP6_Q6PD_PULL_SKIPPED reason=no_operator_pinned_bootstrap_peer"
                        );
                    } else {
                        let peer_index = next_q6pd_peer_index % configured_peers.len();
                        next_q6pd_peer_index = (peer_index + 1) % configured_peers.len();
                        let peer = configured_peers[peer_index].clone();
                        let discovery_config = QRunV06HistorySyncClientConfig {
                            // A DNS seed may return several A/AAAA routes. Bound each
                            // route attempt tightly so one dead edge cannot stall discovery.
                            connect_timeout: Duration::from_secs(3),
                            io_timeout: Duration::from_secs(5),
                            max_blocks_per_page: 1,
                            max_bytes_per_page: 64 * 1024,
                            max_pages: 1,
                            max_rounds: 1,
                        };
                        if let Some(store) = q6pd_candidate.as_deref_mut() {
                            let announcement_now_ms = system_now_ms()?;
                            let local_announcement =
                                q6pd_self_announcement
                                    .as_ref()
                                    .and_then(|(identity, _, _)| {
                                        store.record_wire_for_peer(
                                            &identity.info().peer_id,
                                            announcement_now_ms,
                                        )
                                    });
                            let pull_result = if let Some(hostname) =
                                peer.tls_server_name.as_deref()
                            {
                                crate::qrun_v06_history_sync_service_candidate::pull_q6pd_peer_records_from_dns_seed_with_announcement(
                                    hostname,
                                    peer.address.port(),
                                    local_static_private_key,
                                    &peer.noise_static_public_key,
                                    network_id,
                                    profile_id,
                                    discovery_config,
                                    crate::qrun_v06_peer_discovery_candidate::Q6PD_MAX_RECORDS_PER_FRAME as u16,
                                    local_announcement.as_deref(),
                                    store,
                                )
                            } else {
                                crate::qrun_v06_history_sync_service_candidate::pull_q6pd_peer_records_from_pinned_peer_with_announcement(
                                    peer.address,
                                    local_static_private_key,
                                    &peer.noise_static_public_key,
                                    network_id,
                                    profile_id,
                                    discovery_config,
                                    None,
                                    crate::qrun_v06_peer_discovery_candidate::Q6PD_MAX_RECORDS_PER_FRAME as u16,
                                    local_announcement.as_deref(),
                                    store,
                                )
                            };
                            match pull_result {
                                Ok(report) => eprintln!(
                                    "QFP6_Q6PD_DISCOVERY_REFRESH peer={} received={} inserted={} updated={} duplicate={} rejected={} next_pull_seconds={}",
                                    peer.address,
                                    report.records_received,
                                    report.records_inserted,
                                    report.records_updated,
                                    report.records_duplicate,
                                    report.records_rejected,
                                    QRUN_V06_Q6PD_DISCOVERY_PULL_INTERVAL.as_secs()
                                ),
                                Err(error) => eprintln!(
                                    "QFP6_Q6PD_DISCOVERY_REFRESH_RETRY peer={} error={error}; next_pull_seconds={}",
                                    peer.address,
                                    QRUN_V06_Q6PD_DISCOVERY_PULL_INTERVAL.as_secs()
                                ),
                            }
                        }
                    }
                }

                // Merge configured bootstrap peers only with the operator-selected approved set.
                // approved_peer_keys comes from the launcher trust-domain / attempt-budget selection;
                // this preserves enable_approved_peer_outbound_sync and its configured cap.
                // Anonymous/unapproved advertisements never enter this vector.
                let configured_peers = outbound_sync_peers.unwrap_or(&[]);
                let mut dial_peers = configured_peers.to_vec();
                if let Some((book, _, approved_peer_keys, _)) = q6ar_candidate.as_ref() {
                    let now_ms = system_now_ms()?;
                    for approved in address_book_approved_dial_targets(
                        &**book,
                        configured_peers,
                        approved_peer_keys,
                        now_ms,
                    ) {
                        if !dial_peers.iter().any(|peer| {
                            peer.address == approved.address
                                && peer.noise_static_public_key == approved.noise_static_public_key
                        }) {
                            dial_peers.push(approved);
                        }
                    }
                }

                if !dial_peers.is_empty() {
                    let sync_now = Instant::now();
                    if outbound_bootstrap_resync_due(last_outbound_sync, sync_now) {
                        last_outbound_sync = sync_now;
                        let attempts = dial_peers
                            .len()
                            .min(QRUN_V06_OUTBOUND_BOOTSTRAP_RESYNC_PEERS_PER_CYCLE);
                        for _ in 0..attempts {
                            if shutdown_requested.load(Ordering::Acquire) {
                                break;
                            }
                            let peer_index = next_outbound_peer_index % dial_peers.len();
                            next_outbound_peer_index = (peer_index + 1) % dial_peers.len();
                            let peer = dial_peers[peer_index].clone();
                            let refresh_config = QRunV06HistorySyncClientConfig {
                                connect_timeout: Duration::from_secs(5),
                                io_timeout: Duration::from_secs(15),
                                max_blocks_per_page: 16,
                                max_bytes_per_page: 4 * 1024 * 1024,
                                max_pages: 2,
                                // Keep each Noise session small, but resume the exact pinned
                                // source snapshot across bounded reconnect windows. The verified
                                // session manager is transitioned for every reconnect below.
                                max_rounds: 64,
                            };
                            let sync_result = if let (Some(manager), Some((book, _, _, _))) =
                                (peer_connection_manager.as_mut(), q6ar_candidate.as_mut())
                            {
                                let book: &mut crate::qrun_v06_peer_address_manager_candidate::QRunV06PeerAddressBookCandidate =
                                        &mut **book;
                                let reservation_ms = system_now_ms()?;
                                match manager.reserve_operator_approved_endpoint(
                                        book,
                                        peer.address,
                                        reservation_ms,
                                    ) {
                                        Ok(_) => {}
                                        Err(crate::qrun_v06_peer_connection_manager_candidate::QRunV06PeerConnectionManagerError::PeerNotEligible) => {
                                            eprintln!(
                                                "QFP6_PEER_DIAL_SKIPPED peer={} reason=address_book_backoff",
                                                peer.address
                                            );
                                            continue;
                                        }
                                        Err(error) => {
                                            return Err(QRunV06NodeSupervisorError::BootstrapSync(
                                                format!("approved peer reservation failed for {}: {error}", peer.address),
                                            ));
                                        }
                                    }

                                let mut verification_callback_invoked = false;
                                let mut verified_session_count = 0u32;
                                let result = crate::qrun_v06_history_sync_service_candidate::sync_history_from_pinned_peer_with_verified_session_callback(
                                        peer.address,
                                        local_static_private_key,
                                        &peer.noise_static_public_key,
                                        runtime,
                                        authenticator,
                                        refresh_config,
                                        quote_authorizer.as_deref_mut(),
                                        peer.tls_server_name.as_deref(),
                                        |noise_session| {
                                            verification_callback_invoked = true;
                                            let verified_at_ms =
                                                system_now_ms().map_err(|error| error.to_string())?;
                                            // The history client deliberately reconnects between
                                            // bounded page windows while retaining the same
                                            // authenticated source snapshot and branch cursor.
                                            // Mirror each real stream lifetime in the peer manager:
                                            // close the previous verified session, reserve the same
                                            // operator-pinned endpoint again, then verify this exact
                                            // new Noise session before any page is accepted.
                                            if verified_session_count > 0 {
                                                manager
                                                    .mark_disconnected(
                                                        book,
                                                        peer.address,
                                                        verified_at_ms,
                                                        false,
                                                    )
                                                    .map_err(|error| error.to_string())?;
                                                manager
                                                    .reserve_operator_approved_endpoint(
                                                        book,
                                                        peer.address,
                                                        verified_at_ms,
                                                    )
                                                    .map_err(|error| error.to_string())?;
                                            }
                                            manager
                                                .complete_outbound_handshake(
                                                    book,
                                                    peer.address,
                                                    noise_session,
                                                    verified_at_ms,
                                                )
                                                .map_err(|error| error.to_string())?;
                                            verified_session_count = verified_session_count
                                                .checked_add(1)
                                                .ok_or_else(|| "verified session counter overflow".to_string())?;
                                            Ok(())
                                        },
                                    );

                                // The history-sync helper owns and drops the actual stream.
                                // Mirror that exact lifetime in the manager; never retain a
                                // stale "verified" flag after the stream has been closed.
                                // A wall-clock error must not leave a verified session or
                                // pending dial reservation stranded after its stream is dropped.
                                let closed_at_ms = system_now_ms().unwrap_or(reservation_ms);
                                let address = peer.address.to_string();
                                if manager.trust_state(book, &address)
                                    == QRunV06PeerTrustState::NoiseKeyVerified
                                {
                                    manager
                                        .mark_disconnected(
                                            book,
                                            peer.address,
                                            closed_at_ms,
                                            result.is_err(),
                                        )
                                        .map_err(|error| {
                                            QRunV06NodeSupervisorError::BootstrapSync(
                                                format!("verified peer close bookkeeping failed for {}: {error}", peer.address),
                                            )
                                        })?;
                                } else if manager.trust_state(book, &address)
                                    == QRunV06PeerTrustState::DialPending
                                {
                                    manager
                                        .fail_outbound_attempt(book, peer.address, closed_at_ms)
                                        .map_err(|error| {
                                            QRunV06NodeSupervisorError::BootstrapSync(format!(
                                                "pending peer dial cleanup failed for {}: {error}",
                                                peer.address
                                            ))
                                        })?;
                                } else if verification_callback_invoked {
                                    book.record_failure(&address, closed_at_ms).map_err(|error| {
                                        QRunV06NodeSupervisorError::BootstrapSync(
                                            format!("rejected peer failure bookkeeping failed for {}: {error}", peer.address),
                                        )
                                    })?;
                                } else {
                                    manager
                                        .fail_outbound_attempt(book, peer.address, closed_at_ms)
                                        .map_err(|error| {
                                            QRunV06NodeSupervisorError::BootstrapSync(
                                                format!("peer dial failure bookkeeping failed for {}: {error}", peer.address),
                                            )
                                        })?;
                                }
                                result
                            } else {
                                crate::qrun_v06_history_sync_service_candidate::sync_history_from_pinned_peer_with_quote_asset_authorization(
                                        peer.address,
                                        local_static_private_key,
                                        &peer.noise_static_public_key,
                                        runtime,
                                        authenticator,
                                        refresh_config,
                                        quote_authorizer.as_deref_mut(),
                                        peer.tls_server_name.as_deref(),
                                    )
                            };

                            match sync_result {
                                Ok(report) => {
                                    if report.blocks_imported > 0 {
                                        let refreshed_graph =
                                            runtime.fork_choice_snapshot().map_err(|error| {
                                                QRunV06NodeSupervisorError::Runtime(
                                                    error.to_string(),
                                                )
                                            })?;
                                        let refreshed_timestamp = current_candidate_timestamp(
                                            refreshed_graph.canonical_state(),
                                        )
                                        .map_err(QRunV06NodeSupervisorError::Mining)?;
                                        mempool
                                            .reconcile_after_canonical_change_with_quote_asset_authorization(
                                                runtime,
                                                authenticator,
                                                producer,
                                                refreshed_timestamp,
                                                quote_authorizer.as_deref_mut(),
                                            )
                                            .map_err(|error| QRunV06NodeSupervisorError::Mempool(error.to_string()))?;
                                        history_responder = QRunV06HistorySyncResponder::default();
                                    }
                                    eprintln!(
                                        "QFP6_OUTBOUND_SYNC peer={} blocks_imported={} pages={} source_height={} final_height={} complete={}",
                                        peer.address,
                                        report.blocks_imported,
                                        report.pages_imported,
                                        report.source_height,
                                        report.final_height,
                                        report.complete
                                    );
                                }
                                Err(error) => {
                                    // A transient or stale peer never stops the local node. The
                                    // bounded scheduler retries after the interval and rotates.
                                    eprintln!(
                                        "QFP6_OUTBOUND_SYNC_RETRY peer={} error={error}; retry_after_seconds={}",
                                        peer.address,
                                        QRUN_V06_OUTBOUND_BOOTSTRAP_RESYNC_INTERVAL.as_secs()
                                    );
                                }
                            }
                        }
                    }
                }

                // Bitcoin-style peer discovery continuation: signed Q6PD candidates are
                // dialed directly, without per-peer operator approval. The record store has
                // already checked Ed25519 signature, network/profile, endpoint, TTL and replay
                // sequence. The live Noise handshake pins the exact Noise key in that record.
                // A bounded candidate attempt is scheduled every five seconds; failed candidates back off.
                if q6pd_pull_enabled
                    && q6pd_candidate.is_some()
                    && q6pd_candidate_dial_due(last_q6pd_candidate_dial, Instant::now())
                {
                    last_q6pd_candidate_dial = Instant::now();
                    let now_ms = system_now_ms()?;
                    let mut candidates = q6pd_candidate
                        .as_deref()
                        .map(|store| store.candidates(now_ms))
                        .unwrap_or_default();
                    // Configured seeds have their own bootstrap cadence and are excluded
                    // from candidate dialing to avoid duplicate work on the same endpoint.
                    candidates.retain(|record| {
                        !configured_peers.iter().any(|peer| {
                            peer.address == record.endpoint
                                && peer.noise_static_public_key == record.noise_static_public_key
                        })
                    });
                    let local_peer_id = q6pd_self_announcement
                        .as_ref()
                        .map(|(identity, _, _)| identity.info().peer_id);
                    let selected = match q6pd_address_manager.as_mut() {
                        Some(manager) => manager
                            .select_candidate(
                                &candidates,
                                local_peer_id,
                                local_q6pd_noise_key,
                                now_ms,
                            )
                            .map_err(|error| {
                                QRunV06NodeSupervisorError::BootstrapSync(format!(
                                    "Q6PD Address Manager selection failed: {error}"
                                ))
                            })?,
                        None => None,
                    };

                    if selected.is_none() {
                        eprintln!(
                            "QFP6_Q6PD_AUTO_DIAL_SKIPPED reason=no_eligible_signed_candidates stored_candidates={}",
                            q6pd_candidate
                                .as_deref()
                                .map_or(0, |store| store.candidate_count())
                        );
                    } else {
                        let peer = selected.expect("selected candidate was checked as present");
                        let is_feeler = q6pd_address_manager
                            .as_ref()
                            .is_some_and(|manager| manager.is_pending_feeler(&peer.peer_id));
                        if is_feeler {
                            if let Some(manager) = q6pd_address_manager.as_mut() {
                                manager
                                    .record_attempt(&peer.peer_id, now_ms)
                                    .map_err(|error| {
                                        QRunV06NodeSupervisorError::BootstrapSync(format!(
                                            "Q6PD feeler attempt update failed: {error}"
                                        ))
                                    })?;
                            }
                            let feeler_config = QRunV06HistorySyncClientConfig {
                                connect_timeout: Duration::from_secs(3),
                                io_timeout: Duration::from_secs(3),
                                max_blocks_per_page: 1,
                                max_bytes_per_page: 4096,
                                max_pages: 1,
                                max_rounds: 1,
                            };
                            match crate::qrun_v06_history_sync_service_candidate::probe_q6pd_pinned_peer(
                                peer.endpoint,
                                local_static_private_key,
                                &peer.noise_static_public_key,
                                network_id,
                                profile_id,
                                peer.tls_server_name.as_deref(),
                                feeler_config,
                            ) {
                                Ok(()) => {
                                    if let Some(manager) = q6pd_address_manager.as_mut() {
                                        manager.record_success(&peer.peer_id, system_now_ms()?).map_err(|error| {
                                            QRunV06NodeSupervisorError::BootstrapSync(format!(
                                                "Q6PD feeler success update failed: {error}"
                                            ))
                                        })?;
                                    }
                                    eprintln!(
                                        "QFP6_Q6PD_FEELER_AUTHENTICATED endpoint={} action=retain_tried_incumbent",
                                        peer.endpoint
                                    );
                                }
                                Err(error) => {
                                    if let Some(manager) = q6pd_address_manager.as_mut() {
                                        manager.record_feeler_failure(&peer.peer_id, system_now_ms()?).map_err(|manager_error| {
                                            QRunV06NodeSupervisorError::BootstrapSync(format!(
                                                "Q6PD feeler collision resolution failed: {manager_error}"
                                            ))
                                        })?;
                                    }
                                    eprintln!(
                                        "QFP6_Q6PD_FEELER_FAILED endpoint={} action=demote_incumbent_promote_new error={error}",
                                        peer.endpoint
                                    );
                                }
                            }
                        } else {
                            if let Some(manager) = q6pd_address_manager.as_mut() {
                                manager
                                    .record_attempt(&peer.peer_id, now_ms)
                                    .map_err(|error| {
                                        QRunV06NodeSupervisorError::BootstrapSync(format!(
                                            "Q6PD Address Manager attempt update failed: {error}"
                                        ))
                                    })?;
                            }
                            let pull_config = QRunV06HistorySyncClientConfig {
                                connect_timeout: Duration::from_secs(3),
                                io_timeout: Duration::from_secs(5),
                                max_blocks_per_page: 1,
                                max_bytes_per_page: 64 * 1024,
                                max_pages: 1,
                                max_rounds: 1,
                            };

                            let pull_result = match q6pd_candidate.as_deref_mut() {
                                Some(store) => {
                                    let announcement_now_ms = system_now_ms()?;
                                    let local_announcement = q6pd_self_announcement
                                        .as_ref()
                                        .and_then(|(identity, _, _)| {
                                            store.record_wire_for_peer(
                                                &identity.info().peer_id,
                                                announcement_now_ms,
                                            )
                                        });
                                    crate::qrun_v06_history_sync_service_candidate::pull_q6pd_peer_records_from_pinned_peer_with_announcement(
                                    peer.endpoint,
                                    local_static_private_key,
                                    &peer.noise_static_public_key,
                                    network_id,
                                    profile_id,
                                    pull_config,
                                    peer.tls_server_name.as_deref(),
                                    crate::qrun_v06_peer_discovery_candidate::Q6PD_MAX_RECORDS_PER_FRAME as u16,
                                    local_announcement.as_deref(),
                                    store,
                                )
                                }
                                None => continue,
                            };

                            match pull_result {
                                Ok(report) => {
                                    // Attribute pulled records to the authenticated pinned source,
                                    // rather than inventing a source from each advertised endpoint.
                                    if let Some(manager) = q6pd_address_manager.as_mut() {
                                        manager
                                            .observe_all_from(
                                                &report.accepted_records,
                                                peer.endpoint,
                                                system_now_ms()?,
                                            )
                                            .map_err(|error| {
                                                QRunV06NodeSupervisorError::BootstrapSync(format!(
                                                    "Q6PD source-aware AddrMan ingest failed: {error}"
                                                ))
                                            })?;
                                    }
                                    // This exchange authenticates the candidate's Noise key and
                                    // refreshes its signed address inventory, but the bounded helper
                                    // closes its socket on return. Record a success cooldown instead
                                    // of claiming a long-lived connection or redialing every 30s.
                                    if let Some(manager) = q6pd_address_manager.as_mut() {
                                        manager
                                        .record_success(&peer.peer_id, system_now_ms()?)
                                        .map_err(|error| {
                                            QRunV06NodeSupervisorError::BootstrapSync(format!(
                                                "Q6PD Address Manager success update failed: {error}"
                                            ))
                                        })?;
                                    }
                                    eprintln!(
                                    "QFP6_Q6PD_AUTO_DIAL_AUTHENTICATED endpoint={} peer_id_prefix={:02x?} records_received={} inserted={} updated={} duplicate={} rejected={} next_recheck_seconds={}",
                                    peer.endpoint,
                                    &peer.peer_id[..4],
                                    report.records_received,
                                    report.records_inserted,
                                    report.records_updated,
                                    report.records_duplicate,
                                    report.records_rejected,
                                    crate::qrun_v06_q6pd_address_manager_candidate::Q6PD_ADDRMAN_SUCCESS_RECHECK_MS / 1000
                                );

                                    // A node behind NAT still keeps the verified outbound
                                    // Noise session alive; self-announcement is independently optional.
                                    if q6pd_persistent_peer_keys.len()
                                        < crate::qrun_v06_q6pd_session_candidate::Q6PD_MAX_PERSISTENT_SESSIONS
                                        && q6pd_persistent_peer_keys.insert(peer.noise_static_public_key)
                                    {
                                        let local_noise_key = local_q6pd_noise_key;
                                        let address = peer.endpoint;
                                        let tls_server_name = peer.tls_server_name.clone();
                                        let local_key = *local_static_private_key;
                                        let remote_key = peer.noise_static_public_key;
                                        let network = *network_id;
                                        let profile = *profile_id;
                                        let announcement =
                                            std::sync::Arc::clone(&local_q6pd_announcement);
                                        let shutdown = &q6pd_workers_stop;
                                        eprintln!(
                                            "QFP6_Q6PD_SESSION_MANAGER_START endpoint={} source=signed_candidate peer_id_prefix={:02x?}",
                                            address,
                                            &peer.peer_id[..4]
                                        );
                                        scope.spawn(move || {
                                            crate::qrun_v06_q6pd_session_candidate::run_q6pd_persistent_peer_session_worker(
                                                address,
                                                tls_server_name,
                                                local_key,
                                                local_noise_key,
                                                remote_key,
                                                network,
                                                profile,
                                                announcement,
                                                shutdown,
                                            );
                                        });
                                    }

                                    // Reuse the newly authenticated peer as a bounded history
                                    // source. Consensus validation and local fork choice remain
                                    // authoritative; peer count is never treated as a vote.
                                    // Keep candidate discovery responsive: this opportunistic
                                    // history sample is deliberately one small bounded page.
                                    let history_config = QRunV06HistorySyncClientConfig {
                                        connect_timeout: Duration::from_secs(3),
                                        io_timeout: Duration::from_secs(5),
                                        max_blocks_per_page: 1,
                                        max_bytes_per_page: 64 * 1024,
                                        max_pages: 1,
                                        max_rounds: 1,
                                    };
                                    match crate::qrun_v06_history_sync_service_candidate::sync_history_from_pinned_peer_with_quote_asset_authorization(
                                    peer.endpoint,
                                    local_static_private_key,
                                    &peer.noise_static_public_key,
                                    runtime,
                                    authenticator,
                                    history_config,
                                    quote_authorizer.as_deref_mut(),
                                    peer.tls_server_name.as_deref(),
                                ) {
                                    Ok(history_report) => {
                                        if history_report.blocks_imported > 0 {
                                            let refreshed_graph =
                                                runtime.fork_choice_snapshot().map_err(|error| {
                                                    QRunV06NodeSupervisorError::Runtime(
                                                        error.to_string(),
                                                    )
                                                })?;
                                            let refreshed_timestamp = current_candidate_timestamp(
                                                refreshed_graph.canonical_state(),
                                            )
                                            .map_err(QRunV06NodeSupervisorError::Mining)?;
                                            mempool
                                                .reconcile_after_canonical_change_with_quote_asset_authorization(
                                                    runtime,
                                                    authenticator,
                                                    producer,
                                                    refreshed_timestamp,
                                                    quote_authorizer.as_deref_mut(),
                                                )
                                                .map_err(|error| {
                                                    QRunV06NodeSupervisorError::Mempool(
                                                        error.to_string(),
                                                    )
                                                })?;
                                            history_responder = QRunV06HistorySyncResponder::default();
                                        }
                                        eprintln!(
                                            "QFP6_Q6PD_PEER_HISTORY_SYNC endpoint={} blocks_imported={} pages={} source_height={} final_height={} complete={}",
                                            peer.endpoint,
                                            history_report.blocks_imported,
                                            history_report.pages_imported,
                                            history_report.source_height,
                                            history_report.final_height,
                                            history_report.complete
                                        );
                                    }
                                    Err(error) => eprintln!(
                                        "QFP6_Q6PD_PEER_HISTORY_SYNC_RETRY endpoint={} error={error}",
                                        peer.endpoint
                                    ),
                                }
                                }
                                Err(error) => {
                                    let failed_at_ms = system_now_ms()?;
                                    let mut failures = 0u32;
                                    let mut retry_after_ms = failed_at_ms;
                                    if let Some(manager) = q6pd_address_manager.as_mut() {
                                        manager
                                        .record_failure(&peer.peer_id, failed_at_ms)
                                        .map_err(|manager_error| {
                                            QRunV06NodeSupervisorError::BootstrapSync(format!(
                                                "Q6PD Address Manager failure update failed: {manager_error}"
                                            ))
                                        })?;
                                        if let Some(entry) = manager
                                        .entries()
                                        .find(|entry| entry.peer_id == crate::qrun_v06_q6pd_address_manager_candidate::peer_id_hex(&peer.peer_id))
                                    {
                                        failures = entry.failures;
                                        retry_after_ms = entry.retry_after_ms;
                                    }
                                    }
                                    eprintln!(
                                    "QFP6_Q6PD_AUTO_DIAL_RETRY endpoint={} peer_id_prefix={:02x?} failures={} retry_after_ms={} error={error}",
                                    peer.endpoint,
                                    &peer.peer_id[..4],
                                    failures,
                                    retry_after_ms
                                );
                                }
                            }
                        }
                    }
                }

                let graph = runtime
                    .fork_choice_snapshot()
                    .map_err(|error| QRunV06NodeSupervisorError::Runtime(error.to_string()))?;
                let candidate_timestamp = current_candidate_timestamp(graph.canonical_state())
                    .map_err(QRunV06NodeSupervisorError::Mining)?;
                let mined = match mempool.mine_one_batch_with_quote_asset_authorization(
                    runtime,
                    authenticator,
                    producer,
                    candidate_timestamp,
                    config.max_nonce_attempts_per_block,
                    shutdown_requested,
                    quote_authorizer.as_deref_mut(),
                ) {
                    Ok(mined) => mined,
                    // A bounded nonce window is one mining slice, not a fatal node error.
                    // The mempool service has advanced its nonce cursor; return to the listener
                    // so peers/transactions are serviced before the next mining slice.
                    Err(QRunV06PermissionlessServiceError::MiningNonceBudgetExhausted {
                        next_nonce: _,
                    }) => None,
                    Err(QRunV06PermissionlessServiceError::MiningCancelled)
                        if shutdown_requested.load(Ordering::Acquire) =>
                    {
                        stop_reason = QRunV06NodeSupervisorStopReason::ShutdownRequested;
                        break;
                    }
                    Err(error) => {
                        return Err(QRunV06NodeSupervisorError::Mining(error.to_string()))
                    }
                };
                mining_rounds = mining_rounds
                    .checked_add(1)
                    .ok_or(QRunV06NodeSupervisorError::StatisticsOverflow)?;
                if let Some(mined) = mined {
                    blocks_durably_committed = blocks_durably_committed
                        .checked_add(1)
                        .ok_or(QRunV06NodeSupervisorError::StatisticsOverflow)?;
                    if mined.became_canonical {
                        blocks_became_canonical = blocks_became_canonical
                            .checked_add(1)
                            .ok_or(QRunV06NodeSupervisorError::StatisticsOverflow)?;
                    }
                }
                if shutdown_requested.load(Ordering::Acquire) {
                    stop_reason = QRunV06NodeSupervisorStopReason::ShutdownRequested;
                    break;
                }
            }

            let ending = runtime
                .status()
                .map_err(|error| QRunV06NodeSupervisorError::Runtime(error.to_string()))?;
            Ok(QRunV06PermissionlessMiningSupervisorReport {
                listener_rounds,
                mining_rounds,
                blocks_durably_committed,
                blocks_became_canonical,
                ending_height: ending.height,
                pending_mempool_transactions: mempool.pending_count(),
                pending_mempool_bytes: mempool.pending_bytes(),
                mempool_journal_generation: mempool.journal_generation(),
                stats: aggregate,
                stop_reason,
            })
        })();
        q6pd_workers_stop.store(true, Ordering::Release);
        watcher_stop.store(true, Ordering::Release);
        if watcher.join().is_err() {
            return Err(QRunV06NodeSupervisorError::ShutdownWatcherPanicked);
        }
        service_result
    });

    let uninstall_result = match signal {
        Some(signal) => signal
            .uninstall()
            .map_err(|error| QRunV06NodeSupervisorError::ShutdownSignal(error.to_string())),
        None => Ok(()),
    };
    match (run_result, uninstall_result) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Ok(report), Ok(())) => Ok(report),
    }
}

/// Permissionless inbound variant: peers may establish anonymous QFP6 Noise sessions.
/// Transport does not authenticate peer identity; consensus and transaction validation do.
/// Long-running open inbound supervisor. Each inner run has a finite accepted-connection
/// budget; when that window fills, it rolls the listener window without closing the TCP socket,
/// clearing the durable runtime, or losing Q6MJ. Ctrl-C/SIGTERM still exits the outer loop.
#[allow(clippy::too_many_arguments)]
pub fn run_qfp6_permissionless_mining_supervisor_open_with_q6ar_candidate<
    T: TransactionAuthenticator,
>(
    listener: &TcpListener,
    config: QRunV06PermissionlessMiningSupervisorConfig,
    local_static_private_key: &[u8; 32],
    q6ar_relay_static_public_key_pins: &[[u8; 32]],
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
    shutdown_requested: &AtomicBool,
    runtime: &mut QRunV06PermissionlessNodeRuntime,
    authenticator: &T,
    producer: [u8; 32],
    mempool: &mut QRunV06PermissionlessMempool,
    address_book: &mut crate::qrun_v06_peer_address_manager_candidate::QRunV06PeerAddressBookCandidate,
    trust_domains: &crate::qrun_v06_bootstrap_trust_domain_candidate::BootstrapTrustDomainPolicy,
) -> Result<QRunV06PermissionlessMiningSupervisorReport, QRunV06NodeSupervisorError> {
    let mut total = QRunV06PermissionlessMiningSupervisorReport {
        listener_rounds: 0,
        mining_rounds: 0,
        blocks_durably_committed: 0,
        blocks_became_canonical: 0,
        ending_height: 0,
        pending_mempool_transactions: 0,
        pending_mempool_bytes: 0,
        mempool_journal_generation: 0,
        stats: QRunV06PeerListenerStats::default(),
        stop_reason: QRunV06NodeSupervisorStopReason::ShutdownRequested,
    };
    loop {
        if shutdown_requested.load(Ordering::Acquire) {
            total.stop_reason = QRunV06NodeSupervisorStopReason::ShutdownRequested;
            return Ok(total);
        }
        let report = run_qfp6_permissionless_mining_supervisor_with_q6ar_candidate(
            listener,
            config,
            local_static_private_key,
            &[],
            q6ar_relay_static_public_key_pins,
            network_id,
            profile_id,
            shutdown_requested,
            runtime,
            authenticator,
            producer,
            mempool,
            address_book,
            trust_domains,
        )?;
        total.listener_rounds = total
            .listener_rounds
            .checked_add(report.listener_rounds)
            .ok_or(QRunV06NodeSupervisorError::StatisticsOverflow)?;
        total.mining_rounds = total
            .mining_rounds
            .checked_add(report.mining_rounds)
            .ok_or(QRunV06NodeSupervisorError::StatisticsOverflow)?;
        total.blocks_durably_committed = total
            .blocks_durably_committed
            .checked_add(report.blocks_durably_committed)
            .ok_or(QRunV06NodeSupervisorError::StatisticsOverflow)?;
        total.blocks_became_canonical = total
            .blocks_became_canonical
            .checked_add(report.blocks_became_canonical)
            .ok_or(QRunV06NodeSupervisorError::StatisticsOverflow)?;
        add_stats(&mut total.stats, report.stats)?;
        total.ending_height = report.ending_height;
        total.pending_mempool_transactions = report.pending_mempool_transactions;
        total.pending_mempool_bytes = report.pending_mempool_bytes;
        total.mempool_journal_generation = report.mempool_journal_generation;
        total.stop_reason = report.stop_reason;
        if report.stop_reason == QRunV06NodeSupervisorStopReason::ShutdownRequested {
            return Ok(total);
        }
        thread::sleep(Duration::from_millis(100));
    }
}

#[allow(clippy::too_many_arguments)]
pub fn run_qfp6_permissionless_mining_supervisor_open<T: TransactionAuthenticator>(
    listener: &TcpListener,
    config: QRunV06PermissionlessMiningSupervisorConfig,
    local_static_private_key: &[u8; 32],
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
    shutdown_requested: &AtomicBool,
    runtime: &mut QRunV06PermissionlessNodeRuntime,
    authenticator: &T,
    producer: [u8; 32],
    mempool: &mut QRunV06PermissionlessMempool,
) -> Result<QRunV06PermissionlessMiningSupervisorReport, QRunV06NodeSupervisorError> {
    let mut total = QRunV06PermissionlessMiningSupervisorReport {
        listener_rounds: 0,
        mining_rounds: 0,
        blocks_durably_committed: 0,
        blocks_became_canonical: 0,
        ending_height: 0,
        pending_mempool_transactions: 0,
        pending_mempool_bytes: 0,
        mempool_journal_generation: 0,
        stats: QRunV06PeerListenerStats::default(),
        stop_reason: QRunV06NodeSupervisorStopReason::ShutdownRequested,
    };
    loop {
        if shutdown_requested.load(Ordering::Acquire) {
            total.stop_reason = QRunV06NodeSupervisorStopReason::ShutdownRequested;
            return Ok(total);
        }
        let report = run_qfp6_permissionless_mining_supervisor(
            listener,
            config,
            local_static_private_key,
            &[],
            network_id,
            profile_id,
            shutdown_requested,
            runtime,
            authenticator,
            producer,
            mempool,
        )?;
        total.listener_rounds = total
            .listener_rounds
            .checked_add(report.listener_rounds)
            .ok_or(QRunV06NodeSupervisorError::StatisticsOverflow)?;
        total.mining_rounds = total
            .mining_rounds
            .checked_add(report.mining_rounds)
            .ok_or(QRunV06NodeSupervisorError::StatisticsOverflow)?;
        total.blocks_durably_committed = total
            .blocks_durably_committed
            .checked_add(report.blocks_durably_committed)
            .ok_or(QRunV06NodeSupervisorError::StatisticsOverflow)?;
        total.blocks_became_canonical = total
            .blocks_became_canonical
            .checked_add(report.blocks_became_canonical)
            .ok_or(QRunV06NodeSupervisorError::StatisticsOverflow)?;
        add_stats(&mut total.stats, report.stats)?;
        total.ending_height = report.ending_height;
        total.pending_mempool_transactions = report.pending_mempool_transactions;
        total.pending_mempool_bytes = report.pending_mempool_bytes;
        total.mempool_journal_generation = report.mempool_journal_generation;
        total.stop_reason = report.stop_reason;
        if report.stop_reason == QRunV06NodeSupervisorStopReason::ShutdownRequested {
            return Ok(total);
        }
        // SessionBudgetReached is a window rotation, not a node shutdown.
        thread::sleep(Duration::from_millis(100));
    }
}
/// Genesis-rooted open listener with Q6PD signed-record serving and self-announcement.
/// Unlike the legacy open wrapper, this keeps the candidate store attached to inbound Noise
/// application frames when the root has no upstream peers; signed inbound candidates may still
/// be pulled and auto-dialed when Q6PD outbound discovery is enabled.
#[allow(clippy::too_many_arguments)]
pub fn run_qfp6_permissionless_mining_supervisor_open_with_q6pd_candidate<
    T: TransactionAuthenticator,
>(
    listener: &TcpListener,
    config: QRunV06PermissionlessMiningSupervisorConfig,
    local_static_private_key: &[u8; 32],
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
    shutdown_requested: &AtomicBool,
    runtime: &mut QRunV06PermissionlessNodeRuntime,
    authenticator: &T,
    producer: [u8; 32],
    mempool: &mut QRunV06PermissionlessMempool,
    mut quote_authorizer: Option<&mut QRunV06QuoteAssetAuthorizationProvider<'_>>,
    q6pd_candidate: &mut Q6pdPeerRecordStore,
    q6pd_pull_enabled: bool,
    q6pd_self_announcement: Option<(&Q6pdNodeIdentity, SocketAddr, Option<String>)>,
) -> Result<QRunV06PermissionlessMiningSupervisorReport, QRunV06NodeSupervisorError> {
    let mut total = QRunV06PermissionlessMiningSupervisorReport {
        listener_rounds: 0,
        mining_rounds: 0,
        blocks_durably_committed: 0,
        blocks_became_canonical: 0,
        ending_height: 0,
        pending_mempool_transactions: 0,
        pending_mempool_bytes: 0,
        mempool_journal_generation: 0,
        stats: QRunV06PeerListenerStats::default(),
        stop_reason: QRunV06NodeSupervisorStopReason::ShutdownRequested,
    };
    loop {
        if shutdown_requested.load(Ordering::Acquire) {
            total.stop_reason = QRunV06NodeSupervisorStopReason::ShutdownRequested;
            return Ok(total);
        }
        let report = run_qfp6_permissionless_mining_supervisor_inner(
            listener,
            config,
            local_static_private_key,
            &[],
            network_id,
            profile_id,
            shutdown_requested,
            runtime,
            authenticator,
            producer,
            mempool,
            None,
            None,
            quote_authorizer.as_deref_mut(),
            None,
            Some(&mut *q6pd_candidate),
            q6pd_pull_enabled,
            q6pd_self_announcement.clone(),
        )?;
        total.listener_rounds = total
            .listener_rounds
            .checked_add(report.listener_rounds)
            .ok_or(QRunV06NodeSupervisorError::StatisticsOverflow)?;
        total.mining_rounds = total
            .mining_rounds
            .checked_add(report.mining_rounds)
            .ok_or(QRunV06NodeSupervisorError::StatisticsOverflow)?;
        total.blocks_durably_committed = total
            .blocks_durably_committed
            .checked_add(report.blocks_durably_committed)
            .ok_or(QRunV06NodeSupervisorError::StatisticsOverflow)?;
        total.blocks_became_canonical = total
            .blocks_became_canonical
            .checked_add(report.blocks_became_canonical)
            .ok_or(QRunV06NodeSupervisorError::StatisticsOverflow)?;
        add_stats(&mut total.stats, report.stats)?;
        total.ending_height = report.ending_height;
        total.pending_mempool_transactions = report.pending_mempool_transactions;
        total.pending_mempool_bytes = report.pending_mempool_bytes;
        total.mempool_journal_generation = report.mempool_journal_generation;
        total.stop_reason = report.stop_reason;
        if report.stop_reason == QRunV06NodeSupervisorStopReason::ShutdownRequested {
            return Ok(total);
        }
        thread::sleep(Duration::from_millis(100));
    }
}
/// Validate a static set of outbound bootstrap peers and return their Noise static-key pins.
pub fn validate_qfp6_pinned_bootstrap_peers(
    peers: &[QRunV06PinnedBootstrapPeer],
) -> Result<Vec<[u8; 32]>, QRunV06NodeSupervisorError> {
    if peers.is_empty() || peers.len() > 64 {
        return Err(QRunV06NodeSupervisorError::InvalidBootstrapPeers);
    }
    let mut addresses = HashSet::new();
    let mut keys = HashSet::new();
    let mut trusted_keys = Vec::with_capacity(peers.len());
    for peer in peers {
        let invalid_tls_relay = match peer.tls_server_name.as_deref() {
            None => false,
            Some(name) => {
                peer.address.port() != 443
                    || name.is_empty()
                    || name.len() > 253
                    || name.parse::<std::net::IpAddr>().is_ok()
                    || !name.contains('.')
                    || name.ends_with('.')
                    || name.split('.').any(|label| {
                        let bytes = label.as_bytes();
                        bytes.is_empty()
                            || bytes.len() > 63
                            || !bytes[0].is_ascii_alphanumeric()
                            || !bytes[bytes.len() - 1].is_ascii_alphanumeric()
                            || bytes
                                .iter()
                                .any(|byte| !byte.is_ascii_alphanumeric() && *byte != b'-')
                    })
                    || name.eq_ignore_ascii_case("localhost")
                    || [
                        ".localhost",
                        ".local",
                        ".internal",
                        ".test",
                        ".invalid",
                        ".example",
                    ]
                    .iter()
                    .any(|suffix| name.to_ascii_lowercase().ends_with(suffix))
            }
        };
        if peer.address.port() == 0
            || peer.address.ip().is_unspecified()
            || peer.address.ip().is_multicast()
            || peer.noise_static_public_key == [0; 32]
            || invalid_tls_relay
            || !addresses.insert(peer.address)
            || !keys.insert(peer.noise_static_public_key)
        {
            return Err(QRunV06NodeSupervisorError::InvalidBootstrapPeers);
        }
        trusted_keys.push(peer.noise_static_public_key);
    }
    Ok(trusted_keys)
}

/// Require independent bootstrap snapshots to describe one retained ancestry chain.
/// A source is counted once per operator-assigned trust domain. Peer count is never a vote:
/// every snapshot must already be imported and validated by the local fork-choice graph.
fn validate_bootstrap_source_tip_relationships<F>(
    source_tips: &[([u8; 32], [u8; 32])],
    mut is_ancestor: F,
) -> Result<(), String>
where
    F: FnMut(&[u8; 32], &[u8; 32]) -> bool,
{
    if source_tips.len() < 2 {
        return Err("fewer than two independent bootstrap source domains completed sync".into());
    }

    let mut domains = HashSet::new();
    for (domain, _) in source_tips {
        if !domains.insert(*domain) {
            return Err("bootstrap source evidence contains a duplicate trust domain".into());
        }
    }
    if domains.len() < 2 {
        return Err("bootstrap source agreement requires at least two trust domains".into());
    }

    for left in 0..source_tips.len() {
        for right in (left + 1)..source_tips.len() {
            let left_tip = &source_tips[left].1;
            let right_tip = &source_tips[right].1;
            if !is_ancestor(left_tip, right_tip) && !is_ancestor(right_tip, left_tip) {
                return Err(format!(
                    "independent bootstrap sources report divergent histories: domain {:02x?} tip {} conflicts with domain {:02x?} tip {}",
                    &source_tips[left].0[..4],
                    left_tip.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
                    &source_tips[right].0[..4],
                    right_tip.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_bootstrap_source_snapshots(
    graph: &QRunV06PowForkChoice,
    snapshots: &[([u8; 32], QRunV06HistorySyncClientReport)],
) -> Result<(), String> {
    if snapshots.len() < 2 {
        return Err("at least two independent bootstrap snapshots are required".into());
    }

    let mut source_tips = Vec::with_capacity(snapshots.len());
    for (domain, report) in snapshots {
        if !report.complete {
            return Err(
                "incomplete bootstrap source snapshot cannot participate in agreement".into(),
            );
        }
        let chain_tip = graph.tip_for_hash(&report.source_tip).ok_or_else(|| {
            "bootstrap source consensus tip is missing from the locally validated fork archive"
                .to_string()
        })?;
        let chain_state = graph.state_for_tip(&report.source_tip).ok_or_else(|| {
            "bootstrap source execution state is missing from the locally validated fork archive".to_string()
        })?;
        if chain_tip.height != report.source_height
            || chain_state.tip_hash() != report.source_execution_tip
        {
            return Err(
                "bootstrap source height/execution tip disagrees with the locally validated snapshot"
                    .into(),
            );
        }
        source_tips.push((*domain, report.source_tip));
    }

    validate_bootstrap_source_tip_relationships(&source_tips, |ancestor, descendant| {
        graph.is_ancestor_tip(ancestor, descendant)
    })
}

/// QAP1-only startup: authenticate and synchronize from an operator-pinned peer set, then
/// enter the QAP1 mining supervisor. No non-QAP1 runtime or bulk-import fallback is available.
#[allow(clippy::too_many_arguments)]
pub fn run_qfp6_mining_supervisor_with_qap1_bootstrap<A, T, P, PV, AV, Q, F>(
    listener: &TcpListener,
    config: QRunV06MiningSupervisorConfig,
    local_static_private_key: &[u8; 32],
    bootstrap_peers: &[QRunV06PinnedBootstrapPeer],
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
    shutdown_requested: &AtomicBool,
    runtime: &mut QRunV06NodeRuntime<A>,
    authenticator: &T,
    quote_authorizer: &mut QRunV06QuoteAssetAuthorizationProvider<'_>,
    coordinator: &mut QRunV06Qap1ExternalCoordinator<P, PV, AV, Q>,
    producer: [u8; 32],
    transaction_journal: &mut QRunV06TransactionJournal,
    next_template: F,
    sync_config: QRunV06HistorySyncClientConfig,
) -> Result<QRunV06Qap1LaunchReport, QRunV06NodeSupervisorError>
where
    A: QRunV06NodeAnchorGate,
    T: TransactionAuthenticator,
    P: ExternalCasProviderTransport,
    PV: MlDsa65Verifier + Clone,
    AV: MlDsa65Verifier,
    Q: QRunV06Qap1AnchorTransport,
    F: FnMut(&QRunV06CanonicalExecutionState) -> Result<(u64, Vec<QRunV06BlockOperation>), String>,
{
    config.validate()?;
    sync_config
        .validate()
        .map_err(|error| QRunV06NodeSupervisorError::BootstrapSync(error.to_string()))?;
    validate_identity_material(local_static_private_key, network_id, profile_id)?;
    if producer == [0; 32] {
        return Err(QRunV06NodeSupervisorError::InvalidIdentity);
    }
    let trusted_keys = validate_qfp6_pinned_bootstrap_peers(bootstrap_peers)?;
    if !runtime.requires_qap1() || !runtime.qap1_recovery_verified() {
        return Err(QRunV06NodeSupervisorError::RuntimeNotQap1Recovered);
    }
    if runtime.requires_reopen() {
        return Err(QRunV06NodeSupervisorError::RuntimeRequiresRecovery);
    }
    if runtime.has_pending_external_anchor() {
        return Err(QRunV06NodeSupervisorError::PendingAnchorTransition);
    }
    let anchor = runtime.committed_anchor_state();
    if anchor.network_id != *network_id {
        return Err(QRunV06NodeSupervisorError::NetworkMismatch);
    }
    if anchor.profile_id != *profile_id {
        return Err(QRunV06NodeSupervisorError::ProfileMismatch);
    }
    validate_qap1_pin_bindings(anchor, coordinator.provider_pin(), coordinator.qfp6_pin())?;
    let mut bootstrap_sync = None;
    let mut peer_errors = Vec::new();
    for peer in bootstrap_peers {
        match sync_history_from_pinned_peer_until_complete_with_qap1(
            peer.address,
            local_static_private_key,
            &peer.noise_static_public_key,
            runtime,
            authenticator,
            quote_authorizer,
            coordinator,
            sync_config,
            peer.tls_server_name.as_deref(),
        ) {
            Ok(report) if report.complete => {
                bootstrap_sync = Some(report);
                break;
            }
            Ok(_) => peer_errors.push(format!(
                "{}: bounded QAP1 sync did not reach the pinned snapshot",
                peer.address
            )),
            Err(error) => {
                peer_errors.push(format!("{}: {error}", peer.address));
                if runtime.requires_reopen() {
                    return Err(QRunV06NodeSupervisorError::RuntimeRequiresRecovery);
                }
                if runtime.has_pending_external_anchor() {
                    return Err(QRunV06NodeSupervisorError::PendingAnchorTransition);
                }
            }
        }
    }
    let bootstrap_sync = bootstrap_sync
        .ok_or_else(|| QRunV06NodeSupervisorError::BootstrapSync(peer_errors.join("; ")))?;
    let supervisor = run_qfp6_mining_supervisor(
        listener,
        config,
        local_static_private_key,
        &trusted_keys,
        network_id,
        profile_id,
        shutdown_requested,
        runtime,
        authenticator,
        quote_authorizer,
        coordinator,
        producer,
        transaction_journal,
        next_template,
    )?;
    Ok(QRunV06Qap1LaunchReport {
        bootstrap_sync,
        supervisor,
    })
}
/// Bootstrap-synchronized variant with candidate-only Q6AR persistence. Inbound sessions remain
/// anonymous; the bootstrap keys identify only which relays may contribute persisted addresses.
#[allow(clippy::too_many_arguments)]
pub fn run_qfp6_permissionless_mining_supervisor_with_bootstrap_and_q6ar_candidate<
    T: TransactionAuthenticator,
>(
    listener: &TcpListener,
    config: QRunV06PermissionlessMiningSupervisorConfig,
    local_static_private_key: &[u8; 32],
    bootstrap_peers: &[QRunV06PinnedBootstrapPeer],
    q6ar_relay_static_public_key_pins: &[[u8; 32]],
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
    shutdown_requested: &AtomicBool,
    runtime: &mut QRunV06PermissionlessNodeRuntime,
    authenticator: &T,
    producer: [u8; 32],
    mempool: &mut QRunV06PermissionlessMempool,
    sync_config: QRunV06HistorySyncClientConfig,
    max_peer_attempts: usize,
    address_book: &mut crate::qrun_v06_peer_address_manager_candidate::QRunV06PeerAddressBookCandidate,
    trust_domains: &crate::qrun_v06_bootstrap_trust_domain_candidate::BootstrapTrustDomainPolicy,
    mut quote_authorizer: Option<&mut QRunV06QuoteAssetAuthorizationProvider<'_>>,
    read_api_listener: Option<&TcpListener>,
    q6pd_candidate: Option<&mut Q6pdPeerRecordStore>,
    q6pd_pull_enabled: bool,
    q6pd_self_announcement: Option<(&Q6pdNodeIdentity, SocketAddr, Option<String>)>,
) -> Result<QRunV06PermissionlessLaunchReport, QRunV06NodeSupervisorError> {
    config.validate()?;
    sync_config
        .validate()
        .map_err(|error| QRunV06NodeSupervisorError::BootstrapSync(error.to_string()))?;
    validate_identity_material(local_static_private_key, network_id, profile_id)?;
    if !(1..=64).contains(&max_peer_attempts) {
        return Err(QRunV06NodeSupervisorError::InvalidConfiguration);
    }
    validate_qfp6_pinned_bootstrap_peers(bootstrap_peers)?;
    let startup = runtime
        .status()
        .map_err(|error| QRunV06NodeSupervisorError::Runtime(error.to_string()))?;
    if startup.network_id != *network_id {
        return Err(QRunV06NodeSupervisorError::NetworkMismatch);
    }
    if startup.profile_id != *profile_id {
        return Err(QRunV06NodeSupervisorError::ProfileMismatch);
    }
    let configured_domains: HashSet<[u8; 32]> = bootstrap_peers
        .iter()
        .take(max_peer_attempts)
        .map(|peer| trust_domains.domain_for(&peer.noise_static_public_key))
        .collect::<Result<_, _>>()
        .map_err(|error| {
            QRunV06NodeSupervisorError::BootstrapSync(format!(
                "bootstrap relay has no operator trust-domain assignment: {error:?}"
            ))
        })?;
    let require_independent_agreement = configured_domains.len() >= 2;
    let mut successful_domains = HashSet::new();
    let mut source_snapshots: Vec<([u8; 32], QRunV06HistorySyncClientReport)> = Vec::new();
    let mut peer_errors = Vec::new();

    // Try peers until the configured budget is exhausted, but count at most one successful
    // snapshot per operator-assigned domain. A second peer in the same domain is only a
    // fallback when the first one in that domain did not complete synchronization.
    for peer in bootstrap_peers.iter().take(max_peer_attempts) {
        let domain = trust_domains
            .domain_for(&peer.noise_static_public_key)
            .map_err(|error| {
                QRunV06NodeSupervisorError::BootstrapSync(format!(
                    "bootstrap relay trust-domain lookup failed: {error:?}"
                ))
            })?;
        if successful_domains.contains(&domain) {
            continue;
        }

        let address_key = peer.address.to_string();
        match crate::qrun_v06_history_sync_service_candidate::sync_history_from_pinned_peer_until_complete_with_quote_asset_authorization(
            peer.address,
            local_static_private_key,
            &peer.noise_static_public_key,
            runtime,
            authenticator,
            sync_config,
            quote_authorizer.as_deref_mut(),
            peer.tls_server_name.as_deref(),
        ) {
            Ok(report) if report.complete => {
                address_book.record_success(&address_key).map_err(|error| {
                    QRunV06NodeSupervisorError::BootstrapSync(format!(
                        "cannot persist peer success state: {error}"
                    ))
                })?;
                successful_domains.insert(domain);
                source_snapshots.push((domain, report));
            }
            Ok(_) => {
                address_book
                    .record_failure(&address_key, system_now_ms()?)
                    .map_err(|error| {
                        QRunV06NodeSupervisorError::BootstrapSync(format!(
                            "cannot persist peer backoff: {error}"
                        ))
                    })?;
                peer_errors.push(format!(
                    "{} returned without reaching the pinned source tip",
                    peer.address
                ));
            }
            Err(error) => {
                address_book
                    .record_failure(&address_key, system_now_ms()?)
                    .map_err(|store_error| {
                        QRunV06NodeSupervisorError::BootstrapSync(format!(
                            "{error}; additionally failed to persist peer backoff: {store_error}"
                        ))
                    })?;
                peer_errors.push(format!("{}: {error}", peer.address));
            }
        }
    }

    if source_snapshots.is_empty() {
        return Err(QRunV06NodeSupervisorError::BootstrapSync(
            peer_errors.join("; "),
        ));
    }
    if require_independent_agreement {
        if source_snapshots.len() < 2 {
            return Err(QRunV06NodeSupervisorError::BootstrapSync(format!(
                "independent bootstrap agreement required, but only {} of {} configured trust domains completed sync; {}",
                source_snapshots.len(),
                configured_domains.len(),
                peer_errors.join("; ")
            )));
        }
        let graph = runtime.fork_choice_snapshot().map_err(|error| {
            QRunV06NodeSupervisorError::BootstrapSync(format!(
                "cannot inspect locally validated branches for bootstrap agreement: {error}"
            ))
        })?;
        validate_bootstrap_source_snapshots(&graph, &source_snapshots)
            .map_err(QRunV06NodeSupervisorError::BootstrapSync)?;
    }
    let bootstrap_sync = source_snapshots
        .first()
        .map(|(_, report)| report.clone())
        .ok_or_else(|| QRunV06NodeSupervisorError::BootstrapSync(peer_errors.join("; ")))?;
    let relay_pins: Vec<[u8; 32]> = bootstrap_peers
        .iter()
        .map(|peer| peer.noise_static_public_key)
        .collect();
    let supervisor = run_qfp6_permissionless_mining_supervisor_inner(
        listener,
        config,
        local_static_private_key,
        &relay_pins,
        network_id,
        profile_id,
        shutdown_requested,
        runtime,
        authenticator,
        producer,
        mempool,
        Some(bootstrap_peers),
        Some((
            address_book,
            q6ar_relay_static_public_key_pins.to_vec(),
            bootstrap_peers
                .iter()
                .map(|peer| peer.noise_static_public_key)
                .collect(),
            trust_domains,
        )),
        quote_authorizer.as_deref_mut(),
        read_api_listener,
        q6pd_candidate,
        q6pd_pull_enabled,
        q6pd_self_announcement,
    )?;
    Ok(QRunV06PermissionlessLaunchReport {
        bootstrap_sync,
        supervisor,
    })
}

/// Startup path that refuses to begin mining until one of the configured statically pinned
/// peers has completed Q6HI/Q6HR discovery and full bounded canonical-history synchronization.
/// The same peer key set is then used by the permissionless inbound Noise listener.
#[allow(clippy::too_many_arguments)]
pub fn run_qfp6_permissionless_mining_supervisor_with_bootstrap<T: TransactionAuthenticator>(
    listener: &TcpListener,
    config: QRunV06PermissionlessMiningSupervisorConfig,
    local_static_private_key: &[u8; 32],
    bootstrap_peers: &[QRunV06PinnedBootstrapPeer],
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
    shutdown_requested: &AtomicBool,
    runtime: &mut QRunV06PermissionlessNodeRuntime,
    authenticator: &T,
    producer: [u8; 32],
    mempool: &mut QRunV06PermissionlessMempool,
    sync_config: QRunV06HistorySyncClientConfig,
    mut quote_authorizer: Option<&mut QRunV06QuoteAssetAuthorizationProvider<'_>>,
    read_api_listener: Option<&TcpListener>,
    q6pd_candidate: Option<&mut Q6pdPeerRecordStore>,
    q6pd_pull_enabled: bool,
    q6pd_self_announcement: Option<(&Q6pdNodeIdentity, SocketAddr, Option<String>)>,
) -> Result<QRunV06PermissionlessLaunchReport, QRunV06NodeSupervisorError> {
    config.validate()?;
    sync_config
        .validate()
        .map_err(|error| QRunV06NodeSupervisorError::BootstrapSync(error.to_string()))?;
    validate_identity_material(local_static_private_key, network_id, profile_id)?;
    validate_qfp6_pinned_bootstrap_peers(bootstrap_peers)?;
    let startup = runtime
        .status()
        .map_err(|error| QRunV06NodeSupervisorError::Runtime(error.to_string()))?;
    if startup.network_id != *network_id {
        return Err(QRunV06NodeSupervisorError::NetworkMismatch);
    }
    if startup.profile_id != *profile_id {
        return Err(QRunV06NodeSupervisorError::ProfileMismatch);
    }

    let mut bootstrap_report = None;
    let mut peer_errors = Vec::new();
    for peer in bootstrap_peers {
        match crate::qrun_v06_history_sync_service_candidate::sync_history_from_pinned_peer_until_complete_with_quote_asset_authorization(
            peer.address,
            local_static_private_key,
            &peer.noise_static_public_key,
            runtime,
            authenticator,
            sync_config,
            quote_authorizer.as_deref_mut(),
            peer.tls_server_name.as_deref(),
        ) {
            Ok(report) if report.complete => {
                bootstrap_report = Some(report);
                break;
            }
            Ok(_) => peer_errors.push(format!(
                "{} returned without reaching the pinned source tip",
                peer.address
            )),
            Err(error) => peer_errors.push(format!("{}: {error}", peer.address)),
        }
    }
    let bootstrap_sync = bootstrap_report
        .ok_or_else(|| QRunV06NodeSupervisorError::BootstrapSync(peer_errors.join("; ")))?;
    let supervisor = run_qfp6_permissionless_mining_supervisor_inner(
        listener,
        config,
        local_static_private_key,
        &validate_qfp6_pinned_bootstrap_peers(bootstrap_peers)?,
        network_id,
        profile_id,
        shutdown_requested,
        runtime,
        authenticator,
        producer,
        mempool,
        Some(bootstrap_peers),
        None,
        quote_authorizer.as_deref_mut(),
        read_api_listener,
        q6pd_candidate,
        q6pd_pull_enabled,
        q6pd_self_announcement,
    )?;
    Ok(QRunV06PermissionlessLaunchReport {
        bootstrap_sync,
        supervisor,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outbound_bootstrap_resync_waits_for_bounded_poll_interval() {
        let started = Instant::now();
        assert!(!outbound_bootstrap_resync_due(
            started,
            started + Duration::from_secs(29),
        ));
        assert!(outbound_bootstrap_resync_due(
            started,
            started + Duration::from_secs(30),
        ));
        let next_poll = started + Duration::from_secs(30);
        assert!(!outbound_bootstrap_resync_due(
            next_poll,
            next_poll + Duration::from_secs(29),
        ));
    }

    #[test]
    fn q6pd_discovery_refresh_runs_every_thirty_seconds() {
        let started = Instant::now();
        assert!(!q6pd_discovery_pull_due(
            started,
            started + Duration::from_secs(29),
        ));
        assert!(q6pd_discovery_pull_due(
            started,
            started + Duration::from_secs(30),
        ));
        let next_pull = started + Duration::from_secs(30);
        assert!(!q6pd_discovery_pull_due(
            next_pull,
            next_pull + Duration::from_secs(29),
        ));
    }

    #[test]
    fn q6pd_candidate_dial_runs_on_a_five_second_cadence() {
        let started = Instant::now();
        assert!(!q6pd_candidate_dial_due(
            started,
            started + Duration::from_secs(4),
        ));
        assert!(q6pd_candidate_dial_due(
            started,
            started + Duration::from_secs(5),
        ));
    }

    #[test]
    fn q6ar_discovery_refresh_waits_for_five_minute_interval() {
        let started = Instant::now();
        assert!(!q6ar_discovery_pull_due(
            started,
            started + Duration::from_secs(299),
        ));
        assert!(q6ar_discovery_pull_due(
            started,
            started + Duration::from_secs(300),
        ));
        let next_pull = started + Duration::from_secs(300);
        assert!(!q6ar_discovery_pull_due(
            next_pull,
            next_pull + Duration::from_secs(299),
        ));
    }

    #[test]
    fn automatic_dial_targets_respect_selected_approved_key_set() {
        use crate::qrun_v06_peer_address_manager_candidate::{
            PeerAddressSource, QRunV06PeerAddressBookCandidate,
        };

        const NETWORK: [u8; 32] = [0xA1; 32];
        const PROFILE: [u8; 32] = [0xA2; 32];
        const SELECTED_KEY: [u8; 32] = [0x31; 32];
        const OTHER_APPROVED_KEY: [u8; 32] = [0x32; 32];

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "qfp6-approved-dial-targets-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let store = root.join("peers.q6pa");

        let mut book = QRunV06PeerAddressBookCandidate::open(&store, NETWORK, PROFILE).unwrap();
        let selected_address: std::net::SocketAddr = "127.0.0.1:30336".parse().unwrap();
        let other_address: std::net::SocketAddr = "127.0.0.1:30337".parse().unwrap();
        book.pin_manual_peer(&selected_address.to_string(), SELECTED_KEY, 100)
            .unwrap();
        book.pin_manual_peer(&other_address.to_string(), OTHER_APPROVED_KEY, 100)
            .unwrap();
        book.upsert("127.0.0.1:30338", PeerAddressSource::Gossip, 100)
            .unwrap();

        let configured = [QRunV06PinnedBootstrapPeer {
            address: selected_address,
            noise_static_public_key: SELECTED_KEY,
            tls_server_name: Some("seed.example".into()),
        }];
        let targets =
            address_book_approved_dial_targets(&book, &configured, &[SELECTED_KEY], 1_000);

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].address, selected_address);
        assert_eq!(targets[0].noise_static_public_key, SELECTED_KEY);
        assert_eq!(targets[0].tls_server_name.as_deref(), Some("seed.example"));

        drop(book);
        std::fs::remove_dir_all(root).unwrap();
    }
    use crate::{
        consensus::{ConsensusParameters, PowAlgorithm, PowParameters, Uint256},
        qrun_v06_genesis_descriptor_candidate::QRunV06GenesisDescriptor,
        qrun_v06_hybrid_auth_candidate::{
            QRunV06HybridTransactionAuthenticator, QRunV06HybridTransactionSigner,
        },
        qrun_v06_tokenomics_candidate::{QRunV06MiningScheduleCandidate, QRunV06TokenomicsState},
        qrun_v06_transaction_mempool_candidate::QRunV06MempoolLimits,
        state_machine::Transaction,
        v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate,
        v4_fat1_trust_candidate::ML_DSA_65_PUBLIC_KEY_BYTES,
    };

    #[test]
    fn bootstrap_source_snapshots_require_distinct_domains_and_one_ancestry_chain() {
        const DOMAIN_A: [u8; 32] = [0xA1; 32];
        const DOMAIN_B: [u8; 32] = [0xB1; 32];
        const TIP_BASE: [u8; 32] = [0x10; 32];
        const TIP_CHILD: [u8; 32] = [0x20; 32];
        const TIP_SIBLING: [u8; 32] = [0x30; 32];

        let consistent = [(DOMAIN_A, TIP_BASE), (DOMAIN_B, TIP_CHILD)];
        assert!(validate_bootstrap_source_tip_relationships(
            &consistent,
            |ancestor, descendant| {
                ancestor == descendant || (*ancestor == TIP_BASE && *descendant == TIP_CHILD)
            },
        )
        .is_ok());

        let divergent = [(DOMAIN_A, TIP_CHILD), (DOMAIN_B, TIP_SIBLING)];
        let error =
            validate_bootstrap_source_tip_relationships(&divergent, |ancestor, descendant| {
                ancestor == descendant
            })
            .unwrap_err();
        assert!(error.contains("divergent histories"));

        let duplicate_domain = [(DOMAIN_A, TIP_BASE), (DOMAIN_A, TIP_CHILD)];
        assert!(validate_bootstrap_source_tip_relationships(
            &duplicate_domain,
            |ancestor, descendant| ancestor == descendant,
        )
        .unwrap_err()
        .contains("duplicate trust domain"));

        assert!(validate_bootstrap_source_tip_relationships(
            &[(DOMAIN_A, TIP_BASE)],
            |ancestor, descendant| ancestor == descendant,
        )
        .unwrap_err()
        .contains("fewer than two"));
    }

    #[test]
    fn bootstrap_source_snapshot_metadata_must_match_local_fork_archive() {
        use crate::{
            consensus::ConsensusParameters,
            qrun_v06_canonical_execution_candidate::QRunV06CanonicalExecutionState,
            qrun_v06_checkpoint_candidate::qrun_v06_consensus_fingerprint,
            qrun_v06_cp0604_supply_candidate::Cp0604FounderControlledSupply,
            qrun_v06_genesis_descriptor_candidate::QRunV06GenesisDescriptor,
            qrun_v06_tokenomics_candidate::QRunV06MiningScheduleCandidate,
        };

        const NETWORK: [u8; 32] = [0x51; 32];
        const PROFILE: [u8; 32] = [0x52; 32];
        const FOUNDER: [u8; 32] = [0x53; 32];
        let params = ConsensusParameters::qrun_v06_sha256d_candidate().unwrap();
        let schedule = QRunV06MiningScheduleCandidate::cp0422_research_candidate();
        let supply = Cp0604FounderControlledSupply::genesis(NETWORK, FOUNDER, schedule).unwrap();
        let descriptor = QRunV06GenesisDescriptor::new(
            NETWORK,
            PROFILE,
            FOUNDER,
            1,
            qrun_v06_consensus_fingerprint(&params).unwrap(),
            supply.policy_fingerprint(),
        )
        .unwrap();
        let genesis = QRunV06CanonicalExecutionState::cp0604_genesis_candidate_with_descriptor(
            descriptor, schedule,
        )
        .unwrap();
        let genesis_commitment = genesis.genesis_descriptor_commitment().unwrap();
        let graph = QRunV06PowForkChoice::new_with_expected_genesis_descriptor_commitment(
            genesis,
            params,
            genesis_commitment,
        )
        .unwrap();
        let source_tip = graph.base_tip();
        let source_execution_tip = graph.state_for_tip(&source_tip).unwrap().tip_hash();
        let report = QRunV06HistorySyncClientReport {
            source_height: 0,
            final_height: 0,
            pages_imported: 0,
            blocks_imported: 0,
            source_tip,
            source_execution_tip,
            complete: true,
        };

        assert!(validate_bootstrap_source_snapshots(
            &graph,
            &[([0xA1; 32], report.clone()), ([0xB1; 32], report.clone())],
        )
        .is_ok());

        let mut mismatched = report.clone();
        mismatched.source_execution_tip = [0xEE; 32];
        assert!(validate_bootstrap_source_snapshots(
            &graph,
            &[([0xA1; 32], mismatched), ([0xB1; 32], report)],
        )
        .unwrap_err()
        .contains("execution tip disagrees"));
    }

    #[test]
    fn permissionless_mining_supervisor_config_is_finite_and_bounded() {
        let mut config = QRunV06PermissionlessMiningSupervisorConfig::default();
        assert!(config.validate().is_ok());
        assert_eq!(config.max_sessions_per_listener_round, 1);
        config.max_sessions_per_listener_round = 6;
        assert!(config.validate().is_ok());
        config.max_sessions_per_listener_round = 0;
        assert_eq!(
            config.validate(),
            Err(QRunV06NodeSupervisorError::InvalidConfiguration)
        );
        config = QRunV06PermissionlessMiningSupervisorConfig::default();
        config.max_sessions_per_listener_round =
            crate::qrun_v06_peer_listener_candidate::QRUN_V06_LISTENER_MAX_SESSIONS + 1;
        assert_eq!(
            config.validate(),
            Err(QRunV06NodeSupervisorError::InvalidConfiguration)
        );
        config = QRunV06PermissionlessMiningSupervisorConfig::default();
        config.max_nonce_attempts_per_block = 0;
        assert_eq!(
            config.validate(),
            Err(QRunV06NodeSupervisorError::InvalidConfiguration)
        );
        config = QRunV06PermissionlessMiningSupervisorConfig::default();
        config.max_nonce_attempts_per_block = QRUN_V06_MAX_NONCE_ATTEMPTS_PER_JOB + 1;
        assert_eq!(
            config.validate(),
            Err(QRunV06NodeSupervisorError::InvalidConfiguration)
        );
        config = QRunV06PermissionlessMiningSupervisorConfig::default();
        config.listener_round_timeout = Duration::from_secs(31);
        assert_eq!(
            config.validate(),
            Err(QRunV06NodeSupervisorError::InvalidConfiguration)
        );
    }

    #[test]
    fn supervisor_q6ar_pinned_noise_listener_persists_only_under_bound_operator_policy() {
        use crate::{
            qrun_v06_bootstrap_trust_domain_candidate::BootstrapTrustDomainPolicy,
            qrun_v06_noise_transport_candidate::QRunV06NoiseSession,
            qrun_v06_peer_address_manager_candidate::QRunV06PeerAddressBookCandidate,
            qrun_v06_peer_address_relay_candidate::{encode_q6ar, Q6arAddress, Q6arAdvertisement},
        };

        const NETWORK: [u8; 32] = [0xC1; 32];
        const PROFILE: [u8; 32] = [0xC2; 32];
        const DOMAIN: [u8; 32] = [0xC3; 32];

        let temp_root = std::env::temp_dir().join(format!(
            "qfp6-cp0643-noise-q6ar-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&temp_root).unwrap();
        let store_path = temp_root.join("address-book.q6pa");

        let noise_params = "Noise_XX_25519_ChaChaPoly_SHA256".parse().unwrap();
        let server_pair = snow::Builder::new(noise_params).generate_keypair().unwrap();
        let client_pair = snow::Builder::new("Noise_XX_25519_ChaChaPoly_SHA256".parse().unwrap())
            .generate_keypair()
            .unwrap();
        let server_private: [u8; 32] = server_pair.private.as_slice().try_into().unwrap();
        let server_public: [u8; 32] = server_pair.public.as_slice().try_into().unwrap();
        let client_private: [u8; 32] = client_pair.private.as_slice().try_into().unwrap();
        let client_public: [u8; 32] = client_pair.public.as_slice().try_into().unwrap();

        // The exact static key pinned by the listener is the operator-registered relay key.
        let policy = BootstrapTrustDomainPolicy::new([(client_public, DOMAIN)], 8, 1).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_address = listener.local_addr().unwrap();
        let shutdown = AtomicBool::new(false);
        let relay_pins = [client_public];

        let server = thread::spawn(move || {
            let mut address_book =
                QRunV06PeerAddressBookCandidate::open(&store_path, NETWORK, PROFILE)
                    .map_err(|error| error.to_string())?;
            address_book
                .bind_trust_domain_registry(&policy, 0)
                .map_err(|error| error.to_string())?;

            let mut listener_config = QRunV06PeerListenerConfig::default();
            listener_config.max_sessions = 1;
            listener_config.max_requests_per_session = 2;
            let mut source_rate_limiter = QRunV06PeerSourceRateLimiter::new(Instant::now());

            let (report, process_stopped) = serve_qfp6_history_listener_round(
                &listener,
                listener_config,
                &server_private,
                &[],
                &NETWORK,
                &PROFILE,
                &shutdown,
                Duration::from_secs(2),
                &mut source_rate_limiter,
                &relay_pins,
                |received| {
                    if received.relay_origin.relay_static_key_pinned {
                        let now_ms = received.advertisement.issued_at_secs.saturating_mul(1_000);
                        persist_pinned_q6ar_with_operator_policy(
                            &mut address_book,
                            &policy,
                            &received,
                            now_ms,
                        )
                    } else {
                        Ok(())
                    }
                },
                |_peer_addr, _guard, _frame| {
                    Err("Q6AR must not reach the application transaction handler".into())
                },
            )
            .map_err(|error| error.to_string())?;

            let stored = address_book
                .records()
                .map(|record| {
                    (
                        record.address.clone(),
                        record.advertised_noise_static_key,
                        record.relay_static_public_key,
                        record.relay_static_key_pinned,
                    )
                })
                .collect::<Vec<_>>();
            drop(address_book);
            Ok::<_, String>((report, process_stopped, stored))
        });

        let mut stream = std::net::TcpStream::connect(listen_address).unwrap();
        stream.set_nodelay(true).unwrap();
        let mut noise = QRunV06NoiseSession::connect(
            &mut stream,
            &client_private,
            &server_public,
            &NETWORK,
            &PROFILE,
        )
        .unwrap();
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let frame = encode_q6ar(&Q6arAdvertisement {
            network_id: NETWORK,
            profile_id: PROFILE,
            issued_at_secs: now_secs,
            ttl_secs: 300,
            addresses: vec![Q6arAddress {
                endpoint: "8.8.8.8:8333".parse().unwrap(),
                noise_static_public_key: [0xC5; 32],
            }],
        })
        .unwrap();
        noise.write_record(&mut stream, &frame).unwrap();
        drop(stream);

        let (report, process_stopped, stored) = server.join().unwrap().unwrap();
        assert!(!process_stopped);
        assert_eq!(report.stats.q6ar_rejections, 0);
        assert_eq!(report.stats.handler_failures, 0);
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].0, "8.8.8.8:8333");
        assert_eq!(stored[0].1, Some([0xC5; 32]));
        assert_eq!(stored[0].2, Some(client_public));
        assert!(stored[0].3);

        let _ = std::fs::remove_dir_all(temp_root);
    }

    #[test]
    fn supervisor_q6ar_noise_listener_preserves_independent_domain_budgets() {
        use crate::{
            qrun_v06_bootstrap_trust_domain_candidate::BootstrapTrustDomainPolicy,
            qrun_v06_noise_transport_candidate::QRunV06NoiseSession,
            qrun_v06_peer_address_manager_candidate::QRunV06PeerAddressBookCandidate,
            qrun_v06_peer_address_relay_candidate::{encode_q6ar, Q6arAddress, Q6arAdvertisement},
        };
        use std::sync::{
            atomic::{AtomicUsize, Ordering as AtomicOrdering},
            Arc,
        };

        const NETWORK: [u8; 32] = [0xE1; 32];
        const PROFILE: [u8; 32] = [0xE2; 32];
        const DOMAIN_ONE: [u8; 32] = [0xE3; 32];
        const DOMAIN_TWO: [u8; 32] = [0xE4; 32];

        let temp_root = std::env::temp_dir().join(format!(
            "qfp6-cp0646-independent-domains-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&temp_root).unwrap();
        let store_path = temp_root.join("address-book.q6pa");

        let noise_params = "Noise_XX_25519_ChaChaPoly_SHA256".parse().unwrap();
        let server_pair = snow::Builder::new(noise_params).generate_keypair().unwrap();
        let client_one_pair =
            snow::Builder::new("Noise_XX_25519_ChaChaPoly_SHA256".parse().unwrap())
                .generate_keypair()
                .unwrap();
        let client_two_pair =
            snow::Builder::new("Noise_XX_25519_ChaChaPoly_SHA256".parse().unwrap())
                .generate_keypair()
                .unwrap();

        let server_private: [u8; 32] = server_pair.private.as_slice().try_into().unwrap();
        let server_public: [u8; 32] = server_pair.public.as_slice().try_into().unwrap();
        let client_one_private: [u8; 32] = client_one_pair.private.as_slice().try_into().unwrap();
        let client_one_public: [u8; 32] = client_one_pair.public.as_slice().try_into().unwrap();
        let client_two_private: [u8; 32] = client_two_pair.private.as_slice().try_into().unwrap();
        let client_two_public: [u8; 32] = client_two_pair.public.as_slice().try_into().unwrap();

        // Each relay is assigned to a different independently provisioned domain.
        let policy = BootstrapTrustDomainPolicy::new(
            [
                (client_one_public, DOMAIN_ONE),
                (client_two_public, DOMAIN_TWO),
            ],
            1,
            1,
        )
        .unwrap();
        let relay_pins = [client_one_public, client_two_public];

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_address = listener.local_addr().unwrap();
        let attempts = Arc::new(AtomicUsize::new(0));
        let accepted = Arc::new(AtomicUsize::new(0));
        let callback_errors = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let observed_relays = Arc::new(std::sync::Mutex::new(Vec::<([u8; 32], bool)>::new()));
        let server_attempts = attempts.clone();
        let server_accepted = accepted.clone();
        let server_errors = callback_errors.clone();
        let server_observed = observed_relays.clone();

        let server = thread::spawn(move || {
            let mut address_book =
                QRunV06PeerAddressBookCandidate::open(&store_path, NETWORK, PROFILE)
                    .map_err(|error| error.to_string())?;
            address_book
                .bind_trust_domain_registry(&policy, 0)
                .map_err(|error| error.to_string())?;

            let mut config = QRunV06PeerListenerConfig::default();
            config.max_sessions = 2;
            config.max_requests_per_session = 1;
            let mut source_rate_limiter = QRunV06PeerSourceRateLimiter::new(Instant::now());
            let shutdown = AtomicBool::new(false);
            let (report, process_stopped) = serve_qfp6_history_listener_round(
                &listener,
                config,
                &server_private,
                &[],
                &NETWORK,
                &PROFILE,
                &shutdown,
                Duration::from_secs(5),
                &mut source_rate_limiter,
                &relay_pins,
                |received| {
                    server_attempts.fetch_add(1, AtomicOrdering::AcqRel);
                    server_observed.lock().unwrap().push((
                        received.relay_origin.relay_static_public_key,
                        received.relay_origin.relay_static_key_pinned,
                    ));
                    if !received.relay_origin.relay_static_key_pinned {
                        return Ok(());
                    }
                    let now_ms = received.advertisement.issued_at_secs.saturating_mul(1_000);
                    match persist_pinned_q6ar_with_operator_policy(
                        &mut address_book,
                        &policy,
                        &received,
                        now_ms,
                    ) {
                        Ok(()) => {
                            server_accepted.fetch_add(1, AtomicOrdering::AcqRel);
                            Ok(())
                        }
                        Err(error) => {
                            server_errors.lock().unwrap().push(error.clone());
                            Err(error)
                        }
                    }
                },
                |_peer_addr, _guard, _frame| {
                    Err("Q6AR must not reach the application transaction handler".into())
                },
            )
            .map_err(|error| error.to_string())?;

            let stored = address_book
                .records()
                .map(|record| {
                    (
                        record.address.clone(),
                        record.relay_static_public_key,
                        record.relay_static_key_pinned,
                    )
                })
                .collect::<Vec<_>>();
            drop(address_book);
            Ok::<_, String>((
                report,
                process_stopped,
                stored,
                server_errors.lock().unwrap().clone(),
                server_observed.lock().unwrap().clone(),
            ))
        });

        let send_advertisement = |client_private: &[u8; 32], endpoint: &str, peer_key: [u8; 32]| {
            let mut stream = std::net::TcpStream::connect(listen_address).unwrap();
            stream.set_nodelay(true).unwrap();
            let mut noise = QRunV06NoiseSession::connect(
                &mut stream,
                client_private,
                &server_public,
                &NETWORK,
                &PROFILE,
            )
            .unwrap();
            let now_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let frame = encode_q6ar(&Q6arAdvertisement {
                network_id: NETWORK,
                profile_id: PROFILE,
                issued_at_secs: now_secs,
                ttl_secs: 300,
                addresses: vec![Q6arAddress {
                    endpoint: endpoint.parse().unwrap(),
                    noise_static_public_key: peer_key,
                }],
            })
            .unwrap();
            noise.write_record(&mut stream, &frame).unwrap();
            drop(stream);
        };

        send_advertisement(&client_one_private, "8.8.4.4:8333", [0xE5; 32]);
        for _ in 0..500 {
            if accepted.load(AtomicOrdering::Acquire) >= 1 {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(attempts.load(AtomicOrdering::Acquire), 1);
        assert_eq!(accepted.load(AtomicOrdering::Acquire), 1);

        // Domain two gets its own one-candidate allowance; domain one's use is irrelevant.
        send_advertisement(&client_two_private, "1.0.0.1:8333", [0xE6; 32]);
        for _ in 0..500 {
            if attempts.load(AtomicOrdering::Acquire) >= 2 {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(attempts.load(AtomicOrdering::Acquire), 2);

        let (report, process_stopped, stored, errors, observed) = server.join().unwrap().unwrap();
        assert_eq!(
            accepted.load(AtomicOrdering::Acquire),
            2,
            "both independent domains should admit one candidate; errors={errors:?}, observed={observed:?}, stats={:?}",
            report.stats
        );
        assert_eq!(
            observed,
            vec![(client_one_public, true), (client_two_public, true)]
        );
        assert!(errors.is_empty(), "unexpected ingestion errors: {errors:?}");
        assert!(!process_stopped);
        assert_eq!(report.stats.authenticated_sessions, 2);
        assert_eq!(report.stats.requests_received, 2);
        assert_eq!(report.stats.q6ar_rejections, 0);
        assert_eq!(report.stats.handler_failures, 0);
        assert_eq!(stored.len(), 2);
        assert!(stored
            .iter()
            .any(|row| { row.0 == "8.8.4.4:8333" && row.1 == Some(client_one_public) && row.2 }));
        assert!(stored
            .iter()
            .any(|row| { row.0 == "1.0.0.1:8333" && row.1 == Some(client_two_public) && row.2 }));
        let _ = std::fs::remove_dir_all(temp_root);
    }

    #[test]
    fn supervisor_q6ar_noise_listener_rejects_second_relay_in_same_operator_domain() {
        use crate::{
            qrun_v06_bootstrap_trust_domain_candidate::BootstrapTrustDomainPolicy,
            qrun_v06_noise_transport_candidate::QRunV06NoiseSession,
            qrun_v06_peer_address_manager_candidate::QRunV06PeerAddressBookCandidate,
            qrun_v06_peer_address_relay_candidate::{encode_q6ar, Q6arAddress, Q6arAdvertisement},
        };
        use std::sync::{
            atomic::{AtomicUsize, Ordering as AtomicOrdering},
            Arc,
        };

        const NETWORK: [u8; 32] = [0xD1; 32];
        const PROFILE: [u8; 32] = [0xD2; 32];
        const DOMAIN: [u8; 32] = [0xD3; 32];

        let temp_root = std::env::temp_dir().join(format!(
            "qfp6-cp0644-two-relay-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&temp_root).unwrap();
        let store_path = temp_root.join("address-book.q6pa");

        let noise_params = "Noise_XX_25519_ChaChaPoly_SHA256".parse().unwrap();
        let server_pair = snow::Builder::new(noise_params).generate_keypair().unwrap();
        let client_one_pair =
            snow::Builder::new("Noise_XX_25519_ChaChaPoly_SHA256".parse().unwrap())
                .generate_keypair()
                .unwrap();
        let client_two_pair =
            snow::Builder::new("Noise_XX_25519_ChaChaPoly_SHA256".parse().unwrap())
                .generate_keypair()
                .unwrap();

        let server_private: [u8; 32] = server_pair.private.as_slice().try_into().unwrap();
        let server_public: [u8; 32] = server_pair.public.as_slice().try_into().unwrap();
        let client_one_private: [u8; 32] = client_one_pair.private.as_slice().try_into().unwrap();
        let client_one_public: [u8; 32] = client_one_pair.public.as_slice().try_into().unwrap();
        let client_two_private: [u8; 32] = client_two_pair.private.as_slice().try_into().unwrap();
        let client_two_public: [u8; 32] = client_two_pair.public.as_slice().try_into().unwrap();

        let policy = BootstrapTrustDomainPolicy::new(
            [(client_one_public, DOMAIN), (client_two_public, DOMAIN)],
            1,
            2,
        )
        .unwrap();
        let relay_pins = [client_one_public, client_two_public];

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_address = listener.local_addr().unwrap();
        let attempts = Arc::new(AtomicUsize::new(0));
        let accepted = Arc::new(AtomicUsize::new(0));
        let server_attempts = attempts.clone();
        let server_accepted = accepted.clone();

        let server = thread::spawn(move || {
            let mut address_book =
                QRunV06PeerAddressBookCandidate::open(&store_path, NETWORK, PROFILE)
                    .map_err(|error| error.to_string())?;
            address_book
                .bind_trust_domain_registry(&policy, 0)
                .map_err(|error| error.to_string())?;

            let mut config = QRunV06PeerListenerConfig::default();
            config.max_sessions = 2;
            config.max_requests_per_session = 1;
            let mut source_rate_limiter = QRunV06PeerSourceRateLimiter::new(Instant::now());
            let shutdown = AtomicBool::new(false);
            let (report, process_stopped) = serve_qfp6_history_listener_round(
                &listener,
                config,
                &server_private,
                &[],
                &NETWORK,
                &PROFILE,
                &shutdown,
                Duration::from_secs(5),
                &mut source_rate_limiter,
                &relay_pins,
                |received| {
                    server_attempts.fetch_add(1, AtomicOrdering::AcqRel);
                    if !received.relay_origin.relay_static_key_pinned {
                        return Ok(());
                    }
                    let now_ms = received.advertisement.issued_at_secs.saturating_mul(1_000);
                    persist_pinned_q6ar_with_operator_policy(
                        &mut address_book,
                        &policy,
                        &received,
                        now_ms,
                    )?;
                    server_accepted.fetch_add(1, AtomicOrdering::AcqRel);
                    Ok(())
                },
                |_peer_addr, _guard, _frame| {
                    Err("Q6AR must not reach the application transaction handler".into())
                },
            )
            .map_err(|error| error.to_string())?;

            let stored = address_book
                .records()
                .map(|record| {
                    (
                        record.address.clone(),
                        record.relay_static_public_key,
                        record.relay_static_key_pinned,
                    )
                })
                .collect::<Vec<_>>();
            drop(address_book);
            Ok::<_, String>((report, process_stopped, stored))
        });

        let send_advertisement = |client_private: &[u8; 32], endpoint: &str, peer_key: [u8; 32]| {
            let mut stream = std::net::TcpStream::connect(listen_address).unwrap();
            stream.set_nodelay(true).unwrap();
            let mut noise = QRunV06NoiseSession::connect(
                &mut stream,
                client_private,
                &server_public,
                &NETWORK,
                &PROFILE,
            )
            .unwrap();
            let now_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let frame = encode_q6ar(&Q6arAdvertisement {
                network_id: NETWORK,
                profile_id: PROFILE,
                issued_at_secs: now_secs,
                ttl_secs: 300,
                addresses: vec![Q6arAddress {
                    endpoint: endpoint.parse().unwrap(),
                    noise_static_public_key: peer_key,
                }],
            })
            .unwrap();
            noise.write_record(&mut stream, &frame).unwrap();
            drop(stream);
        };

        send_advertisement(&client_one_private, "8.8.4.4:8333", [0xD4; 32]);
        for _ in 0..500 {
            if attempts.load(AtomicOrdering::Acquire) >= 1
                && accepted.load(AtomicOrdering::Acquire) >= 1
            {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(attempts.load(AtomicOrdering::Acquire), 1);
        assert_eq!(accepted.load(AtomicOrdering::Acquire), 1);

        send_advertisement(&client_two_private, "9.9.9.9:8333", [0xD5; 32]);
        for _ in 0..500 {
            if attempts.load(AtomicOrdering::Acquire) >= 2 {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(attempts.load(AtomicOrdering::Acquire), 2);

        let (report, process_stopped, stored) = server.join().unwrap().unwrap();
        assert!(!process_stopped);
        assert_eq!(report.stats.authenticated_sessions, 2);
        assert_eq!(report.stats.requests_received, 2);
        assert_eq!(report.stats.q6ar_rejections, 1);
        assert_eq!(report.stats.handler_failures, 0);
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].0, "8.8.4.4:8333");
        assert_eq!(stored[0].1, Some(client_one_public));
        assert!(stored[0].2);
        let _ = std::fs::remove_dir_all(temp_root);
    }

    #[test]
    fn supervisor_q6ar_callback_enforces_shared_operator_domain_candidate_quota() {
        use crate::{
            qrun_v06_bootstrap_trust_domain_candidate::BootstrapTrustDomainPolicy,
            qrun_v06_peer_address_manager_candidate::QRunV06PeerAddressBookCandidate,
            qrun_v06_peer_address_relay_candidate::{
                Q6arAddress, Q6arAdvertisement, Q6arReceivedAdvertisement, Q6arRelayOrigin,
            },
        };
        use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

        static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
        const NETWORK: [u8; 32] = [0xA1; 32];
        const PROFILE: [u8; 32] = [0xA2; 32];
        const DOMAIN: [u8; 32] = [0xA3; 32];
        const RELAY_ONE: [u8; 32] = [0xA4; 32];
        const RELAY_TWO: [u8; 32] = [0xA5; 32];

        let sequence = TEMP_SEQUENCE.fetch_add(1, AtomicOrdering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "qfp6-cp0642-supervisor-q6ar-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let store_path = root.join("address-book.q6pa");
        let policy =
            BootstrapTrustDomainPolicy::new([(RELAY_ONE, DOMAIN), (RELAY_TWO, DOMAIN)], 1, 2)
                .unwrap();
        let mut address_book =
            QRunV06PeerAddressBookCandidate::open(&store_path, NETWORK, PROFILE).unwrap();
        address_book
            .bind_trust_domain_registry(&policy, 100_000)
            .unwrap();

        let received = |relay_key: [u8; 32], peer_key: [u8; 32], endpoint: &str, issued_at_secs| {
            Q6arReceivedAdvertisement {
                advertisement: Q6arAdvertisement {
                    network_id: NETWORK,
                    profile_id: PROFILE,
                    issued_at_secs,
                    ttl_secs: 60,
                    addresses: vec![Q6arAddress {
                        endpoint: endpoint.parse().unwrap(),
                        noise_static_public_key: peer_key,
                    }],
                },
                relay_origin: Q6arRelayOrigin {
                    relay_static_public_key: relay_key,
                    relay_static_key_pinned: true,
                },
            }
        };

        let first = received(RELAY_ONE, [0xB1; 32], "8.8.8.8:8333", 100);
        persist_pinned_q6ar_with_operator_policy(&mut address_book, &policy, &first, 100_000)
            .unwrap();
        assert_eq!(address_book.records().count(), 1);

        // A second, distinct pinned relay in the same operator domain shares the same quota.
        let second = received(RELAY_TWO, [0xB2; 32], "1.1.1.1:8333", 101);
        assert!(persist_pinned_q6ar_with_operator_policy(
            &mut address_book,
            &policy,
            &second,
            101_000
        )
        .is_err());
        assert_eq!(address_book.records().count(), 1);
        assert!(address_book
            .records()
            .any(|record| record.address == "8.8.8.8:8333"));
        assert!(!address_book
            .records()
            .any(|record| record.address == "1.1.1.1:8333"));

        // A pinned but unregistered relay is rejected at the same runtime callback boundary.
        let unknown = received([0xA6; 32], [0xB3; 32], "9.9.9.9:8333", 102);
        assert!(persist_pinned_q6ar_with_operator_policy(
            &mut address_book,
            &policy,
            &unknown,
            102_000
        )
        .is_err());
        assert_eq!(address_book.records().count(), 1);

        drop(address_book);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn q6ti_pending_transfers_are_selected_for_mining_and_pruned_after_canonical_execution() {
        const NETWORK: [u8; 32] = [0x91; 32];
        const PROFILE: [u8; 32] = [0x92; 32];
        const PRODUCER: [u8; 32] = [0x93; 32];
        const RECIPIENT: [u8; 32] = [0x94; 32];

        let signer = QRunV06HybridTransactionSigner::from_seeds([0xA1; 32], [0xA2; 32]).unwrap();
        let mut params = ConsensusParameters::candidate_testnet().unwrap();
        params.protocol_version = 6;
        params.target_block_time_secs = 30;
        params.difficulty_window_blocks = 2;
        params.difficulty_min_ratio_divisor = 4;
        params.difficulty_max_ratio = 4;
        params.initial_target = Uint256::from_be_bytes([0x7F; 32]);
        params.pow_limit = Uint256::MAX;
        params.pow = PowParameters {
            algorithm: PowAlgorithm::Argon2id,
            memory_kib: 8,
            iterations: 1,
            lanes: 1,
            output_bytes: 32,
        };
        params.validate().unwrap();

        let schedule = QRunV06MiningScheduleCandidate::cp0422_research_candidate();
        let economics =
            QRunV06TokenomicsState::genesis(NETWORK, signer.account_id(), schedule).unwrap();
        let descriptor = QRunV06GenesisDescriptor::new(
            NETWORK,
            PROFILE,
            signer.account_id(),
            1,
            crate::qrun_v06_checkpoint_candidate::qrun_v06_consensus_fingerprint(&params).unwrap(),
            economics.policy_fingerprint(),
        )
        .unwrap();
        let mut state = QRunV06CanonicalExecutionState::cp0528_genesis_candidate_with_descriptor(
            descriptor, schedule,
        )
        .unwrap();
        let authenticator =
            QRunV06HybridTransactionAuthenticator::new(LibcruxMlDsa65VerifierCandidate);
        let mut transaction = Transaction {
            network_id: NETWORK,
            sender: signer.account_id(),
            recipient: RECIPIENT,
            nonce: 1,
            amount: 10_000,
            fee: 10,
            expires_at: 10_000,
            signature: Vec::new(),
        };
        signer.sign_transaction(&mut transaction).unwrap();

        let mut mempool =
            QRunV06NativeTransactionMempool::new(QRunV06MempoolLimits::default()).unwrap();
        let first_timestamp = state.last_timestamp() + 60;
        mempool
            .submit(
                transaction.clone(),
                &state,
                &authenticator,
                PRODUCER,
                first_timestamp,
            )
            .unwrap();

        let mut operations = Vec::new();
        assert_eq!(
            append_pending_mempool_transfers(
                &mut mempool,
                &state,
                &authenticator,
                PRODUCER,
                first_timestamp,
                &mut operations,
            )
            .unwrap(),
            1
        );
        assert!(matches!(
            operations.as_slice(),
            [QRunV06BlockOperation::NativeTransfer(_)]
        ));

        let block = mempool
            .build_block(&state, &authenticator, PRODUCER, first_timestamp)
            .unwrap();
        state.apply_block(&block, &authenticator).unwrap();

        let mut next_operations = Vec::new();
        assert_eq!(
            append_pending_mempool_transfers(
                &mut mempool,
                &state,
                &authenticator,
                PRODUCER,
                state.last_timestamp() + 60,
                &mut next_operations,
            )
            .unwrap(),
            0
        );
        assert!(next_operations.is_empty());
        assert!(mempool.is_empty());
    }

    #[test]
    fn cp0604_permissionless_supervisor_mines_and_recovers_durable_genesis_state() {
        use crate::{
            consensus::{ConsensusParameters, Uint256},
            external_cas_anchor_candidate::ExternalCasPin,
            qrun_v06_checkpoint_candidate::qrun_v06_consensus_fingerprint,
            qrun_v06_cp0604_supply_candidate::Cp0604FounderControlledSupply,
            qrun_v06_genesis_descriptor_candidate::QRunV06GenesisDescriptor,
            qrun_v06_permissionless_runtime_candidate::QRunV06PermissionlessNodeRuntime,
            qrun_v06_permissionless_service_candidate::QRunV06PermissionlessMempool,
            qrun_v06_profile_pin_candidate::{
                QRunV06ProfilePinCandidate, QRunV06VerifiedProfilePin,
            },
            qrun_v06_tokenomics_candidate::QRunV06MiningScheduleCandidate,
            qrun_v06_transaction_mempool_candidate::QRunV06MempoolLimits,
            v4_fat1_trust_candidate::ML_DSA_65_PUBLIC_KEY_BYTES,
        };
        use std::sync::Arc;

        const NETWORK: [u8; 32] = [0xB1; 32];
        const PROFILE: [u8; 32] = [0xB2; 32];
        const FOUNDER: [u8; 32] = [0xB3; 32];
        let mut params = ConsensusParameters::qrun_v06_sha256d_candidate().unwrap();
        params.target_block_time_secs = 30;
        params.difficulty_window_blocks = 2;
        params.difficulty_min_ratio_divisor = 4;
        params.difficulty_max_ratio = 4;
        params.initial_target = Uint256::from_be_bytes([0x7F; 32]);
        params.pow_limit = Uint256::MAX;
        params.validate().unwrap();

        let schedule = QRunV06MiningScheduleCandidate::cp0422_research_candidate();
        let supply = Cp0604FounderControlledSupply::genesis(NETWORK, FOUNDER, schedule).unwrap();
        let descriptor = QRunV06GenesisDescriptor::new(
            NETWORK,
            PROFILE,
            FOUNDER,
            1,
            qrun_v06_consensus_fingerprint(&params).unwrap(),
            supply.policy_fingerprint(),
        )
        .unwrap();
        let genesis = crate::qrun_v06_canonical_execution_candidate::QRunV06CanonicalExecutionState::
            cp0604_genesis_candidate_with_descriptor(descriptor.clone(), schedule).unwrap();
        let bundle = QRunV06ProfilePinCandidate::new(
            descriptor,
            ExternalCasPin {
                provider_id: [0xC1; 32],
                network_id: NETWORK,
                genesis_digest: [0xC2; 32],
                receipt_key_id: [0xC3; 32],
                receipt_public_key: [0xC4; ML_DSA_65_PUBLIC_KEY_BYTES],
            },
        )
        .unwrap();
        let pin_bytes = bundle.encode().unwrap();
        let pin_commitment = bundle.commitment().unwrap();
        let verified_pin = QRunV06VerifiedProfilePin::decode(&pin_bytes, pin_commitment).unwrap();

        let store_dir = std::env::temp_dir().join(format!(
            "qfp6-cp0604-supervisor-store-{}",
            std::process::id()
        ));
        let mempool_dir = store_dir.with_extension("mempool");
        let _ = std::fs::remove_dir_all(&store_dir);
        let _ = std::fs::remove_dir_all(&mempool_dir);
        let authenticator =
            QRunV06HybridTransactionAuthenticator::new(LibcruxMlDsa65VerifierCandidate);
        let mut runtime = QRunV06PermissionlessNodeRuntime::open(
            &store_dir,
            genesis.clone(),
            params.clone(),
            &authenticator,
            None,
            &verified_pin,
        )
        .unwrap();
        let mut mempool =
            QRunV06PermissionlessMempool::open(&mempool_dir, QRunV06MempoolLimits::default())
                .unwrap();

        let noise_params = "Noise_XX_25519_ChaChaPoly_SHA256".parse().unwrap();
        let local_pair = snow::Builder::new(noise_params).generate_keypair().unwrap();
        let remote_pair = snow::Builder::new("Noise_XX_25519_ChaChaPoly_SHA256".parse().unwrap())
            .generate_keypair()
            .unwrap();
        let mut local_private = [0u8; 32];
        let mut remote_public = [0u8; 32];
        local_private.copy_from_slice(&local_pair.private);
        remote_public.copy_from_slice(&remote_pair.public);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let signal = shutdown.clone();
        let stopper = std::thread::spawn(move || {
            // Allow runtime + Q6MJ/Q6MM startup and at least one bounded mining pass
            // on slower CI/workstations; the previous 180 ms cutoff raced node startup.
            std::thread::sleep(Duration::from_millis(1_500));
            signal.store(true, Ordering::Release);
        });
        let mut config = QRunV06PermissionlessMiningSupervisorConfig::default();
        config.peer.install_os_signal_handler = false;
        config.peer.max_total_sessions = 8;
        config.listener_round_timeout = Duration::from_millis(20);
        config.max_nonce_attempts_per_block = QRUN_V06_MAX_NONCE_ATTEMPTS_PER_JOB;

        let report = run_qfp6_permissionless_mining_supervisor(
            &listener,
            config,
            &local_private,
            &[remote_public],
            &NETWORK,
            &PROFILE,
            shutdown.as_ref(),
            &mut runtime,
            &authenticator,
            FOUNDER,
            &mut mempool,
        )
        .unwrap();
        stopper.join().unwrap();
        local_private.fill(0);
        let committed = runtime.status().unwrap();
        assert_eq!(
            report.stop_reason,
            QRunV06NodeSupervisorStopReason::ShutdownRequested
        );
        assert!(report.blocks_durably_committed >= 1);
        assert!(report.blocks_became_canonical >= 1);
        assert!(report.ending_height >= 1);
        assert_eq!(committed.height, report.ending_height);
        assert_eq!(committed.network_id, NETWORK);
        assert_eq!(committed.profile_id, PROFILE);
        let trusted_manifest_anchor = committed.manifest_anchor;
        let committed_root = committed.state_root;
        drop(runtime);
        drop(mempool);

        let recovered = QRunV06PermissionlessNodeRuntime::open(
            &store_dir,
            genesis,
            params,
            &authenticator,
            Some(trusted_manifest_anchor),
            &verified_pin,
        )
        .unwrap();
        let recovered_status = recovered.status().unwrap();
        assert_eq!(recovered_status.height, committed.height);
        assert_eq!(recovered_status.tip, committed.tip);
        assert_eq!(recovered_status.state_root, committed_root);
        assert_eq!(
            recovered_status.manifest_generation,
            committed.manifest_generation
        );
        drop(recovered);
        std::fs::remove_dir_all(store_dir).unwrap();
        std::fs::remove_dir_all(mempool_dir).unwrap();
    }
    #[test]
    fn supervisor_requires_the_recovery_coordinator_provider_and_genesis_pins_to_match() {
        let state = QRunV06ExternalAnchorState {
            network_id: [3; 32],
            genesis_digest: [4; 32],
            genesis_descriptor_commitment: [5; 32],
            profile_id: [6; 32],
            consensus_fingerprint: [7; 32],
            segment_base_height: 0,
            segment_base_tip: [8; 32],
            checkpoint_anchor: [0; 32],
            manifest_generation: 0,
            manifest_anchor: [9; 32],
            canonical_height: 0,
            canonical_tip: [8; 32],
            canonical_state_root: [10; 32],
            cumulative_chainwork: [0; 32],
        };
        let provider_pin = ExternalCasPin {
            provider_id: [11; 32],
            network_id: state.network_id,
            genesis_digest: state.genesis_digest,
            receipt_key_id: [12; 32],
            receipt_public_key: [13; ML_DSA_65_PUBLIC_KEY_BYTES],
        };
        let qfp6_pin = QRunV06ExternalAnchorPin::new(
            provider_pin.clone(),
            state.genesis_descriptor_commitment,
        )
        .unwrap();

        assert!(validate_qap1_pin_bindings(&state, &provider_pin, &qfp6_pin).is_ok());

        let mut wrong_provider = provider_pin.clone();
        wrong_provider.network_id = [14; 32];
        assert_eq!(
            validate_qap1_pin_bindings(&state, &wrong_provider, &qfp6_pin),
            Err(QRunV06NodeSupervisorError::CoordinatorPinMismatch)
        );

        let wrong_descriptor_pin =
            QRunV06ExternalAnchorPin::new(provider_pin.clone(), [15; 32]).unwrap();
        assert_eq!(
            validate_qap1_pin_bindings(&state, &provider_pin, &wrong_descriptor_pin),
            Err(QRunV06NodeSupervisorError::CoordinatorPinMismatch)
        );
    }

    #[test]
    fn mining_supervisor_config_requires_finite_listener_and_mining_windows() {
        let mut config = QRunV06MiningSupervisorConfig::default();
        assert!(config.validate().is_ok());
        assert_eq!(config.mining.max_blocks_per_run, 1);
        config.listener_round_timeout = Duration::from_millis(1);
        assert_eq!(
            config.validate(),
            Err(QRunV06NodeSupervisorError::InvalidConfiguration)
        );
        config = QRunV06MiningSupervisorConfig::default();
        config.mining.max_blocks_per_run = 0;
        assert!(matches!(
            config.validate(),
            Err(QRunV06NodeSupervisorError::Mining(_))
        ));
    }

    #[test]
    fn listener_round_returns_after_idle_deadline_without_global_shutdown() {
        let params = "Noise_XX_25519_ChaChaPoly_SHA256".parse().unwrap();
        let pair = snow::Builder::new(params).generate_keypair().unwrap();
        let mut private = [0u8; 32];
        let mut public = [0u8; 32];
        private.copy_from_slice(&pair.private);
        public.copy_from_slice(&pair.public);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let shutdown = AtomicBool::new(false);
        let started = Instant::now();
        let mut source_rate_limiter = QRunV06PeerSourceRateLimiter::new(Instant::now());
        let mut handler = |_guard: &mut QRunV06PeerReplayGuard, _frame: &[u8]| {
            Err("no connection should reach the frame callback".to_string())
        };
        let (report, process_stopped) = serve_qfp6_listener_round(
            &listener,
            QRunV06PeerListenerConfig {
                max_sessions: 1,
                max_requests_per_session: 1,
                max_failed_handshakes: 1,
                accept_poll_interval: Duration::from_millis(10),
            },
            &private,
            &[public],
            &[0xA1; 32],
            &[0xA2; 32],
            &shutdown,
            Duration::from_millis(80),
            &mut source_rate_limiter,
            &mut handler,
        )
        .unwrap();
        assert!(!process_stopped);
        assert!(!shutdown.load(Ordering::Acquire));
        assert_eq!(
            report.stop_reason,
            QRunV06PeerListenerStopReason::ShutdownRequested
        );
        assert_eq!(report.stats.accepted_connections, 0);
        assert!(started.elapsed() >= Duration::from_millis(70));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn supervisor_default_config_is_bounded_and_valid() {
        let config = QRunV06NodeSupervisorConfig::default();
        assert!(config.validate().is_ok());
        assert_eq!(
            config.max_total_sessions,
            QRUN_V06_SUPERVISOR_MAX_TOTAL_SESSIONS
        );
        assert!(config.install_os_signal_handler);
    }

    #[test]
    fn pinned_bootstrap_peer_validation_rejects_empty_duplicate_and_zero_keys() {
        assert_eq!(
            validate_qfp6_pinned_bootstrap_peers(&[]),
            Err(QRunV06NodeSupervisorError::InvalidBootstrapPeers)
        );
        let first = QRunV06PinnedBootstrapPeer {
            address: "127.0.0.1:30333".parse().unwrap(),
            noise_static_public_key: [0x31; 32],
            tls_server_name: None,
        };
        assert_eq!(
            validate_qfp6_pinned_bootstrap_peers(std::slice::from_ref(&first)),
            Ok(vec![[0x31; 32]])
        );
        let relay = QRunV06PinnedBootstrapPeer {
            address: "1.1.1.1:443".parse().unwrap(),
            noise_static_public_key: [0x32; 32],
            tls_server_name: Some("seed.tailnet.ts.net".to_owned()),
        };
        assert_eq!(
            validate_qfp6_pinned_bootstrap_peers(std::slice::from_ref(&relay)),
            Ok(vec![[0x32; 32]])
        );
        let invalid_relay = QRunV06PinnedBootstrapPeer {
            tls_server_name: Some("seed..tailnet.ts.net".to_owned()),
            ..relay.clone()
        };
        assert_eq!(
            validate_qfp6_pinned_bootstrap_peers(&[invalid_relay]),
            Err(QRunV06NodeSupervisorError::InvalidBootstrapPeers)
        );
        let relay_wrong_port = QRunV06PinnedBootstrapPeer {
            address: "1.1.1.1:30333".parse().unwrap(),
            ..relay
        };
        assert_eq!(
            validate_qfp6_pinned_bootstrap_peers(&[relay_wrong_port]),
            Err(QRunV06NodeSupervisorError::InvalidBootstrapPeers)
        );
        assert_eq!(
            validate_qfp6_pinned_bootstrap_peers(&[first.clone(), first.clone()]),
            Err(QRunV06NodeSupervisorError::InvalidBootstrapPeers)
        );
        let zero_key = QRunV06PinnedBootstrapPeer {
            noise_static_public_key: [0; 32],
            ..first.clone()
        };
        assert_eq!(
            validate_qfp6_pinned_bootstrap_peers(&[zero_key]),
            Err(QRunV06NodeSupervisorError::InvalidBootstrapPeers)
        );
    }

    #[test]
    fn supervisor_rejects_zero_or_unbounded_process_session_budgets() {
        let mut config = QRunV06NodeSupervisorConfig::default();
        config.max_total_sessions = 0;
        assert_eq!(
            config.validate(),
            Err(QRunV06NodeSupervisorError::InvalidConfiguration)
        );
        config.max_total_sessions = QRUN_V06_SUPERVISOR_MAX_TOTAL_SESSIONS + 1;
        assert_eq!(
            config.validate(),
            Err(QRunV06NodeSupervisorError::InvalidConfiguration)
        );
    }

    #[test]
    fn supervisor_statistics_use_checked_addition() {
        let mut total = QRunV06PeerListenerStats {
            accepted_connections: usize::MAX,
            ..Default::default()
        };
        assert_eq!(
            add_stats(
                &mut total,
                QRunV06PeerListenerStats {
                    accepted_connections: 1,
                    ..Default::default()
                }
            ),
            Err(QRunV06NodeSupervisorError::StatisticsOverflow)
        );
    }

    #[test]
    fn supervisor_requires_both_qap1_admission_and_verified_restart_recovery() {
        assert_eq!(
            validate_qap1_lifecycle(false, false),
            Err(QRunV06NodeSupervisorError::RuntimeNotQap1Recovered)
        );
        assert_eq!(
            validate_qap1_lifecycle(true, false),
            Err(QRunV06NodeSupervisorError::RuntimeNotQap1Recovered)
        );
        assert!(validate_qap1_lifecycle(true, true).is_ok());
    }

    #[test]
    fn supervisor_startup_rejects_zero_identity_material() {
        assert_eq!(
            validate_identity_material(&[0; 32], &[1; 32], &[2; 32]),
            Err(QRunV06NodeSupervisorError::InvalidIdentity)
        );
        assert_eq!(
            validate_identity_material(&[1; 32], &[0; 32], &[2; 32]),
            Err(QRunV06NodeSupervisorError::InvalidIdentity)
        );
        assert_eq!(
            validate_identity_material(&[1; 32], &[2; 32], &[0; 32]),
            Err(QRunV06NodeSupervisorError::InvalidIdentity)
        );
        assert!(validate_identity_material(&[1; 32], &[2; 32], &[3; 32]).is_ok());
    }

    #[test]
    fn supervisor_statistics_keep_pinned_and_unverified_peer_counts_separate() {
        let mut total = QRunV06PeerListenerStats::default();
        add_stats(
            &mut total,
            QRunV06PeerListenerStats {
                authenticated_sessions: 2,
                unverified_peer_sessions: 3,
                accepted_connections: 5,
                handshake_queue_rejections: 7,
                cancelled_handshakes: 2,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(total.authenticated_sessions, 2);
        assert_eq!(total.unverified_peer_sessions, 3);
        assert_eq!(total.accepted_connections, 5);
        assert_eq!(total.handshake_queue_rejections, 7);
        assert_eq!(total.cancelled_handshakes, 2);
    }
}
