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
//! production launcher, RPC server, peer-discovery service, full-history sync daemon or Mainnet.

use crate::{
    external_cas_anchor_candidate::{ExternalCasPin, ExternalCasProviderTransport},
    qrun_node_shutdown_signal_candidate::QRunNodeShutdownSignalCandidate,
    qrun_v06_canonical_execution_candidate::{
        QRunV06BlockOperation, QRunV06CanonicalExecutionState, MAX_QRUN_V06_BLOCK_OPERATIONS,
    },
    qrun_v06_external_anchor_candidate::{QRunV06ExternalAnchorPin, QRunV06ExternalAnchorState},
    qrun_v06_miner_candidate::QRUN_V06_MAX_NONCE_ATTEMPTS_PER_JOB,
    qrun_v06_node_runtime_candidate::{
        QRunV06NodeAnchorGate, QRunV06NodeRuntime, QRunV06PeerReplayGuard,
    },
    qrun_v06_peer_listener_candidate::{
        process_qfp6_peer_frame_with_permissionless_runtime, process_qfp6_peer_frame_with_qap1,
        serve_qfp6_noise_listener, QRunV06PeerListenerConfig, QRunV06PeerListenerError,
        QRunV06PeerListenerStats, QRunV06PeerListenerStopReason,
    },
    qrun_v06_permissionless_runtime_candidate::QRunV06PermissionlessNodeRuntime,
    qrun_v06_permissionless_service_candidate::{
        QRunV06PermissionlessMempool, QRunV06PermissionlessServiceError,
    },
    qrun_v06_pow_fork_choice_candidate::QRunV06QuoteAssetAuthorizationProvider,
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
    net::TcpListener,
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const QRUN_V06_SUPERVISOR_MAX_TOTAL_SESSIONS: usize = 1_000_000;
const SHUTDOWN_WATCH_INTERVAL: Duration = Duration::from_millis(10);

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
    pub max_nonce_attempts_per_block: u64,
}

impl Default for QRunV06PermissionlessMiningSupervisorConfig {
    fn default() -> Self {
        Self {
            peer: QRunV06NodeSupervisorConfig::default(),
            listener_round_timeout: Duration::from_millis(250),
            max_nonce_attempts_per_block: QRUN_V06_MAX_NONCE_ATTEMPTS_PER_JOB,
        }
    }
}

impl QRunV06PermissionlessMiningSupervisorConfig {
    pub fn validate(&self) -> Result<(), QRunV06NodeSupervisorError> {
        self.peer.validate()?;
        if !(Duration::from_millis(20)..=Duration::from_secs(30))
            .contains(&self.listener_round_timeout)
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
    add_counter(&mut total.rejected_handshakes, next.rejected_handshakes)?;
    add_counter(&mut total.requests_received, next.requests_received)?;
    add_counter(&mut total.responses_written, next.responses_written)?;
    add_counter(&mut total.handler_failures, next.handler_failures)?;
    add_counter(&mut total.malformed_responses, next.malformed_responses)?;
    add_counter(&mut total.sessions_closed, next.sessions_closed)?;
    Ok(())
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
            let mut rounds = 0u64;

            let stop_reason = loop {
                if shutdown_requested.load(Ordering::Acquire) {
                    break QRunV06NodeSupervisorStopReason::ShutdownRequested;
                }
                if aggregate.accepted_connections >= config.max_total_sessions {
                    break QRunV06NodeSupervisorStopReason::SessionBudgetReached;
                }
                if runtime.requires_reopen() || runtime.has_pending_external_anchor() {
                    return Err(QRunV06NodeSupervisorError::RuntimePoisoned);
                }

                let remaining = config
                    .max_total_sessions
                    .checked_sub(aggregate.accepted_connections)
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

                let report = serve_qfp6_noise_listener(
                    listener,
                    round_config,
                    local_static_private_key,
                    trusted_remote_static_public_keys,
                    network_id,
                    profile_id,
                    shutdown_requested,
                    &mut on_q6pb,
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
                        if aggregate.accepted_connections >= config.max_total_sessions {
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

        let report = serve_qfp6_noise_listener(
            listener,
            config,
            local_static_private_key,
            trusted_remote_static_public_keys,
            network_id,
            profile_id,
            &round_shutdown,
            on_q6pb,
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
            let mut listener_rounds = 0u64;
            let mut mining_rounds = 0u64;
            let mut blocks_acknowledged = 0u64;
            let stop_reason;

            loop {
                if shutdown_requested.load(Ordering::Acquire) {
                    stop_reason = QRunV06NodeSupervisorStopReason::ShutdownRequested;
                    break;
                }
                if aggregate.accepted_connections >= config.peer.max_total_sessions {
                    stop_reason = QRunV06NodeSupervisorStopReason::SessionBudgetReached;
                    break;
                }
                if runtime.requires_reopen() || runtime.has_pending_external_anchor() {
                    return Err(QRunV06NodeSupervisorError::RuntimePoisoned);
                }

                let remaining = config
                    .peer
                    .max_total_sessions
                    .checked_sub(aggregate.accepted_connections)
                    .ok_or(QRunV06NodeSupervisorError::StatisticsOverflow)?;
                let mut round_config = config.peer.listener;
                // One accepted connection per round gives the miner a bounded scheduling point.
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

/// Dispatch Q6TI or Q6PB inside an already authenticated Noise session for the permissionless
/// runtime. Q6TA Accepted means the transaction is validated and durably journaled as pending;
/// Q6PA Accepted means a local durable block commit. Neither response means global finality.
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
    if frame.get(..4) == Some(&Q6TI_MAGIC) {
        let graph = runtime
            .fork_choice_snapshot()
            .map_err(|error| format!("cannot snapshot permissionless state for Q6TI: {error}"))?;
        let candidate_timestamp = current_candidate_timestamp(graph.canonical_state())?;
        let response = mempool
            .submit_q6ti(
                runtime,
                replay_guard,
                frame,
                authenticator,
                producer,
                candidate_timestamp,
            )
            .map_err(|error: QRunV06PermissionlessServiceError| error.to_string())?;
        return response
            .try_into()
            .map_err(|_| "Q6TA response did not have the fixed 128-byte wire length".to_string());
    }

    let response = process_qfp6_peer_frame_with_permissionless_runtime(
        runtime,
        replay_guard,
        frame,
        authenticator,
    )?;
    let graph = runtime.fork_choice_snapshot().map_err(|error| {
        format!("cannot refresh permissionless canonical state after Q6PB: {error}")
    })?;
    let candidate_timestamp = current_candidate_timestamp(graph.canonical_state())?;
    mempool
        .reconcile_after_canonical_change(runtime, authenticator, producer, candidate_timestamp)
        .map_err(|error| error.to_string())?;
    Ok(response)
}

/// Run the authenticated QFP6 Noise listener and permissionless durable miner in alternating,
/// bounded windows. The runtime must already be opened from complete Genesis-rooted history with
/// an independently verified profile pin. This does not perform peer discovery or history sync.
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
    config.validate()?;
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
        .restore(runtime, authenticator, producer, startup_timestamp)
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
            let mut listener_rounds = 0u64;
            let mut mining_rounds = 0u64;
            let mut blocks_durably_committed = 0u64;
            let mut blocks_became_canonical = 0u64;
            let stop_reason;

            loop {
                if shutdown_requested.load(Ordering::Acquire) {
                    stop_reason = QRunV06NodeSupervisorStopReason::ShutdownRequested;
                    break;
                }
                if aggregate.accepted_connections >= config.peer.max_total_sessions {
                    stop_reason = QRunV06NodeSupervisorStopReason::SessionBudgetReached;
                    break;
                }
                let remaining = config
                    .peer
                    .max_total_sessions
                    .checked_sub(aggregate.accepted_connections)
                    .ok_or(QRunV06NodeSupervisorError::StatisticsOverflow)?;
                let mut round_config = config.peer.listener;
                round_config.max_sessions = round_config.max_sessions.min(remaining).min(1);
                let mut on_application_frame =
                    |guard: &mut QRunV06PeerReplayGuard, frame: &[u8]| {
                        process_qfp6_application_frame_with_permissionless_runtime(
                            runtime,
                            guard,
                            mempool,
                            frame,
                            authenticator,
                            producer,
                        )
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
                    &mut on_application_frame,
                )?;
                listener_rounds = listener_rounds
                    .checked_add(1)
                    .ok_or(QRunV06NodeSupervisorError::StatisticsOverflow)?;
                add_stats(&mut aggregate, listener_report.stats)?;
                if listener_report.stop_reason
                    == QRunV06PeerListenerStopReason::FailedHandshakeLimitReached
                {
                    return Err(QRunV06NodeSupervisorError::HandshakeBudgetExceeded);
                }
                if listener_report.stats.handler_failures > 0
                    || listener_report.stats.malformed_responses > 0
                {
                    return Err(QRunV06NodeSupervisorError::Listener(
                        "permissionless application handler failed; supervisor stops before mining"
                            .into(),
                    ));
                }
                if process_stopped || shutdown_requested.load(Ordering::Acquire) {
                    stop_reason = QRunV06NodeSupervisorStopReason::ShutdownRequested;
                    break;
                }

                let graph = runtime
                    .fork_choice_snapshot()
                    .map_err(|error| QRunV06NodeSupervisorError::Runtime(error.to_string()))?;
                let candidate_timestamp = current_candidate_timestamp(graph.canonical_state())
                    .map_err(QRunV06NodeSupervisorError::Mining)?;
                let mined = match mempool.mine_one_batch(
                    runtime,
                    authenticator,
                    producer,
                    candidate_timestamp,
                    config.max_nonce_attempts_per_block,
                    shutdown_requested,
                ) {
                    Ok(mined) => mined,
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

#[cfg(test)]
mod tests {
    use super::*;
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
    fn permissionless_mining_supervisor_config_is_finite_and_bounded() {
        let mut config = QRunV06PermissionlessMiningSupervisorConfig::default();
        assert!(config.validate().is_ok());
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
}
