//! CP-0568 supervised QFP6 peer-service lifecycle candidate.
//!
//! Joins the existing QAP1 admission coordinator, authenticated QFP6 Noise listener and
//! process-shutdown signal bridge. It accepts an already-opened, QAP1-recovered runtime and
//! already-provisioned cryptographic dependencies; it never generates keys, bootstraps Genesis,
//! invents trust pins or provisions a cloud service.
//!
//! Startup fails closed unless the runtime is QAP1-required, matches the supplied network/profile,
//! has no unresolved anchor transition and does not require recovery. Only loopback/private/LAN/
//! overlay binding remains accepted by the underlying listener. The service is serial (one peer at
//! a time) and bounded by a total accepted-connection budget. It is not yet a miner, RPC server,
//! peer-discovery service, full-history sync daemon or public Mainnet binary.

use crate::{
    external_cas_anchor_candidate::ExternalCasProviderTransport,
    qrun_node_shutdown_signal_candidate::QRunNodeShutdownSignalCandidate,
    qrun_v06_node_runtime_candidate::{
        QRunV06NodeAnchorGate, QRunV06NodeRuntime, QRunV06PeerReplayGuard,
    },
    qrun_v06_peer_listener_candidate::{
        process_qfp6_peer_frame_with_qap1, serve_qfp6_noise_listener, QRunV06PeerListenerConfig,
        QRunV06PeerListenerError, QRunV06PeerListenerStats, QRunV06PeerListenerStopReason,
    },
    qrun_v06_pow_fork_choice_candidate::QRunV06QuoteAssetAuthorizationProvider,
    qrun_v06_qap1_coordinator_candidate::{
        QRunV06Qap1AnchorTransport, QRunV06Qap1ExternalCoordinator,
    },
    state_machine::TransactionAuthenticator,
    v4_fat1_trust_candidate::MlDsa65Verifier,
};
use std::{
    net::TcpListener,
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::Duration,
};

pub const QRUN_V06_SUPERVISOR_MAX_TOTAL_SESSIONS: usize = 1_000_000;
const SHUTDOWN_WATCH_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QRunV06NodeSupervisorConfig {
    /// Per-listener-round cap. The supervisor re-enters the listener after a full round.
    pub listener: QRunV06PeerListenerConfig,
    /// Hard process-lifetime cap on accepted TCP connections, including failed handshakes.
    pub max_total_sessions: usize,
}

impl Default for QRunV06NodeSupervisorConfig {
    fn default() -> Self {
        Self {
            listener: QRunV06PeerListenerConfig::default(),
            max_total_sessions: QRUN_V06_SUPERVISOR_MAX_TOTAL_SESSIONS,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QRunV06NodeSupervisorError {
    InvalidConfiguration,
    InvalidIdentity,
    RuntimeNotQap1Recovered,
    RuntimeRequiresRecovery,
    PendingAnchorTransition,
    NetworkMismatch,
    ProfileMismatch,
    Listener(String),
    HandshakeBudgetExceeded,
    StatisticsOverflow,
    ShutdownSignal(String),
    ShutdownWatcherPanicked,
    RuntimePoisoned,
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
    if trusted_remote_static_public_keys.is_empty()
        || trusted_remote_static_public_keys.len() > 64
        || trusted_remote_static_public_keys
            .iter()
            .any(|key| key.iter().all(|byte| *byte == 0))
    {
        return Err(QRunV06NodeSupervisorError::InvalidIdentity);
    }

    let signal = QRunNodeShutdownSignalCandidate::install()
        .map_err(|error| QRunV06NodeSupervisorError::ShutdownSignal(error.to_string()))?;
    let shutdown = AtomicBool::new(false);
    let watcher_stop = AtomicBool::new(false);

    let run_result = thread::scope(|scope| {
        let watcher = scope.spawn(|| {
            while !watcher_stop.load(Ordering::Acquire) {
                if signal.is_shutdown_requested() {
                    shutdown.store(true, Ordering::Release);
                    break;
                }
                thread::sleep(SHUTDOWN_WATCH_INTERVAL);
            }
        });

        let service_result = (|| {
            let mut aggregate = QRunV06PeerListenerStats::default();
            let mut rounds = 0u64;

            let stop_reason = loop {
                if shutdown.load(Ordering::Acquire) {
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
                        shutdown.store(true, Ordering::Release);
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
                        shutdown.store(true, Ordering::Release);
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
                    &shutdown,
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

    let uninstall_result = signal
        .uninstall()
        .map_err(|error| QRunV06NodeSupervisorError::ShutdownSignal(error.to_string()));

    match (run_result, uninstall_result) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Ok(report), Ok(())) => Ok(report),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supervisor_default_config_is_bounded_and_valid() {
        let config = QRunV06NodeSupervisorConfig::default();
        assert!(config.validate().is_ok());
        assert_eq!(
            config.max_total_sessions,
            QRUN_V06_SUPERVISOR_MAX_TOTAL_SESSIONS
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
}
