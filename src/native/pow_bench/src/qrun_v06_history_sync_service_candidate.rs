//! CP-0597 one-snapshot QFP6 history responder and Noise page client.
//!
//! This module connects the CP-0596 bounded page codec to the permissionless durable runtime.
//! The responder retains at most one immutable fork-choice snapshot so subsequent page requests
//! can continue against the same canonical tip while the live node advances.

use crate::qrun_v06_peer_listener_candidate::{
    serve_qfp6_noise_listener_with_history, QRunV06PeerListenerConfig, QRunV06PeerListenerError,
    QRunV06PeerListenerReport,
};
use crate::{
    consensus::pow_digest,
    external_cas_anchor_candidate::ExternalCasProviderTransport,
    qrun_v06_history_sync_wire_candidate::{
        decode_q6hi_request, decode_q6hr_status, decode_q6hs_request, encode_q6hp_page_chunks,
        encode_q6hr_status, Q6HistorySyncWireError, QRunV06HistoryInfoRequest,
        QRunV06HistoryPageChunkAssembler, QRunV06HistorySyncRequest, Q6HI_REQUEST_MAGIC,
        Q6HS_REQUEST_MAGIC,
    },
    qrun_v06_node_runtime_candidate::{
        QRunV06NodeAdmission, QRunV06NodeRuntime, QRunV06NodeRuntimeError,
    },
    qrun_v06_noise_transport_candidate::{QRunV06NoiseError, QRunV06NoiseSession},
    qrun_v06_permissionless_runtime_candidate::{
        QRunV06HistorySyncError, QRunV06HistorySyncReport, QRunV06PermissionlessNodeRuntime,
        QRunV06PermissionlessRuntimeError,
    },
    qrun_v06_pow_fork_choice_candidate::{
        QRunV06CanonicalHistoryPage, QRunV06QuoteAssetAuthorizationProvider,
    },
    qrun_v06_pow_wire_candidate::decode_qrun_v06_pow_block,
    qrun_v06_qap1_coordinator_candidate::{
        QRunV06Qap1AnchorTransport, QRunV06Qap1ExternalCoordinator,
    },
    state_machine::TransactionAuthenticator,
    v4_fat1_trust_candidate::MlDsa65Verifier,
};
use std::{
    net::{SocketAddr, TcpListener, TcpStream},
    sync::atomic::AtomicBool,
    time::Duration,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QRunV06HistorySyncServiceError {
    Runtime(String),
    Wire(String),
    Noise(String),
    SnapshotUnavailable,
    WrongNetwork,
    WrongProfile,
    PageDoesNotContinueLocalTip,
    PageDoesNotMatchSnapshot,
    EmptyPage,
    InvalidClientConfig,
    SourceBehind,
    SnapshotMismatch,
    NoProgress,
    PageBudgetExceeded,
}

impl std::fmt::Display for QRunV06HistorySyncServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "QFP6 history-sync service failed: {self:?}")
    }
}
impl std::error::Error for QRunV06HistorySyncServiceError {}

impl From<Q6HistorySyncWireError> for QRunV06HistorySyncServiceError {
    fn from(value: Q6HistorySyncWireError) -> Self {
        Self::Wire(value.to_string())
    }
}
impl From<QRunV06NoiseError> for QRunV06HistorySyncServiceError {
    fn from(value: QRunV06NoiseError) -> Self {
        Self::Noise(value.to_string())
    }
}
impl From<QRunV06PermissionlessRuntimeError> for QRunV06HistorySyncServiceError {
    fn from(value: QRunV06PermissionlessRuntimeError) -> Self {
        Self::Runtime(value.to_string())
    }
}
impl From<QRunV06HistorySyncError> for QRunV06HistorySyncServiceError {
    fn from(value: QRunV06HistorySyncError) -> Self {
        Self::Runtime(value.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06HistorySnapshotInfo {
    pub height: u64,
    pub consensus_tip: [u8; 32],
    pub execution_tip: [u8; 32],
}

/// One-peer responder state. At most one immutable fork-choice snapshot is retained.
/// A request for a different snapshot is accepted only if it names the node's current tip;
/// otherwise the peer must restart from a fresh status/tip observation.
#[derive(Default)]
pub struct QRunV06HistorySyncResponder {
    snapshot: Option<crate::qrun_v06_pow_fork_choice_candidate::QRunV06PowForkChoice>,
}

impl QRunV06HistorySyncResponder {
    /// Capture and pin the exact current canonical snapshot before advertising its tip.
    /// Subsequent Q6HS pages may continue against this immutable view while mining advances.
    pub fn pin_current_snapshot(
        &mut self,
        runtime: &QRunV06PermissionlessNodeRuntime,
    ) -> Result<QRunV06HistorySnapshotInfo, QRunV06HistorySyncServiceError> {
        // Retain one immutable source snapshot across the client's bounded reconnect windows.
        // A new mining block must not silently change Q6HR while a client is paging the old tip.
        if let Some(snapshot) = self.snapshot.as_ref() {
            let tip = snapshot.canonical_tip();
            return Ok(QRunV06HistorySnapshotInfo {
                height: tip.height,
                consensus_tip: tip.tip_hash,
                execution_tip: snapshot.canonical_state().tip_hash(),
            });
        }
        let status = runtime.status()?;
        let snapshot = runtime.fork_choice_snapshot()?;
        let consensus_tip = snapshot.canonical_tip().tip_hash;
        if consensus_tip != status.tip {
            return Err(QRunV06HistorySyncServiceError::SnapshotUnavailable);
        }
        let execution_tip = snapshot.canonical_state().tip_hash();
        self.snapshot = Some(snapshot);
        Ok(QRunV06HistorySnapshotInfo {
            height: status.height,
            consensus_tip,
            execution_tip,
        })
    }

    pub fn retained_snapshot_tip(&self) -> Option<[u8; 32]> {
        self.snapshot
            .as_ref()
            .map(|snapshot| snapshot.canonical_tip().tip_hash)
    }

    pub fn respond(
        &mut self,
        runtime: &QRunV06PermissionlessNodeRuntime,
        request: &QRunV06HistorySyncRequest,
    ) -> Result<Vec<Vec<u8>>, QRunV06HistorySyncServiceError> {
        request.validate()?;
        let status = runtime.status()?;
        if request.network_id != status.network_id {
            return Err(QRunV06HistorySyncServiceError::WrongNetwork);
        }
        if request.profile_id != status.profile_id {
            return Err(QRunV06HistorySyncServiceError::WrongProfile);
        }

        let retained_matches = self
            .snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot.canonical_tip().tip_hash == request.snapshot_tip);
        if !retained_matches {
            if status.tip != request.snapshot_tip {
                return Err(QRunV06HistorySyncServiceError::SnapshotUnavailable);
            }
            self.snapshot = Some(runtime.fork_choice_snapshot()?);
        }

        let snapshot = self
            .snapshot
            .as_ref()
            .ok_or(QRunV06HistorySyncServiceError::SnapshotUnavailable)?;
        if snapshot.canonical_tip().tip_hash != request.snapshot_tip {
            return Err(QRunV06HistorySyncServiceError::SnapshotUnavailable);
        }
        let page = snapshot
            .canonical_history_page(
                request.start_height,
                usize::from(request.max_blocks),
                request.max_bytes as usize,
            )
            .map_err(|error| QRunV06HistorySyncServiceError::Runtime(error.to_string()))?;
        let complete = page.complete;
        let chunks = encode_q6hp_page_chunks(request, &page)?;
        // Release only after the final page has been encoded. The next Q6HI then pins a fresh tip.
        if complete {
            self.clear_snapshot();
        }
        Ok(chunks)
    }

    pub fn clear_snapshot(&mut self) {
        self.snapshot = None;
    }
}

/// Bind the Q6HS/Q6HC listener directly to the permissionless durable runtime.
/// The responder and its one retained snapshot live for this listener invocation.
pub fn serve_permissionless_history_sync_listener(
    listener: &TcpListener,
    config: QRunV06PeerListenerConfig,
    local_static_private_key: &[u8; 32],
    trusted_remote_static_public_keys: &[[u8; 32]],
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
    shutdown: &AtomicBool,
    runtime: &QRunV06PermissionlessNodeRuntime,
) -> Result<QRunV06PeerListenerReport, QRunV06PeerListenerError> {
    let mut responder = QRunV06HistorySyncResponder::default();
    serve_qfp6_noise_listener_with_history(
        listener,
        config,
        local_static_private_key,
        trusted_remote_static_public_keys,
        network_id,
        profile_id,
        shutdown,
        |_replay_guard, frame| {
            if frame.get(..4) == Some(&Q6HI_REQUEST_MAGIC) {
                let request = decode_q6hi_request(frame)
                    .map_err(|error| format!("Q6HI request rejected: {error}"))?;
                let snapshot = responder
                    .pin_current_snapshot(runtime)
                    .map_err(|error| format!("cannot pin Q6HR source snapshot: {error}"))?;
                let status = encode_q6hr_status(
                    &request,
                    snapshot.height,
                    snapshot.consensus_tip,
                    snapshot.execution_tip,
                )
                .map_err(|error| format!("cannot encode Q6HR status: {error}"))?;
                Ok(vec![status.to_vec()])
            } else if frame.get(..4) == Some(&Q6HS_REQUEST_MAGIC) {
                let request = decode_q6hs_request(frame)
                    .map_err(|error| format!("Q6HS request rejected: {error}"))?;
                responder
                    .respond(runtime, &request)
                    .map_err(|error| error.to_string())
            } else {
                Err("unsupported application frame on history-only listener".into())
            }
        },
    )
}

/// Build the next-page request from the destination node's exact durable tip.
/// The caller supplies the source's snapshot tip from an independently authenticated status
/// observation; this function never guesses or trusts an unpinned remote height.
pub fn make_next_history_request(
    runtime: &QRunV06PermissionlessNodeRuntime,
    request_id: u64,
    source_snapshot_tip: [u8; 32],
    max_blocks: u16,
    max_bytes: u32,
) -> Result<QRunV06HistorySyncRequest, QRunV06HistorySyncServiceError> {
    let status = runtime.status()?;
    let graph = runtime.fork_choice_snapshot()?;
    let request = QRunV06HistorySyncRequest {
        request_id,
        network_id: status.network_id,
        profile_id: status.profile_id,
        snapshot_tip: source_snapshot_tip,
        expected_parent_consensus_hash: status.tip,
        expected_parent_execution_hash: graph.canonical_state().tip_hash(),
        start_height: status.height.checked_add(1).ok_or_else(|| {
            QRunV06HistorySyncServiceError::Runtime("local height overflow".into())
        })?,
        max_blocks,
        max_bytes,
    };
    request.validate()?;
    Ok(request)
}

/// Exchange one Q6HS request for a complete, checksum-verified canonical page over an
/// already-authenticated Noise session. Every Q6HC chunk is read as a separate bounded record.
pub fn request_history_page_over_noise(
    noise: &mut QRunV06NoiseSession,
    stream: &mut TcpStream,
    request: QRunV06HistorySyncRequest,
    params: crate::consensus::ConsensusParameters,
) -> Result<QRunV06CanonicalHistoryPage, QRunV06HistorySyncServiceError> {
    let encoded = request.encode()?;
    noise.write_record(stream, &encoded)?;
    let mut assembler = QRunV06HistoryPageChunkAssembler::new(request, params)?;
    for _ in 0..crate::qrun_v06_history_sync_wire_candidate::Q6_HISTORY_SYNC_MAX_CHUNKS {
        let frame = noise.read_record(stream)?;
        if let Some(page) = assembler.push(&frame)? {
            return Ok(page);
        }
    }
    Err(QRunV06HistorySyncServiceError::Wire(
        "Q6HC chunk budget exhausted before a complete page arrived".into(),
    ))
}

/// Import one fully decoded page. The durable CP-0594 store independently rechecks PoW,
/// consensus, execution, state roots and persistence; this function does not bypass it.
pub fn import_history_page<A: TransactionAuthenticator>(
    runtime: &mut QRunV06PermissionlessNodeRuntime,
    page: &QRunV06CanonicalHistoryPage,
    authenticator: &A,
) -> Result<QRunV06HistorySyncReport, QRunV06HistorySyncServiceError> {
    if page.envelopes.is_empty() {
        return Err(QRunV06HistorySyncServiceError::EmptyPage);
    }
    let status = runtime.status()?;
    if page.start_height != status.height.saturating_add(1) || page.envelopes.first().is_none() {
        return Err(QRunV06HistorySyncServiceError::PageDoesNotContinueLocalTip);
    }
    let expected_next = page
        .start_height
        .checked_add(page.envelopes.len() as u64)
        .ok_or(QRunV06HistorySyncServiceError::PageDoesNotMatchSnapshot)?;
    let after_snapshot = page
        .snapshot_height
        .checked_add(1)
        .ok_or(QRunV06HistorySyncServiceError::PageDoesNotMatchSnapshot)?;
    if page.next_height != expected_next
        || page.complete != (page.next_height > page.snapshot_height)
        || (page.complete && page.next_height != after_snapshot)
        || (!page.complete && page.next_height > page.snapshot_height)
    {
        return Err(QRunV06HistorySyncServiceError::PageDoesNotMatchSnapshot);
    }
    if page.complete {
        let graph = runtime.fork_choice_snapshot()?;
        let last = decode_qrun_v06_pow_block(page.envelopes.last().unwrap())
            .map_err(|error| QRunV06HistorySyncServiceError::Wire(error.to_string()))?;
        let final_digest = pow_digest(&last.header, graph.consensus_parameters().pow)
            .map_err(|error| QRunV06HistorySyncServiceError::Wire(error.to_string()))?;
        if final_digest != page.snapshot_tip || page.snapshot_height != expected_next - 1 {
            return Err(QRunV06HistorySyncServiceError::PageDoesNotMatchSnapshot);
        }
    }
    let report = runtime.import_history_batch(&page.envelopes, authenticator)?;
    if page.complete
        && (report.resulting_height != page.snapshot_height
            || report.resulting_tip != page.snapshot_tip)
    {
        return Err(QRunV06HistorySyncServiceError::PageDoesNotMatchSnapshot);
    }
    Ok(report)
}

/// Import a page from a peer's canonical history onto the exact known parent branch.
/// This is the branch-aware counterpart to `import_history_page`, which only accepts an
/// extension of the current canonical tip.
pub fn import_history_branch_page<A: TransactionAuthenticator>(
    runtime: &mut QRunV06PermissionlessNodeRuntime,
    request: &QRunV06HistorySyncRequest,
    page: &QRunV06CanonicalHistoryPage,
    authenticator: &A,
) -> Result<QRunV06HistorySyncReport, QRunV06HistorySyncServiceError> {
    request.validate()?;
    if page.envelopes.is_empty() {
        return Err(QRunV06HistorySyncServiceError::EmptyPage);
    }
    let status = runtime.status()?;
    if request.network_id != status.network_id {
        return Err(QRunV06HistorySyncServiceError::WrongNetwork);
    }
    if request.profile_id != status.profile_id {
        return Err(QRunV06HistorySyncServiceError::WrongProfile);
    }
    let expected_next = page
        .start_height
        .checked_add(page.envelopes.len() as u64)
        .ok_or(QRunV06HistorySyncServiceError::PageDoesNotMatchSnapshot)?;
    let after_snapshot = page
        .snapshot_height
        .checked_add(1)
        .ok_or(QRunV06HistorySyncServiceError::PageDoesNotMatchSnapshot)?;
    if page.start_height != request.start_height
        || page.snapshot_tip != request.snapshot_tip
        || page.next_height != expected_next
        || page.complete != (page.next_height > page.snapshot_height)
        || (page.complete && page.next_height != after_snapshot)
        || (!page.complete && page.next_height > page.snapshot_height)
    {
        return Err(QRunV06HistorySyncServiceError::PageDoesNotMatchSnapshot);
    }
    if page.complete {
        let graph = runtime.fork_choice_snapshot()?;
        let last = decode_qrun_v06_pow_block(page.envelopes.last().unwrap())
            .map_err(|error| QRunV06HistorySyncServiceError::Wire(error.to_string()))?;
        let final_digest = pow_digest(&last.header, graph.consensus_parameters().pow)
            .map_err(|error| QRunV06HistorySyncServiceError::Wire(error.to_string()))?;
        if final_digest != page.snapshot_tip || page.snapshot_height != expected_next - 1 {
            return Err(QRunV06HistorySyncServiceError::PageDoesNotMatchSnapshot);
        }
    }
    runtime
        .import_history_branch_batch(
            request.start_height,
            request.expected_parent_consensus_hash,
            request.expected_parent_execution_hash,
            &page.envelopes,
            authenticator,
        )
        .map_err(Into::into)
}

/// Import a verified Q6HS page through QAP1. Every block is committed and acknowledged by
/// Provider/Q6EA before the next block is attempted. A partial failure leaves the exact
/// acknowledged prefix durable and requires restart recovery before more admission.
#[allow(clippy::too_many_arguments)]
pub fn import_history_page_with_qap1<A, P, PV, AV, Q, T>(
    runtime: &mut QRunV06NodeRuntime<A>,
    page: &QRunV06CanonicalHistoryPage,
    authenticator: &T,
    quote_authorizer: &mut QRunV06QuoteAssetAuthorizationProvider<'_>,
    coordinator: &mut QRunV06Qap1ExternalCoordinator<P, PV, AV, Q>,
) -> Result<QRunV06HistorySyncReport, QRunV06HistorySyncServiceError>
where
    A: crate::qrun_v06_node_runtime_candidate::QRunV06NodeAnchorGate,
    P: ExternalCasProviderTransport,
    PV: MlDsa65Verifier + Clone,
    AV: MlDsa65Verifier,
    Q: QRunV06Qap1AnchorTransport,
    T: TransactionAuthenticator,
{
    if !runtime.requires_qap1()
        || !runtime.qap1_recovery_verified()
        || runtime.requires_reopen()
        || runtime.has_pending_external_anchor()
    {
        return Err(QRunV06HistorySyncServiceError::Runtime(
            "QAP1 recovery/anchor gate is not in an admission-ready state".into(),
        ));
    }
    if page.envelopes.is_empty() {
        return Err(QRunV06HistorySyncServiceError::EmptyPage);
    }
    let before = runtime.committed_anchor_state();
    if page.start_height != before.canonical_height.saturating_add(1) {
        return Err(QRunV06HistorySyncServiceError::PageDoesNotContinueLocalTip);
    }
    let expected_next = page
        .start_height
        .checked_add(page.envelopes.len() as u64)
        .ok_or(QRunV06HistorySyncServiceError::PageDoesNotMatchSnapshot)?;
    let after_snapshot = page
        .snapshot_height
        .checked_add(1)
        .ok_or(QRunV06HistorySyncServiceError::PageDoesNotMatchSnapshot)?;
    if page.next_height != expected_next
        || page.complete != (page.next_height > page.snapshot_height)
        || (page.complete && page.next_height != after_snapshot)
        || (!page.complete && page.next_height > page.snapshot_height)
    {
        return Err(QRunV06HistorySyncServiceError::PageDoesNotMatchSnapshot);
    }
    let graph = runtime
        .fork_choice_snapshot()
        .map_err(|error: QRunV06NodeRuntimeError| {
            QRunV06HistorySyncServiceError::Runtime(error.to_string())
        })?;
    if before.canonical_tip != graph.canonical_tip().tip_hash {
        return Err(QRunV06HistorySyncServiceError::SnapshotMismatch);
    }
    if page.complete {
        let last = decode_qrun_v06_pow_block(page.envelopes.last().unwrap())
            .map_err(|error| QRunV06HistorySyncServiceError::Wire(error.to_string()))?;
        let final_digest = pow_digest(&last.header, graph.consensus_parameters().pow)
            .map_err(|error| QRunV06HistorySyncServiceError::Wire(error.to_string()))?;
        if final_digest != page.snapshot_tip || page.snapshot_height != expected_next - 1 {
            return Err(QRunV06HistorySyncServiceError::PageDoesNotMatchSnapshot);
        }
    }
    for envelope in &page.envelopes {
        match runtime.submit_envelope_with_qap1(
            envelope,
            authenticator,
            quote_authorizer,
            coordinator,
        ) {
            Ok(QRunV06NodeAdmission::Acknowledged(_)) => {}
            Ok(QRunV06NodeAdmission::ExternalAnchorPending(_)) => {
                return Err(QRunV06HistorySyncServiceError::Runtime(
                    "QAP1 page import stopped: external anchor pending; no further block admitted"
                        .into(),
                ));
            }
            Err(error) => return Err(QRunV06HistorySyncServiceError::Runtime(error.to_string())),
        }
    }
    let after = runtime.committed_anchor_state();
    if page.complete
        && (after.canonical_height != page.snapshot_height
            || after.canonical_tip != page.snapshot_tip)
    {
        return Err(QRunV06HistorySyncServiceError::PageDoesNotMatchSnapshot);
    }
    Ok(QRunV06HistorySyncReport {
        imported_blocks: page.envelopes.len(),
        resulting_height: after.canonical_height,
        resulting_tip: after.canonical_tip,
        resulting_state_root: after.canonical_state_root,
    })
}
/// Bounds for one statically pinned peer bootstrap/synchronization attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QRunV06HistorySyncClientConfig {
    pub connect_timeout: Duration,
    pub io_timeout: Duration,
    pub max_blocks_per_page: u16,
    pub max_bytes_per_page: u32,
    /// Page requests per Noise session; one additional request is used for Q6HI status.
    pub max_pages: u32,
    /// Bounded reconnect rounds; each round obtains and pins a fresh Q6HR source snapshot.
    pub max_rounds: u32,
}

impl Default for QRunV06HistorySyncClientConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            io_timeout: Duration::from_secs(30),
            max_blocks_per_page: 128,
            max_bytes_per_page: 16 * 1024 * 1024,
            max_pages: 15,
            max_rounds: 64,
        }
    }
}

impl QRunV06HistorySyncClientConfig {
    pub fn validate(&self) -> Result<(), QRunV06HistorySyncServiceError> {
        if self.connect_timeout.is_zero()
            || self.io_timeout.is_zero()
            || self.max_blocks_per_page == 0
            || usize::from(self.max_blocks_per_page)
                > crate::qrun_v06_history_sync_wire_candidate::Q6_HISTORY_SYNC_MAX_BLOCKS
            || self.max_bytes_per_page == 0
            || self.max_bytes_per_page as usize
                > crate::qrun_v06_history_sync_wire_candidate::Q6_HISTORY_SYNC_MAX_BYTES
            || !(1..=15).contains(&self.max_pages)
            || !(1..=1024).contains(&self.max_rounds)
        {
            return Err(QRunV06HistorySyncServiceError::InvalidClientConfig);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06HistorySyncClientReport {
    pub source_height: u64,
    pub final_height: u64,
    pub pages_imported: u32,
    pub blocks_imported: u64,
    pub source_tip: [u8; 32],
    pub complete: bool,
}

/// Connect to one statically pinned QFP6 peer, authenticate its Q6HR status over Noise,
/// download canonical pages on the same session, and import each page through CP-0594's
/// durable PoW/consensus/execution validator. No peer discovery or key trust is inferred.
pub fn sync_history_from_pinned_peer<A: TransactionAuthenticator>(
    address: SocketAddr,
    local_static_private_key: &[u8; 32],
    remote_static_public_key: &[u8; 32],
    runtime: &mut QRunV06PermissionlessNodeRuntime,
    authenticator: &A,
    config: QRunV06HistorySyncClientConfig,
) -> Result<QRunV06HistorySyncClientReport, QRunV06HistorySyncServiceError> {
    config.validate()?;
    if local_static_private_key.iter().all(|byte| *byte == 0)
        || remote_static_public_key.iter().all(|byte| *byte == 0)
    {
        return Err(QRunV06HistorySyncServiceError::InvalidClientConfig);
    }

    let local_start = runtime.status()?;
    let base_graph = runtime.fork_choice_snapshot()?;
    let base_tip = base_graph.base_tip();
    let base_state = base_graph
        .state_for_tip(&base_tip)
        .ok_or(QRunV06HistorySyncServiceError::SnapshotUnavailable)?;
    let base_height = base_state.height();
    let base_execution_tip = base_state.tip_hash();
    let mut next_height = base_height
        .checked_add(1)
        .ok_or(QRunV06HistorySyncServiceError::PageBudgetExceeded)?;
    let mut parent_consensus = base_tip;
    let mut parent_execution = base_execution_tip;
    let mut source_snapshot: Option<(u64, [u8; 32], [u8; 32])> = None;
    let mut pages_imported = 0u32;
    let mut blocks_imported = 0u64;

    // Bounded reconnect windows resume the same source branch even when it is not canonical
    // locally. The durable fork-choice graph, not remote height, selects the canonical tip.
    for _round in 0..config.max_rounds {
        if source_snapshot.is_some_and(|(height, _, _)| next_height > height) {
            break;
        }
        let mut stream = TcpStream::connect_timeout(&address, config.connect_timeout)
            .map_err(|error| QRunV06HistorySyncServiceError::Noise(error.to_string()))?;
        stream
            .set_read_timeout(Some(config.io_timeout))
            .map_err(|error| QRunV06HistorySyncServiceError::Noise(error.to_string()))?;
        stream
            .set_write_timeout(Some(config.io_timeout))
            .map_err(|error| QRunV06HistorySyncServiceError::Noise(error.to_string()))?;
        stream
            .set_nodelay(true)
            .map_err(|error| QRunV06HistorySyncServiceError::Noise(error.to_string()))?;
        let mut noise = QRunV06NoiseSession::connect(
            &mut stream,
            local_static_private_key,
            remote_static_public_key,
            &local_start.network_id,
            &local_start.profile_id,
        )?;
        let info_request = QRunV06HistoryInfoRequest {
            request_id: 1,
            network_id: local_start.network_id,
            profile_id: local_start.profile_id,
        };
        noise.write_record(&mut stream, &info_request.encode()?)?;
        let info_frame = noise.read_record(&mut stream)?;
        let source = decode_q6hr_status(&info_frame, &info_request)?;
        let observed = (source.height, source.consensus_tip, source.execution_tip);
        if let Some(previous) = source_snapshot {
            if observed != previous {
                return Err(QRunV06HistorySyncServiceError::SnapshotMismatch);
            }
        } else {
            if source.height < base_height {
                return Err(QRunV06HistorySyncServiceError::SourceBehind);
            }
            source_snapshot = Some(observed);
            if source.height == base_height {
                if source.consensus_tip != base_tip || source.execution_tip != base_execution_tip {
                    return Err(QRunV06HistorySyncServiceError::SnapshotMismatch);
                }
                // Complete an empty Q6HS page at height tip+1 so the responder releases its
                // retained snapshot. Without this sentinel, an already-current node would leave
                // a stale snapshot pinned forever and miss later source-chain growth.
                let empty_request = QRunV06HistorySyncRequest {
                    request_id: 2,
                    network_id: local_start.network_id,
                    profile_id: local_start.profile_id,
                    snapshot_tip: source.consensus_tip,
                    expected_parent_consensus_hash: base_tip,
                    expected_parent_execution_hash: base_execution_tip,
                    start_height: next_height,
                    max_blocks: config.max_blocks_per_page,
                    max_bytes: config.max_bytes_per_page,
                };
                empty_request.validate()?;
                let empty_page = request_history_page_over_noise(
                    &mut noise,
                    &mut stream,
                    empty_request,
                    runtime
                        .fork_choice_snapshot()?
                        .consensus_parameters()
                        .clone(),
                )?;
                if !empty_page.envelopes.is_empty()
                    || !empty_page.complete
                    || empty_page.start_height != next_height
                    || empty_page.next_height != next_height
                    || empty_page.snapshot_height != source.height
                    || empty_page.snapshot_tip != source.consensus_tip
                {
                    return Err(QRunV06HistorySyncServiceError::PageDoesNotMatchSnapshot);
                }
                break;
            }
        }

        let mut pages_this_session = 0u32;
        let mut request_id = 2u64;
        while pages_this_session < config.max_pages
            && source_snapshot.is_some_and(|(height, _, _)| next_height <= height)
        {
            let request = QRunV06HistorySyncRequest {
                request_id,
                network_id: local_start.network_id,
                profile_id: local_start.profile_id,
                snapshot_tip: source.consensus_tip,
                expected_parent_consensus_hash: parent_consensus,
                expected_parent_execution_hash: parent_execution,
                start_height: next_height,
                max_blocks: config.max_blocks_per_page,
                max_bytes: config.max_bytes_per_page,
            };
            request.validate()?;
            let params = runtime
                .fork_choice_snapshot()?
                .consensus_parameters()
                .clone();
            let page = request_history_page_over_noise(
                &mut noise,
                &mut stream,
                request.clone(),
                params.clone(),
            )?;
            if page.snapshot_height != source.height || page.snapshot_tip != source.consensus_tip {
                return Err(QRunV06HistorySyncServiceError::SnapshotMismatch);
            }
            if page.envelopes.is_empty() {
                return Err(QRunV06HistorySyncServiceError::NoProgress);
            }
            let page_blocks = page.envelopes.len() as u64;
            let complete = page.complete;
            import_history_branch_page(runtime, &request, &page, authenticator)?;
            let last = decode_qrun_v06_pow_block(page.envelopes.last().unwrap())
                .map_err(|error| QRunV06HistorySyncServiceError::Wire(error.to_string()))?;
            parent_consensus = pow_digest(&last.header, params.pow)
                .map_err(|error| QRunV06HistorySyncServiceError::Wire(error.to_string()))?;
            let imported_graph = runtime.fork_choice_snapshot()?;
            parent_execution = imported_graph
                .state_for_tip(&parent_consensus)
                .ok_or(QRunV06HistorySyncServiceError::SnapshotUnavailable)?
                .tip_hash();
            next_height = page.next_height;
            pages_imported = pages_imported
                .checked_add(1)
                .ok_or(QRunV06HistorySyncServiceError::PageBudgetExceeded)?;
            blocks_imported = blocks_imported
                .checked_add(page_blocks)
                .ok_or(QRunV06HistorySyncServiceError::PageBudgetExceeded)?;
            pages_this_session += 1;
            request_id = request_id
                .checked_add(1)
                .ok_or(QRunV06HistorySyncServiceError::PageBudgetExceeded)?;
            if complete {
                break;
            }
        }
    }

    let (source_height, source_tip, source_execution_tip) =
        source_snapshot.ok_or(QRunV06HistorySyncServiceError::SnapshotUnavailable)?;
    if next_height <= source_height {
        return Err(QRunV06HistorySyncServiceError::PageBudgetExceeded);
    }
    let final_graph = runtime.fork_choice_snapshot()?;
    let source_chain_tip = final_graph
        .tip_for_hash(&source_tip)
        .ok_or(QRunV06HistorySyncServiceError::SnapshotMismatch)?;
    let source_chain_state = final_graph
        .state_for_tip(&source_tip)
        .ok_or(QRunV06HistorySyncServiceError::SnapshotMismatch)?;
    if source_chain_tip.height != source_height
        || source_chain_state.tip_hash() != source_execution_tip
        || final_graph.canonical_tip().cumulative_work < source_chain_tip.cumulative_work
    {
        return Err(QRunV06HistorySyncServiceError::SnapshotMismatch);
    }
    let final_status = runtime.status()?;
    Ok(QRunV06HistorySyncClientReport {
        source_height,
        final_height: final_status.height,
        pages_imported,
        blocks_imported,
        source_tip,
        complete: true,
    })
}

/// Synchronize history from one statically pinned Noise peer using the QAP1 runtime only.
/// Each received Q6HS page is imported through `import_history_page_with_qap1`; this function
/// never opens or falls back to the non-QAP1 runtime/import path.
#[allow(clippy::too_many_arguments)]
pub fn sync_history_from_pinned_peer_with_qap1<A, P, PV, AV, Q, T>(
    address: SocketAddr,
    local_static_private_key: &[u8; 32],
    remote_static_public_key: &[u8; 32],
    runtime: &mut QRunV06NodeRuntime<A>,
    authenticator: &T,
    quote_authorizer: &mut QRunV06QuoteAssetAuthorizationProvider<'_>,
    coordinator: &mut QRunV06Qap1ExternalCoordinator<P, PV, AV, Q>,
    config: QRunV06HistorySyncClientConfig,
) -> Result<QRunV06HistorySyncClientReport, QRunV06HistorySyncServiceError>
where
    A: crate::qrun_v06_node_runtime_candidate::QRunV06NodeAnchorGate,
    P: ExternalCasProviderTransport,
    PV: MlDsa65Verifier + Clone,
    AV: MlDsa65Verifier,
    Q: QRunV06Qap1AnchorTransport,
    T: TransactionAuthenticator,
{
    config.validate()?;
    if !runtime.requires_qap1()
        || !runtime.qap1_recovery_verified()
        || runtime.requires_reopen()
        || runtime.has_pending_external_anchor()
        || local_static_private_key.iter().all(|byte| *byte == 0)
        || remote_static_public_key.iter().all(|byte| *byte == 0)
    {
        return Err(QRunV06HistorySyncServiceError::InvalidClientConfig);
    }
    let anchor = runtime.committed_anchor_state();
    let network_id = anchor.network_id;
    let profile_id = anchor.profile_id;
    let local_height = anchor.canonical_height;
    let local_tip = anchor.canonical_tip;
    let local_graph = runtime
        .fork_choice_snapshot()
        .map_err(|error| QRunV06HistorySyncServiceError::Runtime(error.to_string()))?;
    if local_graph.canonical_tip().tip_hash != local_tip
        || local_graph
            .canonical_state()
            .state_root()
            .map_err(|error| QRunV06HistorySyncServiceError::Runtime(format!("{error:?}")))?
            != anchor.canonical_state_root
    {
        return Err(QRunV06HistorySyncServiceError::SnapshotMismatch);
    }
    let mut stream = TcpStream::connect_timeout(&address, config.connect_timeout)
        .map_err(|error| QRunV06HistorySyncServiceError::Noise(error.to_string()))?;
    stream
        .set_read_timeout(Some(config.io_timeout))
        .map_err(|error| QRunV06HistorySyncServiceError::Noise(error.to_string()))?;
    stream
        .set_write_timeout(Some(config.io_timeout))
        .map_err(|error| QRunV06HistorySyncServiceError::Noise(error.to_string()))?;
    stream
        .set_nodelay(true)
        .map_err(|error| QRunV06HistorySyncServiceError::Noise(error.to_string()))?;
    let mut noise = QRunV06NoiseSession::connect(
        &mut stream,
        local_static_private_key,
        remote_static_public_key,
        &network_id,
        &profile_id,
    )?;
    let info_request = QRunV06HistoryInfoRequest {
        request_id: 1,
        network_id,
        profile_id,
    };
    noise.write_record(&mut stream, &info_request.encode()?)?;
    let info_frame = noise.read_record(&mut stream)?;
    let source = decode_q6hr_status(&info_frame, &info_request)?;
    if source.height < local_height {
        return Err(QRunV06HistorySyncServiceError::SourceBehind);
    }
    if source.height == local_height
        && (source.consensus_tip != local_tip
            || source.execution_tip != local_graph.canonical_state().tip_hash())
    {
        return Err(QRunV06HistorySyncServiceError::SnapshotMismatch);
    }

    let mut pages_imported = 0u32;
    let mut blocks_imported = 0u64;
    let mut request_id = 2u64;
    while runtime.committed_anchor_state().canonical_height < source.height {
        if pages_imported >= config.max_pages {
            return Err(QRunV06HistorySyncServiceError::PageBudgetExceeded);
        }
        if runtime.requires_reopen() || runtime.has_pending_external_anchor() {
            return Err(QRunV06HistorySyncServiceError::Runtime(
                "QAP1 anchor transition requires restart recovery before history sync continues"
                    .into(),
            ));
        }
        let anchor = runtime.committed_anchor_state();
        let graph = runtime
            .fork_choice_snapshot()
            .map_err(|error| QRunV06HistorySyncServiceError::Runtime(error.to_string()))?;
        if graph.canonical_tip().tip_hash != anchor.canonical_tip
            || graph
                .canonical_state()
                .state_root()
                .map_err(|error| QRunV06HistorySyncServiceError::Runtime(format!("{error:?}")))?
                != anchor.canonical_state_root
        {
            return Err(QRunV06HistorySyncServiceError::SnapshotMismatch);
        }
        let request = QRunV06HistorySyncRequest {
            request_id,
            network_id: anchor.network_id,
            profile_id: anchor.profile_id,
            snapshot_tip: source.consensus_tip,
            expected_parent_consensus_hash: anchor.canonical_tip,
            expected_parent_execution_hash: graph.canonical_state().tip_hash(),
            start_height: anchor.canonical_height.checked_add(1).ok_or_else(|| {
                QRunV06HistorySyncServiceError::Runtime("local height overflow".into())
            })?,
            max_blocks: config.max_blocks_per_page,
            max_bytes: config.max_bytes_per_page,
        };
        request.validate()?;
        let page = request_history_page_over_noise(
            &mut noise,
            &mut stream,
            request,
            graph.consensus_parameters().clone(),
        )?;
        if page.snapshot_height != source.height || page.snapshot_tip != source.consensus_tip {
            return Err(QRunV06HistorySyncServiceError::SnapshotMismatch);
        }
        if page.envelopes.is_empty() {
            return Err(QRunV06HistorySyncServiceError::NoProgress);
        }
        let imported_count = page.envelopes.len() as u64;
        import_history_page_with_qap1(
            runtime,
            &page,
            authenticator,
            quote_authorizer,
            coordinator,
        )?;
        pages_imported = pages_imported
            .checked_add(1)
            .ok_or(QRunV06HistorySyncServiceError::PageBudgetExceeded)?;
        blocks_imported = blocks_imported
            .checked_add(imported_count)
            .ok_or(QRunV06HistorySyncServiceError::PageBudgetExceeded)?;
        request_id = request_id
            .checked_add(1)
            .ok_or(QRunV06HistorySyncServiceError::PageBudgetExceeded)?;
        if page.complete {
            break;
        }
    }
    let final_anchor = runtime.committed_anchor_state();
    if final_anchor.canonical_height > source.height {
        return Err(QRunV06HistorySyncServiceError::SnapshotMismatch);
    }
    let complete = final_anchor.canonical_height == source.height;
    if complete {
        let final_graph = runtime
            .fork_choice_snapshot()
            .map_err(|error| QRunV06HistorySyncServiceError::Runtime(error.to_string()))?;
        if final_anchor.canonical_tip != source.consensus_tip
            || final_graph.canonical_state().tip_hash() != source.execution_tip
            || final_graph
                .canonical_state()
                .state_root()
                .map_err(|error| QRunV06HistorySyncServiceError::Runtime(format!("{error:?}")))?
                != final_anchor.canonical_state_root
        {
            return Err(QRunV06HistorySyncServiceError::SnapshotMismatch);
        }
    } else if pages_imported != config.max_pages {
        return Err(QRunV06HistorySyncServiceError::NoProgress);
    }
    Ok(QRunV06HistorySyncClientReport {
        source_height: source.height,
        final_height: final_anchor.canonical_height,
        pages_imported,
        blocks_imported,
        source_tip: source.consensus_tip,
        complete,
    })
}

/// Repeat bounded QAP1-gated Q6HS sessions until the peer's canonical height and tips match.
/// A failed anchor transition must be reconciled by reopening the QAP1 runtime before retry.
#[allow(clippy::too_many_arguments)]
pub fn sync_history_from_pinned_peer_until_complete_with_qap1<A, P, PV, AV, Q, T>(
    address: SocketAddr,
    local_static_private_key: &[u8; 32],
    remote_static_public_key: &[u8; 32],
    runtime: &mut QRunV06NodeRuntime<A>,
    authenticator: &T,
    quote_authorizer: &mut QRunV06QuoteAssetAuthorizationProvider<'_>,
    coordinator: &mut QRunV06Qap1ExternalCoordinator<P, PV, AV, Q>,
    config: QRunV06HistorySyncClientConfig,
) -> Result<QRunV06HistorySyncClientReport, QRunV06HistorySyncServiceError>
where
    A: crate::qrun_v06_node_runtime_candidate::QRunV06NodeAnchorGate,
    P: ExternalCasProviderTransport,
    PV: MlDsa65Verifier + Clone,
    AV: MlDsa65Verifier,
    Q: QRunV06Qap1AnchorTransport,
    T: TransactionAuthenticator,
{
    config.validate()?;
    let mut total_pages = 0u32;
    let mut total_blocks = 0u64;
    for _ in 0..config.max_rounds {
        let mut report = sync_history_from_pinned_peer_with_qap1(
            address,
            local_static_private_key,
            remote_static_public_key,
            runtime,
            authenticator,
            quote_authorizer,
            coordinator,
            config,
        )?;
        total_pages = total_pages
            .checked_add(report.pages_imported)
            .ok_or(QRunV06HistorySyncServiceError::PageBudgetExceeded)?;
        total_blocks = total_blocks
            .checked_add(report.blocks_imported)
            .ok_or(QRunV06HistorySyncServiceError::PageBudgetExceeded)?;
        if report.complete {
            report.pages_imported = total_pages;
            report.blocks_imported = total_blocks;
            return Ok(report);
        }
    }
    Err(QRunV06HistorySyncServiceError::PageBudgetExceeded)
}
/// Repeat bounded Q6HI/Q6HR + page sessions until the peer's canonical height/tips match
/// the local durable runtime. Each round is independently authenticated and pins a fresh
/// source snapshot; CP-0594 validates every imported page. A reorg below the imported prefix
/// fails closed rather than silently rolling back local history.
pub fn sync_history_from_pinned_peer_until_complete<A: TransactionAuthenticator>(
    address: SocketAddr,
    local_static_private_key: &[u8; 32],
    remote_static_public_key: &[u8; 32],
    runtime: &mut QRunV06PermissionlessNodeRuntime,
    authenticator: &A,
    config: QRunV06HistorySyncClientConfig,
) -> Result<QRunV06HistorySyncClientReport, QRunV06HistorySyncServiceError> {
    config.validate()?;
    let mut total_pages = 0u32;
    let mut total_blocks = 0u64;
    for _ in 0..config.max_rounds {
        let mut report = sync_history_from_pinned_peer(
            address,
            local_static_private_key,
            remote_static_public_key,
            runtime,
            authenticator,
            config,
        )?;
        total_pages = total_pages
            .checked_add(report.pages_imported)
            .ok_or(QRunV06HistorySyncServiceError::PageBudgetExceeded)?;
        total_blocks = total_blocks
            .checked_add(report.blocks_imported)
            .ok_or(QRunV06HistorySyncServiceError::PageBudgetExceeded)?;
        if report.complete {
            report.pages_imported = total_pages;
            report.blocks_imported = total_blocks;
            return Ok(report);
        }
        if report.pages_imported == 0 {
            return Err(QRunV06HistorySyncServiceError::NoProgress);
        }
    }
    Err(QRunV06HistorySyncServiceError::PageBudgetExceeded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        consensus::{ConsensusParameters, Uint256},
        external_cas_anchor_candidate::ExternalCasPin,
        qrun_v06_canonical_execution_candidate::QRunV06CanonicalExecutionState,
        qrun_v06_cp0604_supply_candidate::Cp0604FounderControlledSupply,
        qrun_v06_genesis_descriptor_candidate::QRunV06GenesisDescriptor,
        qrun_v06_hybrid_auth_candidate::QRunV06HybridTransactionAuthenticator,
        qrun_v06_permissionless_runtime_candidate::QRunV06PermissionlessNodeRuntime,
        qrun_v06_permissionless_service_candidate::QRunV06PermissionlessMempool,
        qrun_v06_profile_pin_candidate::{QRunV06ProfilePinCandidate, QRunV06VerifiedProfilePin},
        qrun_v06_tokenomics_candidate::QRunV06MiningScheduleCandidate,
        qrun_v06_transaction_mempool_candidate::QRunV06MempoolLimits,
        v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate,
        v4_fat1_trust_candidate::ML_DSA_65_PUBLIC_KEY_BYTES,
    };
    use std::{
        fs,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        thread,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn pinned_noise_sync_imports_a_heavier_competing_branch_and_recovers_after_restart() {
        const NETWORK: [u8; 32] = [0xD1; 32];
        const PROFILE: [u8; 32] = [0xD2; 32];
        const FOUNDER: [u8; 32] = [0xD3; 32];

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
            crate::qrun_v06_checkpoint_candidate::qrun_v06_consensus_fingerprint(&params).unwrap(),
            supply.policy_fingerprint(),
        )
        .unwrap();
        let genesis = QRunV06CanonicalExecutionState::cp0604_genesis_candidate_with_descriptor(
            descriptor.clone(),
            schedule,
        )
        .unwrap();
        let profile_bundle = QRunV06ProfilePinCandidate::new(
            descriptor,
            ExternalCasPin {
                provider_id: [0xD4; 32],
                network_id: NETWORK,
                genesis_digest: [0xD5; 32],
                receipt_key_id: [0xD6; 32],
                receipt_public_key: [0xD7; ML_DSA_65_PUBLIC_KEY_BYTES],
            },
        )
        .unwrap();
        let profile_pin_bytes = profile_bundle.encode().unwrap();
        let verified_pin = QRunV06VerifiedProfilePin::decode(
            &profile_pin_bytes,
            profile_bundle.commitment().unwrap(),
        )
        .unwrap();
        let authenticator =
            QRunV06HybridTransactionAuthenticator::new(LibcruxMlDsa65VerifierCandidate);

        let test_root = std::env::temp_dir().join(format!(
            "qfp6-branch-sync-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        let source_dir = test_root.join("source-store");
        let source_mempool_dir = test_root.join("source-mempool");
        let destination_dir = test_root.join("destination-store");
        let destination_mempool_dir = test_root.join("destination-mempool");
        fs::create_dir_all(&test_root).unwrap();

        let mut source_runtime = QRunV06PermissionlessNodeRuntime::open(
            &source_dir,
            genesis.clone(),
            params.clone(),
            &authenticator,
            None,
            &verified_pin,
        )
        .unwrap();
        let mut destination_runtime = QRunV06PermissionlessNodeRuntime::open(
            &destination_dir,
            genesis.clone(),
            params.clone(),
            &authenticator,
            None,
            &verified_pin,
        )
        .unwrap();
        let mut source_mempool = QRunV06PermissionlessMempool::open(
            &source_mempool_dir,
            QRunV06MempoolLimits::default(),
        )
        .unwrap();
        let mut destination_mempool = QRunV06PermissionlessMempool::open(
            &destination_mempool_dir,
            QRunV06MempoolLimits::default(),
        )
        .unwrap();
        let stop_mining = AtomicBool::new(false);
        let wall_clock = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let first_branch_timestamp = wall_clock.max(genesis.last_timestamp().saturating_add(60));
        destination_mempool
            .restore(
                &destination_runtime,
                &authenticator,
                FOUNDER,
                first_branch_timestamp,
            )
            .unwrap();
        source_mempool
            .restore(
                &source_runtime,
                &authenticator,
                FOUNDER,
                first_branch_timestamp,
            )
            .unwrap();

        // Both independent nodes mine the same deterministic first block from Genesis.
        let source_common = source_mempool
            .mine_one_batch(
                &mut source_runtime,
                &authenticator,
                FOUNDER,
                first_branch_timestamp,
                10_000,
                &stop_mining,
            )
            .unwrap()
            .unwrap();
        assert!(source_common.became_canonical);
        let destination_common = destination_mempool
            .mine_one_batch(
                &mut destination_runtime,
                &authenticator,
                FOUNDER,
                first_branch_timestamp,
                10_000,
                &stop_mining,
            )
            .unwrap()
            .unwrap();
        assert!(destination_common.became_canonical);
        let common_tip = source_runtime.status().unwrap().tip;
        assert_eq!(destination_runtime.status().unwrap().tip, common_tip);

        // The branches diverge at height two: destination has one block, source has two.
        let local_mined = destination_mempool
            .mine_one_batch(
                &mut destination_runtime,
                &authenticator,
                FOUNDER,
                first_branch_timestamp.saturating_add(120),
                10_000,
                &stop_mining,
            )
            .unwrap()
            .unwrap();
        assert!(local_mined.became_canonical);
        let local_tip = destination_runtime.status().unwrap().tip;
        for timestamp in [
            first_branch_timestamp.saturating_add(60),
            first_branch_timestamp.saturating_add(120),
        ] {
            let mined = source_mempool
                .mine_one_batch(
                    &mut source_runtime,
                    &authenticator,
                    FOUNDER,
                    timestamp,
                    10_000,
                    &stop_mining,
                )
                .unwrap()
                .unwrap();
            assert!(mined.became_canonical);
        }
        let source_status = source_runtime.status().unwrap();
        assert_eq!(source_status.height, 3);
        assert_ne!(source_status.tip, local_tip);
        let source_work = source_runtime
            .fork_choice_snapshot()
            .unwrap()
            .canonical_tip()
            .cumulative_work;
        let local_work = destination_runtime
            .fork_choice_snapshot()
            .unwrap()
            .canonical_tip()
            .cumulative_work;
        assert!(source_work > local_work);

        // The destination has only the authenticated source Noise key, not an anonymous peer.
        let noise_params = "Noise_XX_25519_ChaChaPoly_SHA256".parse().unwrap();
        let server_pair = snow::Builder::new(noise_params).generate_keypair().unwrap();
        let client_pair = snow::Builder::new("Noise_XX_25519_ChaChaPoly_SHA256".parse().unwrap())
            .generate_keypair()
            .unwrap();
        let server_private: [u8; 32] = server_pair.private.as_slice().try_into().unwrap();
        let server_public: [u8; 32] = server_pair.public.as_slice().try_into().unwrap();
        let client_private: [u8; 32] = client_pair.private.as_slice().try_into().unwrap();
        let client_public: [u8; 32] = client_pair.public.as_slice().try_into().unwrap();
        assert_ne!(server_private, [0; 32]);
        assert_ne!(client_private, [0; 32]);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let server_shutdown = shutdown.clone();
        let server = thread::spawn(move || {
            let mut listener_config = QRunV06PeerListenerConfig::default();
            listener_config.max_sessions = 8;
            listener_config.max_requests_per_session = 16;
            listener_config.accept_poll_interval = Duration::from_millis(10);
            serve_permissionless_history_sync_listener(
                &listener,
                listener_config,
                &server_private,
                &[client_public],
                &NETWORK,
                &PROFILE,
                server_shutdown.as_ref(),
                &source_runtime,
            )
        });

        // One page per Noise session forces reconnect and cursor resume mid-source-chain.
        let sync_config = QRunV06HistorySyncClientConfig {
            connect_timeout: Duration::from_secs(3),
            io_timeout: Duration::from_secs(5),
            max_blocks_per_page: 1,
            max_bytes_per_page: 1024 * 1024,
            max_pages: 1,
            max_rounds: 4,
        };
        let sync_result = sync_history_from_pinned_peer(
            address,
            &client_private,
            &server_public,
            &mut destination_runtime,
            &authenticator,
            sync_config,
        );
        shutdown.store(true, Ordering::Release);
        let server_report = server.join().unwrap().unwrap();
        let sync_report = sync_result.unwrap();
        assert!(server_report.stats.accepted_connections >= 3);
        assert_eq!(sync_report.source_height, 3);
        assert_eq!(sync_report.pages_imported, 3);
        assert_eq!(sync_report.blocks_imported, 3);
        assert!(sync_report.complete);

        let synchronized = destination_runtime.status().unwrap();
        let graph = destination_runtime.fork_choice_snapshot().unwrap();
        assert_eq!(synchronized.tip, source_status.tip);
        assert_eq!(synchronized.height, source_status.height);
        assert_eq!(synchronized.state_root, source_status.state_root);
        assert!(graph.reorg_count() >= 1);
        assert!(
            graph.archive_len() >= 4,
            "the common block and both competing branch suffixes must remain in the fork archive"
        );
        let trusted_manifest_anchor = synchronized.manifest_anchor;
        drop(destination_runtime);
        drop(destination_mempool);

        // A restart must rebuild the same canonical branch and retain the competing branch set.
        let recovered = QRunV06PermissionlessNodeRuntime::open(
            &destination_dir,
            genesis,
            params,
            &authenticator,
            Some(trusted_manifest_anchor),
            &verified_pin,
        )
        .unwrap();
        let recovered_status = recovered.status().unwrap();
        let recovered_graph = recovered.fork_choice_snapshot().unwrap();
        assert_eq!(recovered_status.tip, source_status.tip);
        assert_eq!(recovered_status.height, source_status.height);
        assert_eq!(recovered_status.state_root, source_status.state_root);
        assert!(recovered_graph.archive_len() >= 4);
        drop(recovered);
        drop(source_mempool);
        let _ = fs::remove_dir_all(test_root);
    }
}
