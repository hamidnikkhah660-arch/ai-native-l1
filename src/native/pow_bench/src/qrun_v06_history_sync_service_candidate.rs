//! CP-0597 one-snapshot QFP6 history responder and Noise page client.
//!
//! This module connects the CP-0596 bounded page codec to the permissionless durable runtime.
//! The responder retains at most one immutable fork-choice snapshot so subsequent page requests
//! can continue against the same canonical tip while the live node advances.

use crate::qrun_v06_peer_listener_candidate::{
    serve_qfp6_noise_history_listener, QRunV06PeerListenerConfig, QRunV06PeerListenerError,
    QRunV06PeerListenerReport,
};
use crate::{
    consensus::pow_digest,
    qrun_v06_history_sync_wire_candidate::{
        decode_q6hr_status, encode_q6hp_page_chunks, Q6HistorySyncWireError,
        QRunV06HistoryInfoRequest, QRunV06HistoryPageChunkAssembler, QRunV06HistorySyncRequest,
    },
    qrun_v06_noise_transport_candidate::{QRunV06NoiseError, QRunV06NoiseSession},
    qrun_v06_permissionless_runtime_candidate::{
        QRunV06HistorySyncError, QRunV06HistorySyncReport, QRunV06PermissionlessNodeRuntime,
        QRunV06PermissionlessRuntimeError,
    },
    qrun_v06_pow_fork_choice_candidate::QRunV06CanonicalHistoryPage,
    qrun_v06_pow_wire_candidate::decode_qrun_v06_pow_block,
    state_machine::TransactionAuthenticator,
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
        Ok(encode_q6hp_page_chunks(request, &page)?)
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
    serve_qfp6_noise_history_listener(
        listener,
        config,
        local_static_private_key,
        trusted_remote_static_public_keys,
        network_id,
        profile_id,
        shutdown,
        |request| {
            responder
                .respond(runtime, request)
                .map_err(|error| error.to_string())
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
    if source.height < local_start.height {
        return Err(QRunV06HistorySyncServiceError::SourceBehind);
    }
    let local_graph = runtime.fork_choice_snapshot()?;
    if source.height == local_start.height
        && (source.consensus_tip != local_start.tip
            || source.execution_tip != local_graph.canonical_state().tip_hash())
    {
        return Err(QRunV06HistorySyncServiceError::SnapshotMismatch);
    }

    let mut pages_imported = 0u32;
    let mut blocks_imported = 0u64;
    let mut request_id = 2u64;
    while runtime.status()?.height < source.height {
        if pages_imported >= config.max_pages {
            return Err(QRunV06HistorySyncServiceError::PageBudgetExceeded);
        }
        let request = make_next_history_request(
            runtime,
            request_id,
            source.consensus_tip,
            config.max_blocks_per_page,
            config.max_bytes_per_page,
        )?;
        let params = runtime
            .fork_choice_snapshot()?
            .consensus_parameters()
            .clone();
        let page = request_history_page_over_noise(&mut noise, &mut stream, request, params)?;
        if page.snapshot_height != source.height || page.snapshot_tip != source.consensus_tip {
            return Err(QRunV06HistorySyncServiceError::SnapshotMismatch);
        }
        if page.envelopes.is_empty() {
            return Err(QRunV06HistorySyncServiceError::NoProgress);
        }
        let imported_count = page.envelopes.len() as u64;
        let complete = page.complete;
        import_history_page(runtime, &page, authenticator)?;
        pages_imported = pages_imported
            .checked_add(1)
            .ok_or(QRunV06HistorySyncServiceError::PageBudgetExceeded)?;
        blocks_imported = blocks_imported
            .checked_add(imported_count)
            .ok_or(QRunV06HistorySyncServiceError::PageBudgetExceeded)?;
        request_id = request_id
            .checked_add(1)
            .ok_or(QRunV06HistorySyncServiceError::PageBudgetExceeded)?;
        if complete {
            break;
        }
    }

    let final_status = runtime.status()?;
    if final_status.height > source.height {
        return Err(QRunV06HistorySyncServiceError::SnapshotMismatch);
    }
    let complete = final_status.height == source.height;
    if complete {
        let final_graph = runtime.fork_choice_snapshot()?;
        if final_status.tip != source.consensus_tip
            || final_graph.canonical_state().tip_hash() != source.execution_tip
        {
            return Err(QRunV06HistorySyncServiceError::SnapshotMismatch);
        }
    } else if pages_imported != config.max_pages {
        return Err(QRunV06HistorySyncServiceError::NoProgress);
    }
    Ok(QRunV06HistorySyncClientReport {
        source_height: source.height,
        final_height: final_status.height,
        pages_imported,
        blocks_imported,
        source_tip: source.consensus_tip,
        complete,
    })
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
