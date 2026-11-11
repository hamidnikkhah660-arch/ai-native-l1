//! CP-0596 bounded QFP6 history request and chunked response wire codec.
//!
//! History pages are split into small authenticated Noise application records. A complete
//! canonical page may exceed the single-message limit of the Noise transport, so this codec
//! never assumes that one 16 MiB history batch fits in one Noise record.

use crate::{
    consensus::{pow_digest, ConsensusParameters},
    qrun_v06_canonical_execution_candidate::qrun_v06_block_id,
    qrun_v06_pow_fork_choice_candidate::QRunV06CanonicalHistoryPage,
    qrun_v06_pow_wire_candidate::decode_qrun_v06_pow_block,
};
use sha2::{Digest, Sha256};

pub const Q6HI_REQUEST_MAGIC: [u8; 4] = *b"Q6HI";
pub const Q6HR_STATUS_MAGIC: [u8; 4] = *b"Q6HR";
pub const Q6HI_REQUEST_BYTES: usize = 80;
pub const Q6HR_STATUS_BYTES: usize = 152;
pub const Q6HS_REQUEST_MAGIC: [u8; 4] = *b"Q6HS";
pub const Q6HP_PAGE_MAGIC: [u8; 4] = *b"Q6HP";
pub const Q6HC_CHUNK_MAGIC: [u8; 4] = *b"Q6HC";
pub const Q6_HISTORY_SYNC_WIRE_VERSION: u16 = 1;
pub const Q6HS_REQUEST_BYTES: usize = 192;
pub const Q6HP_PAGE_HEADER_BYTES: usize = 80;
pub const Q6HC_CHUNK_HEADER_BYTES: usize = 96;
pub const Q6HC_CHUNK_PAYLOAD_BYTES: usize = 48 * 1024;
pub const Q6_HISTORY_SYNC_MAX_BLOCKS: usize = 128;
pub const Q6_HISTORY_SYNC_MAX_BYTES: usize = 16 * 1024 * 1024;
pub const Q6_HISTORY_SYNC_MAX_PAGE_WIRE_BYTES: usize =
    Q6_HISTORY_SYNC_MAX_BYTES + Q6_HISTORY_SYNC_MAX_BLOCKS * 4 + Q6HP_PAGE_HEADER_BYTES;
pub const Q6_HISTORY_SYNC_MAX_CHUNKS: usize =
    Q6_HISTORY_SYNC_MAX_PAGE_WIRE_BYTES.div_ceil(Q6HC_CHUNK_PAYLOAD_BYTES);

const Q6HP_COMPLETE_FLAG: u16 = 1;
const Q6HC_FINAL_FLAG: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Q6HistorySyncWireError {
    InvalidRequest,
    MalformedRequest,
    InvalidStatus,
    MalformedStatus,
    WrongRequest,
    MalformedChunk,
    Oversized,
    ChunkOrder,
    ChunkMetadataMismatch,
    PayloadChecksumMismatch,
    MalformedPage,
    WrongNetwork,
    WrongProfile,
    NonContiguous,
    Consensus(String),
    AlreadyComplete,
    Poisoned,
}

impl std::fmt::Display for Q6HistorySyncWireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "QFP6 history-sync wire rejected input: {self:?}")
    }
}
impl std::error::Error for Q6HistorySyncWireError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06HistoryInfoRequest {
    pub request_id: u64,
    pub network_id: [u8; 32],
    pub profile_id: [u8; 32],
}

impl QRunV06HistoryInfoRequest {
    pub fn encode(&self) -> Result<[u8; Q6HI_REQUEST_BYTES], Q6HistorySyncWireError> {
        if self.request_id == 0 || is_zero(&self.network_id) || is_zero(&self.profile_id) {
            return Err(Q6HistorySyncWireError::InvalidRequest);
        }
        let mut out = [0u8; Q6HI_REQUEST_BYTES];
        out[..4].copy_from_slice(&Q6HI_REQUEST_MAGIC);
        out[4..6].copy_from_slice(&Q6_HISTORY_SYNC_WIRE_VERSION.to_be_bytes());
        out[6..8].copy_from_slice(&0u16.to_be_bytes());
        out[8..16].copy_from_slice(&self.request_id.to_be_bytes());
        out[16..48].copy_from_slice(&self.network_id);
        out[48..80].copy_from_slice(&self.profile_id);
        Ok(out)
    }
}

pub fn decode_q6hi_request(
    bytes: &[u8],
) -> Result<QRunV06HistoryInfoRequest, Q6HistorySyncWireError> {
    if bytes.len() != Q6HI_REQUEST_BYTES || bytes[..4] != Q6HI_REQUEST_MAGIC {
        return Err(Q6HistorySyncWireError::MalformedRequest);
    }
    if u16_at(bytes, 4)? != Q6_HISTORY_SYNC_WIRE_VERSION || u16_at(bytes, 6)? != 0 {
        return Err(Q6HistorySyncWireError::MalformedRequest);
    }
    let request = QRunV06HistoryInfoRequest {
        request_id: u64_at(bytes, 8)?,
        network_id: array_at(bytes, 16)?,
        profile_id: array_at(bytes, 48)?,
    };
    if request.request_id == 0 || is_zero(&request.network_id) || is_zero(&request.profile_id) {
        return Err(Q6HistorySyncWireError::InvalidRequest);
    }
    Ok(request)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06HistoryInfoResponse {
    pub request_id: u64,
    pub network_id: [u8; 32],
    pub profile_id: [u8; 32],
    pub height: u64,
    pub consensus_tip: [u8; 32],
    pub execution_tip: [u8; 32],
}

pub fn encode_q6hr_status(
    request: &QRunV06HistoryInfoRequest,
    height: u64,
    consensus_tip: [u8; 32],
    execution_tip: [u8; 32],
) -> Result<[u8; Q6HR_STATUS_BYTES], Q6HistorySyncWireError> {
    if request.request_id == 0
        || is_zero(&request.network_id)
        || is_zero(&request.profile_id)
        || is_zero(&consensus_tip)
        || is_zero(&execution_tip)
    {
        return Err(Q6HistorySyncWireError::InvalidStatus);
    }
    let mut out = [0u8; Q6HR_STATUS_BYTES];
    out[..4].copy_from_slice(&Q6HR_STATUS_MAGIC);
    out[4..6].copy_from_slice(&Q6_HISTORY_SYNC_WIRE_VERSION.to_be_bytes());
    out[6..8].copy_from_slice(&0u16.to_be_bytes());
    out[8..16].copy_from_slice(&request.request_id.to_be_bytes());
    out[16..48].copy_from_slice(&request.network_id);
    out[48..80].copy_from_slice(&request.profile_id);
    out[80..88].copy_from_slice(&height.to_be_bytes());
    out[88..120].copy_from_slice(&consensus_tip);
    out[120..152].copy_from_slice(&execution_tip);
    Ok(out)
}

pub fn decode_q6hr_status(
    bytes: &[u8],
    request: &QRunV06HistoryInfoRequest,
) -> Result<QRunV06HistoryInfoResponse, Q6HistorySyncWireError> {
    if bytes.len() != Q6HR_STATUS_BYTES || bytes[..4] != Q6HR_STATUS_MAGIC {
        return Err(Q6HistorySyncWireError::MalformedStatus);
    }
    if u16_at(bytes, 4)? != Q6_HISTORY_SYNC_WIRE_VERSION || u16_at(bytes, 6)? != 0 {
        return Err(Q6HistorySyncWireError::MalformedStatus);
    }
    let response = QRunV06HistoryInfoResponse {
        request_id: u64_at(bytes, 8)?,
        network_id: array_at(bytes, 16)?,
        profile_id: array_at(bytes, 48)?,
        height: u64_at(bytes, 80)?,
        consensus_tip: array_at(bytes, 88)?,
        execution_tip: array_at(bytes, 120)?,
    };
    if response.request_id != request.request_id {
        return Err(Q6HistorySyncWireError::WrongRequest);
    }
    if response.network_id != request.network_id {
        return Err(Q6HistorySyncWireError::WrongNetwork);
    }
    if response.profile_id != request.profile_id {
        return Err(Q6HistorySyncWireError::WrongProfile);
    }
    if is_zero(&response.consensus_tip) || is_zero(&response.execution_tip) {
        return Err(Q6HistorySyncWireError::InvalidStatus);
    }
    Ok(response)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06HistorySyncRequest {
    pub request_id: u64,
    pub network_id: [u8; 32],
    pub profile_id: [u8; 32],
    pub snapshot_tip: [u8; 32],
    pub expected_parent_consensus_hash: [u8; 32],
    pub expected_parent_execution_hash: [u8; 32],
    pub start_height: u64,
    pub max_blocks: u16,
    pub max_bytes: u32,
}

impl QRunV06HistorySyncRequest {
    pub fn validate(&self) -> Result<(), Q6HistorySyncWireError> {
        if self.request_id == 0
            || is_zero(&self.network_id)
            || is_zero(&self.profile_id)
            || is_zero(&self.snapshot_tip)
            || self.start_height == 0
            || self.max_blocks == 0
            || usize::from(self.max_blocks) > Q6_HISTORY_SYNC_MAX_BLOCKS
            || self.max_bytes == 0
            || self.max_bytes as usize > Q6_HISTORY_SYNC_MAX_BYTES
        {
            return Err(Q6HistorySyncWireError::InvalidRequest);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<[u8; Q6HS_REQUEST_BYTES], Q6HistorySyncWireError> {
        self.validate()?;
        let mut out = [0u8; Q6HS_REQUEST_BYTES];
        out[..4].copy_from_slice(&Q6HS_REQUEST_MAGIC);
        out[4..6].copy_from_slice(&Q6_HISTORY_SYNC_WIRE_VERSION.to_be_bytes());
        out[6..8].copy_from_slice(&1u16.to_be_bytes());
        out[8..16].copy_from_slice(&self.request_id.to_be_bytes());
        out[16..48].copy_from_slice(&self.network_id);
        out[48..80].copy_from_slice(&self.profile_id);
        out[80..112].copy_from_slice(&self.snapshot_tip);
        out[112..144].copy_from_slice(&self.expected_parent_consensus_hash);
        out[144..176].copy_from_slice(&self.expected_parent_execution_hash);
        out[176..184].copy_from_slice(&self.start_height.to_be_bytes());
        out[184..186].copy_from_slice(&self.max_blocks.to_be_bytes());
        out[188..192].copy_from_slice(&self.max_bytes.to_be_bytes());
        Ok(out)
    }
}

pub fn decode_q6hs_request(
    bytes: &[u8],
) -> Result<QRunV06HistorySyncRequest, Q6HistorySyncWireError> {
    if bytes.len() != Q6HS_REQUEST_BYTES || bytes[..4] != Q6HS_REQUEST_MAGIC {
        return Err(Q6HistorySyncWireError::MalformedRequest);
    }
    if u16_at(bytes, 4)? != Q6_HISTORY_SYNC_WIRE_VERSION
        || u16_at(bytes, 6)? != 1
        || bytes[186..188] != [0, 0]
    {
        return Err(Q6HistorySyncWireError::MalformedRequest);
    }
    let request = QRunV06HistorySyncRequest {
        request_id: u64_at(bytes, 8)?,
        network_id: array_at(bytes, 16)?,
        profile_id: array_at(bytes, 48)?,
        snapshot_tip: array_at(bytes, 80)?,
        expected_parent_consensus_hash: array_at(bytes, 112)?,
        expected_parent_execution_hash: array_at(bytes, 144)?,
        start_height: u64_at(bytes, 176)?,
        max_blocks: u16_at(bytes, 184)?,
        max_bytes: u32_at(bytes, 188)?,
    };
    request.validate()?;
    Ok(request)
}

/// Encode one bounded canonical history page as ordered Q6HC chunks. Each frame is at most
/// 48 KiB plus its 96-byte header, safely below a single Noise application record limit.
pub fn encode_q6hp_page_chunks(
    request: &QRunV06HistorySyncRequest,
    page: &QRunV06CanonicalHistoryPage,
) -> Result<Vec<Vec<u8>>, Q6HistorySyncWireError> {
    request.validate()?;
    if page.start_height != request.start_height
        || page.snapshot_tip != request.snapshot_tip
        || page.envelopes.len() > usize::from(request.max_blocks)
        || page.envelopes.is_empty() && !page.complete
        || page.envelopes.iter().any(Vec::is_empty)
    {
        return Err(Q6HistorySyncWireError::MalformedPage);
    }
    let mut envelope_bytes = 0usize;
    for envelope in &page.envelopes {
        envelope_bytes = envelope_bytes
            .checked_add(envelope.len())
            .ok_or(Q6HistorySyncWireError::Oversized)?;
        if envelope_bytes > request.max_bytes as usize {
            return Err(Q6HistorySyncWireError::Oversized);
        }
    }
    let expected_next = page
        .start_height
        .checked_add(page.envelopes.len() as u64)
        .ok_or(Q6HistorySyncWireError::MalformedPage)?;
    let after_snapshot = page
        .snapshot_height
        .checked_add(1)
        .ok_or(Q6HistorySyncWireError::MalformedPage)?;
    if page.next_height != expected_next
        || page.start_height > after_snapshot
        || page.complete != (page.next_height > page.snapshot_height)
        || (page.complete && page.next_height != after_snapshot)
    {
        return Err(Q6HistorySyncWireError::MalformedPage);
    }

    let mut payload =
        Vec::with_capacity(Q6HP_PAGE_HEADER_BYTES + envelope_bytes + page.envelopes.len() * 4);
    payload.extend_from_slice(&Q6HP_PAGE_MAGIC);
    payload.extend_from_slice(&Q6_HISTORY_SYNC_WIRE_VERSION.to_be_bytes());
    payload.extend_from_slice(&(if page.complete { Q6HP_COMPLETE_FLAG } else { 0 }).to_be_bytes());
    payload.extend_from_slice(&request.request_id.to_be_bytes());
    payload.extend_from_slice(&page.snapshot_tip);
    payload.extend_from_slice(&page.snapshot_height.to_be_bytes());
    payload.extend_from_slice(&page.start_height.to_be_bytes());
    payload.extend_from_slice(&page.next_height.to_be_bytes());
    payload.extend_from_slice(&(page.envelopes.len() as u16).to_be_bytes());
    payload.extend_from_slice(&0u16.to_be_bytes());
    let entry_section_bytes = envelope_bytes
        .checked_add(page.envelopes.len() * 4)
        .ok_or(Q6HistorySyncWireError::Oversized)?;
    payload.extend_from_slice(&(entry_section_bytes as u32).to_be_bytes());
    for envelope in &page.envelopes {
        let len = u32::try_from(envelope.len()).map_err(|_| Q6HistorySyncWireError::Oversized)?;
        payload.extend_from_slice(&len.to_be_bytes());
        payload.extend_from_slice(envelope);
    }
    if payload.len() > Q6_HISTORY_SYNC_MAX_PAGE_WIRE_BYTES {
        return Err(Q6HistorySyncWireError::Oversized);
    }

    let digest: [u8; 32] = Sha256::digest(&payload).into();
    let total_len = payload.len();
    let chunk_count = total_len.div_ceil(Q6HC_CHUNK_PAYLOAD_BYTES);
    if chunk_count == 0 || chunk_count > Q6_HISTORY_SYNC_MAX_CHUNKS {
        return Err(Q6HistorySyncWireError::Oversized);
    }
    let mut chunks = Vec::with_capacity(chunk_count);
    for (index, part) in payload.chunks(Q6HC_CHUNK_PAYLOAD_BYTES).enumerate() {
        let mut frame = Vec::with_capacity(Q6HC_CHUNK_HEADER_BYTES + part.len());
        frame.extend_from_slice(&Q6HC_CHUNK_MAGIC);
        frame.extend_from_slice(&Q6_HISTORY_SYNC_WIRE_VERSION.to_be_bytes());
        frame.extend_from_slice(
            &(if index + 1 == chunk_count {
                Q6HC_FINAL_FLAG
            } else {
                0
            })
            .to_be_bytes(),
        );
        frame.extend_from_slice(&request.request_id.to_be_bytes());
        frame.extend_from_slice(&(index as u32).to_be_bytes());
        frame.extend_from_slice(&(chunk_count as u32).to_be_bytes());
        frame.extend_from_slice(&(total_len as u32).to_be_bytes());
        frame.extend_from_slice(&(part.len() as u32).to_be_bytes());
        frame.extend_from_slice(&page.snapshot_tip);
        frame.extend_from_slice(&digest);
        frame.extend_from_slice(part);
        chunks.push(frame);
    }
    Ok(chunks)
}

pub struct QRunV06HistoryPageChunkAssembler {
    request: QRunV06HistorySyncRequest,
    params: ConsensusParameters,
    chunk_count: Option<u32>,
    total_len: Option<usize>,
    snapshot_tip: Option<[u8; 32]>,
    payload_digest: Option<[u8; 32]>,
    next_chunk: u32,
    payload: Vec<u8>,
    complete: bool,
    poisoned: bool,
}

impl QRunV06HistoryPageChunkAssembler {
    pub fn new(
        request: QRunV06HistorySyncRequest,
        params: ConsensusParameters,
    ) -> Result<Self, Q6HistorySyncWireError> {
        request.validate()?;
        Ok(Self {
            request,
            params,
            chunk_count: None,
            total_len: None,
            snapshot_tip: None,
            payload_digest: None,
            next_chunk: 0,
            payload: Vec::new(),
            complete: false,
            poisoned: false,
        })
    }

    /// Accept exactly the next authenticated Noise application chunk. Returns the verified
    /// canonical page only after the full-page SHA-256 and all parent/height bindings pass.
    pub fn push(
        &mut self,
        frame: &[u8],
    ) -> Result<Option<QRunV06CanonicalHistoryPage>, Q6HistorySyncWireError> {
        if self.poisoned {
            return Err(Q6HistorySyncWireError::Poisoned);
        }
        if self.complete {
            return Err(Q6HistorySyncWireError::AlreadyComplete);
        }
        let parsed = parse_chunk(frame)?;
        if parsed.request_id != self.request.request_id
            || parsed.snapshot_tip != self.request.snapshot_tip
        {
            return Err(Q6HistorySyncWireError::WrongRequest);
        }
        if parsed.chunk_index != self.next_chunk {
            return Err(Q6HistorySyncWireError::ChunkOrder);
        }
        if let Some(count) = self.chunk_count {
            if parsed.chunk_count != count
                || Some(parsed.total_len) != self.total_len
                || Some(parsed.snapshot_tip) != self.snapshot_tip
                || Some(parsed.payload_digest) != self.payload_digest
            {
                return Err(Q6HistorySyncWireError::ChunkMetadataMismatch);
            }
        } else {
            if parsed.chunk_index != 0 {
                return Err(Q6HistorySyncWireError::ChunkOrder);
            }
            self.chunk_count = Some(parsed.chunk_count);
            self.total_len = Some(parsed.total_len);
            self.snapshot_tip = Some(parsed.snapshot_tip);
            self.payload_digest = Some(parsed.payload_digest);
            self.payload = Vec::with_capacity(parsed.total_len);
        }

        self.payload.extend_from_slice(parsed.payload);
        self.next_chunk += 1;
        if self.next_chunk < parsed.chunk_count {
            return Ok(None);
        }
        if self.payload.len() != parsed.total_len {
            self.poisoned = true;
            return Err(Q6HistorySyncWireError::MalformedChunk);
        }
        let digest: [u8; 32] = Sha256::digest(&self.payload).into();
        if Some(digest) != self.payload_digest {
            self.poisoned = true;
            return Err(Q6HistorySyncWireError::PayloadChecksumMismatch);
        }
        let page =
            decode_page_payload(&self.payload, &self.request, &self.params).map_err(|error| {
                self.poisoned = true;
                error
            })?;
        self.complete = true;
        Ok(Some(page))
    }
}

struct ParsedChunk<'a> {
    request_id: u64,
    chunk_index: u32,
    chunk_count: u32,
    total_len: usize,
    snapshot_tip: [u8; 32],
    payload_digest: [u8; 32],
    payload: &'a [u8],
}

/// Validate one response chunk before a server writes it to an authenticated Noise peer.
pub fn validate_q6hc_response_chunk(
    frame: &[u8],
    request_id: u64,
    snapshot_tip: &[u8; 32],
    expected_index: u32,
) -> Result<(), Q6HistorySyncWireError> {
    let parsed = parse_chunk(frame)?;
    if parsed.request_id != request_id || &parsed.snapshot_tip != snapshot_tip {
        return Err(Q6HistorySyncWireError::WrongRequest);
    }
    if parsed.chunk_index != expected_index {
        return Err(Q6HistorySyncWireError::ChunkOrder);
    }
    Ok(())
}

/// Validate an entire response sequence before any chunk is written to the peer.
/// This prevents a local handler from emitting a truncated or mixed-metadata page.
pub fn validate_q6hc_response_sequence(
    chunks: &[Vec<u8>],
    request_id: u64,
    snapshot_tip: &[u8; 32],
) -> Result<(), Q6HistorySyncWireError> {
    if chunks.is_empty() || chunks.len() > Q6_HISTORY_SYNC_MAX_CHUNKS {
        return Err(Q6HistorySyncWireError::Oversized);
    }
    let first = parse_chunk(&chunks[0])?;
    if first.request_id != request_id
        || &first.snapshot_tip != snapshot_tip
        || first.chunk_index != 0
        || first.chunk_count as usize != chunks.len()
    {
        return Err(Q6HistorySyncWireError::ChunkMetadataMismatch);
    }
    for (index, frame) in chunks.iter().enumerate() {
        let parsed = parse_chunk(frame)?;
        if parsed.request_id != request_id
            || &parsed.snapshot_tip != snapshot_tip
            || parsed.chunk_index as usize != index
            || parsed.chunk_count != first.chunk_count
            || parsed.total_len != first.total_len
            || parsed.payload_digest != first.payload_digest
        {
            return Err(Q6HistorySyncWireError::ChunkMetadataMismatch);
        }
    }
    Ok(())
}

fn parse_chunk(frame: &[u8]) -> Result<ParsedChunk<'_>, Q6HistorySyncWireError> {
    if frame.len() < Q6HC_CHUNK_HEADER_BYTES || frame[..4] != Q6HC_CHUNK_MAGIC {
        return Err(Q6HistorySyncWireError::MalformedChunk);
    }
    if u16_at(frame, 4)? != Q6_HISTORY_SYNC_WIRE_VERSION {
        return Err(Q6HistorySyncWireError::MalformedChunk);
    }
    let flags = u16_at(frame, 6)?;
    let request_id = u64_at(frame, 8)?;
    let chunk_index = u32_at(frame, 16)?;
    let chunk_count = u32_at(frame, 20)?;
    let total_len = u32_at(frame, 24)? as usize;
    let payload_len = u32_at(frame, 28)? as usize;
    let snapshot_tip = array_at(frame, 32)?;
    let payload_digest = array_at(frame, 64)?;
    if request_id == 0
        || chunk_count == 0
        || chunk_count as usize > Q6_HISTORY_SYNC_MAX_CHUNKS
        || chunk_index >= chunk_count
        || total_len == 0
        || total_len > Q6_HISTORY_SYNC_MAX_PAGE_WIRE_BYTES
        || payload_len == 0
        || payload_len > Q6HC_CHUNK_PAYLOAD_BYTES
        || frame.len() != Q6HC_CHUNK_HEADER_BYTES + payload_len
        || is_zero(&snapshot_tip)
        || is_zero(&payload_digest)
    {
        return Err(Q6HistorySyncWireError::MalformedChunk);
    }
    let expected_count = total_len.div_ceil(Q6HC_CHUNK_PAYLOAD_BYTES);
    let chunk_offset = (chunk_index as usize)
        .checked_mul(Q6HC_CHUNK_PAYLOAD_BYTES)
        .ok_or(Q6HistorySyncWireError::MalformedChunk)?;
    if chunk_offset >= total_len {
        return Err(Q6HistorySyncWireError::MalformedChunk);
    }
    let expected_len = (total_len - chunk_offset).min(Q6HC_CHUNK_PAYLOAD_BYTES);
    let is_final = chunk_index + 1 == chunk_count;
    if chunk_count as usize != expected_count
        || payload_len != expected_len
        || flags != if is_final { Q6HC_FINAL_FLAG } else { 0 }
    {
        return Err(Q6HistorySyncWireError::MalformedChunk);
    }
    Ok(ParsedChunk {
        request_id,
        chunk_index,
        chunk_count,
        total_len,
        snapshot_tip,
        payload_digest,
        payload: &frame[Q6HC_CHUNK_HEADER_BYTES..],
    })
}

fn decode_page_payload(
    bytes: &[u8],
    request: &QRunV06HistorySyncRequest,
    params: &ConsensusParameters,
) -> Result<QRunV06CanonicalHistoryPage, Q6HistorySyncWireError> {
    if bytes.len() < Q6HP_PAGE_HEADER_BYTES || bytes[..4] != Q6HP_PAGE_MAGIC {
        return Err(Q6HistorySyncWireError::MalformedPage);
    }
    if u16_at(bytes, 4)? != Q6_HISTORY_SYNC_WIRE_VERSION {
        return Err(Q6HistorySyncWireError::MalformedPage);
    }
    let flags = u16_at(bytes, 6)?;
    if flags & !Q6HP_COMPLETE_FLAG != 0
        || u64_at(bytes, 8)? != request.request_id
        || array_at::<32>(bytes, 16)? != request.snapshot_tip
        || u16_at(bytes, 74)? != 0
    {
        return Err(Q6HistorySyncWireError::WrongRequest);
    }
    let snapshot_tip = array_at(bytes, 16)?;
    let snapshot_height = u64_at(bytes, 48)?;
    let start_height = u64_at(bytes, 56)?;
    let next_height = u64_at(bytes, 64)?;
    let entry_count = u16_at(bytes, 72)? as usize;
    let declared_payload_bytes = u32_at(bytes, 76)? as usize;
    let max_entry_section_bytes = (request.max_bytes as usize)
        .checked_add(entry_count.saturating_mul(4))
        .ok_or(Q6HistorySyncWireError::Oversized)?;
    if start_height != request.start_height
        || entry_count > usize::from(request.max_blocks)
        || declared_payload_bytes > max_entry_section_bytes
        || bytes.len() != Q6HP_PAGE_HEADER_BYTES + declared_payload_bytes
        || snapshot_height.checked_add(1).is_none()
    {
        return Err(Q6HistorySyncWireError::MalformedPage);
    }
    let complete = flags & Q6HP_COMPLETE_FLAG != 0;
    let expected_next = start_height
        .checked_add(entry_count as u64)
        .ok_or(Q6HistorySyncWireError::MalformedPage)?;
    if next_height != expected_next
        || complete != (next_height > snapshot_height)
        || snapshot_height
            .checked_add(1)
            .is_none_or(|after_tip| start_height > after_tip)
        || (!complete && entry_count == 0)
    {
        return Err(Q6HistorySyncWireError::MalformedPage);
    }

    let mut offset = Q6HP_PAGE_HEADER_BYTES;
    let mut envelopes = Vec::with_capacity(entry_count);
    let mut envelope_bytes = 0usize;
    let mut expected_consensus_parent = request.expected_parent_consensus_hash;
    let mut expected_execution_parent = request.expected_parent_execution_hash;
    let mut last_digest = None;
    for index in 0..entry_count {
        if offset.checked_add(4).is_none_or(|end| end > bytes.len()) {
            return Err(Q6HistorySyncWireError::MalformedPage);
        }
        let length = u32_at(bytes, offset)? as usize;
        offset += 4;
        if length == 0
            || length > crate::qrun_v06_pow_wire_candidate::MAX_QRUN_V06_POW_ENVELOPE_BYTES
            || offset
                .checked_add(length)
                .is_none_or(|end| end > bytes.len())
        {
            return Err(Q6HistorySyncWireError::Oversized);
        }
        envelope_bytes = envelope_bytes
            .checked_add(length)
            .ok_or(Q6HistorySyncWireError::Oversized)?;
        if envelope_bytes > request.max_bytes as usize {
            return Err(Q6HistorySyncWireError::Oversized);
        }
        let envelope = &bytes[offset..offset + length];
        offset += length;
        let decoded = decode_qrun_v06_pow_block(envelope)
            .map_err(|_| Q6HistorySyncWireError::MalformedPage)?;
        if decoded.header.network_id != request.network_id
            || decoded.block.network_id != request.network_id
        {
            return Err(Q6HistorySyncWireError::WrongNetwork);
        }
        if decoded.block.profile_id != request.profile_id {
            return Err(Q6HistorySyncWireError::WrongProfile);
        }
        let expected_height = start_height
            .checked_add(index as u64)
            .ok_or(Q6HistorySyncWireError::MalformedPage)?;
        if decoded.header.height != expected_height
            || decoded.block.height != expected_height
            || decoded.header.previous_consensus_hash != expected_consensus_parent
            || decoded.block.parent_hash != expected_execution_parent
            || decoded.header.parent_hash != decoded.block.parent_hash
        {
            return Err(Q6HistorySyncWireError::NonContiguous);
        }
        let digest = pow_digest(&decoded.header, params.pow)
            .map_err(|error| Q6HistorySyncWireError::Consensus(error.to_string()))?;
        let execution_id = qrun_v06_block_id(&decoded.block)
            .map_err(|error| Q6HistorySyncWireError::Consensus(format!("{error:?}")))?;
        expected_consensus_parent = digest;
        expected_execution_parent = execution_id;
        last_digest = Some(digest);
        envelopes.push(envelope.to_vec());
    }
    if offset != bytes.len()
        || offset - Q6HP_PAGE_HEADER_BYTES != declared_payload_bytes
        || envelope_bytes > request.max_bytes as usize
    {
        return Err(Q6HistorySyncWireError::MalformedPage);
    }
    if complete {
        if next_height != snapshot_height + 1
            || (entry_count > 0 && last_digest != Some(snapshot_tip))
            || (entry_count == 0 && request.expected_parent_consensus_hash != snapshot_tip)
        {
            return Err(Q6HistorySyncWireError::MalformedPage);
        }
    }
    Ok(QRunV06CanonicalHistoryPage {
        start_height,
        next_height,
        snapshot_height,
        snapshot_tip,
        complete,
        envelopes,
    })
}

fn is_zero(bytes: &[u8; 32]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, Q6HistorySyncWireError> {
    let end = offset
        .checked_add(2)
        .ok_or(Q6HistorySyncWireError::MalformedChunk)?;
    let slice = bytes
        .get(offset..end)
        .ok_or(Q6HistorySyncWireError::MalformedChunk)?;
    Ok(u16::from_be_bytes([slice[0], slice[1]]))
}
fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, Q6HistorySyncWireError> {
    let end = offset
        .checked_add(4)
        .ok_or(Q6HistorySyncWireError::MalformedChunk)?;
    let slice = bytes
        .get(offset..end)
        .ok_or(Q6HistorySyncWireError::MalformedChunk)?;
    Ok(u32::from_be_bytes(slice.try_into().unwrap()))
}
fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, Q6HistorySyncWireError> {
    let end = offset
        .checked_add(8)
        .ok_or(Q6HistorySyncWireError::MalformedChunk)?;
    let slice = bytes
        .get(offset..end)
        .ok_or(Q6HistorySyncWireError::MalformedChunk)?;
    Ok(u64::from_be_bytes(slice.try_into().unwrap()))
}
fn array_at<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], Q6HistorySyncWireError> {
    let end = offset
        .checked_add(N)
        .ok_or(Q6HistorySyncWireError::MalformedChunk)?;
    let slice = bytes
        .get(offset..end)
        .ok_or(Q6HistorySyncWireError::MalformedChunk)?;
    Ok(slice.try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> QRunV06HistorySyncRequest {
        QRunV06HistorySyncRequest {
            request_id: 9,
            network_id: [0x11; 32],
            profile_id: [0x22; 32],
            snapshot_tip: [0x33; 32],
            expected_parent_consensus_hash: [0x44; 32],
            expected_parent_execution_hash: [0x55; 32],
            start_height: 8,
            max_blocks: 64,
            max_bytes: 1024 * 1024,
        }
    }

    #[test]
    fn q6hi_q6hr_status_roundtrips_and_binds_authenticated_peer_request() {
        let request = QRunV06HistoryInfoRequest {
            request_id: 41,
            network_id: [0x31; 32],
            profile_id: [0x42; 32],
        };
        let encoded_request = request.encode().unwrap();
        assert_eq!(encoded_request.len(), Q6HI_REQUEST_BYTES);
        let decoded_request = decode_q6hi_request(&encoded_request).unwrap();
        assert_eq!(decoded_request, request);

        let encoded_status = encode_q6hr_status(&request, 987, [0x53; 32], [0x64; 32]).unwrap();
        assert_eq!(encoded_status.len(), Q6HR_STATUS_BYTES);
        let decoded_status = decode_q6hr_status(&encoded_status, &request).unwrap();
        assert_eq!(decoded_status.height, 987);
        assert_eq!(decoded_status.consensus_tip, [0x53; 32]);
        assert_eq!(decoded_status.execution_tip, [0x64; 32]);

        let mut wrong_id = encoded_status;
        wrong_id[15] ^= 1;
        assert_eq!(
            decode_q6hr_status(&wrong_id, &request),
            Err(Q6HistorySyncWireError::WrongRequest)
        );
    }

    #[test]
    fn q6hs_request_is_fixed_width_canonical_and_roundtrips() {
        let request = request();
        let encoded = request.encode().unwrap();
        assert_eq!(encoded.len(), Q6HS_REQUEST_BYTES);
        assert_eq!(decode_q6hs_request(&encoded).unwrap(), request);

        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert_eq!(
            decode_q6hs_request(&trailing),
            Err(Q6HistorySyncWireError::MalformedRequest)
        );
        let mut reserved = encoded;
        reserved[186] = 1;
        assert_eq!(
            decode_q6hs_request(&reserved),
            Err(Q6HistorySyncWireError::MalformedRequest)
        );
    }

    #[test]
    fn q6hs_request_rejects_zero_identity_and_unbounded_limits() {
        let mut invalid = request();
        invalid.network_id = [0; 32];
        assert_eq!(
            invalid.encode(),
            Err(Q6HistorySyncWireError::InvalidRequest)
        );
        let mut invalid = request();
        invalid.max_blocks = 129;
        assert_eq!(
            invalid.encode(),
            Err(Q6HistorySyncWireError::InvalidRequest)
        );
        let mut invalid = request();
        invalid.max_bytes = (Q6_HISTORY_SYNC_MAX_BYTES + 1) as u32;
        assert_eq!(
            invalid.encode(),
            Err(Q6HistorySyncWireError::InvalidRequest)
        );
    }

    #[test]
    fn q6hc_chunk_parser_rejects_oversized_and_inconsistent_frames_before_payload_copy() {
        let mut frame = vec![0u8; Q6HC_CHUNK_HEADER_BYTES + Q6HC_CHUNK_PAYLOAD_BYTES + 1];
        frame[..4].copy_from_slice(&Q6HC_CHUNK_MAGIC);
        frame[4..6].copy_from_slice(&Q6_HISTORY_SYNC_WIRE_VERSION.to_be_bytes());
        frame[8..16].copy_from_slice(&9u64.to_be_bytes());
        frame[16..20].copy_from_slice(&0u32.to_be_bytes());
        frame[20..24].copy_from_slice(&1u32.to_be_bytes());
        frame[24..28].copy_from_slice(&1u32.to_be_bytes());
        frame[28..32].copy_from_slice(&1u32.to_be_bytes());
        frame[32..64].copy_from_slice(&[0x33; 32]);
        frame[64..96].copy_from_slice(&[0x66; 32]);
        assert!(matches!(
            parse_chunk(&frame),
            Err(Q6HistorySyncWireError::MalformedChunk)
        ));
    }

    #[test]
    fn q6hc_response_sequence_rejects_truncation_and_mixed_metadata_before_send() {
        let request = request();
        let page = QRunV06CanonicalHistoryPage {
            start_height: 8,
            next_height: 9,
            snapshot_height: 8,
            snapshot_tip: request.snapshot_tip,
            complete: true,
            envelopes: vec![vec![0x99; 100_000]],
        };
        let chunks = encode_q6hp_page_chunks(&request, &page).unwrap();
        assert_eq!(chunks.len(), 3);
        validate_q6hc_response_sequence(&chunks, request.request_id, &request.snapshot_tip)
            .unwrap();

        let mut truncated = chunks.clone();
        truncated.pop();
        assert_eq!(
            validate_q6hc_response_sequence(&truncated, request.request_id, &request.snapshot_tip),
            Err(Q6HistorySyncWireError::ChunkMetadataMismatch)
        );

        let mut mixed = chunks;
        mixed[1][64] ^= 1;
        assert_eq!(
            validate_q6hc_response_sequence(&mixed, request.request_id, &request.snapshot_tip),
            Err(Q6HistorySyncWireError::ChunkMetadataMismatch)
        );
    }

    #[test]
    fn q6hc_chunk_assembler_rejects_out_of_order_first_chunk() {
        let mut assembler = QRunV06HistoryPageChunkAssembler::new(
            request(),
            ConsensusParameters::candidate_testnet().unwrap(),
        )
        .unwrap();
        let mut frame = vec![0u8; Q6HC_CHUNK_HEADER_BYTES + 1];
        frame[..4].copy_from_slice(&Q6HC_CHUNK_MAGIC);
        frame[4..6].copy_from_slice(&Q6_HISTORY_SYNC_WIRE_VERSION.to_be_bytes());
        frame[6..8].copy_from_slice(&Q6HC_FINAL_FLAG.to_be_bytes());
        frame[8..16].copy_from_slice(&9u64.to_be_bytes());
        frame[16..20].copy_from_slice(&1u32.to_be_bytes());
        frame[20..24].copy_from_slice(&2u32.to_be_bytes());
        frame[24..28].copy_from_slice(&((Q6HC_CHUNK_PAYLOAD_BYTES + 1) as u32).to_be_bytes());
        frame[28..32].copy_from_slice(&1u32.to_be_bytes());
        frame[32..64].copy_from_slice(&[0x33; 32]);
        frame[64..96].copy_from_slice(&[0x66; 32]);
        assert_eq!(
            assembler.push(&frame),
            Err(Q6HistorySyncWireError::ChunkOrder)
        );
    }
}
