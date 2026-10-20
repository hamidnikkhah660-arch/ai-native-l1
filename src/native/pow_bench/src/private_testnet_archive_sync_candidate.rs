//! Research-only paginated archive sync planner; deliberately not wired into the node or public wire.
//!
//! It plans ranges over bounded metadata, not block payload allocation. The caller must keep the
//! corresponding immutable archive snapshot alive and fetch only the returned range. Cursors are
//! authenticated with an application-provided per-session key and are bound to network, profile,
//! snapshot generation, exact limits, and session identity. This module does not authenticate peers,
//! manage keys, fetch ancestors, or define public wire semantics.
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

type HmacSha256 = Hmac<Sha256>;
const SNAPSHOT_DOMAIN: &[u8] = b"AI_NATIVE_L1_ARCHIVE_SYNC_SNAPSHOT_V1";
const LIMITS_DOMAIN: &[u8] = b"AI_NATIVE_L1_ARCHIVE_SYNC_LIMITS_V1";
const CURSOR_MAGIC: &[u8; 4] = b"ARS1";
const CURSOR_BODY_BYTES: usize = 204;
pub const ARCHIVE_SYNC_CURSOR_BYTES: usize = CURSOR_BODY_BYTES + 32;

/// Hard ceilings for this local research candidate, not public protocol parameters.
pub const MAX_CANDIDATE_PAGE_ITEMS: u32 = 256;
pub const MAX_CANDIDATE_PAGE_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_CANDIDATE_ENVELOPE_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_CANDIDATE_TOTAL_ITEMS: u64 = 65_536;
pub const MAX_CANDIDATE_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_CANDIDATE_PAGES: u32 = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchiveSyncLimits {
    pub max_page_items: u32,
    pub max_page_bytes: u64,
    pub max_envelope_bytes: u64,
    pub max_total_items: u64,
    pub max_total_bytes: u64,
    pub max_pages: u32,
}

impl ArchiveSyncLimits {
    pub fn validate(&self) -> Result<(), ArchiveSyncError> {
        if self.max_page_items == 0
            || self.max_page_bytes == 0
            || self.max_envelope_bytes == 0
            || self.max_total_items == 0
            || self.max_total_bytes == 0
            || self.max_pages == 0
            || self.max_page_items > MAX_CANDIDATE_PAGE_ITEMS
            || self.max_page_bytes > MAX_CANDIDATE_PAGE_BYTES
            || self.max_envelope_bytes > MAX_CANDIDATE_ENVELOPE_BYTES
            || self.max_total_items > MAX_CANDIDATE_TOTAL_ITEMS
            || self.max_total_bytes > MAX_CANDIDATE_TOTAL_BYTES
            || self.max_pages > MAX_CANDIDATE_PAGES
            || self.max_envelope_bytes > self.max_page_bytes
        {
            return Err(ArchiveSyncError::InvalidLimits);
        }
        Ok(())
    }

    fn commitment(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(LIMITS_DOMAIN);
        hash.update(self.max_page_items.to_be_bytes());
        hash.update(self.max_page_bytes.to_be_bytes());
        hash.update(self.max_envelope_bytes.to_be_bytes());
        hash.update(self.max_total_items.to_be_bytes());
        hash.update(self.max_total_bytes.to_be_bytes());
        hash.update(self.max_pages.to_be_bytes());
        hash.finalize().into()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveEntryMeta {
    pub height: u64,
    pub digest: [u8; 32],
    pub encoded_len: u64,
    /// SHA-256 of the exact encoded payload, distinct from the consensus/block digest.
    pub payload_sha256: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveSyncError {
    InvalidLimits,
    TotalItemBudgetExceeded,
    TotalByteBudgetExceeded,
    EnvelopeTooLarge,
    EmptyEnvelope,
    DuplicateDigest,
    ArithmeticOverflow,
    CursorInvalidLength,
    CursorAuthenticationFailed,
    CursorMalformed,
    WrongNetwork,
    WrongProfile,
    WrongSession,
    StaleGeneration,
    SnapshotMismatch,
    LimitsMismatch,
    CursorOutOfBounds,
    CursorBudgetMismatch,
    PageTooLarge,
    MaxPagesExceeded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveSyncPage {
    /// Half-open metadata/payload range. Keep the source snapshot immutable while using it.
    pub start_index: usize,
    pub end_index: usize,
    /// One-based page number; an empty archive returns page number zero.
    pub page_number: u32,
    pub page_bytes: u64,
    pub total_items_after_page: u64,
    pub total_bytes_after_page: u64,
    pub complete: bool,
    pub next_cursor: Option<[u8; ARCHIVE_SYNC_CURSOR_BYTES]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ArchiveSyncCursor {
    network_id: [u8; 32],
    profile_id: [u8; 32],
    snapshot_commitment: [u8; 32],
    limits_commitment: [u8; 32],
    session_binding: [u8; 32],
    generation: u64,
    next_offset: u64,
    emitted_items: u64,
    emitted_bytes: u64,
    pages_emitted: u64,
}

impl ArchiveSyncCursor {
    fn encode(&self, key: &[u8; 32]) -> [u8; ARCHIVE_SYNC_CURSOR_BYTES] {
        let mut out = [0u8; ARCHIVE_SYNC_CURSOR_BYTES];
        let mut at = 0usize;
        out[at..at + 4].copy_from_slice(CURSOR_MAGIC);
        at += 4;
        for part in [
            &self.network_id,
            &self.profile_id,
            &self.snapshot_commitment,
            &self.limits_commitment,
            &self.session_binding,
        ] {
            out[at..at + 32].copy_from_slice(part);
            at += 32;
        }
        for value in [
            self.generation,
            self.next_offset,
            self.emitted_items,
            self.emitted_bytes,
            self.pages_emitted,
        ] {
            out[at..at + 8].copy_from_slice(&value.to_be_bytes());
            at += 8;
        }
        debug_assert_eq!(at, CURSOR_BODY_BYTES);
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts a 32-byte key");
        mac.update(&out[..CURSOR_BODY_BYTES]);
        let tag = mac.finalize().into_bytes();
        out[CURSOR_BODY_BYTES..].copy_from_slice(&tag);
        out
    }

    fn decode(encoded: &[u8], key: &[u8; 32]) -> Result<Self, ArchiveSyncError> {
        if encoded.len() != ARCHIVE_SYNC_CURSOR_BYTES {
            return Err(ArchiveSyncError::CursorInvalidLength);
        }
        let mut mac = HmacSha256::new_from_slice(key)
            .map_err(|_| ArchiveSyncError::CursorAuthenticationFailed)?;
        mac.update(&encoded[..CURSOR_BODY_BYTES]);
        mac.verify_slice(&encoded[CURSOR_BODY_BYTES..])
            .map_err(|_| ArchiveSyncError::CursorAuthenticationFailed)?;
        if &encoded[..4] != CURSOR_MAGIC {
            return Err(ArchiveSyncError::CursorMalformed);
        }
        let mut at = 4usize;
        let network_id = take_array::<32>(encoded, &mut at)?;
        let profile_id = take_array::<32>(encoded, &mut at)?;
        let snapshot_commitment = take_array::<32>(encoded, &mut at)?;
        let limits_commitment = take_array::<32>(encoded, &mut at)?;
        let session_binding = take_array::<32>(encoded, &mut at)?;
        let generation = take_u64(encoded, &mut at)?;
        let next_offset = take_u64(encoded, &mut at)?;
        let emitted_items = take_u64(encoded, &mut at)?;
        let emitted_bytes = take_u64(encoded, &mut at)?;
        let pages_emitted = take_u64(encoded, &mut at)?;
        if at != CURSOR_BODY_BYTES {
            return Err(ArchiveSyncError::CursorMalformed);
        }
        Ok(Self {
            network_id,
            profile_id,
            snapshot_commitment,
            limits_commitment,
            session_binding,
            generation,
            next_offset,
            emitted_items,
            emitted_bytes,
            pages_emitted,
        })
    }
}

fn take_array<const N: usize>(bytes: &[u8], at: &mut usize) -> Result<[u8; N], ArchiveSyncError> {
    let end = at
        .checked_add(N)
        .ok_or(ArchiveSyncError::ArithmeticOverflow)?;
    let part = bytes
        .get(*at..end)
        .ok_or(ArchiveSyncError::CursorMalformed)?;
    let mut out = [0u8; N];
    out.copy_from_slice(part);
    *at = end;
    Ok(out)
}

fn take_u64(bytes: &[u8], at: &mut usize) -> Result<u64, ArchiveSyncError> {
    Ok(u64::from_be_bytes(take_array::<8>(bytes, at)?))
}

/// Immutable metadata index for one archive generation, ordered parent-first by height and then
/// deterministically by digest. Constructing the index checks total budgets before page planning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveSyncIndex {
    network_id: [u8; 32],
    profile_id: [u8; 32],
    generation: u64,
    snapshot_commitment: [u8; 32],
    limits_commitment: [u8; 32],
    entries: Vec<ArchiveEntryMeta>,
    prefix_bytes: Vec<u64>,
}

impl ArchiveSyncIndex {
    pub fn new(
        network_id: [u8; 32],
        profile_id: [u8; 32],
        generation: u64,
        mut entries: Vec<ArchiveEntryMeta>,
        limits: ArchiveSyncLimits,
    ) -> Result<Self, ArchiveSyncError> {
        limits.validate()?;
        let item_count =
            u64::try_from(entries.len()).map_err(|_| ArchiveSyncError::ArithmeticOverflow)?;
        if item_count > limits.max_total_items {
            return Err(ArchiveSyncError::TotalItemBudgetExceeded);
        }
        let mut total_bytes = 0u64;
        let mut seen = BTreeSet::new();
        for entry in &entries {
            if entry.encoded_len == 0 {
                return Err(ArchiveSyncError::EmptyEnvelope);
            }
            if entry.encoded_len > limits.max_envelope_bytes {
                return Err(ArchiveSyncError::EnvelopeTooLarge);
            }
            if !seen.insert(entry.digest) {
                return Err(ArchiveSyncError::DuplicateDigest);
            }
            total_bytes = total_bytes
                .checked_add(entry.encoded_len)
                .ok_or(ArchiveSyncError::ArithmeticOverflow)?;
            if total_bytes > limits.max_total_bytes {
                return Err(ArchiveSyncError::TotalByteBudgetExceeded);
            }
        }
        entries.sort_unstable_by(|a, b| {
            a.height
                .cmp(&b.height)
                .then_with(|| a.digest.cmp(&b.digest))
        });

        let prefix_capacity = entries
            .len()
            .checked_add(1)
            .ok_or(ArchiveSyncError::ArithmeticOverflow)?;
        let mut prefix_bytes = Vec::with_capacity(prefix_capacity);
        prefix_bytes.push(0u64);
        let mut running = 0u64;
        for entry in &entries {
            running = running
                .checked_add(entry.encoded_len)
                .ok_or(ArchiveSyncError::ArithmeticOverflow)?;
            prefix_bytes.push(running);
        }

        let snapshot_commitment =
            compute_snapshot_commitment(&network_id, &profile_id, generation, &entries);
        Ok(Self {
            network_id,
            profile_id,
            generation,
            snapshot_commitment,
            limits_commitment: limits.commitment(),
            entries,
            prefix_bytes,
        })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> &[ArchiveEntryMeta] {
        &self.entries
    }

    pub fn total_bytes(&self) -> u64 {
        self.prefix_bytes.last().copied().unwrap_or(0)
    }

    pub fn snapshot_commitment(&self) -> [u8; 32] {
        self.snapshot_commitment
    }

    pub fn first_page(
        &self,
        limits: ArchiveSyncLimits,
        session_binding: [u8; 32],
        cursor_key: &[u8; 32],
    ) -> Result<ArchiveSyncPage, ArchiveSyncError> {
        limits.validate()?;
        self.check_limits(&limits)?;
        self.plan_page(0, 0, 0, 0, limits, session_binding, cursor_key)
    }

    pub fn continue_page(
        &self,
        encoded_cursor: &[u8],
        limits: ArchiveSyncLimits,
        session_binding: [u8; 32],
        cursor_key: &[u8; 32],
    ) -> Result<ArchiveSyncPage, ArchiveSyncError> {
        limits.validate()?;
        self.check_limits(&limits)?;
        let cursor = ArchiveSyncCursor::decode(encoded_cursor, cursor_key)?;
        if cursor.network_id != self.network_id {
            return Err(ArchiveSyncError::WrongNetwork);
        }
        if cursor.profile_id != self.profile_id {
            return Err(ArchiveSyncError::WrongProfile);
        }
        if cursor.session_binding != session_binding {
            return Err(ArchiveSyncError::WrongSession);
        }
        if cursor.generation != self.generation {
            return Err(ArchiveSyncError::StaleGeneration);
        }
        if cursor.snapshot_commitment != self.snapshot_commitment {
            return Err(ArchiveSyncError::SnapshotMismatch);
        }
        if cursor.limits_commitment != self.limits_commitment {
            return Err(ArchiveSyncError::LimitsMismatch);
        }
        let offset =
            usize::try_from(cursor.next_offset).map_err(|_| ArchiveSyncError::CursorOutOfBounds)?;
        if offset > self.entries.len() || cursor.emitted_items != cursor.next_offset {
            return Err(ArchiveSyncError::CursorOutOfBounds);
        }
        if self.prefix_bytes.get(offset).copied() != Some(cursor.emitted_bytes)
            || cursor.pages_emitted == 0
            || cursor.pages_emitted >= u64::from(limits.max_pages)
            || (offset == 0)
        {
            return Err(ArchiveSyncError::CursorBudgetMismatch);
        }
        self.plan_page(
            cursor.next_offset,
            cursor.emitted_items,
            cursor.emitted_bytes,
            cursor.pages_emitted,
            limits,
            session_binding,
            cursor_key,
        )
    }

    pub(crate) fn check_limits(&self, limits: &ArchiveSyncLimits) -> Result<(), ArchiveSyncError> {
        if limits.commitment() != self.limits_commitment {
            return Err(ArchiveSyncError::LimitsMismatch);
        }
        Ok(())
    }

    fn plan_page(
        &self,
        start: u64,
        emitted_items: u64,
        emitted_bytes: u64,
        pages_emitted: u64,
        limits: ArchiveSyncLimits,
        session_binding: [u8; 32],
        cursor_key: &[u8; 32],
    ) -> Result<ArchiveSyncPage, ArchiveSyncError> {
        let start = usize::try_from(start).map_err(|_| ArchiveSyncError::CursorOutOfBounds)?;
        if start > self.entries.len() {
            return Err(ArchiveSyncError::CursorOutOfBounds);
        }
        if emitted_items != start as u64
            || self.prefix_bytes.get(start).copied() != Some(emitted_bytes)
            || pages_emitted > u64::from(limits.max_pages)
        {
            return Err(ArchiveSyncError::CursorBudgetMismatch);
        }
        if self.entries.is_empty() {
            return Ok(ArchiveSyncPage {
                start_index: 0,
                end_index: 0,
                page_number: 0,
                page_bytes: 0,
                total_items_after_page: 0,
                total_bytes_after_page: 0,
                complete: true,
                next_cursor: None,
            });
        }
        if pages_emitted >= u64::from(limits.max_pages) {
            return Err(ArchiveSyncError::MaxPagesExceeded);
        }
        let mut end = start;
        let mut page_bytes = 0u64;
        while end < self.entries.len() && (end - start) < limits.max_page_items as usize {
            let len = self.entries[end].encoded_len;
            let candidate_bytes = page_bytes
                .checked_add(len)
                .ok_or(ArchiveSyncError::ArithmeticOverflow)?;
            if candidate_bytes > limits.max_page_bytes {
                break;
            }
            page_bytes = candidate_bytes;
            end += 1;
        }
        if end == start {
            return Err(ArchiveSyncError::PageTooLarge);
        }
        let total_items_after_page =
            u64::try_from(end).map_err(|_| ArchiveSyncError::ArithmeticOverflow)?;
        let total_bytes_after_page = *self
            .prefix_bytes
            .get(end)
            .ok_or(ArchiveSyncError::CursorOutOfBounds)?;
        if total_items_after_page > limits.max_total_items {
            return Err(ArchiveSyncError::TotalItemBudgetExceeded);
        }
        if total_bytes_after_page > limits.max_total_bytes {
            return Err(ArchiveSyncError::TotalByteBudgetExceeded);
        }
        let next_page_number = pages_emitted
            .checked_add(1)
            .ok_or(ArchiveSyncError::ArithmeticOverflow)?;
        let complete = end == self.entries.len();
        if !complete && next_page_number >= u64::from(limits.max_pages) {
            return Err(ArchiveSyncError::MaxPagesExceeded);
        }
        let next_cursor = if complete {
            None
        } else {
            let cursor = ArchiveSyncCursor {
                network_id: self.network_id,
                profile_id: self.profile_id,
                snapshot_commitment: self.snapshot_commitment,
                limits_commitment: self.limits_commitment,
                session_binding,
                generation: self.generation,
                next_offset: total_items_after_page,
                emitted_items: total_items_after_page,
                emitted_bytes: total_bytes_after_page,
                pages_emitted: next_page_number,
            };
            Some(cursor.encode(cursor_key))
        };
        Ok(ArchiveSyncPage {
            start_index: start,
            end_index: end,
            page_number: u32::try_from(next_page_number)
                .map_err(|_| ArchiveSyncError::ArithmeticOverflow)?,
            page_bytes,
            total_items_after_page,
            total_bytes_after_page,
            complete,
            next_cursor,
        })
    }
}

fn compute_snapshot_commitment(
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
    generation: u64,
    entries: &[ArchiveEntryMeta],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(SNAPSHOT_DOMAIN);
    hash.update(network_id);
    hash.update(profile_id);
    hash.update(generation.to_be_bytes());
    hash.update((entries.len() as u64).to_be_bytes());
    for entry in entries {
        hash.update(entry.height.to_be_bytes());
        hash.update(entry.digest);
        hash.update(entry.encoded_len.to_be_bytes());
        hash.update(entry.payload_sha256);
    }
    hash.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> ArchiveSyncLimits {
        ArchiveSyncLimits {
            max_page_items: 2,
            max_page_bytes: 7,
            max_envelope_bytes: 7,
            max_total_items: 5,
            max_total_bytes: 15,
            max_pages: 3,
        }
    }

    fn entry(height: u64, digest_byte: u8, encoded_len: u64) -> ArchiveEntryMeta {
        ArchiveEntryMeta {
            height,
            digest: [digest_byte; 32],
            encoded_len,
            payload_sha256: [digest_byte.wrapping_add(100); 32],
        }
    }

    fn entries() -> Vec<ArchiveEntryMeta> {
        vec![
            entry(5, 5, 1),
            entry(2, 2, 3),
            entry(4, 4, 2),
            entry(1, 1, 4),
            entry(3, 3, 5),
        ]
    }

    fn index(gen: u64, all: Vec<ArchiveEntryMeta>, lim: ArchiveSyncLimits) -> ArchiveSyncIndex {
        ArchiveSyncIndex::new([0xC0; 32], [0xA1; 32], gen, all, lim).expect("fixture index")
    }

    const SESSION: [u8; 32] = [0x51; 32];
    const KEY: [u8; 32] = [0x77; 32];

    #[test]
    fn sorts_parent_first_then_digest_and_is_deterministic() {
        let first = index(7, entries(), limits());
        let second = index(7, entries().into_iter().rev().collect(), limits());
        assert_eq!(first.entries(), second.entries());
        assert_eq!(first.snapshot_commitment(), second.snapshot_commitment());
        assert_eq!(
            first.entries().iter().map(|e| e.height).collect::<Vec<_>>(),
            vec![1, 2, 3, 4, 5]
        );
        let mut changed_payload_commitment = entries();
        changed_payload_commitment[0].payload_sha256[0] ^= 1;
        let changed = index(7, changed_payload_commitment, limits());
        assert_ne!(first.snapshot_commitment(), changed.snapshot_commitment());
    }

    #[test]
    fn paginates_exact_item_and_byte_boundaries_with_resumable_cursor() {
        let ix = index(7, entries(), limits());
        let p1 = ix.first_page(limits(), SESSION, &KEY).unwrap();
        assert_eq!((p1.start_index, p1.end_index, p1.page_bytes), (0, 2, 7));
        assert_eq!(p1.total_items_after_page, 2);
        let token = p1.next_cursor.unwrap();
        assert_eq!(token.len(), ARCHIVE_SYNC_CURSOR_BYTES);

        // A new in-memory index rebuilt after process restart resumes from the authenticated cursor.
        let reopened = index(7, entries().into_iter().rev().collect(), limits());
        let p2 = reopened
            .continue_page(&token, limits(), SESSION, &KEY)
            .unwrap();
        assert_eq!((p2.start_index, p2.end_index, p2.page_bytes), (2, 4, 7));
        let p3 = reopened
            .continue_page(&p2.next_cursor.unwrap(), limits(), SESSION, &KEY)
            .unwrap();
        assert_eq!((p3.start_index, p3.end_index, p3.page_bytes), (4, 5, 1));
        assert_eq!(p3.total_items_after_page, 5);
        assert_eq!(p3.total_bytes_after_page, 15);
        assert!(p3.complete);
        assert!(p3.next_cursor.is_none());
    }

    #[test]
    fn empty_archive_returns_complete_without_phantom_cursor() {
        let ix = index(1, Vec::new(), limits());
        let page = ix.first_page(limits(), SESSION, &KEY).unwrap();
        assert!(page.complete);
        assert_eq!(page.page_number, 0);
        assert_eq!(
            (page.start_index, page.end_index, page.page_bytes),
            (0, 0, 0)
        );
        assert!(page.next_cursor.is_none());
    }

    #[test]
    fn rejects_each_hard_index_budget_before_planning() {
        let mut lim = limits();
        lim.max_total_items = 4;
        assert_eq!(
            ArchiveSyncIndex::new([0; 32], [1; 32], 0, entries(), lim).unwrap_err(),
            ArchiveSyncError::TotalItemBudgetExceeded
        );

        let mut lim = limits();
        lim.max_total_bytes = 14;
        assert_eq!(
            ArchiveSyncIndex::new([0; 32], [1; 32], 0, entries(), lim).unwrap_err(),
            ArchiveSyncError::TotalByteBudgetExceeded
        );

        let mut lim = limits();
        lim.max_envelope_bytes = 4;
        assert_eq!(
            ArchiveSyncIndex::new([0; 32], [1; 32], 0, entries(), lim).unwrap_err(),
            ArchiveSyncError::EnvelopeTooLarge
        );
    }

    #[test]
    fn rejects_empty_duplicate_and_invalid_config_entries() {
        assert_eq!(
            ArchiveSyncIndex::new([0; 32], [1; 32], 0, vec![entry(1, 1, 0)], limits()).unwrap_err(),
            ArchiveSyncError::EmptyEnvelope
        );
        assert_eq!(
            ArchiveSyncIndex::new(
                [0; 32],
                [1; 32],
                0,
                vec![entry(1, 1, 2), entry(2, 1, 3)],
                limits()
            )
            .unwrap_err(),
            ArchiveSyncError::DuplicateDigest
        );
        let mut lim = limits();
        lim.max_page_items = 0;
        assert_eq!(lim.validate(), Err(ArchiveSyncError::InvalidLimits));
        let mut above_hard_ceiling = limits();
        above_hard_ceiling.max_total_items = MAX_CANDIDATE_TOTAL_ITEMS + 1;
        assert_eq!(
            above_hard_ceiling.validate(),
            Err(ArchiveSyncError::InvalidLimits)
        );
        let mut lim = limits();
        lim.max_envelope_bytes = lim.max_page_bytes + 1;
        assert_eq!(lim.validate(), Err(ArchiveSyncError::InvalidLimits));
    }

    #[test]
    fn cursor_mac_session_and_context_are_checked() {
        let ix = index(7, entries(), limits());
        let page = ix.first_page(limits(), SESSION, &KEY).unwrap();
        let token = page.next_cursor.unwrap();
        let mut tampered = token;
        tampered[12] ^= 1;
        assert_eq!(
            ix.continue_page(&tampered, limits(), SESSION, &KEY)
                .unwrap_err(),
            ArchiveSyncError::CursorAuthenticationFailed
        );
        assert_eq!(
            ix.continue_page(&token[..token.len() - 1], limits(), SESSION, &KEY)
                .unwrap_err(),
            ArchiveSyncError::CursorInvalidLength
        );
        assert_eq!(
            ix.continue_page(&token, limits(), [0x52; 32], &KEY)
                .unwrap_err(),
            ArchiveSyncError::WrongSession
        );
        assert_eq!(
            ix.continue_page(&token, limits(), SESSION, &[0x78; 32])
                .unwrap_err(),
            ArchiveSyncError::CursorAuthenticationFailed
        );

        let stale = index(8, entries(), limits());
        assert_eq!(
            stale
                .continue_page(&token, limits(), SESSION, &KEY)
                .unwrap_err(),
            ArchiveSyncError::StaleGeneration
        );
        let wrong_network =
            ArchiveSyncIndex::new([9; 32], [0xA1; 32], 7, entries(), limits()).unwrap();
        assert_eq!(
            wrong_network
                .continue_page(&token, limits(), SESSION, &KEY)
                .unwrap_err(),
            ArchiveSyncError::WrongNetwork
        );
        let wrong_profile =
            ArchiveSyncIndex::new([0xC0; 32], [9; 32], 7, entries(), limits()).unwrap();
        assert_eq!(
            wrong_profile
                .continue_page(&token, limits(), SESSION, &KEY)
                .unwrap_err(),
            ArchiveSyncError::WrongProfile
        );
        let changed_snapshot = index(
            7,
            vec![
                entry(1, 8, 4),
                entry(2, 2, 3),
                entry(3, 3, 5),
                entry(4, 4, 2),
                entry(5, 5, 1),
            ],
            limits(),
        );
        assert_eq!(
            changed_snapshot
                .continue_page(&token, limits(), SESSION, &KEY)
                .unwrap_err(),
            ArchiveSyncError::SnapshotMismatch
        );
    }

    #[test]
    fn cursor_is_bound_to_exact_page_and_global_limits() {
        let ix = index(7, entries(), limits());
        let p1 = ix.first_page(limits(), SESSION, &KEY).unwrap();
        let token = p1.next_cursor.unwrap();
        let mut different_limits = limits();
        different_limits.max_page_items = 3;
        assert_eq!(
            ix.continue_page(&token, different_limits, SESSION, &KEY)
                .unwrap_err(),
            ArchiveSyncError::LimitsMismatch
        );
    }

    #[test]
    fn operation_fails_closed_when_remaining_archive_would_exceed_page_budget() {
        let mut lim = limits();
        lim.max_pages = 1;
        let ix = index(7, entries(), lim);
        assert_eq!(
            ix.first_page(lim, SESSION, &KEY).unwrap_err(),
            ArchiveSyncError::MaxPagesExceeded
        );

        let short_archive = index(7, vec![entry(1, 1, 4), entry(2, 2, 3)], lim);
        let complete = short_archive.first_page(lim, SESSION, &KEY).unwrap();
        assert!(complete.complete);
        assert!(complete.next_cursor.is_none());
    }
}
