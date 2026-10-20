//! Research-only receiver-side page validator with commit-after-verification semantics.
//!
//! The caller must obtain expected snapshot commitment and archive totals from its chosen trusted
//! inventory/session flow. This module checks consistency/content integrity and range continuity;
//! it does not authenticate the transport, prove a remote manifest truthful, or validate consensus.
//! The commit closure must persist a page atomically. Receiver progress advances only if it succeeds.
use crate::private_testnet_archive_range_server_candidate::{
    ArchiveSyncServedEntry, ArchiveSyncServedPage,
};
use crate::private_testnet_archive_sync_candidate::{
    ArchiveSyncLimits, MAX_CANDIDATE_TOTAL_BYTES, MAX_CANDIDATE_TOTAL_ITEMS,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveRangeReceiverError<E> {
    InvalidManifest,
    AlreadyComplete,
    WrongSnapshot,
    ManifestMismatch,
    OutOfOrderPage,
    InvalidRange,
    PageNumberMismatch,
    EmptyPage,
    PageTooLarge,
    EnvelopeTooLarge,
    EmptyPayload,
    PayloadLengthMismatch,
    PayloadHashMismatch,
    DuplicateDigest,
    MetadataOrderViolation,
    CounterMismatch,
    TotalBudgetExceeded,
    CompletionMismatch,
    CounterOverflow,
    Commit(E),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedArchiveRangeReceipt {
    pub start_index: usize,
    pub end_index: usize,
    pub pages_verified: u32,
    pub total_items_verified: u64,
    pub total_bytes_verified: u64,
    pub complete: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StagedPage {
    end_index: usize,
    new_total_bytes: u64,
    pages_verified: u32,
    complete: bool,
}

/// Bounded streaming verifier; it keeps digest metadata only, never retains prior payload bytes.
pub struct ArchiveRangeReceiverCandidate {
    limits: ArchiveSyncLimits,
    expected_snapshot_commitment: [u8; 32],
    expected_total_items: u64,
    expected_total_bytes: u64,
    next_index: usize,
    total_bytes_verified: u64,
    pages_verified: u32,
    seen_digests: BTreeSet<[u8; 32]>,
    last_order_key: Option<(u64, [u8; 32])>,
    complete: bool,
}

impl ArchiveRangeReceiverCandidate {
    pub fn new(
        limits: ArchiveSyncLimits,
        expected_snapshot_commitment: [u8; 32],
        expected_total_items: u64,
        expected_total_bytes: u64,
    ) -> Result<Self, ArchiveRangeReceiverError<std::convert::Infallible>> {
        limits
            .validate()
            .map_err(|_| ArchiveRangeReceiverError::InvalidManifest)?;
        if expected_total_items > limits.max_total_items
            || expected_total_items > MAX_CANDIDATE_TOTAL_ITEMS
            || expected_total_bytes > limits.max_total_bytes
            || expected_total_bytes > MAX_CANDIDATE_TOTAL_BYTES
            || ((expected_total_items == 0) != (expected_total_bytes == 0))
        {
            return Err(ArchiveRangeReceiverError::InvalidManifest);
        }
        let _bounded_item_count = usize::try_from(expected_total_items)
            .map_err(|_| ArchiveRangeReceiverError::InvalidManifest)?;
        Ok(Self {
            limits,
            expected_snapshot_commitment,
            expected_total_items,
            expected_total_bytes,
            next_index: 0,
            total_bytes_verified: 0,
            pages_verified: 0,
            seen_digests: BTreeSet::new(),
            last_order_key: None,
            complete: false,
        })
    }

    /// Verify every field and payload before `commit` runs. Only a successful commit advances the
    /// cursor/index counters, so a failed durable page write is retryable without skipping a range.
    pub fn apply_page_with_commit<F, E>(
        &mut self,
        page: &ArchiveSyncServedPage,
        commit: F,
    ) -> Result<VerifiedArchiveRangeReceipt, ArchiveRangeReceiverError<E>>
    where
        F: FnOnce(&ArchiveSyncServedPage) -> Result<(), E>,
    {
        let staged = self.validate_page(page)?;
        let start_index = self.next_index;
        commit(page).map_err(ArchiveRangeReceiverError::Commit)?;

        for entry in &page.entries {
            self.seen_digests.insert(entry.metadata.digest);
            self.last_order_key = Some((entry.metadata.height, entry.metadata.digest));
        }
        self.next_index = staged.end_index;
        self.total_bytes_verified = staged.new_total_bytes;
        self.pages_verified = staged.pages_verified;
        self.complete = staged.complete;
        Ok(VerifiedArchiveRangeReceipt {
            start_index,
            end_index: self.next_index,
            pages_verified: self.pages_verified,
            total_items_verified: self.next_index as u64,
            total_bytes_verified: self.total_bytes_verified,
            complete: self.complete,
        })
    }

    pub(crate) fn validate_page_only(
        &self,
        page: &ArchiveSyncServedPage,
    ) -> Result<(), ArchiveRangeReceiverError<std::convert::Infallible>> {
        self.validate_page(page).map(|_| ())
    }

    fn validate_page<E>(
        &self,
        page: &ArchiveSyncServedPage,
    ) -> Result<StagedPage, ArchiveRangeReceiverError<E>> {
        if self.complete {
            return Err(ArchiveRangeReceiverError::AlreadyComplete);
        }
        if page.snapshot_commitment != self.expected_snapshot_commitment {
            return Err(ArchiveRangeReceiverError::WrongSnapshot);
        }
        if page.archive_total_items != self.expected_total_items
            || page.archive_total_bytes != self.expected_total_bytes
        {
            return Err(ArchiveRangeReceiverError::ManifestMismatch);
        }
        let plan = &page.plan;
        if plan.start_index != self.next_index || plan.end_index < plan.start_index {
            return Err(ArchiveRangeReceiverError::OutOfOrderPage);
        }
        if plan.end_index as u64 > self.expected_total_items {
            return Err(ArchiveRangeReceiverError::InvalidRange);
        }
        let range_items = plan
            .end_index
            .checked_sub(plan.start_index)
            .ok_or(ArchiveRangeReceiverError::InvalidRange)?;
        if range_items != page.entries.len() {
            return Err(ArchiveRangeReceiverError::InvalidRange);
        }
        if page.entries.len() > self.limits.max_page_items as usize
            || plan.page_bytes > self.limits.max_page_bytes
        {
            return Err(ArchiveRangeReceiverError::PageTooLarge);
        }

        if self.expected_total_items == 0 {
            if self.next_index != 0
                || self.pages_verified != 0
                || plan.start_index != 0
                || plan.end_index != 0
                || !page.entries.is_empty()
                || plan.page_number != 0
                || plan.page_bytes != 0
                || plan.total_items_after_page != 0
                || plan.total_bytes_after_page != 0
                || !plan.complete
                || plan.next_cursor.is_some()
            {
                return Err(ArchiveRangeReceiverError::InvalidRange);
            }
            return Ok(StagedPage {
                end_index: 0,
                new_total_bytes: 0,
                pages_verified: 0,
                complete: true,
            });
        }

        if page.entries.is_empty() {
            return Err(ArchiveRangeReceiverError::EmptyPage);
        }
        let expected_page_number = self
            .pages_verified
            .checked_add(1)
            .ok_or(ArchiveRangeReceiverError::CounterOverflow)?;
        if plan.page_number != expected_page_number || plan.page_number == 0 {
            return Err(ArchiveRangeReceiverError::PageNumberMismatch);
        }
        let mut page_bytes = 0u64;
        let mut previous_order_key = self.last_order_key;
        let mut staged_digests = BTreeSet::new();
        for entry in &page.entries {
            validate_payload_entry::<E>(entry, self.limits)?;
            let order_key = (entry.metadata.height, entry.metadata.digest);
            if previous_order_key.is_some_and(|previous| previous >= order_key) {
                return Err(ArchiveRangeReceiverError::MetadataOrderViolation);
            }
            previous_order_key = Some(order_key);
            if self.seen_digests.contains(&entry.metadata.digest)
                || !staged_digests.insert(entry.metadata.digest)
            {
                return Err(ArchiveRangeReceiverError::DuplicateDigest);
            }
            page_bytes = page_bytes
                .checked_add(entry.metadata.encoded_len)
                .ok_or(ArchiveRangeReceiverError::CounterOverflow)?;
            if page_bytes > self.limits.max_page_bytes {
                return Err(ArchiveRangeReceiverError::PageTooLarge);
            }
        }
        if page_bytes != plan.page_bytes {
            return Err(ArchiveRangeReceiverError::CounterMismatch);
        }
        let new_total_bytes = self
            .total_bytes_verified
            .checked_add(page_bytes)
            .ok_or(ArchiveRangeReceiverError::CounterOverflow)?;
        let new_total_items = u64::try_from(plan.end_index)
            .map_err(|_| ArchiveRangeReceiverError::CounterOverflow)?;
        if new_total_items > self.limits.max_total_items
            || new_total_bytes > self.limits.max_total_bytes
            || new_total_items > MAX_CANDIDATE_TOTAL_ITEMS
            || new_total_bytes > MAX_CANDIDATE_TOTAL_BYTES
        {
            return Err(ArchiveRangeReceiverError::TotalBudgetExceeded);
        }
        if plan.total_items_after_page != new_total_items
            || plan.total_bytes_after_page != new_total_bytes
        {
            return Err(ArchiveRangeReceiverError::CounterMismatch);
        }
        let should_be_complete = new_total_items == self.expected_total_items
            && new_total_bytes == self.expected_total_bytes;
        if plan.complete != should_be_complete || plan.next_cursor.is_some() == should_be_complete {
            return Err(ArchiveRangeReceiverError::CompletionMismatch);
        }
        if !should_be_complete && plan.page_number >= self.limits.max_pages {
            return Err(ArchiveRangeReceiverError::CompletionMismatch);
        }
        Ok(StagedPage {
            end_index: plan.end_index,
            new_total_bytes,
            pages_verified: expected_page_number,
            complete: should_be_complete,
        })
    }

    pub fn receipt(&self) -> VerifiedArchiveRangeReceipt {
        VerifiedArchiveRangeReceipt {
            start_index: 0,
            end_index: self.next_index,
            pages_verified: self.pages_verified,
            total_items_verified: self.next_index as u64,
            total_bytes_verified: self.total_bytes_verified,
            complete: self.complete,
        }
    }
}

fn validate_payload_entry<E>(
    entry: &ArchiveSyncServedEntry,
    limits: ArchiveSyncLimits,
) -> Result<(), ArchiveRangeReceiverError<E>> {
    if entry.encoded.is_empty() || entry.metadata.encoded_len == 0 {
        return Err(ArchiveRangeReceiverError::EmptyPayload);
    }
    if entry.metadata.encoded_len > limits.max_envelope_bytes
        || entry.metadata.encoded_len > MAX_CANDIDATE_TOTAL_BYTES
    {
        return Err(ArchiveRangeReceiverError::EnvelopeTooLarge);
    }
    let len = u64::try_from(entry.encoded.len())
        .map_err(|_| ArchiveRangeReceiverError::PayloadLengthMismatch)?;
    if len != entry.metadata.encoded_len {
        return Err(ArchiveRangeReceiverError::PayloadLengthMismatch);
    }
    let payload_hash: [u8; 32] = Sha256::digest(&entry.encoded).into();
    if payload_hash != entry.metadata.payload_sha256 {
        return Err(ArchiveRangeReceiverError::PayloadHashMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::private_testnet_archive_range_server_candidate::{
        ArchiveRangeBudgetConfig, ArchiveRangeServerCandidate, ArchiveSyncPayload,
    };
    use crate::private_testnet_archive_sync_candidate::{ArchiveEntryMeta, ArchiveSyncIndex};
    use sha2::{Digest, Sha256};

    fn limits() -> ArchiveSyncLimits {
        ArchiveSyncLimits {
            max_page_items: 2,
            max_page_bytes: 8,
            max_envelope_bytes: 8,
            max_total_items: 5,
            max_total_bytes: 32,
            max_pages: 3,
        }
    }

    fn meta(height: u64, digest: u8, data: &[u8]) -> ArchiveEntryMeta {
        ArchiveEntryMeta {
            height,
            digest: [digest; 32],
            encoded_len: data.len() as u64,
            payload_sha256: Sha256::digest(data).into(),
        }
    }

    fn server() -> ArchiveRangeServerCandidate {
        let specs = vec![
            (3, 3, b"ccccc".to_vec()),
            (1, 1, b"aaaa".to_vec()),
            (5, 5, b"e".to_vec()),
            (2, 2, b"bbb".to_vec()),
            (4, 4, b"dd".to_vec()),
        ];
        let metas = specs.iter().map(|(h, d, b)| meta(*h, *d, b)).collect();
        let index = ArchiveSyncIndex::new([0xC0; 32], [0xA1; 32], 45, metas, limits()).unwrap();
        let payloads = specs
            .into_iter()
            .map(|(h, d, b)| ArchiveSyncPayload::new(meta(h, d, &b), b))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let budget = ArchiveRangeBudgetConfig {
            max_sessions: 2,
            per_session_max_pages: 3,
            per_session_max_items: 5,
            per_session_max_bytes: 15,
            global_max_pages: 6,
            global_max_items: 10,
            global_max_bytes: 30,
        };
        ArchiveRangeServerCandidate::new(index, payloads, limits(), budget).unwrap()
    }

    fn first_two_pages(
        server: &ArchiveRangeServerCandidate,
    ) -> (ArchiveSyncServedPage, ArchiveSyncServedPage) {
        server
            .register_authenticated_session([1; 32], [2; 32])
            .unwrap();
        let p1 = (*server.serve_first_page([1; 32]).unwrap()).clone();
        let p2 = (*server
            .serve_next_page([1; 32], p1.plan.next_cursor.as_ref().unwrap())
            .unwrap())
        .clone();
        (p1, p2)
    }

    #[test]
    fn accepts_only_complete_ordered_pages_and_reports_final_totals() {
        let server = server();
        let mut receiver =
            ArchiveRangeReceiverCandidate::new(limits(), server.snapshot_commitment(), 5, 15)
                .unwrap();
        let (p1, p2) = first_two_pages(&server);
        let commit = |_: &ArchiveSyncServedPage| -> Result<(), ()> { Ok(()) };
        let r1 = receiver.apply_page_with_commit(&p1, commit).unwrap();
        assert_eq!(
            (
                r1.start_index,
                r1.end_index,
                r1.pages_verified,
                r1.total_bytes_verified
            ),
            (0, 2, 1, 7)
        );
        let p3 = (*server
            .serve_next_page([1; 32], p2.plan.next_cursor.as_ref().unwrap())
            .unwrap())
        .clone();
        let r2 = receiver.apply_page_with_commit(&p2, commit).unwrap();
        assert_eq!(r2.end_index, 4);
        let r3 = receiver.apply_page_with_commit(&p3, commit).unwrap();
        assert!(r3.complete);
        assert_eq!(
            (
                r3.total_items_verified,
                r3.total_bytes_verified,
                r3.pages_verified
            ),
            (5, 15, 3)
        );
        assert_eq!(
            receiver.apply_page_with_commit(&p3, commit),
            Err(ArchiveRangeReceiverError::AlreadyComplete)
        );
    }

    #[test]
    fn rejects_hash_corruption_without_advancing_or_committing() {
        let server = server();
        let (mut p1, _) = first_two_pages(&server);
        let mut receiver =
            ArchiveRangeReceiverCandidate::new(limits(), p1.snapshot_commitment, 5, 15).unwrap();
        p1.entries[0].encoded[0] ^= 1;
        let mut commits = 0;
        let result = receiver.apply_page_with_commit(&p1, |_| {
            commits += 1;
            Ok::<(), ()>(())
        });
        assert_eq!(result, Err(ArchiveRangeReceiverError::PayloadHashMismatch));
        assert_eq!(commits, 0);
        assert_eq!(receiver.receipt().end_index, 0);
    }

    #[test]
    fn failed_durable_commit_does_not_advance_page_state() {
        let server = server();
        let (p1, _) = first_two_pages(&server);
        let mut receiver =
            ArchiveRangeReceiverCandidate::new(limits(), p1.snapshot_commitment, 5, 15).unwrap();
        assert_eq!(
            receiver.apply_page_with_commit(&p1, |_| Err::<(), _>("disk full")),
            Err(ArchiveRangeReceiverError::Commit("disk full"))
        );
        assert_eq!(receiver.receipt().end_index, 0);
        let good = receiver
            .apply_page_with_commit(&p1, |_| Ok::<(), ()>(()))
            .unwrap();
        assert_eq!(good.end_index, 2);
    }

    #[test]
    fn rejects_early_complete_wrong_manifest_and_page_counter_tampering() {
        let server = server();
        let (p1, _) = first_two_pages(&server);
        let mut receiver =
            ArchiveRangeReceiverCandidate::new(limits(), p1.snapshot_commitment, 5, 15).unwrap();
        let mut early = p1.clone();
        early.plan.complete = true;
        early.plan.next_cursor = None;
        assert_eq!(
            receiver.apply_page_with_commit(&early, |_| Ok::<(), ()>(())),
            Err(ArchiveRangeReceiverError::CompletionMismatch)
        );
        let mut wrong = p1.clone();
        wrong.archive_total_items = 4;
        assert_eq!(
            receiver.apply_page_with_commit(&wrong, |_| Ok::<(), ()>(())),
            Err(ArchiveRangeReceiverError::ManifestMismatch)
        );
        let mut counter = p1.clone();
        counter.plan.total_bytes_after_page += 1;
        assert_eq!(
            receiver.apply_page_with_commit(&counter, |_| Ok::<(), ()>(())),
            Err(ArchiveRangeReceiverError::CounterMismatch)
        );
        assert_eq!(receiver.receipt().end_index, 0);
    }

    #[test]
    fn rejects_out_of_order_duplicate_or_wrong_snapshot_pages() {
        let server = server();
        let (p1, p2) = first_two_pages(&server);
        let mut receiver =
            ArchiveRangeReceiverCandidate::new(limits(), p1.snapshot_commitment, 5, 15).unwrap();
        assert_eq!(
            receiver.apply_page_with_commit(&p2, |_| Ok::<(), ()>(())),
            Err(ArchiveRangeReceiverError::OutOfOrderPage)
        );
        let mut wrong = p1.clone();
        wrong.snapshot_commitment[0] ^= 1;
        assert_eq!(
            receiver.apply_page_with_commit(&wrong, |_| Ok::<(), ()>(())),
            Err(ArchiveRangeReceiverError::WrongSnapshot)
        );
        let mut duplicate = p1.clone();
        duplicate.entries[1].metadata.digest = duplicate.entries[0].metadata.digest;
        assert_eq!(
            receiver.apply_page_with_commit(&duplicate, |_| Ok::<(), ()>(())),
            Err(ArchiveRangeReceiverError::DuplicateDigest)
        );
        assert_eq!(receiver.receipt().end_index, 0);
    }

    #[test]
    fn empty_archive_is_completed_without_phantom_page() {
        let index =
            ArchiveSyncIndex::new([0xC0; 32], [0xA1; 32], 46, Vec::new(), limits()).unwrap();
        let budget = ArchiveRangeBudgetConfig {
            max_sessions: 1,
            per_session_max_pages: 3,
            per_session_max_items: 5,
            per_session_max_bytes: 32,
            global_max_pages: 3,
            global_max_items: 5,
            global_max_bytes: 32,
        };
        let server = ArchiveRangeServerCandidate::new(index, Vec::new(), limits(), budget).unwrap();
        server
            .register_authenticated_session([9; 32], [8; 32])
            .unwrap();
        let page = server.serve_first_page([9; 32]).unwrap();
        assert!(page.plan.complete);
        assert_eq!(page.plan.page_number, 0);
        let mut receiver =
            ArchiveRangeReceiverCandidate::new(limits(), page.snapshot_commitment, 0, 0).unwrap();
        let receipt = receiver
            .apply_page_with_commit(&page, |_| Ok::<(), ()>(()))
            .unwrap();
        assert!(receipt.complete);
        assert_eq!(receipt.pages_verified, 0);
        assert_eq!(receipt.total_items_verified, 0);
    }

    #[test]
    fn rejects_truncated_payload_without_advancing_or_committing() {
        let server = server();
        let (mut page, _) = first_two_pages(&server);
        let mut receiver =
            ArchiveRangeReceiverCandidate::new(limits(), page.snapshot_commitment, 5, 15).unwrap();
        page.entries[0].encoded.pop();
        let result = receiver.apply_page_with_commit(&page, |_| Ok::<(), ()>(()));
        assert_eq!(
            result,
            Err(ArchiveRangeReceiverError::PayloadLengthMismatch)
        );
        assert_eq!(receiver.receipt().end_index, 0);
    }
}
