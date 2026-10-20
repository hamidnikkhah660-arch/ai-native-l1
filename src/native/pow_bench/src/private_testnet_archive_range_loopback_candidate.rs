//! In-memory loopback integration of the archive range server and receiver candidates.
//!
//! This harness injects lost responses and corrupt/truncated pages at the API boundary. It is not
//! a TCP/socket/P2P test and must not be interpreted as a real transport reliability or DoS result.
use crate::private_testnet_archive_range_receiver_candidate::{
    ArchiveRangeReceiverCandidate, ArchiveRangeReceiverError, VerifiedArchiveRangeReceipt,
};
use crate::private_testnet_archive_range_server_candidate::{
    ArchiveRangeBudgetConfig, ArchiveRangeServerCandidate, ArchiveSyncPayload,
    ArchiveSyncServedPage,
};
use crate::private_testnet_archive_sync_candidate::{
    ArchiveEntryMeta, ArchiveSyncIndex, ArchiveSyncLimits,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;

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

fn budget() -> ArchiveRangeBudgetConfig {
    ArchiveRangeBudgetConfig {
        max_sessions: 2,
        per_session_max_pages: 6,
        per_session_max_items: 12,
        per_session_max_bytes: 30,
        global_max_pages: 6,
        global_max_items: 12,
        global_max_bytes: 30,
    }
}

fn fixture(generation: u64, budgets: ArchiveRangeBudgetConfig) -> ArchiveRangeServerCandidate {
    let specs = vec![
        (3, 3, b"ccccc".to_vec()),
        (1, 1, b"aaaa".to_vec()),
        (5, 5, b"e".to_vec()),
        (2, 2, b"bbb".to_vec()),
        (4, 4, b"dd".to_vec()),
    ];
    let metadata = specs
        .iter()
        .map(|(height, digest, bytes)| meta(*height, *digest, bytes))
        .collect();
    let index =
        ArchiveSyncIndex::new([0xC0; 32], [0xA1; 32], generation, metadata, limits()).unwrap();
    let payloads = specs
        .into_iter()
        .map(|(height, digest, bytes)| ArchiveSyncPayload::new(meta(height, digest, &bytes), bytes))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    ArchiveRangeServerCandidate::new(index, payloads, limits(), budgets).unwrap()
}

fn meta(height: u64, digest: u8, bytes: &[u8]) -> ArchiveEntryMeta {
    ArchiveEntryMeta {
        height,
        digest: [digest; 32],
        encoded_len: bytes.len() as u64,
        payload_sha256: Sha256::digest(bytes).into(),
    }
}

fn bootstrap(server: &ArchiveRangeServerCandidate) -> ArchiveRangeReceiverCandidate {
    ArchiveRangeReceiverCandidate::new(limits(), server.snapshot_commitment(), 5, 15).unwrap()
}

fn commit_page(
    receiver: &mut ArchiveRangeReceiverCandidate,
    page: &ArchiveSyncServedPage,
    persisted: &mut Vec<Vec<u8>>,
) -> Result<VerifiedArchiveRangeReceipt, ArchiveRangeReceiverError<&'static str>> {
    receiver.apply_page_with_commit(page, |valid| {
        persisted.extend(valid.entries.iter().map(|entry| entry.encoded.clone()));
        Ok::<(), &'static str>(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SESSION: [u8; 32] = [0x51; 32];
    const KEY: [u8; 32] = [0x61; 32];

    #[test]
    fn lost_first_and_middle_responses_retry_end_to_end_byte_exactly() {
        let server = fixture(44, budget());
        server.register_authenticated_session(SESSION, KEY).unwrap();
        let mut receiver = bootstrap(&server);
        let mut persisted = Vec::new();

        // Simulate a response lost after the server generated and budgeted it.
        let lost_first = server.serve_first_page(SESSION).unwrap();
        let first_retry = server.serve_first_page(SESSION).unwrap();
        assert!(Arc::ptr_eq(&lost_first, &first_retry));
        commit_page(&mut receiver, &first_retry, &mut persisted).unwrap();
        let cursor_1 = first_retry.plan.next_cursor.clone().unwrap();

        let lost_second = server.serve_next_page(SESSION, &cursor_1).unwrap();
        let second_retry = server.serve_next_page(SESSION, &cursor_1).unwrap();
        assert!(Arc::ptr_eq(&lost_second, &second_retry));
        commit_page(&mut receiver, &second_retry, &mut persisted).unwrap();
        let cursor_2 = second_retry.plan.next_cursor.clone().unwrap();

        let final_page = server.serve_next_page(SESSION, &cursor_2).unwrap();
        let receipt = commit_page(&mut receiver, &final_page, &mut persisted).unwrap();

        assert!(receipt.complete);
        assert_eq!(
            (receipt.total_items_verified, receipt.total_bytes_verified),
            (5, 15)
        );
        assert_eq!(
            persisted,
            vec![
                b"aaaa".to_vec(),
                b"bbb".to_vec(),
                b"ccccc".to_vec(),
                b"dd".to_vec(),
                b"e".to_vec()
            ]
        );
        let usage = server.global_usage().unwrap();
        assert_eq!((usage.pages, usage.items, usage.bytes), (5, 9, 29));
        assert_eq!(server.session_usage(&SESSION).unwrap(), usage);
    }

    #[test]
    fn truncated_or_corrupt_page_is_not_committed_then_valid_retry_recovers() {
        let server = fixture(44, budget());
        server.register_authenticated_session(SESSION, KEY).unwrap();
        let first = server.serve_first_page(SESSION).unwrap();
        let mut receiver = bootstrap(&server);
        let mut persisted = Vec::new();

        let mut truncated = (*first).clone();
        truncated.entries[0].encoded.pop();
        assert_eq!(
            commit_page(&mut receiver, &truncated, &mut persisted),
            Err(ArchiveRangeReceiverError::PayloadLengthMismatch)
        );
        let mut corrupt = (*first).clone();
        corrupt.entries[0].encoded[0] ^= 0x80;
        assert_eq!(
            commit_page(&mut receiver, &corrupt, &mut persisted),
            Err(ArchiveRangeReceiverError::PayloadHashMismatch)
        );
        assert!(persisted.is_empty());
        assert_eq!(receiver.receipt().end_index, 0);

        let recovered = commit_page(&mut receiver, &first, &mut persisted).unwrap();
        assert_eq!(recovered.end_index, 2);
        assert_eq!(persisted, vec![b"aaaa".to_vec(), b"bbb".to_vec()]);
    }

    #[test]
    fn stale_archive_generation_after_reorg_is_rejected_before_persistence() {
        let old_snapshot = fixture(44, budget());
        let new_snapshot = fixture(45, budget());
        assert_ne!(
            old_snapshot.snapshot_commitment(),
            new_snapshot.snapshot_commitment()
        );
        new_snapshot
            .register_authenticated_session(SESSION, KEY)
            .unwrap();
        let page_from_new_generation = new_snapshot.serve_first_page(SESSION).unwrap();
        let mut receiver = bootstrap(&old_snapshot);
        let mut persisted = Vec::new();

        assert_eq!(
            commit_page(&mut receiver, &page_from_new_generation, &mut persisted),
            Err(ArchiveRangeReceiverError::WrongSnapshot)
        );
        assert!(persisted.is_empty());
        assert_eq!(receiver.receipt().end_index, 0);
    }

    #[test]
    fn quota_denies_excess_retry_without_partial_debit_and_receiver_can_keep_progress() {
        let tight_budget = ArchiveRangeBudgetConfig {
            max_sessions: 1,
            per_session_max_pages: 1,
            per_session_max_items: 2,
            per_session_max_bytes: 7,
            global_max_pages: 1,
            global_max_items: 2,
            global_max_bytes: 7,
        };
        let server = fixture(44, tight_budget);
        server.register_authenticated_session(SESSION, KEY).unwrap();
        let mut receiver = bootstrap(&server);
        let first = server.serve_first_page(SESSION).unwrap();
        let before = server.global_usage().unwrap();
        assert_eq!(
            server.serve_first_page(SESSION).unwrap_err(),
            crate::private_testnet_archive_range_server_candidate::ArchiveRangeServerError::GlobalQuotaExceeded
        );
        assert_eq!(server.global_usage().unwrap(), before);
        let mut persisted = Vec::new();
        let receipt = commit_page(&mut receiver, &first, &mut persisted).unwrap();
        assert_eq!(receipt.end_index, 2);
        assert_eq!(server.global_usage().unwrap(), before);
    }
}

#[cfg(test)]
mod tcp_loopback_tests {
    use super::*;
    use crate::auth_transport::{
        derive_direction_key, open_record, seal_record, AuthError, MAX_AUTH_RECORD,
    };
    use crate::private_testnet_archive_range_receiver_candidate::VerifiedArchiveRangeReceipt;
    use crate::private_testnet_archive_range_server_candidate::ArchiveSyncServedEntry;
    use crate::private_testnet_archive_sync_candidate::ARCHIVE_SYNC_CURSOR_BYTES;
    use std::io::{self, Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::thread;
    use std::time::{Duration, Instant};

    const SESSION: [u8; 32] = [0x51; 32];
    const KEY: [u8; 32] = [0x61; 32];
    const REQUEST_MAGIC: &[u8; 4] = b"ARQ1";
    const RESPONSE_MAGIC: &[u8; 4] = b"ARP1";
    const MAX_REQUEST_FRAME: usize = 4 + 1 + 32 + ARCHIVE_SYNC_CURSOR_BYTES;
    const MAX_RESPONSE_FRAME: usize = 5 * 1024 * 1024;
    const LENGTH_PREFIX_BYTES: usize = 4;

    fn deadline(timeout: Duration) -> io::Result<Instant> {
        Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "deadline overflow"))
    }

    fn remaining(until: Instant) -> io::Result<Duration> {
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "I/O deadline elapsed",
            ))
        } else {
            Ok(left)
        }
    }

    fn write_deadline(stream: &mut TcpStream, bytes: &[u8], until: Instant) -> io::Result<()> {
        let mut offset = 0;
        while offset < bytes.len() {
            stream.set_write_timeout(Some(remaining(until)?))?;
            match stream.write(&bytes[offset..]) {
                Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "socket closed")),
                Ok(written) => offset += written,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1));
                    continue;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn read_exact_deadline(
        stream: &mut TcpStream,
        bytes: &mut [u8],
        until: Instant,
    ) -> io::Result<()> {
        let mut offset = 0;
        while offset < bytes.len() {
            stream.set_read_timeout(Some(remaining(until)?))?;
            match stream.read(&mut bytes[offset..]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated TCP frame",
                    ))
                }
                Ok(read) => offset += read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1));
                    continue;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn write_frame(stream: &mut TcpStream, body: &[u8], until: Instant) -> io::Result<()> {
        if body.len() > MAX_RESPONSE_FRAME {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "candidate frame exceeds hard cap",
            ));
        }
        let length = u32::try_from(body.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame length overflow"))?;
        write_deadline(stream, &length.to_be_bytes(), until)?;
        write_deadline(stream, body, until)
    }

    fn read_frame(stream: &mut TcpStream, max_len: usize, until: Instant) -> io::Result<Vec<u8>> {
        let mut prefix = [0; LENGTH_PREFIX_BYTES];
        read_exact_deadline(stream, &mut prefix, until)?;
        let len = u32::from_be_bytes(prefix) as usize;
        if len == 0 || len > max_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame length outside candidate cap",
            ));
        }
        let mut body = vec![0; len];
        read_exact_deadline(stream, &mut body, until)?;
        Ok(body)
    }

    fn connect_and_exchange(
        address: SocketAddr,
        body: &[u8],
        timeout: Duration,
    ) -> io::Result<Vec<u8>> {
        let until = deadline(timeout)?;
        let mut stream = TcpStream::connect_timeout(&address, remaining(until)?)?;
        stream.set_nodelay(true)?;
        write_frame(&mut stream, body, until)?;
        read_frame(&mut stream, MAX_RESPONSE_FRAME, until)
    }

    fn request_body(
        session: [u8; 32],
        cursor: Option<&[u8; ARCHIVE_SYNC_CURSOR_BYTES]>,
    ) -> Vec<u8> {
        let mut body = Vec::with_capacity(MAX_REQUEST_FRAME);
        body.extend_from_slice(REQUEST_MAGIC);
        body.push(u8::from(cursor.is_some()));
        body.extend_from_slice(&session);
        if let Some(cursor) = cursor {
            body.extend_from_slice(cursor);
        }
        body
    }

    fn parse_request(
        body: &[u8],
    ) -> io::Result<([u8; 32], Option<[u8; ARCHIVE_SYNC_CURSOR_BYTES]>)> {
        if body.len() < 4 + 1 + 32 || body.get(..4) != Some(REQUEST_MAGIC.as_slice()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid request magic/size",
            ));
        }
        let kind = body[4];
        let mut session = [0; 32];
        session.copy_from_slice(&body[5..37]);
        match kind {
            0 if body.len() == 37 => Ok((session, None)),
            1 if body.len() == 37 + ARCHIVE_SYNC_CURSOR_BYTES => {
                let mut cursor = [0; ARCHIVE_SYNC_CURSOR_BYTES];
                cursor.copy_from_slice(&body[37..]);
                Ok((session, Some(cursor)))
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid request cursor shape",
            )),
        }
    }

    fn encode_page(page: &ArchiveSyncServedPage) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(RESPONSE_MAGIC);
        out.extend_from_slice(&page.snapshot_commitment);
        out.extend_from_slice(&page.archive_total_items.to_be_bytes());
        out.extend_from_slice(&page.archive_total_bytes.to_be_bytes());
        out.extend_from_slice(
            &u64::try_from(page.plan.start_index)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "start index overflow"))?
                .to_be_bytes(),
        );
        out.extend_from_slice(
            &u64::try_from(page.plan.end_index)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "end index overflow"))?
                .to_be_bytes(),
        );
        out.extend_from_slice(&page.plan.page_number.to_be_bytes());
        out.extend_from_slice(&page.plan.page_bytes.to_be_bytes());
        out.extend_from_slice(&page.plan.total_items_after_page.to_be_bytes());
        out.extend_from_slice(&page.plan.total_bytes_after_page.to_be_bytes());
        out.push(u8::from(page.plan.complete));
        match &page.plan.next_cursor {
            Some(cursor) => {
                out.push(1);
                out.extend_from_slice(cursor);
            }
            None => out.push(0),
        }
        let count = u32::try_from(page.entries.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "entry count overflow"))?;
        out.extend_from_slice(&count.to_be_bytes());
        for entry in &page.entries {
            out.extend_from_slice(&entry.metadata.height.to_be_bytes());
            out.extend_from_slice(&entry.metadata.digest);
            out.extend_from_slice(&entry.metadata.encoded_len.to_be_bytes());
            out.extend_from_slice(&entry.metadata.payload_sha256);
            let encoded_len = u32::try_from(entry.encoded.len()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "payload length overflow")
            })?;
            out.extend_from_slice(&encoded_len.to_be_bytes());
            out.extend_from_slice(&entry.encoded);
        }
        if out.len() > MAX_RESPONSE_FRAME {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "encoded page exceeds frame cap",
            ));
        }
        Ok(out)
    }

    struct Decoder<'a> {
        bytes: &'a [u8],
        offset: usize,
    }
    impl<'a> Decoder<'a> {
        fn new(bytes: &'a [u8]) -> Self {
            Self { bytes, offset: 0 }
        }
        fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
            let end = self
                .offset
                .checked_add(n)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "offset overflow"))?;
            let slice = self.bytes.get(self.offset..end).ok_or_else(|| {
                io::Error::new(io::ErrorKind::UnexpectedEof, "truncated encoded page")
            })?;
            self.offset = end;
            Ok(slice)
        }
        fn u8(&mut self) -> io::Result<u8> {
            Ok(self.take(1)?[0])
        }
        fn u32(&mut self) -> io::Result<u32> {
            Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
        }
        fn u64(&mut self) -> io::Result<u64> {
            Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
        }
        fn array32(&mut self) -> io::Result<[u8; 32]> {
            Ok(self.take(32)?.try_into().unwrap())
        }
    }

    fn decode_page(body: &[u8]) -> io::Result<ArchiveSyncServedPage> {
        if body.len() < 4 || body.get(..4) != Some(RESPONSE_MAGIC.as_slice()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid response magic",
            ));
        }
        let mut d = Decoder::new(body);
        let _ = d.take(4)?;
        let snapshot_commitment = d.array32()?;
        let archive_total_items = d.u64()?;
        let archive_total_bytes = d.u64()?;
        let start_index = usize::try_from(d.u64()?)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "start index overflow"))?;
        let end_index = usize::try_from(d.u64()?)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "end index overflow"))?;
        let page_number = d.u32()?;
        let page_bytes = d.u64()?;
        let total_items_after_page = d.u64()?;
        let total_bytes_after_page = d.u64()?;
        let complete = match d.u8()? {
            0 => false,
            1 => true,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid complete flag",
                ))
            }
        };
        let next_cursor = match d.u8()? {
            0 => None,
            1 => Some(d.take(ARCHIVE_SYNC_CURSOR_BYTES)?.try_into().unwrap()),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid cursor flag",
                ))
            }
        };
        let count = d.u32()? as usize;
        if count > 256 || end_index < start_index || end_index - start_index != count {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid bounded range",
            ));
        }
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            let height = d.u64()?;
            let digest = d.array32()?;
            let encoded_len = d.u64()?;
            let payload_sha256 = d.array32()?;
            let actual_len = d.u32()? as usize;
            if actual_len == 0
                || actual_len > MAX_RESPONSE_FRAME
                || actual_len as u64 != encoded_len
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid bounded payload length",
                ));
            }
            let encoded = d.take(actual_len)?.to_vec();
            entries.push(ArchiveSyncServedEntry {
                metadata: ArchiveEntryMeta {
                    height,
                    digest,
                    encoded_len,
                    payload_sha256,
                },
                encoded,
            });
        }
        if d.offset != body.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "trailing response bytes",
            ));
        }
        Ok(ArchiveSyncServedPage {
            plan: crate::private_testnet_archive_sync_candidate::ArchiveSyncPage {
                start_index,
                end_index,
                page_number,
                page_bytes,
                total_items_after_page,
                total_bytes_after_page,
                complete,
                next_cursor,
            },
            archive_total_items,
            archive_total_bytes,
            snapshot_commitment,
            entries,
        })
    }

    fn handle_one_request(
        stream: &mut TcpStream,
        server: &ArchiveRangeServerCandidate,
    ) -> io::Result<()> {
        let until = deadline(Duration::from_secs(5))?;
        let body = read_frame(stream, MAX_REQUEST_FRAME, until)?;
        let (session, cursor) = parse_request(&body)?;
        let page = match cursor {
            None => server.serve_first_page(session).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("first page rejected: {e:?}"),
                )
            })?,
            Some(cursor) => server.serve_next_page(session, &cursor).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("next page rejected: {e:?}"),
                )
            })?,
        };
        let encoded = encode_page(&page)?;
        write_frame(stream, &encoded, until)
    }

    fn start_server(server: Arc<ArchiveRangeServerCandidate>, request_count: usize) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || {
            let until = Instant::now() + Duration::from_secs(5);
            for _ in 0..request_count {
                let (mut stream, _) = loop {
                    match listener.accept() {
                        Ok(pair) => break pair,
                        Err(error)
                            if error.kind() == io::ErrorKind::WouldBlock
                                && Instant::now() < until =>
                        {
                            thread::sleep(Duration::from_millis(2))
                        }
                        Err(error) => panic!("loopback accept failed/deadline elapsed: {error}"),
                    }
                };
                stream.set_nodelay(true).unwrap();
                handle_one_request(&mut stream, &server).unwrap();
            }
        });
        address
    }

    fn tcp_request(
        address: SocketAddr,
        session: [u8; 32],
        cursor: Option<&[u8; ARCHIVE_SYNC_CURSOR_BYTES]>,
        timeout: Duration,
    ) -> io::Result<ArchiveSyncServedPage> {
        let body = request_body(session, cursor);
        let response = connect_and_exchange(address, &body, timeout)?;
        decode_page(&response)
    }

    fn new_receiver(server: &ArchiveRangeServerCandidate) -> ArchiveRangeReceiverCandidate {
        ArchiveRangeReceiverCandidate::new(limits(), server.snapshot_commitment(), 5, 15).unwrap()
    }

    fn persist(
        receiver: &mut ArchiveRangeReceiverCandidate,
        page: &ArchiveSyncServedPage,
        saved: &mut Vec<Vec<u8>>,
    ) -> io::Result<VerifiedArchiveRangeReceipt> {
        receiver
            .apply_page_with_commit(page, |verified| {
                saved.extend(verified.entries.iter().map(|entry| entry.encoded.clone()));
                Ok::<(), io::Error>(())
            })
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("receiver rejected page: {error:?}"),
                )
            })
    }

    #[test]
    fn tcp_loopback_retries_lost_first_and_middle_responses_and_finishes_import() {
        let server = Arc::new(fixture(44, budget()));
        server.register_authenticated_session(SESSION, KEY).unwrap();
        let address = start_server(Arc::clone(&server), 5);
        let mut receiver = new_receiver(&server);
        let mut saved = Vec::new();

        let lost_first_response =
            tcp_request(address, SESSION, None, Duration::from_secs(5)).unwrap();
        let first = tcp_request(address, SESSION, None, Duration::from_secs(5)).unwrap();
        assert_eq!(lost_first_response, first);
        persist(&mut receiver, &first, &mut saved).unwrap();

        let cursor1 = first.plan.next_cursor.unwrap();
        let lost_middle_response =
            tcp_request(address, SESSION, Some(&cursor1), Duration::from_secs(5)).unwrap();
        let middle = tcp_request(address, SESSION, Some(&cursor1), Duration::from_secs(5)).unwrap();
        assert_eq!(lost_middle_response, middle);
        persist(&mut receiver, &middle, &mut saved).unwrap();

        let cursor2 = middle.plan.next_cursor.unwrap();
        let last = tcp_request(address, SESSION, Some(&cursor2), Duration::from_secs(5)).unwrap();
        let receipt = persist(&mut receiver, &last, &mut saved).unwrap();
        assert!(receipt.complete);
        assert_eq!(
            (receipt.total_items_verified, receipt.total_bytes_verified),
            (5, 15)
        );
        assert_eq!(
            saved,
            vec![
                b"aaaa".to_vec(),
                b"bbb".to_vec(),
                b"ccccc".to_vec(),
                b"dd".to_vec(),
                b"e".to_vec()
            ]
        );
        let usage = server.global_usage().unwrap();
        assert_eq!((usage.pages, usage.items, usage.bytes), (5, 9, 29));
    }

    #[test]
    fn tcp_truncated_frame_is_rejected_without_receiver_progress() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server_thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let until = deadline(Duration::from_secs(5)).unwrap();
            let _request = read_frame(&mut stream, MAX_REQUEST_FRAME, until).unwrap();
            stream.write_all(&100u32.to_be_bytes()).unwrap();
            let mut partial = RESPONSE_MAGIC.to_vec();
            partial.extend_from_slice(&[0xA1; 5]);
            stream.write_all(&partial).unwrap();
            // Return early: the declared body is intentionally truncated.
        });
        let honest_server = fixture(44, budget());
        let receiver = new_receiver(&honest_server);
        let result = tcp_request(address, SESSION, None, Duration::from_secs(1));
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(receiver.receipt().end_index, 0);
        server_thread.join().unwrap();
    }

    #[test]
    fn tcp_oversized_frame_is_rejected_before_body_allocation() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server_thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let until = deadline(Duration::from_secs(5)).unwrap();
            let _request = read_frame(&mut stream, MAX_REQUEST_FRAME, until).unwrap();
            stream
                .write_all(&((MAX_RESPONSE_FRAME as u32) + 1).to_be_bytes())
                .unwrap();
        });
        let result = tcp_request(address, SESSION, None, Duration::from_secs(1));
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        server_thread.join().unwrap();
    }

    #[test]
    fn tcp_slow_partial_response_obeys_one_total_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server_thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let until = deadline(Duration::from_secs(5)).unwrap();
            let _request = read_frame(&mut stream, MAX_REQUEST_FRAME, until).unwrap();
            stream.write_all(&100u32.to_be_bytes()).unwrap();
            let mut partial = RESPONSE_MAGIC.to_vec();
            partial.extend_from_slice(&[0xA1; 4]);
            stream.write_all(&partial).unwrap();
            thread::sleep(Duration::from_millis(150));
        });
        let begin = Instant::now();
        let result = tcp_request(address, SESSION, None, Duration::from_millis(35));
        let elapsed = begin.elapsed();
        assert!(matches!(
            result.unwrap_err().kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        ));
        assert!(
            elapsed < Duration::from_millis(120),
            "total deadline exceeded: {elapsed:?}"
        );
        server_thread.join().unwrap();
    }

    const TEST_PSK: [u8; 32] = [0xB3; 32];
    const CLIENT_NONCE: [u8; 32] = [0x91; 32];
    const SERVER_NONCE: [u8; 32] = [0xA1; 32];

    fn auth_key(direction: u8) -> [u8; 32] {
        derive_direction_key(&TEST_PSK, CLIENT_NONCE, SERVER_NONCE, direction)
    }

    fn auth_io_error(error: AuthError) -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("authenticated record rejected: {error:?}"),
        )
    }

    fn tcp_authenticated_request(
        address: SocketAddr,
        session: [u8; 32],
        cursor: Option<&[u8; ARCHIVE_SYNC_CURSOR_BYTES]>,
        sequence: u64,
        tamper_request_mac: bool,
        timeout: Duration,
    ) -> io::Result<ArchiveSyncServedPage> {
        let until = deadline(timeout)?;
        let mut stream = TcpStream::connect_timeout(&address, remaining(until)?)?;
        stream.set_nodelay(true)?;
        tcp_authenticated_request_on_stream(
            &mut stream,
            session,
            cursor,
            sequence,
            tamper_request_mac,
            until,
        )
    }

    fn tcp_authenticated_request_on_stream(
        stream: &mut TcpStream,
        session: [u8; 32],
        cursor: Option<&[u8; ARCHIVE_SYNC_CURSOR_BYTES]>,
        sequence: u64,
        tamper_request_mac: bool,
        until: Instant,
    ) -> io::Result<ArchiveSyncServedPage> {
        let inner_request = request_body(session, cursor);
        let mut record =
            seal_record(&auth_key(0), sequence, &inner_request).map_err(auth_io_error)?;
        if tamper_request_mac {
            *record.last_mut().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "empty auth record")
            })? ^= 1;
        }
        write_frame(stream, &record, until)?;
        let response_record = read_frame(stream, MAX_AUTH_RECORD, until)?;
        let response =
            open_record(&auth_key(1), sequence, &response_record).map_err(auth_io_error)?;
        decode_page(&response)
    }

    fn handle_one_authenticated_request(
        stream: &mut TcpStream,
        server: &ArchiveRangeServerCandidate,
        sequence: u64,
        tamper_response_mac: bool,
    ) -> io::Result<()> {
        let until = deadline(Duration::from_secs(5))?;
        let record = read_frame(stream, MAX_AUTH_RECORD, until)?;
        let request = open_record(&auth_key(0), sequence, &record).map_err(auth_io_error)?;
        let (session, cursor) = parse_request(&request)?;
        let page = match cursor {
            None => server.serve_first_page(session).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("first page rejected: {e:?}"),
                )
            })?,
            Some(cursor) => server.serve_next_page(session, &cursor).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("next page rejected: {e:?}"),
                )
            })?,
        };
        let body = encode_page(&page)?;
        let mut record = seal_record(&auth_key(1), sequence, &body).map_err(auth_io_error)?;
        if tamper_response_mac {
            *record.last_mut().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "empty auth response")
            })? ^= 1;
        }
        write_frame(stream, &record, until)
    }

    fn start_authenticated_server(
        server: Arc<ArchiveRangeServerCandidate>,
        request_count: usize,
        tamper_response_at: Option<usize>,
    ) -> (SocketAddr, thread::JoinHandle<io::Result<()>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let task = thread::spawn(move || {
            let until = Instant::now() + Duration::from_secs(5);
            for sequence in 0..request_count {
                let (mut stream, _) = loop {
                    match listener.accept() {
                        Ok(pair) => break pair,
                        Err(error)
                            if error.kind() == io::ErrorKind::WouldBlock
                                && Instant::now() < until =>
                        {
                            thread::sleep(Duration::from_millis(2))
                        }
                        Err(error) => return Err(error),
                    }
                };
                stream.set_nodelay(true)?;
                handle_one_authenticated_request(
                    &mut stream,
                    &server,
                    sequence as u64,
                    tamper_response_at == Some(sequence),
                )?;
            }
            Ok(())
        });
        (address, task)
    }

    #[test]
    fn authenticated_tcp_records_wrap_archive_ranges_and_retry_by_session_sequence() {
        let server = Arc::new(fixture(44, budget()));
        server.register_authenticated_session(SESSION, KEY).unwrap();
        let (address, task) = start_authenticated_server(Arc::clone(&server), 5, None);
        let mut receiver = new_receiver(&server);
        let mut saved = Vec::new();

        let lost_first =
            tcp_authenticated_request(address, SESSION, None, 0, false, Duration::from_secs(5))
                .unwrap();
        let first =
            tcp_authenticated_request(address, SESSION, None, 1, false, Duration::from_secs(5))
                .unwrap();
        assert_eq!(lost_first, first);
        persist(&mut receiver, &first, &mut saved).unwrap();

        let cursor1 = first.plan.next_cursor.unwrap();
        let lost_middle = tcp_authenticated_request(
            address,
            SESSION,
            Some(&cursor1),
            2,
            false,
            Duration::from_secs(5),
        )
        .unwrap();
        let middle = tcp_authenticated_request(
            address,
            SESSION,
            Some(&cursor1),
            3,
            false,
            Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(lost_middle, middle);
        persist(&mut receiver, &middle, &mut saved).unwrap();

        let cursor2 = middle.plan.next_cursor.unwrap();
        let last = tcp_authenticated_request(
            address,
            SESSION,
            Some(&cursor2),
            4,
            false,
            Duration::from_secs(5),
        )
        .unwrap();
        assert!(persist(&mut receiver, &last, &mut saved).unwrap().complete);
        task.join().unwrap().unwrap();
        assert_eq!(
            saved,
            vec![
                b"aaaa".to_vec(),
                b"bbb".to_vec(),
                b"ccccc".to_vec(),
                b"dd".to_vec(),
                b"e".to_vec()
            ]
        );
        assert_eq!(server.global_usage().unwrap().bytes, 29);
    }

    #[test]
    fn authenticated_tcp_rejects_tampered_server_mac_before_receiver_import() {
        let server = Arc::new(fixture(44, budget()));
        server.register_authenticated_session(SESSION, KEY).unwrap();
        let (address, task) = start_authenticated_server(Arc::clone(&server), 1, Some(0));
        let receiver = new_receiver(&server);
        let result =
            tcp_authenticated_request(address, SESSION, None, 0, false, Duration::from_secs(5));
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert_eq!(receiver.receipt().end_index, 0);
        task.join().unwrap().unwrap();
        // The serving candidate debits a response attempt before transport delivery is confirmed.
        assert_eq!(server.global_usage().unwrap().pages, 1);
    }

    fn start_authenticated_replay_server(
        server: Arc<ArchiveRangeServerCandidate>,
    ) -> (SocketAddr, thread::JoinHandle<io::Result<()>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let task = thread::spawn(move || {
            let until = Instant::now() + Duration::from_secs(10);
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(pair) => break pair,
                    Err(error)
                        if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < until =>
                    {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => return Err(error),
                }
            };
            stream.set_nodelay(true)?;
            handle_one_authenticated_request(&mut stream, &server, 0, false)?;
            // This connection expects sequence 1; a replayed sequence 0 must be rejected.
            handle_one_authenticated_request(&mut stream, &server, 1, false)
        });
        (address, task)
    }

    #[test]
    fn authenticated_tcp_replay_sequence_is_rejected_before_a_second_page_charge() {
        let server = Arc::new(fixture(44, budget()));
        server.register_authenticated_session(SESSION, KEY).unwrap();
        let (address, task) = start_authenticated_replay_server(Arc::clone(&server));
        let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(5)).unwrap();
        stream.set_nodelay(true).unwrap();
        let first = tcp_authenticated_request_on_stream(
            &mut stream,
            SESSION,
            None,
            0,
            false,
            deadline(Duration::from_secs(5)).unwrap(),
        )
        .unwrap();
        assert_eq!(first.plan.page_number, 1);
        // Replay sequence zero on the same authenticated session; the next sequence must be one.
        let replay = tcp_authenticated_request_on_stream(
            &mut stream,
            SESSION,
            None,
            0,
            false,
            deadline(Duration::from_secs(5)).unwrap(),
        );
        assert!(matches!(
            replay.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::ConnectionReset
        ));
        assert_eq!(
            task.join().unwrap().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(server.global_usage().unwrap().pages, 1);
    }

    #[test]
    fn authenticated_tcp_rejects_tampered_client_mac_before_archive_service() {
        let server = Arc::new(fixture(44, budget()));
        server.register_authenticated_session(SESSION, KEY).unwrap();
        let (address, task) = start_authenticated_server(Arc::clone(&server), 1, None);
        let result =
            tcp_authenticated_request(address, SESSION, None, 0, true, Duration::from_secs(5));
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(server.global_usage().unwrap().pages, 0);
        assert_eq!(
            task.join().unwrap().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
