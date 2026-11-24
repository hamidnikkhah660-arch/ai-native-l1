//! Bounded persistent Q6PD candidate store with per-peer sequence high-water marks.
//!
//! Signed records are still untrusted discovery hints. This store never approves or dials
//! records. It preserves sequence high-water marks after candidate expiry so a replay cannot
//! be reintroduced immediately after pruning. A local operator must separately authorize a
//! peer, or a future independently audited endorsement policy must make it eligible.
use crate::qrun_v06_peer_discovery_candidate::{
    decode_q6pd_pull_request, encode_q6pd_pull_response, verify_q6pd_peer_record, Q6pdError,
    VerifiedQ6pdPeerRecord,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

// Per-node inventory safety bounds only. Peer gossip can span a network larger than any
// single node's local address book; these constants are not a network-wide node limit.
pub const Q6PD_MAX_CANDIDATES: usize = 16_384;
pub const Q6PD_MAX_SEQUENCE_WATERMARKS: usize = 32_768;
pub const Q6PD_MAX_STORE_BYTES: usize = 32 * 1024 * 1024;
const Q6PD_WATERMARK_RETENTION_MS: u64 = 30 * 24 * 60 * 60 * 1000;
const STORE_SCHEMA: &str = "qfp6-q6pd-candidate-store";
const STORE_VERSION: u64 = 1;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Q6pdStoreError {
    Io(String),
    Malformed,
    ChecksumMismatch,
    WrongNetwork,
    WrongProfile,
    LockHeld,
    StoreTooLarge,
    Capacity,
    Replay,
    InvalidRecord(Q6pdError),
}
impl std::fmt::Display for Q6pdStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Q6pdStoreError {}
impl From<std::io::Error> for Q6pdStoreError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}
impl From<Q6pdError> for Q6pdStoreError {
    fn from(error: Q6pdError) -> Self {
        Self::InvalidRecord(error)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct StoredCandidate {
    peer_id: String,
    sequence: u64,
    wire_hex: String,
    fingerprint: String,
    expires_at_ms: u64,
    last_seen_ms: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct SequenceWatermark {
    peer_id: String,
    sequence: u64,
    fingerprint: String,
    observed_at_ms: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct StorePayload {
    schema: String,
    version: u64,
    network_id: String,
    profile_id: String,
    watermarks: Vec<SequenceWatermark>,
    candidates: Vec<StoredCandidate>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct StoreEnvelope {
    payload: StorePayload,
    checksum: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Q6pdIngestResult {
    Inserted,
    Updated,
    Duplicate,
}

pub struct Q6pdPeerRecordStore {
    path: PathBuf,
    lock_path: PathBuf,
    _lock: File,
    network_id: [u8; 32],
    profile_id: [u8; 32],
    candidates: BTreeMap<String, StoredCandidate>,
    watermarks: BTreeMap<String, SequenceWatermark>,
}
impl Q6pdPeerRecordStore {
    pub fn open(
        path: impl AsRef<Path>,
        network_id: [u8; 32],
        profile_id: [u8; 32],
        now_ms: u64,
    ) -> Result<Self, Q6pdStoreError> {
        if network_id == [0; 32] || profile_id == [0; 32] {
            return Err(Q6pdStoreError::Malformed);
        }
        let path = path.as_ref().to_path_buf();
        let parent = path.parent().ok_or(Q6pdStoreError::Malformed)?;
        fs::create_dir_all(parent)?;
        let lock_path = path.with_extension("q6pd.lock");
        let lock = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    Q6pdStoreError::LockHeld
                } else {
                    error.into()
                }
            })?;
        let mut store = Self {
            path,
            lock_path,
            _lock: lock,
            network_id,
            profile_id,
            candidates: BTreeMap::new(),
            watermarks: BTreeMap::new(),
        };
        if store.path.exists() {
            store.load()?;
        } else {
            // Persist the network/profile binding even before the first peer record arrives.
            store.persist()?;
        }
        let before_counts = (store.candidates.len(), store.watermarks.len());
        store.prune_expired(now_ms);
        store.prune_old_watermarks(now_ms);
        if before_counts != (store.candidates.len(), store.watermarks.len()) {
            store.persist()?;
        }
        Ok(store)
    }

    pub fn candidate_count(&self) -> usize {
        self.candidates.len()
    }

    /// Separate durable Address Manager state; the signed-record store remains authoritative.
    pub fn address_manager_path(&self) -> PathBuf {
        self.path.with_extension("q6pd-addrman.json")
    }

    /// Return a bounded canonical batch of current signed records for peer-to-peer gossip.
    pub fn gossip_record_wires(&self, now_ms: u64, limit: usize) -> Vec<Vec<u8>> {
        if limit == 0 {
            return Vec::new();
        }
        let mut records: Vec<([u8; 32], Vec<u8>)> = self
            .candidates
            .values()
            .filter(|candidate| candidate.expires_at_ms > now_ms)
            .filter_map(|candidate| {
                let wire = decode_hex(&candidate.wire_hex).ok()?;
                let record = verify_q6pd_peer_record(
                    &wire,
                    &self.network_id,
                    &self.profile_id,
                    now_ms / 1_000,
                )
                .ok()?;
                Some((record.peer_id, wire))
            })
            .collect();
        records.sort_by_key(|(peer_id, _)| *peer_id);
        let count = limit
            .min(crate::qrun_v06_peer_discovery_candidate::Q6PD_MAX_RECORDS_PER_FRAME)
            .min(records.len());
        if count == 0 {
            return Vec::new();
        }
        // Rotate the bounded gossip window so records beyond the first frame are
        // eventually relayed instead of permanently starving by peer-ID order.
        let start = ((now_ms / 30_000).wrapping_mul(73) as usize) % records.len();
        (0..count)
            .map(|offset| records[(start + offset) % records.len()].1.clone())
            .collect()
    }

    pub fn watermark_count(&self) -> usize {
        self.watermarks.len()
    }

    /// Return the durable sequence high-water for one peer identity, including expired records.
    /// This is used by an operator-configured node to choose its next self-announcement sequence.
    pub fn sequence_for_peer(&self, peer_id: &[u8; 32]) -> Option<u64> {
        let key = encode_hex(peer_id);
        self.watermarks
            .get(&key)
            .map(|watermark| watermark.sequence)
    }

    pub fn candidates(&self, now_ms: u64) -> Vec<VerifiedQ6pdPeerRecord> {
        self.candidates
            .values()
            .filter(|candidate| candidate.expires_at_ms > now_ms)
            .filter_map(|candidate| {
                let wire = decode_hex(&candidate.wire_hex).ok()?;
                verify_q6pd_peer_record(&wire, &self.network_id, &self.profile_id, now_ms / 1000)
                    .ok()
            })
            .collect()
    }

    /// Return the exact current signed record for one local identity, if still live.
    /// Callers may send it to an authenticated seed so the seed can add this peer to
    /// its own address inventory without learning or trusting any private key material.
    pub fn record_wire_for_peer(&self, peer_id: &[u8; 32], now_ms: u64) -> Option<Vec<u8>> {
        let key = encode_hex(peer_id);
        let candidate = self.candidates.get(&key)?;
        if candidate.expires_at_ms <= now_ms {
            return None;
        }
        let wire = decode_hex(&candidate.wire_hex).ok()?;
        let verified =
            verify_q6pd_peer_record(&wire, &self.network_id, &self.profile_id, now_ms / 1000)
                .ok()?;
        (verified.peer_id == *peer_id).then_some(wire)
    }

    /// Answer one bounded Q6PD request with currently live, locally verified candidate records.
    /// The returned records remain candidate hints; serving them does not approve or dial peers.
    pub fn respond_to_pull_frame(
        &self,
        request_frame: &[u8],
        now_secs: u64,
    ) -> Result<Vec<u8>, Q6pdStoreError> {
        let request = decode_q6pd_pull_request(request_frame, &self.network_id, &self.profile_id)?;
        let now_ms = now_secs.saturating_mul(1000);
        let mut eligible: Vec<([u8; 32], Vec<u8>)> = self
            .candidates
            .values()
            .filter(|candidate| candidate.expires_at_ms > now_ms)
            .filter_map(|candidate| {
                let wire = decode_hex(&candidate.wire_hex).ok()?;
                let record =
                    verify_q6pd_peer_record(&wire, &self.network_id, &self.profile_id, now_secs)
                        .ok()?;
                Some((record.peer_id, wire))
            })
            .collect();
        eligible.sort_by_key(|(peer_id, _)| *peer_id);
        // Rotate the bounded response window using the request nonce. A fixed
        // sorted prefix would starve every peer after the first frame; rotating makes
        // the complete inventory discoverable over repeated Bitcoin-style addr exchanges.
        let count = eligible.len().min(request.max_records as usize);
        let start = if eligible.len() > count {
            (request.request_id as usize) % eligible.len()
        } else {
            0
        };
        let records: Vec<Vec<u8>> = (0..count)
            .map(|offset| eligible[(start + offset) % eligible.len()].1.clone())
            .collect();
        encode_q6pd_pull_response(&request, &records, now_secs).map_err(Into::into)
    }

    /// Verify and persist one signed peer record. Equal-sequence identical records are
    /// idempotent; lower or conflicting equal-sequence records are rejected as replay.
    /// This operation stores a candidate only; Q6PD AddrMan separately selects signed records
    /// for bounded outbound attempts. No operator trust or consensus authority is granted.
    pub fn ingest(&mut self, wire: &[u8], now_ms: u64) -> Result<Q6pdIngestResult, Q6pdStoreError> {
        let record =
            verify_q6pd_peer_record(wire, &self.network_id, &self.profile_id, now_ms / 1000)?;
        let peer_id = encode_hex(&record.peer_id);
        let fingerprint = fingerprint(wire);
        let expires_at_ms = record
            .issued_at_secs
            .saturating_add(record.ttl_secs as u64)
            .saturating_mul(1000);
        if expires_at_ms <= now_ms {
            return Err(Q6pdStoreError::InvalidRecord(Q6pdError::Expired));
        }

        if let Some(watermark) = self.watermarks.get(&peer_id) {
            if record.sequence < watermark.sequence
                || (record.sequence == watermark.sequence && fingerprint != watermark.fingerprint)
            {
                return Err(Q6pdStoreError::Replay);
            }
            if record.sequence == watermark.sequence {
                if let Some(candidate) = self.candidates.get_mut(&peer_id) {
                    if candidate.fingerprint != fingerprint {
                        return Err(Q6pdStoreError::Replay);
                    }
                    let previous_seen = candidate.last_seen_ms;
                    candidate.last_seen_ms = candidate.last_seen_ms.max(now_ms);
                    if let Err(error) = self.persist() {
                        if let Some(candidate) = self.candidates.get_mut(&peer_id) {
                            candidate.last_seen_ms = previous_seen;
                        }
                        return Err(error);
                    }
                    return Ok(Q6pdIngestResult::Duplicate);
                }
                // A previously accepted, now-expired record remains covered by its
                // watermark. Replaying it cannot make the expired candidate live again.
                return Err(Q6pdStoreError::Replay);
            }
        } else if self.watermarks.len() >= Q6PD_MAX_SEQUENCE_WATERMARKS {
            self.prune_old_watermarks(now_ms);
            if self.watermarks.len() >= Q6PD_MAX_SEQUENCE_WATERMARKS {
                return Err(Q6pdStoreError::Capacity);
            }
        }

        self.prune_expired(now_ms);
        if !self.candidates.contains_key(&peer_id) && self.candidates.len() >= Q6PD_MAX_CANDIDATES {
            return Err(Q6pdStoreError::Capacity);
        }

        let before_candidates = self.candidates.clone();
        let before_watermarks = self.watermarks.clone();
        let was_present = self.candidates.contains_key(&peer_id);
        self.candidates.insert(
            peer_id.clone(),
            StoredCandidate {
                peer_id: peer_id.clone(),
                sequence: record.sequence,
                wire_hex: encode_hex(wire),
                fingerprint: fingerprint.clone(),
                expires_at_ms,
                last_seen_ms: now_ms,
            },
        );
        self.watermarks.insert(
            peer_id.clone(),
            SequenceWatermark {
                peer_id,
                sequence: record.sequence,
                fingerprint,
                observed_at_ms: now_ms,
            },
        );
        if let Err(error) = self.persist() {
            self.candidates = before_candidates;
            self.watermarks = before_watermarks;
            return Err(error);
        }
        Ok(if was_present {
            Q6pdIngestResult::Updated
        } else {
            Q6pdIngestResult::Inserted
        })
    }

    pub fn prune_expired(&mut self, now_ms: u64) {
        self.candidates
            .retain(|_, candidate| candidate.expires_at_ms > now_ms);
    }

    fn prune_old_watermarks(&mut self, now_ms: u64) {
        self.watermarks.retain(|_, watermark| {
            watermark
                .observed_at_ms
                .saturating_add(Q6PD_WATERMARK_RETENTION_MS)
                > now_ms
                || self.candidates.contains_key(&watermark.peer_id)
        });
    }

    fn payload(&self) -> StorePayload {
        StorePayload {
            schema: STORE_SCHEMA.to_string(),
            version: STORE_VERSION,
            network_id: encode_hex(&self.network_id),
            profile_id: encode_hex(&self.profile_id),
            watermarks: self.watermarks.values().cloned().collect(),
            candidates: self.candidates.values().cloned().collect(),
        }
    }

    fn persist(&self) -> Result<(), Q6pdStoreError> {
        let payload = self.payload();
        let canonical = serde_json::to_vec(&payload).map_err(|_| Q6pdStoreError::Malformed)?;
        let envelope = StoreEnvelope {
            payload,
            checksum: fingerprint(&canonical),
        };
        let bytes = serde_json::to_vec(&envelope).map_err(|_| Q6pdStoreError::Malformed)?;
        if bytes.len() > Q6PD_MAX_STORE_BYTES {
            return Err(Q6pdStoreError::StoreTooLarge);
        }
        write_atomic(&self.path, &bytes)?;
        Ok(())
    }

    fn load(&mut self) -> Result<(), Q6pdStoreError> {
        let metadata = fs::symlink_metadata(&self.path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(Q6pdStoreError::Malformed);
        }
        if metadata.len() as usize > Q6PD_MAX_STORE_BYTES {
            return Err(Q6pdStoreError::StoreTooLarge);
        }
        let mut file = File::open(&self.path)?;
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.read_to_end(&mut bytes)?;
        let envelope: StoreEnvelope =
            serde_json::from_slice(&bytes).map_err(|_| Q6pdStoreError::Malformed)?;
        let canonical =
            serde_json::to_vec(&envelope.payload).map_err(|_| Q6pdStoreError::Malformed)?;
        if fingerprint(&canonical) != envelope.checksum {
            return Err(Q6pdStoreError::ChecksumMismatch);
        }
        let payload = envelope.payload;
        if payload.schema != STORE_SCHEMA || payload.version != STORE_VERSION {
            return Err(Q6pdStoreError::Malformed);
        }
        if decode_hex_32(&payload.network_id)? != self.network_id {
            return Err(Q6pdStoreError::WrongNetwork);
        }
        if decode_hex_32(&payload.profile_id)? != self.profile_id {
            return Err(Q6pdStoreError::WrongProfile);
        }
        if payload.candidates.len() > Q6PD_MAX_CANDIDATES
            || payload.watermarks.len() > Q6PD_MAX_SEQUENCE_WATERMARKS
        {
            return Err(Q6pdStoreError::Capacity);
        }
        let mut candidates = BTreeMap::new();
        for candidate in payload.candidates {
            if candidate.peer_id != candidate.peer_id.to_ascii_lowercase()
                || candidate.sequence == 0
                || candidate.fingerprint.len() != 64
            {
                return Err(Q6pdStoreError::Malformed);
            }
            let wire = decode_hex(&candidate.wire_hex)?;
            if fingerprint(&wire) != candidate.fingerprint {
                return Err(Q6pdStoreError::ChecksumMismatch);
            }
            let record = verify_q6pd_peer_record(
                &wire,
                &self.network_id,
                &self.profile_id,
                candidate.expires_at_ms.saturating_sub(1) / 1000,
            )?;
            if encode_hex(&record.peer_id) != candidate.peer_id
                || record.sequence != candidate.sequence
                || record
                    .issued_at_secs
                    .saturating_add(record.ttl_secs as u64)
                    .saturating_mul(1000)
                    != candidate.expires_at_ms
            {
                return Err(Q6pdStoreError::Malformed);
            }
            if candidates
                .insert(candidate.peer_id.clone(), candidate)
                .is_some()
            {
                return Err(Q6pdStoreError::Malformed);
            }
        }
        let mut watermarks = BTreeMap::new();
        for watermark in payload.watermarks {
            if watermark.sequence == 0
                || watermark.peer_id.len() != 64
                || watermark.fingerprint.len() != 64
                || decode_hex_32(&watermark.peer_id).is_err()
                || decode_hex_32(&watermark.fingerprint).is_err()
            {
                return Err(Q6pdStoreError::Malformed);
            }
            if let Some(candidate) = candidates.get(&watermark.peer_id) {
                if candidate.sequence != watermark.sequence
                    || candidate.fingerprint != watermark.fingerprint
                {
                    return Err(Q6pdStoreError::Malformed);
                }
            }
            if watermarks
                .insert(watermark.peer_id.clone(), watermark)
                .is_some()
            {
                return Err(Q6pdStoreError::Malformed);
            }
        }
        if candidates
            .keys()
            .any(|peer_id| !watermarks.contains_key(peer_id))
        {
            return Err(Q6pdStoreError::Malformed);
        }
        self.candidates = candidates;
        self.watermarks = watermarks;
        Ok(())
    }
}
impl Drop for Q6pdPeerRecordStore {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_path);
    }
}

fn fingerprint(bytes: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    encode_hex(&digest)
}
fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
fn decode_hex(value: &str) -> Result<Vec<u8>, Q6pdStoreError> {
    if value.len() % 2 != 0 || !value.is_ascii() {
        return Err(Q6pdStoreError::Malformed);
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let hi = (pair[0] as char)
                .to_digit(16)
                .ok_or(Q6pdStoreError::Malformed)?;
            let lo = (pair[1] as char)
                .to_digit(16)
                .ok_or(Q6pdStoreError::Malformed)?;
            Ok(((hi << 4) | lo) as u8)
        })
        .collect()
}
fn decode_hex_32(value: &str) -> Result<[u8; 32], Q6pdStoreError> {
    let bytes = decode_hex(value)?;
    bytes.try_into().map_err(|_| Q6pdStoreError::Malformed)
}

pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), Q6pdStoreError> {
    let parent = path.parent().ok_or(Q6pdStoreError::Malformed)?;
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temp = parent.join(format!(".q6pd-{}-{sequence}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)?;
    let result = file
        .write_all(bytes)
        .and_then(|_| file.flush())
        .and_then(|_| file.sync_all());
    drop(file);
    if let Err(error) = result {
        let _ = fs::remove_file(&temp);
        return Err(Q6pdStoreError::Io(error.to_string()));
    }
    let replace_result = atomic_replace(&temp, path);
    if replace_result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    replace_result
}
#[cfg(windows)]
fn atomic_replace(source: &Path, destination: &Path) -> Result<(), Q6pdStoreError> {
    use std::os::windows::ffi::OsStrExt;
    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;
    let from: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let to: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    #[link(name = "Kernel32")]
    extern "system" {
        fn MoveFileExW(existing: *const u16, new_name: *const u16, flags: u32) -> i32;
    }
    let result = unsafe {
        MoveFileExW(
            from.as_ptr(),
            to.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        Err(Q6pdStoreError::Io(
            std::io::Error::last_os_error().to_string(),
        ))
    } else {
        Ok(())
    }
}
#[cfg(not(windows))]
fn atomic_replace(source: &Path, destination: &Path) -> Result<(), Q6pdStoreError> {
    fs::rename(source, destination).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qrun_v06_peer_discovery_candidate::{
        q6pd_peer_id_for_identity_public_key, sign_q6pd_peer_record,
    };
    use ed25519_dalek::SigningKey;
    use std::net::SocketAddr;

    const NETWORK: [u8; 32] = [0x31; 32];
    const PROFILE: [u8; 32] = [0x42; 32];

    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "q6pd-store-{}-{}",
                std::process::id(),
                TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn test_peer_id() -> [u8; 32] {
        let key = SigningKey::from_bytes(&[0x53; 32]);
        q6pd_peer_id_for_identity_public_key(&key.verifying_key().to_bytes())
    }

    fn signed(sequence: u64, issued_at: u64) -> Vec<u8> {
        sign_q6pd_peer_record(
            NETWORK,
            PROFILE,
            [0x64; 32],
            "8.8.8.8:30336".parse::<SocketAddr>().unwrap(),
            sequence,
            issued_at,
            600,
            &SigningKey::from_bytes(&[0x53; 32]),
        )
        .unwrap()
    }

    fn signed_distinct(seed: u8, endpoint: SocketAddr, issued_at: u64) -> Vec<u8> {
        sign_q6pd_peer_record(
            NETWORK,
            PROFILE,
            [seed.wrapping_add(1); 32],
            endpoint,
            1,
            issued_at,
            600,
            &SigningKey::from_bytes(&[seed; 32]),
        )
        .unwrap()
    }

    #[test]
    fn persists_and_reloads_candidate_and_watermark() {
        let temp = Temp::new();
        let path = temp.0.join("records.q6pd");
        {
            let mut store = Q6pdPeerRecordStore::open(&path, NETWORK, PROFILE, 1_100_000).unwrap();
            assert_eq!(
                store.ingest(&signed(7, 1_100), 1_100_000).unwrap(),
                Q6pdIngestResult::Inserted
            );
            assert_eq!(store.candidate_count(), 1);
            assert_eq!(store.watermark_count(), 1);
            assert_eq!(store.sequence_for_peer(&test_peer_id()), Some(7));
        }
        let store = Q6pdPeerRecordStore::open(&path, NETWORK, PROFILE, 1_100_001).unwrap();
        assert_eq!(store.candidate_count(), 1);
        assert_eq!(store.watermark_count(), 1);
        assert_eq!(store.candidates(1_100_001)[0].sequence, 7);
        assert_eq!(store.sequence_for_peer(&test_peer_id()), Some(7));
    }

    #[test]
    fn identical_sequence_is_idempotent_but_conflicting_or_lower_is_replay() {
        let temp = Temp::new();
        let path = temp.0.join("records.q6pd");
        let mut store = Q6pdPeerRecordStore::open(&path, NETWORK, PROFILE, 1_100_000).unwrap();
        let first = signed(7, 1_100);
        assert_eq!(
            store.ingest(&first, 1_100_000).unwrap(),
            Q6pdIngestResult::Inserted
        );
        assert_eq!(
            store.ingest(&first, 1_100_001).unwrap(),
            Q6pdIngestResult::Duplicate
        );
        assert_eq!(
            store.ingest(&signed(6, 1_100), 1_100_002),
            Err(Q6pdStoreError::Replay)
        );
        assert_eq!(
            store.ingest(&signed(7, 1_101), 1_101_000),
            Err(Q6pdStoreError::Replay)
        );
    }

    #[test]
    fn higher_sequence_updates_record_and_watermark() {
        let temp = Temp::new();
        let path = temp.0.join("records.q6pd");
        let mut store = Q6pdPeerRecordStore::open(&path, NETWORK, PROFILE, 1_100_000).unwrap();
        store.ingest(&signed(7, 1_100), 1_100_000).unwrap();
        assert_eq!(
            store.ingest(&signed(8, 1_101), 1_101_000).unwrap(),
            Q6pdIngestResult::Updated
        );
        assert_eq!(store.candidates(1_101_000)[0].sequence, 8);
        assert_eq!(store.sequence_for_peer(&test_peer_id()), Some(8));
    }

    #[test]
    fn expired_candidate_is_pruned_but_high_water_blocks_replay() {
        let temp = Temp::new();
        let path = temp.0.join("records.q6pd");
        {
            let mut store = Q6pdPeerRecordStore::open(&path, NETWORK, PROFILE, 1_100_000).unwrap();
            store.ingest(&signed(7, 1_100), 1_100_000).unwrap();
        }
        let mut store = Q6pdPeerRecordStore::open(&path, NETWORK, PROFILE, 1_701_000).unwrap();
        assert_eq!(store.candidate_count(), 0);
        assert_eq!(store.watermark_count(), 1);
        assert_eq!(store.sequence_for_peer(&test_peer_id()), Some(7));
        assert_eq!(
            store.ingest(&signed(7, 1_100), 1_701_000),
            Err(Q6pdStoreError::InvalidRecord(Q6pdError::Expired))
        );
        assert_eq!(store.watermark_count(), 1);
    }

    #[test]
    fn rejects_wrong_network_and_profile_store() {
        let temp = Temp::new();
        let path = temp.0.join("records.q6pd");
        drop(Q6pdPeerRecordStore::open(&path, NETWORK, PROFILE, 1_100_000).unwrap());
        assert!(matches!(
            Q6pdPeerRecordStore::open(&path, [0x99; 32], PROFILE, 1_100_000),
            Err(Q6pdStoreError::WrongNetwork)
        ));
        assert!(matches!(
            Q6pdPeerRecordStore::open(&path, NETWORK, [0x98; 32], 1_100_000),
            Err(Q6pdStoreError::WrongProfile)
        ));
    }

    #[test]
    fn exclusive_lock_blocks_second_writer() {
        let temp = Temp::new();
        let path = temp.0.join("records.q6pd");
        let first = Q6pdPeerRecordStore::open(&path, NETWORK, PROFILE, 1_100_000).unwrap();
        assert!(matches!(
            Q6pdPeerRecordStore::open(&path, NETWORK, PROFILE, 1_100_000),
            Err(Q6pdStoreError::LockHeld)
        ));
        drop(first);
        assert!(Q6pdPeerRecordStore::open(&path, NETWORK, PROFILE, 1_100_000).is_ok());
    }

    #[test]
    fn pull_response_rotates_beyond_the_first_sixteen_records() {
        use crate::qrun_v06_peer_discovery_candidate::{
            decode_q6pd_pull_response, encode_q6pd_pull_request, Q6pdPullRequest,
            Q6PD_MAX_RECORDS_PER_FRAME,
        };
        use std::collections::BTreeSet;

        let temp = Temp::new();
        let mut store = Q6pdPeerRecordStore::open(
            temp.0.join("rotating/records.q6pd"),
            NETWORK,
            PROFILE,
            1_100_000,
        )
        .unwrap();
        for seed in 1u8..=20 {
            let endpoint = SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 1, seed)),
                30336,
            );
            store
                .ingest(&signed_distinct(seed, endpoint, 1_100), 1_100_000)
                .unwrap();
        }

        let make_request = |request_id| Q6pdPullRequest {
            request_id,
            network_id: NETWORK,
            profile_id: PROFILE,
            max_records: Q6PD_MAX_RECORDS_PER_FRAME as u16,
        };
        let first_request = make_request(100);
        let second_request = make_request(117);
        let first_wire = store
            .respond_to_pull_frame(&encode_q6pd_pull_request(&first_request).unwrap(), 1_100)
            .unwrap();
        let second_wire = store
            .respond_to_pull_frame(&encode_q6pd_pull_request(&second_request).unwrap(), 1_100)
            .unwrap();
        let first = decode_q6pd_pull_response(&first_wire, &first_request, 1_100).unwrap();
        let second = decode_q6pd_pull_response(&second_wire, &second_request, 1_100).unwrap();
        let first_ids: BTreeSet<_> = first.records.iter().map(|r| r.peer_id).collect();
        let second_ids: BTreeSet<_> = second.records.iter().map(|r| r.peer_id).collect();

        assert_eq!(first.records.len(), Q6PD_MAX_RECORDS_PER_FRAME);
        assert_eq!(second.records.len(), Q6PD_MAX_RECORDS_PER_FRAME);
        assert_ne!(first_ids, second_ids);
        assert!(first_ids.union(&second_ids).count() > Q6PD_MAX_RECORDS_PER_FRAME);
    }

    #[test]
    fn signed_records_relay_across_multiple_candidate_stores() {
        use crate::qrun_v06_peer_discovery_candidate::{
            decode_q6pd_pull_response, encode_q6pd_pull_request, Q6pdPullRequest,
            Q6PD_MAX_RECORDS_PER_FRAME,
        };

        let temp = Temp::new();
        let mut origin = Q6pdPeerRecordStore::open(
            temp.0.join("origin/records.q6pd"),
            NETWORK,
            PROFILE,
            1_100_000,
        )
        .unwrap();
        let mut relay = Q6pdPeerRecordStore::open(
            temp.0.join("relay/records.q6pd"),
            NETWORK,
            PROFILE,
            1_100_000,
        )
        .unwrap();
        let mut downstream = Q6pdPeerRecordStore::open(
            temp.0.join("downstream/records.q6pd"),
            NETWORK,
            PROFILE,
            1_100_000,
        )
        .unwrap();

        let record = signed(7, 1_100);
        assert_eq!(
            origin.ingest(&record, 1_100_000).unwrap(),
            Q6pdIngestResult::Inserted
        );

        let relay_request = Q6pdPullRequest {
            request_id: 101,
            network_id: NETWORK,
            profile_id: PROFILE,
            max_records: Q6PD_MAX_RECORDS_PER_FRAME as u16,
        };
        let relay_request_wire = encode_q6pd_pull_request(&relay_request).unwrap();
        let relayed_frame = origin
            .respond_to_pull_frame(&relay_request_wire, 1_100)
            .unwrap();
        let relayed = decode_q6pd_pull_response(&relayed_frame, &relay_request, 1_100).unwrap();
        assert_eq!(relayed.record_wires.len(), 1);
        assert_eq!(
            relay.ingest(&relayed.record_wires[0], 1_100_000).unwrap(),
            Q6pdIngestResult::Inserted
        );

        let downstream_request = Q6pdPullRequest {
            request_id: 102,
            network_id: NETWORK,
            profile_id: PROFILE,
            max_records: Q6PD_MAX_RECORDS_PER_FRAME as u16,
        };
        let downstream_request_wire = encode_q6pd_pull_request(&downstream_request).unwrap();
        let relayed_again = relay
            .respond_to_pull_frame(&downstream_request_wire, 1_100)
            .unwrap();
        let downstream_response =
            decode_q6pd_pull_response(&relayed_again, &downstream_request, 1_100).unwrap();
        assert_eq!(downstream_response.record_wires.len(), 1);
        assert_eq!(
            downstream
                .ingest(&downstream_response.record_wires[0], 1_100_000)
                .unwrap(),
            Q6pdIngestResult::Inserted
        );

        let learned = downstream.candidates(1_100_000);
        assert_eq!(learned.len(), 1);
        assert_eq!(learned[0].peer_id, test_peer_id());
        assert_eq!(learned[0].sequence, 7);
        assert_eq!(downstream.sequence_for_peer(&test_peer_id()), Some(7));
    }
}
