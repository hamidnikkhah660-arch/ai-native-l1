//! Bitcoin-Core AddrMan-style manager for Q6PD signed peer records.
//!
//! Implements the new/tried bucket model, keyed placement, network-group diversity,
//! probabilistic reference insertion, probabilistic selection, and tried collision
//! bookkeeping/test-before-evict. QFP6 keeps its signed Ed25519 records and exact Noise
//! key pinning. The wire protocol remains QFP6-specific, not Bitcoin wire compatibility.
use crate::qrun_v06_peer_discovery_candidate::VerifiedQ6pdPeerRecord;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs::{self, File, OpenOptions},
    io::Read,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub const Q6PD_ADDRMAN_TRIED_BUCKETS: usize = 256;
pub const Q6PD_ADDRMAN_NEW_BUCKETS: usize = 1024;
pub const Q6PD_ADDRMAN_BUCKET_SIZE: usize = 64;
pub const Q6PD_ADDRMAN_TRIED_BUCKETS_PER_GROUP: usize = 8;
pub const Q6PD_ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP: usize = 64;
pub const Q6PD_ADDRMAN_NEW_BUCKETS_PER_ADDRESS: usize = 8;
pub const Q6PD_ADDRMAN_MAX_ENTRIES: usize = Q6PD_ADDRMAN_TRIED_BUCKETS * Q6PD_ADDRMAN_BUCKET_SIZE
    + Q6PD_ADDRMAN_NEW_BUCKETS * Q6PD_ADDRMAN_BUCKET_SIZE;
pub const Q6PD_ADDRMAN_MAX_BYTES: usize = 32 * 1024 * 1024;
pub const Q6PD_ADDRMAN_HORIZON_MS: u64 = 30 * 24 * 60 * 60 * 1000;
pub const Q6PD_ADDRMAN_RETRIES: u32 = 3;
pub const Q6PD_ADDRMAN_MAX_FAILURES: u32 = 10;
pub const Q6PD_ADDRMAN_MIN_FAIL_MS: u64 = 7 * 24 * 60 * 60 * 1000;
pub const Q6PD_ADDRMAN_REPLACEMENT_MS: u64 = 4 * 60 * 60 * 1000;
pub const Q6PD_ADDRMAN_COLLISION_LIMIT: usize = 10;
pub const Q6PD_ADDRMAN_TEST_WINDOW_MS: u64 = 40 * 60 * 1000;
pub const Q6PD_ADDRMAN_SUCCESS_RECHECK_MS: u64 = 20 * 60 * 1000;

const SCHEMA: &str = "qfp6-bitcoin-addrman";
const VERSION: u64 = 2;
const DOMAIN: &[u8] = b"QFP6-BITCOIN-ADDRMAN-V2\0";
const COLLISION_MIN_TEST_MS: u64 = 60_000;
const RECENT_ATTEMPT_MS: u64 = 10 * 60 * 1000;
const VERY_RECENT_ATTEMPT_MS: u64 = 60_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Q6pdAddressEntry {
    pub peer_id: String,
    pub endpoint: String,
    pub noise_static_public_key: String,
    pub source_endpoint: String,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub last_attempt_ms: u64,
    pub last_count_attempt_ms: u64,
    pub last_success_ms: u64,
    pub attempts: u32,
    pub successes: u32,
    pub failures: u32,
    pub retry_after_ms: u64,
    pub last_sequence: u64,
    pub issued_at_ms: u64,
    pub new_buckets: Vec<u16>,
    pub tried_bucket: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct AddressManagerPayload {
    schema: String,
    version: u64,
    network_id: String,
    profile_id: String,
    bucket_key: String,
    last_good_ms: u64,
    entries: Vec<Q6pdAddressEntry>,
    tried_collisions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct AddressManagerEnvelope {
    payload: AddressManagerPayload,
    checksum: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AddressManagerPayloadV1 {
    schema: String,
    version: u64,
    network_id: String,
    profile_id: String,
    entries: Vec<Q6pdAddressEntryV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AddressManagerEnvelopeV1 {
    payload: AddressManagerPayloadV1,
    checksum: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Q6pdAddressEntryV1 {
    peer_id: String,
    endpoint: String,
    noise_static_public_key: String,
    first_seen_ms: u64,
    last_seen_ms: u64,
    last_attempt_ms: u64,
    last_success_ms: u64,
    attempts: u32,
    successes: u32,
    failures: u32,
    retry_after_ms: u64,
    last_sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Q6pdAddressManagerError {
    Io(String),
    Malformed,
    ChecksumMismatch,
    WrongNetwork,
    WrongProfile,
    LockHeld,
    Capacity,
    UnknownPeer,
    StoreTooLarge,
    RandomnessUnavailable,
    DuplicateEndpoint,
}

impl std::fmt::Display for Q6pdAddressManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Q6pdAddressManagerError {}
impl From<std::io::Error> for Q6pdAddressManagerError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

pub fn peer_id_hex(peer_id: &[u8; 32]) -> String {
    hex(peer_id)
}

fn decode_hex_32(value: &str) -> Result<[u8; 32], Q6pdAddressManagerError> {
    if value.len() != 64 {
        return Err(Q6pdAddressManagerError::Malformed);
    }
    let mut output = [0u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(pair).map_err(|_| Q6pdAddressManagerError::Malformed)?;
        output[index] =
            u8::from_str_radix(pair, 16).map_err(|_| Q6pdAddressManagerError::Malformed)?;
    }
    if output == [0; 32] {
        return Err(Q6pdAddressManagerError::Malformed);
    }
    Ok(output)
}

fn sha256d(parts: &[&[u8]]) -> [u8; 32] {
    let mut first = Sha256::new();
    for part in parts {
        first.update(part);
    }
    let intermediate = first.finalize();
    let second = Sha256::digest(intermediate);
    let mut result = [0u8; 32];
    result.copy_from_slice(&second);
    result
}

fn hash64(parts: &[&[u8]]) -> u64 {
    let digest = sha256d(parts);
    u64::from_le_bytes(digest[..8].try_into().expect("fixed digest width"))
}

fn random_u64() -> Result<u64, Q6pdAddressManagerError> {
    let mut bytes = [0u8; 8];
    getrandom::getrandom(&mut bytes).map_err(|_| Q6pdAddressManagerError::RandomnessUnavailable)?;
    Ok(u64::from_le_bytes(bytes))
}

fn random_below(upper: usize) -> Result<usize, Q6pdAddressManagerError> {
    if upper <= 1 {
        return Ok(0);
    }
    let upper = upper as u64;
    let threshold = upper.wrapping_neg() % upper;
    loop {
        let value = random_u64()?;
        if value >= threshold {
            return Ok((value % upper) as usize);
        }
    }
}

fn group_key(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            vec![4, octets[0], octets[1]]
        }
        IpAddr::V6(ip) => {
            let octets = ip.octets();
            if octets[..10].iter().all(|byte| *byte == 0)
                && octets[10] == 0xff
                && octets[11] == 0xff
            {
                vec![4, octets[12], octets[13]]
            } else {
                vec![6, octets[0], octets[1], octets[2], octets[3]]
            }
        }
    }
}

fn service_key(endpoint: SocketAddr) -> Vec<u8> {
    let mut key = Vec::with_capacity(19);
    match endpoint.ip() {
        IpAddr::V4(ip) => {
            key.push(4);
            key.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            key.push(6);
            key.extend_from_slice(&ip.octets());
        }
    }
    key.extend_from_slice(&endpoint.port().to_be_bytes());
    key
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_millis().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

fn is_terrible(entry: &Q6pdAddressEntry, now: u64) -> bool {
    if now.saturating_sub(entry.last_attempt_ms) <= VERY_RECENT_ATTEMPT_MS {
        return false;
    }
    if entry.issued_at_ms > now.saturating_add(10 * 60 * 1000) {
        return true;
    }
    if now.saturating_sub(entry.last_seen_ms) > Q6PD_ADDRMAN_HORIZON_MS {
        return true;
    }
    if entry.last_success_ms == 0 && entry.attempts >= Q6PD_ADDRMAN_RETRIES {
        return true;
    }
    entry.last_success_ms > 0
        && now.saturating_sub(entry.last_success_ms) > Q6PD_ADDRMAN_MIN_FAIL_MS
        && entry.attempts >= Q6PD_ADDRMAN_MAX_FAILURES
}

fn get_chance(entry: &Q6pdAddressEntry, now: u64) -> f64 {
    let mut chance = 1.0f64;
    if now.saturating_sub(entry.last_attempt_ms) < RECENT_ATTEMPT_MS {
        chance *= 0.01;
    }
    chance * 0.66f64.powi(entry.attempts.min(8) as i32)
}

pub struct Q6pdAddressManager {
    path: PathBuf,
    lock_path: PathBuf,
    _lock: File,
    network_id: [u8; 32],
    profile_id: [u8; 32],
    bucket_key: [u8; 32],
    last_good_ms: u64,
    entries: BTreeMap<String, Q6pdAddressEntry>,
    new_buckets: Vec<Vec<Option<String>>>,
    tried_buckets: Vec<Vec<Option<String>>>,
    tried_collisions: BTreeSet<String>,
}

impl Q6pdAddressManager {
    pub fn open(
        path: impl AsRef<Path>,
        network_id: [u8; 32],
        profile_id: [u8; 32],
    ) -> Result<Self, Q6pdAddressManagerError> {
        if network_id == [0; 32] || profile_id == [0; 32] {
            return Err(Q6pdAddressManagerError::Malformed);
        }
        let path = path.as_ref().to_path_buf();
        let parent = path.parent().ok_or(Q6pdAddressManagerError::Malformed)?;
        fs::create_dir_all(parent)?;
        let lock_path = path.with_extension("q6pd-addrman.lock");
        let lock = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    Q6pdAddressManagerError::LockHeld
                } else {
                    error.into()
                }
            })?;
        let mut manager = Self {
            path,
            lock_path,
            _lock: lock,
            network_id,
            profile_id,
            bucket_key: [0; 32],
            last_good_ms: 1,
            entries: BTreeMap::new(),
            new_buckets: vec![vec![None; Q6PD_ADDRMAN_BUCKET_SIZE]; Q6PD_ADDRMAN_NEW_BUCKETS],
            tried_buckets: vec![vec![None; Q6PD_ADDRMAN_BUCKET_SIZE]; Q6PD_ADDRMAN_TRIED_BUCKETS],
            tried_collisions: BTreeSet::new(),
        };
        if manager.path.exists() {
            manager.load()?;
        } else {
            getrandom::getrandom(&mut manager.bucket_key)
                .map_err(|_| Q6pdAddressManagerError::RandomnessUnavailable)?;
            manager.persist()?;
        }
        Ok(manager)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn new_count(&self) -> usize {
        self.new_buckets
            .iter()
            .flatten()
            .filter(|slot| slot.is_some())
            .count()
    }

    pub fn tried_count(&self) -> usize {
        self.tried_buckets
            .iter()
            .flatten()
            .filter(|slot| slot.is_some())
            .count()
    }

    pub fn pending_tried_collisions(&self) -> usize {
        self.tried_collisions.len()
    }

    pub fn entries(&self) -> impl Iterator<Item = &Q6pdAddressEntry> {
        self.entries.values()
    }

    fn new_bucket(&self, record: &VerifiedQ6pdPeerRecord, source: SocketAddr) -> usize {
        let address_group = group_key(record.endpoint.ip());
        let source_group = group_key(source.ip());
        let first = hash64(&[&self.bucket_key, &address_group, &source_group]);
        let bucket_mod = (first % Q6PD_ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP as u64).to_le_bytes();
        (hash64(&[&self.bucket_key, &source_group, &bucket_mod]) % Q6PD_ADDRMAN_NEW_BUCKETS as u64)
            as usize
    }

    fn new_bucket_for(&self, endpoint: SocketAddr, source: SocketAddr) -> usize {
        let address_group = group_key(endpoint.ip());
        let source_group = group_key(source.ip());
        let first = hash64(&[&self.bucket_key, &address_group, &source_group]);
        let bucket_mod = (first % Q6PD_ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP as u64).to_le_bytes();
        (hash64(&[&self.bucket_key, &source_group, &bucket_mod]) % Q6PD_ADDRMAN_NEW_BUCKETS as u64)
            as usize
    }

    fn tried_bucket_for(&self, endpoint: SocketAddr) -> usize {
        let key = service_key(endpoint);
        let first = hash64(&[&self.bucket_key, &key]);
        let group = group_key(endpoint.ip());
        let bucket_mod = (first % Q6PD_ADDRMAN_TRIED_BUCKETS_PER_GROUP as u64).to_le_bytes();
        (hash64(&[&self.bucket_key, &group, &bucket_mod]) % Q6PD_ADDRMAN_TRIED_BUCKETS as u64)
            as usize
    }

    fn position(&self, endpoint: SocketAddr, tried: bool, bucket: usize) -> usize {
        let key = service_key(endpoint);
        let tag: &[u8] = if tried { b"K" } else { b"N" };
        let bucket_bytes = (bucket as u32).to_le_bytes();
        (hash64(&[&self.bucket_key, tag, &bucket_bytes, &key]) % Q6PD_ADDRMAN_BUCKET_SIZE as u64)
            as usize
    }

    fn clear_new_slot(&mut self, bucket: usize, position: usize) {
        let Some(peer_id) = self.new_buckets[bucket][position].take() else {
            return;
        };
        let mut remove = false;
        if let Some(entry) = self.entries.get_mut(&peer_id) {
            entry.new_buckets.retain(|value| *value as usize != bucket);
            remove = entry.new_buckets.is_empty() && entry.tried_bucket.is_none();
        }
        // Keep a pending collision candidate alive if demoting the incumbent evicts
        // its final new-bucket reference.
        if remove && !self.tried_collisions.contains(&peer_id) {
            self.entries.remove(&peer_id);
            self.tried_collisions.remove(&peer_id);
        }
    }

    fn remove_from_all_new(&mut self, peer_id: &str) {
        let Some(entry) = self.entries.get(peer_id).cloned() else {
            return;
        };
        if let Ok(endpoint) = entry.endpoint.parse::<SocketAddr>() {
            for bucket in &entry.new_buckets {
                let bucket = *bucket as usize;
                let position = self.position(endpoint, false, bucket);
                if self.new_buckets[bucket][position].as_deref() == Some(peer_id) {
                    self.new_buckets[bucket][position] = None;
                }
            }
        }
        if let Some(entry) = self.entries.get_mut(peer_id) {
            entry.new_buckets.clear();
        }
    }

    fn insert_new_reference(
        &mut self,
        peer_id: &str,
        bucket: usize,
        now: u64,
    ) -> Result<bool, Q6pdAddressManagerError> {
        let endpoint = self
            .entries
            .get(peer_id)
            .ok_or(Q6pdAddressManagerError::UnknownPeer)?
            .endpoint
            .parse::<SocketAddr>()
            .map_err(|_| Q6pdAddressManagerError::Malformed)?;
        let position = self.position(endpoint, false, bucket);
        let current = self.new_buckets[bucket][position].clone();
        if current.as_deref() == Some(peer_id) {
            return Ok(false);
        }
        let replace = match current.as_deref().and_then(|id| self.entries.get(id)) {
            None => true,
            Some(existing) => {
                is_terrible(existing, now)
                    || (existing.new_buckets.len() > 1
                        && self.entries[peer_id].new_buckets.is_empty())
            }
        };
        if !replace {
            if self.entries[peer_id].new_buckets.is_empty() {
                self.entries.remove(peer_id);
            }
            return Ok(false);
        }
        self.clear_new_slot(bucket, position);
        self.new_buckets[bucket][position] = Some(peer_id.to_owned());
        if let Some(entry) = self.entries.get_mut(peer_id) {
            if !entry.new_buckets.contains(&(bucket as u16)) {
                entry.new_buckets.push(bucket as u16);
                entry.new_buckets.sort_unstable();
            }
        }
        Ok(true)
    }

    fn evict_terrible_new(&mut self, now: u64) -> Result<bool, Q6pdAddressManagerError> {
        let start = random_below(Q6PD_ADDRMAN_NEW_BUCKETS)?;
        for offset in 0..Q6PD_ADDRMAN_NEW_BUCKETS {
            let bucket = (start + offset) % Q6PD_ADDRMAN_NEW_BUCKETS;
            let occupied: Vec<usize> = self.new_buckets[bucket]
                .iter()
                .enumerate()
                .filter_map(|(position, id)| id.as_ref().map(|_| position))
                .collect();
            if occupied.is_empty() {
                continue;
            }
            let position = occupied[random_below(occupied.len())?];
            let terrible = self.new_buckets[bucket][position]
                .as_ref()
                .and_then(|id| self.entries.get(id))
                .is_some_and(|entry| is_terrible(entry, now));
            if terrible {
                self.clear_new_slot(bucket, position);
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Source is the authenticated socket peer that supplied this record, not the
    /// address being advertised. It determines the Bitcoin-style source-group bucket.
    pub fn observe_from(
        &mut self,
        record: &VerifiedQ6pdPeerRecord,
        source: SocketAddr,
        now: u64,
    ) -> Result<(), Q6pdAddressManagerError> {
        if !crate::qrun_v06_peer_discovery_candidate::is_public_q6pd_endpoint(record.endpoint)
            || record.peer_id == [0; 32]
            || record.noise_static_public_key == [0; 32]
            || record.sequence == 0
        {
            return Err(Q6pdAddressManagerError::Malformed);
        }
        let peer_id = hex(&record.peer_id);
        let endpoint = record.endpoint.to_string();
        let noise_key = hex(&record.noise_static_public_key);

        if self
            .entries
            .values()
            .any(|entry| entry.endpoint == endpoint && entry.peer_id != peer_id)
        {
            return Err(Q6pdAddressManagerError::DuplicateEndpoint);
        }

        let previous = self.entries.get(&peer_id).cloned();
        if let Some(old) = previous {
            let route_changed =
                old.endpoint != endpoint || old.noise_static_public_key != noise_key;
            let newer = record.sequence > old.last_sequence
                || record.issued_at_secs.saturating_mul(1000) > old.issued_at_ms;
            if !route_changed && !newer {
                if let Some(entry) = self.entries.get_mut(&peer_id) {
                    entry.last_seen_ms = entry.last_seen_ms.max(now);
                }
                return self.persist();
            }
            if route_changed {
                self.remove_from_all_new(&peer_id);
                if let Some(bucket) = old.tried_bucket {
                    if let Ok(old_endpoint) = old.endpoint.parse::<SocketAddr>() {
                        let position = self.position(old_endpoint, true, bucket as usize);
                        if self.tried_buckets[bucket as usize][position].as_deref()
                            == Some(&peer_id)
                        {
                            self.tried_buckets[bucket as usize][position] = None;
                        }
                    }
                }
            }
            if let Some(entry) = self.entries.get_mut(&peer_id) {
                entry.endpoint = endpoint;
                entry.noise_static_public_key = noise_key;
                entry.last_seen_ms = entry.last_seen_ms.max(now);
                entry.last_sequence = entry.last_sequence.max(record.sequence);
                entry.issued_at_ms = entry
                    .issued_at_ms
                    .max(record.issued_at_secs.saturating_mul(1000));
                if route_changed {
                    entry.source_endpoint = source.to_string();
                    entry.new_buckets.clear();
                    entry.tried_bucket = None;
                    entry.last_attempt_ms = 0;
                    entry.last_count_attempt_ms = 0;
                    entry.last_success_ms = 0;
                    entry.attempts = 0;
                    entry.successes = 0;
                    entry.failures = 0;
                    entry.retry_after_ms = 0;
                } else if entry.tried_bucket.is_some() {
                    return self.persist();
                }
            }
        } else {
            if self.entries.len() >= Q6PD_ADDRMAN_MAX_ENTRIES && !self.evict_terrible_new(now)? {
                return Err(Q6pdAddressManagerError::Capacity);
            }
            self.entries.insert(
                peer_id.clone(),
                Q6pdAddressEntry {
                    peer_id: peer_id.clone(),
                    endpoint,
                    noise_static_public_key: noise_key,
                    source_endpoint: source.to_string(),
                    first_seen_ms: now,
                    last_seen_ms: now,
                    last_attempt_ms: 0,
                    last_count_attempt_ms: 0,
                    last_success_ms: 0,
                    attempts: 0,
                    successes: 0,
                    failures: 0,
                    retry_after_ms: 0,
                    last_sequence: record.sequence,
                    issued_at_ms: record.issued_at_secs.saturating_mul(1000),
                    new_buckets: Vec::new(),
                    tried_bucket: None,
                },
            );
        }

        let references = self
            .entries
            .get(&peer_id)
            .map(|entry| entry.new_buckets.len())
            .unwrap_or(0);
        if references >= Q6PD_ADDRMAN_NEW_BUCKETS_PER_ADDRESS {
            return self.persist();
        }
        if references > 0 && random_below(1usize << references)? != 0 {
            return self.persist();
        }
        let bucket = self.new_bucket(record, source);
        self.insert_new_reference(&peer_id, bucket, now)?;
        self.persist()
    }

    /// Compatibility path for bootstrap records that have no recorded source metadata.
    /// Live listener ingress must use observe_from with the authenticated remote socket.
    pub fn observe(
        &mut self,
        record: &VerifiedQ6pdPeerRecord,
        now: u64,
    ) -> Result<(), Q6pdAddressManagerError> {
        self.observe_from(record, record.endpoint, now)
    }

    pub fn observe_all(
        &mut self,
        records: &[VerifiedQ6pdPeerRecord],
        now: u64,
    ) -> Result<(), Q6pdAddressManagerError> {
        for record in records {
            self.observe(record, now)?;
        }
        Ok(())
    }

    pub fn observe_all_from(
        &mut self,
        records: &[VerifiedQ6pdPeerRecord],
        source: SocketAddr,
        now: u64,
    ) -> Result<(), Q6pdAddressManagerError> {
        for record in records {
            self.observe_from(record, source, now)?;
        }
        Ok(())
    }

    fn tried_position(
        &self,
        entry: &Q6pdAddressEntry,
    ) -> Result<(usize, usize), Q6pdAddressManagerError> {
        let endpoint = entry
            .endpoint
            .parse::<SocketAddr>()
            .map_err(|_| Q6pdAddressManagerError::Malformed)?;
        let bucket = self.tried_bucket_for(endpoint);
        let position = self.position(endpoint, true, bucket);
        Ok((bucket, position))
    }

    fn make_tried(&mut self, peer_id: &str) -> Result<bool, Q6pdAddressManagerError> {
        let entry = self
            .entries
            .get(peer_id)
            .ok_or(Q6pdAddressManagerError::UnknownPeer)?
            .clone();
        let (bucket, position) = self.tried_position(&entry)?;
        if let Some(existing) = self.tried_buckets[bucket][position].as_ref() {
            if existing != peer_id {
                if self.tried_collisions.len() < Q6PD_ADDRMAN_COLLISION_LIMIT {
                    self.tried_collisions.insert(peer_id.to_owned());
                }
                return Ok(false);
            }
        }
        self.remove_from_all_new(peer_id);
        if let Some(entry) = self.entries.get_mut(peer_id) {
            entry.tried_bucket = Some(bucket as u16);
            entry.new_buckets.clear();
        }
        self.tried_buckets[bucket][position] = Some(peer_id.to_owned());
        Ok(true)
    }

    fn demote_tried(&mut self, peer_id: &str, now: u64) -> Result<(), Q6pdAddressManagerError> {
        let entry = self
            .entries
            .get(peer_id)
            .ok_or(Q6pdAddressManagerError::UnknownPeer)?
            .clone();
        let bucket = entry
            .tried_bucket
            .ok_or(Q6pdAddressManagerError::Malformed)? as usize;
        let endpoint = entry
            .endpoint
            .parse::<SocketAddr>()
            .map_err(|_| Q6pdAddressManagerError::Malformed)?;
        let position = self.position(endpoint, true, bucket);
        if self.tried_buckets[bucket][position].as_deref() == Some(peer_id) {
            self.tried_buckets[bucket][position] = None;
        }
        if let Some(item) = self.entries.get_mut(peer_id) {
            item.tried_bucket = None;
        }
        let source = entry
            .source_endpoint
            .parse::<SocketAddr>()
            .unwrap_or(endpoint);
        let new_bucket = self.new_bucket_for(endpoint, source);
        let new_position = self.position(endpoint, false, new_bucket);
        self.clear_new_slot(new_bucket, new_position);
        self.new_buckets[new_bucket][new_position] = Some(peer_id.to_owned());
        if let Some(item) = self.entries.get_mut(peer_id) {
            item.new_buckets = vec![new_bucket as u16];
        }
        let _ = now;
        Ok(())
    }

    fn resolve_collisions(&mut self, now: u64) -> Result<(), Q6pdAddressManagerError> {
        let pending: Vec<String> = self.tried_collisions.iter().cloned().collect();
        for new_id in pending {
            let Some(new_entry) = self.entries.get(&new_id).cloned() else {
                self.tried_collisions.remove(&new_id);
                continue;
            };
            if is_terrible(&new_entry, now) {
                self.tried_collisions.remove(&new_id);
                continue;
            }
            let (bucket, position) = self.tried_position(&new_entry)?;
            let Some(old_id) = self.tried_buckets[bucket][position].clone() else {
                self.tried_collisions.remove(&new_id);
                let _ = self.make_tried(&new_id)?;
                continue;
            };
            let Some(old_entry) = self.entries.get(&old_id).cloned() else {
                self.tried_collisions.remove(&new_id);
                continue;
            };
            if old_entry.last_success_ms > 0
                && now.saturating_sub(old_entry.last_success_ms) < Q6PD_ADDRMAN_REPLACEMENT_MS
            {
                // The incumbent was recently proven good; discard this collision.
                self.tried_collisions.remove(&new_id);
            }
            // Otherwise keep the collision pending. The 40-minute window makes the
            // incumbent eligible for a feeler; it is never an automatic eviction timer.
        }
        Ok(())
    }

    pub fn pending_feeler_candidate(
        &self,
        records: &[VerifiedQ6pdPeerRecord],
    ) -> Option<VerifiedQ6pdPeerRecord> {
        let by_id: HashMap<String, &VerifiedQ6pdPeerRecord> = records
            .iter()
            .map(|record| (hex(&record.peer_id), record))
            .collect();
        for pending_id in &self.tried_collisions {
            let new_entry = self.entries.get(pending_id)?;
            let (bucket, position) = self.tried_position(new_entry).ok()?;
            let old_id = self.tried_buckets[bucket][position].as_ref()?;
            if let Some(record) = by_id.get(old_id) {
                return Some((**record).clone());
            }
        }
        None
    }

    pub fn is_pending_feeler(&self, peer_id: &[u8; 32]) -> bool {
        let target = hex(peer_id);
        self.tried_collisions.iter().any(|pending_id| {
            self.entries
                .get(pending_id)
                .and_then(|entry| {
                    let (bucket, position) = self.tried_position(entry).ok()?;
                    self.tried_buckets[bucket][position].as_ref().cloned()
                })
                .as_deref()
                == Some(target.as_str())
        })
    }

    pub fn select_candidate(
        &mut self,
        records: &[VerifiedQ6pdPeerRecord],
        local_peer_id: Option<[u8; 32]>,
        local_noise_key: Option<[u8; 32]>,
        now: u64,
    ) -> Result<Option<VerifiedQ6pdPeerRecord>, Q6pdAddressManagerError> {
        // Candidate records must enter through observe_from() at the authenticated ingress
        // point. Re-observing here would fabricate source groups from each record's own endpoint.
        self.resolve_collisions(now)?;
        if let Some(feeler) = self.pending_feeler_candidate(records) {
            let feeler_id = hex(&feeler.peer_id);
            let collision_due = self.tried_collisions.iter().any(|pending_id| {
                let Some(candidate) = self.entries.get(pending_id) else {
                    return false;
                };
                let Ok((bucket, position)) = self.tried_position(candidate) else {
                    return false;
                };
                self.tried_buckets[bucket][position].as_deref() == Some(feeler_id.as_str())
                    && now.saturating_sub(candidate.last_success_ms) >= Q6PD_ADDRMAN_TEST_WINDOW_MS
            });
            let feeler_attempt_due = self.entries.get(&feeler_id).is_some_and(|entry| {
                entry.last_attempt_ms == 0
                    || now.saturating_sub(entry.last_attempt_ms) >= COLLISION_MIN_TEST_MS
            });
            if collision_due
                && feeler_attempt_due
                && local_peer_id != Some(feeler.peer_id)
                && local_noise_key != Some(feeler.noise_static_public_key)
            {
                return Ok(Some(feeler));
            }
        }
        let by_id: HashMap<String, &VerifiedQ6pdPeerRecord> = records
            .iter()
            .map(|record| (hex(&record.peer_id), record))
            .collect();
        let new_nonempty = self.new_count() > 0;
        let tried_nonempty = self.tried_count() > 0;
        if !new_nonempty && !tried_nonempty {
            return Ok(None);
        }
        let search_tried = if !new_nonempty {
            true
        } else if !tried_nonempty {
            false
        } else {
            random_below(2)? == 1
        };
        let (tables, count) = if search_tried {
            (&self.tried_buckets, Q6PD_ADDRMAN_TRIED_BUCKETS)
        } else {
            (&self.new_buckets, Q6PD_ADDRMAN_NEW_BUCKETS)
        };
        let mut chance_factor = 1.0f64;
        for _ in 0..8192 {
            let bucket = random_below(count)?;
            let occupied: Vec<&String> = tables[bucket].iter().filter_map(Option::as_ref).collect();
            if occupied.is_empty() {
                chance_factor *= 1.2;
                continue;
            }
            let peer_id = occupied[random_below(occupied.len())?];
            let Some(entry) = self.entries.get(peer_id) else {
                continue;
            };
            if is_terrible(entry, now) {
                continue;
            }
            let Some(record) = by_id.get(peer_id) else {
                continue;
            };
            if local_peer_id == Some(record.peer_id)
                || local_noise_key == Some(record.noise_static_public_key)
            {
                continue;
            }
            let threshold = (get_chance(entry, now) * chance_factor * ((1u64 << 30) as f64))
                .clamp(0.0, (1u64 << 30) as f64) as u64;
            if (random_u64()? & ((1u64 << 30) - 1)) < threshold {
                return Ok(Some((**record).clone()));
            }
            chance_factor *= 1.2;
        }
        Ok(None)
    }

    pub fn record_attempt(
        &mut self,
        peer_id: &[u8; 32],
        now: u64,
    ) -> Result<(), Q6pdAddressManagerError> {
        let entry = self
            .entries
            .get_mut(&hex(peer_id))
            .ok_or(Q6pdAddressManagerError::UnknownPeer)?;
        entry.last_attempt_ms = now;
        entry.retry_after_ms = now.saturating_add(RECENT_ATTEMPT_MS);
        self.persist()
    }

    pub fn record_success(
        &mut self,
        peer_id: &[u8; 32],
        now: u64,
    ) -> Result<(), Q6pdAddressManagerError> {
        let key = hex(peer_id);
        {
            let entry = self
                .entries
                .get_mut(&key)
                .ok_or(Q6pdAddressManagerError::UnknownPeer)?;
            entry.last_success_ms = now;
            entry.last_attempt_ms = now;
            entry.last_count_attempt_ms = now;
            entry.successes = entry.successes.saturating_add(1);
            entry.attempts = 0;
            entry.failures = 0;
            entry.retry_after_ms = now.saturating_add(Q6PD_ADDRMAN_SUCCESS_RECHECK_MS);
        }
        self.last_good_ms = now.max(1);
        let _ = self.make_tried(&key)?;
        self.resolve_collisions(now)?;
        self.persist()
    }

    pub fn record_failure(
        &mut self,
        peer_id: &[u8; 32],
        now: u64,
    ) -> Result<(), Q6pdAddressManagerError> {
        let key = hex(peer_id);
        {
            let entry = self
                .entries
                .get_mut(&key)
                .ok_or(Q6pdAddressManagerError::UnknownPeer)?;
            entry.last_attempt_ms = now;
            if entry.last_count_attempt_ms < self.last_good_ms {
                entry.last_count_attempt_ms = now;
                entry.attempts = entry.attempts.saturating_add(1);
                entry.failures = entry.attempts;
            }
            entry.retry_after_ms = now.saturating_add(RECENT_ATTEMPT_MS);
        }
        self.resolve_collisions(now)?;
        self.persist()
    }

    /// Resolve a tried-bucket collision after a failed short, key-pinned feeler probe.
    /// The incumbent is demoted to `new` and the authenticated challenger is promoted to `tried`.
    pub fn record_feeler_failure(
        &mut self,
        peer_id: &[u8; 32],
        now: u64,
    ) -> Result<(), Q6pdAddressManagerError> {
        let incumbent = hex(peer_id);
        // Update failures without invoking the generic resolver before this feeler
        // outcome is applied to the incumbent/candidate collision.
        {
            let entry = self
                .entries
                .get_mut(&incumbent)
                .ok_or(Q6pdAddressManagerError::UnknownPeer)?;
            entry.last_attempt_ms = now;
            if entry.last_count_attempt_ms < self.last_good_ms {
                entry.last_count_attempt_ms = now;
                entry.attempts = entry.attempts.saturating_add(1);
                entry.failures = entry.attempts;
            }
            entry.retry_after_ms = now.saturating_add(RECENT_ATTEMPT_MS);
        }
        let colliding: Vec<String> = self
            .tried_collisions
            .iter()
            .filter_map(|candidate_id| {
                let candidate = self.entries.get(candidate_id)?;
                let (bucket, position) = self.tried_position(candidate).ok()?;
                (self.tried_buckets[bucket][position].as_deref() == Some(incumbent.as_str()))
                    .then(|| candidate_id.clone())
            })
            .collect();
        if colliding.is_empty() {
            return self.persist();
        }
        self.demote_tried(&incumbent, now)?;
        for candidate_id in colliding {
            self.tried_collisions.remove(&candidate_id);
            let _ = self.make_tried(&candidate_id)?;
        }
        self.persist()
    }

    pub fn is_eligible(&self, peer_id: &[u8; 32], now: u64) -> bool {
        self.entries
            .get(&hex(peer_id))
            .is_some_and(|entry| !is_terrible(entry, now))
    }

    fn payload(&self) -> AddressManagerPayload {
        AddressManagerPayload {
            schema: SCHEMA.to_string(),
            version: VERSION,
            network_id: hex(&self.network_id),
            profile_id: hex(&self.profile_id),
            bucket_key: hex(&self.bucket_key),
            last_good_ms: self.last_good_ms,
            entries: self.entries.values().cloned().collect(),
            tried_collisions: self.tried_collisions.iter().cloned().collect(),
        }
    }

    fn persist(&self) -> Result<(), Q6pdAddressManagerError> {
        let payload = self.payload();
        let body = serde_json::to_vec(&payload).map_err(|_| Q6pdAddressManagerError::Malformed)?;
        let mut digest = Sha256::new();
        digest.update(DOMAIN);
        digest.update(&body);
        let envelope = AddressManagerEnvelope {
            payload,
            checksum: hex(&digest.finalize()),
        };
        let bytes =
            serde_json::to_vec(&envelope).map_err(|_| Q6pdAddressManagerError::Malformed)?;
        if bytes.len() > Q6PD_ADDRMAN_MAX_BYTES {
            return Err(Q6pdAddressManagerError::StoreTooLarge);
        }
        crate::qrun_v06_peer_discovery_store_candidate::write_atomic(&self.path, &bytes)
            .map_err(|error| Q6pdAddressManagerError::Io(error.to_string()))
    }

    /// Migrate the bounded V1 Q6PD candidate list into the keyed Bitcoin-style tables.
    /// Legacy successes are promoted into tried; untested entries are re-bucketed as new.
    fn load_v1(&mut self, bytes: &[u8]) -> Result<(), Q6pdAddressManagerError> {
        const DOMAIN_V1: &[u8] = b"QFP6-Q6PD-ADDRESS-MANAGER-V1\0";
        let envelope: AddressManagerEnvelopeV1 =
            serde_json::from_slice(bytes).map_err(|_| Q6pdAddressManagerError::Malformed)?;
        let body = serde_json::to_vec(&envelope.payload)
            .map_err(|_| Q6pdAddressManagerError::Malformed)?;
        let mut digest = Sha256::new();
        digest.update(DOMAIN_V1);
        digest.update(&body);
        if hex(&digest.finalize()) != envelope.checksum {
            return Err(Q6pdAddressManagerError::ChecksumMismatch);
        }
        let payload = envelope.payload;
        if payload.schema != "qfp6-q6pd-address-manager" || payload.version != 1 {
            return Err(Q6pdAddressManagerError::Malformed);
        }
        if decode_hex_32(&payload.network_id)? != self.network_id {
            return Err(Q6pdAddressManagerError::WrongNetwork);
        }
        if decode_hex_32(&payload.profile_id)? != self.profile_id {
            return Err(Q6pdAddressManagerError::WrongProfile);
        }
        if payload.entries.len() > 256 {
            return Err(Q6pdAddressManagerError::Capacity);
        }

        getrandom::getrandom(&mut self.bucket_key)
            .map_err(|_| Q6pdAddressManagerError::RandomnessUnavailable)?;
        self.entries.clear();
        self.tried_collisions.clear();
        self.new_buckets = vec![vec![None; Q6PD_ADDRMAN_BUCKET_SIZE]; Q6PD_ADDRMAN_NEW_BUCKETS];
        self.tried_buckets = vec![vec![None; Q6PD_ADDRMAN_BUCKET_SIZE]; Q6PD_ADDRMAN_TRIED_BUCKETS];
        self.last_good_ms = payload
            .entries
            .iter()
            .map(|entry| entry.last_success_ms)
            .max()
            .unwrap_or(1)
            .max(1);

        let mut seen_endpoints = BTreeSet::new();
        for old in payload.entries {
            let peer_id = decode_hex_32(&old.peer_id)?;
            let noise_key = decode_hex_32(&old.noise_static_public_key)?;
            let endpoint = old
                .endpoint
                .parse::<SocketAddr>()
                .map_err(|_| Q6pdAddressManagerError::Malformed)?;
            if !crate::qrun_v06_peer_discovery_candidate::is_public_q6pd_endpoint(endpoint)
                || !seen_endpoints.insert(endpoint)
                || old.last_sequence == 0
            {
                return Err(Q6pdAddressManagerError::Malformed);
            }
            let peer_id = hex(&peer_id);
            self.entries.insert(
                peer_id.clone(),
                Q6pdAddressEntry {
                    peer_id,
                    endpoint: endpoint.to_string(),
                    noise_static_public_key: hex(&noise_key),
                    source_endpoint: endpoint.to_string(),
                    first_seen_ms: old.first_seen_ms,
                    last_seen_ms: old.last_seen_ms,
                    last_attempt_ms: old.last_attempt_ms,
                    last_count_attempt_ms: old.last_attempt_ms,
                    last_success_ms: old.last_success_ms,
                    attempts: old.attempts,
                    successes: old.successes,
                    failures: old.failures,
                    retry_after_ms: old.retry_after_ms,
                    last_sequence: old.last_sequence,
                    issued_at_ms: old.last_seen_ms,
                    new_buckets: Vec::new(),
                    tried_bucket: None,
                },
            );
        }

        let ids: Vec<String> = self.entries.keys().cloned().collect();
        for peer_id in ids {
            let entry = self
                .entries
                .get(&peer_id)
                .ok_or(Q6pdAddressManagerError::Malformed)?
                .clone();
            if entry.successes > 0 {
                let _ = self.make_tried(&peer_id)?;
            } else {
                let endpoint = entry
                    .endpoint
                    .parse::<SocketAddr>()
                    .map_err(|_| Q6pdAddressManagerError::Malformed)?;
                let source = entry
                    .source_endpoint
                    .parse::<SocketAddr>()
                    .map_err(|_| Q6pdAddressManagerError::Malformed)?;
                let bucket = self.new_bucket_for(endpoint, source);
                let _ = self.insert_new_reference(&peer_id, bucket, now_ms())?;
            }
        }
        self.persist()
    }

    fn load(&mut self) -> Result<(), Q6pdAddressManagerError> {
        let metadata = fs::symlink_metadata(&self.path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(Q6pdAddressManagerError::Malformed);
        }
        if metadata.len() as usize > Q6PD_ADDRMAN_MAX_BYTES {
            return Err(Q6pdAddressManagerError::StoreTooLarge);
        }
        let mut file = File::open(&self.path)?;
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.read_to_end(&mut bytes)?;
        // Windows MoveFileExW cannot replace a destination while this read handle is open.
        // Close it before migrating V1 in place; the bytes are already fully buffered.
        drop(file);
        let version_probe: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| Q6pdAddressManagerError::Malformed)?;
        if version_probe
            .pointer("/payload/version")
            .and_then(serde_json::Value::as_u64)
            == Some(1)
        {
            self.load_v1(&bytes)?;
            return Ok(());
        }
        let envelope: AddressManagerEnvelope =
            serde_json::from_slice(&bytes).map_err(|_| Q6pdAddressManagerError::Malformed)?;
        let body = serde_json::to_vec(&envelope.payload)
            .map_err(|_| Q6pdAddressManagerError::Malformed)?;
        let mut digest = Sha256::new();
        digest.update(DOMAIN);
        digest.update(&body);
        if hex(&digest.finalize()) != envelope.checksum {
            return Err(Q6pdAddressManagerError::ChecksumMismatch);
        }
        let payload = envelope.payload;
        if payload.schema != SCHEMA || payload.version != VERSION {
            return Err(Q6pdAddressManagerError::Malformed);
        }
        if decode_hex_32(&payload.network_id)? != self.network_id {
            return Err(Q6pdAddressManagerError::WrongNetwork);
        }
        if decode_hex_32(&payload.profile_id)? != self.profile_id {
            return Err(Q6pdAddressManagerError::WrongProfile);
        }
        self.bucket_key = decode_hex_32(&payload.bucket_key)?;
        self.last_good_ms = payload.last_good_ms.max(1);
        if payload.entries.len() > Q6PD_ADDRMAN_MAX_ENTRIES
            || payload.tried_collisions.len() > Q6PD_ADDRMAN_COLLISION_LIMIT
        {
            return Err(Q6pdAddressManagerError::Capacity);
        }
        let mut entries = BTreeMap::new();
        for entry in payload.entries {
            let peer_id = decode_hex_32(&entry.peer_id)?;
            let noise_key = decode_hex_32(&entry.noise_static_public_key)?;
            let endpoint = entry
                .endpoint
                .parse::<SocketAddr>()
                .map_err(|_| Q6pdAddressManagerError::Malformed)?;
            let _source = entry
                .source_endpoint
                .parse::<SocketAddr>()
                .map_err(|_| Q6pdAddressManagerError::Malformed)?;
            if !crate::qrun_v06_peer_discovery_candidate::is_public_q6pd_endpoint(endpoint)
                || peer_id == [0; 32]
                || noise_key == [0; 32]
                || entry.last_sequence == 0
                || entry.new_buckets.len() > Q6PD_ADDRMAN_NEW_BUCKETS_PER_ADDRESS
                || entry
                    .new_buckets
                    .iter()
                    .any(|bucket| *bucket as usize >= Q6PD_ADDRMAN_NEW_BUCKETS)
                || entry
                    .tried_bucket
                    .is_some_and(|bucket| bucket as usize >= Q6PD_ADDRMAN_TRIED_BUCKETS)
                || (entry.tried_bucket.is_some() && !entry.new_buckets.is_empty())
            {
                return Err(Q6pdAddressManagerError::Malformed);
            }
            if entries.insert(entry.peer_id.clone(), entry).is_some() {
                return Err(Q6pdAddressManagerError::Malformed);
            }
        }
        self.entries = entries;
        self.new_buckets = vec![vec![None; Q6PD_ADDRMAN_BUCKET_SIZE]; Q6PD_ADDRMAN_NEW_BUCKETS];
        self.tried_buckets = vec![vec![None; Q6PD_ADDRMAN_BUCKET_SIZE]; Q6PD_ADDRMAN_TRIED_BUCKETS];
        for (peer_id, entry) in &self.entries {
            let endpoint = entry
                .endpoint
                .parse::<SocketAddr>()
                .map_err(|_| Q6pdAddressManagerError::Malformed)?;
            for bucket in &entry.new_buckets {
                let bucket = *bucket as usize;
                let position = self.position(endpoint, false, bucket);
                if self.new_buckets[bucket][position]
                    .replace(peer_id.clone())
                    .is_some()
                {
                    return Err(Q6pdAddressManagerError::Malformed);
                }
            }
            if let Some(bucket) = entry.tried_bucket {
                let bucket = bucket as usize;
                if bucket != self.tried_bucket_for(endpoint) {
                    return Err(Q6pdAddressManagerError::Malformed);
                }
                let position = self.position(endpoint, true, bucket);
                if self.tried_buckets[bucket][position]
                    .replace(peer_id.clone())
                    .is_some()
                {
                    return Err(Q6pdAddressManagerError::Malformed);
                }
            }
        }
        self.tried_collisions = payload.tried_collisions.into_iter().collect();
        if self.tried_collisions.iter().any(|peer_id| {
            !self.entries.contains_key(peer_id)
                || self
                    .entries
                    .get(peer_id)
                    .is_some_and(|entry| entry.tried_bucket.is_some())
        }) {
            return Err(Q6pdAddressManagerError::Malformed);
        }
        Ok(())
    }
}

impl Drop for Q6pdAddressManager {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qrun_v06_peer_discovery_candidate::sign_q6pd_peer_record;
    use ed25519_dalek::SigningKey;
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_DIR: AtomicU64 = AtomicU64::new(1);
    const NETWORK: [u8; 32] = [0x11; 32];
    const PROFILE: [u8; 32] = [0x22; 32];

    fn temp_dir() -> PathBuf {
        let n = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("q6pd-addrman-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn candidate(seed: u8, endpoint: &str, issued: u64) -> VerifiedQ6pdPeerRecord {
        let identity = SigningKey::from_bytes(&[seed; 32]);
        let endpoint = endpoint.parse().unwrap();
        let noise_key = [seed.wrapping_add(1); 32];
        let wire = sign_q6pd_peer_record(
            NETWORK, PROFILE, noise_key, endpoint, 1, issued, 3600, &identity,
        )
        .unwrap();
        crate::qrun_v06_peer_discovery_candidate::verify_q6pd_peer_record(
            &wire, &NETWORK, &PROFILE, issued,
        )
        .unwrap()
    }

    #[test]
    fn uses_bitcoin_core_bucket_dimensions_and_persists_bucket_key() {
        assert_eq!(Q6PD_ADDRMAN_NEW_BUCKETS, 1024);
        assert_eq!(Q6PD_ADDRMAN_TRIED_BUCKETS, 256);
        assert_eq!(Q6PD_ADDRMAN_BUCKET_SIZE, 64);
        assert_eq!(Q6PD_ADDRMAN_NEW_BUCKETS_PER_ADDRESS, 8);
        let dir = temp_dir();
        let path = dir.join("peers.addrman.json");
        let peer = candidate(7, "8.8.8.8:8333", 10_000);
        let mut key = [0u8; 32];
        {
            let mut manager = Q6pdAddressManager::open(&path, NETWORK, PROFILE).unwrap();
            manager
                .observe_from(&peer, "1.1.1.1:8333".parse().unwrap(), 10_000_000)
                .unwrap();
            key = manager.bucket_key;
            assert_eq!(manager.new_count(), 1);
            assert_eq!(manager.tried_count(), 0);
        }
        let manager = Q6pdAddressManager::open(&path, NETWORK, PROFILE).unwrap();
        assert_eq!(manager.bucket_key, key);
        assert_eq!(manager.new_count(), 1);
        drop(manager);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn good_connection_moves_entry_from_new_to_tried() {
        let dir = temp_dir();
        let path = dir.join("peers.addrman.json");
        let peer = candidate(9, "1.1.1.1:8333", 10_000);
        let mut manager = Q6pdAddressManager::open(&path, NETWORK, PROFILE).unwrap();
        manager
            .observe_from(&peer, "8.8.8.8:8333".parse().unwrap(), 10_000_000)
            .unwrap();
        manager.record_attempt(&peer.peer_id, 10_000_001).unwrap();
        manager.record_success(&peer.peer_id, 10_010_000).unwrap();
        assert_eq!(manager.new_count(), 0);
        assert_eq!(manager.tried_count(), 1);
        assert!(manager.entries().next().unwrap().tried_bucket.is_some());
        drop(manager);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn failed_attempts_reduce_selection_chance_without_hard_exponential_backoff() {
        let dir = temp_dir();
        let path = dir.join("peers.addrman.json");
        let peer = candidate(11, "9.9.9.9:8333", 10_000);
        let mut manager = Q6pdAddressManager::open(&path, NETWORK, PROFILE).unwrap();
        manager
            .observe_from(&peer, "8.8.8.8:8333".parse().unwrap(), 10_000_000)
            .unwrap();
        manager.record_attempt(&peer.peer_id, 10_000_001).unwrap();
        manager.record_failure(&peer.peer_id, 10_000_002).unwrap();
        let entry = manager.entries().next().unwrap();
        assert_eq!(entry.attempts, 1);
        assert_eq!(entry.failures, 1);
        assert!((get_chance(entry, 10_000_003) - 0.0066).abs() < 0.000001);
        assert!(manager.is_eligible(&peer.peer_id, 10_000_003));
        drop(manager);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn refuses_identity_collision_on_the_same_network_endpoint() {
        let dir = temp_dir();
        let path = dir.join("peers.addrman.json");
        let a = candidate(15, "8.8.4.4:8333", 10_000);
        let b = candidate(16, "8.8.4.4:8333", 10_000);
        let mut manager = Q6pdAddressManager::open(&path, NETWORK, PROFILE).unwrap();
        manager
            .observe_from(&a, "9.9.9.9:8333".parse().unwrap(), 10_000_000)
            .unwrap();
        assert_eq!(
            manager.observe_from(&b, "9.9.9.9:8333".parse().unwrap(), 10_000_000),
            Err(Q6pdAddressManagerError::DuplicateEndpoint)
        );
        drop(manager);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn restores_new_and_tried_bucket_indexes_after_restart() {
        let dir = temp_dir();
        let path = dir.join("peers.addrman.json");
        let peer = candidate(31, "208.67.222.222:8333", 10_000);
        {
            let mut manager = Q6pdAddressManager::open(&path, NETWORK, PROFILE).unwrap();
            manager
                .observe_from(&peer, "8.8.8.8:8333".parse().unwrap(), 10_000_000)
                .unwrap();
            manager.record_success(&peer.peer_id, 10_010_000).unwrap();
        }
        let manager = Q6pdAddressManager::open(&path, NETWORK, PROFILE).unwrap();
        assert_eq!(manager.len(), 1);
        assert_eq!(manager.new_count(), 0);
        assert_eq!(manager.tried_count(), 1);
        drop(manager);
        assert!(matches!(
            Q6pdAddressManager::open(&path, [0x99; 32], PROFILE),
            Err(Q6pdAddressManagerError::WrongNetwork)
        ));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn attributes_discovered_records_to_the_authenticated_source_group() {
        let dir = temp_dir();
        let path = dir.join("peers.addrman.json");
        let source: SocketAddr = "9.9.9.9:8333".parse().unwrap();
        let peer = candidate(43, "8.8.8.8:8333", 10_000);
        let mut manager = Q6pdAddressManager::open(&path, NETWORK, PROFILE).unwrap();

        manager
            .observe_all_from(&[peer.clone()], source, 20_000_000)
            .unwrap();

        let entry = manager.entries.get(&hex(&peer.peer_id)).unwrap();
        assert_eq!(entry.source_endpoint, source.to_string());
        assert_ne!(entry.source_endpoint, entry.endpoint);
        let expected_bucket = manager.new_bucket(&peer, source);
        assert!(entry.new_buckets.contains(&(expected_bucket as u16)));

        drop(manager);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn tried_collision_waits_for_feeler_and_only_replaces_a_failed_incumbent() {
        let dir = temp_dir();
        let path = dir.join("peers.addrman.json");
        let now = 80_000_000u64;
        let old_success = now - 5 * 60 * 60 * 1000;
        let incumbent = candidate(51, "8.8.8.8:8333", 10_000);
        let mut manager = Q6pdAddressManager::open(&path, NETWORK, PROFILE).unwrap();
        manager
            .observe_from(&incumbent, "9.9.9.9:8333".parse().unwrap(), old_success)
            .unwrap();
        manager
            .record_success(&incumbent.peer_id, old_success)
            .unwrap();

        let incumbent_entry = manager
            .entries
            .get(&hex(&incumbent.peer_id))
            .unwrap()
            .clone();
        let (target_bucket, target_position) = manager.tried_position(&incumbent_entry).unwrap();
        // Tried-bucket selection is group-scoped (8 buckets per address group).
        // Search across the full 11/8 public range rather than one small run of /16
        // groups; a narrow range may not map to the incumbent's bucket at all.
        let mut challenger_endpoint = None;
        'groups: for group in 0u16..=255 {
            for host in 1u16..=1024 {
                let endpoint = SocketAddr::new(
                    IpAddr::V4(std::net::Ipv4Addr::new(
                        11,
                        group as u8,
                        (host >> 8) as u8,
                        host as u8,
                    )),
                    8333,
                );
                if manager.tried_bucket_for(endpoint) == target_bucket
                    && manager.position(endpoint, true, target_bucket) == target_position
                {
                    challenger_endpoint = Some(endpoint);
                    break 'groups;
                }
            }
        }
        let challenger_endpoint = challenger_endpoint.expect("must find a tried-slot collision");
        let challenger = candidate(52, &challenger_endpoint.to_string(), 10_000);
        manager
            .observe_from(&challenger, "9.9.9.9:8333".parse().unwrap(), now)
            .unwrap();
        manager.record_success(&challenger.peer_id, now).unwrap();
        assert_eq!(manager.pending_tried_collisions(), 1);

        manager
            .resolve_collisions(now + Q6PD_ADDRMAN_TEST_WINDOW_MS - 1)
            .unwrap();
        let incumbent_id = hex(&incumbent.peer_id);
        assert_eq!(
            manager.tried_buckets[target_bucket][target_position].as_deref(),
            Some(incumbent_id.as_str())
        );
        assert_eq!(manager.pending_tried_collisions(), 1);

        let feeler = manager
            .select_candidate(
                &[incumbent.clone(), challenger.clone()],
                None,
                None,
                now + Q6PD_ADDRMAN_TEST_WINDOW_MS + 1,
            )
            .unwrap()
            .unwrap();
        assert_eq!(feeler.peer_id, incumbent.peer_id);
        assert!(manager.is_pending_feeler(&feeler.peer_id));

        manager
            .record_feeler_failure(&incumbent.peer_id, now + Q6PD_ADDRMAN_TEST_WINDOW_MS + 2)
            .unwrap();
        assert_eq!(manager.pending_tried_collisions(), 0);
        assert!(manager
            .entries
            .get(&incumbent_id)
            .unwrap()
            .tried_bucket
            .is_none());
        assert!(manager
            .entries
            .get(&hex(&challenger.peer_id))
            .unwrap()
            .tried_bucket
            .is_some());

        drop(manager);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn migrates_v1_address_manager_without_losing_known_candidates() {
        let dir = temp_dir();
        let path = dir.join("peers.addrman.json");
        let peer = candidate(41, "208.67.220.220:8333", 10_000);
        let old_entry = Q6pdAddressEntryV1 {
            peer_id: hex(&peer.peer_id),
            endpoint: peer.endpoint.to_string(),
            noise_static_public_key: hex(&peer.noise_static_public_key),
            first_seen_ms: 9_000_000,
            last_seen_ms: 10_000_000,
            last_attempt_ms: 0,
            last_success_ms: 0,
            attempts: 0,
            successes: 0,
            failures: 0,
            retry_after_ms: 0,
            last_sequence: peer.sequence,
        };
        let payload = AddressManagerPayloadV1 {
            schema: "qfp6-q6pd-address-manager".to_owned(),
            version: 1,
            network_id: hex(&NETWORK),
            profile_id: hex(&PROFILE),
            entries: vec![old_entry],
        };
        let body = serde_json::to_vec(&payload).unwrap();
        let mut digest = Sha256::new();
        digest.update(b"QFP6-Q6PD-ADDRESS-MANAGER-V1\0");
        digest.update(&body);
        let envelope = AddressManagerEnvelopeV1 {
            payload,
            checksum: hex(&digest.finalize()),
        };
        fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();

        let manager = Q6pdAddressManager::open(&path, NETWORK, PROFILE).unwrap();
        assert_eq!(manager.len(), 1);
        assert_eq!(manager.new_count(), 1);
        assert_eq!(
            manager.entries().next().unwrap().peer_id,
            hex(&peer.peer_id)
        );
        drop(manager);

        let stored: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            stored
                .pointer("/payload/version")
                .and_then(serde_json::Value::as_u64),
            Some(2)
        );
        let _ = fs::remove_dir_all(dir);
    }
}
