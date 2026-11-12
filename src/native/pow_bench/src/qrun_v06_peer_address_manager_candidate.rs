//! Candidate-only bounded QFP6 peer-address book. Not connected to discovery or runtime.
//! Local checksums provide corruption detection, not freshness or peer authentication.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
};

pub const MAX_PEERS: usize = 256;
pub const MAX_STORE_BYTES: usize = 256 * 1024;
const MAGIC: &str = "Q6PA-ADDRESS-BOOK";
const VERSION: u64 = 2;
const DOMAIN_V1: &[u8] = b"QFP6-PEER-ADDRESS-BOOK-V1\0";
const DOMAIN_V2: &[u8] = b"QFP6-PEER-ADDRESS-BOOK-V2\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum PeerAddressSource {
    Manual = 1,
    Bootstrap = 2,
    Gossip = 3,
}
impl PeerAddressSource {
    fn parse(v: u64) -> Option<Self> {
        match v {
            1 => Some(Self::Manual),
            2 => Some(Self::Bootstrap),
            3 => Some(Self::Gossip),
            _ => None,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerAddressRecord {
    pub address: String,
    pub source: PeerAddressSource,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub failures: u32,
    pub retry_after_ms: u64,
    pub banned_until_ms: u64,
    /// Advertised key is a candidate only; it is not trusted until a later pinned handshake.
    pub advertised_noise_static_key: Option<[u8; 32]>,
    pub relay_static_public_key: Option<[u8; 32]>,
    pub relay_static_key_pinned: bool,
    pub advertisement_expires_at_ms: u64,
    pub advertisement_fingerprint: Option<[u8; 32]>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerAddressBookError {
    Io(String),
    Malformed,
    ChecksumMismatch,
    WrongNetwork,
    WrongProfile,
    Capacity,
    InvalidAddress,
    LockHeld,
    StoreTooLarge,
    UnauthenticatedRelay,
    Replay,
}
impl std::fmt::Display for PeerAddressBookError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for PeerAddressBookError {}
impl From<std::io::Error> for PeerAddressBookError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

fn parse_optional_key(value: Option<&Value>) -> Result<Option<[u8; 32]>, PeerAddressBookError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if value.len() == 64 => {
            let mut key = [0u8; 32];
            for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
                let text =
                    std::str::from_utf8(chunk).map_err(|_| PeerAddressBookError::Malformed)?;
                key[index] =
                    u8::from_str_radix(text, 16).map_err(|_| PeerAddressBookError::Malformed)?;
            }
            if key == [0; 32] {
                return Err(PeerAddressBookError::Malformed);
            }
            Ok(Some(key))
        }
        _ => Err(PeerAddressBookError::Malformed),
    }
}

pub struct QRunV06PeerAddressBookCandidate {
    path: PathBuf,
    lock_path: PathBuf,
    _lock: File,
    network: [u8; 32],
    profile: [u8; 32],
    records: BTreeMap<String, PeerAddressRecord>,
}
impl QRunV06PeerAddressBookCandidate {
    pub fn open(
        path: impl AsRef<Path>,
        network: [u8; 32],
        profile: [u8; 32],
    ) -> Result<Self, PeerAddressBookError> {
        let path = path.as_ref().to_path_buf();
        let parent = path.parent().ok_or(PeerAddressBookError::Malformed)?;
        fs::create_dir_all(parent)?;
        let lock_path = path.with_extension("q6pa.lock");
        let lock = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    PeerAddressBookError::LockHeld
                } else {
                    e.into()
                }
            })?;
        let mut book = Self {
            path,
            lock_path,
            _lock: lock,
            network,
            profile,
            records: BTreeMap::new(),
        };
        if book.path.exists() {
            book.load()?;
        }
        Ok(book)
    }
    pub fn records(&self) -> impl Iterator<Item = &PeerAddressRecord> {
        self.records.values()
    }
    pub fn upsert(
        &mut self,
        address: &str,
        source: PeerAddressSource,
        now_ms: u64,
    ) -> Result<(), PeerAddressBookError> {
        let parsed: SocketAddr = address
            .parse()
            .map_err(|_| PeerAddressBookError::InvalidAddress)?;
        if parsed.port() == 0 || parsed.ip().is_unspecified() || parsed.ip().is_multicast() {
            return Err(PeerAddressBookError::InvalidAddress);
        }
        let canonical = parsed.to_string();
        if !self.records.contains_key(&canonical) && self.records.len() >= MAX_PEERS {
            return Err(PeerAddressBookError::Capacity);
        }
        self.records
            .entry(canonical.clone())
            .and_modify(|r| {
                r.last_seen_ms = r.last_seen_ms.max(now_ms);
                if source == PeerAddressSource::Manual {
                    r.source = source;
                }
            })
            .or_insert(PeerAddressRecord {
                address: canonical,
                source,
                first_seen_ms: now_ms,
                last_seen_ms: now_ms,
                failures: 0,
                retry_after_ms: 0,
                banned_until_ms: 0,
                advertised_noise_static_key: None,
                relay_static_public_key: None,
                relay_static_key_pinned: false,
                advertisement_expires_at_ms: 0,
                advertisement_fingerprint: None,
            });
        self.persist()
    }
    pub fn record_failure(
        &mut self,
        address: &str,
        now_ms: u64,
    ) -> Result<(), PeerAddressBookError> {
        let r = self
            .records
            .get_mut(address)
            .ok_or(PeerAddressBookError::InvalidAddress)?;
        r.failures = r.failures.saturating_add(1);
        let shift = r.failures.saturating_sub(1).min(10);
        let delay = 30_000u64
            .saturating_mul(1u64 << shift)
            .min(6 * 60 * 60 * 1000);
        r.retry_after_ms = now_ms.saturating_add(delay);
        self.persist()
    }
    pub fn is_eligible(&self, address: &str, now_ms: u64) -> bool {
        self.records
            .get(address)
            .is_some_and(|r| now_ms >= r.retry_after_ms && now_ms >= r.banned_until_ms)
    }
    pub fn ban_until(&mut self, address: &str, until_ms: u64) -> Result<(), PeerAddressBookError> {
        let r = self
            .records
            .get_mut(address)
            .ok_or(PeerAddressBookError::InvalidAddress)?;
        r.banned_until_ms = r.banned_until_ms.max(until_ms);
        self.persist()
    }
    /// Persist only advertisements relayed over an operator-pinned Noise session.
    /// Advertised endpoint keys remain candidates and are never promoted to trust pins here.
    pub fn ingest_pinned_q6ar(
        &mut self,
        received: &crate::qrun_v06_peer_address_relay_candidate::Q6arReceivedAdvertisement,
        now_ms: u64,
    ) -> Result<usize, PeerAddressBookError> {
        if !received.relay_origin.relay_static_key_pinned
            || received.relay_origin.relay_static_public_key == [0; 32]
        {
            return Err(PeerAddressBookError::UnauthenticatedRelay);
        }
        if received.advertisement.network_id != self.network {
            return Err(PeerAddressBookError::WrongNetwork);
        }
        if received.advertisement.profile_id != self.profile {
            return Err(PeerAddressBookError::WrongProfile);
        }
        if received.advertisement.issued_at_secs
            > now_ms / 1000
                + crate::qrun_v06_peer_address_relay_candidate::Q6AR_MAX_FUTURE_SKEW_SECS
        {
            return Err(PeerAddressBookError::Malformed);
        }
        let expires = received
            .advertisement
            .issued_at_secs
            .saturating_add(received.advertisement.ttl_secs as u64)
            .saturating_mul(1000);
        if expires <= now_ms {
            return Err(PeerAddressBookError::Malformed);
        }
        let encoded =
            crate::qrun_v06_peer_address_relay_candidate::encode_q6ar(&received.advertisement)
                .map_err(|_| PeerAddressBookError::Malformed)?;
        let mut fingerprint_hash = Sha256::new();
        fingerprint_hash.update(b"QFP6-Q6AR-REPLAY-V1\0");
        fingerprint_hash.update(&encoded);
        let fingerprint: [u8; 32] = fingerprint_hash.finalize().into();
        if self
            .records
            .values()
            .any(|record| record.advertisement_fingerprint == Some(fingerprint))
        {
            return Err(PeerAddressBookError::Replay);
        }
        let before = self.records.clone();
        for advertised in &received.advertisement.addresses {
            let address = advertised.endpoint.to_string();
            if !self.records.contains_key(&address) && self.records.len() >= MAX_PEERS {
                self.records = before;
                return Err(PeerAddressBookError::Capacity);
            }
            let record = self
                .records
                .entry(address.clone())
                .or_insert(PeerAddressRecord {
                    address,
                    source: PeerAddressSource::Gossip,
                    first_seen_ms: now_ms,
                    last_seen_ms: now_ms,
                    failures: 0,
                    retry_after_ms: 0,
                    banned_until_ms: 0,
                    advertised_noise_static_key: None,
                    relay_static_public_key: None,
                    relay_static_key_pinned: false,
                    advertisement_expires_at_ms: 0,
                    advertisement_fingerprint: None,
                });
            record.last_seen_ms = record.last_seen_ms.max(now_ms);
            record.advertised_noise_static_key = Some(advertised.noise_static_public_key);
            record.relay_static_public_key = Some(received.relay_origin.relay_static_public_key);
            record.relay_static_key_pinned = true;
            record.advertisement_expires_at_ms = record.advertisement_expires_at_ms.max(expires);
            record.advertisement_fingerprint = Some(fingerprint);
            if record.source != PeerAddressSource::Manual
                && record.source != PeerAddressSource::Bootstrap
            {
                record.source = PeerAddressSource::Gossip;
            }
        }
        if let Err(error) = self.persist() {
            self.records = before;
            return Err(error);
        }
        Ok(received.advertisement.addresses.len())
    }
    fn payload(&self) -> Value {
        let rows:Vec<Value>=self.records.values().map(|r|json!({"address":r.address,"source":r.source as u64,"first_seen_ms":r.first_seen_ms,"last_seen_ms":r.last_seen_ms,"failures":r.failures,"retry_after_ms":r.retry_after_ms,"banned_until_ms":r.banned_until_ms,"advertised_noise_static_key":r.advertised_noise_static_key.map(|v|hex(&v)),"relay_static_public_key":r.relay_static_public_key.map(|v|hex(&v)),"relay_static_key_pinned":r.relay_static_key_pinned,"advertisement_expires_at_ms":r.advertisement_expires_at_ms,"advertisement_fingerprint":r.advertisement_fingerprint.map(|v|hex(&v))})).collect();
        json!({"magic":MAGIC,"version":VERSION,"network":hex(&self.network),"profile":hex(&self.profile),"records":rows})
    }
    fn persist(&self) -> Result<(), PeerAddressBookError> {
        let payload = self.payload();
        let body = serde_json::to_vec(&payload).map_err(|_| PeerAddressBookError::Malformed)?;
        let mut h = Sha256::new();
        h.update(DOMAIN_V2);
        h.update(&body);
        let checksum = hex(&h.finalize());
        let bytes = serde_json::to_vec(&json!({"payload":payload,"checksum":checksum}))
            .map_err(|_| PeerAddressBookError::Malformed)?;
        if bytes.len() > MAX_STORE_BYTES {
            return Err(PeerAddressBookError::StoreTooLarge);
        }
        let temp = self
            .path
            .with_extension(format!("q6pa.{}.tmp", std::process::id()));
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        let result = (|| {
            f.write_all(&bytes)?;
            f.sync_all()?;
            drop(f);
            atomic_replace(&temp, &self.path)?;
            Ok::<(), PeerAddressBookError>(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result
    }
    fn load(&mut self) -> Result<(), PeerAddressBookError> {
        let meta = fs::metadata(&self.path)?;
        if meta.len() as usize > MAX_STORE_BYTES {
            return Err(PeerAddressBookError::StoreTooLarge);
        }
        let mut bytes = Vec::new();
        File::open(&self.path)?.read_to_end(&mut bytes)?;
        let root: Value =
            serde_json::from_slice(&bytes).map_err(|_| PeerAddressBookError::Malformed)?;
        let payload = root.get("payload").ok_or(PeerAddressBookError::Malformed)?;
        let body = serde_json::to_vec(payload).map_err(|_| PeerAddressBookError::Malformed)?;
        let version = payload
            .get("version")
            .and_then(Value::as_u64)
            .ok_or(PeerAddressBookError::Malformed)?;
        let domain = match version {
            1 => DOMAIN_V1,
            2 => DOMAIN_V2,
            _ => return Err(PeerAddressBookError::Malformed),
        };
        let mut h = Sha256::new();
        h.update(domain);
        h.update(&body);
        if root.get("checksum").and_then(Value::as_str) != Some(hex(&h.finalize()).as_str()) {
            return Err(PeerAddressBookError::ChecksumMismatch);
        }
        if payload.get("magic").and_then(Value::as_str) != Some(MAGIC) || !matches!(version, 1 | 2)
        {
            return Err(PeerAddressBookError::Malformed);
        }
        if payload.get("network").and_then(Value::as_str) != Some(hex(&self.network).as_str()) {
            return Err(PeerAddressBookError::WrongNetwork);
        }
        if payload.get("profile").and_then(Value::as_str) != Some(hex(&self.profile).as_str()) {
            return Err(PeerAddressBookError::WrongProfile);
        }
        let rows = payload
            .get("records")
            .and_then(Value::as_array)
            .ok_or(PeerAddressBookError::Malformed)?;
        if rows.len() > MAX_PEERS {
            return Err(PeerAddressBookError::Capacity);
        }
        let mut loaded = BTreeMap::new();
        for v in rows {
            let s = |k: &str| {
                v.get(k)
                    .and_then(Value::as_u64)
                    .ok_or(PeerAddressBookError::Malformed)
            };
            let address = v
                .get("address")
                .and_then(Value::as_str)
                .ok_or(PeerAddressBookError::Malformed)?
                .to_owned();
            let parsed: SocketAddr = address
                .parse()
                .map_err(|_| PeerAddressBookError::Malformed)?;
            if parsed.to_string() != address
                || parsed.port() == 0
                || parsed.ip().is_unspecified()
                || parsed.ip().is_multicast()
            {
                return Err(PeerAddressBookError::Malformed);
            }
            let source =
                PeerAddressSource::parse(s("source")?).ok_or(PeerAddressBookError::Malformed)?;
            let failures =
                u32::try_from(s("failures")?).map_err(|_| PeerAddressBookError::Malformed)?;
            let rec = PeerAddressRecord {
                address: address.clone(),
                source,
                first_seen_ms: s("first_seen_ms")?,
                last_seen_ms: s("last_seen_ms")?,
                failures,
                retry_after_ms: s("retry_after_ms")?,
                banned_until_ms: s("banned_until_ms")?,
                advertised_noise_static_key: if version >= 2 {
                    parse_optional_key(v.get("advertised_noise_static_key"))?
                } else {
                    None
                },
                relay_static_public_key: if version >= 2 {
                    parse_optional_key(v.get("relay_static_public_key"))?
                } else {
                    None
                },
                relay_static_key_pinned: if version >= 2 {
                    v.get("relay_static_key_pinned")
                        .and_then(Value::as_bool)
                        .ok_or(PeerAddressBookError::Malformed)?
                } else {
                    false
                },
                advertisement_expires_at_ms: if version >= 2 {
                    s("advertisement_expires_at_ms")?
                } else {
                    0
                },
                advertisement_fingerprint: if version >= 2 {
                    parse_optional_key(v.get("advertisement_fingerprint"))?
                } else {
                    None
                },
            };
            let metadata_consistent = match (
                rec.advertised_noise_static_key,
                rec.relay_static_public_key,
                rec.relay_static_key_pinned,
                rec.advertisement_expires_at_ms,
                rec.advertisement_fingerprint,
            ) {
                (None, None, false, 0, None) => true,
                (Some(_), Some(_), true, expiry, Some(_)) if expiry > 0 => true,
                _ => false,
            };
            if rec.last_seen_ms < rec.first_seen_ms
                || !metadata_consistent
                || loaded.insert(address, rec).is_some()
            {
                return Err(PeerAddressBookError::Malformed);
            }
        }
        self.records = loaded;
        if version == 1 {
            self.persist()?;
        }
        Ok(())
    }
}
impl Drop for QRunV06PeerAddressBookCandidate {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_path);
    }
}
fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 15) as usize] as char);
    }
    s
}
#[cfg(windows)]
fn atomic_replace(src: &Path, dst: &Path) -> Result<(), PeerAddressBookError> {
    use std::os::windows::ffi::OsStrExt;
    const REPLACE: u32 = 1;
    const WRITE: u32 = 8;
    #[link(name = "Kernel32")]
    extern "system" {
        fn MoveFileExW(a: *const u16, b: *const u16, c: u32) -> i32;
    }
    let a: Vec<u16> = src.as_os_str().encode_wide().chain(Some(0)).collect();
    let b: Vec<u16> = dst.as_os_str().encode_wide().chain(Some(0)).collect();
    if unsafe { MoveFileExW(a.as_ptr(), b.as_ptr(), REPLACE | WRITE) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
#[cfg(unix)]
fn atomic_replace(src: &Path, dst: &Path) -> Result<(), PeerAddressBookError> {
    fs::rename(src, dst)?;
    if let Some(p) = dst.parent() {
        File::open(p)?.sync_all()?;
    }
    Ok(())
}
#[cfg(not(any(windows, unix)))]
fn atomic_replace(_: &Path, _: &Path) -> Result<(), PeerAddressBookError> {
    Err(PeerAddressBookError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "q6pa-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn persists_and_recovers_network_bound_records() {
        let t = Temp::new();
        let p = t.0.join("peers.q6pa");
        let n = [1; 32];
        let f = [2; 32];
        {
            let mut b = QRunV06PeerAddressBookCandidate::open(&p, n, f).unwrap();
            b.upsert("127.0.0.1:8333", PeerAddressSource::Manual, 10)
                .unwrap();
            b.record_failure("127.0.0.1:8333", 20).unwrap();
            assert!(!b.is_eligible("127.0.0.1:8333", 30));
        }
        let b = QRunV06PeerAddressBookCandidate::open(&p, n, f).unwrap();
        assert_eq!(b.records().count(), 1);
        drop(b);
        assert!(matches!(
            QRunV06PeerAddressBookCandidate::open(&p, [9; 32], f),
            Err(PeerAddressBookError::WrongNetwork)
        ));
    }
    #[test]
    fn migrates_v1_store_to_v2_without_losing_records() {
        let t = Temp::new();
        let p = t.0.join("peers.q6pa");
        let payload = json!({
            "magic": MAGIC, "version": 1, "network": hex(&[1; 32]), "profile": hex(&[2; 32]),
            "records": [{"address":"127.0.0.1:8333","source":1,"first_seen_ms":10,"last_seen_ms":20,"failures":2,"retry_after_ms":30,"banned_until_ms":0}]
        });
        let body = serde_json::to_vec(&payload).unwrap();
        let mut hash = Sha256::new();
        hash.update(DOMAIN_V1);
        hash.update(&body);
        fs::write(
            &p,
            serde_json::to_vec(&json!({"payload":payload,"checksum":hex(&hash.finalize())}))
                .unwrap(),
        )
        .unwrap();
        let book = QRunV06PeerAddressBookCandidate::open(&p, [1; 32], [2; 32]).unwrap();
        let record = book.records().next().unwrap();
        assert_eq!(record.address, "127.0.0.1:8333");
        assert_eq!(record.failures, 2);
        assert_eq!(record.advertised_noise_static_key, None);
        drop(book);
        let migrated: Value = serde_json::from_slice(&fs::read(&p).unwrap()).unwrap();
        assert_eq!(migrated["payload"]["version"].as_u64(), Some(2));
    }

    #[test]
    fn stores_only_pinned_q6ar_relay_metadata_and_recovers_it() {
        let t = Temp::new();
        let p = t.0.join("peers.q6pa");
        let received = crate::qrun_v06_peer_address_relay_candidate::Q6arReceivedAdvertisement {
            advertisement: crate::qrun_v06_peer_address_relay_candidate::Q6arAdvertisement {
                network_id: [1; 32],
                profile_id: [2; 32],
                issued_at_secs: 100,
                ttl_secs: 60,
                addresses: vec![crate::qrun_v06_peer_address_relay_candidate::Q6arAddress {
                    endpoint: "8.8.8.8:8333".parse().unwrap(),
                    noise_static_public_key: [7; 32],
                }],
            },
            relay_origin: crate::qrun_v06_peer_address_relay_candidate::Q6arRelayOrigin {
                relay_static_public_key: [9; 32],
                relay_static_key_pinned: true,
            },
        };
        {
            let mut book = QRunV06PeerAddressBookCandidate::open(&p, [1; 32], [2; 32]).unwrap();
            assert_eq!(book.ingest_pinned_q6ar(&received, 100_000).unwrap(), 1);
            let record = book.records().next().unwrap();
            assert_eq!(record.advertised_noise_static_key, Some([7; 32]));
            assert_eq!(record.relay_static_public_key, Some([9; 32]));
            assert!(record.relay_static_key_pinned);
            assert_eq!(record.advertisement_expires_at_ms, 160_000);
        }
        let mut book = QRunV06PeerAddressBookCandidate::open(&p, [1; 32], [2; 32]).unwrap();
        assert_eq!(
            book.ingest_pinned_q6ar(&received, 100_000),
            Err(PeerAddressBookError::Replay)
        );
        drop(book);
        let book = QRunV06PeerAddressBookCandidate::open(&p, [1; 32], [2; 32]).unwrap();
        assert_eq!(
            book.records().next().unwrap().advertised_noise_static_key,
            Some([7; 32])
        );
    }

    #[test]
    fn refuses_unpinned_q6ar_relay_and_wrong_profile() {
        let t = Temp::new();
        let p = t.0.join("peers.q6pa");
        let mut book = QRunV06PeerAddressBookCandidate::open(&p, [1; 32], [2; 32]).unwrap();
        let mut received =
            crate::qrun_v06_peer_address_relay_candidate::Q6arReceivedAdvertisement {
                advertisement: crate::qrun_v06_peer_address_relay_candidate::Q6arAdvertisement {
                    network_id: [1; 32],
                    profile_id: [2; 32],
                    issued_at_secs: 100,
                    ttl_secs: 60,
                    addresses: vec![crate::qrun_v06_peer_address_relay_candidate::Q6arAddress {
                        endpoint: "1.1.1.1:8333".parse().unwrap(),
                        noise_static_public_key: [7; 32],
                    }],
                },
                relay_origin: crate::qrun_v06_peer_address_relay_candidate::Q6arRelayOrigin {
                    relay_static_public_key: [9; 32],
                    relay_static_key_pinned: false,
                },
            };
        assert_eq!(
            book.ingest_pinned_q6ar(&received, 100_000),
            Err(PeerAddressBookError::UnauthenticatedRelay)
        );
        received.relay_origin.relay_static_key_pinned = true;
        received.advertisement.profile_id = [3; 32];
        assert_eq!(
            book.ingest_pinned_q6ar(&received, 100_000),
            Err(PeerAddressBookError::WrongProfile)
        );
        assert_eq!(book.records().count(), 0);
    }

    #[test]
    fn rejects_checksum_corruption() {
        let t = Temp::new();
        let p = t.0.join("peers.q6pa");
        {
            let mut b = QRunV06PeerAddressBookCandidate::open(&p, [1; 32], [2; 32]).unwrap();
            b.upsert("127.0.0.1:8333", PeerAddressSource::Bootstrap, 1)
                .unwrap();
        }
        let mut v = fs::read(&p).unwrap();
        let i = v.iter().position(|x| *x == b'1').unwrap();
        v[i] = b'9';
        fs::write(&p, v).unwrap();
        assert!(matches!(
            QRunV06PeerAddressBookCandidate::open(&p, [1; 32], [2; 32]),
            Err(PeerAddressBookError::ChecksumMismatch) | Err(PeerAddressBookError::Malformed)
        ));
    }
    #[test]
    fn rejects_invalid_addresses_and_applies_backoff() {
        let t = Temp::new();
        let p = t.0.join("peers.q6pa");
        let mut b = QRunV06PeerAddressBookCandidate::open(&p, [1; 32], [2; 32]).unwrap();
        assert_eq!(
            b.upsert("0.0.0.0:0", PeerAddressSource::Gossip, 1),
            Err(PeerAddressBookError::InvalidAddress)
        );
        b.upsert("127.0.0.1:8333", PeerAddressSource::Gossip, 1)
            .unwrap();
        b.record_failure("127.0.0.1:8333", 10).unwrap();
        assert!(!b.is_eligible("127.0.0.1:8333", 20));
        assert!(b.is_eligible("127.0.0.1:8333", 30_010));
    }
}
