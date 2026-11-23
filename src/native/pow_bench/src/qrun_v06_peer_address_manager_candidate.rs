//! Bounded QFP6 peer candidate/trust address book. Q6AR candidates and operator-approved pins are
//! stored separately; runtime use is opt-in and never auto-trusts or auto-connects candidates.
//! Local checksums provide corruption detection, not freshness or peer authentication.
use crate::qrun_v06_bootstrap_trust_domain_candidate::{
    BootstrapTrustDomainPolicy, TrustDomainPolicyError,
};
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
pub const MAX_GOSSIP_PEERS_PER_RELAY: usize = 32;
pub const MAX_STORE_BYTES: usize = 256 * 1024;
const MAGIC: &str = "Q6PA-ADDRESS-BOOK";
const VERSION: u64 = 4;
const DOMAIN_V1: &[u8] = b"QFP6-PEER-ADDRESS-BOOK-V1\0";
const DOMAIN_V2: &[u8] = b"QFP6-PEER-ADDRESS-BOOK-V2\0";
const DOMAIN_V3: &[u8] = b"QFP6-PEER-ADDRESS-BOOK-V3\0";
const DOMAIN_V4: &[u8] = b"QFP6-PEER-ADDRESS-BOOK-V4\0";

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
    /// Explicit operator-approved outbound pin. Never populated by Q6AR ingestion.
    pub operator_approved_noise_static_key: Option<[u8; 32]>,
    pub operator_approved_at_ms: u64,
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
    RelayCapacity,
    Replay,
    ApprovalKeyConflict,
    NotAnApprovedCandidate,
    TrustDomain(TrustDomainPolicyError),
    UnattributableCandidate,
    TrustDomainRegistryMismatch,
    TrustDomainRotationNotBound,
    TrustDomainRotationBlockedByLiveCandidates,
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
    trust_domain_registry_fingerprint: Option<[u8; 32]>,
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
            trust_domain_registry_fingerprint: None,
        };
        if book.path.exists() {
            book.load()?;
        }
        Ok(book)
    }
    pub fn records(&self) -> impl Iterator<Item = &PeerAddressRecord> {
        self.records.values()
    }

    /// Network and profile scope are immutable for this open address book.
    pub fn network_id(&self) -> &[u8; 32] {
        &self.network
    }

    pub fn profile_id(&self) -> &[u8; 32] {
        &self.profile
    }

    /// Build a bounded, expiring inventory from authenticated-relay gossip only.
    /// Manual pins without an original, fresh advertisement are never exported.
    pub fn current_gossip_advertisement(
        &self,
        now_ms: u64,
        max_addresses: usize,
    ) -> Option<crate::qrun_v06_peer_address_relay_candidate::Q6arAdvertisement> {
        use crate::qrun_v06_peer_address_relay_candidate::{
            Q6arAddress, Q6arAdvertisement, Q6AR_MAX_ADDRESSES, Q6AR_MAX_TTL_SECS,
        };
        if self.trust_domain_registry_fingerprint.is_none()
            || max_addresses == 0
            || max_addresses > Q6AR_MAX_ADDRESSES
        {
            return None;
        }
        let mut addresses = Vec::new();
        let mut earliest_expiry_ms = u64::MAX;
        for record in self.records.values() {
            if !record.relay_static_key_pinned
                || record.relay_static_public_key.is_none()
                || record.advertisement_fingerprint.is_none()
                || record.advertised_noise_static_key.is_none()
                || record.advertisement_expires_at_ms <= now_ms
                || record.banned_until_ms > now_ms
            {
                continue;
            }
            let endpoint = match record.address.parse::<SocketAddr>() {
                Ok(endpoint) => endpoint,
                Err(_) => continue,
            };
            let Some(noise_static_public_key) = record.advertised_noise_static_key else {
                continue;
            };
            addresses.push(Q6arAddress {
                endpoint,
                noise_static_public_key,
            });
            earliest_expiry_ms = earliest_expiry_ms.min(record.advertisement_expires_at_ms);
            if addresses.len() >= max_addresses {
                break;
            }
        }
        if addresses.is_empty() {
            return None;
        }
        // Never extend a candidate beyond the earliest source-advertisement expiry.
        let issued_at_secs = now_ms / 1_000;
        let remaining_secs = earliest_expiry_ms.saturating_sub(now_ms) / 1_000;
        let ttl_secs = remaining_secs.min(Q6AR_MAX_TTL_SECS as u64) as u32;
        if ttl_secs == 0 {
            return None;
        }
        Some(Q6arAdvertisement {
            network_id: self.network,
            profile_id: self.profile,
            issued_at_secs,
            ttl_secs,
            addresses,
        })
    }

    /// Bind this persistent address book to one exact operator-provisioned trust registry.
    /// Existing live Q6AR Gossip records must be attributable and fit the new domain quotas.
    /// Expired unapproved candidates are reclaimed as part of this startup transaction.
    pub fn bind_trust_domain_registry(
        &mut self,
        policy: &BootstrapTrustDomainPolicy,
        now_ms: u64,
    ) -> Result<(), PeerAddressBookError> {
        let fingerprint = policy.fingerprint();
        if self
            .trust_domain_registry_fingerprint
            .is_some_and(|stored| stored != fingerprint)
        {
            return Err(PeerAddressBookError::TrustDomainRegistryMismatch);
        }

        let before_records = self.records.clone();
        let before_fingerprint = self.trust_domain_registry_fingerprint;
        let result = (|| {
            self.records.retain(|_, record| {
                !(record.source == PeerAddressSource::Gossip
                    && record.operator_approved_noise_static_key.is_none()
                    && record.advertisement_expires_at_ms != 0
                    && record.advertisement_expires_at_ms <= now_ms)
            });

            let mut candidate_relay_keys = Vec::new();
            for record in self.records.values().filter(|record| {
                record.source == PeerAddressSource::Gossip
                    && record.operator_approved_noise_static_key.is_none()
            }) {
                if !record.relay_static_key_pinned
                    || record.relay_static_public_key.is_none()
                    || record.advertised_noise_static_key.is_none()
                    || record.advertisement_fingerprint.is_none()
                    || record.advertisement_expires_at_ms == 0
                {
                    return Err(PeerAddressBookError::UnattributableCandidate);
                }
                candidate_relay_keys.push(
                    record
                        .relay_static_public_key
                        .ok_or(PeerAddressBookError::UnattributableCandidate)?,
                );
            }
            policy
                .validate_existing_candidate_records(&candidate_relay_keys)
                .map_err(PeerAddressBookError::TrustDomain)?;

            let changed = self.trust_domain_registry_fingerprint != Some(fingerprint)
                || self.records.len() != before_records.len();
            self.trust_domain_registry_fingerprint = Some(fingerprint);
            if changed {
                self.persist()?;
            }
            Ok(())
        })();

        if result.is_err() {
            self.records = before_records;
            self.trust_domain_registry_fingerprint = before_fingerprint;
        }
        result
    }
    /// Explicitly rotate a previously bound operator registry after all old, unapproved
    /// Q6AR candidates have expired or been removed. Ordinary startup binding never rotates.
    ///
    /// Operator-approved peer pins are retained: their outbound trust is an independent,
    /// explicit operator decision and no longer depends on the relay's Q6AR trust domain.
    pub fn rotate_trust_domain_registry(
        &mut self,
        policy: &BootstrapTrustDomainPolicy,
        now_ms: u64,
    ) -> Result<(), PeerAddressBookError> {
        let fingerprint = policy.fingerprint();
        let Some(stored) = self.trust_domain_registry_fingerprint else {
            return Err(PeerAddressBookError::TrustDomainRotationNotBound);
        };
        if stored == fingerprint {
            return self.bind_trust_domain_registry(policy, now_ms);
        }

        let before_records = self.records.clone();
        let before_fingerprint = self.trust_domain_registry_fingerprint;
        let result = (|| {
            // Only stale, unapproved Q6AR candidate metadata may be discarded automatically.
            self.records.retain(|_, record| {
                !(record.source == PeerAddressSource::Gossip
                    && record.operator_approved_noise_static_key.is_none()
                    && record.advertisement_expires_at_ms != 0
                    && record.advertisement_expires_at_ms <= now_ms)
            });

            for record in self.records.values().filter(|record| {
                record.source == PeerAddressSource::Gossip
                    && record.operator_approved_noise_static_key.is_none()
            }) {
                if !record.relay_static_key_pinned
                    || record.relay_static_public_key.is_none()
                    || record.advertised_noise_static_key.is_none()
                    || record.advertisement_fingerprint.is_none()
                    || record.advertisement_expires_at_ms == 0
                {
                    return Err(PeerAddressBookError::UnattributableCandidate);
                }
                return Err(PeerAddressBookError::TrustDomainRotationBlockedByLiveCandidates);
            }

            self.trust_domain_registry_fingerprint = Some(fingerprint);
            self.persist()?;
            Ok(())
        })();

        if result.is_err() {
            self.records = before_records;
            self.trust_domain_registry_fingerprint = before_fingerprint;
        }
        result
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
                operator_approved_noise_static_key: None,
                operator_approved_at_ms: 0,
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
        self.ingest_pinned_q6ar_inner(received, now_ms, None)
    }

    /// Persist Q6AR advertisements under operator-provisioned trust-domain quotas.
    ///
    /// The trust registry is local policy: only the authenticated relay static key is
    /// read from the received advertisement. Existing Q6AR candidates must all be
    /// attributable through the supplied registry; legacy/unattributable Gossip records
    /// fail closed. The caller must keep the registry's domain assignments stable while
    /// records attributed to those keys remain in the address book.
    pub fn ingest_pinned_q6ar_with_trust_domains(
        &mut self,
        received: &crate::qrun_v06_peer_address_relay_candidate::Q6arReceivedAdvertisement,
        now_ms: u64,
        trust_domains: &BootstrapTrustDomainPolicy,
    ) -> Result<usize, PeerAddressBookError> {
        self.ingest_pinned_q6ar_inner(received, now_ms, Some(trust_domains))
    }

    fn ingest_pinned_q6ar_inner(
        &mut self,
        received: &crate::qrun_v06_peer_address_relay_candidate::Q6arReceivedAdvertisement,
        now_ms: u64,
        trust_domains: Option<&BootstrapTrustDomainPolicy>,
    ) -> Result<usize, PeerAddressBookError> {
        if trust_domains.is_some_and(|policy| {
            self.trust_domain_registry_fingerprint != Some(policy.fingerprint())
        }) {
            return Err(PeerAddressBookError::TrustDomainRegistryMismatch);
        }
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
        // Treat expiry reclamation, all batch updates, all quota checks and persistence
        // as one transaction. Any error restores the exact pre-ingestion in-memory book.
        let before = self.records.clone();
        let result = (|| {
            // Expired, unapproved gossip is disposable candidate metadata. Reclaim it before
            // enforcing capacity; explicit operator pins and non-gossip records are retained.
            self.records.retain(|_, record| {
                !(record.source == PeerAddressSource::Gossip
                    && record.operator_approved_noise_static_key.is_none()
                    && record.advertisement_expires_at_ms != 0
                    && record.advertisement_expires_at_ms <= now_ms)
            });

            // Rebuild one relay-key entry per live Q6AR candidate record. A plain/legacy
            // Gossip record has no defensible trust-domain attribution and blocks strict
            // admission until explicitly migrated or removed.
            let mut domain_candidate_relays = if trust_domains.is_some() {
                let mut relay_keys = Vec::new();
                for record in self
                    .records
                    .values()
                    .filter(|record| record.source == PeerAddressSource::Gossip)
                {
                    if !record.relay_static_key_pinned
                        || record.relay_static_public_key.is_none()
                        || record.advertised_noise_static_key.is_none()
                        || record.advertisement_fingerprint.is_none()
                        || record.advertisement_expires_at_ms == 0
                    {
                        return Err(PeerAddressBookError::UnattributableCandidate);
                    }
                    relay_keys.push(
                        record
                            .relay_static_public_key
                            .ok_or(PeerAddressBookError::UnattributableCandidate)?,
                    );
                }
                Some(relay_keys)
            } else {
                None
            };

            let relay_key = received.relay_origin.relay_static_public_key;
            let mut relay_peer_count = self
                .records
                .values()
                .filter(|record| {
                    record.source == PeerAddressSource::Gossip
                        && record.relay_static_key_pinned
                        && record.relay_static_public_key == Some(relay_key)
                })
                .count();

            for advertised in &received.advertisement.addresses {
                let address = advertised.endpoint.to_string();
                let existing = self.records.get(&address);
                let remains_candidate = existing.is_none_or(|record| {
                    record.source != PeerAddressSource::Manual
                        && record.source != PeerAddressSource::Bootstrap
                });
                let new_for_relay = remains_candidate
                    && existing.is_none_or(|record| {
                        !record.relay_static_key_pinned
                            || record.relay_static_public_key != Some(relay_key)
                    });

                if new_for_relay {
                    if let (Some(policy), Some(candidate_relays)) =
                        (trust_domains, domain_candidate_relays.as_mut())
                    {
                        // Re-attributing an existing endpoint moves exactly one candidate
                        // slot from its former relay before checking the new relay/domain.
                        if let Some(previous_relay) = existing
                            .filter(|record| record.source == PeerAddressSource::Gossip)
                            .and_then(|record| record.relay_static_public_key)
                        {
                            let position = candidate_relays
                                .iter()
                                .position(|key| *key == previous_relay)
                                .ok_or(PeerAddressBookError::UnattributableCandidate)?;
                            candidate_relays.remove(position);
                        }
                        policy
                            .check_candidate_admission(&relay_key, candidate_relays)
                            .map_err(PeerAddressBookError::TrustDomain)?;
                        candidate_relays.push(relay_key);
                    }
                }

                if new_for_relay && relay_peer_count >= MAX_GOSSIP_PEERS_PER_RELAY {
                    return Err(PeerAddressBookError::RelayCapacity);
                }
                if !self.records.contains_key(&address) && self.records.len() >= MAX_PEERS {
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
                        operator_approved_noise_static_key: None,
                        operator_approved_at_ms: 0,
                    });
                record.last_seen_ms = record.last_seen_ms.max(now_ms);
                record.advertised_noise_static_key = Some(advertised.noise_static_public_key);
                record.relay_static_public_key = Some(relay_key);
                record.relay_static_key_pinned = true;
                record.advertisement_expires_at_ms =
                    record.advertisement_expires_at_ms.max(expires);
                record.advertisement_fingerprint = Some(fingerprint);
                if record.source != PeerAddressSource::Manual
                    && record.source != PeerAddressSource::Bootstrap
                {
                    record.source = PeerAddressSource::Gossip;
                    if new_for_relay {
                        relay_peer_count += 1;
                    }
                }
            }

            self.persist()?;
            Ok(received.advertisement.addresses.len())
        })();

        if result.is_err() {
            self.records = before;
        }
        result
    }
    /// Explicitly trust an endpoint/key pair supplied by the node operator. If the endpoint
    /// came from Q6AR, the key must exactly match the recorded, still-fresh advertised key.
    /// Changing an existing approval requires a separate revoke operation first.
    pub fn pin_manual_peer(
        &mut self,
        address: &str,
        noise_static_public_key: [u8; 32],
        now_ms: u64,
    ) -> Result<(), PeerAddressBookError> {
        let parsed: SocketAddr = address
            .parse()
            .map_err(|_| PeerAddressBookError::InvalidAddress)?;
        if parsed.port() == 0
            || parsed.ip().is_unspecified()
            || parsed.ip().is_multicast()
            || noise_static_public_key == [0; 32]
        {
            return Err(PeerAddressBookError::InvalidAddress);
        }
        let canonical = parsed.to_string();
        if !self.records.contains_key(&canonical) && self.records.len() >= MAX_PEERS {
            return Err(PeerAddressBookError::Capacity);
        }
        if let Some(record) = self.records.get(&canonical) {
            if record
                .advertised_noise_static_key
                .is_some_and(|key| key != noise_static_public_key)
            {
                return Err(PeerAddressBookError::ApprovalKeyConflict);
            }
            if record
                .operator_approved_noise_static_key
                .is_some_and(|key| key != noise_static_public_key)
            {
                return Err(PeerAddressBookError::ApprovalKeyConflict);
            }
            if record.advertisement_expires_at_ms != 0
                && record.advertisement_expires_at_ms <= now_ms
                && record.operator_approved_noise_static_key.is_none()
            {
                return Err(PeerAddressBookError::NotAnApprovedCandidate);
            }
        }
        let before = self.records.clone();
        self.records
            .entry(canonical.clone())
            .and_modify(|record| {
                record.source = PeerAddressSource::Manual;
                record.last_seen_ms = record.last_seen_ms.max(now_ms);
                record.operator_approved_noise_static_key = Some(noise_static_public_key);
                // Approval generation must advance even when two operator actions share
                // the same wall-clock millisecond or the local clock moves backwards.
                record.operator_approved_at_ms = now_ms
                    .max(record.operator_approved_at_ms.saturating_add(1))
                    .max(1);
                record.failures = 0;
                record.retry_after_ms = 0;
                record.banned_until_ms = 0;
            })
            .or_insert(PeerAddressRecord {
                address: canonical,
                source: PeerAddressSource::Manual,
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
                operator_approved_noise_static_key: Some(noise_static_public_key),
                operator_approved_at_ms: now_ms.max(1),
            });
        if let Err(error) = self.persist() {
            self.records = before;
            return Err(error);
        }
        Ok(())
    }

    /// Explicitly approve a Q6AR candidate only after independently checking its endpoint/key.
    pub fn approve_advertised_candidate(
        &mut self,
        address: &str,
        independently_verified_noise_static_public_key: [u8; 32],
        now_ms: u64,
    ) -> Result<(), PeerAddressBookError> {
        let record = self
            .records
            .get(address)
            .ok_or(PeerAddressBookError::NotAnApprovedCandidate)?;
        if record.advertised_noise_static_key
            != Some(independently_verified_noise_static_public_key)
            || record.advertisement_expires_at_ms <= now_ms
            || !record.relay_static_key_pinned
        {
            return Err(PeerAddressBookError::NotAnApprovedCandidate);
        }
        self.pin_manual_peer(
            address,
            independently_verified_noise_static_public_key,
            now_ms,
        )
    }

    /// Remove the operator's explicit outbound trust pin. Candidate metadata is retained.
    pub fn revoke_operator_approval(&mut self, address: &str) -> Result<(), PeerAddressBookError> {
        if self.records.get(address).is_none() {
            return Err(PeerAddressBookError::InvalidAddress);
        }
        if self
            .records
            .get(address)
            .is_some_and(|record| record.operator_approved_noise_static_key.is_none())
        {
            return Err(PeerAddressBookError::NotAnApprovedCandidate);
        }
        let before = self.records.clone();
        let record = self
            .records
            .get_mut(address)
            .ok_or(PeerAddressBookError::InvalidAddress)?;
        record.operator_approved_noise_static_key = None;
        record.operator_approved_at_ms = 0;
        if let Err(error) = self.persist() {
            self.records = before;
            return Err(error);
        }
        Ok(())
    }

    /// Return only explicit operator-approved endpoint/key pins, bounded by the caller's budget.
    pub fn approved_peer_pins(&self, now_ms: u64, limit: usize) -> Vec<(SocketAddr, [u8; 32])> {
        if limit == 0 {
            return Vec::new();
        }
        self.records
            .values()
            .filter(|record| self.is_eligible(&record.address, now_ms))
            .filter_map(|record| {
                let key = record.operator_approved_noise_static_key?;
                let address = record.address.parse().ok()?;
                Some((address, key))
            })
            .take(limit.min(MAX_PEERS))
            .collect()
    }

    pub fn record_success(&mut self, address: &str) -> Result<(), PeerAddressBookError> {
        if !self.records.contains_key(address) {
            return Err(PeerAddressBookError::InvalidAddress);
        }
        let before = self.records.clone();
        let record = self
            .records
            .get_mut(address)
            .ok_or(PeerAddressBookError::InvalidAddress)?;
        record.failures = 0;
        record.retry_after_ms = 0;
        if let Err(error) = self.persist() {
            self.records = before;
            return Err(error);
        }
        Ok(())
    }

    fn payload(&self) -> Value {
        let rows:Vec<Value>=self.records.values().map(|r|json!({"address":r.address,"source":r.source as u64,"first_seen_ms":r.first_seen_ms,"last_seen_ms":r.last_seen_ms,"failures":r.failures,"retry_after_ms":r.retry_after_ms,"banned_until_ms":r.banned_until_ms,"advertised_noise_static_key":r.advertised_noise_static_key.map(|v|hex(&v)),"relay_static_public_key":r.relay_static_public_key.map(|v|hex(&v)),"relay_static_key_pinned":r.relay_static_key_pinned,"advertisement_expires_at_ms":r.advertisement_expires_at_ms,"advertisement_fingerprint":r.advertisement_fingerprint.map(|v|hex(&v)),"operator_approved_noise_static_key":r.operator_approved_noise_static_key.map(|v|hex(&v)),"operator_approved_at_ms":r.operator_approved_at_ms})).collect();
        json!({"magic":MAGIC,"version":VERSION,"network":hex(&self.network),"profile":hex(&self.profile),"trust_domain_registry_fingerprint":self.trust_domain_registry_fingerprint.map(|v|hex(&v)),"records":rows})
    }
    fn persist(&self) -> Result<(), PeerAddressBookError> {
        let payload = self.payload();
        let body = serde_json::to_vec(&payload).map_err(|_| PeerAddressBookError::Malformed)?;
        let mut h = Sha256::new();
        h.update(DOMAIN_V4);
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
            3 => DOMAIN_V3,
            4 => DOMAIN_V4,
            _ => return Err(PeerAddressBookError::Malformed),
        };
        let mut h = Sha256::new();
        h.update(domain);
        h.update(&body);
        if root.get("checksum").and_then(Value::as_str) != Some(hex(&h.finalize()).as_str()) {
            return Err(PeerAddressBookError::ChecksumMismatch);
        }
        if payload.get("magic").and_then(Value::as_str) != Some(MAGIC)
            || !matches!(version, 1 | 2 | 3 | 4)
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
                operator_approved_noise_static_key: if version >= 3 {
                    parse_optional_key(v.get("operator_approved_noise_static_key"))?
                } else {
                    None
                },
                operator_approved_at_ms: if version >= 3 {
                    s("operator_approved_at_ms")?
                } else {
                    0
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
            let approval_consistent = match (
                rec.operator_approved_noise_static_key,
                rec.operator_approved_at_ms,
            ) {
                (None, 0) => true,
                (Some(key), approved_at)
                    if approved_at > 0
                        && rec
                            .advertised_noise_static_key
                            .is_none_or(|advertised| advertised == key) =>
                {
                    true
                }
                _ => false,
            };
            if rec.last_seen_ms < rec.first_seen_ms
                || !metadata_consistent
                || !approval_consistent
                || loaded.insert(address, rec).is_some()
            {
                return Err(PeerAddressBookError::Malformed);
            }
        }
        let registry_fingerprint = if version >= 4 {
            parse_optional_key(Some(
                payload
                    .get("trust_domain_registry_fingerprint")
                    .ok_or(PeerAddressBookError::Malformed)?,
            ))?
        } else {
            None
        };
        self.records = loaded;
        self.trust_domain_registry_fingerprint = registry_fingerprint;
        if version < VERSION {
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
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let p = std::env::temp_dir().join(format!(
                "q6pa-{}-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                sequence
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
    fn migrates_v1_store_to_v4_without_losing_records() {
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
        assert_eq!(migrated["payload"]["version"].as_u64(), Some(4));
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
    fn exports_only_fresh_relay_bound_candidates_with_nonextended_ttl() {
        let t = Temp::new();
        let p = t.0.join("peers.q6pa");
        let policy = BootstrapTrustDomainPolicy::new([([9; 32], [10; 32])], 8, 1).unwrap();
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

        let mut book = QRunV06PeerAddressBookCandidate::open(&p, [1; 32], [2; 32]).unwrap();
        book.bind_trust_domain_registry(&policy, 100_000).unwrap();
        book.ingest_pinned_q6ar_with_trust_domains(&received, 100_000, &policy)
            .unwrap();
        book.upsert("1.1.1.1:8333", PeerAddressSource::Gossip, 100_000)
            .unwrap();

        let exported = book.current_gossip_advertisement(100_000, 32).unwrap();
        assert_eq!(exported.network_id, [1; 32]);
        assert_eq!(exported.profile_id, [2; 32]);
        assert_eq!(exported.issued_at_secs, 100);
        assert_eq!(exported.ttl_secs, 60);
        assert_eq!(exported.addresses.len(), 1);
        assert_eq!(
            exported.addresses[0].endpoint,
            "8.8.8.8:8333".parse().unwrap()
        );
        assert_eq!(exported.addresses[0].noise_static_public_key, [7; 32]);
        assert!(book.approved_peer_pins(100_001, 8).is_empty());

        // A fresh advertisement may be relayed, but its original expiry may not be extended.
        let near_expiry = book.current_gossip_advertisement(159_000, 32).unwrap();
        assert_eq!(near_expiry.ttl_secs, 1);
        assert_eq!(book.current_gossip_advertisement(160_000, 32), None);
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
    fn only_explicit_operator_approval_enters_bounded_outbound_peer_set() {
        let t = Temp::new();
        let p = t.0.join("peers.q6pa");
        let mut book = QRunV06PeerAddressBookCandidate::open(&p, [1; 32], [2; 32]).unwrap();
        book.upsert("8.8.8.8:8333", PeerAddressSource::Gossip, 10)
            .unwrap();
        book.upsert("1.1.1.1:8333", PeerAddressSource::Manual, 10)
            .unwrap();
        assert!(book.approved_peer_pins(20, 8).is_empty());
        book.pin_manual_peer("8.8.8.8:8333", [7; 32], 30).unwrap();
        assert_eq!(
            book.approved_peer_pins(31, 8),
            vec![("8.8.8.8:8333".parse().unwrap(), [7; 32])]
        );
        assert!(book.approved_peer_pins(31, 1).len() <= 1);
        book.revoke_operator_approval("8.8.8.8:8333").unwrap();
        assert!(book.approved_peer_pins(32, 8).is_empty());
    }

    #[test]
    fn approved_peer_inventory_is_not_truncated_before_domain_diversification() {
        let t = Temp::new();
        let p = t.0.join("peers.q6pa");
        let mut book = QRunV06PeerAddressBookCandidate::open(&p, [1; 32], [2; 32]).unwrap();

        for index in 1..=10u8 {
            let address = format!("198.51.100.{index}:8333");
            book.pin_manual_peer(&address, [index; 32], 10).unwrap();
        }

        assert_eq!(book.approved_peer_pins(11, MAX_PEERS).len(), 10);
        assert_eq!(book.approved_peer_pins(11, 4).len(), 4);
    }

    #[test]
    fn advertised_candidate_requires_exact_fresh_key_and_survives_operator_approval_restart() {
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
            book.ingest_pinned_q6ar(&received, 100_000).unwrap();
            assert_eq!(
                book.approve_advertised_candidate("8.8.8.8:8333", [8; 32], 110_000),
                Err(PeerAddressBookError::NotAnApprovedCandidate)
            );
            assert_eq!(
                book.approve_advertised_candidate("8.8.8.8:8333", [7; 32], 160_000),
                Err(PeerAddressBookError::NotAnApprovedCandidate)
            );
            book.approve_advertised_candidate("8.8.8.8:8333", [7; 32], 110_000)
                .unwrap();
            assert_eq!(
                book.approved_peer_pins(111_000, 1),
                vec![("8.8.8.8:8333".parse().unwrap(), [7; 32])]
            );
        }
        let book = QRunV06PeerAddressBookCandidate::open(&p, [1; 32], [2; 32]).unwrap();
        assert_eq!(
            book.approved_peer_pins(200_000, 1),
            vec![("8.8.8.8:8333".parse().unwrap(), [7; 32])]
        );
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

    #[test]
    fn one_pinned_relay_cannot_fill_the_candidate_book_across_repeated_advertisements() {
        let t = Temp::new();
        let p = t.0.join("peers.q6pa");
        let mut book = QRunV06PeerAddressBookCandidate::open(&p, [1; 32], [2; 32]).unwrap();
        let relay_key = [9; 32];
        let first = crate::qrun_v06_peer_address_relay_candidate::Q6arReceivedAdvertisement {
            advertisement: crate::qrun_v06_peer_address_relay_candidate::Q6arAdvertisement {
                network_id: [1; 32],
                profile_id: [2; 32],
                issued_at_secs: 1,
                ttl_secs: 60,
                addresses: (0..MAX_GOSSIP_PEERS_PER_RELAY)
                    .map(
                        |index| crate::qrun_v06_peer_address_relay_candidate::Q6arAddress {
                            endpoint: format!("8.8.8.{}:8333", index + 1).parse().unwrap(),
                            noise_static_public_key: [(index + 1) as u8; 32],
                        },
                    )
                    .collect(),
            },
            relay_origin: crate::qrun_v06_peer_address_relay_candidate::Q6arRelayOrigin {
                relay_static_public_key: relay_key,
                relay_static_key_pinned: true,
            },
        };

        assert_eq!(book.ingest_pinned_q6ar(&first, 2_000).unwrap(), 32);
        assert_eq!(book.records().count(), MAX_GOSSIP_PEERS_PER_RELAY);

        let second = crate::qrun_v06_peer_address_relay_candidate::Q6arReceivedAdvertisement {
            advertisement: crate::qrun_v06_peer_address_relay_candidate::Q6arAdvertisement {
                network_id: [1; 32],
                profile_id: [2; 32],
                issued_at_secs: 2,
                ttl_secs: 60,
                addresses: vec![crate::qrun_v06_peer_address_relay_candidate::Q6arAddress {
                    endpoint: "1.1.1.1:8333".parse().unwrap(),
                    noise_static_public_key: [42; 32],
                }],
            },
            relay_origin: crate::qrun_v06_peer_address_relay_candidate::Q6arRelayOrigin {
                relay_static_public_key: relay_key,
                relay_static_key_pinned: true,
            },
        };

        assert_eq!(
            book.ingest_pinned_q6ar(&second, 3_000),
            Err(PeerAddressBookError::RelayCapacity)
        );
        assert_eq!(book.records().count(), MAX_GOSSIP_PEERS_PER_RELAY);
        assert!(book.records.get("1.1.1.1:8333").is_none());
        assert!(book.approved_peer_pins(3_001, MAX_PEERS).is_empty());
    }

    #[test]
    fn multiple_pinned_relays_can_reach_but_not_exceed_global_candidate_capacity() {
        let t = Temp::new();
        let p = t.0.join("peers.q6pa");
        let mut book = QRunV06PeerAddressBookCandidate::open(&p, [1; 32], [2; 32]).unwrap();

        for relay_index in 0..(MAX_PEERS / MAX_GOSSIP_PEERS_PER_RELAY) {
            let relay_key = [(relay_index + 20) as u8; 32];
            let received =
                crate::qrun_v06_peer_address_relay_candidate::Q6arReceivedAdvertisement {
                    advertisement:
                        crate::qrun_v06_peer_address_relay_candidate::Q6arAdvertisement {
                            network_id: [1; 32],
                            profile_id: [2; 32],
                            issued_at_secs: relay_index as u64 + 1,
                            ttl_secs: 120,
                            addresses: (0..MAX_GOSSIP_PEERS_PER_RELAY)
                                .map(|index| {
                                    let mut peer_key = [0u8; 32];
                                    peer_key[..8].copy_from_slice(
                                        &((relay_index * MAX_GOSSIP_PEERS_PER_RELAY + index + 1)
                                            as u64)
                                            .to_be_bytes(),
                                    );
                                    crate::qrun_v06_peer_address_relay_candidate::Q6arAddress {
                                        endpoint: format!(
                                            "8.8.{}.{}:8333",
                                            relay_index + 1,
                                            index + 1
                                        )
                                        .parse()
                                        .unwrap(),
                                        noise_static_public_key: peer_key,
                                    }
                                })
                                .collect(),
                        },
                    relay_origin: crate::qrun_v06_peer_address_relay_candidate::Q6arRelayOrigin {
                        relay_static_public_key: relay_key,
                        relay_static_key_pinned: true,
                    },
                };
            assert_eq!(
                book.ingest_pinned_q6ar(&received, (relay_index as u64 + 2) * 1_000)
                    .unwrap(),
                MAX_GOSSIP_PEERS_PER_RELAY
            );
        }

        assert_eq!(book.records().count(), MAX_PEERS);
        assert!(book.approved_peer_pins(20_000, MAX_PEERS).is_empty());

        let ninth_relay = crate::qrun_v06_peer_address_relay_candidate::Q6arReceivedAdvertisement {
            advertisement: crate::qrun_v06_peer_address_relay_candidate::Q6arAdvertisement {
                network_id: [1; 32],
                profile_id: [2; 32],
                issued_at_secs: 20,
                ttl_secs: 120,
                addresses: vec![crate::qrun_v06_peer_address_relay_candidate::Q6arAddress {
                    endpoint: "1.0.0.1:8333".parse().unwrap(),
                    noise_static_public_key: [99; 32],
                }],
            },
            relay_origin: crate::qrun_v06_peer_address_relay_candidate::Q6arRelayOrigin {
                relay_static_public_key: [99; 32],
                relay_static_key_pinned: true,
            },
        };
        assert_eq!(
            book.ingest_pinned_q6ar(&ninth_relay, 21_000),
            Err(PeerAddressBookError::Capacity)
        );
        assert_eq!(book.records().count(), MAX_PEERS);
        assert!(book.records.get("1.0.0.1:8333").is_none());
    }

    #[test]
    fn expired_unapproved_gossip_is_reclaimed_before_candidate_capacity_rejects_new_peers() {
        let t = Temp::new();
        let p = t.0.join("peers.q6pa");
        let mut book = QRunV06PeerAddressBookCandidate::open(&p, [1; 32], [2; 32]).unwrap();

        for index in 0..MAX_PEERS {
            let address = format!("127.0.0.1:{}", 10_000 + index);
            book.upsert(&address, PeerAddressSource::Gossip, 100)
                .unwrap();
        }
        let stale = book.records.get_mut("127.0.0.1:10000").unwrap();
        stale.advertised_noise_static_key = Some([7; 32]);
        stale.relay_static_public_key = Some([9; 32]);
        stale.relay_static_key_pinned = true;
        stale.advertisement_expires_at_ms = 1_000;
        stale.advertisement_fingerprint = Some([8; 32]);

        let received = crate::qrun_v06_peer_address_relay_candidate::Q6arReceivedAdvertisement {
            advertisement: crate::qrun_v06_peer_address_relay_candidate::Q6arAdvertisement {
                network_id: [1; 32],
                profile_id: [2; 32],
                issued_at_secs: 1,
                ttl_secs: 10,
                addresses: vec![crate::qrun_v06_peer_address_relay_candidate::Q6arAddress {
                    endpoint: "8.8.8.8:8333".parse().unwrap(),
                    noise_static_public_key: [6; 32],
                }],
            },
            relay_origin: crate::qrun_v06_peer_address_relay_candidate::Q6arRelayOrigin {
                relay_static_public_key: [9; 32],
                relay_static_key_pinned: true,
            },
        };

        assert_eq!(book.records().count(), MAX_PEERS);
        assert_eq!(book.ingest_pinned_q6ar(&received, 2_000).unwrap(), 1);
        assert_eq!(book.records().count(), MAX_PEERS);
        assert!(book.records.get("127.0.0.1:10000").is_none());
        assert!(book.records.get("8.8.8.8:8333").is_some());
        assert!(book.approved_peer_pins(2_001, MAX_PEERS).is_empty());
    }

    #[test]
    fn sybil_candidate_flood_is_bounded_and_never_auto_trusted() {
        let t = Temp::new();
        let p = t.0.join("peers.q6pa");
        let mut book = QRunV06PeerAddressBookCandidate::open(&p, [1; 32], [2; 32]).unwrap();

        // Model an attacker advertising many independently-addressed candidate identities.
        for index in 0..MAX_PEERS {
            let address = format!("127.0.0.1:{}", 10_000 + index);
            book.upsert(&address, PeerAddressSource::Gossip, 100)
                .unwrap();
        }

        assert_eq!(book.records().count(), MAX_PEERS);
        assert_eq!(
            book.upsert("127.0.0.1:20000", PeerAddressSource::Gossip, 101),
            Err(PeerAddressBookError::Capacity)
        );
        assert!(book.approved_peer_pins(102, MAX_PEERS).is_empty());

        // Repeated advertisements for one endpoint must not create extra identities or trust.
        book.upsert("127.0.0.1:10000", PeerAddressSource::Gossip, 103)
            .unwrap();
        assert_eq!(book.records().count(), MAX_PEERS);
        assert!(book.approved_peer_pins(104, MAX_PEERS).is_empty());
    }

    fn trust_domain_policy(
        assignments: Vec<([u8; 32], [u8; 32])>,
        max_candidates: usize,
        max_relays: usize,
    ) -> BootstrapTrustDomainPolicy {
        BootstrapTrustDomainPolicy::new(assignments, max_candidates, max_relays).unwrap()
    }

    fn q6ar_received(
        relay_key: [u8; 32],
        issued_at_secs: u64,
        ttl_secs: u32,
        addresses: &[&str],
    ) -> crate::qrun_v06_peer_address_relay_candidate::Q6arReceivedAdvertisement {
        crate::qrun_v06_peer_address_relay_candidate::Q6arReceivedAdvertisement {
            advertisement: crate::qrun_v06_peer_address_relay_candidate::Q6arAdvertisement {
                network_id: [1; 32],
                profile_id: [2; 32],
                issued_at_secs,
                ttl_secs,
                addresses: addresses
                    .iter()
                    .enumerate()
                    .map(|(index, address)| {
                        crate::qrun_v06_peer_address_relay_candidate::Q6arAddress {
                            endpoint: address.parse().unwrap(),
                            noise_static_public_key: [(index + 1) as u8; 32],
                        }
                    })
                    .collect(),
            },
            relay_origin: crate::qrun_v06_peer_address_relay_candidate::Q6arRelayOrigin {
                relay_static_public_key: relay_key,
                relay_static_key_pinned: true,
            },
        }
    }

    #[test]
    fn trust_domain_registry_identity_persists_and_changed_policy_fails_closed() {
        let t = Temp::new();
        let p = t.0.join("peers.q6pa");
        let original = trust_domain_policy(vec![([9; 32], [10; 32])], 8, 2);
        {
            let mut book = QRunV06PeerAddressBookCandidate::open(&p, [1; 32], [2; 32]).unwrap();
            book.bind_trust_domain_registry(&original, 100_000).unwrap();
        }
        {
            let mut reopened = QRunV06PeerAddressBookCandidate::open(&p, [1; 32], [2; 32]).unwrap();
            reopened
                .bind_trust_domain_registry(&original, 101_000)
                .unwrap();
            let changed = trust_domain_policy(vec![([9; 32], [11; 32])], 8, 2);
            assert_eq!(
                reopened.bind_trust_domain_registry(&changed, 101_000),
                Err(PeerAddressBookError::TrustDomainRegistryMismatch)
            );
        }
    }

    #[test]
    fn explicit_registry_rotation_waits_for_live_candidates_then_persists_new_fingerprint() {
        let t = Temp::new();
        let p = t.0.join("peers.q6pa");
        let old_policy = trust_domain_policy(vec![([9; 32], [10; 32])], 8, 2);
        let new_policy = trust_domain_policy(vec![([8; 32], [11; 32])], 8, 2);

        {
            let mut book = QRunV06PeerAddressBookCandidate::open(&p, [1; 32], [2; 32]).unwrap();
            book.bind_trust_domain_registry(&old_policy, 99_000)
                .unwrap();
            let live = q6ar_received([9; 32], 100, 60, &["8.8.8.9:8333"]);
            book.ingest_pinned_q6ar_with_trust_domains(&live, 100_000, &old_policy)
                .unwrap();

            assert_eq!(
                book.rotate_trust_domain_registry(&new_policy, 120_000),
                Err(PeerAddressBookError::TrustDomainRotationBlockedByLiveCandidates)
            );
            assert_eq!(book.records().count(), 1);

            // Failed rotation must preserve the old binding and existing candidate.
            let still_old = q6ar_received([9; 32], 101, 60, &["8.8.8.8:8333"]);
            book.ingest_pinned_q6ar_with_trust_domains(&still_old, 101_000, &old_policy)
                .unwrap();
            assert_eq!(book.records().count(), 2);

            // Both old candidates have now expired; explicit rotation may reclaim them.
            book.rotate_trust_domain_registry(&new_policy, 161_000)
                .unwrap();
            assert_eq!(book.records().count(), 0);

            let new_candidate = q6ar_received([8; 32], 162, 60, &["1.1.1.1:8333"]);
            book.ingest_pinned_q6ar_with_trust_domains(&new_candidate, 162_000, &new_policy)
                .unwrap();
            assert_eq!(book.records().count(), 1);
        }

        let mut reopened = QRunV06PeerAddressBookCandidate::open(&p, [1; 32], [2; 32]).unwrap();
        reopened
            .bind_trust_domain_registry(&new_policy, 163_000)
            .unwrap();
        assert_eq!(reopened.records().count(), 1);
        assert!(reopened.records.contains_key("1.1.1.1:8333"));
        assert_eq!(
            reopened.bind_trust_domain_registry(&old_policy, 163_000),
            Err(PeerAddressBookError::TrustDomainRegistryMismatch)
        );
    }

    #[test]
    fn explicit_registry_rotation_requires_an_existing_binding() {
        let t = Temp::new();
        let p = t.0.join("peers.q6pa");
        let mut book = QRunV06PeerAddressBookCandidate::open(&p, [1; 32], [2; 32]).unwrap();
        let policy = trust_domain_policy(vec![([9; 32], [10; 32])], 8, 2);
        assert_eq!(
            book.rotate_trust_domain_registry(&policy, 100_000),
            Err(PeerAddressBookError::TrustDomainRotationNotBound)
        );
        assert_eq!(book.records().count(), 0);
    }

    #[test]
    fn legacy_q6ar_records_can_be_bound_only_when_every_relay_is_mapped() {
        let t = Temp::new();
        let p = t.0.join("peers.q6pa");
        {
            let mut book = QRunV06PeerAddressBookCandidate::open(&p, [1; 32], [2; 32]).unwrap();
            let legacy = q6ar_received([9; 32], 100, 60, &["8.8.8.9:8333"]);
            book.ingest_pinned_q6ar(&legacy, 100_000).unwrap();
        }
        let matching = trust_domain_policy(vec![([9; 32], [10; 32])], 8, 2);
        {
            let mut book = QRunV06PeerAddressBookCandidate::open(&p, [1; 32], [2; 32]).unwrap();
            book.bind_trust_domain_registry(&matching, 101_000).unwrap();
        }
        let missing_key = trust_domain_policy(vec![([8; 32], [10; 32])], 8, 2);
        let mut book = QRunV06PeerAddressBookCandidate::open(&p, [1; 32], [2; 32]).unwrap();
        assert_eq!(
            book.bind_trust_domain_registry(&missing_key, 102_000),
            Err(PeerAddressBookError::TrustDomainRegistryMismatch)
        );
    }

    #[test]
    fn trust_domain_candidate_budget_is_shared_across_pinned_relay_keys() {
        let t = Temp::new();
        let p = t.0.join("peers.q6pa");
        let mut book = QRunV06PeerAddressBookCandidate::open(&p, [1; 32], [2; 32]).unwrap();
        let policy = trust_domain_policy(vec![([9; 32], [10; 32]), ([8; 32], [10; 32])], 2, 2);
        book.bind_trust_domain_registry(&policy, 99_000).unwrap();

        let first = q6ar_received([9; 32], 100, 60, &["8.8.8.9:8333"]);
        let second = q6ar_received([8; 32], 101, 60, &["8.8.8.8:8333"]);
        let overflow = q6ar_received([9; 32], 102, 60, &["1.1.1.1:8333"]);

        assert_eq!(
            book.ingest_pinned_q6ar_with_trust_domains(&first, 100_000, &policy)
                .unwrap(),
            1
        );
        assert_eq!(
            book.ingest_pinned_q6ar_with_trust_domains(&second, 101_000, &policy)
                .unwrap(),
            1
        );
        assert_eq!(
            book.ingest_pinned_q6ar_with_trust_domains(&overflow, 102_000, &policy),
            Err(PeerAddressBookError::TrustDomain(
                TrustDomainPolicyError::DomainCandidateCapacity
            ))
        );
        assert_eq!(book.records().count(), 2);
        assert!(!book.records.contains_key("1.1.1.1:8333"));
    }

    #[test]
    fn trust_domain_batch_failure_rolls_back_all_changes_and_expiry_reclamation() {
        let t = Temp::new();
        let p = t.0.join("peers.q6pa");
        let mut book = QRunV06PeerAddressBookCandidate::open(&p, [1; 32], [2; 32]).unwrap();
        let policy = trust_domain_policy(vec![([9; 32], [10; 32])], 1, 1);
        book.bind_trust_domain_registry(&policy, 99_000).unwrap();

        let expiring = q6ar_received([9; 32], 100, 1, &["8.8.8.9:8333"]);
        book.ingest_pinned_q6ar(&expiring, 100_000).unwrap();
        assert_eq!(book.records().count(), 1);

        let batch = q6ar_received([9; 32], 101, 60, &["8.8.8.8:8333", "8.8.4.4:8333"]);
        assert_eq!(
            book.ingest_pinned_q6ar_with_trust_domains(&batch, 101_001, &policy),
            Err(PeerAddressBookError::TrustDomain(
                TrustDomainPolicyError::DomainCandidateCapacity
            ))
        );

        // The stale record and both new endpoints are unchanged by the rejected transaction.
        assert_eq!(book.records().count(), 1);
        assert!(book.records.contains_key("8.8.8.9:8333"));
        assert!(!book.records.contains_key("8.8.8.8:8333"));
        assert!(!book.records.contains_key("8.8.4.4:8333"));
        drop(book);

        let reopened = QRunV06PeerAddressBookCandidate::open(&p, [1; 32], [2; 32]).unwrap();
        assert_eq!(reopened.records().count(), 1);
        assert!(reopened.records.contains_key("8.8.8.9:8333"));
    }

    #[test]
    fn duplicate_advertisement_update_does_not_consume_another_domain_candidate_slot() {
        let t = Temp::new();
        let p = t.0.join("peers.q6pa");
        let mut book = QRunV06PeerAddressBookCandidate::open(&p, [1; 32], [2; 32]).unwrap();
        let policy = trust_domain_policy(vec![([9; 32], [10; 32])], 1, 1);
        book.bind_trust_domain_registry(&policy, 99_000).unwrap();

        let first = q6ar_received([9; 32], 100, 60, &["8.8.8.9:8333"]);
        let mut update = q6ar_received([9; 32], 101, 60, &["8.8.8.9:8333"]);
        update.advertisement.addresses[0].noise_static_public_key = [7; 32];

        book.ingest_pinned_q6ar_with_trust_domains(&first, 100_000, &policy)
            .unwrap();
        book.ingest_pinned_q6ar_with_trust_domains(&update, 101_000, &policy)
            .unwrap();

        assert_eq!(book.records().count(), 1);
        assert_eq!(
            book.records
                .get("8.8.8.9:8333")
                .unwrap()
                .advertised_noise_static_key,
            Some([7; 32])
        );
    }

    #[test]
    fn relay_key_rotation_shares_domain_budget_and_removed_old_keys_fail_closed() {
        let t = Temp::new();
        let p = t.0.join("peers.q6pa");
        let mut book = QRunV06PeerAddressBookCandidate::open(&p, [1; 32], [2; 32]).unwrap();
        let stable_registry =
            trust_domain_policy(vec![([9; 32], [10; 32]), ([8; 32], [10; 32])], 2, 2);
        book.bind_trust_domain_registry(&stable_registry, 99_000)
            .unwrap();

        let old_key = q6ar_received([9; 32], 100, 60, &["8.8.8.9:8333"]);
        let rotated_key = q6ar_received([8; 32], 101, 60, &["8.8.8.8:8333"]);
        book.ingest_pinned_q6ar_with_trust_domains(&old_key, 100_000, &stable_registry)
            .unwrap();
        book.ingest_pinned_q6ar_with_trust_domains(&rotated_key, 101_000, &stable_registry)
            .unwrap();
        assert_eq!(book.records().count(), 2);

        let registry_that_drops_old_key = trust_domain_policy(vec![([8; 32], [10; 32])], 2, 2);
        let next = q6ar_received([8; 32], 102, 60, &["1.1.1.1:8333"]);
        assert_eq!(
            book.ingest_pinned_q6ar_with_trust_domains(
                &next,
                102_000,
                &registry_that_drops_old_key
            ),
            Err(PeerAddressBookError::TrustDomainRegistryMismatch)
        );
        assert_eq!(book.records().count(), 2);
        assert!(!book.records.contains_key("1.1.1.1:8333"));
    }

    #[test]
    fn strict_trust_domain_ingestion_rejects_unattributable_legacy_gossip() {
        let t = Temp::new();
        let p = t.0.join("peers.q6pa");
        let mut book = QRunV06PeerAddressBookCandidate::open(&p, [1; 32], [2; 32]).unwrap();
        book.upsert("127.0.0.1:8333", PeerAddressSource::Gossip, 10)
            .unwrap();
        let policy = trust_domain_policy(vec![([9; 32], [10; 32])], 2, 2);
        let incoming = q6ar_received([9; 32], 100, 60, &["8.8.8.9:8333"]);

        assert_eq!(
            book.bind_trust_domain_registry(&policy, 100_000),
            Err(PeerAddressBookError::UnattributableCandidate)
        );
        assert_eq!(
            book.ingest_pinned_q6ar_with_trust_domains(&incoming, 100_000, &policy),
            Err(PeerAddressBookError::TrustDomainRegistryMismatch)
        );
        assert_eq!(book.records().count(), 1);
        assert!(book.records.contains_key("127.0.0.1:8333"));
        assert!(!book.records.contains_key("8.8.8.9:8333"));
    }
}
