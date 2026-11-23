//! Candidate/approved/Noise-key-verified peer state machine for QFP6.
//!
//! Discovery records are untrusted address hints. Only an exact operator-approved
//! endpoint/static-key pin can enter the bounded outbound dial queue. A peer reaches
//! NoiseKeyVerified only after a live QFP6 Noise session reports a pinned remote key
//! that exactly matches that endpoint's local approval and the same network/profile.
//!
//! This module tracks session metadata; the supervisor must call disconnect when the
//! corresponding stream/session is dropped. It deliberately does not create sockets,
//! run a DHT, or turn remote advertisements into trust. The current Noise profile is
//! classical X25519 and this state is not a post-quantum identity attestation.

use crate::{
    qrun_v06_noise_transport_candidate::QRunV06NoiseSession,
    qrun_v06_peer_address_manager_candidate::QRunV06PeerAddressBookCandidate,
};
use std::{collections::BTreeMap, net::SocketAddr};

pub const MAX_ACTIVE_VERIFIED_PEERS: usize = 8;
pub const MAX_OUTBOUND_DIALS_PER_ROUND: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QRunV06PeerTrustState {
    Unknown,
    /// An address/key hint exists, but no operator-approved key is attached to it.
    AnonymousCandidate,
    /// The operator approved an exact endpoint/static-key pair; no live verified session exists.
    OperatorApproved,
    /// An approved outbound dial is reserved but the Noise handshake is not yet accepted.
    DialPending,
    /// A live Noise session proved possession of the exact operator-pinned static key.
    /// This is transport-key verification, not a persistent human/operator identity claim.
    NoiseKeyVerified,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06PeerDialTarget {
    pub endpoint: SocketAddr,
    pub expected_noise_static_public_key: [u8; 32],
    /// Binds this reservation to one exact operator approval generation.
    pub operator_approved_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06VerifiedPeerSession {
    pub endpoint: SocketAddr,
    pub noise_static_public_key: [u8; 32],
    /// A revoke/re-approve cycle invalidates sessions created under an older approval.
    pub operator_approved_at_ms: u64,
    pub connected_at_ms: u64,
    pub last_authenticated_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QRunV06PeerConnectionManagerError {
    NetworkProfileMismatch,
    UnknownPeer,
    NotOperatorApproved,
    NotDialPending,
    UnpinnedNoiseSession,
    NoiseKeyMismatch,
    ActivePeerCapacity,
    DuplicateActiveNoiseKey,
    AlreadyConnected,
    PeerNotEligible,
}
impl std::fmt::Display for QRunV06PeerConnectionManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for QRunV06PeerConnectionManagerError {}

/// Ephemeral session registry and bounded dial scheduler.
/// The address book remains the durable source of candidates and operator approvals;
/// connected-session state is intentionally never persisted across process restart.
pub struct QRunV06PeerConnectionManagerCandidate {
    network_id: [u8; 32],
    profile_id: [u8; 32],
    dialing: BTreeMap<SocketAddr, ([u8; 32], u64)>,
    verified: BTreeMap<SocketAddr, QRunV06VerifiedPeerSession>,
    last_selected: Option<SocketAddr>,
}
impl QRunV06PeerConnectionManagerCandidate {
    pub fn new(address_book: &QRunV06PeerAddressBookCandidate) -> Self {
        Self {
            network_id: *address_book.network_id(),
            profile_id: *address_book.profile_id(),
            dialing: BTreeMap::new(),
            verified: BTreeMap::new(),
            last_selected: None,
        }
    }

    pub fn active_verified_count(&self) -> usize {
        self.verified.len()
    }

    pub fn pending_dial_count(&self) -> usize {
        self.dialing.len()
    }

    /// Return only sessions that still match the current, exact operator approval generation.
    pub fn verified_sessions<'a>(
        &'a self,
        address_book: &QRunV06PeerAddressBookCandidate,
    ) -> Vec<&'a QRunV06VerifiedPeerSession> {
        self.verified
            .values()
            .filter(|session| {
                let address = session.endpoint.to_string();
                address_book.records().any(|record| {
                    record.address == address
                        && record.operator_approved_noise_static_key
                            == Some(session.noise_static_public_key)
                        && record.operator_approved_at_ms == session.operator_approved_at_ms
                })
            })
            .collect()
    }

    /// Sessions whose operator pin was revoked or replaced. The supervisor should close
    /// their owning streams before treating them as disconnected.
    pub fn invalidated_verified_endpoints(
        &self,
        address_book: &QRunV06PeerAddressBookCandidate,
    ) -> Vec<SocketAddr> {
        self.verified
            .values()
            .filter_map(|session| {
                let address = session.endpoint.to_string();
                let still_approved = address_book.records().any(|record| {
                    record.address == address
                        && record.operator_approved_noise_static_key
                            == Some(session.noise_static_public_key)
                        && record.operator_approved_at_ms == session.operator_approved_at_ms
                });
                (!still_approved).then_some(session.endpoint)
            })
            .collect()
    }

    /// Return a trust class without promoting a candidate.
    pub fn trust_state(
        &self,
        address_book: &QRunV06PeerAddressBookCandidate,
        address: &str,
    ) -> QRunV06PeerTrustState {
        let Some(record) = address_book
            .records()
            .find(|record| record.address == address)
        else {
            return QRunV06PeerTrustState::Unknown;
        };
        let endpoint = match record.address.parse::<SocketAddr>() {
            Ok(endpoint) => endpoint,
            Err(_) => return QRunV06PeerTrustState::Unknown,
        };
        let Some(approved_key) = record.operator_approved_noise_static_key else {
            return QRunV06PeerTrustState::AnonymousCandidate;
        };
        if self.verified.get(&endpoint).is_some_and(|session| {
            session.noise_static_public_key == approved_key
                && session.operator_approved_at_ms == record.operator_approved_at_ms
        }) {
            return QRunV06PeerTrustState::NoiseKeyVerified;
        }
        if self
            .dialing
            .get(&endpoint)
            .is_some_and(|(key, approved_at)| {
                *key == approved_key && *approved_at == record.operator_approved_at_ms
            })
        {
            return QRunV06PeerTrustState::DialPending;
        }
        QRunV06PeerTrustState::OperatorApproved
    }

    /// Reserve one exact endpoint selected by the caller's already-validated bootstrap policy.
    /// This prevents the scheduler from substituting another approved peer outside the
    /// operator's current trust-domain ordering or attempt budget.
    pub fn reserve_operator_approved_endpoint(
        &mut self,
        address_book: &QRunV06PeerAddressBookCandidate,
        endpoint: SocketAddr,
        now_ms: u64,
    ) -> Result<QRunV06PeerDialTarget, QRunV06PeerConnectionManagerError> {
        if address_book.network_id() != &self.network_id
            || address_book.profile_id() != &self.profile_id
        {
            return Err(QRunV06PeerConnectionManagerError::NetworkProfileMismatch);
        }
        if self.verified.contains_key(&endpoint) || self.dialing.contains_key(&endpoint) {
            return Err(QRunV06PeerConnectionManagerError::AlreadyConnected);
        }
        if self.verified.len().saturating_add(self.dialing.len()) >= MAX_ACTIVE_VERIFIED_PEERS {
            return Err(QRunV06PeerConnectionManagerError::ActivePeerCapacity);
        }
        let address = endpoint.to_string();
        let record = address_book
            .records()
            .find(|record| record.address == address)
            .ok_or(QRunV06PeerConnectionManagerError::UnknownPeer)?;
        let expected_noise_static_public_key = record
            .operator_approved_noise_static_key
            .ok_or(QRunV06PeerConnectionManagerError::NotOperatorApproved)?;
        if record.operator_approved_at_ms == 0 || !address_book.is_eligible(&address, now_ms) {
            return Err(QRunV06PeerConnectionManagerError::PeerNotEligible);
        }
        if self
            .verified
            .values()
            .any(|peer| peer.noise_static_public_key == expected_noise_static_public_key)
        {
            return Err(QRunV06PeerConnectionManagerError::DuplicateActiveNoiseKey);
        }
        let target = QRunV06PeerDialTarget {
            endpoint,
            expected_noise_static_public_key,
            operator_approved_at_ms: record.operator_approved_at_ms,
        };
        self.dialing.insert(
            endpoint,
            (
                target.expected_noise_static_public_key,
                target.operator_approved_at_ms,
            ),
        );
        Ok(target)
    }

    /// Reserve a round-robin batch from operator-approved pins only.
    /// Q6AR candidates, DNS results, and relay-supplied keys are never dial targets here.
    /// Returned entries are reserved until complete_outbound_handshake or
    /// fail_outbound_attempt is called. The supervisor owns the actual sockets.
    pub fn reserve_outbound_batch(
        &mut self,
        address_book: &QRunV06PeerAddressBookCandidate,
        now_ms: u64,
        requested: usize,
    ) -> Result<Vec<QRunV06PeerDialTarget>, QRunV06PeerConnectionManagerError> {
        if address_book.network_id() != &self.network_id
            || address_book.profile_id() != &self.profile_id
        {
            return Err(QRunV06PeerConnectionManagerError::NetworkProfileMismatch);
        }
        let available_slots = MAX_ACTIVE_VERIFIED_PEERS
            .saturating_sub(self.verified.len().saturating_add(self.dialing.len()));
        let limit = requested
            .min(MAX_OUTBOUND_DIALS_PER_ROUND)
            .min(available_slots);
        if limit == 0 {
            return Ok(Vec::new());
        }

        let mut candidates: Vec<QRunV06PeerDialTarget> = address_book
            .records()
            .filter_map(|record| {
                let key = record.operator_approved_noise_static_key?;
                let approved_at_ms = record.operator_approved_at_ms;
                let endpoint = record.address.parse::<SocketAddr>().ok()?;
                if approved_at_ms == 0
                    || !address_book.is_eligible(&record.address, now_ms)
                    || self.verified.contains_key(&endpoint)
                    || self.dialing.contains_key(&endpoint)
                {
                    return None;
                }
                Some(QRunV06PeerDialTarget {
                    endpoint,
                    expected_noise_static_public_key: key,
                    operator_approved_at_ms: approved_at_ms,
                })
            })
            .collect();

        // BTreeMap-backed records are deterministic. Rotate after the last selection so
        // one lexicographically early endpoint cannot starve later approved peers.
        candidates.sort_by_key(|target| target.endpoint);
        if let Some(cursor) = self.last_selected {
            let split = candidates
                .iter()
                .position(|target| target.endpoint > cursor)
                .unwrap_or(0);
            candidates.rotate_left(split);
        }

        let selected: Vec<_> = candidates.into_iter().take(limit).collect();
        for target in &selected {
            self.dialing.insert(
                target.endpoint,
                (
                    target.expected_noise_static_public_key,
                    target.operator_approved_at_ms,
                ),
            );
        }
        if let Some(last) = selected.last() {
            self.last_selected = Some(last.endpoint);
        }
        Ok(selected)
    }

    /// Promote one reserved endpoint only after its Noise session proves the exact pin.
    /// The session's network/profile prologue must match the address book's network/profile.
    pub fn complete_outbound_handshake(
        &mut self,
        address_book: &mut QRunV06PeerAddressBookCandidate,
        endpoint: SocketAddr,
        session: &QRunV06NoiseSession,
        now_ms: u64,
    ) -> Result<(), QRunV06PeerConnectionManagerError> {
        let Some((expected_key, expected_approval_at_ms)) = self.dialing.get(&endpoint).copied()
        else {
            return Err(QRunV06PeerConnectionManagerError::NotDialPending);
        };
        let result = (|| {
            if address_book.network_id() != &self.network_id
                || address_book.profile_id() != &self.profile_id
                || session.network_id() != &self.network_id
                || session.profile_id() != &self.profile_id
            {
                return Err(QRunV06PeerConnectionManagerError::NetworkProfileMismatch);
            }
            if !session.remote_static_key_pinned() {
                return Err(QRunV06PeerConnectionManagerError::UnpinnedNoiseSession);
            }
            if session.remote_static_public_key() != &expected_key {
                return Err(QRunV06PeerConnectionManagerError::NoiseKeyMismatch);
            }
            if self.verified.contains_key(&endpoint) {
                return Err(QRunV06PeerConnectionManagerError::AlreadyConnected);
            }
            if self.verified.len() >= MAX_ACTIVE_VERIFIED_PEERS {
                return Err(QRunV06PeerConnectionManagerError::ActivePeerCapacity);
            }
            if self
                .verified
                .values()
                .any(|peer| peer.noise_static_public_key == expected_key)
            {
                return Err(QRunV06PeerConnectionManagerError::DuplicateActiveNoiseKey);
            }
            let address = endpoint.to_string();
            let approved = address_book
                .records()
                .find(|record| record.address == address)
                .map(|record| {
                    (
                        record.operator_approved_noise_static_key,
                        record.operator_approved_at_ms,
                    )
                });
            if approved != Some((Some(expected_key), expected_approval_at_ms)) {
                return Err(QRunV06PeerConnectionManagerError::NotOperatorApproved);
            }
            address_book
                .record_success(&address)
                .map_err(|_| QRunV06PeerConnectionManagerError::NotOperatorApproved)?;
            self.verified.insert(
                endpoint,
                QRunV06VerifiedPeerSession {
                    endpoint,
                    noise_static_public_key: expected_key,
                    operator_approved_at_ms: expected_approval_at_ms,
                    connected_at_ms: now_ms,
                    last_authenticated_at_ms: now_ms,
                },
            );
            Ok(())
        })();
        self.dialing.remove(&endpoint);
        result
    }

    /// Mark an outbound attempt failed and apply the address book's bounded exponential backoff.
    pub fn fail_outbound_attempt(
        &mut self,
        address_book: &mut QRunV06PeerAddressBookCandidate,
        endpoint: SocketAddr,
        now_ms: u64,
    ) -> Result<(), QRunV06PeerConnectionManagerError> {
        if self.dialing.remove(&endpoint).is_none() {
            return Err(QRunV06PeerConnectionManagerError::NotDialPending);
        }
        address_book
            .record_failure(&endpoint.to_string(), now_ms)
            .map_err(|_| QRunV06PeerConnectionManagerError::UnknownPeer)
    }

    /// Remove ephemeral verified-session state when its owning stream is closed.
    /// On an abnormal disconnect, apply the same bounded address backoff.
    pub fn mark_disconnected(
        &mut self,
        address_book: &mut QRunV06PeerAddressBookCandidate,
        endpoint: SocketAddr,
        now_ms: u64,
        abnormal: bool,
    ) -> Result<(), QRunV06PeerConnectionManagerError> {
        if self.verified.remove(&endpoint).is_none() {
            return Err(QRunV06PeerConnectionManagerError::UnknownPeer);
        }
        if abnormal {
            address_book
                .record_failure(&endpoint.to_string(), now_ms)
                .map_err(|_| QRunV06PeerConnectionManagerError::UnknownPeer)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qrun_v06_peer_address_manager_candidate::{
        PeerAddressSource, QRunV06PeerAddressBookCandidate,
    };
    use snow::{params::NoiseParams, Builder};
    use std::{
        net::{TcpListener, TcpStream},
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
        thread,
    };

    const NETWORK: [u8; 32] = [0x71; 32];
    const PROFILE: [u8; 32] = [0x72; 32];
    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "qfp6-peer-manager-{}-{sequence}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn keypair() -> ([u8; 32], [u8; 32]) {
        let params: NoiseParams = "Noise_XX_25519_ChaChaPoly_SHA256".parse().unwrap();
        let mut pair = Builder::new(params).generate_keypair().unwrap();
        let mut private = [0u8; 32];
        let mut public = [0u8; 32];
        private.copy_from_slice(&pair.private);
        public.copy_from_slice(&pair.public);
        pair.private.fill(0);
        pair.public.fill(0);
        (private, public)
    }

    fn pinned_client_session() -> (QRunV06NoiseSession, SocketAddr, [u8; 32]) {
        let (server_private, server_public) = keypair();
        let (client_private, client_public) = keypair();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            QRunV06NoiseSession::accept(
                &mut stream,
                &server_private,
                &[client_public],
                &NETWORK,
                &PROFILE,
            )
            .unwrap()
        });
        let mut stream = TcpStream::connect(endpoint).unwrap();
        let client_session = QRunV06NoiseSession::connect(
            &mut stream,
            &client_private,
            &server_public,
            &NETWORK,
            &PROFILE,
        )
        .unwrap();
        let _server_session = server.join().unwrap();
        assert!(client_session.remote_static_key_pinned());
        (client_session, endpoint, server_public)
    }

    #[test]
    fn exact_endpoint_reservation_never_substitutes_another_approved_peer() {
        let temp = Temp::new();
        let path = temp.0.join("peers.q6pa");
        let mut book = QRunV06PeerAddressBookCandidate::open(&path, NETWORK, PROFILE).unwrap();
        let first = "198.51.100.10:30336".parse::<SocketAddr>().unwrap();
        let selected = "198.51.100.11:30336".parse::<SocketAddr>().unwrap();
        let mut first_key = [0u8; 32];
        first_key[0] = 10;
        first_key[31] = 10;
        let mut selected_key = [0u8; 32];
        selected_key[0] = 11;
        selected_key[31] = 11;
        book.pin_manual_peer(&first.to_string(), first_key, 10)
            .unwrap();
        book.pin_manual_peer(&selected.to_string(), selected_key, 10)
            .unwrap();
        book.upsert("198.51.100.12:30336", PeerAddressSource::Gossip, 10)
            .unwrap();
        let mut manager = QRunV06PeerConnectionManagerCandidate::new(&book);

        let target = manager
            .reserve_operator_approved_endpoint(&book, selected, 11)
            .unwrap();
        assert_eq!(target.endpoint, selected);
        assert_eq!(target.expected_noise_static_public_key, selected_key);
        assert!(manager
            .reserve_operator_approved_endpoint(&book, "198.51.100.12:30336".parse().unwrap(), 11)
            .is_err());
        assert_eq!(manager.pending_dial_count(), 1);
        assert_eq!(first, "198.51.100.10:30336".parse().unwrap());
    }

    #[test]
    fn anonymous_candidates_never_enter_the_outbound_dial_queue() {
        let temp = Temp::new();
        let path = temp.0.join("peers.q6pa");
        let mut book = QRunV06PeerAddressBookCandidate::open(&path, NETWORK, PROFILE).unwrap();
        book.upsert("192.0.2.9:30336", PeerAddressSource::Gossip, 1)
            .unwrap();
        let mut manager = QRunV06PeerConnectionManagerCandidate::new(&book);

        assert_eq!(
            manager.trust_state(&book, "192.0.2.9:30336"),
            QRunV06PeerTrustState::AnonymousCandidate
        );
        assert!(manager
            .reserve_outbound_batch(&book, 2, 4)
            .unwrap()
            .is_empty());
        assert_eq!(manager.pending_dial_count(), 0);
        assert_eq!(manager.active_verified_count(), 0);
    }

    #[test]
    fn exact_pinned_noise_handshake_is_required_before_verified_state() {
        let temp = Temp::new();
        let path = temp.0.join("peers.q6pa");
        let (session, endpoint, server_public) = pinned_client_session();
        let mut book = QRunV06PeerAddressBookCandidate::open(&path, NETWORK, PROFILE).unwrap();
        book.pin_manual_peer(&endpoint.to_string(), server_public, 10)
            .unwrap();
        let mut manager = QRunV06PeerConnectionManagerCandidate::new(&book);

        let targets = manager.reserve_outbound_batch(&book, 11, 99).unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].endpoint, endpoint);
        assert_eq!(
            manager.trust_state(&book, &endpoint.to_string()),
            QRunV06PeerTrustState::DialPending
        );
        manager
            .complete_outbound_handshake(&mut book, endpoint, &session, 12)
            .unwrap();
        assert_eq!(
            manager.trust_state(&book, &endpoint.to_string()),
            QRunV06PeerTrustState::NoiseKeyVerified
        );
        assert_eq!(manager.active_verified_count(), 1);

        manager
            .mark_disconnected(&mut book, endpoint, 13, false)
            .unwrap();
        assert_eq!(
            manager.trust_state(&book, &endpoint.to_string()),
            QRunV06PeerTrustState::OperatorApproved
        );
        assert_eq!(manager.active_verified_count(), 0);
    }

    #[test]
    fn mismatched_noise_key_cannot_promote_an_operator_approved_endpoint() {
        let temp = Temp::new();
        let path = temp.0.join("peers.q6pa");
        let (session, endpoint, _server_public) = pinned_client_session();
        let mut book = QRunV06PeerAddressBookCandidate::open(&path, NETWORK, PROFILE).unwrap();
        let (_other_private, other_public) = keypair();
        book.pin_manual_peer(&endpoint.to_string(), other_public, 10)
            .unwrap();
        let mut manager = QRunV06PeerConnectionManagerCandidate::new(&book);
        assert_eq!(
            manager.reserve_outbound_batch(&book, 11, 1).unwrap().len(),
            1
        );

        assert_eq!(
            manager.complete_outbound_handshake(&mut book, endpoint, &session, 12),
            Err(QRunV06PeerConnectionManagerError::NoiseKeyMismatch)
        );
        assert_eq!(
            manager.trust_state(&book, &endpoint.to_string()),
            QRunV06PeerTrustState::OperatorApproved
        );
        assert_eq!(manager.active_verified_count(), 0);
        assert_eq!(manager.pending_dial_count(), 0);
    }

    #[test]
    fn outbound_budget_and_active_slots_are_hard_bounded() {
        let temp = Temp::new();
        let path = temp.0.join("peers.q6pa");
        let mut book = QRunV06PeerAddressBookCandidate::open(&path, NETWORK, PROFILE).unwrap();
        for index in 1..=12u8 {
            let address = format!("198.51.100.{index}:30336");
            let mut public = [0u8; 32];
            public[0] = index;
            public[31] = index;
            book.pin_manual_peer(&address, public, 10).unwrap();
        }
        let mut manager = QRunV06PeerConnectionManagerCandidate::new(&book);
        let first = manager.reserve_outbound_batch(&book, 11, 64).unwrap();
        assert_eq!(first.len(), MAX_OUTBOUND_DIALS_PER_ROUND);
        let second = manager.reserve_outbound_batch(&book, 12, 64).unwrap();
        assert_eq!(second.len(), MAX_OUTBOUND_DIALS_PER_ROUND);
        let third = manager.reserve_outbound_batch(&book, 13, 64).unwrap();
        assert!(third.is_empty());
        assert_eq!(manager.pending_dial_count(), MAX_ACTIVE_VERIFIED_PEERS);
        assert_eq!(
            first
                .iter()
                .map(|target| target.endpoint)
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            first.len()
        );
    }

    #[test]
    fn revoke_and_reapprove_same_key_invalidates_old_verified_session() {
        let temp = Temp::new();
        let path = temp.0.join("peers.q6pa");
        let (session, endpoint, server_public) = pinned_client_session();
        let address = endpoint.to_string();
        let mut book = QRunV06PeerAddressBookCandidate::open(&path, NETWORK, PROFILE).unwrap();
        book.pin_manual_peer(&address, server_public, 10).unwrap();
        let mut manager = QRunV06PeerConnectionManagerCandidate::new(&book);

        assert_eq!(
            manager.reserve_outbound_batch(&book, 11, 1).unwrap().len(),
            1
        );
        manager
            .complete_outbound_handshake(&mut book, endpoint, &session, 12)
            .unwrap();
        assert_eq!(manager.verified_sessions(&book).len(), 1);

        book.revoke_operator_approval(&address).unwrap();
        assert_eq!(
            manager.trust_state(&book, &address),
            QRunV06PeerTrustState::AnonymousCandidate
        );
        assert_eq!(
            manager.invalidated_verified_endpoints(&book),
            vec![endpoint]
        );

        book.pin_manual_peer(&address, server_public, 20).unwrap();
        assert_eq!(
            manager.trust_state(&book, &address),
            QRunV06PeerTrustState::OperatorApproved
        );
        assert!(manager.verified_sessions(&book).is_empty());
        assert_eq!(
            manager.invalidated_verified_endpoints(&book),
            vec![endpoint]
        );
    }

    #[test]
    fn approval_generation_change_invalidates_pending_dial_reservation() {
        let temp = Temp::new();
        let path = temp.0.join("peers.q6pa");
        let (session, endpoint, server_public) = pinned_client_session();
        let address = endpoint.to_string();
        let mut book = QRunV06PeerAddressBookCandidate::open(&path, NETWORK, PROFILE).unwrap();
        book.pin_manual_peer(&address, server_public, 10).unwrap();
        let mut manager = QRunV06PeerConnectionManagerCandidate::new(&book);

        assert_eq!(
            manager.reserve_outbound_batch(&book, 11, 1).unwrap().len(),
            1
        );
        // Same wall-clock value must still produce a new approval generation.
        book.pin_manual_peer(&address, server_public, 10).unwrap();
        assert!(
            book.records()
                .find(|record| record.address == address)
                .unwrap()
                .operator_approved_at_ms
                > 10
        );

        assert_eq!(
            manager.complete_outbound_handshake(&mut book, endpoint, &session, 13),
            Err(QRunV06PeerConnectionManagerError::NotOperatorApproved)
        );
        assert_eq!(manager.pending_dial_count(), 0);
        assert_eq!(manager.active_verified_count(), 0);
        assert_eq!(
            manager.trust_state(&book, &address),
            QRunV06PeerTrustState::OperatorApproved
        );
    }
}
