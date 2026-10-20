//! Authenticated reference-time policy and challenge-response verification.
//!
//! This verifies signed policy and time samples. CP-0026-K adds a bounded TCP adapter and
//! process-exclusive durable high-water state; deployment, authority operations, and a globally
//! deterministic consensus clock remain outside this research module. The policy-admin public
//! key is a local trust anchor supplied out of band.
use crate::chain_admission::{
    ReferenceTimeError, ReferenceTimeProvenance, ReferenceTimeProvider, ReferenceTimeSample,
};
use crate::reference_time_store::ReferenceTimeStateStore;
use ed25519_dalek::{Signature, VerifyingKey};
use getrandom::getrandom;
use sha2::{Digest, Sha256};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Mutex,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const POLICY_MAGIC: &[u8; 4] = b"RTP1";
pub const ATTESTATION_MAGIC: &[u8; 4] = b"TMA1";
pub const WIRE_VERSION: u16 = 1;
pub const POLICY_BODY_LEN: usize = 90;
pub const POLICY_WIRE_LEN: usize = POLICY_BODY_LEN + 64;
pub const ATTESTATION_BODY_LEN: usize = 86;
pub const ATTESTATION_WIRE_LEN: usize = ATTESTATION_BODY_LEN + 64;
pub const POLICY_DOMAIN: &[u8] = b"AIN1-REFERENCE-TIME-POLICY-V1\0";
pub const ATTESTATION_DOMAIN: &[u8] = b"AIN1-REFERENCE-TIME-ATTESTATION-V1\0";
pub const MAX_REFERENCE_TIME_RTT_MS: u32 = 5_000;
pub const MAX_LOCAL_CLOCK_SKEW_SECS: u64 = 86_400;
const NO_LOCAL_SKEW_LIMIT: u64 = u64::MAX;
const SOURCE_ID: &str = "ed25519-attested-time-v1";

/// Persist this high-water state next to operator configuration. A document with the same
/// sequence is accepted only if its digest is identical to the active signed document.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PolicyTrustState {
    highest_sequence: u64,
    active_digest: Option<[u8; 32]>,
}
impl PolicyTrustState {
    pub fn highest_sequence(&self) -> u64 {
        self.highest_sequence
    }

    /// Restore the rollback floor from protected operator state. Sequence zero is uninitialized.
    pub fn from_persisted(
        highest_sequence: u64,
        active_digest: Option<[u8; 32]>,
    ) -> Result<Self, ReferenceTimeError> {
        if (highest_sequence == 0) != active_digest.is_none() {
            return Err(ReferenceTimeError::PolicyMalformed);
        }
        Ok(Self {
            highest_sequence,
            active_digest,
        })
    }

    /// Advance, never lower, the policy trust floor.
    pub fn record(
        &mut self,
        policy: &VerifiedReferenceTimePolicy,
    ) -> Result<(), ReferenceTimeError> {
        if policy.sequence < self.highest_sequence
            || (policy.sequence == self.highest_sequence
                && self
                    .active_digest
                    .is_some_and(|digest| digest != policy.document_digest))
        {
            return Err(ReferenceTimeError::PolicyRollback);
        }
        if policy.sequence > self.highest_sequence {
            self.highest_sequence = policy.sequence;
            self.active_digest = Some(policy.document_digest);
        }
        Ok(())
    }
}

/// Constructible only by verifying canonical policy bytes with the pinned admin key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedReferenceTimePolicy {
    network_id: [u8; 32],
    sequence: u64,
    authority_public_key: [u8; 32],
    max_round_trip_ms: u32,
    max_local_clock_skew_secs: Option<u64>,
    document_digest: [u8; 32],
}
impl VerifiedReferenceTimePolicy {
    pub fn verify(
        bytes: &[u8],
        expected_network_id: &[u8; 32],
        trusted_policy_admin_public_key: &[u8; 32],
        trust_state: &PolicyTrustState,
    ) -> Result<Self, ReferenceTimeError> {
        if bytes.len() != POLICY_WIRE_LEN || &bytes[..4] != POLICY_MAGIC {
            return Err(ReferenceTimeError::PolicyMalformed);
        }
        if read_u16(&bytes[4..6]) != WIRE_VERSION {
            return Err(ReferenceTimeError::PolicyMalformed);
        }
        let network_id: [u8; 32] = bytes[6..38].try_into().unwrap();
        if &network_id != expected_network_id {
            return Err(ReferenceTimeError::PolicyNetworkMismatch);
        }
        let sequence = read_u64(&bytes[38..46]);
        let digest = sha256(bytes);
        if sequence == 0
            || sequence < trust_state.highest_sequence
            || (sequence == trust_state.highest_sequence
                && trust_state
                    .active_digest
                    .is_some_and(|current| digest != current))
        {
            return Err(ReferenceTimeError::PolicyRollback);
        }
        let authority_public_key: [u8; 32] = bytes[46..78].try_into().unwrap();
        let max_round_trip_ms = read_u32(&bytes[78..82]);
        let raw_skew = read_u64(&bytes[82..90]);
        let max_local_clock_skew_secs = (raw_skew != NO_LOCAL_SKEW_LIMIT).then_some(raw_skew);
        if network_id.iter().all(|b| *b == 0)
            || max_round_trip_ms == 0
            || max_round_trip_ms > MAX_REFERENCE_TIME_RTT_MS
            || max_local_clock_skew_secs.is_some_and(|v| v > MAX_LOCAL_CLOCK_SKEW_SECS)
        {
            return Err(ReferenceTimeError::PolicyMalformed);
        }
        let admin = VerifyingKey::from_bytes(trusted_policy_admin_public_key)
            .map_err(|_| ReferenceTimeError::PolicyMalformed)?;
        let authority = VerifyingKey::from_bytes(&authority_public_key)
            .map_err(|_| ReferenceTimeError::PolicyMalformed)?;
        if admin.is_weak() || authority.is_weak() {
            return Err(ReferenceTimeError::PolicyMalformed);
        }
        let signature = Signature::from_slice(&bytes[POLICY_BODY_LEN..])
            .map_err(|_| ReferenceTimeError::PolicyMalformed)?;
        admin
            .verify_strict(
                &domain_message(POLICY_DOMAIN, &bytes[..POLICY_BODY_LEN]),
                &signature,
            )
            .map_err(|_| ReferenceTimeError::PolicySignatureInvalid)?;
        Ok(Self {
            network_id,
            sequence,
            authority_public_key,
            max_round_trip_ms,
            max_local_clock_skew_secs,
            document_digest: digest,
        })
    }

    pub fn network_id(&self) -> &[u8; 32] {
        &self.network_id
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn authority_public_key(&self) -> &[u8; 32] {
        &self.authority_public_key
    }
    pub fn max_round_trip(&self) -> Duration {
        Duration::from_millis(u64::from(self.max_round_trip_ms))
    }
    pub fn max_local_clock_skew_secs(&self) -> Option<u64> {
        self.max_local_clock_skew_secs
    }
    pub fn digest(&self) -> &[u8; 32] {
        &self.document_digest
    }

    fn authenticate_response(
        &self,
        expected_challenge: &[u8; 32],
        bytes: &[u8],
    ) -> Result<AuthenticatedTimeResponse, ReferenceTimeError> {
        if bytes.len() != ATTESTATION_WIRE_LEN
            || &bytes[..4] != ATTESTATION_MAGIC
            || read_u16(&bytes[4..6]) != WIRE_VERSION
        {
            return Err(ReferenceTimeError::AttestationMalformed);
        }
        let network_id: [u8; 32] = bytes[6..38].try_into().unwrap();
        if network_id != self.network_id {
            return Err(ReferenceTimeError::PolicyNetworkMismatch);
        }
        let challenge: [u8; 32] = bytes[38..70].try_into().unwrap();
        if &challenge != expected_challenge {
            return Err(ReferenceTimeError::ChallengeMismatch);
        }
        let unix_seconds = read_u64(&bytes[70..78]);
        let sequence = read_u64(&bytes[78..86]);
        if sequence == 0 {
            return Err(ReferenceTimeError::SequenceRollback);
        }
        let authority = VerifyingKey::from_bytes(&self.authority_public_key)
            .map_err(|_| ReferenceTimeError::PolicyMalformed)?;
        let signature = Signature::from_slice(&bytes[ATTESTATION_BODY_LEN..])
            .map_err(|_| ReferenceTimeError::AttestationMalformed)?;
        authority
            .verify_strict(
                &domain_message(ATTESTATION_DOMAIN, &bytes[..ATTESTATION_BODY_LEN]),
                &signature,
            )
            .map_err(|_| ReferenceTimeError::AuthoritySignatureInvalid)?;
        Ok(AuthenticatedTimeResponse {
            unix_seconds,
            sequence,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AuthenticatedTimeResponse {
    unix_seconds: u64,
    sequence: u64,
}

/// A concrete transport must enforce its own I/O deadline and return within timeout.
/// The provider also measures elapsed time after return; this check cannot rescue a transport
/// implementation that blocks indefinitely instead of honoring its deadline.
pub trait ReferenceTimeExchange: Send + Sync {
    fn request(
        &self,
        network_id: &[u8; 32],
        challenge: &[u8; 32],
        timeout: Duration,
    ) -> Result<Vec<u8>, ReferenceTimeError>;
}

/// Authenticated provider with network binding, OS-random request challenge, strict signature
/// verification, round-trip timeout, optional local-clock sanity bound, and sequence monotonicity.
pub struct AuthenticatedReferenceTimeProvider<E> {
    policy: VerifiedReferenceTimePolicy,
    exchange: E,
    last_sequence: AtomicU64,
    state_store: Option<ReferenceTimeStateStore>,
    sample_lock: Mutex<()>,
}
impl<E: ReferenceTimeExchange> AuthenticatedReferenceTimeProvider<E> {
    pub fn new(
        policy: VerifiedReferenceTimePolicy,
        exchange: E,
        last_accepted_sequence: u64,
    ) -> Result<Self, ReferenceTimeError> {
        if last_accepted_sequence == u64::MAX {
            return Err(ReferenceTimeError::SequenceRollback);
        }
        Ok(Self {
            policy,
            exchange,
            last_sequence: AtomicU64::new(last_accepted_sequence),
            state_store: None,
            sample_lock: Mutex::new(()),
        })
    }

    /// Construct a provider whose policy rollback floor and authenticated authority sequence
    /// are persisted atomically and locked across OS processes. The sequence high-water is
    /// shared across authority-key rotations for this network.
    pub fn new_persistent(
        policy: VerifiedReferenceTimePolicy,
        exchange: E,
        state_store: ReferenceTimeStateStore,
    ) -> Result<Self, ReferenceTimeError> {
        state_store.record_policy(&policy)?;
        let last_accepted_sequence = state_store.last_accepted_sequence()?;
        if last_accepted_sequence == u64::MAX {
            return Err(ReferenceTimeError::SequenceRollback);
        }
        Ok(Self {
            policy,
            exchange,
            last_sequence: AtomicU64::new(last_accepted_sequence),
            state_store: Some(state_store),
            sample_lock: Mutex::new(()),
        })
    }
    pub fn last_accepted_sequence(&self) -> u64 {
        self.last_sequence.load(Ordering::Acquire)
    }

    fn accept_sequence(&self, sequence: u64) -> Result<(), ReferenceTimeError> {
        let mut current = self.last_sequence.load(Ordering::Acquire);
        loop {
            if sequence <= current {
                return Err(ReferenceTimeError::SequenceRollback);
            }
            match self.last_sequence.compare_exchange(
                current,
                sequence,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(observed) => current = observed,
            }
        }
    }

    fn validate_local_skew(&self, timestamp: u64) -> Result<(), ReferenceTimeError> {
        let Some(max_skew) = self.policy.max_local_clock_skew_secs else {
            return Ok(());
        };
        let local = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ReferenceTimeError::ClockBeforeUnixEpoch)?
            .as_secs();
        if local.abs_diff(timestamp) > max_skew {
            return Err(ReferenceTimeError::ClockSkewExceeded);
        }
        Ok(())
    }
}
impl<E: ReferenceTimeExchange> ReferenceTimeProvider for AuthenticatedReferenceTimeProvider<E> {
    fn sample(&self) -> Result<ReferenceTimeSample, ReferenceTimeError> {
        // Serialize request/verification/commit as one unit. Without this lock two valid
        // concurrent responses could persist sequence 43 before returning a sample for 42.
        let _sample_guard = self
            .sample_lock
            .lock()
            .map_err(|_| ReferenceTimeError::StatePersistence)?;
        let mut challenge = [0u8; 32];
        getrandom(&mut challenge).map_err(|_| ReferenceTimeError::ProviderUnavailable)?;
        let timeout = self.policy.max_round_trip();
        let started = Instant::now();
        let bytes = self
            .exchange
            .request(self.policy.network_id(), &challenge, timeout)?;
        if started.elapsed() > timeout {
            return Err(ReferenceTimeError::StaleResponse);
        }
        let response = self.policy.authenticate_response(&challenge, &bytes)?;
        // Once authenticated, durably consume the sequence even if the independent skew guard
        // fails. This closes the restart/replay gap in the in-memory-only CP-J implementation.
        if let Some(store) = &self.state_store {
            store.advance_authority_sequence(response.sequence)?;
        }
        self.accept_sequence(response.sequence)?;
        self.validate_local_skew(response.unix_seconds)?;
        Ok(ReferenceTimeSample {
            unix_seconds: response.unix_seconds,
            provenance: ReferenceTimeProvenance::ConfiguredProvider,
            source_id: SOURCE_ID,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedReferenceTimeResponse {
    pub network_id: [u8; 32],
    pub challenge: [u8; 32],
    pub unix_seconds: u64,
    pub sequence: u64,
    pub signature: [u8; 64],
}
impl SignedReferenceTimeResponse {
    pub fn decode(bytes: &[u8]) -> Result<Self, ReferenceTimeError> {
        if bytes.len() != ATTESTATION_WIRE_LEN
            || &bytes[..4] != ATTESTATION_MAGIC
            || read_u16(&bytes[4..6]) != WIRE_VERSION
        {
            return Err(ReferenceTimeError::AttestationMalformed);
        }
        Ok(Self {
            network_id: bytes[6..38].try_into().unwrap(),
            challenge: bytes[38..70].try_into().unwrap(),
            unix_seconds: read_u64(&bytes[70..78]),
            sequence: read_u64(&bytes[78..86]),
            signature: bytes[ATTESTATION_BODY_LEN..].try_into().unwrap(),
        })
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ATTESTATION_WIRE_LEN);
        out.extend_from_slice(ATTESTATION_MAGIC);
        out.extend_from_slice(&WIRE_VERSION.to_be_bytes());
        out.extend_from_slice(&self.network_id);
        out.extend_from_slice(&self.challenge);
        out.extend_from_slice(&self.unix_seconds.to_be_bytes());
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.signature);
        out
    }
}

fn read_u16(b: &[u8]) -> u16 {
    u16::from_be_bytes(b.try_into().unwrap())
}
fn read_u32(b: &[u8]) -> u32 {
    u32::from_be_bytes(b.try_into().unwrap())
}
fn read_u64(b: &[u8]) -> u64 {
    u64::from_be_bytes(b.try_into().unwrap())
}
fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}
fn domain_message(domain: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(domain.len() + body.len());
    out.extend_from_slice(domain);
    out.extend_from_slice(body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::thread;

    const NETWORK: [u8; 32] = [0xA5; 32];
    const ADMIN_SEED: [u8; 32] = [0x42; 32];
    const AUTHORITY_SEED: [u8; 32] = [0x24; 32];

    fn key(seed: [u8; 32]) -> SigningKey {
        SigningKey::from_bytes(&seed)
    }

    fn signed_policy(
        admin: &SigningKey,
        authority: [u8; 32],
        network: [u8; 32],
        sequence: u64,
        rtt_ms: u32,
        skew: Option<u64>,
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(POLICY_MAGIC);
        body.extend_from_slice(&WIRE_VERSION.to_be_bytes());
        body.extend_from_slice(&network);
        body.extend_from_slice(&sequence.to_be_bytes());
        body.extend_from_slice(&authority);
        body.extend_from_slice(&rtt_ms.to_be_bytes());
        body.extend_from_slice(&skew.unwrap_or(NO_LOCAL_SKEW_LIMIT).to_be_bytes());
        assert_eq!(body.len(), POLICY_BODY_LEN);
        body.extend_from_slice(&admin.sign(&domain_message(POLICY_DOMAIN, &body)).to_bytes());
        body
    }

    fn signed_response(
        authority: &SigningKey,
        network: [u8; 32],
        challenge: [u8; 32],
        timestamp: u64,
        sequence: u64,
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(ATTESTATION_MAGIC);
        body.extend_from_slice(&WIRE_VERSION.to_be_bytes());
        body.extend_from_slice(&network);
        body.extend_from_slice(&challenge);
        body.extend_from_slice(&timestamp.to_be_bytes());
        body.extend_from_slice(&sequence.to_be_bytes());
        assert_eq!(body.len(), ATTESTATION_BODY_LEN);
        body.extend_from_slice(
            &authority
                .sign(&domain_message(ATTESTATION_DOMAIN, &body))
                .to_bytes(),
        );
        body
    }

    fn policy(skew: Option<u64>) -> VerifiedReferenceTimePolicy {
        let admin = key(ADMIN_SEED);
        let authority = key(AUTHORITY_SEED);
        let bytes = signed_policy(
            &admin,
            authority.verifying_key().to_bytes(),
            NETWORK,
            1,
            500,
            skew,
        );
        VerifiedReferenceTimePolicy::verify(
            &bytes,
            &NETWORK,
            &admin.verifying_key().to_bytes(),
            &PolicyTrustState::default(),
        )
        .unwrap()
    }

    struct MockExchange {
        authority: SigningKey,
        network: [u8; 32],
        sequences: Mutex<VecDeque<u64>>,
        timestamp: u64,
        bad_challenge: bool,
        corrupt_signature: bool,
        delay: Duration,
    }
    impl MockExchange {
        fn new(timestamp: u64, sequences: &[u64]) -> Self {
            Self {
                authority: key(AUTHORITY_SEED),
                network: NETWORK,
                sequences: Mutex::new(sequences.iter().copied().collect()),
                timestamp,
                bad_challenge: false,
                corrupt_signature: false,
                delay: Duration::ZERO,
            }
        }
    }
    impl ReferenceTimeExchange for MockExchange {
        fn request(
            &self,
            _: &[u8; 32],
            challenge: &[u8; 32],
            _: Duration,
        ) -> Result<Vec<u8>, ReferenceTimeError> {
            if !self.delay.is_zero() {
                thread::sleep(self.delay);
            }
            let seq = self
                .sequences
                .lock()
                .unwrap()
                .pop_front()
                .ok_or(ReferenceTimeError::ProviderUnavailable)?;
            let nonce = if self.bad_challenge {
                [0x77; 32]
            } else {
                *challenge
            };
            let mut bytes =
                signed_response(&self.authority, self.network, nonce, self.timestamp, seq);
            if self.corrupt_signature {
                let n = bytes.len() - 1;
                bytes[n] ^= 1;
            }
            Ok(bytes)
        }
    }

    #[test]
    fn shared_policy_and_attestation_vectors_match() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../simulations/cp0026j_reference_time_vectors.txt");
        let text = std::fs::read_to_string(path).expect("read CP-0026-J vector");
        let fields: std::collections::BTreeMap<String, String> = text
            .lines()
            .take_while(|line| *line != "END")
            .filter(|line| line.contains('='))
            .map(|line| {
                let (k, v) = line.split_once('=').unwrap();
                (k.to_string(), v.to_string())
            })
            .collect();
        assert_eq!(text.lines().next(), Some("CP0026J_REFERENCE_TIME_V1"));
        let hx = |name: &str| -> Vec<u8> {
            let s = &fields[name];
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        };
        let network: [u8; 32] = hx("NETWORK_ID").try_into().unwrap();
        let admin: [u8; 32] = hx("ADMIN_PUBLIC_KEY").try_into().unwrap();
        let authority: [u8; 32] = hx("TIME_AUTHORITY_PUBLIC_KEY").try_into().unwrap();
        let policy_wire = hx("POLICY_WIRE");
        let response_wire = hx("ATTESTATION_WIRE");
        assert_eq!(network, NETWORK);
        assert_eq!(authority, key(AUTHORITY_SEED).verifying_key().to_bytes());
        let policy = VerifiedReferenceTimePolicy::verify(
            &policy_wire,
            &network,
            &admin,
            &PolicyTrustState::default(),
        )
        .unwrap();
        assert_eq!(policy.sequence(), 7);
        assert_eq!(policy.max_round_trip(), Duration::from_millis(750));
        assert_eq!(policy.max_local_clock_skew_secs(), Some(300));
        let challenge: [u8; 32] = hx("CHALLENGE").try_into().unwrap();
        let response = policy
            .authenticate_response(&challenge, &response_wire)
            .unwrap();
        assert_eq!(response.unix_seconds, 1_800_000_123);
        assert_eq!(response.sequence, 42);
        assert_eq!(sha256(&policy_wire).to_vec(), hx("POLICY_SHA256"));
        assert_eq!(sha256(&response_wire).to_vec(), hx("ATTESTATION_SHA256"));
    }

    #[test]
    fn operator_policy_checks_admin_signature_network_bounds_and_rollback() {
        let admin = key(ADMIN_SEED);
        let authority = key(AUTHORITY_SEED);
        let valid = signed_policy(
            &admin,
            authority.verifying_key().to_bytes(),
            NETWORK,
            4,
            500,
            None,
        );
        let verified = VerifiedReferenceTimePolicy::verify(
            &valid,
            &NETWORK,
            &admin.verifying_key().to_bytes(),
            &PolicyTrustState::default(),
        )
        .unwrap();
        let mut trust = PolicyTrustState::default();
        trust.record(&verified).unwrap();
        assert_eq!(trust.record(&verified), Ok(()));
        let restored =
            PolicyTrustState::from_persisted(trust.highest_sequence(), Some(*verified.digest()))
                .unwrap();
        assert_eq!(restored.highest_sequence(), 4);
        assert_eq!(
            VerifiedReferenceTimePolicy::verify(
                &valid,
                &NETWORK,
                &admin.verifying_key().to_bytes(),
                &trust
            ),
            Ok(verified.clone())
        );
        let old = signed_policy(
            &admin,
            authority.verifying_key().to_bytes(),
            NETWORK,
            3,
            500,
            None,
        );
        assert_eq!(
            VerifiedReferenceTimePolicy::verify(
                &old,
                &NETWORK,
                &admin.verifying_key().to_bytes(),
                &trust
            ),
            Err(ReferenceTimeError::PolicyRollback)
        );
        let same_sequence_altered = signed_policy(
            &admin,
            authority.verifying_key().to_bytes(),
            NETWORK,
            4,
            400,
            None,
        );
        assert_eq!(
            VerifiedReferenceTimePolicy::verify(
                &same_sequence_altered,
                &NETWORK,
                &admin.verifying_key().to_bytes(),
                &trust
            ),
            Err(ReferenceTimeError::PolicyRollback)
        );
        let mut damaged = valid.clone();
        damaged[50] ^= 1;
        assert_eq!(
            VerifiedReferenceTimePolicy::verify(
                &damaged,
                &NETWORK,
                &admin.verifying_key().to_bytes(),
                &PolicyTrustState::default()
            ),
            Err(ReferenceTimeError::PolicySignatureInvalid)
        );
        assert_eq!(
            VerifiedReferenceTimePolicy::verify(
                &valid,
                &[0x88; 32],
                &admin.verifying_key().to_bytes(),
                &PolicyTrustState::default()
            ),
            Err(ReferenceTimeError::PolicyNetworkMismatch)
        );
        let bounds = signed_policy(
            &admin,
            authority.verifying_key().to_bytes(),
            NETWORK,
            5,
            MAX_REFERENCE_TIME_RTT_MS + 1,
            Some(1),
        );
        assert_eq!(
            VerifiedReferenceTimePolicy::verify(
                &bounds,
                &NETWORK,
                &admin.verifying_key().to_bytes(),
                &PolicyTrustState::default()
            ),
            Err(ReferenceTimeError::PolicyMalformed)
        );
        assert_eq!(
            VerifiedReferenceTimePolicy::verify(
                &valid[..valid.len() - 1],
                &NETWORK,
                &admin.verifying_key().to_bytes(),
                &PolicyTrustState::default()
            ),
            Err(ReferenceTimeError::PolicyMalformed)
        );
    }

    #[test]
    fn provider_accepts_signed_fresh_challenge_bound_sample() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let provider = AuthenticatedReferenceTimeProvider::new(
            policy(Some(300)),
            MockExchange::new(now, &[1]),
            0,
        )
        .unwrap();
        let sample = provider.sample().unwrap();
        assert_eq!(
            sample.provenance,
            ReferenceTimeProvenance::ConfiguredProvider
        );
        assert_eq!(sample.source_id, SOURCE_ID);
        assert_eq!(sample.unix_seconds, now);
        assert_eq!(provider.last_accepted_sequence(), 1);
    }

    #[test]
    fn provider_rejects_bad_signature_wrong_challenge_and_network() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut bad_sig = MockExchange::new(now, &[1]);
        bad_sig.corrupt_signature = true;
        let provider = AuthenticatedReferenceTimeProvider::new(policy(None), bad_sig, 0).unwrap();
        assert_eq!(
            provider.sample(),
            Err(ReferenceTimeError::AuthoritySignatureInvalid)
        );
        let mut bad_nonce = MockExchange::new(now, &[1]);
        bad_nonce.bad_challenge = true;
        let provider = AuthenticatedReferenceTimeProvider::new(policy(None), bad_nonce, 0).unwrap();
        assert_eq!(
            provider.sample(),
            Err(ReferenceTimeError::ChallengeMismatch)
        );
        let mut wrong_network = MockExchange::new(now, &[1]);
        wrong_network.network = [0x99; 32];
        let provider =
            AuthenticatedReferenceTimeProvider::new(policy(None), wrong_network, 0).unwrap();
        assert_eq!(
            provider.sample(),
            Err(ReferenceTimeError::PolicyNetworkMismatch)
        );
    }

    #[test]
    fn provider_rejects_slow_stale_and_sequence_rollback() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let admin = key(ADMIN_SEED);
        let authority = key(AUTHORITY_SEED);
        let bytes = signed_policy(
            &admin,
            authority.verifying_key().to_bytes(),
            NETWORK,
            1,
            1,
            None,
        );
        let short_policy = VerifiedReferenceTimePolicy::verify(
            &bytes,
            &NETWORK,
            &admin.verifying_key().to_bytes(),
            &PolicyTrustState::default(),
        )
        .unwrap();
        let mut slow = MockExchange::new(now, &[1]);
        slow.delay = Duration::from_millis(8);
        let provider = AuthenticatedReferenceTimeProvider::new(short_policy, slow, 0).unwrap();
        assert_eq!(provider.sample(), Err(ReferenceTimeError::StaleResponse));
        let provider = AuthenticatedReferenceTimeProvider::new(
            policy(None),
            MockExchange::new(now, &[3, 2]),
            0,
        )
        .unwrap();
        assert!(provider.sample().is_ok());
        assert_eq!(provider.sample(), Err(ReferenceTimeError::SequenceRollback));
        assert_eq!(provider.last_accepted_sequence(), 3);
    }

    #[test]
    fn provider_fails_closed_on_skew_and_unavailable_source() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let provider = AuthenticatedReferenceTimeProvider::new(
            policy(Some(1)),
            MockExchange::new(now.saturating_sub(100), &[1]),
            0,
        )
        .unwrap();
        assert_eq!(
            provider.sample(),
            Err(ReferenceTimeError::ClockSkewExceeded)
        );
        assert_eq!(provider.last_accepted_sequence(), 1);
        struct Offline;
        impl ReferenceTimeExchange for Offline {
            fn request(
                &self,
                _: &[u8; 32],
                _: &[u8; 32],
                _: Duration,
            ) -> Result<Vec<u8>, ReferenceTimeError> {
                Err(ReferenceTimeError::ProviderUnavailable)
            }
        }
        let provider = AuthenticatedReferenceTimeProvider::new(policy(None), Offline, 0).unwrap();
        assert_eq!(
            provider.sample(),
            Err(ReferenceTimeError::ProviderUnavailable)
        );
        assert_eq!(provider.last_accepted_sequence(), 0);
    }

    #[test]
    fn durable_sequence_is_consumed_before_skew_rejection_and_survives_restart() {
        let path = std::env::temp_dir().join(format!(
            "ain1-cp0026k-skew-{}-{}.bin",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        {
            let store = ReferenceTimeStateStore::open(&path, &NETWORK).unwrap();
            let provider = AuthenticatedReferenceTimeProvider::new_persistent(
                policy(Some(1)),
                MockExchange::new(now.saturating_sub(100), &[77]),
                store,
            )
            .unwrap();
            assert_eq!(
                provider.sample(),
                Err(ReferenceTimeError::ClockSkewExceeded)
            );
            assert_eq!(provider.last_accepted_sequence(), 77);
        }
        {
            let store = ReferenceTimeStateStore::open(&path, &NETWORK).unwrap();
            assert_eq!(store.last_accepted_sequence().unwrap(), 77);
            let provider = AuthenticatedReferenceTimeProvider::new_persistent(
                policy(Some(1)),
                MockExchange::new(now, &[77]),
                store,
            )
            .unwrap();
            assert_eq!(provider.sample(), Err(ReferenceTimeError::SequenceRollback));
        }
        let _ = std::fs::remove_file(&path);
        let lock_path = path.with_file_name(format!(
            "{}.writer.lock",
            path.file_name().unwrap().to_string_lossy()
        ));
        let _ = std::fs::remove_file(lock_path);
    }
}
