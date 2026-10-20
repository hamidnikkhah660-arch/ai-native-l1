//! CP-0226 isolated signed-FAT1 validator and anti-rollback trust-floor contract.
//!
//! The 248-byte FAT1 record is public/canonical data, not proof of authenticity. FAS1
//! wraps it with an externally pinned authority's Ed25519 + ML-DSA-65 signatures and
//! a predecessor-record link. Ed25519 is verified here; ML-DSA verification is injected
//! and MUST be supplied by a separately pinned, reviewed production implementation.
//! This module has no persistent anchor provider and no migration/consensus callsite.
use ed25519_dalek::{Signature as EdSignature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fmt;

pub const FAT1_BYTES: usize = 248;
pub const FAT1_VERSION: u16 = 1;
pub const FAS1_VERSION: u16 = 1;
pub const FAS1_AUTH_SUITE_HYBRID_V4: u16 = 4;
pub const FAS1_BYTES: usize = 3_697;
pub const ED25519_PUBLIC_KEY_BYTES: usize = 32;
pub const ED25519_SIGNATURE_BYTES: usize = 64;
pub const ML_DSA_65_PUBLIC_KEY_BYTES: usize = 1_952;
pub const ML_DSA_65_SIGNATURE_BYTES: usize = 3_309;
const FAS1_MAGIC: &[u8; 4] = b"FAS1";
const FAT1_MAGIC: &[u8; 4] = b"FAT1";
const RECORD_ID_DOMAIN: &[u8] = b"AIN1-FORK-ACTIVATION-TRUST-RECORD-ID-V1\0";
const ENVELOPE_ID_DOMAIN: &[u8] = b"AIN1-FAS1-ENVELOPE-ID-V1\0";
const AUTHORITY_KEYSET_DOMAIN: &[u8] = b"AIN1-FAT1-AUTHORITY-KEYSET-V1\0";
const SIGNING_DOMAIN: &[u8] = b"AIN1-FAT1-TRUST-SIGN-V1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fat1Error {
    WrongRecordLength,
    WrongEnvelopeLength,
    WrongMagic,
    UnsupportedVersion,
    UnsupportedSuite,
    WrongPayloadLength,
    NonzeroReserved,
    ZeroField(&'static str),
    EpochZero,
    HeightZero,
    AlgorithmZero,
    PolicyContextMismatch(&'static str),
    WrongAuthorityKeyset,
    InvalidEd25519PublicKey,
    InvalidEd25519Signature,
    InvalidMlDsa65Signature,
    TrustFloorNetworkMismatch,
    Rollback,
    SameEpochConflict,
    EpochGap,
    PredecessorMismatch,
    EpochOverflow,
    FloorCasConflict,
    FloorUnavailable,
}
impl fmt::Display for Fat1Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Fat1Error {}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| *b == 0)
}
fn hash_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for part in parts {
        h.update(part);
    }
    h.finalize().into()
}
fn take<const N: usize>(bytes: &[u8], start: usize) -> [u8; N] {
    bytes[start..start + N].try_into().expect("length checked")
}
fn u16_at(bytes: &[u8], start: usize) -> u16 {
    u16::from_be_bytes(take(bytes, start))
}
fn u64_at(bytes: &[u8], start: usize) -> u64 {
    u64::from_be_bytes(take(bytes, start))
}
fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fat1Record {
    pub trust_epoch: u64,
    pub network_id: [u8; 32],
    pub manifest_id: [u8; 32],
    pub migration_plan_id: [u8; 32],
    pub activation_height: u64,
    pub parent_block_id: [u8; 32],
    pub pre_stv3_root: [u8; 32],
    pub migration_algorithm_id: u16,
    pub migration_policy_hash: [u8; 32],
    pub expected_post_stv4_root: [u8; 32],
}
impl Fat1Record {
    pub fn decode(bytes: &[u8]) -> Result<Self, Fat1Error> {
        if bytes.len() != FAT1_BYTES {
            return Err(Fat1Error::WrongRecordLength);
        }
        if &bytes[..4] != FAT1_MAGIC {
            return Err(Fat1Error::WrongMagic);
        }
        if u16_at(bytes, 4) != FAT1_VERSION {
            return Err(Fat1Error::UnsupportedVersion);
        }
        let record = Self {
            trust_epoch: u64_at(bytes, 6),
            network_id: take(bytes, 14),
            manifest_id: take(bytes, 46),
            migration_plan_id: take(bytes, 78),
            activation_height: u64_at(bytes, 110),
            parent_block_id: take(bytes, 118),
            pre_stv3_root: take(bytes, 150),
            migration_algorithm_id: u16_at(bytes, 182),
            migration_policy_hash: take(bytes, 184),
            expected_post_stv4_root: take(bytes, 216),
        };
        record.validate_shape()?;
        Ok(record)
    }

    pub fn encode(&self) -> Result<[u8; FAT1_BYTES], Fat1Error> {
        self.validate_shape()?;
        let mut out = Vec::with_capacity(FAT1_BYTES);
        out.extend_from_slice(FAT1_MAGIC);
        push_u16(&mut out, FAT1_VERSION);
        out.extend_from_slice(&self.trust_epoch.to_be_bytes());
        out.extend_from_slice(&self.network_id);
        out.extend_from_slice(&self.manifest_id);
        out.extend_from_slice(&self.migration_plan_id);
        out.extend_from_slice(&self.activation_height.to_be_bytes());
        out.extend_from_slice(&self.parent_block_id);
        out.extend_from_slice(&self.pre_stv3_root);
        push_u16(&mut out, self.migration_algorithm_id);
        out.extend_from_slice(&self.migration_policy_hash);
        out.extend_from_slice(&self.expected_post_stv4_root);
        out.try_into().map_err(|_| Fat1Error::WrongRecordLength)
    }

    pub fn validate_shape(&self) -> Result<(), Fat1Error> {
        if self.trust_epoch == 0 {
            return Err(Fat1Error::EpochZero);
        }
        for (name, value) in [
            ("network_id", &self.network_id),
            ("manifest_id", &self.manifest_id),
            ("migration_plan_id", &self.migration_plan_id),
            ("parent_block_id", &self.parent_block_id),
            ("pre_stv3_root", &self.pre_stv3_root),
            ("migration_policy_hash", &self.migration_policy_hash),
            ("expected_post_stv4_root", &self.expected_post_stv4_root),
        ] {
            if is_zero(value) {
                return Err(Fat1Error::ZeroField(name));
            }
        }
        if self.activation_height == 0 {
            return Err(Fat1Error::HeightZero);
        }
        if self.migration_algorithm_id == 0 {
            return Err(Fat1Error::AlgorithmZero);
        }
        Ok(())
    }

    pub fn record_id(&self) -> Result<[u8; 32], Fat1Error> {
        let bytes = self.encode()?;
        Ok(hash_parts(&[RECORD_ID_DOMAIN, &bytes]))
    }

    /// Exact authority-signing digest. Signature input includes predecessor and keyset pin.
    pub fn signing_digest(
        &self,
        predecessor_record_id: &[u8; 32],
        authority_keyset_id: &[u8; 32],
    ) -> Result<[u8; 32], Fat1Error> {
        if is_zero(predecessor_record_id) && self.trust_epoch != 1 {
            return Err(Fat1Error::PredecessorMismatch);
        }
        if self.trust_epoch == 1 && !is_zero(predecessor_record_id) {
            return Err(Fat1Error::PredecessorMismatch);
        }
        let bytes = self.encode()?;
        Ok(hash_parts(&[
            SIGNING_DOMAIN,
            &bytes,
            predecessor_record_id,
            authority_keyset_id,
        ]))
    }
}

/// FAS1 envelope does not embed public keys. Only the independently configured/pinned
/// authority public-key tuple may verify it, avoiding self-signed trust bootstrap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fat1SignedEnvelope {
    pub record: Fat1Record,
    pub predecessor_record_id: [u8; 32],
    pub authority_keyset_id: [u8; 32],
    pub ed25519_signature: [u8; ED25519_SIGNATURE_BYTES],
    pub mldsa65_signature: [u8; ML_DSA_65_SIGNATURE_BYTES],
}
impl Fat1SignedEnvelope {
    pub fn decode(bytes: &[u8]) -> Result<Self, Fat1Error> {
        if bytes.len() != FAS1_BYTES {
            return Err(Fat1Error::WrongEnvelopeLength);
        }
        if &bytes[..4] != FAS1_MAGIC {
            return Err(Fat1Error::WrongMagic);
        }
        if u16_at(bytes, 4) != FAS1_VERSION {
            return Err(Fat1Error::UnsupportedVersion);
        }
        if u16_at(bytes, 6) != FAS1_AUTH_SUITE_HYBRID_V4 {
            return Err(Fat1Error::UnsupportedSuite);
        }
        if u16_at(bytes, 8) as usize != FAT1_BYTES {
            return Err(Fat1Error::WrongPayloadLength);
        }
        if u16_at(bytes, 10) != 0 {
            return Err(Fat1Error::NonzeroReserved);
        }
        let record = Fat1Record::decode(&bytes[12..12 + FAT1_BYTES])?;
        let predecessor_record_id = take(bytes, 260);
        let authority_keyset_id = take(bytes, 292);
        let ed25519_signature = take(bytes, 324);
        let mldsa65_signature = take(bytes, 388);
        Ok(Self {
            record,
            predecessor_record_id,
            authority_keyset_id,
            ed25519_signature,
            mldsa65_signature,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, Fat1Error> {
        let record = self.record.encode()?;
        let mut out = Vec::with_capacity(FAS1_BYTES);
        out.extend_from_slice(FAS1_MAGIC);
        push_u16(&mut out, FAS1_VERSION);
        push_u16(&mut out, FAS1_AUTH_SUITE_HYBRID_V4);
        push_u16(&mut out, FAT1_BYTES as u16);
        push_u16(&mut out, 0);
        out.extend_from_slice(&record);
        out.extend_from_slice(&self.predecessor_record_id);
        out.extend_from_slice(&self.authority_keyset_id);
        out.extend_from_slice(&self.ed25519_signature);
        out.extend_from_slice(&self.mldsa65_signature);
        if out.len() != FAS1_BYTES {
            return Err(Fat1Error::WrongEnvelopeLength);
        }
        Ok(out)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedFat1Authority {
    pub ed25519_public_key: [u8; ED25519_PUBLIC_KEY_BYTES],
    pub mldsa65_public_key: [u8; ML_DSA_65_PUBLIC_KEY_BYTES],
}
impl PinnedFat1Authority {
    pub fn keyset_id(&self) -> Result<[u8; 32], Fat1Error> {
        if is_zero(&self.ed25519_public_key) || is_zero(&self.mldsa65_public_key) {
            return Err(Fat1Error::ZeroField("authority public key"));
        }
        Ok(hash_parts(&[
            AUTHORITY_KEYSET_DOMAIN,
            &self.ed25519_public_key,
            &self.mldsa65_public_key,
        ]))
    }
}

/// Production must inject the actual separately pinned ML-DSA-65 verifier.
/// An accept-all/mock implementation is test-only and cannot qualify for deployment.
pub trait MlDsa65Verifier {
    fn verify(
        &self,
        public_key: &[u8; ML_DSA_65_PUBLIC_KEY_BYTES],
        digest: &[u8; 32],
        signature: &[u8; ML_DSA_65_SIGNATURE_BYTES],
    ) -> bool;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedForkContext {
    pub network_id: [u8; 32],
    pub manifest_id: [u8; 32],
    pub migration_plan_id: [u8; 32],
    pub activation_height: u64,
    pub parent_block_id: [u8; 32],
    pub pre_stv3_root: [u8; 32],
    pub migration_algorithm_id: u16,
    pub migration_policy_hash: [u8; 32],
    /// Immutable value independently pinned from a separately reviewed STV4 computation.
    pub expected_post_stv4_root: [u8; 32],
}
impl ExpectedForkContext {
    pub fn check(&self, record: &Fat1Record) -> Result<(), Fat1Error> {
        for (name, a, b) in [
            ("network_id", &record.network_id, &self.network_id),
            ("manifest_id", &record.manifest_id, &self.manifest_id),
            (
                "migration_plan_id",
                &record.migration_plan_id,
                &self.migration_plan_id,
            ),
            (
                "parent_block_id",
                &record.parent_block_id,
                &self.parent_block_id,
            ),
            ("pre_stv3_root", &record.pre_stv3_root, &self.pre_stv3_root),
            (
                "migration_policy_hash",
                &record.migration_policy_hash,
                &self.migration_policy_hash,
            ),
            (
                "expected_post_stv4_root",
                &record.expected_post_stv4_root,
                &self.expected_post_stv4_root,
            ),
        ] {
            if a != b {
                return Err(Fat1Error::PolicyContextMismatch(name));
            }
        }
        if record.activation_height != self.activation_height {
            return Err(Fat1Error::PolicyContextMismatch("activation_height"));
        }
        if record.migration_algorithm_id != self.migration_algorithm_id {
            return Err(Fat1Error::PolicyContextMismatch("migration_algorithm_id"));
        }
        Ok(())
    }
}

/// Externally protected floor record. A file-local checksum is NOT a secure monotonic floor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedFat1Floor {
    pub network_id: [u8; 32],
    pub trust_epoch: u64,
    pub record_id: [u8; 32],
    /// Pins the exact authorized signed envelope, including predecessor and signature bytes.
    pub envelope_id: [u8; 32],
}
impl TrustedFat1Floor {
    pub fn initial(network_id: [u8; 32]) -> Result<Self, Fat1Error> {
        if is_zero(&network_id) {
            return Err(Fat1Error::ZeroField("floor network_id"));
        }
        Ok(Self {
            network_id,
            trust_epoch: 0,
            record_id: [0; 32],
            envelope_id: [0; 32],
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloorDecision {
    AlreadyPinnedCurrent,
    AdvanceWithCompareAndSwap,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedFat1 {
    pub record: Fat1Record,
    pub record_id: [u8; 32],
    pub envelope_id: [u8; 32],
    pub predecessor_record_id: [u8; 32],
    pub next_floor: TrustedFat1Floor,
    pub decision: FloorDecision,
}

/// Signature-independent parsing is never acceptance: BOTH signature suites must accept,
/// context must exactly match, and floor rules must pass before a caller may CAS the floor.
pub fn verify_fat1<V: MlDsa65Verifier>(
    envelope: &Fat1SignedEnvelope,
    authority: &PinnedFat1Authority,
    pq_verifier: &V,
    expected: &ExpectedForkContext,
    floor: &TrustedFat1Floor,
) -> Result<VerifiedFat1, Fat1Error> {
    let record = &envelope.record;
    record.validate_shape()?;
    expected.check(record)?;
    if floor.network_id != expected.network_id {
        return Err(Fat1Error::TrustFloorNetworkMismatch);
    }
    let keyset = authority.keyset_id()?;
    if keyset != envelope.authority_keyset_id {
        return Err(Fat1Error::WrongAuthorityKeyset);
    }
    if record.trust_epoch < floor.trust_epoch {
        return Err(Fat1Error::Rollback);
    }
    let record_id = record.record_id()?;
    let signed_envelope_bytes = envelope.encode()?;
    let envelope_id = hash_parts(&[ENVELOPE_ID_DOMAIN, &signed_envelope_bytes]);

    let decision = if record.trust_epoch == floor.trust_epoch {
        if record_id != floor.record_id || envelope_id != floor.envelope_id {
            return Err(Fat1Error::SameEpochConflict);
        }
        FloorDecision::AlreadyPinnedCurrent
    } else {
        let next_epoch = floor
            .trust_epoch
            .checked_add(1)
            .ok_or(Fat1Error::EpochOverflow)?;
        if record.trust_epoch != next_epoch {
            return Err(Fat1Error::EpochGap);
        }
        if envelope.predecessor_record_id != floor.record_id {
            return Err(Fat1Error::PredecessorMismatch);
        }
        FloorDecision::AdvanceWithCompareAndSwap
    };

    let digest = record.signing_digest(&envelope.predecessor_record_id, &keyset)?;
    let ed_pk = VerifyingKey::from_bytes(&authority.ed25519_public_key)
        .map_err(|_| Fat1Error::InvalidEd25519PublicKey)?;
    let ed_sig = EdSignature::from_bytes(&envelope.ed25519_signature);
    ed_pk
        .verify_strict(&digest, &ed_sig)
        .map_err(|_| Fat1Error::InvalidEd25519Signature)?;
    if !pq_verifier.verify(
        &authority.mldsa65_public_key,
        &digest,
        &envelope.mldsa65_signature,
    ) {
        return Err(Fat1Error::InvalidMlDsa65Signature);
    }
    Ok(VerifiedFat1 {
        record: record.clone(),
        record_id,
        envelope_id,
        predecessor_record_id: envelope.predecessor_record_id,
        next_floor: TrustedFat1Floor {
            network_id: record.network_id,
            trust_epoch: record.trust_epoch,
            record_id,
            envelope_id,
        },
        decision,
    })
}

/// The actual provider MUST be durable, independently trusted, monotonic, and atomic.
/// On conflict/unavailable/error callers must stop startup; never fall back to local bytes.
pub trait MonotonicFat1FloorStore {
    fn load(&self, network_id: &[u8; 32]) -> Result<TrustedFat1Floor, Fat1Error>;
    fn compare_and_swap(
        &mut self,
        expected: &TrustedFat1Floor,
        next: &TrustedFat1Floor,
    ) -> Result<(), Fat1Error>;
}

/// Applies a verified trust-floor transition. The provider must implement durable atomic
/// compare-and-swap outside the ordinary local state directory. A lost response is resolved
/// by reloading the exact pinned floor and re-running verify_fat1; never guess commit status.
pub fn commit_verified_floor<S: MonotonicFat1FloorStore>(
    store: &mut S,
    observed_floor: &TrustedFat1Floor,
    verified: &VerifiedFat1,
) -> Result<TrustedFat1Floor, Fat1Error> {
    let current = store.load(&observed_floor.network_id)?;
    if &current != observed_floor {
        return Err(Fat1Error::FloorCasConflict);
    }
    match verified.decision {
        FloorDecision::AlreadyPinnedCurrent => {
            if verified.next_floor != current {
                return Err(Fat1Error::FloorCasConflict);
            }
            Ok(current)
        }
        FloorDecision::AdvanceWithCompareAndSwap => {
            if verified.next_floor.network_id != current.network_id
                || current.trust_epoch.checked_add(1) != Some(verified.next_floor.trust_epoch)
                || verified.next_floor.record_id != verified.record_id
                || verified.next_floor.envelope_id != verified.envelope_id
            {
                return Err(Fat1Error::FloorCasConflict);
            }
            store.compare_and_swap(&current, &verified.next_floor)?;
            let read_back = store.load(&current.network_id)?;
            if read_back != verified.next_floor {
                return Err(Fat1Error::FloorCasConflict);
            }
            Ok(read_back)
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[derive(Clone)]
    struct MemoryFloorStore {
        floor: TrustedFat1Floor,
        unavailable: bool,
        fail_cas: bool,
    }
    impl MonotonicFat1FloorStore for MemoryFloorStore {
        fn load(&self, network_id: &[u8; 32]) -> Result<TrustedFat1Floor, Fat1Error> {
            if self.unavailable {
                return Err(Fat1Error::FloorUnavailable);
            }
            if &self.floor.network_id != network_id {
                return Err(Fat1Error::TrustFloorNetworkMismatch);
            }
            Ok(self.floor.clone())
        }
        fn compare_and_swap(
            &mut self,
            expected: &TrustedFat1Floor,
            next: &TrustedFat1Floor,
        ) -> Result<(), Fat1Error> {
            if self.unavailable {
                return Err(Fat1Error::FloorUnavailable);
            }
            if self.fail_cas || &self.floor != expected {
                return Err(Fat1Error::FloorCasConflict);
            }
            if next.network_id != expected.network_id
                || expected.trust_epoch.checked_add(1) != Some(next.trust_epoch)
                || next.record_id == expected.record_id
                || next.envelope_id == [0; 32]
            {
                return Err(Fat1Error::FloorCasConflict);
            }
            self.floor = next.clone();
            Ok(())
        }
    }
    const FAT1_FIXTURE: &[u8] = include_bytes!("../../../../simulations/cp0224_fat1_record.bin");
    const VECTORS: &str =
        include_str!("../../../../simulations/cp0224_stv4_migration_boundary_vectors.tsv");

    fn vector(key: &str) -> &str {
        VECTORS
            .lines()
            .filter(|line| !line.starts_with('#'))
            .find_map(|line| {
                let (k, v) = line.split_once('\t')?;
                (k == key).then_some(v)
            })
            .expect("required CP-0224 vector")
    }
    fn hex32(value: &str) -> [u8; 32] {
        let mut out = [0; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }
    fn fixture_record() -> Fat1Record {
        Fat1Record::decode(FAT1_FIXTURE).unwrap()
    }

    struct MarkerPqVerifier {
        key: [u8; ML_DSA_65_PUBLIC_KEY_BYTES],
        signature: [u8; ML_DSA_65_SIGNATURE_BYTES],
        digest: [u8; 32],
    }
    impl MlDsa65Verifier for MarkerPqVerifier {
        fn verify(
            &self,
            key: &[u8; ML_DSA_65_PUBLIC_KEY_BYTES],
            digest: &[u8; 32],
            signature: &[u8; ML_DSA_65_SIGNATURE_BYTES],
        ) -> bool {
            *key == self.key && *digest == self.digest && *signature == self.signature
        }
    }
    fn sign_fixture(
        record: Fat1Record,
        previous: [u8; 32],
        ed_seed: [u8; 32],
        pq_pk: [u8; ML_DSA_65_PUBLIC_KEY_BYTES],
    ) -> (Fat1SignedEnvelope, PinnedFat1Authority, MarkerPqVerifier) {
        let key = SigningKey::from_bytes(&ed_seed);
        let ed_pk = key.verifying_key().to_bytes();
        let authority = PinnedFat1Authority {
            ed25519_public_key: ed_pk,
            mldsa65_public_key: pq_pk,
        };
        let keyset = authority.keyset_id().unwrap();
        let digest = record.signing_digest(&previous, &keyset).unwrap();
        let pq_sig = [0x7a; ML_DSA_65_SIGNATURE_BYTES];
        let pq = MarkerPqVerifier {
            key: pq_pk,
            signature: pq_sig,
            digest,
        };
        let env = Fat1SignedEnvelope {
            record: record.clone(),
            predecessor_record_id: previous,
            authority_keyset_id: keyset,
            ed25519_signature: key.sign(&digest).to_bytes(),
            mldsa65_signature: pq_sig,
        };
        (env, authority, pq)
    }
    fn expected(record: &Fat1Record) -> ExpectedForkContext {
        ExpectedForkContext {
            network_id: record.network_id,
            manifest_id: record.manifest_id,
            migration_plan_id: record.migration_plan_id,
            activation_height: record.activation_height,
            parent_block_id: record.parent_block_id,
            pre_stv3_root: record.pre_stv3_root,
            migration_algorithm_id: record.migration_algorithm_id,
            migration_policy_hash: record.migration_policy_hash,
            expected_post_stv4_root: record.expected_post_stv4_root,
        }
    }

    #[test]
    fn cp0224_fat1_fixture_decodes_and_roundtrips_byte_exactly() {
        let record = fixture_record();
        assert_eq!(FAT1_FIXTURE.len(), FAT1_BYTES);
        assert_eq!(record.encode().unwrap().as_slice(), FAT1_FIXTURE);
        assert_eq!(record.trust_epoch, 1); // fixed CP-0224 fixture epoch
        assert_eq!(
            record.record_id().unwrap().as_slice(),
            hex32(vector("fat1.record_id"))
        );
    }
    #[test]
    fn rejects_malformed_fat1_records_and_zero_security_bindings() {
        let mut bad = FAT1_FIXTURE.to_vec();
        bad[0] ^= 1;
        assert_eq!(Fat1Record::decode(&bad), Err(Fat1Error::WrongMagic));
        let mut bad = FAT1_FIXTURE.to_vec();
        bad[4..6].copy_from_slice(&2u16.to_be_bytes());
        assert_eq!(Fat1Record::decode(&bad), Err(Fat1Error::UnsupportedVersion));
        for index in [14usize, 46, 78, 118, 150, 184, 216] {
            let mut bad = FAT1_FIXTURE.to_vec();
            bad[index..index + 32].fill(0);
            assert!(Fat1Record::decode(&bad).is_err(), "zero at {index}");
        }
        let mut bad = FAT1_FIXTURE.to_vec();
        bad[6..14].fill(0);
        assert_eq!(Fat1Record::decode(&bad), Err(Fat1Error::EpochZero));
    }
    #[test]
    fn signed_envelope_is_canonical_and_rejects_length_reserved_suite_mutations() {
        let record = fixture_record();
        let (env, _, _) = sign_fixture(
            record,
            [0; 32],
            [0x41; 32],
            [0x42; ML_DSA_65_PUBLIC_KEY_BYTES],
        );
        let bytes = env.encode().unwrap();
        assert_eq!(bytes.len(), FAS1_BYTES);
        assert_eq!(Fat1SignedEnvelope::decode(&bytes).unwrap(), env);
        for cut in [0usize, 1, 11, 12, 259, FAS1_BYTES - 1] {
            assert!(Fat1SignedEnvelope::decode(&bytes[..cut]).is_err());
        }
        let mut bad = bytes.clone();
        bad[0] ^= 1;
        assert_eq!(Fat1SignedEnvelope::decode(&bad), Err(Fat1Error::WrongMagic));
        let mut bad = bytes.clone();
        bad[6..8].copy_from_slice(&3u16.to_be_bytes());
        assert_eq!(
            Fat1SignedEnvelope::decode(&bad),
            Err(Fat1Error::UnsupportedSuite)
        );
        let mut bad = bytes.clone();
        bad[10] = 1;
        assert_eq!(
            Fat1SignedEnvelope::decode(&bad),
            Err(Fat1Error::NonzeroReserved)
        );
        let mut bad = bytes.clone();
        bad.push(0);
        assert_eq!(
            Fat1SignedEnvelope::decode(&bad),
            Err(Fat1Error::WrongEnvelopeLength)
        );
    }
    #[test]
    fn both_authority_signature_halves_and_exact_context_are_required() {
        let record = fixture_record();
        let (env, auth, pq) = sign_fixture(
            record.clone(),
            [0; 32],
            [0x41; 32],
            [0x42; ML_DSA_65_PUBLIC_KEY_BYTES],
        );
        let floor = TrustedFat1Floor::initial(record.network_id).unwrap();
        let ctx = expected(&record);
        let verified = verify_fat1(&env, &auth, &pq, &ctx, &floor).unwrap();
        assert_eq!(verified.decision, FloorDecision::AdvanceWithCompareAndSwap);

        let mut wrong_ctx = ctx.clone();
        wrong_ctx.expected_post_stv4_root[0] ^= 1;
        assert_eq!(
            verify_fat1(&env, &auth, &pq, &wrong_ctx, &floor),
            Err(Fat1Error::PolicyContextMismatch("expected_post_stv4_root"))
        );

        let mut wrong_auth = auth.clone();
        wrong_auth.ed25519_public_key[0] ^= 1;
        assert_eq!(
            verify_fat1(&env, &wrong_auth, &pq, &ctx, &floor),
            Err(Fat1Error::WrongAuthorityKeyset)
        );

        let mut wrong_ed = env.clone();
        wrong_ed.ed25519_signature[3] ^= 1;
        assert_eq!(
            verify_fat1(&wrong_ed, &auth, &pq, &ctx, &floor),
            Err(Fat1Error::InvalidEd25519Signature)
        );

        let mut wrong_pq = env.clone();
        wrong_pq.mldsa65_signature[3] ^= 1;
        assert_eq!(
            verify_fat1(&wrong_pq, &auth, &pq, &ctx, &floor),
            Err(Fat1Error::InvalidMlDsa65Signature)
        );
    }
    #[test]
    fn floor_requires_exact_current_record_or_one_signed_successor() {
        let r1 = fixture_record();
        let (env1, auth, pq) = sign_fixture(
            r1.clone(),
            [0; 32],
            [0x41; 32],
            [0x42; ML_DSA_65_PUBLIC_KEY_BYTES],
        );
        let floor0 = TrustedFat1Floor::initial(r1.network_id).unwrap();
        let v1 = verify_fat1(&env1, &auth, &pq, &expected(&r1), &floor0).unwrap();
        let floor1 = v1.next_floor.clone();
        let current = verify_fat1(&env1, &auth, &pq, &expected(&r1), &floor1).unwrap();
        assert_eq!(current.decision, FloorDecision::AlreadyPinnedCurrent);

        let mut r2 = r1.clone();
        r2.trust_epoch = 2;
        r2.expected_post_stv4_root[0] ^= 1;
        let (env2, auth2, pq2) = sign_fixture(
            r2.clone(),
            floor1.record_id,
            [0x41; 32],
            [0x42; ML_DSA_65_PUBLIC_KEY_BYTES],
        );
        let v2 = verify_fat1(&env2, &auth2, &pq2, &expected(&r2), &floor1).unwrap();
        assert_eq!(v2.decision, FloorDecision::AdvanceWithCompareAndSwap);
        let floor2 = v2.next_floor;
        // The exact envelope (not just its 248-byte record ID) is pinned, so a
        // second signature envelope with a substituted predecessor is not interchangeable.
        let (alternate_env, alternate_auth, alternate_pq) = sign_fixture(
            r2.clone(),
            [0x77; 32],
            [0x41; 32],
            [0x42; ML_DSA_65_PUBLIC_KEY_BYTES],
        );
        assert_eq!(
            verify_fat1(
                &alternate_env,
                &alternate_auth,
                &alternate_pq,
                &expected(&r2),
                &floor2
            ),
            Err(Fat1Error::SameEpochConflict)
        );
        let old_env = env1.clone();
        let old_ctx = expected(&r1);
        assert_eq!(
            verify_fat1(&old_env, &auth, &pq, &old_ctx, &floor2),
            Err(Fat1Error::Rollback)
        );
        // Same-epoch exact-current case is covered above; same epoch with altered bytes conflicts.
        let mut conflict = old_env.clone();
        conflict.record.expected_post_stv4_root[0] ^= 2;
        assert_eq!(
            verify_fat1(&conflict, &auth, &pq, &expected(&conflict.record), &floor1),
            Err(Fat1Error::SameEpochConflict)
        );
        let mut gap = r2.clone();
        gap.trust_epoch = 3;
        let (gap_env, gap_auth, gap_pq) = sign_fixture(
            gap.clone(),
            floor1.record_id,
            [0x41; 32],
            [0x42; ML_DSA_65_PUBLIC_KEY_BYTES],
        );
        assert_eq!(
            verify_fat1(&gap_env, &gap_auth, &gap_pq, &expected(&gap), &floor1),
            Err(Fat1Error::EpochGap)
        );
    }
    #[test]
    fn floor_compare_and_swap_is_monotonic_idempotent_and_read_back_verified() {
        let record = fixture_record();
        let (env, authority, pq) = sign_fixture(
            record.clone(),
            [0; 32],
            [0x41; 32],
            [0x42; ML_DSA_65_PUBLIC_KEY_BYTES],
        );
        let ctx = expected(&record);
        let floor0 = TrustedFat1Floor::initial(record.network_id).unwrap();
        let verified = verify_fat1(&env, &authority, &pq, &ctx, &floor0).unwrap();
        let mut store = MemoryFloorStore {
            floor: floor0.clone(),
            unavailable: false,
            fail_cas: false,
        };
        let committed = commit_verified_floor(&mut store, &floor0, &verified).unwrap();
        assert_eq!(committed, verified.next_floor);
        assert_eq!(store.floor, committed);

        // Retrying after a response loss sees the exact pinned envelope and is idempotent.
        let current = verify_fat1(&env, &authority, &pq, &ctx, &committed).unwrap();
        assert_eq!(current.decision, FloorDecision::AlreadyPinnedCurrent);
        assert_eq!(
            commit_verified_floor(&mut store, &committed, &current).unwrap(),
            committed
        );
    }

    #[test]
    fn floor_store_unavailable_or_stale_observation_fails_closed() {
        let record = fixture_record();
        let (env, authority, pq) = sign_fixture(
            record.clone(),
            [0; 32],
            [0x41; 32],
            [0x42; ML_DSA_65_PUBLIC_KEY_BYTES],
        );
        let ctx = expected(&record);
        let floor0 = TrustedFat1Floor::initial(record.network_id).unwrap();
        let verified = verify_fat1(&env, &authority, &pq, &ctx, &floor0).unwrap();

        let mut down = MemoryFloorStore {
            floor: floor0.clone(),
            unavailable: true,
            fail_cas: false,
        };
        assert_eq!(
            commit_verified_floor(&mut down, &floor0, &verified),
            Err(Fat1Error::FloorUnavailable)
        );

        let mut changed = floor0.clone();
        changed.trust_epoch = 7;
        changed.record_id = [0x55; 32];
        changed.envelope_id = [0x66; 32];
        let mut raced = MemoryFloorStore {
            floor: changed,
            unavailable: false,
            fail_cas: false,
        };
        assert_eq!(
            commit_verified_floor(&mut raced, &floor0, &verified),
            Err(Fat1Error::FloorCasConflict)
        );

        let mut cas_fail = MemoryFloorStore {
            floor: floor0.clone(),
            unavailable: false,
            fail_cas: true,
        };
        assert_eq!(
            commit_verified_floor(&mut cas_fail, &floor0, &verified),
            Err(Fat1Error::FloorCasConflict)
        );
        assert_eq!(cas_fail.floor, floor0);
    }

    #[test]
    fn real_libcrux_mldsa65_fas1_verifies_before_floor_cas() {
        use crate::v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate;
        use libcrux_ml_dsa::ml_dsa_65::portable;

        let record = fixture_record();
        let pq_key_pair = portable::generate_key_pair([0x21; 32]);
        let pq_public_key: [u8; ML_DSA_65_PUBLIC_KEY_BYTES] =
            *pq_key_pair.verification_key.as_ref();

        let ed_signing_key = SigningKey::from_bytes(&[0x41; 32]);
        let authority = PinnedFat1Authority {
            ed25519_public_key: ed_signing_key.verifying_key().to_bytes(),
            mldsa65_public_key: pq_public_key,
        };
        let keyset_id = authority.keyset_id().unwrap();
        let predecessor = [0u8; 32];
        let digest = record.signing_digest(&predecessor, &keyset_id).unwrap();
        let ed25519_signature = ed_signing_key.sign(&digest).to_bytes();
        let pq_signature =
            portable::sign(&pq_key_pair.signing_key, &digest, &[], [0x37; 32]).unwrap();
        let mldsa65_signature: [u8; ML_DSA_65_SIGNATURE_BYTES] = *pq_signature.as_ref();
        let envelope = Fat1SignedEnvelope {
            record: record.clone(),
            predecessor_record_id: predecessor,
            authority_keyset_id: keyset_id,
            ed25519_signature,
            mldsa65_signature,
        };
        let encoded = envelope.encode().unwrap();
        let decoded = Fat1SignedEnvelope::decode(&encoded).unwrap();
        assert_eq!(decoded, envelope);

        use crate::v4_fat1_disk_floor_candidate::DurableFat1FloorStore;
        use std::time::{SystemTime, UNIX_EPOCH};

        let context = expected(&record);
        let floor0 = TrustedFat1Floor::initial(record.network_id).unwrap();
        let pq_verifier = LibcruxMlDsa65VerifierCandidate;
        let test_dir = std::env::temp_dir().join(format!(
            "ain1_fat1_real_pq_floor_{}_{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&test_dir).unwrap();
        let floor_path = test_dir.join("fat1.floor");
        let mut floor_store = DurableFat1FloorStore::new(floor_path.clone());
        floor_store.initialize(&floor0).unwrap();
        let observed_floor = floor_store.load_checked(&record.network_id).unwrap();
        assert_eq!(observed_floor, floor0);

        let mut invalid_pq = decoded.clone();
        invalid_pq.mldsa65_signature[9] ^= 1;
        assert_eq!(
            verify_fat1(
                &invalid_pq,
                &authority,
                &pq_verifier,
                &context,
                &observed_floor,
            ),
            Err(Fat1Error::InvalidMlDsa65Signature)
        );
        assert_eq!(
            floor_store.load_checked(&record.network_id).unwrap(),
            floor0,
            "invalid ML-DSA must never advance the durable floor"
        );

        let verified = verify_fat1(
            &decoded,
            &authority,
            &pq_verifier,
            &context,
            &observed_floor,
        )
        .unwrap();
        assert_eq!(verified.decision, FloorDecision::AdvanceWithCompareAndSwap);
        let committed =
            commit_verified_floor(&mut floor_store, &observed_floor, &verified).unwrap();
        assert_eq!(committed, verified.next_floor);

        // Reopen the local floor from disk and prove the exact-envelope retry remains idempotent.
        let reopened = DurableFat1FloorStore::new(floor_path.clone());
        assert_eq!(
            reopened.load_checked(&record.network_id).unwrap(),
            committed
        );
        let current =
            verify_fat1(&decoded, &authority, &pq_verifier, &context, &committed).unwrap();
        assert_eq!(current.decision, FloorDecision::AlreadyPinnedCurrent);
        let mut retry_store = DurableFat1FloorStore::new(floor_path);
        assert_eq!(
            commit_verified_floor(&mut retry_store, &committed, &current).unwrap(),
            committed
        );
        std::fs::remove_dir_all(test_dir).unwrap();
    }
}
