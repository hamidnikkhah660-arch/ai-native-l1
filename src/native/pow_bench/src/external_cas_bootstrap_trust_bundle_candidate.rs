//! CP-0768: canonical, independently digest-pinned QBT1 bootstrap bundle.
//!
//! QBTB1 carries the exact generation-zero ECR1 record, the out-of-band BootstrapTrustPin
//! fields, and the exact QBT1 receipt. Provider identity/key material is supplied by an already
//! verified Q6PN profile pin; the Anchor pin is supplied by separately pinned node config.
//! The QBTB1 file is accepted only when its complete SHA-256 is supplied independently by the
//! caller. This codec does not create that trust channel or prove real-world custodian separation.
use crate::{
    external_cas_anchor_candidate::{ExternalCasPin, ExternalCasRecord, EXTERNAL_CAS_RECORD_BYTES},
    external_cas_bootstrap_trust_candidate::{
        verify_bootstrap_trust_receipt, BootstrapTrustError, BootstrapTrustPin,
        VerifiedBootstrapTrust, BOOTSTRAP_TRUST_RECEIPT_BYTES,
    },
    external_cas_offhost_anchor_protocol_candidate::ExternalCasOffhostAnchorPin,
    v4_fat1_trust_candidate::{MlDsa65Verifier, ML_DSA_65_PUBLIC_KEY_BYTES},
};
use sha2::{Digest, Sha256};
use std::fmt;

type Digest32 = [u8; 32];

const MAGIC: &[u8; 4] = b"QBTB";
const VERSION: u16 = 1;
const HEADER_BYTES: usize = 8;
const PIN_DIGEST_FIELDS: usize = 6;
const PIN_BYTES: usize = PIN_DIGEST_FIELDS * 32 + 2 * ML_DSA_65_PUBLIC_KEY_BYTES;

/// Exact QBTB1 wire length. It is fixed-width and bounded before any field parsing.
pub const QBTB1_BUNDLE_BYTES: usize =
    HEADER_BYTES + EXTERNAL_CAS_RECORD_BYTES + PIN_BYTES + BOOTSTRAP_TRUST_RECEIPT_BYTES;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapTrustBundleError {
    WrongLength,
    WrongMagic,
    UnsupportedVersion,
    NoncanonicalHeader,
    InvalidBundleDigestPin,
    BundleDigestMismatch,
    InvalidProfileCommitmentPin,
    ProfileCommitmentMismatch,
    Record(crate::external_cas_anchor_candidate::ExternalCasError),
    BootstrapTrust(BootstrapTrustError),
}

impl fmt::Display for BootstrapTrustBundleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "QBTB1 bundle error: {self:?}")
    }
}
impl std::error::Error for BootstrapTrustBundleError {}
impl From<crate::external_cas_anchor_candidate::ExternalCasError> for BootstrapTrustBundleError {
    fn from(value: crate::external_cas_anchor_candidate::ExternalCasError) -> Self {
        Self::Record(value)
    }
}
impl From<BootstrapTrustError> for BootstrapTrustBundleError {
    fn from(value: BootstrapTrustError) -> Self {
        Self::BootstrapTrust(value)
    }
}

/// Canonical QBTB1 input. The contained signer public keys are public trust pins, not secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Qbt1BootstrapTrustBundleV1 {
    bootstrap_record: ExternalCasRecord,
    trust_pin: BootstrapTrustPin,
    receipt_wire: Vec<u8>,
}

impl Qbt1BootstrapTrustBundleV1 {
    pub fn new(
        bootstrap_record: ExternalCasRecord,
        trust_pin: BootstrapTrustPin,
        receipt_wire: Vec<u8>,
    ) -> Result<Self, BootstrapTrustBundleError> {
        let bundle = Self {
            bootstrap_record,
            trust_pin,
            receipt_wire,
        };
        // Encode validates canonical ECR1, fixed QBT1 length and exact total framing.
        bundle.encode()?;
        Ok(bundle)
    }

    pub fn bootstrap_record(&self) -> &ExternalCasRecord {
        &self.bootstrap_record
    }

    pub fn trust_pin(&self) -> &BootstrapTrustPin {
        &self.trust_pin
    }

    pub fn receipt_wire(&self) -> &[u8] {
        &self.receipt_wire
    }

    /// Encode exact QBTB1 v1 framing. The receipt signature is verified separately.
    pub fn encode(&self) -> Result<Vec<u8>, BootstrapTrustBundleError> {
        if self.receipt_wire.len() != BOOTSTRAP_TRUST_RECEIPT_BYTES {
            return Err(BootstrapTrustBundleError::WrongLength);
        }
        let record_wire = self.bootstrap_record.encode()?;
        let mut wire = Vec::with_capacity(QBTB1_BUNDLE_BYTES);
        wire.extend_from_slice(MAGIC);
        wire.extend_from_slice(&VERSION.to_be_bytes());
        wire.extend_from_slice(&0u16.to_be_bytes());
        wire.extend_from_slice(&record_wire);

        let pin = &self.trust_pin;
        wire.extend_from_slice(&pin.expected_receipt_digest);
        wire.extend_from_slice(&pin.profile_digest);
        wire.extend_from_slice(&pin.initial_record_digest);
        wire.extend_from_slice(&pin.initial_anchor_state_digest);
        wire.extend_from_slice(&pin.owner_signer_id);
        wire.extend_from_slice(&pin.owner_public_key);
        wire.extend_from_slice(&pin.independent_custodian_signer_id);
        wire.extend_from_slice(&pin.independent_custodian_public_key);
        wire.extend_from_slice(&self.receipt_wire);

        if wire.len() != QBTB1_BUNDLE_BYTES {
            return Err(BootstrapTrustBundleError::WrongLength);
        }
        Ok(wire)
    }

    /// Decode only the exact fixed-width v1 form. ECR1 is itself canonically decoded.
    pub fn decode(wire: &[u8]) -> Result<Self, BootstrapTrustBundleError> {
        if wire.len() != QBTB1_BUNDLE_BYTES {
            return Err(BootstrapTrustBundleError::WrongLength);
        }
        if wire.get(..4) != Some(MAGIC.as_slice()) {
            return Err(BootstrapTrustBundleError::WrongMagic);
        }
        let version = u16::from_be_bytes([wire[4], wire[5]]);
        if version != VERSION {
            return Err(BootstrapTrustBundleError::UnsupportedVersion);
        }
        if wire[6..8] != [0, 0] {
            return Err(BootstrapTrustBundleError::NoncanonicalHeader);
        }

        let mut cursor = HEADER_BYTES;
        let record_end = cursor + EXTERNAL_CAS_RECORD_BYTES;
        let bootstrap_record = ExternalCasRecord::decode(&wire[cursor..record_end])?;
        cursor = record_end;

        let expected_receipt_digest = take_array::<32>(wire, &mut cursor)?;
        let profile_digest = take_array::<32>(wire, &mut cursor)?;
        let initial_record_digest = take_array::<32>(wire, &mut cursor)?;
        let initial_anchor_state_digest = take_array::<32>(wire, &mut cursor)?;
        let owner_signer_id = take_array::<32>(wire, &mut cursor)?;
        let owner_public_key = take_array::<ML_DSA_65_PUBLIC_KEY_BYTES>(wire, &mut cursor)?;
        let independent_custodian_signer_id = take_array::<32>(wire, &mut cursor)?;
        let independent_custodian_public_key =
            take_array::<ML_DSA_65_PUBLIC_KEY_BYTES>(wire, &mut cursor)?;

        let receipt_end = cursor
            .checked_add(BOOTSTRAP_TRUST_RECEIPT_BYTES)
            .ok_or(BootstrapTrustBundleError::WrongLength)?;
        let receipt_wire = wire
            .get(cursor..receipt_end)
            .ok_or(BootstrapTrustBundleError::WrongLength)?
            .to_vec();
        if receipt_end != wire.len() {
            return Err(BootstrapTrustBundleError::WrongLength);
        }

        let bundle = Self {
            bootstrap_record,
            trust_pin: BootstrapTrustPin {
                expected_receipt_digest,
                profile_digest,
                initial_record_digest,
                initial_anchor_state_digest,
                owner_signer_id,
                owner_public_key,
                independent_custodian_signer_id,
                independent_custodian_public_key,
            },
            receipt_wire,
        };
        if bundle.encode()?.as_slice() != wire {
            return Err(BootstrapTrustBundleError::WrongLength);
        }
        Ok(bundle)
    }
}

/// A QBTB1 bundle whose whole-file digest and QBT1 trust chain were successfully verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedQbt1BootstrapTrustBundle {
    bootstrap_record: ExternalCasRecord,
    bootstrap_trust: VerifiedBootstrapTrust,
    bundle_sha256: Digest32,
    q6pn_profile_pin_commitment: Digest32,
}

impl VerifiedQbt1BootstrapTrustBundle {
    pub fn bootstrap_record(&self) -> &ExternalCasRecord {
        &self.bootstrap_record
    }

    pub fn bootstrap_trust(&self) -> &VerifiedBootstrapTrust {
        &self.bootstrap_trust
    }

    pub fn bundle_sha256(&self) -> &Digest32 {
        &self.bundle_sha256
    }

    pub fn q6pn_profile_pin_commitment(&self) -> &Digest32 {
        &self.q6pn_profile_pin_commitment
    }
}

/// Verify QBTB1 against two external anchors:
/// - expected_bundle_sha256 must be delivered independently of the bundle file (for example,
///   through a config whose digest is separately supplied out of band);
/// - expected_q6pn_profile_pin_commitment must be taken from QRunV06VerifiedProfilePin, not
///   from the bundle, receipt, or a colocated manifest.
///
/// The caller supplies Provider from the already verified Q6PN and Anchor from independently
/// pinned node configuration. No local-file self-pinning, enrollment, I/O, network, CAS or
/// mutable state access is performed here.
pub fn verify_qbt1_bootstrap_trust_bundle<V: MlDsa65Verifier>(
    wire: &[u8],
    expected_bundle_sha256: &Digest32,
    expected_q6pn_profile_pin_commitment: &Digest32,
    provider: &ExternalCasPin,
    anchor: &ExternalCasOffhostAnchorPin,
    verifier: &V,
) -> Result<VerifiedQbt1BootstrapTrustBundle, BootstrapTrustBundleError> {
    if *expected_bundle_sha256 == [0; 32] {
        return Err(BootstrapTrustBundleError::InvalidBundleDigestPin);
    }
    if *expected_q6pn_profile_pin_commitment == [0; 32] {
        return Err(BootstrapTrustBundleError::InvalidProfileCommitmentPin);
    }
    let bundle_sha256: Digest32 = Sha256::digest(wire).into();
    if &bundle_sha256 != expected_bundle_sha256 {
        return Err(BootstrapTrustBundleError::BundleDigestMismatch);
    }

    let bundle = Qbt1BootstrapTrustBundleV1::decode(wire)?;
    if &bundle.trust_pin.profile_digest != expected_q6pn_profile_pin_commitment {
        return Err(BootstrapTrustBundleError::ProfileCommitmentMismatch);
    }

    let bootstrap_trust = verify_bootstrap_trust_receipt(
        &bundle.receipt_wire,
        &bundle.trust_pin,
        provider,
        anchor,
        &bundle.bootstrap_record,
        verifier,
    )?;

    Ok(VerifiedQbt1BootstrapTrustBundle {
        bootstrap_record: bundle.bootstrap_record,
        bootstrap_trust,
        bundle_sha256,
        q6pn_profile_pin_commitment: *expected_q6pn_profile_pin_commitment,
    })
}

fn take_array<const N: usize>(
    wire: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], BootstrapTrustBundleError> {
    let end = cursor
        .checked_add(N)
        .ok_or(BootstrapTrustBundleError::WrongLength)?;
    let value = wire
        .get(*cursor..end)
        .ok_or(BootstrapTrustBundleError::WrongLength)?
        .try_into()
        .map_err(|_| BootstrapTrustBundleError::WrongLength)?;
    *cursor = end;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::external_cas_bootstrap_trust_candidate::tests::bundle_test_material;
    use crate::v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate;

    #[test]
    fn qbtb1_roundtrips_and_verifies_against_external_bundle_and_q6pn_pins() {
        let (provider, anchor, record, pin, receipt_wire) = bundle_test_material();
        let bundle = Qbt1BootstrapTrustBundleV1::new(record, pin.clone(), receipt_wire).unwrap();
        let wire = bundle.encode().unwrap();
        assert_eq!(wire.len(), QBTB1_BUNDLE_BYTES);
        assert_eq!(&wire[..4], b"QBTB");
        assert_eq!(Qbt1BootstrapTrustBundleV1::decode(&wire).unwrap(), bundle);

        let bundle_digest: Digest32 = Sha256::digest(&wire).into();
        let verified = verify_qbt1_bootstrap_trust_bundle(
            &wire,
            &bundle_digest,
            &pin.profile_digest,
            &provider,
            &anchor,
            &LibcruxMlDsa65VerifierCandidate,
        )
        .unwrap();
        assert_eq!(
            verified.bootstrap_trust().receipt_digest(),
            pin.expected_receipt_digest
        );
        assert_eq!(verified.bootstrap_record(), bundle.bootstrap_record());
        assert_eq!(verified.q6pn_profile_pin_commitment(), &pin.profile_digest);
        assert_eq!(verified.bundle_sha256(), &bundle_digest);
    }

    #[test]
    fn qbtb1_rejects_wrong_bundle_digest_profile_and_trailing_bytes() {
        let (provider, anchor, record, pin, receipt_wire) = bundle_test_material();
        let bundle = Qbt1BootstrapTrustBundleV1::new(record, pin.clone(), receipt_wire).unwrap();
        let wire = bundle.encode().unwrap();
        let digest: Digest32 = Sha256::digest(&wire).into();

        let mut wrong_digest = digest;
        wrong_digest[0] ^= 1;
        assert_eq!(
            verify_qbt1_bootstrap_trust_bundle(
                &wire,
                &wrong_digest,
                &pin.profile_digest,
                &provider,
                &anchor,
                &LibcruxMlDsa65VerifierCandidate,
            ),
            Err(BootstrapTrustBundleError::BundleDigestMismatch)
        );
        let mut wrong_profile = pin.profile_digest;
        wrong_profile[0] ^= 1;
        assert_eq!(
            verify_qbt1_bootstrap_trust_bundle(
                &wire,
                &digest,
                &wrong_profile,
                &provider,
                &anchor,
                &LibcruxMlDsa65VerifierCandidate,
            ),
            Err(BootstrapTrustBundleError::ProfileCommitmentMismatch)
        );
        let mut trailing = wire;
        trailing.push(0);
        assert_eq!(
            Qbt1BootstrapTrustBundleV1::decode(&trailing),
            Err(BootstrapTrustBundleError::WrongLength)
        );
    }

    #[test]
    fn qbtb1_rejects_header_mutation_and_wrong_trust_domain() {
        let (provider, anchor, record, pin, receipt_wire) = bundle_test_material();
        let bundle = Qbt1BootstrapTrustBundleV1::new(record, pin.clone(), receipt_wire).unwrap();
        let wire = bundle.encode().unwrap();
        let digest: Digest32 = Sha256::digest(&wire).into();

        let mut wrong_magic = wire.clone();
        wrong_magic[0] ^= 1;
        assert_eq!(
            Qbt1BootstrapTrustBundleV1::decode(&wrong_magic),
            Err(BootstrapTrustBundleError::WrongMagic)
        );
        let mut wrong_version = wire.clone();
        wrong_version[5] = 2;
        assert_eq!(
            Qbt1BootstrapTrustBundleV1::decode(&wrong_version),
            Err(BootstrapTrustBundleError::UnsupportedVersion)
        );
        let mut reserved = wire.clone();
        reserved[7] = 1;
        assert_eq!(
            Qbt1BootstrapTrustBundleV1::decode(&reserved),
            Err(BootstrapTrustBundleError::NoncanonicalHeader)
        );

        let mut wrong_provider = provider.clone();
        wrong_provider.provider_id[0] ^= 1;
        assert!(matches!(
            verify_qbt1_bootstrap_trust_bundle(
                &wire,
                &digest,
                &pin.profile_digest,
                &wrong_provider,
                &anchor,
                &LibcruxMlDsa65VerifierCandidate,
            ),
            Err(BootstrapTrustBundleError::BootstrapTrust(_))
        ));
    }

    #[test]
    fn qbtb1_rejects_altered_initial_ecr1_even_when_bundle_digest_is_recomputed() {
        let (provider, anchor, mut record, pin, receipt_wire) = bundle_test_material();
        record.next_state_digest[0] ^= 1;
        let bundle = Qbt1BootstrapTrustBundleV1::new(record, pin.clone(), receipt_wire).unwrap();
        let wire = bundle.encode().unwrap();
        let digest: Digest32 = Sha256::digest(&wire).into();
        assert!(matches!(
            verify_qbt1_bootstrap_trust_bundle(
                &wire,
                &digest,
                &pin.profile_digest,
                &provider,
                &anchor,
                &LibcruxMlDsa65VerifierCandidate,
            ),
            Err(BootstrapTrustBundleError::BootstrapTrust(
                BootstrapTrustError::InvalidBootstrapRecord
            ))
        ));
    }
}
