//! Canonical, independently pinned QFP6 profile trust bundle.
//!
//! Q6PN contains the immutable Q6GD descriptor and the provider/key/network/genesis
//! identity used by Q6EA. The bytes are untrusted until the caller supplies the exact
//! Q6PN commitment from a separate trust channel. This module deliberately does not
//! read environment variables, infer a pin from a colocated manifest, or access the
//! filesystem; those choices belong to the node's reviewed trust bootstrap.
use crate::{
    external_cas_anchor_candidate::ExternalCasPin,
    qrun_v06_external_anchor_candidate::{QRunV06ExternalAnchorError, QRunV06ExternalAnchorPin},
    qrun_v06_genesis_descriptor_candidate::{
        QRunV06GenesisDescriptor, QRunV06GenesisDescriptorError, QRUN_V06_GENESIS_DESCRIPTOR_BYTES,
    },
    v4_fat1_trust_candidate::ML_DSA_65_PUBLIC_KEY_BYTES,
};
use sha2::{Digest, Sha256};

const MAGIC: &[u8; 4] = b"Q6PN";
const VERSION_V1: u16 = 1;
const VERSION_V2: u16 = 2;
const HEADER_BYTES: usize = 8;
const PROFILE_PIN_DOMAIN_V1: &[u8] = b"QRUN-V06-PROFILE-TRUST-PIN-COMMITMENT-V1\0";
const PROFILE_PIN_DOMAIN_V2: &[u8] = b"QRUN-V06-PROFILE-TRUST-PIN-COMMITMENT-V2\0";
pub const QRUN_V06_PROFILE_PIN_V2_EXTENSION_BYTES: usize = 2 + 32 * 4 + 8;
pub const QRUN_V06_PROFILE_PIN_V2_BYTES: usize =
    QRUN_V06_PROFILE_PIN_BYTES + QRUN_V06_PROFILE_PIN_V2_EXTENSION_BYTES;
const DIGEST_BYTES: usize = 32;
pub const QRUN_V06_PROFILE_PIN_BYTES: usize = HEADER_BYTES
    + QRUN_V06_GENESIS_DESCRIPTOR_BYTES
    + DIGEST_BYTES * 4
    + ML_DSA_65_PUBLIC_KEY_BYTES;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QRunV06ProfilePinError {
    Malformed,
    UnsupportedVersion,
    NonzeroReserved,
    MissingIndependentCommitment,
    ProfilePinCommitmentMismatch,
    Descriptor(QRunV06GenesisDescriptorError),
    ExternalAnchor(String),
    WrongNetwork,
    InvalidQuoteAssetTrustPin,
}

impl std::fmt::Display for QRunV06ProfilePinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "QFP6 profile pin error: {self:?}")
    }
}
impl std::error::Error for QRunV06ProfilePinError {}

impl From<QRunV06GenesisDescriptorError> for QRunV06ProfilePinError {
    fn from(value: QRunV06GenesisDescriptorError) -> Self {
        Self::Descriptor(value)
    }
}
impl From<QRunV06ExternalAnchorError> for QRunV06ProfilePinError {
    fn from(value: QRunV06ExternalAnchorError) -> Self {
        Self::ExternalAnchor(value.to_string())
    }
}

/// Q6QA authority pin embedded in Q6PN v2. Q6TS v1 then authenticates the exact Q6PN
/// byte commitment, binding this quote-asset commitment and its authority/epoch to the profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06QuoteAssetTrustPin {
    q6qa_format_version: u16,
    q6qa_bundle_commitment: [u8; 32],
    asset_id: [u8; 32],
    authority_key_id: [u8; 32],
    authority_account: [u8; 32],
    qualification_epoch: u64,
}

impl QRunV06QuoteAssetTrustPin {
    pub fn new(
        q6qa_format_version: u16,
        q6qa_bundle_commitment: [u8; 32],
        asset_id: [u8; 32],
        authority_key_id: [u8; 32],
        authority_account: [u8; 32],
        qualification_epoch: u64,
    ) -> Result<Self, QRunV06ProfilePinError> {
        let pin = Self {
            q6qa_format_version,
            q6qa_bundle_commitment,
            asset_id,
            authority_key_id,
            authority_account,
            qualification_epoch,
        };
        pin.validate()?;
        Ok(pin)
    }

    fn validate(&self) -> Result<(), QRunV06ProfilePinError> {
        if self.q6qa_format_version != 1
            || self.q6qa_bundle_commitment == [0; 32]
            || self.asset_id == [0; 32]
            || self.authority_key_id == [0; 32]
            || self.authority_account == [0; 32]
            || self.qualification_epoch == 0
        {
            return Err(QRunV06ProfilePinError::InvalidQuoteAssetTrustPin);
        }
        Ok(())
    }

    pub fn q6qa_format_version(&self) -> u16 {
        self.q6qa_format_version
    }
    pub fn q6qa_bundle_commitment(&self) -> [u8; 32] {
        self.q6qa_bundle_commitment
    }
    pub fn asset_id(&self) -> [u8; 32] {
        self.asset_id
    }
    pub fn authority_key_id(&self) -> [u8; 32] {
        self.authority_key_id
    }
    pub fn authority_account(&self) -> [u8; 32] {
        self.authority_account
    }
    pub fn qualification_epoch(&self) -> u64 {
        self.qualification_epoch
    }
}

/// Complete trust bundle for one QFP6 network profile.
///
/// Q6PN v1 is the historical Genesis/provider pin. Q6PN v2 adds one optional but mandatory-for-v2
/// Q6QA quote-asset pin. Existing Q6TS v1 signs the exact Q6PN byte commitment, so v2 binds the
/// quote qualification into the existing dual-signature profile trust chain without changing
/// Q6TR/Q6TS formats. Neither value is accepted from an untrusted colocated file alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06ProfilePinCandidate {
    descriptor: QRunV06GenesisDescriptor,
    external_cas_pin: ExternalCasPin,
    quote_asset_trust_pin: Option<QRunV06QuoteAssetTrustPin>,
}

impl QRunV06ProfilePinCandidate {
    pub fn new(
        descriptor: QRunV06GenesisDescriptor,
        external_cas_pin: ExternalCasPin,
    ) -> Result<Self, QRunV06ProfilePinError> {
        external_cas_pin
            .validate()
            .map_err(|error| QRunV06ProfilePinError::ExternalAnchor(error.to_string()))?;
        if external_cas_pin.network_id != descriptor.network_id() {
            return Err(QRunV06ProfilePinError::WrongNetwork);
        }
        // Re-decode canonical bytes to keep malformed descriptor state out of this wrapper.
        let descriptor = QRunV06GenesisDescriptor::decode(&descriptor.encode())?;
        Ok(Self {
            descriptor,
            external_cas_pin,
            quote_asset_trust_pin: None,
        })
    }

    pub fn new_with_quote_asset_trust_pin(
        descriptor: QRunV06GenesisDescriptor,
        external_cas_pin: ExternalCasPin,
        quote_asset_trust_pin: QRunV06QuoteAssetTrustPin,
    ) -> Result<Self, QRunV06ProfilePinError> {
        quote_asset_trust_pin.validate()?;
        let mut bundle = Self::new(descriptor, external_cas_pin)?;
        bundle.quote_asset_trust_pin = Some(quote_asset_trust_pin);
        Ok(bundle)
    }

    pub fn encode(&self) -> Result<Vec<u8>, QRunV06ProfilePinError> {
        self.external_cas_pin
            .validate()
            .map_err(|error| QRunV06ProfilePinError::ExternalAnchor(error.to_string()))?;
        if self.external_cas_pin.network_id != self.descriptor.network_id() {
            return Err(QRunV06ProfilePinError::WrongNetwork);
        }
        if let Some(quote_pin) = &self.quote_asset_trust_pin {
            quote_pin.validate()?;
        }

        let version = if self.quote_asset_trust_pin.is_some() {
            VERSION_V2
        } else {
            VERSION_V1
        };
        let capacity = if version == VERSION_V2 {
            QRUN_V06_PROFILE_PIN_V2_BYTES
        } else {
            QRUN_V06_PROFILE_PIN_BYTES
        };
        let mut output = Vec::with_capacity(capacity);
        output.extend_from_slice(MAGIC);
        output.extend_from_slice(&version.to_be_bytes());
        output.extend_from_slice(&0u16.to_be_bytes());
        output.extend_from_slice(&self.descriptor.encode());
        output.extend_from_slice(&self.external_cas_pin.provider_id);
        output.extend_from_slice(&self.external_cas_pin.network_id);
        output.extend_from_slice(&self.external_cas_pin.genesis_digest);
        output.extend_from_slice(&self.external_cas_pin.receipt_key_id);
        output.extend_from_slice(&self.external_cas_pin.receipt_public_key);
        if let Some(quote_pin) = &self.quote_asset_trust_pin {
            output.extend_from_slice(&quote_pin.q6qa_format_version.to_be_bytes());
            output.extend_from_slice(&quote_pin.q6qa_bundle_commitment);
            output.extend_from_slice(&quote_pin.asset_id);
            output.extend_from_slice(&quote_pin.authority_key_id);
            output.extend_from_slice(&quote_pin.authority_account);
            output.extend_from_slice(&quote_pin.qualification_epoch.to_be_bytes());
        }
        if output.len() != capacity {
            return Err(QRunV06ProfilePinError::Malformed);
        }
        Ok(output)
    }

    /// Decode only when the complete file commitment is supplied independently by the caller.
    ///
    /// Do not pass a commitment read from the same untrusted file or data directory. The caller
    /// must obtain it from a separately administered profile registry, protected local trust
    /// store, signed deployment record, or another explicitly reviewed source.
    pub fn decode_pinned(
        bytes: &[u8],
        expected_profile_pin_commitment: [u8; 32],
    ) -> Result<Self, QRunV06ProfilePinError> {
        if expected_profile_pin_commitment == [0; 32] {
            return Err(QRunV06ProfilePinError::MissingIndependentCommitment);
        }
        if bytes.len() != QRUN_V06_PROFILE_PIN_BYTES && bytes.len() != QRUN_V06_PROFILE_PIN_V2_BYTES
        {
            return Err(QRunV06ProfilePinError::Malformed);
        }
        if Self::commitment_for_bytes(bytes) != expected_profile_pin_commitment {
            return Err(QRunV06ProfilePinError::ProfilePinCommitmentMismatch);
        }
        if &bytes[..4] != MAGIC {
            return Err(QRunV06ProfilePinError::Malformed);
        }
        let version = u16::from_be_bytes([bytes[4], bytes[5]]);
        if version != VERSION_V1 && version != VERSION_V2 {
            return Err(QRunV06ProfilePinError::UnsupportedVersion);
        }
        if (version == VERSION_V1 && bytes.len() != QRUN_V06_PROFILE_PIN_BYTES)
            || (version == VERSION_V2 && bytes.len() != QRUN_V06_PROFILE_PIN_V2_BYTES)
        {
            return Err(QRunV06ProfilePinError::Malformed);
        }
        if bytes[6..8] != [0, 0] {
            return Err(QRunV06ProfilePinError::NonzeroReserved);
        }

        let descriptor_start = HEADER_BYTES;
        let descriptor_end = descriptor_start + QRUN_V06_GENESIS_DESCRIPTOR_BYTES;
        let descriptor =
            QRunV06GenesisDescriptor::decode(&bytes[descriptor_start..descriptor_end])?;
        let mut cursor = descriptor_end;
        let provider_id = take_array::<32>(bytes, &mut cursor)?;
        let network_id = take_array::<32>(bytes, &mut cursor)?;
        let genesis_digest = take_array::<32>(bytes, &mut cursor)?;
        let receipt_key_id = take_array::<32>(bytes, &mut cursor)?;
        let receipt_public_key = take_array::<ML_DSA_65_PUBLIC_KEY_BYTES>(bytes, &mut cursor)?;
        let quote_asset_trust_pin = if version == VERSION_V2 {
            let q6qa_format_version = u16::from_be_bytes(take_array::<2>(bytes, &mut cursor)?);
            let q6qa_bundle_commitment = take_array::<32>(bytes, &mut cursor)?;
            let asset_id = take_array::<32>(bytes, &mut cursor)?;
            let authority_key_id = take_array::<32>(bytes, &mut cursor)?;
            let authority_account = take_array::<32>(bytes, &mut cursor)?;
            let qualification_epoch = u64::from_be_bytes(take_array::<8>(bytes, &mut cursor)?);
            Some(QRunV06QuoteAssetTrustPin::new(
                q6qa_format_version,
                q6qa_bundle_commitment,
                asset_id,
                authority_key_id,
                authority_account,
                qualification_epoch,
            )?)
        } else {
            None
        };
        if cursor != bytes.len() {
            return Err(QRunV06ProfilePinError::Malformed);
        }

        let bundle = Self {
            descriptor,
            external_cas_pin: ExternalCasPin {
                provider_id,
                network_id,
                genesis_digest,
                receipt_key_id,
                receipt_public_key,
            },
            quote_asset_trust_pin,
        };
        if bundle.encode()?.as_slice() != bytes {
            return Err(QRunV06ProfilePinError::Malformed);
        }
        Ok(bundle)
    }

    pub fn commitment(&self) -> Result<[u8; 32], QRunV06ProfilePinError> {
        Ok(Self::commitment_for_bytes(&self.encode()?))
    }

    fn commitment_for_bytes(bytes: &[u8]) -> [u8; 32] {
        let mut hash = Sha256::new();
        let domain = if bytes.get(4..6) == Some(VERSION_V2.to_be_bytes().as_slice()) {
            PROFILE_PIN_DOMAIN_V2
        } else {
            PROFILE_PIN_DOMAIN_V1
        };
        hash.update(domain);
        hash.update(bytes);
        hash.finalize().into()
    }

    pub fn descriptor(&self) -> &QRunV06GenesisDescriptor {
        &self.descriptor
    }

    pub fn external_cas_pin(&self) -> &ExternalCasPin {
        &self.external_cas_pin
    }

    pub fn quote_asset_trust_pin(&self) -> Option<&QRunV06QuoteAssetTrustPin> {
        self.quote_asset_trust_pin.as_ref()
    }

    pub fn genesis_descriptor_commitment(&self) -> [u8; 32] {
        self.descriptor.commitment()
    }

    pub fn into_external_anchor_pin(
        &self,
    ) -> Result<QRunV06ExternalAnchorPin, QRunV06ProfilePinError> {
        Ok(QRunV06ExternalAnchorPin::new(
            self.external_cas_pin.clone(),
            self.descriptor.commitment(),
        )?)
    }
}

/// A Q6PN bundle whose complete byte representation matched a commitment supplied by
/// the caller from a separately administered trust channel. This type does not discover,
/// persist, or authenticate that channel; the caller is responsible for its provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06VerifiedProfilePin {
    bundle: QRunV06ProfilePinCandidate,
    profile_pin_commitment: [u8; 32],
}

impl QRunV06VerifiedProfilePin {
    /// Verify Q6PN bytes against the independently provisioned commitment. Never derive the
    /// expected commitment from the same bytes or from a colocated data-directory manifest.
    pub fn decode(
        bytes: &[u8],
        independently_provisioned_commitment: [u8; 32],
    ) -> Result<Self, QRunV06ProfilePinError> {
        let bundle =
            QRunV06ProfilePinCandidate::decode_pinned(bytes, independently_provisioned_commitment)?;
        Ok(Self {
            bundle,
            profile_pin_commitment: independently_provisioned_commitment,
        })
    }

    pub fn bundle(&self) -> &QRunV06ProfilePinCandidate {
        &self.bundle
    }

    pub fn descriptor(&self) -> &QRunV06GenesisDescriptor {
        self.bundle.descriptor()
    }

    pub fn profile_pin_commitment(&self) -> [u8; 32] {
        self.profile_pin_commitment
    }

    pub fn quote_asset_trust_pin(&self) -> Option<&QRunV06QuoteAssetTrustPin> {
        self.bundle.quote_asset_trust_pin()
    }

    pub fn into_external_anchor_pin(
        &self,
    ) -> Result<QRunV06ExternalAnchorPin, QRunV06ProfilePinError> {
        self.bundle.into_external_anchor_pin()
    }
}

fn take_array<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], QRunV06ProfilePinError> {
    let end = cursor
        .checked_add(N)
        .ok_or(QRunV06ProfilePinError::Malformed)?;
    let output = bytes
        .get(*cursor..end)
        .ok_or(QRunV06ProfilePinError::Malformed)?
        .try_into()
        .map_err(|_| QRunV06ProfilePinError::Malformed)?;
    *cursor = end;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NETWORK: [u8; 32] = [0x11; 32];
    const PROFILE: [u8; 32] = [0x22; 32];
    const FOUNDER: [u8; 32] = [0x23; 32];
    const GENESIS_DIGEST: [u8; 32] = [0x24; 32];
    const CONSENSUS: [u8; 32] = [0x33; 32];
    const TOKENOMICS: [u8; 32] = [0x44; 32];

    fn sample_pin() -> QRunV06ProfilePinCandidate {
        let descriptor = QRunV06GenesisDescriptor::new(
            NETWORK,
            PROFILE,
            FOUNDER,
            1_800_000_000,
            CONSENSUS,
            TOKENOMICS,
        )
        .unwrap();
        let external_cas_pin = ExternalCasPin {
            provider_id: [0x51; 32],
            network_id: NETWORK,
            genesis_digest: GENESIS_DIGEST,
            receipt_key_id: [0x52; 32],
            receipt_public_key: [0x53; ML_DSA_65_PUBLIC_KEY_BYTES],
        };
        QRunV06ProfilePinCandidate::new(descriptor, external_cas_pin).unwrap()
    }

    #[test]
    fn q6pn_profile_pin_is_fixed_width_canonical_and_roundtrips() {
        let pin = sample_pin();
        let encoded = pin.encode().unwrap();
        assert_eq!(encoded.len(), QRUN_V06_PROFILE_PIN_BYTES);
        assert_eq!(&encoded[..4], b"Q6PN");
        assert_eq!(u16::from_be_bytes([encoded[4], encoded[5]]), 1);
        let commitment = pin.commitment().unwrap();
        assert_eq!(
            commitment,
            [
                0x45, 0x27, 0x5d, 0xeb, 0xb7, 0xc1, 0x0b, 0xcd, 0x5c, 0xb6, 0x10, 0x7b, 0xcb, 0x7e,
                0xf6, 0xc6, 0xf1, 0x85, 0x0d, 0x4b, 0x01, 0xd2, 0x5d, 0xf3, 0xee, 0x2a, 0x94, 0xe8,
                0x6f, 0x3a, 0xd9, 0x3a,
            ]
        );
        let decoded = QRunV06ProfilePinCandidate::decode_pinned(&encoded, commitment).unwrap();
        assert_eq!(decoded, pin);
        assert_eq!(
            decoded.genesis_descriptor_commitment(),
            pin.descriptor().commitment()
        );
        let anchor_pin = decoded.into_external_anchor_pin().unwrap();
        assert_eq!(
            anchor_pin.genesis_descriptor_commitment(),
            pin.descriptor().commitment()
        );
        assert_eq!(anchor_pin.external_cas_pin(), pin.external_cas_pin());
    }

    #[test]
    fn q6pn_refuses_missing_wrong_or_self_changed_external_commitment() {
        let pin = sample_pin();
        let encoded = pin.encode().unwrap();
        let commitment = pin.commitment().unwrap();
        assert!(matches!(
            QRunV06ProfilePinCandidate::decode_pinned(&encoded, [0; 32]),
            Err(QRunV06ProfilePinError::MissingIndependentCommitment)
        ));
        let mut wrong_commitment = commitment;
        wrong_commitment[0] ^= 1;
        assert!(matches!(
            QRunV06ProfilePinCandidate::decode_pinned(&encoded, wrong_commitment),
            Err(QRunV06ProfilePinError::ProfilePinCommitmentMismatch)
        ));
        let mut tampered = encoded;
        tampered[HEADER_BYTES + 16] ^= 1;
        assert!(matches!(
            QRunV06ProfilePinCandidate::decode_pinned(&tampered, commitment),
            Err(QRunV06ProfilePinError::ProfilePinCommitmentMismatch)
        ));
    }

    #[test]
    fn q6pn_binds_provider_key_and_legacy_genesis_identity_to_profile() {
        let pin = sample_pin();
        let original = pin.commitment().unwrap();
        let mut provider = pin.external_cas_pin().clone();
        provider.provider_id[0] ^= 1;
        let altered = QRunV06ProfilePinCandidate::new(*pin.descriptor(), provider).unwrap();
        assert_ne!(altered.commitment().unwrap(), original);

        let mut provider = pin.external_cas_pin().clone();
        provider.receipt_key_id[0] ^= 1;
        let altered = QRunV06ProfilePinCandidate::new(*pin.descriptor(), provider).unwrap();
        assert_ne!(altered.commitment().unwrap(), original);

        let mut provider = pin.external_cas_pin().clone();
        provider.genesis_digest[0] ^= 1;
        let altered = QRunV06ProfilePinCandidate::new(*pin.descriptor(), provider).unwrap();
        assert_ne!(altered.commitment().unwrap(), original);
    }

    #[test]
    fn q6pn_rejects_external_provider_network_mismatch() {
        let descriptor = QRunV06GenesisDescriptor::new(
            NETWORK,
            PROFILE,
            FOUNDER,
            1_800_000_000,
            CONSENSUS,
            TOKENOMICS,
        )
        .unwrap();
        let provider = ExternalCasPin {
            provider_id: [0x51; 32],
            network_id: [0x61; 32],
            genesis_digest: GENESIS_DIGEST,
            receipt_key_id: [0x52; 32],
            receipt_public_key: [0x53; ML_DSA_65_PUBLIC_KEY_BYTES],
        };
        assert!(matches!(
            QRunV06ProfilePinCandidate::new(descriptor, provider),
            Err(QRunV06ProfilePinError::WrongNetwork)
        ));
    }

    #[test]
    fn q6pn_rejects_version_and_reserved_byte_mutations_when_commitment_is_recomputed() {
        let pin = sample_pin();
        let mut encoded = pin.encode().unwrap();
        encoded[5] = 3;
        let commitment = QRunV06ProfilePinCandidate::commitment_for_bytes(&encoded);
        assert!(matches!(
            QRunV06ProfilePinCandidate::decode_pinned(&encoded, commitment),
            Err(QRunV06ProfilePinError::UnsupportedVersion)
        ));

        let mut encoded = pin.encode().unwrap();
        encoded[7] = 1;
        let commitment = QRunV06ProfilePinCandidate::commitment_for_bytes(&encoded);
        assert!(matches!(
            QRunV06ProfilePinCandidate::decode_pinned(&encoded, commitment),
            Err(QRunV06ProfilePinError::NonzeroReserved)
        ));
    }

    #[test]
    fn q6pn_v2_cross_language_golden_vector() {
        let pin = sample_pin();
        let quote_pin =
            QRunV06QuoteAssetTrustPin::new(1, [0x71; 32], [0x72; 32], [0x73; 32], [0x74; 32], 9)
                .unwrap();
        let v2 = QRunV06ProfilePinCandidate::new_with_quote_asset_trust_pin(
            *pin.descriptor(),
            pin.external_cas_pin().clone(),
            quote_pin,
        )
        .unwrap();
        assert_eq!(
            v2.descriptor().commitment(),
            [
                0xc5, 0x51, 0x71, 0xf1, 0x64, 0xa1, 0x2f, 0xb8, 0xee, 0x4e, 0x70, 0xbc, 0x0b, 0x51,
                0xa0, 0x8f, 0xe0, 0x76, 0x44, 0x40, 0xfc, 0xe9, 0x5a, 0xf7, 0xa6, 0x94, 0xda, 0xd4,
                0xc0, 0x52, 0xe0, 0x70,
            ]
        );
        assert_eq!(v2.encode().unwrap().len(), 2432);
        assert_eq!(
            v2.commitment().unwrap(),
            [
                0x4f, 0x1f, 0x28, 0x7c, 0x41, 0xcc, 0x27, 0xf9, 0xe8, 0xde, 0x20, 0xde, 0xed, 0x91,
                0x91, 0xd8, 0xea, 0xad, 0x07, 0xfe, 0x93, 0x6f, 0x63, 0x31, 0x3d, 0x47, 0x45, 0x8d,
                0x01, 0x6c, 0x8d, 0x89,
            ]
        );
    }

    #[test]
    fn q6pn_v2_binds_q6qa_commitment_authority_asset_and_epoch() {
        let pin = sample_pin();
        let quote_pin =
            QRunV06QuoteAssetTrustPin::new(1, [0x71; 32], [0x72; 32], [0x73; 32], [0x74; 32], 9)
                .unwrap();
        let v2 = QRunV06ProfilePinCandidate::new_with_quote_asset_trust_pin(
            *pin.descriptor(),
            pin.external_cas_pin().clone(),
            quote_pin.clone(),
        )
        .unwrap();
        let bytes = v2.encode().unwrap();
        assert_eq!(bytes.len(), QRUN_V06_PROFILE_PIN_V2_BYTES);
        assert_eq!(u16::from_be_bytes([bytes[4], bytes[5]]), VERSION_V2);
        let commitment = v2.commitment().unwrap();
        let decoded = QRunV06ProfilePinCandidate::decode_pinned(&bytes, commitment).unwrap();
        assert_eq!(decoded, v2);
        assert_eq!(decoded.quote_asset_trust_pin(), Some(&quote_pin));
        let verified = QRunV06VerifiedProfilePin::decode(&bytes, commitment).unwrap();
        assert_eq!(verified.quote_asset_trust_pin(), Some(&quote_pin));

        let altered =
            QRunV06QuoteAssetTrustPin::new(1, [0x75; 32], [0x72; 32], [0x73; 32], [0x74; 32], 9)
                .unwrap();
        let changed = QRunV06ProfilePinCandidate::new_with_quote_asset_trust_pin(
            *pin.descriptor(),
            pin.external_cas_pin().clone(),
            altered,
        )
        .unwrap();
        assert_ne!(changed.commitment().unwrap(), commitment);

        let altered_epoch =
            QRunV06QuoteAssetTrustPin::new(1, [0x71; 32], [0x72; 32], [0x73; 32], [0x74; 32], 10)
                .unwrap();
        let changed = QRunV06ProfilePinCandidate::new_with_quote_asset_trust_pin(
            *pin.descriptor(),
            pin.external_cas_pin().clone(),
            altered_epoch,
        )
        .unwrap();
        assert_ne!(changed.commitment().unwrap(), commitment);
    }

    #[test]
    fn q6pn_v2_rejects_invalid_quote_asset_trust_pin_context() {
        assert!(matches!(
            QRunV06QuoteAssetTrustPin::new(2, [0x71; 32], [0x72; 32], [0x73; 32], [0x74; 32], 9,),
            Err(QRunV06ProfilePinError::InvalidQuoteAssetTrustPin)
        ));
        assert!(matches!(
            QRunV06QuoteAssetTrustPin::new(1, [0; 32], [0x72; 32], [0x73; 32], [0x74; 32], 9,),
            Err(QRunV06ProfilePinError::InvalidQuoteAssetTrustPin)
        ));
        let pin = sample_pin();
        let quote_pin =
            QRunV06QuoteAssetTrustPin::new(1, [0x71; 32], [0x72; 32], [0x73; 32], [0x74; 32], 9)
                .unwrap();
        let bundle = QRunV06ProfilePinCandidate::new_with_quote_asset_trust_pin(
            *pin.descriptor(),
            pin.external_cas_pin().clone(),
            quote_pin,
        )
        .unwrap();
        let bytes = bundle.encode().unwrap();
        let mut tampered = bytes.clone();
        tampered[QRUN_V06_PROFILE_PIN_BYTES + 1] ^= 3;
        let recomputed = QRunV06ProfilePinCandidate::commitment_for_bytes(&tampered);
        assert!(matches!(
            QRunV06ProfilePinCandidate::decode_pinned(&tampered, recomputed),
            Err(QRunV06ProfilePinError::InvalidQuoteAssetTrustPin)
        ));
    }

    #[test]
    fn q6pn_verified_wrapper_retains_only_the_independently_matched_commitment() {
        let pin = sample_pin();
        let encoded = pin.encode().unwrap();
        let commitment = pin.commitment().unwrap();
        let verified = QRunV06VerifiedProfilePin::decode(&encoded, commitment).unwrap();
        assert_eq!(verified.bundle(), &pin);
        assert_eq!(verified.descriptor(), pin.descriptor());
        assert_eq!(verified.profile_pin_commitment(), commitment);
        assert_eq!(
            verified.into_external_anchor_pin().unwrap(),
            pin.into_external_anchor_pin().unwrap()
        );

        let mut wrong = commitment;
        wrong[31] ^= 1;
        assert!(matches!(
            QRunV06VerifiedProfilePin::decode(&encoded, wrong),
            Err(QRunV06ProfilePinError::ProfilePinCommitmentMismatch)
        ));
    }
}
