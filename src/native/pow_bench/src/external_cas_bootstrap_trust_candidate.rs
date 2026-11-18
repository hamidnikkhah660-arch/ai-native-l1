//! CP-0761: versioned, dual-attested bootstrap trust receipt candidate.
//!
//! This module verifies the initial trust enrollment for the existing ECR1/ECS1 Provider and
//! QAR1 off-host Anchor contracts. It deliberately does not mutate or extend those V1 wire
//! formats, enroll real keys, provision an Anchor, or claim independent custody. The expected
//! receipt digest and all signer pins must arrive through an independently authenticated
//! out-of-band channel before this verifier is called.
use crate::{
    external_cas_anchor_candidate::{ExternalCasPin, ExternalCasRecord},
    external_cas_offhost_anchor_candidate::ExternalCasOffhostAnchorState,
    external_cas_offhost_anchor_protocol_candidate::ExternalCasOffhostAnchorPin,
    v4_fat1_trust_candidate::{
        MlDsa65Verifier, ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SIGNATURE_BYTES,
    },
};
use sha2::{Digest, Sha256};
use std::fmt;

type Digest32 = [u8; 32];

pub const BOOTSTRAP_TRUST_RECEIPT_PAYLOAD_BYTES: usize = 560;
pub const BOOTSTRAP_TRUST_RECEIPT_BYTES: usize =
    BOOTSTRAP_TRUST_RECEIPT_PAYLOAD_BYTES + (2 * ML_DSA_65_SIGNATURE_BYTES);
pub const BOOTSTRAP_TRUST_RECEIPT_VERSION: u16 = 1;

const RECEIPT_MAGIC: &[u8; 4] = b"QBT1";
const FLAGS_V1: u16 = 0;
const OWNER_ROLE: u16 = 1;
const INDEPENDENT_CUSTODIAN_ROLE: u16 = 2;
const ML_DSA_65_ALGORITHM: u16 = 1;
const RESERVED_V1: u16 = 0;

const OWNER_SIGNING_DOMAIN: &[u8] = b"QRUN-BOOTSTRAP-TRUST-OWNER-ACCEPT-V1\0";
const CUSTODIAN_SIGNING_DOMAIN: &[u8] = b"QRUN-BOOTSTRAP-TRUST-INDEPENDENT-CUSTODIAN-ACCEPT-V1\0";
const RECEIPT_DIGEST_DOMAIN: &[u8] = b"QRUN-BOOTSTRAP-TRUST-RECEIPT-DIGEST-V1\0";
const KEY_FINGERPRINT_DOMAIN: &[u8] = b"QRUN-BOOTSTRAP-TRUST-MLDSA65-KEY-FINGERPRINT-V1\0";

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn hash_parts(parts: &[&[u8]]) -> Digest32 {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn take<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    bytes[offset..offset + N]
        .try_into()
        .expect("fixed length checked")
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(take(bytes, offset))
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(take(bytes, offset))
}

/// Stable fingerprint of the complete ML-DSA-65 public-key encoding.
/// Key IDs remain separately assigned identifiers and are never treated as key material.
pub fn mldsa65_key_fingerprint(public_key: &[u8; ML_DSA_65_PUBLIC_KEY_BYTES]) -> Digest32 {
    hash_parts(&[KEY_FINGERPRINT_DOMAIN, public_key])
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapTrustError {
    WrongReceiptLength,
    WrongMagic,
    UnsupportedVersion,
    NoncanonicalHeader,
    InvalidReceiptShape,
    InvalidOutOfBandPin,
    InvalidProviderPin,
    InvalidAnchorPin,
    InvalidBootstrapRecord,
    InvalidInitialAnchorState,
    WrongReceiptDigest,
    WrongTrustDomain,
    SignerIdentityCollision,
    SignerKeyReuse,
    InvalidOwnerSignature,
    InvalidCustodianSignature,
}

impl fmt::Display for BootstrapTrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for BootstrapTrustError {}

/// Independently supplied trust inputs. This is configuration, not data parsed from QBT1.
///
/// expected_receipt_digest, profile_digest, the two signer IDs/public keys, and both initial
/// state digests must be provisioned through a separately authenticated channel. Constructing this
/// value from the QBT1 bytes or from a writable node directory defeats its trust purpose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapTrustPin {
    pub expected_receipt_digest: Digest32,
    pub profile_digest: Digest32,
    pub initial_record_digest: Digest32,
    pub initial_anchor_state_digest: Digest32,
    pub owner_signer_id: Digest32,
    pub owner_public_key: [u8; ML_DSA_65_PUBLIC_KEY_BYTES],
    pub independent_custodian_signer_id: Digest32,
    pub independent_custodian_public_key: [u8; ML_DSA_65_PUBLIC_KEY_BYTES],
}

impl BootstrapTrustPin {
    fn validate(
        &self,
        provider: &ExternalCasPin,
        anchor: &ExternalCasOffhostAnchorPin,
        bootstrap_record: &ExternalCasRecord,
    ) -> Result<ExternalCasOffhostAnchorState, BootstrapTrustError> {
        provider
            .validate()
            .map_err(|_| BootstrapTrustError::InvalidProviderPin)?;
        anchor
            .validate(provider)
            .map_err(|_| BootstrapTrustError::InvalidAnchorPin)?;

        for value in [
            &self.expected_receipt_digest[..],
            &self.profile_digest[..],
            &self.initial_record_digest[..],
            &self.initial_anchor_state_digest[..],
            &self.owner_signer_id[..],
            &self.independent_custodian_signer_id[..],
            &self.owner_public_key[..],
            &self.independent_custodian_public_key[..],
        ] {
            if is_zero(value) {
                return Err(BootstrapTrustError::InvalidOutOfBandPin);
            }
        }

        if self.owner_signer_id == self.independent_custodian_signer_id
            || self.owner_signer_id == provider.receipt_key_id
            || self.owner_signer_id == anchor.receipt_key_id
            || self.independent_custodian_signer_id == provider.receipt_key_id
            || self.independent_custodian_signer_id == anchor.receipt_key_id
            || provider.receipt_key_id == anchor.receipt_key_id
        {
            return Err(BootstrapTrustError::SignerIdentityCollision);
        }

        if self.owner_public_key == self.independent_custodian_public_key
            || self.owner_public_key == provider.receipt_public_key
            || self.owner_public_key == anchor.receipt_public_key
            || self.independent_custodian_public_key == provider.receipt_public_key
            || self.independent_custodian_public_key == anchor.receipt_public_key
            || provider.receipt_public_key == anchor.receipt_public_key
        {
            return Err(BootstrapTrustError::SignerKeyReuse);
        }

        if bootstrap_record.validate_shape().is_err()
            || bootstrap_record.generation != 0
            || bootstrap_record.provider_id != provider.provider_id
            || bootstrap_record.network_id != provider.network_id
            || bootstrap_record.genesis_digest != provider.genesis_digest
        {
            return Err(BootstrapTrustError::InvalidBootstrapRecord);
        }

        if bootstrap_record.digest().ok() != Some(self.initial_record_digest) {
            return Err(BootstrapTrustError::InvalidBootstrapRecord);
        }

        let initial_anchor_state = ExternalCasOffhostAnchorState::provision_bootstrap(
            provider,
            bootstrap_record.clone(),
            1,
        )
        .map_err(|_| BootstrapTrustError::InvalidInitialAnchorState)?;

        if initial_anchor_state.sequence != 1
            || initial_anchor_state.provider_object_generation != 1
            || initial_anchor_state.provider_record.generation != 0
            || initial_anchor_state.digest().ok() != Some(self.initial_anchor_state_digest)
        {
            return Err(BootstrapTrustError::InvalidInitialAnchorState);
        }

        Ok(initial_anchor_state)
    }
}

/// Canonical QBT1 payload plus two role-specific ML-DSA-65 signatures.
///
/// The role order is fixed: owner first, independently administered custodian second. Both
/// signatures cover the same canonical payload, with separate role-domain prefixes. The signed
/// payload carries no timestamps; time is not used as a substitute for an external trust pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapTrustReceipt {
    pub bootstrap_generation: u64,
    pub provider_record_generation: u64,
    pub provider_object_generation: u64,
    pub anchor_sequence: u64,

    pub provider_id: Digest32,
    pub anchor_id: Digest32,
    pub network_id: Digest32,
    pub profile_digest: Digest32,
    pub genesis_digest: Digest32,

    pub provider_receipt_key_id: Digest32,
    pub provider_receipt_key_fingerprint: Digest32,
    pub anchor_receipt_key_id: Digest32,
    pub anchor_receipt_key_fingerprint: Digest32,

    pub owner_signer_id: Digest32,
    pub owner_key_fingerprint: Digest32,
    pub independent_custodian_signer_id: Digest32,
    pub independent_custodian_key_fingerprint: Digest32,

    pub initial_record_digest: Digest32,
    pub initial_record_state_digest: Digest32,
    pub initial_anchor_state_digest: Digest32,

    pub owner_signature: [u8; ML_DSA_65_SIGNATURE_BYTES],
    pub independent_custodian_signature: [u8; ML_DSA_65_SIGNATURE_BYTES],
}

impl BootstrapTrustReceipt {
    fn validate_shape(&self) -> Result<(), BootstrapTrustError> {
        if self.bootstrap_generation != 1
            || self.provider_record_generation != 0
            || self.provider_object_generation != 1
            || self.anchor_sequence != 1
        {
            return Err(BootstrapTrustError::InvalidReceiptShape);
        }

        for value in [
            &self.provider_id[..],
            &self.anchor_id[..],
            &self.network_id[..],
            &self.profile_digest[..],
            &self.genesis_digest[..],
            &self.provider_receipt_key_id[..],
            &self.provider_receipt_key_fingerprint[..],
            &self.anchor_receipt_key_id[..],
            &self.anchor_receipt_key_fingerprint[..],
            &self.owner_signer_id[..],
            &self.owner_key_fingerprint[..],
            &self.independent_custodian_signer_id[..],
            &self.independent_custodian_key_fingerprint[..],
            &self.initial_record_digest[..],
            &self.initial_record_state_digest[..],
            &self.initial_anchor_state_digest[..],
        ] {
            if is_zero(value) {
                return Err(BootstrapTrustError::InvalidReceiptShape);
            }
        }

        if self.owner_signer_id == self.independent_custodian_signer_id
            || self.owner_key_fingerprint == self.independent_custodian_key_fingerprint
            || self.provider_receipt_key_id == self.anchor_receipt_key_id
            || self.owner_signer_id == self.provider_receipt_key_id
            || self.owner_signer_id == self.anchor_receipt_key_id
            || self.independent_custodian_signer_id == self.provider_receipt_key_id
            || self.independent_custodian_signer_id == self.anchor_receipt_key_id
        {
            return Err(BootstrapTrustError::SignerIdentityCollision);
        }

        if self.owner_key_fingerprint == self.provider_receipt_key_fingerprint
            || self.owner_key_fingerprint == self.anchor_receipt_key_fingerprint
            || self.independent_custodian_key_fingerprint == self.provider_receipt_key_fingerprint
            || self.independent_custodian_key_fingerprint == self.anchor_receipt_key_fingerprint
            || self.provider_receipt_key_fingerprint == self.anchor_receipt_key_fingerprint
        {
            return Err(BootstrapTrustError::SignerKeyReuse);
        }

        Ok(())
    }

    fn canonical_payload(
        &self,
    ) -> Result<[u8; BOOTSTRAP_TRUST_RECEIPT_PAYLOAD_BYTES], BootstrapTrustError> {
        self.validate_shape()?;
        let mut out = Vec::with_capacity(BOOTSTRAP_TRUST_RECEIPT_PAYLOAD_BYTES);
        out.extend_from_slice(RECEIPT_MAGIC);
        out.extend_from_slice(&BOOTSTRAP_TRUST_RECEIPT_VERSION.to_be_bytes());
        out.extend_from_slice(&FLAGS_V1.to_be_bytes());
        out.extend_from_slice(&OWNER_ROLE.to_be_bytes());
        out.extend_from_slice(&INDEPENDENT_CUSTODIAN_ROLE.to_be_bytes());
        out.extend_from_slice(&ML_DSA_65_ALGORITHM.to_be_bytes());
        out.extend_from_slice(&RESERVED_V1.to_be_bytes());

        out.extend_from_slice(&self.bootstrap_generation.to_be_bytes());
        out.extend_from_slice(&self.provider_record_generation.to_be_bytes());
        out.extend_from_slice(&self.provider_object_generation.to_be_bytes());
        out.extend_from_slice(&self.anchor_sequence.to_be_bytes());

        for digest in [
            &self.provider_id,
            &self.anchor_id,
            &self.network_id,
            &self.profile_digest,
            &self.genesis_digest,
            &self.provider_receipt_key_id,
            &self.provider_receipt_key_fingerprint,
            &self.anchor_receipt_key_id,
            &self.anchor_receipt_key_fingerprint,
            &self.owner_signer_id,
            &self.owner_key_fingerprint,
            &self.independent_custodian_signer_id,
            &self.independent_custodian_key_fingerprint,
            &self.initial_record_digest,
            &self.initial_record_state_digest,
            &self.initial_anchor_state_digest,
        ] {
            out.extend_from_slice(digest);
        }

        out.try_into()
            .map_err(|_| BootstrapTrustError::WrongReceiptLength)
    }

    pub fn owner_signing_digest(&self) -> Result<Digest32, BootstrapTrustError> {
        Ok(hash_parts(&[
            OWNER_SIGNING_DOMAIN,
            &self.canonical_payload()?,
        ]))
    }

    pub fn independent_custodian_signing_digest(&self) -> Result<Digest32, BootstrapTrustError> {
        Ok(hash_parts(&[
            CUSTODIAN_SIGNING_DOMAIN,
            &self.canonical_payload()?,
        ]))
    }

    pub fn encode(&self) -> Result<Vec<u8>, BootstrapTrustError> {
        let payload = self.canonical_payload()?;
        let mut out = Vec::with_capacity(BOOTSTRAP_TRUST_RECEIPT_BYTES);
        out.extend_from_slice(&payload);
        out.extend_from_slice(&self.owner_signature);
        out.extend_from_slice(&self.independent_custodian_signature);
        if out.len() != BOOTSTRAP_TRUST_RECEIPT_BYTES {
            return Err(BootstrapTrustError::WrongReceiptLength);
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, BootstrapTrustError> {
        if bytes.len() != BOOTSTRAP_TRUST_RECEIPT_BYTES {
            return Err(BootstrapTrustError::WrongReceiptLength);
        }
        if &bytes[..4] != RECEIPT_MAGIC {
            return Err(BootstrapTrustError::WrongMagic);
        }
        if u16_at(bytes, 4) != BOOTSTRAP_TRUST_RECEIPT_VERSION {
            return Err(BootstrapTrustError::UnsupportedVersion);
        }
        if u16_at(bytes, 6) != FLAGS_V1
            || u16_at(bytes, 8) != OWNER_ROLE
            || u16_at(bytes, 10) != INDEPENDENT_CUSTODIAN_ROLE
            || u16_at(bytes, 12) != ML_DSA_65_ALGORITHM
            || u16_at(bytes, 14) != RESERVED_V1
        {
            return Err(BootstrapTrustError::NoncanonicalHeader);
        }

        let receipt = Self {
            bootstrap_generation: u64_at(bytes, 16),
            provider_record_generation: u64_at(bytes, 24),
            provider_object_generation: u64_at(bytes, 32),
            anchor_sequence: u64_at(bytes, 40),

            provider_id: take(bytes, 48),
            anchor_id: take(bytes, 80),
            network_id: take(bytes, 112),
            profile_digest: take(bytes, 144),
            genesis_digest: take(bytes, 176),

            provider_receipt_key_id: take(bytes, 208),
            provider_receipt_key_fingerprint: take(bytes, 240),
            anchor_receipt_key_id: take(bytes, 272),
            anchor_receipt_key_fingerprint: take(bytes, 304),

            owner_signer_id: take(bytes, 336),
            owner_key_fingerprint: take(bytes, 368),
            independent_custodian_signer_id: take(bytes, 400),
            independent_custodian_key_fingerprint: take(bytes, 432),

            initial_record_digest: take(bytes, 464),
            initial_record_state_digest: take(bytes, 496),
            initial_anchor_state_digest: take(bytes, 528),

            owner_signature: take(bytes, BOOTSTRAP_TRUST_RECEIPT_PAYLOAD_BYTES),
            independent_custodian_signature: take(
                bytes,
                BOOTSTRAP_TRUST_RECEIPT_PAYLOAD_BYTES + ML_DSA_65_SIGNATURE_BYTES,
            ),
        };
        if receipt.canonical_payload()?.as_slice()
            != &bytes[..BOOTSTRAP_TRUST_RECEIPT_PAYLOAD_BYTES]
        {
            return Err(BootstrapTrustError::NoncanonicalHeader);
        }
        Ok(receipt)
    }

    pub fn digest(&self) -> Result<Digest32, BootstrapTrustError> {
        let encoded = self.encode()?;
        Ok(hash_parts(&[RECEIPT_DIGEST_DOMAIN, &encoded]))
    }

    fn verify_against_pins<V: MlDsa65Verifier>(
        &self,
        trust_pin: &BootstrapTrustPin,
        provider: &ExternalCasPin,
        anchor: &ExternalCasOffhostAnchorPin,
        bootstrap_record: &ExternalCasRecord,
        verifier: &V,
    ) -> Result<ExternalCasOffhostAnchorState, BootstrapTrustError> {
        let initial_state = trust_pin.validate(provider, anchor, bootstrap_record)?;

        if self.digest()? != trust_pin.expected_receipt_digest {
            return Err(BootstrapTrustError::WrongReceiptDigest);
        }

        let expected_provider_fp = mldsa65_key_fingerprint(&provider.receipt_public_key);
        let expected_anchor_fp = mldsa65_key_fingerprint(&anchor.receipt_public_key);
        let expected_owner_fp = mldsa65_key_fingerprint(&trust_pin.owner_public_key);
        let expected_custodian_fp =
            mldsa65_key_fingerprint(&trust_pin.independent_custodian_public_key);

        if self.bootstrap_generation != 1
            || self.provider_record_generation != 0
            || self.provider_object_generation != 1
            || self.anchor_sequence != 1
            || self.provider_id != provider.provider_id
            || self.anchor_id != anchor.anchor_id
            || self.network_id != provider.network_id
            || self.profile_digest != trust_pin.profile_digest
            || self.genesis_digest != provider.genesis_digest
            || self.provider_receipt_key_id != provider.receipt_key_id
            || self.provider_receipt_key_fingerprint != expected_provider_fp
            || self.anchor_receipt_key_id != anchor.receipt_key_id
            || self.anchor_receipt_key_fingerprint != expected_anchor_fp
            || self.owner_signer_id != trust_pin.owner_signer_id
            || self.owner_key_fingerprint != expected_owner_fp
            || self.independent_custodian_signer_id != trust_pin.independent_custodian_signer_id
            || self.independent_custodian_key_fingerprint != expected_custodian_fp
            || self.initial_record_digest != trust_pin.initial_record_digest
            || self.initial_record_state_digest != bootstrap_record.next_state_digest
            || self.initial_anchor_state_digest != trust_pin.initial_anchor_state_digest
        {
            return Err(BootstrapTrustError::WrongTrustDomain);
        }

        if !verifier.verify(
            &trust_pin.owner_public_key,
            &self.owner_signing_digest()?,
            &self.owner_signature,
        ) {
            return Err(BootstrapTrustError::InvalidOwnerSignature);
        }

        if !verifier.verify(
            &trust_pin.independent_custodian_public_key,
            &self.independent_custodian_signing_digest()?,
            &self.independent_custodian_signature,
        ) {
            return Err(BootstrapTrustError::InvalidCustodianSignature);
        }

        Ok(initial_state)
    }
}

/// A successful pure verification result. This is not proof that the pin itself came from an
/// independent custodian; that provenance is an operational prerequisite outside this module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedBootstrapTrust {
    // Private fields seal this value as a capability produced only by successful verification.
    receipt: BootstrapTrustReceipt,
    initial_anchor_state: ExternalCasOffhostAnchorState,
    receipt_digest: Digest32,
}
impl VerifiedBootstrapTrust {
    pub fn receipt(&self) -> &BootstrapTrustReceipt {
        &self.receipt
    }

    pub fn initial_anchor_state(&self) -> &ExternalCasOffhostAnchorState {
        &self.initial_anchor_state
    }

    pub fn receipt_digest(&self) -> Digest32 {
        self.receipt_digest
    }

    pub fn receipt_wire(&self) -> Result<Vec<u8>, BootstrapTrustError> {
        self.receipt.encode()
    }
}

/// Verify an exact, externally pinned QBT1 bootstrap receipt against the existing Provider and
/// Anchor V1 pins and the exact ECR1 generation-zero record. No storage, network, key enrollment,
/// fallback, CAS, or mutation occurs here.
pub fn verify_bootstrap_trust_receipt<V: MlDsa65Verifier>(
    receipt_bytes: &[u8],
    trust_pin: &BootstrapTrustPin,
    provider: &ExternalCasPin,
    anchor: &ExternalCasOffhostAnchorPin,
    bootstrap_record: &ExternalCasRecord,
    verifier: &V,
) -> Result<VerifiedBootstrapTrust, BootstrapTrustError> {
    let receipt = BootstrapTrustReceipt::decode(receipt_bytes)?;
    let initial_anchor_state =
        receipt.verify_against_pins(trust_pin, provider, anchor, bootstrap_record, verifier)?;
    let receipt_digest = receipt.digest()?;
    Ok(VerifiedBootstrapTrust {
        receipt,
        initial_anchor_state,
        receipt_digest,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate;
    use libcrux_ml_dsa::ml_dsa_65::portable;

    struct Fixture {
        provider: ExternalCasPin,
        anchor: ExternalCasOffhostAnchorPin,
        bootstrap: ExternalCasRecord,
        pin: BootstrapTrustPin,
        receipt: BootstrapTrustReceipt,
    }

    fn fixture() -> Fixture {
        // Deterministic keys are fixtures only and do not establish real-world custody separation.
        let provider_keys = portable::generate_key_pair([0x11; 32]);
        let anchor_keys = portable::generate_key_pair([0x22; 32]);
        let owner_keys = portable::generate_key_pair([0x33; 32]);
        let custodian_keys = portable::generate_key_pair([0x44; 32]);

        let provider_public: [u8; ML_DSA_65_PUBLIC_KEY_BYTES] =
            *provider_keys.verification_key.as_ref();
        let anchor_public: [u8; ML_DSA_65_PUBLIC_KEY_BYTES] =
            *anchor_keys.verification_key.as_ref();
        let owner_public: [u8; ML_DSA_65_PUBLIC_KEY_BYTES] = *owner_keys.verification_key.as_ref();
        let custodian_public: [u8; ML_DSA_65_PUBLIC_KEY_BYTES] =
            *custodian_keys.verification_key.as_ref();

        let provider = ExternalCasPin {
            provider_id: [0x51; 32],
            network_id: [0x52; 32],
            genesis_digest: [0x53; 32],
            receipt_key_id: [0x54; 32],
            receipt_public_key: provider_public,
        };
        let anchor = ExternalCasOffhostAnchorPin {
            anchor_id: [0x61; 32],
            provider_id: provider.provider_id,
            network_id: provider.network_id,
            genesis_digest: provider.genesis_digest,
            receipt_key_id: [0x62; 32],
            receipt_public_key: anchor_public,
        };
        let bootstrap = ExternalCasRecord {
            generation: 0,
            provider_id: provider.provider_id,
            network_id: provider.network_id,
            genesis_digest: provider.genesis_digest,
            previous_record_digest: [0; 32],
            previous_state_digest: [0; 32],
            next_state_digest: [0x71; 32],
            operation_id: [0x72; 32],
            request_digest: [0x73; 32],
        };
        let initial_anchor_state =
            ExternalCasOffhostAnchorState::provision_bootstrap(&provider, bootstrap.clone(), 1)
                .unwrap();

        let mut receipt = BootstrapTrustReceipt {
            bootstrap_generation: 1,
            provider_record_generation: 0,
            provider_object_generation: 1,
            anchor_sequence: 1,
            provider_id: provider.provider_id,
            anchor_id: anchor.anchor_id,
            network_id: provider.network_id,
            profile_digest: [0x81; 32],
            genesis_digest: provider.genesis_digest,
            provider_receipt_key_id: provider.receipt_key_id,
            provider_receipt_key_fingerprint: mldsa65_key_fingerprint(&provider.receipt_public_key),
            anchor_receipt_key_id: anchor.receipt_key_id,
            anchor_receipt_key_fingerprint: mldsa65_key_fingerprint(&anchor.receipt_public_key),
            owner_signer_id: [0x91; 32],
            owner_key_fingerprint: mldsa65_key_fingerprint(&owner_public),
            independent_custodian_signer_id: [0x92; 32],
            independent_custodian_key_fingerprint: mldsa65_key_fingerprint(&custodian_public),
            initial_record_digest: bootstrap.digest().unwrap(),
            initial_record_state_digest: bootstrap.next_state_digest,
            initial_anchor_state_digest: initial_anchor_state.digest().unwrap(),
            owner_signature: [0; ML_DSA_65_SIGNATURE_BYTES],
            independent_custodian_signature: [0; ML_DSA_65_SIGNATURE_BYTES],
        };

        let owner_digest = receipt.owner_signing_digest().unwrap();
        receipt.owner_signature =
            *portable::sign(&owner_keys.signing_key, &owner_digest, &[], [0xA1; 32])
                .unwrap()
                .as_ref();

        let custodian_digest = receipt.independent_custodian_signing_digest().unwrap();
        receipt.independent_custodian_signature = *portable::sign(
            &custodian_keys.signing_key,
            &custodian_digest,
            &[],
            [0xA2; 32],
        )
        .unwrap()
        .as_ref();

        let pin = BootstrapTrustPin {
            expected_receipt_digest: receipt.digest().unwrap(),
            profile_digest: receipt.profile_digest,
            initial_record_digest: receipt.initial_record_digest,
            initial_anchor_state_digest: receipt.initial_anchor_state_digest,
            owner_signer_id: receipt.owner_signer_id,
            owner_public_key: owner_public,
            independent_custodian_signer_id: receipt.independent_custodian_signer_id,
            independent_custodian_public_key: custodian_public,
        };

        Fixture {
            provider,
            anchor,
            bootstrap,
            pin,
            receipt,
        }
    }

    fn verify(
        fixture: &Fixture,
        receipt: &BootstrapTrustReceipt,
        pin: &BootstrapTrustPin,
    ) -> Result<VerifiedBootstrapTrust, BootstrapTrustError> {
        verify_bootstrap_trust_receipt(
            &receipt.encode().unwrap(),
            pin,
            &fixture.provider,
            &fixture.anchor,
            &fixture.bootstrap,
            &LibcruxMlDsa65VerifierCandidate,
        )
    }

    /// Shared only by sibling unit tests; deterministic fixture keys are not deployment identities.
    pub(crate) fn verified_test_fixture() -> (
        ExternalCasPin,
        ExternalCasOffhostAnchorPin,
        VerifiedBootstrapTrust,
    ) {
        let fixture = fixture();
        let verified = verify(&fixture, &fixture.receipt, &fixture.pin).unwrap();
        (fixture.provider, fixture.anchor, verified)
    }

    /// Complete deterministic material for the sibling QBTB1 codec tests only.
    /// The fixed keys are synthetic and never represent deployment identities.
    pub(crate) fn bundle_test_material() -> (
        ExternalCasPin,
        ExternalCasOffhostAnchorPin,
        ExternalCasRecord,
        BootstrapTrustPin,
        Vec<u8>,
    ) {
        let fixture = fixture();
        (
            fixture.provider,
            fixture.anchor,
            fixture.bootstrap,
            fixture.pin,
            fixture.receipt.encode().unwrap(),
        )
    }
    #[test]
    fn qbt1_roundtrip_and_both_independent_signatures_verify() {
        let fixture = fixture();
        let encoded = fixture.receipt.encode().unwrap();
        assert_eq!(encoded.len(), BOOTSTRAP_TRUST_RECEIPT_BYTES);
        assert_eq!(&encoded[..4], b"QBT1");
        assert_eq!(
            BootstrapTrustReceipt::decode(&encoded).unwrap(),
            fixture.receipt
        );

        let verified = verify(&fixture, &fixture.receipt, &fixture.pin).unwrap();
        assert_eq!(verified.receipt, fixture.receipt);
        assert_eq!(verified.receipt_digest, fixture.pin.expected_receipt_digest);
        assert_eq!(verified.initial_anchor_state.sequence, 1);
        assert_eq!(verified.initial_anchor_state.provider_object_generation, 1);
        assert_eq!(verified.initial_anchor_state.provider_record.generation, 0);
    }

    #[test]
    fn refuses_a_receipt_whose_digest_is_not_independently_pinned() {
        let fixture = fixture();
        let mut changed = fixture.receipt.clone();
        changed.profile_digest[0] ^= 1;
        let pin = fixture.pin.clone();
        assert_eq!(
            verify(&fixture, &changed, &pin),
            Err(BootstrapTrustError::WrongReceiptDigest)
        );

        let mut repinned = fixture.pin.clone();
        repinned.expected_receipt_digest = changed.digest().unwrap();
        assert_eq!(
            verify(&fixture, &changed, &repinned),
            Err(BootstrapTrustError::WrongTrustDomain)
        );
    }

    #[test]
    fn rejects_owner_or_custodian_key_reuse_and_identity_collision() {
        let fixture = fixture();
        let mut pin = fixture.pin.clone();
        pin.independent_custodian_public_key = pin.owner_public_key;
        assert_eq!(
            pin.validate(&fixture.provider, &fixture.anchor, &fixture.bootstrap),
            Err(BootstrapTrustError::SignerKeyReuse)
        );

        let mut pin = fixture.pin.clone();
        pin.independent_custodian_signer_id = pin.owner_signer_id;
        assert_eq!(
            pin.validate(&fixture.provider, &fixture.anchor, &fixture.bootstrap),
            Err(BootstrapTrustError::SignerIdentityCollision)
        );
    }

    #[test]
    fn rejects_provider_or_anchor_key_reuse_by_an_acceptance_signer() {
        let fixture = fixture();
        let mut pin = fixture.pin.clone();
        pin.owner_public_key = fixture.provider.receipt_public_key;
        assert_eq!(
            pin.validate(&fixture.provider, &fixture.anchor, &fixture.bootstrap),
            Err(BootstrapTrustError::SignerKeyReuse)
        );

        let mut pin = fixture.pin.clone();
        pin.independent_custodian_public_key = fixture.anchor.receipt_public_key;
        assert_eq!(
            pin.validate(&fixture.provider, &fixture.anchor, &fixture.bootstrap),
            Err(BootstrapTrustError::SignerKeyReuse)
        );
    }

    #[test]
    fn rejects_zero_profile_and_zero_or_duplicate_key_ids() {
        let fixture = fixture();
        let mut pin = fixture.pin.clone();
        pin.profile_digest = [0; 32];
        assert_eq!(
            pin.validate(&fixture.provider, &fixture.anchor, &fixture.bootstrap),
            Err(BootstrapTrustError::InvalidOutOfBandPin)
        );

        let mut pin = fixture.pin.clone();
        pin.owner_signer_id = fixture.provider.receipt_key_id;
        assert_eq!(
            pin.validate(&fixture.provider, &fixture.anchor, &fixture.bootstrap),
            Err(BootstrapTrustError::SignerIdentityCollision)
        );
    }

    #[test]
    fn rejects_a_different_bootstrap_record_and_anchor_state() {
        let fixture = fixture();
        let mut altered = fixture.bootstrap.clone();
        altered.next_state_digest[0] ^= 0x80;
        assert_eq!(
            verify_bootstrap_trust_receipt(
                &fixture.receipt.encode().unwrap(),
                &fixture.pin,
                &fixture.provider,
                &fixture.anchor,
                &altered,
                &LibcruxMlDsa65VerifierCandidate,
            ),
            Err(BootstrapTrustError::InvalidBootstrapRecord)
        );

        let mut pin = fixture.pin.clone();
        pin.initial_anchor_state_digest[0] ^= 0x01;
        assert_eq!(
            verify(&fixture, &fixture.receipt, &pin),
            Err(BootstrapTrustError::InvalidInitialAnchorState)
        );
    }

    #[test]
    fn rejects_invalid_generation_sequence_and_object_generation() {
        let fixture = fixture();
        let mut altered = fixture.receipt.clone();
        altered.anchor_sequence = 2;
        assert_eq!(
            altered.canonical_payload(),
            Err(BootstrapTrustError::InvalidReceiptShape)
        );

        let mut altered = fixture.receipt.clone();
        altered.provider_record_generation = 1;
        assert_eq!(
            altered.canonical_payload(),
            Err(BootstrapTrustError::InvalidReceiptShape)
        );

        let mut altered = fixture.receipt.clone();
        altered.provider_object_generation = 0;
        assert_eq!(
            altered.canonical_payload(),
            Err(BootstrapTrustError::InvalidReceiptShape)
        );
    }

    #[test]
    fn rejects_signature_tampering_even_when_the_digest_pin_is_updated() {
        let fixture = fixture();
        let mut altered = fixture.receipt.clone();
        altered.owner_signature[0] ^= 1;
        let mut pin = fixture.pin.clone();
        pin.expected_receipt_digest = altered.digest().unwrap();
        assert_eq!(
            verify(&fixture, &altered, &pin),
            Err(BootstrapTrustError::InvalidOwnerSignature)
        );

        let mut altered = fixture.receipt.clone();
        altered.independent_custodian_signature[0] ^= 1;
        let mut pin = fixture.pin.clone();
        pin.expected_receipt_digest = altered.digest().unwrap();
        assert_eq!(
            verify(&fixture, &altered, &pin),
            Err(BootstrapTrustError::InvalidCustodianSignature)
        );
    }

    #[test]
    fn rejects_noncanonical_header_wrong_length_and_trailing_bytes() {
        let fixture = fixture();
        let encoded = fixture.receipt.encode().unwrap();

        let mut reserved = encoded.clone();
        reserved[14] = 1;
        assert_eq!(
            BootstrapTrustReceipt::decode(&reserved),
            Err(BootstrapTrustError::NoncanonicalHeader)
        );

        let mut wrong_role = encoded.clone();
        wrong_role[9] = 3;
        assert_eq!(
            BootstrapTrustReceipt::decode(&wrong_role),
            Err(BootstrapTrustError::NoncanonicalHeader)
        );

        assert_eq!(
            BootstrapTrustReceipt::decode(&encoded[..encoded.len() - 1]),
            Err(BootstrapTrustError::WrongReceiptLength)
        );

        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            BootstrapTrustReceipt::decode(&trailing),
            Err(BootstrapTrustError::WrongReceiptLength)
        );
    }

    #[test]
    fn refuses_invalid_external_provider_or_anchor_pins() {
        let fixture = fixture();
        let mut provider = fixture.provider.clone();
        provider.network_id = [0; 32];
        assert_eq!(
            verify_bootstrap_trust_receipt(
                &fixture.receipt.encode().unwrap(),
                &fixture.pin,
                &provider,
                &fixture.anchor,
                &fixture.bootstrap,
                &LibcruxMlDsa65VerifierCandidate,
            ),
            Err(BootstrapTrustError::InvalidProviderPin)
        );

        let mut anchor = fixture.anchor.clone();
        anchor.anchor_id = [0; 32];
        assert_eq!(
            verify_bootstrap_trust_receipt(
                &fixture.receipt.encode().unwrap(),
                &fixture.pin,
                &fixture.provider,
                &anchor,
                &fixture.bootstrap,
                &LibcruxMlDsa65VerifierCandidate,
            ),
            Err(BootstrapTrustError::InvalidAnchorPin)
        );
    }
}
