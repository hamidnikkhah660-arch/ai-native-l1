//! CP-0400 canonical wire representation for the independent PFM5 High-Water state.
//!
//! This module freezes deterministic bytes and a domain-separated digest only. It does not
//! authenticate an authority, provide a remote CAS, or turn a local/test provider into an
//! independent production authority. Those require a separately pinned authority verifier and
//! a qualified linearizable provider implementation.

use crate::v4_fat1_trust_candidate::{
    MlDsa65Verifier, ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SIGNATURE_BYTES,
};
use crate::{
    external_cas_anchor_candidate::{ExternalCasPin, ExternalCasRecord},
    private_testnet_pfm5_external_cas_highwater_candidate::{
        Pfm5ExternalCasHighWaterAuthorityPin, Pfm5ExternalCasHighWaterState,
    },
};
use sha2::{Digest, Sha256};

pub const PFM5_HIGHWATER_WIRE_MAGIC: [u8; 4] = *b"QHWA";
pub const PFM5_HIGHWATER_WIRE_VERSION: u16 = 1;
pub const PFM5_HIGHWATER_STATE_DIGEST_DOMAIN: &[u8] = b"QRun/PFM5/HighWater/StateDigest/v1\0";
const FIXED_LEN: usize = 4 + 2 + (4 * 32) + 8 + 8 + (8 * 32) + 8;

/// Version-1 fixed-width canonical representation. All integers are unsigned big-endian.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pfm5ExternalCasHighWaterWireV1 {
    pub state: Pfm5ExternalCasHighWaterState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pfm5ExternalCasHighWaterWireError {
    InvalidLength,
    InvalidMagic,
    UnsupportedVersion,
    InvalidState,
}

impl Pfm5ExternalCasHighWaterWireV1 {
    pub fn from_state(
        state: &Pfm5ExternalCasHighWaterState,
        authority: &Pfm5ExternalCasHighWaterAuthorityPin,
        pin: &ExternalCasPin,
    ) -> Result<Self, Pfm5ExternalCasHighWaterWireError> {
        state
            .validate(authority, pin)
            .map_err(|_| Pfm5ExternalCasHighWaterWireError::InvalidState)?;
        state
            .record
            .validate_shape()
            .map_err(|_| Pfm5ExternalCasHighWaterWireError::InvalidState)?;
        Ok(Self {
            state: state.clone(),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(FIXED_LEN);
        out.extend_from_slice(&PFM5_HIGHWATER_WIRE_MAGIC);
        out.extend_from_slice(&PFM5_HIGHWATER_WIRE_VERSION.to_be_bytes());
        out.extend_from_slice(&self.state.authority_id);
        out.extend_from_slice(&self.state.provider_id);
        out.extend_from_slice(&self.state.network_id);
        out.extend_from_slice(&self.state.genesis_digest);
        out.extend_from_slice(&self.state.journal_sequence.to_be_bytes());
        let record = &self.state.record;
        out.extend_from_slice(&record.generation.to_be_bytes());
        out.extend_from_slice(&record.provider_id);
        out.extend_from_slice(&record.network_id);
        out.extend_from_slice(&record.genesis_digest);
        out.extend_from_slice(&record.previous_record_digest);
        out.extend_from_slice(&record.previous_state_digest);
        out.extend_from_slice(&record.next_state_digest);
        out.extend_from_slice(&record.operation_id);
        out.extend_from_slice(&record.request_digest);
        out.extend_from_slice(&self.state.object_generation.to_be_bytes());
        out
    }

    pub fn decode(
        bytes: &[u8],
        authority: &Pfm5ExternalCasHighWaterAuthorityPin,
        pin: &ExternalCasPin,
    ) -> Result<Self, Pfm5ExternalCasHighWaterWireError> {
        if bytes.len() != FIXED_LEN {
            return Err(Pfm5ExternalCasHighWaterWireError::InvalidLength);
        }
        if bytes[..4] != PFM5_HIGHWATER_WIRE_MAGIC {
            return Err(Pfm5ExternalCasHighWaterWireError::InvalidMagic);
        }
        let version = u16::from_be_bytes([bytes[4], bytes[5]]);
        if version != PFM5_HIGHWATER_WIRE_VERSION {
            return Err(Pfm5ExternalCasHighWaterWireError::UnsupportedVersion);
        }
        let mut cursor = 6;
        let authority_id = take32(bytes, &mut cursor);
        let provider_id = take32(bytes, &mut cursor);
        let network_id = take32(bytes, &mut cursor);
        let genesis_digest = take32(bytes, &mut cursor);
        let journal_sequence = take_u64(bytes, &mut cursor);
        let generation = take_u64(bytes, &mut cursor);
        let record = ExternalCasRecord {
            generation,
            provider_id: take32(bytes, &mut cursor),
            network_id: take32(bytes, &mut cursor),
            genesis_digest: take32(bytes, &mut cursor),
            previous_record_digest: take32(bytes, &mut cursor),
            previous_state_digest: take32(bytes, &mut cursor),
            next_state_digest: take32(bytes, &mut cursor),
            operation_id: take32(bytes, &mut cursor),
            request_digest: take32(bytes, &mut cursor),
        };
        let object_generation = take_u64(bytes, &mut cursor);
        if cursor != bytes.len() {
            return Err(Pfm5ExternalCasHighWaterWireError::InvalidLength);
        }
        let state = Pfm5ExternalCasHighWaterState {
            authority_id,
            provider_id,
            network_id,
            genesis_digest,
            journal_sequence,
            record,
            object_generation,
        };
        state
            .validate(authority, pin)
            .map_err(|_| Pfm5ExternalCasHighWaterWireError::InvalidState)?;
        state
            .record
            .validate_shape()
            .map_err(|_| Pfm5ExternalCasHighWaterWireError::InvalidState)?;
        let wire = Self { state };
        // Reject any alternate representation, now or after future decoder changes.
        if wire.encode().as_slice() != bytes {
            return Err(Pfm5ExternalCasHighWaterWireError::InvalidState);
        }
        Ok(wire)
    }

    pub fn state_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(PFM5_HIGHWATER_STATE_DIGEST_DOMAIN);
        hasher.update(self.encode());
        hasher.finalize().into()
    }
}

// Authority verification material is provisioned out-of-band. The private key must never be
// stored in the node, provider database, or this pin. Revocation/rotation policy is deliberately
// external until a reviewed trust-store lifecycle is specified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pfm5ExternalCasHighWaterAuthorityVerifierPin {
    pub authority_id: [u8; 32],
    pub key_id: [u8; 32],
    pub key_generation: u64,
    pub public_key: [u8; ML_DSA_65_PUBLIC_KEY_BYTES],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pfm5ExternalCasHighWaterAuthError {
    InvalidPin,
    ChallengeMismatch,
    AuthorityMismatch,
    KeyIdMismatch,
    KeyGenerationMismatch,
    InvalidWire(Pfm5ExternalCasHighWaterWireError),
    InvalidSignature,
}

pub const PFM5_HIGHWATER_RESPONSE_SIGNING_DOMAIN: &[u8] =
    b"QRun/PFM5/HighWater/AuthenticatedResponse/v1\0";

/// Signed response envelope. The challenge must be freshly generated by the caller and checked
/// against its outstanding request; this module does not generate randomness or manage replay
/// caches for a network client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pfm5ExternalCasHighWaterSignedResponseV1 {
    pub challenge: [u8; 32],
    pub key_id: [u8; 32],
    pub key_generation: u64,
    pub wire_state: Vec<u8>,
    pub signature: [u8; ML_DSA_65_SIGNATURE_BYTES],
}

impl Pfm5ExternalCasHighWaterSignedResponseV1 {
    pub fn signing_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(PFM5_HIGHWATER_RESPONSE_SIGNING_DOMAIN);
        hasher.update(self.challenge);
        hasher.update(self.key_id);
        hasher.update(self.key_generation.to_be_bytes());
        hasher.update((self.wire_state.len() as u64).to_be_bytes());
        hasher.update(&self.wire_state);
        hasher.finalize().into()
    }

    pub fn verify<V: MlDsa65Verifier>(
        &self,
        expected_challenge: &[u8; 32],
        authority: &Pfm5ExternalCasHighWaterAuthorityPin,
        verifier_pin: &Pfm5ExternalCasHighWaterAuthorityVerifierPin,
        provider_pin: &ExternalCasPin,
        verifier: &V,
    ) -> Result<Pfm5ExternalCasHighWaterWireV1, Pfm5ExternalCasHighWaterAuthError> {
        if expected_challenge.iter().all(|byte| *byte == 0) || self.challenge != *expected_challenge
        {
            return Err(Pfm5ExternalCasHighWaterAuthError::ChallengeMismatch);
        }
        if verifier_pin.authority_id != authority.authority_id {
            return Err(Pfm5ExternalCasHighWaterAuthError::AuthorityMismatch);
        }
        if verifier_pin.key_id.iter().all(|byte| *byte == 0)
            || verifier_pin.key_generation == 0
            || verifier_pin.public_key.iter().all(|byte| *byte == 0)
        {
            return Err(Pfm5ExternalCasHighWaterAuthError::InvalidPin);
        }
        if self.key_id != verifier_pin.key_id {
            return Err(Pfm5ExternalCasHighWaterAuthError::KeyIdMismatch);
        }
        if self.key_generation != verifier_pin.key_generation {
            return Err(Pfm5ExternalCasHighWaterAuthError::KeyGenerationMismatch);
        }
        let wire =
            Pfm5ExternalCasHighWaterWireV1::decode(&self.wire_state, authority, provider_pin)
                .map_err(Pfm5ExternalCasHighWaterAuthError::InvalidWire)?;
        let digest = self.signing_digest();
        if !verifier.verify(&verifier_pin.public_key, &digest, &self.signature) {
            return Err(Pfm5ExternalCasHighWaterAuthError::InvalidSignature);
        }
        Ok(wire)
    }
}
fn take32(bytes: &[u8], cursor: &mut usize) -> [u8; 32] {
    let mut value = [0u8; 32];
    value.copy_from_slice(&bytes[*cursor..*cursor + 32]);
    *cursor += 32;
    value
}

fn take_u64(bytes: &[u8], cursor: &mut usize) -> u64 {
    let mut value = [0u8; 8];
    value.copy_from_slice(&bytes[*cursor..*cursor + 8]);
    *cursor += 8;
    u64::from_be_bytes(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v4_fat1_trust_candidate::ML_DSA_65_PUBLIC_KEY_BYTES;

    fn fixture() -> (
        Pfm5ExternalCasHighWaterAuthorityPin,
        ExternalCasPin,
        Pfm5ExternalCasHighWaterState,
    ) {
        let authority = Pfm5ExternalCasHighWaterAuthorityPin {
            authority_id: [0xA1; 32],
        };
        let pin = ExternalCasPin {
            provider_id: [0x11; 32],
            network_id: [0x22; 32],
            genesis_digest: [0x33; 32],
            receipt_key_id: [0x44; 32],
            receipt_public_key: [0x55; ML_DSA_65_PUBLIC_KEY_BYTES],
        };
        let record = ExternalCasRecord {
            generation: 7,
            provider_id: pin.provider_id,
            network_id: pin.network_id,
            genesis_digest: pin.genesis_digest,
            previous_record_digest: [0x61; 32],
            previous_state_digest: [0x62; 32],
            next_state_digest: [0x63; 32],
            operation_id: [0x64; 32],
            request_digest: [0x65; 32],
        };
        let state = Pfm5ExternalCasHighWaterState {
            authority_id: authority.authority_id,
            provider_id: pin.provider_id,
            network_id: pin.network_id,
            genesis_digest: pin.genesis_digest,
            journal_sequence: 9,
            record,
            object_generation: 40,
        };
        (authority, pin, state)
    }
    #[test]
    fn canonical_wire_roundtrips_and_digest_is_domain_separated() {
        let (authority, pin, state) = fixture();
        let wire = Pfm5ExternalCasHighWaterWireV1::from_state(&state, &authority, &pin).unwrap();
        let encoded = wire.encode();
        assert_eq!(encoded.len(), FIXED_LEN);
        let decoded = Pfm5ExternalCasHighWaterWireV1::decode(&encoded, &authority, &pin).unwrap();
        assert_eq!(decoded, wire);
        assert_eq!(decoded.encode(), encoded);
        assert_eq!(decoded.state_digest(), wire.state_digest());
        let mut changed = encoded.clone();
        changed[encoded.len() - 1] ^= 1;
        assert_ne!(
            Pfm5ExternalCasHighWaterWireV1::decode(&changed, &authority, &pin)
                .unwrap()
                .state_digest(),
            wire.state_digest()
        );
    }

    fn signed_fixture() -> (
        Pfm5ExternalCasHighWaterAuthorityPin,
        ExternalCasPin,
        Pfm5ExternalCasHighWaterAuthorityVerifierPin,
        [u8; 32],
        Pfm5ExternalCasHighWaterSignedResponseV1,
        crate::v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate,
        libcrux_ml_dsa::ml_dsa_65::MLDSA65SigningKey,
    ) {
        use crate::v4_fat1_trust_candidate::ML_DSA_65_SIGNATURE_BYTES;
        use libcrux_ml_dsa::ml_dsa_65::portable;

        let (authority, provider_pin, state) = fixture();
        let key_pair = portable::generate_key_pair([0x71; 32]);
        let public_key: [u8; ML_DSA_65_PUBLIC_KEY_BYTES] = *key_pair.verification_key.as_ref();
        let verifier_pin = Pfm5ExternalCasHighWaterAuthorityVerifierPin {
            authority_id: authority.authority_id,
            key_id: [0x72; 32],
            key_generation: 1,
            public_key,
        };
        let wire =
            Pfm5ExternalCasHighWaterWireV1::from_state(&state, &authority, &provider_pin).unwrap();
        let challenge = [0x73; 32];
        let mut response = Pfm5ExternalCasHighWaterSignedResponseV1 {
            challenge,
            key_id: verifier_pin.key_id,
            key_generation: verifier_pin.key_generation,
            wire_state: wire.encode(),
            signature: [0; ML_DSA_65_SIGNATURE_BYTES],
        };
        let digest = response.signing_digest();
        response.signature = *portable::sign(&key_pair.signing_key, &digest, &[], [0x74; 32])
            .unwrap()
            .as_ref();
        (
            authority,
            provider_pin,
            verifier_pin,
            challenge,
            response,
            crate::v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate,
            key_pair.signing_key,
        )
    }
    #[test]
    fn authenticated_response_verifies_real_mldsa65_and_exact_challenge() {
        let (authority, provider, pin, challenge, response, verifier, _) = signed_fixture();
        let verified = response
            .verify(&challenge, &authority, &pin, &provider, &verifier)
            .unwrap();
        assert_eq!(verified.state.journal_sequence, 9);
    }

    #[test]
    fn authenticated_response_rejects_replay_wrong_key_generation_and_tampering() {
        let (authority, provider, pin, challenge, response, verifier, _) = signed_fixture();
        let stale_challenge = [0x75; 32];
        assert_eq!(
            response.verify(&stale_challenge, &authority, &pin, &provider, &verifier),
            Err(Pfm5ExternalCasHighWaterAuthError::ChallengeMismatch)
        );

        let mut wrong_key = response.clone();
        wrong_key.key_id[0] ^= 1;
        assert_eq!(
            wrong_key.verify(&challenge, &authority, &pin, &provider, &verifier),
            Err(Pfm5ExternalCasHighWaterAuthError::KeyIdMismatch)
        );

        let mut wrong_generation = response.clone();
        wrong_generation.key_generation += 1;
        assert_eq!(
            wrong_generation.verify(&challenge, &authority, &pin, &provider, &verifier),
            Err(Pfm5ExternalCasHighWaterAuthError::KeyGenerationMismatch)
        );

        let mut tampered = response.clone();
        tampered.wire_state[141] ^= 1;
        assert_eq!(
            tampered.verify(&challenge, &authority, &pin, &provider, &verifier),
            Err(Pfm5ExternalCasHighWaterAuthError::InvalidSignature)
        );

        let mut bad_signature = response;
        bad_signature.signature[0] ^= 1;
        assert_eq!(
            bad_signature.verify(&challenge, &authority, &pin, &provider, &verifier),
            Err(Pfm5ExternalCasHighWaterAuthError::InvalidSignature)
        );
    }

    #[test]
    fn authenticated_response_rejects_wrong_authority_and_zero_challenge() {
        let (authority, provider, mut pin, challenge, response, verifier, _) = signed_fixture();
        pin.authority_id[0] ^= 1;
        assert_eq!(
            response.verify(&challenge, &authority, &pin, &provider, &verifier),
            Err(Pfm5ExternalCasHighWaterAuthError::AuthorityMismatch)
        );
        let zero = [0; 32];
        let (_, provider, pin, _, response, verifier, _) = signed_fixture();
        assert_eq!(
            response.verify(&zero, &authority, &pin, &provider, &verifier),
            Err(Pfm5ExternalCasHighWaterAuthError::ChallengeMismatch)
        );
    }
    #[test]
    fn canonical_wire_rejects_truncation_magic_version_and_trailing_bytes() {
        let (authority, pin, state) = fixture();
        let wire = Pfm5ExternalCasHighWaterWireV1::from_state(&state, &authority, &pin).unwrap();
        let encoded = wire.encode();
        assert_eq!(
            Pfm5ExternalCasHighWaterWireV1::decode(&encoded[..encoded.len() - 1], &authority, &pin),
            Err(Pfm5ExternalCasHighWaterWireError::InvalidLength)
        );
        let mut bad_magic = encoded.clone();
        bad_magic[0] ^= 1;
        assert_eq!(
            Pfm5ExternalCasHighWaterWireV1::decode(&bad_magic, &authority, &pin),
            Err(Pfm5ExternalCasHighWaterWireError::InvalidMagic)
        );
        let mut bad_version = encoded.clone();
        bad_version[5] = 2;
        assert_eq!(
            Pfm5ExternalCasHighWaterWireV1::decode(&bad_version, &authority, &pin),
            Err(Pfm5ExternalCasHighWaterWireError::UnsupportedVersion)
        );
        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            Pfm5ExternalCasHighWaterWireV1::decode(&trailing, &authority, &pin),
            Err(Pfm5ExternalCasHighWaterWireError::InvalidLength)
        );
    }
}
