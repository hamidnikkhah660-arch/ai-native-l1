//! CP-0400 canonical wire representation for the independent PFM5 High-Water state.
//!
//! This module freezes deterministic bytes and a domain-separated digest only. It does not
//! authenticate an authority, provide a remote CAS, or turn a local/test provider into an
//! independent production authority. Those require a separately pinned authority verifier and
//! a qualified linearizable provider implementation.

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
