//! Versioned, candidate-only peer-identity scope contract.
//!
//! PIS2 is separate from the legacy PIV1 anchor scope. It binds a peer role to a QVDN devnet
//! profile verified against locally constructed expected configuration. The QVDN manifest digest
//! is an unkeyed integrity digest, not an external signature or trust anchor. Callers remain
//! responsible for sourcing the expected profile from independently trusted configuration.
//! This module does not write anchors, migrate PIV1, activate identities, or start nodes/listeners.

use crate::{
    consensus::{PowAlgorithm, Uint256},
    devnet_profile_candidate::{DevnetProfileCandidate, DevnetProfileError},
};
use sha2::{Digest, Sha256};

const MAGIC: &[u8; 4] = b"PIS2";
const VERSION: u16 = 2;
const PROFILE_FAMILY_QVDN_CANDIDATE: u8 = 1;
const GENESIS_KIND_QVDN_STATE_ROOT_V1: u8 = 1;
const SCOPE_DOMAIN: &[u8] = b"AI-NATIVE-L1-PEER-IDENTITY-SCOPE-V2\0";
const WIRE_LEN: usize = 227;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PeerIdentityRoleV2 {
    Seed = 1,
    Joining = 2,
}

impl PeerIdentityRoleV2 {
    pub fn label(self) -> &'static str {
        match self {
            Self::Seed => "seed",
            Self::Joining => "joining",
        }
    }

    pub fn wire_code(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for PeerIdentityRoleV2 {
    type Error = PeerIdentityScopeV2Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Seed),
            2 => Ok(Self::Joining),
            _ => Err(PeerIdentityScopeV2Error::UnsupportedRole),
        }
    }
}

impl TryFrom<&str> for PeerIdentityRoleV2 {
    type Error = PeerIdentityScopeV2Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "seed" => Ok(Self::Seed),
            "joining" => Ok(Self::Joining),
            _ => Err(PeerIdentityScopeV2Error::UnsupportedRole),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PeerIdentityProfileModeV2 {
    QvdnCandidate = 1,
    QvdnLocalTestPow = 2,
}

impl TryFrom<u8> for PeerIdentityProfileModeV2 {
    type Error = PeerIdentityScopeV2Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::QvdnCandidate),
            2 => Ok(Self::QvdnLocalTestPow),
            _ => Err(PeerIdentityScopeV2Error::UnsupportedProfileMode),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerIdentityScopeV2Error {
    MalformedEncoding,
    UnsupportedVersion,
    UnsupportedRole,
    UnsupportedProfileFamily,
    UnsupportedProfileMode,
    UnsupportedGenesisKind,
    UnsupportedExpectedProfile,
    InvalidIdentityBinding,
    Profile(DevnetProfileError),
    ProfileBindingMismatch,
}

impl From<DevnetProfileError> for PeerIdentityScopeV2Error {
    fn from(value: DevnetProfileError) -> Self {
        Self::Profile(value)
    }
}

/// A PIS2 scope is constructed only after supplied QVDN bytes match an expected local profile.
/// This proves equality to that candidate configuration, not the independent provenance of the
/// candidate configuration itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentityScopeV2 {
    role: PeerIdentityRoleV2,
    profile_mode: PeerIdentityProfileModeV2,
    network_id: [u8; 32],
    profile_id: [u8; 32],
    consensus_digest: [u8; 32],
    genesis_state_root: [u8; 32],
    profile_manifest_digest: [u8; 32],
    issuer_id: u32,
    issuer_public_key_fingerprint: [u8; 32],
    key_purpose: u8,
    credential_id: u128,
    key_id: u32,
}

impl PeerIdentityScopeV2 {
    /// Construct PIS2 by verifying exact canonical QVDN bytes against expected local configuration.
    /// The caller must source expected_profile from independently trusted configuration.
    #[allow(clippy::too_many_arguments)]
    pub fn from_expected_qvdn_profile(
        expected_profile: &DevnetProfileCandidate,
        manifest_wire: &[u8],
        role: PeerIdentityRoleV2,
        issuer_id: u32,
        issuer_public_key_fingerprint: [u8; 32],
        key_purpose: u8,
        credential_id: u128,
        key_id: u32,
    ) -> Result<Self, PeerIdentityScopeV2Error> {
        if issuer_id == 0
            || issuer_public_key_fingerprint == [0; 32]
            || key_purpose == 0
            || credential_id == 0
            || key_id == 0
        {
            return Err(PeerIdentityScopeV2Error::InvalidIdentityBinding);
        }

        let verified = expected_profile.verify_manifest(manifest_wire)?;
        let profile_mode = classify_expected_profile(expected_profile)?;

        Ok(Self {
            role,
            profile_mode,
            network_id: *verified.network_id(),
            profile_id: *verified.profile_id(),
            consensus_digest: *verified.consensus_digest(),
            genesis_state_root: *verified.genesis_state_root(),
            profile_manifest_digest: *verified.manifest_digest(),
            issuer_id,
            issuer_public_key_fingerprint,
            key_purpose,
            credential_id,
            key_id,
        })
    }

    /// Decode only when the embedded profile binding exactly matches a locally expected QVDN
    /// profile. No fallback, profile auto-discovery, or PIV1 reinterpretation is attempted.
    pub fn decode_and_verify(
        wire: &[u8],
        expected_profile: &DevnetProfileCandidate,
        manifest_wire: &[u8],
    ) -> Result<Self, PeerIdentityScopeV2Error> {
        if wire.len() != WIRE_LEN || &wire[..4] != MAGIC {
            return Err(PeerIdentityScopeV2Error::MalformedEncoding);
        }

        let version = u16::from_be_bytes([wire[4], wire[5]]);
        if version != VERSION {
            return Err(PeerIdentityScopeV2Error::UnsupportedVersion);
        }

        let mut offset = 6;
        let role = PeerIdentityRoleV2::try_from(take_u8(wire, &mut offset)?)?;
        if take_u8(wire, &mut offset)? != PROFILE_FAMILY_QVDN_CANDIDATE {
            return Err(PeerIdentityScopeV2Error::UnsupportedProfileFamily);
        }
        let embedded_mode = PeerIdentityProfileModeV2::try_from(take_u8(wire, &mut offset)?)?;
        if take_u8(wire, &mut offset)? != GENESIS_KIND_QVDN_STATE_ROOT_V1 {
            return Err(PeerIdentityScopeV2Error::UnsupportedGenesisKind);
        }

        // Consume embedded profile fields. Canonical re-encoding below compares every byte against
        // values re-derived from the expected profile and verified QVDN manifest.
        let _embedded_network = take_array::<32>(wire, &mut offset)?;
        let _embedded_profile = take_array::<32>(wire, &mut offset)?;
        let _embedded_consensus = take_array::<32>(wire, &mut offset)?;
        let _embedded_genesis = take_array::<32>(wire, &mut offset)?;
        let _embedded_manifest_digest = take_array::<32>(wire, &mut offset)?;
        let issuer_id = take_u32(wire, &mut offset)?;
        let issuer_public_key_fingerprint = take_array::<32>(wire, &mut offset)?;
        let key_purpose = take_u8(wire, &mut offset)?;
        let credential_id = take_u128(wire, &mut offset)?;
        let key_id = take_u32(wire, &mut offset)?;
        if offset != wire.len() {
            return Err(PeerIdentityScopeV2Error::MalformedEncoding);
        }

        let decoded = Self::from_expected_qvdn_profile(
            expected_profile,
            manifest_wire,
            role,
            issuer_id,
            issuer_public_key_fingerprint,
            key_purpose,
            credential_id,
            key_id,
        )?;

        if decoded.profile_mode != embedded_mode || decoded.canonical_bytes() != wire {
            return Err(PeerIdentityScopeV2Error::ProfileBindingMismatch);
        }
        Ok(decoded)
    }

    pub fn role(&self) -> PeerIdentityRoleV2 {
        self.role
    }

    pub fn profile_mode(&self) -> PeerIdentityProfileModeV2 {
        self.profile_mode
    }

    pub fn network_id(&self) -> &[u8; 32] {
        &self.network_id
    }

    pub fn profile_id(&self) -> &[u8; 32] {
        &self.profile_id
    }

    pub fn consensus_digest(&self) -> &[u8; 32] {
        &self.consensus_digest
    }

    pub fn genesis_state_root(&self) -> &[u8; 32] {
        &self.genesis_state_root
    }

    /// This is the QVDN manifest's unkeyed integrity digest, not a signature or external witness.
    pub fn profile_manifest_digest(&self) -> &[u8; 32] {
        &self.profile_manifest_digest
    }

    /// Canonical PIS2 bytes. Field length and order are fixed by this module version.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(WIRE_LEN);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.push(self.role.wire_code());
        bytes.push(PROFILE_FAMILY_QVDN_CANDIDATE);
        bytes.push(self.profile_mode as u8);
        bytes.push(GENESIS_KIND_QVDN_STATE_ROOT_V1);
        bytes.extend_from_slice(&self.network_id);
        bytes.extend_from_slice(&self.profile_id);
        bytes.extend_from_slice(&self.consensus_digest);
        bytes.extend_from_slice(&self.genesis_state_root);
        bytes.extend_from_slice(&self.profile_manifest_digest);
        bytes.extend_from_slice(&self.issuer_id.to_be_bytes());
        bytes.extend_from_slice(&self.issuer_public_key_fingerprint);
        bytes.push(self.key_purpose);
        bytes.extend_from_slice(&self.credential_id.to_be_bytes());
        bytes.extend_from_slice(&self.key_id.to_be_bytes());
        debug_assert_eq!(bytes.len(), WIRE_LEN);
        bytes
    }

    /// Domain-separated identity-scope digest. This is a local binding, not a signature.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(SCOPE_DOMAIN);
        hasher.update(self.canonical_bytes());
        hasher.finalize().into()
    }
}

fn classify_expected_profile(
    profile: &DevnetProfileCandidate,
) -> Result<PeerIdentityProfileModeV2, PeerIdentityScopeV2Error> {
    let consensus = profile.consensus();
    if consensus.pow.algorithm != PowAlgorithm::Argon2id {
        return Err(PeerIdentityScopeV2Error::UnsupportedExpectedProfile);
    }

    if consensus.initial_target == Uint256::MAX
        && consensus.pow_limit == Uint256::MAX
        && consensus.pow.memory_kib == 8 * 1024
    {
        return Ok(PeerIdentityProfileModeV2::QvdnLocalTestPow);
    }

    if consensus.initial_target != Uint256::MAX && consensus.pow.memory_kib >= 64 * 1024 {
        return Ok(PeerIdentityProfileModeV2::QvdnCandidate);
    }

    Err(PeerIdentityScopeV2Error::UnsupportedExpectedProfile)
}

fn take_u8(wire: &[u8], offset: &mut usize) -> Result<u8, PeerIdentityScopeV2Error> {
    let value = *wire
        .get(*offset)
        .ok_or(PeerIdentityScopeV2Error::MalformedEncoding)?;
    *offset += 1;
    Ok(value)
}

fn take_u32(wire: &[u8], offset: &mut usize) -> Result<u32, PeerIdentityScopeV2Error> {
    Ok(u32::from_be_bytes(take_array::<4>(wire, offset)?))
}

fn take_u128(wire: &[u8], offset: &mut usize) -> Result<u128, PeerIdentityScopeV2Error> {
    Ok(u128::from_be_bytes(take_array::<16>(wire, offset)?))
}

fn take_array<const N: usize>(
    wire: &[u8],
    offset: &mut usize,
) -> Result<[u8; N], PeerIdentityScopeV2Error> {
    let end = offset
        .checked_add(N)
        .ok_or(PeerIdentityScopeV2Error::MalformedEncoding)?;
    let slice = wire
        .get(*offset..end)
        .ok_or(PeerIdentityScopeV2Error::MalformedEncoding)?;
    let value = slice
        .try_into()
        .map_err(|_| PeerIdentityScopeV2Error::MalformedEncoding)?;
    *offset = end;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity_fields() -> (u32, [u8; 32], u8, u128, u32) {
        (7, [0x77; 32], 1, 42, 9)
    }

    fn make_scope(
        profile: &DevnetProfileCandidate,
        role: PeerIdentityRoleV2,
    ) -> PeerIdentityScopeV2 {
        let manifest = profile.encode_manifest();
        let (issuer_id, issuer_fingerprint, purpose, credential_id, key_id) = identity_fields();
        PeerIdentityScopeV2::from_expected_qvdn_profile(
            profile,
            &manifest,
            role,
            issuer_id,
            issuer_fingerprint,
            purpose,
            credential_id,
            key_id,
        )
        .unwrap()
    }

    #[test]
    fn role_text_and_wire_codes_are_canonical_and_namespaced() {
        assert_eq!(
            PeerIdentityRoleV2::try_from("seed"),
            Ok(PeerIdentityRoleV2::Seed)
        );
        assert_eq!(
            PeerIdentityRoleV2::try_from("joining"),
            Ok(PeerIdentityRoleV2::Joining)
        );
        assert_eq!(
            PeerIdentityRoleV2::try_from("Seed"),
            Err(PeerIdentityScopeV2Error::UnsupportedRole)
        );
        assert_eq!(
            PeerIdentityRoleV2::try_from("client"),
            Err(PeerIdentityScopeV2Error::UnsupportedRole)
        );
        assert_eq!(
            PeerIdentityRoleV2::try_from(1),
            Ok(PeerIdentityRoleV2::Seed)
        );
        assert_eq!(
            PeerIdentityRoleV2::try_from(2),
            Ok(PeerIdentityRoleV2::Joining)
        );
        assert_eq!(
            PeerIdentityRoleV2::try_from(0),
            Err(PeerIdentityScopeV2Error::UnsupportedRole)
        );
        assert_eq!(
            PeerIdentityRoleV2::try_from(3),
            Err(PeerIdentityScopeV2Error::UnsupportedRole)
        );
    }

    #[test]
    fn normal_qvdn_scope_round_trips_against_expected_profile() {
        let network = [0x31; 32];
        let profile = DevnetProfileCandidate::new(network).unwrap();
        let scope = make_scope(&profile, PeerIdentityRoleV2::Seed);
        let wire = scope.canonical_bytes();

        assert_eq!(wire.len(), WIRE_LEN);
        assert_eq!(
            scope.profile_mode(),
            PeerIdentityProfileModeV2::QvdnCandidate
        );
        assert_eq!(scope.network_id(), &network);
        assert_eq!(scope.genesis_state_root(), profile.genesis_state_root());
        assert_eq!(
            scope.profile_manifest_digest(),
            profile
                .verify_manifest(&profile.encode_manifest())
                .unwrap()
                .manifest_digest()
        );

        let decoded =
            PeerIdentityScopeV2::decode_and_verify(&wire, &profile, &profile.encode_manifest())
                .unwrap();
        assert_eq!(decoded, scope);
        assert_eq!(decoded.digest(), scope.digest());
    }

    #[test]
    fn local_test_pow_profile_is_distinct_and_cannot_be_confused_with_candidate() {
        let network = [0x32; 32];
        let candidate = DevnetProfileCandidate::new(network).unwrap();
        let test_pow = DevnetProfileCandidate::new_test_pow(network).unwrap();
        let candidate_scope = make_scope(&candidate, PeerIdentityRoleV2::Seed);
        let test_scope = make_scope(&test_pow, PeerIdentityRoleV2::Seed);

        assert_eq!(
            candidate_scope.profile_mode(),
            PeerIdentityProfileModeV2::QvdnCandidate
        );
        assert_eq!(
            test_scope.profile_mode(),
            PeerIdentityProfileModeV2::QvdnLocalTestPow
        );
        assert_ne!(candidate_scope.profile_id(), test_scope.profile_id());
        assert_ne!(
            candidate_scope.consensus_digest(),
            test_scope.consensus_digest()
        );
        assert_ne!(candidate_scope.digest(), test_scope.digest());

        let test_wire = test_scope.canonical_bytes();
        assert_eq!(
            PeerIdentityScopeV2::decode_and_verify(
                &test_wire,
                &candidate,
                &test_pow.encode_manifest(),
            ),
            Err(PeerIdentityScopeV2Error::Profile(
                DevnetProfileError::ProfileMismatch
            ))
        );
    }

    #[test]
    fn role_change_changes_scope_digest_and_wire() {
        let profile = DevnetProfileCandidate::new([0x33; 32]).unwrap();
        let seed = make_scope(&profile, PeerIdentityRoleV2::Seed);
        let joining = make_scope(&profile, PeerIdentityRoleV2::Joining);
        assert_ne!(seed.canonical_bytes(), joining.canonical_bytes());
        assert_ne!(seed.digest(), joining.digest());
    }

    #[test]
    fn malformed_version_role_and_trailing_bytes_fail_closed() {
        let profile = DevnetProfileCandidate::new([0x34; 32]).unwrap();
        let scope = make_scope(&profile, PeerIdentityRoleV2::Joining);
        let manifest = profile.encode_manifest();

        let mut bad_version = scope.canonical_bytes();
        bad_version[5] = 3;
        assert_eq!(
            PeerIdentityScopeV2::decode_and_verify(&bad_version, &profile, &manifest),
            Err(PeerIdentityScopeV2Error::UnsupportedVersion)
        );

        let mut bad_role = scope.canonical_bytes();
        bad_role[6] = 3;
        assert_eq!(
            PeerIdentityScopeV2::decode_and_verify(&bad_role, &profile, &manifest),
            Err(PeerIdentityScopeV2Error::UnsupportedRole)
        );

        let mut trailing = scope.canonical_bytes();
        trailing.push(0);
        assert_eq!(
            PeerIdentityScopeV2::decode_and_verify(&trailing, &profile, &manifest),
            Err(PeerIdentityScopeV2Error::MalformedEncoding)
        );
    }

    #[test]
    fn manifest_tampering_and_zero_identity_bindings_fail_closed() {
        let profile = DevnetProfileCandidate::new([0x35; 32]).unwrap();
        let scope = make_scope(&profile, PeerIdentityRoleV2::Seed);
        let mut manifest = profile.encode_manifest();
        manifest[102] ^= 0x01;
        assert!(PeerIdentityScopeV2::decode_and_verify(
            &scope.canonical_bytes(),
            &profile,
            &manifest
        )
        .is_err());

        assert_eq!(
            PeerIdentityScopeV2::from_expected_qvdn_profile(
                &profile,
                &profile.encode_manifest(),
                PeerIdentityRoleV2::Seed,
                0,
                [0x77; 32],
                1,
                42,
                9,
            ),
            Err(PeerIdentityScopeV2Error::InvalidIdentityBinding)
        );
    }
}
