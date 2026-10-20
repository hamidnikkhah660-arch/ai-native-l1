//! CP-0226: isolated V4 account-identity continuity and hybrid-auth boundary.
//!
//! Design candidate only. Account-ID derivation is real SHA-256 and Ed25519 verification
//! uses ed25519-dalek, but ML-DSA-65 verification must be supplied by a separately pinned,
//! reviewed implementation. There is deliberately no production/default PQ verifier and
//! no migration/consensus callsite. Test-only verifier fixtures are not ML-DSA signatures.
use ed25519_dalek::{Signature as EdSignature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fmt;

pub const LEGACY_V3_ID_DOMAIN: &[u8] = b"AIN1-ACCOUNT-ID-V3\0";
pub const NATIVE_V4_ID_DOMAIN: &[u8] = b"AIN1-ACCOUNT-ID-V4\0";
pub const V4_TX_SIGN_DOMAIN: &[u8] = b"AIN1-TX-SIGN-V4\0";
pub const V4_VERSION: u16 = 4;
pub const HYBRID_SUITE_V3_ID: u16 = 3;
pub const V4_HYBRID_AUTH_SUITE_ID: u16 = 3;
pub const V4_TRANSACTION_MAGIC: [u8; 4] = *b"TXN4";
pub const V4_TRANSACTION_WIRE_VERSION: u16 = 4;
pub const ED25519_PUBLIC_KEY_BYTES: usize = 32;
pub const ML_DSA_65_PUBLIC_KEY_BYTES: usize = 1_952;
pub const ED25519_SIGNATURE_BYTES: usize = 64;
pub const ML_DSA_65_SIGNATURE_BYTES: usize = 3_309;
pub const HYBRID_SIGNATURE_BYTES: usize = ED25519_SIGNATURE_BYTES + ML_DSA_65_SIGNATURE_BYTES;
/// Fixed canonical TXN4 encoding; unlike TXN2 this layout carries the full hybrid key tuple.
pub const V4_HYBRID_TRANSACTION_WIRE_BYTES: usize = 4
    + 2
    + 32 * 4
    + 8 * 4
    + 2
    + 2
    + ED25519_PUBLIC_KEY_BYTES
    + ML_DSA_65_PUBLIC_KEY_BYTES
    + HYBRID_SIGNATURE_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum AccountIdentityScheme {
    /// Reuses the exact CP-0215 V3 account-ID derivation to preserve migrated balances.
    LegacyV3Hybrid = 3,
    /// Domain-separated account IDs for accounts first created under V4.
    NativeV4Hybrid = 4,
}

impl TryFrom<u16> for AccountIdentityScheme {
    type Error = IdentityContinuityError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            3 => Ok(Self::LegacyV3Hybrid),
            4 => Ok(Self::NativeV4Hybrid),
            other => Err(IdentityContinuityError::UnknownIdentityScheme(other)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityContinuityError {
    ZeroField(&'static str),
    ZeroKey(&'static str),
    InvalidNonce,
    InvalidAmount,
    InvalidExpiry,
    AccountIdMismatch,
    UnknownIdentityScheme(u16),
    InvalidEd25519PublicKey,
    InvalidEd25519Signature,
    InvalidMlDsa65Signature,
    WrongWireLength { actual: usize, expected: usize },
    WrongWireMagic,
    UnsupportedWireVersion(u16),
    UnsupportedAuthSuite(u16),
}

impl fmt::Display for IdentityContinuityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for IdentityContinuityError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V4HybridAuthorization {
    pub network_id: [u8; 32],
    pub manifest_id: [u8; 32],
    pub sender_id: [u8; 32],
    pub recipient_id: [u8; 32],
    pub nonce: u64,
    pub amount_atoms: u64,
    pub fee_atoms: u64,
    /// Exclusive transaction expiry timestamp/height as defined by the finalized V4 tx spec.
    pub expires_at: u64,
    pub identity_scheme: AccountIdentityScheme,
    pub ed25519_public_key: [u8; ED25519_PUBLIC_KEY_BYTES],
    pub mldsa65_public_key: [u8; ML_DSA_65_PUBLIC_KEY_BYTES],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V4HybridSignature {
    pub ed25519_signature: [u8; ED25519_SIGNATURE_BYTES],
    pub mldsa65_signature: [u8; ML_DSA_65_SIGNATURE_BYTES],
}

/// Standalone, versioned TXN4 signed envelope for the V4 hybrid authorization candidate.
/// This codec is deliberately separate from the legacy TXN2 Transaction structure: converting
/// to TXN2 would lose the manifest, identity scheme, and public-key tuple bound by the V4 digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V4HybridTransaction {
    pub authorization: V4HybridAuthorization,
    pub signature: V4HybridSignature,
}

impl V4HybridTransaction {
    /// Serialize the single canonical fixed-width TXN4 format. Variable-width or optional fields
    /// are deliberately absent so the same authorization cannot acquire multiple wire encodings.
    pub fn encode(&self) -> Result<Vec<u8>, IdentityContinuityError> {
        self.authorization.validate()?;
        let mut bytes = Vec::with_capacity(V4_HYBRID_TRANSACTION_WIRE_BYTES);
        bytes.extend_from_slice(&V4_TRANSACTION_MAGIC);
        bytes.extend_from_slice(&V4_TRANSACTION_WIRE_VERSION.to_be_bytes());
        bytes.extend_from_slice(&self.authorization.network_id);
        bytes.extend_from_slice(&self.authorization.manifest_id);
        bytes.extend_from_slice(&self.authorization.sender_id);
        bytes.extend_from_slice(&self.authorization.recipient_id);
        bytes.extend_from_slice(&self.authorization.nonce.to_be_bytes());
        bytes.extend_from_slice(&self.authorization.amount_atoms.to_be_bytes());
        bytes.extend_from_slice(&self.authorization.fee_atoms.to_be_bytes());
        bytes.extend_from_slice(&self.authorization.expires_at.to_be_bytes());
        bytes.extend_from_slice(&(self.authorization.identity_scheme as u16).to_be_bytes());
        bytes.extend_from_slice(&V4_HYBRID_AUTH_SUITE_ID.to_be_bytes());
        bytes.extend_from_slice(&self.authorization.ed25519_public_key);
        bytes.extend_from_slice(&self.authorization.mldsa65_public_key);
        bytes.extend_from_slice(&self.signature.ed25519_signature);
        bytes.extend_from_slice(&self.signature.mldsa65_signature);
        debug_assert_eq!(bytes.len(), V4_HYBRID_TRANSACTION_WIRE_BYTES);
        Ok(bytes)
    }

    /// Decode only the exact canonical TXN4 length/version/suite and then validate account binding.
    /// This rejects truncation, suffix malleability, unknown schemes and silent suite fallback.
    pub fn decode(bytes: &[u8]) -> Result<Self, IdentityContinuityError> {
        if bytes.len() != V4_HYBRID_TRANSACTION_WIRE_BYTES {
            return Err(IdentityContinuityError::WrongWireLength {
                actual: bytes.len(),
                expected: V4_HYBRID_TRANSACTION_WIRE_BYTES,
            });
        }
        if bytes[..4] != V4_TRANSACTION_MAGIC {
            return Err(IdentityContinuityError::WrongWireMagic);
        }
        let version = u16::from_be_bytes(bytes[4..6].try_into().expect("fixed header length"));
        if version != V4_TRANSACTION_WIRE_VERSION {
            return Err(IdentityContinuityError::UnsupportedWireVersion(version));
        }
        let identity_scheme = AccountIdentityScheme::try_from(u16::from_be_bytes(
            bytes[166..168].try_into().expect("fixed TXN4 layout"),
        ))?;
        let auth_suite = u16::from_be_bytes(bytes[168..170].try_into().expect("fixed TXN4 layout"));
        if auth_suite != V4_HYBRID_AUTH_SUITE_ID {
            return Err(IdentityContinuityError::UnsupportedAuthSuite(auth_suite));
        }
        let authorization = V4HybridAuthorization {
            network_id: bytes[6..38].try_into().expect("fixed TXN4 layout"),
            manifest_id: bytes[38..70].try_into().expect("fixed TXN4 layout"),
            sender_id: bytes[70..102].try_into().expect("fixed TXN4 layout"),
            recipient_id: bytes[102..134].try_into().expect("fixed TXN4 layout"),
            nonce: u64::from_be_bytes(bytes[134..142].try_into().expect("fixed TXN4 layout")),
            amount_atoms: u64::from_be_bytes(
                bytes[142..150].try_into().expect("fixed TXN4 layout"),
            ),
            fee_atoms: u64::from_be_bytes(bytes[150..158].try_into().expect("fixed TXN4 layout")),
            expires_at: u64::from_be_bytes(bytes[158..166].try_into().expect("fixed TXN4 layout")),
            identity_scheme,
            ed25519_public_key: bytes[170..202].try_into().expect("fixed TXN4 layout"),
            mldsa65_public_key: bytes[202..2154].try_into().expect("fixed TXN4 layout"),
        };
        authorization.validate()?;
        let signature = V4HybridSignature {
            ed25519_signature: bytes[2154..2218].try_into().expect("fixed TXN4 layout"),
            mldsa65_signature: bytes[2218..5527].try_into().expect("fixed TXN4 layout"),
        };
        Ok(Self {
            authorization,
            signature,
        })
    }

    /// Verify both halves against the same domain-separated V4 signing digest.
    pub fn verify<V: MlDsa65Verifier>(
        &self,
        mldsa_verifier: &V,
    ) -> Result<(), IdentityContinuityError> {
        self.authorization
            .verify_hybrid_signature(&self.signature, mldsa_verifier)
    }
}

/// Mandatory integration boundary for an independently pinned ML-DSA-65 implementation.
/// Production code must inject the real verifier; there is no accept-all fallback.
pub trait MlDsa65Verifier {
    fn verify(
        &self,
        public_key: &[u8; ML_DSA_65_PUBLIC_KEY_BYTES],
        message: &[u8; 32],
        signature: &[u8; ML_DSA_65_SIGNATURE_BYTES],
    ) -> bool;
}

fn all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

/// Legacy V3 ID: SHA-256("AIN1-ACCOUNT-ID-V3\\0" || u16(3) || Ed25519_pk || ML-DSA-65_pk).
/// This exact byte formula preserves the ID to which a migrated STV3 balance is keyed.
pub fn legacy_v3_account_id(
    ed25519_public_key: &[u8; ED25519_PUBLIC_KEY_BYTES],
    mldsa65_public_key: &[u8; ML_DSA_65_PUBLIC_KEY_BYTES],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(LEGACY_V3_ID_DOMAIN);
    hash.update(HYBRID_SUITE_V3_ID.to_be_bytes());
    hash.update(ed25519_public_key);
    hash.update(mldsa65_public_key);
    hash.finalize().into()
}

/// Native V4 ID: uses a different domain and identity-scheme ID.
pub fn native_v4_account_id(
    ed25519_public_key: &[u8; ED25519_PUBLIC_KEY_BYTES],
    mldsa65_public_key: &[u8; ML_DSA_65_PUBLIC_KEY_BYTES],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(NATIVE_V4_ID_DOMAIN);
    hash.update((AccountIdentityScheme::NativeV4Hybrid as u16).to_be_bytes());
    hash.update(ed25519_public_key);
    hash.update(mldsa65_public_key);
    hash.finalize().into()
}

impl V4HybridAuthorization {
    pub fn derive_sender_id(&self) -> [u8; 32] {
        match self.identity_scheme {
            AccountIdentityScheme::LegacyV3Hybrid => {
                legacy_v3_account_id(&self.ed25519_public_key, &self.mldsa65_public_key)
            }
            AccountIdentityScheme::NativeV4Hybrid => {
                native_v4_account_id(&self.ed25519_public_key, &self.mldsa65_public_key)
            }
        }
    }

    pub fn validate(&self) -> Result<(), IdentityContinuityError> {
        for (name, bytes) in [
            ("network_id", self.network_id.as_slice()),
            ("manifest_id", self.manifest_id.as_slice()),
            ("sender_id", self.sender_id.as_slice()),
            ("recipient_id", self.recipient_id.as_slice()),
        ] {
            if all_zero(bytes) {
                return Err(IdentityContinuityError::ZeroField(name));
            }
        }
        if self.nonce == 0 {
            return Err(IdentityContinuityError::InvalidNonce);
        }
        if self.amount_atoms == 0 {
            return Err(IdentityContinuityError::InvalidAmount);
        }
        if self.expires_at == 0 {
            return Err(IdentityContinuityError::InvalidExpiry);
        }
        if all_zero(&self.ed25519_public_key) {
            return Err(IdentityContinuityError::ZeroKey("Ed25519 public key"));
        }
        if all_zero(&self.mldsa65_public_key) {
            return Err(IdentityContinuityError::ZeroKey("ML-DSA-65 public key"));
        }
        if self.derive_sender_id() != self.sender_id {
            return Err(IdentityContinuityError::AccountIdMismatch);
        }
        Ok(())
    }

    /// Byte-exact signing input for the V4 authorization candidate.
    /// Network and manifest IDs, selected identity scheme, sender/recipient, replay controls,
    /// economic fields and both public keys are included; V3 signed bytes cannot be replayed.
    pub fn signing_preimage(&self) -> Result<Vec<u8>, IdentityContinuityError> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(
            V4_TX_SIGN_DOMAIN.len()
                + 2
                + 32 * 4
                + 8 * 4
                + 2
                + 2
                + ED25519_PUBLIC_KEY_BYTES
                + ML_DSA_65_PUBLIC_KEY_BYTES,
        );
        bytes.extend_from_slice(V4_TX_SIGN_DOMAIN);
        bytes.extend_from_slice(&V4_VERSION.to_be_bytes());
        bytes.extend_from_slice(&self.network_id);
        bytes.extend_from_slice(&self.manifest_id);
        bytes.extend_from_slice(&self.sender_id);
        bytes.extend_from_slice(&self.recipient_id);
        bytes.extend_from_slice(&self.nonce.to_be_bytes());
        bytes.extend_from_slice(&self.amount_atoms.to_be_bytes());
        bytes.extend_from_slice(&self.fee_atoms.to_be_bytes());
        bytes.extend_from_slice(&self.expires_at.to_be_bytes());
        bytes.extend_from_slice(&(self.identity_scheme as u16).to_be_bytes());
        bytes.extend_from_slice(&V4_HYBRID_AUTH_SUITE_ID.to_be_bytes());
        bytes.extend_from_slice(&self.ed25519_public_key);
        bytes.extend_from_slice(&self.mldsa65_public_key);
        Ok(bytes)
    }

    pub fn signing_digest(&self) -> Result<[u8; 32], IdentityContinuityError> {
        Ok(Sha256::digest(self.signing_preimage()?).into())
    }

    /// Fails closed unless BOTH real Ed25519 verification and the injected ML-DSA-65
    /// verifier accept the same V4 digest. This module does not supply a PQ implementation.
    pub fn verify_hybrid_signature<V: MlDsa65Verifier>(
        &self,
        signature: &V4HybridSignature,
        mldsa_verifier: &V,
    ) -> Result<(), IdentityContinuityError> {
        let digest = self.signing_digest()?;
        let ed_key = VerifyingKey::from_bytes(&self.ed25519_public_key)
            .map_err(|_| IdentityContinuityError::InvalidEd25519PublicKey)?;
        let ed_signature = EdSignature::from_bytes(&signature.ed25519_signature);
        ed_key
            .verify_strict(&digest, &ed_signature)
            .map_err(|_| IdentityContinuityError::InvalidEd25519Signature)?;

        if !mldsa_verifier.verify(
            &self.mldsa65_public_key,
            &digest,
            &signature.mldsa65_signature,
        ) {
            return Err(IdentityContinuityError::InvalidMlDsa65Signature);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    struct ExpectedPqTestVerifier {
        public_key: [u8; ML_DSA_65_PUBLIC_KEY_BYTES],
        digest: [u8; 32],
        signature: [u8; ML_DSA_65_SIGNATURE_BYTES],
    }
    impl MlDsa65Verifier for ExpectedPqTestVerifier {
        fn verify(
            &self,
            public_key: &[u8; ML_DSA_65_PUBLIC_KEY_BYTES],
            message: &[u8; 32],
            signature: &[u8; ML_DSA_65_SIGNATURE_BYTES],
        ) -> bool {
            *public_key == self.public_key
                && *message == self.digest
                && *signature == self.signature
        }
    }
    const VECTOR_FILE: &str =
        include_str!("../../../../simulations/cp0226_account_identity_vectors.tsv");
    const CONTINUITY_VECTOR_FILE: &str =
        include_str!("../../../../simulations/cp0233_v3_v4_spend_continuity_vectors.tsv");

    fn continuity_vector_value(key: &str) -> &str {
        CONTINUITY_VECTOR_FILE
            .lines()
            .filter(|line| !line.starts_with('#'))
            .find_map(|line| {
                let (name, value) = line.split_once('\t')?;
                (name == key).then_some(value)
            })
            .expect("required CP-0233 V3/V4 continuity vector")
    }

    fn continuity_vector_hex(key: &str) -> Vec<u8> {
        let hex = continuity_vector_value(key);
        assert_eq!(hex.len() % 2, 0, "even hex width for {key}");
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid CP-0233 vector hex"))
            .collect()
    }

    fn continuity_vector_hex32(key: &str) -> [u8; 32] {
        continuity_vector_hex(key)
            .try_into()
            .unwrap_or_else(|_| panic!("CP-0233 vector {key} must be 32 bytes"))
    }

    // Independent test oracle for the CP-0215 TXN3 unsigned preimage. This deliberately
    // constructs bytes from the written field contract rather than calling the V3 codec.
    fn legacy_v3_unsigned_preimage(authorization: &V4HybridAuthorization) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(2122);
        bytes.extend_from_slice(b"TXN3");
        bytes.extend_from_slice(&3u16.to_be_bytes());
        bytes.extend_from_slice(&authorization.network_id);
        bytes.extend_from_slice(&authorization.sender_id);
        bytes.extend_from_slice(&authorization.recipient_id);
        bytes.extend_from_slice(&authorization.nonce.to_be_bytes());
        bytes.extend_from_slice(&authorization.amount_atoms.to_be_bytes());
        bytes.extend_from_slice(&authorization.fee_atoms.to_be_bytes());
        bytes.extend_from_slice(&authorization.expires_at.to_be_bytes());
        bytes.extend_from_slice(&HYBRID_SUITE_V3_ID.to_be_bytes());
        bytes.extend_from_slice(&1984u16.to_be_bytes());
        bytes.extend_from_slice(&authorization.ed25519_public_key);
        bytes.extend_from_slice(&authorization.mldsa65_public_key);
        bytes
    }

    fn legacy_v3_signing_digest(authorization: &V4HybridAuthorization) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"AIN1-TX-SIGN-V3");
        hash.update([0u8]);
        hash.update(legacy_v3_unsigned_preimage(authorization));
        hash.finalize().into()
    }

    fn vector_value(key: &str) -> &str {
        VECTOR_FILE
            .lines()
            .filter(|line| !line.starts_with('#'))
            .find_map(|line| {
                let (name, value) = line.split_once('\t')?;
                (name == key).then_some(value)
            })
            .expect("required CP-0226 cross-language vector")
    }

    fn vector_hex32(key: &str) -> [u8; 32] {
        let hex = vector_value(key);
        assert_eq!(hex.len(), 64);
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("valid vector hex");
        }
        out
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        let digest = Sha256::digest(bytes);
        digest.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn bytes_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn fixture(scheme: AccountIdentityScheme) -> (SigningKey, V4HybridAuthorization) {
        let ed_signer = SigningKey::from_bytes(&[0x42; 32]);
        let ed_pk = ed_signer.verifying_key().to_bytes();
        let pq_pk = [0x53; ML_DSA_65_PUBLIC_KEY_BYTES];
        let sender_id = match scheme {
            AccountIdentityScheme::LegacyV3Hybrid => legacy_v3_account_id(&ed_pk, &pq_pk),
            AccountIdentityScheme::NativeV4Hybrid => native_v4_account_id(&ed_pk, &pq_pk),
        };
        (
            ed_signer,
            V4HybridAuthorization {
                network_id: [0xA1; 32],
                manifest_id: [0xB2; 32],
                sender_id,
                recipient_id: [0xC3; 32],
                nonce: 1,
                amount_atoms: 123_456,
                fee_atoms: 789,
                expires_at: 1_900_000_000,
                identity_scheme: scheme,
                ed25519_public_key: ed_pk,
                mldsa65_public_key: pq_pk,
            },
        )
    }

    fn test_signature(
        ed_signer: &SigningKey,
        authorization: &V4HybridAuthorization,
    ) -> (V4HybridSignature, ExpectedPqTestVerifier) {
        let digest = authorization.signing_digest().unwrap();
        let ed_sig = ed_signer.sign(&digest).to_bytes();
        let pq_sig = [0x6D; ML_DSA_65_SIGNATURE_BYTES]; // synthetic marker, not ML-DSA
        let verifier = ExpectedPqTestVerifier {
            public_key: authorization.mldsa65_public_key,
            digest,
            signature: pq_sig,
        };
        (
            V4HybridSignature {
                ed25519_signature: ed_sig,
                mldsa65_signature: pq_sig,
            },
            verifier,
        )
    }
    #[test]
    fn python_26_cross_language_golden_vectors_match_rust() {
        let ed_pk = [0x11; ED25519_PUBLIC_KEY_BYTES];
        let pq_pk = [0x22; ML_DSA_65_PUBLIC_KEY_BYTES];

        let legacy_id = legacy_v3_account_id(&ed_pk, &pq_pk);
        assert_eq!(legacy_id, vector_hex32("legacy.sender_id_hex"));
        let legacy = V4HybridAuthorization {
            network_id: [0xA1; 32],
            manifest_id: [0xB2; 32],
            sender_id: legacy_id,
            recipient_id: [0xC3; 32],
            nonce: 1,
            amount_atoms: 123456,
            fee_atoms: 789,
            expires_at: 1_900_000_000,
            identity_scheme: AccountIdentityScheme::LegacyV3Hybrid,
            ed25519_public_key: ed_pk,
            mldsa65_public_key: pq_pk,
        };
        let legacy_preimage = legacy.signing_preimage().unwrap();
        assert_eq!(
            legacy_preimage.len().to_string(),
            vector_value("legacy.preimage_bytes")
        );
        assert_eq!(
            sha256_hex(&legacy_preimage),
            vector_value("legacy.preimage_sha256")
        );

        let native_id = native_v4_account_id(&ed_pk, &pq_pk);
        assert_eq!(native_id, vector_hex32("native.sender_id_hex"));
        let native = V4HybridAuthorization {
            sender_id: native_id,
            identity_scheme: AccountIdentityScheme::NativeV4Hybrid,
            ..legacy.clone()
        };
        let native_preimage = native.signing_preimage().unwrap();
        assert_eq!(
            native_preimage.len().to_string(),
            vector_value("native.preimage_bytes")
        );
        assert_eq!(
            sha256_hex(&native_preimage),
            vector_value("native.preimage_sha256")
        );

        let mut changed = legacy.clone();
        changed.network_id = [0xA2; 32];
        assert_eq!(
            sha256_hex(&changed.signing_preimage().unwrap()),
            vector_value("mutation.network_digest")
        );

        let mut changed = legacy.clone();
        changed.manifest_id = [0xB3; 32];
        assert_eq!(
            sha256_hex(&changed.signing_preimage().unwrap()),
            vector_value("mutation.manifest_digest")
        );

        let mut changed = legacy.clone();
        changed.recipient_id = [0xC4; 32];
        assert_eq!(
            sha256_hex(&changed.signing_preimage().unwrap()),
            vector_value("mutation.recipient_digest")
        );

        let mut changed = legacy.clone();
        changed.nonce = 2;
        assert_eq!(
            sha256_hex(&changed.signing_preimage().unwrap()),
            vector_value("mutation.nonce_digest")
        );

        let mut changed = legacy.clone();
        changed.amount_atoms += 1;
        assert_eq!(
            sha256_hex(&changed.signing_preimage().unwrap()),
            vector_value("mutation.amount_digest")
        );

        let mut changed = legacy.clone();
        changed.fee_atoms += 1;
        assert_eq!(
            sha256_hex(&changed.signing_preimage().unwrap()),
            vector_value("mutation.fee_digest")
        );

        let mut changed = legacy.clone();
        changed.expires_at += 1;
        assert_eq!(
            sha256_hex(&changed.signing_preimage().unwrap()),
            vector_value("mutation.expiry_digest")
        );

        let mut changed = legacy.clone();
        changed.ed25519_public_key = [0x12; ED25519_PUBLIC_KEY_BYTES];
        changed.sender_id = changed.derive_sender_id();
        assert_eq!(
            sha256_hex(&changed.signing_preimage().unwrap()),
            vector_value("mutation.ed_key_digest")
        );

        let mut changed = legacy;
        changed.mldsa65_public_key = [0x23; ML_DSA_65_PUBLIC_KEY_BYTES];
        changed.sender_id = changed.derive_sender_id();
        assert_eq!(
            sha256_hex(&changed.signing_preimage().unwrap()),
            vector_value("mutation.pq_key_digest")
        );
    }
    #[test]
    fn legacy_v3_id_matches_frozen_formula_without_cross_module_calls() {
        let ed = [0x21; 32];
        let pq = [0x32; ML_DSA_65_PUBLIC_KEY_BYTES];
        let observed = legacy_v3_account_id(&ed, &pq);
        let mut independent = Sha256::new();
        independent.update(b"AIN1-ACCOUNT-ID-V3\0");
        independent.update(3u16.to_be_bytes());
        independent.update(ed);
        independent.update(pq);
        let expected: [u8; 32] = independent.finalize().into();
        assert_eq!(observed, expected);
    }

    #[test]
    fn legacy_identity_is_preserved_while_native_v4_is_domain_separated() {
        let (_, legacy) = fixture(AccountIdentityScheme::LegacyV3Hybrid);
        let (_, native) = fixture(AccountIdentityScheme::NativeV4Hybrid);
        assert_eq!(legacy.sender_id, legacy.derive_sender_id());
        assert_eq!(native.sender_id, native.derive_sender_id());
        assert_ne!(legacy.sender_id, native.sender_id);
        assert_ne!(
            legacy.signing_digest().unwrap(),
            native.signing_digest().unwrap()
        );
    }

    #[test]
    fn v4_digest_changes_with_network_manifest_and_every_authorization_dimension() {
        let (_, base) = fixture(AccountIdentityScheme::LegacyV3Hybrid);
        let digest = base.signing_digest().unwrap();

        let mut changed = base.clone();
        changed.network_id[0] ^= 1;
        assert_ne!(changed.signing_digest().unwrap(), digest);

        let mut changed = base.clone();
        changed.manifest_id[0] ^= 1;
        assert_ne!(changed.signing_digest().unwrap(), digest);

        let mut changed = base.clone();
        changed.recipient_id[0] ^= 1;
        assert_ne!(changed.signing_digest().unwrap(), digest);

        let mut changed = base.clone();
        changed.nonce += 1;
        assert_ne!(changed.signing_digest().unwrap(), digest);

        let mut changed = base.clone();
        changed.amount_atoms += 1;
        assert_ne!(changed.signing_digest().unwrap(), digest);

        let mut changed = base.clone();
        changed.fee_atoms += 1;
        assert_ne!(changed.signing_digest().unwrap(), digest);

        let mut changed = base.clone();
        changed.expires_at += 1;
        assert_ne!(changed.signing_digest().unwrap(), digest);
    }

    #[test]
    fn sender_must_match_selected_identity_scheme_and_unknown_scheme_rejects() {
        let (_, base) = fixture(AccountIdentityScheme::LegacyV3Hybrid);
        let mut changed = base.clone();
        changed.sender_id = [0xCC; 32];
        assert_eq!(
            changed.validate(),
            Err(IdentityContinuityError::AccountIdMismatch)
        );
        assert_eq!(
            AccountIdentityScheme::try_from(5),
            Err(IdentityContinuityError::UnknownIdentityScheme(5))
        );
    }

    #[test]
    fn rejects_zero_identity_key_nonce_amount_and_expiry_fields() {
        let (_, base) = fixture(AccountIdentityScheme::LegacyV3Hybrid);
        let mut changed = base.clone();
        changed.network_id = [0; 32];
        assert_eq!(
            changed.validate(),
            Err(IdentityContinuityError::ZeroField("network_id"))
        );

        let mut changed = base.clone();
        changed.mldsa65_public_key = [0; ML_DSA_65_PUBLIC_KEY_BYTES];
        assert_eq!(
            changed.validate(),
            Err(IdentityContinuityError::ZeroKey("ML-DSA-65 public key"))
        );

        let mut changed = base.clone();
        changed.nonce = 0;
        assert_eq!(
            changed.validate(),
            Err(IdentityContinuityError::InvalidNonce)
        );

        let mut changed = base.clone();
        changed.amount_atoms = 0;
        assert_eq!(
            changed.validate(),
            Err(IdentityContinuityError::InvalidAmount)
        );

        let mut changed = base.clone();
        changed.expires_at = 0;
        assert_eq!(
            changed.validate(),
            Err(IdentityContinuityError::InvalidExpiry)
        );
    }

    #[test]
    fn both_signature_halves_are_required_and_bound_to_the_v4_digest() {
        let (ed_signer, authorization) = fixture(AccountIdentityScheme::LegacyV3Hybrid);
        let (signature, pq_verifier) = test_signature(&ed_signer, &authorization);
        assert!(authorization
            .verify_hybrid_signature(&signature, &pq_verifier)
            .is_ok());

        let mut tampered_ed = signature.clone();
        tampered_ed.ed25519_signature[0] ^= 1;
        assert_eq!(
            authorization.verify_hybrid_signature(&tampered_ed, &pq_verifier),
            Err(IdentityContinuityError::InvalidEd25519Signature)
        );

        let mut tampered_pq = signature.clone();
        tampered_pq.mldsa65_signature[0] ^= 1;
        assert_eq!(
            authorization.verify_hybrid_signature(&tampered_pq, &pq_verifier),
            Err(IdentityContinuityError::InvalidMlDsa65Signature)
        );

        let mut tampered_authorization = authorization.clone();
        tampered_authorization.amount_atoms += 1;
        assert_eq!(
            tampered_authorization.verify_hybrid_signature(&signature, &pq_verifier),
            Err(IdentityContinuityError::InvalidEd25519Signature)
        );
    }

    #[test]
    fn preimage_contains_both_domains_and_fixed_key_tuple() {
        let (_, authorization) = fixture(AccountIdentityScheme::LegacyV3Hybrid);
        let bytes = authorization.signing_preimage().unwrap();
        assert!(bytes.starts_with(V4_TX_SIGN_DOMAIN));
        assert_eq!(
            bytes.len(),
            V4_TX_SIGN_DOMAIN.len() + 2 + 32 * 4 + 8 * 4 + 2 + 2 + 32 + ML_DSA_65_PUBLIC_KEY_BYTES
        );
        assert!(bytes
            .windows(LEGACY_V3_ID_DOMAIN.len())
            .all(|window| window != LEGACY_V3_ID_DOMAIN));
    }

    #[test]
    fn python_27_cross_language_v3_v4_spend_continuity_vectors_match_rust() {
        let ed_pk = continuity_vector_hex32("fixture.ed25519_public_key_hex");
        let pq_fill = u8::from_str_radix(
            continuity_vector_value("fixture.mldsa65_public_key_fill"),
            16,
        )
        .expect("valid synthetic public-key fill");
        let pq_pk = [pq_fill; ML_DSA_65_PUBLIC_KEY_BYTES];
        let network_id = continuity_vector_hex32("fixture.network_id_hex");
        let manifest_id = continuity_vector_hex32("fixture.manifest_id_hex");
        let recipient_id = continuity_vector_hex32("fixture.recipient_id_hex");
        let legacy_id = legacy_v3_account_id(&ed_pk, &pq_pk);

        assert_eq!(legacy_id, continuity_vector_hex32("legacy.sender_id_hex"));
        let legacy = V4HybridAuthorization {
            network_id,
            manifest_id,
            sender_id: legacy_id,
            recipient_id,
            nonce: continuity_vector_value("fixture.nonce").parse().unwrap(),
            amount_atoms: continuity_vector_value("fixture.amount_atoms")
                .parse()
                .unwrap(),
            fee_atoms: continuity_vector_value("fixture.fee_atoms")
                .parse()
                .unwrap(),
            expires_at: continuity_vector_value("fixture.expires_at")
                .parse()
                .unwrap(),
            identity_scheme: AccountIdentityScheme::LegacyV3Hybrid,
            ed25519_public_key: ed_pk,
            mldsa65_public_key: pq_pk,
        };

        let legacy_v3_preimage = legacy_v3_unsigned_preimage(&legacy);
        assert_eq!(
            legacy_v3_preimage.len().to_string(),
            continuity_vector_value("legacy.v3_unsigned_bytes")
        );
        let v3_digest = legacy_v3_signing_digest(&legacy);
        assert_eq!(
            bytes_hex(&v3_digest),
            continuity_vector_value("legacy.v3_signing_digest_hex")
        );

        let v4_digest = legacy.signing_digest().unwrap();
        assert_eq!(
            legacy.signing_preimage().unwrap().len().to_string(),
            continuity_vector_value("legacy.v4_signing_preimage_bytes")
        );
        assert_eq!(
            bytes_hex(&v4_digest),
            continuity_vector_value("legacy.v4_signing_digest_hex")
        );
        assert_ne!(v3_digest, v4_digest);
        assert_eq!(
            continuity_vector_value("domain.v3_v4_digest_equal"),
            "false"
        );

        let native_id = native_v4_account_id(&ed_pk, &pq_pk);
        assert_eq!(native_id, continuity_vector_hex32("native.sender_id_hex"));
        let native = V4HybridAuthorization {
            sender_id: native_id,
            identity_scheme: AccountIdentityScheme::NativeV4Hybrid,
            ..legacy.clone()
        };
        assert_eq!(
            native.signing_preimage().unwrap().len().to_string(),
            continuity_vector_value("native.v4_signing_preimage_bytes")
        );
        assert_eq!(
            bytes_hex(&native.signing_digest().unwrap()),
            continuity_vector_value("native.v4_signing_digest_hex")
        );
        assert_ne!(
            legacy.signing_digest().unwrap(),
            native.signing_digest().unwrap()
        );
        assert_eq!(
            continuity_vector_value("domain.legacy_native_v4_digest_equal"),
            "false"
        );

        let mut changed_ed = ed_pk;
        changed_ed[0] ^= 1;
        assert_eq!(
            legacy_v3_account_id(&changed_ed, &pq_pk),
            continuity_vector_hex32("mutation.ed_key_sender_id_hex")
        );
        assert_ne!(legacy_v3_account_id(&changed_ed, &pq_pk), legacy_id);
        assert_eq!(
            continuity_vector_value("mutation.ed_key_keeps_legacy_id"),
            "false"
        );

        let mut changed_pq = pq_pk;
        changed_pq[0] ^= 1;
        assert_eq!(
            legacy_v3_account_id(&ed_pk, &changed_pq),
            continuity_vector_hex32("mutation.pq_key_sender_id_hex")
        );
        assert_ne!(legacy_v3_account_id(&ed_pk, &changed_pq), legacy_id);
        assert_eq!(
            continuity_vector_value("mutation.pq_key_keeps_legacy_id"),
            "false"
        );
    }

    #[test]
    fn migrated_v3_balance_requires_the_exact_original_hybrid_public_key_tuple() {
        use std::collections::BTreeMap;

        let (_, legacy) = fixture(AccountIdentityScheme::LegacyV3Hybrid);
        let original_v3_id = legacy.sender_id;
        let migrated_balances = BTreeMap::from([(original_v3_id, 123_456_u64)]);
        assert_eq!(legacy.validate(), Ok(()));
        assert_eq!(migrated_balances.get(&original_v3_id), Some(&123_456));

        let mut changed_ed = legacy.clone();
        changed_ed.ed25519_public_key[0] ^= 1;
        assert_eq!(
            changed_ed.validate(),
            Err(IdentityContinuityError::AccountIdMismatch)
        );
        let rebound_ed_id = changed_ed.derive_sender_id();
        assert_ne!(rebound_ed_id, original_v3_id);
        changed_ed.sender_id = rebound_ed_id;
        assert_eq!(changed_ed.validate(), Ok(()));
        assert!(
            !migrated_balances.contains_key(&changed_ed.sender_id),
            "a substituted Ed25519 key derives a new account and cannot select the migrated V3 balance"
        );

        let mut changed_pq = legacy.clone();
        changed_pq.mldsa65_public_key[0] ^= 1;
        assert_eq!(
            changed_pq.validate(),
            Err(IdentityContinuityError::AccountIdMismatch)
        );
        let rebound_pq_id = changed_pq.derive_sender_id();
        assert_ne!(rebound_pq_id, original_v3_id);
        changed_pq.sender_id = rebound_pq_id;
        assert_eq!(changed_pq.validate(), Ok(()));
        assert!(
            !migrated_balances.contains_key(&changed_pq.sender_id),
            "a substituted ML-DSA public key derives a new account and cannot select the migrated V3 balance"
        );

        let mut wrong_scheme = legacy;
        wrong_scheme.identity_scheme = AccountIdentityScheme::NativeV4Hybrid;
        assert_eq!(
            wrong_scheme.validate(),
            Err(IdentityContinuityError::AccountIdMismatch),
            "an unchanged V3 ID cannot be re-labelled as a native V4 identity"
        );
        assert!(
            !migrated_balances.contains_key(&wrong_scheme.derive_sender_id()),
            "native V4 identity is domain-separated from the migrated V3 account"
        );
    }

    #[test]
    fn legacy_v3_transaction_signatures_cannot_replay_on_the_v4_signing_domain() {
        let (ed_signer, authorization) = fixture(AccountIdentityScheme::LegacyV3Hybrid);
        let v3_digest = legacy_v3_signing_digest(&authorization);
        let v4_digest = authorization.signing_digest().unwrap();
        assert_ne!(v3_digest, v4_digest);

        // This is a real deterministic Ed25519 test signature for V3 bytes, not a production key.
        let old_ed_signature = ed_signer.sign(&v3_digest).to_bytes();
        // Synthetic marker only: this is explicitly NOT an ML-DSA signature.
        let old_pq_signature = [0x7B; ML_DSA_65_SIGNATURE_BYTES];
        let v3_bound_pq_verifier = ExpectedPqTestVerifier {
            public_key: authorization.mldsa65_public_key,
            digest: v3_digest,
            signature: old_pq_signature,
        };

        let replay = V4HybridSignature {
            ed25519_signature: old_ed_signature,
            mldsa65_signature: old_pq_signature,
        };
        assert_eq!(
            authorization.verify_hybrid_signature(&replay, &v3_bound_pq_verifier),
            Err(IdentityContinuityError::InvalidEd25519Signature),
            "an Ed25519 signature made for TXN3 must not verify against the V4 digest"
        );

        // Even a valid V4 Ed25519 half cannot make a V3-bound PQ half acceptable.
        let v4_ed_signature = ed_signer.sign(&v4_digest).to_bytes();
        let replayed_pq_half = V4HybridSignature {
            ed25519_signature: v4_ed_signature,
            mldsa65_signature: old_pq_signature,
        };
        assert_eq!(
            authorization.verify_hybrid_signature(&replayed_pq_half, &v3_bound_pq_verifier),
            Err(IdentityContinuityError::InvalidMlDsa65Signature),
            "the PQ verifier contract must bind its result to the V4 digest and exact signature"
        );
    }

    #[test]
    fn txn4_canonical_wire_round_trips_both_identity_schemes() {
        for scheme in [
            AccountIdentityScheme::LegacyV3Hybrid,
            AccountIdentityScheme::NativeV4Hybrid,
        ] {
            let (ed_signer, authorization) = fixture(scheme);
            let (signature, _) = test_signature(&ed_signer, &authorization);
            let transaction = V4HybridTransaction {
                authorization,
                signature,
            };
            let bytes = transaction.encode().unwrap();
            assert_eq!(bytes.len(), V4_HYBRID_TRANSACTION_WIRE_BYTES);
            assert_eq!(&bytes[..4], &V4_TRANSACTION_MAGIC);
            let decoded = V4HybridTransaction::decode(&bytes).unwrap();
            assert_eq!(decoded, transaction);
            assert_eq!(decoded.encode().unwrap(), bytes);
        }
    }

    #[test]
    fn txn4_decode_rejects_noncanonical_headers_lengths_and_key_binding() {
        let (ed_signer, authorization) = fixture(AccountIdentityScheme::LegacyV3Hybrid);
        let (signature, _) = test_signature(&ed_signer, &authorization);
        let bytes = V4HybridTransaction {
            authorization,
            signature,
        }
        .encode()
        .unwrap();

        assert!(matches!(
            V4HybridTransaction::decode(&bytes[..bytes.len() - 1]),
            Err(IdentityContinuityError::WrongWireLength { .. })
        ));
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(matches!(
            V4HybridTransaction::decode(&trailing),
            Err(IdentityContinuityError::WrongWireLength { .. })
        ));

        let mut changed = bytes.clone();
        changed[0] ^= 1;
        assert_eq!(
            V4HybridTransaction::decode(&changed),
            Err(IdentityContinuityError::WrongWireMagic)
        );
        let mut changed = bytes.clone();
        changed[5] ^= 1;
        assert_eq!(
            V4HybridTransaction::decode(&changed),
            Err(IdentityContinuityError::UnsupportedWireVersion(5))
        );
        let mut changed = bytes.clone();
        changed[166..168].copy_from_slice(&5u16.to_be_bytes());
        assert_eq!(
            V4HybridTransaction::decode(&changed),
            Err(IdentityContinuityError::UnknownIdentityScheme(5))
        );
        let mut changed = bytes.clone();
        changed[168..170].copy_from_slice(&99u16.to_be_bytes());
        assert_eq!(
            V4HybridTransaction::decode(&changed),
            Err(IdentityContinuityError::UnsupportedAuthSuite(99))
        );
        let mut changed = bytes;
        changed[70] ^= 1; // sender ID no longer matches the encoded hybrid public-key tuple.
        assert_eq!(
            V4HybridTransaction::decode(&changed),
            Err(IdentityContinuityError::AccountIdMismatch)
        );
    }

    #[test]
    fn txn4_round_trip_verifies_real_ed25519_and_mldsa65_signatures() {
        use crate::v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate;
        use libcrux_ml_dsa::ml_dsa_65::portable;

        let (ed_signer, mut authorization) = fixture(AccountIdentityScheme::NativeV4Hybrid);
        let pq_pair = portable::generate_key_pair([0x66u8; 32]);
        authorization.mldsa65_public_key = *pq_pair.verification_key.as_ref();
        authorization.sender_id = authorization.derive_sender_id();
        let digest = authorization.signing_digest().unwrap();
        let ed_signature = ed_signer.sign(&digest).to_bytes();
        let pq_signature = portable::sign(&pq_pair.signing_key, &digest, &[], [0x77u8; 32])
            .expect("deterministic test ML-DSA signature should succeed");
        let pq_signature: [u8; ML_DSA_65_SIGNATURE_BYTES] = *pq_signature.as_ref();
        let transaction = V4HybridTransaction {
            authorization,
            signature: V4HybridSignature {
                ed25519_signature: ed_signature,
                mldsa65_signature: pq_signature,
            },
        };
        let bytes = transaction.encode().unwrap();
        let decoded = V4HybridTransaction::decode(&bytes).unwrap();
        let verifier = LibcruxMlDsa65VerifierCandidate;
        assert_eq!(decoded.verify(&verifier), Ok(()));

        let mut tampered_pq = decoded.clone();
        tampered_pq.signature.mldsa65_signature[0] ^= 1;
        assert_eq!(
            tampered_pq.verify(&verifier),
            Err(IdentityContinuityError::InvalidMlDsa65Signature)
        );
        let mut tampered_ed = decoded;
        tampered_ed.signature.ed25519_signature[0] ^= 1;
        assert_eq!(
            tampered_ed.verify(&verifier),
            Err(IdentityContinuityError::InvalidEd25519Signature)
        );
    }
}
