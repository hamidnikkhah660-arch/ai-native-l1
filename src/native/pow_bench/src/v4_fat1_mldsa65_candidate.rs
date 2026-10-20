//! CP-0291 candidate adapter for raw FIPS 204 ML-DSA-65 signatures.
//!
//! This uses the pinned Libcrux implementation. Upstream describes arithmetic, NTT polynomial
//! arithmetic and serialization as formally verified, but that is not a blanket deployment
//! approval for this network or for its authority/key-management design. This adapter is NOT
//! production-approved and MUST NOT activate STV4, close release gates, or authorize Mainnet.
//! FAT1 has no runtime callsite here; this adapter makes real ML-DSA acceptance/rejection tests
//! possible while leaving the independent review and integration gates explicit.
use crate::v4_fat1_trust_candidate::{
    MlDsa65Verifier, ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SIGNATURE_BYTES,
};
use libcrux_ml_dsa::ml_dsa_65::{portable, MLDSA65Signature, MLDSA65VerificationKey};

#[derive(Clone, Copy, Debug, Default)]
pub struct LibcruxMlDsa65VerifierCandidate;

impl MlDsa65Verifier for LibcruxMlDsa65VerifierCandidate {
    fn verify(
        &self,
        public_key: &[u8; ML_DSA_65_PUBLIC_KEY_BYTES],
        digest: &[u8; 32],
        signature: &[u8; ML_DSA_65_SIGNATURE_BYTES],
    ) -> bool {
        // FAT1 signs the canonical 32-byte SHA-256 signing digest as pure ML-DSA with the empty
        // context. The protocol's signing_digest already carries domain separation.
        let verifying_key = MLDSA65VerificationKey::new(*public_key);
        let signature = MLDSA65Signature::new(*signature);
        portable::verify(&verifying_key, digest, &[], &signature).is_ok()
    }
}

// Use the same pinned candidate primitive for V4 transaction identity as for FAT1 envelopes.
// This bridges only the verifier interface; it does not activate either flow in the runtime.
impl crate::v4_account_identity_candidate::MlDsa65Verifier for LibcruxMlDsa65VerifierCandidate {
    fn verify(
        &self,
        public_key: &[u8; ML_DSA_65_PUBLIC_KEY_BYTES],
        digest: &[u8; 32],
        signature: &[u8; ML_DSA_65_SIGNATURE_BYTES],
    ) -> bool {
        <Self as MlDsa65Verifier>::verify(self, public_key, digest, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libcrux_ml_dsa::ml_dsa_65::portable;

    #[test]
    fn verifies_real_mldsa65_and_rejects_wrong_digest_and_tampering() {
        // Deterministic values are only for reproducible tests; they are not production keys.
        let key_pair = portable::generate_key_pair([0x21u8; 32]);
        let message = [0x5au8; 32];
        let signature = portable::sign(&key_pair.signing_key, &message, &[], [0x37u8; 32])
            .expect("test ML-DSA-65 signing should succeed");

        let public_key: [u8; ML_DSA_65_PUBLIC_KEY_BYTES] = *key_pair.verification_key.as_ref();
        let signature: [u8; ML_DSA_65_SIGNATURE_BYTES] = *signature.as_ref();
        let verifier = LibcruxMlDsa65VerifierCandidate;

        assert!(verifier.verify(&public_key, &message, &signature));
        let mut wrong_message = message;
        wrong_message[0] ^= 1;
        assert!(!verifier.verify(&public_key, &wrong_message, &signature));

        let mut tampered_signature = signature;
        tampered_signature[0] ^= 1;
        assert!(!verifier.verify(&public_key, &message, &tampered_signature));

        let wrong_key = [0u8; ML_DSA_65_PUBLIC_KEY_BYTES];
        assert!(!verifier.verify(&wrong_key, &message, &signature));
    }

    #[test]
    fn verifies_pinned_wycheproof_mldsa65_vectors() {
        const VECTORS: &str = include_str!(
            "../../../../simulations/crypto_vectors/ml_dsa_65_wycheproof_selected.tsv"
        );

        fn decode_hex<const N: usize>(hex: &str) -> [u8; N] {
            assert_eq!(hex.len(), N * 2, "hex byte length mismatch");
            let mut out = [0u8; N];
            for (index, byte) in out.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
                    .expect("vector hex is valid");
            }
            out
        }

        let verifier = LibcruxMlDsa65VerifierCandidate;
        let mut executed = 0usize;
        let mut expected_valid = 0usize;
        let mut expected_invalid = 0usize;

        for line in VECTORS.lines() {
            if line.starts_with('#') || line.trim().is_empty() {
                continue;
            }
            let fields: Vec<&str> = line.split('\t').collect();
            assert_eq!(fields.len(), 6, "invalid pinned Wycheproof row: {line}");
            let test_id = fields[0];
            let expected = match fields[1] {
                "valid" => {
                    expected_valid += 1;
                    true
                }
                "invalid" => {
                    expected_invalid += 1;
                    false
                }
                other => panic!("unknown result '{other}' in Wycheproof tcId={test_id}"),
            };
            let message: [u8; 32] = decode_hex(fields[2]);
            let signature: [u8; ML_DSA_65_SIGNATURE_BYTES] = decode_hex(fields[3]);
            let public_key: [u8; ML_DSA_65_PUBLIC_KEY_BYTES] = decode_hex(fields[4]);
            let actual = verifier.verify(&public_key, &message, &signature);
            assert_eq!(
                actual, expected,
                "Libcrux verification differs from C2SP/Wycheproof tcId={test_id}: {}",
                fields[5]
            );
            executed += 1;
        }
        assert_eq!(
            executed, 53,
            "expected all selected hash-pinned vector cases"
        );
        assert_eq!(
            expected_valid, 48,
            "pinned source has 48 selected valid cases"
        );
        assert_eq!(
            expected_invalid, 5,
            "pinned source has 5 selected invalid cases"
        );
    }
}
