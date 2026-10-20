use ai_native_l1_pow_bench::{
    identity_policy::{KeyAlgorithm, KeyPurpose, KeyRecord, KeyState, SecurityClass},
    signature_policy::{SigPolicy, SignatureEnvelope, SignatureSuite},
    verifier::{signing_preimage, verify, SignatureProvider, VerificationRequest},
};

struct DemoProvider;
impl SignatureProvider for DemoProvider {
    fn verify(
        &self,
        suite: SignatureSuite,
        public_key: &[u8],
        preimage: &[u8],
        signature: &[u8],
    ) -> Result<(), String> {
        if suite != SignatureSuite::Ed25519
            || public_key != [9, 8, 7]
            || preimage != signing_preimage(7, b"hello")
            || signature != [1, 2, 3]
        {
            return Err("provider vector mismatch".into());
        }
        Ok(())
    }
}
fn main() {
    let key = KeyRecord {
        key_id: 42,
        generation: 3,
        algorithm: KeyAlgorithm::Ed25519,
        purpose: KeyPurpose::AccountAuth,
        state: KeyState::Active,
        not_before: 1,
        not_after: 100,
        public_key: vec![9, 8, 7],
    };
    let sig = SignatureEnvelope {
        suite: SignatureSuite::Ed25519,
        key_id: 42,
        generation: 3,
        purpose: KeyPurpose::AccountAuth,
        domain: 7,
        signature: vec![1, 2, 3],
    };
    let policy = SigPolicy {
        min_class: SecurityClass::Classical,
        pq_activation_epoch: None,
        require_hybrid_until: None,
    };
    verify(
        &DemoProvider,
        VerificationRequest {
            key: &key,
            signature: &sig,
            message: b"hello",
            expected_domain: 7,
            epoch: 10,
            policy,
        },
    )
    .unwrap();
    println!("verifier_dispatch=PASS domain=7 key_id=42 generation=3");
}
