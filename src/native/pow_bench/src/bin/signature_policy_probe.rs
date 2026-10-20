#[path = "../identity_policy.rs"]
mod identity_policy;
#[path = "../signature_policy.rs"]
mod signature_policy;

use identity_policy::{KeyAlgorithm, KeyPurpose, SecurityClass};
use signature_policy::{encode, SigPolicy, SignatureEnvelope, SignatureSuite};

fn main() {
    let env = SignatureEnvelope {
        suite: SignatureSuite::MlDsa65,
        key_id: 42,
        generation: 3,
        purpose: KeyPurpose::AccountAuth,
        domain: 7,
        signature: vec![1, 2, 3, 4],
    };
    let wire = encode(&env).unwrap();
    println!(
        "signature_vector suite={:?} key_id={} generation={} bytes={}",
        env.suite,
        env.key_id,
        env.generation,
        wire.len()
    );
    let err = env
        .validate(
            KeyAlgorithm::Ed25519,
            KeyPurpose::AccountAuth,
            20,
            SigPolicy {
                min_class: SecurityClass::Pq,
                pq_activation_epoch: Some(20),
                require_hybrid_until: None,
            },
        )
        .unwrap_err();
    println!("algorithm_binding_guard={:?}", err);
}
