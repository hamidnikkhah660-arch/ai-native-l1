#[path = "../identity_policy.rs"]
mod identity_policy;

use identity_policy::{
    decode, encode, CryptoPolicy, KeyAlgorithm, KeyPurpose, KeyRecord, KeyState, SecurityClass,
};

fn sample(algorithm: KeyAlgorithm, generation: u32, state: KeyState) -> KeyRecord {
    KeyRecord {
        key_id: 42,
        generation,
        algorithm,
        purpose: KeyPurpose::AccountAuth,
        state,
        not_before: 10,
        not_after: 100,
        public_key: vec![1, 2, 3, 4],
    }
}

fn main() {
    let x = sample(KeyAlgorithm::MlDsa65, 1, KeyState::Active);
    let wire = encode(&x).unwrap();
    let decoded = decode(&wire).unwrap();
    println!(
        "identity_roundtrip key_id={} generation={} alg={:?} bytes={}",
        decoded.key_id,
        decoded.generation,
        decoded.algorithm,
        wire.len()
    );
    let old = sample(KeyAlgorithm::MlDsa65, 1, KeyState::Active);
    let mut new = sample(KeyAlgorithm::Ed25519, 2, KeyState::Active);
    new.not_before = 20;
    let err = KeyRecord::rotate_from(
        &old,
        &new,
        CryptoPolicy {
            min_class: SecurityClass::Pq,
            pq_lock_epoch: Some(20),
        },
    )
    .unwrap_err();
    println!("downgrade_guard={:?}", err);
}
