use ai_native_l1_pow_bench::bounded_reward_pools_candidate::{
    ClaimSignature, RewardClaim, RewardPool,
};
use ed25519_dalek::{Signer, SigningKey};

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

fn main() {
    // Deterministic test-only keys: never use these seeds for any real funds or deployment.
    let keys = [
        SigningKey::from_bytes(&[11; 32]),
        SigningKey::from_bytes(&[22; 32]),
    ];
    let mut claim = RewardClaim {
        network_id: [0xA1; 32],
        pool: RewardPool::Adoption,
        amount_atoms: 25,
        recipient: [0x77; 32],
        claim_id: [0x01; 32],
        valid_from_epoch: 5,
        expires_at_epoch: 10,
        signatures: Vec::new(),
    };
    let message = claim.signing_bytes();
    claim.signatures = keys
        .iter()
        .map(|key| ClaimSignature {
            signer_public_key: key.verifying_key().to_bytes(),
            signature: key.sign(&message).to_bytes(),
        })
        .collect();

    println!("{{");
    println!("  \"schema\": \"cpw-reward-claim-vector-v1\",");
    println!("  \"key_material\": \"DETERMINISTIC_TEST_ONLY_NOT_FOR_FUNDS\",");
    println!("  \"claim\": {{");
    println!("    \"network_id_hex\": \"{}\",", hex(&claim.network_id));
    println!("    \"pool_id\": {},", claim.pool.id());
    println!("    \"amount_atoms_decimal\": \"{}\",", claim.amount_atoms);
    println!("    \"recipient_hex\": \"{}\",", hex(&claim.recipient));
    println!("    \"claim_id_hex\": \"{}\",", hex(&claim.claim_id));
    println!("    \"valid_from_epoch\": {},", claim.valid_from_epoch);
    println!("    \"expires_at_epoch\": {}", claim.expires_at_epoch);
    println!("  }},");
    println!("  \"signing_bytes_hex\": \"{}\",", hex(&message));
    println!("  \"signatures\": [");
    for (i, item) in claim.signatures.iter().enumerate() {
        println!(
            "    {{\"public_key_hex\": \"{}\", \"signature_hex\": \"{}\"}}{}",
            hex(&item.signer_public_key),
            hex(&item.signature),
            if i + 1 == claim.signatures.len() {
                ""
            } else {
                ","
            }
        );
    }
    println!("  ]");
    println!("}}");
}
