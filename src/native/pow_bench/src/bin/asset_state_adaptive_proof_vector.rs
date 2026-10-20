use ai_native_l1_pow_bench::asset_state_adaptive_commitment_candidate::AdaptiveAssetStateCommitment;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

const NETWORK: [u8; 32] = [0xC7; 32];
const BUCKET: [u8; 2] = [0x5A, 0xA5];

fn synthetic_key(suffix: u64) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[..2].copy_from_slice(&BUCKET);
    key[24..].copy_from_slice(&suffix.to_be_bytes());
    key
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut out, "{byte:02x}").unwrap();
    }
    out
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut commitment = AdaptiveAssetStateCommitment::new(NETWORK, 100)?;
    for suffix in 0u64..64 {
        commitment.set_raw_leaf_value(synthetic_key(suffix), Some(&[0x07; 32]))?;
    }

    let key = synthetic_key(17);
    let value = [0x07; 32];
    let proof = commitment.membership_proof_with_value(key, &value)?;
    let encoded = AdaptiveAssetStateCommitment::encode_membership_proof(&proof)?;
    let actual_size = encoded.len();
    let verified = AdaptiveAssetStateCommitment::verify_membership_proof_typed(
        NETWORK,
        commitment.inner_root_typed(),
        &proof,
    )?;
    let serialized_hash = Sha256::digest(&encoded);

    println!("CPW_ASSET_STATE_ADAPTIVE_PROOF_VECTOR_V1");
    println!("NETWORK={}", hex(&NETWORK));
    println!("ROOT={}", hex(&commitment.root()));
    println!("KEY={}", hex(&proof.leaf_key));
    println!("VALUE={}", hex(&proof.value));
    println!("CHUNK_COUNT={}", proof.chunk_entries.len());
    for (index, (key, hash)) in proof.chunk_entries.iter().enumerate() {
        println!("CHUNK_{index}_KEY={}", hex(key));
        println!("CHUNK_{index}_HASH={}", hex(hash));
    }
    println!("SECONDARY_LEVEL_COUNT={}", proof.secondary_levels.len());
    for (level, item) in proof.secondary_levels.iter().enumerate() {
        println!("SECONDARY_{level}_SIBLING_COUNT={}", item.siblings.len());
        for (index, sibling) in item.siblings.iter().enumerate() {
            println!("SECONDARY_{level}_{index}={}", hex(sibling));
        }
    }
    println!("TOP_SIBLING_COUNT={}", proof.top_siblings.len());
    for (index, sibling) in proof.top_siblings.iter().enumerate() {
        println!("TOP_{index}={}", hex(sibling));
    }
    println!("RUST_VERIFY={verified}");
    println!("SERIALIZED_BYTES={actual_size}");
    println!("SERIALIZED_SHA256={}", hex(&serialized_hash));
    Ok(())
}
