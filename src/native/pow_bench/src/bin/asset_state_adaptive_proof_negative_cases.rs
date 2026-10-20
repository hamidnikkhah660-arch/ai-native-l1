use ai_native_l1_pow_bench::asset_state_adaptive_commitment_candidate::{
    AdaptiveAssetStateCommitment, AdaptiveMembershipProof, AdaptiveNetworkBoundRoot,
    MAX_PROOF_VALUE_BYTES,
};
use ai_native_l1_pow_bench::asset_state_candidate::AssetStateCandidate;
use std::collections::BTreeSet;
use std::error::Error;

const NETWORK: [u8; 32] = [0xC7; 32];
const OTHER_NETWORK: [u8; 32] = [0xD8; 32];
const PRIMARY_SIBLINGS: usize = 16;
const CHUNK_ENTRY_BYTES: usize = 64;

fn expect_decode_reject(
    label: &str,
    bytes: &[u8],
    rejected: &mut usize,
) -> Result<(), Box<dyn Error>> {
    if AdaptiveAssetStateCommitment::decode_membership_proof(bytes).is_ok() {
        return Err(format!("decoder unexpectedly accepted {label}").into());
    }
    *rejected += 1;
    println!("REJECTED={label}");
    Ok(())
}

fn expect_encode_reject(
    label: &str,
    proof: &AdaptiveMembershipProof,
    rejected: &mut usize,
) -> Result<(), Box<dyn Error>> {
    if AdaptiveAssetStateCommitment::encode_membership_proof(proof).is_ok() {
        return Err(format!("encoder unexpectedly accepted {label}").into());
    }
    *rejected += 1;
    println!("REJECTED={label}");
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut leaves = Vec::new();
    for index in 1u8..=12 {
        let mut key = [0u8; 32];
        key[..2].copy_from_slice(&[0x21, 0x31]);
        key[2] = 0xA5;
        key[31] = index;
        leaves.push((key, vec![0x60 + (index % 7); 32]));
    }

    let mut commitment = AdaptiveAssetStateCommitment::new(NETWORK, 100)?;
    commitment.rebuild_from_raw_leaves(&leaves)?;
    let (target, value) = leaves[4].clone();
    let proof = commitment.membership_proof_with_value(target, &value)?;
    let encoded = AdaptiveAssetStateCommitment::encode_membership_proof(&proof)?;
    let decoded = AdaptiveAssetStateCommitment::decode_membership_proof(&encoded)?;
    if decoded != proof
        || !AdaptiveAssetStateCommitment::verify_membership_proof(
            NETWORK,
            commitment.root(),
            &decoded,
        )?
    {
        return Err("baseline APF1 round-trip or verification failed".into());
    }
    if proof.chunk_entries.len() < 2 {
        return Err(format!(
            "test fixture needs >=2 chunk entries; got {}",
            proof.chunk_entries.len()
        )
        .into());
    }

    let mut decoder_rejects = 0usize;
    let mut truncation_rejects = 0usize;
    let mut insertion_rejects = 0usize;
    let mut deletion_rejects = 0usize;
    let mut canonical_encoder_rejects = 0usize;

    let mut bad = encoded.clone();
    bad[0] ^= 0x01;
    expect_decode_reject("bad_magic", &bad, &mut decoder_rejects)?;

    let mut bad = encoded.clone();
    bad[5] = 2;
    expect_decode_reject("unsupported_version", &bad, &mut decoder_rejects)?;

    let mut bad = encoded.clone();
    bad[38..42].copy_from_slice(&0u32.to_be_bytes());
    expect_decode_reject("zero_value_length", &bad, &mut decoder_rejects)?;

    let mut bad = encoded.clone();
    bad[38..42].copy_from_slice(&((MAX_PROOF_VALUE_BYTES as u32) + 1).to_be_bytes());
    expect_decode_reject("value_length_over_limit", &bad, &mut decoder_rejects)?;

    let chunk_count_offset = 42 + value.len();
    let mut bad = encoded.clone();
    bad[chunk_count_offset] = 0;
    expect_decode_reject("zero_chunk_count", &bad, &mut decoder_rejects)?;

    let mut bad = encoded.clone();
    bad[chunk_count_offset] = 33;
    expect_decode_reject("chunk_count_over_cap", &bad, &mut decoder_rejects)?;

    let entries_start = chunk_count_offset + 1;
    let level_count_offset = entries_start + proof.chunk_entries.len() * CHUNK_ENTRY_BYTES;
    let mut bad = encoded.clone();
    bad[level_count_offset] = 31;
    expect_decode_reject(
        "secondary_level_count_over_limit",
        &bad,
        &mut decoder_rejects,
    )?;

    let top_count_offset = encoded.len() - PRIMARY_SIBLINGS * 32 - 1;
    let mut bad = encoded.clone();
    bad[top_count_offset] = 15;
    expect_decode_reject("wrong_top_sibling_count", &bad, &mut decoder_rejects)?;

    let mut bad = encoded.clone();
    bad.push(0xA5);
    expect_decode_reject("trailing_byte", &bad, &mut decoder_rejects)?;

    let mut unordered = encoded.clone();
    let first_key = unordered[entries_start..entries_start + 32].to_vec();
    let second_start = entries_start + CHUNK_ENTRY_BYTES;
    let second_key = unordered[second_start..second_start + 32].to_vec();
    unordered[entries_start..entries_start + 32].copy_from_slice(&second_key);
    unordered[second_start..second_start + 32].copy_from_slice(&first_key);
    expect_decode_reject("unordered_chunk_keys", &unordered, &mut decoder_rejects)?;

    let mut duplicate = encoded.clone();
    let first_key = duplicate[entries_start..entries_start + 32].to_vec();
    duplicate[second_start..second_start + 32].copy_from_slice(&first_key);
    expect_decode_reject("duplicate_chunk_key", &duplicate, &mut decoder_rejects)?;

    let mut boundary_lengths = BTreeSet::new();
    for length in [
        0usize,
        1,
        3,
        4,
        5,
        6,
        38,
        42,
        chunk_count_offset,
        chunk_count_offset + 1,
        entries_start,
        entries_start + 32,
        entries_start + CHUNK_ENTRY_BYTES,
        level_count_offset,
        level_count_offset + 1,
        top_count_offset,
        top_count_offset + 1,
        top_count_offset + 32,
        encoded.len() - 1,
    ] {
        if length < encoded.len() {
            boundary_lengths.insert(length);
        }
    }
    for index in 1..proof.chunk_entries.len() {
        let boundary = entries_start + index * CHUNK_ENTRY_BYTES;
        if boundary < encoded.len() {
            boundary_lengths.insert(boundary);
        }
    }
    for length in boundary_lengths.iter().copied() {
        expect_decode_reject(
            &format!("truncate_at_{length}"),
            &encoded[..length],
            &mut decoder_rejects,
        )?;
        truncation_rejects += 1;
    }

    let mut insert_positions = BTreeSet::new();
    for position in [
        0usize,
        4,
        6,
        38,
        42,
        chunk_count_offset,
        entries_start,
        level_count_offset,
        top_count_offset,
        encoded.len(),
    ] {
        insert_positions.insert(position.min(encoded.len()));
    }
    for position in insert_positions {
        let mut malformed = encoded.clone();
        malformed.insert(position, 0xA5);
        expect_decode_reject(
            &format!("insert_byte_at_{position}"),
            &malformed,
            &mut decoder_rejects,
        )?;
        insertion_rejects += 1;
    }

    let mut delete_positions = BTreeSet::new();
    for position in [
        0usize,
        4,
        6,
        38,
        42,
        entries_start,
        level_count_offset,
        top_count_offset,
        encoded.len() - 1,
    ] {
        if position < encoded.len() {
            delete_positions.insert(position);
        }
    }
    for position in delete_positions {
        let mut malformed = encoded.clone();
        malformed.remove(position);
        expect_decode_reject(
            &format!("delete_byte_at_{position}"),
            &malformed,
            &mut decoder_rejects,
        )?;
        deletion_rejects += 1;
    }

    let mut bad_proof = proof.clone();
    bad_proof.chunk_entries.swap(0, 1);
    expect_encode_reject(
        "encoder_unordered_chunk_keys",
        &bad_proof,
        &mut canonical_encoder_rejects,
    )?;

    let mut bad_proof = proof.clone();
    bad_proof.chunk_entries[1].0 = bad_proof.chunk_entries[0].0;
    expect_encode_reject(
        "encoder_duplicate_chunk_key",
        &bad_proof,
        &mut canonical_encoder_rejects,
    )?;

    let mut bad_proof = proof.clone();
    bad_proof.top_siblings.pop();
    expect_encode_reject(
        "encoder_wrong_top_sibling_count",
        &bad_proof,
        &mut canonical_encoder_rejects,
    )?;

    if AdaptiveAssetStateCommitment::verify_membership_proof(NETWORK, [0xEE; 32], &proof)? {
        return Err("membership proof unexpectedly verified against a mismatched root".into());
    }
    println!("SEMANTIC_NEGATIVE=wrong_root_rejected");

    // Contract probe only: arbitrary raw-leaf roots do not include NetworkId by themselves.
    // This is not a claim that production headers/state roots are interchangeable.
    let mut other_commitment = AdaptiveAssetStateCommitment::new(OTHER_NETWORK, 100)?;
    other_commitment.rebuild_from_raw_leaves(&leaves)?;
    let other_network_verifies = AdaptiveAssetStateCommitment::verify_membership_proof(
        OTHER_NETWORK,
        commitment.root(),
        &proof,
    )?;
    let same_roots = other_commitment.root() == commitment.root();
    if same_roots && other_network_verifies {
        println!("NETWORK_CONTEXT_PROBE=REPRODUCED");
        println!(
            "NETWORK_CONTEXT_NOTE=arbitrary_raw_leaf_root_and_verifier_do_not_independently_bind_network_id"
        );
    } else {
        println!("NETWORK_CONTEXT_PROBE=NOT_REPRODUCED");
    }

    // Optional outer-root design: preserve the inner tree root and APF1 bytes,
    // while binding an additional authenticated root to NetworkId.
    let bound_root = commitment.network_bound_root();
    let other_bound_root = other_commitment.network_bound_root();
    if bound_root == other_bound_root {
        return Err("network-bound roots unexpectedly equal across NetworkIds".into());
    }
    if !AdaptiveAssetStateCommitment::verify_membership_proof_network_bound(
        NETWORK, bound_root, &proof,
    )? {
        return Err("proof failed against its correct network-bound root".into());
    }
    if AdaptiveAssetStateCommitment::verify_membership_proof_network_bound(
        OTHER_NETWORK,
        bound_root,
        &proof,
    )? {
        return Err("proof unexpectedly verified under another NetworkId-bound root".into());
    }

    let typed_bound_root = commitment.network_bound_root_typed();
    if !AdaptiveAssetStateCommitment::verify_membership_proof_network_bound_typed(
        typed_bound_root,
        &proof,
    )? {
        return Err("typed network-bound verifier rejected the matching root".into());
    }
    let (_, typed_digest) = typed_bound_root.into_parts();
    let mislabeled_typed_root =
        AdaptiveNetworkBoundRoot::from_untrusted_parts(OTHER_NETWORK, typed_digest)?;
    if AdaptiveAssetStateCommitment::verify_membership_proof_network_bound_typed(
        mislabeled_typed_root,
        &proof,
    )? {
        return Err(
            "typed network-bound verifier accepted an outer root under the wrong NetworkId".into(),
        );
    }
    println!("NETWORK_BOUND_VERIFIER=PASS");
    println!("TYPED_NETWORK_BOUND_VERIFIER=PASS");
    println!("TYPED_NETWORK_BOUND_WRONG_NETWORK=REJECTED");
    println!("NETWORK_BOUND_ROOTS_DIFFER=PASS");
    println!(
        "NETWORK_BOUND_VECTOR={},{},{}",
        hex(&NETWORK),
        hex(&commitment.root()),
        hex(&bound_root),
    );
    println!(
        "NETWORK_BOUND_VECTOR={},{},{}",
        hex(&OTHER_NETWORK),
        hex(&other_commitment.root()),
        hex(&other_bound_root),
    );

    // The higher-level AssetStateCandidate adapter adds a network-derived height key.
    // Check that this is different from the intentionally generic raw-leaf construction above.
    let mut state_a = AssetStateCandidate::genesis(NETWORK)?;
    state_a.advance_height(100)?;
    let mut state_b = AssetStateCandidate::genesis(OTHER_NETWORK)?;
    state_b.advance_height(100)?;
    let mut state_bound_a = AdaptiveAssetStateCommitment::from_state(&state_a)?;
    let state_bound_b = AdaptiveAssetStateCommitment::from_state(&state_b)?;
    if state_bound_a.root() == state_bound_b.root() {
        return Err("from_state roots unexpectedly identical across NetworkIds".into());
    }
    if AdaptiveAssetStateCommitment::verify_membership_proof(
        OTHER_NETWORK,
        state_bound_b.root(),
        &proof,
    )? {
        return Err("raw-leaf proof unexpectedly matched the state-adapter root".into());
    }
    if state_bound_a.rebuild_from_state(&state_b).is_ok() {
        return Err("adaptive state adapter accepted a mismatched NetworkId".into());
    }
    println!("STATE_ADAPTER_NETWORK_CONTEXT=BOUND");
    println!("STATE_ADAPTER_REBUILD_NETWORK_MISMATCH=REJECTED");
    println!("STATE_ADAPTER_RAW_PROOF_MISMATCH=REJECTED");

    println!(
        "STRUCTURAL_NEGATIVE_SUMMARY=PASS DECODER_REJECTS={} TRUNCATION_REJECTS={} INSERTION_REJECTS={} DELETION_REJECTS={} ENCODER_REJECTS={} PROOF_BYTES={} CHUNK_ENTRIES={} SECONDARY_LEVELS={}",
        decoder_rejects, truncation_rejects, insertion_rejects,
        deletion_rejects, canonical_encoder_rejects, encoded.len(),
        proof.chunk_entries.len(), proof.secondary_levels.len(),
    );
    println!("NEGATIVE_CASES_RESULT=PASS");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("NEGATIVE_CASES_FAILED={error}");
        std::process::exit(1);
    }
}
