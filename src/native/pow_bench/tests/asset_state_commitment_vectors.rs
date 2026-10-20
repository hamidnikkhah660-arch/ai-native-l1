use ai_native_l1_pow_bench::asset_state_adaptive_commitment_candidate::{
    AdaptiveAssetStateCommitment, ADAPTIVE_KEY_DOMAIN,
};
use ai_native_l1_pow_bench::asset_state_candidate::AssetStateCandidate;
use ai_native_l1_pow_bench::token_forge::encode_definition;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::PathBuf};

fn parse_values(path: PathBuf, header: &str) -> BTreeMap<String, String> {
    let text = fs::read_to_string(path).expect("read shared candidate vector");
    let mut values = BTreeMap::new();
    let mut seen_header = false;
    for raw in text.lines() {
        let line = raw.trim().trim_start_matches('\u{feff}');
        if line.is_empty() {
            continue;
        }
        if !seen_header {
            assert_eq!(line, header);
            seen_header = true;
            continue;
        }
        if line == "END" {
            break;
        }
        let (key, value) = line.split_once('=').expect("key=value vector line");
        assert!(values.insert(key.to_owned(), value.to_owned()).is_none());
    }
    assert!(seen_header, "vector header missing");
    values
}

fn asset_state_vector() -> BTreeMap<String, String> {
    parse_values(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../simulations/cpw_asset_state_vectors.txt"),
        "CPW_ASSET_STATE_CAND_V1",
    )
}

fn split_vector() -> BTreeMap<String, String> {
    parse_values(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../simulations/cpw_adaptive_split_root_vectors_v1.txt"),
        "CPW_ADAPTIVE_SPLIT_ROOT_V1",
    )
}

fn split_depth2_vector() -> BTreeMap<String, String> {
    parse_values(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../simulations/cpw_adaptive_split_depth2_root_vectors_v1.txt"),
        "CPW_ADAPTIVE_SPLIT_DEPTH2_ROOT_V1",
    )
}

fn split_max_depth_vector() -> BTreeMap<String, String> {
    parse_values(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../simulations/cpw_adaptive_split_max_depth_root_vectors_v1.txt"),
        "CPW_ADAPTIVE_SPLIT_MAX_DEPTH_ROOT_V1",
    )
}

fn boundary_vector() -> BTreeMap<String, String> {
    parse_values(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../simulations/cpw_adaptive_boundary_root_vectors_v1.txt"),
        "CPW_ADAPTIVE_BOUNDARY_ROOT_V1",
    )
}

fn mutation_trace_vector() -> BTreeMap<String, String> {
    parse_values(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../simulations/cpw_adaptive_mutation_trace_vectors_v1.txt"),
        "CPW_ADAPTIVE_MUTATION_TRACE_V1",
    )
}

fn multi_bucket_mutation_trace_vector() -> BTreeMap<String, String> {
    parse_values(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../simulations/cpw_adaptive_multi_bucket_mutation_trace_vectors_v1.txt"),
        "CPW_ADAPTIVE_MULTI_BUCKET_MUTATION_TRACE_V1",
    )
}

fn decode_hex(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0, "hex value has odd length");
    (0..input.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&input[i..i + 2], 16).expect("hex byte"))
        .collect()
}

fn hex(input: &[u8]) -> String {
    input.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn assert_incremental_matches_raw_map(
    commitment: &AdaptiveAssetStateCommitment,
    values: &BTreeMap<[u8; 32], Vec<u8>>,
    network: [u8; 32],
    label: &str,
) {
    let mut entries: Vec<([u8; 32], Vec<u8>)> = values
        .iter()
        .map(|(key, value)| (*key, value.clone()))
        .collect();
    let mut rebuilt = AdaptiveAssetStateCommitment::new(network, 100).unwrap();
    rebuilt.rebuild_from_raw_leaves(&entries).unwrap();
    assert_eq!(
        commitment.root(),
        rebuilt.root(),
        "{label}: incremental/rebuild inner root"
    );
    assert_eq!(
        commitment.network_bound_root(),
        rebuilt.network_bound_root(),
        "{label}: incremental/rebuild outer root"
    );
    assert_eq!(
        commitment.bucket_count(),
        rebuilt.bucket_count(),
        "{label}: bucket count"
    );
    assert_eq!(
        commitment.largest_bucket_len(),
        rebuilt.largest_bucket_len(),
        "{label}: largest bucket"
    );
    assert_eq!(
        commitment.largest_terminal_chunk_len(),
        rebuilt.largest_terminal_chunk_len(),
        "{label}: terminal chunk"
    );
    assert_eq!(
        commitment.deepest_bucket_path(),
        rebuilt.deepest_bucket_path(),
        "{label}: secondary depth"
    );
    let trace = mutation_trace_vector();
    assert_eq!(
        hex(&commitment.root()),
        trace[&format!("INNER_ROOT_{label}")],
        "{label}: shared cross-language mutation inner root"
    );
    assert_eq!(
        hex(&commitment.network_bound_root()),
        trace[&format!("OUTER_ROOT_{label}")],
        "{label}: shared cross-language mutation outer root"
    );

    if matches!(values.len(), 31 | 32 | 33 | 63 | 64 | 65) {
        entries.reverse();
        if let Some((key, value)) = values.iter().next() {
            let proof = commitment.membership_proof_with_value(*key, value).unwrap();
            assert!(
                AdaptiveAssetStateCommitment::verify_membership_proof_typed(
                    network,
                    commitment.inner_root_typed(),
                    &proof,
                )
                .unwrap(),
                "{label}: proof rejected after mutation"
            );
        }

        if !entries.is_empty() {
            let mut reverse_rebuilt = AdaptiveAssetStateCommitment::new(network, 100).unwrap();
            reverse_rebuilt.rebuild_from_raw_leaves(&entries).unwrap();
            assert_eq!(
                rebuilt.root(),
                reverse_rebuilt.root(),
                "{label}: reversed bulk rebuild changed root"
            );
        }
    }
}

fn make_split_leaves(
    bucket: [u8; 2],
    count: usize,
    split_group_size: usize,
    value: &[u8],
) -> Vec<([u8; 32], Vec<u8>)> {
    assert!(count > 0);
    assert!(split_group_size > 0);
    (0..count)
        .map(|index| {
            let mut key = [0u8; 32];
            key[..2].copy_from_slice(&bucket);
            key[2] = (index / split_group_size) as u8;
            key[24..].copy_from_slice(&(index as u64).to_be_bytes());
            (key, value.to_vec())
        })
        .collect()
}

#[test]
fn flat_and_adaptive_roots_match_shared_candidate_state_fixture() {
    let vector = asset_state_vector();
    let network: [u8; 32] = decode_hex(&vector["NETWORK_ID"])
        .try_into()
        .expect("32-byte NetworkId");
    let snapshot = decode_hex(&vector["SNAPSHOT_HEX"]);
    let state = AssetStateCandidate::decode_snapshot(&snapshot, &network)
        .expect("decode shared ASV1 candidate snapshot");

    assert_eq!(state.network_id(), network);
    assert_eq!(state.height(), vector["HEIGHT"].parse::<u64>().unwrap());
    assert_eq!(hex(&state.state_root().unwrap()), vector["ROOT_HEX"]);

    let adaptive = AdaptiveAssetStateCommitment::from_state(&state)
        .expect("build adaptive commitment from the same logical state");
    let inner_root = hex(&adaptive.root());
    let outer_root = hex(&adaptive.network_bound_root());

    assert_eq!(inner_root, vector["ADAPTIVE_INNER_ROOT_HEX"]);
    assert_eq!(outer_root, vector["ADAPTIVE_NETWORK_BOUND_ROOT_HEX"]);
}

#[test]
fn empty_asset_state_roots_match_empty_state_vectors() {
    let vector = asset_state_vector();
    let network: [u8; 32] = decode_hex(&vector["NETWORK_ID"])
        .try_into()
        .expect("32-byte NetworkId");
    let state = AssetStateCandidate::genesis(network).unwrap();

    assert_eq!(state.height(), 0);
    assert!(state.iter_registry().next().is_none());
    assert!(state.iter_balances().next().is_none());
    let flat_root = hex(&state.state_root().unwrap());

    let adaptive = AdaptiveAssetStateCommitment::from_state(&state).unwrap();
    let inner_root = hex(&adaptive.root());
    let outer_root = hex(&adaptive.network_bound_root());
    assert_eq!(flat_root, vector["EMPTY_HEIGHT0_ROOT_HEX"]);
    assert_eq!(inner_root, vector["EMPTY_ADAPTIVE_INNER_ROOT_HEX"]);
    assert_eq!(outer_root, vector["EMPTY_NETWORK_BOUND_ROOT_HEX"]);
}

#[test]
fn wrong_network_and_height_contexts_are_rejected_for_bound_state_proofs() {
    const OTHER_NETWORK: [u8; 32] = [0xC8; 32];
    let vector = asset_state_vector();
    let network: [u8; 32] = decode_hex(&vector["NETWORK_ID"])
        .try_into()
        .expect("32-byte NetworkId");
    let snapshot = decode_hex(&vector["SNAPSHOT_HEX"]);
    assert!(
        AssetStateCandidate::decode_snapshot(&snapshot, &OTHER_NETWORK).is_err(),
        "the ASV1 decoder must reject another expected NetworkId"
    );

    let state = AssetStateCandidate::decode_snapshot(&snapshot, &network).unwrap();
    let adaptive = AdaptiveAssetStateCommitment::from_state(&state).unwrap();
    let (asset_id, asset) = state.iter_registry().next().expect("fixture asset");

    let mut key_hasher = Sha256::new();
    key_hasher.update(ADAPTIVE_KEY_DOMAIN);
    key_hasher.update([0x01]);
    key_hasher.update(asset_id);
    let registry_key: [u8; 32] = key_hasher.finalize().into();

    let definition = encode_definition(&asset.definition).unwrap();
    let mut value = Vec::with_capacity(2 + definition.len() + 17);
    value.extend_from_slice(&(definition.len() as u16).to_be_bytes());
    value.extend_from_slice(&definition);
    value.extend_from_slice(&asset.total_supply.to_be_bytes());
    value.push(u8::from(asset.frozen));

    let proof = adaptive
        .membership_proof_with_value(registry_key, &value)
        .unwrap();
    assert!(AdaptiveAssetStateCommitment::verify_membership_proof_typed(
        network,
        adaptive.inner_root_typed(),
        &proof
    )
    .unwrap());

    let mut later_state = state.clone();
    later_state.advance_height(state.height() + 1).unwrap();
    let later_adaptive = AdaptiveAssetStateCommitment::from_state(&later_state).unwrap();
    assert_ne!(adaptive.root(), later_adaptive.root());
    assert!(
        !AdaptiveAssetStateCommitment::verify_membership_proof_typed(
            network,
            later_adaptive.inner_root_typed(),
            &proof
        )
        .unwrap(),
        "a height-9 proof must not verify against the height-10 root"
    );

    assert!(
        !AdaptiveAssetStateCommitment::verify_membership_proof_network_bound(
            OTHER_NETWORK,
            adaptive.network_bound_root(),
            &proof
        )
        .unwrap(),
        "a root bound to the original network must fail under another NetworkId"
    );
    assert!(
        AdaptiveAssetStateCommitment::verify_membership_proof([0; 32], adaptive.root(), &proof)
            .is_err(),
        "zero NetworkId must be rejected"
    );
}

#[test]
fn split_bucket_roots_match_shared_candidate_split_vector() {
    let vector = split_vector();
    let network: [u8; 32] = decode_hex(&vector["NETWORK_ID"])
        .try_into()
        .expect("32-byte NetworkId");
    let bucket: [u8; 2] = decode_hex(&vector["BUCKET"])
        .try_into()
        .expect("two-byte primary bucket");
    let count: usize = vector["LEAF_COUNT"].parse().unwrap();
    let split_group_size: usize = vector["SPLIT_GROUP_SIZE"].parse().unwrap();
    let value = decode_hex(&vector["VALUE_HEX"]);
    let leaves = make_split_leaves(bucket, count, split_group_size, &value);

    let mut commitment =
        AdaptiveAssetStateCommitment::new(network, vector["HEIGHT_METADATA"].parse().unwrap())
            .unwrap();
    commitment.rebuild_from_raw_leaves(&leaves).unwrap();

    assert_eq!(commitment.bucket_count(), 1);
    assert_eq!(commitment.largest_bucket_len(), count);
    assert_eq!(commitment.largest_terminal_chunk_len(), 32);
    assert_eq!(commitment.deepest_bucket_path(), 1);

    let target_index: usize = vector["TARGET_INDEX"].parse().unwrap();
    let (target_key, target_value) = &leaves[target_index];
    let proof = commitment
        .membership_proof_with_value(*target_key, target_value)
        .unwrap();
    assert_eq!(proof.secondary_levels.len(), 1);
    assert!(AdaptiveAssetStateCommitment::verify_membership_proof_typed(
        network,
        commitment.inner_root_typed(),
        &proof
    )
    .unwrap());

    let inner_root = hex(&commitment.root());
    let outer_root = hex(&commitment.network_bound_root());
    assert_eq!(inner_root, vector["INNER_ROOT_HEX"]);
    assert_eq!(outer_root, vector["NETWORK_BOUND_ROOT_HEX"]);
}

#[test]
fn secondary_depth_vectors_match_rust_builder_and_malformed_proofs_fail_closed() {
    let cases = [
        (split_depth2_vector(), "depth2", 2usize),
        (split_max_depth_vector(), "max_depth", 30usize),
    ];

    for (vector, label, expected_depth) in cases {
        let network: [u8; 32] = decode_hex(&vector["NETWORK_ID"])
            .try_into()
            .expect("32-byte NetworkId");
        let bucket: [u8; 2] = decode_hex(&vector["BUCKET"])
            .try_into()
            .expect("two-byte bucket");
        let count: usize = vector["LEAF_COUNT"].parse().unwrap();
        let target_index: usize = vector["TARGET_INDEX"].parse().unwrap();
        let value = decode_hex(&vector["VALUE_HEX"]);
        assert_eq!(
            vector["EXPECTED_SECONDARY_DEPTH"].parse::<usize>().unwrap(),
            expected_depth
        );

        let mut leaves = Vec::with_capacity(count);
        for index in 0..count {
            let mut key = [0u8; 32];
            key[..2].copy_from_slice(&bucket);
            if expected_depth == 2 {
                key[2] = (index / 64) as u8;
                key[3] = ((index / 32) % 2) as u8;
            } else {
                // Keep the first 29 suffix bytes equal; the final byte distinguishes
                // 33 leaves and forces the maximum 30-level secondary path.
                key[2..31].fill(0);
            }
            key[24..].copy_from_slice(&(index as u64).to_be_bytes());
            leaves.push((key, value.clone()));
        }

        let mut commitment =
            AdaptiveAssetStateCommitment::new(network, vector["HEIGHT_METADATA"].parse().unwrap())
                .unwrap();
        commitment.rebuild_from_raw_leaves(&leaves).unwrap();
        assert_eq!(commitment.bucket_count(), 1, "{label}");
        assert_eq!(commitment.largest_bucket_len(), count, "{label}");
        assert_eq!(commitment.deepest_bucket_path(), expected_depth, "{label}");
        if expected_depth == 2 {
            assert_eq!(commitment.largest_terminal_chunk_len(), 32, "{label}");
        } else {
            assert_eq!(commitment.largest_terminal_chunk_len(), 1, "{label}");
        }

        let (target_key, target_value) = &leaves[target_index];
        let proof = commitment
            .membership_proof_with_value(*target_key, target_value)
            .unwrap();
        assert_eq!(proof.secondary_levels.len(), expected_depth, "{label}");
        let encoded = AdaptiveAssetStateCommitment::encode_membership_proof(&proof).unwrap();
        assert_eq!(
            AdaptiveAssetStateCommitment::decode_membership_proof(&encoded).unwrap(),
            proof,
            "{label}: APF1 round-trip"
        );
        assert!(
            AdaptiveAssetStateCommitment::verify_membership_proof_typed(
                network,
                commitment.inner_root_typed(),
                &proof,
            )
            .unwrap(),
            "{label}: valid proof rejected"
        );

        let inner_root = hex(&commitment.root());
        let outer_root = hex(&commitment.network_bound_root());
        assert_eq!(
            inner_root, vector["INNER_ROOT_HEX"],
            "{label}: inner root vector"
        );
        assert_eq!(
            outer_root, vector["NETWORK_BOUND_ROOT_HEX"],
            "{label}: network-bound outer root vector"
        );

        let mut wrong_value = proof.clone();
        wrong_value.value[0] ^= 0x01;
        assert!(
            !AdaptiveAssetStateCommitment::verify_membership_proof_typed(
                network,
                commitment.inner_root_typed(),
                &wrong_value,
            )
            .unwrap(),
            "{label}: proof with a changed value must not verify"
        );

        let mut malformed_level = proof.clone();
        malformed_level.secondary_levels[0].siblings.pop();
        assert!(
            AdaptiveAssetStateCommitment::verify_membership_proof_typed(
                network,
                commitment.inner_root_typed(),
                &malformed_level,
            )
            .is_err(),
            "{label}: malformed sibling width must be rejected"
        );
    }
}

#[test]
fn boundary_bucket_sizes_match_shared_roots_and_verify_membership() {
    let vector = boundary_vector();
    let network: [u8; 32] = decode_hex(&vector["NETWORK_ID"])
        .try_into()
        .expect("32-byte NetworkId");
    let bucket: [u8; 2] = decode_hex(&vector["BUCKET"])
        .try_into()
        .expect("two-byte primary bucket");
    let group_size: usize = vector["GROUP_SIZE"].parse().unwrap();
    let height: u64 = vector["HEIGHT_METADATA"].parse().unwrap();
    let value = decode_hex(&vector["VALUE_HEX"]);
    let counts: Vec<usize> = vector["CASE_COUNTS"]
        .split(',')
        .map(|count| count.parse().unwrap())
        .collect();

    assert_eq!(counts, vec![31, 32, 33, 63, 64, 65, 95, 96, 97]);
    for count in counts {
        let leaves = make_split_leaves(bucket, count, group_size, &value);
        let mut commitment = AdaptiveAssetStateCommitment::new(network, height).unwrap();
        commitment.rebuild_from_raw_leaves(&leaves).unwrap();

        let expected_depth = usize::from(count > 32);
        let expected_chunk = count.min(32);
        assert_eq!(commitment.bucket_count(), 1, "count={count}");
        assert_eq!(commitment.largest_bucket_len(), count, "count={count}");
        assert_eq!(
            commitment.largest_terminal_chunk_len(),
            expected_chunk,
            "count={count}"
        );
        assert_eq!(
            commitment.deepest_bucket_path(),
            expected_depth,
            "count={count}"
        );

        let target = count / 2;
        let (key, target_value) = &leaves[target];
        let proof = commitment
            .membership_proof_with_value(*key, target_value)
            .unwrap();
        assert_eq!(
            proof.secondary_levels.len(),
            expected_depth,
            "count={count}"
        );
        assert!(
            AdaptiveAssetStateCommitment::verify_membership_proof_typed(
                network,
                commitment.inner_root_typed(),
                &proof,
            )
            .unwrap(),
            "valid boundary proof rejected for count={count}"
        );

        let inner = hex(&commitment.root());
        let outer = hex(&commitment.network_bound_root());
        println!("boundary_inner_{count}={inner}");
        println!("boundary_outer_{count}={outer}");
        if vector[&format!("INNER_ROOT_{count}")] != "TO_BE_FILLED" {
            assert_eq!(
                inner,
                vector[&format!("INNER_ROOT_{count}")],
                "count={count}"
            );
            assert_eq!(
                outer,
                vector[&format!("OUTER_ROOT_{count}")],
                "count={count}"
            );
        }
    }
}

#[test]
fn apf1_serialized_boundary_mutations_fail_closed() {
    let network = [0xC7; 32];
    let bucket = [0x5A, 0xA9];
    let leaves = make_split_leaves(bucket, 64, 32, &[0x07; 32]);
    let mut commitment = AdaptiveAssetStateCommitment::new(network, 100).unwrap();
    commitment.rebuild_from_raw_leaves(&leaves).unwrap();
    let (key, value) = &leaves[37];
    let proof = commitment.membership_proof_with_value(*key, value).unwrap();
    let encoded = AdaptiveAssetStateCommitment::encode_membership_proof(&proof).unwrap();
    let chunk_count_offset = 6 + 32 + 4 + proof.value.len();
    let entries_start = chunk_count_offset + 1;
    let level_count_offset = entries_start + proof.chunk_entries.len() * 64;
    let top_count_offset = encoded.len() - 16 * 32 - 1;

    let mut truncated = encoded.clone();
    truncated.pop();
    assert!(AdaptiveAssetStateCommitment::decode_membership_proof(&truncated).is_err());

    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(AdaptiveAssetStateCommitment::decode_membership_proof(&trailing).is_err());

    let mut bad_version = encoded.clone();
    bad_version[5] = 2;
    assert!(AdaptiveAssetStateCommitment::decode_membership_proof(&bad_version).is_err());

    let mut oversize_value = encoded.clone();
    oversize_value[38..42].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(AdaptiveAssetStateCommitment::decode_membership_proof(&oversize_value).is_err());

    let mut zero_chunk_count = encoded.clone();
    zero_chunk_count[chunk_count_offset] = 0;
    assert!(AdaptiveAssetStateCommitment::decode_membership_proof(&zero_chunk_count).is_err());

    let mut unordered_chunk = encoded.clone();
    let first = unordered_chunk[entries_start..entries_start + 64].to_vec();
    let second = unordered_chunk[entries_start + 64..entries_start + 128].to_vec();
    unordered_chunk[entries_start..entries_start + 64].copy_from_slice(&second);
    unordered_chunk[entries_start + 64..entries_start + 128].copy_from_slice(&first);
    assert!(
        AdaptiveAssetStateCommitment::decode_membership_proof(&unordered_chunk).is_err(),
        "non-canonical chunk-entry ordering must fail closed"
    );

    let mut excessive_secondary_count = encoded.clone();
    excessive_secondary_count[level_count_offset] = 31;
    assert!(
        AdaptiveAssetStateCommitment::decode_membership_proof(&excessive_secondary_count).is_err()
    );

    let mut bad_top_count = encoded.clone();
    bad_top_count[top_count_offset] = 15;
    assert!(AdaptiveAssetStateCommitment::decode_membership_proof(&bad_top_count).is_err());
}

#[test]
fn incremental_insert_update_delete_matches_rebuild_across_split_transitions() {
    let vector = boundary_vector();
    let trace = mutation_trace_vector();
    assert_eq!(trace["NETWORK_ID"], vector["NETWORK_ID"]);
    assert_eq!(trace["BUCKET"], vector["BUCKET"]);
    assert_eq!(trace["GROUP_SIZE"], vector["GROUP_SIZE"]);
    assert_eq!(trace["VALUE_HEX"], vector["VALUE_HEX"]);
    assert_eq!(trace["HEIGHT_METADATA"], vector["HEIGHT_METADATA"]);
    assert_eq!(trace["INITIAL_COUNT"], "31");
    assert_eq!(trace["UPDATED_INDEX"], "17");
    assert_eq!(trace["UPDATED_VALUE_HEX"], hex(&[0x99; 32]));
    assert_eq!(
        trace["STAGES"],
        "initial-31,insert-count-32,insert-count-33,update-at-33,insert-count-63,insert-count-64,insert-count-65,delete-to-count-64,delete-to-count-63,delete-to-count-33,delete-to-count-32,delete-to-count-31,reinsert-count-32,reinsert-count-33"
    );

    let network: [u8; 32] = decode_hex(&vector["NETWORK_ID"])
        .try_into()
        .expect("32-byte NetworkId");
    let bucket: [u8; 2] = decode_hex(&vector["BUCKET"])
        .try_into()
        .expect("two-byte primary bucket");
    let initial_value = decode_hex(&vector["VALUE_HEX"]);
    let changed_value = vec![0x99; 32];
    let all_leaves = make_split_leaves(bucket, 65, 32, &initial_value);

    // Start from a canonical bulk build at 31 leaves, then cross the 32/33 split boundary incrementally.
    let mut values: BTreeMap<[u8; 32], Vec<u8>> = all_leaves[..31]
        .iter()
        .map(|(key, value)| (*key, value.clone()))
        .collect();
    let mut commitment = AdaptiveAssetStateCommitment::new(network, 100).unwrap();
    commitment
        .rebuild_from_raw_leaves(
            &values
                .iter()
                .map(|(k, v)| (*k, v.clone()))
                .collect::<Vec<_>>(),
        )
        .unwrap();
    assert_incremental_matches_raw_map(&commitment, &values, network, "initial-31");

    for index in [31usize, 32usize] {
        let (key, value) = &all_leaves[index];
        commitment.set_raw_leaf_value(*key, Some(value)).unwrap();
        values.insert(*key, value.clone());
        assert_incremental_matches_raw_map(
            &commitment,
            &values,
            network,
            &format!("insert-count-{}", values.len()),
        );
    }
    assert_eq!(commitment.deepest_bucket_path(), 1, "33 leaves must split");

    // Capture a proof immediately before changing the target value.
    let update_key = all_leaves[17].0;
    let stale_proof = commitment
        .membership_proof_with_value(update_key, &initial_value)
        .unwrap();

    // Updating an existing value changes both roots and invalidates the old proof.
    commitment
        .set_raw_leaf_value(update_key, Some(&changed_value))
        .unwrap();
    values.insert(update_key, changed_value.clone());
    assert_incremental_matches_raw_map(&commitment, &values, network, "update-at-33");
    assert!(
        !AdaptiveAssetStateCommitment::verify_membership_proof_typed(
            network,
            commitment.inner_root_typed(),
            &stale_proof,
        )
        .unwrap(),
        "proof for the pre-update value must fail against the changed root"
    );

    // Grow the split bucket through the 63/64/65 boundaries using incremental inserts.
    for index in 33..63 {
        let (key, value) = &all_leaves[index];
        commitment.set_raw_leaf_value(*key, Some(value)).unwrap();
        values.insert(*key, value.clone());
    }
    assert_eq!(values.len(), 63);
    assert_incremental_matches_raw_map(&commitment, &values, network, "insert-count-63");

    for index in [63usize, 64usize] {
        let (key, value) = &all_leaves[index];
        commitment.set_raw_leaf_value(*key, Some(value)).unwrap();
        values.insert(*key, value.clone());
        assert_incremental_matches_raw_map(
            &commitment,
            &values,
            network,
            &format!("insert-count-{}", values.len()),
        );
    }
    assert_eq!(commitment.largest_bucket_len(), 65);
    assert_eq!(commitment.deepest_bucket_path(), 1);

    // Remove from the final chunk, then remove a whole secondary child to return to an unsplit bucket.
    for index in [64usize, 63usize] {
        let key = all_leaves[index].0;
        commitment.set_raw_leaf_value(key, None).unwrap();
        values.remove(&key).unwrap();
        assert_incremental_matches_raw_map(
            &commitment,
            &values,
            network,
            &format!("delete-to-count-{}", values.len()),
        );
    }
    for index in (33usize..=62usize).rev() {
        let key = all_leaves[index].0;
        commitment.set_raw_leaf_value(key, None).unwrap();
        values.remove(&key).unwrap();
    }
    assert_eq!(values.len(), 33);
    assert_incremental_matches_raw_map(&commitment, &values, network, "delete-to-count-33");

    let split_only_key = all_leaves[32].0;
    commitment.set_raw_leaf_value(split_only_key, None).unwrap();
    values.remove(&split_only_key).unwrap();
    assert_eq!(values.len(), 32);
    assert_eq!(
        commitment.deepest_bucket_path(),
        0,
        "32 leaves should become unsplit"
    );
    assert_incremental_matches_raw_map(&commitment, &values, network, "delete-to-count-32");
    assert!(
        commitment
            .membership_proof_with_value(split_only_key, &initial_value)
            .is_err(),
        "deleted leaf must no longer produce a membership proof"
    );

    let boundary_key = all_leaves[31].0;
    commitment.set_raw_leaf_value(boundary_key, None).unwrap();
    values.remove(&boundary_key).unwrap();
    assert_eq!(values.len(), 31);
    assert_eq!(commitment.deepest_bucket_path(), 0);
    assert_incremental_matches_raw_map(&commitment, &values, network, "delete-to-count-31");

    // Reinsert across the same boundary and prove rebuilding is deterministic irrespective of input order.
    for index in [31usize, 32usize] {
        let (key, value) = &all_leaves[index];
        commitment.set_raw_leaf_value(*key, Some(value)).unwrap();
        values.insert(*key, value.clone());
        assert_incremental_matches_raw_map(
            &commitment,
            &values,
            network,
            &format!("reinsert-count-{}", values.len()),
        );
    }
    assert_eq!(commitment.deepest_bucket_path(), 1);
}

#[test]
fn incremental_mutations_across_multiple_primary_buckets_match_rebuild() {
    let vector = boundary_vector();
    let trace = multi_bucket_mutation_trace_vector();
    assert_eq!(trace["NETWORK_ID"], vector["NETWORK_ID"]);
    assert_eq!(trace["VALUE_HEX"], vector["VALUE_HEX"]);
    assert_eq!(trace["HEIGHT_METADATA"], "100");
    assert_eq!(trace["BUCKET_A"], "5aa8");
    assert_eq!(trace["INITIAL_A_COUNT"], "33");
    assert_eq!(trace["MAX_A_COUNT"], "34");
    assert_eq!(trace["BUCKET_B"], "5aa9");
    assert_eq!(trace["INITIAL_B_COUNT"], "32");
    assert_eq!(trace["MAX_B_COUNT"], "33");
    assert_eq!(trace["BUCKET_C"], "1001");
    assert_eq!(trace["INITIAL_C_COUNT"], "5");
    assert_eq!(trace["BUCKET_D"], "fffe");
    assert_eq!(trace["INITIAL_D_COUNT"], "2");
    assert_eq!(trace["UPDATED_VALUE_HEX"], hex(&[0x99; 32]));
    assert_eq!(
        trace["STAGES"],
        "initial_a33_b32_c5_d2,insert_b_index32,insert_a_index33,update_c_index2,delete_a_index33,delete_a_index32,delete_b_index32,reinsert_b_index32,reinsert_a_index32,reinsert_a_index33,revert_update_c_index2,delete_a_index33_again,final_restored_initial"
    );

    let network: [u8; 32] = decode_hex(&vector["NETWORK_ID"])
        .try_into()
        .expect("32-byte NetworkId");
    let base_value = decode_hex(&vector["VALUE_HEX"]);
    let changed_value = vec![0x99; 32];

    let bucket_a = make_split_leaves([0x5a, 0xa8], 34, 32, &base_value);
    let bucket_b = make_split_leaves([0x5a, 0xa9], 33, 32, &base_value);
    let bucket_c = make_split_leaves([0x10, 0x01], 5, 32, &base_value);
    let bucket_d = make_split_leaves([0xff, 0xfe], 2, 32, &base_value);

    let mut values: BTreeMap<[u8; 32], Vec<u8>> = bucket_a[..33]
        .iter()
        .chain(bucket_b[..32].iter())
        .chain(bucket_c.iter())
        .chain(bucket_d.iter())
        .map(|(key, value)| (*key, value.clone()))
        .collect();
    assert_eq!(values.len(), 72);

    let mut commitment = AdaptiveAssetStateCommitment::new(network, 100).unwrap();
    commitment
        .rebuild_from_raw_leaves(
            &values
                .iter()
                .map(|(key, value)| (*key, value.clone()))
                .collect::<Vec<_>>(),
        )
        .unwrap();
    assert_eq!(commitment.bucket_count(), 4);
    assert_eq!(commitment.largest_bucket_len(), 33);
    assert_eq!(commitment.largest_terminal_chunk_len(), 32);
    assert_eq!(commitment.deepest_bucket_path(), 1);
    assert_multi_bucket_roots_match_rebuild(&commitment, &values, network, "initial_a33_b32_c5_d2");

    // Split a second primary bucket while the first is already split.
    let b32 = bucket_b[32].0;
    commitment
        .set_raw_leaf_value(b32, Some(&base_value))
        .unwrap();
    values.insert(b32, base_value.clone());
    assert_multi_bucket_roots_match_rebuild(&commitment, &values, network, "insert_b_index32");

    // Grow the first split bucket from 33 to 34 leaves (32 + 2 uneven child distribution).
    let a33 = bucket_a[33].0;
    commitment
        .set_raw_leaf_value(a33, Some(&base_value))
        .unwrap();
    values.insert(a33, base_value.clone());
    assert_multi_bucket_roots_match_rebuild(&commitment, &values, network, "insert_a_index33");

    // Update a leaf in a separate shallow bucket without changing bucket counts.
    let c2 = bucket_c[2].0;
    commitment
        .set_raw_leaf_value(c2, Some(&changed_value))
        .unwrap();
    values.insert(c2, changed_value.clone());
    assert_multi_bucket_roots_match_rebuild(&commitment, &values, network, "update_c_index2");

    // Shrink bucket A through split collapse, then bucket B from 33 to 32.
    for (key, label) in [
        (a33, "delete_a_index33"),
        (bucket_a[32].0, "delete_a_index32"),
        (b32, "delete_b_index32"),
    ] {
        commitment.set_raw_leaf_value(key, None).unwrap();
        values.remove(&key).unwrap();
        assert_multi_bucket_roots_match_rebuild(&commitment, &values, network, label);
    }

    // Replay the same mutations in reverse and check that roots are reversible.
    commitment
        .set_raw_leaf_value(b32, Some(&base_value))
        .unwrap();
    values.insert(b32, base_value.clone());
    assert_multi_bucket_roots_match_rebuild(&commitment, &values, network, "reinsert_b_index32");

    commitment
        .set_raw_leaf_value(bucket_a[32].0, Some(&base_value))
        .unwrap();
    values.insert(bucket_a[32].0, base_value.clone());
    assert_multi_bucket_roots_match_rebuild(&commitment, &values, network, "reinsert_a_index32");

    commitment
        .set_raw_leaf_value(a33, Some(&base_value))
        .unwrap();
    values.insert(a33, base_value.clone());
    assert_multi_bucket_roots_match_rebuild(&commitment, &values, network, "reinsert_a_index33");

    commitment
        .set_raw_leaf_value(c2, Some(&base_value))
        .unwrap();
    values.insert(c2, base_value);
    assert_multi_bucket_roots_match_rebuild(
        &commitment,
        &values,
        network,
        "revert_update_c_index2",
    );

    commitment.set_raw_leaf_value(a33, None).unwrap();
    values.remove(&a33).unwrap();
    assert_multi_bucket_roots_match_rebuild(
        &commitment,
        &values,
        network,
        "delete_a_index33_again",
    );

    commitment.set_raw_leaf_value(b32, None).unwrap();
    values.remove(&b32).unwrap();
    assert_multi_bucket_roots_match_rebuild(
        &commitment,
        &values,
        network,
        "final_restored_initial",
    );
    assert_eq!(values.len(), 72);
    assert_eq!(commitment.bucket_count(), 4);
    assert_eq!(commitment.largest_bucket_len(), 33);
    assert_eq!(commitment.deepest_bucket_path(), 1);
}

fn assert_multi_bucket_roots_match_rebuild(
    commitment: &AdaptiveAssetStateCommitment,
    values: &BTreeMap<[u8; 32], Vec<u8>>,
    network: [u8; 32],
    label: &str,
) {
    let leaves: Vec<([u8; 32], Vec<u8>)> = values
        .iter()
        .map(|(key, value)| (*key, value.clone()))
        .collect();
    let mut rebuilt = AdaptiveAssetStateCommitment::new(network, 100).unwrap();
    rebuilt.rebuild_from_raw_leaves(&leaves).unwrap();

    assert_eq!(
        commitment.root(),
        rebuilt.root(),
        "{label}: inner root vs rebuild"
    );
    assert_eq!(
        commitment.network_bound_root(),
        rebuilt.network_bound_root(),
        "{label}: outer root vs rebuild"
    );
    assert_eq!(
        commitment.bucket_count(),
        rebuilt.bucket_count(),
        "{label}: bucket count"
    );
    assert_eq!(
        commitment.largest_bucket_len(),
        rebuilt.largest_bucket_len(),
        "{label}: largest bucket"
    );
    assert_eq!(
        commitment.largest_terminal_chunk_len(),
        rebuilt.largest_terminal_chunk_len(),
        "{label}: terminal chunk"
    );
    assert_eq!(
        commitment.deepest_bucket_path(),
        rebuilt.deepest_bucket_path(),
        "{label}: secondary depth"
    );
    let trace = multi_bucket_mutation_trace_vector();
    assert_eq!(
        hex(&commitment.root()),
        trace[&format!("INNER_ROOT_{label}")],
        "{label}: shared multi-bucket inner root"
    );
    assert_eq!(
        hex(&commitment.network_bound_root()),
        trace[&format!("OUTER_ROOT_{label}")],
        "{label}: shared multi-bucket outer root"
    );
}
