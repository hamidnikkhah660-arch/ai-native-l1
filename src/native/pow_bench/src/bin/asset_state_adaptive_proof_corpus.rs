use ai_native_l1_pow_bench::asset_state_adaptive_commitment_candidate::AdaptiveAssetStateCommitment;
use sha2::{Digest, Sha256};
use std::{fmt::Write as _, fs, path::PathBuf};

const NETWORK: [u8; 32] = [0xC7; 32];

struct Case {
    label: &'static str,
    bucket: [u8; 2],
    count: usize,
    depth: usize,
    value_len: usize,
    spread_buckets: bool,
}

fn key(bucket: [u8; 2], split_bytes: &[u8], suffix: u64) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[..2].copy_from_slice(&bucket);
    key[24..].copy_from_slice(&suffix.to_be_bytes());
    key[2..2 + split_bytes.len()].copy_from_slice(split_bytes);
    key
}

fn value(case_index: usize, entry_index: usize, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| ((case_index * 31 + entry_index * 7 + i * 13) % 255 + 1) as u8)
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut out, "{byte:02x}").unwrap();
    }
    out
}

fn render_vector(case: &Case, case_index: usize) -> Result<String, Box<dyn std::error::Error>> {
    let mut leaves: Vec<([u8; 32], Vec<u8>)> = Vec::with_capacity(case.count);
    for index in 0..case.count {
        let bucket = if case.spread_buckets {
            [0x20 + (index / 256) as u8, (index % 256) as u8]
        } else {
            case.bucket
        };
        let split = match case.depth {
            0 => Vec::new(),
            1 => vec![(index / 17) as u8],
            2 => vec![(index / 64) as u8, ((index / 32) % 2) as u8],
            3 => vec![
                (index / 128) as u8,
                ((index / 64) % 2) as u8,
                ((index / 32) % 2) as u8,
            ],
            30 => vec![0u8; 29],
            other => return Err(format!("unsupported shape depth {other}").into()),
        };
        let leaf_key = key(bucket, &split, index as u64);
        leaves.push((leaf_key, value(case_index, index, case.value_len)));
    }

    let mut commitment = AdaptiveAssetStateCommitment::new(NETWORK, 100)?;
    commitment.rebuild_from_raw_leaves(&leaves)?;
    let (target_key, target_value) = leaves[case.count / 2].clone();
    let proof = commitment.membership_proof_with_value(target_key, &target_value)?;
    let encoded = AdaptiveAssetStateCommitment::encode_membership_proof(&proof)?;
    let verified = AdaptiveAssetStateCommitment::verify_membership_proof_typed(
        NETWORK,
        commitment.inner_root_typed(),
        &proof,
    )?;
    if !verified {
        return Err(format!("{}: Rust self-verification failed", case.label).into());
    }

    let mut out = String::new();
    writeln!(
        &mut out,
        "CPW_ASSET_ADAPTIVE_PROOF_CORPUS_V2_{}",
        case.label
    )?;
    writeln!(&mut out, "NETWORK={}", hex(&NETWORK))?;
    writeln!(&mut out, "ROOT={}", hex(&commitment.root()))?;
    writeln!(&mut out, "KEY={}", hex(&proof.leaf_key))?;
    writeln!(&mut out, "VALUE={}", hex(&proof.value))?;
    writeln!(&mut out, "CHUNK_COUNT={}", proof.chunk_entries.len())?;
    for (index, (leaf_key, leaf_hash)) in proof.chunk_entries.iter().enumerate() {
        writeln!(&mut out, "CHUNK_{index}_KEY={}", hex(leaf_key))?;
        writeln!(&mut out, "CHUNK_{index}_HASH={}", hex(leaf_hash))?;
    }
    writeln!(
        &mut out,
        "SECONDARY_LEVEL_COUNT={}",
        proof.secondary_levels.len()
    )?;
    for (level, item) in proof.secondary_levels.iter().enumerate() {
        writeln!(
            &mut out,
            "SECONDARY_{level}_SIBLING_COUNT={}",
            item.siblings.len()
        )?;
        for (index, sibling) in item.siblings.iter().enumerate() {
            writeln!(&mut out, "SECONDARY_{level}_{index}={}", hex(sibling))?;
        }
    }
    writeln!(&mut out, "TOP_SIBLING_COUNT={}", proof.top_siblings.len())?;
    for (index, sibling) in proof.top_siblings.iter().enumerate() {
        writeln!(&mut out, "TOP_{index}={}", hex(sibling))?;
    }
    writeln!(&mut out, "RUST_VERIFY={verified}")?;
    writeln!(&mut out, "SERIALIZED_BYTES={}", encoded.len())?;
    writeln!(
        &mut out,
        "SERIALIZED_SHA256={}",
        hex(&Sha256::digest(&encoded))
    )?;
    writeln!(&mut out, "EXPECTED_STATE_LEAVES={}", case.count)?;
    writeln!(&mut out, "EXPECTED_VALUE_LEN={}", case.value_len)?;
    writeln!(&mut out, "EXPECTED_SECONDARY_LEVELS={}", case.depth)?;
    writeln!(&mut out, "EXPECTED_TOP_SIBLINGS=16")?;
    Ok(out)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cases = [
        Case {
            label: "SHALLOW_SINGLE_VALUE_1",
            bucket: [0x10, 0x11],
            count: 1,
            depth: 0,
            value_len: 1,
            spread_buckets: false,
        },
        Case {
            label: "SHALLOW_16_VALUE_32",
            bucket: [0x10, 0x12],
            count: 16,
            depth: 0,
            value_len: 32,
            spread_buckets: false,
        },
        Case {
            label: "FULL_CHUNK_32_VALUE_8",
            bucket: [0x10, 0x13],
            count: 32,
            depth: 0,
            value_len: 8,
            spread_buckets: false,
        },
        Case {
            label: "DEPTH_1_33_VALUE_16",
            bucket: [0x10, 0x14],
            count: 33,
            depth: 1,
            value_len: 16,
            spread_buckets: false,
        },
        Case {
            label: "DEPTH_2_128_VALUE_32",
            bucket: [0x10, 0x15],
            count: 128,
            depth: 2,
            value_len: 32,
            spread_buckets: false,
        },
        Case {
            label: "DEPTH_3_256_VALUE_1",
            bucket: [0x10, 0x16],
            count: 256,
            depth: 3,
            value_len: 1,
            spread_buckets: false,
        },
        Case {
            label: "MAX_DEPTH_64_VALUE_32",
            bucket: [0x10, 0x17],
            count: 64,
            depth: 30,
            value_len: 32,
            spread_buckets: false,
        },
        Case {
            label: "SPREAD_BUCKETS_VALUE_127",
            bucket: [0x20, 0x00],
            count: 64,
            depth: 0,
            value_len: 127,
            spread_buckets: true,
        },
        Case {
            label: "LONG_VALUE_1024",
            bucket: [0x10, 0x18],
            count: 8,
            depth: 0,
            value_len: 1024,
            spread_buckets: false,
        },
    ];

    let args: Vec<String> = std::env::args().collect();
    let out_dir = args
        .iter()
        .position(|arg| arg == "--out-dir")
        .and_then(|index| args.get(index + 1))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("..\\..\\..\\simulations"));

    fs::create_dir_all(&out_dir)?;
    println!("CPW_ASSET_ADAPTIVE_PROOF_CORPUS_GENERATOR_V2");
    for (index, case) in cases.iter().enumerate() {
        let text = render_vector(case, index)?;
        let path = out_dir.join(format!(
            "cpw_asset_adaptive_proof_vector_v2_{}.txt",
            case.label.to_ascii_lowercase()
        ));
        fs::write(&path, text.as_bytes())?;
        println!(
            "CASE={} ROOT_FILE={} BYTES={} VALUE_LEN={} ENTRIES={} SELF_VERIFY=true",
            case.label,
            path.display(),
            text.len(),
            case.value_len,
            case.count
        );
    }
    println!("CORPUS_CASES={} RESULT=PASS", cases.len());
    Ok(())
}
