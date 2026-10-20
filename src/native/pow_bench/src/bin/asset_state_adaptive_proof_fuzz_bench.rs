use ai_native_l1_pow_bench::asset_state_adaptive_commitment_candidate::{
    AdaptiveAssetStateCommitment, MAX_PROOF_VALUE_BYTES,
};
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf, time::Instant};

const NETWORK: [u8; 32] = [0xC7; 32];
const CHUNK_CAP: usize = 32;
const MAX_SUFFIX_DEPTH: usize = 30;
const MUTATIONS_PER_CASE: usize = 256;

#[derive(Clone, Copy)]
struct FuzzCase {
    label: &'static str,
    bucket: [u8; 2],
    depth: usize,
    count: usize,
    value_len: usize,
}

const CASES: [FuzzCase; 6] = [
    FuzzCase {
        label: "SHALLOW",
        bucket: [0x21, 0x01],
        depth: 0,
        count: 16,
        value_len: 32,
    },
    FuzzCase {
        label: "FULL_CHUNK",
        bucket: [0x21, 0x02],
        depth: 0,
        count: 32,
        value_len: 8,
    },
    FuzzCase {
        label: "DEPTH_1",
        bucket: [0x21, 0x03],
        depth: 1,
        count: 33,
        value_len: 16,
    },
    FuzzCase {
        label: "DEPTH_2",
        bucket: [0x21, 0x04],
        depth: 2,
        count: 128,
        value_len: 32,
    },
    FuzzCase {
        label: "DEPTH_3",
        bucket: [0x21, 0x05],
        depth: 3,
        count: 256,
        value_len: 1,
    },
    FuzzCase {
        label: "MAX_DEPTH",
        bucket: [0x21, 0x06],
        depth: MAX_SUFFIX_DEPTH,
        count: 64,
        value_len: 32,
    },
];

fn synthetic_key(bucket: [u8; 2], suffix: u64) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[..2].copy_from_slice(&bucket);
    key[24..].copy_from_slice(&suffix.to_be_bytes());
    key
}

fn shaped_key(bucket: [u8; 2], split_bytes: &[u8], suffix: u64) -> [u8; 32] {
    assert!(split_bytes.len() <= MAX_SUFFIX_DEPTH);
    let mut key = synthetic_key(bucket, suffix);
    key[2..2 + split_bytes.len()].copy_from_slice(split_bytes);
    key
}

fn xorshift32(state: &mut u32) -> u32 {
    *state ^= *state << 13;
    *state ^= *state >> 17;
    *state ^= *state << 5;
    *state
}

fn build_case(
    case: FuzzCase,
) -> Result<(AdaptiveAssetStateCommitment, [u8; 32], Vec<u8>), Box<dyn std::error::Error>> {
    let mut leaves = Vec::with_capacity(case.count);
    for index in 0..case.count {
        let key = match case.depth {
            0 => synthetic_key(case.bucket, index as u64),
            1 => shaped_key(case.bucket, &[(index / 17) as u8], index as u64),
            2 => shaped_key(
                case.bucket,
                &[(index / 64) as u8, ((index / 32) % 2) as u8],
                index as u64,
            ),
            3 => shaped_key(
                case.bucket,
                &[
                    (index / 128) as u8,
                    ((index / 64) % 2) as u8,
                    ((index / 32) % 2) as u8,
                ],
                index as u64,
            ),
            depth => shaped_key(case.bucket, &vec![0u8; depth - 1], index as u64),
        };
        leaves.push((key, vec![0x50 + (index % 11) as u8; case.value_len]));
    }
    let mut commitment = AdaptiveAssetStateCommitment::new(NETWORK, 100)?;
    commitment.rebuild_from_raw_leaves(&leaves)?;
    let (target, value) = leaves[case.count / 2].clone();
    Ok((commitment, target, value))
}

fn mutation_plan(encoded: &[u8], bucket: [u8; 2]) -> Vec<(usize, u8)> {
    let mut rng = 0xA341_316Cu32 ^ ((bucket[0] as u32) << 8) ^ bucket[1] as u32;
    let mut plan = Vec::with_capacity(MUTATIONS_PER_CASE);
    for _ in 0..MUTATIONS_PER_CASE {
        let position = (xorshift32(&mut rng) as usize) % encoded.len();
        let mut mask = (xorshift32(&mut rng) >> 24) as u8;
        if mask == 0 {
            mask = 1;
        }
        plan.push((position, mask));
    }
    plan
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn parse_hex_byte(value: &str) -> Result<u8, Box<dyn std::error::Error>> {
    Ok(u8::from_str_radix(value, 16)?)
}

fn run_corpus(path: Option<PathBuf>, replay: bool) -> Result<(), Box<dyn std::error::Error>> {
    let start = Instant::now();
    let mut generated = String::from("CPW_ASSET_ADAPTIVE_PROOF_MUTATION_CORPUS_V1\n");
    let supplied = if replay {
        let path = path.as_ref().ok_or("replay requires a corpus path")?;
        Some(fs::read_to_string(path)?)
    } else {
        None
    };
    let source = supplied.as_deref();
    if let Some(source) = source {
        if source.lines().next() != Some("CPW_ASSET_ADAPTIVE_PROOF_MUTATION_CORPUS_V1") {
            return Err("bad mutation corpus header".into());
        }
    }

    let mut total_mutations = 0usize;
    let mut decode_rejects = 0usize;
    let mut verify_rejects = 0usize;
    for case in CASES {
        let (commitment, target, value) = build_case(case)?;
        if value.len() > MAX_PROOF_VALUE_BYTES
            || case.count == 0
            || (case.depth != 0 && case.count <= CHUNK_CAP)
        {
            return Err(format!("{}: invalid compiled shape", case.label).into());
        }
        let proof = commitment.membership_proof_with_value(target, &value)?;
        let encoded = AdaptiveAssetStateCommitment::encode_membership_proof(&proof)?;
        let decoded = AdaptiveAssetStateCommitment::decode_membership_proof(&encoded)?;
        if decoded != proof
            || !AdaptiveAssetStateCommitment::verify_membership_proof_typed(
                NETWORK,
                commitment.inner_root_typed(),
                &decoded,
            )?
        {
            return Err(format!("{}: baseline proof failed", case.label).into());
        }

        let digest = hex(&Sha256::digest(&encoded));
        let plan = mutation_plan(&encoded, case.bucket);
        let mut expected_plan = Vec::new();
        if let Some(source) = source {
            let mut seen_case = false;
            for line in source.lines().skip(1) {
                let fields: Vec<&str> = line.split('|').collect();
                if fields.len() >= 2 && fields[1] == case.label {
                    if fields[0] == "CASE" {
                        if fields.len() != 8 {
                            return Err(format!("{}: malformed CASE row", case.label).into());
                        }
                        if fields[2] != hex(&case.bucket)
                            || fields[3].parse::<usize>()? != case.depth
                            || fields[4].parse::<usize>()? != case.count
                            || fields[5].parse::<usize>()? != case.value_len
                            || fields[6].parse::<usize>()? != encoded.len()
                            || fields[7] != digest
                        {
                            return Err(format!(
                                "{}: case metadata or proof digest mismatch",
                                case.label
                            )
                            .into());
                        }
                        if seen_case {
                            return Err(format!("{}: duplicate CASE row", case.label).into());
                        }
                        seen_case = true;
                    } else if fields[0] == "MUT" {
                        if fields.len() != 5 {
                            return Err(format!("{}: malformed MUT row", case.label).into());
                        }
                        expected_plan.push((
                            fields[2].parse::<usize>()?,
                            fields[3].parse::<usize>()?,
                            parse_hex_byte(fields[4])?,
                        ));
                    }
                }
            }
            if !seen_case || expected_plan.len() != MUTATIONS_PER_CASE {
                return Err(format!("{}: missing case or mutation rows", case.label).into());
            }
            expected_plan.sort_by_key(|row| row.0);
            for (expected_index, row) in expected_plan.iter().enumerate() {
                if row.0 != expected_index
                    || row.1 != plan[expected_index].0
                    || row.2 != plan[expected_index].1
                {
                    return Err(format!(
                        "{}: deterministic mutation plan mismatch at {}",
                        case.label, expected_index
                    )
                    .into());
                }
            }
        } else {
            generated.push_str(&format!(
                "CASE|{}|{}|{}|{}|{}|{}|{}\n",
                case.label,
                hex(&case.bucket),
                case.depth,
                case.count,
                case.value_len,
                encoded.len(),
                digest
            ));
            for (index, (offset, mask)) in plan.iter().enumerate() {
                generated.push_str(&format!(
                    "MUT|{}|{}|{}|{:02x}\n",
                    case.label, index, offset, mask
                ));
            }
        }

        let mut case_decode = 0usize;
        let mut case_verify = 0usize;
        for (mutation_index, (offset, mask)) in plan.iter().copied().enumerate() {
            let mut mutated = encoded.clone();
            mutated[offset] ^= mask;
            total_mutations += 1;
            match AdaptiveAssetStateCommitment::decode_membership_proof(&mutated) {
                Err(_) => {
                    decode_rejects += 1;
                    case_decode += 1;
                }
                Ok(mutated_proof) => {
                    match AdaptiveAssetStateCommitment::verify_membership_proof_typed(
                        NETWORK,
                        commitment.inner_root_typed(),
                        &mutated_proof,
                    ) {
                        Ok(false) | Err(_) => {
                            verify_rejects += 1;
                            case_verify += 1;
                        }
                        Ok(true) => {
                            return Err(format!(
                                "{} mutation {} unexpectedly verified",
                                case.label, mutation_index
                            )
                            .into())
                        }
                    }
                }
            }
        }
        println!(
            "CASE={} DEPTH={} COUNT={} VALUE_LEN={} PROOF_BYTES={} MUTATIONS={} DECODE_REJECTS={} VERIFY_REJECTS={} PROOF_SHA256={}",
            case.label, proof.secondary_levels.len(), case.count, value.len(), encoded.len(),
            MUTATIONS_PER_CASE, case_decode, case_verify, digest
        );
    }

    if let Some(path) = path {
        if replay {
            let source = source.unwrap_or_default();
            let actual_mut_rows = source
                .lines()
                .filter(|line| line.starts_with("MUT|"))
                .count();
            if actual_mut_rows != CASES.len() * MUTATIONS_PER_CASE {
                return Err("unexpected mutation row count".into());
            }
        } else {
            fs::write(&path, generated.as_bytes())?;
            println!("CORPUS_WRITTEN={}", path.display());
        }
    }
    let expected_total = CASES.len() * MUTATIONS_PER_CASE;
    if total_mutations != expected_total || total_mutations != decode_rejects + verify_rejects {
        return Err("mutation accounting mismatch".into());
    }
    println!("CPW_ASSET_STATE_ADAPTIVE_PROOF_FUZZ_CORPUS_V1");
    println!("TOTAL_MUTATIONS={} DECODE_REJECTS={} VERIFY_REJECTS={} UNEXPECTED_ACCEPTS=0 ELAPSED_MS={:.3}",
        total_mutations, decode_rejects, verify_rejects, start.elapsed().as_secs_f64() * 1000.0);
    println!("FUZZ_RESULT=PASS");
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let result: Result<(), Box<dyn std::error::Error>> = match args.get(1).map(String::as_str) {
        Some("--write-corpus") => match args.get(2) {
            Some(path) => run_corpus(Some(PathBuf::from(path)), false),
            None => Err("write requires a path".into()),
        },
        Some("--replay-corpus") => match args.get(2) {
            Some(path) => run_corpus(Some(PathBuf::from(path)), true),
            None => Err("replay requires a path".into()),
        },
        _ => run_corpus(None, false),
    };
    if let Err(error) = result {
        eprintln!("FUZZ_CORPUS_FAILED ERROR={error}");
        std::process::exit(1);
    }
}
