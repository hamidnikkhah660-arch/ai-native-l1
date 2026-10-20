use ai_native_l1_pow_bench::{
    asset_state_adaptive_commitment_candidate::{AdaptiveAssetStateCommitment, CHUNK_CAP},
    asset_state_bucketed_commitment_candidate::BucketedAssetStateCommitment,
};
use std::time::Instant;

const NETWORK: [u8; 32] = [0xC7; 32];
const BUCKET: [u8; 2] = [0x5A, 0xA5];
const DEFAULT_ROUNDS: usize = 32;

fn synthetic_key(suffix: u64) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[..2].copy_from_slice(&BUCKET);
    key[24..].copy_from_slice(&suffix.to_be_bytes());
    key
}

fn leaves(size: usize) -> Vec<([u8; 32], Vec<u8>)> {
    (0..size)
        .map(|suffix| (synthetic_key(suffix as u64), vec![0x01; 32]))
        .collect()
}

fn run(size: usize, rounds: usize) -> Result<(), Box<dyn std::error::Error>> {
    let leaves = leaves(size);
    let target = synthetic_key((size / 2) as u64);

    let mut old = BucketedAssetStateCommitment::new(NETWORK, 100)?;
    let old_rebuild_start = Instant::now();
    old.rebuild_from_raw_leaves(&leaves)?;
    let old_rebuild_ms = old_rebuild_start.elapsed().as_secs_f64() * 1000.0;

    let mut adaptive = AdaptiveAssetStateCommitment::new(NETWORK, 100)?;
    let adaptive_rebuild_start = Instant::now();
    adaptive.rebuild_from_raw_leaves(&leaves)?;
    let adaptive_rebuild_ms = adaptive_rebuild_start.elapsed().as_secs_f64() * 1000.0;

    let old_proof_bytes = old.membership_proof_size_upper_bound(target, 32)?;
    let adaptive_proof = adaptive.membership_proof_with_value(target, &[0x01; 32])?;
    let adaptive_encoded_proof =
        AdaptiveAssetStateCommitment::encode_membership_proof(&adaptive_proof)?;
    let adaptive_decoded_proof =
        AdaptiveAssetStateCommitment::decode_membership_proof(&adaptive_encoded_proof)?;
    let adaptive_actual_proof_bytes = adaptive_encoded_proof.len();
    let adaptive_proof_bytes = adaptive.membership_proof_size_upper_bound(target, 32)?;
    let adaptive_proof_verified = AdaptiveAssetStateCommitment::verify_membership_proof_typed(
        NETWORK,
        adaptive.inner_root_typed(),
        &adaptive_proof,
    )?;
    let adaptive_worst =
        AdaptiveAssetStateCommitment::worst_case_membership_proof_size_upper_bound(32)?;

    let mut old_update_us = 0u128;
    let mut adaptive_update_us = 0u128;

    for round in 0..rounds {
        let value = if round % 2 == 0 {
            [0x02; 32]
        } else {
            [0x03; 32]
        };

        let start = Instant::now();
        old.set_raw_leaf_value(target, Some(&value))?;
        let _ = old.root();
        old_update_us = old_update_us.saturating_add(start.elapsed().as_micros());

        let start = Instant::now();
        adaptive.set_raw_leaf_value(target, Some(&value))?;
        let _ = adaptive.root();
        adaptive_update_us = adaptive_update_us.saturating_add(start.elapsed().as_micros());
    }

    if old.largest_bucket_len() != size {
        return Err("old bucketed concentration size changed unexpectedly".into());
    }
    if adaptive.largest_bucket_len() != size {
        return Err("adaptive concentration size changed unexpectedly".into());
    }
    if adaptive.largest_terminal_chunk_len() > CHUNK_CAP {
        return Err("adaptive terminal chunk exceeded cap".into());
    }
    if adaptive_decoded_proof != adaptive_proof {
        return Err("adaptive proof decode/encode round-trip changed proof".into());
    }
    if adaptive_actual_proof_bytes != adaptive_proof_bytes {
        return Err("adaptive actual proof size differs from path accounting".into());
    }
    if !adaptive_proof_verified {
        return Err("adaptive proof verification failed".into());
    }
    if adaptive_actual_proof_bytes > adaptive_worst {
        return Err("adaptive proof exceeded theoretical bound".into());
    }

    let old_update_ms = old_update_us as f64 / 1000.0 / rounds.max(1) as f64;
    let adaptive_update_ms = adaptive_update_us as f64 / 1000.0 / rounds.max(1) as f64;
    let speedup = if adaptive_update_ms > 0.0 {
        old_update_ms / adaptive_update_ms
    } else {
        0.0
    };

    println!(
        "SIZE={} OLD_REBUILD_MS={:.3} ADAPTIVE_REBUILD_MS={:.3} OLD_PROOF_BYTES={} ADAPTIVE_PROOF_BYTES={} ADAPTIVE_ACTUAL_PROOF_BYTES={} ADAPTIVE_PROOF_VERIFIED={} ADAPTIVE_WORST_PROOF_BYTES={} OLD_UPDATE_MS={:.3} ADAPTIVE_UPDATE_MS={:.3} UPDATE_SPEEDUP_X={:.3} OLD_BUCKET={} ADAPTIVE_BUCKET={} ADAPTIVE_CHUNK={} ADAPTIVE_DEPTH={} ROUNDS={}",
        size,
        old_rebuild_ms,
        adaptive_rebuild_ms,
        old_proof_bytes,
        adaptive_proof_bytes,
        adaptive_actual_proof_bytes,
        adaptive_proof_verified,
        adaptive_worst,
        old_update_ms,
        adaptive_update_ms,
        speedup,
        old.largest_bucket_len(),
        adaptive.largest_bucket_len(),
        adaptive.largest_terminal_chunk_len(),
        adaptive.deepest_bucket_path(),
        rounds
    );
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut sizes = vec![32usize, 256, 1024, 4096, 10000];
    let mut rounds = DEFAULT_ROUNDS;

    let mut index = 1usize;
    while index < args.len() {
        match args[index].as_str() {
            "--sizes" => {
                index += 1;
                let Some(raw) = args.get(index) else {
                    eprintln!("--sizes requires comma-separated positive integers");
                    std::process::exit(2);
                };
                match raw
                    .split(',')
                    .map(str::parse::<usize>)
                    .collect::<Result<Vec<_>, _>>()
                {
                    Ok(values) if values.iter().all(|value| *value > 0) => sizes = values,
                    _ => {
                        eprintln!("--sizes must contain only positive integers");
                        std::process::exit(2);
                    }
                }
            }
            "--rounds" => {
                index += 1;
                let Some(raw) = args.get(index) else {
                    eprintln!("--rounds requires a positive integer");
                    std::process::exit(2);
                };
                rounds = match raw.parse::<usize>() {
                    Ok(value) if value > 0 => value,
                    _ => {
                        eprintln!("--rounds requires a positive integer");
                        std::process::exit(2);
                    }
                };
            }
            "--help" | "-h" => {
                println!("asset_state_adaptive_concentration_bench [--sizes N,N,N] [--rounds N]");
                return;
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
        index += 1;
    }

    println!("CPW_ASSET_STATE_ADAPTIVE_CONCENTRATION_BENCH_V1");
    println!(
        "PARAMETERS ROUNDS={} BUCKET=0x5aa5 NOTE=old is fixed 16-bit bucket; adaptive uses bounded terminal chunks",
        rounds
    );

    for size in sizes {
        if let Err(error) = run(size, rounds) {
            eprintln!("BENCHMARK_FAILED SIZE={} ERROR={}", size, error);
            std::process::exit(1);
        }
    }
}
