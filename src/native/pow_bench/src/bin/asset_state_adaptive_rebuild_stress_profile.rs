use ai_native_l1_pow_bench::asset_state_adaptive_commitment_candidate::AdaptiveAssetStateCommitment;
use sha2::{Digest, Sha256};
use std::error::Error;
use std::time::Instant;

const NETWORK: [u8; 32] = [0xC7; 32];
const HEIGHT: u64 = 100;
const KEY_DOMAIN: &[u8] = b"CPW-ADAPTIVE-REBUILD-STRESS-KEY-V1\0";

fn make_dataset(count: usize) -> Vec<([u8; 32], Vec<u8>)> {
    (0..count)
        .map(|index| {
            let index_bytes = (index as u64).to_be_bytes();
            let mut hasher = Sha256::new();
            hasher.update(KEY_DOMAIN);
            hasher.update(index_bytes);
            let key: [u8; 32] = hasher.finalize().into();

            // Approximate a mixed state-value corpus: balance-like 16-byte values dominate,
            // with shorter metadata and larger registry-like values in the tail.
            let value_len = match index % 100 {
                0..=79 => 16,
                80..=94 => 32,
                95..=98 => 64,
                _ => 128,
            };
            let value = (0..value_len)
                .map(|offset| key[(offset + index) % key.len()] ^ (offset as u8).wrapping_mul(31))
                .collect();
            (key, value)
        })
        .collect()
}

fn median(sorted: &[u128]) -> f64 {
    let mid = sorted.len() / 2;
    if sorted.len() % 2 == 0 {
        (sorted[mid - 1] as f64 + sorted[mid] as f64) / 2.0 / 1_000.0
    } else {
        sorted[mid] as f64 / 1_000.0
    }
}

fn run_size(count: usize, rounds: usize, label: &str) -> Result<(), Box<dyn Error>> {
    let leaves = make_dataset(count);
    let mut commitment = AdaptiveAssetStateCommitment::new(NETWORK, HEIGHT)?;
    commitment.rebuild_from_raw_leaves(&leaves)?;
    let expected_inner = commitment.root();
    let expected_outer = commitment.network_bound_root();
    let bucket_count = commitment.bucket_count();

    let mut samples_ns = Vec::with_capacity(rounds.saturating_sub(1));
    for round in 0..rounds {
        let start = Instant::now();
        commitment.rebuild_from_raw_leaves(&leaves)?;
        let elapsed = start.elapsed().as_nanos();

        if commitment.root() != expected_inner
            || commitment.network_bound_root() != expected_outer
            || commitment.bucket_count() != bucket_count
        {
            return Err(
                format!("root/structure changed for {count} leaves at round {round}").into(),
            );
        }

        if round > 0 {
            samples_ns.push(elapsed);
            println!(
                "SAMPLE|label={label}|leaves={count}|buckets={bucket_count}|sample={round}|rebuild_us={:.3}|root_match=true",
                elapsed as f64 / 1_000.0
            );
        }
    }

    let mut sorted = samples_ns.clone();
    sorted.sort_unstable();
    let mean_us = samples_ns.iter().sum::<u128>() as f64 / samples_ns.len() as f64 / 1_000.0;
    let min_us = sorted[0] as f64 / 1_000.0;
    let max_us = sorted[sorted.len() - 1] as f64 / 1_000.0;
    println!(
        "SUMMARY|label={label}|leaves={count}|buckets={bucket_count}|samples={}|mean_us={mean_us:.3}|median_us={:.3}|min_us={min_us:.3}|max_us={max_us:.3}|inner_root={}|outer_root={}|root_checks=all",
        samples_ns.len(),
        median(&sorted),
        hex(&expected_inner),
        hex(&expected_outer)
    );
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let rounds = args
        .iter()
        .position(|arg| arg == "--rounds")
        .and_then(|index| args.get(index + 1))
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value >= 3)
        .unwrap_or(7);
    let label = args
        .iter()
        .position(|arg| arg == "--label")
        .and_then(|index| args.get(index + 1))
        .map(String::as_str)
        .unwrap_or("baseline");

    println!("CPW_ADAPTIVE_REBUILD_STRESS_PROFILE_V1");
    println!(
        "ENV|label={label}|OS={}|ARCH={}|ROUNDS={rounds}|WARMUP_ROUNDS=1|METHOD=timed_rebuild_only|DATA=sha256-distributed-keys,mixed-16-128-byte-values",
        std::env::consts::OS,
        std::env::consts::ARCH,
    );

    for count in [256usize, 1_024, 4_096, 16_384] {
        if let Err(error) = run_size(count, rounds, label) {
            eprintln!("PROFILE_FAILED|leaves={count}|error={error}");
            std::process::exit(1);
        }
    }
    println!("PROFILE_RESULT=PASS");
}
