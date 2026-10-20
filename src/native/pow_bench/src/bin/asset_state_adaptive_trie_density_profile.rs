use ai_native_l1_pow_bench::asset_state_adaptive_commitment_candidate::AdaptiveAssetStateCommitment;
use sha2::{Digest, Sha256};
use std::time::Instant;

const NETWORK: [u8; 32] = [0xC7; 32];
const HEIGHT: u64 = 100;
const KEY_DOMAIN: &[u8] = b"CPW-ADAPTIVE-TRIE-DENSITY-V1\0";
const SIZES: [usize; 8] = [32, 33, 64, 128, 256, 512, 4_096, 16_384];

#[derive(Clone, Copy)]
enum Distribution {
    Spread,
    CommonPrefix,
}

impl Distribution {
    fn label(self) -> &'static str {
        match self {
            Self::Spread => "spread_suffix",
            Self::CommonPrefix => "common_prefix_9",
        }
    }
}

fn make_key(index: usize, distribution: Distribution) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[..2].copy_from_slice(&[0x5A, 0xA8]);

    match distribution {
        Distribution::Spread => {
            let mut hasher = Sha256::new();
            hasher.update(KEY_DOMAIN);
            hasher.update((index as u64).to_be_bytes());
            let digest: [u8; 32] = hasher.finalize().into();
            key[2..].copy_from_slice(&digest[2..]);
        }
        Distribution::CommonPrefix => {
            // All keys share one primary bucket and nine suffix bytes. Distinct
            // indices start at key[11], forcing a deeper secondary trie before split.
            key[2..11].fill(0x44);
            key[11] = (index % 256) as u8;
            key[12] = (index / 256) as u8;
            key[13..21].copy_from_slice(&(index as u64).to_be_bytes());
        }
    }
    key
}

fn make_dataset(count: usize, distribution: Distribution) -> Vec<([u8; 32], Vec<u8>)> {
    (0..count)
        .map(|index| {
            let key = make_key(index, distribution);
            let value_len = match index % 100 {
                0..=69 => 16,
                70..=89 => 32,
                90..=97 => 64,
                _ => 128,
            };
            let value = (0..value_len)
                .map(|offset| key[(offset + index) % key.len()] ^ (offset as u8).wrapping_mul(17))
                .collect();
            (key, value)
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn median(sorted: &[u128]) -> f64 {
    let mid = sorted.len() / 2;
    if sorted.len() % 2 == 0 {
        (sorted[mid - 1] as f64 + sorted[mid] as f64) / 2.0 / 1_000.0
    } else {
        sorted[mid] as f64 / 1_000.0
    }
}

fn run_fixture(
    count: usize,
    distribution: Distribution,
    rounds: usize,
    run_label: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let leaves = make_dataset(count, distribution);
    let mut commitment = AdaptiveAssetStateCommitment::new(NETWORK, HEIGHT)?;
    commitment.rebuild_from_raw_leaves(&leaves)?;
    let expected_inner = commitment.root();
    let expected_outer = commitment.network_bound_root();
    let buckets = commitment.bucket_count();
    if buckets != 1 {
        return Err(format!("expected exactly one primary bucket; got {buckets}").into());
    }

    let mut samples_ns = Vec::with_capacity(rounds - 1);
    for round in 0..rounds {
        let start = Instant::now();
        commitment.rebuild_from_raw_leaves(&leaves)?;
        let elapsed = start.elapsed().as_nanos();

        if commitment.root() != expected_inner
            || commitment.network_bound_root() != expected_outer
            || commitment.bucket_count() != 1
        {
            return Err(format!(
                "root/shape mismatch for {}/{} at round {round}",
                distribution.label(),
                count
            )
            .into());
        }
        if round > 0 {
            samples_ns.push(elapsed);
            println!(
                "SAMPLE|run={run_label}|distribution={}|leaves={count}|sample={round}|rebuild_us={:.3}|root_match=true",
                distribution.label(),
                elapsed as f64 / 1_000.0
            );
        }
    }
    samples_ns.sort_unstable();
    let mean_us = samples_ns.iter().sum::<u128>() as f64 / samples_ns.len() as f64 / 1_000.0;
    println!(
        "SUMMARY|run={run_label}|distribution={}|leaves={count}|buckets={buckets}|samples={}|mean_us={mean_us:.3}|median_us={:.3}|min_us={:.3}|max_us={:.3}|inner_root={}|outer_root={}|root_checks=all",
        distribution.label(),
        samples_ns.len(),
        median(&samples_ns),
        samples_ns[0] as f64 / 1_000.0,
        samples_ns[samples_ns.len() - 1] as f64 / 1_000.0,
        hex(&expected_inner),
        hex(&expected_outer)
    );
    Ok(())
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
    let run_label = args
        .iter()
        .position(|arg| arg == "--label")
        .and_then(|index| args.get(index + 1))
        .map(String::as_str)
        .unwrap_or("baseline");

    println!("CPW_ADAPTIVE_TRIE_DENSITY_PROFILE_V1");
    println!("ENV|run={run_label}|OS={}|ARCH={}|ROUNDS={rounds}|WARMUP_ROUNDS=1|METHOD=timed_rebuild_only|DATA=single-primary-bucket,mixed-16-128-byte-values", std::env::consts::OS, std::env::consts::ARCH);
    for distribution in [Distribution::Spread, Distribution::CommonPrefix] {
        for count in SIZES {
            if let Err(error) = run_fixture(count, distribution, rounds, run_label) {
                eprintln!(
                    "PROFILE_FAILED|distribution={}|leaves={count}|error={error}",
                    distribution.label()
                );
                std::process::exit(1);
            }
        }
    }
    println!("PROFILE_RESULT=PASS");
}
