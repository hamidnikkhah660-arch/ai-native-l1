//! Reproducible Rust-side Argon2id throughput benchmark using the candidate pow_digest.
//!
//! Research benchmark only. It measures hashes/second, not wall power, joules/hash, hardware
//! rental availability, pool behavior, or production consensus security.

use ai_native_l1_pow_bench::consensus::{pow_digest, ConsensusParameters, PowHeader, Uint256};
use std::time::Instant;

const MEMORY_MIB_CASES: [u32; 3] = [16, 32, 64];
const TRIALS: usize = 7;
const HASHES_PER_TRIAL: u64 = 8;
const WARMUP_HASHES: u64 = 2;
const NONCE_BASE: u64 = 0xC060_1000;

fn median(values: &[f64]) -> f64 {
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let middle = sorted.len() / 2;
    if sorted.len() % 2 == 0 {
        (sorted[middle - 1] + sorted[middle]) / 2.0
    } else {
        sorted[middle]
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("CPW_RUST_CANDIDATE_POW_BENCHMARK=START");
    println!("algorithm=Argon2id; version=19; time_cost=1; lanes=1; output_bytes=32");
    println!(
        "input=PowHeader preimage via project consensus::pow_digest; nonce and timestamp vary"
    );
    println!("trials_per_case={TRIALS}; hashes_per_trial={HASHES_PER_TRIAL}; warmup_hashes={WARMUP_HASHES}");
    println!("scope=single host; research measurement; not a consensus or joules-per-hash result");

    for memory_mib in MEMORY_MIB_CASES {
        let mut params = ConsensusParameters::candidate_testnet()?;
        params.pow.memory_kib = memory_mib * 1024;
        params.pow.validate()?;

        let mut header = PowHeader {
            protocol_version: params.protocol_version,
            network_id: [0xA1; 32],
            height: 1,
            timestamp: 1_800_000_000,
            parent_hash: [0xB2; 32],
            previous_consensus_hash: [0xD4; 32],
            state_root: [0xC3; 32],
            target: Uint256::from_be_bytes({
                let mut target = [0xFF; 32];
                target[0] = 0x00;
                target[1] = 0x7F;
                target
            }),
            nonce: NONCE_BASE,
        };

        let mut checksum = 0u8;
        for warm in 0..WARMUP_HASHES {
            header.nonce = NONCE_BASE + warm;
            header.timestamp = 1_800_000_000 + warm;
            checksum ^= pow_digest(&header, params.pow)?[0];
        }

        let mut rates = Vec::with_capacity(TRIALS);
        let mut elapsed_samples = Vec::with_capacity(TRIALS);
        for trial in 0..TRIALS {
            let start = Instant::now();
            for offset in 0..HASHES_PER_TRIAL {
                let nonce = NONCE_BASE + WARMUP_HASHES + (trial as u64) * HASHES_PER_TRIAL + offset;
                header.nonce = nonce;
                header.timestamp = 1_800_000_000 + nonce;
                let digest = pow_digest(&header, params.pow)?;
                checksum ^= digest[(nonce as usize) % digest.len()];
            }
            let elapsed = start.elapsed().as_secs_f64();
            if elapsed <= 0.0 {
                return Err("benchmark clock reported non-positive duration".into());
            }
            elapsed_samples.push(elapsed);
            rates.push(HASHES_PER_TRIAL as f64 / elapsed);
        }

        let rate_median = median(&rates);
        let rate_mad = median(
            &rates
                .iter()
                .map(|value| (value - rate_median).abs())
                .collect::<Vec<_>>(),
        );
        let elapsed_median = median(&elapsed_samples);
        println!(
            "MEMORY_MIB={memory_mib} MEDIAN_TRIAL_SECONDS={elapsed_median:.6} \
             HASHES_PER_SECOND_MEDIAN={rate_median:.3} HPS_MAD={rate_mad:.3} \
             TRIALS={} HASHES_PER_TRIAL={} CHECKSUM={checksum:02x}",
            rates.len(),
            HASHES_PER_TRIAL
        );
    }

    println!("POWER_WATTS=NOT_MEASURED");
    println!("CROSS_HARDWARE=NOT_MEASURED");
    println!("CPW_RUST_CANDIDATE_POW_BENCHMARK=PASS");
    Ok(())
}
