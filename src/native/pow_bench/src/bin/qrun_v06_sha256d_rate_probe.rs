use ai_native_l1_pow_bench::consensus::{pow_digest, ConsensusParameters, PowHeader, Uint256};
use std::{
    hint::black_box,
    time::{Duration, Instant},
};

const SAMPLES: usize = 5;
const SECONDS_PER_SAMPLE: u64 = 2;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let params = ConsensusParameters::qrun_v06_sha256d_candidate()?;
    let mut header = PowHeader {
        protocol_version: params.protocol_version,
        network_id: [0xA1; 32],
        height: 1,
        timestamp: 1_800_000_000,
        parent_hash: [0xB2; 32],
        previous_consensus_hash: [0xC3; 32],
        state_root: [0xD4; 32],
        target: Uint256::MAX,
        nonce: 0,
    };

    // Warm the exact canonical-header + SHA-256d path before collecting measurements.
    let mut nonce = 0u64;
    let mut checksum = 0u8;
    for _ in 0..100_000 {
        header.nonce = nonce;
        nonce = nonce.checked_add(1).ok_or("nonce overflow")?;
        let digest = pow_digest(&header, params.pow)?;
        checksum ^= digest[0] ^ digest[31];
    }
    black_box(checksum);

    let mut rates = Vec::with_capacity(SAMPLES);
    println!("benchmark=qrun_v06_canonical_sha256d_pow_digest");
    println!("protocol_version={}", params.protocol_version);
    println!("algorithm=SHA-256d");
    println!("samples={SAMPLES}");
    println!("seconds_per_sample={SECONDS_PER_SAMPLE}");
    println!("warmup_hashes=100000");

    for sample in 1..=SAMPLES {
        let start = Instant::now();
        let duration = Duration::from_secs(SECONDS_PER_SAMPLE);
        let mut attempts = 0u64;
        while start.elapsed() < duration {
            header.nonce = nonce;
            nonce = nonce.checked_add(1).ok_or("nonce overflow")?;
            let digest = pow_digest(&header, params.pow)?;
            checksum ^= digest[0] ^ digest[31];
            attempts += 1;
        }
        let elapsed = start.elapsed().as_secs_f64();
        let rate = attempts as f64 / elapsed;
        rates.push(rate);
        println!("sample_{sample}_hashes={attempts}");
        println!("sample_{sample}_elapsed_seconds={elapsed:.6}");
        println!("sample_{sample}_hashes_per_second={rate:.3}");
    }

    rates.sort_by(f64::total_cmp);
    println!("median_hashes_per_second={:.3}", rates[SAMPLES / 2]);
    println!("minimum_hashes_per_second={:.3}", rates[0]);
    println!("maximum_hashes_per_second={:.3}", rates[SAMPLES - 1]);
    println!("checksum={checksum:02x}");
    println!("measurement_scope=single_host_cpu_only_not_network_hashrate");
    Ok(())
}
