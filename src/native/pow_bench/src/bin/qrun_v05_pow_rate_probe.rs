use ai_native_l1_pow_bench::consensus::{pow_digest, ConsensusParameters, PowHeader, Uint256};
use std::time::Instant;

fn main() {
    let params =
        ConsensusParameters::qrun_v05_calibrated_candidate().expect("calibrated QRun profile");
    let target = params.initial_target;
    let mut header = PowHeader {
        protocol_version: params.protocol_version,
        network_id: [0xA1; 32],
        height: 1,
        timestamp: 1_800_000_000,
        parent_hash: [0xB2; 32],
        previous_consensus_hash: [0xC3; 32],
        state_root: [0xD4; 32],
        target,
        nonce: 0,
    };
    let attempts = 12u64;
    let start = Instant::now();
    let mut hits = 0u64;
    for nonce in 0..attempts {
        header.nonce = nonce;
        let digest = pow_digest(&header, params.pow).expect("Argon2id digest");
        if Uint256::from_be_bytes(digest) <= target {
            hits += 1;
        }
    }
    let elapsed = start.elapsed();
    println!("profile=qrun_v05_calibrated_candidate");
    println!("algorithm=Argon2id");
    println!("memory_kib={}", params.pow.memory_kib);
    println!("iterations={}", params.pow.iterations);
    println!("lanes={}", params.pow.lanes);
    println!("target_hex={}", hex(&target.to_be_bytes()));
    println!(
        "theoretical_success_probability={:.12}",
        target_ratio(&target)
    );
    println!("attempts={attempts}");
    println!("hits={hits}");
    println!("elapsed_ms={}", elapsed.as_millis());
    println!(
        "hashes_per_second={:.4}",
        attempts as f64 / elapsed.as_secs_f64()
    );
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

fn target_ratio(target: &Uint256) -> f64 {
    let bytes = target.to_be_bytes();
    let mut ratio = 0.0f64;
    for byte in bytes {
        ratio = ratio * 256.0 + byte as f64;
    }
    ratio / f64::from_bits(0x4ff0_0000_0000_0000)
}
