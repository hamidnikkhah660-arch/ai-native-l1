use ai_native_l1_pow_bench::asset_state_adaptive_commitment_candidate::AdaptiveAssetStateCommitment;
use std::time::Instant;

const NETWORK: [u8; 32] = [0xC7; 32];
const BUCKET: [u8; 2] = [0x5A, 0xA5];

fn key(suffix: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..2].copy_from_slice(&BUCKET);
    out[24..].copy_from_slice(&suffix.to_be_bytes());
    out
}

fn run(size: usize, rounds: usize) -> Result<(), Box<dyn std::error::Error>> {
    let leaves: Vec<([u8; 32], Vec<u8>)> =
        (0..size).map(|i| (key(i as u64), vec![0x01; 32])).collect();

    let mut commitment = AdaptiveAssetStateCommitment::new(NETWORK, 100)?;
    commitment.rebuild_from_raw_leaves(&leaves)?;
    let target = key((size / 2) as u64);

    let mut proof_ms = 0.0f64;
    let mut encode_ms = 0.0f64;
    let mut verify_ms = 0.0f64;
    let mut proof_bytes = 0usize;

    for _ in 0..rounds {
        let start = Instant::now();
        let proof = commitment.membership_proof_with_value(target, &[0x01; 32])?;
        proof_ms += start.elapsed().as_secs_f64() * 1000.0;

        let start = Instant::now();
        let encoded = AdaptiveAssetStateCommitment::encode_membership_proof(&proof)?;
        encode_ms += start.elapsed().as_secs_f64() * 1000.0;
        proof_bytes = encoded.len();

        let decoded = AdaptiveAssetStateCommitment::decode_membership_proof(&encoded)?;

        let start = Instant::now();
        let verified = AdaptiveAssetStateCommitment::verify_membership_proof_typed(
            NETWORK,
            commitment.inner_root_typed(),
            &decoded,
        )?;
        verify_ms += start.elapsed().as_secs_f64() * 1000.0;

        if !verified {
            return Err(format!("size {size}: proof verification failed").into());
        }
    }

    println!(
        "SIZE={} ROUNDS={} PROOF_MS_AVG={:.3} ENCODE_MS_AVG={:.3} VERIFY_MS_AVG={:.3} TOTAL_MS_AVG={:.3} PROOF_BYTES={} DEPTH={} CHUNK={} ",
        size,
        rounds,
        proof_ms / rounds as f64,
        encode_ms / rounds as f64,
        verify_ms / rounds as f64,
        (proof_ms + encode_ms + verify_ms) / rounds as f64,
        proof_bytes,
        commitment.deepest_bucket_path(),
        commitment.largest_terminal_chunk_len(),
    );
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let sizes = args
        .iter()
        .position(|arg| arg == "--sizes")
        .and_then(|i| args.get(i + 1))
        .map(|raw| {
            raw.split(',')
                .filter_map(|v| v.parse::<usize>().ok())
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| vec![1000, 10000, 100000]);
    let rounds = args
        .iter()
        .position(|arg| arg == "--rounds")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(8);

    println!("CPW_ASSET_STATE_ADAPTIVE_PROOF_PROFILE_V1");
    for size in sizes {
        if let Err(error) = run(size, rounds) {
            eprintln!("PROFILE_FAILED SIZE={} ERROR={}", size, error);
            std::process::exit(1);
        }
    }
}
