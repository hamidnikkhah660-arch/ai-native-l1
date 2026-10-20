use ai_native_l1_pow_bench::asset_state_adaptive_commitment_candidate::{
    CHUNK_CAP, MAX_PROOF_VALUE_BYTES,
};
use sha2::{Digest, Sha256};
use std::time::Instant;

const MAX_SUFFIX_DEPTH: usize = 30;
const BENCH_ITERS: usize = 20_000;

fn domain_hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(bytes);
    h.finalize().into()
}

fn current_chunk_hash(prefix_len: usize, entries: &[([u8; 32], [u8; 32])]) -> [u8; 32] {
    let mut payload = Vec::with_capacity(1 + 1 + prefix_len + 4 + entries.len() * 64);
    payload.push(0x01);
    payload.push(prefix_len as u8);
    payload.extend_from_slice(&[0u8; 30][..prefix_len]);
    payload.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    for (key, leaf_hash) in entries {
        payload.extend_from_slice(key);
        payload.extend_from_slice(leaf_hash);
    }
    domain_hash(b"AIN1-ASSET-COMMIT-ADAPT-CHUNK-CAND-V1\0", &payload)
}

fn alternative_chunk_merkle_root(prefix_len: usize, entries: &[([u8; 32], [u8; 32])]) -> [u8; 32] {
    let mut level: Vec<[u8; 32]> = entries
        .iter()
        .map(|(key, leaf_hash)| {
            let mut payload = Vec::with_capacity(1 + 1 + prefix_len + 32 + 32);
            payload.push(0x21);
            payload.push(prefix_len as u8);
            payload.extend_from_slice(&[0u8; 30][..prefix_len]);
            payload.extend_from_slice(key);
            payload.extend_from_slice(leaf_hash);
            domain_hash(b"AIN1-ASSET-COMMIT-CHUNK-MERKLE-ALT-V1\0", &payload)
        })
        .collect();

    if level.is_empty() {
        return domain_hash(b"AIN1-ASSET-COMMIT-CHUNK-MERKLE-ALT-V1\0", &[0x20, 0]);
    }

    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let left = pair[0];
            let right = pair.get(1).copied().unwrap_or_else(|| {
                domain_hash(b"AIN1-ASSET-COMMIT-CHUNK-MERKLE-ALT-V1\0", &[0x22])
            });
            let mut payload = Vec::with_capacity(65);
            payload.push(0x23);
            payload.extend_from_slice(&left);
            payload.extend_from_slice(&right);
            next.push(domain_hash(
                b"AIN1-ASSET-COMMIT-CHUNK-MERKLE-ALT-V1\0",
                &payload,
            ));
        }
        level = next;
    }

    level[0]
}

fn current_proof_size(value_len: usize, chunk_count: usize, depth: usize) -> usize {
    557 + value_len + 64 * chunk_count + 256 * depth
}

fn alternative_proof_size(value_len: usize, depth: usize) -> usize {
    717 + value_len + 256 * depth
}

fn build_entries() -> Vec<([u8; 32], [u8; 32])> {
    (0..CHUNK_CAP)
        .map(|index| {
            let mut key = [0u8; 32];
            key[..2].copy_from_slice(&[0x5A, 0xA5]);
            key[24..].copy_from_slice(&(index as u64).to_be_bytes());
            let mut leaf_payload = Vec::with_capacity(34);
            leaf_payload.extend_from_slice(&key);
            leaf_payload.extend_from_slice(&[0x20, index as u8]);
            let leaf_hash = domain_hash(b"AIN1-ASSET-COMMIT-ADAPT-LEAF-CAND-V1\0", &leaf_payload);
            (key, leaf_hash)
        })
        .collect()
}

fn run() {
    let entries = build_entries();
    let mut current_sink = [0u8; 32];
    let mut alternative_sink = [0u8; 32];

    let current_start = Instant::now();
    for _ in 0..BENCH_ITERS {
        current_sink = current_chunk_hash(8, &entries);
    }
    let current_ms = current_start.elapsed().as_secs_f64() * 1000.0;

    let alternative_start = Instant::now();
    for _ in 0..BENCH_ITERS {
        alternative_sink = alternative_chunk_merkle_root(8, &entries);
    }
    let alternative_ms = alternative_start.elapsed().as_secs_f64() * 1000.0;

    let cases = [
        ("CHUNK_1", 1usize),
        ("CHUNK_8", 8usize),
        ("CHUNK_16", 16usize),
        ("CHUNK_32", 32usize),
    ];

    println!("CPW_ASSET_STATE_ADAPTIVE_ARCHITECTURE_COMPARE_V1");
    println!(
        "PARAMETERS CHUNK_CAP={} MAX_DEPTH={} ITERS={} NOTE=ALT changes terminal chunk commitment semantics; no production freeze",
        CHUNK_CAP, MAX_SUFFIX_DEPTH, BENCH_ITERS
    );

    for (label, chunk_count) in cases {
        let current = current_proof_size(32, chunk_count, MAX_SUFFIX_DEPTH);
        let alternative = alternative_proof_size(32, MAX_SUFFIX_DEPTH);
        let savings = current.saturating_sub(alternative);
        let pct = (savings as f64 / current as f64) * 100.0;
        println!(
            "CASE={} CURRENT_BYTES={} ALT_BYTES={} SAVED_BYTES={} SAVED_PCT={:.2}",
            label, current, alternative, savings, pct
        );
    }

    println!(
        "CHUNK_HASH_BENCH CURRENT_MS={:.3} ALT_MS={:.3} ALT_TO_CURRENT_X={:.3} CURRENT_ROOT={} ALT_ROOT={}",
        current_ms,
        alternative_ms,
        if current_ms > 0.0 { alternative_ms / current_ms } else { 0.0 },
        hex(&current_sink),
        hex(&alternative_sink)
    );
    println!("ROOTS_DISTINCT={}", current_sink != alternative_sink);
    println!("MAX_VALUE_BYTES={}", MAX_PROOF_VALUE_BYTES);
}

fn hex(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn main() {
    run();
}
