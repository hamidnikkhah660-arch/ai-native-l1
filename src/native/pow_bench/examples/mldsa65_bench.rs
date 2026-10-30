//! Reproducible single-host ML-DSA-65 microbenchmark for QRun's pinned Libcrux adapter.
//!
//! This measures the portable implementation over a 32-byte QRun-style digest and empty
//! context. Deterministic seeds are benchmark fixtures only, never production entropy.
//! Run in release mode; record CPU, OS, rustc, Cargo.lock hash and power profile with results.

use libcrux_ml_dsa::ml_dsa_65::portable;
use std::hint::black_box;
use std::time::Instant;

const SAMPLES: usize = 31;
const KEYGEN_OPS_PER_SAMPLE: usize = 20;
const SIGN_OPS_PER_SAMPLE: usize = 32;
const VERIFY_OPS_PER_SAMPLE: usize = 256;

fn seed(counter: usize, domain: u8) -> [u8; 32] {
    let mut out = [domain; 32];
    let counter = (counter as u64).to_be_bytes();
    out[..8].copy_from_slice(&counter);
    out[8] ^= domain.wrapping_mul(17);
    out[31] ^= domain.wrapping_add(0x5a);
    out
}

fn percentile(sorted: &[f64], percentile: usize) -> f64 {
    let index = ((sorted.len() * percentile + 99) / 100)
        .saturating_sub(1)
        .min(sorted.len().saturating_sub(1));
    sorted[index]
}

fn measure<F>(name: &str, ops_per_sample: usize, mut operation: F)
where
    F: FnMut(usize),
{
    for warmup in 0..3 * ops_per_sample {
        operation(warmup);
    }

    let mut ns_per_op = Vec::with_capacity(SAMPLES);
    for sample in 0..SAMPLES {
        let start = Instant::now();
        for operation_index in 0..ops_per_sample {
            operation(sample * ops_per_sample + operation_index);
        }
        let elapsed = start.elapsed().as_nanos() as f64;
        ns_per_op.push(elapsed / ops_per_sample as f64);
    }
    ns_per_op.sort_by(f64::total_cmp);

    let p50 = percentile(&ns_per_op, 50);
    let p95 = percentile(&ns_per_op, 95);
    println!(
        "{name}: p50={p50:.0} ns/op ({:.3} us/op), p95={p95:.0} ns/op ({:.3} us/op), p50_rate={:.1} ops/s",
        p50 / 1_000.0,
        p95 / 1_000.0,
        1_000_000_000.0 / p50
    );
}

fn main() {
    let message = [0x5a_u8; 32];
    let key_pair = portable::generate_key_pair(seed(1, 0x4b));
    let signature = portable::sign(&key_pair.signing_key, &message, &[], seed(2, 0x53))
        .expect("Libcrux ML-DSA-65 signing fixture must succeed");
    assert!(
        portable::verify(&key_pair.verification_key, &message, &[], &signature).is_ok(),
        "preflight signature must verify"
    );

    println!("algorithm=ML-DSA-65");
    println!("implementation=libcrux-ml-dsa 0.0.4 / portable");
    println!("message_bytes={}", message.len());
    println!("context_bytes=0");
    println!(
        "public_key_bytes={}",
        key_pair.verification_key.as_ref().len()
    );
    println!("signature_bytes={}", signature.as_ref().len());
    println!("samples={SAMPLES}");
    println!("warmup_batches=3");

    measure("keygen", KEYGEN_OPS_PER_SAMPLE, |index| {
        let pair = portable::generate_key_pair(seed(index + 100, 0x4b));
        black_box(pair.verification_key.as_ref()[0]);
    });

    measure("sign", SIGN_OPS_PER_SAMPLE, |index| {
        let signed = portable::sign(
            &key_pair.signing_key,
            &message,
            &[],
            seed(index + 10_000, 0x53),
        )
        .expect("Libcrux ML-DSA-65 signing must succeed");
        black_box(signed.as_ref()[0]);
    });

    measure("verify", VERIFY_OPS_PER_SAMPLE, |_| {
        let valid = portable::verify(&key_pair.verification_key, &message, &[], &signature).is_ok();
        black_box(valid);
        assert!(valid, "preflight signature must continue to verify");
    });

    println!("note=single-host microbenchmark; no production or multi-node performance claim");
}
