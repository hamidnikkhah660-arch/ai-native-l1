use std::env;
use std::time::{Duration, Instant};

fn mix(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^ (x >> 31)
}

fn run(bytes: usize, rounds: u64, seconds: f64) -> (u64, Duration, u64) {
    let words = (bytes / 8).max(1024);
    let mut state: Vec<u64> = (0..words as u64).map(mix).collect();
    let start = Instant::now();
    let deadline = start + Duration::from_secs_f64(seconds);
    let mut evaluations = 0u64;
    let mut checksum = 0u64;

    while Instant::now() < deadline {
        for r in 0..rounds {
            let mut i = (mix(evaluations ^ r) as usize) % words;
            for _ in 0..words.min(4096) {
                let j = (i ^ (state[i] as usize)) % words;
                state[j] = mix(state[j].wrapping_add(state[i]).wrapping_add(r));
                checksum ^= state[j];
                i = j;
            }
        }
        evaluations += 1;
    }

    let elapsed = start.elapsed();
    (evaluations, elapsed, checksum)
}

fn parse_arg(name: &str, default: String) -> String {
    let args: Vec<String> = env::args().collect();
    args.windows(2)
        .find(|w| w[0] == name)
        .map(|w| w[1].clone())
        .unwrap_or(default)
}

fn main() {
    println!("AI-NATIVE L1 native PoW benchmark harness");
    println!("WARNING: synthetic memory-bound workload; NOT cryptographic PoW");

    let mib: usize = parse_arg("--mib", "16".into()).parse().unwrap_or(16);
    let rounds: u64 = parse_arg("--rounds", "2".into()).parse().unwrap_or(2);
    let seconds: f64 = parse_arg("--seconds", "3".into()).parse().unwrap_or(3.0);
    let (evaluations, elapsed, checksum) = run(mib * 1024 * 1024, rounds, seconds);

    let rate = evaluations as f64 / elapsed.as_secs_f64().max(1e-9);

    println!("working_set_mib={mib}");
    println!("rounds={rounds}");
    println!("elapsed_seconds={:.3}", elapsed.as_secs_f64());
    println!("evaluations={evaluations}");
    println!("evaluations_per_second={rate:.3}");
    println!("checksum={checksum:016x}");
}
