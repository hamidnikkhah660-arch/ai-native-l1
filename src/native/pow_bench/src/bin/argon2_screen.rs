use argon2::{Algorithm, Argon2, Params, Version};
use std::env;
use std::time::{Duration, Instant};

fn parse_arg(name: &str, default: String) -> String {
    let args: Vec<String> = env::args().collect();
    args.windows(2)
        .find(|w| w[0] == name)
        .map(|w| w[1].clone())
        .unwrap_or(default)
}

fn run(mib: u32, algorithm: Algorithm, seconds: f64) -> (u64, Duration, u8) {
    let params = Params::new(mib * 1024, 1, 1, Some(32)).expect("valid screening parameters");
    let argon = Argon2::new(algorithm, Version::default(), params);

    let password = [0x42u8; 32];
    let salt = [0xA5u8; 16];
    let mut output = [0u8; 32];
    let start = Instant::now();
    let deadline = start + Duration::from_secs_f64(seconds);
    let mut hashes = 0u64;
    let mut checksum = 0u8;
    while Instant::now() < deadline {
        argon
            .hash_password_into(&password, &salt, &mut output)
            .expect("hashing should succeed");
        checksum ^= output[hashes as usize % output.len()];
        hashes += 1;
    }

    (hashes, start.elapsed(), checksum)
}

fn main() {
    println!("AI-NATIVE L1 Argon2 candidate screening");
    println!("WARNING: candidate benchmark only; NOT consensus code");

    let mib: u32 = parse_arg("--mib", "16".into()).parse().unwrap_or(16);
    let seconds: f64 = parse_arg("--seconds", "2".into()).parse().unwrap_or(2.0);
    let mode = parse_arg("--mode", "argon2d".into());

    let algorithm = match mode.as_str() {
        "argon2d" => Algorithm::Argon2d,
        "argon2i" => Algorithm::Argon2i,
        "argon2id" => Algorithm::Argon2id,
        _ => panic!("mode must be argon2d, argon2i, or argon2id"),
    };

    let (hashes, elapsed, checksum) = run(mib, algorithm, seconds);
    let rate = hashes as f64 / elapsed.as_secs_f64().max(1e-9);

    println!("algorithm={mode}");
    println!("working_set_mib={mib}");
    println!("elapsed_seconds={:.3}", elapsed.as_secs_f64());
    println!("hashes={hashes}");
    println!("hashes_per_second={rate:.3}");
    println!("checksum={checksum:02x}");
}
