use ai_native_l1_pow_bench::{
    noise_key_provisioning::load_protected_noise_private_key,
    qfp6_device_identity_candidate::derive_noise_static_public_key,
};
use std::{env, path::PathBuf};
use zeroize::Zeroizing;

fn value(args: &[String], name: &str) -> Result<String, String> {
    let mut found = None;
    let mut i = 0usize;
    while i < args.len() {
        if args[i] == name {
            if found.is_some() || i + 1 >= args.len() || args[i + 1].starts_with("--") {
                return Err(format!("{name} must be supplied exactly once with a value"));
            }
            found = Some(args[i + 1].clone());
            i += 2;
        } else {
            i += 1;
        }
    }
    found.ok_or_else(|| format!("missing required argument {name}"))
}

fn parse_network_id(text: &str) -> Result<[u8; 32], String> {
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("network ID must contain exactly 64 hexadecimal characters".into());
    }
    let mut out = [0u8; 32];
    for (i, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(pair).map_err(|_| "network ID is not ASCII")?;
        out[i] = u8::from_str_radix(pair, 16).map_err(|_| "network ID is malformed")?;
    }
    Ok(out)
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let noise_key_path = PathBuf::from(value(&args, "--noise-key")?);
    let network_id = parse_network_id(&value(&args, "--network-id-hex")?)?;
    let private_key = Zeroizing::new(
        load_protected_noise_private_key(&noise_key_path, &network_id)
            .map_err(|error| format!("protected Noise key rejected: {error}"))?,
    );
    let public_key = derive_noise_static_public_key(&*private_key)?;
    let public_hex = public_key
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    use sha2::{Digest, Sha256};
    let fingerprint = Sha256::digest(public_key);
    let fingerprint_hex = fingerprint
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    println!("QFP6_NOISE_STATIC_PUBLIC_KEY_HEX={public_hex}");
    println!("QFP6_NOISE_STATIC_PUBLIC_KEY_SHA256={fingerprint_hex}");
    println!("PRIVATE_KEY_EXPORTED=FALSE");
    println!("NETWORK_ACCESS=NONE");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("QFP6_NOISE_PUBLIC_KEY_PROBE=REJECTED");
        eprintln!("reason={error}");
        std::process::exit(2);
    }
}
