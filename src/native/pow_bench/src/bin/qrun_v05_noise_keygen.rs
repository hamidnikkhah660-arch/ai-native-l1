//! Local key provisioning helper for the QRun v0.5 Noise peer-transport candidate.
//! Saves the private static key in a network-bound Windows CurrentUser DPAPI envelope and prints
//! only the public key. A generated key is not a Mainnet identity until the network profile is frozen.
use ai_native_l1_pow_bench::noise_key_provisioning::store_protected_noise_private_key;
use snow::{params::NoiseParams, Builder};
use std::{env, path::PathBuf};

fn parse_hex32(value: &str, name: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.is_ascii() {
        return Err(format!("{name} must be 64 hex characters"));
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16)
            .map_err(|_| format!("{name} contains a non-hex character"))?;
    }
    Ok(out)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(DIGITS[(byte >> 4) as usize] as char);
        value.push(DIGITS[(byte & 15) as usize] as char);
    }
    value
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!("QRun v0.5 candidate peer-key provisioning (not a Mainnet launch)\nUsage: qrun_v05_noise_keygen --network-id-hex HEX64 --output-key-file ABSOLUTE_PATH\nThe private key is stored using Windows CurrentUser DPAPI; only the public key is printed.");
        return Ok(());
    }
    if args.len() != 4 || args[0] != "--network-id-hex" || args[2] != "--output-key-file" {
        return Err("expected --network-id-hex HEX64 --output-key-file ABSOLUTE_PATH".into());
    }
    let network_id = parse_hex32(&args[1], "network ID")?;
    if network_id.iter().all(|byte| *byte == 0) {
        return Err("network ID must be nonzero".into());
    }
    let path = PathBuf::from(&args[3]);
    if !path.is_absolute()
        || path.file_name().is_none()
        || !path.parent().is_some_and(|p| p.is_dir())
    {
        return Err(
            "output path must be absolute and its parent directory must already exist".into(),
        );
    }
    if path.exists() {
        return Err("refusing to overwrite an existing peer-key file".into());
    }
    let params: NoiseParams = "Noise_XX_25519_ChaChaPoly_SHA256"
        .parse()
        .map_err(|error: snow::Error| error.to_string())?;
    let mut pair = Builder::new(params)
        .generate_keypair()
        .map_err(|error| error.to_string())?;
    if pair.private.len() != 32 || pair.public.len() != 32 {
        pair.private.fill(0);
        pair.public.fill(0);
        return Err("generated Noise static keypair has an unexpected length".into());
    }
    let mut private_key = [0u8; 32];
    private_key.copy_from_slice(&pair.private);
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&pair.public);
    pair.private.fill(0);
    pair.public.fill(0);
    let stored = store_protected_noise_private_key(&path, &network_id, &private_key);
    private_key.fill(0);
    stored.map_err(|error| format!("protect peer key with Windows CurrentUser DPAPI: {error}"))?;
    println!("key_file={}", path.display());
    println!("network_id_hex={}", hex(&network_id));
    println!("static_public_key_hex={}", hex(&public_key));
    println!("private_key_output=none");
    println!("profile_status=candidate_only_not_mainnet");
    public_key.fill(0);
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!(
            "QRUN_V05_NOISE_KEYGEN_ERROR: {}",
            error.replace(['\r', '\n'], "_")
        );
        std::process::exit(2);
    }
}
