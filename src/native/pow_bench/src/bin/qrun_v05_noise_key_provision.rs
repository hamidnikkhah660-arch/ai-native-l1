//! Provision a network-bound DPAPI-protected QRun Noise XX static key.
use ai_native_l1_pow_bench::noise_key_provisioning::store_protected_noise_private_key;
use snow::{params::NoiseParams, Builder};
use std::{env, fs, path::PathBuf};

fn parse_hex32(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.is_ascii() {
        return Err("--network-id-hex must be exactly 64 hexadecimal characters".into());
    }
    let mut bytes = [0u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| "--network-id-hex contains a non-hexadecimal character".to_string())?;
    }
    if bytes.iter().all(|byte| *byte == 0) {
        return Err("--network-id-hex must be nonzero".into());
    }
    Ok(bytes)
}

fn run() -> Result<(), String> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() == 1 && args[0] == "--help" {
        println!("QRun Noise key provisioner\nUsage: qrun_v05_noise_key_provision --network-id-hex HEX64 --output ABSOLUTE_NPK1_FILE");
        return Ok(());
    }
    if args.len() != 4 || args[0] != "--network-id-hex" || args[2] != "--output" {
        return Err("usage: --network-id-hex HEX64 --output ABSOLUTE_NPK1_FILE".into());
    }

    let network_id = parse_hex32(&args[1])?;
    let output = PathBuf::from(&args[3]);
    if !output.is_absolute() || output.file_name().is_none() {
        return Err("--output must be an absolute file path".into());
    }
    let parent = output
        .parent()
        .ok_or_else(|| "--output must have an existing parent directory".to_string())?;
    let parent_metadata =
        fs::metadata(parent).map_err(|error| format!("inspect output directory: {error}"))?;
    if !parent_metadata.is_dir() {
        return Err("--output parent must be a directory".into());
    }
    if fs::symlink_metadata(&output).is_ok() {
        return Err("refusing to overwrite an existing Noise key file".into());
    }

    let params: NoiseParams = "Noise_XX_25519_ChaChaPoly_SHA256"
        .parse()
        .map_err(|error| format!("parse QRun Noise pattern: {error}"))?;
    let mut keypair = Builder::new(params)
        .generate_keypair()
        .map_err(|error| format!("generate OS-random Noise keypair: {error}"))?;
    if keypair.private.len() != 32 || keypair.public.len() != 32 {
        keypair.private.fill(0);
        keypair.public.fill(0);
        return Err("Noise implementation returned an unexpected static-key length".into());
    }
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&keypair.public);
    let mut private_key = [0u8; 32];
    private_key.copy_from_slice(&keypair.private);
    let persisted = store_protected_noise_private_key(&output, &network_id, &private_key)
        .map_err(|error| format!("protect and persist NPK1 key with CurrentUser DPAPI: {error}"));
    private_key.fill(0);
    keypair.private.fill(0);
    keypair.public.fill(0);
    persisted?;

    println!("noise_key_provisioned=true");
    println!("key_format=NPK1");
    println!("key_protection=Windows_CurrentUser_DPAPI");
    println!("network_id_hex={}", hex(&network_id));
    println!("public_key_hex={}", hex(&public_key));
    println!("private_key_output=never");
    println!("output_path={}", output.display());
    public_key.fill(0);
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

fn main() {
    if let Err(error) = run() {
        eprintln!(
            "QRUN_NOISE_KEY_PROVISION_ERROR: {}",
            error.replace(['\r', '\n'], "_")
        );
        std::process::exit(2);
    }
}
