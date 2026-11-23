//! Owner-run local provisioning/verification utility for QFP6 TPM-to-Noise binding.
//! The existing DPAPI/NPK1 Noise key is read through the library custody API; raw private
//! material is never accepted as an argument, printed, or written to disk.
use ai_native_l1_pow_bench::{
    noise_key_provisioning::load_protected_noise_private_key,
    qfp6_device_identity_candidate::{
        create_device_root_binding_record, derive_noise_static_public_key,
        verify_device_root_binding,
    },
};
use std::{env, fs::OpenOptions, io::Write, path::PathBuf};
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

fn parse_hex32(name: &str, value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "{name} must contain exactly 64 hexadecimal characters"
        ));
    }
    let mut out = [0u8; 32];
    for (i, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(pair).map_err(|_| format!("{name} is not ASCII"))?;
        out[i] = u8::from_str_radix(text, 16).map_err(|_| format!("{name} is malformed"))?;
    }
    Ok(out)
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let mode = value(&args, "--mode")?;
    let metadata = PathBuf::from(value(&args, "--metadata")?);
    let noise_key = PathBuf::from(value(&args, "--noise-key")?);
    let network = parse_hex32("NetworkId", &value(&args, "--network-id-hex")?)?;
    let profile = parse_hex32("ProfileId", &value(&args, "--profile-id-hex")?)?;

    match mode.as_str() {
        "create" => {
            let output = PathBuf::from(value(&args, "--output")?);
            let record =
                create_device_root_binding_record(&metadata, &noise_key, &network, &profile)?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&output)
                .map_err(|error| {
                    format!("refusing to overwrite binding output; create-new failed: {error}")
                })?;
            if let Err(error) = file.write_all(&record).and_then(|_| file.sync_all()) {
                let _ = std::fs::remove_file(&output);
                return Err(format!(
                    "binding record could not be written durably: {error}"
                ));
            }
            println!("QFP6_DEVICE_ROOT_BINDING=CREATED");
            println!("TPM_PRIVATE_EXPORT=NOT_USED");
            println!("NOISE_PRIVATE_KEY=EXISTING_DPAPI_NPK1_UNCHANGED");
            println!("NETWORK_ACCESS=NOT_USED");
            println!("SCOPE=LOCAL_ONLY_NOT_PUBLISHED");
            println!("OUTPUT={}", output.display());
            Ok(())
        }
        "verify" => {
            let binding = PathBuf::from(value(&args, "--binding")?);
            let private_key = Zeroizing::new(
                load_protected_noise_private_key(&noise_key, &network)
                    .map_err(|error| format!("existing protected Noise key rejected: {error}"))?,
            );
            let public_key = derive_noise_static_public_key(&private_key)?;
            let verified =
                verify_device_root_binding(&metadata, &binding, &public_key, &network, &profile)?;
            println!("QFP6_DEVICE_ROOT_BINDING=VERIFIED");
            println!("TPM_PRIVATE_EXPORT=BLOCKED_BY_CNG_KEY_POLICY");
            println!("TPM_PRIVATE_KEY_OPERATION=PASS");
            println!("NOISE_KEY_MATCH=PASS");
            println!("NETWORK_PROFILE_BINDING=PASS");
            println!("SCOPE=LOCAL_ONLY_NOT_PUBLISHED");
            println!("DEVICE_ID={}", verified.device_id);
            Ok(())
        }
        _ => Err("mode must be exactly create or verify".into()),
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("QFP6_DEVICE_ROOT_BINDING=REJECTED");
        eprintln!("reason={error}");
        std::process::exit(2);
    }
}
