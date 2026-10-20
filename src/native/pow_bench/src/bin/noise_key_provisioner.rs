//! Provision a random Noise XX static key into a Windows CurrentUser-DPAPI NPK1 file.
//! No private-key material is accepted through process arguments or written to stdout.
use ai_native_l1_pow_bench::noise_key_provisioning::store_protected_noise_private_key;
use snow::{params::NoiseParams, Builder};
use std::{env, path::PathBuf};

const PATTERN: &str = "Noise_XX_25519_ChaChaPoly_SHA256";

struct Config {
    output: PathBuf,
    network_id: [u8; 32],
    replace_existing: bool,
}

fn decode_hex32(value: &str, label: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 {
        return Err(format!("{label} must be exactly 64 hexadecimal characters"));
    }
    let mut bytes = [0u8; 32];
    for (index, slot) in bytes.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| format!("{label} contains invalid hexadecimal"))?;
    }
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(format!("{label} cannot be all zero"));
    }
    Ok(bytes)
}

fn config() -> Result<Config, String> {
    let mut args = env::args().skip(1);
    let mut output = None;
    let mut network_id = None;
    let mut replace_existing = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--output" => {
                if output.is_some() {
                    return Err("--output specified more than once".into());
                }
                output = Some(PathBuf::from(
                    args.next().ok_or("--output requires a path")?,
                ));
            }
            "--network-id-hex" => {
                if network_id.is_some() {
                    return Err("--network-id-hex specified more than once".into());
                }
                network_id = Some(decode_hex32(
                    &args.next().ok_or("--network-id-hex requires a value")?,
                    "--network-id-hex",
                )?);
            }
            "--replace-existing" => {
                if replace_existing {
                    return Err("--replace-existing specified more than once".into());
                }
                replace_existing = true;
            }
            "--private-key-hex" | "--private-key-file" | "--private-key-stdin" => {
                return Err(
                    "private-key input is not accepted; this tool generates its own random key"
                        .into(),
                );
            }
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }
    let output = output.ok_or("missing --output")?;
    let network_id = network_id.ok_or("missing --network-id-hex")?;
    if output.as_os_str().is_empty() || output.file_name().is_none() {
        return Err("invalid --output path".into());
    }
    if output.exists() && !replace_existing {
        return Err("output already exists; specify --replace-existing only for an intentional key replacement".into());
    }
    Ok(Config {
        output,
        network_id,
        replace_existing,
    })
}

fn bytes_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn main_result() -> Result<(), String> {
    #[cfg(not(windows))]
    {
        return Err("noise_key_provisioner requires Windows CurrentUser DPAPI".into());
    }

    #[cfg(windows)]
    {
        let config = config()?;
        if config.output.exists() && !config.replace_existing {
            return Err("output already exists; refusing to replace protected key".into());
        }
        let params: NoiseParams = PATTERN
            .parse()
            .map_err(|error: snow::Error| format!("Noise pattern invalid: {error}"))?;
        let mut keypair = Builder::new(params)
            .generate_keypair()
            .map_err(|error| format!("secure Noise key generation failed: {error}"))?;
        if keypair.private.len() != 32 || keypair.public.len() != 32 {
            keypair.private.fill(0);
            return Err("Noise provider returned an unexpected key length".into());
        }
        let mut private = [0u8; 32];
        private.copy_from_slice(&keypair.private);
        let store_result =
            store_protected_noise_private_key(&config.output, &config.network_id, &private);
        private.fill(0);
        keypair.private.fill(0);
        store_result.map_err(|error| format!("DPAPI key protection failed: {error}"))?;
        println!("protected_key_file={}", config.output.display());
        println!("network_id_hex={}", bytes_hex(&config.network_id));
        println!("noise_static_public_key_hex={}", bytes_hex(&keypair.public));
        println!("protection=Windows_CurrentUser_DPAPI_NPK1");
        keypair.public.fill(0);
        Ok(())
    }
}

fn main() {
    if let Err(error) = main_result() {
        eprintln!("NOISE_KEY_PROVISIONING_ERROR: {error}");
        std::process::exit(2);
    }
}
