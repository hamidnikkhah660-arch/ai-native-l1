//! Local-only Q6PD node identity provision/verify utility.
//! The Ed25519 signing seed is generated internally, protected by CurrentUser DPAPI,
//! and bound by the non-exportable TPM Device Root to the exact Noise key/network/profile.
//! No endpoint is selected or published by this command.
use ai_native_l1_pow_bench::qrun_v06_peer_identity_candidate::{
    load_q6pd_node_identity, provision_q6pd_node_identity,
};
use std::{env, path::PathBuf};

fn value(args: &[String], name: &str) -> Result<String, String> {
    let mut found = None;
    let mut index = 0usize;
    while index < args.len() {
        if args[index] == name {
            if found.is_some() || index + 1 >= args.len() || args[index + 1].starts_with("--") {
                return Err(format!("{name} must be supplied exactly once with a value"));
            }
            found = Some(args[index + 1].clone());
            index += 2;
        } else {
            index += 1;
        }
    }
    found.ok_or_else(|| format!("missing required argument {name}"))
}

fn parse_hex32(name: &str, value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!(
            "{name} must contain exactly 64 hexadecimal characters"
        ));
    }
    let mut output = [0u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(pair).map_err(|_| format!("{name} is not ASCII"))?;
        output[index] = u8::from_str_radix(text, 16).map_err(|_| format!("{name} is malformed"))?;
    }
    Ok(output)
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let mode = value(&args, "--mode")?;
    let metadata_path = PathBuf::from(value(&args, "--metadata")?);
    let noise_key_path = PathBuf::from(value(&args, "--noise-key")?);
    let identity_key_path = PathBuf::from(value(&args, "--identity-key")?);
    let binding_path = PathBuf::from(value(&args, "--binding")?);
    let network_id = parse_hex32("NetworkId", &value(&args, "--network-id-hex")?)?;
    let profile_id = parse_hex32("ProfileId", &value(&args, "--profile-id-hex")?)?;

    match mode.as_str() {
        "provision" => {
            let info = provision_q6pd_node_identity(
                &identity_key_path,
                &binding_path,
                &metadata_path,
                &noise_key_path,
                &network_id,
                &profile_id,
            )?;
            println!("QFP6_Q6PD_NODE_IDENTITY=PROVISIONED_AND_TPM_VERIFIED");
            println!("IDENTITY_KEY_CUSTODY=CURRENT_USER_DPAPI_ROLE_PEER_NODE_IDENTITY");
            println!("TPM_DEVICE_ROOT_BINDING=VERIFIED");
            println!("NOISE_PUBLIC_KEY_BINDING=VERIFIED");
            println!("NETWORK_PROFILE_BINDING=VERIFIED");
            println!("IDENTITY_PRIVATE_SEED=NEVER_EXPORTED_OR_PRINTED");
            println!("NETWORK_ACCESS=NOT_USED");
            println!("PUBLIC_ENDPOINT=NOT_CONFIGURED");
            println!(
                "PEER_ID={}",
                info.peer_id
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            );
            println!("DEVICE_ID={}", info.device_id);
            Ok(())
        }
        "verify" => {
            let identity = load_q6pd_node_identity(
                &identity_key_path,
                &binding_path,
                &metadata_path,
                &noise_key_path,
                &network_id,
                &profile_id,
            )?;
            let info = identity.info();
            println!("QFP6_Q6PD_NODE_IDENTITY=VERIFIED");
            println!("IDENTITY_KEY_CUSTODY=CURRENT_USER_DPAPI_ROLE_PEER_NODE_IDENTITY");
            println!("TPM_DEVICE_ROOT_BINDING=VERIFIED");
            println!("NOISE_PUBLIC_KEY_BINDING=VERIFIED");
            println!("NETWORK_PROFILE_BINDING=VERIFIED");
            println!("IDENTITY_PRIVATE_SEED=NEVER_EXPORTED_OR_PRINTED");
            println!("NETWORK_ACCESS=NOT_USED");
            println!("PUBLIC_ENDPOINT=NOT_CONFIGURED");
            println!(
                "PEER_ID={}",
                info.peer_id
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            );
            println!("DEVICE_ID={}", info.device_id);
            Ok(())
        }
        _ => Err("mode must be exactly provision or verify".into()),
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("QFP6_Q6PD_NODE_IDENTITY=REJECTED");
        eprintln!("reason={error}");
        std::process::exit(2);
    }
}
