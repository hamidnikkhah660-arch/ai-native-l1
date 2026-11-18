//! Verify an existing protected Noise identity in a fresh process without exporting its key.
//! The only successful output is a public fingerprint comparison result.
use ai_native_l1_pow_bench::noise_key_provisioning::load_protected_noise_private_key;
use sha2::{Digest, Sha256};
use snow::{params::NoiseParams, Builder};
use std::{env, path::PathBuf, process::ExitCode};
use zeroize::Zeroize;

fn decode_hex32(value: &str, label: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.is_ascii() {
        return Err(format!("{label} must be 64 hexadecimal characters"));
    }
    let mut output = [0u8; 32];
    for (index, slot) in output.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| format!("{label} contains invalid hexadecimal"))?;
    }
    if output == [0; 32] {
        return Err(format!("{label} must not be zero"));
    }
    Ok(output)
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() != 3 {
        return Err("usage: noise_identity_reload_verify <protected-key-path> <network-id-hex> <expected-public-fingerprint-hex>".into());
    }
    let path = PathBuf::from(&args[0]);
    let network = decode_hex32(&args[1], "network ID")?;
    let expected_fingerprint = decode_hex32(&args[2], "expected fingerprint")?;

    let mut local_private = load_protected_noise_private_key(&path, &network)
        .map_err(|error| format!("protected identity reload failed: {error:?}"))?;

    let params: NoiseParams = "Noise_XX_25519_ChaChaPoly_SHA256"
        .parse()
        .map_err(|error: snow::Error| format!("Noise pattern invalid: {error}"))?;
    let mut initiator = Builder::new(params.clone())
        .local_private_key(&local_private)
        .build_initiator()
        .map_err(|error| format!("Noise initiator construction failed: {error}"))?;
    local_private.zeroize();

    let mut responder_keypair = Builder::new(params.clone())
        .generate_keypair()
        .map_err(|error| format!("temporary responder key generation failed: {error}"))?;
    let mut responder = Builder::new(params)
        .local_private_key(&responder_keypair.private)
        .build_responder()
        .map_err(|error| format!("Noise responder construction failed: {error}"))?;
    responder_keypair.private.zeroize();
    responder_keypair.public.zeroize();

    let mut message = vec![0u8; 256];
    let mut payload = vec![0u8; 256];
    let len1 = initiator
        .write_message(&[], &mut message)
        .map_err(|error| format!("Noise message 1 failed: {error}"))?;
    responder
        .read_message(&message[..len1], &mut payload)
        .map_err(|error| format!("Noise responder rejected message 1: {error}"))?;

    let len2 = responder
        .write_message(&[], &mut message)
        .map_err(|error| format!("Noise message 2 failed: {error}"))?;
    initiator
        .read_message(&message[..len2], &mut payload)
        .map_err(|error| format!("Noise initiator rejected message 2: {error}"))?;

    let len3 = initiator
        .write_message(&[], &mut message)
        .map_err(|error| format!("Noise message 3 failed: {error}"))?;
    responder
        .read_message(&message[..len3], &mut payload)
        .map_err(|error| format!("Noise responder rejected message 3: {error}"))?;

    let remote_static = responder
        .get_remote_static()
        .ok_or("Noise handshake did not expose the initiator static public key")?;
    if remote_static.len() != 32 {
        return Err("recovered Noise static public key has an invalid length".into());
    }
    let actual_fingerprint: [u8; 32] = Sha256::digest(remote_static).into();
    message.zeroize();
    payload.zeroize();

    if actual_fingerprint != expected_fingerprint {
        return Err(
            "reloaded protected identity does not match the expected public fingerprint".into(),
        );
    }

    println!("PROTECTED_IDENTITY_RELOAD=PASS");
    println!("NOISE_XX_STATIC_KEY_PROOF=PASS");
    println!("PUBLIC_FINGERPRINT_MATCH=TRUE");
    println!("PRIVATE_KEY_EXPORTED=FALSE");
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("PROTECTED_IDENTITY_RELOAD=FAIL: {error}");
            ExitCode::FAILURE
        }
    }
}
