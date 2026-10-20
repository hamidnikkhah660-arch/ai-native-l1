//! Deterministic test-only TXN4 fixture generator for CP-0319 loopback smoke.
//! Never use these compiled-in private keys for real assets or production networks.
use ai_native_l1_pow_bench::{
    consensus::Uint256,
    devnet_profile_candidate::DevnetProfileCandidate,
    v4_account_identity_candidate::{
        native_v4_account_id, AccountIdentityScheme, V4HybridAuthorization, V4HybridSignature,
        V4HybridTransaction, ML_DSA_65_PUBLIC_KEY_BYTES,
    },
    v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate,
};
use ed25519_dalek::{Signer, SigningKey};
use libcrux_ml_dsa::ml_dsa_65::portable;
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

const MANIFEST_ID_DOMAIN: &[u8] = b"AIN1-LOCAL-PMT4-PFM4-MANIFEST-ID-V1\0";

fn parse_hex32(value: &str, label: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 {
        return Err(format!("{label} must be 64 hexadecimal characters"));
    }
    let mut result = [0u8; 32];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| format!("{label} must be hexadecimal"))?;
    }
    Ok(result)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(DIGITS[(byte >> 4) as usize] as char);
        text.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    text
}

fn test_manifest_id(network: [u8; 32]) -> Result<[u8; 32], String> {
    let profile =
        DevnetProfileCandidate::new(network).map_err(|error| format!("profile: {error}"))?;
    let mut params = profile.consensus().clone();
    params.initial_target = Uint256::MAX;
    params.pow.memory_kib = 8 * 1024;
    params
        .validate()
        .map_err(|error| format!("test PoW parameters: {error}"))?;

    let mut profile_bytes = Vec::with_capacity(256);
    profile_bytes.extend_from_slice(b"AIN1-LOCAL-MONETARY-POW-SMOKE-PROFILE-V1\0");
    profile_bytes.extend_from_slice(profile.profile_id());
    profile_bytes.extend_from_slice(profile.consensus_digest());
    profile_bytes.extend_from_slice(&params.protocol_version.to_be_bytes());
    profile_bytes.extend_from_slice(&params.initial_target.to_be_bytes());
    profile_bytes.extend_from_slice(&params.pow_limit.to_be_bytes());
    profile_bytes.extend_from_slice(&params.pow.memory_kib.to_be_bytes());
    profile_bytes.extend_from_slice(&params.pow.iterations.to_be_bytes());
    profile_bytes.extend_from_slice(&params.pow.lanes.to_be_bytes());
    profile_bytes.push(params.pow.output_bytes);
    let profile_digest: [u8; 32] = Sha256::digest(&profile_bytes).into();

    let mut canonical = Vec::with_capacity(160);
    canonical.extend_from_slice(MANIFEST_ID_DOMAIN);
    canonical.extend_from_slice(profile.network_id());
    canonical.extend_from_slice(profile.profile_id());
    canonical.extend_from_slice(profile.consensus_digest());
    canonical.extend_from_slice(&profile_digest);
    Ok(Sha256::digest(&canonical).into())
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let mut network = None;
    let mut out_dir = None;
    let mut index = 0usize;
    while index < args.len() {
        if index + 1 >= args.len() {
            return Err(format!("missing value for {}", args[index]));
        }
        match args[index].as_str() {
            "--network-id" => network = Some(parse_hex32(&args[index + 1], "--network-id")?),
            "--out-dir" => out_dir = Some(PathBuf::from(&args[index + 1])),
            flag => return Err(format!("unknown option {flag}")),
        }
        index += 2;
    }
    let network = network.ok_or("--network-id is required")?;
    let out_dir = out_dir.ok_or("--out-dir is required")?;
    fs::create_dir_all(&out_dir).map_err(|error| format!("create output directory: {error}"))?;
    let manifest_id = test_manifest_id(network)?;

    // Compiled-in keys are deterministic disposable fixture material only.
    let ed_signer = SigningKey::from_bytes(&[0x31; 32]);
    let pq_pair = portable::generate_key_pair([0x42; 32]);
    let ed_public_key = ed_signer.verifying_key().to_bytes();
    let mldsa65_public_key: [u8; ML_DSA_65_PUBLIC_KEY_BYTES] = *pq_pair.verification_key.as_ref();
    let sender = native_v4_account_id(&ed_public_key, &mldsa65_public_key);
    let recipient = [0xCC; 32];
    if sender == recipient || recipient.iter().all(|byte| *byte == 0) {
        return Err("fixture sender/recipient must be distinct and nonzero".into());
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock predates Unix epoch")?
        .as_secs();
    let authorization = V4HybridAuthorization {
        network_id: network,
        manifest_id,
        sender_id: sender,
        recipient_id: recipient,
        nonce: 1,
        amount_atoms: 1_000,
        fee_atoms: 17,
        expires_at: now.saturating_add(3_600),
        identity_scheme: AccountIdentityScheme::NativeV4Hybrid,
        ed25519_public_key: ed_public_key,
        mldsa65_public_key,
    };
    let digest = authorization
        .signing_digest()
        .map_err(|error| format!("TXN4 signing digest: {error:?}"))?;
    let pq_signature = portable::sign(&pq_pair.signing_key, &digest, &[], [0x53; 32])
        .map_err(|error| format!("ML-DSA-65 test signing: {error:?}"))?;
    let transaction = V4HybridTransaction {
        authorization,
        signature: V4HybridSignature {
            ed25519_signature: ed_signer.sign(&digest).to_bytes(),
            mldsa65_signature: *pq_signature.as_ref(),
        },
    };
    transaction
        .verify(&LibcruxMlDsa65VerifierCandidate)
        .map_err(|error| format!("self-verify signed TXN4 fixture: {error:?}"))?;
    let wire = transaction
        .encode()
        .map_err(|error| format!("encode TXN4 fixture: {error:?}"))?;

    let transaction_path = out_dir.join("transaction.txn4");
    let founder_mldsa_path = out_dir.join("founder-mldsa65.pub");
    fs::write(&transaction_path, &wire).map_err(|error| format!("write TXN4 fixture: {error}"))?;
    fs::write(&founder_mldsa_path, mldsa65_public_key)
        .map_err(|error| format!("write founder public key fixture: {error}"))?;
    println!("fixture_only=true private_keys_written=false");
    println!("network_id={}", hex(&network));
    println!("manifest_id={}", hex(&manifest_id));
    println!("founder_ed25519_public_key_hex={}", hex(&ed_public_key));
    println!(
        "founder_mldsa65_public_key_file={}",
        founder_mldsa_path.display()
    );
    println!("sender_id={}", hex(&sender));
    println!("recipient_id={}", hex(&recipient));
    let mut txid_hash = Sha256::new();
    txid_hash.update(b"AIN1-V4-MEMPOOL-TX-ID-V1\0");
    txid_hash.update(&wire);
    let txid: [u8; 32] = txid_hash.finalize().into();
    println!("txid={}", hex(&txid));
    println!("transaction_file={}", transaction_path.display());
    println!("transaction_bytes={}", wire.len());
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("txn4_loopback_fixture: {error}");
        std::process::exit(2);
    }
}
