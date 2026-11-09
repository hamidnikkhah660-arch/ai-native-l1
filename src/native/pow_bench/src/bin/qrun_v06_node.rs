//! QFP6 bootstrap preflight executable.
//!
//! This binary verifies externally supplied Q6PN/Q6TS bootstrap material without opening a
//! QFP6 data directory, mutating the QFP6 store/trust floor, binding a node P2P listener, or
//! starting consensus/mining services. The read-only AWS CLI floor lookup uses network access.
//! It is intentionally preflight-only until the production QAP1/Provider/Anchor/runtime wiring
//! and independent deployment qualifications are complete.
use ai_native_l1_pow_bench::{
    qrun_v06_profile_pin_candidate::QRunV06VerifiedProfilePin,
    qrun_v06_profile_trust_candidate::{
        verify_qrun_v06_profile_trust_envelope, MonotonicQRunV06ProfileTrustFloorStore,
        PinnedQRunV06ProfileTrustAuthority, QRunV06ProfileTrustFloorDecision,
        QRunV06ProfileTrustStatus, QRunV06SignedProfileTrustEnvelope,
    },
    qrun_v06_profile_trust_dynamodb_floor_candidate::AwsDynamoDbQ6tsProfileTrustFloorStore,
    v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate,
    v4_fat1_trust_candidate::ML_DSA_65_PUBLIC_KEY_BYTES,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::ExitCode,
};

const MAX_CONFIG_BYTES: u64 = 64 * 1024;
const MAX_BOOTSTRAP_BYTES: u64 = 16 * 1024;

#[derive(Debug)]
struct Config {
    network_id: [u8; 32],
    profile_id: [u8; 32],
    profile_pin_commitment: [u8; 32],
    founder_account: [u8; 32],
    consensus_fingerprint: [u8; 32],
    tokenomics_policy_fingerprint: [u8; 32],
    profile_pin_path: PathBuf,
    trust_envelope_path: PathBuf,
    authority_ed25519_path: PathBuf,
    authority_mldsa65_path: PathBuf,
    authority_keyset_id: [u8; 32],
    aws_cli_path: PathBuf,
    aws_region: String,
    trust_floor_table: String,
}

#[derive(Debug)]
struct PreflightSummary {
    network_id: [u8; 32],
    profile_id: [u8; 32],
    genesis_commitment: [u8; 32],
    trust_epoch: u64,
    has_quote_asset_pin: bool,
    provider_id: [u8; 32],
}

fn parse_hex32(name: &str, value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.is_ascii() || value.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(format!(
            "{name} must be exactly 64 lowercase hexadecimal characters"
        ));
    }
    let mut output = [0u8; 32];
    for (index, slot) in output.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| format!("{name} contains non-hexadecimal characters"))?;
    }
    if output == [0; 32] {
        return Err(format!("{name} must not be zero"));
    }
    Ok(output)
}

fn verify_config_digest(bytes: &[u8], expected: &[u8; 32]) -> Result<(), String> {
    let actual: [u8; 32] = Sha256::digest(bytes).into();
    if &actual != expected {
        return Err(
            "bootstrap config SHA-256 does not match the digest supplied out of band".into(),
        );
    }
    Ok(())
}

fn required_string<'a>(value: &'a Value, name: &str) -> Result<&'a str, String> {
    value
        .get(name)
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty())
        .ok_or_else(|| format!("config field '{name}' is required and must be a non-empty string"))
}

fn resolve_path(base: &Path, value: &str) -> PathBuf {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        path
    } else {
        base.join(path)
    }
}

fn resolve_executable(base: &Path, value: &str) -> PathBuf {
    let path = PathBuf::from(value);
    if path.is_absolute() || value.contains('/') || value.contains('\\') {
        resolve_path(base, value)
    } else {
        // A bare executable name is resolved by the OS PATH lookup (e.g. `aws` or `aws.exe`).
        path
    }
}

fn read_bounded(path: &Path, max_bytes: u64, label: &str) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {label} '{}': {error}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(format!(
            "{label} '{}' must be a regular file (symlinks are refused)",
            path.display()
        ));
    }
    if metadata.len() == 0 || metadata.len() > max_bytes {
        return Err(format!(
            "{label} '{}' has invalid size {} (allowed 1..={max_bytes} bytes)",
            path.display(),
            metadata.len()
        ));
    }
    let bytes = fs::read(path)
        .map_err(|error| format!("cannot read {label} '{}': {error}", path.display()))?;
    if bytes.len() as u64 != metadata.len() {
        return Err(format!(
            "{label} '{}' changed while being read",
            path.display()
        ));
    }
    Ok(bytes)
}

fn parse_config(
    path: &Path,
    independently_pinned_config_digest: &[u8; 32],
) -> Result<Config, String> {
    let bytes = read_bounded(path, MAX_CONFIG_BYTES, "config")?;
    verify_config_digest(&bytes, independently_pinned_config_digest)?;
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|error| format!("invalid JSON config: {error}"))?;
    let base = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    let path_field = |name: &str| -> Result<PathBuf, String> {
        Ok(resolve_path(base, required_string(&value, name)?))
    };

    Ok(Config {
        network_id: parse_hex32("network_id", required_string(&value, "network_id")?)?,
        profile_id: parse_hex32("profile_id", required_string(&value, "profile_id")?)?,
        profile_pin_commitment: parse_hex32(
            "profile_pin_commitment",
            required_string(&value, "profile_pin_commitment")?,
        )?,
        founder_account: parse_hex32(
            "founder_account",
            required_string(&value, "founder_account")?,
        )?,
        consensus_fingerprint: parse_hex32(
            "consensus_fingerprint",
            required_string(&value, "consensus_fingerprint")?,
        )?,
        tokenomics_policy_fingerprint: parse_hex32(
            "tokenomics_policy_fingerprint",
            required_string(&value, "tokenomics_policy_fingerprint")?,
        )?,
        profile_pin_path: path_field("q6pn_path")?,
        trust_envelope_path: path_field("q6ts_path")?,
        authority_ed25519_path: path_field("q6ts_ed25519_authority_public_key_path")?,
        authority_mldsa65_path: path_field("q6ts_mldsa65_authority_public_key_path")?,
        authority_keyset_id: parse_hex32(
            "q6ts_authority_keyset_id",
            required_string(&value, "q6ts_authority_keyset_id")?,
        )?,
        aws_cli_path: resolve_executable(base, required_string(&value, "aws_cli_path")?),
        aws_region: required_string(&value, "aws_region")?.to_owned(),
        trust_floor_table: required_string(&value, "q6ts_floor_table")?.to_owned(),
    })
}

fn preflight(
    config_path: &Path,
    independently_pinned_config_digest: &[u8; 32],
) -> Result<PreflightSummary, String> {
    let config = parse_config(config_path, independently_pinned_config_digest)?;

    let profile_pin_bytes = read_bounded(
        &config.profile_pin_path,
        MAX_BOOTSTRAP_BYTES,
        "Q6PN profile pin",
    )?;
    let trust_envelope_bytes = read_bounded(
        &config.trust_envelope_path,
        MAX_BOOTSTRAP_BYTES,
        "Q6TS signed trust envelope",
    )?;
    let ed25519_bytes = read_bounded(
        &config.authority_ed25519_path,
        32,
        "Q6TS Ed25519 authority public key",
    )?;
    let mldsa65_bytes = read_bounded(
        &config.authority_mldsa65_path,
        ML_DSA_65_PUBLIC_KEY_BYTES as u64,
        "Q6TS ML-DSA-65 authority public key",
    )?;
    if ed25519_bytes.len() != 32 {
        return Err("Q6TS Ed25519 authority public key must be exactly 32 bytes".into());
    }
    if mldsa65_bytes.len() != ML_DSA_65_PUBLIC_KEY_BYTES {
        return Err(format!(
            "Q6TS ML-DSA-65 authority public key must be exactly {ML_DSA_65_PUBLIC_KEY_BYTES} bytes"
        ));
    }

    // The Q6PN commitment is supplied separately in the deployment config. It is never
    // calculated from the colocated Q6PN file, so a modified file cannot self-authorize.
    let profile_pin =
        QRunV06VerifiedProfilePin::decode(&profile_pin_bytes, config.profile_pin_commitment)
            .map_err(|error| format!("Q6PN independently pinned decode failed: {error}"))?;
    let descriptor = profile_pin.descriptor();
    if descriptor.network_id() != config.network_id
        || descriptor.profile_id() != config.profile_id
        || descriptor.founder_account() != config.founder_account
        || descriptor.consensus_fingerprint() != config.consensus_fingerprint
        || descriptor.tokenomics_policy_fingerprint() != config.tokenomics_policy_fingerprint
    {
        return Err("Q6GD Genesis descriptor does not match the independently supplied network/profile/founder/consensus/tokenomics identity".into());
    }

    let envelope = QRunV06SignedProfileTrustEnvelope::decode(&trust_envelope_bytes)
        .map_err(|error| format!("Q6TS signed envelope decode failed: {error}"))?;
    if envelope.record.status != QRunV06ProfileTrustStatus::Active {
        return Err("Q6TS profile is revoked; startup is refused".into());
    }
    if envelope.record.network_id != config.network_id
        || envelope.record.profile_id != config.profile_id
        || envelope.record.profile_pin_commitment != config.profile_pin_commitment
    {
        return Err(
            "Q6TS envelope does not authorize the exact configured network/profile/Q6PN commitment"
                .into(),
        );
    }

    let authority = PinnedQRunV06ProfileTrustAuthority {
        ed25519_public_key: ed25519_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "invalid Ed25519 authority key length")?,
        mldsa65_public_key: mldsa65_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "invalid ML-DSA-65 authority key length")?,
    };

    // Read only. Startup never provisions or advances this floor from the Q6TS envelope.
    let floor_store = AwsDynamoDbQ6tsProfileTrustFloorStore::new(
        &config.aws_cli_path,
        &config.aws_region,
        &config.trust_floor_table,
    )
    .map_err(|error| format!("Q6TS independent floor adapter configuration failed: {error}"))?;
    let actual_keyset_id = authority
        .keyset_id()
        .map_err(|error| format!("Q6TS authority keyset is invalid: {error}"))?;
    if actual_keyset_id != config.authority_keyset_id {
        return Err("Q6TS authority keyset differs from the independently pinned keyset ID".into());
    }

    let floor = floor_store
        .load(&config.network_id, &config.profile_id)
        .map_err(|error| format!("Q6TS independent monotonic floor unavailable: {error}"))?;
    let verified = verify_qrun_v06_profile_trust_envelope(
        &envelope,
        &authority,
        &LibcruxMlDsa65VerifierCandidate,
        &floor,
    )
    .map_err(|error| format!("Q6TS signature/floor verification failed: {error}"))?;
    if verified.decision() != QRunV06ProfileTrustFloorDecision::AlreadyPinnedCurrent {
        return Err("Q6TS envelope is not the exact current head in the independent floor; a control-plane CAS/publish cycle is required before node startup".into());
    }

    Ok(PreflightSummary {
        network_id: config.network_id,
        profile_id: config.profile_id,
        genesis_commitment: descriptor.commitment(),
        trust_epoch: envelope.record.trust_epoch,
        has_quote_asset_pin: profile_pin.quote_asset_trust_pin().is_some(),
        provider_id: profile_pin.bundle().external_cas_pin().provider_id,
    })
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(DIGITS[(byte >> 4) as usize] as char);
        result.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    result
}

fn print_help() {
    println!(
        "QRun QFP6 bootstrap preflight\n\
         \n\
         Usage:\n\
           qrun_v06_node --preflight --config <path> --config-sha256 <64-hex>\n\
           qrun_v06_node --help\n\
         \n\
         This build verifies Q6GD/Q6PN/Q6TS and the independent AWS DynamoDB Q6TS floor.\n\
         It is preflight-only: it does not open a QFP6 data directory, bind P2P, or start a node."
    );
}

fn run(args: &[String]) -> Result<(), String> {
    if args == ["--help"] {
        print_help();
        return Ok(());
    }
    if args.iter().any(|arg| arg == "--run") {
        return Err("node runtime is not enabled in this build: QAP1/Provider/Anchor, node-key custody, durable-store recovery and independent production qualification must be wired and verified first".into());
    }
    if args.len() != 5
        || args[0] != "--preflight"
        || args[1] != "--config"
        || args[3] != "--config-sha256"
    {
        return Err(
            "expected '--preflight --config <path> --config-sha256 <64-hex>' (or '--help')".into(),
        );
    }
    let expected_config_digest = parse_hex32("config_sha256", &args[4])?;
    let summary = preflight(Path::new(&args[2]), &expected_config_digest)?;
    println!("QFP6 BOOTSTRAP PREFLIGHT: PASS");
    println!("config_sha256={}", hex(&expected_config_digest));
    println!("network_id={}", hex(&summary.network_id));
    println!("profile_id={}", hex(&summary.profile_id));
    println!(
        "genesis_descriptor_commitment={}",
        hex(&summary.genesis_commitment)
    );
    println!("provider_id={}", hex(&summary.provider_id));
    println!("q6ts_trust_epoch={}", summary.trust_epoch);
    println!(
        "q6qa_quote_asset_pin={}",
        if summary.has_quote_asset_pin {
            "present"
        } else {
            "absent (native chain only; quote-asset operations remain gated)"
        }
    );
    println!("runtime=NOT_STARTED");
    println!("node_p2p_listener=NOT_OPENED");
    println!("qfp6_data_directory=NOT_TOUCHED");
    println!("qfp6_store=NOT_MUTATED");
    println!("anti_rollback_floor=independent DynamoDB strongly-consistent read; no writes");
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("QFP6 PREFLIGHT REFUSED: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ai_native_l1_pow_bench::qrun_v06_profile_trust_candidate::{
        QRunV06ProfileTrustRecord, TrustedQRunV06ProfileTrustFloor,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use libcrux_ml_dsa::ml_dsa_65::portable;

    const TEST_NETWORK: [u8; 32] = [0xA1; 32];
    const TEST_PROFILE: [u8; 32] = [0xA2; 32];
    const TEST_Q6PN_COMMITMENT: [u8; 32] = [0xA3; 32];

    #[test]
    fn q6ts_real_dual_signatures_verify_against_exact_current_floor() {
        let ed_signing_key = SigningKey::from_bytes(&[0x51; 32]);
        let mldsa_key_pair = portable::generate_key_pair([0x52; 32]);
        let authority = PinnedQRunV06ProfileTrustAuthority {
            ed25519_public_key: ed_signing_key.verifying_key().to_bytes(),
            mldsa65_public_key: *mldsa_key_pair.verification_key.as_ref(),
        };
        let record = QRunV06ProfileTrustRecord {
            trust_epoch: 1,
            status: QRunV06ProfileTrustStatus::Active,
            network_id: TEST_NETWORK,
            profile_id: TEST_PROFILE,
            profile_pin_commitment: TEST_Q6PN_COMMITMENT,
            previous_record_id: [0; 32],
        };
        let digest = record
            .signing_digest(&authority.keyset_id().unwrap())
            .unwrap();
        let ed25519_signature = ed_signing_key.sign(&digest).to_bytes();
        let mldsa65_signature =
            portable::sign(&mldsa_key_pair.signing_key, &digest, &[], [0x53; 32]).unwrap();
        let envelope = QRunV06SignedProfileTrustEnvelope {
            record: record.clone(),
            authority_keyset_id: authority.keyset_id().unwrap(),
            ed25519_signature,
            mldsa65_signature: *mldsa65_signature.as_ref(),
        };
        let floor = TrustedQRunV06ProfileTrustFloor::provisioned(
            TEST_NETWORK,
            TEST_PROFILE,
            1,
            QRunV06ProfileTrustStatus::Active,
            record.record_id().unwrap(),
            envelope.envelope_id().unwrap(),
        )
        .unwrap();

        let encoded = envelope.encode().unwrap();
        let decoded = QRunV06SignedProfileTrustEnvelope::decode(&encoded).unwrap();
        let verified = verify_qrun_v06_profile_trust_envelope(
            &decoded,
            &authority,
            &LibcruxMlDsa65VerifierCandidate,
            &floor,
        )
        .unwrap();
        assert_eq!(
            verified.decision(),
            QRunV06ProfileTrustFloorDecision::AlreadyPinnedCurrent
        );

        let mut altered = decoded;
        altered.ed25519_signature[0] ^= 1;
        assert!(verify_qrun_v06_profile_trust_envelope(
            &altered,
            &authority,
            &LibcruxMlDsa65VerifierCandidate,
            &floor,
        )
        .is_err());
    }

    #[test]
    fn help_is_available_without_loading_any_artifact() {
        assert!(run(&["--help".into()]).is_ok());
    }

    #[test]
    fn runtime_mode_is_explicitly_fail_closed() {
        let error = run(&["--run".into()]).unwrap_err();
        assert!(error.contains("node runtime is not enabled"));
    }

    #[test]
    fn bare_aws_binary_uses_path_lookup_and_explicit_paths_are_config_relative() {
        let base = Path::new("C:/qrun/config");
        assert_eq!(resolve_executable(base, "aws"), PathBuf::from("aws"));
        assert_eq!(
            resolve_executable(base, "tools/aws.exe"),
            PathBuf::from("C:/qrun/config/tools/aws.exe")
        );
        assert_eq!(
            resolve_executable(base, "C:/AWS/aws.exe"),
            PathBuf::from("C:/AWS/aws.exe")
        );
    }

    #[test]
    fn independently_pinned_config_digest_accepts_exact_bytes_and_rejects_tampering() {
        let original = br#"{"network_id":"a"}"#;
        let expected: [u8; 32] = Sha256::digest(original).into();
        assert!(verify_config_digest(original, &expected).is_ok());
        assert!(verify_config_digest(br#"{"network_id":"b"}"#, &expected).is_err());
    }

    #[test]
    fn malformed_or_zero_identity_values_are_rejected() {
        assert!(parse_hex32("network_id", &"00".repeat(32)).is_err());
        assert!(parse_hex32("network_id", &"AA".repeat(32)).is_err());
        assert!(parse_hex32("network_id", &"0g".repeat(32)).is_err());
        assert_eq!(
            parse_hex32("network_id", &"ab".repeat(32)).unwrap(),
            [0xab; 32]
        );
    }

    #[test]
    fn wrong_invocation_is_rejected() {
        assert!(run(&[]).is_err());
        assert!(run(&["--preflight".into()]).is_err());
        assert!(run(&["--unknown".into()]).is_err());
    }

    #[test]
    fn missing_config_is_rejected_without_creating_anything() {
        let path = env::temp_dir().join(format!(
            "qrun-qfp6-missing-config-{}-{}.json",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = fs::remove_file(&path);
        assert!(preflight(&path, &[0x01; 32]).is_err());
        assert!(!path.exists());
    }
}
