//! QFP6 bootstrap preflight executable.
//!
//! This binary verifies externally supplied Q6PN/Q6TS bootstrap material without opening a
//! QFP6 data directory, mutating the QFP6 store/trust floor, binding a node P2P listener, or
//! starting consensus/mining services. The read-only AWS CLI floor lookup uses network access.
//! It is intentionally preflight-only until the production QAP1/Provider/Anchor/runtime wiring
//! and independent deployment qualifications are complete.
use ai_native_l1_pow_bench::{
    external_cas_anchor_candidate::ExternalCasPin,
    external_cas_floor_store_candidate::ExternalCasFloorStore,
    external_cas_noise_transport_candidate::NoiseTcpExternalCasProviderTransport,
    external_cas_offhost_anchor_noise_transport_candidate::NoiseTcpOffhostAnchorTransport,
    external_cas_offhost_anchor_protocol_candidate::ExternalCasOffhostAnchorPin,
    noise_key_provisioning::load_protected_noise_private_key,
    qrun_v06_canonical_execution_candidate::QRunV06CanonicalExecutionState,
    qrun_v06_consensus_profile_candidate::{
        QRunV06ConsensusProfile, QRUN_V06_CONSENSUS_PROFILE_MAX_BYTES,
    },
    qrun_v06_external_anchor_candidate::{QRunV06ExternalAnchorPin, QRunV06ExternalAnchorState},
    qrun_v06_profile_pin_candidate::QRunV06VerifiedProfilePin,
    qrun_v06_profile_trust_candidate::{
        verify_qrun_v06_profile_trust_envelope, MonotonicQRunV06ProfileTrustFloorStore,
        PinnedQRunV06ProfileTrustAuthority, QRunV06ProfileTrustFloorDecision,
        QRunV06ProfileTrustStatus, QRunV06SignedProfileTrustEnvelope,
    },
    qrun_v06_profile_trust_dynamodb_floor_candidate::AwsDynamoDbQ6tsProfileTrustFloorStore,
    qrun_v06_qap1_coordinator_candidate::QRunV06Qap1ExternalCoordinator,
    qrun_v06_tokenomics_candidate::QRUN_V06_FOUNDER_GENESIS_ATOMS,
    v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate,
    v4_fat1_trust_candidate::ML_DSA_65_PUBLIC_KEY_BYTES,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::ExitCode,
};

const MAX_CONFIG_BYTES: u64 = 64 * 1024;
const MAX_BOOTSTRAP_BYTES: u64 = 16 * 1024;
const MAX_GENESIS_SNAPSHOT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_CONSENSUS_PROFILE_BYTES: u64 = QRUN_V06_CONSENSUS_PROFILE_MAX_BYTES as u64;

#[derive(Debug)]
struct Config {
    network_id: [u8; 32],
    profile_id: [u8; 32],
    profile_pin_commitment: [u8; 32],
    founder_account: [u8; 32],
    consensus_fingerprint: [u8; 32],
    consensus_profile_path: PathBuf,
    consensus_profile_sha256: [u8; 32],
    tokenomics_policy_fingerprint: [u8; 32],
    genesis_snapshot_sha256: [u8; 32],
    genesis_snapshot_path: PathBuf,
    profile_pin_path: PathBuf,
    trust_envelope_path: PathBuf,
    authority_ed25519_path: PathBuf,
    authority_mldsa65_path: PathBuf,
    authority_keyset_id: [u8; 32],
    aws_cli_path: PathBuf,
    aws_region: String,
    trust_floor_table: String,
    q6ea_anchor_id: [u8; 32],
    q6ea_receipt_key_id: [u8; 32],
    q6ea_receipt_public_key_path: PathBuf,
    provider_noise_server_key_path: PathBuf,
    provider_noise_server_key_sha256: [u8; 32],
    q6ea_anchor_noise_server_key_path: PathBuf,
    q6ea_anchor_noise_server_key_sha256: [u8; 32],
    provider_endpoint: SocketAddr,
    q6ea_anchor_endpoint: SocketAddr,
    provider_noise_client_key_path: Option<PathBuf>,
    q6ea_anchor_noise_client_key_path: Option<PathBuf>,
    provider_floor_store_path: Option<PathBuf>,
    q6ea_expected_state_path: Option<PathBuf>,
    q6ea_expected_state_sha256: Option<[u8; 32]>,
}

#[derive(Debug)]
struct PreflightSummary {
    network_id: [u8; 32],
    profile_id: [u8; 32],
    genesis_commitment: [u8; 32],
    genesis_state_root: [u8; 32],
    genesis_snapshot_sha256: [u8; 32],
    consensus_profile_sha256: [u8; 32],
    consensus_fingerprint: [u8; 32],
    consensus_protocol_version: u16,
    target_block_time_secs: u64,
    difficulty_window_blocks: u64,
    initial_target: [u8; 32],
    pow_limit: [u8; 32],
    pow_memory_kib: u32,
    pow_iterations: u32,
    pow_lanes: u32,
    issuance_maximum_supply_atoms: u128,
    issuance_initial_subsidy_atoms: u128,
    issuance_blocks_per_halving: u64,
    founder_genesis_atoms: u128,
    q6ea_anchor_id: [u8; 32],
    provider_noise_server_key_sha256: [u8; 32],
    q6ea_anchor_noise_server_key_sha256: [u8; 32],
    provider_endpoint: SocketAddr,
    q6ea_anchor_endpoint: SocketAddr,
    trust_epoch: u64,
    has_quote_asset_pin: bool,
    provider_id: [u8; 32],
    provider_pin: ExternalCasPin,
    q6ea_anchor_pin: ExternalCasOffhostAnchorPin,
    provider_noise_server_public_key: [u8; 32],
    q6ea_anchor_noise_server_public_key: [u8; 32],
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

fn is_windows_absolute_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    (bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\'))
        || value.starts_with("\\\\")
}

fn parse_service_endpoint(name: &str, value: &str) -> Result<SocketAddr, String> {
    let address: SocketAddr = value
        .parse()
        .map_err(|_| format!("{name} must be a numeric SocketAddr; DNS names are not accepted"))?;
    if address.port() == 0 || address.ip().is_unspecified() || address.ip().is_multicast() {
        return Err(format!(
            "{name} must use a nonzero port and a unicast, specified IP address"
        ));
    }
    Ok(address)
}

fn read_pinned_noise_server_key(
    path: &Path,
    expected_sha256: &[u8; 32],
    label: &str,
) -> Result<[u8; 32], String> {
    let bytes = read_bounded(path, 32, label)?;
    if bytes.len() != 32 {
        return Err(format!("{label} must be exactly 32 bytes"));
    }
    let actual_sha256: [u8; 32] = Sha256::digest(&bytes).into();
    if &actual_sha256 != expected_sha256 {
        return Err(format!(
            "{label} SHA-256 differs from the independently pinned config digest"
        ));
    }
    let key: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("{label} has an invalid length"))?;
    if key == [0; 32] {
        return Err(format!("{label} must not be zero"));
    }
    Ok(key)
}

fn validate_distinct_qap1_endpoints(
    provider: SocketAddr,
    anchor: SocketAddr,
) -> Result<(), String> {
    if provider == anchor {
        return Err("Provider and Q6EA Anchor endpoints must be distinct".into());
    }
    Ok(())
}

fn resolve_executable(base: &Path, value: &str) -> PathBuf {
    let path = PathBuf::from(value);
    if path.is_absolute() || is_windows_absolute_path(value) {
        path
    } else if value.contains('/') || value.contains('\\') {
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
    let optional_path_field = |name: &str| -> Result<Option<PathBuf>, String> {
        match value.get(name) {
            None => Ok(None),
            Some(_) => Ok(Some(resolve_path(base, required_string(&value, name)?))),
        }
    };
    let optional_digest_field = |name: &str| -> Result<Option<[u8; 32]>, String> {
        match value.get(name) {
            None => Ok(None),
            Some(_) => Ok(Some(parse_hex32(name, required_string(&value, name)?)?)),
        }
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
        consensus_profile_path: path_field("consensus_profile_path")?,
        consensus_profile_sha256: parse_hex32(
            "consensus_profile_sha256",
            required_string(&value, "consensus_profile_sha256")?,
        )?,
        tokenomics_policy_fingerprint: parse_hex32(
            "tokenomics_policy_fingerprint",
            required_string(&value, "tokenomics_policy_fingerprint")?,
        )?,
        genesis_snapshot_sha256: parse_hex32(
            "genesis_snapshot_sha256",
            required_string(&value, "genesis_snapshot_sha256")?,
        )?,
        genesis_snapshot_path: path_field("genesis_snapshot_path")?,
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
        q6ea_anchor_id: parse_hex32("q6ea_anchor_id", required_string(&value, "q6ea_anchor_id")?)?,
        q6ea_receipt_key_id: parse_hex32(
            "q6ea_receipt_key_id",
            required_string(&value, "q6ea_receipt_key_id")?,
        )?,
        q6ea_receipt_public_key_path: path_field("q6ea_receipt_public_key_path")?,
        provider_noise_server_key_path: path_field("provider_noise_server_key_path")?,
        provider_noise_server_key_sha256: parse_hex32(
            "provider_noise_server_key_sha256",
            required_string(&value, "provider_noise_server_key_sha256")?,
        )?,
        q6ea_anchor_noise_server_key_path: path_field("q6ea_anchor_noise_server_key_path")?,
        q6ea_anchor_noise_server_key_sha256: parse_hex32(
            "q6ea_anchor_noise_server_key_sha256",
            required_string(&value, "q6ea_anchor_noise_server_key_sha256")?,
        )?,
        provider_endpoint: parse_service_endpoint(
            "provider_endpoint",
            required_string(&value, "provider_endpoint")?,
        )?,
        q6ea_anchor_endpoint: parse_service_endpoint(
            "q6ea_anchor_endpoint",
            required_string(&value, "q6ea_anchor_endpoint")?,
        )?,
        provider_noise_client_key_path: optional_path_field("provider_noise_client_key_path")?,
        q6ea_anchor_noise_client_key_path: optional_path_field(
            "q6ea_anchor_noise_client_key_path",
        )?,
        provider_floor_store_path: optional_path_field("provider_floor_store_path")?,
        q6ea_expected_state_path: optional_path_field("q6ea_expected_state_path")?,
        q6ea_expected_state_sha256: optional_digest_field("q6ea_expected_state_sha256")?,
    })
}

fn verify_genesis_snapshot(
    bytes: &[u8],
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
    founder_account: &[u8; 32],
    consensus_fingerprint: &[u8; 32],
    tokenomics_policy_fingerprint: &[u8; 32],
    expected_descriptor: &ai_native_l1_pow_bench::qrun_v06_genesis_descriptor_candidate::QRunV06GenesisDescriptor,
) -> Result<([u8; 32], u128), String> {
    let state = QRunV06CanonicalExecutionState::decode_snapshot(bytes, network_id, profile_id)
        .map_err(|error| format!("full QFP6 Genesis execution snapshot is invalid: {error:?}"))?;
    state
        .verify_invariants()
        .map_err(|error| format!("QFP6 Genesis execution invariants failed: {error:?}"))?;
    if state.height() != 0 {
        return Err("configured Genesis execution snapshot must be at height zero".into());
    }
    let descriptor = state.genesis_descriptor().ok_or_else(|| {
        "full Genesis snapshot is missing its immutable Q6GD descriptor".to_string()
    })?;
    if descriptor != expected_descriptor
        || descriptor.founder_account() != *founder_account
        || descriptor.consensus_fingerprint() != *consensus_fingerprint
        || descriptor.tokenomics_policy_fingerprint() != *tokenomics_policy_fingerprint
        || state.last_timestamp() != descriptor.genesis_timestamp()
    {
        return Err("full Q6GD descriptor/timestamp differs from the independently pinned Q6PN profile identity".into());
    }
    let tokenomics = state
        .tokenomics()
        .ok_or_else(|| "full Genesis snapshot is missing CP-0528 tokenomics state".to_string())?;
    if tokenomics.founder_account() != *founder_account
        || tokenomics.policy_fingerprint() != *tokenomics_policy_fingerprint
    {
        return Err(
            "full Genesis CP-0528 policy or Founder binding differs from the pinned identity"
                .into(),
        );
    }
    let founder_balance = state
        .unified()
        .ledger()
        .account(founder_account)
        .map_or(0u128, |account| account.balance as u128);
    if founder_balance != QRUN_V06_FOUNDER_GENESIS_ATOMS {
        return Err(format!(
            "Genesis Founder allocation must be exactly {} atoms; found {founder_balance}",
            QRUN_V06_FOUNDER_GENESIS_ATOMS
        ));
    }
    // verify_invariants binds Ledger total value to the CP-0528 live-supply counters. Since the
    // only live Genesis issuance is the exact Founder allocation checked above, there is no
    // remaining spendable supply available to another account.
    let state_root = state
        .state_root()
        .map_err(|error| format!("QFP6 Genesis state-root verification failed: {error:?}"))?;
    Ok((state_root, founder_balance))
}

fn load_pinned_q6cp_profile(
    path: &Path,
    independently_pinned_sha256: &[u8; 32],
    expected_descriptor: &ai_native_l1_pow_bench::qrun_v06_genesis_descriptor_candidate::QRunV06GenesisDescriptor,
) -> Result<([u8; 32], QRunV06ConsensusProfile), String> {
    let bytes = read_bounded(
        path,
        MAX_CONSENSUS_PROFILE_BYTES,
        "Q6CP full consensus-parameters artifact",
    )?;
    let actual_sha256: [u8; 32] = Sha256::digest(&bytes).into();
    if &actual_sha256 != independently_pinned_sha256 {
        return Err(
            "Q6CP consensus-parameters SHA-256 differs from the independently pinned config digest"
                .into(),
        );
    }
    let profile = QRunV06ConsensusProfile::decode(&bytes)
        .map_err(|error| format!("Q6CP canonical consensus profile decode failed: {error:?}"))?;
    profile
        .validate_against(expected_descriptor)
        .map_err(|error| {
            format!("Q6CP identity/fingerprint does not match Q6GD/Q6PN: {error:?}")
        })?;
    Ok((actual_sha256, profile))
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

    // Decode the complete fixed-width Q6CP artifact, verify its out-of-band file hash and
    // recompute every consensus parameter against the immutable Q6GD descriptor.
    let (actual_consensus_profile_sha256, consensus_profile) = load_pinned_q6cp_profile(
        &config.consensus_profile_path,
        &config.consensus_profile_sha256,
        descriptor,
    )?;
    if consensus_profile.network_id() != config.network_id
        || consensus_profile.profile_id() != config.profile_id
        || consensus_profile.consensus_fingerprint() != config.consensus_fingerprint
    {
        return Err("Q6CP network/profile/fingerprint differs from the independently supplied bootstrap identity".into());
    }
    let consensus_params = consensus_profile.parameters();

    // Validate the complete canonical Genesis state, not merely its descriptor. The external
    // SHA-256 binds every nested ledger/AMM/registry/orderbook/tokenomics byte to the pinned config.
    let genesis_snapshot_bytes = read_bounded(
        &config.genesis_snapshot_path,
        MAX_GENESIS_SNAPSHOT_BYTES,
        "full QFP6 Genesis execution snapshot",
    )?;
    let actual_genesis_snapshot_sha256: [u8; 32] = Sha256::digest(&genesis_snapshot_bytes).into();
    if actual_genesis_snapshot_sha256 != config.genesis_snapshot_sha256 {
        return Err("full QFP6 Genesis snapshot SHA-256 differs from the independently pinned config digest".into());
    }
    let (genesis_state_root, founder_genesis_atoms) = verify_genesis_snapshot(
        &genesis_snapshot_bytes,
        &config.network_id,
        &config.profile_id,
        &config.founder_account,
        &config.consensus_fingerprint,
        &config.tokenomics_policy_fingerprint,
        descriptor,
    )?;

    // Q6EA must have its own receipt key and endpoint. Its pin is bound to the exact Provider,
    // network and genesis domain embedded in Q6PN; it is never inferred from the local Node.
    validate_distinct_qap1_endpoints(config.provider_endpoint, config.q6ea_anchor_endpoint)?;
    let q6ea_public_key_bytes = read_bounded(
        &config.q6ea_receipt_public_key_path,
        ML_DSA_65_PUBLIC_KEY_BYTES as u64,
        "Q6EA Anchor ML-DSA-65 receipt public key",
    )?;
    if q6ea_public_key_bytes.len() != ML_DSA_65_PUBLIC_KEY_BYTES {
        return Err(format!(
            "Q6EA Anchor ML-DSA-65 receipt key must be exactly {ML_DSA_65_PUBLIC_KEY_BYTES} bytes"
        ));
    }
    let q6ea_anchor_pin = ExternalCasOffhostAnchorPin {
        anchor_id: config.q6ea_anchor_id,
        provider_id: profile_pin.bundle().external_cas_pin().provider_id,
        network_id: config.network_id,
        genesis_digest: profile_pin.bundle().external_cas_pin().genesis_digest,
        receipt_key_id: config.q6ea_receipt_key_id,
        receipt_public_key: q6ea_public_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "invalid Q6EA Anchor receipt public key length")?,
    };
    q6ea_anchor_pin
        .validate(profile_pin.bundle().external_cas_pin())
        .map_err(|error| {
            format!("Q6EA Anchor pin is invalid or not independent from Provider: {error:?}")
        })?;

    // Pin the Noise XX server identities separately from the Provider/Anchor receipt keys.
    let provider_noise_server_key = read_pinned_noise_server_key(
        &config.provider_noise_server_key_path,
        &config.provider_noise_server_key_sha256,
        "Provider Noise XX server static public key",
    )?;
    let q6ea_anchor_noise_server_key = read_pinned_noise_server_key(
        &config.q6ea_anchor_noise_server_key_path,
        &config.q6ea_anchor_noise_server_key_sha256,
        "Q6EA Anchor Noise XX server static public key",
    )?;
    if provider_noise_server_key == q6ea_anchor_noise_server_key {
        return Err("Provider and Q6EA Anchor Noise XX server static keys must be distinct".into());
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
        genesis_state_root,
        genesis_snapshot_sha256: actual_genesis_snapshot_sha256,
        consensus_profile_sha256: actual_consensus_profile_sha256,
        consensus_fingerprint: consensus_profile.consensus_fingerprint(),
        consensus_protocol_version: consensus_params.protocol_version,
        target_block_time_secs: consensus_params.target_block_time_secs,
        difficulty_window_blocks: consensus_params.difficulty_window_blocks,
        initial_target: consensus_params.initial_target.to_be_bytes(),
        pow_limit: consensus_params.pow_limit.to_be_bytes(),
        pow_memory_kib: consensus_params.pow.memory_kib,
        pow_iterations: consensus_params.pow.iterations,
        pow_lanes: consensus_params.pow.lanes,
        issuance_maximum_supply_atoms: consensus_params.issuance.maximum_supply(),
        issuance_initial_subsidy_atoms: consensus_params.issuance.initial_subsidy(),
        issuance_blocks_per_halving: consensus_params.issuance.blocks_per_halving(),
        founder_genesis_atoms,
        q6ea_anchor_id: config.q6ea_anchor_id,
        provider_noise_server_key_sha256: config.provider_noise_server_key_sha256,
        q6ea_anchor_noise_server_key_sha256: config.q6ea_anchor_noise_server_key_sha256,
        provider_endpoint: config.provider_endpoint,
        q6ea_anchor_endpoint: config.q6ea_anchor_endpoint,
        trust_epoch: envelope.record.trust_epoch,
        has_quote_asset_pin: profile_pin.quote_asset_trust_pin().is_some(),
        provider_id: profile_pin.bundle().external_cas_pin().provider_id,
        provider_pin: profile_pin.bundle().external_cas_pin().clone(),
        q6ea_anchor_pin,
        provider_noise_server_public_key: provider_noise_server_key,
        q6ea_anchor_noise_server_public_key: q6ea_anchor_noise_server_key,
    })
}

fn require_distinct_qap1_client_keys(
    provider_key: &mut [u8; 32],
    anchor_key: &mut [u8; 32],
) -> Result<(), String> {
    if provider_key == anchor_key {
        provider_key.fill(0);
        anchor_key.fill(0);
        return Err("Provider and Q6EA Anchor Noise client private keys must be distinct".into());
    }
    Ok(())
}

fn validate_q6ea_expected_state_identity(
    state: &QRunV06ExternalAnchorState,
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
    genesis_digest: &[u8; 32],
    genesis_descriptor_commitment: &[u8; 32],
    consensus_fingerprint: &[u8; 32],
) -> Result<(), String> {
    state
        .validate()
        .map_err(|error| format!("Q6EA expected state is invalid: {error:?}"))?;
    if &state.network_id != network_id
        || &state.profile_id != profile_id
        || &state.genesis_digest != genesis_digest
        || &state.genesis_descriptor_commitment != genesis_descriptor_commitment
        || &state.consensus_fingerprint != consensus_fingerprint
    {
        return Err("Q6EA expected state does not bind the exact Q6PN Provider/network/Genesis/Q6GD/consensus identity".into());
    }
    Ok(())
}

/// Read-only QAP1 state qualification. This sends signed Provider Read and Q6EA Read
/// requests only; it never issues Provider CAS, Anchor CAS, floor advance, block admission or ACK.
/// The local Provider floor's OS writer-lock file may be created/updated for mutual exclusion;
/// the trusted floor record itself remains unchanged.
fn probe_qap1_services(
    config_path: &Path,
    independently_pinned_config_digest: &[u8; 32],
) -> Result<(PreflightSummary, QRunV06ExternalAnchorState), String> {
    let config = parse_config(config_path, independently_pinned_config_digest)?;
    let expected_state_path = config
        .q6ea_expected_state_path
        .as_deref()
        .ok_or_else(|| "--probe-qap1 requires q6ea_expected_state_path".to_string())?;
    let expected_state_digest = config
        .q6ea_expected_state_sha256
        .as_ref()
        .ok_or_else(|| "--probe-qap1 requires q6ea_expected_state_sha256".to_string())?;
    let provider_client_key_path = config
        .provider_noise_client_key_path
        .as_deref()
        .ok_or_else(|| "--probe-qap1 requires provider_noise_client_key_path".to_string())?;
    let anchor_client_key_path = config
        .q6ea_anchor_noise_client_key_path
        .as_deref()
        .ok_or_else(|| "--probe-qap1 requires q6ea_anchor_noise_client_key_path".to_string())?;
    let provider_floor_path = config
        .provider_floor_store_path
        .as_deref()
        .ok_or_else(|| "--probe-qap1 requires provider_floor_store_path".to_string())?;
    let summary = preflight(config_path, independently_pinned_config_digest)?;

    let expected_state_bytes = read_bounded(
        expected_state_path,
        512,
        "independently pinned Q6EA expected state",
    )?;
    let actual_state_sha256: [u8; 32] = Sha256::digest(&expected_state_bytes).into();
    if &actual_state_sha256 != expected_state_digest {
        return Err(
            "Q6EA expected-state SHA-256 differs from the independently pinned config digest"
                .into(),
        );
    }
    let expected_state = QRunV06ExternalAnchorState::decode(&expected_state_bytes)
        .map_err(|error| format!("Q6EA expected state decode failed: {error:?}"))?;
    validate_q6ea_expected_state_identity(
        &expected_state,
        &config.network_id,
        &config.profile_id,
        &summary.provider_pin.genesis_digest,
        &summary.genesis_commitment,
        &config.consensus_fingerprint,
    )?;

    // Open only an existing Provider high-water floor. No initialize/create/advance fallback.
    let provider_floor =
        ExternalCasFloorStore::open(provider_floor_path, summary.provider_pin.clone()).map_err(
            |error| format!("existing Provider monotonic floor could not be opened: {error:?}"),
        )?;

    // Client static identities are protected by Windows CurrentUser DPAPI and bound to this
    // exact network ID. Plaintext keys never appear in the JSON config or on a command line.
    let mut provider_client_key =
        load_protected_noise_private_key(provider_client_key_path, &config.network_id).map_err(
            |error| format!("protected Provider Noise client key unavailable: {error:?}"),
        )?;
    let mut anchor_client_key =
        match load_protected_noise_private_key(anchor_client_key_path, &config.network_id) {
            Ok(key) => key,
            Err(error) => {
                provider_client_key.fill(0);
                return Err(format!(
                    "protected Q6EA Anchor Noise client key unavailable: {error:?}"
                ));
            }
        };
    require_distinct_qap1_client_keys(&mut provider_client_key, &mut anchor_client_key)?;

    let provider_transport_result = NoiseTcpExternalCasProviderTransport::new(
        config.provider_endpoint,
        provider_client_key,
        summary.provider_noise_server_public_key,
        summary.provider_pin.clone(),
    );
    provider_client_key.fill(0);
    let provider_transport = match provider_transport_result {
        Ok(transport) => transport,
        Err(error) => {
            anchor_client_key.fill(0);
            return Err(format!(
                "Provider Noise transport configuration failed: {error:?}"
            ));
        }
    };

    let anchor_transport_result = NoiseTcpOffhostAnchorTransport::new(
        config.q6ea_anchor_endpoint,
        anchor_client_key,
        summary.q6ea_anchor_noise_server_public_key,
        summary.q6ea_anchor_pin.clone(),
        summary.provider_pin.clone(),
    );
    anchor_client_key.fill(0);
    let anchor_transport = anchor_transport_result
        .map_err(|error| format!("Q6EA Anchor Noise transport configuration failed: {error:?}"))?;

    let qfp6_anchor_pin =
        QRunV06ExternalAnchorPin::new(summary.provider_pin.clone(), summary.genesis_commitment)
            .map_err(|error| format!("QFP6 external-anchor pin construction failed: {error:?}"))?;
    let mut coordinator = QRunV06Qap1ExternalCoordinator::new(
        provider_transport,
        provider_floor,
        anchor_transport,
        qfp6_anchor_pin,
        summary.q6ea_anchor_pin.clone(),
        LibcruxMlDsa65VerifierCandidate,
        LibcruxMlDsa65VerifierCandidate,
    )
    .map_err(|error| format!("QAP1 Provider/Anchor pin binding failed: {error:?}"))?;

    coordinator
        .verify_current(&expected_state)
        .map_err(|error| {
            format!("read-only QAP1 Provider/Anchor verification failed: {error:?}")
        })?;

    Ok((summary, expected_state))
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
           qrun_v06_node --probe-qap1 --config <path> --config-sha256 <64-hex>\n\
           qrun_v06_node --help\n\
         \n\
         --preflight verifies the pinned Genesis/Q6CP/Q6PN/Q6TS/Q6EA bootstrap package.\n\
         --probe-qap1 additionally performs read-only signed Provider and Q6EA Anchor reads over pinned Noise endpoints.\n\
         Neither command starts a node, mutates a store/floor, admits transactions, or mines."
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
        || !matches!(args[0].as_str(), "--preflight" | "--probe-qap1")
        || args[1] != "--config"
        || args[3] != "--config-sha256"
    {
        return Err("expected '--preflight|--probe-qap1 --config <path> --config-sha256 <64-hex>' (or '--help')".into());
    }
    let expected_config_digest = parse_hex32("config_sha256", &args[4])?;
    let (summary, q6ea_state) = if args[0] == "--probe-qap1" {
        let (summary, state) = probe_qap1_services(Path::new(&args[2]), &expected_config_digest)?;
        (summary, Some(state))
    } else {
        (
            preflight(Path::new(&args[2]), &expected_config_digest)?,
            None,
        )
    };
    println!("QFP6 BOOTSTRAP PREFLIGHT: PASS");
    println!("config_sha256={}", hex(&expected_config_digest));
    println!("network_id={}", hex(&summary.network_id));
    println!("profile_id={}", hex(&summary.profile_id));
    println!(
        "genesis_descriptor_commitment={}",
        hex(&summary.genesis_commitment)
    );
    println!(
        "genesis_snapshot_sha256={}",
        hex(&summary.genesis_snapshot_sha256)
    );
    println!(
        "q6cp_profile_sha256={}",
        hex(&summary.consensus_profile_sha256)
    );
    println!(
        "q6cp_consensus_fingerprint={}",
        hex(&summary.consensus_fingerprint)
    );
    println!(
        "q6cp_protocol_version={}",
        summary.consensus_protocol_version
    );
    println!(
        "q6cp_target_block_time_secs={}",
        summary.target_block_time_secs
    );
    println!(
        "q6cp_difficulty_window_blocks={}",
        summary.difficulty_window_blocks
    );
    println!("q6cp_initial_target={}", hex(&summary.initial_target));
    println!("q6cp_pow_limit={}", hex(&summary.pow_limit));
    println!("q6cp_pow_algorithm=Argon2id");
    println!("q6cp_pow_memory_kib={}", summary.pow_memory_kib);
    println!("q6cp_pow_iterations={}", summary.pow_iterations);
    println!("q6cp_pow_lanes={}", summary.pow_lanes);
    println!(
        "q6cp_maximum_supply_atoms={}",
        summary.issuance_maximum_supply_atoms
    );
    println!(
        "q6cp_initial_subsidy_atoms={}",
        summary.issuance_initial_subsidy_atoms
    );
    println!(
        "q6cp_blocks_per_halving={}",
        summary.issuance_blocks_per_halving
    );
    println!("q6cp_qualification=CANDIDATE_ONLY_NOT_MAINNET_APPROVED");
    println!("genesis_state_root={}", hex(&summary.genesis_state_root));
    println!("genesis_founder_atoms={}", summary.founder_genesis_atoms);
    println!("provider_id={}", hex(&summary.provider_id));
    println!("provider_endpoint={}", summary.provider_endpoint);
    println!("q6ea_anchor_id={}", hex(&summary.q6ea_anchor_id));
    println!("q6ea_anchor_endpoint={}", summary.q6ea_anchor_endpoint);
    println!(
        "provider_noise_server_key_sha256={}",
        hex(&summary.provider_noise_server_key_sha256)
    );
    println!(
        "q6ea_anchor_noise_server_key_sha256={}",
        hex(&summary.q6ea_anchor_noise_server_key_sha256)
    );
    println!("provider_anchor_endpoint_distinct=true");
    println!("provider_anchor_noise_server_keys_distinct=true");
    println!("q6ts_trust_epoch={}", summary.trust_epoch);
    println!(
        "q6qa_quote_asset_pin={}",
        if summary.has_quote_asset_pin {
            "present"
        } else {
            "absent (native chain only; quote-asset operations remain gated)"
        }
    );
    println!("crypto_verifier=LibcruxMlDsa65VerifierCandidate");
    println!("crypto_qualification=CANDIDATE_ONLY_NOT_PRODUCTION_APPROVED");
    println!("runtime=NOT_STARTED");
    println!("node_p2p_listener=NOT_OPENED");
    println!("qfp6_data_directory=NOT_TOUCHED");
    println!("qfp6_store=NOT_MUTATED");
    println!("anti_rollback_floor=independent DynamoDB strongly-consistent read; no writes");
    if let Some(state) = q6ea_state {
        println!("qap1_service_probe=PASS");
        println!("provider_signed_read=PASS");
        println!("q6ea_anchor_signed_read=PASS");
        println!("q6ea_sequence={}", state.canonical_height);
        println!("q6ea_manifest_generation={}", state.manifest_generation);
        println!("q6ea_canonical_tip={}", hex(&state.canonical_tip));
        println!("provider_floor_state=READ_ONLY_NO_ADVANCE");
        println!("provider_floor_lock=OS_LOCK_METADATA_MAY_BE_CREATED_OR_UPDATED");
        println!("provider_cas=NOT_CALLED");
        println!("q6ea_anchor_cas=NOT_CALLED");
    } else {
        println!("qap1_service_probe=NOT_REQUESTED");
    }
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
    use ai_native_l1_pow_bench::{
        consensus::ConsensusParameters,
        qrun_v06_consensus_profile_candidate::QRunV06ConsensusProfile,
        qrun_v06_genesis_descriptor_candidate::QRunV06GenesisDescriptor,
        qrun_v06_tokenomics_candidate::{QRunV06MiningScheduleCandidate, QRunV06TokenomicsState},
    };
    use ai_native_l1_pow_bench::{
        external_cas_anchor_candidate::ExternalCasPin,
        qrun_v06_profile_trust_candidate::{
            QRunV06ProfileTrustRecord, TrustedQRunV06ProfileTrustFloor,
        },
    };
    use ed25519_dalek::{Signer, SigningKey};
    use libcrux_ml_dsa::ml_dsa_65::portable;

    const TEST_NETWORK: [u8; 32] = [0xA1; 32];
    const TEST_PROFILE: [u8; 32] = [0xA2; 32];
    const TEST_Q6PN_COMMITMENT: [u8; 32] = [0xA3; 32];

    #[test]
    fn preflight_loads_q6cp_only_with_exact_file_hash_and_q6gd_identity() {
        let mut params = ConsensusParameters::candidate_testnet().unwrap();
        params.protocol_version =
            ai_native_l1_pow_bench::qrun_v06_pow_wire_candidate::QRUN_V06_PROTOCOL_VERSION;
        let fingerprint = QRunV06ConsensusProfile::fingerprint_parameters(&params).unwrap();
        let descriptor = QRunV06GenesisDescriptor::new(
            TEST_NETWORK,
            TEST_PROFILE,
            [0xA3; 32],
            1_800_000_000,
            fingerprint,
            [0xA4; 32],
        )
        .unwrap();
        let profile = QRunV06ConsensusProfile::new(
            TEST_NETWORK,
            TEST_PROFILE,
            descriptor.commitment(),
            params,
        )
        .unwrap();
        let encoded = profile.encode().unwrap();
        let path = env::temp_dir().join(format!(
            "qrun-qfp6-q6cp-preflight-{}.bin",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        fs::write(&path, encoded).unwrap();
        let digest: [u8; 32] = Sha256::digest(encoded).into();
        let (loaded_digest, loaded) =
            load_pinned_q6cp_profile(&path, &digest, &descriptor).unwrap();
        assert_eq!(loaded_digest, digest);
        assert_eq!(loaded, profile);

        assert!(load_pinned_q6cp_profile(&path, &[0x55; 32], &descriptor).is_err());

        let wrong_descriptor = QRunV06GenesisDescriptor::new(
            TEST_NETWORK,
            [0xB2; 32],
            [0xA3; 32],
            1_800_000_000,
            fingerprint,
            [0xA4; 32],
        )
        .unwrap();
        assert!(load_pinned_q6cp_profile(&path, &digest, &wrong_descriptor).is_err());

        let mut corrupted = encoded;
        corrupted[206] ^= 1;
        fs::write(&path, corrupted).unwrap();
        let corrupted_digest: [u8; 32] = Sha256::digest(corrupted).into();
        assert!(load_pinned_q6cp_profile(&path, &corrupted_digest, &descriptor).is_err());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn preflight_config_does_not_require_qap1_client_secrets_or_provider_floor() {
        let path = env::temp_dir().join(format!(
            "qrun-qfp6-cp0574-config-{}.json",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        let mut value = serde_json::json!({
            "network_id": "01".repeat(32),
            "profile_id": "02".repeat(32),
            "profile_pin_commitment": "03".repeat(32),
            "founder_account": "04".repeat(32),
            "consensus_fingerprint": "05".repeat(32),
            "consensus_profile_path": "consensus.q6cp",
            "consensus_profile_sha256": "0e".repeat(32),
            "tokenomics_policy_fingerprint": "06".repeat(32),
            "genesis_snapshot_sha256": "07".repeat(32),
            "genesis_snapshot_path": "genesis.q6gs",
            "q6pn_path": "q6pn.bin",
            "q6ts_path": "q6ts.bin",
            "q6ts_ed25519_authority_public_key_path": "authority-ed.pub",
            "q6ts_mldsa65_authority_public_key_path": "authority-pq.pub",
            "q6ts_authority_keyset_id": "08".repeat(32),
            "aws_cli_path": "aws",
            "aws_region": "us-east-1",
            "q6ts_floor_table": "q6ts-floor",
            "q6ea_anchor_id": "09".repeat(32),
            "q6ea_receipt_key_id": "0a".repeat(32),
            "q6ea_receipt_public_key_path": "q6ea-receipt.pub",
            "provider_noise_server_key_path": "provider-noise.pub",
            "provider_noise_server_key_sha256": "0b".repeat(32),
            "q6ea_anchor_noise_server_key_path": "anchor-noise.pub",
            "q6ea_anchor_noise_server_key_sha256": "0c".repeat(32),
            "provider_endpoint": "192.0.2.10:9100",
            "q6ea_anchor_endpoint": "192.0.2.11:9200"
        });

        let bytes = serde_json::to_vec(&value).unwrap();
        fs::write(&path, &bytes).unwrap();
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        let basic = parse_config(&path, &digest).unwrap();
        assert_eq!(
            basic.consensus_profile_path,
            env::temp_dir().join("consensus.q6cp")
        );
        assert_eq!(basic.consensus_profile_sha256, [0x0e; 32]);
        assert!(basic.provider_noise_client_key_path.is_none());
        assert!(basic.q6ea_anchor_noise_client_key_path.is_none());
        assert!(basic.provider_floor_store_path.is_none());
        assert!(basic.q6ea_expected_state_path.is_none());
        assert!(basic.q6ea_expected_state_sha256.is_none());

        value["provider_noise_client_key_path"] = serde_json::json!("provider-client.npk1");
        value["q6ea_anchor_noise_client_key_path"] = serde_json::json!("anchor-client.npk1");
        value["provider_floor_store_path"] = serde_json::json!("provider-floor");
        value["q6ea_expected_state_path"] = serde_json::json!("anchor-state.q6ea");
        value["q6ea_expected_state_sha256"] = serde_json::json!("0d".repeat(32));
        let bytes = serde_json::to_vec(&value).unwrap();
        fs::write(&path, &bytes).unwrap();
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        let probe = parse_config(&path, &digest).unwrap();
        assert!(probe.provider_noise_client_key_path.is_some());
        assert!(probe.q6ea_anchor_noise_client_key_path.is_some());
        assert!(probe.provider_floor_store_path.is_some());
        assert!(probe.q6ea_expected_state_path.is_some());
        assert_eq!(probe.q6ea_expected_state_sha256, Some([0x0d; 32]));

        value["q6ea_expected_state_sha256"] = serde_json::json!("not-a-digest");
        let bytes = serde_json::to_vec(&value).unwrap();
        fs::write(&path, &bytes).unwrap();
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        assert!(parse_config(&path, &digest).is_err());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn equal_qap1_client_keys_are_rejected_and_zeroized() {
        let mut provider = [0x41; 32];
        let mut anchor = [0x41; 32];
        assert!(require_distinct_qap1_client_keys(&mut provider, &mut anchor).is_err());
        assert_eq!(provider, [0; 32]);
        assert_eq!(anchor, [0; 32]);

        let mut provider = [0x42; 32];
        let mut anchor = [0x43; 32];
        assert!(require_distinct_qap1_client_keys(&mut provider, &mut anchor).is_ok());
        assert_eq!(provider, [0x42; 32]);
        assert_eq!(anchor, [0x43; 32]);
    }

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
    fn full_genesis_snapshot_is_verified_against_q6gd_and_exact_founder_allocation() {
        let schedule = QRunV06MiningScheduleCandidate::new(35_673_515_981, 4_204_800).unwrap();
        let tokenomics =
            QRunV06TokenomicsState::genesis(TEST_NETWORK, [0xA3; 32], schedule).unwrap();
        let policy = tokenomics.policy_fingerprint();
        let descriptor = QRunV06GenesisDescriptor::new(
            TEST_NETWORK,
            TEST_PROFILE,
            [0xA3; 32],
            1_800_000_000,
            [0xA4; 32],
            policy,
        )
        .unwrap();
        let state = QRunV06CanonicalExecutionState::cp0528_genesis_candidate_with_descriptor(
            descriptor.clone(),
            schedule,
        )
        .unwrap();
        let bytes = state.encode_snapshot().unwrap();
        let (root, founder_balance) = verify_genesis_snapshot(
            &bytes,
            &TEST_NETWORK,
            &TEST_PROFILE,
            &[0xA3; 32],
            &[0xA4; 32],
            &policy,
            &descriptor,
        )
        .unwrap();
        assert_eq!(root, state.state_root().unwrap());
        assert_eq!(founder_balance, QRUN_V06_FOUNDER_GENESIS_ATOMS);

        let mut corrupted = bytes.clone();
        let last_byte = corrupted.len() - 1;
        corrupted[last_byte] ^= 1;
        assert!(verify_genesis_snapshot(
            &corrupted,
            &TEST_NETWORK,
            &TEST_PROFILE,
            &[0xA3; 32],
            &[0xA4; 32],
            &policy,
            &descriptor,
        )
        .is_err());

        let wrong_consensus = [0xA5; 32];
        assert!(verify_genesis_snapshot(
            &bytes,
            &TEST_NETWORK,
            &TEST_PROFILE,
            &[0xA3; 32],
            &wrong_consensus,
            &policy,
            &descriptor,
        )
        .is_err());
    }

    #[test]
    fn q6ea_anchor_pin_must_bind_provider_domain_with_distinct_receipt_key() {
        let provider = ExternalCasPin {
            provider_id: [0x11; 32],
            network_id: TEST_NETWORK,
            genesis_digest: [0x12; 32],
            receipt_key_id: [0x13; 32],
            receipt_public_key: [0x14; ML_DSA_65_PUBLIC_KEY_BYTES],
        };
        let anchor = ExternalCasOffhostAnchorPin {
            anchor_id: [0x21; 32],
            provider_id: provider.provider_id,
            network_id: provider.network_id,
            genesis_digest: provider.genesis_digest,
            receipt_key_id: [0x22; 32],
            receipt_public_key: [0x23; ML_DSA_65_PUBLIC_KEY_BYTES],
        };
        assert!(anchor.validate(&provider).is_ok());

        let mut reused_key_id = anchor.clone();
        reused_key_id.receipt_key_id = provider.receipt_key_id;
        assert!(reused_key_id.validate(&provider).is_err());

        let mut reused_public_key = anchor.clone();
        reused_public_key.receipt_public_key = provider.receipt_public_key;
        assert!(reused_public_key.validate(&provider).is_err());

        let mut wrong_domain = anchor;
        wrong_domain.network_id[0] ^= 1;
        assert!(wrong_domain.validate(&provider).is_err());
    }

    #[test]
    fn noise_server_public_key_loader_requires_exact_pinned_32_byte_key() {
        let path = env::temp_dir().join(format!("qrun-qfp6-noise-pin-{}.bin", std::process::id()));
        let _ = fs::remove_file(&path);
        let key = [0x41u8; 32];
        fs::write(&path, key).unwrap();
        let digest: [u8; 32] = Sha256::digest(key).into();
        assert_eq!(
            read_pinned_noise_server_key(&path, &digest, "test Noise key").unwrap(),
            key
        );
        assert!(read_pinned_noise_server_key(&path, &[0x42; 32], "test Noise key").is_err());
        fs::write(&path, [0u8; 32]).unwrap();
        let zero_digest: [u8; 32] = Sha256::digest([0u8; 32]).into();
        assert!(read_pinned_noise_server_key(&path, &zero_digest, "test Noise key").is_err());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn qap1_service_endpoints_are_numeric_unicast_and_distinct() {
        let provider = parse_service_endpoint("provider_endpoint", "192.0.2.10:9100").unwrap();
        let anchor = parse_service_endpoint("q6ea_anchor_endpoint", "[2001:db8::10]:9200").unwrap();
        assert!(validate_distinct_qap1_endpoints(provider, anchor).is_ok());
        assert!(validate_distinct_qap1_endpoints(provider, provider).is_err());
        assert!(parse_service_endpoint("provider_endpoint", "provider.example:9100").is_err());
        assert!(parse_service_endpoint("provider_endpoint", "0.0.0.0:9100").is_err());
        assert!(parse_service_endpoint("provider_endpoint", "224.0.0.1:9100").is_err());
        assert!(parse_service_endpoint("provider_endpoint", "192.0.2.10:0").is_err());
    }

    #[test]
    fn q6ea_expected_state_must_bind_exact_q6pn_and_genesis_identity() {
        let state = QRunV06ExternalAnchorState {
            network_id: TEST_NETWORK,
            genesis_digest: [0x31; 32],
            genesis_descriptor_commitment: [0x32; 32],
            profile_id: TEST_PROFILE,
            consensus_fingerprint: [0x33; 32],
            segment_base_height: 0,
            segment_base_tip: [0x34; 32],
            checkpoint_anchor: [0; 32],
            manifest_generation: 0,
            manifest_anchor: [0x35; 32],
            canonical_height: 0,
            canonical_tip: [0x34; 32],
            canonical_state_root: [0x36; 32],
            cumulative_chainwork: [0; 32],
        };
        assert!(validate_q6ea_expected_state_identity(
            &state,
            &TEST_NETWORK,
            &TEST_PROFILE,
            &[0x31; 32],
            &[0x32; 32],
            &[0x33; 32],
        )
        .is_ok());
        assert!(validate_q6ea_expected_state_identity(
            &state,
            &[0xA9; 32],
            &TEST_PROFILE,
            &[0x31; 32],
            &[0x32; 32],
            &[0x33; 32],
        )
        .is_err());
        assert!(validate_q6ea_expected_state_identity(
            &state,
            &TEST_NETWORK,
            &TEST_PROFILE,
            &[0xA9; 32],
            &[0x32; 32],
            &[0x33; 32],
        )
        .is_err());
        assert!(validate_q6ea_expected_state_identity(
            &state,
            &TEST_NETWORK,
            &TEST_PROFILE,
            &[0x31; 32],
            &[0x32; 32],
            &[0xA9; 32],
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
        assert_eq!(
            resolve_executable(base, "C:\\AWS\\aws.exe"),
            PathBuf::from("C:\\AWS\\aws.exe")
        );
        assert_eq!(
            resolve_executable(base, r"\\server\share\aws.exe"),
            PathBuf::from(r"\\server\share\aws.exe")
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
    fn read_only_qap1_probe_refuses_missing_config_before_any_network_call() {
        let error = run(&[
            "--probe-qap1".into(),
            "--config".into(),
            "missing-qrun-v06-node.json".into(),
            "--config-sha256".into(),
            "11".repeat(32),
        ])
        .unwrap_err();
        assert!(error.contains("cannot inspect config"));
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
