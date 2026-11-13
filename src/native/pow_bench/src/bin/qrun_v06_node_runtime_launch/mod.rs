//! CP-0613 executable-level QFP6 QAP1 bootstrap and private candidate supervisor.
//!
//! This launcher is intentionally private-candidate only. It never creates Genesis, trust
//! authorities, provider floors, Q6EA state, Noise identities, or bootstrap peer pins. Every
//! one of those inputs must be independently provisioned and pass the existing preflight.

use super::{
    load_pinned_q6cp_profile, parse_config, parse_hex32, preflight, read_bounded, resolve_path,
    validate_q6ea_expected_state_identity, Config, PreflightSummary, MAX_BOOTSTRAP_BYTES,
    MAX_CONFIG_BYTES, MAX_GENESIS_SNAPSHOT_BYTES,
};
use ai_native_l1_pow_bench::{
    external_cas_floor_store_candidate::ExternalCasFloorStore,
    external_cas_noise_transport_candidate::NoiseTcpExternalCasProviderTransport,
    external_cas_offhost_anchor_noise_transport_candidate::NoiseTcpOffhostAnchorTransport,
    noise_key_provisioning::load_protected_noise_private_key,
    qrun_v06_canonical_execution_candidate::{
        QRunV06Block, QRunV06BlockOperation, QRunV06CanonicalExecutionState,
    },
    qrun_v06_external_anchor_candidate::{QRunV06ExternalAnchorPin, QRunV06ExternalAnchorState},
    qrun_v06_history_sync_service_candidate::QRunV06HistorySyncClientConfig,
    qrun_v06_hybrid_auth_candidate::QRunV06HybridTransactionAuthenticator,
    qrun_v06_node_runtime_candidate::{QRunV06NodeAnchorGate, QRunV06NodeRuntime},
    qrun_v06_node_supervisor_candidate::{
        run_qfp6_mining_supervisor_with_qap1_bootstrap, validate_qfp6_pinned_bootstrap_peers,
        QRunV06MiningSupervisorConfig, QRunV06PinnedBootstrapPeer,
    },
    qrun_v06_pow_fork_store_candidate::QRunV06DurableForkStore,
    qrun_v06_profile_trust_candidate::{
        authorize_qrun_v06_profile_pin, PinnedQRunV06ProfileTrustAuthority,
        QRunV06TrustAuthorizedProfilePin, QRunV06TrustAuthorizedQuoteAsset,
    },
    qrun_v06_profile_trust_dynamodb_floor_candidate::AwsDynamoDbQ6tsReadOnlyProfileTrustFloorStore,
    qrun_v06_qap1_coordinator_candidate::QRunV06Qap1ExternalCoordinator,
    qrun_v06_transaction_journal_candidate::QRunV06TransactionJournal,
    qrun_v06_transaction_mempool_candidate::QRunV06MempoolLimits,
    v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs,
    net::{IpAddr, SocketAddr, TcpListener},
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_RUNTIME_CONFIG_PEERS_BYTES: u64 = 16 * 1024;
const MAX_Q6QA_BYTES: u64 = 16 * 1024;

#[derive(Debug)]
struct CandidateRuntimeConfig {
    data_directory: PathBuf,
    node_noise_private_key_path: PathBuf,
    listen_address: SocketAddr,
    bootstrap_peers_path: PathBuf,
    transaction_journal_directory: PathBuf,
    producer_account: [u8; 32],
    max_blocks_per_run: u64,
    max_nonce_attempts_per_block: u64,
    q6qa_bundle_path: Option<PathBuf>,
}

fn required_runtime_string<'a>(runtime: &'a Value, name: &str) -> Result<&'a str, String> {
    runtime
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("runtime.{name} is required and must be a non-empty string"))
}

fn optional_runtime_u64(runtime: &Value, name: &str, default: u64) -> Result<u64, String> {
    match runtime.get(name) {
        None => Ok(default),
        Some(value) => value
            .as_u64()
            .ok_or_else(|| format!("runtime.{name} must be an unsigned integer")),
    }
}

fn candidate_private_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            ip.is_loopback() || (segments[0] & 0xfe00) == 0xfc00 || (segments[0] & 0xffc0) == 0xfe80
        }
    }
}

fn parse_private_endpoint(name: &str, value: &str) -> Result<SocketAddr, String> {
    let address: SocketAddr = value
        .parse()
        .map_err(|_| format!("{name} must be a numeric SocketAddr"))?;
    if address.port() == 0
        || address.ip().is_unspecified()
        || address.ip().is_multicast()
        || !candidate_private_ip(address.ip())
    {
        return Err(format!(
            "{name} must use a nonzero port and loopback, RFC1918, link-local, ULA, or NetBird/CGNAT address; public binding is disabled"
        ));
    }
    Ok(address)
}

fn validate_listener_separation(
    listener: SocketAddr,
    provider: SocketAddr,
    anchor: SocketAddr,
    peers: &[QRunV06PinnedBootstrapPeer],
) -> Result<(), String> {
    if listener == provider || listener == anchor {
        return Err(
            "private node listener must not share a Provider or Q6EA service endpoint".into(),
        );
    }
    if peers.iter().any(|peer| peer.address == listener) {
        return Err("private node listener must not alias a pinned bootstrap peer endpoint".into());
    }
    Ok(())
}

fn validate_separate_runtime_directories(
    data_directory: &Path,
    transaction_journal_directory: &Path,
) -> Result<(), String> {
    if data_directory == transaction_journal_directory
        || data_directory.starts_with(transaction_journal_directory)
        || transaction_journal_directory.starts_with(data_directory)
    {
        return Err("runtime.transaction_journal_directory must be a separate, non-nested directory from runtime.data_directory".into());
    }
    Ok(())
}

fn parse_candidate_runtime_config(
    config_path: &Path,
    independently_pinned_config_digest: &[u8; 32],
) -> Result<CandidateRuntimeConfig, String> {
    let config_bytes = read_bounded(config_path, MAX_CONFIG_BYTES, "config")?;
    let actual_digest: [u8; 32] = Sha256::digest(&config_bytes).into();
    if &actual_digest != independently_pinned_config_digest {
        return Err("config digest changed between preflight and runtime parsing".into());
    }
    let value: Value = serde_json::from_slice(&config_bytes)
        .map_err(|error| format!("invalid JSON config: {error}"))?;
    let runtime = value
        .get("runtime")
        .ok_or_else(|| "config.runtime is required for --run".to_string())?;
    if runtime.get("mode").and_then(Value::as_str) != Some("private-candidate") {
        return Err("runtime.mode must be exactly 'private-candidate'; public/Mainnet launch is not enabled".into());
    }
    if runtime
        .get("allow_candidate_runtime")
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err("runtime.allow_candidate_runtime=true is required for explicit candidate-only execution".into());
    }

    let base = config_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let path = |name: &str| -> Result<PathBuf, String> {
        let resolved = resolve_path(base, required_runtime_string(runtime, name)?);
        if !resolved.is_absolute() {
            return Err(format!("runtime.{name} must resolve to an absolute path"));
        }
        Ok(resolved)
    };
    let q6qa_bundle_path = match runtime.get("q6qa_bundle_path") {
        None => None,
        Some(_) => Some(path("q6qa_bundle_path")?),
    };
    let max_blocks_per_run = optional_runtime_u64(runtime, "max_blocks_per_run", 1)?;
    let max_nonce_budget = QRunV06MiningSupervisorConfig::default()
        .mining
        .max_nonce_attempts_per_block;
    let max_nonce_attempts_per_block =
        optional_runtime_u64(runtime, "max_nonce_attempts_per_block", max_nonce_budget)?;
    if !(1..=16).contains(&max_blocks_per_run) {
        return Err("runtime.max_blocks_per_run must be in 1..=16".into());
    }
    if !(1..=max_nonce_budget).contains(&max_nonce_attempts_per_block) {
        return Err(format!(
            "runtime.max_nonce_attempts_per_block must be in 1..={max_nonce_budget}"
        ));
    }

    Ok(CandidateRuntimeConfig {
        data_directory: path("data_directory")?,
        node_noise_private_key_path: path("node_noise_private_key_path")?,
        listen_address: parse_private_endpoint(
            "runtime.listen_address",
            required_runtime_string(runtime, "listen_address")?,
        )?,
        bootstrap_peers_path: path("bootstrap_peers_path")?,
        transaction_journal_directory: path("transaction_journal_directory")?,
        producer_account: parse_hex32(
            "runtime.producer_account",
            required_runtime_string(runtime, "producer_account")?,
        )?,
        max_blocks_per_run,
        max_nonce_attempts_per_block,
        q6qa_bundle_path,
    })
}

fn load_pinned_bootstrap_peers(path: &Path) -> Result<Vec<QRunV06PinnedBootstrapPeer>, String> {
    let bytes = read_bounded(
        path,
        MAX_RUNTIME_CONFIG_PEERS_BYTES,
        "pinned bootstrap peers",
    )?;
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid pinned bootstrap peers JSON: {error}"))?;
    let peers = value
        .as_array()
        .ok_or_else(|| "pinned bootstrap peers must be a JSON array".to_string())?;
    if peers.is_empty() || peers.len() > 64 {
        return Err("pinned bootstrap peers must contain 1..=64 entries".into());
    }
    let mut result = Vec::with_capacity(peers.len());
    for (index, peer) in peers.iter().enumerate() {
        let address_text = peer
            .get("address")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("bootstrap peer {index} is missing address"))?;
        let key_text = peer
            .get("noise_static_public_key")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("bootstrap peer {index} is missing noise_static_public_key"))?;
        let address = parse_private_endpoint(&format!("bootstrap peer {index}"), address_text)?;
        let noise_static_public_key =
            parse_hex32(&format!("bootstrap peer {index} Noise key"), key_text)?;
        result.push(QRunV06PinnedBootstrapPeer {
            address,
            noise_static_public_key,
        });
    }
    validate_qfp6_pinned_bootstrap_peers(&result)
        .map_err(|error| format!("invalid pinned bootstrap peer set: {error:?}"))?;
    Ok(result)
}

fn load_expected_q6ea_state(
    config: &Config,
    summary: &PreflightSummary,
) -> Result<QRunV06ExternalAnchorState, String> {
    let path = config
        .q6ea_expected_state_path
        .as_deref()
        .ok_or_else(|| "--run requires q6ea_expected_state_path".to_string())?;
    let expected_digest = config
        .q6ea_expected_state_sha256
        .as_ref()
        .ok_or_else(|| "--run requires q6ea_expected_state_sha256".to_string())?;
    let bytes = read_bounded(path, 512, "independently pinned Q6EA expected state")?;
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    if &digest != expected_digest {
        return Err("Q6EA expected-state digest mismatch".into());
    }
    let state = QRunV06ExternalAnchorState::decode(&bytes)
        .map_err(|error| format!("Q6EA expected-state decode failed: {error:?}"))?;
    validate_q6ea_expected_state_identity(
        &state,
        &summary.network_id,
        &summary.profile_id,
        &summary.provider_pin.genesis_digest,
        &summary.genesis_commitment,
        &summary.consensus_fingerprint,
    )?;
    Ok(state)
}

fn load_authorized_profile_pin(
    config: &Config,
) -> Result<QRunV06TrustAuthorizedProfilePin, String> {
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
        ai_native_l1_pow_bench::v4_fat1_trust_candidate::ML_DSA_65_PUBLIC_KEY_BYTES as u64,
        "Q6TS ML-DSA-65 authority public key",
    )?;
    if ed25519_bytes.len() != 32
        || mldsa65_bytes.len()
            != ai_native_l1_pow_bench::v4_fat1_trust_candidate::ML_DSA_65_PUBLIC_KEY_BYTES
    {
        return Err("Q6TS authority public-key length is invalid".into());
    }
    let authority = PinnedQRunV06ProfileTrustAuthority {
        ed25519_public_key: ed25519_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "invalid Q6TS Ed25519 authority key length")?,
        mldsa65_public_key: mldsa65_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "invalid Q6TS ML-DSA-65 authority key length")?,
    };
    let actual_keyset_id = authority
        .keyset_id()
        .map_err(|error| format!("Q6TS authority keyset is invalid: {error}"))?;
    if actual_keyset_id != config.authority_keyset_id {
        return Err("Q6TS authority keyset differs from the independently pinned keyset ID".into());
    }
    let mut floor_store = AwsDynamoDbQ6tsReadOnlyProfileTrustFloorStore::new(
        &config.aws_cli_path,
        &config.aws_region,
        &config.trust_floor_table,
    )
    .map_err(|error| format!("Q6TS read-only floor adapter unavailable: {error}"))?;
    authorize_qrun_v06_profile_pin(
        Some(&profile_pin_bytes),
        &trust_envelope_bytes,
        &authority,
        &LibcruxMlDsa65VerifierCandidate,
        &mut floor_store,
        config.network_id,
        config.profile_id,
    )
    .map_err(|error| format!("Q6TS/Q6PN authorization failed: {error}"))
}

fn build_qap1_coordinator(
    config: &Config,
    summary: &PreflightSummary,
    local_node_private_key: &[u8; 32],
) -> Result<
    QRunV06Qap1ExternalCoordinator<
        NoiseTcpExternalCasProviderTransport,
        LibcruxMlDsa65VerifierCandidate,
        LibcruxMlDsa65VerifierCandidate,
        NoiseTcpOffhostAnchorTransport,
    >,
    String,
> {
    let provider_floor_path = config
        .provider_floor_store_path
        .as_deref()
        .ok_or_else(|| "--run requires provider_floor_store_path".to_string())?;
    let provider_client_key_path = config
        .provider_noise_client_key_path
        .as_deref()
        .ok_or_else(|| "--run requires provider_noise_client_key_path".to_string())?;
    let anchor_client_key_path = config
        .q6ea_anchor_noise_client_key_path
        .as_deref()
        .ok_or_else(|| "--run requires q6ea_anchor_noise_client_key_path".to_string())?;
    let provider_floor =
        ExternalCasFloorStore::open(provider_floor_path, summary.provider_pin.clone())
            .map_err(|error| format!("existing Provider monotonic floor unavailable: {error:?}"))?;

    let mut provider_client_key =
        load_protected_noise_private_key(provider_client_key_path, &summary.network_id).map_err(
            |error| format!("protected Provider Noise client key unavailable: {error:?}"),
        )?;
    let mut anchor_client_key =
        match load_protected_noise_private_key(anchor_client_key_path, &summary.network_id) {
            Ok(key) => key,
            Err(error) => {
                provider_client_key.fill(0);
                return Err(format!(
                    "protected Q6EA Anchor Noise client key unavailable: {error:?}"
                ));
            }
        };
    if provider_client_key == anchor_client_key
        || provider_client_key == *local_node_private_key
        || anchor_client_key == *local_node_private_key
    {
        provider_client_key.fill(0);
        anchor_client_key.fill(0);
        return Err(
            "node, Provider, and Q6EA Anchor Noise client identities must be pairwise distinct"
                .into(),
        );
    }

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
            return Err(format!("Provider Noise transport setup failed: {error:?}"));
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
        .map_err(|error| format!("Q6EA Anchor Noise transport setup failed: {error:?}"))?;

    let qfp6_anchor_pin =
        QRunV06ExternalAnchorPin::new(summary.provider_pin.clone(), summary.genesis_commitment)
            .map_err(|error| format!("QFP6 external-anchor pin construction failed: {error:?}"))?;
    let coordinator = QRunV06Qap1ExternalCoordinator::new(
        provider_transport,
        provider_floor,
        anchor_transport,
        qfp6_anchor_pin,
        summary.q6ea_anchor_pin.clone(),
        LibcruxMlDsa65VerifierCandidate,
        LibcruxMlDsa65VerifierCandidate,
    )
    .map_err(|error| format!("QAP1 Provider/Anchor pin binding failed: {error:?}"))?;
    Ok(coordinator)
}

fn existing_manifest_anchor(
    data_directory: &Path,
    expected_state: &QRunV06ExternalAnchorState,
    qap1_recovery_pair: Option<(&QRunV06ExternalAnchorState, &QRunV06ExternalAnchorState)>,
) -> Result<Option<[u8; 32]>, String> {
    let manifests = data_directory.join("manifests");
    let metadata = match fs::symlink_metadata(&manifests) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if qap1_recovery_pair.is_some() {
                return Err(
                    "QAP1 recovery intent exists but the local Manifest directory is absent".into(),
                );
            }
            return Ok(None);
        }
        Err(error) => return Err(format!("cannot inspect QFP6 manifests directory: {error}")),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err("QFP6 manifests path must be a real directory".into());
        }
        Ok(metadata) => metadata,
    };
    let _ = metadata;
    let entries = fs::read_dir(&manifests)
        .map_err(|error| format!("cannot read QFP6 manifests directory: {error}"))?;
    let mut latest_generation: Option<u64> = None;
    for entry in entries {
        let entry = entry.map_err(|error| format!("cannot read QFP6 manifest entry: {error}"))?;
        let kind = entry
            .file_type()
            .map_err(|error| format!("cannot inspect QFP6 manifest entry: {error}"))?;
        if kind.is_symlink() || !kind.is_file() {
            return Err("QFP6 manifest directory contains a symlink or non-file entry".into());
        }
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            return Err("QFP6 manifest filename is not valid Unicode".into());
        };
        let Some(digits) = name
            .strip_prefix("qfp6-manifest-")
            .and_then(|value| value.strip_suffix(".q6mf"))
        else {
            continue;
        };
        if digits.len() != 20 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        let generation = digits
            .parse::<u64>()
            .map_err(|error| format!("invalid QFP6 manifest generation: {error}"))?;
        latest_generation =
            Some(latest_generation.map_or(generation, |value| value.max(generation)));
    }

    let Some(local_generation) = latest_generation else {
        if qap1_recovery_pair.is_some() {
            return Err("QAP1 recovery intent exists but the local Manifest chain is empty".into());
        }
        return Ok(None);
    };

    if let Some((predecessor, successor)) = qap1_recovery_pair {
        if expected_state != predecessor && expected_state != successor {
            return Err(
                "independent Q6EA state is neither the saved QAP1 predecessor nor successor".into(),
            );
        }
        if local_generation == predecessor.manifest_generation {
            return Ok(Some(predecessor.manifest_anchor));
        }
        if local_generation == successor.manifest_generation {
            return Ok(Some(successor.manifest_anchor));
        }
        return Err(
            "local Manifest generation is neither the saved QAP1 predecessor nor successor".into(),
        );
    }

    Ok(Some(expected_state.manifest_anchor))
}

struct RejectLegacyAnchorGate;

impl QRunV06NodeAnchorGate for RejectLegacyAnchorGate {
    fn verify_current(&mut self, _state: &QRunV06ExternalAnchorState) -> Result<(), String> {
        Err(
            "legacy single-provider anchor path is disabled; QAP1 is the only runtime authority"
                .into(),
        )
    }

    fn advance_after_local_commit(
        &mut self,
        _current: &QRunV06ExternalAnchorState,
        _next: &QRunV06ExternalAnchorState,
    ) -> Result<(), String> {
        Err(
            "legacy single-provider anchor path is disabled; QAP1 is the only runtime authority"
                .into(),
        )
    }
}

fn run_candidate_node_inner(
    config: &Config,
    summary: &PreflightSummary,
    runtime_config: &CandidateRuntimeConfig,
    bootstrap_peers: &[QRunV06PinnedBootstrapPeer],
    local_node_private_key: &mut [u8; 32],
) -> Result<(), String> {
    let expected_q6ea_state = load_expected_q6ea_state(config, summary)?;
    let authorized_profile_pin = load_authorized_profile_pin(config)?;

    let (_, consensus_profile) = load_pinned_q6cp_profile(
        &config.consensus_profile_path,
        &config.consensus_profile_sha256,
        authorized_profile_pin.verified_profile_pin().descriptor(),
    )?;
    let consensus_params = consensus_profile.parameters().clone();

    let genesis_snapshot_bytes = read_bounded(
        &config.genesis_snapshot_path,
        MAX_GENESIS_SNAPSHOT_BYTES,
        "full QFP6 Genesis execution snapshot",
    )?;
    let genesis_state = QRunV06CanonicalExecutionState::decode_snapshot(
        &genesis_snapshot_bytes,
        &summary.network_id,
        &summary.profile_id,
    )
    .map_err(|error| format!("Genesis snapshot decode failed: {error:?}"))?;
    genesis_state
        .verify_invariants()
        .map_err(|error| format!("Genesis invariant validation failed: {error:?}"))?;

    let authenticator = QRunV06HybridTransactionAuthenticator::new(LibcruxMlDsa65VerifierCandidate);
    let q6qa_bundle_bytes = match &runtime_config.q6qa_bundle_path {
        Some(path) => Some(read_bounded(
            path,
            MAX_Q6QA_BYTES,
            "Q6QA quote-asset qualification bundle",
        )?),
        None if authorized_profile_pin
            .verified_profile_pin()
            .quote_asset_trust_pin()
            .is_some() =>
        {
            return Err(
                "Q6PN contains a quote-asset trust pin; runtime.q6qa_bundle_path is required"
                    .into(),
            );
        }
        None => None,
    };
    let mut quote_authorizer = |_parent: &QRunV06CanonicalExecutionState,
                                block: &QRunV06Block,
                                required_quote_asset_id: [u8; 32]|
     -> Result<QRunV06TrustAuthorizedQuoteAsset, String> {
        let bytes = q6qa_bundle_bytes.as_deref().ok_or_else(|| {
            "external quote-asset operation refused: no pinned Q6QA bundle was supplied".to_string()
        })?;
        let authorized = authorized_profile_pin
            .authorize_quote_asset(bytes, block.height, &authenticator)
            .map_err(|error| format!("Q6QA authorization failed: {error}"))?;
        authorized
            .require_for_pair(
                &summary.network_id,
                &summary.profile_id,
                &required_quote_asset_id,
                block.height,
            )
            .map_err(|error| format!("Q6QA pair/height authorization failed: {error}"))?;
        Ok(authorized)
    };

    // Acquire the local Q6MJ writer lock and private listener before any QAP1 recovery can
    // advance an independent Provider/Anchor transition. A local resource failure must not leave
    // external QAP1 state half-advanced merely because the listener port or journal path was bad.
    let mut transaction_journal = QRunV06TransactionJournal::open(
        &runtime_config.transaction_journal_directory,
        QRunV06MempoolLimits::default(),
    )
    .map_err(|error| format!("durable Q6MJ transaction journal open failed: {error:?}"))?;
    let listener = TcpListener::bind(runtime_config.listen_address)
        .map_err(|error| format!("private QFP6 P2P listener bind failed: {error}"))?;
    let mut supervisor_config = QRunV06MiningSupervisorConfig::default();
    supervisor_config.mining.max_blocks_per_run = runtime_config.max_blocks_per_run;
    supervisor_config.mining.max_nonce_attempts_per_block =
        runtime_config.max_nonce_attempts_per_block;
    supervisor_config
        .validate()
        .map_err(|error| format!("candidate mining supervisor config is invalid: {error:?}"))?;

    // Authenticate any durable QAP1 intent before choosing the local Manifest anchor. Without
    // an intent, Provider and Q6EA must match the independent state. With an intent, recovery must
    // reconcile intermediate Provider/Anchor phases rather than requiring premature equality.
    let mut recovery_coordinator = build_qap1_coordinator(config, summary, local_node_private_key)?;
    let qap1_journal_directory = runtime_config
        .data_directory
        .join(ai_native_l1_pow_bench::qrun_v06_qap1_journal_candidate::QAP1_DIRECTORY);
    let qap1_journal = recovery_coordinator
        .load_latest_journal(&qap1_journal_directory)
        .map_err(|error| format!("QAP1 journal verification failed before store open: {error}"))?;
    if qap1_journal.is_none() {
        recovery_coordinator
            .verify_current(&expected_q6ea_state)
            .map_err(|error| format!("pre-start QAP1 Provider/Anchor read failed: {error}"))?;
    }
    let recovery_pair = qap1_journal
        .as_ref()
        .map(|journal| (journal.predecessor(), journal.successor()));
    let trusted_manifest_anchor = existing_manifest_anchor(
        &runtime_config.data_directory,
        &expected_q6ea_state,
        recovery_pair,
    )?;
    let store =
        QRunV06DurableForkStore::open_with_trust_authorized_profile_pin_and_quote_asset_authorization(
            &runtime_config.data_directory,
            genesis_state,
            consensus_params,
            &authenticator,
            trusted_manifest_anchor,
            &authorized_profile_pin,
            &mut quote_authorizer,
        )
        .map_err(|error| format!("QFP6 durable QAP1 store open/recovery failed: {error:?}"))?;

    // The recovery coordinator is consumed by the recovery constructor. A fresh independently
    // pinned coordinator is created below for history sync and steady-state block admission.
    let mut runtime = QRunV06NodeRuntime::recover_qap1_after_process_restart(
        store,
        RejectLegacyAnchorGate,
        recovery_coordinator,
        summary.provider_pin.genesis_digest,
        &authenticator,
        &mut quote_authorizer,
    )
    .map_err(|error| format!("QAP1 runtime recovery failed: {error}"))?;

    let mut coordinator = build_qap1_coordinator(config, summary, local_node_private_key)?;
    coordinator
        .verify_current(runtime.committed_anchor_state())
        .map_err(|error| {
            format!("QAP1 runtime state is not current at Provider/Anchor: {error}")
        })?;

    let sync_config = QRunV06HistorySyncClientConfig::default();
    let shutdown_requested = AtomicBool::new(false);
    let result = run_qfp6_mining_supervisor_with_qap1_bootstrap(
        &listener,
        supervisor_config,
        local_node_private_key,
        &bootstrap_peers,
        &summary.network_id,
        &summary.profile_id,
        &shutdown_requested,
        &mut runtime,
        &authenticator,
        &mut quote_authorizer,
        &mut coordinator,
        runtime_config.producer_account,
        &mut transaction_journal,
        |parent| {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|error| format!("system clock is before Unix epoch: {error}"))?
                .as_secs();
            let next_timestamp = parent
                .last_timestamp()
                .checked_add(1)
                .ok_or_else(|| "parent timestamp is exhausted".to_string())?;
            Ok((now.max(next_timestamp), Vec::<QRunV06BlockOperation>::new()))
        },
        sync_config,
    );
    local_node_private_key.fill(0);
    let report =
        result.map_err(|error| format!("QFP6 QAP1 bootstrap/supervisor stopped: {error}"))?;
    println!("QFP6 PRIVATE CANDIDATE RUNTIME: STOPPED");
    println!("bootstrap_sync_complete={}", report.bootstrap_sync.complete);
    println!(
        "bootstrap_source_height={}",
        report.bootstrap_sync.source_height
    );
    println!(
        "bootstrap_final_height={}",
        report.bootstrap_sync.final_height
    );
    println!(
        "bootstrap_pages_imported={}",
        report.bootstrap_sync.pages_imported
    );
    println!(
        "bootstrap_blocks_imported={}",
        report.bootstrap_sync.blocks_imported
    );
    println!("listener_rounds={}", report.supervisor.listener_rounds);
    println!("mining_rounds={}", report.supervisor.mining_rounds);
    println!(
        "blocks_qap1_acknowledged={}",
        report.supervisor.blocks_acknowledged
    );
    println!("ending_height={}", report.supervisor.ending_height);
    println!(
        "pending_mempool_transactions={}",
        report.supervisor.pending_mempool_transactions
    );
    println!(
        "mempool_journal_generation={}",
        report.supervisor.mempool_journal_generation
    );
    println!("public_listener=DISABLED");
    println!("mainnet_authorization=NOT_GRANTED");
    Ok(())
}

pub fn run_candidate_node(
    config_path: &Path,
    independently_pinned_config_digest: &[u8; 32],
) -> Result<(), String> {
    let config = parse_config(config_path, independently_pinned_config_digest)?;
    // Refuse public/Mainnet modes and public bind addresses before the Q6TS AWS read or
    // protected-key loading. Candidate opt-in is an explicit local operator decision.
    let runtime_config =
        parse_candidate_runtime_config(config_path, independently_pinned_config_digest)?;
    if runtime_config.producer_account == [0; 32] {
        return Err("runtime.producer_account must be nonzero".into());
    }
    validate_separate_runtime_directories(
        &runtime_config.data_directory,
        &runtime_config.transaction_journal_directory,
    )?;
    let bootstrap_peers = load_pinned_bootstrap_peers(&runtime_config.bootstrap_peers_path)?;
    validate_listener_separation(
        runtime_config.listen_address,
        config.provider_endpoint,
        config.q6ea_anchor_endpoint,
        &bootstrap_peers,
    )?;
    let summary = preflight(config_path, independently_pinned_config_digest)?;
    let mut local_node_private_key = load_protected_noise_private_key(
        &runtime_config.node_noise_private_key_path,
        &summary.network_id,
    )
    .map_err(|error| format!("protected local QFP6 Noise key unavailable: {error:?}"))?;
    let result = run_candidate_node_inner(
        &config,
        &summary,
        &runtime_config,
        &bootstrap_peers,
        &mut local_node_private_key,
    );
    local_node_private_key.fill(0);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anchor_state(generation: u64, anchor_byte: u8) -> QRunV06ExternalAnchorState {
        QRunV06ExternalAnchorState {
            network_id: [1; 32],
            genesis_digest: [2; 32],
            genesis_descriptor_commitment: [3; 32],
            profile_id: [4; 32],
            consensus_fingerprint: [5; 32],
            segment_base_height: 0,
            segment_base_tip: [6; 32],
            checkpoint_anchor: [0; 32],
            manifest_generation: generation,
            manifest_anchor: [anchor_byte; 32],
            canonical_height: generation,
            canonical_tip: [anchor_byte.wrapping_add(1); 32],
            canonical_state_root: [anchor_byte.wrapping_add(2); 32],
            cumulative_chainwork: [anchor_byte.wrapping_add(3); 32],
        }
    }

    fn temporary_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "qrun-v06-node-runtime-{label}-{}",
            std::process::id()
        ))
    }

    #[test]
    fn candidate_listener_policy_accepts_private_and_overlay_addresses_only() {
        assert!(parse_private_endpoint("listener", "127.0.0.1:30303").is_ok());
        assert!(parse_private_endpoint("listener", "10.10.1.2:30303").is_ok());
        assert!(parse_private_endpoint("listener", "100.96.1.2:30303").is_ok());
        assert!(parse_private_endpoint("listener", "[fc00::1]:30303").is_ok());
        assert!(parse_private_endpoint("listener", "[fe80::1]:30303").is_ok());

        assert!(parse_private_endpoint("listener", "8.8.8.8:30303").is_err());
        assert!(parse_private_endpoint("listener", "0.0.0.0:30303").is_err());
        assert!(parse_private_endpoint("listener", "224.0.0.1:30303").is_err());
        assert!(parse_private_endpoint("listener", "10.10.1.2:0").is_err());
        assert!(parse_private_endpoint("listener", "node.example:30303").is_err());
    }

    #[test]
    fn candidate_runtime_refuses_mainnet_or_public_modes_before_loading_any_secret() {
        let path = temporary_path("mode-refusal.json");
        let _ = fs::remove_file(&path);
        let bytes = br#"{"runtime":{"mode":"mainnet","allow_candidate_runtime":true}}"#;
        fs::write(&path, bytes).expect("write temporary runtime config");
        let digest: [u8; 32] = Sha256::digest(bytes).into();

        let result = parse_candidate_runtime_config(&path, &digest);
        let _ = fs::remove_file(&path);
        assert!(result.unwrap_err().contains("private-candidate"));
    }

    #[test]
    fn listener_cannot_alias_provider_anchor_or_pinned_bootstrap_peer() {
        let peers = [QRunV06PinnedBootstrapPeer {
            address: "10.10.1.3:30303".parse().unwrap(),
            noise_static_public_key: [7; 32],
        }];
        let listener: SocketAddr = "127.0.0.1:30303".parse().unwrap();
        let provider: SocketAddr = "10.10.1.1:40401".parse().unwrap();
        let anchor: SocketAddr = "10.10.1.2:40402".parse().unwrap();

        assert!(validate_listener_separation(listener, provider, anchor, &peers).is_ok());
        assert!(validate_listener_separation(provider, provider, anchor, &peers).is_err());
        assert!(validate_listener_separation(anchor, provider, anchor, &peers).is_err());
        assert!(validate_listener_separation(peers[0].address, provider, anchor, &peers).is_err());
    }

    #[test]
    fn q6mj_journal_directory_must_be_separate_from_qfp6_store_tree() {
        let root = temporary_path("separate-runtime-directories");
        let store = root.join("store");
        let journal = root.join("journal");
        assert!(validate_separate_runtime_directories(&store, &journal).is_ok());
        assert!(validate_separate_runtime_directories(&store, &store).is_err());
        assert!(validate_separate_runtime_directories(&store, &store.join("journal")).is_err());
        assert!(validate_separate_runtime_directories(&store, &root).is_err());
    }

    #[test]
    fn qap1_restart_selects_only_the_saved_local_predecessor_or_successor_manifest() {
        let data_directory = temporary_path("qap1-recovery");
        let _ = fs::remove_dir_all(&data_directory);
        let manifests = data_directory.join("manifests");
        fs::create_dir_all(&manifests).expect("create test manifests directory");

        let predecessor = anchor_state(4, 0x44);
        let successor = anchor_state(5, 0x55);
        let expected_external_state = successor.clone();

        let predecessor_name = "qfp6-manifest-00000000000000000004.q6mf";
        fs::write(manifests.join(predecessor_name), b"predecessor fixture")
            .expect("write predecessor marker");
        assert_eq!(
            existing_manifest_anchor(
                &data_directory,
                &expected_external_state,
                Some((&predecessor, &successor)),
            )
            .expect("select signed QAP1 predecessor"),
            Some(predecessor.manifest_anchor)
        );

        let successor_name = "qfp6-manifest-00000000000000000005.q6mf";
        fs::write(manifests.join(successor_name), b"successor fixture")
            .expect("write successor marker");
        assert_eq!(
            existing_manifest_anchor(
                &data_directory,
                &expected_external_state,
                Some((&predecessor, &successor)),
            )
            .expect("select signed QAP1 successor"),
            Some(successor.manifest_anchor)
        );
        assert_eq!(
            existing_manifest_anchor(
                &data_directory,
                &predecessor,
                Some((&predecessor, &successor)),
            )
            .expect("select successor while the independent state is predecessor"),
            Some(successor.manifest_anchor)
        );

        let unrelated = anchor_state(6, 0x66);
        assert!(existing_manifest_anchor(
            &data_directory,
            &unrelated,
            Some((&predecessor, &successor)),
        )
        .is_err());
        fs::write(
            manifests.join("qfp6-manifest-00000000000000000006.q6mf"),
            b"unrelated manifest fixture",
        )
        .expect("write unrelated generation marker");
        assert!(existing_manifest_anchor(
            &data_directory,
            &expected_external_state,
            Some((&predecessor, &successor)),
        )
        .is_err());

        fs::remove_dir_all(&data_directory).expect("remove test manifests directory");
    }
}

mod permissionless;
pub(super) use permissionless::run_permissionless_node;
