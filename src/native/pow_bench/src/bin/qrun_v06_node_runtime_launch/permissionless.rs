//! Separate Genesis-rooted permissionless base-runtime launcher.
//! It deliberately does not load Q6TS, Provider, Q6EA, or QAP1 services.
use super::{
    load_pinned_q6cp_profile, parse_hex32, read_bounded, resolve_path, MAX_BOOTSTRAP_BYTES,
    MAX_CONFIG_BYTES, MAX_GENESIS_SNAPSHOT_BYTES,
};
use ai_native_l1_pow_bench::{
    noise_key_provisioning::load_protected_noise_private_key,
    qrun_v06_canonical_execution_candidate::QRunV06CanonicalExecutionState,
    qrun_v06_history_sync_service_candidate::QRunV06HistorySyncClientConfig,
    qrun_v06_hybrid_auth_candidate::QRunV06HybridTransactionAuthenticator,
    qrun_v06_node_supervisor_candidate::{
        run_qfp6_permissionless_mining_supervisor_with_bootstrap,
        validate_qfp6_pinned_bootstrap_peers, QRunV06PermissionlessMiningSupervisorConfig,
        QRunV06PinnedBootstrapPeer,
    },
    qrun_v06_permissionless_runtime_candidate::QRunV06PermissionlessNodeRuntime,
    qrun_v06_permissionless_service_candidate::QRunV06PermissionlessMempool,
    qrun_v06_profile_pin_candidate::QRunV06VerifiedProfilePin,
    qrun_v06_transaction_mempool_candidate::QRunV06MempoolLimits,
    v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs,
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

const MAX_PEERS_BYTES: u64 = 16 * 1024;

fn req<'a>(v: &'a Value, key: &str) -> Result<&'a str, String> {
    v.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| format!("permissionless_runtime.{key} is required"))
}
fn path(base: &Path, v: &Value, key: &str) -> Result<PathBuf, String> {
    let p = resolve_path(base, req(v, key)?);
    if !p.is_absolute() {
        return Err(format!(
            "permissionless_runtime.{key} must resolve to an absolute path"
        ));
    }
    Ok(p)
}
fn endpoint(name: &str, text: &str, allow_unspecified: bool) -> Result<SocketAddr, String> {
    let a: SocketAddr = text
        .parse()
        .map_err(|_| format!("{name} must be a numeric SocketAddr"))?;
    if a.port() == 0 || a.ip().is_multicast() || (!allow_unspecified && a.ip().is_unspecified()) {
        return Err(format!("{name} is not a valid unicast endpoint"));
    }
    Ok(a)
}
fn load_peers(
    path: &Path,
    expected_sha: [u8; 32],
) -> Result<Vec<QRunV06PinnedBootstrapPeer>, String> {
    let bytes = read_bounded(path, MAX_PEERS_BYTES, "permissionless bootstrap peer set")?;
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    if digest != expected_sha {
        return Err(
            "bootstrap peer set SHA-256 mismatch against independently pinned config".into(),
        );
    }
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("invalid bootstrap peer JSON: {e}"))?;
    let rows = value
        .as_array()
        .ok_or("bootstrap peer set must be a JSON array")?;
    if rows.is_empty() || rows.len() > 64 {
        return Err("bootstrap peer set must contain 1..=64 peers".into());
    }
    let mut peers = Vec::with_capacity(rows.len());
    for (i, row) in rows.iter().enumerate() {
        let address = endpoint(
            &format!("bootstrap peer {i}"),
            row.get("address")
                .and_then(Value::as_str)
                .ok_or("bootstrap peer address missing")?,
            false,
        )?;
        let key = row
            .get("noise_static_public_key")
            .and_then(Value::as_str)
            .ok_or("bootstrap peer Noise key missing")?;
        peers.push(QRunV06PinnedBootstrapPeer {
            address,
            noise_static_public_key: parse_hex32("bootstrap peer Noise key", key)?,
        });
    }
    validate_qfp6_pinned_bootstrap_peers(&peers)
        .map_err(|e| format!("invalid bootstrap peer pins: {e:?}"))?;
    Ok(peers)
}

fn trusted_manifest_anchor(cfg: &Value, data_dir: &Path) -> Result<Option<[u8; 32]>, String> {
    let manifests = data_dir.join("manifests");
    let entries = match fs::symlink_metadata(&manifests) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0usize,
        Err(e) => return Err(format!("cannot inspect existing manifest directory: {e}")),
        Ok(meta) if meta.file_type().is_symlink() || !meta.is_dir() => {
            return Err("manifest path must be a real directory".into())
        }
        Ok(_) => fs::read_dir(&manifests)
            .map_err(|e| format!("cannot read manifest directory: {e}"))?
            .count(),
    };
    match (entries > 0, cfg.get("trusted_manifest_anchor")) {
        (true, Some(value)) => {
            let text = value.as_str().filter(|s| !s.trim().is_empty()).ok_or("trusted_manifest_anchor must be a non-empty 64-hex string")?;
            Ok(Some(parse_hex32("trusted_manifest_anchor", text)?))
        }
        (true, None) => Err("existing durable history requires independently pinned permissionless_runtime.trusted_manifest_anchor; refusing local-only rollback trust".into()),
        (false, Some(_)) => Err("trusted_manifest_anchor must be omitted for a fresh Genesis-only data directory".into()),
        (false, None) => Ok(None),
    }
}
pub fn run_permissionless_node(
    config_path: &Path,
    expected_config_sha: &[u8; 32],
) -> Result<(), String> {
    let bytes = read_bounded(config_path, MAX_CONFIG_BYTES, "permissionless config")?;
    let actual: [u8; 32] = Sha256::digest(&bytes).into();
    if &actual != expected_config_sha {
        return Err(
            "permissionless config digest mismatch; supply the independently pinned SHA-256".into(),
        );
    }
    let root: Value = serde_json::from_slice(&bytes)
        .map_err(|e| format!("invalid permissionless config JSON: {e}"))?;
    let cfg = root
        .get("permissionless_runtime")
        .ok_or("permissionless_runtime section missing")?;
    if req(cfg, "mode")? != "permissionless-full-history-candidate" {
        return Err("permissionless_runtime.mode must be permissionless-full-history-candidate; production Mainnet remains separately gated".into());
    }
    if cfg.get("allow_candidate_runtime").and_then(Value::as_bool) != Some(true) {
        return Err("permissionless_runtime.allow_candidate_runtime=true is required".into());
    }
    let base = config_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let profile_path = path(base, cfg, "q6pn_profile_pin_path")?;
    let profile_commitment = parse_hex32(
        "q6pn_profile_pin_commitment",
        req(cfg, "q6pn_profile_pin_commitment")?,
    )?;
    let profile_bytes = read_bounded(&profile_path, MAX_BOOTSTRAP_BYTES, "Q6PN profile pin")?;
    let verified_pin = QRunV06VerifiedProfilePin::decode(&profile_bytes, profile_commitment)
        .map_err(|e| format!("Q6PN independent commitment verification failed: {e:?}"))?;
    let descriptor = verified_pin.descriptor();
    let q6cp_path = path(base, cfg, "q6cp_profile_path")?;
    let q6cp_sha = parse_hex32("q6cp_profile_sha256", req(cfg, "q6cp_profile_sha256")?)?;
    let (_, profile) = load_pinned_q6cp_profile(&q6cp_path, &q6cp_sha, descriptor)?;
    let params = profile.parameters().clone();
    let genesis_path = path(base, cfg, "genesis_snapshot_path")?;
    let genesis_sha = parse_hex32(
        "genesis_snapshot_sha256",
        req(cfg, "genesis_snapshot_sha256")?,
    )?;
    let genesis_bytes = read_bounded(
        &genesis_path,
        MAX_GENESIS_SNAPSHOT_BYTES,
        "QFP6 Genesis snapshot",
    )?;
    let digest: [u8; 32] = Sha256::digest(&genesis_bytes).into();
    if digest != genesis_sha {
        return Err("Genesis snapshot SHA-256 mismatch".into());
    }
    super::super::verify_genesis_snapshot(
        &genesis_bytes,
        &descriptor.network_id(),
        &descriptor.profile_id(),
        &descriptor.founder_account(),
        &descriptor.consensus_fingerprint(),
        &descriptor.tokenomics_policy_fingerprint(),
        descriptor,
    )?;
    let genesis = QRunV06CanonicalExecutionState::decode_snapshot(
        &genesis_bytes,
        &descriptor.network_id(),
        &descriptor.profile_id(),
    )
    .map_err(|e| format!("Genesis snapshot decode failed: {e:?}"))?;
    let data_dir = path(base, cfg, "data_directory")?;
    let mempool_dir = path(base, cfg, "mempool_directory")?;
    if data_dir == mempool_dir
        || data_dir.starts_with(&mempool_dir)
        || mempool_dir.starts_with(&data_dir)
    {
        return Err(
            "data_directory and mempool_directory must be separate, non-nested directories".into(),
        );
    }
    let peer_path = path(base, cfg, "bootstrap_peers_path")?;
    let peer_sha = parse_hex32(
        "bootstrap_peers_sha256",
        req(cfg, "bootstrap_peers_sha256")?,
    )?;
    let peers = load_peers(&peer_path, peer_sha)?;
    let listen = endpoint(
        "permissionless_runtime.listen_address",
        req(cfg, "listen_address")?,
        true,
    )?;
    if peers.iter().any(|p| p.address == listen) {
        return Err("P2P listener cannot alias a bootstrap peer".into());
    }
    let listener = TcpListener::bind(listen)
        .map_err(|e| format!("permissionless P2P listener bind failed: {e}"))?;
    let key_path = path(base, cfg, "node_noise_private_key_path")?;
    let local_key = Zeroizing::new(
        load_protected_noise_private_key(&key_path, &descriptor.network_id())
            .map_err(|e| format!("protected local Noise key unavailable: {e:?}"))?,
    );
    let authenticator = QRunV06HybridTransactionAuthenticator::new(LibcruxMlDsa65VerifierCandidate);
    let trusted_anchor = trusted_manifest_anchor(cfg, &data_dir)?;
    let mut runtime = QRunV06PermissionlessNodeRuntime::open(
        &data_dir,
        genesis,
        params,
        &authenticator,
        trusted_anchor,
        &verified_pin,
    )
    .map_err(|e| format!("Genesis-rooted permissionless durable store open failed: {e:?}"))?;
    let mut mempool =
        QRunV06PermissionlessMempool::open(&mempool_dir, QRunV06MempoolLimits::default())
            .map_err(|e| format!("Q6MJ mempool journal open failed: {e:?}"))?;
    let producer = parse_hex32("producer_account", req(cfg, "producer_account")?)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("system clock invalid: {e}"))?
        .as_secs();
    let current_timestamp = runtime
        .fork_choice_snapshot()
        .map_err(|e| format!("canonical state snapshot unavailable for Q6MJ restore: {e:?}"))?
        .canonical_state()
        .last_timestamp();
    let candidate_timestamp = now.max(current_timestamp.saturating_add(1));
    mempool
        .restore(&runtime, &authenticator, producer, candidate_timestamp)
        .map_err(|e| format!("Q6MJ restore/revalidation failed: {e:?}"))?;
    let mut supervisor_config = QRunV06PermissionlessMiningSupervisorConfig::default();
    if let Some(n) = cfg.get("max_nonce_attempts_per_block") {
        supervisor_config.max_nonce_attempts_per_block = n
            .as_u64()
            .ok_or("max_nonce_attempts_per_block must be an unsigned integer")?;
    }
    supervisor_config
        .validate()
        .map_err(|e| format!("permissionless supervisor config invalid: {e:?}"))?;
    let shutdown = AtomicBool::new(false);
    println!("QFP6 PERMISSIONLESS BASE RUNTIME: STARTING (candidate qualification only)");
    println!("network_id={}", super::super::hex(&descriptor.network_id()));
    println!("profile_id={}", super::super::hex(&descriptor.profile_id()));
    println!(
        "genesis_snapshot_sha256={}",
        super::super::hex(&genesis_sha)
    );
    println!("listener={listen}");
    println!("bootstrap_peer_count={}", peers.len());
    println!("Q6TS=NOT_REQUIRED; Provider=NOT_REQUIRED; Q6EA=NOT_REQUIRED; QAP1=NOT_REQUIRED");
    let result = run_qfp6_permissionless_mining_supervisor_with_bootstrap(
        &listener,
        supervisor_config,
        &local_key,
        &peers,
        &descriptor.network_id(),
        &descriptor.profile_id(),
        &shutdown,
        &mut runtime,
        &authenticator,
        producer,
        &mut mempool,
        QRunV06HistorySyncClientConfig::default(),
    );
    let report = result.map_err(|e| format!("permissionless bootstrap/supervisor stopped: {e}"))?;
    println!(
        "permissionless_bootstrap_complete={}",
        report.bootstrap_sync.complete
    );
    println!("bootstrap_height={}", report.bootstrap_sync.final_height);
    println!(
        "blocks_committed={}",
        report.supervisor.blocks_durably_committed
    );
    println!("ending_height={}", report.supervisor.ending_height);
    println!(
        "pending_mempool_transactions={}",
        report.supervisor.pending_mempool_transactions
    );
    println!("runtime_status=STOPPED");
    println!("production_authorized=false");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::endpoint;

    #[test]
    fn permissionless_listener_accepts_wildcard_bind_but_peer_endpoints_must_be_specific() {
        assert_eq!(
            endpoint("listen", "0.0.0.0:30333", true).unwrap().port(),
            30333
        );
        assert!(endpoint("peer", "0.0.0.0:30333", false).is_err());
        assert!(endpoint("peer", "239.1.1.1:30333", false).is_err());
        assert!(endpoint("peer", "127.0.0.1:30333", false).is_ok());
        assert!(endpoint("listen", "0.0.0.0:0", true).is_err());
    }
}

#[cfg(test)]
mod manifest_anchor_tests {
    use super::trusted_manifest_anchor;
    use serde_json::json;
    use std::{fs, path::PathBuf};

    fn test_dir() -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("qfp6-permissionless-anchor-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn existing_manifest_history_requires_independently_pinned_anchor() {
        let dir = test_dir();
        assert_eq!(trusted_manifest_anchor(&json!({}), &dir).unwrap(), None);
        fs::create_dir_all(dir.join("manifests")).unwrap();
        fs::write(
            dir.join("manifests")
                .join("qfp6-manifest-00000000000000000000.q6mf"),
            b"fixture",
        )
        .unwrap();
        assert!(trusted_manifest_anchor(&json!({}), &dir).is_err());
        let cfg = json!({"trusted_manifest_anchor": "1111111111111111111111111111111111111111111111111111111111111111"});
        assert_eq!(
            trusted_manifest_anchor(&cfg, &dir).unwrap(),
            Some([0x11; 32])
        );
        fs::remove_dir_all(dir).unwrap();
    }
}
