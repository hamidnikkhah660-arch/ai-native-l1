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
        run_qfp6_permissionless_mining_supervisor_open,
        run_qfp6_permissionless_mining_supervisor_open_with_q6ar_candidate,
        run_qfp6_permissionless_mining_supervisor_with_bootstrap,
        run_qfp6_permissionless_mining_supervisor_with_bootstrap_and_q6ar_candidate,
        validate_qfp6_pinned_bootstrap_peers, QRunV06PermissionlessMiningSupervisorConfig,
        QRunV06PinnedBootstrapPeer,
    },
    qrun_v06_peer_address_manager_candidate::{PeerAddressSource, QRunV06PeerAddressBookCandidate},
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

/// Permissionless QFP6 must use the current CP-0604 7B/3B policy, never the
/// historical CP-0528 founder-allocation path. This is stricter than the
/// shared snapshot verifier, which retains legacy decoding for compatibility.
fn validate_permissionless_cp0604_genesis(
    genesis: &QRunV06CanonicalExecutionState,
    founder_account: &[u8; 32],
    policy_fingerprint: &[u8; 32],
) -> Result<(), String> {
    let supply = genesis.cp0604_supply().ok_or_else(|| {
        "permissionless QFP6 requires CP-0604 7B founder / 3B mining policy; legacy CP-0528 Genesis is forbidden".to_string()
    })?;
    if genesis.tokenomics().is_some()
        || supply.founder_account() != *founder_account
        || supply.policy_fingerprint() != *policy_fingerprint
        || supply.mining_issued_atoms() != 0
    {
        return Err("permissionless Genesis CP-0604 founder/policy identity or zero pre-mining issuance mismatch".into());
    }
    let founder_balance = genesis
        .unified()
        .ledger()
        .account(founder_account)
        .map_or(0u128, |account| account.balance as u128);
    if founder_balance != supply.founder_genesis_atoms() {
        return Err(
            "permissionless Genesis must credit exactly the CP-0604 7B founder allocation".into(),
        );
    }
    let ledger_total = genesis
        .unified()
        .ledger()
        .total_value()
        .map_err(|error| format!("permissionless Genesis Ledger total failed: {error:?}"))?;
    supply
        .validate_ledger_supply(ledger_total)
        .map_err(|error| {
            format!("permissionless Genesis CP-0604 issuance invariant failed: {error:?}")
        })
}

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
fn requires_public_listener_opt_in(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(address) => {
            let octets = address.octets();
            let shared = octets[0] == 100 && (64..=127).contains(&octets[1]);
            address.is_unspecified()
                || !(address.is_loopback()
                    || address.is_private()
                    || address.is_link_local()
                    || shared)
        }
        std::net::IpAddr::V6(address) => {
            let octets = address.octets();
            let unique_local = octets[0] & 0xfe == 0xfc;
            let link_local = octets[0] == 0xfe && octets[1] & 0xc0 == 0x80;
            address.is_unspecified() || !(address.is_loopback() || unique_local || link_local)
        }
    }
}

fn validate_public_listener_opt_in(runtime: &Value, listen: SocketAddr) -> Result<(), String> {
    if requires_public_listener_opt_in(listen.ip())
        && runtime
            .get("allow_public_listener")
            .and_then(Value::as_bool)
            != Some(true)
    {
        return Err("wildcard/public listen_address requires permissionless_runtime.allow_public_listener=true".into());
    }
    Ok(())
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
    if rows.len() > 64 {
        return Err("bootstrap peer set must contain at most 64 peers".into());
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
    if !peers.is_empty() {
        validate_qfp6_pinned_bootstrap_peers(&peers)
            .map_err(|e| format!("invalid bootstrap peer pins: {e:?}"))?;
    }
    Ok(peers)
}

fn q6ar_candidate_address_book_enabled(cfg: &Value) -> Result<bool, String> {
    match cfg.get("enable_q6ar_candidate_address_book") {
        None => Ok(false),
        Some(Value::Bool(enabled)) => Ok(*enabled),
        Some(_) => Err(
            "permissionless_runtime.enable_q6ar_candidate_address_book must be a boolean".into(),
        ),
    }
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
    // Bind decoded Genesis economics to the exact Q6CP parameters before opening
    // any durable store or network listener. CP-0604 enforces the 7B founder
    // Genesis and 3B mining issuance ceiling/schedule.
    validate_permissionless_cp0604_genesis(
        &genesis,
        &descriptor.founder_account(),
        &descriptor.tokenomics_policy_fingerprint(),
    )?;
    genesis
        .validate_consensus_parameters(&params)
        .map_err(|e| format!("Genesis CP-0604/Q6CP monetary-policy binding failed: {e:?}"))?;
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
    let enable_q6ar_candidate = q6ar_candidate_address_book_enabled(cfg)?;
    let mut q6ar_address_book = if enable_q6ar_candidate {
        let address_book_path = path(base, cfg, "q6ar_candidate_address_book_path")?;
        if address_book_path == data_dir
            || address_book_path.starts_with(&data_dir)
            || data_dir.starts_with(&address_book_path)
            || address_book_path == mempool_dir
            || address_book_path.starts_with(&mempool_dir)
            || mempool_dir.starts_with(&address_book_path)
        {
            return Err("Q6AR candidate address-book path must be separate from data and mempool directories".into());
        }
        let mut book = QRunV06PeerAddressBookCandidate::open(
            &address_book_path,
            descriptor.network_id(),
            descriptor.profile_id(),
        )
        .map_err(|error| format!("Q6AR candidate address-book open failed: {error}"))?;
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| format!("system clock invalid for Q6AR address book: {error}"))?
            .as_millis()
            .try_into()
            .map_err(|_| "system clock exceeds Q6AR millisecond range".to_string())?;
        for peer in &peers {
            book.upsert(
                &peer.address.to_string(),
                PeerAddressSource::Bootstrap,
                now_ms,
            )
            .map_err(|error| {
                format!("cannot seed Q6AR address book from pinned bootstrap peer: {error}")
            })?;
        }
        Some(book)
    } else {
        None
    };
    let q6ar_relay_pins: Vec<[u8; 32]> = if enable_q6ar_candidate {
        peers
            .iter()
            .map(|peer| peer.noise_static_public_key)
            .collect()
    } else {
        Vec::new()
    };
    let listen = endpoint(
        "permissionless_runtime.listen_address",
        req(cfg, "listen_address")?,
        true,
    )?;
    validate_public_listener_opt_in(cfg, listen)?;
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
    if let Some(book) = q6ar_address_book.as_ref() {
        println!("q6ar_candidate_address_book=ENABLED");
        println!("q6ar_candidate_records_at_start={}", book.records().count());
        println!("q6ar_pinned_relay_count={}", q6ar_relay_pins.len());
        println!("q6ar_advertised_keys_auto_trusted=false");
        println!("q6ar_discovered_peers_auto_connected=false");
    } else {
        println!("q6ar_candidate_address_book=DISABLED_DEFAULT");
    }
    let supervisor_report = if peers.is_empty() {
        println!("bootstrap_mode=GENESIS_ROOTED_NO_SEED_PEERS");
        if let Some(book) = q6ar_address_book.as_mut() {
            run_qfp6_permissionless_mining_supervisor_open_with_q6ar_candidate(
                &listener,
                supervisor_config,
                &local_key,
                &q6ar_relay_pins,
                &descriptor.network_id(),
                &descriptor.profile_id(),
                &shutdown,
                &mut runtime,
                &authenticator,
                producer,
                &mut mempool,
                book,
            )
            .map_err(|e| format!("permissionless open-network/Q6AR supervisor stopped: {e}"))?
        } else {
            run_qfp6_permissionless_mining_supervisor_open(
                &listener,
                supervisor_config,
                &local_key,
                &descriptor.network_id(),
                &descriptor.profile_id(),
                &shutdown,
                &mut runtime,
                &authenticator,
                producer,
                &mut mempool,
            )
            .map_err(|e| format!("permissionless open-network supervisor stopped: {e}"))?
        }
    } else {
        let report = if let Some(book) = q6ar_address_book.as_mut() {
            run_qfp6_permissionless_mining_supervisor_with_bootstrap_and_q6ar_candidate(
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
                book,
            )
            .map_err(|e| format!("permissionless bootstrap/Q6AR supervisor stopped: {e}"))?
        } else {
            run_qfp6_permissionless_mining_supervisor_with_bootstrap(
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
            )
            .map_err(|e| format!("permissionless bootstrap/supervisor stopped: {e}"))?
        };
        println!(
            "permissionless_bootstrap_complete={}",
            report.bootstrap_sync.complete
        );
        println!("bootstrap_height={}", report.bootstrap_sync.final_height);
        report.supervisor
    };
    println!("permissionless_inbound_peer_policy=ANONYMOUS_UNAUTHENTICATED_NOISE_XX");
    println!("bootstrap_peer_authentication=PINNED_OUTBOUND_ONLY");
    println!(
        "blocks_committed={}",
        supervisor_report.blocks_durably_committed
    );
    println!("ending_height={}", supervisor_report.ending_height);
    println!(
        "pending_mempool_transactions={}",
        supervisor_report.pending_mempool_transactions
    );
    println!("runtime_status=STOPPED");
    println!("production_authorized=false");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        endpoint, load_peers, q6ar_candidate_address_book_enabled,
        validate_permissionless_cp0604_genesis, validate_public_listener_opt_in,
    };

    #[test]
    fn q6ar_address_book_is_opt_in_and_rejects_non_boolean_flags() {
        assert!(!q6ar_candidate_address_book_enabled(&serde_json::json!({})).unwrap());
        assert!(q6ar_candidate_address_book_enabled(
            &serde_json::json!({"enable_q6ar_candidate_address_book": true})
        )
        .unwrap());
        assert!(!q6ar_candidate_address_book_enabled(
            &serde_json::json!({"enable_q6ar_candidate_address_book": false})
        )
        .unwrap());
        assert!(q6ar_candidate_address_book_enabled(
            &serde_json::json!({"enable_q6ar_candidate_address_book": "true"})
        )
        .is_err());
    }

    #[test]
    fn permissionless_genesis_rejects_legacy_cp0528_and_accepts_only_cp0604_7b3b() {
        use ai_native_l1_pow_bench::{
            qrun_v06_canonical_execution_candidate::QRunV06CanonicalExecutionState,
            qrun_v06_tokenomics_candidate::QRunV06MiningScheduleCandidate,
        };
        const NETWORK: [u8; 32] = [0x61; 32];
        const PROFILE: [u8; 32] = [0x62; 32];
        const FOUNDER: [u8; 32] = [0x63; 32];
        let schedule = QRunV06MiningScheduleCandidate::cp0422_research_candidate();

        let legacy = QRunV06CanonicalExecutionState::cp0528_genesis_candidate(
            NETWORK, PROFILE, FOUNDER, schedule,
        )
        .unwrap();
        assert!(validate_permissionless_cp0604_genesis(&legacy, &FOUNDER, &[0x64; 32]).is_err());

        let current = QRunV06CanonicalExecutionState::cp0604_genesis_candidate(
            NETWORK, PROFILE, FOUNDER, schedule,
        )
        .unwrap();
        let policy_fingerprint = current.cp0604_supply().unwrap().policy_fingerprint();
        assert!(
            validate_permissionless_cp0604_genesis(&current, &FOUNDER, &policy_fingerprint).is_ok()
        );
        assert!(
            validate_permissionless_cp0604_genesis(&current, &[0x65; 32], &policy_fingerprint)
                .is_err()
        );
        assert!(validate_permissionless_cp0604_genesis(&current, &FOUNDER, &[0x66; 32]).is_err());
    }

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

    #[test]
    fn public_listener_bind_requires_explicit_candidate_opt_in() {
        use serde_json::json;
        use std::net::SocketAddr;
        let wildcard: SocketAddr = "0.0.0.0:30333".parse().unwrap();
        assert!(validate_public_listener_opt_in(&json!({}), wildcard).is_err());
        assert!(validate_public_listener_opt_in(
            &json!({"allow_public_listener": false}),
            wildcard
        )
        .is_err());
        assert!(
            validate_public_listener_opt_in(&json!({"allow_public_listener": true}), wildcard)
                .is_ok()
        );
        let private: SocketAddr = "10.0.0.2:30333".parse().unwrap();
        assert!(validate_public_listener_opt_in(&json!({}), private).is_ok());
    }

    #[test]
    fn empty_bootstrap_seed_set_is_accepted_only_as_a_hash_pinned_array() {
        use sha2::{Digest, Sha256};
        use std::{fs, path::PathBuf};
        let path: PathBuf =
            std::env::temp_dir().join(format!("qfp6-empty-seeds-{}.json", std::process::id()));
        fs::write(&path, b"[]").unwrap();
        let digest: [u8; 32] = Sha256::digest(b"[]").into();
        assert!(load_peers(&path, digest).unwrap().is_empty());
        assert!(load_peers(&path, [0xA5; 32]).is_err());
        fs::remove_file(path).unwrap();
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
