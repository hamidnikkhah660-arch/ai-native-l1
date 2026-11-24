use ai_native_l1_pow_bench::{
    qrun_v06_history_sync_service_candidate::{
        pull_q6pd_peer_records_from_pinned_peer, QRunV06HistorySyncClientConfig,
    },
    qrun_v06_peer_discovery_store_candidate::Q6pdPeerRecordStore,
    qrun_v06_q6pd_session_candidate::run_q6pd_persistent_peer_session_worker,
};
use snow::params::NoiseParams;
use std::{
    env,
    net::{SocketAddr, ToSocketAddrs},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, RwLock,
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

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
        let pair = std::str::from_utf8(pair).map_err(|_| format!("{name} is not ASCII"))?;
        out[i] = u8::from_str_radix(pair, 16).map_err(|_| format!("{name} is malformed"))?;
    }
    Ok(out)
}

fn now_ms() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("system clock is before Unix epoch: {e}"))?
        .as_millis()
        .try_into()
        .map_err(|_| "system clock exceeds millisecond range".into())
}

fn parse_address(host: &str, port: u16) -> Result<SocketAddr, String> {
    let addresses = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("Seed DNS resolution failed: {e}"))?;
    addresses
        .filter(|address| address.ip().is_ipv4())
        .next()
        .or_else(|| (host, port).to_socket_addrs().ok()?.next())
        .ok_or_else(|| "Seed DNS returned no usable address".into())
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let host = value(&args, "--host")?;
    let port = value(&args, "--port")?
        .parse::<u16>()
        .map_err(|_| "port is invalid")?;
    let network_id = parse_hex32("network ID", &value(&args, "--network-id-hex")?)?;
    let profile_id = parse_hex32("profile ID", &value(&args, "--profile-id-hex")?)?;
    let remote_key = parse_hex32(
        "remote Noise public key",
        &value(&args, "--remote-noise-key-hex")?,
    )?;
    let session_seconds = value(&args, "--session-seconds")?
        .parse::<u64>()
        .map_err(|_| "session duration is invalid")?;
    if port != 443 || !(65..=120).contains(&session_seconds) {
        return Err("port must be 443 and session duration must be 65..=120 seconds".into());
    }

    let address = parse_address(&host, port)?;
    println!("HOSTED_JOINER_RUNNER=github-windows-2022");
    println!("SEED_DNS_RESOLVED=PASS");
    println!(
        "SEED_ADDRESS_FAMILY={}",
        if address.is_ipv4() { "IPv4" } else { "IPv6" }
    );
    println!("CLIENT_NOISE_IDENTITY=EPHEMERAL_NOT_SAVED");
    println!("LOCAL_SELF_ANNOUNCEMENT=DISABLED_NAT_ONLY_MODE");

    let params: NoiseParams = "Noise_XX_25519_ChaChaPoly_SHA256"
        .parse()
        .map_err(|e: snow::Error| format!("Noise parameters rejected: {e}"))?;
    let ephemeral = snow::Builder::new(params)
        .generate_keypair()
        .map_err(|e| format!("ephemeral Noise key generation failed: {e}"))?;
    let local_private: [u8; 32] = ephemeral
        .private
        .as_slice()
        .try_into()
        .map_err(|_| "ephemeral Noise private key has unexpected length")?;

    let store_path: PathBuf = env::temp_dir().join(format!(
        "qfp6-cp0849-q6pd-joiner-{}.json",
        std::process::id()
    ));
    let mut store = Q6pdPeerRecordStore::open(&store_path, network_id, profile_id, now_ms()?)
        .map_err(|e| format!("temporary Q6PD record store could not open: {e}"))?;

    let discovery_config = QRunV06HistorySyncClientConfig {
        connect_timeout: Duration::from_secs(5),
        io_timeout: Duration::from_secs(15),
        max_blocks_per_page: 1,
        max_bytes_per_page: 64 * 1024,
        max_pages: 1,
        max_rounds: 1,
    };
    let pull = pull_q6pd_peer_records_from_pinned_peer(
        address,
        &local_private,
        &remote_key,
        &network_id,
        &profile_id,
        discovery_config,
        Some(&host),
        ai_native_l1_pow_bench::qrun_v06_peer_discovery_candidate::Q6PD_MAX_RECORDS_PER_FRAME
            as u16,
        &mut store,
    )
    .map_err(|e| format!("Q6PD signed-record pull failed: {e}"))?;

    let seed_identity_present = pull
        .accepted_records
        .iter()
        .any(|record| record.noise_static_public_key == remote_key);
    println!("Q6PD_RECORDS_RECEIVED={}", pull.records_received);
    println!("Q6PD_RECORDS_INSERTED={}", pull.records_inserted);
    println!("Q6PD_RECORDS_UPDATED={}", pull.records_updated);
    println!("Q6PD_RECORDS_DUPLICATE={}", pull.records_duplicate);
    println!("Q6PD_RECORDS_REJECTED={}", pull.records_rejected);
    println!(
        "Q6PD_PINNED_SEED_IDENTITY_IN_INVENTORY={}",
        seed_identity_present
    );
    if pull.records_received == 0 || pull.accepted_records.is_empty() || !seed_identity_present {
        return Err(
            "Seed did not return an accepted signed Q6PD record bound to its pinned Noise key"
                .into(),
        );
    }
    println!("Q6PD_SIGNED_RECORD_PULL=PASS");

    drop(store);

    let shutdown = Arc::new(AtomicBool::new(false));
    let worker_shutdown = Arc::clone(&shutdown);
    let local_announcement = Arc::new(RwLock::new(None));
    let worker = thread::spawn(move || {
        run_q6pd_persistent_peer_session_worker(
            address,
            Some(host),
            local_private,
            None,
            remote_key,
            network_id,
            profile_id,
            local_announcement,
            &worker_shutdown,
        );
    });

    println!("Q6PD_SESSION_TEST_SECONDS={session_seconds}");
    thread::sleep(Duration::from_secs(session_seconds));
    shutdown.store(true, Ordering::Release);
    worker
        .join()
        .map_err(|_| "Q6PD persistent-session worker panicked".to_string())?;
    println!("Q6PD_JOINER_WORKER_STOPPED=PASS");
    println!("TEST_SCOPE=SIGNED_Q6PD_INVENTORY_PULL_AND_EPHEMERAL_PERSISTENT_HEARTBEAT");
    println!("SCOPE_LIMIT=NOT_A_FULL_CHAIN_STATE_OR_CONSENSUS_NODE");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("QFP6_PUBLIC_Q6PD_JOINER=FAILED");
        eprintln!("reason={error}");
        std::process::exit(2);
    }
}
