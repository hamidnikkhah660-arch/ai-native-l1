//! Local-only, two-process Q6AR pull probe. Never binds beyond loopback.
use ai_native_l1_pow_bench::{
    noise_key_provisioning::load_protected_noise_private_key,
    qrun_v06_bootstrap_trust_domain_candidate::BootstrapTrustDomainPolicy,
    qrun_v06_history_sync_service_candidate::{
        pull_q6ar_candidates_from_pinned_peer, QRunV06HistorySyncClientConfig,
    },
    qrun_v06_peer_address_manager_candidate::{PeerAddressSource, QRunV06PeerAddressBookCandidate},
    qrun_v06_peer_address_relay_candidate::{
        decode_q6ar_pull_request, encode_q6ar_pull_response, Q6arAddress, Q6arAdvertisement,
    },
    qrun_v06_peer_listener_candidate::{
        serve_qfp6_noise_listener_with_history_and_q6ar, QRunV06PeerListenerConfig,
    },
};
use std::{
    env,
    net::{SocketAddr, TcpListener},
    path::PathBuf,
    sync::atomic::AtomicBool,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const NETWORK: [u8; 32] = [0xA1; 32];
const PROFILE: [u8; 32] = [0xA2; 32];
const DOMAIN: [u8; 32] = [0xA3; 32];
const CANDIDATE_KEY: [u8; 32] = [0xA4; 32];

fn now_ms() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("system clock error: {e}"))?
        .as_millis()
        .try_into()
        .map_err(|_| "system clock exceeds u64 millisecond range".to_string())
}

fn parse_hex32(input: &str) -> Result<[u8; 32], String> {
    if input.len() != 64 {
        return Err("relay public key must be exactly 64 hexadecimal characters".into());
    }
    let mut out = [0u8; 32];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&input[index * 2..index * 2 + 2], 16)
            .map_err(|_| "relay public key contains invalid hexadecimal".to_string())?;
    }
    if out.iter().all(|byte| *byte == 0) {
        return Err("relay public key cannot be all zero".into());
    }
    Ok(out)
}

fn loopback_address(input: &str) -> Result<SocketAddr, String> {
    let address: SocketAddr = input
        .parse()
        .map_err(|_| "address must be IP:PORT".to_string())?;
    if !address.ip().is_loopback() {
        return Err("probe is restricted to loopback TCP addresses".into());
    }
    Ok(address)
}

fn server(address_text: &str, key_path: &str, client_public_hex: &str) -> Result<(), String> {
    let address = loopback_address(address_text)?;
    let key_path = PathBuf::from(key_path);
    let client_public = parse_hex32(client_public_hex)?;
    let mut local_key = load_protected_noise_private_key(&key_path, &NETWORK)
        .map_err(|e| format!("cannot load DPAPI-protected relay key: {e}"))?;

    let listener = TcpListener::bind(address).map_err(|e| format!("loopback bind failed: {e}"))?;
    println!(
        "Q6AR_PROBE_SERVER_READY address={}",
        listener.local_addr().map_err(|e| e.to_string())?
    );

    let issued_at_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    let advertisement = Q6arAdvertisement {
        network_id: NETWORK,
        profile_id: PROFILE,
        issued_at_secs,
        ttl_secs: 300,
        addresses: vec![Q6arAddress {
            endpoint: "8.8.8.8:8333"
                .parse()
                .map_err(|e| format!("test endpoint: {e}"))?,
            noise_static_public_key: CANDIDATE_KEY,
        }],
    };

    let shutdown = AtomicBool::new(false);
    let mut on_q6ar = |_received| Ok(());
    let mut on_application_frame = |_guard: &mut _, frame: &[u8]| {
        let request = decode_q6ar_pull_request(frame, &NETWORK, &PROFILE)
            .map_err(|e| format!("Q6AR pull request rejected: {e}"))?;
        let response = encode_q6ar_pull_response(&request, Some(&advertisement))
            .map_err(|e| format!("Q6AR pull response encode failed: {e}"))?;
        Ok(vec![response])
    };
    let report = serve_qfp6_noise_listener_with_history_and_q6ar(
        &listener,
        QRunV06PeerListenerConfig {
            max_sessions: 1,
            max_requests_per_session: 1,
            max_failed_handshakes: 8,
            accept_poll_interval: Duration::from_millis(50),
        },
        &local_key,
        &[client_public],
        &NETWORK,
        &PROFILE,
        &shutdown,
        &mut on_q6ar,
        &mut on_application_frame,
    )
    .map_err(|e| format!("Q6AR probe listener failed: {e}"))?;

    println!(
        "Q6AR_PROBE_SERVER_DONE pinned_sessions={} unverified_sessions={} requests={} responses={} handler_failures={} stop_reason={:?}",
        report.stats.authenticated_sessions,
        report.stats.unverified_peer_sessions,
        report.stats.requests_received,
        report.stats.responses_written,
        report.stats.handler_failures,
        report.stop_reason
    );
    local_key.fill(0);
    if report.stats.authenticated_sessions != 1
        || report.stats.unverified_peer_sessions != 0
        || report.stats.requests_received != 1
        || report.stats.responses_written != 1
        || report.stats.handler_failures != 0
    {
        return Err("server did not complete exactly one clean Q6AR pull exchange".into());
    }
    Ok(())
}

fn client(
    address_text: &str,
    local_key_path: &str,
    relay_public_hex: &str,
    address_book_path: &str,
) -> Result<(), String> {
    let address = loopback_address(address_text)?;
    if address.port() == 0 {
        return Err("client target must use the server's assigned nonzero loopback port".into());
    }
    let relay_public = parse_hex32(relay_public_hex)?;
    let mut local_key = load_protected_noise_private_key(local_key_path, &NETWORK)
        .map_err(|e| format!("cannot load DPAPI-protected client key: {e}"))?;
    let trust_domains = BootstrapTrustDomainPolicy::new([(relay_public, DOMAIN)], 8, 1)
        .map_err(|e| format!("trust-domain policy rejected: {e:?}"))?;
    let mut book = QRunV06PeerAddressBookCandidate::open(address_book_path, NETWORK, PROFILE)
        .map_err(|e| format!("address book open failed: {e:?}"))?;

    book.bind_trust_domain_registry(&trust_domains, now_ms()?)
        .map_err(|e| format!("address-book trust binding failed: {e:?}"))?;

    let accepted = pull_q6ar_candidates_from_pinned_peer(
        address,
        &local_key,
        &relay_public,
        &NETWORK,
        &PROFILE,
        QRunV06HistorySyncClientConfig {
            connect_timeout: Duration::from_secs(3),
            io_timeout: Duration::from_secs(5),
            ..QRunV06HistorySyncClientConfig::default()
        },
        None,
        &mut book,
        &trust_domains,
    )
    .map_err(|e| format!("pinned Q6AR pull failed: {e}"))?;

    let candidate = book
        .records()
        .next()
        .ok_or("expected one candidate record after Q6AR pull")?;
    if accepted != 1
        || book.records().count() != 1
        || candidate.address != "8.8.8.8:8333"
        || candidate.source != PeerAddressSource::Gossip
        || candidate.advertised_noise_static_key != Some(CANDIDATE_KEY)
        || candidate.relay_static_public_key != Some(relay_public)
        || !candidate.relay_static_key_pinned
        || candidate.operator_approved_noise_static_key.is_some()
        || !book
            .approved_peer_pins(now_ms()?.saturating_add(1), 8)
            .is_empty()
    {
        local_key.fill(0);
        return Err(
            "pulled record did not remain candidate-only under the pinned relay policy".into(),
        );
    }

    println!(
        "Q6AR_PROBE_CLIENT_PASS accepted={} address={} source=Gossip relay_pin_verified=true operator_approved=false approved_outbound_count=0",
        accepted,
        candidate.address
    );
    local_key.fill(0);
    Ok(())
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("server") if args.len() == 4 => server(&args[1], &args[2], &args[3]),
        Some("client") if args.len() == 5 => {
            client(&args[1], &args[2], &args[3], &args[4])
        }
        _ => Err(
            "usage: q6ar_process_probe server 127.0.0.1:0 <relay-dpapi-key> <client-public-key-hex> | client 127.0.0.1:<assigned-port> <client-dpapi-key> <relay-public-key-hex> <address-book-path>".into(),
        ),
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("Q6AR_PROBE_ERROR: {error}");
        std::process::exit(2);
    }
}
