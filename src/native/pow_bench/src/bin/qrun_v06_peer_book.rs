//! Operator-controlled QFP6 peer discovery, candidate review, and trust-pin management.
//!
//! The optional Q6AR pull contacts only one operator-supplied relay with its exact Noise key pinned.
//! Pulled addresses remain unapproved candidates. Verify endpoint and Noise-key fingerprints through
//! an independent channel before approving them. Approval authorizes a later pinned outbound
//! connection, not consensus trust.
use ai_native_l1_pow_bench::{
    noise_key_provisioning::load_protected_noise_private_key,
    qrun_v06_bootstrap_trust_domain_candidate::BootstrapTrustDomainPolicy,
    qrun_v06_history_sync_service_candidate::{
        pull_q6ar_candidates_from_pinned_peer, QRunV06HistorySyncClientConfig,
    },
    qrun_v06_peer_address_manager_candidate::{
        PeerAddressBookError, PeerAddressSource, QRunV06PeerAddressBookCandidate,
    },
};
use std::{
    env,
    net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs},
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

fn hex32(name: &str, text: &str) -> Result<[u8; 32], String> {
    if text.len() != 64 || !text.is_ascii() || text.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(format!(
            "{name} must be 64 lowercase hexadecimal characters"
        ));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16)
            .map_err(|_| format!("{name} contains non-hexadecimal characters"))?;
    }
    if out == [0; 32] {
        return Err(format!("{name} must not be zero"));
    }
    Ok(out)
}
fn hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(TABLE[(byte >> 4) as usize] as char);
        out.push(TABLE[(byte & 15) as usize] as char);
    }
    out
}
fn now_ms() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock invalid: {error}"))?
        .as_millis()
        .try_into()
        .map_err(|_| "system clock exceeds millisecond range".into())
}

fn ipv4_in_prefix(address: Ipv4Addr, network: [u8; 4], prefix: u8) -> bool {
    let value = u32::from_be_bytes(address.octets());
    let base = u32::from_be_bytes(network);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    value & mask == base & mask
}

fn is_public_unicast(ip: IpAddr) -> bool {
    let IpAddr::V4(address) = ip else {
        // This helper deliberately limits DNS relay resolution to public IPv4 answers.
        return false;
    };
    !(address.is_private()
        || address.is_loopback()
        || address.is_link_local()
        || address.is_unspecified()
        || address.is_multicast()
        || address == Ipv4Addr::BROADCAST
        || ipv4_in_prefix(address, [0, 0, 0, 0], 8)
        || ipv4_in_prefix(address, [100, 64, 0, 0], 10)
        || ipv4_in_prefix(address, [192, 0, 0, 0], 24)
        || ipv4_in_prefix(address, [192, 0, 2, 0], 24)
        || ipv4_in_prefix(address, [192, 88, 99, 0], 24)
        || ipv4_in_prefix(address, [198, 18, 0, 0], 15)
        || ipv4_in_prefix(address, [198, 51, 100, 0], 24)
        || ipv4_in_prefix(address, [203, 0, 113, 0], 24)
        || ipv4_in_prefix(address, [240, 0, 0, 0], 4))
}

/// Numeric globally-routable IP:port is accepted directly. DNS is limited to a public
/// FQDN on TCP/443, with all resolved answers checked before a TLS-SNI-pinned dial.
fn resolve_relay_endpoint(text: &str) -> Result<(SocketAddr, Option<String>), String> {
    if let Ok(address) = text.parse::<SocketAddr>() {
        if address.port() == 0 || !is_public_unicast(address.ip()) {
            return Err("relay endpoint must be a globally routable IPv4:port".into());
        }
        return Ok((address, None));
    }

    let (host, port_text) = text
        .rsplit_once(':')
        .ok_or("relay must be numeric IPv4:port or public FQDN:443")?;
    let port = port_text
        .parse::<u16>()
        .map_err(|_| "relay DNS port is invalid")?;
    if port != 443
        || host.is_empty()
        || host.len() > 253
        || host.ends_with('.')
        || host.contains(':')
        || host.starts_with('[')
        || host.ends_with(']')
        || host.parse::<IpAddr>().is_ok()
        || host.to_ascii_lowercase() != host
        || host
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return Err("DNS relay must be a lowercase public FQDN on TCP/443".into());
    }
    let lower = host.to_ascii_lowercase();
    if lower == "localhost"
        || [
            ".localhost",
            ".local",
            ".internal",
            ".test",
            ".invalid",
            ".example",
        ]
        .iter()
        .any(|suffix| lower.ends_with(suffix))
    {
        return Err("relay hostname is not an accepted public FQDN".into());
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2
        || !labels.iter().all(|label| {
            let bytes = label.as_bytes();
            !bytes.is_empty()
                && bytes.len() <= 63
                && bytes[0].is_ascii_alphanumeric()
                && bytes[bytes.len() - 1].is_ascii_alphanumeric()
                && bytes
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        })
    {
        return Err("relay hostname is not a valid public FQDN".into());
    }

    let mut addresses: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|error| format!("relay DNS resolution failed: {error}"))?
        .collect();
    addresses.sort_unstable();
    addresses.dedup();
    if addresses.is_empty() || addresses.len() > 16 {
        return Err("relay DNS must resolve to 1..=16 addresses".into());
    }
    if addresses
        .iter()
        .any(|address| address.port() != port || !is_public_unicast(address.ip()))
    {
        return Err("relay DNS returned a non-public or non-IPv4 answer; rejected".into());
    }
    Ok((addresses[0], Some(host.to_owned())))
}
fn usage() -> &'static str {
    concat!(
        "Usage:\n",
        "  qrun_v06_peer_book list <book_path> <network_id_hex> <profile_id_hex>\n",
        "  qrun_v06_peer_book pull <book_path> <network_id_hex> <profile_id_hex> <relay_ip:port|public-fqdn:443> <relay_noise_public_key_hex> <trust_domain_id_hex> <local_dpapi_noise_key_path>\n",
        "  qrun_v06_peer_book approve <book_path> <network_id_hex> <profile_id_hex> <numeric_ip:port> <noise_static_public_key_hex>\n",
        "  qrun_v06_peer_book revoke <book_path> <network_id_hex> <profile_id_hex> <numeric_ip:port>\n\n",
        "pull contacts only the supplied pinned relay and stores Q6AR results as unapproved candidates. ",
        "approve adds an explicit persistent outbound key pin; it does not dial peers."
    )
}
fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() < 4 {
        return Err(usage().into());
    }
    let action = args[0].as_str();
    let path = PathBuf::from(&args[1]);
    let network = hex32("network_id", &args[2])?;
    let profile = hex32("profile_id", &args[3])?;
    let mut book = QRunV06PeerAddressBookCandidate::open(path, network, profile)
        .map_err(|error| format!("address book open failed: {error}"))?;
    match action {
        "list" if args.len() == 4 => {
            println!("network_id={}", hex(&network));
            println!("profile_id={}", hex(&profile));
            for record in book.records() {
                println!("peer={}", record.address);
                println!(
                    "  source={:?} first_seen_ms={} last_seen_ms={}",
                    record.source, record.first_seen_ms, record.last_seen_ms
                );
                println!(
                    "  advertised_noise_key={}",
                    record
                        .advertised_noise_static_key
                        .map(|key| hex(&key))
                        .unwrap_or_else(|| "none".into())
                );
                println!(
                    "  relay_noise_key={} relay_pinned={}",
                    record
                        .relay_static_public_key
                        .map(|key| hex(&key))
                        .unwrap_or_else(|| "none".into()),
                    record.relay_static_key_pinned
                );
                println!(
                    "  advertisement_expires_at_ms={}",
                    record.advertisement_expires_at_ms
                );
                println!(
                    "  operator_approved_noise_key={}",
                    record
                        .operator_approved_noise_static_key
                        .map(|key| hex(&key))
                        .unwrap_or_else(|| "none".into())
                );
                println!(
                    "  operator_approved_at_ms={} failures={} retry_after_ms={} banned_until_ms={}",
                    record.operator_approved_at_ms,
                    record.failures,
                    record.retry_after_ms,
                    record.banned_until_ms
                );
            }
            println!("records={}", book.records().count());
        }
        "pull" if args.len() == 8 => {
            let relay_noise_key = hex32("relay_noise_static_public_key", &args[5])?;
            let trust_domain_id = hex32("trust_domain_id", &args[6])?;
            let (relay_address, tls_server_name) = resolve_relay_endpoint(&args[4])?;
            let trust_domains =
                BootstrapTrustDomainPolicy::new([(relay_noise_key, trust_domain_id)], 32, 1)
                    .map_err(|error| {
                        format!("operator relay trust-domain policy rejected: {error:?}")
                    })?;
            book.bind_trust_domain_registry(&trust_domains, now_ms()?)
                .map_err(|error| format!("address-book trust-domain binding failed: {error}"))?;

            let mut local_key = load_protected_noise_private_key(&args[7], &network)
                .map_err(|error| format!("cannot load local DPAPI-protected Noise key: {error}"))?;
            let pull_result = pull_q6ar_candidates_from_pinned_peer(
                relay_address,
                &local_key,
                &relay_noise_key,
                &network,
                &profile,
                QRunV06HistorySyncClientConfig {
                    connect_timeout: Duration::from_secs(5),
                    io_timeout: Duration::from_secs(10),
                    max_blocks_per_page: 1,
                    max_bytes_per_page: 64 * 1024,
                    max_pages: 1,
                    max_rounds: 1,
                },
                tls_server_name.as_deref(),
                &mut book,
                &trust_domains,
            )
            .map_err(|error| format!("pinned Q6AR peer search failed: {error}"));
            local_key.fill(0);
            let accepted = pull_result?;

            println!("Q6AR_PULL=PASS");
            println!("relay_endpoint={}", args[4]);
            println!("candidates_accepted={accepted}");
            let now = now_ms()?;
            for record in book.records().filter(|record| {
                record.source == PeerAddressSource::Gossip
                    && record.operator_approved_noise_static_key.is_none()
                    && record.advertisement_expires_at_ms > now
            }) {
                println!(
                    "candidate={} advertised_noise_key={} expires_at_ms={} operator_approved=false",
                    record.address,
                    record
                        .advertised_noise_static_key
                        .map(|key| hex(&key))
                        .unwrap_or_else(|| "none".into()),
                    record.advertisement_expires_at_ms
                );
            }
            println!("auto_approval=false");
            println!("auto_dial=false");
        }
        "approve" if args.len() == 6 => {
            let address = &args[4];
            let key = hex32("noise_static_public_key", &args[5])?;
            let now = now_ms()?;
            let candidate = book
                .records()
                .find(|record| record.address == *address)
                .and_then(|record| record.advertised_noise_static_key);
            let result = if candidate.is_some() {
                book.approve_advertised_candidate(address, key, now)
            } else {
                book.pin_manual_peer(address, key, now)
            };
            result.map_err(|error| format!("peer approval failed: {error}"))?;
            println!("operator_peer_approval=STORED");
            println!("address={address}");
            println!("noise_static_public_key={}", hex(&key));
            println!("outbound_connection=NOT_ATTEMPTED");
        }
        "revoke" if args.len() == 5 => {
            book.revoke_operator_approval(&args[4])
                .map_err(|error: PeerAddressBookError| {
                    format!("peer approval revoke failed: {error}")
                })?;
            println!("operator_peer_approval=REVOKED");
            println!("address={}", args[4]);
        }
        _ => return Err(usage().into()),
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::{is_public_unicast, resolve_relay_endpoint};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn relay_search_rejects_private_shared_and_documentation_addresses() {
        for address in [
            "10.0.0.1:30336",
            "100.100.10.1:443",
            "192.0.2.1:443",
            "198.51.100.10:443",
            "203.0.113.8:443",
            "127.0.0.1:30336",
        ] {
            assert!(resolve_relay_endpoint(address).is_err(), "{address}");
        }
    }

    #[test]
    fn relay_search_accepts_only_public_ipv4_numeric_endpoints() {
        assert!(resolve_relay_endpoint("8.8.8.8:30336").is_ok());
        assert!(!is_public_unicast(IpAddr::V4(Ipv4Addr::new(
            192, 168, 1, 1
        ))));
        assert!(is_public_unicast(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn relay_dns_requires_public_fqdn_on_tls_port() {
        assert!(resolve_relay_endpoint("localhost:443").is_err());
        assert!(resolve_relay_endpoint("seed.example.net:443").is_err());
        assert!(resolve_relay_endpoint("seed.example.net:30336").is_err());
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("ERROR: {error}");
        std::process::exit(2);
    }
}
