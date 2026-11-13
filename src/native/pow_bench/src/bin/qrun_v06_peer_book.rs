//! Operator-controlled QFP6 peer candidate review and trust-pin management.
//!
//! This tool never connects to a peer. It only reads or updates the local network/profile-bound
//! Q6PA address book. Verify endpoint and Noise-key fingerprints through an independent channel
//! before approving them. Approval authorizes a later pinned outbound connection, not consensus trust.
use ai_native_l1_pow_bench::qrun_v06_peer_address_manager_candidate::{
    PeerAddressBookError, QRunV06PeerAddressBookCandidate,
};
use std::{
    env,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
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
fn usage() -> &'static str {
    "Usage:\n  qrun_v06_peer_book list <book_path> <network_id_hex> <profile_id_hex>\n  qrun_v06_peer_book approve <book_path> <network_id_hex> <profile_id_hex> <numeric_ip:port> <noise_static_public_key_hex>\n  qrun_v06_peer_book revoke <book_path> <network_id_hex> <profile_id_hex> <numeric_ip:port>\n\nThis tool does not dial peers. Approval only adds an explicit persistent outbound key pin."
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
fn main() {
    if let Err(error) = run() {
        eprintln!("ERROR: {error}");
        std::process::exit(2);
    }
}
