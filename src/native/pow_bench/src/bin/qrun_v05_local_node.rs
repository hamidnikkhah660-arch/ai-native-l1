//! QRun v0.5 local-loopback integration node.
//!
//! This is an executable integration harness for the QRun v0.5 Genesis-bound runtime and the
//! existing QZXB wallet TXN2/QZTS/1 + read-only HTTP RPC protocols. It is deliberately restricted
//! to loopback, labelled test-only, and cannot claim Mainnet status. It executes accepted transfers
//! immediately as candidate blocks; it is not production PoW/consensus or a multi-peer node.
use ai_native_l1_pow_bench::qrun_v05_runtime_candidate::QRunV05ExecutionRuntime;
use ai_native_l1_pow_bench::qzbe_tx_ingress_candidate::{
    decode_request_header, encode_ack, TxIngressAck, TxIngressStatus, ACK_BYTES,
    REQUEST_HEADER_BYTES,
};
use ai_native_l1_pow_bench::state_machine::{
    decode_transaction, transaction_id, AccountId, NetworkId, MAX_TRANSACTION_BYTES,
};
use ai_native_l1_pow_bench::transaction_auth::{
    account_id_from_public_key, AccountPublicKey, Ed25519TransactionAuthenticator,
    TransactionAuthenticatorKind,
};
use ed25519_dalek::VerifyingKey;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_HTTP_REQUEST: usize = 4096;
const MAX_HTTP_RESPONSE: usize = 16 * 1024;
const LOCAL_PROFILE_DOMAIN: &[u8] = b"QUANTUMZXB-QRUN-V05-LOCAL-LOOPBACK-TESTNET\0";

#[derive(Clone)]
struct Receipt {
    height: u64,
}

struct NodeState {
    runtime: QRunV05ExecutionRuntime<Ed25519TransactionAuthenticator>,
    receipts: BTreeMap<[u8; 32], Receipt>,
    profile_id: [u8; 32],
}

#[derive(Clone)]
struct Config {
    network_id: NetworkId,
    owner_account: AccountId,
    owner_public_key: [u8; 32],
    data_dir: PathBuf,
    rpc_listen: SocketAddr,
    tx_listen: SocketAddr,
}

fn parse_hex32(value: &str, name: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.is_ascii() {
        return Err(format!("{name} must be 64 hex characters"));
    }
    let mut output = [0; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| format!("{name} contains a non-hex character"))?;
    }
    Ok(output)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(DIGITS[(byte >> 4) as usize] as char);
        result.push(DIGITS[(byte & 15) as usize] as char);
    }
    result
}

fn parse_socket(value: &str, name: &str) -> Result<SocketAddr, String> {
    let address = value
        .parse::<SocketAddr>()
        .map_err(|_| format!("{name} must be a numeric IP:PORT socket address"))?;
    if !address.ip().is_loopback() {
        return Err(format!(
            "{name} must be loopback-only; public binds are forbidden"
        ));
    }
    Ok(address)
}

fn parse_config() -> Result<Config, String> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!(
            "QRun v0.5 local-loopback integration node (test-only; never Mainnet)\n\
Usage: qrun_v05_local_node --local-testnet --network-id-hex HEX64 \
--owner-account-id-hex HEX64 --owner-public-key-hex HEX64 --data-dir ABSOLUTE_PATH \
[--rpc-listen 127.0.0.1:49339] [--tx-listen 127.0.0.1:49340]\n\
Initializes the full 10B candidate Genesis in a test-only local store. Both listeners must use loopback."
        );
        return Err("__help__".into());
    }
    if !args.iter().any(|arg| arg == "--local-testnet") {
        return Err(
            "explicit --local-testnet flag is required; this binary never launches Mainnet".into(),
        );
    }
    if args
        .iter()
        .filter(|arg| arg.as_str() != "--local-testnet")
        .count()
        % 2
        != 0
    {
        return Err("options must be --name value pairs".into());
    }
    let mut values = BTreeMap::<String, String>::new();
    let mut index = 0;
    while index < args.len() {
        let key = &args[index];
        if key == "--local-testnet" {
            index += 1;
            continue;
        }
        if !key.starts_with("--") {
            return Err(format!("unexpected argument {key}"));
        }
        let value = args
            .get(index + 1)
            .ok_or_else(|| format!("missing value for {key}"))?;
        if value.starts_with("--") {
            return Err(format!("missing value for {key}"));
        }
        if values.insert(key.clone(), value.clone()).is_some() {
            return Err(format!("duplicate option {key}"));
        }
        index += 2;
    }
    let allowed = [
        "--network-id-hex",
        "--owner-account-id-hex",
        "--owner-public-key-hex",
        "--data-dir",
        "--rpc-listen",
        "--tx-listen",
    ];
    if let Some(key) = values.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(format!("unknown option {key}"));
    }
    let required = |key: &str| {
        values
            .get(key)
            .map(String::as_str)
            .ok_or_else(|| format!("required option missing: {key}"))
    };
    let network_id = parse_hex32(required("--network-id-hex")?, "network ID")?;
    let owner_account = parse_hex32(required("--owner-account-id-hex")?, "owner account ID")?;
    let owner_public_key = parse_hex32(required("--owner-public-key-hex")?, "owner public key")?;
    if network_id.iter().all(|byte| *byte == 0)
        || owner_account.iter().all(|byte| *byte == 0)
        || owner_public_key.iter().all(|byte| *byte == 0)
    {
        return Err("network and owner identifiers must be nonzero".into());
    }
    if account_id_from_public_key(&owner_public_key) != owner_account {
        return Err("owner account ID does not match owner public key".into());
    }
    VerifyingKey::from_bytes(&owner_public_key)
        .map_err(|_| "owner public key is invalid".to_string())?;
    let data_dir = PathBuf::from(required("--data-dir")?);
    if !data_dir.is_absolute() || data_dir.file_name().is_none() {
        return Err("--data-dir must be an absolute path with a final directory name".into());
    }
    let rpc_listen = parse_socket(
        values
            .get("--rpc-listen")
            .map(String::as_str)
            .unwrap_or("127.0.0.1:49339"),
        "--rpc-listen",
    )?;
    let tx_listen = parse_socket(
        values
            .get("--tx-listen")
            .map(String::as_str)
            .unwrap_or("127.0.0.1:49340"),
        "--tx-listen",
    )?;
    if rpc_listen == tx_listen {
        return Err("RPC and transaction-ingress endpoints must use different sockets".into());
    }
    Ok(Config {
        network_id,
        owner_account,
        owner_public_key,
        data_dir,
        rpc_listen,
        tx_listen,
    })
}

fn profile_id(network_id: &NetworkId) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(LOCAL_PROFILE_DOMAIN);
    hash.update(network_id);
    hash.finalize().into()
}

fn now_unix() -> Result<u64, String> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is before Unix epoch".to_string())?
        .as_secs())
}

fn response_json(value: &Value) -> Vec<u8> {
    let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{\"ok\":false}".to_vec());
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut bytes = Vec::with_capacity(header.len() + body.len());
    bytes.extend_from_slice(header.as_bytes());
    bytes.extend_from_slice(&body);
    bytes
}

fn handle_rpc(stream: &mut TcpStream, state: &Arc<Mutex<NodeState>>) -> Result<(), String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .map_err(|error| error.to_string())?;
    let mut request = Vec::new();
    stream
        .take((MAX_HTTP_REQUEST + 1) as u64)
        .read_to_end(&mut request)
        .map_err(|error| error.to_string())?;
    if request.is_empty() || request.len() > MAX_HTTP_REQUEST {
        return Err("empty or oversized HTTP RPC request".into());
    }
    let header_end = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| "HTTP request headers incomplete".to_string())?;
    let header = std::str::from_utf8(&request[..header_end])
        .map_err(|_| "HTTP headers are not UTF-8".to_string())?;
    let mut first = header.lines().next().unwrap_or("").split_whitespace();
    if first.next() != Some("GET") || first.next().is_none() || first.next() != Some("HTTP/1.1") {
        return Err("only HTTP/1.1 GET is supported by candidate read-only RPC".into());
    }
    let path = header
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap();
    if path.contains('?') || path.contains('#') || path.contains("..") || path.contains('%') {
        return Err("invalid RPC path".into());
    }
    let state = state
        .lock()
        .map_err(|_| "node state lock poisoned".to_string())?;
    let height = state.runtime.height();
    let tip = hex(&state.runtime.state().tip_hash());
    let root = hex(&state.runtime.state_root());
    let network = hex(&state.runtime.network_id());
    let genesis = hex(&state.runtime.genesis_commitment());
    let profile = hex(&state.profile_id);
    let value = if path == "/v1/status" {
        json!({
            "ok": true, "mainnet": false, "read_only": true,
            "network_id": network, "genesis_id": genesis, "profile_id": profile,
            "height": height, "tip": tip, "state_root": root, "generation": 0,
            "network_class": "local_loopback_testnet_not_mainnet",
            "consensus": "single_process_candidate_execution_not_production_pow"
        })
    } else if let Some(account_text) = path.strip_prefix("/v1/balance/") {
        match parse_hex32(account_text, "account ID") {
            Ok(account) => json!({
                "ok": true, "mainnet": false, "read_only": true,
                "account_id": hex(&account),
                "balance_atoms": state.runtime.balance_atoms(&account),
                "height": height, "tip": tip, "state_root": root,
                "network_id": network, "genesis_id": genesis,
                "network_class": "local_loopback_testnet_not_mainnet"
            }),
            Err(_) => {
                json!({"ok": false, "mainnet": false, "read_only": true, "error": "invalid account ID"})
            }
        }
    } else if let Some(txid_text) = path.strip_prefix("/v1/transaction/") {
        match parse_hex32(txid_text, "transaction ID") {
            Ok(txid) => {
                if let Some(receipt) = state.receipts.get(&txid) {
                    json!({
                        "ok": true, "mainnet": false, "read_only": true, "txid": hex(&txid),
                        "status": "confirmed", "confirmations": height.saturating_sub(receipt.height) + 1,
                        "block_height": receipt.height, "search_floor_height": 0,
                        "height": height, "tip": tip, "state_root": root
                    })
                } else {
                    json!({
                        "ok": true, "mainnet": false, "read_only": true, "txid": hex(&txid),
                        "status": "not_found_in_retained_suffix", "confirmations": 0,
                        "block_height": Value::Null, "search_floor_height": 0,
                        "height": height, "tip": tip, "state_root": root
                    })
                }
            }
            Err(_) => {
                json!({"ok": false, "mainnet": false, "read_only": true, "error": "invalid transaction ID"})
            }
        }
    } else {
        json!({"ok": false, "mainnet": false, "read_only": true, "error": "unsupported endpoint"})
    };
    if serde_json::to_vec(&value).map_or(MAX_HTTP_RESPONSE + 1, |bytes| bytes.len())
        > MAX_HTTP_RESPONSE
    {
        return Err("RPC response exceeded size cap".into());
    }
    stream
        .write_all(&response_json(&value))
        .map_err(|error| error.to_string())
}

fn serve_rpc(address: SocketAddr, state: Arc<Mutex<NodeState>>) {
    let listener = match TcpListener::bind(address) {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("qrun_local_rpc_bind_failed address={address} error={error}");
            return;
        }
    };
    println!("qrun_local_rpc_ready address={address} read_only=true mainnet=false");
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                if let Err(error) = handle_rpc(&mut stream, &state) {
                    eprintln!(
                        "qrun_local_rpc_request_rejected reason={}",
                        error.replace(['\r', '\n'], "_")
                    );
                }
            }
            Err(error) => eprintln!("qrun_local_rpc_accept_error error={error}"),
        }
    }
}

fn reject_ack(transaction_id: [u8; 32], status: TxIngressStatus, count: usize) -> [u8; ACK_BYTES] {
    encode_ack(TxIngressAck {
        status,
        mempool_count: u32::try_from(count).unwrap_or(u32::MAX),
        transaction_id,
    })
}

fn handle_transaction(stream: &mut TcpStream, state: &Arc<Mutex<NodeState>>) -> Result<(), String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|error| error.to_string())?;
    let mut header = [0u8; REQUEST_HEADER_BYTES];
    if stream.read_exact(&mut header).is_err() {
        return Err("could not read complete QZTS/1 header".into());
    }
    let payload_len = decode_request_header(&header)
        .map_err(|error| format!("invalid QZTS/1 header: {error:?}"))?;
    if payload_len > MAX_TRANSACTION_BYTES {
        return Err("transaction exceeds QZXB wire cap".into());
    }
    let mut wire = vec![0u8; payload_len];
    stream
        .read_exact(&mut wire)
        .map_err(|error| format!("short QZTS/1 body: {error}"))?;
    let tx = decode_transaction(&wire)
        .map_err(|error| format!("invalid TXN2 transaction: {error:?}"))?;
    let txid = transaction_id(&tx).map_err(|error| format!("transaction ID error: {error:?}"))?;

    let (ack, log_line) = {
        let mut locked = state
            .lock()
            .map_err(|_| "node state lock poisoned".to_string())?;
        if let Some(receipt) = locked.receipts.get(&txid) {
            let _ = receipt.height;
            (
                reject_ack(txid, TxIngressStatus::Duplicate, 0),
                format!("duplicate txid={}", hex(&txid)),
            )
        } else {
            let timestamp =
                now_unix()?.max(locked.runtime.state().last_timestamp().saturating_add(1));
            match locked.runtime.build_next_block(timestamp, vec![tx]) {
                Ok(block) => match locked.runtime.import_block(&block) {
                    Ok(summary) => {
                        locked.receipts.insert(
                            txid,
                            Receipt {
                                height: summary.height,
                            },
                        );
                        (
                            reject_ack(txid, TxIngressStatus::Accepted, 0),
                            format!(
                                "accepted_and_executed txid={} height={} block_hash={}",
                                hex(&txid),
                                summary.height,
                                hex(&summary.block_hash)
                            ),
                        )
                    }
                    Err(error) => (
                        reject_ack(txid, TxIngressStatus::Rejected, 0),
                        format!("execution_rejected txid={} error={error:?}", hex(&txid)),
                    ),
                },
                Err(error) => (
                    reject_ack(txid, TxIngressStatus::Rejected, 0),
                    format!("validation_rejected txid={} error={error:?}", hex(&txid)),
                ),
            }
        }
    };
    stream.write_all(&ack).map_err(|error| error.to_string())?;
    println!("qrun_local_tx_ingress {log_line}");
    Ok(())
}

fn serve_transactions(address: SocketAddr, state: Arc<Mutex<NodeState>>) {
    let listener = match TcpListener::bind(address) {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("qrun_local_tx_bind_failed address={address} error={error}");
            return;
        }
    };
    println!("qrun_local_tx_ready address={address} protocol=QZTS/1 mainnet=false");
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                if let Err(error) = handle_transaction(&mut stream, &state) {
                    eprintln!(
                        "qrun_local_tx_request_rejected reason={}",
                        error.replace(['\r', '\n'], "_")
                    );
                }
            }
            Err(error) => eprintln!("qrun_local_tx_accept_error error={error}"),
        }
    }
}

fn run(config: Config) -> Result<(), String> {
    if !config.rpc_listen.ip().is_loopback() || !config.tx_listen.ip().is_loopback() {
        return Err("refusing non-loopback listener".into());
    }
    fs::create_dir_all(&config.data_dir)
        .map_err(|error| format!("create data directory: {error}"))?;
    let store_path = config.data_dir.join("qrun-v05-local-testnet.qrs");
    let authenticator = Ed25519TransactionAuthenticator::select(
        TransactionAuthenticatorKind::Ed25519V1,
        [AccountPublicKey {
            account_id: config.owner_account,
            public_key: config.owner_public_key,
        }],
    )
    .map_err(|error| format!("configure Ed25519 authenticator: {error:?}"))?;
    let runtime = QRunV05ExecutionRuntime::open_or_create(
        config.network_id,
        config.owner_account,
        authenticator,
        store_path,
    )
    .map_err(|error| format!("open QRun v0.5 candidate runtime: {error:?}"))?;
    let root = runtime.state_root();
    let network_id = runtime.network_id();
    let genesis_id = runtime.genesis_commitment();
    let profile_id = profile_id(&network_id);
    println!("QRUN_V05_LOCAL_LOOPBACK_TESTNET_READY");
    println!("mainnet=false");
    println!("public_launch_approved=false");
    println!("network_class=local_loopback_testnet_not_mainnet");
    println!("network_id_hex={}", hex(&network_id));
    println!("genesis_id_hex={}", hex(&genesis_id));
    println!("profile_id_hex={}", hex(&profile_id));
    println!("owner_account_id_hex={}", hex(&config.owner_account));
    println!("owner_balance_atoms={}", runtime.owner_balance_atoms());
    println!(
        "owner_balance_qzxb={:.8}",
        runtime.owner_balance_atoms() as f64 / 100_000_000.0
    );
    println!(
        "total_supply_atoms={}",
        runtime
            .total_supply_atoms()
            .map_err(|error| format!("{error:?}"))?
    );
    println!("state_root_hex={}", hex(&root));
    println!("height={}", runtime.height());
    println!("rpc_listen={}", config.rpc_listen);
    println!("tx_listen={}", config.tx_listen);
    println!(
        "security_note=single_process_candidate_execution_not_production_pow_or_peer_consensus"
    );

    let state = Arc::new(Mutex::new(NodeState {
        runtime,
        receipts: BTreeMap::new(),
        profile_id,
    }));
    let rpc_state = Arc::clone(&state);
    let rpc_address = config.rpc_listen;
    std::thread::spawn(move || serve_rpc(rpc_address, rpc_state));
    let tx_state = Arc::clone(&state);
    let tx_address = config.tx_listen;
    std::thread::spawn(move || serve_transactions(tx_address, tx_state));
    loop {
        std::thread::park_timeout(Duration::from_secs(3600));
    }
}

fn main() {
    match parse_config() {
        Ok(config) => {
            if let Err(error) = run(config) {
                eprintln!(
                    "QRUN_V05_LOCAL_NODE_ERROR: {}",
                    error.replace(['\r', '\n'], "_")
                );
                std::process::exit(2);
            }
        }
        Err(error) if error == "__help__" => {}
        Err(error) => {
            eprintln!(
                "QRUN_V05_LOCAL_NODE_ERROR: {}",
                error.replace(['\r', '\n'], "_")
            );
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_listener_addresses_are_refused() {
        assert!(parse_socket("127.0.0.1:49339", "test").is_ok());
        assert!(parse_socket("[::1]:49339", "test").is_ok());
        assert!(parse_socket("0.0.0.0:49339", "test").is_err());
        assert!(parse_socket("192.0.2.1:49339", "test").is_err());
    }

    #[test]
    fn network_and_genesis_profile_ids_are_domain_separated() {
        let network = [0x51; 32];
        assert_ne!(profile_id(&network), network);
        assert_eq!(profile_id(&network), profile_id(&network));
        assert_ne!(profile_id(&network), profile_id(&[0x52; 32]));
    }
}
