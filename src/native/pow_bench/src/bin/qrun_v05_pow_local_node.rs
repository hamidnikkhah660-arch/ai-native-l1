//! QRun v0.5 local-loopback PoW integration node.
//!
//! This is an executable integration harness for the QRun v0.5 Genesis-bound runtime and the
//! existing QZXB wallet TXN2/QZTS/1 + read-only HTTP RPC protocols. It is deliberately restricted
//! to loopback, labelled test-only, and cannot claim Mainnet status. It uses persistent PoW fork choice with a deliberately trivial local-only smoke target.
//! It is not a public-network consensus profile.
use ai_native_l1_pow_bench::chain_admission::SystemClockReferenceTime;
use ai_native_l1_pow_bench::consensus::{ConsensusParameters, PowAlgorithm, Uint256};
use ai_native_l1_pow_bench::noise_key_provisioning::load_protected_noise_private_key;
use ai_native_l1_pow_bench::private_testnet_wire::decode_candidate_network_block;
use ai_native_l1_pow_bench::qrun_v05_noise_transport_candidate::{
    QRunV05NoiseSession, MAX_NOISE_APPLICATION_RECORD_BYTES,
};
use ai_native_l1_pow_bench::qrun_v05_pow_fork_runtime_candidate::QRunV05PowForkRuntime;
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
const BLOCK_MAGIC: &[u8; 4] = b"QRB5";
const BLOCK_ACK_MAGIC: &[u8; 4] = b"QRA5";
const BLOCK_PROTOCOL_VERSION: u16 = 2;
const BLOCK_FRAME_HEADER_BYTES: usize = 10;
const BLOCK_ACK_BYTES: usize = 47;
const MAX_BLOCK_FRAME_BYTES: usize = 8 * 1024 * 1024;
const SYNC_REQUEST_MAGIC: &[u8; 4] = b"QRS5";
const SYNC_RESPONSE_MAGIC: &[u8; 4] = b"QRR5";
const SYNC_PROTOCOL_VERSION: u16 = 1;
const SYNC_REQUEST_BYTES: usize = 20;
const SYNC_RESPONSE_HEADER_BYTES: usize = 120;
const MAX_SYNC_PAGE_BLOCKS: usize = 16;

#[derive(Clone)]
struct Receipt {
    height: u64,
}

struct NodeState {
    runtime: QRunV05PowForkRuntime,
    authenticator: Ed25519TransactionAuthenticator,
    clock: SystemClockReferenceTime,
    receipts: BTreeMap<[u8; 32], Receipt>,
    profile_id: [u8; 32],
    block_peers: Vec<SocketAddr>,
    noise_private_key: Option<[u8; 32]>,
    trusted_peer_static_keys: Vec<[u8; 32]>,
    peer_static_keys_by_addr: BTreeMap<SocketAddr, [u8; 32]>,
}

impl Drop for NodeState {
    fn drop(&mut self) {
        if let Some(private_key) = self.noise_private_key.as_mut() {
            private_key.fill(0);
        }
    }
}

impl NodeState {
    fn refresh_receipts(&mut self) -> Result<(), String> {
        let locations = self
            .runtime
            .canonical_transaction_locations()
            .map_err(|error| format!("rebuild canonical transaction index: {error:?}"))?;
        self.receipts.clear();
        for (txid, height) in locations {
            self.receipts.insert(txid, Receipt { height });
        }
        Ok(())
    }
}

#[derive(Clone)]
struct Config {
    network_id: NetworkId,
    owner_account: AccountId,
    producer_account: AccountId,
    owner_public_key: [u8; 32],
    data_dir: PathBuf,
    rpc_listen: SocketAddr,
    tx_listen: SocketAddr,
    block_listen: SocketAddr,
    peers: Vec<SocketAddr>,
    noise_private_key_file: Option<PathBuf>,
    peer_static_public_keys: Vec<[u8; 32]>,
    sync_on_start: bool,
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
            "QRun v0.5 local-loopback PoW integration node (test-only; never Mainnet)\n\
Usage: qrun_v05_pow_local_node --local-testnet --network-id-hex HEX64 \
--owner-account-id-hex HEX64 --owner-public-key-hex HEX64 --data-dir ABSOLUTE_PATH \
[--rpc-listen 127.0.0.1:49339] [--tx-listen 127.0.0.1:49340]\n\
Authenticated candidate peers: --noise-private-key-file NPK1 --peer 127.0.0.1:PORT --peer-static-public-key-hex HEX64 (repeat peer and pin together).\n\
Optional --sync-on-start true requests bounded authenticated catch-up from pinned peers before listeners bind. The binary remains loopback-only and uses an insecure smoke target; it is not Mainnet."
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
    let mut peers = Vec::new();
    let mut peer_static_public_keys = Vec::new();
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
        if key == "--peer" {
            peers.push(parse_socket(value, "--peer")?);
        } else if key == "--peer-static-public-key-hex" {
            peer_static_public_keys.push(parse_hex32(value, "peer static public key")?);
        } else if values.insert(key.clone(), value.clone()).is_some() {
            return Err(format!("duplicate option {key}"));
        }
        index += 2;
    }
    let allowed = [
        "--network-id-hex",
        "--owner-account-id-hex",
        "--producer-account-id-hex",
        "--owner-public-key-hex",
        "--data-dir",
        "--rpc-listen",
        "--tx-listen",
        "--block-listen",
        "--noise-private-key-file",
        "--sync-on-start",
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
    let producer_account = values
        .get("--producer-account-id-hex")
        .map(|value| parse_hex32(value, "producer account ID"))
        .transpose()?
        .unwrap_or(owner_account);
    let owner_public_key = parse_hex32(required("--owner-public-key-hex")?, "owner public key")?;
    if network_id.iter().all(|byte| *byte == 0)
        || owner_account.iter().all(|byte| *byte == 0)
        || producer_account.iter().all(|byte| *byte == 0)
        || owner_public_key.iter().all(|byte| *byte == 0)
    {
        return Err("network, owner, and producer identifiers must be nonzero".into());
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
    let block_listen = parse_socket(
        values
            .get("--block-listen")
            .map(String::as_str)
            .unwrap_or("127.0.0.1:49341"),
        "--block-listen",
    )?;
    if rpc_listen == tx_listen || rpc_listen == block_listen || tx_listen == block_listen {
        return Err(
            "RPC, transaction ingress, and block listeners must use different sockets".into(),
        );
    }
    if peers.iter().any(|peer| *peer == block_listen) {
        return Err("a node cannot list its own block listener as a peer".into());
    }
    for (index, peer) in peers.iter().enumerate() {
        if peers.iter().skip(index + 1).any(|other| other == peer) {
            return Err("peer socket list must be duplicate-free".into());
        }
    }
    let noise_private_key_file = values.get("--noise-private-key-file").map(PathBuf::from);
    let sync_on_start = match values
        .get("--sync-on-start")
        .map(String::as_str)
        .unwrap_or("false")
    {
        "true" => true,
        "false" => false,
        _ => return Err("--sync-on-start must be exactly true or false".into()),
    };
    if sync_on_start && noise_private_key_file.is_none() {
        return Err(
            "--sync-on-start requires --noise-private-key-file and pinned peer keys".into(),
        );
    }
    if noise_private_key_file.is_some() {
        if peer_static_public_keys.len() != peers.len() || peers.is_empty() {
            return Err("authenticated peer mode requires exactly one --peer-static-public-key-hex for each --peer, with at least one pinned peer".into());
        }
        if peer_static_public_keys
            .iter()
            .any(|key| key.iter().all(|byte| *byte == 0))
        {
            return Err("peer static public keys must be nonzero".into());
        }
        for (index, key) in peer_static_public_keys.iter().enumerate() {
            if peer_static_public_keys
                .iter()
                .skip(index + 1)
                .any(|other| other == key)
            {
                return Err("peer static public keys must be unique".into());
            }
        }
    } else if !peer_static_public_keys.is_empty() {
        return Err("--peer-static-public-key-hex requires --noise-private-key-file".into());
    }
    Ok(Config {
        network_id,
        owner_account,
        producer_account,
        owner_public_key,
        data_dir,
        rpc_listen,
        tx_listen,
        block_listen,
        peers,
        noise_private_key_file,
        peer_static_public_keys,
        sync_on_start,
    })
}

fn profile_id(
    network_id: &NetworkId,
    params: &ConsensusParameters,
    genesis_commitment: &[u8; 32],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(LOCAL_PROFILE_DOMAIN);
    hash.update(network_id);
    hash.update(genesis_commitment);
    hash.update(params.protocol_version.to_be_bytes());
    hash.update(params.target_block_time_secs.to_be_bytes());
    hash.update(params.difficulty_window_blocks.to_be_bytes());
    hash.update(params.difficulty_min_ratio_divisor.to_be_bytes());
    hash.update(params.difficulty_max_ratio.to_be_bytes());
    hash.update(params.pow_limit.to_be_bytes());
    hash.update(params.initial_target.to_be_bytes());
    hash.update(match params.pow.algorithm {
        PowAlgorithm::Argon2id => [1u8],
    });
    hash.update(params.pow.memory_kib.to_be_bytes());
    hash.update(params.pow.iterations.to_be_bytes());
    hash.update(params.pow.lanes.to_be_bytes());
    hash.update([params.pow.output_bytes]);
    hash.update(params.issuance.maximum_supply().to_be_bytes());
    hash.update(params.issuance.initial_subsidy().to_be_bytes());
    hash.update(params.issuance.blocks_per_halving().to_be_bytes());
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
    let mut request = vec![0u8; MAX_HTTP_REQUEST];
    let count = stream
        .read(&mut request)
        .map_err(|error| error.to_string())?;
    if count == 0 || count == MAX_HTTP_REQUEST {
        return Err("empty or oversized HTTP request".into());
    }
    let text = std::str::from_utf8(&request[..count]).map_err(|_| "HTTP request is not UTF-8")?;
    let line = text.lines().next().ok_or("missing HTTP request line")?;
    let mut parts = line.split_whitespace();
    let method = parts.next();
    let path = parts.next().unwrap_or("/");
    let version = parts.next();
    if method != Some("GET") || version != Some("HTTP/1.1") {
        return Err("only HTTP/1.1 GET is supported by read-only RPC".into());
    }
    if path.contains('?') || path.contains('#') || path.contains("..") || path.contains('%') {
        return Err("invalid RPC path".into());
    }
    let locked = state
        .lock()
        .map_err(|_| "node state lock poisoned".to_string())?;
    let height = locked.runtime.canonical_height();
    let tip = hex(&locked.runtime.canonical_tip());
    let root = hex(&locked.runtime.canonical_state_root());
    let network = hex(&locked.runtime.network_id());
    let genesis = hex(&locked.runtime.genesis_commitment());
    let profile = hex(&locked.profile_id);
    let value = if path == "/v1/status" {
        json!({
            "ok": true, "mainnet": false, "read_only": true,
            "network_id": network, "genesis_id": genesis, "profile_id": profile,
            "height": height, "tip": tip, "state_root": root, "generation": 0,
            "network_class": "local_loopback_pow_testnet_not_mainnet",
            "consensus": "candidate_argon2id_pow_pfs2_persistent_fork_choice"
        })
    } else if let Some(account_text) = path.strip_prefix("/v1/balance/") {
        match parse_hex32(account_text, "account ID") {
            Ok(account) => json!({
                "ok": true, "mainnet": false, "read_only": true,
                "account_id": hex(&account),
                "balance_atoms": locked.runtime.canonical_state().account(&account).map_or(0, |a| a.balance),
                "nonce": locked.runtime.canonical_state().account(&account).map_or(0, |a| a.nonce),
                "height": height, "tip": tip, "state_root": root,
                "network_id": network, "genesis_id": genesis,
                "network_class": "local_loopback_pow_testnet_not_mainnet"
            }),
            Err(_) => {
                json!({"ok": false, "mainnet": false, "read_only": true, "error": "invalid account ID"})
            }
        }
    } else if let Some(txid_text) = path.strip_prefix("/v1/transaction/") {
        match parse_hex32(txid_text, "transaction ID") {
            Ok(txid) => {
                if let Some(receipt) = locked.receipts.get(&txid) {
                    json!({
                        "ok": true, "mainnet": false, "read_only": true, "txid": hex(&txid),
                        "status": "confirmed", "confirmations": height.saturating_sub(receipt.height) + 1,
                        "block_height": receipt.height, "search_floor_height": 0,
                        "height": height, "tip": tip, "state_root": root
                    })
                } else {
                    json!({
                        "ok": true, "mainnet": false, "read_only": true, "txid": hex(&txid),
                        "status": "not_found_in_canonical_chain", "confirmations": 0,
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

fn poll_rpc_listener(
    listener: &TcpListener,
    state: &Arc<Mutex<NodeState>>,
) -> Result<bool, String> {
    match listener.accept() {
        Ok((mut stream, _)) => {
            if let Err(error) = handle_rpc(&mut stream, state) {
                eprintln!(
                    "qrun_pow_local_rpc_request_rejected reason={}",
                    error.replace(['\r', '\n'], "_")
                );
            }
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(false),
        Err(error) => Err(format!("RPC listener accept failed: {error}")),
    }
}

fn block_id(envelope: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"QRUN-LOCAL-POW-ENVELOPE-ID-V1\0");
    hash.update(envelope);
    hash.finalize().into()
}

fn encode_block_frame(envelope: &[u8]) -> Result<Vec<u8>, String> {
    if envelope.is_empty()
        || envelope.len() > MAX_BLOCK_FRAME_BYTES
        || envelope.len() > u32::MAX as usize
    {
        return Err("QRun PTB2 envelope exceeds bounded gossip frame".into());
    }
    let mut frame = Vec::with_capacity(BLOCK_FRAME_HEADER_BYTES + envelope.len());
    frame.extend_from_slice(BLOCK_MAGIC);
    frame.extend_from_slice(&BLOCK_PROTOCOL_VERSION.to_be_bytes());
    frame.extend_from_slice(&(envelope.len() as u32).to_be_bytes());
    frame.extend_from_slice(envelope);
    Ok(frame)
}

fn decode_block_frame(frame: &[u8]) -> Result<Vec<u8>, String> {
    if frame.len() < BLOCK_FRAME_HEADER_BYTES {
        return Err("truncated QRun PoW frame".into());
    }
    let header = &frame[..BLOCK_FRAME_HEADER_BYTES];
    if &header[..4] != BLOCK_MAGIC
        || u16::from_be_bytes([header[4], header[5]]) != BLOCK_PROTOCOL_VERSION
    {
        return Err("invalid QRun PoW frame magic/version".into());
    }
    let payload_len = u32::from_be_bytes(header[6..10].try_into().unwrap()) as usize;
    if payload_len == 0
        || payload_len > MAX_BLOCK_FRAME_BYTES
        || frame.len() != BLOCK_FRAME_HEADER_BYTES + payload_len
    {
        return Err("invalid or oversized QRun PTB2 frame".into());
    }
    Ok(frame[BLOCK_FRAME_HEADER_BYTES..].to_vec())
}

#[derive(Debug)]
struct CanonicalSyncResponse {
    base_height: u64,
    height: u64,
    base_tip: [u8; 32],
    canonical_tip: [u8; 32],
    state_root: [u8; 32],
    envelopes: Vec<Vec<u8>>,
}

fn max_sync_response_block_bytes(max_blocks: usize) -> Result<usize, String> {
    if max_blocks == 0 || max_blocks > MAX_SYNC_PAGE_BLOCKS {
        return Err("canonical sync page block count is outside the allowed range".into());
    }
    MAX_NOISE_APPLICATION_RECORD_BYTES
        .checked_sub(SYNC_RESPONSE_HEADER_BYTES + 4 * max_blocks)
        .ok_or_else(|| "canonical sync page budget underflows the Noise record bound".into())
}

fn encode_sync_request(
    start_height: u64,
    max_blocks: usize,
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    let max_record_bytes = max_sync_response_block_bytes(max_blocks)?;
    if start_height == 0
        || max_bytes == 0
        || max_bytes > max_record_bytes
        || max_bytes > u32::MAX as usize
    {
        return Err("canonical sync request is outside the allowed height/size bounds".into());
    }
    let mut request = Vec::with_capacity(SYNC_REQUEST_BYTES);
    request.extend_from_slice(SYNC_REQUEST_MAGIC);
    request.extend_from_slice(&SYNC_PROTOCOL_VERSION.to_be_bytes());
    request.extend_from_slice(&start_height.to_be_bytes());
    request.extend_from_slice(&(max_blocks as u16).to_be_bytes());
    request.extend_from_slice(&(max_bytes as u32).to_be_bytes());
    Ok(request)
}

fn decode_sync_request(request: &[u8]) -> Result<(u64, usize, usize), String> {
    if request.len() != SYNC_REQUEST_BYTES
        || &request[..4] != SYNC_REQUEST_MAGIC
        || u16::from_be_bytes([request[4], request[5]]) != SYNC_PROTOCOL_VERSION
    {
        return Err("invalid canonical sync request magic/version/length".into());
    }
    let start_height = u64::from_be_bytes(request[6..14].try_into().unwrap());
    let max_blocks = u16::from_be_bytes(request[14..16].try_into().unwrap()) as usize;
    let max_bytes = u32::from_be_bytes(request[16..20].try_into().unwrap()) as usize;
    encode_sync_request(start_height, max_blocks, max_bytes)?;
    Ok((start_height, max_blocks, max_bytes))
}

fn encode_sync_response(
    base_height: u64,
    height: u64,
    base_tip: [u8; 32],
    canonical_tip: [u8; 32],
    state_root: [u8; 32],
    envelopes: &[Vec<u8>],
) -> Result<Vec<u8>, String> {
    if envelopes.len() > MAX_SYNC_PAGE_BLOCKS {
        return Err("canonical sync response has too many blocks".into());
    }
    let mut response = Vec::with_capacity(SYNC_RESPONSE_HEADER_BYTES);
    response.extend_from_slice(SYNC_RESPONSE_MAGIC);
    response.extend_from_slice(&SYNC_PROTOCOL_VERSION.to_be_bytes());
    response.extend_from_slice(&base_height.to_be_bytes());
    response.extend_from_slice(&height.to_be_bytes());
    response.extend_from_slice(&base_tip);
    response.extend_from_slice(&canonical_tip);
    response.extend_from_slice(&state_root);
    response.extend_from_slice(&(envelopes.len() as u16).to_be_bytes());
    for envelope in envelopes {
        if envelope.is_empty() || envelope.len() > u32::MAX as usize {
            return Err("canonical sync response has an invalid envelope length".into());
        }
        response.extend_from_slice(&(envelope.len() as u32).to_be_bytes());
        response.extend_from_slice(envelope);
        if response.len() > MAX_NOISE_APPLICATION_RECORD_BYTES {
            return Err("canonical sync response exceeds the bounded Noise record size".into());
        }
    }
    Ok(response)
}

fn decode_sync_response(
    response: &[u8],
    max_blocks: usize,
    max_bytes: usize,
) -> Result<CanonicalSyncResponse, String> {
    let allowed_bytes = max_sync_response_block_bytes(max_blocks)?.min(max_bytes);
    if response.len() < SYNC_RESPONSE_HEADER_BYTES
        || response.len() > MAX_NOISE_APPLICATION_RECORD_BYTES
        || &response[..4] != SYNC_RESPONSE_MAGIC
        || u16::from_be_bytes([response[4], response[5]]) != SYNC_PROTOCOL_VERSION
    {
        return Err("invalid canonical sync response magic/version/length".into());
    }
    let base_height = u64::from_be_bytes(response[6..14].try_into().unwrap());
    let height = u64::from_be_bytes(response[14..22].try_into().unwrap());
    let base_tip: [u8; 32] = response[22..54].try_into().unwrap();
    let canonical_tip: [u8; 32] = response[54..86].try_into().unwrap();
    let state_root: [u8; 32] = response[86..118].try_into().unwrap();
    let count = u16::from_be_bytes([response[118], response[119]]) as usize;
    if count > max_blocks || count > MAX_SYNC_PAGE_BLOCKS || base_height > height {
        return Err("canonical sync response violates the requested bounds".into());
    }
    let mut offset = SYNC_RESPONSE_HEADER_BYTES;
    let mut total_bytes = 0usize;
    let mut envelopes = Vec::with_capacity(count);
    for _ in 0..count {
        let length_end = offset
            .checked_add(4)
            .ok_or("sync response length overflow")?;
        if length_end > response.len() {
            return Err("truncated canonical sync envelope length".into());
        }
        let length = u32::from_be_bytes(response[offset..length_end].try_into().unwrap()) as usize;
        offset = length_end;
        if length == 0 {
            return Err("canonical sync response contains an empty block envelope".into());
        }
        let envelope_end = offset
            .checked_add(length)
            .ok_or("sync response length overflow")?;
        if envelope_end > response.len() {
            return Err("truncated canonical sync block envelope".into());
        }
        total_bytes = total_bytes
            .checked_add(length)
            .ok_or("sync response byte budget overflow")?;
        if total_bytes > allowed_bytes {
            return Err("canonical sync response exceeds its requested byte budget".into());
        }
        envelopes.push(response[offset..envelope_end].to_vec());
        offset = envelope_end;
    }
    if offset != response.len() {
        return Err("canonical sync response contains trailing bytes".into());
    }
    if count > 0 && height < base_height.saturating_add(count as u64) {
        return Err("canonical sync response range extends beyond its advertised tip".into());
    }
    Ok(CanonicalSyncResponse {
        base_height,
        height,
        base_tip,
        canonical_tip,
        state_root,
        envelopes,
    })
}

fn serve_sync_request(
    request: &[u8],
    session: &mut QRunV05NoiseSession,
    stream: &mut TcpStream,
    state: &Arc<Mutex<NodeState>>,
) -> Result<(), String> {
    let (start_height, max_blocks, max_bytes) = decode_sync_request(request)?;
    let (base_height, height, base_tip, canonical_tip, state_root, envelopes) = {
        let locked = state
            .lock()
            .map_err(|_| "node state lock poisoned".to_string())?;
        let envelopes = locked
            .runtime
            .canonical_envelopes_range(start_height, max_blocks, max_bytes)
            .map_err(|error| format!("export canonical sync range: {error:?}"))?;
        (
            locked.runtime.archive_base_height(),
            locked.runtime.canonical_height(),
            locked.runtime.archive_base_tip(),
            locked.runtime.canonical_tip(),
            locked.runtime.canonical_state_root(),
            envelopes,
        )
    };
    let response = encode_sync_response(
        base_height,
        height,
        base_tip,
        canonical_tip,
        state_root,
        &envelopes,
    )?;
    session
        .write_record(stream, &response)
        .map_err(|error| format!("write encrypted canonical sync response: {error}"))?;
    println!(
        "qrun_pow_local_canonical_sync_served start_height={start_height} count={} tip_height={height} base_height={base_height}",
        envelopes.len()
    );
    Ok(())
}

fn block_ack(status: u8, height: u64, hash: [u8; 32]) -> [u8; BLOCK_ACK_BYTES] {
    let mut ack = [0u8; BLOCK_ACK_BYTES];
    ack[..4].copy_from_slice(BLOCK_ACK_MAGIC);
    ack[4..6].copy_from_slice(&BLOCK_PROTOCOL_VERSION.to_be_bytes());
    ack[6] = status;
    ack[7..15].copy_from_slice(&height.to_be_bytes());
    ack[15..47].copy_from_slice(&hash);
    ack
}

fn send_block_to_peer_plain(peer: SocketAddr, envelope: &[u8]) -> Result<(), String> {
    if !peer.ip().is_loopback() {
        return Err("peer must be loopback in the local PoW integration profile".into());
    }
    let candidate = decode_candidate_network_block(envelope)
        .map_err(|error| format!("decode PTB2 envelope: {error:?}"))?;
    if candidate.fee_block.is_some() {
        return Err(
            "local loopback PTB2 node refuses QFP5; use the profile-locked QRun path".into(),
        );
    }
    let height = candidate.block.height;
    let expected_hash = block_id(envelope);
    let frame = encode_block_frame(envelope)?;
    let mut stream = TcpStream::connect_timeout(&peer, Duration::from_secs(2))
        .map_err(|error| format!("connect block peer {peer}: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| error.to_string())?;
    stream
        .write_all(&frame)
        .map_err(|error| format!("send block to {peer}: {error}"))?;
    let mut ack = [0u8; BLOCK_ACK_BYTES];
    stream
        .read_exact(&mut ack)
        .map_err(|error| format!("read block ACK from {peer}: {error}"))?;
    validate_block_ack(peer, &ack, height, expected_hash)
}

fn validate_block_ack(
    peer: SocketAddr,
    ack: &[u8],
    height: u64,
    expected_hash: [u8; 32],
) -> Result<(), String> {
    if ack.len() != BLOCK_ACK_BYTES {
        return Err(format!("peer {peer} returned an invalid ACK length"));
    }
    let ack_height = u64::from_be_bytes(ack[7..15].try_into().unwrap());
    if &ack[..4] != BLOCK_ACK_MAGIC
        || u16::from_be_bytes([ack[4], ack[5]]) != BLOCK_PROTOCOL_VERSION
        || ack[6] > 1
        || ack_height != height
        || ack[15..47] != expected_hash
    {
        return Err(format!(
            "peer {peer} rejected envelope or returned a mismatched ACK"
        ));
    }
    Ok(())
}

struct EphemeralNoisePrivateKey([u8; 32]);

impl Drop for EphemeralNoisePrivateKey {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

fn send_block_to_peer_authenticated(
    peer: SocketAddr,
    envelope: &[u8],
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
    local_private_key: [u8; 32],
    remote_static_public_key: &[u8; 32],
) -> Result<(), String> {
    let local_private_key = EphemeralNoisePrivateKey(local_private_key);
    if !peer.ip().is_loopback() {
        return Err("peer must be loopback in the local PoW integration profile".into());
    }
    let candidate = decode_candidate_network_block(envelope)
        .map_err(|error| format!("decode PTB2 envelope: {error:?}"))?;
    // QFP5 relay is permitted only through this authenticated, profile-bound session.
    let height = candidate.block.height;
    let expected_hash = block_id(envelope);
    let frame = encode_block_frame(envelope)?;
    let mut stream = TcpStream::connect_timeout(&peer, Duration::from_secs(2))
        .map_err(|error| format!("connect authenticated block peer {peer}: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(6)))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(6)))
        .map_err(|error| error.to_string())?;
    let established = QRunV05NoiseSession::connect(
        &mut stream,
        &local_private_key.0,
        remote_static_public_key,
        network_id,
        profile_id,
    );
    let mut session =
        established.map_err(|error| format!("Noise XX peer authentication failed: {error}"))?;
    if session.remote_static_public_key() != remote_static_public_key {
        return Err(format!(
            "peer {peer} Noise static key differs from the configured pin"
        ));
    }
    session
        .write_record(&mut stream, &frame)
        .map_err(|error| format!("send encrypted block to {peer}: {error}"))?;
    let ack = session
        .read_record(&mut stream)
        .map_err(|error| format!("read authenticated block ACK from {peer}: {error}"))?;
    validate_block_ack(peer, &ack, height, expected_hash)
}

fn send_block_to_peer(
    peer: SocketAddr,
    envelope: &[u8],
    state: &Arc<Mutex<NodeState>>,
) -> Result<(), String> {
    let (network_id, profile_id, local_private_key, remote_static_public_key) = {
        let locked = state
            .lock()
            .map_err(|_| "node state lock poisoned".to_string())?;
        (
            locked.runtime.network_id(),
            locked.profile_id,
            locked.noise_private_key,
            locked.peer_static_keys_by_addr.get(&peer).copied(),
        )
    };
    match (local_private_key, remote_static_public_key) {
        (None, None) => send_block_to_peer_plain(peer, envelope),
        (Some(mut private_key), Some(public_key)) => {
            let result = send_block_to_peer_authenticated(
                peer,
                envelope,
                &network_id,
                &profile_id,
                private_key,
                &public_key,
            );
            private_key.fill(0);
            result
        }
        _ => {
            Err("authenticated block peer config is incomplete; refusing plaintext fallback".into())
        }
    }
}

/// Request one bounded canonical page from a statically pinned authenticated peer, then
/// independently validate and persist every returned PTB2 block before reporting progress.
fn request_sync_page_authenticated(
    peer: SocketAddr,
    state: &Arc<Mutex<NodeState>>,
    max_blocks: usize,
    max_bytes: usize,
) -> Result<(u64, u64), String> {
    if !peer.ip().is_loopback() {
        return Err("peer must be loopback in the local PoW integration profile".into());
    }
    let (
        network_id,
        profile_id,
        local_private_key,
        remote_static_public_key,
        start_height,
        local_height,
        local_tip,
    ) = {
        let locked = state
            .lock()
            .map_err(|_| "node state lock poisoned".to_string())?;
        let local_height = locked.runtime.canonical_height();
        (
            locked.runtime.network_id(),
            locked.profile_id,
            locked
                .noise_private_key
                .ok_or("authenticated sync requires a local Noise key")?,
            *locked
                .peer_static_keys_by_addr
                .get(&peer)
                .ok_or("authenticated sync requires a pinned key for the peer")?,
            local_height
                .checked_add(1)
                .ok_or("local chain height overflow")?,
            local_height,
            locked.runtime.canonical_tip(),
        )
    };
    let request = encode_sync_request(start_height, max_blocks, max_bytes)?;
    let local_private_key = EphemeralNoisePrivateKey(local_private_key);
    let mut stream = TcpStream::connect_timeout(&peer, Duration::from_secs(2))
        .map_err(|error| format!("connect authenticated sync peer {peer}: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(6)))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(6)))
        .map_err(|error| error.to_string())?;
    let mut session = QRunV05NoiseSession::connect(
        &mut stream,
        &local_private_key.0,
        &remote_static_public_key,
        &network_id,
        &profile_id,
    )
    .map_err(|error| format!("Noise XX sync authentication failed: {error}"))?;
    if session.remote_static_public_key() != &remote_static_public_key {
        return Err("sync peer static key differs from the configured pin".into());
    }
    session
        .write_record(&mut stream, &request)
        .map_err(|error| format!("send encrypted canonical sync request: {error}"))?;
    let response_bytes = session
        .read_record(&mut stream)
        .map_err(|error| format!("read encrypted canonical sync response: {error}"))?;
    let response = decode_sync_response(&response_bytes, max_blocks, max_bytes)?;

    if response.base_height > local_height {
        return Err(format!(
            "peer checkpoint base {} is ahead of local height {}; obtain an independently authenticated checkpoint first",
            response.base_height, local_height
        ));
    }
    if response.base_height == local_height && response.base_tip != local_tip {
        return Err("peer base tip does not match the local canonical tip".into());
    }
    if response.height < local_height && !response.envelopes.is_empty() {
        return Err("peer returned blocks despite advertising a lower canonical height".into());
    }
    if response.envelopes.len() as u64 > response.height.saturating_sub(local_height) {
        return Err(
            "peer returned more blocks than its advertised canonical height permits".into(),
        );
    }

    for envelope in &response.envelopes {
        let candidate = decode_candidate_network_block(envelope)
            .map_err(|error| format!("decode synced PTB2 block: {error:?}"))?;
        let mut locked = state
            .lock()
            .map_err(|_| "node state lock poisoned".to_string())?;
        if candidate.fee_block.is_some() != locked.runtime.is_qrun_v05_fee_only() {
            return Err("sync envelope execution mode differs from the local QRun profile".into());
        }
        let expected_height = locked
            .runtime
            .canonical_height()
            .checked_add(1)
            .ok_or("local chain height overflow")?;
        if candidate.block.height != expected_height {
            return Err(format!(
                "synced block height {} is not the expected next height {expected_height}",
                candidate.block.height
            ));
        }
        if candidate.header.previous_consensus_hash != locked.runtime.canonical_tip() {
            return Err("synced block does not extend the local canonical tip".into());
        }
        let previous_count = locked.runtime.retained_branch_count();
        let submit_result = {
            let NodeState {
                runtime,
                authenticator,
                clock,
                ..
            } = &mut *locked;
            runtime.submit_block(envelope, authenticator, clock)
        };
        submit_result
            .map_err(|error| format!("local consensus rejected synced block: {error:?}"))?;
        if locked.runtime.retained_branch_count() > previous_count {
            locked.refresh_receipts()?;
        }
    }

    let locked = state
        .lock()
        .map_err(|_| "node state lock poisoned".to_string())?;
    let current_height = locked.runtime.canonical_height();
    if current_height < response.height && response.envelopes.is_empty() {
        return Err("sync peer made no progress while advertising a higher tip".into());
    }
    if current_height == response.height
        && (locked.runtime.canonical_tip() != response.canonical_tip
            || locked.runtime.canonical_state_root() != response.state_root)
    {
        return Err(
            "local canonical tip/state root does not match the peer's advertised tip".into(),
        );
    }
    println!(
        "qrun_pow_authenticated_sync_page peer={peer} received={} local_height={} peer_height={}",
        response.envelopes.len(),
        current_height,
        response.height
    );
    Ok((current_height, response.height))
}

/// Catch up with a pinned peer over bounded authenticated pages. No peer-supplied checkpoint
/// is adopted automatically; if the advertised trusted base is ahead of our state this fails.
fn sync_from_peer_authenticated(
    peer: SocketAddr,
    state: &Arc<Mutex<NodeState>>,
    max_blocks: usize,
    max_bytes: usize,
) -> Result<u64, String> {
    if max_blocks == 0 || max_blocks > MAX_SYNC_PAGE_BLOCKS {
        return Err("canonical sync page block count is outside the allowed range".into());
    }
    let max_pages = (1_024usize + max_blocks - 1) / max_blocks + 1;
    let mut previous_height = state
        .lock()
        .map_err(|_| "node state lock poisoned".to_string())?
        .runtime
        .canonical_height();

    for _ in 0..max_pages {
        let (local_height, peer_height) =
            request_sync_page_authenticated(peer, state, max_blocks, max_bytes)?;
        if local_height > peer_height {
            return Err("pinned sync peer is behind the local canonical chain".into());
        }
        if local_height == peer_height {
            return Ok(local_height);
        }
        if local_height <= previous_height {
            return Err("authenticated sync stopped making canonical-height progress".into());
        }
        previous_height = local_height;
    }
    Err("authenticated sync exceeded the bounded catch-up page budget".into())
}

fn handle_block(stream: &mut TcpStream, state: &Arc<Mutex<NodeState>>) -> Result<(), String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| error.to_string())?;
    let (network_id, profile_id, local_private_key, trusted_peer_static_keys) = {
        let locked = state
            .lock()
            .map_err(|_| "node state lock poisoned".to_string())?;
        (
            locked.runtime.network_id(),
            locked.profile_id,
            locked.noise_private_key,
            locked.trusted_peer_static_keys.clone(),
        )
    };
    let mut noise_session = if let Some(mut private_key) = local_private_key {
        let result = QRunV05NoiseSession::accept(
            stream,
            &private_key,
            &trusted_peer_static_keys,
            &network_id,
            &profile_id,
        );
        private_key.fill(0);
        Some(
            result
                .map_err(|error| format!("Noise XX inbound peer authentication failed: {error}"))?,
        )
    } else {
        None
    };
    let payload = if let Some(session) = noise_session.as_mut() {
        let frame = session.read_record(stream).map_err(|error| {
            format!("read authenticated encrypted QRun application record: {error}")
        })?;
        if frame.starts_with(SYNC_REQUEST_MAGIC) {
            serve_sync_request(&frame, session, stream, state)?;
            return Ok(());
        }
        decode_block_frame(&frame)?
    } else {
        let mut header = [0u8; BLOCK_FRAME_HEADER_BYTES];
        stream
            .read_exact(&mut header)
            .map_err(|error| format!("read QRun PoW frame header: {error}"))?;
        if &header[..4] != BLOCK_MAGIC
            || u16::from_be_bytes([header[4], header[5]]) != BLOCK_PROTOCOL_VERSION
        {
            return Err("invalid QRun PoW frame magic/version".into());
        }
        let payload_len = u32::from_be_bytes(header[6..10].try_into().unwrap()) as usize;
        if payload_len == 0 || payload_len > MAX_BLOCK_FRAME_BYTES {
            return Err("invalid or oversized QRun PTB2 frame".into());
        }
        let mut full_frame = Vec::with_capacity(BLOCK_FRAME_HEADER_BYTES + payload_len);
        full_frame.extend_from_slice(&header);
        full_frame.resize(BLOCK_FRAME_HEADER_BYTES + payload_len, 0);
        stream
            .read_exact(&mut full_frame[BLOCK_FRAME_HEADER_BYTES..])
            .map_err(|error| format!("read PTB2 envelope: {error}"))?;
        decode_block_frame(&full_frame)?
    };
    let candidate = decode_candidate_network_block(&payload)
        .map_err(|error| format!("decode PTB2 envelope: {error:?}"))?;
    let height = candidate.block.height;
    let id = block_id(&payload);
    let (status, forward_peers, log) = {
        let mut locked = state
            .lock()
            .map_err(|_| "node state lock poisoned".to_string())?;
        if candidate.fee_block.is_some() != locked.runtime.is_qrun_v05_fee_only() {
            return Err("incoming block execution mode differs from the local QRun profile".into());
        }
        let previous_count = locked.runtime.retained_branch_count();
        let submit_result = {
            let NodeState {
                runtime,
                authenticator,
                clock,
                ..
            } = &mut *locked;
            runtime.submit_block(&payload, authenticator, clock)
        };
        match submit_result {
            Ok(canonical_tip) => {
                let inserted = locked.runtime.retained_branch_count() > previous_count;
                if inserted {
                    locked.refresh_receipts()?;
                }
                (
                    if inserted { 0u8 } else { 1u8 },
                    if inserted {
                        locked.block_peers.clone()
                    } else {
                        Vec::new()
                    },
                    format!(
                        "{} height={} canonical_height={} canonical_tip={}",
                        if inserted { "accepted" } else { "duplicate" },
                        height,
                        locked.runtime.canonical_height(),
                        hex(&canonical_tip)
                    ),
                )
            }
            Err(error) => (
                2u8,
                Vec::new(),
                format!("rejected height={height} reason={error:?}"),
            ),
        }
    };
    let ack = block_ack(status, height, id);
    if let Some(session) = noise_session.as_mut() {
        session
            .write_record(stream, &ack)
            .map_err(|error| format!("write encrypted QRun block ACK: {error}"))?;
    } else {
        stream.write_all(&ack).map_err(|error| error.to_string())?;
    }
    println!("qrun_pow_local_block_gossip {log}");
    if status == 0 {
        for peer in forward_peers {
            if peer == stream.peer_addr().unwrap_or(peer) {
                continue;
            }
            match send_block_to_peer(peer, &payload, state) {
                Ok(()) => println!("qrun_pow_local_block_forwarded peer={peer} height={height}"),
                Err(error) => eprintln!(
                    "qrun_pow_local_block_forward_failed peer={peer} reason={}",
                    error.replace(['\r', '\n'], "_")
                ),
            }
        }
    }
    Ok(())
}

fn poll_block_listener(
    listener: &TcpListener,
    state: &Arc<Mutex<NodeState>>,
) -> Result<bool, String> {
    match listener.accept() {
        Ok((mut stream, _)) => {
            if let Err(error) = handle_block(&mut stream, state) {
                eprintln!(
                    "qrun_pow_local_block_request_rejected reason={}",
                    error.replace(['\r', '\n'], "_")
                );
            }
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(false),
        Err(error) => Err(format!("block listener accept failed: {error}")),
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

    let mut block_to_broadcast: Option<Vec<u8>> = None;
    let mut peers_to_broadcast = Vec::new();
    let (ack, log_line) = {
        let mut locked = state
            .lock()
            .map_err(|_| "node state lock poisoned".to_string())?;
        if locked.receipts.contains_key(&txid) {
            (
                reject_ack(txid, TxIngressStatus::Duplicate, 0),
                format!("duplicate canonical txid={}", hex(&txid)),
            )
        } else {
            let timestamp = now_unix()?.max(
                locked
                    .runtime
                    .canonical_state()
                    .last_timestamp()
                    .saturating_add(1),
            );
            let envelope_result = {
                let auth = &locked.authenticator;
                locked
                    .runtime
                    .mine_candidate(timestamp, vec![tx.clone()], auth, 1)
            };
            match envelope_result {
                Ok(envelope) => {
                    let candidate = decode_candidate_network_block(&envelope)
                        .map_err(|error| format!("decode newly mined QFP5 envelope: {error:?}"))?;
                    if candidate.fee_block.is_some() != locked.runtime.is_qrun_v05_fee_only() {
                        return Err(
                            "mined envelope execution mode differs from the local QRun profile"
                                .into(),
                        );
                    }
                    let candidate_height = candidate.block.height;
                    let submit_result = {
                        let NodeState {
                            runtime,
                            authenticator,
                            clock,
                            ..
                        } = &mut *locked;
                        runtime.submit_block(&envelope, authenticator, clock)
                    };
                    match submit_result {
                        Ok(canonical_tip) => {
                            locked.refresh_receipts()?;
                            block_to_broadcast = Some(envelope.clone());
                            peers_to_broadcast = locked.block_peers.clone();
                            (
                                reject_ack(txid, TxIngressStatus::Accepted, 0),
                                format!(
                                    "accepted_pow_candidate txid={} height={} canonical_height={} canonical_tip={} canonically_included={}",
                                    hex(&txid), candidate_height, locked.runtime.canonical_height(),
                                    hex(&canonical_tip), locked.receipts.contains_key(&txid)
                                ),
                            )
                        }
                        Err(error) => (
                            reject_ack(txid, TxIngressStatus::Rejected, 0),
                            format!("pow_consensus_rejected txid={} error={error:?}", hex(&txid)),
                        ),
                    }
                }
                Err(error) => (
                    reject_ack(txid, TxIngressStatus::Rejected, 0),
                    format!("pow_mining_rejected txid={} error={error:?}", hex(&txid)),
                ),
            }
        }
    };
    for peer in peers_to_broadcast {
        if let Some(envelope) = block_to_broadcast.as_ref() {
            match send_block_to_peer(peer, envelope, state) {
                Ok(()) => println!("qrun_pow_local_block_broadcast peer={peer}"),
                Err(error) => eprintln!(
                    "qrun_pow_local_block_broadcast_failed peer={peer} reason={}",
                    error.replace(['\r', '\n'], "_")
                ),
            }
        }
    }
    stream.write_all(&ack).map_err(|error| error.to_string())?;
    println!("qrun_pow_local_tx_ingress {log_line}");
    Ok(())
}

fn poll_transaction_listener(
    listener: &TcpListener,
    state: &Arc<Mutex<NodeState>>,
) -> Result<bool, String> {
    match listener.accept() {
        Ok((mut stream, _)) => {
            if let Err(error) = handle_transaction(&mut stream, state) {
                eprintln!(
                    "qrun_pow_local_tx_request_rejected reason={}",
                    error.replace(['\r', '\n'], "_")
                );
            }
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(false),
        Err(error) => Err(format!("transaction listener accept failed: {error}")),
    }
}

fn run(config: Config) -> Result<(), String> {
    if !config.rpc_listen.ip().is_loopback()
        || !config.tx_listen.ip().is_loopback()
        || !config.block_listen.ip().is_loopback()
        || config.peers.iter().any(|peer| !peer.ip().is_loopback())
    {
        return Err("refusing non-loopback listener or peer".into());
    }
    fs::create_dir_all(&config.data_dir)
        .map_err(|error| format!("create data directory: {error}"))?;
    let authenticator = Ed25519TransactionAuthenticator::select(
        TransactionAuthenticatorKind::Ed25519V1,
        [AccountPublicKey {
            account_id: config.owner_account,
            public_key: config.owner_public_key,
        }],
    )
    .map_err(|error| format!("configure Ed25519 authenticator: {error:?}"))?;

    // This explicitly local-only smoke profile has an easy target. It verifies the QFP5
    // fee-only producer commitment and fork-selection path, but is not secure and must not be
    // reused for public consensus. Protocol version 5 is pinned to the exact candidate identity.
    let qrun_v05_identity = config.network_id
        == ai_native_l1_pow_bench::qrun_v05_profile_identity_candidate::PROPOSED_QRUN_V05_NETWORK_ID
        && config.owner_account
            == ai_native_l1_pow_bench::qrun_v05_profile_identity_candidate::PROPOSED_OWNER_ACCOUNT_ID;
    let mut params = ConsensusParameters::candidate_testnet()
        .map_err(|error| format!("load candidate PoW profile: {error:?}"))?;
    if qrun_v05_identity {
        params.protocol_version = 5;
    }
    params.initial_target = Uint256::MAX;
    params.pow_limit = Uint256::MAX;
    params.pow.memory_kib = 8 * 1024;
    params.pow.iterations = 1;
    params.pow.lanes = 1;
    let profile_params = params.clone();
    if !config.peers.is_empty() && config.noise_private_key_file.is_none() {
        return Err(
            "QFP5 peer operation requires the authenticated, pinned Noise transport".into(),
        );
    }
    let clock = SystemClockReferenceTime;
    let store_dir = if qrun_v05_identity {
        config.data_dir.join("qrun-v05-qfp5-store")
    } else {
        // Preserve isolated PTB2 fixtures for startup-sync compatibility tests; QRun v0.5 uses
        // its profile-specific directory so the two modes cannot share a manifest accidentally.
        config.data_dir.join("qrun-v05-pow-fork-store")
    };
    let mut runtime = QRunV05PowForkRuntime::open(
        &store_dir,
        config.network_id,
        config.owner_account,
        params,
        &authenticator,
        &clock,
    )
    .map_err(|error| format!("open QRun QFP5 fee-only runtime: {error:?}"))?;
    runtime
        .set_producer_account(config.producer_account)
        .map_err(|error| format!("configure fee-only producer: {error:?}"))?;
    let network_id = runtime.network_id();
    let genesis_id = runtime.genesis_commitment();
    let profile_id = profile_id(&network_id, &profile_params, &genesis_id);
    let root = runtime.canonical_state_root();
    let owner_balance = runtime
        .canonical_state()
        .account(&config.owner_account)
        .map_or(0, |account| account.balance);
    let total_supply = runtime
        .canonical_state()
        .total_value()
        .map_err(|error| format!("{error:?}"))?;

    println!("QRUN_V05_LOCAL_POW_LOOPBACK_TESTNET_READY");
    println!("mainnet=false");
    println!("network_class=local_loopback_pow_testnet_not_public");
    println!("network_id_hex={}", hex(&network_id));
    println!("genesis_id_hex={}", hex(&genesis_id));
    println!("profile_id_hex={}", hex(&profile_id));
    println!("owner_account_id_hex={}", hex(&config.owner_account));
    println!("producer_account_id_hex={}", hex(&config.producer_account));
    println!("owner_balance_atoms={owner_balance}");
    println!(
        "owner_balance_qzxb={:.8}",
        owner_balance as f64 / 100_000_000.0
    );
    println!("total_supply_atoms={total_supply}");
    println!("state_root_hex={}", hex(&root));
    println!("height={}", runtime.canonical_height());
    println!("rpc_listen={}", config.rpc_listen);
    println!("tx_listen={}", config.tx_listen);
    println!("block_listen={}", config.block_listen);
    println!("block_peer_count={}", config.peers.len());
    println!(
        "peer_transport={}",
        if config.noise_private_key_file.is_some() {
            "qrun_v05_noise_xx_pinned_candidate"
        } else {
            "plaintext_loopback_smoke_only"
        }
    );
    println!("consensus=PoW_fork_choice_persistent_PFS2");
    println!("security_note=loopback_only_max_target_smoke_profile_not_public_consensus");

    let state = Arc::new(Mutex::new(NodeState {
        runtime,
        authenticator,
        clock,
        receipts: BTreeMap::new(),
        profile_id,
        block_peers: config.peers.clone(),
        noise_private_key: config
            .noise_private_key_file
            .as_ref()
            .map(|path| {
                load_protected_noise_private_key(path, &network_id)
                    .map_err(|error| format!("load network-bound QRun Noise private key: {error}"))
            })
            .transpose()?,
        trusted_peer_static_keys: config.peer_static_public_keys.clone(),
        peer_static_keys_by_addr: config
            .peers
            .iter()
            .copied()
            .zip(config.peer_static_public_keys.iter().copied())
            .collect(),
    }));
    state
        .lock()
        .map_err(|_| "node state lock poisoned".to_string())?
        .refresh_receipts()?;

    if config.sync_on_start {
        let page_bytes = max_sync_response_block_bytes(MAX_SYNC_PAGE_BLOCKS)?;
        let mut synced = false;
        let mut last_error = "no pinned peers configured".to_string();
        for peer in &config.peers {
            match sync_from_peer_authenticated(*peer, &state, MAX_SYNC_PAGE_BLOCKS, page_bytes) {
                Ok(height) => {
                    println!(
                        "qrun_pow_authenticated_startup_sync_complete peer={peer} height={height}"
                    );
                    synced = true;
                    break;
                }
                Err(error) => {
                    eprintln!(
                        "qrun_pow_authenticated_startup_sync_failed peer={peer} reason={}",
                        error.replace(['\r', '\n'], "_")
                    );
                    last_error = error;
                }
            }
        }
        if !synced {
            return Err(format!(
                "authenticated startup sync requested but every pinned peer failed: {last_error}"
            ));
        }
    }

    // StoreWriterLock is deliberately single-writer. Keep all listener work on this one event
    // loop rather than moving the OS lock and its Windows OVERLAPPED state between worker threads.
    let rpc_listener =
        TcpListener::bind(config.rpc_listen).map_err(|error| format!("bind RPC: {error}"))?;
    let tx_listener = TcpListener::bind(config.tx_listen)
        .map_err(|error| format!("bind transaction ingress: {error}"))?;
    let block_listener = TcpListener::bind(config.block_listen)
        .map_err(|error| format!("bind block listener: {error}"))?;
    rpc_listener
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    tx_listener
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    block_listener
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    println!(
        "qrun_pow_local_rpc_ready address={} read_only=true mainnet=false",
        config.rpc_listen
    );
    println!(
        "qrun_pow_local_tx_ready address={} protocol=QZTS/1 mainnet=false",
        config.tx_listen
    );
    println!(
        "qrun_pow_local_block_ready address={} protocol=QRB5/2 loopback_only=true",
        config.block_listen
    );

    loop {
        let mut handled = false;
        handled |= poll_rpc_listener(&rpc_listener, &state)?;
        handled |= poll_transaction_listener(&tx_listener, &state)?;
        handled |= poll_block_listener(&block_listener, &state)?;
        if !handled {
            std::thread::sleep(Duration::from_millis(5));
        }
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
    use ai_native_l1_pow_bench::state_machine::Transaction;
    use ai_native_l1_pow_bench::transaction_auth::Ed25519TransactionSigner;
    use snow::{params::NoiseParams, Builder};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(1);

    struct TestDir(PathBuf);
    impl TestDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "qrun_v05_pow_local_node_{}_{}",
                std::process::id(),
                NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn smoke_params() -> ConsensusParameters {
        let mut params = ConsensusParameters::candidate_testnet().unwrap();
        params.initial_target = Uint256::MAX;
        params.pow_limit = Uint256::MAX;
        params.pow.memory_kib = 8 * 1024;
        params.pow.iterations = 1;
        params.pow.lanes = 1;
        params
    }

    fn node_state(
        directory: &Path,
        network: NetworkId,
        signer: &Ed25519TransactionSigner,
    ) -> NodeState {
        node_state_with_params(directory, network, signer, smoke_params())
    }

    fn node_state_with_params(
        directory: &Path,
        network: NetworkId,
        signer: &Ed25519TransactionSigner,
        params: ConsensusParameters,
    ) -> NodeState {
        let owner = signer.account_id();
        let authenticator = Ed25519TransactionAuthenticator::select(
            TransactionAuthenticatorKind::Ed25519V1,
            [AccountPublicKey {
                account_id: owner,
                public_key: signer.public_key(),
            }],
        )
        .unwrap();
        let clock = SystemClockReferenceTime;
        let profile_params = params.clone();
        let runtime =
            QRunV05PowForkRuntime::open(directory, network, owner, params, &authenticator, &clock)
                .unwrap();
        let profile_id = profile_id(&network, &profile_params, &runtime.genesis_commitment());
        let mut state = NodeState {
            runtime,
            authenticator,
            clock,
            receipts: BTreeMap::new(),
            profile_id,
            block_peers: Vec::new(),
            noise_private_key: None,
            trusted_peer_static_keys: Vec::new(),
            peer_static_keys_by_addr: BTreeMap::new(),
        };
        state.refresh_receipts().unwrap();
        state
    }

    fn qrun_v05_node_state(directory: &Path, signer: &Ed25519TransactionSigner) -> NodeState {
        use ai_native_l1_pow_bench::qrun_v05_profile_identity_candidate::{
            PROPOSED_OWNER_ACCOUNT_ID, PROPOSED_QRUN_V05_NETWORK_ID,
        };

        let network = PROPOSED_QRUN_V05_NETWORK_ID;
        let owner = PROPOSED_OWNER_ACCOUNT_ID;
        let authenticator = Ed25519TransactionAuthenticator::select(
            TransactionAuthenticatorKind::Ed25519V1,
            [AccountPublicKey {
                account_id: signer.account_id(),
                public_key: signer.public_key(),
            }],
        )
        .unwrap();
        let clock = SystemClockReferenceTime;
        let mut params = smoke_params();
        params.protocol_version = 5;
        let profile_params = params.clone();
        let mut runtime =
            QRunV05PowForkRuntime::open(directory, network, owner, params, &authenticator, &clock)
                .unwrap();
        runtime.set_producer_account(owner).unwrap();
        assert!(runtime.is_qrun_v05_fee_only());
        let profile_id = profile_id(&network, &profile_params, &runtime.genesis_commitment());
        let mut state = NodeState {
            runtime,
            authenticator,
            clock,
            receipts: BTreeMap::new(),
            profile_id,
            block_peers: Vec::new(),
            noise_private_key: None,
            trusted_peer_static_keys: Vec::new(),
            peer_static_keys_by_addr: BTreeMap::new(),
        };
        state.refresh_receipts().unwrap();
        state
    }

    fn deliver_ptb2_over_tcp(
        listener: &TcpListener,
        state: &Arc<Mutex<NodeState>>,
        envelope: &[u8],
    ) {
        let candidate = decode_candidate_network_block(envelope).unwrap();
        let expected_hash = block_id(envelope);
        let mut sender = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        sender
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        sender
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        sender
            .write_all(&encode_block_frame(envelope).unwrap())
            .unwrap();

        let (mut receiver, _) = listener.accept().unwrap();
        handle_block(&mut receiver, state).unwrap();

        let mut ack = [0u8; BLOCK_ACK_BYTES];
        sender.read_exact(&mut ack).unwrap();
        assert_eq!(&ack[..4], BLOCK_ACK_MAGIC);
        assert_eq!(u16::from_be_bytes([ack[4], ack[5]]), BLOCK_PROTOCOL_VERSION);
        assert_eq!(ack[6], 0);
        assert_eq!(
            u64::from_be_bytes(ack[7..15].try_into().unwrap()),
            candidate.block.height
        );
        assert_eq!(&ack[15..47], expected_hash.as_slice());
    }

    fn test_noise_keypair() -> ([u8; 32], [u8; 32]) {
        let params: NoiseParams = "Noise_XX_25519_ChaChaPoly_SHA256".parse().unwrap();
        let mut pair = Builder::new(params).generate_keypair().unwrap();
        let mut private = [0u8; 32];
        private.copy_from_slice(&pair.private);
        let mut public = [0u8; 32];
        public.copy_from_slice(&pair.public);
        pair.private.fill(0);
        pair.public.fill(0);
        (private, public)
    }

    fn deliver_authenticated_block(
        listener: &TcpListener,
        receiver: &Arc<Mutex<NodeState>>,
        sender: &Arc<Mutex<NodeState>>,
        envelope: &[u8],
    ) {
        let peer = listener.local_addr().unwrap();
        let (network_id, profile_id, mut local_private_key, remote_static_public_key) = {
            let locked = sender.lock().unwrap();
            (
                locked.runtime.network_id(),
                locked.profile_id,
                locked.noise_private_key.unwrap(),
                *locked.peer_static_keys_by_addr.get(&peer).unwrap(),
            )
        };
        let envelope = envelope.to_vec();
        let client = std::thread::spawn(move || {
            let result = send_block_to_peer_authenticated(
                peer,
                &envelope,
                &network_id,
                &profile_id,
                local_private_key,
                &remote_static_public_key,
            );
            local_private_key.fill(0);
            result.unwrap();
        });
        let (mut stream, _) = listener.accept().unwrap();
        handle_block(&mut stream, receiver).unwrap();
        client.join().unwrap();
    }

    #[test]
    fn bounded_sync_wire_rejects_bad_versions_trailing_bytes_and_budget_overruns() {
        let request = encode_sync_request(7, 2, 1_024).unwrap();
        assert_eq!(decode_sync_request(&request).unwrap(), (7, 2, 1_024));
        let mut bad_request = request.clone();
        bad_request[0] ^= 0x40;
        assert!(decode_sync_request(&bad_request).is_err());
        assert!(encode_sync_request(0, 2, 1_024).is_err());
        assert!(encode_sync_request(7, 0, 1_024).is_err());

        let envelope = vec![0xAB; 8];
        let response =
            encode_sync_response(0, 9, [1; 32], [2; 32], [3; 32], &[envelope.clone()]).unwrap();
        let decoded = decode_sync_response(&response, 1, 8).unwrap();
        assert_eq!(decoded.envelopes, vec![envelope.clone()]);
        assert_eq!(decoded.height, 9);
        assert!(decode_sync_response(&response, 1, 7).is_err());
        assert!(decode_sync_response(&response, 0, 8).is_err());

        let mut trailing = response.clone();
        trailing.push(0);
        assert!(decode_sync_response(&trailing, 1, 8).is_err());
        let two_envelopes = encode_sync_response(
            0,
            9,
            [1; 32],
            [2; 32],
            [3; 32],
            &[envelope.clone(), envelope],
        )
        .unwrap();
        assert!(decode_sync_response(&two_envelopes, 1, 64).is_err());
    }

    #[test]
    fn consensus_profile_fingerprint_changes_when_pow_parameters_change() {
        let network = [0x54; 32];
        let baseline = smoke_params();
        let mut modified = baseline.clone();
        modified.pow.memory_kib += 1;
        let genesis = [0x64; 32];
        let genesis_other = [0x65; 32];
        let baseline_fingerprint = profile_id(&network, &baseline, &genesis);
        assert_eq!(
            baseline_fingerprint,
            profile_id(&network, &smoke_params(), &genesis)
        );
        assert_ne!(
            baseline_fingerprint,
            profile_id(&network, &modified, &genesis)
        );
        assert_ne!(
            baseline_fingerprint,
            profile_id(&network, &baseline, &genesis_other)
        );
    }

    #[test]
    fn authenticated_mode_refuses_unpinned_peer_instead_of_plaintext_fallback() {
        let dir = TestDir::new();
        let network = [0x53; 32];
        let signer = Ed25519TransactionSigner::from_seed([0x37; 32]);
        let state = Arc::new(Mutex::new(node_state(&dir.0, network, &signer)));
        state.lock().unwrap().noise_private_key = Some([0xA3; 32]);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = listener.local_addr().unwrap();

        let error = send_block_to_peer(peer, b"not-a-block", &state).unwrap_err();
        assert!(error.contains("authenticated block peer config is incomplete"));

        listener.set_nonblocking(true).unwrap();
        assert!(matches!(
            listener.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
    }

    #[test]
    fn smoke_node_public_listener_guard_remains_fail_closed() {
        assert!(parse_socket("0.0.0.0:49341", "--block-listen").is_err());
        assert!(parse_socket("192.0.2.10:49341", "--block-listen").is_err());
        assert!(parse_socket("127.0.0.1:49341", "--block-listen").is_ok());
    }

    #[test]
    fn two_pow_nodes_sync_signed_transfer_over_real_loopback_socket() {
        let first_dir = TestDir::new();
        let second_dir = TestDir::new();
        let network = [0x51; 32];
        let signer = Ed25519TransactionSigner::from_seed([0x35; 32]);
        let owner = signer.account_id();
        let recipient = [0x77; 32];
        let first = Arc::new(Mutex::new(node_state(&first_dir.0, network, &signer)));
        let second = Arc::new(Mutex::new(node_state(&second_dir.0, network, &signer)));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();

        let timestamp = now_unix().unwrap();
        let empty_envelope = {
            let mut node = first.lock().unwrap();
            let auth = &node.authenticator;
            node.runtime
                .mine_candidate(timestamp, Vec::new(), auth, 1)
                .unwrap()
        };
        {
            let mut node = first.lock().unwrap();
            let NodeState {
                runtime,
                authenticator,
                clock,
                ..
            } = &mut *node;
            runtime
                .submit_block(&empty_envelope, authenticator, clock)
                .unwrap();
        }
        deliver_ptb2_over_tcp(&listener, &second, &empty_envelope);

        let mut tx = Transaction {
            network_id: network,
            sender: owner,
            recipient,
            nonce: 1,
            amount: 1_000,
            fee: 1,
            expires_at: timestamp + 3_600,
            signature: Vec::new(),
        };
        signer.sign_transaction(&mut tx).unwrap();
        let transfer_envelope = {
            let mut node = first.lock().unwrap();
            let auth = &node.authenticator;
            node.runtime
                .mine_candidate(timestamp + 1, vec![tx.clone()], auth, 1)
                .unwrap()
        };
        {
            let mut node = first.lock().unwrap();
            let NodeState {
                runtime,
                authenticator,
                clock,
                ..
            } = &mut *node;
            runtime
                .submit_block(&transfer_envelope, authenticator, clock)
                .unwrap();
        }
        deliver_ptb2_over_tcp(&listener, &second, &transfer_envelope);

        let first = first.lock().unwrap();
        let second = second.lock().unwrap();
        assert_eq!(first.runtime.canonical_height(), 2);
        assert_eq!(second.runtime.canonical_height(), 2);
        assert_eq!(
            first.runtime.canonical_tip(),
            second.runtime.canonical_tip()
        );
        assert_eq!(
            first.runtime.canonical_state_root(),
            second.runtime.canonical_state_root()
        );
        assert_eq!(
            second
                .runtime
                .canonical_state()
                .account(&recipient)
                .unwrap()
                .balance,
            1_000
        );
        assert_eq!(
            second.runtime.canonical_state().total_value().unwrap(),
            ai_native_l1_pow_bench::state_machine::MAX_TOTAL_SUPPLY_ATOMS
        );
        let txid = transaction_id(&tx).unwrap();
        assert_eq!(
            second.receipts.get(&txid).map(|receipt| receipt.height),
            Some(2)
        );
    }

    #[test]
    fn fresh_node_catches_up_canonical_signed_transfer_over_authenticated_sync_page() {
        let source_dir = TestDir::new();
        let receiver_dir = TestDir::new();
        let network = [0x55; 32];
        let signer = Ed25519TransactionSigner::from_seed([0x38; 32]);
        let owner = signer.account_id();
        let recipient = [0x7a; 32];
        let source = Arc::new(Mutex::new(node_state(&source_dir.0, network, &signer)));
        let receiver = Arc::new(Mutex::new(node_state(&receiver_dir.0, network, &signer)));
        let timestamp = now_unix().unwrap();

        let first_envelope = {
            let mut node = source.lock().unwrap();
            let auth = &node.authenticator;
            node.runtime
                .mine_candidate(timestamp, Vec::new(), auth, 1)
                .unwrap()
        };
        {
            let mut node = source.lock().unwrap();
            let NodeState {
                runtime,
                authenticator,
                clock,
                ..
            } = &mut *node;
            runtime
                .submit_block(&first_envelope, authenticator, clock)
                .unwrap();
        }

        let mut tx = Transaction {
            network_id: network,
            sender: owner,
            recipient,
            nonce: 1,
            amount: 2_500,
            fee: 1,
            expires_at: timestamp + 3_600,
            signature: Vec::new(),
        };
        signer.sign_transaction(&mut tx).unwrap();
        let second_envelope = {
            let mut node = source.lock().unwrap();
            let auth = &node.authenticator;
            node.runtime
                .mine_candidate(timestamp + 1, vec![tx.clone()], auth, 1)
                .unwrap()
        };
        {
            let mut node = source.lock().unwrap();
            let NodeState {
                runtime,
                authenticator,
                clock,
                ..
            } = &mut *node;
            runtime
                .submit_block(&second_envelope, authenticator, clock)
                .unwrap();
        }

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = listener.local_addr().unwrap();
        let (mut source_private, source_public) = test_noise_keypair();
        let (mut receiver_private, receiver_public) = test_noise_keypair();
        {
            let mut node = source.lock().unwrap();
            node.noise_private_key = Some(source_private);
            node.trusted_peer_static_keys = vec![receiver_public];
        }
        {
            let mut node = receiver.lock().unwrap();
            node.noise_private_key = Some(receiver_private);
            node.trusted_peer_static_keys = vec![source_public];
            node.peer_static_keys_by_addr.insert(peer, source_public);
            receiver_private.fill(0);
        }

        let page_budget = max_sync_response_block_bytes(8).unwrap();
        let (base_height, peer_height, base_tip, peer_tip, peer_root, peer_envelopes, peer_profile) = {
            let node = source.lock().unwrap();
            let envelopes = node
                .runtime
                .canonical_envelopes_range(1, 8, page_budget)
                .unwrap();
            (
                node.runtime.archive_base_height(),
                node.runtime.canonical_height(),
                node.runtime.archive_base_tip(),
                node.runtime.canonical_tip(),
                node.runtime.canonical_state_root(),
                envelopes,
                node.profile_id,
            )
        };
        let accepted = listener.try_clone().unwrap();
        let mut server_private = source_private;
        source_private.fill(0);
        let network_for_server = network;
        let server = std::thread::spawn(move || {
            let (mut stream, _) = accepted.accept().unwrap();
            let trusted_client = [receiver_public];
            let mut session = QRunV05NoiseSession::accept(
                &mut stream,
                &server_private,
                &trusted_client,
                &network_for_server,
                &peer_profile,
            )
            .unwrap();
            let request = session.read_record(&mut stream).unwrap();
            let (start_height, max_blocks, max_bytes) = decode_sync_request(&request).unwrap();
            assert_eq!(start_height, 1);
            assert_eq!(max_blocks, 8);
            assert_eq!(max_bytes, page_budget);
            let response = encode_sync_response(
                base_height,
                peer_height,
                base_tip,
                peer_tip,
                peer_root,
                &peer_envelopes,
            )
            .unwrap();
            session.write_record(&mut stream, &response).unwrap();
            server_private.fill(0);
        });
        let synced_height = sync_from_peer_authenticated(peer, &receiver, 8, page_budget).unwrap();
        server.join().unwrap();

        let source = source.lock().unwrap();
        let receiver = receiver.lock().unwrap();
        assert_eq!(synced_height, 2);
        assert_eq!(
            receiver.runtime.canonical_height(),
            source.runtime.canonical_height()
        );
        assert_eq!(
            receiver.runtime.canonical_tip(),
            source.runtime.canonical_tip()
        );
        assert_eq!(
            receiver.runtime.canonical_state_root(),
            source.runtime.canonical_state_root()
        );
        assert_eq!(
            receiver
                .runtime
                .canonical_state()
                .account(&recipient)
                .unwrap()
                .balance,
            2_500
        );
        assert_eq!(
            receiver.runtime.canonical_state().total_value().unwrap(),
            ai_native_l1_pow_bench::state_machine::MAX_TOTAL_SUPPLY_ATOMS
        );
        assert_eq!(
            receiver
                .receipts
                .get(&transaction_id(&tx).unwrap())
                .map(|receipt| receipt.height),
            Some(2)
        );
    }

    #[test]
    fn fresh_node_catches_up_multiple_pages_through_authenticated_sync_handler() {
        let source_dir = TestDir::new();
        let receiver_dir = TestDir::new();
        let source_path = source_dir.0.clone();
        let network = [0x56; 32];
        let seed = [0x39; 32];
        let signer = Ed25519TransactionSigner::from_seed(seed);
        let mut sync_params = smoke_params();
        sync_params.pow.memory_kib = 8;
        let owner = signer.account_id();
        let recipient = [0x7b; 32];
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = listener.local_addr().unwrap();

        let (mut server_private, server_public) = test_noise_keypair();
        let (mut receiver_private, receiver_public) = test_noise_keypair();
        let receiver = Arc::new(Mutex::new(node_state_with_params(
            &receiver_dir.0,
            network,
            &signer,
            sync_params.clone(),
        )));
        {
            let mut node = receiver.lock().unwrap();
            node.noise_private_key = Some(receiver_private);
            node.trusted_peer_static_keys = vec![server_public];
            node.peer_static_keys_by_addr.insert(peer, server_public);
            receiver_private.fill(0);
        }

        let (ready_sender, ready_receiver) = std::sync::mpsc::channel();
        let server_params = sync_params.clone();
        let server = std::thread::spawn(move || {
            let signer = Ed25519TransactionSigner::from_seed(seed);
            let mut source = node_state_with_params(&source_path, network, &signer, server_params);
            source.noise_private_key = Some(server_private);
            source.trusted_peer_static_keys = vec![receiver_public];
            server_private.fill(0);
            let source = Arc::new(Mutex::new(source));
            let timestamp = now_unix().unwrap();

            let first_envelope = {
                let mut node = source.lock().unwrap();
                let auth = &node.authenticator;
                node.runtime
                    .mine_candidate(timestamp, Vec::new(), auth, 1)
                    .unwrap()
            };
            {
                let mut node = source.lock().unwrap();
                let NodeState {
                    runtime,
                    authenticator,
                    clock,
                    ..
                } = &mut *node;
                runtime
                    .submit_block(&first_envelope, authenticator, clock)
                    .unwrap();
            }

            let mut tx = Transaction {
                network_id: network,
                sender: owner,
                recipient,
                nonce: 1,
                amount: 2_500,
                fee: 1,
                expires_at: timestamp + 3_600,
                signature: Vec::new(),
            };
            signer.sign_transaction(&mut tx).unwrap();
            let txid = transaction_id(&tx).unwrap();
            let second_envelope = {
                let mut node = source.lock().unwrap();
                let auth = &node.authenticator;
                node.runtime
                    .mine_candidate(timestamp + 1, vec![tx], auth, 1)
                    .unwrap()
            };
            {
                let mut node = source.lock().unwrap();
                let NodeState {
                    runtime,
                    authenticator,
                    clock,
                    ..
                } = &mut *node;
                runtime
                    .submit_block(&second_envelope, authenticator, clock)
                    .unwrap();
            }

            for height in 3..=18 {
                let envelope = {
                    let mut node = source.lock().unwrap();
                    let auth = &node.authenticator;
                    node.runtime
                        .mine_candidate(timestamp + height, Vec::new(), auth, 1)
                        .unwrap()
                };
                let mut node = source.lock().unwrap();
                let NodeState {
                    runtime,
                    authenticator,
                    clock,
                    ..
                } = &mut *node;
                runtime
                    .submit_block(&envelope, authenticator, clock)
                    .unwrap();
            }

            source.lock().unwrap().refresh_receipts().unwrap();
            // The handshake deadline starts only after PoW fixture construction is complete.
            ready_sender.send(()).unwrap();
            // Serve three 8-block-bounded requests through the real authenticated node handler.
            for _ in 0..3 {
                let (mut stream, _) = listener.accept().unwrap();
                handle_block(&mut stream, &source).unwrap();
            }

            let node = source.lock().unwrap();
            (
                txid,
                node.runtime.canonical_height(),
                node.runtime.canonical_tip(),
                node.runtime.canonical_state_root(),
                node.runtime
                    .canonical_state()
                    .account(&recipient)
                    .unwrap()
                    .balance,
                node.runtime.canonical_state().total_value().unwrap(),
                node.receipts.get(&txid).map(|receipt| receipt.height),
            )
        });

        ready_receiver
            .recv_timeout(Duration::from_secs(30))
            .expect("PoW fixture and authenticated sync listener should become ready");
        let page_budget = max_sync_response_block_bytes(8).unwrap();
        let synced_height = sync_from_peer_authenticated(peer, &receiver, 8, page_budget).unwrap();
        let (
            txid,
            source_height,
            source_tip,
            source_root,
            source_balance,
            source_supply,
            source_receipt,
        ) = server.join().unwrap();
        let receiver = receiver.lock().unwrap();

        assert_eq!(synced_height, 18);
        assert_eq!(source_height, 18);
        assert_eq!(receiver.runtime.canonical_height(), source_height);
        assert_eq!(receiver.runtime.canonical_tip(), source_tip);
        assert_eq!(receiver.runtime.canonical_state_root(), source_root);
        assert_eq!(
            receiver
                .runtime
                .canonical_state()
                .account(&recipient)
                .unwrap()
                .balance,
            2_500
        );
        assert_eq!(
            receiver
                .runtime
                .canonical_state()
                .account(&recipient)
                .unwrap()
                .balance,
            source_balance
        );
        assert_eq!(
            receiver.runtime.canonical_state().total_value().unwrap(),
            source_supply
        );
        assert_eq!(
            source_supply,
            ai_native_l1_pow_bench::state_machine::MAX_TOTAL_SUPPLY_ATOMS
        );
        assert_eq!(
            receiver.receipts.get(&txid).map(|receipt| receipt.height),
            Some(2)
        );
        assert_eq!(source_receipt, Some(2));
    }

    #[test]
    fn qrun_fee_only_qfp5_authenticated_gossip_and_sync_converge() {
        use ai_native_l1_pow_bench::{
            qrun_v05_profile_identity_candidate::PROPOSED_OWNER_ACCOUNT_ID,
            state_machine::MAX_TOTAL_SUPPLY_ATOMS,
        };

        let source_dir = TestDir::new();
        let receiver_dir = TestDir::new();
        let fresh_dir = TestDir::new();
        let source_signer = Ed25519TransactionSigner::from_seed([0x31; 32]);
        let receiver_signer = Ed25519TransactionSigner::from_seed([0x32; 32]);
        let fresh_signer = Ed25519TransactionSigner::from_seed([0x33; 32]);
        let source = Arc::new(Mutex::new(qrun_v05_node_state(
            &source_dir.0,
            &source_signer,
        )));
        let receiver = Arc::new(Mutex::new(qrun_v05_node_state(
            &receiver_dir.0,
            &receiver_signer,
        )));
        let gossip_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let gossip_peer = gossip_listener.local_addr().unwrap();
        let (mut source_private, source_public) = test_noise_keypair();
        let (mut receiver_private, receiver_public) = test_noise_keypair();
        {
            let mut node = source.lock().unwrap();
            node.noise_private_key = Some(source_private);
            node.trusted_peer_static_keys = vec![receiver_public];
            node.peer_static_keys_by_addr
                .insert(gossip_peer, receiver_public);
            node.block_peers = vec![gossip_peer];
            source_private.fill(0);
        }
        {
            let mut node = receiver.lock().unwrap();
            node.noise_private_key = Some(receiver_private);
            node.trusted_peer_static_keys = vec![source_public];
            receiver_private.fill(0);
        }

        let timestamp = now_unix().unwrap();
        let envelope = {
            let mut node = source.lock().unwrap();
            let auth = &node.authenticator;
            node.runtime
                .mine_candidate(timestamp, Vec::new(), auth, 1)
                .unwrap()
        };
        assert!(envelope.starts_with(b"QFP5"));
        {
            let mut node = source.lock().unwrap();
            let NodeState {
                runtime,
                authenticator,
                clock,
                ..
            } = &mut *node;
            runtime
                .submit_block(&envelope, authenticator, clock)
                .unwrap();
        }
        deliver_authenticated_block(&gossip_listener, &receiver, &source, &envelope);

        let sync_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let sync_peer = sync_listener.local_addr().unwrap();
        let (mut fresh_private, fresh_public) = test_noise_keypair();
        {
            let mut node = source.lock().unwrap();
            node.trusted_peer_static_keys.push(fresh_public);
        }
        let fresh = Arc::new(Mutex::new(qrun_v05_node_state(&fresh_dir.0, &fresh_signer)));
        {
            let mut node = fresh.lock().unwrap();
            node.noise_private_key = Some(fresh_private);
            node.trusted_peer_static_keys = vec![source_public];
            node.peer_static_keys_by_addr
                .insert(sync_peer, source_public);
            fresh_private.fill(0);
        }

        // The store lock is deliberately not Send on Windows, so the source node remains on the
        // test thread. The client worker carries only the network identity, Noise key and wire bytes.
        let (network, profile, client_private) = {
            let node = fresh.lock().unwrap();
            (
                node.runtime.network_id(),
                node.profile_id,
                node.noise_private_key.unwrap(),
            )
        };
        let page_bytes = max_sync_response_block_bytes(MAX_SYNC_PAGE_BLOCKS).unwrap();
        let request = encode_sync_request(1, MAX_SYNC_PAGE_BLOCKS, page_bytes).unwrap();
        let client = std::thread::spawn(move || {
            let private_key = EphemeralNoisePrivateKey(client_private);
            let mut stream =
                TcpStream::connect_timeout(&sync_peer, Duration::from_secs(2)).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(6)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(6)))
                .unwrap();
            let mut session = QRunV05NoiseSession::connect(
                &mut stream,
                &private_key.0,
                &source_public,
                &network,
                &profile,
            )
            .unwrap();
            session.write_record(&mut stream, &request).unwrap();
            session.read_record(&mut stream).unwrap()
        });
        let (mut stream, _) = sync_listener.accept().unwrap();
        handle_block(&mut stream, &source).unwrap();
        let response_bytes = client.join().unwrap();
        let response =
            decode_sync_response(&response_bytes, MAX_SYNC_PAGE_BLOCKS, page_bytes).unwrap();
        assert_eq!(response.height, 1);
        assert_eq!(response.envelopes.len(), 1);
        assert!(response.envelopes[0].starts_with(b"QFP5"));
        for envelope in &response.envelopes {
            let candidate = decode_candidate_network_block(envelope).unwrap();
            assert!(candidate.fee_block.is_some());
            let mut node = fresh.lock().unwrap();
            let NodeState {
                runtime,
                authenticator,
                clock,
                ..
            } = &mut *node;
            runtime
                .submit_block(envelope, authenticator, clock)
                .unwrap();
            node.refresh_receipts().unwrap();
        }

        let source = source.lock().unwrap();
        let receiver = receiver.lock().unwrap();
        let fresh = fresh.lock().unwrap();
        assert_eq!(receiver.runtime.canonical_height(), 1);
        assert_eq!(fresh.runtime.canonical_height(), 1);
        assert_eq!(
            source.runtime.canonical_tip(),
            receiver.runtime.canonical_tip()
        );
        assert_eq!(
            source.runtime.canonical_tip(),
            fresh.runtime.canonical_tip()
        );
        assert_eq!(
            source.runtime.canonical_state_root(),
            receiver.runtime.canonical_state_root()
        );
        assert_eq!(
            source.runtime.canonical_state_root(),
            fresh.runtime.canonical_state_root()
        );
        for node in [&*source, &*receiver, &*fresh] {
            assert_eq!(
                node.runtime.canonical_state().total_value().unwrap(),
                MAX_TOTAL_SUPPLY_ATOMS
            );
            assert_eq!(
                node.runtime
                    .canonical_state()
                    .account(&PROPOSED_OWNER_ACCOUNT_ID)
                    .unwrap()
                    .balance as u128,
                MAX_TOTAL_SUPPLY_ATOMS
            );
        }
    }

    #[test]
    fn two_qrun_nodes_sync_signed_transfer_over_authenticated_noise_xx() {
        let first_dir = TestDir::new();
        let second_dir = TestDir::new();
        let network = [0x52; 32];
        let signer = Ed25519TransactionSigner::from_seed([0x36; 32]);
        let owner = signer.account_id();
        let recipient = [0x79; 32];
        let first = Arc::new(Mutex::new(node_state(&first_dir.0, network, &signer)));
        let second = Arc::new(Mutex::new(node_state(&second_dir.0, network, &signer)));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = listener.local_addr().unwrap();
        let (mut first_private, first_public) = test_noise_keypair();
        let (mut second_private, second_public) = test_noise_keypair();
        {
            let mut node = first.lock().unwrap();
            node.noise_private_key = Some(first_private);
            node.trusted_peer_static_keys = vec![second_public];
            node.peer_static_keys_by_addr.insert(peer, second_public);
            node.block_peers = vec![peer];
            first_private.fill(0);
        }
        {
            let mut node = second.lock().unwrap();
            node.noise_private_key = Some(second_private);
            node.trusted_peer_static_keys = vec![first_public];
            second_private.fill(0);
        }

        let timestamp = now_unix().unwrap();
        let empty_envelope = {
            let mut node = first.lock().unwrap();
            let auth = &node.authenticator;
            node.runtime
                .mine_candidate(timestamp, Vec::new(), auth, 1)
                .unwrap()
        };
        {
            let mut node = first.lock().unwrap();
            let NodeState {
                runtime,
                authenticator,
                clock,
                ..
            } = &mut *node;
            runtime
                .submit_block(&empty_envelope, authenticator, clock)
                .unwrap();
        }
        deliver_authenticated_block(&listener, &second, &first, &empty_envelope);

        let mut tx = Transaction {
            network_id: network,
            sender: owner,
            recipient,
            nonce: 1,
            amount: 2_500,
            fee: 1,
            expires_at: timestamp + 3_600,
            signature: Vec::new(),
        };
        signer.sign_transaction(&mut tx).unwrap();
        let transfer_envelope = {
            let mut node = first.lock().unwrap();
            let auth = &node.authenticator;
            node.runtime
                .mine_candidate(timestamp + 1, vec![tx.clone()], auth, 1)
                .unwrap()
        };
        {
            let mut node = first.lock().unwrap();
            let NodeState {
                runtime,
                authenticator,
                clock,
                ..
            } = &mut *node;
            runtime
                .submit_block(&transfer_envelope, authenticator, clock)
                .unwrap();
        }
        deliver_authenticated_block(&listener, &second, &first, &transfer_envelope);

        let txid = transaction_id(&tx).unwrap();
        let first = first.lock().unwrap();
        let second = second.lock().unwrap();
        assert_eq!(first.runtime.canonical_height(), 2);
        assert_eq!(second.runtime.canonical_height(), 2);
        assert_eq!(
            first.runtime.canonical_tip(),
            second.runtime.canonical_tip()
        );
        assert_eq!(
            first.runtime.canonical_state_root(),
            second.runtime.canonical_state_root()
        );
        assert_eq!(
            second
                .runtime
                .canonical_state()
                .account(&recipient)
                .unwrap()
                .balance,
            2_500
        );
        assert_eq!(
            second.runtime.canonical_state().total_value().unwrap(),
            ai_native_l1_pow_bench::state_machine::MAX_TOTAL_SUPPLY_ATOMS
        );
        assert_eq!(
            second.receipts.get(&txid).map(|receipt| receipt.height),
            Some(2)
        );
    }
}

#[cfg(test)]
mod tx_ingress_tests {
    use super::*;
    use ai_native_l1_pow_bench::qzbe_tx_ingress_candidate::{decode_ack, encode_request};
    use ai_native_l1_pow_bench::state_machine::{encode_transaction, Transaction};
    use ai_native_l1_pow_bench::transaction_auth::Ed25519TransactionSigner;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TX_TEST: AtomicU64 = AtomicU64::new(1);
    struct TestDir(PathBuf);
    impl TestDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "qrun_v05_qzts_ingress_{}_{}",
                std::process::id(),
                NEXT_TX_TEST.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn test_params() -> ConsensusParameters {
        let mut params = ConsensusParameters::candidate_testnet().unwrap();
        params.initial_target = Uint256::MAX;
        params.pow_limit = Uint256::MAX;
        params.pow.memory_kib = 8 * 1024;
        params.pow.iterations = 1;
        params.pow.lanes = 1;
        params
    }

    fn test_node_state(
        directory: &Path,
        network: NetworkId,
        signer: &Ed25519TransactionSigner,
    ) -> NodeState {
        let account = signer.account_id();
        let authenticator = Ed25519TransactionAuthenticator::select(
            TransactionAuthenticatorKind::Ed25519V1,
            [AccountPublicKey {
                account_id: account,
                public_key: signer.public_key(),
            }],
        )
        .unwrap();
        let clock = SystemClockReferenceTime;
        let params = test_params();
        let profile_params = params.clone();
        let runtime = QRunV05PowForkRuntime::open(
            directory,
            network,
            account,
            params,
            &authenticator,
            &clock,
        )
        .unwrap();
        let profile_id = profile_id(&network, &profile_params, &runtime.genesis_commitment());
        let mut state = NodeState {
            runtime,
            authenticator,
            clock,
            receipts: BTreeMap::new(),
            profile_id,
            block_peers: Vec::new(),
            noise_private_key: None,
            trusted_peer_static_keys: Vec::new(),
            peer_static_keys_by_addr: BTreeMap::new(),
        };
        state.refresh_receipts().unwrap();
        state
    }

    #[test]
    fn qzts_signed_wallet_request_executes_and_persists_canonical_receipt() {
        let dir = TestDir::new();
        let network = [0x51; 32];
        let signer = Ed25519TransactionSigner::from_seed([0x46; 32]);
        let owner = signer.account_id();
        let recipient = [0x78; 32];
        let state = Arc::new(Mutex::new(test_node_state(&dir.0, network, &signer)));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();

        let timestamp = now_unix().unwrap();
        let mut tx = Transaction {
            network_id: network,
            sender: owner,
            recipient,
            nonce: 1,
            amount: 7_500,
            fee: 7,
            expires_at: timestamp + 3_600,
            signature: Vec::new(),
        };
        signer.sign_transaction(&mut tx).unwrap();
        let wire = encode_transaction(&tx).unwrap();
        client.write_all(&encode_request(&wire).unwrap()).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        handle_transaction(&mut server, &state).unwrap();

        let mut ack_wire = [0u8; ACK_BYTES];
        client.read_exact(&mut ack_wire).unwrap();
        let ack = decode_ack(&ack_wire).unwrap();
        let txid = transaction_id(&tx).unwrap();
        assert_eq!(ack.status, TxIngressStatus::Accepted);
        assert_eq!(ack.transaction_id, txid);

        let node = state.lock().unwrap();
        assert_eq!(node.runtime.canonical_height(), 1);
        assert_eq!(
            node.runtime
                .canonical_state()
                .account(&recipient)
                .unwrap()
                .balance,
            7_500
        );
        assert_eq!(
            node.runtime.canonical_state().total_value().unwrap(),
            ai_native_l1_pow_bench::state_machine::MAX_TOTAL_SUPPLY_ATOMS
        );
        assert_eq!(
            node.receipts.get(&txid).map(|receipt| receipt.height),
            Some(1)
        );
    }
}
