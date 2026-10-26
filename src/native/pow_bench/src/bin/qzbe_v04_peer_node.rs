//! CP-0413: isolated QZBE v2 authenticated two-node loopback runtime candidate.
//!
//! This binary is a QZBE v2 runtime candidate: it requires explicit network, Genesis-owner,
//! miner and issuance-schedule arguments and accepts one pinned Noise peer. Canonical v0.4 Argon2id
//! parameters are the default; the deliberately easy 8 MiB profile requires an explicit test-only
//! flag. Listener and peer addresses remain loopback-only until persistent external anti-rollback
//! anchoring and canonical-runtime activation are complete.

use ai_native_l1_pow_bench::{
    consensus::{ConsensusParameters, Uint256},
    devnet_noise_transport_candidate::{DevnetNoiseSession, MAX_NOISE_APPLICATION_RECORD_BYTES},
    monetary_genesis_v04_candidate::GenesisManifestV04,
    monetary_issuance_v04_candidate::V04MiningIssuanceScheduleCandidate,
    monetary_pow_v04_candidate::{
        qzbe_pow_digest, V04ExecutionForkChoiceOutcome, V04ExecutionPowEnvelope,
        MAX_ENCODED_V04_EXECUTION_POW_ENVELOPE_BYTES, MAX_QZBE_MINING_ATTEMPTS,
    },
    monetary_pow_v04_checkpoint_candidate::{
        QzbeCheckpointRecord, QzbeCheckpointValidationContext,
    },
    monetary_pow_v04_checkpoint_store_candidate::V04ExecutionCheckpointForkStoreCandidate,
    monetary_transition_v04_candidate::{
        MonetaryLedgerStateV04TransitionCandidate, V04ConsensusProfileCandidate,
    },
    noise_key_provisioning::load_protected_noise_private_key,
    private_testnet_driver::TargetHistory,
    state_machine::{AccountId, Transaction},
    transaction_auth::{
        account_id_from_public_key, AccountPublicKey, Ed25519TransactionAuthenticator,
        TransactionAuthenticatorKind,
    },
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env,
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process, thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const ACK_MAGIC: &[u8; 4] = b"QZA4";
const ACK_VERSION: u16 = 1;
const ACK_BYTES: usize = 183;
/// Root-level immutable profile lock for every QZBE candidate data directory.
/// Legacy PTB2/PFS2 and PMT3/PMT4 entrypoints detect its presence and fail closed.
const QZBE_RUNTIME_PROFILE_FILE: &str = "qzbe-runtime.profile";
const QZBE_RUNTIME_PROFILE_MAGIC: &[u8; 4] = b"QZRP";
const QZBE_RUNTIME_PROFILE_VERSION: u16 = 1;
const QZBE_RUNTIME_PROFILE_CHECKSUM_DOMAIN: &[u8] = b"AIN1-QZBE-RUNTIME-PROFILE-CHECKSUM-V1\0";
const QZBE_RUNTIME_PARAMS_DOMAIN: &[u8] = b"AIN1-QZBE-CONSENSUS-PARAMS-V1\0";
const QZBE_RUNTIME_PROFILE_PREFIX_BYTES: usize = 4 + 2 + 32 * 4;
const QZBE_RUNTIME_PROFILE_MARKER_BYTES: usize = QZBE_RUNTIME_PROFILE_PREFIX_BYTES + 32;
const MAX_MINE_BLOCKS: u64 = 32;
const MAX_PEER_MESSAGES: u64 = 512;
const DEFAULT_RUN_SECONDS: u64 = 30;

struct SecretKey([u8; 32]);
impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Debug, Clone)]
struct Args {
    data_dir: PathBuf,
    listen: SocketAddr,
    peers: Vec<SocketAddr>,
    network_id: [u8; 32],
    owner_id: [u8; 32],
    miner_id: [u8; 32],
    tx_public_key: [u8; 32],
    observe_account_id: [u8; 32],
    transaction: Option<Transaction>,
    probe_invalid_signature_first: bool,
    trusted_peer_keys: Vec<[u8; 32]>,
    noise_key_path: PathBuf,
    initial_subsidy_atoms: u128,
    blocks_per_halving: u64,
    mine_blocks: u64,
    run_seconds: u64,
    stop_after_height: Option<u64>,
    exit_after_mining: bool,
    test_easy_pow: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Snapshot {
    height: u64,
    tip: [u8; 32],
    state_root: [u8; 32],
    generation: u64,
}

#[derive(Debug)]
struct PeerAck {
    status: u8,
    candidate_digest: [u8; 32],
    snapshot: Snapshot,
}

fn usage() -> &'static str {
    "Usage: qzbe_v04_peer_node --network-id HEX64 --owner-id HEX64 --miner-id HEX64 --tx-public-key-hex HEX64 --observe-account-id HEX64 --data-dir ABS_PATH --listen 127.0.0.1:PORT --noise-static-private-key-dpapi-file PATH --trusted-peer-key-hex HEX64 [--trusted-peer-key-hex HEX64 ...] --initial-subsidy-atoms U128 --blocks-per-halving U64 [--tx-recipient-id HEX64 --tx-nonce U64 --tx-amount-atoms U64 --tx-fee-atoms U64 --tx-expires-at U64 --tx-signature-hex HEX128] [--probe-invalid-signature-first] [--test-easy-pow] [--peer 127.0.0.1:PORT ...] [--mine-blocks N] [--run-seconds N] [--stop-after-height N] [--exit-after-mining]\nQZBE v2 runtime candidate with statically pinned multi-peer loopback connections. Each --peer is paired by order with the corresponding --trusted-peer-key-hex; additional trusted keys may authorize inbound peers. Canonical v0.4 Argon2id is the default. --test-easy-pow is for isolated loopback tests only. No public bind or Mainnet activation."
}

fn parse_hex32(value: &str, name: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.is_ascii() {
        return Err(format!(
            "{name} must be exactly 64 ASCII hexadecimal characters"
        ));
    }
    let mut output = [0u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| format!("{name} contains a non-hexadecimal character"))?;
    }
    Ok(output)
}

fn parse_hex_bytes(value: &str, name: &str, expected_bytes: usize) -> Result<Vec<u8>, String> {
    if value.len() != expected_bytes.saturating_mul(2) || !value.is_ascii() {
        return Err(format!(
            "{name} must be exactly {} ASCII hexadecimal characters",
            expected_bytes * 2
        ));
    }
    let mut output = Vec::with_capacity(expected_bytes);
    for index in 0..expected_bytes {
        output.push(
            u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
                .map_err(|_| format!("{name} contains a non-hexadecimal character"))?,
        );
    }
    Ok(output)
}

fn ensure_loopback_address(address: SocketAddr, role: &str) -> Result<(), String> {
    if address.ip().is_loopback() {
        Ok(())
    } else {
        Err(format!(
            "QZBE runtime candidate refuses all non-loopback {role}"
        ))
    }
}
fn parse_args() -> Result<Option<Args>, String> {
    parse_args_from(env::args().skip(1).collect())
}

fn parse_args_from(tokens: Vec<String>) -> Result<Option<Args>, String> {
    if tokens
        .iter()
        .any(|value| value == "--help" || value == "-h")
    {
        return Ok(None);
    }
    let mut values = BTreeMap::<String, String>::new();
    let mut peer_values = Vec::<String>::new();
    let mut trusted_peer_values = Vec::<String>::new();
    let mut exit_after_mining = false;
    let mut probe_invalid_signature_first = false;
    let mut test_easy_pow = false;
    let mut i = 0usize;
    while i < tokens.len() {
        let key = tokens[i].as_str();
        if key == "--exit-after-mining" {
            if exit_after_mining {
                return Err("duplicate option: --exit-after-mining".into());
            }
            exit_after_mining = true;
            i += 1;
            continue;
        }
        if key == "--probe-invalid-signature-first" {
            if probe_invalid_signature_first {
                return Err("duplicate option: --probe-invalid-signature-first".into());
            }
            probe_invalid_signature_first = true;
            i += 1;
            continue;
        }
        if key == "--test-easy-pow" {
            if test_easy_pow {
                return Err("duplicate option: --test-easy-pow".into());
            }
            test_easy_pow = true;
            i += 1;
            continue;
        }
        if key == "--peer" || key == "--trusted-peer-key-hex" {
            let value = tokens
                .get(i + 1)
                .ok_or_else(|| format!("missing value for {key}"))?;
            if value.starts_with("--") {
                return Err(format!("missing value for {key}"));
            }
            if key == "--peer" {
                peer_values.push(value.clone());
            } else {
                trusted_peer_values.push(value.clone());
            }
            i += 2;
            continue;
        }
        if !matches!(
            key,
            "--network-id"
                | "--owner-id"
                | "--miner-id"
                | "--tx-public-key-hex"
                | "--observe-account-id"
                | "--tx-recipient-id"
                | "--tx-nonce"
                | "--tx-amount-atoms"
                | "--tx-fee-atoms"
                | "--tx-expires-at"
                | "--tx-signature-hex"
                | "--data-dir"
                | "--listen"
                | "--noise-static-private-key-dpapi-file"
                | "--initial-subsidy-atoms"
                | "--blocks-per-halving"
                | "--mine-blocks"
                | "--run-seconds"
                | "--stop-after-height"
        ) {
            return Err(format!("unknown option: {key}\n{}", usage()));
        }
        let value = tokens
            .get(i + 1)
            .ok_or_else(|| format!("missing value for {key}"))?;
        if value.starts_with("--") {
            return Err(format!("missing value for {key}"));
        }
        if values.insert(key.to_string(), value.clone()).is_some() {
            return Err(format!("duplicate option: {key}"));
        }
        i += 2;
    }
    let take = |key: &str| -> Result<String, String> {
        values
            .get(key)
            .cloned()
            .ok_or_else(|| format!("required option missing: {key}\n{}", usage()))
    };
    let data_dir = PathBuf::from(take("--data-dir")?);
    if !data_dir.is_absolute() {
        return Err("--data-dir must be an absolute path to a dedicated QZBE store".into());
    }
    let listen = take("--listen")?
        .parse::<SocketAddr>()
        .map_err(|_| "--listen is not a valid socket address".to_string())?;

    ensure_loopback_address(listen, "listen addresses")?;

    let peers = peer_values
        .iter()
        .map(|value| {
            value
                .parse::<SocketAddr>()
                .map_err(|_| "--peer contains an invalid socket address".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    for (index, address) in peers.iter().enumerate() {
        ensure_loopback_address(*address, "peers")?;
        if *address == listen {
            return Err("--peer cannot refer to this node's own listener".into());
        }
        if peers[..index].contains(address) {
            return Err("duplicate --peer address".into());
        }
    }
    if peers.len() > 16 {
        return Err("at most 16 statically pinned outbound --peer entries are allowed".into());
    }
    let network_id = parse_hex32(&take("--network-id")?, "--network-id")?;
    let owner_id = parse_hex32(&take("--owner-id")?, "--owner-id")?;
    let miner_id = parse_hex32(&take("--miner-id")?, "--miner-id")?;
    let tx_public_key = parse_hex32(&take("--tx-public-key-hex")?, "--tx-public-key-hex")?;
    let observe_account_id = parse_hex32(&take("--observe-account-id")?, "--observe-account-id")?;
    let trusted_peer_keys = trusted_peer_values
        .iter()
        .map(|value| parse_hex32(value, "--trusted-peer-key-hex"))
        .collect::<Result<Vec<_>, _>>()?;
    if trusted_peer_keys.is_empty() {
        return Err(
            "at least one --trusted-peer-key-hex is required for inbound Noise authentication"
                .into(),
        );
    }
    if trusted_peer_keys.len() > 32 {
        return Err("at most 32 --trusted-peer-key-hex entries are allowed".into());
    }
    if peers.len() > trusted_peer_keys.len() {
        return Err("each outbound --peer requires a corresponding --trusted-peer-key-hex in the same order".into());
    }
    for (index, key) in trusted_peer_keys.iter().enumerate() {
        if key.iter().all(|byte| *byte == 0) {
            return Err("--trusted-peer-key-hex values must be nonzero".into());
        }
        if trusted_peer_keys[..index].contains(key) {
            return Err("duplicate --trusted-peer-key-hex value".into());
        }
    }
    if network_id.iter().all(|byte| *byte == 0)
        || owner_id.iter().all(|byte| *byte == 0)
        || miner_id.iter().all(|byte| *byte == 0)
        || tx_public_key.iter().all(|byte| *byte == 0)
        || observe_account_id.iter().all(|byte| *byte == 0)
    {
        return Err(
            "network, owner, miner, transaction public key and observe account must be nonzero"
                .into(),
        );
    }
    if account_id_from_public_key(&tx_public_key) != owner_id {
        return Err("--owner-id must equal the domain-separated account ID derived from --tx-public-key-hex".into());
    }
    if owner_id == miner_id {
        return Err("owner and miner IDs must be distinct for this integration fixture".into());
    }
    let noise_key_path = PathBuf::from(take("--noise-static-private-key-dpapi-file")?);
    let initial_subsidy_atoms = take("--initial-subsidy-atoms")?
        .parse::<u128>()
        .map_err(|_| "--initial-subsidy-atoms must be an unsigned u128".to_string())?;
    let blocks_per_halving = take("--blocks-per-halving")?
        .parse::<u64>()
        .map_err(|_| "--blocks-per-halving must be an unsigned u64".to_string())?;
    let tx_fields = [
        "--tx-recipient-id",
        "--tx-nonce",
        "--tx-amount-atoms",
        "--tx-fee-atoms",
        "--tx-expires-at",
        "--tx-signature-hex",
    ];
    let tx_field_count = tx_fields
        .iter()
        .filter(|key| values.contains_key(**key))
        .count();
    let transaction = match tx_field_count {
        0 => None,
        count if count == tx_fields.len() => {
            let recipient = parse_hex32(&values["--tx-recipient-id"], "--tx-recipient-id")?;
            let nonce = values["--tx-nonce"].parse::<u64>().map_err(|_| "--tx-nonce must be u64".to_string())?;
            let amount = values["--tx-amount-atoms"].parse::<u64>().map_err(|_| "--tx-amount-atoms must be u64".to_string())?;
            let fee = values["--tx-fee-atoms"].parse::<u64>().map_err(|_| "--tx-fee-atoms must be u64".to_string())?;
            let expires_at = values["--tx-expires-at"].parse::<u64>().map_err(|_| "--tx-expires-at must be u64".to_string())?;
            let signature = parse_hex_bytes(&values["--tx-signature-hex"], "--tx-signature-hex", 64)?;
            if recipient.iter().all(|byte| *byte == 0) || recipient == owner_id {
                return Err("transaction recipient must be nonzero and distinct from the owner account".into());
            }
            if nonce == 0 || amount == 0 || expires_at <= 2 {
                return Err("transaction nonce/amount must be positive and expiry must exceed the local block timestamps".into());
            }
            if observe_account_id != recipient {
                return Err("--observe-account-id must equal --tx-recipient-id for this loopback fixture".into());
            }
            Some(Transaction { network_id, sender: owner_id, recipient, nonce, amount, fee, expires_at, signature })
        }
        _ => return Err("transaction requires all six fields: recipient, nonce, amount, fee, expiry and signature".into()),
    };
    let mine_blocks = values
        .get("--mine-blocks")
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|_| "--mine-blocks must be an unsigned u64".to_string())
        })
        .transpose()?
        .unwrap_or(0);
    let run_seconds = values
        .get("--run-seconds")
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|_| "--run-seconds must be an unsigned u64".to_string())
        })
        .transpose()?
        .unwrap_or(DEFAULT_RUN_SECONDS);
    let stop_after_height = values
        .get("--stop-after-height")
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|_| "--stop-after-height must be an unsigned u64".to_string())
        })
        .transpose()?;
    if initial_subsidy_atoms == 0 || blocks_per_halving == 0 {
        return Err("issuance schedule values must be explicit and greater than zero".into());
    }
    if mine_blocks > MAX_MINE_BLOCKS {
        return Err(format!(
            "--mine-blocks exceeds local candidate cap {MAX_MINE_BLOCKS}"
        ));
    }
    if !(1..=3600).contains(&run_seconds) {
        return Err("--run-seconds must be between 1 and 3600".into());
    }
    if stop_after_height == Some(0) {
        return Err("--stop-after-height must be greater than zero".into());
    }
    if mine_blocks > 0 && peers.is_empty() {
        return Err(
            "mining requires at least one --peer so each candidate is peer-acknowledged".into(),
        );
    }
    if probe_invalid_signature_first
        && (transaction.is_none() || mine_blocks == 0 || peers.is_empty())
    {
        return Err("--probe-invalid-signature-first requires a signed --transaction, --peer and --mine-blocks > 0".into());
    }
    if transaction.is_some() && mine_blocks == 0 && exit_after_mining {
        return Err("--exit-after-mining cannot be used without mining a block".into());
    }
    if exit_after_mining && mine_blocks == 0 {
        return Err("--exit-after-mining requires --mine-blocks greater than zero".into());
    }
    if exit_after_mining && stop_after_height.is_some() {
        return Err("--exit-after-mining and --stop-after-height are mutually exclusive".into());
    }
    Ok(Some(Args {
        data_dir,
        listen,
        peers,
        network_id,
        owner_id,
        miner_id,
        tx_public_key,
        observe_account_id,
        transaction,
        probe_invalid_signature_first,
        trusted_peer_keys,
        noise_key_path,
        initial_subsidy_atoms,
        blocks_per_halving,
        mine_blocks,
        run_seconds,
        stop_after_height,
        exit_after_mining,
        test_easy_pow,
    }))
}

fn configured_authenticator(args: &Args) -> Result<Ed25519TransactionAuthenticator, String> {
    if account_id_from_public_key(&args.tx_public_key) != args.owner_id {
        return Err(
            "configured transaction public key does not match Genesis owner account".into(),
        );
    }
    Ed25519TransactionAuthenticator::select_by_id(
        TransactionAuthenticatorKind::Ed25519V1 as u16,
        [AccountPublicKey {
            account_id: args.owner_id,
            public_key: args.tx_public_key,
        }],
    )
    .map_err(|error| format!("configure explicit Ed25519 transaction registry: {error:?}"))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

fn next_block_timestamp(previous_timestamp: u64, now: SystemTime) -> Result<u64, String> {
    let wall_clock = now
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock predates UNIX epoch: {error}"))?
        .as_secs();
    let minimum_next = previous_timestamp
        .checked_add(1)
        .ok_or_else(|| "QZBE timestamp overflow".to_string())?;
    Ok(wall_clock.max(minimum_next))
}

fn consensus_parameters_fingerprint(params: &ConsensusParameters) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(256);
    preimage.extend_from_slice(QZBE_RUNTIME_PARAMS_DOMAIN);
    preimage.extend_from_slice(&params.protocol_version.to_be_bytes());
    preimage.extend_from_slice(&params.target_block_time_secs.to_be_bytes());
    preimage.extend_from_slice(&params.difficulty_window_blocks.to_be_bytes());
    preimage.extend_from_slice(&params.difficulty_min_ratio_divisor.to_be_bytes());
    preimage.extend_from_slice(&params.difficulty_max_ratio.to_be_bytes());
    preimage.extend_from_slice(&params.pow_limit.to_be_bytes());
    preimage.extend_from_slice(&params.initial_target.to_be_bytes());
    preimage.push(match params.pow.algorithm {
        ai_native_l1_pow_bench::consensus::PowAlgorithm::Argon2id => 1,
    });
    preimage.extend_from_slice(&params.pow.memory_kib.to_be_bytes());
    preimage.extend_from_slice(&params.pow.iterations.to_be_bytes());
    preimage.extend_from_slice(&params.pow.lanes.to_be_bytes());
    preimage.push(params.pow.output_bytes);
    preimage.extend_from_slice(&params.issuance.maximum_supply().to_be_bytes());
    preimage.extend_from_slice(&params.issuance.initial_subsidy().to_be_bytes());
    preimage.extend_from_slice(&params.issuance.blocks_per_halving().to_be_bytes());
    Sha256::digest(&preimage).into()
}

fn qzbe_runtime_profile_marker(
    network_id: &[u8; 32],
    genesis_id: &[u8; 32],
    profile_id: &[u8; 32],
    params: &ConsensusParameters,
) -> Vec<u8> {
    let params_id = consensus_parameters_fingerprint(params);
    let mut marker = Vec::with_capacity(QZBE_RUNTIME_PROFILE_MARKER_BYTES);
    marker.extend_from_slice(QZBE_RUNTIME_PROFILE_MAGIC);
    marker.extend_from_slice(&QZBE_RUNTIME_PROFILE_VERSION.to_be_bytes());
    marker.extend_from_slice(network_id);
    marker.extend_from_slice(genesis_id);
    marker.extend_from_slice(profile_id);
    marker.extend_from_slice(&params_id);
    debug_assert_eq!(marker.len(), QZBE_RUNTIME_PROFILE_PREFIX_BYTES);
    let mut hash = Sha256::new();
    hash.update(QZBE_RUNTIME_PROFILE_CHECKSUM_DOMAIN);
    hash.update(&marker);
    marker.extend_from_slice(&hash.finalize());
    debug_assert_eq!(marker.len(), QZBE_RUNTIME_PROFILE_MARKER_BYTES);
    marker
}

fn read_exact_profile_marker(path: &Path, expected: &[u8]) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect QZBE profile lock {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("QZBE profile lock must be a regular non-symlink file".into());
    }
    if metadata.len() != expected.len() as u64 {
        return Err(format!(
            "QZBE profile lock has noncanonical length {}; expected {}; refusing profile reset/downgrade",
            metadata.len(), expected.len()
        ));
    }
    // Bound the read even if a concurrent writer replaces/grows the file after metadata check.
    let mut file = fs::File::open(path)
        .map_err(|error| format!("open QZBE profile lock {}: {error}", path.display()))?;
    let mut bytes = Vec::with_capacity(expected.len());
    Read::by_ref(&mut file)
        .take(expected.len() as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read QZBE profile lock {}: {error}", path.display()))?;
    if bytes.as_slice() != expected {
        return Err("QZBE profile lock checksum or chain/profile/consensus binding mismatch; refusing profile reset/downgrade".into());
    }
    Ok(())
}

fn sync_profile_directory(path: &Path) -> Result<(), String> {
    // Unix supports fsync on an open directory using the standard library. On Windows the file
    // itself is flushed with sync_all above; std does not expose a portable directory fsync.
    #[cfg(unix)]
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("sync QZBE profile directory {}: {error}", path.display()))?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn require_dedicated_store_directory(
    path: &Path,
    network_id: &[u8; 32],
    genesis_id: &[u8; 32],
    profile_id: &[u8; 32],
    params: &ConsensusParameters,
) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|error| format!("create QZBE store directory: {error}"))?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect QZBE store directory: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("QZBE data directory must be a real directory, not a symlink or file".into());
    }
    let marker_path = path.join(QZBE_RUNTIME_PROFILE_FILE);
    let expected_marker = qzbe_runtime_profile_marker(network_id, genesis_id, profile_id, params);
    let mut marker_present = false;
    let mut store_artifacts_present = false;
    for entry in
        fs::read_dir(path).map_err(|error| format!("list QZBE store directory: {error}"))?
    {
        let entry = entry.map_err(|error| format!("read QZBE store entry: {error}"))?;
        let name = entry.file_name().to_string_lossy().to_string();
        let kind = entry
            .file_type()
            .map_err(|error| format!("inspect QZBE store entry {name}: {error}"))?;
        match name.as_str() {
            "branches" | "manifests" | "checkpoints" => {
                if kind.is_symlink() || !kind.is_dir() {
                    return Err(format!("QZBE path {name} must be a real directory"));
                }
                store_artifacts_present = true;
            }
            "qzbe-store.lock" | "qzbe-checkpoint-store.lock" => {
                if kind.is_symlink() || !kind.is_file() {
                    return Err("QZBE store lock must be a regular non-symlink file".into());
                }
                store_artifacts_present = true;
            }
            QZBE_RUNTIME_PROFILE_FILE => {
                marker_present = true;
                if kind.is_symlink() || !kind.is_file() {
                    return Err("QZBE profile lock must be a regular non-symlink file".into());
                }
            }
            ".qzbe-manifest.pending-cas" | ".qzbe-external-cas-required" => {
                if kind.is_symlink() || !kind.is_file() {
                    return Err(format!("QZBE marker {name} must be a regular file"));
                }
                return Err(format!("QZBE runtime candidate refuses external-CAS/pending state ({name}); use a separate disposable store"));
            }
            _ => return Err(format!("refusing non-QZBE data in dedicated store: {name}")),
        }
    }

    if marker_present {
        // Existing QZBE stores must never be adopted under changed Genesis/schedule/PoW/profile.
        return read_exact_profile_marker(&marker_path, &expected_marker);
    }
    if store_artifacts_present {
        // Older or partially restored QZBE stores without the profile lock are ambiguous. Do not
        // infer their intended profile from their current blocks and never silently bless them.
        return Err("existing QZBE store artifacts have no immutable qzbe-runtime.profile lock; refusing implicit adoption, restore, or profile downgrade; preserve this directory and provision a separate fresh store".into());
    }

    // Fresh directories are locked exactly once. A crash that leaves a truncated marker makes the
    // next startup fail closed; no automatic delete/rewrite path exists. Concurrent first boots
    // must either create this exact lock or validate the winner's identical bytes.
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker_path)
    {
        Ok(mut file) => {
            file.write_all(&expected_marker).map_err(|error| {
                format!("write QZBE profile lock {}: {error}", marker_path.display())
            })?;
            file.sync_all().map_err(|error| {
                format!("flush QZBE profile lock {}: {error}", marker_path.display())
            })?;
            sync_profile_directory(path)?;
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            read_exact_profile_marker(&marker_path, &expected_marker)
        }
        Err(error) => Err(format!(
            "create QZBE profile lock {}: {error}",
            marker_path.display()
        )),
    }
}

fn prepare_profile(
    args: &Args,
) -> Result<
    (
        GenesisManifestV04,
        V04ConsensusProfileCandidate,
        MonetaryLedgerStateV04TransitionCandidate,
        ConsensusParameters,
    ),
    String,
> {
    let manifest = GenesisManifestV04::new(args.network_id, args.owner_id)
        .map_err(|error| format!("construct explicit QZBE Genesis manifest: {error:?}"))?;
    let schedule = V04MiningIssuanceScheduleCandidate::new(
        args.initial_subsidy_atoms,
        args.blocks_per_halving,
    )
    .map_err(|error| format!("validate explicit v0.4 issuance schedule: {error:?}"))?;
    schedule
        .validate_canonical_v04_launch_parameters()
        .map_err(|error| {
            format!("QZBE node launch schedule differs from canonical v0.4 tokenomics: {error:?}")
        })?;
    let profile = V04ConsensusProfileCandidate::from_manifest_and_schedule(&manifest, schedule)
        .map_err(|error| format!("construct QZBE profile: {error:?}"))?;
    let genesis =
        MonetaryLedgerStateV04TransitionCandidate::from_genesis_manifest(&manifest, &profile)
            .map_err(|error| format!("construct QZBE Genesis state: {error:?}"))?;
    let mut params = ConsensusParameters::candidate_testnet()
        .map_err(|error| format!("construct canonical v0.4 candidate PoW params: {error}"))?;
    // Canonical v0.4 Argon2id/difficulty parameters remain the default. The 8 MiB/easy-target
    // profile may only be chosen explicitly for isolated loopback tests.
    if args.test_easy_pow {
        params.initial_target = Uint256::from_be_bytes([0xEF; 32]);
        params.pow_limit = Uint256::MAX;
        params.pow.memory_kib = 8 * 1024;
    }
    params
        .validate()
        .map_err(|error| format!("candidate PoW params rejected: {error}"))?;
    if MAX_ENCODED_V04_EXECUTION_POW_ENVELOPE_BYTES > MAX_NOISE_APPLICATION_RECORD_BYTES {
        return Err(format!(
            "QZBE max envelope {} exceeds Noise record cap {}; refusing to start",
            MAX_ENCODED_V04_EXECUTION_POW_ENVELOPE_BYTES, MAX_NOISE_APPLICATION_RECORD_BYTES
        ));
    }
    Ok((manifest, profile, genesis, params))
}

fn snapshot(store: &V04ExecutionCheckpointForkStoreCandidate) -> Result<Snapshot, String> {
    Ok(Snapshot {
        height: store.canonical_height(),
        tip: store.canonical_tip(),
        state_root: store
            .canonical_state_root()
            .map_err(|error| format!("read canonical QZBE state root: {error}"))?,
        generation: store.generation(),
    })
}

fn encode_ack(
    network_id: &[u8; 32],
    profile: &[u8; 32],
    status: u8,
    digest: [u8; 32],
    current: &Snapshot,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(ACK_BYTES);
    bytes.extend_from_slice(ACK_MAGIC);
    bytes.extend_from_slice(&ACK_VERSION.to_be_bytes());
    bytes.extend_from_slice(network_id);
    bytes.extend_from_slice(profile);
    bytes.push(status);
    bytes.extend_from_slice(&digest);
    bytes.extend_from_slice(&current.height.to_be_bytes());
    bytes.extend_from_slice(&current.tip);
    bytes.extend_from_slice(&current.state_root);
    bytes.extend_from_slice(&current.generation.to_be_bytes());
    debug_assert_eq!(bytes.len(), ACK_BYTES);
    bytes
}

fn decode_ack(bytes: &[u8], network_id: &[u8; 32], profile: &[u8; 32]) -> Result<PeerAck, String> {
    if bytes.len() != ACK_BYTES || &bytes[..4] != ACK_MAGIC {
        return Err("peer ACK magic or length mismatch".into());
    }
    if u16::from_be_bytes([bytes[4], bytes[5]]) != ACK_VERSION {
        return Err("unsupported QZBE peer ACK version".into());
    }
    if &bytes[6..38] != network_id || &bytes[38..70] != profile {
        return Err("peer ACK network/profile mismatch".into());
    }
    let status = bytes[70];
    if status > 2 {
        return Err("peer ACK contains an unknown status".into());
    }
    let candidate_digest = bytes[71..103]
        .try_into()
        .map_err(|_| "peer ACK digest width mismatch")?;
    let height = u64::from_be_bytes(
        bytes[103..111]
            .try_into()
            .map_err(|_| "peer ACK height width mismatch")?,
    );
    let tip = bytes[111..143]
        .try_into()
        .map_err(|_| "peer ACK tip width mismatch")?;
    let state_root = bytes[143..175]
        .try_into()
        .map_err(|_| "peer ACK state-root width mismatch")?;
    let generation = u64::from_be_bytes(
        bytes[175..183]
            .try_into()
            .map_err(|_| "peer ACK generation width mismatch")?,
    );
    Ok(PeerAck {
        status,
        candidate_digest,
        snapshot: Snapshot {
            height,
            tip,
            state_root,
            generation,
        },
    })
}

fn send_candidate(
    address: SocketAddr,
    local_key: &[u8; 32],
    peer_key: &[u8; 32],
    network_id: &[u8; 32],
    profile: &[u8; 32],
    bytes: &[u8],
    expected_digest: [u8; 32],
    expected: &Snapshot,
) -> Result<(), String> {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(5))
        .map_err(|error| format!("connect to pinned QZBE peer {address}: {error}"))?;
    stream
        .set_nodelay(true)
        .map_err(|error| format!("configure peer TCP_NODELAY: {error}"))?;
    let mut session = DevnetNoiseSession::connect(&mut stream, local_key, peer_key, network_id)
        .map_err(|error| format!("authenticate outbound Noise session: {error}"))?;
    session
        .write_record(&mut stream, bytes)
        .map_err(|error| format!("send encrypted QZBE candidate: {error}"))?;
    let response = session
        .read_record(&mut stream)
        .map_err(|error| format!("read encrypted QZBE ACK: {error}"))?;
    let ack = decode_ack(&response, network_id, profile)?;
    if ack.status == 2 {
        return Err("pinned peer rejected the QZBE candidate".into());
    }
    if ack.candidate_digest != expected_digest {
        return Err("peer ACK candidate digest does not match submitted QZBE block".into());
    }
    if &ack.snapshot != expected {
        return Err(format!(
            "peer did not converge: local height/tip/root/generation={}/{}/{}/{} peer={}/{}/{}/{}",
            expected.height,
            hex(&expected.tip),
            hex(&expected.state_root),
            expected.generation,
            ack.snapshot.height,
            hex(&ack.snapshot.tip),
            hex(&ack.snapshot.state_root),
            ack.snapshot.generation
        ));
    }
    Ok(())
}

fn tamper_first_signature_and_remine(
    valid_envelope: &[u8],
    profile: &V04ConsensusProfileCandidate,
    params: &ConsensusParameters,
) -> Result<Vec<u8>, String> {
    let mut envelope = V04ExecutionPowEnvelope::decode(valid_envelope, profile, params)
        .map_err(|error| format!("decode valid QZBE probe source: {error}"))?;
    let tx = envelope
        .block
        .transactions
        .first_mut()
        .ok_or_else(|| "invalid-signature probe requires a transaction".to_string())?;
    let first = tx
        .signature
        .first_mut()
        .ok_or_else(|| "invalid-signature probe cannot tamper an empty signature".to_string())?;
    *first ^= 1;
    for attempt in 0..MAX_QZBE_MINING_ATTEMPTS {
        let digest = qzbe_pow_digest(&envelope.header, &envelope.block, params)
            .map_err(|error| format!("hash tampered QZBE probe: {error}"))?;
        if Uint256::from_be_bytes(digest) <= envelope.header.target {
            return envelope
                .encode(profile, params)
                .map_err(|error| format!("encode tampered QZBE probe: {error}"));
        }
        if attempt + 1 < MAX_QZBE_MINING_ATTEMPTS {
            envelope.header.nonce = envelope
                .header
                .nonce
                .checked_add(1)
                .ok_or_else(|| "invalid-signature probe nonce overflow".to_string())?;
        }
    }
    Err("bounded PoW nonce search exhausted for invalid-signature probe".into())
}

fn send_rejection_probe(
    address: SocketAddr,
    local_key: &[u8; 32],
    peer_key: &[u8; 32],
    network_id: &[u8; 32],
    profile: &[u8; 32],
    bytes: &[u8],
    expected_unchanged: &Snapshot,
) -> Result<(), String> {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(5))
        .map_err(|error| format!("connect to pinned QZBE probe peer {address}: {error}"))?;
    stream
        .set_nodelay(true)
        .map_err(|error| format!("configure probe TCP_NODELAY: {error}"))?;
    let mut session = DevnetNoiseSession::connect(&mut stream, local_key, peer_key, network_id)
        .map_err(|error| format!("authenticate invalid-signature probe session: {error}"))?;
    session
        .write_record(&mut stream, bytes)
        .map_err(|error| format!("send encrypted invalid-signature probe: {error}"))?;
    let response = session
        .read_record(&mut stream)
        .map_err(|error| format!("read invalid-signature probe ACK: {error}"))?;
    let ack = decode_ack(&response, network_id, profile)?;
    if ack.status != 2 {
        return Err(format!(
            "peer did not reject invalid transaction signature (ACK status {})",
            ack.status
        ));
    }
    if ack.candidate_digest != [0; 32] {
        return Err("rejection ACK must not report an accepted candidate digest".into());
    }
    if &ack.snapshot != expected_unchanged {
        return Err(format!("invalid-signature candidate changed receiver state: expected height={} tip={} root={} generation={}, got height={} tip={} root={} generation={}",
            expected_unchanged.height, hex(&expected_unchanged.tip), hex(&expected_unchanged.state_root), expected_unchanged.generation,
            ack.snapshot.height, hex(&ack.snapshot.tip), hex(&ack.snapshot.state_root), ack.snapshot.generation));
    }
    eprintln!("event=qzbe_v04_invalid_signature_probe_rejected height={} tip={} state_root={} generation={} rejected_atomically=true",
        ack.snapshot.height, hex(&ack.snapshot.tip), hex(&ack.snapshot.state_root), ack.snapshot.generation);
    Ok(())
}

fn observed_balance(store: &V04ExecutionCheckpointForkStoreCandidate, account: &AccountId) -> u64 {
    store
        .fork_choice()
        .canonical_state()
        .ledger()
        .account(account)
        .map(|state| state.balance)
        .unwrap_or(0)
}

fn serve_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    local_key: &SecretKey,
    trusted_peer_keys: &[[u8; 32]],
    network_id: &[u8; 32],
    profile: &[u8; 32],
    store: &mut V04ExecutionCheckpointForkStoreCandidate,
    checkpoint_context: &QzbeCheckpointValidationContext<'_>,
    authenticator: &Ed25519TransactionAuthenticator,
    accepted_count: &mut u64,
) -> Result<(), String> {
    stream
        .set_nodelay(true)
        .map_err(|error| format!("set inbound TCP_NODELAY: {error}"))?;
    let mut session =
        DevnetNoiseSession::accept(&mut stream, &local_key.0, trusted_peer_keys, network_id)
            .map_err(|error| format!("authenticate inbound peer {peer_addr}: {error}"))?;
    if !trusted_peer_keys.contains(session.remote_static_public_key()) {
        return Err(
            "authenticated peer static key is not present in the configured trust set".into(),
        );
    }
    let candidate = session
        .read_record(&mut stream)
        .map_err(|error| format!("read encrypted QZBE candidate: {error}"))?;
    let (status, digest) = match store.submit(&candidate, checkpoint_context, authenticator) {
        Ok(outcome) => (0u8, outcome.block_digest),
        Err(error) => {
            eprintln!(
                "event=qzbe_v04_peer_candidate_rejected peer={} reason={}",
                peer_addr, error
            );
            (2u8, [0u8; 32])
        }
    };
    let current = snapshot(store)?;
    let ack = encode_ack(network_id, profile, status, digest, &current);
    session
        .write_record(&mut stream, &ack)
        .map_err(|error| format!("send encrypted QZBE ACK: {error}"))?;
    if status == 0 {
        *accepted_count = accepted_count.saturating_add(1);
        eprintln!("event=qzbe_v04_peer_block_accepted peer={} height={} digest={} tip={} state_root={} generation={} accepted_count={}",
            peer_addr, current.height, hex(&digest), hex(&current.tip), hex(&current.state_root), current.generation, accepted_count);
    }
    Ok(())
}

fn poll_connections(
    listener: &TcpListener,
    local_key: &SecretKey,
    trusted_peer_keys: &[[u8; 32]],
    network_id: &[u8; 32],
    profile: &[u8; 32],
    store: &mut V04ExecutionCheckpointForkStoreCandidate,
    checkpoint_context: &QzbeCheckpointValidationContext<'_>,
    authenticator: &Ed25519TransactionAuthenticator,
    accepted_count: &mut u64,
    message_count: &mut u64,
) -> Result<(), String> {
    loop {
        match listener.accept() {
            Ok((stream, peer_addr)) => {
                *message_count = message_count.saturating_add(1);
                if *message_count > MAX_PEER_MESSAGES {
                    return Err("QZBE loopback peer-message budget exhausted".into());
                }
                if let Err(error) = serve_connection(
                    stream,
                    peer_addr,
                    local_key,
                    trusted_peer_keys,
                    network_id,
                    profile,
                    store,
                    checkpoint_context,
                    authenticator,
                    accepted_count,
                ) {
                    eprintln!(
                        "event=qzbe_v04_peer_connection_rejected peer={} reason={}",
                        peer_addr, error
                    );
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) => return Err(format!("accept loopback QZBE peer connection: {error}")),
        }
    }
}
fn run(args: Args) -> Result<(), String> {
    let authenticator = configured_authenticator(&args)?;
    let (manifest, profile, genesis, params) = prepare_profile(&args)?;
    let checkpoint_context = QzbeCheckpointValidationContext {
        manifest: &manifest,
        profile: &profile,
        params: &params,
    };
    let genesis_target_history = TargetHistory::new(params.clone())
        .map_err(|error| format!("construct QZBE Genesis target history: {error}"))?
        .checkpoint_snapshot()
        .map_err(|error| format!("snapshot QZBE Genesis target history: {error}"))?;
    let genesis_checkpoint = QzbeCheckpointRecord::from_state(
        &checkpoint_context,
        &genesis,
        genesis.ledger().tip_hash(),
        Uint256::ZERO,
        [0; 32],
        genesis_target_history,
    )
    .map_err(|error| format!("construct canonical QZBE Genesis checkpoint: {error}"))?;
    let profile_id = *profile.profile_fingerprint();
    let genesis_id = manifest
        .manifest_hash()
        .map_err(|error| format!("hash QZBE Genesis manifest: {error:?}"))?;
    require_dedicated_store_directory(
        &args.data_dir,
        &args.network_id,
        &genesis_id,
        &profile_id,
        &params,
    )?;
    let mut raw_key = load_protected_noise_private_key(&args.noise_key_path, &args.network_id)
        .map_err(|error| format!("load protected QZBE Noise private key: {error}"))?;
    let secret = SecretKey(raw_key);
    raw_key.fill(0);
    let mut store = V04ExecutionCheckpointForkStoreCandidate::open_from_trusted_checkpoint(
        &args.data_dir,
        genesis_checkpoint.clone(),
        &checkpoint_context,
        params.clone(),
        &authenticator,
    )
    .map_err(|error| format!("open checkpoint-rooted local QZBE store: {error}"))?;
    let initial = snapshot(&store)?;
    let listener = TcpListener::bind(args.listen)
        .map_err(|error| format!("bind loopback QZBE listener {}: {error}", args.listen))?;
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("set QZBE listener nonblocking: {error}"))?;
    let mut accepted_count = 0u64;
    let mut message_count = 0u64;
    let mut sent_count = 0u64;
    let pow_profile = if args.test_easy_pow {
        "EXPLICIT_LOCAL_TEST_EASY_POW_8MIB"
    } else {
        "QZXB_V04_ARGON2ID_64MIB"
    };
    eprintln!("event=qzbe_v04_peer_smoke_ready network_id={} genesis={} profile={} listen={} peer={} height={} root={} tip={} store=QZBE ack=QZA4 noise=Noise_XX_25519_ChaChaPoly_SHA256 pow_profile={} tx_policy=Ed25519V1_single_explicit_key local_only=true public_launch_approved=false",
        hex(&args.network_id), hex(&genesis_id), hex(&profile_id), args.listen,
        if args.peers.is_empty() {
            "inbound_only".to_string()
        } else {
            args.peers.iter().map(ToString::to_string).collect::<Vec<_>>().join(",")
        },
        initial.height, hex(&initial.state_root), hex(&initial.tip), pow_profile);

    if args.probe_invalid_signature_first {
        let peer = *args
            .peers
            .first()
            .ok_or("invalid-signature probe requires a pinned outbound peer")?;
        let peer_key = args.trusted_peer_keys[0];
        let candidate = store
            .fork_choice()
            .mine_candidate_on(
                store.canonical_tip(),
                store
                    .canonical_height()
                    .checked_add(1)
                    .ok_or_else(|| "QZBE probe height overflow".to_string())?,
                args.miner_id,
                vec![args
                    .transaction
                    .clone()
                    .ok_or("invalid-signature probe missing transaction")?],
                store.canonical_height().saturating_add(1),
                MAX_QZBE_MINING_ATTEMPTS,
                &authenticator,
                || false,
            )
            .map_err(|error| {
                format!("build valid source transaction block for signature-tamper probe: {error}")
            })?;
        let tampered = tamper_first_signature_and_remine(&candidate, &profile, &params)?;
        send_rejection_probe(
            peer,
            &secret.0,
            &peer_key,
            &args.network_id,
            &profile_id,
            &tampered,
            &initial,
        )?;
    }

    for block_index in 0..args.mine_blocks {
        poll_connections(
            &listener,
            &secret,
            &args.trusted_peer_keys,
            &args.network_id,
            &profile_id,
            &mut store,
            &checkpoint_context,
            &authenticator,
            &mut accepted_count,
            &mut message_count,
        )?;
        let parent_tip = store.canonical_tip();
        let next_height = store
            .canonical_height()
            .checked_add(1)
            .ok_or_else(|| "QZBE height overflow".to_string())?;
        let previous_timestamp = store
            .fork_choice()
            .canonical_timestamp()
            .map_err(|error| format!("read canonical QZBE timestamp: {error}"))?;
        let timestamp = next_block_timestamp(previous_timestamp, SystemTime::now())?;
        let encoded = store
            .fork_choice()
            .mine_candidate_on(
                parent_tip,
                timestamp,
                args.miner_id,
                if block_index == 0 {
                    args.transaction.clone().into_iter().collect()
                } else {
                    Vec::new()
                },
                next_height,
                MAX_QZBE_MINING_ATTEMPTS,
                &authenticator,
                || false,
            )
            .map_err(|error| format!("mine bounded QZBE block at height {next_height}: {error}"))?;
        let outcome: V04ExecutionForkChoiceOutcome = store
            .submit(&encoded, &checkpoint_context, &authenticator)
            .map_err(|error| format!("submit locally mined QZBE block: {error}"))?;
        if !outcome.canonical_changed || outcome.canonical_height != next_height {
            return Err(format!(
                "QZBE local fork choice did not advance to height {next_height} from {}",
                hex(&parent_tip)
            ));
        }
        let current = snapshot(&store)?;
        for (index, peer) in args.peers.iter().enumerate() {
            send_candidate(
                *peer,
                &secret.0,
                &args.trusted_peer_keys[index],
                &args.network_id,
                &profile_id,
                &encoded,
                outcome.block_digest,
                &current,
            )?;
            sent_count = sent_count.saturating_add(1);
            eprintln!("event=qzbe_v04_peer_broadcast_ack height={} digest={} root={} tip={} generation={} peer={} status=accepted_or_duplicate sent_count={}",
                current.height, hex(&outcome.block_digest), hex(&current.state_root), hex(&current.tip), current.generation, peer, sent_count);
        }
    }

    if !args.exit_after_mining {
        let deadline = Instant::now() + Duration::from_secs(args.run_seconds);
        loop {
            poll_connections(
                &listener,
                &secret,
                &args.trusted_peer_keys,
                &args.network_id,
                &profile_id,
                &mut store,
                &checkpoint_context,
                &authenticator,
                &mut accepted_count,
                &mut message_count,
            )?;
            if args
                .stop_after_height
                .is_some_and(|height| store.canonical_height() >= height)
            {
                break;
            }
            if Instant::now() >= deadline {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    let expected_final = snapshot(&store)?;
    drop(store);
    drop(secret);
    // A new store instance verifies persistent manifest replay and catches any in-memory-only state.
    let replayed = V04ExecutionCheckpointForkStoreCandidate::open_from_trusted_checkpoint(
        &args.data_dir,
        genesis_checkpoint,
        &checkpoint_context,
        params.clone(),
        &authenticator,
    )
    .map_err(|error| format!("reopen/replay checkpoint-rooted QZBE store: {error}"))?;
    let final_snapshot = snapshot(&replayed)?;
    if final_snapshot != expected_final {
        return Err(format!(
            "QZBE restart/replay mismatch: before={:?} after={:?}",
            expected_final, final_snapshot
        ));
    }
    let recipient_balance = observed_balance(&replayed, &args.observe_account_id);
    let total_mined_atoms = replayed.fork_choice().canonical_state().total_mined_atoms();
    eprintln!("event=qzbe_v04_peer_smoke_stopped network_id={} profile={} height={} state_root={} tip={} generation={} total_mined_atoms={} observed_account={} observed_balance_atoms={} accepted_peer_blocks={} sent_peer_blocks={} replay=matched local_only=true public_launch_approved=false",
        hex(&args.network_id), hex(&profile_id), final_snapshot.height, hex(&final_snapshot.state_root),
        hex(&final_snapshot.tip), final_snapshot.generation, total_mined_atoms, hex(&args.observe_account_id), recipient_balance, accepted_count, sent_count);
    if final_snapshot.height < initial.height || final_snapshot.tip.iter().all(|byte| *byte == 0) {
        return Err("QZBE replay returned an invalid canonical snapshot".into());
    }
    if args
        .stop_after_height
        .is_some_and(|height| final_snapshot.height < height)
    {
        return Err(format!(
            "QZBE node did not reach requested stop height {}; final height {}",
            args.stop_after_height.unwrap_or_default(),
            final_snapshot.height
        ));
    }
    Ok(())
}
/// Run only after `devnet_node` has explicitly consumed `--qzbe-v04-peer-smoke`.
/// The token list excludes that dispatch token and is parsed with the same strict parser as the
/// standalone diagnostic binary. This does not select QZBE for the default PTB2/PFS2 runtime.
pub fn run_from_devnet_dispatch(tokens: Vec<String>) -> Result<(), String> {
    match parse_args_from(tokens)? {
        None => {
            println!("{}", usage());
            Ok(())
        }
        Some(args) => run(args),
    }
}

fn main() {
    match parse_args() {
        Ok(None) => println!("{}", usage()),
        Ok(Some(args)) => {
            if let Err(error) = run(args) {
                eprintln!("event=qzbe_v04_peer_smoke_failed reason={error} local_only=true public_launch_approved=false");
                process::exit(1);
            }
        }
        Err(error) => {
            eprintln!("{error}");
            process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_profile_root() -> PathBuf {
        let tick = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time after epoch")
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "ain1_qzbe_profile_lock_{}_{}",
            std::process::id(),
            tick
        ));
        fs::create_dir_all(&path).expect("create temporary QZBE profile test root");
        path
    }

    fn test_candidate_params() -> ConsensusParameters {
        let mut params = ConsensusParameters::candidate_testnet().expect("candidate params");
        params.initial_target = Uint256::from_be_bytes([0xEF; 32]);
        params.pow_limit = Uint256::MAX;
        params.pow.memory_kib = 8 * 1024;
        params.validate().expect("valid candidate test params");
        params
    }

    fn test_args(initial_subsidy_atoms: u128, blocks_per_halving: u64) -> Args {
        Args {
            data_dir: temp_profile_root(),
            listen: "127.0.0.1:49331".parse().unwrap(),
            peers: Vec::new(),
            network_id: [0x31; 32],
            owner_id: [0xA7; 32],
            miner_id: [0xC4; 32],
            tx_public_key: [0xD1; 32],
            observe_account_id: [0xB2; 32],
            transaction: None,
            probe_invalid_signature_first: false,
            trusted_peer_keys: vec![[0xE6; 32]],
            noise_key_path: env::temp_dir().join("unused-qzbe-test-noise-key"),
            initial_subsidy_atoms,
            blocks_per_halving,
            mine_blocks: 0,
            run_seconds: 1,
            stop_after_height: None,
            exit_after_mining: true,
            test_easy_pow: false,
        }
    }

    fn parser_fixture_tokens(peers: &[(&str, &str)]) -> Vec<String> {
        let network = [0x31; 32];
        let tx_public_key = [0xD1; 32];
        let owner = account_id_from_public_key(&tx_public_key);
        let mut tokens = vec![
            "--network-id".into(),
            hex(&network),
            "--owner-id".into(),
            hex(&owner),
            "--miner-id".into(),
            "c4".repeat(32),
            "--tx-public-key-hex".into(),
            hex(&tx_public_key),
            "--observe-account-id".into(),
            "b2".repeat(32),
            "--data-dir".into(),
            env::temp_dir()
                .join("qzbe-multi-peer-parser-test")
                .to_string_lossy()
                .to_string(),
            "--listen".into(),
            "127.0.0.1:49331".into(),
            "--noise-static-private-key-dpapi-file".into(),
            env::temp_dir()
                .join("unused-qzbe-parser-test-key")
                .to_string_lossy()
                .to_string(),
            "--initial-subsidy-atoms".into(),
            "35673515981".into(),
            "--blocks-per-halving".into(),
            "4204800".into(),
        ];
        for (peer, key) in peers {
            tokens.extend(["--peer".into(), (*peer).into()]);
            tokens.extend(["--trusted-peer-key-hex".into(), (*key).into()]);
        }
        tokens
    }

    #[test]
    fn parser_accepts_ordered_static_multi_peer_pins_and_rejects_bad_peer_sets() {
        let input = parser_fixture_tokens(&[
            ("127.0.0.1:49332", &"e6".repeat(32)),
            ("127.0.0.1:49333", &"f7".repeat(32)),
        ]);
        let parsed = parse_args_from(input).expect("parse two-peer configuration");
        let args = parsed.expect("not help");
        assert_eq!(
            args.peers,
            vec![
                "127.0.0.1:49332".parse::<SocketAddr>().unwrap(),
                "127.0.0.1:49333".parse::<SocketAddr>().unwrap()
            ]
        );
        assert_eq!(args.trusted_peer_keys, vec![[0xE6; 32], [0xF7; 32]]);

        let duplicate_peer = parser_fixture_tokens(&[
            ("127.0.0.1:49332", &"e6".repeat(32)),
            ("127.0.0.1:49332", &"f7".repeat(32)),
        ]);
        assert!(parse_args_from(duplicate_peer)
            .unwrap_err()
            .contains("duplicate --peer"));

        let missing_pin = vec![
            "--network-id".into(),
            "31".repeat(32),
            "--owner-id".into(),
            hex(&account_id_from_public_key(&[0xD1; 32])),
            "--miner-id".into(),
            "c4".repeat(32),
            "--tx-public-key-hex".into(),
            "d1".repeat(32),
            "--observe-account-id".into(),
            "b2".repeat(32),
            "--data-dir".into(),
            env::temp_dir()
                .join("qzbe-multi-peer-parser-test")
                .to_string_lossy()
                .to_string(),
            "--listen".into(),
            "127.0.0.1:49331".into(),
            "--noise-static-private-key-dpapi-file".into(),
            env::temp_dir()
                .join("unused-qzbe-parser-test-key")
                .to_string_lossy()
                .to_string(),
            "--peer".into(),
            "127.0.0.1:49332".into(),
            "--peer".into(),
            "127.0.0.1:49333".into(),
            "--trusted-peer-key-hex".into(),
            "e6".repeat(32),
            "--initial-subsidy-atoms".into(),
            "35673515981".into(),
            "--blocks-per-halving".into(),
            "4204800".into(),
        ];
        assert!(parse_args_from(missing_pin)
            .unwrap_err()
            .contains("corresponding --trusted-peer-key-hex"));
    }

    #[test]
    fn block_timestamps_use_wall_clock_and_remain_strictly_monotonic() {
        let epoch = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        assert_eq!(next_block_timestamp(0, epoch).unwrap(), 1_800_000_000);
        // If two blocks are produced in one second, the next timestamp still advances.
        assert_eq!(
            next_block_timestamp(1_800_000_000, epoch).unwrap(),
            1_800_000_001
        );
        // A temporarily slow local wall clock cannot move the chain timestamp backwards.
        assert_eq!(
            next_block_timestamp(1_800_000_010, epoch).unwrap(),
            1_800_000_011
        );
    }

    #[test]
    fn node_profile_accepts_canonical_schedule_and_rejects_toy_economics() {
        let canonical = test_args(35_673_515_981, 4_204_800);
        let (_, profile, _, _) =
            prepare_profile(&canonical).expect("canonical v0.4 candidate profile");
        assert_eq!(profile.schedule().initial_subsidy_atoms(), 35_673_515_981);
        assert_eq!(profile.schedule().blocks_per_halving(), 4_204_800);
        let default_params = prepare_profile(&canonical).unwrap().3;
        assert_eq!(default_params.pow.memory_kib, 64 * 1024);
        assert_eq!(
            default_params.initial_target,
            ConsensusParameters::candidate_testnet()
                .unwrap()
                .initial_target
        );

        let mut test_profile_args = test_args(35_673_515_981, 4_204_800);
        test_profile_args.test_easy_pow = true;
        let test_params = prepare_profile(&test_profile_args).unwrap().3;
        assert_eq!(test_params.pow.memory_kib, 8 * 1024);
        assert_eq!(
            test_params.initial_target,
            Uint256::from_be_bytes([0xEF; 32])
        );

        let toy = test_args(1_000_000, 1_000);
        let error =
            prepare_profile(&toy).expect_err("node launch must reject noncanonical toy economics");
        assert!(error.contains("NonCanonicalLaunchParameters"), "{error}");
        assert!(error.contains("canonical v0.4 tokenomics"), "{error}");
    }

    #[test]
    fn profile_lock_is_create_once_and_binds_network_genesis_profile_and_consensus() {
        let root = temp_profile_root();
        let network = [0x31; 32];
        let genesis = [0x42; 32];
        let profile = [0x53; 32];
        let params = test_candidate_params();
        require_dedicated_store_directory(&root, &network, &genesis, &profile, &params)
            .expect("fresh QZBE store gets its profile lock");
        let marker_path = root.join(QZBE_RUNTIME_PROFILE_FILE);
        let persisted = fs::read(&marker_path).expect("read persisted profile lock");
        assert_eq!(persisted.len(), QZBE_RUNTIME_PROFILE_MARKER_BYTES);
        assert_eq!(&persisted[..4], QZBE_RUNTIME_PROFILE_MAGIC);
        assert_eq!(
            u16::from_be_bytes([persisted[4], persisted[5]]),
            QZBE_RUNTIME_PROFILE_VERSION
        );
        require_dedicated_store_directory(&root, &network, &genesis, &profile, &params)
            .expect("same immutable profile can reopen");
        assert_eq!(
            fs::read(&marker_path).unwrap(),
            persisted,
            "reopen must not rewrite the marker"
        );
        assert!(
            require_dedicated_store_directory(&root, &[0x32; 32], &genesis, &profile, &params)
                .is_err()
        );
        assert!(
            require_dedicated_store_directory(&root, &network, &[0x43; 32], &profile, &params)
                .is_err()
        );
        assert!(
            require_dedicated_store_directory(&root, &network, &genesis, &[0x54; 32], &params)
                .is_err()
        );
        let mut changed_params = params.clone();
        changed_params.pow.memory_kib += 8;
        assert!(require_dedicated_store_directory(
            &root,
            &network,
            &genesis,
            &profile,
            &changed_params
        )
        .is_err());
        assert_eq!(
            fs::read(&marker_path).unwrap(),
            persisted,
            "profile mismatch must not rewrite lock"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn existing_qzbe_store_without_profile_lock_is_never_silently_adopted() {
        let root = temp_profile_root();
        fs::create_dir(root.join("branches")).unwrap();
        let network = [0x31; 32];
        let genesis = [0x42; 32];
        let profile = [0x53; 32];
        let params = test_candidate_params();
        let error = require_dedicated_store_directory(&root, &network, &genesis, &profile, &params)
            .expect_err("legacy/unlocked store artifacts must fail closed");
        assert!(error.contains("no immutable qzbe-runtime.profile lock"));
        assert!(
            !root.join(QZBE_RUNTIME_PROFILE_FILE).exists(),
            "must not bless the old store by writing a marker"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn corrupt_or_wrong_width_profile_lock_fails_closed_and_is_never_replaced() {
        let root = temp_profile_root();
        let network = [0x31; 32];
        let genesis = [0x42; 32];
        let profile = [0x53; 32];
        let params = test_candidate_params();
        require_dedicated_store_directory(&root, &network, &genesis, &profile, &params).unwrap();
        let marker_path = root.join(QZBE_RUNTIME_PROFILE_FILE);
        let original = fs::read(&marker_path).unwrap();
        let mut corrupted = original.clone();
        corrupted[13] ^= 1;
        fs::write(&marker_path, &corrupted).unwrap();
        assert!(
            require_dedicated_store_directory(&root, &network, &genesis, &profile, &params)
                .is_err()
        );
        assert_eq!(
            fs::read(&marker_path).unwrap(),
            corrupted,
            "corrupt lock is preserved for recovery, never reset"
        );
        fs::write(&marker_path, [0x5a; 7]).unwrap();
        assert!(
            require_dedicated_store_directory(&root, &network, &genesis, &profile, &params)
                .is_err()
        );
        assert_eq!(
            fs::read(&marker_path).unwrap(),
            [0x5a; 7],
            "wrong-width lock is preserved, never reset"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn qzbe_ack_has_a_fixed_canonical_width_and_binds_profile() {
        let current = Snapshot {
            height: 3,
            tip: [0x11; 32],
            state_root: [0x22; 32],
            generation: 9,
        };
        let bytes = encode_ack(&[0x31; 32], &[0x41; 32], 0, [0x51; 32], &current);
        assert_eq!(bytes.len(), ACK_BYTES);
        let decoded = decode_ack(&bytes, &[0x31; 32], &[0x41; 32]).expect("canonical ACK");
        assert_eq!(decoded.status, 0);
        assert_eq!(decoded.candidate_digest, [0x51; 32]);
        assert_eq!(decoded.snapshot, current);
        assert!(decode_ack(&bytes, &[0x32; 32], &[0x41; 32]).is_err());
        assert!(decode_ack(&bytes, &[0x31; 32], &[0x42; 32]).is_err());
        assert!(decode_ack(&bytes[..bytes.len() - 1], &[0x31; 32], &[0x41; 32]).is_err());
    }

    #[test]
    fn cli_rejects_non_loopback_addresses_before_startup() {
        let loopback = "127.0.0.1:49331".parse::<SocketAddr>().unwrap();
        let unspecified = "0.0.0.0:49331".parse::<SocketAddr>().unwrap();
        let public = "192.0.2.10:49331".parse::<SocketAddr>().unwrap();
        assert!(ensure_loopback_address(loopback, "listen addresses").is_ok());
        assert_eq!(
            ensure_loopback_address(unspecified, "listen addresses"),
            Err("QZBE runtime candidate refuses all non-loopback listen addresses".into())
        );
        assert_eq!(
            ensure_loopback_address(public, "peers"),
            Err("QZBE runtime candidate refuses all non-loopback peers".into())
        );
    }
}
