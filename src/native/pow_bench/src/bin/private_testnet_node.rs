//! Loopback-only multi-process private-testnet harness for candidate PTB2 blocks.
//!
//! This is a disposable integration harness, not a public P2P node or mainnet client.
//! It deliberately uses a trivial maximum PoW target and empty blocks so process/wire/import/
//! restart behavior can be exercised quickly. Consensus economics, reorg selection, tx relay,
//! public peer discovery, and production key custody are not implemented here.

use ai_native_l1_pow_bench::{
    chain_admission::SystemClockReferenceTime,
    consensus::{pow_digest, ConsensusParameters, PowHeader, Uint256},
    devnet_noise_transport_candidate::DevnetNoiseSession,
    devnet_profile_candidate::DevnetProfileCandidate,
    devnet_signed_peer_identity_candidate::verify_signed_peer_identity,
    identity_generation_store::IdentityGenerationStateStore,
    identity_policy::KeyPurpose,
    noise_deployment_config::{
        verify_signed_deployment_config, DeploymentConfigStateStore,
        MAX_SIGNED_DEPLOYMENT_CONFIG_LEN,
    },
    noise_issuer_registry::{IssuerRegistryStateStore, MAX_REGISTRY_WIRE_LEN},
    noise_key_provisioning::load_protected_noise_private_key,
    private_testnet_archive_range_server_candidate::ArchiveSyncServedEntry,
    private_testnet_archive_range_server_candidate::{
        ArchiveRangeBudgetConfig, ArchiveRangeServerCandidate, ArchiveSyncPayload,
    },
    private_testnet_archive_range_store_candidate::{
        decode_archive_range_page, encode_archive_range_page, ArchiveRangeWalCandidate,
        MAX_STORED_ARCHIVE_PAGE_BYTES,
    },
    private_testnet_archive_sync_candidate::{
        ArchiveEntryMeta, ArchiveSyncIndex, ArchiveSyncLimits, ARCHIVE_SYNC_CURSOR_BYTES,
        MAX_CANDIDATE_ENVELOPE_BYTES, MAX_CANDIDATE_PAGE_BYTES,
    },
    private_testnet_driver::PrivateTestnetChain,
    private_testnet_fork_choice::ForkChoiceError,
    private_testnet_fork_store::{ForkStoreError, PrivateTestnetForkStore},
    private_testnet_monetary_fork_choice::MonetaryForkChoiceOutcome,
    private_testnet_monetary_fork_store::{
        MonetaryForkStoreError, PrivateTestnetMonetaryForkStore,
    },
    private_testnet_monetary_wire::{
        decode_candidate_monetary_network_block, decode_candidate_v4_hybrid_monetary_network_block,
        encode_candidate_monetary_network_block, encode_candidate_v4_hybrid_monetary_network_block,
        MonetaryWireError,
    },
    private_testnet_v4_hybrid_fork_choice_candidate::{
        V4HybridForkChoiceError, V4HybridForkChoiceOutcome,
    },
    private_testnet_v4_hybrid_fork_store_candidate::{
        PrivateTestnetV4HybridForkStore, V4HybridForkStoreError,
    },
    private_testnet_wire::{
        decode_candidate_network_block, encode_candidate_network_block, CandidateNetworkBlock,
        PrivateTestnetWireError, MAX_PRIVATE_TESTNET_ENVELOPE_BYTES,
    },
    state_machine::{
        AccountId, Block, LedgerState, MonetaryBlock, MonetaryLedgerState, Transaction,
        TransactionAuthenticator, V4HybridMonetaryBlock, MONETARY_PUBLIC_GOODS_BUDGET_ATOMS,
    },
    transaction_auth::{
        AccountPublicKey, Ed25519TransactionAuthenticator, Ed25519TransactionSigner,
        TransactionAuthenticatorKind,
    },
    v4_account_identity_candidate::{
        native_v4_account_id, V4HybridTransaction, ML_DSA_65_PUBLIC_KEY_BYTES,
        V4_HYBRID_TRANSACTION_WIRE_BYTES,
    },
    v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate,
    v4_transaction_mempool_candidate::{
        V4HybridMempoolCandidate, V4HybridMempoolError, V4HybridMempoolLimits,
    },
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, VecDeque},
    env,
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process,
    sync::{
        atomic::{AtomicUsize, Ordering as AtomicOrdering},
        mpsc::{self, Receiver, RecvTimeoutError},
        Arc, Condvar, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const GENESIS_ACCOUNT: AccountId = [0x11; 32];
const GENESIS_BALANCE: u64 = 1_000_000;
const TEST_GENESIS_BALANCE: u64 = 10_000_000;
const TEST_RECIPIENT: AccountId = [0x22; 32];
const TEST_TX_AMOUNT: u64 = 1_000;
const TEST_TX_FEE: u64 = 1;
const MAX_TEST_TX_AMOUNT: u64 = 1_000_000;
const ACK_MAGIC: &[u8; 4] = b"PTA2";
const ACK_LEN: usize = 117;
const MONETARY_ACK_MAGIC: &[u8; 4] = b"MTA3";
const MONETARY_ACK_LEN: usize = 117;
// PMT4 has its own authenticated acknowledgement profile. It binds an ACK to
// the network, protocol version and V4 Genesis/manifest identity, never MTA3.
const MONETARY_ACK_V4_MAGIC: &[u8; 4] = b"MTA4";
const MONETARY_ACK_V4_LEN: usize = 183;
const ACK_STATUS_ACCEPTED: u8 = 0;
const ACK_STATUS_DUPLICATE: u8 = 1;
const ACK_STATUS_REJECTED: u8 = 2;
const ACK_STATUS_UNKNOWN_PARENT: u8 = 3;
const WIRE_READ_TIMEOUT: Duration = Duration::from_secs(3);
const PEER_SEND_MAX_ATTEMPTS: usize = 10;
const PEER_SEND_RETRY_DELAY: Duration = Duration::from_millis(100);
const ARCHIVE_SYNC_MAX_ROUNDS: usize = 16;
const MAX_CONFIGURED_PEERS: usize = 8;
const MAX_ARCHIVE_SYNC_BRANCHES: usize = 512;
const MAX_ARCHIVE_SYNC_BYTES: usize = 32 * 1024 * 1024;
const ARCHIVE_SYNC_RETRY_DELAY: Duration = Duration::from_millis(250);
// Fixed ceilings for loopback-testnet socket ownership. These do not imply a
// public-network DDoS or authenticated-peer policy.
const SOCKET_READER_WORKERS: usize = 4;
const SOCKET_READER_QUEUE_CAPACITY: usize = 8;
const SOCKET_READER_EVENT_POLL: Duration = Duration::from_millis(5);
const MAX_MINE_BLOCKS: u64 = 64;
const MAX_TXN4_HTTP_HEADER_BYTES: usize = 4096;
const TXN4_HTTP_DEADLINE: Duration = Duration::from_secs(2);

#[derive(Debug, Clone)]
struct Config {
    listen: SocketAddr,
    status_listen: Option<SocketAddr>,
    transaction_listen: Option<SocketAddr>,
    v4_founder_ed25519_public_key: Option<[u8; 32]>,
    v4_founder_mldsa65_public_key_file: Option<PathBuf>,
    network_id: [u8; 32],
    data_dir: PathBuf,
    peers: Vec<SocketAddr>,
    mine_blocks: u64,
    stop_after_height: Option<u64>,
    timestamp_offset: u64,
    timestamp_backdate: u64,
    test_transactions: bool,
    test_seed_file: Option<PathBuf>,
    noise_static_private_key_dpapi_file: Option<PathBuf>,
    trusted_peer_keys: Vec<[u8; 32]>,
    trusted_peer_identity_files: Vec<PathBuf>,
    deployment_config_file: Option<PathBuf>,
    deployment_authority_public_key: Option<[u8; 32]>,
    deployment_config_min_sequence: Option<u64>,
    issuer_registry_file: Option<PathBuf>,
    peer_identity_issuer_id: Option<u32>,
    test_tx_amount: u64,
    duplicate_broadcast: bool,
    archive_sync_delay_ms: u64,
    archive_sync_reverse_first_round: bool,
    archive_range_max_page_items: usize,
    archive_range_post_commit_delay_ms: u64,
    run_seconds: u64,
    exit_after_mining: bool,
    monetary_candidate_local_smoke: bool,
    monetary_v4_hybrid_local_smoke: bool,
    monetary_v4_hybrid_peer_smoke: bool,
    monetary_v4_hybrid_archive_range_sync: bool,
    monetary_candidate_peer_smoke: bool,
    monetary_candidate_archive_range_sync: bool,
    test_crash_after_monetary_import: bool,
    test_crash_after_monetary_v4_import: bool,
    test_reorg_after_first_archive_range_page: bool,
    test_reorg_after_second_archive_range_page: bool,
}

fn parse_hex32(value: &str, field: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 {
        return Err(format!("{field} must be exactly 64 hexadecimal characters"));
    }
    let mut out = [0u8; 32];
    for (i, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(pair).map_err(|_| format!("{field} must be hexadecimal"))?;
        out[i] =
            u8::from_str_radix(pair, 16).map_err(|_| format!("{field} must be hexadecimal"))?;
    }
    Ok(out)
}

fn parse_args() -> Result<Config, String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let mut listen = "127.0.0.1:49301"
        .parse::<SocketAddr>()
        .expect("static default socket address");
    let mut status_listen: Option<SocketAddr> = None;
    let mut transaction_listen: Option<SocketAddr> = None;
    let mut v4_founder_ed25519_public_key: Option<[u8; 32]> = None;
    let mut v4_founder_mldsa65_public_key_file: Option<PathBuf> = None;
    let mut network_id = None;
    let mut data_dir = None;
    let mut peers: Vec<SocketAddr> = Vec::new();
    let mut mine_blocks = 0u64;
    let mut stop_after_height = None;
    let mut timestamp_offset = 0u64;
    let mut timestamp_backdate = 0u64;
    let mut test_transactions = false;
    let mut test_seed_file = None;
    let mut noise_static_private_key_dpapi_file = None;
    let mut trusted_peer_keys: Vec<[u8; 32]> = Vec::new();
    let mut trusted_peer_identity_files: Vec<PathBuf> = Vec::new();
    let mut deployment_config_file: Option<PathBuf> = None;
    let mut deployment_authority_public_key: Option<[u8; 32]> = None;
    let mut deployment_config_min_sequence: Option<u64> = None;
    let mut issuer_registry_file: Option<PathBuf> = None;
    let mut peer_identity_issuer_id: Option<u32> = None;
    let mut test_tx_amount = TEST_TX_AMOUNT;
    let mut duplicate_broadcast = false;
    let mut archive_sync_delay_ms = 0u64;
    let mut archive_sync_reverse_first_round = false;
    let mut archive_range_max_page_items = None;
    let mut archive_range_post_commit_delay_ms = None;
    let mut run_seconds = 30u64;
    let mut exit_after_mining = false;
    let mut monetary_candidate_local_smoke = false;
    let mut monetary_v4_hybrid_local_smoke = false;
    let mut monetary_v4_hybrid_peer_smoke = false;
    let mut monetary_v4_hybrid_archive_range_sync = false;
    let mut monetary_candidate_peer_smoke = false;
    let mut monetary_candidate_archive_range_sync = false;
    let mut test_crash_after_monetary_import = false;
    let mut test_crash_after_monetary_v4_import = false;
    let mut test_reorg_after_first_archive_range_page = false;
    let mut test_reorg_after_second_archive_range_page = false;
    let mut i = 0usize;

    while i < args.len() {
        let flag = args[i].as_str();
        match flag {
            "--help" | "-h" => {
                return Err("usage: devnet_node --network-id HEX64 --data-dir PATH [--listen 127.0.0.1:PORT] [--status-listen 127.0.0.1:PORT] [--transaction-listen 127.0.0.1:PORT --v4-founder-ed25519-public-key-hex HEX64 --v4-founder-mldsa65-public-key-file PATH] [--peer 127.0.0.1:PORT ... --noise-static-private-key-dpapi-file PATH (--trusted-peer-key-hex HEX64 ... | --trusted-peer-identity-file PATH ... --deployment-config-file PATH --deployment-authority-key-hex HEX64 --deployment-config-min-sequence N --issuer-registry-file PATH --peer-identity-issuer-id N)] [--archive-range-max-page-items 1..16] [--archive-range-post-commit-delay-ms 0..5000] [--mine-blocks N] [--run-seconds N] [--monetary-candidate-local-smoke | --monetary-v4-hybrid-local-smoke | --monetary-v4-hybrid-peer-smoke [--monetary-v4-hybrid-archive-range-sync] [--test-crash-after-monetary-v4-import] [--test-reorg-after-first-archive-range-page] [--test-reorg-after-second-archive-range-page] | --monetary-candidate-peer-smoke [--monetary-candidate-archive-range-sync]]".into());
            }
            "--test-transactions" => {
                test_transactions = true;
                i += 1;
                continue;
            }
            "--duplicate-broadcast" => {
                duplicate_broadcast = true;
                i += 1;
                continue;
            }
            "--archive-sync-reverse-first-round" => {
                archive_sync_reverse_first_round = true;
                i += 1;
                continue;
            }
            "--monetary-candidate-local-smoke" => {
                monetary_candidate_local_smoke = true;
                i += 1;
                continue;
            }
            "--monetary-v4-hybrid-local-smoke" => {
                monetary_v4_hybrid_local_smoke = true;
                i += 1;
                continue;
            }
            "--monetary-v4-hybrid-peer-smoke" => {
                monetary_v4_hybrid_peer_smoke = true;
                i += 1;
                continue;
            }
            "--monetary-v4-hybrid-archive-range-sync" => {
                monetary_v4_hybrid_archive_range_sync = true;
                i += 1;
                continue;
            }
            "--monetary-candidate-peer-smoke" => {
                monetary_candidate_peer_smoke = true;
                i += 1;
                continue;
            }
            "--monetary-candidate-archive-range-sync" => {
                monetary_candidate_archive_range_sync = true;
                i += 1;
                continue;
            }
            "--test-crash-after-monetary-import" => {
                test_crash_after_monetary_import = true;
                i += 1;
                continue;
            }
            "--test-crash-after-monetary-v4-import" => {
                test_crash_after_monetary_v4_import = true;
                i += 1;
                continue;
            }
            "--test-reorg-after-first-archive-range-page" => {
                test_reorg_after_first_archive_range_page = true;
                i += 1;
                continue;
            }
            "--test-reorg-after-second-archive-range-page" => {
                test_reorg_after_second_archive_range_page = true;
                i += 1;
                continue;
            }
            "--noise-static-private-key-dpapi-file"
            | "--trusted-peer-key-hex"
            | "--trusted-peer-identity-file"
            | "--deployment-config-file"
            | "--deployment-authority-key-hex"
            | "--deployment-config-min-sequence"
            | "--issuer-registry-file"
            | "--peer-identity-issuer-id"
            | "--listen"
            | "--status-listen"
            | "--transaction-listen"
            | "--v4-founder-ed25519-public-key-hex"
            | "--v4-founder-mldsa65-public-key-file"
            | "--network-id"
            | "--data-dir"
            | "--peer"
            | "--mine-blocks"
            | "--run-seconds"
            | "--exit-after-mining"
            | "--stop-after-height"
            | "--timestamp-offset"
            | "--timestamp-backdate"
            | "--archive-sync-delay-ms"
            | "--archive-range-max-page-items"
            | "--archive-range-post-commit-delay-ms"
            | "--test-seed-file"
            | "--test-tx-amount" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| format!("missing value for {flag}"))?;
                if value.starts_with("--") {
                    return Err(format!("missing value for {flag}"));
                }
                match flag {
                    "--noise-static-private-key-dpapi-file" => {
                        if noise_static_private_key_dpapi_file
                            .replace(PathBuf::from(value))
                            .is_some()
                        {
                            return Err(
                                "--noise-static-private-key-dpapi-file may be specified only once"
                                    .into(),
                            );
                        }
                    }
                    "--trusted-peer-key-hex" => {
                        trusted_peer_keys.push(parse_hex32(value, "--trusted-peer-key-hex")?)
                    }
                    "--trusted-peer-identity-file" => {
                        trusted_peer_identity_files.push(PathBuf::from(value));
                    }
                    "--deployment-config-file" => {
                        if deployment_config_file
                            .replace(PathBuf::from(value))
                            .is_some()
                        {
                            return Err(
                                "--deployment-config-file may be specified only once".into()
                            );
                        }
                    }
                    "--deployment-authority-key-hex" => {
                        if deployment_authority_public_key
                            .replace(parse_hex32(value, "--deployment-authority-key-hex")?)
                            .is_some()
                        {
                            return Err(
                                "--deployment-authority-key-hex may be specified only once".into(),
                            );
                        }
                    }
                    "--deployment-config-min-sequence" => {
                        let parsed = value.parse::<u64>().map_err(|_| {
                            "--deployment-config-min-sequence must be an integer".to_string()
                        })?;
                        if parsed == 0 || deployment_config_min_sequence.replace(parsed).is_some() {
                            return Err("--deployment-config-min-sequence must be a nonzero integer specified once".into());
                        }
                    }
                    "--issuer-registry-file" => {
                        if issuer_registry_file.replace(PathBuf::from(value)).is_some() {
                            return Err("--issuer-registry-file may be specified only once".into());
                        }
                    }
                    "--peer-identity-issuer-id" => {
                        let parsed = value.parse::<u32>().map_err(|_| {
                            "--peer-identity-issuer-id must be an integer".to_string()
                        })?;
                        if parsed == 0 || peer_identity_issuer_id.replace(parsed).is_some() {
                            return Err("--peer-identity-issuer-id must be a nonzero integer specified once".into());
                        }
                    }
                    "--listen" => {
                        listen = value
                            .parse()
                            .map_err(|_| "--listen must be IP:port".to_string())?
                    }
                    "--status-listen" => {
                        status_listen = Some(
                            value
                                .parse()
                                .map_err(|_| "--status-listen must be IP:port".to_string())?,
                        )
                    }
                    "--transaction-listen" => {
                        if transaction_listen
                            .replace(
                                value.parse().map_err(|_| {
                                    "--transaction-listen must be IP:port".to_string()
                                })?,
                            )
                            .is_some()
                        {
                            return Err("--transaction-listen may be specified only once".into());
                        }
                    }
                    "--v4-founder-ed25519-public-key-hex" => {
                        if v4_founder_ed25519_public_key
                            .replace(parse_hex32(value, "--v4-founder-ed25519-public-key-hex")?)
                            .is_some()
                        {
                            return Err(
                                "--v4-founder-ed25519-public-key-hex may be specified only once"
                                    .into(),
                            );
                        }
                    }
                    "--v4-founder-mldsa65-public-key-file" => {
                        if v4_founder_mldsa65_public_key_file
                            .replace(PathBuf::from(value))
                            .is_some()
                        {
                            return Err(
                                "--v4-founder-mldsa65-public-key-file may be specified only once"
                                    .into(),
                            );
                        }
                    }
                    "--network-id" => network_id = Some(parse_hex32(value, "--network-id")?),
                    "--data-dir" => data_dir = Some(PathBuf::from(value)),
                    "--peer" => peers.push(
                        value
                            .parse()
                            .map_err(|_| "--peer must be IP:port".to_string())?,
                    ),
                    "--mine-blocks" => {
                        mine_blocks = value
                            .parse()
                            .map_err(|_| "--mine-blocks must be an integer".to_string())?
                    }
                    "--run-seconds" => {
                        run_seconds = value
                            .parse()
                            .map_err(|_| "--run-seconds must be an integer".to_string())?
                    }
                    "--exit-after-mining" => {
                        exit_after_mining = value
                            .parse()
                            .map_err(|_| "--exit-after-mining must be true or false".to_string())?
                    }
                    "--stop-after-height" => {
                        stop_after_height =
                            Some(value.parse().map_err(|_| {
                                "--stop-after-height must be an integer".to_string()
                            })?)
                    }
                    "--timestamp-offset" => {
                        timestamp_offset = value
                            .parse()
                            .map_err(|_| "--timestamp-offset must be an integer".to_string())?;
                    }
                    "--timestamp-backdate" => {
                        timestamp_backdate = value
                            .parse()
                            .map_err(|_| "--timestamp-backdate must be an integer".to_string())?;
                    }
                    "--archive-sync-delay-ms" => {
                        archive_sync_delay_ms = value.parse().map_err(|_| {
                            "--archive-sync-delay-ms must be an integer".to_string()
                        })?;
                    }
                    "--archive-range-max-page-items" => {
                        let parsed = value.parse::<usize>().map_err(|_| {
                            "--archive-range-max-page-items must be an integer".to_string()
                        })?;
                        if !(1..=16).contains(&parsed)
                            || archive_range_max_page_items.replace(parsed).is_some()
                        {
                            return Err("--archive-range-max-page-items must be between 1 and 16 and specified at most once".into());
                        }
                    }
                    "--archive-range-post-commit-delay-ms" => {
                        let parsed = value.parse::<u64>().map_err(|_| {
                            "--archive-range-post-commit-delay-ms must be an integer".to_string()
                        })?;
                        if parsed > 5000
                            || archive_range_post_commit_delay_ms.replace(parsed).is_some()
                        {
                            return Err("--archive-range-post-commit-delay-ms must be between 0 and 5000 and specified at most once".into());
                        }
                    }
                    "--test-seed-file" => test_seed_file = Some(PathBuf::from(value)),
                    "--test-tx-amount" => {
                        test_tx_amount = value
                            .parse()
                            .map_err(|_| "--test-tx-amount must be an integer".to_string())?
                    }
                    _ => unreachable!(),
                }
                i += 2;
            }
            other => return Err(format!("unknown option {other}")),
        }
    }

    let network_id = network_id.ok_or("required option --network-id")?;
    let data_dir = data_dir.ok_or("required option --data-dir")?;
    if network_id.iter().all(|byte| *byte == 0) {
        return Err("--network-id cannot be all zero".into());
    }
    if !listen.ip().is_loopback() {
        return Err("this private-testnet harness only binds loopback addresses".into());
    }
    if status_listen.is_some_and(|address| !address.ip().is_loopback()) {
        return Err("status_api_only_binds_loopback_addresses".into());
    }
    if status_listen == Some(listen) {
        return Err("--status-listen must differ from --listen".into());
    }
    if trusted_peer_keys.len() > 64 || trusted_peer_identity_files.len() > 64 {
        return Err("peer trust entries exceed the maximum of 64".into());
    }
    if !trusted_peer_identity_files.is_empty() && !trusted_peer_keys.is_empty() {
        return Err("choose signed peer-identity files or raw static-key pins, not both".into());
    }
    let signed_identity_mode = !trusted_peer_identity_files.is_empty();
    let has_deployment_trust = deployment_config_file.is_some()
        && deployment_authority_public_key.is_some()
        && deployment_config_min_sequence.is_some()
        && issuer_registry_file.is_some()
        && peer_identity_issuer_id.is_some();
    let any_deployment_trust = deployment_config_file.is_some()
        || deployment_authority_public_key.is_some()
        || deployment_config_min_sequence.is_some()
        || issuer_registry_file.is_some()
        || peer_identity_issuer_id.is_some();
    if signed_identity_mode != has_deployment_trust
        || (!signed_identity_mode && any_deployment_trust)
    {
        return Err("signed peer identities require --deployment-config-file, --deployment-authority-key-hex, --deployment-config-min-sequence, --issuer-registry-file and --peer-identity-issuer-id; all trust options require one or more identity files".into());
    }
    if trusted_peer_keys
        .iter()
        .any(|key| key.iter().all(|byte| *byte == 0))
    {
        return Err("--trusted-peer-key-hex cannot be all zero".into());
    }
    let mut unique_trusted_peer_keys = trusted_peer_keys.clone();
    unique_trusted_peer_keys.sort();
    unique_trusted_peer_keys.dedup();
    if unique_trusted_peer_keys.len() != trusted_peer_keys.len() {
        return Err("duplicate --trusted-peer-key-hex".into());
    }
    let trust_entry_count = if signed_identity_mode {
        trusted_peer_identity_files.len()
    } else {
        trusted_peer_keys.len()
    };
    if noise_static_private_key_dpapi_file.is_some() != (trust_entry_count > 0) {
        return Err("Noise peer mode requires --noise-static-private-key-dpapi-file and either trusted peer key pins or signed peer identity files".into());
    }
    if !peers.is_empty()
        && noise_static_private_key_dpapi_file.is_some()
        && peers.len() != trust_entry_count
    {
        return Err(
            "when --peer is used with Noise, provide one ordered trust entry per peer".into(),
        );
    }
    if peers.len() > MAX_CONFIGURED_PEERS {
        return Err(format!(
            "configured peer count exceeds harness limit of {MAX_CONFIGURED_PEERS}"
        ));
    }

    if peers.iter().any(|peer| !peer.ip().is_loopback()) {
        return Err("this private-testnet harness only connects to loopback peers".into());
    }
    if peers.contains(&listen) {
        return Err("--peer cannot point to this node's own listen address".into());
    }
    let mut unique_peers = peers.clone();
    unique_peers.sort();
    unique_peers.dedup();
    if unique_peers.len() != peers.len() {
        return Err("duplicate --peer address".into());
    }
    if mine_blocks > MAX_MINE_BLOCKS {
        return Err(format!(
            "--mine-blocks is capped at {MAX_MINE_BLOCKS} in this smoke harness"
        ));
    }
    if timestamp_offset > 300 {
        return Err("--timestamp-offset is capped at 300 seconds in this smoke harness".into());
    }
    if timestamp_backdate > 3600 {
        return Err("--timestamp-backdate is capped at 3600 seconds in this smoke harness".into());
    }
    if timestamp_offset > 0 && timestamp_backdate > 0 {
        return Err("--timestamp-offset and --timestamp-backdate are mutually exclusive".into());
    }
    if archive_sync_delay_ms > 250 {
        return Err("--archive-sync-delay-ms is capped at 250 in this smoke harness".into());
    }
    let archive_range_max_page_items = archive_range_max_page_items.unwrap_or(16);
    let archive_range_post_commit_delay_ms = archive_range_post_commit_delay_ms.unwrap_or(0);
    if test_transactions != test_seed_file.is_some() {
        return Err("--test-transactions and --test-seed-file must be used together".into());
    }
    if test_tx_amount == 0 || test_tx_amount > MAX_TEST_TX_AMOUNT {
        return Err(format!(
            "--test-tx-amount must be between 1 and {MAX_TEST_TX_AMOUNT}"
        ));
    }
    if !test_transactions && test_tx_amount != TEST_TX_AMOUNT {
        return Err("--test-tx-amount requires --test-transactions".into());
    }
    if duplicate_broadcast && mine_blocks == 0 {
        return Err("--duplicate-broadcast requires --mine-blocks greater than zero".into());
    }
    if stop_after_height == Some(0) {
        return Err("--stop-after-height must be greater than zero".into());
    }
    if run_seconds == 0 || run_seconds > 3600 {
        return Err("--run-seconds must be between 1 and 3600".into());
    }
    if exit_after_mining && mine_blocks == 0 {
        return Err("--exit-after-mining requires --mine-blocks greater than zero".into());
    }
    if monetary_candidate_archive_range_sync && !monetary_candidate_peer_smoke {
        return Err(
            "--monetary-candidate-archive-range-sync requires --monetary-candidate-peer-smoke"
                .into(),
        );
    }
    if test_crash_after_monetary_import
        && !(monetary_candidate_peer_smoke && monetary_candidate_archive_range_sync)
    {
        return Err(
            "--test-crash-after-monetary-import requires the explicit monetary candidate archive-sync mode"
                .into(),
        );
    }
    if test_crash_after_monetary_v4_import
        && !(monetary_v4_hybrid_peer_smoke && monetary_v4_hybrid_archive_range_sync)
    {
        return Err(
            "--test-crash-after-monetary-v4-import requires the explicit PMT4/PFM4 archive-sync mode".into(),
        );
    }
    if test_reorg_after_first_archive_range_page && test_reorg_after_second_archive_range_page {
        return Err("choose only one archive-page reorg fault stage".into());
    }
    if test_reorg_after_second_archive_range_page
        && !(monetary_v4_hybrid_peer_smoke && monetary_v4_hybrid_archive_range_sync)
    {
        return Err("--test-reorg-after-second-archive-range-page requires the explicit PMT4/PFM4 archive-sync mode".into());
    }
    if test_reorg_after_first_archive_range_page
        && !((monetary_candidate_peer_smoke && monetary_candidate_archive_range_sync)
            || (monetary_v4_hybrid_peer_smoke && monetary_v4_hybrid_archive_range_sync))
    {
        return Err(
            "--test-reorg-after-first-archive-range-page requires the explicit monetary candidate archive-sync mode"
                .into(),
        );
    }

    if v4_founder_ed25519_public_key.is_some() != v4_founder_mldsa65_public_key_file.is_some() {
        return Err(
            "V4 founder Genesis identity requires both Ed25519 public key hex and ML-DSA-65 public-key file"
                .into(),
        );
    }
    if transaction_listen.is_some()
        && (v4_founder_ed25519_public_key.is_none() || v4_founder_mldsa65_public_key_file.is_none())
    {
        return Err(
            "--transaction-listen requires an explicit V4 founder public-key identity so the Genesis allocation is spendable"
                .into(),
        );
    }
    if transaction_listen.is_some() && mine_blocks == 0 {
        return Err("--transaction-listen requires --mine-blocks greater than zero to execute admitted transactions".into());
    }

    Ok(Config {
        listen,
        status_listen,
        transaction_listen,
        v4_founder_ed25519_public_key,
        v4_founder_mldsa65_public_key_file,
        network_id,
        data_dir,
        peers,
        mine_blocks,
        stop_after_height,
        timestamp_offset,
        timestamp_backdate,
        test_transactions,
        test_seed_file,
        noise_static_private_key_dpapi_file,
        trusted_peer_keys,
        trusted_peer_identity_files,
        deployment_config_file,
        deployment_authority_public_key,
        deployment_config_min_sequence,
        issuer_registry_file,
        peer_identity_issuer_id,
        test_tx_amount,
        duplicate_broadcast,
        archive_sync_delay_ms,
        archive_sync_reverse_first_round,
        archive_range_max_page_items,
        archive_range_post_commit_delay_ms,
        run_seconds,
        exit_after_mining,
        monetary_candidate_local_smoke,
        monetary_v4_hybrid_local_smoke,
        monetary_v4_hybrid_peer_smoke,
        monetary_v4_hybrid_archive_range_sync,
        monetary_candidate_peer_smoke,
        monetary_candidate_archive_range_sync,
        test_crash_after_monetary_import,
        test_crash_after_monetary_v4_import,
        test_reorg_after_first_archive_range_page,
        test_reorg_after_second_archive_range_page,
    })
}

// The default mode rejects every transaction. Ed25519 is enabled only for an explicit disposable
// test profile and a caller-supplied 32-byte seed file; no private seed is embedded or logged.
enum NodeAuthenticator {
    RejectAll,
    TestEd25519(Ed25519TransactionAuthenticator),
}
impl TransactionAuthenticator for NodeAuthenticator {
    fn verify(&self, sender: &AccountId, digest: &[u8; 32], signature: &[u8]) -> Result<(), ()> {
        match self {
            Self::RejectAll => Err(()),
            Self::TestEd25519(auth) => auth.verify(sender, digest, signature),
        }
    }
}
fn build_transaction_profile(
    config: &Config,
    runtime_profile: NodeRuntimeProfile,
) -> Result<
    (
        NodeAuthenticator,
        Option<Ed25519TransactionSigner>,
        Vec<(AccountId, u64)>,
        [u8; 32],
    ),
    String,
> {
    if runtime_profile == NodeRuntimeProfile::ZeroValueDevnet {
        if config.test_transactions || config.test_seed_file.is_some() {
            return Err("devnet_node forbids the private smoke transaction fixture".into());
        }
        return Ok((NodeAuthenticator::RejectAll, None, Vec::new(), [0; 32]));
    }
    if !config.test_transactions {
        return Ok((
            NodeAuthenticator::RejectAll,
            None,
            vec![(GENESIS_ACCOUNT, GENESIS_BALANCE)],
            [0; 32],
        ));
    }
    let seed_path = config
        .test_seed_file
        .as_ref()
        .ok_or("test seed file is required")?;
    let metadata =
        fs::metadata(seed_path).map_err(|e| format!("read test seed file metadata: {e}"))?;
    if metadata.len() != 32 {
        return Err("test seed file must contain exactly 32 bytes".into());
    }
    let bytes = fs::read(seed_path).map_err(|e| format!("read test seed file: {e}"))?;
    let seed: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "test seed file must contain exactly 32 bytes")?;
    let signer = Ed25519TransactionSigner::from_seed(seed);
    let public_key = signer.public_key();
    let sender = signer.account_id();
    if sender == TEST_RECIPIENT {
        return Err("derived test sender collides with the fixed test recipient".into());
    }
    let auth = Ed25519TransactionAuthenticator::select_by_id(
        TransactionAuthenticatorKind::Ed25519V1 as u16,
        [AccountPublicKey {
            account_id: sender,
            public_key,
        }],
    )
    .map_err(|e| format!("configure disposable Ed25519 verifier: {e:?}"))?;
    Ok((
        NodeAuthenticator::TestEd25519(auth),
        Some(signer),
        vec![(sender, TEST_GENESIS_BALANCE), (TEST_RECIPIENT, 0)],
        public_key,
    ))
}

fn candidate_params() -> Result<ConsensusParameters, String> {
    let mut params = ConsensusParameters::candidate_testnet()
        .map_err(|error| format!("invalid candidate testnet parameters: {error}"))?;
    // Explicit disposable-loopback overrides: the envelope smoke test must not wait for mining.
    // These are deliberately NOT the candidate public-testnet or any Mainnet PoW parameters.
    params.initial_target = Uint256::MAX;
    params.pow_limit = Uint256::MAX;
    params.pow.memory_kib = 8 * 1024; // 8 MiB only for this process/wire smoke harness.
    params
        .validate()
        .map_err(|error| format!("invalid private-testnet harness profile: {error}"))?;
    Ok(params)
}

fn genesis_manifest(
    network_id: &[u8; 32],
    params: &ConsensusParameters,
    accounts: &[(AccountId, u64)],
    test_transactions: bool,
    test_signer_public_key: &[u8; 32],
) -> Vec<u8> {
    let mut accounts = accounts.to_vec();
    accounts.sort_by_key(|(id, _)| *id);
    let mut bytes = Vec::with_capacity(128 + accounts.len() * 40);
    bytes.extend_from_slice(b"PTG3");
    bytes.extend_from_slice(&3u16.to_be_bytes());
    bytes.extend_from_slice(network_id);
    bytes.push(u8::from(test_transactions));
    bytes.extend_from_slice(test_signer_public_key);
    bytes.extend_from_slice(&(accounts.len() as u32).to_be_bytes());
    for (id, balance) in accounts {
        bytes.extend_from_slice(&id);
        bytes.extend_from_slice(&balance.to_be_bytes());
    }
    bytes.extend_from_slice(&params.initial_target.to_be_bytes());
    bytes.extend_from_slice(&params.pow.memory_kib.to_be_bytes());
    bytes.extend_from_slice(&params.pow.iterations.to_be_bytes());
    bytes.extend_from_slice(&params.pow.lanes.to_be_bytes());
    bytes
}

fn verify_or_create_manifest(
    data_dir: &Path,
    network_id: &[u8; 32],
    params: &ConsensusParameters,
    genesis_accounts: &[(AccountId, u64)],
    test_transactions: bool,
    test_signer_public_key: &[u8; 32],
) -> Result<(), String> {
    fs::create_dir_all(data_dir).map_err(|error| format!("create data directory: {error}"))?;
    let path = data_dir.join("genesis.manifest");
    let expected = genesis_manifest(
        network_id,
        params,
        genesis_accounts,
        test_transactions,
        test_signer_public_key,
    );
    if path.exists() {
        let existing =
            fs::read(&path).map_err(|error| format!("read genesis manifest: {error}"))?;
        if existing != expected {
            return Err(
                "data directory genesis manifest differs from requested network/profile".into(),
            );
        }
        return Ok(());
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|error| format!("create genesis manifest: {error}"))?;
    file.write_all(&expected)
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("persist genesis manifest: {error}"))?;
    Ok(())
}

fn ack_bytes(
    status: u8,
    candidate_height: u64,
    candidate_digest: [u8; 32],
    canonical: &PrivateTestnetChain,
) -> [u8; ACK_LEN] {
    let mut bytes = [0u8; ACK_LEN];
    bytes[..4].copy_from_slice(ACK_MAGIC);
    bytes[4] = status;
    bytes[5..13].copy_from_slice(&candidate_height.to_be_bytes());
    bytes[13..45].copy_from_slice(&candidate_digest);
    bytes[45..53].copy_from_slice(&canonical.state().height().to_be_bytes());
    bytes[53..85].copy_from_slice(&canonical.state().state_root());
    bytes[85..117].copy_from_slice(&canonical.chain_tip().tip_hash);
    bytes
}

fn read_exact_before_deadline(
    stream: &mut TcpStream,
    buffer: &mut [u8],
    deadline: Instant,
) -> io::Result<()> {
    let mut filled = 0usize;
    while filled < buffer.len() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "absolute candidate frame-read deadline exceeded",
            ));
        }
        stream.set_read_timeout(Some(remaining))?;
        match stream.read(&mut buffer[filled..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "peer closed before candidate frame was complete",
                ));
            }
            Ok(read) => filled += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "absolute candidate frame-read deadline exceeded",
        ));
    }
    Ok(())
}

struct NoisePrivateKey([u8; 32]);
impl Drop for NoisePrivateKey {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Clone)]
struct NoiseInboundConfig {
    network_id: [u8; 32],
    local_static_private_key: Arc<NoisePrivateKey>,
    trusted_peer_public_keys: Vec<[u8; 32]>,
    signed_peer_trust_reloader: Option<SignedPeerTrustReloader>,
}

impl NoiseInboundConfig {
    fn current_trusted_peer_public_keys(&self) -> Result<Vec<[u8; 32]>, String> {
        match self.signed_peer_trust_reloader.as_ref() {
            Some(reloader) => reloader.resolve(),
            None => Ok(self.trusted_peer_public_keys.clone()),
        }
    }
}

#[derive(Clone)]
struct NoiseOutboundConfig {
    network_id: [u8; 32],
    local_static_private_key: Arc<NoisePrivateKey>,
    peer_pins: Vec<(SocketAddr, [u8; 32])>,
    signed_peer_trust_reloader: Option<SignedPeerTrustReloader>,
}

impl NoiseOutboundConfig {
    fn trusted_pin(&self, peer: SocketAddr) -> Result<[u8; 32], String> {
        let index = self
            .peer_pins
            .iter()
            .position(|(address, _)| *address == peer)
            .ok_or_else(|| format!("no Noise static-key pin configured for peer {peer}"))?;
        if let Some(reloader) = self.signed_peer_trust_reloader.as_ref() {
            let current = reloader.resolve()?;
            return current.get(index).copied().ok_or_else(|| {
                format!("signed peer identity list no longer has a key for configured peer {peer}")
            });
        }
        Ok(self.peer_pins[index].1)
    }
}

/// Read a bounded public configuration file from a regular non-symlink path.
fn read_bounded_public_file(path: &Path, max_len: usize, label: &str) -> Result<Vec<u8>, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("read {label} metadata: {error}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > max_len as u64
    {
        return Err(format!(
            "{label} must be a bounded regular non-symlink file"
        ));
    }
    let file = fs::File::open(path).map_err(|error| format!("open {label}: {error}"))?;
    let mut wire = Vec::with_capacity(metadata.len() as usize);
    file.take(max_len.saturating_add(1) as u64)
        .read_to_end(&mut wire)
        .map_err(|error| format!("read {label}: {error}"))?;
    if wire.is_empty() || wire.len() > max_len {
        return Err(format!("{label} exceeded its configured size bound"));
    }
    Ok(wire)
}

/// Resolve the remote Noise trust set. For signed identities, authenticate and persist the
/// deployment config -> governance root chain -> issuer registry -> peer key generation chain
/// before the listener is opened. The deployment-authority public key and minimum sequence are
/// still out-of-band launch inputs; local high-water files are not an independent hardware anchor.
fn resolve_trusted_peer_keys(
    config: &Config,
    runtime_profile: NodeRuntimeProfile,
) -> Result<Vec<[u8; 32]>, String> {
    if config.trusted_peer_identity_files.is_empty() {
        return Ok(config.trusted_peer_keys.clone());
    }
    if runtime_profile != NodeRuntimeProfile::ZeroValueDevnet {
        return Err("signed peer identities are accepted only by devnet_node".into());
    }
    let deployment_config_path = config
        .deployment_config_file
        .as_deref()
        .ok_or("signed peer deployment-config file is missing")?;
    let deployment_authority_public_key = config
        .deployment_authority_public_key
        .ok_or("deployment-authority public key is missing")?;
    let deployment_minimum_sequence = config
        .deployment_config_min_sequence
        .ok_or("minimum deployment-config sequence is missing")?;
    let issuer_registry_path = config
        .issuer_registry_file
        .as_deref()
        .ok_or("signed issuer-registry file is missing")?;
    let issuer_id = config
        .peer_identity_issuer_id
        .ok_or("signed peer issuer ID is missing")?;

    let deployment_wire = read_bounded_public_file(
        deployment_config_path,
        MAX_SIGNED_DEPLOYMENT_CONFIG_LEN,
        "signed deployment config",
    )?;
    let deployment = verify_signed_deployment_config(
        &deployment_wire,
        &config.network_id,
        &deployment_authority_public_key,
        deployment_minimum_sequence,
    )
    .map_err(|error| format!("signed deployment config rejected: {error:?}"))?;

    let trust_dir = config.data_dir.join("signed_trust_state");
    fs::create_dir_all(&trust_dir)
        .map_err(|error| format!("create signed trust state directory: {error}"))?;
    let deployment_state = DeploymentConfigStateStore::open(
        trust_dir.join("deployment-config.dcs1"),
        &config.network_id,
        &deployment_authority_public_key,
        deployment_minimum_sequence,
    )
    .map_err(|error| format!("open deployment-config high-water state: {error:?}"))?;
    deployment_state
        .observe(&deployment)
        .map_err(|error| format!("deployment config rollback/state check failed: {error:?}"))?;

    let registry_wire = read_bounded_public_file(
        issuer_registry_path,
        MAX_REGISTRY_WIRE_LEN,
        "signed issuer registry",
    )?;
    let registry_state = IssuerRegistryStateStore::open_with_root_chain(
        trust_dir.join("issuer-registry.irh1"),
        &config.network_id,
        deployment.root_chain.clone(),
        deployment.minimum_registry_sequence,
    )
    .map_err(|error| format!("open issuer-registry high-water state: {error:?}"))?;
    // This call durably stores a newly signed revocation before returning IssuerInactive.
    let issuer_public_key = registry_state
        .accept_signed_registry(&registry_wire, issuer_id)
        .map_err(|error| format!("signed issuer registry rejected: {error:?}"))?;

    let epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock precedes UNIX epoch")?
        .as_secs();
    let state_dir = config.data_dir.join("peer_identity_highwater");
    fs::create_dir_all(&state_dir)
        .map_err(|error| format!("create peer identity state directory: {error}"))?;
    let mut trusted = Vec::with_capacity(config.trusted_peer_identity_files.len());
    for path in &config.trusted_peer_identity_files {
        let wire = read_bounded_public_file(
            path,
            ai_native_l1_pow_bench::devnet_signed_peer_identity_candidate::MAX_SIGNED_PEER_IDENTITY_LEN,
            "signed peer identity",
        )?;
        let verified = verify_signed_peer_identity(
            &wire,
            &config.network_id,
            issuer_id,
            &issuer_public_key,
            epoch,
        )
        .map_err(|error| format!("signed peer identity rejected: {error}"))?;
        let state_path = state_dir.join(format!(
            "issuer_{}_credential_{:032x}_key_{}.highwater",
            verified.issuer_id, verified.credential_id, verified.record.key_id
        ));
        let highwater = IdentityGenerationStateStore::open(
            &state_path,
            &verified.network_id,
            verified.record.key_id,
            KeyPurpose::PeerAuth,
            verified.credential_id,
            verified.issuer_id,
            issuer_public_key,
        )
        .map_err(|error| format!("open peer identity high-water state: {error:?}"))?;
        highwater
            .observe_signed_record(
                &verified.record_bytes,
                &verified.record,
                verified.rotation_wire.as_deref(),
            )
            .map_err(|error| format!("peer identity generation rejected: {error:?}"))?;
        // Persist the signed lifecycle transition first; only then refuse a retired/revoked or
        // currently invalid identity. This makes a signed same-generation revocation terminal.
        if verified.record.state != ai_native_l1_pow_bench::identity_policy::KeyState::Active {
            return Err("signed peer identity is not active".into());
        }
        if !verified.time_valid_at_epoch {
            return Err("signed peer identity is outside its validity window".into());
        }
        trusted.push(verified.noise_public_key);
    }
    let mut sorted = trusted.clone();
    sorted.sort_unstable();
    sorted.dedup();
    if sorted.len() != trusted.len() {
        return Err("signed peer identity files resolve to duplicate Noise public keys".into());
    }
    Ok(trusted)
}

/// Shares a serialized, fail-closed trust refresh across all inbound and outbound connection
/// attempts. Signed files are re-read and fully verified at each new connection boundary; this
/// does not tear down a Noise connection whose handshake was already accepted.
#[derive(Clone)]
struct SignedPeerTrustReloader {
    config: Arc<Config>,
    runtime_profile: NodeRuntimeProfile,
    reload_lock: Arc<Mutex<()>>,
}

impl SignedPeerTrustReloader {
    fn from_config(
        config: &Config,
        runtime_profile: NodeRuntimeProfile,
    ) -> Result<Option<Self>, String> {
        if config.trusted_peer_identity_files.is_empty() {
            return Ok(None);
        }
        if runtime_profile != NodeRuntimeProfile::ZeroValueDevnet {
            return Err("signed peer identities are accepted only by devnet_node".into());
        }
        Ok(Some(Self {
            config: Arc::new(config.clone()),
            runtime_profile,
            reload_lock: Arc::new(Mutex::new(())),
        }))
    }

    fn resolve(&self) -> Result<Vec<[u8; 32]>, String> {
        let _guard = self
            .reload_lock
            .lock()
            .map_err(|_| "signed peer trust reload lock is poisoned".to_string())?;
        // Reuses the exact existing DPC1 -> GRC1 -> IRG1 -> NPI1 verification and monotonic
        // persistence path. Never fall back to the last cached pins if a refresh fails.
        resolve_trusted_peer_keys(&self.config, self.runtime_profile)
    }
}

fn accept_noise_session(
    stream: &mut TcpStream,
    config: &NoiseInboundConfig,
) -> Result<DevnetNoiseSession, String> {
    let trusted_peer_public_keys = config.current_trusted_peer_public_keys()?;
    DevnetNoiseSession::accept(
        stream,
        &config.local_static_private_key.0,
        &trusted_peer_public_keys,
        &config.network_id,
    )
    .map_err(|error| format!("Noise peer authentication failed: {error}"))
}

struct SocketReadJob {
    stream: TcpStream,
    peer: SocketAddr,
    deadline: Instant,
}

struct SocketReadCompletion {
    stream: TcpStream,
    peer: SocketAddr,
    payload: io::Result<Vec<u8>>,
    noise_session: Option<DevnetNoiseSession>,
    noise_required: bool,
}

struct SocketReadQueueState {
    jobs: VecDeque<SocketReadJob>,
    closed: bool,
}

struct SocketReadQueue {
    capacity: usize,
    state: Mutex<SocketReadQueueState>,
    ready: Condvar,
}

impl SocketReadQueue {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            state: Mutex::new(SocketReadQueueState {
                jobs: VecDeque::with_capacity(capacity),
                closed: false,
            }),
            ready: Condvar::new(),
        }
    }

    fn try_push(&self, job: SocketReadJob) -> Result<(), SocketReadJob> {
        let Ok(mut state) = self.state.lock() else {
            return Err(job);
        };
        if state.closed || state.jobs.len() >= self.capacity {
            return Err(job);
        }
        state.jobs.push_back(job);
        self.ready.notify_one();
        Ok(())
    }

    fn take(&self) -> Option<SocketReadJob> {
        let mut state = self.state.lock().ok()?;
        loop {
            if state.closed {
                return None;
            }
            if let Some(job) = state.jobs.pop_front() {
                return Some(job);
            }
            state = self.ready.wait(state).ok()?;
        }
    }

    fn close(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.closed = true;
            // Pending sockets are closed immediately during shutdown rather
            // than extending the node's process lifetime.
            state.jobs.clear();
        }
        self.ready.notify_all();
    }
}

/// A fixed-size socket-reader pool for the disposable loopback node.
///
/// The queue stores only accepted sockets. Each worker reads one frame at a
/// time and hands the completed stream/payload to the main event loop over a
/// rendezvous channel. That channel intentionally has zero buffered entries:
/// the canonical fork store and ACK path remain owned by the single main
/// thread. The accepted-at deadline includes time spent waiting in the queue.
struct SocketReaderPool {
    queue: Arc<SocketReadQueue>,
    completion_rx: Option<Receiver<SocketReadCompletion>>,
    workers: Vec<JoinHandle<()>>,
}

impl SocketReaderPool {
    fn start(
        worker_count: usize,
        queue_capacity: usize,
        noise_config: Option<NoiseInboundConfig>,
    ) -> io::Result<Self> {
        if worker_count == 0 || queue_capacity == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "socket reader worker and queue limits must be nonzero",
            ));
        }

        let queue = Arc::new(SocketReadQueue::new(queue_capacity));
        let (completion_tx, completion_rx) = mpsc::sync_channel::<SocketReadCompletion>(0);
        let mut workers = Vec::with_capacity(worker_count);

        for worker_index in 0..worker_count {
            let worker_queue = Arc::clone(&queue);
            let worker_tx = completion_tx.clone();
            let worker_noise_config = noise_config.clone();
            let spawn_result = thread::Builder::new()
                .name(format!("pt-reader-{worker_index}"))
                .spawn(move || {
                    while let Some(mut job) = worker_queue.take() {
                        let (payload, noise_session, noise_required) = match worker_noise_config
                            .as_ref()
                        {
                            Some(config) => match accept_noise_session(&mut job.stream, config) {
                                Ok(mut session) => {
                                    let payload =
                                        session.read_record(&mut job.stream).map_err(|error| {
                                            io::Error::new(
                                                io::ErrorKind::InvalidData,
                                                error.to_string(),
                                            )
                                        });
                                    (payload, Some(session), true)
                                }
                                Err(error) => (
                                    Err(io::Error::new(io::ErrorKind::PermissionDenied, error)),
                                    None,
                                    true,
                                ),
                            },
                            None => (read_payload(&mut job.stream, job.deadline), None, false),
                        };
                        let completion = SocketReadCompletion {
                            stream: job.stream,
                            peer: job.peer,
                            payload,
                            noise_session,
                            noise_required,
                        };
                        if worker_tx.send(completion).is_err() {
                            break;
                        }
                    }
                });

            match spawn_result {
                Ok(worker) => workers.push(worker),
                Err(error) => {
                    // Break any rendezvous send and join already-started workers.
                    drop(completion_rx);
                    drop(completion_tx);
                    queue.close();
                    for worker in workers {
                        let _ = worker.join();
                    }
                    return Err(error);
                }
            }
        }
        drop(completion_tx);

        Ok(Self {
            queue,
            completion_rx: Some(completion_rx),
            workers,
        })
    }

    fn try_enqueue(&self, stream: TcpStream, peer: SocketAddr) -> Result<(), TcpStream> {
        let job = SocketReadJob {
            stream,
            peer,
            deadline: Instant::now() + WIRE_READ_TIMEOUT,
        };
        match self.queue.try_push(job) {
            Ok(()) => Ok(()),
            Err(job) => Err(job.stream),
        }
    }

    fn recv_timeout(&self, timeout: Duration) -> Result<SocketReadCompletion, RecvTimeoutError> {
        match self.completion_rx.as_ref() {
            Some(receiver) => receiver.recv_timeout(timeout),
            None => Err(RecvTimeoutError::Disconnected),
        }
    }

    fn shutdown(&mut self) {
        // Dropping the rendezvous receiver unblocks workers publishing results.
        self.completion_rx.take();
        self.queue.close();
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

impl Drop for SocketReaderPool {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn read_payload(stream: &mut TcpStream, deadline: Instant) -> io::Result<Vec<u8>> {
    stream.set_write_timeout(Some(WIRE_READ_TIMEOUT))?;
    // The absolute budget begins at accept, including any bounded-queue wait.
    let mut length_bytes = [0u8; 4];
    read_exact_before_deadline(stream, &mut length_bytes, deadline)?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    if length < 196 || length > MAX_PRIVATE_TESTNET_ENVELOPE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "candidate envelope length outside allowed bounds",
        ));
    }
    let mut payload = vec![0u8; length];
    read_exact_before_deadline(stream, &mut payload, deadline)?;
    Ok(payload)
}
#[derive(Debug)]
enum ImportFailure {
    UnknownParent,
    Rejected(String),
}

impl std::fmt::Display for ImportFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownParent => {
                formatter.write_str("candidate references an unknown consensus parent")
            }
            Self::Rejected(reason) => formatter.write_str(reason),
        }
    }
}

fn import_payload(
    payload: &[u8],
    store: &mut PrivateTestnetForkStore,
    params: &ConsensusParameters,
    auth: &NodeAuthenticator,
    clock: &SystemClockReferenceTime,
) -> Result<(u8, u64, [u8; 32]), ImportFailure> {
    let candidate = decode_candidate_network_block(payload)
        .map_err(|error| ImportFailure::Rejected(format!("decode candidate envelope: {error}")))?;
    let height = candidate.header.height;
    let digest = pow_digest(&candidate.header, params.pow)
        .map_err(|error| ImportFailure::Rejected(format!("calculate candidate digest: {error}")))?;

    // A malformed height/genesis relationship is permanent; only a non-genesis,
    // not-yet-known parent is eligible for bounded retry.
    let parent_tip = candidate.header.previous_consensus_hash;
    let genesis_tip = store.archive().genesis_tip();
    if (height == 1 && parent_tip != genesis_tip) || (height != 1 && parent_tip == genesis_tip) {
        return Err(ImportFailure::Rejected(
            "candidate height does not match genesis parent relationship".into(),
        ));
    }

    let duplicate = store.archive().branch_chain(&digest).is_some();
    let outcome = match store.submit(payload, auth, clock) {
        Ok(outcome) => outcome,
        Err(ForkStoreError::Fork(ForkChoiceError::UnknownParent)) => {
            return Err(ImportFailure::UnknownParent);
        }
        Err(error) => {
            return Err(ImportFailure::Rejected(format!(
                "durable fork store rejected candidate: {error}"
            )));
        }
    };
    if outcome.block_digest != digest {
        return Err(ImportFailure::Rejected(
            "durable fork store returned a different candidate digest".into(),
        ));
    }
    Ok((
        if duplicate {
            ACK_STATUS_DUPLICATE
        } else {
            ACK_STATUS_ACCEPTED
        },
        height,
        digest,
    ))
}

fn import_monetary_payload(
    payload: &[u8],
    store: &mut PrivateTestnetMonetaryForkStore,
    params: &ConsensusParameters,
    auth: &NodeAuthenticator,
    clock: &SystemClockReferenceTime,
) -> Result<(u8, MonetaryForkChoiceOutcome), ImportFailure> {
    let candidate = decode_candidate_monetary_network_block(payload).map_err(|error| {
        ImportFailure::Rejected(format!("decode PMT3 monetary candidate: {error}"))
    })?;
    let canonical = store.archive().canonical_chain();
    let monetary = canonical.monetary_state().ok_or_else(|| {
        ImportFailure::Rejected("PFM3 store exposed a non-monetary canonical chain".into())
    })?;
    if candidate.header.network_id != monetary.ledger().network_id() {
        return Err(ImportFailure::Rejected(
            "PMT3 candidate Network ID does not match the PFM3 Genesis".into(),
        ));
    }
    if candidate.header.protocol_version != params.protocol_version {
        return Err(ImportFailure::Rejected(
            "PMT3 candidate protocol version does not match the frozen profile".into(),
        ));
    }
    let height = candidate.header.height;
    if height == 0 {
        return Err(ImportFailure::Rejected(
            "PMT3 candidate height cannot be zero".into(),
        ));
    }
    let digest = pow_digest(&candidate.header, params.pow).map_err(|error| {
        ImportFailure::Rejected(format!("calculate PMT3 candidate digest: {error}"))
    })?;
    let parent_tip = candidate.header.previous_consensus_hash;
    let genesis_tip = store.archive().genesis_tip();
    if (height == 1 && parent_tip != genesis_tip) || (height != 1 && parent_tip == genesis_tip) {
        return Err(ImportFailure::Rejected(
            "PMT3 candidate height does not match the Genesis-parent relationship".into(),
        ));
    }
    let duplicate = store.archive().branch_chain(&digest).is_some();
    let outcome = match store.submit(payload, auth, clock) {
        Ok(outcome) => outcome,
        Err(MonetaryForkStoreError::Fork(
            ai_native_l1_pow_bench::private_testnet_monetary_fork_choice::MonetaryForkChoiceError::UnknownParent,
        )) => return Err(ImportFailure::UnknownParent),
        Err(error) => {
            return Err(ImportFailure::Rejected(format!(
                "durable PFM3 store rejected PMT3 candidate: {error}"
            )));
        }
    };
    if outcome.block_digest != digest {
        return Err(ImportFailure::Rejected(
            "PFM3 returned a different candidate digest".into(),
        ));
    }
    Ok((
        if duplicate {
            ACK_STATUS_DUPLICATE
        } else {
            ACK_STATUS_ACCEPTED
        },
        outcome,
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MonetaryAckV3 {
    status: u8,
    candidate_height: u64,
    candidate_digest: [u8; 32],
    canonical_height: u64,
    state_root: [u8; 32],
    consensus_tip: [u8; 32],
}

fn encode_monetary_ack_v3(
    status: u8,
    candidate_height: u64,
    candidate_digest: [u8; 32],
    canonical: &PrivateTestnetChain,
) -> Result<[u8; MONETARY_ACK_LEN], String> {
    if status > ACK_STATUS_UNKNOWN_PARENT {
        return Err("MTA3 ACK status is unknown".into());
    }
    let monetary = canonical
        .monetary_state()
        .ok_or_else(|| "MTA3 ACK refused for a legacy PTB2 chain".to_string())?;
    let mut bytes = [0u8; MONETARY_ACK_LEN];
    bytes[..4].copy_from_slice(MONETARY_ACK_MAGIC);
    bytes[4] = status;
    bytes[5..13].copy_from_slice(&candidate_height.to_be_bytes());
    bytes[13..45].copy_from_slice(&candidate_digest);
    bytes[45..53].copy_from_slice(&monetary.height().to_be_bytes());
    bytes[53..85].copy_from_slice(&monetary.state_root());
    bytes[85..117].copy_from_slice(&canonical.chain_tip().tip_hash);
    Ok(bytes)
}

fn decode_monetary_ack_v3(bytes: &[u8]) -> Result<MonetaryAckV3, String> {
    if bytes.len() != MONETARY_ACK_LEN || bytes.get(..4) != Some(MONETARY_ACK_MAGIC.as_slice()) {
        return Err("MTA3 ACK has an invalid magic or length".into());
    }
    let status = bytes[4];
    if status > ACK_STATUS_UNKNOWN_PARENT {
        return Err("MTA3 ACK status is unknown".into());
    }
    Ok(MonetaryAckV3 {
        status,
        candidate_height: u64::from_be_bytes(bytes[5..13].try_into().unwrap()),
        candidate_digest: bytes[13..45].try_into().unwrap(),
        canonical_height: u64::from_be_bytes(bytes[45..53].try_into().unwrap()),
        state_root: bytes[53..85].try_into().unwrap(),
        consensus_tip: bytes[85..117].try_into().unwrap(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MonetaryAckV4 {
    status: u8,
    candidate_height: u64,
    candidate_digest: [u8; 32],
    canonical_height: u64,
    state_root: [u8; 32],
    consensus_tip: [u8; 32],
    network_id: [u8; 32],
    manifest_id: [u8; 32],
    protocol_version: u16,
}

fn encode_monetary_ack_v4(
    status: u8,
    candidate_height: u64,
    candidate_digest: [u8; 32],
    canonical: &PrivateTestnetChain,
    network_id: [u8; 32],
    manifest_id: [u8; 32],
    protocol_version: u16,
) -> Result<[u8; MONETARY_ACK_V4_LEN], String> {
    if status > ACK_STATUS_UNKNOWN_PARENT {
        return Err("MTA4 ACK status is unknown".into());
    }
    let monetary = canonical
        .monetary_state()
        .ok_or_else(|| "MTA4 ACK refused for a legacy PTB2 chain".to_string())?;
    if monetary.ledger().network_id() != network_id {
        return Err("MTA4 ACK Network ID does not match the canonical V4 state".into());
    }

    let mut bytes = [0u8; MONETARY_ACK_V4_LEN];
    bytes[..4].copy_from_slice(MONETARY_ACK_V4_MAGIC);
    bytes[4] = status;
    bytes[5..13].copy_from_slice(&candidate_height.to_be_bytes());
    bytes[13..45].copy_from_slice(&candidate_digest);
    bytes[45..53].copy_from_slice(&monetary.height().to_be_bytes());
    bytes[53..85].copy_from_slice(&monetary.state_root());
    bytes[85..117].copy_from_slice(&canonical.chain_tip().tip_hash);
    bytes[117..149].copy_from_slice(&network_id);
    bytes[149..181].copy_from_slice(&manifest_id);
    bytes[181..183].copy_from_slice(&protocol_version.to_be_bytes());
    Ok(bytes)
}

fn decode_monetary_ack_v4(bytes: &[u8]) -> Result<MonetaryAckV4, String> {
    if bytes.len() != MONETARY_ACK_V4_LEN
        || bytes.get(..4) != Some(MONETARY_ACK_V4_MAGIC.as_slice())
    {
        return Err("MTA4 ACK has an invalid magic or length".into());
    }
    let status = bytes[4];
    if status > ACK_STATUS_UNKNOWN_PARENT {
        return Err("MTA4 ACK status is unknown".into());
    }
    Ok(MonetaryAckV4 {
        status,
        candidate_height: u64::from_be_bytes(bytes[5..13].try_into().unwrap()),
        candidate_digest: bytes[13..45].try_into().unwrap(),
        canonical_height: u64::from_be_bytes(bytes[45..53].try_into().unwrap()),
        state_root: bytes[53..85].try_into().unwrap(),
        consensus_tip: bytes[85..117].try_into().unwrap(),
        network_id: bytes[117..149].try_into().unwrap(),
        manifest_id: bytes[149..181].try_into().unwrap(),
        protocol_version: u16::from_be_bytes(bytes[181..183].try_into().unwrap()),
    })
}

fn monetary_ack_v4_matches_profile(
    ack: &MonetaryAckV4,
    network_id: &[u8; 32],
    manifest_id: &[u8; 32],
    protocol_version: u16,
) -> bool {
    ack.network_id == *network_id
        && ack.manifest_id == *manifest_id
        && ack.protocol_version == protocol_version
}

fn write_peer_ack(
    stream: &mut TcpStream,
    noise_session: &mut Option<DevnetNoiseSession>,
    ack: &[u8; ACK_LEN],
) -> io::Result<()> {
    match noise_session {
        Some(session) => session.write_record(stream, ack).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Noise ACK encryption failed: {error}"),
            )
        }),
        None => stream.write_all(ack).and_then(|_| stream.flush()),
    }
}

fn serve_completed_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    payload_result: io::Result<Vec<u8>>,
    mut noise_session: Option<DevnetNoiseSession>,
    noise_required: bool,
    store: &mut PrivateTestnetForkStore,
    params: &ConsensusParameters,
    auth: &NodeAuthenticator,
    clock: &SystemClockReferenceTime,
    archive_range_server: Option<&ArchiveRangeServerCandidate>,
    local_noise_private_key: Option<&[u8; 32]>,
    network_id: &[u8; 32],
) {
    let peer = peer_addr.to_string();
    let payload = match payload_result {
        Ok(payload) => payload,
        Err(error) => {
            eprintln!(
                "event=private_testnet_peer_rejected peer={peer} reason={}",
                sanitize(&error.to_string())
            );
            if noise_required {
                // No plaintext ACK is ever emitted after a failed/malformed Noise handshake or record.
                return;
            }
            let ack = ack_bytes(
                ACK_STATUS_REJECTED,
                0,
                [0; 32],
                store.archive().canonical_chain(),
            );
            let _ = stream.write_all(&ack);
            let _ = stream.flush();
            return;
        }
    };
    if noise_required && payload.get(..4) == Some(ARCHIVE_RANGE_REQUEST_MAGIC.as_slice()) {
        let (Some(server), Some(local_key), Some(session)) = (
            archive_range_server,
            local_noise_private_key,
            noise_session.as_mut(),
        ) else {
            eprintln!("event=devnet_archive_range_request_rejected peer={peer} reason=archive_range_service_unavailable");
            return;
        };
        if let Err(error) = serve_archive_range_request(
            &mut stream,
            &payload,
            session,
            server,
            local_key,
            network_id,
        ) {
            eprintln!(
                "event=devnet_archive_range_request_rejected peer={peer} snapshot={} reason={}",
                hex(&server.snapshot_commitment()),
                sanitize(&error)
            );
        }
        return;
    }
    match import_payload(&payload, store, params, auth, clock) {
        Ok((status, height, digest)) => {
            let canonical = store.archive().canonical_chain();
            let ack = ack_bytes(status, height, digest, canonical);
            let _ = write_peer_ack(&mut stream, &mut noise_session, &ack);
            let event = if status == ACK_STATUS_DUPLICATE {
                "duplicate"
            } else {
                "imported"
            };
            eprintln!(
                "event=private_testnet_{event} peer={peer} height={height} candidate_height={height} candidate_digest={} canonical_height={} state_root={} consensus_tip={}",
                hex(&digest), canonical.state().height(), hex(&canonical.state().state_root()), hex(&canonical.chain_tip().tip_hash)
            );
        }
        Err(ImportFailure::UnknownParent) => {
            eprintln!(
                "event=private_testnet_peer_rejected peer={peer} reason=unknown_parent retryable=true"
            );
            let ack = ack_bytes(
                ACK_STATUS_UNKNOWN_PARENT,
                0,
                [0; 32],
                store.archive().canonical_chain(),
            );
            let _ = write_peer_ack(&mut stream, &mut noise_session, &ack);
        }
        Err(ImportFailure::Rejected(reason)) => {
            eprintln!(
                "event=private_testnet_peer_rejected peer={peer} reason={}",
                sanitize(&reason)
            );
            let ack = ack_bytes(
                ACK_STATUS_REJECTED,
                0,
                [0; 32],
                store.archive().canonical_chain(),
            );
            let _ = write_peer_ack(&mut stream, &mut noise_session, &ack);
        }
    }
}
fn send_to_peer_for_profile(
    peer: SocketAddr,
    payload: &[u8],
    expected_height: u64,
    expected_digest: [u8; 32],
    runtime_profile: NodeRuntimeProfile,
    noise: Option<&NoiseOutboundConfig>,
) -> Result<(), String> {
    send_to_peer_for_profile_with_attempts(
        peer,
        payload,
        expected_height,
        expected_digest,
        runtime_profile,
        noise,
        PEER_SEND_MAX_ATTEMPTS,
    )
}

fn send_to_peer_for_profile_with_attempts(
    peer: SocketAddr,
    payload: &[u8],
    expected_height: u64,
    expected_digest: [u8; 32],
    runtime_profile: NodeRuntimeProfile,
    noise: Option<&NoiseOutboundConfig>,
    max_attempts: usize,
) -> Result<(), String> {
    if runtime_profile == NodeRuntimeProfile::PrivateSmoke {
        return send_to_peer_with_attempts(
            peer,
            payload,
            expected_height,
            expected_digest,
            max_attempts,
        );
    }
    let noise = noise
        .ok_or_else(|| "devnet peer send refused: Noise keys/pins not configured".to_string())?;
    send_to_peer_with_noise_attempts(
        peer,
        payload,
        expected_height,
        expected_digest,
        max_attempts,
        noise,
    )
}

fn send_to_peer(
    peer: SocketAddr,
    payload: &[u8],
    expected_height: u64,
    expected_digest: [u8; 32],
) -> Result<(), String> {
    send_to_peer_with_attempts(
        peer,
        payload,
        expected_height,
        expected_digest,
        PEER_SEND_MAX_ATTEMPTS,
    )
}

fn send_to_peer_with_attempts(
    peer: SocketAddr,
    payload: &[u8],
    expected_height: u64,
    expected_digest: [u8; 32],
    max_attempts: usize,
) -> Result<(), String> {
    if max_attempts == 0 {
        return Err("peer send attempt limit must be nonzero".into());
    }
    let mut last_error = String::from("peer unreachable");
    for attempt in 0..max_attempts {
        match TcpStream::connect_timeout(&peer, Duration::from_millis(500)) {
            Ok(mut stream) => {
                stream
                    .set_read_timeout(Some(WIRE_READ_TIMEOUT))
                    .map_err(|e| e.to_string())?;
                stream
                    .set_write_timeout(Some(WIRE_READ_TIMEOUT))
                    .map_err(|e| e.to_string())?;
                let length = u32::try_from(payload.len()).map_err(|_| "envelope too large")?;
                if let Err(error) = stream
                    .write_all(&length.to_be_bytes())
                    .and_then(|_| stream.write_all(payload))
                    .and_then(|_| stream.flush())
                {
                    last_error = format!("write peer frame: {error}");
                } else {
                    let mut ack = [0u8; ACK_LEN];
                    match stream.read_exact(&mut ack) {
                        Ok(()) => {
                            if &ack[..4] != ACK_MAGIC {
                                return Err(format!(
                                    "peer {peer} returned malformed acknowledgement"
                                ));
                            }
                            let status = ack[4];
                            let height = u64::from_be_bytes(ack[5..13].try_into().unwrap());
                            let digest: [u8; 32] = ack[13..45].try_into().unwrap();
                            if status == ACK_STATUS_UNKNOWN_PARENT {
                                // Only a typed unknown-parent ACK is retryable. Permanent rejection
                                // must not amplify CPU/network work through repeated submissions.
                                last_error = format!(
                                    "peer {peer} has not imported the parent for candidate height {expected_height}"
                                );
                                eprintln!(
                                    "event=private_testnet_peer_retry peer={peer} height={expected_height} attempt={} reason=unknown_parent",
                                    attempt + 1
                                );
                            } else if status >= ACK_STATUS_REJECTED {
                                return Err(format!(
                                    "peer {peer} permanently rejected candidate height {expected_height} with status {status}"
                                ));
                            } else {
                                if height != expected_height || digest != expected_digest {
                                    return Err(format!(
                                        "peer {peer} ACK does not bind the submitted candidate"
                                    ));
                                }
                                // ACK v2 acceptance does not imply the candidate is already canonical.
                                return Ok(());
                            }
                        }
                        Err(error) => last_error = format!("read peer acknowledgement: {error}"),
                    }
                }
            }
            Err(error) => last_error = format!("connect {peer}: {error}"),
        }
        if attempt + 1 < max_attempts {
            thread::sleep(PEER_SEND_RETRY_DELAY);
        }
    }
    Err(last_error)
}

fn send_to_peer_with_noise_attempts(
    peer: SocketAddr,
    payload: &[u8],
    expected_height: u64,
    expected_digest: [u8; 32],
    max_attempts: usize,
    noise: &NoiseOutboundConfig,
) -> Result<(), String> {
    if max_attempts == 0 {
        return Err("peer send attempt limit must be nonzero".into());
    }
    let mut last_error = String::from("peer unreachable");
    for attempt in 0..max_attempts {
        // Refresh signed trust before every dial, including retries. A stale or revoked identity
        // fails closed; it is never replaced with the startup pin as a fallback.
        let remote_pin = noise.trusted_pin(peer)?;
        match TcpStream::connect_timeout(&peer, Duration::from_millis(500)) {
            Ok(mut stream) => {
                if let Err(error) = stream
                    .set_nodelay(true)
                    .and_then(|_| stream.set_read_timeout(Some(WIRE_READ_TIMEOUT)))
                    .and_then(|_| stream.set_write_timeout(Some(WIRE_READ_TIMEOUT)))
                {
                    last_error = format!("configure Noise peer socket: {error}");
                } else {
                    match DevnetNoiseSession::connect(
                        &mut stream,
                        &noise.local_static_private_key.0,
                        &remote_pin,
                        &noise.network_id,
                    ) {
                        Err(error) => {
                            last_error = format!("Noise peer authentication failed: {error}")
                        }
                        Ok(mut session) => match session.write_record(&mut stream, payload) {
                            Err(error) => {
                                last_error = format!("Noise peer block write failed: {error}")
                            }
                            Ok(()) => match session.read_record(&mut stream) {
                                Err(error) => {
                                    last_error = format!("Noise peer ACK read failed: {error}")
                                }
                                Ok(wire) if wire.len() != ACK_LEN => {
                                    return Err(format!("peer {peer} returned malformed encrypted acknowledgement length {}", wire.len()));
                                }
                                Ok(wire) => {
                                    let ack: [u8; ACK_LEN] =
                                        wire.as_slice().try_into().expect("ACK length checked");
                                    if &ack[..4] != ACK_MAGIC {
                                        return Err(format!(
                                            "peer {peer} returned malformed acknowledgement"
                                        ));
                                    }
                                    let status = ack[4];
                                    let height = u64::from_be_bytes(ack[5..13].try_into().unwrap());
                                    let digest: [u8; 32] = ack[13..45].try_into().unwrap();
                                    if status == ACK_STATUS_UNKNOWN_PARENT {
                                        last_error = format!("peer {peer} has not imported the parent for candidate height {expected_height}");
                                        eprintln!("event=devnet_peer_retry peer={peer} height={expected_height} attempt={} reason=unknown_parent", attempt + 1);
                                    } else if status >= ACK_STATUS_REJECTED {
                                        return Err(format!("peer {peer} permanently rejected candidate height {expected_height} with status {status}"));
                                    } else if height != expected_height || digest != expected_digest
                                    {
                                        return Err(format!("peer {peer} encrypted ACK does not bind the submitted candidate"));
                                    } else {
                                        return Ok(());
                                    }
                                }
                            },
                        },
                    }
                }
            }
            Err(error) => last_error = format!("connect {peer}: {error}"),
        }
        if attempt + 1 < max_attempts {
            thread::sleep(PEER_SEND_RETRY_DELAY);
        }
    }
    Err(last_error)
}

fn archive_sync_error_is_retryable(error: &str) -> bool {
    error.starts_with("connect ")
        || error.starts_with("write peer frame:")
        || error.starts_with("read peer acknowledgement:")
        || error.starts_with("Noise peer block write failed:")
        || error.starts_with("Noise peer ACK read failed:")
        || error.contains("has not imported the parent")
}
fn build_next_candidate(
    chain: &PrivateTestnetChain,
    params: &ConsensusParameters,
    auth: &NodeAuthenticator,
    test_signer: Option<&Ed25519TransactionSigner>,
    test_tx_amount: u64,
    timestamp_offset: u64,
    timestamp_backdate: u64,
) -> Result<CandidateNetworkBlock, String> {
    let state = chain.state();
    let wall_clock = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock predates Unix epoch")?
        .as_secs();
    let timestamp = wall_clock
        .saturating_add(timestamp_offset)
        .saturating_sub(timestamp_backdate)
        .max(state.last_timestamp().saturating_add(1));
    let mut transactions = Vec::new();
    if state.height() == 0 {
        if let Some(signer) = test_signer {
            let sender = signer.account_id();
            let account = state
                .account(&sender)
                .ok_or("test sender missing from test Genesis")?;
            let nonce = account
                .nonce
                .checked_add(1)
                .ok_or("test sender nonce overflow")?;
            let mut tx = Transaction {
                network_id: state.network_id(),
                sender,
                recipient: TEST_RECIPIENT,
                nonce,
                amount: test_tx_amount,
                fee: TEST_TX_FEE,
                expires_at: timestamp.saturating_add(3_600),
                signature: Vec::new(),
            };
            signer
                .sign_transaction(&mut tx)
                .map_err(|error| format!("sign disposable Ed25519 test transaction: {error:?}"))?;
            transactions.push(tx);
        }
    }
    let mut block = Block {
        height: state.height().saturating_add(1),
        timestamp,
        parent_hash: state.tip_hash(),
        state_root: [0; 32],
        transactions,
    };
    block.state_root = state
        .preview_state_root_after(&block, auth)
        .map_err(|error| format!("preview block state root: {error:?}"))?;
    let target = chain
        .expected_target(None)
        .map_err(|error| format!("derive target for next block: {error}"))?;

    for nonce in 0..u64::MAX {
        let header = PowHeader {
            protocol_version: params.protocol_version,
            network_id: state.network_id(),
            height: block.height,
            timestamp: block.timestamp,
            parent_hash: block.parent_hash,
            previous_consensus_hash: chain.chain_tip().tip_hash,
            state_root: block.state_root,
            target,
            nonce,
        };
        let digest = pow_digest(&header, params.pow)
            .map_err(|error| format!("calculate candidate PoW digest: {error}"))?;
        if Uint256::from_be_bytes(digest) <= target {
            return Ok(CandidateNetworkBlock { header, block });
        }
    }
    Err("nonce search exhausted".into())
}

fn handle_incoming_payload(
    payload: &[u8],
    store: &mut PrivateTestnetForkStore,
    params: &ConsensusParameters,
    auth: &NodeAuthenticator,
    clock: &SystemClockReferenceTime,
) -> Result<(u8, u64, [u8; 32]), String> {
    import_payload(payload, store, params, auth, clock).map_err(|error| error.to_string())
}

fn log_test_transaction_state(
    phase: &str,
    chain: &PrivateTestnetChain,
    signer: Option<&Ed25519TransactionSigner>,
) {
    let Some(signer) = signer else { return };
    let state = chain.state();
    let sender_id = signer.account_id();
    let sender = state.account(&sender_id);
    let recipient = state.account(&TEST_RECIPIENT);
    eprintln!(
        "event=private_testnet_test_tx_state phase={phase} height={} sender={} sender_balance={} sender_nonce={} recipient={} recipient_balance={} recipient_nonce={}",
        state.height(), hex(&sender_id), sender.map(|a| a.balance).unwrap_or(0), sender.map(|a| a.nonce).unwrap_or(0),
        hex(&TEST_RECIPIENT), recipient.map(|a| a.balance).unwrap_or(0), recipient.map(|a| a.nonce).unwrap_or(0),
    );
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

fn sanitize(message: &str) -> String {
    message
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || "-_.:".contains(ch) {
                ch
            } else {
                '_'
            }
        })
        .take(180)
        .collect()
}

fn ordered_archive_envelopes(
    store: &PrivateTestnetForkStore,
    params: &ConsensusParameters,
) -> Result<Vec<(Vec<u8>, u64, [u8; 32])>, String> {
    let mut ordered = Vec::new();
    let envelopes = store
        .archive()
        .archive_envelopes_bounded(MAX_ARCHIVE_SYNC_BRANCHES, MAX_ARCHIVE_SYNC_BYTES)
        .map_err(|error| format!("startup archive exceeds sync budget (max_branches={MAX_ARCHIVE_SYNC_BRANCHES}, max_bytes={MAX_ARCHIVE_SYNC_BYTES}): {error}"))?;
    for bytes in envelopes {
        let candidate = decode_candidate_network_block(&bytes)
            .map_err(|error| format!("decode archived PTB2 candidate: {error}"))?;
        let digest = pow_digest(&candidate.header, params.pow)
            .map_err(|error| format!("hash archived PTB2 candidate: {error}"))?;
        ordered.push((bytes, candidate.header.height, digest));
    }
    ordered.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.2.cmp(&b.2)));
    Ok(ordered)
}

fn ordered_monetary_archive_envelopes(
    store: &PrivateTestnetMonetaryForkStore,
    params: &ConsensusParameters,
) -> Result<Vec<(Vec<u8>, u64, [u8; 32])>, String> {
    let archive = store.archive();
    if archive.archive_len() > MAX_ARCHIVE_SYNC_BRANCHES {
        return Err(format!(
            "PFM3 snapshot exceeds archive sync branch limit ({}/{})",
            archive.archive_len(),
            MAX_ARCHIVE_SYNC_BRANCHES
        ));
    }

    let mut ordered = Vec::with_capacity(archive.archive_len());
    let mut total_bytes = 0usize;
    for payload in archive.archive_envelopes_iter() {
        total_bytes = total_bytes
            .checked_add(payload.len())
            .ok_or("PFM3 archive snapshot byte count overflow")?;
        if total_bytes > MAX_ARCHIVE_SYNC_BYTES {
            return Err(format!(
                "PFM3 snapshot exceeds archive sync byte limit ({total_bytes}/{MAX_ARCHIVE_SYNC_BYTES})"
            ));
        }
        let candidate = decode_candidate_monetary_network_block(payload)
            .map_err(|error| format!("decode archived PMT3 candidate: {error}"))?;
        let digest = pow_digest(&candidate.header, params.pow)
            .map_err(|error| format!("hash archived PMT3 candidate: {error}"))?;
        ordered.push((payload.to_vec(), candidate.header.height, digest));
    }
    ordered.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.2.cmp(&b.2)));
    Ok(ordered)
}

fn build_monetary_archive_range_server(
    store: &PrivateTestnetMonetaryForkStore,
    network_id: [u8; 32],
    params: &ConsensusParameters,
    max_page_items: usize,
) -> Result<Arc<ArchiveRangeServerCandidate>, String> {
    let generation = store.canonical_height();
    let archive = ordered_monetary_archive_envelopes(store, params)?;
    build_archive_range_server_for_profile(
        archive,
        network_id,
        "MONETARY_PFM3_PMT3_CANDIDATE_LOOPBACK_V1",
        generation,
        max_page_items,
    )
}

fn ordered_monetary_v4_archive_envelopes(
    store: &PrivateTestnetV4HybridForkStore,
    params: &ConsensusParameters,
) -> Result<Vec<(Vec<u8>, u64, [u8; 32])>, String> {
    let envelopes = store
        .archive()
        .archive_envelopes_bounded(MAX_ARCHIVE_SYNC_BRANCHES, MAX_ARCHIVE_SYNC_BYTES)
        .map_err(|error| format!("PFM4 archive exceeds bounded export budget: {error:?}"))?;
    let mut ordered = Vec::with_capacity(envelopes.len());
    for bytes in envelopes {
        let candidate = decode_candidate_v4_hybrid_monetary_network_block(&bytes)
            .map_err(|error| format!("decode archived PMT4 candidate: {error}"))?;
        let digest = pow_digest(&candidate.header, params.pow)
            .map_err(|error| format!("hash archived PMT4 candidate: {error}"))?;
        ordered.push((bytes, candidate.header.height, digest));
    }
    ordered.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.2.cmp(&b.2)));
    Ok(ordered)
}

fn build_monetary_v4_archive_range_server(
    store: &PrivateTestnetV4HybridForkStore,
    network_id: [u8; 32],
    manifest_id: &[u8; 32],
    params: &ConsensusParameters,
    max_page_items: usize,
) -> Result<Arc<ArchiveRangeServerCandidate>, String> {
    let generation = store.canonical_height();
    let archive = ordered_monetary_v4_archive_envelopes(store, params)?;
    let profile_label = format!(
        "{}_{}",
        MONETARY_V4_ARCHIVE_RANGE_PROFILE_DOMAIN,
        hex(manifest_id)
    );
    build_archive_range_server_for_profile(
        archive,
        network_id,
        &profile_label,
        generation,
        max_page_items,
    )
}

fn monetary_v4_archive_snapshot_is_current(
    store: &PrivateTestnetV4HybridForkStore,
    snapshot_manifest_anchor: &[u8; 32],
) -> Result<bool, String> {
    let current_anchor = store
        .manifest_anchor()
        .map_err(|error| format!("read PFM4 archive manifest anchor: {error:?}"))?;
    Ok(&current_anchor == snapshot_manifest_anchor)
}

const ARCHIVE_RANGE_REQUEST_MAGIC: &[u8; 4] = b"ARQ1";
const ARCHIVE_RANGE_PAGE_MAGIC: &[u8; 4] = b"ARW1";
const MONETARY_V4_ARCHIVE_RANGE_REQUEST_MAGIC: &[u8; 4] = b"ARQ4";
const MONETARY_V4_ARCHIVE_RANGE_PAGE_MAGIC: &[u8; 4] = b"ARW4";
const MONETARY_V4_ARCHIVE_RANGE_PROFILE_DOMAIN: &str = "AIN1_PMT4_PFM4_HYBRID_ARCHIVE_RANGE_V1";
const ARCHIVE_RANGE_SESSION_DOMAIN: &[u8] = b"AIN1_ARCHIVE_RANGE_SESSION_V1\0";
const ARCHIVE_RANGE_CURSOR_KEY_DOMAIN: &[u8] = b"AIN1_ARCHIVE_RANGE_CURSOR_KEY_V1\0";
const ARCHIVE_RANGE_PROFILE_DOMAIN: &[u8] = b"AIN1_ARCHIVE_RANGE_PROFILE_V1\0";
const ARCHIVE_RANGE_IMPORT_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
const ARCHIVE_RANGE_TOTAL_SYNC_TIMEOUT: Duration = Duration::from_secs(180);
const ARCHIVE_RANGE_REQUEST_ATTEMPTS: usize = 4;
const ARCHIVE_RANGE_SYNC_DIRECTORY: &str = "archive_range_sync";
const MONETARY_ARCHIVE_RANGE_SYNC_DIRECTORY: &str = "monetary_archive_range_sync";
const MONETARY_V4_ARCHIVE_RANGE_SYNC_DIRECTORY: &str = "monetary_v4_archive_range_sync";
type ArchiveCursorHmac = Hmac<Sha256>;

fn archive_range_limits() -> ArchiveSyncLimits {
    archive_range_limits_with_page_items(16)
}

fn archive_range_limits_with_page_items(max_page_items: usize) -> ArchiveSyncLimits {
    // The operator may reduce the item count for diagnostics, but cannot raise it above the
    // fixed planner/runtime ceiling. A page is encoded inside one bounded Noise record; keep
    // a 4 KiB metadata/framing reserve and respect the archive planner's hard ceilings.
    let bounded_page_items = max_page_items.clamp(1, 16) as u32;
    let transport_page_budget = MAX_PRIVATE_TESTNET_ENVELOPE_BYTES.saturating_sub(4096) as u64;
    let max_page_bytes = MAX_CANDIDATE_PAGE_BYTES.min(transport_page_budget);
    let max_envelope_bytes = MAX_CANDIDATE_ENVELOPE_BYTES.min(max_page_bytes);
    ArchiveSyncLimits {
        max_page_items: bounded_page_items,
        max_page_bytes,
        max_envelope_bytes,
        max_total_items: MAX_ARCHIVE_SYNC_BRANCHES as u64,
        max_total_bytes: MAX_ARCHIVE_SYNC_BYTES as u64,
        max_pages: 64,
    }
}

fn archive_range_budget() -> ArchiveRangeBudgetConfig {
    ArchiveRangeBudgetConfig {
        max_sessions: MAX_CONFIGURED_PEERS,
        per_session_max_pages: 128,
        per_session_max_items: MAX_ARCHIVE_SYNC_BRANCHES as u64 * 2,
        per_session_max_bytes: MAX_ARCHIVE_SYNC_BYTES as u64 * 2,
        global_max_pages: (MAX_CONFIGURED_PEERS * 128) as u64,
        global_max_items: (MAX_CONFIGURED_PEERS * MAX_ARCHIVE_SYNC_BRANCHES * 2) as u64,
        global_max_bytes: 512 * 1024 * 1024,
    }
}

fn build_archive_range_server(
    archive: Vec<(Vec<u8>, u64, [u8; 32])>,
    network_id: [u8; 32],
    runtime_profile: NodeRuntimeProfile,
    generation: u64,
    max_page_items: usize,
) -> Result<Arc<ArchiveRangeServerCandidate>, String> {
    build_archive_range_server_for_profile(
        archive,
        network_id,
        runtime_profile.name(),
        generation,
        max_page_items,
    )
}

fn build_archive_range_server_for_profile(
    archive: Vec<(Vec<u8>, u64, [u8; 32])>,
    network_id: [u8; 32],
    profile_label: &str,
    generation: u64,
    max_page_items: usize,
) -> Result<Arc<ArchiveRangeServerCandidate>, String> {
    let limits = archive_range_limits_with_page_items(max_page_items);
    let mut profile_hash = Sha256::new();
    profile_hash.update(ARCHIVE_RANGE_PROFILE_DOMAIN);
    profile_hash.update(network_id);
    profile_hash.update(profile_label.as_bytes());
    let profile_id: [u8; 32] = profile_hash.finalize().into();
    let metadata = archive
        .iter()
        .map(|(encoded, height, digest)| {
            Ok::<ArchiveEntryMeta, String>(ArchiveEntryMeta {
                height: *height,
                digest: *digest,
                encoded_len: u64::try_from(encoded.len())
                    .map_err(|_| "archive range payload length overflow")?,
                payload_sha256: Sha256::digest(encoded).into(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let index = ArchiveSyncIndex::new(network_id, profile_id, generation, metadata, limits)
        .map_err(|error| format!("build bounded archive range index: {error:?}"))?;
    let payloads = archive
        .into_iter()
        .map(|(encoded, height, digest)| {
            let metadata = ArchiveEntryMeta {
                height,
                digest,
                encoded_len: u64::try_from(encoded.len())
                    .map_err(|_| "archive range payload length overflow")?,
                payload_sha256: Sha256::digest(&encoded).into(),
            };
            ArchiveSyncPayload::new(metadata, encoded)
                .map_err(|error| format!("validate archive range source payload: {error:?}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    ArchiveRangeServerCandidate::new(index, payloads, limits, archive_range_budget())
        .map(Arc::new)
        .map_err(|error| format!("initialize bounded archive range server: {error:?}"))
}

fn archive_range_session_binding(
    remote_static_public_key: &[u8; 32],
    snapshot_commitment: &[u8; 32],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(ARCHIVE_RANGE_SESSION_DOMAIN);
    hash.update(remote_static_public_key);
    hash.update(snapshot_commitment);
    hash.finalize().into()
}

/// Use a short deterministic filename derived from both bindings. Keeping raw 64-character peer
/// and snapshot hex strings in the filename can exceed Windows MAX_PATH under a long Temp root.
fn archive_range_wal_filename(
    remote_static_public_key: &[u8; 32],
    snapshot_commitment: &[u8; 32],
) -> String {
    let mut hash = Sha256::new();
    hash.update(b"AIN1_ARCHIVE_RANGE_WAL_FILE_ID_V1\0");
    hash.update(remote_static_public_key);
    hash.update(snapshot_commitment);
    let file_id: [u8; 32] = hash.finalize().into();
    format!("{}.arw", hex(&file_id))
}

fn derive_archive_range_cursor_key(
    local_static_private_key: &[u8; 32],
    remote_static_public_key: &[u8; 32],
    network_id: &[u8; 32],
    snapshot_commitment: &[u8; 32],
) -> [u8; 32] {
    let mut mac = ArchiveCursorHmac::new_from_slice(local_static_private_key)
        .expect("HMAC accepts a 32-byte Noise static key");
    mac.update(ARCHIVE_RANGE_CURSOR_KEY_DOMAIN);
    mac.update(network_id);
    mac.update(remote_static_public_key);
    mac.update(snapshot_commitment);
    mac.finalize().into_bytes().into()
}

fn encode_archive_range_request(cursor: Option<&[u8; ARCHIVE_SYNC_CURSOR_BYTES]>) -> Vec<u8> {
    encode_archive_range_request_with_magic(cursor, ARCHIVE_RANGE_REQUEST_MAGIC)
}

fn encode_archive_range_request_with_magic(
    cursor: Option<&[u8; ARCHIVE_SYNC_CURSOR_BYTES]>,
    magic: &[u8; 4],
) -> Vec<u8> {
    let mut request = Vec::with_capacity(5 + cursor.map_or(0, |_| ARCHIVE_SYNC_CURSOR_BYTES));
    request.extend_from_slice(magic);
    match cursor {
        Some(cursor) => {
            request.push(1);
            request.extend_from_slice(cursor);
        }
        None => request.push(0),
    }
    request
}

fn decode_archive_range_request(
    request: &[u8],
) -> Result<Option<[u8; ARCHIVE_SYNC_CURSOR_BYTES]>, String> {
    decode_archive_range_request_with_magic(request, ARCHIVE_RANGE_REQUEST_MAGIC)
}

fn decode_archive_range_request_with_magic(
    request: &[u8],
    magic: &[u8; 4],
) -> Result<Option<[u8; ARCHIVE_SYNC_CURSOR_BYTES]>, String> {
    if request.len() < 5 || request.get(..4) != Some(magic.as_slice()) {
        return Err("archive range request magic or length is invalid".into());
    }
    match request[4] {
        0 if request.len() == 5 => Ok(None),
        1 if request.len() == 5 + ARCHIVE_SYNC_CURSOR_BYTES => {
            let mut cursor = [0; ARCHIVE_SYNC_CURSOR_BYTES];
            cursor.copy_from_slice(&request[5..]);
            Ok(Some(cursor))
        }
        _ => Err("archive range request cursor shape is invalid".into()),
    }
}

fn serve_archive_range_request(
    stream: &mut TcpStream,
    payload: &[u8],
    session: &mut DevnetNoiseSession,
    server: &ArchiveRangeServerCandidate,
    local_static_private_key: &[u8; 32],
    network_id: &[u8; 32],
) -> Result<(), String> {
    serve_archive_range_request_with_magic(
        stream,
        payload,
        session,
        server,
        local_static_private_key,
        network_id,
        ARCHIVE_RANGE_REQUEST_MAGIC,
        ARCHIVE_RANGE_PAGE_MAGIC,
    )
}

fn serve_archive_range_request_with_magic(
    stream: &mut TcpStream,
    payload: &[u8],
    session: &mut DevnetNoiseSession,
    server: &ArchiveRangeServerCandidate,
    local_static_private_key: &[u8; 32],
    network_id: &[u8; 32],
    request_magic: &[u8; 4],
    page_magic: &[u8; 4],
) -> Result<(), String> {
    let cursor = decode_archive_range_request_with_magic(payload, request_magic)?;
    let remote_static_public_key = *session.remote_static_public_key();
    let snapshot_commitment = server.snapshot_commitment();
    let session_binding =
        archive_range_session_binding(&remote_static_public_key, &snapshot_commitment);
    let cursor_key = derive_archive_range_cursor_key(
        local_static_private_key,
        &remote_static_public_key,
        network_id,
        &snapshot_commitment,
    );
    server
        .ensure_authenticated_session(session_binding, cursor_key)
        .map_err(|error| format!("archive range session rejected: {error:?}"))?;
    let page = match cursor {
        None => server.serve_first_page(session_binding),
        Some(cursor) => server.serve_next_page(session_binding, &cursor),
    }
    .map_err(|error| format!("archive range cursor rejected: {error:?}"))?;
    let mut encoded = encode_archive_range_page(&page, archive_range_limits())
        .map_err(|error| format!("encode bounded archive range page: {error}"))?;
    if encoded.get(..4) != Some(ARCHIVE_RANGE_PAGE_MAGIC.as_slice()) {
        return Err("archive range page encoder returned an unexpected version marker".into());
    }
    encoded[..4].copy_from_slice(page_magic);
    if encoded.len() > MAX_PRIVATE_TESTNET_ENVELOPE_BYTES
        || encoded.len() > MAX_STORED_ARCHIVE_PAGE_BYTES
    {
        return Err(format!(
            "archive range page exceeded transport/staging bound: {}",
            encoded.len()
        ));
    }
    session
        .write_record(stream, &encoded)
        .map_err(|error| format!("write encrypted archive range page: {error}"))?;
    eprintln!(
        "event=devnet_archive_range_page_served peer_identity={} page={} start={} end={} items={} bytes={} complete={}",
        hex(&remote_static_public_key),
        page.plan.page_number,
        page.plan.start_index,
        page.plan.end_index,
        page.entries.len(),
        page.plan.page_bytes,
        page.plan.complete
    );
    Ok(())
}

fn start_archive_sync_threads(
    peers: &[SocketAddr],
    archive: Arc<Vec<(Vec<u8>, u64, [u8; 32])>>,
    delay_ms: u64,
    reverse_first_round: bool,
    runtime_profile: NodeRuntimeProfile,
    noise_config: Option<NoiseOutboundConfig>,
) {
    if peers.is_empty() {
        return;
    }
    let branch_count = archive.len();
    let archive_bytes: usize = archive.iter().map(|(payload, _, _)| payload.len()).sum();
    eprintln!(
        "event=private_testnet_archive_sync_snapshot peers={} branches={} bytes={} snapshot_mode=shared_read_only",
        peers.len(), branch_count, archive_bytes
    );
    for peer in peers.iter().copied() {
        let branches = Arc::clone(&archive);
        let peer_noise = noise_config.clone();
        thread::spawn(move || {
            // Parent-first order is mandatory; retries restart the bounded batch so a
            // child rejected before its parent is imported can be retried idempotently.
            for round in 0..ARCHIVE_SYNC_MAX_ROUNDS {
                let mut transient_failure: Option<(u64, String)> = None;
                let mut permanent_failure: Option<(u64, String)> = None;
                let mut send_order: Vec<_> = branches.iter().collect();
                if reverse_first_round && round == 0 {
                    send_order.reverse();
                    eprintln!(
                        "event=private_testnet_archive_sync_fault peer={peer} fault=reverse_first_round branches={branch_count}"
                    );
                }
                for (payload, height, digest) in send_order {
                    match send_to_peer_for_profile_with_attempts(
                        peer,
                        payload,
                        *height,
                        *digest,
                        runtime_profile,
                        peer_noise.as_ref(),
                        1,
                    ) {
                        Ok(()) => {
                            eprintln!(
                                "event=private_testnet_archive_sync_item peer={peer} height={height} digest={} round={} status=acknowledged",
                                hex(digest), round + 1
                            );
                            if delay_ms > 0 {
                                thread::sleep(Duration::from_millis(delay_ms));
                            }
                        }
                        Err(error) if archive_sync_error_is_retryable(&error) => {
                            transient_failure = Some((*height, error));
                            break;
                        }
                        Err(error) => {
                            permanent_failure = Some((*height, error));
                            break;
                        }
                    }
                }

                if let Some((height, error)) = permanent_failure {
                    eprintln!(
                        "event=private_testnet_archive_sync_failed peer={peer} height={height} reason={}",
                        sanitize(&error)
                    );
                    return;
                }
                if let Some((height, error)) = transient_failure {
                    if round + 1 == ARCHIVE_SYNC_MAX_ROUNDS {
                        eprintln!(
                            "event=private_testnet_archive_sync_exhausted peer={peer} rounds={} height={height} reason={}",
                            ARCHIVE_SYNC_MAX_ROUNDS,
                            sanitize(&error)
                        );
                        return;
                    }
                    eprintln!(
                        "event=private_testnet_archive_sync_retry peer={peer} round={} next_round={} height={height} reason={}",
                        round + 1,
                        round + 2,
                        sanitize(&error)
                    );
                    thread::sleep(ARCHIVE_SYNC_RETRY_DELAY);
                    continue;
                }

                eprintln!(
                    "event=private_testnet_archive_sync_complete peer={peer} branches={branch_count} rounds={}",
                    round + 1
                );
                return;
            }
        });
    }
}

const MAX_ARCHIVE_RANGE_WAL_DIRECTORY_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ARCHIVE_RANGE_WAL_DIRECTORY_FILES: usize = 32;

struct ArchiveRangeImportBatch {
    peer: SocketAddr,
    entries: Vec<ArchiveSyncServedEntry>,
    response: mpsc::SyncSender<Result<(), String>>,
}

struct MonetaryArchiveRangeImportBatch {
    peer: SocketAddr,
    entries: Vec<ArchiveSyncServedEntry>,
    response: mpsc::SyncSender<Result<(), String>>,
}

struct MonetaryV4ArchiveRangeImportBatch {
    peer: SocketAddr,
    entries: Vec<ArchiveSyncServedEntry>,
    response: mpsc::SyncSender<Result<(), String>>,
}

fn ensure_archive_range_wal_budget(directory: &Path, target_path: &Path) -> Result<(), String> {
    let mut total_bytes = 0u64;
    let mut file_count = 0usize;
    for entry in fs::read_dir(directory)
        .map_err(|error| format!("read archive range staging directory: {error}"))?
    {
        let entry = entry.map_err(|error| format!("read archive range staging entry: {error}"))?;
        if !entry.file_name().to_string_lossy().ends_with(".arw") {
            continue;
        }
        let metadata = entry
            .metadata()
            .map_err(|error| format!("stat archive range staging file: {error}"))?;
        total_bytes = total_bytes
            .checked_add(metadata.len())
            .ok_or("archive range staging byte count overflow")?;
        file_count = file_count
            .checked_add(1)
            .ok_or("archive range staging file count overflow")?;
    }
    let target_exists = target_path.exists();
    let projected_files = file_count + usize::from(!target_exists);
    let projected_bytes = total_bytes
        .checked_add(if target_exists {
            0
        } else {
            MAX_ARCHIVE_SYNC_BYTES as u64
        })
        .ok_or("archive range staging budget overflow")?;
    if projected_files > MAX_ARCHIVE_RANGE_WAL_DIRECTORY_FILES
        || projected_bytes > MAX_ARCHIVE_RANGE_WAL_DIRECTORY_BYTES
    {
        return Err(format!("archive range staging budget exceeded (files={projected_files}, bytes={projected_bytes}); verify/import and archive old staging files before retry"));
    }
    Ok(())
}

fn decode_archive_range_page_with_magic(
    response: &[u8],
    page_magic: &[u8; 4],
) -> Result<
    ai_native_l1_pow_bench::private_testnet_archive_range_server_candidate::ArchiveSyncServedPage,
    String,
> {
    if response.get(..4) != Some(page_magic.as_slice()) {
        return Err("archive range response has wrong page-version magic".into());
    }
    if response.len() < 4 {
        return Err("archive range response is shorter than its version marker".into());
    }
    let mut canonical = response.to_vec();
    canonical[..4].copy_from_slice(ARCHIVE_RANGE_PAGE_MAGIC);
    decode_archive_range_page(&canonical, archive_range_limits())
        .map_err(|error| format!("decode authenticated archive range page: {error}"))
}

fn fetch_archive_range_page_once(
    peer: SocketAddr,
    noise: &NoiseOutboundConfig,
    cursor: Option<&[u8; ARCHIVE_SYNC_CURSOR_BYTES]>,
) -> Result<
    ai_native_l1_pow_bench::private_testnet_archive_range_server_candidate::ArchiveSyncServedPage,
    String,
> {
    fetch_archive_range_page_once_with_magic(
        peer,
        noise,
        cursor,
        ARCHIVE_RANGE_REQUEST_MAGIC,
        ARCHIVE_RANGE_PAGE_MAGIC,
    )
}

fn fetch_archive_range_page_once_with_magic(
    peer: SocketAddr,
    noise: &NoiseOutboundConfig,
    cursor: Option<&[u8; ARCHIVE_SYNC_CURSOR_BYTES]>,
    request_magic: &[u8; 4],
    page_magic: &[u8; 4],
) -> Result<
    ai_native_l1_pow_bench::private_testnet_archive_range_server_candidate::ArchiveSyncServedPage,
    String,
> {
    let remote_pin = noise.trusted_pin(peer)?;
    let mut stream = TcpStream::connect_timeout(&peer, Duration::from_millis(500))
        .map_err(|error| format!("archive range connect {peer}: {error}"))?;
    stream
        .set_nodelay(true)
        .and_then(|_| stream.set_read_timeout(Some(WIRE_READ_TIMEOUT)))
        .and_then(|_| stream.set_write_timeout(Some(WIRE_READ_TIMEOUT)))
        .map_err(|error| format!("configure archive range socket: {error}"))?;
    let mut session = DevnetNoiseSession::connect(
        &mut stream,
        &noise.local_static_private_key.0,
        &remote_pin,
        &noise.network_id,
    )
    .map_err(|error| format!("archive range Noise handshake failed: {error}"))?;
    let request = encode_archive_range_request_with_magic(cursor, request_magic);
    session
        .write_record(&mut stream, &request)
        .map_err(|error| format!("write encrypted archive range request: {error}"))?;
    let response = session
        .read_record(&mut stream)
        .map_err(|error| format!("read encrypted archive range page: {error}"))?;
    decode_archive_range_page_with_magic(&response, page_magic)
}

fn fetch_archive_range_page(
    peer: SocketAddr,
    noise: &NoiseOutboundConfig,
    cursor: Option<&[u8; ARCHIVE_SYNC_CURSOR_BYTES]>,
    sync_deadline: Instant,
) -> Result<
    ai_native_l1_pow_bench::private_testnet_archive_range_server_candidate::ArchiveSyncServedPage,
    String,
> {
    fetch_archive_range_page_with_magic(
        peer,
        noise,
        cursor,
        sync_deadline,
        ARCHIVE_RANGE_REQUEST_MAGIC,
        ARCHIVE_RANGE_PAGE_MAGIC,
    )
}

fn fetch_archive_range_page_with_magic(
    peer: SocketAddr,
    noise: &NoiseOutboundConfig,
    cursor: Option<&[u8; ARCHIVE_SYNC_CURSOR_BYTES]>,
    sync_deadline: Instant,
    request_magic: &[u8; 4],
    page_magic: &[u8; 4],
) -> Result<
    ai_native_l1_pow_bench::private_testnet_archive_range_server_candidate::ArchiveSyncServedPage,
    String,
> {
    let mut last_error = "archive range peer unreachable".to_string();
    for attempt in 0..ARCHIVE_RANGE_REQUEST_ATTEMPTS {
        if Instant::now() >= sync_deadline {
            return Err("archive range sync exceeded its absolute total deadline".into());
        }
        match fetch_archive_range_page_once_with_magic(
            peer,
            noise,
            cursor,
            request_magic,
            page_magic,
        ) {
            Ok(page) => return Ok(page),
            Err(error) => last_error = error,
        }
        if attempt + 1 < ARCHIVE_RANGE_REQUEST_ATTEMPTS && Instant::now() < sync_deadline {
            let remaining = sync_deadline.saturating_duration_since(Instant::now());
            thread::sleep(PEER_SEND_RETRY_DELAY.min(remaining));
        }
    }
    Err(last_error)
}

fn run_archive_range_sync_for_peer(
    peer: SocketAddr,
    noise: &NoiseOutboundConfig,
    data_dir: &Path,
    import_tx: &mpsc::SyncSender<ArchiveRangeImportBatch>,
    post_commit_delay: Duration,
) -> Result<(), String> {
    let mut import_page = |peer: SocketAddr, entries: &[ArchiveSyncServedEntry]| {
        let (response_tx, response_rx) = mpsc::sync_channel(1);
        import_tx
            .send(ArchiveRangeImportBatch {
                peer,
                entries: entries.to_vec(),
                response: response_tx,
            })
            .map_err(|_| "archive range importer stopped".to_string())?;
        match response_rx.recv_timeout(ARCHIVE_RANGE_IMPORT_RESPONSE_TIMEOUT) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(format!(
                "consensus/fork-store rejected archive page: {error}"
            )),
            Err(error) => Err(format!(
                "archive range import acknowledgement failed: {error}"
            )),
        }
    };
    run_archive_range_sync_with_import(
        peer,
        noise,
        data_dir.join(ARCHIVE_RANGE_SYNC_DIRECTORY),
        archive_range_limits(),
        post_commit_delay,
        ARCHIVE_RANGE_REQUEST_MAGIC,
        ARCHIVE_RANGE_PAGE_MAGIC,
        &mut import_page,
    )
}

fn run_monetary_archive_range_sync_for_peer(
    peer: SocketAddr,
    noise: &NoiseOutboundConfig,
    data_dir: &Path,
    import_tx: &mpsc::SyncSender<MonetaryArchiveRangeImportBatch>,
) -> Result<(), String> {
    let mut import_page = |peer: SocketAddr, entries: &[ArchiveSyncServedEntry]| {
        let (response_tx, response_rx) = mpsc::sync_channel(1);
        import_tx
            .send(MonetaryArchiveRangeImportBatch {
                peer,
                entries: entries.to_vec(),
                response: response_tx,
            })
            .map_err(|_| "monetary archive range importer stopped".to_string())?;
        match response_rx.recv_timeout(ARCHIVE_RANGE_IMPORT_RESPONSE_TIMEOUT) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(format!("PFM3 monetary archive page rejected: {error}")),
            Err(error) => Err(format!(
                "PFM3 monetary archive import acknowledgement failed: {error}"
            )),
        }
    };
    run_archive_range_sync_with_import(
        peer,
        noise,
        data_dir.join(MONETARY_ARCHIVE_RANGE_SYNC_DIRECTORY),
        archive_range_limits(),
        Duration::ZERO,
        ARCHIVE_RANGE_REQUEST_MAGIC,
        ARCHIVE_RANGE_PAGE_MAGIC,
        &mut import_page,
    )
}

fn run_archive_range_sync_with_import<F>(
    peer: SocketAddr,
    noise: &NoiseOutboundConfig,
    staging_dir: PathBuf,
    limits: ArchiveSyncLimits,
    post_commit_delay: Duration,
    request_magic: &[u8; 4],
    page_magic: &[u8; 4],
    import_page: &mut F,
) -> Result<(), String>
where
    F: FnMut(SocketAddr, &[ArchiveSyncServedEntry]) -> Result<(), String>,
{
    let initial_pin = noise.trusted_pin(peer)?;
    fs::create_dir_all(&staging_dir)
        .map_err(|error| format!("create archive range staging directory: {error}"))?;
    let mut cursor: Option<[u8; ARCHIVE_SYNC_CURSOR_BYTES]> = None;
    let mut wal: Option<ArchiveRangeWalCandidate> = None;
    let mut snapshot_commitment: Option<[u8; 32]> = None;
    let mut expected_items = 0u64;
    let mut expected_bytes = 0u64;
    let sync_deadline = Instant::now() + ARCHIVE_RANGE_TOTAL_SYNC_TIMEOUT;

    for _ in 0..=limits.max_pages {
        if Instant::now() >= sync_deadline {
            return Err("archive range sync exceeded its absolute total deadline".into());
        }
        let page = fetch_archive_range_page_with_magic(
            peer,
            noise,
            cursor.as_ref(),
            sync_deadline,
            request_magic,
            page_magic,
        )?;
        if page.archive_total_items > limits.max_total_items
            || page.archive_total_bytes > limits.max_total_bytes
        {
            return Err("archive range manifest exceeds the local sync budget".into());
        }
        if let Some(expected) = snapshot_commitment {
            if page.snapshot_commitment != expected
                || page.archive_total_items != expected_items
                || page.archive_total_bytes != expected_bytes
            {
                return Err("archive range snapshot/manifest changed during sync".into());
            }
        } else {
            snapshot_commitment = Some(page.snapshot_commitment);
            expected_items = page.archive_total_items;
            expected_bytes = page.archive_total_bytes;
            let path = staging_dir.join(archive_range_wal_filename(
                &initial_pin,
                &page.snapshot_commitment,
            ));
            ensure_archive_range_wal_budget(&staging_dir, &path)?;
            wal = Some(
                ArchiveRangeWalCandidate::open(
                    &path,
                    limits,
                    page.snapshot_commitment,
                    expected_items,
                    expected_bytes,
                )
                .map_err(|error| format!("open/recover archive range WAL: {error}"))?,
            );
            eprintln!("event=devnet_archive_range_sync_started peer={peer} snapshot={} items={} bytes={} already_durable={}",
                hex(&page.snapshot_commitment), expected_items, expected_bytes,
                wal.as_ref().map(|store| store.receipt().end_index).unwrap_or(0));
        }

        let store = wal
            .as_mut()
            .ok_or_else(|| "archive range WAL was not initialized".to_string())?;
        let receipt = store.receipt();
        if receipt.complete {
            eprintln!("event=devnet_archive_range_sync_complete peer={peer} snapshot={} items={} bytes={} resumed=durable",
                hex(&page.snapshot_commitment), receipt.total_items_verified, receipt.total_bytes_verified);
            return Ok(());
        }

        if page.plan.end_index < receipt.end_index {
            if page.plan.complete {
                return Err("archive range server marked an older range complete before local durable progress".into());
            }
            cursor = page.plan.next_cursor;
            continue;
        }

        if page.plan.end_index == receipt.end_index {
            if expected_items == 0 && page.plan.complete {
                store
                    .validate_page(&page)
                    .map_err(|error| format!("validate empty archive range: {error}"))?;
                store
                    .commit_page(&page)
                    .map_err(|error| format!("commit empty archive range: {error}"))?;
                eprintln!("event=devnet_archive_range_sync_complete peer={peer} snapshot={} items=0 bytes=0", hex(&page.snapshot_commitment));
                return Ok(());
            }
            if page.plan.complete {
                return Err(
                    "archive range complete page duplicates an incomplete durable receipt".into(),
                );
            }
            cursor = Some(
                page.plan
                    .next_cursor
                    .ok_or_else(|| "incomplete archive page omitted its cursor".to_string())?,
            );
            continue;
        }

        if page.plan.start_index != receipt.end_index {
            return Err(format!(
                "archive range page is not contiguous (start={}, durable_end={})",
                page.plan.start_index, receipt.end_index
            ));
        }
        store
            .validate_page(&page)
            .map_err(|error| format!("validate archive range page before import: {error}"))?;

        if !page.entries.is_empty() {
            import_page(peer, &page.entries)?;
        }

        let committed = store
            .commit_page(&page)
            .map_err(|error| format!("durably commit archive range page: {error}"))?;
        eprintln!("event=devnet_archive_range_page_committed peer={peer} page={} start={} end={} bytes={} durable_end={} complete={}",
            page.plan.page_number, page.plan.start_index, page.plan.end_index, page.plan.page_bytes, committed.end_index, committed.complete);
        if committed.complete {
            eprintln!("event=devnet_archive_range_sync_complete peer={peer} snapshot={} items={} bytes={} resumed=false",
                hex(&page.snapshot_commitment), committed.total_items_verified, committed.total_bytes_verified);
            return Ok(());
        }
        // Fault-injection seam: pause only after page validation, consensus import, and durable
        // WAL commit, so restart tests can stop the receiver at a reproducible committed boundary.
        if !post_commit_delay.is_zero() {
            let wal_sha256 = store.diagnostic_sha256().map_err(|error| {
                format!("compute test-only durable archive WAL digest: {error}")
            })?;
            eprintln!(
                "event=devnet_archive_range_wal_digest_for_diagnostics peer={peer} snapshot={} durable_end={} sha256={}",
                hex(&page.snapshot_commitment), committed.end_index, hex(&wal_sha256)
            );
            thread::sleep(post_commit_delay);
        }
        cursor = Some(
            page.plan
                .next_cursor
                .ok_or_else(|| "incomplete archive page omitted its next cursor".to_string())?,
        );
    }
    Err("archive range sync exceeded the configured page-count budget".into())
}

fn start_archive_range_sync_threads(
    peers: &[SocketAddr],
    noise_config: Option<NoiseOutboundConfig>,
    data_dir: PathBuf,
    import_tx: mpsc::SyncSender<ArchiveRangeImportBatch>,
    post_commit_delay: Duration,
) -> Arc<AtomicUsize> {
    let pending = Arc::new(AtomicUsize::new(0));
    if peers.is_empty() {
        return pending;
    }
    let Some(noise_config) = noise_config else {
        eprintln!("event=devnet_archive_range_sync_failed reason=no_noise_config");
        return pending;
    };
    pending.store(peers.len(), AtomicOrdering::Release);
    for peer in peers.iter().copied() {
        let noise = noise_config.clone();
        let directory = data_dir.clone();
        let imports = import_tx.clone();
        let delay = post_commit_delay;
        let completion_counter = Arc::clone(&pending);
        thread::spawn(move || {
            match run_archive_range_sync_for_peer(peer, &noise, &directory, &imports, delay) {
                Ok(()) => {}
                Err(error) => eprintln!(
                    "event=devnet_archive_range_sync_failed peer={peer} reason={}",
                    sanitize(&error)
                ),
            }
            completion_counter.fetch_sub(1, AtomicOrdering::AcqRel);
        });
    }
    pending
}

fn apply_archive_range_import_batch(
    batch: &ArchiveRangeImportBatch,
    store: &mut PrivateTestnetForkStore,
    params: &ConsensusParameters,
    auth: &NodeAuthenticator,
    clock: &SystemClockReferenceTime,
) -> Result<(), String> {
    for entry in &batch.entries {
        let (status, height, digest) = import_payload(&entry.encoded, store, params, auth, clock)
            .map_err(|error| {
            format!(
                "import archive entry at height {}: {error}",
                entry.metadata.height
            )
        })?;
        if height != entry.metadata.height || digest != entry.metadata.digest {
            return Err(format!(
                "archive metadata mismatches consensus-decoded block at height {}",
                entry.metadata.height
            ));
        }
        let canonical = store.archive().canonical_chain();
        let event = if status == ACK_STATUS_DUPLICATE {
            "private_testnet_duplicate"
        } else {
            "private_testnet_imported"
        };
        eprintln!(
            "event={event} peer={} height={} candidate_height={} candidate_digest={} canonical_height={} state_root={} consensus_tip={}",
            batch.peer,
            height,
            height,
            hex(&digest),
            canonical.state().height(),
            hex(&canonical.state().state_root()),
            hex(&canonical.chain_tip().tip_hash)
        );
    }
    Ok(())
}

fn start_monetary_archive_range_sync_threads(
    peers: &[SocketAddr],
    noise_config: NoiseOutboundConfig,
    data_dir: PathBuf,
    import_tx: mpsc::SyncSender<MonetaryArchiveRangeImportBatch>,
) -> Arc<AtomicUsize> {
    let pending = Arc::new(AtomicUsize::new(0));
    if peers.is_empty() {
        return pending;
    }
    pending.store(peers.len(), AtomicOrdering::Release);
    for peer in peers.iter().copied() {
        let noise = noise_config.clone();
        let directory = data_dir.clone();
        let imports = import_tx.clone();
        let completion_counter = Arc::clone(&pending);
        thread::spawn(move || {
            match run_monetary_archive_range_sync_for_peer(peer, &noise, &directory, &imports) {
                Ok(()) => eprintln!("event=monetary_archive_range_sync_complete peer={peer}"),
                Err(error) => eprintln!(
                    "event=monetary_archive_range_sync_failed peer={peer} reason={}",
                    sanitize(&error)
                ),
            }
            completion_counter.fetch_sub(1, AtomicOrdering::AcqRel);
        });
    }
    pending
}

fn apply_monetary_archive_range_import_batch(
    batch: &MonetaryArchiveRangeImportBatch,
    store: &mut PrivateTestnetMonetaryForkStore,
    params: &ConsensusParameters,
    auth: &NodeAuthenticator,
    clock: &SystemClockReferenceTime,
) -> Result<(), String> {
    // Validate every page entry's PMT3 height/digest binding before mutating PFM3. The page
    // receipt authenticates bytes and ordering, but only consensus decoding supplies block IDs.
    let mut identities = Vec::with_capacity(batch.entries.len());
    for entry in &batch.entries {
        let candidate = decode_candidate_monetary_network_block(&entry.encoded)
            .map_err(|error| format!("decode PMT3 archive entry: {error}"))?;
        let digest = pow_digest(&candidate.header, params.pow)
            .map_err(|error| format!("hash PMT3 archive entry: {error}"))?;
        if candidate.header.height != entry.metadata.height || digest != entry.metadata.digest {
            return Err(format!(
                "PMT3 archive metadata mismatch at claimed height {}",
                entry.metadata.height
            ));
        }
        identities.push((candidate.header.height, digest));
    }

    for (entry, (height, digest)) in batch.entries.iter().zip(identities) {
        let (status, outcome) = import_monetary_payload(&entry.encoded, store, params, auth, clock)
            .map_err(|error| format!("import PMT3 archive entry at height {height}: {error}"))?;
        if outcome.block_digest != digest || outcome.canonical_height == 0 {
            return Err(format!(
                "PFM3 importer returned inconsistent outcome at height {height}"
            ));
        }
        let canonical = store.archive().canonical_chain();
        let monetary = canonical
            .monetary_state()
            .ok_or("PFM3 archive import produced a non-monetary canonical chain")?;
        eprintln!(
            "event=monetary_archive_range_item_imported peer={} status={} height={} digest={} canonical_height={} state_root={} consensus_tip={}",
            batch.peer,
            if status == ACK_STATUS_DUPLICATE { "DUPLICATE" } else { "ACCEPTED" },
            height,
            hex(&digest),
            monetary.height(),
            hex(&monetary.state_root()),
            hex(&canonical.chain_tip().tip_hash)
        );
    }
    Ok(())
}

fn run_monetary_v4_archive_range_sync_for_peer(
    peer: SocketAddr,
    noise: &NoiseOutboundConfig,
    data_dir: &Path,
    import_tx: &mpsc::SyncSender<MonetaryV4ArchiveRangeImportBatch>,
) -> Result<(), String> {
    let mut import_page = |peer: SocketAddr, entries: &[ArchiveSyncServedEntry]| {
        let (response_tx, response_rx) = mpsc::sync_channel(1);
        import_tx
            .send(MonetaryV4ArchiveRangeImportBatch {
                peer,
                entries: entries.to_vec(),
                response: response_tx,
            })
            .map_err(|_| "PFM4 archive importer stopped".to_string())?;
        match response_rx.recv_timeout(ARCHIVE_RANGE_IMPORT_RESPONSE_TIMEOUT) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(format!("PFM4 archive page rejected: {error}")),
            Err(error) => Err(format!(
                "PFM4 archive import acknowledgement failed: {error}"
            )),
        }
    };
    run_archive_range_sync_with_import(
        peer,
        noise,
        data_dir.join(MONETARY_V4_ARCHIVE_RANGE_SYNC_DIRECTORY),
        archive_range_limits(),
        Duration::ZERO,
        MONETARY_V4_ARCHIVE_RANGE_REQUEST_MAGIC,
        MONETARY_V4_ARCHIVE_RANGE_PAGE_MAGIC,
        &mut import_page,
    )
}

fn start_monetary_v4_archive_range_sync_threads(
    peers: &[SocketAddr],
    noise_config: NoiseOutboundConfig,
    data_dir: PathBuf,
    import_tx: mpsc::SyncSender<MonetaryV4ArchiveRangeImportBatch>,
) -> Arc<AtomicUsize> {
    let pending = Arc::new(AtomicUsize::new(0));
    if peers.is_empty() {
        return pending;
    }
    pending.store(peers.len(), AtomicOrdering::Release);
    for peer in peers.iter().copied() {
        let noise = noise_config.clone();
        let directory = data_dir.clone();
        let imports = import_tx.clone();
        let completion_counter = Arc::clone(&pending);
        thread::spawn(move || {
            match run_monetary_v4_archive_range_sync_for_peer(peer, &noise, &directory, &imports) {
                Ok(()) => eprintln!("event=monetary_v4_archive_range_sync_complete peer={peer}"),
                Err(error) => eprintln!(
                    "event=monetary_v4_archive_range_sync_failed peer={peer} reason={}",
                    sanitize(&error)
                ),
            }
            completion_counter.fetch_sub(1, AtomicOrdering::AcqRel);
        });
    }
    pending
}

fn apply_monetary_v4_archive_range_import_batch(
    batch: &MonetaryV4ArchiveRangeImportBatch,
    store: &mut PrivateTestnetV4HybridForkStore,
    params: &ConsensusParameters,
    verifier: &LibcruxMlDsa65VerifierCandidate,
    clock: &SystemClockReferenceTime,
) -> Result<(), String> {
    // Validate the complete page's PMT4 identities before any PFM4 mutation. The archive
    // page receipt binds the bytes; consensus decoding supplies the chain digest/height.
    let mut identities = Vec::with_capacity(batch.entries.len());
    for entry in &batch.entries {
        let candidate = decode_candidate_v4_hybrid_monetary_network_block(&entry.encoded)
            .map_err(|error| format!("decode PMT4 archive entry: {error}"))?;
        let digest = pow_digest(&candidate.header, params.pow)
            .map_err(|error| format!("hash PMT4 archive entry: {error}"))?;
        if candidate.header.height != entry.metadata.height || digest != entry.metadata.digest {
            return Err(format!(
                "PMT4 archive metadata mismatch at claimed height {}",
                entry.metadata.height
            ));
        }
        identities.push((candidate.header.height, digest));
    }
    for (entry, (height, digest)) in batch.entries.iter().zip(identities) {
        let (status, outcome) =
            import_v4_hybrid_monetary_payload(&entry.encoded, store, params, verifier, clock)
                .map_err(|error| {
                    format!("import PMT4 archive entry at height {height}: {error}")
                })?;
        if outcome.block_digest != digest {
            return Err(format!(
                "PFM4 importer returned inconsistent block digest at height {height}"
            ));
        }
        let canonical = store.archive().canonical_chain();
        let monetary = canonical
            .monetary_state()
            .ok_or("PFM4 archive import produced a non-monetary canonical chain")?;
        eprintln!(
            "event=monetary_v4_archive_range_item_imported peer={} status={} height={} digest={} canonical_height={} state_root={} consensus_tip={}",
            batch.peer,
            if status == ACK_STATUS_DUPLICATE { "DUPLICATE" } else { "ACCEPTED" },
            height,
            hex(&digest),
            monetary.height(),
            hex(&monetary.state_root()),
            hex(&canonical.chain_tip().tip_hash)
        );
    }
    Ok(())
}

const MAX_STATUS_HTTP_BYTES: usize = 4096;
const STATUS_HTTP_DEADLINE: Duration = Duration::from_millis(250);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StatusRoute {
    Health,
    Status,
}

fn classify_status_request(request: &[u8]) -> Result<StatusRoute, u16> {
    if request.len() > MAX_STATUS_HTTP_BYTES {
        return Err(431);
    }
    if !request.windows(4).any(|part| part == b"\r\n\r\n") {
        return Err(400);
    }
    let line_end = request
        .windows(2)
        .position(|part| part == b"\r\n")
        .ok_or(400u16)?;
    let line = std::str::from_utf8(&request[..line_end]).map_err(|_| 400u16)?;
    let mut fields = line.split_whitespace();
    let method = fields.next().ok_or(400u16)?;
    let path = fields.next().ok_or(400u16)?;
    let version = fields.next().ok_or(400u16)?;
    if fields.next().is_some() || (version != "HTTP/1.0" && version != "HTTP/1.1") {
        return Err(400);
    }
    if method != "GET" {
        return Err(405);
    }
    match path {
        "/health" => Ok(StatusRoute::Health),
        "/status" => Ok(StatusRoute::Status),
        _ => Err(404),
    }
}

fn status_json(
    network_id: &[u8; 32],
    height: u64,
    state_root: &[u8; 32],
    consensus_tip: &[u8; 32],
    archive_branches: usize,
    profile_label: &str,
) -> String {
    format!(
        "{{\"network_id\":\"{}\",\"height\":{},\"state_root\":\"{}\",\"consensus_tip\":\"{}\",\"archive_branches\":{},\"profile\":\"{}\",\"value_bearing\":false}}",
        hex(network_id),
        height,
        hex(state_root),
        hex(consensus_tip),
        archive_branches,
        profile_label
    )
}

fn read_status_request(stream: &mut TcpStream) -> Result<Vec<u8>, u16> {
    stream
        .set_read_timeout(Some(Duration::from_millis(50)))
        .map_err(|_| 500u16)?;
    let deadline = Instant::now() + STATUS_HTTP_DEADLINE;
    let mut request = Vec::with_capacity(512);
    let mut buffer = [0u8; 512];
    loop {
        if request.windows(4).any(|part| part == b"\r\n\r\n") {
            return Ok(request);
        }
        if request.len() >= MAX_STATUS_HTTP_BYTES {
            return Err(431);
        }
        if Instant::now() >= deadline {
            return Err(408);
        }
        let available = (MAX_STATUS_HTTP_BYTES - request.len()).min(buffer.len());
        match stream.read(&mut buffer[..available]) {
            Ok(0) => return Err(400),
            Ok(count) => request.extend_from_slice(&buffer[..count]),
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.kind() == io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(_) => return Err(400),
        }
    }
}

fn status_http_body(status: u16, route: Option<StatusRoute>, status_body: &str) -> String {
    match (status, route) {
        (200, Some(StatusRoute::Health)) => {
            "{\"status\":\"ok\",\"value_bearing\":false}".to_string()
        }
        (200, Some(StatusRoute::Status)) => status_body.to_string(),
        (400, _) => "{\"error\":\"bad_request\"}".to_string(),
        (404, _) => "{\"error\":\"not_found\"}".to_string(),
        (405, _) => "{\"error\":\"method_not_allowed\"}".to_string(),
        (408, _) => "{\"error\":\"request_timeout\"}".to_string(),
        (431, _) => "{\"error\":\"request_too_large\"}".to_string(),
        _ => "{\"error\":\"internal_error\"}".to_string(),
    }
}

fn serve_status_connection(mut stream: TcpStream, status_body: &str) -> io::Result<()> {
    stream.set_write_timeout(Some(Duration::from_millis(100)))?;
    let request_result = read_status_request(&mut stream);
    let (status, route) = match request_result {
        Ok(request) => match classify_status_request(&request) {
            Ok(route) => (200, Some(route)),
            Err(status) => (status, None),
        },
        Err(status) => (status, None),
    };
    let body = status_http_body(status, route, status_body);
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        431 => "Request Header Fields Too Large",
        _ => "Internal Server Error",
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()
}

fn parse_txn4_submit_headers(header: &[u8]) -> Result<usize, u16> {
    if header.len() > MAX_TXN4_HTTP_HEADER_BYTES {
        return Err(431);
    }
    if !header.ends_with(b"\r\n\r\n") {
        return Err(400);
    }
    let text = std::str::from_utf8(&header[..header.len() - 4]).map_err(|_| 400u16)?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().ok_or(400u16)?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().ok_or(400u16)?;
    let path = request_parts.next().ok_or(400u16)?;
    let version = request_parts.next().ok_or(400u16)?;
    if request_parts.next().is_some() {
        return Err(400);
    }
    if method != "POST" {
        return Err(405);
    }
    if path != "/tx/submit" {
        return Err(404);
    }
    if version != "HTTP/1.1" {
        return Err(400);
    }

    let mut content_length = None;
    let mut content_type = false;
    for line in lines {
        if line.is_empty() {
            return Err(400);
        }
        let (name, value) = line.split_once(':').ok_or(400u16)?;
        let name = name.trim();
        let value = value.trim();
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(400);
        }
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some()
                || value.is_empty()
                || !value.as_bytes().iter().all(u8::is_ascii_digit)
            {
                return Err(400);
            }
            content_length = Some(value.parse::<usize>().map_err(|_| 413u16)?);
        } else if name.eq_ignore_ascii_case("content-type") {
            if content_type || !value.eq_ignore_ascii_case("application/octet-stream") {
                return Err(415);
            }
            content_type = true;
        }
    }

    let content_length = content_length.ok_or(411u16)?;
    if !content_type {
        return Err(415);
    }
    if content_length != V4_HYBRID_TRANSACTION_WIRE_BYTES {
        return Err(413);
    }
    Ok(content_length)
}

fn decode_txn4_submit_request(request: &[u8]) -> Result<&[u8], u16> {
    let header_end = request
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .ok_or(400u16)?;
    let header_end = header_end + 4;
    let body_len = parse_txn4_submit_headers(&request[..header_end])?;
    let body = request.get(header_end..).ok_or(400u16)?;
    if body.len() != body_len {
        return Err(400);
    }
    Ok(body)
}

fn read_txn4_submit_body(stream: &mut TcpStream) -> Result<Vec<u8>, u16> {
    stream
        .set_read_timeout(Some(Duration::from_millis(50)))
        .map_err(|_| 500u16)?;
    let deadline = Instant::now() + TXN4_HTTP_DEADLINE;
    let mut header = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    loop {
        if header.len() >= MAX_TXN4_HTTP_HEADER_BYTES {
            return Err(431);
        }
        match stream.read(&mut byte) {
            Ok(0) => return Err(400),
            Ok(1) => {
                header.push(byte[0]);
                if header.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            Ok(_) => unreachable!("one-byte read cannot return more than one byte"),
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.kind() == io::ErrorKind::TimedOut =>
            {
                if Instant::now() >= deadline {
                    return Err(408);
                }
            }
            Err(_) => return Err(400),
        }
        if Instant::now() >= deadline {
            return Err(408);
        }
    }
    let body_len = parse_txn4_submit_headers(&header)?;
    let mut request = header;
    request.resize(request.len() + body_len, 0);
    let body_start = request.len() - body_len;
    let mut filled = 0usize;
    while filled < body_len {
        if Instant::now() >= deadline {
            return Err(408);
        }
        match stream.read(&mut request[body_start + filled..]) {
            Ok(0) => return Err(400),
            Ok(count) => filled += count,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.kind() == io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(_) => return Err(400),
        }
    }
    decode_txn4_submit_request(&request).map(|body| body.to_vec())
}

fn txn4_http_response_body(_status: u16, code: &str) -> String {
    format!("{{\"error\":\"{code}\"}}")
}

fn write_txn4_http_response(stream: &mut TcpStream, status: u16, body: &str) -> io::Result<()> {
    stream.set_write_timeout(Some(Duration::from_millis(250)))?;
    let reason = match status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        411 => "Length Required",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        422 => "Unprocessable Content",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        _ => "Internal Server Error",
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()
}

fn serve_v4_transaction_submit_connection(
    mut stream: TcpStream,
    mempool: &mut V4HybridMempoolCandidate,
    store: &PrivateTestnetV4HybridForkStore,
    verifier: &LibcruxMlDsa65VerifierCandidate,
    miner: AccountId,
) {
    let body = match read_txn4_submit_body(&mut stream) {
        Ok(body) => body,
        Err(status) => {
            let code = match status {
                400 => "bad_request",
                404 => "not_found",
                405 => "method_not_allowed",
                408 => "request_timeout",
                411 => "content_length_required",
                413 => "transaction_size_invalid",
                415 => "content_type_required",
                431 => "headers_too_large",
                _ => "internal_error",
            };
            let _ = write_txn4_http_response(
                &mut stream,
                status,
                &txn4_http_response_body(status, code),
            );
            return;
        }
    };
    let transaction = match V4HybridTransaction::decode(&body) {
        Ok(transaction) => transaction,
        Err(_) => {
            let _ = write_txn4_http_response(
                &mut stream,
                400,
                &txn4_http_response_body(400, "invalid_txn4_wire"),
            );
            return;
        }
    };
    let canonical = store.archive().canonical_chain();
    let Some(state) = canonical.monetary_state() else {
        let _ = write_txn4_http_response(
            &mut stream,
            500,
            &txn4_http_response_body(500, "canonical_state_unavailable"),
        );
        return;
    };
    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(_) => {
            let _ = write_txn4_http_response(
                &mut stream,
                500,
                &txn4_http_response_body(500, "clock_unavailable"),
            );
            return;
        }
    };
    match mempool.submit(transaction, state, verifier, now, miner) {
        Ok(id) => {
            let body = format!(
                "{{\"status\":\"accepted\",\"transaction_id\":\"{}\",\"mempool_count\":{},\"mempool_bytes\":{}}}",
                hex(&id),
                mempool.len(),
                mempool.total_bytes()
            );
            let _ = write_txn4_http_response(&mut stream, 202, &body);
            eprintln!(
                "event=txn4_submission_accepted txid={} mempool_count={} mempool_bytes={}",
                hex(&id),
                mempool.len(),
                mempool.total_bytes()
            );
        }
        Err(V4HybridMempoolError::Duplicate) => {
            let _ = write_txn4_http_response(
                &mut stream,
                409,
                &txn4_http_response_body(409, "duplicate_transaction"),
            );
        }
        Err(V4HybridMempoolError::TransactionLimit | V4HybridMempoolError::ByteLimit) => {
            let _ = write_txn4_http_response(
                &mut stream,
                429,
                &txn4_http_response_body(429, "mempool_capacity_exceeded"),
            );
        }
        Err(_) => {
            let _ = write_txn4_http_response(
                &mut stream,
                422,
                &txn4_http_response_body(422, "transaction_rejected"),
            );
        }
    }
}

fn reconcile_v4_mempool_after_canonical_change(
    mempool: &mut V4HybridMempoolCandidate,
    store: &PrivateTestnetV4HybridForkStore,
    verifier: &LibcruxMlDsa65VerifierCandidate,
    miner: AccountId,
    last_tip: &mut [u8; 32],
) -> Result<(), String> {
    let tip = store.canonical_tip();
    if *last_tip == tip {
        return Ok(());
    }
    let canonical = store.archive().canonical_chain();
    let state = canonical
        .monetary_state()
        .ok_or("PFM4 canonical tip has no monetary state during TXN4 pool reconciliation")?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock predates Unix epoch during TXN4 pool reconciliation")?
        .as_secs();
    let summary = mempool.reconcile_after_state_change(state, verifier, now, miner);
    eprintln!(
        "event=txn4_mempool_reconciled height={} kept={} expired={} invalid={} count={} bytes={}",
        state.height(),
        summary.kept,
        summary.dropped_expired,
        summary.dropped_invalid,
        mempool.len(),
        mempool.total_bytes()
    );
    *last_tip = tip;
    Ok(())
}

fn run() -> Result<(), String> {
    run_with_runtime_profile(NodeRuntimeProfile::PrivateSmoke)
}

pub fn run_devnet() -> Result<(), String> {
    run_with_runtime_profile(NodeRuntimeProfile::ZeroValueDevnet)
}

const MONETARY_GENESIS_MANIFEST_MAGIC: &[u8; 4] = b"MGN3";
const MONETARY_GENESIS_MANIFEST_DOMAIN: &[u8] = b"AIN1-MONETARY-CANDIDATE-GENESIS-V3\0";
const MONETARY_V4_GENESIS_MANIFEST_MAGIC: &[u8; 4] = b"MGN4";
const MONETARY_V4_GENESIS_MANIFEST_DOMAIN: &[u8] =
    b"AIN1-MONETARY-V4-HYBRID-CANDIDATE-GENESIS-V1\0";
const MONETARY_V4_MANIFEST_ID_DOMAIN: &[u8] = b"AIN1-LOCAL-PMT4-PFM4-MANIFEST-ID-V1\0";

fn path_entry_exists(path: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!(
            "inspect profile-isolation path {}: {error}",
            path.display()
        )),
    }
}

fn local_monetary_account_id(network_id: &[u8; 32], role: &[u8]) -> AccountId {
    let mut preimage = Vec::with_capacity(64 + role.len());
    preimage.extend_from_slice(b"AIN1-LOCAL-ONLY-NONKEY-MONETARY-ACCOUNT-V1\0");
    preimage.extend_from_slice(network_id);
    preimage.extend_from_slice(&(role.len() as u32).to_be_bytes());
    preimage.extend_from_slice(role);
    Sha256::digest(&preimage).into()
}

fn local_monetary_smoke_profile_digest(
    profile: &DevnetProfileCandidate,
    params: &ConsensusParameters,
) -> [u8; 32] {
    // Bind the fast smoke overrides independently from the real candidate Devnet parameters.
    // This profile is for local execution checks only and must never be advertised as network consensus.
    let mut canonical = Vec::with_capacity(256);
    canonical.extend_from_slice(b"AIN1-LOCAL-MONETARY-POW-SMOKE-PROFILE-V1\0");
    canonical.extend_from_slice(profile.profile_id());
    canonical.extend_from_slice(profile.consensus_digest());
    canonical.extend_from_slice(&params.protocol_version.to_be_bytes());
    canonical.extend_from_slice(&params.initial_target.to_be_bytes());
    canonical.extend_from_slice(&params.pow_limit.to_be_bytes());
    canonical.extend_from_slice(&params.pow.memory_kib.to_be_bytes());
    canonical.extend_from_slice(&params.pow.iterations.to_be_bytes());
    canonical.extend_from_slice(&params.pow.lanes.to_be_bytes());
    canonical.push(params.pow.output_bytes);
    Sha256::digest(&canonical).into()
}

fn encode_monetary_genesis_manifest(
    profile: &DevnetProfileCandidate,
    params: &ConsensusParameters,
    genesis: &MonetaryLedgerState,
) -> Result<Vec<u8>, String> {
    let snapshot = genesis
        .encode_snapshot()
        .map_err(|error| format!("encode candidate monetary Genesis snapshot: {error:?}"))?;
    let snapshot_len = u32::try_from(snapshot.len())
        .map_err(|_| "candidate monetary Genesis snapshot is too large")?;
    let total_value = genesis
        .total_value()
        .map_err(|error| format!("validate candidate monetary Genesis accounting: {error:?}"))?;
    let mut bytes = Vec::with_capacity(180 + snapshot.len() + 32);
    bytes.extend_from_slice(MONETARY_GENESIS_MANIFEST_MAGIC);
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes.extend_from_slice(profile.network_id());
    bytes.extend_from_slice(profile.profile_id());
    bytes.extend_from_slice(&local_monetary_smoke_profile_digest(profile, params));
    bytes.extend_from_slice(&genesis.tip_hash());
    bytes.extend_from_slice(&genesis.state_root());
    bytes.extend_from_slice(&total_value.to_be_bytes());
    bytes.extend_from_slice(&snapshot_len.to_be_bytes());
    bytes.extend_from_slice(&snapshot);
    let digest = Sha256::digest([MONETARY_GENESIS_MANIFEST_DOMAIN, bytes.as_slice()].concat());
    bytes.extend_from_slice(&digest);
    Ok(bytes)
}

fn persist_or_verify_monetary_genesis_manifest(
    data_dir: &Path,
    expected: &[u8],
) -> Result<(), String> {
    fs::create_dir_all(data_dir)
        .map_err(|error| format!("create monetary candidate data directory: {error}"))?;
    let path = data_dir.join("monetary-genesis.mgn3");
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err("MGN3 manifest must be a regular, non-symlink file".into());
            }
            if metadata.len() != expected.len() as u64 {
                return Err(
                    "existing MGN3 manifest conflicts with requested monetary Genesis".into(),
                );
            }
            let existing = fs::read(&path)
                .map_err(|error| format!("read monetary Genesis manifest: {error}"))?;
            if existing != expected {
                return Err("existing MGN3 manifest conflicts with network/profile/Genesis".into());
            }
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .map_err(|error| format!("create monetary Genesis manifest: {error}"))?;
            let write_result = file
                .write_all(expected)
                .and_then(|_| file.flush())
                .and_then(|_| file.sync_all());
            drop(file);
            if let Err(error) = write_result {
                let _ = fs::remove_file(&path);
                return Err(format!("persist monetary Genesis manifest: {error}"));
            }
            Ok(())
        }
        Err(error) => Err(format!("inspect monetary Genesis manifest: {error}")),
    }
}

fn validate_monetary_candidate_local_config(config: &Config) -> Result<(), String> {
    let default_listen: SocketAddr = "127.0.0.1:49301".parse().expect("static loopback address");
    if config.listen != default_listen
        || config.status_listen.is_some()
        || !config.peers.is_empty()
        || config.noise_static_private_key_dpapi_file.is_some()
        || !config.trusted_peer_keys.is_empty()
        || !config.trusted_peer_identity_files.is_empty()
        || config.deployment_config_file.is_some()
        || config.deployment_authority_public_key.is_some()
        || config.deployment_config_min_sequence.is_some()
        || config.issuer_registry_file.is_some()
        || config.peer_identity_issuer_id.is_some()
        || config.test_transactions
        || config.test_seed_file.is_some()
        || config.duplicate_broadcast
        || config.stop_after_height.is_some()
        || config.archive_sync_delay_ms != 0
        || config.archive_sync_reverse_first_round
        || config.archive_range_max_page_items != 16
        || config.archive_range_post_commit_delay_ms != 0
    {
        return Err(
            "monetary candidate local smoke is offline-only and refuses listeners, peers, trust/network settings, transaction fixtures, archive-sync options, and conflicting runtime flags".into(),
        );
    }
    if config.mine_blocks == 0 || !config.exit_after_mining {
        return Err(
            "monetary candidate local smoke requires --mine-blocks N and --exit-after-mining"
                .into(),
        );
    }
    Ok(())
}

fn local_monetary_v4_manifest_id(
    profile: &DevnetProfileCandidate,
    params: &ConsensusParameters,
) -> [u8; 32] {
    let profile_digest = local_monetary_smoke_profile_digest(profile, params);
    let mut canonical = Vec::with_capacity(160);
    canonical.extend_from_slice(MONETARY_V4_MANIFEST_ID_DOMAIN);
    canonical.extend_from_slice(profile.network_id());
    canonical.extend_from_slice(profile.profile_id());
    canonical.extend_from_slice(profile.consensus_digest());
    canonical.extend_from_slice(&profile_digest);
    Sha256::digest(&canonical).into()
}

fn encode_monetary_v4_genesis_manifest(
    profile: &DevnetProfileCandidate,
    params: &ConsensusParameters,
    genesis: &MonetaryLedgerState,
    manifest_id: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let snapshot = genesis
        .encode_snapshot()
        .map_err(|error| format!("encode PMT4 Genesis snapshot: {error:?}"))?;
    let snapshot_len =
        u32::try_from(snapshot.len()).map_err(|_| "PMT4 Genesis snapshot is too large")?;
    let total_value = genesis
        .total_value()
        .map_err(|error| format!("validate PMT4 Genesis accounting: {error:?}"))?;
    let mut bytes = Vec::with_capacity(256 + snapshot.len());
    bytes.extend_from_slice(MONETARY_V4_GENESIS_MANIFEST_MAGIC);
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes.extend_from_slice(profile.network_id());
    bytes.extend_from_slice(profile.profile_id());
    bytes.extend_from_slice(&local_monetary_smoke_profile_digest(profile, params));
    bytes.extend_from_slice(manifest_id);
    bytes.extend_from_slice(&genesis.tip_hash());
    bytes.extend_from_slice(&genesis.state_root());
    bytes.extend_from_slice(&total_value.to_be_bytes());
    bytes.extend_from_slice(&snapshot_len.to_be_bytes());
    bytes.extend_from_slice(&snapshot);
    let digest = Sha256::digest([MONETARY_V4_GENESIS_MANIFEST_DOMAIN, bytes.as_slice()].concat());
    bytes.extend_from_slice(&digest);
    Ok(bytes)
}

fn persist_or_verify_monetary_v4_genesis_manifest(
    data_dir: &Path,
    expected: &[u8],
) -> Result<(), String> {
    fs::create_dir_all(data_dir)
        .map_err(|error| format!("create PMT4/PFM4 data directory: {error}"))?;
    let path = data_dir.join("monetary-genesis.mgn4");
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err("MGN4 manifest must be a regular, non-symlink file".into());
            }
            if metadata.len() != expected.len() as u64 {
                return Err("existing MGN4 manifest conflicts with requested PMT4 Genesis".into());
            }
            let existing =
                fs::read(&path).map_err(|error| format!("read MGN4 manifest: {error}"))?;
            if existing != expected {
                return Err(
                    "existing MGN4 conflicts with network/profile/manifest ID/Genesis".into(),
                );
            }
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .map_err(|error| format!("create MGN4 manifest: {error}"))?;
            let write_result = file
                .write_all(expected)
                .and_then(|_| file.flush())
                .and_then(|_| file.sync_all());
            drop(file);
            if let Err(error) = write_result {
                let _ = fs::remove_file(&path);
                return Err(format!("persist MGN4 manifest: {error}"));
            }
            Ok(())
        }
        Err(error) => Err(format!("inspect MGN4 manifest: {error}")),
    }
}

fn build_next_v4_hybrid_monetary_candidate(
    chain: &PrivateTestnetChain,
    params: &ConsensusParameters,
    manifest_id: &[u8; 32],
    verifier: &LibcruxMlDsa65VerifierCandidate,
    miner: AccountId,
    timestamp_offset: u64,
    timestamp_backdate: u64,
) -> Result<Vec<u8>, String> {
    build_next_v4_hybrid_monetary_candidate_with_transactions(
        chain,
        params,
        manifest_id,
        verifier,
        miner,
        timestamp_offset,
        timestamp_backdate,
        Vec::new(),
    )
}

fn build_next_v4_hybrid_monetary_candidate_with_transactions(
    chain: &PrivateTestnetChain,
    params: &ConsensusParameters,
    manifest_id: &[u8; 32],
    verifier: &LibcruxMlDsa65VerifierCandidate,
    miner: AccountId,
    timestamp_offset: u64,
    timestamp_backdate: u64,
    transactions: Vec<V4HybridTransaction>,
) -> Result<Vec<u8>, String> {
    let state = chain
        .monetary_state()
        .ok_or("PMT4 builder received a non-monetary parent chain")?;
    let ledger = state.ledger();
    let wall_clock = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock predates Unix epoch")?
        .as_secs();
    let timestamp = wall_clock
        .saturating_add(timestamp_offset)
        .saturating_sub(timestamp_backdate)
        .max(ledger.last_timestamp().saturating_add(1));
    let mut block = V4HybridMonetaryBlock {
        height: state
            .height()
            .checked_add(1)
            .ok_or("PMT4 height overflow")?,
        timestamp,
        parent_hash: state.tip_hash(),
        state_root: [0; 32],
        transactions,
        miner,
        claimed_subsidy_atoms: state
            .expected_miner_reward()
            .map_err(|error| format!("derive PMT4 miner subsidy: {error:?}"))?,
    };
    block.state_root = state
        .preview_v4_hybrid_state_root_after(&block, manifest_id, verifier)
        .map_err(|error| format!("preview PMT4 hybrid state root: {error:?}"))?;
    let target = chain
        .expected_target(None)
        .map_err(|error| format!("derive PMT4 PoW target: {error}"))?;

    for nonce in 0..u64::MAX {
        let header = PowHeader {
            protocol_version: params.protocol_version,
            network_id: ledger.network_id(),
            height: block.height,
            timestamp: block.timestamp,
            parent_hash: block.parent_hash,
            previous_consensus_hash: chain.chain_tip().tip_hash,
            state_root: block.state_root,
            target,
            nonce,
        };
        let digest = pow_digest(&header, params.pow)
            .map_err(|error| format!("calculate PMT4 PoW: {error}"))?;
        if Uint256::from_be_bytes(digest) <= target {
            return encode_candidate_v4_hybrid_monetary_network_block(&header, &block)
                .map_err(|error| format!("encode PMT4 candidate: {error}"));
        }
    }
    Err("PMT4 candidate nonce search exhausted".into())
}

fn import_v4_hybrid_monetary_payload(
    payload: &[u8],
    store: &mut PrivateTestnetV4HybridForkStore,
    params: &ConsensusParameters,
    verifier: &LibcruxMlDsa65VerifierCandidate,
    clock: &SystemClockReferenceTime,
) -> Result<(u8, V4HybridForkChoiceOutcome), ImportFailure> {
    let candidate = decode_candidate_v4_hybrid_monetary_network_block(payload)
        .map_err(|error| ImportFailure::Rejected(format!("decode PMT4 candidate: {error}")))?;
    let canonical = store.archive().canonical_chain();
    let monetary = canonical.monetary_state().ok_or_else(|| {
        ImportFailure::Rejected("PFM4 store exposed a non-monetary canonical chain".into())
    })?;
    if candidate.header.network_id != monetary.ledger().network_id() {
        return Err(ImportFailure::Rejected(
            "PMT4 candidate Network ID does not match the PFM4 Genesis".into(),
        ));
    }
    if candidate.header.protocol_version != params.protocol_version {
        return Err(ImportFailure::Rejected(
            "PMT4 candidate protocol version does not match the frozen V4 profile".into(),
        ));
    }
    let height = candidate.header.height;
    if height == 0 {
        return Err(ImportFailure::Rejected(
            "PMT4 candidate height cannot be zero".into(),
        ));
    }
    let digest = pow_digest(&candidate.header, params.pow)
        .map_err(|error| ImportFailure::Rejected(format!("calculate PMT4 digest: {error}")))?;
    let parent_tip = candidate.header.previous_consensus_hash;
    let genesis_tip = store.archive().genesis_tip();
    if (height == 1 && parent_tip != genesis_tip) || (height != 1 && parent_tip == genesis_tip) {
        return Err(ImportFailure::Rejected(
            "PMT4 candidate height does not match the Genesis-parent relationship".into(),
        ));
    }
    let duplicate = store.archive().branch_chain(&digest).is_some();
    let outcome = match store.submit(payload, verifier, clock) {
        Ok(outcome) => outcome,
        Err(V4HybridForkStoreError::Fork(V4HybridForkChoiceError::UnknownParent)) => {
            return Err(ImportFailure::UnknownParent);
        }
        Err(error) => {
            return Err(ImportFailure::Rejected(format!(
                "durable PFM4 store rejected PMT4 candidate: {error}"
            )));
        }
    };
    if outcome.block_digest != digest {
        return Err(ImportFailure::Rejected(
            "PFM4 returned a different candidate digest".into(),
        ));
    }
    Ok((
        if duplicate {
            ACK_STATUS_DUPLICATE
        } else {
            ACK_STATUS_ACCEPTED
        },
        outcome,
    ))
}

fn build_next_monetary_candidate(
    chain: &PrivateTestnetChain,
    params: &ConsensusParameters,
    authenticator: &NodeAuthenticator,
    miner: AccountId,
    timestamp_offset: u64,
    timestamp_backdate: u64,
) -> Result<Vec<u8>, String> {
    let state = chain
        .monetary_state()
        .ok_or("candidate monetary builder received a legacy chain")?;
    let ledger = state.ledger();
    let wall_clock = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock predates Unix epoch")?
        .as_secs();
    let timestamp = wall_clock
        .saturating_add(timestamp_offset)
        .saturating_sub(timestamp_backdate)
        .max(ledger.last_timestamp().saturating_add(1));
    let mut block = MonetaryBlock {
        body: Block {
            height: state
                .height()
                .checked_add(1)
                .ok_or("monetary height overflow")?,
            timestamp,
            parent_hash: state.tip_hash(),
            state_root: [0; 32],
            transactions: Vec::new(),
        },
        miner,
        claimed_subsidy_atoms: state
            .expected_miner_reward()
            .map_err(|error| format!("derive scheduled miner subsidy: {error:?}"))?,
    };
    block.body.state_root = state
        .preview_state_root_after(&block, authenticator)
        .map_err(|error| format!("preview monetary candidate state root: {error:?}"))?;
    let target = chain
        .expected_target(None)
        .map_err(|error| format!("derive monetary PoW target: {error}"))?;

    for nonce in 0..u64::MAX {
        let header = PowHeader {
            protocol_version: params.protocol_version,
            network_id: ledger.network_id(),
            height: block.body.height,
            timestamp: block.body.timestamp,
            parent_hash: block.body.parent_hash,
            previous_consensus_hash: chain.chain_tip().tip_hash,
            state_root: block.body.state_root,
            target,
            nonce,
        };
        let digest = pow_digest(&header, params.pow)
            .map_err(|error| format!("calculate monetary candidate PoW: {error}"))?;
        if Uint256::from_be_bytes(digest) <= target {
            return encode_candidate_monetary_network_block(&header, &block)
                .map_err(|error: MonetaryWireError| format!("encode PMT3 candidate: {error}"));
        }
    }
    Err("monetary candidate nonce search exhausted".into())
}

/// Build the LOCAL PMT4 smoke Genesis only. This is intentionally value-bearing: the monetary
/// state constructor installs the 4B founder and 3B public-goods allocations at height zero.
/// Its derived placeholder accounts and economics are not a public-devnet or production Genesis.
fn local_monetary_v4_genesis(
    network_id: [u8; 32],
) -> Result<(MonetaryLedgerState, AccountId, AccountId, AccountId), String> {
    local_monetary_v4_genesis_with_founder_identity(network_id, None)
}

fn local_monetary_v4_genesis_with_founder_identity(
    network_id: [u8; 32],
    founder_keys: Option<([u8; 32], [u8; ML_DSA_65_PUBLIC_KEY_BYTES])>,
) -> Result<(MonetaryLedgerState, AccountId, AccountId, AccountId), String> {
    let founder = founder_keys
        .as_ref()
        .map(|(ed25519, mldsa65)| native_v4_account_id(ed25519, mldsa65))
        .unwrap_or_else(|| local_monetary_account_id(&network_id, b"v4-founder-placeholder"));
    let public_goods = local_monetary_account_id(&network_id, b"v4-public-goods-placeholder");
    let miner = local_monetary_account_id(&network_id, b"v4-miner-placeholder");
    if founder == public_goods
        || founder == miner
        || public_goods == miner
        || founder.iter().all(|byte| *byte == 0)
        || public_goods.iter().all(|byte| *byte == 0)
        || miner.iter().all(|byte| *byte == 0)
    {
        return Err(
            "derived local V4 monetary placeholder accounts are not distinct/nonzero".into(),
        );
    }
    let public_goods_budget = u64::try_from(MONETARY_PUBLIC_GOODS_BUDGET_ATOMS)
        .map_err(|_| "public-goods allocation does not fit the candidate account type")?;
    let genesis = MonetaryLedgerState::genesis(
        network_id,
        founder,
        vec![(public_goods, public_goods_budget)],
    )
    .map_err(|error| format!("construct PMT4 Genesis: {error:?}"))?;
    Ok((genesis, founder, public_goods, miner))
}

fn configured_local_monetary_v4_genesis(
    config: &Config,
) -> Result<(MonetaryLedgerState, AccountId, AccountId, AccountId), String> {
    match (
        config.v4_founder_ed25519_public_key,
        config.v4_founder_mldsa65_public_key_file.as_ref(),
    ) {
        (None, None) => local_monetary_v4_genesis(config.network_id),
        (Some(ed25519), Some(path)) => {
            let metadata = fs::symlink_metadata(path).map_err(|error| {
                format!(
                    "inspect V4 founder ML-DSA-65 public-key file {}: {error}",
                    path.display()
                )
            })?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(
                    "V4 founder ML-DSA-65 public-key path must be a regular non-symlink file"
                        .into(),
                );
            }
            if metadata.len() != ML_DSA_65_PUBLIC_KEY_BYTES as u64 {
                return Err(format!(
                    "V4 founder ML-DSA-65 public-key file must be exactly {ML_DSA_65_PUBLIC_KEY_BYTES} bytes"
                ));
            }
            let bytes = fs::read(path).map_err(|error| {
                format!(
                    "read V4 founder ML-DSA-65 public key {}: {error}",
                    path.display()
                )
            })?;
            let mldsa65: [u8; ML_DSA_65_PUBLIC_KEY_BYTES] = bytes
                .try_into()
                .map_err(|_| "V4 founder ML-DSA-65 public-key length changed while reading")?;
            if ed25519.iter().all(|byte| *byte == 0) || mldsa65.iter().all(|byte| *byte == 0) {
                return Err("V4 founder public keys must be nonzero".into());
            }
            local_monetary_v4_genesis_with_founder_identity(
                config.network_id,
                Some((ed25519, mldsa65)),
            )
        }
        _ => Err(
            "V4 founder Genesis identity requires both Ed25519 and ML-DSA-65 public keys".into(),
        ),
    }
}

fn run_monetary_v4_hybrid_local_smoke(config: &Config) -> Result<(), String> {
    validate_monetary_candidate_local_config(config)?;
    for marker in [
        "genesis.qvdn",
        "genesis.manifest",
        "monetary-genesis.mgn3",
        "devnet_forkstore_ptb2",
        "forkstore_ptb2",
        "devnet_forkstore_pfm3",
    ] {
        let path = config.data_dir.join(marker);
        if path_entry_exists(&path)? {
            return Err(format!(
                "PMT4/PFM4 profile refuses an existing legacy/PFM3 profile path: {}",
                path.display()
            ));
        }
    }

    let profile = DevnetProfileCandidate::new(config.network_id)
        .map_err(|error| format!("V4 hybrid Devnet profile rejected: {error}"))?;
    let (genesis, _founder, _public_goods, miner) = configured_local_monetary_v4_genesis(config)?;
    let genesis_value_atoms = genesis
        .total_value()
        .map_err(|error| format!("validate local PMT4 Genesis value: {error:?}"))?;
    let mut params = profile.consensus().clone();
    // This explicitly offline-only fixture makes the complete PFM4 producer/import/reopen loop
    // fast. It is not the real Devnet PoW profile and cannot be used as launch-consensus evidence.
    params.initial_target = Uint256::MAX;
    params.pow.memory_kib = 8 * 1024;
    params
        .validate()
        .map_err(|error| format!("invalid PMT4 local smoke PoW profile: {error}"))?;
    let manifest_id = local_monetary_v4_manifest_id(&profile, &params);
    let genesis_manifest =
        encode_monetary_v4_genesis_manifest(&profile, &params, &genesis, &manifest_id)?;
    persist_or_verify_monetary_v4_genesis_manifest(&config.data_dir, &genesis_manifest)?;

    let verifier = LibcruxMlDsa65VerifierCandidate;
    let clock = SystemClockReferenceTime;
    let store_dir = config.data_dir.join("devnet_forkstore_pfm4");
    let mut store = PrivateTestnetV4HybridForkStore::open(
        &store_dir,
        genesis,
        params.clone(),
        manifest_id,
        &verifier,
        &clock,
    )
    .map_err(|error| format!("open PFM4 hybrid candidate store: {error}"))?;
    let initial_height = store.canonical_height();
    eprintln!(
        "event=monetary_v4_hybrid_local_smoke_ready mode=offline_only network={} height={} genesis_value_atoms={} genesis_profile=LOCAL_RESEARCH_40_30_30 value_bearing=true store=PFM4 wire=PMT4 tx_policy=RejectAll pow_profile=LOCAL_EASY_POW_8MIB target=MAX runtime_dispatch=explicit_v4 public_launch_approved=false",
        hex(&config.network_id),
        initial_height,
        genesis_value_atoms,
    );

    let started = Instant::now();
    let deadline = Duration::from_secs(config.run_seconds);
    for _ in 0..config.mine_blocks {
        if started.elapsed() >= deadline {
            return Err("PMT4/PFM4 local smoke exceeded --run-seconds".into());
        }
        let previous_height = store.canonical_height();
        let parent = store.archive().canonical_chain().clone();
        let payload = build_next_v4_hybrid_monetary_candidate(
            &parent,
            &params,
            &manifest_id,
            &verifier,
            miner,
            config.timestamp_offset,
            config.timestamp_backdate,
        )?;
        let (status, outcome) =
            import_v4_hybrid_monetary_payload(&payload, &mut store, &params, &verifier, &clock)
                .map_err(|error| {
                    format!("PMT4 versioned runtime import rejected the candidate: {error}")
                })?;
        if status != ACK_STATUS_ACCEPTED
            || !outcome.canonical_changed
            || outcome.canonical_height != previous_height.saturating_add(1)
        {
            return Err(
                "PFM4 did not advance the expected canonical PMT4 height through explicit import"
                    .into(),
            );
        }
        let canonical = store.archive().canonical_chain();
        let monetary = canonical
            .monetary_state()
            .ok_or("PFM4 canonical tip has no monetary state")?;
        let ack_wire = encode_monetary_ack_v4(
            status,
            outcome.canonical_height,
            outcome.block_digest,
            canonical,
            config.network_id,
            manifest_id,
            params.protocol_version,
        )?;
        let ack = decode_monetary_ack_v4(&ack_wire)?;
        if ack.status != status
            || ack.candidate_height != outcome.canonical_height
            || ack.candidate_digest != outcome.block_digest
            || ack.canonical_height != monetary.height()
            || ack.state_root != monetary.state_root()
            || ack.consensus_tip != canonical.chain_tip().tip_hash
            || !monetary_ack_v4_matches_profile(
                &ack,
                &config.network_id,
                &manifest_id,
                params.protocol_version,
            )
        {
            return Err(
                "MTA4 offline self-check did not match the PMT4/PFM4 candidate profile".into(),
            );
        }
        eprintln!(
            "event=monetary_v4_hybrid_local_block_accepted wire=PMT4 ack_profile=MTA4 ack_transport=not_emitted height={} digest={} state_root={} tip={} total_value_atoms={} total_mined_atoms={} archive_branches={} reorg_count={}",
            monetary.height(),
            hex(&outcome.block_digest),
            hex(&monetary.state_root()),
            hex(&canonical.chain_tip().tip_hash),
            monetary.total_value().map_err(|error| format!("validate PMT4 supply: {error:?}"))?,
            monetary.total_mined_atoms(),
            store.archive().archive_len(),
            outcome.reorg_count,
        );
    }

    let final_height = store.canonical_height();
    let final_tip = store.canonical_tip();
    let final_state_root = store
        .archive()
        .canonical_chain()
        .monetary_state()
        .ok_or("PFM4 final canonical tip has no monetary state")?
        .state_root();
    let final_anchor = store
        .manifest_anchor()
        .map_err(|error| format!("commit local PFM4 reopen anchor: {error}"))?;
    drop(store);

    let (genesis, _, _, _) = configured_local_monetary_v4_genesis(config)?;
    let reopened = PrivateTestnetV4HybridForkStore::open_anchored(
        &store_dir,
        genesis,
        params,
        manifest_id,
        &verifier,
        &clock,
        final_anchor,
    )
    .map_err(|error| format!("replay PFM4 after runtime smoke: {error}"))?;
    let replayed = reopened
        .archive()
        .canonical_chain()
        .monetary_state()
        .ok_or("PFM4 replayed canonical tip has no monetary state")?;
    if reopened.canonical_height() != final_height
        || reopened.canonical_tip() != final_tip
        || replayed.state_root() != final_state_root
        || reopened
            .manifest_anchor()
            .map_err(|error| format!("recheck PFM4 anchor: {error}"))?
            != final_anchor
    {
        return Err(
            "PMT4/PFM4 restart changed canonical tip, state root, or manifest commitment".into(),
        );
    }
    eprintln!(
        "event=monetary_v4_hybrid_local_smoke_stopped wire=PMT4 store=PFM4 height={} state_root={} tip={} archive_branches={} replay=matched anchor=local_only transactions=empty_only public_launch_approved=false",
        replayed.height(),
        hex(&replayed.state_root()),
        hex(&reopened.canonical_tip()),
        reopened.archive().archive_len(),
    );
    Ok(())
}

fn run_monetary_candidate_local_smoke(config: &Config) -> Result<(), String> {
    validate_monetary_candidate_local_config(config)?;
    let isolation_markers = [
        "genesis.qvdn",
        "genesis.manifest",
        "monetary-genesis.mgn4",
        "devnet_forkstore_pfm4",
        "devnet_forkstore_ptb2",
        "forkstore_ptb2",
    ];
    for marker in isolation_markers {
        let path = config.data_dir.join(marker);
        if path_entry_exists(&path)? {
            return Err(format!(
                "monetary profile refuses an existing legacy/QVDN profile path: {}",
                path.display()
            ));
        }
    }

    let profile = DevnetProfileCandidate::new(config.network_id)
        .map_err(|error| format!("monetary candidate profile rejected: {error}"))?;
    let founder = local_monetary_account_id(&config.network_id, b"founder-placeholder");
    let public_goods = local_monetary_account_id(&config.network_id, b"public-goods-placeholder");
    let miner = local_monetary_account_id(&config.network_id, b"miner-placeholder");
    if founder == public_goods
        || founder == miner
        || public_goods == miner
        || founder.iter().all(|byte| *byte == 0)
        || public_goods.iter().all(|byte| *byte == 0)
        || miner.iter().all(|byte| *byte == 0)
    {
        return Err("derived local monetary placeholder accounts are not distinct/nonzero".into());
    }
    let genesis = MonetaryLedgerState::genesis(
        config.network_id,
        founder,
        vec![(
            public_goods,
            u64::try_from(MONETARY_PUBLIC_GOODS_BUDGET_ATOMS)
                .map_err(|_| "public-goods allocation does not fit the candidate account type")?,
        )],
    )
    .map_err(|error| format!("construct candidate monetary Genesis: {error:?}"))?;
    let mut params = profile.consensus().clone();
    // This opt-in local smoke profile avoids spending minutes on every nonce while still
    // exercising MBK3/PMT3 admission and PFM3 persistence. Its independent MGN3 fingerprint
    // records these test-only parameters; real Devnet PoW remains unchanged and unproven here.
    params.initial_target = Uint256::MAX;
    params.pow.memory_kib = 8 * 1024;
    params
        .validate()
        .map_err(|error| format!("invalid local monetary smoke PoW profile: {error}"))?;
    let genesis_manifest = encode_monetary_genesis_manifest(&profile, &params, &genesis)?;
    persist_or_verify_monetary_genesis_manifest(&config.data_dir, &genesis_manifest)?;
    let auth = NodeAuthenticator::RejectAll;
    let clock = SystemClockReferenceTime;
    let store_dir = config.data_dir.join("devnet_forkstore_pfm3");
    let mut store =
        PrivateTestnetMonetaryForkStore::open(&store_dir, genesis, params.clone(), &auth, &clock)
            .map_err(|error| format!("open PFM3 monetary candidate store: {error}"))?;
    let initial_height = store.canonical_height();
    eprintln!(
        "event=monetary_candidate_local_smoke_ready mode=offline_only pow_profile=LOCAL_EASY_POW_8MIB target=MAX network={} genesis_height={} genesis_value_atoms={} store=PFM3 wire=PMT3 transactions=RejectAll public_launch_approved=false",
        hex(&config.network_id),
        initial_height,
        store.archive().canonical_chain().monetary_state()
            .ok_or("PFM3 reopened a non-monetary chain")?
            .total_value()
            .map_err(|error| format!("validate monetary Genesis total: {error:?}"))?
    );

    let started = Instant::now();
    let deadline = Duration::from_secs(config.run_seconds);
    for _ in 0..config.mine_blocks {
        if started.elapsed() >= deadline {
            return Err("monetary candidate local smoke exceeded --run-seconds".into());
        }
        let previous_height = store.canonical_height();
        let chain = store.archive().canonical_chain().clone();
        let payload = build_next_monetary_candidate(
            &chain,
            &params,
            &auth,
            miner,
            config.timestamp_offset,
            config.timestamp_backdate,
        )?;
        let (status, outcome) = import_monetary_payload(
            &payload, &mut store, &params, &auth, &clock,
        )
        .map_err(|error| format!("PFM3 monetary admission refused local candidate: {error}"))?;
        let digest = outcome.block_digest;
        if status != ACK_STATUS_ACCEPTED
            || outcome.canonical_height != previous_height.saturating_add(1)
            || !outcome.canonical_changed
        {
            return Err(
                "PFM3 candidate did not advance the expected canonical monetary height".into(),
            );
        }
        let canonical = store.archive().canonical_chain();
        let monetary = canonical
            .monetary_state()
            .ok_or("PFM3 canonical tip has no monetary ledger")?;
        let monetary_ack =
            encode_monetary_ack_v3(status, previous_height.saturating_add(1), digest, canonical)?;
        let decoded_ack = decode_monetary_ack_v3(&monetary_ack)?;
        if decoded_ack.status != status
            || decoded_ack.candidate_height != previous_height.saturating_add(1)
            || decoded_ack.candidate_digest != digest
            || decoded_ack.canonical_height != monetary.height()
            || decoded_ack.state_root != monetary.state_root()
            || decoded_ack.consensus_tip != canonical.chain_tip().tip_hash
        {
            return Err("MTA3 acknowledgement did not bind the accepted monetary state".into());
        }
        eprintln!(
            "event=monetary_candidate_local_block_accepted ack=MTA3 height={} block_digest={} state_root={} tip={} total_value_atoms={} total_mined_atoms={} archive_branches={}",
            monetary.height(),
            hex(&digest),
            hex(&monetary.state_root()),
            hex(&canonical.chain_tip().tip_hash),
            monetary.total_value().map_err(|error| format!("validate monetary supply after submit: {error:?}"))?,
            monetary.total_mined_atoms(),
            store.archive().archive_len()
        );
    }
    let final_height = store.canonical_height();
    let final_tip = store.canonical_tip();
    drop(store);

    // Reopen the same PFM3 store inside this invocation as a final deterministic replay check.
    let genesis = MonetaryLedgerState::genesis(
        config.network_id,
        founder,
        vec![(
            public_goods,
            u64::try_from(MONETARY_PUBLIC_GOODS_BUDGET_ATOMS)
                .map_err(|_| "public-goods allocation does not fit the candidate account type")?,
        )],
    )
    .map_err(|error| format!("rebuild candidate monetary Genesis for replay: {error:?}"))?;
    let reopened =
        PrivateTestnetMonetaryForkStore::open(&store_dir, genesis, params, &auth, &clock)
            .map_err(|error| format!("replay PFM3 monetary candidate store: {error}"))?;
    if reopened.canonical_height() != final_height || reopened.canonical_tip() != final_tip {
        return Err("PFM3 replay changed the persisted canonical monetary tip".into());
    }
    let canonical = reopened.archive().canonical_chain();
    let monetary = canonical
        .monetary_state()
        .ok_or("PFM3 replayed tip has no monetary ledger")?;
    eprintln!(
        "event=monetary_candidate_local_smoke_stopped height={} state_root={} tip={} total_value_atoms={} total_mined_atoms={} replay=matched local_only=true public_launch_approved=false",
        monetary.height(),
        hex(&monetary.state_root()),
        hex(&canonical.chain_tip().tip_hash),
        monetary.total_value().map_err(|error| format!("validate replayed monetary supply: {error:?}"))?,
        monetary.total_mined_atoms()
    );
    Ok(())
}

fn validate_monetary_candidate_peer_config(config: &Config) -> Result<(), String> {
    if !config.listen.ip().is_loopback() {
        return Err("monetary peer smoke refuses non-loopback listen addresses".into());
    }
    if let Some(address) = config.status_listen {
        if !address.ip().is_loopback() {
            return Err("monetary peer smoke status API must bind loopback only".into());
        }
        if address == config.listen {
            return Err("monetary peer smoke status API must use a distinct listen address".into());
        }
    }
    if config.peers.is_empty() {
        return Err("monetary peer smoke requires at least one loopback peer".into());
    }
    if config.peers.iter().any(|peer| !peer.ip().is_loopback()) {
        return Err("monetary peer smoke refuses non-loopback peers".into());
    }
    if !config.trusted_peer_identity_files.is_empty() && !config.trusted_peer_keys.is_empty() {
        return Err(
            "monetary peer smoke refuses mixed raw and signed-identity trust entries".into(),
        );
    }
    let trust_entry_count = if config.trusted_peer_identity_files.is_empty() {
        config.trusted_peer_keys.len()
    } else {
        config.trusted_peer_identity_files.len()
    };
    if trust_entry_count != config.peers.len() {
        return Err("monetary peer smoke requires exactly one trust entry per peer".into());
    }
    if config.noise_static_private_key_dpapi_file.is_none() {
        return Err("monetary peer smoke requires authenticated Noise static-key pins".into());
    }
    if config.test_transactions
        || config.test_seed_file.is_some()
        || config.archive_sync_reverse_first_round
    {
        return Err(
            "monetary peer smoke refuses transaction fixtures and legacy archive-sync controls"
                .into(),
        );
    }
    if config.archive_sync_delay_ms != 0 || config.archive_range_post_commit_delay_ms != 0 {
        return Err("monetary peer smoke refuses legacy archive-sync timing/fault controls".into());
    }
    if !(1..=16).contains(&config.archive_range_max_page_items) {
        return Err("monetary archive range page item limit must be in 1..=16".into());
    }
    if config.monetary_candidate_archive_range_sync && config.archive_range_max_page_items != 1 {
        return Err(
            "monetary archive range sync requires exactly one envelope per page until PFM3 import and ARW commit are atomic"
                .into(),
        );
    }
    if config.mine_blocks > 0 && !config.exit_after_mining && config.stop_after_height.is_none() {
        return Err("monetary peer smoke requires a bounded mining stop condition".into());
    }
    Ok(())
}

fn monetary_candidate_genesis(network_id: [u8; 32]) -> Result<MonetaryLedgerState, String> {
    let founder = local_monetary_account_id(&network_id, b"founder-placeholder");
    let public_goods = local_monetary_account_id(&network_id, b"public-goods-placeholder");
    let miner = local_monetary_account_id(&network_id, b"miner-placeholder");
    if founder == public_goods
        || founder == miner
        || public_goods == miner
        || founder.iter().all(|byte| *byte == 0)
        || public_goods.iter().all(|byte| *byte == 0)
        || miner.iter().all(|byte| *byte == 0)
    {
        return Err("derived monetary placeholder accounts are not distinct/nonzero".into());
    }
    MonetaryLedgerState::genesis(
        network_id,
        founder,
        vec![(
            public_goods,
            u64::try_from(MONETARY_PUBLIC_GOODS_BUDGET_ATOMS)
                .map_err(|_| "public-goods allocation does not fit the candidate account type")?,
        )],
    )
    .map_err(|error| format!("construct candidate monetary Genesis: {error:?}"))
}

fn write_peer_monetary_ack(
    stream: &mut TcpStream,
    noise_session: &mut Option<DevnetNoiseSession>,
    ack: &[u8; MONETARY_ACK_LEN],
) -> io::Result<()> {
    match noise_session {
        Some(session) => session.write_record(stream, ack).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Noise MTA3 ACK encryption failed: {error}"),
            )
        }),
        None => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "monetary peer mode refuses plaintext MTA3 acknowledgements",
        )),
    }
}

fn monetary_candidate_identity(
    payload: &[u8],
    params: &ConsensusParameters,
) -> Option<(u64, [u8; 32])> {
    let candidate = decode_candidate_monetary_network_block(payload).ok()?;
    let digest = pow_digest(&candidate.header, params.pow).ok()?;
    Some((candidate.header.height, digest))
}

fn monetary_archive_snapshot_is_current(
    store: &PrivateTestnetMonetaryForkStore,
    snapshot_manifest_anchor: &[u8; 32],
) -> Result<bool, String> {
    let current_anchor = store
        .manifest_anchor()
        .map_err(|error| format!("read PFM3 archive manifest anchor: {error:?}"))?;
    Ok(&current_anchor == snapshot_manifest_anchor)
}

fn force_test_monetary_reorg_after_archive_page(
    store: &mut PrivateTestnetMonetaryForkStore,
    params: &ConsensusParameters,
    auth: &NodeAuthenticator,
    clock: &SystemClockReferenceTime,
    network_id: &[u8; 32],
) -> Result<(), String> {
    let previous_tip = store.canonical_tip();
    let genesis = monetary_candidate_genesis(*network_id)?;
    let mut parent = PrivateTestnetChain::new_monetary(genesis, params.clone())
        .map_err(|error| format!("build test reorg Genesis: {error}"))?;
    let miner = local_monetary_account_id(network_id, b"AIN1-wire-reorg-after-page-test");
    let mut final_reorg = false;
    for height in 1..=4 {
        let payload = build_next_monetary_candidate(&parent, params, auth, miner, 0, 0)?;
        let (status, outcome) = import_monetary_payload(&payload, store, params, auth, clock)
            .map_err(|error| format!("import test reorg candidate at height {height}: {error}"))?;
        if status != ACK_STATUS_ACCEPTED {
            return Err(format!(
                "test reorg candidate at height {height} was not newly accepted"
            ));
        }
        parent = store
            .archive()
            .branch_chain(&outcome.block_digest)
            .ok_or_else(|| format!("test reorg candidate at height {height} was not archived"))?
            .clone();
        if height == 4 {
            final_reorg = outcome.canonical_changed;
        }
    }
    if !final_reorg || store.canonical_height() != 4 || store.canonical_tip() == previous_tip {
        return Err("test branch did not reorg canonical PFM3 state to height 4".into());
    }
    eprintln!(
        "event=test_fault_reorg_after_archive_page old_tip={} new_tip={} canonical_height=4",
        hex(&previous_tip),
        hex(&store.canonical_tip())
    );
    Ok(())
}

fn serve_completed_monetary_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    payload_result: io::Result<Vec<u8>>,
    mut noise_session: Option<DevnetNoiseSession>,
    store: &mut PrivateTestnetMonetaryForkStore,
    params: &ConsensusParameters,
    auth: &NodeAuthenticator,
    clock: &SystemClockReferenceTime,
    archive_range_server: Option<&ArchiveRangeServerCandidate>,
    archive_range_snapshot_anchor: Option<[u8; 32]>,
    test_reorg_after_first_archive_page: &mut bool,
    local_noise_private_key: &[u8; 32],
    network_id: &[u8; 32],
) {
    let peer = peer_addr.to_string();
    let payload = match payload_result {
        Ok(payload) => payload,
        Err(error) => {
            eprintln!(
                "event=monetary_peer_frame_rejected peer={peer} reason={}",
                sanitize(&error.to_string())
            );
            // Failed handshakes and unauthenticated frames receive no reply at all.
            if noise_session.is_none() {
                return;
            }
            let canonical = store.archive().canonical_chain();
            if let Ok(ack) = encode_monetary_ack_v3(ACK_STATUS_REJECTED, 0, [0; 32], canonical) {
                let _ = write_peer_monetary_ack(&mut stream, &mut noise_session, &ack);
            }
            return;
        }
    };
    if payload.get(..4) == Some(ARCHIVE_RANGE_REQUEST_MAGIC.as_slice()) {
        let Some(server) = archive_range_server else {
            eprintln!(
                "event=monetary_archive_range_request_rejected peer={peer} reason=feature_disabled"
            );
            return;
        };
        let Some(session) = noise_session.as_mut() else {
            eprintln!("event=monetary_archive_range_request_rejected peer={peer} reason=no_authenticated_noise_session");
            return;
        };
        let Some(snapshot_anchor) = archive_range_snapshot_anchor.as_ref() else {
            eprintln!("event=monetary_archive_range_request_rejected peer={peer} snapshot={} reason=missing_snapshot_anchor", hex(&server.snapshot_commitment()));
            return;
        };
        match monetary_archive_snapshot_is_current(store, snapshot_anchor) {
            Ok(true) => {}
            Ok(false) => {
                eprintln!("event=monetary_archive_range_request_rejected peer={peer} snapshot={} reason=stale_snapshot manifest_anchor_changed=true", hex(&server.snapshot_commitment()));
                return;
            }
            Err(error) => {
                eprintln!("event=monetary_archive_range_request_rejected peer={peer} snapshot={} reason={}", hex(&server.snapshot_commitment()), sanitize(&error));
                return;
            }
        }
        match serve_archive_range_request(
            &mut stream,
            &payload,
            session,
            server,
            local_noise_private_key,
            network_id,
        ) {
            Err(error) => {
                eprintln!(
                    "event=monetary_archive_range_request_rejected peer={peer} snapshot={} reason={}",
                    hex(&server.snapshot_commitment()),
                    sanitize(&error)
                );
            }
            Ok(()) if *test_reorg_after_first_archive_page => {
                // The first page has been sent over the authenticated wire. Force a deterministic
                // competing-branch reorg before the event loop can accept the client's next cursor.
                *test_reorg_after_first_archive_page = false;
                if let Err(error) = force_test_monetary_reorg_after_archive_page(
                    store, params, auth, clock, network_id,
                ) {
                    eprintln!(
                        "event=test_fault_reorg_after_archive_page_failed peer={peer} reason={}",
                        sanitize(&error)
                    );
                }
            }
            Ok(()) => {}
        }
        return;
    }
    let identity = monetary_candidate_identity(&payload, params).unwrap_or((0, [0; 32]));
    let (status, candidate_height, candidate_digest) = match import_monetary_payload(
        &payload, store, params, auth, clock,
    ) {
        Ok((status, outcome)) => {
            if outcome.block_digest != identity.1 || identity.0 == 0 {
                eprintln!("event=monetary_peer_import_invariant_failed peer={peer}");
                (ACK_STATUS_REJECTED, identity.0, identity.1)
            } else {
                (status, identity.0, outcome.block_digest)
            }
        }
        Err(ImportFailure::UnknownParent) => {
            eprintln!("event=monetary_peer_candidate_deferred peer={peer} reason=unknown_parent retryable=true");
            (ACK_STATUS_UNKNOWN_PARENT, identity.0, identity.1)
        }
        Err(ImportFailure::Rejected(reason)) => {
            eprintln!(
                "event=monetary_peer_candidate_rejected peer={peer} reason={}",
                sanitize(&reason)
            );
            (ACK_STATUS_REJECTED, identity.0, identity.1)
        }
    };
    let canonical = store.archive().canonical_chain();
    match encode_monetary_ack_v3(status, candidate_height, candidate_digest, canonical) {
        Ok(ack) => {
            if let Err(error) = write_peer_monetary_ack(&mut stream, &mut noise_session, &ack) {
                eprintln!(
                    "event=monetary_peer_ack_write_failed peer={peer} reason={}",
                    sanitize(&error.to_string())
                );
                return;
            }
            let monetary = canonical.monetary_state();
            eprintln!(
                "event=monetary_peer_ack_sent peer={peer} ack=MTA3 status={} candidate_height={} candidate_digest={} canonical_height={} state_root={} tip={}",
                status,
                candidate_height,
                hex(&candidate_digest),
                monetary.map_or(0, |state| state.height()),
                monetary.map_or_else(|| "none".into(), |state| hex(&state.state_root())),
                hex(&canonical.chain_tip().tip_hash)
            );
        }
        Err(error) => eprintln!(
            "event=monetary_peer_ack_encode_failed peer={peer} reason={}",
            sanitize(&error)
        ),
    }
}

fn send_monetary_to_peer_with_noise_attempts(
    peer: SocketAddr,
    payload: &[u8],
    expected_height: u64,
    expected_digest: [u8; 32],
    max_attempts: usize,
    noise: &NoiseOutboundConfig,
) -> Result<u8, String> {
    if max_attempts == 0 {
        return Err("monetary peer send attempt limit must be nonzero".into());
    }
    let mut last_error = String::from("monetary peer unreachable");
    for attempt in 0..max_attempts {
        // Trust is refreshed before every dial; failure never falls back to a stale pin.
        let remote_pin = noise.trusted_pin(peer)?;
        match TcpStream::connect_timeout(&peer, Duration::from_millis(500)) {
            Ok(mut stream) => {
                if let Err(error) = stream
                    .set_nodelay(true)
                    .and_then(|_| stream.set_read_timeout(Some(WIRE_READ_TIMEOUT)))
                    .and_then(|_| stream.set_write_timeout(Some(WIRE_READ_TIMEOUT)))
                {
                    last_error = format!("configure monetary Noise peer socket: {error}");
                } else {
                    match DevnetNoiseSession::connect(
                        &mut stream,
                        &noise.local_static_private_key.0,
                        &remote_pin,
                        &noise.network_id,
                    ) {
                        Err(error) => {
                            last_error =
                                format!("monetary Noise peer authentication failed: {error}");
                        }
                        Ok(mut session) => match session.write_record(&mut stream, payload) {
                            Err(error) => last_error = format!("write PMT3 peer record: {error}"),
                            Ok(()) => match session.read_record(&mut stream) {
                                Err(error) => {
                                    last_error = format!("read MTA3 peer record: {error}")
                                }
                                Ok(wire) => {
                                    let ack = decode_monetary_ack_v3(&wire).map_err(|error| {
                                        format!("peer {peer} returned malformed MTA3 ACK: {error}")
                                    })?;
                                    if ack.candidate_height != expected_height
                                        || ack.candidate_digest != expected_digest
                                    {
                                        return Err(format!(
                                            "peer {peer} MTA3 ACK does not bind submitted PMT3 candidate"
                                        ));
                                    }
                                    match ack.status {
                                        ACK_STATUS_ACCEPTED | ACK_STATUS_DUPLICATE => {
                                            return Ok(ack.status)
                                        }
                                        ACK_STATUS_UNKNOWN_PARENT => {
                                            // Let the caller replay the already-validated missing
                                            // ancestry from its durable PFM3 archive, then retry the
                                            // submitted block. Blindly resending this child cannot
                                            // repair an UnknownParent condition.
                                            eprintln!(
                                                "event=monetary_peer_ancestor_repair_required peer={peer} height={expected_height} attempt={}",
                                                attempt + 1
                                            );
                                            return Ok(ACK_STATUS_UNKNOWN_PARENT);
                                        }
                                        _ => {
                                            return Err(format!(
                                                "peer {peer} permanently rejected PMT3 height {expected_height} with MTA3 status {}",
                                                ack.status
                                            ));
                                        }
                                    }
                                }
                            },
                        },
                    }
                }
            }
            Err(error) => last_error = format!("connect monetary peer {peer}: {error}"),
        }
        if attempt + 1 < max_attempts {
            thread::sleep(PEER_SEND_RETRY_DELAY);
        }
    }
    Err(last_error)
}

fn monetary_ancestor_path_before_candidate(
    store: &PrivateTestnetMonetaryForkStore,
    candidate_payload: &[u8],
    params: &ConsensusParameters,
) -> Result<Vec<Vec<u8>>, String> {
    monetary_ancestor_path_from_archive(
        store.archive().archive_envelopes_iter(),
        candidate_payload,
        params,
        MAX_ARCHIVE_SYNC_BRANCHES,
        MAX_ARCHIVE_SYNC_BYTES,
    )
}

fn monetary_ancestor_path_from_archive<'a>(
    archive_payloads: impl IntoIterator<Item = &'a [u8]>,
    candidate_payload: &[u8],
    params: &ConsensusParameters,
    max_branches: usize,
    max_bytes: usize,
) -> Result<Vec<Vec<u8>>, String> {
    let candidate = decode_candidate_monetary_network_block(candidate_payload)
        .map_err(|error| format!("decode PMT3 candidate for ancestor recovery: {error}"))?;
    if candidate.header.height <= 1 {
        return Ok(Vec::new());
    }

    // Borrow committed PMT3 envelopes rather than cloning the entire archive. The map keeps
    // only validated chain metadata and a slice into the archive; payload bytes are copied
    // only for ancestors that are actually selected for replay.
    //
    // previous_consensus_hash links to the preceding consensus block digest; parent_hash
    // instead binds the ledger-state tip.
    let mut by_digest: BTreeMap<[u8; 32], (u64, [u8; 32], &'a [u8])> = BTreeMap::new();
    for payload in archive_payloads {
        let decoded = decode_candidate_monetary_network_block(payload)
            .map_err(|error| format!("decode stored PMT3 ancestor: {error}"))?;
        let digest = pow_digest(&decoded.header, params.pow)
            .map_err(|error| format!("hash stored PMT3 ancestor: {error}"))?;
        if by_digest
            .insert(
                digest,
                (
                    decoded.header.height,
                    decoded.header.previous_consensus_hash,
                    payload,
                ),
            )
            .is_some()
        {
            return Err("PFM3 archive contains duplicate PMT3 block digests".into());
        }
    }

    let mut current_digest = candidate.header.previous_consensus_hash;
    let mut expected_height = candidate.header.height - 1;
    let mut reverse_path: Vec<(u64, [u8; 32], Vec<u8>)> = Vec::new();
    let mut total_bytes = 0usize;

    while expected_height > 0 {
        let Some((stored_height, parent_digest, payload)) = by_digest.get(&current_digest) else {
            return Err(format!(
                "PFM3 archive is missing required ancestor at height {expected_height}"
            ));
        };
        if *stored_height != expected_height {
            return Err(format!(
                "PFM3 ancestry height mismatch: expected {expected_height}, found {stored_height}"
            ));
        }
        total_bytes = total_bytes
            .checked_add(payload.len())
            .ok_or("PMT3 ancestor byte count overflow")?;
        if reverse_path.len() >= max_branches || total_bytes > max_bytes {
            return Err("PMT3 ancestor replay exceeds the bounded repair budget".into());
        }
        reverse_path.push((expected_height, current_digest, payload.to_vec()));
        current_digest = *parent_digest;
        expected_height -= 1;
    }

    reverse_path.reverse();
    Ok(reverse_path
        .into_iter()
        .map(|(_, _, payload)| payload)
        .collect())
}

fn send_monetary_candidate_with_ancestor_repair(
    peer: SocketAddr,
    payload: &[u8],
    expected_height: u64,
    expected_digest: [u8; 32],
    store: &PrivateTestnetMonetaryForkStore,
    params: &ConsensusParameters,
    max_attempts: usize,
    noise: &NoiseOutboundConfig,
) -> Result<u8, String> {
    let status = send_monetary_to_peer_with_noise_attempts(
        peer,
        payload,
        expected_height,
        expected_digest,
        max_attempts,
        noise,
    )?;
    if status != ACK_STATUS_UNKNOWN_PARENT {
        return Ok(status);
    }

    let ancestors = monetary_ancestor_path_before_candidate(store, payload, params)?;
    if ancestors.is_empty() {
        return Err(format!(
            "peer {peer} reported UnknownParent for height {expected_height}, but no local ancestors are available; check Genesis/network identity"
        ));
    }
    eprintln!(
        "event=monetary_peer_ancestor_replay_started peer={peer} target_height={expected_height} ancestor_count={}",
        ancestors.len()
    );
    for ancestor in &ancestors {
        let decoded = decode_candidate_monetary_network_block(&ancestor)
            .map_err(|error| format!("decode ancestor PMT3 before replay: {error}"))?;
        let height = decoded.header.height;
        let digest = pow_digest(&decoded.header, params.pow)
            .map_err(|error| format!("hash ancestor PMT3 before replay: {error}"))?;
        let status = send_monetary_to_peer_with_noise_attempts(
            peer,
            &ancestor,
            height,
            digest,
            max_attempts,
            noise,
        )?;
        if !matches!(status, ACK_STATUS_ACCEPTED | ACK_STATUS_DUPLICATE) {
            return Err(format!(
                "peer {peer} could not replay ancestry block at height {height}; MTA3 status={status}"
            ));
        }
    }
    eprintln!(
        "event=monetary_peer_ancestor_replay_complete peer={peer} target_height={expected_height} ancestor_count={}",
        ancestors.len()
    );

    let status = send_monetary_to_peer_with_noise_attempts(
        peer,
        payload,
        expected_height,
        expected_digest,
        max_attempts,
        noise,
    )?;
    if status == ACK_STATUS_UNKNOWN_PARENT {
        return Err(format!(
            "peer {peer} still reports UnknownParent for height {expected_height} after bounded ancestor replay"
        ));
    }
    Ok(status)
}

fn validate_monetary_v4_peer_config(config: &Config) -> Result<(), String> {
    if !config.listen.ip().is_loopback() {
        return Err("PMT4 peer smoke refuses non-loopback listen addresses".into());
    }
    if let Some(address) = config.status_listen {
        if !address.ip().is_loopback() || address == config.listen {
            return Err("PMT4 status API must use a distinct loopback address".into());
        }
    }
    if let Some(address) = config.transaction_listen {
        if !address.ip().is_loopback()
            || address == config.listen
            || Some(address) == config.status_listen
        {
            return Err("PMT4 transaction API must use a distinct loopback address".into());
        }
    }
    if config.peers.is_empty() || config.peers.iter().any(|peer| !peer.ip().is_loopback()) {
        return Err("PMT4 peer smoke requires loopback peers only".into());
    }
    if config.test_reorg_after_second_archive_range_page && config.peers.len() != 1 {
        return Err("second-page PMT4/PFM4 reorg fault requires exactly one loopback peer".into());
    }
    if !config.trusted_peer_identity_files.is_empty() && !config.trusted_peer_keys.is_empty() {
        return Err("PMT4 peer smoke refuses mixed raw and signed-identity trust entries".into());
    }
    let trust_count = if config.trusted_peer_identity_files.is_empty() {
        config.trusted_peer_keys.len()
    } else {
        config.trusted_peer_identity_files.len()
    };
    if trust_count != config.peers.len() || config.noise_static_private_key_dpapi_file.is_none() {
        return Err("PMT4 peer smoke requires one trusted Noise identity per peer and a protected local key".into());
    }
    if config.test_transactions
        || config.test_seed_file.is_some()
        || config.archive_sync_delay_ms != 0
        || config.archive_sync_reverse_first_round
        || config.monetary_candidate_archive_range_sync
        || config.test_crash_after_monetary_import
        || (config.test_reorg_after_first_archive_range_page
            && !config.monetary_v4_hybrid_archive_range_sync)
        || (config.test_reorg_after_second_archive_range_page
            && !config.monetary_v4_hybrid_archive_range_sync)
        || (config.test_crash_after_monetary_v4_import
            && !config.monetary_v4_hybrid_archive_range_sync)
        || (!config.monetary_v4_hybrid_archive_range_sync
            && (config.archive_range_max_page_items != 16
                || config.archive_range_post_commit_delay_ms != 0))
        || (config.monetary_v4_hybrid_archive_range_sync
            && !(1..=16).contains(&config.archive_range_max_page_items))
    {
        return Err(
            "PMT4 peer smoke refuses transaction fixtures and PFM3 archive-sync/fault controls"
                .into(),
        );
    }
    if config.mine_blocks > 0 && !config.exit_after_mining && config.stop_after_height.is_none() {
        return Err("PMT4 peer smoke requires a bounded mining stop condition".into());
    }
    Ok(())
}

fn force_test_monetary_v4_reorg_after_archive_page(
    store: &mut PrivateTestnetV4HybridForkStore,
    params: &ConsensusParameters,
    manifest_id: &[u8; 32],
    verifier: &LibcruxMlDsa65VerifierCandidate,
    clock: &SystemClockReferenceTime,
    network_id: &[u8; 32],
    trigger_page: u64,
) -> Result<(), String> {
    let previous_tip = store.canonical_tip();
    let (genesis, _founder, _public_goods, _initial_miner) =
        local_monetary_v4_genesis(*network_id)?;
    let mut parent = PrivateTestnetChain::new_monetary(genesis, params.clone())
        .map_err(|error| format!("build PMT4 test reorg Genesis: {error}"))?;
    let miner = local_monetary_account_id(network_id, b"AIN1-PMT4-reorg-after-page-test");
    let mut final_reorg = false;
    for height in 1..=4 {
        let payload = build_next_v4_hybrid_monetary_candidate(
            &parent,
            params,
            manifest_id,
            verifier,
            miner,
            0,
            0,
        )?;
        let (status, outcome) = import_v4_hybrid_monetary_payload(
            &payload, store, params, verifier, clock,
        )
        .map_err(|error| format!("import PMT4 test reorg candidate at height {height}: {error}"))?;
        if status != ACK_STATUS_ACCEPTED {
            return Err(format!(
                "PMT4 test reorg candidate at height {height} was not newly accepted"
            ));
        }
        parent = store
            .archive()
            .branch_chain(&outcome.block_digest)
            .ok_or_else(|| {
                format!("PMT4 test reorg candidate at height {height} was not archived")
            })?
            .clone();
        if height == 4 {
            final_reorg = outcome.canonical_changed;
        }
    }
    if !final_reorg || store.canonical_height() != 4 || store.canonical_tip() == previous_tip {
        return Err("test branch did not reorg canonical PFM4 state to height 4".into());
    }
    eprintln!(
        "event=test_fault_reorg_after_pfm4_archive_page old_tip={} new_tip={} canonical_height=4 trigger_page={}",
        hex(&previous_tip),
        hex(&store.canonical_tip()),
        trigger_page
    );
    Ok(())
}

fn serve_completed_monetary_v4_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    payload_result: io::Result<Vec<u8>>,
    mut noise_session: Option<DevnetNoiseSession>,
    store: &mut PrivateTestnetV4HybridForkStore,
    params: &ConsensusParameters,
    verifier: &LibcruxMlDsa65VerifierCandidate,
    clock: &SystemClockReferenceTime,
    network_id: &[u8; 32],
    manifest_id: &[u8; 32],
    archive_range_server: Option<&ArchiveRangeServerCandidate>,
    archive_range_snapshot_anchor: Option<[u8; 32]>,
    test_reorg_after_first_archive_page: &mut bool,
    test_reorg_after_second_archive_page: &mut bool,
    successful_archive_pages: &mut u64,
    local_noise_private_key: &[u8; 32],
) {
    let peer = peer_addr.to_string();
    let payload = match payload_result {
        Ok(payload) => payload,
        Err(error) => {
            eprintln!(
                "event=monetary_v4_peer_frame_rejected peer={peer} reason={}",
                sanitize(&error.to_string())
            );
            if noise_session.is_none() {
                return;
            }
            let canonical = store.archive().canonical_chain();
            if let Ok(ack) = encode_monetary_ack_v4(
                ACK_STATUS_REJECTED,
                0,
                [0; 32],
                canonical,
                *network_id,
                *manifest_id,
                params.protocol_version,
            ) {
                if let Some(session) = noise_session.as_mut() {
                    let _ = session.write_record(&mut stream, &ack);
                }
            }
            return;
        }
    };
    let Some(session) = noise_session.as_mut() else {
        eprintln!("event=monetary_v4_peer_frame_rejected peer={peer} reason=no_authenticated_noise_session");
        return;
    };
    if payload.get(..4) == Some(MONETARY_V4_ARCHIVE_RANGE_REQUEST_MAGIC.as_slice()) {
        let Some(server) = archive_range_server else {
            eprintln!("event=monetary_v4_archive_range_request_rejected peer={peer} reason=feature_disabled");
            return;
        };
        let Some(snapshot_anchor) = archive_range_snapshot_anchor.as_ref() else {
            eprintln!("event=monetary_v4_archive_range_request_rejected peer={peer} reason=missing_snapshot_anchor");
            return;
        };
        match monetary_v4_archive_snapshot_is_current(store, snapshot_anchor) {
            Ok(true) => {}
            Ok(false) => {
                eprintln!("event=monetary_v4_archive_range_request_rejected peer={peer} reason=stale_snapshot manifest_anchor_changed=true snapshot={}", hex(&server.snapshot_commitment()));
                return;
            }
            Err(error) => {
                eprintln!(
                    "event=monetary_v4_archive_range_request_rejected peer={peer} reason={}",
                    sanitize(&error)
                );
                return;
            }
        }
        match serve_archive_range_request_with_magic(
            &mut stream,
            &payload,
            session,
            server,
            local_noise_private_key,
            network_id,
            MONETARY_V4_ARCHIVE_RANGE_REQUEST_MAGIC,
            MONETARY_V4_ARCHIVE_RANGE_PAGE_MAGIC,
        ) {
            Err(error) => eprintln!(
                "event=monetary_v4_archive_range_request_rejected peer={peer} reason={}",
                sanitize(&error)
            ),
            Ok(()) => {
                *successful_archive_pages = successful_archive_pages.saturating_add(1);
                let trigger_page = if *test_reorg_after_first_archive_page {
                    *test_reorg_after_first_archive_page = false;
                    Some(1)
                } else if *test_reorg_after_second_archive_page && *successful_archive_pages >= 2 {
                    *test_reorg_after_second_archive_page = false;
                    Some(*successful_archive_pages)
                } else {
                    None
                };
                if let Some(trigger_page) = trigger_page {
                    // Change canonical PFM4 only after the selected authenticated page is on the
                    // wire. The next continuation must fail the immutable snapshot-anchor check.
                    if let Err(error) = force_test_monetary_v4_reorg_after_archive_page(
                        store,
                        params,
                        manifest_id,
                        verifier,
                        clock,
                        network_id,
                        trigger_page,
                    ) {
                        eprintln!(
                            "event=test_fault_reorg_after_pfm4_archive_page_failed peer={peer} reason={}",
                            sanitize(&error)
                        );
                    }
                }
            }
        }
        return;
    }
    let identity = decode_candidate_v4_hybrid_monetary_network_block(&payload)
        .ok()
        .and_then(|candidate| {
            pow_digest(&candidate.header, params.pow)
                .ok()
                .map(|digest| (candidate.header.height, digest))
        })
        .unwrap_or((0, [0; 32]));
    let (status, candidate_height, candidate_digest) = match import_v4_hybrid_monetary_payload(
        &payload, store, params, verifier, clock,
    ) {
        Ok((status, outcome)) if identity.0 != 0 && identity.1 == outcome.block_digest => {
            (status, identity.0, outcome.block_digest)
        }
        Ok(_) => {
            eprintln!("event=monetary_v4_peer_import_invariant_failed peer={peer}");
            (ACK_STATUS_REJECTED, identity.0, identity.1)
        }
        Err(ImportFailure::UnknownParent) => {
            eprintln!("event=monetary_v4_peer_candidate_deferred peer={peer} reason=unknown_parent retryable=true");
            (ACK_STATUS_UNKNOWN_PARENT, identity.0, identity.1)
        }
        Err(ImportFailure::Rejected(reason)) => {
            eprintln!(
                "event=monetary_v4_peer_candidate_rejected peer={peer} reason={}",
                sanitize(&reason)
            );
            (ACK_STATUS_REJECTED, identity.0, identity.1)
        }
    };
    let canonical = store.archive().canonical_chain();
    match encode_monetary_ack_v4(
        status,
        candidate_height,
        candidate_digest,
        canonical,
        *network_id,
        *manifest_id,
        params.protocol_version,
    ) {
        Ok(ack) => {
            if let Err(error) = session.write_record(&mut stream, &ack) {
                eprintln!(
                    "event=monetary_v4_peer_ack_write_failed peer={peer} reason={}",
                    sanitize(&error.to_string())
                );
                return;
            }
            let monetary = canonical.monetary_state();
            eprintln!(
                "event=monetary_v4_peer_ack_sent peer={peer} ack=MTA4 status={} candidate_height={} candidate_digest={} canonical_height={} state_root={} tip={}",
                status, candidate_height, hex(&candidate_digest),
                monetary.map_or(0, |state| state.height()),
                monetary.map_or_else(|| "none".into(), |state| hex(&state.state_root())),
                hex(&canonical.chain_tip().tip_hash)
            );
        }
        Err(error) => eprintln!(
            "event=monetary_v4_peer_ack_encode_failed peer={peer} reason={}",
            sanitize(&error)
        ),
    }
}

fn send_monetary_v4_to_peer_with_attempts(
    peer: SocketAddr,
    payload: &[u8],
    expected_height: u64,
    expected_digest: [u8; 32],
    max_attempts: usize,
    noise: &NoiseOutboundConfig,
    manifest_id: &[u8; 32],
    protocol_version: u16,
) -> Result<u8, String> {
    if max_attempts == 0 {
        return Err("PMT4 peer send attempt limit must be nonzero".into());
    }
    let mut last_error = String::from("PMT4 peer unreachable");
    for attempt in 0..max_attempts {
        let remote_pin = noise.trusted_pin(peer)?;
        match TcpStream::connect_timeout(&peer, Duration::from_millis(500)) {
            Ok(mut stream) => {
                if let Err(error) = stream
                    .set_nodelay(true)
                    .and_then(|_| stream.set_read_timeout(Some(WIRE_READ_TIMEOUT)))
                    .and_then(|_| stream.set_write_timeout(Some(WIRE_READ_TIMEOUT)))
                {
                    last_error = format!("configure PMT4 Noise socket: {error}");
                } else {
                    match DevnetNoiseSession::connect(
                        &mut stream,
                        &noise.local_static_private_key.0,
                        &remote_pin,
                        &noise.network_id,
                    ) {
                        Err(error) => {
                            last_error = format!("PMT4 Noise handshake rejected: {error}")
                        }
                        Ok(mut session) => match session.write_record(&mut stream, payload) {
                            Err(error) => last_error = format!("write PMT4 record: {error}"),
                            Ok(()) => match session.read_record(&mut stream) {
                                Err(error) => last_error = format!("read MTA4 record: {error}"),
                                Ok(wire) => {
                                    let ack = decode_monetary_ack_v4(&wire).map_err(|error| {
                                        format!("peer {peer} returned invalid MTA4: {error}")
                                    })?;
                                    if !monetary_ack_v4_matches_profile(
                                        &ack,
                                        &noise.network_id,
                                        manifest_id,
                                        protocol_version,
                                    ) {
                                        return Err(format!("peer {peer} MTA4 ACK belongs to a different Network ID/manifest/protocol profile"));
                                    }
                                    if ack.candidate_height != expected_height
                                        || ack.candidate_digest != expected_digest
                                    {
                                        return Err(format!("peer {peer} MTA4 ACK does not bind submitted PMT4 candidate"));
                                    }
                                    match ack.status {
                                        ACK_STATUS_ACCEPTED | ACK_STATUS_DUPLICATE => return Ok(ack.status),
                                        ACK_STATUS_UNKNOWN_PARENT => {
                                            last_error = format!("peer {peer} has not imported PMT4 parent for height {expected_height}");
                                        }
                                        status => return Err(format!("peer {peer} permanently rejected PMT4 height {expected_height} with MTA4 status {status}")),
                                    }
                                }
                            },
                        },
                    }
                }
            }
            Err(error) => last_error = format!("connect PMT4 peer {peer}: {error}"),
        }
        if attempt + 1 < max_attempts {
            thread::sleep(PEER_SEND_RETRY_DELAY);
        }
    }
    Err(last_error)
}

fn run_monetary_v4_hybrid_peer_smoke(config: &Config) -> Result<(), String> {
    validate_monetary_v4_peer_config(config)?;
    for marker in [
        "genesis.qvdn",
        "genesis.manifest",
        "monetary-genesis.mgn3",
        "devnet_forkstore_pfm3",
        "devnet_forkstore_ptb2",
        "forkstore_ptb2",
    ] {
        let path = config.data_dir.join(marker);
        if path_entry_exists(&path)? {
            return Err(format!(
                "PMT4 peer mode refuses legacy profile path: {}",
                path.display()
            ));
        }
    }
    let profile = DevnetProfileCandidate::new(config.network_id)
        .map_err(|error| format!("PMT4 Devnet profile rejected: {error}"))?;
    let (genesis, _founder, _public_goods, miner) = configured_local_monetary_v4_genesis(config)?;
    let genesis_value_atoms = genesis
        .total_value()
        .map_err(|error| format!("validate local PMT4 Genesis value: {error:?}"))?;
    let mut params = profile.consensus().clone();
    params.initial_target = Uint256::MAX;
    params.pow.memory_kib = 8 * 1024;
    params
        .validate()
        .map_err(|error| format!("invalid PMT4 loopback-only PoW profile: {error}"))?;
    let manifest_id = local_monetary_v4_manifest_id(&profile, &params);
    let genesis_manifest =
        encode_monetary_v4_genesis_manifest(&profile, &params, &genesis, &manifest_id)?;
    persist_or_verify_monetary_v4_genesis_manifest(&config.data_dir, &genesis_manifest)?;

    let verifier = LibcruxMlDsa65VerifierCandidate;
    let clock = SystemClockReferenceTime;
    let store_dir = config.data_dir.join("devnet_forkstore_pfm4");
    let mut store = PrivateTestnetV4HybridForkStore::open(
        &store_dir,
        genesis.clone(),
        params.clone(),
        manifest_id,
        &verifier,
        &clock,
    )
    .map_err(|error| format!("open PFM4 peer store: {error}"))?;
    let mut mempool = V4HybridMempoolCandidate::new(
        config.network_id,
        manifest_id,
        V4HybridMempoolLimits::default(),
    )
    .map_err(|error| format!("initialize bounded TXN4 mempool: {error:?}"))?;
    let mut mempool_tip = store.canonical_tip();

    // Each archive server exposes one immutable PFM4 snapshot. It fails closed when the
    // durable manifest anchor changes; operators restart/snapshot again rather than serve stale pages.
    let archive_range_snapshot_anchor = if config.monetary_v4_hybrid_archive_range_sync {
        Some(
            store
                .manifest_anchor()
                .map_err(|error| format!("read PFM4 archive snapshot anchor: {error:?}"))?,
        )
    } else {
        None
    };
    let archive_range_server = if config.monetary_v4_hybrid_archive_range_sync {
        Some(build_monetary_v4_archive_range_server(
            &store,
            config.network_id,
            &manifest_id,
            &params,
            config.archive_range_max_page_items,
        )?)
    } else {
        None
    };

    let signed_peer_trust_reloader =
        SignedPeerTrustReloader::from_config(config, NodeRuntimeProfile::ZeroValueDevnet)?;
    let trusted_peer_keys = match signed_peer_trust_reloader.as_ref() {
        Some(reloader) => reloader.resolve()?,
        None => resolve_trusted_peer_keys(config, NodeRuntimeProfile::ZeroValueDevnet)?,
    };
    let noise_private_key = config
        .noise_static_private_key_dpapi_file
        .as_ref()
        .map(|path| {
            let mut key = load_protected_noise_private_key(path, &config.network_id)
                .map_err(|error| format!("PMT4 Noise DPAPI key rejected: {error}"))?;
            let held = Arc::new(NoisePrivateKey(key));
            key.fill(0);
            Ok::<Arc<NoisePrivateKey>, String>(held)
        })
        .transpose()?
        .ok_or("PMT4 peer mode requires a protected Noise static key")?;
    let noise_inbound = NoiseInboundConfig {
        network_id: config.network_id,
        local_static_private_key: Arc::clone(&noise_private_key),
        trusted_peer_public_keys: trusted_peer_keys.clone(),
        signed_peer_trust_reloader: signed_peer_trust_reloader.clone(),
    };
    let noise_outbound = NoiseOutboundConfig {
        network_id: config.network_id,
        local_static_private_key: Arc::clone(&noise_private_key),
        peer_pins: config
            .peers
            .iter()
            .copied()
            .zip(trusted_peer_keys.iter().copied())
            .collect(),
        signed_peer_trust_reloader,
    };
    let (archive_import_tx, archive_import_rx) =
        mpsc::sync_channel::<MonetaryV4ArchiveRangeImportBatch>(4);

    let listener = TcpListener::bind(config.listen)
        .map_err(|error| format!("bind PMT4 peer listener {}: {error}", config.listen))?;
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("configure PMT4 listener: {error}"))?;
    let status_listener = config
        .status_listen
        .map(|address| -> Result<TcpListener, String> {
            let listener = TcpListener::bind(address)
                .map_err(|error| format!("bind PMT4 status API {address}: {error}"))?;
            listener
                .set_nonblocking(true)
                .map_err(|error| format!("configure PMT4 status API: {error}"))?;
            Ok(listener)
        })
        .transpose()?;
    let transaction_listener = config
        .transaction_listen
        .map(|address| -> Result<TcpListener, String> {
            let listener = TcpListener::bind(address)
                .map_err(|error| format!("bind PMT4 TXN4 submission API {address}: {error}"))?;
            listener
                .set_nonblocking(true)
                .map_err(|error| format!("configure PMT4 TXN4 submission API: {error}"))?;
            Ok(listener)
        })
        .transpose()?;
    let mut reader_pool = SocketReaderPool::start(
        SOCKET_READER_WORKERS,
        SOCKET_READER_QUEUE_CAPACITY,
        Some(noise_inbound),
    )
    .map_err(|error| format!("start PMT4 Noise socket readers: {error}"))?;
    let archive_sync_pending = if config.monetary_v4_hybrid_archive_range_sync {
        start_monetary_v4_archive_range_sync_threads(
            &config.peers,
            noise_outbound.clone(),
            config.data_dir.clone(),
            archive_import_tx.clone(),
        )
    } else {
        Arc::new(AtomicUsize::new(0))
    };
    drop(archive_import_tx);

    eprintln!(
        "event=monetary_v4_peer_smoke_ready listen={} peers={} network={} manifest={} height={} genesis_value_atoms={} genesis_profile=LOCAL_RESEARCH_40_30_30 value_bearing=true profile_scope=loopback_diagnostic store=PFM4 wire=PMT4 ack=MTA4 noise=required tx_policy=bounded_TXN4_pool tx_submit_listen={} pow_profile=LOCAL_EASY_POW_8MIB archive_sync={} public_launch_approved=false",
        config.listen,
        config.peers.len(),
        hex(&config.network_id),
        hex(&manifest_id),
        store.canonical_height(),
        genesis_value_atoms,
        config.transaction_listen.map(|address| address.to_string()).unwrap_or_else(|| "disabled".into()),
        if config.monetary_v4_hybrid_archive_range_sync { "ARQ4/ARW4-enabled-snapshot" } else { "not_enabled" }
    );
    let started = Instant::now();
    let deadline = Duration::from_secs(config.run_seconds);
    let mut mined = 0u64;
    let mut test_reorg_after_first_archive_page = config.test_reorg_after_first_archive_range_page;
    let mut test_reorg_after_second_archive_page =
        config.test_reorg_after_second_archive_range_page;
    let mut successful_archive_pages = 0u64;
    let mut last_listener_error = Instant::now();
    loop {
        if started.elapsed() >= deadline {
            if mined != config.mine_blocks
                || config
                    .stop_after_height
                    .is_some_and(|height| store.canonical_height() < height)
                || (config.monetary_v4_hybrid_archive_range_sync
                    && archive_sync_pending.load(AtomicOrdering::Acquire) != 0)
            {
                return Err(format!(
                    "PMT4 peer smoke deadline elapsed at height {} after mining {mined}/{} requested blocks",
                    store.canonical_height(), config.mine_blocks
                ));
            }
            break;
        }
        loop {
            match listener.accept() {
                Ok((stream, peer)) if peer.ip().is_loopback() => {
                    let configured = stream
                        .set_nodelay(true)
                        .and_then(|_| stream.set_read_timeout(Some(WIRE_READ_TIMEOUT)))
                        .and_then(|_| stream.set_write_timeout(Some(WIRE_READ_TIMEOUT)));
                    if let Err(error) = configured {
                        eprintln!(
                            "event=monetary_v4_peer_connection_rejected peer={peer} reason={}",
                            sanitize(&error.to_string())
                        );
                    } else if let Err(rejected) = reader_pool.try_enqueue(stream, peer) {
                        drop(rejected);
                        eprintln!("event=monetary_v4_peer_connection_rejected peer={peer} reason=reader_queue_full");
                    }
                }
                Ok((_stream, peer)) => eprintln!(
                    "event=monetary_v4_peer_connection_rejected peer={peer} reason=non_loopback"
                ),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => {
                    if last_listener_error.elapsed() >= Duration::from_secs(1) {
                        eprintln!(
                            "event=monetary_v4_peer_listener_error reason={}",
                            sanitize(&error.to_string())
                        );
                        last_listener_error = Instant::now();
                    }
                    break;
                }
            }
        }
        if let Some(status_listener) = status_listener.as_ref() {
            match status_listener.accept() {
                Ok((stream, peer)) if peer.ip().is_loopback() => {
                    let canonical = store.archive().canonical_chain();
                    let monetary = canonical
                        .monetary_state()
                        .ok_or("PFM4 status observed non-monetary state")?;
                    let body = status_json(
                        &config.network_id,
                        monetary.height(),
                        &monetary.state_root(),
                        &canonical.chain_tip().tip_hash,
                        store.archive().archive_len(),
                        "monetary-v4-hybrid-loopback-only",
                    );
                    if let Err(error) = serve_status_connection(stream, &body) {
                        eprintln!(
                            "event=monetary_v4_status_api_error reason={}",
                            sanitize(&error.to_string())
                        );
                    }
                }
                Ok((_stream, peer)) => eprintln!(
                    "event=monetary_v4_status_api_rejected peer={peer} reason=non_loopback"
                ),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => eprintln!(
                    "event=monetary_v4_status_api_error reason={}",
                    sanitize(&error.to_string())
                ),
            }
        }
        if let Some(transaction_listener) = transaction_listener.as_ref() {
            match transaction_listener.accept() {
                Ok((stream, peer)) if peer.ip().is_loopback() => {
                    serve_v4_transaction_submit_connection(
                        stream,
                        &mut mempool,
                        &store,
                        &verifier,
                        miner,
                    );
                }
                Ok((_stream, peer)) => {
                    eprintln!("event=txn4_submission_rejected peer={peer} reason=non_loopback")
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => eprintln!(
                    "event=txn4_submission_listener_error reason={}",
                    sanitize(&error.to_string())
                ),
            }
        }
        loop {
            match archive_import_rx.try_recv() {
                Ok(batch) => {
                    let result = apply_monetary_v4_archive_range_import_batch(
                        &batch, &mut store, &params, &verifier, &clock,
                    );
                    if config.test_crash_after_monetary_v4_import && result.is_ok() {
                        eprintln!(
                            "event=test_fault_crash_after_monetary_v4_import peer={} exit_code=86 before_archive_wal_commit=true",
                            batch.peer
                        );
                        // Test-only process-kill seam: after durable PFM4 import but before
                        // replying success to the range worker, which is the ARW4 receipt boundary.
                        process::exit(86);
                    }
                    let _ = batch.response.send(result);
                }
                Err(mpsc::TryRecvError::Empty) | Err(mpsc::TryRecvError::Disconnected) => break,
            }
        }
        if let Ok(completion) = reader_pool.recv_timeout(SOCKET_READER_EVENT_POLL) {
            serve_completed_monetary_v4_connection(
                completion.stream,
                completion.peer,
                completion.payload,
                completion.noise_session,
                &mut store,
                &params,
                &verifier,
                &clock,
                &config.network_id,
                &manifest_id,
                archive_range_server.as_deref(),
                archive_range_snapshot_anchor,
                &mut test_reorg_after_first_archive_page,
                &mut test_reorg_after_second_archive_page,
                &mut successful_archive_pages,
                &noise_private_key.0,
            );
        }
        reconcile_v4_mempool_after_canonical_change(
            &mut mempool,
            &store,
            &verifier,
            miner,
            &mut mempool_tip,
        )?;
        if config
            .stop_after_height
            .is_some_and(|height| store.canonical_height() >= height)
            && (!config.monetary_v4_hybrid_archive_range_sync
                || archive_sync_pending.load(AtomicOrdering::Acquire) == 0)
        {
            break;
        }
        if mined < config.mine_blocks && (transaction_listener.is_none() || !mempool.is_empty()) {
            let previous_height = store.canonical_height();
            let parent = store.archive().canonical_chain().clone();
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| "system clock predates Unix epoch before TXN4 block building")?
                .as_secs();
            let canonical_state = store
                .archive()
                .canonical_chain()
                .monetary_state()
                .ok_or("PFM4 canonical tip has no monetary state before TXN4 selection")?;
            let prune_summary = mempool.prune_expired(canonical_state, &verifier, now, miner);
            if prune_summary.dropped_expired > 0 || prune_summary.dropped_invalid > 0 {
                eprintln!(
                    "event=txn4_mempool_pruned expired={} invalid={} count={} bytes={}",
                    prune_summary.dropped_expired,
                    prune_summary.dropped_invalid,
                    mempool.len(),
                    mempool.total_bytes()
                );
            }
            let selected_transactions = mempool.ordered_transactions();
            let payload = build_next_v4_hybrid_monetary_candidate_with_transactions(
                &parent,
                &params,
                &manifest_id,
                &verifier,
                miner,
                config.timestamp_offset,
                config.timestamp_backdate,
                selected_transactions,
            )?;
            let candidate = decode_candidate_v4_hybrid_monetary_network_block(&payload)
                .map_err(|error| format!("decode locally built PMT4 candidate: {error}"))?;
            let height = candidate.header.height;
            let digest = pow_digest(&candidate.header, params.pow)
                .map_err(|error| format!("hash locally built PMT4 candidate: {error}"))?;
            let (status, outcome) =
                import_v4_hybrid_monetary_payload(&payload, &mut store, &params, &verifier, &clock)
                    .map_err(|error| format!("local PMT4 admission failed: {error}"))?;
            if status != ACK_STATUS_ACCEPTED
                || !outcome.canonical_changed
                || outcome.canonical_height != previous_height.saturating_add(1)
                || outcome.block_digest != digest
                || height != previous_height.saturating_add(1)
            {
                return Err("local PMT4 candidate did not advance canonical PFM4".into());
            }
            mempool.remove_included(&candidate.block.transactions);
            reconcile_v4_mempool_after_canonical_change(
                &mut mempool,
                &store,
                &verifier,
                miner,
                &mut mempool_tip,
            )?;
            for peer in &config.peers {
                let ack_status = send_monetary_v4_to_peer_with_attempts(
                    *peer,
                    &payload,
                    height,
                    digest,
                    PEER_SEND_MAX_ATTEMPTS,
                    &noise_outbound,
                    &manifest_id,
                    params.protocol_version,
                )?;
                if !matches!(ack_status, ACK_STATUS_ACCEPTED | ACK_STATUS_DUPLICATE) {
                    return Err(format!(
                        "peer {peer} returned unexpected MTA4 status {ack_status}"
                    ));
                }
                if config.duplicate_broadcast {
                    let duplicate_status = send_monetary_v4_to_peer_with_attempts(
                        *peer,
                        &payload,
                        height,
                        digest,
                        PEER_SEND_MAX_ATTEMPTS,
                        &noise_outbound,
                        &manifest_id,
                        params.protocol_version,
                    )?;
                    if duplicate_status != ACK_STATUS_DUPLICATE {
                        return Err(format!(
                            "peer {peer} did not classify repeated PMT4 as duplicate"
                        ));
                    }
                }
            }
            let canonical = store.archive().canonical_chain();
            let monetary = canonical
                .monetary_state()
                .ok_or("PFM4 canonical tip has no monetary state")?;
            eprintln!(
                "event=monetary_v4_peer_broadcast_complete height={} digest={} state_root={} tip={} peers={} transactions={} duplicate_broadcast={}",
                height,
                hex(&digest),
                hex(&monetary.state_root()),
                hex(&canonical.chain_tip().tip_hash),
                config.peers.len(),
                candidate.block.transactions.len(),
                config.duplicate_broadcast
            );
            mined += 1;
            if config.exit_after_mining
                && mined == config.mine_blocks
                && (!config.monetary_v4_hybrid_archive_range_sync
                    || archive_sync_pending.load(AtomicOrdering::Acquire) == 0)
            {
                break;
            }
        } else {
            thread::sleep(Duration::from_millis(5));
        }
    }
    reader_pool.shutdown();
    if mined != config.mine_blocks {
        return Err(format!(
            "PMT4 peer smoke stopped after mining {mined} of {} requested blocks",
            config.mine_blocks
        ));
    }
    if config
        .stop_after_height
        .is_some_and(|height| store.canonical_height() < height)
    {
        return Err("PMT4 peer smoke stopped before requested canonical height".into());
    }
    let final_height = store.canonical_height();
    let final_tip = store.canonical_tip();
    let final_anchor = store
        .manifest_anchor()
        .map_err(|error| format!("read final PFM4 manifest anchor: {error:?}"))?;
    drop(store);
    let reopened = PrivateTestnetV4HybridForkStore::open_anchored(
        &store_dir,
        genesis,
        params.clone(),
        manifest_id,
        &verifier,
        &clock,
        final_anchor,
    )
    .map_err(|error| format!("reopen PMT4/PFM4 peer store: {error}"))?;
    if reopened.canonical_height() != final_height
        || reopened.canonical_tip() != final_tip
        || reopened
            .manifest_anchor()
            .map_err(|error| format!("verify reopened PFM4 anchor: {error:?}"))?
            != final_anchor
    {
        return Err("PMT4/PFM4 peer restart replay mismatch".into());
    }
    eprintln!(
        "event=monetary_v4_peer_smoke_stopped height={} tip={} archive_branches={} replay=matched anchor=local_only tx_api={} tx_pending={} tx_pending_bytes={} profile_scope=loopback_diagnostic archive_sync={} public_launch_approved=false",
        final_height,
        hex(&final_tip),
        reopened.archive().archive_len(),
        config.transaction_listen.map(|address| address.to_string()).unwrap_or_else(|| "disabled".into()),
        mempool.len(),
        mempool.total_bytes(),
        if config.monetary_v4_hybrid_archive_range_sync { "ARQ4/ARW4-tested-snapshot-mode" } else { "not_enabled" }
    );
    Ok(())
}

fn run_monetary_candidate_peer_smoke(config: &Config) -> Result<(), String> {
    validate_monetary_candidate_peer_config(config)?;
    let legacy_markers = [
        "genesis.qvdn",
        "genesis.manifest",
        "monetary-genesis.mgn4",
        "devnet_forkstore_pfm4",
        "devnet_forkstore_ptb2",
        "forkstore_ptb2",
    ];
    for marker in legacy_markers {
        let path = config.data_dir.join(marker);
        if path_entry_exists(&path)? {
            return Err(format!(
                "monetary peer smoke refuses existing legacy/QVDN path: {}",
                path.display()
            ));
        }
    }

    let profile = DevnetProfileCandidate::new(config.network_id)
        .map_err(|error| format!("monetary peer profile rejected: {error}"))?;
    let genesis = monetary_candidate_genesis(config.network_id)?;
    let miner = local_monetary_account_id(&config.network_id, b"miner-placeholder");
    let mut params = profile.consensus().clone();
    // Deliberately diagnostic: this separately fingerprinted profile proves transport/import
    // behavior only, not candidate-network PoW strength, fairness, or production throughput.
    params.initial_target = Uint256::MAX;
    params.pow.memory_kib = 8 * 1024;
    params
        .validate()
        .map_err(|error| format!("invalid local monetary peer PoW profile: {error}"))?;
    let genesis_manifest = encode_monetary_genesis_manifest(&profile, &params, &genesis)?;
    persist_or_verify_monetary_genesis_manifest(&config.data_dir, &genesis_manifest)?;

    let auth = NodeAuthenticator::RejectAll;
    let clock = SystemClockReferenceTime;
    let store_dir = config.data_dir.join("devnet_forkstore_pfm3");
    let mut store = PrivateTestnetMonetaryForkStore::open(
        &store_dir,
        genesis.clone(),
        params.clone(),
        &auth,
        &clock,
    )
    .map_err(|error| format!("open PFM3 monetary peer store: {error}"))?;
    // Serve one immutable startup snapshot. Bind it to the durable PFM3 manifest anchor so
    // archive mutation (including a reorg) invalidates the old snapshot instead of serving stale pages.
    let archive_range_snapshot_anchor = if config.monetary_candidate_archive_range_sync {
        Some(
            store
                .manifest_anchor()
                .map_err(|error| format!("capture PFM3 archive snapshot anchor: {error:?}"))?,
        )
    } else {
        None
    };
    let mut test_reorg_after_first_archive_page = config.test_reorg_after_first_archive_range_page;
    let archive_range_server = if config.monetary_candidate_archive_range_sync {
        Some(build_monetary_archive_range_server(
            &store,
            config.network_id,
            &params,
            config.archive_range_max_page_items,
        )?)
    } else {
        None
    };

    let signed_peer_trust_reloader =
        SignedPeerTrustReloader::from_config(config, NodeRuntimeProfile::ZeroValueDevnet)?;
    let trusted_peer_keys = match signed_peer_trust_reloader.as_ref() {
        Some(reloader) => reloader.resolve()?,
        None => resolve_trusted_peer_keys(config, NodeRuntimeProfile::ZeroValueDevnet)?,
    };
    let noise_private_key = config
        .noise_static_private_key_dpapi_file
        .as_ref()
        .map(|path| {
            let mut key = load_protected_noise_private_key(path, &config.network_id)
                .map_err(|error| format!("monetary Noise DPAPI key rejected: {error}"))?;
            let held = Arc::new(NoisePrivateKey(key));
            key.fill(0);
            Ok::<Arc<NoisePrivateKey>, String>(held)
        })
        .transpose()?
        .ok_or("monetary peer smoke requires a protected Noise static key")?;
    let noise_inbound = NoiseInboundConfig {
        network_id: config.network_id,
        local_static_private_key: Arc::clone(&noise_private_key),
        trusted_peer_public_keys: trusted_peer_keys.clone(),
        signed_peer_trust_reloader: signed_peer_trust_reloader.clone(),
    };
    let noise_outbound = NoiseOutboundConfig {
        network_id: config.network_id,
        local_static_private_key: Arc::clone(&noise_private_key),
        peer_pins: config
            .peers
            .iter()
            .copied()
            .zip(trusted_peer_keys.iter().copied())
            .collect(),
        signed_peer_trust_reloader,
    };

    let listener = TcpListener::bind(config.listen).map_err(|error| {
        format!(
            "bind monetary peer smoke listener {}: {error}",
            config.listen
        )
    })?;
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("configure monetary listener: {error}"))?;
    let status_listener = config
        .status_listen
        .map(|address| -> Result<TcpListener, String> {
            let listener = TcpListener::bind(address)
                .map_err(|error| format!("bind monetary status API {address}: {error}"))?;
            listener
                .set_nonblocking(true)
                .map_err(|error| format!("configure monetary status API: {error}"))?;
            Ok(listener)
        })
        .transpose()?;
    let mut reader_pool = SocketReaderPool::start(
        SOCKET_READER_WORKERS,
        SOCKET_READER_QUEUE_CAPACITY,
        Some(noise_inbound),
    )
    .map_err(|error| format!("start monetary socket readers: {error}"))?;

    let (archive_import_tx, archive_import_rx) = mpsc::sync_channel(4);
    let archive_sync_pending = if config.monetary_candidate_archive_range_sync {
        let pending = start_monetary_archive_range_sync_threads(
            &config.peers,
            noise_outbound.clone(),
            config.data_dir.clone(),
            archive_import_tx,
        );
        eprintln!(
            "event=monetary_archive_range_sync_started peers={} page_items={} snapshot_items={}",
            config.peers.len(),
            config.archive_range_max_page_items,
            store.archive().archive_len()
        );
        pending
    } else {
        Arc::new(AtomicUsize::new(0))
    };

    let initial_height = store.canonical_height();
    eprintln!(
        "event=monetary_candidate_peer_smoke_ready listen={} peers={} network={} height={} store=PFM3 wire=PMT3 ack=MTA3 noise=required pow_profile=LOCAL_EASY_POW_8MIB transactions=RejectAll public_launch_approved=false",
        config.listen,
        config.peers.len(),
        hex(&config.network_id),
        initial_height
    );
    let started = Instant::now();
    let deadline = Duration::from_secs(config.run_seconds);
    let mut mined = 0u64;
    let mut last_listener_error = Instant::now();
    loop {
        if started.elapsed() >= deadline {
            let sync_pending = archive_sync_pending.load(AtomicOrdering::Acquire);
            if mined != config.mine_blocks
                || config
                    .stop_after_height
                    .is_some_and(|height| store.canonical_height() < height)
                || (config.stop_after_height.is_some() && sync_pending != 0)
            {
                return Err(format!(
                    "monetary peer smoke deadline elapsed at canonical height {} after mining {mined}/{} requested blocks (archive_sync_pending={sync_pending})",
                    store.canonical_height(),
                    config.mine_blocks
                ));
            }
            break;
        }

        loop {
            match listener.accept() {
                Ok((stream, peer)) if peer.ip().is_loopback() => {
                    let configured = stream
                        .set_nodelay(true)
                        .and_then(|_| stream.set_read_timeout(Some(WIRE_READ_TIMEOUT)))
                        .and_then(|_| stream.set_write_timeout(Some(WIRE_READ_TIMEOUT)));
                    if let Err(error) = configured {
                        eprintln!(
                            "event=monetary_peer_connection_rejected peer={peer} reason={}",
                            sanitize(&error.to_string())
                        );
                    } else if let Err(rejected_stream) = reader_pool.try_enqueue(stream, peer) {
                        drop(rejected_stream);
                        eprintln!("event=monetary_peer_connection_rejected peer={peer} reason=reader_queue_full");
                    }
                }
                Ok((_stream, peer)) => {
                    eprintln!(
                        "event=monetary_peer_connection_rejected peer={peer} reason=non_loopback"
                    );
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => {
                    if last_listener_error.elapsed() >= Duration::from_secs(1) {
                        eprintln!(
                            "event=monetary_peer_listener_error reason={}",
                            sanitize(&error.to_string())
                        );
                        last_listener_error = Instant::now();
                    }
                    break;
                }
            }
        }

        if let Some(status_listener) = status_listener.as_ref() {
            match status_listener.accept() {
                Ok((stream, peer)) if peer.ip().is_loopback() => {
                    let canonical = store.archive().canonical_chain();
                    let monetary = canonical
                        .monetary_state()
                        .ok_or("PFM3 status endpoint observed a non-monetary canonical chain")?;
                    let body = status_json(
                        &config.network_id,
                        monetary.height(),
                        &monetary.state_root(),
                        &canonical.chain_tip().tip_hash,
                        store.archive().archive_len(),
                        "monetary-candidate-loopback-only",
                    );
                    if let Err(error) = serve_status_connection(stream, &body) {
                        eprintln!(
                            "event=monetary_candidate_status_api_error error={}",
                            sanitize(&error.to_string())
                        );
                    }
                }
                Ok((_stream, peer)) => eprintln!(
                    "event=monetary_candidate_status_api_rejected peer={peer} reason=non_loopback"
                ),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => eprintln!(
                    "event=monetary_candidate_status_api_accept_error error={}",
                    sanitize(&error.to_string())
                ),
            }
        }

        loop {
            let batch = match archive_import_rx.try_recv() {
                Ok(batch) => batch,
                Err(mpsc::TryRecvError::Empty) | Err(mpsc::TryRecvError::Disconnected) => break,
            };
            let peer = batch.peer;
            let result = apply_monetary_archive_range_import_batch(
                &batch, &mut store, &params, &auth, &clock,
            );
            if let Err(error) = &result {
                eprintln!(
                    "event=monetary_archive_range_import_rejected peer={peer} reason={}",
                    sanitize(error)
                );
            }
            if config.test_crash_after_monetary_import && result.is_ok() {
                eprintln!(
                    "event=test_fault_crash_after_monetary_import peer={} exit_code=86 before_archive_wal_commit=true",
                    batch.peer
                );
                // Test-only process-kill seam: exactly after durable PFM3 import and before
                // the sync worker can commit the corresponding ARW page receipt.
                process::exit(86);
            }
            let _ = batch.response.send(result);
        }

        if let Ok(completion) = reader_pool.recv_timeout(SOCKET_READER_EVENT_POLL) {
            serve_completed_monetary_connection(
                completion.stream,
                completion.peer,
                completion.payload,
                completion.noise_session,
                &mut store,
                &params,
                &auth,
                &clock,
                archive_range_server.as_deref(),
                archive_range_snapshot_anchor,
                &mut test_reorg_after_first_archive_page,
                &noise_private_key.0,
                &config.network_id,
            );
        }

        if config
            .stop_after_height
            .is_some_and(|height| store.canonical_height() >= height)
            && archive_sync_pending.load(AtomicOrdering::Acquire) == 0
        {
            break;
        }

        if mined < config.mine_blocks {
            let previous_height = store.canonical_height();
            let chain = store.archive().canonical_chain().clone();
            let payload = build_next_monetary_candidate(
                &chain,
                &params,
                &auth,
                miner,
                config.timestamp_offset,
                config.timestamp_backdate,
            )?;
            let candidate = decode_candidate_monetary_network_block(&payload)
                .map_err(|error| format!("decode locally built PMT3 candidate: {error}"))?;
            let height = candidate.header.height;
            let digest = pow_digest(&candidate.header, params.pow)
                .map_err(|error| format!("hash locally built PMT3 candidate: {error}"))?;
            let (status, outcome) =
                import_monetary_payload(&payload, &mut store, &params, &auth, &clock)
                    .map_err(|error| format!("local PFM3 admission failed: {error}"))?;
            if status != ACK_STATUS_ACCEPTED
                || !outcome.canonical_changed
                || outcome.canonical_height != previous_height.saturating_add(1)
                || outcome.block_digest != digest
                || height != previous_height.saturating_add(1)
            {
                return Err(
                    "local PMT3 candidate did not advance the expected canonical PFM3 height"
                        .into(),
                );
            }
            let canonical = store.archive().canonical_chain();
            let monetary = canonical
                .monetary_state()
                .ok_or("PFM3 canonical tip has no monetary state")?;
            eprintln!(
                "event=monetary_peer_candidate_mined height={} digest={} state_root={} tip={} total_value_atoms={}",
                height,
                hex(&digest),
                hex(&monetary.state_root()),
                hex(&canonical.chain_tip().tip_hash),
                monetary.total_value().map_err(|error| format!("validate monetary supply: {error:?}"))?
            );
            for peer in &config.peers {
                let ack_status = send_monetary_candidate_with_ancestor_repair(
                    *peer,
                    &payload,
                    height,
                    digest,
                    &store,
                    &params,
                    PEER_SEND_MAX_ATTEMPTS,
                    &noise_outbound,
                )?;
                if !matches!(ack_status, ACK_STATUS_ACCEPTED | ACK_STATUS_DUPLICATE) {
                    return Err(format!(
                        "peer {peer} returned unexpected MTA3 status {ack_status}"
                    ));
                }
                if config.duplicate_broadcast {
                    let duplicate_status = send_monetary_candidate_with_ancestor_repair(
                        *peer,
                        &payload,
                        height,
                        digest,
                        &store,
                        &params,
                        PEER_SEND_MAX_ATTEMPTS,
                        &noise_outbound,
                    )?;
                    if duplicate_status != ACK_STATUS_DUPLICATE {
                        return Err(format!(
                            "peer {peer} did not classify repeated PMT3 candidate as duplicate (status {duplicate_status})"
                        ));
                    }
                }
            }
            eprintln!(
                "event=monetary_peer_broadcast_complete height={height} peers={} duplicate_broadcast={}",
                config.peers.len(),
                config.duplicate_broadcast
            );
            mined += 1;
            if config.exit_after_mining && mined == config.mine_blocks {
                break;
            }
        } else {
            thread::sleep(Duration::from_millis(5));
        }
    }

    reader_pool.shutdown();
    if mined != config.mine_blocks {
        return Err(format!(
            "monetary peer smoke stopped after mining {mined} of {} requested blocks",
            config.mine_blocks
        ));
    }
    if config
        .stop_after_height
        .is_some_and(|height| store.canonical_height() < height)
    {
        return Err(format!(
            "monetary peer smoke did not reach requested canonical height {}",
            config.stop_after_height.unwrap_or_default()
        ));
    }
    let final_height = store.canonical_height();
    let final_tip = store.canonical_tip();
    drop(store);

    let reopened =
        PrivateTestnetMonetaryForkStore::open(&store_dir, genesis, params, &auth, &clock)
            .map_err(|error| format!("replay PFM3 monetary peer store: {error}"))?;
    if reopened.canonical_height() != final_height || reopened.canonical_tip() != final_tip {
        return Err("PFM3 replay changed the monetary peer smoke canonical tip".into());
    }
    let canonical = reopened.archive().canonical_chain();
    let monetary = canonical
        .monetary_state()
        .ok_or("replayed PFM3 tip has no monetary state")?;
    eprintln!(
        "event=monetary_candidate_peer_smoke_stopped listen={} height={} state_root={} tip={} total_value_atoms={} total_mined_atoms={} replay=matched network_transport=Noise+PMT3/MTA3 loopback_only=true public_launch_approved=false",
        config.listen,
        monetary.height(),
        hex(&monetary.state_root()),
        hex(&canonical.chain_tip().tip_hash),
        monetary.total_value().map_err(|error| format!("validate replayed monetary supply: {error:?}"))?,
        monetary.total_mined_atoms()
    );
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NodeRuntimeProfile {
    PrivateSmoke,
    ZeroValueDevnet,
}
impl NodeRuntimeProfile {
    fn name(self) -> &'static str {
        match self {
            Self::PrivateSmoke => "PTB2_PFS2_LOOPBACK_ONLY_SMOKE",
            Self::ZeroValueDevnet => "PTB2_PFS2_LOOPBACK_ZERO_VALUE_DEVNET_CANDIDATE",
        }
    }
    fn observer_profile(self) -> &'static str {
        match self {
            Self::PrivateSmoke => "loopback-private-testnet",
            Self::ZeroValueDevnet => "loopback-zero-value-devnet-candidate",
        }
    }
    fn ready_event(self) -> &'static str {
        match self {
            Self::PrivateSmoke => "private_testnet_ready",
            Self::ZeroValueDevnet => "devnet_node_ready",
        }
    }
    fn stopped_event(self) -> &'static str {
        match self {
            Self::PrivateSmoke => "private_testnet_stopped",
            Self::ZeroValueDevnet => "devnet_node_stopped",
        }
    }
}

fn run_with_runtime_profile(runtime_profile: NodeRuntimeProfile) -> Result<(), String> {
    let config = parse_args()?;
    if config.transaction_listen.is_some() && !config.monetary_v4_hybrid_peer_smoke {
        return Err("--transaction-listen requires --monetary-v4-hybrid-peer-smoke".into());
    }
    let selected_monetary_modes = config.monetary_candidate_local_smoke as u8
        + config.monetary_v4_hybrid_local_smoke as u8
        + config.monetary_v4_hybrid_peer_smoke as u8
        + config.monetary_candidate_peer_smoke as u8;
    if selected_monetary_modes > 1 {
        return Err("choose exactly one monetary candidate smoke profile".into());
    }
    if config.monetary_v4_hybrid_archive_range_sync && !config.monetary_v4_hybrid_peer_smoke {
        return Err(
            "--monetary-v4-hybrid-archive-range-sync requires --monetary-v4-hybrid-peer-smoke"
                .into(),
        );
    }
    if config.monetary_v4_hybrid_local_smoke {
        if runtime_profile != NodeRuntimeProfile::ZeroValueDevnet {
            return Err("--monetary-v4-hybrid-local-smoke is only supported by devnet_node".into());
        }
        return run_monetary_v4_hybrid_local_smoke(&config);
    }
    if config.monetary_v4_hybrid_peer_smoke {
        if runtime_profile != NodeRuntimeProfile::ZeroValueDevnet {
            return Err("--monetary-v4-hybrid-peer-smoke is only supported by devnet_node".into());
        }
        return run_monetary_v4_hybrid_peer_smoke(&config);
    }
    if config.monetary_candidate_local_smoke {
        if runtime_profile != NodeRuntimeProfile::ZeroValueDevnet {
            return Err("--monetary-candidate-local-smoke is only supported by devnet_node".into());
        }
        return run_monetary_candidate_local_smoke(&config);
    }
    if config.monetary_candidate_peer_smoke {
        if runtime_profile != NodeRuntimeProfile::ZeroValueDevnet {
            return Err("--monetary-candidate-peer-smoke is only supported by devnet_node".into());
        }
        return run_monetary_candidate_peer_smoke(&config);
    }
    if path_entry_exists(&config.data_dir.join("monetary-genesis.mgn4"))? {
        return Err("data directory is locked to the PMT4/PFM4 candidate profile; use --monetary-v4-hybrid-local-smoke or a separate data directory".into());
    }
    if path_entry_exists(&config.data_dir.join("monetary-genesis.mgn3"))? {
        return Err("data directory is locked to the PMT3/PFM3 candidate profile; use --monetary-candidate-local-smoke or a separate data directory".into());
    }
    let noise_configured = config.noise_static_private_key_dpapi_file.is_some();
    if runtime_profile == NodeRuntimeProfile::PrivateSmoke && noise_configured {
        return Err("Noise peer options are only accepted by devnet_node; private smoke mode remains unchanged".into());
    }
    if runtime_profile == NodeRuntimeProfile::ZeroValueDevnet
        && !config.peers.is_empty()
        && !noise_configured
    {
        return Err("devnet peer connections require Noise XX static-key pins; plaintext peer fallback is forbidden".into());
    }
    // Resolve and durably observe signed identity generation floors before any listener is
    // opened. In signed-identity Devnet mode, keep the same verifier available for fail-closed
    // refresh before every new inbound/outbound connection. Existing raw pins remain static.
    let signed_peer_trust_reloader =
        SignedPeerTrustReloader::from_config(&config, runtime_profile)?;
    let trusted_peer_keys = match signed_peer_trust_reloader.as_ref() {
        Some(reloader) => reloader.resolve()?,
        None => resolve_trusted_peer_keys(&config, runtime_profile)?,
    };
    let noise_private_key = if runtime_profile == NodeRuntimeProfile::ZeroValueDevnet {
        config
            .noise_static_private_key_dpapi_file
            .as_ref()
            .map(|path| {
                let mut key = load_protected_noise_private_key(path, &config.network_id)
                    .map_err(|error| format!("Noise DPAPI key rejected: {error}"))?;
                let held = Arc::new(NoisePrivateKey(key));
                key.fill(0);
                Ok::<Arc<NoisePrivateKey>, String>(held)
            })
            .transpose()?
    } else {
        None
    };
    let noise_inbound = noise_private_key.as_ref().map(|key| NoiseInboundConfig {
        network_id: config.network_id,
        local_static_private_key: Arc::clone(key),
        trusted_peer_public_keys: trusted_peer_keys.clone(),
        signed_peer_trust_reloader: signed_peer_trust_reloader.clone(),
    });
    let noise_outbound = noise_private_key.as_ref().map(|key| NoiseOutboundConfig {
        network_id: config.network_id,
        local_static_private_key: Arc::clone(key),
        peer_pins: config
            .peers
            .iter()
            .copied()
            .zip(trusted_peer_keys.iter().copied())
            .collect(),
        signed_peer_trust_reloader: signed_peer_trust_reloader.clone(),
    });
    let devnet_profile = if runtime_profile == NodeRuntimeProfile::ZeroValueDevnet {
        Some(
            DevnetProfileCandidate::new(config.network_id)
                .map_err(|error| format!("devnet profile rejected: {error}"))?,
        )
    } else {
        None
    };
    let params = match devnet_profile.as_ref() {
        Some(profile) => profile.consensus().clone(),
        None => candidate_params()?,
    };
    let (auth, signer, genesis_accounts, signer_public_key) =
        build_transaction_profile(&config, runtime_profile)?;
    match devnet_profile.as_ref() {
        Some(profile) => {
            if profile.consensus() != &params
                || !genesis_accounts.is_empty()
                || config.test_transactions
            {
                return Err("devnet profile/configuration boundary mismatch".into());
            }
            profile
                .persist_or_verify_manifest(config.data_dir.join("genesis.qvdn"))
                .map_err(|error| format!("devnet Genesis manifest rejected: {error}"))?;
        }
        None => verify_or_create_manifest(
            &config.data_dir,
            &config.network_id,
            &params,
            &genesis_accounts,
            config.test_transactions,
            &signer_public_key,
        )?,
    }
    let clock = SystemClockReferenceTime;
    let genesis = LedgerState::genesis(config.network_id, genesis_accounts.clone())
        .map_err(|error| format!("build disposable genesis: {error:?}"))?;
    let branch_dir = match runtime_profile {
        NodeRuntimeProfile::PrivateSmoke => config.data_dir.join("forkstore_ptb2"),
        NodeRuntimeProfile::ZeroValueDevnet => config.data_dir.join("devnet_forkstore_ptb2"),
    };
    let mut store =
        PrivateTestnetForkStore::open(&branch_dir, genesis, params.clone(), &auth, &clock)
            .map_err(|error| format!("open durable PTB2 branch store: {error}"))?;

    let listener = TcpListener::bind(config.listen)
        .map_err(|error| format!("bind {}: {error}", config.listen))?;
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("configure listener: {error}"))?;

    let status_listener = if let Some(address) = config.status_listen {
        let status_listener = TcpListener::bind(address)
            .map_err(|error| format!("bind status API {address}: {error}"))?;
        status_listener
            .set_nonblocking(true)
            .map_err(|error| format!("configure status API listener: {error}"))?;
        eprintln!(
            "event={} listen={address} access=loopback_only",
            match runtime_profile {
                NodeRuntimeProfile::PrivateSmoke => "private_testnet_status_api_ready",
                NodeRuntimeProfile::ZeroValueDevnet => "devnet_status_api_ready",
            }
        );
        Some(status_listener)
    } else {
        None
    };

    let mut reader_pool = SocketReaderPool::start(
        SOCKET_READER_WORKERS,
        SOCKET_READER_QUEUE_CAPACITY,
        if runtime_profile == NodeRuntimeProfile::ZeroValueDevnet {
            noise_inbound.clone()
        } else {
            None
        },
    )
    .map_err(|error| format!("start bounded socket readers: {error}"))?;

    // Export a bounded PTB2/PFS2 snapshot only when peers are configured. Every envelope uses
    // the selected profile transport; Devnet has no plaintext archive-sync fallback.
    let use_archive_sync = !config.peers.is_empty();
    let (existing_archive, archive_range_server) = if use_archive_sync {
        let archive = ordered_archive_envelopes(&store, &params)?;
        if runtime_profile == NodeRuntimeProfile::ZeroValueDevnet {
            let generation = store.canonical_height();
            let server = build_archive_range_server(
                archive,
                config.network_id,
                runtime_profile,
                generation,
                config.archive_range_max_page_items,
            )?;
            (Vec::new(), Some(server))
        } else {
            (archive, None)
        }
    } else {
        (Vec::new(), None)
    };
    let (archive_import_tx, archive_import_rx) = mpsc::sync_channel::<ArchiveRangeImportBatch>(1);

    {
        let canonical = store.archive().canonical_chain();
        eprintln!(
            "event={} listen={} height={} state_root={} consensus_tip={} archive_branches={} profile={} initial_target={} pow_memory_kib={} tx_auth={} reader_workers={} reader_queue_capacity={}",
            runtime_profile.ready_event(),
            config.listen,
            canonical.state().height(),
            hex(&canonical.state().state_root()),
            hex(&canonical.chain_tip().tip_hash),
            store.archive().archive_len(),
            runtime_profile.name(),
            if params.initial_target == Uint256::MAX { "max" } else { "candidate" },
            params.pow.memory_kib,
            if config.test_transactions { "ed25519_test_fixture" } else { "reject_all_transactions" },
            SOCKET_READER_WORKERS,
            SOCKET_READER_QUEUE_CAPACITY,
        );
        log_test_transaction_state("ready", canonical, signer.as_ref());
    }

    // Do not block the event loop while peers connect to each other during a reconnect.

    let archive_range_sync_pending =
        if use_archive_sync && runtime_profile == NodeRuntimeProfile::ZeroValueDevnet {
            Some(start_archive_range_sync_threads(
                &config.peers,
                noise_outbound.clone(),
                config.data_dir.clone(),
                archive_import_tx.clone(),
                Duration::from_millis(config.archive_range_post_commit_delay_ms),
            ))
        } else {
            if use_archive_sync {
                start_archive_sync_threads(
                    &config.peers,
                    Arc::new(existing_archive),
                    config.archive_sync_delay_ms,
                    config.archive_sync_reverse_first_round,
                    runtime_profile,
                    noise_outbound.clone(),
                );
            }
            None
        };

    let start = Instant::now();
    let deadline = Duration::from_secs(config.run_seconds);
    let mut mined = 0u64;
    while start.elapsed() < deadline {
        match reader_pool.recv_timeout(SOCKET_READER_EVENT_POLL) {
            Ok(completion) => serve_completed_connection(
                completion.stream,
                completion.peer,
                completion.payload,
                completion.noise_session,
                completion.noise_required,
                &mut store,
                &params,
                &auth,
                &clock,
                archive_range_server.as_deref(),
                noise_inbound
                    .as_ref()
                    .map(|config| &config.local_static_private_key.0),
                &config.network_id,
            ),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                return Err("bounded socket reader completion channel disconnected".into());
            }
        }

        loop {
            let batch = match archive_import_rx.try_recv() {
                Ok(batch) => batch,
                Err(mpsc::TryRecvError::Empty) | Err(mpsc::TryRecvError::Disconnected) => break,
            };
            let peer = batch.peer;
            let result =
                apply_archive_range_import_batch(&batch, &mut store, &params, &auth, &clock);
            if let Err(error) = &result {
                eprintln!(
                    "event=devnet_archive_range_import_rejected peer={peer} reason={}",
                    sanitize(error)
                );
            }
            let _ = batch.response.send(result);
        }

        match listener.accept() {
            Ok((stream, peer)) => {
                // The accept loop never waits for frame bytes. Only the fixed reader pool
                // owns accepted sockets; saturated queues fail closed rather than spawning
                // one unbounded thread per connection. Frame deadlines begin at accept.
                if !peer.ip().is_loopback() {
                    eprintln!(
                        "event=private_testnet_peer_rejected reason=non_loopback peer={peer}"
                    );
                } else if runtime_profile == NodeRuntimeProfile::ZeroValueDevnet
                    && noise_inbound.is_none()
                {
                    drop(stream);
                    eprintln!(
                        "event=devnet_peer_rejected peer={peer} reason=no_noise_trust_config"
                    );
                } else if let Err(error) = stream.set_nonblocking(false) {
                    eprintln!(
                        "event=private_testnet_peer_rejected reason=set_blocking error={}",
                        sanitize(&error.to_string())
                    );
                } else if let Err(error) = stream.set_nodelay(true) {
                    eprintln!(
                        "event=private_testnet_peer_rejected reason=set_nodelay error={}",
                        sanitize(&error.to_string())
                    );
                } else if let Err(error) = stream.set_write_timeout(Some(WIRE_READ_TIMEOUT)) {
                    eprintln!(
                        "event=private_testnet_peer_rejected reason=set_write_timeout error={}",
                        sanitize(&error.to_string())
                    );
                } else if let Err(rejected_stream) = reader_pool.try_enqueue(stream, peer) {
                    drop(rejected_stream);
                    eprintln!(
                        "event=private_testnet_peer_rejected peer={peer} reason=reader_queue_full"
                    );
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => eprintln!(
                "event=private_testnet_listener_error error={}",
                sanitize(&error.to_string())
            ),
        }

        if let Some(status_listener) = status_listener.as_ref() {
            match status_listener.accept() {
                Ok((stream, peer)) if peer.ip().is_loopback() => {
                    let canonical = store.archive().canonical_chain();
                    let body = status_json(
                        &config.network_id,
                        canonical.state().height(),
                        &canonical.state().state_root(),
                        &canonical.chain_tip().tip_hash,
                        store.archive().archive_len(),
                        runtime_profile.observer_profile(),
                    );
                    if let Err(error) = serve_status_connection(stream, &body) {
                        eprintln!(
                            "event=private_testnet_status_api_error error={}",
                            sanitize(&error.to_string())
                        );
                    }
                }
                Ok((_stream, peer)) => eprintln!(
                    "event=private_testnet_status_api_rejected peer={peer} reason=non_loopback"
                ),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => eprintln!(
                    "event=private_testnet_status_api_accept_error error={}",
                    sanitize(&error.to_string())
                ),
            }
        }

        let archive_range_sync_complete = archive_range_sync_pending
            .as_ref()
            .is_none_or(|pending| pending.load(AtomicOrdering::Acquire) == 0);
        if config
            .stop_after_height
            .is_some_and(|height| store.canonical_height() >= height)
            && archive_range_sync_complete
        {
            break;
        }

        if mined < config.mine_blocks {
            let canonical = store.archive().canonical_chain().clone();
            let candidate = build_next_candidate(
                &canonical,
                &params,
                &auth,
                signer.as_ref(),
                config.test_tx_amount,
                config.timestamp_offset,
                config.timestamp_backdate,
            )?;
            let payload = encode_candidate_network_block(&candidate.header, &candidate.block)
                .map_err(|error: PrivateTestnetWireError| format!("encode candidate: {error}"))?;
            let (status, height, digest) =
                handle_incoming_payload(&payload, &mut store, &params, &auth, &clock)?;
            if status != 0 {
                return Err("locally mined block unexpectedly classified as duplicate".into());
            }
            {
                let canonical = store.archive().canonical_chain();
                eprintln!(
                    "event=private_testnet_mined height={height} timestamp={} candidate_digest={} canonical_height={} canonical_state_root={} canonical_tip={}",
                    candidate.header.timestamp, hex(&digest), canonical.state().height(), hex(&canonical.state().state_root()), hex(&canonical.chain_tip().tip_hash)
                );
            }

            let mut accepted_peers = 0usize;
            let mut duplicate_acks = 0usize;
            let mut rejected_peers = Vec::new();
            for peer in &config.peers {
                match send_to_peer_for_profile(
                    *peer,
                    &payload,
                    height,
                    digest,
                    runtime_profile,
                    noise_outbound.as_ref(),
                ) {
                    Ok(()) => accepted_peers += 1,
                    Err(error) => rejected_peers.push(format!("{peer}:{}", sanitize(&error))),
                }
                if config.duplicate_broadcast {
                    match send_to_peer_for_profile(
                        *peer,
                        &payload,
                        height,
                        digest,
                        runtime_profile,
                        noise_outbound.as_ref(),
                    ) {
                        Ok(()) => duplicate_acks += 1,
                        Err(error) => {
                            rejected_peers.push(format!("{peer}:duplicate:{}", sanitize(&error)))
                        }
                    }
                }
            }
            eprintln!(
                "event=private_testnet_broadcast height={height} peers={} accepted={} duplicate_acks={} rejected={}",
                config.peers.len(), accepted_peers, duplicate_acks, rejected_peers.len()
            );
            if !rejected_peers.is_empty() {
                return Err(format!(
                    "peer broadcast failed: {}",
                    rejected_peers.join("|")
                ));
            }
            mined += 1;
            if config.exit_after_mining && mined == config.mine_blocks {
                break;
            }
            thread::sleep(Duration::from_millis(15));
        } else {
            thread::sleep(Duration::from_millis(10));
        }
    }

    reader_pool.shutdown();
    let canonical = store.archive().canonical_chain();
    eprintln!(
        "event={} listen={} height={} state_root={} consensus_tip={} archive_branches={} mined={}",
        runtime_profile.stopped_event(),
        config.listen,
        canonical.state().height(),
        hex(&canonical.state().state_root()),
        hex(&canonical.chain_tip().tip_hash),
        store.archive().archive_len(),
        mined
    );
    log_test_transaction_state("stopped", canonical, signer.as_ref());
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("event=private_testnet_fatal error={}", sanitize(&error));
        process::exit(2);
    }
}

pub fn main_devnet() {
    if let Err(error) = run_devnet() {
        eprintln!("event=devnet_node_fatal error={}", sanitize(&error));
        process::exit(2);
    }
}

#[cfg(test)]
mod socket_retry_tests {
    use super::*;
    use std::net::TcpListener;

    fn test_ack(status: u8, height: u64, digest: [u8; 32]) -> [u8; ACK_LEN] {
        let mut ack = [0u8; ACK_LEN];
        ack[..4].copy_from_slice(ACK_MAGIC);
        ack[4] = status;
        ack[5..13].copy_from_slice(&height.to_be_bytes());
        ack[13..45].copy_from_slice(&digest);
        ack
    }

    #[test]
    fn archive_range_wal_filename_is_short_and_bound_to_peer_and_snapshot() {
        let peer = [0x11; 32];
        let snapshot = [0x22; 32];
        let filename = archive_range_wal_filename(&peer, &snapshot);
        assert_eq!(filename.len(), 68);
        assert!(filename.ends_with(".arw"));
        assert_eq!(filename, archive_range_wal_filename(&peer, &snapshot));
        assert_ne!(filename, archive_range_wal_filename(&[0x12; 32], &snapshot));
        assert_ne!(filename, archive_range_wal_filename(&peer, &[0x23; 32]));
    }

    #[test]
    fn archive_range_page_item_setting_can_only_reduce_the_fixed_ceiling() {
        let default_limits = archive_range_limits();
        let single_item_limits = archive_range_limits_with_page_items(1);
        let over_ceiling_limits = archive_range_limits_with_page_items(usize::MAX);
        assert_eq!(default_limits.max_page_items, 16);
        assert_eq!(single_item_limits.max_page_items, 1);
        assert_eq!(over_ceiling_limits.max_page_items, 16);
    }

    #[test]
    fn archive_range_limits_fit_planner_and_noise_record_budgets() {
        let limits = archive_range_limits();
        assert!(
            limits.validate().is_ok(),
            "range limits must satisfy planner hard ceilings"
        );
        assert!(limits.max_envelope_bytes <= limits.max_page_bytes);
        assert!(limits.max_page_bytes <= MAX_CANDIDATE_PAGE_BYTES);
        assert!(limits.max_envelope_bytes <= MAX_CANDIDATE_ENVELOPE_BYTES);
        assert!(
            limits.max_page_bytes + 4096 <= MAX_PRIVATE_TESTNET_ENVELOPE_BYTES as u64,
            "page body plus metadata reserve must fit a single Noise record"
        );
    }

    fn accept_before(listener: &TcpListener, timeout: Duration) -> TcpStream {
        let deadline = Instant::now() + timeout;
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    return stream;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "client did not retry within deadline"
                    );
                    thread::sleep(Duration::from_millis(2));
                }
                Err(error) => panic!("accept failed: {error}"),
            }
        }
    }

    fn read_test_frame(stream: &mut TcpStream) -> Vec<u8> {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut prefix = [0u8; 4];
        stream.read_exact(&mut prefix).unwrap();
        let length = u32::from_be_bytes(prefix) as usize;
        assert!(length <= 1024, "test frame unexpectedly large");
        let mut payload = vec![0u8; length];
        stream.read_exact(&mut payload).unwrap();
        payload
    }

    #[test]
    fn send_to_peer_retries_temporary_rejection_then_accepts() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let expected_height = 7;
        let expected_digest = [0xa5; 32];
        let server = thread::spawn(move || {
            let mut seen_statuses = Vec::new();
            for status in [ACK_STATUS_UNKNOWN_PARENT, ACK_STATUS_ACCEPTED] {
                let mut stream = accept_before(&listener, Duration::from_secs(4));
                let payload = read_test_frame(&mut stream);
                assert_eq!(payload, b"candidate-fixture");
                let ack = if status == 0 {
                    test_ack(status, expected_height, expected_digest)
                } else {
                    test_ack(status, 0, [0; 32])
                };
                stream.write_all(&ack).unwrap();
                stream.flush().unwrap();
                seen_statuses.push(status);
            }
            seen_statuses
        });

        let result = send_to_peer(
            address,
            b"candidate-fixture",
            expected_height,
            expected_digest,
        );
        assert!(
            result.is_ok(),
            "bounded rejection retry did not recover: {result:?}"
        );
        assert_eq!(
            server.join().unwrap(),
            vec![ACK_STATUS_UNKNOWN_PARENT, ACK_STATUS_ACCEPTED]
        );
    }

    #[test]
    fn send_to_peer_does_not_retry_permanent_rejection() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut stream = accept_before(&listener, Duration::from_secs(4));
            let payload = read_test_frame(&mut stream);
            assert_eq!(payload, b"candidate-fixture");
            let ack = test_ack(ACK_STATUS_REJECTED, 0, [0; 32]);
            stream.write_all(&ack).unwrap();
            stream.flush().unwrap();
            1usize
        });

        let result = send_to_peer(address, b"candidate-fixture", 7, [0x5a; 32]);
        assert!(result.is_err(), "permanent rejection must fail closed");
        assert!(result.unwrap_err().contains("permanently rejected"));
        assert_eq!(server.join().unwrap(), 1);
    }
    #[test]
    fn send_to_peer_bounds_persistent_unknown_parent_to_ten_attempts() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let expected_height = 7;
        let expected_digest = [0x5a; 32];
        let server = thread::spawn(move || {
            let mut attempts = 0usize;
            while attempts < 10 {
                let mut stream = accept_before(&listener, Duration::from_secs(5));
                let payload = read_test_frame(&mut stream);
                assert_eq!(payload, b"candidate-fixture");
                let ack = test_ack(ACK_STATUS_UNKNOWN_PARENT, 0, [0; 32]);
                stream.write_all(&ack).unwrap();
                stream.flush().unwrap();
                attempts += 1;
            }
            attempts
        });

        let result = send_to_peer(
            address,
            b"candidate-fixture",
            expected_height,
            expected_digest,
        );
        assert!(result.is_err(), "persistent rejection must fail closed");
        let error = result.unwrap_err();
        assert!(
            error.contains("has not imported the parent"),
            "unexpected persistent unknown-parent error: {error}"
        );
        assert_eq!(server.join().unwrap(), 10);
    }

    #[test]
    fn archive_sync_retries_only_transient_delivery_errors() {
        let retryable = [
            "connect 127.0.0.1:1: actively refused",
            "write peer frame: connection reset",
            "read peer acknowledgement: timed out",
            "peer 127.0.0.1:1 has not imported the parent for candidate height 2",
        ];
        for error in retryable {
            assert!(
                archive_sync_error_is_retryable(error),
                "transient archive-sync error was not retryable: {error}"
            );
        }

        let fail_closed = [
            "peer 127.0.0.1:1 permanently rejected candidate height 2 with status 2",
            "peer 127.0.0.1:1 returned malformed acknowledgement",
            "peer 127.0.0.1:1 ACK does not bind the submitted candidate",
        ];
        for error in fail_closed {
            assert!(
                !archive_sync_error_is_retryable(error),
                "permanent/protocol error must not be retried: {error}"
            );
        }
    }

    #[test]
    fn send_to_peer_rejects_zero_attempt_budget() {
        let address = "127.0.0.1:1".parse().unwrap();
        let error = send_to_peer_with_attempts(address, b"", 1, [0; 32], 0).unwrap_err();
        assert_eq!(error, "peer send attempt limit must be nonzero");
    }
}

#[cfg(test)]
mod status_api_tests {
    use super::*;

    fn request(line: &str) -> Vec<u8> {
        format!("{line}\r\nHost: localhost\r\n\r\n").into_bytes()
    }

    #[test]
    fn txn4_http_requires_exact_binary_body_and_canonical_route() {
        let header = format!(
            "POST /tx/submit HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
            V4_HYBRID_TRANSACTION_WIRE_BYTES
        );
        let mut request = header.as_bytes().to_vec();
        let body = vec![0x5A; V4_HYBRID_TRANSACTION_WIRE_BYTES];
        request.extend_from_slice(&body);
        assert_eq!(
            decode_txn4_submit_request(&request).unwrap(),
            body.as_slice()
        );
        assert_eq!(
            parse_txn4_submit_headers(header.as_bytes()),
            Ok(V4_HYBRID_TRANSACTION_WIRE_BYTES)
        );
        assert_eq!(
            parse_txn4_submit_headers(
                b"GET /tx/submit HTTP/1.1\r\nContent-Type: application/octet-stream\r\nContent-Length: 1\r\n\r\n"
            ),
            Err(405)
        );
        assert_eq!(
            parse_txn4_submit_headers(
                b"POST /status HTTP/1.1\r\nContent-Type: application/octet-stream\r\nContent-Length: 1\r\n\r\n"
            ),
            Err(404)
        );
        assert_eq!(
            parse_txn4_submit_headers(
                b"POST /tx/submit HTTP/1.1\r\nContent-Type: application/octet-stream\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n"
            ),
            Err(400)
        );
        assert_eq!(
            parse_txn4_submit_headers(
                b"POST /tx/submit HTTP/1.1\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\nContent-Length: 1\r\n\r\n"
            ),
            Err(400)
        );
        assert_eq!(
            parse_txn4_submit_headers(b"POST /tx/submit HTTP/1.1\r\nContent-Length: 1\r\n\r\n"),
            Err(415)
        );
        assert_eq!(
            parse_txn4_submit_headers(
                b"POST /tx/submit HTTP/1.1\r\nContent-Type: application/octet-stream\r\n\r\n"
            ),
            Err(411)
        );
    }

    #[test]
    fn txn4_http_rejects_wrong_size_truncation_and_oversized_headers() {
        let too_short = b"POST /tx/submit HTTP/1.1\r\nContent-Type: application/octet-stream\r\nContent-Length: 1\r\n\r\n";
        assert_eq!(parse_txn4_submit_headers(too_short), Err(413));
        let canonical_header = format!(
            "POST /tx/submit HTTP/1.1\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
            V4_HYBRID_TRANSACTION_WIRE_BYTES
        );
        let request = canonical_header.as_bytes().to_vec();
        assert_eq!(decode_txn4_submit_request(&request), Err(400));
        assert_eq!(
            parse_txn4_submit_headers(&vec![b'X'; MAX_TXN4_HTTP_HEADER_BYTES + 1]),
            Err(431)
        );
    }

    #[test]
    fn status_routes_accept_only_read_only_get_paths() {
        assert_eq!(
            classify_status_request(&request("GET /health HTTP/1.1")),
            Ok(StatusRoute::Health)
        );
        assert_eq!(
            classify_status_request(&request("GET /status HTTP/1.1")),
            Ok(StatusRoute::Status)
        );
        assert_eq!(
            classify_status_request(&request("POST /status HTTP/1.1")),
            Err(405)
        );
        assert_eq!(
            classify_status_request(&request("GET /tx/send HTTP/1.1")),
            Err(404)
        );
        assert_eq!(
            classify_status_request(&request("GET /status HTTP/2")),
            Err(400)
        );
    }

    #[test]
    fn status_routes_reject_incomplete_and_oversized_requests() {
        assert_eq!(
            classify_status_request(b"GET /status HTTP/1.1\r\n"),
            Err(400)
        );
        assert_eq!(
            classify_status_request(&vec![b'X'; MAX_STATUS_HTTP_BYTES + 1]),
            Err(431)
        );
    }

    #[test]
    fn status_json_binds_real_network_state_and_explicit_no_value_profile() {
        let body = status_json(
            &[0x11; 32],
            7,
            &[0x22; 32],
            &[0x33; 32],
            9,
            "loopback-private-testnet",
        );
        assert!(body.contains(
            "\"network_id\":\"1111111111111111111111111111111111111111111111111111111111111111\""
        ));
        assert!(body.contains("\"height\":7"));
        assert!(body.contains(
            "\"state_root\":\"2222222222222222222222222222222222222222222222222222222222222222\""
        ));
        assert!(body.contains("\"consensus_tip\":\"3333333333333333333333333333333333333333333333333333333333333333\""));
        assert!(body.contains("\"archive_branches\":9"));
        assert!(body.contains("\"profile\":\"loopback-private-testnet\""));
        assert!(body.contains("\"value_bearing\":false"));
    }

    #[test]
    fn error_responses_are_json_and_do_not_disclose_request_data() {
        assert_eq!(
            status_http_body(405, None, "{}"),
            "{\"error\":\"method_not_allowed\"}"
        );
        assert_eq!(
            status_http_body(408, None, "{}"),
            "{\"error\":\"request_timeout\"}"
        );
        assert_eq!(
            status_http_body(431, None, "{}"),
            "{\"error\":\"request_too_large\"}"
        );
    }
}

#[cfg(test)]
mod signed_identity_runtime_tests {
    use super::*;
    use ai_native_l1_pow_bench::identity_policy::{encode, KeyAlgorithm, KeyRecord, KeyState};
    use ai_native_l1_pow_bench::v4_account_identity_candidate::{
        native_v4_account_id, AccountIdentityScheme, V4HybridAuthorization, V4HybridSignature,
    };
    use ai_native_l1_pow_bench::v4_transaction_mempool_candidate::{
        V4HybridMempoolCandidate, V4HybridMempoolLimits,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use libcrux_ml_dsa::ml_dsa_65::portable;
    use std::time::{SystemTime, UNIX_EPOCH};

    const IDENTITY_DOMAIN: &[u8] = b"AIN1-DEVNET-SIGNED-PEER-IDENTITY-V1\0";

    fn root() -> PathBuf {
        let tick = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "ain1_signed_peer_runtime_{}_{}",
            std::process::id(),
            tick
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn record(public_key: [u8; 32]) -> KeyRecord {
        record_with_state(public_key, KeyState::Active)
    }

    fn record_with_state(public_key: [u8; 32], state: KeyState) -> KeyRecord {
        record_with_state_and_window(public_key, state, 0, u64::MAX)
    }

    fn record_with_state_and_window(
        public_key: [u8; 32],
        state: KeyState,
        not_before: u64,
        not_after: u64,
    ) -> KeyRecord {
        KeyRecord {
            key_id: 700,
            generation: 1,
            algorithm: KeyAlgorithm::NoiseX25519,
            purpose: KeyPurpose::PeerAuth,
            state,
            not_before,
            not_after,
            public_key: public_key.to_vec(),
        }
    }

    fn signed_identity(
        network: [u8; 32],
        credential_id: u128,
        issuer_id: u32,
        record: &KeyRecord,
        issuer: &SigningKey,
    ) -> Vec<u8> {
        let record_wire = encode(record).unwrap();
        let mut wire = Vec::new();
        wire.extend_from_slice(b"NPI1");
        wire.extend_from_slice(&1u16.to_be_bytes());
        wire.extend_from_slice(&network);
        wire.extend_from_slice(&credential_id.to_be_bytes());
        wire.extend_from_slice(&issuer_id.to_be_bytes());
        wire.extend_from_slice(&(record_wire.len() as u16).to_be_bytes());
        wire.extend_from_slice(&0u16.to_be_bytes());
        wire.extend_from_slice(&record_wire);
        let mut preimage = IDENTITY_DOMAIN.to_vec();
        preimage.extend_from_slice(&wire);
        wire.extend_from_slice(&issuer.sign(&preimage).to_bytes());
        wire
    }

    fn deployment_authority_key() -> SigningKey {
        SigningKey::from_bytes(&[0x94; 32])
    }

    fn governance_key() -> SigningKey {
        SigningKey::from_bytes(&[0x95; 32])
    }

    fn recovery_key() -> SigningKey {
        SigningKey::from_bytes(&[0x96; 32])
    }

    fn issuer_key() -> SigningKey {
        SigningKey::from_bytes(&[0x91; 32])
    }

    fn encode_deployment_config(
        network: [u8; 32],
        sequence: u64,
        authority: &SigningKey,
        governance: &SigningKey,
        recovery: &SigningKey,
    ) -> Vec<u8> {
        // A one-root GRC1 chain. The governance root and original root anchor are identical;
        // the deployment authority and offline recovery key remain distinct.
        let mut root_chain = b"GRC1".to_vec();
        root_chain.extend_from_slice(&1u16.to_be_bytes());
        root_chain.extend_from_slice(&network);
        root_chain.extend_from_slice(&0u16.to_be_bytes());
        let mut core = Vec::new();
        core.extend_from_slice(b"DPC1");
        core.extend_from_slice(&1u16.to_be_bytes());
        core.extend_from_slice(&network);
        core.extend_from_slice(&sequence.to_be_bytes());
        core.extend_from_slice(&governance.verifying_key().to_bytes());
        core.extend_from_slice(&governance.verifying_key().to_bytes());
        core.extend_from_slice(&recovery.verifying_key().to_bytes());
        core.extend_from_slice(&1u64.to_be_bytes()); // minimum root epoch
        core.extend_from_slice(&1u64.to_be_bytes()); // minimum issuer-registry sequence
        core.extend_from_slice(&(root_chain.len() as u32).to_be_bytes());
        core.extend_from_slice(&root_chain);
        let mut preimage = b"AIN1-NOISE-DEPLOYMENT-CONFIG-V1\0".to_vec();
        preimage.extend_from_slice(&core);
        core.extend_from_slice(&authority.sign(&preimage).to_bytes());
        core
    }

    fn encode_issuer_registry(
        network: [u8; 32],
        sequence: u64,
        issuer_id: u32,
        issuer_status: u8,
        issuer: &SigningKey,
        governance: &SigningKey,
    ) -> Vec<u8> {
        let mut core = Vec::new();
        core.extend_from_slice(b"IRG1");
        core.extend_from_slice(&1u16.to_be_bytes());
        core.extend_from_slice(&network);
        core.extend_from_slice(&sequence.to_be_bytes());
        core.extend_from_slice(&1u16.to_be_bytes());
        core.extend_from_slice(&issuer_id.to_be_bytes());
        core.push(issuer_status);
        core.extend_from_slice(&issuer.verifying_key().to_bytes());
        let mut preimage = b"AIN1-NOISE-ISSUER-REGISTRY-V1\0".to_vec();
        preimage.extend_from_slice(&core);
        core.extend_from_slice(&governance.sign(&preimage).to_bytes());
        core
    }

    fn write_trust_bootstrap(
        root: &Path,
        network: [u8; 32],
        authority: &SigningKey,
        issuer: &SigningKey,
        registry_sequence: u64,
        issuer_status: u8,
    ) {
        fs::create_dir_all(root).unwrap();
        let governance = governance_key();
        let recovery = recovery_key();
        fs::write(
            root.join("deployment.dpc1"),
            encode_deployment_config(network, 1, authority, &governance, &recovery),
        )
        .unwrap();
        fs::write(
            root.join("issuer-registry.irg1"),
            encode_issuer_registry(
                network,
                registry_sequence,
                17,
                issuer_status,
                issuer,
                &governance,
            ),
        )
        .unwrap();
    }

    fn runtime_config(root: &Path, network: [u8; 32], authority: &SigningKey) -> Config {
        let issuer = issuer_key();
        write_trust_bootstrap(root, network, authority, &issuer, 1, 1);
        Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            status_listen: None,
            transaction_listen: None,
            v4_founder_ed25519_public_key: None,
            v4_founder_mldsa65_public_key_file: None,
            network_id: network,
            data_dir: root.to_path_buf(),
            peers: Vec::new(),
            mine_blocks: 0,
            stop_after_height: None,
            timestamp_offset: 0,
            timestamp_backdate: 0,
            test_transactions: false,
            test_seed_file: None,
            noise_static_private_key_dpapi_file: None,
            trusted_peer_keys: Vec::new(),
            trusted_peer_identity_files: vec![root.join("peer.npi")],
            deployment_config_file: Some(root.join("deployment.dpc1")),
            deployment_authority_public_key: Some(authority.verifying_key().to_bytes()),
            deployment_config_min_sequence: Some(1),
            issuer_registry_file: Some(root.join("issuer-registry.irg1")),
            peer_identity_issuer_id: Some(17),
            test_tx_amount: TEST_TX_AMOUNT,
            duplicate_broadcast: false,
            archive_sync_delay_ms: 0,
            archive_sync_reverse_first_round: false,
            archive_range_max_page_items: 16,
            archive_range_post_commit_delay_ms: 0,
            run_seconds: 1,
            exit_after_mining: false,
            monetary_candidate_local_smoke: false,
            monetary_v4_hybrid_local_smoke: false,
            monetary_v4_hybrid_peer_smoke: false,
            monetary_v4_hybrid_archive_range_sync: false,
            monetary_candidate_peer_smoke: false,
            monetary_candidate_archive_range_sync: false,
            test_crash_after_monetary_import: false,
            test_crash_after_monetary_v4_import: false,
            test_reorg_after_first_archive_range_page: false,
            test_reorg_after_second_archive_range_page: false,
        }
    }

    fn local_monetary_config(root: &Path, network: [u8; 32]) -> Config {
        Config {
            listen: "127.0.0.1:49301".parse().unwrap(),
            status_listen: None,
            transaction_listen: None,
            v4_founder_ed25519_public_key: None,
            v4_founder_mldsa65_public_key_file: None,
            network_id: network,
            data_dir: root.to_path_buf(),
            peers: Vec::new(),
            mine_blocks: 1,
            stop_after_height: None,
            timestamp_offset: 0,
            timestamp_backdate: 0,
            test_transactions: false,
            test_seed_file: None,
            noise_static_private_key_dpapi_file: None,
            trusted_peer_keys: Vec::new(),
            trusted_peer_identity_files: Vec::new(),
            deployment_config_file: None,
            deployment_authority_public_key: None,
            deployment_config_min_sequence: None,
            issuer_registry_file: None,
            peer_identity_issuer_id: None,
            test_tx_amount: TEST_TX_AMOUNT,
            duplicate_broadcast: false,
            archive_sync_delay_ms: 0,
            archive_sync_reverse_first_round: false,
            archive_range_max_page_items: 16,
            archive_range_post_commit_delay_ms: 0,
            run_seconds: 30,
            exit_after_mining: true,
            monetary_candidate_local_smoke: true,
            monetary_v4_hybrid_local_smoke: false,
            monetary_v4_hybrid_peer_smoke: false,
            monetary_v4_hybrid_archive_range_sync: false,
            monetary_candidate_peer_smoke: false,
            monetary_candidate_archive_range_sync: false,
            test_crash_after_monetary_import: false,
            test_crash_after_monetary_v4_import: false,
            test_reorg_after_first_archive_range_page: false,
            test_reorg_after_second_archive_range_page: false,
        }
    }

    #[test]
    fn monetary_v4_archive_range_magic_is_version_locked() {
        let v4_request =
            encode_archive_range_request_with_magic(None, MONETARY_V4_ARCHIVE_RANGE_REQUEST_MAGIC);
        assert_eq!(&v4_request[..4], b"ARQ4");
        assert_eq!(
            decode_archive_range_request_with_magic(
                &v4_request,
                MONETARY_V4_ARCHIVE_RANGE_REQUEST_MAGIC,
            )
            .unwrap(),
            None,
        );
        assert!(decode_archive_range_request(&v4_request).is_err());
        let v3_request = encode_archive_range_request(None);
        assert_eq!(&v3_request[..4], b"ARQ1");
        assert!(decode_archive_range_request_with_magic(
            &v3_request,
            MONETARY_V4_ARCHIVE_RANGE_REQUEST_MAGIC,
        )
        .is_err());

        assert!(decode_archive_range_page_with_magic(
            b"ARW1\\0\\0\\0\\0",
            MONETARY_V4_ARCHIVE_RANGE_PAGE_MAGIC,
        )
        .is_err());
        assert!(decode_archive_range_page_with_magic(
            b"ARW4\\0\\0\\0\\0",
            ARCHIVE_RANGE_PAGE_MAGIC,
        )
        .is_err());
    }

    #[test]
    fn monetary_v4_peer_mode_requires_noise_trust_and_loopback_only() {
        let root = root();
        let network = [0x79; 32];
        let mut config = local_monetary_config(&root, network);
        config.monetary_candidate_local_smoke = false;
        config.monetary_v4_hybrid_local_smoke = false;
        config.monetary_v4_hybrid_peer_smoke = true;
        config.listen = "127.0.0.1:49311".parse().unwrap();
        config.peers = vec!["127.0.0.1:49312".parse().unwrap()];
        config.noise_static_private_key_dpapi_file = Some(root.join("node.npk1"));
        config.trusted_peer_keys = vec![[0x5a; 32]];
        validate_monetary_v4_peer_config(&config).unwrap();

        let mut no_peer = config.clone();
        no_peer.peers.clear();
        assert!(validate_monetary_v4_peer_config(&no_peer).is_err());

        let mut no_noise = config.clone();
        no_noise.noise_static_private_key_dpapi_file = None;
        assert!(validate_monetary_v4_peer_config(&no_noise).is_err());

        let mut no_trust = config.clone();
        no_trust.trusted_peer_keys.clear();
        assert!(validate_monetary_v4_peer_config(&no_trust).is_err());

        let mut remote_peer = config.clone();
        remote_peer.peers = vec!["192.0.2.13:49312".parse().unwrap()];
        assert!(validate_monetary_v4_peer_config(&remote_peer).is_err());

        let mut transactions = config.clone();
        transactions.test_transactions = true;
        assert!(validate_monetary_v4_peer_config(&transactions).is_err());

        let mut legacy_archive = config.clone();
        legacy_archive.monetary_candidate_archive_range_sync = true;
        assert!(validate_monetary_v4_peer_config(&legacy_archive).is_err());

        let mut crash_without_archive_sync = config.clone();
        crash_without_archive_sync.test_crash_after_monetary_v4_import = true;
        assert!(validate_monetary_v4_peer_config(&crash_without_archive_sync).is_err());

        let mut crash_test_config = config.clone();
        crash_test_config.monetary_v4_hybrid_archive_range_sync = true;
        crash_test_config.archive_range_max_page_items = 1;
        crash_test_config.test_crash_after_monetary_v4_import = true;
        validate_monetary_v4_peer_config(&crash_test_config).unwrap();

        let mut reorg_without_archive_sync = config.clone();
        reorg_without_archive_sync.test_reorg_after_first_archive_range_page = true;
        assert!(validate_monetary_v4_peer_config(&reorg_without_archive_sync).is_err());
        let mut second_page_reorg_without_archive_sync = config.clone();
        second_page_reorg_without_archive_sync.test_reorg_after_second_archive_range_page = true;
        assert!(validate_monetary_v4_peer_config(&second_page_reorg_without_archive_sync).is_err());

        let mut second_page_reorg_test_config = config.clone();
        second_page_reorg_test_config.monetary_v4_hybrid_archive_range_sync = true;
        second_page_reorg_test_config.archive_range_max_page_items = 1;
        second_page_reorg_test_config.test_reorg_after_second_archive_range_page = true;
        validate_monetary_v4_peer_config(&second_page_reorg_test_config).unwrap();

        let mut second_page_reorg_multi_peer = second_page_reorg_test_config.clone();
        second_page_reorg_multi_peer
            .peers
            .push("127.0.0.1:49303".parse().unwrap());
        second_page_reorg_multi_peer
            .trusted_peer_keys
            .push([0x6b; 32]);
        assert!(validate_monetary_v4_peer_config(&second_page_reorg_multi_peer).is_err());

        let mut reorg_test_config = config.clone();
        reorg_test_config.monetary_v4_hybrid_archive_range_sync = true;
        reorg_test_config.archive_range_max_page_items = 1;
        reorg_test_config.test_reorg_after_first_archive_range_page = true;
        validate_monetary_v4_peer_config(&reorg_test_config).unwrap();

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn monetary_peer_mode_requires_loopback_peer_and_one_authenticated_trust_entry() {
        let root = root();
        let network = [0x75; 32];
        let mut config = local_monetary_config(&root, network);
        config.peers = vec!["127.0.0.1:49302".parse().unwrap()];
        config.noise_static_private_key_dpapi_file = Some(root.join("node.npk1"));
        config.trusted_peer_keys = vec![[0x5a; 32]];
        validate_monetary_candidate_peer_config(&config).unwrap();

        let mut no_peer = config.clone();
        no_peer.peers.clear();
        assert!(validate_monetary_candidate_peer_config(&no_peer).is_err());

        let mut no_noise = config.clone();
        no_noise.noise_static_private_key_dpapi_file = None;
        assert!(validate_monetary_candidate_peer_config(&no_noise).is_err());

        let mut no_trust = config.clone();
        no_trust.trusted_peer_keys.clear();
        assert!(validate_monetary_candidate_peer_config(&no_trust).is_err());

        let mut mismatched_trust = config.clone();
        mismatched_trust.trusted_peer_keys.push([0x6b; 32]);
        assert!(validate_monetary_candidate_peer_config(&mismatched_trust).is_err());

        let mut mixed_trust = config.clone();
        mixed_trust
            .trusted_peer_identity_files
            .push(root.join("peer.npi"));
        assert!(validate_monetary_candidate_peer_config(&mixed_trust).is_err());

        let mut remote_peer = config.clone();
        remote_peer.peers = vec!["192.0.2.7:49302".parse().unwrap()];
        assert!(validate_monetary_candidate_peer_config(&remote_peer).is_err());

        let mut status_listener = config.clone();
        status_listener.status_listen = Some("127.0.0.1:49303".parse().unwrap());
        validate_monetary_candidate_peer_config(&status_listener).unwrap();

        let mut remote_status_listener = config.clone();
        remote_status_listener.status_listen = Some("0.0.0.0:49303".parse().unwrap());
        assert!(validate_monetary_candidate_peer_config(&remote_status_listener).is_err());

        let mut same_status_listener = config.clone();
        same_status_listener.status_listen = Some(config.listen);
        assert!(validate_monetary_candidate_peer_config(&same_status_listener).is_err());

        let mut transaction_fixture = config.clone();
        transaction_fixture.test_transactions = true;
        assert!(validate_monetary_candidate_peer_config(&transaction_fixture).is_err());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn monetary_genesis_manifest_is_stable_and_fails_closed_on_tamper() {
        let root = root();
        let network = [0x72; 32];
        let profile = DevnetProfileCandidate::new(network).unwrap();
        let founder = local_monetary_account_id(&network, b"founder-placeholder");
        let public_goods = local_monetary_account_id(&network, b"public-goods-placeholder");
        let genesis = MonetaryLedgerState::genesis(
            network,
            founder,
            vec![(public_goods, MONETARY_PUBLIC_GOODS_BUDGET_ATOMS as u64)],
        )
        .unwrap();
        let mut params = profile.consensus().clone();
        params.initial_target = Uint256::MAX;
        params.pow.memory_kib = 8 * 1024;
        params.validate().unwrap();
        let manifest = encode_monetary_genesis_manifest(&profile, &params, &genesis).unwrap();
        assert_eq!(&manifest[..4], b"MGN3");
        persist_or_verify_monetary_genesis_manifest(&root, &manifest).unwrap();
        persist_or_verify_monetary_genesis_manifest(&root, &manifest).unwrap();

        let path = root.join("monetary-genesis.mgn3");
        let mut tampered = fs::read(&path).unwrap();
        tampered[10] ^= 1;
        fs::write(&path, tampered).unwrap();
        let error = persist_or_verify_monetary_genesis_manifest(&root, &manifest)
            .expect_err("tampered monetary profile manifest must fail closed");
        assert!(error.contains("conflicts"));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn monetary_local_mode_requires_explicit_offline_mining() {
        let root = root();
        let network = [0x73; 32];
        let config = local_monetary_config(&root, network);
        validate_monetary_candidate_local_config(&config).unwrap();

        let mut networked = config.clone();
        networked.peers.push("127.0.0.1:49302".parse().unwrap());
        assert!(validate_monetary_candidate_local_config(&networked).is_err());

        let mut no_explicit_exit = config.clone();
        no_explicit_exit.exit_after_mining = false;
        assert!(validate_monetary_candidate_local_config(&no_explicit_exit).is_err());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn monetary_v4_hybrid_local_mode_refuses_networked_or_legacy_profile_reuse() {
        let root = root();
        let network = [0x76; 32];
        let mut config = local_monetary_config(&root, network);
        config.monetary_candidate_local_smoke = false;
        config.monetary_v4_hybrid_local_smoke = true;
        validate_monetary_candidate_local_config(&config).unwrap();

        let mut networked = config.clone();
        networked.peers.push("127.0.0.1:49302".parse().unwrap());
        assert!(validate_monetary_candidate_local_config(&networked).is_err());

        let mut no_explicit_exit = config.clone();
        no_explicit_exit.exit_after_mining = false;
        assert!(validate_monetary_candidate_local_config(&no_explicit_exit).is_err());

        let mut tx_fixture = config.clone();
        tx_fixture.test_transactions = true;
        assert!(validate_monetary_candidate_local_config(&tx_fixture).is_err());

        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("monetary-genesis.mgn3"), b"legacy-profile-marker").unwrap();
        assert!(run_monetary_v4_hybrid_local_smoke(&config).is_err());
        assert!(
            !root.join("monetary-genesis.mgn4").exists(),
            "V4 run must reject the legacy profile before creating V4 state"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn monetary_v4_hybrid_runtime_smoke_persists_pmt4_pfm4_and_replays() {
        let root = root();
        let network = [0x77; 32];
        let mut config = local_monetary_config(&root, network);
        config.monetary_candidate_local_smoke = false;
        config.monetary_v4_hybrid_local_smoke = true;
        config.mine_blocks = 1;

        run_monetary_v4_hybrid_local_smoke(&config).unwrap();

        assert!(root.join("monetary-genesis.mgn4").is_file());
        assert!(!root.join("monetary-genesis.mgn3").exists());
        let store_dir = root.join("devnet_forkstore_pfm4");
        let manifest = fs::read(store_dir.join("monetary-v4-forkstore.manifest")).unwrap();
        assert!(manifest.starts_with(b"PFM4"));
        let branches: Vec<_> = fs::read_dir(&store_dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                let name = entry.file_name().to_string_lossy().into_owned();
                name.starts_with("monetary-v4-branch-") && name.ends_with(".pmt4")
            })
            .collect();
        assert_eq!(branches.len(), 1);
        assert!(!root.join("devnet_forkstore_pfm3").exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn pmt4_configured_genesis_binds_founder_to_explicit_hybrid_public_keys() {
        let root = root();
        let network = [0x7B; 32];
        let ed_signer = SigningKey::from_bytes(&[0x35; 32]);
        let pq_pair = portable::generate_key_pair([0x46; 32]);
        let ed_public = ed_signer.verifying_key().to_bytes();
        let pq_public = *pq_pair.verification_key.as_ref();
        let key_file = root.join("founder-mldsa65.pub");
        fs::write(&key_file, pq_public).unwrap();

        let mut config = local_monetary_config(&root, network);
        config.v4_founder_ed25519_public_key = Some(ed_public);
        config.v4_founder_mldsa65_public_key_file = Some(key_file);
        let (genesis, founder, _, _) = configured_local_monetary_v4_genesis(&config).unwrap();
        assert_eq!(founder, native_v4_account_id(&ed_public, &pq_public));
        assert!(genesis.ledger().account(&founder).unwrap().balance > 0);

        let mut changed_ed = ed_public;
        changed_ed[0] ^= 1;
        config.v4_founder_ed25519_public_key = Some(changed_ed);
        let (other_genesis, other_founder, _, _) =
            configured_local_monetary_v4_genesis(&config).unwrap();
        assert_ne!(founder, other_founder);
        assert!(other_genesis.ledger().account(&founder).is_none());
        assert_eq!(
            other_genesis
                .ledger()
                .account(&other_founder)
                .unwrap()
                .balance,
            genesis.ledger().account(&founder).unwrap().balance
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pmt4_runtime_builder_imports_real_signed_txn4_and_replays() {
        let root = root();
        let network = [0x7A; 32];
        let profile = DevnetProfileCandidate::new(network).unwrap();
        let mut params = profile.consensus().clone();
        params.initial_target = Uint256::MAX;
        params.pow.memory_kib = 8 * 1024;
        params.validate().unwrap();
        let manifest_id = local_monetary_v4_manifest_id(&profile, &params);
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let clock = SystemClockReferenceTime;

        // Disposable keys are generated only by this test. The production binary and CLI never
        // derive or embed these test keys.
        let ed_signer = SigningKey::from_bytes(&[0x31; 32]);
        let pq_pair = portable::generate_key_pair([0x42; 32]);
        let ed_public_key = ed_signer.verifying_key().to_bytes();
        let mldsa65_public_key = *pq_pair.verification_key.as_ref();
        let sender = native_v4_account_id(&ed_public_key, &mldsa65_public_key);
        let recipient = [0xCC; 32];
        let public_goods = local_monetary_account_id(&network, b"signed-txn4-test-public-goods");
        let miner = local_monetary_account_id(&network, b"signed-txn4-test-miner");
        assert_ne!(sender, recipient);
        assert_ne!(sender, public_goods);
        assert_ne!(sender, miner);
        assert_ne!(recipient, public_goods);
        assert_ne!(recipient, miner);
        assert_ne!(public_goods, miner);

        let public_goods_budget = u64::try_from(MONETARY_PUBLIC_GOODS_BUDGET_ATOMS).unwrap();
        let genesis = MonetaryLedgerState::genesis(
            network,
            sender,
            vec![(public_goods, public_goods_budget)],
        )
        .unwrap();
        let initial_sender_balance = genesis.ledger().account(&sender).unwrap().balance;
        let initial_total_value = genesis.total_value().unwrap();
        let expiry = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_add(3_600);
        let authorization = V4HybridAuthorization {
            network_id: network,
            manifest_id,
            sender_id: sender,
            recipient_id: recipient,
            nonce: 1,
            amount_atoms: 1_000,
            fee_atoms: 17,
            expires_at: expiry,
            identity_scheme: AccountIdentityScheme::NativeV4Hybrid,
            ed25519_public_key: ed_public_key,
            mldsa65_public_key,
        };
        let signing_digest = authorization.signing_digest().unwrap();
        let pq_signature =
            portable::sign(&pq_pair.signing_key, &signing_digest, &[], [0x53; 32]).unwrap();
        let transaction = V4HybridTransaction {
            authorization,
            signature: V4HybridSignature {
                ed25519_signature: ed_signer.sign(&signing_digest).to_bytes(),
                mldsa65_signature: *pq_signature.as_ref(),
            },
        };
        transaction.verify(&verifier).unwrap();

        let parent = PrivateTestnetChain::new_monetary(genesis.clone(), params.clone()).unwrap();
        let store_dir = root.join("signed-txn4-pfm4");
        let mut store = PrivateTestnetV4HybridForkStore::open(
            &store_dir,
            genesis.clone(),
            params.clone(),
            manifest_id,
            &verifier,
            &clock,
        )
        .unwrap();
        let empty_anchor = store.manifest_anchor().unwrap();

        let mut invalid = transaction.clone();
        invalid.signature.mldsa65_signature[0] ^= 1;
        assert!(build_next_v4_hybrid_monetary_candidate_with_transactions(
            &parent,
            &params,
            &manifest_id,
            &verifier,
            miner,
            0,
            0,
            vec![invalid],
        )
        .is_err());
        assert_eq!(store.canonical_height(), 0);
        assert_eq!(store.manifest_anchor().unwrap(), empty_anchor);

        let mut mempool =
            V4HybridMempoolCandidate::new(network, manifest_id, V4HybridMempoolLimits::default())
                .unwrap();
        let admission_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut invalid_pool_transaction = transaction.clone();
        invalid_pool_transaction.signature.mldsa65_signature[0] ^= 1;
        assert!(mempool
            .submit(
                invalid_pool_transaction,
                &genesis,
                &verifier,
                admission_timestamp,
                miner,
            )
            .is_err());
        assert!(mempool.is_empty());
        assert_eq!(store.manifest_anchor().unwrap(), empty_anchor);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (accepted, peer) = listener.accept().unwrap();
        assert!(peer.ip().is_loopback());
        let tx_wire = transaction.encode().unwrap();
        let headers = format!(
            "POST /tx/submit HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
            tx_wire.len()
        );
        client.write_all(headers.as_bytes()).unwrap();
        client.write_all(&tx_wire).unwrap();
        client.flush().unwrap();
        serve_v4_transaction_submit_connection(accepted, &mut mempool, &store, &verifier, miner);
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(response.starts_with("HTTP/1.1 202 Accepted"));
        assert!(response.contains("\"status\":\"accepted\""));
        assert_eq!(mempool.len(), 1);
        let selected_transactions = mempool.ordered_transactions();
        assert_eq!(selected_transactions.len(), 1);

        let payload = build_next_v4_hybrid_monetary_candidate_with_transactions(
            &parent,
            &params,
            &manifest_id,
            &verifier,
            miner,
            0,
            0,
            selected_transactions,
        )
        .unwrap();
        let (status, outcome) =
            import_v4_hybrid_monetary_payload(&payload, &mut store, &params, &verifier, &clock)
                .unwrap();
        assert_eq!(status, ACK_STATUS_ACCEPTED);
        assert!(outcome.canonical_changed);
        assert_eq!(outcome.canonical_height, 1);
        assert_eq!(store.canonical_height(), 1);

        let state = store.archive().canonical_chain().monetary_state().unwrap();
        assert_eq!(
            state.ledger().account(&sender).unwrap().balance,
            initial_sender_balance - 1_017
        );
        assert_eq!(state.ledger().account(&sender).unwrap().nonce, 1);
        assert_eq!(state.ledger().account(&recipient).unwrap().balance, 1_000);
        assert_eq!(
            state.total_value().unwrap(),
            initial_total_value + u128::from(state.total_mined_atoms())
        );
        assert_eq!(mempool.remove_included(&[transaction.clone()]), 1);
        assert!(mempool.is_empty());
        let expected_root = state.state_root();
        let expected_tip = store.canonical_tip();
        let anchor = store.manifest_anchor().unwrap();
        drop(store);

        let reopened = PrivateTestnetV4HybridForkStore::open_anchored(
            &store_dir,
            genesis,
            params,
            manifest_id,
            &verifier,
            &clock,
            anchor,
        )
        .unwrap();
        let replayed = reopened
            .archive()
            .canonical_chain()
            .monetary_state()
            .unwrap();
        assert_eq!(reopened.canonical_height(), 1);
        assert_eq!(reopened.canonical_tip(), expected_tip);
        assert_eq!(replayed.state_root(), expected_root);
        assert_eq!(replayed.ledger().account(&sender).unwrap().nonce, 1);
        assert_eq!(
            replayed.ledger().account(&recipient).unwrap().balance,
            1_000
        );
        assert_eq!(reopened.manifest_anchor().unwrap(), anchor);
        drop(reopened);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pmt4_local_genesis_is_value_bearing_and_distinct_from_qvdn_zero_value_profile() {
        let network = [0x76; 32];
        let (genesis, founder, public_goods, miner) = local_monetary_v4_genesis(network).unwrap();
        assert_ne!(founder, public_goods);
        assert_ne!(founder, miner);
        assert_ne!(public_goods, miner);
        assert_eq!(
            genesis.total_value().unwrap(),
            ai_native_l1_pow_bench::state_machine::MONETARY_FOUNDER_ALLOCATION_ATOMS
                + MONETARY_PUBLIC_GOODS_BUDGET_ATOMS
        );
        let zero_value_profile = DevnetProfileCandidate::new(network).unwrap();
        assert!(!zero_value_profile.value_bearing());
        assert_eq!(zero_value_profile.genesis_account_count(), 0);
    }

    #[test]
    fn monetary_v4_import_refuses_pmt3_without_mutation_then_commits_pmt4_idempotently() {
        let root = root();
        let network = [0x78; 32];
        let profile = DevnetProfileCandidate::new(network).unwrap();
        let (genesis, _founder, _public_goods, miner) = local_monetary_v4_genesis(network).unwrap();
        let mut params = profile.consensus().clone();
        params.initial_target = Uint256::MAX;
        params.pow.memory_kib = 8 * 1024;
        params.validate().unwrap();
        let manifest_id = local_monetary_v4_manifest_id(&profile, &params);
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let auth = NodeAuthenticator::RejectAll;
        let clock = SystemClockReferenceTime;
        let mut store = PrivateTestnetV4HybridForkStore::open(
            root.join("pfm4"),
            genesis.clone(),
            params.clone(),
            manifest_id,
            &verifier,
            &clock,
        )
        .unwrap();
        let initial_anchor = store.manifest_anchor().unwrap();
        assert!(monetary_v4_archive_snapshot_is_current(&store, &initial_anchor).unwrap());
        let startup_snapshot =
            build_monetary_v4_archive_range_server(&store, network, &manifest_id, &params, 1)
                .unwrap();
        let startup_snapshot_commitment = startup_snapshot.snapshot_commitment();

        let legacy_chain =
            PrivateTestnetChain::new_monetary(genesis.clone(), params.clone()).unwrap();
        let pmt3 =
            build_next_monetary_candidate(&legacy_chain, &params, &auth, miner, 0, 0).unwrap();
        assert!(matches!(
            import_v4_hybrid_monetary_payload(&pmt3, &mut store, &params, &verifier, &clock),
            Err(ImportFailure::Rejected(_))
        ));
        assert_eq!(store.canonical_height(), 0);
        assert_eq!(store.manifest_anchor().unwrap(), initial_anchor);

        let v4_chain = store.archive().canonical_chain().clone();
        let pmt4 = build_next_v4_hybrid_monetary_candidate(
            &v4_chain,
            &params,
            &manifest_id,
            &verifier,
            miner,
            0,
            0,
        )
        .unwrap();
        let (status, outcome) =
            import_v4_hybrid_monetary_payload(&pmt4, &mut store, &params, &verifier, &clock)
                .unwrap();
        assert_eq!(status, ACK_STATUS_ACCEPTED);
        assert_eq!(outcome.canonical_height, 1);
        assert!(outcome.canonical_changed);
        assert!(!monetary_v4_archive_snapshot_is_current(&store, &initial_anchor).unwrap());
        let refreshed_snapshot =
            build_monetary_v4_archive_range_server(&store, network, &manifest_id, &params, 1)
                .unwrap();
        assert_ne!(
            refreshed_snapshot.snapshot_commitment(),
            startup_snapshot_commitment
        );

        // PMT4's ACK has its own version and binds the accepted result to the
        // exact network/protocol/manifest profile before any future peer dispatch.
        let canonical_for_ack = store.archive().canonical_chain().clone();
        let ack_wire = encode_monetary_ack_v4(
            status,
            1,
            outcome.block_digest,
            &canonical_for_ack,
            network,
            manifest_id,
            params.protocol_version,
        )
        .unwrap();
        assert_eq!(ack_wire.len(), MONETARY_ACK_V4_LEN);
        assert_eq!(&ack_wire[..4], MONETARY_ACK_V4_MAGIC);
        let ack = decode_monetary_ack_v4(&ack_wire).unwrap();
        assert_eq!(ack.status, ACK_STATUS_ACCEPTED);
        assert_eq!(ack.candidate_height, 1);
        assert_eq!(ack.candidate_digest, outcome.block_digest);
        assert_eq!(ack.canonical_height, 1);
        assert_eq!(
            ack.state_root,
            canonical_for_ack.monetary_state().unwrap().state_root()
        );
        assert_eq!(ack.consensus_tip, canonical_for_ack.chain_tip().tip_hash);
        assert!(monetary_ack_v4_matches_profile(
            &ack,
            &network,
            &manifest_id,
            params.protocol_version,
        ));
        assert!(!monetary_ack_v4_matches_profile(
            &ack,
            &[network[0] ^ 1; 32],
            &manifest_id,
            params.protocol_version,
        ));
        assert!(!monetary_ack_v4_matches_profile(
            &ack,
            &network,
            &[manifest_id[0] ^ 1; 32],
            params.protocol_version,
        ));
        assert!(!monetary_ack_v4_matches_profile(
            &ack,
            &network,
            &manifest_id,
            params.protocol_version.wrapping_add(1),
        ));
        let mut v3_ack = ack_wire;
        v3_ack[..4].copy_from_slice(MONETARY_ACK_MAGIC);
        assert!(decode_monetary_ack_v4(&v3_ack).is_err());
        let mut bad_status_ack = ack_wire;
        bad_status_ack[4] = 0xff;
        assert!(decode_monetary_ack_v4(&bad_status_ack).is_err());
        let mut truncated_ack = ack_wire.to_vec();
        truncated_ack.pop();
        assert!(decode_monetary_ack_v4(&truncated_ack).is_err());

        let committed_anchor = store.manifest_anchor().unwrap();

        let (duplicate_status, duplicate) =
            import_v4_hybrid_monetary_payload(&pmt4, &mut store, &params, &verifier, &clock)
                .unwrap();
        assert_eq!(duplicate_status, ACK_STATUS_DUPLICATE);
        assert!(!duplicate.canonical_changed);
        assert_eq!(store.canonical_height(), 1);
        assert_eq!(store.manifest_anchor().unwrap(), committed_anchor);
        let canonical_tip = store.canonical_tip();
        let state_root = store
            .archive()
            .canonical_chain()
            .monetary_state()
            .unwrap()
            .state_root();
        drop(store);

        let reopened = PrivateTestnetV4HybridForkStore::open_anchored(
            root.join("pfm4"),
            genesis,
            params,
            manifest_id,
            &verifier,
            &clock,
            committed_anchor,
        )
        .unwrap();
        assert_eq!(reopened.canonical_height(), 1);
        assert_eq!(reopened.canonical_tip(), canonical_tip);
        assert_eq!(
            reopened
                .archive()
                .canonical_chain()
                .monetary_state()
                .unwrap()
                .state_root(),
            state_root
        );
        assert_eq!(reopened.manifest_anchor().unwrap(), committed_anchor);
        drop(reopened);
        let _ = fs::remove_dir_all(&root);
    }

    fn monetary_candidate_test_parts(
        network: [u8; 32],
    ) -> (
        DevnetProfileCandidate,
        MonetaryLedgerState,
        ConsensusParameters,
        AccountId,
    ) {
        let profile = DevnetProfileCandidate::new(network).unwrap();
        let founder = local_monetary_account_id(&network, b"founder-placeholder");
        let public_goods = local_monetary_account_id(&network, b"public-goods-placeholder");
        let miner = local_monetary_account_id(&network, b"miner-placeholder");
        let genesis = MonetaryLedgerState::genesis(
            network,
            founder,
            vec![(public_goods, MONETARY_PUBLIC_GOODS_BUDGET_ATOMS as u64)],
        )
        .unwrap();
        let mut params = profile.consensus().clone();
        params.initial_target = Uint256::MAX;
        params.pow.memory_kib = 8 * 1024;
        params.validate().unwrap();
        (profile, genesis, params, miner)
    }

    #[test]
    fn monetary_import_is_fail_closed_duplicate_safe_and_uses_mta3_ack() {
        let root = root();
        let network = [0x74; 32];
        let (_profile, genesis, params, miner) = monetary_candidate_test_parts(network);
        let auth = NodeAuthenticator::RejectAll;
        let clock = SystemClockReferenceTime;
        let mut store = PrivateTestnetMonetaryForkStore::open(
            root.join("monetary"),
            genesis.clone(),
            params.clone(),
            &auth,
            &clock,
        )
        .unwrap();
        let genesis_anchor = store.manifest_anchor().unwrap();

        // A legacy envelope cannot enter the monetary path or advance the PFM3 commit record.
        assert!(matches!(
            import_monetary_payload(b"PTB2\0\0\0", &mut store, &params, &auth, &clock),
            Err(ImportFailure::Rejected(_))
        ));
        assert_eq!(store.canonical_height(), 0);
        assert_eq!(store.manifest_anchor().unwrap(), genesis_anchor);

        let chain = store.archive().canonical_chain().clone();
        let payload = build_next_monetary_candidate(&chain, &params, &auth, miner, 0, 0).unwrap();
        let (status, outcome) =
            import_monetary_payload(&payload, &mut store, &params, &auth, &clock).unwrap();
        assert_eq!(status, ACK_STATUS_ACCEPTED);
        assert_eq!(outcome.canonical_height, 1);
        assert!(outcome.canonical_changed);

        let canonical = store.archive().canonical_chain().clone();
        let ack_wire = encode_monetary_ack_v3(status, 1, outcome.block_digest, &canonical).unwrap();
        assert_eq!(&ack_wire[..4], MONETARY_ACK_MAGIC);
        let ack = decode_monetary_ack_v3(&ack_wire).unwrap();
        assert_eq!(ack.status, ACK_STATUS_ACCEPTED);
        assert_eq!(ack.candidate_height, 1);
        assert_eq!(ack.candidate_digest, outcome.block_digest);
        assert_eq!(ack.canonical_height, 1);
        assert_eq!(
            ack.state_root,
            canonical.monetary_state().unwrap().state_root()
        );
        assert_eq!(ack.consensus_tip, canonical.chain_tip().tip_hash);

        // Re-import is typed as duplicate and cannot move canonical state or manifest commitment.
        let committed_anchor = store.manifest_anchor().unwrap();
        let (duplicate_status, duplicate) =
            import_monetary_payload(&payload, &mut store, &params, &auth, &clock).unwrap();
        assert_eq!(duplicate_status, ACK_STATUS_DUPLICATE);
        assert!(!duplicate.canonical_changed);
        assert_eq!(store.canonical_height(), 1);
        assert_eq!(store.manifest_anchor().unwrap(), committed_anchor);

        let mut legacy_ack = ack_wire;
        legacy_ack[..4].copy_from_slice(ACK_MAGIC);
        assert!(decode_monetary_ack_v3(&legacy_ack).is_err());
        let mut unknown_status_ack = ack_wire;
        unknown_status_ack[4] = 0xff;
        assert!(decode_monetary_ack_v3(&unknown_status_ack).is_err());

        let legacy_chain =
            PrivateTestnetChain::new(LedgerState::genesis(network, Vec::new()).unwrap(), params)
                .unwrap();
        assert!(encode_monetary_ack_v3(ACK_STATUS_ACCEPTED, 1, [9; 32], &legacy_chain).is_err());

        drop(store);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn monetary_import_unknown_parent_is_retryable_without_manifest_mutation() {
        let root = root();
        let network = [0x75; 32];
        let (_profile, genesis, params, miner) = monetary_candidate_test_parts(network);
        let auth = NodeAuthenticator::RejectAll;
        let clock = SystemClockReferenceTime;
        let mut source = PrivateTestnetMonetaryForkStore::open(
            root.join("source"),
            genesis.clone(),
            params.clone(),
            &auth,
            &clock,
        )
        .unwrap();
        let mut receiver = PrivateTestnetMonetaryForkStore::open(
            root.join("receiver"),
            genesis,
            params.clone(),
            &auth,
            &clock,
        )
        .unwrap();

        let first_chain = source.archive().canonical_chain().clone();
        let first =
            build_next_monetary_candidate(&first_chain, &params, &auth, miner, 0, 0).unwrap();
        source.submit(&first, &auth, &clock).unwrap();
        let second_chain = source.archive().canonical_chain().clone();
        let second =
            build_next_monetary_candidate(&second_chain, &params, &auth, miner, 0, 0).unwrap();

        let receiver_anchor = receiver.manifest_anchor().unwrap();
        assert!(matches!(
            import_monetary_payload(&second, &mut receiver, &params, &auth, &clock),
            Err(ImportFailure::UnknownParent)
        ));
        assert_eq!(receiver.canonical_height(), 0);
        assert_eq!(receiver.manifest_anchor().unwrap(), receiver_anchor);

        drop(receiver);
        drop(source);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn runtime_resolves_signed_identity_and_persists_generation_floor() {
        let root = root();
        let network = [0x42; 32];
        let issuer = issuer_key();
        let authority = deployment_authority_key();
        let config = runtime_config(&root, network, &authority);
        fs::write(
            root.join("peer.npi"),
            signed_identity(network, 99, 17, &record([0x31; 32]), &issuer),
        )
        .unwrap();

        // Both signed bootstrap layers fail closed on a tampered signature before peer admission.
        let deployment_path = root.join("deployment.dpc1");
        let mut bad_deployment = fs::read(&deployment_path).unwrap();
        *bad_deployment.last_mut().unwrap() ^= 1;
        fs::write(&deployment_path, &bad_deployment).unwrap();
        let err = resolve_trusted_peer_keys(&config, NodeRuntimeProfile::ZeroValueDevnet)
            .expect_err("tampered deployment config must be rejected");
        assert!(
            err.contains("InvalidSignature"),
            "unexpected DPC1 result: {err}"
        );

        write_trust_bootstrap(&root, network, &authority, &issuer, 1, 1);
        let registry_path = root.join("issuer-registry.irg1");
        let mut bad_registry = fs::read(&registry_path).unwrap();
        *bad_registry.last_mut().unwrap() ^= 1;
        fs::write(&registry_path, &bad_registry).unwrap();
        let err = resolve_trusted_peer_keys(&config, NodeRuntimeProfile::ZeroValueDevnet)
            .expect_err("tampered issuer registry must be rejected");
        assert!(
            err.contains("InvalidSignature"),
            "unexpected IRG1 result: {err}"
        );

        write_trust_bootstrap(&root, network, &authority, &issuer, 1, 1);
        let first = resolve_trusted_peer_keys(&config, NodeRuntimeProfile::ZeroValueDevnet)
            .expect("valid signed identity should be admitted");
        assert_eq!(first, vec![[0x31; 32]]);
        let restart = resolve_trusted_peer_keys(&config, NodeRuntimeProfile::ZeroValueDevnet)
            .expect("the same identity should be idempotent after restart");
        assert_eq!(restart, first);

        // Re-signing a different Noise key under the same identity generation must fail closed.
        fs::write(
            root.join("peer.npi"),
            signed_identity(network, 99, 17, &record([0x32; 32]), &issuer),
        )
        .unwrap();
        let err = resolve_trusted_peer_keys(&config, NodeRuntimeProfile::ZeroValueDevnet)
            .expect_err("same-generation identity mutation must be rejected");
        assert!(
            err.contains("SameGenerationMutation"),
            "unexpected error: {err}"
        );

        // A signed same-generation revocation must be persisted before admission is denied.
        fs::write(
            root.join("peer.npi"),
            signed_identity(
                network,
                99,
                17,
                &record_with_state([0x31; 32], KeyState::Revoked),
                &issuer,
            ),
        )
        .unwrap();
        let err = resolve_trusted_peer_keys(&config, NodeRuntimeProfile::ZeroValueDevnet)
            .expect_err("signed revocation must be persisted and block admission");
        assert!(
            err.contains("not active"),
            "unexpected revocation result: {err}"
        );

        // After restart/revalidation, a previously revoked generation cannot be reactivated.
        fs::write(
            root.join("peer.npi"),
            signed_identity(network, 99, 17, &record([0x31; 32]), &issuer),
        )
        .unwrap();
        let err = resolve_trusted_peer_keys(&config, NodeRuntimeProfile::ZeroValueDevnet)
            .expect_err("revoked generation must remain terminal");
        assert!(
            err.contains("RevokedTerminal"),
            "revocation rollback unexpectedly accepted: {err}"
        );

        // The signed issuer registry is persisted before an issuer revocation is returned.
        // A rollback to the previously active registry must then fail after restart/revalidation.
        let governance = governance_key();
        fs::write(
            root.join("issuer-registry.irg1"),
            encode_issuer_registry(network, 2, 17, 3, &issuer, &governance),
        )
        .unwrap();
        let err = resolve_trusted_peer_keys(&config, NodeRuntimeProfile::ZeroValueDevnet)
            .expect_err("signed issuer revocation must be persisted and deny peers");
        assert!(
            err.contains("IssuerInactive"),
            "unexpected issuer revocation result: {err}"
        );
        fs::write(
            root.join("issuer-registry.irg1"),
            encode_issuer_registry(network, 1, 17, 1, &issuer, &governance),
        )
        .unwrap();
        let err = resolve_trusted_peer_keys(&config, NodeRuntimeProfile::ZeroValueDevnet)
            .expect_err("issuer registry rollback must remain rejected");
        assert!(
            err.contains("SequenceRollback"),
            "issuer registry rollback unexpectedly accepted: {err}"
        );

        // Even an expired but correctly signed revocation must be persisted before denial.
        let expired_root = root.join("expired_case");
        fs::create_dir_all(&expired_root).unwrap();
        let expired_config = runtime_config(&expired_root, network, &authority);
        let expired_active = record_with_state_and_window([0x41; 32], KeyState::Active, 0, 900);
        fs::write(
            expired_root.join("peer.npi"),
            signed_identity(network, 100, 17, &expired_active, &issuer),
        )
        .unwrap();
        let err = resolve_trusted_peer_keys(&expired_config, NodeRuntimeProfile::ZeroValueDevnet)
            .expect_err("expired active identity must not be admitted");
        assert!(
            err.contains("validity window"),
            "unexpected expiry result: {err}"
        );

        let expired_revocation =
            record_with_state_and_window([0x41; 32], KeyState::Revoked, 0, 900);
        fs::write(
            expired_root.join("peer.npi"),
            signed_identity(network, 100, 17, &expired_revocation, &issuer),
        )
        .unwrap();
        let err = resolve_trusted_peer_keys(&expired_config, NodeRuntimeProfile::ZeroValueDevnet)
            .expect_err("expired signed revocation must persist before admission is denied");
        assert!(
            err.contains("not active"),
            "unexpected expired revocation result: {err}"
        );

        fs::write(
            expired_root.join("peer.npi"),
            signed_identity(network, 100, 17, &expired_active, &issuer),
        )
        .unwrap();
        let err = resolve_trusted_peer_keys(&expired_config, NodeRuntimeProfile::ZeroValueDevnet)
            .expect_err("expired revocation must remain terminal after reactivation attempt");
        assert!(
            err.contains("RevokedTerminal"),
            "expired revocation rollback unexpectedly accepted: {err}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn signed_trust_reloader_applies_nrt1_rotation_to_new_connections_without_restart() {
        let root = root();
        let network = [0x62; 32];
        let issuer = issuer_key();
        let authority = deployment_authority_key();
        let config = runtime_config(&root, network, &authority);
        let old = record([0x31; 32]);
        fs::write(
            root.join("peer.npi"),
            ai_native_l1_pow_bench::devnet_signed_peer_identity_candidate::sign_signed_peer_identity(
                network, 99, 17, &old, None, &issuer,
            )
            .unwrap(),
        )
        .unwrap();

        let reloader =
            SignedPeerTrustReloader::from_config(&config, NodeRuntimeProfile::ZeroValueDevnet)
                .unwrap()
                .expect("signed identity mode must create a reloader");
        assert_eq!(reloader.resolve().unwrap(), vec![[0x31; 32]]);

        let mut next = old.clone();
        next.generation = 2;
        next.public_key = vec![0x33; 32];
        let old_record_bytes = encode(&old).unwrap();
        let next_record_bytes = encode(&next).unwrap();
        let rotation =
            ai_native_l1_pow_bench::identity_generation_store::encode_signed_rotation_statement(
                network,
                99,
                17,
                &old_record_bytes,
                &next_record_bytes,
                &issuer,
            )
            .unwrap();
        let next_identity =
            ai_native_l1_pow_bench::devnet_signed_peer_identity_candidate::sign_signed_peer_identity(
                network,
                99,
                17,
                &next,
                Some(&rotation),
                &issuer,
            )
            .unwrap();
        fs::write(root.join("peer.npi"), next_identity).unwrap();

        assert_eq!(
            reloader.resolve().unwrap(),
            vec![[0x33; 32]],
            "the same node trust reloader must recognize a valid NRT1 successor"
        );
        let inbound = NoiseInboundConfig {
            network_id: network,
            local_static_private_key: Arc::new(NoisePrivateKey([0x55; 32])),
            trusted_peer_public_keys: vec![[0x31; 32]],
            signed_peer_trust_reloader: Some(reloader.clone()),
        };
        assert_eq!(
            inbound.current_trusted_peer_public_keys().unwrap(),
            vec![[0x33; 32]]
        );

        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let outbound = NoiseOutboundConfig {
            network_id: network,
            local_static_private_key: Arc::new(NoisePrivateKey([0x56; 32])),
            peer_pins: vec![(peer, [0x31; 32])],
            signed_peer_trust_reloader: Some(reloader.clone()),
        };
        assert_eq!(outbound.trusted_pin(peer).unwrap(), [0x33; 32]);

        // Restoring generation 1 must fail in this still-live reloader after generation 2 was
        // accepted, because the same durable identity high-water state is reused.
        fs::write(
            root.join("peer.npi"),
            ai_native_l1_pow_bench::devnet_signed_peer_identity_candidate::sign_signed_peer_identity(
                network, 99, 17, &old, None, &issuer,
            )
            .unwrap(),
        )
        .unwrap();
        let err = reloader
            .resolve()
            .expect_err("generation rollback must fail without restarting the node");
        assert!(
            err.contains("GenerationRollback"),
            "unexpected rollback result: {err}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn signed_trust_reloader_applies_issuer_revocation_and_rejects_registry_rollback_live() {
        let root = root();
        let network = [0x63; 32];
        let issuer = issuer_key();
        let authority = deployment_authority_key();
        let config = runtime_config(&root, network, &authority);
        fs::write(
            root.join("peer.npi"),
            signed_identity(network, 99, 17, &record([0x31; 32]), &issuer),
        )
        .unwrap();

        let reloader =
            SignedPeerTrustReloader::from_config(&config, NodeRuntimeProfile::ZeroValueDevnet)
                .unwrap()
                .expect("signed identity mode must create a reloader");
        assert_eq!(reloader.resolve().unwrap(), vec![[0x31; 32]]);

        let governance = governance_key();
        fs::write(
            root.join("issuer-registry.irg1"),
            encode_issuer_registry(network, 2, 17, 3, &issuer, &governance),
        )
        .unwrap();
        let err = reloader
            .resolve()
            .expect_err("new sessions must fail closed after issuer revocation");
        assert!(
            err.contains("IssuerInactive"),
            "unexpected revocation result: {err}"
        );

        fs::write(
            root.join("issuer-registry.irg1"),
            encode_issuer_registry(network, 1, 17, 1, &issuer, &governance),
        )
        .unwrap();
        let err = reloader
            .resolve()
            .expect_err("old active registry must not be restored in the running process");
        assert!(
            err.contains("SequenceRollback"),
            "unexpected rollback result: {err}"
        );
        let _ = fs::remove_dir_all(&root);
    }
}

#[cfg(test)]
mod monetary_ancestor_replay_tests {
    use super::*;
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn fixture() -> (
        PathBuf,
        PrivateTestnetMonetaryForkStore,
        ConsensusParameters,
        Vec<u8>,
    ) {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "ain1-monetary-ancestor-test-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();

        let network = [0xD9; 32];
        let profile = DevnetProfileCandidate::new(network).unwrap();
        let genesis = monetary_candidate_genesis(network).unwrap();
        let miner = local_monetary_account_id(&network, b"miner-placeholder");
        let mut params = profile.consensus().clone();
        params.initial_target = Uint256::MAX;
        params.pow.memory_kib = 8 * 1024;
        params.validate().unwrap();

        let authenticator = NodeAuthenticator::RejectAll;
        let clock = SystemClockReferenceTime;
        let mut store = PrivateTestnetMonetaryForkStore::open(
            &root.join("pfm3"),
            genesis,
            params.clone(),
            &authenticator,
            &clock,
        )
        .unwrap();

        for _ in 0..2 {
            let chain = store.archive().canonical_chain().clone();
            let payload =
                build_next_monetary_candidate(&chain, &params, &authenticator, miner, 0, 0)
                    .unwrap();
            let (status, _) =
                import_monetary_payload(&payload, &mut store, &params, &authenticator, &clock)
                    .unwrap();
            assert_eq!(status, ACK_STATUS_ACCEPTED);
        }

        let chain = store.archive().canonical_chain().clone();
        let child =
            build_next_monetary_candidate(&chain, &params, &authenticator, miner, 0, 0).unwrap();
        (root, store, params, child)
    }

    #[test]
    fn borrowed_archive_repair_returns_parents_in_ascending_height_order() {
        let (root, store, params, child) = fixture();
        let path = monetary_ancestor_path_before_candidate(&store, &child, &params).unwrap();
        let heights: Vec<u64> = path
            .iter()
            .map(|payload| {
                decode_candidate_monetary_network_block(payload)
                    .unwrap()
                    .header
                    .height
            })
            .collect();
        assert_eq!(heights, vec![1, 2]);
        drop(store);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn ancestor_repair_rejects_branch_and_byte_budget_overruns() {
        let (root, store, params, child) = fixture();
        let archive = store.archive().archive_envelopes_iter();

        let branch_error = monetary_ancestor_path_from_archive(
            archive,
            &child,
            &params,
            1,
            MAX_ARCHIVE_SYNC_BYTES,
        )
        .expect_err("two required parents must exceed a one-branch budget");
        assert!(branch_error.contains("bounded repair budget"));

        let archive = store.archive().archive_envelopes_iter();
        let byte_error = monetary_ancestor_path_from_archive(archive, &child, &params, 512, 1)
            .expect_err("a real PMT3 parent must exceed a one-byte budget");
        assert!(byte_error.contains("bounded repair budget"));

        drop(store);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn ancestor_repair_rejects_missing_parent_instead_of_returning_partial_path() {
        let (root, store, params, child) = fixture();
        let without_height_one: Vec<Vec<u8>> = store
            .archive()
            .archive_envelopes()
            .into_iter()
            .filter(|payload| {
                decode_candidate_monetary_network_block(payload)
                    .unwrap()
                    .header
                    .height
                    != 1
            })
            .collect();
        let error = monetary_ancestor_path_from_archive(
            without_height_one.iter().map(Vec::as_slice),
            &child,
            &params,
            MAX_ARCHIVE_SYNC_BRANCHES,
            MAX_ARCHIVE_SYNC_BYTES,
        )
        .expect_err("repair must fail closed when a required parent is absent");
        assert!(error.contains("missing required ancestor at height 1"));

        drop(store);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn monetary_import_restart_is_idempotent_and_invalidates_stale_snapshot_anchor() {
        let (root, mut store, params, child) = fixture();
        let network = [0xD9; 32];
        let auth = NodeAuthenticator::RejectAll;
        let clock = SystemClockReferenceTime;
        let snapshot_anchor = store.manifest_anchor().unwrap();
        assert!(
            monetary_archive_snapshot_is_current(&store, &snapshot_anchor).unwrap(),
            "the startup snapshot anchor is current before new archive data is imported"
        );

        // Model the crash window after the durable PFM3 import but before the ARW page commit:
        // no range-WAL commit is made here, and the node store is reopened from disk.
        let (status, outcome) =
            import_monetary_payload(&child, &mut store, &params, &auth, &clock).unwrap();
        assert_eq!(status, ACK_STATUS_ACCEPTED);
        assert!(outcome.canonical_changed);
        let durable_import_anchor = store.manifest_anchor().unwrap();
        assert_ne!(snapshot_anchor, durable_import_anchor);
        assert!(
            !monetary_archive_snapshot_is_current(&store, &snapshot_anchor).unwrap(),
            "the old range snapshot must become stale when PFM3 changes"
        );
        drop(store);

        let mut reopened = PrivateTestnetMonetaryForkStore::open(
            &root.join("pfm3"),
            monetary_candidate_genesis(network).unwrap(),
            params.clone(),
            &auth,
            &clock,
        )
        .unwrap();
        assert_eq!(reopened.canonical_height(), 3);
        assert_eq!(reopened.manifest_anchor().unwrap(), durable_import_anchor);
        assert!(
            !monetary_archive_snapshot_is_current(&reopened, &snapshot_anchor).unwrap(),
            "restarting must not make the pre-import snapshot current again"
        );

        // A restart can safely retry that PMT3 item even though its ARW receipt was not committed.
        let (duplicate_status, duplicate_outcome) =
            import_monetary_payload(&child, &mut reopened, &params, &auth, &clock).unwrap();
        assert_eq!(duplicate_status, ACK_STATUS_DUPLICATE);
        assert!(!duplicate_outcome.canonical_changed);
        assert_eq!(reopened.manifest_anchor().unwrap(), durable_import_anchor);

        drop(reopened);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn monetary_reorg_invalidates_startup_archive_snapshot_anchor() {
        let (root, mut store, params, _child) = fixture();
        let network = [0xD9; 32];
        let auth = NodeAuthenticator::RejectAll;
        let clock = SystemClockReferenceTime;
        let snapshot_anchor = store.manifest_anchor().unwrap();
        let original_tip = store.canonical_tip();

        let genesis = monetary_candidate_genesis(network).unwrap();
        let genesis_chain = PrivateTestnetChain::new_monetary(genesis, params.clone()).unwrap();
        let fork_miner = local_monetary_account_id(&network, b"snapshot-reorg-miner");
        let fork_one =
            build_next_monetary_candidate(&genesis_chain, &params, &auth, fork_miner, 0, 0)
                .unwrap();
        let (status_one, outcome_one) =
            import_monetary_payload(&fork_one, &mut store, &params, &auth, &clock).unwrap();
        assert_eq!(status_one, ACK_STATUS_ACCEPTED);

        let fork_one_chain = store
            .archive()
            .branch_chain(&outcome_one.block_digest)
            .unwrap()
            .clone();
        let fork_two =
            build_next_monetary_candidate(&fork_one_chain, &params, &auth, fork_miner, 0, 0)
                .unwrap();
        let (status_two, outcome_two) =
            import_monetary_payload(&fork_two, &mut store, &params, &auth, &clock).unwrap();
        assert_eq!(status_two, ACK_STATUS_ACCEPTED);

        let fork_two_chain = store
            .archive()
            .branch_chain(&outcome_two.block_digest)
            .unwrap()
            .clone();
        let fork_three =
            build_next_monetary_candidate(&fork_two_chain, &params, &auth, fork_miner, 0, 0)
                .unwrap();
        let (status_three, outcome_three) =
            import_monetary_payload(&fork_three, &mut store, &params, &auth, &clock).unwrap();
        assert_eq!(status_three, ACK_STATUS_ACCEPTED);
        assert!(
            outcome_three.canonical_changed,
            "longer fork must cause a reorg"
        );
        assert_eq!(store.canonical_height(), 3);
        assert_ne!(store.canonical_tip(), original_tip);
        assert_ne!(store.manifest_anchor().unwrap(), snapshot_anchor);
        assert!(
            !monetary_archive_snapshot_is_current(&store, &snapshot_anchor).unwrap(),
            "a reorg must prevent the stale startup server from serving archive pages"
        );

        drop(store);
        let _ = fs::remove_dir_all(root);
    }

    fn served_entry(encoded: Vec<u8>, height: u64, digest: [u8; 32]) -> ArchiveSyncServedEntry {
        ArchiveSyncServedEntry {
            metadata: ArchiveEntryMeta {
                height,
                digest,
                encoded_len: encoded.len() as u64,
                payload_sha256: Sha256::digest(&encoded).into(),
            },
            encoded,
        }
    }

    #[test]
    fn monetary_archive_page_preflights_metadata_and_legacy_bytes_before_mutation() {
        let (root, mut store, params, child) = fixture();
        let auth = NodeAuthenticator::RejectAll;
        let clock = SystemClockReferenceTime;
        let candidate = decode_candidate_monetary_network_block(&child).unwrap();
        let child_digest = pow_digest(&candidate.header, params.pow).unwrap();
        let original_anchor = store.manifest_anchor().unwrap();

        // A valid encoded child with forged page height metadata must fail before PFM3 mutation.
        let (response_tx, _response_rx) = mpsc::sync_channel(1);
        let forged = MonetaryArchiveRangeImportBatch {
            peer: "127.0.0.1:49302".parse().unwrap(),
            entries: vec![served_entry(child.clone(), 4, child_digest)],
            response: response_tx,
        };
        let error =
            apply_monetary_archive_range_import_batch(&forged, &mut store, &params, &auth, &clock)
                .expect_err("forged PMT3 page height metadata must be rejected");
        assert!(error.contains("metadata mismatch"));
        assert_eq!(store.canonical_height(), 2);
        assert_eq!(store.manifest_anchor().unwrap(), original_anchor);

        // Even if the first item is valid, the entire page is preflighted before import, so a
        // trailing legacy PTB2 item prevents the valid child from being committed.
        let (response_tx, _response_rx) = mpsc::sync_channel(1);
        let mixed = MonetaryArchiveRangeImportBatch {
            peer: "127.0.0.1:49302".parse().unwrap(),
            entries: vec![
                served_entry(child, 3, child_digest),
                served_entry(b"PTB2\0\0\0".to_vec(), 4, [0xEE; 32]),
            ],
            response: response_tx,
        };
        let error =
            apply_monetary_archive_range_import_batch(&mixed, &mut store, &params, &auth, &clock)
                .expect_err("a legacy envelope must fail the whole page preflight");
        assert!(error.contains("decode PMT3 archive entry"));
        assert_eq!(store.canonical_height(), 2);
        assert_eq!(store.manifest_anchor().unwrap(), original_anchor);

        drop(store);
        let _ = fs::remove_dir_all(root);
    }
}
