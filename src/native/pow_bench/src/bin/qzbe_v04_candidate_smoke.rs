//! CP-0408: offline-only QZB4 v2 + QZBE persistent-store smoke runner.
//!
//! This executable deliberately opens no P2P, RPC, wallet or market listener. It requires an
//! explicit Genesis scope and explicit schedule parameters on every invocation. It is a local
//! candidate/replay tool, not the canonical node, an approved monetary profile, or a Mainnet mode.

use ai_native_l1_pow_bench::{
    consensus::{ConsensusParameters, Uint256},
    monetary_genesis_v04_candidate::GenesisManifestV04,
    monetary_issuance_v04_candidate::V04MiningIssuanceScheduleCandidate,
    monetary_pow_v04_candidate::{
        MAX_QZBE_MINING_ATTEMPTS, MAX_V04_EXECUTION_FORK_ARCHIVE_BLOCKS,
        MAX_V04_EXECUTION_FORK_ARCHIVE_HEIGHT,
    },
    monetary_pow_v04_store_candidate::V04ExecutionForkStoreCandidate,
    monetary_transition_v04_candidate::{
        MonetaryLedgerStateV04TransitionCandidate, V04ConsensusProfileCandidate,
    },
    state_machine::{AccountId, TransactionAuthenticator},
};
use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
    process,
};

#[derive(Debug, Clone)]
struct Args {
    data_dir: PathBuf,
    network_id: [u8; 32],
    owner_id: [u8; 32],
    miner_id: [u8; 32],
    initial_subsidy_atoms: u128,
    blocks_per_halving: u64,
    blocks_to_build: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SmokeResult {
    network_id: [u8; 32],
    genesis_manifest_hash: [u8; 32],
    profile_fingerprint: [u8; 32],
    start_height: u64,
    end_height: u64,
    start_tip: [u8; 32],
    end_tip: [u8; 32],
    end_state_root: [u8; 32],
    manifest_generation: u64,
    archive_len: usize,
}

struct RejectAllTransactions;

impl TransactionAuthenticator for RejectAllTransactions {
    fn verify(
        &self,
        _account: &AccountId,
        _digest: &[u8; 32],
        _signature: &[u8],
    ) -> Result<(), ()> {
        Err(())
    }
}

fn usage() -> &'static str {
    "Usage: qzbe_v04_candidate_smoke --data-dir ABSOLUTE_PATH --network-id HEX64 --owner-id HEX64 --miner-id HEX64 --initial-subsidy-atoms U128 --blocks-per-halving U64 --blocks U64\n\
     Offline-only QZB4 v2/QZBE store smoke. Schedule, network, Genesis owner and miner are explicit; no network listener is started."
}

fn parse_hex32(value: &str, option: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.is_ascii() {
        return Err(format!(
            "{option} must be exactly 64 hexadecimal characters"
        ));
    }
    let mut result = [0u8; 32];
    for (index, byte) in result.iter_mut().enumerate() {
        let start = index * 2;
        *byte = u8::from_str_radix(&value[start..start + 2], 16)
            .map_err(|_| format!("{option} contains non-hexadecimal characters"))?;
    }
    Ok(result)
}

fn parse_arguments(tokens: &[String]) -> Result<Option<Args>, String> {
    if tokens
        .iter()
        .any(|token| token == "--help" || token == "-h")
    {
        return Ok(None);
    }
    if tokens.is_empty() {
        return Err(usage().to_string());
    }

    let mut options = BTreeMap::<String, String>::new();
    let mut cursor = 0usize;
    while cursor < tokens.len() {
        let key = &tokens[cursor];
        if !key.starts_with("--") {
            return Err(format!(
                "unexpected positional argument: {key}\n{}",
                usage()
            ));
        }
        let value = tokens
            .get(cursor + 1)
            .ok_or_else(|| format!("missing value for {key}\n{}", usage()))?;
        if value.starts_with("--") {
            return Err(format!("missing value for {key}\n{}", usage()));
        }
        if options.insert(key.clone(), value.clone()).is_some() {
            return Err(format!("duplicate option: {key}"));
        }
        cursor += 2;
    }

    let allowed = [
        "--data-dir",
        "--network-id",
        "--owner-id",
        "--miner-id",
        "--initial-subsidy-atoms",
        "--blocks-per-halving",
        "--blocks",
    ];
    for key in options.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(format!("unknown option: {key}\n{}", usage()));
        }
    }
    let take = |key: &str| {
        options
            .get(key)
            .cloned()
            .ok_or_else(|| format!("required option is missing: {key}\n{}", usage()))
    };

    let data_dir = PathBuf::from(take("--data-dir")?);
    if !data_dir.is_absolute() {
        return Err(
            "--data-dir must be an absolute path to a dedicated QZBE candidate store".into(),
        );
    }
    let initial_subsidy_atoms = take("--initial-subsidy-atoms")?
        .parse::<u128>()
        .map_err(|_| "--initial-subsidy-atoms must be an unsigned integer (u128)".to_string())?;
    let blocks_per_halving = take("--blocks-per-halving")?
        .parse::<u64>()
        .map_err(|_| "--blocks-per-halving must be an unsigned integer (u64)".to_string())?;
    let blocks_to_build = take("--blocks")?
        .parse::<u64>()
        .map_err(|_| "--blocks must be an unsigned integer (u64)".to_string())?;
    if initial_subsidy_atoms == 0 || blocks_per_halving == 0 || blocks_to_build == 0 {
        return Err(
            "subsidy, halving interval and block count must all be greater than zero".into(),
        );
    }
    if blocks_to_build > MAX_V04_EXECUTION_FORK_ARCHIVE_HEIGHT {
        return Err(format!(
            "--blocks exceeds the local candidate height ceiling of {}",
            MAX_V04_EXECUTION_FORK_ARCHIVE_HEIGHT
        ));
    }

    let network_id = parse_hex32(&take("--network-id")?, "--network-id")?;
    let owner_id = parse_hex32(&take("--owner-id")?, "--owner-id")?;
    let miner_id = parse_hex32(&take("--miner-id")?, "--miner-id")?;
    if network_id.iter().all(|byte| *byte == 0)
        || owner_id.iter().all(|byte| *byte == 0)
        || miner_id.iter().all(|byte| *byte == 0)
    {
        return Err("network, owner and miner identifiers must be nonzero".into());
    }

    Ok(Some(Args {
        data_dir,
        network_id,
        owner_id,
        miner_id,
        initial_subsidy_atoms,
        blocks_per_halving,
        blocks_to_build,
    }))
}

/// Only the private QZBE candidate store's own top-level entries are accepted. This avoids
/// accidentally co-locating the experimental format with a legacy node data directory.
fn require_dedicated_store_directory(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path)
        .map_err(|error| format!("create candidate store directory: {error}"))?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect candidate store directory: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("--data-dir must be a real directory, not a symlink or file".into());
    }
    for entry in
        fs::read_dir(path).map_err(|error| format!("list candidate store directory: {error}"))?
    {
        let entry = entry.map_err(|error| format!("read candidate store entry: {error}"))?;
        let name = entry.file_name().to_string_lossy().to_string();
        let file_type = entry
            .file_type()
            .map_err(|error| format!("inspect {name}: {error}"))?;
        match name.as_str() {
            "branches" | "manifests" => {
                if file_type.is_symlink() || !file_type.is_dir() {
                    return Err(format!(
                        "candidate store path {name} must be a real directory"
                    ));
                }
            }
            "qzbe-store.lock" => {
                if file_type.is_symlink() || !file_type.is_file() {
                    return Err(
                        "candidate store lock path must be a regular non-symlink file".into(),
                    );
                }
            }
            _ => {
                return Err(format!(
                    "refusing non-candidate data in --data-dir ({name}); choose a dedicated directory"
                ));
            }
        }
    }
    Ok(())
}

fn prepare_consensus_parameters() -> Result<ConsensusParameters, String> {
    let mut params = ConsensusParameters::candidate_testnet()
        .map_err(|error| format!("candidate PoW parameter construction failed: {error:?}"))?;
    // Deliberately easy but NON-MAX local proof-of-work: the smoke must exercise the body-bound
    // mining loop rather than passing every nonce trivially. This is not a production difficulty
    // profile; the exact parameters are fingerprinted in each envelope/manifest.
    params.initial_target = Uint256::from_be_bytes([0xEF; 32]);
    params.pow_limit = Uint256::MAX;
    // Match the deliberately small local research profile used by existing offline smoke paths.
    params.pow.memory_kib = 8 * 1024;
    params
        .validate()
        .map_err(|error| format!("local candidate PoW parameters rejected: {error:?}"))?;
    Ok(params)
}

fn run_smoke(args: &Args) -> Result<SmokeResult, String> {
    require_dedicated_store_directory(&args.data_dir)?;
    let manifest = GenesisManifestV04::new(args.network_id, args.owner_id)
        .map_err(|error| format!("candidate Genesis manifest rejected: {error:?}"))?;
    let genesis_manifest_hash = manifest
        .manifest_hash()
        .map_err(|error| format!("candidate Genesis hash failed: {error:?}"))?;
    let schedule = V04MiningIssuanceScheduleCandidate::new(
        args.initial_subsidy_atoms,
        args.blocks_per_halving,
    )
    .map_err(|error| format!("explicit candidate schedule rejected: {error:?}"))?;
    let profile = V04ConsensusProfileCandidate::from_manifest_and_schedule(&manifest, schedule)
        .map_err(|error| format!("candidate profile construction failed: {error:?}"))?;
    let profile_fingerprint = *profile.profile_fingerprint();
    let genesis =
        MonetaryLedgerStateV04TransitionCandidate::from_genesis_manifest(&manifest, &profile)
            .map_err(|error| format!("candidate ledger Genesis construction failed: {error:?}"))?;
    let params = prepare_consensus_parameters()?;

    let store = V04ExecutionForkStoreCandidate::open(
        &args.data_dir,
        genesis.clone(),
        params.clone(),
        &RejectAllTransactions,
    )
    .map_err(|error| format!("open local QZBE candidate store: {error}"))?;
    let start_height = store.canonical_height();
    let start_tip = store.canonical_tip();
    let end_height = start_height
        .checked_add(args.blocks_to_build)
        .ok_or_else(|| "requested local height overflows u64".to_string())?;
    if end_height > MAX_V04_EXECUTION_FORK_ARCHIVE_HEIGHT {
        return Err(format!(
            "requested local height {end_height} exceeds candidate ceiling {}",
            MAX_V04_EXECUTION_FORK_ARCHIVE_HEIGHT
        ));
    }
    let after_len = store
        .archive_len()
        .checked_add(args.blocks_to_build as usize)
        .ok_or_else(|| "local archive count overflows usize".to_string())?;
    if after_len > MAX_V04_EXECUTION_FORK_ARCHIVE_BLOCKS {
        return Err(format!(
            "requested archive length {after_len} exceeds candidate limit {}",
            MAX_V04_EXECUTION_FORK_ARCHIVE_BLOCKS
        ));
    }
    drop(store);

    let mut store = V04ExecutionForkStoreCandidate::open(
        &args.data_dir,
        genesis.clone(),
        params.clone(),
        &RejectAllTransactions,
    )
    .map_err(|error| format!("reopen local QZBE candidate store: {error}"))?;
    let current_tip = store.canonical_tip();
    let current_height = store.canonical_height();
    if current_tip != start_tip || current_height != start_height {
        return Err("reopen changed the previously committed QZBE canonical state".into());
    }
    for _ in 0..args.blocks_to_build {
        let next_height = store
            .canonical_height()
            .checked_add(1)
            .ok_or_else(|| "next candidate height overflows u64".to_string())?;
        let parent_tip = store.canonical_tip();
        let encoded = store
            .fork_choice()
            .mine_candidate_on(
                parent_tip,
                next_height,
                args.miner_id,
                Vec::new(),
                next_height,
                MAX_QZBE_MINING_ATTEMPTS,
                &RejectAllTransactions,
                || false,
            )
            .map_err(|error| format!("mine bounded body-bound QZBE candidate block: {error}"))?;
        let result = store
            .submit(&encoded, &RejectAllTransactions)
            .map_err(|error| format!("submit QZBE candidate block: {error}"))?;
        if !result.canonical_changed || result.canonical_height != next_height {
            return Err(format!(
                "candidate fork choice did not advance to requested height {next_height}"
            ));
        }
    }

    let expected = SmokeResult {
        network_id: args.network_id,
        genesis_manifest_hash,
        profile_fingerprint,
        start_height: current_height,
        end_height: store.canonical_height(),
        start_tip: current_tip,
        end_tip: store.canonical_tip(),
        end_state_root: store
            .canonical_state_root()
            .map_err(|error| format!("candidate state-root calculation failed: {error}"))?,
        manifest_generation: store.generation(),
        archive_len: store.archive_len(),
    };
    drop(store);

    // A distinct reopen checks the exact committed manifest and deterministically replays every
    // branch from Genesis before this smoke result is emitted.
    let reopened = V04ExecutionForkStoreCandidate::open(
        &args.data_dir,
        genesis,
        params,
        &RejectAllTransactions,
    )
    .map_err(|error| format!("candidate store replay/reopen failed: {error}"))?;
    let reopened_result = SmokeResult {
        network_id: args.network_id,
        genesis_manifest_hash,
        profile_fingerprint,
        start_height: current_height,
        end_height: reopened.canonical_height(),
        start_tip: current_tip,
        end_tip: reopened.canonical_tip(),
        end_state_root: reopened.canonical_state_root().map_err(|error| {
            format!("reopened candidate state-root calculation failed: {error}")
        })?,
        manifest_generation: reopened.generation(),
        archive_len: reopened.archive_len(),
    };
    if expected != reopened_result {
        return Err("post-reopen candidate state differs from just-committed QZBE state".into());
    }
    Ok(reopened_result)
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

fn main() {
    let tokens: Vec<String> = env::args().skip(1).collect();
    let args = match parse_arguments(&tokens) {
        Ok(Some(args)) => args,
        Ok(None) => {
            println!("{}", usage());
            return;
        }
        Err(error) => {
            eprintln!("QZBE_V04_CANDIDATE_SMOKE=ERROR {error}");
            process::exit(2);
        }
    };
    match run_smoke(&args) {
        Ok(result) => {
            println!("QZBE_V04_CANDIDATE_SMOKE=PASS");
            println!("execution_scope=offline_local_candidate_only");
            println!("p2p_listener=disabled rpc_listener=disabled wallet_listener=disabled market_access=disabled");
            println!("public_launch_approved=false mainnet_issuance=disabled transaction_submission=disabled");
            println!("network_id={}", hex(&result.network_id));
            println!(
                "genesis_manifest_hash={}",
                hex(&result.genesis_manifest_hash)
            );
            println!("profile_fingerprint={}", hex(&result.profile_fingerprint));
            println!(
                "height_before={} height_after={}",
                result.start_height, result.end_height
            );
            println!(
                "tip_before={} tip_after={}",
                hex(&result.start_tip),
                hex(&result.end_tip)
            );
            println!("state_root_after_replay={}", hex(&result.end_state_root));
            println!(
                "manifest_generation={} archive_len={}",
                result.manifest_generation, result.archive_len
            );
        }
        Err(error) => {
            eprintln!("QZBE_V04_CANDIDATE_SMOKE=FAIL {error}");
            process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);

    fn temp_path() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before Unix epoch")
            .as_nanos();
        let sequence = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
        env::temp_dir().join(format!(
            "qzbe-v04-smoke-{}-{nanos}-{sequence}",
            process::id()
        ))
    }

    fn args(path: PathBuf, blocks_to_build: u64) -> Args {
        Args {
            data_dir: path,
            network_id: [0x31; 32],
            owner_id: [0xA7; 32],
            miner_id: [0xC4; 32],
            initial_subsidy_atoms: 1_000_000,
            blocks_per_halving: 8,
            blocks_to_build,
        }
    }

    #[test]
    fn parser_requires_explicit_schedule_and_genesis_scope() {
        let tokens = vec![
            "--data-dir".to_string(),
            temp_path().display().to_string(),
            "--network-id".to_string(),
            "31".repeat(32),
            "--owner-id".to_string(),
            "a7".repeat(32),
            "--miner-id".to_string(),
            "c4".repeat(32),
            "--blocks-per-halving".to_string(),
            "8".to_string(),
            "--blocks".to_string(),
            "1".to_string(),
        ];
        assert!(parse_arguments(&tokens).is_err());
    }

    #[test]
    fn parser_rejects_zero_and_wrong_length_identifiers() {
        assert!(parse_hex32("00", "--network-id").is_err());
        assert!(parse_hex32(&"00".repeat(32), "--network-id").is_ok());
        let mut tokens = vec![
            "--data-dir".to_string(),
            temp_path().display().to_string(),
            "--network-id".to_string(),
            "31".repeat(32),
            "--owner-id".to_string(),
            "a7".repeat(32),
            "--miner-id".to_string(),
            "c4".repeat(32),
            "--initial-subsidy-atoms".to_string(),
            "1000000".to_string(),
            "--blocks-per-halving".to_string(),
            "8".to_string(),
            "--blocks".to_string(),
            "1".to_string(),
        ];
        assert!(parse_arguments(&tokens).unwrap().is_some());
        tokens[5] = "00".repeat(32);
        assert!(parse_arguments(&tokens).is_err());
    }

    #[test]
    fn parser_rejects_implicit_or_duplicate_options() {
        let path = temp_path();
        let valid = vec![
            "--data-dir".to_string(),
            path.display().to_string(),
            "--network-id".to_string(),
            "31".repeat(32),
            "--owner-id".to_string(),
            "a7".repeat(32),
            "--miner-id".to_string(),
            "c4".repeat(32),
            "--initial-subsidy-atoms".to_string(),
            "1000000".to_string(),
            "--blocks-per-halving".to_string(),
            "8".to_string(),
            "--blocks".to_string(),
            "1".to_string(),
        ];
        assert!(parse_arguments(&valid).unwrap().is_some());
        let mut duplicate = valid.clone();
        duplicate.extend(["--blocks".into(), "2".into()]);
        assert!(parse_arguments(&duplicate).is_err());
        assert!(parse_arguments(&[]).is_err());
    }

    #[test]
    fn local_smoke_commits_then_reopens_and_replays_qzbe_store() {
        let path = temp_path();
        let first = run_smoke(&args(path.clone(), 3)).unwrap();
        assert_eq!(first.start_height, 0);
        assert_eq!(first.end_height, 3);
        assert_eq!(first.manifest_generation, 3);
        assert_eq!(first.archive_len, 3);
        let second = run_smoke(&args(path.clone(), 2)).unwrap();
        assert_eq!(second.start_height, 3);
        assert_eq!(second.end_height, 5);
        assert_eq!(second.manifest_generation, 5);
        assert_eq!(second.archive_len, 5);
        assert_ne!(second.start_tip, second.end_tip);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn directory_with_non_candidate_data_is_rejected() {
        let path = temp_path();
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join("genesis.qvdn"), b"legacy profile marker").unwrap();
        assert!(run_smoke(&args(path.clone(), 1)).is_err());
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn changing_the_explicit_schedule_cannot_reopen_the_same_store() {
        let path = temp_path();
        run_smoke(&args(path.clone(), 1)).unwrap();
        let mut changed = args(path.clone(), 1);
        changed.initial_subsidy_atoms += 1;
        assert!(run_smoke(&changed).is_err());
        fs::remove_dir_all(path).unwrap();
    }
}
