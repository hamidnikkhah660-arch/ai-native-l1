use ai_native_l1_pow_bench::{
    asset_state_bucketed_commitment_candidate::BucketedAssetStateCommitment,
    asset_state_candidate::{AssetStateCandidate, CandidateResourceLimits},
    asset_state_candidate_store::load as load_asset_state,
    asset_state_incremental_commitment_candidate::IncrementalAssetStateCommitment,
    asset_transactions::{encode_operation, AssetOperation},
    token_forge::{
        asset_id, AccountId, AssetDefinition, BurnAuthority, FreezePolicy, MintAuthority,
        NetworkId, SupplyPolicy,
    },
};
use std::{
    fs,
    process::{Command, Stdio},
    time::Instant,
};

const NETWORK: NetworkId = [0xC7; 32];
const ALICE: AccountId = [0x11; 32];

fn account_from_index(index: usize) -> AccountId {
    let mut account = [0u8; 32];
    account[..8].copy_from_slice(&(index as u64 + 2).to_be_bytes());
    account
}

fn definition(index: usize) -> AssetDefinition {
    let mut metadata = [0u8; 32];
    metadata[..8].copy_from_slice(&(index as u64 + 1).to_be_bytes());
    AssetDefinition {
        network_id: NETWORK,
        creator: ALICE,
        creation_nonce: (index as u64) + 1,
        name: format!("Bench Asset {index}"),
        symbol: format!("B{:0>6}", index % 1_000_000),
        decimals: 8,
        metadata_hash: metadata,
        supply_policy: SupplyPolicy::Capped {
            initial_supply: 1_000,
            max_supply: 5_000,
        },
        mint_authority: MintAuthority::Creator,
        burn_authority: BurnAuthority::Holder,
        freeze_policy: FreezePolicy::Creator,
    }
}

fn run(
    size: usize,
    block_rounds: usize,
    restore_rounds: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut state = AssetStateCandidate::genesis(NETWORK)?;
    state.advance_height(100)?;

    let mut creates = Vec::with_capacity(size);
    let mut ids = Vec::with_capacity(size);
    for index in 0..size {
        let def = definition(index);
        ids.push(asset_id(&def)?);
        creates.push(encode_operation(&AssetOperation::Create {
            definition: def,
        })?);
    }

    let limits = CandidateResourceLimits {
        max_operations: size.max(1),
        max_operation_bytes: size
            .checked_mul(512)
            .ok_or("operation-byte limit overflow")?,
        max_assets: size.max(1),
        max_holdings: size.checked_mul(2).ok_or("holding limit overflow")?,
    };

    let create_start = Instant::now();
    state.apply_encoded_batch(&ALICE, &creates, limits)?;
    let create_ms = create_start.elapsed().as_secs_f64() * 1000.0;

    let mut transfers = Vec::with_capacity(size);
    for (index, asset_id) in ids.iter().copied().enumerate() {
        transfers.push(encode_operation(&AssetOperation::Transfer {
            asset_id,
            recipient: account_from_index(index),
            amount: 1,
        })?);
    }

    let transfer_start = Instant::now();
    state.apply_encoded_batch(&ALICE, &transfers, limits)?;
    let transfer_ms = transfer_start.elapsed().as_secs_f64() * 1000.0;

    let root_start = Instant::now();
    let root = state.state_root()?;
    let root_ms = root_start.elapsed().as_secs_f64() * 1000.0;

    let snapshot_start = Instant::now();
    let snapshot = state.encode_snapshot()?;
    let snapshot_ms = snapshot_start.elapsed().as_secs_f64() * 1000.0;

    let restore_path = std::env::temp_dir().join(format!(
        "cpw_asset_state_restore_bench_{}_{}.asv1",
        std::process::id(),
        size
    ));
    fs::write(&restore_path, &snapshot)?;
    let restore_start = Instant::now();
    for _ in 0..restore_rounds {
        let restored = load_asset_state(&restore_path, &NETWORK)?;
        if restored != state {
            return Err("file restore changed candidate state".into());
        }
    }
    let restore_file_ms =
        restore_start.elapsed().as_secs_f64() * 1000.0 / restore_rounds.max(1) as f64;

    let cold_restore_start = Instant::now();
    for _ in 0..restore_rounds {
        let status = Command::new(std::env::current_exe()?)
            .arg("--restore-child")
            .arg(&restore_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        if !status.success() {
            return Err("cold restore child failed".into());
        }
    }
    let cold_restore_ms =
        cold_restore_start.elapsed().as_secs_f64() * 1000.0 / restore_rounds.max(1) as f64;

    let first_asset = ids
        .first()
        .copied()
        .ok_or("benchmark requires a positive size")?;
    let first_recipient = account_from_index(0);
    let operation_limits = CandidateResourceLimits {
        max_operations: 1,
        max_operation_bytes: 512,
        max_assets: size.max(1),
        max_holdings: (size * 2).max(2),
    };

    let mut full_state = state.clone();
    let mut incremental_state = state.clone();
    let mut commitment = IncrementalAssetStateCommitment::from_state(&incremental_state)?;
    let mut bucketed_state = state.clone();
    let mut bucketed_commitment = BucketedAssetStateCommitment::from_state(&bucketed_state)?;
    let mut full_root_us = 0u128;

    for round in 0..block_rounds {
        full_state.advance_height(full_state.height() + 1)?;
        let (sender, recipient) = if round % 2 == 0 {
            (ALICE, first_recipient)
        } else {
            (first_recipient, ALICE)
        };
        full_state.apply_operation(
            &sender,
            &AssetOperation::Transfer {
                asset_id: first_asset,
                recipient,
                amount: 1,
            },
            operation_limits,
        )?;
        let start = Instant::now();
        let _ = full_state.state_root()?;
        full_root_us = full_root_us.saturating_add(start.elapsed().as_micros());
    }

    let mut incremental_update_us = 0u128;
    for round in 0..block_rounds {
        incremental_state.advance_height(incremental_state.height() + 1)?;
        let (sender, recipient) = if round % 2 == 0 {
            (ALICE, first_recipient)
        } else {
            (first_recipient, ALICE)
        };
        incremental_state.apply_operation(
            &sender,
            &AssetOperation::Transfer {
                asset_id: first_asset,
                recipient,
                amount: 1,
            },
            operation_limits,
        )?;

        let start = Instant::now();
        commitment.set_height(incremental_state.height())?;
        commitment.set_balance(
            first_asset,
            sender,
            incremental_state.balance(&first_asset, &sender),
        )?;
        commitment.set_balance(
            first_asset,
            recipient,
            incremental_state.balance(&first_asset, &recipient),
        )?;
        let _ = commitment.root();
        incremental_update_us = incremental_update_us.saturating_add(start.elapsed().as_micros());
    }

    let mut bucketed_update_us = 0u128;
    for round in 0..block_rounds {
        bucketed_state.advance_height(bucketed_state.height() + 1)?;
        let (sender, recipient) = if round % 2 == 0 {
            (ALICE, first_recipient)
        } else {
            (first_recipient, ALICE)
        };
        bucketed_state.apply_operation(
            &sender,
            &AssetOperation::Transfer {
                asset_id: first_asset,
                recipient,
                amount: 1,
            },
            operation_limits,
        )?;

        let start = Instant::now();
        bucketed_commitment.set_height(bucketed_state.height())?;
        bucketed_commitment.set_balance(
            first_asset,
            sender,
            bucketed_state.balance(&first_asset, &sender),
        )?;
        bucketed_commitment.set_balance(
            first_asset,
            recipient,
            bucketed_state.balance(&first_asset, &recipient),
        )?;
        let _ = bucketed_commitment.root();
        bucketed_update_us = bucketed_update_us.saturating_add(start.elapsed().as_micros());
    }

    if full_state != incremental_state || full_state != bucketed_state {
        return Err("commitment benchmark state executions diverged".into());
    }
    let rebuilt_matches = commitment.matches_rebuild(&incremental_state)?;
    if !rebuilt_matches {
        return Err("incremental commitment diverged from rebuilt state".into());
    }
    let bucketed_rebuilt_matches = bucketed_commitment.matches_rebuild(&bucketed_state)?;
    if !bucketed_rebuilt_matches {
        return Err("bucketed commitment diverged from rebuilt state".into());
    }

    let final_root = full_state.state_root()?;
    let incremental_root = commitment.root();
    let bucketed_root = bucketed_commitment.root();
    let full_root_ms = full_root_us as f64 / 1000.0 / block_rounds.max(1) as f64;
    let incremental_update_ms = incremental_update_us as f64 / 1000.0 / block_rounds.max(1) as f64;
    let incremental_speedup = if incremental_update_ms > 0.0 {
        full_root_ms / incremental_update_ms
    } else {
        0.0
    };
    let bucketed_update_ms = bucketed_update_us as f64 / 1000.0 / block_rounds.max(1) as f64;
    let bucketed_speedup = if bucketed_update_ms > 0.0 {
        full_root_ms / bucketed_update_ms
    } else {
        0.0
    };

    let _ = fs::remove_file(&restore_path);
    println!(
        "SIZE={} ASSETS={} HOLDINGS={} CREATE_MS={:.3} TRANSFER_MS={:.3} INITIAL_ROOT_MS={:.3} SNAPSHOT_MS={:.3} FILE_RESTORE_MS={:.3} COLD_RESTORE_PROCESS_MS={:.3} FULL_ROOT_ONLY_MS={:.3} INCREMENTAL_COMMITMENT_UPDATE_MS={:.3} INCREMENTAL_SPEEDUP_X={:.3} BUCKETED_COMMITMENT_UPDATE_MS={:.3} BUCKETED_SPEEDUP_X={:.3} BUCKET_COUNT={} LARGEST_BUCKET={} REPEATED_BLOCKS={} SNAPSHOT_BYTES={} INITIAL_ROOT={} FINAL_ROOT={} INCREMENTAL_ROOT={} BUCKETED_ROOT={}",
        size,
        full_state.asset_count(),
        full_state.holding_count(),
        create_ms,
        transfer_ms,
        root_ms,
        snapshot_ms,
        restore_file_ms,
        cold_restore_ms,
        full_root_ms,
        incremental_update_ms,
        incremental_speedup,
        bucketed_update_ms,
        bucketed_speedup,
        bucketed_commitment.bucket_count(),
        bucketed_commitment.largest_bucket_len(),
        block_rounds,
        snapshot.len(),
        hex(&root),
        hex(&final_root),
        hex(&incremental_root),
        hex(&bucketed_root)
    );
    Ok(())
}

fn run_restore_child(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let _ = load_asset_state(path, &NETWORK)?;
    Ok(())
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--restore-child") {
        let Some(path) = args.get(2) else {
            eprintln!("--restore-child requires a snapshot path");
            std::process::exit(2);
        };
        if let Err(error) = run_restore_child(std::path::Path::new(path)) {
            eprintln!("RESTORE_CHILD_FAILED ERROR={error}");
            std::process::exit(1);
        }
        return;
    }

    let mut sizes = vec![16usize, 64, 256, 1024];
    let mut block_rounds = 16usize;
    let mut restore_rounds = 4usize;
    let mut index = 1usize;
    while index < args.len() {
        match args[index].as_str() {
            "--sizes" => {
                index += 1;
                let Some(raw) = args.get(index) else {
                    eprintln!("--sizes requires comma-separated positive integers");
                    std::process::exit(2);
                };
                let parsed: Result<Vec<usize>, _> =
                    raw.split(',').map(|value| value.parse::<usize>()).collect();
                match parsed {
                    Ok(values) if values.iter().all(|value| *value > 0) => sizes = values,
                    _ => {
                        eprintln!("--sizes must contain only positive integers");
                        std::process::exit(2);
                    }
                }
            }
            "--block-rounds" => {
                index += 1;
                let Some(raw) = args.get(index) else {
                    eprintln!("--block-rounds requires a positive integer");
                    std::process::exit(2);
                };
                block_rounds = match raw.parse::<usize>() {
                    Ok(value) if value > 0 => value,
                    _ => {
                        eprintln!("--block-rounds requires a positive integer");
                        std::process::exit(2);
                    }
                };
            }
            "--restore-rounds" => {
                index += 1;
                let Some(raw) = args.get(index) else {
                    eprintln!("--restore-rounds requires a positive integer");
                    std::process::exit(2);
                };
                restore_rounds = match raw.parse::<usize>() {
                    Ok(value) if value > 0 => value,
                    _ => {
                        eprintln!("--restore-rounds requires a positive integer");
                        std::process::exit(2);
                    }
                };
            }
            "--help" | "-h" => {
                println!(
                    "asset_state_candidate_bench [--sizes N,N,N] [--block-rounds N] [--restore-rounds N]"
                );
                return;
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
        index += 1;
    }

    println!("CPW_ASSET_STATE_CANDIDATE_BENCH_V1");
    println!(
        "PARAMETERS BLOCK_ROUNDS={} RESTORE_ROUNDS={} NOTE=process-cold means fresh child process with normal OS file-cache behavior",
        block_rounds, restore_rounds
    );
    for size in sizes {
        if let Err(error) = run(size, block_rounds, restore_rounds) {
            eprintln!("BENCHMARK_FAILED SIZE={size} ERROR={error}");
            std::process::exit(1);
        }
    }
}
