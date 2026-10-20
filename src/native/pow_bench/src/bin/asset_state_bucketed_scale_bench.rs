use ai_native_l1_pow_bench::{
    asset_state_bucketed_commitment_candidate::BucketedAssetStateCommitment,
    asset_state_candidate::{AssetStateCandidate, CandidateResourceLimits},
    asset_transactions::{encode_operation, AssetOperation},
    token_forge::{
        asset_id, AccountId, AssetDefinition, BurnAuthority, FreezePolicy, MintAuthority,
        NetworkId, SupplyPolicy,
    },
};
use std::time::Instant;

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
        name: format!("Scale Asset {index}"),
        symbol: format!("S{:0>6}", index % 1_000_000),
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

fn run(size: usize, block_rounds: usize) -> Result<(), Box<dyn std::error::Error>> {
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
    let _ = state.state_root()?;
    let full_root_ms = root_start.elapsed().as_secs_f64() * 1000.0;

    let rebuild_start = Instant::now();
    let mut commitment = BucketedAssetStateCommitment::from_state(&state)?;
    let rebuild_ms = rebuild_start.elapsed().as_secs_f64() * 1000.0;
    let bucket_count = commitment.bucket_count();
    let largest_bucket = commitment.largest_bucket_len();
    let max_proof_bytes = commitment.max_membership_proof_size_upper_bound(32)?;

    let first_asset = *ids.first().ok_or("benchmark requires a positive size")?;
    let first_recipient = account_from_index(0);
    let operation_limits = CandidateResourceLimits {
        max_operations: 1,
        max_operation_bytes: 512,
        max_assets: size.max(1),
        max_holdings: (size * 2).max(2),
    };

    let mut update_total_us = 0u128;
    let mut full_root_total_us = 0u128;
    for round in 0..block_rounds {
        let (sender, recipient) = if round % 2 == 0 {
            (ALICE, first_recipient)
        } else {
            (first_recipient, ALICE)
        };

        state.advance_height(state.height() + 1)?;
        state.apply_operation(
            &sender,
            &AssetOperation::Transfer {
                asset_id: first_asset,
                recipient,
                amount: 1,
            },
            operation_limits,
        )?;

        let full_start = Instant::now();
        let _ = state.state_root()?;
        full_root_total_us = full_root_total_us.saturating_add(full_start.elapsed().as_micros());

        let update_start = Instant::now();
        commitment.set_height(state.height())?;
        commitment.set_balance(first_asset, sender, state.balance(&first_asset, &sender))?;
        commitment.set_balance(
            first_asset,
            recipient,
            state.balance(&first_asset, &recipient),
        )?;
        let _ = commitment.root();
        update_total_us = update_total_us.saturating_add(update_start.elapsed().as_micros());
    }

    if !commitment.matches_rebuild(&state)? {
        return Err("bucketed commitment failed rebuild equivalence".into());
    }

    let avg_full_root_ms = full_root_total_us as f64 / 1000.0 / block_rounds.max(1) as f64;
    let avg_update_ms = update_total_us as f64 / 1000.0 / block_rounds.max(1) as f64;
    let speedup = if avg_update_ms > 0.0 {
        avg_full_root_ms / avg_update_ms
    } else {
        0.0
    };

    println!(
        "SIZE={} ASSETS={} HOLDINGS={} CREATE_MS={:.3} TRANSFER_MS={:.3} INITIAL_FULL_ROOT_MS={:.3} BUCKETED_REBUILD_MS={:.3} BUCKETED_UPDATE_MS={:.3} FULL_ROOT_PER_BLOCK_MS={:.3} SPEEDUP_X={:.3} BUCKET_COUNT={} LARGEST_BUCKET={} MAX_PROOF_BYTES={} REPEATED_BLOCKS={} ",
        size,
        state.asset_count(),
        state.holding_count(),
        create_ms,
        transfer_ms,
        full_root_ms,
        rebuild_ms,
        avg_update_ms,
        avg_full_root_ms,
        speedup,
        bucket_count,
        largest_bucket,
        max_proof_bytes,
        block_rounds
    );
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut sizes = vec![4096usize, 16384];
    let mut block_rounds = 2usize;

    let mut index = 1usize;
    while index < args.len() {
        match args[index].as_str() {
            "--sizes" => {
                index += 1;
                let Some(raw) = args.get(index) else {
                    eprintln!("--sizes requires comma-separated positive integers");
                    std::process::exit(2);
                };
                match raw
                    .split(',')
                    .map(str::parse::<usize>)
                    .collect::<Result<Vec<_>, _>>()
                {
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
                match raw.parse::<usize>() {
                    Ok(value) if value > 0 => block_rounds = value,
                    _ => {
                        eprintln!("--block-rounds requires a positive integer");
                        std::process::exit(2);
                    }
                }
            }
            "--help" | "-h" => {
                println!("asset_state_bucketed_scale_bench [--sizes N,N,N] [--block-rounds N]");
                return;
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
        index += 1;
    }

    println!("CPW_ASSET_STATE_BUCKETED_SCALE_BENCH_V1");
    println!("PARAMETERS BLOCK_ROUNDS={} NOTE=bucketed-only; naive 256-level commitment is not instantiated", block_rounds);

    for size in sizes {
        if let Err(error) = run(size, block_rounds) {
            eprintln!("BENCHMARK_FAILED SIZE={} ERROR={}", size, error);
            std::process::exit(1);
        }
    }
}
