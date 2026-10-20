use ai_native_l1_pow_bench::asset_state_adaptive_commitment_candidate::AdaptiveAssetStateCommitment;
use std::collections::BTreeMap;
use std::error::Error;
use std::time::Instant;

const NETWORK: [u8; 32] = [0xC7; 32];
const HEIGHT: u64 = 100;

#[derive(Clone)]
struct BucketSpec {
    id: [u8; 2],
    count: usize,
    value_len: usize,
}

#[derive(Default)]
struct Timing {
    incremental_ns: u128,
    rebuild_ns: u128,
    samples: usize,
    equivalence_checks: usize,
}

impl Timing {
    fn record(&mut self, incremental_ns: u128, rebuild_ns: u128, checks: usize) {
        self.incremental_ns = self.incremental_ns.saturating_add(incremental_ns);
        self.rebuild_ns = self.rebuild_ns.saturating_add(rebuild_ns);
        self.samples += 1;
        self.equivalence_checks += checks;
    }

    fn print(&self, shape: &str, operation: &str) {
        let divisor = self.samples.max(1) as f64;
        let incremental_us = self.incremental_ns as f64 / divisor / 1_000.0;
        let rebuild_us = self.rebuild_ns as f64 / divisor / 1_000.0;
        let ratio = if incremental_us > 0.0 {
            rebuild_us / incremental_us
        } else {
            0.0
        };
        println!(
            "PROFILE|shape={shape}|operation={operation}|samples={}|incremental_us_avg={incremental_us:.3}|rebuild_us_avg={rebuild_us:.3}|rebuild_over_incremental_x={ratio:.3}|root_checks={}",
            self.samples, self.equivalence_checks
        );
    }
}

fn make_key(bucket: [u8; 2], index: usize) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[..2].copy_from_slice(&bucket);
    key[2] = (index / 32) as u8;
    key[24..].copy_from_slice(&(index as u64).to_be_bytes());
    key
}

fn bucket_value(spec_index: usize, value_len: usize) -> Vec<u8> {
    vec![(0x11u8).wrapping_add(spec_index as u8); value_len]
}

fn fixtures() -> Vec<(&'static str, Vec<BucketSpec>)> {
    let single = vec![BucketSpec {
        id: [0x5a, 0xa8],
        count: 33,
        value_len: 32,
    }];
    let uneven = vec![
        BucketSpec {
            id: [0x5a, 0xa8],
            count: 33,
            value_len: 32,
        },
        BucketSpec {
            id: [0x5a, 0xa9],
            count: 32,
            value_len: 8,
        },
        BucketSpec {
            id: [0x10, 0x01],
            count: 5,
            value_len: 1,
        },
        BucketSpec {
            id: [0xff, 0xfe],
            count: 2,
            value_len: 127,
        },
    ];
    let boundary_counts = [1usize, 2, 7, 31, 32, 33, 64, 65];
    let boundary = boundary_counts
        .iter()
        .enumerate()
        .map(|(i, count)| BucketSpec {
            id: [0x70, i as u8],
            count: *count,
            value_len: [1usize, 8, 32, 127][i % 4],
        })
        .collect();
    let skewed_counts = [
        1usize, 2, 3, 7, 15, 16, 17, 31, 32, 33, 34, 63, 64, 65, 96, 97,
    ];
    let skewed = skewed_counts
        .iter()
        .enumerate()
        .map(|(i, count)| BucketSpec {
            id: [0x20 + (i / 256) as u8, i as u8],
            count: *count,
            value_len: [1usize, 8, 32, 127][(i * 3) % 4],
        })
        .collect();

    vec![
        ("single_split_collapse_33", single),
        ("four_bucket_uneven_33_32_5_2", uneven),
        ("eight_bucket_chunk_boundaries", boundary),
        ("sixteen_bucket_skewed_populations", skewed),
    ]
}

fn entries(values: &BTreeMap<[u8; 32], Vec<u8>>) -> Vec<([u8; 32], Vec<u8>)> {
    values
        .iter()
        .map(|(key, value)| (*key, value.clone()))
        .collect()
}

fn apply_and_check(
    commitment: &mut AdaptiveAssetStateCommitment,
    values: &mut BTreeMap<[u8; 32], Vec<u8>>,
    network: [u8; 32],
    key: [u8; 32],
    new_value: Option<&[u8]>,
) -> Result<(u128, u128), Box<dyn Error>> {
    let start = Instant::now();
    commitment.set_raw_leaf_value(key, new_value)?;
    let incremental_ns = start.elapsed().as_nanos();

    match new_value {
        Some(value) => {
            values.insert(key, value.to_vec());
        }
        None => {
            values
                .remove(&key)
                .ok_or("benchmark attempted to delete absent leaf")?;
        }
    }

    let start = Instant::now();
    let mut rebuilt = AdaptiveAssetStateCommitment::new(network, HEIGHT)?;
    rebuilt.rebuild_from_raw_leaves(&entries(values))?;
    let rebuild_ns = start.elapsed().as_nanos();

    if commitment.root() != rebuilt.root() {
        return Err("incremental inner root diverged from rebuilt root".into());
    }
    if commitment.network_bound_root() != rebuilt.network_bound_root() {
        return Err("incremental network-bound root diverged from rebuilt root".into());
    }
    if commitment.bucket_count() != rebuilt.bucket_count()
        || commitment.largest_bucket_len() != rebuilt.largest_bucket_len()
        || commitment.largest_terminal_chunk_len() != rebuilt.largest_terminal_chunk_len()
        || commitment.deepest_bucket_path() != rebuilt.deepest_bucket_path()
    {
        return Err("incremental structural metrics diverged from rebuilt metrics".into());
    }
    Ok((incremental_ns, rebuild_ns))
}

fn run_shape(name: &str, specs: &[BucketSpec], rounds: usize) -> Result<(), Box<dyn Error>> {
    let mut values = BTreeMap::new();
    let mut bases = Vec::with_capacity(specs.len());
    for (spec_index, spec) in specs.iter().enumerate() {
        let base = bucket_value(spec_index, spec.value_len);
        bases.push(base.clone());
        for index in 0..spec.count {
            values.insert(make_key(spec.id, index), base.clone());
        }
    }
    let initial_leaves = values.len();
    let mut commitment = AdaptiveAssetStateCommitment::new(NETWORK, HEIGHT)?;
    commitment.rebuild_from_raw_leaves(&entries(&values))?;

    let mut timings: BTreeMap<&'static str, Timing> = [
        ("delete", Timing::default()),
        ("insert", Timing::default()),
        ("update", Timing::default()),
        ("revert_update", Timing::default()),
    ]
    .into_iter()
    .collect();

    // Round zero warms the same code paths but is intentionally excluded from timing averages.
    for round in 0..rounds {
        for (spec_index, spec) in specs.iter().enumerate() {
            let base = &bases[spec_index];
            let target = make_key(spec.id, spec.count - 1);
            let update_key = make_key(spec.id, 0);

            let (inc, rebuild) =
                apply_and_check(&mut commitment, &mut values, NETWORK, target, None)?;
            if round > 0 {
                timings.get_mut("delete").unwrap().record(inc, rebuild, 1);
            }

            let (inc, rebuild) =
                apply_and_check(&mut commitment, &mut values, NETWORK, target, Some(base))?;
            if round > 0 {
                timings.get_mut("insert").unwrap().record(inc, rebuild, 1);
            }

            if spec.count > 1 {
                let changed = vec![0x99; base.len()];
                let (inc, rebuild) = apply_and_check(
                    &mut commitment,
                    &mut values,
                    NETWORK,
                    update_key,
                    Some(&changed),
                )?;
                if round > 0 {
                    timings.get_mut("update").unwrap().record(inc, rebuild, 1);
                }

                let (inc, rebuild) = apply_and_check(
                    &mut commitment,
                    &mut values,
                    NETWORK,
                    update_key,
                    Some(base),
                )?;
                if round > 0 {
                    timings
                        .get_mut("revert_update")
                        .unwrap()
                        .record(inc, rebuild, 1);
                }
            }
        }
        if values.len() != initial_leaves {
            return Err("mutation profile failed to restore leaf count".into());
        }
    }

    println!(
        "SHAPE|name={name}|primary_buckets={}|initial_leaves={initial_leaves}|rounds={rounds}|timed_rounds={}",
        commitment.bucket_count(),
        rounds - 1
    );
    for operation in ["delete", "insert", "update", "revert_update"] {
        timings[operation].print(name, operation);
    }
    println!(
        "SHAPE_CHECK|name={name}|root={}|outer_root={}|bucket_count={}|largest_bucket={}|largest_chunk={}|deepest_path={}|RESTORED=true",
        hex(&commitment.root()),
        hex(&commitment.network_bound_root()),
        commitment.bucket_count(),
        commitment.largest_bucket_len(),
        commitment.largest_terminal_chunk_len(),
        commitment.deepest_bucket_path()
    );
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let rounds = args
        .iter()
        .position(|arg| arg == "--rounds")
        .and_then(|index| args.get(index + 1))
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value >= 2)
        .unwrap_or(5);

    println!("CPW_ADAPTIVE_INCREMENTAL_MUTATION_PROFILE_V1");
    println!(
        "ENV|OS={}|ARCH={}|ROUNDS={}|WARMUP_ROUNDS=1|METHOD=single-process-local-timing",
        std::env::consts::OS,
        std::env::consts::ARCH,
        rounds
    );
    for (name, specs) in fixtures() {
        if let Err(error) = run_shape(name, &specs, rounds) {
            eprintln!("PROFILE_FAILED|shape={name}|error={error}");
            std::process::exit(1);
        }
    }
    println!("PROFILE_RESULT=PASS");
}
