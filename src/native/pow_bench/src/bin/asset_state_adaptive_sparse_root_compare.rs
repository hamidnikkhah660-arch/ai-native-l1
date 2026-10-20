use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, time::Instant};

type Hash = [u8; 32];

const BENCH_ITERS: usize = 10_000;

fn hash_domain(domain: &[u8], bytes: &[u8]) -> Hash {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    hash.finalize().into()
}

fn present_slot(child_hash: Hash) -> Hash {
    let mut payload = Vec::with_capacity(33);
    payload.push(0x11);
    payload.extend_from_slice(&child_hash);
    hash_domain(b"AIN1-ASSET-COMMIT-ADAPT-NODE-CAND-V1\0", &payload)
}

fn pair_hash(left: Hash, right: Hash) -> Hash {
    let mut payload = Vec::with_capacity(65);
    payload.push(0x12);
    payload.extend_from_slice(&left);
    payload.extend_from_slice(&right);
    hash_domain(b"AIN1-ASSET-COMMIT-ADAPT-NODE-CAND-V1\0", &payload)
}

fn defaults() -> [Hash; 9] {
    let mut out = [[0u8; 32]; 9];
    out[0] = hash_domain(b"AIN1-ASSET-COMMIT-ADAPT-NODE-CAND-V1\0", &[0x10]);
    for height in 0..8 {
        out[height + 1] = pair_hash(out[height], out[height]);
    }
    out
}

fn current_sparse_root(children: &BTreeMap<u8, Hash>) -> Hash {
    let defaults = defaults();
    let mut level: BTreeMap<usize, Hash> = children
        .iter()
        .map(|(&child, &hash)| (child as usize, present_slot(hash)))
        .collect();

    for height in 0..8 {
        if level.is_empty() {
            return defaults[8];
        }
        let mut parents = std::collections::BTreeSet::new();
        for index in level.keys() {
            parents.insert(index / 2);
        }
        let mut next = BTreeMap::new();
        for parent in parents {
            let left = level
                .get(&(parent * 2))
                .copied()
                .unwrap_or(defaults[height]);
            let right = level
                .get(&(parent * 2 + 1))
                .copied()
                .unwrap_or(defaults[height]);
            next.insert(parent, pair_hash(left, right));
        }
        level = next;
    }
    level.get(&0).copied().unwrap_or(defaults[8])
}

fn fast_sparse_root_from_sorted(children: &[(u8, Hash)]) -> Hash {
    let defaults = defaults();

    fn recurse(items: &[(u8, Hash)], bit: i8, defaults: &[Hash; 9]) -> Hash {
        if items.is_empty() {
            return defaults[(bit + 1) as usize];
        }
        if bit < 0 {
            return items[0].1;
        }

        let split_bit = bit as u8;
        let mask = 1u8 << split_bit;
        let mut split = 0usize;
        while split < items.len() && (items[split].0 & mask) == 0 {
            split += 1;
        }

        let left = recurse(&items[..split], bit - 1, defaults);
        let right = recurse(&items[split..], bit - 1, defaults);
        pair_hash(left, right)
    }

    let present: Vec<(u8, Hash)> = children
        .iter()
        .map(|(index, hash)| (*index, present_slot(*hash)))
        .collect();

    recurse(&present, 7, &defaults)
}

fn make_cases() -> Vec<Vec<(u8, Hash)>> {
    let mut cases = Vec::new();
    for count in [1usize, 2, 4, 8, 16, 32, 64, 128, 256] {
        let mut items = Vec::with_capacity(count);
        for i in 0..count {
            let index = if count == 256 {
                i as u8
            } else {
                ((i * 251 + 17) % 256) as u8
            };
            let mut h = [0u8; 32];
            h[0] = index;
            h[31] = (i as u8).wrapping_mul(17);
            items.push((index, h));
        }
        items.sort_by_key(|(index, _)| *index);
        items.dedup_by_key(|(index, _)| *index);
        cases.push(items);
    }
    cases
}

fn hex(bytes: &Hash) -> String {
    let mut out = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn main() {
    let cases = make_cases();
    for case in &cases {
        let map: BTreeMap<u8, Hash> = case.iter().copied().collect();
        let current = current_sparse_root(&map);
        let fast = fast_sparse_root_from_sorted(case);
        assert_eq!(current, fast, "roots must match");
    }

    println!("CPW_ASSET_STATE_ADAPTIVE_SPARSE_ROOT_COMPARE_V1");
    println!(
        "PARAMETERS ITERS={} NOTE=fast path is candidate-only and must preserve exact roots",
        BENCH_ITERS
    );

    for case in &cases {
        let map: BTreeMap<u8, Hash> = case.iter().copied().collect();
        let current_start = Instant::now();
        let mut current_sink = [0u8; 32];
        for _ in 0..BENCH_ITERS {
            current_sink = current_sparse_root(&map);
        }
        let current_ms = current_start.elapsed().as_secs_f64() * 1000.0;

        let fast_start = Instant::now();
        let mut fast_sink = [0u8; 32];
        for _ in 0..BENCH_ITERS {
            fast_sink = fast_sparse_root_from_sorted(case);
        }
        let fast_ms = fast_start.elapsed().as_secs_f64() * 1000.0;

        println!(
            "CHILDREN={} CURRENT_MS={:.3} FAST_MS={:.3} FAST_TO_CURRENT_X={:.3} ROOT_MATCH={} ROOT={}",
            case.len(),
            current_ms,
            fast_ms,
            if current_ms > 0.0 { fast_ms / current_ms } else { 0.0 },
            current_sink == fast_sink,
            hex(&current_sink)
        );
    }
}
