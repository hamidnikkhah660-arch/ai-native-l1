use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, time::Instant};

type Hash = [u8; 32];

const ITERS: usize = 500;

fn hash_domain(domain: &[u8], bytes: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(bytes);
    h.finalize().into()
}

fn present_slot(child_hash: Hash) -> Hash {
    let mut payload = [0u8; 33];
    payload[0] = 0x11;
    payload[1..].copy_from_slice(&child_hash);
    hash_domain(b"AIN1-ASSET-COMMIT-ADAPT-NODE-CAND-V1\0", &payload)
}

fn pair_hash(left: Hash, right: Hash) -> Hash {
    let mut payload = [0u8; 65];
    payload[0] = 0x12;
    payload[1..33].copy_from_slice(&left);
    payload[33..].copy_from_slice(&right);
    hash_domain(b"AIN1-ASSET-COMMIT-ADAPT-NODE-CAND-V1\0", &payload)
}

fn defaults() -> [Hash; 9] {
    let mut out = [[0u8; 32]; 9];
    out[0] = hash_domain(b"AIN1-ASSET-COMMIT-ADAPT-NODE-CAND-V1\0", &[0x10]);
    for level in 0..8 {
        out[level + 1] = pair_hash(out[level], out[level]);
    }
    out
}

fn current_siblings(children: &BTreeMap<u8, Hash>, target: u8) -> Vec<Hash> {
    let defaults = defaults();
    let mut level: BTreeMap<usize, Hash> = children
        .iter()
        .map(|(&child, &hash)| (child as usize, present_slot(hash)))
        .collect();
    let mut index = target as usize;
    let mut siblings = Vec::with_capacity(8);

    for height in 0..8 {
        siblings.push(level.get(&(index ^ 1)).copied().unwrap_or(defaults[height]));
        if level.is_empty() {
            break;
        }
        let mut parents = std::collections::BTreeSet::new();
        for current in level.keys() {
            parents.insert(current / 2);
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
        index /= 2;
    }

    while siblings.len() < 8 {
        let height = siblings.len();
        siblings.push(defaults[height]);
    }
    siblings
}

fn fast_siblings(children: &BTreeMap<u8, Hash>, target: u8) -> Vec<Hash> {
    let defaults = defaults();
    let mut level: Vec<(usize, Hash)> = children
        .iter()
        .map(|(&child, &hash)| (child as usize, present_slot(hash)))
        .collect();
    let mut index = target as usize;
    let mut siblings = Vec::with_capacity(8);

    for height in 0..8 {
        let sibling_index = index ^ 1;
        let sibling = level
            .binary_search_by_key(&sibling_index, |(child, _)| *child)
            .ok()
            .map(|position| level[position].1)
            .unwrap_or(defaults[height]);
        siblings.push(sibling);

        let mut next: Vec<(usize, Hash)> = Vec::with_capacity(level.len());
        let mut cursor = 0usize;
        while cursor < level.len() {
            let parent = level[cursor].0 / 2;
            let left_index = parent * 2;
            let right_index = left_index + 1;
            let (left, right, advance) = if level[cursor].0 == right_index {
                let right = level[cursor].1;
                (defaults[height], right, 1usize)
            } else if cursor + 1 < level.len() && level[cursor + 1].0 == right_index {
                (level[cursor].1, level[cursor + 1].1, 2usize)
            } else {
                (level[cursor].1, defaults[height], 1usize)
            };
            next.push((parent, pair_hash(left, right)));
            cursor += advance;
        }

        if next.is_empty() {
            level.clear();
            break;
        }
        level = next;
        index /= 2;
    }

    siblings
}

fn make_cases() -> Vec<Vec<(u8, Hash)>> {
    let mut cases = Vec::new();
    for count in [256usize] {
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

fn hex(hash: &Hash) -> String {
    let mut out = String::with_capacity(64);
    for byte in hash {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn main() {
    let cases = make_cases();
    println!("CPW_ASSET_STATE_ADAPTIVE_SPARSE_SIBLING_COMPARE_V1");
    println!(
        "PARAMETERS ITERS={} NOTE=vector candidate must exactly preserve current sibling vectors",
        ITERS
    );

    for case in cases {
        let map: BTreeMap<u8, Hash> = case.iter().copied().collect();
        let target = case[case.len() / 2].0;
        let current = current_siblings(&map, target);
        let fast = fast_siblings(&map, target);
        assert_eq!(current, fast, "sibling vectors must match");

        let start = Instant::now();
        let mut sink = [0u8; 32];
        for _ in 0..ITERS {
            let siblings = current_siblings(&map, target);
            sink = siblings[0];
        }
        let current_ms = start.elapsed().as_secs_f64() * 1000.0;

        let start = Instant::now();
        let mut fast_sink = [0u8; 32];
        for _ in 0..ITERS {
            let siblings = fast_siblings(&map, target);
            fast_sink = siblings[0];
        }
        let fast_ms = start.elapsed().as_secs_f64() * 1000.0;

        println!(
            "CHILDREN={} CURRENT_MS={:.3} FAST_MS={:.3} FAST_TO_CURRENT_X={:.3} MATCH={} ROOT_SAMPLE={} FAST_SAMPLE={}",
            case.len(),
            current_ms,
            fast_ms,
            fast_ms / current_ms,
            sink == fast_sink,
            hex(&sink),
            hex(&fast_sink)
        );
    }
}
