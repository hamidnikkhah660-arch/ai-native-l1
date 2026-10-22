//! CP-0132-AB synthetic branch-local target/time history exporter.
//! No PTB2 blocks are mined or admitted; this is candidate retarget/work/fork-choice math only.
use ai_native_l1_pow_bench::{
    consensus::{block_work, compare_chain_tips, ChainTip, ConsensusParameters, Uint256},
    private_testnet_consensus::target_for_next_block,
};
use sha2::{Digest, Sha256};

const WINDOW: u64 = 4;
const TARGET_SPACING: u64 = 60;
const GENESIS_TIMESTAMP: u64 = 1_000;

#[derive(Clone, Debug)]
struct Row {
    branch: &'static str,
    height: u64,
    timestamp: u64,
    elapsed: Option<u64>,
    target: Uint256,
    work: Uint256,
    cumulative_work: Uint256,
    parent_tip: [u8; 32],
    tip: [u8; 32],
    canonical_tip: [u8; 32],
    canonical_branch: &'static str,
    canonical_height: u64,
    canonical_work: Uint256,
    reorg_count: u64,
}

impl Row {
    fn chain_tip(&self) -> ChainTip {
        ChainTip {
            height: self.height,
            cumulative_work: self.cumulative_work,
            tip_hash: self.tip,
        }
    }
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

fn synthetic_tip(
    branch: &'static str,
    height: u64,
    timestamp: u64,
    target: Uint256,
    parent_tip: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"AIN1-CP0132-AB-SYNTHETIC-TIP-V1\0");
    hasher.update(branch.as_bytes());
    hasher.update(height.to_be_bytes());
    hasher.update(timestamp.to_be_bytes());
    hasher.update(target.to_be_bytes());
    hasher.update(parent_tip);
    hasher.finalize().into()
}

fn params() -> ConsensusParameters {
    let mut params = ConsensusParameters::candidate_testnet().expect("candidate params");
    params.target_block_time_secs = TARGET_SPACING;
    params.difficulty_window_blocks = WINDOW;
    params.difficulty_min_ratio_divisor = 4;
    params.difficulty_max_ratio = 4;
    params.pow_limit = Uint256::MAX;
    let mut initial = [0u8; 32];
    initial[0] = 0x01; // 2^248; ample headroom for the synthetic retarget sequence.
    params.initial_target = Uint256::from_be_bytes(initial);
    params
        .validate()
        .expect("valid synthetic candidate profile");
    params
}

fn build_branch(
    branch: &'static str,
    interval_secs: u64,
    params: &ConsensusParameters,
) -> Vec<Row> {
    let mut timestamps = vec![GENESIS_TIMESTAMP];
    let mut targets = vec![params.initial_target];
    let mut rows = Vec::new();
    let mut parent_tip = [0u8; 32];
    let mut cumulative_work = Uint256::ZERO;

    for height in 1..=9u64 {
        let timestamp = timestamps[(height - 1) as usize]
            .checked_add(interval_secs)
            .expect("fixture timestamp arithmetic");
        timestamps.push(timestamp);

        let elapsed = if height > WINDOW && (height - 1) % WINDOW == 0 {
            let end = timestamps[(height - 1) as usize];
            let start_index = (height - 1 - WINDOW) as usize;
            let start = timestamps[start_index];
            Some(
                end.checked_sub(start)
                    .expect("monotonic fixture timestamps"),
            )
        } else {
            None
        };

        let target = target_for_next_block(targets[(height - 1) as usize], height, elapsed, params)
            .expect("target history transition");
        let work = block_work(target).expect("non-zero target work");
        cumulative_work = cumulative_work
            .checked_add(work)
            .expect("synthetic branch chain work must fit in Uint256");
        let tip = synthetic_tip(branch, height, timestamp, target, parent_tip);

        rows.push(Row {
            branch,
            height,
            timestamp,
            elapsed,
            target,
            work,
            cumulative_work,
            parent_tip,
            tip,
            canonical_tip: [0; 32],
            canonical_branch: "GENESIS",
            canonical_height: 0,
            canonical_work: Uint256::ZERO,
            reorg_count: 0,
        });
        targets.push(target);
        parent_tip = tip;
    }
    rows
}

fn main() {
    let params = params();
    println!(
        "META\tCP0132_AB_BRANCH_TARGET_HISTORY_V1\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        WINDOW,
        TARGET_SPACING,
        GENESIS_TIMESTAMP,
        hex(&params.initial_target.to_be_bytes()),
        hex(&params.pow_limit.to_be_bytes()),
        params.difficulty_min_ratio_divisor,
        params.difficulty_max_ratio,
    );

    // Insert the slower branch first. The faster branch later overtakes it by cumulative work,
    // even while its candidate tip is shorter; this intentionally tests work-before-height.
    let mut insertion_order = build_branch("B", 120, &params);
    insertion_order.extend(build_branch("A", 30, &params));

    let mut accepted: Vec<Row> = Vec::new();
    let mut canonical_tip = [0u8; 32];
    let mut canonical_branch = "GENESIS";
    let mut canonical_height = 0u64;
    let mut canonical_work = Uint256::ZERO;
    let mut reorg_count = 0u64;

    for mut row in insertion_order {
        accepted.push(row.clone());
        let mut best_tip = [0u8; 32];
        let mut best_branch = "GENESIS";
        let mut best_height = 0u64;
        let mut best_work = Uint256::ZERO;
        let genesis_tip = ChainTip {
            height: 0,
            cumulative_work: Uint256::ZERO,
            tip_hash: [0u8; 32],
        };
        let mut best_chain_tip = genesis_tip;

        for candidate in &accepted {
            let tip = candidate.chain_tip();
            if compare_chain_tips(tip, best_chain_tip).is_gt() {
                best_chain_tip = tip;
                best_tip = candidate.tip;
                best_branch = candidate.branch;
                best_height = candidate.height;
                best_work = candidate.cumulative_work;
            }
        }

        if best_tip != canonical_tip {
            if canonical_tip != [0u8; 32] && best_branch != canonical_branch {
                reorg_count = reorg_count.saturating_add(1);
            }
            canonical_tip = best_tip;
            canonical_branch = best_branch;
            canonical_height = best_height;
            canonical_work = best_work;
        }

        row.canonical_tip = canonical_tip;
        row.canonical_branch = canonical_branch;
        row.canonical_height = canonical_height;
        row.canonical_work = canonical_work;
        row.reorg_count = reorg_count;

        println!(
            "ROW\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            row.branch,
            row.height,
            row.timestamp,
            row.elapsed
                .map_or_else(|| "-".to_owned(), |v| v.to_string()),
            hex(&row.target.to_be_bytes()),
            hex(&row.work.to_be_bytes()),
            hex(&row.cumulative_work.to_be_bytes()),
            hex(&row.parent_tip),
            hex(&row.tip),
            hex(&row.canonical_tip),
            row.canonical_branch,
            row.canonical_height,
            hex(&row.canonical_work.to_be_bytes()),
            row.reorg_count,
        );
    }
    println!("END\trows=18\tbranches=2\tcanonical_consensus_untouched=true");
}
