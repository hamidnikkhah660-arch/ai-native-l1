use ai_native_l1_pow_bench::consensus::{
    block_work, compare_chain_tips, cumulative_chain_work, retarget_target, ChainTip,
    ConsensusParameters, Uint256,
};
use std::cmp::Ordering;

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn target_hex(target: Uint256) -> String {
    hex(&target.to_be_bytes())
}

fn target_with_last_byte(value: u8) -> Uint256 {
    let mut bytes = [0u8; 32];
    bytes[31] = value;
    Uint256::from_be_bytes(bytes)
}

fn emit_work(name: &str, target: Uint256) {
    let result = match block_work(target) {
        Ok(work) => target_hex(work),
        Err(error) => format!("ERR:{error:?}"),
    };
    println!("WORK|{name}|{}|{result}", target_hex(target));
}

fn emit_cumulative(name: &str, targets: &[Uint256]) {
    let inputs = targets
        .iter()
        .map(|target| target_hex(*target))
        .collect::<Vec<_>>()
        .join(",");
    let result = match cumulative_chain_work(targets) {
        Ok(work) => target_hex(work),
        Err(error) => format!("ERR:{error:?}"),
    };
    println!("CUM|{name}|{inputs}|{result}");
}

fn emit_retarget(
    name: &str,
    previous_target: Uint256,
    elapsed_secs: u64,
    params: &ConsensusParameters,
) {
    let result = match retarget_target(previous_target, elapsed_secs, params) {
        Ok(target) => target_hex(target),
        Err(error) => format!("ERR:{error:?}"),
    };
    println!(
        "RETARGET|{name}|{},{}|{result}",
        target_hex(previous_target),
        elapsed_secs
    );
}

fn emit_tip(name: &str, left: ChainTip, right: ChainTip) {
    let ordering = compare_chain_tips(left, right);
    println!(
        "TIP|{name}|{},{},{},{},{},{}|{ordering:?}",
        target_hex(left.cumulative_work),
        left.height,
        hex(&left.tip_hash),
        target_hex(right.cumulative_work),
        right.height,
        hex(&right.tip_hash)
    );
}

fn tip(work: u8, height: u64, hash_byte: u8) -> ChainTip {
    let mut tip_hash = [hash_byte; 32];
    // A deterministic, explicit 32-byte hash fixture; no cryptographic derivation is implied.
    tip_hash[31] = hash_byte;
    ChainTip {
        height,
        cumulative_work: target_with_last_byte(work),
        tip_hash,
    }
}

fn main() {
    let params = ConsensusParameters::candidate_testnet().expect("candidate profile");
    let expected = params.target_block_time_secs * params.difficulty_window_blocks;
    println!(
        "PARAM|target_block_time_secs|{}",
        params.target_block_time_secs
    );
    println!(
        "PARAM|difficulty_window_blocks|{}",
        params.difficulty_window_blocks
    );
    println!(
        "PARAM|min_ratio_divisor|{}",
        params.difficulty_min_ratio_divisor
    );
    println!("PARAM|max_ratio|{}", params.difficulty_max_ratio);
    println!("PARAM|pow_limit|{}", target_hex(params.pow_limit));
    println!("PARAM|initial_target|{}", target_hex(params.initial_target));

    let one = target_with_last_byte(1);
    let three = target_with_last_byte(3);
    let hundred = target_with_last_byte(100);
    let zero = Uint256::ZERO;
    let max = Uint256::MAX;
    let mut max_minus_one_bytes = [0xffu8; 32];
    max_minus_one_bytes[31] = 0xfe;
    let max_minus_one = Uint256::from_be_bytes(max_minus_one_bytes);
    let mut two_to_255_minus_one_bytes = [0xffu8; 32];
    two_to_255_minus_one_bytes[0] = 0x7f;
    let two_to_255_minus_one = Uint256::from_be_bytes(two_to_255_minus_one_bytes);

    emit_work("zero_reject", zero);
    emit_work("target_one", one);
    emit_work("target_three", three);
    emit_work("target_hundred", hundred);
    emit_work("target_2pow255_minus1", two_to_255_minus_one);
    emit_work("max_minus_one", max_minus_one);
    emit_work("max_target", max);
    emit_work("initial_target", params.initial_target);

    emit_cumulative("mixed", &[one, three, hundred]);
    emit_cumulative("saturating_overflow", &[one, one]);
    emit_cumulative("max_targets", &[max, max]);
    emit_cumulative("zero_reject", &[zero, one]);

    emit_retarget("elapsed_zero_clamps_min", params.initial_target, 0, &params);
    emit_retarget("at_minimum", params.initial_target, expected / 4, &params);
    emit_retarget(
        "half_expected",
        params.initial_target,
        expected / 2,
        &params,
    );
    emit_retarget("nominal", params.initial_target, expected, &params);
    emit_retarget("at_maximum", params.initial_target, expected * 4, &params);
    emit_retarget(
        "beyond_max_clamps",
        params.initial_target,
        expected * 20,
        &params,
    );
    emit_retarget("zero_previous_reject", zero, expected, &params);
    let mut overflow_params = params.clone();
    overflow_params.target_block_time_secs = u64::MAX;
    emit_retarget(
        "expected_window_overflow",
        params.initial_target,
        1,
        &overflow_params,
    );

    let left = tip(20, 10, 1);
    let right = tip(20, 10, 2);
    emit_tip("higher_work_left", tip(21, 10, 3), right);
    emit_tip("lower_work_left", right, tip(21, 10, 3));
    emit_tip("higher_height_left", tip(20, 11, 3), right);
    emit_tip("lower_height_left", right, tip(20, 11, 3));
    emit_tip("smaller_hash_wins", left, right);
    emit_tip("larger_hash_loses", right, left);
    emit_tip("exact_equal", left, left);

    // Keep an explicit source-level witness that ordering strings are canonical names.
    let _: Ordering = compare_chain_tips(left, right);
}
