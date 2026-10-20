use ai_native_l1_pow_bench::consensus::{pow_digest, ConsensusParameters, PowHeader};

fn main() {
    let params = ConsensusParameters::candidate_testnet().expect("candidate params");
    let header = PowHeader {
        protocol_version: 1,
        network_id: [0xA1; 32],
        height: 1,
        timestamp: 100,
        parent_hash: [0xB2; 32],
        previous_consensus_hash: [0xD4; 32],
        state_root: [0xC3; 32],
        target: params.initial_target,
        nonce: 0,
    };
    let digest = pow_digest(&header, params.pow).expect("pow digest");
    println!("digest={}", hex(&digest));
    println!("target={}", hex(&header.target.to_be_bytes()));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
