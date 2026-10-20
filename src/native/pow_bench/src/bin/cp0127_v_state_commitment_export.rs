use ai_native_l1_pow_bench::{
    private_testnet_wire::decode_candidate_network_block, state_machine::block_id,
};
use std::{env, fs, path::Path};

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn main() {
    let mut found = false;
    for argument in env::args_os().skip(1) {
        found = true;
        let path = Path::new(&argument);
        let bytes = fs::read(path).unwrap_or_else(|error| {
            eprintln!("CP0127_EXPORT_FAIL read {}: {error}", path.display());
            std::process::exit(2);
        });
        let candidate = decode_candidate_network_block(&bytes).unwrap_or_else(|error| {
            eprintln!("CP0127_EXPORT_FAIL decode {}: {error}", path.display());
            std::process::exit(3);
        });
        let id = block_id(&candidate.block).unwrap_or_else(|error| {
            eprintln!("CP0127_EXPORT_FAIL block_id {}: {error:?}", path.display());
            std::process::exit(4);
        });
        println!(
            "BLOCKID|{}|{}|{}",
            path.file_name().unwrap_or_default().to_string_lossy(),
            candidate.header.height,
            hex(&id)
        );
    }
    if !found {
        eprintln!("usage: cp0127_v_state_commitment_export <one-or-more PTB2 paths>");
        std::process::exit(1);
    }
}
