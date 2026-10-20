use ai_native_l1_pow_bench::{
    private_testnet_wire::decode_candidate_network_block,
    state_machine::{encode_transaction, transaction_id, transaction_signing_digest},
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
            eprintln!("CP0128_EXPORT_FAIL read {}: {error}", path.display());
            std::process::exit(2);
        });
        let candidate = decode_candidate_network_block(&bytes).unwrap_or_else(|error| {
            eprintln!("CP0128_EXPORT_FAIL decode {}: {error}", path.display());
            std::process::exit(3);
        });
        if candidate.block.transactions.is_empty() {
            eprintln!("CP0128_EXPORT_FAIL no_transaction {}", path.display());
            std::process::exit(4);
        }
        for (index, tx) in candidate.block.transactions.iter().enumerate() {
            let encoded = encode_transaction(tx).unwrap_or_else(|error| {
                eprintln!("CP0128_EXPORT_FAIL encode_tx {}: {error:?}", path.display());
                std::process::exit(5);
            });
            let signing_digest = transaction_signing_digest(tx).unwrap_or_else(|error| {
                eprintln!(
                    "CP0128_EXPORT_FAIL signing_digest {}: {error:?}",
                    path.display()
                );
                std::process::exit(6);
            });
            let txid = transaction_id(tx).unwrap_or_else(|error| {
                eprintln!("CP0128_EXPORT_FAIL txid {}: {error:?}", path.display());
                std::process::exit(7);
            });
            println!(
                "TX|{}|{}|{}|{}|{}|{}|{}",
                path.file_name().unwrap_or_default().to_string_lossy(),
                candidate.header.height,
                index,
                hex(&encoded),
                hex(&signing_digest),
                hex(&txid),
                tx.signature.len()
            );
        }
    }
    if !found {
        eprintln!("usage: cp0128_x_transaction_export <one-or-more PTB2 paths>");
        std::process::exit(1);
    }
}
