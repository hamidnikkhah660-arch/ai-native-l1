//! Creates a disposable Ed25519-signed QZTS/1 request for loopback two-node smoke tests.
use ai_native_l1_pow_bench::{
    qzbe_tx_ingress_candidate::encode_request,
    state_machine::{encode_transaction, transaction_id, NetworkId, Transaction},
    transaction_auth::{account_id_from_public_key, Ed25519TransactionSigner},
};
use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
};

fn parse_hex32(value: &str, name: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.is_ascii() {
        return Err(format!("{name} must be exactly 64 hexadecimal characters"));
    }
    let mut bytes = [0u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| format!("{name} contains a non-hexadecimal character"))?;
    }
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(format!("{name} must be nonzero"));
    }
    Ok(bytes)
}

fn parse_u64(value: &str, name: &str) -> Result<u64, String> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| format!("{name} must be an unsigned integer"))?;
    if parsed == 0 {
        return Err(format!("{name} must be nonzero"));
    }
    Ok(parsed)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

fn write_request_file(path: &Path, request: &[u8]) -> Result<(), String> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("create QZTS request {}: {error}", path.display()))?;
    if let Err(error) = file
        .write_all(request)
        .and_then(|_| file.flush())
        .and_then(|_| file.sync_all())
    {
        let _ = fs::remove_file(path);
        return Err(format!("persist QZTS request {}: {error}", path.display()));
    }
    Ok(())
}

fn run() -> Result<(), String> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() == 1 && args[0] == "--help" {
        println!("Usage: qrun_v05_smoke_tx_builder --network-id-hex HEX64 --expires-at-unix-secs UNIX --output ABSOLUTE_FILE [--second-output ABSOLUTE_FILE]");
        return Ok(());
    }
    if (args.len() != 6 && args.len() != 8)
        || args[0] != "--network-id-hex"
        || args[2] != "--expires-at-unix-secs"
        || args[4] != "--output"
        || (args.len() == 8 && args[6] != "--second-output")
    {
        return Err(
            "usage: --network-id-hex HEX64 --expires-at-unix-secs UNIX --output ABSOLUTE_FILE [--second-output ABSOLUTE_FILE]"
                .into(),
        );
    }
    let network_id: NetworkId = parse_hex32(&args[1], "Network ID")?;
    let expires_at = parse_u64(&args[3], "expiry")?;
    let output = PathBuf::from(&args[5]);
    let second_output = (args.len() == 8).then(|| PathBuf::from(&args[7]));
    if !output.is_absolute() || output.file_name().is_none() {
        return Err("--output must be an absolute file path".into());
    }
    if let Some(path) = second_output.as_ref() {
        if !path.is_absolute() || path.file_name().is_none() || path == &output {
            return Err("--second-output must be a distinct absolute file path".into());
        }
        if fs::symlink_metadata(path).is_ok() {
            return Err("refusing to overwrite an existing second transaction request".into());
        }
        if path.parent() != output.parent() {
            return Err("--output and --second-output must use the same existing directory".into());
        }
    }
    let parent = output
        .parent()
        .ok_or_else(|| "--output must have a parent directory".to_string())?;
    if !fs::metadata(parent)
        .map_err(|error| format!("inspect output directory: {error}"))?
        .is_dir()
    {
        return Err("--output parent must be a directory".into());
    }
    if fs::symlink_metadata(&output).is_ok() {
        return Err("refusing to overwrite an existing transaction request".into());
    }

    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|error| format!("OS CSPRNG failed: {error}"))?;
    let signer = Ed25519TransactionSigner::from_seed(seed);
    seed.fill(0);
    let public_key = signer.public_key();
    let sender = account_id_from_public_key(&public_key);
    let recipient = [0xD7; 32];
    if recipient == sender {
        return Err("ephemeral recipient collided with sender account".into());
    }

    let mut transaction = Transaction {
        network_id,
        sender,
        recipient,
        nonce: 1,
        amount: 100_000_000,
        fee: 1_000,
        expires_at,
        signature: Vec::new(),
    };
    signer
        .sign_transaction(&mut transaction)
        .map_err(|error| format!("sign ephemeral TXN2: {error:?}"))?;
    let txid = transaction_id(&transaction).map_err(|error| format!("TXN2 ID: {error:?}"))?;
    let tx_wire =
        encode_transaction(&transaction).map_err(|error| format!("encode TXN2: {error:?}"))?;
    let request = encode_request(&tx_wire).map_err(|error| format!("encode QZTS/1: {error:?}"))?;

    write_request_file(&output, &request)?;

    println!("smoke_owner_account_id_hex={}", hex(&sender));
    println!("smoke_owner_public_key_hex={}", hex(&public_key));
    println!("smoke_transaction_id_hex={}", hex(&txid));
    println!("smoke_transaction_id_nonce1_hex={}", hex(&txid));
    println!("smoke_transaction_amount_atoms={}", transaction.amount);
    println!("smoke_transaction_fee_atoms={}", transaction.fee);
    println!("smoke_transaction_nonce={}", transaction.nonce);
    println!("smoke_transaction_expiry_unix={}", transaction.expires_at);
    println!("qzts_request_bytes={}", request.len());
    println!("request_file={}", output.display());

    if let Some(second_path) = second_output {
        let mut second = Transaction {
            network_id,
            sender,
            recipient,
            nonce: 2,
            amount: 200_000_000,
            fee: 1_000,
            expires_at,
            signature: Vec::new(),
        };
        signer
            .sign_transaction(&mut second)
            .map_err(|error| format!("sign second ephemeral TXN2: {error:?}"))?;
        let second_txid =
            transaction_id(&second).map_err(|error| format!("second TXN2 ID: {error:?}"))?;
        let second_wire = encode_transaction(&second)
            .map_err(|error| format!("encode second TXN2: {error:?}"))?;
        let second_request = encode_request(&second_wire)
            .map_err(|error| format!("encode second QZTS/1: {error:?}"))?;
        if let Err(error) = write_request_file(&second_path, &second_request) {
            let _ = fs::remove_file(&output);
            return Err(error);
        }
        println!("smoke_transaction_id_nonce2_hex={}", hex(&second_txid));
        println!("smoke_transaction_amount_nonce2_atoms={}", second.amount);
        println!("smoke_transaction_nonce2={}", second.nonce);
        println!("qzts_request_nonce2_bytes={}", second_request.len());
        println!("second_request_file={}", second_path.display());
    }
    println!("private_seed_exported=false");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!(
            "QRUN_SMOKE_TX_BUILDER_ERROR: {}",
            error.replace(['\r', '\n'], "_")
        );
        std::process::exit(2);
    }
}
