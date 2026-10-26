//! Local-only helper for signing a single CP-0414 integration-test transaction.
//!
//! The 32-byte seed file is temporary test material, never a production wallet format.
//! The caller owns key custody and must delete the file after use.
use ai_native_l1_pow_bench::{
    state_machine::{transaction_id, transaction_signing_digest, Transaction},
    transaction_auth::Ed25519TransactionSigner,
};
use std::{collections::BTreeMap, env, fs, path::PathBuf, process};

struct Seed([u8; 32]);
impl Drop for Seed {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

fn parse_hex32(value: &str, name: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.is_ascii() {
        return Err(format!("{name} must be exactly 64 ASCII hex characters"));
    }
    let mut bytes = [0u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| format!("{name} contains a non-hex character"))?;
    }
    Ok(bytes)
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

fn parse_args() -> Result<Option<BTreeMap<String, String>>, String> {
    let tokens = env::args().skip(1).collect::<Vec<_>>();
    if tokens
        .iter()
        .any(|token| token == "--help" || token == "-h")
    {
        return Ok(None);
    }
    let mut values = BTreeMap::new();
    let mut i = 0usize;
    while i < tokens.len() {
        let key = tokens[i].as_str();
        if !matches!(
            key,
            "--seed-file"
                | "--network-id-hex"
                | "--recipient-id-hex"
                | "--nonce"
                | "--amount-atoms"
                | "--fee-atoms"
                | "--expires-at"
        ) {
            return Err(format!("unknown option: {key}"));
        }
        let value = tokens
            .get(i + 1)
            .ok_or_else(|| format!("missing value for {key}"))?;
        if value.starts_with("--") {
            return Err(format!("missing value for {key}"));
        }
        if values.insert(key.to_string(), value.clone()).is_some() {
            return Err(format!("duplicate option: {key}"));
        }
        i += 2;
    }
    for key in [
        "--seed-file",
        "--network-id-hex",
        "--recipient-id-hex",
        "--nonce",
        "--amount-atoms",
        "--fee-atoms",
        "--expires-at",
    ] {
        if !values.contains_key(key) {
            return Err(format!("required option missing: {key}"));
        }
    }
    Ok(Some(values))
}

fn run(values: BTreeMap<String, String>) -> Result<(), String> {
    let seed_path = PathBuf::from(&values["--seed-file"]);
    let metadata = fs::symlink_metadata(&seed_path)
        .map_err(|error| format!("inspect temporary transaction seed file: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() != 32 {
        return Err(
            "temporary transaction seed must be a regular non-symlink file of exactly 32 bytes"
                .into(),
        );
    }
    let mut raw = fs::read(&seed_path).map_err(|error| format!("read temporary seed: {error}"))?;
    if raw.len() != 32 {
        raw.fill(0);
        return Err("temporary transaction seed must be exactly 32 bytes".into());
    }
    let mut seed_bytes = [0u8; 32];
    seed_bytes.copy_from_slice(&raw);
    raw.fill(0);
    let seed = Seed(seed_bytes);
    let signer = Ed25519TransactionSigner::from_seed(seed.0);
    let network_id = parse_hex32(&values["--network-id-hex"], "--network-id-hex")?;
    let recipient = parse_hex32(&values["--recipient-id-hex"], "--recipient-id-hex")?;
    if network_id.iter().all(|byte| *byte == 0)
        || recipient.iter().all(|byte| *byte == 0)
        || recipient == signer.account_id()
    {
        return Err(
            "network and recipient must be nonzero and recipient must differ from signer account"
                .into(),
        );
    }
    let nonce = values["--nonce"]
        .parse::<u64>()
        .map_err(|_| "nonce must be u64".to_string())?;
    let amount = values["--amount-atoms"]
        .parse::<u64>()
        .map_err(|_| "amount must be u64".to_string())?;
    let fee = values["--fee-atoms"]
        .parse::<u64>()
        .map_err(|_| "fee must be u64".to_string())?;
    let expires_at = values["--expires-at"]
        .parse::<u64>()
        .map_err(|_| "expiry must be u64".to_string())?;
    if nonce == 0 || amount == 0 || expires_at <= 2 {
        return Err(
            "nonce/amount must be positive and expiry must exceed the test block timestamps".into(),
        );
    }
    let mut tx = Transaction {
        network_id,
        sender: signer.account_id(),
        recipient,
        nonce,
        amount,
        fee,
        expires_at,
        signature: Vec::new(),
    };
    signer
        .sign_transaction(&mut tx)
        .map_err(|error| format!("sign test transaction: {error:?}"))?;
    let digest = transaction_signing_digest(&tx)
        .map_err(|error| format!("derive test transaction digest: {error:?}"))?;
    let txid =
        transaction_id(&tx).map_err(|error| format!("derive test transaction ID: {error:?}"))?;
    println!("tx_network_id_hex={}", hex(&tx.network_id));
    println!("tx_public_key_hex={}", hex(&signer.public_key()));
    println!("tx_sender_account_id_hex={}", hex(&signer.account_id()));
    println!("tx_recipient_id_hex={}", hex(&tx.recipient));
    println!("tx_nonce={}", tx.nonce);
    println!("tx_amount_atoms={}", tx.amount);
    println!("tx_fee_atoms={}", tx.fee);
    println!("tx_expires_at={}", tx.expires_at);
    println!("tx_signing_digest_hex={}", hex(&digest));
    println!("tx_id_hex={}", hex(&txid));
    println!("tx_signature_hex={}", hex(&tx.signature));
    Ok(())
}

fn main() {
    match parse_args() {
        Ok(None) => println!("Usage: qzbe_v04_test_tx_signer --seed-file ABS_PATH --network-id-hex HEX64 --recipient-id-hex HEX64 --nonce U64 --amount-atoms U64 --fee-atoms U64 --expires-at U64"),
        Ok(Some(values)) => if let Err(error) = run(values) { eprintln!("QZBE local test signing failed: {error}"); process::exit(1); },
        Err(error) => { eprintln!("{error}"); process::exit(2); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ai_native_l1_pow_bench::state_machine::TransactionAuthenticator;
    use ai_native_l1_pow_bench::transaction_auth::{
        AccountPublicKey, Ed25519TransactionAuthenticator, TransactionAuthenticatorKind,
    };

    #[test]
    fn test_signer_emits_a_signature_accepted_by_an_explicit_public_key_registry() {
        let signer = Ed25519TransactionSigner::from_seed([0x42; 32]);
        let mut tx = Transaction {
            network_id: [0x31; 32],
            sender: signer.account_id(),
            recipient: [0x44; 32],
            nonce: 1,
            amount: 2500,
            fee: 7,
            expires_at: 100,
            signature: Vec::new(),
        };
        signer.sign_transaction(&mut tx).unwrap();
        let auth = Ed25519TransactionAuthenticator::select_by_id(
            TransactionAuthenticatorKind::Ed25519V1 as u16,
            [AccountPublicKey {
                account_id: signer.account_id(),
                public_key: signer.public_key(),
            }],
        )
        .unwrap();
        let digest = transaction_signing_digest(&tx).unwrap();
        assert_eq!(auth.verify(&tx.sender, &digest, &tx.signature), Ok(()));
        let mut tampered = tx.signature.clone();
        tampered[0] ^= 1;
        assert_eq!(auth.verify(&tx.sender, &digest, &tampered), Err(()));
    }
}
