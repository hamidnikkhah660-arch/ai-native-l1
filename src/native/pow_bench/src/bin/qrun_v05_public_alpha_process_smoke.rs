//! Disposable, process-level Public Alpha smoke helper.
//!
//! The deterministic signer is TEST-ONLY and is used only with a freshly generated
//! temporary Network ID and data directories. Never use this key or binary on Mainnet.
use ai_native_l1_pow_bench::qzbe_tx_ingress_candidate::{
    decode_ack, encode_request, TxIngressStatus, ACK_BYTES,
};
use ai_native_l1_pow_bench::state_machine::{
    encode_transaction, transaction_id, NetworkId, Transaction,
};
use ai_native_l1_pow_bench::transaction_auth::Ed25519TransactionSigner;
use std::{
    env,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const TEST_ONLY_SEED: [u8; 32] = [0xA6; 32];

fn signer() -> Ed25519TransactionSigner {
    Ed25519TransactionSigner::from_seed(TEST_ONLY_SEED)
}

fn parse_network(value: &str) -> Result<NetworkId, String> {
    if value.len() != 64 || !value.is_ascii() {
        return Err("--network-id-hex must contain exactly 64 hex characters".into());
    }
    let mut network = [0u8; 32];
    for (index, byte) in network.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| "--network-id-hex contains a non-hex character".to_string())?;
    }
    if network.iter().all(|byte| *byte == 0) {
        return Err("--network-id-hex must be nonzero".into());
    }
    Ok(network)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(DIGITS[(byte >> 4) as usize] as char);
        result.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    result
}

fn now_unix() -> Result<u64, String> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock before Unix epoch: {error}"))?
        .as_secs())
}

fn submit_variant(
    network_id: NetworkId,
    address: SocketAddr,
    nonce: u64,
    recipient_byte: u8,
    amount: u64,
) -> Result<(), String> {
    if !address.ip().is_loopback() {
        return Err("process smoke transaction sender is restricted to loopback".into());
    }
    let signer = signer();
    let timestamp = now_unix()?;
    let mut transaction = Transaction {
        network_id,
        sender: signer.account_id(),
        recipient: [recipient_byte; 32],
        nonce,
        amount,
        fee: 1,
        expires_at: timestamp.saturating_add(3_600),
        signature: Vec::new(),
    };
    signer
        .sign_transaction(&mut transaction)
        .map_err(|error| format!("sign disposable smoke transaction: {error:?}"))?;
    let txid = transaction_id(&transaction)
        .map_err(|error| format!("calculate transaction ID: {error:?}"))?;
    let payload = encode_transaction(&transaction)
        .map_err(|error| format!("encode TXN2 transaction: {error:?}"))?;
    let request =
        encode_request(&payload).map_err(|error| format!("encode QZTS/1 request: {error:?}"))?;
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(5))
        .map_err(|error| format!("connect to QZTS listener {address}: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(900)))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|error| error.to_string())?;
    stream
        .write_all(&request)
        .map_err(|error| format!("send QZTS/1 request: {error}"))?;
    let mut ack_bytes = [0u8; ACK_BYTES];
    stream
        .read_exact(&mut ack_bytes)
        .map_err(|error| format!("read QZTA/1 acknowledgement: {error}"))?;
    let ack = decode_ack(&ack_bytes)
        .map_err(|error| format!("decode QZTA/1 acknowledgement: {error:?}"))?;
    if ack.transaction_id != txid {
        return Err("QZTA/1 returned a different transaction ID".into());
    }
    println!("transaction_id={}", hex(&txid));
    println!("qzts_status={:?}", ack.status);
    println!("qzts_mempool_count={}", ack.mempool_count);
    println!("transaction_nonce={nonce}");
    println!("transaction_recipient_byte={recipient_byte}");
    if ack.status != TxIngressStatus::Accepted {
        return Err(format!(
            "node did not accept disposable smoke transaction: {:?}",
            ack.status
        ));
    }
    Ok(())
}

fn run() -> Result<(), String> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let Some(mode) = args.first().map(String::as_str) else {
        return Err("usage: identity | submit|submit-conflict|submit-next|submit-third|submit-third-conflict|submit-fourth|submit-fifth --network-id-hex HEX64 --address IP:PORT".into());
    };

    match mode {
        "identity" if args.len() == 1 => {
            let signer = signer();
            println!("owner_account_id_hex={}", hex(&signer.account_id()));
            println!("owner_public_key_hex={}", hex(&signer.public_key()));
            println!("signer_seed_output=never");
            Ok(())
        }
        "submit" | "submit-conflict" | "submit-next" | "submit-third" | "submit-third-conflict" | "submit-fourth" | "submit-fifth"
            if args.len() == 5 && args[1] == "--network-id-hex" && args[3] == "--address" =>
        {
            let network_id = parse_network(&args[2])?;
            let address: SocketAddr = args[4]
                .parse()
                .map_err(|error| format!("invalid --address: {error}"))?;
            let (nonce, recipient, amount) = match mode {
                "submit" => (1, 0x78, 1_000),
                "submit-conflict" => (1, 0x79, 2_000),
                "submit-next" => (2, 0x7A, 3_000),
                "submit-third" => (3, 0x7B, 4_000),
                "submit-third-conflict" => (3, 0x79, 2_500),
                "submit-fourth" => (4, 0x7C, 5_000),
                "submit-fifth" => (5, 0x7D, 6_000),
                _ => unreachable!(),
            };
            submit_variant(network_id, address, nonce, recipient, amount)
        }
        _ => Err("usage: identity | submit|submit-conflict|submit-next|submit-third|submit-third-conflict|submit-fourth|submit-fifth --network-id-hex HEX64 --address IP:PORT".into()),
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!(
            "QRUN_PUBLIC_ALPHA_PROCESS_SMOKE_ERROR: {}",
            error.replace(['\r', '\n'], "_")
        );
        std::process::exit(2);
    }
}
