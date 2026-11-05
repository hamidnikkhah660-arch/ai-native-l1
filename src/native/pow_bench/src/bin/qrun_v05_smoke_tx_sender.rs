//! Sends one already-built QZTS/1 request to a loopback QRun node and verifies QZTA/1.
use std::{
    env, fs,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    path::PathBuf,
    time::Duration,
};

const ACK_BYTES: usize = 43;

fn parse_hex32(value: &str, name: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.is_ascii() {
        return Err(format!("{name} must be exactly 64 hexadecimal characters"));
    }
    let mut bytes = [0u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| format!("{name} contains a non-hexadecimal character"))?;
    }
    Ok(bytes)
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

fn run() -> Result<(), String> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() == 1 && args[0] == "--help" {
        println!("Usage: qrun_v05_smoke_tx_sender --address IP:PORT --request-file ABSOLUTE_QZTS_FILE --expected-txid-hex HEX64");
        return Ok(());
    }
    if args.len() != 6
        || args[0] != "--address"
        || args[2] != "--request-file"
        || args[4] != "--expected-txid-hex"
    {
        return Err(
            "usage: --address IP:PORT --request-file ABSOLUTE_QZTS_FILE --expected-txid-hex HEX64"
                .into(),
        );
    }

    let address: SocketAddr = args[1]
        .parse()
        .map_err(|_| "--address must be a numeric IP:PORT socket".to_string())?;
    if !address.ip().is_loopback() {
        return Err("smoke TXN2 sender is restricted to loopback".into());
    }
    let request_path = PathBuf::from(&args[3]);
    if !request_path.is_absolute() || request_path.file_name().is_none() {
        return Err("--request-file must be an absolute file path".into());
    }
    let expected_txid = parse_hex32(&args[5], "expected transaction ID")?;
    let request =
        fs::read(&request_path).map_err(|error| format!("read signed QZTS/1 request: {error}"))?;
    if request.len() < 147 || &request[..4] != b"QZTS" {
        return Err("request file is not a bounded QZTS/1 frame".into());
    }
    let declared = u32::from_be_bytes(request[6..10].try_into().unwrap()) as usize;
    if u16::from_be_bytes(request[4..6].try_into().unwrap()) != 1
        || declared == 0
        || request.len() != 10usize.saturating_add(declared)
    {
        return Err("QZTS/1 frame version/length is invalid".into());
    }

    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(5))
        .map_err(|error| format!("connect QRun TX listener {address}: {error}"))?;
    stream
        // Public Alpha performs full 64 MiB Argon2id PoW synchronously before its QZTA ACK.
        // At the measured ~1.18 H/s on the Windows smoke host, the expected wait is ~282s.
        // Keep the consensus attempt budget unchanged; bound the harness wait at 30 minutes.
        .set_read_timeout(Some(Duration::from_secs(1_800)))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .map_err(|error| error.to_string())?;
    stream
        .write_all(&request)
        .map_err(|error| format!("write complete QZTS/1 request: {error}"))?;
    stream
        .flush()
        .map_err(|error| format!("flush QZTS/1 request: {error}"))?;

    let mut ack = [0u8; ACK_BYTES];
    stream
        .read_exact(&mut ack)
        .map_err(|error| format!("read complete QZTA/1 ACK: {error}"))?;
    if &ack[..4] != b"QZTA" || u16::from_be_bytes([ack[4], ack[5]]) != 1 {
        return Err("node returned an invalid QZTA/1 magic or version".into());
    }
    let status = ack[6];
    let mut transaction_id = [0u8; 32];
    transaction_id.copy_from_slice(&ack[11..43]);
    if transaction_id != expected_txid {
        return Err(format!(
            "ACK transaction ID mismatch: got {}, expected {}",
            hex(&transaction_id),
            hex(&expected_txid)
        ));
    }
    if status != 0 {
        return Err(format!(
            "node did not accept TXN2: QZTA status={status}, txid={}",
            hex(&transaction_id)
        ));
    }

    println!("qzts_request_transmitted_bytes={}", request.len());
    println!("qzta_ack_status=accepted");
    println!("qzta_transaction_id_hex={}", hex(&transaction_id));
    println!("qzts_tcp_sender=PASS");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!(
            "QRUN_SMOKE_TX_SENDER_ERROR: {}",
            error.replace(['\r', '\n'], "_")
        );
        std::process::exit(2);
    }
}
