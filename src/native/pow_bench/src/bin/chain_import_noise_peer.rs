use ai_native_l1_pow_bench::{decode_frame, encode_frame, MessageType, PROTOCOL_VERSION};
use sha2::{Digest, Sha256};
use snow::Builder;
use std::{
    env,
    io::{self, Read, Write},
    net::TcpStream,
    time::{Duration, Instant},
};

const PATTERN: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
const PROLOGUE: &[u8] = b"AI-NATIVE-L1/chain-import-noise-xx-v1";
const MAX_HANDSHAKE: usize = 1024;
const MAX_RECORD: usize = 4 * 1024 * 1024 + 1024;
const PUBLIC_KEY: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];
const NETWORK_ID: [u8; 32] = [0xb6; 32];
const GENESIS_BALANCE: u64 = 1_000_000;

fn arg(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
}

fn hex32(value: &str, name: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 {
        return Err(format!(
            "{name} must contain exactly 64 hexadecimal characters"
        ));
    }
    let mut output = [0u8; 32];
    for index in 0..32 {
        output[index] = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| format!("{name} is not valid hexadecimal"))?;
    }
    Ok(output)
}

fn read_exact_until(
    stream: &mut TcpStream,
    output: &mut [u8],
    deadline: Instant,
) -> io::Result<()> {
    let mut offset = 0;
    while offset < output.len() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Noise peer deadline",
            ));
        }
        stream.set_read_timeout(Some(remaining.min(Duration::from_millis(100))))?;
        match stream.read(&mut output[offset..]) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "peer closed")),
            Ok(count) => offset += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error)
                if error.kind() == io::ErrorKind::TimedOut
                    || error.kind() == io::ErrorKind::WouldBlock =>
            {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "Noise peer deadline",
                    ));
                }
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn write_all_until(stream: &mut TcpStream, bytes: &[u8], deadline: Instant) -> io::Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Noise peer deadline",
            ));
        }
        stream.set_write_timeout(Some(remaining.min(Duration::from_millis(100))))?;
        match stream.write(&bytes[offset..]) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "peer closed")),
            Ok(count) => offset += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error)
                if error.kind() == io::ErrorKind::TimedOut
                    || error.kind() == io::ErrorKind::WouldBlock =>
            {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "Noise peer deadline",
                    ));
                }
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn write_handshake(
    stream: &mut TcpStream,
    message: &[u8],
    deadline: Instant,
) -> Result<(), String> {
    if message.is_empty() || message.len() > MAX_HANDSHAKE || message.len() > u16::MAX as usize {
        return Err(format!(
            "Noise handshake message length invalid: {}",
            message.len()
        ));
    }
    write_all_until(stream, &(message.len() as u16).to_be_bytes(), deadline)
        .and_then(|_| write_all_until(stream, message, deadline))
        .map_err(|error| format!("Noise handshake write failed: {error}"))
}

fn read_handshake(stream: &mut TcpStream, deadline: Instant) -> Result<Vec<u8>, String> {
    let mut header = [0u8; 2];
    read_exact_until(stream, &mut header, deadline)
        .map_err(|error| format!("Noise handshake length read failed: {error}"))?;
    let length = u16::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_HANDSHAKE {
        return Err(format!("Noise handshake length invalid: {length}"));
    }
    let mut message = vec![0u8; length];
    read_exact_until(stream, &mut message, deadline)
        .map_err(|error| format!("Noise handshake read failed: {error}"))?;
    Ok(message)
}

fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn empty_block(height: u64, timestamp: u64) -> Vec<u8> {
    let account_id = hash_parts(b"AIN1-ACCOUNT-ID-ED25519-V1\0", &[&PUBLIC_KEY]);
    let mut canonical = Vec::new();
    canonical.extend_from_slice(b"AIN1-STATE-V2\0");
    canonical.extend_from_slice(&NETWORK_ID);
    canonical.extend_from_slice(&height.to_be_bytes());
    canonical.extend_from_slice(&timestamp.to_be_bytes());
    canonical.extend_from_slice(&0u64.to_be_bytes());
    canonical.extend_from_slice(&1u32.to_be_bytes());
    canonical.extend_from_slice(&account_id);
    canonical.extend_from_slice(&GENESIS_BALANCE.to_be_bytes());
    canonical.extend_from_slice(&0u64.to_be_bytes());
    let state_root = hash_parts(b"AIN1-STATE-ROOT-V2\0", &[&canonical]);

    let mut block = Vec::with_capacity(88);
    block.extend_from_slice(b"BLK2");
    block.extend_from_slice(&2u16.to_be_bytes());
    block.extend_from_slice(&height.to_be_bytes());
    block.extend_from_slice(&timestamp.to_be_bytes());
    block.extend_from_slice(&[0u8; 32]); // genesis parent
    block.extend_from_slice(&state_root);
    block.extend_from_slice(&0u16.to_be_bytes()); // no transactions
    block
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let port = arg(&args, "--port")
        .ok_or("missing --port")?
        .parse::<u16>()
        .map_err(|_| "invalid --port")?;
    let local_private = hex32(
        &arg(&args, "--noise-static-private-key-hex")
            .ok_or("missing --noise-static-private-key-hex")?,
        "--noise-static-private-key-hex",
    )?;
    let expected_server = hex32(
        &arg(&args, "--expected-server-public-key-hex")
            .ok_or("missing --expected-server-public-key-hex")?,
        "--expected-server-public-key-hex",
    )?;
    if local_private.iter().all(|value| *value == 0)
        || expected_server.iter().all(|value| *value == 0)
    {
        return Err("Noise test keys cannot be all zero".into());
    }
    let timestamp = arg(&args, "--timestamp")
        .ok_or("missing --timestamp")?
        .parse::<u64>()
        .map_err(|_| "invalid --timestamp")?;
    let delay_before_request_ms = arg(&args, "--delay-before-request-ms")
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|_| "invalid --delay-before-request-ms")
        })
        .transpose()?
        .unwrap_or(0);
    if delay_before_request_ms > 4_000 {
        return Err("--delay-before-request-ms must not exceed 4000".into());
    }
    let expect_reject = args.iter().any(|value| value == "--expect-reject");

    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .map_err(|error| format!("connect failed: {error}"))?;
    stream
        .set_nodelay(true)
        .map_err(|error| error.to_string())?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let params = PATTERN
        .parse()
        .map_err(|error: snow::Error| format!("Noise XX pattern invalid: {error}"))?;
    let mut handshake = Builder::new(params)
        .prologue(PROLOGUE)
        .local_private_key(&local_private)
        .build_initiator()
        .map_err(|error| format!("Noise XX initiator init failed: {error}"))?;
    let mut buffer = vec![0u8; MAX_HANDSHAKE];

    // XX message 1.
    let length = handshake
        .write_message(&[], &mut buffer)
        .map_err(|error| format!("Noise XX message 1 failed: {error}"))?;
    write_handshake(&mut stream, &buffer[..length], deadline)?;

    // XX message 2 carries the responder's encrypted static key.
    let second = read_handshake(&mut stream, deadline)?;
    let payload_length = handshake
        .read_message(&second, &mut buffer)
        .map_err(|error| format!("Noise XX message 2 rejected: {error}"))?;
    if payload_length != 0 {
        return Err("Noise XX message 2 contained unexpected application data".into());
    }
    let server_static = handshake
        .get_remote_static()
        .ok_or_else(|| "Noise XX responder static key missing".to_string())?;
    if server_static != expected_server {
        if expect_reject {
            println!("CP-N EXPECTED_REJECTION reason=server_static_pin_mismatch");
            return Ok(());
        }
        return Err("server static key does not match the local pin".into());
    }

    // XX message 3 proves possession of this client's static private key.
    let length = handshake
        .write_message(&[], &mut buffer)
        .map_err(|error| format!("Noise XX message 3 failed: {error}"))?;
    write_handshake(&mut stream, &buffer[..length], deadline)?;
    let mut transport = handshake
        .into_transport_mode()
        .map_err(|error| format!("Noise XX transport activation failed: {error}"))?;
    if delay_before_request_ms > 0 {
        println!("CP-O HANDSHAKE_COMPLETE delay_before_request_ms={delay_before_request_ms}");
        std::thread::sleep(Duration::from_millis(delay_before_request_ms));
    }

    let block = empty_block(1, timestamp);
    let frame = encode_frame(PROTOCOL_VERSION, MessageType::Blocks as u16, 1, &block)
        .map_err(|error| format!("AIN1 request encode failed: {error:?}"))?;
    let mut ciphertext = vec![0u8; frame.len() + 128];
    let ciphertext_length = transport
        .write_message(&frame, &mut ciphertext)
        .map_err(|error| format!("Noise request encryption failed: {error}"))?;
    ciphertext.truncate(ciphertext_length);
    let deadline = Instant::now() + Duration::from_secs(5);
    write_all_until(
        &mut stream,
        &(ciphertext.len() as u32).to_be_bytes(),
        deadline,
    )
    .and_then(|_| write_all_until(&mut stream, &ciphertext, deadline))
    .map_err(|error| format!("Noise request write failed: {error}"))?;

    let response = (|| -> Result<String, String> {
        let mut header = [0u8; 4];
        read_exact_until(&mut stream, &mut header, deadline)
            .map_err(|error| format!("Noise receipt length read failed: {error}"))?;
        let length = u32::from_be_bytes(header) as usize;
        if length == 0 || length > 2048 || length > MAX_RECORD {
            return Err(format!("Noise receipt length invalid: {length}"));
        }
        let mut encrypted = vec![0u8; length];
        read_exact_until(&mut stream, &mut encrypted, deadline)
            .map_err(|error| format!("Noise receipt read failed: {error}"))?;
        let mut plaintext = vec![0u8; length];
        let plaintext_length = transport
            .read_message(&encrypted, &mut plaintext)
            .map_err(|error| format!("Noise receipt authentication failed: {error}"))?;
        plaintext.truncate(plaintext_length);
        let receipt = decode_frame(&plaintext)
            .map_err(|error| format!("Noise receipt frame invalid: {error:?}"))?;
        if receipt.version != PROTOCOL_VERSION
            || receipt.message_type != MessageType::BlockImportReceipt as u16
            || receipt.request_id != 1
            || plaintext.len() != ai_native_l1_pow_bench::HEADER_LEN + receipt.payload.len()
        {
            return Err("Noise receipt type/correlation/framing mismatch".into());
        }
        String::from_utf8(receipt.payload)
            .map_err(|_| "Noise receipt payload was not UTF-8".to_string())
    })();

    match response {
        Ok(reply) if expect_reject && reply.starts_with("REJECT ") => {
            println!("CP-O EXPECTED_REJECTION reason={reply}");
            Ok(())
        }
        Ok(reply) if expect_reject => Err(format!(
            "server unexpectedly accepted a rejected request: {reply}"
        )),
        Err(error) if expect_reject => {
            println!("CP-N EXPECTED_REJECTION reason={error}");
            Ok(())
        }
        Ok(reply) if reply.starts_with("ACCEPT height=1 ") => {
            println!("CP-N NOISE_XX IMPORT PASS height=1 receipt={reply}");
            Ok(())
        }
        Ok(reply) => Err(format!("unexpected import receipt: {reply}")),
        Err(error) => Err(error),
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("CP-N NOISE_PEER_ERROR {error}");
        std::process::exit(2);
    }
}
