use ai_native_l1_pow_bench::{
    qrun_v06_history_sync_wire_candidate::{decode_q6hr_status, QRunV06HistoryInfoRequest},
    qrun_v06_noise_transport_candidate::QRunV06NoiseSession,
};
use rustls::{pki_types::ServerName, ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use sha2::Digest;
use std::{
    env,
    net::{TcpStream, ToSocketAddrs},
    sync::Arc,
    time::Duration,
};

fn value(args: &[String], name: &str) -> Result<String, String> {
    let mut found = None;
    let mut i = 0usize;
    while i < args.len() {
        if args[i] == name {
            if found.is_some() || i + 1 >= args.len() || args[i + 1].starts_with("--") {
                return Err(format!("{name} must be supplied exactly once with a value"));
            }
            found = Some(args[i + 1].clone());
            i += 2;
        } else {
            i += 1;
        }
    }
    found.ok_or_else(|| format!("missing required argument {name}"))
}

fn parse_hex32(name: &str, value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "{name} must contain exactly 64 hexadecimal characters"
        ));
    }
    let mut out = [0u8; 32];
    for (i, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(pair).map_err(|_| format!("{name} is not ASCII"))?;
        out[i] = u8::from_str_radix(pair, 16).map_err(|_| format!("{name} is malformed"))?;
    }
    Ok(out)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let host = value(&args, "--host")?;
    let port = value(&args, "--port")?
        .parse::<u16>()
        .map_err(|_| "port is invalid")?;
    let network_id = parse_hex32("network ID", &value(&args, "--network-id-hex")?)?;
    let profile_id = parse_hex32("profile ID", &value(&args, "--profile-id-hex")?)?;
    let remote_key = parse_hex32(
        "remote Noise public key",
        &value(&args, "--remote-noise-key-hex")?,
    )?;
    if port != 443 {
        return Err("this QFP6 TLS relay probe only accepts TCP port 443".into());
    }

    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls_config = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let address = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|e| format!("DNS resolution failed: {e}"))?
        .next()
        .ok_or("DNS returned no addresses")?;
    let mut tcp = TcpStream::connect_timeout(&address, Duration::from_secs(10))
        .map_err(|e| format!("TCP connect failed: {e}"))?;
    tcp.set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| e.to_string())?;
    tcp.set_write_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| e.to_string())?;
    tcp.set_nodelay(true).map_err(|e| e.to_string())?;

    let server_name =
        ServerName::try_from(host.clone()).map_err(|e| format!("TLS SNI invalid: {e}"))?;
    let mut tls = ClientConnection::new(tls_config, server_name)
        .map_err(|e| format!("TLS client setup failed: {e}"))?;
    while tls.is_handshaking() {
        tls.complete_io(&mut tcp)
            .map_err(|e| format!("TLS handshake failed: {e}"))?;
    }
    println!("PUBLIC_FUNNEL_TLS_SNI=PASS");

    let params = "Noise_XX_25519_ChaChaPoly_SHA256"
        .parse()
        .map_err(|e: snow::Error| format!("Noise params rejected: {e}"))?;
    let ephemeral = snow::Builder::new(params)
        .generate_keypair()
        .map_err(|e| format!("ephemeral Noise key generation failed: {e}"))?;
    let local_private: [u8; 32] = ephemeral
        .private
        .as_slice()
        .try_into()
        .map_err(|_| "ephemeral Noise private key has unexpected length")?;
    let mut stream = StreamOwned::new(tls, tcp);
    let mut noise = QRunV06NoiseSession::connect(
        &mut stream,
        &local_private,
        &remote_key,
        &network_id,
        &profile_id,
    )
    .map_err(|e| format!("pinned Noise XX handshake failed: {e}"))?;
    println!("PINNED_NOISE_XX=PASS");
    println!(
        "SERVER_KEY_SHA256={}",
        hex(&sha2::Sha256::digest(remote_key))
    );

    let request = QRunV06HistoryInfoRequest {
        request_id: 1,
        network_id,
        profile_id,
    };
    let request_bytes = request
        .encode()
        .map_err(|e| format!("Q6HI encode failed: {e}"))?;
    noise
        .write_record(&mut stream, &request_bytes)
        .map_err(|e| format!("Q6HI write failed: {e}"))?;
    let response = noise
        .read_record(&mut stream)
        .map_err(|e| format!("Q6HR read failed: {e}"))?;
    let status = decode_q6hr_status(&response, &request)
        .map_err(|e| format!("Q6HR validation failed: {e}"))?;
    println!("Q6HI_Q6HR=PASS");
    println!("SEED_HEIGHT={}", status.height);
    println!("SEED_BASE_HEIGHT={}", status.base_height);
    println!("SEED_CONSENSUS_TIP={}", hex(&status.consensus_tip));
    println!("SEED_EXECUTION_TIP={}", hex(&status.execution_tip));
    println!("CLIENT_NOISE_IDENTITY=EPHEMERAL_NOT_SAVED");
    println!("NODE_STORAGE_WRITES=NONE");
    println!("TEST_SCOPE=SAME_LAPTOP_VIA_PUBLIC_FUNNEL_ENDPOINT");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("QFP6_PUBLIC_SEED_PROBE=FAILED");
        eprintln!("reason={error}");
        std::process::exit(2);
    }
}
