use ai_native_l1_pow_bench::{
    chain_admission::ReferenceTimeProvider,
    offline_signing_key_store::{
        load_protected_signing_seed, store_protected_signing_seed, SigningKeyRole,
    },
    reference_time::{
        AuthenticatedReferenceTimeProvider, VerifiedReferenceTimePolicy, MAX_LOCAL_CLOCK_SKEW_SECS,
        MAX_REFERENCE_TIME_RTT_MS, POLICY_BODY_LEN, POLICY_DOMAIN, POLICY_MAGIC, POLICY_WIRE_LEN,
        WIRE_VERSION,
    },
    reference_time_authority::ReferenceTimeAuthorityService,
    reference_time_store::ReferenceTimeStateStore,
    reference_time_tcp::TcpReferenceTimeExchange,
};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use getrandom::getrandom;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env,
    fs::{self, File, OpenOptions},
    io::Write,
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

const DEFAULT_LISTEN: &str = "127.0.0.1:49550";
const MAX_AUTHORITY_WORKERS: usize = 32;

fn main() {
    if let Err(error) = run() {
        eprintln!("qrun_reference_time_authority_error={error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let mode = args.next().ok_or_else(usage)?;
    let mut values = BTreeMap::new();
    let remaining = args.collect::<Vec<_>>();
    if remaining.len() % 2 != 0 {
        return Err("every option must have exactly one value".into());
    }
    for pair in remaining.chunks_exact(2) {
        if !pair[0].starts_with("--") {
            return Err(format!("unexpected positional argument: {}", pair[0]));
        }
        if values.insert(pair[0].clone(), pair[1].clone()).is_some() {
            return Err(format!("duplicate option: {}", pair[0]));
        }
    }
    match mode.as_str() {
        "provision-key" => provision_key(&values),
        "create-policy" => create_policy(&values),
        "serve" => serve(&values),
        "probe" => probe(&values),
        _ => Err(usage()),
    }
}

fn usage() -> String {
    [
        "QRun authenticated reference-time authority (RTP1/TMA1)",
        "",
        "Provision a DPAPI-protected key:",
        "  qrun_v05_reference_time_authority provision-key --network-id-hex HEX64 --role reference-time-authority|reference-time-policy-admin --output ABSOLUTE_FILE",
        "",
        "Create an RTP1 policy offline:",
        "  qrun_v05_reference_time_authority create-policy --network-id-hex HEX64 --authority-public-key-hex HEX64 --policy-admin-key-file ABSOLUTE_FILE --policy-admin-public-key-hex HEX64 --sequence N --max-round-trip-ms 500 --max-local-clock-skew-secs none|SECONDS --output ABSOLUTE_FILE",
        "",
        "Run the TCP time authority:",
        "  qrun_v05_reference_time_authority serve --network-id-hex HEX64 --authority-key-file ABSOLUTE_FILE --state-file ABSOLUTE_FILE [--listen IP:PORT] [--allow-non-loopback true]",
        "",
        "Probe an authority using the same authenticated client as QRun:",
        "  qrun_v05_reference_time_authority probe --network-id-hex HEX64 --policy-file RTP1_FILE --policy-admin-public-key-hex HEX64 --address IP:PORT --state-file ABSOLUTE_FILE",
        "",
        "The authority host OS clock is trusted input. This service signs time; it is not BFT clock consensus.",
        "The default listener is loopback-only. Non-loopback binding requires explicit --allow-non-loopback true.",
    ]
    .join("\n")
}

fn parse_hex32(value: &str, label: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.is_ascii() {
        return Err(format!(
            "{label} must contain exactly 64 ASCII hex characters"
        ));
    }
    let mut bytes = [0u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| format!("{label} contains a non-hex character"))?;
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

fn required<'a>(values: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str, String> {
    values
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| format!("missing required option {key}"))
}

fn reject_unknown(values: &BTreeMap<String, String>, allowed: &[&str]) -> Result<(), String> {
    if let Some(key) = values.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(format!("unknown option: {key}"));
    }
    Ok(())
}

fn absolute_output(path: &str, label: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(path);
    if !path.is_absolute() || path.file_name().is_none() || !path.parent().is_some_and(Path::is_dir)
    {
        return Err(format!(
            "{label} must be an absolute file path in an existing directory"
        ));
    }
    Ok(path)
}

fn require_new_output(path: &Path, label: &str) -> Result<File, String> {
    match fs::symlink_metadata(path) {
        Ok(_) => return Err(format!("{label} already exists; refusing overwrite")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("cannot inspect {label}: {error}")),
    }
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("cannot create {label}: {error}"))
}

fn provision_key(values: &BTreeMap<String, String>) -> Result<(), String> {
    reject_unknown(values, &["--network-id-hex", "--role", "--output"])?;
    let network_id = parse_hex32(required(values, "--network-id-hex")?, "Network ID")?;
    if network_id == [0; 32] {
        return Err("Network ID must be nonzero".into());
    }
    let role = SigningKeyRole::parse(required(values, "--role")?)?;
    if !matches!(
        role,
        SigningKeyRole::ReferenceTimeAuthority | SigningKeyRole::ReferenceTimePolicyAdmin
    ) {
        return Err("provision-key only supports the two reference-time key roles".into());
    }
    let output = absolute_output(required(values, "--output")?, "protected key output")?;
    let mut seed = [0u8; 32];
    getrandom(&mut seed).map_err(|_| "cryptographic random seed generation failed")?;
    if seed == [0; 32] {
        return Err("cryptographic random source returned an invalid zero seed".into());
    }
    let key = SigningKey::from_bytes(&seed);
    if key.verifying_key().is_weak() {
        seed.fill(0);
        return Err("generated Ed25519 key is weak".into());
    }
    let public_key = key.verifying_key().to_bytes();
    let store_result = store_protected_signing_seed(&output, &network_id, role, &seed);
    seed.fill(0);
    store_result?;
    println!("role={}", role.as_str());
    println!("network_id={}", hex(&network_id));
    println!("public_key={}", hex(&public_key));
    println!("protected_key_file={}", output.display());
    println!("private_seed_exported=false");
    Ok(())
}

fn create_policy(values: &BTreeMap<String, String>) -> Result<(), String> {
    reject_unknown(
        values,
        &[
            "--network-id-hex",
            "--authority-public-key-hex",
            "--policy-admin-key-file",
            "--policy-admin-public-key-hex",
            "--sequence",
            "--max-round-trip-ms",
            "--max-local-clock-skew-secs",
            "--output",
        ],
    )?;
    let network_id = parse_hex32(required(values, "--network-id-hex")?, "Network ID")?;
    if network_id == [0; 32] {
        return Err("Network ID must be nonzero".into());
    }
    let authority_public_key = parse_hex32(
        required(values, "--authority-public-key-hex")?,
        "authority public key",
    )?;
    let authority = VerifyingKey::from_bytes(&authority_public_key)
        .map_err(|_| "authority public key is malformed".to_string())?;
    if authority.is_weak() {
        return Err("authority public key must not be weak".into());
    }
    let expected_admin_public_key = parse_hex32(
        required(values, "--policy-admin-public-key-hex")?,
        "policy admin public key",
    )?;
    let policy_admin_key_file = absolute_output(
        required(values, "--policy-admin-key-file")?,
        "policy admin key file",
    )?;
    let mut admin_seed = load_protected_signing_seed(
        &policy_admin_key_file,
        &network_id,
        SigningKeyRole::ReferenceTimePolicyAdmin,
    )?;
    let admin = SigningKey::from_bytes(&admin_seed);
    admin_seed.fill(0);
    if admin.verifying_key().to_bytes() != expected_admin_public_key {
        return Err("protected policy-admin key does not match the pinned public key".into());
    }

    let sequence = required(values, "--sequence")?
        .parse::<u64>()
        .map_err(|_| "policy sequence must be a nonzero unsigned integer".to_string())?;
    if sequence == 0 {
        return Err("policy sequence must be nonzero".into());
    }
    let max_round_trip_ms = required(values, "--max-round-trip-ms")?
        .parse::<u32>()
        .map_err(|_| "maximum round-trip time must be an unsigned integer".to_string())?;
    if max_round_trip_ms == 0 || max_round_trip_ms > MAX_REFERENCE_TIME_RTT_MS {
        return Err(format!(
            "maximum round-trip time must be 1..={MAX_REFERENCE_TIME_RTT_MS} ms"
        ));
    }
    let skew_text = required(values, "--max-local-clock-skew-secs")?;
    let max_local_skew = if skew_text == "none" {
        u64::MAX
    } else {
        let value = skew_text.parse::<u64>().map_err(|_| {
            "clock skew must be 'none' or an unsigned number of seconds".to_string()
        })?;
        if value > MAX_LOCAL_CLOCK_SKEW_SECS {
            return Err(format!(
                "clock skew must be at most {MAX_LOCAL_CLOCK_SKEW_SECS} seconds"
            ));
        }
        value
    };
    let output = absolute_output(required(values, "--output")?, "RTP1 policy output")?;

    let mut body = Vec::with_capacity(POLICY_BODY_LEN);
    body.extend_from_slice(POLICY_MAGIC);
    body.extend_from_slice(&WIRE_VERSION.to_be_bytes());
    body.extend_from_slice(&network_id);
    body.extend_from_slice(&sequence.to_be_bytes());
    body.extend_from_slice(&authority_public_key);
    body.extend_from_slice(&max_round_trip_ms.to_be_bytes());
    body.extend_from_slice(&max_local_skew.to_be_bytes());
    if body.len() != POLICY_BODY_LEN {
        return Err("internal RTP1 policy body length mismatch".into());
    }
    let mut message = Vec::with_capacity(POLICY_DOMAIN.len() + body.len());
    message.extend_from_slice(POLICY_DOMAIN);
    message.extend_from_slice(&body);
    let signature = admin.sign(&message).to_bytes();
    body.extend_from_slice(&signature);

    let mut file = require_new_output(&output, "RTP1 policy output")?;
    let write_result = file
        .write_all(&body)
        .and_then(|_| file.flush())
        .and_then(|_| file.sync_all());
    drop(file);
    if let Err(error) = write_result {
        let _ = fs::remove_file(&output);
        return Err(format!("cannot durably write RTP1 policy: {error}"));
    }
    let digest: [u8; 32] = Sha256::digest(&body).into();
    println!("policy_file={}", output.display());
    println!("network_id={}", hex(&network_id));
    println!("sequence={sequence}");
    println!("authority_public_key={}", hex(&authority_public_key));
    println!(
        "policy_admin_public_key={}",
        hex(&expected_admin_public_key)
    );
    println!("policy_digest={}", hex(&digest));
    println!("policy_bytes={}", hex(&body));
    Ok(())
}

fn parse_socket(value: &str) -> Result<SocketAddr, String> {
    let address = value
        .parse::<SocketAddr>()
        .map_err(|_| "listen address must be a numeric IP:PORT".to_string())?;
    if address.port() == 0 || address.ip().is_multicast() {
        return Err("listen address requires a nonzero port and a unicast IP".into());
    }
    Ok(address)
}

fn probe(values: &BTreeMap<String, String>) -> Result<(), String> {
    reject_unknown(
        values,
        &[
            "--network-id-hex",
            "--policy-file",
            "--policy-admin-public-key-hex",
            "--address",
            "--state-file",
        ],
    )?;
    let network_id = parse_hex32(required(values, "--network-id-hex")?, "Network ID")?;
    if network_id == [0; 32] {
        return Err("Network ID must be nonzero".into());
    }
    let policy_file = absolute_output(required(values, "--policy-file")?, "RTP1 policy file")?;
    let metadata = fs::symlink_metadata(&policy_file)
        .map_err(|error| format!("cannot inspect RTP1 policy file: {error}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() != POLICY_WIRE_LEN as u64
    {
        return Err(
            "RTP1 policy must be a regular, non-symlink file of the exact wire length".into(),
        );
    }
    let policy_bytes =
        fs::read(&policy_file).map_err(|error| format!("read RTP1 policy file: {error}"))?;
    if policy_bytes.len() != POLICY_WIRE_LEN {
        return Err("RTP1 policy changed length while being read".into());
    }
    let admin_public_key = parse_hex32(
        required(values, "--policy-admin-public-key-hex")?,
        "policy admin public key",
    )?;
    let address = parse_socket(required(values, "--address")?)?;
    let state_file = absolute_output(required(values, "--state-file")?, "probe state file")?;
    if paths_overlap(&policy_file, &state_file) {
        return Err("probe high-water state must be separate from the signed policy file".into());
    }
    let store = ReferenceTimeStateStore::open(&state_file, &network_id)
        .map_err(|error| format!("open probe high-water state: {error:?}"))?;
    let trust = store
        .policy_trust_state()
        .map_err(|error| format!("read probe policy rollback floor: {error:?}"))?;
    let policy =
        VerifiedReferenceTimePolicy::verify(&policy_bytes, &network_id, &admin_public_key, &trust)
            .map_err(|error| format!("verify RTP1 policy: {error:?}"))?;
    let policy_digest = *policy.digest();
    let provider = AuthenticatedReferenceTimeProvider::new_persistent(
        policy,
        TcpReferenceTimeExchange::new(address),
        store,
    )
    .map_err(|error| format!("initialize authenticated probe: {error:?}"))?;
    let sample = provider
        .sample()
        .map_err(|error| format!("authenticated TMA1 probe failed: {error:?}"))?;
    println!("reference_time_probe=PASS");
    println!("network_id={}", hex(&network_id));
    println!("policy_digest={}", hex(&policy_digest));
    println!("authority_address={address}");
    println!("authority_source={}", sample.source_id);
    println!("unix_seconds={}", sample.unix_seconds);
    println!(
        "accepted_authority_sequence={}",
        provider.last_accepted_sequence()
    );
    println!("provenance={:?}", sample.provenance);
    println!("bft_time_consensus=false");
    Ok(())
}

fn serve(values: &BTreeMap<String, String>) -> Result<(), String> {
    reject_unknown(
        values,
        &[
            "--network-id-hex",
            "--authority-key-file",
            "--state-file",
            "--listen",
            "--allow-non-loopback",
        ],
    )?;
    let network_id = parse_hex32(required(values, "--network-id-hex")?, "Network ID")?;
    if network_id == [0; 32] {
        return Err("Network ID must be nonzero".into());
    }
    let key_file = absolute_output(
        required(values, "--authority-key-file")?,
        "authority key file",
    )?;
    let state_file = absolute_output(required(values, "--state-file")?, "authority state file")?;
    if paths_overlap(&key_file, &state_file) {
        return Err("authority state file must be separate from the protected signing key".into());
    }
    let listen = parse_socket(
        values
            .get("--listen")
            .map(String::as_str)
            .unwrap_or(DEFAULT_LISTEN),
    )?;
    let allow_non_loopback = match values
        .get("--allow-non-loopback")
        .map(String::as_str)
        .unwrap_or("false")
    {
        "true" => true,
        "false" => false,
        _ => return Err("--allow-non-loopback must be exactly true or false".into()),
    };
    if !listen.ip().is_loopback() && !allow_non_loopback {
        return Err("non-loopback bind requires explicit --allow-non-loopback true".into());
    }

    let state = Arc::new(
        ReferenceTimeStateStore::open(&state_file, &network_id)
            .map_err(|error| format!("open authority sequence state: {error:?}"))?,
    );
    let mut seed = load_protected_signing_seed(
        &key_file,
        &network_id,
        SigningKeyRole::ReferenceTimeAuthority,
    )?;
    let service_result = ReferenceTimeAuthorityService::new(network_id, seed, state);
    seed.fill(0);
    let service = Arc::new(
        service_result.map_err(|error| format!("initialize reference-time authority: {error}"))?,
    );

    let listener = TcpListener::bind(listen)
        .map_err(|error| format!("bind reference-time authority at {listen}: {error}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("configure authority listener: {error}"))?;
    println!("qrun_reference_time_authority_ready");
    println!("network_id={}", hex(&network_id));
    println!("authority_public_key={}", hex(&service.public_key()));
    println!("listen={listen}");
    println!(
        "last_issued_sequence_in_process={}",
        service.last_issued_sequence().map_err(|e| e.to_string())?
    );
    println!(
        "reserved_sequence_high_water={}",
        service
            .reserved_sequence_high_water()
            .map_err(|e| e.to_string())?
    );
    println!("max_concurrent_connections={MAX_AUTHORITY_WORKERS}");
    println!("clock_source=authority_host_os_clock");
    println!("bft_time_consensus=false");

    let active = Arc::new(AtomicUsize::new(0));
    let mut workers: Vec<JoinHandle<()>> = Vec::new();
    loop {
        while let Some(index) = workers.iter().position(JoinHandle::is_finished) {
            let worker = workers.swap_remove(index);
            let _ = worker.join();
        }
        match listener.accept() {
            Ok((mut stream, peer)) => {
                let reserved = active.fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                    (count < MAX_AUTHORITY_WORKERS).then_some(count + 1)
                });
                if reserved.is_err() {
                    eprintln!("qrun_reference_time_authority_busy peer={peer}");
                    drop(stream);
                    continue;
                }
                let service = Arc::clone(&service);
                let active_for_worker = Arc::clone(&active);
                match thread::Builder::new()
                    .name("qrun-time-authority-client".into())
                    .spawn(move || {
                        struct ActiveGuard(Arc<AtomicUsize>);
                        impl Drop for ActiveGuard {
                            fn drop(&mut self) {
                                self.0.fetch_sub(1, Ordering::AcqRel);
                            }
                        }
                        let _guard = ActiveGuard(active_for_worker);
                        match service.handle_connection(&mut stream) {
                            Ok(sequence) => println!(
                                "qrun_reference_time_response peer={peer} sequence={sequence}"
                            ),
                            Err(error) => eprintln!(
                                "qrun_reference_time_request_rejected peer={peer} reason={error}"
                            ),
                        }
                    }) {
                    Ok(worker) => workers.push(worker),
                    Err(error) => {
                        active.fetch_sub(1, Ordering::AcqRel);
                        eprintln!("qrun_reference_time_worker_spawn_failed reason={error}");
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(format!("authority accept failed: {error}")),
        }
    }
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    fn normalized(path: &Path) -> PathBuf {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let name = path.file_name().unwrap_or_default();
        let parent = parent
            .canonicalize()
            .unwrap_or_else(|_| parent.to_path_buf());
        parent.join(name)
    }
    normalized(left) == normalized(right)
}
