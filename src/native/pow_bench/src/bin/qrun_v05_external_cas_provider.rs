//! Independent QRun v0.5 external-CAS provider daemon candidate.
//!
//! This process is intentionally not a QRun consensus node. It serves one authenticated CAS
//! request per TCP connection, serially, with durable local provider state and an AWS KMS
//! ML-DSA-65 receipt signer. Public interfaces require an explicit opt-in flag and a client-key
//! allow-list. No local-node fallback is provided.

#[cfg(windows)]
use ai_native_l1_pow_bench::noise_key_provisioning::load_protected_noise_private_key;
use ai_native_l1_pow_bench::{
    external_cas_anchor_candidate::{ExternalCasPin, ExternalCasRecord, EXTERNAL_CAS_RECORD_BYTES},
    external_cas_aws_kms_signer_candidate::AwsKmsCliReceiptSigner,
    external_cas_disk_provider_candidate::DurableExternalCasProvider,
    external_cas_noise_transport_candidate::serve_external_cas_noise_connection,
    v4_fat1_trust_candidate::ML_DSA_65_PUBLIC_KEY_BYTES,
};
use snow::{
    params::DHChoice,
    resolvers::{CryptoResolver, DefaultResolver},
};
use std::{
    collections::HashSet,
    env, fs,
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    time::Duration,
};

const DEFAULT_AWS_CLI: &str = "aws";
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(12);

#[derive(Debug)]
struct Config {
    listen: SocketAddr,
    allow_public_bind: bool,
    pin: ExternalCasPin,
    receipt_public_key_file: PathBuf,
    kms_key_arn: String,
    aws_region: String,
    aws_cli: PathBuf,
    noise_private_key_file: PathBuf,
    noise_server_public_key: [u8; 32],
    allowed_client_static_public_keys: Vec<[u8; 32]>,
    provider_directory: PathBuf,
    bootstrap_record_file: Option<PathBuf>,
    initialize: bool,
}

struct Secret32([u8; 32]);
impl Drop for Secret32 {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}
impl Secret32 {
    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

fn parse_hex32(value: &str, name: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.is_ascii() {
        return Err(format!("{name} must be exactly 64 hexadecimal characters"));
    }
    let mut out = [0u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| format!("{name} contains a non-hexadecimal character"))?;
    }
    if out.iter().all(|byte| *byte == 0) {
        return Err(format!("{name} must not be zero"));
    }
    Ok(out)
}

fn parse_args(args: &[String]) -> Result<Config, String> {
    const VALUE_OPTIONS: &[&str] = &[
        "--listen",
        "--provider-id-hex",
        "--network-id-hex",
        "--genesis-digest-hex",
        "--receipt-key-id-hex",
        "--receipt-public-key-file",
        "--kms-key-arn",
        "--aws-region",
        "--aws-cli",
        "--noise-private-key-file",
        "--noise-server-static-public-key-hex",
        "--data-dir",
        "--initialize",
        "--bootstrap-record-file",
    ];
    let mut values = std::collections::HashMap::<String, String>::new();
    let mut allowed_keys = Vec::new();
    let mut allow_public_bind = false;
    let mut index = 0usize;
    while index < args.len() {
        let name = &args[index];
        if name == "--allow-public-bind" {
            if allow_public_bind {
                return Err("--allow-public-bind was repeated".into());
            }
            allow_public_bind = true;
            index += 1;
            continue;
        }
        if name == "--allowed-client-static-public-key-hex" {
            let value = args
                .get(index + 1)
                .ok_or("--allowed-client-static-public-key-hex needs a value")?;
            allowed_keys.push(parse_hex32(value, "allowed client Noise public key")?);
            index += 2;
            continue;
        }
        if !name.starts_with("--") {
            return Err(format!("unexpected positional argument: {name}"));
        }
        if !VALUE_OPTIONS.contains(&name.as_str()) {
            return Err(format!("unknown option: {name}"));
        }
        let value = args
            .get(index + 1)
            .ok_or_else(|| format!("{name} needs a value"))?;
        if values.insert(name.clone(), value.clone()).is_some() {
            return Err(format!("{name} was repeated"));
        }
        index += 2;
    }

    let take = |name: &str| -> Result<String, String> {
        values
            .get(name)
            .cloned()
            .ok_or_else(|| format!("required option {name} is missing"))
    };
    let listen: SocketAddr = take("--listen")?
        .parse()
        .map_err(|_| "--listen must be a numeric IP:PORT address (DNS names are not accepted)")?;
    if !listen.ip().is_loopback() && !allow_public_bind {
        return Err("non-loopback binding requires the explicit --allow-public-bind flag".into());
    }
    if allowed_keys.is_empty() {
        return Err("at least one --allowed-client-static-public-key-hex is required".into());
    }
    let mut distinct_keys = HashSet::new();
    if allowed_keys.iter().any(|key| !distinct_keys.insert(*key)) {
        return Err("allowed client Noise public keys must be unique".into());
    }

    let provider_id = parse_hex32(&take("--provider-id-hex")?, "provider ID")?;
    let network_id = parse_hex32(&take("--network-id-hex")?, "network ID")?;
    let genesis_digest = parse_hex32(&take("--genesis-digest-hex")?, "genesis digest")?;
    let receipt_key_id = parse_hex32(&take("--receipt-key-id-hex")?, "receipt key ID")?;
    let receipt_public_key_file =
        absolute_path(take("--receipt-public-key-file")?, "receipt public key")?;
    let kms_key_arn = take("--kms-key-arn")?;
    let aws_region = take("--aws-region")?;
    let aws_cli = PathBuf::from(
        values
            .get("--aws-cli")
            .cloned()
            .unwrap_or_else(|| DEFAULT_AWS_CLI.to_string()),
    );
    let noise_private_key_file = absolute_path(
        take("--noise-private-key-file")?,
        "Noise private-key credential",
    )?;
    let noise_server_public_key = parse_hex32(
        &take("--noise-server-static-public-key-hex")?,
        "Noise server public key",
    )?;
    let provider_directory = absolute_path(take("--data-dir")?, "provider data directory")?;
    let initialize_text = take("--initialize")?;
    let initialize = match initialize_text.as_str() {
        "true" => true,
        "false" => false,
        _ => return Err("--initialize must be exactly true or false".into()),
    };
    let bootstrap_record_file = values
        .get("--bootstrap-record-file")
        .cloned()
        .map(|value| absolute_path(value, "bootstrap record"))
        .transpose()?;
    if initialize && bootstrap_record_file.is_none() {
        return Err("--bootstrap-record-file is required when --initialize true".into());
    }
    if !initialize && bootstrap_record_file.is_some() {
        return Err("--bootstrap-record-file is only accepted with --initialize true".into());
    }
    let pin = ExternalCasPin {
        provider_id,
        network_id,
        genesis_digest,
        receipt_key_id,
        receipt_public_key: [0u8; ML_DSA_65_PUBLIC_KEY_BYTES],
    };
    Ok(Config {
        listen,
        allow_public_bind,
        pin,
        receipt_public_key_file,
        kms_key_arn,
        aws_region,
        aws_cli,
        noise_private_key_file,
        noise_server_public_key,
        allowed_client_static_public_keys: allowed_keys,
        provider_directory,
        bootstrap_record_file,
        initialize,
    })
}

fn absolute_path(value: String, name: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(value);
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(format!(
            "{name} path must be absolute and include a file or directory name"
        ));
    }
    Ok(path)
}

fn read_exact_regular_file(
    path: &Path,
    expected_bytes: usize,
    name: &str,
) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {name} file: {error}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() != expected_bytes as u64
    {
        return Err(format!(
            "{name} file must be a regular non-symlink file of exactly {expected_bytes} bytes"
        ));
    }
    fs::read(path).map_err(|error| format!("cannot read {name} file: {error}"))
}

fn load_noise_server_private_key(path: &Path, network_id: &[u8; 32]) -> Result<Secret32, String> {
    #[cfg(windows)]
    {
        let key = load_protected_noise_private_key(path, network_id).map_err(|error| {
            format!("Windows DPAPI could not unprotect Noise server key: {error}")
        })?;
        if key.iter().all(|byte| *byte == 0) {
            return Err("Noise server static private key is zero".into());
        }
        return Ok(Secret32(key));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let credential_directory = env::var_os("CREDENTIALS_DIRECTORY")
            .map(PathBuf::from)
            .ok_or("Unix deployments must provide the Noise key through a systemd credential")?;
        let canonical_directory = fs::canonicalize(&credential_directory)
            .map_err(|error| format!("cannot resolve systemd credential directory: {error}"))?;
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| format!("cannot inspect Noise key credential: {error}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("Noise key credential must be a regular non-symlink file".into());
        }
        let canonical_path = fs::canonicalize(path)
            .map_err(|error| format!("cannot resolve Noise key credential: {error}"))?;
        if !canonical_path.starts_with(&canonical_directory) {
            return Err("Noise key credential must reside inside CREDENTIALS_DIRECTORY".into());
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("Noise key credential permissions must deny group and other access".into());
        }
        let bytes =
            fs::read(path).map_err(|error| format!("cannot read Noise key credential: {error}"))?;
        let key: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| "Noise key credential must contain exactly 32 raw bytes")?;
        if key.iter().all(|byte| *byte == 0) {
            return Err("Noise server static private key is zero".into());
        }
        return Ok(Secret32(key));
    }

    #[allow(unreachable_code)]
    Err("Noise key loading is unsupported on this operating system".into())
}

fn derive_noise_static_public_key(private_key: &[u8; 32]) -> Result<[u8; 32], String> {
    let resolver = DefaultResolver::default();
    let mut dh = resolver
        .resolve_dh(&DHChoice::Curve25519)
        .ok_or("Noise Curve25519 implementation is unavailable")?;
    dh.set(private_key);
    dh.pubkey()
        .try_into()
        .map_err(|_| "Noise Curve25519 public key has an unexpected length".into())
}

fn read_bootstrap_record(path: &Path) -> Result<ExternalCasRecord, String> {
    let bytes = read_exact_regular_file(path, EXTERNAL_CAS_RECORD_BYTES, "bootstrap record")?;
    ExternalCasRecord::decode(&bytes)
        .map_err(|error| format!("bootstrap record is invalid: {error}"))
}

fn load_receipt_public_key(path: &Path) -> Result<[u8; ML_DSA_65_PUBLIC_KEY_BYTES], String> {
    let bytes = read_exact_regular_file(path, ML_DSA_65_PUBLIC_KEY_BYTES, "ML-DSA-65 public key")?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| "receipt public key has an unexpected length".into())
}

fn run(config: Config) -> Result<(), String> {
    let public_key = load_receipt_public_key(&config.receipt_public_key_file)?;
    let pin = ExternalCasPin {
        receipt_public_key: public_key,
        ..config.pin.clone()
    };
    pin.validate()
        .map_err(|error| format!("receipt pin is invalid: {error}"))?;

    let kms_signer = AwsKmsCliReceiptSigner::connect(
        &config.aws_cli,
        config.aws_region.clone(),
        config.kms_key_arn.clone(),
        &pin,
    )
    .map_err(|error| format!("AWS KMS receipt signer failed closed: {error}"))?;

    let noise_private_key =
        load_noise_server_private_key(&config.noise_private_key_file, &pin.network_id)?;
    let observed_server_public_key = derive_noise_static_public_key(noise_private_key.as_bytes())?;
    if observed_server_public_key != config.noise_server_public_key {
        return Err("Noise private key does not match the configured server public-key pin".into());
    }

    let listener = TcpListener::bind(config.listen)
        .map_err(|error| format!("cannot bind external-CAS listener: {error}"))?;
    let local_address = listener
        .local_addr()
        .map_err(|error| format!("cannot inspect bound listener: {error}"))?;

    let bootstrap = config
        .bootstrap_record_file
        .as_deref()
        .map(read_bootstrap_record)
        .transpose()?;
    let signer = move |digest: &[u8; 32]| {
        kms_signer
            .sign_digest(digest)
            .map_err(|error| error.to_string())
    };

    let mut provider = if config.initialize {
        let bootstrap = bootstrap.ok_or("--initialize true requires a bootstrap record")?;
        DurableExternalCasProvider::initialize(
            &config.provider_directory,
            pin.clone(),
            bootstrap,
            signer,
        )
        .map_err(|error| {
            format!("cannot initialize durable CAS provider (no reset/fallback): {error}")
        })?
    } else {
        DurableExternalCasProvider::open(&config.provider_directory, pin.clone(), signer).map_err(
            |error| format!("cannot open durable CAS provider (no reset/fallback): {error}"),
        )?
    };

    println!(
        "QRUN_EXTERNAL_CAS_PROVIDER_READY listen={} provider_id={} network_id={} client_keys={} kms_signing=ML_DSA_SHAKE_256 public_bind_opt_in={}",
        local_address,
        hex(&pin.provider_id),
        hex(&pin.network_id),
        config.allowed_client_static_public_keys.len(),
        config.allow_public_bind
    );
    println!("provider_state={}", provider.state_path().display());

    loop {
        let (mut stream, peer) = match listener.accept() {
            Ok(accepted) => accepted,
            Err(error) => {
                eprintln!(
                    "external_cas_accept_error={}",
                    safe_error(&error.to_string())
                );
                continue;
            }
        };
        println!("external_cas_connection_accepted peer={peer}");
        if let Err(error) = configure_connection(&stream) {
            eprintln!(
                "external_cas_connection_setup_rejected={}",
                safe_error(&error)
            );
            continue;
        }
        match serve_external_cas_noise_connection(
            &mut stream,
            noise_private_key.as_bytes(),
            &config.allowed_client_static_public_keys,
            &pin,
            &mut provider,
        ) {
            Ok(()) => println!("external_cas_connection_completed"),
            Err(error) => {
                eprintln!(
                    "external_cas_connection_rejected={}",
                    safe_error(&error.to_string())
                );
            }
        }
    }
}

fn configure_connection(stream: &TcpStream) -> Result<(), String> {
    stream
        .set_read_timeout(Some(CONNECTION_TIMEOUT))
        .map_err(|error| format!("cannot set read timeout: {error}"))?;
    stream
        .set_write_timeout(Some(CONNECTION_TIMEOUT))
        .map_err(|error| format!("cannot set write timeout: {error}"))?;
    Ok(())
}

fn safe_error(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control() || *character == '\t')
        .take(512)
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 15) as usize] as char);
    }
    output
}

fn print_help() {
    println!(
        "QRun v0.5 independent external-CAS provider candidate\n\
         Usage: qrun_v05_external_cas_provider [options]\n\
         Required:\n\
           --listen IP:PORT\n\
           --provider-id-hex HEX64 --network-id-hex HEX64 --genesis-digest-hex HEX64\n\
           --receipt-key-id-hex HEX64 --receipt-public-key-file ABSOLUTE_PATH\n\
           --kms-key-arn FULL_KEY_ARN --aws-region REGION [--aws-cli PATH]\n\
           --noise-private-key-file ABSOLUTE_PATH\n\
           --noise-server-static-public-key-hex HEX64\n\
           --allowed-client-static-public-key-hex HEX64 (repeatable)\n\
           --data-dir ABSOLUTE_PATH --initialize true|false\n\
         Initialization only:\n\
           --bootstrap-record-file ABSOLUTE_PATH\n\
         Public listener only:\n\
           --allow-public-bind\n\
         Security notes:\n\
           * Public/non-loopback binding fails closed unless --allow-public-bind is explicit.\n\
           * Windows Noise keys must be NPK1 protected with CurrentUser DPAPI.\n\
           * Unix Noise keys must be systemd credentials under CREDENTIALS_DIRECTORY.\n\
           * AWS credentials should come from a narrowly scoped instance/task role.\n\
           * The server uses classical Noise_XX_25519_ChaChaPoly_SHA256; receipt signatures are ML-DSA-65.\n\
           * Candidate provider only; not a Mainnet release or independent deployment."
    );
}

fn main() {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.iter().any(|value| value == "--help" || value == "-h") {
        print_help();
        return;
    }
    let result = parse_args(&args).and_then(run);
    if let Err(error) = result {
        eprintln!("QRUN_EXTERNAL_CAS_PROVIDER_ERROR: {}", safe_error(&error));
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    use ai_native_l1_pow_bench::noise_key_provisioning::store_protected_noise_private_key;

    #[test]
    fn hex32_parser_is_strict_and_nonzero() {
        assert_eq!(parse_hex32(&"11".repeat(32), "test").unwrap(), [0x11; 32]);
        assert!(parse_hex32(&"00".repeat(32), "test").is_err());
        assert!(parse_hex32("11", "test").is_err());
        assert!(parse_hex32(&format!("{}g", "11".repeat(31)), "test").is_err());
    }

    #[test]
    fn unknown_command_line_options_are_rejected_fail_closed() {
        let args = vec![
            "--listen".into(),
            "127.0.0.1:49410".into(),
            "--kms-regoin".into(),
            "eu-west-1".into(),
        ];
        assert_eq!(
            parse_args(&args).unwrap_err(),
            "unknown option: --kms-regoin"
        );
    }

    #[test]
    fn curve25519_public_key_is_derived_from_loaded_private_material() {
        let public = derive_noise_static_public_key(&[0x41; 32]).unwrap();
        assert_ne!(public, [0; 32]);
        assert_eq!(public, derive_noise_static_public_key(&[0x41; 32]).unwrap());
        assert_ne!(public, derive_noise_static_public_key(&[0x42; 32]).unwrap());
    }

    #[test]
    fn public_binding_requires_explicit_opt_in() {
        let args = vec!["--listen".into(), "0.0.0.0:49410".into()];
        assert_eq!(
            parse_args(&args).unwrap_err(),
            "non-loopback binding requires the explicit --allow-public-bind flag"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_provider_loads_only_network_bound_dpapi_noise_credentials() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let network_id = [0x31; 32];
        let private_key = [0x42; 32];
        let directory = env::temp_dir().join(format!(
            "qrun-provider-noise-key-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&directory).unwrap();
        let key_file = directory.join("server.npk1");

        store_protected_noise_private_key(&key_file, &network_id, &private_key).unwrap();
        let stored = fs::read(&key_file).unwrap();
        assert!(stored.starts_with(b"NPK1"));
        assert_ne!(stored.as_slice(), private_key.as_slice());

        let loaded = load_noise_server_private_key(&key_file, &network_id).unwrap();
        assert_eq!(loaded.as_bytes(), &private_key);
        let expected_public = derive_noise_static_public_key(&private_key).unwrap();
        assert_eq!(
            derive_noise_static_public_key(loaded.as_bytes()).unwrap(),
            expected_public
        );

        let wrong_network = [0x32; 32];
        assert!(load_noise_server_private_key(&key_file, &wrong_network).is_err());
        drop(loaded);
        fs::remove_dir_all(directory).unwrap();
    }
}
