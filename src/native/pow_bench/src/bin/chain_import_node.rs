//! Local TCP importer for the chain-admission research service.
//! Authenticated HMAC sessions are supported; unauthenticated mode is test-only and explicit.

use ai_native_l1_pow_bench::{
    auth_transport::{
        derive_direction_key, make_auth_ack, open_record, random_nonce, seal_record,
        verify_auth_hello, AUTH_ACK_LEN, AUTH_HELLO_LEN, AUTH_TAG_LEN, MAX_AUTH_RECORD,
        RECORD_HEADER_LEN,
    },
    chain_admission::{
        ChainAdmissionBoundary, ChainAdmissionConfig, ReferenceTimeError, ReferenceTimeProvenance,
        ReferenceTimeProvider, ReferenceTimeSample, ReferenceTimeSourcePolicy,
        SystemClockReferenceTime,
    },
    chain_import::{ChainImportService, ImportMode},
    credential_binding::{session_identity_context, BindingPolicy, CredentialBinding},
    decode_frame, encode_frame,
    identity_generation_store::{IdentityGenerationStateStore, ROTATION_WIRE_LEN},
    identity_policy::{
        decode as decode_key_record, CryptoPolicy, IdentityError, KeyAlgorithm, KeyPurpose,
        KeyRecord, KeyState, SecurityClass, HEADER_LEN as IDENTITY_RECORD_HEADER_LEN,
        MAX_PUBLIC_KEY as MAX_IDENTITY_PUBLIC_KEY_BYTES,
    },
    identity_session::BoundSession,
    key_provider::{ProviderError, PublicKeyProvider},
    noise_deployment_config::{
        verify_signed_deployment_config, DeploymentConfigStateStore,
        MAX_SIGNED_DEPLOYMENT_CONFIG_LEN,
    },
    noise_issuer_registry::{IssuerRegistryStateStore, MAX_REGISTRY_WIRE_LEN},
    reference_time::{
        AuthenticatedReferenceTimeProvider, VerifiedReferenceTimePolicy, POLICY_WIRE_LEN,
    },
    reference_time_store::ReferenceTimeStateStore,
    reference_time_tcp::TcpReferenceTimeExchange,
    state_machine::{LedgerState, MAX_ENCODED_BLOCK_BYTES},
    timestamp_policy::TimestampPolicy,
    transaction_auth::{
        account_id_from_public_key, AccountPublicKey, Ed25519TransactionAuthenticator,
        TransactionAuthenticatorKind, ED25519_PUBLIC_KEY_LEN,
    },
    Frame, MessageType, PROTOCOL_VERSION,
};
use ed25519_dalek::{Signature, VerifyingKey};
use snow::Builder;
use std::{
    env,
    fs::File,
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    ops::Deref,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const READ_SLICE_MS: u64 = 100;
const FRAME_DEADLINE_MS: u64 = 5_000;
const MAX_REPLY_BYTES: usize = 1_024;

#[derive(Debug)]
struct Config {
    port: u16,
    network_id: [u8; 32],
    public_key: [u8; ED25519_PUBLIC_KEY_LEN],
    genesis_balance: u64,
    snapshot_path: PathBuf,
    reference_time_policy_path: Option<PathBuf>,
    reference_time_admin_public_key: Option<[u8; 32]>,
    reference_time_address: Option<SocketAddr>,
    reference_time_state_path: Option<PathBuf>,
    peer_psk: Option<[u8; 32]>,
    peer_noise_static_private_key_dpapi_file: Option<PathBuf>,
    peer_noise_allowed_public_key: Option<[u8; 32]>,
    peer_noise_identity_record_file: Option<PathBuf>,
    peer_noise_identity_signature_file: Option<PathBuf>,
    peer_noise_identity_state_file: Option<PathBuf>,
    peer_noise_rotation_file: Option<PathBuf>,
    peer_noise_issuer_registry_file: Option<PathBuf>,
    peer_noise_issuer_registry_state_file: Option<PathBuf>,
    peer_noise_deployment_config_file: Option<PathBuf>,
    peer_noise_deployment_config_state_file: Option<PathBuf>,
    peer_noise_deployment_authority_public_key: Option<[u8; 32]>,
    peer_noise_deployment_min_sequence: Option<u64>,
    peer_noise_key_id: Option<u32>,
    peer_noise_credential_id: Option<u128>,
    peer_noise_issuer_id: Option<u32>,
    peer_noise_binding_max_validity: u64,
    allow_unauthenticated_test_peer: bool,
    connections: u32,
    duration_ms: u64,
    mode: ImportMode,
    reference_time_unix_seconds: Option<u64>,
    allow_test_time_fixtures: bool,
}

fn option(args: &[String], name: &str) -> Result<Option<String>, String> {
    let matches: Vec<usize> = args
        .iter()
        .enumerate()
        .filter_map(|(i, value)| (value == name).then_some(i))
        .collect();
    if matches.len() > 1 {
        return Err(format!("duplicate option {name}"));
    }
    let Some(index) = matches.first().copied() else {
        return Ok(None);
    };
    let value = args
        .get(index + 1)
        .ok_or_else(|| format!("missing value for {name}"))?;
    if value.starts_with("--") {
        return Err(format!("missing value for {name}"));
    }
    Ok(Some(value.clone()))
}

fn number<T: std::str::FromStr>(args: &[String], name: &str, default: T) -> Result<T, String> {
    match option(args, name)? {
        Some(value) => value
            .parse()
            .map_err(|_| format!("invalid numeric value for {name}")),
        None => Ok(default),
    }
}

fn hex32(value: &str, name: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 {
        return Err(format!("{name} must be exactly 64 hexadecimal characters"));
    }
    let mut out = [0u8; 32];
    for index in 0..32 {
        out[index] = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| format!("{name} is not valid hexadecimal"))?;
    }
    Ok(out)
}

fn config() -> Result<Config, String> {
    let args: Vec<String> = env::args().skip(1).collect();
    config_from_args(&args)
}

fn config_from_args(args: &[String]) -> Result<Config, String> {
    let port = number(args, "--listen", 48150u16)?;
    let network_id = hex32(
        &option(&args, "--network-id")?.ok_or("required option --network-id")?,
        "--network-id",
    )?;
    let public_key = hex32(
        &option(&args, "--public-key-hex")?.ok_or("required option --public-key-hex")?,
        "--public-key-hex",
    )?;
    if network_id.iter().all(|byte| *byte == 0) {
        return Err("--network-id cannot be all zero".into());
    }
    let snapshot_path =
        PathBuf::from(option(&args, "--snapshot")?.ok_or("required option --snapshot")?);
    let mode = match option(&args, "--mode")?.as_deref().unwrap_or("live") {
        "live" => ImportMode::Live,
        "replay" => ImportMode::HistoricalReplay,
        _ => return Err("--mode must be live or replay".into()),
    };
    let reference_time_unix_seconds = option(&args, "--reference-time-unix-seconds")?
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|_| "invalid --reference-time-unix-seconds".to_string())
        })
        .transpose()?;
    let allow_test_time_fixtures = option(&args, "--allow-test-time-fixtures")?
        .unwrap_or_else(|| "false".to_string())
        .parse::<bool>()
        .map_err(|_| "--allow-test-time-fixtures must be true or false".to_string())?;
    if reference_time_unix_seconds.is_some() != allow_test_time_fixtures {
        return Err("fixed reference time requires explicit --allow-test-time-fixtures true, and that flag requires a fixed time".into());
    }
    let reference_time_policy_path =
        option(&args, "--reference-time-policy-file")?.map(PathBuf::from);
    let reference_time_admin_public_key = option(&args, "--reference-time-admin-public-key-hex")?
        .map(|value| hex32(&value, "--reference-time-admin-public-key-hex"))
        .transpose()?;
    let reference_time_address = option(&args, "--reference-time-address")?
        .map(|value| {
            value.parse::<SocketAddr>().map_err(|_| {
                "--reference-time-address must be a numeric IP:port socket address".to_string()
            })
        })
        .transpose()?;
    let reference_time_state_path =
        option(&args, "--reference-time-state-file")?.map(PathBuf::from);
    let reference_time_options = [
        reference_time_policy_path.is_some(),
        reference_time_admin_public_key.is_some(),
        reference_time_address.is_some(),
        reference_time_state_path.is_some(),
    ];
    let any_reference_time_option = reference_time_options.iter().any(|value| *value);
    if any_reference_time_option && !reference_time_options.iter().all(|value| *value) {
        return Err("authenticated reference time requires all four options: --reference-time-policy-file, --reference-time-admin-public-key-hex, --reference-time-address, --reference-time-state-file".into());
    }
    if any_reference_time_option && reference_time_unix_seconds.is_some() {
        return Err(
            "authenticated reference time cannot be combined with test-only fixed-time fixtures"
                .into(),
        );
    }
    if reference_time_state_path
        .as_ref()
        .is_some_and(|path| path == &snapshot_path)
    {
        return Err("reference-time state file must differ from the chain snapshot path".into());
    }
    let peer_psk = option(args, "--peer-psk-hex")?
        .map(|value| hex32(&value, "--peer-psk-hex"))
        .transpose()?;
    if peer_psk.is_some_and(|key| key.iter().all(|byte| *byte == 0)) {
        return Err("--peer-psk-hex cannot be all zero".into());
    }
    if option(args, "--peer-noise-static-private-key-hex")?.is_some() {
        return Err("--peer-noise-static-private-key-hex was removed; use --peer-noise-static-private-key-dpapi-file".into());
    }
    if option(args, "--peer-noise-static-private-key-file")?.is_some() {
        return Err("--peer-noise-static-private-key-file contains unprotected raw key bytes and was removed; use --peer-noise-static-private-key-dpapi-file".into());
    }
    let peer_noise_static_private_key_dpapi_file =
        option(args, "--peer-noise-static-private-key-dpapi-file")?.map(PathBuf::from);
    let peer_noise_allowed_public_key = option(args, "--peer-noise-allowed-public-key-hex")?
        .map(|value| hex32(&value, "--peer-noise-allowed-public-key-hex"))
        .transpose()?;
    if peer_noise_allowed_public_key.is_some_and(|key| key.iter().all(|byte| *byte == 0)) {
        return Err("--peer-noise-allowed-public-key-hex cannot be all zero".into());
    }
    let peer_noise_identity_record_file =
        option(args, "--peer-noise-identity-record-file")?.map(PathBuf::from);
    let peer_noise_identity_signature_file =
        option(args, "--peer-noise-identity-signature-file")?.map(PathBuf::from);
    let peer_noise_identity_state_file =
        option(args, "--peer-noise-identity-state-file")?.map(PathBuf::from);
    let peer_noise_rotation_file = option(args, "--peer-noise-rotation-file")?.map(PathBuf::from);
    if option(args, "--peer-noise-issuer-public-key-hex")?.is_some() {
        return Err("--peer-noise-issuer-public-key-hex was removed; use the signed issuer registry and a pinned governance public key".into());
    }
    let peer_noise_issuer_registry_file =
        option(args, "--peer-noise-issuer-registry-file")?.map(PathBuf::from);
    let peer_noise_issuer_registry_state_file =
        option(args, "--peer-noise-issuer-registry-state-file")?.map(PathBuf::from);
    // Trust roots and version floors are carried in a signed DPC1 deployment manifest. Keep the
    // signing authority and minimum config sequence as out-of-band launch inputs; reject the older
    // individual root/epoch options rather than letting callers bypass the signed bundle.
    let legacy_registry_root =
        option(args, "--peer-noise-issuer-registry-admin-public-key-hex")?.is_some();
    let legacy_root_anchor =
        option(args, "--peer-noise-issuer-root-anchor-public-key-hex")?.is_some();
    let legacy_root_recovery =
        option(args, "--peer-noise-issuer-root-recovery-public-key-hex")?.is_some();
    let legacy_root_chain = option(args, "--peer-noise-issuer-root-chain-file")?.is_some();
    let legacy_root_epoch = option(args, "--peer-noise-issuer-root-min-epoch")?.is_some();
    let legacy_registry_floor =
        option(args, "--peer-noise-issuer-registry-min-sequence")?.is_some();
    if legacy_registry_root
        || legacy_root_anchor
        || legacy_root_recovery
        || legacy_root_chain
        || legacy_root_epoch
        || legacy_registry_floor
    {
        return Err("individual governance roots/floors were removed; use the signed --peer-noise-deployment-config-file".into());
    }
    let peer_noise_deployment_config_file =
        option(args, "--peer-noise-deployment-config-file")?.map(PathBuf::from);
    let peer_noise_deployment_config_state_file =
        option(args, "--peer-noise-deployment-config-state-file")?.map(PathBuf::from);
    let peer_noise_deployment_authority_public_key =
        option(args, "--peer-noise-deployment-authority-public-key-hex")?
            .map(|value| hex32(&value, "--peer-noise-deployment-authority-public-key-hex"))
            .transpose()?;
    if peer_noise_deployment_authority_public_key
        .is_some_and(|key| key.iter().all(|byte| *byte == 0))
    {
        return Err("--peer-noise-deployment-authority-public-key-hex cannot be all zero".into());
    }
    let peer_noise_deployment_min_sequence = option(args, "--peer-noise-deployment-min-sequence")?
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|_| "invalid --peer-noise-deployment-min-sequence".to_string())
        })
        .transpose()?;
    if peer_noise_deployment_min_sequence == Some(0) {
        return Err("--peer-noise-deployment-min-sequence must be greater than zero".into());
    }
    let peer_noise_key_id = option(args, "--peer-noise-key-id")?
        .map(|value| {
            value
                .parse::<u32>()
                .map_err(|_| "invalid --peer-noise-key-id".to_string())
        })
        .transpose()?;
    let peer_noise_credential_id = option(args, "--peer-noise-credential-id")?
        .map(|value| {
            value
                .parse::<u128>()
                .map_err(|_| "invalid --peer-noise-credential-id".to_string())
        })
        .transpose()?;
    let peer_noise_issuer_id = option(args, "--peer-noise-issuer-id")?
        .map(|value| {
            value
                .parse::<u32>()
                .map_err(|_| "invalid --peer-noise-issuer-id".to_string())
        })
        .transpose()?;
    let peer_noise_binding_max_validity =
        number(args, "--peer-noise-max-validity-seconds", 31_536_000u64)?;
    let has_identity_metadata = peer_noise_key_id.is_some()
        || peer_noise_credential_id.is_some()
        || peer_noise_issuer_id.is_some()
        || peer_noise_identity_signature_file.is_some()
        || peer_noise_identity_state_file.is_some()
        || peer_noise_rotation_file.is_some()
        || peer_noise_issuer_registry_file.is_some()
        || peer_noise_issuer_registry_state_file.is_some()
        || peer_noise_deployment_config_file.is_some()
        || peer_noise_deployment_config_state_file.is_some()
        || peer_noise_deployment_authority_public_key.is_some()
        || peer_noise_deployment_min_sequence.is_some()
        || option(args, "--peer-noise-max-validity-seconds")?.is_some();
    let noise_identity_mode = peer_noise_identity_record_file.is_some();
    if noise_identity_mode {
        if peer_noise_identity_signature_file.is_none()
            || peer_noise_issuer_registry_file.is_none()
            || peer_noise_issuer_registry_state_file.is_none()
            || peer_noise_deployment_config_file.is_none()
            || peer_noise_deployment_config_state_file.is_none()
            || peer_noise_deployment_authority_public_key.is_none()
            || peer_noise_deployment_min_sequence.is_none()
        {
            return Err("provider-bound Noise XX requires identity signature/registry/state plus signed deployment config, deployment state, out-of-band config signing key, and minimum config sequence".into());
        }
        if peer_noise_identity_state_file.is_none() || peer_noise_rotation_file.is_none() {
            return Err("provider-bound Noise XX requires --peer-noise-identity-state-file and --peer-noise-rotation-file".into());
        }
        if peer_noise_static_private_key_dpapi_file.is_none()
            || peer_noise_allowed_public_key.is_some()
        {
            return Err("provider-bound Noise XX requires --peer-noise-static-private-key-dpapi-file and --peer-noise-identity-record-file, and forbids --peer-noise-allowed-public-key-hex".into());
        }
        if peer_noise_key_id.unwrap_or(0) == 0
            || peer_noise_credential_id.unwrap_or(0) == 0
            || peer_noise_issuer_id.unwrap_or(0) == 0
        {
            return Err("provider-bound Noise XX requires nonzero --peer-noise-key-id, --peer-noise-credential-id, and --peer-noise-issuer-id".into());
        }
        if peer_noise_binding_max_validity == 0 {
            return Err("--peer-noise-max-validity-seconds must be greater than zero".into());
        }
        let identity_paths = [
            peer_noise_identity_record_file.as_ref(),
            peer_noise_identity_signature_file.as_ref(),
            peer_noise_identity_state_file.as_ref(),
            peer_noise_rotation_file.as_ref(),
            peer_noise_issuer_registry_file.as_ref(),
            peer_noise_issuer_registry_state_file.as_ref(),
            peer_noise_deployment_config_file.as_ref(),
            peer_noise_deployment_config_state_file.as_ref(),
            peer_noise_static_private_key_dpapi_file.as_ref(),
        ];
        for (index, maybe_path) in identity_paths.iter().enumerate() {
            if let Some(path) = *maybe_path {
                if identity_paths
                    .iter()
                    .skip(index + 1)
                    .flatten()
                    .any(|other| *other == path)
                {
                    return Err("provider-bound Noise record/signature/state/rotation/registry/key paths must be distinct".into());
                }
                if path == &snapshot_path
                    || Some(path) == reference_time_state_path.as_ref()
                    || Some(path) == reference_time_policy_path.as_ref()
                {
                    return Err("provider-bound Noise identity files must differ from the chain snapshot and reference-time state".into());
                }
            }
        }
    } else {
        if peer_noise_static_private_key_dpapi_file.is_some()
            != peer_noise_allowed_public_key.is_some()
        {
            return Err("Noise XX pinned mode requires both --peer-noise-static-private-key-dpapi-file and --peer-noise-allowed-public-key-hex".into());
        }
        if has_identity_metadata {
            return Err("provider identity metadata/signature options require --peer-noise-identity-record-file".into());
        }
    }
    let noise_pinned_mode = peer_noise_static_private_key_dpapi_file.is_some()
        && peer_noise_allowed_public_key.is_some();
    if noise_pinned_mode {
        let private_key_path = peer_noise_static_private_key_dpapi_file
            .as_ref()
            .expect("pinned mode requires a private-key path");
        if private_key_path == &snapshot_path
            || Some(private_key_path) == reference_time_state_path.as_ref()
            || Some(private_key_path) == reference_time_policy_path.as_ref()
        {
            return Err("Noise private-key file must differ from the chain snapshot and reference-time state".into());
        }
    }
    let allow_unauthenticated_test_peer = option(args, "--allow-unauthenticated-test-peer")?
        .unwrap_or_else(|| "false".to_string())
        .parse::<bool>()
        .map_err(|_| "--allow-unauthenticated-test-peer must be true or false".to_string())?;
    let selected_modes = usize::from(peer_psk.is_some())
        + usize::from(noise_pinned_mode)
        + usize::from(noise_identity_mode)
        + usize::from(allow_unauthenticated_test_peer);
    if selected_modes != 1 {
        return Err("select exactly one peer mode: --peer-psk-hex, pinned Noise XX key pair, provider-bound Noise XX (--peer-noise-identity-record-file plus credential metadata), or --allow-unauthenticated-test-peer true".into());
    }
    Ok(Config {
        port,
        network_id,
        public_key,
        genesis_balance: number(&args, "--genesis-balance", 1_000_000u64)?,
        snapshot_path,
        reference_time_policy_path,
        reference_time_admin_public_key,
        reference_time_address,
        reference_time_state_path,
        peer_psk,
        peer_noise_static_private_key_dpapi_file,
        peer_noise_allowed_public_key,
        peer_noise_identity_record_file,
        peer_noise_identity_signature_file,
        peer_noise_identity_state_file,
        peer_noise_rotation_file,
        peer_noise_issuer_registry_file,
        peer_noise_issuer_registry_state_file,
        peer_noise_deployment_config_file,
        peer_noise_deployment_config_state_file,
        peer_noise_deployment_authority_public_key,
        peer_noise_deployment_min_sequence,
        peer_noise_key_id,
        peer_noise_credential_id,
        peer_noise_issuer_id,
        peer_noise_binding_max_validity,
        allow_unauthenticated_test_peer,
        connections: number(&args, "--connections", 1u32)?,
        duration_ms: number(&args, "--duration-ms", 30_000u64)?,
        mode,
        reference_time_unix_seconds,
        allow_test_time_fixtures,
    })
}

/// The fixed provider is available only behind an explicit test-fixture CLI opt-in.
/// It is not a trusted-clock implementation and must never be used as a network default.
enum NodeReferenceTime {
    SystemClock,
    FixedTestFixture(u64),
    Authenticated(AuthenticatedReferenceTimeProvider<TcpReferenceTimeExchange>),
}

impl ReferenceTimeProvider for NodeReferenceTime {
    fn sample(&self) -> Result<ReferenceTimeSample, ReferenceTimeError> {
        match self {
            Self::SystemClock => SystemClockReferenceTime.sample(),
            Self::FixedTestFixture(unix_seconds) => Ok(ReferenceTimeSample {
                unix_seconds: *unix_seconds,
                provenance: ReferenceTimeProvenance::DeterministicTestFixture,
                source_id: "cp0026i-test-fixed-clock",
            }),
            Self::Authenticated(provider) => provider.sample(),
        }
    }
}

fn build_authenticated_reference_time(
    config: &Config,
) -> Result<Option<AuthenticatedReferenceTimeProvider<TcpReferenceTimeExchange>>, String> {
    let (Some(policy_path), Some(admin_public_key), Some(address), Some(state_path)) = (
        config.reference_time_policy_path.as_ref(),
        config.reference_time_admin_public_key,
        config.reference_time_address,
        config.reference_time_state_path.as_ref(),
    ) else {
        return Ok(None);
    };

    let file = File::open(policy_path)
        .map_err(|error| format!("cannot open signed reference-time policy: {error}"))?;
    let length = file
        .metadata()
        .map_err(|error| format!("cannot inspect signed reference-time policy: {error}"))?
        .len();
    if length != POLICY_WIRE_LEN as u64 {
        return Err(format!(
            "signed reference-time policy must be exactly {POLICY_WIRE_LEN} bytes"
        ));
    }
    let mut policy_bytes = Vec::with_capacity(POLICY_WIRE_LEN);
    file.take((POLICY_WIRE_LEN + 1) as u64)
        .read_to_end(&mut policy_bytes)
        .map_err(|error| format!("cannot read signed reference-time policy: {error}"))?;
    if policy_bytes.len() != POLICY_WIRE_LEN {
        return Err("signed reference-time policy changed length while being read".into());
    }

    let store = ReferenceTimeStateStore::open(state_path, &config.network_id)
        .map_err(|error| format!("cannot open durable reference-time state: {error:?}"))?;
    let trust_state = store
        .policy_trust_state()
        .map_err(|error| format!("cannot restore reference-time policy high-water: {error:?}"))?;
    let policy = VerifiedReferenceTimePolicy::verify(
        &policy_bytes,
        &config.network_id,
        &admin_public_key,
        &trust_state,
    )
    .map_err(|error| format!("signed reference-time policy rejected: {error:?}"))?;
    let provider = AuthenticatedReferenceTimeProvider::new_persistent(
        policy,
        TcpReferenceTimeExchange::new(address),
        store,
    )
    .map_err(|error| format!("cannot initialize persistent reference-time provider: {error:?}"))?;
    Ok(Some(provider))
}

fn read_exact_until(
    stream: &mut TcpStream,
    output: &mut [u8],
    deadline: Instant,
) -> io::Result<()> {
    let mut offset = 0usize;
    while offset < output.len() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "import frame deadline",
            ));
        }
        stream.set_read_timeout(Some(remaining.min(Duration::from_millis(READ_SLICE_MS))))?;
        match stream.read(&mut output[offset..]) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "peer closed")),
            Ok(count) => offset += count,
            Err(error)
                if error.kind() == io::ErrorKind::TimedOut
                    || error.kind() == io::ErrorKind::WouldBlock =>
            {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "import frame deadline",
                    ));
                }
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn read_block_frame(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let deadline = Instant::now() + Duration::from_millis(FRAME_DEADLINE_MS);
    let mut length_bytes = [0u8; 4];
    read_exact_until(stream, &mut length_bytes, deadline)?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    if length == 0 || length > MAX_ENCODED_BLOCK_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid block frame length",
        ));
    }
    let mut block = vec![0u8; length];
    read_exact_until(stream, &mut block, deadline)?;
    Ok(block)
}

#[derive(Debug, Clone, Copy)]
struct AuthenticatedPeerSession {
    receive_key: [u8; 32],
    send_key: [u8; 32],
}

enum PeerSession {
    Hmac(AuthenticatedPeerSession),
    Noise(snow::TransportState),
    NoiseIdentity {
        transport: snow::TransportState,
        identity: BoundNoiseIdentity,
    },
}

#[derive(Debug)]
struct BoundNoiseIdentity {
    session: BoundSession,
    binding: CredentialBinding,
    remote_static_public_key: [u8; 32],
    max_validity: u64,
}

struct NoiseHandshakeResult {
    transport: snow::TransportState,
    remote_static_public_key: [u8; 32],
    handshake_hash: Vec<u8>,
}

/// Reads a single canonical public KeyRecord envelope on every provider call.
/// Re-reading is deliberate: a rotated or revoked file must affect the next import.
struct FileNoiseKeyProvider {
    record_file: PathBuf,
    signature_file: PathBuf,
    rotation_file: PathBuf,
    issuer_registry_file: PathBuf,
    issuer_registry_state: Arc<IssuerRegistryStateStore>,
    identity_state: Arc<IdentityGenerationStateStore>,
    expected_key_id: u32,
    credential_id: u128,
    issuer_id: u32,
}

fn read_bounded_provider_file(path: &PathBuf, max_bytes: usize) -> Result<Vec<u8>, ProviderError> {
    let file = File::open(path).map_err(|_| ProviderError::NotFound)?;
    let mut bytes = Vec::with_capacity(max_bytes.min(4096));
    file.take((max_bytes + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ProviderError::NotFound)?;
    if bytes.len() > max_bytes {
        return Err(ProviderError::InvalidKey(IdentityError::Oversize(
            bytes.len(),
        )));
    }
    Ok(bytes)
}

impl FileNoiseKeyProvider {
    fn load_record(&self) -> Result<KeyRecord, ProviderError> {
        let bytes = read_bounded_provider_file(
            &self.record_file,
            IDENTITY_RECORD_HEADER_LEN + MAX_IDENTITY_PUBLIC_KEY_BYTES,
        )?;
        let record = decode_key_record(&bytes).map_err(ProviderError::InvalidKey)?;
        if record.key_id != self.expected_key_id {
            return Err(ProviderError::NotFound);
        }
        if self.credential_id == 0 || self.issuer_id == 0 {
            return Err(ProviderError::InvalidKey(IdentityError::Malformed));
        }
        let registry_wire =
            read_bounded_provider_file(&self.issuer_registry_file, MAX_REGISTRY_WIRE_LEN)?;
        let trusted_issuer_public_key = self
            .issuer_registry_state
            .accept_signed_registry(&registry_wire, self.issuer_id)
            .map_err(|error| {
                ProviderError::IdentityState(format!("issuer registry rejected: {error:?}"))
            })?;
        let issuer = VerifyingKey::from_bytes(&trusted_issuer_public_key)
            .map_err(|_| ProviderError::InvalidKey(IdentityError::Malformed))?;
        let signature_bytes = read_bounded_provider_file(&self.signature_file, 64)?;
        if signature_bytes.len() != 64 {
            return Err(ProviderError::InvalidKey(IdentityError::Malformed));
        }
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|_| ProviderError::InvalidKey(IdentityError::Malformed))?;
        let mut message = Vec::with_capacity(48 + bytes.len());
        message.extend_from_slice(b"AIN1-NOISE-IDENTITY-RECORD-SIG-V1\0");
        message.extend_from_slice(&self.credential_id.to_be_bytes());
        message.extend_from_slice(&self.issuer_id.to_be_bytes());
        message.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        message.extend_from_slice(&bytes);
        issuer
            .verify_strict(&message, &signature)
            .map_err(|_| ProviderError::InvalidKey(IdentityError::Malformed))?;
        let rotation_wire = if self.rotation_file.exists() {
            Some(read_bounded_provider_file(
                &self.rotation_file,
                ROTATION_WIRE_LEN,
            )?)
        } else {
            None
        };
        self.identity_state
            .observe_signed_record(&bytes, &record, rotation_wire.as_deref())
            .map_err(|error| ProviderError::IdentityState(format!("{error:?}")))?;
        Ok(record)
    }
}

impl PublicKeyProvider for FileNoiseKeyProvider {
    fn resolve(
        &self,
        key_id: u32,
        generation: u32,
        purpose: KeyPurpose,
    ) -> Result<KeyRecord, ProviderError> {
        if key_id != self.expected_key_id {
            return Err(ProviderError::NotFound);
        }
        let record = self.load_record()?;
        if record.generation != generation {
            return Err(ProviderError::NotFound);
        }
        if record.purpose != purpose {
            return Err(ProviderError::PurposeMismatch);
        }
        Ok(record)
    }

    fn current(&self, key_id: u32, purpose: KeyPurpose) -> Result<KeyRecord, ProviderError> {
        if key_id != self.expected_key_id {
            return Err(ProviderError::NotFound);
        }
        let record = self.load_record()?;
        if record.purpose != purpose {
            return Err(ProviderError::PurposeMismatch);
        }
        if record.state == KeyState::Revoked {
            return Err(ProviderError::NotFound);
        }
        Ok(record)
    }

    fn authorize(
        &self,
        key_id: u32,
        generation: u32,
        purpose: KeyPurpose,
        epoch: u64,
        policy: CryptoPolicy,
    ) -> Result<KeyRecord, ProviderError> {
        let record = self.resolve(key_id, generation, purpose)?;
        if !record.is_valid_at(epoch) {
            return Err(ProviderError::InvalidKey(IdentityError::InvalidWindow));
        }
        if let Some(lock) = policy.pq_lock_epoch {
            if epoch >= lock && record.algorithm.security_class() < policy.min_class {
                return Err(ProviderError::InvalidKey(IdentityError::DowngradeBlocked));
            }
        }
        Ok(record)
    }
}

const NOISE_XX_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
const NOISE_XX_PROLOGUE: &[u8] = b"AI-NATIVE-L1/chain-import-noise-xx-v1";
const MAX_NOISE_HANDSHAKE: usize = 1024;
const MAX_NOISE_RECORD: usize = MAX_ENCODED_BLOCK_BYTES + 1024;

fn authenticate_peer(
    stream: &mut TcpStream,
    psk: &[u8; 32],
) -> Result<AuthenticatedPeerSession, String> {
    let deadline = Instant::now() + Duration::from_millis(FRAME_DEADLINE_MS);
    let mut hello = vec![0u8; AUTH_HELLO_LEN];
    read_exact_until(stream, &mut hello, deadline)
        .map_err(|error| format!("authenticated hello read failed: {error}"))?;
    let (role, client_nonce) = verify_auth_hello(psk, &hello)
        .map_err(|error| format!("authenticated hello rejected: {error:?}"))?;
    if role != 1 {
        return Err(format!(
            "authenticated hello role rejected: expected client role 1, got {role}"
        ));
    }
    let server_nonce =
        random_nonce().map_err(|error| format!("server session nonce failed: {error:?}"))?;
    let ack = make_auth_ack(psk, client_nonce, server_nonce);
    if ack.len() != AUTH_ACK_LEN {
        return Err("internal authenticated ack length mismatch".into());
    }
    write_all_until(stream, &ack, deadline)
        .map_err(|error| format!("authenticated ack write failed: {error}"))?;
    Ok(AuthenticatedPeerSession {
        receive_key: derive_direction_key(psk, client_nonce, server_nonce, 0),
        send_key: derive_direction_key(psk, client_nonce, server_nonce, 1),
    })
}

fn read_noise_handshake_message(
    stream: &mut TcpStream,
    deadline: Instant,
) -> Result<Vec<u8>, String> {
    let mut length_bytes = [0u8; 2];
    read_exact_until(stream, &mut length_bytes, deadline)
        .map_err(|error| format!("Noise handshake length read failed: {error}"))?;
    let length = u16::from_be_bytes(length_bytes) as usize;
    if length == 0 || length > MAX_NOISE_HANDSHAKE {
        return Err(format!(
            "Noise handshake message length out of bounds: {length}"
        ));
    }
    let mut message = vec![0u8; length];
    read_exact_until(stream, &mut message, deadline)
        .map_err(|error| format!("Noise handshake message read failed: {error}"))?;
    Ok(message)
}

fn write_noise_handshake_message(
    stream: &mut TcpStream,
    message: &[u8],
    deadline: Instant,
) -> Result<(), String> {
    if message.is_empty()
        || message.len() > MAX_NOISE_HANDSHAKE
        || message.len() > u16::MAX as usize
    {
        return Err(format!(
            "Noise handshake message length out of bounds: {}",
            message.len()
        ));
    }
    write_all_until(stream, &(message.len() as u16).to_be_bytes(), deadline)
        .and_then(|_| write_all_until(stream, message, deadline))
        .map_err(|error| format!("Noise handshake message write failed: {error}"))
}

fn authenticate_noise_peer_context(
    stream: &mut TcpStream,
    local_static_private_key: &[u8; 32],
    pinned_remote_static_public_key: &[u8; 32],
) -> Result<NoiseHandshakeResult, String> {
    let deadline = Instant::now() + Duration::from_millis(FRAME_DEADLINE_MS);
    let params = NOISE_XX_PATTERN
        .parse()
        .map_err(|error: snow::Error| format!("Noise XX pattern rejected: {error}"))?;
    let builder = Builder::new(params)
        .prologue(NOISE_XX_PROLOGUE)
        .local_private_key(local_static_private_key);
    let mut handshake = builder
        .build_responder()
        .map_err(|error| format!("Noise XX responder initialization failed: {error}"))?;
    let mut payload = vec![0u8; MAX_NOISE_HANDSHAKE];

    // XX message 1: initiator ephemeral key, no application payload.
    let first = read_noise_handshake_message(stream, deadline)?;
    let first_len = handshake
        .read_message(&first, &mut payload)
        .map_err(|error| format!("Noise XX message 1 rejected: {error}"))?;
    if first_len != 0 {
        return Err("Noise XX message 1 must not carry application data".into());
    }

    // XX message 2: responder ephemeral + encrypted responder static key.
    let mut message = vec![0u8; MAX_NOISE_HANDSHAKE];
    let written = handshake
        .write_message(&[], &mut message)
        .map_err(|error| format!("Noise XX message 2 construction failed: {error}"))?;
    write_noise_handshake_message(stream, &message[..written], deadline)?;

    // XX message 3: initiator encrypted static key; only now is the remote identity known.
    let third = read_noise_handshake_message(stream, deadline)?;
    let third_len = handshake
        .read_message(&third, &mut payload)
        .map_err(|error| format!("Noise XX message 3 rejected: {error}"))?;
    if third_len != 0 {
        return Err("Noise XX message 3 must not carry application data".into());
    }
    let remote_static = handshake
        .get_remote_static()
        .ok_or_else(|| "Noise XX completed without a remote static key".to_string())?;
    if remote_static != pinned_remote_static_public_key {
        return Err("Noise XX remote static key does not match the pinned peer identity".into());
    }
    let mut remote_static_public_key = [0u8; 32];
    remote_static_public_key.copy_from_slice(remote_static);
    let handshake_hash = handshake.get_handshake_hash().to_vec();
    let transport = handshake
        .into_transport_mode()
        .map_err(|error| format!("Noise XX transport activation failed: {error}"))?;
    Ok(NoiseHandshakeResult {
        transport,
        remote_static_public_key,
        handshake_hash,
    })
}

fn authenticate_noise_peer(
    stream: &mut TcpStream,
    local_static_private_key: &[u8; 32],
    pinned_remote_static_public_key: &[u8; 32],
) -> Result<snow::TransportState, String> {
    authenticate_noise_peer_context(
        stream,
        local_static_private_key,
        pinned_remote_static_public_key,
    )
    .map(|result| result.transport)
}

fn current_unix_epoch() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| format!("system time predates Unix epoch: {error}"))
}

fn noise_key_crypto_policy() -> CryptoPolicy {
    // Noise_XX uses classical X25519. PQ migration requires a different transport profile.
    CryptoPolicy {
        min_class: SecurityClass::Classical,
        pq_lock_epoch: None,
    }
}

fn validate_noise_record_shape(record: &KeyRecord) -> Result<(), String> {
    if record.algorithm != KeyAlgorithm::NoiseX25519 {
        return Err("provider record algorithm must be NoiseX25519".into());
    }
    if record.purpose != KeyPurpose::PeerAuth {
        return Err("provider record purpose must be PeerAuth".into());
    }
    if record.public_key.len() != 32 {
        return Err("provider NoiseX25519 public key must be exactly 32 bytes".into());
    }
    Ok(())
}

fn authenticate_provider_bound_noise_peer(
    stream: &mut TcpStream,
    local_static_private_key: &[u8; 32],
    provider: &FileNoiseKeyProvider,
    credential_id: u128,
    issuer_id: u32,
    max_validity: u64,
) -> Result<(snow::TransportState, BoundNoiseIdentity), String> {
    if credential_id == 0 || issuer_id == 0 {
        return Err("credential and issuer identifiers must be nonzero".into());
    }
    let key_id = provider.expected_key_id;
    let epoch = current_unix_epoch()?;
    let record = provider
        .current(key_id, KeyPurpose::PeerAuth)
        .map_err(|error| format!("Noise identity provider lookup failed: {error:?}"))?;
    validate_noise_record_shape(&record)?;
    let authorized = provider
        .authorize(
            key_id,
            record.generation,
            KeyPurpose::PeerAuth,
            epoch,
            noise_key_crypto_policy(),
        )
        .map_err(|error| format!("Noise identity provider authorization failed: {error:?}"))?;
    if authorized != record {
        return Err("Noise identity provider record changed during authorization".into());
    }

    let pinned_remote: [u8; 32] = record
        .public_key
        .as_slice()
        .try_into()
        .map_err(|_| "provider NoiseX25519 public key has invalid length".to_string())?;
    let handshake =
        authenticate_noise_peer_context(stream, local_static_private_key, &pinned_remote)?;
    if handshake.remote_static_public_key != pinned_remote {
        return Err("Noise remote static key differs from provider record".into());
    }

    // Re-resolve after the handshake to close the lookup/handshake rotation window.
    let post_handshake_epoch = current_unix_epoch()?;
    let post_handshake_record = provider
        .authorize(
            key_id,
            record.generation,
            KeyPurpose::PeerAuth,
            post_handshake_epoch,
            noise_key_crypto_policy(),
        )
        .map_err(|error| format!("Noise identity changed during handshake: {error:?}"))?;
    if post_handshake_record != record {
        return Err("Noise identity provider record changed during handshake".into());
    }
    let binding = CredentialBinding::from_key(
        credential_id,
        issuer_id,
        &record,
        &handshake.remote_static_public_key,
    );
    binding
        .validate(
            &record,
            post_handshake_epoch,
            BindingPolicy {
                max_validity,
                pq_required_after: None,
            },
            &handshake.remote_static_public_key,
        )
        .map_err(|error| format!("Noise credential binding rejected: {error:?}"))?;
    let context = session_identity_context(&binding, &handshake.handshake_hash);
    let session = BoundSession::bind(&record, context)
        .map_err(|error| format!("Noise bound session creation failed: {error:?}"))?;
    Ok((
        handshake.transport,
        BoundNoiseIdentity {
            session,
            binding,
            remote_static_public_key: handshake.remote_static_public_key,
            max_validity,
        },
    ))
}

fn revalidate_provider_bound_noise_identity(
    identity: &mut BoundNoiseIdentity,
    provider: &FileNoiseKeyProvider,
) -> Result<(), String> {
    let epoch = current_unix_epoch()?;
    identity
        .session
        .revalidate(provider, epoch, noise_key_crypto_policy())
        .map_err(|error| {
            format!("provider-bound Noise session rejected before import: {error:?}")
        })?;
    let record = provider
        .authorize(
            identity.session.key_id(),
            identity.session.generation(),
            KeyPurpose::PeerAuth,
            epoch,
            noise_key_crypto_policy(),
        )
        .map_err(|error| format!("Noise identity not authorized before import: {error:?}"))?;
    validate_noise_record_shape(&record)?;
    if record.public_key.as_slice() != identity.remote_static_public_key
        || identity.binding.not_before != record.not_before
        || identity.binding.not_after != record.not_after
    {
        return Err(
            "Noise identity key material or validity changed without a new generation".into(),
        );
    }
    identity
        .binding
        .validate(
            &record,
            epoch,
            BindingPolicy {
                max_validity: identity.max_validity,
                pq_required_after: None,
            },
            &identity.remote_static_public_key,
        )
        .map_err(|error| format!("Noise credential binding no longer valid: {error:?}"))?;
    Ok(())
}

fn read_noise_request(
    stream: &mut TcpStream,
    transport: &mut snow::TransportState,
) -> Result<Frame, String> {
    let deadline = Instant::now() + Duration::from_millis(FRAME_DEADLINE_MS);
    let mut length_bytes = [0u8; 4];
    read_exact_until(stream, &mut length_bytes, deadline)
        .map_err(|error| format!("Noise record length read failed: {error}"))?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    if length == 0 || length > MAX_NOISE_RECORD {
        return Err(format!("Noise record length out of bounds: {length}"));
    }
    let mut ciphertext = vec![0u8; length];
    read_exact_until(stream, &mut ciphertext, deadline)
        .map_err(|error| format!("Noise record read failed: {error}"))?;
    let mut plaintext = vec![0u8; length];
    let plain_len = transport
        .read_message(&ciphertext, &mut plaintext)
        .map_err(|error| format!("Noise authenticated record rejected: {error}"))?;
    plaintext.truncate(plain_len);
    let frame = decode_frame(&plaintext)
        .map_err(|error| format!("Noise AIN1 frame rejected: {error:?}"))?;
    if plaintext.len() != ai_native_l1_pow_bench::HEADER_LEN + frame.payload.len() {
        return Err("Noise request frame has trailing bytes".into());
    }
    if frame.version != PROTOCOL_VERSION
        || frame.message_type != MessageType::Blocks as u16
        || frame.request_id == 0
    {
        return Err("Noise request must be a nonzero-ID Blocks frame".into());
    }
    if frame.payload.is_empty() || frame.payload.len() > MAX_ENCODED_BLOCK_BYTES {
        return Err(format!(
            "Noise block payload length out of bounds: {}",
            frame.payload.len()
        ));
    }
    Ok(frame)
}

fn write_noise_reply(
    stream: &mut TcpStream,
    transport: &mut snow::TransportState,
    request_id: u64,
    message: &str,
) -> io::Result<()> {
    if message.len() > MAX_REPLY_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "reply length"));
    }
    let frame = encode_frame(
        PROTOCOL_VERSION,
        MessageType::BlockImportReceipt as u16,
        request_id,
        message.as_bytes(),
    )
    .map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("receipt encode failed: {error:?}"),
        )
    })?;
    let mut ciphertext = vec![0u8; frame.len() + 128];
    let cipher_len = transport
        .write_message(&frame, &mut ciphertext)
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Noise receipt encryption failed: {error}"),
            )
        })?;
    let ciphertext = &ciphertext[..cipher_len];
    let deadline = Instant::now() + Duration::from_millis(FRAME_DEADLINE_MS);
    write_all_until(stream, &(ciphertext.len() as u32).to_be_bytes(), deadline)?;
    write_all_until(stream, ciphertext, deadline)
}

fn write_all_until(stream: &mut TcpStream, bytes: &[u8], deadline: Instant) -> io::Result<()> {
    let mut offset = 0usize;
    while offset < bytes.len() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "authenticated write deadline",
            ));
        }
        stream.set_write_timeout(Some(remaining.min(Duration::from_millis(READ_SLICE_MS))))?;
        match stream.write(&bytes[offset..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "peer closed during write",
                ))
            }
            Ok(count) => offset += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error)
                if error.kind() == io::ErrorKind::TimedOut
                    || error.kind() == io::ErrorKind::WouldBlock =>
            {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "authenticated write deadline",
                    ));
                }
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn read_authenticated_request(
    stream: &mut TcpStream,
    receive_key: &[u8; 32],
) -> Result<Frame, String> {
    let deadline = Instant::now() + Duration::from_millis(FRAME_DEADLINE_MS);
    let mut length_bytes = [0u8; 4];
    read_exact_until(stream, &mut length_bytes, deadline)
        .map_err(|error| format!("authenticated record length read failed: {error}"))?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    if !(RECORD_HEADER_LEN + AUTH_TAG_LEN..=MAX_AUTH_RECORD).contains(&length) {
        return Err(format!(
            "authenticated record length out of bounds: {length}"
        ));
    }
    let mut record = vec![0u8; length];
    read_exact_until(stream, &mut record, deadline)
        .map_err(|error| format!("authenticated record read failed: {error}"))?;
    let frame_bytes = open_record(receive_key, 0, &record)
        .map_err(|error| format!("authenticated request record rejected: {error:?}"))?;
    let frame = decode_frame(&frame_bytes)
        .map_err(|error| format!("authenticated AIN1 frame rejected: {error:?}"))?;
    if frame_bytes.len() != ai_native_l1_pow_bench::HEADER_LEN + frame.payload.len() {
        return Err("authenticated request frame has trailing bytes".into());
    }
    if frame.version != PROTOCOL_VERSION
        || frame.message_type != MessageType::Blocks as u16
        || frame.request_id == 0
    {
        return Err("authenticated request must be a nonzero-ID Blocks frame".into());
    }
    if frame.payload.is_empty() || frame.payload.len() > MAX_ENCODED_BLOCK_BYTES {
        return Err(format!(
            "authenticated block payload length out of bounds: {}",
            frame.payload.len()
        ));
    }
    Ok(frame)
}

fn write_authenticated_reply(
    stream: &mut TcpStream,
    send_key: &[u8; 32],
    request_id: u64,
    message: &str,
) -> io::Result<()> {
    if message.len() > MAX_REPLY_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "reply length"));
    }
    let frame = encode_frame(
        PROTOCOL_VERSION,
        MessageType::BlockImportReceipt as u16,
        request_id,
        message.as_bytes(),
    )
    .map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("receipt encode failed: {error:?}"),
        )
    })?;
    let record = seal_record(send_key, 0, &frame).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("receipt seal failed: {error:?}"),
        )
    })?;
    let deadline = Instant::now() + Duration::from_millis(FRAME_DEADLINE_MS);
    write_all_until(stream, &(record.len() as u32).to_be_bytes(), deadline)?;
    write_all_until(stream, &record, deadline)
}

fn write_session_reply(
    stream: &mut TcpStream,
    session: Option<&mut PeerSession>,
    request_id: Option<u64>,
    message: &str,
) -> io::Result<()> {
    match session {
        Some(PeerSession::Hmac(session)) => match request_id {
            Some(request_id) => {
                write_authenticated_reply(stream, &session.send_key, request_id, message)
            }
            None => Ok(()),
        },
        Some(PeerSession::Noise(transport)) => match request_id {
            Some(request_id) => write_noise_reply(stream, transport, request_id, message),
            None => Ok(()),
        },
        Some(PeerSession::NoiseIdentity { transport, .. }) => match request_id {
            Some(request_id) => write_noise_reply(stream, transport, request_id, message),
            None => Ok(()),
        },
        None => write_reply(stream, message),
    }
}

fn write_reply(stream: &mut TcpStream, message: &str) -> io::Result<()> {
    let bytes = message.as_bytes();
    if bytes.len() > MAX_REPLY_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "reply length"));
    }
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(bytes)
}

fn bytes_hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Secret holder that overwrites its local copy on drop. OS ACLs and protected storage remain
/// operational responsibilities; this only keeps the private bytes out of process argv.
struct NoisePrivateKey([u8; 32]);

impl Deref for NoisePrivateKey {
    type Target = [u8; 32];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for NoisePrivateKey {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

fn read_protected_noise_private_key_file(
    path: &Path,
    network_id: &[u8; 32],
) -> Result<NoisePrivateKey, String> {
    let mut key = ai_native_l1_pow_bench::noise_key_provisioning::load_protected_noise_private_key(
        path, network_id,
    )
    .map_err(|error| format!("Noise DPAPI private-key load rejected: {error}"))?;
    let held = NoisePrivateKey(key);
    key.fill(0);
    Ok(held)
}
fn main_result() -> Result<(), String> {
    let config = config()?;
    // Load secret bytes before binding; never accept raw private-key argv.
    let peer_noise_static_private_key = config
        .peer_noise_static_private_key_dpapi_file
        .as_deref()
        .map(|path| read_protected_noise_private_key_file(path, &config.network_id))
        .transpose()?;
    if config.connections == 0 {
        return Err("--connections must be at least 1".into());
    }
    if let Some(parent) = config.snapshot_path.parent() {
        if !parent.as_os_str().is_empty() && !parent.is_dir() {
            return Err("snapshot parent directory must already exist".into());
        }
    }
    // Keep the deployment-state lock alive for the full node lifetime. This serializes launchers
    // sharing the same DCS1 high-water file and persists trust changes before network admission.
    let mut _deployment_config_state_guard: Option<DeploymentConfigStateStore> = None;
    let issuer_registry_state = if config.peer_noise_identity_record_file.is_some() {
        let manifest_path = config
            .peer_noise_deployment_config_file
            .as_ref()
            .ok_or_else(|| {
                "provider-bound Noise mode lost its signed deployment manifest path".to_string()
            })?;
        let deployment_state_path = config
            .peer_noise_deployment_config_state_file
            .as_ref()
            .ok_or_else(|| {
                "provider-bound Noise mode lost its deployment-state path".to_string()
            })?;
        let deployment_authority = config
            .peer_noise_deployment_authority_public_key
            .ok_or_else(|| {
                "provider-bound Noise mode lost its out-of-band deployment authority key"
                    .to_string()
            })?;
        let minimum_config_sequence =
            config.peer_noise_deployment_min_sequence.ok_or_else(|| {
                "provider-bound Noise mode lost its minimum deployment sequence".to_string()
            })?;
        let manifest_wire =
            read_bounded_provider_file(manifest_path, MAX_SIGNED_DEPLOYMENT_CONFIG_LEN)
                .map_err(|error| format!("deployment manifest read rejected: {error:?}"))?;
        let manifest = verify_signed_deployment_config(
            &manifest_wire,
            &config.network_id,
            &deployment_authority,
            minimum_config_sequence,
        )
        .map_err(|error| format!("signed deployment manifest rejected: {error}"))?;
        let deployment_state = DeploymentConfigStateStore::open(
            deployment_state_path,
            &config.network_id,
            &deployment_authority,
            minimum_config_sequence,
        )
        .map_err(|error| format!("deployment high-water startup rejected: {error}"))?;
        deployment_state
            .observe(&manifest)
            .map_err(|error| format!("deployment config rollback check rejected: {error}"))?;
        let minimum_registry_sequence = manifest.minimum_registry_sequence;
        let verified_root_chain = manifest.root_chain.clone();
        _deployment_config_state_guard = Some(deployment_state);

        let registry_path = config
            .peer_noise_issuer_registry_state_file
            .as_ref()
            .ok_or_else(|| {
                "provider-bound Noise mode lost its issuer registry state path".to_string()
            })?;
        let store = Arc::new(
            IssuerRegistryStateStore::open_with_root_chain(
                registry_path,
                &config.network_id,
                verified_root_chain,
                minimum_registry_sequence,
            )
            .map_err(|error| format!("issuer registry state startup rejected: {error:?}"))?,
        );
        let registry_file = config
            .peer_noise_issuer_registry_file
            .as_ref()
            .ok_or_else(|| "provider-bound Noise mode lost its issuer registry file".to_string())?;
        let registry_wire = read_bounded_provider_file(registry_file, MAX_REGISTRY_WIRE_LEN)
            .map_err(|error| format!("issuer registry file read rejected: {error:?}"))?;
        let issuer_id = config
            .peer_noise_issuer_id
            .ok_or_else(|| "provider-bound Noise mode lost its issuer ID".to_string())?;
        store
            .accept_signed_registry(&registry_wire, issuer_id)
            .map_err(|error| format!("issuer registry rejected at startup: {error:?}"))?;
        Some(store)
    } else {
        None
    };
    let identity_generation_state = if config.peer_noise_identity_record_file.is_some() {
        let state_path = config
            .peer_noise_identity_state_file
            .as_ref()
            .ok_or_else(|| {
                "provider-bound Noise mode lost its durable identity state path".to_string()
            })?;
        let key_id = config
            .peer_noise_key_id
            .ok_or_else(|| "provider-bound Noise mode lost its key ID".to_string())?;
        let credential_id = config
            .peer_noise_credential_id
            .ok_or_else(|| "provider-bound Noise mode lost its credential ID".to_string())?;
        let issuer_id = config
            .peer_noise_issuer_id
            .ok_or_else(|| "provider-bound Noise mode lost its issuer ID".to_string())?;
        let registry_file = config
            .peer_noise_issuer_registry_file
            .as_ref()
            .ok_or_else(|| "provider-bound Noise mode lost its issuer registry file".to_string())?;
        let registry_state = issuer_registry_state.as_ref().ok_or_else(|| {
            "provider-bound Noise mode lost its issuer registry state".to_string()
        })?;
        let issuer_id_for_registry = config
            .peer_noise_issuer_id
            .ok_or_else(|| "provider-bound Noise mode lost its issuer ID".to_string())?;
        let registry_wire = read_bounded_provider_file(registry_file, MAX_REGISTRY_WIRE_LEN)
            .map_err(|error| format!("issuer registry file read rejected: {error:?}"))?;
        let issuer_public_key = registry_state
            .accept_signed_registry(&registry_wire, issuer_id_for_registry)
            .map_err(|error| format!("issuer registry rejected: {error:?}"))?;
        Some(Arc::new(
            IdentityGenerationStateStore::open(
                state_path,
                &config.network_id,
                key_id,
                KeyPurpose::PeerAuth,
                credential_id,
                issuer_id,
                issuer_public_key,
            )
            .map_err(|error| format!("identity generation state startup rejected: {error:?}"))?,
        ))
    } else {
        None
    };

    let account_id = account_id_from_public_key(&config.public_key);
    let initial = LedgerState::genesis(
        config.network_id,
        vec![(account_id, config.genesis_balance)],
    )
    .map_err(|error| format!("genesis construction failed: {error:?}"))?;
    let authenticator = Ed25519TransactionAuthenticator::select_by_id(
        TransactionAuthenticatorKind::Ed25519V1 as u16,
        [AccountPublicKey {
            account_id,
            public_key: config.public_key,
        }],
    )
    .map_err(|error| format!("authenticator configuration failed: {error:?}"))?;
    let (admission, clock) = if let Some(provider) = build_authenticated_reference_time(&config)? {
        (
            ChainAdmissionBoundary::new(ChainAdmissionConfig::new(
                TimestampPolicy::testnet(),
                ReferenceTimeSourcePolicy::ConfiguredProviderOnly,
            )),
            NodeReferenceTime::Authenticated(provider),
        )
    } else {
        match config.reference_time_unix_seconds {
            Some(seconds) if config.allow_test_time_fixtures => (
                ChainAdmissionBoundary::new(
                    ChainAdmissionConfig::testnet().with_test_fixtures_enabled(),
                ),
                NodeReferenceTime::FixedTestFixture(seconds),
            ),
            None => (
                ChainAdmissionBoundary::new(ChainAdmissionConfig::new(
                    TimestampPolicy::testnet(),
                    ReferenceTimeSourcePolicy::SystemClockOrConfiguredProvider,
                )),
                NodeReferenceTime::SystemClock,
            ),
            Some(_) => {
                return Err("fixed reference time is not permitted without fixture opt-in".into())
            }
        }
    };
    let mut importer = ChainImportService::open(
        initial,
        admission,
        authenticator,
        clock,
        &config.snapshot_path,
    )
    .map_err(|error| error.to_string())?;

    // Loopback is retained for this testbed listener; authenticated sessions are required
    // unless the operator explicitly enables the unauthenticated local test fixture mode.
    let listener = TcpListener::bind(("127.0.0.1", config.port))
        .map_err(|error| format!("loopback bind failed: {error}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("nonblocking failed: {error}"))?;
    let peer_auth_mode = if config.peer_psk.is_some() {
        "hmac-sha256-psk"
    } else if config.peer_noise_identity_record_file.is_some() {
        "noise-xx-provider-bound-identity"
    } else if config.peer_noise_static_private_key_dpapi_file.is_some() {
        "noise-xx-pinned-static-key"
    } else if config.allow_unauthenticated_test_peer {
        "unauthenticated-test-only"
    } else {
        unreachable!("peer-auth configuration enforces an explicit mode")
    };
    eprintln!(
        "event=chain_import_ready listen=127.0.0.1:{} mode={:?} peer_auth={} height={} snapshot={}",
        config.port,
        config.mode,
        peer_auth_mode,
        importer.state().height(),
        config.snapshot_path.display()
    );

    let stop_at = Instant::now() + Duration::from_millis(config.duration_ms);
    let mut accepted = 0u32;
    let mut imported = 0u32;
    let mut rejected = 0u32;
    while Instant::now() < stop_at && accepted < config.connections {
        match listener.accept() {
            Ok((mut stream, address)) => {
                accepted += 1;
                let mut auth_session = if let Some(psk) = config.peer_psk {
                    match authenticate_peer(&mut stream, &psk) {
                        Ok(session) => Some(PeerSession::Hmac(session)),
                        Err(reason) => {
                            rejected += 1;
                            eprintln!("event=peer_auth_rejected peer={} reason={reason}", address);
                            continue;
                        }
                    }
                } else if let (
                    Some(local_private),
                    Some(record_file),
                    Some(signature_file),
                    Some(rotation_file),
                    Some(issuer_registry_file),
                    Some(issuer_registry_state),
                    Some(key_id),
                    Some(credential_id),
                    Some(issuer_id),
                ) = (
                    peer_noise_static_private_key.as_ref(),
                    config.peer_noise_identity_record_file.as_ref(),
                    config.peer_noise_identity_signature_file.as_ref(),
                    config.peer_noise_rotation_file.as_ref(),
                    config.peer_noise_issuer_registry_file.as_ref(),
                    issuer_registry_state.as_ref(),
                    config.peer_noise_key_id,
                    config.peer_noise_credential_id,
                    config.peer_noise_issuer_id,
                ) {
                    let provider = FileNoiseKeyProvider {
                        record_file: record_file.clone(),
                        signature_file: signature_file.clone(),
                        rotation_file: rotation_file.clone(),
                        issuer_registry_file: issuer_registry_file.clone(),
                        issuer_registry_state: issuer_registry_state.clone(),
                        identity_state: identity_generation_state
                            .as_ref()
                            .ok_or_else(|| "durable identity state unavailable".to_string())?
                            .clone(),
                        expected_key_id: key_id,
                        credential_id,
                        issuer_id,
                    };
                    match authenticate_provider_bound_noise_peer(
                        &mut stream,
                        local_private,
                        &provider,
                        credential_id,
                        issuer_id,
                        config.peer_noise_binding_max_validity,
                    ) {
                        Ok((transport, identity)) => {
                            eprintln!(
                                "event=peer_noise_identity_bound peer={} key_id={} generation={} issuer_id={}",
                                address, identity.session.key_id(), identity.session.generation(), identity.binding.issuer_id
                            );
                            Some(PeerSession::NoiseIdentity {
                                transport,
                                identity,
                            })
                        }
                        Err(reason) => {
                            rejected += 1;
                            eprintln!(
                                "event=peer_noise_identity_rejected peer={} reason={reason}",
                                address
                            );
                            continue;
                        }
                    }
                } else if let (Some(local_private), Some(pinned_remote)) = (
                    peer_noise_static_private_key.as_ref(),
                    config.peer_noise_allowed_public_key.as_ref(),
                ) {
                    match authenticate_noise_peer(&mut stream, local_private, pinned_remote) {
                        Ok(session) => Some(PeerSession::Noise(session)),
                        Err(reason) => {
                            rejected += 1;
                            eprintln!(
                                "event=peer_noise_identity_rejected peer={} reason={reason}",
                                address
                            );
                            continue;
                        }
                    }
                } else {
                    None // Valid only through explicit unauthenticated-test opt-in.
                };
                let mut authenticated_request_id = None;
                let block_payload = match auth_session.as_mut() {
                    Some(PeerSession::Hmac(session)) => {
                        read_authenticated_request(&mut stream, &session.receive_key).map(|frame| {
                            authenticated_request_id = Some(frame.request_id);
                            frame.payload
                        })
                    }
                    Some(PeerSession::Noise(transport)) => {
                        read_noise_request(&mut stream, transport).map(|frame| {
                            authenticated_request_id = Some(frame.request_id);
                            frame.payload
                        })
                    }
                    Some(PeerSession::NoiseIdentity { transport, .. }) => {
                        read_noise_request(&mut stream, transport).map(|frame| {
                            authenticated_request_id = Some(frame.request_id);
                            frame.payload
                        })
                    }
                    None => read_block_frame(&mut stream)
                        .map_err(|error| format!("test-only raw frame rejected: {error}")),
                };
                let result = block_payload.and_then(|bytes| {
                    if let Some(PeerSession::NoiseIdentity { identity, .. }) = auth_session.as_mut() {
                        let provider = FileNoiseKeyProvider {
                            record_file: config.peer_noise_identity_record_file.as_ref()
                                .ok_or_else(|| "provider-bound Noise mode lost its record path".to_string())?
                                .clone(),
                            signature_file: config.peer_noise_identity_signature_file.as_ref()
                                .ok_or_else(|| "provider-bound Noise mode lost its signature path".to_string())?
                                .clone(),
                            rotation_file: config.peer_noise_rotation_file.as_ref()
                                .ok_or_else(|| "provider-bound Noise mode lost its rotation path".to_string())?
                                .clone(),
                            issuer_registry_file: config.peer_noise_issuer_registry_file.as_ref()
                                .ok_or_else(|| "issuer registry file unavailable".to_string())?.clone(),
                            issuer_registry_state: issuer_registry_state.as_ref()
                                .ok_or_else(|| "issuer registry state unavailable".to_string())?.clone(),
                            identity_state: identity_generation_state.as_ref()
                                .ok_or_else(|| "durable identity state unavailable".to_string())?
                                .clone(),
                            expected_key_id: config.peer_noise_key_id
                                .ok_or_else(|| "provider-bound Noise mode lost its key id".to_string())?,
                            credential_id: config.peer_noise_credential_id
                                .ok_or_else(|| "provider-bound Noise mode lost its credential id".to_string())?,
                            issuer_id: config.peer_noise_issuer_id
                                .ok_or_else(|| "provider-bound Noise mode lost its issuer id".to_string())?,
                        };
                        revalidate_provider_bound_noise_identity(identity, &provider)?;
                        eprintln!(
                            "event=peer_noise_identity_authorized_before_import key_id={} generation={}",
                            identity.session.key_id(), identity.session.generation()
                        );
                    }
                    importer
                        .import_bytes(&bytes, config.mode)
                        .map_err(|error| error.to_string())
                });
                match result {
                    Ok(receipt) => {
                        imported += 1;
                        let source = receipt
                            .reference_time
                            .map(|sample| sample.source_id)
                            .unwrap_or("none");
                        let reference = receipt
                            .reference_time
                            .map(|sample| sample.unix_seconds.to_string())
                            .unwrap_or_else(|| "none".into());
                        let message = format!(
                            "ACCEPT height={} hash={} mode={:?} source_id={} reference_time={}",
                            receipt.summary.height,
                            bytes_hex(&receipt.summary.block_hash),
                            receipt.mode,
                            source,
                            reference
                        );
                        eprintln!(
                            "event=chain_block_imported peer={} height={} mode={:?} peer_auth={} source_id={} reference_time={}",
                            address, receipt.summary.height, receipt.mode, peer_auth_mode, source, reference
                        );
                        if let Err(error) = write_session_reply(
                            &mut stream,
                            auth_session.as_mut(),
                            authenticated_request_id,
                            &message,
                        ) {
                            eprintln!(
                                "event=chain_import_reply_error peer={} reason={error}",
                                address
                            );
                        }
                    }
                    Err(error) => {
                        rejected += 1;
                        let message = format!("REJECT {error}");
                        eprintln!("event=chain_block_rejected peer={} reason={error}", address);
                        if let Err(reply_error) = write_session_reply(
                            &mut stream,
                            auth_session.as_mut(),
                            authenticated_request_id,
                            &message,
                        ) {
                            eprintln!(
                                "event=chain_import_reply_error peer={} reason={reply_error}",
                                address
                            );
                        }
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => eprintln!("event=chain_import_accept_error reason={error}"),
        }
    }
    eprintln!(
        "event=chain_import_final height={} accepted={} imported={} rejected={} snapshot_exists={}",
        importer.state().height(),
        accepted,
        imported,
        rejected,
        config.snapshot_path.exists()
    );
    Ok(())
}

fn main() {
    if let Err(error) = main_result() {
        eprintln!("event=chain_import_startup_rejected reason={error}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_args() -> Vec<String> {
        vec![
            "--network-id".into(),
            "b6".repeat(32),
            "--public-key-hex".into(),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a".into(),
            "--snapshot".into(),
            r"C:\temp\ain1-chain.snapshot".into(),
            "--allow-unauthenticated-test-peer".into(),
            "true".into(),
        ]
    }

    fn add_reference_time_options(args: &mut Vec<String>) {
        args.extend([
            "--reference-time-policy-file".into(),
            r"C:\temp\policy.rtp1".into(),
            "--reference-time-admin-public-key-hex".into(),
            "42".repeat(32),
            "--reference-time-address".into(),
            "127.0.0.1:49123".into(),
            "--reference-time-state-file".into(),
            r"C:\temp\reference-time.rts1".into(),
        ]);
    }

    #[test]
    fn configured_reference_time_requires_all_options_and_numeric_socket_address() {
        let mut partial = base_args();
        partial.extend([
            "--reference-time-policy-file".into(),
            r"C:\temp\policy.rtp1".into(),
        ]);
        assert!(config_from_args(&partial)
            .unwrap_err()
            .contains("requires all four options"));

        let mut hostname = base_args();
        add_reference_time_options(&mut hostname);
        let address_index = hostname
            .iter()
            .position(|value| value == "--reference-time-address")
            .unwrap();
        hostname[address_index + 1] = "time-authority.example:49123".into();
        assert!(config_from_args(&hostname)
            .unwrap_err()
            .contains("numeric IP:port"));
    }

    #[test]
    fn authenticated_time_configuration_is_complete_and_separate_from_chain_snapshot() {
        let mut args = base_args();
        add_reference_time_options(&mut args);
        let config = config_from_args(&args).unwrap();
        assert_eq!(
            config.reference_time_address,
            Some("127.0.0.1:49123".parse().unwrap())
        );
        assert!(config.reference_time_policy_path.is_some());
        assert!(config.reference_time_admin_public_key.is_some());
        assert!(config.reference_time_state_path.is_some());
        assert!(config.reference_time_unix_seconds.is_none());
        assert!(!config.allow_test_time_fixtures);

        let mut same_path = base_args();
        same_path.extend([
            "--reference-time-policy-file".into(),
            r"C:\temp\policy.rtp1".into(),
            "--reference-time-admin-public-key-hex".into(),
            "42".repeat(32),
            "--reference-time-address".into(),
            "127.0.0.1:49123".into(),
            "--reference-time-state-file".into(),
            r"C:\temp\ain1-chain.snapshot".into(),
        ]);
        assert!(config_from_args(&same_path)
            .unwrap_err()
            .contains("must differ from the chain snapshot"));
    }

    #[test]
    fn fixed_time_fixture_cannot_mix_with_authenticated_provider() {
        let mut args = base_args();
        add_reference_time_options(&mut args);
        args.extend([
            "--reference-time-unix-seconds".into(),
            "1234".into(),
            "--allow-test-time-fixtures".into(),
            "true".into(),
        ]);
        assert!(config_from_args(&args)
            .unwrap_err()
            .contains("cannot be combined with test-only fixed-time fixtures"));
    }
}

#[cfg(test)]
mod peer_auth_config_tests {
    use super::*;

    fn base_args() -> Vec<String> {
        vec![
            "--network-id".into(),
            "b6".repeat(32),
            "--public-key-hex".into(),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a".into(),
            "--snapshot".into(),
            r"C:\\temp\\ain1-chain.snapshot".into(),
            "--allow-unauthenticated-test-peer".into(),
            "true".into(),
        ]
    }

    #[test]
    fn peer_authentication_mode_must_be_explicit() {
        let mut args = base_args();
        args.truncate(args.len() - 2);
        assert!(config_from_args(&args)
            .unwrap_err()
            .contains("select exactly one peer mode"));
    }

    #[test]
    fn psk_mode_accepts_nonzero_32_byte_key_and_rejects_zero_or_test_mode_mix() {
        let mut args = base_args();
        args.truncate(args.len() - 2);
        args.extend(["--peer-psk-hex".into(), "11".repeat(32)]);
        let config = config_from_args(&args).unwrap();
        assert_eq!(config.peer_psk, Some([0x11; 32]));
        assert!(!config.allow_unauthenticated_test_peer);

        let mut zero = base_args();
        zero.truncate(zero.len() - 2);
        zero.extend(["--peer-psk-hex".into(), "00".repeat(32)]);
        assert!(config_from_args(&zero)
            .unwrap_err()
            .contains("cannot be all zero"));

        let mut conflict = base_args();
        conflict.extend(["--peer-psk-hex".into(), "11".repeat(32)]);
        assert!(config_from_args(&conflict)
            .unwrap_err()
            .contains("select exactly one peer mode"));
    }
}

#[cfg(test)]
mod noise_peer_config_tests {
    use super::*;

    fn base_args() -> Vec<String> {
        vec![
            "--network-id".into(),
            "b6".repeat(32),
            "--public-key-hex".into(),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a".into(),
            "--snapshot".into(),
            r"C:\temp\ain1-noise-chain.snapshot".into(),
        ]
    }

    fn add_noise_options(args: &mut Vec<String>) {
        args.extend([
            "--peer-noise-static-private-key-dpapi-file".into(),
            r"C:\temp\noise-private.key".into(),
            "--peer-noise-allowed-public-key-hex".into(),
            "31".repeat(32),
        ]);
    }

    #[test]
    fn noise_xx_requires_both_pinned_static_keys() {
        let mut args = base_args();
        args.extend([
            "--peer-noise-static-private-key-dpapi-file".into(),
            r"C:\temp\noise-private.key".into(),
        ]);
        assert!(config_from_args(&args)
            .unwrap_err()
            .contains("requires both --peer-noise-static-private-key-dpapi-file"));
    }

    #[test]
    fn noise_xx_mode_is_complete_and_exclusive() {
        let mut args = base_args();
        add_noise_options(&mut args);
        let config = config_from_args(&args).unwrap();
        assert_eq!(
            config.peer_noise_static_private_key_dpapi_file,
            Some(PathBuf::from(r"C:\temp\noise-private.key"))
        );
        assert_eq!(config.peer_noise_allowed_public_key, Some([0x31; 32]));
        assert!(config.peer_psk.is_none());
        assert!(!config.allow_unauthenticated_test_peer);

        let mut mixed = base_args();
        add_noise_options(&mut mixed);
        mixed.extend(["--peer-psk-hex".into(), "44".repeat(32)]);
        assert!(config_from_args(&mixed)
            .unwrap_err()
            .contains("select exactly one peer mode"));
    }

    #[test]
    fn noise_xx_rejects_zero_keys_and_noise_with_test_raw_mode() {
        let mut legacy_secret = base_args();
        legacy_secret.extend([
            "--peer-noise-static-private-key-hex".into(),
            "11".repeat(32),
            "--peer-noise-allowed-public-key-hex".into(),
            "31".repeat(32),
        ]);
        assert!(config_from_args(&legacy_secret)
            .unwrap_err()
            .contains("was removed; use --peer-noise-static-private-key-dpapi-file"));

        let mut raw_file = base_args();
        raw_file.extend([
            "--peer-noise-static-private-key-file".into(),
            r"C:\temp\noise-private.key".into(),
            "--peer-noise-allowed-public-key-hex".into(),
            "31".repeat(32),
        ]);
        assert!(config_from_args(&raw_file)
            .unwrap_err()
            .contains("unprotected raw key bytes"));

        let mut missing_file = base_args();
        missing_file.extend([
            "--peer-noise-allowed-public-key-hex".into(),
            "31".repeat(32),
        ]);
        assert!(config_from_args(&missing_file)
            .unwrap_err()
            .contains("requires both --peer-noise-static-private-key-dpapi-file"));

        let mut zero_remote = base_args();
        zero_remote.extend([
            "--peer-noise-static-private-key-dpapi-file".into(),
            r"C:\temp\noise-private.key".into(),
            "--peer-noise-allowed-public-key-hex".into(),
            "00".repeat(32),
        ]);
        assert!(config_from_args(&zero_remote)
            .unwrap_err()
            .contains("allowed-public-key-hex cannot be all zero"));

        let mut conflict = base_args();
        add_noise_options(&mut conflict);
        conflict.extend(["--allow-unauthenticated-test-peer".into(), "true".into()]);
        assert!(config_from_args(&conflict)
            .unwrap_err()
            .contains("select exactly one peer mode"));
    }

    #[test]
    fn provider_bound_noise_requires_signed_deployment_configuration() {
        let mut args = base_args();
        args.extend([
            "--peer-noise-static-private-key-dpapi-file".into(),
            r"C:\temp\noise-private.npk".into(),
            "--peer-noise-identity-record-file".into(),
            r"C:\temp\peer.keyrec".into(),
            "--peer-noise-identity-signature-file".into(),
            r"C:\temp\peer.keyrec.sig".into(),
            "--peer-noise-identity-state-file".into(),
            r"C:\temp\peer.identity.state".into(),
            "--peer-noise-rotation-file".into(),
            r"C:\temp\peer.rotation".into(),
            "--peer-noise-issuer-registry-file".into(),
            r"C:\temp\issuer-registry.bin".into(),
            "--peer-noise-issuer-registry-state-file".into(),
            r"C:\temp\issuer-registry.state".into(),
            "--peer-noise-deployment-config-file".into(),
            r"C:\temp\deployment.dpc1".into(),
            "--peer-noise-deployment-config-state-file".into(),
            r"C:\temp\deployment.dcs1".into(),
            "--peer-noise-deployment-authority-public-key-hex".into(),
            "44".repeat(32),
            "--peer-noise-deployment-min-sequence".into(),
            "1".into(),
            "--peer-noise-key-id".into(),
            "700".into(),
            "--peer-noise-credential-id".into(),
            "9001".into(),
            "--peer-noise-issuer-id".into(),
            "17".into(),
        ]);
        let config = config_from_args(&args).unwrap();
        assert!(config.peer_noise_identity_record_file.is_some());
        assert!(config.peer_noise_identity_signature_file.is_some());
        assert_eq!(
            config.peer_noise_deployment_config_file,
            Some(PathBuf::from(r"C:\temp\deployment.dpc1"))
        );
        assert_eq!(
            config.peer_noise_deployment_config_state_file,
            Some(PathBuf::from(r"C:\temp\deployment.dcs1"))
        );
        assert_eq!(
            config.peer_noise_deployment_authority_public_key,
            Some([0x44; 32])
        );
        assert_eq!(config.peer_noise_deployment_min_sequence, Some(1));
        assert!(config.peer_noise_allowed_public_key.is_none());

        let mut zero_floor = args.clone();
        let floor_index = zero_floor
            .iter()
            .position(|value| value == "--peer-noise-deployment-min-sequence")
            .unwrap();
        zero_floor[floor_index + 1] = "0".into();
        assert!(config_from_args(&zero_floor)
            .unwrap_err()
            .contains("must be greater than zero"));

        let mut missing_trust = base_args();
        missing_trust.extend([
            "--peer-noise-static-private-key-dpapi-file".into(),
            r"C:\temp\noise-private.npk".into(),
            "--peer-noise-identity-record-file".into(),
            r"C:\temp\peer.keyrec".into(),
            "--peer-noise-key-id".into(),
            "700".into(),
            "--peer-noise-credential-id".into(),
            "9001".into(),
            "--peer-noise-issuer-id".into(),
            "17".into(),
        ]);
        assert!(config_from_args(&missing_trust)
            .unwrap_err()
            .contains("requires identity signature/registry/state plus signed deployment config"));

        let mut legacy_root_input = args.clone();
        legacy_root_input.extend(["--peer-noise-issuer-root-min-epoch".into(), "1".into()]);
        assert!(config_from_args(&legacy_root_input)
            .unwrap_err()
            .contains("individual governance roots/floors were removed"));

        let mut pinned_mix = args.clone();
        pinned_mix.extend([
            "--peer-noise-allowed-public-key-hex".into(),
            "31".repeat(32),
        ]);
        assert!(config_from_args(&pinned_mix)
            .unwrap_err()
            .contains("forbids --peer-noise-allowed-public-key-hex"));
    }
}
