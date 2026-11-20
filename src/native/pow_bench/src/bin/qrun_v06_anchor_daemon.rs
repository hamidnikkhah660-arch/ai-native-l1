//! Standalone QAR2/QBT1 Anchor daemon.
//!
//! All public trust pins are loaded from a config whose SHA-256 is passed separately at launch.
//! Q6PN and QBTB1 are independently digest-pinned and cryptographically verified before startup.
//! Q6TS is dual-signature verified against a monotonic floor in a distinct AWS account using a
//! separate, read-only temporary STS session; this daemon cannot provision or advance that floor.
//! Anchor STS credentials arrive only through QRUN_ANCHOR_STS_* and Q6TS credentials only through
//! QRUN_Q6TS_STS_*; both are removed immediately and never accepted on the CLI.
//! Anchor DynamoDB and KMS share one immutable session-bound runner and one exact KMS key ARN.
//!
//! This executable does not provision generation zero, create AWS resources, enroll signers,
//! or downgrade to QAR1. It requires an already provisioned QBT1-bound DynamoDB Anchor state.

use ai_native_l1_pow_bench::{
    external_cas_aws_kms_signer_candidate::SessionBoundAwsKmsCliOffhostAnchorReceiptSigner,
    external_cas_bootstrap_trust_bundle_candidate::{
        verify_qbt1_bootstrap_trust_bundle, QBTB1_BUNDLE_BYTES,
    },
    external_cas_offhost_anchor_aws_dynamodb_candidate::{
        AwsTemporaryCredentialSession, SessionBoundAwsDynamoDbCliRunner,
    },
    external_cas_offhost_anchor_aws_qualification_candidate::AwsDynamoDbDeploymentPin,
    external_cas_offhost_anchor_noise_daemon_candidate::{
        OffhostAnchorNoiseDaemon, OffhostAnchorNoiseDaemonConfig,
    },
    external_cas_offhost_anchor_protocol_candidate::ExternalCasOffhostAnchorPin,
    noise_key_provisioning::load_protected_noise_private_key,
    qrun_v06_profile_pin_candidate::{
        QRunV06VerifiedProfilePin, QRUN_V06_PROFILE_PIN_BYTES, QRUN_V06_PROFILE_PIN_V2_BYTES,
    },
    qrun_v06_profile_trust_candidate::{
        authorize_qrun_v06_profile_pin, PinnedQRunV06ProfileTrustAuthority,
    },
    qrun_v06_profile_trust_dynamodb_floor_candidate::AwsDynamoDbQ6tsReadOnlyProfileTrustFloorStore,
    v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    env,
    fs::{self, File},
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use zeroize::Zeroize;

const MAX_CONFIG_BYTES: u64 = 64 * 1024;
const MAX_PIN_FILE_BYTES: u64 = 16 * 1024;
const MAX_PUBLIC_KEY_BYTES: u64 = 4 * 1024;
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnchorDaemonConfig {
    q6pn_profile_pin_path: PathBuf,
    q6pn_profile_pin_commitment: String,
    qbt1_bundle_path: PathBuf,
    qbt1_bundle_sha256: String,

    anchor_id: String,
    anchor_receipt_key_id: String,
    anchor_receipt_public_key_path: PathBuf,

    protected_noise_private_key_path: PathBuf,
    trusted_client_static_public_keys: Vec<String>,
    bind_address: SocketAddr,
    max_workers: usize,
    queue_capacity: usize,

    aws_cli_path: PathBuf,
    aws_account_id: String,
    aws_role_arn: String,
    aws_table_arn: String,
    aws_region: String,
    aws_table_name: String,
    anchor_kms_key_arn: String,

    // Q6TS is administered in a separate AWS account and uses a distinct read-only STS session.
    q6ts_trust_envelope_path: PathBuf,
    q6ts_authority_ed25519_path: PathBuf,
    q6ts_authority_mldsa65_path: PathBuf,
    q6ts_authority_keyset_id: String,
    q6ts_floor_account_id: String,
    q6ts_floor_role_arn: String,
    q6ts_floor_table_arn: String,
    q6ts_floor_region: String,
    q6ts_floor_table_name: String,
}

struct StsEnvironmentMaterial {
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
}

impl Drop for StsEnvironmentMaterial {
    fn drop(&mut self) {
        self.access_key_id.zeroize();
        self.secret_access_key.zeroize();
        self.session_token.zeroize();
    }
}

fn take_env(name: &str) -> Result<String, String> {
    let value =
        env::var(name).map_err(|_| format!("required temporary STS input {name} is absent"))?;
    env::remove_var(name);
    if value.is_empty() || value.trim() != value || value.chars().any(char::is_control) {
        let mut value = value;
        value.zeroize();
        return Err(format!("temporary STS input {name} has invalid form"));
    }
    Ok(value)
}

fn load_sts_session(prefix: &str) -> Result<AwsTemporaryCredentialSession, String> {
    if prefix != "QRUN_ANCHOR_STS" && prefix != "QRUN_Q6TS_STS" {
        return Err("unsupported STS credential namespace".into());
    }
    let access_name = format!("{prefix}_ACCESS_KEY_ID");
    let secret_name = format!("{prefix}_SECRET_ACCESS_KEY");
    let token_name = format!("{prefix}_SESSION_TOKEN");
    let expiry_name = format!("{prefix}_EXPIRES_AT_UNIX");
    let mut material = StsEnvironmentMaterial {
        access_key_id: take_env(&access_name)?,
        secret_access_key: String::new(),
        session_token: String::new(),
    };
    material.secret_access_key = take_env(&secret_name)?;
    material.session_token = take_env(&token_name)?;
    let expiry = take_env(&expiry_name)?
        .parse::<u64>()
        .map_err(|_| format!("{expiry_name} must be a Unix timestamp"))?;

    AwsTemporaryCredentialSession::new(
        std::mem::take(&mut material.access_key_id),
        std::mem::take(&mut material.secret_access_key),
        std::mem::take(&mut material.session_token),
        expiry,
    )
}

fn parse_digest(name: &str, text: &str) -> Result<[u8; 32], String> {
    if text.len() != 64 || !text.is_ascii() || text.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(format!(
            "{name} must be exactly 64 lowercase hexadecimal characters"
        ));
    }
    let mut digest = [0u8; 32];
    for (index, slot) in digest.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|_| format!("{name} contains a non-hexadecimal character"))?;
    }
    if digest == [0; 32] {
        return Err(format!("{name} must not be zero"));
    }
    Ok(digest)
}

fn read_regular_file(path: &Path, max_bytes: u64, label: &str) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("{label} metadata unavailable: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!("{label} must be a regular non-symlink file"));
    }
    if metadata.len() == 0 || metadata.len() > max_bytes {
        return Err(format!("{label} has an invalid size"));
    }
    let file = File::open(path).map_err(|error| format!("{label} open failed: {error}"))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("{label} read failed: {error}"))?;
    if bytes.is_empty() || bytes.len() as u64 > max_bytes {
        return Err(format!("{label} exceeds its size limit"));
    }
    Ok(bytes)
}

fn read_config(path: &Path, expected_sha256: &[u8; 32]) -> Result<AnchorDaemonConfig, String> {
    let bytes = read_regular_file(path, MAX_CONFIG_BYTES, "Anchor daemon config")?;
    let actual: [u8; 32] = Sha256::digest(&bytes).into();
    if &actual != expected_sha256 {
        return Err(
            "Anchor daemon config SHA-256 does not match the separately supplied pin".into(),
        );
    }
    serde_json::from_slice(&bytes).map_err(|error| {
        format!("Anchor daemon config is malformed or contains duplicate/unknown fields: {error}")
    })
}

fn require_absolute(path: &Path, name: &str) -> Result<(), String> {
    if !path.is_absolute() {
        return Err(format!("{name} must be an absolute path"));
    }
    Ok(())
}

fn validate_independent_q6ts_pin(
    anchor: &AwsDynamoDbDeploymentPin,
    q6ts: &AwsDynamoDbDeploymentPin,
) -> Result<(), String> {
    q6ts.validate()
        .map_err(|error| format!("Q6TS floor deployment pin is invalid: {error:?}"))?;
    if q6ts.account_id == anchor.account_id
        || q6ts.role_arn == anchor.role_arn
        || q6ts.table_arn == anchor.table_arn
    {
        return Err(
            "Q6TS monotonic floor must use a distinct AWS account, role and table from the Anchor service"
                .into(),
        );
    }
    Ok(())
}

fn authorize_q6ts_profile_pin(
    config: &AnchorDaemonConfig,
    profile_pin_bytes: &[u8],
    expected_network_id: [u8; 32],
    expected_profile_id: [u8; 32],
    anchor_deployment_pin: &AwsDynamoDbDeploymentPin,
) -> Result<u64, String> {
    let q6ts_deployment_pin = AwsDynamoDbDeploymentPin {
        account_id: config.q6ts_floor_account_id.clone(),
        role_arn: config.q6ts_floor_role_arn.clone(),
        table_arn: config.q6ts_floor_table_arn.clone(),
        region: config.q6ts_floor_region.clone(),
        table_name: config.q6ts_floor_table_name.clone(),
    };
    validate_independent_q6ts_pin(anchor_deployment_pin, &q6ts_deployment_pin)?;

    let ed25519_bytes = read_regular_file(
        &config.q6ts_authority_ed25519_path,
        32,
        "Q6TS Ed25519 authority public key",
    )?;
    let mldsa65_bytes = read_regular_file(
        &config.q6ts_authority_mldsa65_path,
        ai_native_l1_pow_bench::v4_fat1_trust_candidate::ML_DSA_65_PUBLIC_KEY_BYTES as u64,
        "Q6TS ML-DSA-65 authority public key",
    )?;
    if ed25519_bytes.len() != 32
        || mldsa65_bytes.len()
            != ai_native_l1_pow_bench::v4_fat1_trust_candidate::ML_DSA_65_PUBLIC_KEY_BYTES
    {
        return Err("Q6TS authority public-key length is invalid".into());
    }
    let authority = PinnedQRunV06ProfileTrustAuthority {
        ed25519_public_key: ed25519_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "invalid Q6TS Ed25519 authority key length")?,
        mldsa65_public_key: mldsa65_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "invalid Q6TS ML-DSA-65 authority key length")?,
    };
    let expected_keyset_id =
        parse_digest("Q6TS authority keyset ID", &config.q6ts_authority_keyset_id)?;
    let actual_keyset_id = authority
        .keyset_id()
        .map_err(|error| format!("Q6TS authority keyset is invalid: {error}"))?;
    if actual_keyset_id != expected_keyset_id {
        return Err("Q6TS authority keyset differs from its independently pinned keyset ID".into());
    }

    let signed_trust_envelope = read_regular_file(
        &config.q6ts_trust_envelope_path,
        MAX_PIN_FILE_BYTES,
        "Q6TS signed profile-trust envelope",
    )?;

    // This is a separate account/role and a separate, read-only temporary STS session.
    // The runner rejects PutItem itself; the floor adapter also refuses compare-and-swap.
    let q6ts_session = load_sts_session("QRUN_Q6TS_STS")?;
    let q6ts_runner = Arc::new(
        SessionBoundAwsDynamoDbCliRunner::new_read_only(
            &config.aws_cli_path,
            q6ts_deployment_pin.clone(),
            q6ts_session,
        )
        .map_err(|error| format!("Q6TS read-only AWS runner construction failed: {error}"))?,
    );
    let mut floor_store =
        AwsDynamoDbQ6tsReadOnlyProfileTrustFloorStore::with_session_bound_read_only_runner(
            q6ts_runner,
            q6ts_deployment_pin,
        )
        .map_err(|error| format!("independent Q6TS floor qualification failed: {error}"))?;

    let authorized = authorize_qrun_v06_profile_pin(
        Some(profile_pin_bytes),
        &signed_trust_envelope,
        &authority,
        &LibcruxMlDsa65VerifierCandidate,
        &mut floor_store,
        expected_network_id,
        expected_profile_id,
    )
    .map_err(|error| format!("Q6TS signature/floor authorization failed: {error}"))?;
    Ok(authorized.trust_epoch())
}

fn install_shutdown_handlers() -> Result<(), String> {
    #[cfg(windows)]
    {
        unsafe extern "system" fn handler(event: u32) -> i32 {
            match event {
                0 | 1 | 2 | 5 | 6 => {
                    SHUTDOWN.store(true, Ordering::Release);
                    1
                }
                _ => 0,
            }
        }
        #[link(name = "Kernel32")]
        extern "system" {
            fn SetConsoleCtrlHandler(
                handler: Option<unsafe extern "system" fn(u32) -> i32>,
                add: i32,
            ) -> i32;
        }
        let ok = unsafe { SetConsoleCtrlHandler(Some(handler), 1) };
        if ok == 0 {
            return Err("could not install Windows console shutdown handler".into());
        }
    }

    #[cfg(unix)]
    {
        extern "C" fn handler(_: libc::c_int) {
            SHUTDOWN.store(true, Ordering::Release);
        }
        unsafe {
            if libc::signal(libc::SIGINT, handler as libc::sighandler_t) == libc::SIG_ERR
                || libc::signal(libc::SIGTERM, handler as libc::sighandler_t) == libc::SIG_ERR
            {
                return Err("could not install SIGINT/SIGTERM shutdown handlers".into());
            }
        }
    }
    Ok(())
}

fn run() -> Result<(), String> {
    let args = env::args_os().skip(1).collect::<Vec<_>>();
    if args.len() != 2 {
        return Err("usage: qrun_v06_anchor_daemon <absolute-config-path> <config-sha256>".into());
    }
    let config_path = PathBuf::from(&args[0]);
    require_absolute(&config_path, "config path")?;
    let digest_text = args[1]
        .to_str()
        .ok_or_else(|| "config SHA-256 argument must be ASCII".to_owned())?;
    let config_digest = parse_digest("config SHA-256", digest_text)?;
    let config = read_config(&config_path, &config_digest)?;

    for (path, name) in [
        (&config.q6pn_profile_pin_path, "Q6PN profile pin path"),
        (&config.qbt1_bundle_path, "QBTB1 bundle path"),
        (
            &config.anchor_receipt_public_key_path,
            "Anchor public-key path",
        ),
        (
            &config.protected_noise_private_key_path,
            "protected Noise key path",
        ),
        (&config.q6ts_trust_envelope_path, "Q6TS trust envelope path"),
        (
            &config.q6ts_authority_ed25519_path,
            "Q6TS Ed25519 authority key path",
        ),
        (
            &config.q6ts_authority_mldsa65_path,
            "Q6TS ML-DSA authority key path",
        ),
        (&config.aws_cli_path, "AWS CLI path"),
    ] {
        require_absolute(path, name)?;
    }

    let profile_commitment = parse_digest(
        "Q6PN profile commitment",
        &config.q6pn_profile_pin_commitment,
    )?;
    let profile_pin_bytes = read_regular_file(
        &config.q6pn_profile_pin_path,
        MAX_PIN_FILE_BYTES,
        "Q6PN profile pin",
    )?;
    if profile_pin_bytes.len() != QRUN_V06_PROFILE_PIN_BYTES
        && profile_pin_bytes.len() != QRUN_V06_PROFILE_PIN_V2_BYTES
    {
        return Err("Q6PN profile pin has an unsupported exact length".into());
    }
    let profile_pin = QRunV06VerifiedProfilePin::decode(&profile_pin_bytes, profile_commitment)
        .map_err(|error| format!("independently pinned Q6PN verification failed: {error}"))?;
    let provider_pin = profile_pin.bundle().external_cas_pin().clone();
    let network_id = profile_pin.descriptor().network_id();

    let anchor_id = parse_digest("Anchor ID", &config.anchor_id)?;
    let anchor_key_id = parse_digest("Anchor receipt key ID", &config.anchor_receipt_key_id)?;
    let anchor_public_key = read_regular_file(
        &config.anchor_receipt_public_key_path,
        MAX_PUBLIC_KEY_BYTES,
        "Anchor ML-DSA-65 receipt public key",
    )?;
    if anchor_public_key.len()
        != ai_native_l1_pow_bench::v4_fat1_trust_candidate::ML_DSA_65_PUBLIC_KEY_BYTES
    {
        return Err("Anchor receipt public key must be exactly 1952 bytes".into());
    }
    let anchor_pin = ExternalCasOffhostAnchorPin {
        anchor_id,
        provider_id: provider_pin.provider_id,
        network_id,
        genesis_digest: provider_pin.genesis_digest,
        receipt_key_id: anchor_key_id,
        receipt_public_key: anchor_public_key
            .as_slice()
            .try_into()
            .map_err(|_| "Anchor public key has an invalid length")?,
    };
    anchor_pin
        .validate(&provider_pin)
        .map_err(|error| format!("Anchor/Provider identity binding failed: {error}"))?;

    let expected_bundle_digest = parse_digest("QBTB1 SHA-256", &config.qbt1_bundle_sha256)?;
    let bundle_bytes = read_regular_file(
        &config.qbt1_bundle_path,
        QBTB1_BUNDLE_BYTES as u64,
        "QBTB1 bootstrap trust bundle",
    )?;
    if bundle_bytes.len() != QBTB1_BUNDLE_BYTES {
        return Err("QBTB1 bundle has an invalid exact length".into());
    }
    let verified_bundle = verify_qbt1_bootstrap_trust_bundle(
        &bundle_bytes,
        &expected_bundle_digest,
        &profile_commitment,
        &provider_pin,
        &anchor_pin,
        &LibcruxMlDsa65VerifierCandidate,
    )
    .map_err(|error| format!("QBTB1/QBT1 signature and domain verification failed: {error}"))?;
    let trust = verified_bundle.bootstrap_trust().clone();

    let deployment_pin = AwsDynamoDbDeploymentPin {
        account_id: config.aws_account_id.clone(),
        role_arn: config.aws_role_arn.clone(),
        table_arn: config.aws_table_arn.clone(),
        region: config.aws_region.clone(),
        table_name: config.aws_table_name.clone(),
    };
    deployment_pin
        .validate()
        .map_err(|error| format!("AWS Anchor deployment pin is invalid: {error:?}"))?;

    // Q6TS must match the exact signed Q6PN commitment and the independently administered
    // monotonic floor in a different AWS account, under a separate read-only STS session.
    let q6ts_trust_epoch = authorize_q6ts_profile_pin(
        &config,
        &profile_pin_bytes,
        network_id,
        profile_pin.descriptor().profile_id(),
        &deployment_pin,
    )?;

    // Capture the Anchor STS session once, then share it only between Anchor DynamoDB and KMS.
    let session = load_sts_session("QRUN_ANCHOR_STS")?;
    let runner = Arc::new(
        SessionBoundAwsDynamoDbCliRunner::new_with_kms_key_arn(
            &config.aws_cli_path,
            deployment_pin.clone(),
            session,
            config.anchor_kms_key_arn.clone(),
        )
        .map_err(|error| format!("session-bound AWS runner construction failed: {error}"))?,
    );

    // KMS key metadata, public-key pin and a startup signature are verified through that
    // exact same temporary STS session before DynamoDB qualification or listener binding.
    let anchor_signer = Arc::new(
        SessionBoundAwsKmsCliOffhostAnchorReceiptSigner::connect(
            Arc::clone(&runner),
            config.anchor_kms_key_arn,
            &anchor_pin,
            &provider_pin,
        )
        .map_err(|error| format!("session-bound Anchor KMS signer startup failed: {error}"))?,
    );

    let mut trusted_clients = Vec::with_capacity(config.trusted_client_static_public_keys.len());
    for (index, key) in config.trusted_client_static_public_keys.iter().enumerate() {
        let parsed = parse_digest(&format!("trusted Noise client key {index}"), key)?;
        trusted_clients.push(parsed);
    }

    // CurrentUser DPAPI keeps the Noise static key out of the config, command line and raw disk.
    let noise_private_key =
        load_protected_noise_private_key(&config.protected_noise_private_key_path, &network_id)
            .map_err(|error| format!("protected Anchor Noise key unavailable: {error}"))?;

    let daemon_config = OffhostAnchorNoiseDaemonConfig {
        bind_address: config.bind_address,
        local_static_private_key: noise_private_key,
        trusted_client_static_public_keys: trusted_clients,
        anchor_pin: anchor_pin.clone(),
        provider_pin: provider_pin.clone(),
        max_workers: config.max_workers,
        queue_capacity: config.queue_capacity,
    };

    // Construction performs live STS/IAM/DynamoDB qualification before TcpListener::bind.
    // It does not create or enroll generation zero; the QBT1-bound item must already exist.
    let daemon = OffhostAnchorNoiseDaemon::bind_qbt1_session_bound_aws_dynamodb(
        daemon_config,
        runner,
        deployment_pin,
        trust,
        Arc::new(LibcruxMlDsa65VerifierCandidate),
        anchor_signer,
    )
    .map_err(|error| format!("QAR2/QBT1 Anchor daemon bind failed: {error}"))?;

    let local_addr = daemon
        .local_addr()
        .map_err(|error| format!("Anchor daemon local address unavailable: {error}"))?;
    eprintln!(
        "qrun_anchor_status=READY_PENDING_RUN q6ts_trust_epoch={} anchor_id={} provider_id={} network_id={} listen={}",
        q6ts_trust_epoch,
        hex(&anchor_pin.anchor_id),
        hex(&provider_pin.provider_id),
        hex(&network_id),
        local_addr
    );

    install_shutdown_handlers()?;
    let stats = daemon
        .run_until_shutdown(&SHUTDOWN)
        .map_err(|error| format!("Anchor daemon terminated with failure: {error}"))?;
    eprintln!(
        "qrun_anchor_status=STOPPED accepted={} rejected={} completed={} failed={} worker_threads_started={}",
        stats.accepted_connections,
        stats.overload_rejected_connections,
        stats.completed_requests,
        stats.failed_requests,
        stats.worker_threads_started
    );
    Ok(())
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

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("qrun_anchor_status=FAIL_CLOSED reason={error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_config_json() -> Vec<u8> {
        br#"{
            "q6pn_profile_pin_path": "C:/qrun/trust/q6pn.bin",
            "q6pn_profile_pin_commitment": "1111111111111111111111111111111111111111111111111111111111111111",
            "qbt1_bundle_path": "C:/qrun/trust/qbtb1.bin",
            "qbt1_bundle_sha256": "2222222222222222222222222222222222222222222222222222222222222222",
            "anchor_id": "3333333333333333333333333333333333333333333333333333333333333333",
            "anchor_receipt_key_id": "4444444444444444444444444444444444444444444444444444444444444444",
            "anchor_receipt_public_key_path": "C:/qrun/keys/anchor-public.bin",
            "protected_noise_private_key_path": "C:/qrun/keys/anchor-noise.npk1",
            "trusted_client_static_public_keys": ["5555555555555555555555555555555555555555555555555555555555555555"],
            "bind_address": "127.0.0.1:9443",
            "max_workers": 4,
            "queue_capacity": 32,
            "aws_cli_path": "C:/Program Files/Amazon/AWSCLIV2/aws.exe",
            "aws_account_id": "123456789012",
            "aws_role_arn": "arn:aws:iam::123456789012:role/QRunAnchorCustodian",
            "aws_table_arn": "arn:aws:dynamodb:us-east-1:123456789012:table/qrun-anchor",
            "aws_region": "us-east-1",
            "aws_table_name": "qrun-anchor",
            "anchor_kms_key_arn": "arn:aws:kms:us-east-1:123456789012:key/123e4567-e89b-12d3-a456-426614174000",
            "q6ts_trust_envelope_path": "C:/qrun/trust/q6ts.bin",
            "q6ts_authority_ed25519_path": "C:/qrun/trust/q6ts-ed25519.pub",
            "q6ts_authority_mldsa65_path": "C:/qrun/trust/q6ts-mldsa65.pub",
            "q6ts_authority_keyset_id": "6666666666666666666666666666666666666666666666666666666666666666",
            "q6ts_floor_account_id": "999999999999",
            "q6ts_floor_role_arn": "arn:aws:iam::999999999999:role/QRunQ6tsReadOnly",
            "q6ts_floor_table_arn": "arn:aws:dynamodb:us-east-2:999999999999:table/qrun-q6ts-floor",
            "q6ts_floor_region": "us-east-2",
            "q6ts_floor_table_name": "qrun-q6ts-floor"
        }"#
        .to_vec()
    }

    fn anchor_deployment_pin() -> AwsDynamoDbDeploymentPin {
        AwsDynamoDbDeploymentPin {
            account_id: "123456789012".into(),
            role_arn: "arn:aws:iam::123456789012:role/QRunAnchorCustodian".into(),
            table_arn: "arn:aws:dynamodb:us-east-1:123456789012:table/qrun-anchor".into(),
            region: "us-east-1".into(),
            table_name: "qrun-anchor".into(),
        }
    }

    fn q6ts_deployment_pin() -> AwsDynamoDbDeploymentPin {
        AwsDynamoDbDeploymentPin {
            account_id: "999999999999".into(),
            role_arn: "arn:aws:iam::999999999999:role/QRunQ6tsReadOnly".into(),
            table_arn: "arn:aws:dynamodb:us-east-2:999999999999:table/qrun-q6ts-floor".into(),
            region: "us-east-2".into(),
            table_name: "qrun-q6ts-floor".into(),
        }
    }

    #[test]
    fn q6ts_floor_requires_a_different_aws_account_and_role_from_anchor() {
        let anchor = anchor_deployment_pin();
        let independent = q6ts_deployment_pin();
        assert!(validate_independent_q6ts_pin(&anchor, &independent).is_ok());

        let mut same_account = independent.clone();
        same_account.account_id = anchor.account_id.clone();
        same_account.role_arn = "arn:aws:iam::123456789012:role/QRunQ6tsReadOnly".into();
        same_account.table_arn =
            "arn:aws:dynamodb:us-east-2:123456789012:table/qrun-q6ts-floor".into();
        assert!(validate_independent_q6ts_pin(&anchor, &same_account).is_err());
    }

    #[test]
    fn config_is_strict_and_rejects_duplicate_or_unknown_fields() {
        let bytes = valid_config_json();
        let parsed: AnchorDaemonConfig = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed.bind_address, "127.0.0.1:9443".parse().unwrap());
        assert_eq!(parsed.max_workers, 4);

        let text = String::from_utf8(bytes).unwrap();
        let duplicate = text.replacen(
            r#""bind_address": "127.0.0.1:9443","#,
            r#""bind_address": "127.0.0.1:9443", "bind_address": "127.0.0.1:9444","#,
            1,
        );
        assert!(serde_json::from_str::<AnchorDaemonConfig>(&duplicate).is_err());

        let unknown = text.replacen(
            r#""max_workers": 4,"#,
            r#""max_workers": 4, "unexpected": true,"#,
            1,
        );
        assert!(serde_json::from_str::<AnchorDaemonConfig>(&unknown).is_err());
    }

    #[test]
    fn config_digest_is_required_and_checked_before_deserialization() {
        let path = env::temp_dir().join(format!(
            "qrun-anchor-daemon-config-{}.json",
            std::process::id()
        ));
        let bytes = valid_config_json();
        fs::write(&path, &bytes).unwrap();
        let expected: [u8; 32] = Sha256::digest(&bytes).into();
        assert!(read_config(&path, &expected).is_ok());

        let mut wrong = expected;
        wrong[0] ^= 1;
        assert!(read_config(&path, &wrong).is_err());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn digest_parser_rejects_uppercase_zero_and_wrong_length() {
        assert!(parse_digest(
            "test",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )
        .is_err());
        assert!(parse_digest(
            "test",
            "0000000000000000000000000000000000000000000000000000000000000000"
        )
        .is_err());
        assert!(parse_digest("test", "1234").is_err());
    }
}
