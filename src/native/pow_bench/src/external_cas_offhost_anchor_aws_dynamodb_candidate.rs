//! CP-0483 AWS DynamoDB adapter candidate for the QRun off-host monotonic Anchor.
//!
//! This adapter uses AWS CLI v2 without a shell. It has not been run against AWS in this
//! environment (the AWS CLI is not installed here). Tests use a scripted command runner and
//! validate request construction, response validation and fail-closed outcomes.
//!
//! Production use requires a separately administered AWS account, single-region table, strict
//! IAM/SCP separation and an independent recovery custodian. This module does not provision AWS.
use crate::external_cas_bootstrap_trust_candidate::{
    mldsa65_key_fingerprint, VerifiedBootstrapTrust,
};
use crate::{
    external_cas_anchor_candidate::ExternalCasPin,
    external_cas_offhost_anchor_candidate::ExternalCasOffhostAnchorState,
    external_cas_offhost_anchor_protocol_candidate::{
        decode_state, encode_state, ExternalCasOffhostAnchorPin, ExternalCasOffhostAnchorStore,
        ExternalCasOffhostAnchorStoreCasOutcome, ExternalCasOffhostAnchorStoreError,
        ExternalCasOffhostAnchorStoreProvisionOutcome, OFFHOST_ANCHOR_STATE_BYTES,
    },
    v4_fat1_trust_candidate::ML_DSA_65_PUBLIC_KEY_BYTES,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroize;

const POLICY_VERSION: &str = "qrun-offhost-anchor-v1";
const BOOTSTRAP_RECEIPT_DIGEST_ATTRIBUTE: &str = "bootstrap_trust_receipt_digest";
const BOOTSTRAP_RECEIPT_WIRE_ATTRIBUTE: &str = "bootstrap_trust_receipt_wire_b64";
const BOOTSTRAP_INITIAL_STATE_DIGEST_ATTRIBUTE: &str = "bootstrap_initial_anchor_state_digest";

#[derive(Debug, Clone)]
struct BootstrapTrustBinding {
    receipt_digest: [u8; 32],
    initial_anchor_state_digest: [u8; 32],
    receipt_wire: Vec<u8>,
}

const CONDITION_EXPRESSION: &str =
    "attribute_exists(#anchor_id) AND #sequence = :expected_sequence AND #state_digest = :expected_state_digest";

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}
fn hex32(value: &[u8; 32]) -> String {
    hex(value)
}
fn parse_hex32(value: &str) -> Result<[u8; 32], ExternalCasOffhostAnchorStoreError> {
    if value.len() != 64 || !value.is_ascii() || value.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(ExternalCasOffhostAnchorStoreError::Corrupt);
    }
    let mut out = [0; 32];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| ExternalCasOffhostAnchorStoreError::Corrupt)?;
    }
    Ok(out)
}
fn public_key_hash(public_key: &[u8; ML_DSA_65_PUBLIC_KEY_BYTES]) -> String {
    hex(&Sha256::digest(public_key))
}
fn json_arg(value: &Value) -> Result<String, ExternalCasOffhostAnchorStoreError> {
    serde_json::to_string(value).map_err(|_| ExternalCasOffhostAnchorStoreError::Corrupt)
}
fn string_attribute(
    item: &Value,
    name: &str,
) -> Result<String, ExternalCasOffhostAnchorStoreError> {
    item.get(name)
        .and_then(|value| value.get("S"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(ExternalCasOffhostAnchorStoreError::Corrupt)
}
fn number_attribute(item: &Value, name: &str) -> Result<u64, ExternalCasOffhostAnchorStoreError> {
    let text = item
        .get(name)
        .and_then(|value| value.get("N"))
        .and_then(Value::as_str)
        .ok_or(ExternalCasOffhostAnchorStoreError::Corrupt)?;
    let number = text
        .parse::<u64>()
        .map_err(|_| ExternalCasOffhostAnchorStoreError::Corrupt)?;
    if number.to_string() != text {
        return Err(ExternalCasOffhostAnchorStoreError::Corrupt);
    }
    Ok(number)
}

#[derive(Debug, Clone)]
pub struct AwsDynamoDbCliOutput {
    pub success: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Injectable command boundary. The production runner invokes AWS CLI directly without a shell.
pub trait AwsDynamoDbCliRunner: Send + Sync {
    fn run(&self, arguments: &[OsString]) -> Result<AwsDynamoDbCliOutput, String>;
}

/// Short-lived STS assumed-role credentials captured once for one immutable AWS CLI session.
/// The secret material is never Clone, Debug output is redacted, and expiry is checked before
/// every child process. Callers must acquire these credentials out-of-band from an authorized
/// STS AssumeRole flow; this type does not discover ambient profiles or refresh credentials.
pub struct AwsTemporaryCredentialSession {
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
    expires_at_unix_seconds: u64,
}

impl std::fmt::Debug for AwsTemporaryCredentialSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsTemporaryCredentialSession")
            .field("access_key_id", &"<redacted>")
            .field("secret_access_key", &"<redacted>")
            .field("session_token", &"<redacted>")
            .field("expires_at_unix_seconds", &self.expires_at_unix_seconds)
            .finish()
    }
}

impl AwsTemporaryCredentialSession {
    pub fn new(
        mut access_key_id: String,
        mut secret_access_key: String,
        mut session_token: String,
        expires_at_unix_seconds: u64,
    ) -> Result<Self, String> {
        let safe_component = |value: &str| {
            !value.is_empty()
                && value.trim() == value
                && !value.chars().any(|character| character.is_control())
        };
        let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(value) => value.as_secs(),
            Err(_) => {
                access_key_id.zeroize();
                secret_access_key.zeroize();
                session_token.zeroize();
                return Err("system clock is before Unix epoch".to_owned());
            }
        };
        if !safe_component(&access_key_id)
            || !safe_component(&secret_access_key)
            || !safe_component(&session_token)
            || !credentials_valid_at(expires_at_unix_seconds, now)
        {
            access_key_id.zeroize();
            secret_access_key.zeroize();
            session_token.zeroize();
            return Err("invalid or expired temporary AWS credential session".into());
        }
        Ok(Self {
            access_key_id,
            secret_access_key,
            session_token,
            expires_at_unix_seconds,
        })
    }

    pub fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }
}

impl Drop for AwsTemporaryCredentialSession {
    fn drop(&mut self) {
        self.access_key_id.zeroize();
        self.secret_access_key.zeroize();
        self.session_token.zeroize();
    }
}

const AWS_SESSION_EXPIRY_SAFETY_SECONDS: u64 = 30;

fn credentials_valid_at(expires_at: u64, now: u64) -> bool {
    expires_at > now.saturating_add(AWS_SESSION_EXPIRY_SAFETY_SECONDS)
}

/// Production AWS CLI runner. Each operation gets the same immutable temporary STS
/// credentials, the same deployment region, a clean environment, and no ambient profile,
/// shared credentials, endpoint override, proxy, or metadata credential provider.
pub struct SessionBoundAwsDynamoDbCliRunner {
    executable: PathBuf,
    deployment_pin:
        crate::external_cas_offhost_anchor_aws_qualification_candidate::AwsDynamoDbDeploymentPin,
    session: AwsTemporaryCredentialSession,
    /// Optional exact KMS key ARN authorized for the Anchor signer on this same STS session.
    kms_key_arn: Option<String>,
    /// Read-only deployments refuse DynamoDB PutItem even if a caller bypasses the store facade.
    allow_dynamodb_put_item: bool,
}

impl std::fmt::Debug for SessionBoundAwsDynamoDbCliRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionBoundAwsDynamoDbCliRunner")
            .field("executable", &self.executable)
            .field("deployment_pin", &self.deployment_pin)
            .field("credential_session", &"<redacted>")
            .field("kms_key_arn", &self.kms_key_arn)
            .field("allow_dynamodb_put_item", &self.allow_dynamodb_put_item)
            .finish()
    }
}

impl SessionBoundAwsDynamoDbCliRunner {
    pub fn new(
        aws_cli: impl AsRef<Path>,
        deployment_pin: crate::external_cas_offhost_anchor_aws_qualification_candidate::AwsDynamoDbDeploymentPin,
        session: AwsTemporaryCredentialSession,
    ) -> Result<Self, String> {
        deployment_pin
            .validate()
            .map_err(|error| format!("invalid AWS deployment pin: {error:?}"))?;
        let requested_executable = aws_cli.as_ref();
        if !requested_executable.is_absolute() {
            return Err("AWS CLI executable path must be absolute".into());
        }
        let executable = std::fs::canonicalize(requested_executable)
            .map_err(|error| format!("cannot resolve AWS CLI executable: {error}"))?;
        if !executable.is_file() {
            return Err("AWS CLI executable is not a file".into());
        }
        Ok(Self {
            executable,
            deployment_pin,
            session,
            kms_key_arn: None,
            allow_dynamodb_put_item: true,
        })
    }

    /// Construct a separately pinned DynamoDB runner which can never issue PutItem.
    /// Intended for independently administered Q6TS read-only trust-floor roles.
    pub fn new_read_only(
        aws_cli: impl AsRef<Path>,
        deployment_pin: crate::external_cas_offhost_anchor_aws_qualification_candidate::AwsDynamoDbDeploymentPin,
        session: AwsTemporaryCredentialSession,
    ) -> Result<Self, String> {
        let mut runner = Self::new(aws_cli, deployment_pin, session)?;
        runner.allow_dynamodb_put_item = false;
        Ok(runner)
    }

    pub(crate) fn allows_dynamodb_put_item(&self) -> bool {
        self.allow_dynamodb_put_item
    }

    /// Construct a runner that may additionally invoke only GetPublicKey/Sign for one exact
    /// ML-DSA KMS key ARN in the same account, region, and temporary STS credential session.
    pub fn new_with_kms_key_arn(
        aws_cli: impl AsRef<Path>,
        deployment_pin: crate::external_cas_offhost_anchor_aws_qualification_candidate::AwsDynamoDbDeploymentPin,
        session: AwsTemporaryCredentialSession,
        kms_key_arn: impl Into<String>,
    ) -> Result<Self, String> {
        let mut runner = Self::new(aws_cli, deployment_pin, session)?;
        let key_arn = kms_key_arn.into();
        let expected_prefix = format!(
            "arn:aws:kms:{}:{}:key/",
            runner.deployment_pin.region, runner.deployment_pin.account_id
        );
        let key_id = key_arn.strip_prefix(&expected_prefix).unwrap_or("");
        if key_id.is_empty()
            || key_id.contains(':')
            || key_id.contains('/')
            || key_id
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        {
            return Err(
                "KMS key ARN must be a full key ARN in the pinned account and region".into(),
            );
        }
        runner.kms_key_arn = Some(key_arn);
        Ok(runner)
    }

    pub(crate) fn matches_kms_key_arn(&self, key_arn: &str) -> bool {
        self.kms_key_arn.as_deref() == Some(key_arn)
    }

    pub(crate) fn deployment_region(&self) -> &str {
        &self.deployment_pin.region
    }

    pub(crate) fn matches_deployment_pin(
        &self,
        pin: &crate::external_cas_offhost_anchor_aws_qualification_candidate::AwsDynamoDbDeploymentPin,
    ) -> bool {
        &self.deployment_pin == pin
    }

    fn environment_overrides(&self) -> Vec<(OsString, OsString)> {
        #[cfg(windows)]
        let null_device = "NUL";
        #[cfg(not(windows))]
        let null_device = "/dev/null";

        vec![
            (
                "AWS_ACCESS_KEY_ID".into(),
                self.session.access_key_id.clone().into(),
            ),
            (
                "AWS_SECRET_ACCESS_KEY".into(),
                self.session.secret_access_key.clone().into(),
            ),
            (
                "AWS_SESSION_TOKEN".into(),
                self.session.session_token.clone().into(),
            ),
            (
                "AWS_REGION".into(),
                self.deployment_pin.region.clone().into(),
            ),
            (
                "AWS_DEFAULT_REGION".into(),
                self.deployment_pin.region.clone().into(),
            ),
            ("AWS_CONFIG_FILE".into(), null_device.into()),
            ("AWS_SHARED_CREDENTIALS_FILE".into(), null_device.into()),
            ("AWS_EC2_METADATA_DISABLED".into(), "true".into()),
            ("AWS_IGNORE_CONFIGURED_ENDPOINT_URLS".into(), "true".into()),
            ("AWS_STS_REGIONAL_ENDPOINTS".into(), "regional".into()),
            ("AWS_RETRY_MODE".into(), "standard".into()),
            ("AWS_MAX_ATTEMPTS".into(), "3".into()),
            ("AWS_CLI_AUTO_PROMPT".into(), "off".into()),
            ("AWS_PAGER".into(), "".into()),
        ]
    }

    fn command_is_in_scope(&self, arguments: &[OsString]) -> bool {
        let args = arguments
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        if args.len() < 2 {
            return false;
        }

        let (allowed_pairs, allowed_bare, required_pairs, required_bare): (
            Vec<&str>,
            Vec<&str>,
            Vec<(&str, String)>,
            Vec<&str>,
        ) = match (
            args.first().map(String::as_str),
            args.get(1).map(String::as_str),
        ) {
            (Some("sts"), Some("get-caller-identity")) => (
                vec!["--region", "--output"],
                vec!["--no-cli-pager"],
                vec![
                    ("--region", self.deployment_pin.region.clone()),
                    ("--output", "json".into()),
                ],
                vec!["--no-cli-pager"],
            ),
            (Some("iam"), Some("get-role")) => (
                vec!["--role-name", "--output"],
                vec!["--no-cli-pager"],
                vec![
                    (
                        "--role-name",
                        self.deployment_pin
                            .role_arn
                            .rsplit('/')
                            .next()
                            .unwrap_or("")
                            .to_owned(),
                    ),
                    ("--output", "json".into()),
                ],
                vec!["--no-cli-pager"],
            ),
            (Some("dynamodb"), Some("describe-table" | "describe-continuous-backups")) => (
                vec!["--table-name", "--region", "--output"],
                vec!["--no-cli-pager"],
                vec![
                    ("--table-name", self.deployment_pin.table_name.clone()),
                    ("--region", self.deployment_pin.region.clone()),
                    ("--output", "json".into()),
                ],
                vec!["--no-cli-pager"],
            ),
            (Some("dynamodb"), Some("get-item")) => (
                vec![
                    "--table-name",
                    "--region",
                    "--output",
                    "--key",
                    "--cli-connect-timeout",
                    "--cli-read-timeout",
                ],
                vec!["--no-cli-pager", "--consistent-read"],
                vec![
                    ("--table-name", self.deployment_pin.table_name.clone()),
                    ("--region", self.deployment_pin.region.clone()),
                    ("--output", "json".into()),
                    ("--cli-connect-timeout", "5".into()),
                    ("--cli-read-timeout", "15".into()),
                ],
                vec!["--no-cli-pager", "--consistent-read"],
            ),
            (Some("dynamodb"), Some("put-item")) if !self.allow_dynamodb_put_item => {
                return false;
            }
            (Some("dynamodb"), Some("put-item")) => (
                vec![
                    "--table-name",
                    "--region",
                    "--output",
                    "--item",
                    "--condition-expression",
                    "--expression-attribute-names",
                    "--expression-attribute-values",
                    "--cli-connect-timeout",
                    "--cli-read-timeout",
                ],
                vec!["--no-cli-pager"],
                vec![
                    ("--table-name", self.deployment_pin.table_name.clone()),
                    ("--region", self.deployment_pin.region.clone()),
                    ("--output", "json".into()),
                    ("--cli-connect-timeout", "5".into()),
                    ("--cli-read-timeout", "15".into()),
                ],
                vec!["--no-cli-pager"],
            ),
            (Some("kms"), Some("get-public-key")) => (
                vec![
                    "--key-id",
                    "--region",
                    "--output",
                    "--cli-connect-timeout",
                    "--cli-read-timeout",
                ],
                vec!["--no-cli-pager"],
                vec![
                    ("--key-id", self.kms_key_arn.clone().unwrap_or_default()),
                    ("--region", self.deployment_pin.region.clone()),
                    ("--output", "json".into()),
                    ("--cli-connect-timeout", "5".into()),
                    ("--cli-read-timeout", "20".into()),
                ],
                vec!["--no-cli-pager"],
            ),
            (Some("kms"), Some("sign")) => (
                vec![
                    "--key-id",
                    "--message",
                    "--message-type",
                    "--signing-algorithm",
                    "--region",
                    "--output",
                    "--cli-connect-timeout",
                    "--cli-read-timeout",
                ],
                vec!["--no-cli-pager"],
                vec![
                    ("--key-id", self.kms_key_arn.clone().unwrap_or_default()),
                    ("--message-type", "RAW".into()),
                    ("--signing-algorithm", "ML_DSA_SHAKE_256".into()),
                    ("--region", self.deployment_pin.region.clone()),
                    ("--output", "json".into()),
                    ("--cli-connect-timeout", "5".into()),
                    ("--cli-read-timeout", "20".into()),
                ],
                vec!["--no-cli-pager"],
            ),
            _ => return false,
        };

        let mut seen = std::collections::HashSet::new();
        let mut index = 2;
        while index < args.len() {
            let flag = args[index].as_str();
            if !seen.insert(flag.to_owned()) {
                return false;
            }
            if allowed_bare.contains(&flag) {
                index += 1;
                continue;
            }
            if !allowed_pairs.contains(&flag) || index + 1 >= args.len() {
                return false;
            }
            index += 2;
        }
        for (flag, expected) in required_pairs {
            if args.windows(2).filter(|pair| pair[0] == flag).count() != 1
                || !args
                    .windows(2)
                    .any(|pair| pair[0] == flag && pair[1] == expected)
            {
                return false;
            }
        }
        for flag in required_bare {
            if !seen.contains(flag) {
                return false;
            }
        }
        match args.get(1).map(String::as_str) {
            Some("get-item") if !seen.contains("--key") => return false,
            Some("put-item")
                if !seen.contains("--item")
                    || !seen.contains("--condition-expression")
                    || !seen.contains("--expression-attribute-names") =>
            {
                return false;
            }
            Some("sign") => {
                let encoded = args
                    .windows(2)
                    .find(|pair| pair[0] == "--message")
                    .map(|pair| pair[1].as_str())
                    .unwrap_or("");
                if encoded.is_empty()
                    || BASE64
                        .decode(encoded)
                        .map(|message| message.len() != 32)
                        .unwrap_or(true)
                {
                    return false;
                }
            }
            _ => {}
        }
        true
    }
}

impl AwsDynamoDbCliRunner for SessionBoundAwsDynamoDbCliRunner {
    fn run(&self, arguments: &[OsString]) -> Result<AwsDynamoDbCliOutput, String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system clock is before Unix epoch".to_owned())?
            .as_secs();
        if !credentials_valid_at(self.session.expires_at_unix_seconds, now) {
            return Err("temporary AWS credential session expired or inside safety window".into());
        }
        if !self.command_is_in_scope(arguments) {
            return Err("AWS CLI command is outside the pinned session scope".into());
        }

        let mut command = Command::new(&self.executable);
        command.args(arguments).env_clear();
        for (key, value) in self.environment_overrides() {
            command.env(key, value);
        }
        // Windows process startup and system certificate-store access require these OS
        // variables. They are not inherited AWS/profile/proxy configuration.
        #[cfg(windows)]
        for name in ["SystemRoot", "WINDIR", "TEMP", "TMP"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        let output = command.output().map_err(|error| error.to_string())?;
        Ok(AwsDynamoDbCliOutput {
            success: output.status.success(),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}

#[cfg(test)]
struct ProcessAwsDynamoDbCliRunner {
    executable: PathBuf,
}
#[cfg(test)]
impl AwsDynamoDbCliRunner for ProcessAwsDynamoDbCliRunner {
    fn run(&self, arguments: &[OsString]) -> Result<AwsDynamoDbCliOutput, String> {
        let output = Command::new(&self.executable)
            .args(arguments)
            .output()
            .map_err(|error| error.to_string())?;
        Ok(AwsDynamoDbCliOutput {
            success: output.status.success(),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}

pub struct AwsDynamoDbOffhostAnchorStore {
    runner: Arc<dyn AwsDynamoDbCliRunner>,
    region: String,
    table_name: String,
    anchor_pin: ExternalCasOffhostAnchorPin,
    provider_pin: ExternalCasPin,
    bootstrap_trust: Option<BootstrapTrustBinding>,
}
impl std::fmt::Debug for AwsDynamoDbOffhostAnchorStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsDynamoDbOffhostAnchorStore")
            .field("region", &self.region)
            .field("table_name", &self.table_name)
            .field("anchor_id", &hex32(&self.anchor_pin.anchor_id))
            .field("provider_id", &hex32(&self.provider_pin.provider_id))
            .field("network_id", &hex32(&self.provider_pin.network_id))
            .field(
                "bootstrap_trust_receipt_digest",
                &self
                    .bootstrap_trust
                    .as_ref()
                    .map(|b| hex32(&b.receipt_digest)),
            )
            .field("aws_credentials", &"<session-bound or test-injected>")
            .finish()
    }
}
impl AwsDynamoDbOffhostAnchorStore {
    #[cfg(test)]
    pub(crate) fn new(
        aws_cli: impl AsRef<Path>,
        region: impl Into<String>,
        table_name: impl Into<String>,
        anchor_pin: ExternalCasOffhostAnchorPin,
        provider_pin: ExternalCasPin,
    ) -> Result<Self, ExternalCasOffhostAnchorStoreError> {
        let executable = aws_cli.as_ref();
        if executable.as_os_str().is_empty() {
            return Err(ExternalCasOffhostAnchorStoreError::Unavailable);
        }
        Self::with_runner(
            Arc::new(ProcessAwsDynamoDbCliRunner {
                executable: executable.to_path_buf(),
            }),
            region,
            table_name,
            anchor_pin,
            provider_pin,
        )
    }

    #[cfg(test)]
    pub(crate) fn from_path(
        region: impl Into<String>,
        table_name: impl Into<String>,
        anchor_pin: ExternalCasOffhostAnchorPin,
        provider_pin: ExternalCasPin,
    ) -> Result<Self, ExternalCasOffhostAnchorStoreError> {
        Self::new("aws", region, table_name, anchor_pin, provider_pin)
    }

    /// QBT1-bound constructor: callers must provide a sealed result of successful dual-signature verification.
    pub(crate) fn with_verified_bootstrap_runner(
        runner: Arc<dyn AwsDynamoDbCliRunner>,
        region: impl Into<String>,
        table_name: impl Into<String>,
        anchor_pin: ExternalCasOffhostAnchorPin,
        provider_pin: ExternalCasPin,
        verified: &VerifiedBootstrapTrust,
    ) -> Result<Self, ExternalCasOffhostAnchorStoreError> {
        anchor_pin
            .validate(&provider_pin)
            .map_err(|_| ExternalCasOffhostAnchorStoreError::Corrupt)?;
        let receipt = verified.receipt();
        let initial_state = verified.initial_anchor_state();
        initial_state
            .validate(&provider_pin)
            .map_err(|_| ExternalCasOffhostAnchorStoreError::Corrupt)?;
        if receipt.provider_id != provider_pin.provider_id
            || receipt.anchor_id != anchor_pin.anchor_id
            || receipt.network_id != provider_pin.network_id
            || receipt.genesis_digest != provider_pin.genesis_digest
            || receipt.provider_receipt_key_id != provider_pin.receipt_key_id
            || receipt.provider_receipt_key_fingerprint
                != mldsa65_key_fingerprint(&provider_pin.receipt_public_key)
            || receipt.anchor_receipt_key_id != anchor_pin.receipt_key_id
            || receipt.anchor_receipt_key_fingerprint
                != mldsa65_key_fingerprint(&anchor_pin.receipt_public_key)
            || initial_state.sequence != 1
            || initial_state.provider_object_generation != 1
            || initial_state.provider_record.generation != 0
            || initial_state
                .digest()
                .map_err(|_| ExternalCasOffhostAnchorStoreError::Corrupt)?
                != receipt.initial_anchor_state_digest
            || initial_state
                .provider_record
                .digest()
                .map_err(|_| ExternalCasOffhostAnchorStoreError::Corrupt)?
                != receipt.initial_record_digest
        {
            return Err(ExternalCasOffhostAnchorStoreError::Corrupt);
        }
        let receipt_wire = verified
            .receipt_wire()
            .map_err(|_| ExternalCasOffhostAnchorStoreError::Corrupt)?;
        let receipt_digest = verified.receipt_digest();
        if receipt
            .digest()
            .map_err(|_| ExternalCasOffhostAnchorStoreError::Corrupt)?
            != receipt_digest
        {
            return Err(ExternalCasOffhostAnchorStoreError::Corrupt);
        }
        let mut store = Self::with_runner(runner, region, table_name, anchor_pin, provider_pin)?;
        store.bootstrap_trust = Some(BootstrapTrustBinding {
            receipt_digest,
            initial_anchor_state_digest: receipt.initial_anchor_state_digest,
            receipt_wire,
        });
        Ok(store)
    }

    #[cfg(test)]
    pub(crate) fn new_with_verified_bootstrap(
        aws_cli: impl AsRef<Path>,
        region: impl Into<String>,
        table_name: impl Into<String>,
        anchor_pin: ExternalCasOffhostAnchorPin,
        provider_pin: ExternalCasPin,
        verified: &VerifiedBootstrapTrust,
    ) -> Result<Self, ExternalCasOffhostAnchorStoreError> {
        let executable = aws_cli.as_ref();
        if executable.as_os_str().is_empty() {
            return Err(ExternalCasOffhostAnchorStoreError::Unavailable);
        }
        Self::with_verified_bootstrap_runner(
            Arc::new(ProcessAwsDynamoDbCliRunner {
                executable: executable.to_path_buf(),
            }),
            region,
            table_name,
            anchor_pin,
            provider_pin,
            verified,
        )
    }
    pub(crate) fn with_runner(
        runner: Arc<dyn AwsDynamoDbCliRunner>,
        region: impl Into<String>,
        table_name: impl Into<String>,
        anchor_pin: ExternalCasOffhostAnchorPin,
        provider_pin: ExternalCasPin,
    ) -> Result<Self, ExternalCasOffhostAnchorStoreError> {
        let region = region.into();
        let table_name = table_name.into();
        if region.is_empty()
            || !region.is_ascii()
            || region.chars().any(char::is_whitespace)
            || table_name.is_empty()
            || !table_name.is_ascii()
            || table_name.chars().any(char::is_whitespace)
        {
            return Err(ExternalCasOffhostAnchorStoreError::Unavailable);
        }
        anchor_pin
            .validate(&provider_pin)
            .map_err(|_| ExternalCasOffhostAnchorStoreError::Corrupt)?;
        Ok(Self {
            runner,
            region,
            table_name,
            anchor_pin,
            provider_pin,
            bootstrap_trust: None,
        })
    }

    fn run(
        &self,
        arguments: &[OsString],
    ) -> Result<AwsDynamoDbCliOutput, ExternalCasOffhostAnchorStoreError> {
        self.runner
            .run(arguments)
            .map_err(|_| ExternalCasOffhostAnchorStoreError::Unavailable)
    }

    fn get_item_args(&self) -> Result<Vec<OsString>, ExternalCasOffhostAnchorStoreError> {
        let key = json!({
            "anchor_id": { "S": hex32(&self.anchor_pin.anchor_id) }
        });
        Ok([
            "dynamodb",
            "get-item",
            "--table-name",
            &self.table_name,
            "--key",
            &json_arg(&key)?,
            "--consistent-read",
            "--no-cli-pager",
            "--cli-connect-timeout",
            "5",
            "--cli-read-timeout",
            "15",
            "--region",
            &self.region,
            "--output",
            "json",
        ]
        .iter()
        .map(OsString::from)
        .collect())
    }

    fn item_for_state(
        &self,
        state: &ExternalCasOffhostAnchorState,
    ) -> Result<Value, ExternalCasOffhostAnchorStoreError> {
        state
            .validate(&self.provider_pin)
            .map_err(|_| ExternalCasOffhostAnchorStoreError::Corrupt)?;
        let wire = encode_state(state).map_err(|_| ExternalCasOffhostAnchorStoreError::Corrupt)?;
        let digest = state
            .digest()
            .map_err(|_| ExternalCasOffhostAnchorStoreError::Corrupt)?;
        let mut item = json!({
            "anchor_id": { "S": hex32(&self.anchor_pin.anchor_id) },
            "provider_id": { "S": hex32(&self.provider_pin.provider_id) },
            "network_id": { "S": hex32(&self.provider_pin.network_id) },
            "genesis_digest": { "S": hex32(&self.provider_pin.genesis_digest) },
            "provider_receipt_key_id": { "S": hex32(&self.provider_pin.receipt_key_id) },
            "provider_receipt_public_key_sha256": {
                "S": public_key_hash(&self.provider_pin.receipt_public_key)
            },
            "anchor_receipt_key_id": { "S": hex32(&self.anchor_pin.receipt_key_id) },
            "anchor_receipt_public_key_sha256": {
                "S": public_key_hash(&self.anchor_pin.receipt_public_key)
            },
            "policy_version": { "S": POLICY_VERSION },
            "sequence": { "N": state.sequence.to_string() },
            "provider_object_generation": { "N": state.provider_object_generation.to_string() },
            "state_digest": { "S": hex32(&digest) },
            "state_wire_b64": { "S": BASE64.encode(wire) }
        });

        if let Some(binding) = &self.bootstrap_trust {
            item[BOOTSTRAP_RECEIPT_DIGEST_ATTRIBUTE] =
                json!({ "S": hex32(&binding.receipt_digest) });
            item[BOOTSTRAP_RECEIPT_WIRE_ATTRIBUTE] =
                json!({ "S": BASE64.encode(&binding.receipt_wire) });
            item[BOOTSTRAP_INITIAL_STATE_DIGEST_ATTRIBUTE] =
                json!({ "S": hex32(&binding.initial_anchor_state_digest) });
        }
        Ok(item)
    }
    fn parse_item(
        &self,
        item: &Value,
    ) -> Result<ExternalCasOffhostAnchorState, ExternalCasOffhostAnchorStoreError> {
        for (name, expected) in [
            ("anchor_id", hex32(&self.anchor_pin.anchor_id)),
            ("provider_id", hex32(&self.provider_pin.provider_id)),
            ("network_id", hex32(&self.provider_pin.network_id)),
            ("genesis_digest", hex32(&self.provider_pin.genesis_digest)),
            (
                "provider_receipt_key_id",
                hex32(&self.provider_pin.receipt_key_id),
            ),
            (
                "provider_receipt_public_key_sha256",
                public_key_hash(&self.provider_pin.receipt_public_key),
            ),
            (
                "anchor_receipt_key_id",
                hex32(&self.anchor_pin.receipt_key_id),
            ),
            (
                "anchor_receipt_public_key_sha256",
                public_key_hash(&self.anchor_pin.receipt_public_key),
            ),
            ("policy_version", POLICY_VERSION.to_owned()),
        ] {
            if string_attribute(item, name)? != expected {
                return Err(ExternalCasOffhostAnchorStoreError::Corrupt);
            }
        }
        match &self.bootstrap_trust {
            Some(binding) => {
                if string_attribute(item, BOOTSTRAP_RECEIPT_DIGEST_ATTRIBUTE)?
                    != hex32(&binding.receipt_digest)
                    || string_attribute(item, BOOTSTRAP_RECEIPT_WIRE_ATTRIBUTE)?
                        != BASE64.encode(&binding.receipt_wire)
                    || string_attribute(item, BOOTSTRAP_INITIAL_STATE_DIGEST_ATTRIBUTE)?
                        != hex32(&binding.initial_anchor_state_digest)
                {
                    return Err(ExternalCasOffhostAnchorStoreError::Corrupt);
                }
            }
            None => {
                if item.get(BOOTSTRAP_RECEIPT_DIGEST_ATTRIBUTE).is_some()
                    || item.get(BOOTSTRAP_RECEIPT_WIRE_ATTRIBUTE).is_some()
                    || item.get(BOOTSTRAP_INITIAL_STATE_DIGEST_ATTRIBUTE).is_some()
                {
                    return Err(ExternalCasOffhostAnchorStoreError::Corrupt);
                }
            }
        }
        let sequence = number_attribute(item, "sequence")?;
        let provider_object_generation = number_attribute(item, "provider_object_generation")?;
        let expected_digest = parse_hex32(&string_attribute(item, "state_digest")?)?;
        let wire_text = string_attribute(item, "state_wire_b64")?;
        let wire = BASE64
            .decode(&wire_text)
            .map_err(|_| ExternalCasOffhostAnchorStoreError::Corrupt)?;
        if wire.len() != OFFHOST_ANCHOR_STATE_BYTES {
            return Err(ExternalCasOffhostAnchorStoreError::Corrupt);
        }
        let state = decode_state(&wire).map_err(|_| ExternalCasOffhostAnchorStoreError::Corrupt)?;
        state
            .validate(&self.provider_pin)
            .map_err(|_| ExternalCasOffhostAnchorStoreError::Corrupt)?;
        let actual_digest = state
            .digest()
            .map_err(|_| ExternalCasOffhostAnchorStoreError::Corrupt)?;
        if state.sequence != sequence
            || state.provider_object_generation != provider_object_generation
            || actual_digest != expected_digest
            || BASE64.encode(
                encode_state(&state).map_err(|_| ExternalCasOffhostAnchorStoreError::Corrupt)?,
            ) != wire_text
        {
            return Err(ExternalCasOffhostAnchorStoreError::Corrupt);
        }
        Ok(state)
    }
}
impl ExternalCasOffhostAnchorStore for AwsDynamoDbOffhostAnchorStore {
    fn provision_bootstrap_if_absent(
        &self,
        bootstrap: &ExternalCasOffhostAnchorState,
    ) -> Result<ExternalCasOffhostAnchorStoreProvisionOutcome, ExternalCasOffhostAnchorStoreError>
    {
        // A bootstrap is exactly the generation-zero record at Anchor sequence/object generation
        // one. Validation also requires every operation/receipt/predecessor field to be zero.
        if bootstrap.provider_record.generation != 0 || bootstrap.sequence != 1 {
            return Err(ExternalCasOffhostAnchorStoreError::Corrupt);
        }
        bootstrap
            .validate(&self.provider_pin)
            .map_err(|_| ExternalCasOffhostAnchorStoreError::Corrupt)?;

        if let Some(binding) = &self.bootstrap_trust {
            if bootstrap.sequence != 1
                || bootstrap.provider_object_generation != 1
                || bootstrap.provider_record.generation != 0
                || bootstrap
                    .digest()
                    .map_err(|_| ExternalCasOffhostAnchorStoreError::Corrupt)?
                    != binding.initial_anchor_state_digest
            {
                return Err(ExternalCasOffhostAnchorStoreError::Corrupt);
            }
        }
        let item = self.item_for_state(bootstrap)?;
        let names = json!({ "#anchor_id": "anchor_id" });
        let arguments: Vec<OsString> = [
            "dynamodb",
            "put-item",
            "--table-name",
            &self.table_name,
            "--item",
            &json_arg(&item)?,
            "--condition-expression",
            "attribute_not_exists(#anchor_id)",
            "--expression-attribute-names",
            &json_arg(&names)?,
            "--no-cli-pager",
            "--cli-connect-timeout",
            "5",
            "--cli-read-timeout",
            "15",
            "--region",
            &self.region,
            "--output",
            "json",
        ]
        .iter()
        .map(OsString::from)
        .collect();

        let output = self.run(&arguments)?;
        if !output.success {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("ConditionalCheckFailedException") {
                // Another provisioner won the one-time insert. Read the item authoritatively;
                // never trust a CLI conflict payload or treat the caller's bootstrap as installed.
                let current = self.load_consistent()?;
                return Ok(ExternalCasOffhostAnchorStoreProvisionOutcome::AlreadyExists(current));
            }
            return Err(ExternalCasOffhostAnchorStoreError::Unavailable);
        }

        // PutItem success is not enough for the ceremony: confirm the complete state by a fresh
        // strongly consistent read before reporting that provisioning completed.
        let current = self.load_consistent()?;
        if current != *bootstrap {
            return Err(ExternalCasOffhostAnchorStoreError::Corrupt);
        }
        Ok(ExternalCasOffhostAnchorStoreProvisionOutcome::Provisioned)
    }

    fn load_consistent(
        &self,
    ) -> Result<ExternalCasOffhostAnchorState, ExternalCasOffhostAnchorStoreError> {
        let output = self.run(&self.get_item_args()?)?;
        if !output.success {
            return Err(ExternalCasOffhostAnchorStoreError::Unavailable);
        }
        let response: Value = serde_json::from_slice(&output.stdout)
            .map_err(|_| ExternalCasOffhostAnchorStoreError::Corrupt)?;
        let item = response
            .get("Item")
            .and_then(Value::as_object)
            .filter(|item| !item.is_empty())
            .ok_or(ExternalCasOffhostAnchorStoreError::Corrupt)?;
        self.parse_item(&Value::Object(item.clone()))
    }

    fn compare_and_swap_atomic(
        &self,
        expected_sequence: u64,
        expected_state_digest: &[u8; 32],
        next_state: &ExternalCasOffhostAnchorState,
    ) -> Result<ExternalCasOffhostAnchorStoreCasOutcome, ExternalCasOffhostAnchorStoreError> {
        if expected_sequence == 0
            || zero(expected_state_digest)
            || next_state.sequence != expected_sequence.checked_add(1).unwrap_or(0)
            || next_state.last_expected_anchor_sequence != expected_sequence
            || next_state.last_expected_anchor_state_digest != *expected_state_digest
        {
            return Err(ExternalCasOffhostAnchorStoreError::Corrupt);
        }
        let item = self.item_for_state(next_state)?;
        let mut values = json!({
            ":expected_sequence": { "N": expected_sequence.to_string() },
            ":expected_state_digest": { "S": hex32(expected_state_digest) }
        });
        let mut names = json!({
            "#anchor_id": "anchor_id",
            "#sequence": "sequence",
            "#state_digest": "state_digest"
        });
        let condition_expression = if let Some(binding) = &self.bootstrap_trust {
            values[":bootstrap_trust_receipt_digest"] =
                json!({ "S": hex32(&binding.receipt_digest) });
            values[":bootstrap_initial_state_digest"] =
                json!({ "S": hex32(&binding.initial_anchor_state_digest) });
            values[":bootstrap_trust_receipt_wire_b64"] =
                json!({ "S": BASE64.encode(&binding.receipt_wire) });
            names["#bootstrap_trust_receipt_digest"] =
                Value::String(BOOTSTRAP_RECEIPT_DIGEST_ATTRIBUTE.to_owned());
            names["#bootstrap_initial_state_digest"] =
                Value::String(BOOTSTRAP_INITIAL_STATE_DIGEST_ATTRIBUTE.to_owned());
            names["#bootstrap_trust_receipt_wire_b64"] =
                Value::String(BOOTSTRAP_RECEIPT_WIRE_ATTRIBUTE.to_owned());
            format!(
                "{CONDITION_EXPRESSION} AND #bootstrap_trust_receipt_digest = :bootstrap_trust_receipt_digest AND #bootstrap_initial_state_digest = :bootstrap_initial_state_digest AND #bootstrap_trust_receipt_wire_b64 = :bootstrap_trust_receipt_wire_b64"
            )
        } else {
            CONDITION_EXPRESSION.to_owned()
        };
        let arguments: Vec<OsString> = [
            "dynamodb",
            "put-item",
            "--table-name",
            &self.table_name,
            "--item",
            &json_arg(&item)?,
            "--condition-expression",
            &condition_expression,
            "--expression-attribute-names",
            &json_arg(&names)?,
            "--expression-attribute-values",
            &json_arg(&values)?,
            "--no-cli-pager",
            "--cli-connect-timeout",
            "5",
            "--cli-read-timeout",
            "15",
            "--region",
            &self.region,
            "--output",
            "json",
        ]
        .iter()
        .map(OsString::from)
        .collect();
        let output = self.run(&arguments)?;
        if output.success {
            return Ok(ExternalCasOffhostAnchorStoreCasOutcome::Applied);
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("ConditionalCheckFailedException") {
            let current = self.load_consistent()?;
            return Ok(ExternalCasOffhostAnchorStoreCasOutcome::Conflict(current));
        }
        Err(ExternalCasOffhostAnchorStoreError::Unavailable)
    }
}

fn zero(value: &[u8; 32]) -> bool {
    value.iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::external_cas_bootstrap_trust_candidate::VerifiedBootstrapTrust;
    use crate::{
        external_cas_anchor_candidate::ExternalCasRecord,
        external_cas_offhost_anchor_candidate::ExternalCasOffhostAnchorState,
    };
    use std::{collections::VecDeque, ffi::OsString, sync::Mutex};

    #[derive(Default)]
    struct ScriptedRunner {
        responses: Mutex<VecDeque<AwsDynamoDbCliOutput>>,
        calls: Mutex<Vec<Vec<String>>>,
    }
    impl ScriptedRunner {
        fn new(responses: Vec<AwsDynamoDbCliOutput>) -> Self {
            Self {
                responses: Mutex::new(responses.into()),
                calls: Mutex::new(Vec::new()),
            }
        }
        fn calls(&self) -> Vec<Vec<String>> {
            self.calls.lock().unwrap().clone()
        }
    }
    impl AwsDynamoDbCliRunner for ScriptedRunner {
        fn run(&self, arguments: &[OsString]) -> Result<AwsDynamoDbCliOutput, String> {
            self.calls.lock().unwrap().push(
                arguments
                    .iter()
                    .map(|value| value.to_string_lossy().into_owned())
                    .collect(),
            );
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| "no scripted response".to_owned())
        }
    }

    struct Fixture {
        anchor_pin: ExternalCasOffhostAnchorPin,
        provider_pin: ExternalCasPin,
        bootstrap: ExternalCasOffhostAnchorState,
    }
    fn fixture() -> Fixture {
        let provider_pin = ExternalCasPin {
            provider_id: [0x11; 32],
            network_id: [0x22; 32],
            genesis_digest: [0x33; 32],
            receipt_key_id: [0x44; 32],
            receipt_public_key: [0x45; ML_DSA_65_PUBLIC_KEY_BYTES],
        };
        let anchor_pin = ExternalCasOffhostAnchorPin {
            anchor_id: [0x91; 32],
            provider_id: provider_pin.provider_id,
            network_id: provider_pin.network_id,
            genesis_digest: provider_pin.genesis_digest,
            receipt_key_id: [0x92; 32],
            receipt_public_key: [0x93; ML_DSA_65_PUBLIC_KEY_BYTES],
        };
        let bootstrap_record = ExternalCasRecord {
            generation: 0,
            provider_id: provider_pin.provider_id,
            network_id: provider_pin.network_id,
            genesis_digest: provider_pin.genesis_digest,
            previous_record_digest: [0; 32],
            previous_state_digest: [0; 32],
            next_state_digest: [0x55; 32],
            operation_id: [0x66; 32],
            request_digest: [0x77; 32],
        };
        let bootstrap =
            ExternalCasOffhostAnchorState::provision_bootstrap(&provider_pin, bootstrap_record, 1)
                .unwrap();
        Fixture {
            anchor_pin,
            provider_pin,
            bootstrap,
        }
    }
    fn store_with(f: &Fixture, runner: Arc<ScriptedRunner>) -> AwsDynamoDbOffhostAnchorStore {
        AwsDynamoDbOffhostAnchorStore::with_runner(
            runner,
            "us-east-1",
            "qrun-offhost-anchor",
            f.anchor_pin.clone(),
            f.provider_pin.clone(),
        )
        .unwrap()
    }
    fn qbt_store_with(
        provider_pin: &ExternalCasPin,
        anchor_pin: &ExternalCasOffhostAnchorPin,
        verified: &VerifiedBootstrapTrust,
        runner: Arc<ScriptedRunner>,
    ) -> AwsDynamoDbOffhostAnchorStore {
        AwsDynamoDbOffhostAnchorStore::with_verified_bootstrap_runner(
            runner,
            "us-east-1",
            "qrun-offhost-anchor",
            anchor_pin.clone(),
            provider_pin.clone(),
            verified,
        )
        .unwrap()
    }
    fn cli_ok(stdout: Vec<u8>) -> AwsDynamoDbCliOutput {
        AwsDynamoDbCliOutput {
            success: true,
            stdout,
            stderr: Vec::new(),
        }
    }
    fn cli_error(stderr: &str) -> AwsDynamoDbCliOutput {
        AwsDynamoDbCliOutput {
            success: false,
            stdout: Vec::new(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }
    fn item_response(
        store: &AwsDynamoDbOffhostAnchorStore,
        state: &ExternalCasOffhostAnchorState,
    ) -> Vec<u8> {
        serde_json::to_vec(&json!({ "Item": store.item_for_state(state).unwrap() })).unwrap()
    }
    fn next_state(f: &Fixture) -> ExternalCasOffhostAnchorState {
        let current = &f.bootstrap;
        let predecessor_digest = current.provider_record.digest().unwrap();
        let predecessor_state_digest = current.digest().unwrap();
        let operation_id = [0xA1; 32];
        let request_digest = [0xA2; 32];
        let record = ExternalCasRecord {
            generation: 1,
            provider_id: f.provider_pin.provider_id,
            network_id: f.provider_pin.network_id,
            genesis_digest: f.provider_pin.genesis_digest,
            previous_record_digest: predecessor_digest,
            previous_state_digest: current.provider_record.next_state_digest,
            next_state_digest: [0xA3; 32],
            operation_id,
            request_digest,
        };
        let state = ExternalCasOffhostAnchorState {
            sequence: 2,
            provider_object_generation: 2,
            provider_record: record,
            last_operation_id: operation_id,
            last_request_digest: request_digest,
            last_provider_receipt_digest: [0xA4; 32],
            last_expected_anchor_sequence: current.sequence,
            last_expected_anchor_state_digest: predecessor_state_digest,
        };
        state.validate(&f.provider_pin).unwrap();
        state
    }
    fn argument_value<'a>(args: &'a [String], flag: &str) -> &'a str {
        let index = args.iter().position(|arg| arg == flag).unwrap();
        &args[index + 1]
    }

    #[test]
    fn explicit_bootstrap_uses_absent_key_condition_and_strong_readback() {
        let f = fixture();
        let placeholder = store_with(&f, Arc::new(ScriptedRunner::default()));
        let persisted = item_response(&placeholder, &f.bootstrap);
        let runner = Arc::new(ScriptedRunner::new(vec![
            cli_ok(b"{}".to_vec()),
            cli_ok(persisted),
        ]));
        let store = store_with(&f, runner.clone());

        assert_eq!(
            store.provision_bootstrap_if_absent(&f.bootstrap).unwrap(),
            ExternalCasOffhostAnchorStoreProvisionOutcome::Provisioned
        );
        let calls = runner.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0][1], "put-item");
        assert_eq!(
            argument_value(&calls[0], "--condition-expression"),
            "attribute_not_exists(#anchor_id)"
        );
        let names: Value =
            serde_json::from_str(argument_value(&calls[0], "--expression-attribute-names"))
                .unwrap();
        assert_eq!(names["#anchor_id"], "anchor_id");
        assert_eq!(calls[1][1], "get-item");
        assert!(calls[1].iter().any(|arg| arg == "--consistent-read"));
    }

    #[test]
    fn concurrent_bootstrap_loser_reads_and_returns_existing_authoritative_state() {
        let f = fixture();
        let placeholder = store_with(&f, Arc::new(ScriptedRunner::default()));
        let existing = item_response(&placeholder, &f.bootstrap);
        let runner = Arc::new(ScriptedRunner::new(vec![
            cli_error("An error occurred (ConditionalCheckFailedException) when calling the PutItem operation."),
            cli_ok(existing),
        ]));
        let store = store_with(&f, runner.clone());

        assert_eq!(
            store.provision_bootstrap_if_absent(&f.bootstrap).unwrap(),
            ExternalCasOffhostAnchorStoreProvisionOutcome::AlreadyExists(f.bootstrap.clone())
        );
        let calls = runner.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1][1], "get-item");
        assert!(calls[1].iter().any(|arg| arg == "--consistent-read"));
    }

    #[test]
    fn bootstrap_refuses_nonzero_generation_before_any_aws_call() {
        let f = fixture();
        let invalid = next_state(&f);
        let runner = Arc::new(ScriptedRunner::default());
        let store = store_with(&f, runner.clone());

        assert_eq!(
            store.provision_bootstrap_if_absent(&invalid),
            Err(ExternalCasOffhostAnchorStoreError::Corrupt)
        );
        assert!(runner.calls().is_empty());
    }

    #[test]
    fn bootstrap_nonconditional_aws_failure_is_unavailable() {
        let f = fixture();
        let runner = Arc::new(ScriptedRunner::new(vec![cli_error(
            "AccessDeniedException",
        )]));
        let store = store_with(&f, runner.clone());

        assert_eq!(
            store.provision_bootstrap_if_absent(&f.bootstrap),
            Err(ExternalCasOffhostAnchorStoreError::Unavailable)
        );
        assert_eq!(runner.calls().len(), 1);
    }

    #[test]
    fn bootstrap_success_requires_exact_strong_readback() {
        let f = fixture();
        let placeholder = store_with(&f, Arc::new(ScriptedRunner::default()));
        let conflicting_state = next_state(&f);
        let response = item_response(&placeholder, &conflicting_state);
        let runner = Arc::new(ScriptedRunner::new(vec![
            cli_ok(b"{}".to_vec()),
            cli_ok(response),
        ]));
        let store = store_with(&f, runner.clone());

        assert_eq!(
            store.provision_bootstrap_if_absent(&f.bootstrap),
            Err(ExternalCasOffhostAnchorStoreError::Corrupt)
        );
        assert_eq!(runner.calls().len(), 2);
    }

    #[test]
    fn bootstrap_conditional_failure_without_an_item_fails_closed() {
        let f = fixture();
        let runner = Arc::new(ScriptedRunner::new(vec![
            cli_error("ConditionalCheckFailedException"),
            cli_ok(br#"{ "Item": {} }"#.to_vec()),
        ]));
        let store = store_with(&f, runner.clone());

        assert_eq!(
            store.provision_bootstrap_if_absent(&f.bootstrap),
            Err(ExternalCasOffhostAnchorStoreError::Corrupt)
        );
        assert_eq!(runner.calls().len(), 2);
    }

    #[test]
    fn get_item_uses_strongly_consistent_base_table_read_and_validates_pins() {
        let f = fixture();
        let bootstrap_digest = f.bootstrap.digest().unwrap();
        let placeholder = Arc::new(ScriptedRunner::new(vec![]));
        let store = store_with(&f, placeholder);
        let response = item_response(&store, &f.bootstrap);
        let runner = Arc::new(ScriptedRunner::new(vec![cli_ok(response)]));
        let store = store_with(&f, runner.clone());
        assert_eq!(store.load_consistent().unwrap(), f.bootstrap);
        let calls = runner.calls();
        assert_eq!(calls.len(), 1);
        assert!(calls[0]
            .windows(1)
            .any(|window| window[0] == "--consistent-read"));
        assert!(calls[0]
            .windows(2)
            .any(|window| window[0] == "--table-name" && window[1] == "qrun-offhost-anchor"));
        assert_eq!(f.bootstrap.digest().unwrap(), bootstrap_digest);
    }

    #[test]
    fn missing_anchor_item_is_corrupt_and_never_silently_bootstrapped() {
        let f = fixture();
        let runner = Arc::new(ScriptedRunner::new(vec![cli_ok(
            br#"{"Item":{}}"#.to_vec(),
        )]));
        let store = store_with(&f, runner);
        assert_eq!(
            store.load_consistent(),
            Err(ExternalCasOffhostAnchorStoreError::Corrupt)
        );
    }

    #[test]
    fn item_domain_key_ids_public_key_hashes_and_state_digest_are_all_checked() {
        let f = fixture();
        let store = store_with(&f, Arc::new(ScriptedRunner::default()));
        let mut item: Value = serde_json::from_slice(&item_response(&store, &f.bootstrap)).unwrap();
        item["Item"]["anchor_receipt_key_id"]["S"] = Value::String(hex32(&[0xEF; 32]));
        let runner = Arc::new(ScriptedRunner::new(vec![cli_ok(
            serde_json::to_vec(&item).unwrap(),
        )]));
        let store = store_with(&f, runner);
        assert_eq!(
            store.load_consistent(),
            Err(ExternalCasOffhostAnchorStoreError::Corrupt)
        );

        let mut item: Value = serde_json::from_slice(&item_response(
            &store_with(&f, Arc::new(ScriptedRunner::default())),
            &f.bootstrap,
        ))
        .unwrap();
        item["Item"]["state_digest"]["S"] = Value::String(hex32(&[0xFE; 32]));
        let runner = Arc::new(ScriptedRunner::new(vec![cli_ok(
            serde_json::to_vec(&item).unwrap(),
        )]));
        let store = store_with(&f, runner);
        assert_eq!(
            store.load_consistent(),
            Err(ExternalCasOffhostAnchorStoreError::Corrupt)
        );
    }

    #[test]
    fn put_item_condition_compares_sequence_and_full_digest_in_one_server_side_write() {
        let f = fixture();
        let target = next_state(&f);
        let expected_digest = f.bootstrap.digest().unwrap();
        let runner = Arc::new(ScriptedRunner::new(vec![cli_ok(b"{}".to_vec())]));
        let store = store_with(&f, runner.clone());
        assert_eq!(
            store
                .compare_and_swap_atomic(f.bootstrap.sequence, &expected_digest, &target)
                .unwrap(),
            ExternalCasOffhostAnchorStoreCasOutcome::Applied
        );
        let calls = runner.calls();
        assert_eq!(calls.len(), 1);
        let args = &calls[0];
        assert_eq!(
            argument_value(args, "--condition-expression"),
            CONDITION_EXPRESSION
        );
        assert!(args.iter().any(|arg| arg == "--item"));
        let names: Value =
            serde_json::from_str(argument_value(args, "--expression-attribute-names")).unwrap();
        assert_eq!(names["#sequence"], "sequence");
        assert_eq!(names["#state_digest"], "state_digest");
        let values: Value =
            serde_json::from_str(argument_value(args, "--expression-attribute-values")).unwrap();
        assert_eq!(values[":expected_sequence"]["N"], "1");
        assert_eq!(
            values[":expected_state_digest"]["S"],
            hex32(&expected_digest)
        );
        let item: Value = serde_json::from_str(argument_value(args, "--item")).unwrap();
        assert_eq!(item["sequence"]["N"], "2");
        assert_eq!(item["state_digest"]["S"], hex32(&target.digest().unwrap()));
    }

    #[test]
    fn conditional_put_failure_returns_a_fresh_strongly_consistent_conflict_state() {
        let f = fixture();
        let target = next_state(&f);
        let expected_digest = f.bootstrap.digest().unwrap();
        let store_for_item = store_with(&f, Arc::new(ScriptedRunner::default()));
        let conflict_item = item_response(&store_for_item, &f.bootstrap);
        let runner = Arc::new(ScriptedRunner::new(vec![
            cli_error("An error occurred (ConditionalCheckFailedException) when calling the PutItem operation."),
            cli_ok(conflict_item),
        ]));
        let store = store_with(&f, runner.clone());
        assert_eq!(
            store
                .compare_and_swap_atomic(f.bootstrap.sequence, &expected_digest, &target)
                .unwrap(),
            ExternalCasOffhostAnchorStoreCasOutcome::Conflict(f.bootstrap)
        );
        let calls = runner.calls();
        assert_eq!(calls.len(), 2);
        assert!(calls[1].iter().any(|arg| arg == "--consistent-read"));
    }

    #[test]
    fn nonconditional_cli_failure_is_unavailable_and_never_reported_as_conflict() {
        let f = fixture();
        let target = next_state(&f);
        let expected_digest = f.bootstrap.digest().unwrap();
        let runner = Arc::new(ScriptedRunner::new(vec![cli_error(
            "AccessDeniedException",
        )]));
        let store = store_with(&f, runner);
        assert_eq!(
            store.compare_and_swap_atomic(f.bootstrap.sequence, &expected_digest, &target),
            Err(ExternalCasOffhostAnchorStoreError::Unavailable)
        );
    }

    #[test]
    fn qbt1_bootstrap_persists_exact_receipt_and_strongly_reads_it_back() {
        let (provider_pin, anchor_pin, verified) =
            crate::external_cas_bootstrap_trust_candidate::tests::verified_test_fixture();
        let bootstrap = verified.initial_anchor_state().clone();
        let placeholder = qbt_store_with(
            &provider_pin,
            &anchor_pin,
            &verified,
            Arc::new(ScriptedRunner::default()),
        );
        let persisted = item_response(&placeholder, &bootstrap);
        let runner = Arc::new(ScriptedRunner::new(vec![
            cli_ok(b"{}".to_vec()),
            cli_ok(persisted),
        ]));
        let store = qbt_store_with(&provider_pin, &anchor_pin, &verified, runner.clone());

        assert_eq!(
            store.provision_bootstrap_if_absent(&bootstrap).unwrap(),
            ExternalCasOffhostAnchorStoreProvisionOutcome::Provisioned
        );

        let calls = runner.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0][1], "put-item");
        assert_eq!(
            argument_value(&calls[0], "--condition-expression"),
            "attribute_not_exists(#anchor_id)"
        );
        let item: Value = serde_json::from_str(argument_value(&calls[0], "--item")).unwrap();
        assert_eq!(
            item[BOOTSTRAP_RECEIPT_DIGEST_ATTRIBUTE]["S"],
            hex32(&verified.receipt_digest())
        );
        assert_eq!(
            item[BOOTSTRAP_RECEIPT_WIRE_ATTRIBUTE]["S"],
            BASE64.encode(verified.receipt_wire().unwrap())
        );
        assert_eq!(
            item[BOOTSTRAP_INITIAL_STATE_DIGEST_ATTRIBUTE]["S"],
            hex32(&bootstrap.digest().unwrap())
        );
        assert_eq!(calls[1][1], "get-item");
        assert!(calls[1].iter().any(|arg| arg == "--consistent-read"));
    }

    #[test]
    fn qbt1_commitment_is_preserved_and_conditioned_on_for_every_successor_cas() {
        let (provider_pin, anchor_pin, verified) =
            crate::external_cas_bootstrap_trust_candidate::tests::verified_test_fixture();
        let f = Fixture {
            anchor_pin: anchor_pin.clone(),
            provider_pin: provider_pin.clone(),
            bootstrap: verified.initial_anchor_state().clone(),
        };
        let target = next_state(&f);
        let expected_digest = f.bootstrap.digest().unwrap();
        let runner = Arc::new(ScriptedRunner::new(vec![cli_ok(b"{}".to_vec())]));
        let store = qbt_store_with(&provider_pin, &anchor_pin, &verified, runner.clone());

        assert_eq!(
            store
                .compare_and_swap_atomic(f.bootstrap.sequence, &expected_digest, &target)
                .unwrap(),
            ExternalCasOffhostAnchorStoreCasOutcome::Applied
        );

        let calls = runner.calls();
        assert_eq!(calls.len(), 1);
        let args = &calls[0];
        let condition = argument_value(args, "--condition-expression");
        assert!(
            condition.contains("#bootstrap_trust_receipt_digest = :bootstrap_trust_receipt_digest")
        );
        assert!(
            condition.contains("#bootstrap_initial_state_digest = :bootstrap_initial_state_digest")
        );
        assert!(condition
            .contains("#bootstrap_trust_receipt_wire_b64 = :bootstrap_trust_receipt_wire_b64"));

        let names: Value =
            serde_json::from_str(argument_value(args, "--expression-attribute-names")).unwrap();
        assert_eq!(
            names["#bootstrap_trust_receipt_digest"],
            BOOTSTRAP_RECEIPT_DIGEST_ATTRIBUTE
        );
        assert_eq!(
            names["#bootstrap_initial_state_digest"],
            BOOTSTRAP_INITIAL_STATE_DIGEST_ATTRIBUTE
        );
        assert_eq!(
            names["#bootstrap_trust_receipt_wire_b64"],
            BOOTSTRAP_RECEIPT_WIRE_ATTRIBUTE
        );

        let values: Value =
            serde_json::from_str(argument_value(args, "--expression-attribute-values")).unwrap();
        assert_eq!(
            values[":bootstrap_trust_receipt_digest"]["S"],
            hex32(&verified.receipt_digest())
        );
        assert_eq!(
            values[":bootstrap_initial_state_digest"]["S"],
            hex32(&f.bootstrap.digest().unwrap())
        );
        assert_eq!(
            values[":bootstrap_trust_receipt_wire_b64"]["S"],
            BASE64.encode(verified.receipt_wire().unwrap())
        );

        let item: Value = serde_json::from_str(argument_value(args, "--item")).unwrap();
        assert_eq!(
            item[BOOTSTRAP_RECEIPT_DIGEST_ATTRIBUTE]["S"],
            hex32(&verified.receipt_digest())
        );
        assert_eq!(
            item[BOOTSTRAP_RECEIPT_WIRE_ATTRIBUTE]["S"],
            BASE64.encode(verified.receipt_wire().unwrap())
        );
        assert_eq!(
            item[BOOTSTRAP_INITIAL_STATE_DIGEST_ATTRIBUTE]["S"],
            hex32(&f.bootstrap.digest().unwrap())
        );
    }

    #[test]
    fn qbt1_read_rejects_changed_commitment_or_receipt_wire() {
        let (provider_pin, anchor_pin, verified) =
            crate::external_cas_bootstrap_trust_candidate::tests::verified_test_fixture();
        let bootstrap = verified.initial_anchor_state().clone();
        let placeholder = qbt_store_with(
            &provider_pin,
            &anchor_pin,
            &verified,
            Arc::new(ScriptedRunner::default()),
        );

        let mut altered: Value =
            serde_json::from_slice(&item_response(&placeholder, &bootstrap)).unwrap();
        altered["Item"][BOOTSTRAP_RECEIPT_DIGEST_ATTRIBUTE]["S"] =
            Value::String(hex32(&[0xEE; 32]));
        let runner = Arc::new(ScriptedRunner::new(vec![cli_ok(
            serde_json::to_vec(&altered).unwrap(),
        )]));
        let store = qbt_store_with(&provider_pin, &anchor_pin, &verified, runner);
        assert_eq!(
            store.load_consistent(),
            Err(ExternalCasOffhostAnchorStoreError::Corrupt)
        );

        let mut altered: Value =
            serde_json::from_slice(&item_response(&placeholder, &bootstrap)).unwrap();
        altered["Item"][BOOTSTRAP_RECEIPT_WIRE_ATTRIBUTE]["S"] =
            Value::String(BASE64.encode(b"not-the-pinned-receipt"));
        let runner = Arc::new(ScriptedRunner::new(vec![cli_ok(
            serde_json::to_vec(&altered).unwrap(),
        )]));
        let store = qbt_store_with(&provider_pin, &anchor_pin, &verified, runner);
        assert_eq!(
            store.load_consistent(),
            Err(ExternalCasOffhostAnchorStoreError::Corrupt)
        );
    }

    #[test]
    fn qbt1_bound_provision_rejects_wrong_initial_state_before_any_store_write() {
        let (provider_pin, anchor_pin, verified) =
            crate::external_cas_bootstrap_trust_candidate::tests::verified_test_fixture();
        let runner = Arc::new(ScriptedRunner::default());
        let store = qbt_store_with(&provider_pin, &anchor_pin, &verified, runner.clone());
        let mut wrong = verified.initial_anchor_state().clone();
        wrong.provider_record.next_state_digest[0] ^= 0x80;

        assert_eq!(
            store.provision_bootstrap_if_absent(&wrong),
            Err(ExternalCasOffhostAnchorStoreError::Corrupt)
        );
        assert!(runner.calls().is_empty());
    }

    #[test]
    fn legacy_unbound_adapter_refuses_to_read_qbt1_bound_anchor_item() {
        let (provider_pin, anchor_pin, verified) =
            crate::external_cas_bootstrap_trust_candidate::tests::verified_test_fixture();
        let bootstrap = verified.initial_anchor_state().clone();
        let bound_placeholder = qbt_store_with(
            &provider_pin,
            &anchor_pin,
            &verified,
            Arc::new(ScriptedRunner::default()),
        );
        let persisted = item_response(&bound_placeholder, &bootstrap);
        let f = Fixture {
            anchor_pin,
            provider_pin,
            bootstrap,
        };
        let runner = Arc::new(ScriptedRunner::new(vec![cli_ok(persisted)]));
        let legacy_store = store_with(&f, runner);
        assert_eq!(
            legacy_store.load_consistent(),
            Err(ExternalCasOffhostAnchorStoreError::Corrupt)
        );
    }
}

#[cfg(test)]
mod session_bound_runner_tests {
    use super::*;

    fn deployment_pin(
    ) -> crate::external_cas_offhost_anchor_aws_qualification_candidate::AwsDynamoDbDeploymentPin
    {
        crate::external_cas_offhost_anchor_aws_qualification_candidate::AwsDynamoDbDeploymentPin {
            account_id: "123456789012".into(),
            role_arn: "arn:aws:iam::123456789012:role/QRunAnchorCustodian".into(),
            table_arn: "arn:aws:dynamodb:us-east-1:123456789012:table/qrun-anchor".into(),
            region: "us-east-1".into(),
            table_name: "qrun-anchor".into(),
        }
    }

    fn temporary_session() -> AwsTemporaryCredentialSession {
        let expires = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        AwsTemporaryCredentialSession::new(
            "ASIA_TEST_ACCESS_KEY".into(),
            "secret-test-only-not-real".into(),
            "session-token-test-only-not-real".into(),
            expires,
        )
        .unwrap()
    }

    fn runner() -> SessionBoundAwsDynamoDbCliRunner {
        SessionBoundAwsDynamoDbCliRunner::new(
            std::env::current_exe().unwrap(),
            deployment_pin(),
            temporary_session(),
        )
        .unwrap()
    }

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn temporary_session_requires_nonempty_unexpired_sts_token_and_redacts_debug() {
        let expires = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 600;
        let session = AwsTemporaryCredentialSession::new(
            "ASIA_TEST".into(),
            "secret-test-only".into(),
            "token-test-only".into(),
            expires,
        )
        .unwrap();
        let debug = format!("{session:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("secret-test-only"));
        assert!(!debug.contains("token-test-only"));

        assert!(AwsTemporaryCredentialSession::new(
            "ASIA_TEST".into(),
            "secret".into(),
            "".into(),
            expires,
        )
        .is_err());
        assert!(AwsTemporaryCredentialSession::new(
            "ASIA_TEST".into(),
            "secret".into(),
            "token".into(),
            0,
        )
        .is_err());
        assert!(AwsTemporaryCredentialSession::new(
            "ASIA_TEST\nINJECTED".into(),
            "secret".into(),
            "token".into(),
            expires,
        )
        .is_err());
    }

    #[test]
    fn expiry_safety_window_fails_closed_before_a_child_process_can_start() {
        assert!(credentials_valid_at(1_000, 969));
        assert!(!credentials_valid_at(1_000, 970));
        assert!(!credentials_valid_at(1_000, 1_000));
    }

    #[test]
    fn child_environment_is_an_explicit_allowlist_with_pinned_credentials_and_no_profile() {
        let runner = runner();
        let environment = runner
            .environment_overrides()
            .into_iter()
            .map(|(key, value)| {
                (
                    key.to_string_lossy().into_owned(),
                    value.to_string_lossy().into_owned(),
                )
            })
            .collect::<std::collections::HashMap<_, _>>();

        assert_eq!(environment["AWS_ACCESS_KEY_ID"], "ASIA_TEST_ACCESS_KEY");
        assert_eq!(
            environment["AWS_SECRET_ACCESS_KEY"],
            "secret-test-only-not-real"
        );
        assert_eq!(
            environment["AWS_SESSION_TOKEN"],
            "session-token-test-only-not-real"
        );
        assert_eq!(environment["AWS_REGION"], "us-east-1");
        assert_eq!(environment["AWS_DEFAULT_REGION"], "us-east-1");
        assert_eq!(environment["AWS_EC2_METADATA_DISABLED"], "true");
        assert_eq!(environment["AWS_IGNORE_CONFIGURED_ENDPOINT_URLS"], "true");
        assert_eq!(environment["AWS_STS_REGIONAL_ENDPOINTS"], "regional");
        assert_eq!(
            environment["AWS_CONFIG_FILE"],
            if cfg!(windows) { "NUL" } else { "/dev/null" }
        );
        assert_eq!(
            environment["AWS_SHARED_CREDENTIALS_FILE"],
            if cfg!(windows) { "NUL" } else { "/dev/null" }
        );
        for forbidden in [
            "AWS_PROFILE",
            "AWS_DEFAULT_PROFILE",
            "AWS_ENDPOINT_URL",
            "AWS_ENDPOINT_URL_DYNAMODB",
            "AWS_CA_BUNDLE",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "NO_PROXY",
            "AWS_WEB_IDENTITY_TOKEN_FILE",
            "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
        ] {
            assert!(
                !environment.contains_key(forbidden),
                "unexpected inherited key: {forbidden}"
            );
        }

        let debug = format!("{runner:?}");
        assert!(!debug.contains("secret-test-only-not-real"));
        assert!(!debug.contains("session-token-test-only-not-real"));
    }

    #[test]
    fn runner_accepts_only_exact_pinned_preflight_and_anchor_command_grammar() {
        let runner = runner();
        assert!(runner.command_is_in_scope(&args(&[
            "sts",
            "get-caller-identity",
            "--no-cli-pager",
            "--region",
            "us-east-1",
            "--output",
            "json",
        ])));
        assert!(runner.command_is_in_scope(&args(&[
            "iam",
            "get-role",
            "--role-name",
            "QRunAnchorCustodian",
            "--no-cli-pager",
            "--output",
            "json",
        ])));
        assert!(runner.command_is_in_scope(&args(&[
            "dynamodb",
            "describe-table",
            "--table-name",
            "qrun-anchor",
            "--region",
            "us-east-1",
            "--no-cli-pager",
            "--output",
            "json",
        ])));
        assert!(runner.command_is_in_scope(&args(&[
            "dynamodb",
            "describe-continuous-backups",
            "--table-name",
            "qrun-anchor",
            "--region",
            "us-east-1",
            "--no-cli-pager",
            "--output",
            "json",
        ])));
        assert!(runner.command_is_in_scope(&args(&[
            "dynamodb",
            "get-item",
            "--table-name",
            "qrun-anchor",
            "--key",
            r#"{"anchor_id":{"S":"test"}}"#,
            "--consistent-read",
            "--no-cli-pager",
            "--cli-connect-timeout",
            "5",
            "--cli-read-timeout",
            "15",
            "--region",
            "us-east-1",
            "--output",
            "json",
        ])));
        assert!(runner.command_is_in_scope(&args(&[
            "dynamodb",
            "put-item",
            "--table-name",
            "qrun-anchor",
            "--item",
            "{}",
            "--condition-expression",
            "attribute_not_exists(#anchor_id)",
            "--expression-attribute-names",
            "{}",
            "--no-cli-pager",
            "--cli-connect-timeout",
            "5",
            "--cli-read-timeout",
            "15",
            "--region",
            "us-east-1",
            "--output",
            "json",
        ])));

        for attack in [
            args(&[
                "dynamodb",
                "get-item",
                "--table-name",
                "qrun-anchor",
                "--key",
                "{}",
                "--consistent-read",
                "--no-cli-pager",
                "--cli-connect-timeout",
                "5",
                "--cli-read-timeout",
                "15",
                "--region",
                "us-east-1",
                "--output",
                "json",
                "--endpoint-url=https://attacker.invalid",
            ]),
            args(&[
                "dynamodb",
                "get-item",
                "--table-name",
                "qrun-anchor",
                "--key",
                "{}",
                "--consistent-read",
                "--no-cli-pager",
                "--cli-connect-timeout",
                "5",
                "--cli-read-timeout",
                "15",
                "--region",
                "us-east-1",
                "--region",
                "us-west-2",
                "--output",
                "json",
            ]),
            args(&[
                "dynamodb",
                "get-item",
                "--table-name",
                "qrun-anchor",
                "--key",
                "{}",
                "--no-cli-pager",
                "--cli-connect-timeout",
                "5",
                "--cli-read-timeout",
                "15",
                "--region",
                "us-east-1",
                "--output",
                "json",
            ]),
            args(&[
                "dynamodb",
                "delete-table",
                "--table-name",
                "qrun-anchor",
                "--region",
                "us-east-1",
            ]),
        ] {
            assert!(!runner.command_is_in_scope(&attack));
        }
    }

    fn runner_with_kms() -> SessionBoundAwsDynamoDbCliRunner {
        SessionBoundAwsDynamoDbCliRunner::new_with_kms_key_arn(
            std::env::current_exe().unwrap(),
            deployment_pin(),
            temporary_session(),
            "arn:aws:kms:us-east-1:123456789012:key/123e4567-e89b-12d3-a456-426614174000",
        )
        .unwrap()
    }

    #[test]
    fn read_only_session_runner_allows_consistent_floor_reads_but_never_put_item() {
        let runner = SessionBoundAwsDynamoDbCliRunner::new_read_only(
            std::env::current_exe().unwrap(),
            deployment_pin(),
            temporary_session(),
        )
        .unwrap();
        assert!(!runner.allows_dynamodb_put_item());
        assert!(runner.command_is_in_scope(&args(&[
            "dynamodb",
            "get-item",
            "--table-name",
            "qrun-anchor",
            "--key",
            r#"{"anchor_id":{"S":"q6ts-floor"}}"#,
            "--consistent-read",
            "--no-cli-pager",
            "--cli-connect-timeout",
            "5",
            "--cli-read-timeout",
            "15",
            "--region",
            "us-east-1",
            "--output",
            "json",
        ])));
        assert!(!runner.command_is_in_scope(&args(&[
            "dynamodb",
            "put-item",
            "--table-name",
            "qrun-anchor",
            "--item",
            "{}",
            "--condition-expression",
            "attribute_exists(#floor_id)",
            "--expression-attribute-names",
            "{}",
            "--no-cli-pager",
            "--cli-connect-timeout",
            "5",
            "--cli-read-timeout",
            "15",
            "--region",
            "us-east-1",
            "--output",
            "json",
        ])));
        assert!(!runner.command_is_in_scope(&args(&[
            "dynamodb",
            "update-item",
            "--table-name",
            "qrun-anchor",
            "--key",
            "{}",
        ])));
    }

    #[test]
    fn runner_kms_scope_is_one_key_one_region_and_raw_mldsa_digest() {
        let kms_runner = runner_with_kms();
        let key_arn = "arn:aws:kms:us-east-1:123456789012:key/123e4567-e89b-12d3-a456-426614174000";
        assert!(kms_runner.command_is_in_scope(&args(&[
            "kms",
            "get-public-key",
            "--key-id",
            key_arn,
            "--region",
            "us-east-1",
            "--output",
            "json",
            "--no-cli-pager",
            "--cli-connect-timeout",
            "5",
            "--cli-read-timeout",
            "20",
        ])));

        let message = BASE64.encode([0x5a; 32]);
        assert!(kms_runner.command_is_in_scope(&args(&[
            "kms",
            "sign",
            "--key-id",
            key_arn,
            "--message",
            &message,
            "--message-type",
            "RAW",
            "--signing-algorithm",
            "ML_DSA_SHAKE_256",
            "--region",
            "us-east-1",
            "--output",
            "json",
            "--no-cli-pager",
            "--cli-connect-timeout",
            "5",
            "--cli-read-timeout",
            "20",
        ])));

        assert!(!kms_runner.command_is_in_scope(&args(&[
            "kms",
            "sign",
            "--key-id",
            "arn:aws:kms:us-east-1:123456789012:key/different",
            "--message",
            &message,
            "--message-type",
            "RAW",
            "--signing-algorithm",
            "ML_DSA_SHAKE_256",
            "--region",
            "us-east-1",
            "--output",
            "json",
            "--no-cli-pager",
            "--cli-connect-timeout",
            "5",
            "--cli-read-timeout",
            "20",
        ])));
        assert!(!kms_runner.command_is_in_scope(&args(&[
            "kms",
            "sign",
            "--key-id",
            key_arn,
            "--message",
            "not-a-digest",
            "--message-type",
            "RAW",
            "--signing-algorithm",
            "ML_DSA_SHAKE_256",
            "--region",
            "us-east-1",
            "--output",
            "json",
            "--no-cli-pager",
            "--cli-connect-timeout",
            "5",
            "--cli-read-timeout",
            "20",
        ])));
        assert!(!kms_runner.command_is_in_scope(&args(&[
            "kms",
            "schedule-key-deletion",
            "--key-id",
            key_arn,
        ])));
        assert!(!runner().command_is_in_scope(&args(&[
            "kms",
            "get-public-key",
            "--key-id",
            key_arn,
            "--region",
            "us-east-1",
            "--output",
            "json",
            "--no-cli-pager",
            "--cli-connect-timeout",
            "5",
            "--cli-read-timeout",
            "20",
        ])));
    }

    #[test]
    fn runner_rejects_kms_key_alias_or_foreign_account_and_region() {
        let exe = std::env::current_exe().unwrap();
        assert!(SessionBoundAwsDynamoDbCliRunner::new_with_kms_key_arn(
            &exe,
            deployment_pin(),
            temporary_session(),
            "arn:aws:kms:us-east-1:123456789012:alias/not-a-key",
        )
        .is_err());

        assert!(SessionBoundAwsDynamoDbCliRunner::new_with_kms_key_arn(
            &exe,
            deployment_pin(),
            temporary_session(),
            "arn:aws:kms:us-west-2:123456789012:key/123e4567-e89b-12d3-a456-426614174000",
        )
        .is_err());

        assert!(SessionBoundAwsDynamoDbCliRunner::new_with_kms_key_arn(
            &exe,
            deployment_pin(),
            temporary_session(),
            "arn:aws:kms:us-east-1:999999999999:key/123e4567-e89b-12d3-a456-426614174000",
        )
        .is_err());
    }

    #[test]
    fn runner_rejects_relative_or_missing_executable_path() {
        assert!(SessionBoundAwsDynamoDbCliRunner::new(
            "aws",
            deployment_pin(),
            temporary_session(),
        )
        .is_err());
        assert!(SessionBoundAwsDynamoDbCliRunner::new(
            std::env::temp_dir().join("qrun-aws-cli-does-not-exist.exe"),
            deployment_pin(),
            temporary_session(),
        )
        .is_err());
    }

    #[test]
    fn runner_rejects_unpinned_command_without_spawning_any_child() {
        let runner = runner();
        let result = runner.run(&args(&[
            "dynamodb",
            "delete-table",
            "--table-name",
            "qrun-anchor",
            "--region",
            "us-east-1",
        ]));
        assert!(result.is_err());
    }
}
