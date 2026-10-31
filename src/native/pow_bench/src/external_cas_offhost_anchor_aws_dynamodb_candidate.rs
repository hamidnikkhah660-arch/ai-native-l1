//! CP-0483 AWS DynamoDB adapter candidate for the QRun off-host monotonic Anchor.
//!
//! This adapter uses AWS CLI v2 without a shell. It has not been run against AWS in this
//! environment (the AWS CLI is not installed here). Tests use a scripted command runner and
//! validate request construction, response validation and fail-closed outcomes.
//!
//! Production use requires a separately administered AWS account, single-region table, strict
//! IAM/SCP separation and an independent recovery custodian. This module does not provision AWS.
use crate::{
    external_cas_anchor_candidate::ExternalCasPin,
    external_cas_offhost_anchor_candidate::ExternalCasOffhostAnchorState,
    external_cas_offhost_anchor_protocol_candidate::{
        decode_state, encode_state, ExternalCasOffhostAnchorPin, ExternalCasOffhostAnchorStore,
        ExternalCasOffhostAnchorStoreCasOutcome, ExternalCasOffhostAnchorStoreError,
        OFFHOST_ANCHOR_STATE_BYTES,
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
};

const POLICY_VERSION: &str = "qrun-offhost-anchor-v1";

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

struct ProcessAwsDynamoDbCliRunner {
    executable: PathBuf,
}
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
}
impl std::fmt::Debug for AwsDynamoDbOffhostAnchorStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsDynamoDbOffhostAnchorStore")
            .field("region", &self.region)
            .field("table_name", &self.table_name)
            .field("anchor_id", &hex32(&self.anchor_pin.anchor_id))
            .field("provider_id", &hex32(&self.provider_pin.provider_id))
            .field("network_id", &hex32(&self.provider_pin.network_id))
            .field("aws_credentials", &"<resolved by AWS CLI credential chain>")
            .finish()
    }
}
impl AwsDynamoDbOffhostAnchorStore {
    pub fn new(
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

    pub fn from_path(
        region: impl Into<String>,
        table_name: impl Into<String>,
        anchor_pin: ExternalCasOffhostAnchorPin,
        provider_pin: ExternalCasPin,
    ) -> Result<Self, ExternalCasOffhostAnchorStoreError> {
        Self::new("aws", region, table_name, anchor_pin, provider_pin)
    }

    pub fn with_runner(
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
        Ok(json!({
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
        }))
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
        let values = json!({
            ":expected_sequence": { "N": expected_sequence.to_string() },
            ":expected_state_digest": { "S": hex32(expected_state_digest) }
        });
        let names = json!({
            "#anchor_id": "anchor_id",
            "#sequence": "sequence",
            "#state_digest": "state_digest"
        });
        let arguments: Vec<OsString> = [
            "dynamodb",
            "put-item",
            "--table-name",
            &self.table_name,
            "--item",
            &json_arg(&item)?,
            "--condition-expression",
            CONDITION_EXPRESSION,
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
}
