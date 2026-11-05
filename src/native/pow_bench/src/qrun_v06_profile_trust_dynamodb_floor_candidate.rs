//! CP-0548 AWS DynamoDB adapter candidate for the independently administered Q6TS floor.
//!
//! This adapter uses AWS CLI v2 without a shell. It performs strongly consistent reads and
//! conditional PutItem CAS over the complete Q6TS floor tuple. It does not provision AWS,
//! create tables, configure IAM/SCP, or prove operator independence. A single account/table
//! controlled by the node operator is not an independent anti-rollback trust domain.
use crate::qrun_v06_profile_trust_candidate::{
    MonotonicQRunV06ProfileTrustFloorStore, QRunV06ProfileTrustError, QRunV06ProfileTrustStatus,
    TrustedQRunV06ProfileTrustFloor,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};

const POLICY_VERSION: &str = "qrun-q6ts-floor-v1";
const FLOOR_ID_DOMAIN: &[u8] = b"QRUN-Q6TS-DYNAMODB-FLOOR-ID-V1\0";
const CAS_CONDITION: &str = "attribute_exists(#floor_id) AND #network_id = :network_id AND #profile_id = :profile_id AND #trust_epoch = :expected_epoch AND #status = :expected_status AND #record_id = :expected_record_id AND #envelope_id = :expected_envelope_id AND #policy_version = :expected_policy_version";

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

fn parse_hex32(value: &str) -> Result<[u8; 32], QRunV06ProfileTrustError> {
    if value.len() != 64 || !value.is_ascii() || value.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(QRunV06ProfileTrustError::Malformed);
    }
    let mut out = [0u8; 32];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| QRunV06ProfileTrustError::Malformed)?;
    }
    Ok(out)
}

fn floor_id(network_id: &[u8; 32], profile_id: &[u8; 32]) -> String {
    let mut hash = Sha256::new();
    hash.update(FLOOR_ID_DOMAIN);
    hash.update(network_id);
    hash.update(profile_id);
    hex(&hash.finalize())
}

fn json_arg(value: &Value) -> Result<String, QRunV06ProfileTrustError> {
    serde_json::to_string(value).map_err(|_| QRunV06ProfileTrustError::Malformed)
}

fn string_attribute(item: &Value, name: &str) -> Result<String, QRunV06ProfileTrustError> {
    item.get(name)
        .and_then(|value| value.get("S"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(QRunV06ProfileTrustError::Malformed)
}

fn number_attribute(item: &Value, name: &str) -> Result<u64, QRunV06ProfileTrustError> {
    let text = item
        .get(name)
        .and_then(|value| value.get("N"))
        .and_then(Value::as_str)
        .ok_or(QRunV06ProfileTrustError::Malformed)?;
    let number = text
        .parse::<u64>()
        .map_err(|_| QRunV06ProfileTrustError::Malformed)?;
    if number.to_string() != text {
        return Err(QRunV06ProfileTrustError::Malformed);
    }
    Ok(number)
}

fn status_name(status: Option<QRunV06ProfileTrustStatus>) -> &'static str {
    match status {
        None => "EMPTY",
        Some(QRunV06ProfileTrustStatus::Active) => "ACTIVE",
        Some(QRunV06ProfileTrustStatus::Revoked) => "REVOKED",
    }
}

fn parse_status(
    value: &str,
) -> Result<Option<QRunV06ProfileTrustStatus>, QRunV06ProfileTrustError> {
    match value {
        "EMPTY" => Ok(None),
        "ACTIVE" => Ok(Some(QRunV06ProfileTrustStatus::Active)),
        "REVOKED" => Ok(Some(QRunV06ProfileTrustStatus::Revoked)),
        _ => Err(QRunV06ProfileTrustError::Malformed),
    }
}

#[derive(Debug, Clone)]
pub struct AwsDynamoDbQ6tsFloorCliOutput {
    pub success: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Injectable process boundary. Production execution invokes AWS CLI directly, never through a shell.
pub trait AwsDynamoDbQ6tsFloorCliRunner: Send + Sync {
    fn run(&self, arguments: &[OsString]) -> Result<AwsDynamoDbQ6tsFloorCliOutput, String>;
}

struct ProcessAwsDynamoDbQ6tsFloorCliRunner {
    executable: PathBuf,
}

impl AwsDynamoDbQ6tsFloorCliRunner for ProcessAwsDynamoDbQ6tsFloorCliRunner {
    fn run(&self, arguments: &[OsString]) -> Result<AwsDynamoDbQ6tsFloorCliOutput, String> {
        let output = Command::new(&self.executable)
            .args(arguments)
            .output()
            .map_err(|error| error.to_string())?;
        Ok(AwsDynamoDbQ6tsFloorCliOutput {
            success: output.status.success(),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}

#[derive(Clone)]
pub struct AwsDynamoDbQ6tsProfileTrustFloorStore {
    runner: Arc<dyn AwsDynamoDbQ6tsFloorCliRunner>,
    region: String,
    table_name: String,
}

impl std::fmt::Debug for AwsDynamoDbQ6tsProfileTrustFloorStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsDynamoDbQ6tsProfileTrustFloorStore")
            .field("region", &self.region)
            .field("table_name", &self.table_name)
            .field("aws_credentials", &"<resolved by AWS CLI credential chain>")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AwsDynamoDbQ6tsFloorProvisionOutcome {
    Provisioned,
    AlreadyExists(TrustedQRunV06ProfileTrustFloor),
}

impl AwsDynamoDbQ6tsProfileTrustFloorStore {
    pub fn new(
        aws_cli: impl AsRef<Path>,
        region: impl Into<String>,
        table_name: impl Into<String>,
    ) -> Result<Self, QRunV06ProfileTrustError> {
        let executable = aws_cli.as_ref();
        if executable.as_os_str().is_empty() {
            return Err(QRunV06ProfileTrustError::FloorUnavailable);
        }
        Self::with_runner(
            Arc::new(ProcessAwsDynamoDbQ6tsFloorCliRunner {
                executable: executable.to_path_buf(),
            }),
            region,
            table_name,
        )
    }

    pub fn from_path(
        region: impl Into<String>,
        table_name: impl Into<String>,
    ) -> Result<Self, QRunV06ProfileTrustError> {
        Self::new("aws", region, table_name)
    }

    pub fn with_runner(
        runner: Arc<dyn AwsDynamoDbQ6tsFloorCliRunner>,
        region: impl Into<String>,
        table_name: impl Into<String>,
    ) -> Result<Self, QRunV06ProfileTrustError> {
        let region = region.into();
        let table_name = table_name.into();
        if region.is_empty()
            || !region.is_ascii()
            || region.chars().any(char::is_whitespace)
            || table_name.is_empty()
            || !table_name.is_ascii()
            || table_name.chars().any(char::is_whitespace)
        {
            return Err(QRunV06ProfileTrustError::FloorUnavailable);
        }
        Ok(Self {
            runner,
            region,
            table_name,
        })
    }

    fn run(
        &self,
        arguments: &[OsString],
    ) -> Result<AwsDynamoDbQ6tsFloorCliOutput, QRunV06ProfileTrustError> {
        self.runner
            .run(arguments)
            .map_err(|_| QRunV06ProfileTrustError::FloorUnavailable)
    }

    fn get_item_args(
        &self,
        network_id: &[u8; 32],
        profile_id: &[u8; 32],
    ) -> Result<Vec<OsString>, QRunV06ProfileTrustError> {
        let key = json!({
            "floor_id": { "S": floor_id(network_id, profile_id) }
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

    fn item_for_floor(
        &self,
        floor: &TrustedQRunV06ProfileTrustFloor,
    ) -> Result<Value, QRunV06ProfileTrustError> {
        floor.validate()?;
        Ok(json!({
            "floor_id": { "S": floor_id(&floor.network_id, &floor.profile_id) },
            "network_id": { "S": hex32(&floor.network_id) },
            "profile_id": { "S": hex32(&floor.profile_id) },
            "trust_epoch": { "N": floor.trust_epoch.to_string() },
            "status": { "S": status_name(floor.status) },
            "record_id": { "S": hex32(&floor.record_id) },
            "envelope_id": { "S": hex32(&floor.envelope_id) },
            "policy_version": { "S": POLICY_VERSION }
        }))
    }

    fn parse_item(
        &self,
        item: &Value,
        expected_network_id: &[u8; 32],
        expected_profile_id: &[u8; 32],
    ) -> Result<TrustedQRunV06ProfileTrustFloor, QRunV06ProfileTrustError> {
        if string_attribute(item, "floor_id")? != floor_id(expected_network_id, expected_profile_id)
            || string_attribute(item, "network_id")? != hex32(expected_network_id)
            || string_attribute(item, "profile_id")? != hex32(expected_profile_id)
            || string_attribute(item, "policy_version")? != POLICY_VERSION
        {
            return Err(QRunV06ProfileTrustError::WrongNetworkOrProfile);
        }
        let floor = TrustedQRunV06ProfileTrustFloor {
            network_id: parse_hex32(&string_attribute(item, "network_id")?)?,
            profile_id: parse_hex32(&string_attribute(item, "profile_id")?)?,
            trust_epoch: number_attribute(item, "trust_epoch")?,
            status: parse_status(&string_attribute(item, "status")?)?,
            record_id: parse_hex32(&string_attribute(item, "record_id")?)?,
            envelope_id: parse_hex32(&string_attribute(item, "envelope_id")?)?,
        };
        floor.validate()?;
        Ok(floor)
    }

    fn load_consistent(
        &self,
        network_id: &[u8; 32],
        profile_id: &[u8; 32],
    ) -> Result<TrustedQRunV06ProfileTrustFloor, QRunV06ProfileTrustError> {
        let output = self.run(&self.get_item_args(network_id, profile_id)?)?;
        if !output.success {
            return Err(QRunV06ProfileTrustError::FloorUnavailable);
        }
        let response: Value = serde_json::from_slice(&output.stdout)
            .map_err(|_| QRunV06ProfileTrustError::Malformed)?;
        let item = response
            .get("Item")
            .and_then(Value::as_object)
            .filter(|item| !item.is_empty())
            .ok_or(QRunV06ProfileTrustError::FloorUnavailable)?;
        self.parse_item(&Value::Object(item.clone()), network_id, profile_id)
    }

    /// One-time provisioning for a new trust domain only. A missing item during ordinary load
    /// is always an error; node startup never initializes or advances the floor from Q6TS bytes.
    pub fn provision_initial_if_absent(
        &self,
        initial: &TrustedQRunV06ProfileTrustFloor,
    ) -> Result<AwsDynamoDbQ6tsFloorProvisionOutcome, QRunV06ProfileTrustError> {
        initial.validate()?;
        if initial.trust_epoch != 0 || initial.status.is_some() {
            return Err(QRunV06ProfileTrustError::InvalidFloor);
        }
        let item = self.item_for_floor(initial)?;
        let names = json!({ "#floor_id": "floor_id" });
        let arguments: Vec<OsString> = [
            "dynamodb",
            "put-item",
            "--table-name",
            &self.table_name,
            "--item",
            &json_arg(&item)?,
            "--condition-expression",
            "attribute_not_exists(#floor_id)",
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
        if output.success {
            let observed = self.load_consistent(&initial.network_id, &initial.profile_id)?;
            if observed != *initial {
                return Err(QRunV06ProfileTrustError::FloorCasConflict);
            }
            return Ok(AwsDynamoDbQ6tsFloorProvisionOutcome::Provisioned);
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("ConditionalCheckFailedException") {
            let observed = self.load_consistent(&initial.network_id, &initial.profile_id)?;
            return Ok(AwsDynamoDbQ6tsFloorProvisionOutcome::AlreadyExists(
                observed,
            ));
        }
        Err(QRunV06ProfileTrustError::FloorUnavailable)
    }
}

impl MonotonicQRunV06ProfileTrustFloorStore for AwsDynamoDbQ6tsProfileTrustFloorStore {
    fn load(
        &self,
        network_id: &[u8; 32],
        profile_id: &[u8; 32],
    ) -> Result<TrustedQRunV06ProfileTrustFloor, QRunV06ProfileTrustError> {
        self.load_consistent(network_id, profile_id)
    }

    fn compare_and_swap(
        &mut self,
        expected: &TrustedQRunV06ProfileTrustFloor,
        next: &TrustedQRunV06ProfileTrustFloor,
    ) -> Result<(), QRunV06ProfileTrustError> {
        expected.validate()?;
        next.validate()?;
        if expected.status == Some(QRunV06ProfileTrustStatus::Revoked) {
            return Err(QRunV06ProfileTrustError::ProfileRevoked);
        }
        if expected.network_id != next.network_id
            || expected.profile_id != next.profile_id
            || expected.trust_epoch.checked_add(1) != Some(next.trust_epoch)
            || next.trust_epoch == 0
        {
            return Err(QRunV06ProfileTrustError::FloorCasConflict);
        }
        let item = self.item_for_floor(next)?;
        let names = json!({
            "#floor_id": "floor_id",
            "#network_id": "network_id",
            "#profile_id": "profile_id",
            "#trust_epoch": "trust_epoch",
            "#status": "status",
            "#record_id": "record_id",
            "#envelope_id": "envelope_id",
            "#policy_version": "policy_version"
        });
        let values = json!({
            ":network_id": { "S": hex32(&expected.network_id) },
            ":profile_id": { "S": hex32(&expected.profile_id) },
            ":expected_epoch": { "N": expected.trust_epoch.to_string() },
            ":expected_status": { "S": status_name(expected.status) },
            ":expected_record_id": { "S": hex32(&expected.record_id) },
            ":expected_envelope_id": { "S": hex32(&expected.envelope_id) },
            ":expected_policy_version": { "S": POLICY_VERSION }
        });
        let arguments: Vec<OsString> = [
            "dynamodb",
            "put-item",
            "--table-name",
            &self.table_name,
            "--item",
            &json_arg(&item)?,
            "--condition-expression",
            CAS_CONDITION,
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
        if !output.success {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("ConditionalCheckFailedException") {
                return Err(QRunV06ProfileTrustError::FloorCasConflict);
            }
            return Err(QRunV06ProfileTrustError::FloorUnavailable);
        }
        let observed = self.load_consistent(&next.network_id, &next.profile_id)?;
        if observed == *next {
            Ok(())
        } else {
            Err(QRunV06ProfileTrustError::FloorCasConflict)
        }
    }
}

/// Read-only Q6TS floor adapter for a QFP6 node process.
///
/// The trust publisher uses AwsDynamoDbQ6tsProfileTrustFloorStore to provision and advance
/// the floor. A node only needs to confirm that its Q6TS envelope is already the independently
/// prepublished head. This wrapper deliberately refuses CAS locally, so an accidental call from
/// the node admission path cannot become a write even when a test or misconfigured IAM role is
/// permissive. Production IAM must independently grant this node role GetItem only and deny
/// PutItem/UpdateItem/DeleteItem and table-management actions.
#[derive(Clone)]
pub struct AwsDynamoDbQ6tsReadOnlyProfileTrustFloorStore {
    inner: AwsDynamoDbQ6tsProfileTrustFloorStore,
}

impl std::fmt::Debug for AwsDynamoDbQ6tsReadOnlyProfileTrustFloorStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsDynamoDbQ6tsReadOnlyProfileTrustFloorStore")
            .field("inner", &self.inner)
            .field("write_capability", &"disabled")
            .finish()
    }
}

impl AwsDynamoDbQ6tsReadOnlyProfileTrustFloorStore {
    pub fn new(
        aws_cli: impl AsRef<Path>,
        region: impl Into<String>,
        table_name: impl Into<String>,
    ) -> Result<Self, QRunV06ProfileTrustError> {
        Ok(Self {
            inner: AwsDynamoDbQ6tsProfileTrustFloorStore::new(aws_cli, region, table_name)?,
        })
    }

    pub fn from_path(
        region: impl Into<String>,
        table_name: impl Into<String>,
    ) -> Result<Self, QRunV06ProfileTrustError> {
        Self::new("aws", region, table_name)
    }

    pub fn with_runner(
        runner: Arc<dyn AwsDynamoDbQ6tsFloorCliRunner>,
        region: impl Into<String>,
        table_name: impl Into<String>,
    ) -> Result<Self, QRunV06ProfileTrustError> {
        Ok(Self {
            inner: AwsDynamoDbQ6tsProfileTrustFloorStore::with_runner(runner, region, table_name)?,
        })
    }
}

impl MonotonicQRunV06ProfileTrustFloorStore for AwsDynamoDbQ6tsReadOnlyProfileTrustFloorStore {
    fn load(
        &self,
        network_id: &[u8; 32],
        profile_id: &[u8; 32],
    ) -> Result<TrustedQRunV06ProfileTrustFloor, QRunV06ProfileTrustError> {
        self.inner.load(network_id, profile_id)
    }

    fn compare_and_swap(
        &mut self,
        _expected: &TrustedQRunV06ProfileTrustFloor,
        _next: &TrustedQRunV06ProfileTrustFloor,
    ) -> Result<(), QRunV06ProfileTrustError> {
        Err(QRunV06ProfileTrustError::FloorCasConflict)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::VecDeque, ffi::OsString, sync::Mutex};

    #[derive(Default)]
    struct ScriptedRunner {
        responses: Mutex<VecDeque<AwsDynamoDbQ6tsFloorCliOutput>>,
        calls: Mutex<Vec<Vec<String>>>,
    }

    impl ScriptedRunner {
        fn new(responses: Vec<AwsDynamoDbQ6tsFloorCliOutput>) -> Self {
            Self {
                responses: Mutex::new(responses.into()),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<Vec<String>> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl AwsDynamoDbQ6tsFloorCliRunner for ScriptedRunner {
        fn run(&self, arguments: &[OsString]) -> Result<AwsDynamoDbQ6tsFloorCliOutput, String> {
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
                .ok_or_else(|| "no scripted response".into())
        }
    }

    fn success(stdout: &str) -> AwsDynamoDbQ6tsFloorCliOutput {
        AwsDynamoDbQ6tsFloorCliOutput {
            success: true,
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        }
    }

    fn failure(stderr: &str) -> AwsDynamoDbQ6tsFloorCliOutput {
        AwsDynamoDbQ6tsFloorCliOutput {
            success: false,
            stdout: Vec::new(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    fn floor(
        epoch: u64,
        status: Option<QRunV06ProfileTrustStatus>,
        id: u8,
    ) -> TrustedQRunV06ProfileTrustFloor {
        if epoch == 0 {
            TrustedQRunV06ProfileTrustFloor::initial([0x31; 32], [0x32; 32]).unwrap()
        } else {
            TrustedQRunV06ProfileTrustFloor::provisioned(
                [0x31; 32],
                [0x32; 32],
                epoch,
                status.unwrap(),
                [id; 32],
                [id + 1; 32],
            )
            .unwrap()
        }
    }

    fn item(floor: &TrustedQRunV06ProfileTrustFloor) -> Value {
        json!({
            "floor_id": { "S": floor_id(&floor.network_id, &floor.profile_id) },
            "network_id": { "S": hex32(&floor.network_id) },
            "profile_id": { "S": hex32(&floor.profile_id) },
            "trust_epoch": { "N": floor.trust_epoch.to_string() },
            "status": { "S": status_name(floor.status) },
            "record_id": { "S": hex32(&floor.record_id) },
            "envelope_id": { "S": hex32(&floor.envelope_id) },
            "policy_version": { "S": POLICY_VERSION }
        })
    }

    fn get_response(floor: &TrustedQRunV06ProfileTrustFloor) -> String {
        json!({ "Item": item(floor) }).to_string()
    }

    fn store(runner: Arc<ScriptedRunner>) -> AwsDynamoDbQ6tsProfileTrustFloorStore {
        AwsDynamoDbQ6tsProfileTrustFloorStore::with_runner(runner, "eu-west-2", "qrun-q6ts-floor")
            .unwrap()
    }

    #[test]
    fn load_uses_strongly_consistent_read_and_validates_exact_domain() {
        let current = floor(1, Some(QRunV06ProfileTrustStatus::Active), 0x41);
        let runner = Arc::new(ScriptedRunner::new(vec![success(&get_response(&current))]));
        let observed = store(runner.clone())
            .load(&current.network_id, &current.profile_id)
            .unwrap();
        assert_eq!(observed, current);
        let calls = runner.calls();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].contains(&"--consistent-read".to_owned()));
        assert!(calls[0].contains(&"get-item".to_owned()));
    }

    #[test]
    fn missing_floor_never_auto_bootstraps_from_a_read() {
        let runner = Arc::new(ScriptedRunner::new(vec![success("{}")]));
        let result = store(runner.clone()).load(&[0x31; 32], &[0x32; 32]);
        assert_eq!(result, Err(QRunV06ProfileTrustError::FloorUnavailable));
        assert_eq!(runner.calls().len(), 1);
        assert!(!runner.calls()[0].contains(&"put-item".to_owned()));
    }

    #[test]
    fn malformed_or_wrong_domain_rows_fail_closed() {
        let current = floor(1, Some(QRunV06ProfileTrustStatus::Active), 0x41);
        let mut bad = item(&current);
        bad["trust_epoch"]["N"] = Value::String("01".into());
        let runner = Arc::new(ScriptedRunner::new(vec![success(
            &json!({"Item": bad}).to_string(),
        )]));
        let result = store(runner).load(&current.network_id, &current.profile_id);
        assert_eq!(result, Err(QRunV06ProfileTrustError::Malformed));

        let mut wrong = item(&current);
        wrong["network_id"]["S"] = Value::String(hex32(&[0x99; 32]));
        let runner = Arc::new(ScriptedRunner::new(vec![success(
            &json!({"Item": wrong}).to_string(),
        )]));
        let result = store(runner).load(&current.network_id, &current.profile_id);
        assert_eq!(result, Err(QRunV06ProfileTrustError::WrongNetworkOrProfile));
    }

    #[test]
    fn cas_conditions_on_epoch_status_and_both_record_identifiers_then_reads_back() {
        let expected = floor(1, Some(QRunV06ProfileTrustStatus::Active), 0x41);
        let next = floor(2, Some(QRunV06ProfileTrustStatus::Active), 0x43);
        let runner = Arc::new(ScriptedRunner::new(vec![
            success("{}"),
            success(&get_response(&next)),
        ]));
        store(runner.clone())
            .compare_and_swap(&expected, &next)
            .unwrap();
        let calls = runner.calls();
        assert_eq!(calls.len(), 2);
        assert!(calls[0].contains(&"--condition-expression".to_owned()));
        let condition = calls[0]
            .iter()
            .position(|arg| arg == "--condition-expression")
            .unwrap();
        assert_eq!(calls[0][condition + 1], CAS_CONDITION);
        assert!(CAS_CONDITION.contains("#trust_epoch"));
        assert!(CAS_CONDITION.contains("#status"));
        assert!(CAS_CONDITION.contains("#record_id"));
        assert!(CAS_CONDITION.contains("#envelope_id"));
        assert!(CAS_CONDITION.contains("#policy_version"));
        assert!(CAS_CONDITION.contains(":expected_policy_version"));
        assert!(calls[1].contains(&"--consistent-read".to_owned()));
    }

    #[test]
    fn cas_conflict_is_not_reported_as_success() {
        let expected = floor(1, Some(QRunV06ProfileTrustStatus::Active), 0x41);
        let next = floor(2, Some(QRunV06ProfileTrustStatus::Revoked), 0x43);
        let runner = Arc::new(ScriptedRunner::new(vec![failure(
            "ConditionalCheckFailedException",
        )]));
        let result = store(runner).compare_and_swap(&expected, &next);
        assert_eq!(result, Err(QRunV06ProfileTrustError::FloorCasConflict));
    }

    #[test]
    fn cas_readback_mismatch_is_not_reported_as_success() {
        let expected = floor(1, Some(QRunV06ProfileTrustStatus::Active), 0x41);
        let next = floor(2, Some(QRunV06ProfileTrustStatus::Active), 0x43);
        let observed = floor(3, Some(QRunV06ProfileTrustStatus::Active), 0x45);
        let runner = Arc::new(ScriptedRunner::new(vec![
            success("{}"),
            success(&get_response(&observed)),
        ]));
        let result = store(runner).compare_and_swap(&expected, &next);
        assert_eq!(result, Err(QRunV06ProfileTrustError::FloorCasConflict));
    }

    #[test]
    fn cas_readback_unavailable_is_not_reported_as_success() {
        let expected = floor(1, Some(QRunV06ProfileTrustStatus::Active), 0x41);
        let next = floor(2, Some(QRunV06ProfileTrustStatus::Active), 0x43);
        let runner = Arc::new(ScriptedRunner::new(vec![success("{}"), success("{}")]));
        let result = store(runner).compare_and_swap(&expected, &next);
        assert_eq!(result, Err(QRunV06ProfileTrustError::FloorUnavailable));
    }

    #[test]
    fn bootstrap_conflict_returns_existing_floor_without_overwrite() {
        let initial = floor(0, None, 0);
        let existing = floor(1, Some(QRunV06ProfileTrustStatus::Active), 0x41);
        let runner = Arc::new(ScriptedRunner::new(vec![
            failure("ConditionalCheckFailedException"),
            success(&get_response(&existing)),
        ]));
        let result = store(runner.clone())
            .provision_initial_if_absent(&initial)
            .unwrap();
        assert_eq!(
            result,
            AwsDynamoDbQ6tsFloorProvisionOutcome::AlreadyExists(existing)
        );
        let calls = runner.calls();
        assert_eq!(calls.len(), 2);
        assert!(calls[0].contains(&"put-item".to_owned()));
        assert!(calls[1].contains(&"get-item".to_owned()));
    }

    #[test]
    fn terminal_revocation_cannot_be_reactivated_by_direct_floor_cas() {
        let expected = floor(1, Some(QRunV06ProfileTrustStatus::Revoked), 0x41);
        let next = floor(2, Some(QRunV06ProfileTrustStatus::Active), 0x43);
        let runner = Arc::new(ScriptedRunner::new(Vec::new()));
        let result = store(runner.clone()).compare_and_swap(&expected, &next);
        assert_eq!(result, Err(QRunV06ProfileTrustError::ProfileRevoked));
        assert!(runner.calls().is_empty());
    }

    #[test]
    fn one_time_bootstrap_only_accepts_epoch_zero_and_never_overwrites() {
        let initial = floor(0, None, 0);
        let runner = Arc::new(ScriptedRunner::new(vec![
            success("{}"),
            success(&get_response(&initial)),
        ]));
        assert_eq!(
            store(runner.clone())
                .provision_initial_if_absent(&initial)
                .unwrap(),
            AwsDynamoDbQ6tsFloorProvisionOutcome::Provisioned
        );
        let calls = runner.calls();
        assert!(calls[0].contains(&"--condition-expression".to_owned()));
        let condition = calls[0]
            .iter()
            .position(|arg| arg == "--condition-expression")
            .unwrap();
        assert_eq!(calls[0][condition + 1], "attribute_not_exists(#floor_id)");
        assert!(calls[1].contains(&"--consistent-read".to_owned()));

        let nonempty = floor(1, Some(QRunV06ProfileTrustStatus::Active), 0x41);
        let runner = Arc::new(ScriptedRunner::new(Vec::new()));
        let result = store(runner.clone()).provision_initial_if_absent(&nonempty);
        assert_eq!(result, Err(QRunV06ProfileTrustError::InvalidFloor));
        assert!(runner.calls().is_empty());
    }

    #[test]
    fn read_only_node_adapter_reads_floor_but_never_issues_a_write() {
        let current = floor(1, Some(QRunV06ProfileTrustStatus::Active), 0x41);
        let next = floor(2, Some(QRunV06ProfileTrustStatus::Revoked), 0x43);
        let runner = Arc::new(ScriptedRunner::new(vec![success(&get_response(&current))]));
        let mut node_store = AwsDynamoDbQ6tsReadOnlyProfileTrustFloorStore::with_runner(
            runner.clone(),
            "eu-west-2",
            "qrun-q6ts-floor",
        )
        .unwrap();

        assert_eq!(
            node_store.load(&current.network_id, &current.profile_id),
            Ok(current.clone())
        );
        assert_eq!(
            node_store.compare_and_swap(&current, &next),
            Err(QRunV06ProfileTrustError::FloorCasConflict)
        );

        let calls = runner.calls();
        assert_eq!(calls.len(), 1, "read-only CAS must not invoke AWS CLI");
        assert!(calls[0].contains(&"get-item".to_owned()));
        assert!(calls[0].contains(&"--consistent-read".to_owned()));
        assert!(!calls[0].contains(&"put-item".to_owned()));
    }
}
