//! CP-0763 read-only AWS deployment qualification for the QBT1 off-host Anchor candidate.
//!
//! This module performs identity/configuration preflight only. It never creates or mutates AWS
//! resources and does not prove IAM/SCP policy separation, independent custody, or anti-rollback.
use crate::external_cas_offhost_anchor_aws_dynamodb_candidate::AwsDynamoDbCliRunner;
use serde_json::Value;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AwsDeploymentQualificationError {
    InvalidPin,
    Unavailable,
    MalformedResponse,
    AccountMismatch,
    CallerRoleMismatch,
    RoleArnMismatch,
    TableArnMismatch,
    TableNotActive,
    UnsupportedTableShape,
    GlobalTableNotAllowed,
    PointInTimeRecoveryDisabled,
    OperationScopeMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsDynamoDbDeploymentPin {
    pub account_id: String,
    pub role_arn: String,
    pub table_arn: String,
    pub region: String,
    pub table_name: String,
}

impl AwsDynamoDbDeploymentPin {
    pub fn validate(&self) -> Result<(), AwsDeploymentQualificationError> {
        let role_prefix = format!("arn:aws:iam::{}:role/", self.account_id);
        let table_prefix = format!(
            "arn:aws:dynamodb:{}:{}:table/",
            self.region, self.account_id
        );
        if self.account_id.len() != 12
            || !self.account_id.bytes().all(|b| b.is_ascii_digit())
            || self.region.is_empty()
            || !self.region.is_ascii()
            || self.region.bytes().any(|b| b.is_ascii_whitespace())
            || self.table_name.is_empty()
            || !self.table_name.is_ascii()
            || self.table_name.bytes().any(|b| b.is_ascii_whitespace())
            || !self.role_arn.starts_with(&role_prefix)
            || self.role_arn[role_prefix.len()..].contains(':')
            || self.role_arn[role_prefix.len()..].is_empty()
            || !self.table_arn.starts_with(&table_prefix)
            || self.table_arn[table_prefix.len()..] != self.table_name
        {
            return Err(AwsDeploymentQualificationError::InvalidPin);
        }
        Ok(())
    }

    fn role_name(&self) -> &str {
        self.role_arn.rsplit('/').next().unwrap_or("")
    }
}

/// Sealed result: callers can inspect the exact identities that passed the read-only probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualifiedAwsDynamoDbDeployment {
    pin: AwsDynamoDbDeploymentPin,
    caller_arn: String,
    caller_user_id: String,
    role_arn: String,
    table_arn: String,
}

impl QualifiedAwsDynamoDbDeployment {
    pub fn pin(&self) -> &AwsDynamoDbDeploymentPin {
        &self.pin
    }
    pub fn caller_arn(&self) -> &str {
        &self.caller_arn
    }
    pub fn caller_user_id(&self) -> &str {
        &self.caller_user_id
    }
    pub fn role_arn(&self) -> &str {
        &self.role_arn
    }
    pub fn table_arn(&self) -> &str {
        &self.table_arn
    }
}

fn run_json(
    runner: &dyn AwsDynamoDbCliRunner,
    args: &[&str],
) -> Result<Value, AwsDeploymentQualificationError> {
    let args = args
        .iter()
        .map(std::ffi::OsString::from)
        .collect::<Vec<_>>();
    let output = runner
        .run(&args)
        .map_err(|_| AwsDeploymentQualificationError::Unavailable)?;
    if !output.success {
        return Err(AwsDeploymentQualificationError::Unavailable);
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|_| AwsDeploymentQualificationError::MalformedResponse)
}

fn required_str<'a>(
    value: &'a Value,
    path: &[&str],
) -> Result<&'a str, AwsDeploymentQualificationError> {
    let mut current = value;
    for key in path {
        current = current
            .get(*key)
            .ok_or(AwsDeploymentQualificationError::MalformedResponse)?;
    }
    current
        .as_str()
        .ok_or(AwsDeploymentQualificationError::MalformedResponse)
}

fn qualify_inner(
    runner: &dyn AwsDynamoDbCliRunner,
    pin: AwsDynamoDbDeploymentPin,
) -> Result<QualifiedAwsDynamoDbDeployment, AwsDeploymentQualificationError> {
    pin.validate()?;

    let identity = run_json(
        runner,
        &[
            "sts",
            "get-caller-identity",
            "--no-cli-pager",
            "--region",
            &pin.region,
            "--output",
            "json",
        ],
    )?;
    let account = required_str(&identity, &["Account"])?;
    let caller_arn = required_str(&identity, &["Arn"])?;
    let caller_user_id = required_str(&identity, &["UserId"])?;
    if account != pin.account_id {
        return Err(AwsDeploymentQualificationError::AccountMismatch);
    }
    let expected_session_prefix = format!(
        "arn:aws:sts::{}:assumed-role/{}/",
        pin.account_id,
        pin.role_name()
    );
    if !caller_arn.starts_with(&expected_session_prefix)
        || caller_arn[expected_session_prefix.len()..].is_empty()
        || caller_arn[expected_session_prefix.len()..].contains('/')
    {
        return Err(AwsDeploymentQualificationError::CallerRoleMismatch);
    }

    let role = run_json(
        runner,
        &[
            "iam",
            "get-role",
            "--role-name",
            pin.role_name(),
            "--no-cli-pager",
            "--output",
            "json",
        ],
    )?;
    let actual_role_arn = required_str(&role, &["Role", "Arn"])?;
    let actual_role_name = required_str(&role, &["Role", "RoleName"])?;
    if actual_role_arn != pin.role_arn || actual_role_name != pin.role_name() {
        return Err(AwsDeploymentQualificationError::RoleArnMismatch);
    }

    let description = run_json(
        runner,
        &[
            "dynamodb",
            "describe-table",
            "--table-name",
            &pin.table_name,
            "--region",
            &pin.region,
            "--no-cli-pager",
            "--output",
            "json",
        ],
    )?;
    let table = description
        .get("Table")
        .ok_or(AwsDeploymentQualificationError::MalformedResponse)?;
    let actual_table_arn = required_str(table, &["TableArn"])?;
    if actual_table_arn != pin.table_arn {
        return Err(AwsDeploymentQualificationError::TableArnMismatch);
    }
    if required_str(table, &["TableStatus"])? != "ACTIVE" {
        return Err(AwsDeploymentQualificationError::TableNotActive);
    }
    if table.get("GlobalTableVersion").is_some()
        || match table.get("Replicas") {
            None => false,
            Some(Value::Array(replicas)) => !replicas.is_empty(),
            Some(_) => true,
        }
    {
        return Err(AwsDeploymentQualificationError::GlobalTableNotAllowed);
    }
    let key_schema = table
        .get("KeySchema")
        .and_then(Value::as_array)
        .ok_or(AwsDeploymentQualificationError::MalformedResponse)?;
    let definitions = table
        .get("AttributeDefinitions")
        .and_then(Value::as_array)
        .ok_or(AwsDeploymentQualificationError::MalformedResponse)?;
    if key_schema.len() != 1
        || key_schema[0].get("AttributeName").and_then(Value::as_str) != Some("anchor_id")
        || key_schema[0].get("KeyType").and_then(Value::as_str) != Some("HASH")
        || definitions.len() != 1
        || definitions[0].get("AttributeName").and_then(Value::as_str) != Some("anchor_id")
        || definitions[0].get("AttributeType").and_then(Value::as_str) != Some("S")
        || table
            .get("DeletionProtectionEnabled")
            .and_then(Value::as_bool)
            != Some(true)
        || table
            .get("SSEDescription")
            .and_then(|v| v.get("Status"))
            .and_then(Value::as_str)
            != Some("ENABLED")
    {
        return Err(AwsDeploymentQualificationError::UnsupportedTableShape);
    }

    let backups = run_json(
        runner,
        &[
            "dynamodb",
            "describe-continuous-backups",
            "--table-name",
            &pin.table_name,
            "--region",
            &pin.region,
            "--no-cli-pager",
            "--output",
            "json",
        ],
    )?;
    if required_str(
        &backups,
        &[
            "ContinuousBackupsDescription",
            "PointInTimeRecoveryDescription",
            "PointInTimeRecoveryStatus",
        ],
    )? != "ENABLED"
    {
        return Err(AwsDeploymentQualificationError::PointInTimeRecoveryDisabled);
    }

    Ok(QualifiedAwsDynamoDbDeployment {
        role_arn: actual_role_arn.to_owned(),
        table_arn: actual_table_arn.to_owned(),
        caller_arn: caller_arn.to_owned(),
        caller_user_id: caller_user_id.to_owned(),
        pin,
    })
}

/// Performs five read-only AWS CLI calls. No PutItem, UpdateItem, CreateTable, or IAM mutation.
pub fn qualify_aws_dynamodb_deployment(
    runner: Arc<dyn AwsDynamoDbCliRunner>,
    pin: AwsDynamoDbDeploymentPin,
) -> Result<QualifiedAwsDynamoDbDeployment, AwsDeploymentQualificationError> {
    qualify_inner(runner.as_ref(), pin)
}

/// Crate-private gate used behind the public immutable-session runner. It repeats identity/table
/// qualification before every DynamoDB operation and pins both the exact assumed-role ARN and
/// STS UserId observed at initial qualification. Production construction cannot inject an
/// arbitrary runner; deterministic custom runners remain available only to in-crate tests.
pub(crate) struct RevalidatingAwsDynamoDbCliRunner {
    inner: Arc<dyn AwsDynamoDbCliRunner>,
    pin: AwsDynamoDbDeploymentPin,
    expected_caller_arn: String,
    expected_caller_user_id: String,
}

impl AwsDynamoDbCliRunner for RevalidatingAwsDynamoDbCliRunner {
    fn run(
        &self,
        arguments: &[std::ffi::OsString],
    ) -> Result<
        crate::external_cas_offhost_anchor_aws_dynamodb_candidate::AwsDynamoDbCliOutput,
        String,
    > {
        let args = arguments
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        let reject = || {
            format!(
                "{:?}",
                AwsDeploymentQualificationError::OperationScopeMismatch
            )
        };
        if args.len() < 2 || args[0] != "dynamodb" {
            return Err(reject());
        }
        let operation = args[1].as_str();
        if operation != "get-item" && operation != "put-item" {
            return Err(reject());
        }
        // Only the adapter's fixed command grammar is accepted. In particular, reject
        // endpoint/profile overrides, duplicate flags, alternate input sources, and any
        // unreviewed AWS CLI switch that could redirect or alter the signed request.
        let mut allowed_pairs = vec![
            "--table-name",
            "--region",
            "--cli-connect-timeout",
            "--cli-read-timeout",
            "--output",
        ];
        let mut allowed_bare = vec!["--no-cli-pager"];
        if operation == "get-item" {
            allowed_pairs.push("--key");
            allowed_bare.push("--consistent-read");
        } else {
            allowed_pairs.extend([
                "--item",
                "--condition-expression",
                "--expression-attribute-names",
                "--expression-attribute-values",
            ]);
        }
        let mut seen = std::collections::HashSet::new();
        let mut index = 2;
        while index < args.len() {
            let flag = args[index].as_str();
            if !seen.insert(flag.to_owned()) {
                return Err(reject());
            }
            if allowed_bare.contains(&flag) {
                index += 1;
                continue;
            }
            if !allowed_pairs.contains(&flag) || index + 1 >= args.len() {
                return Err(reject());
            }
            index += 2;
        }
        let has_exact_pair = |flag: &str, expected: &str| {
            args.windows(2).filter(|pair| pair[0] == flag).count() == 1
                && args
                    .windows(2)
                    .any(|pair| pair[0] == flag && pair[1] == expected)
        };
        if !has_exact_pair("--table-name", &self.pin.table_name)
            || !has_exact_pair("--region", &self.pin.region)
            || !has_exact_pair("--output", "json")
            || !has_exact_pair("--cli-connect-timeout", "5")
            || !has_exact_pair("--cli-read-timeout", "15")
            || !seen.contains("--no-cli-pager")
            || (operation == "get-item" && !seen.contains("--consistent-read"))
            || (operation == "get-item" && !seen.contains("--key"))
            || (operation == "put-item"
                && (!seen.contains("--item")
                    || !seen.contains("--condition-expression")
                    || !seen.contains("--expression-attribute-names")))
        {
            return Err(reject());
        }
        let current = qualify_inner(self.inner.as_ref(), self.pin.clone())
            .map_err(|error| format!("AWS deployment requalification failed: {error:?}"))?;
        if current.caller_arn() != self.expected_caller_arn
            || current.caller_user_id() != self.expected_caller_user_id
        {
            return Err(
                "AWS assumed-role session identity changed after initial qualification".into(),
            );
        }
        self.inner.run(arguments)
    }
}

/// Performs an initial qualification and returns a runner that repeats qualification before
/// every DynamoDB operation. Callers must use this returned runner, not the raw runner.
pub(crate) fn qualified_aws_dynamodb_runner(
    runner: Arc<dyn AwsDynamoDbCliRunner>,
    pin: AwsDynamoDbDeploymentPin,
) -> Result<Arc<dyn AwsDynamoDbCliRunner>, AwsDeploymentQualificationError> {
    let initial = qualify_inner(runner.as_ref(), pin.clone())?;
    Ok(Arc::new(RevalidatingAwsDynamoDbCliRunner {
        inner: runner,
        pin,
        expected_caller_arn: initial.caller_arn().to_owned(),
        expected_caller_user_id: initial.caller_user_id().to_owned(),
    }))
}
impl crate::external_cas_offhost_anchor_aws_dynamodb_candidate::AwsDynamoDbOffhostAnchorStore {
    /// Constructs the QBT1-bound Anchor store only behind the pinned, revalidating AWS runner.
    /// Unqualified constructors are crate-private; external callers must use this entry point.
    pub(crate) fn with_qualified_verified_bootstrap_runner(
        runner: Arc<dyn AwsDynamoDbCliRunner>,
        deployment_pin: AwsDynamoDbDeploymentPin,
        anchor_pin: crate::external_cas_offhost_anchor_protocol_candidate::ExternalCasOffhostAnchorPin,
        provider_pin: crate::external_cas_anchor_candidate::ExternalCasPin,
        verified: &crate::external_cas_bootstrap_trust_candidate::VerifiedBootstrapTrust,
    ) -> Result<
        Self,
        crate::external_cas_offhost_anchor_protocol_candidate::ExternalCasOffhostAnchorStoreError,
    > {
        deployment_pin.validate().map_err(|_| {
            crate::external_cas_offhost_anchor_protocol_candidate::ExternalCasOffhostAnchorStoreError::Unavailable
        })?;
        let qualified = qualified_aws_dynamodb_runner(runner, deployment_pin.clone()).map_err(|_| {
            crate::external_cas_offhost_anchor_protocol_candidate::ExternalCasOffhostAnchorStoreError::Unavailable
        })?;
        crate::external_cas_offhost_anchor_aws_dynamodb_candidate::AwsDynamoDbOffhostAnchorStore::with_verified_bootstrap_runner(
            qualified,
            deployment_pin.region,
            deployment_pin.table_name,
            anchor_pin,
            provider_pin,
            verified,
        )
    }

    /// Public construction path: only a fixed, unexpired STS credential session tied to this
    /// exact deployment pin can be used by external production callers.
    pub fn with_session_bound_verified_bootstrap_runner(
        runner: Arc<crate::external_cas_offhost_anchor_aws_dynamodb_candidate::SessionBoundAwsDynamoDbCliRunner>,
        deployment_pin: AwsDynamoDbDeploymentPin,
        anchor_pin: crate::external_cas_offhost_anchor_protocol_candidate::ExternalCasOffhostAnchorPin,
        provider_pin: crate::external_cas_anchor_candidate::ExternalCasPin,
        verified: &crate::external_cas_bootstrap_trust_candidate::VerifiedBootstrapTrust,
    ) -> Result<
        Self,
        crate::external_cas_offhost_anchor_protocol_candidate::ExternalCasOffhostAnchorStoreError,
    > {
        if !runner.matches_deployment_pin(&deployment_pin) {
            return Err(crate::external_cas_offhost_anchor_protocol_candidate::ExternalCasOffhostAnchorStoreError::Unavailable);
        }
        Self::with_qualified_verified_bootstrap_runner(
            runner,
            deployment_pin,
            anchor_pin,
            provider_pin,
            verified,
        )
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::external_cas_offhost_anchor_aws_dynamodb_candidate::{
        AwsDynamoDbCliOutput, AwsDynamoDbCliRunner,
    };
    use std::{collections::VecDeque, ffi::OsString, sync::Mutex};

    struct ScriptedRunner {
        outputs: Mutex<VecDeque<AwsDynamoDbCliOutput>>,
        calls: Mutex<Vec<Vec<String>>>,
    }
    impl ScriptedRunner {
        fn new(outputs: Vec<Value>) -> Self {
            Self {
                outputs: Mutex::new(
                    outputs
                        .into_iter()
                        .map(|value| AwsDynamoDbCliOutput {
                            success: true,
                            stdout: serde_json::to_vec(&value).unwrap(),
                            stderr: vec![],
                        })
                        .collect(),
                ),
                calls: Mutex::new(vec![]),
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
                    .map(|v| v.to_string_lossy().into_owned())
                    .collect(),
            );
            self.outputs
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| "no scripted response".to_owned())
        }
    }

    fn pin() -> AwsDynamoDbDeploymentPin {
        AwsDynamoDbDeploymentPin {
            account_id: "123456789012".into(),
            role_arn: "arn:aws:iam::123456789012:role/QRunAnchorCustodian".into(),
            table_arn: "arn:aws:dynamodb:us-east-1:123456789012:table/qrun-anchor".into(),
            region: "us-east-1".into(),
            table_name: "qrun-anchor".into(),
        }
    }
    fn valid_outputs() -> Vec<Value> {
        vec![
            serde_json::json!({
                "Account":"123456789012",
                "Arn":"arn:aws:sts::123456789012:assumed-role/QRunAnchorCustodian/session-abc",
                "UserId":"AROAX:session-abc"
            }),
            serde_json::json!({
                "Role":{
                    "Arn":"arn:aws:iam::123456789012:role/QRunAnchorCustodian",
                    "RoleName":"QRunAnchorCustodian"
                }
            }),
            serde_json::json!({
                "Table":{
                    "TableArn":"arn:aws:dynamodb:us-east-1:123456789012:table/qrun-anchor",
                    "TableStatus":"ACTIVE",
                    "KeySchema":[{"AttributeName":"anchor_id","KeyType":"HASH"}],
                    "AttributeDefinitions":[{"AttributeName":"anchor_id","AttributeType":"S"}],
                    "DeletionProtectionEnabled":true,
                    "SSEDescription":{"Status":"ENABLED"},
                    "Replicas":[]
                }
            }),
            serde_json::json!({
                "ContinuousBackupsDescription":{
                    "PointInTimeRecoveryDescription":{"PointInTimeRecoveryStatus":"ENABLED"}
                }
            }),
        ]
    }

    #[test]
    fn accepts_exact_account_role_table_single_region_and_recovery_configuration() {
        let runner = Arc::new(ScriptedRunner::new(valid_outputs()));
        let qualified = qualify_aws_dynamodb_deployment(runner.clone(), pin()).unwrap();
        assert_eq!(qualified.pin().account_id, "123456789012");
        assert_eq!(qualified.role_arn(), pin().role_arn);
        assert_eq!(qualified.table_arn(), pin().table_arn);
        assert!(qualified
            .caller_arn()
            .contains("assumed-role/QRunAnchorCustodian/"));
        let calls = runner.calls();
        assert_eq!(calls.len(), 4);
        assert_eq!(calls[0][0], "sts");
        assert_eq!(calls[1][0], "iam");
        assert_eq!(calls[2][0], "dynamodb");
        assert!(calls[2].contains(&"describe-table".to_owned()));
        assert!(calls[3].contains(&"describe-continuous-backups".to_owned()));
        assert!(calls.iter().all(|call| !call.iter().any(|arg| {
            ["put-item", "update-item", "create-table", "delete-table"].contains(&arg.as_str())
        })));
    }

    #[test]
    fn rejects_wrong_account_before_role_or_table_queries() {
        let mut outputs = valid_outputs();
        outputs[0]["Account"] = Value::String("999999999999".into());
        let runner = Arc::new(ScriptedRunner::new(outputs));
        assert_eq!(
            qualify_aws_dynamodb_deployment(runner.clone(), pin()),
            Err(AwsDeploymentQualificationError::AccountMismatch)
        );
        assert_eq!(runner.calls().len(), 1);
    }

    #[test]
    fn rejects_user_or_wrong_assumed_role_principal() {
        for arn in [
            "arn:aws:iam::123456789012:user/operator",
            "arn:aws:sts::123456789012:assumed-role/OtherRole/session",
        ] {
            let mut outputs = valid_outputs();
            outputs[0]["Arn"] = Value::String(arn.into());
            let runner = Arc::new(ScriptedRunner::new(outputs));
            assert_eq!(
                qualify_aws_dynamodb_deployment(runner, pin()),
                Err(AwsDeploymentQualificationError::CallerRoleMismatch)
            );
        }
    }

    #[test]
    fn rejects_role_arn_drift_and_exact_table_arn_drift() {
        let mut outputs = valid_outputs();
        outputs[1]["Role"]["Arn"] =
            Value::String("arn:aws:iam::123456789012:role/OtherRole".into());
        let runner = Arc::new(ScriptedRunner::new(outputs));
        assert_eq!(
            qualify_aws_dynamodb_deployment(runner, pin()),
            Err(AwsDeploymentQualificationError::RoleArnMismatch)
        );

        let mut outputs = valid_outputs();
        outputs[2]["Table"]["TableArn"] =
            Value::String("arn:aws:dynamodb:us-east-1:123456789012:table/other".into());
        let runner = Arc::new(ScriptedRunner::new(outputs));
        assert_eq!(
            qualify_aws_dynamodb_deployment(runner, pin()),
            Err(AwsDeploymentQualificationError::TableArnMismatch)
        );
    }

    #[test]
    fn rejects_non_active_global_or_wrong_key_schema_table() {
        let mut outputs = valid_outputs();
        outputs[2]["Table"]["TableStatus"] = Value::String("CREATING".into());
        let runner = Arc::new(ScriptedRunner::new(outputs));
        assert_eq!(
            qualify_aws_dynamodb_deployment(runner, pin()),
            Err(AwsDeploymentQualificationError::TableNotActive)
        );

        let mut outputs = valid_outputs();
        outputs[2]["Table"]["Replicas"] = serde_json::json!([{"RegionName":"us-west-2"}]);
        let runner = Arc::new(ScriptedRunner::new(outputs));
        assert_eq!(
            qualify_aws_dynamodb_deployment(runner, pin()),
            Err(AwsDeploymentQualificationError::GlobalTableNotAllowed)
        );

        let mut outputs = valid_outputs();
        outputs[2]["Table"]["Replicas"] = Value::Null;
        let runner = Arc::new(ScriptedRunner::new(outputs));
        assert_eq!(
            qualify_aws_dynamodb_deployment(runner, pin()),
            Err(AwsDeploymentQualificationError::GlobalTableNotAllowed)
        );

        let mut outputs = valid_outputs();
        outputs[2]["Table"]["KeySchema"][0]["AttributeName"] = Value::String("wrong".into());
        let runner = Arc::new(ScriptedRunner::new(outputs));
        assert_eq!(
            qualify_aws_dynamodb_deployment(runner, pin()),
            Err(AwsDeploymentQualificationError::UnsupportedTableShape)
        );
    }

    #[test]
    fn rejects_disabled_deletion_protection_sse_and_point_in_time_recovery() {
        let mut outputs = valid_outputs();
        outputs[2]["Table"]["DeletionProtectionEnabled"] = Value::Bool(false);
        let runner = Arc::new(ScriptedRunner::new(outputs));
        assert_eq!(
            qualify_aws_dynamodb_deployment(runner, pin()),
            Err(AwsDeploymentQualificationError::UnsupportedTableShape)
        );

        let mut outputs = valid_outputs();
        outputs[2]["Table"]["SSEDescription"]["Status"] = Value::String("DISABLED".into());
        let runner = Arc::new(ScriptedRunner::new(outputs));
        assert_eq!(
            qualify_aws_dynamodb_deployment(runner, pin()),
            Err(AwsDeploymentQualificationError::UnsupportedTableShape)
        );

        let mut outputs = valid_outputs();
        outputs[3]["ContinuousBackupsDescription"]["PointInTimeRecoveryDescription"]
            ["PointInTimeRecoveryStatus"] = Value::String("DISABLED".into());
        let runner = Arc::new(ScriptedRunner::new(outputs));
        assert_eq!(
            qualify_aws_dynamodb_deployment(runner, pin()),
            Err(AwsDeploymentQualificationError::PointInTimeRecoveryDisabled)
        );
    }

    #[test]
    fn rejects_malformed_or_incomplete_responses_and_invalid_pins() {
        let mut invalid = pin();
        invalid.table_arn = "arn:aws:dynamodb:us-east-1:123456789012:table/other".into();
        assert_eq!(
            qualify_aws_dynamodb_deployment(
                Arc::new(ScriptedRunner::new(valid_outputs())),
                invalid
            ),
            Err(AwsDeploymentQualificationError::InvalidPin)
        );
        let runner = Arc::new(ScriptedRunner::new(vec![
            serde_json::json!({"Account":"123"}),
        ]));
        assert_eq!(
            qualify_aws_dynamodb_deployment(runner, pin()),
            Err(AwsDeploymentQualificationError::MalformedResponse)
        );
    }

    #[test]
    fn revalidating_runner_rechecks_identity_before_each_storage_command_and_fails_closed() {
        let mut outputs = valid_outputs();
        let mut changed_identity = valid_outputs();
        changed_identity[0]["Account"] = Value::String("999999999999".into());
        outputs.extend(changed_identity);
        let runner = Arc::new(ScriptedRunner::new(outputs));
        let qualified = qualified_aws_dynamodb_runner(runner.clone(), pin()).unwrap();
        let args = [
            "dynamodb",
            "put-item",
            "--table-name",
            "qrun-anchor",
            "--item",
            "{}",
            "--condition-expression",
            "attribute_not_exists(anchor_id)",
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
        ]
        .iter()
        .map(OsString::from)
        .collect::<Vec<_>>();
        assert!(qualified.run(&args).is_err());
        let calls = runner.calls();
        assert_eq!(calls.len(), 5);
        assert_eq!(calls[0][0], "sts");
        assert_eq!(calls[4][0], "sts");
        assert!(!calls
            .iter()
            .any(|call| call.get(1).map(String::as_str) == Some("put-item")));
    }

    #[test]
    fn revalidating_runner_rejects_wrong_table_or_region_without_aws_call() {
        let runner = Arc::new(ScriptedRunner::new(valid_outputs()));
        let qualified = qualified_aws_dynamodb_runner(runner.clone(), pin()).unwrap();
        let args = [
            "dynamodb",
            "put-item",
            "--table-name",
            "other",
            "--region",
            "us-east-1",
        ]
        .iter()
        .map(OsString::from)
        .collect::<Vec<_>>();
        assert!(qualified.run(&args).is_err());
        assert_eq!(runner.calls().len(), 4);
    }
    #[test]
    fn revalidating_runner_rejects_endpoint_profile_duplicate_and_unreviewed_switches() {
        let attacks: Vec<Vec<&str>> = vec![
            vec!["--endpoint-url", "https://attacker.invalid"],
            vec!["--profile", "other-profile"],
            vec!["--table-name", "other-table"],
            vec!["--region", "us-west-2"],
            vec!["--no-sign-request"],
            vec!["--no-verify-ssl"],
            vec!["--cli-input-json", "file://attacker.json"],
        ];
        for attack in attacks {
            let runner = Arc::new(ScriptedRunner::new(valid_outputs()));
            let qualified = qualified_aws_dynamodb_runner(runner.clone(), pin()).unwrap();
            let mut values = vec![
                "dynamodb",
                "put-item",
                "--table-name",
                "qrun-anchor",
                "--item",
                "{}",
                "--condition-expression",
                "attribute_not_exists(anchor_id)",
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
            ];
            values.extend(attack);
            let args = values.iter().map(OsString::from).collect::<Vec<_>>();
            assert!(qualified.run(&args).is_err());
            // The initial four read-only qualification calls are the only AWS calls.
            assert_eq!(runner.calls().len(), 4);
        }
    }

    #[test]
    fn revalidating_runner_rejects_unapproved_operations_and_incomplete_put_contracts() {
        for values in [
            vec![
                "dynamodb",
                "delete-table",
                "--table-name",
                "qrun-anchor",
                "--region",
                "us-east-1",
            ],
            vec![
                "dynamodb",
                "put-item",
                "--table-name",
                "qrun-anchor",
                "--region",
                "us-east-1",
            ],
        ] {
            let runner = Arc::new(ScriptedRunner::new(valid_outputs()));
            let qualified = qualified_aws_dynamodb_runner(runner.clone(), pin()).unwrap();
            let args = values.iter().map(OsString::from).collect::<Vec<_>>();
            assert!(qualified.run(&args).is_err());
            assert_eq!(runner.calls().len(), 4);
        }
    }
    #[test]
    fn revalidating_runner_rejects_assumed_role_session_name_drift_even_when_account_and_role_match(
    ) {
        let mut outputs = valid_outputs();
        let mut rotated_session = valid_outputs();
        rotated_session[0]["Arn"] = Value::String(
            "arn:aws:sts::123456789012:assumed-role/QRunAnchorCustodian/different-session".into(),
        );
        rotated_session[0]["UserId"] = Value::String("AROAX:different-session".into());
        outputs.extend(rotated_session);
        let runner = Arc::new(ScriptedRunner::new(outputs));
        let qualified = qualified_aws_dynamodb_runner(runner.clone(), pin()).unwrap();
        let args = [
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
        ]
        .iter()
        .map(OsString::from)
        .collect::<Vec<_>>();

        assert!(qualified.run(&args).is_err());
        let calls = runner.calls();
        assert_eq!(calls.len(), 8);
        assert_eq!(calls[4][0], "sts");
        assert_eq!(calls[5][0], "iam");
        assert_eq!(calls[6][0], "dynamodb");
        assert_eq!(calls[7][1], "describe-continuous-backups");
        assert!(!calls
            .iter()
            .any(|call| call.get(1).map(String::as_str) == Some("get-item")));
    }

    #[test]
    fn public_session_bound_constructor_rejects_deployment_pin_substitution_before_aws_call() {
        let (provider_pin, anchor_pin, verified) =
            crate::external_cas_bootstrap_trust_candidate::tests::verified_test_fixture();
        let expires = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 600;
        let session = crate::external_cas_offhost_anchor_aws_dynamodb_candidate::AwsTemporaryCredentialSession::new(
            "ASIA_TEST_ACCESS_KEY".into(),
            "secret-test-only".into(),
            "token-test-only".into(),
            expires,
        )
        .unwrap();
        let runner = crate::external_cas_offhost_anchor_aws_dynamodb_candidate::SessionBoundAwsDynamoDbCliRunner::new(
            std::env::current_exe().unwrap(),
            pin(),
            session,
        )
        .unwrap();
        let mut substituted = pin();
        substituted.table_name = "substituted-table".into();

        let result = crate::external_cas_offhost_anchor_aws_dynamodb_candidate::AwsDynamoDbOffhostAnchorStore::with_session_bound_verified_bootstrap_runner(
            Arc::new(runner),
            substituted,
            anchor_pin,
            provider_pin,
            &verified,
        );
        assert!(matches!(
            result,
            Err(crate::external_cas_offhost_anchor_protocol_candidate::ExternalCasOffhostAnchorStoreError::Unavailable)
        ));
    }

    #[test]
    fn qualified_qbt1_constructor_returns_store_only_after_identity_preflight() {
        let (provider_pin, anchor_pin, verified) =
            crate::external_cas_bootstrap_trust_candidate::tests::verified_test_fixture();
        let runner = Arc::new(ScriptedRunner::new(valid_outputs()));
        let store = crate::external_cas_offhost_anchor_aws_dynamodb_candidate::AwsDynamoDbOffhostAnchorStore::with_qualified_verified_bootstrap_runner(
            runner.clone(),
            pin(),
            anchor_pin,
            provider_pin,
            &verified,
        )
        .unwrap();
        let _ = store;
        assert_eq!(runner.calls().len(), 4);
    }
}
