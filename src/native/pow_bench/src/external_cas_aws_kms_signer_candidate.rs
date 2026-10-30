//! AWS KMS-backed ML-DSA-65 receipt signer for the QRun external-CAS provider.
//!
//! The AWS CLI uses the normal AWS credential provider chain. Production deployments should use
//! a narrowly scoped EC2/ECS IAM role, not long-lived access keys. The ML-DSA private key remains
//! inside AWS KMS; this adapter receives signatures only. The CLI is invoked without a shell.
//!
//! KMS is checked at startup: key metadata must be ML_DSA_65 / SIGN_VERIFY, its SPKI public key
//! must exactly match the QRun pin, and a challenge signature must verify locally. Sign calls use
//! MessageType=RAW for the 32-byte QRun signing digest, matching the standard ML-DSA message API.

use crate::{
    external_cas_anchor_candidate::ExternalCasPin,
    external_cas_disk_provider_candidate::ReceiptSignature,
    v4_fat1_trust_candidate::ML_DSA_65_PUBLIC_KEY_BYTES,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use libcrux_ml_dsa::ml_dsa_65::{portable, MLDSA65Signature, MLDSA65VerificationKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

const KMS_ALGORITHM: &str = "ML_DSA_SHAKE_256";
const KMS_KEY_SPEC: &str = "ML_DSA_65";
const KMS_KEY_USAGE: &str = "SIGN_VERIFY";
const SELF_TEST_DOMAIN: &[u8] = b"QRUN-V05-EXTERNAL-CAS-KMS-SELF-TEST-V1\0";
const ML_DSA_65_OID: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12];

#[derive(Debug)]
pub enum AwsKmsReceiptSignerError {
    InvalidConfiguration,
    Pin(String),
    CliStart(String),
    CliRejected(String),
    InvalidResponse,
    WrongKeySpec,
    WrongKeyUsage,
    WrongSigningAlgorithm,
    PublicKeyMismatch,
    InvalidPublicKey,
    InvalidSignature,
    SelfTestFailed,
}

impl std::fmt::Display for AwsKmsReceiptSignerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfiguration => write!(f, "AWS KMS signer configuration is invalid"),
            Self::Pin(error) => write!(f, "external-CAS receipt pin is invalid: {error}"),
            Self::CliStart(error) => write!(f, "AWS CLI could not be started: {error}"),
            Self::CliRejected(error) => write!(f, "AWS KMS CLI request failed: {error}"),
            Self::InvalidResponse => write!(f, "AWS KMS returned a malformed response"),
            Self::WrongKeySpec => write!(f, "AWS KMS key is not ML_DSA_65"),
            Self::WrongKeyUsage => write!(f, "AWS KMS key usage is not SIGN_VERIFY"),
            Self::WrongSigningAlgorithm => {
                write!(f, "AWS KMS key does not advertise ML_DSA_SHAKE_256")
            }
            Self::PublicKeyMismatch => {
                write!(f, "AWS KMS public key does not match the QRun receipt pin")
            }
            Self::InvalidPublicKey => write!(f, "AWS KMS ML-DSA-65 public key encoding is invalid"),
            Self::InvalidSignature => write!(f, "AWS KMS returned an invalid ML-DSA-65 signature"),
            Self::SelfTestFailed => {
                write!(f, "AWS KMS ML-DSA-65 startup signature self-test failed")
            }
        }
    }
}

impl std::error::Error for AwsKmsReceiptSignerError {}

/// Receipt signer backed by an asymmetric AWS KMS ML_DSA_65 key.
/// The configured key identifier must be a full key ARN, not an alias or short key ID.
pub struct AwsKmsCliReceiptSigner {
    aws_cli: PathBuf,
    region: String,
    key_arn: String,
    verification_key: MLDSA65VerificationKey,
}

impl std::fmt::Debug for AwsKmsCliReceiptSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsKmsCliReceiptSigner")
            .field("aws_cli", &self.aws_cli)
            .field("region", &self.region)
            .field("key_arn", &self.key_arn)
            .field("private_key", &"<held by AWS KMS>")
            .finish()
    }
}

impl AwsKmsCliReceiptSigner {
    pub fn connect(
        aws_cli: impl AsRef<Path>,
        region: impl Into<String>,
        key_arn: impl Into<String>,
        pin: &ExternalCasPin,
    ) -> Result<Self, AwsKmsReceiptSignerError> {
        pin.validate()
            .map_err(|error| AwsKmsReceiptSignerError::Pin(error.to_string()))?;
        let region = region.into();
        let key_arn = key_arn.into();
        if region.is_empty()
            || !region.is_ascii()
            || !key_arn.starts_with("arn:aws:kms:")
            || !key_arn.contains(":key/")
            || key_arn.contains(":alias/")
        {
            return Err(AwsKmsReceiptSignerError::InvalidConfiguration);
        }

        let signer = Self {
            aws_cli: aws_cli.as_ref().to_path_buf(),
            region,
            key_arn,
            verification_key: MLDSA65VerificationKey::new(pin.receipt_public_key),
        };

        signer.verify_kms_key_metadata_and_public_key(&pin.receipt_public_key)?;
        let challenge = Self::self_test_challenge(pin);
        let signature = signer.sign_digest(&challenge)?;
        let signature = MLDSA65Signature::new(signature);
        portable::verify(&signer.verification_key, &challenge, &[], &signature)
            .map_err(|_| AwsKmsReceiptSignerError::SelfTestFailed)?;

        Ok(signer)
    }

    pub fn from_path(
        region: impl Into<String>,
        key_arn: impl Into<String>,
        pin: &ExternalCasPin,
    ) -> Result<Self, AwsKmsReceiptSignerError> {
        Self::connect("aws", region, key_arn, pin)
    }

    /// Sign one QRun digest and verify the result against the already pinned public key.
    pub fn sign_digest(
        &self,
        digest: &[u8; 32],
    ) -> Result<ReceiptSignature, AwsKmsReceiptSignerError> {
        let encoded_message = BASE64.encode(digest);
        let output = self.run_cli(&[
            "kms",
            "sign",
            "--key-id",
            &self.key_arn,
            "--message",
            &encoded_message,
            "--message-type",
            "RAW",
            "--signing-algorithm",
            KMS_ALGORITHM,
            "--output",
            "json",
        ])?;
        let response: Value = serde_json::from_slice(&output)
            .map_err(|_| AwsKmsReceiptSignerError::InvalidResponse)?;
        if response.get("SigningAlgorithm").and_then(Value::as_str) != Some(KMS_ALGORITHM)
            || response.get("KeyId").and_then(Value::as_str) != Some(self.key_arn.as_str())
        {
            return Err(AwsKmsReceiptSignerError::InvalidResponse);
        }
        let signature_text = response
            .get("Signature")
            .and_then(Value::as_str)
            .ok_or(AwsKmsReceiptSignerError::InvalidResponse)?;
        let signature_bytes = BASE64
            .decode(signature_text)
            .map_err(|_| AwsKmsReceiptSignerError::InvalidResponse)?;
        let signature: ReceiptSignature = signature_bytes
            .try_into()
            .map_err(|_| AwsKmsReceiptSignerError::InvalidResponse)?;
        let signature_object = MLDSA65Signature::new(signature);
        portable::verify(&self.verification_key, digest, &[], &signature_object)
            .map_err(|_| AwsKmsReceiptSignerError::InvalidSignature)?;
        Ok(signature)
    }

    fn verify_kms_key_metadata_and_public_key(
        &self,
        expected_public_key: &[u8; ML_DSA_65_PUBLIC_KEY_BYTES],
    ) -> Result<(), AwsKmsReceiptSignerError> {
        let output = self.run_cli(&[
            "kms",
            "get-public-key",
            "--key-id",
            &self.key_arn,
            "--output",
            "json",
        ])?;
        let response: Value = serde_json::from_slice(&output)
            .map_err(|_| AwsKmsReceiptSignerError::InvalidResponse)?;
        if response.get("KeySpec").and_then(Value::as_str) != Some(KMS_KEY_SPEC) {
            return Err(AwsKmsReceiptSignerError::WrongKeySpec);
        }
        if response.get("KeyUsage").and_then(Value::as_str) != Some(KMS_KEY_USAGE) {
            return Err(AwsKmsReceiptSignerError::WrongKeyUsage);
        }
        let algorithms = response
            .get("SigningAlgorithms")
            .and_then(Value::as_array)
            .ok_or(AwsKmsReceiptSignerError::InvalidResponse)?;
        if !algorithms
            .iter()
            .any(|value| value.as_str() == Some(KMS_ALGORITHM))
        {
            return Err(AwsKmsReceiptSignerError::WrongSigningAlgorithm);
        }
        if response.get("KeyId").and_then(Value::as_str) != Some(self.key_arn.as_str()) {
            return Err(AwsKmsReceiptSignerError::InvalidResponse);
        }
        let public_key_der = response
            .get("PublicKey")
            .and_then(Value::as_str)
            .ok_or(AwsKmsReceiptSignerError::InvalidResponse)?;
        let public_key_der = BASE64
            .decode(public_key_der)
            .map_err(|_| AwsKmsReceiptSignerError::InvalidPublicKey)?;
        let public_key = extract_mldsa65_spki_public_key(&public_key_der)?;
        if &public_key != expected_public_key {
            return Err(AwsKmsReceiptSignerError::PublicKeyMismatch);
        }
        Ok(())
    }

    fn self_test_challenge(pin: &ExternalCasPin) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(SELF_TEST_DOMAIN);
        hash.update(pin.provider_id);
        hash.update(pin.network_id);
        hash.update(pin.genesis_digest);
        hash.update(pin.receipt_key_id);
        hash.finalize().into()
    }

    fn run_cli(&self, operation: &[&str]) -> Result<Vec<u8>, AwsKmsReceiptSignerError> {
        let mut command = Command::new(&self.aws_cli);
        command
            .args(operation)
            .arg("--region")
            .arg(&self.region)
            .arg("--no-cli-pager")
            .arg("--cli-connect-timeout")
            .arg("5")
            .arg("--cli-read-timeout")
            .arg("20")
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .stdout(Stdio::piped());

        let output = command
            .output()
            .map_err(|error| AwsKmsReceiptSignerError::CliStart(error.to_string()))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let safe = stderr
                .chars()
                .filter(|character| {
                    !character.is_control() || *character == '\n' || *character == '\t'
                })
                .take(512)
                .collect::<String>();
            return Err(AwsKmsReceiptSignerError::CliRejected(safe));
        }
        Ok(output.stdout)
    }
}

/// Extract the raw 1952-byte ML-DSA-65 public key from an X.509 SubjectPublicKeyInfo DER object.
fn extract_mldsa65_spki_public_key(
    der: &[u8],
) -> Result<[u8; ML_DSA_65_PUBLIC_KEY_BYTES], AwsKmsReceiptSignerError> {
    let (outer, remaining) = read_der_tlv(der, 0x30)?;
    if !remaining.is_empty() {
        return Err(AwsKmsReceiptSignerError::InvalidPublicKey);
    }
    let (algorithm, remaining) = read_der_tlv(outer, 0x30)?;
    let (bit_string, trailing) = read_der_tlv(remaining, 0x03)?;
    if !trailing.is_empty() {
        return Err(AwsKmsReceiptSignerError::InvalidPublicKey);
    }
    let (oid, parameters) = read_der_tlv(algorithm, 0x06)?;
    if oid != ML_DSA_65_OID || !parameters.is_empty() {
        return Err(AwsKmsReceiptSignerError::InvalidPublicKey);
    }
    if bit_string.len() != ML_DSA_65_PUBLIC_KEY_BYTES + 1 || bit_string[0] != 0 {
        return Err(AwsKmsReceiptSignerError::InvalidPublicKey);
    }
    bit_string[1..]
        .try_into()
        .map_err(|_| AwsKmsReceiptSignerError::InvalidPublicKey)
}

fn read_der_tlv(
    input: &[u8],
    expected_tag: u8,
) -> Result<(&[u8], &[u8]), AwsKmsReceiptSignerError> {
    if input.len() < 2 || input[0] != expected_tag {
        return Err(AwsKmsReceiptSignerError::InvalidPublicKey);
    }
    let first_length = input[1];
    let (header_length, content_length) = if first_length & 0x80 == 0 {
        (2usize, first_length as usize)
    } else {
        let length_bytes = (first_length & 0x7f) as usize;
        if length_bytes == 0 || length_bytes > 4 || input.len() < 2 + length_bytes {
            return Err(AwsKmsReceiptSignerError::InvalidPublicKey);
        }
        if input[2] == 0 {
            return Err(AwsKmsReceiptSignerError::InvalidPublicKey);
        }
        let mut length = 0usize;
        for byte in &input[2..2 + length_bytes] {
            length = length
                .checked_mul(256)
                .and_then(|value| value.checked_add(*byte as usize))
                .ok_or(AwsKmsReceiptSignerError::InvalidPublicKey)?;
        }
        if length < 128 {
            return Err(AwsKmsReceiptSignerError::InvalidPublicKey);
        }
        (2 + length_bytes, length)
    };
    let end = header_length
        .checked_add(content_length)
        .ok_or(AwsKmsReceiptSignerError::InvalidPublicKey)?;
    if end > input.len() {
        return Err(AwsKmsReceiptSignerError::InvalidPublicKey);
    }
    Ok((&input[header_length..end], &input[end..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn der_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut result = vec![tag];
        if value.len() < 128 {
            result.push(value.len() as u8);
        } else if value.len() <= u16::MAX as usize {
            result.push(0x82);
            result.extend_from_slice(&(value.len() as u16).to_be_bytes());
        } else {
            panic!("test DER fixture unexpectedly large");
        }
        result.extend_from_slice(value);
        result
    }

    #[test]
    fn extracts_exact_mldsa65_spki_public_key() {
        let expected = [0x5a; ML_DSA_65_PUBLIC_KEY_BYTES];
        let algorithm = der_tlv(0x30, &der_tlv(0x06, ML_DSA_65_OID));
        let mut bit_string = Vec::with_capacity(expected.len() + 1);
        bit_string.push(0);
        bit_string.extend_from_slice(&expected);
        let mut spki = algorithm;
        spki.extend_from_slice(&der_tlv(0x03, &bit_string));
        let encoded = der_tlv(0x30, &spki);
        assert_eq!(extract_mldsa65_spki_public_key(&encoded).unwrap(), expected);
    }

    #[test]
    fn rejects_wrong_oid_trailing_der_and_nonzero_unused_bits() {
        let expected = [0x5a; ML_DSA_65_PUBLIC_KEY_BYTES];
        let wrong_algorithm = der_tlv(0x30, &der_tlv(0x06, &[0x2a, 0x03]));
        let mut bits = Vec::with_capacity(expected.len() + 1);
        bits.push(0);
        bits.extend_from_slice(&expected);
        let mut body = wrong_algorithm;
        body.extend_from_slice(&der_tlv(0x03, &bits));
        assert!(extract_mldsa65_spki_public_key(&der_tlv(0x30, &body)).is_err());

        let algorithm = der_tlv(0x30, &der_tlv(0x06, ML_DSA_65_OID));
        bits[0] = 1;
        let mut body = algorithm;
        body.extend_from_slice(&der_tlv(0x03, &bits));
        assert!(extract_mldsa65_spki_public_key(&der_tlv(0x30, &body)).is_err());

        let mut with_trailing = der_tlv(0x30, &body);
        with_trailing.push(0);
        assert!(extract_mldsa65_spki_public_key(&with_trailing).is_err());
    }
}
