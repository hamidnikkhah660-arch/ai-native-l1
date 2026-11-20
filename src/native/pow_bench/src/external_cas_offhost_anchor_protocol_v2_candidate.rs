//! CP-0765 QAR2 envelope candidate. QAR1 V1 remains byte-for-byte unchanged.
//! QAR2 signs the exact QAR1 receipt wire together with the verified QBT1 bootstrap digest.
//! This is a protocol candidate; production caller and AWS runtime integration are separate gates.
use crate::{
    external_cas_anchor_candidate::ExternalCasPin,
    external_cas_bootstrap_trust_candidate::VerifiedBootstrapTrust,
    external_cas_offhost_anchor_candidate::ExternalCasOffhostAnchorState,
    external_cas_offhost_anchor_protocol_candidate::{
        ExternalCasOffhostAnchorCasRequest, ExternalCasOffhostAnchorPin,
        ExternalCasOffhostAnchorReadRequest, ExternalCasOffhostAnchorReceipt,
        OffhostAnchorProtocolError, OffhostAnchorReceiptSigner, OFFHOST_ANCHOR_RECEIPT_BYTES,
    },
    v4_fat1_trust_candidate::{MlDsa65Verifier, ML_DSA_65_SIGNATURE_BYTES},
};
use sha2::{Digest, Sha256};

type Digest32 = [u8; 32];
const MAGIC: &[u8; 4] = b"QAR2";
const VERSION: u16 = 2;
const DOMAIN: &[u8] = b"QRUN-OFFHOST-ANCHOR-RECEIPT-V2-QBT1-BOUND\0";
pub const QAR2_PAYLOAD_BYTES: usize = 8 + 32 + OFFHOST_ANCHOR_RECEIPT_BYTES;
pub const QAR2_RECEIPT_BYTES: usize = QAR2_PAYLOAD_BYTES + ML_DSA_65_SIGNATURE_BYTES;

fn hash(parts: &[&[u8]]) -> Digest32 {
    let mut h = Sha256::new();
    for part in parts {
        h.update(part);
    }
    h.finalize().into()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QAR2BootstrapBoundReceipt {
    pub bootstrap_trust_digest: Digest32,
    pub inner_qar1: ExternalCasOffhostAnchorReceipt,
    pub signature: [u8; ML_DSA_65_SIGNATURE_BYTES],
}
impl QAR2BootstrapBoundReceipt {
    pub fn new(inner: ExternalCasOffhostAnchorReceipt, trust: &VerifiedBootstrapTrust) -> Self {
        Self {
            bootstrap_trust_digest: trust.receipt_digest(),
            inner_qar1: inner,
            signature: [0; ML_DSA_65_SIGNATURE_BYTES],
        }
    }
    fn payload(&self) -> Result<[u8; QAR2_PAYLOAD_BYTES], OffhostAnchorProtocolError> {
        if self.bootstrap_trust_digest.iter().all(|b| *b == 0) {
            return Err(OffhostAnchorProtocolError::InvalidReceipt);
        }
        let inner = self.inner_qar1.encode()?;
        let mut out = Vec::with_capacity(QAR2_PAYLOAD_BYTES);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&self.bootstrap_trust_digest);
        out.extend_from_slice(&inner);
        out.try_into()
            .map_err(|_| OffhostAnchorProtocolError::InvalidReceipt)
    }
    pub fn signing_digest(&self) -> Result<Digest32, OffhostAnchorProtocolError> {
        Ok(hash(&[DOMAIN, &self.payload()?]))
    }
    pub fn sign<S: OffhostAnchorReceiptSigner>(
        &mut self,
        signer: &S,
    ) -> Result<(), OffhostAnchorProtocolError> {
        self.signature = signer
            .sign_digest(&self.signing_digest()?)
            .map_err(OffhostAnchorProtocolError::Signing)?;
        Ok(())
    }
    pub fn encode(&self) -> Result<[u8; QAR2_RECEIPT_BYTES], OffhostAnchorProtocolError> {
        let payload = self.payload()?;
        let mut out = Vec::with_capacity(QAR2_RECEIPT_BYTES);
        out.extend_from_slice(&payload);
        out.extend_from_slice(&self.signature);
        out.try_into()
            .map_err(|_| OffhostAnchorProtocolError::InvalidReceipt)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, OffhostAnchorProtocolError> {
        if bytes.len() != QAR2_RECEIPT_BYTES
            || &bytes[..4] != MAGIC
            || u16::from_be_bytes(bytes[4..6].try_into().unwrap()) != VERSION
            || bytes[6..8] != [0, 0]
        {
            return Err(OffhostAnchorProtocolError::InvalidReceipt);
        }
        let bootstrap_trust_digest = bytes[8..40].try_into().unwrap();
        let inner_qar1 =
            ExternalCasOffhostAnchorReceipt::decode(&bytes[40..40 + OFFHOST_ANCHOR_RECEIPT_BYTES])?;
        let receipt = Self {
            bootstrap_trust_digest,
            inner_qar1,
            signature: bytes[QAR2_PAYLOAD_BYTES..].try_into().unwrap(),
        };
        if receipt.payload()?.as_slice() != &bytes[..QAR2_PAYLOAD_BYTES] {
            return Err(OffhostAnchorProtocolError::InvalidReceipt);
        }
        Ok(receipt)
    }
    fn verify_outer<V: MlDsa65Verifier>(
        &self,
        anchor: &ExternalCasOffhostAnchorPin,
        provider: &ExternalCasPin,
        verifier: &V,
    ) -> Result<(), OffhostAnchorProtocolError> {
        anchor.validate(provider)?;
        if !verifier.verify(
            &anchor.receipt_public_key,
            &self.signing_digest()?,
            &self.signature,
        ) {
            return Err(OffhostAnchorProtocolError::InvalidReceipt);
        }
        Ok(())
    }
    fn verify_bootstrap(
        &self,
        trust: &VerifiedBootstrapTrust,
    ) -> Result<(), OffhostAnchorProtocolError> {
        if self.bootstrap_trust_digest != trust.receipt_digest() {
            return Err(OffhostAnchorProtocolError::InvalidReceipt);
        }
        Ok(())
    }
    pub fn verify_read<V: MlDsa65Verifier>(
        &self,
        trust: &VerifiedBootstrapTrust,
        anchor: &ExternalCasOffhostAnchorPin,
        provider: &ExternalCasPin,
        request: &ExternalCasOffhostAnchorReadRequest,
        verifier: &V,
    ) -> Result<ExternalCasOffhostAnchorState, OffhostAnchorProtocolError> {
        self.verify_bootstrap(trust)?;
        self.verify_outer(anchor, provider, verifier)?;
        self.inner_qar1
            .verify_read(anchor, provider, request, verifier)
    }
    pub fn verify_cas<V: MlDsa65Verifier>(&self, trust: &VerifiedBootstrapTrust, anchor: &ExternalCasOffhostAnchorPin, provider: &ExternalCasPin, request: &ExternalCasOffhostAnchorCasRequest, verifier: &V) -> Result<(crate::external_cas_offhost_anchor_protocol_candidate::ExternalCasOffhostAnchorReceiptOutcome, ExternalCasOffhostAnchorState), OffhostAnchorProtocolError>{
        self.verify_bootstrap(trust)?;
        self.verify_outer(anchor, provider, verifier)?;
        self.inner_qar1
            .verify_cas(anchor, provider, request, verifier)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        external_cas_anchor_candidate::ExternalCasRecord,
        external_cas_offhost_anchor_protocol_candidate::{
            ExternalCasOffhostAnchorReceiptKind, ExternalCasOffhostAnchorReceiptOutcome,
        },
        v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate,
    };
    use libcrux_ml_dsa::ml_dsa_65::{portable, MLDSA65SigningKey};

    struct TestSigner(MLDSA65SigningKey);
    impl OffhostAnchorReceiptSigner for TestSigner {
        fn sign_digest(
            &self,
            digest: &Digest32,
        ) -> Result<[u8; ML_DSA_65_SIGNATURE_BYTES], String> {
            let signature =
                portable::sign(&self.0, digest, &[], [0xE5; 32]).map_err(|e| format!("{e:?}"))?;
            Ok(*signature.as_ref())
        }
    }
    fn fixture() -> (
        ExternalCasPin,
        ExternalCasOffhostAnchorPin,
        ExternalCasOffhostAnchorReceipt,
        TestSigner,
    ) {
        let provider_keys = portable::generate_key_pair([0x61; 32]);
        let provider_pin = ExternalCasPin {
            provider_id: [0x11; 32],
            network_id: [0x22; 32],
            genesis_digest: [0x33; 32],
            receipt_key_id: [0x44; 32],
            receipt_public_key: *provider_keys.verification_key.as_ref(),
        };
        let record = ExternalCasRecord {
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
        let state =
            ExternalCasOffhostAnchorState::provision_bootstrap(&provider_pin, record, 1).unwrap();
        let anchor_keys = portable::generate_key_pair([0x62; 32]);
        let anchor_pin = ExternalCasOffhostAnchorPin {
            anchor_id: [0x91; 32],
            provider_id: provider_pin.provider_id,
            network_id: provider_pin.network_id,
            genesis_digest: provider_pin.genesis_digest,
            receipt_key_id: [0x92; 32],
            receipt_public_key: *anchor_keys.verification_key.as_ref(),
        };
        let signer = TestSigner(anchor_keys.signing_key);
        let mut inner = ExternalCasOffhostAnchorReceipt {
            kind: ExternalCasOffhostAnchorReceiptKind::Read,
            outcome: ExternalCasOffhostAnchorReceiptOutcome::Observed,
            challenge: [0xA1; 32],
            anchor_id: anchor_pin.anchor_id,
            provider_id: provider_pin.provider_id,
            network_id: provider_pin.network_id,
            genesis_digest: provider_pin.genesis_digest,
            receipt_key_id: anchor_pin.receipt_key_id,
            operation_id: [0xA2; 32],
            request_digest: [0xA3; 32],
            expected_sequence: 0,
            expected_state_digest: [0; 32],
            target_state_digest: [0; 32],
            state_digest: state.digest().unwrap(),
            state,
            signature: [0; ML_DSA_65_SIGNATURE_BYTES],
        };
        inner.sign(&signer).unwrap();
        (provider_pin, anchor_pin, inner, signer)
    }

    #[test]
    fn qar2_roundtrips_canonical_wire_and_preserves_signed_qar1() {
        let (_provider, _anchor, inner, signer) = fixture();
        let inner_wire = inner.encode().unwrap();
        let mut receipt = QAR2BootstrapBoundReceipt {
            bootstrap_trust_digest: [0xB1; 32],
            inner_qar1: inner,
            signature: [0; ML_DSA_65_SIGNATURE_BYTES],
        };
        receipt.sign(&signer).unwrap();
        let wire = receipt.encode().unwrap();
        let decoded = QAR2BootstrapBoundReceipt::decode(&wire).unwrap();
        assert_eq!(decoded, receipt);
        assert_eq!(decoded.inner_qar1.encode().unwrap(), inner_wire);
        assert_eq!(decoded.encode().unwrap(), wire);
    }

    #[test]
    fn bootstrap_digest_and_inner_receipt_are_covered_by_outer_signature() {
        let (provider, anchor, inner, signer) = fixture();
        let mut receipt = QAR2BootstrapBoundReceipt {
            bootstrap_trust_digest: [0xB2; 32],
            inner_qar1: inner,
            signature: [0; ML_DSA_65_SIGNATURE_BYTES],
        };
        receipt.sign(&signer).unwrap();
        let verifier = LibcruxMlDsa65VerifierCandidate;
        receipt.verify_outer(&anchor, &provider, &verifier).unwrap();
        let original = receipt.signing_digest().unwrap();
        receipt.bootstrap_trust_digest[0] ^= 1;
        assert_ne!(receipt.signing_digest().unwrap(), original);
        assert!(receipt.verify_outer(&anchor, &provider, &verifier).is_err());
    }

    #[test]
    fn rejects_zero_bootstrap_digest_and_noncanonical_header() {
        let (_provider, _anchor, inner, _signer) = fixture();
        let receipt = QAR2BootstrapBoundReceipt {
            bootstrap_trust_digest: [0; 32],
            inner_qar1: inner,
            signature: [0; ML_DSA_65_SIGNATURE_BYTES],
        };
        assert!(receipt.encode().is_err());
        let (_provider, _anchor, inner, signer) = fixture();
        let mut receipt = QAR2BootstrapBoundReceipt {
            bootstrap_trust_digest: [0xB3; 32],
            inner_qar1: inner,
            signature: [0; ML_DSA_65_SIGNATURE_BYTES],
        };
        receipt.sign(&signer).unwrap();
        let mut wire = receipt.encode().unwrap();
        wire[7] = 1;
        assert!(QAR2BootstrapBoundReceipt::decode(&wire).is_err());
    }
}

#[cfg(test)]
mod qbt1_integration_tests {
    use super::*;
    use crate::{
        external_cas_bootstrap_trust_candidate::tests::verified_test_fixture,
        external_cas_offhost_anchor_protocol_candidate::{
            ExternalCasOffhostAnchorReceiptKind, ExternalCasOffhostAnchorReceiptOutcome,
        },
        v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate,
    };
    use libcrux_ml_dsa::ml_dsa_65::{portable, MLDSA65SigningKey};
    struct AnchorSigner(MLDSA65SigningKey);
    impl OffhostAnchorReceiptSigner for AnchorSigner {
        fn sign_digest(
            &self,
            digest: &Digest32,
        ) -> Result<[u8; ML_DSA_65_SIGNATURE_BYTES], String> {
            Ok(*portable::sign(&self.0, digest, &[], [0xF1; 32])
                .map_err(|e| format!("{e:?}"))?
                .as_ref())
        }
    }
    #[test]
    fn qar2_verifies_only_with_the_exact_verified_qbt1_capability() {
        let (provider, anchor, trust) = verified_test_fixture();
        let keys = portable::generate_key_pair([0x22; 32]);
        let signer = AnchorSigner(keys.signing_key);
        let state = trust.initial_anchor_state().clone();
        let request = ExternalCasOffhostAnchorReadRequest {
            challenge: [0xA1; 32],
            operation_id: [0xA2; 32],
            request_digest: [0xA3; 32],
        };
        let mut inner = ExternalCasOffhostAnchorReceipt {
            kind: ExternalCasOffhostAnchorReceiptKind::Read,
            outcome: ExternalCasOffhostAnchorReceiptOutcome::Observed,
            challenge: request.challenge,
            anchor_id: anchor.anchor_id,
            provider_id: provider.provider_id,
            network_id: provider.network_id,
            genesis_digest: provider.genesis_digest,
            receipt_key_id: anchor.receipt_key_id,
            operation_id: request.operation_id,
            request_digest: request.request_digest,
            expected_sequence: 0,
            expected_state_digest: [0; 32],
            target_state_digest: [0; 32],
            state_digest: state.digest().unwrap(),
            state: state.clone(),
            signature: [0; ML_DSA_65_SIGNATURE_BYTES],
        };
        inner.sign(&signer).unwrap();
        let mut qar2 = QAR2BootstrapBoundReceipt::new(inner, &trust);
        qar2.sign(&signer).unwrap();
        let verifier = LibcruxMlDsa65VerifierCandidate;
        assert_eq!(
            qar2.verify_read(&trust, &anchor, &provider, &request, &verifier)
                .unwrap(),
            state
        );

        // Even a correctly re-signed QAR2 cannot substitute a different QBT1 digest.
        qar2.bootstrap_trust_digest[0] ^= 1;
        qar2.sign(&signer).unwrap();
        assert!(qar2
            .verify_read(&trust, &anchor, &provider, &request, &verifier)
            .is_err());
    }
}

/// Service facade that emits QAR2 for every read/CAS response. It deliberately exposes no
/// QAR1-returning method; callers opting into QBT1-bound mode cannot silently downgrade here.
pub struct QAR2BoundAnchorService {
    service:
        crate::external_cas_offhost_anchor_protocol_candidate::ExternalCasOffhostAnchorMemoryModel,
    trust: VerifiedBootstrapTrust,
    anchor_pin: ExternalCasOffhostAnchorPin,
    provider_pin: ExternalCasPin,
}
impl QAR2BoundAnchorService {
    #[cfg(test)]
    pub(crate) fn from_test_model(
        service: crate::external_cas_offhost_anchor_protocol_candidate::ExternalCasOffhostAnchorMemoryModel,
        trust: VerifiedBootstrapTrust,
        anchor_pin: ExternalCasOffhostAnchorPin,
        provider_pin: ExternalCasPin,
    ) -> Result<Self, OffhostAnchorProtocolError> {
        Self::new(service, trust, anchor_pin, provider_pin)
    }

    fn new(
        service: crate::external_cas_offhost_anchor_protocol_candidate::ExternalCasOffhostAnchorMemoryModel,
        trust: VerifiedBootstrapTrust,
        anchor_pin: ExternalCasOffhostAnchorPin,
        provider_pin: ExternalCasPin,
    ) -> Result<Self, OffhostAnchorProtocolError> {
        use crate::external_cas_bootstrap_trust_candidate::mldsa65_key_fingerprint;
        let qbt = trust.receipt();
        if !service.matches_pins(&anchor_pin, &provider_pin)
            || qbt.provider_id != provider_pin.provider_id
            || qbt.anchor_id != anchor_pin.anchor_id
            || qbt.network_id != provider_pin.network_id
            || qbt.genesis_digest != provider_pin.genesis_digest
            || qbt.provider_receipt_key_id != provider_pin.receipt_key_id
            || qbt.anchor_receipt_key_id != anchor_pin.receipt_key_id
            || qbt.provider_receipt_key_fingerprint
                != mldsa65_key_fingerprint(&provider_pin.receipt_public_key)
            || qbt.anchor_receipt_key_fingerprint
                != mldsa65_key_fingerprint(&anchor_pin.receipt_public_key)
            || trust
                .initial_anchor_state()
                .digest()
                .map_err(|_| OffhostAnchorProtocolError::InvalidReceipt)?
                != qbt.initial_anchor_state_digest
        {
            return Err(OffhostAnchorProtocolError::InvalidPin);
        }
        Ok(Self {
            service,
            trust,
            anchor_pin,
            provider_pin,
        })
    }

    /// Production composition entry point. It never accepts an unqualified or unbound store:
    /// the QBT1 capability is validated, the AWS deployment is pinned and requalified before
    /// each DynamoDB operation, and the resulting store is injected into the anchor protocol model.
    #[cfg(test)]
    pub(crate) fn with_qualified_aws_dynamodb(
        runner: std::sync::Arc<
            dyn crate::external_cas_offhost_anchor_aws_dynamodb_candidate::AwsDynamoDbCliRunner,
        >,
        deployment_pin: crate::external_cas_offhost_anchor_aws_qualification_candidate::AwsDynamoDbDeploymentPin,
        anchor_pin: ExternalCasOffhostAnchorPin,
        provider_pin: ExternalCasPin,
        trust: VerifiedBootstrapTrust,
    ) -> Result<Self, OffhostAnchorProtocolError> {
        let store = crate::external_cas_offhost_anchor_aws_dynamodb_candidate::AwsDynamoDbOffhostAnchorStore::with_qualified_verified_bootstrap_runner(
            runner,
            deployment_pin,
            anchor_pin.clone(),
            provider_pin.clone(),
            &trust,
        )
        .map_err(OffhostAnchorProtocolError::Store)?;
        let service = crate::external_cas_offhost_anchor_protocol_candidate::ExternalCasOffhostAnchorMemoryModel::with_store(
            anchor_pin.clone(),
            provider_pin.clone(),
            std::sync::Arc::new(store),
        )?;
        Self::new(service, trust, anchor_pin, provider_pin)
    }

    /// Public production entry point. The caller must supply one temporary STS credential
    /// snapshot bound to the exact account/role/table/region pin. Arbitrary runner injection is
    /// kept crate-private for deterministic tests only.
    pub fn with_session_bound_aws_dynamodb(
        runner: std::sync::Arc<crate::external_cas_offhost_anchor_aws_dynamodb_candidate::SessionBoundAwsDynamoDbCliRunner>,
        deployment_pin: crate::external_cas_offhost_anchor_aws_qualification_candidate::AwsDynamoDbDeploymentPin,
        anchor_pin: ExternalCasOffhostAnchorPin,
        provider_pin: ExternalCasPin,
        trust: VerifiedBootstrapTrust,
    ) -> Result<Self, OffhostAnchorProtocolError> {
        let store = crate::external_cas_offhost_anchor_aws_dynamodb_candidate::AwsDynamoDbOffhostAnchorStore::with_session_bound_verified_bootstrap_runner(
            runner,
            deployment_pin,
            anchor_pin.clone(),
            provider_pin.clone(),
            &trust,
        )
        .map_err(OffhostAnchorProtocolError::Store)?;
        let service = crate::external_cas_offhost_anchor_protocol_candidate::ExternalCasOffhostAnchorMemoryModel::with_store(
            anchor_pin.clone(),
            provider_pin.clone(),
            std::sync::Arc::new(store),
        )?;
        Self::new(service, trust, anchor_pin, provider_pin)
    }

    pub fn read<S: OffhostAnchorReceiptSigner>(
        &self,
        request: &ExternalCasOffhostAnchorReadRequest,
        signer: &S,
    ) -> Result<QAR2BootstrapBoundReceipt, OffhostAnchorProtocolError> {
        let inner = self.service.read(request, signer)?;
        let mut receipt = QAR2BootstrapBoundReceipt::new(inner, &self.trust);
        receipt.sign(signer)?;
        Ok(receipt)
    }

    pub fn compare_and_swap<S: OffhostAnchorReceiptSigner, V: MlDsa65Verifier>(
        &self,
        request: &ExternalCasOffhostAnchorCasRequest,
        next_record_bytes: &[u8],
        provider_receipt_bytes: &[u8],
        provider_verifier: &V,
        anchor_signer: &S,
    ) -> Result<QAR2BootstrapBoundReceipt, OffhostAnchorProtocolError> {
        let inner = self.service.compare_and_swap(
            request,
            next_record_bytes,
            provider_receipt_bytes,
            provider_verifier,
            anchor_signer,
        )?;
        let mut receipt = QAR2BootstrapBoundReceipt::new(inner, &self.trust);
        receipt.sign(anchor_signer)?;
        Ok(receipt)
    }

    pub fn bootstrap_trust_digest(&self) -> Digest32 {
        self.trust.receipt_digest()
    }

    pub fn matches_pins(
        &self,
        anchor: &ExternalCasOffhostAnchorPin,
        provider: &ExternalCasPin,
    ) -> bool {
        &self.anchor_pin == anchor && &self.provider_pin == provider
    }
}

#[cfg(test)]
mod service_facade_tests {
    use super::*;
    use crate::{
        external_cas_anchor_candidate::{
            ExternalCasReceipt, ExternalCasReceiptKind, ExternalCasReceiptOutcome,
            ExternalCasRecord, ExternalCasWriteRequest,
        },
        external_cas_bootstrap_trust_candidate::tests::verified_test_fixture,
        external_cas_offhost_anchor_aws_dynamodb_candidate::{
            AwsDynamoDbCliOutput, AwsDynamoDbCliRunner,
        },
        external_cas_offhost_anchor_candidate::verify_provider_commit_for_offhost_anchor,
        external_cas_offhost_anchor_protocol_candidate::{
            ExternalCasOffhostAnchorCasRequest, ExternalCasOffhostAnchorReceiptOutcome,
            ExternalCasOffhostAnchorStoreError,
        },
        v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate,
    };
    use libcrux_ml_dsa::ml_dsa_65::{portable, MLDSA65SigningKey};
    use std::{
        ffi::OsString,
        sync::{Arc, Mutex},
    };

    #[derive(Default)]
    struct WrongAwsIdentityRunner {
        calls: Mutex<Vec<Vec<String>>>,
    }

    impl AwsDynamoDbCliRunner for WrongAwsIdentityRunner {
        fn run(&self, arguments: &[OsString]) -> Result<AwsDynamoDbCliOutput, String> {
            self.calls.lock().unwrap().push(
                arguments
                    .iter()
                    .map(|argument| argument.to_string_lossy().into_owned())
                    .collect(),
            );
            Ok(AwsDynamoDbCliOutput {
                success: true,
                stdout: serde_json::json!({
                    "Account": "999999999999",
                    "Arn": "arn:aws:sts::999999999999:assumed-role/QRunAnchorCustodian/wrong-account",
                    "UserId": "wrong-account-session"
                })
                .to_string()
                .into_bytes(),
                stderr: Vec::new(),
            })
        }
    }

    #[test]
    fn qualified_qar2_aws_composition_fails_closed_before_dynamodb_on_wrong_account() {
        let (provider, anchor, trust) = verified_test_fixture();
        let deployment_pin =
            crate::external_cas_offhost_anchor_aws_qualification_candidate::AwsDynamoDbDeploymentPin {
                account_id: "123456789012".into(),
                role_arn: "arn:aws:iam::123456789012:role/QRunAnchorCustodian".into(),
                table_arn: "arn:aws:dynamodb:us-east-1:123456789012:table/qrun-anchor".into(),
                region: "us-east-1".into(),
                table_name: "qrun-anchor".into(),
            };
        let runner = Arc::new(WrongAwsIdentityRunner::default());

        let result = QAR2BoundAnchorService::with_qualified_aws_dynamodb(
            runner.clone(),
            deployment_pin,
            anchor,
            provider,
            trust,
        );

        assert!(matches!(
            result,
            Err(OffhostAnchorProtocolError::Store(
                ExternalCasOffhostAnchorStoreError::Unavailable
            ))
        ));
        let calls = runner.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0][0], "sts");
        assert_eq!(calls[0][1], "get-caller-identity");
        assert!(!calls
            .iter()
            .any(|arguments| { arguments.first().map(String::as_str) == Some("dynamodb") }));
    }

    struct AnchorSigner(MLDSA65SigningKey);
    impl OffhostAnchorReceiptSigner for AnchorSigner {
        fn sign_digest(
            &self,
            digest: &Digest32,
        ) -> Result<[u8; ML_DSA_65_SIGNATURE_BYTES], String> {
            Ok(*portable::sign(&self.0, digest, &[], [0xF1; 32])
                .map_err(|e| format!("{e:?}"))?
                .as_ref())
        }
    }
    #[test]
    fn qbt1_bound_service_emits_only_qar2_for_reads() {
        let (provider, anchor, trust) = verified_test_fixture();
        let service = crate::external_cas_offhost_anchor_protocol_candidate::ExternalCasOffhostAnchorMemoryModel::new(
            anchor.clone(), provider.clone(), trust.initial_anchor_state().clone(),
        ).unwrap();
        let facade =
            QAR2BoundAnchorService::new(service, trust.clone(), anchor.clone(), provider.clone())
                .unwrap();
        assert!(facade.matches_pins(&anchor, &provider));
        assert_eq!(facade.bootstrap_trust_digest(), trust.receipt_digest());
        let signer = AnchorSigner(portable::generate_key_pair([0x22; 32]).signing_key);
        let request = ExternalCasOffhostAnchorReadRequest {
            challenge: [0xB1; 32],
            operation_id: [0xB2; 32],
            request_digest: [0xB3; 32],
        };
        let receipt = facade.read(&request, &signer).unwrap();
        let verifier = LibcruxMlDsa65VerifierCandidate;
        assert_eq!(
            receipt
                .verify_read(&trust, &anchor, &provider, &request, &verifier)
                .unwrap(),
            *trust.initial_anchor_state()
        );
        let wire = receipt.encode().unwrap();
        assert_eq!(QAR2BootstrapBoundReceipt::decode(&wire).unwrap(), receipt);
    }

    #[test]
    fn qbt1_bound_service_emits_and_verifies_qar2_for_atomic_cas() {
        let (provider, anchor, trust) = verified_test_fixture();
        let initial = trust.initial_anchor_state().clone();
        let service =
            crate::external_cas_offhost_anchor_protocol_candidate::ExternalCasOffhostAnchorMemoryModel::new(
                anchor.clone(),
                provider.clone(),
                initial.clone(),
            )
            .unwrap();
        let facade =
            QAR2BoundAnchorService::new(service, trust.clone(), anchor.clone(), provider.clone())
                .unwrap();

        // These deterministic seeds reproduce only the QBT1 unit-test fixture keys.
        let provider_keys = portable::generate_key_pair([0x11; 32]);
        let anchor_signer = AnchorSigner(portable::generate_key_pair([0x22; 32]).signing_key);
        assert_eq!(
            provider.receipt_public_key.as_slice(),
            provider_keys.verification_key.as_ref()
        );

        let previous_record_digest = initial.provider_record.digest().unwrap();
        let operation_id = [0xB2; 32];
        let mut write = ExternalCasWriteRequest {
            request_nonce: [0xB1; 32],
            operation_id,
            request_digest: [1; 32],
            expected_generation: initial.provider_record.generation,
            expected_object_generation: initial.provider_object_generation,
            expected_record_digest: previous_record_digest,
            expected_state_digest: initial.provider_record.next_state_digest,
            next_record: ExternalCasRecord {
                generation: initial.provider_record.generation + 1,
                provider_id: provider.provider_id,
                network_id: provider.network_id,
                genesis_digest: provider.genesis_digest,
                previous_record_digest,
                previous_state_digest: initial.provider_record.next_state_digest,
                next_state_digest: [0xC1; 32],
                operation_id,
                request_digest: [1; 32],
            },
        };
        write.bind_request_digest(&provider).unwrap();

        let mut provider_receipt = ExternalCasReceipt {
            kind: ExternalCasReceiptKind::Commit,
            outcome: ExternalCasReceiptOutcome::Applied,
            generation: write.next_record.generation,
            object_generation: initial.provider_object_generation + 1,
            provider_id: provider.provider_id,
            network_id: provider.network_id,
            genesis_digest: provider.genesis_digest,
            receipt_key_id: provider.receipt_key_id,
            request_nonce: write.request_nonce,
            record_digest: write.next_record.digest().unwrap(),
            previous_record_digest: write.next_record.previous_record_digest,
            previous_state_digest: write.next_record.previous_state_digest,
            state_digest: write.next_record.next_state_digest,
            operation_id: write.operation_id,
            request_digest: write.request_digest,
            signature: [0; ML_DSA_65_SIGNATURE_BYTES],
        };
        let provider_digest = provider_receipt.signing_digest().unwrap();
        provider_receipt.signature = *portable::sign(
            &provider_keys.signing_key,
            &provider_digest,
            &[],
            [0xC2; 32],
        )
        .unwrap()
        .as_ref();

        let next_record_wire = write.next_record.encode().unwrap();
        let provider_receipt_wire = provider_receipt.encode().unwrap();
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let expected_next = verify_provider_commit_for_offhost_anchor(
            &provider,
            &initial,
            &next_record_wire,
            &provider_receipt_wire,
            &verifier,
        )
        .unwrap()
        .next_state;
        let request = ExternalCasOffhostAnchorCasRequest {
            challenge: [0xB3; 32],
            operation_id,
            request_digest: write.request_digest,
            expected_sequence: initial.sequence,
            expected_state_digest: initial.digest().unwrap(),
            target_state_digest: expected_next.digest().unwrap(),
        };

        let receipt = facade
            .compare_and_swap(
                &request,
                &next_record_wire,
                &provider_receipt_wire,
                &verifier,
                &anchor_signer,
            )
            .unwrap();
        assert_eq!(
            receipt
                .verify_cas(&trust, &anchor, &provider, &request, &verifier)
                .unwrap(),
            (
                ExternalCasOffhostAnchorReceiptOutcome::Applied,
                expected_next.clone()
            )
        );
        let wire = receipt.encode().unwrap();
        assert_eq!(QAR2BootstrapBoundReceipt::decode(&wire).unwrap(), receipt);

        let read_request = ExternalCasOffhostAnchorReadRequest {
            challenge: [0xC3; 32],
            operation_id: [0xC4; 32],
            request_digest: [0xC5; 32],
        };
        let read_receipt = facade.read(&read_request, &anchor_signer).unwrap();
        assert_eq!(
            read_receipt
                .verify_read(&trust, &anchor, &provider, &read_request, &verifier)
                .unwrap(),
            expected_next
        );
    }
}

/// CP-0770: stateful qualified-cloud runner integration and stale-snapshot replay harness.
/// The runner is deliberately a deterministic AWS CLI service double; it never opens a network
/// connection. It persists one DynamoDB item across independent adapter/facade constructions.
#[cfg(test)]
mod qualified_aws_remote_state_tests {
    use super::*;
    use crate::{
        external_cas_anchor_candidate::{
            ExternalCasReceipt, ExternalCasReceiptKind, ExternalCasReceiptOutcome,
            ExternalCasRecord, ExternalCasWriteRequest,
        },
        external_cas_bootstrap_trust_candidate::tests::verified_test_fixture,
        external_cas_offhost_anchor_aws_dynamodb_candidate::{
            AwsDynamoDbCliOutput, AwsDynamoDbCliRunner, AwsDynamoDbOffhostAnchorStore,
        },
        external_cas_offhost_anchor_aws_qualification_candidate::AwsDynamoDbDeploymentPin,
        external_cas_offhost_anchor_candidate::verify_provider_commit_for_offhost_anchor,
        external_cas_offhost_anchor_protocol_candidate::{
            ExternalCasOffhostAnchorReceiptOutcome, ExternalCasOffhostAnchorStore,
            ExternalCasOffhostAnchorStoreCasOutcome, ExternalCasOffhostAnchorStoreProvisionOutcome,
        },
        v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate,
    };
    use libcrux_ml_dsa::ml_dsa_65::{portable, MLDSA65SigningKey};
    use serde_json::{json, Value};
    use std::{
        ffi::OsString,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, Mutex,
        },
    };

    struct AnchorSigner(MLDSA65SigningKey);
    impl OffhostAnchorReceiptSigner for AnchorSigner {
        fn sign_digest(
            &self,
            digest: &Digest32,
        ) -> Result<[u8; ML_DSA_65_SIGNATURE_BYTES], String> {
            Ok(*portable::sign(&self.0, digest, &[], [0xF1; 32])
                .map_err(|error| format!("{error:?}"))?
                .as_ref())
        }
    }

    fn deployment_pin() -> AwsDynamoDbDeploymentPin {
        AwsDynamoDbDeploymentPin {
            account_id: "123456789012".into(),
            role_arn: "arn:aws:iam::123456789012:role/QRunAnchorCustodian".into(),
            table_arn: "arn:aws:dynamodb:us-east-1:123456789012:table/qrun-anchor".into(),
            region: "us-east-1".into(),
            table_name: "qrun-anchor".into(),
        }
    }

    fn cli_output(success: bool, value: Value, stderr: &[u8]) -> AwsDynamoDbCliOutput {
        AwsDynamoDbCliOutput {
            success,
            stdout: serde_json::to_vec(&value).unwrap(),
            stderr: stderr.to_vec(),
        }
    }

    fn argument_value<'a>(args: &'a [String], flag: &str) -> &'a str {
        let index = args.iter().position(|argument| argument == flag).unwrap();
        &args[index + 1]
    }

    /// A shared, stateful model of a separately administered remote table. It intentionally
    /// enforces strong reads, exact table/region pins, QBT1 immutable attributes and atomic CAS.
    /// It is test evidence for request composition only, not evidence about real AWS semantics.
    #[derive(Default)]
    struct StatefulQualifiedAwsRunner {
        item: Mutex<Option<Value>>,
        calls: Mutex<Vec<Vec<String>>>,
        wrong_identity: AtomicBool,
    }

    impl StatefulQualifiedAwsRunner {
        fn calls(&self) -> Vec<Vec<String>> {
            self.calls.lock().unwrap().clone()
        }

        fn set_wrong_identity(&self, wrong: bool) {
            self.wrong_identity.store(wrong, Ordering::SeqCst);
        }

        fn current_item(&self) -> Option<Value> {
            self.item.lock().unwrap().clone()
        }
    }

    impl AwsDynamoDbCliRunner for StatefulQualifiedAwsRunner {
        fn run(&self, arguments: &[OsString]) -> Result<AwsDynamoDbCliOutput, String> {
            let args = arguments
                .iter()
                .map(|argument| argument.to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            self.calls.lock().unwrap().push(args.clone());

            match (
                args.first().map(String::as_str),
                args.get(1).map(String::as_str),
            ) {
                (Some("sts"), Some("get-caller-identity")) => {
                    let (account, arn) = if self.wrong_identity.load(Ordering::SeqCst) {
                        (
                            "999999999999",
                            "arn:aws:sts::999999999999:assumed-role/QRunAnchorCustodian/drifted",
                        )
                    } else {
                        (
                            "123456789012",
                            "arn:aws:sts::123456789012:assumed-role/QRunAnchorCustodian/session-cp0770",
                        )
                    };
                    Ok(cli_output(
                        true,
                        json!({"Account": account, "Arn": arn, "UserId": "AROAX:session-cp0770"}),
                        &[],
                    ))
                }
                (Some("iam"), Some("get-role")) => Ok(cli_output(
                    true,
                    json!({"Role":{
                        "Arn":"arn:aws:iam::123456789012:role/QRunAnchorCustodian",
                        "RoleName":"QRunAnchorCustodian"
                    }}),
                    &[],
                )),
                (Some("dynamodb"), Some("describe-table")) => Ok(cli_output(
                    true,
                    json!({"Table":{
                        "TableArn":"arn:aws:dynamodb:us-east-1:123456789012:table/qrun-anchor",
                        "TableStatus":"ACTIVE",
                        "KeySchema":[{"AttributeName":"anchor_id","KeyType":"HASH"}],
                        "AttributeDefinitions":[{"AttributeName":"anchor_id","AttributeType":"S"}],
                        "DeletionProtectionEnabled":true,
                        "SSEDescription":{"Status":"ENABLED"},
                        "Replicas":[]
                    }}),
                    &[],
                )),
                (Some("dynamodb"), Some("describe-continuous-backups")) => Ok(cli_output(
                    true,
                    json!({"ContinuousBackupsDescription":{
                        "PointInTimeRecoveryDescription":{"PointInTimeRecoveryStatus":"ENABLED"}
                    }}),
                    &[],
                )),
                (Some("dynamodb"), Some("get-item")) => {
                    if !args.iter().any(|argument| argument == "--consistent-read")
                        || argument_value(&args, "--table-name") != "qrun-anchor"
                        || argument_value(&args, "--region") != "us-east-1"
                    {
                        return Err("unqualified or non-strong GetItem rejected".into());
                    }
                    let item = self
                        .item
                        .lock()
                        .unwrap()
                        .clone()
                        .unwrap_or_else(|| json!({}));
                    Ok(cli_output(true, json!({"Item": item}), &[]))
                }
                (Some("dynamodb"), Some("put-item")) => {
                    if argument_value(&args, "--table-name") != "qrun-anchor"
                        || argument_value(&args, "--region") != "us-east-1"
                    {
                        return Err("unpinned PutItem rejected".into());
                    }
                    let proposed: Value = serde_json::from_str(argument_value(&args, "--item"))
                        .map_err(|error| format!("malformed item: {error}"))?;
                    let condition = argument_value(&args, "--condition-expression");
                    let mut stored = self.item.lock().unwrap();
                    let permitted = if condition == "attribute_not_exists(#anchor_id)" {
                        stored.is_none()
                    } else {
                        let names: Value = serde_json::from_str(argument_value(
                            &args,
                            "--expression-attribute-names",
                        ))
                        .map_err(|error| format!("malformed names: {error}"))?;
                        let values: Value = serde_json::from_str(argument_value(
                            &args,
                            "--expression-attribute-values",
                        ))
                        .map_err(|error| format!("malformed values: {error}"))?;
                        stored.as_ref().map_or(false, |current| {
                            let mapped_equal = |name_token: &str, value_token: &str| {
                                names
                                    .get(name_token)
                                    .and_then(Value::as_str)
                                    .and_then(|actual_name| current.get(actual_name))
                                    == values.get(value_token)
                            };
                            condition.starts_with(
                                "attribute_exists(#anchor_id) AND #sequence = :expected_sequence AND #state_digest = :expected_state_digest",
                            )
                                && mapped_equal("#sequence", ":expected_sequence")
                                && mapped_equal("#state_digest", ":expected_state_digest")
                                && mapped_equal(
                                    "#bootstrap_trust_receipt_digest",
                                    ":bootstrap_trust_receipt_digest",
                                )
                                && mapped_equal(
                                    "#bootstrap_initial_state_digest",
                                    ":bootstrap_initial_state_digest",
                                )
                                && mapped_equal(
                                    "#bootstrap_trust_receipt_wire_b64",
                                    ":bootstrap_trust_receipt_wire_b64",
                                )
                        })
                    };

                    if permitted {
                        *stored = Some(proposed);
                        Ok(cli_output(true, json!({}), &[]))
                    } else {
                        Ok(cli_output(
                            false,
                            json!({}),
                            b"An error occurred (ConditionalCheckFailedException) when calling the PutItem operation.",
                        ))
                    }
                }
                _ => Err(format!("unrecognized AWS CLI command: {args:?}")),
            }
        }
    }

    fn assert_each_storage_operation_was_requalified(calls: &[Vec<String>]) {
        let prefix = [
            ("sts", "get-caller-identity"),
            ("iam", "get-role"),
            ("dynamodb", "describe-table"),
            ("dynamodb", "describe-continuous-backups"),
        ];
        for (index, call) in calls.iter().enumerate() {
            let is_storage_operation = call.first().map(String::as_str) == Some("dynamodb")
                && matches!(
                    call.get(1).map(String::as_str),
                    Some("get-item") | Some("put-item")
                );
            if is_storage_operation {
                assert!(index >= prefix.len());
                for (offset, (service, operation)) in prefix.iter().enumerate() {
                    assert_eq!(calls[index - prefix.len() + offset][0], *service);
                    assert_eq!(calls[index - prefix.len() + offset][1], *operation);
                }
            }
        }
    }

    fn signed_transition(
        provider: &ExternalCasPin,
        initial: &ExternalCasOffhostAnchorState,
        marker: u8,
    ) -> (
        ExternalCasOffhostAnchorCasRequest,
        Vec<u8>,
        Vec<u8>,
        ExternalCasOffhostAnchorState,
    ) {
        let provider_keys = portable::generate_key_pair([0x11; 32]);
        assert_eq!(
            provider.receipt_public_key.as_slice(),
            provider_keys.verification_key.as_ref()
        );
        let previous_record_digest = initial.provider_record.digest().unwrap();
        let operation_id = [marker; 32];
        let mut write = ExternalCasWriteRequest {
            request_nonce: [marker.wrapping_add(1); 32],
            operation_id,
            request_digest: [marker.wrapping_add(2); 32],
            expected_generation: initial.provider_record.generation,
            expected_object_generation: initial.provider_object_generation,
            expected_record_digest: previous_record_digest,
            expected_state_digest: initial.provider_record.next_state_digest,
            next_record: ExternalCasRecord {
                generation: initial.provider_record.generation + 1,
                provider_id: provider.provider_id,
                network_id: provider.network_id,
                genesis_digest: provider.genesis_digest,
                previous_record_digest,
                previous_state_digest: initial.provider_record.next_state_digest,
                next_state_digest: [marker.wrapping_add(3); 32],
                operation_id,
                request_digest: [marker.wrapping_add(2); 32],
            },
        };
        write.bind_request_digest(provider).unwrap();
        let mut provider_receipt = ExternalCasReceipt {
            kind: ExternalCasReceiptKind::Commit,
            outcome: ExternalCasReceiptOutcome::Applied,
            generation: write.next_record.generation,
            object_generation: initial.provider_object_generation + 1,
            provider_id: provider.provider_id,
            network_id: provider.network_id,
            genesis_digest: provider.genesis_digest,
            receipt_key_id: provider.receipt_key_id,
            request_nonce: write.request_nonce,
            record_digest: write.next_record.digest().unwrap(),
            previous_record_digest: write.next_record.previous_record_digest,
            previous_state_digest: write.next_record.previous_state_digest,
            state_digest: write.next_record.next_state_digest,
            operation_id: write.operation_id,
            request_digest: write.request_digest,
            signature: [0; ML_DSA_65_SIGNATURE_BYTES],
        };
        let signing_digest = provider_receipt.signing_digest().unwrap();
        provider_receipt.signature = *portable::sign(
            &provider_keys.signing_key,
            &signing_digest,
            &[],
            [marker.wrapping_add(4); 32],
        )
        .unwrap()
        .as_ref();

        let record_wire = write.next_record.encode().unwrap();
        let provider_receipt_wire = provider_receipt.encode().unwrap();
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let next_state = verify_provider_commit_for_offhost_anchor(
            provider,
            initial,
            &record_wire,
            &provider_receipt_wire,
            &verifier,
        )
        .unwrap()
        .next_state;
        let request = ExternalCasOffhostAnchorCasRequest {
            challenge: [marker.wrapping_add(5); 32],
            operation_id,
            request_digest: write.request_digest,
            expected_sequence: initial.sequence,
            expected_state_digest: initial.digest().unwrap(),
            target_state_digest: next_state.digest().unwrap(),
        };
        (
            request,
            record_wire.to_vec(),
            provider_receipt_wire.to_vec(),
            next_state,
        )
    }

    #[test]
    fn qualified_qbt1_remote_state_survives_facade_rebuild_and_rejects_restored_snapshot() {
        let (provider, anchor, trust) = verified_test_fixture();
        let initial = trust.initial_anchor_state().clone();
        let runner = Arc::new(StatefulQualifiedAwsRunner::default());
        let deployment = deployment_pin();

        // Provision generation zero through the public qualified QBT1 adapter, then drop it.
        let bootstrap_store =
            AwsDynamoDbOffhostAnchorStore::with_qualified_verified_bootstrap_runner(
                runner.clone(),
                deployment.clone(),
                anchor.clone(),
                provider.clone(),
                &trust,
            )
            .unwrap();
        assert_eq!(
            bootstrap_store
                .provision_bootstrap_if_absent(&initial)
                .unwrap(),
            ExternalCasOffhostAnchorStoreProvisionOutcome::Provisioned
        );
        drop(bootstrap_store);

        // Compose the public QAR2 facade through the qualified AWS constructor, not the
        // cfg(test) local-model factory used in CP-0769.
        let facade = QAR2BoundAnchorService::with_qualified_aws_dynamodb(
            runner.clone(),
            deployment.clone(),
            anchor.clone(),
            provider.clone(),
            trust.clone(),
        )
        .unwrap();
        let (applied_request, applied_record, applied_receipt, applied_state) =
            signed_transition(&provider, &initial, 0xD1);
        let anchor_signer = AnchorSigner(portable::generate_key_pair([0x22; 32]).signing_key);
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let applied = facade
            .compare_and_swap(
                &applied_request,
                &applied_record,
                &applied_receipt,
                &verifier,
                &anchor_signer,
            )
            .unwrap();
        assert_eq!(
            applied
                .verify_cas(&trust, &anchor, &provider, &applied_request, &verifier)
                .unwrap(),
            (
                ExternalCasOffhostAnchorReceiptOutcome::Applied,
                applied_state.clone()
            )
        );
        drop(facade);

        // A separate, stale transaction is signed against the old generation-zero snapshot.
        let (stale_request, stale_record, stale_receipt, stale_state) =
            signed_transition(&provider, &initial, 0xE1);

        // A changed AWS caller identity must prevent the rebuilt facade from reaching DynamoDB.
        let before_identity_drift = runner.calls().len();
        runner.set_wrong_identity(true);
        let drifted = QAR2BoundAnchorService::with_qualified_aws_dynamodb(
            runner.clone(),
            deployment.clone(),
            anchor.clone(),
            provider.clone(),
            trust.clone(),
        );
        assert!(matches!(
            drifted,
            Err(OffhostAnchorProtocolError::Store(
                crate::external_cas_offhost_anchor_protocol_candidate::ExternalCasOffhostAnchorStoreError::Unavailable
            ))
        ));
        let drift_calls = runner.calls();
        assert_eq!(drift_calls.len(), before_identity_drift + 1);
        assert_eq!(drift_calls[before_identity_drift][0], "sts");
        assert_eq!(drift_calls[before_identity_drift][1], "get-caller-identity");
        runner.set_wrong_identity(false);

        // Rebuild after the simulated node-side rollback. The shared remote item remains at
        // sequence two; a fresh QAR2 read verifies that state from the new facade instance.
        let restored_facade = QAR2BoundAnchorService::with_qualified_aws_dynamodb(
            runner.clone(),
            deployment.clone(),
            anchor.clone(),
            provider.clone(),
            trust.clone(),
        )
        .unwrap();
        let read_request = ExternalCasOffhostAnchorReadRequest {
            challenge: [0xF1; 32],
            operation_id: [0xF2; 32],
            request_digest: [0xF3; 32],
        };
        let read_receipt = restored_facade.read(&read_request, &anchor_signer).unwrap();
        assert_eq!(
            read_receipt
                .verify_read(&trust, &anchor, &provider, &read_request, &verifier)
                .unwrap(),
            applied_state
        );

        // Replaying a different stale transaction through QAR2 returns the authoritative
        // remote state, never the stale client's predecessor snapshot.
        let replay_receipt = restored_facade
            .compare_and_swap(
                &stale_request,
                &stale_record,
                &stale_receipt,
                &verifier,
                &anchor_signer,
            )
            .unwrap();
        assert_eq!(
            replay_receipt
                .verify_cas(&trust, &anchor, &provider, &stale_request, &verifier)
                .unwrap(),
            (
                ExternalCasOffhostAnchorReceiptOutcome::Conflict,
                applied_state.clone()
            )
        );
        drop(restored_facade);

        // Also force the stale write through the DynamoDB adapter: its single conditional
        // PutItem must compare sequence, full state digest and all three immutable QBT1 fields.
        let stale_store = AwsDynamoDbOffhostAnchorStore::with_qualified_verified_bootstrap_runner(
            runner.clone(),
            deployment,
            anchor,
            provider.clone(),
            &trust,
        )
        .unwrap();
        let stale_outcome = stale_store
            .compare_and_swap_atomic(initial.sequence, &initial.digest().unwrap(), &stale_state)
            .unwrap();
        assert_eq!(
            stale_outcome,
            ExternalCasOffhostAnchorStoreCasOutcome::Conflict(applied_state.clone())
        );
        assert_eq!(stale_store.load_consistent().unwrap(), applied_state);
        let remote_item = runner.current_item().unwrap();
        assert_eq!(remote_item["sequence"]["N"], "2");
        drop(stale_store);

        let calls = runner.calls();
        assert_each_storage_operation_was_requalified(&calls);
        for call in calls.iter().filter(|call| {
            call.first().map(String::as_str) == Some("dynamodb")
                && call.get(1).map(String::as_str) == Some("put-item")
                && call
                    .iter()
                    .any(|arg| arg == "--expression-attribute-values")
        }) {
            let condition = argument_value(call, "--condition-expression");
            assert!(condition.contains("#bootstrap_trust_receipt_digest"));
            assert!(condition.contains("#bootstrap_initial_state_digest"));
            assert!(condition.contains("#bootstrap_trust_receipt_wire_b64"));
        }
    }
}
