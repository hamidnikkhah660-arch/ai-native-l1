//! CP-0481 service-side proof validation for a future QRun off-host monotonic anchor.
//!
//! This module validates Provider ECR1/ECS1 evidence before a remote Anchor storage adapter
//! may advance its high-water item. It deliberately contains no cloud SDK, persistence, network
//! listener, key provisioning, or runtime callsite. A production Anchor must wrap this verifier
//! with an independently administered atomic monotonic store and separately pinned signer.
use crate::{
    external_cas_anchor_candidate::{
        ExternalCasError, ExternalCasPin, ExternalCasReceipt, ExternalCasWriteRequest,
        EXTERNAL_CAS_RECEIPT_BYTES, EXTERNAL_CAS_RECORD_BYTES,
    },
    v4_fat1_trust_candidate::MlDsa65Verifier,
};
use sha2::{Digest, Sha256};
use std::fmt;

type Digest32 = [u8; 32];

const ANCHOR_STATE_DIGEST_DOMAIN: &[u8] = b"QRUN-OFFHOST-ANCHOR-STATE-V1\0";
const PROVIDER_RECEIPT_DIGEST_DOMAIN: &[u8] = b"QRUN-OFFHOST-ANCHOR-PROVIDER-RECEIPT-V1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalCasOffhostAnchorError {
    Contract(ExternalCasError),
    InvalidBootstrap,
    InvalidAnchorState,
    ProviderObjectGenerationGap,
    AnchorSequenceOverflow,
    AnchorStateConflict,
}
impl fmt::Display for ExternalCasOffhostAnchorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ExternalCasOffhostAnchorError {}
impl From<ExternalCasError> for ExternalCasOffhostAnchorError {
    fn from(value: ExternalCasError) -> Self {
        Self::Contract(value)
    }
}

/// Complete authoritative high-water state for one Provider/Network/Genesis pin.
/// Sequence starts at one for the generation-zero bootstrap and advances once per ECR1
/// successor. Provider object generation starts at one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalCasOffhostAnchorState {
    pub sequence: u64,
    pub provider_record: crate::external_cas_anchor_candidate::ExternalCasRecord,
    pub provider_object_generation: u64,
    /// Last accepted Provider operation. Zero only for the explicit generation-zero bootstrap.
    pub last_operation_id: Digest32,
    pub last_request_digest: Digest32,
    /// Digest of the first accepted signed ECS1 commit receipt; retries never replace it.
    pub last_provider_receipt_digest: Digest32,
    /// Exact Anchor predecessor used by the last successful CAS; retained for retry binding.
    pub last_expected_anchor_sequence: u64,
    pub last_expected_anchor_state_digest: Digest32,
}
impl ExternalCasOffhostAnchorState {
    /// Explicit provisioning only. A remote service must not call this on first read.
    pub fn provision_bootstrap(
        pin: &ExternalCasPin,
        bootstrap: crate::external_cas_anchor_candidate::ExternalCasRecord,
        provider_object_generation: u64,
    ) -> Result<Self, ExternalCasOffhostAnchorError> {
        pin.validate()?;
        if bootstrap.generation != 0 || provider_object_generation != 1 {
            return Err(ExternalCasOffhostAnchorError::InvalidBootstrap);
        }
        let state = Self {
            sequence: 1,
            provider_record: bootstrap,
            provider_object_generation,
            last_operation_id: [0; 32],
            last_request_digest: [0; 32],
            last_provider_receipt_digest: [0; 32],
            last_expected_anchor_sequence: 0,
            last_expected_anchor_state_digest: [0; 32],
        };
        state.validate(pin)?;
        Ok(state)
    }

    pub fn validate(&self, pin: &ExternalCasPin) -> Result<(), ExternalCasOffhostAnchorError> {
        pin.validate()?;
        self.provider_record.validate_shape()?;
        if self.provider_record.provider_id != pin.provider_id
            || self.provider_record.network_id != pin.network_id
            || self.provider_record.genesis_digest != pin.genesis_digest
        {
            return Err(ExternalCasOffhostAnchorError::InvalidAnchorState);
        }
        let expected = self
            .provider_record
            .generation
            .checked_add(1)
            .ok_or(ExternalCasOffhostAnchorError::AnchorSequenceOverflow)?;
        if self.sequence != expected || self.provider_object_generation != expected {
            return Err(ExternalCasOffhostAnchorError::InvalidAnchorState);
        }
        if self.provider_record.generation == 0 {
            if self.last_operation_id != [0; 32]
                || self.last_request_digest != [0; 32]
                || self.last_provider_receipt_digest != [0; 32]
                || self.last_expected_anchor_sequence != 0
                || self.last_expected_anchor_state_digest != [0; 32]
            {
                return Err(ExternalCasOffhostAnchorError::InvalidAnchorState);
            }
        } else if self.last_operation_id != self.provider_record.operation_id
            || self.last_request_digest != self.provider_record.request_digest
            || self.last_operation_id == [0; 32]
            || self.last_request_digest == [0; 32]
            || self.last_provider_receipt_digest == [0; 32]
            || self.last_expected_anchor_sequence.checked_add(1) != Some(self.sequence)
            || self.last_expected_anchor_state_digest == [0; 32]
        {
            return Err(ExternalCasOffhostAnchorError::InvalidAnchorState);
        }
        Ok(())
    }

    /// Digest all fields that a backing store must compare atomically.
    pub fn digest(&self) -> Result<Digest32, ExternalCasOffhostAnchorError> {
        let record = self.provider_record.encode()?;
        let mut hasher = Sha256::new();
        hasher.update(ANCHOR_STATE_DIGEST_DOMAIN);
        hasher.update(self.sequence.to_be_bytes());
        hasher.update(self.provider_object_generation.to_be_bytes());
        hasher.update(record);
        hasher.update(self.last_operation_id);
        hasher.update(self.last_request_digest);
        hasher.update(self.last_provider_receipt_digest);
        hasher.update(self.last_expected_anchor_sequence.to_be_bytes());
        hasher.update(self.last_expected_anchor_state_digest);
        Ok(hasher.finalize().into())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalCasOffhostAnchorOutcome {
    Advance,
    AlreadyApplied,
}

/// Result of independently validating a Provider commit proof.
/// A real Anchor storage adapter may persist next_state only with an atomic conditional write
/// against the exact previously loaded sequence and state digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedExternalCasOffhostAnchorAdvance {
    pub outcome: ExternalCasOffhostAnchorOutcome,
    pub next_state: ExternalCasOffhostAnchorState,
    pub operation_id: Digest32,
    pub request_digest: Digest32,
    pub provider_receipt_digest: Digest32,
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> Digest32 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Reconstructs the exact Provider write request from its ECR1 successor and signed ECS1
/// receipt, then independently verifies the Provider ML-DSA-65 signature and exact high-water
/// transition. This is intended to run inside the off-host Anchor service, not only in the node.
///
/// The caller must still perform an atomic remote CAS against current.sequence and current.digest().
/// This pure verifier is not a monotonic store and is not anti-rollback protection if its caller
/// persists state in a rollbackable local directory.
pub fn verify_provider_commit_for_offhost_anchor<V: MlDsa65Verifier>(
    pin: &ExternalCasPin,
    current: &ExternalCasOffhostAnchorState,
    next_record_bytes: &[u8],
    provider_receipt_bytes: &[u8],
    verifier: &V,
) -> Result<VerifiedExternalCasOffhostAnchorAdvance, ExternalCasOffhostAnchorError> {
    current.validate(pin)?;
    if next_record_bytes.len() != EXTERNAL_CAS_RECORD_BYTES {
        return Err(ExternalCasError::WrongRecordLength.into());
    }
    if provider_receipt_bytes.len() != EXTERNAL_CAS_RECEIPT_BYTES {
        return Err(ExternalCasError::WrongReceiptLength.into());
    }

    let next_record =
        crate::external_cas_anchor_candidate::ExternalCasRecord::decode(next_record_bytes)?;
    let receipt = ExternalCasReceipt::decode(provider_receipt_bytes)?;

    // A retry after Anchor commit must reconstruct the original predecessor from ECR1/ECS1;
    // a first-time advance must reconstruct it from the trusted current Anchor state. Never
    // accept a caller-selected precondition for either case.
    let already_applied = current.provider_record == next_record
        && current.provider_object_generation == receipt.object_generation;
    let (
        expected_generation,
        expected_object_generation,
        expected_record_digest,
        expected_state_digest,
    ) = if already_applied {
        (
            next_record
                .generation
                .checked_sub(1)
                .ok_or(ExternalCasOffhostAnchorError::AnchorStateConflict)?,
            receipt
                .object_generation
                .checked_sub(1)
                .ok_or(ExternalCasOffhostAnchorError::ProviderObjectGenerationGap)?,
            next_record.previous_record_digest,
            next_record.previous_state_digest,
        )
    } else {
        (
            current.provider_record.generation,
            current.provider_object_generation,
            current.provider_record.digest()?,
            current.provider_record.next_state_digest,
        )
    };

    let request = ExternalCasWriteRequest {
        request_nonce: receipt.request_nonce,
        operation_id: receipt.operation_id,
        request_digest: receipt.request_digest,
        expected_generation,
        expected_object_generation,
        expected_record_digest,
        expected_state_digest,
        next_record: next_record.clone(),
    };

    // Checks the exact request digest, ECR1/ECS1 bindings, Provider pin and signature.
    receipt.verify_commit(pin, &request, verifier)?;

    let encoded_receipt = receipt.encode()?;
    let provider_receipt_digest = domain_hash(PROVIDER_RECEIPT_DIGEST_DOMAIN, &encoded_receipt);

    // A lost Anchor response can be retried with the same Provider proof. Accept idempotency
    // only while the exact target remains the current high-water state.
    if current.provider_record == next_record
        && current.provider_object_generation == receipt.object_generation
    {
        if current.last_operation_id != receipt.operation_id
            || current.last_request_digest != receipt.request_digest
            || current.last_provider_receipt_digest == [0; 32]
        {
            return Err(ExternalCasOffhostAnchorError::AnchorStateConflict);
        }
        return Ok(VerifiedExternalCasOffhostAnchorAdvance {
            outcome: ExternalCasOffhostAnchorOutcome::AlreadyApplied,
            next_state: current.clone(),
            operation_id: receipt.operation_id,
            request_digest: receipt.request_digest,
            provider_receipt_digest,
        });
    }

    current.provider_record.validate_successor(&next_record)?;
    let expected_object_generation = current
        .provider_object_generation
        .checked_add(1)
        .ok_or(ExternalCasOffhostAnchorError::ProviderObjectGenerationGap)?;
    if receipt.object_generation != expected_object_generation {
        return Err(ExternalCasOffhostAnchorError::ProviderObjectGenerationGap);
    }
    let sequence = current
        .sequence
        .checked_add(1)
        .ok_or(ExternalCasOffhostAnchorError::AnchorSequenceOverflow)?;
    let next_state = ExternalCasOffhostAnchorState {
        sequence,
        provider_record: next_record,
        provider_object_generation: receipt.object_generation,
        last_operation_id: receipt.operation_id,
        last_request_digest: receipt.request_digest,
        last_provider_receipt_digest: provider_receipt_digest,
        last_expected_anchor_sequence: current.sequence,
        last_expected_anchor_state_digest: current.digest()?,
    };
    next_state.validate(pin)?;

    Ok(VerifiedExternalCasOffhostAnchorAdvance {
        outcome: ExternalCasOffhostAnchorOutcome::Advance,
        operation_id: receipt.operation_id,
        request_digest: receipt.request_digest,
        provider_receipt_digest,
        next_state,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::external_cas_anchor_candidate::{
        ExternalCasPin, ExternalCasReceipt, ExternalCasReceiptKind, ExternalCasReceiptOutcome,
        ExternalCasRecord, ExternalCasWriteRequest,
    };
    use crate::v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate;
    use libcrux_ml_dsa::ml_dsa_65::portable;
    use std::sync::Arc;

    struct Fixture {
        pin: ExternalCasPin,
        bootstrap: ExternalCasRecord,
        signing_key: Arc<libcrux_ml_dsa::ml_dsa_65::MLDSA65SigningKey>,
    }

    fn fixture() -> Fixture {
        let keys = portable::generate_key_pair([0xC1; 32]);
        let public_key: [u8; crate::v4_fat1_trust_candidate::ML_DSA_65_PUBLIC_KEY_BYTES] =
            *keys.verification_key.as_ref();
        let pin = ExternalCasPin {
            provider_id: [0x11; 32],
            network_id: [0x22; 32],
            genesis_digest: [0x33; 32],
            receipt_key_id: [0x44; 32],
            receipt_public_key: public_key,
        };
        let bootstrap = ExternalCasRecord {
            generation: 0,
            provider_id: pin.provider_id,
            network_id: pin.network_id,
            genesis_digest: pin.genesis_digest,
            previous_record_digest: [0; 32],
            previous_state_digest: [0; 32],
            next_state_digest: [0x55; 32],
            operation_id: [0x66; 32],
            request_digest: [0x77; 32],
        };
        Fixture {
            pin,
            bootstrap,
            signing_key: Arc::new(keys.signing_key),
        }
    }

    fn write_request(
        fixture: &Fixture,
        nonce: u8,
        operation: u8,
        next_state: u8,
    ) -> ExternalCasWriteRequest {
        let mut request = ExternalCasWriteRequest {
            request_nonce: [nonce; 32],
            operation_id: [operation; 32],
            request_digest: [1; 32],
            expected_generation: 0,
            expected_object_generation: 1,
            expected_record_digest: fixture.bootstrap.digest().unwrap(),
            expected_state_digest: fixture.bootstrap.next_state_digest,
            next_record: ExternalCasRecord {
                generation: 1,
                provider_id: fixture.pin.provider_id,
                network_id: fixture.pin.network_id,
                genesis_digest: fixture.pin.genesis_digest,
                previous_record_digest: fixture.bootstrap.digest().unwrap(),
                previous_state_digest: fixture.bootstrap.next_state_digest,
                next_state_digest: [next_state; 32],
                operation_id: [operation; 32],
                request_digest: [1; 32],
            },
        };
        request.bind_request_digest(&fixture.pin).unwrap();
        request
    }

    fn signed_receipt(
        fixture: &Fixture,
        request: &ExternalCasWriteRequest,
        object_generation: u64,
        outcome: ExternalCasReceiptOutcome,
    ) -> ExternalCasReceipt {
        let mut receipt = ExternalCasReceipt {
            kind: ExternalCasReceiptKind::Commit,
            outcome,
            generation: request.next_record.generation,
            object_generation,
            provider_id: fixture.pin.provider_id,
            network_id: fixture.pin.network_id,
            genesis_digest: fixture.pin.genesis_digest,
            receipt_key_id: fixture.pin.receipt_key_id,
            request_nonce: request.request_nonce,
            record_digest: request.next_record.digest().unwrap(),
            previous_record_digest: request.next_record.previous_record_digest,
            previous_state_digest: request.next_record.previous_state_digest,
            state_digest: request.next_record.next_state_digest,
            operation_id: request.operation_id,
            request_digest: request.request_digest,
            signature: [0; crate::v4_fat1_trust_candidate::ML_DSA_65_SIGNATURE_BYTES],
        };
        let digest = receipt.signing_digest().unwrap();
        let signature =
            portable::sign(fixture.signing_key.as_ref(), &digest, &[], [0xC2; 32]).unwrap();
        receipt.signature = *signature.as_ref();
        receipt
    }

    fn bootstrap_state(fixture: &Fixture) -> ExternalCasOffhostAnchorState {
        ExternalCasOffhostAnchorState::provision_bootstrap(
            &fixture.pin,
            fixture.bootstrap.clone(),
            1,
        )
        .unwrap()
    }

    #[test]
    fn anchor_accepts_only_a_provider_signed_exact_successor() {
        let fixture = fixture();
        let current = bootstrap_state(&fixture);
        let request = write_request(&fixture, 0xA1, 0xA2, 0xA3);
        let receipt = signed_receipt(&fixture, &request, 2, ExternalCasReceiptOutcome::Applied);
        let verified = verify_provider_commit_for_offhost_anchor(
            &fixture.pin,
            &current,
            &request.next_record.encode().unwrap(),
            &receipt.encode().unwrap(),
            &LibcruxMlDsa65VerifierCandidate,
        )
        .unwrap();

        assert_eq!(verified.outcome, ExternalCasOffhostAnchorOutcome::Advance);
        assert_eq!(verified.next_state.sequence, 2);
        assert_eq!(verified.next_state.provider_record, request.next_record);
        assert_eq!(verified.next_state.provider_object_generation, 2);
        assert_eq!(verified.operation_id, request.operation_id);
        assert_eq!(verified.request_digest, request.request_digest);
        assert_eq!(verified.next_state.last_operation_id, request.operation_id);
        assert_eq!(
            verified.next_state.last_request_digest,
            request.request_digest
        );
        assert_eq!(
            verified.next_state.last_provider_receipt_digest,
            verified.provider_receipt_digest
        );
    }

    #[test]
    fn anchor_rejects_a_forged_provider_receipt_signature() {
        let fixture = fixture();
        let current = bootstrap_state(&fixture);
        let request = write_request(&fixture, 0xA4, 0xA5, 0xA6);
        let mut receipt = signed_receipt(&fixture, &request, 2, ExternalCasReceiptOutcome::Applied);
        receipt.signature[0] ^= 0x80;

        assert_eq!(
            verify_provider_commit_for_offhost_anchor(
                &fixture.pin,
                &current,
                &request.next_record.encode().unwrap(),
                &receipt.encode().unwrap(),
                &LibcruxMlDsa65VerifierCandidate,
            ),
            Err(ExternalCasOffhostAnchorError::Contract(
                ExternalCasError::InvalidSignature
            ))
        );
    }

    #[test]
    fn anchor_rejects_provider_object_generation_skips() {
        let fixture = fixture();
        let current = bootstrap_state(&fixture);
        let request = write_request(&fixture, 0xA7, 0xA8, 0xA9);
        let receipt = signed_receipt(&fixture, &request, 3, ExternalCasReceiptOutcome::Applied);

        assert_eq!(
            verify_provider_commit_for_offhost_anchor(
                &fixture.pin,
                &current,
                &request.next_record.encode().unwrap(),
                &receipt.encode().unwrap(),
                &LibcruxMlDsa65VerifierCandidate,
            ),
            Err(ExternalCasOffhostAnchorError::ProviderObjectGenerationGap)
        );
    }

    #[test]
    fn exact_retry_after_anchor_commit_is_idempotent_but_not_a_second_advance() {
        let fixture = fixture();
        let current = bootstrap_state(&fixture);
        let request = write_request(&fixture, 0xAA, 0xAB, 0xAC);
        let receipt = signed_receipt(&fixture, &request, 2, ExternalCasReceiptOutcome::Applied);
        let advanced = verify_provider_commit_for_offhost_anchor(
            &fixture.pin,
            &current,
            &request.next_record.encode().unwrap(),
            &receipt.encode().unwrap(),
            &LibcruxMlDsa65VerifierCandidate,
        )
        .unwrap()
        .next_state;

        let retry_receipt = signed_receipt(
            &fixture,
            &request,
            2,
            ExternalCasReceiptOutcome::AlreadyApplied,
        );
        let retried = verify_provider_commit_for_offhost_anchor(
            &fixture.pin,
            &advanced,
            &request.next_record.encode().unwrap(),
            &retry_receipt.encode().unwrap(),
            &LibcruxMlDsa65VerifierCandidate,
        )
        .unwrap();
        assert_eq!(
            retried.outcome,
            ExternalCasOffhostAnchorOutcome::AlreadyApplied
        );
        assert_eq!(retried.next_state, advanced);
    }

    #[test]
    fn anchor_rejects_wrong_network_genesis_and_same_generation_equivocation() {
        let fixture = fixture();
        let current = bootstrap_state(&fixture);
        let request = write_request(&fixture, 0xAD, 0xAE, 0xAF);
        let mut wrong_domain_record = request.next_record.clone();
        wrong_domain_record.genesis_digest[0] ^= 1;
        assert!(verify_provider_commit_for_offhost_anchor(
            &fixture.pin,
            &current,
            &wrong_domain_record.encode().unwrap(),
            &signed_receipt(&fixture, &request, 2, ExternalCasReceiptOutcome::Applied,)
                .encode()
                .unwrap(),
            &LibcruxMlDsa65VerifierCandidate,
        )
        .is_err());

        let first_receipt =
            signed_receipt(&fixture, &request, 2, ExternalCasReceiptOutcome::Applied);
        let advanced = verify_provider_commit_for_offhost_anchor(
            &fixture.pin,
            &current,
            &request.next_record.encode().unwrap(),
            &first_receipt.encode().unwrap(),
            &LibcruxMlDsa65VerifierCandidate,
        )
        .unwrap()
        .next_state;

        // A competing sibling can have the same old parent, but after the first sibling is
        // anchored it is no longer a successor of the trusted current high-water state.
        let competing_request = write_request(&fixture, 0xB1, 0xB2, 0xB3);
        let competing_receipt = signed_receipt(
            &fixture,
            &competing_request,
            2,
            ExternalCasReceiptOutcome::Applied,
        );
        assert!(verify_provider_commit_for_offhost_anchor(
            &fixture.pin,
            &advanced,
            &competing_request.next_record.encode().unwrap(),
            &competing_receipt.encode().unwrap(),
            &LibcruxMlDsa65VerifierCandidate,
        )
        .is_err());
    }

    #[test]
    fn anchor_state_rejects_mismatched_last_operation_metadata() {
        let fixture = fixture();
        let bootstrap = bootstrap_state(&fixture);
        let request = write_request(&fixture, 0xD1, 0xD2, 0xD3);
        let receipt = signed_receipt(&fixture, &request, 2, ExternalCasReceiptOutcome::Applied);
        let mut advanced = verify_provider_commit_for_offhost_anchor(
            &fixture.pin,
            &bootstrap,
            &request.next_record.encode().unwrap(),
            &receipt.encode().unwrap(),
            &LibcruxMlDsa65VerifierCandidate,
        )
        .unwrap()
        .next_state;
        advanced.last_operation_id[0] ^= 1;
        assert_eq!(
            advanced.validate(&fixture.pin),
            Err(ExternalCasOffhostAnchorError::InvalidAnchorState)
        );
    }

    #[test]
    fn anchor_state_digest_binds_sequence_object_generation_and_full_ecr1_bytes() {
        let fixture = fixture();
        let state = bootstrap_state(&fixture);
        let baseline = state.digest().unwrap();
        let mut changed = state.clone();
        changed.sequence += 1;
        assert_ne!(baseline, changed.digest().unwrap());
        let mut changed = state.clone();
        changed.provider_object_generation += 1;
        assert_ne!(baseline, changed.digest().unwrap());
        let mut changed = state.clone();
        changed.provider_record.next_state_digest[0] ^= 1;
        assert_ne!(baseline, changed.digest().unwrap());
        let mut changed = state.clone();
        changed.last_operation_id[0] ^= 1;
        assert_ne!(baseline, changed.digest().unwrap());
        let mut changed = state.clone();
        changed.last_request_digest[0] ^= 1;
        assert_ne!(baseline, changed.digest().unwrap());
        let mut changed = state.clone();
        changed.last_provider_receipt_digest[0] ^= 1;
        assert_ne!(baseline, changed.digest().unwrap());
        let mut changed = state.clone();
        changed.last_expected_anchor_sequence ^= 1;
        assert_ne!(baseline, changed.digest().unwrap());
        let mut changed = state;
        changed.last_expected_anchor_state_digest[0] ^= 1;
        assert_ne!(baseline, changed.digest().unwrap());
    }
}
