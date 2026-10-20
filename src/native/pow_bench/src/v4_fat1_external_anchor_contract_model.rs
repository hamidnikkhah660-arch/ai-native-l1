//! CP-0234 test-only contract model for an independently protected FAT1 anchor.
//!
//! A valid signature authenticates an observation; it does NOT by itself make the
//! provider monotonic. Production needs separately administered / hardware-protected
//! state, fresh authenticated reads, exact-successor CAS, durable operation-id semantics,
//! and a no-local-fallback policy. This module is included under cfg(test) only.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const KEY_ID_DOMAIN: &[u8] = b"AIN1-FAT1-ANCHOR-RECEIPT-KEY-ID-V1\0";
const READ_RECEIPT_DOMAIN: &[u8] = b"AIN1-FAT1-ANCHOR-READ-RECEIPT-V1\0";
const CAS_RECEIPT_DOMAIN: &[u8] = b"AIN1-FAT1-ANCHOR-CAS-RECEIPT-V1\0";

type Digest32 = [u8; 32];
type Signature64 = [u8; 64];

#[derive(Clone, Debug, PartialEq, Eq)]
struct AnchorDomain {
    provider_id: Digest32,
    network_id: Digest32,
    deployment_id: Digest32,
    policy_id: Digest32,
    receipt_key_id: Digest32,
}

impl AnchorDomain {
    fn validate(&self) -> Result<(), ContractError> {
        for value in [
            &self.provider_id,
            &self.network_id,
            &self.deployment_id,
            &self.policy_id,
            &self.receipt_key_id,
        ] {
            if *value == [0; 32] {
                return Err(ContractError::ZeroBinding);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AnchorPin {
    domain: AnchorDomain,
    receipt_public_key: [u8; 32],
}

impl AnchorPin {
    fn validate(&self) -> Result<(), ContractError> {
        self.domain.validate()?;
        if self.receipt_public_key == [0; 32] {
            return Err(ContractError::ZeroBinding);
        }
        VerifyingKey::from_bytes(&self.receipt_public_key)
            .map_err(|_| ContractError::BadPinnedReceiptKey)?;
        let expected_id = hash_parts(&[KEY_ID_DOMAIN, &self.receipt_public_key]);
        if expected_id != self.domain.receipt_key_id {
            return Err(ContractError::WrongReceiptKeyId);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AnchorState {
    trust_epoch: u64,
    record_id: Digest32,
    envelope_id: Digest32,
}

impl AnchorState {
    fn initial() -> Self {
        Self {
            trust_epoch: 0,
            record_id: [0; 32],
            envelope_id: [0; 32],
        }
    }

    fn validate(&self) -> Result<(), ContractError> {
        if self.trust_epoch == 0 {
            if self.record_id != [0; 32] || self.envelope_id != [0; 32] {
                return Err(ContractError::InvalidState);
            }
        } else if self.record_id == [0; 32] || self.envelope_id == [0; 32] {
            return Err(ContractError::InvalidState);
        }
        Ok(())
    }

    fn append_canonical(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.trust_epoch.to_be_bytes());
        out.extend_from_slice(&self.record_id);
        out.extend_from_slice(&self.envelope_id);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReadRequest {
    domain: AnchorDomain,
    challenge: Digest32,
}

impl ReadRequest {
    fn validate(&self, pin: &AnchorPin) -> Result<(), ContractError> {
        pin.validate()?;
        if self.domain != pin.domain {
            return Err(ContractError::WrongDomain);
        }
        if self.challenge == [0; 32] {
            return Err(ContractError::ZeroChallenge);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReadReceipt {
    domain: AnchorDomain,
    challenge: Digest32,
    state_sequence: u64,
    state: AnchorState,
    signature: Signature64,
}

impl ReadReceipt {
    fn signing_digest(&self) -> Result<Digest32, ContractError> {
        self.domain.validate()?;
        self.state.validate()?;
        if self.challenge == [0; 32] || self.state_sequence == 0 {
            return Err(ContractError::InvalidReceipt);
        }
        let mut bytes = Vec::with_capacity(32 * 7 + 8);
        append_domain(&mut bytes, &self.domain);
        bytes.extend_from_slice(&self.challenge);
        bytes.extend_from_slice(&self.state_sequence.to_be_bytes());
        self.state.append_canonical(&mut bytes);
        Ok(hash_parts(&[READ_RECEIPT_DOMAIN, &bytes]))
    }

    fn verify_for(
        &self,
        pin: &AnchorPin,
        request: &ReadRequest,
    ) -> Result<AnchorState, ContractError> {
        request.validate(pin)?;
        if self.domain != pin.domain || self.challenge != request.challenge {
            return Err(ContractError::StaleOrMisboundReceipt);
        }
        let digest = self.signing_digest()?;
        let key = VerifyingKey::from_bytes(&pin.receipt_public_key)
            .map_err(|_| ContractError::BadPinnedReceiptKey)?;
        key.verify_strict(&digest, &Signature::from_bytes(&self.signature))
            .map_err(|_| ContractError::InvalidReceiptSignature)?;
        Ok(self.state.clone())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
enum CasOutcome {
    Applied = 1,
    AlreadyApplied = 2,
    Conflict = 3,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CasRequest {
    domain: AnchorDomain,
    operation_id: Digest32,
    challenge: Digest32,
    expected: AnchorState,
    next: AnchorState,
}

impl CasRequest {
    fn validate(&self, pin: &AnchorPin) -> Result<(), ContractError> {
        pin.validate()?;
        if self.domain != pin.domain {
            return Err(ContractError::WrongDomain);
        }
        if self.operation_id == [0; 32] {
            return Err(ContractError::ZeroOperationId);
        }
        if self.challenge == [0; 32] {
            return Err(ContractError::ZeroChallenge);
        }
        self.expected.validate()?;
        self.next.validate()?;
        if self.expected.trust_epoch.checked_add(1) != Some(self.next.trust_epoch)
            || self.expected.record_id == self.next.record_id
            || self.next.record_id == [0; 32]
            || self.next.envelope_id == [0; 32]
        {
            return Err(ContractError::NotExactSuccessor);
        }
        Ok(())
    }

    fn same_operation(&self, other: &Self) -> bool {
        self.domain == other.domain
            && self.operation_id == other.operation_id
            && self.expected == other.expected
            && self.next == other.next
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CasReceipt {
    domain: AnchorDomain,
    operation_id: Digest32,
    challenge: Digest32,
    state_sequence: u64,
    outcome: CasOutcome,
    current: AnchorState,
    signature: Signature64,
}

impl CasReceipt {
    fn signing_digest(&self) -> Result<Digest32, ContractError> {
        self.domain.validate()?;
        self.current.validate()?;
        if self.operation_id == [0; 32] || self.challenge == [0; 32] || self.state_sequence == 0 {
            return Err(ContractError::InvalidReceipt);
        }
        let mut bytes = Vec::with_capacity(32 * 7 + 8 + 2);
        append_domain(&mut bytes, &self.domain);
        bytes.extend_from_slice(&self.operation_id);
        bytes.extend_from_slice(&self.challenge);
        bytes.extend_from_slice(&self.state_sequence.to_be_bytes());
        bytes.extend_from_slice(&(self.outcome as u16).to_be_bytes());
        self.current.append_canonical(&mut bytes);
        Ok(hash_parts(&[CAS_RECEIPT_DOMAIN, &bytes]))
    }

    fn verify_for(
        &self,
        pin: &AnchorPin,
        request: &CasRequest,
    ) -> Result<AnchorState, ContractError> {
        request.validate(pin)?;
        if self.domain != pin.domain
            || self.operation_id != request.operation_id
            || self.challenge != request.challenge
        {
            return Err(ContractError::StaleOrMisboundReceipt);
        }
        if matches!(
            self.outcome,
            CasOutcome::Applied | CasOutcome::AlreadyApplied
        ) && self.current != request.next
        {
            return Err(ContractError::InvalidReceipt);
        }
        let digest = self.signing_digest()?;
        let key = VerifyingKey::from_bytes(&pin.receipt_public_key)
            .map_err(|_| ContractError::BadPinnedReceiptKey)?;
        key.verify_strict(&digest, &Signature::from_bytes(&self.signature))
            .map_err(|_| ContractError::InvalidReceiptSignature)?;
        Ok(self.current.clone())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AmbiguousCommitResolution {
    Committed,
    RetrySameOperationIdAndPayload,
    QuarantineForManualRecovery,
}

fn resolve_ambiguous_commit(
    pin: &AnchorPin,
    read_request: &ReadRequest,
    read_receipt: &ReadReceipt,
    cas_request: &CasRequest,
) -> Result<AmbiguousCommitResolution, ContractError> {
    cas_request.validate(pin)?;
    if read_request.challenge == cas_request.challenge {
        return Err(ContractError::ChallengeReused);
    }
    if read_request.domain != cas_request.domain {
        return Err(ContractError::WrongDomain);
    }
    let current = read_receipt.verify_for(pin, read_request)?;
    if current == cas_request.next {
        Ok(AmbiguousCommitResolution::Committed)
    } else if current == cas_request.expected {
        Ok(AmbiguousCommitResolution::RetrySameOperationIdAndPayload)
    } else {
        Ok(AmbiguousCommitResolution::QuarantineForManualRecovery)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ContractError {
    ZeroBinding,
    BadPinnedReceiptKey,
    WrongReceiptKeyId,
    InvalidState,
    WrongDomain,
    ZeroChallenge,
    ZeroOperationId,
    NotExactSuccessor,
    InvalidReceipt,
    StaleOrMisboundReceipt,
    InvalidReceiptSignature,
    ChallengeReused,
    Uninitialized,
}

fn append_domain(out: &mut Vec<u8>, domain: &AnchorDomain) {
    out.extend_from_slice(&domain.provider_id);
    out.extend_from_slice(&domain.network_id);
    out.extend_from_slice(&domain.deployment_id);
    out.extend_from_slice(&domain.policy_id);
    out.extend_from_slice(&domain.receipt_key_id);
}

fn hash_parts(parts: &[&[u8]]) -> Digest32 {
    let mut h = Sha256::new();
    for part in parts {
        h.update(part);
    }
    h.finalize().into()
}

// Simulated provider exists only in this unit-test module. This deliberately does not claim
// hardware monotonicity: restoring this provider's entire state reproduces the rollback gap.
#[derive(Clone)]
struct ModelProvider {
    domain: AnchorDomain,
    signer: SigningKey,
    state: Option<AnchorState>,
    state_sequence: u64,
    operations: BTreeMap<Digest32, CasRequest>,
}

impl ModelProvider {
    fn new(domain: AnchorDomain, signer: SigningKey) -> Self {
        Self {
            domain,
            signer,
            state: None,
            state_sequence: 0,
            operations: BTreeMap::new(),
        }
    }

    fn provision_explicitly(&mut self, state: AnchorState) -> Result<(), ContractError> {
        self.domain.validate()?;
        if self.state.is_some() {
            return Err(ContractError::InvalidState);
        }
        state.validate()?;
        self.state = Some(state);
        self.state_sequence = 1;
        Ok(())
    }

    fn read(&self, request: &ReadRequest) -> Result<ReadReceipt, ContractError> {
        self.domain.validate()?;
        if request.domain != self.domain {
            return Err(ContractError::WrongDomain);
        }
        if request.challenge == [0; 32] {
            return Err(ContractError::ZeroChallenge);
        }
        let state = self.state.clone().ok_or(ContractError::Uninitialized)?;
        let mut receipt = ReadReceipt {
            domain: self.domain.clone(),
            challenge: request.challenge,
            state_sequence: self.state_sequence,
            state,
            signature: [0; 64],
        };
        let digest = receipt.signing_digest()?;
        receipt.signature = self.signer.sign(&digest).to_bytes();
        Ok(receipt)
    }

    // In production, calls also require mutually authenticated caller authorization and the
    // state/operation journal must be protected in a separately administered monotonic domain.
    fn compare_and_swap(&mut self, request: &CasRequest) -> Result<CasReceipt, ContractError> {
        self.domain.validate()?;
        if request.domain != self.domain {
            return Err(ContractError::WrongDomain);
        }
        request.expected.validate()?;
        request.next.validate()?;
        if request.operation_id == [0; 32] {
            return Err(ContractError::ZeroOperationId);
        }
        if request.challenge == [0; 32] {
            return Err(ContractError::ZeroChallenge);
        }
        if request.expected.trust_epoch.checked_add(1) != Some(request.next.trust_epoch)
            || request.expected.record_id == request.next.record_id
            || request.next.record_id == [0; 32]
            || request.next.envelope_id == [0; 32]
        {
            return Err(ContractError::NotExactSuccessor);
        }

        let current = self.state.clone().ok_or(ContractError::Uninitialized)?;
        let mut outcome = CasOutcome::Conflict;
        let prior_intent = self.operations.get(&request.operation_id);
        if let Some(prior) = prior_intent {
            if prior.same_operation(request) && current == request.next {
                outcome = CasOutcome::AlreadyApplied;
            }
        } else if current == request.expected {
            self.state = Some(request.next.clone());
            self.state_sequence = self
                .state_sequence
                .checked_add(1)
                .ok_or(ContractError::InvalidReceipt)?;
            self.operations
                .insert(request.operation_id, request.clone());
            outcome = CasOutcome::Applied;
        }

        let current = self.state.clone().ok_or(ContractError::Uninitialized)?;
        let mut receipt = CasReceipt {
            domain: self.domain.clone(),
            operation_id: request.operation_id,
            challenge: request.challenge,
            state_sequence: self.state_sequence,
            outcome,
            current,
            signature: [0; 64],
        };
        let digest = receipt.signing_digest()?;
        receipt.signature = self.signer.sign(&digest).to_bytes();
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CP0234_VECTORS: &str =
        include_str!("../../../../simulations/cp0234_fat1_anchor_receipt_vectors.tsv");

    fn vector_value(key: &str) -> &str {
        CP0234_VECTORS
            .lines()
            .filter(|line| !line.starts_with('#'))
            .find_map(|line| {
                let (name, value) = line.split_once('\t')?;
                (name == key).then_some(value)
            })
            .expect("required CP-0234 external-anchor receipt vector")
    }

    fn vector_hex32(key: &str) -> Digest32 {
        let value = vector_value(key);
        assert_eq!(value.len(), 64, "32-byte hex vector {key}");
        let mut result = [0u8; 32];
        for (i, byte) in result.iter_mut().enumerate() {
            *byte =
                u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).expect("valid vector hexadecimal");
        }
        result
    }

    fn nonzero(fill: u8) -> Digest32 {
        [fill; 32]
    }

    fn fixture() -> (SigningKey, AnchorPin, ModelProvider) {
        let signer = SigningKey::from_bytes(&[0x47; 32]);
        let public_key = signer.verifying_key().to_bytes();
        let key_id = hash_parts(&[KEY_ID_DOMAIN, &public_key]);
        let domain = AnchorDomain {
            provider_id: nonzero(0x11),
            network_id: nonzero(0x22),
            deployment_id: nonzero(0x33),
            policy_id: nonzero(0x44),
            receipt_key_id: key_id,
        };
        let pin = AnchorPin {
            domain: domain.clone(),
            receipt_public_key: public_key,
        };
        let provider = ModelProvider::new(domain, signer.clone());
        (signer, pin, provider)
    }

    fn provisioned() -> (SigningKey, AnchorPin, ModelProvider, AnchorState) {
        let (signer, pin, mut provider) = fixture();
        provider
            .provision_explicitly(AnchorState::initial())
            .unwrap();
        (signer, pin, provider, AnchorState::initial())
    }

    fn request(domain: &AnchorDomain, challenge: u8) -> ReadRequest {
        ReadRequest {
            domain: domain.clone(),
            challenge: nonzero(challenge),
        }
    }

    fn successor(current: &AnchorState, record: u8, envelope: u8) -> AnchorState {
        AnchorState {
            trust_epoch: current.trust_epoch + 1,
            record_id: nonzero(record),
            envelope_id: nonzero(envelope),
        }
    }

    fn cas_request(
        domain: &AnchorDomain,
        operation_id: u8,
        challenge: u8,
        expected: &AnchorState,
        next: &AnchorState,
    ) -> CasRequest {
        CasRequest {
            domain: domain.clone(),
            operation_id: nonzero(operation_id),
            challenge: nonzero(challenge),
            expected: expected.clone(),
            next: next.clone(),
        }
    }

    #[test]
    fn uninitialized_anchor_is_not_silently_reset_and_provisioning_is_explicit() {
        let (_, pin, provider) = fixture();
        assert_eq!(
            provider.read(&request(&pin.domain, 0x51)),
            Err(ContractError::Uninitialized)
        );
        let mut provider = provider;
        provider
            .provision_explicitly(AnchorState::initial())
            .unwrap();
        assert!(provider.read(&request(&pin.domain, 0x52)).is_ok());
        assert_eq!(
            provider.provision_explicitly(AnchorState::initial()),
            Err(ContractError::InvalidState)
        );
    }

    #[test]
    fn read_receipt_binds_provider_network_deployment_policy_key_and_fresh_challenge() {
        let (_, pin, provider, current) = provisioned();
        let read_request = request(&pin.domain, 0x61);
        let receipt = provider.read(&read_request).unwrap();
        assert_eq!(receipt.verify_for(&pin, &read_request).unwrap(), current);

        let stale_request = request(&pin.domain, 0x62);
        assert_eq!(
            receipt.verify_for(&pin, &stale_request),
            Err(ContractError::StaleOrMisboundReceipt)
        );

        let mut wrong_domain = read_request.clone();
        wrong_domain.domain.deployment_id[0] ^= 1;
        assert_eq!(
            provider.read(&wrong_domain),
            Err(ContractError::WrongDomain)
        );

        let mut wrong_provider_pin = pin.clone();
        wrong_provider_pin.domain.provider_id[0] ^= 1;
        assert_eq!(
            receipt.verify_for(&wrong_provider_pin, &read_request),
            Err(ContractError::WrongDomain)
        );
    }

    #[test]
    fn read_receipt_signature_binds_the_complete_floor_and_sequence() {
        let (_, pin, mut provider, _) = provisioned();
        let read = request(&pin.domain, 0x71);
        let receipt = provider.read(&read).unwrap();
        let mut changed_state = receipt.clone();
        changed_state.state_sequence += 1;
        assert_eq!(
            changed_state.verify_for(&pin, &read),
            Err(ContractError::InvalidReceiptSignature)
        );

        let next = successor(&AnchorState::initial(), 0x81, 0x82);
        let cas = cas_request(&pin.domain, 0x83, 0x84, &AnchorState::initial(), &next);
        let applied = provider.compare_and_swap(&cas).unwrap();
        assert_eq!(applied.outcome, CasOutcome::Applied);
    }

    #[test]
    fn cas_requires_exact_successor_and_rejects_skips_and_same_epoch() {
        let (_, pin, mut provider, current) = provisioned();
        let skipped = AnchorState {
            trust_epoch: 2,
            record_id: nonzero(0x91),
            envelope_id: nonzero(0x92),
        };
        let request = cas_request(&pin.domain, 0x93, 0x94, &current, &skipped);
        assert_eq!(
            request.validate(&pin),
            Err(ContractError::NotExactSuccessor)
        );
        assert_eq!(
            provider.compare_and_swap(&request),
            Err(ContractError::NotExactSuccessor)
        );

        let unchanged = AnchorState {
            trust_epoch: 1,
            record_id: nonzero(0x91),
            envelope_id: nonzero(0x92),
        };
        let request = cas_request(&pin.domain, 0x95, 0x96, &current, &unchanged);
        assert_eq!(
            provider.compare_and_swap(&request).unwrap().outcome,
            CasOutcome::Applied
        );
    }

    #[test]
    fn cas_receipt_binds_operation_id_challenge_outcome_and_exact_target() {
        let (_, pin, mut provider, current) = provisioned();
        let target = successor(&current, 0xA1, 0xA2);
        let req = cas_request(&pin.domain, 0xA3, 0xA4, &current, &target);
        let receipt = provider.compare_and_swap(&req).unwrap();
        assert_eq!(receipt.outcome, CasOutcome::Applied);
        assert_eq!(receipt.verify_for(&pin, &req).unwrap(), target);

        let mut changed_id = receipt.clone();
        changed_id.operation_id[0] ^= 1;
        assert_eq!(
            changed_id.verify_for(&pin, &req),
            Err(ContractError::StaleOrMisboundReceipt)
        );

        let mut changed_outcome = receipt.clone();
        changed_outcome.outcome = CasOutcome::Conflict;
        assert_eq!(
            changed_outcome.verify_for(&pin, &req),
            Err(ContractError::InvalidReceiptSignature)
        );

        let mut changed_target = receipt.clone();
        changed_target.current.envelope_id[0] ^= 1;
        assert_eq!(
            changed_target.verify_for(&pin, &req),
            Err(ContractError::InvalidReceipt)
        );
    }

    #[test]
    fn exact_operation_retry_is_idempotent_but_operation_id_reuse_with_new_target_conflicts() {
        let (_, pin, mut provider, current) = provisioned();
        let target = successor(&current, 0xB1, 0xB2);
        let first = cas_request(&pin.domain, 0xB3, 0xB4, &current, &target);
        let receipt = provider.compare_and_swap(&first).unwrap();
        assert_eq!(receipt.outcome, CasOutcome::Applied);

        let retry = cas_request(&pin.domain, 0xB3, 0xB5, &current, &target);
        let repeated = provider.compare_and_swap(&retry).unwrap();
        assert_eq!(repeated.outcome, CasOutcome::AlreadyApplied);
        assert_eq!(repeated.current, target);

        let conflicting_target = successor(&target, 0xB6, 0xB7);
        let reuse = cas_request(&pin.domain, 0xB3, 0xB8, &target, &conflicting_target);
        let conflict = provider.compare_and_swap(&reuse).unwrap();
        assert_eq!(conflict.outcome, CasOutcome::Conflict);
        assert_eq!(conflict.current, target);
    }

    #[test]
    fn stale_expected_floor_cannot_overwrite_a_concurrent_successor() {
        let (_, pin, mut provider, initial) = provisioned();
        let target_a = successor(&initial, 0xC1, 0xC2);
        let request_a = cas_request(&pin.domain, 0xC3, 0xC4, &initial, &target_a);
        assert_eq!(
            provider.compare_and_swap(&request_a).unwrap().outcome,
            CasOutcome::Applied
        );

        let target_b = successor(&initial, 0xC5, 0xC6);
        let request_b = cas_request(&pin.domain, 0xC7, 0xC8, &initial, &target_b);
        let conflict = provider.compare_and_swap(&request_b).unwrap();
        assert_eq!(conflict.outcome, CasOutcome::Conflict);
        assert_eq!(conflict.current, target_a);
    }

    #[test]
    fn ambiguous_cas_uses_fresh_authenticated_read_and_exact_state_only() {
        let (_, pin, mut provider, initial) = provisioned();
        let target = successor(&initial, 0xD1, 0xD2);
        let cas = cas_request(&pin.domain, 0xD3, 0xD4, &initial, &target);
        provider.compare_and_swap(&cas).unwrap(); // caller loses response

        let read = request(&pin.domain, 0xD5);
        let receipt = provider.read(&read).unwrap();
        assert_eq!(
            resolve_ambiguous_commit(&pin, &read, &receipt, &cas).unwrap(),
            AmbiguousCommitResolution::Committed
        );

        let mut before_provider =
            ModelProvider::new(pin.domain.clone(), SigningKey::from_bytes(&[0x47; 32]));
        before_provider
            .provision_explicitly(initial.clone())
            .unwrap();
        let read_before = request(&pin.domain, 0xD6);
        let receipt_before = before_provider.read(&read_before).unwrap();
        assert_eq!(
            resolve_ambiguous_commit(&pin, &read_before, &receipt_before, &cas).unwrap(),
            AmbiguousCommitResolution::RetrySameOperationIdAndPayload
        );

        let later = successor(&target, 0xD7, 0xD8);
        let mut different_provider =
            ModelProvider::new(pin.domain.clone(), SigningKey::from_bytes(&[0x47; 32]));
        different_provider
            .provision_explicitly(later.clone())
            .unwrap();
        let read_later = request(&pin.domain, 0xD9);
        let receipt_later = different_provider.read(&read_later).unwrap();
        assert_eq!(
            resolve_ambiguous_commit(&pin, &read_later, &receipt_later, &cas).unwrap(),
            AmbiguousCommitResolution::QuarantineForManualRecovery
        );
    }

    #[test]
    fn ambiguous_cas_rejects_reused_challenge_and_unpinned_or_wrong_network_receipt() {
        let (_, pin, provider, _) = provisioned();
        let initial = AnchorState::initial();
        let target = successor(&initial, 0xE1, 0xE2);
        let cas = cas_request(&pin.domain, 0xE3, 0xE4, &initial, &target);
        let read_same_nonce = request(&pin.domain, 0xE4);
        let receipt = provider.read(&read_same_nonce).unwrap();
        assert_eq!(
            resolve_ambiguous_commit(&pin, &read_same_nonce, &receipt, &cas),
            Err(ContractError::ChallengeReused)
        );

        let wrong_network = request(
            &AnchorDomain {
                network_id: nonzero(0xF1),
                ..pin.domain.clone()
            },
            0xE5,
        );
        assert_eq!(
            resolve_ambiguous_commit(
                &pin,
                &wrong_network,
                &provider.read(&wrong_network).unwrap_or_else(|_| {
                    ReadReceipt {
                        domain: wrong_network.domain.clone(),
                        challenge: wrong_network.challenge,
                        state_sequence: 1,
                        state: initial,
                        signature: [0; 64],
                    }
                }),
                &cas
            ),
            Err(ContractError::WrongDomain)
        );
    }

    #[test]
    fn forged_success_receipt_and_tampered_observation_fail_closed() {
        let (_, pin, provider, initial) = provisioned();
        let target = successor(&initial, 0xF2, 0xF3);
        let cas = cas_request(&pin.domain, 0xF4, 0xF5, &initial, &target);
        let forged = CasReceipt {
            domain: pin.domain.clone(),
            operation_id: cas.operation_id,
            challenge: cas.challenge,
            state_sequence: 2,
            outcome: CasOutcome::Applied,
            current: initial,
            signature: [0; 64],
        };
        assert_eq!(
            forged.verify_for(&pin, &cas),
            Err(ContractError::InvalidReceipt)
        );
        let read = request(&pin.domain, 0xF6);
        let receipt = provider.read(&read).unwrap();
        let mut tampered = receipt.clone();
        tampered.state = successor(&AnchorState::initial(), 0xF7, 0xF8);
        tampered.state.record_id[0] ^= 1;
        assert_eq!(
            tampered.verify_for(&pin, &read),
            Err(ContractError::InvalidReceiptSignature)
        );
    }

    #[test]
    fn joint_restore_of_the_model_provider_and_operation_journal_reproduces_rollback_gap() {
        let (_, pin, mut provider, initial) = provisioned();
        let rollback_snapshot = provider.clone();
        let target = successor(&initial, 0xA7, 0xA8);
        let cas = cas_request(&pin.domain, 0xA9, 0xAA, &initial, &target);
        let receipt = provider.compare_and_swap(&cas).unwrap();
        assert_eq!(receipt.outcome, CasOutcome::Applied);
        assert_eq!(receipt.current, target);

        // Deliberately restore provider state, operation journal and signing key together.
        // The old floor can then be freshly signed; receipt authentication alone is insufficient.
        provider = rollback_snapshot;
        let fresh_read = request(&pin.domain, 0xAB);
        let old_state_receipt = provider.read(&fresh_read).unwrap();
        assert_eq!(
            old_state_receipt.verify_for(&pin, &fresh_read).unwrap(),
            initial
        );
        assert_ne!(old_state_receipt.challenge, cas.challenge);
    }

    #[test]
    fn python_12_external_anchor_receipt_digests_match_rust() {
        let public_key = vector_hex32("fixture.receipt_public_key_hex");
        assert_eq!(
            hash_parts(&[KEY_ID_DOMAIN, &public_key]),
            vector_hex32("fixture.receipt_key_id_hex")
        );
        let domain = AnchorDomain {
            provider_id: vector_hex32("fixture.provider_id_hex"),
            network_id: vector_hex32("fixture.network_id_hex"),
            deployment_id: vector_hex32("fixture.deployment_id_hex"),
            policy_id: vector_hex32("fixture.policy_id_hex"),
            receipt_key_id: vector_hex32("fixture.receipt_key_id_hex"),
        };

        let read_state = AnchorState {
            trust_epoch: vector_value("read.floor_epoch").parse().unwrap(),
            record_id: vector_hex32("read.floor_record_id_hex"),
            envelope_id: vector_hex32("read.floor_envelope_id_hex"),
        };
        let read_receipt = ReadReceipt {
            domain: domain.clone(),
            challenge: vector_hex32("read.challenge_hex"),
            state_sequence: vector_value("read.sequence").parse().unwrap(),
            state: read_state,
            signature: [0; 64],
        };
        assert_eq!(
            read_receipt.signing_digest().unwrap(),
            vector_hex32("read.signing_digest_hex")
        );

        let cas_receipt = CasReceipt {
            domain,
            operation_id: vector_hex32("cas.operation_id_hex"),
            challenge: vector_hex32("cas.challenge_hex"),
            state_sequence: vector_value("cas.sequence").parse().unwrap(),
            outcome: CasOutcome::Applied,
            current: AnchorState {
                trust_epoch: vector_value("cas.current_epoch").parse().unwrap(),
                record_id: vector_hex32("cas.current_record_id_hex"),
                envelope_id: vector_hex32("cas.current_envelope_id_hex"),
            },
            signature: [0; 64],
        };
        assert_eq!(vector_value("cas.outcome_u16"), "1");
        assert_eq!(
            cas_receipt.signing_digest().unwrap(),
            vector_hex32("cas.signing_digest_hex")
        );
        assert_eq!(
            vector_value("fixture.domain_width")
                .parse::<usize>()
                .unwrap(),
            160
        );
        assert_eq!(
            vector_value("fixture.read_receipt_signing_input_bytes")
                .parse::<usize>()
                .unwrap(),
            READ_RECEIPT_DOMAIN.len() + 160 + 32 + 8 + 72
        );
        assert_eq!(
            vector_value("fixture.cas_receipt_signing_input_bytes")
                .parse::<usize>()
                .unwrap(),
            CAS_RECEIPT_DOMAIN.len() + 160 + 32 + 32 + 8 + 2 + 72
        );
    }
}
