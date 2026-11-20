//! Read-only cryptographic proof for a C-anchored successor while D remains on its predecessor.
//! This module does not advance either store, write artifacts, activate identities, or authorize startup.
use crate::{
    devnet_signed_peer_identity_candidate::{verify_signed_peer_identity, SignedPeerIdentityError},
    identity_generation_store::{
        verify_signed_rotation_statement, IdentityGenerationError, IdentityGenerationStateStore,
    },
    identity_policy::{KeyPurpose, KeyState},
    noise_deployment_config::{
        verify_signed_deployment_config_with_floors, DeploymentConfigStateStore,
    },
    noise_identity_rotation_authorization::{verify_dual_attestation, VerifiedDualAttestation},
    noise_issuer_registry::{verify_signed_registry, IssuerRegistryStateStore},
    peer_identity_anchor_vault::{
        PeerAnchorRotationActiveBinding, PeerIdentityAnchorScope, PeerIdentityAnchorVault,
    },
};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchoredSuccessorProofError {
    AnchorScopeMismatch,
    GenerationStoreScopeMismatch,
    AnchorHasNoActiveRotation,
    GenerationStoreUninitialized,
    GenerationStoreNotActive,
    SuccessorOutsideValidityWindow,
    AnchorBindingMismatch,
    ArtifactDigestMismatch,
    IdentityBindingMismatch,
    Npi1(SignedPeerIdentityError),
    Nrt1(IdentityGenerationError),
    DualAttestation(String),
    Dpc1(String),
    Irg1(String),
    RegistryBelowDeploymentFloor,
    RegistryIssuerKeyMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DualAttestationEvidence<'a> {
    pub manifest: &'a [u8],
    pub prepared_identity: &'a [u8],
    pub prepared_previous_identity: &'a [u8],
    pub endpoint_evidence: &'a [u8],
    pub fingerprint_evidence: &'a [u8],
    pub policy: &'a [u8],
    pub authorization: &'a [u8],
    pub operator_public: &'a [u8],
    pub operator_pin: &'a str,
    pub operator_signature: &'a [u8],
    pub owner_public: &'a [u8],
    pub owner_pin: &'a str,
    pub owner_signature: &'a [u8],
    pub dpc1: &'a [u8],
    pub irg1: &'a [u8],
    /// Independently pinned deployment-authority key; never sourced from DPC1 itself.
    pub deployment_authority_public_key: &'a [u8; 32],
    /// External anti-rollback floor for the signed DPC1 sequence.
    pub minimum_dpc1_sequence: u64,
    /// External anti-rollback floor for the GRC1 governance-root epoch.
    pub minimum_dpc1_root_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchoredSuccessorProofEvidence<'a> {
    pub issuer_public_key: &'a [u8; 32],
    pub verification_epoch: u64,
    pub previous_npi1: &'a [u8],
    pub successor_npi1: &'a [u8],
    pub nrt1: &'a [u8],
    pub dual_attestation: DualAttestationEvidence<'a>,
}

/// Output exists only after exact C/D, NPI1, NRT1 and dual-attestation bindings all verify.
/// It is evidence for a separately reviewed recovery procedure, never a recovery authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAnchoredSuccessorProof {
    pub anchor_sequence: u64,
    pub anchor_event_digest: [u8; 32],
    pub predecessor_event_digest: [u8; 32],
    pub previous_generation: u32,
    pub successor_generation: u32,
    pub profile_id: [u8; 32],
    pub previous_record_digest: [u8; 32],
    pub successor_record_digest: [u8; 32],
    pub previous_npi1_digest: [u8; 32],
    pub successor_npi1_digest: [u8; 32],
    pub nrt1_digest: [u8; 32],
    pub noise_fingerprint: [u8; 32],
    pub intent_digest: [u8; 32],
    pub nonce: [u8; 32],
    pub owner_pin_fingerprint: [u8; 32],
    pub operator_pin_fingerprint: [u8; 32],
    pub deployment_config_sequence: u64,
    pub deployment_config_digest: [u8; 32],
    pub governance_root_chain_digest: [u8; 32],
    pub governance_root_epoch: u64,
    pub issuer_registry_sequence: u64,
    pub issuer_registry_digest: [u8; 32],
    pub governance_public_key_fingerprint: [u8; 32],
    pub issuer_registry_key_fingerprint: [u8; 32],
}

fn sha(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn validate_identity(
    identity: &crate::devnet_signed_peer_identity_candidate::VerifiedSignedNoisePeerIdentity,
    scope: &PeerIdentityAnchorScope,
    generation: u32,
) -> bool {
    identity.network_id == scope.network_id
        && identity.credential_id == scope.credential_id
        && identity.issuer_id == scope.issuer_id
        && identity.record.key_id == scope.key_id
        && identity.record.purpose as u8 == scope.key_purpose
        && identity.record.algorithm == crate::identity_policy::KeyAlgorithm::NoiseX25519
        && identity.record.state == KeyState::Active
        && identity.record.generation == generation
        && identity.record.public_key.as_slice() == identity.noise_public_key
}

pub fn verify_anchored_successor_proof(
    vault: &PeerIdentityAnchorVault,
    generation_store: &IdentityGenerationStateStore,
    scope: &PeerIdentityAnchorScope,
    deployment_state: &DeploymentConfigStateStore,
    issuer_registry_state: &IssuerRegistryStateStore,
    evidence: AnchoredSuccessorProofEvidence<'_>,
) -> Result<VerifiedAnchoredSuccessorProof, AnchoredSuccessorProofError> {
    let issuer_fingerprint = sha(evidence.issuer_public_key);
    if !vault.matches_scope(scope)
        || scope.issuer_public_key_fingerprint != issuer_fingerprint
        || scope.key_purpose != KeyPurpose::PeerAuth as u8
    {
        return Err(AnchoredSuccessorProofError::AnchorScopeMismatch);
    }
    let purpose = KeyPurpose::try_from(scope.key_purpose)
        .map_err(|_| AnchoredSuccessorProofError::AnchorScopeMismatch)?;
    if !generation_store.matches_identity_scope(
        &scope.network_id,
        scope.key_id,
        purpose,
        scope.credential_id,
        scope.issuer_id,
        evidence.issuer_public_key,
    ) {
        return Err(AnchoredSuccessorProofError::GenerationStoreScopeMismatch);
    }

    let anchor: PeerAnchorRotationActiveBinding = vault
        .latest_rotation_active_binding()
        .ok_or(AnchoredSuccessorProofError::AnchorHasNoActiveRotation)?;
    let high_water = generation_store
        .high_water_binding()
        .map_err(AnchoredSuccessorProofError::Nrt1)?
        .ok_or(AnchoredSuccessorProofError::GenerationStoreUninitialized)?;

    if high_water.2 != 1 {
        return Err(AnchoredSuccessorProofError::GenerationStoreNotActive);
    }
    if anchor.sequence == 0
        || anchor.event_digest == [0; 32]
        || anchor.predecessor_event_digest == [0; 32]
        || anchor.lifecycle != 1
        || anchor.generation != high_water.0.checked_add(1).unwrap_or(0)
        || anchor.previous_generation != high_water.0
        || anchor.previous_key_record_digest != high_water.1
        || anchor.generation == 0
        || anchor.npi1_digest == [0; 32]
        || anchor.nrt1_digest == [0; 32]
        || anchor.intent_digest == [0; 32]
        || anchor.nonce == [0; 32]
    {
        return Err(AnchoredSuccessorProofError::AnchorBindingMismatch);
    }

    let previous = verify_signed_peer_identity(
        evidence.previous_npi1,
        &scope.network_id,
        scope.issuer_id,
        evidence.issuer_public_key,
        evidence.verification_epoch,
    )
    .map_err(AnchoredSuccessorProofError::Npi1)?;
    let successor = verify_signed_peer_identity(
        evidence.successor_npi1,
        &scope.network_id,
        scope.issuer_id,
        evidence.issuer_public_key,
        evidence.verification_epoch,
    )
    .map_err(AnchoredSuccessorProofError::Npi1)?;

    if !validate_identity(&previous, scope, high_water.0)
        || !validate_identity(&successor, scope, anchor.generation)
    {
        return Err(AnchoredSuccessorProofError::IdentityBindingMismatch);
    }
    if !successor.time_valid_at_epoch {
        return Err(AnchoredSuccessorProofError::SuccessorOutsideValidityWindow);
    }
    if sha(&previous.record_bytes) != high_water.1
        || sha(&successor.record_bytes) != anchor.key_record_digest
        || sha(evidence.successor_npi1) != anchor.npi1_digest
        || sha(&successor.noise_public_key) != anchor.noise_fingerprint
        || sha(evidence.nrt1) != anchor.nrt1_digest
        || successor.rotation_wire.as_deref() != Some(evidence.nrt1)
        || anchor.previous_key_record_digest != sha(&previous.record_bytes)
    {
        return Err(AnchoredSuccessorProofError::ArtifactDigestMismatch);
    }

    verify_signed_rotation_statement(
        evidence.nrt1,
        &scope.network_id,
        scope.credential_id,
        scope.issuer_id,
        scope.key_id,
        purpose,
        high_water.0,
        &high_water.1,
        anchor.generation,
        &anchor.key_record_digest,
        evidence.issuer_public_key,
    )
    .map_err(AnchoredSuccessorProofError::Nrt1)?;

    // Hash-binding DPC1/IRG1 in the operator intent is not sufficient: verify both signed
    // artifacts against the out-of-band deployment authority and DPC1-derived governance root.
    let deployment = verify_signed_deployment_config_with_floors(
        evidence.dual_attestation.dpc1,
        &scope.network_id,
        evidence.dual_attestation.deployment_authority_public_key,
        evidence.dual_attestation.minimum_dpc1_sequence,
        evidence.dual_attestation.minimum_dpc1_root_epoch,
    )
    .map_err(|error| AnchoredSuccessorProofError::Dpc1(format!("{error:?}")))?;
    deployment_state
        .matches_current(&deployment)
        .map_err(|error| AnchoredSuccessorProofError::Dpc1(format!("{error:?}")))?;
    let registry = verify_signed_registry(
        evidence.dual_attestation.irg1,
        &scope.network_id,
        &deployment.governance_public_key,
    )
    .map_err(|error| AnchoredSuccessorProofError::Irg1(format!("{error:?}")))?;
    issuer_registry_state
        .matches_current_registry(&registry, &deployment.root_chain)
        .map_err(|error| AnchoredSuccessorProofError::Irg1(format!("{error:?}")))?;
    if registry.sequence() < deployment.minimum_registry_sequence {
        return Err(AnchoredSuccessorProofError::RegistryBelowDeploymentFloor);
    }
    let registry_issuer_key = registry
        .active_key(scope.issuer_id)
        .map_err(|error| AnchoredSuccessorProofError::Irg1(format!("{error:?}")))?;
    if registry_issuer_key != *evidence.issuer_public_key {
        return Err(AnchoredSuccessorProofError::RegistryIssuerKeyMismatch);
    }

    let dual: VerifiedDualAttestation = verify_dual_attestation(
        evidence.dual_attestation.manifest,
        evidence.dual_attestation.prepared_identity,
        evidence.dual_attestation.prepared_previous_identity,
        evidence.dual_attestation.endpoint_evidence,
        evidence.dual_attestation.fingerprint_evidence,
        evidence.dual_attestation.policy,
        evidence.dual_attestation.authorization,
        evidence.dual_attestation.operator_public,
        evidence.dual_attestation.operator_pin,
        evidence.dual_attestation.operator_signature,
        evidence.dual_attestation.owner_public,
        evidence.dual_attestation.owner_pin,
        evidence.dual_attestation.owner_signature,
        evidence.dual_attestation.dpc1,
        evidence.dual_attestation.irg1,
        evidence.previous_npi1,
        &scope.network_id,
        scope.issuer_id,
        u64::from(high_water.0),
        u64::from(anchor.generation),
        &successor.noise_public_key,
        &previous.noise_public_key,
        successor.record.not_before,
        successor.record.not_after,
        evidence.verification_epoch,
    )
    .map_err(AnchoredSuccessorProofError::DualAttestation)?;

    if dual.profile_id != scope.profile_id
        || dual.intent_digest != anchor.intent_digest
        || dual.nonce != anchor.nonce
        || dual.owner_pin_fingerprint != anchor.owner_pin_fingerprint
        || dual.operator_pin_fingerprint != anchor.operator_pin_fingerprint
    {
        return Err(AnchoredSuccessorProofError::AnchorBindingMismatch);
    }

    Ok(VerifiedAnchoredSuccessorProof {
        anchor_sequence: anchor.sequence,
        anchor_event_digest: anchor.event_digest,
        predecessor_event_digest: anchor.predecessor_event_digest,
        previous_generation: high_water.0,
        successor_generation: anchor.generation,
        profile_id: dual.profile_id,
        previous_record_digest: high_water.1,
        successor_record_digest: anchor.key_record_digest,
        previous_npi1_digest: sha(evidence.previous_npi1),
        successor_npi1_digest: sha(evidence.successor_npi1),
        nrt1_digest: sha(evidence.nrt1),
        noise_fingerprint: anchor.noise_fingerprint,
        intent_digest: dual.intent_digest,
        nonce: dual.nonce,
        owner_pin_fingerprint: dual.owner_pin_fingerprint,
        operator_pin_fingerprint: dual.operator_pin_fingerprint,
        deployment_config_sequence: deployment.sequence,
        deployment_config_digest: deployment.digest,
        governance_root_chain_digest: *deployment.root_chain.digest(),
        governance_root_epoch: deployment.root_chain.current_epoch(),
        issuer_registry_sequence: registry.sequence(),
        issuer_registry_digest: *registry.digest(),
        governance_public_key_fingerprint: sha(&deployment.governance_public_key),
        issuer_registry_key_fingerprint: sha(&registry_issuer_key),
    })
}
