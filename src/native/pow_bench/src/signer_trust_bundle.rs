//! STB1 pure signer-trust-bundle codec and verifier.
//!
//! This module verifies a successor bundle only. It deliberately has no enrollment store,
//! sequence high-water, key custody, CLI, provisioner, or node-startup integration.
//! DPC1 context must come from the strict external-root-floor verifier. The expected profile
//! ID and prior bundle sequence/digest are independent caller inputs; DPC1 v1 does not carry
//! a profile ID. A first bundle is rejected until a separate initial-enrollment authorization
//! contract is implemented.
//!
//! Signer acceptance receipts bind the stable signer assignment (network, profile, ID, role,
//! scope, generation, key fingerprint, and activation coordinates). They do not bind lifecycle
//! fields, allowing a previously accepted receipt to remain auditable after retirement/revocation.
//! The current governance-root signature authenticates the complete bundle and lifecycle state.

use crate::noise_deployment_config::VerifiedDeploymentConfig;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

const MAGIC: &[u8; 4] = b"STB1";
const VERSION: u16 = 1;
const HEADER_LEN: usize = 154;
const SIGNATURE_LEN: usize = 64;
const RECORD_FIXED_LEN: usize = 172;
const SIGNER_TRUST_DOMAIN: &[u8] = b"QFP6-SIGNER-TRUST-BUNDLE\0v1";
const ACCEPTANCE_DOMAIN: &[u8] = b"QFP6-SIGNER-TRUST-ACCEPTANCE\0v1";

pub const MAX_SIGNER_TRUST_ENTRIES: usize = 32;
pub const MAX_SIGNER_ID_LEN: usize = 64;
pub const MIN_SIGNED_SIGNER_TRUST_BUNDLE_LEN: usize =
    HEADER_LEN + 2 * (RECORD_FIXED_LEN + 1) + SIGNATURE_LEN;
pub const MAX_SIGNED_SIGNER_TRUST_BUNDLE_LEN: usize =
    HEADER_LEN + MAX_SIGNER_TRUST_ENTRIES * (RECORD_FIXED_LEN + MAX_SIGNER_ID_LEN) + SIGNATURE_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SignerRole {
    OwnerAuthorizer = 1,
    IndependentOperator = 2,
}

impl TryFrom<u8> for SignerRole {
    type Error = SignerTrustBundleError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::OwnerAuthorizer),
            2 => Ok(Self::IndependentOperator),
            _ => Err(SignerTrustBundleError::InvalidRole),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SignerScope {
    PeerIdentityRotation = 1,
}

impl TryFrom<u8> for SignerScope {
    type Error = SignerTrustBundleError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::PeerIdentityRotation),
            _ => Err(SignerTrustBundleError::InvalidScope),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SignerLifecycle {
    Active = 1,
    Retired = 2,
    Revoked = 3,
}

impl TryFrom<u8> for SignerLifecycle {
    type Error = SignerTrustBundleError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Active),
            2 => Ok(Self::Retired),
            3 => Ok(Self::Revoked),
            _ => Err(SignerTrustBundleError::InvalidLifecycle),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerTrustBundleEntry {
    pub signer_id: String,
    pub role: SignerRole,
    pub scope: SignerScope,
    pub generation: u64,
    pub public_key: [u8; 32],
    pub fingerprint: [u8; 32],
    pub lifecycle: SignerLifecycle,
    pub activation_epoch: u64,
    pub activation_sequence: u64,
    pub terminal_epoch: u64,
    pub terminal_sequence: u64,
    pub acceptance_signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerTrustBundle {
    pub network_id: [u8; 32],
    pub profile_id: [u8; 32],
    pub sequence: u64,
    pub previous_digest: [u8; 32],
    pub governance_root_epoch: u64,
    pub governance_root_fingerprint: [u8; 32],
    pub entries: Vec<SignerTrustBundleEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSignerTrustBundle {
    bundle: SignerTrustBundle,
    digest: [u8; 32],
    wire: Vec<u8>,
}

impl VerifiedSignerTrustBundle {
    pub fn bundle(&self) -> &SignerTrustBundle {
        &self.bundle
    }

    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub fn wire(&self) -> &[u8] {
        &self.wire
    }

    pub fn active_owner(&self) -> Option<&SignerTrustBundleEntry> {
        self.bundle.entries.iter().find(|entry| {
            entry.role == SignerRole::OwnerAuthorizer && entry.lifecycle == SignerLifecycle::Active
        })
    }

    pub fn active_operators(&self) -> impl Iterator<Item = &SignerTrustBundleEntry> {
        self.bundle.entries.iter().filter(|entry| {
            entry.role == SignerRole::IndependentOperator
                && entry.lifecycle == SignerLifecycle::Active
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignerTrustBundleError {
    Malformed,
    UnsupportedVersion,
    ReservedBits,
    UnverifiedDeploymentContext,
    NetworkMismatch,
    ProfileMismatch,
    GovernanceRootEpochMismatch,
    GovernanceRootFingerprintMismatch,
    GovernanceAuthorityMismatch,
    InvalidBundleSignature,
    InvalidAcceptanceSignature,
    InvalidSignerKey,
    InvalidSignerFingerprint,
    InvalidSignerId,
    DuplicateSignerId,
    DuplicateSignerFingerprint,
    NonCanonicalOrder,
    InvalidRole,
    InvalidLifecycle,
    InvalidScope,
    InvalidGeneration,
    DuplicateSignerGeneration,
    InvalidActivation,
    InvalidTerminalState,
    MissingActiveOwner,
    MultipleActiveOwners,
    MissingActiveOperator,
    SequenceDiscontinuity,
    PredecessorMismatch,
    InitialEnrollmentRequiresSeparateAuthorization,
    SignerRemoved,
    SignerIdentityChanged,
    SignerLifecycleRollback,
    SignerTerminalStateChanged,
    SignerGenerationNotAdvanced,
    RootEpochRollback,
    StateMissing,
    StateMalformed,
    StateIdentityMismatch,
    StateNotCurrent,
    StatePersistence,
    StateLocked,
    InvalidStatePath,
    BootstrapCheckpointRequired,
    SequenceRollback,
    SameSequenceConflict,
    GovernanceRootContextChangeRequiresMigration,
}

impl std::fmt::Display for SignerTrustBundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "signer trust bundle error: {self:?}")
    }
}

impl std::error::Error for SignerTrustBundleError {}

/// Build the exact stable assignment message that an owner/operator signer must accept.
/// The acceptance receipt does not authorize later lifecycle transitions; those are covered by
/// the current governance-root signature over the complete STB1 bundle.
pub fn signer_acceptance_preimage(
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
    entry: &SignerTrustBundleEntry,
) -> Result<Vec<u8>, SignerTrustBundleError> {
    validate_entry_identity(entry)?;
    let id = entry.signer_id.as_bytes();
    let mut message = Vec::with_capacity(
        ACCEPTANCE_DOMAIN.len() + 32 + 32 + 1 + id.len() + 1 + 1 + 8 + 32 + 32 + 8 + 8,
    );
    message.extend_from_slice(ACCEPTANCE_DOMAIN);
    message.extend_from_slice(network_id);
    message.extend_from_slice(profile_id);
    message.push(id.len() as u8);
    message.extend_from_slice(id);
    message.push(entry.role as u8);
    message.push(entry.scope as u8);
    message.extend_from_slice(&entry.generation.to_be_bytes());
    message.extend_from_slice(&entry.public_key);
    message.extend_from_slice(&entry.fingerprint);
    message.extend_from_slice(&entry.activation_epoch.to_be_bytes());
    message.extend_from_slice(&entry.activation_sequence.to_be_bytes());
    Ok(message)
}

/// Verify a signed STB1 successor against a strictly verified DPC1/GRC1 context.
///
/// expected_profile_id, expected_previous_sequence, and expected_previous_digest must come
/// from independently trusted configuration/state. This function intentionally refuses
/// sequence-zero/zero-digest initial enrollment; a separate approval policy is required.
pub fn verify_signed_signer_trust_bundle(
    wire: &[u8],
    deployment: &VerifiedDeploymentConfig,
    expected_profile_id: &[u8; 32],
    expected_previous_sequence: u64,
    expected_previous_digest: &[u8; 32],
) -> Result<VerifiedSignerTrustBundle, SignerTrustBundleError> {
    if wire.len() < MIN_SIGNED_SIGNER_TRUST_BUNDLE_LEN
        || wire.len() > MAX_SIGNED_SIGNER_TRUST_BUNDLE_LEN
    {
        return Err(SignerTrustBundleError::Malformed);
    }
    if &wire[..4] != MAGIC {
        return Err(SignerTrustBundleError::Malformed);
    }

    let version = u16::from_be_bytes(
        wire[4..6]
            .try_into()
            .map_err(|_| SignerTrustBundleError::Malformed)?,
    );
    if version != VERSION {
        return Err(SignerTrustBundleError::UnsupportedVersion);
    }
    let reserved = u16::from_be_bytes(
        wire[6..8]
            .try_into()
            .map_err(|_| SignerTrustBundleError::Malformed)?,
    );
    if reserved != 0 {
        return Err(SignerTrustBundleError::ReservedBits);
    }

    let network_id: [u8; 32] = wire[8..40]
        .try_into()
        .map_err(|_| SignerTrustBundleError::Malformed)?;
    let profile_id: [u8; 32] = wire[40..72]
        .try_into()
        .map_err(|_| SignerTrustBundleError::Malformed)?;
    let sequence = u64::from_be_bytes(
        wire[72..80]
            .try_into()
            .map_err(|_| SignerTrustBundleError::Malformed)?,
    );
    let previous_digest: [u8; 32] = wire[80..112]
        .try_into()
        .map_err(|_| SignerTrustBundleError::Malformed)?;
    let governance_root_epoch = u64::from_be_bytes(
        wire[112..120]
            .try_into()
            .map_err(|_| SignerTrustBundleError::Malformed)?,
    );
    let governance_root_fingerprint: [u8; 32] = wire[120..152]
        .try_into()
        .map_err(|_| SignerTrustBundleError::Malformed)?;
    let count = u16::from_be_bytes(
        wire[152..154]
            .try_into()
            .map_err(|_| SignerTrustBundleError::Malformed)?,
    ) as usize;

    if !(2..=MAX_SIGNER_TRUST_ENTRIES).contains(&count) {
        return Err(SignerTrustBundleError::Malformed);
    }

    validate_header_context(
        &network_id,
        &profile_id,
        sequence,
        &previous_digest,
        governance_root_epoch,
        &governance_root_fingerprint,
        deployment,
        expected_profile_id,
        expected_previous_sequence,
        expected_previous_digest,
    )?;

    // The input is strictly size-bounded before parsing. Parse exact record framing first so
    // truncation/trailing-data errors are distinguishable from a well-formed bad signature.
    let signature_offset = wire.len() - SIGNATURE_LEN;
    let mut offset = HEADER_LEN;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let id_len = *take(wire, &mut offset, signature_offset, 1)?
            .first()
            .ok_or(SignerTrustBundleError::Malformed)? as usize;
        if !(1..=MAX_SIGNER_ID_LEN).contains(&id_len) {
            return Err(SignerTrustBundleError::InvalidSignerId);
        }
        let id_bytes = take(wire, &mut offset, signature_offset, id_len)?;
        let signer_id = std::str::from_utf8(id_bytes)
            .map_err(|_| SignerTrustBundleError::InvalidSignerId)?
            .to_owned();
        let role = SignerRole::try_from(
            *take(wire, &mut offset, signature_offset, 1)?
                .first()
                .ok_or(SignerTrustBundleError::Malformed)?,
        )?;
        let scope = SignerScope::try_from(
            *take(wire, &mut offset, signature_offset, 1)?
                .first()
                .ok_or(SignerTrustBundleError::Malformed)?,
        )?;
        let generation = u64::from_be_bytes(read_array::<8>(wire, &mut offset, signature_offset)?);
        let public_key = read_array::<32>(wire, &mut offset, signature_offset)?;
        let fingerprint = read_array::<32>(wire, &mut offset, signature_offset)?;
        let lifecycle = SignerLifecycle::try_from(
            *take(wire, &mut offset, signature_offset, 1)?
                .first()
                .ok_or(SignerTrustBundleError::Malformed)?,
        )?;
        let activation_epoch =
            u64::from_be_bytes(read_array::<8>(wire, &mut offset, signature_offset)?);
        let activation_sequence =
            u64::from_be_bytes(read_array::<8>(wire, &mut offset, signature_offset)?);
        let terminal_epoch =
            u64::from_be_bytes(read_array::<8>(wire, &mut offset, signature_offset)?);
        let terminal_sequence =
            u64::from_be_bytes(read_array::<8>(wire, &mut offset, signature_offset)?);
        let acceptance_signature = read_array::<64>(wire, &mut offset, signature_offset)?;

        entries.push(SignerTrustBundleEntry {
            signer_id,
            role,
            scope,
            generation,
            public_key,
            fingerprint,
            lifecycle,
            activation_epoch,
            activation_sequence,
            terminal_epoch,
            terminal_sequence,
            acceptance_signature,
        });
    }
    if offset != signature_offset {
        return Err(SignerTrustBundleError::Malformed);
    }

    let bundle = SignerTrustBundle {
        network_id,
        profile_id,
        sequence,
        previous_digest,
        governance_root_epoch,
        governance_root_fingerprint,
        entries,
    };
    validate_entries(&bundle)?;

    let signature = Signature::from_slice(&wire[signature_offset..])
        .map_err(|_| SignerTrustBundleError::InvalidBundleSignature)?;
    let governance_key = VerifyingKey::from_bytes(deployment.root_chain.current_key())
        .map_err(|_| SignerTrustBundleError::GovernanceAuthorityMismatch)?;
    let mut bundle_preimage = Vec::with_capacity(SIGNER_TRUST_DOMAIN.len() + signature_offset);
    bundle_preimage.extend_from_slice(SIGNER_TRUST_DOMAIN);
    bundle_preimage.extend_from_slice(&wire[..signature_offset]);
    governance_key
        .verify_strict(&bundle_preimage, &signature)
        .map_err(|_| SignerTrustBundleError::InvalidBundleSignature)?;

    Ok(VerifiedSignerTrustBundle {
        bundle,
        digest: Sha256::digest(wire).into(),
        wire: wire.to_vec(),
    })
}

/// Canonically encode and self-verify an STB1 successor. The governance signing key is supplied
/// by the caller and is never persisted here. Each entry must already contain its signer-issued
/// acceptance receipt.
pub fn encode_signed_signer_trust_bundle(
    bundle: &SignerTrustBundle,
    governance_signing_key: &SigningKey,
    deployment: &VerifiedDeploymentConfig,
    expected_profile_id: &[u8; 32],
    expected_previous_sequence: u64,
    expected_previous_digest: &[u8; 32],
) -> Result<Vec<u8>, SignerTrustBundleError> {
    validate_header_context(
        &bundle.network_id,
        &bundle.profile_id,
        bundle.sequence,
        &bundle.previous_digest,
        bundle.governance_root_epoch,
        &bundle.governance_root_fingerprint,
        deployment,
        expected_profile_id,
        expected_previous_sequence,
        expected_previous_digest,
    )?;
    validate_entries(bundle)?;

    if governance_signing_key.verifying_key().to_bytes() != *deployment.root_chain.current_key() {
        return Err(SignerTrustBundleError::GovernanceAuthorityMismatch);
    }
    if !(2..=MAX_SIGNER_TRUST_ENTRIES).contains(&bundle.entries.len()) {
        return Err(SignerTrustBundleError::Malformed);
    }

    let mut wire = Vec::with_capacity(
        HEADER_LEN + bundle.entries.len() * (RECORD_FIXED_LEN + MAX_SIGNER_ID_LEN) + SIGNATURE_LEN,
    );
    wire.extend_from_slice(MAGIC);
    wire.extend_from_slice(&VERSION.to_be_bytes());
    wire.extend_from_slice(&0u16.to_be_bytes());
    wire.extend_from_slice(&bundle.network_id);
    wire.extend_from_slice(&bundle.profile_id);
    wire.extend_from_slice(&bundle.sequence.to_be_bytes());
    wire.extend_from_slice(&bundle.previous_digest);
    wire.extend_from_slice(&bundle.governance_root_epoch.to_be_bytes());
    wire.extend_from_slice(&bundle.governance_root_fingerprint);
    wire.extend_from_slice(&(bundle.entries.len() as u16).to_be_bytes());

    for entry in &bundle.entries {
        wire.extend_from_slice(&encode_entry_prefix(entry)?);
        wire.extend_from_slice(&entry.acceptance_signature);
    }

    let mut preimage = Vec::with_capacity(SIGNER_TRUST_DOMAIN.len() + wire.len());
    preimage.extend_from_slice(SIGNER_TRUST_DOMAIN);
    preimage.extend_from_slice(&wire);
    wire.extend_from_slice(&governance_signing_key.sign(&preimage).to_bytes());

    verify_signed_signer_trust_bundle(
        &wire,
        deployment,
        expected_profile_id,
        expected_previous_sequence,
        expected_previous_digest,
    )?;
    Ok(wire)
}

fn validate_header_context(
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
    sequence: u64,
    previous_digest: &[u8; 32],
    governance_root_epoch: u64,
    governance_root_fingerprint: &[u8; 32],
    deployment: &VerifiedDeploymentConfig,
    expected_profile_id: &[u8; 32],
    expected_previous_sequence: u64,
    expected_previous_digest: &[u8; 32],
) -> Result<(), SignerTrustBundleError> {
    let external_floor = deployment
        .verified_external_minimum_root_epoch
        .filter(|floor| *floor > 0)
        .ok_or(SignerTrustBundleError::UnverifiedDeploymentContext)?;
    if deployment.network_id == [0; 32]
        || deployment.root_chain.network_id() != &deployment.network_id
        || deployment.root_chain.current_epoch() < external_floor
        || deployment.minimum_root_epoch < external_floor
    {
        return Err(SignerTrustBundleError::UnverifiedDeploymentContext);
    }
    if network_id != &deployment.network_id {
        return Err(SignerTrustBundleError::NetworkMismatch);
    }
    if expected_profile_id == &[0; 32]
        || profile_id == &[0; 32]
        || profile_id != expected_profile_id
    {
        return Err(SignerTrustBundleError::ProfileMismatch);
    }
    if governance_root_epoch != deployment.root_chain.current_epoch() {
        return Err(SignerTrustBundleError::GovernanceRootEpochMismatch);
    }
    let current_root_fingerprint: [u8; 32] =
        Sha256::digest(deployment.root_chain.current_key()).into();
    if governance_root_fingerprint != &current_root_fingerprint {
        return Err(SignerTrustBundleError::GovernanceRootFingerprintMismatch);
    }
    if expected_previous_sequence == 0
        || expected_previous_digest == &[0; 32]
        || previous_digest == &[0; 32]
    {
        return Err(SignerTrustBundleError::InitialEnrollmentRequiresSeparateAuthorization);
    }
    let expected_sequence = expected_previous_sequence
        .checked_add(1)
        .ok_or(SignerTrustBundleError::SequenceDiscontinuity)?;
    if sequence != expected_sequence {
        return Err(SignerTrustBundleError::SequenceDiscontinuity);
    }
    if previous_digest != expected_previous_digest {
        return Err(SignerTrustBundleError::PredecessorMismatch);
    }
    Ok(())
}

fn validate_entries(bundle: &SignerTrustBundle) -> Result<(), SignerTrustBundleError> {
    if !(2..=MAX_SIGNER_TRUST_ENTRIES).contains(&bundle.entries.len()) {
        return Err(SignerTrustBundleError::Malformed);
    }
    let mut previous_id: Option<&str> = None;
    let mut fingerprints: Vec<[u8; 32]> = Vec::with_capacity(bundle.entries.len());
    let mut generations: Vec<(SignerRole, u64)> = Vec::with_capacity(bundle.entries.len());
    let mut active_owners = 0usize;
    let mut active_operators = 0usize;

    for entry in &bundle.entries {
        validate_entry_identity(entry)?;
        if generations
            .iter()
            .any(|(role, generation)| *role == entry.role && *generation == entry.generation)
        {
            return Err(SignerTrustBundleError::DuplicateSignerGeneration);
        }
        generations.push((entry.role, entry.generation));
        if let Some(previous) = previous_id {
            if previous == entry.signer_id {
                return Err(SignerTrustBundleError::DuplicateSignerId);
            }
            if previous.as_bytes() > entry.signer_id.as_bytes() {
                return Err(SignerTrustBundleError::NonCanonicalOrder);
            }
        }
        previous_id = Some(&entry.signer_id);

        if fingerprints.contains(&entry.fingerprint) {
            return Err(SignerTrustBundleError::DuplicateSignerFingerprint);
        }
        fingerprints.push(entry.fingerprint);

        if entry.activation_epoch == 0
            || entry.activation_sequence == 0
            || entry.activation_epoch > bundle.governance_root_epoch
            || entry.activation_sequence > bundle.sequence
        {
            return Err(SignerTrustBundleError::InvalidActivation);
        }
        match entry.lifecycle {
            SignerLifecycle::Active => {
                if entry.terminal_epoch != 0 || entry.terminal_sequence != 0 {
                    return Err(SignerTrustBundleError::InvalidTerminalState);
                }
                match entry.role {
                    SignerRole::OwnerAuthorizer => active_owners += 1,
                    SignerRole::IndependentOperator => active_operators += 1,
                }
            }
            SignerLifecycle::Retired | SignerLifecycle::Revoked => {
                if entry.terminal_epoch == 0
                    || entry.terminal_sequence == 0
                    || entry.terminal_epoch < entry.activation_epoch
                    || entry.terminal_sequence < entry.activation_sequence
                    || entry.terminal_epoch > bundle.governance_root_epoch
                    || entry.terminal_sequence > bundle.sequence
                {
                    return Err(SignerTrustBundleError::InvalidTerminalState);
                }
            }
        }

        let acceptance = signer_acceptance_preimage(&bundle.network_id, &bundle.profile_id, entry)?;
        let signer = VerifyingKey::from_bytes(&entry.public_key)
            .map_err(|_| SignerTrustBundleError::InvalidSignerKey)?;
        let signature = Signature::from_bytes(&entry.acceptance_signature);
        signer
            .verify_strict(&acceptance, &signature)
            .map_err(|_| SignerTrustBundleError::InvalidAcceptanceSignature)?;
    }

    if active_owners == 0 {
        return Err(SignerTrustBundleError::MissingActiveOwner);
    }
    if active_owners != 1 {
        return Err(SignerTrustBundleError::MultipleActiveOwners);
    }
    if active_operators == 0 {
        return Err(SignerTrustBundleError::MissingActiveOperator);
    }
    Ok(())
}

fn validate_entry_identity(entry: &SignerTrustBundleEntry) -> Result<(), SignerTrustBundleError> {
    let id = entry.signer_id.as_bytes();
    if !is_canonical_signer_id(id) {
        return Err(SignerTrustBundleError::InvalidSignerId);
    }
    if entry.generation == 0 {
        return Err(SignerTrustBundleError::InvalidGeneration);
    }
    if entry.scope != SignerScope::PeerIdentityRotation {
        return Err(SignerTrustBundleError::InvalidScope);
    }
    VerifyingKey::from_bytes(&entry.public_key)
        .map_err(|_| SignerTrustBundleError::InvalidSignerKey)?;
    let fingerprint: [u8; 32] = Sha256::digest(entry.public_key).into();
    if entry.fingerprint != fingerprint {
        return Err(SignerTrustBundleError::InvalidSignerFingerprint);
    }
    Ok(())
}

fn is_canonical_signer_id(id: &[u8]) -> bool {
    if id.is_empty() || id.len() > MAX_SIGNER_ID_LEN {
        return false;
    }
    let first = id[0];
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return false;
    }
    id.iter().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(*byte, b'.' | b'_' | b'-')
    })
}

fn encode_entry_prefix(entry: &SignerTrustBundleEntry) -> Result<Vec<u8>, SignerTrustBundleError> {
    validate_entry_identity(entry)?;
    let id = entry.signer_id.as_bytes();
    let mut wire = Vec::with_capacity(108 + id.len());
    wire.push(id.len() as u8);
    wire.extend_from_slice(id);
    wire.push(entry.role as u8);
    wire.push(entry.scope as u8);
    wire.extend_from_slice(&entry.generation.to_be_bytes());
    wire.extend_from_slice(&entry.public_key);
    wire.extend_from_slice(&entry.fingerprint);
    wire.push(entry.lifecycle as u8);
    wire.extend_from_slice(&entry.activation_epoch.to_be_bytes());
    wire.extend_from_slice(&entry.activation_sequence.to_be_bytes());
    wire.extend_from_slice(&entry.terminal_epoch.to_be_bytes());
    wire.extend_from_slice(&entry.terminal_sequence.to_be_bytes());
    Ok(wire)
}

fn take<'a>(
    wire: &'a [u8],
    offset: &mut usize,
    end: usize,
    length: usize,
) -> Result<&'a [u8], SignerTrustBundleError> {
    let next = (*offset)
        .checked_add(length)
        .ok_or(SignerTrustBundleError::Malformed)?;
    if next > end {
        return Err(SignerTrustBundleError::Malformed);
    }
    let value = &wire[*offset..next];
    *offset = next;
    Ok(value)
}

fn read_array<const N: usize>(
    wire: &[u8],
    offset: &mut usize,
    end: usize,
) -> Result<[u8; N], SignerTrustBundleError> {
    take(wire, offset, end, N)?
        .try_into()
        .map_err(|_| SignerTrustBundleError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise_deployment_config::{
        encode_signed_deployment_config, verify_signed_deployment_config,
        verify_signed_deployment_config_with_floors,
    };

    pub(super) struct TestContext {
        pub(super) deployment: VerifiedDeploymentConfig,
        pub(super) deployment_wire: Vec<u8>,
        pub(super) deployment_authority: SigningKey,
        pub(super) governance: SigningKey,
        pub(super) network_id: [u8; 32],
        pub(super) profile_id: [u8; 32],
    }

    pub(super) fn test_context() -> TestContext {
        let network_id = [0x71; 32];
        let profile_id = [0x72; 32];
        let deployment_authority = SigningKey::from_bytes(&[0x41; 32]);
        let governance = SigningKey::from_bytes(&[0x42; 32]);
        let recovery = SigningKey::from_bytes(&[0x43; 32]);

        let mut root_chain = Vec::new();
        root_chain.extend_from_slice(b"GRC1");
        root_chain.extend_from_slice(&1u16.to_be_bytes());
        root_chain.extend_from_slice(&network_id);
        root_chain.extend_from_slice(&0u16.to_be_bytes());

        let deployment_wire = encode_signed_deployment_config(
            network_id,
            1,
            governance.verifying_key().to_bytes(),
            governance.verifying_key().to_bytes(),
            recovery.verifying_key().to_bytes(),
            1,
            1,
            &root_chain,
            &deployment_authority,
        )
        .unwrap();
        let deployment = verify_signed_deployment_config_with_floors(
            &deployment_wire,
            &network_id,
            &deployment_authority.verifying_key().to_bytes(),
            1,
            1,
        )
        .unwrap();

        TestContext {
            deployment,
            deployment_wire,
            deployment_authority,
            governance,
            network_id,
            profile_id,
        }
    }

    pub(super) fn accepted_entry(
        network_id: &[u8; 32],
        profile_id: &[u8; 32],
        signer_id: &str,
        role: SignerRole,
        key: &SigningKey,
    ) -> SignerTrustBundleEntry {
        let public_key = key.verifying_key().to_bytes();
        let fingerprint: [u8; 32] = Sha256::digest(public_key).into();
        let mut entry = SignerTrustBundleEntry {
            signer_id: signer_id.to_owned(),
            role,
            scope: SignerScope::PeerIdentityRotation,
            generation: 1,
            public_key,
            fingerprint,
            lifecycle: SignerLifecycle::Active,
            activation_epoch: 1,
            activation_sequence: 1,
            terminal_epoch: 0,
            terminal_sequence: 0,
            acceptance_signature: [0; 64],
        };
        let message = signer_acceptance_preimage(network_id, profile_id, &entry).unwrap();
        entry.acceptance_signature = key.sign(&message).to_bytes();
        entry
    }

    pub(super) fn valid_bundle(context: &TestContext) -> SignerTrustBundle {
        let owner = SigningKey::from_bytes(&[0x51; 32]);
        let operator = SigningKey::from_bytes(&[0x52; 32]);
        let mut entries = vec![
            accepted_entry(
                &context.network_id,
                &context.profile_id,
                "operator-main",
                SignerRole::IndependentOperator,
                &operator,
            ),
            accepted_entry(
                &context.network_id,
                &context.profile_id,
                "owner-main",
                SignerRole::OwnerAuthorizer,
                &owner,
            ),
        ];
        entries.sort_by(|left, right| left.signer_id.cmp(&right.signer_id));
        let governance_root_fingerprint: [u8; 32] =
            Sha256::digest(context.governance.verifying_key().to_bytes()).into();
        SignerTrustBundle {
            network_id: context.network_id,
            profile_id: context.profile_id,
            sequence: 2,
            previous_digest: [0x61; 32],
            governance_root_epoch: context.deployment.root_chain.current_epoch(),
            governance_root_fingerprint,
            entries,
        }
    }

    pub(super) fn encode_valid(
        context: &TestContext,
        bundle: &SignerTrustBundle,
    ) -> Result<Vec<u8>, SignerTrustBundleError> {
        encode_signed_signer_trust_bundle(
            bundle,
            &context.governance,
            &context.deployment,
            &context.profile_id,
            1,
            &[0x61; 32],
        )
    }

    #[test]
    fn successor_bundle_round_trips_and_exposes_only_verified_records() {
        let context = test_context();
        let bundle = valid_bundle(&context);
        let wire = encode_valid(&context, &bundle).unwrap();
        let verified = verify_signed_signer_trust_bundle(
            &wire,
            &context.deployment,
            &context.profile_id,
            1,
            &[0x61; 32],
        )
        .unwrap();

        assert_eq!(verified.bundle(), &bundle);
        assert_eq!(verified.bundle().sequence, 2);
        assert_eq!(verified.active_owner().unwrap().signer_id, "owner-main");
        assert_eq!(verified.active_operators().count(), 1);
        let expected_digest: [u8; 32] = Sha256::digest(&wire).into();
        assert_eq!(verified.digest(), &expected_digest);
    }

    #[test]
    fn compatibility_dpc1_context_cannot_verify_stb1() {
        let context = test_context();
        let legacy = verify_signed_deployment_config(
            &context.deployment_wire,
            &context.network_id,
            &context.deployment_authority.verifying_key().to_bytes(),
            1,
        )
        .unwrap();
        let bundle = valid_bundle(&context);
        let wire = encode_valid(&context, &bundle).unwrap();
        assert_eq!(
            verify_signed_signer_trust_bundle(&wire, &legacy, &context.profile_id, 1, &[0x61; 32],)
                .unwrap_err(),
            SignerTrustBundleError::UnverifiedDeploymentContext
        );
    }

    #[test]
    fn initial_enrollment_is_not_implicitly_authorized_by_empty_state() {
        let context = test_context();
        let bundle = valid_bundle(&context);
        let wire = encode_valid(&context, &bundle).unwrap();
        assert_eq!(
            verify_signed_signer_trust_bundle(
                &wire,
                &context.deployment,
                &context.profile_id,
                0,
                &[0; 32],
            )
            .unwrap_err(),
            SignerTrustBundleError::InitialEnrollmentRequiresSeparateAuthorization
        );
    }

    #[test]
    fn wrong_profile_network_epoch_or_root_fingerprint_rejects() {
        let context = test_context();
        let bundle = valid_bundle(&context);
        let wire = encode_valid(&context, &bundle).unwrap();

        assert_eq!(
            verify_signed_signer_trust_bundle(
                &wire,
                &context.deployment,
                &[0x73; 32],
                1,
                &[0x61; 32],
            )
            .unwrap_err(),
            SignerTrustBundleError::ProfileMismatch
        );

        let mut wrong_network = bundle.clone();
        wrong_network.network_id = [0x74; 32];
        assert_eq!(
            encode_valid(&context, &wrong_network).unwrap_err(),
            SignerTrustBundleError::NetworkMismatch
        );

        let mut wrong_epoch = bundle.clone();
        wrong_epoch.governance_root_epoch += 1;
        assert_eq!(
            encode_valid(&context, &wrong_epoch).unwrap_err(),
            SignerTrustBundleError::GovernanceRootEpochMismatch
        );

        let mut wrong_fingerprint = bundle;
        wrong_fingerprint.governance_root_fingerprint = [0x75; 32];
        assert_eq!(
            encode_valid(&context, &wrong_fingerprint).unwrap_err(),
            SignerTrustBundleError::GovernanceRootFingerprintMismatch
        );
    }

    #[test]
    fn predecessor_digest_and_sequence_are_exact() {
        let context = test_context();
        let bundle = valid_bundle(&context);
        let wire = encode_valid(&context, &bundle).unwrap();

        assert_eq!(
            verify_signed_signer_trust_bundle(
                &wire,
                &context.deployment,
                &context.profile_id,
                1,
                &[0x62; 32],
            )
            .unwrap_err(),
            SignerTrustBundleError::PredecessorMismatch
        );
        assert_eq!(
            verify_signed_signer_trust_bundle(
                &wire,
                &context.deployment,
                &context.profile_id,
                2,
                &[0x61; 32],
            )
            .unwrap_err(),
            SignerTrustBundleError::SequenceDiscontinuity
        );
    }

    #[test]
    fn missing_or_multiple_active_roles_reject() {
        let context = test_context();
        let mut missing_operator = valid_bundle(&context);
        let operator = missing_operator
            .entries
            .iter_mut()
            .find(|entry| entry.role == SignerRole::IndependentOperator)
            .unwrap();
        operator.lifecycle = SignerLifecycle::Retired;
        operator.terminal_epoch = 1;
        operator.terminal_sequence = 2;
        assert_eq!(
            encode_valid(&context, &missing_operator).unwrap_err(),
            SignerTrustBundleError::MissingActiveOperator
        );

        let owner_key = SigningKey::from_bytes(&[0x53; 32]);
        let mut multiple_owners = valid_bundle(&context);
        let mut secondary_owner = accepted_entry(
            &context.network_id,
            &context.profile_id,
            "owner-secondary",
            SignerRole::OwnerAuthorizer,
            &owner_key,
        );
        secondary_owner.generation = 2;
        let acceptance =
            signer_acceptance_preimage(&context.network_id, &context.profile_id, &secondary_owner)
                .unwrap();
        secondary_owner.acceptance_signature = owner_key.sign(&acceptance).to_bytes();
        multiple_owners.entries.push(secondary_owner);
        multiple_owners
            .entries
            .sort_by(|left, right| left.signer_id.cmp(&right.signer_id));
        assert_eq!(
            encode_valid(&context, &multiple_owners).unwrap_err(),
            SignerTrustBundleError::MultipleActiveOwners
        );
    }

    #[test]
    fn duplicate_ids_or_fingerprints_reject() {
        let context = test_context();
        let mut duplicate_id = valid_bundle(&context);
        duplicate_id.entries[1].signer_id = duplicate_id.entries[0].signer_id.clone();
        assert_eq!(
            encode_valid(&context, &duplicate_id).unwrap_err(),
            SignerTrustBundleError::DuplicateSignerId
        );

        let mut duplicate_fingerprint = valid_bundle(&context);
        duplicate_fingerprint.entries[1].public_key = duplicate_fingerprint.entries[0].public_key;
        duplicate_fingerprint.entries[1].fingerprint = duplicate_fingerprint.entries[0].fingerprint;
        assert_eq!(
            encode_valid(&context, &duplicate_fingerprint).unwrap_err(),
            SignerTrustBundleError::DuplicateSignerFingerprint
        );

        let mut duplicate_generation = valid_bundle(&context);
        let second_operator = SigningKey::from_bytes(&[0x56; 32]);
        duplicate_generation.entries.push(accepted_entry(
            &context.network_id,
            &context.profile_id,
            "operator-secondary",
            SignerRole::IndependentOperator,
            &second_operator,
        ));
        duplicate_generation
            .entries
            .sort_by(|left, right| left.signer_id.cmp(&right.signer_id));
        assert_eq!(
            encode_valid(&context, &duplicate_generation).unwrap_err(),
            SignerTrustBundleError::DuplicateSignerGeneration
        );
    }

    #[test]
    fn acceptance_receipts_and_fingerprints_are_mandatory() {
        let context = test_context();
        let mut bad_receipt = valid_bundle(&context);
        bad_receipt.entries[0].acceptance_signature[0] ^= 1;
        assert_eq!(
            encode_valid(&context, &bad_receipt).unwrap_err(),
            SignerTrustBundleError::InvalidAcceptanceSignature
        );

        let mut bad_fingerprint = valid_bundle(&context);
        bad_fingerprint.entries[0].fingerprint[0] ^= 1;
        assert_eq!(
            encode_valid(&context, &bad_fingerprint).unwrap_err(),
            SignerTrustBundleError::InvalidSignerFingerprint
        );
    }

    #[test]
    fn noncanonical_identifiers_and_record_order_reject() {
        let context = test_context();
        let mut invalid_id = valid_bundle(&context);
        invalid_id.entries[0].signer_id = "Operator-Main".to_owned();
        assert_eq!(
            encode_valid(&context, &invalid_id).unwrap_err(),
            SignerTrustBundleError::InvalidSignerId
        );

        let mut wrong_order = valid_bundle(&context);
        wrong_order.entries.reverse();
        assert_eq!(
            encode_valid(&context, &wrong_order).unwrap_err(),
            SignerTrustBundleError::NonCanonicalOrder
        );
    }

    #[test]
    fn lifecycle_terminal_coordinates_are_fail_closed() {
        let context = test_context();
        let mut active_with_terminal = valid_bundle(&context);
        active_with_terminal.entries[0].terminal_epoch = 1;
        active_with_terminal.entries[0].terminal_sequence = 2;
        assert_eq!(
            encode_valid(&context, &active_with_terminal).unwrap_err(),
            SignerTrustBundleError::InvalidTerminalState
        );

        let mut retired_without_terminal = valid_bundle(&context);
        retired_without_terminal.entries[0].lifecycle = SignerLifecycle::Retired;
        assert_eq!(
            encode_valid(&context, &retired_without_terminal).unwrap_err(),
            SignerTrustBundleError::InvalidTerminalState
        );
    }

    #[test]
    fn valid_retired_record_keeps_its_original_acceptance_receipt() {
        let context = test_context();
        let mut bundle = valid_bundle(&context);
        let retired_key = SigningKey::from_bytes(&[0x54; 32]);
        let mut retired = accepted_entry(
            &context.network_id,
            &context.profile_id,
            "operator-legacy",
            SignerRole::IndependentOperator,
            &retired_key,
        );
        retired.generation = 2;
        let acceptance =
            signer_acceptance_preimage(&context.network_id, &context.profile_id, &retired).unwrap();
        retired.acceptance_signature = retired_key.sign(&acceptance).to_bytes();
        retired.lifecycle = SignerLifecycle::Retired;
        retired.terminal_epoch = 1;
        retired.terminal_sequence = 2;
        bundle.entries.push(retired);
        bundle
            .entries
            .sort_by(|left, right| left.signer_id.cmp(&right.signer_id));

        let wire = encode_valid(&context, &bundle).unwrap();
        let verified = verify_signed_signer_trust_bundle(
            &wire,
            &context.deployment,
            &context.profile_id,
            1,
            &[0x61; 32],
        )
        .unwrap();
        assert_eq!(verified.bundle().entries.len(), 3);
        assert_eq!(verified.active_operators().count(), 1);
    }

    #[test]
    fn malformed_reserved_truncated_trailing_and_tampered_wire_reject() {
        let context = test_context();
        let bundle = valid_bundle(&context);
        let wire = encode_valid(&context, &bundle).unwrap();

        let mut bad_reserved = wire.clone();
        bad_reserved[7] = 1;
        assert_eq!(
            verify_signed_signer_trust_bundle(
                &bad_reserved,
                &context.deployment,
                &context.profile_id,
                1,
                &[0x61; 32],
            )
            .unwrap_err(),
            SignerTrustBundleError::ReservedBits
        );

        let mut bad_signature = wire.clone();
        let last = bad_signature.len() - 1;
        bad_signature[last] ^= 1;
        assert_eq!(
            verify_signed_signer_trust_bundle(
                &bad_signature,
                &context.deployment,
                &context.profile_id,
                1,
                &[0x61; 32],
            )
            .unwrap_err(),
            SignerTrustBundleError::InvalidBundleSignature
        );

        assert_eq!(
            verify_signed_signer_trust_bundle(
                &wire[..wire.len() - 1],
                &context.deployment,
                &context.profile_id,
                1,
                &[0x61; 32],
            )
            .unwrap_err(),
            SignerTrustBundleError::Malformed
        );

        let mut trailing = wire;
        trailing.push(0);
        assert_eq!(
            verify_signed_signer_trust_bundle(
                &trailing,
                &context.deployment,
                &context.profile_id,
                1,
                &[0x61; 32],
            )
            .unwrap_err(),
            SignerTrustBundleError::Malformed
        );
    }
}

/// Validate a fully verified STB1 successor against the exact previously accepted bundle.
///
/// This adds history-sensitive rules: signer records cannot disappear, identities cannot be
/// substituted, lifecycle can only advance, and a new signer record must consume a strictly
/// higher role generation. Governance-root context changes are deliberately rejected here;
/// they require a separately reviewed root-rotation migration path.
pub fn validate_signer_trust_bundle_transition(
    previous: &VerifiedSignerTrustBundle,
    next: &VerifiedSignerTrustBundle,
) -> Result<(), SignerTrustBundleError> {
    let old = previous.bundle();
    let new = next.bundle();

    if old.network_id != new.network_id || old.profile_id != new.profile_id {
        return Err(SignerTrustBundleError::StateIdentityMismatch);
    }
    if new.sequence < old.sequence {
        return Err(SignerTrustBundleError::SequenceRollback);
    }
    let expected_sequence = old
        .sequence
        .checked_add(1)
        .ok_or(SignerTrustBundleError::SequenceDiscontinuity)?;
    if new.sequence != expected_sequence {
        return Err(SignerTrustBundleError::SequenceDiscontinuity);
    }
    if new.previous_digest != *previous.digest() {
        return Err(SignerTrustBundleError::PredecessorMismatch);
    }
    if new.governance_root_epoch < old.governance_root_epoch {
        return Err(SignerTrustBundleError::RootEpochRollback);
    }
    if new.governance_root_epoch != old.governance_root_epoch
        || new.governance_root_fingerprint != old.governance_root_fingerprint
    {
        return Err(SignerTrustBundleError::GovernanceRootContextChangeRequiresMigration);
    }

    for old_entry in &old.entries {
        let new_entry = new
            .entries
            .iter()
            .find(|entry| entry.signer_id == old_entry.signer_id)
            .ok_or(SignerTrustBundleError::SignerRemoved)?;

        if old_entry.role != new_entry.role
            || old_entry.scope != new_entry.scope
            || old_entry.generation != new_entry.generation
            || old_entry.public_key != new_entry.public_key
            || old_entry.fingerprint != new_entry.fingerprint
            || old_entry.activation_epoch != new_entry.activation_epoch
            || old_entry.activation_sequence != new_entry.activation_sequence
            || old_entry.acceptance_signature != new_entry.acceptance_signature
        {
            return Err(SignerTrustBundleError::SignerIdentityChanged);
        }

        match (old_entry.lifecycle, new_entry.lifecycle) {
            (SignerLifecycle::Active, SignerLifecycle::Active) => {
                if new_entry.terminal_epoch != 0 || new_entry.terminal_sequence != 0 {
                    return Err(SignerTrustBundleError::SignerTerminalStateChanged);
                }
            }
            (SignerLifecycle::Active, SignerLifecycle::Retired | SignerLifecycle::Revoked)
            | (SignerLifecycle::Retired, SignerLifecycle::Revoked) => {
                if new_entry.terminal_epoch != new.governance_root_epoch
                    || new_entry.terminal_sequence != new.sequence
                {
                    return Err(SignerTrustBundleError::SignerTerminalStateChanged);
                }
            }
            (SignerLifecycle::Retired, SignerLifecycle::Retired)
            | (SignerLifecycle::Revoked, SignerLifecycle::Revoked) => {
                if old_entry.terminal_epoch != new_entry.terminal_epoch
                    || old_entry.terminal_sequence != new_entry.terminal_sequence
                {
                    return Err(SignerTrustBundleError::SignerTerminalStateChanged);
                }
            }
            _ => return Err(SignerTrustBundleError::SignerLifecycleRollback),
        }
    }

    let mut previous_max_generation = [0u64; 3];
    for entry in &old.entries {
        let index = entry.role as usize;
        previous_max_generation[index] = previous_max_generation[index].max(entry.generation);
    }
    for entry in &new.entries {
        if old
            .entries
            .iter()
            .any(|old_entry| old_entry.signer_id == entry.signer_id)
        {
            continue;
        }
        if entry.lifecycle != SignerLifecycle::Active
            || entry.activation_epoch != new.governance_root_epoch
            || entry.activation_sequence != new.sequence
        {
            return Err(SignerTrustBundleError::InvalidActivation);
        }
        let index = entry.role as usize;
        if entry.generation <= previous_max_generation[index] {
            return Err(SignerTrustBundleError::SignerGenerationNotAdvanced);
        }
        previous_max_generation[index] = entry.generation;
    }
    Ok(())
}

use crate::snapshot_store::{atomic_write_bytes_with_hook, SnapshotWriterLock};
use std::{
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    sync::Mutex,
};

const STB_STATE_MAGIC: &[u8; 4] = b"STH1";
const STB_STATE_VERSION: u16 = 1;
const STB_STATE_HEADER_LEN: usize = 124;
const STB_STATE_CHECKSUM_LEN: usize = 32;

#[derive(Debug, Clone)]
struct PersistedSignerTrustState {
    network_id: [u8; 32],
    profile_id: [u8; 32],
    highest_sequence: u64,
    highest_root_epoch: u64,
    highest_digest: [u8; 32],
    bundle_wire: Vec<u8>,
}

impl PersistedSignerTrustState {
    fn from_verified(bundle: &VerifiedSignerTrustBundle) -> Self {
        Self {
            network_id: bundle.bundle.network_id,
            profile_id: bundle.bundle.profile_id,
            highest_sequence: bundle.bundle.sequence,
            highest_root_epoch: bundle.bundle.governance_root_epoch,
            highest_digest: *bundle.digest(),
            bundle_wire: bundle.wire().to_vec(),
        }
    }

    fn encode(&self) -> Result<Vec<u8>, SignerTrustBundleError> {
        if self.highest_sequence == 0
            || self.highest_root_epoch == 0
            || self.highest_digest == [0; 32]
            || self.bundle_wire.len() < MIN_SIGNED_SIGNER_TRUST_BUNDLE_LEN
            || self.bundle_wire.len() > MAX_SIGNED_SIGNER_TRUST_BUNDLE_LEN
            || self.bundle_wire.len() > u32::MAX as usize
        {
            return Err(SignerTrustBundleError::StateMalformed);
        }
        let mut bytes = Vec::with_capacity(
            STB_STATE_HEADER_LEN + self.bundle_wire.len() + STB_STATE_CHECKSUM_LEN,
        );
        bytes.extend_from_slice(STB_STATE_MAGIC);
        bytes.extend_from_slice(&STB_STATE_VERSION.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&self.network_id);
        bytes.extend_from_slice(&self.profile_id);
        bytes.extend_from_slice(&self.highest_sequence.to_be_bytes());
        bytes.extend_from_slice(&self.highest_root_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.highest_digest);
        bytes.extend_from_slice(&(self.bundle_wire.len() as u32).to_be_bytes());
        if bytes.len() != STB_STATE_HEADER_LEN {
            return Err(SignerTrustBundleError::StateMalformed);
        }
        bytes.extend_from_slice(&self.bundle_wire);
        let checksum: [u8; 32] = Sha256::digest(&bytes).into();
        bytes.extend_from_slice(&checksum);
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, SignerTrustBundleError> {
        if bytes.len()
            < STB_STATE_HEADER_LEN + MIN_SIGNED_SIGNER_TRUST_BUNDLE_LEN + STB_STATE_CHECKSUM_LEN
            || bytes.len()
                > STB_STATE_HEADER_LEN + MAX_SIGNED_SIGNER_TRUST_BUNDLE_LEN + STB_STATE_CHECKSUM_LEN
            || &bytes[..4] != STB_STATE_MAGIC
        {
            return Err(SignerTrustBundleError::StateMalformed);
        }
        if u16::from_be_bytes(
            bytes[4..6]
                .try_into()
                .map_err(|_| SignerTrustBundleError::StateMalformed)?,
        ) != STB_STATE_VERSION
            || bytes[6..8] != [0, 0]
        {
            return Err(SignerTrustBundleError::StateMalformed);
        }
        let payload_end = bytes.len() - STB_STATE_CHECKSUM_LEN;
        let checksum: [u8; 32] = Sha256::digest(&bytes[..payload_end]).into();
        if checksum.as_slice() != &bytes[payload_end..] {
            return Err(SignerTrustBundleError::StateMalformed);
        }
        let network_id = bytes[8..40]
            .try_into()
            .map_err(|_| SignerTrustBundleError::StateMalformed)?;
        let profile_id = bytes[40..72]
            .try_into()
            .map_err(|_| SignerTrustBundleError::StateMalformed)?;
        let highest_sequence = u64::from_be_bytes(
            bytes[72..80]
                .try_into()
                .map_err(|_| SignerTrustBundleError::StateMalformed)?,
        );
        let highest_root_epoch = u64::from_be_bytes(
            bytes[80..88]
                .try_into()
                .map_err(|_| SignerTrustBundleError::StateMalformed)?,
        );
        let highest_digest = bytes[88..120]
            .try_into()
            .map_err(|_| SignerTrustBundleError::StateMalformed)?;
        let wire_len = u32::from_be_bytes(
            bytes[120..124]
                .try_into()
                .map_err(|_| SignerTrustBundleError::StateMalformed)?,
        ) as usize;
        if wire_len < MIN_SIGNED_SIGNER_TRUST_BUNDLE_LEN
            || wire_len > MAX_SIGNED_SIGNER_TRUST_BUNDLE_LEN
            || STB_STATE_HEADER_LEN + wire_len + STB_STATE_CHECKSUM_LEN != bytes.len()
            || highest_sequence == 0
            || highest_root_epoch == 0
            || highest_digest == [0; 32]
        {
            return Err(SignerTrustBundleError::StateMalformed);
        }
        let bundle_wire = bytes[STB_STATE_HEADER_LEN..payload_end].to_vec();
        let wire_digest: [u8; 32] = Sha256::digest(&bundle_wire).into();
        if wire_digest != highest_digest {
            return Err(SignerTrustBundleError::StateMalformed);
        }
        Ok(Self {
            network_id,
            profile_id,
            highest_sequence,
            highest_root_epoch,
            highest_digest,
            bundle_wire,
        })
    }
}

/// Local STB1 high-water store. It serializes writers, stores the exact last accepted signed
/// bundle and checksums its envelope, then reloads that bundle through the strict verifier.
/// The stable writer-lock sibling detects missing-state-after-initialization. This is local
/// filesystem protection only; it is not a TPM counter, remote witness, or hostile-Administrator
/// rollback defense. This version requires the same GRC1 root tip across reopen/update; root
/// changes need a separately reviewed migration checkpoint.
pub struct SignerTrustBundleStateStore {
    path: PathBuf,
    deployment: VerifiedDeploymentConfig,
    expected_profile_id: [u8; 32],
    _writer_lock: SnapshotWriterLock,
    current: Mutex<VerifiedSignerTrustBundle>,
}

impl SignerTrustBundleStateStore {
    /// Open an initialized store. An initial checkpoint is accepted only when neither the state
    /// file nor persistent lock sibling has existed; the caller supplies an already verified
    /// checkpoint, never an empty-state self-enrollment request.
    pub fn open(
        path: impl AsRef<Path>,
        deployment: &VerifiedDeploymentConfig,
        expected_profile_id: &[u8; 32],
        initial_checkpoint: Option<&VerifiedSignerTrustBundle>,
    ) -> Result<Self, SignerTrustBundleError> {
        validate_strict_deployment_context(deployment)?;
        if expected_profile_id == &[0; 32] {
            return Err(SignerTrustBundleError::ProfileMismatch);
        }
        let path = path.as_ref().to_path_buf();
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        if path.file_name().is_none() || !parent.is_dir() {
            return Err(SignerTrustBundleError::InvalidStatePath);
        }
        let lock_path = stb_state_lock_path(&path)?;
        let lock_existed_before = lock_path.exists();
        if !path.exists() && !lock_existed_before && initial_checkpoint.is_none() {
            return Err(SignerTrustBundleError::BootstrapCheckpointRequired);
        }
        let writer_lock =
            SnapshotWriterLock::acquire(&path).map_err(|_| SignerTrustBundleError::StateLocked)?;

        let current = if path.exists() {
            let metadata = fs::symlink_metadata(&path)
                .map_err(|_| SignerTrustBundleError::StatePersistence)?;
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.len()
                    < (STB_STATE_HEADER_LEN
                        + MIN_SIGNED_SIGNER_TRUST_BUNDLE_LEN
                        + STB_STATE_CHECKSUM_LEN) as u64
                || metadata.len()
                    > (STB_STATE_HEADER_LEN
                        + MAX_SIGNED_SIGNER_TRUST_BUNDLE_LEN
                        + STB_STATE_CHECKSUM_LEN) as u64
            {
                return Err(SignerTrustBundleError::StateMalformed);
            }
            let mut bytes = Vec::with_capacity(metadata.len() as usize);
            File::open(&path)
                .map_err(|_| SignerTrustBundleError::StatePersistence)?
                .read_to_end(&mut bytes)
                .map_err(|_| SignerTrustBundleError::StatePersistence)?;
            let state = PersistedSignerTrustState::decode(&bytes)?;
            if state.network_id != deployment.network_id || state.profile_id != *expected_profile_id
            {
                return Err(SignerTrustBundleError::StateIdentityMismatch);
            }
            verify_persisted_bundle(&state, deployment, expected_profile_id)?
        } else if lock_existed_before {
            return Err(SignerTrustBundleError::StateMissing);
        } else {
            let checkpoint =
                initial_checkpoint.ok_or(SignerTrustBundleError::BootstrapCheckpointRequired)?;
            validate_checkpoint_context(checkpoint, deployment, expected_profile_id)?;
            let state = PersistedSignerTrustState::from_verified(checkpoint);
            persist_stb_state(&path, &state)?;
            checkpoint.clone()
        };

        Ok(Self {
            path,
            deployment: deployment.clone(),
            expected_profile_id: *expected_profile_id,
            _writer_lock: writer_lock,
            current: Mutex::new(current),
        })
    }

    /// Accept one exact successor and persist it before advancing memory. Replaying the exact
    /// current bytes is idempotent; older and same-sequence-conflicting wires never mutate state.
    pub fn accept_successor(&self, wire: &[u8]) -> Result<[u8; 32], SignerTrustBundleError> {
        let mut current = self
            .current
            .lock()
            .map_err(|_| SignerTrustBundleError::StatePersistence)?;
        let candidate_digest: [u8; 32] = Sha256::digest(wire).into();
        if candidate_digest == *current.digest() {
            return Ok(candidate_digest);
        }
        if wire.len() >= 80 && &wire[..4] == MAGIC {
            let candidate_sequence = u64::from_be_bytes(
                wire[72..80]
                    .try_into()
                    .map_err(|_| SignerTrustBundleError::Malformed)?,
            );
            if candidate_sequence < current.bundle.sequence {
                return Err(SignerTrustBundleError::SequenceRollback);
            }
            if candidate_sequence == current.bundle.sequence {
                return Err(SignerTrustBundleError::SameSequenceConflict);
            }
        }
        let next = verify_signed_signer_trust_bundle(
            wire,
            &self.deployment,
            &self.expected_profile_id,
            current.bundle.sequence,
            current.digest(),
        )?;
        validate_signer_trust_bundle_transition(&current, &next)?;
        let state = PersistedSignerTrustState::from_verified(&next);
        persist_stb_state(&self.path, &state)?;
        let digest = *next.digest();
        *current = next;
        Ok(digest)
    }

    pub fn highest_sequence(&self) -> Result<u64, SignerTrustBundleError> {
        Ok(self
            .current
            .lock()
            .map_err(|_| SignerTrustBundleError::StatePersistence)?
            .bundle
            .sequence)
    }

    pub fn highest_digest(&self) -> Result<[u8; 32], SignerTrustBundleError> {
        Ok(*self
            .current
            .lock()
            .map_err(|_| SignerTrustBundleError::StatePersistence)?
            .digest())
    }

    pub fn highest_root_epoch(&self) -> Result<u64, SignerTrustBundleError> {
        Ok(self
            .current
            .lock()
            .map_err(|_| SignerTrustBundleError::StatePersistence)?
            .bundle
            .governance_root_epoch)
    }

    pub fn matches_current(
        &self,
        expected: &VerifiedSignerTrustBundle,
    ) -> Result<(), SignerTrustBundleError> {
        let current = self
            .current
            .lock()
            .map_err(|_| SignerTrustBundleError::StatePersistence)?;
        if expected.bundle.network_id != current.bundle.network_id
            || expected.bundle.profile_id != current.bundle.profile_id
        {
            return Err(SignerTrustBundleError::StateIdentityMismatch);
        }
        if expected.bundle.sequence != current.bundle.sequence || expected.digest != current.digest
        {
            return Err(SignerTrustBundleError::StateNotCurrent);
        }
        Ok(())
    }
}

fn validate_strict_deployment_context(
    deployment: &VerifiedDeploymentConfig,
) -> Result<(), SignerTrustBundleError> {
    let floor = deployment
        .verified_external_minimum_root_epoch
        .filter(|floor| *floor > 0)
        .ok_or(SignerTrustBundleError::UnverifiedDeploymentContext)?;
    if deployment.network_id == [0; 32]
        || deployment.root_chain.network_id() != &deployment.network_id
        || deployment.root_chain.current_epoch() < floor
        || deployment.minimum_root_epoch < floor
    {
        return Err(SignerTrustBundleError::UnverifiedDeploymentContext);
    }
    Ok(())
}

fn validate_checkpoint_context(
    checkpoint: &VerifiedSignerTrustBundle,
    deployment: &VerifiedDeploymentConfig,
    expected_profile_id: &[u8; 32],
) -> Result<(), SignerTrustBundleError> {
    validate_strict_deployment_context(deployment)?;
    if checkpoint.bundle.network_id != deployment.network_id
        || checkpoint.bundle.profile_id != *expected_profile_id
    {
        return Err(SignerTrustBundleError::StateIdentityMismatch);
    }
    let root_fp: [u8; 32] = Sha256::digest(deployment.root_chain.current_key()).into();
    let wire_digest: [u8; 32] = Sha256::digest(checkpoint.wire()).into();
    if checkpoint.bundle.governance_root_epoch != deployment.root_chain.current_epoch()
        || checkpoint.bundle.governance_root_fingerprint != root_fp
        || wire_digest != *checkpoint.digest()
    {
        return Err(SignerTrustBundleError::StateIdentityMismatch);
    }
    Ok(())
}

fn verify_persisted_bundle(
    state: &PersistedSignerTrustState,
    deployment: &VerifiedDeploymentConfig,
    expected_profile_id: &[u8; 32],
) -> Result<VerifiedSignerTrustBundle, SignerTrustBundleError> {
    if state.highest_sequence <= 1 {
        return Err(SignerTrustBundleError::StateMalformed);
    }
    let stored_root_epoch = u64::from_be_bytes(
        state.bundle_wire[112..120]
            .try_into()
            .map_err(|_| SignerTrustBundleError::StateMalformed)?,
    );
    let stored_root_fingerprint: [u8; 32] = state.bundle_wire[120..152]
        .try_into()
        .map_err(|_| SignerTrustBundleError::StateMalformed)?;
    let current_root_fingerprint: [u8; 32] =
        Sha256::digest(deployment.root_chain.current_key()).into();
    if stored_root_epoch > deployment.root_chain.current_epoch() {
        return Err(SignerTrustBundleError::RootEpochRollback);
    }
    if stored_root_epoch != deployment.root_chain.current_epoch()
        || stored_root_fingerprint != current_root_fingerprint
    {
        return Err(SignerTrustBundleError::GovernanceRootContextChangeRequiresMigration);
    }
    let previous_digest: [u8; 32] = state.bundle_wire[80..112]
        .try_into()
        .map_err(|_| SignerTrustBundleError::StateMalformed)?;
    let verified = verify_signed_signer_trust_bundle(
        &state.bundle_wire,
        deployment,
        expected_profile_id,
        state.highest_sequence - 1,
        &previous_digest,
    )?;
    if verified.bundle.sequence != state.highest_sequence
        || verified.bundle.governance_root_epoch != state.highest_root_epoch
        || verified.digest != state.highest_digest
    {
        return Err(SignerTrustBundleError::StateMalformed);
    }
    Ok(verified)
}

fn persist_stb_state(
    path: &Path,
    state: &PersistedSignerTrustState,
) -> Result<(), SignerTrustBundleError> {
    let bytes = state.encode()?;
    atomic_write_bytes_with_hook(path, &bytes, |_| Ok(()))
        .map_err(|_| SignerTrustBundleError::StatePersistence)
}

fn stb_state_lock_path(path: &Path) -> Result<PathBuf, SignerTrustBundleError> {
    let name = path
        .file_name()
        .ok_or(SignerTrustBundleError::InvalidStatePath)?;
    let mut lock_name = name.to_os_string();
    lock_name.push(".writer.lock");
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    Ok(parent.join(lock_name))
}

#[cfg(test)]
mod state_store_tests {
    use super::tests::{accepted_entry, encode_valid, test_context, valid_bundle, TestContext};
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn temp_dir(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("qzxb-stb1-{label}-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn checkpoint(context: &TestContext) -> VerifiedSignerTrustBundle {
        let bundle = valid_bundle(context);
        let wire = encode_valid(context, &bundle).unwrap();
        verify_signed_signer_trust_bundle(
            &wire,
            &context.deployment,
            &context.profile_id,
            1,
            &[0x61; 32],
        )
        .unwrap()
    }

    fn successor_bundle(
        _context: &TestContext,
        previous: &VerifiedSignerTrustBundle,
    ) -> SignerTrustBundle {
        let mut bundle = previous.bundle().clone();
        bundle.sequence = previous.bundle().sequence.checked_add(1).unwrap();
        bundle.previous_digest = *previous.digest();
        bundle
    }

    fn sign_successor(
        context: &TestContext,
        bundle: &SignerTrustBundle,
        previous: &VerifiedSignerTrustBundle,
    ) -> Vec<u8> {
        encode_signed_signer_trust_bundle(
            bundle,
            &context.governance,
            &context.deployment,
            &context.profile_id,
            previous.bundle().sequence,
            previous.digest(),
        )
        .unwrap()
    }

    fn new_accepted_entry(
        context: &TestContext,
        id: &str,
        role: SignerRole,
        generation: u64,
        activation_sequence: u64,
        key: &SigningKey,
    ) -> SignerTrustBundleEntry {
        let mut entry = accepted_entry(&context.network_id, &context.profile_id, id, role, key);
        entry.generation = generation;
        entry.activation_epoch = context.deployment.root_chain.current_epoch();
        entry.activation_sequence = activation_sequence;
        let message =
            signer_acceptance_preimage(&context.network_id, &context.profile_id, &entry).unwrap();
        entry.acceptance_signature = key.sign(&message).to_bytes();
        entry
    }

    fn verify_successor(
        context: &TestContext,
        wire: &[u8],
        previous: &VerifiedSignerTrustBundle,
    ) -> VerifiedSignerTrustBundle {
        verify_signed_signer_trust_bundle(
            wire,
            &context.deployment,
            &context.profile_id,
            previous.bundle().sequence,
            previous.digest(),
        )
        .unwrap()
    }

    fn replacement_operator_successor(
        context: &TestContext,
        previous: &VerifiedSignerTrustBundle,
    ) -> SignerTrustBundle {
        let mut next = successor_bundle(context, previous);
        let retired = next
            .entries
            .iter_mut()
            .find(|entry| entry.signer_id == "operator-main")
            .unwrap();
        retired.lifecycle = SignerLifecycle::Retired;
        retired.terminal_epoch = next.governance_root_epoch;
        retired.terminal_sequence = next.sequence;

        let new_key = SigningKey::from_bytes(&[0x67; 32]);
        next.entries.push(new_accepted_entry(
            context,
            "operator-next",
            SignerRole::IndependentOperator,
            2,
            next.sequence,
            &new_key,
        ));
        next.entries.sort_by(|a, b| a.signer_id.cmp(&b.signer_id));
        next
    }

    #[test]
    fn successor_transition_allows_retirement_and_higher_generation_replacement() {
        let context = test_context();
        let previous = checkpoint(&context);
        let next_bundle = replacement_operator_successor(&context, &previous);
        let wire = sign_successor(&context, &next_bundle, &previous);
        let next = verify_successor(&context, &wire, &previous);

        assert_eq!(
            validate_signer_trust_bundle_transition(&previous, &next),
            Ok(())
        );
    }

    #[test]
    fn successor_transition_rejects_removed_signer_identity_substitution_and_generation_reuse() {
        let context = test_context();
        let previous = checkpoint(&context);

        let mut removed = replacement_operator_successor(&context, &previous);
        removed
            .entries
            .retain(|entry| entry.signer_id != "operator-main");
        let removed_wire = sign_successor(&context, &removed, &previous);
        let removed_verified = verify_successor(&context, &removed_wire, &previous);
        assert_eq!(
            validate_signer_trust_bundle_transition(&previous, &removed_verified),
            Err(SignerTrustBundleError::SignerRemoved)
        );

        let mut substituted = successor_bundle(&context, &previous);
        let replacement_key = SigningKey::from_bytes(&[0x68; 32]);
        let old = substituted
            .entries
            .iter_mut()
            .find(|entry| entry.signer_id == "operator-main")
            .unwrap();
        old.public_key = replacement_key.verifying_key().to_bytes();
        old.fingerprint = Sha256::digest(old.public_key).into();
        let message =
            signer_acceptance_preimage(&context.network_id, &context.profile_id, old).unwrap();
        old.acceptance_signature = replacement_key.sign(&message).to_bytes();
        let substituted_wire = sign_successor(&context, &substituted, &previous);
        let substituted_verified = verify_successor(&context, &substituted_wire, &previous);
        assert_eq!(
            validate_signer_trust_bundle_transition(&previous, &substituted_verified),
            Err(SignerTrustBundleError::SignerIdentityChanged)
        );

        // A generation gap is a valid historical shape; a new key may not fill that gap
        // because generations must move strictly above the previous role high-water.
        let mut gap_bundle = valid_bundle(&context);
        let historic_key = SigningKey::from_bytes(&[0x69; 32]);
        let mut historic = new_accepted_entry(
            &context,
            "operator-historic-three",
            SignerRole::IndependentOperator,
            3,
            1,
            &historic_key,
        );
        historic.lifecycle = SignerLifecycle::Retired;
        historic.terminal_epoch = gap_bundle.governance_root_epoch;
        historic.terminal_sequence = gap_bundle.sequence;
        gap_bundle.entries.push(historic);
        gap_bundle
            .entries
            .sort_by(|a, b| a.signer_id.cmp(&b.signer_id));
        let gap_wire = encode_signed_signer_trust_bundle(
            &gap_bundle,
            &context.governance,
            &context.deployment,
            &context.profile_id,
            1,
            &[0x61; 32],
        )
        .unwrap();
        let gap_previous = verify_signed_signer_trust_bundle(
            &gap_wire,
            &context.deployment,
            &context.profile_id,
            1,
            &[0x61; 32],
        )
        .unwrap();

        let reused_generation = replacement_operator_successor(&context, &gap_previous);
        let reused_wire = sign_successor(&context, &reused_generation, &gap_previous);
        let reused_verified = verify_successor(&context, &reused_wire, &gap_previous);
        assert_eq!(
            validate_signer_trust_bundle_transition(&gap_previous, &reused_verified),
            Err(SignerTrustBundleError::SignerGenerationNotAdvanced)
        );
    }

    #[test]
    fn successor_transition_rejects_reactivation_and_terminal_coordinate_rewrite() {
        let context = test_context();
        let mut previous_bundle = valid_bundle(&context);
        let terminal_epoch = previous_bundle.governance_root_epoch;
        let terminal_sequence = previous_bundle.sequence;
        let operator = previous_bundle
            .entries
            .iter_mut()
            .find(|entry| entry.signer_id == "operator-main")
            .unwrap();
        operator.lifecycle = SignerLifecycle::Retired;
        operator.terminal_epoch = terminal_epoch;
        operator.terminal_sequence = terminal_sequence;
        let backup_key = SigningKey::from_bytes(&[0x59; 32]);
        previous_bundle.entries.push(new_accepted_entry(
            &context,
            "operator-backup",
            SignerRole::IndependentOperator,
            2,
            1,
            &backup_key,
        ));
        previous_bundle
            .entries
            .sort_by(|a, b| a.signer_id.cmp(&b.signer_id));

        let previous_wire = encode_signed_signer_trust_bundle(
            &previous_bundle,
            &context.governance,
            &context.deployment,
            &context.profile_id,
            1,
            &[0x61; 32],
        )
        .unwrap();
        let previous = verify_signed_signer_trust_bundle(
            &previous_wire,
            &context.deployment,
            &context.profile_id,
            1,
            &[0x61; 32],
        )
        .unwrap();

        let mut reactivated = successor_bundle(&context, &previous);
        let operator = reactivated
            .entries
            .iter_mut()
            .find(|entry| entry.signer_id == "operator-main")
            .unwrap();
        operator.lifecycle = SignerLifecycle::Active;
        operator.terminal_epoch = 0;
        operator.terminal_sequence = 0;
        let key = SigningKey::from_bytes(&[0x52; 32]);
        let message =
            signer_acceptance_preimage(&context.network_id, &context.profile_id, operator).unwrap();
        operator.acceptance_signature = key.sign(&message).to_bytes();
        let reactivated_wire = sign_successor(&context, &reactivated, &previous);
        let reactivated_verified = verify_successor(&context, &reactivated_wire, &previous);
        assert_eq!(
            validate_signer_trust_bundle_transition(&previous, &reactivated_verified),
            Err(SignerTrustBundleError::SignerLifecycleRollback)
        );

        let mut rewritten = successor_bundle(&context, &previous);
        let operator = rewritten
            .entries
            .iter_mut()
            .find(|entry| entry.signer_id == "operator-main")
            .unwrap();
        operator.terminal_sequence += 1;
        let rewritten_wire = sign_successor(&context, &rewritten, &previous);
        let rewritten_verified = verify_successor(&context, &rewritten_wire, &previous);
        assert_eq!(
            validate_signer_trust_bundle_transition(&previous, &rewritten_verified),
            Err(SignerTrustBundleError::SignerTerminalStateChanged)
        );
    }

    #[test]
    fn local_highwater_survives_restart_and_rejects_replay_and_same_sequence_conflict() {
        let context = test_context();
        let previous = checkpoint(&context);
        let next_bundle = successor_bundle(&context, &previous);
        let next_wire = sign_successor(&context, &next_bundle, &previous);
        let next_digest: [u8; 32] = Sha256::digest(&next_wire).into();
        let dir = temp_dir("durable");
        let path = dir.join("signers.sth1");

        {
            let store = SignerTrustBundleStateStore::open(
                &path,
                &context.deployment,
                &context.profile_id,
                Some(&previous),
            )
            .unwrap();
            assert_eq!(store.highest_sequence().unwrap(), 2);
            assert_eq!(store.accept_successor(&next_wire), Ok(next_digest));
            assert_eq!(store.highest_sequence().unwrap(), 3);
            assert_eq!(store.highest_digest().unwrap(), next_digest);
            assert_eq!(store.accept_successor(&next_wire), Ok(next_digest));
        }

        {
            let store = SignerTrustBundleStateStore::open(
                &path,
                &context.deployment,
                &context.profile_id,
                None,
            )
            .unwrap();
            assert_eq!(store.highest_sequence().unwrap(), 3);
            assert_eq!(store.highest_digest().unwrap(), next_digest);
            assert_eq!(
                store.matches_current(&verify_successor(&context, &next_wire, &previous)),
                Ok(())
            );
            assert_eq!(
                store.accept_successor(previous.wire()),
                Err(SignerTrustBundleError::SequenceRollback)
            );
            let mut conflicting_same_sequence = next_wire.clone();
            let last = conflicting_same_sequence.len() - 1;
            conflicting_same_sequence[last] ^= 1;
            assert_eq!(
                store.accept_successor(&conflicting_same_sequence),
                Err(SignerTrustBundleError::SameSequenceConflict)
            );
        }

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn local_highwater_fails_closed_on_missing_or_corrupt_state() {
        let context = test_context();
        let previous = checkpoint(&context);
        let dir = temp_dir("missing");
        let path = dir.join("signers.sth1");
        {
            let store = SignerTrustBundleStateStore::open(
                &path,
                &context.deployment,
                &context.profile_id,
                Some(&previous),
            )
            .unwrap();
            assert_eq!(store.highest_sequence().unwrap(), 2);
        }
        fs::remove_file(&path).unwrap();
        assert_eq!(
            SignerTrustBundleStateStore::open(
                &path,
                &context.deployment,
                &context.profile_id,
                Some(&previous),
            )
            .err()
            .unwrap(),
            SignerTrustBundleError::StateMissing
        );
        fs::remove_dir_all(&dir).unwrap();

        let dir = temp_dir("corrupt");
        let path = dir.join("signers.sth1");
        {
            let _store = SignerTrustBundleStateStore::open(
                &path,
                &context.deployment,
                &context.profile_id,
                Some(&previous),
            )
            .unwrap();
        }
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(&path, bytes).unwrap();
        assert_eq!(
            SignerTrustBundleStateStore::open(
                &path,
                &context.deployment,
                &context.profile_id,
                None,
            )
            .err()
            .unwrap(),
            SignerTrustBundleError::StateMalformed
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn local_highwater_requires_explicit_checkpoint_without_creating_lock_on_refusal() {
        let context = test_context();
        let dir = temp_dir("bootstrap-refusal");
        let path = dir.join("signers.sth1");
        assert_eq!(
            SignerTrustBundleStateStore::open(
                &path,
                &context.deployment,
                &context.profile_id,
                None,
            )
            .err()
            .unwrap(),
            SignerTrustBundleError::BootstrapCheckpointRequired
        );
        let lock_path = dir.join("signers.sth1.writer.lock");
        assert!(!lock_path.exists());
        fs::remove_dir_all(dir).unwrap();
    }
}
