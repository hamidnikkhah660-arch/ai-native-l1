//! Signed deployment trust bundle and durable local anti-rollback high-water.
//!
//! DPC1 binds the Network ID, deployment-config sequence, registry governance root, original root
//! anchor, offline recovery public key, minimum root epoch, minimum registry sequence and complete
//! signed root-chain wire bytes under a distinct deployment-authority Ed25519 signature.
//! DCS1 v2 persists the highest accepted DPC1 sequence/digest and GRC1 root epoch behind a
//! stable writer lock. Version-1 state can be upgraded only by presenting the exact currently
//! persisted signed manifest; a newer manifest cannot bootstrap an unknown prior root epoch.
//!
//! This detects manifest/root-epoch rollback while the local DCS1 state and lock sibling are intact. The
//! deployment signing key and minimum config sequence must still be supplied by a trusted launch
//! path; an attacker able to roll back that launch configuration and the local state directory is
//! outside this local-filesystem anti-rollback claim.
use crate::{
    governance_root_chain::{
        verify_governance_root_chain_with_recovery, VerifiedGovernanceRootChain,
        MAX_ROOT_CHAIN_WIRE_LEN,
    },
    snapshot_store::{SnapshotStoreError, SnapshotWriterLock},
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
};

const MANIFEST_MAGIC: &[u8; 4] = b"DPC1";
const STATE_MAGIC: &[u8; 4] = b"DCS1";
const VERSION: u16 = 1;
const MANIFEST_HEADER_LEN: usize = 162;
const MANIFEST_SIGNATURE_LEN: usize = 64;
pub const MAX_SIGNED_DEPLOYMENT_CONFIG_LEN: usize =
    MANIFEST_HEADER_LEN + MAX_ROOT_CHAIN_WIRE_LEN + MANIFEST_SIGNATURE_LEN;
const STATE_CHECKSUM_LEN: usize = 32;
const STATE_V1_CORE_LEN: usize = 110;
const STATE_V1_LEN: usize = STATE_V1_CORE_LEN + STATE_CHECKSUM_LEN;
const STATE_CORE_LEN: usize = 118;
const STATE_LEN: usize = STATE_CORE_LEN + STATE_CHECKSUM_LEN;
const STATE_VERSION: u16 = 2;
const SIGNING_DOMAIN: &[u8] = b"AIN1-NOISE-DEPLOYMENT-CONFIG-V1\0";
static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeploymentConfigError {
    Malformed,
    UnsupportedVersion,
    NetworkMismatch,
    InvalidSigningKey,
    InvalidSignature,
    InvalidGovernanceConfig,
    InvalidMinimumSequence,
    InvalidMinimumRootEpoch,
    SequenceBelowMinimum,
    RootEpochBelowMinimum,
    SequenceRollback,
    SequenceDiscontinuity,
    SameSequenceConflict,
    StateMissing,
    StateMalformed,
    StateIdentityMismatch,
    StateNotCurrent,
    StateMigrationRequired,
    RootEpochRollback,
    Persistence,
    Locked,
    InvalidPath,
}

impl std::fmt::Display for DeploymentConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed => write!(f, "deployment manifest is malformed"),
            Self::UnsupportedVersion => write!(f, "deployment manifest version is unsupported"),
            Self::NetworkMismatch => write!(f, "deployment manifest belongs to another network"),
            Self::InvalidSigningKey => write!(f, "deployment authority public key is invalid"),
            Self::InvalidSignature => write!(f, "deployment authority signature is invalid"),
            Self::InvalidGovernanceConfig => write!(
                f,
                "deployment manifest trust roles or root chain are invalid"
            ),
            Self::InvalidMinimumSequence => write!(
                f,
                "minimum deployment config sequence must be greater than zero"
            ),
            Self::InvalidMinimumRootEpoch => write!(
                f,
                "minimum governance root epoch must be greater than zero"
            ),
            Self::SequenceBelowMinimum => write!(
                f,
                "deployment config sequence is below the independently configured minimum"
            ),
            Self::RootEpochBelowMinimum => write!(
                f,
                "governance root epoch or DPC1 root floor is below the independently configured minimum"
            ),
            Self::SequenceRollback => write!(f, "deployment config sequence rollback rejected"),
            Self::SequenceDiscontinuity => write!(
                f,
                "deployment config sequence must advance by exactly one after bootstrap"
            ),
            Self::SameSequenceConflict => write!(
                f,
                "deployment config sequence already exists with different signed contents"
            ),
            Self::StateMissing => write!(f, "initialized deployment config state is missing"),
            Self::StateMalformed => write!(f, "deployment config state is malformed or corrupt"),
            Self::StateIdentityMismatch => write!(
                f,
                "deployment config state belongs to a different network or deployment authority"
            ),
            Self::StateNotCurrent => write!(
                f,
                "deployment config is not the exact current durable snapshot"
            ),
            Self::StateMigrationRequired => write!(
                f,
                "legacy DCS1 state must be upgraded using its exact current signed deployment manifest before accepting a successor"
            ),
            Self::RootEpochRollback => write!(
                f,
                "governance root epoch rollback rejected by durable DCS1 high-water state"
            ),
            Self::Persistence => write!(f, "deployment config state persistence failed"),
            Self::Locked => write!(f, "deployment config state writer lock is busy"),
            Self::InvalidPath => write!(f, "deployment config state path is invalid"),
        }
    }
}
impl std::error::Error for DeploymentConfigError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDeploymentConfig {
    pub network_id: [u8; 32],
    pub sequence: u64,
    pub governance_public_key: [u8; 32],
    pub root_anchor_public_key: [u8; 32],
    pub root_recovery_public_key: [u8; 32],
    pub minimum_root_epoch: u64,
    pub minimum_registry_sequence: u64,
    pub root_chain_wire: Vec<u8>,
    pub root_chain: VerifiedGovernanceRootChain,
    pub digest: [u8; 32],
    deployment_authority_fingerprint: [u8; 32],
    // Set only by the strict verifier; legacy compatibility verification leaves this unset.
    pub(crate) verified_external_minimum_root_epoch: Option<u64>,
}

/// Compatibility verifier: validates the root epoch floor carried inside DPC1.
/// Callers requiring an independently configured rollback floor must use
/// `verify_signed_deployment_config_with_floors`.
/// DPC1 fields are signed together with the complete GRC1 root chain (no path indirection).
pub fn verify_signed_deployment_config(
    wire: &[u8],
    expected_network_id: &[u8; 32],
    deployment_authority_public_key: &[u8; 32],
    minimum_sequence: u64,
) -> Result<VerifiedDeploymentConfig, DeploymentConfigError> {
    if minimum_sequence == 0 {
        return Err(DeploymentConfigError::InvalidMinimumSequence);
    }
    if wire.len() < MANIFEST_HEADER_LEN + 40 + MANIFEST_SIGNATURE_LEN
        || wire.len() > MAX_SIGNED_DEPLOYMENT_CONFIG_LEN
        || &wire[..4] != MANIFEST_MAGIC
    {
        return Err(DeploymentConfigError::Malformed);
    }
    let version = u16::from_be_bytes(
        wire[4..6]
            .try_into()
            .map_err(|_| DeploymentConfigError::Malformed)?,
    );
    if version != VERSION {
        return Err(DeploymentConfigError::UnsupportedVersion);
    }
    let network_id: [u8; 32] = wire[6..38]
        .try_into()
        .map_err(|_| DeploymentConfigError::Malformed)?;
    if &network_id != expected_network_id {
        return Err(DeploymentConfigError::NetworkMismatch);
    }
    let sequence = u64::from_be_bytes(
        wire[38..46]
            .try_into()
            .map_err(|_| DeploymentConfigError::Malformed)?,
    );
    if sequence == 0 || sequence < minimum_sequence {
        return Err(DeploymentConfigError::SequenceBelowMinimum);
    }
    let governance_public_key: [u8; 32] = wire[46..78]
        .try_into()
        .map_err(|_| DeploymentConfigError::Malformed)?;
    let root_anchor_public_key: [u8; 32] = wire[78..110]
        .try_into()
        .map_err(|_| DeploymentConfigError::Malformed)?;
    let root_recovery_public_key: [u8; 32] = wire[110..142]
        .try_into()
        .map_err(|_| DeploymentConfigError::Malformed)?;
    let minimum_root_epoch = u64::from_be_bytes(
        wire[142..150]
            .try_into()
            .map_err(|_| DeploymentConfigError::Malformed)?,
    );
    let minimum_registry_sequence = u64::from_be_bytes(
        wire[150..158]
            .try_into()
            .map_err(|_| DeploymentConfigError::Malformed)?,
    );
    let root_chain_len = u32::from_be_bytes(
        wire[158..162]
            .try_into()
            .map_err(|_| DeploymentConfigError::Malformed)?,
    ) as usize;
    if minimum_root_epoch == 0
        || minimum_registry_sequence == 0
        || root_chain_len < 40
        || root_chain_len > MAX_ROOT_CHAIN_WIRE_LEN
        || MANIFEST_HEADER_LEN
            .checked_add(root_chain_len)
            .and_then(|n| n.checked_add(MANIFEST_SIGNATURE_LEN))
            != Some(wire.len())
    {
        return Err(DeploymentConfigError::Malformed);
    }
    let signer = VerifyingKey::from_bytes(deployment_authority_public_key)
        .map_err(|_| DeploymentConfigError::InvalidSigningKey)?;
    if *deployment_authority_public_key == governance_public_key
        || *deployment_authority_public_key == root_anchor_public_key
        || *deployment_authority_public_key == root_recovery_public_key
    {
        return Err(DeploymentConfigError::InvalidGovernanceConfig);
    }
    let root_chain_wire = wire[MANIFEST_HEADER_LEN..MANIFEST_HEADER_LEN + root_chain_len].to_vec();
    let root_chain = verify_governance_root_chain_with_recovery(
        &root_chain_wire,
        &network_id,
        &root_anchor_public_key,
        &root_recovery_public_key,
        &governance_public_key,
        minimum_root_epoch,
    )
    .map_err(|_| DeploymentConfigError::InvalidGovernanceConfig)?;
    if root_chain.contains_root(deployment_authority_public_key) {
        return Err(DeploymentConfigError::InvalidGovernanceConfig);
    }
    let signature_offset = wire.len() - MANIFEST_SIGNATURE_LEN;
    let signature = Signature::from_slice(&wire[signature_offset..])
        .map_err(|_| DeploymentConfigError::InvalidSignature)?;
    let mut preimage = Vec::with_capacity(SIGNING_DOMAIN.len() + signature_offset);
    preimage.extend_from_slice(SIGNING_DOMAIN);
    preimage.extend_from_slice(&wire[..signature_offset]);
    signer
        .verify_strict(&preimage, &signature)
        .map_err(|_| DeploymentConfigError::InvalidSignature)?;
    let digest: [u8; 32] = Sha256::digest(wire).into();
    let deployment_authority_fingerprint: [u8; 32] =
        Sha256::digest(deployment_authority_public_key).into();
    Ok(VerifiedDeploymentConfig {
        network_id,
        sequence,
        governance_public_key,
        root_anchor_public_key,
        root_recovery_public_key,
        minimum_root_epoch,
        minimum_registry_sequence,
        root_chain_wire,
        root_chain,
        digest,
        deployment_authority_fingerprint,
        verified_external_minimum_root_epoch: None,
    })
}

/// Strict verifier that applies both independently supplied rollback floors.
///
/// The deployment-authority key, minimum config sequence, and minimum root epoch must come
/// from trusted launch configuration, not from the writable DPC1/DCS1 directory. The signed
/// DPC1 root floor must acknowledge at least the external root-epoch floor, and the verified
/// GRC1 tip must meet that floor as well.
pub fn verify_signed_deployment_config_with_floors(
    wire: &[u8],
    expected_network_id: &[u8; 32],
    deployment_authority_public_key: &[u8; 32],
    minimum_sequence: u64,
    minimum_root_epoch: u64,
) -> Result<VerifiedDeploymentConfig, DeploymentConfigError> {
    if minimum_root_epoch == 0 {
        return Err(DeploymentConfigError::InvalidMinimumRootEpoch);
    }
    let mut verified = verify_signed_deployment_config(
        wire,
        expected_network_id,
        deployment_authority_public_key,
        minimum_sequence,
    )?;
    if verified.minimum_root_epoch < minimum_root_epoch
        || verified.root_chain.current_epoch() < minimum_root_epoch
    {
        return Err(DeploymentConfigError::RootEpochBelowMinimum);
    }
    verified.verified_external_minimum_root_epoch = Some(minimum_root_epoch);
    Ok(verified)
}

/// Build and locally verify a DPC1 manifest using the canonical wire format. The signing key must
/// be provided by an offline operator tool; this function never stores key material.
pub fn encode_signed_deployment_config(
    network_id: [u8; 32],
    sequence: u64,
    governance_public_key: [u8; 32],
    root_anchor_public_key: [u8; 32],
    root_recovery_public_key: [u8; 32],
    minimum_root_epoch: u64,
    minimum_registry_sequence: u64,
    root_chain_wire: &[u8],
    signing_key: &SigningKey,
) -> Result<Vec<u8>, DeploymentConfigError> {
    if sequence == 0
        || minimum_root_epoch == 0
        || minimum_registry_sequence == 0
        || root_chain_wire.len() < 40
        || root_chain_wire.len() > MAX_ROOT_CHAIN_WIRE_LEN
        || root_chain_wire.len() > u32::MAX as usize
    {
        return Err(DeploymentConfigError::Malformed);
    }
    let authority_public_key = signing_key.verifying_key().to_bytes();
    if authority_public_key == governance_public_key
        || authority_public_key == root_anchor_public_key
        || authority_public_key == root_recovery_public_key
    {
        return Err(DeploymentConfigError::InvalidGovernanceConfig);
    }
    let mut wire =
        Vec::with_capacity(MANIFEST_HEADER_LEN + root_chain_wire.len() + MANIFEST_SIGNATURE_LEN);
    wire.extend_from_slice(MANIFEST_MAGIC);
    wire.extend_from_slice(&VERSION.to_be_bytes());
    wire.extend_from_slice(&network_id);
    wire.extend_from_slice(&sequence.to_be_bytes());
    wire.extend_from_slice(&governance_public_key);
    wire.extend_from_slice(&root_anchor_public_key);
    wire.extend_from_slice(&root_recovery_public_key);
    wire.extend_from_slice(&minimum_root_epoch.to_be_bytes());
    wire.extend_from_slice(&minimum_registry_sequence.to_be_bytes());
    wire.extend_from_slice(&(root_chain_wire.len() as u32).to_be_bytes());
    wire.extend_from_slice(root_chain_wire);
    let mut preimage = Vec::with_capacity(SIGNING_DOMAIN.len() + wire.len());
    preimage.extend_from_slice(SIGNING_DOMAIN);
    preimage.extend_from_slice(&wire);
    wire.extend_from_slice(&signing_key.sign(&preimage).to_bytes());
    verify_signed_deployment_config(&wire, &network_id, &authority_public_key, 1)?;
    Ok(wire)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PersistedDeploymentState {
    format_version: u16,
    network_id: [u8; 32],
    authority_fingerprint: [u8; 32],
    highest_sequence: u64,
    manifest_digest: [u8; 32],
    highest_root_epoch: u64,
}

impl PersistedDeploymentState {
    fn empty(network_id: [u8; 32], authority_fingerprint: [u8; 32]) -> Self {
        Self {
            format_version: STATE_VERSION,
            network_id,
            authority_fingerprint,
            highest_sequence: 0,
            manifest_digest: [0; 32],
            highest_root_epoch: 0,
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(STATE_LEN);
        bytes.extend_from_slice(STATE_MAGIC);
        bytes.extend_from_slice(&STATE_VERSION.to_be_bytes());
        bytes.extend_from_slice(&self.network_id);
        bytes.extend_from_slice(&self.authority_fingerprint);
        bytes.extend_from_slice(&self.highest_sequence.to_be_bytes());
        bytes.extend_from_slice(&self.manifest_digest);
        bytes.extend_from_slice(&self.highest_root_epoch.to_be_bytes());
        let checksum: [u8; 32] = Sha256::digest(&bytes).into();
        bytes.extend_from_slice(&checksum);
        bytes
    }

    fn decode(
        bytes: &[u8],
        expected_network: &[u8; 32],
        expected_authority_fingerprint: &[u8; 32],
    ) -> Result<Self, DeploymentConfigError> {
        if bytes.len() < 6 || &bytes[..4] != STATE_MAGIC {
            return Err(DeploymentConfigError::StateMalformed);
        }
        let version = u16::from_be_bytes(
            bytes[4..6]
                .try_into()
                .map_err(|_| DeploymentConfigError::StateMalformed)?,
        );
        let (core_len, expected_len) = match version {
            1 => (STATE_V1_CORE_LEN, STATE_V1_LEN),
            STATE_VERSION => (STATE_CORE_LEN, STATE_LEN),
            _ => return Err(DeploymentConfigError::StateMalformed),
        };
        if bytes.len() != expected_len {
            return Err(DeploymentConfigError::StateMalformed);
        }
        let checksum: [u8; 32] = Sha256::digest(&bytes[..core_len]).into();
        if checksum.as_slice() != &bytes[core_len..] {
            return Err(DeploymentConfigError::StateMalformed);
        }
        let network_id: [u8; 32] = bytes[6..38]
            .try_into()
            .map_err(|_| DeploymentConfigError::StateMalformed)?;
        let authority_fingerprint: [u8; 32] = bytes[38..70]
            .try_into()
            .map_err(|_| DeploymentConfigError::StateMalformed)?;
        if &network_id != expected_network
            || &authority_fingerprint != expected_authority_fingerprint
        {
            return Err(DeploymentConfigError::StateIdentityMismatch);
        }
        let highest_sequence = u64::from_be_bytes(
            bytes[70..78]
                .try_into()
                .map_err(|_| DeploymentConfigError::StateMalformed)?,
        );
        let manifest_digest: [u8; 32] = bytes[78..110]
            .try_into()
            .map_err(|_| DeploymentConfigError::StateMalformed)?;
        let highest_root_epoch = if version == STATE_VERSION {
            u64::from_be_bytes(
                bytes[110..118]
                    .try_into()
                    .map_err(|_| DeploymentConfigError::StateMalformed)?,
            )
        } else {
            0
        };
        if version == STATE_VERSION
            && ((highest_sequence == 0 && (manifest_digest != [0; 32] || highest_root_epoch != 0))
                || (highest_sequence != 0
                    && (manifest_digest == [0; 32] || highest_root_epoch == 0)))
        {
            return Err(DeploymentConfigError::StateMalformed);
        }
        Ok(Self {
            format_version: version,
            network_id,
            authority_fingerprint,
            highest_sequence,
            manifest_digest,
            highest_root_epoch,
        })
    }
}

pub struct DeploymentConfigStateStore {
    path: PathBuf,
    network_id: [u8; 32],
    authority_fingerprint: [u8; 32],
    minimum_sequence: u64,
    _writer_lock: SnapshotWriterLock,
    state: Mutex<PersistedDeploymentState>,
}

impl DeploymentConfigStateStore {
    pub fn open(
        path: impl AsRef<Path>,
        network_id: &[u8; 32],
        deployment_authority_public_key: &[u8; 32],
        minimum_sequence: u64,
    ) -> Result<Self, DeploymentConfigError> {
        if minimum_sequence == 0 {
            return Err(DeploymentConfigError::InvalidMinimumSequence);
        }
        VerifyingKey::from_bytes(deployment_authority_public_key)
            .map_err(|_| DeploymentConfigError::InvalidSigningKey)?;
        let authority_fingerprint: [u8; 32] =
            Sha256::digest(deployment_authority_public_key).into();
        let path = path.as_ref().to_path_buf();
        let parent = parent_directory(&path);
        if path.file_name().is_none() || !parent.is_dir() {
            return Err(DeploymentConfigError::InvalidPath);
        }
        let lock_path = lock_path_for(&path)?;
        let lock_existed_before = lock_path.exists();
        let writer_lock = SnapshotWriterLock::acquire(&path).map_err(map_lock_error)?;
        let state = if path.exists() {
            let metadata =
                fs::symlink_metadata(&path).map_err(|_| DeploymentConfigError::Persistence)?;
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || (metadata.len() != STATE_V1_LEN as u64 && metadata.len() != STATE_LEN as u64)
            {
                return Err(DeploymentConfigError::StateMalformed);
            }
            let mut bytes = Vec::with_capacity(metadata.len() as usize);
            File::open(&path)
                .map_err(|_| DeploymentConfigError::Persistence)?
                .read_to_end(&mut bytes)
                .map_err(|_| DeploymentConfigError::Persistence)?;
            PersistedDeploymentState::decode(&bytes, network_id, &authority_fingerprint)?
        } else if lock_existed_before {
            return Err(DeploymentConfigError::StateMissing);
        } else {
            let initial = PersistedDeploymentState::empty(*network_id, authority_fingerprint);
            persist_atomic(&path, &initial.encode())?;
            initial
        };
        Ok(Self {
            path,
            network_id: *network_id,
            authority_fingerprint,
            minimum_sequence,
            _writer_lock: writer_lock,
            state: Mutex::new(state),
        })
    }

    /// Persist an already signature- and policy-verified manifest before the node begins listening.
    /// After bootstrap the sequence must advance exactly one; idempotent restarts accept only the
    /// same sequence with the exact same signed manifest digest.
    pub fn observe(
        &self,
        manifest: &VerifiedDeploymentConfig,
    ) -> Result<(), DeploymentConfigError> {
        if manifest.network_id != self.network_id
            || manifest.deployment_authority_fingerprint != self.authority_fingerprint
        {
            return Err(DeploymentConfigError::StateIdentityMismatch);
        }
        if manifest.sequence < self.minimum_sequence {
            return Err(DeploymentConfigError::SequenceBelowMinimum);
        }
        let mut current = self
            .state
            .lock()
            .map_err(|_| DeploymentConfigError::Persistence)?;
        let manifest_root_epoch = manifest.root_chain.current_epoch();
        if manifest_root_epoch == 0 {
            return Err(DeploymentConfigError::InvalidGovernanceConfig);
        }

        // DCS1 v1 did not retain the accepted GRC1 tip epoch. Upgrade it only when the caller
        // presents the exact current signed DPC1 whose digest is already in that legacy state.
        // A successor cannot establish the unknown predecessor epoch and therefore fails closed.
        if current.format_version == 1 && current.highest_sequence != 0 {
            if manifest.sequence < current.highest_sequence {
                return Err(DeploymentConfigError::SequenceRollback);
            }
            if manifest.sequence == current.highest_sequence {
                if manifest.digest != current.manifest_digest {
                    return Err(DeploymentConfigError::SameSequenceConflict);
                }
                let next = PersistedDeploymentState {
                    format_version: STATE_VERSION,
                    network_id: current.network_id,
                    authority_fingerprint: current.authority_fingerprint,
                    highest_sequence: current.highest_sequence,
                    manifest_digest: current.manifest_digest,
                    highest_root_epoch: manifest_root_epoch,
                };
                persist_atomic(&self.path, &next.encode())?;
                *current = next;
                return Ok(());
            }
            return Err(DeploymentConfigError::StateMigrationRequired);
        }

        if current.highest_sequence == 0 {
            let next = PersistedDeploymentState {
                format_version: STATE_VERSION,
                network_id: current.network_id,
                authority_fingerprint: current.authority_fingerprint,
                highest_sequence: manifest.sequence,
                manifest_digest: manifest.digest,
                highest_root_epoch: manifest_root_epoch,
            };
            persist_atomic(&self.path, &next.encode())?;
            *current = next;
            return Ok(());
        }
        if manifest.sequence < current.highest_sequence {
            return Err(DeploymentConfigError::SequenceRollback);
        }
        if manifest.sequence == current.highest_sequence {
            if manifest.digest != current.manifest_digest {
                return Err(DeploymentConfigError::SameSequenceConflict);
            }
            return if manifest_root_epoch == current.highest_root_epoch {
                Ok(())
            } else {
                Err(DeploymentConfigError::StateMalformed)
            };
        }
        let expected = current
            .highest_sequence
            .checked_add(1)
            .ok_or(DeploymentConfigError::SequenceDiscontinuity)?;
        if manifest.sequence != expected {
            return Err(DeploymentConfigError::SequenceDiscontinuity);
        }
        if manifest_root_epoch < current.highest_root_epoch {
            return Err(DeploymentConfigError::RootEpochRollback);
        }
        let next = PersistedDeploymentState {
            format_version: STATE_VERSION,
            network_id: current.network_id,
            authority_fingerprint: current.authority_fingerprint,
            highest_sequence: manifest.sequence,
            manifest_digest: manifest.digest,
            highest_root_epoch: manifest_root_epoch,
        };
        persist_atomic(&self.path, &next.encode())?;
        *current = next;
        Ok(())
    }

    /// Read-only exact-current check against an already-open, initialized DCS1 store.
    pub fn matches_current(
        &self,
        manifest: &VerifiedDeploymentConfig,
    ) -> Result<(), DeploymentConfigError> {
        if manifest.network_id != self.network_id
            || manifest.deployment_authority_fingerprint != self.authority_fingerprint
        {
            return Err(DeploymentConfigError::StateIdentityMismatch);
        }
        let current = self
            .state
            .lock()
            .map_err(|_| DeploymentConfigError::Persistence)?;
        if current.format_version != STATE_VERSION {
            return Err(DeploymentConfigError::StateMigrationRequired);
        }
        if current.highest_sequence == 0 {
            return Err(DeploymentConfigError::StateMissing);
        }
        if current.highest_sequence != manifest.sequence
            || current.manifest_digest != manifest.digest
            || current.highest_root_epoch != manifest.root_chain.current_epoch()
        {
            return Err(DeploymentConfigError::StateNotCurrent);
        }
        Ok(())
    }

    pub fn highest_sequence(&self) -> Result<u64, DeploymentConfigError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| DeploymentConfigError::Persistence)?
            .highest_sequence)
    }

    pub fn highest_root_epoch(&self) -> Result<u64, DeploymentConfigError> {
        let current = self
            .state
            .lock()
            .map_err(|_| DeploymentConfigError::Persistence)?;
        if current.format_version != STATE_VERSION {
            return Err(DeploymentConfigError::StateMigrationRequired);
        }
        Ok(current.highest_root_epoch)
    }
}

fn lock_path_for(path: &Path) -> Result<PathBuf, DeploymentConfigError> {
    let name = path.file_name().ok_or(DeploymentConfigError::InvalidPath)?;
    Ok(parent_directory(path).join(format!("{}.writer.lock", name.to_string_lossy())))
}
fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}
fn map_lock_error(_: SnapshotStoreError) -> DeploymentConfigError {
    DeploymentConfigError::Locked
}
fn persist_atomic(path: &Path, bytes: &[u8]) -> Result<(), DeploymentConfigError> {
    let parent = parent_directory(path);
    let name = path
        .file_name()
        .ok_or(DeploymentConfigError::InvalidPath)?
        .to_string_lossy();
    let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(".{name}.dpc1.{}.{}.tmp", std::process::id(), id));
    let result = (|| -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.flush()?;
        file.sync_all()?;
        drop(file);
        atomic_replace(&temporary, path)?;
        #[cfg(unix)]
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(|_| DeploymentConfigError::Persistence)
}

#[cfg(windows)]
fn atomic_replace(source: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;
    let from: Vec<u16> = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let to: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    #[link(name = "Kernel32")]
    extern "system" {
        fn MoveFileExW(existing: *const u16, new_name: *const u16, flags: u32) -> i32;
    }
    let ok = unsafe {
        MoveFileExW(
            from.as_ptr(),
            to.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
#[cfg(not(windows))]
fn atomic_replace(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "ain1-dpc1-{label}-{}-{nonce}.bin",
            std::process::id()
        ))
    }

    fn encode_legacy_state_v1(
        network: [u8; 32],
        authority_public_key: &[u8; 32],
        sequence: u64,
        manifest_digest: [u8; 32],
    ) -> Vec<u8> {
        let authority_fingerprint: [u8; 32] = Sha256::digest(authority_public_key).into();
        let mut bytes = Vec::with_capacity(STATE_V1_LEN);
        bytes.extend_from_slice(STATE_MAGIC);
        bytes.extend_from_slice(&1u16.to_be_bytes());
        bytes.extend_from_slice(&network);
        bytes.extend_from_slice(&authority_fingerprint);
        bytes.extend_from_slice(&sequence.to_be_bytes());
        bytes.extend_from_slice(&manifest_digest);
        let checksum: [u8; 32] = Sha256::digest(&bytes).into();
        bytes.extend_from_slice(&checksum);
        assert_eq!(bytes.len(), STATE_V1_LEN);
        bytes
    }

    fn make_root_chain(network: [u8; 32], root: &SigningKey) -> Vec<u8> {
        let mut wire = b"GRC1".to_vec();
        wire.extend_from_slice(&1u16.to_be_bytes());
        wire.extend_from_slice(&network);
        wire.extend_from_slice(&0u16.to_be_bytes());
        assert_eq!(wire.len(), 40);
        let _ = root;
        wire
    }

    fn make_root_chain_with_successor(
        network: [u8; 32],
        anchor: &SigningKey,
        current: &SigningKey,
    ) -> Vec<u8> {
        let mut wire = b"GRC1".to_vec();
        wire.extend_from_slice(&1u16.to_be_bytes());
        wire.extend_from_slice(&network);
        wire.extend_from_slice(&1u16.to_be_bytes());

        let mut core = Vec::with_capacity(72);
        core.extend_from_slice(&2u64.to_be_bytes());
        core.extend_from_slice(&anchor.verifying_key().to_bytes());
        core.extend_from_slice(&current.verifying_key().to_bytes());

        let mut preimage = b"AIN1-NOISE-GOVERNANCE-ROOT-ROTATION-V1\0".to_vec();
        preimage.extend_from_slice(&network);
        preimage.extend_from_slice(&core);
        wire.extend_from_slice(&core);
        wire.extend_from_slice(&anchor.sign(&preimage).to_bytes());
        wire.extend_from_slice(&current.sign(&preimage).to_bytes());
        wire
    }

    fn encode_manifest(
        network: [u8; 32],
        sequence: u64,
        governance: &SigningKey,
        anchor: &SigningKey,
        recovery: &SigningKey,
        minimum_root_epoch: u64,
        minimum_registry_sequence: u64,
        root_chain: &[u8],
        deployment_authority: &SigningKey,
    ) -> Vec<u8> {
        let mut core = Vec::new();
        core.extend_from_slice(MANIFEST_MAGIC);
        core.extend_from_slice(&VERSION.to_be_bytes());
        core.extend_from_slice(&network);
        core.extend_from_slice(&sequence.to_be_bytes());
        core.extend_from_slice(&governance.verifying_key().to_bytes());
        core.extend_from_slice(&anchor.verifying_key().to_bytes());
        core.extend_from_slice(&recovery.verifying_key().to_bytes());
        core.extend_from_slice(&minimum_root_epoch.to_be_bytes());
        core.extend_from_slice(&minimum_registry_sequence.to_be_bytes());
        core.extend_from_slice(&(root_chain.len() as u32).to_be_bytes());
        core.extend_from_slice(root_chain);
        let mut preimage = SIGNING_DOMAIN.to_vec();
        preimage.extend_from_slice(&core);
        core.extend_from_slice(&deployment_authority.sign(&preimage).to_bytes());
        core
    }

    #[test]
    fn signed_manifest_binds_network_keys_floors_and_chain() {
        let deployment = SigningKey::from_bytes(&[0xd1; 32]);
        let governance = SigningKey::from_bytes(&[0xd2; 32]);
        let recovery = SigningKey::from_bytes(&[0xd3; 32]);
        let wrong_signer = SigningKey::from_bytes(&[0xde; 32]);
        let network = [0xe1; 32];
        let chain = make_root_chain(network, &governance);
        let wire = encode_manifest(
            network,
            1,
            &governance,
            &governance,
            &recovery,
            1,
            1,
            &chain,
            &deployment,
        );
        let verified = verify_signed_deployment_config(
            &wire,
            &network,
            &deployment.verifying_key().to_bytes(),
            1,
        )
        .unwrap();
        assert_eq!(verified.sequence, 1);
        assert_eq!(
            verified.governance_public_key,
            governance.verifying_key().to_bytes()
        );
        assert_eq!(verified.root_chain.current_epoch(), 1);

        assert_eq!(
            verify_signed_deployment_config(
                &wire,
                &[0xff; 32],
                &deployment.verifying_key().to_bytes(),
                1
            )
            .unwrap_err(),
            DeploymentConfigError::NetworkMismatch
        );
        assert_eq!(
            verify_signed_deployment_config(
                &wire,
                &network,
                &wrong_signer.verifying_key().to_bytes(),
                1
            )
            .unwrap_err(),
            DeploymentConfigError::InvalidSignature
        );
        assert_eq!(
            verify_signed_deployment_config(
                &wire,
                &network,
                &deployment.verifying_key().to_bytes(),
                2
            )
            .unwrap_err(),
            DeploymentConfigError::SequenceBelowMinimum
        );
        let mut tampered = wire.clone();
        tampered[150] ^= 1; // minimum registry sequence is covered by deployment signature
        assert_eq!(
            verify_signed_deployment_config(
                &tampered,
                &network,
                &deployment.verifying_key().to_bytes(),
                1
            )
            .unwrap_err(),
            DeploymentConfigError::InvalidSignature
        );
    }

    #[test]
    fn strict_verifier_enforces_independent_governance_root_epoch_floor() {
        let deployment = SigningKey::from_bytes(&[0xf1; 32]);
        let anchor = SigningKey::from_bytes(&[0xf2; 32]);
        let next_root = SigningKey::from_bytes(&[0xf3; 32]);
        let recovery = SigningKey::from_bytes(&[0xf4; 32]);
        let network = [0xf5; 32];
        let signer = deployment.verifying_key().to_bytes();

        let epoch_one_chain = make_root_chain(network, &anchor);
        let epoch_one = encode_manifest(
            network,
            1,
            &anchor,
            &anchor,
            &recovery,
            1,
            1,
            &epoch_one_chain,
            &deployment,
        );

        // The compatibility parser accepts the signed embedded floor, but the strict API
        // rejects this otherwise-valid manifest when the independently trusted floor is 2.
        assert!(verify_signed_deployment_config(&epoch_one, &network, &signer, 1).is_ok());
        assert_eq!(
            verify_signed_deployment_config_with_floors(&epoch_one, &network, &signer, 1, 2,)
                .unwrap_err(),
            DeploymentConfigError::RootEpochBelowMinimum
        );

        let epoch_two_chain = make_root_chain_with_successor(network, &anchor, &next_root);
        let epoch_two = encode_manifest(
            network,
            2,
            &next_root,
            &anchor,
            &recovery,
            2,
            1,
            &epoch_two_chain,
            &deployment,
        );
        let verified =
            verify_signed_deployment_config_with_floors(&epoch_two, &network, &signer, 2, 2)
                .unwrap();
        assert_eq!(verified.minimum_root_epoch, 2);
        assert_eq!(verified.root_chain.current_epoch(), 2);

        assert_eq!(
            verify_signed_deployment_config_with_floors(&epoch_two, &network, &signer, 2, 0,)
                .unwrap_err(),
            DeploymentConfigError::InvalidMinimumRootEpoch
        );
    }

    #[test]
    fn deployment_state_persists_highwater_and_rejects_replay_conflict_and_missing_state() {
        let path = temp_path("highwater");
        let deployment = SigningKey::from_bytes(&[0xd4; 32]);
        let governance = SigningKey::from_bytes(&[0xd5; 32]);
        let recovery = SigningKey::from_bytes(&[0xd6; 32]);
        let network = [0xe2; 32];
        let chain = make_root_chain(network, &governance);
        let signer = deployment.verifying_key().to_bytes();
        let one_wire = encode_manifest(
            network,
            1,
            &governance,
            &governance,
            &recovery,
            1,
            1,
            &chain,
            &deployment,
        );
        let one = verify_signed_deployment_config(&one_wire, &network, &signer, 1).unwrap();
        {
            let store = DeploymentConfigStateStore::open(&path, &network, &signer, 1).unwrap();
            store.observe(&one).unwrap();
            assert_eq!(store.highest_sequence().unwrap(), 1);
        }
        let two_wire = encode_manifest(
            network,
            2,
            &governance,
            &governance,
            &recovery,
            1,
            1,
            &chain,
            &deployment,
        );
        let two = verify_signed_deployment_config(&two_wire, &network, &signer, 1).unwrap();
        {
            let store = DeploymentConfigStateStore::open(&path, &network, &signer, 1).unwrap();
            store.observe(&one).unwrap(); // exact same signed config is idempotent on restart
            store.observe(&two).unwrap();
            assert_eq!(store.highest_sequence().unwrap(), 2);
            assert_eq!(store.highest_root_epoch().unwrap(), 1);
            store.matches_current(&two).unwrap();
            assert_eq!(
                store.observe(&one),
                Err(DeploymentConfigError::SequenceRollback)
            );
            let conflict_wire = encode_manifest(
                network,
                2,
                &governance,
                &governance,
                &recovery,
                1,
                2,
                &chain,
                &deployment,
            );
            let conflict =
                verify_signed_deployment_config(&conflict_wire, &network, &signer, 1).unwrap();
            assert_eq!(
                store.observe(&conflict),
                Err(DeploymentConfigError::SameSequenceConflict)
            );
        }
        let lock_path = path.with_file_name(format!(
            "{}.writer.lock",
            path.file_name().unwrap().to_string_lossy()
        ));
        fs::remove_file(&path).unwrap();
        assert!(matches!(
            DeploymentConfigStateStore::open(&path, &network, &signer, 1),
            Err(DeploymentConfigError::StateMissing)
        ));
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(lock_path);
    }

    #[test]
    fn deployment_state_v2_persists_root_epoch_and_rejects_epoch_rollback() {
        let path = temp_path("root-epoch-highwater");
        let deployment = SigningKey::from_bytes(&[0xa1; 32]);
        let anchor = SigningKey::from_bytes(&[0xa2; 32]);
        let next_root = SigningKey::from_bytes(&[0xa3; 32]);
        let recovery = SigningKey::from_bytes(&[0xa4; 32]);
        let network = [0xa5; 32];
        let signer = deployment.verifying_key().to_bytes();

        let epoch_two_chain = make_root_chain_with_successor(network, &anchor, &next_root);
        let current_wire = encode_manifest(
            network,
            1,
            &next_root,
            &anchor,
            &recovery,
            2,
            1,
            &epoch_two_chain,
            &deployment,
        );
        let current =
            verify_signed_deployment_config_with_floors(&current_wire, &network, &signer, 1, 2)
                .unwrap();

        // A newer DPC1 sequence with an older but otherwise valid GRC1 chain must be rejected.
        let epoch_one_chain = make_root_chain(network, &anchor);
        let rollback_wire = encode_manifest(
            network,
            2,
            &anchor,
            &anchor,
            &recovery,
            1,
            1,
            &epoch_one_chain,
            &deployment,
        );
        let rollback =
            verify_signed_deployment_config_with_floors(&rollback_wire, &network, &signer, 2, 1)
                .unwrap();

        {
            let store = DeploymentConfigStateStore::open(&path, &network, &signer, 1).unwrap();
            store.observe(&current).unwrap();
            assert_eq!(store.highest_sequence().unwrap(), 1);
            assert_eq!(store.highest_root_epoch().unwrap(), 2);
            store.matches_current(&current).unwrap();
            assert_eq!(
                store.observe(&rollback),
                Err(DeploymentConfigError::RootEpochRollback)
            );
            assert_eq!(store.highest_sequence().unwrap(), 1);
            assert_eq!(store.highest_root_epoch().unwrap(), 2);
        }
        let lock_path = path.with_file_name(format!(
            "{}.writer.lock",
            path.file_name().unwrap().to_string_lossy()
        ));
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(lock_path);
    }

    #[test]
    fn legacy_dcs1_v1_requires_exact_current_manifest_for_root_epoch_upgrade() {
        let path = temp_path("legacy-v1-upgrade");
        let deployment = SigningKey::from_bytes(&[0xb1; 32]);
        let anchor = SigningKey::from_bytes(&[0xb2; 32]);
        let next_root = SigningKey::from_bytes(&[0xb3; 32]);
        let recovery = SigningKey::from_bytes(&[0xb4; 32]);
        let network = [0xb5; 32];
        let signer = deployment.verifying_key().to_bytes();

        let epoch_two_chain = make_root_chain_with_successor(network, &anchor, &next_root);
        let current_wire = encode_manifest(
            network,
            1,
            &next_root,
            &anchor,
            &recovery,
            2,
            1,
            &epoch_two_chain,
            &deployment,
        );
        let current =
            verify_signed_deployment_config_with_floors(&current_wire, &network, &signer, 1, 2)
                .unwrap();
        fs::write(
            &path,
            encode_legacy_state_v1(network, &signer, current.sequence, current.digest),
        )
        .unwrap();

        let epoch_one_chain = make_root_chain(network, &anchor);
        let successor_wire = encode_manifest(
            network,
            2,
            &anchor,
            &anchor,
            &recovery,
            1,
            1,
            &epoch_one_chain,
            &deployment,
        );
        let successor =
            verify_signed_deployment_config_with_floors(&successor_wire, &network, &signer, 2, 1)
                .unwrap();

        {
            let store = DeploymentConfigStateStore::open(&path, &network, &signer, 1).unwrap();
            assert_eq!(
                store.observe(&successor),
                Err(DeploymentConfigError::StateMigrationRequired)
            );
            // Only the exact manifest already committed in the v1 state can establish its epoch.
            store.observe(&current).unwrap();
            assert_eq!(store.highest_sequence().unwrap(), 1);
            assert_eq!(store.highest_root_epoch().unwrap(), 2);
            let upgraded = fs::read(&path).unwrap();
            assert_eq!(upgraded.len(), STATE_LEN);
            assert_eq!(
                u16::from_be_bytes([upgraded[4], upgraded[5]]),
                STATE_VERSION
            );
            assert_eq!(
                store.observe(&successor),
                Err(DeploymentConfigError::RootEpochRollback)
            );
        }
        let lock_path = path.with_file_name(format!(
            "{}.writer.lock",
            path.file_name().unwrap().to_string_lossy()
        ));
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(lock_path);
    }

    #[test]
    fn deployment_config_requires_consecutive_updates_and_independent_signer_role() {
        let path = temp_path("sequence-gap");
        let deployment = SigningKey::from_bytes(&[0xd7; 32]);
        let governance = SigningKey::from_bytes(&[0xd8; 32]);
        let recovery = SigningKey::from_bytes(&[0xd9; 32]);
        let network = [0xe3; 32];
        let chain = make_root_chain(network, &governance);
        let signer = deployment.verifying_key().to_bytes();
        let one_wire = encode_manifest(
            network,
            1,
            &governance,
            &governance,
            &recovery,
            1,
            1,
            &chain,
            &deployment,
        );
        let three_wire = encode_manifest(
            network,
            3,
            &governance,
            &governance,
            &recovery,
            1,
            1,
            &chain,
            &deployment,
        );
        let one = verify_signed_deployment_config(&one_wire, &network, &signer, 1).unwrap();
        let three = verify_signed_deployment_config(&three_wire, &network, &signer, 1).unwrap();
        {
            let store = DeploymentConfigStateStore::open(&path, &network, &signer, 1).unwrap();
            store.observe(&one).unwrap();
            assert_eq!(
                store.observe(&three),
                Err(DeploymentConfigError::SequenceDiscontinuity)
            );
        }
        let _ = fs::remove_file(&path);
        let lock = path.with_file_name(format!(
            "{}.writer.lock",
            path.file_name().unwrap().to_string_lossy()
        ));
        let _ = fs::remove_file(lock);
    }
}
