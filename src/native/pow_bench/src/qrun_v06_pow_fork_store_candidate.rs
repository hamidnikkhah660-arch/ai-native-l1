//! Isolated QFP6 durable branch archive with immutable generation manifests.
//!
//! This candidate persists every QFP6 envelope and reconstructs QFB6 branch-local state by
//! replaying from either Genesis or a checkpoint decoded against an independent external anchor.
//! Checkpoint rollover creates a new immutable segment; it does not rewrite the prior segment.
//! A local checksum proves integrity, not freshness. Reopening an existing store requires the
//! latest manifest commitment from a trust source outside this directory.

use crate::{
    consensus::{pow_digest, ConsensusError, ConsensusParameters, PowAlgorithm},
    external_cas_anchor_candidate::ExternalCasPin,
    external_cas_offhost_anchor_protocol_candidate::ExternalCasOffhostAnchorPin,
    qrun_v06_canonical_execution_candidate::QRunV06CanonicalExecutionState,
    qrun_v06_checkpoint_candidate::{
        QRunV06CheckpointCandidate, QRunV06CheckpointError, MAX_QRUN_V06_CHECKPOINT_BYTES,
    },
    qrun_v06_external_anchor_candidate::QRunV06ExternalAnchorState,
    qrun_v06_pow_fork_choice_candidate::{
        QRunV06ForkChoiceError, QRunV06ForkChoiceOutcome, QRunV06PowForkChoice,
        QRunV06QuoteAssetAuthorizationProvider, MAX_QRUN_V06_FORK_ARCHIVE_BLOCKS,
        MAX_QRUN_V06_FORK_BRANCH_HEIGHT,
    },
    qrun_v06_pow_wire_candidate::{
        decode_qrun_v06_pow_block, QRunV06PowWireError, MAX_QRUN_V06_POW_ENVELOPE_BYTES,
        QRUN_V06_PROTOCOL_VERSION,
    },
    qrun_v06_profile_pin_candidate::QRunV06VerifiedProfilePin,
    qrun_v06_profile_trust_candidate::QRunV06TrustAuthorizedProfilePin,
    qrun_v06_qap1_journal_candidate::{QRunV06Qap1Error, QRunV06Qap1Journal, QRunV06Qap1Phase},
    state_machine::TransactionAuthenticator,
    store_writer_lock::StoreWriterLock,
    v4_fat1_trust_candidate::MlDsa65Verifier,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const MANIFEST_MAGIC: &[u8; 4] = b"Q6FS";
const MANIFEST_VERSION: u16 = 1;
const MANIFEST_CHECKSUM_DOMAIN: &[u8] = b"QRUN-V06-DURABLE-FORK-STORE-CHECKSUM-V1\0";
const MANIFEST_COMMITMENT_DOMAIN: &[u8] = b"QRUN-V06-DURABLE-FORK-STORE-COMMITMENT-V1\0";
const CONSENSUS_FINGERPRINT_DOMAIN: &[u8] = b"QRUN-V06-DURABLE-FORK-STORE-CONSENSUS-V1\0";
const LOCK_NAME: &str = "qfp6-fork-store.lock";
const CHECKPOINT_FILE: &str = "qfp6-base.checkpoint";
const BRANCH_DIR: &str = "branches";
const MANIFEST_DIR: &str = "manifests";
const QAP1_DIR: &str = crate::qrun_v06_qap1_journal_candidate::QAP1_DIRECTORY;
const BRANCH_PREFIX: &str = "branch-";
const BRANCH_SUFFIX: &str = ".qfp6";
const MANIFEST_PREFIX: &str = "qfp6-manifest-";
const MANIFEST_SUFFIX: &str = ".q6mf";
const TEMP_PREFIX: &str = ".qfp6-";
const TEMP_SUFFIX: &str = ".tmp";
const CHECKSUM_BYTES: usize = 32;
const MANIFEST_FIXED_PREFIX_BYTES: usize = 296;
const MANIFEST_ENTRY_BYTES: usize = 76;
pub const MAX_QRUN_V06_DURABLE_ARCHIVE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_QRUN_V06_MANIFEST_BYTES: usize = MANIFEST_FIXED_PREFIX_BYTES
    + MAX_QRUN_V06_FORK_ARCHIVE_BLOCKS * MANIFEST_ENTRY_BYTES
    + CHECKSUM_BYTES;
static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QRunV06ForkStoreError {
    Io(String),
    Fork(QRunV06ForkChoiceError),
    Checkpoint(QRunV06CheckpointError),
    Wire(QRunV06PowWireError),
    Consensus(ConsensusError),
    WrongProtocolVersion,
    InvalidTrustedManifestAnchor,
    MissingTrustedManifestAnchor,
    ManifestAnchorMismatch,
    ManifestMalformed,
    ManifestChecksumMismatch,
    ManifestGenerationMismatch,
    ManifestParentMismatch,
    ManifestProfileMismatch,
    ManifestConsensusMismatch,
    ProfilePinMismatch,
    ProfilePinConsensusMismatch,
    ProfilePinTokenomicsMismatch,
    WrongNetwork,
    WrongProfile,
    BaseStateMismatch,
    MissingBranch,
    BranchDigestMismatch,
    BranchBytesMismatch,
    UnexpectedEntry,
    ArchiveCapacityExceeded,
    ArchiveBytesExceeded,
    WriterLockHeld,
    RecoveryRequired,
    NoPendingRecovery,
    Qap1(String),
    PreparedCommitMismatch,
    InjectedFailure,
}

impl From<QRunV06Qap1Error> for QRunV06ForkStoreError {
    fn from(value: QRunV06Qap1Error) -> Self {
        Self::Qap1(value.to_string())
    }
}

impl From<io::Error> for QRunV06ForkStoreError {
    fn from(value: io::Error) -> Self {
        Self::Io(value.to_string())
    }
}
impl From<QRunV06ForkChoiceError> for QRunV06ForkStoreError {
    fn from(value: QRunV06ForkChoiceError) -> Self {
        Self::Fork(value)
    }
}
impl From<QRunV06CheckpointError> for QRunV06ForkStoreError {
    fn from(value: QRunV06CheckpointError) -> Self {
        Self::Checkpoint(value)
    }
}
impl From<QRunV06PowWireError> for QRunV06ForkStoreError {
    fn from(value: QRunV06PowWireError) -> Self {
        Self::Wire(value)
    }
}
impl From<ConsensusError> for QRunV06ForkStoreError {
    fn from(value: ConsensusError) -> Self {
        Self::Consensus(value)
    }
}
impl std::fmt::Display for QRunV06ForkStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "QFP6 durable fork-store I/O error: {error}"),
            Self::Fork(error) => write!(f, "QFP6 durable fork-store replay rejected: {error}"),
            Self::Checkpoint(error) => write!(f, "QFP6 durable checkpoint rejected: {error}"),
            Self::Wire(error) => write!(f, "QFP6 durable fork-store envelope rejected: {error}"),
            Self::Consensus(error) => write!(f, "QFP6 durable fork-store consensus error: {error}"),
            Self::WrongProtocolVersion => f.write_str("QFP6 durable store requires protocol version 6"),
            Self::InvalidTrustedManifestAnchor => f.write_str("trusted QFP6 manifest anchor must be nonzero"),
            Self::MissingTrustedManifestAnchor => f.write_str("existing QFP6 durable store requires an independently protected manifest anchor"),
            Self::ManifestAnchorMismatch => f.write_str("QFP6 manifest does not match the independently supplied anchor"),
            Self::ManifestMalformed => f.write_str("QFP6 durable manifest is malformed or non-canonical"),
            Self::ManifestChecksumMismatch => f.write_str("QFP6 durable manifest checksum mismatch"),
            Self::ManifestGenerationMismatch => f.write_str("QFP6 durable manifest generations are missing, duplicated or inconsistent"),
            Self::ManifestParentMismatch => f.write_str("QFP6 durable manifest generation chain is broken"),
            Self::ManifestProfileMismatch => f.write_str("QFP6 durable manifest execution profile differs from Genesis"),
            Self::ManifestConsensusMismatch => f.write_str("QFP6 durable manifest consensus parameters differ from the requested profile"),
            Self::ProfilePinMismatch => f.write_str("verified Q6PN profile pin does not match the supplied Genesis or checkpoint identity"),
            Self::ProfilePinConsensusMismatch => f.write_str("verified Q6PN consensus fingerprint differs from the requested QFP6 parameters"),
            Self::ProfilePinTokenomicsMismatch => f.write_str("verified Q6PN CP-0528 policy or Founder identity differs from the supplied Genesis state"),
            Self::WrongNetwork => f.write_str("QFP6 durable manifest belongs to another network"),
            Self::WrongProfile => f.write_str("QFP6 durable manifest belongs to another execution profile"),
            Self::BaseStateMismatch => f.write_str("QFP6 durable archive is not rooted in the supplied Genesis state"),
            Self::MissingBranch => f.write_str("QFP6 manifest references a missing branch envelope"),
            Self::BranchDigestMismatch => f.write_str("QFP6 branch bytes or PoW digest differ from the manifest entry"),
            Self::BranchBytesMismatch => f.write_str("QFP6 branch digest already exists with different envelope bytes"),
            Self::UnexpectedEntry => f.write_str("QFP6 durable store contains a symlink, special file or unexpected path"),
            Self::ArchiveCapacityExceeded => f.write_str("QFP6 durable branch count exceeds its limit"),
            Self::ArchiveBytesExceeded => f.write_str("QFP6 durable archive exceeds its byte budget"),
            Self::WriterLockHeld => f.write_str("another QFP6 process owns the durable store writer lock"),
            Self::RecoveryRequired => f.write_str("QFP6 store instance is no longer usable; reopen it with the externally anchored manifest"),
            Self::NoPendingRecovery => f.write_str("QFP6 store has no pending ambiguous commit to reconcile"),
            Self::Qap1(error) => write!(f, "QFP6 QAP1 gate rejected prepared manifest publication: {error}"),
            Self::PreparedCommitMismatch => f.write_str("QFP6 prepared transition differs from the exact confirmed QAP1 intent"),
            Self::InjectedFailure => f.write_str("QFP6 durable-store fault injection interrupted the commit"),
        }
    }
}
impl std::error::Error for QRunV06ForkStoreError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QRunV06DurableCommit {
    pub outcome: QRunV06ForkChoiceOutcome,
    pub generation: u64,
    /// Persist this in a trust domain independent of the QFP6 store before acknowledging
    /// the corresponding block to peers or applications.
    pub manifest_anchor: [u8; 32],
}

/// A validated QFP6 successor held in memory but not yet published as the active manifest.
/// Its exact candidate envelope and manifest bytes are also persisted in QAP1 before any
/// Provider/Q6EA CAS is attempted. Only publish_prepared_with_qap1 may make it active.
pub struct QRunV06PreparedCommit {
    outcome: QRunV06ForkChoiceOutcome,
    parent_generation: u64,
    parent_manifest_anchor: [u8; 32],
    generation: u64,
    manifest_anchor: [u8; 32],
    candidate_envelope: Vec<u8>,
    manifest_bytes: Vec<u8>,
    staged_graph: QRunV06PowForkChoice,
}

impl QRunV06PreparedCommit {
    pub fn outcome(&self) -> QRunV06ForkChoiceOutcome {
        self.outcome
    }
    pub fn parent_generation(&self) -> u64 {
        self.parent_generation
    }
    pub fn parent_manifest_anchor(&self) -> [u8; 32] {
        self.parent_manifest_anchor
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn manifest_anchor(&self) -> [u8; 32] {
        self.manifest_anchor
    }
    pub fn candidate_envelope(&self) -> &[u8] {
        &self.candidate_envelope
    }
    pub fn manifest_bytes(&self) -> &[u8] {
        &self.manifest_bytes
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommitStage {
    BranchTempFileCreated,
    BranchTempFileSynced,
    BranchFileInstalled,
    BranchFilesSynced,
    ManifestTempFileCreated,
    ManifestTempFileSynced,
    ManifestFileInstalled,
    ManifestFileSynced,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QRunV06RecoveryHint {
    pub generation: u64,
    pub manifest_anchor: [u8; 32],
    /// True means the next immutable manifest is already visible locally and must be
    /// reconciled into the independently protected anchor before acknowledging its block.
    pub manifest_committed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManifestEntry {
    digest: [u8; 32],
    height: u64,
    encoded_len: u32,
    envelope_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct QRunV06StoreManifest {
    generation: u64,
    parent_manifest_anchor: [u8; 32],
    network_id: [u8; 32],
    profile_id: [u8; 32],
    consensus_fingerprint: [u8; 32],
    base_tip: [u8; 32],
    base_height: u64,
    canonical_tip: [u8; 32],
    canonical_height: u64,
    canonical_state_root: [u8; 32],
    canonical_chainwork: [u8; 32],
    entries: Vec<ManifestEntry>,
}

pub struct QRunV06DurableForkStore {
    branches_dir: PathBuf,
    manifests_dir: PathBuf,
    _writer_lock: StoreWriterLock,
    params: ConsensusParameters,
    graph: QRunV06PowForkChoice,
    generation: u64,
    manifest_anchor: [u8; 32],
    checkpoint_anchor: Option<[u8; 32]>,
    poisoned: bool,
}

impl QRunV06DurableForkStore {
    /// Module-private store core. External callers must use
    /// `open_with_expected_genesis_descriptor_commitment` so the Genesis descriptor
    /// is compared with the independently pinned profile commitment.
    fn open<A: TransactionAuthenticator>(
        directory: impl AsRef<Path>,
        genesis_state: QRunV06CanonicalExecutionState,
        params: ConsensusParameters,
        authenticator: &A,
        trusted_manifest_anchor: Option<[u8; 32]>,
    ) -> Result<Self, QRunV06ForkStoreError> {
        Self::open_inner(
            directory,
            genesis_state,
            params,
            authenticator,
            trusted_manifest_anchor,
            None,
        )
    }

    fn open_inner<A: TransactionAuthenticator>(
        directory: impl AsRef<Path>,
        genesis_state: QRunV06CanonicalExecutionState,
        params: ConsensusParameters,
        authenticator: &A,
        trusted_manifest_anchor: Option<[u8; 32]>,
        mut quote_authorizer: Option<&mut QRunV06QuoteAssetAuthorizationProvider<'_>>,
    ) -> Result<Self, QRunV06ForkStoreError> {
        if params.protocol_version != QRUN_V06_PROTOCOL_VERSION {
            return Err(QRunV06ForkStoreError::WrongProtocolVersion);
        }
        params.validate()?;
        if trusted_manifest_anchor == Some([0; 32]) {
            return Err(QRunV06ForkStoreError::InvalidTrustedManifestAnchor);
        }

        let directory = directory.as_ref().to_path_buf();
        fs::create_dir_all(&directory)?;
        ensure_real_directory(&directory)?;
        let lock_path = directory.join(LOCK_NAME);
        reject_symlink_if_present(&lock_path)?;
        let writer_lock = StoreWriterLock::acquire(&directory, LOCK_NAME).map_err(|error| {
            if error.kind() == io::ErrorKind::WouldBlock {
                QRunV06ForkStoreError::WriterLockHeld
            } else {
                QRunV06ForkStoreError::Io(error.to_string())
            }
        })?;

        let branches_dir = directory.join(BRANCH_DIR);
        let manifests_dir = directory.join(MANIFEST_DIR);
        let qap1_dir = directory.join(QAP1_DIR);
        fs::create_dir_all(&branches_dir)?;
        fs::create_dir_all(&manifests_dir)?;
        if path_exists_no_follow(&qap1_dir)? {
            ensure_real_directory(&qap1_dir)?;
        }
        ensure_real_directory(&branches_dir)?;
        ensure_real_directory(&manifests_dir)?;
        validate_root_entries(&directory)?;
        if path_exists_no_follow(&directory.join(CHECKPOINT_FILE))? {
            return Err(QRunV06ForkStoreError::UnexpectedEntry);
        }

        let expected_genesis_descriptor_commitment = genesis_state
            .genesis_descriptor_commitment()
            .ok_or(QRunV06ForkStoreError::Fork(
                QRunV06ForkChoiceError::MissingGenesisDescriptor,
            ))?;
        let genesis_graph = QRunV06PowForkChoice::new_with_expected_genesis_descriptor_commitment(
            genesis_state.clone(),
            params.clone(),
            expected_genesis_descriptor_commitment,
        )?;
        let fingerprint = consensus_fingerprint(&params)?;
        cleanup_temp_files(&branches_dir)?;
        cleanup_temp_files(&manifests_dir)?;
        let manifest_chain = load_manifest_chain(&manifests_dir)?;

        let (graph, generation, anchor) = if let Some((latest, latest_anchor)) =
            manifest_chain.last()
        {
            let supplied = trusted_manifest_anchor
                .ok_or(QRunV06ForkStoreError::MissingTrustedManifestAnchor)?;
            if supplied != *latest_anchor {
                return Err(QRunV06ForkStoreError::ManifestAnchorMismatch);
            }
            validate_manifest_identity(latest, &genesis_graph, fingerprint)?;

            let envelopes = load_branch_entries(&branches_dir, &latest.entries, &params)?;
            let rebuilt = if let Some(provider) = quote_authorizer.as_deref_mut() {
                QRunV06PowForkChoice::rebuild_from_envelopes_with_quote_asset_authorization(
                    genesis_state,
                    params.clone(),
                    envelopes,
                    authenticator,
                    expected_genesis_descriptor_commitment,
                    provider,
                )?
            } else {
                QRunV06PowForkChoice::rebuild_from_envelopes_with_expected_genesis_descriptor_commitment(
                    genesis_state,
                    params.clone(),
                    envelopes,
                    authenticator,
                    expected_genesis_descriptor_commitment,
                )?
            };
            validate_manifest_graph(latest, &rebuilt)?;
            reconcile_branch_directory(&branches_dir, &latest.entries)?;
            (rebuilt, latest.generation, *latest_anchor)
        } else {
            if trusted_manifest_anchor.is_some() {
                return Err(QRunV06ForkStoreError::ManifestAnchorMismatch);
            }
            reconcile_branch_directory(&branches_dir, &[])?;
            let manifest = manifest_from_graph(0, [0; 32], &params, &genesis_graph)?;
            let bytes = encode_manifest(&manifest)?;
            let anchor = manifest_commitment(&bytes);
            write_new_atomic(&manifests_dir.join(manifest_filename(0)), &bytes)?;
            (genesis_graph, 0, anchor)
        };

        Ok(Self {
            branches_dir,
            manifests_dir,
            _writer_lock: writer_lock,
            params,
            graph,
            generation,
            manifest_anchor: anchor,
            checkpoint_anchor: None,
            poisoned: false,
        })
    }

    /// Production-shaped bootstrap: require an independently pinned Genesis descriptor
    /// commitment before opening a Genesis-rooted durable store. The plain `open` helper is
    /// retained for controlled research fixtures and does not replace profile pin verification.
    pub fn open_with_expected_genesis_descriptor_commitment<A: TransactionAuthenticator>(
        directory: impl AsRef<Path>,
        genesis_state: QRunV06CanonicalExecutionState,
        params: ConsensusParameters,
        authenticator: &A,
        trusted_manifest_anchor: Option<[u8; 32]>,
        expected_genesis_descriptor_commitment: [u8; 32],
    ) -> Result<Self, QRunV06ForkStoreError> {
        if expected_genesis_descriptor_commitment == [0; 32]
            || genesis_state.genesis_descriptor_commitment()
                != Some(expected_genesis_descriptor_commitment)
        {
            return Err(QRunV06ForkStoreError::Fork(
                QRunV06ForkChoiceError::GenesisDescriptorMismatch,
            ));
        }
        Self::open(
            directory,
            genesis_state,
            params,
            authenticator,
            trusted_manifest_anchor,
        )
    }

    /// Test-only reopen seam for integration tests that need to replay external-quote blocks.
    /// Production callers must use the trust-authorized profile-pin constructor below.
    #[cfg(test)]
    pub(crate) fn open_for_test_with_quote_asset_authorization<A: TransactionAuthenticator>(
        directory: impl AsRef<Path>,
        genesis_state: QRunV06CanonicalExecutionState,
        params: ConsensusParameters,
        authenticator: &A,
        trusted_manifest_anchor: Option<[u8; 32]>,
        expected_genesis_descriptor_commitment: [u8; 32],
        quote_authorizer: &mut QRunV06QuoteAssetAuthorizationProvider<'_>,
    ) -> Result<Self, QRunV06ForkStoreError> {
        if expected_genesis_descriptor_commitment == [0; 32]
            || genesis_state.genesis_descriptor_commitment()
                != Some(expected_genesis_descriptor_commitment)
        {
            return Err(QRunV06ForkStoreError::Fork(
                QRunV06ForkChoiceError::GenesisDescriptorMismatch,
            ));
        }
        Self::open_inner(
            directory,
            genesis_state,
            params,
            authenticator,
            trusted_manifest_anchor,
            Some(quote_authorizer),
        )
    }
    /// Open a Genesis-rooted store from a Q6PN bundle that was already checked against a
    /// separately provisioned profile-pin commitment. The descriptor, Founder/tokenomics
    /// identity, and active consensus parameters are cross-checked before any store I/O.
    pub fn open_with_verified_profile_pin<A: TransactionAuthenticator>(
        directory: impl AsRef<Path>,
        genesis_state: QRunV06CanonicalExecutionState,
        params: ConsensusParameters,
        authenticator: &A,
        trusted_manifest_anchor: Option<[u8; 32]>,
        verified_profile_pin: &QRunV06VerifiedProfilePin,
    ) -> Result<Self, QRunV06ForkStoreError> {
        let descriptor = verified_profile_pin.descriptor();
        if descriptor.consensus_fingerprint()
            != crate::qrun_v06_checkpoint_candidate::qrun_v06_consensus_fingerprint(&params)?
        {
            return Err(QRunV06ForkStoreError::ProfilePinConsensusMismatch);
        }
        if genesis_state.genesis_descriptor() != Some(descriptor)
            || genesis_state.network_id() != descriptor.network_id()
            || genesis_state.profile_id() != descriptor.profile_id()
        {
            return Err(QRunV06ForkStoreError::ProfilePinMismatch);
        }
        let tokenomics = genesis_state
            .tokenomics()
            .ok_or(QRunV06ForkStoreError::ProfilePinTokenomicsMismatch)?;
        if tokenomics.founder_account() != descriptor.founder_account()
            || tokenomics.policy_fingerprint() != descriptor.tokenomics_policy_fingerprint()
        {
            return Err(QRunV06ForkStoreError::ProfilePinTokenomicsMismatch);
        }
        Self::open_with_expected_genesis_descriptor_commitment(
            directory,
            genesis_state,
            params,
            authenticator,
            trusted_manifest_anchor,
            descriptor.commitment(),
        )
    }

    /// Stronger CP-0539 bootstrap: require a dual-signed trust record and an advanced/read-back
    /// verified independent monotonic floor before the profile pin can reach this store API.
    pub fn open_with_trust_authorized_profile_pin<A: TransactionAuthenticator>(
        directory: impl AsRef<Path>,
        genesis_state: QRunV06CanonicalExecutionState,
        params: ConsensusParameters,
        authenticator: &A,
        trusted_manifest_anchor: Option<[u8; 32]>,
        authorized_profile_pin: &QRunV06TrustAuthorizedProfilePin,
    ) -> Result<Self, QRunV06ForkStoreError> {
        Self::open_with_verified_profile_pin(
            directory,
            genesis_state,
            params,
            authenticator,
            trusted_manifest_anchor,
            authorized_profile_pin.verified_profile_pin(),
        )
    }

    /// Reopen/replay a Genesis-rooted archive containing non-native quote activity.
    /// The provider must reconstruct a height-correct Q6TS/Q6QA authorization for every
    /// replayed block that uses an external quote asset; missing historical trust evidence
    /// aborts opening rather than silently replaying under a stale cached authorization.
    pub fn open_with_trust_authorized_profile_pin_and_quote_asset_authorization<
        A: TransactionAuthenticator,
    >(
        directory: impl AsRef<Path>,
        genesis_state: QRunV06CanonicalExecutionState,
        params: ConsensusParameters,
        authenticator: &A,
        trusted_manifest_anchor: Option<[u8; 32]>,
        authorized_profile_pin: &QRunV06TrustAuthorizedProfilePin,
        quote_authorizer: &mut QRunV06QuoteAssetAuthorizationProvider<'_>,
    ) -> Result<Self, QRunV06ForkStoreError> {
        let descriptor = authorized_profile_pin.verified_profile_pin().descriptor();
        if descriptor.consensus_fingerprint()
            != crate::qrun_v06_checkpoint_candidate::qrun_v06_consensus_fingerprint(&params)?
        {
            return Err(QRunV06ForkStoreError::ProfilePinConsensusMismatch);
        }
        if genesis_state.genesis_descriptor() != Some(descriptor)
            || genesis_state.network_id() != descriptor.network_id()
            || genesis_state.profile_id() != descriptor.profile_id()
        {
            return Err(QRunV06ForkStoreError::ProfilePinMismatch);
        }
        Self::open_inner(
            directory,
            genesis_state,
            params,
            authenticator,
            trusted_manifest_anchor,
            Some(quote_authorizer),
        )
    }

    /// Production-shaped checkpoint bootstrap: require the exact externally pinned
    /// Genesis descriptor commitment as well as the independent checkpoint byte anchor.
    pub fn open_from_checkpoint_with_expected_genesis_descriptor_commitment<
        A: TransactionAuthenticator,
    >(
        directory: impl AsRef<Path>,
        checkpoint_bytes: &[u8],
        params: ConsensusParameters,
        expected_network_id: [u8; 32],
        expected_profile_id: [u8; 32],
        trusted_checkpoint_anchor: [u8; 32],
        expected_genesis_descriptor_commitment: [u8; 32],
        authenticator: &A,
        trusted_manifest_anchor: Option<[u8; 32]>,
    ) -> Result<Self, QRunV06ForkStoreError> {
        if expected_genesis_descriptor_commitment == [0; 32] {
            return Err(QRunV06ForkStoreError::Fork(
                QRunV06ForkChoiceError::GenesisDescriptorMismatch,
            ));
        }
        let checkpoint = QRunV06CheckpointCandidate::decode_snapshot(
            checkpoint_bytes,
            &params,
            &expected_network_id,
            &expected_profile_id,
            trusted_checkpoint_anchor,
        )?;
        if checkpoint.genesis_descriptor_commitment() != expected_genesis_descriptor_commitment {
            return Err(QRunV06ForkStoreError::Fork(
                QRunV06ForkChoiceError::GenesisDescriptorMismatch,
            ));
        }
        Self::open_from_checkpoint(
            directory,
            checkpoint_bytes,
            params,
            expected_network_id,
            expected_profile_id,
            trusted_checkpoint_anchor,
            authenticator,
            trusted_manifest_anchor,
        )
    }

    /// Checkpoint-store bootstrap using the same externally verified Q6PN profile pin used
    /// for Genesis bootstrap. The checkpoint byte commitment remains a second, independent pin.
    pub fn open_from_checkpoint_with_verified_profile_pin<A: TransactionAuthenticator>(
        directory: impl AsRef<Path>,
        checkpoint_bytes: &[u8],
        params: ConsensusParameters,
        trusted_checkpoint_anchor: [u8; 32],
        verified_profile_pin: &QRunV06VerifiedProfilePin,
        authenticator: &A,
        trusted_manifest_anchor: Option<[u8; 32]>,
    ) -> Result<Self, QRunV06ForkStoreError> {
        let descriptor = verified_profile_pin.descriptor();
        if descriptor.consensus_fingerprint()
            != crate::qrun_v06_checkpoint_candidate::qrun_v06_consensus_fingerprint(&params)?
        {
            return Err(QRunV06ForkStoreError::ProfilePinConsensusMismatch);
        }
        Self::open_from_checkpoint_with_expected_genesis_descriptor_commitment(
            directory,
            checkpoint_bytes,
            params,
            descriptor.network_id(),
            descriptor.profile_id(),
            trusted_checkpoint_anchor,
            descriptor.commitment(),
            authenticator,
            trusted_manifest_anchor,
        )
    }

    /// Stronger CP-0539 checkpoint bootstrap using a dual-signed Q6TS trust record and a
    /// separately administered monotonic floor, while retaining the independent checkpoint pin.
    pub fn open_from_checkpoint_with_trust_authorized_profile_pin<A: TransactionAuthenticator>(
        directory: impl AsRef<Path>,
        checkpoint_bytes: &[u8],
        params: ConsensusParameters,
        trusted_checkpoint_anchor: [u8; 32],
        authorized_profile_pin: &QRunV06TrustAuthorizedProfilePin,
        authenticator: &A,
        trusted_manifest_anchor: Option<[u8; 32]>,
    ) -> Result<Self, QRunV06ForkStoreError> {
        Self::open_from_checkpoint_with_verified_profile_pin(
            directory,
            checkpoint_bytes,
            params,
            trusted_checkpoint_anchor,
            authorized_profile_pin.verified_profile_pin(),
            authenticator,
            trusted_manifest_anchor,
        )
    }

    /// Checkpoint-rooted reopen with exact-height Q6TS/Q6QA authorization for every
    /// replayed post-checkpoint external-quote block. The independent checkpoint anchor
    /// and trust-authorized Genesis/profile pin remain mandatory.
    pub fn open_from_checkpoint_with_trust_authorized_profile_pin_and_quote_asset_authorization<
        A: TransactionAuthenticator,
    >(
        directory: impl AsRef<Path>,
        checkpoint_bytes: &[u8],
        params: ConsensusParameters,
        trusted_checkpoint_anchor: [u8; 32],
        authorized_profile_pin: &QRunV06TrustAuthorizedProfilePin,
        authenticator: &A,
        trusted_manifest_anchor: Option<[u8; 32]>,
        quote_authorizer: &mut QRunV06QuoteAssetAuthorizationProvider<'_>,
    ) -> Result<Self, QRunV06ForkStoreError> {
        let descriptor = authorized_profile_pin.verified_profile_pin().descriptor();
        if descriptor.consensus_fingerprint()
            != crate::qrun_v06_checkpoint_candidate::qrun_v06_consensus_fingerprint(&params)?
        {
            return Err(QRunV06ForkStoreError::ProfilePinConsensusMismatch);
        }
        Self::open_from_checkpoint_inner(
            directory,
            checkpoint_bytes,
            params,
            descriptor.network_id(),
            descriptor.profile_id(),
            trusted_checkpoint_anchor,
            authenticator,
            trusted_manifest_anchor,
            Some(quote_authorizer),
        )
    }

    /// Module-private checkpoint-store core. External callers must use
    /// `open_from_checkpoint_with_expected_genesis_descriptor_commitment` to
    /// verify both the independent checkpoint anchor and the profile-pinned Genesis descriptor.
    fn open_from_checkpoint<A: TransactionAuthenticator>(
        directory: impl AsRef<Path>,
        checkpoint_bytes: &[u8],
        params: ConsensusParameters,
        expected_network_id: [u8; 32],
        expected_profile_id: [u8; 32],
        trusted_checkpoint_anchor: [u8; 32],
        authenticator: &A,
        trusted_manifest_anchor: Option<[u8; 32]>,
    ) -> Result<Self, QRunV06ForkStoreError> {
        Self::open_from_checkpoint_inner(
            directory,
            checkpoint_bytes,
            params,
            expected_network_id,
            expected_profile_id,
            trusted_checkpoint_anchor,
            authenticator,
            trusted_manifest_anchor,
            None,
        )
    }

    fn open_from_checkpoint_inner<A: TransactionAuthenticator>(
        directory: impl AsRef<Path>,
        checkpoint_bytes: &[u8],
        params: ConsensusParameters,
        expected_network_id: [u8; 32],
        expected_profile_id: [u8; 32],
        trusted_checkpoint_anchor: [u8; 32],
        authenticator: &A,
        trusted_manifest_anchor: Option<[u8; 32]>,
        mut quote_authorizer: Option<&mut QRunV06QuoteAssetAuthorizationProvider<'_>>,
    ) -> Result<Self, QRunV06ForkStoreError> {
        if params.protocol_version != QRUN_V06_PROTOCOL_VERSION {
            return Err(QRunV06ForkStoreError::WrongProtocolVersion);
        }
        params.validate()?;
        if trusted_manifest_anchor == Some([0; 32]) {
            return Err(QRunV06ForkStoreError::InvalidTrustedManifestAnchor);
        }
        if checkpoint_bytes.len() > MAX_QRUN_V06_CHECKPOINT_BYTES {
            return Err(QRunV06ForkStoreError::ArchiveBytesExceeded);
        }

        let checkpoint = QRunV06CheckpointCandidate::decode_snapshot(
            checkpoint_bytes,
            &params,
            &expected_network_id,
            &expected_profile_id,
            trusted_checkpoint_anchor,
        )?;
        let expected_genesis_descriptor_commitment = checkpoint.genesis_descriptor_commitment();
        let base_graph =
            QRunV06PowForkChoice::from_checkpoint_with_expected_genesis_descriptor_commitment(
                checkpoint,
                params.clone(),
                expected_genesis_descriptor_commitment,
            )?;
        let fingerprint = consensus_fingerprint(&params)?;

        let directory = directory.as_ref().to_path_buf();
        fs::create_dir_all(&directory)?;
        ensure_real_directory(&directory)?;
        let lock_path = directory.join(LOCK_NAME);
        reject_symlink_if_present(&lock_path)?;
        let writer_lock = StoreWriterLock::acquire(&directory, LOCK_NAME).map_err(|error| {
            if error.kind() == io::ErrorKind::WouldBlock {
                QRunV06ForkStoreError::WriterLockHeld
            } else {
                QRunV06ForkStoreError::Io(error.to_string())
            }
        })?;

        let branches_dir = directory.join(BRANCH_DIR);
        let manifests_dir = directory.join(MANIFEST_DIR);
        let qap1_dir = directory.join(QAP1_DIR);
        fs::create_dir_all(&branches_dir)?;
        fs::create_dir_all(&manifests_dir)?;
        if path_exists_no_follow(&qap1_dir)? {
            ensure_real_directory(&qap1_dir)?;
        }
        ensure_real_directory(&branches_dir)?;
        ensure_real_directory(&manifests_dir)?;
        cleanup_temp_files(&directory)?;
        validate_root_entries(&directory)?;

        let checkpoint_path = directory.join(CHECKPOINT_FILE);
        match read_optional_bounded(&checkpoint_path, MAX_QRUN_V06_CHECKPOINT_BYTES)? {
            Some(existing) if existing == checkpoint_bytes => {}
            Some(_) => {
                return Err(QRunV06ForkStoreError::Checkpoint(
                    QRunV06CheckpointError::CheckpointAnchorMismatch,
                ))
            }
            None => write_new_atomic(&checkpoint_path, checkpoint_bytes)?,
        }
        cleanup_temp_files(&directory)?;
        validate_root_entries(&directory)?;
        cleanup_temp_files(&branches_dir)?;
        cleanup_temp_files(&manifests_dir)?;
        let manifest_chain = load_manifest_chain(&manifests_dir)?;

        let (graph, generation, manifest_anchor) =
            if let Some((latest, latest_anchor)) = manifest_chain.last() {
                let supplied = trusted_manifest_anchor
                    .ok_or(QRunV06ForkStoreError::MissingTrustedManifestAnchor)?;
                if supplied != *latest_anchor {
                    return Err(QRunV06ForkStoreError::ManifestAnchorMismatch);
                }
                validate_manifest_identity(latest, &base_graph, fingerprint)?;
                let envelopes = load_branch_entries(&branches_dir, &latest.entries, &params)?;
                let rebuilt = if let Some(provider) = quote_authorizer.as_deref_mut() {
                    base_graph.rebuild_from_current_base_with_quote_asset_authorization(
                        envelopes,
                        authenticator,
                        provider,
                    )?
                } else {
                    base_graph.rebuild_from_current_base(envelopes, authenticator)?
                };
                validate_manifest_graph(latest, &rebuilt)?;
                reconcile_branch_directory(&branches_dir, &latest.entries)?;
                (rebuilt, latest.generation, *latest_anchor)
            } else {
                if trusted_manifest_anchor.is_some() {
                    return Err(QRunV06ForkStoreError::ManifestAnchorMismatch);
                }
                reconcile_branch_directory(&branches_dir, &[])?;
                let manifest = manifest_from_graph(0, [0; 32], &params, &base_graph)?;
                let bytes = encode_manifest(&manifest)?;
                let anchor = manifest_commitment(&bytes);
                write_new_atomic(&manifests_dir.join(manifest_filename(0)), &bytes)?;
                (base_graph, 0, anchor)
            };

        Ok(Self {
            branches_dir,
            manifests_dir,
            _writer_lock: writer_lock,
            params,
            graph,
            generation,
            manifest_anchor,
            checkpoint_anchor: Some(trusted_checkpoint_anchor),
            poisoned: false,
        })
    }

    /// Validate a candidate block and build its exact next QFP6 manifest without writing
    /// branch files or publishing a manifest. The caller must durably record the returned
    /// candidate envelope and manifest bytes in QAP1 before any Provider/Q6EA write.
    pub fn prepare<A: TransactionAuthenticator>(
        &mut self,
        envelope: &[u8],
        authenticator: &A,
    ) -> Result<Option<QRunV06PreparedCommit>, QRunV06ForkStoreError> {
        self.prepare_inner(envelope, authenticator, None)
    }

    pub fn prepare_with_quote_asset_authorization<A: TransactionAuthenticator>(
        &mut self,
        envelope: &[u8],
        authenticator: &A,
        quote_authorizer: &mut QRunV06QuoteAssetAuthorizationProvider<'_>,
    ) -> Result<Option<QRunV06PreparedCommit>, QRunV06ForkStoreError> {
        self.prepare_inner(envelope, authenticator, Some(quote_authorizer))
    }

    fn prepare_inner<A: TransactionAuthenticator>(
        &mut self,
        envelope: &[u8],
        authenticator: &A,
        mut quote_authorizer: Option<&mut QRunV06QuoteAssetAuthorizationProvider<'_>>,
    ) -> Result<Option<QRunV06PreparedCommit>, QRunV06ForkStoreError> {
        self.ensure_healthy()?;
        if envelope.is_empty() || envelope.len() > MAX_QRUN_V06_POW_ENVELOPE_BYTES {
            return Err(QRunV06ForkStoreError::ArchiveBytesExceeded);
        }

        let mut staged = self.graph.clone();
        let outcome = if let Some(provider) = quote_authorizer.as_deref_mut() {
            staged.insert_encoded_with_quote_asset_authorization(
                envelope,
                authenticator,
                provider,
            )?
        } else {
            staged.insert_encoded(envelope, authenticator)?
        };
        if staged.archive_len() == self.graph.archive_len() {
            return Ok(None);
        }

        let entries = collect_manifest_entries(&staged, &self.params)?;
        let total_bytes = entries
            .iter()
            .try_fold(0usize, |total, entry| {
                total.checked_add(entry.encoded_len as usize)
            })
            .ok_or(QRunV06ForkStoreError::ArchiveBytesExceeded)?;
        if entries.len() > MAX_QRUN_V06_FORK_ARCHIVE_BLOCKS {
            return Err(QRunV06ForkStoreError::ArchiveCapacityExceeded);
        }
        if total_bytes > MAX_QRUN_V06_DURABLE_ARCHIVE_BYTES {
            return Err(QRunV06ForkStoreError::ArchiveBytesExceeded);
        }
        let envelopes = staged.archive_envelopes_bounded(
            MAX_QRUN_V06_FORK_ARCHIVE_BLOCKS,
            MAX_QRUN_V06_DURABLE_ARCHIVE_BYTES,
        )?;
        if envelopes
            .iter()
            .filter(|bytes| bytes.as_slice() == envelope)
            .count()
            != 1
        {
            return Err(QRunV06ForkStoreError::PreparedCommitMismatch);
        }

        let generation = self
            .generation
            .checked_add(1)
            .ok_or(QRunV06ForkStoreError::ManifestGenerationMismatch)?;
        let manifest =
            manifest_from_graph(generation, self.manifest_anchor, &self.params, &staged)?;
        let manifest_bytes = encode_manifest(&manifest)?;
        let manifest_anchor = manifest_commitment(&manifest_bytes);
        Ok(Some(QRunV06PreparedCommit {
            outcome,
            parent_generation: self.generation,
            parent_manifest_anchor: self.manifest_anchor,
            generation,
            manifest_anchor,
            candidate_envelope: envelope.to_vec(),
            manifest_bytes,
            staged_graph: staged,
        }))
    }

    /// Publish a previously prepared QFP6 successor only after QAP1 contains a cryptographically
    /// verified Provider receipt, a signed Q6EA CAS receipt, and a fresh signed Anchor Read.
    /// Branch envelopes are installed first; the immutable next manifest is the sole local
    /// activation point. An ambiguous manifest write poisons this handle and requires anchored reopen.
    pub fn publish_prepared_with_qap1<PV: MlDsa65Verifier, AV: MlDsa65Verifier>(
        &mut self,
        prepared: QRunV06PreparedCommit,
        journal: &QRunV06Qap1Journal,
        provider_pin: &ExternalCasPin,
        anchor_pin: &ExternalCasOffhostAnchorPin,
        provider_verifier: &PV,
        anchor_verifier: &AV,
    ) -> Result<QRunV06DurableCommit, QRunV06ForkStoreError> {
        self.ensure_healthy()?;
        if journal.phase() != QRunV06Qap1Phase::AnchorConfirmed
            || journal.candidate_envelope() != prepared.candidate_envelope
            || journal.next_manifest_bytes() != prepared.manifest_bytes
            || prepared.parent_generation != self.generation
            || prepared.parent_manifest_anchor != self.manifest_anchor
            || prepared.generation
                != self
                    .generation
                    .checked_add(1)
                    .ok_or(QRunV06ForkStoreError::ManifestGenerationMismatch)?
        {
            return Err(QRunV06ForkStoreError::PreparedCommitMismatch);
        }
        journal.verify_saved_evidence(
            provider_pin,
            anchor_pin,
            provider_verifier,
            anchor_verifier,
        )?;

        let local_predecessor =
            QRunV06ExternalAnchorState::from_store(self, journal.predecessor().genesis_digest)
                .map_err(|_| QRunV06ForkStoreError::PreparedCommitMismatch)?;
        if local_predecessor != *journal.predecessor() {
            return Err(QRunV06ForkStoreError::PreparedCommitMismatch);
        }

        let recomputed_manifest = manifest_from_graph(
            prepared.generation,
            self.manifest_anchor,
            &self.params,
            &prepared.staged_graph,
        )?;
        let recomputed_manifest_bytes = encode_manifest(&recomputed_manifest)?;
        let recomputed_manifest_anchor = manifest_commitment(&recomputed_manifest_bytes);
        if recomputed_manifest_bytes != prepared.manifest_bytes
            || recomputed_manifest_anchor != prepared.manifest_anchor
            || journal.successor().manifest_generation != prepared.generation
            || journal.successor().manifest_anchor != prepared.manifest_anchor
        {
            return Err(QRunV06ForkStoreError::PreparedCommitMismatch);
        }

        let tip = prepared.staged_graph.canonical_tip();
        let state_root = prepared
            .staged_graph
            .canonical_state()
            .state_root()
            .map_err(|_| QRunV06ForkStoreError::PreparedCommitMismatch)?;
        let chainwork = prepared
            .staged_graph
            .branch_work(&tip.tip_hash)
            .ok_or(QRunV06ForkStoreError::PreparedCommitMismatch)?
            .to_be_bytes();
        let successor = journal.successor();
        if successor.network_id != prepared.staged_graph.network_id()
            || successor.profile_id != prepared.staged_graph.profile_id()
            || successor.consensus_fingerprint != consensus_fingerprint(&self.params)?
            || successor.segment_base_height != prepared.staged_graph.base_height()
            || successor.segment_base_tip != prepared.staged_graph.base_tip()
            || successor.checkpoint_anchor != self.checkpoint_anchor.unwrap_or([0; 32])
            || successor.canonical_height != tip.height
            || successor.canonical_tip != tip.tip_hash
            || successor.canonical_state_root != state_root
            || successor.cumulative_chainwork != chainwork
        {
            return Err(QRunV06ForkStoreError::PreparedCommitMismatch);
        }

        let envelopes = prepared.staged_graph.archive_envelopes_bounded(
            MAX_QRUN_V06_FORK_ARCHIVE_BLOCKS,
            MAX_QRUN_V06_DURABLE_ARCHIVE_BYTES,
        )?;
        let mut candidate_seen = 0usize;
        for bytes in &envelopes {
            let decoded = decode_qrun_v06_pow_block(bytes)?;
            let digest = pow_digest(&decoded.header, self.params.pow)?;
            let path = self.branches_dir.join(branch_filename(&digest));
            if bytes.as_slice() == prepared.candidate_envelope {
                candidate_seen += 1;
            }
            match read_optional_bounded(&path, MAX_QRUN_V06_POW_ENVELOPE_BYTES)? {
                Some(existing) if existing == *bytes => {}
                Some(_) => return Err(QRunV06ForkStoreError::BranchBytesMismatch),
                None if bytes.as_slice() == prepared.candidate_envelope => {
                    write_new_atomic(&path, bytes)?;
                }
                None => return Err(QRunV06ForkStoreError::MissingBranch),
            }
        }
        if candidate_seen != 1 {
            return Err(QRunV06ForkStoreError::PreparedCommitMismatch);
        }

        let manifest_path = self
            .manifests_dir
            .join(manifest_filename(prepared.generation));
        self.poisoned = true;
        write_new_atomic(&manifest_path, &prepared.manifest_bytes)?;
        self.graph = prepared.staged_graph;
        self.generation = prepared.generation;
        self.manifest_anchor = prepared.manifest_anchor;
        self.poisoned = false;

        Ok(QRunV06DurableCommit {
            outcome: prepared.outcome,
            generation: self.generation,
            manifest_anchor: self.manifest_anchor,
        })
    }

    /// Verify a manifest that may already have been installed before a process crash, while
    /// QAP1 still records AnchorConfirmed. The active manifest and candidate branch must exactly
    /// match the externally confirmed successor before QAP1 may advance to LocalManifestCommitted.
    pub fn verify_published_successor_with_qap1<PV: MlDsa65Verifier, AV: MlDsa65Verifier>(
        &self,
        journal: &QRunV06Qap1Journal,
        provider_pin: &ExternalCasPin,
        anchor_pin: &ExternalCasOffhostAnchorPin,
        provider_verifier: &PV,
        anchor_verifier: &AV,
    ) -> Result<(), QRunV06ForkStoreError> {
        self.ensure_healthy()?;
        if !matches!(
            journal.phase(),
            QRunV06Qap1Phase::AnchorConfirmed
                | QRunV06Qap1Phase::LocalManifestCommitted
                | QRunV06Qap1Phase::Finalized
        ) {
            return Err(QRunV06ForkStoreError::PreparedCommitMismatch);
        }
        journal.verify_saved_evidence(
            provider_pin,
            anchor_pin,
            provider_verifier,
            anchor_verifier,
        )?;
        let local =
            QRunV06ExternalAnchorState::from_store(self, journal.successor().genesis_digest)
                .map_err(|_| QRunV06ForkStoreError::PreparedCommitMismatch)?;
        if local != *journal.successor() {
            return Err(QRunV06ForkStoreError::PreparedCommitMismatch);
        }
        let manifest_path = self
            .manifests_dir
            .join(manifest_filename(journal.successor().manifest_generation));
        let manifest_bytes = read_bounded(&manifest_path, MAX_QRUN_V06_MANIFEST_BYTES)?;
        if manifest_bytes != journal.next_manifest_bytes()
            || manifest_commitment(&manifest_bytes) != journal.successor().manifest_anchor
        {
            return Err(QRunV06ForkStoreError::PreparedCommitMismatch);
        }
        let envelopes = self.graph.archive_envelopes_bounded(
            MAX_QRUN_V06_FORK_ARCHIVE_BLOCKS,
            MAX_QRUN_V06_DURABLE_ARCHIVE_BYTES,
        )?;
        if !envelopes
            .iter()
            .any(|bytes| bytes.as_slice() == journal.candidate_envelope())
        {
            return Err(QRunV06ForkStoreError::PreparedCommitMismatch);
        }
        Ok(())
    }

    /// Validate one QFP6 envelope, stage it on a cloned branch graph, persist all branch files,
    /// and publish an immutable next manifest as the sole local commit point.
    pub fn submit<A: TransactionAuthenticator>(
        &mut self,
        envelope: &[u8],
        authenticator: &A,
    ) -> Result<QRunV06DurableCommit, QRunV06ForkStoreError> {
        self.submit_with_hook_and_quote_authorization(envelope, authenticator, None, |_| Ok(()))
    }

    pub fn submit_with_quote_asset_authorization<A: TransactionAuthenticator>(
        &mut self,
        envelope: &[u8],
        authenticator: &A,
        quote_authorizer: &mut QRunV06QuoteAssetAuthorizationProvider<'_>,
    ) -> Result<QRunV06DurableCommit, QRunV06ForkStoreError> {
        self.submit_with_hook_and_quote_authorization(
            envelope,
            authenticator,
            Some(quote_authorizer),
            |_| Ok(()),
        )
    }

    #[cfg(test)]
    fn submit_with_hook<A, F>(
        &mut self,
        envelope: &[u8],
        authenticator: &A,
        hook: F,
    ) -> Result<QRunV06DurableCommit, QRunV06ForkStoreError>
    where
        A: TransactionAuthenticator,
        F: FnMut(CommitStage) -> Result<(), QRunV06ForkStoreError>,
    {
        self.submit_with_hook_and_quote_authorization(envelope, authenticator, None, hook)
    }

    fn submit_with_hook_and_quote_authorization<A, F>(
        &mut self,
        envelope: &[u8],
        authenticator: &A,
        mut quote_authorizer: Option<&mut QRunV06QuoteAssetAuthorizationProvider<'_>>,
        mut hook: F,
    ) -> Result<QRunV06DurableCommit, QRunV06ForkStoreError>
    where
        A: TransactionAuthenticator,
        F: FnMut(CommitStage) -> Result<(), QRunV06ForkStoreError>,
    {
        self.ensure_healthy()?;
        if envelope.len() > MAX_QRUN_V06_POW_ENVELOPE_BYTES {
            return Err(QRunV06ForkStoreError::ArchiveBytesExceeded);
        }

        let mut staged = self.graph.clone();
        let outcome = if let Some(provider) = quote_authorizer.as_deref_mut() {
            staged.insert_encoded_with_quote_asset_authorization(
                envelope,
                authenticator,
                provider,
            )?
        } else {
            staged.insert_encoded(envelope, authenticator)?
        };
        if staged.archive_len() == self.graph.archive_len() {
            return Ok(QRunV06DurableCommit {
                outcome,
                generation: self.generation,
                manifest_anchor: self.manifest_anchor,
            });
        }

        let entries = collect_manifest_entries(&staged, &self.params)?;
        let total_bytes = entries
            .iter()
            .try_fold(0usize, |total, entry| {
                total.checked_add(entry.encoded_len as usize)
            })
            .ok_or(QRunV06ForkStoreError::ArchiveBytesExceeded)?;
        if entries.len() > MAX_QRUN_V06_FORK_ARCHIVE_BLOCKS {
            return Err(QRunV06ForkStoreError::ArchiveCapacityExceeded);
        }
        if total_bytes > MAX_QRUN_V06_DURABLE_ARCHIVE_BYTES {
            return Err(QRunV06ForkStoreError::ArchiveBytesExceeded);
        }

        let envelopes = staged.archive_envelopes_bounded(
            MAX_QRUN_V06_FORK_ARCHIVE_BLOCKS,
            MAX_QRUN_V06_DURABLE_ARCHIVE_BYTES,
        )?;
        for bytes in &envelopes {
            let decoded = decode_qrun_v06_pow_block(bytes)?;
            let digest = pow_digest(&decoded.header, self.params.pow)?;
            let path = self.branches_dir.join(branch_filename(&digest));
            match read_optional_bounded(&path, MAX_QRUN_V06_POW_ENVELOPE_BYTES)? {
                Some(existing) if existing == *bytes => {}
                Some(_) => return Err(QRunV06ForkStoreError::BranchBytesMismatch),
                None => write_new_atomic_with_hook(&path, bytes, |stage| {
                    hook(match stage {
                        AtomicWriteStage::TemporaryFileCreated => {
                            CommitStage::BranchTempFileCreated
                        }
                        AtomicWriteStage::TemporaryFileSynced => CommitStage::BranchTempFileSynced,
                        AtomicWriteStage::DestinationInstalled => CommitStage::BranchFileInstalled,
                    })
                })?,
            }
        }
        hook(CommitStage::BranchFilesSynced)?;

        let next_generation = self
            .generation
            .checked_add(1)
            .ok_or(QRunV06ForkStoreError::ManifestGenerationMismatch)?;
        let manifest =
            manifest_from_graph(next_generation, self.manifest_anchor, &self.params, &staged)?;
        let manifest_bytes = encode_manifest(&manifest)?;
        let next_anchor = manifest_commitment(&manifest_bytes);
        let manifest_path = self.manifests_dir.join(manifest_filename(next_generation));

        // A failure during manifest publication can leave an ambiguous on-disk commit if the
        // filesystem reports an error after rename. Poison this handle and require anchored reopen.
        self.poisoned = true;
        write_new_atomic_with_hook(&manifest_path, &manifest_bytes, |stage| {
            hook(match stage {
                AtomicWriteStage::TemporaryFileCreated => CommitStage::ManifestTempFileCreated,
                AtomicWriteStage::TemporaryFileSynced => CommitStage::ManifestTempFileSynced,
                AtomicWriteStage::DestinationInstalled => CommitStage::ManifestFileInstalled,
            })
        })?;
        hook(CommitStage::ManifestFileSynced)?;
        self.graph = staged;
        self.generation = next_generation;
        self.manifest_anchor = next_anchor;
        self.poisoned = false;

        Ok(QRunV06DurableCommit {
            outcome,
            generation: self.generation,
            manifest_anchor: self.manifest_anchor,
        })
    }

    pub fn canonical_height(&self) -> Result<u64, QRunV06ForkStoreError> {
        self.ensure_healthy()?;
        Ok(self.graph.canonical_state().height())
    }

    pub fn canonical_tip(&self) -> Result<[u8; 32], QRunV06ForkStoreError> {
        self.ensure_healthy()?;
        Ok(self.graph.canonical_tip().tip_hash)
    }

    pub fn canonical_state_root(&self) -> Result<[u8; 32], QRunV06ForkStoreError> {
        self.ensure_healthy()?;
        self.graph
            .canonical_state()
            .state_root()
            .map_err(|error| QRunV06ForkStoreError::Io(format!("QFB6 state root: {error:?}")))
    }

    pub fn archive_len(&self) -> Result<usize, QRunV06ForkStoreError> {
        self.ensure_healthy()?;
        Ok(self.graph.archive_len())
    }

    pub fn generation(&self) -> Result<u64, QRunV06ForkStoreError> {
        self.ensure_healthy()?;
        Ok(self.generation)
    }

    pub fn manifest_anchor(&self) -> Result<[u8; 32], QRunV06ForkStoreError> {
        self.ensure_healthy()?;
        Ok(self.manifest_anchor)
    }

    /// Return the fingerprint of the consensus profile validated by this store.
    pub fn consensus_fingerprint(&self) -> Result<[u8; 32], QRunV06ForkStoreError> {
        self.ensure_healthy()?;
        consensus_fingerprint(&self.params)
    }

    pub fn checkpoint_anchor(&self) -> Result<Option<[u8; 32]>, QRunV06ForkStoreError> {
        self.ensure_healthy()?;
        Ok(self.checkpoint_anchor)
    }

    /// Export the current canonical QFP6 checkpoint. Persist the returned commitment through
    /// an independent trust provider before opening a new durable segment from these bytes.
    pub fn export_canonical_checkpoint(
        &self,
    ) -> Result<(Vec<u8>, [u8; 32]), QRunV06ForkStoreError> {
        self.ensure_healthy()?;
        let checkpoint = self.graph.canonical_checkpoint()?;
        let bytes = checkpoint.encode_snapshot()?;
        let anchor = checkpoint.commitment()?;
        Ok((bytes, anchor))
    }

    pub fn graph(&self) -> Result<&QRunV06PowForkChoice, QRunV06ForkStoreError> {
        self.ensure_healthy()?;
        Ok(&self.graph)
    }

    /// Dedicated QAP1 journal directory owned by this already-open durable store.
    pub fn qap1_directory(&self) -> Result<PathBuf, QRunV06ForkStoreError> {
        self.ensure_healthy()?;
        let root = self
            .branches_dir
            .parent()
            .ok_or(QRunV06ForkStoreError::UnexpectedEntry)?;
        Ok(root.join(QAP1_DIR))
    }

    /// Detect any unresolved QAP1 phase or interrupted temporary snapshot. Legacy Runtime
    /// constructors use this to refuse startup rather than bypass a durable intent journal.
    pub fn has_qap1_intent(&self) -> Result<bool, QRunV06ForkStoreError> {
        self.ensure_healthy()?;
        let directory = self.qap1_directory()?;
        match fs::symlink_metadata(&directory) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(QRunV06ForkStoreError::Io(error.to_string())),
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() => {
                return Err(QRunV06ForkStoreError::UnexpectedEntry)
            }
            Ok(_) => {}
        }
        let _lock =
            StoreWriterLock::acquire(&directory, "qfp6-qap1.writer.lock").map_err(|error| {
                if error.kind() == io::ErrorKind::WouldBlock {
                    QRunV06ForkStoreError::WriterLockHeld
                } else {
                    QRunV06ForkStoreError::Io(error.to_string())
                }
            })?;
        let mut pending = false;
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_symlink() || !kind.is_file() {
                return Err(QRunV06ForkStoreError::UnexpectedEntry);
            }
            let name = entry.file_name().to_string_lossy().to_string();
            if name == "qfp6-qap1.writer.lock" {
                continue;
            }
            let known_phase =
                (1..=7).any(|phase| name == format!("qfp6-anchor-qap1-{phase:02}.qap1"));
            if known_phase || (name.starts_with(".qap1-") && name.ends_with(".tmp")) {
                pending = true;
                continue;
            }
            return Err(QRunV06ForkStoreError::UnexpectedEntry);
        }
        Ok(pending)
    }

    /// Derive the exact Q6EA successor that the staged, not-yet-published QFP6 graph would
    /// represent. This binds the prepared Manifest, canonical tip, state root and chainwork.
    pub fn external_anchor_state_for_prepared(
        &self,
        prepared: &QRunV06PreparedCommit,
        genesis_digest: [u8; 32],
    ) -> Result<QRunV06ExternalAnchorState, QRunV06ForkStoreError> {
        self.ensure_healthy()?;
        if prepared.parent_generation != self.generation
            || prepared.parent_manifest_anchor != self.manifest_anchor
            || prepared.generation
                != self
                    .generation
                    .checked_add(1)
                    .ok_or(QRunV06ForkStoreError::ManifestGenerationMismatch)?
        {
            return Err(QRunV06ForkStoreError::PreparedCommitMismatch);
        }
        let mut next = QRunV06ExternalAnchorState::from_store(self, genesis_digest)
            .map_err(|error| QRunV06ForkStoreError::Qap1(error.to_string()))?;
        let tip = prepared.staged_graph.canonical_tip();
        next.segment_base_height = prepared.staged_graph.base_height();
        next.segment_base_tip = prepared.staged_graph.base_tip();
        next.manifest_generation = prepared.generation;
        next.manifest_anchor = prepared.manifest_anchor;
        next.canonical_height = tip.height;
        next.canonical_tip = tip.tip_hash;
        next.canonical_state_root = prepared
            .staged_graph
            .canonical_state()
            .state_root()
            .map_err(|error| QRunV06ForkStoreError::Io(format!("QFB6 state root: {error:?}")))?;
        next.cumulative_chainwork = prepared
            .staged_graph
            .branch_work(&tip.tip_hash)
            .ok_or(QRunV06ForkStoreError::PreparedCommitMismatch)?
            .to_be_bytes();
        let current = QRunV06ExternalAnchorState::from_store(self, genesis_digest)
            .map_err(|error| QRunV06ForkStoreError::Qap1(error.to_string()))?;
        current
            .validate_successor(&next)
            .map_err(|error| QRunV06ForkStoreError::Qap1(error.to_string()))?;
        Ok(next)
    }

    /// Reconcile an ambiguous manifest-publication result after submit() poisoned this handle.
    ///
    /// This re-reads the complete manifest chain and replays the latest referenced archive before
    /// returning an anchor. The caller must write the returned anchor to its independent trust
    /// provider, drop this handle, and reopen the store with that exact anchor before continuing.
    pub fn recovery_hint<A: TransactionAuthenticator>(
        &self,
        authenticator: &A,
    ) -> Result<QRunV06RecoveryHint, QRunV06ForkStoreError> {
        self.recovery_hint_inner(authenticator, None)
    }

    pub fn recovery_hint_with_quote_asset_authorization<A: TransactionAuthenticator>(
        &self,
        authenticator: &A,
        quote_authorizer: &mut QRunV06QuoteAssetAuthorizationProvider<'_>,
    ) -> Result<QRunV06RecoveryHint, QRunV06ForkStoreError> {
        self.recovery_hint_inner(authenticator, Some(quote_authorizer))
    }

    fn recovery_hint_inner<A: TransactionAuthenticator>(
        &self,
        authenticator: &A,
        mut quote_authorizer: Option<&mut QRunV06QuoteAssetAuthorizationProvider<'_>>,
    ) -> Result<QRunV06RecoveryHint, QRunV06ForkStoreError> {
        if !self.poisoned {
            return Err(QRunV06ForkStoreError::NoPendingRecovery);
        }
        let manifests = load_manifest_chain(&self.manifests_dir)?;
        let (latest, anchor) = manifests
            .last()
            .ok_or(QRunV06ForkStoreError::ManifestGenerationMismatch)?;

        let expected_fingerprint = consensus_fingerprint(&self.params)?;
        validate_manifest_identity(latest, &self.graph, expected_fingerprint)?;
        let envelopes = load_branch_entries(&self.branches_dir, &latest.entries, &self.params)?;
        let rebuilt = if let Some(provider) = quote_authorizer.as_deref_mut() {
            self.graph
                .rebuild_from_current_base_with_quote_asset_authorization(
                    envelopes,
                    authenticator,
                    provider,
                )?
        } else {
            self.graph
                .rebuild_from_current_base(envelopes, authenticator)?
        };
        validate_manifest_graph(latest, &rebuilt)?;

        if latest.generation == self.generation && *anchor == self.manifest_anchor {
            return Ok(QRunV06RecoveryHint {
                generation: self.generation,
                manifest_anchor: self.manifest_anchor,
                manifest_committed: false,
            });
        }
        let expected_next_generation = self
            .generation
            .checked_add(1)
            .ok_or(QRunV06ForkStoreError::ManifestGenerationMismatch)?;
        if latest.generation == expected_next_generation
            && latest.parent_manifest_anchor == self.manifest_anchor
        {
            return Ok(QRunV06RecoveryHint {
                generation: latest.generation,
                manifest_anchor: *anchor,
                manifest_committed: true,
            });
        }
        Err(QRunV06ForkStoreError::ManifestGenerationMismatch)
    }

    fn ensure_healthy(&self) -> Result<(), QRunV06ForkStoreError> {
        if self.poisoned {
            Err(QRunV06ForkStoreError::RecoveryRequired)
        } else {
            Ok(())
        }
    }
}

fn manifest_from_graph(
    generation: u64,
    parent_manifest_anchor: [u8; 32],
    params: &ConsensusParameters,
    graph: &QRunV06PowForkChoice,
) -> Result<QRunV06StoreManifest, QRunV06ForkStoreError> {
    let tip = graph.canonical_tip();
    let canonical_state_root = graph
        .canonical_state()
        .state_root()
        .map_err(|error| QRunV06ForkStoreError::Io(format!("QFB6 state root: {error:?}")))?;
    let chainwork = graph
        .branch_work(&tip.tip_hash)
        .ok_or(QRunV06ForkStoreError::ManifestMalformed)?;
    Ok(QRunV06StoreManifest {
        generation,
        parent_manifest_anchor,
        network_id: graph.network_id(),
        profile_id: graph.profile_id(),
        consensus_fingerprint: consensus_fingerprint(params)?,
        base_tip: graph.base_tip(),
        base_height: graph.base_height(),
        canonical_tip: tip.tip_hash,
        canonical_height: tip.height,
        canonical_state_root,
        canonical_chainwork: chainwork.to_be_bytes(),
        entries: collect_manifest_entries(graph, params)?,
    })
}

fn collect_manifest_entries(
    graph: &QRunV06PowForkChoice,
    params: &ConsensusParameters,
) -> Result<Vec<ManifestEntry>, QRunV06ForkStoreError> {
    if graph.archive_len() > MAX_QRUN_V06_FORK_ARCHIVE_BLOCKS {
        return Err(QRunV06ForkStoreError::ArchiveCapacityExceeded);
    }
    let mut entries = Vec::with_capacity(graph.archive_len());
    for bytes in graph.archive_envelopes_bounded(
        MAX_QRUN_V06_FORK_ARCHIVE_BLOCKS,
        MAX_QRUN_V06_DURABLE_ARCHIVE_BYTES,
    )? {
        let decoded = decode_qrun_v06_pow_block(&bytes)?;
        let digest = pow_digest(&decoded.header, params.pow)?;
        let encoded_len =
            u32::try_from(bytes.len()).map_err(|_| QRunV06ForkStoreError::ArchiveBytesExceeded)?;
        entries.push(ManifestEntry {
            digest,
            height: decoded.block.height,
            encoded_len,
            envelope_hash: sha256(&bytes),
        });
    }
    entries.sort_by_key(|entry| entry.digest);
    if entries
        .windows(2)
        .any(|pair| pair[0].digest >= pair[1].digest)
    {
        return Err(QRunV06ForkStoreError::ManifestMalformed);
    }
    Ok(entries)
}

fn validate_manifest_identity(
    manifest: &QRunV06StoreManifest,
    graph: &QRunV06PowForkChoice,
    expected_fingerprint: [u8; 32],
) -> Result<(), QRunV06ForkStoreError> {
    if manifest.network_id != graph.network_id() {
        return Err(QRunV06ForkStoreError::WrongNetwork);
    }
    if manifest.profile_id != graph.profile_id() {
        return Err(QRunV06ForkStoreError::WrongProfile);
    }
    if manifest.consensus_fingerprint != expected_fingerprint {
        return Err(QRunV06ForkStoreError::ManifestConsensusMismatch);
    }
    if manifest.base_tip != graph.base_tip() || manifest.base_height != graph.base_height() {
        return Err(QRunV06ForkStoreError::BaseStateMismatch);
    }
    Ok(())
}

fn validate_manifest_graph(
    manifest: &QRunV06StoreManifest,
    graph: &QRunV06PowForkChoice,
) -> Result<(), QRunV06ForkStoreError> {
    let tip = graph.canonical_tip();
    let root = graph
        .canonical_state()
        .state_root()
        .map_err(|error| QRunV06ForkStoreError::Io(format!("QFB6 replay root: {error:?}")))?;
    let work = graph
        .branch_work(&tip.tip_hash)
        .ok_or(QRunV06ForkStoreError::ManifestMalformed)?;
    if tip.tip_hash != manifest.canonical_tip
        || tip.height != manifest.canonical_height
        || root != manifest.canonical_state_root
        || work.to_be_bytes() != manifest.canonical_chainwork
        || graph.archive_len() != manifest.entries.len()
    {
        return Err(QRunV06ForkStoreError::ManifestProfileMismatch);
    }
    Ok(())
}

fn encode_manifest(manifest: &QRunV06StoreManifest) -> Result<Vec<u8>, QRunV06ForkStoreError> {
    if manifest.entries.len() > MAX_QRUN_V06_FORK_ARCHIVE_BLOCKS
        || manifest.network_id == [0; 32]
        || manifest.profile_id == [0; 32]
        || manifest
            .entries
            .windows(2)
            .any(|pair| pair[0].digest >= pair[1].digest)
    {
        return Err(QRunV06ForkStoreError::ManifestMalformed);
    }

    let total_len = MANIFEST_FIXED_PREFIX_BYTES
        .checked_add(
            manifest
                .entries
                .len()
                .checked_mul(MANIFEST_ENTRY_BYTES)
                .ok_or(QRunV06ForkStoreError::ManifestMalformed)?,
        )
        .and_then(|length| length.checked_add(CHECKSUM_BYTES))
        .ok_or(QRunV06ForkStoreError::ManifestMalformed)?;
    if total_len > MAX_QRUN_V06_MANIFEST_BYTES {
        return Err(QRunV06ForkStoreError::ManifestMalformed);
    }

    let mut bytes = Vec::with_capacity(total_len);
    bytes.extend_from_slice(MANIFEST_MAGIC);
    bytes.extend_from_slice(&MANIFEST_VERSION.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.extend_from_slice(&(total_len as u32).to_be_bytes());
    bytes.extend_from_slice(&manifest.generation.to_be_bytes());
    bytes.extend_from_slice(&manifest.parent_manifest_anchor);
    bytes.extend_from_slice(&manifest.network_id);
    bytes.extend_from_slice(&manifest.profile_id);
    bytes.extend_from_slice(&manifest.consensus_fingerprint);
    bytes.extend_from_slice(&manifest.base_tip);
    bytes.extend_from_slice(&manifest.base_height.to_be_bytes());
    bytes.extend_from_slice(&manifest.canonical_tip);
    bytes.extend_from_slice(&manifest.canonical_height.to_be_bytes());
    bytes.extend_from_slice(&manifest.canonical_state_root);
    bytes.extend_from_slice(&manifest.canonical_chainwork);
    bytes.extend_from_slice(&(manifest.entries.len() as u32).to_be_bytes());
    if bytes.len() != MANIFEST_FIXED_PREFIX_BYTES {
        return Err(QRunV06ForkStoreError::ManifestMalformed);
    }
    let maximum_segment_height = manifest
        .base_height
        .checked_add(MAX_QRUN_V06_FORK_BRANCH_HEIGHT)
        .ok_or(QRunV06ForkStoreError::ManifestMalformed)?;
    for entry in &manifest.entries {
        if entry.encoded_len == 0
            || entry.encoded_len as usize > MAX_QRUN_V06_POW_ENVELOPE_BYTES
            || entry.height <= manifest.base_height
            || entry.height > maximum_segment_height
        {
            return Err(QRunV06ForkStoreError::ManifestMalformed);
        }
        bytes.extend_from_slice(&entry.digest);
        bytes.extend_from_slice(&entry.height.to_be_bytes());
        bytes.extend_from_slice(&entry.encoded_len.to_be_bytes());
        bytes.extend_from_slice(&entry.envelope_hash);
    }
    if bytes.len() + CHECKSUM_BYTES != total_len {
        return Err(QRunV06ForkStoreError::ManifestMalformed);
    }
    let checksum = manifest_checksum(&bytes);
    bytes.extend_from_slice(&checksum);
    Ok(bytes)
}

fn decode_manifest(bytes: &[u8]) -> Result<QRunV06StoreManifest, QRunV06ForkStoreError> {
    if bytes.len() < MANIFEST_FIXED_PREFIX_BYTES + CHECKSUM_BYTES
        || bytes.len() > MAX_QRUN_V06_MANIFEST_BYTES
        || &bytes[..4] != MANIFEST_MAGIC
        || take_u16(bytes, 4)? != MANIFEST_VERSION
        || take_u16(bytes, 6)? != 0
        || u32::from_be_bytes(
            bytes[8..12]
                .try_into()
                .map_err(|_| QRunV06ForkStoreError::ManifestMalformed)?,
        ) as usize
            != bytes.len()
    {
        return Err(QRunV06ForkStoreError::ManifestMalformed);
    }
    if bytes[bytes.len() - CHECKSUM_BYTES..]
        != manifest_checksum(&bytes[..bytes.len() - CHECKSUM_BYTES])
    {
        return Err(QRunV06ForkStoreError::ManifestChecksumMismatch);
    }
    let mut cursor = 12usize;
    let generation = take_u64(bytes, &mut cursor)?;
    let parent_manifest_anchor = take_array::<32>(bytes, &mut cursor)?;
    let network_id = take_array::<32>(bytes, &mut cursor)?;
    let profile_id = take_array::<32>(bytes, &mut cursor)?;
    let consensus_fingerprint = take_array::<32>(bytes, &mut cursor)?;
    let base_tip = take_array::<32>(bytes, &mut cursor)?;
    let base_height = take_u64(bytes, &mut cursor)?;
    let canonical_tip = take_array::<32>(bytes, &mut cursor)?;
    let canonical_height = take_u64(bytes, &mut cursor)?;
    let canonical_state_root = take_array::<32>(bytes, &mut cursor)?;
    let canonical_chainwork = take_array::<32>(bytes, &mut cursor)?;
    let count = take_u32(bytes, &mut cursor)? as usize;
    let expected_len = MANIFEST_FIXED_PREFIX_BYTES
        .checked_add(
            count
                .checked_mul(MANIFEST_ENTRY_BYTES)
                .ok_or(QRunV06ForkStoreError::ManifestMalformed)?,
        )
        .and_then(|length| length.checked_add(CHECKSUM_BYTES))
        .ok_or(QRunV06ForkStoreError::ManifestMalformed)?;
    if count > MAX_QRUN_V06_FORK_ARCHIVE_BLOCKS || expected_len != bytes.len() {
        return Err(QRunV06ForkStoreError::ManifestMalformed);
    }
    let maximum_segment_height = base_height
        .checked_add(MAX_QRUN_V06_FORK_BRANCH_HEIGHT)
        .ok_or(QRunV06ForkStoreError::ManifestMalformed)?;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        entries.push(ManifestEntry {
            digest: take_array::<32>(bytes, &mut cursor)?,
            height: take_u64(bytes, &mut cursor)?,
            encoded_len: take_u32(bytes, &mut cursor)?,
            envelope_hash: take_array::<32>(bytes, &mut cursor)?,
        });
    }
    if cursor != bytes.len() - CHECKSUM_BYTES
        || entries
            .windows(2)
            .any(|pair| pair[0].digest >= pair[1].digest)
    {
        return Err(QRunV06ForkStoreError::ManifestMalformed);
    }
    let manifest = QRunV06StoreManifest {
        generation,
        parent_manifest_anchor,
        network_id,
        profile_id,
        consensus_fingerprint,
        base_tip,
        base_height,
        canonical_tip,
        canonical_height,
        canonical_state_root,
        canonical_chainwork,
        entries,
    };
    if manifest.network_id == [0; 32]
        || manifest.profile_id == [0; 32]
        || manifest.entries.iter().any(|entry| {
            entry.height <= manifest.base_height
                || entry.height > maximum_segment_height
                || entry.encoded_len == 0
                || entry.encoded_len as usize > MAX_QRUN_V06_POW_ENVELOPE_BYTES
        })
    {
        return Err(QRunV06ForkStoreError::ManifestMalformed);
    }
    Ok(manifest)
}

fn load_manifest_chain(
    manifests_dir: &Path,
) -> Result<Vec<(QRunV06StoreManifest, [u8; 32])>, QRunV06ForkStoreError> {
    let mut files = BTreeMap::<u64, PathBuf>::new();
    for entry in fs::read_dir(manifests_dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            return Err(QRunV06ForkStoreError::UnexpectedEntry);
        }
        let name = entry.file_name().to_string_lossy().to_string();
        let generation =
            parse_manifest_filename(&name).ok_or(QRunV06ForkStoreError::UnexpectedEntry)?;
        if files.insert(generation, entry.path()).is_some() {
            return Err(QRunV06ForkStoreError::ManifestGenerationMismatch);
        }
    }
    if files.len() > MAX_QRUN_V06_FORK_ARCHIVE_BLOCKS + 1 {
        return Err(QRunV06ForkStoreError::ArchiveCapacityExceeded);
    }

    let mut chain: Vec<(QRunV06StoreManifest, [u8; 32])> = Vec::with_capacity(files.len());
    let mut previous_anchor = [0; 32];
    for (expected_generation, (generation, path)) in files.iter().enumerate() {
        if *generation != expected_generation as u64 {
            return Err(QRunV06ForkStoreError::ManifestGenerationMismatch);
        }
        let bytes = read_bounded(path, MAX_QRUN_V06_MANIFEST_BYTES)?;
        let manifest = decode_manifest(&bytes)?;
        if manifest.generation != *generation {
            return Err(QRunV06ForkStoreError::ManifestGenerationMismatch);
        }
        if manifest.parent_manifest_anchor != previous_anchor {
            return Err(QRunV06ForkStoreError::ManifestParentMismatch);
        }
        if manifest.entries.len() as u64 != manifest.generation {
            return Err(QRunV06ForkStoreError::ManifestGenerationMismatch);
        }
        let anchor = manifest_commitment(&bytes);
        if let Some((previous, _)) = chain.last() {
            if manifest.network_id != previous.network_id
                || manifest.profile_id != previous.profile_id
                || manifest.consensus_fingerprint != previous.consensus_fingerprint
                || manifest.base_tip != previous.base_tip
                || manifest.base_height != previous.base_height
            {
                return Err(QRunV06ForkStoreError::ManifestParentMismatch);
            }
        }
        previous_anchor = anchor;
        chain.push((manifest, anchor));
    }
    Ok(chain)
}

fn load_branch_entries(
    branches_dir: &Path,
    entries: &[ManifestEntry],
    params: &ConsensusParameters,
) -> Result<Vec<Vec<u8>>, QRunV06ForkStoreError> {
    let mut envelopes = Vec::with_capacity(entries.len());
    let mut total_bytes = 0usize;
    for entry in entries {
        let path = branches_dir.join(branch_filename(&entry.digest));
        if !path_exists_no_follow(&path)? {
            return Err(QRunV06ForkStoreError::MissingBranch);
        }
        let bytes = read_bounded(&path, MAX_QRUN_V06_POW_ENVELOPE_BYTES)?;
        if bytes.len() != entry.encoded_len as usize || sha256(&bytes) != entry.envelope_hash {
            return Err(QRunV06ForkStoreError::BranchDigestMismatch);
        }
        let decoded = decode_qrun_v06_pow_block(&bytes)?;
        let digest = pow_digest(&decoded.header, params.pow)?;
        if decoded.block.height != entry.height || digest != entry.digest {
            return Err(QRunV06ForkStoreError::BranchDigestMismatch);
        }
        total_bytes = total_bytes
            .checked_add(bytes.len())
            .ok_or(QRunV06ForkStoreError::ArchiveBytesExceeded)?;
        if total_bytes > MAX_QRUN_V06_DURABLE_ARCHIVE_BYTES {
            return Err(QRunV06ForkStoreError::ArchiveBytesExceeded);
        }
        envelopes.push(bytes);
    }
    Ok(envelopes)
}

fn reconcile_branch_directory(
    branches_dir: &Path,
    referenced: &[ManifestEntry],
) -> Result<(), QRunV06ForkStoreError> {
    let expected = referenced
        .iter()
        .map(|entry| branch_filename(&entry.digest))
        .collect::<BTreeSet<_>>();
    for entry in fs::read_dir(branches_dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            return Err(QRunV06ForkStoreError::UnexpectedEntry);
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if !is_branch_filename(&name) {
            return Err(QRunV06ForkStoreError::UnexpectedEntry);
        }
        if !expected.contains(&name) {
            fs::remove_file(entry.path())?;
        }
    }
    for name in expected {
        let path = branches_dir.join(name);
        if !path_exists_no_follow(&path)? {
            return Err(QRunV06ForkStoreError::MissingBranch);
        }
    }
    Ok(())
}

fn cleanup_temp_files(directory: &Path) -> Result<(), QRunV06ForkStoreError> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with(TEMP_PREFIX) && name.ends_with(TEMP_SUFFIX) {
            if !entry.file_type()?.is_file() {
                return Err(QRunV06ForkStoreError::UnexpectedEntry);
            }
            fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

fn validate_root_entries(directory: &Path) -> Result<(), QRunV06ForkStoreError> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        let kind = entry.file_type()?;
        if kind.is_symlink() {
            return Err(QRunV06ForkStoreError::UnexpectedEntry);
        }
        match name.as_str() {
            LOCK_NAME | CHECKPOINT_FILE if kind.is_file() => {}
            BRANCH_DIR | MANIFEST_DIR | QAP1_DIR if kind.is_dir() => {}
            _ => return Err(QRunV06ForkStoreError::UnexpectedEntry),
        }
    }
    Ok(())
}

fn ensure_real_directory(path: &Path) -> Result<(), QRunV06ForkStoreError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(QRunV06ForkStoreError::UnexpectedEntry);
    }
    Ok(())
}

fn reject_symlink_if_present(path: &Path) -> Result<(), QRunV06ForkStoreError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.file_type().is_file() => {
            Err(QRunV06ForkStoreError::UnexpectedEntry)
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn read_optional_bounded(
    path: &Path,
    max_bytes: usize,
) -> Result<Option<Vec<u8>>, QRunV06ForkStoreError> {
    if !path_exists_no_follow(path)? {
        return Ok(None);
    }
    read_bounded(path, max_bytes).map(Some)
}

fn read_bounded(path: &Path, max_bytes: usize) -> Result<Vec<u8>, QRunV06ForkStoreError> {
    let path_metadata = fs::symlink_metadata(path)?;
    if path_metadata.file_type().is_symlink() || !path_metadata.file_type().is_file() {
        return Err(QRunV06ForkStoreError::UnexpectedEntry);
    }
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > max_bytes as u64 {
        return Err(QRunV06ForkStoreError::ArchiveBytesExceeded);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(max_bytes as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(QRunV06ForkStoreError::ArchiveBytesExceeded);
    }
    Ok(bytes)
}

fn path_exists_no_follow(path: &Path) -> Result<bool, QRunV06ForkStoreError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AtomicWriteStage {
    TemporaryFileCreated,
    TemporaryFileSynced,
    DestinationInstalled,
}

fn write_new_atomic(path: &Path, bytes: &[u8]) -> Result<(), QRunV06ForkStoreError> {
    write_new_atomic_with_hook(path, bytes, |_| Ok(()))
}

fn write_new_atomic_with_hook<F>(
    path: &Path,
    bytes: &[u8],
    mut hook: F,
) -> Result<(), QRunV06ForkStoreError>
where
    F: FnMut(AtomicWriteStage) -> Result<(), QRunV06ForkStoreError>,
{
    let directory = path
        .parent()
        .ok_or(QRunV06ForkStoreError::UnexpectedEntry)?;
    let file_name = path
        .file_name()
        .ok_or(QRunV06ForkStoreError::UnexpectedEntry)?;
    let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    let mut temp_name = std::ffi::OsString::from(TEMP_PREFIX);
    temp_name.push(format!("{}.{}.", std::process::id(), sequence));
    temp_name.push(file_name);
    temp_name.push(TEMP_SUFFIX);
    let temp_path = directory.join(temp_name);
    let mut cleanup = TempCleanup::new(temp_path.clone());

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)?;
    hook(AtomicWriteStage::TemporaryFileCreated)?;
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_all()?;
    drop(file);
    hook(AtomicWriteStage::TemporaryFileSynced)?;

    if path_exists_no_follow(path)? {
        return Err(QRunV06ForkStoreError::BranchBytesMismatch);
    }
    atomic_install_new(&temp_path, path)?;
    cleanup.disarm();
    hook(AtomicWriteStage::DestinationInstalled)?;
    Ok(())
}

struct TempCleanup {
    path: PathBuf,
    armed: bool,
}
impl TempCleanup {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }
    fn disarm(&mut self) {
        self.armed = false;
    }
}
impl Drop for TempCleanup {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(windows)]
fn atomic_install_new(source: &Path, destination: &Path) -> Result<(), QRunV06ForkStoreError> {
    use std::os::windows::ffi::OsStrExt;

    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;
    let source_wide: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination_wide: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();

    #[link(name = "Kernel32")]
    extern "system" {
        fn MoveFileExW(existing: *const u16, new_name: *const u16, flags: u32) -> i32;
    }

    // No REPLACE_EXISTING flag: immutable digest-named branch files and generation manifests
    // must never overwrite an existing destination. WRITE_THROUGH asks Windows to flush the move.
    let success = unsafe {
        MoveFileExW(
            source_wide.as_ptr(),
            destination_wide.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    };
    if success == 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(unix)]
fn atomic_install_new(source: &Path, destination: &Path) -> Result<(), QRunV06ForkStoreError> {
    // A same-filesystem hard link is atomic and fails if the immutable destination already exists.
    // Remove the temporary name, then fsync the directory so both name changes are durable.
    fs::hard_link(source, destination)?;
    fs::remove_file(source)?;
    let parent = destination
        .parent()
        .ok_or(QRunV06ForkStoreError::UnexpectedEntry)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(not(any(windows, unix)))]
fn atomic_install_new(_source: &Path, _destination: &Path) -> Result<(), QRunV06ForkStoreError> {
    Err(QRunV06ForkStoreError::Io(
        "atomic no-replace install is unsupported on this target".into(),
    ))
}

fn consensus_fingerprint(params: &ConsensusParameters) -> Result<[u8; 32], QRunV06ForkStoreError> {
    params.validate()?;
    let mut hash = Sha256::new();
    hash.update(CONSENSUS_FINGERPRINT_DOMAIN);
    hash.update(params.protocol_version.to_be_bytes());
    hash.update(params.target_block_time_secs.to_be_bytes());
    hash.update(params.difficulty_window_blocks.to_be_bytes());
    hash.update(params.difficulty_min_ratio_divisor.to_be_bytes());
    hash.update(params.difficulty_max_ratio.to_be_bytes());
    hash.update(params.pow_limit.to_be_bytes());
    hash.update(params.initial_target.to_be_bytes());
    match params.pow.algorithm {
        PowAlgorithm::Argon2id => hash.update([1]),
    }
    hash.update(params.pow.memory_kib.to_be_bytes());
    hash.update(params.pow.iterations.to_be_bytes());
    hash.update(params.pow.lanes.to_be_bytes());
    hash.update([params.pow.output_bytes]);
    hash.update(params.issuance.maximum_supply().to_be_bytes());
    hash.update(params.issuance.initial_subsidy().to_be_bytes());
    hash.update(params.issuance.blocks_per_halving().to_be_bytes());
    Ok(hash.finalize().into())
}

fn manifest_checksum(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(MANIFEST_CHECKSUM_DOMAIN);
    hash.update(bytes);
    hash.finalize().into()
}

fn manifest_commitment(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(MANIFEST_COMMITMENT_DOMAIN);
    hash.update(bytes);
    hash.finalize().into()
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn branch_filename(digest: &[u8; 32]) -> String {
    format!("{BRANCH_PREFIX}{}{BRANCH_SUFFIX}", hex(digest))
}

fn is_branch_filename(name: &str) -> bool {
    if !name.starts_with(BRANCH_PREFIX) || !name.ends_with(BRANCH_SUFFIX) {
        return false;
    }
    let hex_part = &name[BRANCH_PREFIX.len()..name.len() - BRANCH_SUFFIX.len()];
    hex_part.len() == 64
        && hex_part
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn manifest_filename(generation: u64) -> String {
    format!("{MANIFEST_PREFIX}{generation:020}{MANIFEST_SUFFIX}")
}

fn parse_manifest_filename(name: &str) -> Option<u64> {
    if !name.starts_with(MANIFEST_PREFIX) || !name.ends_with(MANIFEST_SUFFIX) {
        return None;
    }
    let middle = &name[MANIFEST_PREFIX.len()..name.len() - MANIFEST_SUFFIX.len()];
    if middle.len() != 20 || !middle.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    middle.parse().ok()
}

fn take_array<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], QRunV06ForkStoreError> {
    let end = cursor
        .checked_add(N)
        .ok_or(QRunV06ForkStoreError::ManifestMalformed)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(QRunV06ForkStoreError::ManifestMalformed)?
        .try_into()
        .map_err(|_| QRunV06ForkStoreError::ManifestMalformed)?;
    *cursor = end;
    Ok(value)
}

fn take_u16(bytes: &[u8], offset: usize) -> Result<u16, QRunV06ForkStoreError> {
    let end = offset
        .checked_add(2)
        .ok_or(QRunV06ForkStoreError::ManifestMalformed)?;
    Ok(u16::from_be_bytes(
        bytes
            .get(offset..end)
            .ok_or(QRunV06ForkStoreError::ManifestMalformed)?
            .try_into()
            .map_err(|_| QRunV06ForkStoreError::ManifestMalformed)?,
    ))
}

fn take_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, QRunV06ForkStoreError> {
    Ok(u32::from_be_bytes(take_array(bytes, cursor)?))
}
fn take_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64, QRunV06ForkStoreError> {
    Ok(u64::from_be_bytes(take_array(bytes, cursor)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        consensus::{PowAlgorithm, PowParameters, Uint256},
        external_cas_anchor_candidate::{
            ExternalCasPin, ExternalCasReceipt, ExternalCasReceiptKind, ExternalCasReceiptOutcome,
            ExternalCasRecord, ExternalCasWriteRequest,
        },
        external_cas_offhost_anchor_candidate::ExternalCasOffhostAnchorState,
        external_cas_offhost_anchor_protocol_candidate::{
            ExternalCasOffhostAnchorCasRequest, ExternalCasOffhostAnchorMemoryModel,
            ExternalCasOffhostAnchorPin, ExternalCasOffhostAnchorReadRequest,
            OffhostAnchorReceiptSigner,
        },
        qrun_v06_canonical_execution_candidate::{
            QRunV06Block, QRunV06BlockOperation, QRunV06ExecutionError,
        },
        qrun_v06_pow_wire_candidate::{encode_qrun_v06_pow_block, qrun_v06_pow_state_commitment},
        qrun_v06_profile_pin_candidate::QRunV06ProfilePinCandidate,
        qrun_v06_profile_trust_candidate::{
            authorize_qrun_v06_profile_pin, prepublish_qrun_v06_profile_trust_floor,
            MonotonicQRunV06ProfileTrustFloorStore, PinnedQRunV06ProfileTrustAuthority,
            QRunV06ProfileTrustError, QRunV06ProfileTrustRecord, QRunV06ProfileTrustStatus,
            QRunV06SignedProfileTrustEnvelope, TrustedQRunV06ProfileTrustFloor,
        },
        qrun_v06_qap1_journal_candidate::{QRunV06Qap1Journal, QRunV06Qap1Phase, QAP1_DIRECTORY},
        qrun_v06_tokenomics_candidate::{
            QRunV06AllocationBucket, QRunV06MiningScheduleCandidate, QRunV06TokenomicsError,
            QRUN_V06_FOUNDER_GENESIS_ATOMS,
        },
        state_machine::{AccountId, TransactionAuthenticator},
        transaction_auth::{
            AccountPublicKey, Ed25519TransactionAuthenticator, Ed25519TransactionSigner,
            TransactionAuthenticatorKind,
        },
        v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate,
        v4_fat1_trust_candidate::{
            MlDsa65Verifier, ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SIGNATURE_BYTES,
        },
    };
    use ed25519_dalek::{Signer, SigningKey};
    use libcrux_ml_dsa::ml_dsa_65::{portable, MLDSA65SigningKey};
    use std::sync::Arc;
    use std::{
        env,
        process::Command,
        time::{SystemTime, UNIX_EPOCH},
    };

    const NETWORK: [u8; 32] = [0x71; 32];
    const PROFILE: [u8; 32] = [0x72; 32];
    const OWNER: [u8; 32] = [0x73; 32];
    const PRODUCER: [u8; 32] = [0x74; 32];

    struct TestQ6eaAnchorSigner(Arc<MLDSA65SigningKey>);
    impl OffhostAnchorReceiptSigner for TestQ6eaAnchorSigner {
        fn sign_digest(
            &self,
            digest: &[u8; 32],
        ) -> Result<[u8; ML_DSA_65_SIGNATURE_BYTES], String> {
            let signature = portable::sign(self.0.as_ref(), digest, &[], [0xCB; 32])
                .map_err(|error| format!("{error:?}"))?;
            Ok(*signature.as_ref())
        }
    }

    struct EmptyAuthenticator;
    impl TransactionAuthenticator for EmptyAuthenticator {
        fn verify(&self, _: &AccountId, _: &[u8; 32], _: &[u8]) -> Result<(), ()> {
            Err(())
        }
    }

    struct TestQ6pnTrustFloor {
        floor: TrustedQRunV06ProfileTrustFloor,
    }
    impl MonotonicQRunV06ProfileTrustFloorStore for TestQ6pnTrustFloor {
        fn load(
            &self,
            network_id: &[u8; 32],
            profile_id: &[u8; 32],
        ) -> Result<TrustedQRunV06ProfileTrustFloor, QRunV06ProfileTrustError> {
            if &self.floor.network_id != network_id || &self.floor.profile_id != profile_id {
                return Err(QRunV06ProfileTrustError::WrongNetworkOrProfile);
            }
            Ok(self.floor.clone())
        }

        fn compare_and_swap(
            &mut self,
            expected: &TrustedQRunV06ProfileTrustFloor,
            next: &TrustedQRunV06ProfileTrustFloor,
        ) -> Result<(), QRunV06ProfileTrustError> {
            if &self.floor != expected {
                return Err(QRunV06ProfileTrustError::FloorCasConflict);
            }
            self.floor = next.clone();
            Ok(())
        }
    }

    struct TestPqVerifier;
    impl MlDsa65Verifier for TestPqVerifier {
        fn verify(
            &self,
            public_key: &[u8; ML_DSA_65_PUBLIC_KEY_BYTES],
            digest: &[u8; 32],
            signature: &[u8; ML_DSA_65_SIGNATURE_BYTES],
        ) -> bool {
            *public_key == [0x98; ML_DSA_65_PUBLIC_KEY_BYTES]
                && *digest != [0; 32]
                && *signature == [0x97; ML_DSA_65_SIGNATURE_BYTES]
        }
    }

    struct TestDir(PathBuf);
    impl TestDir {
        fn new() -> Self {
            let tick = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = env::temp_dir().join(format!("qfp6_store_{}_{}", std::process::id(), tick));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn params() -> ConsensusParameters {
        let mut params = ConsensusParameters::candidate_testnet().unwrap();
        params.protocol_version = 6;
        params.target_block_time_secs = 30;
        params.difficulty_window_blocks = 2;
        params.difficulty_min_ratio_divisor = 4;
        params.difficulty_max_ratio = 4;
        params.initial_target = crate::consensus::Uint256::from_be_bytes([0x7F; 32]);
        params.pow_limit = crate::consensus::Uint256::MAX;
        params.pow = PowParameters {
            algorithm: PowAlgorithm::Argon2id,
            memory_kib: 8,
            iterations: 1,
            lanes: 1,
            output_bytes: 32,
        };
        params.validate().unwrap();
        params
    }

    fn genesis_state_for_founder(founder: AccountId) -> QRunV06CanonicalExecutionState {
        let consensus = params();
        let schedule = QRunV06MiningScheduleCandidate::cp0422_research_candidate();
        let tokenomics = crate::qrun_v06_tokenomics_candidate::QRunV06TokenomicsState::genesis(
            NETWORK, founder, schedule,
        )
        .unwrap();
        let descriptor =
            crate::qrun_v06_genesis_descriptor_candidate::QRunV06GenesisDescriptor::new(
                NETWORK,
                PROFILE,
                founder,
                1,
                crate::qrun_v06_checkpoint_candidate::qrun_v06_consensus_fingerprint(&consensus)
                    .unwrap(),
                tokenomics.policy_fingerprint(),
            )
            .unwrap();
        QRunV06CanonicalExecutionState::cp0528_genesis_candidate_with_descriptor(
            descriptor, schedule,
        )
        .unwrap()
    }

    fn genesis_state() -> QRunV06CanonicalExecutionState {
        genesis_state_for_founder(OWNER)
    }

    fn cp0528_genesis_state() -> QRunV06CanonicalExecutionState {
        genesis_state_for_founder(OWNER)
    }

    fn candidate(
        parent: &QRunV06CanonicalExecutionState,
        parent_consensus_tip: [u8; 32],
        timestamp: u64,
        target: Uint256,
        params: &ConsensusParameters,
    ) -> (Vec<u8>, [u8; 32]) {
        let mut block = QRunV06Block {
            network_id: NETWORK,
            profile_id: parent.profile_id(),
            height: parent.height() + 1,
            timestamp,
            parent_hash: parent.tip_hash(),
            state_root: [0; 32],
            producer: PRODUCER,
            operations: Vec::<QRunV06BlockOperation>::new(),
        };
        block.state_root = parent
            .preview_state_root_after(&block, &EmptyAuthenticator)
            .unwrap();
        let mut header = crate::consensus::PowHeader {
            protocol_version: 6,
            network_id: NETWORK,
            height: block.height,
            timestamp,
            parent_hash: block.parent_hash,
            previous_consensus_hash: parent_consensus_tip,
            state_root: qrun_v06_pow_state_commitment(&block).unwrap(),
            target,
            nonce: 0,
        };
        for nonce in 0..4_096u64 {
            header.nonce = nonce;
            let digest = pow_digest(&header, params.pow).unwrap();
            if Uint256::from_be_bytes(digest) <= target {
                return (encode_qrun_v06_pow_block(&header, &block).unwrap(), digest);
            }
        }
        panic!("test PoW nonce search exhausted");
    }

    fn candidate_with_operations<A: TransactionAuthenticator>(
        parent: &QRunV06CanonicalExecutionState,
        parent_consensus_tip: [u8; 32],
        timestamp: u64,
        target: Uint256,
        params: &ConsensusParameters,
        operations: Vec<QRunV06BlockOperation>,
        authenticator: &A,
    ) -> (Vec<u8>, [u8; 32]) {
        let mut block = QRunV06Block {
            network_id: NETWORK,
            profile_id: parent.profile_id(),
            height: parent.height() + 1,
            timestamp,
            parent_hash: parent.tip_hash(),
            state_root: [0; 32],
            producer: PRODUCER,
            operations,
        };
        block.state_root = parent
            .preview_state_root_after(&block, authenticator)
            .unwrap();
        let mut header = crate::consensus::PowHeader {
            protocol_version: 6,
            network_id: NETWORK,
            height: block.height,
            timestamp,
            parent_hash: block.parent_hash,
            previous_consensus_hash: parent_consensus_tip,
            state_root: qrun_v06_pow_state_commitment(&block).unwrap(),
            target,
            nonce: 0,
        };
        for nonce in 0..4_096u64 {
            header.nonce = nonce;
            let digest = pow_digest(&header, params.pow).unwrap();
            if Uint256::from_be_bytes(digest) <= target {
                return (encode_qrun_v06_pow_block(&header, &block).unwrap(), digest);
            }
        }
        panic!("test PoW nonce search exhausted");
    }

    fn candidate_with_quote_authorization(
        parent: &QRunV06CanonicalExecutionState,
        parent_consensus_tip: [u8; 32],
        timestamp: u64,
        target: Uint256,
        params: &ConsensusParameters,
        quote_authorization: &crate::qrun_v06_profile_trust_candidate::QRunV06TrustAuthorizedQuoteAsset,
    ) -> Vec<u8> {
        let mut block = QRunV06Block {
            network_id: NETWORK,
            profile_id: parent.profile_id(),
            height: parent.height() + 1,
            timestamp,
            parent_hash: parent.tip_hash(),
            state_root: [0; 32],
            producer: PRODUCER,
            operations: Vec::new(),
        };
        block.state_root = parent
            .preview_state_root_after_with_quote_asset_authorization(
                &block,
                &EmptyAuthenticator,
                Some(quote_authorization),
            )
            .unwrap();
        let mut header = crate::consensus::PowHeader {
            protocol_version: 6,
            network_id: NETWORK,
            height: block.height,
            timestamp,
            parent_hash: block.parent_hash,
            previous_consensus_hash: parent_consensus_tip,
            state_root: qrun_v06_pow_state_commitment(&block).unwrap(),
            target,
            nonce: 0,
        };
        for nonce in 0..4_096u64 {
            header.nonce = nonce;
            let digest = pow_digest(&header, params.pow).unwrap();
            if Uint256::from_be_bytes(digest) <= target {
                return encode_qrun_v06_pow_block(&header, &block).unwrap();
            }
        }
        panic!("test quote-authorized durable-store PoW nonce search exhausted");
    }

    fn invalid_candidate_with_operations(
        parent: &QRunV06CanonicalExecutionState,
        parent_consensus_tip: [u8; 32],
        timestamp: u64,
        target: Uint256,
        params: &ConsensusParameters,
        operations: Vec<QRunV06BlockOperation>,
    ) -> Vec<u8> {
        let block = QRunV06Block {
            network_id: NETWORK,
            profile_id: parent.profile_id(),
            height: parent.height() + 1,
            timestamp,
            parent_hash: parent.tip_hash(),
            state_root: [0xEE; 32],
            producer: PRODUCER,
            operations,
        };
        let mut header = crate::consensus::PowHeader {
            protocol_version: 6,
            network_id: NETWORK,
            height: block.height,
            timestamp,
            parent_hash: block.parent_hash,
            previous_consensus_hash: parent_consensus_tip,
            state_root: qrun_v06_pow_state_commitment(&block).unwrap(),
            target,
            nonce: 0,
        };
        for nonce in 0..4_096u64 {
            header.nonce = nonce;
            let digest = pow_digest(&header, params.pow).unwrap();
            if Uint256::from_be_bytes(digest) <= target {
                return encode_qrun_v06_pow_block(&header, &block).unwrap();
            }
        }
        panic!("test PoW nonce search exhausted");
    }

    #[test]
    fn durable_signed_category_release_survives_segment_rollover_and_two_restarts() {
        let genesis_dir = TestDir::new();
        let segment_one = TestDir::new();
        let segment_two = TestDir::new();
        let params = params();
        let founder = Ed25519TransactionSigner::from_seed([0xA1; 32]);
        let recipient = Ed25519TransactionSigner::from_seed([0xA2; 32]);
        let founder_id = founder.account_id();
        let recipient_id = recipient.account_id();
        let authenticator = Ed25519TransactionAuthenticator::select(
            TransactionAuthenticatorKind::Ed25519V1,
            [
                AccountPublicKey {
                    account_id: founder_id,
                    public_key: founder.public_key(),
                },
                AccountPublicKey {
                    account_id: recipient_id,
                    public_key: recipient.public_key(),
                },
            ],
        )
        .unwrap();
        let genesis = genesis_state_for_founder(founder_id);

        // Segment zero advances from Genesis, then exports an independently anchored checkpoint.
        let mut genesis_store = QRunV06DurableForkStore::open(
            &genesis_dir.0,
            genesis.clone(),
            params.clone(),
            &authenticator,
            None,
        )
        .unwrap();
        let genesis_tip = genesis_store.graph().unwrap().base_tip();
        let target1 = genesis_store
            .graph()
            .unwrap()
            .expected_next_target(&genesis_tip)
            .unwrap();
        let (block1, tip1) = candidate(&genesis, genesis_tip, 100, target1, &params);
        genesis_store.submit(&block1, &authenticator).unwrap();
        let (checkpoint1, checkpoint1_anchor) =
            genesis_store.export_canonical_checkpoint().unwrap();
        drop(genesis_store);

        // Segment one receives the checkpoint and executes a real dual-Ed25519 release.
        let mut store = QRunV06DurableForkStore::open_from_checkpoint(
            &segment_one.0,
            &checkpoint1,
            params.clone(),
            NETWORK,
            PROFILE,
            checkpoint1_anchor,
            &authenticator,
            None,
        )
        .unwrap();
        let mut release = crate::qrun_v06_tokenomics_candidate::QRunV06SignedCategoryRelease {
            network_id: NETWORK,
            bucket: QRunV06AllocationBucket::CommunityAirdrop,
            nonce: 1,
            recipient: recipient_id,
            amount_atoms: 77_000,
            valid_until_timestamp: 10_000,
            purpose_digest: [0xA3; 32],
            evidence_digest: [0xA4; 32],
            milestone_policy_digest: [0xA5; 32],
            founder_signature: Vec::new(),
            recipient_acceptance_signature: Vec::new(),
        };
        release.founder_signature = founder.sign_digest(&release.signing_digest().unwrap());
        release.recipient_acceptance_signature =
            recipient.sign_digest(&release.recipient_acceptance_digest().unwrap());
        let release_id = release.release_id().unwrap();
        let replay_release = release.clone();
        let parent = store.graph().unwrap().canonical_state().clone();
        let target2 = store.graph().unwrap().expected_next_target(&tip1).unwrap();
        let (release_block, tip2) = candidate_with_operations(
            &parent,
            tip1,
            120,
            target2,
            &params,
            vec![QRunV06BlockOperation::CategoryRelease(release)],
            &authenticator,
        );
        store.submit(&release_block, &authenticator).unwrap();
        assert_eq!(store.canonical_tip().unwrap(), tip2);

        let expected_root = store.canonical_state_root().unwrap();
        let expected_anchor = store.manifest_anchor().unwrap();
        let state = store.graph().unwrap().canonical_state();
        let tokenomics = state.tokenomics().unwrap();
        assert_eq!(tokenomics.founder_release_nonce(), 1);
        assert_eq!(tokenomics.last_release_id(), release_id);
        assert_eq!(
            tokenomics.issued_by_bucket_atoms(QRunV06AllocationBucket::CommunityAirdrop),
            77_000
        );
        assert_eq!(
            state
                .unified()
                .ledger()
                .account(&recipient_id)
                .unwrap()
                .balance,
            77_000
        );
        drop(store);

        // Restart one: replay the complete segment from its checkpoint and manifest anchor.
        let mut reopened = QRunV06DurableForkStore::open_from_checkpoint(
            &segment_one.0,
            &checkpoint1,
            params.clone(),
            NETWORK,
            PROFILE,
            checkpoint1_anchor,
            &authenticator,
            Some(expected_anchor),
        )
        .unwrap();
        assert_eq!(reopened.canonical_tip().unwrap(), tip2);
        assert_eq!(reopened.canonical_state_root().unwrap(), expected_root);
        let restored = reopened.graph().unwrap().canonical_state();
        assert_eq!(restored.tokenomics().unwrap().founder_release_nonce(), 1);
        assert_eq!(restored.tokenomics().unwrap().last_release_id(), release_id);
        assert_eq!(
            restored
                .unified()
                .ledger()
                .account(&recipient_id)
                .unwrap()
                .balance,
            77_000
        );

        // A byte-identical old release cannot be replayed after a full store restart.
        let replay_target = reopened
            .graph()
            .unwrap()
            .expected_next_target(&tip2)
            .unwrap();
        let replay_envelope = invalid_candidate_with_operations(
            restored,
            tip2,
            180,
            replay_target,
            &params,
            vec![QRunV06BlockOperation::CategoryRelease(replay_release)],
        );
        let before_generation = reopened.generation().unwrap();
        let before_anchor = reopened.manifest_anchor().unwrap();
        assert!(matches!(
            reopened.submit(&replay_envelope, &authenticator),
            Err(QRunV06ForkStoreError::Fork(
                QRunV06ForkChoiceError::Execution(QRunV06ExecutionError::Tokenomics(
                    QRunV06TokenomicsError::InvalidReleaseNonce {
                        expected: 2,
                        actual: 1
                    }
                ))
            ))
        ));
        assert_eq!(reopened.canonical_tip().unwrap(), tip2);
        assert_eq!(reopened.canonical_state_root().unwrap(), expected_root);
        assert_eq!(reopened.generation().unwrap(), before_generation);
        assert_eq!(reopened.manifest_anchor().unwrap(), before_anchor);

        // Roll over again from the restored canonical state, then restart a second time.
        let (checkpoint2, checkpoint2_anchor) = reopened.export_canonical_checkpoint().unwrap();
        drop(reopened);
        let reopened_segment_two = QRunV06DurableForkStore::open_from_checkpoint(
            &segment_two.0,
            &checkpoint2,
            params,
            NETWORK,
            PROFILE,
            checkpoint2_anchor,
            &authenticator,
            None,
        )
        .unwrap();
        assert_eq!(reopened_segment_two.canonical_tip().unwrap(), tip2);
        assert_eq!(
            reopened_segment_two.canonical_state_root().unwrap(),
            expected_root
        );
        let final_state = reopened_segment_two.graph().unwrap().canonical_state();
        assert_eq!(final_state.tokenomics().unwrap().founder_release_nonce(), 1);
        assert_eq!(
            final_state.tokenomics().unwrap().last_release_id(),
            release_id
        );
        assert_eq!(
            final_state
                .tokenomics()
                .unwrap()
                .issued_by_bucket_atoms(QRunV06AllocationBucket::CommunityAirdrop),
            77_000
        );
        assert_eq!(
            final_state
                .unified()
                .ledger()
                .account(&recipient_id)
                .unwrap()
                .balance,
            77_000
        );
    }

    #[test]
    fn durable_reorg_never_leaks_signed_release_from_losing_branch_after_restart() {
        let dir = TestDir::new();
        let params = params();
        let founder = Ed25519TransactionSigner::from_seed([0xB1; 32]);
        let recipient = Ed25519TransactionSigner::from_seed([0xB2; 32]);
        let founder_id = founder.account_id();
        let recipient_id = recipient.account_id();
        let authenticator = Ed25519TransactionAuthenticator::select(
            TransactionAuthenticatorKind::Ed25519V1,
            [
                AccountPublicKey {
                    account_id: founder_id,
                    public_key: founder.public_key(),
                },
                AccountPublicKey {
                    account_id: recipient_id,
                    public_key: recipient.public_key(),
                },
            ],
        )
        .unwrap();
        let genesis = genesis_state_for_founder(founder_id);
        let mut store = QRunV06DurableForkStore::open(
            &dir.0,
            genesis.clone(),
            params.clone(),
            &authenticator,
            None,
        )
        .unwrap();
        let base = store.graph().unwrap().base_tip();
        let target1 = store.graph().unwrap().expected_next_target(&base).unwrap();

        let mut release = crate::qrun_v06_tokenomics_candidate::QRunV06SignedCategoryRelease {
            network_id: NETWORK,
            bucket: QRunV06AllocationBucket::CommunityAirdrop,
            nonce: 1,
            recipient: recipient_id,
            amount_atoms: 77_000,
            valid_until_timestamp: 10_000,
            purpose_digest: [0xB3; 32],
            evidence_digest: [0xB4; 32],
            milestone_policy_digest: [0xB5; 32],
            founder_signature: Vec::new(),
            recipient_acceptance_signature: Vec::new(),
        };
        release.founder_signature = founder.sign_digest(&release.signing_digest().unwrap());
        release.recipient_acceptance_signature =
            recipient.sign_digest(&release.recipient_acceptance_digest().unwrap());
        let (release_branch, release_tip) = candidate_with_operations(
            &genesis,
            base,
            100,
            target1,
            &params,
            vec![QRunV06BlockOperation::CategoryRelease(release)],
            &authenticator,
        );
        store.submit(&release_branch, &authenticator).unwrap();

        // The competing sibling has no release. A child gives it strictly more cumulative work.
        let (plain_branch, plain_tip) = candidate(&genesis, base, 100, target1, &params);
        store.submit(&plain_branch, &authenticator).unwrap();
        let plain_state = store
            .graph()
            .unwrap()
            .state_for_tip(&plain_tip)
            .unwrap()
            .clone();
        let target2 = store
            .graph()
            .unwrap()
            .expected_next_target(&plain_tip)
            .unwrap();
        let (plain_child, canonical_tip) =
            candidate(&plain_state, plain_tip, 130, target2, &params);
        store.submit(&plain_child, &authenticator).unwrap();
        assert_eq!(store.canonical_tip().unwrap(), canonical_tip);
        assert!(
            store.graph().unwrap().branch_work(&canonical_tip).unwrap()
                > store.graph().unwrap().branch_work(&release_tip).unwrap()
        );

        let canonical_state = store.graph().unwrap().canonical_state();
        assert_eq!(
            canonical_state
                .tokenomics()
                .unwrap()
                .founder_release_nonce(),
            0
        );
        assert!(canonical_state
            .unified()
            .ledger()
            .account(&recipient_id)
            .is_none());
        let losing_state = store.graph().unwrap().state_for_tip(&release_tip).unwrap();
        assert_eq!(
            losing_state.tokenomics().unwrap().founder_release_nonce(),
            1
        );
        assert_eq!(
            losing_state
                .unified()
                .ledger()
                .account(&recipient_id)
                .unwrap()
                .balance,
            77_000
        );
        let expected_root = store.canonical_state_root().unwrap();
        let anchor = store.manifest_anchor().unwrap();
        drop(store);

        // Restart replays both siblings, but only the heavier no-release branch is canonical.
        let reopened =
            QRunV06DurableForkStore::open(&dir.0, genesis, params, &authenticator, Some(anchor))
                .unwrap();
        assert_eq!(reopened.canonical_tip().unwrap(), canonical_tip);
        assert_eq!(reopened.canonical_state_root().unwrap(), expected_root);
        let canonical_after_restart = reopened.graph().unwrap().canonical_state();
        assert_eq!(
            canonical_after_restart
                .tokenomics()
                .unwrap()
                .founder_release_nonce(),
            0
        );
        assert!(canonical_after_restart
            .unified()
            .ledger()
            .account(&recipient_id)
            .is_none());
        let losing_after_restart = reopened
            .graph()
            .unwrap()
            .state_for_tip(&release_tip)
            .unwrap();
        assert_eq!(
            losing_after_restart
                .tokenomics()
                .unwrap()
                .founder_release_nonce(),
            1
        );
        assert_eq!(
            losing_after_restart
                .unified()
                .ledger()
                .account(&recipient_id)
                .unwrap()
                .balance,
            77_000
        );
    }

    #[test]
    fn prepare_is_side_effect_free_and_reproducible_before_qap1() {
        let params = params();
        let genesis = genesis_state();
        let descriptor_commitment = genesis.genesis_descriptor_commitment().unwrap();
        let auth = EmptyAuthenticator;
        let directory = TestDir::new();
        let mut store = QRunV06DurableForkStore::open_with_expected_genesis_descriptor_commitment(
            &directory.0,
            genesis,
            params.clone(),
            &auth,
            None,
            descriptor_commitment,
        )
        .unwrap();

        let parent = store.graph().unwrap().canonical_state().clone();
        let parent_tip = store.graph().unwrap().canonical_tip().tip_hash;
        let target = store
            .graph()
            .unwrap()
            .expected_next_target(&parent_tip)
            .unwrap();
        let (envelope, candidate_digest) = candidate(&parent, parent_tip, 60, target, &params);
        let before_generation = store.generation().unwrap();
        let before_anchor = store.manifest_anchor().unwrap();
        let before_height = store.canonical_height().unwrap();
        let branch_path = store.branches_dir.join(branch_filename(&candidate_digest));
        let manifest_path = store
            .manifests_dir
            .join(manifest_filename(before_generation + 1));

        let first = store.prepare(&envelope, &auth).unwrap().unwrap();
        assert_eq!(first.candidate_envelope(), envelope);
        assert_eq!(first.parent_generation(), before_generation);
        assert_eq!(first.parent_manifest_anchor(), before_anchor);
        assert_eq!(first.generation(), before_generation + 1);
        assert_eq!(
            manifest_commitment(first.manifest_bytes()),
            first.manifest_anchor()
        );
        assert!(!branch_path.exists());
        assert!(!manifest_path.exists());
        assert_eq!(store.generation().unwrap(), before_generation);
        assert_eq!(store.manifest_anchor().unwrap(), before_anchor);
        assert_eq!(store.canonical_height().unwrap(), before_height);
        assert_eq!(store.canonical_tip().unwrap(), parent_tip);

        let second = store.prepare(&envelope, &auth).unwrap().unwrap();
        assert_eq!(second.candidate_envelope(), first.candidate_envelope());
        assert_eq!(second.manifest_bytes(), first.manifest_bytes());
        assert_eq!(second.manifest_anchor(), first.manifest_anchor());
        assert_eq!(second.generation(), first.generation());

        // The old one-shot API still provides its historical semantics; the new prepare API
        // remains uncommitted until publish_prepared_with_qap1 is supplied an AnchorConfirmed QAP1.
    }

    #[test]
    fn qap1_publish_rejects_unconfirmed_anchor_without_any_store_mutation() {
        let params = params();
        let genesis = genesis_state();
        let descriptor_commitment = genesis.genesis_descriptor_commitment().unwrap();
        let auth = EmptyAuthenticator;
        let directory = TestDir::new();
        let mut store = QRunV06DurableForkStore::open_with_expected_genesis_descriptor_commitment(
            &directory.0,
            genesis,
            params.clone(),
            &auth,
            None,
            descriptor_commitment,
        )
        .unwrap();

        let before = QRunV06ExternalAnchorState::from_store(&store, [0x75; 32]).unwrap();
        let parent = store.graph().unwrap().canonical_state().clone();
        let parent_tip = store.graph().unwrap().canonical_tip().tip_hash;
        let target = store
            .graph()
            .unwrap()
            .expected_next_target(&parent_tip)
            .unwrap();
        let (envelope, candidate_digest) = candidate(&parent, parent_tip, 60, target, &params);
        let prepared = store.prepare(&envelope, &auth).unwrap().unwrap();

        let provider_keys = libcrux_ml_dsa::ml_dsa_65::portable::generate_key_pair([0xD5; 32]);
        let anchor_keys = libcrux_ml_dsa::ml_dsa_65::portable::generate_key_pair([0xD6; 32]);
        let provider_public: [u8; ML_DSA_65_PUBLIC_KEY_BYTES] =
            *provider_keys.verification_key.as_ref();
        let anchor_public: [u8; ML_DSA_65_PUBLIC_KEY_BYTES] =
            *anchor_keys.verification_key.as_ref();
        let pin = ExternalCasPin {
            provider_id: [0xD1; 32],
            network_id: NETWORK,
            genesis_digest: [0x75; 32],
            receipt_key_id: [0xD2; 32],
            receipt_public_key: provider_public,
        };
        let anchor_pin = ExternalCasOffhostAnchorPin {
            anchor_id: [0xD3; 32],
            provider_id: pin.provider_id,
            network_id: pin.network_id,
            genesis_digest: pin.genesis_digest,
            receipt_key_id: [0xD4; 32],
            receipt_public_key: anchor_public,
        };

        let tip = prepared.staged_graph.canonical_tip();
        let work = prepared
            .staged_graph
            .branch_work(&tip.tip_hash)
            .unwrap()
            .to_be_bytes();
        let successor = QRunV06ExternalAnchorState {
            network_id: before.network_id,
            genesis_digest: before.genesis_digest,
            genesis_descriptor_commitment: before.genesis_descriptor_commitment,
            profile_id: before.profile_id,
            consensus_fingerprint: store.consensus_fingerprint().unwrap(),
            segment_base_height: prepared.staged_graph.base_height(),
            segment_base_tip: prepared.staged_graph.base_tip(),
            checkpoint_anchor: store.checkpoint_anchor().unwrap().unwrap_or([0; 32]),
            manifest_generation: prepared.generation,
            manifest_anchor: prepared.manifest_anchor,
            canonical_height: tip.height,
            canonical_tip: tip.tip_hash,
            canonical_state_root: prepared
                .staged_graph
                .canonical_state()
                .state_root()
                .unwrap(),
            cumulative_chainwork: work,
        };
        before.validate_successor(&successor).unwrap();

        let bootstrap_record = ExternalCasRecord {
            generation: 0,
            provider_id: pin.provider_id,
            network_id: pin.network_id,
            genesis_digest: pin.genesis_digest,
            previous_record_digest: [0; 32],
            previous_state_digest: [0; 32],
            next_state_digest: before.digest().unwrap(),
            operation_id: [0xD7; 32],
            request_digest: [0xD8; 32],
        };
        let anchor_before =
            ExternalCasOffhostAnchorState::provision_bootstrap(&pin, bootstrap_record.clone(), 1)
                .unwrap();
        let operation_id = [0xD9; 32];
        let mut provider_request = ExternalCasWriteRequest {
            request_nonce: [0xDA; 32],
            operation_id,
            request_digest: [1; 32],
            expected_generation: 0,
            expected_object_generation: 1,
            expected_record_digest: bootstrap_record.digest().unwrap(),
            expected_state_digest: before.digest().unwrap(),
            next_record: ExternalCasRecord {
                generation: 1,
                provider_id: pin.provider_id,
                network_id: pin.network_id,
                genesis_digest: pin.genesis_digest,
                previous_record_digest: bootstrap_record.digest().unwrap(),
                previous_state_digest: before.digest().unwrap(),
                next_state_digest: successor.digest().unwrap(),
                operation_id,
                request_digest: [0; 32],
            },
        };
        provider_request.bind_request_digest(&pin).unwrap();

        let prepared_journal = QRunV06Qap1Journal::new(
            before.clone(),
            successor,
            anchor_before,
            provider_request,
            envelope.clone(),
            prepared.manifest_bytes.clone(),
            &pin,
        )
        .unwrap();
        assert_eq!(prepared_journal.phase(), QRunV06Qap1Phase::Prepared);

        let branch_path = store.branches_dir.join(branch_filename(&candidate_digest));
        let manifest_path = store
            .manifests_dir
            .join(manifest_filename(prepared.generation));
        let result = store.publish_prepared_with_qap1(
            prepared,
            &prepared_journal,
            &pin,
            &anchor_pin,
            &LibcruxMlDsa65VerifierCandidate,
            &LibcruxMlDsa65VerifierCandidate,
        );
        assert!(matches!(
            result,
            Err(QRunV06ForkStoreError::PreparedCommitMismatch)
        ));
        assert!(!branch_path.exists());
        assert!(!manifest_path.exists());
        assert_eq!(store.generation().unwrap(), before.manifest_generation);
        assert_eq!(store.manifest_anchor().unwrap(), before.manifest_anchor);
        assert_eq!(store.canonical_height().unwrap(), before.canonical_height);
        assert_eq!(store.canonical_tip().unwrap(), before.canonical_tip);
    }

    #[test]
    fn qap1_anchor_confirmed_rebuilds_and_publishes_exact_manifest_after_store_restart() {
        let params = params();
        let genesis = genesis_state();
        let descriptor_commitment = genesis.genesis_descriptor_commitment().unwrap();
        let auth = EmptyAuthenticator;
        let directory = TestDir::new();
        let mut store = QRunV06DurableForkStore::open_with_expected_genesis_descriptor_commitment(
            &directory.0,
            genesis.clone(),
            params.clone(),
            &auth,
            None,
            descriptor_commitment,
        )
        .unwrap();

        // Build a QFP6 candidate without changing the active manifest.
        let predecessor = QRunV06ExternalAnchorState::from_store(&store, [0x75; 32]).unwrap();
        let parent = store.graph().unwrap().canonical_state().clone();
        let parent_tip = store.graph().unwrap().canonical_tip().tip_hash;
        let target = store
            .graph()
            .unwrap()
            .expected_next_target(&parent_tip)
            .unwrap();
        let (candidate_envelope, _) = candidate(&parent, parent_tip, 60, target, &params);
        let prepared = store.prepare(&candidate_envelope, &auth).unwrap().unwrap();

        // Independent Provider and Q6EA test identities. These deterministic keys are test-only.
        let provider_pair = portable::generate_key_pair([0xE1; 32]);
        let anchor_pair = portable::generate_key_pair([0xE2; 32]);
        let provider_public: [u8; ML_DSA_65_PUBLIC_KEY_BYTES] =
            *provider_pair.verification_key.as_ref();
        let anchor_public: [u8; ML_DSA_65_PUBLIC_KEY_BYTES] =
            *anchor_pair.verification_key.as_ref();
        let provider_key = Arc::new(provider_pair.signing_key);
        let anchor_key = Arc::new(anchor_pair.signing_key);
        let provider_pin = ExternalCasPin {
            provider_id: [0xE3; 32],
            network_id: NETWORK,
            genesis_digest: predecessor.genesis_digest,
            receipt_key_id: [0xE4; 32],
            receipt_public_key: provider_public,
        };
        let anchor_pin = ExternalCasOffhostAnchorPin {
            anchor_id: [0xE5; 32],
            provider_id: provider_pin.provider_id,
            network_id: provider_pin.network_id,
            genesis_digest: provider_pin.genesis_digest,
            receipt_key_id: [0xE6; 32],
            receipt_public_key: anchor_public,
        };

        let tip = prepared.staged_graph.canonical_tip();
        let successor = QRunV06ExternalAnchorState {
            network_id: predecessor.network_id,
            genesis_digest: predecessor.genesis_digest,
            genesis_descriptor_commitment: predecessor.genesis_descriptor_commitment,
            profile_id: predecessor.profile_id,
            consensus_fingerprint: store.consensus_fingerprint().unwrap(),
            segment_base_height: prepared.staged_graph.base_height(),
            segment_base_tip: prepared.staged_graph.base_tip(),
            checkpoint_anchor: store.checkpoint_anchor().unwrap().unwrap_or([0; 32]),
            manifest_generation: prepared.generation,
            manifest_anchor: prepared.manifest_anchor,
            canonical_height: tip.height,
            canonical_tip: tip.tip_hash,
            canonical_state_root: prepared
                .staged_graph
                .canonical_state()
                .state_root()
                .unwrap(),
            cumulative_chainwork: prepared
                .staged_graph
                .branch_work(&tip.tip_hash)
                .unwrap()
                .to_be_bytes(),
        };
        predecessor.validate_successor(&successor).unwrap();

        let bootstrap_record = ExternalCasRecord {
            generation: 0,
            provider_id: provider_pin.provider_id,
            network_id: provider_pin.network_id,
            genesis_digest: provider_pin.genesis_digest,
            previous_record_digest: [0; 32],
            previous_state_digest: [0; 32],
            next_state_digest: predecessor.digest().unwrap(),
            operation_id: [0xE7; 32],
            request_digest: [0xE8; 32],
        };
        let anchor_before = ExternalCasOffhostAnchorState::provision_bootstrap(
            &provider_pin,
            bootstrap_record.clone(),
            1,
        )
        .unwrap();
        let operation_id = [0xE9; 32];
        let mut provider_request = ExternalCasWriteRequest {
            request_nonce: [0xEA; 32],
            operation_id,
            request_digest: [1; 32],
            expected_generation: 0,
            expected_object_generation: 1,
            expected_record_digest: bootstrap_record.digest().unwrap(),
            expected_state_digest: predecessor.digest().unwrap(),
            next_record: ExternalCasRecord {
                generation: 1,
                provider_id: provider_pin.provider_id,
                network_id: provider_pin.network_id,
                genesis_digest: provider_pin.genesis_digest,
                previous_record_digest: bootstrap_record.digest().unwrap(),
                previous_state_digest: predecessor.digest().unwrap(),
                next_state_digest: successor.digest().unwrap(),
                operation_id,
                request_digest: [0; 32],
            },
        };
        provider_request.bind_request_digest(&provider_pin).unwrap();

        let mut journal = QRunV06Qap1Journal::new(
            predecessor.clone(),
            successor.clone(),
            anchor_before.clone(),
            provider_request,
            candidate_envelope.clone(),
            prepared.manifest_bytes.clone(),
            &provider_pin,
        )
        .unwrap();
        let qap1_dir = directory.0.join(QAP1_DIRECTORY);
        journal.persist_prepared(&qap1_dir, &provider_pin).unwrap();

        // Provider CAS is represented by a real test ML-DSA-65 ECS1 receipt.
        let provider_record = &journal.provider_request().next_record;
        let mut provider_receipt = ExternalCasReceipt {
            kind: ExternalCasReceiptKind::Commit,
            outcome: ExternalCasReceiptOutcome::Applied,
            generation: provider_record.generation,
            object_generation: 2,
            provider_id: provider_pin.provider_id,
            network_id: provider_pin.network_id,
            genesis_digest: provider_pin.genesis_digest,
            receipt_key_id: provider_pin.receipt_key_id,
            request_nonce: journal.provider_request().request_nonce,
            record_digest: provider_record.digest().unwrap(),
            previous_record_digest: provider_record.previous_record_digest,
            previous_state_digest: provider_record.previous_state_digest,
            state_digest: provider_record.next_state_digest,
            operation_id: journal.provider_request().operation_id,
            request_digest: journal.provider_request().request_digest,
            signature: [0; ML_DSA_65_SIGNATURE_BYTES],
        };
        let provider_signing_digest = provider_receipt.signing_digest().unwrap();
        let provider_signature = portable::sign(
            provider_key.as_ref(),
            &provider_signing_digest,
            &[],
            [0xEB; 32],
        )
        .unwrap();
        provider_receipt.signature = *provider_signature.as_ref();
        let provider_receipt_bytes = provider_receipt.encode().unwrap();

        let verifier = LibcruxMlDsa65VerifierCandidate;
        let provider_committed = journal
            .record_provider_receipt(&provider_receipt_bytes, &provider_pin, &verifier)
            .unwrap();
        provider_committed
            .persist_transition(
                &qap1_dir,
                &journal,
                &provider_pin,
                &anchor_pin,
                &verifier,
                &verifier,
            )
            .unwrap();

        // The Anchor accepts the exact Provider evidence, advances by one CAS and signs it.
        let anchor_successor = provider_committed.anchor_successor().unwrap();
        let anchor_cas_request = ExternalCasOffhostAnchorCasRequest {
            challenge: [0xEC; 32],
            operation_id: provider_committed.provider_request().operation_id,
            request_digest: provider_committed.provider_request().request_digest,
            expected_sequence: anchor_before.sequence,
            expected_state_digest: anchor_before.digest().unwrap(),
            target_state_digest: anchor_successor.digest().unwrap(),
        };
        let anchor_cas_prepared = provider_committed
            .prepare_anchor_cas(anchor_cas_request.clone(), &provider_pin)
            .unwrap();
        anchor_cas_prepared
            .persist_transition(
                &qap1_dir,
                &provider_committed,
                &provider_pin,
                &anchor_pin,
                &verifier,
                &verifier,
            )
            .unwrap();

        let anchor_model = ExternalCasOffhostAnchorMemoryModel::new(
            anchor_pin.clone(),
            provider_pin.clone(),
            anchor_before,
        )
        .unwrap();
        let anchor_signer = TestQ6eaAnchorSigner(anchor_key);
        let next_record_bytes = provider_committed
            .provider_request()
            .next_record
            .encode()
            .unwrap();
        let anchor_cas_receipt = anchor_model
            .compare_and_swap(
                &anchor_cas_request,
                &next_record_bytes,
                &provider_receipt_bytes,
                &verifier,
                &anchor_signer,
            )
            .unwrap();
        let anchor_committed = anchor_cas_prepared
            .record_anchor_receipt(
                &anchor_cas_receipt.encode().unwrap(),
                &anchor_pin,
                &provider_pin,
                &verifier,
            )
            .unwrap();
        anchor_committed
            .persist_transition(
                &qap1_dir,
                &anchor_cas_prepared,
                &provider_pin,
                &anchor_pin,
                &verifier,
                &verifier,
            )
            .unwrap();

        let read_request = ExternalCasOffhostAnchorReadRequest {
            challenge: [0xED; 32],
            operation_id: [0xEE; 32],
            request_digest: [0xEF; 32],
        };
        let read_receipt = anchor_model.read(&read_request, &anchor_signer).unwrap();
        journal = anchor_committed
            .confirm_anchor_read(
                read_request,
                &read_receipt.encode().unwrap(),
                &anchor_pin,
                &provider_pin,
                &verifier,
            )
            .unwrap();
        assert_eq!(journal.phase(), QRunV06Qap1Phase::AnchorConfirmed);
        journal
            .persist_transition(
                &qap1_dir,
                &anchor_committed,
                &provider_pin,
                &anchor_pin,
                &verifier,
                &verifier,
            )
            .unwrap();

        // Simulate process restart after Q6EA committed but before local Manifest publication.
        drop(store);
        let mut recovered_store =
            QRunV06DurableForkStore::open_with_expected_genesis_descriptor_commitment(
                &directory.0,
                genesis,
                params.clone(),
                &auth,
                Some(predecessor.manifest_anchor),
                descriptor_commitment,
            )
            .unwrap();
        let recovered_journal = QRunV06Qap1Journal::load_latest(
            &qap1_dir,
            &provider_pin,
            &anchor_pin,
            &verifier,
            &verifier,
        )
        .unwrap()
        .unwrap();
        assert_eq!(recovered_journal.phase(), QRunV06Qap1Phase::AnchorConfirmed);
        assert_eq!(recovered_journal, journal);

        // Re-run deterministic consensus validation from the exact persisted candidate bytes.
        let recovered_prepared = recovered_store
            .prepare(recovered_journal.candidate_envelope(), &auth)
            .unwrap()
            .unwrap();
        assert_eq!(
            recovered_prepared.manifest_bytes(),
            recovered_journal.next_manifest_bytes()
        );
        assert_eq!(
            recovered_prepared.manifest_anchor(),
            recovered_journal.successor().manifest_anchor
        );

        let committed = recovered_store
            .publish_prepared_with_qap1(
                recovered_prepared,
                &recovered_journal,
                &provider_pin,
                &anchor_pin,
                &verifier,
                &verifier,
            )
            .unwrap();
        assert_eq!(committed.generation, 1);
        assert_eq!(recovered_store.canonical_height().unwrap(), 1);
        recovered_store
            .verify_published_successor_with_qap1(
                &recovered_journal,
                &provider_pin,
                &anchor_pin,
                &verifier,
                &verifier,
            )
            .unwrap();

        let recovered_state =
            QRunV06ExternalAnchorState::from_store(&recovered_store, [0x75; 32]).unwrap();
        let local_manifest_committed = recovered_journal
            .mark_local_manifest_committed(&recovered_state, &provider_pin)
            .unwrap();
        local_manifest_committed
            .persist_transition(
                &qap1_dir,
                &recovered_journal,
                &provider_pin,
                &anchor_pin,
                &verifier,
                &verifier,
            )
            .unwrap();
        local_manifest_committed
            .finalize_and_clear(
                &qap1_dir,
                &recovered_state,
                &provider_pin,
                &anchor_pin,
                &verifier,
                &verifier,
            )
            .unwrap();

        let expected_anchor = recovered_store.manifest_anchor().unwrap();
        drop(recovered_store);
        let reopened = QRunV06DurableForkStore::open_with_expected_genesis_descriptor_commitment(
            &directory.0,
            genesis_state(),
            params,
            &auth,
            Some(expected_anchor),
            descriptor_commitment,
        )
        .unwrap();
        assert_eq!(reopened.canonical_height().unwrap(), 1);
        assert_eq!(reopened.manifest_anchor().unwrap(), expected_anchor);
    }

    #[test]
    fn production_store_bootstrap_requires_pinned_genesis_descriptor_for_genesis_and_checkpoint() {
        let params = params();
        let genesis = genesis_state();
        let descriptor_commitment = genesis.genesis_descriptor_commitment().unwrap();
        let auth = EmptyAuthenticator;

        let genesis_dir = TestDir::new();
        let store = QRunV06DurableForkStore::open_with_expected_genesis_descriptor_commitment(
            &genesis_dir.0,
            genesis.clone(),
            params.clone(),
            &auth,
            None,
            descriptor_commitment,
        )
        .unwrap();
        assert_eq!(
            store
                .graph()
                .unwrap()
                .canonical_state()
                .genesis_descriptor_commitment(),
            Some(descriptor_commitment)
        );
        drop(store);

        let wrong_pin_dir = TestDir::new();
        assert!(matches!(
            QRunV06DurableForkStore::open_with_expected_genesis_descriptor_commitment(
                &wrong_pin_dir.0,
                genesis.clone(),
                params.clone(),
                &auth,
                None,
                [0xFE; 32],
            ),
            Err(QRunV06ForkStoreError::Fork(
                QRunV06ForkChoiceError::GenesisDescriptorMismatch
            ))
        ));

        let graph = QRunV06PowForkChoice::new_with_expected_genesis_descriptor_commitment(
            genesis,
            params.clone(),
            descriptor_commitment,
        )
        .unwrap();
        let checkpoint = graph.canonical_checkpoint().unwrap();
        let checkpoint_bytes = checkpoint.encode_snapshot().unwrap();
        let checkpoint_anchor = checkpoint.commitment().unwrap();

        let resumed_dir = TestDir::new();
        let resumed = QRunV06DurableForkStore::open_from_checkpoint_with_expected_genesis_descriptor_commitment(
            &resumed_dir.0,
            &checkpoint_bytes,
            params.clone(),
            NETWORK,
            PROFILE,
            checkpoint_anchor,
            descriptor_commitment,
            &auth,
            None,
        )
        .unwrap();
        assert_eq!(
            resumed
                .graph()
                .unwrap()
                .canonical_state()
                .genesis_descriptor_commitment(),
            Some(descriptor_commitment)
        );

        let wrong_checkpoint_dir = TestDir::new();
        assert!(matches!(
            QRunV06DurableForkStore::open_from_checkpoint_with_expected_genesis_descriptor_commitment(
                &wrong_checkpoint_dir.0,
                &checkpoint_bytes,
                params,
                NETWORK,
                PROFILE,
                checkpoint_anchor,
                [0xFD; 32],
                &auth,
                None,
            ),
            Err(QRunV06ForkStoreError::Fork(
                QRunV06ForkChoiceError::GenesisDescriptorMismatch
            ))
        ));
    }

    #[test]
    fn durable_store_submit_and_reopen_require_height_bound_quote_authorization() {
        let dir = TestDir::new();
        let params = params();
        let mut genesis = genesis_state();
        let quote_asset = [0x91; 32];
        let q6qa_commitment = [0x92; 32];
        let q6pn_commitment = [0x93; 32];
        genesis.install_test_quote_asset_authorization(
            quote_asset,
            q6qa_commitment,
            q6pn_commitment,
            5,
            1,
            50,
            3,
        );
        let descriptor_commitment = genesis.genesis_descriptor_commitment().unwrap();
        let mut store = QRunV06DurableForkStore::open_with_expected_genesis_descriptor_commitment(
            &dir.0,
            genesis.clone(),
            params.clone(),
            &EmptyAuthenticator,
            None,
            descriptor_commitment,
        )
        .unwrap();
        let parent_tip = store.graph().unwrap().base_tip();
        let target = store
            .graph()
            .unwrap()
            .expected_next_target(&parent_tip)
            .unwrap();
        let auth_at_one =
            crate::qrun_v06_profile_trust_candidate::test_trust_authorized_quote_asset_candidate(
                NETWORK,
                PROFILE,
                quote_asset,
                q6qa_commitment,
                q6pn_commitment,
                5,
                1,
                50,
                3,
                1,
            );
        let block1 = candidate_with_quote_authorization(
            &genesis,
            parent_tip,
            100,
            target,
            &params,
            &auth_at_one,
        );

        assert!(matches!(
            store.submit(&block1, &EmptyAuthenticator),
            Err(QRunV06ForkStoreError::Fork(
                QRunV06ForkChoiceError::Execution(
                    QRunV06ExecutionError::MissingQuoteAssetAuthorization
                )
            ))
        ));
        assert_eq!(store.archive_len().unwrap(), 0);
        assert_eq!(store.generation().unwrap(), 0);

        let mut stale_provider = |_: &QRunV06CanonicalExecutionState,
                                  block: &QRunV06Block,
                                  asset_id: [u8; 32]| {
            assert_eq!(asset_id, quote_asset);
            Ok(crate::qrun_v06_profile_trust_candidate::test_trust_authorized_quote_asset_candidate(
                NETWORK,
                PROFILE,
                asset_id,
                q6qa_commitment,
                q6pn_commitment,
                5,
                1,
                50,
                3,
                block.height.saturating_sub(1),
            ))
        };
        assert!(matches!(
            store.submit_with_quote_asset_authorization(
                &block1,
                &EmptyAuthenticator,
                &mut stale_provider,
            ),
            Err(QRunV06ForkStoreError::Fork(
                QRunV06ForkChoiceError::Execution(
                    QRunV06ExecutionError::QuoteAssetAuthorizationMismatch
                )
            ))
        ));
        assert_eq!(store.archive_len().unwrap(), 0);
        assert_eq!(store.generation().unwrap(), 0);

        let accepted_heights = std::cell::RefCell::new(Vec::new());
        let mut provider = |_state: &QRunV06CanonicalExecutionState,
                            block: &QRunV06Block,
                            asset_id: [u8; 32]| {
            assert_eq!(asset_id, quote_asset);
            accepted_heights.borrow_mut().push(block.height);
            Ok(crate::qrun_v06_profile_trust_candidate::test_trust_authorized_quote_asset_candidate(
                NETWORK,
                PROFILE,
                asset_id,
                q6qa_commitment,
                q6pn_commitment,
                5,
                1,
                50,
                3,
                block.height,
            ))
        };
        let committed = store
            .submit_with_quote_asset_authorization(&block1, &EmptyAuthenticator, &mut provider)
            .unwrap();
        assert_eq!(committed.generation, 1);
        assert_eq!(accepted_heights.borrow().as_slice(), &[1]);
        let expected_root = store.canonical_state_root().unwrap();
        let trusted_anchor = store.manifest_anchor().unwrap();
        drop(store);

        // The legacy reopen path cannot replay an external-quote branch without a provider.
        assert!(matches!(
            QRunV06DurableForkStore::open(
                &dir.0,
                genesis.clone(),
                params.clone(),
                &EmptyAuthenticator,
                Some(trusted_anchor),
            ),
            Err(QRunV06ForkStoreError::Fork(
                QRunV06ForkChoiceError::Execution(
                    QRunV06ExecutionError::MissingQuoteAssetAuthorization
                )
            ))
        ));

        // Provider-aware reopen replays every external-quote block through the same
        // exact-height authorization callback before reconstructing the durable graph.
        let replayed_heights = std::cell::RefCell::new(Vec::new());
        let mut replay_provider = |_state: &QRunV06CanonicalExecutionState,
                                   block: &QRunV06Block,
                                   asset_id: [u8; 32]| {
            assert_eq!(asset_id, quote_asset);
            replayed_heights.borrow_mut().push(block.height);
            Ok(crate::qrun_v06_profile_trust_candidate::test_trust_authorized_quote_asset_candidate(
                NETWORK,
                PROFILE,
                asset_id,
                q6qa_commitment,
                q6pn_commitment,
                5,
                1,
                50,
                3,
                block.height,
            ))
        };
        let reopened = QRunV06DurableForkStore::open_inner(
            &dir.0,
            genesis,
            params,
            &EmptyAuthenticator,
            Some(trusted_anchor),
            Some(&mut replay_provider),
        )
        .unwrap();
        assert_eq!(replayed_heights.borrow().as_slice(), &[1]);
        assert_eq!(reopened.canonical_height().unwrap(), 1);
        assert_eq!(reopened.canonical_state_root().unwrap(), expected_root);
        assert_eq!(reopened.manifest_anchor().unwrap(), trusted_anchor);
    }

    #[test]
    fn durable_store_persists_all_branches_and_replays_exact_canonical_state() {
        let dir = TestDir::new();
        let genesis = genesis_state();
        let params = params();
        let mut store = QRunV06DurableForkStore::open(
            &dir.0,
            genesis.clone(),
            params.clone(),
            &EmptyAuthenticator,
            None,
        )
        .unwrap();
        let base = store.graph().unwrap().base_tip();
        let initial_anchor = store.manifest_anchor().unwrap();
        assert_eq!(store.generation().unwrap(), 0);

        let target = store.graph().unwrap().expected_next_target(&base).unwrap();
        let (first, first_tip) = candidate(&genesis, base, 100, target, &params);
        let first_commit = store.submit(&first, &EmptyAuthenticator).unwrap();
        assert_eq!(first_commit.generation, 1);
        assert_ne!(first_commit.manifest_anchor, initial_anchor);

        let graph = store.graph().unwrap();
        let first_state = graph.state_for_tip(&first_tip).unwrap().clone();
        let child_target = graph.expected_next_target(&first_tip).unwrap();
        let (child_a, tip_a) = candidate(&first_state, first_tip, 120, child_target, &params);
        let (child_b, tip_b) = candidate(&first_state, first_tip, 130, child_target, &params);
        store.submit(&child_a, &EmptyAuthenticator).unwrap();
        let final_commit = store.submit(&child_b, &EmptyAuthenticator).unwrap();
        assert_eq!(final_commit.generation, 3);
        assert_eq!(store.archive_len().unwrap(), 3);
        let expected_tip = store.canonical_tip().unwrap();
        let expected_root = store.canonical_state_root().unwrap();
        assert!(expected_tip == tip_a || expected_tip == tip_b);
        let trusted_anchor = store.manifest_anchor().unwrap();
        drop(store);

        let reopened = QRunV06DurableForkStore::open(
            &dir.0,
            genesis,
            params,
            &EmptyAuthenticator,
            Some(trusted_anchor),
        )
        .unwrap();
        assert_eq!(reopened.generation().unwrap(), 3);
        assert_eq!(reopened.archive_len().unwrap(), 3);
        assert_eq!(reopened.canonical_tip().unwrap(), expected_tip);
        assert_eq!(reopened.canonical_state_root().unwrap(), expected_root);
        assert_eq!(reopened.manifest_anchor().unwrap(), trusted_anchor);
    }

    #[test]
    fn existing_store_requires_exact_external_anchor_and_rejects_stale_anchor() {
        let dir = TestDir::new();
        let genesis = genesis_state();
        let params = params();
        let store = QRunV06DurableForkStore::open(
            &dir.0,
            genesis.clone(),
            params.clone(),
            &EmptyAuthenticator,
            None,
        )
        .unwrap();
        let anchor = store.manifest_anchor().unwrap();
        drop(store);

        assert!(matches!(
            QRunV06DurableForkStore::open(
                &dir.0,
                genesis.clone(),
                params.clone(),
                &EmptyAuthenticator,
                None,
            ),
            Err(QRunV06ForkStoreError::MissingTrustedManifestAnchor)
        ));
        assert!(matches!(
            QRunV06DurableForkStore::open(
                &dir.0,
                genesis.clone(),
                params.clone(),
                &EmptyAuthenticator,
                Some([0xFF; 32]),
            ),
            Err(QRunV06ForkStoreError::ManifestAnchorMismatch)
        ));
        let reopened = QRunV06DurableForkStore::open(
            &dir.0,
            genesis,
            params,
            &EmptyAuthenticator,
            Some(anchor),
        )
        .unwrap();
        assert_eq!(reopened.generation().unwrap(), 0);
    }

    #[test]
    fn unreferenced_branch_from_interrupted_pre_manifest_commit_is_discarded() {
        let dir = TestDir::new();
        let genesis = genesis_state();
        let params = params();
        let store = QRunV06DurableForkStore::open(
            &dir.0,
            genesis.clone(),
            params.clone(),
            &EmptyAuthenticator,
            None,
        )
        .unwrap();
        let old_anchor = store.manifest_anchor().unwrap();
        let base = store.graph().unwrap().base_tip();
        let target = store.graph().unwrap().expected_next_target(&base).unwrap();
        let (orphan, digest) = candidate(&genesis, base, 100, target, &params);
        let branch_path = dir.0.join(BRANCH_DIR).join(branch_filename(&digest));
        write_new_atomic(&branch_path, &orphan).unwrap();
        drop(store);

        let reopened = QRunV06DurableForkStore::open(
            &dir.0,
            genesis,
            params,
            &EmptyAuthenticator,
            Some(old_anchor),
        )
        .unwrap();
        assert_eq!(reopened.archive_len().unwrap(), 0);
        assert!(!branch_path.exists());
    }

    #[test]
    fn manifest_checksum_is_checked_before_state_is_exposed() {
        let dir = TestDir::new();
        let genesis = genesis_state();
        let params = params();
        let mut store = QRunV06DurableForkStore::open(
            &dir.0,
            genesis.clone(),
            params.clone(),
            &EmptyAuthenticator,
            None,
        )
        .unwrap();
        let base = store.graph().unwrap().base_tip();
        let target = store.graph().unwrap().expected_next_target(&base).unwrap();
        let (block, _) = candidate(&genesis, base, 100, target, &params);
        let commit = store.submit(&block, &EmptyAuthenticator).unwrap();
        drop(store);

        let manifest_path = dir
            .0
            .join(MANIFEST_DIR)
            .join(manifest_filename(commit.generation));
        let mut manifest_bytes = fs::read(&manifest_path).unwrap();
        let last = manifest_bytes.len() - 1;
        manifest_bytes[last] ^= 1;
        fs::write(&manifest_path, manifest_bytes).unwrap();
        assert!(matches!(
            QRunV06DurableForkStore::open(
                &dir.0,
                genesis.clone(),
                params.clone(),
                &EmptyAuthenticator,
                Some(commit.manifest_anchor),
            ),
            Err(QRunV06ForkStoreError::ManifestAnchorMismatch)
                | Err(QRunV06ForkStoreError::ManifestChecksumMismatch)
        ));
    }

    #[test]
    fn truncated_branch_and_manifest_files_are_rejected_before_state_exposure() {
        let branch_dir = TestDir::new();
        let genesis = genesis_state();
        let params = params();
        let mut branch_store = QRunV06DurableForkStore::open(
            &branch_dir.0,
            genesis.clone(),
            params.clone(),
            &EmptyAuthenticator,
            None,
        )
        .unwrap();
        let base = branch_store.graph().unwrap().base_tip();
        let target = branch_store
            .graph()
            .unwrap()
            .expected_next_target(&base)
            .unwrap();
        let (block, _) = candidate(&genesis, base, 100, target, &params);
        let branch_commit = branch_store.submit(&block, &EmptyAuthenticator).unwrap();
        drop(branch_store);

        let branch_path = fs::read_dir(branch_dir.0.join(BRANCH_DIR))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let truncated_branch = OpenOptions::new().write(true).open(&branch_path).unwrap();
        truncated_branch.set_len(7).unwrap();
        truncated_branch.sync_all().unwrap();
        assert!(matches!(
            QRunV06DurableForkStore::open(
                &branch_dir.0,
                genesis.clone(),
                params.clone(),
                &EmptyAuthenticator,
                Some(branch_commit.manifest_anchor),
            ),
            Err(QRunV06ForkStoreError::BranchDigestMismatch)
        ));

        let manifest_dir = TestDir::new();
        let mut manifest_store = QRunV06DurableForkStore::open(
            &manifest_dir.0,
            genesis.clone(),
            params.clone(),
            &EmptyAuthenticator,
            None,
        )
        .unwrap();
        let base = manifest_store.graph().unwrap().base_tip();
        let target = manifest_store
            .graph()
            .unwrap()
            .expected_next_target(&base)
            .unwrap();
        let (block, _) = candidate(&genesis, base, 100, target, &params);
        let manifest_commit = manifest_store.submit(&block, &EmptyAuthenticator).unwrap();
        drop(manifest_store);

        let manifest_path = manifest_dir
            .0
            .join(MANIFEST_DIR)
            .join(manifest_filename(manifest_commit.generation));
        let truncated_manifest = OpenOptions::new().write(true).open(&manifest_path).unwrap();
        truncated_manifest
            .set_len((MANIFEST_FIXED_PREFIX_BYTES - 1) as u64)
            .unwrap();
        truncated_manifest.sync_all().unwrap();
        assert!(matches!(
            QRunV06DurableForkStore::open(
                &manifest_dir.0,
                genesis,
                params,
                &EmptyAuthenticator,
                Some(manifest_commit.manifest_anchor),
            ),
            Err(QRunV06ForkStoreError::ManifestMalformed)
        ));
    }

    #[test]
    fn branch_bytes_are_checked_before_state_is_exposed() {
        let dir = TestDir::new();
        let genesis = genesis_state();
        let params = params();
        let mut store = QRunV06DurableForkStore::open(
            &dir.0,
            genesis.clone(),
            params.clone(),
            &EmptyAuthenticator,
            None,
        )
        .unwrap();
        let base = store.graph().unwrap().base_tip();
        let target = store.graph().unwrap().expected_next_target(&base).unwrap();
        let (block, _) = candidate(&genesis, base, 100, target, &params);
        let commit = store.submit(&block, &EmptyAuthenticator).unwrap();
        drop(store);

        let branch_path = fs::read_dir(dir.0.join(BRANCH_DIR))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let mut branch_bytes = fs::read(&branch_path).unwrap();
        branch_bytes[0] ^= 1;
        fs::write(&branch_path, branch_bytes).unwrap();

        assert!(matches!(
            QRunV06DurableForkStore::open(
                &dir.0,
                genesis,
                params,
                &EmptyAuthenticator,
                Some(commit.manifest_anchor),
            ),
            Err(QRunV06ForkStoreError::BranchDigestMismatch)
        ));
    }

    #[test]
    fn interruption_before_manifest_publication_keeps_old_anchor_and_discards_orphan() {
        let dir = TestDir::new();
        let genesis = genesis_state();
        let params = params();
        let mut store = QRunV06DurableForkStore::open(
            &dir.0,
            genesis.clone(),
            params.clone(),
            &EmptyAuthenticator,
            None,
        )
        .unwrap();
        let old_anchor = store.manifest_anchor().unwrap();
        let base = store.graph().unwrap().base_tip();
        let target = store.graph().unwrap().expected_next_target(&base).unwrap();
        let (block, digest) = candidate(&genesis, base, 100, target, &params);

        assert_eq!(
            store.submit_with_hook(&block, &EmptyAuthenticator, |stage| {
                if stage == CommitStage::BranchFilesSynced {
                    Err(QRunV06ForkStoreError::InjectedFailure)
                } else {
                    Ok(())
                }
            }),
            Err(QRunV06ForkStoreError::InjectedFailure)
        );
        assert_eq!(store.canonical_height().unwrap(), 0);
        assert_eq!(store.manifest_anchor().unwrap(), old_anchor);
        let orphan_path = dir.0.join(BRANCH_DIR).join(branch_filename(&digest));
        assert!(orphan_path.exists());
        drop(store);

        let reopened = QRunV06DurableForkStore::open(
            &dir.0,
            genesis,
            params,
            &EmptyAuthenticator,
            Some(old_anchor),
        )
        .unwrap();
        assert_eq!(reopened.archive_len().unwrap(), 0);
        assert!(!orphan_path.exists());
    }

    #[test]
    fn interruption_after_manifest_publication_returns_replay_verified_recovery_anchor() {
        let dir = TestDir::new();
        let genesis = genesis_state();
        let params = params();
        let mut store = QRunV06DurableForkStore::open(
            &dir.0,
            genesis.clone(),
            params.clone(),
            &EmptyAuthenticator,
            None,
        )
        .unwrap();
        let base = store.graph().unwrap().base_tip();
        let target = store.graph().unwrap().expected_next_target(&base).unwrap();
        let (block, _) = candidate(&genesis, base, 100, target, &params);

        assert_eq!(
            store.submit_with_hook(&block, &EmptyAuthenticator, |stage| {
                if stage == CommitStage::ManifestFileSynced {
                    Err(QRunV06ForkStoreError::InjectedFailure)
                } else {
                    Ok(())
                }
            }),
            Err(QRunV06ForkStoreError::InjectedFailure)
        );
        assert_eq!(
            store.canonical_height(),
            Err(QRunV06ForkStoreError::RecoveryRequired)
        );

        let hint = store.recovery_hint(&EmptyAuthenticator).unwrap();
        assert_eq!(hint.generation, 1);
        assert!(hint.manifest_committed);
        drop(store);

        // This simulates the operator/CAS persisting the returned anchor outside the store.
        let recovered = QRunV06DurableForkStore::open(
            &dir.0,
            genesis,
            params,
            &EmptyAuthenticator,
            Some(hint.manifest_anchor),
        )
        .unwrap();
        assert_eq!(recovered.generation().unwrap(), hint.generation);
        assert_eq!(recovered.canonical_height().unwrap(), 1);
        assert_eq!(recovered.archive_len().unwrap(), 1);
        assert_eq!(recovered.manifest_anchor().unwrap(), hint.manifest_anchor);
    }

    #[test]
    fn hard_process_crash_at_durable_commit_boundaries_is_reconciled_or_fails_closed() {
        const TEST_NAME: &str =
            "qrun_v06_pow_fork_store_candidate::tests::hard_process_crash_at_durable_commit_boundaries_is_reconciled_or_fails_closed";

        // The same test binary is relaunched as a child. abort() bypasses Rust destructors,
        // unlike the in-process InjectedFailure hooks used by the neighbouring tests.
        if let Ok(mode) = env::var("QRUN_M2M_CRASH_CHILD_MODE") {
            let store_dir = PathBuf::from(env::var("QRUN_M2M_CRASH_STORE_DIR").unwrap());
            let trust_anchor_path = PathBuf::from(env::var("QRUN_M2M_CRASH_TRUST_PATH").unwrap());
            let anchor_bytes = fs::read(&trust_anchor_path).unwrap();
            assert_eq!(anchor_bytes.len(), 32);
            let mut trusted_anchor = [0u8; 32];
            trusted_anchor.copy_from_slice(&anchor_bytes);

            let genesis = genesis_state();
            let params = params();
            let mut store = QRunV06DurableForkStore::open(
                &store_dir,
                genesis.clone(),
                params.clone(),
                &EmptyAuthenticator,
                Some(trusted_anchor),
            )
            .unwrap();
            let parent = store.graph().unwrap().base_tip();
            let target = store
                .graph()
                .unwrap()
                .expected_next_target(&parent)
                .unwrap();
            let (block, _) = candidate(&genesis, parent, 100, target, &params);

            let crash_stage = match mode.as_str() {
                "branch_temp_created" => CommitStage::BranchTempFileCreated,
                "branch_temp_synced" => CommitStage::BranchTempFileSynced,
                "branch_file_installed" => CommitStage::BranchFileInstalled,
                "branch_files_synced" => CommitStage::BranchFilesSynced,
                "manifest_temp_created" => CommitStage::ManifestTempFileCreated,
                "manifest_temp_synced" => CommitStage::ManifestTempFileSynced,
                "manifest_file_installed" => CommitStage::ManifestFileInstalled,
                "manifest_published_without_external_anchor"
                | "manifest_published_with_external_anchor" => CommitStage::ManifestFileSynced,
                _ => panic!("unknown crash mode: {mode}"),
            };
            let submit_result = store.submit_with_hook(&block, &EmptyAuthenticator, |stage| {
                if stage == crash_stage {
                    if mode == "manifest_published_with_external_anchor" {
                        // Test-only external trust-domain surrogate: the anchor file is
                        // deliberately outside the durable store directory and is synced
                        // before the child dies. This is not a production CAS provider.
                        let manifest_path = store_dir.join(MANIFEST_DIR).join(manifest_filename(1));
                        let manifest_bytes = fs::read(manifest_path).unwrap();
                        let next_anchor = manifest_commitment(&manifest_bytes);
                        let mut trust_file = OpenOptions::new()
                            .write(true)
                            .truncate(true)
                            .open(&trust_anchor_path)
                            .unwrap();
                        trust_file.write_all(&next_anchor).unwrap();
                        trust_file.sync_all().unwrap();
                    }
                    std::process::abort();
                }
                Ok(())
            });
            panic!("crash child unexpectedly returned from submit: {submit_result:?}");
        }

        for mode in [
            "branch_temp_created",
            "branch_temp_synced",
            "branch_file_installed",
            "branch_files_synced",
            "manifest_temp_created",
            "manifest_temp_synced",
            "manifest_file_installed",
            "manifest_published_without_external_anchor",
            "manifest_published_with_external_anchor",
        ] {
            let store_dir = TestDir::new();
            let trust_dir = TestDir::new();
            let trust_anchor_path = trust_dir.0.join("trusted-manifest-anchor.bin");
            let genesis = genesis_state();
            let params = params();
            let initial_store = QRunV06DurableForkStore::open(
                &store_dir.0,
                genesis.clone(),
                params.clone(),
                &EmptyAuthenticator,
                None,
            )
            .unwrap();
            let initial_anchor = initial_store.manifest_anchor().unwrap();
            drop(initial_store);
            fs::write(&trust_anchor_path, initial_anchor).unwrap();

            let child = Command::new(env::current_exe().unwrap())
                .arg("--exact")
                .arg(TEST_NAME)
                .arg("--nocapture")
                .env("QRUN_M2M_CRASH_CHILD_MODE", mode)
                .env("QRUN_M2M_CRASH_STORE_DIR", &store_dir.0)
                .env("QRUN_M2M_CRASH_TRUST_PATH", &trust_anchor_path)
                .output()
                .unwrap();
            assert!(
                !child.status.success(),
                "crash child must terminate abnormally for mode {mode}; stdout={} stderr={}",
                String::from_utf8_lossy(&child.stdout),
                String::from_utf8_lossy(&child.stderr)
            );

            match mode {
                "manifest_file_installed" | "manifest_published_without_external_anchor" => {
                    // A process death after local manifest publication but before the
                    // independent anchor update must not silently trust the local manifest.
                    assert_eq!(fs::read(&trust_anchor_path).unwrap(), initial_anchor);
                    assert!(matches!(
                        QRunV06DurableForkStore::open(
                            &store_dir.0,
                            genesis,
                            params,
                            &EmptyAuthenticator,
                            Some(initial_anchor),
                        ),
                        Err(QRunV06ForkStoreError::ManifestAnchorMismatch)
                    ));
                }
                "manifest_published_with_external_anchor" => {
                    // If the independent trust domain durably records the new anchor first,
                    // an abrupt process death can be followed by a fully replayed reopen.
                    let anchor_bytes = fs::read(&trust_anchor_path).unwrap();
                    assert_eq!(anchor_bytes.len(), 32);
                    let mut trusted_anchor = [0u8; 32];
                    trusted_anchor.copy_from_slice(&anchor_bytes);
                    assert_ne!(trusted_anchor, initial_anchor);
                    let reopened = QRunV06DurableForkStore::open(
                        &store_dir.0,
                        genesis,
                        params,
                        &EmptyAuthenticator,
                        Some(trusted_anchor),
                    )
                    .unwrap();
                    assert_eq!(reopened.generation().unwrap(), 1);
                    assert_eq!(reopened.canonical_height().unwrap(), 1);
                    assert_eq!(reopened.archive_len().unwrap(), 1);
                    assert_eq!(reopened.manifest_anchor().unwrap(), trusted_anchor);
                }
                _ => {
                    // A crash before Manifest installation leaves either no branch file,
                    // an orphan branch file, or an incomplete temp file. Restart must
                    // clean all unreferenced artifacts and retain the previous generation.
                    let reopened = QRunV06DurableForkStore::open(
                        &store_dir.0,
                        genesis,
                        params,
                        &EmptyAuthenticator,
                        Some(initial_anchor),
                    )
                    .unwrap();
                    assert_eq!(reopened.generation().unwrap(), 0);
                    assert_eq!(reopened.archive_len().unwrap(), 0);
                    assert_eq!(
                        fs::read_dir(store_dir.0.join(BRANCH_DIR)).unwrap().count(),
                        0
                    );
                    for directory in [store_dir.0.join(BRANCH_DIR), store_dir.0.join(MANIFEST_DIR)]
                    {
                        assert!(fs::read_dir(directory).unwrap().all(|entry| {
                            let name = entry.unwrap().file_name();
                            let name = name.to_string_lossy();
                            !(name.starts_with(TEMP_PREFIX) && name.ends_with(TEMP_SUFFIX))
                        }));
                    }
                }
            }
        }
    }

    #[test]
    fn cp0528_monetary_state_survives_durable_checkpoint_rollover_and_restart() {
        let genesis_dir = TestDir::new();
        let segment_one = TestDir::new();
        let genesis = cp0528_genesis_state();
        let consensus = params();
        assert_eq!(
            genesis.unified().ledger().total_value().unwrap(),
            QRUN_V06_FOUNDER_GENESIS_ATOMS
        );

        let mut first_store = QRunV06DurableForkStore::open(
            &genesis_dir.0,
            genesis.clone(),
            consensus.clone(),
            &EmptyAuthenticator,
            None,
        )
        .unwrap();
        let base = first_store.graph().unwrap().base_tip();
        let target1 = first_store
            .graph()
            .unwrap()
            .expected_next_target(&base)
            .unwrap();
        let (block1, tip1) = candidate(&genesis, base, 100, target1, &consensus);
        first_store.submit(&block1, &EmptyAuthenticator).unwrap();
        assert_eq!(first_store.canonical_tip().unwrap(), tip1);
        let state1 = first_store.graph().unwrap().canonical_state();
        assert_eq!(
            state1
                .tokenomics()
                .unwrap()
                .issued_by_bucket_atoms(QRunV06AllocationBucket::MiningNetworkSecurity),
            35_673_515_981
        );
        assert_eq!(
            state1.unified().ledger().total_value().unwrap(),
            QRUN_V06_FOUNDER_GENESIS_ATOMS + 35_673_515_981
        );
        let (checkpoint_bytes, checkpoint_anchor) =
            first_store.export_canonical_checkpoint().unwrap();
        drop(first_store);

        let mut resumed = QRunV06DurableForkStore::open_from_checkpoint(
            &segment_one.0,
            &checkpoint_bytes,
            consensus.clone(),
            NETWORK,
            PROFILE,
            checkpoint_anchor,
            &EmptyAuthenticator,
            None,
        )
        .unwrap();
        assert_eq!(
            resumed.checkpoint_anchor().unwrap(),
            Some(checkpoint_anchor)
        );
        assert_eq!(resumed.canonical_height().unwrap(), 1);
        let restored = resumed.graph().unwrap().canonical_state();
        assert_eq!(
            restored
                .tokenomics()
                .unwrap()
                .issued_by_bucket_atoms(QRunV06AllocationBucket::MiningNetworkSecurity),
            35_673_515_981
        );
        assert_eq!(
            restored.unified().ledger().total_value().unwrap(),
            QRUN_V06_FOUNDER_GENESIS_ATOMS + 35_673_515_981
        );

        let target2 = resumed
            .graph()
            .unwrap()
            .expected_next_target(&tip1)
            .unwrap();
        let state1 = resumed.graph().unwrap().canonical_state().clone();
        let (block2, tip2) = candidate(&state1, tip1, 120, target2, &consensus);
        resumed.submit(&block2, &EmptyAuthenticator).unwrap();
        assert_eq!(resumed.canonical_tip().unwrap(), tip2);
        let state2 = resumed.graph().unwrap().canonical_state();
        assert_eq!(
            state2
                .tokenomics()
                .unwrap()
                .issued_by_bucket_atoms(QRunV06AllocationBucket::MiningNetworkSecurity),
            71_347_031_962
        );
        assert_eq!(
            state2.unified().ledger().total_value().unwrap(),
            QRUN_V06_FOUNDER_GENESIS_ATOMS + 71_347_031_962
        );
        let expected_root = resumed.canonical_state_root().unwrap();
        let manifest_anchor = resumed.manifest_anchor().unwrap();
        drop(resumed);

        let reopened = QRunV06DurableForkStore::open_from_checkpoint(
            &segment_one.0,
            &checkpoint_bytes,
            consensus,
            NETWORK,
            PROFILE,
            checkpoint_anchor,
            &EmptyAuthenticator,
            Some(manifest_anchor),
        )
        .unwrap();
        assert_eq!(reopened.canonical_tip().unwrap(), tip2);
        assert_eq!(reopened.canonical_state_root().unwrap(), expected_root);
        assert_eq!(
            reopened
                .graph()
                .unwrap()
                .canonical_state()
                .tokenomics()
                .unwrap()
                .issued_by_bucket_atoms(QRunV06AllocationBucket::MiningNetworkSecurity),
            71_347_031_962
        );
        assert_eq!(
            reopened
                .graph()
                .unwrap()
                .canonical_state()
                .unified()
                .ledger()
                .total_value()
                .unwrap(),
            QRUN_V06_FOUNDER_GENESIS_ATOMS + 71_347_031_962
        );
    }

    #[test]
    fn checkpoint_segment_persists_restarts_and_rolls_forward_across_retarget() {
        let old_dir = TestDir::new();
        let segment_one = TestDir::new();
        let segment_two = TestDir::new();
        let genesis = genesis_state();
        let params = params();

        // Segment one is Genesis-rooted and produces the first checkpoint.
        let mut first_store = QRunV06DurableForkStore::open(
            &old_dir.0,
            genesis.clone(),
            params.clone(),
            &EmptyAuthenticator,
            None,
        )
        .unwrap();
        let genesis_consensus_tip = first_store.graph().unwrap().base_tip();
        let first_target = first_store
            .graph()
            .unwrap()
            .expected_next_target(&genesis_consensus_tip)
            .unwrap();
        let (block1, tip1) = candidate(&genesis, genesis_consensus_tip, 100, first_target, &params);
        first_store.submit(&block1, &EmptyAuthenticator).unwrap();
        assert_eq!(first_store.canonical_height().unwrap(), 1);
        let (checkpoint1_bytes, checkpoint1_anchor) =
            first_store.export_canonical_checkpoint().unwrap();
        let old_segment_root = old_dir.0.clone();
        drop(first_store);
        assert!(old_segment_root.join(CHECKPOINT_FILE).exists() == false);

        // The checkpoint must fail closed for an incorrect external anchor or changed profile.
        assert!(matches!(
            QRunV06DurableForkStore::open_from_checkpoint(
                &segment_one.0,
                &checkpoint1_bytes,
                params.clone(),
                NETWORK,
                PROFILE,
                [0xFE; 32],
                &EmptyAuthenticator,
                None,
            ),
            Err(QRunV06ForkStoreError::Checkpoint(
                QRunV06CheckpointError::CheckpointAnchorMismatch
            ))
        ));
        let mut wrong_params = params.clone();
        wrong_params.target_block_time_secs += 1;
        assert!(matches!(
            QRunV06DurableForkStore::open_from_checkpoint(
                &segment_one.0,
                &checkpoint1_bytes,
                wrong_params,
                NETWORK,
                PROFILE,
                checkpoint1_anchor,
                &EmptyAuthenticator,
                None,
            ),
            Err(QRunV06ForkStoreError::Checkpoint(
                QRunV06CheckpointError::WrongConsensusParameters
            ))
        ));

        // Segment two starts from the independently anchored checkpoint at absolute height 1.
        let mut second_store = QRunV06DurableForkStore::open_from_checkpoint(
            &segment_one.0,
            &checkpoint1_bytes,
            params.clone(),
            NETWORK,
            PROFILE,
            checkpoint1_anchor,
            &EmptyAuthenticator,
            None,
        )
        .unwrap();
        assert_eq!(
            second_store.checkpoint_anchor().unwrap(),
            Some(checkpoint1_anchor)
        );
        assert_eq!(second_store.canonical_height().unwrap(), 1);
        assert_eq!(second_store.canonical_tip().unwrap(), tip1);
        assert_eq!(second_store.archive_len().unwrap(), 0);

        let target2 = second_store
            .graph()
            .unwrap()
            .expected_next_target(&tip1)
            .unwrap();
        let state1 = second_store.graph().unwrap().canonical_state().clone();
        let (block2, tip2) = candidate(&state1, tip1, 120, target2, &params);
        let commit2 = second_store.submit(&block2, &EmptyAuthenticator).unwrap();
        assert_eq!(second_store.canonical_height().unwrap(), 2);
        assert_eq!(second_store.canonical_tip().unwrap(), tip2);
        assert_eq!(commit2.generation, 1);
        let second_root = second_store.canonical_state_root().unwrap();
        let second_work = second_store.graph().unwrap().branch_work(&tip2).unwrap();
        let segment_two_manifest_anchor = second_store.manifest_anchor().unwrap();
        drop(second_store);

        // Restart the second segment from the same checkpoint plus its externally saved manifest.
        let reopened_second = QRunV06DurableForkStore::open_from_checkpoint(
            &segment_one.0,
            &checkpoint1_bytes,
            params.clone(),
            NETWORK,
            PROFILE,
            checkpoint1_anchor,
            &EmptyAuthenticator,
            Some(segment_two_manifest_anchor),
        )
        .unwrap();
        assert_eq!(reopened_second.generation().unwrap(), 1);
        assert_eq!(reopened_second.canonical_height().unwrap(), 2);
        assert_eq!(reopened_second.canonical_tip().unwrap(), tip2);
        assert_eq!(reopened_second.canonical_state_root().unwrap(), second_root);
        assert_eq!(
            reopened_second.graph().unwrap().branch_work(&tip2).unwrap(),
            second_work
        );
        let (checkpoint2_bytes, checkpoint2_anchor) =
            reopened_second.export_canonical_checkpoint().unwrap();
        assert_ne!(checkpoint2_anchor, checkpoint1_anchor);
        drop(reopened_second);

        // Segment three starts at height 2 and preserves the target history needed for height-3 retarget.
        let mut third_store = QRunV06DurableForkStore::open_from_checkpoint(
            &segment_two.0,
            &checkpoint2_bytes,
            params.clone(),
            NETWORK,
            PROFILE,
            checkpoint2_anchor,
            &EmptyAuthenticator,
            None,
        )
        .unwrap();
        assert_eq!(third_store.canonical_height().unwrap(), 2);
        let expected_target3 = third_store
            .graph()
            .unwrap()
            .expected_next_target(&tip2)
            .unwrap();
        let state2 = third_store.graph().unwrap().canonical_state().clone();
        let (block3, tip3) = candidate(&state2, tip2, 180, expected_target3, &params);
        third_store.submit(&block3, &EmptyAuthenticator).unwrap();
        assert_eq!(third_store.canonical_height().unwrap(), 3);
        assert_eq!(third_store.canonical_tip().unwrap(), tip3);
        assert!(third_store.graph().unwrap().branch_work(&tip3).unwrap() > second_work);
        assert!(old_segment_root
            .join(MANIFEST_DIR)
            .join(manifest_filename(1))
            .exists());
    }

    #[test]
    fn checkpoint_segment_ambiguous_commit_recovers_from_checkpoint_base() {
        let genesis_dir = TestDir::new();
        let segment_dir = TestDir::new();
        let genesis = genesis_state();
        let params = params();

        let mut genesis_store = QRunV06DurableForkStore::open(
            &genesis_dir.0,
            genesis.clone(),
            params.clone(),
            &EmptyAuthenticator,
            None,
        )
        .unwrap();
        let genesis_tip = genesis_store.graph().unwrap().base_tip();
        let target1 = genesis_store
            .graph()
            .unwrap()
            .expected_next_target(&genesis_tip)
            .unwrap();
        let (block1, tip1) = candidate(&genesis, genesis_tip, 100, target1, &params);
        genesis_store.submit(&block1, &EmptyAuthenticator).unwrap();
        let (checkpoint_bytes, checkpoint_anchor) =
            genesis_store.export_canonical_checkpoint().unwrap();
        drop(genesis_store);

        let mut store = QRunV06DurableForkStore::open_from_checkpoint(
            &segment_dir.0,
            &checkpoint_bytes,
            params.clone(),
            NETWORK,
            PROFILE,
            checkpoint_anchor,
            &EmptyAuthenticator,
            None,
        )
        .unwrap();
        let state1 = store.graph().unwrap().canonical_state().clone();
        let target2 = store.graph().unwrap().expected_next_target(&tip1).unwrap();
        let (block2, tip2) = candidate(&state1, tip1, 120, target2, &params);
        let commit2 = store.submit(&block2, &EmptyAuthenticator).unwrap();
        assert_eq!(commit2.generation, 1);

        let state2 = store.graph().unwrap().canonical_state().clone();
        let target3 = store.graph().unwrap().expected_next_target(&tip2).unwrap();
        let (block3, tip3) = candidate(&state2, tip2, 180, target3, &params);
        assert_eq!(
            store.submit_with_hook(&block3, &EmptyAuthenticator, |stage| {
                if stage == CommitStage::ManifestFileSynced {
                    Err(QRunV06ForkStoreError::InjectedFailure)
                } else {
                    Ok(())
                }
            }),
            Err(QRunV06ForkStoreError::InjectedFailure)
        );
        assert_eq!(
            store.canonical_height(),
            Err(QRunV06ForkStoreError::RecoveryRequired)
        );

        let hint = store.recovery_hint(&EmptyAuthenticator).unwrap();
        assert_eq!(hint.generation, 2);
        assert!(hint.manifest_committed);
        drop(store);

        let recovered = QRunV06DurableForkStore::open_from_checkpoint(
            &segment_dir.0,
            &checkpoint_bytes,
            params,
            NETWORK,
            PROFILE,
            checkpoint_anchor,
            &EmptyAuthenticator,
            Some(hint.manifest_anchor),
        )
        .unwrap();
        assert_eq!(recovered.generation().unwrap(), 2);
        assert_eq!(recovered.canonical_height().unwrap(), 3);
        assert_eq!(recovered.canonical_tip().unwrap(), tip3);
        assert_eq!(recovered.archive_len().unwrap(), 2);
        assert_eq!(recovered.manifest_anchor().unwrap(), hint.manifest_anchor);
    }

    #[test]
    fn concurrent_writer_is_rejected_by_os_lock() {
        let dir = TestDir::new();
        let genesis = genesis_state();
        let params = params();
        let first = QRunV06DurableForkStore::open(
            &dir.0,
            genesis.clone(),
            params.clone(),
            &EmptyAuthenticator,
            None,
        )
        .unwrap();
        assert!(matches!(
            QRunV06DurableForkStore::open(
                &dir.0,
                genesis,
                params,
                &EmptyAuthenticator,
                Some(first.manifest_anchor().unwrap()),
            ),
            Err(QRunV06ForkStoreError::WriterLockHeld)
        ));
        drop(first);
    }

    #[test]
    fn verified_q6pn_bootstrap_binds_genesis_and_checkpoint_store_paths() {
        let genesis = genesis_state();
        let params = params();
        let descriptor = *genesis.genesis_descriptor().unwrap();
        let profile_bundle =
            crate::qrun_v06_profile_pin_candidate::QRunV06ProfilePinCandidate::new(
                descriptor,
                crate::external_cas_anchor_candidate::ExternalCasPin {
                    provider_id: [0x91; 32],
                    network_id: NETWORK,
                    genesis_digest: [0x92; 32],
                    receipt_key_id: [0x93; 32],
                    receipt_public_key: [0x94;
                        crate::v4_fat1_trust_candidate::ML_DSA_65_PUBLIC_KEY_BYTES],
                },
            )
            .unwrap();
        let profile_bytes = profile_bundle.encode().unwrap();
        let independent_profile_commitment = profile_bundle.commitment().unwrap();
        let verified_profile_pin =
            crate::qrun_v06_profile_pin_candidate::QRunV06VerifiedProfilePin::decode(
                &profile_bytes,
                independent_profile_commitment,
            )
            .unwrap();

        // The Q6PN trust proof must also match the requested active consensus parameters.
        let mut wrong_params = params.clone();
        wrong_params.target_block_time_secs += 1;
        let wrong_dir = TestDir::new();
        assert!(matches!(
            QRunV06DurableForkStore::open_with_verified_profile_pin(
                &wrong_dir.0,
                genesis.clone(),
                wrong_params,
                &EmptyAuthenticator,
                None,
                &verified_profile_pin,
            ),
            Err(QRunV06ForkStoreError::ProfilePinConsensusMismatch)
        ));

        let genesis_dir = TestDir::new();
        let store = QRunV06DurableForkStore::open_with_verified_profile_pin(
            &genesis_dir.0,
            genesis,
            params.clone(),
            &EmptyAuthenticator,
            None,
            &verified_profile_pin,
        )
        .unwrap();
        assert_eq!(
            crate::qrun_v06_checkpoint_candidate::qrun_v06_consensus_fingerprint(&params).unwrap(),
            descriptor.consensus_fingerprint()
        );
        assert_ne!(store.consensus_fingerprint().unwrap(), [0; 32]);
        assert_eq!(store.canonical_height().unwrap(), 0);
        assert_eq!(
            verified_profile_pin
                .into_external_anchor_pin()
                .unwrap()
                .genesis_descriptor_commitment(),
            descriptor.commitment()
        );

        let (checkpoint_bytes, checkpoint_anchor) = store.export_canonical_checkpoint().unwrap();
        drop(store);
        let checkpoint_dir = TestDir::new();
        let resumed = QRunV06DurableForkStore::open_from_checkpoint_with_verified_profile_pin(
            &checkpoint_dir.0,
            &checkpoint_bytes,
            params,
            checkpoint_anchor,
            &verified_profile_pin,
            &EmptyAuthenticator,
            None,
        )
        .unwrap();
        assert_eq!(resumed.canonical_height().unwrap(), 0);
        assert_eq!(
            resumed.checkpoint_anchor().unwrap(),
            Some(checkpoint_anchor)
        );
    }

    #[test]
    fn q6ts_authorized_pin_is_required_by_stronger_genesis_and_checkpoint_store_apis() {
        let genesis = genesis_state();
        let params = params();
        let descriptor = *genesis.genesis_descriptor().unwrap();
        let bundle = QRunV06ProfilePinCandidate::new(
            descriptor,
            ExternalCasPin {
                provider_id: [0x91; 32],
                network_id: NETWORK,
                genesis_digest: [0x92; 32],
                receipt_key_id: [0x93; 32],
                receipt_public_key: [0x94; ML_DSA_65_PUBLIC_KEY_BYTES],
            },
        )
        .unwrap();
        let profile_bytes = bundle.encode().unwrap().to_vec();
        let profile_commitment = bundle.commitment().unwrap();

        let ed_signing_key = SigningKey::from_bytes(&[0xA8; 32]);
        let authority = PinnedQRunV06ProfileTrustAuthority {
            ed25519_public_key: ed_signing_key.verifying_key().to_bytes(),
            mldsa65_public_key: [0x98; ML_DSA_65_PUBLIC_KEY_BYTES],
        };
        let record = QRunV06ProfileTrustRecord {
            trust_epoch: 1,
            status: QRunV06ProfileTrustStatus::Active,
            network_id: NETWORK,
            profile_id: PROFILE,
            profile_pin_commitment: profile_commitment,
            previous_record_id: [0; 32],
        };
        let keyset_id = authority.keyset_id().unwrap();
        let signing_digest = record.signing_digest(&keyset_id).unwrap();
        let envelope = QRunV06SignedProfileTrustEnvelope {
            record,
            authority_keyset_id: keyset_id,
            ed25519_signature: ed_signing_key.sign(&signing_digest).to_bytes(),
            mldsa65_signature: [0x97; ML_DSA_65_SIGNATURE_BYTES],
        };
        let trust_bytes = envelope.encode().unwrap();
        let mut trust_floor = TestQ6pnTrustFloor {
            floor: TrustedQRunV06ProfileTrustFloor::initial(NETWORK, PROFILE).unwrap(),
        };
        prepublish_qrun_v06_profile_trust_floor(
            &trust_bytes,
            &authority,
            &TestPqVerifier,
            &mut trust_floor,
        )
        .unwrap();
        let authorized = authorize_qrun_v06_profile_pin(
            Some(&profile_bytes),
            &trust_bytes,
            &authority,
            &TestPqVerifier,
            &mut trust_floor,
            NETWORK,
            PROFILE,
        )
        .unwrap();
        assert_eq!(authorized.trust_epoch(), 1);

        let mut wrong_params = params.clone();
        wrong_params.target_block_time_secs += 1;
        let wrong_dir = TestDir::new();
        assert!(matches!(
            QRunV06DurableForkStore::open_with_trust_authorized_profile_pin(
                &wrong_dir.0,
                genesis.clone(),
                wrong_params,
                &EmptyAuthenticator,
                None,
                &authorized,
            ),
            Err(QRunV06ForkStoreError::ProfilePinConsensusMismatch)
        ));

        let genesis_dir = TestDir::new();
        let store = QRunV06DurableForkStore::open_with_trust_authorized_profile_pin(
            &genesis_dir.0,
            genesis,
            params.clone(),
            &EmptyAuthenticator,
            None,
            &authorized,
        )
        .unwrap();
        assert_eq!(store.canonical_height().unwrap(), 0);
        let (checkpoint_bytes, checkpoint_anchor) = store.export_canonical_checkpoint().unwrap();
        drop(store);

        let checkpoint_dir = TestDir::new();
        let resumed =
            QRunV06DurableForkStore::open_from_checkpoint_with_trust_authorized_profile_pin(
                &checkpoint_dir.0,
                &checkpoint_bytes,
                params,
                checkpoint_anchor,
                &authorized,
                &EmptyAuthenticator,
                None,
            )
            .unwrap();
        assert_eq!(resumed.canonical_height().unwrap(), 0);
        assert_eq!(
            resumed.checkpoint_anchor().unwrap(),
            Some(checkpoint_anchor)
        );
    }
}
