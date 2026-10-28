//! Candidate-only durable PTB2 branch store (not integrated with the public TCP listener).
//!
//! The PFS2 manifest is the commit record: a branch envelope is durably staged first, then an
//! atomically replaced manifest makes its digest visible to replay. A crash before manifest
//! publication leaves an orphan envelope that startup ignores/removes while holding the writer
//! lock. Startup validates the profile, manifest checksum, every referenced filename/digest,
//! each PTB2 envelope, and the complete ancestor graph before exposing the selected chain.

use crate::{
    chain_admission::ReferenceTimeProvider,
    consensus::{pow_digest, ConsensusError, ConsensusParameters, PowAlgorithm},
    external_cas_anchor_candidate::{
        ExternalCasClientError, ExternalCasPin, ExternalCasProviderTransport, ExternalCasRecord,
        ExternalCasWriteRequest, VerifiedExternalCasClient, EXTERNAL_CAS_RECORD_BYTES,
    },
    private_testnet_fork_choice::{
        ForkChoiceError, ForkChoiceOutcome, PrivateTestnetForkChoice, MAX_FORK_ARCHIVE_BLOCKS,
    },
    private_testnet_wire::{
        decode_candidate_network_block, PrivateTestnetWireError,
        MAX_CANDIDATE_NETWORK_ENVELOPE_BYTES,
    },
    state_machine::{LedgerState, StateError, TransactionAuthenticator},
    store_writer_lock::StoreWriterLock,
    v4_fat1_trust_candidate::MlDsa65Verifier,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process,
    sync::atomic::{AtomicU64, Ordering as AtomicOrdering},
};

const MANIFEST_MAGIC: &[u8; 4] = b"PFS2";
const MANIFEST_VERSION: u16 = 2;
const MANIFEST_FIXED_PREFIX: usize = 4 + 2 + 32 + 32 + 32 + 32 + 4;
const MANIFEST_CHECKSUM_BYTES: usize = 32;
const MAX_MANIFEST_BYTES: usize =
    MANIFEST_FIXED_PREFIX + MAX_FORK_ARCHIVE_BLOCKS * 32 + MANIFEST_CHECKSUM_BYTES;
const PROFILE_DOMAIN: &[u8] = b"AIN1-PTB2-STORE-PROFILE-V1\0";
const QRUN_V05_FEE_PROFILE_DOMAIN: &[u8] = b"QRUN-V05-FEE-ONLY-STORE-PROFILE-V1\0";
const QRUN_V05_FEE_CHECKPOINT_PROFILE_DOMAIN: &[u8] = b"QRUN-V05-FEE-CHECKPOINT-STORE-PROFILE-V1\0";
const MANIFEST_NAME: &str = "forkstore.manifest";
const QRUN_PENDING_NAME: &str = "qrun-v05-external-cas.pending";
const QRUN_PENDING_MAGIC: &[u8; 4] = b"QAP1";
const QRUN_PENDING_VERSION: u16 = 1;
const QRUN_PENDING_CHECKSUM_BYTES: usize = 32;
const QRUN_PENDING_DOMAIN: &[u8] = b"QRUN-V05-EXTERNAL-CAS-PENDING-V1\0";
const MAX_QRUN_PENDING_BYTES: usize =
    4 + 2 + EXTERNAL_CAS_RECORD_BYTES * 2 + 4 + MAX_MANIFEST_BYTES + QRUN_PENDING_CHECKSUM_BYTES;
const LOCK_NAME: &str = "forkstore.lock";
const BRANCH_PREFIX: &str = "branch-";
const BRANCH_SUFFIX: &str = ".ptb2";
const TEMP_MARKER: &str = ".tmp-";
static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
pub enum ForkStoreError {
    Io(io::Error),
    State(StateError),
    Fork(ForkChoiceError),
    Consensus(ConsensusError),
    LockHeld,
    ManifestMalformed,
    ManifestChecksumMismatch,
    ManifestAnchorMismatch,
    ManifestProfileMismatch,
    MissingReferencedBranch,
    BranchFilenameDigestMismatch,
    UnexpectedBranchFileName,
    UnexpectedStoreEntry,
    CanonicalTipMismatch,
    BranchFileTooLarge,
    ManifestTooLarge,
    DuplicateManifestDigest,
    ProfileEncodingInvalid,
    ExternalCasClient(ExternalCasClientError),
    ExternalCasContract(crate::external_cas_anchor_candidate::ExternalCasError),
    PendingAnchorMalformed,
    PendingRecoveryRequired,
    ExternalAnchorMismatch,
    RandomnessUnavailable,
}

impl std::fmt::Display for ForkStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "fork-store I/O error: {error}"),
            Self::State(error) => write!(f, "fork-store genesis state error: {error:?}"),
            Self::Fork(error) => write!(f, "fork-store branch validation error: {error}"),
            Self::Consensus(error) => write!(f, "fork-store consensus profile error: {error}"),
            Self::LockHeld => write!(f, "fork-store writer lock already exists"),
            Self::ManifestMalformed => write!(f, "fork-store manifest is malformed"),
            Self::ManifestChecksumMismatch => write!(f, "fork-store manifest checksum mismatch"),
            Self::ManifestAnchorMismatch => write!(
                f,
                "fork-store manifest does not match the independently supplied anchor"
            ),
            Self::ManifestProfileMismatch => write!(
                f,
                "fork-store profile differs from the requested network/genesis/consensus settings"
            ),
            Self::MissingReferencedBranch => write!(
                f,
                "fork-store manifest references a missing branch envelope"
            ),
            Self::BranchFilenameDigestMismatch => write!(
                f,
                "fork-store branch filename does not match the PoW digest"
            ),
            Self::UnexpectedBranchFileName => {
                write!(f, "fork-store PTB2 file has a non-canonical filename")
            }
            Self::UnexpectedStoreEntry => {
                write!(f, "fork-store contains an unexpected filesystem entry")
            }
            Self::CanonicalTipMismatch => write!(
                f,
                "fork-store manifest canonical tip differs from replayed fork choice"
            ),
            Self::BranchFileTooLarge => {
                write!(f, "fork-store branch envelope exceeds its byte limit")
            }
            Self::ManifestTooLarge => write!(f, "fork-store manifest exceeds its byte limit"),
            Self::DuplicateManifestDigest => {
                write!(f, "fork-store manifest contains duplicate branch digests")
            }
            Self::ProfileEncodingInvalid => {
                write!(f, "fork-store consensus profile cannot be encoded")
            }
            Self::ExternalCasClient(error) => write!(f, "QRun external CAS rejected: {error}"),
            Self::ExternalCasContract(error) => write!(f, "QRun external CAS contract rejected: {error}"),
            Self::PendingAnchorMalformed => write!(f, "QRun external-CAS pending commit is malformed or inconsistent"),
            Self::PendingRecoveryRequired => write!(f, "QRun external-CAS commit recovery is required; reopen the store before writing again"),
            Self::ExternalAnchorMismatch => write!(f, "QRun external anchor does not match the durable manifest or pinned record"),
            Self::RandomnessUnavailable => write!(f, "secure randomness is unavailable for QRun external-CAS operation IDs"),
        }
    }
}

impl std::error::Error for ForkStoreError {}

impl From<io::Error> for ForkStoreError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<StateError> for ForkStoreError {
    fn from(value: StateError) -> Self {
        Self::State(value)
    }
}

impl From<ForkChoiceError> for ForkStoreError {
    fn from(value: ForkChoiceError) -> Self {
        Self::Fork(value)
    }
}

impl From<ConsensusError> for ForkStoreError {
    fn from(value: ConsensusError) -> Self {
        Self::Consensus(value)
    }
}

impl From<ExternalCasClientError> for ForkStoreError {
    fn from(value: ExternalCasClientError) -> Self {
        Self::ExternalCasClient(value)
    }
}

impl From<crate::external_cas_anchor_candidate::ExternalCasError> for ForkStoreError {
    fn from(value: crate::external_cas_anchor_candidate::ExternalCasError) -> Self {
        Self::ExternalCasContract(value)
    }
}

fn acquire_writer_lock(directory: &Path) -> Result<StoreWriterLock, ForkStoreError> {
    StoreWriterLock::acquire(directory, LOCK_NAME).map_err(|error| {
        if error.kind() == io::ErrorKind::WouldBlock {
            ForkStoreError::LockHeld
        } else {
            ForkStoreError::Io(error)
        }
    })
}

#[derive(Debug)]
struct ParsedManifest {
    network_id: [u8; 32],
    profile_fingerprint: [u8; 32],
    genesis_tip: [u8; 32],
    canonical_tip: [u8; 32],
    digests: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingExternalCasCommit {
    previous_record: ExternalCasRecord,
    next_record: ExternalCasRecord,
    manifest: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PendingRecoveryOutcome {
    NotPresent,
    NotCommitted(ExternalCasRecord),
    Committed(ExternalCasRecord, u64),
}

pub struct QRunV05ExternalCasForkStore<P, V> {
    store: PrivateTestnetForkStore,
    client: VerifiedExternalCasClient<P, V>,
    pin: ExternalCasPin,
    trusted_record: ExternalCasRecord,
    minimum_object_generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ForkStoreProfile {
    LegacyPtb2,
    QRunV05FeeOnly,
    QRunV05FeeCheckpoint([u8; 32]),
}

impl ForkStoreProfile {
    fn is_qrun_fee_only(self) -> bool {
        matches!(self, Self::QRunV05FeeOnly | Self::QRunV05FeeCheckpoint(_))
    }
}

pub struct PrivateTestnetForkStore {
    directory: PathBuf,
    genesis: LedgerState,
    params: ConsensusParameters,
    profile_fingerprint: [u8; 32],
    profile: ForkStoreProfile,
    genesis_tip: [u8; 32],
    archive: PrivateTestnetForkChoice,
    _writer_lock: StoreWriterLock,
}

impl PrivateTestnetForkStore {
    /// Open a single-writer candidate branch store. A persistent lock file is reused only
    /// after the operating system grants its exclusive byte-range lock; PID text is diagnostic.
    pub fn open<A: TransactionAuthenticator>(
        directory: impl AsRef<Path>,
        genesis: LedgerState,
        params: ConsensusParameters,
        authenticator: &A,
        clock: &dyn ReferenceTimeProvider,
    ) -> Result<Self, ForkStoreError> {
        Self::open_inner(
            directory,
            genesis,
            params,
            authenticator,
            clock,
            None,
            None,
            ForkStoreProfile::LegacyPtb2,
        )
    }

    /// Open only when the stored PFS2 manifest matches an anchor provisioned independently
    /// of this mutable archive directory. A same-directory checksum is not an external anchor.
    pub fn open_anchored<A: TransactionAuthenticator>(
        directory: impl AsRef<Path>,
        genesis: LedgerState,
        params: ConsensusParameters,
        authenticator: &A,
        clock: &dyn ReferenceTimeProvider,
        expected_manifest_anchor: [u8; 32],
    ) -> Result<Self, ForkStoreError> {
        Self::open_inner(
            directory,
            genesis,
            params,
            authenticator,
            clock,
            Some(expected_manifest_anchor),
            None,
            ForkStoreProfile::LegacyPtb2,
        )
    }

    /// Open a Genesis-rooted QRun QFP5 branch store. The execution profile is domain-separated
    /// from the legacy PTB2 profile; checkpoint-rooted mode is deliberately not supported yet.
    pub fn open_qrun_v05_fee_only<A: TransactionAuthenticator>(
        directory: impl AsRef<Path>,
        genesis: LedgerState,
        params: ConsensusParameters,
        authenticator: &A,
        clock: &dyn ReferenceTimeProvider,
    ) -> Result<Self, ForkStoreError> {
        Self::open_inner(
            directory,
            genesis,
            params,
            authenticator,
            clock,
            None,
            None,
            ForkStoreProfile::QRunV05FeeOnly,
        )
    }

    /// Reopen the QRun profile only if its PFS2 manifest matches an externally retained anchor.
    pub fn open_qrun_v05_fee_only_anchored<A: TransactionAuthenticator>(
        directory: impl AsRef<Path>,
        genesis: LedgerState,
        params: ConsensusParameters,
        authenticator: &A,
        clock: &dyn ReferenceTimeProvider,
        expected_manifest_anchor: [u8; 32],
    ) -> Result<Self, ForkStoreError> {
        Self::open_inner(
            directory,
            genesis,
            params,
            authenticator,
            clock,
            Some(expected_manifest_anchor),
            None,
            ForkStoreProfile::QRunV05FeeOnly,
        )
    }

    /// Open a QRun QFP5 PFS2 suffix store rooted at a QRCP checkpoint whose exact commitment and
    /// monotonic height floor are supplied independently on every open. This constructor does not
    /// contact the external CAS provider; use the CAS wrapper for value-bearing production work.
    pub fn open_qrun_v05_fee_only_from_checkpoint<A: TransactionAuthenticator>(
        directory: impl AsRef<Path>,
        genesis: LedgerState,
        params: ConsensusParameters,
        authenticator: &A,
        clock: &dyn ReferenceTimeProvider,
        checkpoint_bytes: &[u8],
        expected_checkpoint_commitment: [u8; 32],
        minimum_checkpoint_height: u64,
        expected_manifest_anchor: Option<[u8; 32]>,
    ) -> Result<Self, ForkStoreError> {
        if genesis.network_id()
            != crate::qrun_v05_profile_identity_candidate::PROPOSED_QRUN_V05_NETWORK_ID
            || genesis.state_root()
                != crate::qrun_v05_profile_identity_candidate::PROPOSED_GENESIS_STATE_ROOT
            || expected_checkpoint_commitment == [0; 32]
        {
            return Err(ForkStoreError::ManifestProfileMismatch);
        }
        let frozen = crate::qrun_v05_profile_identity_candidate::build_candidate_genesis()
            .map_err(|_| ForkStoreError::ManifestProfileMismatch)?;
        if frozen.commitment()
            != crate::qrun_v05_profile_identity_candidate::PROPOSED_GENESIS_COMMITMENT
        {
            return Err(ForkStoreError::ManifestProfileMismatch);
        }
        let mut base_chain =
            crate::qrun_v05_checkpoint_candidate::QRunV05PowCheckpoint::restore_chain_anchored(
                checkpoint_bytes,
                &genesis.network_id(),
                &crate::qrun_v05_profile_identity_candidate::PROPOSED_GENESIS_COMMITMENT,
                &params,
                expected_checkpoint_commitment,
                minimum_checkpoint_height,
            )
            .map_err(|_| ForkStoreError::ManifestAnchorMismatch)?;
        base_chain
            .enable_qrun_v05_fee_only_execution()
            .map_err(|_| ForkStoreError::ManifestProfileMismatch)?;
        let checkpoint_commitment = expected_checkpoint_commitment;
        let base_state = base_chain.state().clone();
        Self::open_inner(
            directory,
            base_state,
            params,
            authenticator,
            clock,
            expected_manifest_anchor,
            Some(base_chain),
            ForkStoreProfile::QRunV05FeeCheckpoint(checkpoint_commitment),
        )
    }

    /// Open a bounded suffix store rooted at a previously authenticated checkpoint chain.
    /// Persist the checkpoint record/commitment separately and supply it again on every restart.
    pub fn open_from_base_chain<A: TransactionAuthenticator>(
        directory: impl AsRef<Path>,
        base_chain: crate::private_testnet_driver::PrivateTestnetChain,
        params: ConsensusParameters,
        authenticator: &A,
        clock: &dyn ReferenceTimeProvider,
        expected_manifest_anchor: Option<[u8; 32]>,
    ) -> Result<Self, ForkStoreError> {
        let base_state = base_chain.state().clone();
        Self::open_inner(
            directory,
            base_state,
            params,
            authenticator,
            clock,
            expected_manifest_anchor,
            Some(base_chain),
            ForkStoreProfile::LegacyPtb2,
        )
    }

    fn open_inner<A: TransactionAuthenticator>(
        directory: impl AsRef<Path>,
        genesis: LedgerState,
        params: ConsensusParameters,
        authenticator: &A,
        clock: &dyn ReferenceTimeProvider,
        expected_manifest_anchor: Option<[u8; 32]>,
        base_chain: Option<crate::private_testnet_driver::PrivateTestnetChain>,
        profile: ForkStoreProfile,
    ) -> Result<Self, ForkStoreError> {
        Self::open_inner_with_preopen_recovery(
            directory,
            genesis,
            params,
            authenticator,
            clock,
            expected_manifest_anchor,
            base_chain,
            profile,
            None,
        )
    }

    fn open_inner_with_preopen_recovery<A: TransactionAuthenticator>(
        directory: impl AsRef<Path>,
        genesis: LedgerState,
        params: ConsensusParameters,
        authenticator: &A,
        clock: &dyn ReferenceTimeProvider,
        expected_manifest_anchor: Option<[u8; 32]>,
        base_chain: Option<crate::private_testnet_driver::PrivateTestnetChain>,
        profile: ForkStoreProfile,
        mut preopen_recovery: Option<&mut dyn FnMut(&Path) -> Result<(), ForkStoreError>>,
    ) -> Result<Self, ForkStoreError> {
        params.validate()?;
        match profile {
            ForkStoreProfile::QRunV05FeeOnly if base_chain.is_some() => {
                return Err(ForkStoreError::ManifestProfileMismatch);
            }
            ForkStoreProfile::QRunV05FeeCheckpoint(_) if base_chain.is_none() => {
                return Err(ForkStoreError::ManifestProfileMismatch);
            }
            _ => {}
        }
        let directory = directory.as_ref().to_path_buf();
        fs::create_dir_all(&directory)?;
        let writer_lock = acquire_writer_lock(&directory)?;
        if let Some(recover) = preopen_recovery.as_mut() {
            recover(&directory)?;
        }

        let profile_fingerprint = match profile {
            ForkStoreProfile::LegacyPtb2 => profile_fingerprint(&genesis, &params)?,
            ForkStoreProfile::QRunV05FeeOnly => {
                qrun_v05_fee_profile_fingerprint(&genesis, &params)?
            }
            ForkStoreProfile::QRunV05FeeCheckpoint(commitment) => {
                qrun_v05_fee_checkpoint_profile_fingerprint(&genesis, &params, commitment)?
            }
        };
        let empty = match profile {
            ForkStoreProfile::QRunV05FeeOnly => {
                PrivateTestnetForkChoice::new_qrun_v05_fee_only(genesis.clone(), params.clone())?
            }
            ForkStoreProfile::QRunV05FeeCheckpoint(commitment) => {
                let base = base_chain
                    .as_ref()
                    .ok_or(ForkStoreError::ManifestProfileMismatch)?;
                PrivateTestnetForkChoice::new_qrun_v05_fee_only_from_checkpoint(
                    genesis.clone(),
                    params.clone(),
                    base.clone(),
                    commitment,
                )?
            }
            ForkStoreProfile::LegacyPtb2 => match base_chain.as_ref() {
                Some(base) => PrivateTestnetForkChoice::from_base_chain(
                    genesis.clone(),
                    params.clone(),
                    base.clone(),
                )?,
                None => PrivateTestnetForkChoice::new(genesis.clone(), params.clone())?,
            },
        };
        let genesis_tip = empty.canonical_chain().chain_tip().tip_hash;
        let manifest_path = directory.join(MANIFEST_NAME);

        let (archive, known_digests) = if manifest_path.exists() {
            let manifest_bytes = read_bounded_file(&manifest_path, MAX_MANIFEST_BYTES).map_err(
                |error| match error {
                    BoundedReadError::Io(error) => ForkStoreError::Io(error),
                    BoundedReadError::TooLarge => ForkStoreError::ManifestTooLarge,
                },
            )?;
            // A checkpoint-rooted segment must not silently reopen an existing suffix
            // without an anchor retained outside the mutable archive directory. Otherwise a
            // self-consistent rollback of its manifest can discard already-committed blocks.
            if base_chain.is_some() && expected_manifest_anchor.is_none() {
                return Err(ForkStoreError::ManifestAnchorMismatch);
            }
            if expected_manifest_anchor
                .is_some_and(|expected| manifest_anchor_commitment(&manifest_bytes) != expected)
            {
                return Err(ForkStoreError::ManifestAnchorMismatch);
            }
            let manifest = decode_manifest(&manifest_bytes)?;
            if manifest.network_id != genesis.network_id()
                || manifest.profile_fingerprint != profile_fingerprint
                || manifest.genesis_tip != genesis_tip
            {
                return Err(ForkStoreError::ManifestProfileMismatch);
            }

            let mut envelopes = Vec::with_capacity(manifest.digests.len());
            let known: BTreeSet<[u8; 32]> = manifest.digests.iter().copied().collect();
            for digest in &manifest.digests {
                let path = directory.join(branch_file_name(digest));
                if !path.is_file() {
                    return Err(ForkStoreError::MissingReferencedBranch);
                }
                let bytes = read_bounded_file(&path, MAX_CANDIDATE_NETWORK_ENVELOPE_BYTES)
                    .map_err(|error| match error {
                        BoundedReadError::Io(error) => ForkStoreError::Io(error),
                        BoundedReadError::TooLarge => ForkStoreError::BranchFileTooLarge,
                    })?;
                let decoded =
                    decode_candidate_network_block(&bytes).map_err(ForkStoreError::from_wire)?;
                if decoded.fee_block.is_some() != profile.is_qrun_fee_only() {
                    return Err(ForkStoreError::ManifestProfileMismatch);
                }
                if decoded.header.network_id != genesis.network_id()
                    || pow_digest(&decoded.header, params.pow)? != *digest
                {
                    return Err(ForkStoreError::BranchFilenameDigestMismatch);
                }
                envelopes.push(bytes);
            }
            let archive = match profile {
                ForkStoreProfile::QRunV05FeeOnly => {
                    PrivateTestnetForkChoice::rebuild_qrun_v05_fee_from_envelopes(
                        genesis.clone(),
                        params.clone(),
                        envelopes,
                        authenticator,
                        clock,
                    )?
                }
                ForkStoreProfile::QRunV05FeeCheckpoint(commitment) => {
                    let base = base_chain
                        .as_ref()
                        .ok_or(ForkStoreError::ManifestProfileMismatch)?;
                    PrivateTestnetForkChoice::rebuild_qrun_v05_fee_from_checkpoint(
                        genesis.clone(),
                        params.clone(),
                        base.clone(),
                        commitment,
                        envelopes,
                        authenticator,
                        clock,
                    )?
                }
                ForkStoreProfile::LegacyPtb2 => match base_chain.as_ref() {
                    Some(base) => PrivateTestnetForkChoice::rebuild_from_base_chain(
                        genesis.clone(),
                        params.clone(),
                        base.clone(),
                        envelopes,
                        authenticator,
                        clock,
                    )?,
                    None => PrivateTestnetForkChoice::rebuild_from_envelopes(
                        genesis.clone(),
                        params.clone(),
                        envelopes,
                        authenticator,
                        clock,
                    )?,
                },
            };
            let replayed_tip = archive.canonical_chain().chain_tip().tip_hash;
            if replayed_tip != manifest.canonical_tip {
                return Err(ForkStoreError::CanonicalTipMismatch);
            }
            (archive, known)
        } else {
            if expected_manifest_anchor.is_some() {
                return Err(ForkStoreError::ManifestAnchorMismatch);
            }
            if manifest_path.exists() {
                return Err(ForkStoreError::ManifestMalformed);
            }
            let known = BTreeSet::new();
            write_manifest_atomic(
                &manifest_path,
                &encode_manifest(
                    &genesis.network_id(),
                    &profile_fingerprint,
                    &genesis_tip,
                    &genesis_tip,
                    &[],
                )?,
            )?;
            (empty, known)
        };

        cleanup_orphan_branch_files(&directory, &known_digests)?;
        Ok(Self {
            directory,
            genesis,
            params,
            profile_fingerprint,
            profile,
            genesis_tip,
            archive,
            _writer_lock: writer_lock,
        })
    }

    pub fn archive(&self) -> &PrivateTestnetForkChoice {
        &self.archive
    }

    pub fn canonical_tip(&self) -> [u8; 32] {
        self.archive.canonical_chain().chain_tip().tip_hash
    }

    pub fn canonical_height(&self) -> u64 {
        self.archive.canonical_chain().state().height()
    }

    /// Return the commitment that an operator must persist outside this archive directory
    /// to make later `open_anchored` calls meaningful. The manifest is checked against the
    /// already-open in-memory archive before the commitment is returned.
    pub fn manifest_anchor(&self) -> Result<[u8; 32], ForkStoreError> {
        let bytes = read_bounded_file(&self.directory.join(MANIFEST_NAME), MAX_MANIFEST_BYTES)
            .map_err(|error| match error {
                BoundedReadError::Io(error) => ForkStoreError::Io(error),
                BoundedReadError::TooLarge => ForkStoreError::ManifestTooLarge,
            })?;
        let manifest = decode_manifest(&bytes)?;
        if manifest.network_id != self.genesis.network_id()
            || manifest.profile_fingerprint != self.profile_fingerprint
            || manifest.genesis_tip != self.genesis_tip
            || manifest.canonical_tip != self.canonical_tip()
        {
            return Err(ForkStoreError::ManifestAnchorMismatch);
        }
        let mut digests = self
            .archive
            .archive_envelopes()
            .iter()
            .map(|bytes| {
                let decoded =
                    decode_candidate_network_block(bytes).map_err(ForkStoreError::from_wire)?;
                Ok(pow_digest(&decoded.header, self.params.pow)?)
            })
            .collect::<Result<Vec<_>, ForkStoreError>>()?;
        digests.sort_unstable();
        if digests != manifest.digests {
            return Err(ForkStoreError::ManifestAnchorMismatch);
        }
        Ok(manifest_anchor_commitment(&bytes))
    }

    pub fn submit<A: TransactionAuthenticator>(
        &mut self,
        envelope: &[u8],
        authenticator: &A,
        clock: &dyn ReferenceTimeProvider,
    ) -> Result<ForkChoiceOutcome, ForkStoreError> {
        let is_qfp5 = envelope.starts_with(b"QFP5");
        if is_qfp5 != self.profile.is_qrun_fee_only() {
            return Err(ForkStoreError::Fork(ForkChoiceError::ExecutionModeMismatch));
        }
        // Validate into an isolated clone first. No durable bytes or visible in-memory state
        // change if consensus/fork-choice validation fails.
        let mut candidate_archive = self.archive.clone();
        let outcome = candidate_archive.insert_encoded(envelope, authenticator, clock)?;
        let digest = outcome.block_digest;
        let branch_path = self.directory.join(branch_file_name(&digest));

        if branch_path.exists() {
            let existing = read_bounded_file(&branch_path, MAX_CANDIDATE_NETWORK_ENVELOPE_BYTES)
                .map_err(|error| match error {
                    BoundedReadError::Io(error) => ForkStoreError::Io(error),
                    BoundedReadError::TooLarge => ForkStoreError::BranchFileTooLarge,
                })?;
            if existing != envelope {
                return Err(ForkStoreError::BranchFilenameDigestMismatch);
            }
        } else if self.archive.branch_chain(&digest).is_none() {
            write_branch_create_new(&branch_path, envelope)?;
        }

        // PFS2 manifest publication is the commit point. If it fails, the branch file is an
        // unreferenced orphan and current memory remains unchanged.
        let mut digests: Vec<[u8; 32]> = candidate_archive
            .archive_envelopes()
            .iter()
            .map(|bytes| {
                let decoded =
                    decode_candidate_network_block(bytes).map_err(ForkStoreError::from_wire)?;
                Ok(pow_digest(&decoded.header, self.params.pow)?)
            })
            .collect::<Result<_, ForkStoreError>>()?;
        digests.sort_unstable();
        if digests.len() > MAX_FORK_ARCHIVE_BLOCKS {
            return Err(ForkStoreError::ManifestTooLarge);
        }
        let canonical_tip = candidate_archive.canonical_chain().chain_tip().tip_hash;
        let manifest = encode_manifest(
            &self.genesis.network_id(),
            &self.profile_fingerprint,
            &self.genesis_tip,
            &canonical_tip,
            &digests,
        )?;
        write_manifest_atomic(&self.directory.join(MANIFEST_NAME), &manifest)?;
        self.archive = candidate_archive;
        Ok(outcome)
    }
}

impl<P, V> QRunV05ExternalCasForkStore<P, V>
where
    P: ExternalCasProviderTransport,
    V: MlDsa65Verifier,
{
    /// Open the QRun PFS2 store only when its current manifest is linked to the caller's
    /// independently retained signed-CAS record. The transport must target an independently
    /// administered provider with atomic server-side CAS; the local implementation cannot prove
    /// that operational-independence requirement for the caller.
    pub fn open<A: TransactionAuthenticator>(
        directory: impl AsRef<Path>,
        genesis: LedgerState,
        params: ConsensusParameters,
        authenticator: &A,
        clock: &dyn ReferenceTimeProvider,
        pin: ExternalCasPin,
        mut client: VerifiedExternalCasClient<P, V>,
        trusted_record: ExternalCasRecord,
        minimum_object_generation: u64,
    ) -> Result<Self, ForkStoreError> {
        pin.validate()?;
        trusted_record.validate_shape()?;
        if minimum_object_generation == 0
            || !client.is_pinned_to(&pin)
            || pin.network_id != genesis.network_id()
            || pin.network_id
                != crate::qrun_v05_profile_identity_candidate::PROPOSED_QRUN_V05_NETWORK_ID
            || pin.genesis_digest
                != crate::qrun_v05_profile_identity_candidate::PROPOSED_GENESIS_COMMITMENT
            || trusted_record.provider_id != pin.provider_id
            || trusted_record.network_id != pin.network_id
            || trusted_record.genesis_digest != pin.genesis_digest
        {
            return Err(ForkStoreError::ExternalAnchorMismatch);
        }
        let frozen_genesis = crate::qrun_v05_profile_identity_candidate::build_candidate_genesis()
            .map_err(|_| ForkStoreError::ExternalAnchorMismatch)?;
        if frozen_genesis.state_root() != genesis.state_root()
            || frozen_genesis.commitment()
                != crate::qrun_v05_profile_identity_candidate::PROPOSED_GENESIS_COMMITMENT
        {
            return Err(ForkStoreError::ExternalAnchorMismatch);
        }

        let recovery_genesis = genesis.clone();
        let recovery_params = params.clone();
        let recovery_pin = pin.clone();
        let mut recovery = |directory: &Path| {
            recover_pending_external_cas(
                directory,
                &recovery_genesis,
                &recovery_params,
                &recovery_pin,
                &mut client,
                minimum_object_generation,
            )
            .map(|_| ())
        };
        let store = PrivateTestnetForkStore::open_inner_with_preopen_recovery(
            directory,
            genesis,
            params,
            authenticator,
            clock,
            None,
            None,
            ForkStoreProfile::QRunV05FeeOnly,
            Some(&mut recovery),
        )?;
        drop(recovery);

        // If a crash happened after the signed external CAS but just before the caller updated its
        // independently stored floor, allow only one exact successor whose state digest matches
        // the locally committed manifest. Never accept a remote jump over missing local history.
        let local_anchor = store.manifest_anchor()?;
        let (observed, object_generation) =
            read_verified_external_record(&mut client, &trusted_record, minimum_object_generation)?;
        if observed.next_state_digest != local_anchor {
            return Err(ForkStoreError::ExternalAnchorMismatch);
        }
        Ok(Self {
            store,
            client,
            pin,
            trusted_record: observed,
            minimum_object_generation: object_generation,
        })
    }

    pub fn canonical_height(&self) -> u64 {
        self.store.canonical_height()
    }

    pub fn canonical_state(&self) -> &LedgerState {
        self.store.archive.canonical_chain().state()
    }

    pub fn manifest_anchor(&self) -> Result<[u8; 32], ForkStoreError> {
        self.store.manifest_anchor()
    }

    /// The caller must durably retain this signed-CAS record outside the PFS2 archive before
    /// treating the next process start as trusted. The provider pin/key must also be provisioned
    /// out-of-band; this method cannot establish provider independence by itself.
    pub fn trusted_record(&self) -> &ExternalCasRecord {
        &self.trusted_record
    }

    pub fn minimum_object_generation(&self) -> u64 {
        self.minimum_object_generation
    }

    /// Two-phase QRun commit:
    /// 1. verify the current external anchor and candidate branch;
    /// 2. durably write QAP1 containing the exact next manifest and CAS successor;
    /// 3. require the provider's signed atomic CAS receipt;
    /// 4. publish the PFS2 manifest, then publish in-memory state.
    ///
    /// If the provider call has an ambiguous result, a fresh signed read resolves it only when
    /// the observed record is exactly the old record or exactly the prepared successor. Otherwise
    /// QAP1 is left in place and the store fails closed until reopening/reconciliation.
    pub fn submit<A: TransactionAuthenticator>(
        &mut self,
        envelope: &[u8],
        authenticator: &A,
        clock: &dyn ReferenceTimeProvider,
    ) -> Result<ForkChoiceOutcome, ForkStoreError> {
        if self.store.profile != ForkStoreProfile::QRunV05FeeOnly {
            return Err(ForkStoreError::ManifestProfileMismatch);
        }
        if self.store.directory.join(QRUN_PENDING_NAME).exists() {
            return Err(ForkStoreError::PendingRecoveryRequired);
        }
        let current_anchor = self.store.manifest_anchor()?;
        if current_anchor != self.trusted_record.next_state_digest {
            return Err(ForkStoreError::ExternalAnchorMismatch);
        }
        let (remote_before, object_generation) = read_verified_external_record(
            &mut self.client,
            &self.trusted_record,
            self.minimum_object_generation,
        )?;
        if remote_before.digest()? != self.trusted_record.digest()?
            || remote_before.next_state_digest != current_anchor
        {
            return Err(ForkStoreError::ExternalAnchorMismatch);
        }
        self.minimum_object_generation = object_generation;

        if !envelope.starts_with(b"QFP5") {
            return Err(ForkStoreError::Fork(ForkChoiceError::ExecutionModeMismatch));
        }

        let mut candidate_archive = self.store.archive.clone();
        let outcome = candidate_archive.insert_encoded(envelope, authenticator, clock)?;
        let digest = outcome.block_digest;
        let branch_path = self.store.directory.join(branch_file_name(&digest));

        if branch_path.exists() {
            let existing = read_bounded_file(&branch_path, MAX_CANDIDATE_NETWORK_ENVELOPE_BYTES)
                .map_err(|error| match error {
                    BoundedReadError::Io(error) => ForkStoreError::Io(error),
                    BoundedReadError::TooLarge => ForkStoreError::BranchFileTooLarge,
                })?;
            if existing != envelope {
                return Err(ForkStoreError::BranchFilenameDigestMismatch);
            }
        } else if self.store.archive.branch_chain(&digest).is_none() {
            write_branch_create_new(&branch_path, envelope)?;
        }

        let mut digests: Vec<[u8; 32]> = candidate_archive
            .archive_envelopes()
            .iter()
            .map(|bytes| {
                let decoded =
                    decode_candidate_network_block(bytes).map_err(ForkStoreError::from_wire)?;
                Ok(pow_digest(&decoded.header, self.store.params.pow)?)
            })
            .collect::<Result<_, ForkStoreError>>()?;
        digests.sort_unstable();
        if digests.len() > MAX_FORK_ARCHIVE_BLOCKS {
            return Err(ForkStoreError::ManifestTooLarge);
        }
        let canonical_tip = candidate_archive.canonical_chain().chain_tip().tip_hash;
        let manifest = encode_manifest(
            &self.store.genesis.network_id(),
            &self.store.profile_fingerprint,
            &self.store.genesis_tip,
            &canonical_tip,
            &digests,
        )?;
        let next_state_digest = manifest_anchor_commitment(&manifest);
        if next_state_digest == self.trusted_record.next_state_digest {
            // An exact duplicate is idempotent and must not advance the external generation.
            return Ok(outcome);
        }

        let operation_id = random_nonzero_digest()?;
        let request_nonce = random_nonzero_digest()?;
        let previous_record = self.trusted_record.clone();
        let previous_record_digest = previous_record.digest()?;
        let mut next_record = ExternalCasRecord {
            generation: previous_record
                .generation
                .checked_add(1)
                .ok_or(ForkStoreError::ExternalAnchorMismatch)?,
            provider_id: self.pin.provider_id,
            network_id: self.pin.network_id,
            genesis_digest: self.pin.genesis_digest,
            previous_record_digest,
            previous_state_digest: previous_record.next_state_digest,
            next_state_digest,
            operation_id,
            // bind_request_digest replaces this placeholder before any bytes are sent.
            request_digest: [1; 32],
        };
        let mut request = ExternalCasWriteRequest {
            request_nonce,
            operation_id,
            request_digest: [1; 32],
            expected_generation: previous_record.generation,
            expected_object_generation: self.minimum_object_generation,
            expected_record_digest: previous_record_digest,
            expected_state_digest: previous_record.next_state_digest,
            next_record: next_record.clone(),
        };
        request.bind_request_digest(&self.pin)?;
        next_record = request.next_record.clone();
        let pending = PendingExternalCasCommit {
            previous_record,
            next_record: next_record.clone(),
            manifest: manifest.clone(),
        };
        write_pending_external_cas_commit(&self.store.directory, &pending)?;

        match self.client.compare_and_swap(&request) {
            Ok(receipt) => {
                // The provider has signed the exact successor, so local publication can now proceed.
                write_manifest_atomic(&self.store.directory.join(MANIFEST_NAME), &manifest)?;
                self.store.archive = candidate_archive;
                self.trusted_record = next_record;
                self.minimum_object_generation = receipt.object_generation;
                // A stale pending marker is safe: reopen will verify the exact external successor
                // and finish cleanup. Do not turn a committed block into a reported failure merely
                // because deleting this recovery marker failed after manifest publication.
                let _ = remove_pending_external_cas_commit(&self.store.directory);
                Ok(outcome)
            }
            Err(cas_error) => {
                // Provider errors can mean the CAS committed but the response was lost. Resolve
                // only from a fresh, signed read of the exact pending successor.
                match recover_pending_external_cas(
                    &self.store.directory,
                    &self.store.genesis,
                    &self.store.params,
                    &self.pin,
                    &mut self.client,
                    self.minimum_object_generation,
                ) {
                    Ok(PendingRecoveryOutcome::NotCommitted(record)) => {
                        self.trusted_record = record;
                        Err(ForkStoreError::ExternalCasClient(cas_error))
                    }
                    Ok(PendingRecoveryOutcome::Committed(record, generation)) => {
                        self.store.archive = candidate_archive;
                        self.trusted_record = record;
                        self.minimum_object_generation = generation;
                        Ok(outcome)
                    }
                    Ok(PendingRecoveryOutcome::NotPresent) | Err(_) => {
                        Err(ForkStoreError::PendingRecoveryRequired)
                    }
                }
            }
        }
    }
}

impl ForkStoreError {
    fn from_wire(error: PrivateTestnetWireError) -> Self {
        Self::Fork(ForkChoiceError::Wire(error))
    }
}

#[derive(Debug)]
enum BoundedReadError {
    Io(io::Error),
    TooLarge,
}

fn read_bounded_file(path: &Path, max_bytes: usize) -> Result<Vec<u8>, BoundedReadError> {
    let file = File::open(path).map_err(BoundedReadError::Io)?;
    let length = file.metadata().map_err(BoundedReadError::Io)?.len();
    if length > max_bytes as u64 {
        return Err(BoundedReadError::TooLarge);
    }
    let mut bytes = Vec::with_capacity(length as usize);
    file.take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(BoundedReadError::Io)?;
    if bytes.len() > max_bytes {
        return Err(BoundedReadError::TooLarge);
    }
    Ok(bytes)
}

fn manifest_anchor_commitment(manifest_bytes: &[u8]) -> [u8; 32] {
    let mut canonical =
        Vec::with_capacity(b"AIN1-PTB2-MANIFEST-ANCHOR-V1\\0".len() + 8 + manifest_bytes.len());
    canonical.extend_from_slice(b"AIN1-PTB2-MANIFEST-ANCHOR-V1\\0");
    canonical.extend_from_slice(&(manifest_bytes.len() as u64).to_be_bytes());
    canonical.extend_from_slice(manifest_bytes);
    Sha256::digest(&canonical).into()
}

fn profile_fingerprint(
    genesis: &LedgerState,
    params: &ConsensusParameters,
) -> Result<[u8; 32], ForkStoreError> {
    let genesis_bytes = genesis.encode_snapshot()?;
    let mut canonical = Vec::with_capacity(256 + genesis_bytes.len());
    canonical.extend_from_slice(PROFILE_DOMAIN);
    canonical.extend_from_slice(&(genesis_bytes.len() as u64).to_be_bytes());
    canonical.extend_from_slice(&genesis_bytes);
    canonical.extend_from_slice(&params.protocol_version.to_be_bytes());
    canonical.extend_from_slice(&params.target_block_time_secs.to_be_bytes());
    canonical.extend_from_slice(&params.difficulty_window_blocks.to_be_bytes());
    canonical.extend_from_slice(&params.difficulty_min_ratio_divisor.to_be_bytes());
    canonical.extend_from_slice(&params.difficulty_max_ratio.to_be_bytes());
    canonical.extend_from_slice(&params.pow_limit.to_be_bytes());
    canonical.extend_from_slice(&params.initial_target.to_be_bytes());
    canonical.push(match params.pow.algorithm {
        PowAlgorithm::Argon2id => 1,
    });
    canonical.extend_from_slice(&params.pow.memory_kib.to_be_bytes());
    canonical.extend_from_slice(&params.pow.iterations.to_be_bytes());
    canonical.extend_from_slice(&params.pow.lanes.to_be_bytes());
    canonical.push(params.pow.output_bytes);
    canonical.extend_from_slice(&params.issuance.maximum_supply().to_be_bytes());
    canonical.extend_from_slice(&params.issuance.initial_subsidy().to_be_bytes());
    canonical.extend_from_slice(&params.issuance.blocks_per_halving().to_be_bytes());
    Ok(Sha256::digest(&canonical).into())
}

fn qrun_v05_fee_profile_fingerprint(
    genesis: &LedgerState,
    params: &ConsensusParameters,
) -> Result<[u8; 32], ForkStoreError> {
    let legacy_fingerprint = profile_fingerprint(genesis, params)?;
    let mut canonical = Vec::with_capacity(QRUN_V05_FEE_PROFILE_DOMAIN.len() + 32);
    canonical.extend_from_slice(QRUN_V05_FEE_PROFILE_DOMAIN);
    canonical.extend_from_slice(&legacy_fingerprint);
    Ok(Sha256::digest(&canonical).into())
}

fn qrun_v05_fee_checkpoint_profile_fingerprint(
    base_state: &LedgerState,
    params: &ConsensusParameters,
    checkpoint_commitment: [u8; 32],
) -> Result<[u8; 32], ForkStoreError> {
    if checkpoint_commitment == [0; 32]
        || base_state.network_id()
            != crate::qrun_v05_profile_identity_candidate::PROPOSED_QRUN_V05_NETWORK_ID
        || base_state.height() == 0
        || base_state.total_value().ok() != Some(crate::state_machine::MAX_TOTAL_SUPPLY_ATOMS)
    {
        return Err(ForkStoreError::ManifestProfileMismatch);
    }
    let base_fingerprint = qrun_v05_fee_profile_fingerprint(base_state, params)?;
    let mut canonical = Vec::with_capacity(QRUN_V05_FEE_CHECKPOINT_PROFILE_DOMAIN.len() + 64);
    canonical.extend_from_slice(QRUN_V05_FEE_CHECKPOINT_PROFILE_DOMAIN);
    canonical.extend_from_slice(&checkpoint_commitment);
    canonical.extend_from_slice(&base_fingerprint);
    Ok(Sha256::digest(&canonical).into())
}

fn encode_pending_external_cas_commit(
    pending: &PendingExternalCasCommit,
) -> Result<Vec<u8>, ForkStoreError> {
    pending
        .previous_record
        .validate_successor(&pending.next_record)?;
    if pending.manifest.is_empty()
        || pending.manifest.len() > MAX_MANIFEST_BYTES
        || manifest_anchor_commitment(&pending.manifest) != pending.next_record.next_state_digest
    {
        return Err(ForkStoreError::PendingAnchorMalformed);
    }
    let previous = pending.previous_record.encode()?;
    let next = pending.next_record.encode()?;
    let mut bytes = Vec::with_capacity(
        4 + 2
            + previous.len()
            + next.len()
            + 4
            + pending.manifest.len()
            + QRUN_PENDING_CHECKSUM_BYTES,
    );
    bytes.extend_from_slice(QRUN_PENDING_MAGIC);
    bytes.extend_from_slice(&QRUN_PENDING_VERSION.to_be_bytes());
    bytes.extend_from_slice(&previous);
    bytes.extend_from_slice(&next);
    bytes.extend_from_slice(&(pending.manifest.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&pending.manifest);
    let mut checksum_preimage = Vec::with_capacity(QRUN_PENDING_DOMAIN.len() + bytes.len());
    checksum_preimage.extend_from_slice(QRUN_PENDING_DOMAIN);
    checksum_preimage.extend_from_slice(&bytes);
    bytes.extend_from_slice(&Sha256::digest(&checksum_preimage));
    if bytes.len() > MAX_QRUN_PENDING_BYTES {
        return Err(ForkStoreError::PendingAnchorMalformed);
    }
    Ok(bytes)
}

fn decode_pending_external_cas_commit(
    bytes: &[u8],
) -> Result<PendingExternalCasCommit, ForkStoreError> {
    if bytes.len() > MAX_QRUN_PENDING_BYTES
        || bytes.len() < 4 + 2 + 2 * EXTERNAL_CAS_RECORD_BYTES + 4 + QRUN_PENDING_CHECKSUM_BYTES
    {
        return Err(ForkStoreError::PendingAnchorMalformed);
    }
    if &bytes[..4] != QRUN_PENDING_MAGIC
        || u16::from_be_bytes([bytes[4], bytes[5]]) != QRUN_PENDING_VERSION
    {
        return Err(ForkStoreError::PendingAnchorMalformed);
    }
    let checksum_offset = bytes.len() - QRUN_PENDING_CHECKSUM_BYTES;
    let mut checksum_preimage = Vec::with_capacity(QRUN_PENDING_DOMAIN.len() + checksum_offset);
    checksum_preimage.extend_from_slice(QRUN_PENDING_DOMAIN);
    checksum_preimage.extend_from_slice(&bytes[..checksum_offset]);
    if Sha256::digest(&checksum_preimage).as_slice() != &bytes[checksum_offset..] {
        return Err(ForkStoreError::PendingAnchorMalformed);
    }
    let previous_start = 6;
    let previous_end = previous_start + EXTERNAL_CAS_RECORD_BYTES;
    let next_end = previous_end + EXTERNAL_CAS_RECORD_BYTES;
    let previous_record = ExternalCasRecord::decode(&bytes[previous_start..previous_end])?;
    let next_record = ExternalCasRecord::decode(&bytes[previous_end..next_end])?;
    let manifest_len = u32::from_be_bytes(
        bytes[next_end..next_end + 4]
            .try_into()
            .map_err(|_| ForkStoreError::PendingAnchorMalformed)?,
    ) as usize;
    let manifest_start = next_end + 4;
    let manifest_end = manifest_start
        .checked_add(manifest_len)
        .ok_or(ForkStoreError::PendingAnchorMalformed)?;
    if manifest_len == 0 || manifest_len > MAX_MANIFEST_BYTES || manifest_end != checksum_offset {
        return Err(ForkStoreError::PendingAnchorMalformed);
    }
    let manifest = bytes[manifest_start..manifest_end].to_vec();
    let pending = PendingExternalCasCommit {
        previous_record,
        next_record,
        manifest,
    };
    // Re-encode to reject any noncanonical envelope or link relation.
    if encode_pending_external_cas_commit(&pending)? != bytes {
        return Err(ForkStoreError::PendingAnchorMalformed);
    }
    Ok(pending)
}

fn write_pending_external_cas_commit(
    directory: &Path,
    pending: &PendingExternalCasCommit,
) -> Result<(), ForkStoreError> {
    let path = directory.join(QRUN_PENDING_NAME);
    match fs::symlink_metadata(&path) {
        Ok(_) => return Err(ForkStoreError::PendingRecoveryRequired),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(ForkStoreError::Io(error)),
    }
    write_manifest_atomic(&path, &encode_pending_external_cas_commit(pending)?)
}

fn remove_pending_external_cas_commit(directory: &Path) -> Result<(), ForkStoreError> {
    let path = directory.join(QRUN_PENDING_NAME);
    match fs::remove_file(&path) {
        Ok(()) => sync_parent(directory).map_err(ForkStoreError::Io),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(ForkStoreError::Io(error)),
    }
}

fn random_nonzero_digest() -> Result<[u8; 32], ForkStoreError> {
    for _ in 0..2 {
        let mut value = [0u8; 32];
        getrandom::getrandom(&mut value).map_err(|_| ForkStoreError::RandomnessUnavailable)?;
        if value.iter().any(|byte| *byte != 0) {
            return Ok(value);
        }
    }
    Err(ForkStoreError::RandomnessUnavailable)
}

fn read_verified_external_record<P, V>(
    client: &mut VerifiedExternalCasClient<P, V>,
    expected: &ExternalCasRecord,
    minimum_object_generation: u64,
) -> Result<(ExternalCasRecord, u64), ForkStoreError>
where
    P: ExternalCasProviderTransport,
    V: MlDsa65Verifier,
{
    let operation_id = random_nonzero_digest()?;
    let mut hasher = Sha256::new();
    hasher.update(b"QRUN-V05-EXTERNAL-CAS-READ-REQUEST-V1\0");
    hasher.update(operation_id);
    hasher.update(expected.digest()?);
    let request_digest: [u8; 32] = hasher.finalize().into();
    let request = client.fresh_read_request(operation_id, request_digest)?;
    let observed = client.read_current(
        &request,
        expected.generation,
        minimum_object_generation,
        Some(expected),
    )?;
    Ok((observed.record, observed.object_generation))
}

fn recover_pending_external_cas<P, V>(
    directory: &Path,
    genesis: &LedgerState,
    params: &ConsensusParameters,
    pin: &ExternalCasPin,
    client: &mut VerifiedExternalCasClient<P, V>,
    minimum_object_generation: u64,
) -> Result<PendingRecoveryOutcome, ForkStoreError>
where
    P: ExternalCasProviderTransport,
    V: MlDsa65Verifier,
{
    let path = directory.join(QRUN_PENDING_NAME);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(PendingRecoveryOutcome::NotPresent)
        }
        Err(error) => return Err(ForkStoreError::Io(error)),
    };
    if !metadata.file_type().is_file() {
        return Err(ForkStoreError::PendingAnchorMalformed);
    }
    let bytes = read_bounded_file(&path, MAX_QRUN_PENDING_BYTES).map_err(|error| match error {
        BoundedReadError::Io(error) => ForkStoreError::Io(error),
        BoundedReadError::TooLarge => ForkStoreError::PendingAnchorMalformed,
    })?;
    let pending = decode_pending_external_cas_commit(&bytes)?;
    pin.validate()?;
    if pending.previous_record.provider_id != pin.provider_id
        || pending.next_record.provider_id != pin.provider_id
        || pending.previous_record.network_id != pin.network_id
        || pending.next_record.network_id != pin.network_id
        || pending.previous_record.genesis_digest != pin.genesis_digest
        || pending.next_record.genesis_digest != pin.genesis_digest
        || genesis.network_id() != pin.network_id
        || pin.genesis_digest
            != crate::qrun_v05_profile_identity_candidate::PROPOSED_GENESIS_COMMITMENT
    {
        return Err(ForkStoreError::PendingAnchorMalformed);
    }
    let manifest = decode_manifest(&pending.manifest)?;
    let profile_fingerprint = qrun_v05_fee_profile_fingerprint(genesis, params)?;
    let expected_genesis_tip =
        PrivateTestnetForkChoice::new_qrun_v05_fee_only(genesis.clone(), params.clone())?
            .genesis_tip();
    if manifest.network_id != pin.network_id
        || manifest.profile_fingerprint != profile_fingerprint
        || manifest.genesis_tip != expected_genesis_tip
        || manifest_anchor_commitment(&pending.manifest) != pending.next_record.next_state_digest
    {
        return Err(ForkStoreError::PendingAnchorMalformed);
    }

    let (observed, object_generation) =
        read_verified_external_record(client, &pending.previous_record, minimum_object_generation)?;
    let observed_digest = observed.digest()?;
    if observed_digest == pending.previous_record.digest()? {
        remove_pending_external_cas_commit(directory)?;
        return Ok(PendingRecoveryOutcome::NotCommitted(observed));
    }
    if observed_digest != pending.next_record.digest()?
        || observed.next_state_digest != pending.next_record.next_state_digest
        || observed.operation_id != pending.next_record.operation_id
        || observed.request_digest != pending.next_record.request_digest
    {
        return Err(ForkStoreError::ExternalAnchorMismatch);
    }

    // The provider has signed the exact successor. Only now publish the manifest it names.
    write_manifest_atomic(&directory.join(MANIFEST_NAME), &pending.manifest)?;
    remove_pending_external_cas_commit(directory)?;
    Ok(PendingRecoveryOutcome::Committed(
        observed,
        object_generation,
    ))
}

fn encode_manifest(
    network_id: &[u8; 32],
    profile_fingerprint: &[u8; 32],
    genesis_tip: &[u8; 32],
    canonical_tip: &[u8; 32],
    digests: &[[u8; 32]],
) -> Result<Vec<u8>, ForkStoreError> {
    if digests.len() > MAX_FORK_ARCHIVE_BLOCKS {
        return Err(ForkStoreError::ManifestTooLarge);
    }
    let mut sorted = digests.to_vec();
    sorted.sort_unstable();
    if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ForkStoreError::DuplicateManifestDigest);
    }
    if *canonical_tip != *genesis_tip && sorted.binary_search(canonical_tip).is_err() {
        return Err(ForkStoreError::CanonicalTipMismatch);
    }

    let mut bytes = Vec::with_capacity(MANIFEST_FIXED_PREFIX + sorted.len() * 32 + 32);
    bytes.extend_from_slice(MANIFEST_MAGIC);
    bytes.extend_from_slice(&MANIFEST_VERSION.to_be_bytes());
    bytes.extend_from_slice(network_id);
    bytes.extend_from_slice(profile_fingerprint);
    bytes.extend_from_slice(genesis_tip);
    bytes.extend_from_slice(canonical_tip);
    bytes.extend_from_slice(&(sorted.len() as u32).to_be_bytes());
    for digest in sorted {
        bytes.extend_from_slice(&digest);
    }
    let checksum: [u8; 32] = Sha256::digest(&bytes).into();
    bytes.extend_from_slice(&checksum);
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(ForkStoreError::ManifestTooLarge);
    }
    Ok(bytes)
}

fn decode_manifest(bytes: &[u8]) -> Result<ParsedManifest, ForkStoreError> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(ForkStoreError::ManifestTooLarge);
    }
    if bytes.len() < MANIFEST_FIXED_PREFIX + MANIFEST_CHECKSUM_BYTES
        || &bytes[..4] != MANIFEST_MAGIC
        || u16::from_be_bytes([bytes[4], bytes[5]]) != MANIFEST_VERSION
    {
        return Err(ForkStoreError::ManifestMalformed);
    }
    let count = u32::from_be_bytes(bytes[134..138].try_into().unwrap()) as usize;
    if count > MAX_FORK_ARCHIVE_BLOCKS
        || bytes.len() != MANIFEST_FIXED_PREFIX + count * 32 + MANIFEST_CHECKSUM_BYTES
    {
        return Err(ForkStoreError::ManifestMalformed);
    }
    let checksum_offset = bytes.len() - MANIFEST_CHECKSUM_BYTES;
    let expected: [u8; 32] = Sha256::digest(&bytes[..checksum_offset]).into();
    if bytes[checksum_offset..] != expected {
        return Err(ForkStoreError::ManifestChecksumMismatch);
    }
    let network_id = bytes[6..38].try_into().unwrap();
    let profile_fingerprint = bytes[38..70].try_into().unwrap();
    let genesis_tip = bytes[70..102].try_into().unwrap();
    let canonical_tip = bytes[102..134].try_into().unwrap();
    let mut digests = Vec::with_capacity(count);
    let mut offset = MANIFEST_FIXED_PREFIX;
    for _ in 0..count {
        let digest: [u8; 32] = bytes[offset..offset + 32].try_into().unwrap();
        digests.push(digest);
        offset += 32;
    }
    if digests.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(ForkStoreError::DuplicateManifestDigest);
    }
    if canonical_tip != genesis_tip && digests.binary_search(&canonical_tip).is_err() {
        return Err(ForkStoreError::CanonicalTipMismatch);
    }
    Ok(ParsedManifest {
        network_id,
        profile_fingerprint,
        genesis_tip,
        canonical_tip,
        digests,
    })
}

fn branch_file_name(digest: &[u8; 32]) -> String {
    format!("{BRANCH_PREFIX}{}{BRANCH_SUFFIX}", encode_hex(digest))
}

fn parse_branch_file_name(name: &str) -> Result<[u8; 32], ForkStoreError> {
    let hex = name
        .strip_prefix(BRANCH_PREFIX)
        .and_then(|s| s.strip_suffix(BRANCH_SUFFIX))
        .ok_or(ForkStoreError::UnexpectedBranchFileName)?;
    if hex.len() != 64 {
        return Err(ForkStoreError::UnexpectedBranchFileName);
    }
    let mut digest = [0u8; 32];
    for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        let pair =
            std::str::from_utf8(pair).map_err(|_| ForkStoreError::UnexpectedBranchFileName)?;
        digest[index] =
            u8::from_str_radix(pair, 16).map_err(|_| ForkStoreError::UnexpectedBranchFileName)?;
    }
    if branch_file_name(&digest) != name {
        return Err(ForkStoreError::UnexpectedBranchFileName);
    }
    Ok(digest)
}

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

fn unique_temp_path(parent: &Path, final_name: &std::ffi::OsStr) -> PathBuf {
    let sequence = NEXT_TEMP_ID.fetch_add(1, AtomicOrdering::Relaxed);
    let mut name = OsString::from(".");
    name.push(final_name);
    name.push(format!("{TEMP_MARKER}{}.{}", process::id(), sequence));
    parent.join(name)
}

fn write_synced_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    // The manifest is the commit record, so a partially written destination is never trusted
    // before publication. create_new prevents replacing a prior candidate file.
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    let write_result = file
        .write_all(bytes)
        .and_then(|_| file.flush())
        .and_then(|_| file.sync_all());
    drop(file);
    if let Err(error) = write_result {
        let _ = fs::remove_file(path);
        let _ = sync_parent(parent);
        return Err(error);
    }
    // A directory-sync failure leaves an unreferenced file. It is ignored and cleaned on restart
    // unless/until a validated PFS2 manifest references its digest.
    sync_parent(parent)
}

fn write_branch_create_new(path: &Path, bytes: &[u8]) -> Result<(), ForkStoreError> {
    if bytes.len() > MAX_CANDIDATE_NETWORK_ENVELOPE_BYTES {
        return Err(ForkStoreError::BranchFileTooLarge);
    }
    match write_synced_new(path, bytes) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let existing =
                read_bounded_file(path, MAX_CANDIDATE_NETWORK_ENVELOPE_BYTES).map_err(|error| {
                    match error {
                        BoundedReadError::Io(error) => ForkStoreError::Io(error),
                        BoundedReadError::TooLarge => ForkStoreError::BranchFileTooLarge,
                    }
                })?;
            if existing == bytes {
                Ok(())
            } else {
                Err(ForkStoreError::BranchFilenameDigestMismatch)
            }
        }
        Err(error) => Err(ForkStoreError::Io(error)),
    }
}

fn write_manifest_atomic(path: &Path, bytes: &[u8]) -> Result<(), ForkStoreError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let final_name = path.file_name().ok_or(ForkStoreError::ManifestMalformed)?;
    let temp = unique_temp_path(parent, final_name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)?;
    let write_result = file
        .write_all(bytes)
        .and_then(|_| file.flush())
        .and_then(|_| file.sync_all());
    if let Err(error) = write_result {
        drop(file);
        let _ = fs::remove_file(&temp);
        return Err(ForkStoreError::Io(error));
    }
    drop(file);
    let replace_result = atomic_replace(&temp, path);
    if replace_result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    replace_result.map_err(ForkStoreError::Io)?;
    sync_parent(parent).map_err(ForkStoreError::Io)
}

fn cleanup_orphan_branch_files(
    directory: &Path,
    known_digests: &BTreeSet<[u8; 32]>,
) -> Result<(), ForkStoreError> {
    let mut seen = 0usize;
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if !file_type.is_file() {
            // We own one lock file and manifest; unexpected subdirectories are refused.
            let name = entry.file_name();
            if name != LOCK_NAME && name != MANIFEST_NAME {
                return Err(ForkStoreError::UnexpectedStoreEntry);
            }
            continue;
        }
        let name = entry.file_name();
        let name = name.to_str().ok_or(ForkStoreError::UnexpectedStoreEntry)?;
        if name == LOCK_NAME || name == MANIFEST_NAME {
            continue;
        }
        if name.starts_with(BRANCH_PREFIX) && name.ends_with(BRANCH_SUFFIX) {
            seen += 1;
            if seen > MAX_FORK_ARCHIVE_BLOCKS + 256 {
                return Err(ForkStoreError::ManifestTooLarge);
            }
            let digest = parse_branch_file_name(name)?;
            if !known_digests.contains(&digest) {
                // Manifest publication is the commit point; unreferenced files are orphans.
                fs::remove_file(entry.path())?;
            }
        } else {
            return Err(ForkStoreError::UnexpectedStoreEntry);
        }
    }
    sync_parent(directory)?;
    Ok(())
}

#[cfg(windows)]
fn atomic_replace(source: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;
    let from: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let to: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    #[link(name = "Kernel32")]
    extern "system" {
        fn MoveFileExW(existing: *const u16, new_name: *const u16, flags: u32) -> i32;
    }
    let success = unsafe {
        MoveFileExW(
            from.as_ptr(),
            to.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if success == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn atomic_replace(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)?;
    sync_parent(destination.parent().unwrap_or_else(|| Path::new(".")))
}

#[cfg(windows)]
fn sync_parent(_directory: &Path) -> io::Result<()> {
    // MOVEFILE_WRITE_THROUGH provides the platform-specific durability request for rename.
    Ok(())
}

#[cfg(unix)]
fn sync_parent(directory: &Path) -> io::Result<()> {
    File::open(directory)?.sync_all()
}

#[cfg(not(any(windows, unix)))]
fn sync_parent(_directory: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        asert_anchor_policy_candidate::{
            median_time_past, select_asert_anchor, validate_candidate_mtp, HeaderTimeSample,
        },
        chain_admission::{ReferenceTimeProvenance, ReferenceTimeSample},
        consensus::{pow_digest, ConsensusParameters, PowHeader, Uint256},
        difficulty_adjustment_candidates::target_to_compact_bits,
        private_testnet_wire::{decode_candidate_network_block, encode_candidate_network_block},
        state_machine::{AccountId, Block, TransactionAuthenticator},
    };
    use crate::{
        external_cas_anchor_candidate::{
            ExternalCasReadRequest, ExternalCasReceipt, ExternalCasReceiptKind,
            ExternalCasReceiptOutcome,
        },
        v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate,
        v4_fat1_trust_candidate::ML_DSA_65_SIGNATURE_BYTES,
    };
    use libcrux_ml_dsa::ml_dsa_65::portable;
    use std::{
        collections::BTreeMap,
        process::Command,
        sync::{
            atomic::{AtomicU64, Ordering},
            Arc, Mutex,
        },
    };

    static TEST_ID: AtomicU64 = AtomicU64::new(1);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "ain1_cp0074_forkstore_{}_{}",
                process::id(),
                TEST_ID.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct EmptyAuthenticator;

    impl TransactionAuthenticator for EmptyAuthenticator {
        fn verify(&self, _: &AccountId, _: &[u8; 32], _: &[u8]) -> Result<(), ()> {
            Err(())
        }
    }

    struct FixedClock;

    impl ReferenceTimeProvider for FixedClock {
        fn sample(
            &self,
        ) -> Result<ReferenceTimeSample, crate::chain_admission::ReferenceTimeError> {
            Ok(ReferenceTimeSample {
                unix_seconds: 1_000_000,
                provenance: ReferenceTimeProvenance::ConfiguredProvider,
                source_id: "fork-store-test-clock",
            })
        }
    }

    struct MemoryCasState {
        record: ExternalCasRecord,
        object_generation: u64,
        lose_next_commit_response: bool,
        reject_next_commit_before_apply: bool,
    }

    struct MemoryCasProvider<F> {
        pin: ExternalCasPin,
        state: Arc<Mutex<MemoryCasState>>,
        sign: F,
    }

    fn sign_cas_receipt<F: Fn(ExternalCasReceipt) -> ExternalCasReceipt>(
        sign: &F,
        pin: &ExternalCasPin,
        record: &ExternalCasRecord,
        kind: ExternalCasReceiptKind,
        outcome: ExternalCasReceiptOutcome,
        object_generation: u64,
        nonce: [u8; 32],
        operation_id: [u8; 32],
        request_digest: [u8; 32],
    ) -> ExternalCasReceipt {
        sign(ExternalCasReceipt {
            kind,
            outcome,
            generation: record.generation,
            object_generation,
            provider_id: pin.provider_id,
            network_id: pin.network_id,
            genesis_digest: pin.genesis_digest,
            receipt_key_id: pin.receipt_key_id,
            request_nonce: nonce,
            record_digest: record.digest().unwrap(),
            previous_record_digest: record.previous_record_digest,
            previous_state_digest: record.previous_state_digest,
            state_digest: record.next_state_digest,
            operation_id,
            request_digest,
            signature: [0; ML_DSA_65_SIGNATURE_BYTES],
        })
    }

    impl<F> ExternalCasProviderTransport for MemoryCasProvider<F>
    where
        F: Fn(ExternalCasReceipt) -> ExternalCasReceipt,
    {
        type Error = String;

        fn read_current(
            &mut self,
            request: &ExternalCasReadRequest,
        ) -> Result<(ExternalCasRecord, ExternalCasReceipt), Self::Error> {
            let state = self
                .state
                .lock()
                .map_err(|_| "CAS test lock poisoned".to_string())?;
            let record = state.record.clone();
            let receipt = sign_cas_receipt(
                &self.sign,
                &self.pin,
                &record,
                ExternalCasReceiptKind::Read,
                ExternalCasReceiptOutcome::Observed,
                state.object_generation,
                request.request_nonce,
                request.operation_id,
                request.request_digest,
            );
            Ok((record, receipt))
        }

        fn compare_and_swap(
            &mut self,
            request: &ExternalCasWriteRequest,
        ) -> Result<ExternalCasReceipt, Self::Error> {
            request
                .validate(&self.pin)
                .map_err(|error| error.to_string())?;
            let (record, object_generation, outcome, lose_response) = {
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| "CAS test lock poisoned".to_string())?;
                if state.reject_next_commit_before_apply {
                    state.reject_next_commit_before_apply = false;
                    return Err("simulated CAS rejection before external commit".to_string());
                }
                let already_applied = state.record.digest().map_err(|error| error.to_string())?
                    == request
                        .next_record
                        .digest()
                        .map_err(|error| error.to_string())?
                    && state.record.operation_id == request.operation_id
                    && state.record.request_digest == request.request_digest;
                let can_apply = state.record.generation == request.expected_generation
                    && state.object_generation == request.expected_object_generation
                    && state.record.digest().map_err(|error| error.to_string())?
                        == request.expected_record_digest
                    && state.record.next_state_digest == request.expected_state_digest;
                let outcome = if already_applied {
                    ExternalCasReceiptOutcome::AlreadyApplied
                } else if can_apply {
                    state.record = request.next_record.clone();
                    state.object_generation = state
                        .object_generation
                        .checked_add(1)
                        .ok_or_else(|| "CAS object generation overflow".to_string())?;
                    ExternalCasReceiptOutcome::Applied
                } else {
                    ExternalCasReceiptOutcome::Conflict
                };
                let lose_response = state.lose_next_commit_response
                    && matches!(outcome, ExternalCasReceiptOutcome::Applied);
                if lose_response {
                    state.lose_next_commit_response = false;
                }
                (
                    state.record.clone(),
                    state.object_generation,
                    outcome,
                    lose_response,
                )
            };
            if lose_response {
                // Model a provider that commits atomically but loses the response in transit.
                return Err("simulated lost response after CAS commit".to_string());
            }
            Ok(sign_cas_receipt(
                &self.sign,
                &self.pin,
                &record,
                ExternalCasReceiptKind::Commit,
                outcome,
                object_generation,
                request.request_nonce,
                request.operation_id,
                request.request_digest,
            ))
        }
    }

    fn make_memory_cas_provider<F>(
        pin: ExternalCasPin,
        state: Arc<Mutex<MemoryCasState>>,
        sign: F,
    ) -> MemoryCasProvider<F>
    where
        F: Fn(ExternalCasReceipt) -> ExternalCasReceipt,
    {
        MemoryCasProvider { pin, state, sign }
    }

    fn params() -> ConsensusParameters {
        let mut params = ConsensusParameters::candidate_testnet().unwrap();
        params.initial_target = Uint256::MAX;
        params.pow_limit = Uint256::MAX;
        // This store test uses disposable, non-mainnet parameters to keep repeated replay cheap.
        params.pow.memory_kib = 8 * 1024;
        params.pow.iterations = 1;
        params
    }

    fn genesis() -> LedgerState {
        LedgerState::genesis([0xD8; 32], vec![([1; 32], 10_000)]).unwrap()
    }

    fn envelope(
        chain: &crate::private_testnet_driver::PrivateTestnetChain,
        params: &ConsensusParameters,
        timestamp: u64,
        nonce: u64,
    ) -> (Vec<u8>, [u8; 32]) {
        let mut block = Block {
            height: chain.state().height() + 1,
            timestamp,
            parent_hash: chain.state().tip_hash(),
            state_root: [0; 32],
            transactions: Vec::new(),
        };
        block.state_root = chain
            .state()
            .preview_state_root_after(&block, &EmptyAuthenticator)
            .unwrap();
        let header = PowHeader {
            protocol_version: params.protocol_version,
            network_id: chain.state().network_id(),
            height: block.height,
            timestamp: block.timestamp,
            parent_hash: block.parent_hash,
            previous_consensus_hash: chain.chain_tip().tip_hash,
            state_root: block.state_root,
            target: chain.expected_target(None).unwrap(),
            nonce,
        };
        let digest = pow_digest(&header, params.pow).unwrap();
        (
            encode_candidate_network_block(&header, &block).unwrap(),
            digest,
        )
    }

    fn child_envelope(
        parent: &crate::private_testnet_driver::PrivateTestnetChain,
        params: &ConsensusParameters,
        timestamp: u64,
        nonce: u64,
    ) -> (Vec<u8>, [u8; 32]) {
        envelope(parent, params, timestamp, nonce)
    }

    fn qrun_fee_envelope_from_chain(
        chain: &crate::private_testnet_driver::PrivateTestnetChain,
        params: &ConsensusParameters,
        producer: [u8; 32],
        timestamp: u64,
    ) -> Vec<u8> {
        let mut fee_block = crate::state_machine::QRunV05FeeBlock {
            body: Block {
                height: chain.state().height() + 1,
                timestamp,
                parent_hash: chain.state().tip_hash(),
                state_root: [0; 32],
                transactions: Vec::new(),
            },
            producer,
        };
        fee_block.body.state_root = chain
            .state()
            .preview_qrun_v05_fee_state_root_after(&fee_block, &EmptyAuthenticator)
            .unwrap();
        let header = PowHeader {
            protocol_version: params.protocol_version,
            network_id: chain.state().network_id(),
            height: fee_block.body.height,
            timestamp: fee_block.body.timestamp,
            parent_hash: fee_block.body.parent_hash,
            previous_consensus_hash: chain.chain_tip().tip_hash,
            state_root: crate::qrun_v05_fee_pow_wire_candidate::qrun_v05_fee_pow_state_commitment(
                &fee_block,
            )
            .unwrap(),
            target: chain.expected_target(None).unwrap(),
            nonce: 0,
        };
        crate::qrun_v05_fee_pow_wire_candidate::encode_qrun_v05_fee_pow_block(&header, &fee_block)
            .unwrap()
    }

    fn qrun_fee_envelope(genesis: &LedgerState, params: &ConsensusParameters) -> Vec<u8> {
        let chain = crate::private_testnet_driver::PrivateTestnetChain::new(
            genesis.clone(),
            params.clone(),
        )
        .unwrap();
        let mut fee_block = crate::state_machine::QRunV05FeeBlock {
            body: Block {
                height: 1,
                timestamp: 100,
                parent_hash: genesis.tip_hash(),
                state_root: [0; 32],
                transactions: Vec::new(),
            },
            producer: [0x77; 32],
        };
        fee_block.body.state_root = genesis
            .preview_qrun_v05_fee_state_root_after(&fee_block, &EmptyAuthenticator)
            .unwrap();
        let header = PowHeader {
            protocol_version: params.protocol_version,
            network_id: genesis.network_id(),
            height: 1,
            timestamp: 100,
            parent_hash: genesis.tip_hash(),
            previous_consensus_hash: chain.chain_tip().tip_hash,
            state_root: crate::qrun_v05_fee_pow_wire_candidate::qrun_v05_fee_pow_state_commitment(
                &fee_block,
            )
            .unwrap(),
            target: params.initial_target,
            nonce: 0,
        };
        crate::qrun_v05_fee_pow_wire_candidate::encode_qrun_v05_fee_pow_block(&header, &fee_block)
            .unwrap()
    }

    #[test]
    fn qrun_checkpoint_pfs2_reopens_only_from_exact_external_commitment_and_replays_qfp5_suffix() {
        let dir = TestDir::new();
        let genesis_candidate =
            crate::qrun_v05_profile_identity_candidate::build_candidate_genesis().unwrap();
        let genesis = genesis_candidate.ledger().clone();
        let mut params = params();
        params.protocol_version = 5;
        params.target_block_time_secs = 1;
        params.initial_target = Uint256::MAX;
        params.pow_limit = Uint256::MAX;

        let first = qrun_fee_envelope(&genesis, &params);
        let mut genesis_archive =
            PrivateTestnetForkChoice::new_qrun_v05_fee_only(genesis.clone(), params.clone())
                .unwrap();
        genesis_archive
            .insert_encoded(&first, &EmptyAuthenticator, &FixedClock)
            .unwrap();
        let checkpoint_chain = genesis_archive.canonical_chain().clone();
        assert_eq!(checkpoint_chain.state().height(), 1);
        assert_eq!(
            checkpoint_chain.state().total_value().unwrap(),
            crate::state_machine::MAX_TOTAL_SUPPLY_ATOMS
        );

        let checkpoint = crate::qrun_v05_checkpoint_candidate::QRunV05PowCheckpoint::capture(
            genesis.network_id(),
            crate::qrun_v05_profile_identity_candidate::PROPOSED_GENESIS_COMMITMENT,
            &params,
            &checkpoint_chain,
            [0xC7; 32],
        )
        .unwrap();
        let checkpoint_bytes = checkpoint.encode(&params).unwrap();
        let checkpoint_commitment = checkpoint.commitment(&params).unwrap();
        assert_ne!(checkpoint_commitment, [0; 32]);

        let restored_chain =
            crate::qrun_v05_checkpoint_candidate::QRunV05PowCheckpoint::restore_chain_anchored(
                &checkpoint_bytes,
                &genesis.network_id(),
                &crate::qrun_v05_profile_identity_candidate::PROPOSED_GENESIS_COMMITMENT,
                &params,
                checkpoint_commitment,
                1,
            )
            .unwrap();
        assert_eq!(restored_chain.state(), checkpoint_chain.state());
        assert!(!restored_chain.uses_qrun_v05_fee_only_execution());

        let mut store = PrivateTestnetForkStore::open_qrun_v05_fee_only_from_checkpoint(
            &dir.0,
            genesis.clone(),
            params.clone(),
            &EmptyAuthenticator,
            &FixedClock,
            &checkpoint_bytes,
            checkpoint_commitment,
            1,
            None,
        )
        .unwrap();
        assert_eq!(store.canonical_height(), 1);
        let next = qrun_fee_envelope_from_chain(
            store.archive().canonical_chain(),
            &params,
            [0x78; 32],
            101,
        );
        store
            .submit(&next, &EmptyAuthenticator, &FixedClock)
            .unwrap();
        assert_eq!(store.canonical_height(), 2);
        assert_eq!(
            store
                .archive()
                .canonical_chain()
                .state()
                .total_value()
                .unwrap(),
            crate::state_machine::MAX_TOTAL_SUPPLY_ATOMS
        );
        let anchor = store.manifest_anchor().unwrap();
        drop(store);

        let reopened = PrivateTestnetForkStore::open_qrun_v05_fee_only_from_checkpoint(
            &dir.0,
            genesis.clone(),
            params.clone(),
            &EmptyAuthenticator,
            &FixedClock,
            &checkpoint_bytes,
            checkpoint_commitment,
            1,
            Some(anchor),
        )
        .unwrap();
        assert_eq!(reopened.canonical_height(), 2);
        assert_eq!(
            reopened
                .archive()
                .canonical_chain()
                .state()
                .total_value()
                .unwrap(),
            crate::state_machine::MAX_TOTAL_SUPPLY_ATOMS
        );
        assert_eq!(
            reopened
                .archive()
                .canonical_chain()
                .state()
                .account(&crate::qrun_v05_profile_identity_candidate::PROPOSED_OWNER_ACCOUNT_ID)
                .unwrap()
                .balance,
            crate::state_machine::MAX_TOTAL_SUPPLY_ATOMS as u64
        );

        let mut wrong_commitment = checkpoint_commitment;
        wrong_commitment[0] ^= 1;
        let wrong_dir = TestDir::new();
        assert!(matches!(
            PrivateTestnetForkStore::open_qrun_v05_fee_only_from_checkpoint(
                &wrong_dir.0,
                genesis.clone(),
                params.clone(),
                &EmptyAuthenticator,
                &FixedClock,
                &checkpoint_bytes,
                wrong_commitment,
                1,
                None,
            ),
            Err(ForkStoreError::ManifestAnchorMismatch)
        ));

        drop(reopened);
        assert!(matches!(
            PrivateTestnetForkStore::open(
                &dir.0,
                genesis,
                params,
                &EmptyAuthenticator,
                &FixedClock,
            ),
            Err(ForkStoreError::ManifestProfileMismatch)
        ));
    }

    #[test]
    fn exact_ten_billion_candidate_genesis_persists_through_qfp5_store_restart() {
        let dir = TestDir::new();
        let mut params = params();
        params.protocol_version = 5;
        params.pow.memory_kib = 8;
        let genesis_candidate =
            crate::qrun_v05_profile_identity_candidate::build_candidate_genesis().unwrap();
        assert_eq!(
            genesis_candidate.commitment(),
            crate::qrun_v05_profile_identity_candidate::PROPOSED_GENESIS_COMMITMENT
        );
        let genesis = genesis_candidate.ledger().clone();
        assert_eq!(genesis.state_root(), genesis_candidate.state_root());
        assert_eq!(
            genesis.total_value().unwrap(),
            crate::state_machine::MAX_TOTAL_SUPPLY_ATOMS
        );
        assert_eq!(
            genesis
                .account(&crate::qrun_v05_profile_identity_candidate::PROPOSED_OWNER_ACCOUNT_ID)
                .unwrap()
                .balance,
            crate::state_machine::MAX_TOTAL_SUPPLY_ATOMS as u64
        );

        let mut store = PrivateTestnetForkStore::open_qrun_v05_fee_only(
            &dir.0,
            genesis.clone(),
            params.clone(),
            &EmptyAuthenticator,
            &FixedClock,
        )
        .unwrap();
        let chain = store.archive().canonical_chain();
        assert_eq!(
            chain.state().network_id(),
            crate::qrun_v05_profile_identity_candidate::PROPOSED_QRUN_V05_NETWORK_ID
        );
        let mut fee_block = crate::state_machine::QRunV05FeeBlock {
            body: Block {
                height: 1,
                timestamp: 100,
                parent_hash: chain.state().tip_hash(),
                state_root: [0; 32],
                transactions: Vec::new(),
            },
            producer: [0x77; 32],
        };
        fee_block.body.state_root = chain
            .state()
            .preview_qrun_v05_fee_state_root_after(&fee_block, &EmptyAuthenticator)
            .unwrap();
        let header = PowHeader {
            protocol_version: params.protocol_version,
            network_id: chain.state().network_id(),
            height: 1,
            timestamp: 100,
            parent_hash: fee_block.body.parent_hash,
            previous_consensus_hash: chain.chain_tip().tip_hash,
            state_root: crate::qrun_v05_fee_pow_wire_candidate::qrun_v05_fee_pow_state_commitment(
                &fee_block,
            )
            .unwrap(),
            target: chain.expected_target(None).unwrap(),
            nonce: 0,
        };
        let envelope = crate::qrun_v05_fee_pow_wire_candidate::encode_qrun_v05_fee_pow_block(
            &header, &fee_block,
        )
        .unwrap();
        store
            .submit(&envelope, &EmptyAuthenticator, &FixedClock)
            .unwrap();
        assert_eq!(store.canonical_height(), 1);
        assert_eq!(
            store
                .archive()
                .canonical_chain()
                .state()
                .total_value()
                .unwrap(),
            crate::state_machine::MAX_TOTAL_SUPPLY_ATOMS
        );
        assert_eq!(
            store
                .archive()
                .canonical_chain()
                .state()
                .account(&crate::qrun_v05_profile_identity_candidate::PROPOSED_OWNER_ACCOUNT_ID)
                .unwrap()
                .balance,
            crate::state_machine::MAX_TOTAL_SUPPLY_ATOMS as u64
        );
        let anchor = store.manifest_anchor().unwrap();
        drop(store);

        let reopened = PrivateTestnetForkStore::open_qrun_v05_fee_only_anchored(
            &dir.0,
            genesis,
            params,
            &EmptyAuthenticator,
            &FixedClock,
            anchor,
        )
        .unwrap();
        assert_eq!(reopened.canonical_height(), 1);
        assert_eq!(
            reopened
                .archive()
                .canonical_chain()
                .state()
                .total_value()
                .unwrap(),
            crate::state_machine::MAX_TOTAL_SUPPLY_ATOMS
        );
        assert_eq!(
            reopened
                .archive()
                .canonical_chain()
                .state()
                .account(&crate::qrun_v05_profile_identity_candidate::PROPOSED_OWNER_ACCOUNT_ID)
                .unwrap()
                .balance,
            crate::state_machine::MAX_TOTAL_SUPPLY_ATOMS as u64
        );
    }

    #[test]
    fn qrun_external_cas_open_recovers_crash_after_remote_commit_before_local_manifest() {
        let dir = TestDir::new();
        let genesis = crate::qrun_v05_profile_identity_candidate::build_candidate_genesis()
            .unwrap()
            .ledger()
            .clone();
        let mut params = params();
        params.protocol_version = 5;
        params.initial_target = Uint256::MAX;
        params.pow_limit = Uint256::MAX;
        params.pow.memory_kib = 8;
        params.pow.iterations = 1;
        params.pow.lanes = 1;

        let initial_anchor = {
            let local = PrivateTestnetForkStore::open_qrun_v05_fee_only(
                &dir.0,
                genesis.clone(),
                params.clone(),
                &EmptyAuthenticator,
                &FixedClock,
            )
            .unwrap();
            local.manifest_anchor().unwrap()
        };

        let keypair = portable::generate_key_pair([0x5Bu8; 32]);
        let signing_key = Arc::new(keypair.signing_key);
        let public_key: [u8; crate::v4_fat1_trust_candidate::ML_DSA_65_PUBLIC_KEY_BYTES] =
            *keypair.verification_key.as_ref();
        let pin = ExternalCasPin {
            provider_id: [0xA1; 32],
            network_id: genesis.network_id(),
            genesis_digest: crate::qrun_v05_profile_identity_candidate::PROPOSED_GENESIS_COMMITMENT,
            receipt_key_id: [0xA2; 32],
            receipt_public_key: public_key,
        };
        let previous_record = ExternalCasRecord {
            generation: 0,
            provider_id: pin.provider_id,
            network_id: pin.network_id,
            genesis_digest: pin.genesis_digest,
            previous_record_digest: [0; 32],
            previous_state_digest: [0; 32],
            next_state_digest: initial_anchor,
            operation_id: [0xA3; 32],
            request_digest: [0xA4; 32],
        };

        // Simulate the state after the external provider committed but before the local manifest
        // was replaced: the new QFP5 branch and QAP1 pending record are durable, manifest is old.
        let envelope = qrun_fee_envelope(&genesis, &params);
        let mut candidate_archive =
            PrivateTestnetForkChoice::new_qrun_v05_fee_only(genesis.clone(), params.clone())
                .unwrap();
        let outcome = candidate_archive
            .insert_encoded(&envelope, &EmptyAuthenticator, &FixedClock)
            .unwrap();
        write_branch_create_new(
            &dir.0.join(branch_file_name(&outcome.block_digest)),
            &envelope,
        )
        .unwrap();
        let mut digests: Vec<[u8; 32]> = candidate_archive
            .archive_envelopes()
            .iter()
            .map(|bytes| {
                let decoded = decode_candidate_network_block(bytes).unwrap();
                pow_digest(&decoded.header, params.pow).unwrap()
            })
            .collect();
        digests.sort_unstable();
        let canonical_tip = candidate_archive.canonical_chain().chain_tip().tip_hash;
        let manifest = encode_manifest(
            &genesis.network_id(),
            &qrun_v05_fee_profile_fingerprint(&genesis, &params).unwrap(),
            &candidate_archive.genesis_tip(),
            &canonical_tip,
            &digests,
        )
        .unwrap();
        let next_state_digest = manifest_anchor_commitment(&manifest);
        let operation_id = [0xA5; 32];
        let mut write_request = ExternalCasWriteRequest {
            request_nonce: [0xA6; 32],
            operation_id,
            request_digest: [1; 32],
            expected_generation: previous_record.generation,
            expected_object_generation: 1,
            expected_record_digest: previous_record.digest().unwrap(),
            expected_state_digest: previous_record.next_state_digest,
            next_record: ExternalCasRecord {
                generation: 1,
                provider_id: pin.provider_id,
                network_id: pin.network_id,
                genesis_digest: pin.genesis_digest,
                previous_record_digest: previous_record.digest().unwrap(),
                previous_state_digest: previous_record.next_state_digest,
                next_state_digest,
                operation_id,
                request_digest: [1; 32],
            },
        };
        write_request.bind_request_digest(&pin).unwrap();
        let next_record = write_request.next_record.clone();
        write_pending_external_cas_commit(
            &dir.0,
            &PendingExternalCasCommit {
                previous_record: previous_record.clone(),
                next_record: next_record.clone(),
                manifest: manifest.clone(),
            },
        )
        .unwrap();
        assert_eq!(
            manifest_anchor_commitment(
                &read_bounded_file(&dir.0.join(MANIFEST_NAME), MAX_MANIFEST_BYTES).unwrap()
            ),
            previous_record.next_state_digest
        );

        let shared = Arc::new(Mutex::new(MemoryCasState {
            record: next_record.clone(),
            object_generation: 2,
            lose_next_commit_response: false,
            reject_next_commit_before_apply: false,
        }));
        let sign_key = signing_key.clone();
        let provider = make_memory_cas_provider(pin.clone(), shared.clone(), move |mut receipt| {
            let digest = receipt.signing_digest().unwrap();
            receipt.signature = *portable::sign(&sign_key, &digest, &[], [0x73u8; 32])
                .unwrap()
                .as_ref();
            receipt
        });
        let client =
            VerifiedExternalCasClient::new(pin.clone(), provider, LibcruxMlDsa65VerifierCandidate)
                .unwrap();
        let reopened = QRunV05ExternalCasForkStore::open(
            &dir.0,
            genesis,
            params,
            &EmptyAuthenticator,
            &FixedClock,
            pin,
            client,
            previous_record,
            1,
        )
        .unwrap();

        assert_eq!(reopened.canonical_height(), 1);
        assert_eq!(
            reopened.canonical_state().total_value().unwrap(),
            crate::state_machine::MAX_TOTAL_SUPPLY_ATOMS
        );
        assert_eq!(reopened.trusted_record(), &next_record);
        assert!(!dir.0.join(QRUN_PENDING_NAME).exists());
        assert_eq!(
            manifest_anchor_commitment(
                &read_bounded_file(&dir.0.join(MANIFEST_NAME), MAX_MANIFEST_BYTES).unwrap()
            ),
            next_state_digest
        );
    }

    #[test]
    fn qrun_external_cas_rejection_keeps_old_manifest_and_removes_pending() {
        let dir = TestDir::new();
        let genesis = crate::qrun_v05_profile_identity_candidate::build_candidate_genesis()
            .unwrap()
            .ledger()
            .clone();
        let mut params = params();
        params.protocol_version = 5;
        params.initial_target = Uint256::MAX;
        params.pow_limit = Uint256::MAX;
        params.pow.memory_kib = 8;
        params.pow.iterations = 1;
        params.pow.lanes = 1;
        let initial_anchor = {
            let local = PrivateTestnetForkStore::open_qrun_v05_fee_only(
                &dir.0,
                genesis.clone(),
                params.clone(),
                &EmptyAuthenticator,
                &FixedClock,
            )
            .unwrap();
            local.manifest_anchor().unwrap()
        };

        let keypair = portable::generate_key_pair([0x5Cu8; 32]);
        let signing_key = Arc::new(keypair.signing_key);
        let public_key: [u8; crate::v4_fat1_trust_candidate::ML_DSA_65_PUBLIC_KEY_BYTES] =
            *keypair.verification_key.as_ref();
        let pin = ExternalCasPin {
            provider_id: [0xB1; 32],
            network_id: genesis.network_id(),
            genesis_digest: crate::qrun_v05_profile_identity_candidate::PROPOSED_GENESIS_COMMITMENT,
            receipt_key_id: [0xB2; 32],
            receipt_public_key: public_key,
        };
        let bootstrap = ExternalCasRecord {
            generation: 0,
            provider_id: pin.provider_id,
            network_id: pin.network_id,
            genesis_digest: pin.genesis_digest,
            previous_record_digest: [0; 32],
            previous_state_digest: [0; 32],
            next_state_digest: initial_anchor,
            operation_id: [0xB3; 32],
            request_digest: [0xB4; 32],
        };
        let shared = Arc::new(Mutex::new(MemoryCasState {
            record: bootstrap.clone(),
            object_generation: 1,
            lose_next_commit_response: false,
            reject_next_commit_before_apply: true,
        }));
        let sign_key = signing_key.clone();
        let provider = make_memory_cas_provider(pin.clone(), shared.clone(), move |mut receipt| {
            let digest = receipt.signing_digest().unwrap();
            receipt.signature = *portable::sign(&sign_key, &digest, &[], [0x73u8; 32])
                .unwrap()
                .as_ref();
            receipt
        });
        let client =
            VerifiedExternalCasClient::new(pin.clone(), provider, LibcruxMlDsa65VerifierCandidate)
                .unwrap();
        let mut store = QRunV05ExternalCasForkStore::open(
            &dir.0,
            genesis.clone(),
            params.clone(),
            &EmptyAuthenticator,
            &FixedClock,
            pin,
            client,
            bootstrap.clone(),
            1,
        )
        .unwrap();

        assert!(matches!(
            store.submit(
                &qrun_fee_envelope(&genesis, &params),
                &EmptyAuthenticator,
                &FixedClock
            ),
            Err(ForkStoreError::ExternalCasClient(
                ExternalCasClientError::Provider(_)
            ))
        ));
        assert_eq!(store.canonical_height(), 0);
        assert_eq!(store.manifest_anchor().unwrap(), initial_anchor);
        assert_eq!(store.trusted_record(), &bootstrap);
        assert_eq!(store.minimum_object_generation(), 1);
        assert!(!dir.0.join(QRUN_PENDING_NAME).exists());
        let remote = shared.lock().unwrap();
        assert_eq!(remote.record, bootstrap);
        assert_eq!(remote.object_generation, 1);
    }

    #[test]
    fn qrun_external_cas_store_resolves_lost_receipt_and_reopens_on_signed_anchor() {
        let dir = TestDir::new();
        let genesis = crate::qrun_v05_profile_identity_candidate::build_candidate_genesis()
            .unwrap()
            .ledger()
            .clone();
        let mut params = params();
        params.protocol_version = 5;
        params.initial_target = Uint256::MAX;
        params.pow_limit = Uint256::MAX;
        params.pow.memory_kib = 8;
        params.pow.iterations = 1;
        params.pow.lanes = 1;

        // The initial PFS2 Genesis manifest is created first. The external provider must be
        // provisioned out-of-band with this exact digest; the node never overwrites a provider.
        let initial_anchor = {
            let local = PrivateTestnetForkStore::open_qrun_v05_fee_only(
                &dir.0,
                genesis.clone(),
                params.clone(),
                &EmptyAuthenticator,
                &FixedClock,
            )
            .unwrap();
            local.manifest_anchor().unwrap()
        };

        let keypair = portable::generate_key_pair([0x5Au8; 32]);
        let signing_key = Arc::new(keypair.signing_key);
        let public_key: [u8; crate::v4_fat1_trust_candidate::ML_DSA_65_PUBLIC_KEY_BYTES] =
            *keypair.verification_key.as_ref();
        let pin = ExternalCasPin {
            provider_id: [0x91; 32],
            network_id: genesis.network_id(),
            genesis_digest: crate::qrun_v05_profile_identity_candidate::PROPOSED_GENESIS_COMMITMENT,
            receipt_key_id: [0x92; 32],
            receipt_public_key: public_key,
        };
        let bootstrap = ExternalCasRecord {
            generation: 0,
            provider_id: pin.provider_id,
            network_id: pin.network_id,
            genesis_digest: pin.genesis_digest,
            previous_record_digest: [0; 32],
            previous_state_digest: [0; 32],
            next_state_digest: initial_anchor,
            operation_id: [0x93; 32],
            request_digest: [0x94; 32],
        };
        let shared = Arc::new(Mutex::new(MemoryCasState {
            record: bootstrap.clone(),
            object_generation: 1,
            lose_next_commit_response: true,
            reject_next_commit_before_apply: false,
        }));
        let sign_key_1 = signing_key.clone();
        let provider = make_memory_cas_provider(pin.clone(), shared.clone(), move |mut receipt| {
            let digest = receipt.signing_digest().unwrap();
            receipt.signature = *portable::sign(&sign_key_1, &digest, &[], [0x73u8; 32])
                .unwrap()
                .as_ref();
            receipt
        });
        let client =
            VerifiedExternalCasClient::new(pin.clone(), provider, LibcruxMlDsa65VerifierCandidate)
                .unwrap();
        let mut store = QRunV05ExternalCasForkStore::open(
            &dir.0,
            genesis.clone(),
            params.clone(),
            &EmptyAuthenticator,
            &FixedClock,
            pin.clone(),
            client,
            bootstrap,
            1,
        )
        .unwrap();

        let envelope = qrun_fee_envelope(&genesis, &params);
        let outcome = store
            .submit(&envelope, &EmptyAuthenticator, &FixedClock)
            .unwrap();
        assert_eq!(outcome.canonical_height, 1);
        assert_eq!(store.canonical_height(), 1);
        assert_eq!(
            store.canonical_state().total_value().unwrap(),
            crate::state_machine::MAX_TOTAL_SUPPLY_ATOMS
        );
        assert_eq!(store.trusted_record().generation, 1);
        assert_eq!(store.minimum_object_generation(), 2);
        assert!(!dir.0.join(QRUN_PENDING_NAME).exists());
        {
            let state = shared.lock().unwrap();
            assert_eq!(state.record, *store.trusted_record());
            assert_eq!(state.object_generation, 2);
            assert!(!state.lose_next_commit_response);
        }
        let trusted = store.trusted_record().clone();
        let minimum_object_generation = store.minimum_object_generation();
        drop(store);

        // A new client process can reopen only using the independently retained signed record.
        let sign_key_2 = signing_key.clone();
        let provider = make_memory_cas_provider(pin.clone(), shared.clone(), move |mut receipt| {
            let digest = receipt.signing_digest().unwrap();
            receipt.signature = *portable::sign(&sign_key_2, &digest, &[], [0x73u8; 32])
                .unwrap()
                .as_ref();
            receipt
        });
        let client =
            VerifiedExternalCasClient::new(pin.clone(), provider, LibcruxMlDsa65VerifierCandidate)
                .unwrap();
        let reopened = QRunV05ExternalCasForkStore::open(
            &dir.0,
            genesis,
            params,
            &EmptyAuthenticator,
            &FixedClock,
            pin,
            client,
            trusted,
            minimum_object_generation,
        )
        .unwrap();
        assert_eq!(reopened.canonical_height(), 1);
        assert_eq!(
            reopened.canonical_state().total_value().unwrap(),
            crate::state_machine::MAX_TOTAL_SUPPLY_ATOMS
        );
        assert_eq!(reopened.trusted_record().generation, 1);
    }

    #[test]
    fn qrun_fee_store_reopens_with_profile_and_external_anchor_and_rejects_legacy() {
        let dir = TestDir::new();
        let mut params = params();
        params.protocol_version = 5;
        params.pow.memory_kib = 8;
        let genesis = crate::qrun_v05_profile_identity_candidate::build_candidate_genesis()
            .unwrap()
            .ledger()
            .clone();
        let fee = qrun_fee_envelope(&genesis, &params);
        let mut store = PrivateTestnetForkStore::open_qrun_v05_fee_only(
            &dir.0,
            genesis.clone(),
            params.clone(),
            &EmptyAuthenticator,
            &FixedClock,
        )
        .unwrap();
        store
            .submit(&fee, &EmptyAuthenticator, &FixedClock)
            .unwrap();
        assert_eq!(store.canonical_height(), 1);
        assert_eq!(
            store
                .archive()
                .canonical_chain()
                .state()
                .total_value()
                .unwrap(),
            crate::state_machine::MAX_TOTAL_SUPPLY_ATOMS
        );
        let anchor = store.manifest_anchor().unwrap();
        drop(store);

        let reopened = PrivateTestnetForkStore::open_qrun_v05_fee_only_anchored(
            &dir.0,
            genesis.clone(),
            params.clone(),
            &EmptyAuthenticator,
            &FixedClock,
            anchor,
        )
        .unwrap();
        assert_eq!(reopened.canonical_height(), 1);
        assert_eq!(
            reopened
                .archive()
                .canonical_chain()
                .state()
                .total_value()
                .unwrap(),
            crate::state_machine::MAX_TOTAL_SUPPLY_ATOMS
        );
        drop(reopened);

        assert!(matches!(
            PrivateTestnetForkStore::open(
                &dir.0,
                genesis.clone(),
                params.clone(),
                &EmptyAuthenticator,
                &FixedClock,
            ),
            Err(ForkStoreError::ManifestProfileMismatch)
        ));

        let legacy_dir = TestDir::new();
        let mut legacy = PrivateTestnetForkStore::open(
            &legacy_dir.0,
            genesis.clone(),
            params.clone(),
            &EmptyAuthenticator,
            &FixedClock,
        )
        .unwrap();
        assert!(matches!(
            legacy.submit(&fee, &EmptyAuthenticator, &FixedClock),
            Err(ForkStoreError::Fork(ForkChoiceError::ExecutionModeMismatch))
        ));
    }

    #[test]
    fn durable_branch_manifest_reopens_and_replays_same_canonical_state() {
        let dir = TestDir::new();
        let params = params();
        let genesis = genesis();
        let mut g = crate::private_testnet_driver::PrivateTestnetChain::new(
            genesis.clone(),
            params.clone(),
        )
        .unwrap();
        let (a, da) = envelope(&g, &params, 100, 0);
        let (b, db) = envelope(&g, &params, 100, 1);
        assert_ne!(da, db);

        let store = PrivateTestnetForkStore::open(
            &dir.0,
            genesis.clone(),
            params.clone(),
            &EmptyAuthenticator,
            &FixedClock,
        )
        .unwrap();
        assert_eq!(store.canonical_height(), 0);
        let mut store = store;
        store.submit(&a, &EmptyAuthenticator, &FixedClock).unwrap();
        store.submit(&b, &EmptyAuthenticator, &FixedClock).unwrap();

        let chosen = if da < db { da } else { db };
        assert_eq!(store.canonical_tip(), chosen);
        assert_eq!(store.archive().archive_len(), 2);
        let root_before = store.archive().canonical_chain().state().state_root();
        drop(store);

        let reopened = PrivateTestnetForkStore::open(
            &dir.0,
            genesis.clone(),
            params.clone(),
            &EmptyAuthenticator,
            &FixedClock,
        )
        .unwrap();
        assert_eq!(reopened.archive().archive_len(), 2);
        assert_eq!(reopened.canonical_tip(), chosen);
        assert_eq!(
            reopened.archive().canonical_chain().state().state_root(),
            root_before
        );
        drop(reopened);

        // Extend one competing branch to height 2, then force restart/replay to choose it.
        let parent_envelope = if da > db { &a } else { &b };
        let parent = decode_candidate_network_block(parent_envelope).unwrap();
        g.append_live(
            &parent.block,
            &parent.header,
            None,
            &EmptyAuthenticator,
            &FixedClock,
        )
        .unwrap();
        let (child, child_digest) = child_envelope(&g, &params, 101, 2);
        let mut reopened = PrivateTestnetForkStore::open(
            &dir.0,
            genesis.clone(),
            params.clone(),
            &EmptyAuthenticator,
            &FixedClock,
        )
        .unwrap();
        reopened
            .submit(&child, &EmptyAuthenticator, &FixedClock)
            .unwrap();
        assert_eq!(reopened.canonical_tip(), child_digest);
        let root_after = reopened.archive().canonical_chain().state().state_root();
        drop(reopened);

        let final_store = PrivateTestnetForkStore::open(
            &dir.0,
            genesis,
            params,
            &EmptyAuthenticator,
            &FixedClock,
        )
        .unwrap();
        assert_eq!(final_store.canonical_tip(), child_digest);
        assert_eq!(final_store.canonical_height(), 2);
        assert_eq!(
            final_store.archive().canonical_chain().state().state_root(),
            root_after
        );
    }

    #[test]
    fn qrun_full_supply_survives_durable_pow_reorg_and_restart() {
        let dir = TestDir::new();
        let qrun_genesis =
            crate::qrun_v05_genesis_candidate::QRunGenesisV05::new([0x51; 32], [0x2a; 32]).unwrap();
        let genesis = qrun_genesis.ledger().clone();
        let expected_supply = crate::state_machine::MAX_TOTAL_SUPPLY_ATOMS;
        assert_eq!(genesis.total_value().unwrap(), expected_supply);
        let params = params();
        let mut source_chain = crate::private_testnet_driver::PrivateTestnetChain::new(
            genesis.clone(),
            params.clone(),
        )
        .unwrap();
        let (branch_a, digest_a) = envelope(&source_chain, &params, 100, 10);
        let (branch_b, digest_b) = envelope(&source_chain, &params, 100, 11);
        assert_ne!(digest_a, digest_b);

        let mut store = PrivateTestnetForkStore::open(
            &dir.0,
            genesis.clone(),
            params.clone(),
            &EmptyAuthenticator,
            &FixedClock,
        )
        .unwrap();
        store
            .submit(&branch_a, &EmptyAuthenticator, &FixedClock)
            .unwrap();
        store
            .submit(&branch_b, &EmptyAuthenticator, &FixedClock)
            .unwrap();
        let tied_tip = if digest_a < digest_b {
            digest_a
        } else {
            digest_b
        };
        assert_eq!(store.canonical_tip(), tied_tip);
        assert_eq!(
            store
                .archive()
                .canonical_chain()
                .state()
                .total_value()
                .unwrap(),
            expected_supply
        );
        drop(store);

        // Extend the losing height-1 branch. The durable store must select the greater-work
        // descendant even after its parent was not canonical, and it must survive a full restart.
        let losing_parent = if digest_a > digest_b {
            &branch_a
        } else {
            &branch_b
        };
        let decoded_parent = decode_candidate_network_block(losing_parent).unwrap();
        source_chain
            .append_live(
                &decoded_parent.block,
                &decoded_parent.header,
                None,
                &EmptyAuthenticator,
                &FixedClock,
            )
            .unwrap();
        let (child, child_digest) = child_envelope(&source_chain, &params, 101, 12);
        let mut reopened = PrivateTestnetForkStore::open(
            &dir.0,
            genesis.clone(),
            params.clone(),
            &EmptyAuthenticator,
            &FixedClock,
        )
        .unwrap();
        reopened
            .submit(&child, &EmptyAuthenticator, &FixedClock)
            .unwrap();
        assert_eq!(reopened.canonical_tip(), child_digest);
        assert_eq!(reopened.canonical_height(), 2);
        assert_eq!(
            reopened
                .archive()
                .canonical_chain()
                .state()
                .total_value()
                .unwrap(),
            expected_supply
        );
        let expected_root = reopened.archive().canonical_chain().state().state_root();
        drop(reopened);

        let final_store = PrivateTestnetForkStore::open(
            &dir.0,
            genesis,
            params,
            &EmptyAuthenticator,
            &FixedClock,
        )
        .unwrap();
        assert_eq!(final_store.canonical_tip(), child_digest);
        assert_eq!(final_store.canonical_height(), 2);
        assert_eq!(
            final_store.archive().canonical_chain().state().state_root(),
            expected_root
        );
        assert_eq!(
            final_store
                .archive()
                .canonical_chain()
                .state()
                .total_value()
                .unwrap(),
            expected_supply
        );
    }

    #[test]
    fn stale_pid_text_does_not_block_os_lock_recovery() {
        let dir = TestDir::new();
        fs::write(dir.0.join(LOCK_NAME), b"pid=4294967295\n").unwrap();
        let reopened = PrivateTestnetForkStore::open(
            &dir.0,
            genesis(),
            params(),
            &EmptyAuthenticator,
            &FixedClock,
        )
        .unwrap();
        assert_eq!(
            fs::read_to_string(dir.0.join(LOCK_NAME)).unwrap(),
            format!("pid={}\n", std::process::id())
        );
        drop(reopened);
    }

    #[test]
    fn lock_profile_manifest_corruption_and_orphans_fail_closed() {
        let dir = TestDir::new();
        let params = params();
        let genesis = genesis();
        let store = PrivateTestnetForkStore::open(
            &dir.0,
            genesis.clone(),
            params.clone(),
            &EmptyAuthenticator,
            &FixedClock,
        )
        .unwrap();
        assert!(matches!(
            PrivateTestnetForkStore::open(
                &dir.0,
                genesis.clone(),
                params.clone(),
                &EmptyAuthenticator,
                &FixedClock
            ),
            Err(ForkStoreError::LockHeld)
        ));
        drop(store);

        let other_genesis = LedgerState::genesis([0xD9; 32], vec![([1; 32], 10_000)]).unwrap();
        assert!(matches!(
            PrivateTestnetForkStore::open(
                &dir.0,
                other_genesis,
                params.clone(),
                &EmptyAuthenticator,
                &FixedClock
            ),
            Err(ForkStoreError::ManifestProfileMismatch)
        ));

        let manifest_path = dir.0.join(MANIFEST_NAME);
        let mut corrupted = fs::read(&manifest_path).unwrap();
        corrupted[12] ^= 1;
        fs::write(&manifest_path, &corrupted).unwrap();
        assert!(matches!(
            PrivateTestnetForkStore::open(
                &dir.0,
                genesis,
                params,
                &EmptyAuthenticator,
                &FixedClock
            ),
            Err(ForkStoreError::ManifestChecksumMismatch)
        ));
    }

    #[test]
    fn missing_manifest_referenced_branch_blocks_startup() {
        let dir = TestDir::new();
        let params = params();
        let genesis = genesis();
        let chain = crate::private_testnet_driver::PrivateTestnetChain::new(
            genesis.clone(),
            params.clone(),
        )
        .unwrap();
        let (bytes, digest) = envelope(&chain, &params, 100, 78);
        let mut store = PrivateTestnetForkStore::open(
            &dir.0,
            genesis.clone(),
            params.clone(),
            &EmptyAuthenticator,
            &FixedClock,
        )
        .unwrap();
        store
            .submit(&bytes, &EmptyAuthenticator, &FixedClock)
            .unwrap();
        drop(store);

        fs::remove_file(dir.0.join(branch_file_name(&digest))).unwrap();
        assert!(matches!(
            PrivateTestnetForkStore::open(
                &dir.0,
                genesis,
                params,
                &EmptyAuthenticator,
                &FixedClock
            ),
            Err(ForkStoreError::MissingReferencedBranch)
        ));
    }

    #[test]
    fn consensus_profile_change_is_not_replayed_under_an_old_manifest() {
        let dir = TestDir::new();
        let params = params();
        let genesis = genesis();
        drop(
            PrivateTestnetForkStore::open(
                &dir.0,
                genesis.clone(),
                params.clone(),
                &EmptyAuthenticator,
                &FixedClock,
            )
            .unwrap(),
        );

        let mut changed = params.clone();
        changed.pow.memory_kib = 16 * 1024;
        assert!(matches!(
            PrivateTestnetForkStore::open(
                &dir.0,
                genesis,
                changed,
                &EmptyAuthenticator,
                &FixedClock
            ),
            Err(ForkStoreError::ManifestProfileMismatch)
        ));
    }

    #[test]
    fn canonical_tip_must_match_replayed_archive_even_with_valid_checksum() {
        let dir = TestDir::new();
        let params = params();
        let genesis = genesis();
        let mut store = PrivateTestnetForkStore::open(
            &dir.0,
            genesis.clone(),
            params.clone(),
            &EmptyAuthenticator,
            &FixedClock,
        )
        .unwrap();
        let chain = crate::private_testnet_driver::PrivateTestnetChain::new(
            genesis.clone(),
            params.clone(),
        )
        .unwrap();
        let (bytes, _) = envelope(&chain, &params, 100, 79);
        store
            .submit(&bytes, &EmptyAuthenticator, &FixedClock)
            .unwrap();
        drop(store);

        let manifest_path = dir.0.join(MANIFEST_NAME);
        let mut manifest = fs::read(&manifest_path).unwrap();
        manifest[102] ^= 0x80;
        let checksum_offset = manifest.len() - MANIFEST_CHECKSUM_BYTES;
        let checksum: [u8; 32] = Sha256::digest(&manifest[..checksum_offset]).into();
        manifest[checksum_offset..].copy_from_slice(&checksum);
        fs::write(&manifest_path, &manifest).unwrap();

        assert!(matches!(
            PrivateTestnetForkStore::open(
                &dir.0,
                genesis,
                params,
                &EmptyAuthenticator,
                &FixedClock
            ),
            Err(ForkStoreError::CanonicalTipMismatch)
        ));
    }

    const CP0119_STAGE_ENV: &str = "AIN1_CP0119_STAGE";
    const CP0119_STORE_ENV: &str = "AIN1_CP0119_STORE_DIR";

    fn invoke_persisted_anchor_child(stage: &str, store_dir: &Path) {
        let executable = std::env::current_exe().unwrap();
        let output = Command::new(executable)
            .arg("--exact")
            .arg("private_testnet_fork_store::tests::persisted_mtp_anchor_child_entrypoint")
            .arg("--nocapture")
            .env(CP0119_STAGE_ENV, stage)
            .env(CP0119_STORE_ENV, store_dir)
            .output()
            .expect("launch the isolated fork-store child test process");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "child stage {stage} failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
        assert!(
            stdout.contains(&format!("CP0119_CHILD_STAGE_OK={stage}")),
            "child stage {stage} did not execute the expected test entrypoint\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
        println!("{stdout}");
        println!("{stderr}");
    }

    fn timestamp_history_from_tip(
        tip: [u8; 32],
        genesis_tip: [u8; 32],
        genesis_timestamp: i128,
        genesis_bits: u32,
        by_digest: &BTreeMap<[u8; 32], HeaderTimeSample>,
    ) -> Vec<HeaderTimeSample> {
        let mut backwards = Vec::<HeaderTimeSample>::new();
        let mut cursor = tip;
        let mut reached_genesis = false;
        for _ in 0..=crate::private_testnet_fork_choice::MAX_FORK_ARCHIVE_HEIGHT {
            if cursor == genesis_tip {
                reached_genesis = true;
                break;
            }
            let sample = *by_digest
                .get(&cursor)
                .expect("every non-genesis parent must be persisted in the manifest");
            backwards.push(sample);
            cursor = sample.parent_hash;
        }
        assert!(reached_genesis, "persisted parent walk exceeded its bound");
        backwards.reverse();

        let mut history = vec![HeaderTimeSample {
            height: 0,
            timestamp: genesis_timestamp,
            bits: genesis_bits,
            parent_hash: [0; 32],
            block_hash: genesis_tip,
        }];
        for sample in backwards {
            let parent = history.last().unwrap();
            assert_eq!(sample.height, parent.height + 1);
            assert_eq!(sample.parent_hash, parent.block_hash);
            history.push(sample);
        }
        assert_eq!(history.last().unwrap().block_hash, tip);
        history
    }

    fn persisted_timestamp_samples(
        store: &PrivateTestnetForkStore,
        params: &ConsensusParameters,
    ) -> BTreeMap<[u8; 32], HeaderTimeSample> {
        let mut by_digest = BTreeMap::new();
        for envelope_bytes in store.archive().archive_envelopes() {
            let decoded = decode_candidate_network_block(&envelope_bytes).unwrap();
            let digest = pow_digest(&decoded.header, params.pow).unwrap();
            let previous = by_digest.insert(
                digest,
                HeaderTimeSample {
                    height: decoded.header.height,
                    timestamp: decoded.header.timestamp as i128,
                    bits: target_to_compact_bits(decoded.header.target),
                    parent_hash: decoded.header.previous_consensus_hash,
                    block_hash: digest,
                },
            );
            assert!(
                previous.is_none(),
                "replayed archive has a duplicate block digest"
            );
        }
        by_digest
    }

    fn execute_persisted_anchor_child_stage(stage: &str, store_dir: &Path) {
        let params = params();
        let genesis = genesis();

        match stage {
            "seed" => {
                let mut store = PrivateTestnetForkStore::open(
                    store_dir,
                    genesis.clone(),
                    params.clone(),
                    &EmptyAuthenticator,
                    &FixedClock,
                )
                .unwrap();
                let genesis_chain = crate::private_testnet_driver::PrivateTestnetChain::new(
                    genesis.clone(),
                    params.clone(),
                )
                .unwrap();

                let (a1, a1_digest) = envelope(&genesis_chain, &params, 1_000_001, 101);
                let (b1, b1_digest) = envelope(&genesis_chain, &params, 1_000_002, 201);
                store.submit(&a1, &EmptyAuthenticator, &FixedClock).unwrap();
                store.submit(&b1, &EmptyAuthenticator, &FixedClock).unwrap();

                let a1_chain = store.archive().branch_chain(&a1_digest).unwrap().clone();
                let b1_chain = store.archive().branch_chain(&b1_digest).unwrap().clone();
                let (a2, a2_digest) = envelope(&a1_chain, &params, 1_000_010, 102);
                let (b2, b2_digest) = envelope(&b1_chain, &params, 1_000_020, 202);
                store.submit(&a2, &EmptyAuthenticator, &FixedClock).unwrap();
                store.submit(&b2, &EmptyAuthenticator, &FixedClock).unwrap();

                assert_eq!(store.archive().archive_len(), 4);
                // Equal-height/equal-work choice has one loser; extend that branch so the
                // resulting height-3 branch must win after a reorg.
                let (loser_chain, child_timestamp) = if a2_digest > b2_digest {
                    (
                        store.archive().branch_chain(&a2_digest).unwrap().clone(),
                        1_000_015,
                    )
                } else {
                    (
                        store.archive().branch_chain(&b2_digest).unwrap().clone(),
                        1_000_025,
                    )
                };
                let (child, child_digest) = envelope(&loser_chain, &params, child_timestamp, 303);
                let outcome = store
                    .submit(&child, &EmptyAuthenticator, &FixedClock)
                    .unwrap();
                assert_eq!(outcome.canonical_tip, child_digest);
                assert_eq!(outcome.canonical_height, 3);
                assert_eq!(store.canonical_height(), 3);
                assert_eq!(store.archive().archive_len(), 5);
                drop(store);
                println!("CP0119_CHILD_STAGE_OK=seed");
            }
            "verify" => {
                let store = PrivateTestnetForkStore::open(
                    store_dir,
                    genesis,
                    params.clone(),
                    &EmptyAuthenticator,
                    &FixedClock,
                )
                .expect("second process must reopen and replay the persisted manifest");
                assert_eq!(store.canonical_height(), 3);
                assert_eq!(store.archive().archive_len(), 5);

                let by_digest = persisted_timestamp_samples(&store, &params);
                let genesis_tip = store.archive().genesis_tip();
                let genesis_bits = target_to_compact_bits(params.initial_target);
                let max_bits = target_to_compact_bits(params.pow_limit);
                let canonical = timestamp_history_from_tip(
                    store.canonical_tip(),
                    genesis_tip,
                    1_000_000,
                    genesis_bits,
                    &by_digest,
                );
                assert_eq!(canonical.len(), 4);
                assert_eq!(canonical.last().unwrap().height, 3);

                let canonical_anchor = select_asert_anchor(&canonical, 2, max_bits).unwrap();
                let expected_mtp = match canonical_anchor.parent_timestamp {
                    1_000_001 => 1_000_010,
                    1_000_002 => 1_000_020,
                    other => panic!("unexpected persisted canonical anchor parent time {other}"),
                };
                assert_eq!(
                    median_time_past(&canonical).unwrap(),
                    expected_mtp,
                    "MTP must be derived from the winning branch after process restart"
                );
                assert_eq!(
                    validate_candidate_mtp(
                        &canonical,
                        4,
                        canonical.last().unwrap().block_hash,
                        canonical.last().unwrap().timestamp + 1,
                    ),
                    Ok(())
                );

                let competing_tips = by_digest
                    .iter()
                    .filter_map(|(digest, sample)| (sample.height == 2).then_some(*digest))
                    .collect::<Vec<_>>();
                assert_eq!(competing_tips.len(), 2);
                let mut branch_anchor_parents = competing_tips
                    .iter()
                    .map(|tip| {
                        let history = timestamp_history_from_tip(
                            *tip,
                            genesis_tip,
                            1_000_000,
                            genesis_bits,
                            &by_digest,
                        );
                        select_asert_anchor(&history, 2, max_bits)
                            .unwrap()
                            .parent_timestamp
                    })
                    .collect::<Vec<_>>();
                branch_anchor_parents.sort_unstable();
                assert_eq!(branch_anchor_parents, vec![1_000_001, 1_000_002]);
                assert!(branch_anchor_parents.contains(&canonical_anchor.parent_timestamp));
                assert!(branch_anchor_parents
                    .iter()
                    .any(|time| *time != canonical_anchor.parent_timestamp));

                println!(
                    "CP0119_RESTART_REPLAY_PASS canonical_height=3 persisted_candidates=5 anchor_parent_time={} mtp={} competing_anchor_parent_times={:?}",
                    canonical_anchor.parent_timestamp,
                    median_time_past(&canonical).unwrap(),
                    branch_anchor_parents
                );
                drop(store);
                println!("CP0119_CHILD_STAGE_OK=verify");
            }
            other => panic!("unknown persisted-anchor child stage {other}"),
        }
    }

    #[test]
    fn persisted_mtp_anchor_child_entrypoint() {
        let Ok(stage) = std::env::var(CP0119_STAGE_ENV) else {
            // Normal all-target runs include this entrypoint without invoking child mode.
            return;
        };
        let store_dir = std::env::var_os(CP0119_STORE_ENV)
            .map(PathBuf::from)
            .expect("child stage requires a store directory");
        execute_persisted_anchor_child_stage(&stage, &store_dir);
    }

    #[test]
    fn persisted_mtp_anchor_reorg_survives_two_process_starts() {
        let dir = TestDir::new();
        invoke_persisted_anchor_child("seed", &dir.0);
        // The seed process has exited and its file lock/handles are gone. The verify process
        // must reopen every referenced PTB2 envelope and reconstruct canonical state from PFS2.
        invoke_persisted_anchor_child("verify", &dir.0);
    }

    #[test]
    fn external_manifest_anchor_rejects_rewritten_but_self_consistent_missing_branch_catalog() {
        let dir = TestDir::new();
        let params = params();
        let genesis = genesis();
        let chain = crate::private_testnet_driver::PrivateTestnetChain::new(
            genesis.clone(),
            params.clone(),
        )
        .unwrap();
        let (block, digest) = envelope(&chain, &params, 100, 44);
        let trusted_anchor;
        {
            let mut store = PrivateTestnetForkStore::open(
                &dir.0,
                genesis.clone(),
                params.clone(),
                &EmptyAuthenticator,
                &FixedClock,
            )
            .unwrap();
            store
                .submit(&block, &EmptyAuthenticator, &FixedClock)
                .unwrap();
            assert_eq!(store.archive().archive_len(), 1);
            trusted_anchor = store.manifest_anchor().unwrap();
        }
        assert!(dir.0.join(branch_file_name(&digest)).is_file());

        // Simulate an attacker rewriting the local catalog and its unkeyed checksum so it
        // self-consistently claims the genesis-only store, while leaving the branch file behind.
        let empty = PrivateTestnetForkChoice::new(genesis.clone(), params.clone()).unwrap();
        let genesis_tip = empty.canonical_chain().chain_tip().tip_hash;
        let fingerprint = profile_fingerprint(&genesis, &params).unwrap();
        let rewritten = encode_manifest(
            &genesis.network_id(),
            &fingerprint,
            &genesis_tip,
            &genesis_tip,
            &[],
        )
        .unwrap();
        fs::write(dir.0.join(MANIFEST_NAME), rewritten).unwrap();

        assert!(matches!(
            PrivateTestnetForkStore::open_anchored(
                &dir.0,
                genesis.clone(),
                params.clone(),
                &EmptyAuthenticator,
                &FixedClock,
                trusted_anchor,
            ),
            Err(ForkStoreError::ManifestAnchorMismatch)
        ));

        // Legacy reopen has no outside trust anchor and accepts the self-consistent omission.
        let unanchored = PrivateTestnetForkStore::open(
            &dir.0,
            genesis,
            params,
            &EmptyAuthenticator,
            &FixedClock,
        )
        .unwrap();
        assert_eq!(unanchored.archive().archive_len(), 0);
        assert_eq!(unanchored.canonical_tip(), genesis_tip);
        assert_eq!(unanchored.canonical_height(), 0);
    }

    #[test]
    fn startup_discards_uncommitted_orphan_branch_files() {
        let dir = TestDir::new();
        let params = params();
        let genesis = genesis();
        let chain = crate::private_testnet_driver::PrivateTestnetChain::new(
            genesis.clone(),
            params.clone(),
        )
        .unwrap();
        let (envelope, digest) = envelope(&chain, &params, 100, 44);
        let orphan = dir.0.join(branch_file_name(&digest));
        fs::write(&orphan, envelope).unwrap();

        let store = PrivateTestnetForkStore::open(
            &dir.0,
            genesis,
            params,
            &EmptyAuthenticator,
            &FixedClock,
        )
        .unwrap();
        assert_eq!(store.archive().archive_len(), 0);
        assert_eq!(store.canonical_height(), 0);
        assert!(!orphan.exists());
    }
}
