//! CP-0406/CP-0407 candidate persistent archive and injected-CAS anchoring for QZBE / QZB4 v2.
//!
//! This store persists bounded, individually digest-named envelopes and immutable manifest
//! generations. On open, it verifies exact bytes and rebuilds the complete branch graph from
//! Genesis before exposing a canonical tip. CP-0407 optionally binds exact manifest bytes to the
//! repository's signed external-CAS contract and reconciles a pending commit by a fresh read.
//! The provider remains an injected interface/test fixture: there is no deployed provider,
//! independent key custody, canonical-node wiring, or Mainnet launch in this module.
use crate::{
    consensus::{pow_digest, ConsensusError, ConsensusParameters},
    external_cas_anchor_candidate::{
        ExternalCasClientError, ExternalCasError, ExternalCasPin, ExternalCasProviderTransport,
        ExternalCasReceipt, ExternalCasReceiptOutcome, ExternalCasRecord, ExternalCasWriteRequest,
        VerifiedExternalCasClient,
    },
    monetary_pow_v04_candidate::{
        pow_consensus_profile_fingerprint, V04ExecutionForkChoiceCandidate,
        V04ExecutionForkChoiceOutcome, V04ExecutionPowEnvelope, V04ExecutionPowError,
        MAX_ENCODED_V04_EXECUTION_POW_ENVELOPE_BYTES, MAX_V04_EXECUTION_FORK_ARCHIVE_BLOCKS,
    },
    monetary_transition_v04_candidate::{
        MonetaryLedgerStateV04TransitionCandidate, V04TransitionError,
    },
    state_machine::TransactionAuthenticator,
    store_writer_lock::StoreWriterLock,
    v4_fat1_trust_candidate::MlDsa65Verifier,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const MANIFEST_MAGIC: &[u8; 4] = b"QZMF";
const MANIFEST_VERSION: u16 = 1;
const MANIFEST_DOMAIN: &[u8] = b"QUANTUMZXB-QZBE-STORE-MANIFEST-CANDIDATE-V1\0";
const MANIFEST_PREFIX_BYTES: usize = 4 + 2 + 8 + 32 * 6 + 8 + 4;
const MANIFEST_ENTRY_BYTES: usize = 64;
const MANIFEST_CHECKSUM_BYTES: usize = 32;
const MAX_MANIFEST_BYTES: usize = MANIFEST_PREFIX_BYTES
    + MAX_V04_EXECUTION_FORK_ARCHIVE_BLOCKS * MANIFEST_ENTRY_BYTES
    + MANIFEST_CHECKSUM_BYTES;
const MAX_ARCHIVE_BYTES: usize = 64 * 1024 * 1024;
const MANIFEST_PREFIX: &str = "qzbe-manifest-";
const MANIFEST_SUFFIX: &str = ".qzmf";
const BRANCH_SUFFIX: &str = ".qzbe";
const BRANCH_DIR: &str = "branches";
const MANIFEST_DIR: &str = "manifests";
const LOCK_NAME: &str = "qzbe-store.lock";
const PENDING_MANIFEST_NAME: &str = ".qzbe-manifest.pending-cas";
const ANCHOR_MODE_MARKER_NAME: &str = ".qzbe-external-cas-required";
const ANCHOR_MODE_MARKER_MAGIC: &[u8; 4] = b"QZCA";
const ANCHOR_MODE_MARKER_VERSION: u16 = 1;
const ANCHOR_MODE_MARKER_DOMAIN: &[u8] = b"QUANTUMZXB-QZBE-EXTERNAL-CAS-MODE-MARKER-V1\0";
const ANCHOR_MODE_MARKER_BYTES: usize = 4 + 2 + 7 * 32 + 32;
const MANIFEST_ANCHOR_DOMAIN: &[u8] = b"QUANTUMZXB-QZBE-MANIFEST-ANCHOR-CANDIDATE-V1\0";
const CAS_READ_OPERATION_DOMAIN: &[u8] = b"QUANTUMZXB-QZBE-CAS-READ-CANDIDATE-V1\0";
const CAS_WRITE_OPERATION_DOMAIN: &[u8] = b"QUANTUMZXB-QZBE-CAS-WRITE-CANDIDATE-V1\0";
const CAS_WRITE_NONCE_DOMAIN: &[u8] = b"QUANTUMZXB-QZBE-CAS-WRITE-NONCE-CANDIDATE-V1\0";
const CAS_GENESIS_DOMAIN: &[u8] = b"QUANTUMZXB-QZBE-CAS-GENESIS-CANDIDATE-V1\0";
static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
pub enum V04ExecutionForkStoreError {
    Io(io::Error),
    Pow(V04ExecutionPowError),
    ManifestMalformed,
    ManifestChecksumMismatch,
    ManifestProfileMismatch,
    ManifestGenerationMismatch,
    ManifestSequenceOverflow,
    ManifestMissingWithBranches,
    MissingBranch,
    BranchDigestMismatch,
    BranchBytesMismatch,
    CanonicalStateMismatch,
    ArchiveCapacityExceeded,
    StoreLocked,
    ExternalAnchorRequired,
    ExternalAnchorMismatch,
    PendingManifestExists,
    PendingManifestMalformed,
    ExternalCasFailure(String),
    ExternalCasConflict,
    ExternalCasInvalidOutcome(ExternalCasReceiptOutcome),
    UnexpectedBranchFile,
    UnsafeStorePath,
}

impl std::fmt::Display for V04ExecutionForkStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "QZBE store I/O error: {e}"),
            Self::Pow(e) => write!(f, "QZBE store replay error: {e}"),
            Self::ManifestMalformed => write!(f, "QZMF manifest is malformed"),
            Self::ManifestChecksumMismatch => write!(f, "QZMF manifest checksum mismatch"),
            Self::ManifestProfileMismatch => write!(f, "QZMF manifest profile mismatch"),
            Self::ManifestGenerationMismatch => write!(f, "QZMF filename/generation mismatch"),
            Self::ManifestSequenceOverflow => write!(f, "QZMF manifest generation overflow"),
            Self::ManifestMissingWithBranches => {
                write!(f, "QZBE branch files exist without a committed manifest")
            }
            Self::MissingBranch => write!(f, "QZMF references a missing branch file"),
            Self::BranchDigestMismatch => write!(f, "QZBE branch digest/filename mismatch"),
            Self::BranchBytesMismatch => write!(f, "QZBE branch bytes conflict with digest name"),
            Self::CanonicalStateMismatch => {
                write!(
                    f,
                    "QZMF canonical tip/state differs from deterministic replay"
                )
            }
            Self::ArchiveCapacityExceeded => write!(f, "QZBE archive exceeds candidate bounds"),
            Self::StoreLocked => write!(f, "QZBE store already has a writer"),
            Self::ExternalAnchorRequired => write!(
                f,
                "QZBE store is externally anchored; use submit_with_external_cas"
            ),
            Self::ExternalAnchorMismatch => write!(
                f,
                "external CAS anchor does not match the exact QZBE manifest"
            ),
            Self::PendingManifestExists => write!(
                f,
                "pending QZBE CAS manifest requires signed-anchor recovery"
            ),
            Self::PendingManifestMalformed => {
                write!(f, "pending QZBE CAS manifest is malformed or inconsistent")
            }
            Self::ExternalCasFailure(error) => write!(f, "external QZBE CAS failure: {error}"),
            Self::ExternalCasConflict => write!(
                f,
                "external QZBE CAS conditional write conflicted; recover with a fresh signed read"
            ),
            Self::ExternalCasInvalidOutcome(outcome) => write!(
                f,
                "external QZBE CAS returned non-commit outcome: {outcome:?}"
            ),
            Self::UnexpectedBranchFile => write!(
                f,
                "QZBE branch directory contains an uncommitted or non-canonical entry"
            ),
            Self::UnsafeStorePath => write!(
                f,
                "QZBE store path contains a symlink, reparse point, or non-directory entry"
            ),
        }
    }
}
impl std::error::Error for V04ExecutionForkStoreError {}
impl From<io::Error> for V04ExecutionForkStoreError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<V04ExecutionPowError> for V04ExecutionForkStoreError {
    fn from(value: V04ExecutionPowError) -> Self {
        Self::Pow(value)
    }
}
impl From<ConsensusError> for V04ExecutionForkStoreError {
    fn from(value: ConsensusError) -> Self {
        Self::Pow(V04ExecutionPowError::Consensus(value))
    }
}
impl From<V04TransitionError> for V04ExecutionForkStoreError {
    fn from(value: V04TransitionError) -> Self {
        Self::Pow(V04ExecutionPowError::Transition(value))
    }
}

#[derive(Debug)]
struct Manifest {
    generation: u64,
    network_id: [u8; 32],
    genesis_tip: [u8; 32],
    profile_fingerprint: [u8; 32],
    pow_fingerprint: [u8; 32],
    canonical_tip: [u8; 32],
    canonical_height: u64,
    canonical_state_root: [u8; 32],
    entries: Vec<([u8; 32], [u8; 32])>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AnchorModeMarker {
    provider_id: [u8; 32],
    network_id: [u8; 32],
    genesis_digest: [u8; 32],
    receipt_key_id: [u8; 32],
    receipt_key_fingerprint: [u8; 32],
    profile_fingerprint: [u8; 32],
    pow_fingerprint: [u8; 32],
}

/// Local operational mode latch only. This file prevents accidental plain-open writes after CAS
/// setup, but is mutable local state and is not itself anti-rollback security evidence.
fn decode_anchor_mode_marker(bytes: &[u8]) -> Result<AnchorModeMarker, V04ExecutionForkStoreError> {
    if bytes.len() != ANCHOR_MODE_MARKER_BYTES
        || &bytes[..4] != ANCHOR_MODE_MARKER_MAGIC
        || u16::from_be_bytes([bytes[4], bytes[5]]) != ANCHOR_MODE_MARKER_VERSION
    {
        return Err(V04ExecutionForkStoreError::ExternalAnchorMismatch);
    }
    let payload_end = bytes.len() - 32;
    let mut hasher = Sha256::new();
    hasher.update(ANCHOR_MODE_MARKER_DOMAIN);
    hasher.update(&bytes[..payload_end]);
    let expected: [u8; 32] = hasher.finalize().into();
    if bytes[payload_end..] != expected {
        return Err(V04ExecutionForkStoreError::ExternalAnchorMismatch);
    }
    let mut cursor = 6usize;
    let mut take32 = || {
        let mut result = [0u8; 32];
        result.copy_from_slice(&bytes[cursor..cursor + 32]);
        cursor += 32;
        result
    };
    let marker = AnchorModeMarker {
        provider_id: take32(),
        network_id: take32(),
        genesis_digest: take32(),
        receipt_key_id: take32(),
        receipt_key_fingerprint: take32(),
        profile_fingerprint: take32(),
        pow_fingerprint: take32(),
    };
    if [
        marker.provider_id,
        marker.network_id,
        marker.genesis_digest,
        marker.receipt_key_id,
        marker.receipt_key_fingerprint,
        marker.profile_fingerprint,
        marker.pow_fingerprint,
    ]
    .iter()
    .any(|value| value.iter().all(|byte| *byte == 0))
    {
        return Err(V04ExecutionForkStoreError::ExternalAnchorMismatch);
    }
    Ok(marker)
}

/// Load a marker without following symlinks. A malformed marker fails closed rather than
/// silently converting an anchored data directory to local-only submission mode.
fn load_anchor_mode_marker(
    directory: &Path,
) -> Result<Option<AnchorModeMarker>, V04ExecutionForkStoreError> {
    let path = directory.join(ANCHOR_MODE_MARKER_NAME);
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() {
                return Err(V04ExecutionForkStoreError::ExternalAnchorMismatch);
            }
            let bytes = read_bounded(&path, ANCHOR_MODE_MARKER_BYTES)
                .map_err(|_| V04ExecutionForkStoreError::ExternalAnchorMismatch)?;
            Ok(Some(decode_anchor_mode_marker(&bytes)?))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(V04ExecutionForkStoreError::Io(error)),
    }
}

fn compute_external_cas_genesis_digest(
    graph: &V04ExecutionForkChoiceCandidate,
    params: &ConsensusParameters,
) -> Result<[u8; 32], V04ExecutionForkStoreError> {
    let mut hash = Sha256::new();
    hash.update(CAS_GENESIS_DOMAIN);
    hash.update(graph.profile().network_id());
    hash.update(graph.genesis_tip());
    hash.update(graph.profile().profile_fingerprint());
    hash.update(pow_consensus_profile_fingerprint(params)?);
    Ok(hash.finalize().into())
}

fn validate_anchor_mode_marker_for_store(
    marker: &AnchorModeMarker,
    graph: &V04ExecutionForkChoiceCandidate,
    params: &ConsensusParameters,
) -> Result<(), V04ExecutionForkStoreError> {
    if marker.network_id != *graph.profile().network_id()
        || marker.genesis_digest != compute_external_cas_genesis_digest(graph, params)?
        || marker.profile_fingerprint != *graph.profile().profile_fingerprint()
        || marker.pow_fingerprint != pow_consensus_profile_fingerprint(params)?
    {
        return Err(V04ExecutionForkStoreError::ExternalAnchorMismatch);
    }
    Ok(())
}

fn validate_anchor_mode_marker_pin(
    marker: &AnchorModeMarker,
    pin: &ExternalCasPin,
) -> Result<(), V04ExecutionForkStoreError> {
    let key_fingerprint: [u8; 32] = Sha256::digest(&pin.receipt_public_key).into();
    if marker.provider_id != pin.provider_id
        || marker.network_id != pin.network_id
        || marker.genesis_digest != pin.genesis_digest
        || marker.receipt_key_id != pin.receipt_key_id
        || marker.receipt_key_fingerprint != key_fingerprint
    {
        return Err(V04ExecutionForkStoreError::ExternalAnchorMismatch);
    }
    Ok(())
}

fn encode_anchor_mode_marker(
    store: &V04ExecutionForkStoreCandidate,
    pin: &ExternalCasPin,
) -> Result<Vec<u8>, V04ExecutionForkStoreError> {
    let genesis_digest = store.external_cas_genesis_digest()?;
    if pin.network_id != *store.fork_choice.profile().network_id()
        || pin.genesis_digest != genesis_digest
    {
        return Err(V04ExecutionForkStoreError::ExternalAnchorMismatch);
    }
    let mut bytes = Vec::with_capacity(ANCHOR_MODE_MARKER_BYTES);
    bytes.extend_from_slice(ANCHOR_MODE_MARKER_MAGIC);
    bytes.extend_from_slice(&ANCHOR_MODE_MARKER_VERSION.to_be_bytes());
    bytes.extend_from_slice(&pin.provider_id);
    bytes.extend_from_slice(&pin.network_id);
    bytes.extend_from_slice(&pin.genesis_digest);
    bytes.extend_from_slice(&pin.receipt_key_id);
    let key_fingerprint: [u8; 32] = Sha256::digest(&pin.receipt_public_key).into();
    bytes.extend_from_slice(&key_fingerprint);
    bytes.extend_from_slice(store.fork_choice.profile().profile_fingerprint());
    bytes.extend_from_slice(&pow_consensus_profile_fingerprint(&store.params)?);
    let mut hasher = Sha256::new();
    hasher.update(ANCHOR_MODE_MARKER_DOMAIN);
    hasher.update(&bytes);
    bytes.extend_from_slice(&<[u8; 32]>::from(hasher.finalize()));
    if bytes.len() != ANCHOR_MODE_MARKER_BYTES {
        return Err(V04ExecutionForkStoreError::ExternalAnchorMismatch);
    }
    Ok(bytes)
}

/// Persist a local operational guard against accidentally reopening an externally anchored store
/// through plain submit(). The signed remote CAS remains the anti-rollback authority; this marker
/// is deliberately not described as tamper-resistant or an independent trust anchor.
fn persist_anchor_mode_marker(
    store: &V04ExecutionForkStoreCandidate,
    pin: &ExternalCasPin,
) -> Result<(), V04ExecutionForkStoreError> {
    let bytes = encode_anchor_mode_marker(store, pin)?;
    let expected = decode_anchor_mode_marker(&bytes)?;
    let path = store.directory.join(ANCHOR_MODE_MARKER_NAME);
    match load_anchor_mode_marker(&store.directory)? {
        Some(existing) => {
            if existing != expected {
                return Err(V04ExecutionForkStoreError::ExternalAnchorMismatch);
            }
            // Re-publish an existing marker too: it may have been created by an older writer
            // that synced file contents but did not flush the parent directory entry.
            write_replace_atomic(&path, &bytes)
        }
        None => write_new_atomic(&path, &bytes),
    }
}

/// Local-only persistent QZBE archive. Not a production consensus store or Gate 8 provider.
///
/// The store serializes writers using the repository's OS-backed lock, keeps immutable manifest
/// generations, and replays all committed envelopes on every open. A successful local manifest
/// checksum is not proof against whole-directory rollback; a separately administered external
/// CAS/anchor and live runtime integration remain required.
pub struct V04ExecutionForkStoreCandidate {
    directory: PathBuf,
    _writer_lock: StoreWriterLock,
    fork_choice: V04ExecutionForkChoiceCandidate,
    params: ConsensusParameters,
    generation: u64,
    external_anchor_required: bool,
}

/// Result of a QZBE submission whose manifest commitment was accepted by the pinned CAS contract.
/// receipt is None only for an already-known duplicate envelope that caused no state change.
#[derive(Debug)]
pub struct V04ExecutionAnchoredSubmitOutcome {
    pub block: V04ExecutionForkChoiceOutcome,
    pub anchor_record: ExternalCasRecord,
    pub receipt: Option<ExternalCasReceipt>,
}

fn manifest_anchor_commitment(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(MANIFEST_ANCHOR_DOMAIN);
    hash.update(bytes);
    hash.finalize().into()
}

/// After the remote anchor has been verified, remove local branches that are not named by the
/// active committed manifest. Non-regular and non-canonical branch entries are rejected.
fn prune_unreferenced_branch_files(
    store: &V04ExecutionForkStoreCandidate,
) -> Result<(), V04ExecutionForkStoreError> {
    let manifest_path = store
        .directory
        .join(MANIFEST_DIR)
        .join(manifest_filename(store.generation));
    let manifest_bytes = read_bounded(&manifest_path, MAX_MANIFEST_BYTES)?;
    let manifest = decode_manifest(&manifest_bytes)?;
    if manifest.generation != store.generation {
        return Err(V04ExecutionForkStoreError::ManifestGenerationMismatch);
    }
    let committed: std::collections::BTreeSet<String> = manifest
        .entries
        .iter()
        .map(|(digest, _)| format!("{}{}", hex(digest), BRANCH_SUFFIX))
        .collect();
    let branches_dir = store.directory.join(BRANCH_DIR);
    let mut removed = false;
    for entry in fs::read_dir(&branches_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(BRANCH_SUFFIX) {
            continue;
        }
        if !entry.file_type()?.is_file() {
            return Err(V04ExecutionForkStoreError::UnexpectedBranchFile);
        }
        let digest_text = &name[..name.len() - BRANCH_SUFFIX.len()];
        if digest_text.len() != 64
            || !digest_text
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(V04ExecutionForkStoreError::UnexpectedBranchFile);
        }
        if !committed.contains(&name) {
            fs::remove_file(entry.path())?;
            removed = true;
        }
    }
    if removed {
        sync_directory(&branches_dir)?;
    }
    Ok(())
}

impl V04ExecutionForkStoreCandidate {
    pub fn open<A: TransactionAuthenticator>(
        directory: impl AsRef<Path>,
        genesis: MonetaryLedgerStateV04TransitionCandidate,
        params: ConsensusParameters,
        authenticator: &A,
    ) -> Result<Self, V04ExecutionForkStoreError> {
        let directory = directory.as_ref().to_path_buf();
        ensure_store_root_directory(&directory)?;
        let writer_lock = StoreWriterLock::acquire(&directory, LOCK_NAME).map_err(|error| {
            if error.kind() == io::ErrorKind::WouldBlock {
                V04ExecutionForkStoreError::StoreLocked
            } else {
                V04ExecutionForkStoreError::Io(error)
            }
        })?;
        // Read mutable recovery state only after acquiring the process lock. Checking the pending
        // CAS manifest before lock acquisition permits a stale pre-lock observation if another
        // writer creates it while this opener waits.
        // Atomic marker/pending publication also stages files in the store root, so clean those
        // abandoned temporaries alongside the branch and manifest staging files below.
        clean_temporary_files(&directory)?;
        let pending_path = directory.join(PENDING_MANIFEST_NAME);
        let pending_exists = match fs::symlink_metadata(&pending_path) {
            Ok(_) => true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(V04ExecutionForkStoreError::Io(error)),
        };
        let branches_dir = ensure_store_subdirectory(&directory, BRANCH_DIR)?;
        let manifests_dir = ensure_store_subdirectory(&directory, MANIFEST_DIR)?;
        clean_temporary_files(&branches_dir)?;
        clean_temporary_files(&manifests_dir)?;

        let graph = V04ExecutionForkChoiceCandidate::new(genesis.clone(), params.clone())?;
        let anchor_marker = load_anchor_mode_marker(&directory)?;
        if let Some(marker) = &anchor_marker {
            validate_anchor_mode_marker_for_store(marker, &graph, &params)?;
        }
        let latest = latest_manifest(&manifests_dir)?;
        let (fork_choice, generation) = match latest {
            Some((filename_generation, manifest_path)) => {
                let bytes = read_bounded(&manifest_path, MAX_MANIFEST_BYTES)?;
                let manifest = decode_manifest(&bytes)?;
                if manifest.generation != filename_generation {
                    return Err(V04ExecutionForkStoreError::ManifestGenerationMismatch);
                }
                verify_manifest_profile(&manifest, &graph, &params)?;
                let mut envelopes = Vec::with_capacity(manifest.entries.len());
                let mut total_bytes = 0usize;
                for (digest, expected_bytes_hash) in &manifest.entries {
                    let path = branches_dir.join(format!("{}{}", hex(digest), BRANCH_SUFFIX));
                    let envelope_bytes =
                        read_bounded(&path, MAX_ENCODED_V04_EXECUTION_POW_ENVELOPE_BYTES).map_err(
                            |error| {
                                if matches!(
                                    error,
                                    V04ExecutionForkStoreError::Io(ref io_error)
                                        if io_error.kind() == io::ErrorKind::NotFound
                                ) {
                                    V04ExecutionForkStoreError::MissingBranch
                                } else {
                                    error
                                }
                            },
                        )?;
                    total_bytes = total_bytes
                        .checked_add(envelope_bytes.len())
                        .ok_or(V04ExecutionForkStoreError::ArchiveCapacityExceeded)?;
                    if total_bytes > MAX_ARCHIVE_BYTES
                        || sha256(&envelope_bytes) != *expected_bytes_hash
                    {
                        return Err(V04ExecutionForkStoreError::BranchBytesMismatch);
                    }
                    let envelope =
                        V04ExecutionPowEnvelope::decode(&envelope_bytes, graph.profile(), &params)?;
                    if pow_digest(&envelope.header, params.pow)? != *digest {
                        return Err(V04ExecutionForkStoreError::BranchDigestMismatch);
                    }
                    envelopes.push(envelope_bytes);
                }
                let replayed = V04ExecutionForkChoiceCandidate::rebuild_from_envelopes(
                    genesis,
                    params.clone(),
                    envelopes,
                    authenticator,
                )?;
                verify_manifest_canonical_state(&manifest, &replayed)?;
                (replayed, filename_generation)
            }
            None => {
                if has_branch_files(&branches_dir)? {
                    return Err(V04ExecutionForkStoreError::ManifestMissingWithBranches);
                }
                let bytes = encode_manifest(&graph, &params, 0)?;
                write_new_atomic(&manifests_dir.join(manifest_filename(0)), &bytes)?;
                (graph, 0)
            }
        };

        Ok(Self {
            directory,
            _writer_lock: writer_lock,
            fork_choice,
            params,
            generation,
            // A local open must not silently bypass a pending external CAS operation.
            // Only open_with_external_cas can resolve this flag with a verified signed read.
            // Persist the mode latch so a normal reopen cannot accidentally forget that the
            // store was placed under the external-CAS submission path.
            external_anchor_required: pending_exists || anchor_marker.is_some(),
        })
    }

    /// Exact local manifest commitment used as the value in the external CAS chain.
    /// The receipt-verification key and minimum object-generation floor must be provisioned
    /// out of band; this hash is not anti-rollback protection on its own.
    pub fn manifest_anchor(&self) -> Result<[u8; 32], V04ExecutionForkStoreError> {
        let path = self
            .directory
            .join(MANIFEST_DIR)
            .join(manifest_filename(self.generation));
        let bytes = read_bounded(&path, MAX_MANIFEST_BYTES)?;
        let manifest = decode_manifest(&bytes)?;
        if manifest.generation != self.generation {
            return Err(V04ExecutionForkStoreError::ManifestGenerationMismatch);
        }
        Ok(manifest_anchor_commitment(&bytes))
    }

    /// Stable scope binding for a provider bootstrap record. The initial record must be created
    /// by the separately administered provider/operator; this method does not provision a provider.
    pub fn external_cas_genesis_digest(&self) -> Result<[u8; 32], V04ExecutionForkStoreError> {
        compute_external_cas_genesis_digest(&self.fork_choice, &self.params)
    }

    /// Open/reconcile QZBE against a signed, pinned external anchor. A remote anchor may be the
    /// same generation as the caller's trusted record or its exact successor only; the minimum
    /// provider object-generation floor must be persisted outside this directory.
    pub fn open_with_external_cas<A, P, V>(
        directory: impl AsRef<Path>,
        genesis: MonetaryLedgerStateV04TransitionCandidate,
        params: ConsensusParameters,
        authenticator: &A,
        pin: &ExternalCasPin,
        client: &mut VerifiedExternalCasClient<P, V>,
        expected_record: Option<&ExternalCasRecord>,
        minimum_object_generation: u64,
    ) -> Result<(Self, ExternalCasRecord, u64), V04ExecutionForkStoreError>
    where
        A: TransactionAuthenticator,
        P: ExternalCasProviderTransport,
        V: MlDsa65Verifier,
    {
        if !client.is_pinned_to(pin) {
            return Err(V04ExecutionForkStoreError::ExternalAnchorMismatch);
        }
        let directory = directory.as_ref().to_path_buf();
        let mut store = Self::open(&directory, genesis.clone(), params.clone(), authenticator)?;
        let local_anchor = store.manifest_anchor()?;
        let genesis_digest = store.external_cas_genesis_digest()?;
        if pin.network_id != *store.fork_choice.profile().network_id()
            || pin.genesis_digest != genesis_digest
        {
            return Err(V04ExecutionForkStoreError::ExternalAnchorMismatch);
        }
        if let Some(marker) = load_anchor_mode_marker(&directory)? {
            validate_anchor_mode_marker_pin(&marker, pin)?;
        }
        // Latch anchored mode durably before contacting the provider. If this function fails,
        // or the process later crashes after a remote CAS commit but before local publication,
        // a plain reopen must already be blocked from local-only submission.
        persist_anchor_mode_marker(&store, pin)?;
        let (remote, object_generation) = store.read_external_anchor(
            pin,
            client,
            expected_record,
            minimum_object_generation,
            local_anchor,
        )?;
        let pending_path = directory.join(PENDING_MANIFEST_NAME);

        if fs::symlink_metadata(&pending_path).is_ok() {
            let pending_bytes = read_bounded(&pending_path, MAX_MANIFEST_BYTES)
                .map_err(|_| V04ExecutionForkStoreError::PendingManifestMalformed)?;
            let pending = decode_manifest(&pending_bytes)
                .map_err(|_| V04ExecutionForkStoreError::PendingManifestMalformed)?;
            let pending_anchor = manifest_anchor_commitment(&pending_bytes);
            let next_generation = store
                .generation
                .checked_add(1)
                .ok_or(V04ExecutionForkStoreError::ManifestSequenceOverflow)?;

            if remote.generation == store.generation
                && remote.next_state_digest == local_anchor
                && pending.generation == store.generation
                && pending_anchor == local_anchor
            {
                // A prior promotion may have published the exact committed generation but the
                // pending-name deletion may have been lost across a platform crash. The signed
                // remote anchor and already-replayed local manifest prove this is stale duplicate
                // intent, not a new operation; remove it idempotently.
                verify_manifest_profile(&pending, &store.fork_choice, &store.params)?;
                remove_file_synced(&pending_path)?;
                prune_unreferenced_branch_files(&store)?;
            } else if remote.generation == store.generation
                && remote.next_state_digest == local_anchor
                && pending.generation == next_generation
            {
                // The conditional write did not commit. The signed remote record still names
                // the active local state, so discard the pending manifest and any uncommitted
                // branches only after this anchor has been verified.
                remove_file_synced(&pending_path)?;
                prune_unreferenced_branch_files(&store)?;
            } else if remote.generation == next_generation
                && remote.previous_state_digest == local_anchor
                && remote.next_state_digest == pending_anchor
                && pending.generation == remote.generation
            {
                // The provider committed but the client lost the response (or crashed before
                // publishing the final local manifest). Only this exact remote commitment may
                // promote the pending bytes.
                if let Some(expected) = expected_record {
                    let expected_digest = expected.digest().map_err(|e| {
                        V04ExecutionForkStoreError::ExternalCasFailure(e.to_string())
                    })?;
                    if remote.previous_record_digest != expected_digest
                        && remote.digest().map_err(|e| {
                            V04ExecutionForkStoreError::ExternalCasFailure(e.to_string())
                        })? != expected_digest
                    {
                        return Err(V04ExecutionForkStoreError::ExternalAnchorMismatch);
                    }
                }
                verify_manifest_profile(&pending, &store.fork_choice, &store.params)?;
                let target = directory
                    .join(MANIFEST_DIR)
                    .join(manifest_filename(remote.generation));
                promote_pending_manifest(&pending_path, &target, &pending_bytes)?;
                drop(store);
                let mut reopened = Self::open(&directory, genesis, params, authenticator)?;
                if reopened.generation != remote.generation
                    || reopened.manifest_anchor()? != remote.next_state_digest
                {
                    return Err(V04ExecutionForkStoreError::ExternalAnchorMismatch);
                }
                persist_anchor_mode_marker(&reopened, pin)?;
                reopened.external_anchor_required = true;
                return Ok((reopened, remote, object_generation));
            } else {
                return Err(V04ExecutionForkStoreError::ExternalAnchorMismatch);
            }
        }

        let current_anchor = store.manifest_anchor()?;
        if remote.generation != store.generation || remote.next_state_digest != current_anchor {
            return Err(V04ExecutionForkStoreError::ExternalAnchorMismatch);
        }
        prune_unreferenced_branch_files(&store)?;
        persist_anchor_mode_marker(&store, pin)?;
        store.external_anchor_required = true;
        Ok((store, remote, object_generation))
    }

    fn read_external_anchor<P, V>(
        &self,
        pin: &ExternalCasPin,
        client: &mut VerifiedExternalCasClient<P, V>,
        expected_record: Option<&ExternalCasRecord>,
        minimum_object_generation: u64,
        local_anchor: [u8; 32],
    ) -> Result<(ExternalCasRecord, u64), V04ExecutionForkStoreError>
    where
        P: ExternalCasProviderTransport,
        V: MlDsa65Verifier,
    {
        let expected_record_digest = match expected_record {
            Some(record) => record
                .digest()
                .map_err(|e| V04ExecutionForkStoreError::ExternalCasFailure(e.to_string()))?,
            None => [0; 32],
        };
        let mut operation_hash = Sha256::new();
        operation_hash.update(CAS_READ_OPERATION_DOMAIN);
        operation_hash.update(local_anchor);
        operation_hash.update(expected_record_digest);
        operation_hash.update(minimum_object_generation.to_be_bytes());
        let operation_id: [u8; 32] = operation_hash.finalize().into();
        let mut request_hash = Sha256::new();
        request_hash.update(CAS_READ_OPERATION_DOMAIN);
        request_hash.update(b"request-digest\0");
        request_hash.update(operation_id);
        request_hash.update(local_anchor);
        let request_digest: [u8; 32] = request_hash.finalize().into();
        let request = client
            .fresh_read_request(operation_id, request_digest)
            .map_err(|e| V04ExecutionForkStoreError::ExternalCasFailure(e.to_string()))?;
        let min_generation = expected_record.map_or(0, |record| record.generation);
        let verified = client
            .read_current(
                &request,
                min_generation,
                minimum_object_generation,
                expected_record,
            )
            .map_err(|e| V04ExecutionForkStoreError::ExternalCasFailure(e.to_string()))?;
        if verified.record.provider_id != pin.provider_id
            || verified.record.network_id != *self.fork_choice.profile().network_id()
            || verified.record.genesis_digest != self.external_cas_genesis_digest()?
        {
            return Err(V04ExecutionForkStoreError::ExternalAnchorMismatch);
        }
        Ok((verified.record, verified.object_generation))
    }

    /// Submit only after confirming that a fresh signed provider read names the active QZMF
    /// manifest. The pending manifest is synced before CAS; the committed manifest is published
    /// only after the CAS receipt is cryptographically verified. Transport ambiguity leaves the
    /// pending record intact for open_with_external_cas recovery.
    pub fn submit_with_external_cas<A, P, V>(
        &mut self,
        envelope_bytes: &[u8],
        authenticator: &A,
        pin: &ExternalCasPin,
        client: &mut VerifiedExternalCasClient<P, V>,
        expected_record: &ExternalCasRecord,
        minimum_object_generation: u64,
    ) -> Result<V04ExecutionAnchoredSubmitOutcome, V04ExecutionForkStoreError>
    where
        A: TransactionAuthenticator,
        P: ExternalCasProviderTransport,
        V: MlDsa65Verifier,
    {
        if !self.external_anchor_required || !client.is_pinned_to(pin) {
            return Err(V04ExecutionForkStoreError::ExternalAnchorMismatch);
        }
        let pending_path = self.directory.join(PENDING_MANIFEST_NAME);
        if fs::symlink_metadata(&pending_path).is_ok() {
            return Err(V04ExecutionForkStoreError::PendingManifestExists);
        }
        let current_anchor = self.manifest_anchor()?;
        if expected_record.generation != self.generation
            || expected_record.next_state_digest != current_anchor
            || expected_record.provider_id != pin.provider_id
            || expected_record.network_id != *self.fork_choice.profile().network_id()
            || expected_record.genesis_digest != self.external_cas_genesis_digest()?
        {
            return Err(V04ExecutionForkStoreError::ExternalAnchorMismatch);
        }
        let (remote, object_generation) = self.read_external_anchor(
            pin,
            client,
            Some(expected_record),
            minimum_object_generation,
            current_anchor,
        )?;
        if remote
            .digest()
            .map_err(|e| V04ExecutionForkStoreError::ExternalCasFailure(e.to_string()))?
            != expected_record
                .digest()
                .map_err(|e| V04ExecutionForkStoreError::ExternalCasFailure(e.to_string()))?
            || remote.next_state_digest != current_anchor
        {
            return Err(V04ExecutionForkStoreError::ExternalAnchorMismatch);
        }

        if envelope_bytes.len() > MAX_ENCODED_V04_EXECUTION_POW_ENVELOPE_BYTES {
            return Err(V04ExecutionForkStoreError::ArchiveCapacityExceeded);
        }
        let decoded = V04ExecutionPowEnvelope::decode(
            envelope_bytes,
            self.fork_choice.profile(),
            &self.params,
        )?;
        let digest = pow_digest(&decoded.header, self.params.pow)?;
        let mut staged = self.fork_choice.clone();
        let outcome = staged.insert_encoded(envelope_bytes, authenticator)?;
        if staged.archive_len() == self.fork_choice.archive_len() {
            return Ok(V04ExecutionAnchoredSubmitOutcome {
                block: outcome,
                anchor_record: remote,
                receipt: None,
            });
        }
        let archive = staged
            .archive_envelopes_bounded(MAX_V04_EXECUTION_FORK_ARCHIVE_BLOCKS, MAX_ARCHIVE_BYTES)?;
        if archive.iter().map(Vec::len).sum::<usize>() > MAX_ARCHIVE_BYTES {
            return Err(V04ExecutionForkStoreError::ArchiveCapacityExceeded);
        }
        let branch_path =
            self.directory
                .join(BRANCH_DIR)
                .join(format!("{}{}", hex(&digest), BRANCH_SUFFIX));
        if branch_path.exists() {
            let existing =
                read_bounded(&branch_path, MAX_ENCODED_V04_EXECUTION_POW_ENVELOPE_BYTES)?;
            if existing != envelope_bytes {
                return Err(V04ExecutionForkStoreError::BranchBytesMismatch);
            }
            // Re-publish identical bytes so a branch created by an older, non-durable writer is
            // durable before a new manifest is allowed to reference it.
            write_replace_atomic(&branch_path, envelope_bytes)?;
        } else {
            write_new_atomic(&branch_path, envelope_bytes)?;
        }

        let next_generation = self
            .generation
            .checked_add(1)
            .ok_or(V04ExecutionForkStoreError::ManifestSequenceOverflow)?;
        let manifest_bytes = encode_manifest(&staged, &self.params, next_generation)?;
        let next_anchor = manifest_anchor_commitment(&manifest_bytes);
        let mut operation_hash = Sha256::new();
        operation_hash.update(CAS_WRITE_OPERATION_DOMAIN);
        operation_hash.update(current_anchor);
        operation_hash.update(next_anchor);
        operation_hash.update(digest);
        operation_hash.update(expected_record.generation.to_be_bytes());
        let operation_id: [u8; 32] = operation_hash.finalize().into();
        let mut nonce_hash = Sha256::new();
        nonce_hash.update(CAS_WRITE_NONCE_DOMAIN);
        nonce_hash.update(operation_id);
        nonce_hash.update(object_generation.to_be_bytes());
        let request_nonce: [u8; 32] = nonce_hash.finalize().into();
        let mut next_record = ExternalCasRecord {
            generation: expected_record
                .generation
                .checked_add(1)
                .ok_or(V04ExecutionForkStoreError::ManifestSequenceOverflow)?,
            provider_id: pin.provider_id,
            network_id: pin.network_id,
            genesis_digest: pin.genesis_digest,
            previous_record_digest: expected_record
                .digest()
                .map_err(|e| V04ExecutionForkStoreError::ExternalCasFailure(e.to_string()))?,
            previous_state_digest: current_anchor,
            next_state_digest: next_anchor,
            operation_id,
            request_digest: [0; 32],
        };
        let mut request = ExternalCasWriteRequest {
            request_nonce,
            operation_id,
            request_digest: [0; 32],
            expected_generation: expected_record.generation,
            expected_object_generation: object_generation,
            expected_record_digest: next_record.previous_record_digest,
            expected_state_digest: current_anchor,
            next_record: next_record.clone(),
        };
        request
            .bind_request_digest(pin)
            .map_err(|e| V04ExecutionForkStoreError::ExternalCasFailure(e.to_string()))?;
        next_record = request.next_record.clone();

        write_new_atomic(&pending_path, &manifest_bytes).map_err(|e| match e {
            V04ExecutionForkStoreError::Io(ref io_error)
                if io_error.kind() == io::ErrorKind::AlreadyExists =>
            {
                V04ExecutionForkStoreError::PendingManifestExists
            }
            other => other,
        })?;
        self.external_anchor_required = true;
        let receipt = client
            .compare_and_swap(&request)
            .map_err(|error| match error {
                ExternalCasClientError::Contract(ExternalCasError::CasConflict) => {
                    V04ExecutionForkStoreError::ExternalCasConflict
                }
                other => V04ExecutionForkStoreError::ExternalCasFailure(other.to_string()),
            })?;
        if !matches!(
            receipt.outcome,
            ExternalCasReceiptOutcome::Applied | ExternalCasReceiptOutcome::AlreadyApplied
        ) || receipt.generation != next_record.generation
            || receipt.record_digest
                != next_record
                    .digest()
                    .map_err(|e| V04ExecutionForkStoreError::ExternalCasFailure(e.to_string()))?
            || receipt.state_digest != next_anchor
        {
            return Err(V04ExecutionForkStoreError::ExternalAnchorMismatch);
        }

        let target = self
            .directory
            .join(MANIFEST_DIR)
            .join(manifest_filename(next_generation));
        promote_pending_manifest(&pending_path, &target, &manifest_bytes)?;
        self.fork_choice = staged;
        self.generation = next_generation;
        Ok(V04ExecutionAnchoredSubmitOutcome {
            block: outcome,
            anchor_record: next_record,
            receipt: Some(receipt),
        })
    }

    pub fn canonical_tip(&self) -> [u8; 32] {
        self.fork_choice.canonical_tip()
    }

    pub fn canonical_height(&self) -> u64 {
        self.fork_choice.canonical_height()
    }

    pub fn canonical_state_root(&self) -> Result<[u8; 32], V04ExecutionForkStoreError> {
        Ok(self.fork_choice.canonical_state().state_root()?)
    }

    pub fn archive_len(&self) -> usize {
        self.fork_choice.archive_len()
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn fork_choice(&self) -> &V04ExecutionForkChoiceCandidate {
        &self.fork_choice
    }

    pub fn submit<A: TransactionAuthenticator>(
        &mut self,
        envelope_bytes: &[u8],
        authenticator: &A,
    ) -> Result<V04ExecutionForkChoiceOutcome, V04ExecutionForkStoreError> {
        if self.external_anchor_required || self.directory.join(PENDING_MANIFEST_NAME).exists() {
            return Err(V04ExecutionForkStoreError::ExternalAnchorRequired);
        }
        if envelope_bytes.len() > MAX_ENCODED_V04_EXECUTION_POW_ENVELOPE_BYTES {
            return Err(V04ExecutionForkStoreError::ArchiveCapacityExceeded);
        }
        let decoded = V04ExecutionPowEnvelope::decode(
            envelope_bytes,
            self.fork_choice.profile(),
            &self.params,
        )?;
        let digest = pow_digest(&decoded.header, self.params.pow)?;
        let mut staged = self.fork_choice.clone();
        let outcome = staged.insert_encoded(envelope_bytes, authenticator)?;
        if staged.archive_len() == self.fork_choice.archive_len() {
            return Ok(outcome);
        }

        let archive = staged
            .archive_envelopes_bounded(MAX_V04_EXECUTION_FORK_ARCHIVE_BLOCKS, MAX_ARCHIVE_BYTES)?;
        if archive.iter().map(Vec::len).sum::<usize>() > MAX_ARCHIVE_BYTES {
            return Err(V04ExecutionForkStoreError::ArchiveCapacityExceeded);
        }

        let branch_path =
            self.directory
                .join(BRANCH_DIR)
                .join(format!("{}{}", hex(&digest), BRANCH_SUFFIX));
        if branch_path.exists() {
            let existing =
                read_bounded(&branch_path, MAX_ENCODED_V04_EXECUTION_POW_ENVELOPE_BYTES)?;
            if existing != envelope_bytes {
                return Err(V04ExecutionForkStoreError::BranchBytesMismatch);
            }
            // Re-publish identical bytes so a branch created by an older, non-durable writer is
            // durable before a new manifest is allowed to reference it.
            write_replace_atomic(&branch_path, envelope_bytes)?;
        } else {
            write_new_atomic(&branch_path, envelope_bytes)?;
        }

        let next_generation = self
            .generation
            .checked_add(1)
            .ok_or(V04ExecutionForkStoreError::ManifestSequenceOverflow)?;
        let manifest_bytes = encode_manifest(&staged, &self.params, next_generation)?;
        let manifest_path = self
            .directory
            .join(MANIFEST_DIR)
            .join(manifest_filename(next_generation));
        write_new_atomic(&manifest_path, &manifest_bytes)?;

        self.fork_choice = staged;
        self.generation = next_generation;
        Ok(outcome)
    }
}

fn encode_manifest(
    graph: &V04ExecutionForkChoiceCandidate,
    params: &ConsensusParameters,
    generation: u64,
) -> Result<Vec<u8>, V04ExecutionForkStoreError> {
    let envelopes = graph
        .archive_envelopes_bounded(MAX_V04_EXECUTION_FORK_ARCHIVE_BLOCKS, MAX_ARCHIVE_BYTES)?;
    let mut entries = BTreeMap::<[u8; 32], [u8; 32]>::new();
    let mut total_bytes = 0usize;
    for bytes in envelopes {
        total_bytes = total_bytes
            .checked_add(bytes.len())
            .ok_or(V04ExecutionForkStoreError::ArchiveCapacityExceeded)?;
        if total_bytes > MAX_ARCHIVE_BYTES {
            return Err(V04ExecutionForkStoreError::ArchiveCapacityExceeded);
        }
        let envelope = V04ExecutionPowEnvelope::decode(&bytes, graph.profile(), params)?;
        let digest = pow_digest(&envelope.header, params.pow)?;
        if entries.insert(digest, sha256(&bytes)).is_some() {
            return Err(V04ExecutionForkStoreError::BranchDigestMismatch);
        }
    }
    let state_root = graph.canonical_state().state_root()?;
    let mut bytes = Vec::with_capacity(
        MANIFEST_PREFIX_BYTES + entries.len() * MANIFEST_ENTRY_BYTES + MANIFEST_CHECKSUM_BYTES,
    );
    bytes.extend_from_slice(MANIFEST_MAGIC);
    bytes.extend_from_slice(&MANIFEST_VERSION.to_be_bytes());
    bytes.extend_from_slice(&generation.to_be_bytes());
    bytes.extend_from_slice(graph.profile().network_id());
    bytes.extend_from_slice(&graph.genesis_tip());
    bytes.extend_from_slice(graph.profile().profile_fingerprint());
    bytes.extend_from_slice(&pow_consensus_profile_fingerprint(params)?);
    bytes.extend_from_slice(&graph.canonical_tip());
    bytes.extend_from_slice(&graph.canonical_height().to_be_bytes());
    bytes.extend_from_slice(&state_root);
    bytes.extend_from_slice(
        &u32::try_from(entries.len())
            .map_err(|_| V04ExecutionForkStoreError::ArchiveCapacityExceeded)?
            .to_be_bytes(),
    );
    for (digest, envelope_hash) in entries {
        bytes.extend_from_slice(&digest);
        bytes.extend_from_slice(&envelope_hash);
    }
    let checksum = manifest_checksum(&bytes);
    bytes.extend_from_slice(&checksum);
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(V04ExecutionForkStoreError::ArchiveCapacityExceeded);
    }
    Ok(bytes)
}

fn decode_manifest(bytes: &[u8]) -> Result<Manifest, V04ExecutionForkStoreError> {
    if bytes.len() < MANIFEST_PREFIX_BYTES + MANIFEST_CHECKSUM_BYTES
        || bytes.len() > MAX_MANIFEST_BYTES
        || &bytes[..4] != MANIFEST_MAGIC
        || u16::from_be_bytes([bytes[4], bytes[5]]) != MANIFEST_VERSION
    {
        return Err(V04ExecutionForkStoreError::ManifestMalformed);
    }
    let expected_checksum = manifest_checksum(&bytes[..bytes.len() - MANIFEST_CHECKSUM_BYTES]);
    if bytes[bytes.len() - MANIFEST_CHECKSUM_BYTES..] != expected_checksum {
        return Err(V04ExecutionForkStoreError::ManifestChecksumMismatch);
    }
    let mut cursor = 6usize;
    let generation = take_u64(bytes, &mut cursor)?;
    let network_id = take_array::<32>(bytes, &mut cursor)?;
    let genesis_tip = take_array::<32>(bytes, &mut cursor)?;
    let profile_fingerprint = take_array::<32>(bytes, &mut cursor)?;
    let pow_fingerprint = take_array::<32>(bytes, &mut cursor)?;
    let canonical_tip = take_array::<32>(bytes, &mut cursor)?;
    let canonical_height = take_u64(bytes, &mut cursor)?;
    let canonical_state_root = take_array::<32>(bytes, &mut cursor)?;
    let count = take_u32(bytes, &mut cursor)? as usize;
    let expected_len = MANIFEST_PREFIX_BYTES
        .checked_add(
            count
                .checked_mul(MANIFEST_ENTRY_BYTES)
                .ok_or(V04ExecutionForkStoreError::ManifestMalformed)?,
        )
        .and_then(|value| value.checked_add(MANIFEST_CHECKSUM_BYTES))
        .ok_or(V04ExecutionForkStoreError::ManifestMalformed)?;
    if count > MAX_V04_EXECUTION_FORK_ARCHIVE_BLOCKS || bytes.len() != expected_len {
        return Err(V04ExecutionForkStoreError::ManifestMalformed);
    }
    let mut entries = Vec::with_capacity(count);
    let mut previous: Option<[u8; 32]> = None;
    for _ in 0..count {
        let digest = take_array::<32>(bytes, &mut cursor)?;
        let envelope_hash = take_array::<32>(bytes, &mut cursor)?;
        if previous.is_some_and(|last| last >= digest) {
            return Err(V04ExecutionForkStoreError::ManifestMalformed);
        }
        previous = Some(digest);
        entries.push((digest, envelope_hash));
    }
    if cursor != bytes.len() - MANIFEST_CHECKSUM_BYTES {
        return Err(V04ExecutionForkStoreError::ManifestMalformed);
    }
    Ok(Manifest {
        generation,
        network_id,
        genesis_tip,
        profile_fingerprint,
        pow_fingerprint,
        canonical_tip,
        canonical_height,
        canonical_state_root,
        entries,
    })
}

fn verify_manifest_profile(
    manifest: &Manifest,
    graph: &V04ExecutionForkChoiceCandidate,
    params: &ConsensusParameters,
) -> Result<(), V04ExecutionForkStoreError> {
    if manifest.network_id != *graph.profile().network_id()
        || manifest.genesis_tip != graph.genesis_tip()
        || manifest.profile_fingerprint != *graph.profile().profile_fingerprint()
        || manifest.pow_fingerprint != pow_consensus_profile_fingerprint(params)?
    {
        return Err(V04ExecutionForkStoreError::ManifestProfileMismatch);
    }
    Ok(())
}

fn verify_manifest_canonical_state(
    manifest: &Manifest,
    graph: &V04ExecutionForkChoiceCandidate,
) -> Result<(), V04ExecutionForkStoreError> {
    if manifest.canonical_tip != graph.canonical_tip()
        || manifest.canonical_height != graph.canonical_height()
        || manifest.canonical_state_root != graph.canonical_state().state_root()?
        || graph.archive_len() != manifest.entries.len()
    {
        return Err(V04ExecutionForkStoreError::CanonicalStateMismatch);
    }
    Ok(())
}

fn manifest_checksum(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(MANIFEST_DOMAIN);
    hash.update(bytes);
    hash.finalize().into()
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn manifest_filename(generation: u64) -> String {
    format!("{MANIFEST_PREFIX}{generation:020}{MANIFEST_SUFFIX}")
}

fn latest_manifest(directory: &Path) -> Result<Option<(u64, PathBuf)>, V04ExecutionForkStoreError> {
    let mut latest: Option<(u64, PathBuf)> = None;
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with(MANIFEST_PREFIX) || !name.ends_with(MANIFEST_SUFFIX) {
            continue;
        }
        // A newer manifest-shaped directory or symlink must not be silently skipped in
        // favour of an older generation: that would turn local corruption into rollback.
        if !entry.file_type()?.is_file() {
            return Err(V04ExecutionForkStoreError::ManifestMalformed);
        }
        let generation_text = &name[MANIFEST_PREFIX.len()..name.len() - MANIFEST_SUFFIX.len()];
        if generation_text.len() != 20 || !generation_text.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(V04ExecutionForkStoreError::ManifestMalformed);
        }
        let generation = generation_text
            .parse::<u64>()
            .map_err(|_| V04ExecutionForkStoreError::ManifestMalformed)?;
        if latest
            .as_ref()
            .is_none_or(|(current, _)| generation > *current)
        {
            latest = Some((generation, entry.path()));
        } else if latest
            .as_ref()
            .is_some_and(|(current, _)| generation == *current)
        {
            return Err(V04ExecutionForkStoreError::ManifestMalformed);
        }
    }
    Ok(latest)
}

fn has_branch_files(directory: &Path) -> Result<bool, V04ExecutionForkStoreError> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if !entry.file_name().to_string_lossy().ends_with(BRANCH_SUFFIX) {
            continue;
        }
        if !entry.file_type()?.is_file() {
            return Err(V04ExecutionForkStoreError::BranchDigestMismatch);
        }
        return Ok(true);
    }
    Ok(false)
}

fn clean_temporary_files(directory: &Path) -> Result<(), V04ExecutionForkStoreError> {
    let mut removed = false;
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        let path = entry.path();
        if name.starts_with(".qzbe-tmp-") {
            let metadata = fs::symlink_metadata(&path)?;
            if !is_reparse_point(&metadata) && metadata.is_file() {
                fs::remove_file(path)?;
                removed = true;
            }
        } else if name.starts_with(".qzbe-dir-tmp-") {
            let metadata = fs::symlink_metadata(&path)?;
            // Staging directories are created empty. Remove only an actual empty directory;
            // never recurse through a reparse point or delete an unexpected non-empty tree.
            if !is_reparse_point(&metadata) && metadata.is_dir() {
                fs::remove_dir(path)?;
                removed = true;
            }
        }
    }
    if removed {
        sync_directory(directory)?;
    }
    Ok(())
}

fn write_new_atomic(destination: &Path, bytes: &[u8]) -> Result<(), V04ExecutionForkStoreError> {
    let parent = destination
        .parent()
        .ok_or(V04ExecutionForkStoreError::ManifestMalformed)?;
    ensure_real_directory(parent)?;
    let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(".qzbe-tmp-{}-{id}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    let write_result = (|| -> io::Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        publish_new_atomic(&temporary, destination)?;
        Ok(())
    })();
    if let Err(error) = write_result {
        let _ = fs::remove_file(&temporary);
        return Err(V04ExecutionForkStoreError::Io(error));
    }
    Ok(())
}

/// Publish a fully synced sibling file without replacing an existing entry. On Unix, the
/// hard-link makes publication atomic and no-replace; syncing the directory before unlinking
/// the temporary name preserves a recoverable name across the two durability boundaries. On
/// Windows, MoveFileExW without REPLACE_EXISTING plus WRITE_THROUGH provides the equivalent move.
fn publish_new_atomic(source: &Path, destination: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
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
        let success = unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), MOVEFILE_WRITE_THROUGH) };
        if success == 0 {
            return Err(io::Error::last_os_error());
        }
        return Ok(());
    }
    #[cfg(unix)]
    {
        let destination_parent = destination.parent().unwrap_or_else(|| Path::new("."));
        let source_parent = source.parent().unwrap_or_else(|| Path::new("."));
        fs::hard_link(source, destination)?;
        sync_directory(destination_parent)?;
        fs::remove_file(source)?;
        sync_directory(source_parent)
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = (source, destination);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "durable no-replace publication is unsupported on this platform",
        ))
    }
}

/// Re-publish already-verified bytes over an existing manifest name and request the platform's
/// durability barrier again. Used when recovery finds an identical target left by an interrupted
/// promotion while the pending source still exists.
fn write_replace_atomic(
    destination: &Path,
    bytes: &[u8],
) -> Result<(), V04ExecutionForkStoreError> {
    let parent = destination
        .parent()
        .ok_or(V04ExecutionForkStoreError::ManifestMalformed)?;
    ensure_real_directory(parent)?;
    let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(".qzbe-tmp-{}-{id}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    let result = (|| -> io::Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        replace_existing_atomic(&temporary, destination)
    })();
    if let Err(error) = result {
        let _ = fs::remove_file(&temporary);
        return Err(V04ExecutionForkStoreError::Io(error));
    }
    Ok(())
}

#[cfg(windows)]
fn replace_existing_atomic(source: &Path, destination: &Path) -> io::Result<()> {
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

#[cfg(unix)]
fn replace_existing_atomic(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)?;
    sync_directory(destination.parent().unwrap_or_else(|| Path::new(".")))
}

#[cfg(not(any(unix, windows)))]
fn replace_existing_atomic(_source: &Path, _destination: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "durable replace publication is unsupported on this platform",
    ))
}

fn remove_file_synced(path: &Path) -> io::Result<()> {
    fs::remove_file(path)?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    sync_directory(parent)
}

/// Promote a CAS-pending manifest while retaining the recovery source until the committed
/// manifest name has crossed its durability boundary. If a previous attempt published the
/// exact target but failed before removing pending, accept only byte-identical replay.
fn promote_pending_manifest(
    pending_path: &Path,
    target_path: &Path,
    expected_bytes: &[u8],
) -> Result<(), V04ExecutionForkStoreError> {
    match fs::symlink_metadata(target_path) {
        Ok(_) => {
            let committed_bytes = read_bounded(target_path, MAX_MANIFEST_BYTES)?;
            if committed_bytes != expected_bytes {
                return Err(V04ExecutionForkStoreError::PendingManifestMalformed);
            }
            write_replace_atomic(target_path, expected_bytes)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            write_new_atomic(target_path, expected_bytes)?;
        }
        Err(error) => return Err(V04ExecutionForkStoreError::Io(error)),
    }
    remove_file_synced(pending_path)?;
    Ok(())
}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> io::Result<()> {
    File::open(directory)?.sync_all()
}

#[cfg(windows)]
fn sync_directory(_directory: &Path) -> io::Result<()> {
    // This implementation does not issue a directory-handle flush on Windows. State-changing
    // publications use MoveFileExW(MOVEFILE_WRITE_THROUGH); removals are limited to idempotent
    // cleanup and pending-marker housekeeping, so recovery must tolerate them reappearing.
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn sync_directory(_directory: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(unix)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(not(any(unix, windows)))]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

fn ensure_real_directory(path: &Path) -> Result<(), V04ExecutionForkStoreError> {
    let metadata = fs::symlink_metadata(path)?;
    if is_reparse_point(&metadata) || !metadata.is_dir() {
        return Err(V04ExecutionForkStoreError::UnsafeStorePath);
    }
    Ok(())
}

fn parent_or_dot(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[cfg(unix)]
fn create_directory_durable(path: &Path) -> io::Result<()> {
    fs::create_dir(path)?;
    sync_directory(parent_or_dot(path))
}

#[cfg(windows)]
fn create_directory_durable(path: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;
    #[link(name = "Kernel32")]
    extern "system" {
        fn MoveFileExW(existing: *const u16, new_name: *const u16, flags: u32) -> i32;
    }

    // Stage the directory beside its destination so the final same-volume rename can request
    // write-through metadata flushing. A process crash before publication can leave only an
    // unreferenced staging directory, never a partially initialized store directory.
    let parent = parent_or_dot(path);
    for _ in 0..1024 {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let temporary = parent.join(format!(".qzbe-dir-tmp-{}-{id}", std::process::id()));
        match fs::create_dir(&temporary) {
            Ok(()) => {
                let from: Vec<u16> = temporary.as_os_str().encode_wide().chain(Some(0)).collect();
                let to: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
                let success =
                    unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), MOVEFILE_WRITE_THROUGH) };
                if success != 0 {
                    return Ok(());
                }
                let error = io::Error::last_os_error();
                let _ = fs::remove_dir(&temporary);
                return Err(error);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique QZBE directory staging path",
    ))
}

#[cfg(not(any(unix, windows)))]
fn create_directory_durable(_path: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "durable store directory creation is unsupported on this platform",
    ))
}

/// Create each missing root component separately and sync the parent directory after each
/// creation. Existing ancestor symlinks may be intentional user path aliases; the final store
/// root itself must always be a real directory and not a reparse point.
fn ensure_store_root_directory(path: &Path) -> Result<(), V04ExecutionForkStoreError> {
    let mut missing = Vec::<PathBuf>::new();
    let mut current = path;
    loop {
        match fs::symlink_metadata(current) {
            Ok(_) => break,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                missing.push(current.to_path_buf());
                let parent = parent_or_dot(current);
                if parent == current {
                    return Err(V04ExecutionForkStoreError::UnsafeStorePath);
                }
                current = parent;
            }
            Err(error) => return Err(V04ExecutionForkStoreError::Io(error)),
        }
    }

    for directory in missing.iter().rev() {
        match create_directory_durable(directory) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(V04ExecutionForkStoreError::Io(error)),
        }
        ensure_real_directory(directory)?;
    }
    ensure_real_directory(path)
}

fn ensure_store_subdirectory(
    store_directory: &Path,
    name: &str,
) -> Result<PathBuf, V04ExecutionForkStoreError> {
    ensure_real_directory(store_directory)?;
    let path = store_directory.join(name);
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if is_reparse_point(&metadata) || !metadata.is_dir() {
                return Err(V04ExecutionForkStoreError::UnsafeStorePath);
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            match create_directory_durable(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(V04ExecutionForkStoreError::Io(error)),
            }
            ensure_real_directory(&path)?;
        }
        Err(error) => return Err(V04ExecutionForkStoreError::Io(error)),
    }
    Ok(path)
}

#[cfg(unix)]
fn same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(windows)]
fn same_file_identity(_left: &fs::Metadata, _right: &fs::Metadata) -> bool {
    // The file is opened with FILE_FLAG_OPEN_REPARSE_POINT and its handle metadata is checked
    // below. Stable file-index metadata APIs are not available on the pinned Rust 1.82 toolchain.
    true
}

#[cfg(not(any(unix, windows)))]
fn same_file_identity(_left: &fs::Metadata, _right: &fs::Metadata) -> bool {
    true
}

#[cfg(unix)]
fn open_regular_file_no_follow(path: &Path) -> io::Result<File> {
    use std::{ffi::CString, os::fd::FromRawFd, os::unix::ffi::OsStrExt};
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let descriptor = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

#[cfg(windows)]
fn open_regular_file_no_follow(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(not(any(unix, windows)))]
fn open_regular_file_no_follow(path: &Path) -> io::Result<File> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "symlink rejected",
        ));
    }
    File::open(path)
}

fn read_exact_bounded<R: Read>(
    reader: R,
    expected_length: usize,
    maximum: usize,
) -> Result<Vec<u8>, V04ExecutionForkStoreError> {
    if expected_length > maximum {
        return Err(V04ExecutionForkStoreError::ArchiveCapacityExceeded);
    }
    // Metadata length is only an observation: another local process may append to the file
    // after open(). Limit the actual read to maximum + 1 so growth cannot turn a bounded file
    // into an unbounded allocation. The extra byte distinguishes exact-limit data from growth.
    let read_limit = maximum
        .checked_add(1)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(V04ExecutionForkStoreError::ArchiveCapacityExceeded)?;
    let mut bytes = Vec::with_capacity(expected_length);
    reader.take(read_limit).read_to_end(&mut bytes)?;
    if bytes.len() != expected_length || bytes.len() > maximum {
        return Err(V04ExecutionForkStoreError::ManifestMalformed);
    }
    Ok(bytes)
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, V04ExecutionForkStoreError> {
    let metadata = fs::symlink_metadata(path)?;
    if is_reparse_point(&metadata) || !metadata.is_file() {
        return Err(V04ExecutionForkStoreError::ManifestMalformed);
    }
    let file = open_regular_file_no_follow(path)?;
    let opened_metadata = file.metadata()?;
    if is_reparse_point(&opened_metadata)
        || !opened_metadata.is_file()
        || !same_file_identity(&metadata, &opened_metadata)
    {
        return Err(V04ExecutionForkStoreError::ManifestMalformed);
    }
    let length = usize::try_from(opened_metadata.len())
        .map_err(|_| V04ExecutionForkStoreError::ArchiveCapacityExceeded)?;
    if length > maximum {
        return Err(V04ExecutionForkStoreError::ArchiveCapacityExceeded);
    }
    read_exact_bounded(file, length, maximum)
}

fn take_slice<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> Result<&'a [u8], V04ExecutionForkStoreError> {
    let end = cursor
        .checked_add(length)
        .ok_or(V04ExecutionForkStoreError::ManifestMalformed)?;
    if end > bytes.len() {
        return Err(V04ExecutionForkStoreError::ManifestMalformed);
    }
    let slice = &bytes[*cursor..end];
    *cursor = end;
    Ok(slice)
}
fn take_array<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], V04ExecutionForkStoreError> {
    take_slice(bytes, cursor, N)?
        .try_into()
        .map_err(|_| V04ExecutionForkStoreError::ManifestMalformed)
}
fn take_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, V04ExecutionForkStoreError> {
    Ok(u32::from_be_bytes(take_array(bytes, cursor)?))
}
fn take_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64, V04ExecutionForkStoreError> {
    Ok(u64::from_be_bytes(take_array(bytes, cursor)?))
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        consensus::{ConsensusParameters, Uint256},
        external_cas_anchor_candidate::{ExternalCasReadRequest, ExternalCasReceiptKind},
        monetary_genesis_v04_candidate::GenesisManifestV04,
        monetary_issuance_v04_candidate::V04MiningIssuanceScheduleCandidate,
        monetary_transition_v04_candidate::V04ConsensusProfileCandidate,
        state_machine::{AccountId, Transaction},
        v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate,
    };
    use libcrux_ml_dsa::ml_dsa_65::portable;
    #[cfg(windows)]
    use std::process::Command;
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    const NETWORK: [u8; 32] = [0x31; 32];
    const OWNER: [u8; 32] = [0xA7; 32];
    const RECIPIENT: [u8; 32] = [0xB2; 32];
    const MINER_A: [u8; 32] = [0xC4; 32];
    const MINER_B: [u8; 32] = [0xD5; 32];

    struct TestAuthenticator;
    impl TransactionAuthenticator for TestAuthenticator {
        fn verify(&self, _: &AccountId, _: &[u8; 32], signature: &[u8]) -> Result<(), ()> {
            if signature == [0x5A] {
                Ok(())
            } else {
                Err(())
            }
        }
    }

    #[derive(Clone, Copy)]
    enum CasBehavior {
        Apply,
        Conflict,
        ApplyThenLoseResponse,
    }

    struct MemoryCasProvider<F> {
        pin: ExternalCasPin,
        current: ExternalCasRecord,
        object_generation: u64,
        pending_manifest_path: PathBuf,
        behavior: CasBehavior,
        sign: F,
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
            let current = self.current.clone();
            let receipt = ExternalCasReceipt {
                kind: ExternalCasReceiptKind::Read,
                outcome: ExternalCasReceiptOutcome::Observed,
                generation: current.generation,
                object_generation: self.object_generation,
                provider_id: current.provider_id,
                network_id: current.network_id,
                genesis_digest: current.genesis_digest,
                receipt_key_id: self.pin.receipt_key_id,
                request_nonce: request.request_nonce,
                record_digest: current.digest().map_err(|e| e.to_string())?,
                previous_record_digest: current.previous_record_digest,
                previous_state_digest: current.previous_state_digest,
                state_digest: current.next_state_digest,
                operation_id: request.operation_id,
                request_digest: request.request_digest,
                signature: [0; crate::v4_fat1_trust_candidate::ML_DSA_65_SIGNATURE_BYTES],
            };
            Ok((current, (self.sign)(receipt)))
        }

        fn compare_and_swap(
            &mut self,
            request: &ExternalCasWriteRequest,
        ) -> Result<ExternalCasReceipt, Self::Error> {
            request.validate(&self.pin).map_err(|e| e.to_string())?;
            let pending = fs::read(&self.pending_manifest_path).map_err(|e| e.to_string())?;
            if manifest_anchor_commitment(&pending) != request.next_record.next_state_digest {
                return Err("CAS called before the exact pending manifest was durable".into());
            }
            let old_record_digest = self.current.digest().map_err(|e| e.to_string())?;
            if matches!(self.behavior, CasBehavior::Conflict) {
                self.object_generation = self
                    .object_generation
                    .checked_add(1)
                    .ok_or_else(|| "provider object generation overflow".to_string())?;
                let current = self.current.clone();
                let receipt = ExternalCasReceipt {
                    kind: ExternalCasReceiptKind::Commit,
                    outcome: ExternalCasReceiptOutcome::Conflict,
                    generation: current.generation,
                    object_generation: self.object_generation,
                    provider_id: current.provider_id,
                    network_id: current.network_id,
                    genesis_digest: current.genesis_digest,
                    receipt_key_id: self.pin.receipt_key_id,
                    request_nonce: request.request_nonce,
                    record_digest: old_record_digest,
                    previous_record_digest: current.previous_record_digest,
                    previous_state_digest: current.previous_state_digest,
                    state_digest: current.next_state_digest,
                    operation_id: request.operation_id,
                    request_digest: request.request_digest,
                    signature: [0; crate::v4_fat1_trust_candidate::ML_DSA_65_SIGNATURE_BYTES],
                };
                return Ok((self.sign)(receipt));
            }
            if self.current.generation != request.expected_generation
                || self.object_generation != request.expected_object_generation
                || old_record_digest != request.expected_record_digest
                || self.current.next_state_digest != request.expected_state_digest
            {
                return Err("memory CAS exact-successor precondition failed".into());
            }
            self.current = request.next_record.clone();
            self.object_generation = self
                .object_generation
                .checked_add(1)
                .ok_or_else(|| "provider object generation overflow".to_string())?;
            if matches!(self.behavior, CasBehavior::ApplyThenLoseResponse) {
                return Err("injected lost response after durable CAS commit".into());
            }
            let current = self.current.clone();
            let receipt = ExternalCasReceipt {
                kind: ExternalCasReceiptKind::Commit,
                outcome: ExternalCasReceiptOutcome::Applied,
                generation: current.generation,
                object_generation: self.object_generation,
                provider_id: current.provider_id,
                network_id: current.network_id,
                genesis_digest: current.genesis_digest,
                receipt_key_id: self.pin.receipt_key_id,
                request_nonce: request.request_nonce,
                record_digest: current.digest().map_err(|e| e.to_string())?,
                previous_record_digest: current.previous_record_digest,
                previous_state_digest: current.previous_state_digest,
                state_digest: current.next_state_digest,
                operation_id: request.operation_id,
                request_digest: request.request_digest,
                signature: [0; crate::v4_fat1_trust_candidate::ML_DSA_65_SIGNATURE_BYTES],
            };
            Ok((self.sign)(receipt))
        }
    }

    fn cas_fixture(
        path: &Path,
        store: &V04ExecutionForkStoreCandidate,
        behavior: CasBehavior,
    ) -> (
        ExternalCasPin,
        ExternalCasRecord,
        VerifiedExternalCasClient<
            MemoryCasProvider<impl Fn(ExternalCasReceipt) -> ExternalCasReceipt>,
            LibcruxMlDsa65VerifierCandidate,
        >,
    ) {
        let key_pair = portable::generate_key_pair([0x51u8; 32]);
        let pin = ExternalCasPin {
            provider_id: [0x71; 32],
            network_id: NETWORK,
            genesis_digest: store.external_cas_genesis_digest().unwrap(),
            receipt_key_id: [0x72; 32],
            receipt_public_key: *key_pair.verification_key.as_ref(),
        };
        let bootstrap = ExternalCasRecord {
            generation: 0,
            provider_id: pin.provider_id,
            network_id: pin.network_id,
            genesis_digest: pin.genesis_digest,
            previous_record_digest: [0; 32],
            previous_state_digest: [0; 32],
            next_state_digest: store.manifest_anchor().unwrap(),
            operation_id: [0x73; 32],
            request_digest: [0x74; 32],
        };
        let sign = move |mut receipt: ExternalCasReceipt| {
            let digest = receipt.signing_digest().unwrap();
            receipt.signature = *portable::sign(&key_pair.signing_key, &digest, &[], [0x75u8; 32])
                .unwrap()
                .as_ref();
            receipt
        };
        let provider = MemoryCasProvider {
            pin: pin.clone(),
            current: bootstrap.clone(),
            object_generation: 1,
            pending_manifest_path: path.join(PENDING_MANIFEST_NAME),
            behavior,
            sign,
        };
        let client =
            VerifiedExternalCasClient::new(pin.clone(), provider, LibcruxMlDsa65VerifierCandidate)
                .unwrap();
        (pin, bootstrap, client)
    }

    fn profile() -> (GenesisManifestV04, V04ConsensusProfileCandidate) {
        let manifest = GenesisManifestV04::new(NETWORK, OWNER).unwrap();
        let schedule = V04MiningIssuanceScheduleCandidate::new(10_000, 2).unwrap();
        let profile =
            V04ConsensusProfileCandidate::from_manifest_and_schedule(&manifest, schedule).unwrap();
        (manifest, profile)
    }

    fn params() -> ConsensusParameters {
        let mut parameters = ConsensusParameters::candidate_testnet().unwrap();
        parameters.initial_target = Uint256::MAX;
        parameters.pow_limit = Uint256::MAX;
        parameters
    }

    fn genesis(
        profile: &V04ConsensusProfileCandidate,
    ) -> MonetaryLedgerStateV04TransitionCandidate {
        let manifest = GenesisManifestV04::new(NETWORK, OWNER).unwrap();
        MonetaryLedgerStateV04TransitionCandidate::from_genesis_manifest(&manifest, profile)
            .unwrap()
    }

    fn transaction() -> Transaction {
        Transaction {
            network_id: NETWORK,
            sender: OWNER,
            recipient: RECIPIENT,
            nonce: 1,
            amount: 2_500,
            fee: 7,
            expires_at: 100,
            signature: vec![0x5A],
        }
    }

    fn temporary_directory() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "qzbe-store-test-{}-{nanos}-{sequence}",
            std::process::id()
        ))
    }

    #[cfg(unix)]
    fn create_directory_link(target: &std::path::Path, link: &std::path::Path) {
        std::os::unix::fs::symlink(target, link).unwrap();
    }

    #[cfg(windows)]
    fn create_directory_link(target: &std::path::Path, link: &std::path::Path) {
        let output = Command::new("cmd.exe")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .output()
            .expect("cmd.exe must be available for junction test");
        assert!(
            output.status.success(),
            "could not create test junction: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn open_rejects_reparse_point_store_root() {
        let (_manifest, profile) = profile();
        let parent = temporary_directory();
        let store_path = parent.join("store");
        let target_path = parent.join("target");
        fs::create_dir_all(&target_path).unwrap();
        create_directory_link(&target_path, &store_path);

        let result = V04ExecutionForkStoreCandidate::open(
            &store_path,
            genesis(&profile),
            params(),
            &TestAuthenticator,
        );
        assert!(matches!(
            result,
            Err(V04ExecutionForkStoreError::UnsafeStorePath)
        ));
        let _ = fs::remove_dir(&store_path);
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn open_rejects_reparse_point_store_subdirectories() {
        let (_manifest, profile) = profile();
        for name in [BRANCH_DIR, MANIFEST_DIR] {
            let store_path = temporary_directory();
            let target_path = temporary_directory();
            fs::create_dir_all(&store_path).unwrap();
            fs::create_dir_all(&target_path).unwrap();
            let link_path = store_path.join(name);
            create_directory_link(&target_path, &link_path);

            let result = V04ExecutionForkStoreCandidate::open(
                &store_path,
                genesis(&profile),
                params(),
                &TestAuthenticator,
            );
            assert!(
                matches!(result, Err(V04ExecutionForkStoreError::UnsafeStorePath)),
                "store must reject redirected subdirectory {name}"
            );

            let _ = fs::remove_dir(&link_path);
            fs::remove_dir_all(&store_path).unwrap();
            fs::remove_dir_all(&target_path).unwrap();
        }
    }

    #[test]
    fn new_atomic_publication_never_overwrites_an_existing_entry() {
        let directory = temporary_directory();
        fs::create_dir_all(&directory).unwrap();
        let destination = directory.join("already-committed.qzmf");
        fs::write(&destination, b"committed-bytes").unwrap();

        let result = write_new_atomic(&destination, b"replacement-bytes");
        assert!(matches!(result, Err(V04ExecutionForkStoreError::Io(_))));
        assert_eq!(fs::read(&destination).unwrap(), b"committed-bytes");
        assert_eq!(
            fs::read_dir(&directory).unwrap().count(),
            1,
            "failed publication must not leave a temporary file"
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn pending_promotion_is_idempotent_only_for_the_exact_published_manifest() {
        let directory = temporary_directory();
        let manifests = directory.join(MANIFEST_DIR);
        fs::create_dir_all(&manifests).unwrap();
        let pending = directory.join(PENDING_MANIFEST_NAME);
        let target = manifests.join(manifest_filename(1));
        let committed = b"exact-committed-manifest";
        fs::write(&pending, committed).unwrap();
        fs::write(&target, committed).unwrap();

        promote_pending_manifest(&pending, &target, committed).unwrap();
        assert!(!pending.exists());
        assert_eq!(fs::read(&target).unwrap(), committed);

        let pending_mismatch = directory.join("pending-mismatch");
        let target_mismatch = manifests.join(manifest_filename(2));
        fs::write(&pending_mismatch, b"pending-bytes").unwrap();
        fs::write(&target_mismatch, b"different-committed-bytes").unwrap();
        assert!(matches!(
            promote_pending_manifest(&pending_mismatch, &target_mismatch, b"pending-bytes"),
            Err(V04ExecutionForkStoreError::PendingManifestMalformed)
        ));
        assert_eq!(fs::read(&pending_mismatch).unwrap(), b"pending-bytes");
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn store_reopens_by_replaying_every_branch_and_preserves_canonical_state() {
        let (_manifest, profile) = profile();
        let genesis_state = genesis(&profile);
        let path = temporary_directory();
        let (expected_tip, expected_height, expected_root, expected_generation);
        {
            let mut store = V04ExecutionForkStoreCandidate::open(
                &path,
                genesis_state.clone(),
                params(),
                &TestAuthenticator,
            )
            .unwrap();
            assert_eq!(store.generation(), 0);
            let genesis_tip = store.canonical_tip();
            let a = store
                .fork_choice()
                .build_candidate_on(
                    genesis_tip,
                    1,
                    MINER_A,
                    vec![transaction()],
                    1,
                    &TestAuthenticator,
                )
                .unwrap();
            store.submit(&a, &TestAuthenticator).unwrap();
            let b = store
                .fork_choice()
                .build_candidate_on(genesis_tip, 2, MINER_B, vec![], 2, &TestAuthenticator)
                .unwrap();
            store.submit(&b, &TestAuthenticator).unwrap();
            assert_eq!(store.archive_len(), 2);
            let da = pow_digest(
                &V04ExecutionPowEnvelope::decode(&a, &profile, &params())
                    .unwrap()
                    .header,
                params().pow,
            )
            .unwrap();
            let db = pow_digest(
                &V04ExecutionPowEnvelope::decode(&b, &profile, &params())
                    .unwrap()
                    .header,
                params().pow,
            )
            .unwrap();
            let losing_tip = if store.canonical_tip() == da { db } else { da };
            let extension = store
                .fork_choice()
                .build_candidate_on(losing_tip, 3, MINER_B, vec![], 3, &TestAuthenticator)
                .unwrap();
            let outcome = store.submit(&extension, &TestAuthenticator).unwrap();
            assert!(outcome.canonical_changed);
            expected_tip = store.canonical_tip();
            expected_height = store.canonical_height();
            expected_root = store.canonical_state_root().unwrap();
            expected_generation = store.generation();
            assert_eq!(expected_height, 2);
            assert_eq!(expected_generation, 3);
        }
        {
            let store = V04ExecutionForkStoreCandidate::open(
                &path,
                genesis_state,
                params(),
                &TestAuthenticator,
            )
            .unwrap();
            assert_eq!(store.canonical_tip(), expected_tip);
            assert_eq!(store.canonical_height(), expected_height);
            assert_eq!(store.canonical_state_root().unwrap(), expected_root);
            assert_eq!(store.generation(), expected_generation);
            assert_eq!(store.archive_len(), 3);
        }
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn duplicate_submit_is_idempotent_and_does_not_publish_a_new_manifest() {
        let (_manifest, profile) = profile();
        let path = temporary_directory();
        let mut store = V04ExecutionForkStoreCandidate::open(
            &path,
            genesis(&profile),
            params(),
            &TestAuthenticator,
        )
        .unwrap();
        let encoded = store
            .fork_choice()
            .build_candidate_on(
                store.canonical_tip(),
                1,
                MINER_A,
                vec![],
                1,
                &TestAuthenticator,
            )
            .unwrap();
        store.submit(&encoded, &TestAuthenticator).unwrap();
        let generation = store.generation();
        let outcome = store.submit(&encoded, &TestAuthenticator).unwrap();
        assert!(!outcome.canonical_changed);
        assert_eq!(store.generation(), generation);
        assert_eq!(store.archive_len(), 1);
        drop(store);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn corrupt_latest_manifest_fails_closed_without_falling_back_to_an_older_generation() {
        let (_manifest, profile) = profile();
        let path = temporary_directory();
        {
            let store = V04ExecutionForkStoreCandidate::open(
                &path,
                genesis(&profile),
                params(),
                &TestAuthenticator,
            )
            .unwrap();
            assert_eq!(store.generation(), 0);
        }
        let manifest_path = path.join(MANIFEST_DIR).join(manifest_filename(0));
        let mut bytes = fs::read(&manifest_path).unwrap();
        *bytes.last_mut().unwrap() ^= 0x80;
        fs::write(&manifest_path, bytes).unwrap();
        assert!(matches!(
            V04ExecutionForkStoreCandidate::open(
                &path,
                genesis(&profile),
                params(),
                &TestAuthenticator,
            ),
            Err(V04ExecutionForkStoreError::ManifestChecksumMismatch)
        ));
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn missing_referenced_branch_fails_closed() {
        let (_manifest, profile) = profile();
        let path = temporary_directory();
        let genesis_state = genesis(&profile);
        let digest;
        {
            let mut store = V04ExecutionForkStoreCandidate::open(
                &path,
                genesis_state.clone(),
                params(),
                &TestAuthenticator,
            )
            .unwrap();
            let encoded = store
                .fork_choice()
                .build_candidate_on(
                    store.canonical_tip(),
                    1,
                    MINER_A,
                    vec![],
                    1,
                    &TestAuthenticator,
                )
                .unwrap();
            digest = pow_digest(
                &V04ExecutionPowEnvelope::decode(&encoded, &profile, &params())
                    .unwrap()
                    .header,
                params().pow,
            )
            .unwrap();
            store.submit(&encoded, &TestAuthenticator).unwrap();
        }
        fs::remove_file(
            path.join(BRANCH_DIR)
                .join(format!("{}{}", hex(&digest), BRANCH_SUFFIX)),
        )
        .unwrap();
        assert!(matches!(
            V04ExecutionForkStoreCandidate::open(
                &path,
                genesis_state,
                params(),
                &TestAuthenticator,
            ),
            Err(V04ExecutionForkStoreError::MissingBranch)
        ));
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn newer_manifest_shaped_directory_fails_closed_instead_of_loading_old_generation() {
        let (_manifest, profile) = profile();
        let path = temporary_directory();
        {
            let store = V04ExecutionForkStoreCandidate::open(
                &path,
                genesis(&profile),
                params(),
                &TestAuthenticator,
            )
            .unwrap();
            assert_eq!(store.generation(), 0);
        }
        fs::create_dir(path.join(MANIFEST_DIR).join(manifest_filename(1))).unwrap();
        assert!(matches!(
            V04ExecutionForkStoreCandidate::open(
                &path,
                genesis(&profile),
                params(),
                &TestAuthenticator,
            ),
            Err(V04ExecutionForkStoreError::ManifestMalformed)
        ));
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn branch_digest_path_must_be_a_regular_file() {
        let (_manifest, profile) = profile();
        let path = temporary_directory();
        let genesis_state = genesis(&profile);
        let digest;
        {
            let mut store = V04ExecutionForkStoreCandidate::open(
                &path,
                genesis_state.clone(),
                params(),
                &TestAuthenticator,
            )
            .unwrap();
            let encoded = store
                .fork_choice()
                .build_candidate_on(
                    store.canonical_tip(),
                    1,
                    MINER_A,
                    vec![],
                    1,
                    &TestAuthenticator,
                )
                .unwrap();
            digest = pow_digest(
                &V04ExecutionPowEnvelope::decode(&encoded, &profile, &params())
                    .unwrap()
                    .header,
                params().pow,
            )
            .unwrap();
            store.submit(&encoded, &TestAuthenticator).unwrap();
        }
        let branch_path = path
            .join(BRANCH_DIR)
            .join(format!("{}{}", hex(&digest), BRANCH_SUFFIX));
        fs::remove_file(&branch_path).unwrap();
        fs::create_dir(&branch_path).unwrap();
        assert!(matches!(
            V04ExecutionForkStoreCandidate::open(
                &path,
                genesis_state,
                params(),
                &TestAuthenticator,
            ),
            Err(V04ExecutionForkStoreError::ManifestMalformed)
        ));
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn bounded_reader_rejects_growth_without_reading_past_maximum_plus_one() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };

        struct GrowingReader(Arc<AtomicUsize>);
        impl Read for GrowingReader {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                let count = buffer.len().min(3);
                buffer[..count].fill(0xA5);
                self.0.fetch_add(count, Ordering::Relaxed);
                Ok(count)
            }
        }

        let bytes_read = Arc::new(AtomicUsize::new(0));
        let result = read_exact_bounded(GrowingReader(bytes_read.clone()), 0, 31);
        assert!(matches!(
            result,
            Err(V04ExecutionForkStoreError::ManifestMalformed)
        ));
        assert_eq!(bytes_read.load(Ordering::Relaxed), 32);
    }

    #[test]
    fn clean_temporary_files_removes_abandoned_root_publication_files() {
        let directory = temporary_directory();
        fs::create_dir_all(&directory).unwrap();
        let abandoned = directory.join(".qzbe-tmp-1234-7");
        let abandoned_directory = directory.join(".qzbe-dir-tmp-1234-8");
        let unrelated = directory.join("pending-manifest.bin");
        fs::write(&abandoned, b"incomplete").unwrap();
        fs::create_dir(&abandoned_directory).unwrap();
        fs::write(&unrelated, b"preserve").unwrap();

        clean_temporary_files(&directory).unwrap();

        assert!(!abandoned.exists());
        assert!(!abandoned_directory.exists());
        assert_eq!(fs::read(&unrelated).unwrap(), b"preserve");
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn no_follow_reader_opens_fifo_without_blocking() {
        use std::{ffi::CString, os::unix::ffi::OsStrExt};

        let directory = temporary_directory();
        fs::create_dir_all(&directory).unwrap();
        let fifo = directory.join("branch.pipe");
        let c_path = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        let created = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        assert_eq!(
            created,
            0,
            "mkfifo failed: {}",
            std::io::Error::last_os_error()
        );

        let opened = open_regular_file_no_follow(&fifo)
            .expect("O_NONBLOCK must allow safe metadata validation without a writer");
        assert!(!opened.metadata().unwrap().is_file());
        drop(opened);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn external_cas_commits_qzbe_manifest_only_after_verified_receipt_and_reopens() {
        let (_manifest, profile) = profile();
        let genesis_state = genesis(&profile);
        let parameters = params();
        let path = temporary_directory();
        let seed = V04ExecutionForkStoreCandidate::open(
            &path,
            genesis_state.clone(),
            parameters.clone(),
            &TestAuthenticator,
        )
        .unwrap();
        let (pin, bootstrap, mut client) = cas_fixture(&path, &seed, CasBehavior::Apply);
        drop(seed);

        let (mut store, observed, object_floor) =
            V04ExecutionForkStoreCandidate::open_with_external_cas(
                &path,
                genesis_state.clone(),
                parameters.clone(),
                &TestAuthenticator,
                &pin,
                &mut client,
                None,
                1,
            )
            .unwrap();
        assert_eq!(observed, bootstrap);
        assert_eq!(object_floor, 1);
        assert_eq!(store.generation(), 0);
        let envelope = store
            .fork_choice()
            .build_candidate_on(
                store.canonical_tip(),
                1,
                MINER_A,
                vec![],
                1,
                &TestAuthenticator,
            )
            .unwrap();
        let result = store
            .submit_with_external_cas(
                &envelope,
                &TestAuthenticator,
                &pin,
                &mut client,
                &bootstrap,
                object_floor,
            )
            .unwrap();
        assert_eq!(result.anchor_record.generation, 1);
        assert_eq!(store.generation(), 1);
        assert_eq!(store.canonical_height(), 1);
        let receipt = result.receipt.expect("changed state has a signed receipt");
        assert_eq!(receipt.outcome, ExternalCasReceiptOutcome::Applied);
        let current_record = result.anchor_record.clone();
        let next_floor = receipt.object_generation;
        drop(store);

        // Simulate a pending-name deletion that reappears after a platform crash. The bytes are
        // exactly the now-committed generation; recovery must reconcile it idempotently.
        let committed_manifest = fs::read(
            path.join(MANIFEST_DIR)
                .join(manifest_filename(current_record.generation)),
        )
        .unwrap();
        fs::write(path.join(PENDING_MANIFEST_NAME), committed_manifest).unwrap();

        // A regular reopen must not forget the externally anchored mode and accidentally accept
        // a local-only submit. A corrupted mode latch must fail closed as well.
        assert!(path.join(ANCHOR_MODE_MARKER_NAME).is_file());
        let mut plain_reopen = V04ExecutionForkStoreCandidate::open(
            &path,
            genesis_state.clone(),
            parameters.clone(),
            &TestAuthenticator,
        )
        .unwrap();
        assert!(plain_reopen.external_anchor_required);
        assert!(matches!(
            plain_reopen.submit(&envelope, &TestAuthenticator),
            Err(V04ExecutionForkStoreError::ExternalAnchorRequired)
        ));
        drop(plain_reopen);
        let marker_path = path.join(ANCHOR_MODE_MARKER_NAME);
        let marker_bytes = fs::read(&marker_path).unwrap();
        let mut corrupt_marker = marker_bytes.clone();
        corrupt_marker[12] ^= 0x80;
        fs::write(&marker_path, corrupt_marker).unwrap();
        assert!(matches!(
            V04ExecutionForkStoreCandidate::open(
                &path,
                genesis_state.clone(),
                parameters.clone(),
                &TestAuthenticator,
            ),
            Err(V04ExecutionForkStoreError::ExternalAnchorMismatch)
        ));
        fs::write(&marker_path, marker_bytes).unwrap();

        let (reopened, remote, observed_floor) =
            V04ExecutionForkStoreCandidate::open_with_external_cas(
                &path,
                genesis_state,
                parameters,
                &TestAuthenticator,
                &pin,
                &mut client,
                Some(&current_record),
                next_floor,
            )
            .unwrap();
        assert!(
            !path.join(PENDING_MANIFEST_NAME).exists(),
            "an already-committed duplicate pending manifest must be cleaned up"
        );
        assert_eq!(reopened.generation(), 1);
        assert_eq!(reopened.canonical_height(), 1);
        assert_eq!(
            reopened.manifest_anchor().unwrap(),
            remote.next_state_digest
        );
        assert_eq!(remote, current_record);
        assert_eq!(observed_floor, next_floor);
        drop(reopened);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn external_cas_conflict_keeps_old_manifest_and_signed_recovery_discards_pending() {
        let (_manifest, profile) = profile();
        let genesis_state = genesis(&profile);
        let parameters = params();
        let path = temporary_directory();
        let seed = V04ExecutionForkStoreCandidate::open(
            &path,
            genesis_state.clone(),
            parameters.clone(),
            &TestAuthenticator,
        )
        .unwrap();
        let (pin, bootstrap, mut client) = cas_fixture(&path, &seed, CasBehavior::Conflict);
        drop(seed);
        let (mut store, observed, floor) = V04ExecutionForkStoreCandidate::open_with_external_cas(
            &path,
            genesis_state.clone(),
            parameters.clone(),
            &TestAuthenticator,
            &pin,
            &mut client,
            None,
            1,
        )
        .unwrap();
        assert_eq!(observed, bootstrap);
        let envelope = store
            .fork_choice()
            .build_candidate_on(
                store.canonical_tip(),
                1,
                MINER_A,
                vec![],
                1,
                &TestAuthenticator,
            )
            .unwrap();
        assert!(matches!(
            store.submit_with_external_cas(
                &envelope,
                &TestAuthenticator,
                &pin,
                &mut client,
                &bootstrap,
                floor,
            ),
            Err(V04ExecutionForkStoreError::ExternalCasConflict)
        ));
        assert_eq!(store.generation(), 0);
        assert_eq!(store.canonical_height(), 0);
        assert!(path.join(PENDING_MANIFEST_NAME).exists());
        assert!(matches!(
            store.submit(&envelope, &TestAuthenticator),
            Err(V04ExecutionForkStoreError::ExternalAnchorRequired)
        ));
        drop(store);

        let (recovered, remote, object_generation) =
            V04ExecutionForkStoreCandidate::open_with_external_cas(
                &path,
                genesis_state,
                parameters,
                &TestAuthenticator,
                &pin,
                &mut client,
                Some(&bootstrap),
                floor,
            )
            .unwrap();
        assert_eq!(remote, bootstrap);
        assert_eq!(object_generation, floor + 1);
        assert_eq!(recovered.generation(), 0);
        assert_eq!(recovered.canonical_height(), 0);
        assert!(!path.join(PENDING_MANIFEST_NAME).exists());
        assert_eq!(fs::read_dir(path.join(BRANCH_DIR)).unwrap().count(), 0);
        drop(recovered);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn lost_cas_response_promotes_only_the_pending_manifest_named_by_signed_remote_record() {
        let (_manifest, profile) = profile();
        let genesis_state = genesis(&profile);
        let parameters = params();
        let path = temporary_directory();
        let seed = V04ExecutionForkStoreCandidate::open(
            &path,
            genesis_state.clone(),
            parameters.clone(),
            &TestAuthenticator,
        )
        .unwrap();
        let (pin, bootstrap, mut client) =
            cas_fixture(&path, &seed, CasBehavior::ApplyThenLoseResponse);
        drop(seed);
        let (mut store, _, floor) = V04ExecutionForkStoreCandidate::open_with_external_cas(
            &path,
            genesis_state.clone(),
            parameters.clone(),
            &TestAuthenticator,
            &pin,
            &mut client,
            None,
            1,
        )
        .unwrap();
        let envelope = store
            .fork_choice()
            .build_candidate_on(
                store.canonical_tip(),
                1,
                MINER_A,
                vec![],
                1,
                &TestAuthenticator,
            )
            .unwrap();
        assert!(matches!(
            store.submit_with_external_cas(
                &envelope,
                &TestAuthenticator,
                &pin,
                &mut client,
                &bootstrap,
                floor,
            ),
            Err(V04ExecutionForkStoreError::ExternalCasFailure(_))
        ));
        assert_eq!(store.generation(), 0);
        assert_eq!(store.canonical_height(), 0);
        assert!(path.join(PENDING_MANIFEST_NAME).exists());
        drop(store);

        let (recovered, remote, object_generation) =
            V04ExecutionForkStoreCandidate::open_with_external_cas(
                &path,
                genesis_state,
                parameters,
                &TestAuthenticator,
                &pin,
                &mut client,
                Some(&bootstrap),
                floor,
            )
            .unwrap();
        assert_eq!(remote.generation, 1);
        assert_eq!(recovered.generation(), 1);
        assert_eq!(recovered.canonical_height(), 1);
        assert_eq!(
            recovered.manifest_anchor().unwrap(),
            remote.next_state_digest
        );
        assert_eq!(object_generation, floor + 1);
        assert!(!path.join(PENDING_MANIFEST_NAME).exists());
        drop(recovered);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn store_manifest_encoding_rejects_trailing_bytes_and_unsorted_entries() {
        let (_manifest, profile) = profile();
        let mut graph = V04ExecutionForkChoiceCandidate::new(genesis(&profile), params()).unwrap();
        let genesis_tip = graph.genesis_tip();
        let a = graph
            .build_candidate_on(genesis_tip, 1, MINER_A, vec![], 1, &TestAuthenticator)
            .unwrap();
        graph.insert_encoded(&a, &TestAuthenticator).unwrap();
        let b = graph
            .build_candidate_on(genesis_tip, 2, MINER_B, vec![], 2, &TestAuthenticator)
            .unwrap();
        graph.insert_encoded(&b, &TestAuthenticator).unwrap();

        let bytes = encode_manifest(&graph, &params(), 2).unwrap();
        assert_eq!(decode_manifest(&bytes).unwrap().generation, 2);
        let mut trailing = bytes.clone();
        trailing.push(0);
        let checksum_start = trailing.len() - MANIFEST_CHECKSUM_BYTES;
        let checksum = manifest_checksum(&trailing[..checksum_start]);
        trailing[checksum_start..].copy_from_slice(&checksum);
        assert!(matches!(
            decode_manifest(&trailing),
            Err(V04ExecutionForkStoreError::ManifestMalformed)
        ));

        let mut unsorted = bytes.clone();
        let entries_start = MANIFEST_PREFIX_BYTES;
        let first = unsorted[entries_start..entries_start + MANIFEST_ENTRY_BYTES].to_vec();
        let second = unsorted
            [entries_start + MANIFEST_ENTRY_BYTES..entries_start + 2 * MANIFEST_ENTRY_BYTES]
            .to_vec();
        unsorted[entries_start..entries_start + MANIFEST_ENTRY_BYTES].copy_from_slice(&second);
        unsorted[entries_start + MANIFEST_ENTRY_BYTES..entries_start + 2 * MANIFEST_ENTRY_BYTES]
            .copy_from_slice(&first);
        let checksum_start = unsorted.len() - MANIFEST_CHECKSUM_BYTES;
        let checksum = manifest_checksum(&unsorted[..checksum_start]);
        unsorted[checksum_start..].copy_from_slice(&checksum);
        assert!(matches!(
            decode_manifest(&unsorted),
            Err(V04ExecutionForkStoreError::ManifestMalformed)
        ));
    }
}
