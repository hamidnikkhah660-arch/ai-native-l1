//! CP-0421 checkpoint-based durable QZBE suffix store candidate.
//!
//! Every open requires the trusted checkpoint to be supplied by the caller. A local checkpoint
//! checksum is never treated as authority or freshness. The store persists only suffix envelopes
//! and canonical metadata rooted at that exact checkpoint; independent external anti-rollback
//! anchoring and checkpoint trust selection remain responsibilities of the caller.

use crate::{
    consensus::ConsensusParameters,
    monetary_genesis_v04_candidate::GenesisManifestError,
    monetary_pow_v04_candidate::{
        qzbe_pow_digest, V04ExecutionForkChoiceCandidate, V04ExecutionForkChoiceOutcome,
        V04ExecutionPowEnvelope, V04ExecutionPowError,
        MAX_ENCODED_V04_EXECUTION_POW_ENVELOPE_BYTES, MAX_V04_EXECUTION_FORK_ARCHIVE_BLOCKS,
    },
    monetary_pow_v04_checkpoint_candidate::{
        QzbeCheckpointError, QzbeCheckpointRecord, QzbeCheckpointValidationContext,
    },
    state_machine::TransactionAuthenticator,
    store_writer_lock::StoreWriterLock,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const MANIFEST_MAGIC: &[u8; 4] = b"QZCS";
const MANIFEST_VERSION: u16 = 1;
const CHECKSUM_DOMAIN: &[u8] = b"QUANTUMZXB-QZBE-CHECKPOINT-STORE-MANIFEST-CHECKSUM-V1\0";
const LOCK_NAME: &str = "qzbe-checkpoint-store.lock";
const CHECKPOINT_DIR: &str = "checkpoints";
const BRANCH_DIR: &str = "branches";
const MANIFEST_DIR: &str = "manifests";
const CHECKPOINT_SUFFIX: &str = ".qzcp";
const BRANCH_SUFFIX: &str = ".qzbe";
const MANIFEST_PREFIX: &str = "qzcs-manifest-";
const MANIFEST_SUFFIX: &str = ".qzcs";
const CHECKSUM_BYTES: usize = 32;
const MANIFEST_PREFIX_BYTES: usize = 344;
const MANIFEST_ENTRY_BYTES: usize = 64;
const MAX_ARCHIVE_BYTES: usize = 64 * 1024 * 1024;
const MAX_MANIFEST_BYTES: usize = MANIFEST_PREFIX_BYTES
    + MAX_V04_EXECUTION_FORK_ARCHIVE_BLOCKS * MANIFEST_ENTRY_BYTES
    + CHECKSUM_BYTES;
static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
pub enum V04CheckpointForkStoreError {
    Io(io::Error),
    Checkpoint(QzbeCheckpointError),
    Pow(V04ExecutionPowError),
    StoreLocked,
    ManifestMalformed,
    ManifestChecksumMismatch,
    ManifestGenerationMismatch,
    CheckpointCommitmentMismatch,
    CheckpointFileMismatch,
    BranchDigestMismatch,
    BranchBytesMismatch,
    MissingBranch,
    UnexpectedFile,
    ArchiveCapacityExceeded,
    CanonicalStateMismatch,
    WrongNetwork,
    ProfileMismatch,
    ConsensusMismatch,
}

impl From<io::Error> for V04CheckpointForkStoreError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<QzbeCheckpointError> for V04CheckpointForkStoreError {
    fn from(value: QzbeCheckpointError) -> Self {
        Self::Checkpoint(value)
    }
}
impl From<GenesisManifestError> for V04CheckpointForkStoreError {
    fn from(value: GenesisManifestError) -> Self {
        Self::Checkpoint(QzbeCheckpointError::from(value))
    }
}
impl From<V04ExecutionPowError> for V04CheckpointForkStoreError {
    fn from(value: V04ExecutionPowError) -> Self {
        Self::Pow(value)
    }
}
impl std::fmt::Display for V04CheckpointForkStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for V04CheckpointForkStoreError {}

#[derive(Debug, Clone)]
struct CheckpointManifest {
    generation: u64,
    checkpoint_commitment: [u8; 32],
    network_id: [u8; 32],
    genesis_manifest_hash: [u8; 32],
    profile_fingerprint: [u8; 32],
    consensus_fingerprint: [u8; 32],
    base_tip: [u8; 32],
    base_height: u64,
    canonical_tip: [u8; 32],
    canonical_height: u64,
    state_root: [u8; 32],
    total_mined_atoms: u128,
    cumulative_chainwork: [u8; 32],
    entries: Vec<([u8; 32], [u8; 32])>,
}

/// Local durable checkpoint store for a bounded QZBE suffix. The checkpoint remains a trust
/// parameter: callers must supply the currently trusted record on every open.
pub struct V04ExecutionCheckpointForkStoreCandidate {
    directory: PathBuf,
    _writer_lock: StoreWriterLock,
    checkpoint: QzbeCheckpointRecord,
    checkpoint_commitment: [u8; 32],
    params: ConsensusParameters,
    fork_choice: V04ExecutionForkChoiceCandidate,
    generation: u64,
}

impl V04ExecutionCheckpointForkStoreCandidate {
    pub fn open_from_trusted_checkpoint<A: TransactionAuthenticator>(
        directory: impl AsRef<Path>,
        trusted_checkpoint: QzbeCheckpointRecord,
        context: &QzbeCheckpointValidationContext<'_>,
        params: ConsensusParameters,
        authenticator: &A,
    ) -> Result<Self, V04CheckpointForkStoreError> {
        trusted_checkpoint.validate(context)?;
        params
            .validate()
            .map_err(|_| V04CheckpointForkStoreError::ConsensusMismatch)?;
        if params != *context.params
            || crate::monetary_pow_v04_candidate::pow_consensus_profile_fingerprint(&params)?
                != trusted_checkpoint.consensus_profile_fingerprint
        {
            return Err(V04CheckpointForkStoreError::ConsensusMismatch);
        }

        let directory = directory.as_ref().to_path_buf();
        fs::create_dir_all(&directory)?;
        let writer_lock = StoreWriterLock::acquire(&directory, LOCK_NAME).map_err(|error| {
            if error.kind() == io::ErrorKind::WouldBlock {
                V04CheckpointForkStoreError::StoreLocked
            } else {
                V04CheckpointForkStoreError::Io(error)
            }
        })?;
        let checkpoints_dir = directory.join(CHECKPOINT_DIR);
        let branches_dir = directory.join(BRANCH_DIR);
        let manifests_dir = directory.join(MANIFEST_DIR);
        fs::create_dir_all(&checkpoints_dir)?;
        fs::create_dir_all(&branches_dir)?;
        fs::create_dir_all(&manifests_dir)?;

        let checkpoint_bytes = trusted_checkpoint.encode(context)?;
        let checkpoint_commitment = trusted_checkpoint.commitment(context)?;
        let checkpoint_path = checkpoints_dir.join(format!(
            "{}{}",
            hex(&checkpoint_commitment),
            CHECKPOINT_SUFFIX
        ));
        match read_optional_bounded(
            &checkpoint_path,
            crate::monetary_pow_v04_checkpoint_candidate::MAX_QZBE_CHECKPOINT_RECORD_BYTES,
        )? {
            Some(existing) if existing == checkpoint_bytes => {}
            Some(_) => return Err(V04CheckpointForkStoreError::CheckpointFileMismatch),
            None => write_new_atomic(&checkpoint_path, &checkpoint_bytes)?,
        }

        let existing = latest_manifest(&manifests_dir)?;
        let (fork_choice, generation) = if let Some(manifest) = existing {
            if manifest.checkpoint_commitment != checkpoint_commitment {
                return Err(V04CheckpointForkStoreError::CheckpointCommitmentMismatch);
            }
            if manifest.network_id != *context.manifest.network_id()
                || manifest.genesis_manifest_hash != context.manifest.manifest_hash()?
            {
                return Err(V04CheckpointForkStoreError::WrongNetwork);
            }
            if manifest.profile_fingerprint != *context.profile.profile_fingerprint() {
                return Err(V04CheckpointForkStoreError::ProfileMismatch);
            }
            let expected_consensus =
                crate::monetary_pow_v04_candidate::pow_consensus_profile_fingerprint(&params)?;
            if manifest.consensus_fingerprint != expected_consensus
                || manifest.base_tip != trusted_checkpoint.consensus_tip_digest
                || manifest.base_height != trusted_checkpoint.logical_height
            {
                return Err(V04CheckpointForkStoreError::ConsensusMismatch);
            }
            let envelopes =
                load_manifest_envelopes(&branches_dir, &manifest, context.profile, &params)?;
            let graph = V04ExecutionForkChoiceCandidate::rebuild_from_checkpoint(
                &trusted_checkpoint,
                context,
                params.clone(),
                envelopes,
                authenticator,
            )?;
            validate_manifest_graph(&manifest, &graph)?;
            (graph, manifest.generation)
        } else {
            reject_unreferenced_startup_files(&branches_dir)?;
            let graph = V04ExecutionForkChoiceCandidate::from_checkpoint_record(
                &trusted_checkpoint,
                context,
                params.clone(),
            )?;
            let bytes = encode_manifest_for_graph(
                0,
                checkpoint_commitment,
                &trusted_checkpoint,
                context,
                &params,
                &graph,
            )?;
            write_new_atomic(&manifests_dir.join(manifest_filename(0)), &bytes)?;
            (graph, 0)
        };

        Ok(Self {
            directory,
            _writer_lock: writer_lock,
            checkpoint: trusted_checkpoint,
            checkpoint_commitment,
            params,
            fork_choice,
            generation,
        })
    }

    /// Validate and commit one envelope. The caller must pass the same context used at open.
    pub fn submit<A: TransactionAuthenticator>(
        &mut self,
        envelope_bytes: &[u8],
        context: &QzbeCheckpointValidationContext<'_>,
        authenticator: &A,
    ) -> Result<V04ExecutionForkChoiceOutcome, V04CheckpointForkStoreError> {
        if envelope_bytes.len() > MAX_ENCODED_V04_EXECUTION_POW_ENVELOPE_BYTES
            || self.checkpoint.genesis_manifest_hash != context.manifest.manifest_hash()?
            || *context.profile.profile_fingerprint() != self.checkpoint.profile_fingerprint
            || self.checkpoint.commitment(context)? != self.checkpoint_commitment
        {
            return Err(V04CheckpointForkStoreError::CheckpointCommitmentMismatch);
        }
        let mut staged = self.fork_choice.clone();
        let outcome = staged.insert_encoded(envelope_bytes, authenticator)?;
        if staged.archive_len() == self.fork_choice.archive_len() {
            return Ok(outcome);
        }

        let envelopes = staged
            .archive_envelopes_bounded(MAX_V04_EXECUTION_FORK_ARCHIVE_BLOCKS, MAX_ARCHIVE_BYTES)?;
        let branches_dir = self.directory.join(BRANCH_DIR);
        for bytes in &envelopes {
            let envelope = V04ExecutionPowEnvelope::decode(bytes, staged.profile(), &self.params)?;
            let digest = qzbe_pow_digest(&envelope.header, &envelope.block, &self.params)?;
            let path = branches_dir.join(format!("{}{}", hex(&digest), BRANCH_SUFFIX));
            match read_optional_bounded(&path, MAX_ENCODED_V04_EXECUTION_POW_ENVELOPE_BYTES)? {
                Some(existing) if existing == *bytes => {}
                Some(_) => return Err(V04CheckpointForkStoreError::BranchBytesMismatch),
                None => write_new_atomic(&path, bytes)?,
            }
        }
        let next_generation = self
            .generation
            .checked_add(1)
            .ok_or(V04CheckpointForkStoreError::ManifestGenerationMismatch)?;
        let manifest_bytes = encode_manifest_for_graph(
            next_generation,
            self.checkpoint_commitment,
            &self.checkpoint,
            context,
            &self.params,
            &staged,
        )?;
        write_new_atomic(
            &self
                .directory
                .join(MANIFEST_DIR)
                .join(manifest_filename(next_generation)),
            &manifest_bytes,
        )?;
        self.fork_choice = staged;
        self.generation = next_generation;
        Ok(outcome)
    }

    pub fn canonical_height(&self) -> u64 {
        self.fork_choice.canonical_height()
    }
    pub fn canonical_tip(&self) -> [u8; 32] {
        self.fork_choice.canonical_tip()
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn checkpoint_commitment(&self) -> [u8; 32] {
        self.checkpoint_commitment
    }
    pub fn fork_choice(&self) -> &V04ExecutionForkChoiceCandidate {
        &self.fork_choice
    }
}

fn encode_manifest_for_graph(
    generation: u64,
    checkpoint_commitment: [u8; 32],
    checkpoint: &QzbeCheckpointRecord,
    context: &QzbeCheckpointValidationContext<'_>,
    params: &ConsensusParameters,
    graph: &V04ExecutionForkChoiceCandidate,
) -> Result<Vec<u8>, V04CheckpointForkStoreError> {
    let envelopes = graph
        .archive_envelopes_bounded(MAX_V04_EXECUTION_FORK_ARCHIVE_BLOCKS, MAX_ARCHIVE_BYTES)?;
    let mut entries = BTreeMap::<[u8; 32], [u8; 32]>::new();
    let mut total_bytes = 0usize;
    for bytes in envelopes {
        total_bytes = total_bytes
            .checked_add(bytes.len())
            .ok_or(V04CheckpointForkStoreError::ArchiveCapacityExceeded)?;
        if total_bytes > MAX_ARCHIVE_BYTES {
            return Err(V04CheckpointForkStoreError::ArchiveCapacityExceeded);
        }
        let envelope = V04ExecutionPowEnvelope::decode(&bytes, graph.profile(), params)?;
        let digest = qzbe_pow_digest(&envelope.header, &envelope.block, params)?;
        if entries.insert(digest, sha256(&bytes)).is_some() {
            return Err(V04CheckpointForkStoreError::BranchDigestMismatch);
        }
    }
    let state_root = graph
        .canonical_state()
        .state_root()
        .map_err(V04ExecutionPowError::from)?;
    let mut bytes = Vec::with_capacity(
        MANIFEST_PREFIX_BYTES + entries.len() * MANIFEST_ENTRY_BYTES + CHECKSUM_BYTES,
    );
    bytes.extend_from_slice(MANIFEST_MAGIC);
    bytes.extend_from_slice(&MANIFEST_VERSION.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.extend_from_slice(&0u32.to_be_bytes());
    bytes.extend_from_slice(&generation.to_be_bytes());
    bytes.extend_from_slice(&checkpoint_commitment);
    bytes.extend_from_slice(context.manifest.network_id());
    bytes.extend_from_slice(&context.manifest.manifest_hash()?);
    bytes.extend_from_slice(context.profile.profile_fingerprint());
    bytes.extend_from_slice(
        &crate::monetary_pow_v04_candidate::pow_consensus_profile_fingerprint(params)?,
    );
    bytes.extend_from_slice(&checkpoint.consensus_tip_digest);
    bytes.extend_from_slice(&checkpoint.logical_height.to_be_bytes());
    bytes.extend_from_slice(&graph.canonical_tip());
    bytes.extend_from_slice(&graph.canonical_height().to_be_bytes());
    bytes.extend_from_slice(&state_root);
    bytes.extend_from_slice(&graph.canonical_state().total_mined_atoms().to_be_bytes());
    bytes.extend_from_slice(&graph.canonical_cumulative_work().to_be_bytes());
    bytes.extend_from_slice(
        &u32::try_from(entries.len())
            .map_err(|_| V04CheckpointForkStoreError::ArchiveCapacityExceeded)?
            .to_be_bytes(),
    );
    if bytes.len() != MANIFEST_PREFIX_BYTES {
        return Err(V04CheckpointForkStoreError::ManifestMalformed);
    }
    for (digest, hash) in entries {
        bytes.extend_from_slice(&digest);
        bytes.extend_from_slice(&hash);
    }
    let length = bytes
        .len()
        .checked_add(CHECKSUM_BYTES)
        .ok_or(V04CheckpointForkStoreError::ArchiveCapacityExceeded)?;
    if length > MAX_MANIFEST_BYTES {
        return Err(V04CheckpointForkStoreError::ArchiveCapacityExceeded);
    }
    bytes[8..12].copy_from_slice(
        &u32::try_from(length)
            .map_err(|_| V04CheckpointForkStoreError::ArchiveCapacityExceeded)?
            .to_be_bytes(),
    );
    let checksum = manifest_checksum(&bytes);
    bytes.extend_from_slice(&checksum);
    Ok(bytes)
}

fn decode_manifest(bytes: &[u8]) -> Result<CheckpointManifest, V04CheckpointForkStoreError> {
    if bytes.len() < MANIFEST_PREFIX_BYTES + CHECKSUM_BYTES
        || bytes.len() > MAX_MANIFEST_BYTES
        || &bytes[..4] != MANIFEST_MAGIC
        || u16::from_be_bytes([bytes[4], bytes[5]]) != MANIFEST_VERSION
        || u16::from_be_bytes([bytes[6], bytes[7]]) != 0
        || u32::from_be_bytes(
            bytes[8..12]
                .try_into()
                .map_err(|_| V04CheckpointForkStoreError::ManifestMalformed)?,
        ) as usize
            != bytes.len()
    {
        return Err(V04CheckpointForkStoreError::ManifestMalformed);
    }
    if bytes[bytes.len() - CHECKSUM_BYTES..]
        != manifest_checksum(&bytes[..bytes.len() - CHECKSUM_BYTES])
    {
        return Err(V04CheckpointForkStoreError::ManifestChecksumMismatch);
    }
    let mut cursor = 12usize;
    let generation = take_u64(bytes, &mut cursor)?;
    let checkpoint_commitment = take_array::<32>(bytes, &mut cursor)?;
    let network_id = take_array::<32>(bytes, &mut cursor)?;
    let genesis_manifest_hash = take_array::<32>(bytes, &mut cursor)?;
    let profile_fingerprint = take_array::<32>(bytes, &mut cursor)?;
    let consensus_fingerprint = take_array::<32>(bytes, &mut cursor)?;
    let base_tip = take_array::<32>(bytes, &mut cursor)?;
    let base_height = take_u64(bytes, &mut cursor)?;
    let canonical_tip = take_array::<32>(bytes, &mut cursor)?;
    let canonical_height = take_u64(bytes, &mut cursor)?;
    let state_root = take_array::<32>(bytes, &mut cursor)?;
    let total_mined_atoms = u128::from_be_bytes(take_array::<16>(bytes, &mut cursor)?);
    let cumulative_chainwork = take_array::<32>(bytes, &mut cursor)?;
    let count = take_u32(bytes, &mut cursor)? as usize;
    let expected_len = MANIFEST_PREFIX_BYTES
        .checked_add(
            count
                .checked_mul(MANIFEST_ENTRY_BYTES)
                .ok_or(V04CheckpointForkStoreError::ManifestMalformed)?,
        )
        .and_then(|len| len.checked_add(CHECKSUM_BYTES))
        .ok_or(V04CheckpointForkStoreError::ManifestMalformed)?;
    if count > MAX_V04_EXECUTION_FORK_ARCHIVE_BLOCKS || expected_len != bytes.len() {
        return Err(V04CheckpointForkStoreError::ManifestMalformed);
    }
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        entries.push((
            take_array::<32>(bytes, &mut cursor)?,
            take_array::<32>(bytes, &mut cursor)?,
        ));
    }
    if entries.windows(2).any(|pair| pair[0].0 >= pair[1].0)
        || cursor != bytes.len() - CHECKSUM_BYTES
    {
        return Err(V04CheckpointForkStoreError::ManifestMalformed);
    }
    Ok(CheckpointManifest {
        generation,
        checkpoint_commitment,
        network_id,
        genesis_manifest_hash,
        profile_fingerprint,
        consensus_fingerprint,
        base_tip,
        base_height,
        canonical_tip,
        canonical_height,
        state_root,
        total_mined_atoms,
        cumulative_chainwork,
        entries,
    })
}

fn validate_manifest_graph(
    manifest: &CheckpointManifest,
    graph: &V04ExecutionForkChoiceCandidate,
) -> Result<(), V04CheckpointForkStoreError> {
    if graph.canonical_tip() != manifest.canonical_tip
        || graph.canonical_height() != manifest.canonical_height
        || graph
            .canonical_state()
            .state_root()
            .map_err(V04ExecutionPowError::from)?
            != manifest.state_root
        || graph.canonical_state().total_mined_atoms() != manifest.total_mined_atoms
        || graph.canonical_cumulative_work().to_be_bytes() != manifest.cumulative_chainwork
    {
        return Err(V04CheckpointForkStoreError::CanonicalStateMismatch);
    }
    Ok(())
}

fn load_manifest_envelopes(
    branches_dir: &Path,
    manifest: &CheckpointManifest,
    profile: &crate::monetary_transition_v04_candidate::V04ConsensusProfileCandidate,
    params: &ConsensusParameters,
) -> Result<Vec<Vec<u8>>, V04CheckpointForkStoreError> {
    let mut envelopes = Vec::with_capacity(manifest.entries.len());
    for (digest, expected_hash) in &manifest.entries {
        let path = branches_dir.join(format!("{}{}", hex(digest), BRANCH_SUFFIX));
        let bytes =
            read_bounded(&path, MAX_ENCODED_V04_EXECUTION_POW_ENVELOPE_BYTES).map_err(|error| {
                match error {
                    V04CheckpointForkStoreError::Io(ref io_error)
                        if io_error.kind() == io::ErrorKind::NotFound =>
                    {
                        V04CheckpointForkStoreError::MissingBranch
                    }
                    other => other,
                }
            })?;
        if sha256(&bytes) != *expected_hash {
            return Err(V04CheckpointForkStoreError::BranchDigestMismatch);
        }
        let envelope = V04ExecutionPowEnvelope::decode(&bytes, profile, params)?;
        if qzbe_pow_digest(&envelope.header, &envelope.block, params)? != *digest {
            return Err(V04CheckpointForkStoreError::BranchDigestMismatch);
        }
        envelopes.push(bytes);
    }
    Ok(envelopes)
}

fn latest_manifest(
    manifests_dir: &Path,
) -> Result<Option<CheckpointManifest>, V04CheckpointForkStoreError> {
    let mut latest: Option<(u64, PathBuf)> = None;
    for entry in fs::read_dir(manifests_dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            return Err(V04CheckpointForkStoreError::UnexpectedFile);
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with(MANIFEST_PREFIX) || !name.ends_with(MANIFEST_SUFFIX) {
            return Err(V04CheckpointForkStoreError::UnexpectedFile);
        }
        let middle = &name[MANIFEST_PREFIX.len()..name.len() - MANIFEST_SUFFIX.len()];
        let generation = middle
            .parse::<u64>()
            .map_err(|_| V04CheckpointForkStoreError::ManifestMalformed)?;
        if latest.as_ref().is_none_or(|(known, _)| generation > *known) {
            latest = Some((generation, entry.path()));
        }
    }
    let Some((generation_from_name, path)) = latest else {
        return Ok(None);
    };
    let manifest = decode_manifest(&read_bounded(&path, MAX_MANIFEST_BYTES)?)?;
    if manifest.generation != generation_from_name {
        return Err(V04CheckpointForkStoreError::ManifestGenerationMismatch);
    }
    Ok(Some(manifest))
}

fn reject_unreferenced_startup_files(
    branches_dir: &Path,
) -> Result<(), V04CheckpointForkStoreError> {
    for entry in fs::read_dir(branches_dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file()
            || !entry.file_name().to_string_lossy().ends_with(BRANCH_SUFFIX)
        {
            return Err(V04CheckpointForkStoreError::UnexpectedFile);
        }
        return Err(V04CheckpointForkStoreError::MissingBranch);
    }
    Ok(())
}

fn write_new_atomic(path: &Path, bytes: &[u8]) -> Result<(), V04CheckpointForkStoreError> {
    let directory = path
        .parent()
        .ok_or(V04CheckpointForkStoreError::UnexpectedFile)?;
    fs::create_dir_all(directory)?;
    let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("qzbe-checkpoint");
    let temp_path = directory.join(format!(".{name}.{}.{}.tmp", std::process::id(), id));
    let result = (|| -> Result<(), V04CheckpointForkStoreError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        if path.exists() {
            return Err(V04CheckpointForkStoreError::ManifestGenerationMismatch);
        }
        fs::rename(&temp_path, path)?;
        sync_parent(directory);
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}
fn sync_parent(directory: &Path) {
    if let Ok(file) = File::open(directory) {
        let _ = file.sync_all();
    }
}
fn read_optional_bounded(
    path: &Path,
    max_bytes: usize,
) -> Result<Option<Vec<u8>>, V04CheckpointForkStoreError> {
    match read_bounded(path, max_bytes) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(V04CheckpointForkStoreError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}
fn read_bounded(path: &Path, max_bytes: usize) -> Result<Vec<u8>, V04CheckpointForkStoreError> {
    let path_metadata = fs::symlink_metadata(path)?;
    if path_metadata.file_type().is_symlink() || !path_metadata.file_type().is_file() {
        return Err(V04CheckpointForkStoreError::UnexpectedFile);
    }
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > max_bytes as u64 {
        return Err(V04CheckpointForkStoreError::ArchiveCapacityExceeded);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(max_bytes as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(V04CheckpointForkStoreError::ArchiveCapacityExceeded);
    }
    Ok(bytes)
}
fn manifest_checksum(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(CHECKSUM_DOMAIN);
    hash.update(bytes);
    hash.finalize().into()
}
fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn manifest_filename(generation: u64) -> String {
    format!("{MANIFEST_PREFIX}{generation:020}{MANIFEST_SUFFIX}")
}
fn take_array<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], V04CheckpointForkStoreError> {
    let end = cursor
        .checked_add(N)
        .ok_or(V04CheckpointForkStoreError::ManifestMalformed)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(V04CheckpointForkStoreError::ManifestMalformed)?
        .try_into()
        .map_err(|_| V04CheckpointForkStoreError::ManifestMalformed)?;
    *cursor = end;
    Ok(value)
}
fn take_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, V04CheckpointForkStoreError> {
    Ok(u32::from_be_bytes(take_array(bytes, cursor)?))
}
fn take_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64, V04CheckpointForkStoreError> {
    Ok(u64::from_be_bytes(take_array(bytes, cursor)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        consensus::Uint256,
        monetary_genesis_v04_candidate::GenesisManifestV04,
        monetary_issuance_v04_candidate::V04MiningIssuanceScheduleCandidate,
        monetary_transition_v04_candidate::{
            MonetaryLedgerStateV04TransitionCandidate, V04ConsensusProfileCandidate,
        },
        private_testnet_driver::TargetHistory,
        state_machine::{AccountId, TransactionAuthenticator},
    };
    use std::{
        env,
        time::{SystemTime, UNIX_EPOCH},
    };

    const NETWORK: [u8; 32] = [0x31; 32];
    const OWNER: [u8; 32] = [0xA7; 32];

    struct NoTransactionAuth;
    impl TransactionAuthenticator for NoTransactionAuth {
        fn verify(&self, _: &AccountId, _: &[u8; 32], _: &[u8]) -> Result<(), ()> {
            Err(())
        }
    }

    fn temp_root() -> PathBuf {
        let tick = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "qzbe_checkpoint_store_{}_{}",
            std::process::id(),
            tick
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn fixture() -> (
        GenesisManifestV04,
        V04ConsensusProfileCandidate,
        ConsensusParameters,
        QzbeCheckpointRecord,
    ) {
        let manifest = GenesisManifestV04::new(NETWORK, OWNER).unwrap();
        let schedule = V04MiningIssuanceScheduleCandidate::new(35_673_515_981, 4_204_800).unwrap();
        let profile =
            V04ConsensusProfileCandidate::from_manifest_and_schedule(&manifest, schedule).unwrap();
        let mut params = ConsensusParameters::candidate_testnet().unwrap();
        params.initial_target = crate::consensus::Uint256::from_be_bytes([0xEF; 32]);
        params.pow_limit = crate::consensus::Uint256::MAX;
        params.pow.memory_kib = 8 * 1024;
        let state =
            MonetaryLedgerStateV04TransitionCandidate::from_genesis_manifest(&manifest, &profile)
                .unwrap();
        let history = TargetHistory::new(params.clone())
            .unwrap()
            .checkpoint_snapshot()
            .unwrap();
        let context = QzbeCheckpointValidationContext {
            manifest: &manifest,
            profile: &profile,
            params: &params,
        };
        let checkpoint = QzbeCheckpointRecord::from_state(
            &context,
            &state,
            state.ledger().tip_hash(),
            Uint256::ZERO,
            [0; 32],
            history,
        )
        .unwrap();
        (manifest, profile, params, checkpoint)
    }

    #[test]
    fn checkpoint_store_persists_and_replays_block_2017_from_trusted_checkpoint_2016() {
        let manifest = GenesisManifestV04::new(NETWORK, OWNER).unwrap();
        let schedule = V04MiningIssuanceScheduleCandidate::new(35_673_515_981, 4_204_800).unwrap();
        let profile =
            V04ConsensusProfileCandidate::from_manifest_and_schedule(&manifest, schedule).unwrap();
        let mut params = ConsensusParameters::candidate_testnet().unwrap();
        params.initial_target = crate::consensus::Uint256::from_be_bytes([0xEF; 32]);
        params.pow_limit = crate::consensus::Uint256::MAX;
        params.pow.memory_kib = 8 * 1024;
        let mut state =
            MonetaryLedgerStateV04TransitionCandidate::from_genesis_manifest(&manifest, &profile)
                .unwrap();
        let mut history = TargetHistory::new(params.clone()).unwrap();
        for height in 1..=2_016u64 {
            let timestamp = height * params.target_block_time_secs;
            let block = state.build_next_block(timestamp, [0x23; 32]).unwrap();
            state.apply_block(&block).unwrap();
            let target = history.expected_target(height, None).unwrap();
            history.record_next(height, target, timestamp).unwrap();
        }
        let context = QzbeCheckpointValidationContext {
            manifest: &manifest,
            profile: &profile,
            params: &params,
        };
        let checkpoint = QzbeCheckpointRecord::from_state(
            &context,
            &state,
            [0x91; 32],
            Uint256::ONE,
            [0x42; 32],
            history.checkpoint_snapshot().unwrap(),
        )
        .unwrap();

        let dir = temp_root();
        let mut store = V04ExecutionCheckpointForkStoreCandidate::open_from_trusted_checkpoint(
            &dir,
            checkpoint.clone(),
            &context,
            params.clone(),
            &NoTransactionAuth,
        )
        .unwrap();
        assert_eq!(store.canonical_height(), 2_016);
        let encoded = store
            .fork_choice()
            .mine_candidate_on(
                checkpoint.consensus_tip_digest,
                2_017 * params.target_block_time_secs,
                [0x24; 32],
                Vec::new(),
                1,
                crate::monetary_pow_v04_candidate::MAX_QZBE_MINING_ATTEMPTS,
                &NoTransactionAuth,
                || false,
            )
            .unwrap();
        let outcome = store
            .submit(&encoded, &context, &NoTransactionAuth)
            .unwrap();
        assert!(outcome.canonical_changed);
        assert_eq!(store.canonical_height(), 2_017);
        let expected_tip = store.canonical_tip();
        let expected_root = store.fork_choice().canonical_state().state_root().unwrap();
        drop(store);

        let reopened = V04ExecutionCheckpointForkStoreCandidate::open_from_trusted_checkpoint(
            &dir,
            checkpoint,
            &context,
            params.clone(),
            &NoTransactionAuth,
        )
        .unwrap();
        assert_eq!(reopened.canonical_height(), 2_017);
        assert_eq!(reopened.canonical_tip(), expected_tip);
        assert_eq!(
            reopened
                .fork_choice()
                .canonical_state()
                .state_root()
                .unwrap(),
            expected_root
        );
        drop(reopened);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn checkpoint_store_rejects_manifest_checksum_tampering() {
        let (manifest, profile, params, checkpoint) = fixture();
        let context = QzbeCheckpointValidationContext {
            manifest: &manifest,
            profile: &profile,
            params: &params,
        };
        let dir = temp_root();
        let store = V04ExecutionCheckpointForkStoreCandidate::open_from_trusted_checkpoint(
            &dir,
            checkpoint.clone(),
            &context,
            params.clone(),
            &NoTransactionAuth,
        )
        .unwrap();
        drop(store);
        let manifest_path = dir.join(MANIFEST_DIR).join(manifest_filename(0));
        let mut bytes = fs::read(&manifest_path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(&manifest_path, bytes).unwrap();

        let result = V04ExecutionCheckpointForkStoreCandidate::open_from_trusted_checkpoint(
            &dir,
            checkpoint,
            &context,
            params.clone(),
            &NoTransactionAuth,
        );
        assert!(matches!(
            result,
            Err(V04CheckpointForkStoreError::ManifestChecksumMismatch)
        ));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn checkpoint_store_rejects_branch_byte_tampering_before_replay() {
        let (manifest, profile, params, checkpoint) = fixture();
        let context = QzbeCheckpointValidationContext {
            manifest: &manifest,
            profile: &profile,
            params: &params,
        };
        let dir = temp_root();
        let mut store = V04ExecutionCheckpointForkStoreCandidate::open_from_trusted_checkpoint(
            &dir,
            checkpoint.clone(),
            &context,
            params.clone(),
            &NoTransactionAuth,
        )
        .unwrap();
        let encoded = store
            .fork_choice()
            .mine_candidate_on(
                store.canonical_tip(),
                1_800_000_000,
                [0x24; 32],
                Vec::new(),
                1,
                crate::monetary_pow_v04_candidate::MAX_QZBE_MINING_ATTEMPTS,
                &NoTransactionAuth,
                || false,
            )
            .unwrap();
        store
            .submit(&encoded, &context, &NoTransactionAuth)
            .unwrap();
        drop(store);

        let branch_path = fs::read_dir(dir.join(BRANCH_DIR))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let mut bytes = fs::read(&branch_path).unwrap();
        bytes[0] ^= 1;
        fs::write(&branch_path, bytes).unwrap();

        let result = V04ExecutionCheckpointForkStoreCandidate::open_from_trusted_checkpoint(
            &dir,
            checkpoint,
            &context,
            params.clone(),
            &NoTransactionAuth,
        );
        assert!(matches!(
            result,
            Err(V04CheckpointForkStoreError::BranchDigestMismatch)
        ));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn checkpoint_store_commits_suffix_and_reopens_only_with_exact_trusted_checkpoint() {
        let (manifest, profile, params, checkpoint) = fixture();
        let context = QzbeCheckpointValidationContext {
            manifest: &manifest,
            profile: &profile,
            params: &params,
        };
        let dir = temp_root();
        let mut store = V04ExecutionCheckpointForkStoreCandidate::open_from_trusted_checkpoint(
            &dir,
            checkpoint.clone(),
            &context,
            params.clone(),
            &NoTransactionAuth,
        )
        .unwrap();
        let checkpoint_tip = store.canonical_tip();
        assert_eq!(store.canonical_height(), 0);
        let next = store
            .fork_choice()
            .mine_candidate_on(
                checkpoint_tip,
                1_800_000_000,
                [0x24; 32],
                Vec::new(),
                1,
                crate::monetary_pow_v04_candidate::MAX_QZBE_MINING_ATTEMPTS,
                &NoTransactionAuth,
                || false,
            )
            .unwrap();
        let admitted = store.submit(&next, &context, &NoTransactionAuth).unwrap();
        assert!(admitted.canonical_changed);
        assert_eq!(store.canonical_height(), 1);
        let expected_tip = store.canonical_tip();
        let expected_root = store.fork_choice().canonical_state().state_root().unwrap();
        drop(store);

        let mut wrong_checkpoint = checkpoint.clone();
        wrong_checkpoint.state_root[0] ^= 1;
        assert!(
            V04ExecutionCheckpointForkStoreCandidate::open_from_trusted_checkpoint(
                &dir,
                wrong_checkpoint,
                &context,
                params.clone(),
                &NoTransactionAuth,
            )
            .is_err()
        );

        let reopened = V04ExecutionCheckpointForkStoreCandidate::open_from_trusted_checkpoint(
            &dir,
            checkpoint,
            &context,
            params.clone(),
            &NoTransactionAuth,
        )
        .unwrap();
        assert_eq!(reopened.canonical_tip(), expected_tip);
        assert_eq!(reopened.canonical_height(), 1);
        assert_eq!(
            reopened
                .fork_choice()
                .canonical_state()
                .state_root()
                .unwrap(),
            expected_root
        );
        drop(reopened);
        fs::remove_dir_all(dir).unwrap();
    }
}
