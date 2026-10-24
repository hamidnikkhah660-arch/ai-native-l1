//! CP-0406 candidate persistent archive for QZBE / QZB4 v2 execution forks.
//!
//! This store persists bounded, individually digest-named envelopes and immutable manifest
//! generations. On open, it verifies exact bytes and rebuilds the complete branch graph from
//! Genesis before exposing a canonical tip. The manifest history avoids in-place replacement;
//! it is still local state and is vulnerable to restoring the whole directory. No external CAS
//! provider is implemented here, and this module is not wired into the live node/Mainnet.
use crate::{
    consensus::{pow_digest, ConsensusError, ConsensusParameters},
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
}

impl V04ExecutionForkStoreCandidate {
    pub fn open<A: TransactionAuthenticator>(
        directory: impl AsRef<Path>,
        genesis: MonetaryLedgerStateV04TransitionCandidate,
        params: ConsensusParameters,
        authenticator: &A,
    ) -> Result<Self, V04ExecutionForkStoreError> {
        let directory = directory.as_ref().to_path_buf();
        fs::create_dir_all(&directory)?;
        let writer_lock = StoreWriterLock::acquire(&directory, LOCK_NAME).map_err(|error| {
            if error.kind() == io::ErrorKind::WouldBlock {
                V04ExecutionForkStoreError::StoreLocked
            } else {
                V04ExecutionForkStoreError::Io(error)
            }
        })?;
        let branches_dir = directory.join(BRANCH_DIR);
        let manifests_dir = directory.join(MANIFEST_DIR);
        fs::create_dir_all(&branches_dir)?;
        fs::create_dir_all(&manifests_dir)?;
        clean_temporary_files(&branches_dir)?;
        clean_temporary_files(&manifests_dir)?;

        let graph = V04ExecutionForkChoiceCandidate::new(genesis.clone(), params.clone())?;
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
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if entry.file_type()?.is_file()
            && entry
                .file_name()
                .to_string_lossy()
                .starts_with(".qzbe-tmp-")
        {
            fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

fn write_new_atomic(destination: &Path, bytes: &[u8]) -> Result<(), V04ExecutionForkStoreError> {
    let parent = destination
        .parent()
        .ok_or(V04ExecutionForkStoreError::ManifestMalformed)?;
    fs::create_dir_all(parent)?;
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
        fs::rename(&temporary, destination)?;
        Ok(())
    })();
    if let Err(error) = write_result {
        let _ = fs::remove_file(&temporary);
        return Err(V04ExecutionForkStoreError::Io(error));
    }
    Ok(())
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, V04ExecutionForkStoreError> {
    // Do not follow symlinks for branch or manifest objects. A digest-valid target outside
    // the store directory is not itself an approved store object.
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(V04ExecutionForkStoreError::ManifestMalformed);
    }
    let length = usize::try_from(metadata.len())
        .map_err(|_| V04ExecutionForkStoreError::ArchiveCapacityExceeded)?;
    if length > maximum {
        return Err(V04ExecutionForkStoreError::ArchiveCapacityExceeded);
    }
    let mut file = File::open(path)?;
    let mut bytes = Vec::with_capacity(length);
    file.read_to_end(&mut bytes)?;
    if bytes.len() != length || bytes.len() > maximum {
        return Err(V04ExecutionForkStoreError::ManifestMalformed);
    }
    Ok(bytes)
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
        monetary_genesis_v04_candidate::GenesisManifestV04,
        monetary_issuance_v04_candidate::V04MiningIssuanceScheduleCandidate,
        monetary_transition_v04_candidate::V04ConsensusProfileCandidate,
        state_machine::{AccountId, Transaction},
    };
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
