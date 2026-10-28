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
    private_testnet_fork_choice::{
        ForkChoiceError, ForkChoiceOutcome, PrivateTestnetForkChoice, MAX_FORK_ARCHIVE_BLOCKS,
    },
    private_testnet_wire::{
        decode_candidate_network_block, PrivateTestnetWireError, MAX_PRIVATE_TESTNET_ENVELOPE_BYTES,
    },
    state_machine::{LedgerState, StateError, TransactionAuthenticator},
    store_writer_lock::StoreWriterLock,
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
const MANIFEST_NAME: &str = "forkstore.manifest";
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

pub struct PrivateTestnetForkStore {
    directory: PathBuf,
    genesis: LedgerState,
    params: ConsensusParameters,
    profile_fingerprint: [u8; 32],
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
        Self::open_inner(directory, genesis, params, authenticator, clock, None, None)
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
    ) -> Result<Self, ForkStoreError> {
        params.validate()?;
        let directory = directory.as_ref().to_path_buf();
        fs::create_dir_all(&directory)?;
        let writer_lock = acquire_writer_lock(&directory)?;

        let profile_fingerprint = profile_fingerprint(&genesis, &params)?;
        let empty = match base_chain.as_ref() {
            Some(base) => PrivateTestnetForkChoice::from_base_chain(
                genesis.clone(),
                params.clone(),
                base.clone(),
            )?,
            None => PrivateTestnetForkChoice::new(genesis.clone(), params.clone())?,
        };
        let genesis_tip = empty.canonical_chain().chain_tip().tip_hash;
        let manifest_path = directory.join(MANIFEST_NAME);

        let (archive, known_digests) =
            if manifest_path.exists() {
                let manifest_bytes = read_bounded_file(&manifest_path, MAX_MANIFEST_BYTES)
                    .map_err(|error| match error {
                        BoundedReadError::Io(error) => ForkStoreError::Io(error),
                        BoundedReadError::TooLarge => ForkStoreError::ManifestTooLarge,
                    })?;
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
                    let bytes = read_bounded_file(&path, MAX_PRIVATE_TESTNET_ENVELOPE_BYTES)
                        .map_err(|error| match error {
                            BoundedReadError::Io(error) => ForkStoreError::Io(error),
                            BoundedReadError::TooLarge => ForkStoreError::BranchFileTooLarge,
                        })?;
                    let decoded = decode_candidate_network_block(&bytes)
                        .map_err(ForkStoreError::from_wire)?;
                    if decoded.header.network_id != genesis.network_id()
                        || pow_digest(&decoded.header, params.pow)? != *digest
                    {
                        return Err(ForkStoreError::BranchFilenameDigestMismatch);
                    }
                    envelopes.push(bytes);
                }
                let archive = match base_chain.as_ref() {
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
        // Validate into an isolated clone first. No durable bytes or visible in-memory state
        // change if consensus/fork-choice validation fails.
        let mut candidate_archive = self.archive.clone();
        let outcome = candidate_archive.insert_encoded(envelope, authenticator, clock)?;
        let digest = outcome.block_digest;
        let branch_path = self.directory.join(branch_file_name(&digest));

        if branch_path.exists() {
            let existing = read_bounded_file(&branch_path, MAX_PRIVATE_TESTNET_ENVELOPE_BYTES)
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
    if bytes.len() > MAX_PRIVATE_TESTNET_ENVELOPE_BYTES {
        return Err(ForkStoreError::BranchFileTooLarge);
    }
    match write_synced_new(path, bytes) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let existing =
                read_bounded_file(path, MAX_PRIVATE_TESTNET_ENVELOPE_BYTES).map_err(|error| {
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
    replace_result.map_err(ForkStoreError::Io)
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
    use std::{
        collections::BTreeMap,
        process::Command,
        sync::atomic::{AtomicU64, Ordering},
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
