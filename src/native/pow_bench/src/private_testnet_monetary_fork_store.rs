//! Candidate-only durable PFM3 store for PMT3/MBK3 monetary branches.
//!
//! The manifest is the commit record: a branch envelope is written and synced first, then an
//! atomically replaced manifest publishes its digest. Startup validates the frozen profile,
//! manifest, every referenced PMT3 envelope, proof-of-work and the complete monetary ancestor
//! graph by deterministic replay. A local checksum detects corruption; it is not an independent
//! anti-rollback anchor. This store is not yet connected to the live devnet_node runtime.

use crate::{
    chain_admission::ReferenceTimeProvider,
    consensus::{pow_digest, ConsensusParameters, PowAlgorithm},
    private_testnet_monetary_fork_choice::{
        MonetaryForkChoiceError, MonetaryForkChoiceOutcome, PrivateTestnetMonetaryForkChoice,
        MAX_MONETARY_FORK_ARCHIVE_BLOCKS,
    },
    private_testnet_monetary_wire::{
        decode_candidate_monetary_network_block, MonetaryWireError,
        MAX_PRIVATE_TESTNET_MONETARY_ENVELOPE_BYTES,
    },
    state_machine::{MonetaryLedgerState, StateError, TransactionAuthenticator},
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

const MANIFEST_MAGIC: &[u8; 4] = b"PFM3";
const MANIFEST_VERSION: u16 = 3;
const MANIFEST_FIXED_PREFIX: usize = 4 + 2 + 32 + 32 + 32 + 32 + 4;
const MANIFEST_CHECKSUM_BYTES: usize = 32;
const MAX_MANIFEST_BYTES: usize =
    MANIFEST_FIXED_PREFIX + MAX_MONETARY_FORK_ARCHIVE_BLOCKS * 32 + MANIFEST_CHECKSUM_BYTES;
const PROFILE_DOMAIN: &[u8] = b"AIN1-PMT3-STORE-PROFILE-V1\0";
const MANIFEST_ANCHOR_DOMAIN: &[u8] = b"AIN1-PFM3-MANIFEST-ANCHOR-V1\0";
const MANIFEST_NAME: &str = "monetary-forkstore.manifest";
const LOCK_NAME: &str = "monetary-forkstore.lock";
const BRANCH_PREFIX: &str = "monetary-branch-";
const BRANCH_SUFFIX: &str = ".pmt3";
const TEMP_MARKER: &str = ".tmp-";
static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

// Test-binary-only hard-crash hooks used by subprocess recovery tests. They are not compiled
// into non-test builds and intentionally terminate without running destructors.
#[cfg(test)]
fn crash_at_pfm3_test_boundary(stage: &str) {
    if std::env::var("AIN1_PFM3_CRASH_TEST_STAGE").ok().as_deref() == Some(stage) {
        process::abort();
    }
}

#[derive(Debug)]
pub enum MonetaryForkStoreError {
    Io(io::Error),
    State(StateError),
    Fork(MonetaryForkChoiceError),
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

impl std::fmt::Display for MonetaryForkStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "monetary fork-store I/O error: {error}"),
            Self::State(error) => write!(f, "monetary fork-store state error: {error:?}"),
            Self::Fork(error) => write!(f, "monetary fork-store branch validation error: {error}"),
            Self::LockHeld => write!(f, "monetary fork-store writer lock already exists"),
            Self::ManifestMalformed => write!(f, "PFM3 manifest is malformed"),
            Self::ManifestChecksumMismatch => write!(f, "PFM3 manifest checksum mismatch"),
            Self::ManifestAnchorMismatch => write!(
                f,
                "PFM3 manifest does not match the independently supplied anchor"
            ),
            Self::ManifestProfileMismatch => write!(
                f,
                "PFM3 profile differs from the requested network/Genesis/consensus settings"
            ),
            Self::MissingReferencedBranch => {
                write!(f, "PFM3 manifest references a missing PMT3 envelope")
            }
            Self::BranchFilenameDigestMismatch => {
                write!(f, "PFM3 branch filename does not match its PoW digest")
            }
            Self::UnexpectedBranchFileName => {
                write!(f, "monetary fork-store branch filename is non-canonical")
            }
            Self::UnexpectedStoreEntry => {
                write!(
                    f,
                    "monetary fork-store contains an unexpected filesystem entry"
                )
            }
            Self::CanonicalTipMismatch => {
                write!(f, "PFM3 canonical tip differs from deterministic replay")
            }
            Self::BranchFileTooLarge => {
                write!(f, "PMT3 branch envelope exceeds its byte limit")
            }
            Self::ManifestTooLarge => write!(f, "PFM3 manifest exceeds its byte limit"),
            Self::DuplicateManifestDigest => {
                write!(f, "PFM3 manifest contains duplicate branch digests")
            }
            Self::ProfileEncodingInvalid => {
                write!(f, "monetary store consensus profile cannot be encoded")
            }
        }
    }
}

impl std::error::Error for MonetaryForkStoreError {}

impl From<io::Error> for MonetaryForkStoreError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<StateError> for MonetaryForkStoreError {
    fn from(value: StateError) -> Self {
        Self::State(value)
    }
}

impl From<MonetaryForkChoiceError> for MonetaryForkStoreError {
    fn from(value: MonetaryForkChoiceError) -> Self {
        Self::Fork(value)
    }
}

fn acquire_writer_lock(directory: &Path) -> Result<StoreWriterLock, MonetaryForkStoreError> {
    StoreWriterLock::acquire(directory, LOCK_NAME).map_err(|error| {
        if error.kind() == io::ErrorKind::WouldBlock {
            MonetaryForkStoreError::LockHeld
        } else {
            MonetaryForkStoreError::Io(error)
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

/// Single-writer durable store for the separate PFM3/PMT3 monetary candidate format.
/// Existing PFS2/PTB2 data are never interpreted as monetary blocks.
pub struct PrivateTestnetMonetaryForkStore {
    directory: PathBuf,
    genesis: MonetaryLedgerState,
    params: ConsensusParameters,
    profile_fingerprint: [u8; 32],
    genesis_tip: [u8; 32],
    archive: PrivateTestnetMonetaryForkChoice,
    _writer_lock: StoreWriterLock,
}

impl PrivateTestnetMonetaryForkStore {
    /// Open a single-writer monetary candidate store. A persistent lock file is reused only
    /// after the operating system grants its exclusive byte-range lock; PID text is diagnostic.
    pub fn open<A: TransactionAuthenticator>(
        directory: impl AsRef<Path>,
        genesis: MonetaryLedgerState,
        params: ConsensusParameters,
        authenticator: &A,
        clock: &dyn ReferenceTimeProvider,
    ) -> Result<Self, MonetaryForkStoreError> {
        Self::open_inner(directory, genesis, params, authenticator, clock, None)
    }

    /// Optional defense-in-depth: caller supplies a manifest commitment kept outside this
    /// mutable store. This method cannot itself provide an independent anchor or anti-rollback
    /// guarantee if the expected value is stored alongside the archive.
    pub fn open_anchored<A: TransactionAuthenticator>(
        directory: impl AsRef<Path>,
        genesis: MonetaryLedgerState,
        params: ConsensusParameters,
        authenticator: &A,
        clock: &dyn ReferenceTimeProvider,
        expected_manifest_anchor: [u8; 32],
    ) -> Result<Self, MonetaryForkStoreError> {
        Self::open_inner(
            directory,
            genesis,
            params,
            authenticator,
            clock,
            Some(expected_manifest_anchor),
        )
    }

    fn open_inner<A: TransactionAuthenticator>(
        directory: impl AsRef<Path>,
        genesis: MonetaryLedgerState,
        params: ConsensusParameters,
        authenticator: &A,
        _clock: &dyn ReferenceTimeProvider,
        expected_manifest_anchor: Option<[u8; 32]>,
    ) -> Result<Self, MonetaryForkStoreError> {
        params
            .validate()
            .map_err(|_| MonetaryForkStoreError::ProfileEncodingInvalid)?;
        genesis.total_value()?;
        let directory = directory.as_ref().to_path_buf();
        fs::create_dir_all(&directory)?;
        let writer_lock = acquire_writer_lock(&directory)?;

        let profile_fingerprint = profile_fingerprint(&genesis, &params)?;
        let empty = PrivateTestnetMonetaryForkChoice::new(genesis.clone(), params.clone())
            .map_err(MonetaryForkStoreError::Fork)?;
        let genesis_tip = empty.genesis_tip();
        let manifest_path = directory.join(MANIFEST_NAME);

        let (archive, known_digests) = if manifest_path.exists() {
            if !manifest_path.is_file() {
                return Err(MonetaryForkStoreError::ManifestMalformed);
            }
            let manifest_bytes = read_bounded_file(&manifest_path, MAX_MANIFEST_BYTES).map_err(
                |error| match error {
                    BoundedReadError::Io(error) => MonetaryForkStoreError::Io(error),
                    BoundedReadError::TooLarge => MonetaryForkStoreError::ManifestTooLarge,
                },
            )?;
            if expected_manifest_anchor
                .is_some_and(|expected| manifest_anchor_commitment(&manifest_bytes) != expected)
            {
                return Err(MonetaryForkStoreError::ManifestAnchorMismatch);
            }
            let manifest = decode_manifest(&manifest_bytes)?;
            if manifest.network_id != genesis.ledger().network_id()
                || manifest.profile_fingerprint != profile_fingerprint
                || manifest.genesis_tip != genesis_tip
            {
                return Err(MonetaryForkStoreError::ManifestProfileMismatch);
            }

            let mut envelopes = Vec::with_capacity(manifest.digests.len());
            let known: BTreeSet<[u8; 32]> = manifest.digests.iter().copied().collect();
            for digest in &manifest.digests {
                let path = directory.join(branch_file_name(digest));
                if !path.is_file() {
                    return Err(MonetaryForkStoreError::MissingReferencedBranch);
                }
                let bytes = read_bounded_file(&path, MAX_PRIVATE_TESTNET_MONETARY_ENVELOPE_BYTES)
                    .map_err(|error| match error {
                    BoundedReadError::Io(error) => MonetaryForkStoreError::Io(error),
                    BoundedReadError::TooLarge => MonetaryForkStoreError::BranchFileTooLarge,
                })?;
                let decoded = decode_candidate_monetary_network_block(&bytes)
                    .map_err(MonetaryForkStoreError::from_wire)?;
                if decoded.header.network_id != genesis.ledger().network_id()
                    || pow_digest(&decoded.header, params.pow)
                        .map_err(|_| MonetaryForkStoreError::ProfileEncodingInvalid)?
                        != *digest
                {
                    return Err(MonetaryForkStoreError::BranchFilenameDigestMismatch);
                }
                envelopes.push(bytes);
            }
            let archive = PrivateTestnetMonetaryForkChoice::rebuild_from_envelopes(
                genesis.clone(),
                params.clone(),
                envelopes,
                authenticator,
            )?;
            if archive.canonical_chain().chain_tip().tip_hash != manifest.canonical_tip {
                return Err(MonetaryForkStoreError::CanonicalTipMismatch);
            }
            (archive, known)
        } else {
            if expected_manifest_anchor.is_some() {
                return Err(MonetaryForkStoreError::ManifestAnchorMismatch);
            }
            let known = BTreeSet::new();
            let bytes = encode_manifest(
                &genesis.ledger().network_id(),
                &profile_fingerprint,
                &genesis_tip,
                &genesis_tip,
                &[],
            )?;
            write_manifest_atomic(&manifest_path, &bytes)?;
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

    pub fn archive(&self) -> &PrivateTestnetMonetaryForkChoice {
        &self.archive
    }

    pub fn canonical_tip(&self) -> [u8; 32] {
        self.archive.canonical_chain().chain_tip().tip_hash
    }

    pub fn canonical_height(&self) -> u64 {
        self.archive.canonical_chain().state().height()
    }

    /// Return a commitment operators can store in a separately protected system. The manifest
    /// is verified against the profile and current in-memory fork archive before commitment.
    pub fn manifest_anchor(&self) -> Result<[u8; 32], MonetaryForkStoreError> {
        let bytes = read_bounded_file(&self.directory.join(MANIFEST_NAME), MAX_MANIFEST_BYTES)
            .map_err(|error| match error {
                BoundedReadError::Io(error) => MonetaryForkStoreError::Io(error),
                BoundedReadError::TooLarge => MonetaryForkStoreError::ManifestTooLarge,
            })?;
        let manifest = decode_manifest(&bytes)?;
        if manifest.network_id != self.genesis.ledger().network_id()
            || manifest.profile_fingerprint != self.profile_fingerprint
            || manifest.genesis_tip != self.genesis_tip
            || manifest.canonical_tip != self.canonical_tip()
        {
            return Err(MonetaryForkStoreError::ManifestAnchorMismatch);
        }
        let mut digests = Vec::new();
        for envelope in self.archive.archive_envelopes() {
            let decoded = decode_candidate_monetary_network_block(&envelope)
                .map_err(MonetaryForkStoreError::from_wire)?;
            let digest = pow_digest(&decoded.header, self.params.pow)
                .map_err(|_| MonetaryForkStoreError::ProfileEncodingInvalid)?;
            if !self.directory.join(branch_file_name(&digest)).is_file() {
                return Err(MonetaryForkStoreError::MissingReferencedBranch);
            }
            digests.push(digest);
        }
        digests.sort_unstable();
        if digests != manifest.digests {
            return Err(MonetaryForkStoreError::ManifestAnchorMismatch);
        }
        Ok(manifest_anchor_commitment(&bytes))
    }

    /// Validate against a cloned archive, durably stage the PMT3 record, then publish the PFM3
    /// manifest as commit point. Failure before manifest publication does not change in-memory
    /// state; an unreferenced branch file is cleaned on next open.
    pub fn submit<A: TransactionAuthenticator>(
        &mut self,
        envelope: &[u8],
        authenticator: &A,
        clock: &dyn ReferenceTimeProvider,
    ) -> Result<MonetaryForkChoiceOutcome, MonetaryForkStoreError> {
        // Refuse new commits if the already-published manifest or any committed branch file
        // has drifted since open; otherwise a fresh manifest could publish a graph with a gap.
        let _current_manifest_anchor = self.manifest_anchor()?;
        let mut candidate_archive = self.archive.clone();
        let outcome = candidate_archive.insert_encoded(envelope, authenticator, clock)?;
        let digest = outcome.block_digest;
        let branch_path = self.directory.join(branch_file_name(&digest));

        if branch_path.exists() {
            let existing =
                read_bounded_file(&branch_path, MAX_PRIVATE_TESTNET_MONETARY_ENVELOPE_BYTES)
                    .map_err(|error| match error {
                        BoundedReadError::Io(error) => MonetaryForkStoreError::Io(error),
                        BoundedReadError::TooLarge => MonetaryForkStoreError::BranchFileTooLarge,
                    })?;
            if existing != envelope {
                return Err(MonetaryForkStoreError::BranchFilenameDigestMismatch);
            }
        } else if self.archive.branch_chain(&digest).is_none() {
            write_branch_create_new(&branch_path, envelope)?;
        }

        // Simulate abrupt process termination after the PMT3 branch is durable but before the
        // PFM3 manifest publishes it. The hook exists only in unit-test binaries.
        #[cfg(test)]
        crash_at_pfm3_test_boundary("after_branch_sync_before_manifest_temp");

        let mut digests: Vec<[u8; 32]> = candidate_archive
            .archive_envelopes()
            .iter()
            .map(|bytes| {
                let decoded = decode_candidate_monetary_network_block(bytes)
                    .map_err(MonetaryForkStoreError::from_wire)?;
                pow_digest(&decoded.header, self.params.pow)
                    .map_err(|_| MonetaryForkStoreError::ProfileEncodingInvalid)
            })
            .collect::<Result<_, MonetaryForkStoreError>>()?;
        digests.sort_unstable();
        if digests.len() > MAX_MONETARY_FORK_ARCHIVE_BLOCKS {
            return Err(MonetaryForkStoreError::ManifestTooLarge);
        }

        let canonical_tip = candidate_archive.canonical_chain().chain_tip().tip_hash;
        let manifest = encode_manifest(
            &self.genesis.ledger().network_id(),
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

impl MonetaryForkStoreError {
    fn from_wire(error: MonetaryWireError) -> Self {
        Self::Fork(MonetaryForkChoiceError::Wire(error))
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
    let mut canonical = Vec::with_capacity(MANIFEST_ANCHOR_DOMAIN.len() + 8 + manifest_bytes.len());
    canonical.extend_from_slice(MANIFEST_ANCHOR_DOMAIN);
    canonical.extend_from_slice(&(manifest_bytes.len() as u64).to_be_bytes());
    canonical.extend_from_slice(manifest_bytes);
    Sha256::digest(&canonical).into()
}

fn profile_fingerprint(
    genesis: &MonetaryLedgerState,
    params: &ConsensusParameters,
) -> Result<[u8; 32], MonetaryForkStoreError> {
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
) -> Result<Vec<u8>, MonetaryForkStoreError> {
    if digests.len() > MAX_MONETARY_FORK_ARCHIVE_BLOCKS {
        return Err(MonetaryForkStoreError::ManifestTooLarge);
    }
    let mut sorted = digests.to_vec();
    sorted.sort_unstable();
    if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(MonetaryForkStoreError::DuplicateManifestDigest);
    }
    if *canonical_tip != *genesis_tip && sorted.binary_search(canonical_tip).is_err() {
        return Err(MonetaryForkStoreError::CanonicalTipMismatch);
    }

    let mut bytes =
        Vec::with_capacity(MANIFEST_FIXED_PREFIX + sorted.len() * 32 + MANIFEST_CHECKSUM_BYTES);
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
        return Err(MonetaryForkStoreError::ManifestTooLarge);
    }
    Ok(bytes)
}

fn decode_manifest(bytes: &[u8]) -> Result<ParsedManifest, MonetaryForkStoreError> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(MonetaryForkStoreError::ManifestTooLarge);
    }
    if bytes.len() < MANIFEST_FIXED_PREFIX + MANIFEST_CHECKSUM_BYTES
        || &bytes[..4] != MANIFEST_MAGIC
        || u16::from_be_bytes([bytes[4], bytes[5]]) != MANIFEST_VERSION
    {
        return Err(MonetaryForkStoreError::ManifestMalformed);
    }
    let count = u32::from_be_bytes(bytes[134..138].try_into().unwrap()) as usize;
    if count > MAX_MONETARY_FORK_ARCHIVE_BLOCKS
        || bytes.len() != MANIFEST_FIXED_PREFIX + count * 32 + MANIFEST_CHECKSUM_BYTES
    {
        return Err(MonetaryForkStoreError::ManifestMalformed);
    }
    let checksum_offset = bytes.len() - MANIFEST_CHECKSUM_BYTES;
    let expected: [u8; 32] = Sha256::digest(&bytes[..checksum_offset]).into();
    if bytes[checksum_offset..] != expected {
        return Err(MonetaryForkStoreError::ManifestChecksumMismatch);
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
        return Err(MonetaryForkStoreError::DuplicateManifestDigest);
    }
    if canonical_tip != genesis_tip && digests.binary_search(&canonical_tip).is_err() {
        return Err(MonetaryForkStoreError::CanonicalTipMismatch);
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

fn parse_branch_file_name(name: &str) -> Result<[u8; 32], MonetaryForkStoreError> {
    let hex = name
        .strip_prefix(BRANCH_PREFIX)
        .and_then(|s| s.strip_suffix(BRANCH_SUFFIX))
        .ok_or(MonetaryForkStoreError::UnexpectedBranchFileName)?;
    if hex.len() != 64 {
        return Err(MonetaryForkStoreError::UnexpectedBranchFileName);
    }
    let mut digest = [0u8; 32];
    for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(pair)
            .map_err(|_| MonetaryForkStoreError::UnexpectedBranchFileName)?;
        digest[index] = u8::from_str_radix(pair, 16)
            .map_err(|_| MonetaryForkStoreError::UnexpectedBranchFileName)?;
    }
    if branch_file_name(&digest) != name {
        return Err(MonetaryForkStoreError::UnexpectedBranchFileName);
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
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    let result = file
        .write_all(bytes)
        .and_then(|_| file.flush())
        .and_then(|_| file.sync_all());
    drop(file);
    if let Err(error) = result {
        let _ = fs::remove_file(path);
        let _ = sync_parent(parent);
        return Err(error);
    }
    sync_parent(parent)
}

fn write_branch_create_new(path: &Path, bytes: &[u8]) -> Result<(), MonetaryForkStoreError> {
    if bytes.len() > MAX_PRIVATE_TESTNET_MONETARY_ENVELOPE_BYTES {
        return Err(MonetaryForkStoreError::BranchFileTooLarge);
    }
    match write_synced_new(path, bytes) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let existing = read_bounded_file(path, MAX_PRIVATE_TESTNET_MONETARY_ENVELOPE_BYTES)
                .map_err(|error| match error {
                    BoundedReadError::Io(error) => MonetaryForkStoreError::Io(error),
                    BoundedReadError::TooLarge => MonetaryForkStoreError::BranchFileTooLarge,
                })?;
            if existing == bytes {
                Ok(())
            } else {
                Err(MonetaryForkStoreError::BranchFilenameDigestMismatch)
            }
        }
        Err(error) => Err(MonetaryForkStoreError::Io(error)),
    }
}

fn write_manifest_atomic(path: &Path, bytes: &[u8]) -> Result<(), MonetaryForkStoreError> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(MonetaryForkStoreError::ManifestTooLarge);
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let final_name = path
        .file_name()
        .ok_or(MonetaryForkStoreError::ManifestMalformed)?;
    let temp = unique_temp_path(parent, final_name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)?;
    let result = file
        .write_all(bytes)
        .and_then(|_| file.flush())
        .and_then(|_| file.sync_all());
    if let Err(error) = result {
        drop(file);
        let _ = fs::remove_file(&temp);
        return Err(MonetaryForkStoreError::Io(error));
    }
    drop(file);
    #[cfg(test)]
    crash_at_pfm3_test_boundary("after_manifest_temp_sync_before_replace");
    let replace = atomic_replace(&temp, path);
    #[cfg(test)]
    if replace.is_ok() {
        // The durable commit record is published, but submit() has not yet swapped the new
        // archive into memory. On restart, replay must follow the new manifest.
        crash_at_pfm3_test_boundary("after_manifest_replace_before_archive_publish");
    }
    if replace.is_err() {
        let _ = fs::remove_file(&temp);
    }
    replace.map_err(MonetaryForkStoreError::Io)
}

fn cleanup_orphan_branch_files(
    directory: &Path,
    known_digests: &BTreeSet<[u8; 32]>,
) -> Result<(), MonetaryForkStoreError> {
    let mut seen = 0usize;
    let mut removed = false;
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or(MonetaryForkStoreError::UnexpectedStoreEntry)?;
        if !kind.is_file() {
            return Err(MonetaryForkStoreError::UnexpectedStoreEntry);
        }
        if name == LOCK_NAME || name == MANIFEST_NAME {
            continue;
        }
        if name.starts_with(BRANCH_PREFIX) && name.ends_with(BRANCH_SUFFIX) {
            seen += 1;
            if seen > MAX_MONETARY_FORK_ARCHIVE_BLOCKS + 256 {
                return Err(MonetaryForkStoreError::ManifestTooLarge);
            }
            let digest = parse_branch_file_name(name)?;
            if !known_digests.contains(&digest) {
                fs::remove_file(entry.path())?;
                removed = true;
            }
            continue;
        }
        // Only clean the exact temporary manifest-file pattern left by our own writer.
        if is_our_temp_manifest_name(name) {
            fs::remove_file(entry.path())?;
            removed = true;
            continue;
        }
        return Err(MonetaryForkStoreError::UnexpectedStoreEntry);
    }
    if removed {
        sync_parent(directory)?;
    }
    Ok(())
}

fn is_our_temp_manifest_name(name: &str) -> bool {
    let Some(rest) = name
        .strip_prefix('.')
        .and_then(|s| s.strip_prefix(MANIFEST_NAME))
        .and_then(|s| s.strip_prefix(TEMP_MARKER))
    else {
        return false;
    };
    let Some((pid, sequence)) = rest.split_once('.') else {
        return false;
    };
    !pid.is_empty()
        && !sequence.is_empty()
        && pid.bytes().all(|byte| byte.is_ascii_digit())
        && sequence.bytes().all(|byte| byte.is_ascii_digit())
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
    // MOVEFILE_WRITE_THROUGH is the Windows rename durability request.
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
        chain_admission::{ReferenceTimeError, ReferenceTimeProvenance, ReferenceTimeSample},
        consensus::{ConsensusParameters, PowHeader, Uint256},
        private_testnet_driver::PrivateTestnetChain,
        private_testnet_monetary_wire::encode_candidate_monetary_network_block,
        state_machine::{AccountId, Block, MonetaryBlock, MONETARY_PUBLIC_GOODS_BUDGET_ATOMS},
    };
    use std::{
        fs,
        path::PathBuf,
        process,
        sync::atomic::{AtomicU64, Ordering},
    };

    static TEST_ID: AtomicU64 = AtomicU64::new(1);

    struct TestDir(PathBuf);
    impl TestDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "ain1_cp0271_monetary_forkstore_{}_{}",
                process::id(),
                TEST_ID.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> &Path {
            &self.0
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
            Ok(())
        }
    }

    struct FixedClock;
    impl ReferenceTimeProvider for FixedClock {
        fn sample(&self) -> Result<ReferenceTimeSample, ReferenceTimeError> {
            Ok(ReferenceTimeSample {
                unix_seconds: 100,
                provenance: ReferenceTimeProvenance::ConfiguredProvider,
                source_id: "monetary-store-test-clock",
            })
        }
    }

    struct LaterClock;
    impl ReferenceTimeProvider for LaterClock {
        fn sample(&self) -> Result<ReferenceTimeSample, ReferenceTimeError> {
            Ok(ReferenceTimeSample {
                unix_seconds: 20_000,
                provenance: ReferenceTimeProvenance::ConfiguredProvider,
                source_id: "monetary-store-later-test-clock",
            })
        }
    }

    fn params() -> ConsensusParameters {
        let mut params = ConsensusParameters::candidate_testnet().unwrap();
        params.initial_target = Uint256::MAX;
        params.pow_limit = Uint256::MAX;
        params
    }

    fn genesis() -> MonetaryLedgerState {
        MonetaryLedgerState::genesis(
            [0xB6; 32],
            [1; 32],
            vec![([2; 32], MONETARY_PUBLIC_GOODS_BUDGET_ATOMS as u64)],
        )
        .unwrap()
    }

    fn envelope(
        state: &MonetaryLedgerState,
        params: &ConsensusParameters,
        miner: AccountId,
        timestamp: u64,
        nonce: u64,
    ) -> Vec<u8> {
        let driver = PrivateTestnetChain::new_monetary(state.clone(), params.clone()).unwrap();
        child_envelope(&driver, params, miner, timestamp, nonce)
    }

    fn child_envelope(
        driver: &PrivateTestnetChain,
        params: &ConsensusParameters,
        miner: AccountId,
        timestamp: u64,
        nonce: u64,
    ) -> Vec<u8> {
        let state = driver.monetary_state().unwrap();
        let mut block = MonetaryBlock {
            body: Block {
                height: state.height() + 1,
                timestamp,
                parent_hash: state.tip_hash(),
                state_root: [0; 32],
                transactions: Vec::new(),
            },
            miner,
            claimed_subsidy_atoms: state.expected_miner_reward().unwrap(),
        };
        block.body.state_root = state
            .preview_state_root_after(&block, &EmptyAuthenticator)
            .unwrap();
        let header = PowHeader {
            protocol_version: params.protocol_version,
            network_id: state.ledger().network_id(),
            height: block.body.height,
            timestamp,
            parent_hash: block.body.parent_hash,
            previous_consensus_hash: driver.chain_tip().tip_hash,
            state_root: block.body.state_root,
            target: params.initial_target,
            nonce,
        };
        encode_candidate_monetary_network_block(&header, &block).unwrap()
    }

    #[test]
    fn durable_pfm3_manifest_reopens_and_replays_same_monetary_state() {
        let directory = TestDir::new();
        let genesis = genesis();
        let params = params();
        let first = envelope(&genesis, &params, [3; 32], 100, 1);
        let mut store = PrivateTestnetMonetaryForkStore::open(
            directory.path(),
            genesis.clone(),
            params.clone(),
            &EmptyAuthenticator,
            &FixedClock,
        )
        .unwrap();
        let outcome = store
            .submit(&first, &EmptyAuthenticator, &FixedClock)
            .unwrap();
        assert_eq!(outcome.canonical_height, 1);
        let expected_tip = store.canonical_tip();
        let expected_state_root = store
            .archive()
            .canonical_chain()
            .monetary_state()
            .unwrap()
            .state_root();
        let anchor = store.manifest_anchor().unwrap();
        drop(store);

        let reopened = PrivateTestnetMonetaryForkStore::open(
            directory.path(),
            genesis,
            params,
            &EmptyAuthenticator,
            &FixedClock,
        )
        .unwrap();
        assert_eq!(reopened.canonical_tip(), expected_tip);
        assert_eq!(reopened.canonical_height(), 1);
        assert_eq!(
            reopened
                .archive()
                .canonical_chain()
                .monetary_state()
                .unwrap()
                .state_root(),
            expected_state_root
        );
        assert_eq!(reopened.manifest_anchor().unwrap(), anchor);
    }

    #[test]
    fn submit_fails_closed_if_committed_branch_file_disappears() {
        let directory = TestDir::new();
        let genesis = genesis();
        let params = params();
        let first = envelope(&genesis, &params, [3; 32], 100, 1);
        let mut store = PrivateTestnetMonetaryForkStore::open(
            directory.path(),
            genesis,
            params.clone(),
            &EmptyAuthenticator,
            &FixedClock,
        )
        .unwrap();
        let first_outcome = store
            .submit(&first, &EmptyAuthenticator, &FixedClock)
            .unwrap();
        let first_chain = store
            .archive()
            .branch_chain(&first_outcome.block_digest)
            .unwrap()
            .clone();
        let second = child_envelope(&first_chain, &params, [4; 32], 101, 2);
        let manifest_path = directory.path().join(MANIFEST_NAME);
        let committed_manifest = fs::read(&manifest_path).unwrap();

        fs::remove_file(
            directory
                .path()
                .join(branch_file_name(&first_outcome.block_digest)),
        )
        .unwrap();

        assert!(matches!(
            store.submit(&second, &EmptyAuthenticator, &LaterClock),
            Err(MonetaryForkStoreError::MissingReferencedBranch)
        ));
        assert_eq!(store.canonical_height(), 1);
        assert_eq!(fs::read(&manifest_path).unwrap(), committed_manifest);
    }

    #[test]
    fn durable_replay_is_independent_of_present_wall_clock() {
        let directory = TestDir::new();
        let genesis = genesis();
        let params = params();
        let first = envelope(&genesis, &params, [3; 32], 100, 1);
        let mut store = PrivateTestnetMonetaryForkStore::open(
            directory.path(),
            genesis.clone(),
            params.clone(),
            &EmptyAuthenticator,
            &FixedClock,
        )
        .unwrap();
        let first_outcome = store
            .submit(&first, &EmptyAuthenticator, &FixedClock)
            .unwrap();
        let first_chain = store
            .archive()
            .branch_chain(&first_outcome.block_digest)
            .unwrap()
            .clone();
        let second = child_envelope(&first_chain, &params, [4; 32], 10_000, 2);
        // Live admission at a later time accepts the valid historical block.
        store
            .submit(&second, &EmptyAuthenticator, &LaterClock)
            .unwrap();
        assert_eq!(store.canonical_height(), 2);
        let expected_tip = store.canonical_tip();
        let expected_root = store
            .archive()
            .canonical_chain()
            .monetary_state()
            .unwrap()
            .state_root();
        drop(store);

        // Restart deliberately uses a clock much earlier than the stored height-2 block.
        // Opening must replay from consensus history and must not use the present clock.
        let reopened = PrivateTestnetMonetaryForkStore::open(
            directory.path(),
            genesis,
            params,
            &EmptyAuthenticator,
            &FixedClock,
        )
        .unwrap();
        assert_eq!(reopened.canonical_height(), 2);
        assert_eq!(reopened.canonical_tip(), expected_tip);
        assert_eq!(
            reopened
                .archive()
                .canonical_chain()
                .monetary_state()
                .unwrap()
                .state_root(),
            expected_root
        );
    }

    #[test]
    fn anchored_open_rejects_wrong_external_manifest_commitment() {
        let directory = TestDir::new();
        let genesis = genesis();
        let params = params();
        let store = PrivateTestnetMonetaryForkStore::open(
            directory.path(),
            genesis.clone(),
            params.clone(),
            &EmptyAuthenticator,
            &FixedClock,
        )
        .unwrap();
        let correct_anchor = store.manifest_anchor().unwrap();
        drop(store);
        assert!(matches!(
            PrivateTestnetMonetaryForkStore::open_anchored(
                directory.path(),
                genesis.clone(),
                params.clone(),
                &EmptyAuthenticator,
                &FixedClock,
                [0xFF; 32],
            ),
            Err(MonetaryForkStoreError::ManifestAnchorMismatch)
        ));
        let anchored = PrivateTestnetMonetaryForkStore::open_anchored(
            directory.path(),
            genesis,
            params,
            &EmptyAuthenticator,
            &FixedClock,
            correct_anchor,
        )
        .unwrap();
        assert_eq!(anchored.manifest_anchor().unwrap(), correct_anchor);
    }

    #[test]
    fn manifest_corruption_and_profile_change_fail_closed_but_stale_pid_text_recovers() {
        let directory = TestDir::new();
        let genesis = genesis();
        let params = params();
        {
            let store = PrivateTestnetMonetaryForkStore::open(
                directory.path(),
                genesis.clone(),
                params.clone(),
                &EmptyAuthenticator,
                &FixedClock,
            )
            .unwrap();
            drop(store);
        }
        let manifest_path = directory.path().join(MANIFEST_NAME);
        let mut bytes = fs::read(&manifest_path).unwrap();
        bytes[10] ^= 0x40;
        fs::write(&manifest_path, &bytes).unwrap();
        assert!(matches!(
            PrivateTestnetMonetaryForkStore::open(
                directory.path(),
                genesis.clone(),
                params.clone(),
                &EmptyAuthenticator,
                &FixedClock
            ),
            Err(MonetaryForkStoreError::ManifestChecksumMismatch)
        ));

        // Restore an empty valid manifest by replacing the test directory with a fresh store.
        fs::remove_dir_all(directory.path()).unwrap();
        fs::create_dir_all(directory.path()).unwrap();
        let store = PrivateTestnetMonetaryForkStore::open(
            directory.path(),
            genesis.clone(),
            params.clone(),
            &EmptyAuthenticator,
            &FixedClock,
        )
        .unwrap();
        drop(store);
        let mut changed_params = params.clone();
        changed_params.protocol_version += 1;
        assert!(matches!(
            PrivateTestnetMonetaryForkStore::open(
                directory.path(),
                genesis.clone(),
                changed_params,
                &EmptyAuthenticator,
                &FixedClock,
            ),
            Err(MonetaryForkStoreError::ManifestProfileMismatch)
        ));

        // The lock pathname may survive an abrupt process exit. The OS lock, not stale PID
        // text or file existence, decides ownership and allows safe reuse after the owner exits.
        fs::write(directory.path().join(LOCK_NAME), b"pid=stale\n").unwrap();
        let reopened = PrivateTestnetMonetaryForkStore::open(
            directory.path(),
            genesis,
            params,
            &EmptyAuthenticator,
            &FixedClock,
        )
        .unwrap();
        assert_eq!(
            fs::read_to_string(directory.path().join(LOCK_NAME)).unwrap(),
            format!("pid={}\n", process::id())
        );
        drop(reopened);
    }

    #[test]
    fn uncommitted_orphan_branch_is_removed_on_reopen() {
        let directory = TestDir::new();
        let genesis = genesis();
        let params = params();
        let orphan_name = branch_file_name(&[0xA5; 32]);
        fs::write(directory.path().join(orphan_name), b"uncommitted").unwrap();
        let store = PrivateTestnetMonetaryForkStore::open(
            directory.path(),
            genesis,
            params,
            &EmptyAuthenticator,
            &FixedClock,
        )
        .unwrap();
        assert_eq!(store.archive().archive_len(), 0);
        assert!(!directory
            .path()
            .join(branch_file_name(&[0xA5; 32]))
            .exists());
    }

    #[test]
    fn durable_pfm3_reopens_same_canonical_tip_after_competing_branch_reorg() {
        let directory = TestDir::new();
        let genesis = genesis();
        let params = params();
        let seed_chain =
            PrivateTestnetChain::new_monetary(genesis.clone(), params.clone()).unwrap();
        let branch_a = child_envelope(&seed_chain, &params, [3; 32], 100, 11);
        let branch_b = child_envelope(&seed_chain, &params, [4; 32], 100, 12);
        let mut store = PrivateTestnetMonetaryForkStore::open(
            directory.path(),
            genesis.clone(),
            params.clone(),
            &EmptyAuthenticator,
            &FixedClock,
        )
        .unwrap();

        let outcome_a = store
            .submit(&branch_a, &EmptyAuthenticator, &FixedClock)
            .unwrap();
        let outcome_b = store
            .submit(&branch_b, &EmptyAuthenticator, &FixedClock)
            .unwrap();
        assert_eq!(store.canonical_height(), 1);
        assert_eq!(store.archive().archive_len(), 2);

        // Extend the competing branch that is not currently canonical. A longer branch
        // must trigger a reorg, and that selected tip must survive the durable manifest replay.
        let current_tip = store.canonical_tip();
        let extension_parent = if current_tip == outcome_a.block_digest {
            outcome_b.block_digest
        } else {
            outcome_a.block_digest
        };
        let parent_chain = store
            .archive()
            .branch_chain(&extension_parent)
            .unwrap()
            .clone();
        let extension = child_envelope(&parent_chain, &params, [5; 32], 101, 13);
        let reorg = store
            .submit(&extension, &EmptyAuthenticator, &FixedClock)
            .unwrap();

        assert!(reorg.canonical_changed);
        assert_eq!(reorg.previous_canonical_tip, current_tip);
        assert_eq!(reorg.canonical_height, 2);
        assert_ne!(reorg.canonical_tip, current_tip);
        assert_eq!(reorg.reorg_count, 1);
        assert_eq!(store.canonical_height(), 2);
        assert_eq!(store.archive().archive_len(), 3);

        let expected_tip = store.canonical_tip();
        let expected_root = store
            .archive()
            .canonical_chain()
            .monetary_state()
            .unwrap()
            .state_root();
        let expected_anchor = store.manifest_anchor().unwrap();
        drop(store);

        let reopened = PrivateTestnetMonetaryForkStore::open(
            directory.path(),
            genesis,
            params,
            &EmptyAuthenticator,
            &FixedClock,
        )
        .unwrap();
        assert_eq!(reopened.canonical_height(), 2);
        assert_eq!(reopened.canonical_tip(), expected_tip);
        assert_eq!(reopened.archive().archive_len(), 3);
        assert_eq!(
            reopened
                .archive()
                .canonical_chain()
                .monetary_state()
                .unwrap()
                .state_root(),
            expected_root
        );
        assert_eq!(reopened.manifest_anchor().unwrap(), expected_anchor);
    }

    #[test]
    fn child_process_crash_worker_for_manifest_commit_window() {
        let Ok(directory) = std::env::var("AIN1_PFM3_CRASH_TEST_DIR") else {
            return;
        };
        let directory = PathBuf::from(directory);
        let genesis = genesis();
        let params = params();
        let mut store = PrivateTestnetMonetaryForkStore::open(
            &directory,
            genesis,
            params.clone(),
            &EmptyAuthenticator,
            &FixedClock,
        )
        .unwrap();
        let parent = store.archive().canonical_chain().clone();
        let next = child_envelope(&parent, &params, [8; 32], 101, 99);
        let _ = store
            .submit(&next, &EmptyAuthenticator, &FixedClock)
            .unwrap();
        panic!("PFM3 subprocess crash failpoint did not terminate the worker");
    }

    #[test]
    fn process_crash_windows_reopen_only_the_manifest_committed_state() {
        const STAGES: [&str; 3] = [
            "after_branch_sync_before_manifest_temp",
            "after_manifest_temp_sync_before_replace",
            "after_manifest_replace_before_archive_publish",
        ];

        for stage in STAGES {
            let directory = TestDir::new();
            let genesis = genesis();
            let params = params();
            let first = envelope(&genesis, &params, [3; 32], 100, 1);
            let mut store = PrivateTestnetMonetaryForkStore::open(
                directory.path(),
                genesis.clone(),
                params.clone(),
                &EmptyAuthenticator,
                &FixedClock,
            )
            .unwrap();
            store
                .submit(&first, &EmptyAuthenticator, &FixedClock)
                .unwrap();
            let old_tip = store.canonical_tip();
            let parent = store.archive().canonical_chain().clone();
            let second = child_envelope(&parent, &params, [8; 32], 101, 99);
            let decoded = decode_candidate_monetary_network_block(&second).unwrap();
            let expected_new_tip = pow_digest(&decoded.header, params.pow).unwrap();
            drop(store);

            let output = process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "private_testnet_monetary_fork_store::tests::child_process_crash_worker_for_manifest_commit_window",
                    "--nocapture",
                ])
                .env("AIN1_PFM3_CRASH_TEST_DIR", directory.path())
                .env("AIN1_PFM3_CRASH_TEST_STAGE", stage)
                .output()
                .unwrap();
            assert!(
                !output.status.success(),
                "subprocess unexpectedly survived failpoint {stage}; stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                !String::from_utf8_lossy(&output.stderr)
                    .contains("PFM3 subprocess crash failpoint did not terminate the worker"),
                "child failed for the wrong reason at {stage}: {}",
                String::from_utf8_lossy(&output.stderr)
            );

            // The store intentionally fails closed on a stale writer lock. This test process
            // has waited for the child to exit, so it performs the documented operator recovery
            // step before validating replay; it does not test automatic stale-lock recovery.
            fs::remove_file(directory.path().join(LOCK_NAME)).unwrap();
            let reopened = PrivateTestnetMonetaryForkStore::open(
                directory.path(),
                genesis,
                params,
                &EmptyAuthenticator,
                &FixedClock,
            )
            .unwrap();

            if stage == "after_manifest_replace_before_archive_publish" {
                assert_eq!(reopened.canonical_height(), 2, "stage={stage}");
                assert_eq!(reopened.canonical_tip(), expected_new_tip, "stage={stage}");
                assert_eq!(reopened.archive().archive_len(), 2, "stage={stage}");
            } else {
                assert_eq!(reopened.canonical_height(), 1, "stage={stage}");
                assert_eq!(reopened.canonical_tip(), old_tip, "stage={stage}");
                assert_eq!(reopened.archive().archive_len(), 1, "stage={stage}");
            }
        }
    }

    #[test]
    fn rejects_pfs2_manifest_magic_in_monetary_store() {
        let directory = TestDir::new();
        fs::write(
            directory.path().join(MANIFEST_NAME),
            b"PFS2-not-a-monetary-manifest",
        )
        .unwrap();
        assert!(matches!(
            PrivateTestnetMonetaryForkStore::open(
                directory.path(),
                genesis(),
                params(),
                &EmptyAuthenticator,
                &FixedClock
            ),
            Err(MonetaryForkStoreError::ManifestMalformed)
        ));
    }
}
