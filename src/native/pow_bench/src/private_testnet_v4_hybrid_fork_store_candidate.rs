//! Candidate-only durable PFM4 store for PMT4/MBK4 monetary branches.
//!
//! The manifest is the commit record: a branch envelope is written and synced first, then an
//! atomically replaced manifest publishes its digest. Startup validates the frozen profile,
//! manifest, every referenced PMT4 envelope, proof-of-work and the complete monetary ancestor
//! graph by deterministic replay. A local checksum detects corruption; it is not an independent
//! anti-rollback anchor. This store is not yet connected to the live devnet_node runtime.

use crate::{
    chain_admission::ReferenceTimeProvider,
    consensus::{pow_digest, ConsensusParameters, PowAlgorithm},
    private_testnet_monetary_wire::{
        decode_candidate_v4_hybrid_monetary_network_block, V4HybridMonetaryWireError,
        MAX_PRIVATE_TESTNET_V4_HYBRID_MONETARY_ENVELOPE_BYTES,
    },
    private_testnet_v4_hybrid_fork_choice_candidate::{
        PrivateTestnetV4HybridForkChoice, V4HybridForkChoiceError, V4HybridForkChoiceOutcome,
        MAX_V4_HYBRID_FORK_ARCHIVE_BLOCKS,
    },
    state_machine::{MonetaryLedgerState, StateError},
    store_writer_lock::StoreWriterLock,
    v4_account_identity_candidate::MlDsa65Verifier,
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

const MANIFEST_MAGIC: &[u8; 4] = b"PFM4";
const MANIFEST_VERSION: u16 = 4;
const MANIFEST_FIXED_PREFIX: usize = 4 + 2 + 32 + 32 + 32 + 32 + 4;
const MANIFEST_CHECKSUM_BYTES: usize = 32;
const MAX_MANIFEST_BYTES: usize =
    MANIFEST_FIXED_PREFIX + MAX_V4_HYBRID_FORK_ARCHIVE_BLOCKS * 32 + MANIFEST_CHECKSUM_BYTES;
const PROFILE_DOMAIN: &[u8] = b"AIN1-PMT4-STORE-PROFILE-V1\0";
const MANIFEST_ANCHOR_DOMAIN: &[u8] = b"AIN1-PFM4-MANIFEST-ANCHOR-V1\0";
const MANIFEST_NAME: &str = "monetary-v4-forkstore.manifest";
const LOCK_NAME: &str = "monetary-v4-forkstore.lock";
const BRANCH_PREFIX: &str = "monetary-v4-branch-";
const BRANCH_SUFFIX: &str = ".pmt4";
const TEMP_MARKER: &str = ".tmp-";
static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

// Test-binary-only abrupt-exit hooks used by subprocess recovery tests. They are not compiled
// into non-test builds. process::exit skips Rust destructors and releases the OS process resources;
// unlike abort(), this avoids opening an interactive Windows Error Reporting dialog in CI.
#[cfg(test)]
fn crash_at_pfm4_test_boundary(stage: &str) {
    if std::env::var("AIN1_PFM4_CRASH_TEST_STAGE").ok().as_deref() == Some(stage) {
        process::exit(86);
    }
}

#[derive(Debug)]
pub enum V4HybridForkStoreError {
    Io(io::Error),
    State(StateError),
    Fork(V4HybridForkChoiceError),
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

impl std::fmt::Display for V4HybridForkStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "monetary fork-store I/O error: {error}"),
            Self::State(error) => write!(f, "monetary fork-store state error: {error:?}"),
            Self::Fork(error) => write!(f, "monetary fork-store branch validation error: {error}"),
            Self::LockHeld => write!(f, "monetary fork-store writer lock already exists"),
            Self::ManifestMalformed => write!(f, "PFM4 manifest is malformed"),
            Self::ManifestChecksumMismatch => write!(f, "PFM4 manifest checksum mismatch"),
            Self::ManifestAnchorMismatch => write!(
                f,
                "PFM4 manifest does not match the independently supplied anchor"
            ),
            Self::ManifestProfileMismatch => write!(
                f,
                "PFM4 profile differs from the requested network/Genesis/consensus settings"
            ),
            Self::MissingReferencedBranch => {
                write!(f, "PFM4 manifest references a missing PMT4 envelope")
            }
            Self::BranchFilenameDigestMismatch => {
                write!(f, "PFM4 branch filename does not match its PoW digest")
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
                write!(f, "PFM4 canonical tip differs from deterministic replay")
            }
            Self::BranchFileTooLarge => {
                write!(f, "PMT4 branch envelope exceeds its byte limit")
            }
            Self::ManifestTooLarge => write!(f, "PFM4 manifest exceeds its byte limit"),
            Self::DuplicateManifestDigest => {
                write!(f, "PFM4 manifest contains duplicate branch digests")
            }
            Self::ProfileEncodingInvalid => {
                write!(f, "monetary store consensus profile cannot be encoded")
            }
        }
    }
}

impl std::error::Error for V4HybridForkStoreError {}

impl From<io::Error> for V4HybridForkStoreError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<StateError> for V4HybridForkStoreError {
    fn from(value: StateError) -> Self {
        Self::State(value)
    }
}

impl From<V4HybridForkChoiceError> for V4HybridForkStoreError {
    fn from(value: V4HybridForkChoiceError) -> Self {
        Self::Fork(value)
    }
}

fn acquire_writer_lock(directory: &Path) -> Result<StoreWriterLock, V4HybridForkStoreError> {
    StoreWriterLock::acquire(directory, LOCK_NAME).map_err(|error| {
        if error.kind() == io::ErrorKind::WouldBlock {
            V4HybridForkStoreError::LockHeld
        } else {
            V4HybridForkStoreError::Io(error)
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

/// Single-writer durable store for the separate PFM4/PMT4 monetary candidate format.
/// Existing PFS2/PTB2 data are never interpreted as monetary blocks.
pub struct PrivateTestnetV4HybridForkStore {
    directory: PathBuf,
    genesis: MonetaryLedgerState,
    params: ConsensusParameters,
    expected_manifest_id: [u8; 32],
    profile_fingerprint: [u8; 32],
    genesis_tip: [u8; 32],
    archive: PrivateTestnetV4HybridForkChoice,
    _writer_lock: StoreWriterLock,
}

impl PrivateTestnetV4HybridForkStore {
    /// Open a single-writer monetary candidate store. A persistent lock file is reused only
    /// after the operating system grants its exclusive byte-range lock; PID text is diagnostic.
    pub fn open<V: MlDsa65Verifier>(
        directory: impl AsRef<Path>,
        genesis: MonetaryLedgerState,
        params: ConsensusParameters,
        expected_manifest_id: [u8; 32],
        verifier: &V,
        clock: &dyn ReferenceTimeProvider,
    ) -> Result<Self, V4HybridForkStoreError> {
        Self::open_inner(
            directory,
            genesis,
            params,
            expected_manifest_id,
            verifier,
            clock,
            None,
        )
    }

    /// Optional defense-in-depth: caller supplies a manifest commitment kept outside this
    /// mutable store. This method cannot itself provide an independent anchor or anti-rollback
    /// guarantee if the expected value is stored alongside the archive.
    pub fn open_anchored<V: MlDsa65Verifier>(
        directory: impl AsRef<Path>,
        genesis: MonetaryLedgerState,
        params: ConsensusParameters,
        expected_manifest_id: [u8; 32],
        verifier: &V,
        clock: &dyn ReferenceTimeProvider,
        expected_manifest_anchor: [u8; 32],
    ) -> Result<Self, V4HybridForkStoreError> {
        Self::open_inner(
            directory,
            genesis,
            params,
            expected_manifest_id,
            verifier,
            clock,
            Some(expected_manifest_anchor),
        )
    }

    fn open_inner<V: MlDsa65Verifier>(
        directory: impl AsRef<Path>,
        genesis: MonetaryLedgerState,
        params: ConsensusParameters,
        expected_manifest_id: [u8; 32],
        verifier: &V,
        _clock: &dyn ReferenceTimeProvider,
        expected_manifest_anchor: Option<[u8; 32]>,
    ) -> Result<Self, V4HybridForkStoreError> {
        params
            .validate()
            .map_err(|_| V4HybridForkStoreError::ProfileEncodingInvalid)?;
        genesis.total_value()?;
        let directory = directory.as_ref().to_path_buf();
        fs::create_dir_all(&directory)?;
        let writer_lock = acquire_writer_lock(&directory)?;

        let profile_fingerprint = profile_fingerprint(&genesis, &params, &expected_manifest_id)?;
        let empty = PrivateTestnetV4HybridForkChoice::new(
            genesis.clone(),
            params.clone(),
            expected_manifest_id,
        )
        .map_err(V4HybridForkStoreError::Fork)?;
        let genesis_tip = empty.genesis_tip();
        let manifest_path = directory.join(MANIFEST_NAME);

        let (archive, known_digests) = if manifest_path.exists() {
            if !manifest_path.is_file() {
                return Err(V4HybridForkStoreError::ManifestMalformed);
            }
            let manifest_bytes = read_bounded_file(&manifest_path, MAX_MANIFEST_BYTES).map_err(
                |error| match error {
                    BoundedReadError::Io(error) => V4HybridForkStoreError::Io(error),
                    BoundedReadError::TooLarge => V4HybridForkStoreError::ManifestTooLarge,
                },
            )?;
            if expected_manifest_anchor
                .is_some_and(|expected| manifest_anchor_commitment(&manifest_bytes) != expected)
            {
                return Err(V4HybridForkStoreError::ManifestAnchorMismatch);
            }
            let manifest = decode_manifest(&manifest_bytes)?;
            if manifest.network_id != genesis.ledger().network_id()
                || manifest.profile_fingerprint != profile_fingerprint
                || manifest.genesis_tip != genesis_tip
            {
                return Err(V4HybridForkStoreError::ManifestProfileMismatch);
            }

            let mut envelopes = Vec::with_capacity(manifest.digests.len());
            let known: BTreeSet<[u8; 32]> = manifest.digests.iter().copied().collect();
            for digest in &manifest.digests {
                let path = directory.join(branch_file_name(digest));
                if !path.is_file() {
                    return Err(V4HybridForkStoreError::MissingReferencedBranch);
                }
                let bytes =
                    read_bounded_file(&path, MAX_PRIVATE_TESTNET_V4_HYBRID_MONETARY_ENVELOPE_BYTES)
                        .map_err(|error| match error {
                            BoundedReadError::Io(error) => V4HybridForkStoreError::Io(error),
                            BoundedReadError::TooLarge => {
                                V4HybridForkStoreError::BranchFileTooLarge
                            }
                        })?;
                let decoded = decode_candidate_v4_hybrid_monetary_network_block(&bytes)
                    .map_err(V4HybridForkStoreError::from_wire)?;
                if decoded.header.network_id != genesis.ledger().network_id()
                    || pow_digest(&decoded.header, params.pow)
                        .map_err(|_| V4HybridForkStoreError::ProfileEncodingInvalid)?
                        != *digest
                {
                    return Err(V4HybridForkStoreError::BranchFilenameDigestMismatch);
                }
                envelopes.push(bytes);
            }
            let archive = PrivateTestnetV4HybridForkChoice::rebuild_from_envelopes(
                genesis.clone(),
                params.clone(),
                expected_manifest_id,
                envelopes,
                verifier,
            )?;
            if archive.canonical_chain().chain_tip().tip_hash != manifest.canonical_tip {
                return Err(V4HybridForkStoreError::CanonicalTipMismatch);
            }
            (archive, known)
        } else {
            if expected_manifest_anchor.is_some() {
                return Err(V4HybridForkStoreError::ManifestAnchorMismatch);
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
            expected_manifest_id,
            profile_fingerprint,
            genesis_tip,
            archive,
            _writer_lock: writer_lock,
        })
    }

    pub fn expected_manifest_id(&self) -> [u8; 32] {
        self.expected_manifest_id
    }

    pub fn archive(&self) -> &PrivateTestnetV4HybridForkChoice {
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
    pub fn manifest_anchor(&self) -> Result<[u8; 32], V4HybridForkStoreError> {
        let bytes = read_bounded_file(&self.directory.join(MANIFEST_NAME), MAX_MANIFEST_BYTES)
            .map_err(|error| match error {
                BoundedReadError::Io(error) => V4HybridForkStoreError::Io(error),
                BoundedReadError::TooLarge => V4HybridForkStoreError::ManifestTooLarge,
            })?;
        let manifest = decode_manifest(&bytes)?;
        if manifest.network_id != self.genesis.ledger().network_id()
            || manifest.profile_fingerprint != self.profile_fingerprint
            || manifest.genesis_tip != self.genesis_tip
            || manifest.canonical_tip != self.canonical_tip()
        {
            return Err(V4HybridForkStoreError::ManifestAnchorMismatch);
        }
        let mut digests = Vec::new();
        for envelope in self.archive.archive_envelopes() {
            let decoded = decode_candidate_v4_hybrid_monetary_network_block(&envelope)
                .map_err(V4HybridForkStoreError::from_wire)?;
            let digest = pow_digest(&decoded.header, self.params.pow)
                .map_err(|_| V4HybridForkStoreError::ProfileEncodingInvalid)?;
            if !self.directory.join(branch_file_name(&digest)).is_file() {
                return Err(V4HybridForkStoreError::MissingReferencedBranch);
            }
            digests.push(digest);
        }
        digests.sort_unstable();
        if digests != manifest.digests {
            return Err(V4HybridForkStoreError::ManifestAnchorMismatch);
        }
        Ok(manifest_anchor_commitment(&bytes))
    }

    /// Validate against a cloned archive, durably stage the PMT4 record, then publish the PFM4
    /// manifest as commit point. Failure before manifest publication does not change in-memory
    /// state; an unreferenced branch file is cleaned on next open.
    pub fn submit<A: MlDsa65Verifier>(
        &mut self,
        envelope: &[u8],
        authenticator: &A,
        clock: &dyn ReferenceTimeProvider,
    ) -> Result<V4HybridForkChoiceOutcome, V4HybridForkStoreError> {
        // Refuse new commits if the already-published manifest or any committed branch file
        // has drifted since open; otherwise a fresh manifest could publish a graph with a gap.
        let _current_manifest_anchor = self.manifest_anchor()?;
        let mut candidate_archive = self.archive.clone();
        let outcome = candidate_archive.insert_encoded(envelope, authenticator, clock)?;
        let digest = outcome.block_digest;
        let branch_path = self.directory.join(branch_file_name(&digest));

        if branch_path.exists() {
            let existing = read_bounded_file(
                &branch_path,
                MAX_PRIVATE_TESTNET_V4_HYBRID_MONETARY_ENVELOPE_BYTES,
            )
            .map_err(|error| match error {
                BoundedReadError::Io(error) => V4HybridForkStoreError::Io(error),
                BoundedReadError::TooLarge => V4HybridForkStoreError::BranchFileTooLarge,
            })?;
            if existing != envelope {
                return Err(V4HybridForkStoreError::BranchFilenameDigestMismatch);
            }
        } else if self.archive.branch_chain(&digest).is_none() {
            write_branch_create_new(&branch_path, envelope)?;
        }

        // Simulate abrupt process termination after the PMT4 branch is durable but before the
        // PFM4 manifest publishes it. The hook exists only in unit-test binaries.
        #[cfg(test)]
        crash_at_pfm4_test_boundary("after_branch_sync_before_manifest_temp");

        let mut digests: Vec<[u8; 32]> = candidate_archive
            .archive_envelopes()
            .iter()
            .map(|bytes| {
                let decoded = decode_candidate_v4_hybrid_monetary_network_block(bytes)
                    .map_err(V4HybridForkStoreError::from_wire)?;
                pow_digest(&decoded.header, self.params.pow)
                    .map_err(|_| V4HybridForkStoreError::ProfileEncodingInvalid)
            })
            .collect::<Result<_, V4HybridForkStoreError>>()?;
        digests.sort_unstable();
        if digests.len() > MAX_V4_HYBRID_FORK_ARCHIVE_BLOCKS {
            return Err(V4HybridForkStoreError::ManifestTooLarge);
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

impl V4HybridForkStoreError {
    fn from_wire(error: V4HybridMonetaryWireError) -> Self {
        Self::Fork(V4HybridForkChoiceError::Wire(error))
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
    expected_manifest_id: &[u8; 32],
) -> Result<[u8; 32], V4HybridForkStoreError> {
    let genesis_bytes = genesis.encode_snapshot()?;
    let mut canonical = Vec::with_capacity(256 + genesis_bytes.len());
    canonical.extend_from_slice(PROFILE_DOMAIN);
    canonical.extend_from_slice(expected_manifest_id);
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
) -> Result<Vec<u8>, V4HybridForkStoreError> {
    if digests.len() > MAX_V4_HYBRID_FORK_ARCHIVE_BLOCKS {
        return Err(V4HybridForkStoreError::ManifestTooLarge);
    }
    let mut sorted = digests.to_vec();
    sorted.sort_unstable();
    if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(V4HybridForkStoreError::DuplicateManifestDigest);
    }
    if *canonical_tip != *genesis_tip && sorted.binary_search(canonical_tip).is_err() {
        return Err(V4HybridForkStoreError::CanonicalTipMismatch);
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
        return Err(V4HybridForkStoreError::ManifestTooLarge);
    }
    Ok(bytes)
}

fn decode_manifest(bytes: &[u8]) -> Result<ParsedManifest, V4HybridForkStoreError> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(V4HybridForkStoreError::ManifestTooLarge);
    }
    if bytes.len() < MANIFEST_FIXED_PREFIX + MANIFEST_CHECKSUM_BYTES
        || &bytes[..4] != MANIFEST_MAGIC
        || u16::from_be_bytes([bytes[4], bytes[5]]) != MANIFEST_VERSION
    {
        return Err(V4HybridForkStoreError::ManifestMalformed);
    }
    let count = u32::from_be_bytes(bytes[134..138].try_into().unwrap()) as usize;
    if count > MAX_V4_HYBRID_FORK_ARCHIVE_BLOCKS
        || bytes.len() != MANIFEST_FIXED_PREFIX + count * 32 + MANIFEST_CHECKSUM_BYTES
    {
        return Err(V4HybridForkStoreError::ManifestMalformed);
    }
    let checksum_offset = bytes.len() - MANIFEST_CHECKSUM_BYTES;
    let expected: [u8; 32] = Sha256::digest(&bytes[..checksum_offset]).into();
    if bytes[checksum_offset..] != expected {
        return Err(V4HybridForkStoreError::ManifestChecksumMismatch);
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
        return Err(V4HybridForkStoreError::DuplicateManifestDigest);
    }
    if canonical_tip != genesis_tip && digests.binary_search(&canonical_tip).is_err() {
        return Err(V4HybridForkStoreError::CanonicalTipMismatch);
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

fn parse_branch_file_name(name: &str) -> Result<[u8; 32], V4HybridForkStoreError> {
    let hex = name
        .strip_prefix(BRANCH_PREFIX)
        .and_then(|s| s.strip_suffix(BRANCH_SUFFIX))
        .ok_or(V4HybridForkStoreError::UnexpectedBranchFileName)?;
    if hex.len() != 64 {
        return Err(V4HybridForkStoreError::UnexpectedBranchFileName);
    }
    let mut digest = [0u8; 32];
    for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(pair)
            .map_err(|_| V4HybridForkStoreError::UnexpectedBranchFileName)?;
        digest[index] = u8::from_str_radix(pair, 16)
            .map_err(|_| V4HybridForkStoreError::UnexpectedBranchFileName)?;
    }
    if branch_file_name(&digest) != name {
        return Err(V4HybridForkStoreError::UnexpectedBranchFileName);
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

fn write_branch_create_new(path: &Path, bytes: &[u8]) -> Result<(), V4HybridForkStoreError> {
    if bytes.len() > MAX_PRIVATE_TESTNET_V4_HYBRID_MONETARY_ENVELOPE_BYTES {
        return Err(V4HybridForkStoreError::BranchFileTooLarge);
    }
    match write_synced_new(path, bytes) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let existing =
                read_bounded_file(path, MAX_PRIVATE_TESTNET_V4_HYBRID_MONETARY_ENVELOPE_BYTES)
                    .map_err(|error| match error {
                        BoundedReadError::Io(error) => V4HybridForkStoreError::Io(error),
                        BoundedReadError::TooLarge => V4HybridForkStoreError::BranchFileTooLarge,
                    })?;
            if existing == bytes {
                Ok(())
            } else {
                Err(V4HybridForkStoreError::BranchFilenameDigestMismatch)
            }
        }
        Err(error) => Err(V4HybridForkStoreError::Io(error)),
    }
}

fn write_manifest_atomic(path: &Path, bytes: &[u8]) -> Result<(), V4HybridForkStoreError> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(V4HybridForkStoreError::ManifestTooLarge);
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let final_name = path
        .file_name()
        .ok_or(V4HybridForkStoreError::ManifestMalformed)?;
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
        return Err(V4HybridForkStoreError::Io(error));
    }
    drop(file);
    #[cfg(test)]
    crash_at_pfm4_test_boundary("after_manifest_temp_sync_before_replace");
    let replace = atomic_replace(&temp, path);
    #[cfg(test)]
    if replace.is_ok() {
        // The durable commit record is published, but submit() has not yet swapped the new
        // archive into memory. On restart, replay must follow the new manifest.
        crash_at_pfm4_test_boundary("after_manifest_replace_before_archive_publish");
    }
    if replace.is_err() {
        let _ = fs::remove_file(&temp);
    }
    replace.map_err(V4HybridForkStoreError::Io)
}

fn cleanup_orphan_branch_files(
    directory: &Path,
    known_digests: &BTreeSet<[u8; 32]>,
) -> Result<(), V4HybridForkStoreError> {
    let mut seen = 0usize;
    let mut removed = false;
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or(V4HybridForkStoreError::UnexpectedStoreEntry)?;
        if !kind.is_file() {
            return Err(V4HybridForkStoreError::UnexpectedStoreEntry);
        }
        if name == LOCK_NAME || name == MANIFEST_NAME {
            continue;
        }
        if name.starts_with(BRANCH_PREFIX) && name.ends_with(BRANCH_SUFFIX) {
            seen += 1;
            if seen > MAX_V4_HYBRID_FORK_ARCHIVE_BLOCKS + 256 {
                return Err(V4HybridForkStoreError::ManifestTooLarge);
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
        return Err(V4HybridForkStoreError::UnexpectedStoreEntry);
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
        consensus::{ConsensusParameters, PowHeader, Uint256},
        private_testnet_driver::PrivateTestnetChain,
        state_machine::{V4HybridMonetaryBlock, MONETARY_PUBLIC_GOODS_BUDGET_ATOMS},
        v4_account_identity_candidate::{
            native_v4_account_id, AccountIdentityScheme, V4HybridAuthorization, V4HybridSignature,
            V4HybridTransaction,
        },
        v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use libcrux_ml_dsa::ml_dsa_65::portable;

    const NETWORK: [u8; 32] = [0xB7; 32];
    const MANIFEST: [u8; 32] = [0xC4; 32];

    struct FixedClock;
    impl ReferenceTimeProvider for FixedClock {
        fn sample(
            &self,
        ) -> Result<
            crate::chain_admission::ReferenceTimeSample,
            crate::chain_admission::ReferenceTimeError,
        > {
            Ok(crate::chain_admission::ReferenceTimeSample {
                unix_seconds: 200,
                provenance: crate::chain_admission::ReferenceTimeProvenance::ConfiguredProvider,
                source_id: "pfm4-test-clock",
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
            NETWORK,
            [1; 32],
            vec![([2; 32], MONETARY_PUBLIC_GOODS_BUDGET_ATOMS as u64)],
        )
        .unwrap()
    }

    fn path(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "ain1-pfm4-{label}-{}-{}",
            process::id(),
            NEXT_TEMP_ID.fetch_add(1, AtomicOrdering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn first_block_envelope(state: &MonetaryLedgerState, params: &ConsensusParameters) -> Vec<u8> {
        let parent = PrivateTestnetChain::new_monetary(state.clone(), params.clone()).unwrap();
        child_envelope(&parent, params, [3; 32], 100, 0x0102_0304_0506_0708)
    }

    fn child_envelope(
        parent: &PrivateTestnetChain,
        params: &ConsensusParameters,
        miner: [u8; 32],
        timestamp: u64,
        nonce: u64,
    ) -> Vec<u8> {
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let state = parent.monetary_state().unwrap();
        let mut block = V4HybridMonetaryBlock {
            height: state.height() + 1,
            timestamp,
            parent_hash: state.tip_hash(),
            state_root: [0; 32],
            transactions: Vec::new(),
            miner,
            claimed_subsidy_atoms: state.expected_miner_reward().unwrap(),
        };
        block.state_root = state
            .preview_v4_hybrid_state_root_after(&block, &MANIFEST, &verifier)
            .unwrap();
        let header = PowHeader {
            protocol_version: params.protocol_version,
            network_id: state.ledger().network_id(),
            height: block.height,
            timestamp: block.timestamp,
            parent_hash: block.parent_hash,
            previous_consensus_hash: parent.chain_tip().tip_hash,
            state_root: block.state_root,
            target: parent.expected_target(None).unwrap(),
            nonce,
        };
        crate::private_testnet_monetary_wire::encode_candidate_v4_hybrid_monetary_network_block(
            &header, &block,
        )
        .unwrap()
    }

    #[test]
    fn pfm4_commit_anchor_and_reopen_replay_the_exact_pmt4_branch_graph() {
        let directory = path("reopen");
        let genesis = genesis();
        let params = params();
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let envelope = first_block_envelope(&genesis, &params);
        let mut store = PrivateTestnetV4HybridForkStore::open(
            &directory,
            genesis.clone(),
            params.clone(),
            MANIFEST,
            &verifier,
            &FixedClock,
        )
        .unwrap();
        assert_eq!(store.expected_manifest_id(), MANIFEST);
        let outcome = store.submit(&envelope, &verifier, &FixedClock).unwrap();
        assert_eq!(outcome.canonical_height, 1);
        assert_eq!(store.canonical_height(), 1);
        assert!(directory.join(MANIFEST_NAME).is_file());
        assert!(directory
            .join(branch_file_name(&outcome.block_digest))
            .is_file());
        let anchor = store.manifest_anchor().unwrap();
        drop(store);

        let reopened = PrivateTestnetV4HybridForkStore::open_anchored(
            &directory,
            genesis.clone(),
            params.clone(),
            MANIFEST,
            &verifier,
            &FixedClock,
            anchor,
        )
        .unwrap();
        assert_eq!(reopened.archive().archive_len(), 1);
        assert_eq!(reopened.canonical_height(), 1);
        assert_eq!(reopened.canonical_tip(), outcome.canonical_tip);
        assert_eq!(
            reopened
                .archive()
                .canonical_chain()
                .monetary_state()
                .unwrap()
                .height(),
            1
        );
        drop(reopened);

        let wrong_manifest = PrivateTestnetV4HybridForkStore::open(
            &directory,
            genesis,
            params,
            [0xC5; 32],
            &verifier,
            &FixedClock,
        );
        assert!(matches!(
            wrong_manifest,
            Err(V4HybridForkStoreError::ManifestProfileMismatch)
        ));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn child_process_crash_worker_for_manifest_commit_window() {
        let Ok(directory) = std::env::var("AIN1_PFM4_CRASH_TEST_DIR") else {
            return;
        };
        let directory = PathBuf::from(directory);
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let params = params();
        let mut store = PrivateTestnetV4HybridForkStore::open(
            &directory,
            genesis(),
            params.clone(),
            MANIFEST,
            &verifier,
            &FixedClock,
        )
        .unwrap();
        let parent = store.archive().canonical_chain().clone();
        let next = child_envelope(&parent, &params, [8; 32], 101, 99);
        let _ = store.submit(&next, &verifier, &FixedClock).unwrap();
        panic!("PFM4 subprocess crash failpoint did not terminate the worker");
    }

    #[test]
    fn process_crash_windows_reopen_only_the_manifest_committed_state() {
        const STAGES: [&str; 3] = [
            "after_branch_sync_before_manifest_temp",
            "after_manifest_temp_sync_before_replace",
            "after_manifest_replace_before_archive_publish",
        ];

        for stage in STAGES {
            let directory = path("crash-windows");
            let genesis = genesis();
            let params = params();
            let verifier = LibcruxMlDsa65VerifierCandidate;
            let first = first_block_envelope(&genesis, &params);
            let mut store = PrivateTestnetV4HybridForkStore::open(
                &directory,
                genesis.clone(),
                params.clone(),
                MANIFEST,
                &verifier,
                &FixedClock,
            )
            .unwrap();
            let first_outcome = store.submit(&first, &verifier, &FixedClock).unwrap();
            let old_tip = store.canonical_tip();
            let old_state_root = store
                .archive()
                .canonical_chain()
                .monetary_state()
                .unwrap()
                .state_root();
            let parent = store.archive().canonical_chain().clone();
            let second = child_envelope(&parent, &params, [8; 32], 101, 99);
            let decoded_second =
                decode_candidate_v4_hybrid_monetary_network_block(&second).unwrap();
            let expected_new_tip = pow_digest(&decoded_second.header, params.pow).unwrap();
            let expected_new_root = decoded_second.header.state_root;
            assert_ne!(first_outcome.block_digest, expected_new_tip);
            drop(store);

            let output = process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "private_testnet_v4_hybrid_fork_store_candidate::tests::child_process_crash_worker_for_manifest_commit_window",
                    "--nocapture",
                ])
                .env("AIN1_PFM4_CRASH_TEST_DIR", &directory)
                .env("AIN1_PFM4_CRASH_TEST_STAGE", stage)
                .output()
                .unwrap();
            assert_eq!(
                output.status.code(),
                Some(86),
                "subprocess did not exit at failpoint {stage}; status={:?} stdout={} stderr={}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );

            // StoreWriterLock uses an OS-held lock; abrupt child exit must release ownership
            // without deleting the persistent lock path or manually repairing the directory.
            let reopened = PrivateTestnetV4HybridForkStore::open(
                &directory,
                genesis,
                params,
                MANIFEST,
                &verifier,
                &FixedClock,
            )
            .unwrap();
            let committed_manifest_bytes = fs::read(directory.join(MANIFEST_NAME)).unwrap();
            let committed_manifest = decode_manifest(&committed_manifest_bytes).unwrap();
            let manifest_contains_new_tip = committed_manifest.digests.contains(&expected_new_tip);
            let after_replace = stage == "after_manifest_replace_before_archive_publish";
            assert_eq!(manifest_contains_new_tip, after_replace, "stage={stage}");
            assert_eq!(
                reopened.archive().archive_len(),
                committed_manifest.digests.len()
            );
            if after_replace {
                assert_eq!(reopened.canonical_height(), 2, "stage={stage}");
                assert_eq!(reopened.canonical_tip(), expected_new_tip, "stage={stage}");
                assert_eq!(
                    reopened
                        .archive()
                        .canonical_chain()
                        .monetary_state()
                        .unwrap()
                        .state_root(),
                    expected_new_root,
                    "stage={stage}"
                );
                assert!(directory
                    .join(branch_file_name(&expected_new_tip))
                    .is_file());
            } else {
                assert_eq!(reopened.canonical_height(), 1, "stage={stage}");
                assert_eq!(reopened.canonical_tip(), old_tip, "stage={stage}");
                assert_eq!(
                    reopened
                        .archive()
                        .canonical_chain()
                        .monetary_state()
                        .unwrap()
                        .state_root(),
                    old_state_root,
                    "stage={stage}"
                );
                assert!(!directory.join(branch_file_name(&expected_new_tip)).exists());
            }
            let published_branch_count = fs::read_dir(&directory)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with(BRANCH_PREFIX)
                        && entry.file_name().to_string_lossy().ends_with(BRANCH_SUFFIX)
                })
                .count();
            assert_eq!(published_branch_count, committed_manifest.digests.len());
            assert!(!fs::read_dir(&directory)
                .unwrap()
                .filter_map(Result::ok)
                .any(|entry| {
                    entry
                        .file_name()
                        .to_str()
                        .is_some_and(is_our_temp_manifest_name)
                }));
            drop(reopened);
            fs::remove_dir_all(directory).unwrap();
        }
    }

    #[test]
    fn pfm4_reorg_winner_and_state_survive_restart_and_parent_first_replay() {
        let directory = path("reorg-reopen");
        let genesis = genesis();
        let params = params();
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let genesis_chain =
            PrivateTestnetChain::new_monetary(genesis.clone(), params.clone()).unwrap();
        let branch_a = first_block_envelope(&genesis, &params);
        let branch_b = child_envelope(&genesis_chain, &params, [4; 32], 100, 22);
        let mut store = PrivateTestnetV4HybridForkStore::open(
            &directory,
            genesis.clone(),
            params.clone(),
            MANIFEST,
            &verifier,
            &FixedClock,
        )
        .unwrap();
        let outcome_a = store.submit(&branch_a, &verifier, &FixedClock).unwrap();
        let outcome_b = store.submit(&branch_b, &verifier, &FixedClock).unwrap();
        assert_eq!(store.archive().archive_len(), 2);
        let losing_tip = if store.canonical_tip() == outcome_a.block_digest {
            outcome_b.block_digest
        } else {
            outcome_a.block_digest
        };
        let losing_parent = store.archive().branch_chain(&losing_tip).unwrap().clone();
        let extension = child_envelope(&losing_parent, &params, [5; 32], 101, 33);
        let decoded_extension =
            decode_candidate_v4_hybrid_monetary_network_block(&extension).unwrap();
        let expected_tip = pow_digest(&decoded_extension.header, params.pow).unwrap();
        let expected_root = decoded_extension.header.state_root;
        let before_reorg = store.canonical_tip();
        let extension_outcome = store.submit(&extension, &verifier, &FixedClock).unwrap();
        assert!(extension_outcome.canonical_changed);
        assert_ne!(
            extension_outcome.previous_canonical_tip,
            extension_outcome.canonical_tip
        );
        assert_ne!(before_reorg, expected_tip);
        assert_eq!(extension_outcome.canonical_tip, expected_tip);
        assert_eq!(store.canonical_height(), 2);
        assert!(extension_outcome.reorg_count >= 1);
        assert_eq!(
            store
                .archive()
                .canonical_chain()
                .monetary_state()
                .unwrap()
                .state_root(),
            expected_root
        );
        let anchor = store.manifest_anchor().unwrap();
        drop(store);

        let reopened = PrivateTestnetV4HybridForkStore::open_anchored(
            &directory,
            genesis,
            params,
            MANIFEST,
            &verifier,
            &FixedClock,
            anchor,
        )
        .unwrap();
        assert_eq!(reopened.archive().archive_len(), 3);
        assert_eq!(reopened.canonical_height(), 2);
        assert_eq!(reopened.canonical_tip(), expected_tip);
        assert_eq!(reopened.manifest_anchor().unwrap(), anchor);
        assert_eq!(
            reopened
                .archive()
                .canonical_chain()
                .monetary_state()
                .unwrap()
                .state_root(),
            expected_root
        );
        drop(reopened);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn pfm4_imports_real_signed_txn4_transfer_and_replays_after_reopen() {
        let directory = path("signed-txn4-reopen");
        let params = params();
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let ed_signer = SigningKey::from_bytes(&[0x31; 32]);
        let pq_pair = portable::generate_key_pair([0x42; 32]);
        let ed_public_key = ed_signer.verifying_key().to_bytes();
        let mldsa65_public_key = *pq_pair.verification_key.as_ref();
        let sender = native_v4_account_id(&ed_public_key, &mldsa65_public_key);
        let recipient = [0xCC; 32];
        let miner = [0xD0; 32];
        assert_ne!(sender, recipient);
        assert_ne!(sender, miner);
        assert_ne!(recipient, miner);

        // Use the TXN4 signer's own V4 account ID as the Genesis founder, so this test executes
        // real spend authorization while keeping all deterministic test keys local/disposable.
        let genesis = MonetaryLedgerState::genesis(
            NETWORK,
            sender,
            vec![([2; 32], MONETARY_PUBLIC_GOODS_BUDGET_ATOMS as u64)],
        )
        .unwrap();
        let initial_sender_balance = genesis.ledger().account(&sender).unwrap().balance;
        let initial_total_value = genesis.total_value().unwrap();

        let authorization = V4HybridAuthorization {
            network_id: NETWORK,
            manifest_id: MANIFEST,
            sender_id: sender,
            recipient_id: recipient,
            nonce: 1,
            amount_atoms: 1_000,
            fee_atoms: 17,
            expires_at: 1_000,
            identity_scheme: AccountIdentityScheme::NativeV4Hybrid,
            ed25519_public_key: ed_public_key,
            mldsa65_public_key,
        };
        let signing_digest = authorization.signing_digest().unwrap();
        let ed25519_signature = ed_signer.sign(&signing_digest).to_bytes();
        let mldsa65_signature =
            portable::sign(&pq_pair.signing_key, &signing_digest, &[], [0x53; 32]).unwrap();
        let transaction = V4HybridTransaction {
            authorization,
            signature: V4HybridSignature {
                ed25519_signature,
                mldsa65_signature: *mldsa65_signature.as_ref(),
            },
        };
        transaction.verify(&verifier).unwrap();

        let parent = PrivateTestnetChain::new_monetary(genesis.clone(), params.clone()).unwrap();
        let mut block = V4HybridMonetaryBlock {
            height: 1,
            timestamp: 100,
            parent_hash: genesis.tip_hash(),
            state_root: [0; 32],
            transactions: vec![transaction],
            miner,
            claimed_subsidy_atoms: genesis.expected_miner_reward().unwrap(),
        };
        block.state_root = genesis
            .preview_v4_hybrid_state_root_after(&block, &MANIFEST, &verifier)
            .unwrap();
        let header = PowHeader {
            protocol_version: params.protocol_version,
            network_id: NETWORK,
            height: block.height,
            timestamp: block.timestamp,
            parent_hash: block.parent_hash,
            previous_consensus_hash: parent.chain_tip().tip_hash,
            state_root: block.state_root,
            target: parent.expected_target(None).unwrap(),
            nonce: 0,
        };
        let payload =
            crate::private_testnet_monetary_wire::encode_candidate_v4_hybrid_monetary_network_block(
                &header, &block,
            );

        let mut store = PrivateTestnetV4HybridForkStore::open(
            &directory,
            genesis.clone(),
            params.clone(),
            MANIFEST,
            &verifier,
            &FixedClock,
        )
        .unwrap();
        let empty_manifest_anchor = store.manifest_anchor().unwrap();

        // Invalid PQ signature must fail before the durable manifest commit point, leaving the
        // existing PFM4 state and externally observable local anchor unchanged.
        let mut invalid_block = block.clone();
        invalid_block.transactions[0].signature.mldsa65_signature[0] ^= 1;
        let invalid_payload =
            crate::private_testnet_monetary_wire::encode_candidate_v4_hybrid_monetary_network_block(
                &header,
                &invalid_block,
            );
        assert!(invalid_payload.is_ok());
        assert!(store
            .submit(&invalid_payload.unwrap(), &verifier, &FixedClock)
            .is_err());
        assert_eq!(store.canonical_height(), 0);
        assert_eq!(store.manifest_anchor().unwrap(), empty_manifest_anchor);

        let outcome = store
            .submit(&payload.unwrap(), &verifier, &FixedClock)
            .unwrap();
        assert!(outcome.canonical_changed);
        assert_eq!(outcome.canonical_height, 1);
        assert_eq!(
            outcome.block_digest,
            pow_digest(&header, params.pow).unwrap()
        );
        assert_eq!(store.canonical_tip(), outcome.block_digest);
        let state = store.archive().canonical_chain().monetary_state().unwrap();
        assert_eq!(state.height(), 1);
        assert_eq!(
            state.ledger().account(&sender).unwrap().balance,
            initial_sender_balance - 1_017
        );
        assert_eq!(state.ledger().account(&sender).unwrap().nonce, 1);
        assert_eq!(state.ledger().account(&recipient).unwrap().balance, 1_000);
        assert_eq!(
            state.total_mined_atoms(),
            u128::from(block.claimed_subsidy_atoms)
        );
        assert_eq!(
            state.total_value().unwrap(),
            initial_total_value + u128::from(block.claimed_subsidy_atoms)
        );
        assert_eq!(state.state_root(), block.state_root);
        let committed_anchor = store.manifest_anchor().unwrap();
        drop(store);

        let reopened = PrivateTestnetV4HybridForkStore::open_anchored(
            &directory,
            genesis,
            params,
            MANIFEST,
            &verifier,
            &FixedClock,
            committed_anchor,
        )
        .unwrap();
        assert_eq!(reopened.canonical_height(), 1);
        assert_eq!(reopened.canonical_tip(), outcome.block_digest);
        assert_eq!(reopened.manifest_anchor().unwrap(), committed_anchor);
        let replayed = reopened
            .archive()
            .canonical_chain()
            .monetary_state()
            .unwrap();
        assert_eq!(
            replayed.ledger().account(&sender).unwrap().balance,
            initial_sender_balance - 1_017
        );
        assert_eq!(replayed.ledger().account(&sender).unwrap().nonce, 1);
        assert_eq!(
            replayed.ledger().account(&recipient).unwrap().balance,
            1_000
        );
        assert_eq!(
            replayed.total_value().unwrap(),
            initial_total_value + u128::from(block.claimed_subsidy_atoms)
        );
        assert_eq!(replayed.state_root(), block.state_root);
        drop(reopened);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn pfm4_reopen_fails_closed_on_branch_corruption_digest_mismatch_and_manifest_tampering() {
        for corruption in [
            "branch-bytes",
            "branch-digest",
            "missing-branch",
            "manifest-checksum",
        ] {
            let directory = path(corruption);
            let genesis = genesis();
            let params = params();
            let verifier = LibcruxMlDsa65VerifierCandidate;
            let mut store = PrivateTestnetV4HybridForkStore::open(
                &directory,
                genesis.clone(),
                params.clone(),
                MANIFEST,
                &verifier,
                &FixedClock,
            )
            .unwrap();
            let first = first_block_envelope(&genesis, &params);
            let outcome = store.submit(&first, &verifier, &FixedClock).unwrap();
            let committed_branch = directory.join(branch_file_name(&outcome.block_digest));
            drop(store);

            match corruption {
                "branch-bytes" => {
                    let mut bytes = fs::read(&committed_branch).unwrap();
                    bytes[0] ^= 0x01;
                    fs::write(&committed_branch, bytes).unwrap();
                }
                "branch-digest" => {
                    let genesis_chain =
                        PrivateTestnetChain::new_monetary(genesis.clone(), params.clone()).unwrap();
                    let alternate = child_envelope(&genesis_chain, &params, [4; 32], 101, 77);
                    let decoded =
                        decode_candidate_v4_hybrid_monetary_network_block(&alternate).unwrap();
                    let alternate_digest = pow_digest(&decoded.header, params.pow).unwrap();
                    assert_ne!(alternate_digest, outcome.block_digest);
                    fs::write(&committed_branch, alternate).unwrap();
                }
                "missing-branch" => fs::remove_file(&committed_branch).unwrap(),
                "manifest-checksum" => {
                    let manifest_path = directory.join(MANIFEST_NAME);
                    let mut bytes = fs::read(&manifest_path).unwrap();
                    let last = bytes.len() - 1;
                    bytes[last] ^= 0x01;
                    fs::write(manifest_path, bytes).unwrap();
                }
                _ => unreachable!(),
            }

            let reopened = PrivateTestnetV4HybridForkStore::open(
                &directory,
                genesis,
                params,
                MANIFEST,
                &verifier,
                &FixedClock,
            );
            match corruption {
                "branch-digest" => assert!(matches!(
                    reopened,
                    Err(V4HybridForkStoreError::BranchFilenameDigestMismatch)
                )),
                "missing-branch" => assert!(matches!(
                    reopened,
                    Err(V4HybridForkStoreError::MissingReferencedBranch)
                )),
                "manifest-checksum" => assert!(matches!(
                    reopened,
                    Err(V4HybridForkStoreError::ManifestChecksumMismatch)
                )),
                "branch-bytes" => assert!(reopened.is_err()),
                _ => unreachable!(),
            }
            fs::remove_dir_all(directory).unwrap();
        }
    }

    #[test]
    fn pfm4_manifest_rejects_duplicate_digests_and_unlisted_canonical_tip() {
        let network = [1; 32];
        let profile = [2; 32];
        let genesis_tip = [3; 32];
        let canonical_tip = [5; 32];

        assert!(matches!(
            encode_manifest(
                &network,
                &profile,
                &genesis_tip,
                &canonical_tip,
                &[[5; 32], [5; 32]],
            ),
            Err(V4HybridForkStoreError::DuplicateManifestDigest)
        ));

        let mut duplicate = encode_manifest(
            &network,
            &profile,
            &genesis_tip,
            &canonical_tip,
            &[[5; 32], [6; 32]],
        )
        .unwrap();
        let first = duplicate[MANIFEST_FIXED_PREFIX..MANIFEST_FIXED_PREFIX + 32].to_vec();
        duplicate[MANIFEST_FIXED_PREFIX + 32..MANIFEST_FIXED_PREFIX + 64].copy_from_slice(&first);
        let checksum_offset = duplicate.len() - MANIFEST_CHECKSUM_BYTES;
        let checksum: [u8; 32] = Sha256::digest(&duplicate[..checksum_offset]).into();
        duplicate[checksum_offset..].copy_from_slice(&checksum);
        assert!(matches!(
            decode_manifest(&duplicate),
            Err(V4HybridForkStoreError::DuplicateManifestDigest)
        ));

        let mut unknown_tip =
            encode_manifest(&network, &profile, &genesis_tip, &canonical_tip, &[[5; 32]]).unwrap();
        unknown_tip[102..134].copy_from_slice(&[9; 32]);
        let checksum_offset = unknown_tip.len() - MANIFEST_CHECKSUM_BYTES;
        let checksum: [u8; 32] = Sha256::digest(&unknown_tip[..checksum_offset]).into();
        unknown_tip[checksum_offset..].copy_from_slice(&checksum);
        assert!(matches!(
            decode_manifest(&unknown_tip),
            Err(V4HybridForkStoreError::CanonicalTipMismatch)
        ));
    }

    #[test]
    fn pfm4_never_accepts_pmt3_envelopes_or_implicitly_downgrades() {
        let directory = path("strict-version");
        let genesis = genesis();
        let params = params();
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let mut store = PrivateTestnetV4HybridForkStore::open(
            &directory,
            genesis,
            params,
            MANIFEST,
            &verifier,
            &FixedClock,
        )
        .unwrap();
        assert!(matches!(
            store.submit(b"PMT3", &verifier, &FixedClock),
            Err(V4HybridForkStoreError::Fork(V4HybridForkChoiceError::Wire(
                V4HybridMonetaryWireError::Incomplete
            )))
        ));
        assert_eq!(store.canonical_height(), 0);
        assert_eq!(store.archive().archive_len(), 0);
        drop(store);
        fs::remove_dir_all(directory).unwrap();
    }
}
