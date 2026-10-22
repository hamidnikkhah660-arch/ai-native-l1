//! Candidate-only durable PFM4 store for PMT4/MBK4 monetary branches.
//!
//! In local-only mode, a synced branch envelope followed by atomic manifest publication is the
//! commit protocol; the local manifest checksum detects corruption but is not an independent
//! anti-rollback anchor. The explicit external-CAS path first writes a durable pending manifest,
//! verifies a pinned signed provider read, conditionally advances the external anchor, and only
//! then publishes the local manifest. Restart reconciliation promotes only a pending manifest
//! named by the freshly verified remote anchor, or discards it when the remote anchor remains on
//! the old commit. Both modes replay and validate the complete PMT4 ancestor graph.
//!
//! The external provider is still an abstract transport contract/test fixture, not a deployed
//! HTTPS service, and this store is not yet wired into the live devnet_node runtime. These
//! candidate APIs therefore do not by themselves establish Gate 8 or Mainnet readiness.

use crate::{
    chain_admission::ReferenceTimeProvider,
    consensus::{pow_digest, ConsensusParameters, PowAlgorithm},
    external_cas_anchor_candidate::{
        ExternalCasPin, ExternalCasProviderTransport, ExternalCasReceipt,
        ExternalCasReceiptOutcome, ExternalCasRecord, ExternalCasWriteRequest,
        VerifiedExternalCasClient,
    },
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
const PENDING_MANIFEST_NAME: &str = "monetary-v4-forkstore.manifest.pending-cas";
const EXTERNAL_CAS_OPERATION_DOMAIN: &[u8] = b"AIN1-PFM4-EXTERNAL-CAS-OPERATION-V1\0";
const EXTERNAL_CAS_COMMIT_OPERATION_DOMAIN: &[u8] = b"AIN1-PFM4-EXTERNAL-CAS-COMMIT-OP-V1\0";
const EXTERNAL_CAS_WRITE_NONCE_DOMAIN: &[u8] = b"AIN1-PFM4-EXTERNAL-CAS-WRITE-NONCE-V1\0";
const EXTERNAL_CAS_GENESIS_DOMAIN: &[u8] = b"AIN1-PFM4-EXTERNAL-CAS-GENESIS-V1\0";
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
    ExternalAnchorMismatch,
    ExternalAnchorRequired,
    ExternalAnchorNoStateChange,
    PendingManifestExists,
    ExternalCasFailure(String),
    ExternalCasConflict,
    ExternalCasInvalidOutcome(ExternalCasReceiptOutcome),
}

/// Result of a PFM4 commit whose next manifest was accepted by the external CAS provider.
#[derive(Debug)]
pub struct V4HybridAnchoredSubmitOutcome {
    pub block: V4HybridForkChoiceOutcome,
    pub anchor_record: ExternalCasRecord,
    pub receipt: ExternalCasReceipt,
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
            Self::ExternalAnchorMismatch => write!(
                f,
                "external CAS anchor does not identify the currently committed PFM4 manifest"
            ),
            Self::ExternalAnchorRequired => write!(
                f,
                "this store was opened in externally anchored mode; local-only submit is disabled"
            ),
            Self::ExternalAnchorNoStateChange => write!(
                f,
                "candidate PMT4 submission does not change the committed PFM4 manifest"
            ),
            Self::PendingManifestExists => write!(
                f,
                "a pending externally anchored manifest requires signed-anchor recovery before another submit"
            ),
            Self::ExternalCasFailure(error) => {
                write!(f, "external CAS provider/client error: {error}")
            }
            Self::ExternalCasConflict => write!(
                f,
                "external CAS conditional commit conflicted; pending manifest must be reconciled with a fresh signed read"
            ),
            Self::ExternalCasInvalidOutcome(outcome) => {
                write!(f, "external CAS returned non-commit outcome: {outcome:?}")
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
    external_anchor_required: bool,
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

    /// Open/recover a store from a freshly verified external CAS read rather than accepting
    /// an arbitrary caller-supplied manifest hash. If the provider is one generation ahead,
    /// open_anchored reconciles the pending manifest with that exact signed remote state.
    /// The caller's object-generation floor must be kept outside the rollback domain.
    pub fn open_with_external_cas<P, V, A>(
        directory: impl AsRef<Path>,
        genesis: MonetaryLedgerState,
        params: ConsensusParameters,
        expected_manifest_id: [u8; 32],
        verifier: &A,
        clock: &dyn ReferenceTimeProvider,
        pin: &ExternalCasPin,
        client: &mut VerifiedExternalCasClient<P, V>,
        expected_record: Option<&ExternalCasRecord>,
        minimum_object_generation: u64,
    ) -> Result<(Self, ExternalCasRecord, u64), V4HybridForkStoreError>
    where
        P: ExternalCasProviderTransport,
        V: crate::v4_fat1_trust_candidate::MlDsa65Verifier,
        A: MlDsa65Verifier,
    {
        if !client.is_pinned_to(pin) {
            return Err(V4HybridForkStoreError::ExternalAnchorMismatch);
        }
        let network_id = genesis.ledger().network_id();
        let profile = profile_fingerprint(&genesis, &params, &expected_manifest_id)?;
        let empty = PrivateTestnetV4HybridForkChoice::new(
            genesis.clone(),
            params.clone(),
            expected_manifest_id,
        )
        .map_err(V4HybridForkStoreError::Fork)?;
        let genesis_tip = empty.genesis_tip();
        let mut genesis_hasher = Sha256::new();
        genesis_hasher.update(EXTERNAL_CAS_GENESIS_DOMAIN);
        genesis_hasher.update(network_id);
        genesis_hasher.update(profile);
        genesis_hasher.update(genesis_tip);
        let expected_genesis_digest: [u8; 32] = genesis_hasher.finalize().into();
        if pin.network_id != network_id || pin.genesis_digest != expected_genesis_digest {
            return Err(V4HybridForkStoreError::ExternalAnchorMismatch);
        }

        let expected_generation = expected_record.map_or(0, |record| record.generation);
        let mut operation_hasher = Sha256::new();
        operation_hasher.update(EXTERNAL_CAS_OPERATION_DOMAIN);
        operation_hasher.update(b"open-read");
        operation_hasher.update(network_id);
        operation_hasher.update(expected_genesis_digest);
        operation_hasher.update(expected_manifest_id);
        operation_hasher.update(expected_generation.to_be_bytes());
        let operation_id: [u8; 32] = operation_hasher.finalize().into();
        let mut request_hasher = Sha256::new();
        request_hasher.update(b"AIN1-PFM4-EXTERNAL-CAS-OPEN-READ-REQUEST-V1\0");
        request_hasher.update(operation_id);
        request_hasher.update(minimum_object_generation.to_be_bytes());
        let request_digest: [u8; 32] = request_hasher.finalize().into();
        let read_request = client
            .fresh_read_request(operation_id, request_digest)
            .map_err(|error| V4HybridForkStoreError::ExternalCasFailure(error.to_string()))?;
        let verified = client
            .read_current(
                &read_request,
                expected_generation,
                minimum_object_generation,
                expected_record,
            )
            .map_err(|error| V4HybridForkStoreError::ExternalCasFailure(error.to_string()))?;
        if verified.record.network_id != network_id
            || verified.record.genesis_digest != expected_genesis_digest
            || verified.record.provider_id != pin.provider_id
        {
            return Err(V4HybridForkStoreError::ExternalAnchorMismatch);
        }

        let store = Self::open_anchored(
            directory,
            genesis,
            params,
            expected_manifest_id,
            verifier,
            clock,
            verified.record.next_state_digest,
        )?;
        Ok((store, verified.record, verified.object_generation))
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
        let pending_manifest_path = directory.join(PENDING_MANIFEST_NAME);

        // Reconcile the narrow crash window after external CAS succeeds but before the
        // local manifest is published. The expected anchor must come from a separately
        // verified provider receipt. If the currently committed manifest already matches it,
        // any pending file is an uncommitted/stale attempt and can be discarded. Otherwise,
        // promote only a pending manifest whose exact commitment matches that verified anchor.
        if pending_manifest_path.exists() {
            if !pending_manifest_path.is_file() {
                return Err(V4HybridForkStoreError::UnexpectedStoreEntry);
            }
            let expected_anchor =
                expected_manifest_anchor.ok_or(V4HybridForkStoreError::ManifestAnchorMismatch)?;
            let current_matches =
                if manifest_path.is_file() {
                    let current_bytes = read_bounded_file(&manifest_path, MAX_MANIFEST_BYTES)
                        .map_err(|error| match error {
                            BoundedReadError::Io(error) => V4HybridForkStoreError::Io(error),
                            BoundedReadError::TooLarge => V4HybridForkStoreError::ManifestTooLarge,
                        })?;
                    manifest_anchor_commitment(&current_bytes) == expected_anchor
                } else {
                    false
                };
            if current_matches {
                // A signed remote read still identifies the old local commit; CAS did not
                // advance to this pending manifest, so drop the uncommitted proposal.
                fs::remove_file(&pending_manifest_path)?;
                sync_parent(&directory)?;
            } else {
                let pending_bytes = read_bounded_file(&pending_manifest_path, MAX_MANIFEST_BYTES)
                    .map_err(|error| match error {
                    BoundedReadError::Io(error) => V4HybridForkStoreError::Io(error),
                    BoundedReadError::TooLarge => V4HybridForkStoreError::ManifestTooLarge,
                })?;
                if manifest_anchor_commitment(&pending_bytes) != expected_anchor {
                    return Err(V4HybridForkStoreError::ManifestAnchorMismatch);
                }
                atomic_replace(&pending_manifest_path, &manifest_path)?;
            }
        }

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
            external_anchor_required: expected_manifest_anchor.is_some(),
            _writer_lock: writer_lock,
        })
    }

    pub fn expected_manifest_id(&self) -> [u8; 32] {
        self.expected_manifest_id
    }

    /// Stable nonzero binding for external anti-rollback configuration. Unlike the genesis tip,
    /// which is normally zero at height zero, this commits to the network, frozen candidate
    /// profile fingerprint, and canonical genesis-tip value.
    pub fn external_cas_genesis_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(EXTERNAL_CAS_GENESIS_DOMAIN);
        hasher.update(self.genesis.ledger().network_id());
        hasher.update(self.profile_fingerprint);
        hasher.update(self.genesis_tip);
        hasher.finalize().into()
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
        // A pending external-CAS manifest may represent an ambiguous remote commit. Never let
        // the local-only path overtake it; recover using a fresh signed provider read first.
        if self.directory.join(PENDING_MANIFEST_NAME).exists() {
            return Err(V4HybridForkStoreError::PendingManifestExists);
        }
        if self.external_anchor_required {
            return Err(V4HybridForkStoreError::ExternalAnchorRequired);
        }
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

    /// Submit a PMT4 block under an external anti-rollback commit protocol.
    ///
    /// Ordering is fail-closed: read/verify the current signed anchor; require that it names
    /// the current local PFM4 manifest; durably write the branch and exact pending manifest;
    /// submit an atomic provider CAS to the pending manifest commitment; only after a verified
    /// Applied/AlreadyApplied receipt atomically publish the local manifest. Provider errors
    /// are ambiguous and deliberately leave the pending file for signed-read recovery.
    ///
    /// pin.genesis_digest is the stable external_cas_genesis_digest() binding for this store.
    /// The caller must retain
    /// the returned anchor_record and receipt object generation outside this mutable store;
    /// an in-memory floor alone is not a whole-disk rollback defense.
    pub fn submit_with_external_anchor<P, V, A>(
        &mut self,
        envelope: &[u8],
        authenticator: &A,
        clock: &dyn ReferenceTimeProvider,
        pin: &ExternalCasPin,
        client: &mut VerifiedExternalCasClient<P, V>,
        expected_record: &ExternalCasRecord,
        minimum_object_generation: u64,
    ) -> Result<V4HybridAnchoredSubmitOutcome, V4HybridForkStoreError>
    where
        P: ExternalCasProviderTransport,
        V: crate::v4_fat1_trust_candidate::MlDsa65Verifier,
        A: MlDsa65Verifier,
    {
        if !client.is_pinned_to(pin) {
            return Err(V4HybridForkStoreError::ExternalAnchorMismatch);
        }
        let pending_path = self.directory.join(PENDING_MANIFEST_NAME);
        if pending_path.exists() {
            return Err(V4HybridForkStoreError::PendingManifestExists);
        }

        let network_id = self.genesis.ledger().network_id();
        let genesis_digest = self.external_cas_genesis_digest();
        if pin.network_id != network_id
            || pin.genesis_digest != genesis_digest
            || expected_record.provider_id != pin.provider_id
            || expected_record.network_id != network_id
            || expected_record.genesis_digest != genesis_digest
        {
            return Err(V4HybridForkStoreError::ExternalAnchorMismatch);
        }

        let current_anchor = self.manifest_anchor()?;
        if expected_record.next_state_digest != current_anchor {
            return Err(V4HybridForkStoreError::ExternalAnchorMismatch);
        }

        // Build and fully validate the next canonical candidate without mutating the store.
        let mut candidate_archive = self.archive.clone();
        let outcome = candidate_archive.insert_encoded(envelope, authenticator, clock)?;
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
            &network_id,
            &self.profile_fingerprint,
            &self.genesis_tip,
            &canonical_tip,
            &digests,
        )?;
        let next_anchor = manifest_anchor_commitment(&manifest);
        if next_anchor == current_anchor {
            return Err(V4HybridForkStoreError::ExternalAnchorNoStateChange);
        }

        // The read challenge gets a stable proposal identifier. The write operation ID is
        // derived later from the provider object generation too, so an unchanged predecessor
        // produces the same immutable CAS request digest on retry.
        let mut operation_hash = Sha256::new();
        operation_hash.update(EXTERNAL_CAS_OPERATION_DOMAIN);
        operation_hash.update(current_anchor);
        operation_hash.update(next_anchor);
        operation_hash.update(outcome.block_digest);
        operation_hash.update(expected_record.generation.to_be_bytes());
        let read_operation_id: [u8; 32] = operation_hash.finalize().into();

        let read_request = client
            .fresh_read_request(read_operation_id, current_anchor)
            .map_err(|error| V4HybridForkStoreError::ExternalCasFailure(error.to_string()))?;
        let verified = client
            .read_current(
                &read_request,
                expected_record.generation,
                minimum_object_generation,
                Some(expected_record),
            )
            .map_err(|error| V4HybridForkStoreError::ExternalCasFailure(error.to_string()))?;
        if verified
            .record
            .digest()
            .map_err(|error| V4HybridForkStoreError::ExternalCasFailure(error.to_string()))?
            != expected_record
                .digest()
                .map_err(|error| V4HybridForkStoreError::ExternalCasFailure(error.to_string()))?
            || verified.record.next_state_digest != current_anchor
        {
            return Err(V4HybridForkStoreError::ExternalAnchorMismatch);
        }

        let mut commit_operation_hash = Sha256::new();
        commit_operation_hash.update(EXTERNAL_CAS_COMMIT_OPERATION_DOMAIN);
        commit_operation_hash.update(current_anchor);
        commit_operation_hash.update(next_anchor);
        commit_operation_hash.update(outcome.block_digest);
        commit_operation_hash.update(expected_record.generation.to_be_bytes());
        commit_operation_hash.update(verified.object_generation.to_be_bytes());
        let operation_id: [u8; 32] = commit_operation_hash.finalize().into();

        // A deterministic nonce makes the entire CAS request digest reproducible after a
        // crash/ambiguous reply when the provider's predecessor and object generation did not
        // change. The read above still uses a fresh cryptographic challenge nonce.
        let mut nonce_hash = Sha256::new();
        nonce_hash.update(EXTERNAL_CAS_WRITE_NONCE_DOMAIN);
        nonce_hash.update(operation_id);
        nonce_hash.update(verified.object_generation.to_be_bytes());
        let request_nonce: [u8; 32] = nonce_hash.finalize().into();
        if request_nonce.iter().all(|byte| *byte == 0) {
            return Err(V4HybridForkStoreError::ExternalCasFailure(
                "deterministic write nonce unexpectedly zero".to_string(),
            ));
        }

        let branch_path = self.directory.join(branch_file_name(&outcome.block_digest));
        write_branch_create_new(&branch_path, envelope)?;

        let next_record = ExternalCasRecord {
            generation: expected_record
                .generation
                .checked_add(1)
                .ok_or(V4HybridForkStoreError::ExternalAnchorMismatch)?,
            provider_id: pin.provider_id,
            network_id,
            genesis_digest,
            previous_record_digest: expected_record
                .digest()
                .map_err(|error| V4HybridForkStoreError::ExternalCasFailure(error.to_string()))?,
            previous_state_digest: current_anchor,
            next_state_digest: next_anchor,
            operation_id,
            request_digest: [0; 32],
        };
        let mut write_request = ExternalCasWriteRequest {
            request_nonce,
            operation_id,
            request_digest: [0; 32],
            expected_generation: expected_record.generation,
            expected_object_generation: verified.object_generation,
            expected_record_digest: next_record.previous_record_digest,
            expected_state_digest: current_anchor,
            next_record: next_record.clone(),
        };
        write_request
            .bind_request_digest(pin)
            .map_err(|error| V4HybridForkStoreError::ExternalCasFailure(error.to_string()))?;
        let next_record = write_request.next_record.clone();

        // Persist the exact manifest before the external commit. A crash before CAS is resolved
        // by a signed read that still names current_anchor; a crash after CAS promotes only this
        // exact pending manifest if the signed remote state names next_anchor.
        write_synced_new(&pending_path, &manifest).map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                V4HybridForkStoreError::PendingManifestExists
            } else {
                V4HybridForkStoreError::Io(error)
            }
        })?;
        #[cfg(test)]
        crash_at_pfm4_test_boundary("after_external_pending_sync_before_cas");

        let receipt = client
            .compare_and_swap(&write_request)
            .map_err(|error| match error {
                crate::external_cas_anchor_candidate::ExternalCasClientError::Contract(
                    crate::external_cas_anchor_candidate::ExternalCasError::CasConflict,
                ) => V4HybridForkStoreError::ExternalCasConflict,
                // A transport error may mean the provider committed but the reply was lost. Do not
                // delete pending state or guess: restart must reconcile it with a fresh signed read.
                other => V4HybridForkStoreError::ExternalCasFailure(other.to_string()),
            })?;
        match receipt.outcome {
            ExternalCasReceiptOutcome::Applied | ExternalCasReceiptOutcome::AlreadyApplied => {}
            ExternalCasReceiptOutcome::Conflict => {
                return Err(V4HybridForkStoreError::ExternalCasConflict)
            }
            other => return Err(V4HybridForkStoreError::ExternalCasInvalidOutcome(other)),
        }
        if receipt.generation != next_record.generation
            || receipt.record_digest
                != next_record.digest().map_err(|error| {
                    V4HybridForkStoreError::ExternalCasFailure(error.to_string())
                })?
            || receipt.state_digest != next_anchor
        {
            return Err(V4HybridForkStoreError::ExternalAnchorMismatch);
        }

        #[cfg(test)]
        crash_at_pfm4_test_boundary("after_external_cas_commit_before_manifest_replace");
        atomic_replace(&pending_path, &self.directory.join(MANIFEST_NAME))?;
        self.archive = candidate_archive;
        self.external_anchor_required = true;

        Ok(V4HybridAnchoredSubmitOutcome {
            block: outcome,
            anchor_record: next_record,
            receipt,
        })
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
        external_cas_anchor_candidate::{ExternalCasReadRequest, ExternalCasReceiptKind},
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

    struct MemoryCasProvider<F> {
        pin: ExternalCasPin,
        current: ExternalCasRecord,
        object_generation: u64,
        pending_manifest_path: Option<PathBuf>,
        advance_generation_before_cas: bool,
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
                record_digest: current.digest().map_err(|error| error.to_string())?,
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
            request
                .validate(&self.pin)
                .map_err(|error| error.to_string())?;
            if let Some(pending_path) = &self.pending_manifest_path {
                let pending_bytes = fs::read(pending_path).map_err(|error| error.to_string())?;
                if manifest_anchor_commitment(&pending_bytes)
                    != request.next_record.next_state_digest
                {
                    return Err("pending manifest was not durable before external CAS".to_string());
                }
            }
            // Model a concurrent provider-side object update between signed read and CAS.
            // The request must conflict on the object-generation precondition and must not
            // publish the local manifest.
            if self.advance_generation_before_cas {
                self.object_generation = self
                    .object_generation
                    .checked_add(1)
                    .ok_or_else(|| "provider object generation overflow".to_string())?;
                self.advance_generation_before_cas = false;
            }
            let current_digest = self.current.digest().map_err(|error| error.to_string())?;
            let requested_digest = request
                .next_record
                .digest()
                .map_err(|error| error.to_string())?;
            let already_applied = current_digest == requested_digest
                && self.current.operation_id == request.operation_id
                && self.current.request_digest == request.request_digest;
            let can_apply = self.current.generation == request.expected_generation
                && self.object_generation == request.expected_object_generation
                && current_digest == request.expected_record_digest
                && self.current.next_state_digest == request.expected_state_digest;

            let outcome = if already_applied {
                ExternalCasReceiptOutcome::AlreadyApplied
            } else if can_apply {
                self.current = request.next_record.clone();
                self.object_generation = self
                    .object_generation
                    .checked_add(1)
                    .ok_or_else(|| "provider object generation overflow".to_string())?;
                ExternalCasReceiptOutcome::Applied
            } else {
                ExternalCasReceiptOutcome::Conflict
            };
            let current = self.current.clone();
            let receipt = ExternalCasReceipt {
                kind: ExternalCasReceiptKind::Commit,
                outcome,
                generation: current.generation,
                object_generation: self.object_generation,
                provider_id: current.provider_id,
                network_id: current.network_id,
                genesis_digest: current.genesis_digest,
                receipt_key_id: self.pin.receipt_key_id,
                request_nonce: request.request_nonce,
                record_digest: current.digest().map_err(|error| error.to_string())?,
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

    fn stage_pending_candidate(
        store: &PrivateTestnetV4HybridForkStore,
        envelope: &[u8],
        verifier: &LibcruxMlDsa65VerifierCandidate,
    ) -> ([u8; 32], [u8; 32]) {
        let mut candidate_archive = store.archive.clone();
        let outcome = candidate_archive
            .insert_encoded(envelope, verifier, &FixedClock)
            .unwrap();
        let mut digests: Vec<[u8; 32]> = candidate_archive
            .archive_envelopes()
            .iter()
            .map(|bytes| {
                let decoded = decode_candidate_v4_hybrid_monetary_network_block(bytes).unwrap();
                pow_digest(&decoded.header, store.params.pow).unwrap()
            })
            .collect();
        digests.sort_unstable();
        let manifest = encode_manifest(
            &store.genesis.ledger().network_id(),
            &store.profile_fingerprint,
            &store.genesis_tip,
            &outcome.canonical_tip,
            &digests,
        )
        .unwrap();
        write_branch_create_new(
            &store
                .directory
                .join(branch_file_name(&outcome.block_digest)),
            envelope,
        )
        .unwrap();
        write_synced_new(&store.directory.join(PENDING_MANIFEST_NAME), &manifest).unwrap();
        (manifest_anchor_commitment(&manifest), outcome.canonical_tip)
    }

    #[test]
    fn pfm4_external_cas_is_committed_after_pending_manifest_is_durable() {
        let directory = path("external-cas-commit");
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
        let current_anchor = store.manifest_anchor().unwrap();
        let key_pair = portable::generate_key_pair([0x51u8; 32]);
        let pin = ExternalCasPin {
            provider_id: [0x71; 32],
            network_id: NETWORK,
            genesis_digest: store.external_cas_genesis_digest(),
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
            next_state_digest: current_anchor,
            operation_id: [0x73; 32],
            request_digest: [0x74; 32],
        };
        let sign = |mut receipt: ExternalCasReceipt| {
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
            pending_manifest_path: Some(directory.join(PENDING_MANIFEST_NAME)),
            advance_generation_before_cas: false,
            sign,
        };
        let mut client =
            VerifiedExternalCasClient::new(pin.clone(), provider, LibcruxMlDsa65VerifierCandidate)
                .unwrap();

        // A separately supplied trust pin must not disagree with the key that verifies receipts.
        let mut mismatched_pin = pin.clone();
        mismatched_pin.receipt_key_id = [0x76; 32];
        assert!(matches!(
            store.submit_with_external_anchor(
                &envelope,
                &verifier,
                &FixedClock,
                &mismatched_pin,
                &mut client,
                &bootstrap,
                1,
            ),
            Err(V4HybridForkStoreError::ExternalAnchorMismatch)
        ));
        assert!(!directory.join(PENDING_MANIFEST_NAME).exists());

        let committed = store
            .submit_with_external_anchor(
                &envelope,
                &verifier,
                &FixedClock,
                &pin,
                &mut client,
                &bootstrap,
                1,
            )
            .unwrap();
        assert_eq!(committed.block.canonical_height, 1);
        assert_eq!(
            committed.receipt.outcome,
            ExternalCasReceiptOutcome::Applied
        );
        assert_eq!(committed.anchor_record.generation, 1);
        assert_eq!(committed.receipt.object_generation, 2);
        assert_eq!(
            store.manifest_anchor().unwrap(),
            committed.anchor_record.next_state_digest
        );
        assert!(!directory.join(PENDING_MANIFEST_NAME).exists());
        let second = child_envelope(
            store.archive().canonical_chain(),
            &params,
            [0x64; 32],
            101,
            42,
        );
        assert!(matches!(
            store.submit(&second, &verifier, &FixedClock),
            Err(V4HybridForkStoreError::ExternalAnchorRequired)
        ));
        drop(store);

        // Reopen succeeds only after a fresh signed provider read of the next-state commitment.
        let (reopened, observed_record, observed_object_generation) =
            PrivateTestnetV4HybridForkStore::open_with_external_cas(
                &directory,
                genesis,
                params,
                MANIFEST,
                &verifier,
                &FixedClock,
                &pin,
                &mut client,
                Some(&committed.anchor_record),
                committed.receipt.object_generation,
            )
            .unwrap();
        assert_eq!(observed_record, committed.anchor_record);
        assert_eq!(
            observed_object_generation,
            committed.receipt.object_generation
        );
        assert_eq!(reopened.canonical_height(), 1);
        assert_eq!(reopened.canonical_tip(), committed.block.canonical_tip);
        drop(reopened);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn pfm4_external_cas_conflict_leaves_pending_and_recovery_discards_it_when_remote_is_old() {
        let directory = path("external-cas-conflict");
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
        let old_anchor = store.manifest_anchor().unwrap();
        let key_pair = portable::generate_key_pair([0x91u8; 32]);
        let pin = ExternalCasPin {
            provider_id: [0xA1; 32],
            network_id: NETWORK,
            genesis_digest: store.external_cas_genesis_digest(),
            receipt_key_id: [0xA2; 32],
            receipt_public_key: *key_pair.verification_key.as_ref(),
        };
        let bootstrap = ExternalCasRecord {
            generation: 0,
            provider_id: pin.provider_id,
            network_id: pin.network_id,
            genesis_digest: pin.genesis_digest,
            previous_record_digest: [0; 32],
            previous_state_digest: [0; 32],
            next_state_digest: old_anchor,
            operation_id: [0xA3; 32],
            request_digest: [0xA4; 32],
        };
        let sign = |mut receipt: ExternalCasReceipt| {
            let digest = receipt.signing_digest().unwrap();
            receipt.signature = *portable::sign(&key_pair.signing_key, &digest, &[], [0xA5u8; 32])
                .unwrap()
                .as_ref();
            receipt
        };
        let provider = MemoryCasProvider {
            pin: pin.clone(),
            current: bootstrap.clone(),
            object_generation: 1,
            pending_manifest_path: Some(directory.join(PENDING_MANIFEST_NAME)),
            advance_generation_before_cas: true,
            sign,
        };
        let mut client =
            VerifiedExternalCasClient::new(pin.clone(), provider, LibcruxMlDsa65VerifierCandidate)
                .unwrap();

        assert!(matches!(
            store.submit_with_external_anchor(
                &envelope,
                &verifier,
                &FixedClock,
                &pin,
                &mut client,
                &bootstrap,
                1,
            ),
            Err(V4HybridForkStoreError::ExternalCasConflict)
        ));
        assert_eq!(store.canonical_height(), 0);
        assert_eq!(store.manifest_anchor().unwrap(), old_anchor);
        assert!(directory.join(PENDING_MANIFEST_NAME).is_file());
        assert!(matches!(
            store.submit(&envelope, &verifier, &FixedClock),
            Err(V4HybridForkStoreError::PendingManifestExists)
        ));
        drop(store);

        // A fresh signed read still identifies the old record, so recovery discards the proposal
        // and its orphan branch instead of guessing that the failed CAS might have committed.
        let (recovered, observed, object_generation) =
            PrivateTestnetV4HybridForkStore::open_with_external_cas(
                &directory,
                genesis,
                params,
                MANIFEST,
                &verifier,
                &FixedClock,
                &pin,
                &mut client,
                Some(&bootstrap),
                2,
            )
            .unwrap();
        assert_eq!(observed, bootstrap);
        assert_eq!(object_generation, 2);
        assert_eq!(recovered.canonical_height(), 0);
        assert_eq!(recovered.manifest_anchor().unwrap(), old_anchor);
        assert!(!directory.join(PENDING_MANIFEST_NAME).exists());
        assert_eq!(
            fs::read_dir(&directory)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(BRANCH_PREFIX))
                .count(),
            0
        );
        drop(recovered);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn pfm4_open_with_signed_successor_recovers_commit_before_local_manifest_replace() {
        let directory = path("external-cas-signed-recovery");
        let genesis = genesis();
        let params = params();
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let envelope = first_block_envelope(&genesis, &params);
        let store = PrivateTestnetV4HybridForkStore::open(
            &directory,
            genesis.clone(),
            params.clone(),
            MANIFEST,
            &verifier,
            &FixedClock,
        )
        .unwrap();
        let old_anchor = store.manifest_anchor().unwrap();
        let key_pair = portable::generate_key_pair([0x61u8; 32]);
        let pin = ExternalCasPin {
            provider_id: [0x81; 32],
            network_id: NETWORK,
            genesis_digest: store.external_cas_genesis_digest(),
            receipt_key_id: [0x82; 32],
            receipt_public_key: *key_pair.verification_key.as_ref(),
        };
        let bootstrap = ExternalCasRecord {
            generation: 0,
            provider_id: pin.provider_id,
            network_id: pin.network_id,
            genesis_digest: pin.genesis_digest,
            previous_record_digest: [0; 32],
            previous_state_digest: [0; 32],
            next_state_digest: old_anchor,
            operation_id: [0x83; 32],
            request_digest: [0x84; 32],
        };
        let (next_anchor, expected_tip) = stage_pending_candidate(&store, &envelope, &verifier);
        let committed_remote_record = ExternalCasRecord {
            generation: 1,
            provider_id: pin.provider_id,
            network_id: pin.network_id,
            genesis_digest: pin.genesis_digest,
            previous_record_digest: bootstrap.digest().unwrap(),
            previous_state_digest: old_anchor,
            next_state_digest: next_anchor,
            operation_id: [0x85; 32],
            request_digest: [0x86; 32],
        };
        drop(store);

        let sign = |mut receipt: ExternalCasReceipt| {
            let digest = receipt.signing_digest().unwrap();
            receipt.signature = *portable::sign(&key_pair.signing_key, &digest, &[], [0x87u8; 32])
                .unwrap()
                .as_ref();
            receipt
        };
        let provider = MemoryCasProvider {
            pin: pin.clone(),
            current: committed_remote_record.clone(),
            object_generation: 2,
            pending_manifest_path: None,
            advance_generation_before_cas: false,
            sign,
        };
        let mut client =
            VerifiedExternalCasClient::new(pin.clone(), provider, LibcruxMlDsa65VerifierCandidate)
                .unwrap();
        let mut mismatched_pin = pin.clone();
        mismatched_pin.receipt_key_id = [0x88; 32];
        assert!(matches!(
            PrivateTestnetV4HybridForkStore::open_with_external_cas(
                &directory,
                genesis.clone(),
                params.clone(),
                MANIFEST,
                &verifier,
                &FixedClock,
                &mismatched_pin,
                &mut client,
                Some(&bootstrap),
                1,
            ),
            Err(V4HybridForkStoreError::ExternalAnchorMismatch)
        ));
        assert!(directory.join(PENDING_MANIFEST_NAME).exists());

        let (recovered, observed, object_generation) =
            PrivateTestnetV4HybridForkStore::open_with_external_cas(
                &directory,
                genesis,
                params,
                MANIFEST,
                &verifier,
                &FixedClock,
                &pin,
                &mut client,
                Some(&bootstrap),
                1,
            )
            .unwrap();
        assert_eq!(observed, committed_remote_record);
        assert_eq!(object_generation, 2);
        assert_eq!(recovered.canonical_height(), 1);
        assert_eq!(recovered.canonical_tip(), expected_tip);
        assert_eq!(recovered.manifest_anchor().unwrap(), next_anchor);
        assert!(!directory.join(PENDING_MANIFEST_NAME).exists());
        drop(recovered);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn pfm4_external_cas_recovery_promotes_only_the_pending_manifest_named_by_remote_anchor() {
        let directory = path("external-cas-recovery-promote");
        let genesis = genesis();
        let params = params();
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let envelope = first_block_envelope(&genesis, &params);
        let store = PrivateTestnetV4HybridForkStore::open(
            &directory,
            genesis.clone(),
            params.clone(),
            MANIFEST,
            &verifier,
            &FixedClock,
        )
        .unwrap();
        let (next_anchor, expected_tip) = stage_pending_candidate(&store, &envelope, &verifier);
        drop(store);

        let recovered = PrivateTestnetV4HybridForkStore::open_anchored(
            &directory,
            genesis,
            params,
            MANIFEST,
            &verifier,
            &FixedClock,
            next_anchor,
        )
        .unwrap();
        assert_eq!(recovered.canonical_height(), 1);
        assert_eq!(recovered.canonical_tip(), expected_tip);
        assert_eq!(recovered.manifest_anchor().unwrap(), next_anchor);
        assert!(!directory.join(PENDING_MANIFEST_NAME).exists());
        drop(recovered);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn pfm4_external_cas_recovery_discards_pending_if_remote_still_names_old_commit() {
        let directory = path("external-cas-recovery-discard");
        let genesis = genesis();
        let params = params();
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let envelope = first_block_envelope(&genesis, &params);
        let store = PrivateTestnetV4HybridForkStore::open(
            &directory,
            genesis.clone(),
            params.clone(),
            MANIFEST,
            &verifier,
            &FixedClock,
        )
        .unwrap();
        let old_anchor = store.manifest_anchor().unwrap();
        let _ = stage_pending_candidate(&store, &envelope, &verifier);
        drop(store);

        let recovered = PrivateTestnetV4HybridForkStore::open_anchored(
            &directory,
            genesis,
            params,
            MANIFEST,
            &verifier,
            &FixedClock,
            old_anchor,
        )
        .unwrap();
        assert_eq!(recovered.canonical_height(), 0);
        assert_eq!(recovered.manifest_anchor().unwrap(), old_anchor);
        assert!(!directory.join(PENDING_MANIFEST_NAME).exists());
        assert_eq!(
            fs::read_dir(&directory)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with(BRANCH_PREFIX)
                })
                .count(),
            0
        );
        drop(recovered);
        fs::remove_dir_all(directory).unwrap();
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
    fn pfm4_rejects_valid_pow_under_wrong_target_without_publishing_manifest_or_branch() {
        let directory = path("wrong-target-atomic");
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

        let genesis_tip = store.canonical_tip();
        let committed_anchor = store.manifest_anchor().unwrap();
        let valid_envelope = first_block_envelope(&genesis, &params);
        let candidate = decode_candidate_v4_hybrid_monetary_network_block(&valid_envelope).unwrap();
        let forged_target = Uint256::from_be_bytes([0x7F; 32]);
        assert_ne!(forged_target, params.initial_target);
        assert!(forged_target <= params.pow_limit);

        // The nonce must satisfy the peer-supplied target. This isolates expected-target binding
        // from a simple insufficient-work rejection: consensus must still reject the header
        // because the active network profile expects params.initial_target.
        let wrong_target_envelope = (0..256u64)
            .find_map(|nonce| {
                let mut header = candidate.header;
                header.target = forged_target;
                header.nonce = nonce;
                let digest = crate::consensus::pow_digest(&header, params.pow).unwrap();
                (Uint256::from_be_bytes(digest) <= forged_target).then(|| {
                    crate::private_testnet_monetary_wire::encode_candidate_v4_hybrid_monetary_network_block(
                        &header,
                        &candidate.block,
                    )
                    .unwrap()
                })
            })
            .expect("a nonce meeting the half-range forged target should be found");

        let decoded =
            decode_candidate_v4_hybrid_monetary_network_block(&wrong_target_envelope).unwrap();
        assert_eq!(decoded.header.target, forged_target);
        assert_ne!(decoded.header.target, params.initial_target);
        assert!(
            Uint256::from_be_bytes(
                crate::consensus::pow_digest(&decoded.header, params.pow).unwrap()
            ) <= decoded.header.target
        );

        assert!(store
            .submit(&wrong_target_envelope, &verifier, &FixedClock)
            .is_err());
        assert_eq!(store.canonical_height(), 0);
        assert_eq!(store.canonical_tip(), genesis_tip);
        assert_eq!(store.archive().archive_len(), 0);
        assert_eq!(store.manifest_anchor().unwrap(), committed_anchor);
        let branch_count = fs::read_dir(&directory)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                name.starts_with(BRANCH_PREFIX) && name.ends_with(BRANCH_SUFFIX)
            })
            .count();
        assert_eq!(branch_count, 0);

        drop(store);
        let reopened = PrivateTestnetV4HybridForkStore::open(
            &directory,
            genesis,
            params,
            MANIFEST,
            &verifier,
            &FixedClock,
        )
        .unwrap();
        assert_eq!(reopened.canonical_height(), 0);
        assert_eq!(reopened.canonical_tip(), genesis_tip);
        assert_eq!(reopened.archive().archive_len(), 0);
        assert_eq!(reopened.manifest_anchor().unwrap(), committed_anchor);
        drop(reopened);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn pfm4_rejects_bad_pow_without_publishing_manifest_or_branch() {
        let directory = path("invalid-pow-atomic");
        let genesis = genesis();
        let mut params = params();
        let mut target_bytes = [0u8; 32];
        target_bytes[31] = 1;
        params.initial_target = Uint256::from_be_bytes(target_bytes);
        params.pow_limit = Uint256::MAX;
        params.validate().unwrap();

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
        let genesis_tip = store.canonical_tip();
        let committed_anchor = store.manifest_anchor().unwrap();
        let candidate = decode_candidate_v4_hybrid_monetary_network_block(&first_block_envelope(
            &genesis, &params,
        ))
        .unwrap();

        // Keep the body, state root, target and ancestry valid, but deliberately choose a nonce
        // whose digest is above the expected target. This isolates the PoW gate from body checks.
        let invalid_pow_envelope = (0..256u64)
            .find_map(|nonce| {
                let mut header = candidate.header;
                header.nonce = nonce;
                let digest = pow_digest(&header, params.pow).unwrap();
                (Uint256::from_be_bytes(digest) > header.target).then(|| {
                    crate::private_testnet_monetary_wire::encode_candidate_v4_hybrid_monetary_network_block(
                        &header,
                        &candidate.block,
                    )
                    .unwrap()
                })
            })
            .expect("a nonce above target 1 must be found in the bounded search");

        let decoded =
            decode_candidate_v4_hybrid_monetary_network_block(&invalid_pow_envelope).unwrap();
        assert_eq!(decoded.header.target, Uint256::from_be_bytes(target_bytes));
        assert!(
            Uint256::from_be_bytes(pow_digest(&decoded.header, params.pow).unwrap())
                > decoded.header.target
        );

        assert!(store
            .submit(&invalid_pow_envelope, &verifier, &FixedClock)
            .is_err());
        assert_eq!(store.canonical_height(), 0);
        assert_eq!(store.canonical_tip(), genesis_tip);
        assert_eq!(store.archive().archive_len(), 0);
        assert_eq!(store.manifest_anchor().unwrap(), committed_anchor);
        let branch_count = fs::read_dir(&directory)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                name.starts_with(BRANCH_PREFIX) && name.ends_with(BRANCH_SUFFIX)
            })
            .count();
        assert_eq!(branch_count, 0);

        drop(store);
        let reopened = PrivateTestnetV4HybridForkStore::open(
            &directory,
            genesis,
            params,
            MANIFEST,
            &verifier,
            &FixedClock,
        )
        .unwrap();
        assert_eq!(reopened.canonical_height(), 0);
        assert_eq!(reopened.canonical_tip(), genesis_tip);
        assert_eq!(reopened.archive().archive_len(), 0);
        assert_eq!(reopened.manifest_anchor().unwrap(), committed_anchor);
        drop(reopened);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn pfm4_rejects_invalid_miner_reward_without_publishing_manifest_or_branch() {
        let directory = path("invalid-reward-atomic");
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

        let genesis_tip = store.canonical_tip();
        let committed_anchor = store.manifest_anchor().unwrap();
        let valid_envelope = first_block_envelope(&genesis, &params);
        let mut candidate =
            decode_candidate_v4_hybrid_monetary_network_block(&valid_envelope).unwrap();

        // Preserve the header, valid PoW, ancestry and header/body state-root binding, but change
        // the miner's committed reward by one atomic unit. MBK4 admission must derive the reward
        // from height and cumulative issuance, reject the peer claim, and leave PFM4 untouched.
        let valid_digest = pow_digest(&candidate.header, params.pow).unwrap();
        assert!(Uint256::from_be_bytes(valid_digest) <= candidate.header.target);
        candidate.block.claimed_subsidy_atoms = candidate
            .block
            .claimed_subsidy_atoms
            .checked_add(1)
            .expect("the first-block subsidy is far below u64::MAX");
        let invalid_reward_envelope =
            crate::private_testnet_monetary_wire::encode_candidate_v4_hybrid_monetary_network_block(
                &candidate.header,
                &candidate.block,
            )
            .unwrap();

        let decoded =
            decode_candidate_v4_hybrid_monetary_network_block(&invalid_reward_envelope).unwrap();
        assert_eq!(decoded.header, candidate.header);
        assert_eq!(
            decoded.block.claimed_subsidy_atoms,
            candidate.block.claimed_subsidy_atoms
        );
        assert!(
            Uint256::from_be_bytes(pow_digest(&decoded.header, params.pow).unwrap())
                <= decoded.header.target
        );

        assert!(store
            .submit(&invalid_reward_envelope, &verifier, &FixedClock)
            .is_err());
        assert_eq!(store.canonical_height(), 0);
        assert_eq!(store.canonical_tip(), genesis_tip);
        assert_eq!(store.archive().archive_len(), 0);
        assert_eq!(store.manifest_anchor().unwrap(), committed_anchor);
        let branch_count = fs::read_dir(&directory)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                name.starts_with(BRANCH_PREFIX) && name.ends_with(BRANCH_SUFFIX)
            })
            .count();
        assert_eq!(branch_count, 0);

        drop(store);
        let reopened = PrivateTestnetV4HybridForkStore::open(
            &directory,
            genesis,
            params,
            MANIFEST,
            &verifier,
            &FixedClock,
        )
        .unwrap();
        assert_eq!(reopened.canonical_height(), 0);
        assert_eq!(reopened.canonical_tip(), genesis_tip);
        assert_eq!(reopened.archive().archive_len(), 0);
        assert_eq!(reopened.manifest_anchor().unwrap(), committed_anchor);
        drop(reopened);
        fs::remove_dir_all(directory).unwrap();
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
