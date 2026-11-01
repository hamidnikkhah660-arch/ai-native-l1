//! CP-0393 candidate transport for immutable PFM5/PCP4/PMT4 objects.
//!
//! The provider is an untrusted byte store. Typed object keys are domain-separated by network,
//! trusted Genesis fingerprint and object kind. Publication is atomic create-if-absent followed
//! by read-back. The checkpoint and every retained branch are published before the manifest.
//! Fetch requires a manifest commitment obtained from a separately authenticated ECR1 read.
//!
//! This is a transport contract and local candidate implementation. It contains no cloud adapter,
//! does not execute External-CAS, and is not wired into a node or Devnet runtime.

use crate::{
    consensus::pow_digest,
    private_testnet_checkpoint_candidate::{
        trusted_genesis_fingerprint, Pcp4CheckpointRecord, Pcp4ValidationContext,
        MAX_PCP4_RECORD_BYTES,
    },
    private_testnet_monetary_wire::{
        decode_candidate_v4_hybrid_monetary_network_block,
        MAX_PRIVATE_TESTNET_V4_HYBRID_MONETARY_ENVELOPE_BYTES,
    },
    private_testnet_pfm5_manifest_candidate::{Pfm5CheckpointManifest, MAX_PFM5_MANIFEST_BYTES},
    private_testnet_v4_hybrid_fork_choice_candidate::{
        PrivateTestnetV4HybridForkChoice, MAX_V4_HYBRID_FORK_ARCHIVE_BLOCKS,
        MAX_V4_HYBRID_FORK_ARCHIVE_BYTES,
    },
    v4_account_identity_candidate::MlDsa65Verifier,
};
use std::{collections::BTreeMap, fmt};

const OBJECT_KEY_DOMAIN: &[u8] = b"AIN1-PFM5-IMMUTABLE-OBJECT-KEY-V1\0";
const MAX_BUNDLE_BYTES: usize =
    MAX_V4_HYBRID_FORK_ARCHIVE_BYTES + MAX_PCP4_RECORD_BYTES + MAX_PFM5_MANIFEST_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Pfm5ImmutableObjectKind {
    Manifest = 1,
    Checkpoint = 2,
    Branch = 3,
}

impl Pfm5ImmutableObjectKind {
    fn from_byte(value: u8) -> Result<Self, Pfm5ObjectError> {
        match value {
            1 => Ok(Self::Manifest),
            2 => Ok(Self::Checkpoint),
            3 => Ok(Self::Branch),
            _ => Err(Pfm5ObjectError::InvalidKey),
        }
    }

    fn max_bytes(self) -> usize {
        match self {
            Self::Manifest => MAX_PFM5_MANIFEST_BYTES,
            Self::Checkpoint => MAX_PCP4_RECORD_BYTES,
            Self::Branch => MAX_PRIVATE_TESTNET_V4_HYBRID_MONETARY_ENVELOPE_BYTES,
        }
    }
}

/// Canonical locator. Digest is the PFM5 manifest commitment, PCP4 record commitment or
/// PMT4 proof-of-work digest according to kind; it is never an arbitrary filesystem path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Pfm5ImmutableObjectKey {
    pub kind: Pfm5ImmutableObjectKind,
    pub network_id: [u8; 32],
    pub genesis_fingerprint: [u8; 32],
    pub digest: [u8; 32],
}

impl Pfm5ImmutableObjectKey {
    pub fn encode(&self) -> Result<Vec<u8>, Pfm5ObjectError> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(OBJECT_KEY_DOMAIN.len() + 97);
        bytes.extend_from_slice(OBJECT_KEY_DOMAIN);
        bytes.push(self.kind as u8);
        bytes.extend_from_slice(&self.network_id);
        bytes.extend_from_slice(&self.genesis_fingerprint);
        bytes.extend_from_slice(&self.digest);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Pfm5ObjectError> {
        let expected_len = OBJECT_KEY_DOMAIN.len() + 97;
        if bytes.len() != expected_len || !bytes.starts_with(OBJECT_KEY_DOMAIN) {
            return Err(Pfm5ObjectError::InvalidKey);
        }
        let mut offset = OBJECT_KEY_DOMAIN.len();
        let kind = Pfm5ImmutableObjectKind::from_byte(bytes[offset])?;
        offset += 1;
        let mut network_id = [0; 32];
        network_id.copy_from_slice(&bytes[offset..offset + 32]);
        offset += 32;
        let mut genesis_fingerprint = [0; 32];
        genesis_fingerprint.copy_from_slice(&bytes[offset..offset + 32]);
        offset += 32;
        let mut digest = [0; 32];
        digest.copy_from_slice(&bytes[offset..offset + 32]);
        let key = Self {
            kind,
            network_id,
            genesis_fingerprint,
            digest,
        };
        key.validate()?;
        Ok(key)
    }

    fn validate(&self) -> Result<(), Pfm5ObjectError> {
        if self.network_id == [0; 32]
            || self.genesis_fingerprint == [0; 32]
            || self.digest == [0; 32]
        {
            return Err(Pfm5ObjectError::InvalidKey);
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pfm5ImmutablePutOutcome {
    Created,
    AlreadyPresent,
}

/// Untrusted immutable object-store boundary. put_immutable MUST be an atomic server-side
/// create-if-absent operation. Client-side read-then-unconditional-write does not satisfy it.
/// Existing objects must never be overwritten.
pub trait Pfm5ImmutableObjectProviderTransport {
    type Error: fmt::Display;

    fn put_immutable(
        &mut self,
        key: &[u8],
        bytes: &[u8],
    ) -> Result<Pfm5ImmutablePutOutcome, Self::Error>;

    fn get(&mut self, key: &[u8]) -> Result<Vec<u8>, Self::Error>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pfm5ObjectError {
    InvalidKey,
    EmptyObject,
    ObjectTooLarge,
    BundleTooLarge,
    ObjectCountMismatch,
    BranchSetMismatch,
    DomainMismatch,
    ManifestAnchorMismatch,
    ReadbackMismatch,
    Provider(String),
    Manifest(String),
    Checkpoint(String),
    Branch(String),
    ArchiveReplay(String),
}

impl fmt::Display for Pfm5ObjectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Pfm5ObjectError {}

/// Fully decoded and replay-validated immutable object set for one exact PFM5 manifest.
/// Branch bytes are canonicalized into the digest order recorded by the manifest.
#[derive(Debug, Clone)]
pub struct Pfm5ImmutableObjectBundle {
    manifest: Pfm5CheckpointManifest,
    manifest_bytes: Vec<u8>,
    checkpoint_bytes: Vec<u8>,
    branch_envelopes: Vec<Vec<u8>>,
    manifest_commitment: [u8; 32],
    total_bytes: usize,
}

impl Pfm5ImmutableObjectBundle {
    pub fn from_parts<V: MlDsa65Verifier>(
        manifest_bytes: Vec<u8>,
        checkpoint_bytes: Vec<u8>,
        branch_envelopes: Vec<Vec<u8>>,
        context: &Pcp4ValidationContext<'_>,
        minimum_generation: u64,
        minimum_checkpoint_height: u64,
        verifier: &V,
    ) -> Result<Self, Pfm5ObjectError> {
        if manifest_bytes.is_empty() || checkpoint_bytes.is_empty() {
            return Err(Pfm5ObjectError::EmptyObject);
        }
        if manifest_bytes.len() > MAX_PFM5_MANIFEST_BYTES
            || checkpoint_bytes.len() > MAX_PCP4_RECORD_BYTES
        {
            return Err(Pfm5ObjectError::ObjectTooLarge);
        }
        if branch_envelopes.len() > MAX_V4_HYBRID_FORK_ARCHIVE_BLOCKS {
            return Err(Pfm5ObjectError::ObjectCountMismatch);
        }
        let manifest = Pfm5CheckpointManifest::decode(&manifest_bytes)
            .map_err(|error| Pfm5ObjectError::Manifest(error.to_string()))?;
        let manifest_commitment = manifest
            .commitment()
            .map_err(|error| Pfm5ObjectError::Manifest(error.to_string()))?;
        let expected_genesis = trusted_genesis_fingerprint(context)
            .map_err(|error| Pfm5ObjectError::Checkpoint(error.to_string()))?;
        if manifest.network_id != *context.network_id
            || manifest.genesis_fingerprint != expected_genesis
            || manifest.branch_digests.len() != branch_envelopes.len()
        {
            return Err(Pfm5ObjectError::DomainMismatch);
        }
        let checkpoint = Pcp4CheckpointRecord::decode(&checkpoint_bytes, context)
            .map_err(|error| Pfm5ObjectError::Checkpoint(error.to_string()))?;
        manifest
            .validate_checkpoint(&checkpoint, context)
            .map_err(|error| Pfm5ObjectError::Manifest(error.to_string()))?;

        let mut supplied = BTreeMap::new();
        let mut branch_bytes_total = 0usize;
        for envelope in branch_envelopes {
            if envelope.is_empty()
                || envelope.len() > MAX_PRIVATE_TESTNET_V4_HYBRID_MONETARY_ENVELOPE_BYTES
            {
                return Err(Pfm5ObjectError::ObjectTooLarge);
            }
            branch_bytes_total = branch_bytes_total
                .checked_add(envelope.len())
                .ok_or(Pfm5ObjectError::BundleTooLarge)?;
            if branch_bytes_total > MAX_V4_HYBRID_FORK_ARCHIVE_BYTES {
                return Err(Pfm5ObjectError::BundleTooLarge);
            }
            let decoded = decode_candidate_v4_hybrid_monetary_network_block(&envelope)
                .map_err(|error| Pfm5ObjectError::Branch(error.to_string()))?;
            if decoded.header.network_id != manifest.network_id {
                return Err(Pfm5ObjectError::DomainMismatch);
            }
            let digest = pow_digest(&decoded.header, context.params.pow)
                .map_err(|error| Pfm5ObjectError::Branch(format!("{error:?}")))?;
            if supplied.insert(digest, envelope).is_some() {
                return Err(Pfm5ObjectError::BranchSetMismatch);
            }
        }

        let mut ordered = Vec::with_capacity(manifest.branch_digests.len());
        for digest in &manifest.branch_digests {
            ordered.push(
                supplied
                    .remove(digest)
                    .ok_or(Pfm5ObjectError::BranchSetMismatch)?,
            );
        }
        if !supplied.is_empty() {
            return Err(Pfm5ObjectError::BranchSetMismatch);
        }
        // Rebuild from the trusted checkpoint and every retained envelope; matching hashes alone
        // is not enough to establish branch ancestry, signatures, state roots or fork-choice state.
        PrivateTestnetV4HybridForkChoice::rebuild_from_pfm5_checkpoint(
            &manifest,
            &checkpoint,
            context,
            manifest_commitment,
            minimum_generation,
            minimum_checkpoint_height,
            ordered.clone(),
            verifier,
        )
        .map_err(|error| Pfm5ObjectError::ArchiveReplay(format!("{error:?}")))?;

        let total_bytes = manifest_bytes
            .len()
            .checked_add(checkpoint_bytes.len())
            .and_then(|total| total.checked_add(branch_bytes_total))
            .ok_or(Pfm5ObjectError::BundleTooLarge)?;
        if total_bytes > MAX_BUNDLE_BYTES {
            return Err(Pfm5ObjectError::BundleTooLarge);
        }

        Ok(Self {
            manifest,
            manifest_bytes,
            checkpoint_bytes,
            branch_envelopes: ordered,
            manifest_commitment,
            total_bytes,
        })
    }

    pub fn manifest(&self) -> &Pfm5CheckpointManifest {
        &self.manifest
    }
    pub fn manifest_commitment(&self) -> [u8; 32] {
        self.manifest_commitment
    }
    pub fn object_count(&self) -> usize {
        2 + self.branch_envelopes.len()
    }
    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    fn entries(&self) -> Vec<(Pfm5ImmutableObjectKey, &[u8])> {
        let mut entries = Vec::with_capacity(self.object_count());
        entries.push((
            Pfm5ImmutableObjectKey {
                kind: Pfm5ImmutableObjectKind::Checkpoint,
                network_id: self.manifest.network_id,
                genesis_fingerprint: self.manifest.genesis_fingerprint,
                digest: self.manifest.checkpoint_record_commitment,
            },
            self.checkpoint_bytes.as_slice(),
        ));
        for (digest, bytes) in self
            .manifest
            .branch_digests
            .iter()
            .zip(self.branch_envelopes.iter())
        {
            entries.push((
                Pfm5ImmutableObjectKey {
                    kind: Pfm5ImmutableObjectKind::Branch,
                    network_id: self.manifest.network_id,
                    genesis_fingerprint: self.manifest.genesis_fingerprint,
                    digest: *digest,
                },
                bytes.as_slice(),
            ));
        }
        entries.push((
            Pfm5ImmutableObjectKey {
                kind: Pfm5ImmutableObjectKind::Manifest,
                network_id: self.manifest.network_id,
                genesis_fingerprint: self.manifest.genesis_fingerprint,
                digest: self.manifest_commitment,
            },
            self.manifest_bytes.as_slice(),
        ));
        entries
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pfm5ObjectPublishReport {
    pub manifest_commitment: [u8; 32],
    pub object_count: usize,
    pub total_bytes: usize,
}
/// Read-back-verifying client. Object-provider identity is not authenticated here; typed content
/// commitments prove byte identity, while the caller separately authenticates the ECR1 anchor.
pub struct Pfm5ImmutableObjectClient<P> {
    provider: P,
}

impl<P: Pfm5ImmutableObjectProviderTransport> Pfm5ImmutableObjectClient<P> {
    pub fn new(provider: P) -> Self {
        Self { provider }
    }

    pub fn into_inner(self) -> P {
        self.provider
    }

    /// Publish checkpoint, then all branches, then manifest. Each object must read back byte
    /// exactly and pass typed validation before the next object is attempted. The returned
    /// commitment may be proposed as ECR1 next_state_digest only after this succeeds.
    pub fn publish_bundle(
        &mut self,
        bundle: &Pfm5ImmutableObjectBundle,
        context: &Pcp4ValidationContext<'_>,
    ) -> Result<Pfm5ObjectPublishReport, Pfm5ObjectError> {
        for (key, bytes) in bundle.entries() {
            verify_object(&key, bytes, context)?;
            let encoded_key = key.encode()?;
            self.provider
                .put_immutable(&encoded_key, bytes)
                .map_err(|error| Pfm5ObjectError::Provider(error.to_string()))?;
            let read_back = self
                .provider
                .get(&encoded_key)
                .map_err(|error| Pfm5ObjectError::Provider(error.to_string()))?;
            check_object_size(key.kind, &read_back)?;
            if read_back != bytes {
                return Err(Pfm5ObjectError::ReadbackMismatch);
            }
            verify_object(&key, &read_back, context)?;
        }
        Ok(Pfm5ObjectPublishReport {
            manifest_commitment: bundle.manifest_commitment,
            object_count: bundle.object_count(),
            total_bytes: bundle.total_bytes,
        })
    }

    /// Fetch from a manifest commitment obtained from a separately authenticated signed ECR1
    /// read. All referenced objects are checked and the complete branch graph is replayed.
    pub fn fetch_bundle<V: MlDsa65Verifier>(
        &mut self,
        expected_manifest_commitment: [u8; 32],
        context: &Pcp4ValidationContext<'_>,
        minimum_generation: u64,
        minimum_checkpoint_height: u64,
        verifier: &V,
    ) -> Result<Pfm5ImmutableObjectBundle, Pfm5ObjectError> {
        if expected_manifest_commitment == [0; 32] {
            return Err(Pfm5ObjectError::ManifestAnchorMismatch);
        }
        let genesis_fingerprint = trusted_genesis_fingerprint(context)
            .map_err(|error| Pfm5ObjectError::Checkpoint(error.to_string()))?;
        let manifest_key = Pfm5ImmutableObjectKey {
            kind: Pfm5ImmutableObjectKind::Manifest,
            network_id: *context.network_id,
            genesis_fingerprint,
            digest: expected_manifest_commitment,
        };
        let manifest_bytes = self.fetch_one(&manifest_key, context)?;
        let manifest = Pfm5CheckpointManifest::decode(&manifest_bytes)
            .map_err(|error| Pfm5ObjectError::Manifest(error.to_string()))?;
        if manifest
            .commitment()
            .map_err(|error| Pfm5ObjectError::Manifest(error.to_string()))?
            != expected_manifest_commitment
        {
            return Err(Pfm5ObjectError::ManifestAnchorMismatch);
        }

        let checkpoint_key = Pfm5ImmutableObjectKey {
            kind: Pfm5ImmutableObjectKind::Checkpoint,
            network_id: manifest.network_id,
            genesis_fingerprint: manifest.genesis_fingerprint,
            digest: manifest.checkpoint_record_commitment,
        };
        let checkpoint_bytes = self.fetch_one(&checkpoint_key, context)?;
        let mut branches = Vec::with_capacity(manifest.branch_digests.len());
        for digest in &manifest.branch_digests {
            let key = Pfm5ImmutableObjectKey {
                kind: Pfm5ImmutableObjectKind::Branch,
                network_id: manifest.network_id,
                genesis_fingerprint: manifest.genesis_fingerprint,
                digest: *digest,
            };
            branches.push(self.fetch_one(&key, context)?);
        }

        Pfm5ImmutableObjectBundle::from_parts(
            manifest_bytes,
            checkpoint_bytes,
            branches,
            context,
            minimum_generation,
            minimum_checkpoint_height,
            verifier,
        )
    }

    fn fetch_one(
        &mut self,
        key: &Pfm5ImmutableObjectKey,
        context: &Pcp4ValidationContext<'_>,
    ) -> Result<Vec<u8>, Pfm5ObjectError> {
        let encoded_key = key.encode()?;
        let bytes = self
            .provider
            .get(&encoded_key)
            .map_err(|error| Pfm5ObjectError::Provider(error.to_string()))?;
        check_object_size(key.kind, &bytes)?;
        verify_object(key, &bytes, context)?;
        Ok(bytes)
    }
}

fn check_object_size(kind: Pfm5ImmutableObjectKind, bytes: &[u8]) -> Result<(), Pfm5ObjectError> {
    if bytes.is_empty() {
        return Err(Pfm5ObjectError::EmptyObject);
    }
    if bytes.len() > kind.max_bytes() {
        return Err(Pfm5ObjectError::ObjectTooLarge);
    }
    Ok(())
}
fn verify_object(
    key: &Pfm5ImmutableObjectKey,
    bytes: &[u8],
    context: &Pcp4ValidationContext<'_>,
) -> Result<(), Pfm5ObjectError> {
    key.validate()?;
    check_object_size(key.kind, bytes)?;
    let trusted_genesis = trusted_genesis_fingerprint(context)
        .map_err(|error| Pfm5ObjectError::Checkpoint(error.to_string()))?;
    if key.network_id != *context.network_id || key.genesis_fingerprint != trusted_genesis {
        return Err(Pfm5ObjectError::DomainMismatch);
    }
    match key.kind {
        Pfm5ImmutableObjectKind::Manifest => {
            let manifest = Pfm5CheckpointManifest::decode(bytes)
                .map_err(|error| Pfm5ObjectError::Manifest(error.to_string()))?;
            if manifest.network_id != key.network_id
                || manifest.genesis_fingerprint != key.genesis_fingerprint
                || manifest
                    .commitment()
                    .map_err(|error| Pfm5ObjectError::Manifest(error.to_string()))?
                    != key.digest
            {
                return Err(Pfm5ObjectError::ManifestAnchorMismatch);
            }
        }
        Pfm5ImmutableObjectKind::Checkpoint => {
            let checkpoint = Pcp4CheckpointRecord::decode(bytes, context)
                .map_err(|error| Pfm5ObjectError::Checkpoint(error.to_string()))?;
            if checkpoint.genesis_fingerprint != key.genesis_fingerprint
                || checkpoint
                    .commitment(context)
                    .map_err(|error| Pfm5ObjectError::Checkpoint(error.to_string()))?
                    != key.digest
            {
                return Err(Pfm5ObjectError::Checkpoint(
                    "PCP4 key does not match record commitment".to_string(),
                ));
            }
        }
        Pfm5ImmutableObjectKind::Branch => {
            let decoded = decode_candidate_v4_hybrid_monetary_network_block(bytes)
                .map_err(|error| Pfm5ObjectError::Branch(error.to_string()))?;
            let digest = pow_digest(&decoded.header, context.params.pow)
                .map_err(|error| Pfm5ObjectError::Branch(format!("{error:?}")))?;
            if decoded.header.network_id != key.network_id || digest != key.digest {
                return Err(Pfm5ObjectError::Branch(
                    "PMT4 key does not match network or PoW digest".to_string(),
                ));
            }
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chain_admission::{
            ReferenceTimeError, ReferenceTimeProvenance, ReferenceTimeProvider, ReferenceTimeSample,
        },
        consensus::{ConsensusParameters, PowHeader, Uint256},
        private_testnet_checkpoint_candidate::{
            consensus_profile_fingerprint, trusted_genesis_fingerprint, Pcp4CheckpointRecord,
        },
        private_testnet_driver::PrivateTestnetChain,
        private_testnet_monetary_wire::encode_candidate_v4_hybrid_monetary_network_block,
        private_testnet_pfm5_fork_store_candidate::PrivateTestnetPfm5ForkStoreCandidate,
        state_machine::{
            MonetaryLedgerState, V4HybridMonetaryBlock, MONETARY_PUBLIC_GOODS_BUDGET_ATOMS,
        },
        v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate,
    };
    use std::{
        collections::BTreeMap,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    const NETWORK: [u8; 32] = [0x81; 32];
    const TX_MANIFEST: [u8; 32] = [0x44; 32];
    static NEXT_DIR: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);
    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "ain1-pfm5-object-{}-{}",
                std::process::id(),
                NEXT_DIR.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }
    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    struct FixedClock;
    impl ReferenceTimeProvider for FixedClock {
        fn sample(&self) -> Result<ReferenceTimeSample, ReferenceTimeError> {
            Ok(ReferenceTimeSample {
                unix_seconds: 200,
                provenance: ReferenceTimeProvenance::ConfiguredProvider,
                source_id: "pfm5-object-test-clock",
            })
        }
    }

    struct Fixture {
        network: [u8; 32],
        genesis: MonetaryLedgerState,
        params: ConsensusParameters,
        tx_manifest: [u8; 32],
        checkpoint: Pcp4CheckpointRecord,
    }
    impl Fixture {
        fn new() -> Self {
            let network = NETWORK;
            let genesis = MonetaryLedgerState::genesis(
                network,
                [0x11; 32],
                vec![([0x22; 32], MONETARY_PUBLIC_GOODS_BUDGET_ATOMS as u64)],
            )
            .unwrap();
            let mut params = ConsensusParameters::candidate_testnet().unwrap();
            params.initial_target = Uint256::MAX;
            params.pow_limit = Uint256::MAX;
            params.pow.memory_kib = 8;
            params.pow.iterations = 1;
            params.pow.lanes = 1;
            let tx_manifest = TX_MANIFEST;
            let context = Pcp4ValidationContext {
                network_id: &network,
                trusted_genesis: &genesis,
                params: &params,
                active_transaction_manifest_id: &tx_manifest,
            };
            let chain = PrivateTestnetChain::new_monetary(genesis.clone(), params.clone()).unwrap();
            let state = chain.monetary_state().unwrap();
            let checkpoint = Pcp4CheckpointRecord {
                network_id: network,
                genesis_fingerprint: trusted_genesis_fingerprint(&context).unwrap(),
                consensus_profile_fingerprint: consensus_profile_fingerprint(&params).unwrap(),
                transaction_manifest_id: tx_manifest,
                logical_height: state.height(),
                consensus_tip_digest: chain.chain_tip().tip_hash,
                ledger_tip_hash: state.tip_hash(),
                monetary_state_root: state.state_root(),
                total_mined_atoms: state.total_mined_atoms(),
                cumulative_chainwork: chain.cumulative_work(),
                parent_checkpoint_commitment: [0; 32],
                monetary_snapshot: state.encode_snapshot().unwrap(),
                target_history: chain.target_history().checkpoint_snapshot().unwrap(),
            };
            Self {
                network,
                genesis,
                params,
                tx_manifest,
                checkpoint,
            }
        }

        fn context(&self) -> Pcp4ValidationContext<'_> {
            Pcp4ValidationContext {
                network_id: &self.network,
                trusted_genesis: &self.genesis,
                params: &self.params,
                active_transaction_manifest_id: &self.tx_manifest,
            }
        }

        fn bundle(
            &self,
            verifier: &LibcruxMlDsa65VerifierCandidate,
            with_branch: bool,
        ) -> Pfm5ImmutableObjectBundle {
            let context = self.context();
            let directory = TestDirectory::new();
            let mut store = PrivateTestnetPfm5ForkStoreCandidate::initialize(
                directory.path(),
                self.checkpoint.clone(),
                &context,
                verifier,
            )
            .unwrap();
            if with_branch {
                let chain =
                    PrivateTestnetChain::new_monetary(self.genesis.clone(), self.params.clone())
                        .unwrap();
                let state = chain.monetary_state().unwrap();
                let mut block = V4HybridMonetaryBlock {
                    height: state.height() + 1,
                    timestamp: 100 + state.height(),
                    parent_hash: state.tip_hash(),
                    state_root: [0; 32],
                    transactions: Vec::new(),
                    miner: [0x33; 32],
                    claimed_subsidy_atoms: state.expected_miner_reward().unwrap(),
                };
                block.state_root = state
                    .preview_v4_hybrid_state_root_after(&block, &self.tx_manifest, verifier)
                    .unwrap();
                let header = PowHeader {
                    protocol_version: self.params.protocol_version,
                    network_id: self.network,
                    height: block.height,
                    timestamp: block.timestamp,
                    parent_hash: block.parent_hash,
                    previous_consensus_hash: chain.chain_tip().tip_hash,
                    state_root: block.state_root,
                    target: chain.expected_target(None).unwrap(),
                    nonce: 0x0102_0304_0506_0708,
                };
                let envelope =
                    encode_candidate_v4_hybrid_monetary_network_block(&header, &block).unwrap();
                store
                    .submit_local(&envelope, verifier, &FixedClock)
                    .unwrap();
            }
            let branches = store
                .archive()
                .archive_envelopes_bounded(
                    MAX_V4_HYBRID_FORK_ARCHIVE_BLOCKS,
                    MAX_V4_HYBRID_FORK_ARCHIVE_BYTES,
                )
                .unwrap();
            Pfm5ImmutableObjectBundle::from_parts(
                store.manifest().encode().unwrap(),
                self.checkpoint.encode(&context).unwrap(),
                branches,
                &context,
                store.manifest().generation,
                store.manifest().checkpoint_height,
                verifier,
            )
            .unwrap()
        }
    }
    #[derive(Default)]
    struct MemoryProvider {
        objects: BTreeMap<Vec<u8>, Vec<u8>>,
        writes: Vec<Vec<u8>>,
    }
    #[derive(Debug)]
    struct MemoryError(&'static str);
    impl fmt::Display for MemoryError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.0)
        }
    }
    impl Pfm5ImmutableObjectProviderTransport for MemoryProvider {
        type Error = MemoryError;
        fn put_immutable(
            &mut self,
            key: &[u8],
            bytes: &[u8],
        ) -> Result<Pfm5ImmutablePutOutcome, Self::Error> {
            self.writes.push(key.to_vec());
            match self.objects.get(key) {
                Some(_) => Ok(Pfm5ImmutablePutOutcome::AlreadyPresent),
                None => {
                    self.objects.insert(key.to_vec(), bytes.to_vec());
                    Ok(Pfm5ImmutablePutOutcome::Created)
                }
            }
        }
        fn get(&mut self, key: &[u8]) -> Result<Vec<u8>, Self::Error> {
            self.objects
                .get(key)
                .cloned()
                .ok_or(MemoryError("missing immutable object"))
        }
    }

    #[test]
    fn object_key_is_canonical_and_domain_separated() {
        let key = Pfm5ImmutableObjectKey {
            kind: Pfm5ImmutableObjectKind::Branch,
            network_id: [1; 32],
            genesis_fingerprint: [2; 32],
            digest: [3; 32],
        };
        assert_eq!(
            Pfm5ImmutableObjectKey::decode(&key.encode().unwrap()).unwrap(),
            key
        );
        let mut other_network = key;
        other_network.network_id = [4; 32];
        assert_ne!(key.encode().unwrap(), other_network.encode().unwrap());
        let mut other_kind = key;
        other_kind.kind = Pfm5ImmutableObjectKind::Checkpoint;
        assert_ne!(key.encode().unwrap(), other_kind.encode().unwrap());
        let mut bad = key.encode().unwrap();
        bad[OBJECT_KEY_DOMAIN.len()] = 0xFF;
        assert!(Pfm5ImmutableObjectKey::decode(&bad).is_err());
        assert!(Pfm5ImmutableObjectKey::decode(
            &key.encode().unwrap()[..key.encode().unwrap().len() - 1]
        )
        .is_err());
    }
    #[test]
    fn publish_bundle_orders_objects_and_fetch_replays_exact_snapshot() {
        let fixture = Fixture::new();
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let bundle = fixture.bundle(&verifier, true);
        let anchor = bundle.manifest_commitment();
        let mut client = Pfm5ImmutableObjectClient::new(MemoryProvider::default());
        let report = client.publish_bundle(&bundle, &fixture.context()).unwrap();
        assert_eq!(report.manifest_commitment, anchor);
        assert_eq!(report.object_count, 3);

        let provider = client.into_inner();
        let kinds: Vec<_> = provider
            .writes
            .iter()
            .map(|key| Pfm5ImmutableObjectKey::decode(key).unwrap().kind)
            .collect();
        assert_eq!(
            kinds,
            vec![
                Pfm5ImmutableObjectKind::Checkpoint,
                Pfm5ImmutableObjectKind::Branch,
                Pfm5ImmutableObjectKind::Manifest,
            ]
        );

        let mut client = Pfm5ImmutableObjectClient::new(provider);
        let fetched = client
            .fetch_bundle(
                anchor,
                &fixture.context(),
                bundle.manifest().generation,
                bundle.manifest().checkpoint_height,
                &verifier,
            )
            .unwrap();
        assert_eq!(fetched.manifest_commitment(), anchor);
        assert_eq!(fetched.manifest(), bundle.manifest());
        assert_eq!(fetched.object_count(), bundle.object_count());
    }

    #[test]
    fn immutable_conflict_is_not_overwritten_and_manifest_is_not_published() {
        let fixture = Fixture::new();
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let bundle = fixture.bundle(&verifier, false);
        let (key, _) = bundle.entries()[0];
        let encoded_key = key.encode().unwrap();
        let mut provider = MemoryProvider::default();
        provider
            .objects
            .insert(encoded_key.clone(), b"old conflicting bytes".to_vec());
        let mut client = Pfm5ImmutableObjectClient::new(provider);
        assert!(matches!(
            client.publish_bundle(&bundle, &fixture.context()),
            Err(Pfm5ObjectError::ReadbackMismatch)
        ));
        let provider = client.into_inner();
        assert_eq!(provider.objects[&encoded_key], b"old conflicting bytes");
        assert!(!provider.objects.keys().any(|key| {
            Pfm5ImmutableObjectKey::decode(key).unwrap().kind == Pfm5ImmutableObjectKind::Manifest
        }));
    }
    #[test]
    fn fetch_rejects_corrupt_branch_even_when_manifest_anchor_is_correct() {
        let fixture = Fixture::new();
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let bundle = fixture.bundle(&verifier, true);
        let anchor = bundle.manifest_commitment();
        let mut client = Pfm5ImmutableObjectClient::new(MemoryProvider::default());
        client.publish_bundle(&bundle, &fixture.context()).unwrap();
        let mut provider = client.into_inner();
        let branch_key = provider
            .objects
            .keys()
            .find(|key| {
                Pfm5ImmutableObjectKey::decode(key).unwrap().kind == Pfm5ImmutableObjectKind::Branch
            })
            .unwrap()
            .clone();
        provider.objects.get_mut(&branch_key).unwrap()[0] ^= 1;
        let mut client = Pfm5ImmutableObjectClient::new(provider);
        assert!(matches!(
            client.fetch_bundle(anchor, &fixture.context(), 1, 0, &verifier),
            Err(Pfm5ObjectError::Branch(_))
        ));
    }

    #[test]
    fn fetch_requires_nonzero_manifest_anchor_and_missing_objects_fail_closed() {
        let fixture = Fixture::new();
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let bundle = fixture.bundle(&verifier, false);
        let mut client = Pfm5ImmutableObjectClient::new(MemoryProvider::default());
        assert!(matches!(
            client.fetch_bundle([0; 32], &fixture.context(), 1, 0, &verifier),
            Err(Pfm5ObjectError::ManifestAnchorMismatch)
        ));
        assert!(matches!(
            client.fetch_bundle(
                bundle.manifest_commitment(),
                &fixture.context(),
                1,
                0,
                &verifier
            ),
            Err(Pfm5ObjectError::Provider(_))
        ));
    }
}
