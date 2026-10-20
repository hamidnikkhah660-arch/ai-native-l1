//! Candidate adaptive bucket/chunk authenticated commitment.
//!
//! This remains pre-activation. A 16-bit primary bucket is retained for the
//! hot path. When a bucket exceeds CHUNK_CAP leaves, the bucket is recursively
//! split by subsequent key bytes until every terminal chunk is bounded.
//!
//! The construction deliberately uses the 32-byte authenticated key, so a
//! distinct-key bucket can require at most MAX_SUFFIX_DEPTH split levels.

use crate::asset_state_candidate::{AccountId, AssetStateCandidate};
use crate::token_forge::{encode_definition, AssetId, NetworkId};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::OnceLock};

pub const ADAPTIVE_COMMITMENT_DOMAIN: &[u8] = b"AIN1-ASSET-COMMIT-ADAPT-CAND-V1\0";
pub const ADAPTIVE_KEY_DOMAIN: &[u8] = b"AIN1-ASSET-COMMIT-ADAPT-KEY-CAND-V1\0";
pub const ADAPTIVE_LEAF_DOMAIN: &[u8] = b"AIN1-ASSET-COMMIT-ADAPT-LEAF-CAND-V1\0";
pub const ADAPTIVE_CHUNK_DOMAIN: &[u8] = b"AIN1-ASSET-COMMIT-ADAPT-CHUNK-CAND-V1\0";
pub const ADAPTIVE_NODE_DOMAIN: &[u8] = b"AIN1-ASSET-COMMIT-ADAPT-NODE-CAND-V1\0";
pub const ADAPTIVE_NETWORK_ROOT_DOMAIN: &[u8] = b"AIN1-ASSET-COMMIT-ADAPT-NETWORK-ROOT-CAND-V1\0";

const PRIMARY_BUCKET_BITS: usize = 16;
pub const CHUNK_CAP: usize = 32;
const MAX_SUFFIX_DEPTH: usize = 32 - 2;
pub const MAX_PROOF_VALUE_BYTES: usize = 1_048_576;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdaptiveCommitmentError {
    InvalidNetworkId,
    ZeroKey,
    EmptyValue,
    InvalidStructure,
    AssetState(crate::asset_state_candidate::AssetStateCandidateError),
    TokenForge(crate::token_forge::TokenForgeError),
}

impl From<crate::asset_state_candidate::AssetStateCandidateError> for AdaptiveCommitmentError {
    fn from(value: crate::asset_state_candidate::AssetStateCandidateError) -> Self {
        Self::AssetState(value)
    }
}

impl From<crate::token_forge::TokenForgeError> for AdaptiveCommitmentError {
    fn from(value: crate::token_forge::TokenForgeError) -> Self {
        Self::TokenForge(value)
    }
}

impl std::fmt::Display for AdaptiveCommitmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidNetworkId => write!(f, "adaptive commitment network ID is zero"),
            Self::ZeroKey => write!(f, "adaptive commitment key is zero"),
            Self::EmptyValue => write!(f, "adaptive commitment value is empty"),
            Self::InvalidStructure => write!(f, "adaptive commitment structure is invalid"),
            Self::AssetState(error) => write!(f, "asset-state error: {error}"),
            Self::TokenForge(error) => write!(f, "token-forge error: {error}"),
        }
    }
}

impl std::error::Error for AdaptiveCommitmentError {}

/// A typed wrapper around the inner adaptive-tree root.
///
/// This type labels the root layer; it does not imply the bytes are trusted or network-bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AdaptiveInnerRoot([u8; 32]);

impl AdaptiveInnerRoot {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Typed NetworkId-bound outer root for the adaptive commitment candidate.
///
/// The type prevents accidental substitution of an inner root for an outer root, but
/// does not authenticate arbitrary bytes. Authentication must still occur against the
/// intended network's trusted header/state context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AdaptiveNetworkBoundRoot {
    network_id: NetworkId,
    digest: [u8; 32],
}

impl AdaptiveNetworkBoundRoot {
    /// Wrap externally supplied candidate bytes. This validates only the NetworkId shape;
    /// callers must separately authenticate the root in the intended header/state context.
    pub fn from_untrusted_parts(
        network_id: NetworkId,
        digest: [u8; 32],
    ) -> Result<Self, AdaptiveCommitmentError> {
        if network_id.iter().all(|byte| *byte == 0) {
            return Err(AdaptiveCommitmentError::InvalidNetworkId);
        }
        Ok(Self { network_id, digest })
    }

    pub const fn network_id(&self) -> NetworkId {
        self.network_id
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.digest
    }

    pub const fn into_parts(self) -> (NetworkId, [u8; 32]) {
        (self.network_id, self.digest)
    }
}

type LeafMap = BTreeMap<[u8; 32], [u8; 32]>;

#[derive(Debug, Clone, PartialEq, Eq)]
struct TrieNode {
    prefix: Vec<u8>,
    entries: LeafMap,
    children: BTreeMap<u8, Box<TrieNode>>,
    count: usize,
    hash: [u8; 32],
}

impl TrieNode {
    fn empty(prefix: Vec<u8>) -> Self {
        Self {
            prefix,
            entries: BTreeMap::new(),
            children: BTreeMap::new(),
            count: 0,
            hash: [0u8; 32],
        }
    }

    fn new_leaf(prefix: Vec<u8>, entries: LeafMap) -> Self {
        let count = entries.len();
        let hash = hash_chunk(&prefix, &entries);
        Self {
            prefix,
            entries,
            children: BTreeMap::new(),
            count,
            hash,
        }
    }

    fn set(
        &mut self,
        key: [u8; 32],
        value: Option<[u8; 32]>,
    ) -> Result<(), AdaptiveCommitmentError> {
        if self.children.is_empty() {
            match value {
                Some(value_hash) => {
                    self.entries.insert(key, value_hash);
                }
                None => {
                    self.entries.remove(&key);
                }
            }
            self.count = self.entries.len();

            if self.count == 0 {
                self.hash = [0u8; 32];
                return Ok(());
            }

            if self.count > CHUNK_CAP {
                self.split()?;
            } else {
                self.hash = hash_chunk(&self.prefix, &self.entries);
            }
            return Ok(());
        }

        let depth = self.prefix.len();
        if depth >= MAX_SUFFIX_DEPTH {
            return Err(AdaptiveCommitmentError::InvalidStructure);
        }
        let child_byte = key[2 + depth];
        let child = self.children.entry(child_byte).or_insert_with(|| {
            Box::new(TrieNode::new_leaf(
                {
                    let mut child_prefix = self.prefix.clone();
                    child_prefix.push(child_byte);
                    child_prefix
                },
                LeafMap::new(),
            ))
        });

        child.set(key, value)?;

        if child.count == 0 {
            self.children.remove(&child_byte);
        }
        self.count = self.children.values().map(|node| node.count).sum();

        if self.count == 0 {
            self.hash = [0u8; 32];
            return Ok(());
        }

        if self.count <= CHUNK_CAP {
            let entries = collect_entries(&self.children)?;
            self.entries = entries;
            self.children.clear();
            self.count = self.entries.len();
            self.hash = hash_chunk(&self.prefix, &self.entries);
        } else {
            self.entries.clear();
            self.hash = hash_internal(&self.prefix, &self.children);
        }
        Ok(())
    }

    fn split(&mut self) -> Result<(), AdaptiveCommitmentError> {
        let depth = self.prefix.len();
        if depth >= MAX_SUFFIX_DEPTH {
            return Err(AdaptiveCommitmentError::InvalidStructure);
        }

        let next_index = 2 + depth;
        let entries = std::mem::take(&mut self.entries);
        let mut children: BTreeMap<u8, Box<TrieNode>> = BTreeMap::new();

        for (key, value_hash) in entries {
            let child_byte = key[next_index];
            let child = children.entry(child_byte).or_insert_with(|| {
                let mut child_prefix = self.prefix.clone();
                child_prefix.push(child_byte);
                Box::new(TrieNode::new_leaf(child_prefix, LeafMap::new()))
            });
            child.entries.insert(key, value_hash);
            child.count = child.entries.len();
        }

        self.children = children;
        self.count = self.children.values().map(|node| node.count).sum();

        for child in self.children.values_mut() {
            child.hash = hash_chunk(&child.prefix, &child.entries);
            if child.count > CHUNK_CAP {
                child.split()?;
            }
        }

        self.hash = hash_internal(&self.prefix, &self.children);
        Ok(())
    }

    fn max_chunk_len_and_depth(&self, internal_depth: usize) -> (usize, usize) {
        if self.children.is_empty() {
            return (self.entries.len(), internal_depth);
        }
        self.children
            .values()
            .map(|node| node.max_chunk_len_and_depth(internal_depth + 1))
            .max()
            .unwrap_or((0, internal_depth))
    }

    fn collect_membership_path(
        &self,
        key: [u8; 32],
        levels: &mut Vec<AdaptiveSecondaryProofLevel>,
    ) -> Result<LeafMap, AdaptiveCommitmentError> {
        if self.children.is_empty() {
            if self.entries.contains_key(&key) {
                return Ok(self.entries.clone());
            }
            return Err(AdaptiveCommitmentError::InvalidStructure);
        }

        let depth = self.prefix.len();
        if depth >= MAX_SUFFIX_DEPTH {
            return Err(AdaptiveCommitmentError::InvalidStructure);
        }
        let child_byte = key[2 + depth];
        let child = self
            .children
            .get(&child_byte)
            .ok_or(AdaptiveCommitmentError::InvalidStructure)?;
        let entries = child.collect_membership_path(key, levels)?;

        let siblings = sparse_siblings(&self.children, child_byte);
        levels.push(AdaptiveSecondaryProofLevel { siblings });
        Ok(entries)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AdaptiveBucket {
    root: TrieNode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdaptiveSecondaryProofLevel {
    /// Exactly eight sibling hashes for the fixed 8-bit sparse-Merkle child index.
    /// Order is bottom-up: bit 0 through bit 7 of the path byte.
    pub siblings: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdaptiveMembershipProof {
    pub leaf_key: [u8; 32],
    pub value: Vec<u8>,
    pub chunk_entries: Vec<([u8; 32], [u8; 32])>,
    /// Levels are encoded from the terminal chunk parent back toward the bucket root.
    pub secondary_levels: Vec<AdaptiveSecondaryProofLevel>,
    /// Siblings are encoded from the bucket leaf (depth 16) toward the top root (depth 0).
    pub top_siblings: Vec<[u8; 32]>,
}

impl AdaptiveBucket {
    fn new() -> Self {
        Self {
            root: TrieNode::empty(Vec::new()),
        }
    }

    fn from_entries(entries: LeafMap) -> Result<Self, AdaptiveCommitmentError> {
        Ok(Self {
            root: build_trie_node(Vec::new(), entries)?,
        })
    }

    fn hash(&self) -> [u8; 32] {
        if self.root.count == 0 {
            empty_bucket_hash()
        } else {
            self.root.hash
        }
    }

    fn set(
        &mut self,
        key: [u8; 32],
        value: Option<[u8; 32]>,
    ) -> Result<(), AdaptiveCommitmentError> {
        self.root.set(key, value)
    }

    fn max_chunk_len_and_depth(&self) -> (usize, usize) {
        self.root.max_chunk_len_and_depth(0)
    }

    fn membership_proof(
        &self,
        key: [u8; 32],
    ) -> Result<(LeafMap, Vec<AdaptiveSecondaryProofLevel>), AdaptiveCommitmentError> {
        let mut levels = Vec::new();
        let entries = self.root.collect_membership_path(key, &mut levels)?;
        Ok((entries, levels))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct TopNodeKey {
    depth: u8,
    prefix: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdaptiveAssetStateCommitment {
    network_id: NetworkId,
    height: u64,
    buckets: BTreeMap<u16, AdaptiveBucket>,
    top_nodes: BTreeMap<TopNodeKey, [u8; 32]>,
    default_hashes: [[u8; 32]; PRIMARY_BUCKET_BITS + 1],
}

impl AdaptiveAssetStateCommitment {
    /// Create an empty generic candidate tree.
    ///
    /// A fresh value stores `network_id` and `height` as builder metadata, but does not
    /// insert the state-height leaf. Consequently, `root()` on a fresh value is the
    /// generic empty-tree root and does not commit to either metadata field. Use
    /// `from_state()` / `rebuild_from_state()` for a state-derived commitment, or insert
    /// the height leaf with `set_height()` after a generic rebuild before treating the
    /// result as height-bound. This API is candidate-only, not a canonical state root.
    pub fn new(network_id: NetworkId, height: u64) -> Result<Self, AdaptiveCommitmentError> {
        if network_id.iter().all(|byte| *byte == 0) {
            return Err(AdaptiveCommitmentError::InvalidNetworkId);
        }
        Ok(Self {
            network_id,
            height,
            buckets: BTreeMap::new(),
            top_nodes: BTreeMap::new(),
            default_hashes: build_default_hashes(),
        })
    }

    pub fn from_state(state: &AssetStateCandidate) -> Result<Self, AdaptiveCommitmentError> {
        state.verify_invariants()?;
        let mut commitment = Self::new(state.network_id(), state.height())?;
        commitment.rebuild_from_state(state)?;
        Ok(commitment)
    }

    pub fn root(&self) -> [u8; 32] {
        self.top_nodes
            .get(&TopNodeKey {
                depth: 0,
                prefix: 0,
            })
            .copied()
            .unwrap_or(self.default_hashes[0])
    }

    pub fn height(&self) -> u64 {
        self.height
    }

    pub fn bucket_count(&self) -> usize {
        self.buckets.len()
    }

    pub fn largest_bucket_len(&self) -> usize {
        self.buckets
            .values()
            .map(|bucket| bucket.root.count)
            .max()
            .unwrap_or(0)
    }

    pub fn largest_terminal_chunk_len(&self) -> usize {
        self.buckets
            .values()
            .map(AdaptiveBucket::max_chunk_len_and_depth)
            .map(|(len, _)| len)
            .max()
            .unwrap_or(0)
    }

    pub fn deepest_bucket_path(&self) -> usize {
        self.buckets
            .values()
            .map(AdaptiveBucket::max_chunk_len_and_depth)
            .map(|(_, depth)| depth)
            .max()
            .unwrap_or(0)
    }

    pub fn worst_case_membership_proof_size_upper_bound(
        value_len: usize,
    ) -> Result<usize, AdaptiveCommitmentError> {
        if value_len == 0 || value_len > MAX_PROOF_VALUE_BYTES {
            return Err(AdaptiveCommitmentError::InvalidStructure);
        }
        let leaf_bytes = 32usize
            .checked_add(4)
            .and_then(|bytes| bytes.checked_add(value_len))
            .ok_or(AdaptiveCommitmentError::InvalidStructure)?;
        let chunk_bytes = 1usize
            .checked_add(
                CHUNK_CAP
                    .checked_mul(64)
                    .ok_or(AdaptiveCommitmentError::InvalidStructure)?,
            )
            .ok_or(AdaptiveCommitmentError::InvalidStructure)?;
        let secondary_path = 1usize
            .checked_add(
                MAX_SUFFIX_DEPTH
                    .checked_mul(8 * 32)
                    .ok_or(AdaptiveCommitmentError::InvalidStructure)?,
            )
            .ok_or(AdaptiveCommitmentError::InvalidStructure)?;
        let top_path = 1usize
            .checked_add(
                PRIMARY_BUCKET_BITS
                    .checked_mul(32)
                    .ok_or(AdaptiveCommitmentError::InvalidStructure)?,
            )
            .ok_or(AdaptiveCommitmentError::InvalidStructure)?;
        6usize
            .checked_add(leaf_bytes)
            .and_then(|bytes| bytes.checked_add(chunk_bytes))
            .and_then(|bytes| bytes.checked_add(secondary_path))
            .and_then(|bytes| bytes.checked_add(top_path))
            .ok_or(AdaptiveCommitmentError::InvalidStructure)
    }

    pub fn membership_proof_with_value(
        &self,
        leaf_key: [u8; 32],
        value: &[u8],
    ) -> Result<AdaptiveMembershipProof, AdaptiveCommitmentError> {
        if leaf_key.iter().all(|byte| *byte == 0) {
            return Err(AdaptiveCommitmentError::ZeroKey);
        }
        if value.is_empty() {
            return Err(AdaptiveCommitmentError::EmptyValue);
        }
        if value.len() > MAX_PROOF_VALUE_BYTES {
            return Err(AdaptiveCommitmentError::InvalidStructure);
        }
        let expected_leaf_hash = hash_leaf(leaf_key, value)?;
        let bucket = bucket_for(leaf_key);
        let adaptive_bucket = self
            .buckets
            .get(&bucket)
            .ok_or(AdaptiveCommitmentError::InvalidStructure)?;
        let (chunk_entries, secondary_levels) = adaptive_bucket.membership_proof(leaf_key)?;
        if chunk_entries.get(&leaf_key).copied() != Some(expected_leaf_hash) {
            return Err(AdaptiveCommitmentError::InvalidStructure);
        }

        let mut top_siblings = Vec::with_capacity(PRIMARY_BUCKET_BITS);
        let mut child_prefix = bucket;
        for depth in (0..PRIMARY_BUCKET_BITS).rev() {
            top_siblings.push(self.top_hash(depth + 1, child_prefix ^ 1));
            child_prefix >>= 1;
        }

        Ok(AdaptiveMembershipProof {
            leaf_key,
            value: value.to_vec(),
            chunk_entries: chunk_entries.into_iter().collect(),
            secondary_levels,
            top_siblings,
        })
    }

    /// Verify a proof against the inner adaptive-tree root.
    ///
    /// Candidate limitation: APF1 v1 does not independently bind an arbitrary raw-leaf
    /// commitment to NetworkId. This parameter rejects the all-zero sentinel; callers
    /// must authenticate expected_root in the intended network's trusted state/header
    /// context. See verify_membership_proof_network_bound for the additive outer-root option.
    pub fn verify_membership_proof(
        network_id: NetworkId,
        expected_root: [u8; 32],
        proof: &AdaptiveMembershipProof,
    ) -> Result<bool, AdaptiveCommitmentError> {
        let Some(computed_root) = Self::compute_membership_proof_root(network_id, proof)? else {
            return Ok(false);
        };
        Ok(computed_root == expected_root)
    }

    /// Return the candidate inner root with an explicit type label.
    ///
    /// This is not a network-authenticated root; callers must authenticate it in context.
    pub fn inner_root_typed(&self) -> AdaptiveInnerRoot {
        AdaptiveInnerRoot(self.root())
    }

    /// Typed wrapper for the legacy inner-root verifier. Network context is still supplied
    /// separately because this root type intentionally carries no NetworkId binding.
    pub fn verify_membership_proof_typed(
        network_id: NetworkId,
        expected_root: AdaptiveInnerRoot,
        proof: &AdaptiveMembershipProof,
    ) -> Result<bool, AdaptiveCommitmentError> {
        Self::verify_membership_proof(network_id, expected_root.into_bytes(), proof)
    }

    /// Candidate-only outer root that binds an inner adaptive root to one NetworkId.
    ///
    /// This leaves root() and APF1 v1 bytes unchanged. The outer root itself still must be
    /// authenticated in the intended network context. It is not wired into canonical
    /// block.state_root or production consensus.
    pub fn network_bound_root(&self) -> [u8; 32] {
        Self::bind_root_to_network(self.network_id, self.root())
    }

    /// Same as network_bound_root(), but returns a type distinct from the inner root.
    pub fn network_bound_root_typed(&self) -> AdaptiveNetworkBoundRoot {
        AdaptiveNetworkBoundRoot {
            network_id: self.network_id,
            digest: self.network_bound_root(),
        }
    }

    /// Verify APF1 against the candidate outer root H(domain || NetworkId || inner_root).
    /// This byte-array API is retained for vector harnesses and compatibility experiments.
    pub fn verify_membership_proof_network_bound(
        network_id: NetworkId,
        expected_network_bound_root: [u8; 32],
        proof: &AdaptiveMembershipProof,
    ) -> Result<bool, AdaptiveCommitmentError> {
        let Some(inner_root) = Self::compute_membership_proof_root(network_id, proof)? else {
            return Ok(false);
        };
        Ok(Self::bind_root_to_network(network_id, inner_root) == expected_network_bound_root)
    }

    /// Verify using a typed outer root. The NetworkId is carried by the expected-root value,
    /// preventing the caller from separately pairing an outer-root byte array with a different
    /// NetworkId at this call site. This still does not authenticate the supplied root bytes.
    pub fn verify_membership_proof_network_bound_typed(
        expected_root: AdaptiveNetworkBoundRoot,
        proof: &AdaptiveMembershipProof,
    ) -> Result<bool, AdaptiveCommitmentError> {
        Self::verify_membership_proof_network_bound(
            expected_root.network_id,
            expected_root.digest,
            proof,
        )
    }

    fn bind_root_to_network(network_id: NetworkId, inner_root: [u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(ADAPTIVE_NETWORK_ROOT_DOMAIN);
        hasher.update(network_id);
        hasher.update(inner_root);
        hasher.finalize().into()
    }

    fn compute_membership_proof_root(
        network_id: NetworkId,
        proof: &AdaptiveMembershipProof,
    ) -> Result<Option<[u8; 32]>, AdaptiveCommitmentError> {
        if network_id.iter().all(|byte| *byte == 0)
            || proof.leaf_key.iter().all(|byte| *byte == 0)
            || proof.value.is_empty()
            || proof.value.len() > MAX_PROOF_VALUE_BYTES
            || proof.chunk_entries.is_empty()
            || proof.chunk_entries.len() > CHUNK_CAP
            || proof.secondary_levels.len() > MAX_SUFFIX_DEPTH
            || proof.top_siblings.len() != PRIMARY_BUCKET_BITS
        {
            return Err(AdaptiveCommitmentError::InvalidStructure);
        }

        let expected_leaf_hash = hash_leaf(proof.leaf_key, &proof.value)?;
        let mut entries = BTreeMap::new();
        for (key, leaf_hash) in &proof.chunk_entries {
            if key.iter().all(|byte| *byte == 0) || entries.insert(*key, *leaf_hash).is_some() {
                return Err(AdaptiveCommitmentError::InvalidStructure);
            }
        }
        if entries.get(&proof.leaf_key).copied() != Some(expected_leaf_hash) {
            return Ok(None);
        }

        let prefix_len = proof.secondary_levels.len();
        let prefix = proof.leaf_key[2..2 + prefix_len].to_vec();
        let mut current = hash_chunk(&prefix, &entries);

        for (level_index, level) in proof.secondary_levels.iter().enumerate() {
            let depth = prefix_len - 1 - level_index;
            let path_child = proof.leaf_key[2 + depth];
            current = hash_secondary_proof_root(
                &proof.leaf_key[2..2 + depth],
                current,
                path_child,
                &level.siblings,
            )?;
        }

        let bucket = bucket_for(proof.leaf_key);
        let mut child_prefix = bucket;
        for sibling in &proof.top_siblings {
            current = if child_prefix & 1 == 0 {
                hash_top_node(current, *sibling)
            } else {
                hash_top_node(*sibling, current)
            };
            child_prefix >>= 1;
        }

        Ok(Some(current))
    }

    pub fn membership_proof_size(
        proof: &AdaptiveMembershipProof,
    ) -> Result<usize, AdaptiveCommitmentError> {
        let leaf_bytes = 32usize
            .checked_add(4)
            .and_then(|bytes| bytes.checked_add(proof.value.len()))
            .ok_or(AdaptiveCommitmentError::InvalidStructure)?;
        let chunk_bytes = 1usize
            .checked_add(
                proof
                    .chunk_entries
                    .len()
                    .checked_mul(64)
                    .ok_or(AdaptiveCommitmentError::InvalidStructure)?,
            )
            .ok_or(AdaptiveCommitmentError::InvalidStructure)?;
        let secondary_bytes = 1usize
            .checked_add(
                proof
                    .secondary_levels
                    .len()
                    .checked_mul(8 * 32)
                    .ok_or(AdaptiveCommitmentError::InvalidStructure)?,
            )
            .ok_or(AdaptiveCommitmentError::InvalidStructure)?;
        let top_bytes = 1usize
            .checked_add(
                proof
                    .top_siblings
                    .len()
                    .checked_mul(32)
                    .ok_or(AdaptiveCommitmentError::InvalidStructure)?,
            )
            .ok_or(AdaptiveCommitmentError::InvalidStructure)?;
        6usize
            .checked_add(leaf_bytes)
            .and_then(|bytes| bytes.checked_add(chunk_bytes))
            .and_then(|bytes| bytes.checked_add(secondary_bytes))
            .and_then(|bytes| bytes.checked_add(top_bytes))
            .ok_or(AdaptiveCommitmentError::InvalidStructure)
    }

    /// Candidate-only canonical byte encoding for membership proofs.
    /// This is NOT a production wire format. It is intentionally versioned and
    /// strictly bounded so malformed or trailing bytes fail closed.
    pub fn encode_membership_proof(
        proof: &AdaptiveMembershipProof,
    ) -> Result<Vec<u8>, AdaptiveCommitmentError> {
        if proof.leaf_key.iter().all(|byte| *byte == 0)
            || proof.value.is_empty()
            || proof.value.len() > MAX_PROOF_VALUE_BYTES
            || proof.value.len() > u32::MAX as usize
            || proof.chunk_entries.is_empty()
            || proof.chunk_entries.len() > CHUNK_CAP
            || proof.secondary_levels.len() > MAX_SUFFIX_DEPTH
            || proof.top_siblings.len() != PRIMARY_BUCKET_BITS
        {
            return Err(AdaptiveCommitmentError::InvalidStructure);
        }

        let size = Self::membership_proof_size(proof)?;
        let mut out = Vec::with_capacity(8 + size);
        out.extend_from_slice(b"APF1");
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&proof.leaf_key);
        out.extend_from_slice(&(proof.value.len() as u32).to_be_bytes());
        out.extend_from_slice(&proof.value);
        out.push(proof.chunk_entries.len() as u8);

        let mut previous: Option<[u8; 32]> = None;
        for (key, hash) in &proof.chunk_entries {
            if key.iter().all(|byte| *byte == 0) {
                return Err(AdaptiveCommitmentError::InvalidStructure);
            }
            if let Some(prev) = previous {
                if prev >= *key {
                    return Err(AdaptiveCommitmentError::InvalidStructure);
                }
            }
            previous = Some(*key);
            out.extend_from_slice(key);
            out.extend_from_slice(hash);
        }

        out.push(proof.secondary_levels.len() as u8);
        for level in &proof.secondary_levels {
            if level.siblings.len() != 8 {
                return Err(AdaptiveCommitmentError::InvalidStructure);
            }
            out.extend(level.siblings.iter().flatten());
        }

        out.push(proof.top_siblings.len() as u8);
        out.extend(proof.top_siblings.iter().flatten());
        Ok(out)
    }

    /// Decode the candidate canonical membership-proof encoding.
    /// APF1 v1 carries no NetworkId; callers must authenticate expected_root against
    /// the intended network's trusted state/header context. The verifier's NetworkId
    /// argument is a non-zero guard, not independent network-domain separation.
    pub fn decode_membership_proof(
        bytes: &[u8],
    ) -> Result<AdaptiveMembershipProof, AdaptiveCommitmentError> {
        const MAGIC: &[u8; 4] = b"APF1";
        const VERSION: u16 = 1;

        struct Reader<'a> {
            bytes: &'a [u8],
            offset: usize,
        }

        impl<'a> Reader<'a> {
            fn take(&mut self, len: usize) -> Result<&'a [u8], AdaptiveCommitmentError> {
                let end = self
                    .offset
                    .checked_add(len)
                    .ok_or(AdaptiveCommitmentError::InvalidStructure)?;
                if end > self.bytes.len() {
                    return Err(AdaptiveCommitmentError::InvalidStructure);
                }
                let slice = &self.bytes[self.offset..end];
                self.offset = end;
                Ok(slice)
            }

            fn u8(&mut self) -> Result<u8, AdaptiveCommitmentError> {
                Ok(self.take(1)?[0])
            }

            fn u16(&mut self) -> Result<u16, AdaptiveCommitmentError> {
                Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
            }

            fn u32(&mut self) -> Result<u32, AdaptiveCommitmentError> {
                Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
            }

            fn exact_end(&self) -> Result<(), AdaptiveCommitmentError> {
                if self.offset == self.bytes.len() {
                    Ok(())
                } else {
                    Err(AdaptiveCommitmentError::InvalidStructure)
                }
            }
        }

        let mut reader = Reader { bytes, offset: 0 };
        if reader.take(4)? != MAGIC {
            return Err(AdaptiveCommitmentError::InvalidStructure);
        }
        if reader.u16()? != VERSION {
            return Err(AdaptiveCommitmentError::InvalidStructure);
        }

        let leaf_key: [u8; 32] = reader.take(32)?.try_into().unwrap();
        if leaf_key.iter().all(|byte| *byte == 0) {
            return Err(AdaptiveCommitmentError::ZeroKey);
        }

        let value_len = reader.u32()? as usize;
        if value_len == 0 || value_len > 1_048_576 {
            return Err(AdaptiveCommitmentError::InvalidStructure);
        }
        let value = reader.take(value_len)?.to_vec();

        let chunk_count = reader.u8()? as usize;
        if chunk_count == 0 || chunk_count > CHUNK_CAP {
            return Err(AdaptiveCommitmentError::InvalidStructure);
        }
        let mut chunk_entries = Vec::with_capacity(chunk_count);
        let mut previous: Option<[u8; 32]> = None;
        for _ in 0..chunk_count {
            let key: [u8; 32] = reader.take(32)?.try_into().unwrap();
            let hash: [u8; 32] = reader.take(32)?.try_into().unwrap();
            if key.iter().all(|byte| *byte == 0) {
                return Err(AdaptiveCommitmentError::ZeroKey);
            }
            if let Some(prev) = previous {
                if prev >= key {
                    return Err(AdaptiveCommitmentError::InvalidStructure);
                }
            }
            previous = Some(key);
            chunk_entries.push((key, hash));
        }

        let level_count = reader.u8()? as usize;
        if level_count > MAX_SUFFIX_DEPTH {
            return Err(AdaptiveCommitmentError::InvalidStructure);
        }
        let mut secondary_levels = Vec::with_capacity(level_count);
        for _ in 0..level_count {
            let mut siblings = Vec::with_capacity(8);
            for _ in 0..8 {
                siblings.push(reader.take(32)?.try_into().unwrap());
            }
            secondary_levels.push(AdaptiveSecondaryProofLevel { siblings });
        }

        let top_count = reader.u8()? as usize;
        if top_count != PRIMARY_BUCKET_BITS {
            return Err(AdaptiveCommitmentError::InvalidStructure);
        }
        let mut top_siblings = Vec::with_capacity(top_count);
        for _ in 0..top_count {
            top_siblings.push(reader.take(32)?.try_into().unwrap());
        }

        reader.exact_end()?;

        Ok(AdaptiveMembershipProof {
            leaf_key,
            value,
            chunk_entries,
            secondary_levels,
            top_siblings,
        })
    }

    pub fn membership_proof_size_upper_bound(
        &self,
        leaf_key: [u8; 32],
        value_len: usize,
    ) -> Result<usize, AdaptiveCommitmentError> {
        if leaf_key.iter().all(|byte| *byte == 0) {
            return Err(AdaptiveCommitmentError::ZeroKey);
        }
        let bucket = self
            .buckets
            .get(&bucket_for(leaf_key))
            .ok_or(AdaptiveCommitmentError::InvalidStructure)?;
        let (entries, secondary_levels) = bucket.membership_proof(leaf_key)?;

        if value_len == 0 || value_len > MAX_PROOF_VALUE_BYTES {
            return Err(AdaptiveCommitmentError::InvalidStructure);
        }
        let leaf_bytes = 32usize
            .checked_add(4)
            .and_then(|bytes| bytes.checked_add(value_len))
            .ok_or(AdaptiveCommitmentError::InvalidStructure)?;
        let chunk_bytes = 1usize
            .checked_add(
                entries
                    .len()
                    .checked_mul(64)
                    .ok_or(AdaptiveCommitmentError::InvalidStructure)?,
            )
            .ok_or(AdaptiveCommitmentError::InvalidStructure)?;
        let secondary_path = 1usize
            .checked_add(
                secondary_levels
                    .len()
                    .checked_mul(8 * 32)
                    .ok_or(AdaptiveCommitmentError::InvalidStructure)?,
            )
            .ok_or(AdaptiveCommitmentError::InvalidStructure)?;
        let top_path = 1usize
            .checked_add(
                PRIMARY_BUCKET_BITS
                    .checked_mul(32)
                    .ok_or(AdaptiveCommitmentError::InvalidStructure)?,
            )
            .ok_or(AdaptiveCommitmentError::InvalidStructure)?;

        6usize
            .checked_add(leaf_bytes)
            .and_then(|bytes| bytes.checked_add(chunk_bytes))
            .and_then(|bytes| bytes.checked_add(secondary_path))
            .and_then(|bytes| bytes.checked_add(top_path))
            .ok_or(AdaptiveCommitmentError::InvalidStructure)
    }

    /// Candidate-only raw leaf setter for structural/benchmark experiments.
    /// This is not part of the transaction or consensus wire contract.
    pub fn set_raw_leaf_value(
        &mut self,
        leaf_key: [u8; 32],
        value: Option<&[u8]>,
    ) -> Result<(), AdaptiveCommitmentError> {
        if leaf_key.iter().all(|byte| *byte == 0) {
            return Err(AdaptiveCommitmentError::ZeroKey);
        }
        let value = match value {
            Some(value) => Some(value.to_vec()),
            None => None,
        };
        self.update_leaf(leaf_key, value)
    }

    /// Candidate-only bulk rebuild helper for adversarial benchmarks.
    pub fn rebuild_from_raw_leaves(
        &mut self,
        leaves: &[([u8; 32], Vec<u8>)],
    ) -> Result<(), AdaptiveCommitmentError> {
        let mut grouped: BTreeMap<u16, LeafMap> = BTreeMap::new();

        for (leaf_key, value) in leaves {
            let leaf_hash = hash_leaf(*leaf_key, value)?;
            grouped
                .entry(bucket_for(*leaf_key))
                .or_default()
                .insert(*leaf_key, leaf_hash);
        }

        self.buckets.clear();
        self.top_nodes.clear();

        for (bucket, entries) in grouped {
            self.buckets
                .insert(bucket, AdaptiveBucket::from_entries(entries)?);
        }

        self.rebuild_top_tree();
        Ok(())
    }

    pub fn set_height(&mut self, height: u64) -> Result<(), AdaptiveCommitmentError> {
        self.height = height;
        self.update_leaf(
            height_key(self.network_id),
            Some(height.to_be_bytes().to_vec()),
        )
    }

    pub fn set_balance(
        &mut self,
        asset_id: AssetId,
        account: AccountId,
        amount: u128,
    ) -> Result<(), AdaptiveCommitmentError> {
        let value = if amount == 0 {
            None
        } else {
            Some(amount.to_be_bytes().to_vec())
        };
        self.update_leaf(balance_key(asset_id, account), value)
    }

    pub fn set_registry(
        &mut self,
        asset_id: AssetId,
        definition: &[u8],
        total_supply: u128,
        frozen: bool,
    ) -> Result<(), AdaptiveCommitmentError> {
        let mut value = Vec::with_capacity(2 + definition.len() + 16 + 1);
        value.extend_from_slice(&(definition.len() as u16).to_be_bytes());
        value.extend_from_slice(definition);
        value.extend_from_slice(&total_supply.to_be_bytes());
        value.push(u8::from(frozen));
        self.update_leaf(registry_key(asset_id), Some(value))
    }

    pub fn rebuild_from_state(
        &mut self,
        state: &AssetStateCandidate,
    ) -> Result<(), AdaptiveCommitmentError> {
        if state.network_id() != self.network_id {
            return Err(AdaptiveCommitmentError::InvalidNetworkId);
        }
        self.height = state.height();
        self.buckets.clear();
        self.top_nodes.clear();

        self.insert_height_leaf()?;

        for (asset_id, asset_state) in state.iter_registry() {
            let definition = encode_definition(&asset_state.definition)?;
            let leaf = registry_key(*asset_id);
            let value = registry_value(&definition, asset_state.total_supply, asset_state.frozen);
            self.insert_leaf_without_repath(leaf, value)?;
        }

        for ((asset_id, account), amount) in state.iter_balances() {
            self.insert_leaf_without_repath(
                balance_key(*asset_id, *account),
                amount.to_be_bytes().to_vec(),
            )?;
        }

        self.rebuild_top_tree();
        Ok(())
    }

    pub fn matches_rebuild(
        &self,
        state: &AssetStateCandidate,
    ) -> Result<bool, AdaptiveCommitmentError> {
        let rebuilt = Self::from_state(state)?;
        Ok(self.root() == rebuilt.root())
    }

    fn insert_height_leaf(&mut self) -> Result<(), AdaptiveCommitmentError> {
        self.insert_leaf_without_repath(
            height_key(self.network_id),
            self.height.to_be_bytes().to_vec(),
        )
    }

    fn insert_leaf_without_repath(
        &mut self,
        leaf_key: [u8; 32],
        value: Vec<u8>,
    ) -> Result<(), AdaptiveCommitmentError> {
        let bucket = bucket_for(leaf_key);
        let leaf_hash = hash_leaf(leaf_key, &value)?;
        self.buckets
            .entry(bucket)
            .or_insert_with(AdaptiveBucket::new)
            .set(leaf_key, Some(leaf_hash))
    }

    fn update_leaf(
        &mut self,
        leaf_key: [u8; 32],
        value: Option<Vec<u8>>,
    ) -> Result<(), AdaptiveCommitmentError> {
        let bucket = bucket_for(leaf_key);

        if value.is_none() && !self.buckets.contains_key(&bucket) {
            return Ok(());
        }

        let empty_after = {
            let adaptive_bucket = self
                .buckets
                .entry(bucket)
                .or_insert_with(AdaptiveBucket::new);
            let value_hash = match value {
                Some(value) => Some(hash_leaf(leaf_key, &value)?),
                None => None,
            };
            adaptive_bucket.set(leaf_key, value_hash)?;
            adaptive_bucket.root.count == 0
        };

        if empty_after {
            self.buckets.remove(&bucket);
        }

        let bucket_hash = self
            .buckets
            .get(&bucket)
            .map(AdaptiveBucket::hash)
            .unwrap_or(self.default_hashes[PRIMARY_BUCKET_BITS]);
        self.rehash_top_path(bucket, bucket_hash);
        Ok(())
    }

    fn rebuild_top_tree(&mut self) {
        self.top_nodes.clear();

        // Rebuild only prefixes containing an occupied bucket. The previous full-width
        // sweep visited all 65,535 possible internal prefixes, even when the commitment
        // held only a few active buckets. Missing siblings still resolve via
        // the precomputed default hashes, so the root is byte-for-byte unchanged.
        let bucket_hashes: Vec<(u16, [u8; 32])> = self
            .buckets
            .iter()
            .map(|(&bucket, adaptive_bucket)| (bucket, adaptive_bucket.hash()))
            .collect();
        // The bucket map yields sorted keys. Right-shifting a sorted prefix list
        // preserves order, so Vec::dedup avoids a tree allocation at every depth.
        let mut active_prefixes = Vec::with_capacity(bucket_hashes.len());
        for (bucket, hash) in bucket_hashes {
            active_prefixes.push(bucket);
            self.set_top_node(
                TopNodeKey {
                    depth: PRIMARY_BUCKET_BITS as u8,
                    prefix: bucket,
                },
                hash,
            );
        }

        for depth in (0..PRIMARY_BUCKET_BITS).rev() {
            let mut parent_prefixes: Vec<u16> =
                active_prefixes.iter().map(|prefix| prefix >> 1).collect();
            parent_prefixes.dedup();
            for &prefix in &parent_prefixes {
                let child_prefix = prefix << 1;
                let left = self.top_hash(depth + 1, child_prefix);
                let right = self.top_hash(depth + 1, child_prefix | 1);
                self.set_top_node(
                    TopNodeKey {
                        depth: depth as u8,
                        prefix,
                    },
                    hash_top_node(left, right),
                );
            }
            active_prefixes = parent_prefixes;
        }
    }

    fn rehash_top_path(&mut self, bucket: u16, bucket_hash: [u8; 32]) {
        self.set_top_node(
            TopNodeKey {
                depth: PRIMARY_BUCKET_BITS as u8,
                prefix: bucket,
            },
            bucket_hash,
        );

        for depth in (0..PRIMARY_BUCKET_BITS).rev() {
            let child_prefix = if depth + 1 == PRIMARY_BUCKET_BITS {
                bucket
            } else {
                bucket >> (PRIMARY_BUCKET_BITS - (depth + 1))
            };
            let left_prefix = child_prefix & !1;
            let right_prefix = left_prefix | 1;
            let left = self.top_hash(depth + 1, left_prefix);
            let right = self.top_hash(depth + 1, right_prefix);
            let parent_prefix = if depth == 0 {
                0
            } else {
                bucket >> (PRIMARY_BUCKET_BITS - depth)
            };
            self.set_top_node(
                TopNodeKey {
                    depth: depth as u8,
                    prefix: parent_prefix,
                },
                hash_top_node(left, right),
            );
        }
    }

    fn top_hash(&self, depth: usize, prefix: u16) -> [u8; 32] {
        self.top_nodes
            .get(&TopNodeKey {
                depth: depth as u8,
                prefix,
            })
            .copied()
            .unwrap_or(self.default_hashes[depth])
    }

    fn set_top_node(&mut self, key: TopNodeKey, value: [u8; 32]) {
        if value == self.default_hashes[key.depth as usize] {
            self.top_nodes.remove(&key);
        } else {
            self.top_nodes.insert(key, value);
        }
    }
}

fn bucket_for(leaf_key: [u8; 32]) -> u16 {
    u16::from_be_bytes([leaf_key[0], leaf_key[1]])
}

fn build_default_hashes() -> [[u8; 32]; PRIMARY_BUCKET_BITS + 1] {
    let mut defaults = [[0u8; 32]; PRIMARY_BUCKET_BITS + 1];
    defaults[PRIMARY_BUCKET_BITS] = empty_bucket_hash();
    for depth in (0..PRIMARY_BUCKET_BITS).rev() {
        defaults[depth] = hash_top_node(defaults[depth + 1], defaults[depth + 1]);
    }
    defaults
}

fn registry_key(asset_id: AssetId) -> [u8; 32] {
    let mut payload = Vec::with_capacity(33);
    payload.push(0x01);
    payload.extend_from_slice(&asset_id);
    hash_domain(ADAPTIVE_KEY_DOMAIN, &payload)
}

fn balance_key(asset_id: AssetId, account: AccountId) -> [u8; 32] {
    let mut payload = Vec::with_capacity(65);
    payload.push(0x02);
    payload.extend_from_slice(&asset_id);
    payload.extend_from_slice(&account);
    hash_domain(ADAPTIVE_KEY_DOMAIN, &payload)
}

fn height_key(network_id: NetworkId) -> [u8; 32] {
    let mut payload = Vec::with_capacity(33);
    payload.push(0x03);
    payload.extend_from_slice(&network_id);
    hash_domain(ADAPTIVE_KEY_DOMAIN, &payload)
}

fn registry_value(definition: &[u8], total_supply: u128, frozen: bool) -> Vec<u8> {
    let mut value = Vec::with_capacity(2 + definition.len() + 16 + 1);
    value.extend_from_slice(&(definition.len() as u16).to_be_bytes());
    value.extend_from_slice(definition);
    value.extend_from_slice(&total_supply.to_be_bytes());
    value.push(u8::from(frozen));
    value
}

fn hash_leaf(key: [u8; 32], value: &[u8]) -> Result<[u8; 32], AdaptiveCommitmentError> {
    if key.iter().all(|byte| *byte == 0) {
        return Err(AdaptiveCommitmentError::ZeroKey);
    }
    if value.is_empty() {
        return Err(AdaptiveCommitmentError::EmptyValue);
    }
    let mut payload = Vec::with_capacity(32 + 4 + value.len());
    payload.extend_from_slice(&key);
    payload.extend_from_slice(&(value.len() as u32).to_be_bytes());
    payload.extend_from_slice(value);
    Ok(hash_domain(ADAPTIVE_LEAF_DOMAIN, &payload))
}

fn hash_chunk(prefix: &[u8], entries: &LeafMap) -> [u8; 32] {
    let mut payload = Vec::with_capacity(1 + 1 + prefix.len() + 4 + entries.len() * 64);
    payload.push(0x01);
    payload.push(prefix.len() as u8);
    payload.extend_from_slice(prefix);
    payload.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    for (key, leaf_hash) in entries {
        payload.extend_from_slice(key);
        payload.extend_from_slice(leaf_hash);
    }
    hash_domain(ADAPTIVE_CHUNK_DOMAIN, &payload)
}

fn hash_internal(prefix: &[u8], children: &BTreeMap<u8, Box<TrieNode>>) -> [u8; 32] {
    let sparse_root = hash_sparse_root(children);
    let mut payload = Vec::with_capacity(1 + 1 + prefix.len() + 32);
    payload.push(0x03);
    payload.push(prefix.len() as u8);
    payload.extend_from_slice(prefix);
    payload.extend_from_slice(&sparse_root);
    hash_domain(ADAPTIVE_NODE_DOMAIN, &payload)
}

fn secondary_empty_slot_hash() -> [u8; 32] {
    hash_domain(ADAPTIVE_NODE_DOMAIN, &[0x10])
}

fn secondary_present_slot_hash(child_hash: [u8; 32]) -> [u8; 32] {
    let mut payload = Vec::with_capacity(33);
    payload.push(0x11);
    payload.extend_from_slice(&child_hash);
    hash_domain(ADAPTIVE_NODE_DOMAIN, &payload)
}

fn secondary_pair_hash(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut payload = Vec::with_capacity(65);
    payload.push(0x12);
    payload.extend_from_slice(&left);
    payload.extend_from_slice(&right);
    hash_domain(ADAPTIVE_NODE_DOMAIN, &payload)
}

fn secondary_defaults() -> [[u8; 32]; 9] {
    static DEFAULTS: OnceLock<[[u8; 32]; 9]> = OnceLock::new();
    *DEFAULTS.get_or_init(|| {
        let mut defaults = [[0u8; 32]; 9];
        defaults[0] = secondary_empty_slot_hash();
        for level in 0..8 {
            defaults[level + 1] = secondary_pair_hash(defaults[level], defaults[level]);
        }
        defaults
    })
}

fn sparse_level_map(children: &BTreeMap<u8, Box<TrieNode>>) -> BTreeMap<usize, [u8; 32]> {
    children
        .iter()
        .map(|(&child, node)| (child as usize, secondary_present_slot_hash(node.hash)))
        .collect()
}

fn hash_sparse_root(children: &BTreeMap<u8, Box<TrieNode>>) -> [u8; 32] {
    let defaults = secondary_defaults();
    let mut level = sparse_level_map(children);
    for height in 0..8 {
        if level.is_empty() {
            return defaults[8];
        }
        let mut parents = std::collections::BTreeSet::new();
        for index in level.keys() {
            parents.insert(index / 2);
        }
        let mut next = BTreeMap::new();
        for parent in parents {
            let left = level
                .get(&(parent * 2))
                .copied()
                .unwrap_or(defaults[height]);
            let right = level
                .get(&(parent * 2 + 1))
                .copied()
                .unwrap_or(defaults[height]);
            let hash = secondary_pair_hash(left, right);
            if hash != defaults[height + 1] {
                next.insert(parent, hash);
            }
        }
        level = next;
    }
    level.get(&0).copied().unwrap_or(defaults[8])
}

fn sparse_siblings(children: &BTreeMap<u8, Box<TrieNode>>, target: u8) -> Vec<[u8; 32]> {
    let defaults = secondary_defaults();
    let mut level: Vec<(usize, [u8; 32])> = children
        .iter()
        .map(|(&child, node)| (child as usize, secondary_present_slot_hash(node.hash)))
        .collect();
    let mut index = target as usize;
    let mut siblings = Vec::with_capacity(8);

    for height in 0..8 {
        let sibling_index = index ^ 1;
        let sibling = level
            .binary_search_by_key(&sibling_index, |(child, _)| *child)
            .ok()
            .map(|position| level[position].1)
            .unwrap_or(defaults[height]);
        siblings.push(sibling);

        let mut next = Vec::with_capacity(level.len());
        let mut cursor = 0usize;
        while cursor < level.len() {
            let parent = level[cursor].0 / 2;
            let left_index = parent * 2;
            let right_index = left_index + 1;
            let (left, right, advance) = if level[cursor].0 == right_index {
                (defaults[height], level[cursor].1, 1usize)
            } else if cursor + 1 < level.len() && level[cursor + 1].0 == right_index {
                (level[cursor].1, level[cursor + 1].1, 2usize)
            } else if level[cursor].0 == left_index {
                (level[cursor].1, defaults[height], 1usize)
            } else {
                return Vec::new();
            };
            next.push((parent, secondary_pair_hash(left, right)));
            cursor += advance;
        }

        level = next;
        index /= 2;
    }

    siblings
}

fn hash_secondary_proof_root(
    prefix: &[u8],
    child_hash: [u8; 32],
    child_byte: u8,
    siblings: &[[u8; 32]],
) -> Result<[u8; 32], AdaptiveCommitmentError> {
    if siblings.len() != 8 {
        return Err(AdaptiveCommitmentError::InvalidStructure);
    }
    let mut current = secondary_present_slot_hash(child_hash);
    let mut index = child_byte as usize;
    for sibling in siblings {
        current = if index & 1 == 0 {
            secondary_pair_hash(current, *sibling)
        } else {
            secondary_pair_hash(*sibling, current)
        };
        index /= 2;
    }
    let mut payload = Vec::with_capacity(1 + 1 + prefix.len() + 32);
    payload.push(0x03);
    payload.push(prefix.len() as u8);
    payload.extend_from_slice(prefix);
    payload.extend_from_slice(&current);
    Ok(hash_domain(ADAPTIVE_NODE_DOMAIN, &payload))
}

fn hash_top_node(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut payload = Vec::with_capacity(64);
    payload.extend_from_slice(&left);
    payload.extend_from_slice(&right);
    hash_domain(ADAPTIVE_COMMITMENT_DOMAIN, &payload)
}

fn empty_bucket_hash() -> [u8; 32] {
    hash_domain(ADAPTIVE_CHUNK_DOMAIN, &[0u8; 4])
}

fn build_trie_node(prefix: Vec<u8>, entries: LeafMap) -> Result<TrieNode, AdaptiveCommitmentError> {
    if entries.len() <= CHUNK_CAP {
        return Ok(TrieNode::new_leaf(prefix, entries));
    }

    let depth = prefix.len();
    if depth >= MAX_SUFFIX_DEPTH {
        return Err(AdaptiveCommitmentError::InvalidStructure);
    }

    let next_index = 2 + depth;
    let mut grouped: BTreeMap<u8, LeafMap> = BTreeMap::new();
    for (key, value_hash) in entries {
        let child_byte = key
            .get(next_index)
            .copied()
            .ok_or(AdaptiveCommitmentError::InvalidStructure)?;
        grouped
            .entry(child_byte)
            .or_default()
            .insert(key, value_hash);
    }

    let mut children = BTreeMap::new();
    let mut count = 0usize;
    for (child_byte, child_entries) in grouped {
        let mut child_prefix = prefix.clone();
        child_prefix.push(child_byte);
        let child = build_trie_node(child_prefix, child_entries)?;
        count = count.saturating_add(child.count);
        children.insert(child_byte, Box::new(child));
    }

    let hash = hash_internal(&prefix, &children);
    Ok(TrieNode {
        prefix,
        entries: BTreeMap::new(),
        children,
        count,
        hash,
    })
}

fn collect_entries(
    children: &BTreeMap<u8, Box<TrieNode>>,
) -> Result<LeafMap, AdaptiveCommitmentError> {
    let mut entries = BTreeMap::new();
    for child in children.values() {
        collect_leaf_entries(child, &mut entries)?;
        if entries.len() > CHUNK_CAP {
            return Err(AdaptiveCommitmentError::InvalidStructure);
        }
    }
    Ok(entries)
}

fn collect_leaf_entries(
    node: &TrieNode,
    entries: &mut LeafMap,
) -> Result<(), AdaptiveCommitmentError> {
    if node.children.is_empty() {
        entries.extend(node.entries.iter().map(|(&key, &value)| (key, value)));
        if entries.len() > CHUNK_CAP {
            return Err(AdaptiveCommitmentError::InvalidStructure);
        }
        return Ok(());
    }
    for child in node.children.values() {
        collect_leaf_entries(child, entries)?;
        if entries.len() > CHUNK_CAP {
            return Err(AdaptiveCommitmentError::InvalidStructure);
        }
    }
    Ok(())
}

fn hash_domain(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    hash.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        asset_state_candidate::CandidateResourceLimits,
        asset_transactions::AssetOperation,
        token_forge::{
            AccountId, AssetDefinition, BurnAuthority, FreezePolicy, MintAuthority, SupplyPolicy,
        },
    };

    const NETWORK: NetworkId = [0xC7; 32];
    const ALICE: AccountId = [0x11; 32];
    const BOB: AccountId = [0x22; 32];

    fn limits(max_assets: usize) -> CandidateResourceLimits {
        CandidateResourceLimits {
            max_operations: max_assets.max(1),
            max_operation_bytes: max_assets.saturating_mul(512).max(512),
            max_assets: max_assets.max(1),
            max_holdings: max_assets.saturating_mul(2).max(2),
        }
    }

    fn definition(nonce: u64) -> AssetDefinition {
        AssetDefinition {
            network_id: NETWORK,
            creator: ALICE,
            creation_nonce: nonce,
            name: format!("Adaptive {nonce}"),
            symbol: format!("A{nonce}"),
            decimals: 8,
            metadata_hash: [0x77; 32],
            supply_policy: SupplyPolicy::Capped {
                initial_supply: 1_000,
                max_supply: 5_000,
            },
            mint_authority: MintAuthority::Creator,
            burn_authority: BurnAuthority::Holder,
            freeze_policy: FreezePolicy::Creator,
        }
    }

    fn state() -> AssetStateCandidate {
        let mut state = AssetStateCandidate::genesis(NETWORK).unwrap();
        state.advance_height(100).unwrap();
        state
            .apply_operation(
                &ALICE,
                &AssetOperation::Create {
                    definition: definition(1),
                },
                limits(4),
            )
            .unwrap();
        state
    }

    fn synthetic_key(bucket: [u8; 2], suffix: u64) -> [u8; 32] {
        let mut key = [0u8; 32];
        key[..2].copy_from_slice(&bucket);
        key[24..].copy_from_slice(&suffix.to_be_bytes());
        key
    }

    fn shaped_key(bucket: [u8; 2], split_bytes: &[u8], suffix: u64) -> [u8; 32] {
        assert!(split_bytes.len() <= MAX_SUFFIX_DEPTH);
        let mut key = synthetic_key(bucket, suffix);
        key[2..2 + split_bytes.len()].copy_from_slice(split_bytes);
        key
    }

    #[test]
    fn fresh_generic_tree_root_does_not_bind_network_or_height_until_height_leaf_is_inserted() {
        const OTHER_NETWORK: NetworkId = [0xC8; 32];
        const HEIGHT: u64 = 100;

        let same_network_other_height =
            AdaptiveAssetStateCommitment::new(NETWORK, HEIGHT + 1).unwrap();
        let other_network_same_height =
            AdaptiveAssetStateCommitment::new(OTHER_NETWORK, HEIGHT).unwrap();
        let mut first = AdaptiveAssetStateCommitment::new(NETWORK, HEIGHT).unwrap();
        let empty_root = first.root();

        // Before any leaves are added, the root is only the generic empty-tree constant.
        assert_eq!(empty_root, same_network_other_height.root());
        assert_eq!(empty_root, other_network_same_height.root());

        // Inserting the network-keyed height leaf makes both context fields affect the root.
        first.set_height(HEIGHT).unwrap();
        let mut other_height = same_network_other_height;
        other_height.set_height(HEIGHT + 1).unwrap();
        let mut other_network = other_network_same_height;
        other_network.set_height(HEIGHT).unwrap();

        assert_ne!(empty_root, first.root());
        assert_ne!(first.root(), other_height.root());
        assert_ne!(first.root(), other_network.root());
    }

    #[test]
    fn rebuild_is_deterministic_and_bound() {
        let state = state();
        let commitment = AdaptiveAssetStateCommitment::from_state(&state).unwrap();
        assert_ne!(commitment.root(), [0u8; 32]);
        assert!(commitment.bucket_count() >= 2);
        assert!(commitment.largest_terminal_chunk_len() <= CHUNK_CAP);
        assert!(commitment.deepest_bucket_path() <= MAX_SUFFIX_DEPTH);
        assert!(commitment.matches_rebuild(&state).unwrap());
    }

    #[test]
    fn incremental_updates_match_rebuild() {
        let mut state = state();
        let asset_id = state.iter_registry().next().map(|(id, _)| *id).unwrap();
        let mut commitment = AdaptiveAssetStateCommitment::from_state(&state).unwrap();

        for (index, recipient) in [BOB, [0x33; 32], [0x44; 32], [0x55; 32]]
            .into_iter()
            .enumerate()
        {
            state.advance_height(101 + index as u64).unwrap();
            state
                .apply_operation(
                    &ALICE,
                    &AssetOperation::Transfer {
                        asset_id,
                        recipient,
                        amount: 1,
                    },
                    limits(4),
                )
                .unwrap();
            commitment.set_height(state.height()).unwrap();
            commitment
                .set_balance(asset_id, ALICE, state.balance(&asset_id, &ALICE))
                .unwrap();
            commitment
                .set_balance(asset_id, recipient, state.balance(&asset_id, &recipient))
                .unwrap();
            assert!(commitment.matches_rebuild(&state).unwrap());
        }
    }

    #[test]
    fn membership_proof_shape_matrix_covers_shallow_medium_and_deep_paths() {
        let cases = [
            ("SHALLOW", 0usize, 16usize, 32usize),
            ("FULL_CHUNK", 0usize, 32usize, 8usize),
            ("SPLIT_DEPTH_1", 1usize, 33usize, 16usize),
            ("SPLIT_DEPTH_2", 2usize, 128usize, 32usize),
            ("SPLIT_DEPTH_3", 3usize, 256usize, 1usize),
        ];

        for (label, shape_depth, count, value_len) in cases {
            let bucket = match label {
                "SHALLOW" => [0x10, 0x01],
                "FULL_CHUNK" => [0x10, 0x02],
                "SPLIT_DEPTH_1" => [0x10, 0x03],
                "SPLIT_DEPTH_2" => [0x10, 0x04],
                "SPLIT_DEPTH_3" => [0x10, 0x05],
                _ => unreachable!(),
            };

            let mut leaves = Vec::with_capacity(count);
            for index in 0..count {
                let key = if shape_depth == 0 {
                    synthetic_key(bucket, index as u64)
                } else if shape_depth == 1 {
                    shaped_key(bucket, &[(index / 17) as u8], index as u64)
                } else if shape_depth == 2 {
                    shaped_key(
                        bucket,
                        &[(index / 64) as u8, ((index / 32) % 2) as u8],
                        index as u64,
                    )
                } else if shape_depth == 3 {
                    shaped_key(
                        bucket,
                        &[
                            (index / 64) as u8,
                            ((index / 32) % 2) as u8,
                            (index % 2) as u8,
                        ],
                        index as u64,
                    )
                } else {
                    shaped_key(bucket, &vec![0u8; shape_depth], index as u64)
                };
                leaves.push((key, vec![0x30 + (index % 16) as u8; value_len]));
            }

            let mut commitment = AdaptiveAssetStateCommitment::new(NETWORK, 100).unwrap();
            commitment.rebuild_from_raw_leaves(&leaves).unwrap();

            let (target, target_value) = leaves[count / 2].clone();
            let proof = commitment
                .membership_proof_with_value(target, &target_value)
                .unwrap();
            let encoded = AdaptiveAssetStateCommitment::encode_membership_proof(&proof).unwrap();
            let decoded = AdaptiveAssetStateCommitment::decode_membership_proof(&encoded).unwrap();

            assert_eq!(decoded, proof, "{label}: APF1 round-trip changed proof");
            assert!(
                AdaptiveAssetStateCommitment::verify_membership_proof(
                    NETWORK,
                    commitment.root(),
                    &decoded,
                )
                .unwrap(),
                "{label}: valid proof did not verify"
            );
            assert_eq!(
                AdaptiveAssetStateCommitment::membership_proof_size(&proof).unwrap(),
                encoded.len(),
                "{label}: size accounting mismatch"
            );
            assert!(
                encoded.len()
                    <= AdaptiveAssetStateCommitment::worst_case_membership_proof_size_upper_bound(
                        value_len,
                    )
                    .unwrap(),
                "{label}: proof exceeded candidate worst-case bound"
            );

            if shape_depth == 0 {
                assert_eq!(
                    proof.secondary_levels.len(),
                    0,
                    "{label}: unexpected secondary path"
                );
            } else {
                assert!(
                    proof.secondary_levels.len() > 0,
                    "{label}: expected a secondary path"
                );
            }
        }

        let mut deep = AdaptiveAssetStateCommitment::new(NETWORK, 100).unwrap();
        let mut deep_leaves = Vec::with_capacity(64);
        for index in 0u64..64 {
            deep_leaves.push((
                shaped_key([0x10, 0x07], &vec![0u8; MAX_SUFFIX_DEPTH - 1], index),
                vec![0x07; 32],
            ));
        }
        deep.rebuild_from_raw_leaves(&deep_leaves).unwrap();
        let target = deep_leaves[17].0;
        let proof = deep
            .membership_proof_with_value(target, &[0x07; 32])
            .unwrap();
        assert_eq!(proof.secondary_levels.len(), MAX_SUFFIX_DEPTH);
        assert!(AdaptiveAssetStateCommitment::verify_membership_proof(
            NETWORK,
            deep.root(),
            &proof,
        )
        .unwrap());
    }

    #[test]
    fn concentrated_bucket_splits_into_bounded_chunks() {
        let mut commitment = AdaptiveAssetStateCommitment::new(NETWORK, 100).unwrap();
        let bucket = [0x5A, 0xA5];

        for suffix in 0u64..128 {
            let key = synthetic_key(bucket, suffix);
            commitment
                .insert_leaf_without_repath(key, vec![0x01; 32])
                .unwrap();
        }
        commitment.rebuild_top_tree();

        assert_eq!(commitment.largest_bucket_len(), 128);
        assert!(commitment.largest_terminal_chunk_len() <= CHUNK_CAP);
        assert!(commitment.deepest_bucket_path() <= MAX_SUFFIX_DEPTH);
        let key = synthetic_key(bucket, 99);
        let proof = commitment
            .membership_proof_size_upper_bound(key, 32)
            .unwrap();
        let worst =
            AdaptiveAssetStateCommitment::worst_case_membership_proof_size_upper_bound(32).unwrap();
        assert!(proof <= worst);
        assert_eq!(worst, 10_317);
    }

    #[test]
    fn deleting_last_leaf_returns_to_empty_commitment() {
        let mut commitment = AdaptiveAssetStateCommitment::new(NETWORK, 100).unwrap();
        let key = synthetic_key([0x12, 0x34], 1);
        let empty_root = commitment.root();
        commitment.update_leaf(key, Some(vec![0x01])).unwrap();
        assert_ne!(commitment.root(), empty_root);
        commitment.update_leaf(key, None).unwrap();
        assert_eq!(commitment.root(), empty_root);
        assert_eq!(commitment.bucket_count(), 0);
    }

    #[test]
    fn deleting_from_split_bucket_collapses_back_to_single_chunk() {
        let mut commitment = AdaptiveAssetStateCommitment::new(NETWORK, 100).unwrap();
        let bucket = [0x31, 0x41];
        for suffix in 0u64..(CHUNK_CAP as u64 + 1) {
            commitment
                .set_raw_leaf_value(synthetic_key(bucket, suffix), Some(&[0x09; 8]))
                .unwrap();
        }
        assert!(commitment.deepest_bucket_path() > 0);
        commitment
            .set_raw_leaf_value(synthetic_key(bucket, CHUNK_CAP as u64), None)
            .unwrap();
        assert_eq!(commitment.largest_bucket_len(), CHUNK_CAP);
        assert_eq!(commitment.largest_terminal_chunk_len(), CHUNK_CAP);
        assert_eq!(commitment.deepest_bucket_path(), 0);
    }

    #[test]
    fn proof_size_overflow_and_missing_key_fail_closed() {
        let commitment = AdaptiveAssetStateCommitment::new(NETWORK, 100).unwrap();
        let missing = synthetic_key([0x43, 0x21], 1);
        assert!(matches!(
            commitment.membership_proof_size_upper_bound(missing, 32),
            Err(AdaptiveCommitmentError::InvalidStructure)
        ));
        assert!(matches!(
            AdaptiveAssetStateCommitment::worst_case_membership_proof_size_upper_bound(usize::MAX),
            Err(AdaptiveCommitmentError::InvalidStructure)
        ));
    }

    #[test]
    fn distinct_concentrated_inputs_are_deterministic() {
        let mut left = AdaptiveAssetStateCommitment::new(NETWORK, 100).unwrap();
        let mut right = AdaptiveAssetStateCommitment::new(NETWORK, 100).unwrap();
        for suffix in 0u64..64 {
            let key = synthetic_key([0x66, 0x55], suffix);
            left.update_leaf(key, Some(vec![0x02; 16])).unwrap();
            right.update_leaf(key, Some(vec![0x02; 16])).unwrap();
        }
        assert_eq!(left.root(), right.root());
        assert_eq!(
            left.largest_terminal_chunk_len(),
            right.largest_terminal_chunk_len()
        );
    }

    #[test]
    fn membership_proof_builds_and_verifies_against_root() {
        let mut commitment = AdaptiveAssetStateCommitment::new(NETWORK, 100).unwrap();
        let bucket = [0x5A, 0xA5];
        let target = synthetic_key(bucket, 17);
        for suffix in 0u64..64 {
            commitment
                .set_raw_leaf_value(synthetic_key(bucket, suffix), Some(&[0x07; 32]))
                .unwrap();
        }
        let proof = commitment
            .membership_proof_with_value(target, &[0x07; 32])
            .unwrap();
        let size = AdaptiveAssetStateCommitment::membership_proof_size(&proof).unwrap();
        let upper = commitment
            .membership_proof_size_upper_bound(target, 32)
            .unwrap();
        let encoded = AdaptiveAssetStateCommitment::encode_membership_proof(&proof).unwrap();
        assert_eq!(encoded.len(), size);
        let decoded = AdaptiveAssetStateCommitment::decode_membership_proof(&encoded).unwrap();
        assert_eq!(decoded, proof);
        assert!(size <= upper);
        assert!(AdaptiveAssetStateCommitment::verify_membership_proof(
            NETWORK,
            commitment.root(),
            &proof,
        )
        .unwrap());
    }

    #[test]
    fn network_bound_root_separates_networks_without_changing_inner_root() {
        const OTHER_NETWORK: NetworkId = [0xD8; 32];
        let bucket = [0x5A, 0xA5];
        let target = synthetic_key(bucket, 17);
        let mut first = AdaptiveAssetStateCommitment::new(NETWORK, 100).unwrap();
        let mut second = AdaptiveAssetStateCommitment::new(OTHER_NETWORK, 100).unwrap();

        for suffix in 0u64..64 {
            let key = synthetic_key(bucket, suffix);
            first.set_raw_leaf_value(key, Some(&[0x07; 32])).unwrap();
            second.set_raw_leaf_value(key, Some(&[0x07; 32])).unwrap();
        }

        let proof = first
            .membership_proof_with_value(target, &[0x07; 32])
            .unwrap();
        let inner_root = first.root();
        assert_eq!(inner_root, second.root());
        assert_ne!(first.network_bound_root(), second.network_bound_root());

        // The legacy API remains an inner-root API for compatibility.
        assert!(AdaptiveAssetStateCommitment::verify_membership_proof(
            OTHER_NETWORK,
            inner_root,
            &proof,
        )
        .unwrap());

        let expected_outer_root = first.network_bound_root();
        assert!(
            AdaptiveAssetStateCommitment::verify_membership_proof_network_bound(
                NETWORK,
                expected_outer_root,
                &proof,
            )
            .unwrap()
        );
        assert!(
            !AdaptiveAssetStateCommitment::verify_membership_proof_network_bound(
                OTHER_NETWORK,
                expected_outer_root,
                &proof,
            )
            .unwrap()
        );

        let typed_inner = first.inner_root_typed();
        assert_eq!(typed_inner.into_bytes(), inner_root);
        assert!(AdaptiveAssetStateCommitment::verify_membership_proof_typed(
            NETWORK,
            typed_inner,
            &proof,
        )
        .unwrap());

        let typed_outer = first.network_bound_root_typed();
        assert_eq!(typed_outer.network_id(), NETWORK);
        assert_eq!(*typed_outer.as_bytes(), expected_outer_root);
        assert!(
            AdaptiveAssetStateCommitment::verify_membership_proof_network_bound_typed(
                typed_outer,
                &proof,
            )
            .unwrap()
        );

        let wrong_network_root =
            AdaptiveNetworkBoundRoot::from_untrusted_parts(OTHER_NETWORK, expected_outer_root)
                .unwrap();
        assert!(
            !AdaptiveAssetStateCommitment::verify_membership_proof_network_bound_typed(
                wrong_network_root,
                &proof,
            )
            .unwrap()
        );
        assert!(
            AdaptiveNetworkBoundRoot::from_untrusted_parts([0; 32], expected_outer_root).is_err()
        );
        assert_eq!(first.root(), inner_root);
    }

    #[test]
    fn membership_proof_rejects_tampered_value_and_sibling() {
        let mut commitment = AdaptiveAssetStateCommitment::new(NETWORK, 100).unwrap();
        let bucket = [0x12, 0x34];
        let target = synthetic_key(bucket, 8);
        for suffix in 0u64..64 {
            commitment
                .set_raw_leaf_value(synthetic_key(bucket, suffix), Some(&[0x0B; 16]))
                .unwrap();
        }
        let mut proof = commitment
            .membership_proof_with_value(target, &[0x0B; 16])
            .unwrap();
        proof.value[0] ^= 0x01;
        assert!(!AdaptiveAssetStateCommitment::verify_membership_proof(
            NETWORK,
            commitment.root(),
            &proof,
        )
        .unwrap());

        let mut proof = commitment
            .membership_proof_with_value(target, &[0x0B; 16])
            .unwrap();
        proof.top_siblings[0][0] ^= 0x01;
        assert!(!AdaptiveAssetStateCommitment::verify_membership_proof(
            NETWORK,
            commitment.root(),
            &proof,
        )
        .unwrap());
    }

    #[test]
    fn serialized_membership_proof_rejects_malformed_and_bit_flipped_inputs() {
        let mut commitment = AdaptiveAssetStateCommitment::new(NETWORK, 100).unwrap();
        let bucket = [0x45, 0x67];
        let target = synthetic_key(bucket, 19);
        for suffix in 0u64..64 {
            commitment
                .set_raw_leaf_value(synthetic_key(bucket, suffix), Some(&[0x0D; 32]))
                .unwrap();
        }

        let proof = commitment
            .membership_proof_with_value(target, &[0x0D; 32])
            .unwrap();
        let encoded = AdaptiveAssetStateCommitment::encode_membership_proof(&proof).unwrap();
        assert_eq!(
            encoded.len(),
            AdaptiveAssetStateCommitment::membership_proof_size(&proof).unwrap()
        );

        let mut truncated = encoded.clone();
        truncated.pop();
        assert!(AdaptiveAssetStateCommitment::decode_membership_proof(&truncated).is_err());

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(AdaptiveAssetStateCommitment::decode_membership_proof(&trailing).is_err());

        let mut bad_version = encoded.clone();
        bad_version[5] = 2;
        assert!(AdaptiveAssetStateCommitment::decode_membership_proof(&bad_version).is_err());

        let chunk_count_offset = 6 + 32 + 4 + proof.value.len();
        let mut bad_chunk_count = encoded.clone();
        bad_chunk_count[chunk_count_offset] = 0;
        assert!(AdaptiveAssetStateCommitment::decode_membership_proof(&bad_chunk_count).is_err());

        let top_count_offset = encoded.len() - PRIMARY_BUCKET_BITS * 32 - 1;
        let mut bad_top_count = encoded.clone();
        bad_top_count[top_count_offset] = 15;
        assert!(AdaptiveAssetStateCommitment::decode_membership_proof(&bad_top_count).is_err());

        let mut flip_positions = vec![
            0usize,
            5usize,
            chunk_count_offset + 1 + 32,
            chunk_count_offset + 1 + 64 + 4,
            encoded.len() - 1,
        ];
        let mut cursor = 0x9E37_79B9u32;
        for _ in 0..128 {
            cursor ^= cursor << 13;
            cursor ^= cursor >> 17;
            cursor ^= cursor << 5;
            flip_positions.push((cursor as usize) % encoded.len());
        }
        for position in flip_positions {
            let mut mutated = encoded.clone();
            mutated[position] ^= 0x01;
            match AdaptiveAssetStateCommitment::decode_membership_proof(&mutated) {
                Ok(decoded) => {
                    assert!(
                        !AdaptiveAssetStateCommitment::verify_membership_proof(
                            NETWORK,
                            commitment.root(),
                            &decoded,
                        )
                        .unwrap(),
                        "bit flip at byte {position} must not verify"
                    );
                }
                Err(_) => {}
            }
        }
    }

    #[test]
    fn proof_upper_bound_accounts_for_full_sparse_sibling_sets() {
        let bound =
            AdaptiveAssetStateCommitment::worst_case_membership_proof_size_upper_bound(32).unwrap();
        assert_eq!(bound, 10_317);
    }
}
