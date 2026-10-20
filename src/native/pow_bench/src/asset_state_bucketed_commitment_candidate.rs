//! Candidate bucketed authenticated asset-state commitment.
//!
//! This is a pre-activation architecture experiment. It keeps a canonical
//! bucket map at a 16-bit prefix and authenticates the bucket roots with a
//! sparse 16-level Merkle tree. Updating one state leaf therefore touches
//! one bucket plus a short top-level path instead of a 256-level path.
//!
//! The bucket contents are hashed canonically. A proof for one entry would
//! need the bucket membership data plus the top-level sibling path; proof-size
//! and adversarial bucket-concentration limits remain open decisions.

use crate::asset_state_candidate::{AccountId, AssetStateCandidate};
use crate::token_forge::{encode_definition, AssetId, NetworkId};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const BUCKETED_COMMITMENT_DOMAIN: &[u8] = b"AIN1-ASSET-COMMIT-BKT-CAND-V1\0";
pub const BUCKETED_KEY_DOMAIN: &[u8] = b"AIN1-ASSET-COMMIT-BKT-KEY-CAND-V1\0";
pub const BUCKETED_LEAF_DOMAIN: &[u8] = b"AIN1-ASSET-COMMIT-BKT-LEAF-CAND-V1\0";
pub const BUCKETED_BUCKET_DOMAIN: &[u8] = b"AIN1-ASSET-COMMIT-BKT-BUCKET-CAND-V1\0";
pub const BUCKETED_NODE_DOMAIN: &[u8] = b"AIN1-ASSET-COMMIT-BKT-NODE-CAND-V1\0";

const BUCKET_BITS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct TopNodeKey {
    depth: u8,
    prefix: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BucketedCommitmentError {
    InvalidNetworkId,
    ZeroKey,
    EmptyValue,
    InvalidBucket,
    AssetState(crate::asset_state_candidate::AssetStateCandidateError),
    TokenForge(crate::token_forge::TokenForgeError),
}

impl From<crate::asset_state_candidate::AssetStateCandidateError> for BucketedCommitmentError {
    fn from(value: crate::asset_state_candidate::AssetStateCandidateError) -> Self {
        Self::AssetState(value)
    }
}

impl From<crate::token_forge::TokenForgeError> for BucketedCommitmentError {
    fn from(value: crate::token_forge::TokenForgeError) -> Self {
        Self::TokenForge(value)
    }
}

impl std::fmt::Display for BucketedCommitmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidNetworkId => write!(f, "bucketed commitment network ID is zero"),
            Self::ZeroKey => write!(f, "bucketed commitment key is zero"),
            Self::EmptyValue => write!(f, "bucketed commitment value is empty"),
            Self::InvalidBucket => write!(f, "bucketed commitment bucket is invalid"),
            Self::AssetState(error) => write!(f, "asset-state error: {error}"),
            Self::TokenForge(error) => write!(f, "token-forge error: {error}"),
        }
    }
}

impl std::error::Error for BucketedCommitmentError {}

type LeafMap = BTreeMap<[u8; 32], [u8; 32]>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketedAssetStateCommitment {
    network_id: NetworkId,
    height: u64,
    buckets: BTreeMap<u16, LeafMap>,
    top_nodes: BTreeMap<TopNodeKey, [u8; 32]>,
    default_hashes: [[u8; 32]; BUCKET_BITS + 1],
}

impl BucketedAssetStateCommitment {
    pub fn new(network_id: NetworkId, height: u64) -> Result<Self, BucketedCommitmentError> {
        if network_id.iter().all(|byte| *byte == 0) {
            return Err(BucketedCommitmentError::InvalidNetworkId);
        }
        Ok(Self {
            network_id,
            height,
            buckets: BTreeMap::new(),
            top_nodes: BTreeMap::new(),
            default_hashes: build_default_hashes(),
        })
    }

    pub fn from_state(state: &AssetStateCandidate) -> Result<Self, BucketedCommitmentError> {
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

    pub fn stored_top_node_count(&self) -> usize {
        self.top_nodes.len()
    }

    pub fn largest_bucket_len(&self) -> usize {
        self.buckets.values().map(LeafMap::len).max().unwrap_or(0)
    }

    pub fn bucket_len_for_key(&self, leaf_key: [u8; 32]) -> usize {
        self.buckets
            .get(&bucket_for(leaf_key))
            .map(LeafMap::len)
            .unwrap_or(0)
    }

    pub fn max_membership_proof_size_upper_bound(
        &self,
        value_len: usize,
    ) -> Result<usize, BucketedCommitmentError> {
        let entries = self.largest_bucket_len();
        if entries == 0 {
            return Err(BucketedCommitmentError::InvalidBucket);
        }
        let bucket_bytes = entries
            .checked_mul(32 + 32)
            .and_then(|bytes| bytes.checked_add(2 + 4))
            .ok_or(BucketedCommitmentError::InvalidBucket)?;
        let leaf_bytes = 32usize
            .checked_add(4)
            .and_then(|bytes| bytes.checked_add(value_len))
            .ok_or(BucketedCommitmentError::InvalidBucket)?;
        let top_path_bytes = BUCKET_BITS
            .checked_mul(32)
            .ok_or(BucketedCommitmentError::InvalidBucket)?;
        leaf_bytes
            .checked_add(bucket_bytes)
            .and_then(|bytes| bytes.checked_add(top_path_bytes))
            .ok_or(BucketedCommitmentError::InvalidBucket)
    }

    pub fn membership_proof_size_upper_bound(
        &self,
        leaf_key: [u8; 32],
        value_len: usize,
    ) -> Result<usize, BucketedCommitmentError> {
        if leaf_key.iter().all(|byte| *byte == 0) {
            return Err(BucketedCommitmentError::ZeroKey);
        }
        let entries = self.bucket_len_for_key(leaf_key);
        if entries == 0 {
            return Err(BucketedCommitmentError::InvalidBucket);
        }
        let bucket_bytes = entries
            .checked_mul(32 + 32)
            .and_then(|bytes| bytes.checked_add(2 + 4))
            .ok_or(BucketedCommitmentError::InvalidBucket)?;
        let leaf_bytes = 32usize
            .checked_add(4)
            .and_then(|bytes| bytes.checked_add(value_len))
            .ok_or(BucketedCommitmentError::InvalidBucket)?;
        let top_path_bytes = BUCKET_BITS
            .checked_mul(32)
            .ok_or(BucketedCommitmentError::InvalidBucket)?;
        leaf_bytes
            .checked_add(bucket_bytes)
            .and_then(|bytes| bytes.checked_add(top_path_bytes))
            .ok_or(BucketedCommitmentError::InvalidBucket)
    }

    /// Candidate-only raw leaf setter for structural/benchmark experiments.
    /// This is not part of the transaction or consensus wire contract.
    pub fn set_raw_leaf_value(
        &mut self,
        leaf_key: [u8; 32],
        value: Option<&[u8]>,
    ) -> Result<(), BucketedCommitmentError> {
        if leaf_key.iter().all(|byte| *byte == 0) {
            return Err(BucketedCommitmentError::ZeroKey);
        }
        let value = value.map(|bytes| bytes.to_vec());
        self.update_leaf(leaf_key, value)
    }

    /// Candidate-only bulk rebuild helper for adversarial benchmarks.
    pub fn rebuild_from_raw_leaves(
        &mut self,
        leaves: &[([u8; 32], Vec<u8>)],
    ) -> Result<(), BucketedCommitmentError> {
        self.buckets.clear();
        self.top_nodes.clear();
        for (leaf_key, value) in leaves {
            self.insert_leaf_without_repath(*leaf_key, value.clone())?;
        }
        self.rebuild_top_tree();
        Ok(())
    }

    pub fn set_height(&mut self, height: u64) -> Result<(), BucketedCommitmentError> {
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
    ) -> Result<(), BucketedCommitmentError> {
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
    ) -> Result<(), BucketedCommitmentError> {
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
    ) -> Result<(), BucketedCommitmentError> {
        if state.network_id() != self.network_id {
            return Err(BucketedCommitmentError::InvalidNetworkId);
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
    ) -> Result<bool, BucketedCommitmentError> {
        let rebuilt = Self::from_state(state)?;
        Ok(self.root() == rebuilt.root())
    }

    fn insert_height_leaf(&mut self) -> Result<(), BucketedCommitmentError> {
        self.insert_leaf_without_repath(
            height_key(self.network_id),
            self.height.to_be_bytes().to_vec(),
        )
    }

    fn insert_leaf_without_repath(
        &mut self,
        leaf_key: [u8; 32],
        value: Vec<u8>,
    ) -> Result<(), BucketedCommitmentError> {
        let bucket = bucket_for(leaf_key);
        let leaf_hash = hash_leaf(leaf_key, &value)?;
        self.buckets
            .entry(bucket)
            .or_default()
            .insert(leaf_key, leaf_hash);
        Ok(())
    }

    fn update_leaf(
        &mut self,
        leaf_key: [u8; 32],
        value: Option<Vec<u8>>,
    ) -> Result<(), BucketedCommitmentError> {
        let bucket = bucket_for(leaf_key);
        let bucket_map = self.buckets.entry(bucket).or_default();
        match value {
            Some(value) => {
                bucket_map.insert(leaf_key, hash_leaf(leaf_key, &value)?);
            }
            None => {
                bucket_map.remove(&leaf_key);
                if bucket_map.is_empty() {
                    self.buckets.remove(&bucket);
                }
            }
        }

        self.rehash_bucket_and_path(bucket);
        Ok(())
    }

    fn rebuild_top_tree(&mut self) {
        self.top_nodes.clear();
        let bucket_hashes: Vec<(u16, [u8; 32])> = self
            .buckets
            .iter()
            .map(|(&bucket, entries)| (bucket, hash_bucket(bucket, entries)))
            .collect();
        for (bucket, hash) in bucket_hashes {
            self.set_top_node(
                TopNodeKey {
                    depth: BUCKET_BITS as u8,
                    prefix: bucket,
                },
                hash,
            );
        }

        for depth in (0..BUCKET_BITS).rev() {
            let prefix_count = 1usize << depth;
            for raw_prefix in 0..prefix_count {
                let prefix = raw_prefix as u16;
                let child_prefix = prefix << 1;
                let left = self.top_hash(depth + 1, child_prefix);
                let right = self.top_hash(depth + 1, child_prefix | 1);
                let parent = hash_node(left, right);
                self.set_top_node(
                    TopNodeKey {
                        depth: depth as u8,
                        prefix,
                    },
                    parent,
                );
            }
        }
    }

    fn rehash_bucket_and_path(&mut self, bucket: u16) {
        let bucket_hash = self
            .buckets
            .get(&bucket)
            .map(|entries| hash_bucket(bucket, entries))
            .unwrap_or(self.default_hashes[BUCKET_BITS]);
        self.set_top_node(
            TopNodeKey {
                depth: BUCKET_BITS as u8,
                prefix: bucket,
            },
            bucket_hash,
        );

        for depth in (0..BUCKET_BITS).rev() {
            let child_prefix = bucket >> (BUCKET_BITS - (depth + 1));
            let left_prefix = child_prefix & !1;
            let right_prefix = left_prefix | 1;
            let left = self.top_hash(depth + 1, left_prefix);
            let right = self.top_hash(depth + 1, right_prefix);
            let parent_prefix = if depth == 0 {
                0
            } else {
                bucket >> (BUCKET_BITS - depth)
            };
            self.set_top_node(
                TopNodeKey {
                    depth: depth as u8,
                    prefix: parent_prefix,
                },
                hash_node(left, right),
            );
        }
    }

    fn top_hash(&self, depth: usize, prefix: u16) -> [u8; 32] {
        self.top_nodes
            .get(&TopNodeKey {
                depth: depth as u8,
                prefix: prefix as u16,
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

fn build_default_hashes() -> [[u8; 32]; BUCKET_BITS + 1] {
    let mut defaults = [[0u8; 32]; BUCKET_BITS + 1];
    defaults[BUCKET_BITS] = empty_bucket_hash();
    for depth in (0..BUCKET_BITS).rev() {
        defaults[depth] = hash_node(defaults[depth + 1], defaults[depth + 1]);
    }
    defaults
}

fn registry_key(asset_id: AssetId) -> [u8; 32] {
    let mut payload = Vec::with_capacity(33);
    payload.push(0x01);
    payload.extend_from_slice(&asset_id);
    hash_domain(BUCKETED_KEY_DOMAIN, &payload)
}

fn balance_key(asset_id: AssetId, account: AccountId) -> [u8; 32] {
    let mut payload = Vec::with_capacity(65);
    payload.push(0x02);
    payload.extend_from_slice(&asset_id);
    payload.extend_from_slice(&account);
    hash_domain(BUCKETED_KEY_DOMAIN, &payload)
}

fn height_key(network_id: NetworkId) -> [u8; 32] {
    let mut payload = Vec::with_capacity(33);
    payload.push(0x03);
    payload.extend_from_slice(&network_id);
    hash_domain(BUCKETED_KEY_DOMAIN, &payload)
}

fn registry_value(definition: &[u8], total_supply: u128, frozen: bool) -> Vec<u8> {
    let mut value = Vec::with_capacity(2 + definition.len() + 16 + 1);
    value.extend_from_slice(&(definition.len() as u16).to_be_bytes());
    value.extend_from_slice(definition);
    value.extend_from_slice(&total_supply.to_be_bytes());
    value.push(u8::from(frozen));
    value
}

fn hash_leaf(key: [u8; 32], value: &[u8]) -> Result<[u8; 32], BucketedCommitmentError> {
    if key.iter().all(|byte| *byte == 0) {
        return Err(BucketedCommitmentError::ZeroKey);
    }
    if value.is_empty() {
        return Err(BucketedCommitmentError::EmptyValue);
    }
    let mut payload = Vec::with_capacity(32 + 4 + value.len());
    payload.extend_from_slice(&key);
    payload.extend_from_slice(&(value.len() as u32).to_be_bytes());
    payload.extend_from_slice(value);
    Ok(hash_domain(BUCKETED_LEAF_DOMAIN, &payload))
}

fn empty_bucket_hash() -> [u8; 32] {
    hash_domain(BUCKETED_BUCKET_DOMAIN, &[0u8; 4])
}

fn hash_bucket(bucket: u16, entries: &LeafMap) -> [u8; 32] {
    let mut payload = Vec::with_capacity(2 + 4 + entries.len() * 64);
    payload.extend_from_slice(&bucket.to_be_bytes());
    payload.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    for (leaf_key, leaf_hash) in entries {
        payload.extend_from_slice(leaf_key);
        payload.extend_from_slice(leaf_hash);
    }
    hash_domain(BUCKETED_BUCKET_DOMAIN, &payload)
}

fn hash_node(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut payload = Vec::with_capacity(64);
    payload.extend_from_slice(&left);
    payload.extend_from_slice(&right);
    hash_domain(BUCKETED_NODE_DOMAIN, &payload)
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

    fn limits() -> CandidateResourceLimits {
        CandidateResourceLimits {
            max_operations: 64,
            max_operation_bytes: 32 * 1024,
            max_assets: 64,
            max_holdings: 128,
        }
    }

    fn definition(nonce: u64) -> AssetDefinition {
        AssetDefinition {
            network_id: NETWORK,
            creator: ALICE,
            creation_nonce: nonce,
            name: format!("Bucketed {nonce}"),
            symbol: format!("B{nonce}"),
            decimals: 8,
            metadata_hash: [0x66; 32],
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
                limits(),
            )
            .unwrap();
        state
    }

    #[test]
    fn rebuild_is_deterministic_and_bound() {
        let state = state();
        let commitment = BucketedAssetStateCommitment::from_state(&state).unwrap();
        assert_ne!(commitment.root(), [0u8; 32]);
        assert!(commitment.bucket_count() >= 2);
        assert!(commitment.stored_top_node_count() >= commitment.bucket_count());
        assert!(commitment.matches_rebuild(&state).unwrap());
    }

    #[test]
    fn incremental_updates_match_full_rebuild() {
        let mut state = state();
        let asset_id = state.iter_registry().next().map(|(id, _)| *id).unwrap();
        let mut commitment = BucketedAssetStateCommitment::from_state(&state).unwrap();

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
                    limits(),
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
    fn clearing_balance_removes_bucket_entry_and_changes_root() {
        let state = state();
        let asset_id = state.iter_registry().next().map(|(id, _)| *id).unwrap();
        let mut commitment = BucketedAssetStateCommitment::from_state(&state).unwrap();
        let before = commitment.root();
        commitment.set_balance(asset_id, ALICE, 0).unwrap();
        assert_ne!(commitment.root(), before);
        assert!(!commitment.matches_rebuild(&state).unwrap());
    }

    #[test]
    fn deleting_last_nonzero_bucket_leaf_returns_to_empty_commitment() {
        let mut commitment = BucketedAssetStateCommitment::new(NETWORK, 100).unwrap();
        let key = [0xAA; 32];
        let empty_root = commitment.root();
        commitment.update_leaf(key, Some(vec![0x01])).unwrap();
        assert_ne!(commitment.root(), empty_root);
        assert_eq!(commitment.largest_bucket_len(), 1);
        commitment.update_leaf(key, None).unwrap();
        assert_eq!(commitment.root(), empty_root);
        assert_eq!(commitment.bucket_count(), 0);
    }

    #[test]
    fn concentrated_bucket_rehash_remains_deterministic() {
        let mut left = BucketedAssetStateCommitment::new(NETWORK, 100).unwrap();
        let mut right = BucketedAssetStateCommitment::new(NETWORK, 100).unwrap();
        for suffix in 0u16..256 {
            let mut key = [0u8; 32];
            key[0] = 0x5A;
            key[1] = 0xA5;
            key[30..].copy_from_slice(&suffix.to_be_bytes());
            let value = vec![((suffix as u32 % 255) + 1) as u8];
            left.update_leaf(key, Some(value.clone())).unwrap();
            right.update_leaf(key, Some(value)).unwrap();
        }
        assert_eq!(left.largest_bucket_len(), 256);
        assert_eq!(left.root(), right.root());
    }

    #[test]
    fn membership_proof_size_scales_with_bucket_occupancy() {
        let mut commitment = BucketedAssetStateCommitment::new(NETWORK, 100).unwrap();
        let target = [0x12, 0x34];
        let mut target_key = [0u8; 32];
        target_key[..2].copy_from_slice(&target);
        for suffix in 0u16..1024 {
            let mut key = [0u8; 32];
            key[..2].copy_from_slice(&target);
            key[30..].copy_from_slice(&suffix.to_be_bytes());
            commitment
                .insert_leaf_without_repath(key, vec![0x01; 32])
                .unwrap();
        }
        commitment.rebuild_top_tree();
        assert_eq!(commitment.bucket_len_for_key(target_key), 1024);
        let proof_bytes = commitment
            .membership_proof_size_upper_bound(target_key, 32)
            .unwrap();
        assert_eq!(proof_bytes, 1024 * 64 + 6 + 32 + 4 + 32 + 16 * 32);
    }

    #[test]
    fn missing_membership_proof_is_rejected_and_size_overflow_fails_closed() {
        let commitment = BucketedAssetStateCommitment::new(NETWORK, 100).unwrap();
        let missing_key = [0x21; 32];
        assert_eq!(commitment.bucket_len_for_key(missing_key), 0);
        assert!(matches!(
            commitment.membership_proof_size_upper_bound(missing_key, 1),
            Err(BucketedCommitmentError::InvalidBucket)
        ));

        let mut present = BucketedAssetStateCommitment::new(NETWORK, 100).unwrap();
        let present_key = [0x43; 32];
        present.update_leaf(present_key, Some(vec![0x01])).unwrap();
        assert!(matches!(
            present.membership_proof_size_upper_bound(present_key, usize::MAX),
            Err(BucketedCommitmentError::InvalidBucket)
        ));
    }
}
