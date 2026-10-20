//! Candidate incremental authenticated commitment for the asset-state experiment.
//!
//! This module is deliberately separate from consensus, LedgerState and the final
//! state-root wire decision. It evaluates a fixed-depth sparse Merkle commitment
//! where a leaf update touches only one root-to-leaf path.

use crate::asset_state_candidate::{AccountId, AssetStateCandidate};
use crate::token_forge::{encode_definition, AssetId, NetworkId};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const INCREMENTAL_COMMITMENT_DOMAIN: &[u8] = b"AIN1-ASSET-COMMIT-SMT-CAND-V1\0";
pub const INCREMENTAL_KEY_DOMAIN: &[u8] = b"AIN1-ASSET-COMMIT-KEY-CAND-V1\0";
pub const INCREMENTAL_LEAF_DOMAIN: &[u8] = b"AIN1-ASSET-COMMIT-LEAF-CAND-V1\0";
pub const INCREMENTAL_NODE_DOMAIN: &[u8] = b"AIN1-ASSET-COMMIT-NODE-CAND-V1\0";

const DEPTH: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct NodeKey {
    depth: u16,
    prefix: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IncrementalCommitmentError {
    InvalidNetworkId,
    ZeroKey,
    EmptyValue,
    HeightOverflow,
    AssetState(crate::asset_state_candidate::AssetStateCandidateError),
    TokenForge(crate::token_forge::TokenForgeError),
}

impl From<crate::asset_state_candidate::AssetStateCandidateError> for IncrementalCommitmentError {
    fn from(value: crate::asset_state_candidate::AssetStateCandidateError) -> Self {
        Self::AssetState(value)
    }
}

impl From<crate::token_forge::TokenForgeError> for IncrementalCommitmentError {
    fn from(value: crate::token_forge::TokenForgeError) -> Self {
        Self::TokenForge(value)
    }
}

impl std::fmt::Display for IncrementalCommitmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidNetworkId => write!(f, "incremental commitment network ID is zero"),
            Self::ZeroKey => write!(f, "incremental commitment key is zero"),
            Self::EmptyValue => write!(f, "incremental commitment value is empty"),
            Self::HeightOverflow => write!(f, "incremental commitment height overflow"),
            Self::AssetState(error) => write!(f, "asset-state error: {error}"),
            Self::TokenForge(error) => write!(f, "token-forge error: {error}"),
        }
    }
}

impl std::error::Error for IncrementalCommitmentError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncrementalAssetStateCommitment {
    network_id: NetworkId,
    height: u64,
    nodes: BTreeMap<NodeKey, [u8; 32]>,
    default_hashes: [[u8; 32]; DEPTH + 1],
}

impl IncrementalAssetStateCommitment {
    pub fn new(network_id: NetworkId, height: u64) -> Result<Self, IncrementalCommitmentError> {
        if network_id.iter().all(|byte| *byte == 0) {
            return Err(IncrementalCommitmentError::InvalidNetworkId);
        }
        Ok(Self {
            network_id,
            height,
            nodes: BTreeMap::new(),
            default_hashes: build_default_hashes(),
        })
    }

    pub fn from_state(state: &AssetStateCandidate) -> Result<Self, IncrementalCommitmentError> {
        state.verify_invariants()?;
        let mut commitment = Self::new(state.network_id(), state.height())?;
        commitment.rebuild_from_state(state)?;
        Ok(commitment)
    }

    pub fn network_id(&self) -> NetworkId {
        self.network_id
    }

    pub fn height(&self) -> u64 {
        self.height
    }

    pub fn root(&self) -> [u8; 32] {
        self.nodes
            .get(&NodeKey {
                depth: 0,
                prefix: [0u8; 32],
            })
            .copied()
            .unwrap_or(self.default_hashes[0])
    }

    pub fn stored_node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn leaf_count(&self) -> usize {
        self.nodes
            .keys()
            .filter(|key| key.depth == DEPTH as u16)
            .count()
    }

    pub fn set_height(&mut self, height: u64) -> Result<(), IncrementalCommitmentError> {
        self.height = height;
        self.update_leaf(height_key(self.network_id), height.to_be_bytes().to_vec())
    }

    pub fn set_balance(
        &mut self,
        asset_id: AssetId,
        account: AccountId,
        amount: u128,
    ) -> Result<(), IncrementalCommitmentError> {
        let key = balance_key(asset_id, account);
        let value = if amount == 0 {
            None
        } else {
            Some(amount.to_be_bytes().to_vec())
        };
        self.update_leaf(key, value)
    }

    pub fn set_registry(
        &mut self,
        asset_id: AssetId,
        definition: &[u8],
        total_supply: u128,
        frozen: bool,
    ) -> Result<(), IncrementalCommitmentError> {
        let key = registry_key(asset_id);
        let mut value = Vec::with_capacity(2 + definition.len() + 16 + 1);
        value.extend_from_slice(&(definition.len() as u16).to_be_bytes());
        value.extend_from_slice(definition);
        value.extend_from_slice(&total_supply.to_be_bytes());
        value.push(u8::from(frozen));
        self.update_leaf(key, Some(value))
    }

    pub fn clear_registry(&mut self, asset_id: AssetId) -> Result<(), IncrementalCommitmentError> {
        self.update_leaf(registry_key(asset_id), None)
    }

    pub fn rebuild_from_state(
        &mut self,
        state: &AssetStateCandidate,
    ) -> Result<(), IncrementalCommitmentError> {
        if state.network_id() != self.network_id {
            return Err(IncrementalCommitmentError::InvalidNetworkId);
        }
        self.nodes.clear();
        self.height = state.height();
        self.update_leaf(
            height_key(self.network_id),
            self.height.to_be_bytes().to_vec(),
        )?;

        for (asset_id, asset_state) in state.iter_registry() {
            let definition = encode_definition(&asset_state.definition)?;
            self.set_registry(
                *asset_id,
                &definition,
                asset_state.total_supply,
                asset_state.frozen,
            )?;
        }
        for ((asset_id, account), amount) in state.iter_balances() {
            self.set_balance(*asset_id, *account, *amount)?;
        }
        Ok(())
    }

    pub fn matches_rebuild(
        &self,
        state: &AssetStateCandidate,
    ) -> Result<bool, IncrementalCommitmentError> {
        let rebuilt = Self::from_state(state)?;
        Ok(self.root() == rebuilt.root())
    }

    fn update_leaf(
        &mut self,
        raw_key: [u8; 32],
        value: impl Into<Option<Vec<u8>>>,
    ) -> Result<(), IncrementalCommitmentError> {
        if raw_key.iter().all(|byte| *byte == 0) {
            return Err(IncrementalCommitmentError::ZeroKey);
        }
        let value = value.into();
        let leaf_key = hash_domain(INCREMENTAL_COMMITMENT_DOMAIN, &raw_key);
        let leaf_hash = match value {
            None => self.default_hashes[DEPTH],
            Some(value) if value.is_empty() => return Err(IncrementalCommitmentError::EmptyValue),
            Some(value) => {
                let mut payload = Vec::with_capacity(32 + 4 + value.len());
                payload.extend_from_slice(&leaf_key);
                payload.extend_from_slice(&(value.len() as u32).to_be_bytes());
                payload.extend_from_slice(&value);
                hash_domain(INCREMENTAL_LEAF_DOMAIN, &payload)
            }
        };

        let leaf_node = NodeKey {
            depth: DEPTH as u16,
            prefix: leaf_key,
        };
        self.set_node(leaf_node, leaf_hash);

        for depth in (0..DEPTH).rev() {
            let child_prefix = mask_prefix(leaf_key, depth + 1);
            let sibling_prefix = flip_bit(child_prefix, depth);
            let left = if bit_at(leaf_key, depth) == 0 {
                self.node_hash(depth + 1, child_prefix)
            } else {
                self.node_hash(depth + 1, sibling_prefix)
            };
            let right = if bit_at(leaf_key, depth) == 0 {
                self.node_hash(depth + 1, sibling_prefix)
            } else {
                self.node_hash(depth + 1, child_prefix)
            };
            let mut payload = Vec::with_capacity(64);
            payload.extend_from_slice(&left);
            payload.extend_from_slice(&right);
            let parent = hash_domain(INCREMENTAL_NODE_DOMAIN, &payload);
            self.set_node(
                NodeKey {
                    depth: depth as u16,
                    prefix: mask_prefix(leaf_key, depth),
                },
                parent,
            );
        }
        Ok(())
    }

    fn set_node(&mut self, key: NodeKey, value: [u8; 32]) {
        if value == self.default_hashes[key.depth as usize] {
            self.nodes.remove(&key);
        } else {
            self.nodes.insert(key, value);
        }
    }

    fn node_hash(&self, depth: usize, prefix: [u8; 32]) -> [u8; 32] {
        self.nodes
            .get(&NodeKey {
                depth: depth as u16,
                prefix,
            })
            .copied()
            .unwrap_or(self.default_hashes[depth])
    }
}

fn build_default_hashes() -> [[u8; 32]; DEPTH + 1] {
    let mut defaults = [[0u8; 32]; DEPTH + 1];
    defaults[DEPTH] = hash_domain(INCREMENTAL_LEAF_DOMAIN, b"");
    for depth in (0..DEPTH).rev() {
        let mut payload = Vec::with_capacity(64);
        payload.extend_from_slice(&defaults[depth + 1]);
        payload.extend_from_slice(&defaults[depth + 1]);
        defaults[depth] = hash_domain(INCREMENTAL_NODE_DOMAIN, &payload);
    }
    defaults
}

fn registry_key(asset_id: AssetId) -> [u8; 32] {
    let mut payload = Vec::with_capacity(33);
    payload.push(0x01);
    payload.extend_from_slice(&asset_id);
    hash_domain(INCREMENTAL_KEY_DOMAIN, &payload)
}

fn balance_key(asset_id: AssetId, account: AccountId) -> [u8; 32] {
    let mut payload = Vec::with_capacity(65);
    payload.push(0x02);
    payload.extend_from_slice(&asset_id);
    payload.extend_from_slice(&account);
    hash_domain(INCREMENTAL_KEY_DOMAIN, &payload)
}

fn height_key(network_id: NetworkId) -> [u8; 32] {
    let mut payload = Vec::with_capacity(33);
    payload.push(0x03);
    payload.extend_from_slice(&network_id);
    hash_domain(INCREMENTAL_KEY_DOMAIN, &payload)
}

fn hash_domain(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    hash.finalize().into()
}

fn bit_at(key: [u8; 32], depth: usize) -> u8 {
    let byte = key[depth / 8];
    (byte >> (7 - (depth % 8))) & 1
}

fn mask_prefix(key: [u8; 32], bits: usize) -> [u8; 32] {
    if bits == 0 {
        return [0u8; 32];
    }
    let mut out = key;
    let full_bytes = bits / 8;
    let rem = bits % 8;
    if rem != 0 {
        out[full_bytes] &= 0xFF << (8 - rem);
        for byte in &mut out[(full_bytes + 1)..] {
            *byte = 0;
        }
    } else {
        for byte in &mut out[full_bytes..] {
            *byte = 0;
        }
    }
    out
}

fn flip_bit(mut key: [u8; 32], depth: usize) -> [u8; 32] {
    key[depth / 8] ^= 1 << (7 - (depth % 8));
    mask_prefix(key, depth + 1)
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
            name: format!("Incremental {nonce}"),
            symbol: format!("I{nonce}"),
            decimals: 8,
            metadata_hash: [0x44; 32],
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
        let create = AssetOperation::Create {
            definition: definition(1),
        };
        state.apply_operation(&ALICE, &create, limits()).unwrap();
        state
    }

    #[test]
    fn rebuild_is_deterministic_and_non_empty() {
        let state = state();
        let commitment = IncrementalAssetStateCommitment::from_state(&state).unwrap();
        assert_ne!(commitment.root(), [0u8; 32]);
        assert!(commitment.leaf_count() >= 2);
        assert!(commitment.stored_node_count() >= commitment.leaf_count());
        assert!(commitment.matches_rebuild(&state).unwrap());
    }

    #[test]
    fn incremental_balance_updates_match_full_rebuild() {
        let mut state = state();
        let asset_id = state
            .iter_registry()
            .next()
            .map(|(asset_id, _)| *asset_id)
            .unwrap();
        let mut commitment = IncrementalAssetStateCommitment::from_state(&state).unwrap();

        let recipients = [BOB, [0x33; 32], [0x44; 32], [0x55; 32]];
        for (index, recipient) in recipients.into_iter().enumerate() {
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

            let previous_balance = state.balance(&asset_id, &ALICE) + 1;
            commitment
                .set_balance(asset_id, ALICE, previous_balance - 1)
                .unwrap();
            commitment
                .set_balance(asset_id, recipient, state.balance(&asset_id, &recipient))
                .unwrap();

            assert!(commitment.matches_rebuild(&state).unwrap());
        }
    }

    #[test]
    fn clearing_a_balance_removes_its_leaf_and_changes_root() {
        let state = state();
        let asset_id = state
            .iter_registry()
            .next()
            .map(|(asset_id, _)| *asset_id)
            .unwrap();
        let mut commitment = IncrementalAssetStateCommitment::from_state(&state).unwrap();
        let root_before = commitment.root();
        commitment.set_balance(asset_id, ALICE, 0).unwrap();
        assert_ne!(commitment.root(), root_before);
        let leaf_key = hash_domain(INCREMENTAL_COMMITMENT_DOMAIN, &balance_key(asset_id, ALICE));
        assert!(commitment
            .nodes
            .keys()
            .all(|key| { !(key.depth == DEPTH as u16 && key.prefix == leaf_key) }));
    }
}
