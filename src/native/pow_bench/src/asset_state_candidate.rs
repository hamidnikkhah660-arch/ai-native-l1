//! Candidate native-asset state engine for CP-W.
//!
//! This module is intentionally pre-activation. It composes the already-tested
//! Token Forge definition/registry and AOP1 envelope into a bounded, deterministic
//! asset substate without changing TXN2, LedgerState, consensus, or production wire.
//!
//! Candidate decisions represented here for testability only:
//! - CREATE credits initial_supply to definition.creator;
//! - AOP1 BURN treats the transaction sender as the holder;
//! - frozen assets reject mint, burn, and transfer;
//! - resource limits are supplied by the caller and remain non-ratified.
//!
//! Any production activation must re-run the owner approval gates in the integration
//! proposal and must not infer final wire semantics from this candidate module.

use crate::{
    asset_transactions::{
        decode_operation, encode_operation, AssetOperation, AssetOperationError,
        MAX_ASSET_OPERATION_BYTES, MAX_CREATE_DEFINITION_BYTES,
    },
    token_forge::{
        encode_definition, AssetDefinition, AssetId, AssetRegistry, AssetState, NetworkId,
        TokenForgeError,
    },
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{Cursor, Read},
};

pub const ASSET_STATE_MAGIC: [u8; 4] = *b"ASV1";
pub const ASSET_STATE_VERSION: u16 = 1;
pub const ASSET_STATE_CHECKSUM_DOMAIN: &[u8] = b"AIN1-ASSET-STATE-CHECK-V1\0";
pub const ASSET_STATE_ROOT_DOMAIN: &[u8] = b"AIN1-ASSET-STATE-ROOT-CAND-V1\0";
pub const MAX_CANDIDATE_ASSET_SNAPSHOT_BYTES: usize = 8 * 1024 * 1024;

const SNAPSHOT_HEADER_LEN: usize = 4 + 2 + 32 + 8 + 4 + 4;
const CHECKSUM_LEN: usize = 32;

pub type AccountId = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CandidateResourceLimits {
    pub max_operations: usize,
    pub max_operation_bytes: usize,
    pub max_assets: usize,
    pub max_holdings: usize,
}

impl CandidateResourceLimits {
    pub fn validate(&self) -> Result<(), AssetStateCandidateError> {
        if self.max_operations == 0
            || self.max_operation_bytes == 0
            || self.max_assets == 0
            || self.max_holdings == 0
        {
            return Err(AssetStateCandidateError::InvalidResourceLimit);
        }
        if self.max_operation_bytes > MAX_ASSET_OPERATION_BYTES.saturating_mul(self.max_operations)
        {
            return Err(AssetStateCandidateError::InvalidResourceLimit);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetStateCandidate {
    network_id: NetworkId,
    height: u64,
    registry: AssetRegistry,
    balances: BTreeMap<(AssetId, AccountId), u128>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssetStateCandidateError {
    TokenForge(TokenForgeError),
    AssetOperation(AssetOperationError),
    InvalidNetworkId,
    NetworkMismatch,
    InvalidResourceLimit,
    TooManyOperations(usize),
    AssetOperationBytesExceeded { actual: usize, limit: usize },
    TooManyAssets(usize),
    TooManyHoldings(usize),
    InvalidHeight,
    InvalidSnapshot,
    UnsupportedSnapshotVersion(u16),
    SnapshotChecksumMismatch,
    SnapshotNonCanonical,
    SnapshotOversize { actual: usize, limit: usize },
    DuplicateAsset,
    AssetIdMismatch,
    InvalidAccountId,
    InvalidBalance,
    BalanceOverflow,
    BalanceUnderflow,
    InvariantViolation,
}

impl From<TokenForgeError> for AssetStateCandidateError {
    fn from(value: TokenForgeError) -> Self {
        Self::TokenForge(value)
    }
}

impl From<AssetOperationError> for AssetStateCandidateError {
    fn from(value: AssetOperationError) -> Self {
        Self::AssetOperation(value)
    }
}

impl std::fmt::Display for AssetStateCandidateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TokenForge(error) => write!(f, "token forge error: {error}"),
            Self::AssetOperation(error) => write!(f, "asset operation error: {error}"),
            Self::InvalidNetworkId => write!(f, "candidate asset state network ID is zero"),
            Self::NetworkMismatch => {
                write!(f, "asset operation or definition uses another network")
            }
            Self::InvalidResourceLimit => write!(f, "candidate resource limits are invalid"),
            Self::TooManyOperations(actual) => write!(f, "too many asset operations: {actual}"),
            Self::AssetOperationBytesExceeded { actual, limit } => {
                write!(f, "asset operation bytes {actual} exceed limit {limit}")
            }
            Self::TooManyAssets(actual) => write!(f, "too many registered assets: {actual}"),
            Self::TooManyHoldings(actual) => write!(f, "too many asset holdings: {actual}"),
            Self::InvalidHeight => write!(f, "candidate asset state height must be positive"),
            Self::InvalidSnapshot => write!(f, "candidate asset snapshot is malformed"),
            Self::UnsupportedSnapshotVersion(version) => {
                write!(f, "unsupported candidate asset snapshot version {version}")
            }
            Self::SnapshotChecksumMismatch => {
                write!(f, "candidate asset snapshot checksum mismatch")
            }
            Self::SnapshotNonCanonical => write!(f, "candidate asset snapshot is non-canonical"),
            Self::SnapshotOversize { actual, limit } => {
                write!(f, "candidate asset snapshot {actual} exceeds limit {limit}")
            }
            Self::DuplicateAsset => write!(f, "candidate asset ID is duplicated"),
            Self::AssetIdMismatch => write!(f, "candidate asset ID does not match definition"),
            Self::InvalidAccountId => write!(f, "candidate asset account ID is zero"),
            Self::InvalidBalance => write!(f, "candidate asset balance must be positive"),
            Self::BalanceOverflow => write!(f, "candidate asset balance overflow"),
            Self::BalanceUnderflow => write!(f, "candidate asset balance underflow"),
            Self::InvariantViolation => write!(f, "candidate asset state invariant violated"),
        }
    }
}

impl std::error::Error for AssetStateCandidateError {}

impl AssetStateCandidate {
    pub fn genesis(network_id: NetworkId) -> Result<Self, AssetStateCandidateError> {
        if network_id.iter().all(|byte| *byte == 0) {
            return Err(AssetStateCandidateError::InvalidNetworkId);
        }
        Ok(Self {
            network_id,
            height: 0,
            registry: AssetRegistry::new(),
            balances: BTreeMap::new(),
        })
    }

    pub fn network_id(&self) -> NetworkId {
        self.network_id
    }

    pub fn height(&self) -> u64 {
        self.height
    }

    pub fn asset_count(&self) -> usize {
        self.registry.len()
    }

    pub fn iter_registry(&self) -> impl Iterator<Item = (&AssetId, &AssetState)> {
        self.registry.iter()
    }

    pub fn holding_count(&self) -> usize {
        self.balances.len()
    }

    pub fn iter_balances(&self) -> impl Iterator<Item = (&(AssetId, AccountId), &u128)> {
        self.balances.iter()
    }

    pub fn asset(&self, asset_id: &AssetId) -> Result<&AssetState, AssetStateCandidateError> {
        self.registry.get(asset_id).map_err(Into::into)
    }

    pub fn balance(&self, asset_id: &AssetId, account: &AccountId) -> u128 {
        self.balances
            .get(&(*asset_id, *account))
            .copied()
            .unwrap_or(0)
    }

    pub fn advance_height(&mut self, height: u64) -> Result<(), AssetStateCandidateError> {
        if height < self.height {
            return Err(AssetStateCandidateError::InvalidHeight);
        }
        self.height = height;
        self.verify_invariants()
    }

    pub fn verify_invariants(&self) -> Result<(), AssetStateCandidateError> {
        if self.network_id.iter().all(|byte| *byte == 0) {
            return Err(AssetStateCandidateError::InvalidNetworkId);
        }
        for (asset_id, state) in self.registry.iter() {
            if state.definition.network_id != self.network_id {
                return Err(AssetStateCandidateError::NetworkMismatch);
            }
            if state.asset_id()? != *asset_id {
                return Err(AssetStateCandidateError::AssetIdMismatch);
            }
            let sum = self
                .balances
                .iter()
                .filter(|((id, _), _)| id == asset_id)
                .try_fold(0u128, |sum, (_, amount)| {
                    sum.checked_add(*amount)
                        .ok_or(AssetStateCandidateError::BalanceOverflow)
                })?;
            if sum != state.total_supply {
                return Err(AssetStateCandidateError::InvariantViolation);
            }
        }
        for ((asset_id, account), amount) in &self.balances {
            if account.iter().all(|byte| *byte == 0) {
                return Err(AssetStateCandidateError::InvalidAccountId);
            }
            if *amount == 0 {
                return Err(AssetStateCandidateError::InvalidBalance);
            }
            if !self.registry.contains(asset_id) {
                return Err(AssetStateCandidateError::InvariantViolation);
            }
        }
        Ok(())
    }

    /// Apply a canonical batch atomically. Limits are explicit inputs because their final
    /// consensus values still require load testing and owner ratification.
    pub fn apply_encoded_batch(
        &mut self,
        sender: &AccountId,
        encoded_operations: &[Vec<u8>],
        limits: CandidateResourceLimits,
    ) -> Result<(), AssetStateCandidateError> {
        limits.validate()?;
        if self.height == 0 {
            return Err(AssetStateCandidateError::InvalidHeight);
        }
        if encoded_operations.len() > limits.max_operations {
            return Err(AssetStateCandidateError::TooManyOperations(
                encoded_operations.len(),
            ));
        }
        let total_bytes = encoded_operations.iter().try_fold(0usize, |sum, bytes| {
            sum.checked_add(bytes.len()).ok_or(
                AssetStateCandidateError::AssetOperationBytesExceeded {
                    actual: usize::MAX,
                    limit: limits.max_operation_bytes,
                },
            )
        })?;
        if total_bytes > limits.max_operation_bytes {
            return Err(AssetStateCandidateError::AssetOperationBytesExceeded {
                actual: total_bytes,
                limit: limits.max_operation_bytes,
            });
        }

        let mut working = self.clone();
        for bytes in encoded_operations {
            let operation = decode_operation(bytes)?;
            working.apply_operation_in_place(sender, &operation, &limits)?;
        }
        working.verify_invariants()?;
        *self = working;
        Ok(())
    }

    pub fn apply_operation(
        &mut self,
        sender: &AccountId,
        operation: &AssetOperation,
        limits: CandidateResourceLimits,
    ) -> Result<(), AssetStateCandidateError> {
        let encoded = encode_operation(operation)?;
        self.apply_encoded_batch(sender, &[encoded], limits)
    }

    fn apply_operation_in_place(
        &mut self,
        sender: &AccountId,
        operation: &AssetOperation,
        limits: &CandidateResourceLimits,
    ) -> Result<(), AssetStateCandidateError> {
        if sender.iter().all(|byte| *byte == 0) {
            return Err(AssetStateCandidateError::InvalidAccountId);
        }

        match operation {
            AssetOperation::Create { definition } => {
                if definition.network_id != self.network_id {
                    return Err(AssetStateCandidateError::NetworkMismatch);
                }
                if definition.creator != *sender {
                    return Err(AssetStateCandidateError::InvalidAccountId);
                }
                if self.registry.len() >= limits.max_assets {
                    return Err(AssetStateCandidateError::TooManyAssets(
                        self.registry.len() + 1,
                    ));
                }

                let state = AssetState::new(definition.clone())?;
                let asset_id = state.asset_id()?;
                if self.registry.contains(&asset_id) {
                    return Err(AssetStateCandidateError::DuplicateAsset);
                }
                let initial_supply = state.total_supply;
                self.registry.create(definition.clone())?;
                if initial_supply > 0 {
                    self.credit(asset_id, *sender, initial_supply, limits)?;
                }
            }
            AssetOperation::Mint { asset_id, amount } => {
                let current = self.balance(asset_id, sender);
                let state = self.registry.get_mut(asset_id)?;
                state.mint(sender, *amount, self.height)?;
                let next = current
                    .checked_add(*amount)
                    .ok_or(AssetStateCandidateError::BalanceOverflow)?;
                if current == 0 && next > 0 && !self.balances.contains_key(&(*asset_id, *sender)) {
                    if self.balances.len() >= limits.max_holdings {
                        return Err(AssetStateCandidateError::TooManyHoldings(
                            self.balances.len() + 1,
                        ));
                    }
                }
                self.balances.insert((*asset_id, *sender), next);
            }
            AssetOperation::Burn { asset_id, amount } => {
                let current = self.balance(asset_id, sender);
                let mut next = current;
                let state = self.registry.get_mut(asset_id)?;
                if state.frozen {
                    return Err(TokenForgeError::AssetFrozen.into());
                }
                state.burn_from_holder(sender, &mut next, *amount)?;
                if next == 0 {
                    self.balances.remove(&(*asset_id, *sender));
                } else {
                    self.balances.insert((*asset_id, *sender), next);
                }
            }
            AssetOperation::Freeze { asset_id, frozen } => {
                let state = self.registry.get_mut(asset_id)?;
                if *frozen {
                    state.freeze(sender)?;
                } else {
                    state.unfreeze(sender)?;
                }
            }
            AssetOperation::Transfer {
                asset_id,
                recipient,
                amount,
            } => {
                if recipient.iter().all(|byte| *byte == 0) {
                    return Err(AssetStateCandidateError::InvalidAccountId);
                }
                let state = self.registry.get(asset_id)?;
                if state.frozen {
                    return Err(TokenForgeError::AssetFrozen.into());
                }
                let sender_balance = self.balance(asset_id, sender);
                if sender_balance < *amount {
                    return Err(TokenForgeError::HolderInsufficientBalance.into());
                }
                let recipient_current = self.balance(asset_id, recipient);
                let recipient_next = recipient_current
                    .checked_add(*amount)
                    .ok_or(AssetStateCandidateError::BalanceOverflow)?;
                if sender != recipient
                    && recipient_current == 0
                    && self.balances.len() >= limits.max_holdings
                {
                    return Err(AssetStateCandidateError::TooManyHoldings(
                        self.balances.len() + 1,
                    ));
                }
                let sender_next = sender_balance
                    .checked_sub(*amount)
                    .ok_or(AssetStateCandidateError::BalanceUnderflow)?;
                if sender_next == 0 {
                    self.balances.remove(&(*asset_id, *sender));
                } else {
                    self.balances.insert((*asset_id, *sender), sender_next);
                }
                if recipient_next == 0 {
                    self.balances.remove(&(*asset_id, *recipient));
                } else {
                    self.balances
                        .insert((*asset_id, *recipient), recipient_next);
                }
            }
        }

        if self.registry.len() > limits.max_assets {
            return Err(AssetStateCandidateError::TooManyAssets(self.registry.len()));
        }
        if self.balances.len() > limits.max_holdings {
            return Err(AssetStateCandidateError::TooManyHoldings(
                self.balances.len(),
            ));
        }
        Ok(())
    }

    fn credit(
        &mut self,
        asset_id: AssetId,
        account: AccountId,
        amount: u128,
        limits: &CandidateResourceLimits,
    ) -> Result<(), AssetStateCandidateError> {
        if account.iter().all(|byte| *byte == 0) {
            return Err(AssetStateCandidateError::InvalidAccountId);
        }
        if amount == 0 {
            return Err(AssetStateCandidateError::InvalidBalance);
        }
        let current = self.balance(&asset_id, &account);
        let next = current
            .checked_add(amount)
            .ok_or(AssetStateCandidateError::BalanceOverflow)?;
        if current == 0 && self.balances.len() >= limits.max_holdings {
            return Err(AssetStateCandidateError::TooManyHoldings(
                self.balances.len() + 1,
            ));
        }
        self.balances.insert((asset_id, account), next);
        Ok(())
    }

    /// Candidate state root. The hash commits to the network, logical height, canonical
    /// sorted registry records, and canonical sorted sparse balances. No tip/block hash is
    /// included, avoiding a circular commitment.
    pub fn state_root(&self) -> Result<[u8; 32], AssetStateCandidateError> {
        self.verify_invariants()?;
        let mut canonical = Vec::new();
        canonical.extend_from_slice(&self.network_id);
        canonical.extend_from_slice(&self.height.to_be_bytes());
        canonical.extend_from_slice(&(self.registry.len() as u32).to_be_bytes());
        for (asset_id, state) in self.registry.iter() {
            let definition = encode_definition(&state.definition)?;
            canonical.extend_from_slice(asset_id);
            canonical.extend_from_slice(&(definition.len() as u16).to_be_bytes());
            canonical.extend_from_slice(&definition);
            canonical.extend_from_slice(&state.total_supply.to_be_bytes());
            canonical.push(u8::from(state.frozen));
        }
        canonical.extend_from_slice(&(self.balances.len() as u32).to_be_bytes());
        for ((asset_id, account), amount) in &self.balances {
            canonical.extend_from_slice(asset_id);
            canonical.extend_from_slice(account);
            canonical.extend_from_slice(&amount.to_be_bytes());
        }
        let mut hash = Sha256::new();
        hash.update(ASSET_STATE_ROOT_DOMAIN);
        hash.update(canonical);
        Ok(hash.finalize().into())
    }

    pub fn encode_snapshot(&self) -> Result<Vec<u8>, AssetStateCandidateError> {
        self.verify_invariants()?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ASSET_STATE_MAGIC);
        bytes.extend_from_slice(&ASSET_STATE_VERSION.to_be_bytes());
        bytes.extend_from_slice(&self.network_id);
        bytes.extend_from_slice(&self.height.to_be_bytes());
        bytes.extend_from_slice(&(self.registry.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&(self.balances.len() as u32).to_be_bytes());

        for (asset_id, state) in self.registry.iter() {
            let definition = encode_definition(&state.definition)?;
            if definition.len() > MAX_CREATE_DEFINITION_BYTES {
                return Err(AssetStateCandidateError::InvalidSnapshot);
            }
            bytes.extend_from_slice(asset_id);
            bytes.extend_from_slice(&(definition.len() as u16).to_be_bytes());
            bytes.extend_from_slice(&definition);
            bytes.extend_from_slice(&state.total_supply.to_be_bytes());
            bytes.push(u8::from(state.frozen));
        }

        for ((asset_id, account), amount) in &self.balances {
            bytes.extend_from_slice(asset_id);
            bytes.extend_from_slice(account);
            bytes.extend_from_slice(&amount.to_be_bytes());
        }

        if bytes.len() + CHECKSUM_LEN > MAX_CANDIDATE_ASSET_SNAPSHOT_BYTES {
            return Err(AssetStateCandidateError::SnapshotOversize {
                actual: bytes.len() + CHECKSUM_LEN,
                limit: MAX_CANDIDATE_ASSET_SNAPSHOT_BYTES,
            });
        }
        let checksum = hash_domain(ASSET_STATE_CHECKSUM_DOMAIN, &bytes);
        bytes.extend_from_slice(&checksum);
        Ok(bytes)
    }

    pub fn decode_snapshot(
        bytes: &[u8],
        expected_network_id: &NetworkId,
    ) -> Result<Self, AssetStateCandidateError> {
        if expected_network_id.iter().all(|byte| *byte == 0) {
            return Err(AssetStateCandidateError::InvalidNetworkId);
        }
        if bytes.len() > MAX_CANDIDATE_ASSET_SNAPSHOT_BYTES {
            return Err(AssetStateCandidateError::SnapshotOversize {
                actual: bytes.len(),
                limit: MAX_CANDIDATE_ASSET_SNAPSHOT_BYTES,
            });
        }
        if bytes.len() < SNAPSHOT_HEADER_LEN + CHECKSUM_LEN {
            return Err(AssetStateCandidateError::InvalidSnapshot);
        }

        let payload_len = bytes.len() - CHECKSUM_LEN;
        let expected_checksum = hash_domain(ASSET_STATE_CHECKSUM_DOMAIN, &bytes[..payload_len]);
        if bytes[payload_len..] != expected_checksum {
            return Err(AssetStateCandidateError::SnapshotChecksumMismatch);
        }

        let mut cursor = Cursor::new(&bytes[..payload_len]);
        if read_array::<4>(&mut cursor)? != ASSET_STATE_MAGIC {
            return Err(AssetStateCandidateError::InvalidSnapshot);
        }
        let version = read_u16(&mut cursor)?;
        if version != ASSET_STATE_VERSION {
            return Err(AssetStateCandidateError::UnsupportedSnapshotVersion(
                version,
            ));
        }
        let network_id = read_array::<32>(&mut cursor)?;
        if network_id != *expected_network_id {
            return Err(AssetStateCandidateError::NetworkMismatch);
        }
        let height = read_u64(&mut cursor)?;
        let asset_count = read_u32(&mut cursor)? as usize;
        let holding_count = read_u32(&mut cursor)? as usize;

        if asset_count == 0 && holding_count != 0 {
            return Err(AssetStateCandidateError::SnapshotNonCanonical);
        }

        let mut registry = AssetRegistry::new();
        let mut previous_asset_id: Option<AssetId> = None;
        for _ in 0..asset_count {
            let asset_id = read_array::<32>(&mut cursor)?;
            if previous_asset_id.is_some_and(|previous| asset_id <= previous) {
                return Err(AssetStateCandidateError::SnapshotNonCanonical);
            }
            previous_asset_id = Some(asset_id);

            let definition_len = read_u16(&mut cursor)? as usize;
            if definition_len > MAX_CREATE_DEFINITION_BYTES {
                return Err(AssetStateCandidateError::InvalidSnapshot);
            }
            let definition_bytes = read_vec(&mut cursor, definition_len)?;
            let definition = crate::token_forge::decode_definition(&definition_bytes)?;
            if definition.network_id != network_id {
                return Err(AssetStateCandidateError::NetworkMismatch);
            }
            if crate::token_forge::asset_id(&definition)? != asset_id {
                return Err(AssetStateCandidateError::AssetIdMismatch);
            }
            let total_supply = read_u128(&mut cursor)?;
            let frozen = match read_u8(&mut cursor)? {
                0 => false,
                1 => true,
                _ => return Err(AssetStateCandidateError::SnapshotNonCanonical),
            };

            let inserted = registry.create(definition)?;
            if inserted != asset_id {
                return Err(AssetStateCandidateError::AssetIdMismatch);
            }
            registry.get_mut(&asset_id)?.total_supply = total_supply;
            registry.get_mut(&asset_id)?.frozen = frozen;
        }

        let mut balances = BTreeMap::new();
        let mut previous_holding: Option<(AssetId, AccountId)> = None;
        for _ in 0..holding_count {
            let asset_id = read_array::<32>(&mut cursor)?;
            let account = read_array::<32>(&mut cursor)?;
            if account.iter().all(|byte| *byte == 0) {
                return Err(AssetStateCandidateError::InvalidAccountId);
            }
            let amount = read_u128(&mut cursor)?;
            if amount == 0 {
                return Err(AssetStateCandidateError::InvalidBalance);
            }
            let key = (asset_id, account);
            if previous_holding.is_some_and(|previous| key <= previous) {
                return Err(AssetStateCandidateError::SnapshotNonCanonical);
            }
            previous_holding = Some(key);
            if !registry.contains(&asset_id) {
                return Err(AssetStateCandidateError::InvariantViolation);
            }
            if balances.insert(key, amount).is_some() {
                return Err(AssetStateCandidateError::SnapshotNonCanonical);
            }
        }

        if cursor.position() as usize != payload_len {
            return Err(AssetStateCandidateError::InvalidSnapshot);
        }

        let state = Self {
            network_id,
            height,
            registry,
            balances,
        };
        state.verify_invariants()?;
        Ok(state)
    }

    pub fn rollback_to(&mut self, prior: &Self) -> Result<(), AssetStateCandidateError> {
        if prior.network_id != self.network_id {
            return Err(AssetStateCandidateError::NetworkMismatch);
        }
        prior.verify_invariants()?;
        *self = prior.clone();
        Ok(())
    }

    pub fn asset_definition(
        &self,
        asset_id: &AssetId,
    ) -> Result<&AssetDefinition, AssetStateCandidateError> {
        Ok(&self.registry.get(asset_id)?.definition)
    }
}

fn hash_domain(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    hash.finalize().into()
}

fn read_array<const N: usize>(
    cursor: &mut Cursor<&[u8]>,
) -> Result<[u8; N], AssetStateCandidateError> {
    let mut value = [0u8; N];
    cursor
        .read_exact(&mut value)
        .map_err(|_| AssetStateCandidateError::InvalidSnapshot)?;
    Ok(value)
}

fn read_u8(cursor: &mut Cursor<&[u8]>) -> Result<u8, AssetStateCandidateError> {
    Ok(read_array::<1>(cursor)?[0])
}

fn read_u16(cursor: &mut Cursor<&[u8]>) -> Result<u16, AssetStateCandidateError> {
    Ok(u16::from_be_bytes(read_array(cursor)?))
}

fn read_u32(cursor: &mut Cursor<&[u8]>) -> Result<u32, AssetStateCandidateError> {
    Ok(u32::from_be_bytes(read_array(cursor)?))
}

fn read_u64(cursor: &mut Cursor<&[u8]>) -> Result<u64, AssetStateCandidateError> {
    Ok(u64::from_be_bytes(read_array(cursor)?))
}

fn read_u128(cursor: &mut Cursor<&[u8]>) -> Result<u128, AssetStateCandidateError> {
    Ok(u128::from_be_bytes(read_array(cursor)?))
}

fn read_vec(cursor: &mut Cursor<&[u8]>, len: usize) -> Result<Vec<u8>, AssetStateCandidateError> {
    let mut value = vec![0u8; len];
    cursor
        .read_exact(&mut value)
        .map_err(|_| AssetStateCandidateError::InvalidSnapshot)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        asset_transactions::AssetOperation,
        token_forge::{BurnAuthority, FreezePolicy, MintAuthority, SupplyPolicy},
    };
    use std::process::Command;

    const NETWORK: NetworkId = [0xC7; 32];
    const ALICE: AccountId = [0x11; 32];
    const BOB: AccountId = [0x22; 32];
    const CAROL: AccountId = [0x33; 32];

    fn limits() -> CandidateResourceLimits {
        CandidateResourceLimits {
            max_operations: 16,
            max_operation_bytes: 4096,
            max_assets: 8,
            max_holdings: 16,
        }
    }

    fn definition(creator: AccountId, nonce: u64, symbol: &str) -> AssetDefinition {
        AssetDefinition {
            network_id: NETWORK,
            creator,
            creation_nonce: nonce,
            name: format!("Candidate Asset {nonce}"),
            symbol: symbol.to_owned(),
            decimals: 8,
            metadata_hash: [0x55; 32],
            supply_policy: SupplyPolicy::Capped {
                initial_supply: 1_000,
                max_supply: 5_000,
            },
            mint_authority: MintAuthority::Creator,
            burn_authority: BurnAuthority::Holder,
            freeze_policy: FreezePolicy::Creator,
        }
    }

    fn create_op(definition: AssetDefinition) -> AssetOperation {
        AssetOperation::Create { definition }
    }

    #[test]
    fn separate_process_branch_probe() {
        let Ok(input_path) = std::env::var("CPW_ASSET_STATE_CHILD_INPUT") else {
            return;
        };
        let output_path =
            std::env::var("CPW_ASSET_STATE_CHILD_OUTPUT").expect("candidate child output path");
        let recipient = match std::env::var("CPW_ASSET_STATE_CHILD_RECIPIENT")
            .expect("candidate child recipient")
            .as_str()
        {
            "BOB" => BOB,
            "CAROL" => CAROL,
            other => panic!("unsupported candidate child recipient {other}"),
        };
        let amount: u128 = std::env::var("CPW_ASSET_STATE_CHILD_AMOUNT")
            .unwrap_or_else(|_| "111".to_owned())
            .parse()
            .expect("candidate child amount");

        let input = std::fs::read(&input_path).expect("read candidate branch input");
        let mut state =
            AssetStateCandidate::decode_snapshot(&input, &NETWORK).expect("decode branch input");
        let def = definition(ALICE, 77, "CHA");
        let asset_id = crate::token_forge::asset_id(&def).unwrap();
        assert_eq!(state.balance(&asset_id, &ALICE), 1_000);

        state
            .apply_operation(
                &ALICE,
                &AssetOperation::Transfer {
                    asset_id,
                    recipient,
                    amount,
                },
                limits(),
            )
            .expect("apply candidate branch operation");

        let encoded = state.encode_snapshot().unwrap();
        std::fs::write(output_path, encoded).expect("write candidate branch output");
    }

    #[test]
    fn separate_process_forks_diverge_and_reorg_restores_exact_state() {
        let mut base = AssetStateCandidate::genesis(NETWORK).unwrap();
        base.advance_height(101).unwrap();
        let create = create_op(definition(ALICE, 77, "CHA"));
        base.apply_operation(&ALICE, &create, limits()).unwrap();

        let base_root = base.state_root().unwrap();
        let base_snapshot = base.encode_snapshot().unwrap();
        let stem = format!("cpw_asset_reorg_{}_{}", std::process::id(), base.height());
        let input_path = std::env::temp_dir().join(format!("{stem}_base.bin"));
        let bob_path = std::env::temp_dir().join(format!("{stem}_bob.bin"));
        let carol_path = std::env::temp_dir().join(format!("{stem}_carol.bin"));
        for path in [&input_path, &bob_path, &carol_path] {
            let _ = std::fs::remove_file(path);
        }
        std::fs::write(&input_path, &base_snapshot).expect("write shared base snapshot");

        let current_test_binary = std::env::current_exe().expect("candidate test binary");

        for (recipient, output) in [("BOB", &bob_path), ("CAROL", &carol_path)] {
            let status = Command::new(&current_test_binary)
                .arg("--exact")
                .arg("asset_state_candidate::tests::separate_process_branch_probe")
                .arg("--nocapture")
                .env("CPW_ASSET_STATE_CHILD_INPUT", &input_path)
                .env("CPW_ASSET_STATE_CHILD_OUTPUT", output)
                .env("CPW_ASSET_STATE_CHILD_RECIPIENT", recipient)
                .status()
                .expect("launch candidate branch process");
            assert!(
                status.success(),
                "candidate branch process failed for {recipient}: {status:?}"
            );
        }

        let bob = AssetStateCandidate::decode_snapshot(
            &std::fs::read(&bob_path).expect("read bob branch"),
            &NETWORK,
        )
        .unwrap();
        let carol = AssetStateCandidate::decode_snapshot(
            &std::fs::read(&carol_path).expect("read carol branch"),
            &NETWORK,
        )
        .unwrap();

        assert_ne!(bob.state_root().unwrap(), base_root);
        assert_ne!(carol.state_root().unwrap(), base_root);
        assert_ne!(bob.state_root().unwrap(), carol.state_root().unwrap());

        let asset_id = if let AssetOperation::Create { ref definition } = create {
            crate::token_forge::asset_id(definition).unwrap()
        } else {
            unreachable!()
        };
        assert_eq!(bob.balance(&asset_id, &BOB), 111);
        assert_eq!(bob.balance(&asset_id, &ALICE), 889);
        assert_eq!(carol.balance(&asset_id, &CAROL), 111);
        assert_eq!(carol.balance(&asset_id, &ALICE), 889);

        let mut rolled_back = bob.clone();
        rolled_back.rollback_to(&base).unwrap();
        assert_eq!(rolled_back.state_root().unwrap(), base_root);
        assert_eq!(rolled_back.encode_snapshot().unwrap(), base_snapshot);
        base.verify_invariants().unwrap();
        bob.verify_invariants().unwrap();
        carol.verify_invariants().unwrap();

        let _ = std::fs::remove_file(input_path);
        let _ = std::fs::remove_file(bob_path);
        let _ = std::fs::remove_file(carol_path);
    }

    #[test]
    fn repeated_partition_rounds_diverge_and_rollback_from_common_ancestor() {
        let mut base = AssetStateCandidate::genesis(NETWORK).unwrap();
        base.advance_height(500).unwrap();
        let create = create_op(definition(ALICE, 77, "CHA"));
        base.apply_operation(&ALICE, &create, limits()).unwrap();

        let asset_id = if let AssetOperation::Create { ref definition } = create {
            crate::token_forge::asset_id(definition).unwrap()
        } else {
            unreachable!()
        };
        let base_root = base.state_root().unwrap();
        let base_snapshot = base.encode_snapshot().unwrap();
        let exe = std::env::current_exe().expect("candidate test binary");

        for round in 1u128..=5 {
            let input_path = std::env::temp_dir().join(format!(
                "cpw_asset_partition_{}_{}_base.bin",
                std::process::id(),
                round
            ));
            let bob_path = std::env::temp_dir().join(format!(
                "cpw_asset_partition_{}_{}_bob.bin",
                std::process::id(),
                round
            ));
            let carol_path = std::env::temp_dir().join(format!(
                "cpw_asset_partition_{}_{}_carol.bin",
                std::process::id(),
                round
            ));
            for path in [&input_path, &bob_path, &carol_path] {
                let _ = std::fs::remove_file(path);
            }
            std::fs::write(&input_path, &base_snapshot).expect("write partition ancestor");

            let bob_amount = 10 + round;
            let carol_amount = 20 + round;
            for (recipient, amount, output) in [
                ("BOB", bob_amount, &bob_path),
                ("CAROL", carol_amount, &carol_path),
            ] {
                let status = Command::new(&exe)
                    .arg("--exact")
                    .arg("asset_state_candidate::tests::separate_process_branch_probe")
                    .arg("--nocapture")
                    .env("CPW_ASSET_STATE_CHILD_INPUT", &input_path)
                    .env("CPW_ASSET_STATE_CHILD_OUTPUT", output)
                    .env("CPW_ASSET_STATE_CHILD_RECIPIENT", recipient)
                    .env("CPW_ASSET_STATE_CHILD_AMOUNT", amount.to_string())
                    .status()
                    .expect("launch partition branch process");
                assert!(
                    status.success(),
                    "partition branch process failed for {recipient}: {status:?}"
                );
            }

            let bob = AssetStateCandidate::decode_snapshot(
                &std::fs::read(&bob_path).expect("read bob partition branch"),
                &NETWORK,
            )
            .unwrap();
            let carol = AssetStateCandidate::decode_snapshot(
                &std::fs::read(&carol_path).expect("read carol partition branch"),
                &NETWORK,
            )
            .unwrap();

            assert_eq!(bob.height(), base.height());
            assert_eq!(carol.height(), base.height());
            assert_ne!(bob.state_root().unwrap(), base_root);
            assert_ne!(carol.state_root().unwrap(), base_root);
            assert_ne!(bob.state_root().unwrap(), carol.state_root().unwrap());
            assert_eq!(bob.balance(&asset_id, &BOB), bob_amount);
            assert_eq!(carol.balance(&asset_id, &CAROL), carol_amount);
            assert_eq!(bob.balance(&asset_id, &ALICE), 1_000 - bob_amount);
            assert_eq!(carol.balance(&asset_id, &ALICE), 1_000 - carol_amount);
            bob.verify_invariants().unwrap();
            carol.verify_invariants().unwrap();

            let mut rolled_back_bob = bob.clone();
            rolled_back_bob.rollback_to(&base).unwrap();
            assert_eq!(rolled_back_bob.state_root().unwrap(), base_root);
            assert_eq!(rolled_back_bob.encode_snapshot().unwrap(), base_snapshot);

            let mut rolled_back_carol = carol.clone();
            rolled_back_carol.rollback_to(&base).unwrap();
            assert_eq!(rolled_back_carol.state_root().unwrap(), base_root);
            assert_eq!(rolled_back_carol.encode_snapshot().unwrap(), base_snapshot);

            let _ = std::fs::remove_file(input_path);
            let _ = std::fs::remove_file(bob_path);
            let _ = std::fs::remove_file(carol_path);
        }
    }

    #[test]
    fn create_assigns_initial_supply_and_preserves_supply_invariant() {
        let mut state = AssetStateCandidate::genesis(NETWORK).unwrap();
        state.advance_height(1).unwrap();
        let op = create_op(definition(ALICE, 1, "CA1"));
        let asset_id = {
            let AssetOperation::Create { definition } = &op else {
                unreachable!();
            };
            crate::token_forge::asset_id(definition).unwrap()
        };
        state.apply_operation(&ALICE, &op, limits()).unwrap();
        assert_eq!(state.balance(&asset_id, &ALICE), 1_000);
        assert_eq!(state.asset(&asset_id).unwrap().total_supply, 1_000);
        state.verify_invariants().unwrap();
    }

    #[test]
    fn batch_is_atomic_and_reorg_restores_exact_root() {
        let mut state = AssetStateCandidate::genesis(NETWORK).unwrap();
        state.advance_height(10).unwrap();
        let create = create_op(definition(ALICE, 2, "CA2"));
        state.apply_operation(&ALICE, &create, limits()).unwrap();
        let asset_id = if let AssetOperation::Create { ref definition } = create {
            crate::token_forge::asset_id(definition).unwrap()
        } else {
            unreachable!()
        };
        let before = state.clone();
        let before_root = state.state_root().unwrap();

        let valid_transfer = AssetOperation::Transfer {
            asset_id,
            recipient: BOB,
            amount: 100,
        };
        let invalid_transfer = AssetOperation::Transfer {
            asset_id,
            recipient: BOB,
            amount: 10_000_000,
        };
        let encoded = vec![
            encode_operation(&valid_transfer).unwrap(),
            encode_operation(&invalid_transfer).unwrap(),
        ];
        assert!(state
            .apply_encoded_batch(&ALICE, &encoded, limits())
            .is_err());
        assert_eq!(state, before);
        assert_eq!(state.state_root().unwrap(), before_root);

        state
            .apply_operation(&ALICE, &valid_transfer, limits())
            .unwrap();
        let branch_root = state.state_root().unwrap();
        assert_ne!(before_root, branch_root);
        state.rollback_to(&before).unwrap();
        assert_eq!(state.state_root().unwrap(), before_root);
    }

    #[test]
    fn freeze_blocks_mint_transfer_and_burn_but_unfreeze_restores_flow() {
        let mut state = AssetStateCandidate::genesis(NETWORK).unwrap();
        state.advance_height(20).unwrap();
        let create = create_op(definition(ALICE, 3, "CA3"));
        state.apply_operation(&ALICE, &create, limits()).unwrap();
        let asset_id = if let AssetOperation::Create { ref definition } = create {
            crate::token_forge::asset_id(definition).unwrap()
        } else {
            unreachable!()
        };

        state
            .apply_operation(
                &ALICE,
                &AssetOperation::Freeze {
                    asset_id,
                    frozen: true,
                },
                limits(),
            )
            .unwrap();

        for operation in [
            AssetOperation::Mint {
                asset_id,
                amount: 1,
            },
            AssetOperation::Transfer {
                asset_id,
                recipient: BOB,
                amount: 1,
            },
            AssetOperation::Burn {
                asset_id,
                amount: 1,
            },
        ] {
            assert!(state.apply_operation(&ALICE, &operation, limits()).is_err());
        }

        state
            .apply_operation(
                &ALICE,
                &AssetOperation::Freeze {
                    asset_id,
                    frozen: false,
                },
                limits(),
            )
            .unwrap();
        state
            .apply_operation(
                &ALICE,
                &AssetOperation::Transfer {
                    asset_id,
                    recipient: BOB,
                    amount: 25,
                },
                limits(),
            )
            .unwrap();
        assert_eq!(state.balance(&asset_id, &BOB), 25);
        state.verify_invariants().unwrap();
    }

    #[test]
    fn deterministic_root_is_independent_of_operation_insertion_order() {
        let def_a = definition(ALICE, 4, "A4");
        let def_b = definition(ALICE, 5, "B5");
        let create_a = create_op(def_a.clone());
        let create_b = create_op(def_b.clone());

        let mut first = AssetStateCandidate::genesis(NETWORK).unwrap();
        first.advance_height(50).unwrap();
        first
            .apply_encoded_batch(
                &ALICE,
                &[
                    encode_operation(&create_a).unwrap(),
                    encode_operation(&create_b).unwrap(),
                ],
                limits(),
            )
            .unwrap();

        let mut second = AssetStateCandidate::genesis(NETWORK).unwrap();
        second.advance_height(50).unwrap();
        second
            .apply_encoded_batch(
                &ALICE,
                &[
                    encode_operation(&create_b).unwrap(),
                    encode_operation(&create_a).unwrap(),
                ],
                limits(),
            )
            .unwrap();

        assert_eq!(first.state_root().unwrap(), second.state_root().unwrap());
        assert_eq!(
            first.encode_snapshot().unwrap(),
            second.encode_snapshot().unwrap()
        );
    }

    #[test]
    fn snapshot_roundtrip_tamper_and_noncanonical_order_are_fail_closed() {
        let mut state = AssetStateCandidate::genesis(NETWORK).unwrap();
        state.advance_height(77).unwrap();
        let create = create_op(definition(ALICE, 6, "S77"));
        state.apply_operation(&ALICE, &create, limits()).unwrap();
        let asset_id = if let AssetOperation::Create { ref definition } = create {
            crate::token_forge::asset_id(definition).unwrap()
        } else {
            unreachable!()
        };
        state
            .apply_operation(
                &ALICE,
                &AssetOperation::Transfer {
                    asset_id,
                    recipient: BOB,
                    amount: 250,
                },
                limits(),
            )
            .unwrap();

        let snapshot = state.encode_snapshot().unwrap();
        let restored = AssetStateCandidate::decode_snapshot(&snapshot, &NETWORK).unwrap();
        assert_eq!(restored, state);
        assert_eq!(restored.encode_snapshot().unwrap(), snapshot);
        assert_eq!(restored.state_root().unwrap(), state.state_root().unwrap());

        let mut tampered = snapshot.clone();
        tampered[10] ^= 1;
        assert_eq!(
            AssetStateCandidate::decode_snapshot(&tampered, &NETWORK).unwrap_err(),
            AssetStateCandidateError::SnapshotChecksumMismatch
        );

        let mut bad_version = snapshot.clone();
        bad_version[4..6].copy_from_slice(&2u16.to_be_bytes());
        let new_checksum = hash_domain(
            ASSET_STATE_CHECKSUM_DOMAIN,
            &bad_version[..bad_version.len() - CHECKSUM_LEN],
        );
        let len = bad_version.len();
        bad_version[len - CHECKSUM_LEN..].copy_from_slice(&new_checksum);
        assert_eq!(
            AssetStateCandidate::decode_snapshot(&bad_version, &NETWORK).unwrap_err(),
            AssetStateCandidateError::UnsupportedSnapshotVersion(2)
        );

        let mut noncanonical = snapshot.clone();
        // One-asset snapshot cannot reorder registry records; flip the sole asset ID and
        // recompute its definition-derived identity, so the decoder reaches the identity check.
        noncanonical[SNAPSHOT_HEADER_LEN] ^= 1;
        let checksum = hash_domain(
            ASSET_STATE_CHECKSUM_DOMAIN,
            &noncanonical[..noncanonical.len() - CHECKSUM_LEN],
        );
        let len = noncanonical.len();
        noncanonical[len - CHECKSUM_LEN..].copy_from_slice(&checksum);
        assert!(matches!(
            AssetStateCandidate::decode_snapshot(&noncanonical, &NETWORK),
            Err(AssetStateCandidateError::AssetIdMismatch)
                | Err(AssetStateCandidateError::SnapshotNonCanonical)
        ));
    }

    #[test]
    fn state_growth_is_bounded_by_explicit_candidate_limits() {
        let mut state = AssetStateCandidate::genesis(NETWORK).unwrap();
        state.advance_height(100).unwrap();
        let tight = CandidateResourceLimits {
            max_operations: 4,
            max_operation_bytes: 2048,
            max_assets: 2,
            max_holdings: 2,
        };

        for nonce in 1..=2 {
            state
                .apply_operation(&ALICE, &create_op(definition(ALICE, nonce, "LIM")), tight)
                .unwrap();
        }
        let third = create_op(definition(ALICE, 3, "LIM"));
        assert!(matches!(
            state.apply_operation(&ALICE, &third, tight),
            Err(AssetStateCandidateError::TooManyAssets(_))
        ));
        assert_eq!(state.asset_count(), 2);

        let second_def = definition(ALICE, 2, "LIM");
        let second_asset = crate::token_forge::asset_id(&second_def).unwrap();
        assert!(state.balance(&second_asset, &ALICE) > 0);
    }

    #[test]
    fn snapshot_bitflip_campaign_and_malformed_lengths_fail_closed() {
        let mut state = AssetStateCandidate::genesis(NETWORK).unwrap();
        state.advance_height(90).unwrap();
        let create = create_op(definition(ALICE, 90, "FUZ"));
        state.apply_operation(&ALICE, &create, limits()).unwrap();
        let asset_id = if let AssetOperation::Create { ref definition } = create {
            crate::token_forge::asset_id(definition).unwrap()
        } else {
            unreachable!()
        };
        state
            .apply_operation(
                &ALICE,
                &AssetOperation::Transfer {
                    asset_id,
                    recipient: BOB,
                    amount: 321,
                },
                limits(),
            )
            .unwrap();
        let snapshot = state.encode_snapshot().unwrap();

        for index in 0..snapshot.len() {
            for bit in 0..8 {
                let mut mutated = snapshot.clone();
                mutated[index] ^= 1u8 << bit;
                let result = AssetStateCandidate::decode_snapshot(&mutated, &NETWORK);
                assert!(
                    result.is_err(),
                    "bit-flipped snapshot unexpectedly decoded: index={index}, bit={bit}"
                );
            }
        }

        for truncated_len in 0..=snapshot.len().min(32) {
            assert!(
                AssetStateCandidate::decode_snapshot(&snapshot[..truncated_len], &NETWORK).is_err()
            );
        }

        let mut huge_counts = snapshot.clone();
        huge_counts[46..50].copy_from_slice(&u32::MAX.to_be_bytes());
        let checksum = hash_domain(
            ASSET_STATE_CHECKSUM_DOMAIN,
            &huge_counts[..huge_counts.len() - CHECKSUM_LEN],
        );
        let len = huge_counts.len();
        huge_counts[len - CHECKSUM_LEN..].copy_from_slice(&checksum);
        assert!(AssetStateCandidate::decode_snapshot(&huge_counts, &NETWORK).is_err());
    }

    #[test]
    fn canonical_snapshot_bytes_and_root_have_stable_known_fixture() {
        let mut state = AssetStateCandidate::genesis(NETWORK).unwrap();
        state.advance_height(9).unwrap();
        let create = create_op(definition(ALICE, 9, "VEC"));
        state.apply_operation(&ALICE, &create, limits()).unwrap();
        let asset_id = if let AssetOperation::Create { ref definition } = create {
            crate::token_forge::asset_id(definition).unwrap()
        } else {
            unreachable!()
        };
        state
            .apply_operation(
                &ALICE,
                &AssetOperation::Transfer {
                    asset_id,
                    recipient: BOB,
                    amount: 123,
                },
                limits(),
            )
            .unwrap();
        println!(
            "ASSET_STATE_VECTOR_ROOT={}",
            hex(&state.state_root().unwrap())
        );
        println!(
            "ASSET_STATE_VECTOR_SNAPSHOT={}",
            hex(&state.encode_snapshot().unwrap())
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
