//! Native Token Forge primitive for CP-W.
//!
//! Research/testbed only. This module deliberately implements assets as a small,
//! deterministic base-layer primitive rather than as arbitrary smart-contract code.
//! It is not yet wired into canonical transaction/block wire format or mainnet
//! activation. That separation keeps the initial attack surface bounded.
//!
//! Design goals:
//! - deterministic AssetId and canonical asset-definition bytes;
//! - permissionless creation with explicit issuer powers;
//! - fixed, capped, or height-scheduled supply;
//! - explicit mint/burn/freeze semantics;
//! - bounded metadata and resource accounting to resist state-bloat spam;
//! - fail-closed arithmetic and no implicit administrative backdoors.

use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{Cursor, Read},
};

pub type AccountId = [u8; 32];
pub type NetworkId = [u8; 32];
pub type AssetId = [u8; 32];

pub const ASSET_MAGIC: [u8; 4] = *b"AST1";
pub const ASSET_VERSION: u16 = 1;
pub const ASSET_ID_DOMAIN: &[u8] = b"AIN1-ASSET-ID-V1\0";
pub const ASSET_RESOURCE_DOMAIN: &[u8] = b"AIN1-ASSET-RESOURCE-V1\0";

pub const MAX_ASSET_NAME_BYTES: usize = 32;
pub const MAX_ASSET_SYMBOL_BYTES: usize = 16;
pub const MAX_ASSET_METADATA_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupplyPolicy {
    Fixed {
        initial_supply: u128,
    },
    Capped {
        initial_supply: u128,
        max_supply: u128,
    },
    Scheduled {
        initial_supply: u128,
        max_supply: u128,
        period_blocks: u64,
        emission_per_period: u128,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MintAuthority {
    Immutable,
    Creator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BurnAuthority {
    Holder,
    Creator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreezePolicy {
    None,
    Creator,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetDefinition {
    pub network_id: NetworkId,
    pub creator: AccountId,
    /// Creator-local monotonic nonce. The nonce is part of AssetId derivation.
    pub creation_nonce: u64,
    /// UTF-8 bytes, normalized by the caller before construction. The primitive only
    /// validates UTF-8 and byte length; it does not silently transform user strings.
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub metadata_hash: [u8; 32],
    pub supply_policy: SupplyPolicy,
    pub mint_authority: MintAuthority,
    pub burn_authority: BurnAuthority,
    pub freeze_policy: FreezePolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetState {
    pub definition: AssetDefinition,
    pub total_supply: u128,
    pub frozen: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceQuote {
    pub encoded_definition_bytes: usize,
    pub metadata_bytes: usize,
    pub state_bytes: usize,
    pub resource_units: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenForgeError {
    ZeroNetworkId,
    ZeroCreator,
    InvalidName,
    InvalidSymbol,
    NameTooLong(usize),
    SymbolTooLong(usize),
    MetadataTooLarge(usize),
    InvalidDecimals,
    InvalidSupplyPolicy,
    InvalidPeriod,
    ZeroEmission,
    DuplicateAsset,
    UnknownAsset,
    UnauthorizedMint,
    UnauthorizedBurn,
    UnauthorizedFreeze,
    AssetFrozen,
    SupplyOverflow,
    SupplyCapExceeded { requested: u128, allowed: u128 },
    ScheduledSupplyNotAvailable { height: u64, allowed: u128 },
    HolderBalanceOverflow,
    HolderInsufficientBalance,
    ResourceOverflow,
    BadMagic,
    UnsupportedVersion(u16),
    InvalidAuthority(u8),
    NonCanonicalDefinition,
    TrailingBytes,
}

impl std::fmt::Display for TokenForgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroNetworkId => write!(f, "network ID must not be all zero"),
            Self::ZeroCreator => write!(f, "creator account must not be all zero"),
            Self::InvalidName => write!(f, "asset name must be non-empty UTF-8"),
            Self::InvalidSymbol => write!(f, "asset symbol must be non-empty UTF-8"),
            Self::NameTooLong(n) => write!(
                f,
                "asset name is {n} bytes; maximum is {MAX_ASSET_NAME_BYTES}"
            ),
            Self::SymbolTooLong(n) => write!(
                f,
                "asset symbol is {n} bytes; maximum is {MAX_ASSET_SYMBOL_BYTES}"
            ),
            Self::MetadataTooLarge(n) => write!(
                f,
                "metadata commitment payload is {n} bytes; maximum is {MAX_ASSET_METADATA_BYTES}"
            ),
            Self::InvalidDecimals => write!(f, "decimals must be <= 18"),
            Self::InvalidSupplyPolicy => write!(f, "supply policy parameters are inconsistent"),
            Self::InvalidPeriod => write!(f, "scheduled emission period must be positive"),
            Self::ZeroEmission => write!(f, "scheduled emission must be positive"),
            Self::DuplicateAsset => write!(f, "asset ID already exists"),
            Self::UnknownAsset => write!(f, "unknown asset"),
            Self::UnauthorizedMint => write!(f, "caller is not authorized to mint"),
            Self::UnauthorizedBurn => write!(f, "caller is not authorized to burn"),
            Self::UnauthorizedFreeze => write!(f, "caller is not authorized to freeze or unfreeze"),
            Self::AssetFrozen => write!(f, "asset is frozen"),
            Self::SupplyOverflow => write!(f, "asset supply arithmetic overflowed"),
            Self::SupplyCapExceeded { requested, allowed } => write!(
                f,
                "requested supply {requested} exceeds allowed supply {allowed}"
            ),
            Self::ScheduledSupplyNotAvailable { height, allowed } => write!(
                f,
                "scheduled supply is not available at height {height}; allowed total is {allowed}"
            ),
            Self::HolderBalanceOverflow => write!(f, "holder balance arithmetic overflowed"),
            Self::HolderInsufficientBalance => write!(f, "holder balance is insufficient"),
            Self::ResourceOverflow => write!(f, "resource accounting overflowed"),
            Self::BadMagic => write!(f, "bad asset definition magic"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported asset definition version {version}")
            }
            Self::InvalidAuthority(value) => {
                write!(f, "invalid asset authority value {value}")
            }
            Self::NonCanonicalDefinition => write!(f, "asset definition is not canonical"),
            Self::TrailingBytes => write!(f, "asset definition has trailing bytes"),
        }
    }
}

impl std::error::Error for TokenForgeError {}

fn nonzero_32(value: &[u8; 32]) -> bool {
    value.iter().any(|byte| *byte != 0)
}

fn checked_string_bytes(value: &str, max: usize) -> Result<usize, TokenForgeError> {
    if value.is_empty() || value.as_bytes().is_empty() {
        return Err(TokenForgeError::InvalidName);
    }
    if value.len() > max {
        return Err(TokenForgeError::NameTooLong(value.len()));
    }
    if !value.is_ascii() {
        // Keep the first primitive deliberately ASCII-only. A later version can
        // standardize Unicode normalization without making existing IDs ambiguous.
        return Err(TokenForgeError::InvalidName);
    }
    Ok(value.len())
}

fn validate_definition(definition: &AssetDefinition) -> Result<(), TokenForgeError> {
    if !nonzero_32(&definition.network_id) {
        return Err(TokenForgeError::ZeroNetworkId);
    }
    if !nonzero_32(&definition.creator) {
        return Err(TokenForgeError::ZeroCreator);
    }
    checked_string_bytes(&definition.name, MAX_ASSET_NAME_BYTES)?;
    if definition.symbol.is_empty() {
        return Err(TokenForgeError::InvalidSymbol);
    }
    if definition.symbol.len() > MAX_ASSET_SYMBOL_BYTES {
        return Err(TokenForgeError::SymbolTooLong(definition.symbol.len()));
    }
    if !definition.symbol.is_ascii() {
        return Err(TokenForgeError::InvalidSymbol);
    }
    if definition.decimals > 18 {
        return Err(TokenForgeError::InvalidDecimals);
    }

    match definition.supply_policy {
        SupplyPolicy::Fixed { initial_supply } => {
            if initial_supply == 0 {
                return Err(TokenForgeError::InvalidSupplyPolicy);
            }
        }
        SupplyPolicy::Capped {
            initial_supply,
            max_supply,
        } => {
            if initial_supply == 0 || max_supply == 0 || initial_supply > max_supply {
                return Err(TokenForgeError::InvalidSupplyPolicy);
            }
        }
        SupplyPolicy::Scheduled {
            initial_supply,
            max_supply,
            period_blocks,
            emission_per_period,
        } => {
            if initial_supply == 0 || max_supply == 0 || initial_supply > max_supply {
                return Err(TokenForgeError::InvalidSupplyPolicy);
            }
            if period_blocks == 0 {
                return Err(TokenForgeError::InvalidPeriod);
            }
            if emission_per_period == 0 {
                return Err(TokenForgeError::ZeroEmission);
            }
        }
    }
    Ok(())
}

fn write_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_u128(out: &mut Vec<u8>, value: u128) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn policy_tag(policy: SupplyPolicy) -> u8 {
    match policy {
        SupplyPolicy::Fixed { .. } => 0,
        SupplyPolicy::Capped { .. } => 1,
        SupplyPolicy::Scheduled { .. } => 2,
    }
}

/// Canonical bytes used for the AssetId and for future wire-format integration.
pub fn encode_definition(definition: &AssetDefinition) -> Result<Vec<u8>, TokenForgeError> {
    validate_definition(definition)?;
    let name_len = u8::try_from(definition.name.len())
        .map_err(|_| TokenForgeError::NameTooLong(definition.name.len()))?;
    let symbol_len = u8::try_from(definition.symbol.len())
        .map_err(|_| TokenForgeError::SymbolTooLong(definition.symbol.len()))?;

    let mut out = Vec::with_capacity(
        4 + 2
            + 32
            + 32
            + 8
            + 1
            + name_len as usize
            + 1
            + symbol_len as usize
            + 1
            + 32
            + 1
            + 1
            + 1
            + 1
            + 16 * 3
            + 8
            + 16,
    );
    out.extend_from_slice(&ASSET_MAGIC);
    write_u16(&mut out, ASSET_VERSION);
    out.extend_from_slice(&definition.network_id);
    out.extend_from_slice(&definition.creator);
    write_u64(&mut out, definition.creation_nonce);
    out.push(name_len);
    out.extend_from_slice(definition.name.as_bytes());
    out.push(symbol_len);
    out.extend_from_slice(definition.symbol.as_bytes());
    out.push(definition.decimals);
    out.extend_from_slice(&definition.metadata_hash);

    out.push(policy_tag(definition.supply_policy));
    match definition.supply_policy {
        SupplyPolicy::Fixed { initial_supply } => {
            write_u128(&mut out, initial_supply);
        }
        SupplyPolicy::Capped {
            initial_supply,
            max_supply,
        } => {
            write_u128(&mut out, initial_supply);
            write_u128(&mut out, max_supply);
        }
        SupplyPolicy::Scheduled {
            initial_supply,
            max_supply,
            period_blocks,
            emission_per_period,
        } => {
            write_u128(&mut out, initial_supply);
            write_u128(&mut out, max_supply);
            write_u64(&mut out, period_blocks);
            write_u128(&mut out, emission_per_period);
        }
    }

    out.push(definition.mint_authority as u8);
    out.push(definition.burn_authority as u8);
    out.push(definition.freeze_policy as u8);
    Ok(out)
}

/// Decode the canonical asset definition and reject any byte-level alternate encoding.
pub fn decode_definition(bytes: &[u8]) -> Result<AssetDefinition, TokenForgeError> {
    if bytes.len() > MAX_ASSET_METADATA_BYTES {
        return Err(TokenForgeError::MetadataTooLarge(bytes.len()));
    }
    if bytes.len() < 6 {
        return Err(TokenForgeError::NonCanonicalDefinition);
    }

    let mut cursor = Cursor::new(bytes);
    let magic = read_array::<4>(&mut cursor)?;
    if magic != ASSET_MAGIC {
        return Err(TokenForgeError::BadMagic);
    }
    let version = read_u16(&mut cursor)?;
    if version != ASSET_VERSION {
        return Err(TokenForgeError::UnsupportedVersion(version));
    }

    let network_id = read_array::<32>(&mut cursor)?;
    let creator = read_array::<32>(&mut cursor)?;
    let creation_nonce = read_u64(&mut cursor)?;

    let name_len = read_u8(&mut cursor)? as usize;
    let name_bytes = read_vec(&mut cursor, name_len)?;
    let name = std::str::from_utf8(&name_bytes)
        .map_err(|_| TokenForgeError::InvalidName)?
        .to_owned();

    let symbol_len = read_u8(&mut cursor)? as usize;
    let symbol_bytes = read_vec(&mut cursor, symbol_len)?;
    let symbol = std::str::from_utf8(&symbol_bytes)
        .map_err(|_| TokenForgeError::InvalidSymbol)?
        .to_owned();

    let decimals = read_u8(&mut cursor)?;
    let metadata_hash = read_array::<32>(&mut cursor)?;

    let supply_policy = match read_u8(&mut cursor)? {
        0 => SupplyPolicy::Fixed {
            initial_supply: read_u128(&mut cursor)?,
        },
        1 => SupplyPolicy::Capped {
            initial_supply: read_u128(&mut cursor)?,
            max_supply: read_u128(&mut cursor)?,
        },
        2 => SupplyPolicy::Scheduled {
            initial_supply: read_u128(&mut cursor)?,
            max_supply: read_u128(&mut cursor)?,
            period_blocks: read_u64(&mut cursor)?,
            emission_per_period: read_u128(&mut cursor)?,
        },
        _ => return Err(TokenForgeError::InvalidSupplyPolicy),
    };

    let mint_authority = match read_u8(&mut cursor)? {
        0 => MintAuthority::Immutable,
        1 => MintAuthority::Creator,
        value => return Err(TokenForgeError::InvalidAuthority(value)),
    };
    let burn_authority = match read_u8(&mut cursor)? {
        0 => BurnAuthority::Holder,
        1 => BurnAuthority::Creator,
        value => return Err(TokenForgeError::InvalidAuthority(value)),
    };
    let freeze_policy = match read_u8(&mut cursor)? {
        0 => FreezePolicy::None,
        1 => FreezePolicy::Creator,
        value => return Err(TokenForgeError::InvalidAuthority(value)),
    };

    if cursor.position() as usize != bytes.len() {
        return Err(TokenForgeError::TrailingBytes);
    }

    let definition = AssetDefinition {
        network_id,
        creator,
        creation_nonce,
        name,
        symbol,
        decimals,
        metadata_hash,
        supply_policy,
        mint_authority,
        burn_authority,
        freeze_policy,
    };
    definition.validate()?;

    if encode_definition(&definition)? != bytes {
        return Err(TokenForgeError::NonCanonicalDefinition);
    }
    Ok(definition)
}

fn read_array<const N: usize>(cursor: &mut Cursor<&[u8]>) -> Result<[u8; N], TokenForgeError> {
    let mut value = [0u8; N];
    cursor
        .read_exact(&mut value)
        .map_err(|_| TokenForgeError::NonCanonicalDefinition)?;
    Ok(value)
}

fn read_u8(cursor: &mut Cursor<&[u8]>) -> Result<u8, TokenForgeError> {
    Ok(read_array::<1>(cursor)?[0])
}

fn read_u16(cursor: &mut Cursor<&[u8]>) -> Result<u16, TokenForgeError> {
    Ok(u16::from_be_bytes(read_array(cursor)?))
}

fn read_u64(cursor: &mut Cursor<&[u8]>) -> Result<u64, TokenForgeError> {
    Ok(u64::from_be_bytes(read_array(cursor)?))
}

fn read_u128(cursor: &mut Cursor<&[u8]>) -> Result<u128, TokenForgeError> {
    Ok(u128::from_be_bytes(read_array(cursor)?))
}

fn read_vec(cursor: &mut Cursor<&[u8]>, len: usize) -> Result<Vec<u8>, TokenForgeError> {
    let mut value = vec![0u8; len];
    cursor
        .read_exact(&mut value)
        .map_err(|_| TokenForgeError::NonCanonicalDefinition)?;
    Ok(value)
}

pub fn asset_id(definition: &AssetDefinition) -> Result<AssetId, TokenForgeError> {
    let canonical = encode_definition(definition)?;
    let mut hash = Sha256::new();
    hash.update(ASSET_ID_DOMAIN);
    hash.update(&canonical);
    Ok(hash.finalize().into())
}

/// Calculate the total supply permitted by a policy at a block height, independent of
/// current state. This is used both by validators and by simulation/reference tests.
pub fn allowed_supply_at_height(
    policy: SupplyPolicy,
    height: u64,
) -> Result<u128, TokenForgeError> {
    match policy {
        SupplyPolicy::Fixed { initial_supply } => Ok(initial_supply),
        SupplyPolicy::Capped { max_supply, .. } => Ok(max_supply),
        SupplyPolicy::Scheduled {
            initial_supply,
            max_supply,
            period_blocks,
            emission_per_period,
        } => {
            let periods = height / period_blocks;
            let incremental = (periods as u128)
                .checked_mul(emission_per_period)
                .ok_or(TokenForgeError::SupplyOverflow)?;
            initial_supply
                .checked_add(incremental)
                .map(|value| value.min(max_supply))
                .ok_or(TokenForgeError::SupplyOverflow)
        }
    }
}

impl AssetDefinition {
    pub fn validate(&self) -> Result<(), TokenForgeError> {
        validate_definition(self)
    }

    pub fn initial_supply(&self) -> u128 {
        match self.supply_policy {
            SupplyPolicy::Fixed { initial_supply }
            | SupplyPolicy::Capped { initial_supply, .. }
            | SupplyPolicy::Scheduled { initial_supply, .. } => initial_supply,
        }
    }
}

impl AssetState {
    pub fn new(definition: AssetDefinition) -> Result<Self, TokenForgeError> {
        definition.validate()?;
        Ok(Self {
            total_supply: definition.initial_supply(),
            definition,
            frozen: false,
        })
    }

    pub fn asset_id(&self) -> Result<AssetId, TokenForgeError> {
        asset_id(&self.definition)
    }

    pub fn mint_limit_at_height(&self, height: u64) -> Result<u128, TokenForgeError> {
        allowed_supply_at_height(self.definition.supply_policy, height)
    }

    pub fn can_mint(
        &self,
        caller: &AccountId,
        amount: u128,
        height: u64,
    ) -> Result<(), TokenForgeError> {
        if self.frozen {
            return Err(TokenForgeError::AssetFrozen);
        }
        if amount == 0 {
            return Err(TokenForgeError::SupplyOverflow);
        }
        if self.definition.mint_authority != MintAuthority::Creator
            || self.definition.creator != *caller
        {
            return Err(TokenForgeError::UnauthorizedMint);
        }
        let allowed = self.mint_limit_at_height(height)?;
        let requested = self
            .total_supply
            .checked_add(amount)
            .ok_or(TokenForgeError::SupplyOverflow)?;
        if requested > allowed {
            return Err(TokenForgeError::SupplyCapExceeded { requested, allowed });
        }
        Ok(())
    }

    pub fn mint(
        &mut self,
        caller: &AccountId,
        amount: u128,
        height: u64,
    ) -> Result<(), TokenForgeError> {
        self.can_mint(caller, amount, height)?;
        self.total_supply = self
            .total_supply
            .checked_add(amount)
            .ok_or(TokenForgeError::SupplyOverflow)?;
        Ok(())
    }

    pub fn burn_from_holder(
        &mut self,
        caller: &AccountId,
        holder_balance: &mut u128,
        amount: u128,
    ) -> Result<(), TokenForgeError> {
        if self.definition.burn_authority != BurnAuthority::Holder
            && self.definition.burn_authority != BurnAuthority::Creator
        {
            return Err(TokenForgeError::UnauthorizedBurn);
        }
        if self.definition.burn_authority == BurnAuthority::Creator
            && self.definition.creator != *caller
        {
            return Err(TokenForgeError::UnauthorizedBurn);
        }
        if amount == 0 || *holder_balance < amount || self.total_supply < amount {
            return Err(TokenForgeError::HolderInsufficientBalance);
        }
        *holder_balance -= amount;
        self.total_supply -= amount;
        Ok(())
    }

    pub fn freeze(&mut self, caller: &AccountId) -> Result<(), TokenForgeError> {
        if self.definition.freeze_policy != FreezePolicy::Creator
            || self.definition.creator != *caller
        {
            return Err(TokenForgeError::UnauthorizedFreeze);
        }
        self.frozen = true;
        Ok(())
    }

    pub fn unfreeze(&mut self, caller: &AccountId) -> Result<(), TokenForgeError> {
        if self.definition.freeze_policy != FreezePolicy::Creator
            || self.definition.creator != *caller
        {
            return Err(TokenForgeError::UnauthorizedFreeze);
        }
        self.frozen = false;
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AssetRegistry {
    assets: BTreeMap<AssetId, AssetState>,
}

impl AssetRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn create(&mut self, definition: AssetDefinition) -> Result<AssetId, TokenForgeError> {
        let state = AssetState::new(definition)?;
        let id = state.asset_id()?;
        if self.assets.contains_key(&id) {
            return Err(TokenForgeError::DuplicateAsset);
        }
        self.assets.insert(id, state);
        Ok(id)
    }

    pub fn get(&self, id: &AssetId) -> Result<&AssetState, TokenForgeError> {
        self.assets.get(id).ok_or(TokenForgeError::UnknownAsset)
    }

    pub fn get_mut(&mut self, id: &AssetId) -> Result<&mut AssetState, TokenForgeError> {
        self.assets.get_mut(id).ok_or(TokenForgeError::UnknownAsset)
    }

    pub fn contains(&self, id: &AssetId) -> bool {
        self.assets.contains_key(id)
    }

    pub fn len(&self) -> usize {
        self.assets.len()
    }

    /// Deterministic AssetId order for candidate state-root/snapshot integration.
    pub fn iter(&self) -> impl Iterator<Item = (&AssetId, &AssetState)> {
        self.assets.iter()
    }
}

/// Deterministic resource estimate. This is intentionally independent of fee pricing:
/// consensus can later multiply resource_units by a network fee schedule without changing
/// the asset identity or semantics.
pub fn resource_quote(definition: &AssetDefinition) -> Result<ResourceQuote, TokenForgeError> {
    let encoded = encode_definition(definition)?;
    let metadata_bytes = 32usize; // only the fixed commitment is stored on-chain
    let state_bytes = encoded
        .len()
        .checked_add(64)
        .ok_or(TokenForgeError::ResourceOverflow)?;
    let resource_units = u64::try_from(
        (encoded.len() as u128)
            .checked_add(metadata_bytes as u128)
            .and_then(|v| v.checked_add(state_bytes as u128))
            .ok_or(TokenForgeError::ResourceOverflow)?,
    )
    .map_err(|_| TokenForgeError::ResourceOverflow)?;
    Ok(ResourceQuote {
        encoded_definition_bytes: encoded.len(),
        metadata_bytes,
        state_bytes,
        resource_units,
    })
}

pub fn metadata_commitment(payload: &[u8]) -> Result<[u8; 32], TokenForgeError> {
    if payload.len() > MAX_ASSET_METADATA_BYTES {
        return Err(TokenForgeError::MetadataTooLarge(payload.len()));
    }
    let mut hash = Sha256::new();
    hash.update(ASSET_RESOURCE_DOMAIN);
    hash.update(payload);
    Ok(hash.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NETWORK: NetworkId = [0x11; 32];
    const CREATOR: AccountId = [0x22; 32];
    const OTHER: AccountId = [0x33; 32];

    fn definition(policy: SupplyPolicy) -> AssetDefinition {
        AssetDefinition {
            network_id: NETWORK,
            creator: CREATOR,
            creation_nonce: 7,
            name: "SafeWork Credit".to_owned(),
            symbol: "SWC".to_owned(),
            decimals: 8,
            metadata_hash: [0x44; 32],
            supply_policy: policy,
            mint_authority: MintAuthority::Creator,
            burn_authority: BurnAuthority::Holder,
            freeze_policy: FreezePolicy::Creator,
        }
    }

    #[test]
    fn deterministic_asset_id_binds_network_creator_nonce_and_policy() {
        let base = definition(SupplyPolicy::Capped {
            initial_supply: 1_000,
            max_supply: 10_000,
        });
        let id_a = asset_id(&base).unwrap();

        let mut network_variant = base.clone();
        network_variant.network_id = [0x55; 32];
        assert_ne!(id_a, asset_id(&network_variant).unwrap());

        let mut nonce_variant = base.clone();
        nonce_variant.creation_nonce += 1;
        assert_ne!(id_a, asset_id(&nonce_variant).unwrap());

        let mut supply_variant = base;
        supply_variant.supply_policy = SupplyPolicy::Capped {
            initial_supply: 1_000,
            max_supply: 20_000,
        };
        assert_ne!(id_a, asset_id(&supply_variant).unwrap());
    }

    #[test]
    fn fixed_asset_cannot_mint_after_creation() {
        let definition = definition(SupplyPolicy::Fixed {
            initial_supply: 1_000,
        });
        let mut state = AssetState::new(definition).unwrap();
        assert_eq!(state.total_supply, 1_000);
        assert_eq!(
            state.mint(&CREATOR, 1, 0),
            Err(TokenForgeError::SupplyCapExceeded {
                requested: 1_001,
                allowed: 1_000
            })
        );
    }

    #[test]
    fn capped_asset_mint_is_authorized_and_bounded() {
        let mut state = AssetState::new(definition(SupplyPolicy::Capped {
            initial_supply: 100,
            max_supply: 200,
        }))
        .unwrap();
        state.mint(&CREATOR, 50, 1).unwrap();
        assert_eq!(state.total_supply, 150);
        assert_eq!(
            state.mint(&OTHER, 1, 1),
            Err(TokenForgeError::UnauthorizedMint)
        );
        assert_eq!(
            state.mint(&CREATOR, 51, 1),
            Err(TokenForgeError::SupplyCapExceeded {
                requested: 201,
                allowed: 200
            })
        );
    }

    #[test]
    fn scheduled_supply_is_height_deterministic_and_capped() {
        let policy = SupplyPolicy::Scheduled {
            initial_supply: 100,
            max_supply: 250,
            period_blocks: 10,
            emission_per_period: 30,
        };
        assert_eq!(allowed_supply_at_height(policy, 0).unwrap(), 100);
        assert_eq!(allowed_supply_at_height(policy, 9).unwrap(), 100);
        assert_eq!(allowed_supply_at_height(policy, 10).unwrap(), 130);
        assert_eq!(allowed_supply_at_height(policy, 40).unwrap(), 220);
        assert_eq!(allowed_supply_at_height(policy, 60).unwrap(), 250);

        let mut state = AssetState::new(definition(policy)).unwrap();
        assert_eq!(
            state.mint(&CREATOR, 31, 10),
            Err(TokenForgeError::SupplyCapExceeded {
                requested: 131,
                allowed: 130
            })
        );
        state.mint(&CREATOR, 30, 10).unwrap();
        assert_eq!(state.total_supply, 130);
    }

    #[test]
    fn burn_authority_and_holder_balance_are_checked() {
        let mut state = AssetState::new(definition(SupplyPolicy::Capped {
            initial_supply: 1_000,
            max_supply: 2_000,
        }))
        .unwrap();
        let mut holder_balance = 200u128;
        state
            .burn_from_holder(&CREATOR, &mut holder_balance, 50)
            .unwrap();
        assert_eq!(holder_balance, 150);
        assert_eq!(state.total_supply, 950);

        assert_eq!(
            state.burn_from_holder(&OTHER, &mut holder_balance, 151),
            Err(TokenForgeError::HolderInsufficientBalance)
        );
        assert_eq!(holder_balance, 150);
    }

    #[test]
    fn freeze_is_explicit_and_blocks_mint_but_can_unfreeze() {
        let mut state = AssetState::new(definition(SupplyPolicy::Capped {
            initial_supply: 100,
            max_supply: 200,
        }))
        .unwrap();
        state.freeze(&CREATOR).unwrap();
        assert_eq!(
            state.mint(&CREATOR, 1, 0),
            Err(TokenForgeError::AssetFrozen)
        );
        assert_eq!(
            state.freeze(&OTHER),
            Err(TokenForgeError::UnauthorizedFreeze)
        );
        state.unfreeze(&CREATOR).unwrap();
        state.mint(&CREATOR, 1, 0).unwrap();
        assert_eq!(state.total_supply, 101);
    }

    #[test]
    fn canonical_definition_is_stable_and_resource_quote_is_bounded() {
        let definition = definition(SupplyPolicy::Scheduled {
            initial_supply: 100,
            max_supply: 10_000,
            period_blocks: 100,
            emission_per_period: 25,
        });
        let encoded_a = encode_definition(&definition).unwrap();
        let encoded_b = encode_definition(&definition).unwrap();
        assert_eq!(encoded_a, encoded_b);

        let quote = resource_quote(&definition).unwrap();
        assert!(quote.encoded_definition_bytes > 0);
        assert!(quote.resource_units >= quote.state_bytes as u64);

        let commitment = metadata_commitment(b"example metadata");
        assert_ne!(commitment.unwrap(), [0; 32]);
        assert_eq!(
            metadata_commitment(&vec![0u8; MAX_ASSET_METADATA_BYTES + 1]),
            Err(TokenForgeError::MetadataTooLarge(
                MAX_ASSET_METADATA_BYTES + 1
            ))
        );
    }

    #[test]
    fn registry_rejects_duplicate_asset_ids_and_unknown_lookup() {
        let definition = definition(SupplyPolicy::Fixed { initial_supply: 1 });
        let mut registry = AssetRegistry::new();
        let id = registry.create(definition.clone()).unwrap();
        assert!(registry.contains(&id));
        assert_eq!(registry.len(), 1);
        assert_eq!(
            registry.create(definition),
            Err(TokenForgeError::DuplicateAsset)
        );
        assert_eq!(
            registry.get(&[0x99; 32]),
            Err(TokenForgeError::UnknownAsset)
        );
    }

    #[test]
    fn invalid_definitions_fail_closed() {
        let mut invalid = definition(SupplyPolicy::Capped {
            initial_supply: 10,
            max_supply: 1,
        });
        assert_eq!(
            invalid.validate(),
            Err(TokenForgeError::InvalidSupplyPolicy)
        );

        invalid = definition(SupplyPolicy::Scheduled {
            initial_supply: 1,
            max_supply: 10,
            period_blocks: 0,
            emission_per_period: 1,
        });
        assert_eq!(invalid.validate(), Err(TokenForgeError::InvalidPeriod));

        invalid = definition(SupplyPolicy::Capped {
            initial_supply: 1,
            max_supply: 10,
        });
        invalid.name = "é".to_owned();
        assert_eq!(invalid.validate(), Err(TokenForgeError::InvalidName));

        invalid = definition(SupplyPolicy::Capped {
            initial_supply: 1,
            max_supply: 10,
        });
        invalid.decimals = 19;
        assert_eq!(invalid.validate(), Err(TokenForgeError::InvalidDecimals));
    }

    #[test]
    fn canonical_definition_decodes_and_rejects_byte_level_tampering() {
        let definition = definition(SupplyPolicy::Scheduled {
            initial_supply: 100,
            max_supply: 10_000,
            period_blocks: 100,
            emission_per_period: 25,
        });
        let bytes = encode_definition(&definition).unwrap();
        assert_eq!(decode_definition(&bytes).unwrap(), definition);

        let mut bad_magic = bytes.clone();
        bad_magic[0] ^= 1;
        assert_eq!(
            decode_definition(&bad_magic),
            Err(TokenForgeError::BadMagic)
        );

        let mut bad_version = bytes.clone();
        bad_version[4..6].copy_from_slice(&2u16.to_be_bytes());
        assert_eq!(
            decode_definition(&bad_version),
            Err(TokenForgeError::UnsupportedVersion(2))
        );

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            decode_definition(&trailing),
            Err(TokenForgeError::TrailingBytes)
        );
    }

    #[test]
    fn mint_overflow_fails_closed_without_mutation() {
        let mut state = AssetState::new(definition(SupplyPolicy::Capped {
            initial_supply: u128::MAX,
            max_supply: u128::MAX,
        }))
        .unwrap();
        let before = state.clone();
        assert_eq!(
            state.mint(&CREATOR, 1, 0),
            Err(TokenForgeError::SupplyOverflow)
        );
        assert_eq!(state, before);
    }
}
