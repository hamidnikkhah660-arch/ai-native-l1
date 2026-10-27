//! Candidate native constant-product AMM state machine for QZXB.
//!
//! Deterministic arithmetic, checksummed snapshots, and atomic state transitions are implemented
//! here, but this module is NOT yet part of TXN4/QZB4 consensus or node transaction decoding.
//! It must not be used to claim public-market or Mainnet readiness. Production activation must
//! bind these transitions to authenticated transactions, canonical block events and state roots.
use crate::state_machine::TransactionAuthenticator;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub type AmmAssetId = [u8; 32];
pub type AmmAccountId = [u8; 32];
pub type AmmPairId = [u8; 32];

pub const AMM_FEE_BPS: u128 = 30;
pub const AMM_BPS_DENOMINATOR: u128 = 10_000;
pub const AMM_OUTPUT_MULTIPLIER: u128 = AMM_BPS_DENOMINATOR - AMM_FEE_BPS;
pub const AMM_SNAPSHOT_MAGIC: [u8; 4] = *b"QAMS";
pub const AMM_SNAPSHOT_VERSION: u16 = 2;
pub const MAX_AMM_SNAPSHOT_BYTES: usize = 8 * 1024 * 1024;
pub const AMM_OPERATION_MAGIC: [u8; 4] = *b"QAO1";
pub const AMM_OPERATION_VERSION: u16 = 1;
pub const AMM_SIGNED_OPERATION_MAGIC: [u8; 4] = *b"QAX1";
pub const AMM_SIGNED_OPERATION_VERSION: u16 = 1;
pub const MAX_AMM_OPERATION_BYTES: usize = 256;
pub const MAX_AMM_SIGNATURE_BYTES: usize = 4 * 1024;
const AMM_OPERATION_SIGNING_DOMAIN: &[u8] = b"QZXB-AMM-OPERATION-SIGN-V1\0";
const MAX_SNAPSHOT_ENTRIES: usize = 100_000;
const AMM_SNAPSHOT_CHECKSUM_DOMAIN: &[u8] = b"QZXB-NATIVE-AMM-SNAPSHOT-CHECK-V1\0";
const PAIR_ID_DOMAIN: &[u8] = b"QZXB-NATIVE-AMM-PAIR-V1\0";
const STATE_ROOT_DOMAIN: &[u8] = b"QZXB-NATIVE-AMM-STATE-ROOT-CANDIDATE-V1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AmmError {
    InvalidResourceLimit,
    InvalidAssetId,
    InvalidAccountId,
    DuplicateAsset,
    UnknownAsset,
    PairAlreadyExists,
    PairNotFound,
    ZeroAmount,
    InsufficientBalance,
    ArithmeticOverflow,
    ArithmeticUnderflow,
    TooManyAssets,
    TooManyPairs,
    TooManyHoldings,
    SlippageLimit,
    InsufficientLiquidity,
    InvariantViolation,
    SnapshotMalformed,
    SnapshotChecksumMismatch,
    SnapshotNonCanonical,
    SnapshotOversize { actual: usize, limit: usize },
    InvalidNetworkId,
    WrongNetwork,
    InvalidNonce,
    NonceMismatch { expected: u64, actual: u64 },
    Expired,
    InvalidSignature,
    UnsupportedOperationVersion(u16),
    UnknownOperation(u8),
    SignatureOversize { actual: usize, limit: usize },
    OperationOversize { actual: usize, limit: usize },
    SignedOperationOversize { actual: usize, limit: usize },
}

impl fmt::Display for AmmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for AmmError {}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Pool {
    token0: AmmAssetId,
    token1: AmmAssetId,
    reserve0: u128,
    reserve1: u128,
    total_lp_shares: u128,
    lp_balances: BTreeMap<AmmAccountId, u128>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QzxbAmmStateCandidate {
    network_id: [u8; 32],
    registered_assets: BTreeSet<AmmAssetId>,
    balances: BTreeMap<(AmmAssetId, AmmAccountId), u128>,
    pools: BTreeMap<AmmPairId, Pool>,
    nonces: BTreeMap<AmmAccountId, u64>,
    max_assets: usize,
    max_pairs: usize,
    max_holdings: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiquidityAdded {
    pub pair_id: AmmPairId,
    pub amount0_used: u128,
    pub amount1_used: u128,
    pub lp_shares_minted: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiquidityRemoved {
    pub pair_id: AmmPairId,
    pub amount0_out: u128,
    pub amount1_out: u128,
    pub lp_shares_burned: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapReceipt {
    pub pair_id: AmmPairId,
    pub token_in: AmmAssetId,
    pub token_out: AmmAssetId,
    pub amount_in: u128,
    pub amount_out: u128,
    pub fee_atoms: u128,
    pub reserve0_after: u128,
    pub reserve1_after: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AmmOperation {
    RegisterAsset {
        asset_id: AmmAssetId,
    },
    CreatePair {
        token_a: AmmAssetId,
        token_b: AmmAssetId,
    },
    TransferAsset {
        asset_id: AmmAssetId,
        recipient: AmmAccountId,
        amount: u128,
    },
    AddLiquidity {
        pair_id: AmmPairId,
        amount0_desired: u128,
        amount1_desired: u128,
        min_lp_shares: u128,
    },
    RemoveLiquidity {
        pair_id: AmmPairId,
        shares: u128,
        min_amount0_out: u128,
        min_amount1_out: u128,
    },
    SwapExactIn {
        token_in: AmmAssetId,
        token_out: AmmAssetId,
        amount_in: u128,
        min_amount_out: u128,
    },
}

impl AmmOperation {
    pub fn tag(&self) -> u8 {
        match self {
            Self::RegisterAsset { .. } => 1,
            Self::CreatePair { .. } => 2,
            Self::TransferAsset { .. } => 3,
            Self::AddLiquidity { .. } => 4,
            Self::RemoveLiquidity { .. } => 5,
            Self::SwapExactIn { .. } => 6,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, AmmError> {
        let mut bytes = Vec::with_capacity(MAX_AMM_OPERATION_BYTES);
        bytes.extend_from_slice(&AMM_OPERATION_MAGIC);
        bytes.extend_from_slice(&AMM_OPERATION_VERSION.to_be_bytes());
        bytes.push(self.tag());
        bytes.push(0);
        match self {
            Self::RegisterAsset { asset_id } => {
                if is_zero(asset_id) {
                    return Err(AmmError::InvalidAssetId);
                }
                bytes.extend_from_slice(asset_id);
            }
            Self::CreatePair { token_a, token_b } => {
                QzxbAmmStateCandidate::pair_id_for_assets(*token_a, *token_b)?;
                bytes.extend_from_slice(token_a);
                bytes.extend_from_slice(token_b);
            }
            Self::TransferAsset {
                asset_id,
                recipient,
                amount,
            } => {
                if is_zero(asset_id) {
                    return Err(AmmError::InvalidAssetId);
                }
                if is_zero(recipient) {
                    return Err(AmmError::InvalidAccountId);
                }
                if *amount == 0 {
                    return Err(AmmError::ZeroAmount);
                }
                bytes.extend_from_slice(asset_id);
                bytes.extend_from_slice(recipient);
                bytes.extend_from_slice(&amount.to_be_bytes());
            }
            Self::AddLiquidity {
                pair_id,
                amount0_desired,
                amount1_desired,
                min_lp_shares,
            } => {
                if is_zero(pair_id) {
                    return Err(AmmError::PairNotFound);
                }
                if *amount0_desired == 0 || *amount1_desired == 0 || *min_lp_shares == 0 {
                    return Err(AmmError::ZeroAmount);
                }
                bytes.extend_from_slice(pair_id);
                bytes.extend_from_slice(&amount0_desired.to_be_bytes());
                bytes.extend_from_slice(&amount1_desired.to_be_bytes());
                bytes.extend_from_slice(&min_lp_shares.to_be_bytes());
            }
            Self::RemoveLiquidity {
                pair_id,
                shares,
                min_amount0_out,
                min_amount1_out,
            } => {
                if is_zero(pair_id) {
                    return Err(AmmError::PairNotFound);
                }
                if *shares == 0 || *min_amount0_out == 0 || *min_amount1_out == 0 {
                    return Err(AmmError::ZeroAmount);
                }
                bytes.extend_from_slice(pair_id);
                bytes.extend_from_slice(&shares.to_be_bytes());
                bytes.extend_from_slice(&min_amount0_out.to_be_bytes());
                bytes.extend_from_slice(&min_amount1_out.to_be_bytes());
            }
            Self::SwapExactIn {
                token_in,
                token_out,
                amount_in,
                min_amount_out,
            } => {
                QzxbAmmStateCandidate::pair_id_for_assets(*token_in, *token_out)?;
                if *amount_in == 0 || *min_amount_out == 0 {
                    return Err(AmmError::ZeroAmount);
                }
                bytes.extend_from_slice(token_in);
                bytes.extend_from_slice(token_out);
                bytes.extend_from_slice(&amount_in.to_be_bytes());
                bytes.extend_from_slice(&min_amount_out.to_be_bytes());
            }
        }
        if bytes.len() > MAX_AMM_OPERATION_BYTES {
            return Err(AmmError::OperationOversize {
                actual: bytes.len(),
                limit: MAX_AMM_OPERATION_BYTES,
            });
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, AmmError> {
        if bytes.len() > MAX_AMM_OPERATION_BYTES {
            return Err(AmmError::OperationOversize {
                actual: bytes.len(),
                limit: MAX_AMM_OPERATION_BYTES,
            });
        }
        if bytes.len() < 8 {
            return Err(AmmError::SnapshotMalformed);
        }
        if bytes[..4] != AMM_OPERATION_MAGIC {
            return Err(AmmError::SnapshotMalformed);
        }
        let version = u16::from_be_bytes([bytes[4], bytes[5]]);
        if version != AMM_OPERATION_VERSION {
            return Err(AmmError::UnsupportedOperationVersion(version));
        }
        if bytes[7] != 0 {
            return Err(AmmError::SnapshotNonCanonical);
        }
        let tag = bytes[6];
        let payload = &bytes[8..];
        let read32 = |slice: &[u8]| -> Result<[u8; 32], AmmError> {
            slice.try_into().map_err(|_| AmmError::SnapshotMalformed)
        };
        let read128 = |slice: &[u8]| -> Result<u128, AmmError> {
            let value: [u8; 16] = slice.try_into().map_err(|_| AmmError::SnapshotMalformed)?;
            Ok(u128::from_be_bytes(value))
        };
        let op = match tag {
            1 if payload.len() == 32 => Self::RegisterAsset {
                asset_id: read32(payload)?,
            },
            2 if payload.len() == 64 => Self::CreatePair {
                token_a: read32(&payload[..32])?,
                token_b: read32(&payload[32..])?,
            },
            3 if payload.len() == 80 => Self::TransferAsset {
                asset_id: read32(&payload[..32])?,
                recipient: read32(&payload[32..64])?,
                amount: read128(&payload[64..80])?,
            },
            4 if payload.len() == 80 => Self::AddLiquidity {
                pair_id: read32(&payload[..32])?,
                amount0_desired: read128(&payload[32..48])?,
                amount1_desired: read128(&payload[48..64])?,
                min_lp_shares: read128(&payload[64..80])?,
            },
            5 if payload.len() == 80 => Self::RemoveLiquidity {
                pair_id: read32(&payload[..32])?,
                shares: read128(&payload[32..48])?,
                min_amount0_out: read128(&payload[48..64])?,
                min_amount1_out: read128(&payload[64..80])?,
            },
            6 if payload.len() == 96 => Self::SwapExactIn {
                token_in: read32(&payload[..32])?,
                token_out: read32(&payload[32..64])?,
                amount_in: read128(&payload[64..80])?,
                min_amount_out: read128(&payload[80..96])?,
            },
            1..=6 => return Err(AmmError::SnapshotMalformed),
            other => return Err(AmmError::UnknownOperation(other)),
        };
        if op.encode()?.as_slice() != bytes {
            return Err(AmmError::SnapshotNonCanonical);
        }
        Ok(op)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmmSignedOperation {
    pub network_id: [u8; 32],
    pub sender: AmmAccountId,
    pub nonce: u64,
    pub expires_at: u64,
    pub operation: AmmOperation,
    pub signature: Vec<u8>,
}

impl AmmSignedOperation {
    pub fn signing_digest(&self) -> Result<[u8; 32], AmmError> {
        if is_zero(&self.network_id) {
            return Err(AmmError::InvalidNetworkId);
        }
        if is_zero(&self.sender) {
            return Err(AmmError::InvalidAccountId);
        }
        if self.nonce == 0 {
            return Err(AmmError::InvalidNonce);
        }
        if self.expires_at == 0 {
            return Err(AmmError::Expired);
        }
        let operation = self.operation.encode()?;
        let mut hash = Sha256::new();
        hash.update(AMM_OPERATION_SIGNING_DOMAIN);
        hash.update(self.network_id);
        hash.update(self.sender);
        hash.update(self.nonce.to_be_bytes());
        hash.update(self.expires_at.to_be_bytes());
        hash.update((operation.len() as u32).to_be_bytes());
        hash.update(operation);
        Ok(hash.finalize().into())
    }

    pub fn encode(&self) -> Result<Vec<u8>, AmmError> {
        let operation = self.operation.encode()?;
        if self.signature.is_empty() {
            return Err(AmmError::InvalidSignature);
        }
        if self.signature.len() > MAX_AMM_SIGNATURE_BYTES {
            return Err(AmmError::SignatureOversize {
                actual: self.signature.len(),
                limit: MAX_AMM_SIGNATURE_BYTES,
            });
        }
        let _ = self.signing_digest()?;
        let mut bytes = Vec::with_capacity(
            4 + 2 + 32 + 32 + 8 + 8 + 2 + operation.len() + 2 + self.signature.len(),
        );
        bytes.extend_from_slice(&AMM_SIGNED_OPERATION_MAGIC);
        bytes.extend_from_slice(&AMM_SIGNED_OPERATION_VERSION.to_be_bytes());
        bytes.extend_from_slice(&self.network_id);
        bytes.extend_from_slice(&self.sender);
        bytes.extend_from_slice(&self.nonce.to_be_bytes());
        bytes.extend_from_slice(&self.expires_at.to_be_bytes());
        bytes.extend_from_slice(&(operation.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&operation);
        bytes.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.signature);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, AmmError> {
        if bytes.len() > MAX_AMM_OPERATION_BYTES + MAX_AMM_SIGNATURE_BYTES + 128 {
            return Err(AmmError::SignedOperationOversize {
                actual: bytes.len(),
                limit: MAX_AMM_OPERATION_BYTES + MAX_AMM_SIGNATURE_BYTES + 128,
            });
        }
        if bytes.len() < 4 + 2 + 32 + 32 + 8 + 8 + 2 + 2 {
            return Err(AmmError::SnapshotMalformed);
        }
        if bytes[..4] != AMM_SIGNED_OPERATION_MAGIC {
            return Err(AmmError::SnapshotMalformed);
        }
        let version = u16::from_be_bytes([bytes[4], bytes[5]]);
        if version != AMM_SIGNED_OPERATION_VERSION {
            return Err(AmmError::UnsupportedOperationVersion(version));
        }
        let mut cursor = 6usize;
        let network_id: [u8; 32] = snapshot_take(bytes, &mut cursor, 32)?
            .try_into()
            .map_err(|_| AmmError::SnapshotMalformed)?;
        let sender: AmmAccountId = snapshot_take(bytes, &mut cursor, 32)?
            .try_into()
            .map_err(|_| AmmError::SnapshotMalformed)?;
        let nonce = u64::from_be_bytes(
            snapshot_take(bytes, &mut cursor, 8)?
                .try_into()
                .map_err(|_| AmmError::SnapshotMalformed)?,
        );
        let expires_at = u64::from_be_bytes(
            snapshot_take(bytes, &mut cursor, 8)?
                .try_into()
                .map_err(|_| AmmError::SnapshotMalformed)?,
        );
        let operation_len = snapshot_u16(bytes, &mut cursor)? as usize;
        if operation_len == 0 || operation_len > MAX_AMM_OPERATION_BYTES {
            return Err(AmmError::SnapshotMalformed);
        }
        let operation = AmmOperation::decode(snapshot_take(bytes, &mut cursor, operation_len)?)?;
        let signature_len = snapshot_u16(bytes, &mut cursor)? as usize;
        if signature_len == 0 {
            return Err(AmmError::InvalidSignature);
        }
        if signature_len > MAX_AMM_SIGNATURE_BYTES {
            return Err(AmmError::SignatureOversize {
                actual: signature_len,
                limit: MAX_AMM_SIGNATURE_BYTES,
            });
        }
        let signature = snapshot_take(bytes, &mut cursor, signature_len)?.to_vec();
        if cursor != bytes.len() {
            return Err(AmmError::SnapshotNonCanonical);
        }
        let signed = Self {
            network_id,
            sender,
            nonce,
            expires_at,
            operation,
            signature,
        };
        if signed.encode()?.as_slice() != bytes {
            return Err(AmmError::SnapshotNonCanonical);
        }
        Ok(signed)
    }
}

impl QzxbAmmStateCandidate {
    pub fn new(
        network_id: [u8; 32],
        max_assets: usize,
        max_pairs: usize,
        max_holdings: usize,
    ) -> Result<Self, AmmError> {
        if is_zero(&network_id) {
            return Err(AmmError::InvalidNetworkId);
        }
        if max_assets == 0
            || max_pairs == 0
            || max_holdings == 0
            || max_assets > MAX_SNAPSHOT_ENTRIES
            || max_pairs > MAX_SNAPSHOT_ENTRIES
            || max_holdings > MAX_SNAPSHOT_ENTRIES
        {
            return Err(AmmError::InvalidResourceLimit);
        }
        Ok(Self {
            network_id,
            registered_assets: BTreeSet::new(),
            balances: BTreeMap::new(),
            pools: BTreeMap::new(),
            nonces: BTreeMap::new(),
            max_assets,
            max_pairs,
            max_holdings,
        })
    }

    pub fn register_asset(&mut self, asset: AmmAssetId) -> Result<(), AmmError> {
        if is_zero(&asset) {
            return Err(AmmError::InvalidAssetId);
        }
        if self.registered_assets.contains(&asset) {
            return Err(AmmError::DuplicateAsset);
        }
        if self.registered_assets.len() >= self.max_assets {
            return Err(AmmError::TooManyAssets);
        }
        self.registered_assets.insert(asset);
        Ok(())
    }

    /// Genesis/bootstrap helper for tests and candidate construction only.
    /// It is not a mint operation suitable for the live transaction path.
    pub fn credit_genesis_balance(
        &mut self,
        asset: AmmAssetId,
        account: AmmAccountId,
        amount: u128,
    ) -> Result<(), AmmError> {
        self.ensure_asset(&asset)?;
        self.ensure_user_account(&account)?;
        if amount == 0 {
            return Err(AmmError::ZeroAmount);
        }
        let next_balance = self
            .balance_of(&asset, &account)
            .checked_add(amount)
            .ok_or(AmmError::ArithmeticOverflow)?;
        if !self.balances.contains_key(&(asset, account))
            && self.balances.len() >= self.max_holdings
        {
            return Err(AmmError::TooManyHoldings);
        }
        self.balances.insert((asset, account), next_balance);
        self.verify_invariants()
    }

    pub fn balance_of(&self, asset: &AmmAssetId, account: &AmmAccountId) -> u128 {
        self.balances.get(&(*asset, *account)).copied().unwrap_or(0)
    }

    pub fn asset_count(&self) -> usize {
        self.registered_assets.len()
    }

    pub fn pair_count(&self) -> usize {
        self.pools.len()
    }

    pub fn network_id(&self) -> [u8; 32] {
        self.network_id
    }

    pub fn operation_nonce(&self, account: &AmmAccountId) -> u64 {
        self.nonces.get(account).copied().unwrap_or(0)
    }

    /// Authenticate and atomically execute one AMM operation in the candidate state.
    /// Inclusion time is supplied by the block-transition caller; this method never reads the wall clock.
    pub fn apply_signed_operation<A: TransactionAuthenticator>(
        &mut self,
        signed: &AmmSignedOperation,
        inclusion_timestamp: u64,
        authenticator: &A,
    ) -> Result<(), AmmError> {
        let _ = signed.encode()?;
        if signed.network_id != self.network_id {
            return Err(AmmError::WrongNetwork);
        }
        if inclusion_timestamp == 0 || signed.expires_at <= inclusion_timestamp {
            return Err(AmmError::Expired);
        }
        let expected_nonce = self
            .operation_nonce(&signed.sender)
            .checked_add(1)
            .ok_or(AmmError::InvalidNonce)?;
        if signed.nonce != expected_nonce {
            return Err(AmmError::NonceMismatch {
                expected: expected_nonce,
                actual: signed.nonce,
            });
        }
        let digest = signed.signing_digest()?;
        authenticator
            .verify(&signed.sender, &digest, &signed.signature)
            .map_err(|_| AmmError::InvalidSignature)?;

        let mut next = self.clone();
        match &signed.operation {
            AmmOperation::RegisterAsset { asset_id } => next.register_asset(*asset_id)?,
            AmmOperation::CreatePair { token_a, token_b } => {
                next.create_pair(*token_a, *token_b)?;
            }
            AmmOperation::TransferAsset {
                asset_id,
                recipient,
                amount,
            } => {
                next.ensure_asset(asset_id)?;
                next.ensure_user_account(&signed.sender)?;
                next.ensure_user_account(recipient)?;
                next.move_balance(*asset_id, signed.sender, *recipient, *amount)?;
            }
            AmmOperation::AddLiquidity {
                pair_id,
                amount0_desired,
                amount1_desired,
                min_lp_shares,
            } => {
                next.add_liquidity(
                    signed.sender,
                    *pair_id,
                    *amount0_desired,
                    *amount1_desired,
                    *min_lp_shares,
                )?;
            }
            AmmOperation::RemoveLiquidity {
                pair_id,
                shares,
                min_amount0_out,
                min_amount1_out,
            } => {
                next.remove_liquidity(
                    signed.sender,
                    *pair_id,
                    *shares,
                    *min_amount0_out,
                    *min_amount1_out,
                )?;
            }
            AmmOperation::SwapExactIn {
                token_in,
                token_out,
                amount_in,
                min_amount_out,
            } => {
                next.swap_exact_in(
                    signed.sender,
                    *token_in,
                    *token_out,
                    *amount_in,
                    *min_amount_out,
                )?;
            }
        }
        if !next.nonces.contains_key(&signed.sender) && next.nonces.len() >= next.max_holdings {
            return Err(AmmError::TooManyHoldings);
        }
        next.nonces.insert(signed.sender, signed.nonce);
        next.verify_invariants()?;
        *self = next;
        Ok(())
    }

    pub fn pair_id_for_assets(a: AmmAssetId, b: AmmAssetId) -> Result<AmmPairId, AmmError> {
        if is_zero(&a) || is_zero(&b) {
            return Err(AmmError::InvalidAssetId);
        }
        if a == b {
            return Err(AmmError::InvalidAssetId);
        }
        let (token0, token1) = ordered_assets(a, b);
        let mut hash = Sha256::new();
        hash.update(PAIR_ID_DOMAIN);
        hash.update(token0);
        hash.update(token1);
        Ok(hash.finalize().into())
    }

    /// Create an empty permissionless pair for two already registered asset IDs.
    pub fn create_pair(&mut self, a: AmmAssetId, b: AmmAssetId) -> Result<AmmPairId, AmmError> {
        self.ensure_asset(&a)?;
        self.ensure_asset(&b)?;
        let (token0, token1) = ordered_assets(a, b);
        let pair_id = Self::pair_id_for_assets(token0, token1)?;
        if self.pools.contains_key(&pair_id) {
            return Err(AmmError::PairAlreadyExists);
        }
        if self.pools.len() >= self.max_pairs {
            return Err(AmmError::TooManyPairs);
        }
        // The pair ID doubles as the deterministic internal custody account. Refuse a
        // collision with any pre-existing user account or LP holder.
        if self.balances.keys().any(|(_, account)| *account == pair_id)
            || self.nonces.contains_key(&pair_id)
            || self
                .pools
                .values()
                .any(|pool| pool.lp_balances.contains_key(&pair_id))
        {
            return Err(AmmError::InvariantViolation);
        }
        self.pools.insert(
            pair_id,
            Pool {
                token0,
                token1,
                reserve0: 0,
                reserve1: 0,
                total_lp_shares: 0,
                lp_balances: BTreeMap::new(),
            },
        );
        self.verify_invariants()?;
        Ok(pair_id)
    }

    pub fn reserves(
        &self,
        pair_id: &AmmPairId,
    ) -> Result<(AmmAssetId, u128, AmmAssetId, u128), AmmError> {
        let pool = self.pools.get(pair_id).ok_or(AmmError::PairNotFound)?;
        Ok((pool.token0, pool.reserve0, pool.token1, pool.reserve1))
    }

    pub fn lp_balance_of(
        &self,
        pair_id: &AmmPairId,
        account: &AmmAccountId,
    ) -> Result<u128, AmmError> {
        let pool = self.pools.get(pair_id).ok_or(AmmError::PairNotFound)?;
        Ok(pool.lp_balances.get(account).copied().unwrap_or(0))
    }

    /// Add liquidity; `amount_a` and `amount_b` are desired amounts for canonical token0 and token1.
    pub fn add_liquidity(
        &mut self,
        provider: AmmAccountId,
        pair_id: AmmPairId,
        amount_a: u128,
        amount_b: u128,
        min_lp_shares: u128,
    ) -> Result<LiquidityAdded, AmmError> {
        let mut next = self.clone();
        let receipt =
            next.add_liquidity_inner(provider, pair_id, amount_a, amount_b, min_lp_shares)?;
        next.verify_invariants()?;
        *self = next;
        Ok(receipt)
    }

    fn add_liquidity_inner(
        &mut self,
        provider: AmmAccountId,
        pair_id: AmmPairId,
        amount_a: u128,
        amount_b: u128,
        min_lp_shares: u128,
    ) -> Result<LiquidityAdded, AmmError> {
        self.ensure_user_account(&provider)?;
        if amount_a == 0 || amount_b == 0 || min_lp_shares == 0 {
            return Err(AmmError::ZeroAmount);
        }
        let pool = self
            .pools
            .get(&pair_id)
            .ok_or(AmmError::PairNotFound)?
            .clone();
        // Amounts are ordered by the canonical token0/token1 IDs returned by reserves().
        let (amount0_in, amount1_in) = (amount_a, amount_b);
        if self.balance_of(&pool.token0, &provider) < amount0_in
            || self.balance_of(&pool.token1, &provider) < amount1_in
        {
            return Err(AmmError::InsufficientBalance);
        }

        let (amount0_used, amount1_used, shares) = if pool.total_lp_shares == 0 {
            if pool.reserve0 != 0 || pool.reserve1 != 0 {
                return Err(AmmError::InvariantViolation);
            }
            let product = amount0_in
                .checked_mul(amount1_in)
                .ok_or(AmmError::ArithmeticOverflow)?;
            (amount0_in, amount1_in, integer_sqrt(product))
        } else {
            if pool.reserve0 == 0 || pool.reserve1 == 0 {
                return Err(AmmError::InvariantViolation);
            }
            let amount1_optimal = amount0_in
                .checked_mul(pool.reserve1)
                .ok_or(AmmError::ArithmeticOverflow)?
                / pool.reserve0;
            let (used0, used1) = if amount1_optimal <= amount1_in {
                (amount0_in, amount1_optimal)
            } else {
                (
                    amount1_in
                        .checked_mul(pool.reserve0)
                        .ok_or(AmmError::ArithmeticOverflow)?
                        / pool.reserve1,
                    amount1_in,
                )
            };
            let shares0 = used0
                .checked_mul(pool.total_lp_shares)
                .ok_or(AmmError::ArithmeticOverflow)?
                / pool.reserve0;
            let shares1 = used1
                .checked_mul(pool.total_lp_shares)
                .ok_or(AmmError::ArithmeticOverflow)?
                / pool.reserve1;
            (used0, used1, shares0.min(shares1))
        };
        if amount0_used == 0 || amount1_used == 0 || shares == 0 || shares < min_lp_shares {
            return Err(AmmError::SlippageLimit);
        }

        self.move_balance(pool.token0, provider, pair_id, amount0_used)?;
        self.move_balance(pool.token1, provider, pair_id, amount1_used)?;
        let pool = self.pools.get_mut(&pair_id).ok_or(AmmError::PairNotFound)?;
        pool.reserve0 = pool
            .reserve0
            .checked_add(amount0_used)
            .ok_or(AmmError::ArithmeticOverflow)?;
        pool.reserve1 = pool
            .reserve1
            .checked_add(amount1_used)
            .ok_or(AmmError::ArithmeticOverflow)?;
        pool.total_lp_shares = pool
            .total_lp_shares
            .checked_add(shares)
            .ok_or(AmmError::ArithmeticOverflow)?;
        let lp = pool
            .lp_balances
            .get(&provider)
            .copied()
            .unwrap_or(0)
            .checked_add(shares)
            .ok_or(AmmError::ArithmeticOverflow)?;
        if !pool.lp_balances.contains_key(&provider) && pool.lp_balances.len() >= self.max_holdings
        {
            return Err(AmmError::TooManyHoldings);
        }
        pool.lp_balances.insert(provider, lp);
        Ok(LiquidityAdded {
            pair_id,
            amount0_used,
            amount1_used,
            lp_shares_minted: shares,
        })
    }

    pub fn remove_liquidity(
        &mut self,
        provider: AmmAccountId,
        pair_id: AmmPairId,
        shares: u128,
        min_amount0_out: u128,
        min_amount1_out: u128,
    ) -> Result<LiquidityRemoved, AmmError> {
        let mut next = self.clone();
        let receipt = next.remove_liquidity_inner(
            provider,
            pair_id,
            shares,
            min_amount0_out,
            min_amount1_out,
        )?;
        next.verify_invariants()?;
        *self = next;
        Ok(receipt)
    }

    fn remove_liquidity_inner(
        &mut self,
        provider: AmmAccountId,
        pair_id: AmmPairId,
        shares: u128,
        min_amount0_out: u128,
        min_amount1_out: u128,
    ) -> Result<LiquidityRemoved, AmmError> {
        self.ensure_user_account(&provider)?;
        if shares == 0 || min_amount0_out == 0 || min_amount1_out == 0 {
            return Err(AmmError::ZeroAmount);
        }
        let pool = self
            .pools
            .get(&pair_id)
            .ok_or(AmmError::PairNotFound)?
            .clone();
        let owned = pool.lp_balances.get(&provider).copied().unwrap_or(0);
        if shares > owned || pool.total_lp_shares == 0 {
            return Err(AmmError::InsufficientBalance);
        }
        let amount0_out = pool
            .reserve0
            .checked_mul(shares)
            .ok_or(AmmError::ArithmeticOverflow)?
            / pool.total_lp_shares;
        let amount1_out = pool
            .reserve1
            .checked_mul(shares)
            .ok_or(AmmError::ArithmeticOverflow)?
            / pool.total_lp_shares;
        if amount0_out == 0
            || amount1_out == 0
            || amount0_out < min_amount0_out
            || amount1_out < min_amount1_out
        {
            return Err(AmmError::SlippageLimit);
        }
        self.move_balance(pool.token0, pair_id, provider, amount0_out)?;
        self.move_balance(pool.token1, pair_id, provider, amount1_out)?;
        let pool = self.pools.get_mut(&pair_id).ok_or(AmmError::PairNotFound)?;
        pool.reserve0 -= amount0_out;
        pool.reserve1 -= amount1_out;
        pool.total_lp_shares -= shares;
        let remaining = owned - shares;
        if remaining == 0 {
            pool.lp_balances.remove(&provider);
        } else {
            pool.lp_balances.insert(provider, remaining);
        }
        Ok(LiquidityRemoved {
            pair_id,
            amount0_out,
            amount1_out,
            lp_shares_burned: shares,
        })
    }

    pub fn swap_exact_in(
        &mut self,
        trader: AmmAccountId,
        token_in: AmmAssetId,
        token_out: AmmAssetId,
        amount_in: u128,
        min_amount_out: u128,
    ) -> Result<SwapReceipt, AmmError> {
        let mut next = self.clone();
        let receipt =
            next.swap_exact_in_inner(trader, token_in, token_out, amount_in, min_amount_out)?;
        next.verify_invariants()?;
        *self = next;
        Ok(receipt)
    }

    fn swap_exact_in_inner(
        &mut self,
        trader: AmmAccountId,
        token_in: AmmAssetId,
        token_out: AmmAssetId,
        amount_in: u128,
        min_amount_out: u128,
    ) -> Result<SwapReceipt, AmmError> {
        self.ensure_user_account(&trader)?;
        self.ensure_asset(&token_in)?;
        self.ensure_asset(&token_out)?;
        if amount_in == 0 || min_amount_out == 0 {
            return Err(AmmError::ZeroAmount);
        }
        let pair_id = Self::pair_id_for_assets(token_in, token_out)?;
        if self.balance_of(&token_in, &trader) < amount_in {
            return Err(AmmError::InsufficientBalance);
        }
        let pool = self
            .pools
            .get(&pair_id)
            .ok_or(AmmError::PairNotFound)?
            .clone();
        let (reserve_in, reserve_out, input_is_token0) = if token_in == pool.token0 {
            (pool.reserve0, pool.reserve1, true)
        } else if token_in == pool.token1 {
            (pool.reserve1, pool.reserve0, false)
        } else {
            return Err(AmmError::PairNotFound);
        };
        if reserve_in == 0 || reserve_out == 0 || pool.total_lp_shares == 0 {
            return Err(AmmError::InsufficientLiquidity);
        }
        let amount_in_with_fee = amount_in
            .checked_mul(AMM_OUTPUT_MULTIPLIER)
            .ok_or(AmmError::ArithmeticOverflow)?;
        let numerator = amount_in_with_fee
            .checked_mul(reserve_out)
            .ok_or(AmmError::ArithmeticOverflow)?;
        let denominator = reserve_in
            .checked_mul(AMM_BPS_DENOMINATOR)
            .and_then(|value| value.checked_add(amount_in_with_fee))
            .ok_or(AmmError::ArithmeticOverflow)?;
        let amount_out = numerator / denominator;
        if amount_out == 0 || amount_out < min_amount_out || amount_out >= reserve_out {
            return Err(AmmError::SlippageLimit);
        }
        let old_k = reserve_in
            .checked_mul(reserve_out)
            .ok_or(AmmError::ArithmeticOverflow)?;
        let new_reserve_in = reserve_in
            .checked_add(amount_in)
            .ok_or(AmmError::ArithmeticOverflow)?;
        let new_reserve_out = reserve_out - amount_out;
        let new_k = new_reserve_in
            .checked_mul(new_reserve_out)
            .ok_or(AmmError::ArithmeticOverflow)?;
        if new_k < old_k {
            return Err(AmmError::InvariantViolation);
        }

        self.move_balance(token_in, trader, pair_id, amount_in)?;
        self.move_balance(token_out, pair_id, trader, amount_out)?;
        let pool = self.pools.get_mut(&pair_id).ok_or(AmmError::PairNotFound)?;
        if input_is_token0 {
            pool.reserve0 = new_reserve_in;
            pool.reserve1 = new_reserve_out;
        } else {
            pool.reserve1 = new_reserve_in;
            pool.reserve0 = new_reserve_out;
        }
        let fee_atoms = amount_in - amount_in_with_fee / AMM_BPS_DENOMINATOR;
        Ok(SwapReceipt {
            pair_id,
            token_in,
            token_out,
            amount_in,
            amount_out,
            fee_atoms,
            reserve0_after: pool.reserve0,
            reserve1_after: pool.reserve1,
        })
    }

    pub fn verify_invariants(&self) -> Result<(), AmmError> {
        if is_zero(&self.network_id) {
            return Err(AmmError::InvalidNetworkId);
        }
        if self.registered_assets.len() > self.max_assets
            || self.pools.len() > self.max_pairs
            || self.balances.len() > self.max_holdings
            || self.nonces.len() > self.max_holdings
        {
            return Err(AmmError::InvariantViolation);
        }
        let total_lp_entries = self.pools.values().try_fold(0usize, |sum, pool| {
            sum.checked_add(pool.lp_balances.len())
                .ok_or(AmmError::ArithmeticOverflow)
        })?;
        if total_lp_entries > self.max_holdings {
            return Err(AmmError::TooManyHoldings);
        }
        if self.registered_assets.iter().any(is_zero)
            || self.nonces.iter().any(|(account, nonce)| {
                is_zero(account) || *nonce == 0 || self.is_pool_account(account)
            })
        {
            return Err(AmmError::InvariantViolation);
        }
        for ((asset, account), amount) in &self.balances {
            if !self.registered_assets.contains(asset) || is_zero(account) || *amount == 0 {
                return Err(AmmError::InvariantViolation);
            }
        }
        for (pair_id, pool) in &self.pools {
            if is_zero(pair_id)
                || pool.token0 >= pool.token1
                || !self.registered_assets.contains(&pool.token0)
                || !self.registered_assets.contains(&pool.token1)
                || Self::pair_id_for_assets(pool.token0, pool.token1)? != *pair_id
                || self.balance_of(&pool.token0, pair_id) != pool.reserve0
                || self.balance_of(&pool.token1, pair_id) != pool.reserve1
            {
                return Err(AmmError::InvariantViolation);
            }
            let sum_lp = pool
                .lp_balances
                .iter()
                .try_fold(0u128, |sum, (account, shares)| {
                    if is_zero(account) || *shares == 0 || self.is_pool_account(account) {
                        return Err(AmmError::InvariantViolation);
                    }
                    sum.checked_add(*shares).ok_or(AmmError::ArithmeticOverflow)
                })?;
            if sum_lp != pool.total_lp_shares {
                return Err(AmmError::InvariantViolation);
            }
            if pool.total_lp_shares == 0 {
                if pool.reserve0 != 0 || pool.reserve1 != 0 || !pool.lp_balances.is_empty() {
                    return Err(AmmError::InvariantViolation);
                }
            } else {
                if pool.reserve0 == 0 || pool.reserve1 == 0 {
                    return Err(AmmError::InvariantViolation);
                }
                pool.reserve0
                    .checked_mul(pool.reserve1)
                    .ok_or(AmmError::ArithmeticOverflow)?;
            }
        }
        Ok(())
    }

    /// Stable candidate root over registered asset IDs, spendable balances, pool reserves and LP shares.
    pub fn state_root(&self) -> Result<[u8; 32], AmmError> {
        self.verify_invariants()?;
        let mut hash = Sha256::new();
        hash.update(STATE_ROOT_DOMAIN);
        hash.update(self.network_id);
        // Bind fee policy to the candidate state commitment so implementations using a different
        // fee schedule cannot silently report the same empty-state root.
        hash.update(AMM_FEE_BPS.to_be_bytes());
        hash.update(AMM_BPS_DENOMINATOR.to_be_bytes());
        hash.update((self.registered_assets.len() as u64).to_be_bytes());
        for asset in &self.registered_assets {
            hash.update(asset);
        }
        hash.update((self.balances.len() as u64).to_be_bytes());
        for ((asset, account), amount) in &self.balances {
            hash.update(asset);
            hash.update(account);
            hash.update(amount.to_be_bytes());
        }
        hash.update((self.nonces.len() as u64).to_be_bytes());
        for (account, nonce) in &self.nonces {
            hash.update(account);
            hash.update(nonce.to_be_bytes());
        }
        hash.update((self.pools.len() as u64).to_be_bytes());
        for (pair_id, pool) in &self.pools {
            hash.update(pair_id);
            hash.update(pool.token0);
            hash.update(pool.token1);
            hash.update(pool.reserve0.to_be_bytes());
            hash.update(pool.reserve1.to_be_bytes());
            hash.update(pool.total_lp_shares.to_be_bytes());
            hash.update((pool.lp_balances.len() as u64).to_be_bytes());
            for (account, shares) in &pool.lp_balances {
                hash.update(account);
                hash.update(shares.to_be_bytes());
            }
        }
        Ok(hash.finalize().into())
    }

    /// Encode a bounded, checksummed canonical snapshot. This is a candidate codec only:
    /// the node's durable store and reorg/replay logic do not call it yet.
    pub fn encode_snapshot(&self) -> Result<Vec<u8>, AmmError> {
        self.verify_invariants()?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&AMM_SNAPSHOT_MAGIC);
        bytes.extend_from_slice(&AMM_SNAPSHOT_VERSION.to_be_bytes());
        bytes.extend_from_slice(&self.network_id);
        write_snapshot_usize(&mut bytes, self.max_assets)?;
        write_snapshot_usize(&mut bytes, self.max_pairs)?;
        write_snapshot_usize(&mut bytes, self.max_holdings)?;
        write_snapshot_usize(&mut bytes, self.registered_assets.len())?;
        for asset in &self.registered_assets {
            bytes.extend_from_slice(asset);
        }
        write_snapshot_usize(&mut bytes, self.balances.len())?;
        for ((asset, account), amount) in &self.balances {
            bytes.extend_from_slice(asset);
            bytes.extend_from_slice(account);
            bytes.extend_from_slice(&amount.to_be_bytes());
        }
        write_snapshot_usize(&mut bytes, self.nonces.len())?;
        for (account, nonce) in &self.nonces {
            bytes.extend_from_slice(account);
            bytes.extend_from_slice(&nonce.to_be_bytes());
        }
        write_snapshot_usize(&mut bytes, self.pools.len())?;
        for (pair_id, pool) in &self.pools {
            bytes.extend_from_slice(pair_id);
            bytes.extend_from_slice(&pool.token0);
            bytes.extend_from_slice(&pool.token1);
            bytes.extend_from_slice(&pool.reserve0.to_be_bytes());
            bytes.extend_from_slice(&pool.reserve1.to_be_bytes());
            bytes.extend_from_slice(&pool.total_lp_shares.to_be_bytes());
            write_snapshot_usize(&mut bytes, pool.lp_balances.len())?;
            for (account, shares) in &pool.lp_balances {
                bytes.extend_from_slice(account);
                bytes.extend_from_slice(&shares.to_be_bytes());
            }
            if bytes.len().saturating_add(32) > MAX_AMM_SNAPSHOT_BYTES {
                return Err(AmmError::SnapshotOversize {
                    actual: bytes.len().saturating_add(32),
                    limit: MAX_AMM_SNAPSHOT_BYTES,
                });
            }
        }
        if bytes.len().saturating_add(32) > MAX_AMM_SNAPSHOT_BYTES {
            return Err(AmmError::SnapshotOversize {
                actual: bytes.len().saturating_add(32),
                limit: MAX_AMM_SNAPSHOT_BYTES,
            });
        }
        let mut checksum = Sha256::new();
        checksum.update(AMM_SNAPSHOT_CHECKSUM_DOMAIN);
        checksum.update(&bytes);
        bytes.extend_from_slice(&checksum.finalize());
        Ok(bytes)
    }

    /// Decode a canonical snapshot and validate every reserve, LP, and account invariant.
    /// Snapshot checksums detect corruption only; they do not authenticate an operator or prevent rollback.
    pub fn decode_snapshot(bytes: &[u8]) -> Result<Self, AmmError> {
        if bytes.len() > MAX_AMM_SNAPSHOT_BYTES {
            return Err(AmmError::SnapshotOversize {
                actual: bytes.len(),
                limit: MAX_AMM_SNAPSHOT_BYTES,
            });
        }
        if bytes.len() < 62 + 32 {
            return Err(AmmError::SnapshotMalformed);
        }
        let checksum_offset = bytes.len() - 32;
        let mut checksum = Sha256::new();
        checksum.update(AMM_SNAPSHOT_CHECKSUM_DOMAIN);
        checksum.update(&bytes[..checksum_offset]);
        if checksum.finalize().as_slice() != &bytes[checksum_offset..] {
            return Err(AmmError::SnapshotChecksumMismatch);
        }

        let body = &bytes[..checksum_offset];
        let mut cursor = 0usize;
        if snapshot_take(body, &mut cursor, 4)? != AMM_SNAPSHOT_MAGIC {
            return Err(AmmError::SnapshotMalformed);
        }
        if snapshot_u16(body, &mut cursor)? != AMM_SNAPSHOT_VERSION {
            return Err(AmmError::SnapshotMalformed);
        }
        let network_id: [u8; 32] = snapshot_take(body, &mut cursor, 32)?
            .try_into()
            .map_err(|_| AmmError::SnapshotMalformed)?;
        if is_zero(&network_id) {
            return Err(AmmError::InvalidNetworkId);
        }
        let max_assets = snapshot_count(body, &mut cursor)?;
        let max_pairs = snapshot_count(body, &mut cursor)?;
        let max_holdings = snapshot_count(body, &mut cursor)?;
        if max_assets == 0
            || max_pairs == 0
            || max_holdings == 0
            || max_assets > MAX_SNAPSHOT_ENTRIES
            || max_pairs > MAX_SNAPSHOT_ENTRIES
            || max_holdings > MAX_SNAPSHOT_ENTRIES
        {
            return Err(AmmError::SnapshotMalformed);
        }

        let asset_count = snapshot_count(body, &mut cursor)?;
        if asset_count > max_assets || asset_count > MAX_SNAPSHOT_ENTRIES {
            return Err(AmmError::SnapshotMalformed);
        }
        let mut registered_assets = BTreeSet::new();
        for _ in 0..asset_count {
            let asset: AmmAssetId = snapshot_take(body, &mut cursor, 32)?
                .try_into()
                .map_err(|_| AmmError::SnapshotMalformed)?;
            if !registered_assets.insert(asset) {
                return Err(AmmError::SnapshotNonCanonical);
            }
        }

        let balance_count = snapshot_count(body, &mut cursor)?;
        if balance_count > max_holdings || balance_count > MAX_SNAPSHOT_ENTRIES {
            return Err(AmmError::SnapshotMalformed);
        }
        let mut balances = BTreeMap::new();
        for _ in 0..balance_count {
            let asset: AmmAssetId = snapshot_take(body, &mut cursor, 32)?
                .try_into()
                .map_err(|_| AmmError::SnapshotMalformed)?;
            let account: AmmAccountId = snapshot_take(body, &mut cursor, 32)?
                .try_into()
                .map_err(|_| AmmError::SnapshotMalformed)?;
            let amount = snapshot_u128(body, &mut cursor)?;
            if balances.insert((asset, account), amount).is_some() {
                return Err(AmmError::SnapshotNonCanonical);
            }
        }

        let nonce_count = snapshot_count(body, &mut cursor)?;
        if nonce_count > max_holdings || nonce_count > MAX_SNAPSHOT_ENTRIES {
            return Err(AmmError::SnapshotMalformed);
        }
        let mut nonces = BTreeMap::new();
        for _ in 0..nonce_count {
            let account: AmmAccountId = snapshot_take(body, &mut cursor, 32)?
                .try_into()
                .map_err(|_| AmmError::SnapshotMalformed)?;
            let nonce = u64::from_be_bytes(
                snapshot_take(body, &mut cursor, 8)?
                    .try_into()
                    .map_err(|_| AmmError::SnapshotMalformed)?,
            );
            if nonces.insert(account, nonce).is_some() {
                return Err(AmmError::SnapshotNonCanonical);
            }
        }

        let pair_count = snapshot_count(body, &mut cursor)?;
        if pair_count > max_pairs || pair_count > MAX_SNAPSHOT_ENTRIES {
            return Err(AmmError::SnapshotMalformed);
        }
        let mut pools = BTreeMap::new();
        let mut total_lp_entries = 0usize;
        for _ in 0..pair_count {
            let pair_id: AmmPairId = snapshot_take(body, &mut cursor, 32)?
                .try_into()
                .map_err(|_| AmmError::SnapshotMalformed)?;
            let token0: AmmAssetId = snapshot_take(body, &mut cursor, 32)?
                .try_into()
                .map_err(|_| AmmError::SnapshotMalformed)?;
            let token1: AmmAssetId = snapshot_take(body, &mut cursor, 32)?
                .try_into()
                .map_err(|_| AmmError::SnapshotMalformed)?;
            let reserve0 = snapshot_u128(body, &mut cursor)?;
            let reserve1 = snapshot_u128(body, &mut cursor)?;
            let total_lp_shares = snapshot_u128(body, &mut cursor)?;
            let lp_count = snapshot_count(body, &mut cursor)?;
            total_lp_entries = total_lp_entries
                .checked_add(lp_count)
                .ok_or(AmmError::SnapshotMalformed)?;
            if total_lp_entries > max_holdings || total_lp_entries > MAX_SNAPSHOT_ENTRIES {
                return Err(AmmError::SnapshotMalformed);
            }
            let mut lp_balances = BTreeMap::new();
            for _ in 0..lp_count {
                let account: AmmAccountId = snapshot_take(body, &mut cursor, 32)?
                    .try_into()
                    .map_err(|_| AmmError::SnapshotMalformed)?;
                let shares = snapshot_u128(body, &mut cursor)?;
                if lp_balances.insert(account, shares).is_some() {
                    return Err(AmmError::SnapshotNonCanonical);
                }
            }
            if pools
                .insert(
                    pair_id,
                    Pool {
                        token0,
                        token1,
                        reserve0,
                        reserve1,
                        total_lp_shares,
                        lp_balances,
                    },
                )
                .is_some()
            {
                return Err(AmmError::SnapshotNonCanonical);
            }
        }
        if cursor != body.len() {
            return Err(AmmError::SnapshotNonCanonical);
        }
        let state = Self {
            network_id,
            registered_assets,
            balances,
            pools,
            nonces,
            max_assets,
            max_pairs,
            max_holdings,
        };
        state.verify_invariants()?;
        if state.encode_snapshot()?.as_slice() != bytes {
            return Err(AmmError::SnapshotNonCanonical);
        }
        Ok(state)
    }

    fn ensure_asset(&self, asset: &AmmAssetId) -> Result<(), AmmError> {
        if is_zero(asset) {
            return Err(AmmError::InvalidAssetId);
        }
        if !self.registered_assets.contains(asset) {
            return Err(AmmError::UnknownAsset);
        }
        Ok(())
    }

    fn ensure_user_account(&self, account: &AmmAccountId) -> Result<(), AmmError> {
        if is_zero(account) || self.is_pool_account(account) {
            return Err(AmmError::InvalidAccountId);
        }
        Ok(())
    }

    fn is_pool_account(&self, account: &AmmAccountId) -> bool {
        self.pools.contains_key(account)
    }

    fn move_balance(
        &mut self,
        asset: AmmAssetId,
        from: AmmAccountId,
        to: AmmAccountId,
        amount: u128,
    ) -> Result<(), AmmError> {
        if amount == 0 {
            return Err(AmmError::ZeroAmount);
        }
        if from == to {
            return Err(AmmError::InvalidAccountId);
        }
        let source = self.balance_of(&asset, &from);
        if source < amount {
            return Err(AmmError::InsufficientBalance);
        }
        let destination = self.balance_of(&asset, &to);
        let next_destination = destination
            .checked_add(amount)
            .ok_or(AmmError::ArithmeticOverflow)?;
        if destination == 0 && self.balances.len() >= self.max_holdings && source != amount {
            return Err(AmmError::TooManyHoldings);
        }
        if source == amount {
            self.balances.remove(&(asset, from));
        } else {
            self.balances.insert((asset, from), source - amount);
        }
        self.balances.insert((asset, to), next_destination);
        Ok(())
    }
}

fn write_snapshot_usize(out: &mut Vec<u8>, value: usize) -> Result<(), AmmError> {
    let value = u32::try_from(value).map_err(|_| AmmError::SnapshotMalformed)?;
    out.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

fn snapshot_take<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> Result<&'a [u8], AmmError> {
    let end = cursor
        .checked_add(length)
        .ok_or(AmmError::SnapshotMalformed)?;
    if end > bytes.len() {
        return Err(AmmError::SnapshotMalformed);
    }
    let result = &bytes[*cursor..end];
    *cursor = end;
    Ok(result)
}

fn snapshot_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16, AmmError> {
    let value: [u8; 2] = snapshot_take(bytes, cursor, 2)?
        .try_into()
        .map_err(|_| AmmError::SnapshotMalformed)?;
    Ok(u16::from_be_bytes(value))
}

fn snapshot_count(bytes: &[u8], cursor: &mut usize) -> Result<usize, AmmError> {
    let value: [u8; 4] = snapshot_take(bytes, cursor, 4)?
        .try_into()
        .map_err(|_| AmmError::SnapshotMalformed)?;
    Ok(u32::from_be_bytes(value) as usize)
}

fn snapshot_u128(bytes: &[u8], cursor: &mut usize) -> Result<u128, AmmError> {
    let value: [u8; 16] = snapshot_take(bytes, cursor, 16)?
        .try_into()
        .map_err(|_| AmmError::SnapshotMalformed)?;
    Ok(u128::from_be_bytes(value))
}

fn ordered_assets(a: AmmAssetId, b: AmmAssetId) -> (AmmAssetId, AmmAssetId) {
    if a < b {
        (a, b)
    } else {
        (b, a)
    }
}

fn is_zero(value: &[u8; 32]) -> bool {
    value.iter().all(|byte| *byte == 0)
}

fn integer_sqrt(n: u128) -> u128 {
    if n < 2 {
        return n;
    }
    let mut x = n / 2 + 1;
    let mut next = (x + n / x) / 2;
    while next < x {
        x = next;
        next = (x + n / x) / 2;
    }
    x
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction_auth::{
        AccountPublicKey, Ed25519TransactionAuthenticator, Ed25519TransactionSigner,
        TransactionAuthenticatorKind,
    };

    const NETWORK: [u8; 32] = [0xAA; 32];
    const A: AmmAssetId = [1; 32];
    const B: AmmAssetId = [2; 32];
    const C: AmmAssetId = [9; 32];
    const TRADER: AmmAccountId = [3; 32];
    const OTHER: AmmAccountId = [4; 32];

    struct DigestAuthenticator;

    impl TransactionAuthenticator for DigestAuthenticator {
        fn verify(
            &self,
            sender: &AmmAccountId,
            signing_digest: &[u8; 32],
            signature: &[u8],
        ) -> Result<(), ()> {
            if !is_zero(sender) && signature == signing_digest {
                Ok(())
            } else {
                Err(())
            }
        }
    }

    fn signed_operation(
        sender: AmmAccountId,
        nonce: u64,
        operation: AmmOperation,
    ) -> AmmSignedOperation {
        let mut signed = AmmSignedOperation {
            network_id: NETWORK,
            sender,
            nonce,
            expires_at: 1_000,
            operation,
            signature: vec![0; 32],
        };
        signed.signature = signed.signing_digest().unwrap().to_vec();
        signed
    }

    fn fixture() -> (QzxbAmmStateCandidate, AmmPairId) {
        let mut state = QzxbAmmStateCandidate::new(NETWORK, 8, 16, 128).unwrap();
        state.register_asset(A).unwrap();
        state.register_asset(B).unwrap();
        state.credit_genesis_balance(A, TRADER, 1_000_000).unwrap();
        state.credit_genesis_balance(B, TRADER, 1_000_000).unwrap();
        let pair = state.create_pair(B, A).unwrap();
        (state, pair)
    }

    #[test]
    fn signed_operation_wire_round_trips_and_signing_digest_binds_payload() {
        let signed = signed_operation(
            TRADER,
            1,
            AmmOperation::TransferAsset {
                asset_id: A,
                recipient: OTHER,
                amount: 123,
            },
        );
        let encoded = signed.encode().unwrap();
        assert_eq!(&encoded[..4], &AMM_SIGNED_OPERATION_MAGIC);
        assert_eq!(AmmSignedOperation::decode(&encoded).unwrap(), signed);

        let mut changed = signed.clone();
        changed.operation = AmmOperation::TransferAsset {
            asset_id: A,
            recipient: OTHER,
            amount: 124,
        };
        assert_ne!(
            signed.signing_digest().unwrap(),
            changed.signing_digest().unwrap()
        );

        let mut corrupted = encoded.clone();
        corrupted.push(0);
        assert_eq!(
            AmmSignedOperation::decode(&corrupted),
            Err(AmmError::SnapshotNonCanonical)
        );
    }

    #[test]
    fn authenticated_operations_enforce_network_nonce_expiry_and_signature_atomically() {
        let mut state = QzxbAmmStateCandidate::new(NETWORK, 8, 16, 128).unwrap();
        let register = signed_operation(TRADER, 1, AmmOperation::RegisterAsset { asset_id: A });
        state
            .apply_signed_operation(&register, 10, &DigestAuthenticator)
            .unwrap();
        assert_eq!(state.operation_nonce(&TRADER), 1);
        assert_eq!(state.asset_count(), 1);

        assert_eq!(
            state.apply_signed_operation(&register, 10, &DigestAuthenticator),
            Err(AmmError::NonceMismatch {
                expected: 2,
                actual: 1
            })
        );
        let before = state.state_root().unwrap();

        let mut bad_signature =
            signed_operation(TRADER, 2, AmmOperation::RegisterAsset { asset_id: B });
        bad_signature.signature[0] ^= 1;
        assert_eq!(
            state.apply_signed_operation(&bad_signature, 10, &DigestAuthenticator),
            Err(AmmError::InvalidSignature)
        );
        assert_eq!(state.state_root().unwrap(), before);

        let mut expired = signed_operation(TRADER, 2, AmmOperation::RegisterAsset { asset_id: B });
        expired.expires_at = 10;
        expired.signature = expired.signing_digest().unwrap().to_vec();
        assert_eq!(
            state.apply_signed_operation(&expired, 10, &DigestAuthenticator),
            Err(AmmError::Expired)
        );
        assert_eq!(state.state_root().unwrap(), before);

        let mut wrong_network =
            signed_operation(TRADER, 2, AmmOperation::RegisterAsset { asset_id: B });
        wrong_network.network_id = [0xBB; 32];
        wrong_network.signature = wrong_network.signing_digest().unwrap().to_vec();
        assert_eq!(
            state.apply_signed_operation(&wrong_network, 10, &DigestAuthenticator),
            Err(AmmError::WrongNetwork)
        );
        assert_eq!(state.state_root().unwrap(), before);
    }

    #[test]
    fn production_ed25519_authenticator_verifies_amm_operation_signature() {
        let signer = Ed25519TransactionSigner::from_seed([0x44; 32]);
        let authenticator = Ed25519TransactionAuthenticator::select(
            TransactionAuthenticatorKind::Ed25519V1,
            [AccountPublicKey {
                account_id: signer.account_id(),
                public_key: signer.public_key(),
            }],
        )
        .unwrap();
        let mut state = QzxbAmmStateCandidate::new(NETWORK, 8, 16, 128).unwrap();
        let mut signed = AmmSignedOperation {
            network_id: NETWORK,
            sender: signer.account_id(),
            nonce: 1,
            expires_at: 1_000,
            operation: AmmOperation::RegisterAsset { asset_id: A },
            signature: Vec::new(),
        };
        signed.signature = signer.sign_digest(&signed.signing_digest().unwrap());
        state
            .apply_signed_operation(&signed, 10, &authenticator)
            .unwrap();
        assert_eq!(state.operation_nonce(&signer.account_id()), 1);
        assert_eq!(state.asset_count(), 1);

        let before = state.state_root().unwrap();
        let mut forged = signed.clone();
        forged.nonce = 2;
        // Do not re-sign after changing the nonce: the Ed25519 verifier must reject it atomically.
        assert_eq!(
            state.apply_signed_operation(&forged, 10, &authenticator),
            Err(AmmError::InvalidSignature)
        );
        assert_eq!(state.state_root().unwrap(), before);
    }

    #[test]
    fn authenticated_pair_creation_liquidity_and_swap_execute_with_replay_protection() {
        let mut state = QzxbAmmStateCandidate::new(NETWORK, 8, 16, 128).unwrap();
        state
            .apply_signed_operation(
                &signed_operation(TRADER, 1, AmmOperation::RegisterAsset { asset_id: A }),
                10,
                &DigestAuthenticator,
            )
            .unwrap();
        state
            .apply_signed_operation(
                &signed_operation(TRADER, 2, AmmOperation::RegisterAsset { asset_id: B }),
                10,
                &DigestAuthenticator,
            )
            .unwrap();
        state.credit_genesis_balance(A, TRADER, 1_000_000).unwrap();
        state.credit_genesis_balance(B, TRADER, 1_000_000).unwrap();

        let pair = QzxbAmmStateCandidate::pair_id_for_assets(A, B).unwrap();
        state
            .apply_signed_operation(
                &signed_operation(
                    TRADER,
                    3,
                    AmmOperation::CreatePair {
                        token_a: A,
                        token_b: B,
                    },
                ),
                10,
                &DigestAuthenticator,
            )
            .unwrap();
        state
            .apply_signed_operation(
                &signed_operation(
                    TRADER,
                    4,
                    AmmOperation::AddLiquidity {
                        pair_id: pair,
                        amount0_desired: 100_000,
                        amount1_desired: 100_000,
                        min_lp_shares: 100_000,
                    },
                ),
                10,
                &DigestAuthenticator,
            )
            .unwrap();
        state
            .apply_signed_operation(
                &signed_operation(
                    TRADER,
                    5,
                    AmmOperation::SwapExactIn {
                        token_in: A,
                        token_out: B,
                        amount_in: 1_000,
                        min_amount_out: 1,
                    },
                ),
                10,
                &DigestAuthenticator,
            )
            .unwrap();
        assert_eq!(state.operation_nonce(&TRADER), 5);
        assert!(state.balance_of(&B, &TRADER) > 900_000);
        assert!(state.reserves(&pair).unwrap().1 > 100_000);
        assert_eq!(
            state.apply_signed_operation(
                &signed_operation(
                    TRADER,
                    5,
                    AmmOperation::SwapExactIn {
                        token_in: A,
                        token_out: B,
                        amount_in: 1_000,
                        min_amount_out: 1
                    }
                ),
                10,
                &DigestAuthenticator
            ),
            Err(AmmError::NonceMismatch {
                expected: 6,
                actual: 5
            })
        );
    }

    #[test]
    fn creates_pair_with_order_independent_id_and_rejects_duplicate() {
        let (mut state, pair) = fixture();
        assert_eq!(
            pair,
            QzxbAmmStateCandidate::pair_id_for_assets(A, B).unwrap()
        );
        assert_eq!(state.create_pair(A, B), Err(AmmError::PairAlreadyExists));
        assert_eq!(state.pair_count(), 1);
    }

    #[test]
    fn adds_liquidity_swaps_with_fee_and_preserves_constant_product() {
        let (mut state, pair) = fixture();
        let added = state
            .add_liquidity(TRADER, pair, 100_000, 100_000, 99_000)
            .unwrap();
        assert_eq!(added.lp_shares_minted, 100_000);
        let (_, reserve0, _, reserve1) = state.reserves(&pair).unwrap();
        let old_k = reserve0 * reserve1;
        let receipt = state.swap_exact_in(TRADER, A, B, 1_000, 1).unwrap();
        assert!(receipt.fee_atoms > 0);
        assert!(receipt.amount_out > 0);
        assert!(receipt.amount_out < 1_000);
        assert!(receipt.reserve0_after * receipt.reserve1_after >= old_k);
        assert_eq!(state.balance_of(&A, &TRADER), 899_000);
        assert_eq!(state.balance_of(&B, &TRADER), 900_000 + receipt.amount_out);
        state.verify_invariants().unwrap();
    }

    #[test]
    fn subsequent_liquidity_uses_optimal_ratio_and_only_debits_used_amounts() {
        let (mut state, pair) = fixture();
        state
            .add_liquidity(TRADER, pair, 100_000, 100_000, 100_000)
            .unwrap();
        let added = state
            .add_liquidity(TRADER, pair, 10_000, 5_000, 5_000)
            .unwrap();
        assert_eq!(added.amount0_used, 5_000);
        assert_eq!(added.amount1_used, 5_000);
        assert_eq!(added.lp_shares_minted, 5_000);
        assert_eq!(state.balance_of(&A, &TRADER), 895_000);
        assert_eq!(state.balance_of(&B, &TRADER), 895_000);
        state.verify_invariants().unwrap();
    }

    #[test]
    fn snapshot_round_trip_preserves_pool_lp_balances_and_state_root() {
        let (mut state, pair) = fixture();
        state
            .add_liquidity(TRADER, pair, 100_000, 100_000, 100_000)
            .unwrap();
        state.swap_exact_in(TRADER, A, B, 1_000, 1).unwrap();
        let register = signed_operation(TRADER, 1, AmmOperation::RegisterAsset { asset_id: C });
        state
            .apply_signed_operation(&register, 10, &DigestAuthenticator)
            .unwrap();
        let root = state.state_root().unwrap();
        let encoded = state.encode_snapshot().unwrap();
        assert_eq!(&encoded[..4], &AMM_SNAPSHOT_MAGIC);
        let restored = QzxbAmmStateCandidate::decode_snapshot(&encoded).unwrap();
        assert_eq!(restored, state);
        assert_eq!(restored.state_root().unwrap(), root);
        assert_eq!(restored.encode_snapshot().unwrap(), encoded);
    }

    #[test]
    fn snapshot_rejects_corruption_and_trailing_bytes() {
        let (state, _) = fixture();
        let encoded = state.encode_snapshot().unwrap();
        let mut corrupt = encoded.clone();
        corrupt[24] ^= 0x80;
        assert_eq!(
            QzxbAmmStateCandidate::decode_snapshot(&corrupt),
            Err(AmmError::SnapshotChecksumMismatch)
        );
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            QzxbAmmStateCandidate::decode_snapshot(&trailing),
            Err(AmmError::SnapshotChecksumMismatch)
        );
    }

    #[test]
    fn failed_slippage_is_atomic() {
        let (mut state, pair) = fixture();
        state
            .add_liquidity(TRADER, pair, 100_000, 100_000, 99_000)
            .unwrap();
        let before = state.state_root().unwrap();
        let balances = (state.balance_of(&A, &TRADER), state.balance_of(&B, &TRADER));
        assert_eq!(
            state.swap_exact_in(TRADER, A, B, 1_000, 100_000),
            Err(AmmError::SlippageLimit)
        );
        assert_eq!(state.state_root().unwrap(), before);
        assert_eq!(
            (state.balance_of(&A, &TRADER), state.balance_of(&B, &TRADER)),
            balances
        );
    }

    #[test]
    fn removes_liquidity_and_returns_assets_in_proportion() {
        let (mut state, pair) = fixture();
        let added = state
            .add_liquidity(TRADER, pair, 100_000, 100_000, 100_000)
            .unwrap();
        let removed = state
            .remove_liquidity(TRADER, pair, added.lp_shares_minted / 2, 1, 1)
            .unwrap();
        assert_eq!(removed.amount0_out, 50_000);
        assert_eq!(removed.amount1_out, 50_000);
        assert_eq!(state.lp_balance_of(&pair, &TRADER).unwrap(), 50_000);
        state.verify_invariants().unwrap();
    }

    #[test]
    fn rejects_unknown_assets_and_zero_or_same_asset_pair() {
        let mut state = QzxbAmmStateCandidate::new(NETWORK, 2, 2, 2).unwrap();
        state.register_asset(A).unwrap();
        assert_eq!(state.create_pair(A, B), Err(AmmError::UnknownAsset));
        assert_eq!(
            QzxbAmmStateCandidate::pair_id_for_assets(A, A),
            Err(AmmError::InvalidAssetId)
        );
        assert_eq!(
            QzxbAmmStateCandidate::pair_id_for_assets([0; 32], B),
            Err(AmmError::InvalidAssetId)
        );
    }

    #[test]
    fn arithmetic_overflow_does_not_mutate_state() {
        let (mut state, pair) = fixture();
        state
            .add_liquidity(TRADER, pair, 100_000, 100_000, 99_000)
            .unwrap();
        // Build a balance large enough to reach the checked multiplication path.
        let current = state.balance_of(&A, &TRADER);
        state
            .credit_genesis_balance(A, TRADER, u128::MAX - current)
            .unwrap();
        let before = state.state_root().unwrap();
        assert_eq!(
            state.swap_exact_in(TRADER, A, B, u128::MAX, 1),
            Err(AmmError::ArithmeticOverflow)
        );
        assert_eq!(state.state_root().unwrap(), before);
    }
}
