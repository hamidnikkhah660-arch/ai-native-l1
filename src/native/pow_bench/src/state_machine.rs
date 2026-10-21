//! Deterministic account-state execution substrate for CP-0026-A.
//!
//! Research/testbed state execution. BLK2 remains the legacy/test-only transfer format.
//! The versioned MBK3/MST3 monetary transition below is a candidate implementation with
//! explicit issuance and miner-reward accounting; it is not connected to the live Devnet
//! block producer/importer or frozen production consensus. This module does not choose a
//! default authenticator. Production issuance/Genesis, fork choice, durable anti-rollback,
//! public networking and activation still require integration and independent review.
//! Test-only deterministic authenticators below are never the runtime default.
use crate::timestamp_policy::{validate_block_timestamp, TimestampPolicy, TimestampPolicyError};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Cursor, Read},
};

pub type AccountId = [u8; 32];
pub type NetworkId = [u8; 32];

pub const TX_MAGIC: [u8; 4] = *b"TXN2";
pub const BLOCK_MAGIC: [u8; 4] = *b"BLK2";
pub const STATE_VERSION: u16 = 2;
pub const MAX_SIGNATURE_BYTES: usize = 4 * 1024;
pub const MAX_TRANSACTION_BYTES: usize = 136 + MAX_SIGNATURE_BYTES;
pub const MAX_TRANSACTIONS_PER_BLOCK: usize = 1024;
pub const MAX_ENCODED_BLOCK_BYTES: usize = 5 * 1024 * 1024;
pub const MAX_ACCOUNTS: usize = 100_000;
pub const SNAPSHOT_MAGIC: [u8; 4] = *b"STV2";
pub const SNAPSHOT_VERSION: u16 = 2;
pub const MAX_ENCODED_SNAPSHOT_BYTES: usize = 5 * 1024 * 1024;
/// High-level policy decision: 10 billion coins maximum, with 8 decimal atomic units.
/// This bounds the existing ledger substrate. Production/canonical subsidy and Genesis
/// integration remain unfinished; use of this cap does not itself authorize issuance.
pub const ATOMS_PER_COIN: u128 = 100_000_000;
pub const MAX_TOTAL_SUPPLY_ATOMS: u128 = 10_000_000_000u128 * ATOMS_PER_COIN;

const TX_UNSIGNED_LEN: usize = 134;
const TX_FIXED_LEN: usize = 136;
const BLOCK_HEADER_LEN: usize = 88;
const SNAPSHOT_HEADER_LEN: usize = 98;
const SNAPSHOT_CHECKSUM_LEN: usize = 32;
const SNAPSHOT_ACCOUNT_RECORD_LEN: usize = 48;
const SNAPSHOT_CHECKSUM_DOMAIN: &[u8] = b"AIN1-STATE-SNAPSHOT-CHECK-V2\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountState {
    pub balance: u64,
    pub nonce: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    /// Fixed 32-byte chain/network domain, included in the signing digest and TXN2 bytes.
    pub network_id: NetworkId,
    pub sender: AccountId,
    pub recipient: AccountId,
    pub nonce: u64,
    pub amount: u64,
    pub fee: u64,
    /// Exclusive expiry: the transaction is invalid when block.timestamp >= expires_at.
    pub expires_at: u64,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub height: u64,
    /// Canonical block timestamp used for deterministic expiry validation.
    pub timestamp: u64,
    pub parent_hash: [u8; 32],
    /// Post-execution state commitment included in the canonical block ID.
    pub state_root: [u8; 32],
    pub transactions: Vec<Transaction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockApplySummary {
    pub height: u64,
    pub block_hash: [u8; 32],
    pub state_root: [u8; 32],
    pub transactions_applied: usize,
    pub fees_collected: u64,
    pub account_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateError {
    Malformed,
    BadMagic,
    UnsupportedVersion(u16),
    Oversize {
        actual: usize,
        limit: usize,
    },
    EmptySignature,
    InvalidAccountId,
    DuplicateGenesisAccount,
    InvalidHeight,
    HeightMismatch {
        expected: u64,
        actual: u64,
    },
    ParentHashMismatch,
    StateRootMismatch,
    TooManyTransactions(usize),
    TooManyAccounts,
    InvalidNonce(u64),
    InvalidAmount,
    MissingSender,
    NonceMismatch {
        expected: u64,
        actual: u64,
    },
    AmountOverflow,
    InsufficientBalance,
    BalanceOverflow,
    FeeOverflow,
    SupplyCapExceeded,
    MinerBudgetExceeded,
    InvalidMonetaryAllocation,
    MinerRewardMismatch {
        expected: u64,
        actual: u64,
    },
    MonetarySnapshotChecksumMismatch,
    MonetaryPolicyMismatch,
    DuplicateTransaction,
    Unauthorized,
    InvariantViolation,
    SnapshotChecksumMismatch,
    SnapshotNonCanonical,
    InvalidNetworkId,
    WrongNetwork,
    InvalidExpiry,
    TransactionExpired {
        expires_at: u64,
        block_timestamp: u64,
    },
    InvalidBlockTimestamp,
    TimestampNotIncreasing {
        previous: u64,
        actual: u64,
    },
    TimestampTooFarInFuture {
        latest_allowed: u64,
        actual: u64,
    },
    SnapshotNetworkMismatch,
    ManifestMismatch,
    InvalidHybridAuthorization,
}

pub trait TransactionAuthenticator {
    // Implementations must fail closed. No permissive production implementation is
    // provided in this crate; the fake authenticator below exists only in unit tests.
    fn verify(
        &self,
        sender: &AccountId,
        signing_digest: &[u8; 32],
        signature: &[u8],
    ) -> Result<(), ()>;

    /// Optional fingerprint of every configuration/policy fact that can affect verify().
    ///
    /// A caller may reuse a previously successful verification only when this returns Some
    /// and the exact fingerprint is unchanged. Implementations with dynamic revocation,
    /// mutable key registries or unknown policy state MUST return None unless that state is
    /// fully represented in the fingerprint. The default deliberately disables such caching.
    fn verification_cache_scope(&self) -> Option<[u8; 32]> {
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerState {
    network_id: NetworkId,
    height: u64,
    last_timestamp: u64,
    tip_hash: [u8; 32],
    fee_pool: u64,
    accounts: BTreeMap<AccountId, AccountState>,
}

fn hash_domain(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    for part in parts {
        hash.update(part);
    }
    hash.finalize().into()
}

fn is_zero_account(account: &AccountId) -> bool {
    account.iter().all(|byte| *byte == 0)
}

fn validate_unsigned_fields(tx: &Transaction) -> Result<(), StateError> {
    if tx.network_id.iter().all(|byte| *byte == 0) {
        return Err(StateError::InvalidNetworkId);
    }
    if tx.expires_at == 0 {
        return Err(StateError::InvalidExpiry);
    }
    if is_zero_account(&tx.sender) || is_zero_account(&tx.recipient) {
        return Err(StateError::InvalidAccountId);
    }
    if tx.nonce == 0 {
        return Err(StateError::InvalidNonce(tx.nonce));
    }
    if tx.amount == 0 {
        return Err(StateError::InvalidAmount);
    }
    Ok(())
}

fn encode_unsigned_transaction(tx: &Transaction) -> Result<Vec<u8>, StateError> {
    validate_unsigned_fields(tx)?;
    let mut out = Vec::with_capacity(TX_UNSIGNED_LEN);
    out.extend_from_slice(&TX_MAGIC);
    out.extend_from_slice(&STATE_VERSION.to_be_bytes());
    out.extend_from_slice(&tx.network_id);
    out.extend_from_slice(&tx.sender);
    out.extend_from_slice(&tx.recipient);
    out.extend_from_slice(&tx.nonce.to_be_bytes());
    out.extend_from_slice(&tx.amount.to_be_bytes());
    out.extend_from_slice(&tx.fee.to_be_bytes());
    out.extend_from_slice(&tx.expires_at.to_be_bytes());
    debug_assert_eq!(out.len(), TX_UNSIGNED_LEN);
    Ok(out)
}

/// Domain-separated digest for an external signature provider.
/// Signature bytes are excluded from the signing preimage.
pub fn transaction_signing_digest(tx: &Transaction) -> Result<[u8; 32], StateError> {
    let unsigned = encode_unsigned_transaction(tx)?;
    Ok(hash_domain(b"AIN1-TX-SIGN-V2\0", &[&unsigned]))
}

pub fn encode_transaction(tx: &Transaction) -> Result<Vec<u8>, StateError> {
    let unsigned = encode_unsigned_transaction(tx)?;
    if tx.signature.is_empty() {
        return Err(StateError::EmptySignature);
    }
    if tx.signature.len() > MAX_SIGNATURE_BYTES {
        return Err(StateError::Oversize {
            actual: tx.signature.len(),
            limit: MAX_SIGNATURE_BYTES,
        });
    }
    let signature_len = u16::try_from(tx.signature.len()).map_err(|_| StateError::Malformed)?;
    let mut out = Vec::with_capacity(TX_FIXED_LEN + tx.signature.len());
    out.extend_from_slice(&unsigned);
    out.extend_from_slice(&signature_len.to_be_bytes());
    out.extend_from_slice(&tx.signature);
    if out.len() > MAX_TRANSACTION_BYTES {
        return Err(StateError::Oversize {
            actual: out.len(),
            limit: MAX_TRANSACTION_BYTES,
        });
    }
    Ok(out)
}

fn read_array<const N: usize>(cursor: &mut Cursor<&[u8]>) -> Result<[u8; N], StateError> {
    let mut out = [0u8; N];
    cursor
        .read_exact(&mut out)
        .map_err(|_| StateError::Malformed)?;
    Ok(out)
}

fn read_u16(cursor: &mut Cursor<&[u8]>) -> Result<u16, StateError> {
    Ok(u16::from_be_bytes(read_array(cursor)?))
}

fn read_u32(cursor: &mut Cursor<&[u8]>) -> Result<u32, StateError> {
    Ok(u32::from_be_bytes(read_array(cursor)?))
}

fn read_u64(cursor: &mut Cursor<&[u8]>) -> Result<u64, StateError> {
    Ok(u64::from_be_bytes(read_array(cursor)?))
}

fn read_prefix(cursor: &mut Cursor<&[u8]>, expected: &[u8; 4]) -> Result<(), StateError> {
    if &read_array::<4>(cursor)? != expected {
        return Err(StateError::BadMagic);
    }
    let version = read_u16(cursor)?;
    if version != STATE_VERSION {
        return Err(StateError::UnsupportedVersion(version));
    }
    Ok(())
}

pub fn decode_transaction(bytes: &[u8]) -> Result<Transaction, StateError> {
    if bytes.len() > MAX_TRANSACTION_BYTES {
        return Err(StateError::Oversize {
            actual: bytes.len(),
            limit: MAX_TRANSACTION_BYTES,
        });
    }
    if bytes.len() < TX_FIXED_LEN {
        return Err(StateError::Malformed);
    }
    let mut cursor = Cursor::new(bytes);
    read_prefix(&mut cursor, &TX_MAGIC)?;
    let network_id = read_array(&mut cursor)?;
    let sender = read_array(&mut cursor)?;
    let recipient = read_array(&mut cursor)?;
    let nonce = read_u64(&mut cursor)?;
    let amount = read_u64(&mut cursor)?;
    let fee = read_u64(&mut cursor)?;
    let expires_at = read_u64(&mut cursor)?;
    let signature_len = read_u16(&mut cursor)? as usize;
    if signature_len == 0 {
        return Err(StateError::EmptySignature);
    }
    if signature_len > MAX_SIGNATURE_BYTES {
        return Err(StateError::Oversize {
            actual: signature_len,
            limit: MAX_SIGNATURE_BYTES,
        });
    }
    let mut signature = vec![0u8; signature_len];
    cursor
        .read_exact(&mut signature)
        .map_err(|_| StateError::Malformed)?;
    if cursor.position() as usize != bytes.len() {
        return Err(StateError::Malformed);
    }
    let tx = Transaction {
        network_id,
        sender,
        recipient,
        nonce,
        amount,
        fee,
        expires_at,
        signature,
    };
    validate_unsigned_fields(&tx)?;
    Ok(tx)
}

pub fn transaction_id(tx: &Transaction) -> Result<[u8; 32], StateError> {
    let canonical = encode_transaction(tx)?;
    Ok(hash_domain(b"AIN1-TX-ID-V2\0", &[&canonical]))
}

pub fn encode_block(block: &Block) -> Result<Vec<u8>, StateError> {
    if block.height == 0 {
        return Err(StateError::InvalidHeight);
    }
    if block.timestamp == 0 {
        return Err(StateError::InvalidBlockTimestamp);
    }
    if block.transactions.len() > MAX_TRANSACTIONS_PER_BLOCK {
        return Err(StateError::TooManyTransactions(block.transactions.len()));
    }
    let count = u16::try_from(block.transactions.len()).map_err(|_| StateError::Malformed)?;
    let mut out = Vec::with_capacity(BLOCK_HEADER_LEN);
    out.extend_from_slice(&BLOCK_MAGIC);
    out.extend_from_slice(&STATE_VERSION.to_be_bytes());
    out.extend_from_slice(&block.height.to_be_bytes());
    out.extend_from_slice(&block.timestamp.to_be_bytes());
    out.extend_from_slice(&block.parent_hash);
    out.extend_from_slice(&block.state_root);
    out.extend_from_slice(&count.to_be_bytes());
    for tx in &block.transactions {
        let encoded = encode_transaction(tx)?;
        let len = u32::try_from(encoded.len()).map_err(|_| StateError::Malformed)?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&encoded);
        if out.len() > MAX_ENCODED_BLOCK_BYTES {
            return Err(StateError::Oversize {
                actual: out.len(),
                limit: MAX_ENCODED_BLOCK_BYTES,
            });
        }
    }
    Ok(out)
}

pub fn decode_block(bytes: &[u8]) -> Result<Block, StateError> {
    if bytes.len() > MAX_ENCODED_BLOCK_BYTES {
        return Err(StateError::Oversize {
            actual: bytes.len(),
            limit: MAX_ENCODED_BLOCK_BYTES,
        });
    }
    if bytes.len() < BLOCK_HEADER_LEN {
        return Err(StateError::Malformed);
    }
    let mut cursor = Cursor::new(bytes);
    read_prefix(&mut cursor, &BLOCK_MAGIC)?;
    let height = read_u64(&mut cursor)?;
    if height == 0 {
        return Err(StateError::InvalidHeight);
    }
    let timestamp = read_u64(&mut cursor)?;
    if timestamp == 0 {
        return Err(StateError::InvalidBlockTimestamp);
    }
    let parent_hash = read_array(&mut cursor)?;
    let state_root = read_array(&mut cursor)?;
    let count = read_u16(&mut cursor)? as usize;
    if count > MAX_TRANSACTIONS_PER_BLOCK {
        return Err(StateError::TooManyTransactions(count));
    }
    let mut transactions = Vec::with_capacity(count);
    for _ in 0..count {
        let len = read_u32(&mut cursor)? as usize;
        if !(TX_FIXED_LEN..=MAX_TRANSACTION_BYTES).contains(&len) {
            return Err(StateError::Malformed);
        }
        let mut tx_bytes = vec![0u8; len];
        cursor
            .read_exact(&mut tx_bytes)
            .map_err(|_| StateError::Malformed)?;
        transactions.push(decode_transaction(&tx_bytes)?);
    }
    if cursor.position() as usize != bytes.len() {
        return Err(StateError::Malformed);
    }
    Ok(Block {
        height,
        timestamp,
        parent_hash,
        state_root,
        transactions,
    })
}

pub fn block_id(block: &Block) -> Result<[u8; 32], StateError> {
    let canonical = encode_block(block)?;
    Ok(hash_domain(b"AIN1-BLOCK-ID-V2\0", &[&canonical]))
}

impl LedgerState {
    pub fn genesis(
        network_id: NetworkId,
        accounts: Vec<(AccountId, u64)>,
    ) -> Result<Self, StateError> {
        if network_id.iter().all(|byte| *byte == 0) {
            return Err(StateError::InvalidNetworkId);
        }
        if accounts.len() > MAX_ACCOUNTS {
            return Err(StateError::TooManyAccounts);
        }
        let mut map = BTreeMap::new();
        for (id, balance) in accounts {
            if is_zero_account(&id) {
                return Err(StateError::InvalidAccountId);
            }
            if map.insert(id, AccountState { balance, nonce: 0 }).is_some() {
                return Err(StateError::DuplicateGenesisAccount);
            }
        }
        let state = Self {
            network_id,
            height: 0,
            last_timestamp: 0,
            tip_hash: [0u8; 32],
            fee_pool: 0,
            accounts: map,
        };
        // Fail closed on any Genesis distribution that violates the selected lifetime cap.
        state.total_value()?;
        Ok(state)
    }

    pub fn network_id(&self) -> NetworkId {
        self.network_id
    }

    pub fn height(&self) -> u64 {
        self.height
    }

    pub fn last_timestamp(&self) -> u64 {
        self.last_timestamp
    }

    pub fn tip_hash(&self) -> [u8; 32] {
        self.tip_hash
    }

    pub fn fee_pool(&self) -> u64 {
        self.fee_pool
    }

    pub fn account(&self, id: &AccountId) -> Option<AccountState> {
        self.accounts.get(id).copied()
    }

    pub fn account_count(&self) -> usize {
        self.accounts.len()
    }

    pub fn total_value(&self) -> Result<u128, StateError> {
        let balances = self.accounts.values().try_fold(0u128, |sum, account| {
            sum.checked_add(account.balance as u128)
                .ok_or(StateError::InvariantViolation)
        })?;
        let total = balances
            .checked_add(self.fee_pool as u128)
            .ok_or(StateError::InvariantViolation)?;
        if total > MAX_TOTAL_SUPPLY_ATOMS {
            return Err(StateError::SupplyCapExceeded);
        }
        Ok(total)
    }

    /// Canonical commitment over network domain, height, last block timestamp,
    /// fee pool and sorted accounts. Tip hash is excluded to avoid a hash/root cycle.
    pub fn state_root(&self) -> [u8; 32] {
        let mut canonical = Vec::with_capacity(74 + self.accounts.len() * 48);
        canonical.extend_from_slice(b"AIN1-STATE-V2\0");
        canonical.extend_from_slice(&self.network_id);
        canonical.extend_from_slice(&self.height.to_be_bytes());
        canonical.extend_from_slice(&self.last_timestamp.to_be_bytes());
        canonical.extend_from_slice(&self.fee_pool.to_be_bytes());
        canonical.extend_from_slice(&(self.accounts.len() as u32).to_be_bytes());
        for (id, account) in &self.accounts {
            canonical.extend_from_slice(id);
            canonical.extend_from_slice(&account.balance.to_be_bytes());
            canonical.extend_from_slice(&account.nonce.to_be_bytes());
        }
        hash_domain(b"AIN1-STATE-ROOT-V2\0", &[&canonical])
    }

    /// Encode a canonical restart snapshot. Accounts are serialized in AccountId order,
    /// followed by a domain-separated SHA-256 checksum over the complete payload.
    pub fn encode_snapshot(&self) -> Result<Vec<u8>, StateError> {
        // The checksum only detects corruption; it does not authorize a supply state.
        self.total_value()?;
        if self.accounts.len() > MAX_ACCOUNTS {
            return Err(StateError::TooManyAccounts);
        }
        let count = u32::try_from(self.accounts.len()).map_err(|_| StateError::TooManyAccounts)?;
        let mut bytes = Vec::with_capacity(
            SNAPSHOT_HEADER_LEN
                + self.accounts.len() * SNAPSHOT_ACCOUNT_RECORD_LEN
                + SNAPSHOT_CHECKSUM_LEN,
        );
        bytes.extend_from_slice(&SNAPSHOT_MAGIC);
        bytes.extend_from_slice(&SNAPSHOT_VERSION.to_be_bytes());
        bytes.extend_from_slice(&self.network_id);
        bytes.extend_from_slice(&self.height.to_be_bytes());
        bytes.extend_from_slice(&self.last_timestamp.to_be_bytes());
        bytes.extend_from_slice(&self.tip_hash);
        bytes.extend_from_slice(&self.fee_pool.to_be_bytes());
        bytes.extend_from_slice(&count.to_be_bytes());
        for (id, account) in &self.accounts {
            bytes.extend_from_slice(id);
            bytes.extend_from_slice(&account.balance.to_be_bytes());
            bytes.extend_from_slice(&account.nonce.to_be_bytes());
        }
        if bytes.len() + SNAPSHOT_CHECKSUM_LEN > MAX_ENCODED_SNAPSHOT_BYTES {
            return Err(StateError::Oversize {
                actual: bytes.len() + SNAPSHOT_CHECKSUM_LEN,
                limit: MAX_ENCODED_SNAPSHOT_BYTES,
            });
        }
        let checksum = hash_domain(SNAPSHOT_CHECKSUM_DOMAIN, &[&bytes]);
        bytes.extend_from_slice(&checksum);
        Ok(bytes)
    }

    /// Restore a snapshot only if its checksum, version, length and strictly ordered
    /// account table are canonical. This is integrity/error detection, not authenticity.
    pub fn decode_snapshot(
        bytes: &[u8],
        expected_network_id: &NetworkId,
    ) -> Result<Self, StateError> {
        if expected_network_id.iter().all(|byte| *byte == 0) {
            return Err(StateError::InvalidNetworkId);
        }
        if bytes.len() > MAX_ENCODED_SNAPSHOT_BYTES {
            return Err(StateError::Oversize {
                actual: bytes.len(),
                limit: MAX_ENCODED_SNAPSHOT_BYTES,
            });
        }
        if bytes.len() < SNAPSHOT_HEADER_LEN + SNAPSHOT_CHECKSUM_LEN {
            return Err(StateError::Malformed);
        }
        let payload_len = bytes.len() - SNAPSHOT_CHECKSUM_LEN;
        let expected_checksum = hash_domain(SNAPSHOT_CHECKSUM_DOMAIN, &[&bytes[..payload_len]]);
        if bytes[payload_len..] != expected_checksum[..] {
            return Err(StateError::SnapshotChecksumMismatch);
        }

        let payload = &bytes[..payload_len];
        let mut cursor = Cursor::new(payload);
        if read_array::<4>(&mut cursor)? != SNAPSHOT_MAGIC {
            return Err(StateError::BadMagic);
        }
        let version = read_u16(&mut cursor)?;
        if version != SNAPSHOT_VERSION {
            return Err(StateError::UnsupportedVersion(version));
        }
        let network_id = read_array(&mut cursor)?;
        if network_id.iter().all(|byte| *byte == 0) {
            return Err(StateError::InvalidNetworkId);
        }
        if &network_id != expected_network_id {
            return Err(StateError::SnapshotNetworkMismatch);
        }
        let height = read_u64(&mut cursor)?;
        let last_timestamp = read_u64(&mut cursor)?;
        let tip_hash = read_array(&mut cursor)?;
        let fee_pool = read_u64(&mut cursor)?;
        let count = read_u32(&mut cursor)? as usize;
        if count > MAX_ACCOUNTS {
            return Err(StateError::TooManyAccounts);
        }
        let records_len = count
            .checked_mul(SNAPSHOT_ACCOUNT_RECORD_LEN)
            .ok_or(StateError::TooManyAccounts)?;
        let expected_payload_len = SNAPSHOT_HEADER_LEN
            .checked_add(records_len)
            .ok_or(StateError::TooManyAccounts)?;
        if payload.len() != expected_payload_len {
            return Err(StateError::Malformed);
        }

        let mut accounts = BTreeMap::new();
        let mut previous: Option<AccountId> = None;
        for _ in 0..count {
            let id = read_array(&mut cursor)?;
            let balance = read_u64(&mut cursor)?;
            let nonce = read_u64(&mut cursor)?;
            if is_zero_account(&id) {
                return Err(StateError::InvalidAccountId);
            }
            if previous.is_some_and(|last| last >= id) {
                return Err(StateError::SnapshotNonCanonical);
            }
            previous = Some(id);
            accounts.insert(id, AccountState { balance, nonce });
        }

        let restored = Self {
            network_id,
            height,
            last_timestamp,
            tip_hash,
            fee_pool,
            accounts,
        };
        let _ = restored.total_value()?;
        Ok(restored)
    }

    fn prepare_candidate<A: TransactionAuthenticator>(
        &self,
        block: &Block,
        authenticator: &A,
    ) -> Result<(LedgerState, u64), StateError> {
        // Encoding enforces the structural limits before signatures or state work.
        encode_block(block)?;
        let expected_height = self
            .height
            .checked_add(1)
            .ok_or(StateError::InvalidHeight)?;
        if block.height != expected_height {
            return Err(StateError::HeightMismatch {
                expected: expected_height,
                actual: block.height,
            });
        }
        if block.parent_hash != self.tip_hash {
            return Err(StateError::ParentHashMismatch);
        }
        if block.timestamp <= self.last_timestamp {
            return Err(StateError::TimestampNotIncreasing {
                previous: self.last_timestamp,
                actual: block.timestamp,
            });
        }

        let mut next = self.clone();
        let total_before = next.total_value()?;
        let mut local_txids = BTreeSet::new();
        let mut fees_collected = 0u64;
        for tx in &block.transactions {
            if tx.network_id != self.network_id {
                return Err(StateError::WrongNetwork);
            }
            if block.timestamp >= tx.expires_at {
                return Err(StateError::TransactionExpired {
                    expires_at: tx.expires_at,
                    block_timestamp: block.timestamp,
                });
            }
            let id = transaction_id(tx)?;
            if !local_txids.insert(id) {
                return Err(StateError::DuplicateTransaction);
            }
            let digest = transaction_signing_digest(tx)?;
            authenticator
                .verify(&tx.sender, &digest, &tx.signature)
                .map_err(|_| StateError::Unauthorized)?;
            next.apply_transaction(tx)?;
            fees_collected = fees_collected
                .checked_add(tx.fee)
                .ok_or(StateError::FeeOverflow)?;
        }

        next.height = block.height;
        next.last_timestamp = block.timestamp;
        if next.total_value()? != total_before {
            return Err(StateError::InvariantViolation);
        }
        Ok((next, fees_collected))
    }

    /// Compute the state root a valid block body would produce. A block builder uses
    /// this to populate Block.state_root; received blocks independently recompute it.
    pub fn preview_state_root_after<A: TransactionAuthenticator>(
        &self,
        block: &Block,
        authenticator: &A,
    ) -> Result<[u8; 32], StateError> {
        let (candidate, _) = self.prepare_candidate(block, authenticator)?;
        Ok(candidate.state_root())
    }

    /// Apply a block through an explicit time-admission policy.
    ///
    /// reference_time is provided by the caller; this method never reads the system
    /// clock. Replayers can keep using apply_block for historical deterministic
    /// execution, while live admission must use this policy-aware entry point.
    /// Rejection occurs before any state mutation.
    pub(crate) fn apply_block_with_timestamp_policy<A: TransactionAuthenticator>(
        &mut self,
        block: &Block,
        authenticator: &A,
        reference_time: u64,
        policy: TimestampPolicy,
    ) -> Result<BlockApplySummary, StateError> {
        // Preserve structural/chain-link error precedence before time-window checks.
        encode_block(block)?;
        let expected_height = self
            .height
            .checked_add(1)
            .ok_or(StateError::InvalidHeight)?;
        if block.height != expected_height {
            return Err(StateError::HeightMismatch {
                expected: expected_height,
                actual: block.height,
            });
        }
        if block.parent_hash != self.tip_hash {
            return Err(StateError::ParentHashMismatch);
        }
        validate_block_timestamp(self.last_timestamp, block.timestamp, reference_time, policy)
            .map_err(|error| match error {
                TimestampPolicyError::ZeroTimestamp => StateError::InvalidBlockTimestamp,
                TimestampPolicyError::NotIncreasing { previous, actual } => {
                    StateError::TimestampNotIncreasing { previous, actual }
                }
                TimestampPolicyError::TooFarInFuture {
                    latest_allowed,
                    actual,
                } => StateError::TimestampTooFarInFuture {
                    latest_allowed,
                    actual,
                },
            })?;
        self.apply_block(block, authenticator)
    }

    /// Atomically execute one block and require its committed state root to match.
    /// Any failure leaves the original state byte-for-byte unchanged.
    pub(crate) fn apply_block<A: TransactionAuthenticator>(
        &mut self,
        block: &Block,
        authenticator: &A,
    ) -> Result<BlockApplySummary, StateError> {
        let canonical_block = encode_block(block)?;
        let (mut next, fees_collected) = self.prepare_candidate(block, authenticator)?;
        let computed_state_root = next.state_root();
        if computed_state_root != block.state_root {
            return Err(StateError::StateRootMismatch);
        }
        let block_hash = hash_domain(b"AIN1-BLOCK-ID-V2\0", &[&canonical_block]);
        next.tip_hash = block_hash;
        let summary = BlockApplySummary {
            height: next.height,
            block_hash,
            state_root: computed_state_root,
            transactions_applied: block.transactions.len(),
            fees_collected,
            account_count: next.account_count(),
        };
        *self = next;
        Ok(summary)
    }

    fn apply_transaction(&mut self, tx: &Transaction) -> Result<(), StateError> {
        let sender = *self
            .accounts
            .get(&tx.sender)
            .ok_or(StateError::MissingSender)?;
        let expected_nonce = sender
            .nonce
            .checked_add(1)
            .ok_or(StateError::InvalidNonce(tx.nonce))?;
        if tx.nonce != expected_nonce {
            return Err(StateError::NonceMismatch {
                expected: expected_nonce,
                actual: tx.nonce,
            });
        }
        let debit = tx
            .amount
            .checked_add(tx.fee)
            .ok_or(StateError::AmountOverflow)?;
        if sender.balance < debit {
            return Err(StateError::InsufficientBalance);
        }
        let new_fee_pool = self
            .fee_pool
            .checked_add(tx.fee)
            .ok_or(StateError::FeeOverflow)?;

        if tx.sender == tx.recipient {
            self.accounts.insert(
                tx.sender,
                AccountState {
                    balance: sender.balance - tx.fee,
                    nonce: tx.nonce,
                },
            );
            self.fee_pool = new_fee_pool;
            return Ok(());
        }

        let recipient = self
            .accounts
            .get(&tx.recipient)
            .copied()
            .unwrap_or(AccountState {
                balance: 0,
                nonce: 0,
            });
        if !self.accounts.contains_key(&tx.recipient) && self.accounts.len() >= MAX_ACCOUNTS {
            return Err(StateError::TooManyAccounts);
        }
        let recipient_balance = recipient
            .balance
            .checked_add(tx.amount)
            .ok_or(StateError::BalanceOverflow)?;

        self.accounts.insert(
            tx.sender,
            AccountState {
                balance: sender.balance - debit,
                nonce: tx.nonce,
            },
        );
        self.accounts.insert(
            tx.recipient,
            AccountState {
                balance: recipient_balance,
                nonce: recipient.nonce,
            },
        );
        self.fee_pool = new_fee_pool;
        Ok(())
    }
}

/// Versioned monetary block envelope. BLK2 remains unchanged for legacy/test-only
/// history; this candidate path commits miner and subsidy fields under a separate block ID.
pub const MONETARY_BLOCK_MAGIC: [u8; 4] = *b"MBK3";
/// Version 4 monetary blocks carry canonical TXN4 hybrid transactions without re-encoding them as TXN2.
pub const V4_HYBRID_MONETARY_BLOCK_MAGIC: [u8; 4] = *b"MBK4";
pub const MONETARY_SNAPSHOT_MAGIC: [u8; 4] = *b"MST3";

/// These parameters materialize the current 10B/40-30-30 research direction only.
/// They are not a frozen production or Mainnet consensus profile.
pub const MONETARY_FOUNDER_ALLOCATION_ATOMS: u128 = 400_000_000_000_000_000;
pub const MONETARY_MINER_BUDGET_ATOMS: u128 = 300_000_000_000_000_000;
pub const MONETARY_PUBLIC_GOODS_BUDGET_ATOMS: u128 = 300_000_000_000_000_000;
pub const MONETARY_INITIAL_SUBSIDY_ATOMS: u128 = 35_673_515_981;
pub const MONETARY_BLOCKS_PER_HALVING: u64 = 4_204_800;
const MONETARY_FORMAT_VERSION: u16 = 3;
const MONETARY_BLOCK_FIXED_OVERHEAD: usize = 4 + 2 + 4 + 32 + 8;
const V4_HYBRID_MONETARY_FORMAT_VERSION: u16 = 4;
const V4_HYBRID_MONETARY_FIXED_OVERHEAD: usize = 4 + 2 + 8 + 8 + 32 + 32 + 4 + 32 + 8;
pub const MAX_ENCODED_V4_HYBRID_MONETARY_BLOCK_BYTES: usize =
    MAX_ENCODED_BLOCK_BYTES + V4_HYBRID_MONETARY_FIXED_OVERHEAD;
const MAX_ENCODED_MONETARY_BLOCK_BYTES: usize =
    MAX_ENCODED_BLOCK_BYTES + MONETARY_BLOCK_FIXED_OVERHEAD;
const MONETARY_SNAPSHOT_VERSION: u16 = 3;
const MONETARY_SNAPSHOT_CHECKSUM_DOMAIN: &[u8] = b"AIN1-MONETARY-SNAPSHOT-CHECK-V3\0";
const MONETARY_STATE_ROOT_DOMAIN: &[u8] = b"AIN1-MONETARY-STATE-ROOT-V3\0";
const MONETARY_POLICY_DOMAIN: &[u8] = b"AIN1-MONETARY-POLICY-CANDIDATE-V3\0";
const MONETARY_SNAPSHOT_OVERHEAD: usize = 4 + 2 + 32 + 16 + 4 + 32;
const MAX_ENCODED_MONETARY_SNAPSHOT_BYTES: usize =
    MAX_ENCODED_SNAPSHOT_BYTES + MONETARY_SNAPSHOT_OVERHEAD;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonetaryBlock {
    /// The existing transaction/block fields, whose state_root commits to the monetary root
    /// when this envelope is used (not to the legacy BLK2-only root).
    pub body: Block,
    pub miner: AccountId,
    pub claimed_subsidy_atoms: u64,
}

/// Versioned hybrid block candidate. It is intentionally a separate type from MBK3 so a
/// TXN4 envelope can never be silently downgraded into a TXN2 transaction during serialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V4HybridMonetaryBlock {
    pub height: u64,
    pub timestamp: u64,
    pub parent_hash: [u8; 32],
    pub state_root: [u8; 32],
    pub transactions: Vec<crate::v4_account_identity_candidate::V4HybridTransaction>,
    pub miner: AccountId,
    pub claimed_subsidy_atoms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonetaryLedgerState {
    ledger: LedgerState,
    total_mined_atoms: u128,
}

fn monetary_policy_fingerprint() -> [u8; 32] {
    let max_supply = MAX_TOTAL_SUPPLY_ATOMS.to_be_bytes();
    let founder = MONETARY_FOUNDER_ALLOCATION_ATOMS.to_be_bytes();
    let miner_budget = MONETARY_MINER_BUDGET_ATOMS.to_be_bytes();
    let public_goods = MONETARY_PUBLIC_GOODS_BUDGET_ATOMS.to_be_bytes();
    let subsidy = MONETARY_INITIAL_SUBSIDY_ATOMS.to_be_bytes();
    let halving = MONETARY_BLOCKS_PER_HALVING.to_be_bytes();
    let decimals = 8u16.to_be_bytes();
    hash_domain(
        MONETARY_POLICY_DOMAIN,
        &[
            &max_supply,
            &founder,
            &miner_budget,
            &public_goods,
            &subsidy,
            &halving,
            &decimals,
        ],
    )
}

/// Use the shared issuance-schedule implementation for the monetary ledger candidate.
/// The budget/subsidy/halving constants above remain provisional design inputs; this wiring
/// prevents candidate state execution from drifting away from the reusable schedule model.
fn monetary_issuance_parameters() -> crate::issuance_schedule::IssuanceParameters {
    crate::issuance_schedule::IssuanceParameters::new(
        MONETARY_MINER_BUDGET_ATOMS,
        MONETARY_INITIAL_SUBSIDY_ATOMS,
        MONETARY_BLOCKS_PER_HALVING,
    )
    .expect("monetary candidate constants must remain valid")
}

fn monetary_issuance_after_blocks(blocks_mined: u64) -> u128 {
    monetary_issuance_parameters().cumulative_issuance_after_blocks(blocks_mined)
}

/// Derive the subsidy for a 1-based native block height from the shared issuance model.
/// Current mined supply comes only from the already-validated monetary ledger state.
fn monetary_reward_for_height(
    block_height: u64,
    current_mined_atoms: u128,
) -> Result<u128, StateError> {
    let schedule_height = block_height
        .checked_sub(1)
        .ok_or(StateError::InvalidHeight)?;
    monetary_issuance_parameters()
        .reward_for_block(schedule_height, current_mined_atoms)
        .map_err(|error| match error {
            crate::issuance_schedule::IssuanceError::CurrentSupplyAboveMaximum => {
                StateError::MinerBudgetExceeded
            }
            _ => StateError::InvariantViolation,
        })
}

/// Encode a versioned monetary envelope around a canonical BLK2 transaction body.
/// The outer bytes, not the inner BLK2 bytes alone, determine the monetary block ID.
pub fn encode_monetary_block(block: &MonetaryBlock) -> Result<Vec<u8>, StateError> {
    if is_zero_account(&block.miner) {
        return Err(StateError::InvalidAccountId);
    }
    if block.claimed_subsidy_atoms as u128 > MONETARY_MINER_BUDGET_ATOMS {
        return Err(StateError::MinerBudgetExceeded);
    }
    let body = encode_block(&block.body)?;
    let body_len = u32::try_from(body.len()).map_err(|_| StateError::Malformed)?;
    let mut out = Vec::with_capacity(MONETARY_BLOCK_FIXED_OVERHEAD + body.len());
    out.extend_from_slice(&MONETARY_BLOCK_MAGIC);
    out.extend_from_slice(&MONETARY_FORMAT_VERSION.to_be_bytes());
    out.extend_from_slice(&body_len.to_be_bytes());
    out.extend_from_slice(&body);
    out.extend_from_slice(&block.miner);
    out.extend_from_slice(&block.claimed_subsidy_atoms.to_be_bytes());
    if out.len() > MAX_ENCODED_MONETARY_BLOCK_BYTES {
        return Err(StateError::Oversize {
            actual: out.len(),
            limit: MAX_ENCODED_MONETARY_BLOCK_BYTES,
        });
    }
    Ok(out)
}

pub fn decode_monetary_block(bytes: &[u8]) -> Result<MonetaryBlock, StateError> {
    if bytes.len() > MAX_ENCODED_MONETARY_BLOCK_BYTES {
        return Err(StateError::Oversize {
            actual: bytes.len(),
            limit: MAX_ENCODED_MONETARY_BLOCK_BYTES,
        });
    }
    if bytes.len() < MONETARY_BLOCK_FIXED_OVERHEAD {
        return Err(StateError::Malformed);
    }
    let mut cursor = Cursor::new(bytes);
    if read_array::<4>(&mut cursor)? != MONETARY_BLOCK_MAGIC {
        return Err(StateError::BadMagic);
    }
    let version = read_u16(&mut cursor)?;
    if version != MONETARY_FORMAT_VERSION {
        return Err(StateError::UnsupportedVersion(version));
    }
    let body_len = read_u32(&mut cursor)? as usize;
    if !(BLOCK_HEADER_LEN..=MAX_ENCODED_BLOCK_BYTES).contains(&body_len) {
        return Err(StateError::Malformed);
    }
    let mut body_bytes = vec![0u8; body_len];
    cursor
        .read_exact(&mut body_bytes)
        .map_err(|_| StateError::Malformed)?;
    let body = decode_block(&body_bytes)?;
    let miner = read_array(&mut cursor)?;
    if is_zero_account(&miner) {
        return Err(StateError::InvalidAccountId);
    }
    let claimed_subsidy_atoms = read_u64(&mut cursor)?;
    if cursor.position() as usize != bytes.len() {
        return Err(StateError::Malformed);
    }
    let block = MonetaryBlock {
        body,
        miner,
        claimed_subsidy_atoms,
    };
    // Re-encoding ensures exactly one canonical representation.
    if encode_monetary_block(&block)? != bytes {
        return Err(StateError::Malformed);
    }
    Ok(block)
}

pub fn monetary_block_id(block: &MonetaryBlock) -> Result<[u8; 32], StateError> {
    let canonical = encode_monetary_block(block)?;
    Ok(hash_domain(b"AIN1-MONETARY-BLOCK-ID-V3\0", &[&canonical]))
}

/// Canonical MBK4 codec. Unlike MBK3, every transaction is an exact fixed-width TXN4 envelope.
/// Legacy MBK3 bytes, transaction encoding and block ID remain unchanged.
pub fn encode_v4_hybrid_monetary_block(
    block: &V4HybridMonetaryBlock,
) -> Result<Vec<u8>, StateError> {
    use crate::v4_account_identity_candidate::V4_HYBRID_TRANSACTION_WIRE_BYTES;

    if is_zero_account(&block.miner) {
        return Err(StateError::InvalidAccountId);
    }
    if block.transactions.len() > MAX_TRANSACTIONS_PER_BLOCK {
        return Err(StateError::TooManyTransactions(block.transactions.len()));
    }
    if block.claimed_subsidy_atoms as u128 > MONETARY_MINER_BUDGET_ATOMS {
        return Err(StateError::MinerBudgetExceeded);
    }
    let mut out = Vec::with_capacity(
        V4_HYBRID_MONETARY_FIXED_OVERHEAD
            + block.transactions.len() * V4_HYBRID_TRANSACTION_WIRE_BYTES,
    );
    out.extend_from_slice(&V4_HYBRID_MONETARY_BLOCK_MAGIC);
    out.extend_from_slice(&V4_HYBRID_MONETARY_FORMAT_VERSION.to_be_bytes());
    out.extend_from_slice(&block.height.to_be_bytes());
    out.extend_from_slice(&block.timestamp.to_be_bytes());
    out.extend_from_slice(&block.parent_hash);
    out.extend_from_slice(&block.state_root);
    out.extend_from_slice(
        &u32::try_from(block.transactions.len())
            .map_err(|_| StateError::TooManyTransactions(block.transactions.len()))?
            .to_be_bytes(),
    );
    for tx in &block.transactions {
        let canonical_tx = tx
            .encode()
            .map_err(|_| StateError::InvalidHybridAuthorization)?;
        if canonical_tx.len() != V4_HYBRID_TRANSACTION_WIRE_BYTES {
            return Err(StateError::Malformed);
        }
        out.extend_from_slice(&canonical_tx);
    }
    out.extend_from_slice(&block.miner);
    out.extend_from_slice(&block.claimed_subsidy_atoms.to_be_bytes());
    if out.len() > MAX_ENCODED_V4_HYBRID_MONETARY_BLOCK_BYTES {
        return Err(StateError::Oversize {
            actual: out.len(),
            limit: MAX_ENCODED_V4_HYBRID_MONETARY_BLOCK_BYTES,
        });
    }
    Ok(out)
}

pub fn decode_v4_hybrid_monetary_block(bytes: &[u8]) -> Result<V4HybridMonetaryBlock, StateError> {
    use crate::v4_account_identity_candidate::V4_HYBRID_TRANSACTION_WIRE_BYTES;

    if bytes.len() > MAX_ENCODED_V4_HYBRID_MONETARY_BLOCK_BYTES {
        return Err(StateError::Oversize {
            actual: bytes.len(),
            limit: MAX_ENCODED_V4_HYBRID_MONETARY_BLOCK_BYTES,
        });
    }
    if bytes.len() < V4_HYBRID_MONETARY_FIXED_OVERHEAD {
        return Err(StateError::Malformed);
    }
    let mut cursor = Cursor::new(bytes);
    if read_array::<4>(&mut cursor)? != V4_HYBRID_MONETARY_BLOCK_MAGIC {
        return Err(StateError::BadMagic);
    }
    let version = read_u16(&mut cursor)?;
    if version != V4_HYBRID_MONETARY_FORMAT_VERSION {
        return Err(StateError::UnsupportedVersion(version));
    }
    let height = read_u64(&mut cursor)?;
    let timestamp = read_u64(&mut cursor)?;
    let parent_hash = read_array(&mut cursor)?;
    let state_root = read_array(&mut cursor)?;
    let transaction_count = read_u32(&mut cursor)? as usize;
    if transaction_count > MAX_TRANSACTIONS_PER_BLOCK {
        return Err(StateError::TooManyTransactions(transaction_count));
    }
    let expected_len = V4_HYBRID_MONETARY_FIXED_OVERHEAD
        .checked_add(
            transaction_count
                .checked_mul(V4_HYBRID_TRANSACTION_WIRE_BYTES)
                .ok_or(StateError::Malformed)?,
        )
        .ok_or(StateError::Malformed)?;
    if bytes.len() != expected_len {
        return Err(StateError::Malformed);
    }
    let mut transactions = Vec::with_capacity(transaction_count);
    for _ in 0..transaction_count {
        let mut tx_bytes = vec![0u8; V4_HYBRID_TRANSACTION_WIRE_BYTES];
        cursor
            .read_exact(&mut tx_bytes)
            .map_err(|_| StateError::Malformed)?;
        let tx = crate::v4_account_identity_candidate::V4HybridTransaction::decode(&tx_bytes)
            .map_err(|_| StateError::InvalidHybridAuthorization)?;
        transactions.push(tx);
    }
    let miner = read_array(&mut cursor)?;
    if is_zero_account(&miner) {
        return Err(StateError::InvalidAccountId);
    }
    let claimed_subsidy_atoms = read_u64(&mut cursor)?;
    if cursor.position() as usize != bytes.len() {
        return Err(StateError::Malformed);
    }
    let block = V4HybridMonetaryBlock {
        height,
        timestamp,
        parent_hash,
        state_root,
        transactions,
        miner,
        claimed_subsidy_atoms,
    };
    if encode_v4_hybrid_monetary_block(&block)? != bytes {
        return Err(StateError::Malformed);
    }
    Ok(block)
}

pub fn v4_hybrid_monetary_block_id(block: &V4HybridMonetaryBlock) -> Result<[u8; 32], StateError> {
    let canonical = encode_v4_hybrid_monetary_block(block)?;
    Ok(hash_domain(b"AIN1-MONETARY-BLOCK-ID-V4\\0", &[&canonical]))
}

impl MonetaryLedgerState {
    /// Build a candidate Genesis with the directed 4B founder / 3B public-goods split.
    /// Account identifiers must come from a separate reviewed key ceremony; this function
    /// generates no keys, and is not a production Genesis builder.
    pub fn genesis(
        network_id: NetworkId,
        founder_account: AccountId,
        public_goods_accounts: Vec<(AccountId, u64)>,
    ) -> Result<Self, StateError> {
        let mut public_goods_total = 0u128;
        let mut accounts = Vec::with_capacity(public_goods_accounts.len() + 1);
        accounts.push((
            founder_account,
            u64::try_from(MONETARY_FOUNDER_ALLOCATION_ATOMS)
                .map_err(|_| StateError::InvariantViolation)?,
        ));
        for (account, amount) in public_goods_accounts {
            if amount == 0 {
                return Err(StateError::InvalidMonetaryAllocation);
            }
            public_goods_total = public_goods_total
                .checked_add(amount as u128)
                .ok_or(StateError::InvariantViolation)?;
            accounts.push((account, amount));
        }
        if public_goods_total != MONETARY_PUBLIC_GOODS_BUDGET_ATOMS {
            return Err(StateError::InvalidMonetaryAllocation);
        }
        let ledger = LedgerState::genesis(network_id, accounts)?;
        if ledger.total_value()?
            != MONETARY_FOUNDER_ALLOCATION_ATOMS + MONETARY_PUBLIC_GOODS_BUDGET_ATOMS
        {
            return Err(StateError::InvalidMonetaryAllocation);
        }
        Ok(Self {
            ledger,
            total_mined_atoms: 0,
        })
    }

    pub fn ledger(&self) -> &LedgerState {
        &self.ledger
    }

    pub fn height(&self) -> u64 {
        self.ledger.height()
    }

    pub fn tip_hash(&self) -> [u8; 32] {
        self.ledger.tip_hash()
    }

    pub fn total_mined_atoms(&self) -> u128 {
        self.total_mined_atoms
    }

    pub fn total_value(&self) -> Result<u128, StateError> {
        let total = self.ledger.total_value()?;
        let expected = MONETARY_FOUNDER_ALLOCATION_ATOMS
            .checked_add(MONETARY_PUBLIC_GOODS_BUDGET_ATOMS)
            .and_then(|v| v.checked_add(self.total_mined_atoms))
            .ok_or(StateError::InvariantViolation)?;
        if total != expected
            || self.total_mined_atoms != monetary_issuance_after_blocks(self.height())
        {
            return Err(StateError::InvariantViolation);
        }
        if total > MAX_TOTAL_SUPPLY_ATOMS {
            return Err(StateError::SupplyCapExceeded);
        }
        Ok(total)
    }

    /// Monetary root commits to the legacy account root, the deterministic cumulative miner
    /// counter and the exact candidate policy. The tip hash is excluded to avoid a hash cycle.
    pub fn state_root(&self) -> [u8; 32] {
        let mined = self.total_mined_atoms.to_be_bytes();
        let policy = monetary_policy_fingerprint();
        let ledger_root = self.ledger.state_root();
        hash_domain(MONETARY_STATE_ROOT_DOMAIN, &[&policy, &ledger_root, &mined])
    }

    /// The subsidy for the next height is derived from height and cumulative scheduled issuance,
    /// not from miner-supplied input. First post-Genesis block (height 1) uses schedule index 0.
    pub fn expected_miner_reward(&self) -> Result<u64, StateError> {
        self.total_value()?;
        let next_height = self
            .height()
            .checked_add(1)
            .ok_or(StateError::InvalidHeight)?;
        let reward = monetary_reward_for_height(next_height, self.total_mined_atoms)?;
        u64::try_from(reward).map_err(|_| StateError::InvariantViolation)
    }

    fn prepare_monetary_candidate<A: TransactionAuthenticator>(
        &self,
        block: &MonetaryBlock,
        authenticator: &A,
    ) -> Result<(LedgerState, u128, u64), StateError> {
        self.total_value()?;
        encode_monetary_block(block)?;
        let (mut next, fees_collected) =
            self.ledger.prepare_candidate(&block.body, authenticator)?;
        let expected_reward =
            monetary_reward_for_height(block.body.height, self.total_mined_atoms)?;
        let claimed_reward = block.claimed_subsidy_atoms as u128;
        if claimed_reward != expected_reward {
            return Err(StateError::MinerRewardMismatch {
                expected: u64::try_from(expected_reward).unwrap_or(u64::MAX),
                actual: block.claimed_subsidy_atoms,
            });
        }
        let total_mined_atoms = self
            .total_mined_atoms
            .checked_add(claimed_reward)
            .ok_or(StateError::InvariantViolation)?;
        if total_mined_atoms > MONETARY_MINER_BUDGET_ATOMS {
            return Err(StateError::MinerBudgetExceeded);
        }
        if total_mined_atoms != monetary_issuance_after_blocks(block.body.height) {
            return Err(StateError::InvariantViolation);
        }
        if claimed_reward != 0 {
            let old = next.accounts.get(&block.miner).copied();
            if old.is_none() && next.accounts.len() >= MAX_ACCOUNTS {
                return Err(StateError::TooManyAccounts);
            }
            let prior_balance = old.map_or(0, |account| account.balance);
            let balance = prior_balance
                .checked_add(block.claimed_subsidy_atoms)
                .ok_or(StateError::BalanceOverflow)?;
            next.accounts.insert(
                block.miner,
                AccountState {
                    balance,
                    nonce: old.map_or(0, |account| account.nonce),
                },
            );
        }
        let expected_total = MONETARY_FOUNDER_ALLOCATION_ATOMS
            .checked_add(MONETARY_PUBLIC_GOODS_BUDGET_ATOMS)
            .and_then(|v| v.checked_add(total_mined_atoms))
            .ok_or(StateError::InvariantViolation)?;
        if next.total_value()? != expected_total || expected_total > MAX_TOTAL_SUPPLY_ATOMS {
            return Err(StateError::SupplyCapExceeded);
        }
        Ok((next, total_mined_atoms, fees_collected))
    }

    fn prepare_v4_hybrid_monetary_candidate<
        V: crate::v4_account_identity_candidate::MlDsa65Verifier,
    >(
        &self,
        block: &V4HybridMonetaryBlock,
        expected_manifest_id: &[u8; 32],
        verifier: &V,
    ) -> Result<(LedgerState, u128, u64), StateError> {
        self.total_value()?;
        encode_v4_hybrid_monetary_block(block)?;
        if block.height
            != self
                .height()
                .checked_add(1)
                .ok_or(StateError::InvalidHeight)?
        {
            return Err(StateError::HeightMismatch {
                expected: self.height().saturating_add(1),
                actual: block.height,
            });
        }
        if block.parent_hash != self.tip_hash() {
            return Err(StateError::ParentHashMismatch);
        }
        if block.timestamp <= self.ledger.last_timestamp() {
            return Err(StateError::TimestampNotIncreasing {
                previous: self.ledger.last_timestamp(),
                actual: block.timestamp,
            });
        }

        let mut next = self.ledger.clone();
        let mut local_txids = BTreeSet::new();
        let mut fees_collected = 0u64;
        for tx in &block.transactions {
            let authorization = &tx.authorization;
            if authorization.network_id != self.ledger.network_id {
                return Err(StateError::WrongNetwork);
            }
            if &authorization.manifest_id != expected_manifest_id {
                return Err(StateError::ManifestMismatch);
            }
            if block.timestamp >= authorization.expires_at {
                return Err(StateError::TransactionExpired {
                    expires_at: authorization.expires_at,
                    block_timestamp: block.timestamp,
                });
            }
            let canonical_tx = tx
                .encode()
                .map_err(|_| StateError::InvalidHybridAuthorization)?;
            let txid = hash_domain(b"AIN1-TXN4-ID-V4\\0", &[&canonical_tx]);
            if !local_txids.insert(txid) {
                return Err(StateError::DuplicateTransaction);
            }
            tx.verify(verifier).map_err(|_| StateError::Unauthorized)?;

            // Reuse the established account/nonce/balance/fee checks only after the full TXN4
            // envelope has been verified. This projection is internal execution data, not wire
            // encoding; the canonical block ID is computed from the actual TXN4 bytes below.
            let projected = Transaction {
                network_id: authorization.network_id,
                sender: authorization.sender_id,
                recipient: authorization.recipient_id,
                nonce: authorization.nonce,
                amount: authorization.amount_atoms,
                fee: authorization.fee_atoms,
                expires_at: authorization.expires_at,
                signature: Vec::new(),
            };
            next.apply_transaction(&projected)?;
            fees_collected = fees_collected
                .checked_add(authorization.fee_atoms)
                .ok_or(StateError::FeeOverflow)?;
        }

        let expected_reward = monetary_reward_for_height(block.height, self.total_mined_atoms)?;
        if block.claimed_subsidy_atoms as u128 != expected_reward {
            return Err(StateError::MinerRewardMismatch {
                expected: u64::try_from(expected_reward).unwrap_or(u64::MAX),
                actual: block.claimed_subsidy_atoms,
            });
        }
        let total_mined_atoms = self
            .total_mined_atoms
            .checked_add(expected_reward)
            .ok_or(StateError::InvariantViolation)?;
        if total_mined_atoms > MONETARY_MINER_BUDGET_ATOMS
            || total_mined_atoms != monetary_issuance_after_blocks(block.height)
        {
            return Err(StateError::MinerBudgetExceeded);
        }
        if expected_reward != 0 {
            let old = next.accounts.get(&block.miner).copied();
            if old.is_none() && next.accounts.len() >= MAX_ACCOUNTS {
                return Err(StateError::TooManyAccounts);
            }
            let balance = old
                .map_or(0, |account| account.balance)
                .checked_add(block.claimed_subsidy_atoms)
                .ok_or(StateError::BalanceOverflow)?;
            next.accounts.insert(
                block.miner,
                AccountState {
                    balance,
                    nonce: old.map_or(0, |account| account.nonce),
                },
            );
        }

        let expected_total = MONETARY_FOUNDER_ALLOCATION_ATOMS
            .checked_add(MONETARY_PUBLIC_GOODS_BUDGET_ATOMS)
            .and_then(|value| value.checked_add(total_mined_atoms))
            .ok_or(StateError::InvariantViolation)?;
        if next.total_value()? != expected_total || expected_total > MAX_TOTAL_SUPPLY_ATOMS {
            return Err(StateError::SupplyCapExceeded);
        }
        next.height = block.height;
        next.last_timestamp = block.timestamp;
        Ok((next, total_mined_atoms, fees_collected))
    }

    pub fn preview_v4_hybrid_state_root_after<
        V: crate::v4_account_identity_candidate::MlDsa65Verifier,
    >(
        &self,
        block: &V4HybridMonetaryBlock,
        expected_manifest_id: &[u8; 32],
        verifier: &V,
    ) -> Result<[u8; 32], StateError> {
        let (next, total_mined_atoms, _) =
            self.prepare_v4_hybrid_monetary_candidate(block, expected_manifest_id, verifier)?;
        let mined = total_mined_atoms.to_be_bytes();
        let policy = monetary_policy_fingerprint();
        let next_root = next.state_root();
        Ok(hash_domain(
            MONETARY_STATE_ROOT_DOMAIN,
            &[&policy, &next_root, &mined],
        ))
    }

    /// Atomically execute a versioned MBK4 block after validating every TXN4 envelope.
    /// This candidate path is not yet wired to the PMT3/PFM3 node import/fork-choice runtime.
    pub fn apply_v4_hybrid_block_candidate<
        V: crate::v4_account_identity_candidate::MlDsa65Verifier,
    >(
        &mut self,
        block: &V4HybridMonetaryBlock,
        expected_manifest_id: &[u8; 32],
        verifier: &V,
    ) -> Result<BlockApplySummary, StateError> {
        let canonical = encode_v4_hybrid_monetary_block(block)?;
        let (mut next, total_mined_atoms, fees_collected) =
            self.prepare_v4_hybrid_monetary_candidate(block, expected_manifest_id, verifier)?;
        let mined = total_mined_atoms.to_be_bytes();
        let policy = monetary_policy_fingerprint();
        let next_root = next.state_root();
        let computed_state_root =
            hash_domain(MONETARY_STATE_ROOT_DOMAIN, &[&policy, &next_root, &mined]);
        if computed_state_root != block.state_root {
            return Err(StateError::StateRootMismatch);
        }
        let block_hash = hash_domain(b"AIN1-MONETARY-BLOCK-ID-V4\\0", &[&canonical]);
        next.tip_hash = block_hash;
        let summary = BlockApplySummary {
            height: next.height,
            block_hash,
            state_root: computed_state_root,
            transactions_applied: block.transactions.len(),
            fees_collected,
            account_count: next.account_count(),
        };
        self.ledger = next;
        self.total_mined_atoms = total_mined_atoms;
        Ok(summary)
    }

    pub(crate) fn apply_v4_hybrid_block_with_timestamp_policy<
        V: crate::v4_account_identity_candidate::MlDsa65Verifier,
    >(
        &mut self,
        block: &V4HybridMonetaryBlock,
        expected_manifest_id: &[u8; 32],
        verifier: &V,
        reference_time: u64,
        policy: TimestampPolicy,
    ) -> Result<BlockApplySummary, StateError> {
        encode_v4_hybrid_monetary_block(block)?;
        let expected_height = self
            .height()
            .checked_add(1)
            .ok_or(StateError::InvalidHeight)?;
        if block.height != expected_height {
            return Err(StateError::HeightMismatch {
                expected: expected_height,
                actual: block.height,
            });
        }
        if block.parent_hash != self.tip_hash() {
            return Err(StateError::ParentHashMismatch);
        }
        validate_block_timestamp(
            self.ledger.last_timestamp(),
            block.timestamp,
            reference_time,
            policy,
        )
        .map_err(|error| match error {
            TimestampPolicyError::ZeroTimestamp => StateError::InvalidBlockTimestamp,
            TimestampPolicyError::NotIncreasing { previous, actual } => {
                StateError::TimestampNotIncreasing { previous, actual }
            }
            TimestampPolicyError::TooFarInFuture {
                latest_allowed,
                actual,
            } => StateError::TimestampTooFarInFuture {
                latest_allowed,
                actual,
            },
        })?;
        self.apply_v4_hybrid_block_candidate(block, expected_manifest_id, verifier)
    }

    pub fn preview_state_root_after<A: TransactionAuthenticator>(
        &self,
        block: &MonetaryBlock,
        authenticator: &A,
    ) -> Result<[u8; 32], StateError> {
        let (next, total_mined_atoms, _) = self.prepare_monetary_candidate(block, authenticator)?;
        let mined = total_mined_atoms.to_be_bytes();
        let policy = monetary_policy_fingerprint();
        let root = next.state_root();
        Ok(hash_domain(
            MONETARY_STATE_ROOT_DOMAIN,
            &[&policy, &root, &mined],
        ))
    }

    pub(crate) fn apply_block_with_timestamp_policy<A: TransactionAuthenticator>(
        &mut self,
        block: &MonetaryBlock,
        authenticator: &A,
        reference_time: u64,
        policy: TimestampPolicy,
    ) -> Result<BlockApplySummary, StateError> {
        encode_monetary_block(block)?;
        let expected_height = self
            .height()
            .checked_add(1)
            .ok_or(StateError::InvalidHeight)?;
        if block.body.height != expected_height {
            return Err(StateError::HeightMismatch {
                expected: expected_height,
                actual: block.body.height,
            });
        }
        if block.body.parent_hash != self.tip_hash() {
            return Err(StateError::ParentHashMismatch);
        }
        validate_block_timestamp(
            self.ledger.last_timestamp(),
            block.body.timestamp,
            reference_time,
            policy,
        )
        .map_err(|error| match error {
            TimestampPolicyError::ZeroTimestamp => StateError::InvalidBlockTimestamp,
            TimestampPolicyError::NotIncreasing { previous, actual } => {
                StateError::TimestampNotIncreasing { previous, actual }
            }
            TimestampPolicyError::TooFarInFuture {
                latest_allowed,
                actual,
            } => StateError::TimestampTooFarInFuture {
                latest_allowed,
                actual,
            },
        })?;
        self.apply_block(block, authenticator)
    }

    /// Atomically apply transactions plus the exact scheduled miner subsidy.
    /// Failure leaves balances, issuance count, tip and height unchanged.
    pub fn apply_block<A: TransactionAuthenticator>(
        &mut self,
        block: &MonetaryBlock,
        authenticator: &A,
    ) -> Result<BlockApplySummary, StateError> {
        let canonical = encode_monetary_block(block)?;
        let (mut next, total_mined_atoms, fees_collected) =
            self.prepare_monetary_candidate(block, authenticator)?;
        let mined = total_mined_atoms.to_be_bytes();
        let policy = monetary_policy_fingerprint();
        let next_root = next.state_root();
        let computed_state_root =
            hash_domain(MONETARY_STATE_ROOT_DOMAIN, &[&policy, &next_root, &mined]);
        if computed_state_root != block.body.state_root {
            return Err(StateError::StateRootMismatch);
        }
        let block_hash = hash_domain(b"AIN1-MONETARY-BLOCK-ID-V3\0", &[&canonical]);
        next.tip_hash = block_hash;
        let summary = BlockApplySummary {
            height: next.height,
            block_hash,
            state_root: computed_state_root,
            transactions_applied: block.body.transactions.len(),
            fees_collected,
            account_count: next.account_count(),
        };
        self.ledger = next;
        self.total_mined_atoms = total_mined_atoms;
        Ok(summary)
    }

    /// Durable candidate snapshot binds the nested account snapshot, cumulative issuance and
    /// the exact monetary policy. It detects malformed/stale values but is not anti-rollback.
    pub fn encode_snapshot(&self) -> Result<Vec<u8>, StateError> {
        self.total_value()?;
        let ledger_bytes = self.ledger.encode_snapshot()?;
        let len = u32::try_from(ledger_bytes.len()).map_err(|_| StateError::Malformed)?;
        let mut out = Vec::with_capacity(MONETARY_SNAPSHOT_OVERHEAD + ledger_bytes.len());
        out.extend_from_slice(&MONETARY_SNAPSHOT_MAGIC);
        out.extend_from_slice(&MONETARY_SNAPSHOT_VERSION.to_be_bytes());
        out.extend_from_slice(&monetary_policy_fingerprint());
        out.extend_from_slice(&self.total_mined_atoms.to_be_bytes());
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&ledger_bytes);
        if out.len() + 32 > MAX_ENCODED_MONETARY_SNAPSHOT_BYTES {
            return Err(StateError::Oversize {
                actual: out.len() + 32,
                limit: MAX_ENCODED_MONETARY_SNAPSHOT_BYTES,
            });
        }
        let checksum = hash_domain(MONETARY_SNAPSHOT_CHECKSUM_DOMAIN, &[&out]);
        out.extend_from_slice(&checksum);
        Ok(out)
    }

    pub fn decode_snapshot(
        bytes: &[u8],
        expected_network_id: &NetworkId,
    ) -> Result<Self, StateError> {
        if bytes.len() > MAX_ENCODED_MONETARY_SNAPSHOT_BYTES {
            return Err(StateError::Oversize {
                actual: bytes.len(),
                limit: MAX_ENCODED_MONETARY_SNAPSHOT_BYTES,
            });
        }
        if bytes.len() < MONETARY_SNAPSHOT_OVERHEAD + SNAPSHOT_HEADER_LEN {
            return Err(StateError::Malformed);
        }
        let payload_len = bytes.len() - 32;
        let checksum = hash_domain(MONETARY_SNAPSHOT_CHECKSUM_DOMAIN, &[&bytes[..payload_len]]);
        if bytes[payload_len..] != checksum[..] {
            return Err(StateError::MonetarySnapshotChecksumMismatch);
        }
        let mut cursor = Cursor::new(&bytes[..payload_len]);
        if read_array::<4>(&mut cursor)? != MONETARY_SNAPSHOT_MAGIC {
            return Err(StateError::BadMagic);
        }
        let version = read_u16(&mut cursor)?;
        if version != MONETARY_SNAPSHOT_VERSION {
            return Err(StateError::UnsupportedVersion(version));
        }
        let policy = read_array::<32>(&mut cursor)?;
        if policy != monetary_policy_fingerprint() {
            return Err(StateError::MonetaryPolicyMismatch);
        }
        let total_mined_atoms = u128::from_be_bytes(read_array::<16>(&mut cursor)?);
        let ledger_len = read_u32(&mut cursor)? as usize;
        if !(SNAPSHOT_HEADER_LEN + SNAPSHOT_CHECKSUM_LEN..=MAX_ENCODED_SNAPSHOT_BYTES)
            .contains(&ledger_len)
        {
            return Err(StateError::Malformed);
        }
        let mut ledger_bytes = vec![0u8; ledger_len];
        cursor
            .read_exact(&mut ledger_bytes)
            .map_err(|_| StateError::Malformed)?;
        if cursor.position() as usize != payload_len {
            return Err(StateError::Malformed);
        }
        let ledger = LedgerState::decode_snapshot(&ledger_bytes, expected_network_id)?;
        let restored = Self {
            ledger,
            total_mined_atoms,
        };
        restored.total_value()?;
        Ok(restored)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_NETWORK_ID: NetworkId = [0xAA; 32];

    // Test-only deterministic authorization; this is not a cryptographic signature.
    struct TestOnlyAuthenticator;

    fn test_signature(sender: &AccountId, digest: &[u8; 32]) -> Vec<u8> {
        hash_domain(b"CP0026A-TEST-ONLY-AUTH\0", &[sender, digest]).to_vec()
    }

    impl TransactionAuthenticator for TestOnlyAuthenticator {
        fn verify(
            &self,
            sender: &AccountId,
            signing_digest: &[u8; 32],
            signature: &[u8],
        ) -> Result<(), ()> {
            if signature == test_signature(sender, signing_digest) {
                Ok(())
            } else {
                Err(())
            }
        }
    }

    fn account(byte: u8) -> AccountId {
        [byte; 32]
    }

    fn signed_tx(
        sender: AccountId,
        recipient: AccountId,
        nonce: u64,
        amount: u64,
        fee: u64,
    ) -> Transaction {
        let mut tx = Transaction {
            network_id: TEST_NETWORK_ID,
            sender,
            recipient,
            nonce,
            amount,
            fee,
            expires_at: 10_000,
            signature: Vec::new(),
        };
        tx.signature = test_signature(&tx.sender, &transaction_signing_digest(&tx).unwrap());
        tx
    }

    fn block(height: u64, parent_hash: [u8; 32], transactions: Vec<Transaction>) -> Block {
        Block {
            height,
            timestamp: height * 1_000,
            parent_hash,
            state_root: [0; 32],
            transactions,
        }
    }

    fn alice_bob_state() -> LedgerState {
        LedgerState::genesis(TEST_NETWORK_ID, vec![(account(1), 1_000), (account(2), 5)]).unwrap()
    }

    fn committed_block(state: &LedgerState, transactions: Vec<Transaction>) -> Block {
        let mut candidate = block(state.height() + 1, state.tip_hash(), transactions);
        candidate.state_root = state
            .preview_state_root_after(&candidate, &TestOnlyAuthenticator)
            .unwrap();
        candidate
    }

    #[test]
    fn genesis_and_live_ledger_enforce_the_ten_billion_coin_cap() {
        let at_cap = LedgerState::genesis(
            TEST_NETWORK_ID,
            vec![(account(1), MAX_TOTAL_SUPPLY_ATOMS as u64)],
        )
        .unwrap();
        assert_eq!(at_cap.total_value(), Ok(MAX_TOTAL_SUPPLY_ATOMS));

        assert_eq!(
            LedgerState::genesis(
                TEST_NETWORK_ID,
                vec![(account(1), MAX_TOTAL_SUPPLY_ATOMS as u64), (account(2), 1),],
            ),
            Err(StateError::SupplyCapExceeded)
        );
        assert_eq!(
            LedgerState::genesis(
                TEST_NETWORK_ID,
                vec![(account(1), MAX_TOTAL_SUPPLY_ATOMS as u64 + 1)],
            ),
            Err(StateError::SupplyCapExceeded)
        );
    }

    #[test]
    fn checksum_valid_snapshot_cannot_bypass_the_hard_supply_cap() {
        let genesis = LedgerState::genesis(TEST_NETWORK_ID, vec![(account(1), 100)]).unwrap();
        let mut snapshot = genesis.encode_snapshot().unwrap();
        let balance_start = SNAPSHOT_HEADER_LEN + 32;
        snapshot[balance_start..balance_start + 8]
            .copy_from_slice(&(MAX_TOTAL_SUPPLY_ATOMS as u64 + 1).to_be_bytes());

        // Recompute the unkeyed checksum to model a deliberately constructed over-cap snapshot,
        // not simple accidental corruption. Supply policy must reject it independently.
        let checksum_start = snapshot.len() - SNAPSHOT_CHECKSUM_LEN;
        let checksum = hash_domain(SNAPSHOT_CHECKSUM_DOMAIN, &[&snapshot[..checksum_start]]);
        snapshot[checksum_start..].copy_from_slice(&checksum);
        assert_eq!(
            LedgerState::decode_snapshot(&snapshot, &TEST_NETWORK_ID),
            Err(StateError::SupplyCapExceeded)
        );
    }

    #[test]
    fn cp0026c_network_binding_expiry_boundary_and_snapshot_domain_replay_reject() {
        let network_b = [0xBBu8; 32];
        let initial_accounts = vec![(account(1), 1_000), (account(2), 5)];
        let mut state_a = LedgerState::genesis(TEST_NETWORK_ID, initial_accounts.clone()).unwrap();
        let state_before = state_a.encode_snapshot().unwrap();

        // A correctly formed transaction signed for another network must not execute here.
        let mut cross_network = signed_tx(account(1), account(2), 1, 100, 2);
        cross_network.network_id = network_b;
        cross_network.signature = test_signature(
            &cross_network.sender,
            &transaction_signing_digest(&cross_network).unwrap(),
        );
        let cross_block = block(1, state_a.tip_hash(), vec![cross_network]);
        assert_eq!(
            state_a.apply_block(&cross_block, &TestOnlyAuthenticator),
            Err(StateError::WrongNetwork)
        );
        assert_eq!(state_a.encode_snapshot().unwrap(), state_before);

        // Expiry is exclusive: timestamp expiry-1 is valid; exactly expiry is expired.
        let mut before_boundary_tx = signed_tx(account(1), account(2), 1, 100, 2);
        before_boundary_tx.expires_at = 2_000;
        before_boundary_tx.signature = test_signature(
            &before_boundary_tx.sender,
            &transaction_signing_digest(&before_boundary_tx).unwrap(),
        );
        let mut before_boundary_block = block(1, state_a.tip_hash(), vec![before_boundary_tx]);
        before_boundary_block.timestamp = 1_999;
        before_boundary_block.state_root = state_a
            .preview_state_root_after(&before_boundary_block, &TestOnlyAuthenticator)
            .unwrap();
        state_a
            .apply_block(&before_boundary_block, &TestOnlyAuthenticator)
            .expect("expiry-1 boundary remains valid");

        let mut exact_boundary_state =
            LedgerState::genesis(TEST_NETWORK_ID, initial_accounts.clone()).unwrap();
        let mut exact_tx = signed_tx(account(1), account(2), 1, 100, 2);
        exact_tx.expires_at = 2_000;
        exact_tx.signature = test_signature(
            &exact_tx.sender,
            &transaction_signing_digest(&exact_tx).unwrap(),
        );
        let mut exact_block = block(1, exact_boundary_state.tip_hash(), vec![exact_tx]);
        exact_block.timestamp = 2_000;
        let exact_before = exact_boundary_state.encode_snapshot().unwrap();
        assert_eq!(
            exact_boundary_state.apply_block(&exact_block, &TestOnlyAuthenticator),
            Err(StateError::TransactionExpired {
                expires_at: 2_000,
                block_timestamp: 2_000,
            })
        );
        assert_eq!(
            exact_boundary_state.encode_snapshot().unwrap(),
            exact_before
        );

        let mut after_state = LedgerState::genesis(TEST_NETWORK_ID, initial_accounts).unwrap();
        let mut after_tx = signed_tx(account(1), account(2), 1, 100, 2);
        after_tx.expires_at = 2_000;
        after_tx.signature = test_signature(
            &after_tx.sender,
            &transaction_signing_digest(&after_tx).unwrap(),
        );
        let mut after_block = block(1, after_state.tip_hash(), vec![after_tx]);
        after_block.timestamp = 2_001;
        assert!(matches!(
            after_state.apply_block(&after_block, &TestOnlyAuthenticator),
            Err(StateError::TransactionExpired {
                expires_at: 2_000,
                block_timestamp: 2_001,
            })
        ));

        // A checksummed snapshot cannot be silently imported under another network domain.
        let snapshot_a = exact_boundary_state.encode_snapshot().unwrap();
        assert_eq!(
            LedgerState::decode_snapshot(&snapshot_a, &network_b),
            Err(StateError::SnapshotNetworkMismatch)
        );
        assert_eq!(
            LedgerState::decode_snapshot(&snapshot_a, &TEST_NETWORK_ID),
            Ok(exact_boundary_state)
        );
        let mut invalid_expiry = signed_tx(account(1), account(2), 1, 10, 1);
        invalid_expiry.expires_at = 0;
        assert_eq!(
            encode_transaction(&invalid_expiry),
            Err(StateError::InvalidExpiry)
        );
    }

    #[test]
    fn shared_cp0026c_signing_domain_vectors_match_rust() {
        use std::collections::BTreeMap;
        use std::path::PathBuf;

        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../simulations/cp0026c_signing_domain_vectors.txt");
        let contents = std::fs::read_to_string(path).expect("read CP-0026-C vectors");
        let lines: Vec<_> = contents.lines().collect();
        assert_eq!(lines.first(), Some(&"CP0026C_SIGNING_DOMAIN_VECTORS_V1"));
        assert_eq!(lines.last(), Some(&"END"));
        let mut values = BTreeMap::new();
        for line in lines.iter().skip(1).take_while(|line| **line != "END") {
            let (key, value) = line.split_once('=').expect("key=value vector");
            assert!(values.insert(key.to_string(), value.to_string()).is_none());
        }
        let value = |key: &str| {
            values
                .get(key)
                .unwrap_or_else(|| panic!("missing vector {key}"))
                .clone()
        };
        let unhex = |value: &str| -> Vec<u8> {
            assert_eq!(value.len() % 2, 0);
            (0..value.len())
                .step_by(2)
                .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
                .collect()
        };

        assert_eq!(value("EXPIRY_RULE"), "exclusive");
        assert_eq!(value("TIME_BEFORE"), "1999");
        assert_eq!(value("EXPIRES_AT"), "2000");
        assert_eq!(value("TIME_AT"), "2000");
        assert_eq!(value("TIME_AFTER"), "2001");

        let tx_a = decode_transaction(&unhex(&value("TX_A_HEX"))).unwrap();
        let tx_b = decode_transaction(&unhex(&value("TX_B_HEX"))).unwrap();
        assert_eq!(tx_a.network_id.to_vec(), unhex(&value("NETWORK_A")));
        assert_eq!(tx_b.network_id.to_vec(), unhex(&value("NETWORK_B")));
        assert_eq!(tx_a.expires_at, 2_000);
        assert_eq!(tx_b.expires_at, 2_000);
        assert_eq!(
            transaction_signing_digest(&tx_a).unwrap().to_vec(),
            unhex(&value("TX_A_SIGNING_DIGEST"))
        );
        assert_eq!(
            transaction_signing_digest(&tx_b).unwrap().to_vec(),
            unhex(&value("TX_B_SIGNING_DIGEST"))
        );
        assert_eq!(
            transaction_id(&tx_a).unwrap().to_vec(),
            unhex(&value("TX_A_ID"))
        );
        assert_eq!(
            transaction_id(&tx_b).unwrap().to_vec(),
            unhex(&value("TX_B_ID"))
        );
        assert_ne!(tx_a.network_id, tx_b.network_id);
        assert_ne!(
            transaction_signing_digest(&tx_a).unwrap(),
            transaction_signing_digest(&tx_b).unwrap()
        );
        assert_eq!(value("VALID_BEFORE_EXPIRY"), "true");
        assert_eq!(value("VALID_AT_EXPIRY"), "false");
        assert_eq!(value("VALID_AFTER_EXPIRY"), "false");
    }

    #[test]
    fn transaction_and_block_roundtrip_are_canonical() {
        let tx = signed_tx(account(1), account(2), 1, 100, 2);
        let tx_bytes = encode_transaction(&tx).unwrap();
        assert_eq!(decode_transaction(&tx_bytes).unwrap(), tx);
        assert_eq!(
            encode_transaction(&decode_transaction(&tx_bytes).unwrap()).unwrap(),
            tx_bytes
        );

        let blk = block(1, [0; 32], vec![tx]);
        let bytes = encode_block(&blk).unwrap();
        assert_eq!(decode_block(&bytes).unwrap(), blk);
        assert_eq!(encode_block(&decode_block(&bytes).unwrap()).unwrap(), bytes);
        assert_eq!(
            block_id(&blk).unwrap(),
            block_id(&decode_block(&bytes).unwrap()).unwrap()
        );
    }

    #[test]
    fn malformed_and_noncanonical_inputs_fail_closed() {
        let tx = signed_tx(account(1), account(2), 1, 10, 1);
        let bytes = encode_transaction(&tx).unwrap();
        assert_eq!(
            decode_transaction(&bytes[..bytes.len() - 1]),
            Err(StateError::Malformed)
        );

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(decode_transaction(&trailing), Err(StateError::Malformed));

        let mut bad_magic = bytes;
        bad_magic[0] ^= 1;
        assert_eq!(decode_transaction(&bad_magic), Err(StateError::BadMagic));

        let blk = block(1, [0; 32], vec![tx]);
        let mut bad_block = encode_block(&blk).unwrap();
        bad_block.push(0);
        assert_eq!(decode_block(&bad_block), Err(StateError::Malformed));
    }

    #[test]
    fn oversized_inputs_are_rejected_before_parsing() {
        assert!(matches!(
            decode_transaction(&vec![0; MAX_TRANSACTION_BYTES + 1]),
            Err(StateError::Oversize { .. })
        ));
        assert!(matches!(
            decode_block(&vec![0; MAX_ENCODED_BLOCK_BYTES + 1]),
            Err(StateError::Oversize { .. })
        ));
    }

    #[test]
    fn block_transaction_count_is_bounded_before_encoding() {
        let tx = signed_tx(account(1), account(2), 1, 1, 0);
        let oversized = block(1, [0; 32], vec![tx; MAX_TRANSACTIONS_PER_BLOCK + 1]);
        assert_eq!(
            encode_block(&oversized),
            Err(StateError::TooManyTransactions(
                MAX_TRANSACTIONS_PER_BLOCK + 1
            ))
        );
    }

    #[test]
    fn timestamp_policy_rejects_future_block_atomically_and_accepts_inclusive_limit() {
        let mut state = alice_bob_state();
        let before = state.encode_snapshot().unwrap();

        let mut too_far = block(1, state.tip_hash(), vec![]);
        too_far.timestamp = 1_121;
        too_far.state_root = state
            .preview_state_root_after(&too_far, &TestOnlyAuthenticator)
            .unwrap();
        assert_eq!(
            state.apply_block_with_timestamp_policy(
                &too_far,
                &TestOnlyAuthenticator,
                1_000,
                TimestampPolicy::testnet(),
            ),
            Err(StateError::TimestampTooFarInFuture {
                latest_allowed: 1_120,
                actual: 1_121,
            })
        );
        assert_eq!(state.encode_snapshot().unwrap(), before);

        let mut at_limit = block(1, state.tip_hash(), vec![]);
        at_limit.timestamp = 1_120;
        at_limit.state_root = state
            .preview_state_root_after(&at_limit, &TestOnlyAuthenticator)
            .unwrap();
        state
            .apply_block_with_timestamp_policy(
                &at_limit,
                &TestOnlyAuthenticator,
                1_000,
                TimestampPolicy::testnet(),
            )
            .unwrap();
        assert_eq!(state.last_timestamp(), 1_120);
    }

    #[test]
    fn genesis_rejects_zero_and_duplicate_account_ids() {
        assert_eq!(
            LedgerState::genesis(TEST_NETWORK_ID, vec![([0; 32], 1)]),
            Err(StateError::InvalidAccountId)
        );
        assert_eq!(
            LedgerState::genesis(TEST_NETWORK_ID, vec![(account(1), 1), (account(1), 2)]),
            Err(StateError::DuplicateGenesisAccount)
        );
    }

    #[test]
    fn genesis_and_state_root_ignore_insertion_order() {
        let left =
            LedgerState::genesis(TEST_NETWORK_ID, vec![(account(1), 100), (account(2), 200)])
                .unwrap();
        let right =
            LedgerState::genesis(TEST_NETWORK_ID, vec![(account(2), 200), (account(1), 100)])
                .unwrap();
        assert_eq!(left.state_root(), right.state_root());
    }

    #[test]
    fn valid_transfer_conserves_value_and_nonce_blocks_replay() {
        let mut state = alice_bob_state();
        let tx = signed_tx(account(1), account(2), 1, 100, 2);
        let mut blk = block(1, state.tip_hash(), vec![tx.clone()]);
        blk.state_root = state
            .preview_state_root_after(&blk, &TestOnlyAuthenticator)
            .unwrap();
        let initial_total = state.total_value().unwrap();
        let summary = state.apply_block(&blk, &TestOnlyAuthenticator).unwrap();

        assert_eq!(summary.height, 1);
        assert_eq!(summary.transactions_applied, 1);
        assert_eq!(summary.fees_collected, 2);
        assert_eq!(
            state.account(&account(1)).unwrap(),
            AccountState {
                balance: 898,
                nonce: 1
            }
        );
        assert_eq!(
            state.account(&account(2)).unwrap(),
            AccountState {
                balance: 105,
                nonce: 0
            }
        );
        assert_eq!(state.fee_pool(), 2);
        assert_eq!(state.total_value().unwrap(), initial_total);
        let after_first = state.state_root();

        let replay = block(2, state.tip_hash(), vec![tx]);
        assert!(matches!(
            state.apply_block(&replay, &TestOnlyAuthenticator),
            Err(StateError::NonceMismatch { .. })
        ));
        assert_eq!(state.state_root(), after_first);
    }

    #[test]
    fn invalid_later_transaction_rolls_back_whole_block() {
        let mut state = alice_bob_state();
        let before_root = state.state_root();
        let good = signed_tx(account(1), account(2), 1, 100, 1);
        let overspend = signed_tx(account(1), account(2), 2, 10_000, 1);
        let blk = block(1, state.tip_hash(), vec![good, overspend]);

        assert_eq!(
            state.apply_block(&blk, &TestOnlyAuthenticator),
            Err(StateError::InsufficientBalance)
        );
        assert_eq!(state.height(), 0);
        assert_eq!(state.state_root(), before_root);
        assert_eq!(state.account(&account(1)).unwrap().nonce, 0);
    }

    #[test]
    fn parent_and_height_mismatch_are_atomic() {
        let mut state = alice_bob_state();
        let before = state.state_root();
        assert_eq!(
            state.apply_block(&block(1, [9; 32], vec![]), &TestOnlyAuthenticator),
            Err(StateError::ParentHashMismatch)
        );
        assert_eq!(
            state.apply_block(&block(2, state.tip_hash(), vec![]), &TestOnlyAuthenticator),
            Err(StateError::HeightMismatch {
                expected: 1,
                actual: 2
            })
        );
        assert_eq!(state.state_root(), before);
    }

    #[test]
    fn duplicate_transaction_is_rejected() {
        let mut state = alice_bob_state();
        let tx = signed_tx(account(1), account(2), 1, 5, 0);
        let blk = block(1, state.tip_hash(), vec![tx.clone(), tx]);
        assert_eq!(
            state.apply_block(&blk, &TestOnlyAuthenticator),
            Err(StateError::DuplicateTransaction)
        );
        assert_eq!(state.height(), 0);
    }

    #[test]
    fn bad_authorization_fails_without_mutation() {
        let mut state = alice_bob_state();
        let before = state.state_root();
        let mut tx = signed_tx(account(1), account(2), 1, 5, 0);
        tx.signature[0] ^= 0x80;
        assert_eq!(
            state.apply_block(
                &block(1, state.tip_hash(), vec![tx]),
                &TestOnlyAuthenticator
            ),
            Err(StateError::Unauthorized)
        );
        assert_eq!(state.state_root(), before);
    }

    #[test]
    fn missing_sender_fails_and_over_cap_genesis_is_rejected() {
        let mut state = alice_bob_state();
        let before = state.state_root();
        let missing = signed_tx(account(9), account(2), 1, 1, 0);
        assert_eq!(
            state.apply_block(
                &block(1, state.tip_hash(), vec![missing]),
                &TestOnlyAuthenticator
            ),
            Err(StateError::MissingSender)
        );
        assert_eq!(state.state_root(), before);

        // A ledger large enough to exercise u64 amount overflow is already invalid under the
        // stricter 10B-coin lifetime cap, so it cannot be used as a valid block-admission fixture.
        assert_eq!(
            LedgerState::genesis(
                TEST_NETWORK_ID,
                vec![(account(1), u64::MAX), (account(2), 0)],
            ),
            Err(StateError::SupplyCapExceeded)
        );
    }

    #[test]
    fn recipient_balance_overflow_fixture_is_rejected_by_genesis_cap() {
        assert_eq!(
            LedgerState::genesis(
                TEST_NETWORK_ID,
                vec![(account(1), 100), (account(2), u64::MAX)],
            ),
            Err(StateError::SupplyCapExceeded)
        );
    }

    #[test]
    fn self_transfer_only_charges_fee_and_advances_nonce() {
        let mut state = alice_bob_state();
        let tx = signed_tx(account(1), account(1), 1, 100, 2);
        let mut blk = block(1, state.tip_hash(), vec![tx]);
        blk.state_root = state
            .preview_state_root_after(&blk, &TestOnlyAuthenticator)
            .unwrap();
        let total = state.total_value().unwrap();
        state.apply_block(&blk, &TestOnlyAuthenticator).unwrap();
        assert_eq!(
            state.account(&account(1)).unwrap(),
            AccountState {
                balance: 998,
                nonce: 1
            }
        );
        assert_eq!(state.fee_pool(), 2);
        assert_eq!(state.total_value().unwrap(), total);
    }

    #[test]
    fn fee_overflow_fixture_is_rejected_by_genesis_cap() {
        // Sum-of-fees overflow requires a starting supply above the agreed hard cap here;
        // such a state is now rejected before block admission can begin.
        assert_eq!(
            LedgerState::genesis(
                TEST_NETWORK_ID,
                vec![(account(1), u64::MAX), (account(2), u64::MAX)],
            ),
            Err(StateError::SupplyCapExceeded)
        );
    }

    #[test]
    fn snapshot_child_restore_probe() {
        let Ok(input_path) = std::env::var("CP0026B_RESTORE_SNAPSHOT") else {
            // This probe is activated only by the parent subprocess-equivalence test.
            return;
        };
        let output_path = std::env::var("CP0026B_RESTART_OUTPUT")
            .expect("restart output path supplied by parent");
        let input = std::fs::read(input_path).expect("read persisted snapshot in child process");
        let mut restored = LedgerState::decode_snapshot(&input, &TEST_NETWORK_ID)
            .expect("restore snapshot in child");
        assert_eq!(restored.height(), 1);
        assert_eq!(
            restored.account(&account(1)).unwrap(),
            AccountState {
                balance: 898,
                nonce: 1
            }
        );
        assert_eq!(
            restored.account(&account(2)).unwrap(),
            AccountState {
                balance: 105,
                nonce: 0
            }
        );

        let second = committed_block(&restored, vec![signed_tx(account(2), account(3), 1, 10, 1)]);
        restored
            .apply_block(&second, &TestOnlyAuthenticator)
            .unwrap();
        std::fs::write(output_path, restored.encode_snapshot().unwrap())
            .expect("persist child-process continuation result");
    }

    #[test]
    fn actual_child_process_restore_matches_uninterrupted_execution() {
        use std::process::Command;

        let mut uninterrupted = alice_bob_state();
        let first = committed_block(
            &uninterrupted,
            vec![signed_tx(account(1), account(2), 1, 100, 2)],
        );
        uninterrupted
            .apply_block(&first, &TestOnlyAuthenticator)
            .unwrap();

        let stem = format!("cp0026b_restart_{}", std::process::id());
        let input_path = std::env::temp_dir().join(format!("{stem}_input.bin"));
        let output_path = std::env::temp_dir().join(format!("{stem}_output.bin"));
        let _ = std::fs::remove_file(&input_path);
        let _ = std::fs::remove_file(&output_path);
        std::fs::write(&input_path, uninterrupted.encode_snapshot().unwrap())
            .expect("write snapshot for independent process");

        let current_test_binary = std::env::current_exe().expect("test executable path");
        let status = Command::new(current_test_binary)
            .arg("--exact")
            .arg("state_machine::tests::snapshot_child_restore_probe")
            .arg("--nocapture")
            .env("CP0026B_RESTORE_SNAPSHOT", &input_path)
            .env("CP0026B_RESTART_OUTPUT", &output_path)
            .status()
            .expect("launch independent restore process");
        assert!(
            status.success(),
            "snapshot restore child process failed: {status:?}"
        );

        let second = committed_block(
            &uninterrupted,
            vec![signed_tx(account(2), account(3), 1, 10, 1)],
        );
        uninterrupted
            .apply_block(&second, &TestOnlyAuthenticator)
            .unwrap();

        let child_bytes = std::fs::read(&output_path).expect("read snapshot emitted by child");
        let restarted = LedgerState::decode_snapshot(&child_bytes, &TEST_NETWORK_ID)
            .expect("decode child output snapshot");
        assert_eq!(restarted, uninterrupted);
        assert_eq!(restarted.state_root(), uninterrupted.state_root());
        assert_eq!(restarted.tip_hash(), uninterrupted.tip_hash());
        assert_eq!(
            restarted.encode_snapshot().unwrap(),
            uninterrupted.encode_snapshot().unwrap()
        );

        let _ = std::fs::remove_file(input_path);
        let _ = std::fs::remove_file(output_path);
    }

    #[test]
    fn snapshot_roundtrip_and_restart_continuation_are_equivalent() {
        let mut uninterrupted = alice_bob_state();
        let first = committed_block(
            &uninterrupted,
            vec![signed_tx(account(1), account(2), 1, 100, 2)],
        );
        uninterrupted
            .apply_block(&first, &TestOnlyAuthenticator)
            .unwrap();

        let snapshot = uninterrupted.encode_snapshot().unwrap();
        let mut restored = LedgerState::decode_snapshot(&snapshot, &TEST_NETWORK_ID).unwrap();
        assert_eq!(restored, uninterrupted);
        assert_eq!(restored.encode_snapshot().unwrap(), snapshot);
        assert_eq!(restored.state_root(), uninterrupted.state_root());
        assert_eq!(restored.tip_hash(), uninterrupted.tip_hash());

        let second = committed_block(
            &uninterrupted,
            vec![signed_tx(account(2), account(3), 1, 10, 1)],
        );
        let a = uninterrupted
            .apply_block(&second, &TestOnlyAuthenticator)
            .unwrap();
        let b = restored
            .apply_block(&second, &TestOnlyAuthenticator)
            .unwrap();
        assert_eq!(a, b);
        assert_eq!(restored, uninterrupted);
        assert_eq!(
            restored.encode_snapshot().unwrap(),
            uninterrupted.encode_snapshot().unwrap()
        );
        assert_eq!(
            restored.account(&account(2)).unwrap(),
            AccountState {
                balance: 94,
                nonce: 1
            }
        );
        assert_eq!(
            restored.account(&account(3)).unwrap(),
            AccountState {
                balance: 10,
                nonce: 0
            }
        );
        assert_eq!(restored.fee_pool(), 3);
        assert_eq!(restored.total_value().unwrap(), 1_005);
    }

    #[test]
    fn snapshot_checksum_bounds_and_version_fail_closed() {
        let state = alice_bob_state();
        let snapshot = state.encode_snapshot().unwrap();
        assert_eq!(
            LedgerState::decode_snapshot(&snapshot, &TEST_NETWORK_ID).unwrap(),
            state
        );
        assert_eq!(
            LedgerState::decode_snapshot(&[], &TEST_NETWORK_ID),
            Err(StateError::Malformed)
        );
        assert!(matches!(
            LedgerState::decode_snapshot(
                &vec![0; MAX_ENCODED_SNAPSHOT_BYTES + 1],
                &TEST_NETWORK_ID
            ),
            Err(StateError::Oversize { .. })
        ));

        let mut corrupt = snapshot.clone();
        corrupt[SNAPSHOT_HEADER_LEN] ^= 1;
        assert_eq!(
            LedgerState::decode_snapshot(&corrupt, &TEST_NETWORK_ID),
            Err(StateError::SnapshotChecksumMismatch)
        );

        let mut unknown_version = snapshot;
        unknown_version[4..6].copy_from_slice(&3u16.to_be_bytes());
        let payload_len = unknown_version.len() - SNAPSHOT_CHECKSUM_LEN;
        let checksum = hash_domain(SNAPSHOT_CHECKSUM_DOMAIN, &[&unknown_version[..payload_len]]);
        unknown_version[payload_len..].copy_from_slice(&checksum);
        assert_eq!(
            LedgerState::decode_snapshot(&unknown_version, &TEST_NETWORK_ID),
            Err(StateError::UnsupportedVersion(3))
        );
    }

    #[test]
    fn snapshot_rejects_malformed_lengths_and_resource_counts_with_valid_checksum() {
        let state = alice_bob_state();
        let good = state.encode_snapshot().unwrap();

        // Remove one byte from the final account record, recompute checksum, then
        // ensure exact declared-count/record-length validation still rejects it.
        let body_len = good.len() - SNAPSHOT_CHECKSUM_LEN;
        let mut truncated = good[..body_len - 1].to_vec();
        let checksum = hash_domain(SNAPSHOT_CHECKSUM_DOMAIN, &[&truncated]);
        truncated.extend_from_slice(&checksum);
        assert_eq!(
            LedgerState::decode_snapshot(&truncated, &TEST_NETWORK_ID),
            Err(StateError::Malformed)
        );

        // Add a payload byte while preserving a correct checksum; exact length wins.
        let mut trailing = good[..body_len].to_vec();
        trailing.push(0xAA);
        let checksum = hash_domain(SNAPSHOT_CHECKSUM_DOMAIN, &[&trailing]);
        trailing.extend_from_slice(&checksum);
        assert_eq!(
            LedgerState::decode_snapshot(&trailing, &TEST_NETWORK_ID),
            Err(StateError::Malformed)
        );

        // Claim more than MAX_ACCOUNTS before the decoder can allocate an account table.
        let mut excessive_count = good[..body_len].to_vec();
        excessive_count[94..98].copy_from_slice(&((MAX_ACCOUNTS as u32) + 1).to_be_bytes());
        let checksum = hash_domain(SNAPSHOT_CHECKSUM_DOMAIN, &[&excessive_count]);
        excessive_count.extend_from_slice(&checksum);
        assert_eq!(
            LedgerState::decode_snapshot(&excessive_count, &TEST_NETWORK_ID),
            Err(StateError::TooManyAccounts)
        );

        // Zero account IDs are also rejected even when the envelope checksum is valid.
        let mut zero_account = good[..body_len].to_vec();
        zero_account[SNAPSHOT_HEADER_LEN..SNAPSHOT_HEADER_LEN + 32].fill(0);
        let checksum = hash_domain(SNAPSHOT_CHECKSUM_DOMAIN, &[&zero_account]);
        zero_account.extend_from_slice(&checksum);
        assert_eq!(
            LedgerState::decode_snapshot(&zero_account, &TEST_NETWORK_ID),
            Err(StateError::InvalidAccountId)
        );
    }

    #[test]
    fn snapshot_rejects_noncanonical_account_order_even_with_valid_checksum() {
        let state = alice_bob_state();
        let mut snapshot = state.encode_snapshot().unwrap();
        let first_start = SNAPSHOT_HEADER_LEN;
        let second_start = first_start + SNAPSHOT_ACCOUNT_RECORD_LEN;
        let first = snapshot[first_start..first_start + SNAPSHOT_ACCOUNT_RECORD_LEN].to_vec();
        let second = snapshot[second_start..second_start + SNAPSHOT_ACCOUNT_RECORD_LEN].to_vec();
        snapshot[first_start..first_start + SNAPSHOT_ACCOUNT_RECORD_LEN].copy_from_slice(&second);
        snapshot[second_start..second_start + SNAPSHOT_ACCOUNT_RECORD_LEN].copy_from_slice(&first);

        // Recompute the checksum to make this a canonicality check, not just corruption detection.
        let payload_len = snapshot.len() - SNAPSHOT_CHECKSUM_LEN;
        let checksum = hash_domain(SNAPSHOT_CHECKSUM_DOMAIN, &[&snapshot[..payload_len]]);
        snapshot[payload_len..].copy_from_slice(&checksum);
        assert_eq!(
            LedgerState::decode_snapshot(&snapshot, &TEST_NETWORK_ID),
            Err(StateError::SnapshotNonCanonical)
        );
    }

    #[test]
    fn multiblock_replay_is_deterministic_and_stale_forks_reject() {
        let mut left = alice_bob_state();
        let mut right = left.clone();
        let first = committed_block(&left, vec![signed_tx(account(1), account(2), 1, 100, 2)]);
        let left_first = left.apply_block(&first, &TestOnlyAuthenticator).unwrap();
        let right_first = right.apply_block(&first, &TestOnlyAuthenticator).unwrap();
        assert_eq!(left_first, right_first);
        assert_eq!(left, right);

        let second = committed_block(&left, vec![signed_tx(account(2), account(3), 1, 10, 1)]);
        let left_second = left.apply_block(&second, &TestOnlyAuthenticator).unwrap();
        let right_second = right.apply_block(&second, &TestOnlyAuthenticator).unwrap();
        assert_eq!(left_second, right_second);
        assert_eq!(left, right);

        let before = left.encode_snapshot().unwrap();
        let stale_parent = block(3, left_first.block_hash, vec![]);
        assert_eq!(
            left.apply_block(&stale_parent, &TestOnlyAuthenticator),
            Err(StateError::ParentHashMismatch)
        );
        assert_eq!(left.encode_snapshot().unwrap(), before);
        assert_eq!(
            left.apply_block(&first, &TestOnlyAuthenticator),
            Err(StateError::HeightMismatch {
                expected: 3,
                actual: 1
            })
        );
        assert_eq!(left.encode_snapshot().unwrap(), before);
    }

    #[test]
    fn shared_python_golden_snapshot_vector_matches_rust_restore() {
        use std::collections::BTreeMap;
        use std::path::PathBuf;

        fn parse(path: PathBuf) -> BTreeMap<String, String> {
            let content = std::fs::read_to_string(path).expect("read snapshot vector");
            let mut values = BTreeMap::new();
            for line in content.lines().skip(1).take_while(|line| *line != "END") {
                let (key, value) = line.split_once('=').expect("key=value vector line");
                assert!(values.insert(key.to_string(), value.to_string()).is_none());
            }
            values
        }
        fn hex(value: &str) -> Vec<u8> {
            assert_eq!(value.len() % 2, 0);
            (0..value.len())
                .step_by(2)
                .map(|index| u8::from_str_radix(&value[index..index + 2], 16).expect("hex byte"))
                .collect()
        }

        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../simulations");
        let tx_vector = parse(root.join("cp0026a_state_vectors.txt"));
        let snapshot_vector = parse(root.join("cp0026b_snapshot_vectors.txt"));
        assert_eq!(snapshot_vector.get("SNAPSHOT_MAGIC").unwrap(), "53545632");

        let sender: AccountId = hex(tx_vector.get("SENDER").unwrap())
            .try_into()
            .expect("sender ID width");
        let recipient: AccountId = hex(tx_vector.get("RECIPIENT").unwrap())
            .try_into()
            .expect("recipient ID width");
        let tx = decode_transaction(&hex(tx_vector.get("TRANSACTION_HEX").unwrap()))
            .expect("canonical transaction");
        let block =
            decode_block(&hex(tx_vector.get("BLOCK_HEX").unwrap())).expect("canonical block");
        assert_eq!(block.transactions, vec![tx]);
        let mut state = LedgerState::genesis(
            TEST_NETWORK_ID,
            vec![
                (
                    sender,
                    tx_vector
                        .get("INITIAL_SENDER_BALANCE")
                        .unwrap()
                        .parse()
                        .unwrap(),
                ),
                (
                    recipient,
                    tx_vector
                        .get("INITIAL_RECIPIENT_BALANCE")
                        .unwrap()
                        .parse()
                        .unwrap(),
                ),
            ],
        )
        .unwrap();
        state.apply_block(&block, &TestOnlyAuthenticator).unwrap();

        assert_eq!(
            state.height().to_string(),
            *snapshot_vector.get("HEIGHT").unwrap()
        );
        assert_eq!(
            state.tip_hash().to_vec(),
            hex(snapshot_vector.get("TIP_HASH").unwrap())
        );
        assert_eq!(
            state.fee_pool().to_string(),
            *snapshot_vector.get("FEE_POOL").unwrap()
        );
        let expected_snapshot = hex(snapshot_vector.get("SNAPSHOT_HEX").unwrap());
        assert_eq!(state.encode_snapshot().unwrap(), expected_snapshot);

        let restored = LedgerState::decode_snapshot(&expected_snapshot, &TEST_NETWORK_ID).unwrap();
        assert_eq!(restored, state);
        assert_eq!(restored.encode_snapshot().unwrap(), expected_snapshot);
        assert_eq!(
            restored.state_root().to_vec(),
            hex(tx_vector.get("STATE_ROOT_AFTER").unwrap())
        );
        assert_eq!(
            restored.total_value().unwrap().to_string(),
            tx_vector.get("TOTAL_VALUE_AFTER").unwrap().as_str()
        );
    }

    #[test]
    fn shared_cp0026b_vectors_match_multiblock_snapshot_restart_and_rejections() {
        use std::collections::BTreeMap;
        use std::path::PathBuf;

        let vector_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../simulations/cp0026b_state_vectors.txt");
        let text = std::fs::read_to_string(vector_path).expect("read shared CP-0026-B vectors");
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(lines.first(), Some(&"CP0026B_STATE_VECTORS_V2"));
        assert_eq!(lines.last(), Some(&"END"));
        let mut values = BTreeMap::new();
        for line in lines.iter().skip(1).take_while(|line| **line != "END") {
            let (key, value) = line.split_once('=').expect("key=value vector record");
            assert!(values.insert(key.to_string(), value.to_string()).is_none());
        }
        let value = |key: &str| {
            values
                .get(key)
                .unwrap_or_else(|| panic!("missing CP-0026-B vector field {key}"))
                .clone()
        };
        let unhex = |hex: &str| -> Vec<u8> {
            assert_eq!(hex.len() % 2, 0);
            (0..hex.len())
                .step_by(2)
                .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("hex byte"))
                .collect()
        };
        let hex =
            |bytes: &[u8]| -> String { bytes.iter().map(|byte| format!("{byte:02x}")).collect() };

        assert_eq!(value("CASE"), "multiblock_restart");
        let network_id: NetworkId = unhex(&value("NETWORK_ID"))
            .try_into()
            .expect("32-byte network id");
        assert_eq!(network_id, TEST_NETWORK_ID);
        let sender: AccountId = unhex(&value("GENESIS_ACCOUNT1"))
            .try_into()
            .expect("32-byte first account");
        let recipient: AccountId = unhex(&value("GENESIS_ACCOUNT2"))
            .try_into()
            .expect("32-byte second account");
        let tx1_bytes = unhex(&value("TX1_HEX"));
        let tx1 = decode_transaction(&tx1_bytes).expect("decode transaction 1");
        assert_eq!(encode_transaction(&tx1).unwrap(), tx1_bytes);
        assert_eq!(tx1.network_id, network_id);
        assert_eq!(
            tx1.expires_at,
            value("TX1_EXPIRES_AT").parse::<u64>().unwrap()
        );
        assert_eq!(
            transaction_signing_digest(&tx1).unwrap().to_vec(),
            unhex(&value("TX1_SIGNING_DIGEST"))
        );
        assert_eq!(
            transaction_id(&tx1).unwrap().to_vec(),
            unhex(&value("TX1_ID"))
        );

        let block1_bytes = unhex(&value("BLOCK1_HEX"));
        let block1 = decode_block(&block1_bytes).expect("decode block 1");
        assert_eq!(encode_block(&block1).unwrap(), block1_bytes);
        assert_eq!(
            block1.timestamp,
            value("BLOCK1_TIMESTAMP").parse::<u64>().unwrap()
        );
        assert_eq!(block1.transactions, vec![tx1]);
        assert_eq!(
            block1.state_root.to_vec(),
            unhex(&value("BLOCK1_STATE_ROOT"))
        );
        assert_eq!(
            block_id(&block1).unwrap().to_vec(),
            unhex(&value("BLOCK1_ID"))
        );

        let mut uninterrupted = LedgerState::genesis(
            network_id,
            vec![
                (sender, value("GENESIS_BALANCE1").parse::<u64>().unwrap()),
                (recipient, value("GENESIS_BALANCE2").parse::<u64>().unwrap()),
            ],
        )
        .unwrap();
        let before_genesis = uninterrupted.encode_snapshot().unwrap();

        let tampered = decode_block(&unhex(&value("BLOCK1_TAMPERED_ROOT_HEX")))
            .expect("tampered but structurally canonical block");
        assert_eq!(
            uninterrupted.apply_block(&tampered, &TestOnlyAuthenticator),
            Err(StateError::StateRootMismatch)
        );
        assert_eq!(uninterrupted.encode_snapshot().unwrap(), before_genesis);

        let first_summary = uninterrupted
            .apply_block(&block1, &TestOnlyAuthenticator)
            .expect("apply canonical first block");
        assert_eq!(
            first_summary.block_hash.to_vec(),
            unhex(&value("BLOCK1_ID"))
        );
        assert_eq!(
            uninterrupted.state_root().to_vec(),
            unhex(&value("BLOCK1_STATE_ROOT"))
        );
        assert_eq!(
            uninterrupted.total_value().unwrap().to_string(),
            value("TOTAL_VALUE_AFTER_BLOCK1")
        );
        let snapshot1 = uninterrupted.encode_snapshot().unwrap();
        assert_eq!(hex(&snapshot1), value("SNAPSHOT1_HEX"));
        let mut restored =
            LedgerState::decode_snapshot(&snapshot1, &TEST_NETWORK_ID).expect("restore snapshot 1");
        assert_eq!(restored, uninterrupted);
        assert_eq!(restored.encode_snapshot().unwrap(), snapshot1);
        assert_eq!(
            LedgerState::decode_snapshot(
                &unhex(&value("SNAPSHOT1_CORRUPTED_HEX")),
                &TEST_NETWORK_ID
            ),
            Err(StateError::SnapshotChecksumMismatch)
        );

        let tx2_bytes = unhex(&value("TX2_HEX"));
        let tx2 = decode_transaction(&tx2_bytes).expect("decode transaction 2");
        assert_eq!(encode_transaction(&tx2).unwrap(), tx2_bytes);
        assert_eq!(tx2.network_id, network_id);
        assert_eq!(
            tx2.expires_at,
            value("TX2_EXPIRES_AT").parse::<u64>().unwrap()
        );
        assert_eq!(
            transaction_signing_digest(&tx2).unwrap().to_vec(),
            unhex(&value("TX2_SIGNING_DIGEST"))
        );
        assert_eq!(
            transaction_id(&tx2).unwrap().to_vec(),
            unhex(&value("TX2_ID"))
        );
        let block2_bytes = unhex(&value("BLOCK2_HEX"));
        let block2 = decode_block(&block2_bytes).expect("decode block 2");
        assert_eq!(encode_block(&block2).unwrap(), block2_bytes);
        assert_eq!(
            block2.timestamp,
            value("BLOCK2_TIMESTAMP").parse::<u64>().unwrap()
        );
        assert_eq!(block2.parent_hash.to_vec(), unhex(&value("BLOCK1_ID")));
        assert_eq!(
            block2.state_root.to_vec(),
            unhex(&value("BLOCK2_STATE_ROOT"))
        );
        assert_eq!(
            block_id(&block2).unwrap().to_vec(),
            unhex(&value("BLOCK2_ID"))
        );

        let summary_live = uninterrupted
            .apply_block(&block2, &TestOnlyAuthenticator)
            .expect("apply second block without restart");
        let summary_restart = restored
            .apply_block(&block2, &TestOnlyAuthenticator)
            .expect("apply second block after snapshot restore");
        assert_eq!(summary_live, summary_restart);
        assert_eq!(summary_live.block_hash.to_vec(), unhex(&value("BLOCK2_ID")));
        assert_eq!(uninterrupted, restored);
        assert_eq!(
            uninterrupted.state_root().to_vec(),
            unhex(&value("BLOCK2_STATE_ROOT"))
        );
        assert_eq!(
            uninterrupted.total_value().unwrap().to_string(),
            value("TOTAL_VALUE_AFTER_BLOCK2")
        );
        let snapshot2 = uninterrupted.encode_snapshot().unwrap();
        assert_eq!(hex(&snapshot2), value("SNAPSHOT2_HEX"));
        assert_eq!(snapshot2, restored.encode_snapshot().unwrap());
        assert_eq!(
            LedgerState::decode_snapshot(&snapshot2, &TEST_NETWORK_ID).unwrap(),
            uninterrupted
        );

        // This height-3 fork vector has the correct next height after block 2,
        // so the test isolates parent-hash rejection instead of height rejection.
        let before_wrong_parent = uninterrupted.encode_snapshot().unwrap();
        let wrong_parent = decode_block(&unhex(&value("BLOCK3_WRONG_PARENT_HEX")))
            .expect("structurally valid alternate-fork block");
        assert_eq!(
            uninterrupted.apply_block(&wrong_parent, &TestOnlyAuthenticator),
            Err(StateError::ParentHashMismatch)
        );
        assert_eq!(
            uninterrupted.encode_snapshot().unwrap(),
            before_wrong_parent
        );
        assert_eq!(restored.encode_snapshot().unwrap(), before_wrong_parent);

        let before_replay = uninterrupted.encode_snapshot().unwrap();
        assert_eq!(
            uninterrupted.apply_block(&block1, &TestOnlyAuthenticator),
            Err(StateError::HeightMismatch {
                expected: 3,
                actual: 1
            })
        );
        assert_eq!(uninterrupted.encode_snapshot().unwrap(), before_replay);
        assert_eq!(value("EXPECTED_TAMPER_REJECTION"), "StateRootMismatch");
        assert_eq!(value("EXPECTED_PARENT_REJECTION"), "ParentHashMismatch");
        assert_eq!(
            value("EXPECTED_SNAPSHOT_CORRUPTION"),
            "SnapshotChecksumMismatch"
        );
        assert_eq!(value("EXPECTED_REPLAY_REJECTION"), "HeightMismatch");
    }

    #[test]
    fn shared_python_golden_state_vector_matches_rust_execution() {
        use std::collections::BTreeMap;
        use std::path::PathBuf;

        let vector_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../simulations/cp0026a_state_vectors.txt");
        let text = std::fs::read_to_string(vector_path).expect("read shared state vector");
        let mut values = BTreeMap::new();
        for line in text.lines().skip(1).take_while(|line| *line != "END") {
            let (key, value) = line.split_once('=').expect("key=value vector line");
            assert!(values.insert(key.to_string(), value.to_string()).is_none());
        }
        let value = |key: &str| {
            values
                .get(key)
                .unwrap_or_else(|| panic!("missing vector field {key}"))
                .clone()
        };
        let unhex = |hex: &str| -> Vec<u8> {
            assert_eq!(hex.len() % 2, 0);
            (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex byte"))
                .collect()
        };

        assert_eq!(value("CASE"), "valid_transfer");
        let sender_bytes = unhex(&value("SENDER"));
        let recipient_bytes = unhex(&value("RECIPIENT"));
        let sender: AccountId = sender_bytes.try_into().expect("32-byte sender");
        let recipient: AccountId = recipient_bytes.try_into().expect("32-byte recipient");

        let tx_bytes = unhex(&value("TRANSACTION_HEX"));
        let tx = decode_transaction(&tx_bytes).expect("decode transaction vector");
        assert_eq!(tx.network_id.to_vec(), unhex(&value("NETWORK_ID")));
        assert_eq!(tx.expires_at, value("EXPIRES_AT").parse::<u64>().unwrap());
        assert_eq!(tx.sender, sender);
        assert_eq!(tx.recipient, recipient);
        assert_eq!(tx.nonce, value("NONCE").parse::<u64>().unwrap());
        assert_eq!(tx.amount, value("AMOUNT").parse::<u64>().unwrap());
        assert_eq!(tx.fee, value("FEE").parse::<u64>().unwrap());
        assert_eq!(tx.signature, unhex(&value("TEST_SIGNATURE")));
        assert_eq!(encode_transaction(&tx).unwrap(), tx_bytes);
        assert_eq!(
            transaction_signing_digest(&tx).unwrap().to_vec(),
            unhex(&value("TX_SIGNING_DIGEST"))
        );
        assert_eq!(
            transaction_id(&tx).unwrap().to_vec(),
            unhex(&value("TX_ID"))
        );

        let block_bytes = unhex(&value("BLOCK_HEX"));
        let block = decode_block(&block_bytes).expect("decode block vector");
        assert_eq!(block.height, value("BLOCK_HEIGHT").parse::<u64>().unwrap());
        assert_eq!(
            block.timestamp,
            value("BLOCK_TIMESTAMP").parse::<u64>().unwrap()
        );
        assert_eq!(
            block.parent_hash.to_vec(),
            unhex(&value("BLOCK_PARENT_HASH"))
        );
        assert_eq!(block.transactions, vec![tx]);
        assert_eq!(encode_block(&block).unwrap(), block_bytes);
        assert_eq!(
            block_id(&block).unwrap().to_vec(),
            unhex(&value("BLOCK_ID"))
        );

        let mut state = LedgerState::genesis(
            TEST_NETWORK_ID,
            vec![
                (
                    sender,
                    value("INITIAL_SENDER_BALANCE").parse::<u64>().unwrap(),
                ),
                (
                    recipient,
                    value("INITIAL_RECIPIENT_BALANCE").parse::<u64>().unwrap(),
                ),
            ],
        )
        .unwrap();
        assert_eq!(
            state.state_root().to_vec(),
            unhex(&value("STATE_ROOT_BEFORE"))
        );
        assert_eq!(
            state.total_value().unwrap().to_string(),
            value("TOTAL_VALUE_BEFORE")
        );
        let summary = state.apply_block(&block, &TestOnlyAuthenticator).unwrap();
        assert_eq!(summary.block_hash.to_vec(), unhex(&value("BLOCK_ID")));
        assert_eq!(
            summary.state_root.to_vec(),
            unhex(&value("STATE_ROOT_AFTER"))
        );
        assert_eq!(summary.fees_collected, value("FEE").parse::<u64>().unwrap());
        assert_eq!(
            state.account(&sender).unwrap(),
            AccountState {
                balance: 898,
                nonce: 1,
            }
        );
        assert_eq!(
            state.account(&recipient).unwrap(),
            AccountState {
                balance: 105,
                nonce: 0,
            }
        );
        assert_eq!(
            state.total_value().unwrap().to_string(),
            value("TOTAL_VALUE_AFTER")
        );
    }

    #[test]
    fn uncommitted_or_wrong_state_root_is_rejected_atomically() {
        let mut state = alice_bob_state();
        let before = state.state_root();
        let tx = signed_tx(account(1), account(2), 1, 100, 1);
        let mut block = block(1, state.tip_hash(), vec![tx]);
        block.state_root = state
            .preview_state_root_after(&block, &TestOnlyAuthenticator)
            .unwrap();
        block.state_root[0] ^= 0x80;
        assert_eq!(
            state.apply_block(&block, &TestOnlyAuthenticator),
            Err(StateError::StateRootMismatch)
        );
        assert_eq!(state.height(), 0);
        assert_eq!(state.state_root(), before);
    }

    #[test]
    fn malformed_byte_campaign_never_panics() {
        let mut seed = 0xC0FF_EE12_3456_789Au64;
        for case in 0..2_000usize {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let len = (seed as usize) % 160;
            let mut bytes = vec![0u8; len];
            for value in &mut bytes {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                *value = (seed >> 24) as u8;
            }
            let _ = decode_transaction(&bytes);
            let _ = decode_block(&bytes);
            let _ = decode_monetary_block(&bytes);
            if case % 7 == 0 {
                let mut expanded = bytes.clone();
                expanded.extend_from_slice(&seed.to_be_bytes());
                let _ = decode_block(&expanded);
                let _ = decode_monetary_block(&expanded);
            }
        }
    }

    fn monetary_genesis() -> MonetaryLedgerState {
        MonetaryLedgerState::genesis(
            TEST_NETWORK_ID,
            account(1),
            vec![(account(2), MONETARY_PUBLIC_GOODS_BUDGET_ATOMS as u64)],
        )
        .unwrap()
    }

    fn monetary_block(
        state: &MonetaryLedgerState,
        miner: AccountId,
        timestamp: u64,
        transactions: Vec<Transaction>,
    ) -> MonetaryBlock {
        let mut block = MonetaryBlock {
            body: Block {
                height: state.height() + 1,
                timestamp,
                parent_hash: state.tip_hash(),
                state_root: [0; 32],
                transactions,
            },
            miner,
            claimed_subsidy_atoms: state.expected_miner_reward().unwrap(),
        };
        block.body.state_root = state
            .preview_state_root_after(&block, &TestOnlyAuthenticator)
            .unwrap();
        block
    }

    #[test]
    fn monetary_genesis_snapshot_matches_independent_python_byte_vector() {
        use sha2::{Digest, Sha256};
        use std::path::PathBuf;

        fn decode_hex(value: &str) -> Vec<u8> {
            assert_eq!(value.len() % 2, 0);
            (0..value.len())
                .step_by(2)
                .map(|index| {
                    u8::from_str_radix(&value[index..index + 2], 16)
                        .expect("snapshot vector hex byte")
                })
                .collect()
        }

        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../simulations/cp0361_monetary_genesis_snapshot_vectors.tsv");
        let contents = std::fs::read_to_string(path).expect("read CP-0361 snapshot vector");
        let rows: Vec<_> = contents
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect();
        assert_eq!(rows.len(), 1, "exactly one frozen vector is expected");
        let fields: Vec<_> = rows[0].split('|').collect();
        assert_eq!(fields.len(), 14);
        assert_eq!(fields[0], "MONETARY_GENESIS_SNAPSHOT_V1");

        let network_id: NetworkId = decode_hex(fields[1]).try_into().expect("network ID width");
        let founder_account: AccountId = decode_hex(fields[2])
            .try_into()
            .expect("founder account width");
        let founder_atoms: u64 = fields[3].parse().expect("founder atoms");
        let public_goods_account: AccountId = decode_hex(fields[4])
            .try_into()
            .expect("public-goods account width");
        let public_goods_atoms: u64 = fields[5].parse().expect("public-goods atoms");
        let expected_ledger_snapshot = decode_hex(fields[6]);
        let expected_monetary_snapshot = decode_hex(fields[7]);

        let state = MonetaryLedgerState::genesis(
            network_id,
            founder_account,
            vec![(public_goods_account, public_goods_atoms)],
        )
        .expect("independent vector Genesis must be valid");
        assert_eq!(
            state.ledger().account(&founder_account).unwrap().balance,
            founder_atoms
        );

        let ledger_snapshot = state.ledger().encode_snapshot().unwrap();
        let monetary_snapshot = state.encode_snapshot().unwrap();
        assert_eq!(ledger_snapshot, expected_ledger_snapshot);
        assert_eq!(monetary_snapshot, expected_monetary_snapshot);
        assert_eq!(
            Sha256::digest(&ledger_snapshot).to_vec(),
            decode_hex(fields[8])
        );
        assert_eq!(
            Sha256::digest(&monetary_snapshot).to_vec(),
            decode_hex(fields[9])
        );
        assert_eq!(state.ledger().state_root().to_vec(), decode_hex(fields[10]));
        assert_eq!(
            monetary_policy_fingerprint().to_vec(),
            decode_hex(fields[11])
        );
        assert_eq!(state.state_root().to_vec(), decode_hex(fields[12]));
        assert_eq!(state.total_value().unwrap().to_string(), fields[13]);
        assert_eq!(
            MonetaryLedgerState::decode_snapshot(&expected_monetary_snapshot, &network_id).unwrap(),
            state
        );
    }

    #[test]
    fn monetary_genesis_requires_exact_founder_and_public_goods_budgets() {
        let state = monetary_genesis();
        assert_eq!(state.total_mined_atoms(), 0);
        assert_eq!(
            state.total_value().unwrap(),
            MONETARY_FOUNDER_ALLOCATION_ATOMS + MONETARY_PUBLIC_GOODS_BUDGET_ATOMS
        );
        assert_eq!(
            state.ledger().account(&account(1)).unwrap().balance as u128,
            MONETARY_FOUNDER_ALLOCATION_ATOMS
        );
        assert_eq!(
            state.ledger().account(&account(2)).unwrap().balance as u128,
            MONETARY_PUBLIC_GOODS_BUDGET_ATOMS
        );

        assert_eq!(
            MonetaryLedgerState::genesis(TEST_NETWORK_ID, account(1), vec![]),
            Err(StateError::InvalidMonetaryAllocation)
        );
        assert_eq!(
            MonetaryLedgerState::genesis(
                TEST_NETWORK_ID,
                account(1),
                vec![(account(2), (MONETARY_PUBLIC_GOODS_BUDGET_ATOMS - 1) as u64)]
            ),
            Err(StateError::InvalidMonetaryAllocation)
        );
        assert_eq!(
            MonetaryLedgerState::genesis(
                TEST_NETWORK_ID,
                account(1),
                vec![(account(1), MONETARY_PUBLIC_GOODS_BUDGET_ATOMS as u64)]
            ),
            Err(StateError::DuplicateGenesisAccount)
        );
    }

    #[test]
    fn monetary_genesis_rejects_invalid_network_zero_and_duplicate_allocations() {
        let public_goods_total = MONETARY_PUBLIC_GOODS_BUDGET_ATOMS as u64;
        let zero = [0u8; 32];

        assert_eq!(
            MonetaryLedgerState::genesis(zero, account(1), vec![(account(2), public_goods_total)]),
            Err(StateError::InvalidNetworkId)
        );
        assert_eq!(
            MonetaryLedgerState::genesis(
                TEST_NETWORK_ID,
                zero,
                vec![(account(2), public_goods_total)]
            ),
            Err(StateError::InvalidAccountId)
        );
        assert_eq!(
            MonetaryLedgerState::genesis(
                TEST_NETWORK_ID,
                account(1),
                vec![(zero, public_goods_total)]
            ),
            Err(StateError::InvalidAccountId)
        );
        assert_eq!(
            MonetaryLedgerState::genesis(TEST_NETWORK_ID, account(1), vec![(account(2), 0)]),
            Err(StateError::InvalidMonetaryAllocation)
        );
        assert_eq!(
            MonetaryLedgerState::genesis(
                TEST_NETWORK_ID,
                account(1),
                vec![(account(2), 1), (account(2), public_goods_total - 1),]
            ),
            Err(StateError::DuplicateGenesisAccount)
        );
        assert_eq!(
            MonetaryLedgerState::genesis(
                TEST_NETWORK_ID,
                account(1),
                vec![(account(2), public_goods_total), (account(3), 1),]
            ),
            Err(StateError::InvalidMonetaryAllocation)
        );
    }

    #[test]
    fn monetary_genesis_accepts_exact_public_goods_budget_split_across_accounts() {
        let half_budget = (MONETARY_PUBLIC_GOODS_BUDGET_ATOMS / 2) as u64;
        let state = MonetaryLedgerState::genesis(
            TEST_NETWORK_ID,
            account(1),
            vec![(account(2), half_budget), (account(3), half_budget)],
        )
        .expect("valid exact-budget split across distinct accounts");

        assert_eq!(
            state.total_value().unwrap(),
            MONETARY_FOUNDER_ALLOCATION_ATOMS + MONETARY_PUBLIC_GOODS_BUDGET_ATOMS
        );
        assert_eq!(
            state.ledger().account(&account(2)).unwrap().balance,
            half_budget
        );
        assert_eq!(
            state.ledger().account(&account(3)).unwrap().balance,
            half_budget
        );
    }

    #[test]
    fn monetary_reward_at_height_matches_cumulative_schedule_boundaries() {
        let heights = [
            1,
            2,
            MONETARY_BLOCKS_PER_HALVING - 1,
            MONETARY_BLOCKS_PER_HALVING,
            MONETARY_BLOCKS_PER_HALVING + 1,
            MONETARY_BLOCKS_PER_HALVING * 2 - 1,
            MONETARY_BLOCKS_PER_HALVING * 2,
            MONETARY_BLOCKS_PER_HALVING * 2 + 1,
            MONETARY_BLOCKS_PER_HALVING * 8,
            u64::MAX,
        ];

        for height in heights {
            let current_mined_atoms = monetary_issuance_after_blocks(height - 1);
            let expected_reward = monetary_issuance_after_blocks(height) - current_mined_atoms;
            assert_eq!(
                monetary_reward_for_height(height, current_mined_atoms),
                Ok(expected_reward),
                "reward model diverged from cumulative schedule at block height {height}"
            );
        }
    }

    #[test]
    fn monetary_issuance_schedule_has_exact_boundaries_and_never_exceeds_miner_budget() {
        assert_eq!(monetary_issuance_after_blocks(0), 0);
        assert_eq!(
            monetary_issuance_after_blocks(1),
            MONETARY_INITIAL_SUBSIDY_ATOMS
        );
        assert_eq!(
            monetary_issuance_after_blocks(MONETARY_BLOCKS_PER_HALVING),
            MONETARY_INITIAL_SUBSIDY_ATOMS * MONETARY_BLOCKS_PER_HALVING as u128
        );
        assert_eq!(
            monetary_issuance_after_blocks(MONETARY_BLOCKS_PER_HALVING + 1),
            MONETARY_INITIAL_SUBSIDY_ATOMS * MONETARY_BLOCKS_PER_HALVING as u128
                + MONETARY_INITIAL_SUBSIDY_ATOMS / 2
        );
        assert_eq!(
            monetary_issuance_after_blocks(u64::MAX),
            299_999_999_913_926_400
        );
        assert!(monetary_issuance_after_blocks(u64::MAX) <= MONETARY_MINER_BUDGET_ATOMS);
    }

    #[test]
    fn monetary_block_commits_miner_reward_and_applies_transactions_atomically() {
        let mut state = monetary_genesis();
        let expected_reward = state.expected_miner_reward().unwrap();
        let transaction = signed_tx(account(1), account(2), 1, 1_000, 3);
        let block = monetary_block(&state, account(3), 10, vec![transaction]);
        let encoded = encode_monetary_block(&block).unwrap();
        assert_eq!(decode_monetary_block(&encoded).unwrap(), block);

        let summary = state.apply_block(&block, &TestOnlyAuthenticator).unwrap();
        assert_eq!(summary.height, 1);
        assert_eq!(summary.transactions_applied, 1);
        assert_eq!(summary.fees_collected, 3);
        assert_eq!(summary.block_hash, monetary_block_id(&block).unwrap());
        assert_eq!(state.tip_hash(), summary.block_hash);
        assert_eq!(state.total_mined_atoms(), expected_reward as u128);
        assert_eq!(
            state.ledger().account(&account(3)).unwrap().balance,
            expected_reward
        );
        assert_eq!(
            state.ledger().account(&account(1)).unwrap().balance as u128,
            MONETARY_FOUNDER_ALLOCATION_ATOMS - 1_003
        );
        assert_eq!(state.ledger().fee_pool(), 3);
        assert_eq!(
            state.total_value().unwrap(),
            MONETARY_FOUNDER_ALLOCATION_ATOMS
                + MONETARY_PUBLIC_GOODS_BUDGET_ATOMS
                + expected_reward as u128
        );
        assert_eq!(summary.state_root, state.state_root());
    }

    #[test]
    fn wrong_miner_reward_and_state_root_are_rejected_without_mutation() {
        let mut state = monetary_genesis();
        let before = state.encode_snapshot().unwrap();
        let mut wrong_reward = monetary_block(&state, account(3), 10, vec![]);
        wrong_reward.claimed_subsidy_atoms += 1;
        assert!(matches!(
            state.apply_block(&wrong_reward, &TestOnlyAuthenticator),
            Err(StateError::MinerRewardMismatch { .. })
        ));
        assert_eq!(state.encode_snapshot().unwrap(), before);

        let mut wrong_root = monetary_block(&state, account(3), 10, vec![]);
        wrong_root.body.state_root[0] ^= 0x80;
        assert_eq!(
            state.apply_block(&wrong_root, &TestOnlyAuthenticator),
            Err(StateError::StateRootMismatch)
        );
        assert_eq!(state.encode_snapshot().unwrap(), before);
        assert_eq!(state.height(), 0);
        assert_eq!(state.total_mined_atoms(), 0);
    }

    #[test]
    fn monetary_snapshot_roundtrip_checks_counter_against_height_and_total_value() {
        let mut state = monetary_genesis();
        let first = monetary_block(&state, account(3), 10, vec![]);
        state.apply_block(&first, &TestOnlyAuthenticator).unwrap();
        let encoded = state.encode_snapshot().unwrap();
        let restored = MonetaryLedgerState::decode_snapshot(&encoded, &TEST_NETWORK_ID).unwrap();
        assert_eq!(restored, state);
        assert_eq!(restored.state_root(), state.state_root());

        let mut forged_counter = encoded.clone();
        forged_counter[53] ^= 1;
        let payload_len = forged_counter.len() - 32;
        let checksum = hash_domain(
            MONETARY_SNAPSHOT_CHECKSUM_DOMAIN,
            &[&forged_counter[..payload_len]],
        );
        forged_counter[payload_len..].copy_from_slice(&checksum);
        assert_eq!(
            MonetaryLedgerState::decode_snapshot(&forged_counter, &TEST_NETWORK_ID),
            Err(StateError::InvariantViolation)
        );
    }

    #[test]
    fn monetary_envelope_rejects_trailing_bytes_and_other_versions() {
        let state = monetary_genesis();
        let block = monetary_block(&state, account(3), 10, vec![]);
        let encoded = encode_monetary_block(&block).unwrap();
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(decode_monetary_block(&trailing), Err(StateError::Malformed));

        let mut unsupported = encoded;
        unsupported[5] = MONETARY_FORMAT_VERSION as u8 + 1;
        assert_eq!(
            decode_monetary_block(&unsupported),
            Err(StateError::UnsupportedVersion(MONETARY_FORMAT_VERSION + 1))
        );
    }
}

#[cfg(test)]
mod v4_hybrid_mbk4_tests {
    use super::*;
    use crate::v4_account_identity_candidate::{
        legacy_v3_account_id, native_v4_account_id, AccountIdentityScheme, V4HybridAuthorization,
        V4HybridSignature, V4HybridTransaction, ML_DSA_65_PUBLIC_KEY_BYTES,
        ML_DSA_65_SIGNATURE_BYTES,
    };
    use crate::v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate;
    use ed25519_dalek::{Signer, SigningKey};
    use libcrux_ml_dsa::ml_dsa_65::portable;

    const NETWORK: NetworkId = [0xAA; 32];
    const MANIFEST: [u8; 32] = [0xB2; 32];

    fn account(byte: u8) -> AccountId {
        [byte; 32]
    }

    fn signed_tx(
        scheme: AccountIdentityScheme,
        manifest_id: [u8; 32],
        nonce: u64,
        amount_atoms: u64,
    ) -> V4HybridTransaction {
        let ed_signer = SigningKey::from_bytes(&[0x31; 32]);
        let ed_public_key = ed_signer.verifying_key().to_bytes();
        let pq_pair = portable::generate_key_pair([0x42; 32]);
        let mldsa65_public_key: [u8; ML_DSA_65_PUBLIC_KEY_BYTES] =
            *pq_pair.verification_key.as_ref();
        let sender_id = match scheme {
            AccountIdentityScheme::LegacyV3Hybrid => {
                legacy_v3_account_id(&ed_public_key, &mldsa65_public_key)
            }
            AccountIdentityScheme::NativeV4Hybrid => {
                native_v4_account_id(&ed_public_key, &mldsa65_public_key)
            }
        };
        let authorization = V4HybridAuthorization {
            network_id: NETWORK,
            manifest_id,
            sender_id,
            recipient_id: account(0xCC),
            nonce,
            amount_atoms,
            fee_atoms: 17,
            expires_at: 1_000,
            identity_scheme: scheme,
            ed25519_public_key: ed_public_key,
            mldsa65_public_key,
        };
        let digest = authorization.signing_digest().unwrap();
        let ed25519_signature = ed_signer.sign(&digest).to_bytes();
        let mldsa65_signature =
            portable::sign(&pq_pair.signing_key, &digest, &[], [0x53; 32]).unwrap();
        let mldsa65_signature: [u8; ML_DSA_65_SIGNATURE_BYTES] = *mldsa65_signature.as_ref();
        V4HybridTransaction {
            authorization,
            signature: V4HybridSignature {
                ed25519_signature,
                mldsa65_signature,
            },
        }
    }

    fn genesis_for(tx: &V4HybridTransaction) -> MonetaryLedgerState {
        let sender = tx.authorization.sender_id;
        let sender_allocation = 1_000_000u64;
        let remaining =
            u64::try_from(MONETARY_PUBLIC_GOODS_BUDGET_ATOMS - u128::from(sender_allocation))
                .unwrap();
        MonetaryLedgerState::genesis(
            NETWORK,
            account(0xF0),
            vec![(sender, sender_allocation), (account(0xF1), remaining)],
        )
        .unwrap()
    }

    fn block_for(
        state: &MonetaryLedgerState,
        transactions: Vec<V4HybridTransaction>,
    ) -> V4HybridMonetaryBlock {
        V4HybridMonetaryBlock {
            height: state.height() + 1,
            timestamp: 100,
            parent_hash: state.tip_hash(),
            state_root: [0; 32],
            transactions,
            miner: account(0xD0),
            claimed_subsidy_atoms: state.expected_miner_reward().unwrap(),
        }
    }

    #[test]
    fn mbk4_canonical_codec_and_atomic_transfer_work_for_v3_and_v4_id_schemes() {
        let verifier = LibcruxMlDsa65VerifierCandidate;
        for scheme in [
            AccountIdentityScheme::LegacyV3Hybrid,
            AccountIdentityScheme::NativeV4Hybrid,
        ] {
            let tx = signed_tx(scheme, MANIFEST, 1, 1_000);
            let mut state = genesis_for(&tx);
            let sender = tx.authorization.sender_id;
            let initial_sender_balance = state.ledger().account(&sender).unwrap().balance;
            let mut block = block_for(&state, vec![tx]);
            block.state_root = state
                .preview_v4_hybrid_state_root_after(&block, &MANIFEST, &verifier)
                .unwrap();

            let encoded = encode_v4_hybrid_monetary_block(&block).unwrap();
            assert_eq!(&encoded[..4], b"MBK4");
            assert_eq!(decode_v4_hybrid_monetary_block(&encoded).unwrap(), block);
            assert_eq!(
                encode_v4_hybrid_monetary_block(
                    &decode_v4_hybrid_monetary_block(&encoded).unwrap()
                )
                .unwrap(),
                encoded
            );

            let summary = state
                .apply_v4_hybrid_block_candidate(&block, &MANIFEST, &verifier)
                .unwrap();
            assert_eq!(summary.transactions_applied, 1);
            assert_eq!(summary.fees_collected, 17);
            assert_eq!(state.height(), 1);
            assert_eq!(
                state.ledger().account(&sender).unwrap().balance,
                initial_sender_balance - 1_017
            );
            assert_eq!(state.ledger().account(&sender).unwrap().nonce, 1);
            assert_eq!(
                state.ledger().account(&account(0xCC)).unwrap().balance,
                1_000
            );
            assert_eq!(
                state.total_mined_atoms(),
                u128::from(block.claimed_subsidy_atoms)
            );
            assert_eq!(summary.state_root, state.state_root());
        }
    }

    #[test]
    fn mbk4_wrong_manifest_and_mutated_signature_are_atomic_failures() {
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let tx = signed_tx(AccountIdentityScheme::NativeV4Hybrid, MANIFEST, 1, 1_000);
        let mut state = genesis_for(&tx);
        let mut block = block_for(&state, vec![tx]);
        block.state_root = state
            .preview_v4_hybrid_state_root_after(&block, &MANIFEST, &verifier)
            .unwrap();
        let before = state.encode_snapshot().unwrap();

        assert_eq!(
            state.apply_v4_hybrid_block_candidate(&block, &[0xB3; 32], &verifier),
            Err(StateError::ManifestMismatch)
        );
        assert_eq!(state.encode_snapshot().unwrap(), before);

        block.transactions[0].signature.mldsa65_signature[0] ^= 1;
        assert_eq!(
            state.apply_v4_hybrid_block_candidate(&block, &MANIFEST, &verifier),
            Err(StateError::Unauthorized)
        );
        assert_eq!(state.encode_snapshot().unwrap(), before);
        assert_eq!(state.height(), 0);
        assert_eq!(state.total_mined_atoms(), 0);
    }

    #[test]
    fn mbk4_duplicate_transactions_wrong_network_and_expired_tx_reject_atomically() {
        let verifier = LibcruxMlDsa65VerifierCandidate;
        let tx = signed_tx(AccountIdentityScheme::NativeV4Hybrid, MANIFEST, 1, 1_000);
        let mut state = genesis_for(&tx);
        let before = state.encode_snapshot().unwrap();

        let duplicate = block_for(&state, vec![tx.clone(), tx.clone()]);
        assert_eq!(
            state.apply_v4_hybrid_block_candidate(&duplicate, &MANIFEST, &verifier),
            Err(StateError::DuplicateTransaction)
        );
        assert_eq!(state.encode_snapshot().unwrap(), before);

        let mut wrong_network = tx.clone();
        wrong_network.authorization.network_id = [0xAB; 32];
        let (ed_signer, pq_pair) = {
            let ed = SigningKey::from_bytes(&[0x31; 32]);
            let pq = portable::generate_key_pair([0x42; 32]);
            (ed, pq)
        };
        wrong_network.authorization.ed25519_public_key = ed_signer.verifying_key().to_bytes();
        wrong_network.authorization.mldsa65_public_key = *pq_pair.verification_key.as_ref();
        wrong_network.authorization.sender_id = native_v4_account_id(
            &wrong_network.authorization.ed25519_public_key,
            &wrong_network.authorization.mldsa65_public_key,
        );
        let digest = wrong_network.authorization.signing_digest().unwrap();
        wrong_network.signature.ed25519_signature = ed_signer.sign(&digest).to_bytes();
        wrong_network.signature.mldsa65_signature =
            *portable::sign(&pq_pair.signing_key, &digest, &[], [0x53; 32])
                .unwrap()
                .as_ref();
        let wrong_network_block = block_for(&state, vec![wrong_network]);
        assert_eq!(
            state.apply_v4_hybrid_block_candidate(&wrong_network_block, &MANIFEST, &verifier),
            Err(StateError::WrongNetwork)
        );
        assert_eq!(state.encode_snapshot().unwrap(), before);

        let expired = signed_tx(AccountIdentityScheme::NativeV4Hybrid, MANIFEST, 1, 1_000);
        let mut expired = expired;
        expired.authorization.expires_at = 100;
        let ed_signer = SigningKey::from_bytes(&[0x31; 32]);
        let pq_pair = portable::generate_key_pair([0x42; 32]);
        expired.authorization.ed25519_public_key = ed_signer.verifying_key().to_bytes();
        expired.authorization.mldsa65_public_key = *pq_pair.verification_key.as_ref();
        expired.authorization.sender_id = native_v4_account_id(
            &expired.authorization.ed25519_public_key,
            &expired.authorization.mldsa65_public_key,
        );
        let digest = expired.authorization.signing_digest().unwrap();
        expired.signature.ed25519_signature = ed_signer.sign(&digest).to_bytes();
        expired.signature.mldsa65_signature =
            *portable::sign(&pq_pair.signing_key, &digest, &[], [0x53; 32])
                .unwrap()
                .as_ref();
        let expired_block = block_for(&state, vec![expired]);
        assert_eq!(
            state.apply_v4_hybrid_block_candidate(&expired_block, &MANIFEST, &verifier),
            Err(StateError::TransactionExpired {
                expires_at: 100,
                block_timestamp: 100,
            })
        );
        assert_eq!(state.encode_snapshot().unwrap(), before);
    }

    #[test]
    fn mbk4_codec_rejects_suffix_wrong_version_and_noncanonical_length() {
        let tx = signed_tx(AccountIdentityScheme::NativeV4Hybrid, MANIFEST, 1, 1_000);
        let state = genesis_for(&tx);
        let block = block_for(&state, vec![tx]);
        let encoded = encode_v4_hybrid_monetary_block(&block).unwrap();

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            decode_v4_hybrid_monetary_block(&trailing),
            Err(StateError::Malformed)
        );

        let mut unsupported = encoded.clone();
        unsupported[5] ^= 1;
        assert_eq!(
            decode_v4_hybrid_monetary_block(&unsupported),
            Err(StateError::UnsupportedVersion(
                V4_HYBRID_MONETARY_FORMAT_VERSION + 1
            ))
        );

        let mut wrong_magic = encoded.clone();
        wrong_magic[0] ^= 1;
        assert_eq!(
            decode_v4_hybrid_monetary_block(&wrong_magic),
            Err(StateError::BadMagic)
        );
    }
}
