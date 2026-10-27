//! QRun v0.5 state execution candidate.
//!
//! This module connects the 10B Genesis candidate to native transfer block execution and a
//! checksummed local snapshot format. It is NOT yet connected to the peer/node binary, canonical
//! fork choice, externally anchored anti-rollback storage, or production signer/RPC endpoints.
//! Store checksums detect accidental corruption, not a malicious operator rewriting history.
use crate::qrun_v05_genesis_candidate::{QRunGenesisError, QRunGenesisV05};
use crate::state_machine::{
    decode_block, encode_block, AccountId, Block, BlockApplySummary, LedgerState, NetworkId,
    StateError, Transaction, TransactionAuthenticator, MAX_TOTAL_SUPPLY_ATOMS,
};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const STORE_MAGIC: [u8; 4] = *b"QRS5";
const STORE_VERSION: u16 = 2;
const STORE_DOMAIN: &[u8] = b"QUANTUMZXB-QRUN-RUNTIME-STORE-V05\0";
const STORE_CHECKSUM_LEN: usize = 32;
const STORE_HEADER_V1_LEN: usize = 4 + 2 + 32 + 32 + 32 + 4;
const STORE_HEADER_LEN: usize = 4 + 2 + 32 + 32 + 32 + 4 + 4;
const MAX_STORE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QRunV05RuntimeError {
    Io(String),
    Genesis(QRunGenesisError),
    Ledger(StateError),
    InvalidStore,
    StoreChecksumMismatch,
    StoreTooLarge,
    LegacyStoreMissingHistory,
    StoreHistoryMismatch,
    WrongGenesisIdentity,
    SupplyInvariant { expected: u128, actual: u128 },
    TimestampNotIncreasing { previous: u64, actual: u64 },
}

impl From<StateError> for QRunV05RuntimeError {
    fn from(value: StateError) -> Self {
        Self::Ledger(value)
    }
}

impl From<QRunGenesisError> for QRunV05RuntimeError {
    fn from(value: QRunGenesisError) -> Self {
        Self::Genesis(value)
    }
}

/// Candidate state executor for a selected QRun v0.5 Genesis and explicit transaction verifier.
/// A production node still needs consensus, peer transport, fork choice, externally anchored
/// anti-rollback, metrics, and network/API integration before this can be treated as canonical.
pub struct QRunV05ExecutionRuntime<A: TransactionAuthenticator> {
    network_id: NetworkId,
    owner_account: AccountId,
    genesis_commitment: [u8; 32],
    state: LedgerState,
    history: Vec<Block>,
    authenticator: A,
    store_path: PathBuf,
}

impl<A: TransactionAuthenticator> QRunV05ExecutionRuntime<A> {
    /// Open existing state, or explicitly initialize a fresh v0.5 Genesis at the given path.
    /// If a store exists, changing the network or Genesis owner is rejected.
    pub fn open_or_create(
        network_id: NetworkId,
        owner_account: AccountId,
        authenticator: A,
        store_path: impl AsRef<Path>,
    ) -> Result<Self, QRunV05RuntimeError> {
        let genesis = QRunGenesisV05::new(network_id, owner_account)?;
        let store_path = store_path.as_ref().to_path_buf();
        let mut rewrite_store = !store_path.exists();
        let (state, history) = if store_path.exists() {
            let bytes = fs::read(&store_path)
                .map_err(|error| QRunV05RuntimeError::Io(error.to_string()))?;
            let (stored_network, stored_owner, stored_commitment, snapshot, history, version) =
                decode_store(&bytes)?;
            if stored_network != network_id
                || stored_owner != owner_account
                || stored_commitment != genesis.commitment()
            {
                return Err(QRunV05RuntimeError::WrongGenesisIdentity);
            }
            let stored_state = LedgerState::decode_snapshot(snapshot, &network_id)?;
            Self::check_full_supply(&stored_state)?;
            if version == 1 {
                let expected_genesis = genesis.ledger().encode_snapshot()?;
                if stored_state.height() != 0 || expected_genesis.as_slice() != snapshot {
                    return Err(QRunV05RuntimeError::LegacyStoreMissingHistory);
                }
                // Only an untouched Genesis can be migrated from the old snapshot-only format.
                rewrite_store = true;
                (genesis.ledger().clone(), Vec::new())
            } else {
                if history.len() as u64 != stored_state.height() {
                    return Err(QRunV05RuntimeError::StoreHistoryMismatch);
                }
                let mut replayed = genesis.ledger().clone();
                for block in &history {
                    replayed.apply_block(block, &authenticator)?;
                    Self::check_full_supply(&replayed)?;
                }
                let replayed_snapshot = replayed.encode_snapshot()?;
                if replayed_snapshot.as_slice() != snapshot {
                    return Err(QRunV05RuntimeError::StoreHistoryMismatch);
                }
                (replayed, history)
            }
        } else {
            (genesis.ledger().clone(), Vec::new())
        };
        let runtime = Self {
            network_id,
            owner_account,
            genesis_commitment: genesis.commitment(),
            state,
            history,
            authenticator,
            store_path,
        };
        if rewrite_store {
            runtime.persist()?;
        }
        Ok(runtime)
    }
    fn check_full_supply(state: &LedgerState) -> Result<(), QRunV05RuntimeError> {
        let actual = state.total_value()?;
        if actual != MAX_TOTAL_SUPPLY_ATOMS {
            return Err(QRunV05RuntimeError::SupplyInvariant {
                expected: MAX_TOTAL_SUPPLY_ATOMS,
                actual,
            });
        }
        Ok(())
    }

    fn persist(&self) -> Result<(), QRunV05RuntimeError> {
        let snapshot = self.state.encode_snapshot()?;
        let bytes = encode_store(
            self.network_id,
            self.owner_account,
            self.genesis_commitment,
            &snapshot,
            &self.history,
        )?;
        atomic_write(&self.store_path, &bytes)
    }
    pub fn network_id(&self) -> NetworkId {
        self.network_id
    }

    pub fn owner_account(&self) -> AccountId {
        self.owner_account
    }

    pub fn height(&self) -> u64 {
        self.state.height()
    }

    pub fn genesis_commitment(&self) -> [u8; 32] {
        self.genesis_commitment
    }

    pub fn retained_block_count(&self) -> usize {
        self.history.len()
    }

    pub fn state_root(&self) -> [u8; 32] {
        self.state.state_root()
    }

    pub fn total_supply_atoms(&self) -> Result<u128, QRunV05RuntimeError> {
        Self::check_full_supply(&self.state)?;
        Ok(MAX_TOTAL_SUPPLY_ATOMS)
    }

    pub fn owner_balance_atoms(&self) -> u64 {
        self.state
            .account(&self.owner_account)
            .map_or(0, |account| account.balance)
    }

    pub fn balance_atoms(&self, account: &AccountId) -> u64 {
        self.state
            .account(account)
            .map_or(0, |account| account.balance)
    }

    pub fn state(&self) -> &LedgerState {
        &self.state
    }

    /// Build a block using the current tip and independently compute its post-state root.
    /// The supplied verifier must reject any signature that is not valid for its sender.
    pub fn build_next_block(
        &self,
        timestamp: u64,
        transactions: Vec<Transaction>,
    ) -> Result<Block, QRunV05RuntimeError> {
        if timestamp <= self.state.last_timestamp() {
            return Err(QRunV05RuntimeError::TimestampNotIncreasing {
                previous: self.state.last_timestamp(),
                actual: timestamp,
            });
        }
        let height = self
            .state
            .height()
            .checked_add(1)
            .ok_or(StateError::InvalidHeight)?;
        let mut block = Block {
            height,
            timestamp,
            parent_hash: self.state.tip_hash(),
            state_root: [0; 32],
            transactions,
        };
        block.state_root = self
            .state
            .preview_state_root_after(&block, &self.authenticator)?;
        Ok(block)
    }

    /// Independently execute a block; persist only a valid full-supply result. If storage fails,
    /// restore the in-memory state so callers do not observe an uncommitted state transition.
    pub fn import_block(
        &mut self,
        block: &Block,
    ) -> Result<BlockApplySummary, QRunV05RuntimeError> {
        // Stage the complete state transition before altering the published runtime state.
        let mut candidate = self.state.clone();
        let summary = candidate.apply_block(block, &self.authenticator)?;
        Self::check_full_supply(&candidate)?;

        let previous = std::mem::replace(&mut self.state, candidate);
        self.history.push(block.clone());
        if let Err(error) = self.persist() {
            self.history.pop();
            self.state = previous;
            return Err(error);
        }
        Ok(summary)
    }
}
fn store_checksum(payload: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(STORE_DOMAIN);
    hash.update(payload);
    hash.finalize().into()
}

fn encode_store(
    network_id: NetworkId,
    owner_account: AccountId,
    genesis_commitment: [u8; 32],
    snapshot: &[u8],
    history: &[Block],
) -> Result<Vec<u8>, QRunV05RuntimeError> {
    if snapshot.len() > u32::MAX as usize || history.len() > u32::MAX as usize {
        return Err(QRunV05RuntimeError::StoreTooLarge);
    }
    let mut bytes = Vec::with_capacity(
        STORE_HEADER_LEN + snapshot.len() + STORE_CHECKSUM_LEN + history.len().saturating_mul(64),
    );
    bytes.extend_from_slice(&STORE_MAGIC);
    bytes.extend_from_slice(&STORE_VERSION.to_be_bytes());
    bytes.extend_from_slice(&network_id);
    bytes.extend_from_slice(&owner_account);
    bytes.extend_from_slice(&genesis_commitment);
    bytes.extend_from_slice(&(snapshot.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&(history.len() as u32).to_be_bytes());
    bytes.extend_from_slice(snapshot);
    for block in history {
        let encoded = encode_block(block).map_err(|_| QRunV05RuntimeError::InvalidStore)?;
        if encoded.is_empty() || encoded.len() > u32::MAX as usize {
            return Err(QRunV05RuntimeError::StoreTooLarge);
        }
        let needed = bytes
            .len()
            .checked_add(4)
            .and_then(|len| len.checked_add(encoded.len()))
            .and_then(|len| len.checked_add(STORE_CHECKSUM_LEN))
            .ok_or(QRunV05RuntimeError::StoreTooLarge)?;
        if needed > MAX_STORE_BYTES {
            return Err(QRunV05RuntimeError::StoreTooLarge);
        }
        bytes.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&encoded);
    }
    if bytes.len().saturating_add(STORE_CHECKSUM_LEN) > MAX_STORE_BYTES {
        return Err(QRunV05RuntimeError::StoreTooLarge);
    }
    let checksum = store_checksum(&bytes);
    bytes.extend_from_slice(&checksum);
    Ok(bytes)
}

/// Version 1 is accepted only for an untouched Genesis and is immediately upgraded.
/// Version 2 binds the ordered block history into the same checksummed atomic store.
fn decode_store(
    bytes: &[u8],
) -> Result<(NetworkId, AccountId, [u8; 32], &[u8], Vec<Block>, u16), QRunV05RuntimeError> {
    if bytes.len() > MAX_STORE_BYTES || bytes.len() < STORE_HEADER_V1_LEN + STORE_CHECKSUM_LEN {
        return Err(if bytes.len() > MAX_STORE_BYTES {
            QRunV05RuntimeError::StoreTooLarge
        } else {
            QRunV05RuntimeError::InvalidStore
        });
    }
    if bytes[..4] != STORE_MAGIC {
        return Err(QRunV05RuntimeError::InvalidStore);
    }
    let version = u16::from_be_bytes([bytes[4], bytes[5]]);
    if version != 1 && version != STORE_VERSION {
        return Err(QRunV05RuntimeError::InvalidStore);
    }
    let payload_len = bytes.len() - STORE_CHECKSUM_LEN;
    let expected_checksum = store_checksum(&bytes[..payload_len]);
    if bytes[payload_len..] != expected_checksum[..] {
        return Err(QRunV05RuntimeError::StoreChecksumMismatch);
    }

    let network_id = bytes[6..38].try_into().expect("fixed network ID range");
    let owner = bytes[38..70].try_into().expect("fixed owner range");
    let commitment = bytes[70..102].try_into().expect("fixed commitment range");
    let snapshot_len =
        u32::from_be_bytes(bytes[102..106].try_into().expect("fixed snapshot length")) as usize;
    let (snapshot_start, history_count) = if version == 1 {
        (STORE_HEADER_V1_LEN, 0usize)
    } else {
        let count =
            u32::from_be_bytes(bytes[106..110].try_into().expect("fixed history count")) as usize;
        (STORE_HEADER_LEN, count)
    };
    let snapshot_end = snapshot_start
        .checked_add(snapshot_len)
        .ok_or(QRunV05RuntimeError::InvalidStore)?;
    if snapshot_end > payload_len {
        return Err(QRunV05RuntimeError::InvalidStore);
    }

    let mut history = Vec::new();
    let mut cursor = snapshot_end;
    for _ in 0..history_count {
        let len_end = cursor
            .checked_add(4)
            .ok_or(QRunV05RuntimeError::InvalidStore)?;
        if len_end > payload_len {
            return Err(QRunV05RuntimeError::InvalidStore);
        }
        let block_len = u32::from_be_bytes(
            bytes[cursor..len_end]
                .try_into()
                .expect("fixed block length"),
        ) as usize;
        if block_len == 0 || block_len > MAX_STORE_BYTES {
            return Err(QRunV05RuntimeError::InvalidStore);
        }
        let block_end = len_end
            .checked_add(block_len)
            .ok_or(QRunV05RuntimeError::InvalidStore)?;
        if block_end > payload_len {
            return Err(QRunV05RuntimeError::InvalidStore);
        }
        let block = decode_block(&bytes[len_end..block_end])
            .map_err(|_| QRunV05RuntimeError::InvalidStore)?;
        history.push(block);
        cursor = block_end;
    }
    if cursor != payload_len {
        return Err(QRunV05RuntimeError::InvalidStore);
    }
    Ok((
        network_id,
        owner,
        commitment,
        &bytes[snapshot_start..snapshot_end],
        history,
        version,
    ))
}
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), QRunV05RuntimeError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| QRunV05RuntimeError::Io(error.to_string()))?;
    }
    let temp = path.with_extension(format!("qrun-v05-{}.tmp", std::process::id()));
    if temp.exists() {
        fs::remove_file(&temp).map_err(|error| QRunV05RuntimeError::Io(error.to_string()))?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .map_err(|error| QRunV05RuntimeError::Io(error.to_string()))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| QRunV05RuntimeError::Io(error.to_string()))?;
    drop(file);
    fs::rename(&temp, path).map_err(|error| {
        let _ = fs::remove_file(&temp);
        QRunV05RuntimeError::Io(error.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_machine::ATOMS_PER_COIN;
    use std::time::{SystemTime, UNIX_EPOCH};

    const NETWORK: NetworkId = [0x51; 32];
    const OWNER: AccountId = [0x2a; 32];
    const RECIPIENT: AccountId = [0x3b; 32];

    struct TestAuthenticator;

    impl TransactionAuthenticator for TestAuthenticator {
        fn verify(
            &self,
            _sender: &AccountId,
            _signing_digest: &[u8; 32],
            signature: &[u8],
        ) -> Result<(), ()> {
            if signature == &[0x5a] {
                Ok(())
            } else {
                Err(())
            }
        }
    }

    fn store_path() -> PathBuf {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("qrun-v05-runtime-{}-{now}.qrs", std::process::id()))
    }

    fn transfer(signature: Vec<u8>) -> Transaction {
        Transaction {
            network_id: NETWORK,
            sender: OWNER,
            recipient: RECIPIENT,
            nonce: 1,
            amount: 12_345,
            fee: 67,
            expires_at: 100,
            signature,
        }
    }

    #[test]
    fn genesis_snapshot_transfer_and_restart_preserve_full_supply() {
        let path = store_path();
        let mut runtime =
            QRunV05ExecutionRuntime::open_or_create(NETWORK, OWNER, TestAuthenticator, &path)
                .unwrap();
        assert_eq!(runtime.height(), 0);
        assert_eq!(runtime.owner_balance_atoms(), MAX_TOTAL_SUPPLY_ATOMS as u64);
        assert_eq!(
            runtime.total_supply_atoms().unwrap(),
            10_000_000_000u128 * ATOMS_PER_COIN as u128
        );

        let block = runtime
            .build_next_block(1, vec![transfer(vec![0x5a])])
            .unwrap();
        let receipt = runtime.import_block(&block).unwrap();
        assert_eq!(receipt.height, 1);
        assert_eq!(runtime.height(), 1);
        assert_eq!(
            runtime.owner_balance_atoms(),
            MAX_TOTAL_SUPPLY_ATOMS as u64 - 12_345 - 67
        );
        assert_eq!(runtime.balance_atoms(&RECIPIENT), 12_345);
        assert_eq!(runtime.state().fee_pool(), 67);
        assert_eq!(
            runtime.total_supply_atoms().unwrap(),
            MAX_TOTAL_SUPPLY_ATOMS
        );
        drop(runtime);

        let reopened =
            QRunV05ExecutionRuntime::open_or_create(NETWORK, OWNER, TestAuthenticator, &path)
                .unwrap();
        assert_eq!(reopened.height(), 1);
        assert_eq!(reopened.retained_block_count(), 1);
        assert_eq!(reopened.balance_atoms(&RECIPIENT), 12_345);
        assert_eq!(
            reopened.total_supply_atoms().unwrap(),
            MAX_TOTAL_SUPPLY_ATOMS
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn runtime_executes_real_ed25519_signed_transfer() {
        use crate::transaction_auth::{
            AccountPublicKey, Ed25519TransactionAuthenticator, Ed25519TransactionSigner,
            TransactionAuthenticatorKind,
        };

        let signer = Ed25519TransactionSigner::from_seed([0x61; 32]);
        let owner = signer.account_id();
        let recipient: AccountId = [0x72; 32];
        let authenticator = Ed25519TransactionAuthenticator::select(
            TransactionAuthenticatorKind::Ed25519V1,
            vec![AccountPublicKey {
                account_id: owner,
                public_key: signer.public_key(),
            }],
        )
        .unwrap();
        let path = store_path();
        let mut runtime =
            QRunV05ExecutionRuntime::open_or_create(NETWORK, owner, authenticator, &path).unwrap();
        let mut tx = Transaction {
            network_id: NETWORK,
            sender: owner,
            recipient,
            nonce: 1,
            amount: 1_000,
            fee: 10,
            expires_at: 100,
            signature: Vec::new(),
        };
        signer.sign_transaction(&mut tx).unwrap();
        let block = runtime.build_next_block(1, vec![tx]).unwrap();
        runtime.import_block(&block).unwrap();

        assert_eq!(runtime.balance_atoms(&recipient), 1_000);
        assert_eq!(
            runtime.owner_balance_atoms(),
            MAX_TOTAL_SUPPLY_ATOMS as u64 - 1_010
        );
        assert_eq!(
            runtime.total_supply_atoms().unwrap(),
            MAX_TOTAL_SUPPLY_ATOMS
        );
        drop(runtime);
        let _ = fs::remove_file(path);
    }
    #[test]
    fn runtime_rejects_wrong_genesis_identity_and_bad_signatures() {
        let path = store_path();
        let runtime =
            QRunV05ExecutionRuntime::open_or_create(NETWORK, OWNER, TestAuthenticator, &path)
                .unwrap();
        assert!(matches!(
            QRunV05ExecutionRuntime::open_or_create(NETWORK, RECIPIENT, TestAuthenticator, &path),
            Err(QRunV05RuntimeError::WrongGenesisIdentity)
        ));
        assert!(matches!(
            runtime.build_next_block(1, vec![transfer(vec![0])]),
            Err(QRunV05RuntimeError::Ledger(StateError::Unauthorized))
        ));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn runtime_rejects_corrupt_store_checksum() {
        let path = store_path();
        let _runtime =
            QRunV05ExecutionRuntime::open_or_create(NETWORK, OWNER, TestAuthenticator, &path)
                .unwrap();
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x80;
        fs::write(&path, bytes).unwrap();
        assert!(matches!(
            QRunV05ExecutionRuntime::open_or_create(NETWORK, OWNER, TestAuthenticator, &path),
            Err(QRunV05RuntimeError::StoreChecksumMismatch)
        ));
        let _ = fs::remove_file(path);
    }
}
