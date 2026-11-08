//! QRun v0.6 unified native-ledger + AMM asset-transition candidate.
//!
//! The native QZXB LedgerState is the sole source of spendable native balances and nonce.
//! The AMM keeps a deterministic projection of those same native balances alongside
//! non-native registered assets, pool custody and LP accounting. Every market operation
//! stages both states on a clone, applies the AMM operation, reflects native balance deltas
//! into LedgerState, verifies the mirror and only then commits the combined candidate.
//!
//! This is M2b candidate code only. It is not wired into QFP5/QFB5 or a QFP6 block executor;
//! callers must already have verified the signed transaction and must include the combined
//! root in a future versioned consensus transition before it can represent live execution.

use crate::qrun_v06_asset_registry_candidate::{
    AssetId, AssetRegistration, AssetRegistryError, QRunV06AssetRegistryCandidate,
    SignedAssetAdminOperation,
};
use crate::qrun_v06_orderbook_candidate::{
    Error as OrderBookError, QRunV06SignedOrderBookOperation,
};
use crate::qzxb_amm_candidate::{
    qzxb_native_asset_id, AmmError, AmmOperation, AmmSignedOperation, QzxbAmmStateCandidate,
    SwapReceipt,
};
use crate::state_machine::{AccountId, LedgerState, StateError, TransactionAuthenticator};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const UNIFIED_STATE_ROOT_DOMAIN: &[u8] = b"QRUN-V06-UNIFIED-ASSET-STATE-ROOT-CANDIDATE-V2\0";
const MAX_V06_REGISTERED_ASSETS: usize = 4_096;
const ORDERBOOK_VAULT_DOMAIN: &[u8] = b"QRUN-V06-ORDERBOOK-ASSET-VAULT\0";

pub(crate) fn orderbook_vault_account(network: [u8; 32], asset: AssetId) -> AccountId {
    let mut hash = Sha256::new();
    hash.update(ORDERBOOK_VAULT_DOMAIN);
    hash.update(network);
    hash.update(asset);
    hash.finalize().into()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnifiedAssetError {
    WrongNetwork,
    NativeAssetNotRegistered,
    NativeBalanceMirrorMismatch {
        account: AccountId,
        ledger: u64,
        amm: u128,
    },
    PoolCustodyMismatch {
        account: AccountId,
        ledger: u64,
        amm: u128,
    },
    NativeBalanceOutOfRange {
        account: AccountId,
        balance: u128,
    },
    AmmNonceAheadOfLedger {
        account: AccountId,
        amm_nonce: u64,
        ledger_nonce: u64,
    },
    InvalidMarketNonce {
        expected: u64,
        actual: u64,
    },
    AssetNotRegistered(AssetId),
    AssetTransfersDisabled(AssetId),
    AssetSupplyMismatch {
        asset_id: AssetId,
        registry_supply: u128,
        amm_supply: u128,
    },
    NativeAssetReserved,
    UnmanagedAssetRegistration,
    TestQuoteMintNotAvailableInUnifiedState,
    OrderBookVaultMismatch {
        asset_id: AssetId,
        expected_backing: u128,
        actual_vault_balance: u128,
    },
    OrderBookVaultCollision(AssetId),
    InvalidOrderBookTransfer,
    AssetRegistry(AssetRegistryError),
    OrderBook(OrderBookError),
    Amm(AmmError),
    Ledger(StateError),
}

impl From<OrderBookError> for UnifiedAssetError {
    fn from(value: OrderBookError) -> Self {
        Self::OrderBook(value)
    }
}

impl From<AssetRegistryError> for UnifiedAssetError {
    fn from(value: AssetRegistryError) -> Self {
        Self::AssetRegistry(value)
    }
}

impl From<AmmError> for UnifiedAssetError {
    fn from(value: AmmError) -> Self {
        Self::Amm(value)
    }
}
impl From<StateError> for UnifiedAssetError {
    fn from(value: StateError) -> Self {
        Self::Ledger(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06UnifiedAssetState {
    ledger: LedgerState,
    amm: QzxbAmmStateCandidate,
    registry: QRunV06AssetRegistryCandidate,
    native_asset_id: [u8; 32],
}

impl QRunV06UnifiedAssetState {
    /// Bind an AMM candidate to the native ledger with no non-native assets registered.
    /// Any pre-existing non-native AMM IDs are rejected rather than implicitly trusted.
    pub fn new(ledger: LedgerState, amm: QzxbAmmStateCandidate) -> Result<Self, UnifiedAssetError> {
        let registry =
            QRunV06AssetRegistryCandidate::new(ledger.network_id(), MAX_V06_REGISTERED_ASSETS)?;
        Self::new_with_registry(ledger, amm, registry)
    }

    /// Bind a pre-populated metadata registry to LedgerState and the AMM projection.
    /// Every non-native AMM asset must have registry metadata and aggregate balances equal
    /// to its registered outstanding supply. Native QZXB remains governed by LedgerState.
    pub fn new_with_registry(
        ledger: LedgerState,
        mut amm: QzxbAmmStateCandidate,
        registry: QRunV06AssetRegistryCandidate,
    ) -> Result<Self, UnifiedAssetError> {
        if ledger.network_id() != amm.network_id() || ledger.network_id() != registry.network_id() {
            return Err(UnifiedAssetError::WrongNetwork);
        }
        let native_asset_id = qzxb_native_asset_id(ledger.network_id())?;
        if registry.asset(&native_asset_id).is_some() {
            return Err(UnifiedAssetError::NativeAssetReserved);
        }
        if !amm.is_asset_registered(&native_asset_id) {
            amm.register_asset(native_asset_id)?;
        }

        let existing_native_accounts = amm.accounts_with_asset_balance(&native_asset_id);
        if existing_native_accounts.is_empty() {
            // Bootstrap is allowed only from the canonical ledger. Pool custody must already
            // be represented in both views; a nonzero unmirrored pool balance is never seeded.
            for (account, state) in ledger.account_entries() {
                if state.balance == 0 {
                    continue;
                }
                if amm.is_pool_account_id(&account) {
                    return Err(UnifiedAssetError::PoolCustodyMismatch {
                        account,
                        ledger: state.balance,
                        amm: 0,
                    });
                }
                amm.reconcile_external_balance(native_asset_id, account, state.balance as u128)?;
            }
        }

        let candidate = Self {
            ledger,
            amm,
            registry,
            native_asset_id,
        };
        candidate.verify_invariants()?;
        Ok(candidate)
    }

    pub fn network_id(&self) -> [u8; 32] {
        self.ledger.network_id()
    }
    pub(crate) fn block_height(&self) -> u64 {
        self.ledger.height()
    }
    pub(crate) fn last_block_timestamp(&self) -> u64 {
        self.ledger.last_timestamp()
    }
    pub(crate) fn tip_hash(&self) -> [u8; 32] {
        self.ledger.tip_hash()
    }
    pub fn native_asset_id(&self) -> [u8; 32] {
        self.native_asset_id
    }
    pub fn ledger(&self) -> &LedgerState {
        &self.ledger
    }
    pub fn amm(&self) -> &QzxbAmmStateCandidate {
        &self.amm
    }
    pub fn registry(&self) -> &QRunV06AssetRegistryCandidate {
        &self.registry
    }

    pub(crate) fn is_asset_registered(&self, asset: &AssetId) -> bool {
        *asset == self.native_asset_id || self.registry.asset(asset).is_some()
    }

    pub(crate) fn ensure_asset_transfer_enabled(
        &self,
        asset: &AssetId,
    ) -> Result<(), UnifiedAssetError> {
        self.require_market_asset(asset, true)
    }

    /// Verify that every LOB sub-ledger unit is backed by the single deterministic AMM
    /// vault for that asset. User free balances and order escrow are not double-counted:
    /// their aggregate equals the one vault balance in the canonical asset ledger.
    pub(crate) fn verify_orderbook_vaults(
        &self,
        orderbook: &crate::qrun_v06_orderbook_candidate::OrderBook,
    ) -> Result<(), UnifiedAssetError> {
        if orderbook.network_id() != self.network_id() {
            return Err(UnifiedAssetError::WrongNetwork);
        }
        let lob_assets: BTreeSet<AssetId> = orderbook.registered_asset_ids().into_iter().collect();
        let mut all_assets: BTreeSet<AssetId> =
            self.registry.registered_asset_ids().into_iter().collect();
        all_assets.insert(self.native_asset_id);
        for asset in all_assets {
            let vault = orderbook_vault_account(self.network_id(), asset);
            if self.amm.is_pool_account_id(&vault) {
                return Err(UnifiedAssetError::OrderBookVaultCollision(asset));
            }
            let expected_backing = if lob_assets.contains(&asset) {
                orderbook.total_asset_balance(asset)?
            } else {
                0
            };
            let actual_vault_balance = self.amm.balance_of(&asset, &vault);
            if expected_backing != actual_vault_balance {
                return Err(UnifiedAssetError::OrderBookVaultMismatch {
                    asset_id: asset,
                    expected_backing,
                    actual_vault_balance,
                });
            }
        }
        Ok(())
    }

    /// Verify a user-signed OrderBook operation, consume the shared account nonce and
    /// optionally move canonical asset backing between the sender and the LOB vault.
    /// The caller stages the matching OrderBook sub-ledger operation on the same block clone.
    pub(crate) fn apply_signed_orderbook_transition<A: TransactionAuthenticator>(
        &mut self,
        signed: &QRunV06SignedOrderBookOperation,
        inclusion_timestamp: u64,
        transfer: Option<(AssetId, AccountId, AccountId, u128)>,
        authenticator: &A,
    ) -> Result<(), UnifiedAssetError> {
        self.verify_invariants()?;
        if signed.network_id != self.network_id() {
            return Err(UnifiedAssetError::WrongNetwork);
        }
        let mut protected_assets: BTreeSet<AssetId> =
            self.registry.registered_asset_ids().into_iter().collect();
        protected_assets.insert(self.native_asset_id);
        if protected_assets
            .iter()
            .any(|asset| orderbook_vault_account(self.network_id(), *asset) == signed.sender)
        {
            return Err(UnifiedAssetError::InvalidOrderBookTransfer);
        }
        if inclusion_timestamp == 0 || signed.expires_at <= inclusion_timestamp {
            return Err(UnifiedAssetError::InvalidOrderBookTransfer);
        }
        let digest = signed
            .signing_digest()
            .map_err(UnifiedAssetError::OrderBook)?;
        authenticator
            .verify(&signed.sender, &digest, &signed.signature)
            .map_err(|_| UnifiedAssetError::InvalidOrderBookTransfer)?;

        let current_nonce = self
            .ledger
            .account(&signed.sender)
            .map_or(0, |account| account.nonce);
        let expected_nonce =
            current_nonce
                .checked_add(1)
                .ok_or(UnifiedAssetError::InvalidMarketNonce {
                    expected: current_nonce,
                    actual: signed.nonce,
                })?;
        if signed.nonce != expected_nonce
            || self.amm.operation_nonce(&signed.sender) >= signed.nonce
        {
            return Err(UnifiedAssetError::InvalidMarketNonce {
                expected: expected_nonce,
                actual: signed.nonce,
            });
        }

        let mut next = self.clone();
        if let Some((asset, from, to, amount)) = transfer {
            next.require_market_asset(&asset, true)?;
            let vault = orderbook_vault_account(next.network_id(), asset);
            if next.amm.is_pool_account_id(&vault)
                || amount == 0
                || !((from == signed.sender && to == vault)
                    || (from == vault && to == signed.sender))
            {
                return Err(UnifiedAssetError::InvalidOrderBookTransfer);
            }
            next.amm
                .transfer_balance_for_orderbook(asset, from, to, amount)?;
        }
        next.amm
            .advance_orderbook_operation_nonce(signed.sender, signed.nonce)?;

        let mut accounts = BTreeSet::new();
        for (account, _) in next.ledger.account_entries() {
            accounts.insert(account);
        }
        for account in next.amm.accounts_with_asset_balance(&next.native_asset_id) {
            accounts.insert(account);
        }
        if let Some((_, from, to, _)) = transfer {
            accounts.insert(from);
            accounts.insert(to);
        }
        accounts.insert(signed.sender);
        let mut updates = Vec::with_capacity(accounts.len());
        for account in accounts {
            let balance = next.amm.balance_of(&next.native_asset_id, &account);
            let balance = u64::try_from(balance)
                .map_err(|_| UnifiedAssetError::NativeBalanceOutOfRange { account, balance })?;
            updates.push((account, balance));
        }
        next.ledger
            .apply_amm_account_updates(signed.sender, signed.nonce, &updates)?;
        next.verify_invariants()?;
        *self = next;
        Ok(())
    }

    /// Register a non-native asset and issue its declared initial supply in one staged
    /// transition. The issuer signature binds the initial recipient and every policy field.
    pub fn register_signed_asset<A: TransactionAuthenticator>(
        &mut self,
        registration: &AssetRegistration,
        inclusion_timestamp: u64,
        authenticator: &A,
    ) -> Result<AssetId, UnifiedAssetError> {
        let mut next = self.clone();
        let metadata = next
            .registry
            .register(registration, inclusion_timestamp, authenticator)?;
        if metadata.asset_id == next.native_asset_id {
            return Err(UnifiedAssetError::NativeAssetReserved);
        }
        let mut protected_assets: BTreeSet<AssetId> =
            next.registry.registered_asset_ids().into_iter().collect();
        protected_assets.insert(next.native_asset_id);
        if protected_assets.iter().any(|asset| {
            orderbook_vault_account(next.network_id(), *asset) == registration.initial_recipient
        }) {
            return Err(UnifiedAssetError::InvalidOrderBookTransfer);
        }
        next.amm.register_asset(metadata.asset_id)?;
        if metadata.initial_supply > 0 {
            next.amm.credit_issued_balance(
                metadata.asset_id,
                registration.initial_recipient,
                metadata.initial_supply,
            )?;
        }
        next.verify_invariants()?;
        let asset_id = metadata.asset_id;
        *self = next;
        Ok(asset_id)
    }

    /// Apply an issuer-signed mint or transfer-freeze action and project any issuance
    /// into AMM balances atomically with the registry supply counter.
    pub fn apply_signed_asset_admin_operation<A: TransactionAuthenticator>(
        &mut self,
        operation: &SignedAssetAdminOperation,
        inclusion_timestamp: u64,
        authenticator: &A,
    ) -> Result<(), UnifiedAssetError> {
        let mut next = self.clone();
        let effect =
            next.registry
                .apply_admin_operation(operation, inclusion_timestamp, authenticator)?;
        if let Some((asset_id, recipient, amount)) = effect.minted {
            if asset_id == next.native_asset_id {
                return Err(UnifiedAssetError::NativeAssetReserved);
            }
            let mut protected_assets: BTreeSet<AssetId> =
                next.registry.registered_asset_ids().into_iter().collect();
            protected_assets.insert(next.native_asset_id);
            if protected_assets
                .iter()
                .any(|asset| orderbook_vault_account(next.network_id(), *asset) == recipient)
            {
                return Err(UnifiedAssetError::InvalidOrderBookTransfer);
            }
            next.amm
                .credit_issued_balance(asset_id, recipient, amount)?;
        }
        next.verify_invariants()?;
        *self = next;
        Ok(())
    }

    /// Apply one native TXN2 transfer within a QFP6 candidate and refresh the AMM
    /// projection atomically. Fee accumulation remains in LedgerState until block settlement.
    pub(crate) fn apply_signed_native_transaction<A: TransactionAuthenticator>(
        &mut self,
        transaction: &crate::state_machine::Transaction,
        inclusion_timestamp: u64,
        authenticator: &A,
    ) -> Result<[u8; 32], UnifiedAssetError> {
        let mut protected_assets: BTreeSet<AssetId> =
            self.registry.registered_asset_ids().into_iter().collect();
        protected_assets.insert(self.native_asset_id);
        if protected_assets.iter().any(|asset| {
            let vault = orderbook_vault_account(self.network_id(), *asset);
            transaction.sender == vault || transaction.recipient == vault
        }) {
            return Err(UnifiedAssetError::InvalidOrderBookTransfer);
        }
        let mut next = self.clone();
        let txid = next.ledger.apply_v06_signed_transaction(
            transaction,
            inclusion_timestamp,
            authenticator,
        )?;
        next.refresh_native_balance_mirror()?;
        next.verify_invariants()?;
        *self = next;
        Ok(txid)
    }

    pub(crate) fn fee_pool(&self) -> u64 {
        self.ledger.fee_pool()
    }

    /// Apply a deterministic QFP6 mining reward to Ledger and refresh its AMM projection
    /// atomically. The caller must update the matching CP-0528 issuance counter in the
    /// same cloned QFB6 execution state before the post-state root is accepted.
    pub(crate) fn apply_v06_mining_reward(
        &mut self,
        producer: AccountId,
        reward_atoms: u128,
    ) -> Result<(), UnifiedAssetError> {
        if self.amm.is_pool_account_id(&producer)
            || self
                .registry
                .registered_asset_ids()
                .iter()
                .any(|asset| orderbook_vault_account(self.network_id(), *asset) == producer)
            || orderbook_vault_account(self.network_id(), self.native_asset_id) == producer
        {
            return Err(UnifiedAssetError::InvalidOrderBookTransfer);
        }
        let mut next = self.clone();
        next.ledger
            .credit_v06_mining_reward(&producer, reward_atoms)?;
        next.refresh_native_balance_mirror()?;
        next.verify_invariants()?;
        *self = next;
        Ok(())
    }

    /// Apply a verified CP-0528 category issuance to Ledger and refresh the AMM projection.
    /// The caller stages the matching Q6TM bucket counter in the same QFB6 clone.
    pub(crate) fn apply_v06_category_release(
        &mut self,
        recipient: AccountId,
        amount_atoms: u128,
    ) -> Result<(), UnifiedAssetError> {
        if self.amm.is_pool_account_id(&recipient)
            || self
                .registry
                .registered_asset_ids()
                .iter()
                .any(|asset| orderbook_vault_account(self.network_id(), *asset) == recipient)
            || orderbook_vault_account(self.network_id(), self.native_asset_id) == recipient
        {
            return Err(UnifiedAssetError::InvalidOrderBookTransfer);
        }
        let mut next = self.clone();
        next.ledger
            .credit_v06_protocol_issuance(&recipient, amount_atoms)?;
        next.refresh_native_balance_mirror()?;
        next.verify_invariants()?;
        *self = next;
        Ok(())
    }

    /// Atomically credit then debit the network/policy-derived sink for a reserve retirement.
    /// No spendable balance remains after this staged transition.
    pub(crate) fn apply_v06_protocol_burn_reserve_retirement(
        &mut self,
        burn_sink: AccountId,
        amount_atoms: u128,
    ) -> Result<(), UnifiedAssetError> {
        if burn_sink == [0; 32]
            || amount_atoms == 0
            || self.ledger.account(&burn_sink).is_some()
            || self.amm.is_pool_account_id(&burn_sink)
            || self
                .registry
                .registered_asset_ids()
                .iter()
                .any(|asset| orderbook_vault_account(self.network_id(), *asset) == burn_sink)
            || orderbook_vault_account(self.network_id(), self.native_asset_id) == burn_sink
        {
            return Err(UnifiedAssetError::InvalidOrderBookTransfer);
        }
        let mut next = self.clone();
        let before = next.ledger.total_value()?;
        next.ledger
            .credit_v06_protocol_issuance(&burn_sink, amount_atoms)?;
        next.ledger
            .burn_v06_protocol_issuance(&burn_sink, amount_atoms)?;
        next.refresh_native_balance_mirror()?;
        next.verify_invariants()?;
        if next.ledger.total_value()? != before {
            return Err(UnifiedAssetError::Ledger(StateError::InvariantViolation));
        }
        *self = next;
        Ok(())
    }

    /// Deterministically pay this block's native transfer fees to its committed producer.
    pub(crate) fn settle_v06_block_fees(
        &mut self,
        producer: AccountId,
    ) -> Result<u64, UnifiedAssetError> {
        let mut protected_assets: BTreeSet<AssetId> =
            self.registry.registered_asset_ids().into_iter().collect();
        protected_assets.insert(self.native_asset_id);
        if protected_assets
            .iter()
            .any(|asset| orderbook_vault_account(self.network_id(), *asset) == producer)
        {
            return Err(UnifiedAssetError::InvalidOrderBookTransfer);
        }
        let mut next = self.clone();
        let fees = next.ledger.settle_v06_block_fees(producer)?;
        next.refresh_native_balance_mirror()?;
        next.verify_invariants()?;
        *self = next;
        Ok(fees)
    }

    pub(crate) fn advance_v06_block_header(
        &mut self,
        height: u64,
        timestamp: u64,
        expected_parent: &[u8; 32],
    ) -> Result<(), UnifiedAssetError> {
        let mut next = self.clone();
        next.ledger
            .advance_v06_block_header(height, timestamp, expected_parent)?;
        next.verify_invariants()?;
        *self = next;
        Ok(())
    }

    pub(crate) fn commit_v06_block_id(
        &mut self,
        expected_parent: &[u8; 32],
        block_id: [u8; 32],
    ) -> Result<(), UnifiedAssetError> {
        self.ledger.commit_v06_block_id(expected_parent, block_id)?;
        self.verify_invariants()
    }

    /// Commit a complete native-ledger balance transition after the caller has already
    /// verified the canonical transfer signature and transaction semantics. This method
    /// atomically updates the ledger and refreshes the AMM's native projection. Pool-custody
    /// balances are not user-transferable and must remain equal to the AMM's reserve record.
    pub fn apply_verified_native_account_updates(
        &mut self,
        sender: AccountId,
        sender_nonce: u64,
        balances: &[(AccountId, u64)],
    ) -> Result<(), UnifiedAssetError> {
        let mut next = self.clone();
        next.ledger
            .apply_amm_account_updates(sender, sender_nonce, balances)?;
        next.refresh_native_balance_mirror()?;
        next.verify_invariants()?;
        *self = next;
        Ok(())
    }

    /// Explicitly refresh the AMM's native-balance projection after ordinary canonical
    /// native transfers have been applied to LedgerState outside the market-operation path.
    /// Pool-custody balances cannot be refreshed from user accounts: they must already match.
    pub fn refresh_native_balance_mirror(&mut self) -> Result<(), UnifiedAssetError> {
        let mut next_amm = self.amm.clone();
        let mut accounts = BTreeSet::new();
        for (account, _) in self.ledger.account_entries() {
            accounts.insert(account);
        }
        for account in next_amm.accounts_with_asset_balance(&self.native_asset_id) {
            accounts.insert(account);
        }

        for account in accounts {
            let ledger_balance = self
                .ledger
                .account(&account)
                .map_or(0, |state| state.balance);
            let amm_balance = next_amm.balance_of(&self.native_asset_id, &account);
            let mut protected_assets: BTreeSet<AssetId> =
                self.registry.registered_asset_ids().into_iter().collect();
            protected_assets.insert(self.native_asset_id);
            let is_orderbook_vault = protected_assets
                .iter()
                .any(|asset| orderbook_vault_account(self.network_id(), *asset) == account);
            if next_amm.is_pool_account_id(&account) {
                if ledger_balance as u128 != amm_balance {
                    return Err(UnifiedAssetError::PoolCustodyMismatch {
                        account,
                        ledger: ledger_balance,
                        amm: amm_balance,
                    });
                }
            } else if is_orderbook_vault {
                if ledger_balance as u128 != amm_balance {
                    return Err(UnifiedAssetError::InvalidOrderBookTransfer);
                }
            } else {
                next_amm.reconcile_external_balance(
                    self.native_asset_id,
                    account,
                    ledger_balance as u128,
                )?;
            }
        }

        next_amm.verify_invariants()?;
        let mut candidate = self.clone();
        candidate.amm = next_amm;
        candidate.verify_invariants()?;
        self.amm = candidate.amm;
        Ok(())
    }

    /// Apply one authenticated AMM operation against the next native-ledger nonce.
    /// The authenticator is the exact same verifier used for native transaction signatures.
    /// Any failure—including an AMM error, u64 conversion, account update or mirror mismatch—
    /// leaves both the native ledger and AMM state unchanged.
    pub fn apply_signed_market_operation<A: TransactionAuthenticator>(
        &mut self,
        signed: &AmmSignedOperation,
        inclusion_timestamp: u64,
        authenticator: &A,
    ) -> Result<Option<SwapReceipt>, UnifiedAssetError> {
        self.verify_invariants()?;
        if signed.network_id != self.network_id() {
            return Err(UnifiedAssetError::WrongNetwork);
        }
        let mut vault_assets: BTreeSet<AssetId> =
            self.registry.registered_asset_ids().into_iter().collect();
        vault_assets.insert(self.native_asset_id);
        if vault_assets
            .iter()
            .any(|asset| orderbook_vault_account(self.network_id(), *asset) == signed.sender)
        {
            return Err(UnifiedAssetError::InvalidOrderBookTransfer);
        }
        if let AmmOperation::TransferAsset { recipient, .. } = &signed.operation {
            if vault_assets
                .iter()
                .any(|asset| orderbook_vault_account(self.network_id(), *asset) == *recipient)
            {
                return Err(UnifiedAssetError::InvalidOrderBookTransfer);
            }
        }
        self.validate_market_operation_assets(&signed.operation)?;

        let current = self
            .ledger
            .account(&signed.sender)
            .map_or(0, |state| state.nonce);
        let expected = current
            .checked_add(1)
            .ok_or(UnifiedAssetError::InvalidMarketNonce {
                expected: current,
                actual: signed.nonce,
            })?;
        if signed.nonce != expected {
            return Err(UnifiedAssetError::InvalidMarketNonce {
                expected,
                actual: signed.nonce,
            });
        }

        let mut next = self.clone();
        let receipt = next.amm.apply_signed_operation_with_expected_nonce(
            signed,
            inclusion_timestamp,
            expected,
            authenticator,
        )?;

        let mut accounts = BTreeSet::new();
        for (account, _) in next.ledger.account_entries() {
            accounts.insert(account);
        }
        for account in next.amm.accounts_with_asset_balance(&next.native_asset_id) {
            accounts.insert(account);
        }
        accounts.insert(signed.sender);

        let mut updates = Vec::with_capacity(accounts.len());
        for account in accounts {
            let balance = next.amm.balance_of(&next.native_asset_id, &account);
            let balance = u64::try_from(balance)
                .map_err(|_| UnifiedAssetError::NativeBalanceOutOfRange { account, balance })?;
            updates.push((account, balance));
        }

        // This updates the sender nonce and all native balances in one checked ledger clone.
        // LedgerState verifies exact native-supply conservation before accepting the batch.
        next.ledger
            .apply_amm_account_updates(signed.sender, signed.nonce, &updates)?;
        next.verify_invariants()?;
        *self = next;
        Ok(receipt)
    }

    fn require_market_asset(
        &self,
        asset_id: &AssetId,
        movement: bool,
    ) -> Result<(), UnifiedAssetError> {
        if *asset_id == self.native_asset_id {
            return Ok(());
        }
        let metadata = self
            .registry
            .asset(asset_id)
            .ok_or(UnifiedAssetError::AssetNotRegistered(*asset_id))?;
        if movement && !metadata.transfers_enabled {
            return Err(UnifiedAssetError::AssetTransfersDisabled(*asset_id));
        }
        Ok(())
    }

    fn validate_market_operation_assets(
        &self,
        operation: &AmmOperation,
    ) -> Result<(), UnifiedAssetError> {
        match operation {
            AmmOperation::RegisterAsset { .. } => {
                Err(UnifiedAssetError::UnmanagedAssetRegistration)
            }
            AmmOperation::MintTestQuote { .. } => {
                Err(UnifiedAssetError::TestQuoteMintNotAvailableInUnifiedState)
            }
            AmmOperation::CreatePair { token_a, token_b } => {
                self.require_market_asset(token_a, false)?;
                self.require_market_asset(token_b, false)
            }
            AmmOperation::TransferAsset { asset_id, .. } => {
                self.require_market_asset(asset_id, true)
            }
            AmmOperation::AddLiquidity { pair_id, .. }
            | AmmOperation::RemoveLiquidity { pair_id, .. } => {
                let (asset0, asset1) = self.amm.pair_assets(pair_id)?;
                self.require_market_asset(&asset0, true)?;
                self.require_market_asset(&asset1, true)
            }
            AmmOperation::SwapExactIn {
                token_in,
                token_out,
                ..
            } => {
                self.require_market_asset(token_in, true)?;
                self.require_market_asset(token_out, true)
            }
        }
    }

    pub fn verify_invariants(&self) -> Result<(), UnifiedAssetError> {
        if self.ledger.network_id() != self.amm.network_id()
            || qzxb_native_asset_id(self.ledger.network_id())? != self.native_asset_id
            || !self.amm.is_asset_registered(&self.native_asset_id)
        {
            return Err(UnifiedAssetError::WrongNetwork);
        }
        self.ledger.total_value()?;
        self.amm.verify_invariants()?;
        self.registry.verify_invariants()?;
        self.verify_native_balance_mirror()?;

        let mut expected_assets: BTreeSet<AssetId> =
            self.registry.registered_asset_ids().into_iter().collect();
        expected_assets.insert(self.native_asset_id);
        let actual_assets: BTreeSet<AssetId> =
            self.amm.registered_asset_ids().into_iter().collect();
        if actual_assets != expected_assets {
            return Err(UnifiedAssetError::UnmanagedAssetRegistration);
        }
        for asset_id in self.registry.registered_asset_ids() {
            let registry_supply = self.registry.current_supply(&asset_id)?;
            let amm_supply = self.amm.total_balance_for_asset(&asset_id)?;
            if registry_supply != amm_supply {
                return Err(UnifiedAssetError::AssetSupplyMismatch {
                    asset_id,
                    registry_supply,
                    amm_supply,
                });
            }
        }

        for (account, amm_nonce) in self.amm.operation_nonce_entries() {
            let ledger_nonce = self.ledger.account(&account).map_or(0, |state| state.nonce);
            if amm_nonce > ledger_nonce {
                return Err(UnifiedAssetError::AmmNonceAheadOfLedger {
                    account,
                    amm_nonce,
                    ledger_nonce,
                });
            }
        }
        Ok(())
    }

    fn verify_native_balance_mirror(&self) -> Result<(), UnifiedAssetError> {
        let mut accounts = BTreeSet::new();
        for (account, _) in self.ledger.account_entries() {
            accounts.insert(account);
        }
        for account in self.amm.accounts_with_asset_balance(&self.native_asset_id) {
            accounts.insert(account);
        }

        for account in accounts {
            let ledger_balance = self
                .ledger
                .account(&account)
                .map_or(0, |state| state.balance);
            let amm_balance = self.amm.balance_of(&self.native_asset_id, &account);
            if ledger_balance as u128 != amm_balance {
                if self.amm.is_pool_account_id(&account) {
                    return Err(UnifiedAssetError::PoolCustodyMismatch {
                        account,
                        ledger: ledger_balance,
                        amm: amm_balance,
                    });
                }
                return Err(UnifiedAssetError::NativeBalanceMirrorMismatch {
                    account,
                    ledger: ledger_balance,
                    amm: amm_balance,
                });
            }
        }
        Ok(())
    }

    /// Combined candidate commitment. A future QFP6 block must commit to this value.
    /// QFP5/QFB5 encoding and state roots are deliberately not changed here.
    pub fn state_root(&self) -> Result<[u8; 32], UnifiedAssetError> {
        self.verify_invariants()?;
        let ledger_root = self.ledger.state_root();
        let amm_root = self.amm.state_root()?;
        let registry_root = self.registry.state_root()?;
        let mut hash = Sha256::new();
        hash.update(UNIFIED_STATE_ROOT_DOMAIN);
        hash.update(self.network_id());
        hash.update(ledger_root);
        hash.update(amm_root);
        hash.update(registry_root);
        Ok(hash.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qzxb_amm_candidate::{AmmAssetId, AmmOperation};
    const NETWORK: [u8; 32] = [0xA6; 32];
    const OWNER: AccountId = [0xA1; 32];
    const RECIPIENT: AccountId = [0xA2; 32];

    fn quote_registration() -> AssetRegistration {
        let mut registration = AssetRegistration {
            network_id: NETWORK,
            issuer: OWNER,
            issuer_nonce: 1,
            salt: [0xA3; 32],
            name: "QRun Test Quote".to_string(),
            symbol: "QTQ".to_string(),
            decimals: 6,
            supply_policy: crate::qrun_v06_asset_registry_candidate::AssetSupplyPolicy::Fixed {
                total_supply: 20_000,
            },
            initial_supply: 20_000,
            initial_recipient: OWNER,
            trust_policy: crate::qrun_v06_asset_registry_candidate::AssetTrustPolicy::Unverified,
            expires_at: 10_000,
            signature: Vec::new(),
        };
        registration.signature = registration.signing_digest().unwrap().to_vec();
        registration
    }

    fn quote_asset() -> AmmAssetId {
        quote_registration().asset_id()
    }

    fn utility_registration(
        nonce: u64,
        initial_supply: u128,
        max_supply: u128,
    ) -> AssetRegistration {
        let mut registration = AssetRegistration {
            network_id: NETWORK,
            issuer: OWNER,
            issuer_nonce: nonce,
            salt: [0xB4u8.wrapping_add(nonce as u8); 32],
            name: "QRun Utility Asset".to_string(),
            symbol: "QUA".to_string(),
            decimals: 8,
            supply_policy:
                crate::qrun_v06_asset_registry_candidate::AssetSupplyPolicy::IssuerCapped {
                    max_supply,
                },
            initial_supply,
            initial_recipient: RECIPIENT,
            trust_policy: crate::qrun_v06_asset_registry_candidate::AssetTrustPolicy::Unverified,
            expires_at: 10_000,
            signature: Vec::new(),
        };
        registration.signature = registration.signing_digest().unwrap().to_vec();
        registration
    }

    fn signed_asset_admin(
        nonce: u64,
        action: crate::qrun_v06_asset_registry_candidate::AssetAdminAction,
    ) -> SignedAssetAdminOperation {
        let mut operation = SignedAssetAdminOperation {
            network_id: NETWORK,
            issuer: OWNER,
            issuer_nonce: nonce,
            expires_at: 10_000,
            action,
            signature: Vec::new(),
        };
        operation.signature = operation.signing_digest().unwrap().to_vec();
        operation
    }

    fn empty_unified() -> QRunV06UnifiedAssetState {
        let ledger =
            LedgerState::genesis(NETWORK, vec![(OWNER, 10_000), (RECIPIENT, 2_000)]).unwrap();
        let amm = QzxbAmmStateCandidate::new(NETWORK, 16, 32, 256).unwrap();
        QRunV06UnifiedAssetState::new(ledger, amm).unwrap()
    }

    struct DigestAuthenticator;
    impl TransactionAuthenticator for DigestAuthenticator {
        fn verify(
            &self,
            sender: &AccountId,
            digest: &[u8; 32],
            signature: &[u8],
        ) -> Result<(), ()> {
            if sender.iter().any(|byte| *byte != 0) && signature == digest {
                Ok(())
            } else {
                Err(())
            }
        }
    }

    fn signed(nonce: u64, operation: AmmOperation) -> AmmSignedOperation {
        let mut operation = AmmSignedOperation {
            network_id: NETWORK,
            sender: OWNER,
            nonce,
            expires_at: 10_000,
            operation,
            signature: vec![0; 32],
        };
        operation.signature = operation.signing_digest().unwrap().to_vec();
        operation
    }

    fn fixture() -> (QRunV06UnifiedAssetState, [u8; 32], [u8; 32]) {
        let native = qzxb_native_asset_id(NETWORK).unwrap();
        let ledger =
            LedgerState::genesis(NETWORK, vec![(OWNER, 10_000), (RECIPIENT, 2_000)]).unwrap();
        let mut amm = QzxbAmmStateCandidate::new(NETWORK, 16, 32, 256).unwrap();
        amm.register_asset(native).unwrap();
        let quote_registration = quote_registration();
        let quote = quote_registration.asset_id();
        let mut registry = QRunV06AssetRegistryCandidate::new(NETWORK, 16).unwrap();
        let quote_metadata = registry
            .register(&quote_registration, 100, &DigestAuthenticator)
            .unwrap();
        assert_eq!(quote_metadata.asset_id, quote);
        amm.register_asset(quote).unwrap();
        amm.credit_issued_balance(quote, OWNER, quote_metadata.initial_supply)
            .unwrap();
        let pair = amm.create_pair(native, quote).unwrap();
        let unified = QRunV06UnifiedAssetState::new_with_registry(ledger, amm, registry).unwrap();
        (unified, native, pair)
    }

    #[test]
    fn bootstrap_uses_ledger_as_native_source_of_truth() {
        let (state, native, _) = fixture();
        assert_eq!(state.amm().balance_of(&native, &OWNER), 10_000);
        assert_eq!(state.amm().balance_of(&native, &RECIPIENT), 2_000);
        assert_eq!(state.ledger().account(&OWNER).unwrap().balance, 10_000);
        assert_eq!(state.ledger().total_value().unwrap(), 12_000);
        state.verify_invariants().unwrap();
    }

    #[test]
    fn add_liquidity_updates_native_ledger_and_pool_custody_atomically() {
        let (mut state, native, pair) = fixture();
        let before_total = state.ledger().total_value().unwrap();
        let (token0, token1) = state.amm().pair_assets(&pair).unwrap();
        assert!(token0 == native || token1 == native);
        let result = state
            .apply_signed_market_operation(
                &signed(
                    1,
                    AmmOperation::AddLiquidity {
                        pair_id: pair,
                        amount0_desired: 1_000,
                        amount1_desired: 1_000,
                        min_lp_shares: 1,
                    },
                ),
                100,
                &DigestAuthenticator,
            )
            .unwrap();
        assert!(result.is_none());
        assert_eq!(state.ledger().account(&OWNER).unwrap().nonce, 1);
        assert_eq!(state.amm().operation_nonce(&OWNER), 1);
        assert_eq!(state.ledger().account(&OWNER).unwrap().balance, 9_000);
        assert_eq!(state.ledger().account(&pair).unwrap().balance, 1_000);
        assert_eq!(state.ledger().total_value().unwrap(), before_total);
        assert_eq!(state.amm().balance_of(&native, &OWNER), 9_000);
        assert_eq!(state.amm().balance_of(&native, &pair), 1_000);
        state.verify_invariants().unwrap();
    }

    #[test]
    fn native_swap_updates_both_views_and_preserves_supply() {
        let (mut state, native, pair) = fixture();
        let before_total = state.ledger().total_value().unwrap();
        state
            .apply_signed_market_operation(
                &signed(
                    1,
                    AmmOperation::AddLiquidity {
                        pair_id: pair,
                        amount0_desired: 1_000,
                        amount1_desired: 1_000,
                        min_lp_shares: 1,
                    },
                ),
                100,
                &DigestAuthenticator,
            )
            .unwrap();
        let before = state.ledger().account(&OWNER).unwrap().balance;
        let receipt = state
            .apply_signed_market_operation(
                &signed(
                    2,
                    AmmOperation::SwapExactIn {
                        token_in: native,
                        token_out: quote_asset(),
                        amount_in: 100,
                        min_amount_out: 1,
                    },
                ),
                101,
                &DigestAuthenticator,
            )
            .unwrap()
            .unwrap();
        assert!(receipt.amount_out > 0);
        assert_eq!(
            state.ledger().account(&OWNER).unwrap().balance,
            before - 100
        );
        assert_eq!(state.ledger().account(&pair).unwrap().balance, 1_000 + 100);
        assert_eq!(state.ledger().account(&OWNER).unwrap().nonce, 2);
        assert_eq!(state.ledger().total_value().unwrap(), before_total);
        assert_eq!(
            state.amm().balance_of(&native, &OWNER),
            state.ledger().account(&OWNER).unwrap().balance as u128
        );
        state.verify_invariants().unwrap();
    }

    #[test]
    fn rejected_market_operation_leaves_ledger_amm_and_combined_root_unchanged() {
        let (mut state, native, pair) = fixture();
        state
            .apply_signed_market_operation(
                &signed(
                    1,
                    AmmOperation::AddLiquidity {
                        pair_id: pair,
                        amount0_desired: 1_000,
                        amount1_desired: 1_000,
                        min_lp_shares: 1,
                    },
                ),
                100,
                &DigestAuthenticator,
            )
            .unwrap();
        let before = state.state_root().unwrap();
        let result = state.apply_signed_market_operation(
            &signed(
                2,
                AmmOperation::SwapExactIn {
                    token_in: native,
                    token_out: quote_asset(),
                    amount_in: 100,
                    min_amount_out: u128::MAX,
                },
            ),
            101,
            &DigestAuthenticator,
        );
        assert_eq!(result, Err(UnifiedAssetError::Amm(AmmError::SlippageLimit)));
        assert_eq!(state.state_root().unwrap(), before);
        assert_eq!(state.ledger().account(&OWNER).unwrap().nonce, 1);
        state.verify_invariants().unwrap();
    }

    #[test]
    fn stale_native_projection_fails_closed_until_explicit_ledger_refresh() {
        let (mut state, _, _) = fixture();
        let current = state.ledger().account(&OWNER).unwrap();
        let mut updates = vec![
            (OWNER, current.balance - 1),
            (
                RECIPIENT,
                state.ledger().account(&RECIPIENT).unwrap().balance + 1,
            ),
        ];
        updates.sort_by_key(|(account, _)| *account);
        state
            .ledger
            .apply_amm_account_updates(OWNER, 1, &updates)
            .unwrap();
        assert!(matches!(
            state.apply_signed_market_operation(
                &signed(
                    2,
                    AmmOperation::TransferAsset {
                        asset_id: state.native_asset_id,
                        recipient: RECIPIENT,
                        amount: 1,
                    }
                ),
                101,
                &DigestAuthenticator,
            ),
            Err(UnifiedAssetError::NativeBalanceMirrorMismatch { .. })
        ));
        state.refresh_native_balance_mirror().unwrap();
        state
            .apply_signed_market_operation(
                &signed(
                    2,
                    AmmOperation::TransferAsset {
                        asset_id: state.native_asset_id,
                        recipient: RECIPIENT,
                        amount: 1,
                    },
                ),
                101,
                &DigestAuthenticator,
            )
            .unwrap();
        assert_eq!(
            state.ledger().account(&OWNER).unwrap().balance,
            current.balance - 2
        );
        assert_eq!(state.ledger().account(&RECIPIENT).unwrap().balance, 2_002);
        state.verify_invariants().unwrap();
    }

    #[test]
    fn verified_native_transfer_updates_ledger_and_amm_projection_atomically() {
        let (mut state, native, _) = fixture();
        let before_total = state.ledger().total_value().unwrap();
        state
            .apply_verified_native_account_updates(OWNER, 1, &[(OWNER, 9_990), (RECIPIENT, 2_010)])
            .unwrap();
        assert_eq!(state.ledger().account(&OWNER).unwrap().balance, 9_990);
        assert_eq!(state.ledger().account(&OWNER).unwrap().nonce, 1);
        assert_eq!(state.ledger().account(&RECIPIENT).unwrap().balance, 2_010);
        assert_eq!(state.amm().balance_of(&native, &OWNER), 9_990);
        assert_eq!(state.amm().balance_of(&native, &RECIPIENT), 2_010);
        assert_eq!(state.ledger().total_value().unwrap(), before_total);
        state.verify_invariants().unwrap();
    }

    #[test]
    fn ordinary_native_transfer_cannot_mutate_pool_custody() {
        let (mut state, _, pair) = fixture();
        state
            .apply_signed_market_operation(
                &signed(
                    1,
                    AmmOperation::AddLiquidity {
                        pair_id: pair,
                        amount0_desired: 1_000,
                        amount1_desired: 1_000,
                        min_lp_shares: 1,
                    },
                ),
                100,
                &DigestAuthenticator,
            )
            .unwrap();
        let before = state.state_root().unwrap();
        let result = state.apply_verified_native_account_updates(
            OWNER,
            2,
            &[(OWNER, 8_900), (pair, 1_100), (RECIPIENT, 2_000)],
        );
        assert!(matches!(
            result,
            Err(UnifiedAssetError::PoolCustodyMismatch { .. })
        ));
        assert_eq!(state.state_root().unwrap(), before);
        assert_eq!(state.ledger().account(&OWNER).unwrap().balance, 9_000);
        assert_eq!(state.ledger().account(&pair).unwrap().balance, 1_000);
        state.verify_invariants().unwrap();
    }

    #[test]
    fn preexisting_unbacked_native_amm_balance_is_rejected() {
        let native = qzxb_native_asset_id(NETWORK).unwrap();
        let ledger = LedgerState::genesis(NETWORK, vec![(OWNER, 10_000)]).unwrap();
        let mut amm = QzxbAmmStateCandidate::new(NETWORK, 8, 8, 64).unwrap();
        amm.register_asset(native).unwrap();
        amm.credit_genesis_balance(native, OWNER, 9_999).unwrap();
        assert!(matches!(
            QRunV06UnifiedAssetState::new(ledger, amm),
            Err(UnifiedAssetError::NativeBalanceMirrorMismatch { .. })
        ));
    }

    #[test]
    fn wrong_network_binding_is_rejected() {
        let native = qzxb_native_asset_id(NETWORK).unwrap();
        let ledger = LedgerState::genesis(NETWORK, vec![(OWNER, 10_000)]).unwrap();
        let mut amm = QzxbAmmStateCandidate::new([0xB6; 32], 8, 8, 64).unwrap();
        amm.register_asset(native).unwrap();
        assert_eq!(
            QRunV06UnifiedAssetState::new(ledger, amm),
            Err(UnifiedAssetError::WrongNetwork)
        );
    }

    #[test]
    fn signed_asset_registration_projects_initial_supply_atomically() {
        let mut state = empty_unified();
        let registration = utility_registration(1, 100, 500);
        let before = state.state_root().unwrap();
        let asset_id = state
            .register_signed_asset(&registration, 100, &DigestAuthenticator)
            .unwrap();
        assert_eq!(asset_id, registration.asset_id());
        assert_eq!(state.registry().current_supply(&asset_id), Ok(100));
        assert_eq!(state.amm().balance_of(&asset_id, &RECIPIENT), 100);
        assert_ne!(state.state_root().unwrap(), before);
        state.verify_invariants().unwrap();
    }

    #[test]
    fn signed_issuer_mint_updates_registry_and_amm_in_one_commit() {
        let mut state = empty_unified();
        let registration = utility_registration(1, 100, 500);
        let asset_id = state
            .register_signed_asset(&registration, 100, &DigestAuthenticator)
            .unwrap();
        let mint = signed_asset_admin(
            2,
            crate::qrun_v06_asset_registry_candidate::AssetAdminAction::Mint {
                asset_id,
                recipient: RECIPIENT,
                amount: 50,
            },
        );
        state
            .apply_signed_asset_admin_operation(&mint, 101, &DigestAuthenticator)
            .unwrap();
        assert_eq!(state.registry().current_supply(&asset_id), Ok(150));
        assert_eq!(state.amm().balance_of(&asset_id, &RECIPIENT), 150);
        state.verify_invariants().unwrap();
    }

    #[test]
    fn issuer_freeze_blocks_market_movement_and_preserves_market_nonce() {
        let mut state = empty_unified();
        let registration = utility_registration(1, 100, 500);
        let asset_id = state
            .register_signed_asset(&registration, 100, &DigestAuthenticator)
            .unwrap();
        let freeze = signed_asset_admin(
            2,
            crate::qrun_v06_asset_registry_candidate::AssetAdminAction::SetTransfersEnabled {
                asset_id,
                enabled: false,
            },
        );
        state
            .apply_signed_asset_admin_operation(&freeze, 101, &DigestAuthenticator)
            .unwrap();
        let frozen_root = state.state_root().unwrap();
        let transfer = signed(
            1,
            AmmOperation::TransferAsset {
                asset_id,
                recipient: OWNER,
                amount: 1,
            },
        );
        assert_eq!(
            state.apply_signed_market_operation(&transfer, 102, &DigestAuthenticator),
            Err(UnifiedAssetError::AssetTransfersDisabled(asset_id))
        );
        assert_eq!(state.state_root().unwrap(), frozen_root);
        assert_eq!(state.ledger().account(&OWNER).unwrap().nonce, 0);
        assert_eq!(state.registry().current_supply(&asset_id), Ok(100));
    }

    #[test]
    fn unified_state_rejects_raw_asset_registration_and_test_faucet() {
        let mut state = empty_unified();
        let before = state.state_root().unwrap();
        let raw_registration = signed(
            1,
            AmmOperation::RegisterAsset {
                asset_id: [0x55; 32],
            },
        );
        assert_eq!(
            state.apply_signed_market_operation(&raw_registration, 100, &DigestAuthenticator),
            Err(UnifiedAssetError::UnmanagedAssetRegistration)
        );
        let faucet = signed(1, AmmOperation::MintTestQuote { amount: 10 });
        assert_eq!(
            state.apply_signed_market_operation(&faucet, 100, &DigestAuthenticator),
            Err(UnifiedAssetError::TestQuoteMintNotAvailableInUnifiedState)
        );
        assert_eq!(state.state_root().unwrap(), before);
        assert_eq!(state.ledger().account(&OWNER).unwrap().nonce, 0);
    }

    #[test]
    fn constructor_rejects_non_native_amm_asset_without_metadata() {
        let native = qzxb_native_asset_id(NETWORK).unwrap();
        let ledger = LedgerState::genesis(NETWORK, vec![(OWNER, 10_000)]).unwrap();
        let mut amm = QzxbAmmStateCandidate::new(NETWORK, 8, 8, 64).unwrap();
        amm.register_asset(native).unwrap();
        amm.register_asset([0x55; 32]).unwrap();
        assert_eq!(
            QRunV06UnifiedAssetState::new(ledger, amm),
            Err(UnifiedAssetError::UnmanagedAssetRegistration)
        );
    }

    #[test]
    fn constructor_rejects_registry_supply_not_backed_by_amm_balances() {
        let native = qzxb_native_asset_id(NETWORK).unwrap();
        let ledger = LedgerState::genesis(NETWORK, vec![(OWNER, 10_000)]).unwrap();
        let registration = utility_registration(1, 100, 500);
        let asset_id = registration.asset_id();
        let mut registry = QRunV06AssetRegistryCandidate::new(NETWORK, 8).unwrap();
        registry
            .register(&registration, 100, &DigestAuthenticator)
            .unwrap();
        let mut amm = QzxbAmmStateCandidate::new(NETWORK, 8, 8, 64).unwrap();
        amm.register_asset(native).unwrap();
        amm.register_asset(asset_id).unwrap();
        amm.credit_issued_balance(asset_id, RECIPIENT, 99).unwrap();
        assert_eq!(
            QRunV06UnifiedAssetState::new_with_registry(ledger, amm, registry),
            Err(UnifiedAssetError::AssetSupplyMismatch {
                asset_id,
                registry_supply: 100,
                amm_supply: 99,
            })
        );
    }

    #[test]
    fn over_cap_issuer_mint_leaves_combined_root_and_nonce_unchanged() {
        let mut state = empty_unified();
        let registration = utility_registration(1, 100, 100);
        let asset_id = state
            .register_signed_asset(&registration, 100, &DigestAuthenticator)
            .unwrap();
        let before = state.state_root().unwrap();
        let mint = signed_asset_admin(
            2,
            crate::qrun_v06_asset_registry_candidate::AssetAdminAction::Mint {
                asset_id,
                recipient: RECIPIENT,
                amount: 1,
            },
        );
        assert_eq!(
            state.apply_signed_asset_admin_operation(&mint, 101, &DigestAuthenticator),
            Err(UnifiedAssetError::AssetRegistry(
                AssetRegistryError::SupplyCapExceeded
            ))
        );
        assert_eq!(state.state_root().unwrap(), before);
        assert_eq!(state.registry().issuer_nonce(&OWNER), 1);
        assert_eq!(state.amm().balance_of(&asset_id, &RECIPIENT), 100);
    }
}
