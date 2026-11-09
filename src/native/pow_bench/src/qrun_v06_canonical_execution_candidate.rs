//! Isolated QFP6 canonical block codec and deterministic execution candidate.
//!
//! QFP5/QFB5 encodings are untouched. QFB6 v5 commits CP-0528 issuance counters, signed category releases,
//! the Founder Genesis policy and the mining-security reward schedule in the execution root.
//! The candidate also executes native TXN2 transfers, signed AMM operations, signed asset
//! registrations and issuer-admin operations in the canonical order carried by QFB6. The root is computed
//! after per-block fee settlement and header advancement, then the tip is committed from
//! the canonical block bytes. This is not yet a production consensus or node callsite.
use crate::consensus::ConsensusParameters;
use crate::qrun_v06_asset_registry_candidate::{
    AssetAdminAction, AssetRegistration, AssetRegistryError, AssetSupplyPolicy, AssetTrustPolicy,
    QRunV06AssetRegistryCandidate, SignedAssetAdminOperation, MAX_QRUN_V06_REGISTRY_SNAPSHOT_BYTES,
};
use crate::qrun_v06_genesis_descriptor_candidate::{
    QRunV06GenesisDescriptor, QRunV06GenesisDescriptorError,
};
use crate::qrun_v06_orderbook_candidate::{
    Error as OrderBookError, OrderBook, PlaceLimit, Priority, QRunV06OrderBookOperation,
    QRunV06SignedOrderBookOperation, MAX_QRUN_V06_ORDERBOOK_SNAPSHOT_BYTES,
};
use crate::qrun_v06_profile_trust_candidate::QRunV06TrustAuthorizedQuoteAsset;
use crate::qrun_v06_tokenomics_candidate::{
    QRunV06AllocationBucket, QRunV06MiningScheduleCandidate, QRunV06SignedBurnReserveRetirement,
    QRunV06SignedCategoryRelease, QRunV06TokenomicsError, QRunV06TokenomicsState,
    QRUN_V06_FOUNDER_GENESIS_ATOMS, QRUN_V06_TOKENOMICS_SNAPSHOT_BYTES,
};
use crate::qrun_v06_unified_asset_candidate::{
    orderbook_vault_account, QRunV06UnifiedAssetState, UnifiedAssetError,
};
use crate::qzxb_amm_candidate::{
    AmmError, AmmOperation, AmmSignedOperation, QzxbAmmStateCandidate, MAX_AMM_SNAPSHOT_BYTES,
};
use crate::state_machine::{
    decode_transaction, encode_transaction, transaction_id, AccountId, LedgerState, NetworkId,
    StateError, Transaction, TransactionAuthenticator, MAX_ENCODED_SNAPSHOT_BYTES,
};
use sha2::{Digest, Sha256};
use std::io::{Cursor, Read};

pub const QRUN_V06_BLOCK_MAGIC: [u8; 4] = *b"QFB6";
pub const QRUN_V06_BLOCK_VERSION: u16 = 5;
pub const MAX_QRUN_V06_BLOCK_OPERATIONS: usize = 512;
pub const MAX_QRUN_V06_BLOCK_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_QRUN_V06_ASSET_SIGNATURE_BYTES: usize = 4 * 1024;

const BLOCK_ID_DOMAIN: &[u8] = b"QRUN-V06-CANONICAL-BLOCK-ID-V5\0";
const EXECUTION_ROOT_DOMAIN: &[u8] = b"QRUN-V06-CANONICAL-EXECUTION-ROOT-V5\0";
const EXECUTION_SNAPSHOT_MAGIC: [u8; 4] = *b"Q6SN";
const EXECUTION_SNAPSHOT_VERSION: u16 = 5;
const EXECUTION_SNAPSHOT_VERSION_LEGACY: u16 = 4;
const EXECUTION_SNAPSHOT_CHECKSUM_DOMAIN: &[u8] =
    b"QRUN-V06-CANONICAL-EXECUTION-SNAPSHOT-CHECKSUM-V1\0";
pub const MAX_QRUN_V06_EXECUTION_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;
const QUOTE_ASSET_EXECUTION_PIN_BYTES: usize = 32 * 3 + 8 * 4;
const QUOTE_ASSET_EXECUTION_PIN_DOMAIN: &[u8] = b"QRUN-V06-EXECUTION-QUOTE-ASSET-AUTH-PIN-V1\0";
const MAX_NAME_BYTES: usize = 64;
const MAX_SYMBOL_BYTES: usize = 16;
const PROTOCOL_BURN_SINK_DOMAIN: &[u8] = b"QRUN-V06-CP0566E-PROTOCOL-BURN-SINK-V1\0";

fn protocol_burn_sink_account(network_id: NetworkId, policy_fingerprint: [u8; 32]) -> AccountId {
    let mut hash = Sha256::new();
    hash.update(PROTOCOL_BURN_SINK_DOMAIN);
    hash.update(network_id);
    hash.update(policy_fingerprint);
    hash.finalize().into()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QRunV06ExecutionError {
    Malformed,
    BadMagic,
    UnsupportedVersion(u16),
    Oversize {
        actual: usize,
        limit: usize,
    },
    TooManyOperations(usize),
    InvalidNetwork,
    InvalidProfile,
    WrongNetwork,
    WrongProfile,
    InvalidHeight,
    InvalidTimestamp,
    HeightMismatch {
        expected: u64,
        actual: u64,
    },
    ParentHashMismatch,
    TimestampNotIncreasing {
        previous: u64,
        actual: u64,
    },
    FeePoolNotEmptyAtBlockStart,
    DuplicateTransaction,
    StateRootMismatch,
    InvalidSignature,
    InvalidAssetRegistration,
    InvalidAssetAdminOperation,
    InvalidCategoryRelease,
    InvalidProtocolBurn,
    ProtocolBurnSinkNotEmpty,
    OrderBook(OrderBookError),
    State(StateError),
    Amm(AmmError),
    AssetRegistry(AssetRegistryError),
    Unified(UnifiedAssetError),
    Tokenomics(QRunV06TokenomicsError),
    TokenomicsGenesisRequiresEmptyLedger,
    TokenomicsConsensusMismatch,
    GenesisDescriptor(QRunV06GenesisDescriptorError),
    MissingQuoteAssetAuthorization,
    QuoteAssetAuthorizationMismatch,
    QuoteAssetDecimalsMismatch {
        asset_id: [u8; 32],
        q6qa_decimals: u8,
        registry_decimals: u8,
    },
    QuoteAssetAuthorizationRollback,
    InvalidQuoteAssetAuthorizationPin,
    SnapshotMalformed,
    SnapshotChecksumMismatch,
    SnapshotNonCanonical,
    SnapshotOversize,
}

impl From<OrderBookError> for QRunV06ExecutionError {
    fn from(value: OrderBookError) -> Self {
        Self::OrderBook(value)
    }
}
impl From<StateError> for QRunV06ExecutionError {
    fn from(value: StateError) -> Self {
        Self::State(value)
    }
}
impl From<AmmError> for QRunV06ExecutionError {
    fn from(value: AmmError) -> Self {
        Self::Amm(value)
    }
}
impl From<AssetRegistryError> for QRunV06ExecutionError {
    fn from(value: AssetRegistryError) -> Self {
        Self::AssetRegistry(value)
    }
}
impl From<UnifiedAssetError> for QRunV06ExecutionError {
    fn from(value: UnifiedAssetError) -> Self {
        Self::Unified(value)
    }
}
impl From<QRunV06TokenomicsError> for QRunV06ExecutionError {
    fn from(value: QRunV06TokenomicsError) -> Self {
        Self::Tokenomics(value)
    }
}
impl From<QRunV06GenesisDescriptorError> for QRunV06ExecutionError {
    fn from(value: QRunV06GenesisDescriptorError) -> Self {
        Self::GenesisDescriptor(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QRunV06BlockOperation {
    NativeTransfer(Transaction),
    Amm(AmmSignedOperation),
    AssetRegistration(AssetRegistration),
    AssetAdmin(SignedAssetAdminOperation),
    OrderBook(QRunV06SignedOrderBookOperation),
    CategoryRelease(QRunV06SignedCategoryRelease),
    ProtocolBurnReserveRetirement(QRunV06SignedBurnReserveRetirement),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06Block {
    pub network_id: NetworkId,
    pub profile_id: [u8; 32],
    pub height: u64,
    pub timestamp: u64,
    pub parent_hash: [u8; 32],
    pub state_root: [u8; 32],
    pub producer: [u8; 32],
    pub operations: Vec<QRunV06BlockOperation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06BlockApplySummary {
    pub height: u64,
    pub block_id: [u8; 32],
    pub state_root: [u8; 32],
    pub mining_reward_atoms: u128,
    pub operations_applied: usize,
    pub native_transfers: usize,
    pub amm_operations: usize,
    pub asset_registrations: usize,
    pub asset_admin_operations: usize,
    pub orderbook_operations: usize,
    pub category_releases: usize,
    pub protocol_burns: usize,
    pub orders_expired: usize,
    pub fees_paid_to_producer: u64,
}

/// Canonical, snapshot-persisted identity of the one externally qualified quote asset
/// selected by the current Q6PN v2/Q6TS profile. It contains no trust keys or local paths;
/// each block that uses QFB6 execution must still present a freshly authorized quote object.
#[derive(Debug, Clone, PartialEq, Eq)]
struct QRunV06PersistedQuoteAssetAuthorization {
    asset_id: [u8; 32],
    q6qa_bundle_commitment: [u8; 32],
    q6pn_profile_pin_commitment: [u8; 32],
    qualification_epoch: u64,
    valid_from_height: u64,
    valid_until_height: u64,
    profile_trust_epoch: u64,
}

impl QRunV06PersistedQuoteAssetAuthorization {
    fn from_authorized(authorized: &QRunV06TrustAuthorizedQuoteAsset) -> Self {
        let qualification = authorized.qualification();
        Self {
            asset_id: qualification.asset_id(),
            q6qa_bundle_commitment: qualification.commitment(),
            q6pn_profile_pin_commitment: authorized.profile_pin_commitment(),
            qualification_epoch: qualification.qualification_epoch(),
            valid_from_height: qualification.valid_from_height(),
            valid_until_height: qualification.valid_until_height(),
            profile_trust_epoch: authorized.profile_trust_epoch(),
        }
    }

    fn validate(&self) -> Result<(), QRunV06ExecutionError> {
        if zero(&self.asset_id)
            || zero(&self.q6qa_bundle_commitment)
            || zero(&self.q6pn_profile_pin_commitment)
            || self.qualification_epoch == 0
            || self.profile_trust_epoch == 0
            || self.valid_until_height <= self.valid_from_height
        {
            return Err(QRunV06ExecutionError::InvalidQuoteAssetAuthorizationPin);
        }
        Ok(())
    }

    fn encode(&self) -> Result<[u8; QUOTE_ASSET_EXECUTION_PIN_BYTES], QRunV06ExecutionError> {
        self.validate()?;
        let mut out = Vec::with_capacity(QUOTE_ASSET_EXECUTION_PIN_BYTES);
        out.extend_from_slice(&self.asset_id);
        out.extend_from_slice(&self.q6qa_bundle_commitment);
        out.extend_from_slice(&self.q6pn_profile_pin_commitment);
        out.extend_from_slice(&self.qualification_epoch.to_be_bytes());
        out.extend_from_slice(&self.valid_from_height.to_be_bytes());
        out.extend_from_slice(&self.valid_until_height.to_be_bytes());
        out.extend_from_slice(&self.profile_trust_epoch.to_be_bytes());
        out.try_into()
            .map_err(|_| QRunV06ExecutionError::InvalidQuoteAssetAuthorizationPin)
    }

    fn decode(bytes: &[u8]) -> Result<Self, QRunV06ExecutionError> {
        if bytes.len() != QUOTE_ASSET_EXECUTION_PIN_BYTES {
            return Err(QRunV06ExecutionError::SnapshotNonCanonical);
        }
        let mut c = Cursor::new(bytes);
        let pin = Self {
            asset_id: read_array::<32>(&mut c)?,
            q6qa_bundle_commitment: read_array::<32>(&mut c)?,
            q6pn_profile_pin_commitment: read_array::<32>(&mut c)?,
            qualification_epoch: read_u64(&mut c)?,
            valid_from_height: read_u64(&mut c)?,
            valid_until_height: read_u64(&mut c)?,
            profile_trust_epoch: read_u64(&mut c)?,
        };
        if c.position() as usize != bytes.len() {
            return Err(QRunV06ExecutionError::SnapshotNonCanonical);
        }
        pin.validate()?;
        Ok(pin)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06CanonicalExecutionState {
    unified: QRunV06UnifiedAssetState,
    orderbook: OrderBook,
    profile_id: [u8; 32],
    /// None identifies a legacy/market-only QFB6 research fixture. CP-0528-aware
    /// candidate Genesis and subsequent state transitions must carry Some(policy).
    tokenomics: Option<QRunV06TokenomicsState>,
    /// Immutable Genesis descriptor. Production QFP6 admission must reject None.
    genesis_descriptor: Option<QRunV06GenesisDescriptor>,
    quote_asset_authorization: Option<QRunV06PersistedQuoteAssetAuthorization>,
}

impl QRunV06CanonicalExecutionState {
    pub fn new(
        unified: QRunV06UnifiedAssetState,
        profile_id: [u8; 32],
    ) -> Result<Self, QRunV06ExecutionError> {
        let orderbook = OrderBook::new(unified.network_id(), 64, 4_096, 65_536)?;
        Self::new_with_orderbook(unified, profile_id, orderbook)
    }

    pub fn new_with_orderbook(
        unified: QRunV06UnifiedAssetState,
        profile_id: [u8; 32],
        orderbook: OrderBook,
    ) -> Result<Self, QRunV06ExecutionError> {
        if zero(&profile_id) {
            return Err(QRunV06ExecutionError::InvalidProfile);
        }
        unified.verify_invariants()?;
        orderbook.verify()?;
        if orderbook.network_id() != unified.network_id() {
            return Err(QRunV06ExecutionError::WrongNetwork);
        }
        for asset in orderbook.registered_asset_ids() {
            if !unified.is_asset_registered(&asset) {
                return Err(QRunV06ExecutionError::Unified(
                    UnifiedAssetError::AssetNotRegistered(asset),
                ));
            }
        }
        unified.verify_orderbook_vaults(&orderbook)?;
        Ok(Self {
            unified,
            orderbook,
            profile_id,
            tokenomics: None,
            genesis_descriptor: None,
            quote_asset_authorization: None,
        })
    }

    /// Construct a policy-bound CP-0528 Genesis candidate. Exactly 1B QZXB must
    /// exist in the Founder account; the other seven buckets are initially unissued.
    pub fn new_with_tokenomics(
        unified: QRunV06UnifiedAssetState,
        profile_id: [u8; 32],
        tokenomics: QRunV06TokenomicsState,
    ) -> Result<Self, QRunV06ExecutionError> {
        if unified.block_height() != 0 || unified.last_block_timestamp() != 0 {
            return Err(QRunV06ExecutionError::TokenomicsGenesisRequiresEmptyLedger);
        }
        let founder = tokenomics.founder_account();
        let founder_balance = unified
            .ledger()
            .account(&founder)
            .map_or(0u128, |account| account.balance as u128);
        if founder_balance != QRUN_V06_FOUNDER_GENESIS_ATOMS
            || unified
                .ledger()
                .account_entries()
                .iter()
                .any(|(account, state)| *account != founder && state.balance != 0)
        {
            return Err(QRunV06ExecutionError::TokenomicsGenesisRequiresEmptyLedger);
        }
        let mut state = Self::new(unified, profile_id)?;
        if tokenomics.network_id() != state.network_id() {
            return Err(QRunV06ExecutionError::WrongNetwork);
        }
        state.tokenomics = Some(tokenomics);
        state.verify_invariants()?;
        Ok(state)
    }

    /// Build an isolated CP-0528 Genesis candidate without changing QFP5 or Mainnet identity.
    pub fn cp0528_genesis_candidate(
        network_id: [u8; 32],
        profile_id: [u8; 32],
        founder_account: [u8; 32],
        schedule: QRunV06MiningScheduleCandidate,
    ) -> Result<Self, QRunV06ExecutionError> {
        let tokenomics = QRunV06TokenomicsState::genesis(network_id, founder_account, schedule)?;
        let ledger = LedgerState::genesis(
            network_id,
            vec![(founder_account, QRUN_V06_FOUNDER_GENESIS_ATOMS as u64)],
        )?;
        let amm = QzxbAmmStateCandidate::new(network_id, 32, 64, 512)?;
        let unified = QRunV06UnifiedAssetState::new(ledger, amm)?;
        Self::new_with_tokenomics(unified, profile_id, tokenomics)
    }

    /// Construct a CP-0528 Genesis state from an immutable, profile-pinned descriptor.
    /// Unlike the legacy research fixture constructor, this path sets the Ledger Genesis
    /// timestamp and commits the descriptor into every canonical execution root.
    pub fn new_with_genesis_descriptor(
        unified: QRunV06UnifiedAssetState,
        profile_id: [u8; 32],
        tokenomics: QRunV06TokenomicsState,
        descriptor: QRunV06GenesisDescriptor,
    ) -> Result<Self, QRunV06ExecutionError> {
        if unified.block_height() != 0
            || unified.last_block_timestamp() != descriptor.genesis_timestamp()
        {
            return Err(QRunV06ExecutionError::TokenomicsGenesisRequiresEmptyLedger);
        }
        let founder = tokenomics.founder_account();
        let founder_balance = unified
            .ledger()
            .account(&founder)
            .map_or(0u128, |account| account.balance as u128);
        if founder_balance != QRUN_V06_FOUNDER_GENESIS_ATOMS
            || unified
                .ledger()
                .account_entries()
                .iter()
                .any(|(account, state)| *account != founder && state.balance != 0)
        {
            return Err(QRunV06ExecutionError::TokenomicsGenesisRequiresEmptyLedger);
        }
        let mut state = Self::new(unified, profile_id)?;
        if tokenomics.network_id() != state.network_id() {
            return Err(QRunV06ExecutionError::WrongNetwork);
        }
        descriptor.validate_binding(
            &state.network_id(),
            &state.profile_id,
            &founder,
            &descriptor.consensus_fingerprint(),
            &tokenomics.policy_fingerprint(),
        )?;
        state.tokenomics = Some(tokenomics);
        state.genesis_descriptor = Some(descriptor);
        state.verify_invariants()?;
        Ok(state)
    }

    /// Build a timestamp-anchored CP-0528 Genesis. The caller must supply a descriptor
    /// whose commitment is pinned by the selected network/profile configuration.
    pub fn cp0528_genesis_candidate_with_descriptor(
        descriptor: QRunV06GenesisDescriptor,
        schedule: QRunV06MiningScheduleCandidate,
    ) -> Result<Self, QRunV06ExecutionError> {
        let network_id = descriptor.network_id();
        let founder_account = descriptor.founder_account();
        let tokenomics = QRunV06TokenomicsState::genesis(network_id, founder_account, schedule)?;
        let ledger = LedgerState::genesis_at(
            network_id,
            vec![(founder_account, QRUN_V06_FOUNDER_GENESIS_ATOMS as u64)],
            descriptor.genesis_timestamp(),
        )?;
        let amm = QzxbAmmStateCandidate::new(network_id, 32, 64, 512)?;
        let unified = QRunV06UnifiedAssetState::new(ledger, amm)?;
        Self::new_with_genesis_descriptor(unified, descriptor.profile_id(), tokenomics, descriptor)
    }

    pub fn genesis_descriptor(&self) -> Option<&QRunV06GenesisDescriptor> {
        self.genesis_descriptor.as_ref()
    }

    pub fn genesis_timestamp(&self) -> Option<u64> {
        self.genesis_descriptor
            .as_ref()
            .map(QRunV06GenesisDescriptor::genesis_timestamp)
    }

    pub fn genesis_descriptor_commitment(&self) -> Option<[u8; 32]> {
        self.genesis_descriptor
            .as_ref()
            .map(QRunV06GenesisDescriptor::commitment)
    }

    pub fn tokenomics(&self) -> Option<&QRunV06TokenomicsState> {
        self.tokenomics.as_ref()
    }

    /// Verify and atomically apply a Founder-authorized, recipient-accepted CP-0528 release.
    /// This path cannot release Mining, Founder, or ProtocolBurnReserve buckets.
    fn apply_signed_category_release<A: TransactionAuthenticator>(
        &mut self,
        release: &QRunV06SignedCategoryRelease,
        inclusion_timestamp: u64,
        authenticator: &A,
    ) -> Result<(), QRunV06ExecutionError> {
        if inclusion_timestamp == 0 || release.network_id != self.network_id() {
            return Err(QRunV06ExecutionError::InvalidCategoryRelease);
        }
        let policy = self
            .tokenomics
            .as_ref()
            .ok_or(QRunV06ExecutionError::TokenomicsGenesisRequiresEmptyLedger)?;
        let founder = policy.founder_account();
        if release.recipient == founder || release.valid_until_timestamp < inclusion_timestamp {
            return Err(QRunV06ExecutionError::InvalidCategoryRelease);
        }
        let release_id = release.signing_digest()?;
        let recipient_acceptance = release.recipient_acceptance_digest()?;
        authenticator
            .verify(&founder, &release_id, &release.founder_signature)
            .map_err(|_| QRunV06ExecutionError::InvalidCategoryRelease)?;
        authenticator
            .verify(
                &release.recipient,
                &recipient_acceptance,
                &release.recipient_acceptance_signature,
            )
            .map_err(|_| QRunV06ExecutionError::InvalidCategoryRelease)?;

        // Work on a complete execution clone so no failed authorization, cap or ledger
        // projection can leave the policy counter and account balances out of sync.
        let mut next = self.clone();
        next.tokenomics
            .as_mut()
            .ok_or(QRunV06ExecutionError::TokenomicsGenesisRequiresEmptyLedger)?
            .record_category_release(
                release.bucket,
                release.amount_atoms,
                release.nonce,
                release_id,
            )?;
        next.unified
            .apply_v06_category_release(release.recipient, release.amount_atoms)?;
        next.verify_invariants()?;
        *self = next;
        Ok(())
    }

    /// Founder-authorized retirement of unissued ProtocolBurnReserve capacity.
    /// It cannot debit a user account and never leaves a spendable sink balance.
    fn apply_signed_burn_reserve_retirement<A: TransactionAuthenticator>(
        &mut self,
        retirement: &QRunV06SignedBurnReserveRetirement,
        inclusion_timestamp: u64,
        authenticator: &A,
    ) -> Result<(), QRunV06ExecutionError> {
        if inclusion_timestamp == 0
            || retirement.network_id != self.network_id()
            || retirement.valid_until_timestamp < inclusion_timestamp
        {
            return Err(QRunV06ExecutionError::InvalidProtocolBurn);
        }
        let policy = self
            .tokenomics
            .as_ref()
            .ok_or(QRunV06ExecutionError::TokenomicsGenesisRequiresEmptyLedger)?;
        if retirement.policy_fingerprint != policy.policy_fingerprint()
            || retirement.amount_atoms
                > policy.unissued_by_bucket_atoms(QRunV06AllocationBucket::ProtocolBurnReserve)?
        {
            return Err(QRunV06ExecutionError::InvalidProtocolBurn);
        }
        let founder = policy.founder_account();
        let digest = retirement.signing_digest()?;
        authenticator
            .verify(&founder, &digest, &retirement.founder_signature)
            .map_err(|_| QRunV06ExecutionError::InvalidProtocolBurn)?;

        let sink = protocol_burn_sink_account(self.network_id(), retirement.policy_fingerprint);
        if sink == [0; 32] {
            return Err(QRunV06ExecutionError::InvalidProtocolBurn);
        }

        let mut next = self.clone();
        next.tokenomics
            .as_mut()
            .ok_or(QRunV06ExecutionError::TokenomicsGenesisRequiresEmptyLedger)?
            .record_protocol_burn_reserve_retirement(
                retirement.amount_atoms,
                retirement.expected_burned_atoms,
            )?;
        next.unified
            .apply_v06_protocol_burn_reserve_retirement(sink, retirement.amount_atoms)?;
        next.verify_invariants()?;
        *self = next;
        Ok(())
    }

    /// The active QFP6 consensus profile must use the same subsidy schedule as Q6TM.
    pub fn validate_consensus_parameters(
        &self,
        params: &ConsensusParameters,
    ) -> Result<(), QRunV06ExecutionError> {
        if let Some(tokenomics) = &self.tokenomics {
            let schedule = tokenomics.mining_schedule();
            if params.issuance.maximum_supply()
                != crate::qrun_v06_tokenomics_candidate::QRUN_V06_MAX_GROSS_ISSUANCE_ATOMS
                || params.issuance.initial_subsidy() != schedule.initial_subsidy_atoms
                || params.issuance.blocks_per_halving() != schedule.blocks_per_halving
            {
                return Err(QRunV06ExecutionError::TokenomicsConsensusMismatch);
            }
            if let Some(descriptor) = &self.genesis_descriptor {
                let consensus_fingerprint =
                    crate::qrun_v06_checkpoint_candidate::qrun_v06_consensus_fingerprint(params)
                        .map_err(|_| QRunV06ExecutionError::TokenomicsConsensusMismatch)?;
                descriptor.validate_binding(
                    &self.network_id(),
                    &self.profile_id,
                    &tokenomics.founder_account(),
                    &consensus_fingerprint,
                    &tokenomics.policy_fingerprint(),
                )?;
            }
        } else if self.genesis_descriptor.is_some() {
            return Err(QRunV06ExecutionError::TokenomicsConsensusMismatch);
        }
        Ok(())
    }

    pub fn unified(&self) -> &QRunV06UnifiedAssetState {
        &self.unified
    }

    pub fn orderbook(&self) -> &OrderBook {
        &self.orderbook
    }

    pub fn verify_invariants(&self) -> Result<(), QRunV06ExecutionError> {
        self.unified.verify_invariants()?;
        self.orderbook.verify()?;
        self.unified.verify_orderbook_vaults(&self.orderbook)?;
        if let Some(tokenomics) = &self.tokenomics {
            if tokenomics.network_id() != self.network_id() {
                return Err(QRunV06ExecutionError::WrongNetwork);
            }
            tokenomics.validate_against_ledger(self.unified.ledger().total_value()?)?;
            let burn_sink =
                protocol_burn_sink_account(self.network_id(), tokenomics.policy_fingerprint());
            if self.unified.ledger().account(&burn_sink).is_some() {
                return Err(QRunV06ExecutionError::ProtocolBurnSinkNotEmpty);
            }
            if let Some(descriptor) = &self.genesis_descriptor {
                descriptor.validate_binding(
                    &self.network_id(),
                    &self.profile_id,
                    &tokenomics.founder_account(),
                    &descriptor.consensus_fingerprint(),
                    &tokenomics.policy_fingerprint(),
                )?;
                let genesis_timestamp = descriptor.genesis_timestamp();
                if self.height() == 0 {
                    if self.last_timestamp() != genesis_timestamp {
                        return Err(QRunV06ExecutionError::InvalidTimestamp);
                    }
                } else if self.last_timestamp() <= genesis_timestamp {
                    return Err(QRunV06ExecutionError::InvalidTimestamp);
                }
            }
        } else if self.genesis_descriptor.is_some() {
            return Err(QRunV06ExecutionError::TokenomicsConsensusMismatch);
        }
        if let Some(quote_authorization) = &self.quote_asset_authorization {
            quote_authorization.validate()?;
            if quote_authorization.asset_id == self.unified.native_asset_id() {
                return Err(QRunV06ExecutionError::InvalidQuoteAssetAuthorizationPin);
            }
            if quote_authorization.valid_until_height <= self.height() {
                // A state snapshot may be restored after the authorization window has ended.
                // It remains readable, but block execution is fail-closed until a newer
                // Q6TS-authorized qualification is supplied.
            }
        }
        Ok(())
    }

    pub fn quote_asset_authorization_commitment(&self) -> Option<[u8; 32]> {
        self.quote_asset_authorization
            .as_ref()
            .map(|pin| pin.q6qa_bundle_commitment)
    }

    pub fn quote_asset_authorization_asset_id(&self) -> Option<[u8; 32]> {
        self.quote_asset_authorization
            .as_ref()
            .map(|pin| pin.asset_id)
    }

    #[cfg(test)]
    pub(crate) fn clear_test_quote_asset_authorization(&mut self) {
        self.quote_asset_authorization = None;
    }

    #[cfg(test)]
    pub(crate) fn install_test_quote_asset_authorization(
        &mut self,
        asset_id: [u8; 32],
        q6qa_bundle_commitment: [u8; 32],
        q6pn_profile_pin_commitment: [u8; 32],
        qualification_epoch: u64,
        valid_from_height: u64,
        valid_until_height: u64,
        profile_trust_epoch: u64,
    ) {
        self.quote_asset_authorization = Some(QRunV06PersistedQuoteAssetAuthorization {
            asset_id,
            q6qa_bundle_commitment,
            q6pn_profile_pin_commitment,
            qualification_epoch,
            valid_from_height,
            valid_until_height,
            profile_trust_epoch,
        });
    }

    /// Determine which single non-native quote asset must be freshly authorized for
    /// this exact block. Existing pairs are inspected as well as new operations, so
    /// legacy snapshots containing an unpinned external pair fail closed rather than
    /// allowing ordinary transfers or replays to bypass the market gate.
    pub fn required_quote_asset_for_block(
        &self,
        block: &QRunV06Block,
    ) -> Result<Option<[u8; 32]>, QRunV06ExecutionError> {
        fn include_quote(
            required: &mut Option<[u8; 32]>,
            native_asset: [u8; 32],
            asset: [u8; 32],
        ) -> Result<(), QRunV06ExecutionError> {
            if asset == native_asset {
                return Ok(());
            }
            match *required {
                Some(existing) if existing != asset => {
                    Err(QRunV06ExecutionError::QuoteAssetAuthorizationMismatch)
                }
                Some(_) => Ok(()),
                None => {
                    *required = Some(asset);
                    Ok(())
                }
            }
        }

        fn include_pair(
            required: &mut Option<[u8; 32]>,
            native_asset: [u8; 32],
            asset_a: [u8; 32],
            asset_b: [u8; 32],
        ) -> Result<(), QRunV06ExecutionError> {
            include_quote(required, native_asset, asset_a)?;
            include_quote(required, native_asset, asset_b)
        }

        let native_asset = self.unified.native_asset_id();
        let mut required = None;

        if let Some(pin) = &self.quote_asset_authorization {
            include_quote(&mut required, native_asset, pin.asset_id)?;
        }

        // Existing OrderBook markets remain trust-pinned across unrelated later blocks.
        for rules in self.orderbook.pair_rules_iter() {
            include_quote(&mut required, native_asset, rules.quote)?;
        }

        // Existing AMM pools must also keep requiring the same fresh quote authorization.
        // A pool with two distinct external assets fails closed because this profile pins one
        // quote asset at a time; it must not silently choose one side.
        for (asset_a, asset_b) in self.unified.amm().pair_asset_pairs_iter() {
            include_pair(&mut required, native_asset, asset_a, asset_b)?;
        }

        for operation in &block.operations {
            match operation {
                QRunV06BlockOperation::OrderBook(signed) => match &signed.operation {
                    QRunV06OrderBookOperation::CreatePair { quote, .. } => {
                        include_quote(&mut required, native_asset, *quote)?;
                    }
                    QRunV06OrderBookOperation::PlaceLimit { pair, .. } => {
                        if let Some(rules) = self.orderbook.pair_rules(pair) {
                            include_quote(&mut required, native_asset, rules.quote)?;
                        }
                    }
                    QRunV06OrderBookOperation::Deposit { .. }
                    | QRunV06OrderBookOperation::Withdraw { .. }
                    | QRunV06OrderBookOperation::Cancel { .. } => {}
                },
                QRunV06BlockOperation::Amm(signed) => match &signed.operation {
                    AmmOperation::CreatePair { token_a, token_b } => {
                        include_pair(&mut required, native_asset, *token_a, *token_b)?;
                    }
                    AmmOperation::SwapExactIn {
                        token_in,
                        token_out,
                        ..
                    } => {
                        include_pair(&mut required, native_asset, *token_in, *token_out)?;
                    }
                    AmmOperation::AddLiquidity { pair_id, .. }
                    | AmmOperation::RemoveLiquidity { pair_id, .. } => {
                        if let Ok((asset_a, asset_b)) = self.unified.amm().pair_assets(pair_id) {
                            include_pair(&mut required, native_asset, asset_a, asset_b)?;
                        }
                    }
                    AmmOperation::RegisterAsset { .. }
                    | AmmOperation::TransferAsset { .. }
                    | AmmOperation::MintTestQuote { .. } => {}
                },
                QRunV06BlockOperation::NativeTransfer(_)
                | QRunV06BlockOperation::AssetRegistration(_)
                | QRunV06BlockOperation::AssetAdmin(_)
                | QRunV06BlockOperation::CategoryRelease(_)
                | QRunV06BlockOperation::ProtocolBurnReserveRetirement(_) => {}
            }
        }
        Ok(required)
    }
    pub fn quote_asset_authorization_epoch(&self) -> Option<u64> {
        self.quote_asset_authorization
            .as_ref()
            .map(|pin| pin.qualification_epoch)
    }

    pub fn network_id(&self) -> NetworkId {
        self.unified.network_id()
    }

    pub fn profile_id(&self) -> [u8; 32] {
        self.profile_id
    }

    pub fn height(&self) -> u64 {
        self.unified.block_height()
    }

    pub fn last_timestamp(&self) -> u64 {
        self.unified.last_block_timestamp()
    }

    pub fn tip_hash(&self) -> [u8; 32] {
        self.unified.tip_hash()
    }

    pub fn state_root(&self) -> Result<[u8; 32], QRunV06ExecutionError> {
        self.verify_invariants()?;
        let unified_root = self.unified.state_root()?;
        let orderbook_root = self.orderbook.state_root()?;
        let mut hash = Sha256::new();
        hash.update(EXECUTION_ROOT_DOMAIN);
        hash.update(self.network_id());
        hash.update(self.profile_id);
        hash.update(unified_root);
        hash.update(orderbook_root);
        match &self.tokenomics {
            Some(tokenomics) => {
                hash.update([1u8]);
                hash.update(tokenomics.state_root()?);
            }
            None => hash.update([0u8]),
        }
        match &self.genesis_descriptor {
            Some(descriptor) => {
                hash.update([1u8]);
                hash.update(descriptor.commitment());
            }
            None => hash.update([0u8]),
        }
        if let Some(quote_authorization) = &self.quote_asset_authorization {
            hash.update(QUOTE_ASSET_EXECUTION_PIN_DOMAIN);
            hash.update(quote_authorization.encode()?);
        }
        Ok(hash.finalize().into())
    }

    /// Encode all QFB6 execution components into one bounded canonical snapshot.
    /// Header metadata and the recomputed combined root bind Ledger, AMM, registry, order book,
    /// escrow and fill history into a single restart object.
    pub fn encode_snapshot(&self) -> Result<Vec<u8>, QRunV06ExecutionError> {
        self.verify_invariants()?;
        let ledger = self.unified.ledger().encode_snapshot()?;
        let amm = self.unified.amm().encode_snapshot()?;
        let registry = self.unified.registry().encode_snapshot()?;
        let orderbook = self.orderbook.encode_snapshot()?;
        let tokenomics = self
            .tokenomics
            .as_ref()
            .map(QRunV06TokenomicsState::encode_snapshot)
            .transpose()?;
        let root = self.state_root()?;

        let mut out = Vec::with_capacity(
            186usize
                .saturating_add(ledger.len())
                .saturating_add(amm.len())
                .saturating_add(registry.len())
                .saturating_add(orderbook.len())
                .saturating_add(32),
        );
        out.extend_from_slice(&EXECUTION_SNAPSHOT_MAGIC);
        out.extend_from_slice(&EXECUTION_SNAPSHOT_VERSION.to_be_bytes());
        out.extend_from_slice(&self.network_id());
        out.extend_from_slice(&self.profile_id);
        out.extend_from_slice(&self.height().to_be_bytes());
        out.extend_from_slice(&self.last_timestamp().to_be_bytes());
        out.extend_from_slice(&self.tip_hash());
        out.extend_from_slice(&root);
        execution_snapshot_put_component(&mut out, &ledger)?;
        execution_snapshot_put_component(&mut out, &amm)?;
        execution_snapshot_put_component(&mut out, &registry)?;
        execution_snapshot_put_component(&mut out, &orderbook)?;
        match tokenomics {
            Some(snapshot) => {
                out.push(1);
                execution_snapshot_put_component(&mut out, &snapshot)?;
            }
            None => out.push(0),
        }
        match &self.genesis_descriptor {
            Some(descriptor) => {
                out.push(1);
                execution_snapshot_put_component(&mut out, &descriptor.encode())?;
            }
            None => out.push(0),
        }
        match &self.quote_asset_authorization {
            Some(authorization) => {
                out.push(1);
                out.extend_from_slice(&authorization.encode()?);
            }
            None => out.push(0),
        }
        if out.len().saturating_add(32) > MAX_QRUN_V06_EXECUTION_SNAPSHOT_BYTES {
            return Err(QRunV06ExecutionError::SnapshotOversize);
        }
        let mut checksum = Sha256::new();
        checksum.update(EXECUTION_SNAPSHOT_CHECKSUM_DOMAIN);
        checksum.update(&out);
        out.extend_from_slice(&checksum.finalize());
        Ok(out)
    }

    /// Restore an entire QFB6 execution state. Every nested codec checks its own checksum,
    /// network binding, bounds and canonical ordering; the outer codec then rebinds tip,
    /// height, timestamp, profile and the combined state root before exposing the state.
    pub fn decode_snapshot(
        bytes: &[u8],
        expected_network_id: &NetworkId,
        expected_profile_id: &[u8; 32],
    ) -> Result<Self, QRunV06ExecutionError> {
        if bytes.len() > MAX_QRUN_V06_EXECUTION_SNAPSHOT_BYTES {
            return Err(QRunV06ExecutionError::SnapshotOversize);
        }
        const HEADER_BYTES_V4: usize = 4 + 2 + 32 + 32 + 8 + 8 + 32 + 32 + 4 * 4 + 1 + 1;
        if bytes.len() < HEADER_BYTES_V4 + 32
            || zero(expected_network_id)
            || zero(expected_profile_id)
        {
            return Err(QRunV06ExecutionError::SnapshotMalformed);
        }
        let payload_len = bytes.len() - 32;
        let mut checksum = Sha256::new();
        checksum.update(EXECUTION_SNAPSHOT_CHECKSUM_DOMAIN);
        checksum.update(&bytes[..payload_len]);
        if checksum.finalize().as_slice() != &bytes[payload_len..] {
            return Err(QRunV06ExecutionError::SnapshotChecksumMismatch);
        }

        let payload = &bytes[..payload_len];
        let mut cursor = Cursor::new(payload);
        if execution_snapshot_read::<4>(&mut cursor)? != EXECUTION_SNAPSHOT_MAGIC {
            return Err(QRunV06ExecutionError::SnapshotMalformed);
        }
        let version = execution_snapshot_u16(&mut cursor)?;
        if version != EXECUTION_SNAPSHOT_VERSION && version != EXECUTION_SNAPSHOT_VERSION_LEGACY {
            return Err(QRunV06ExecutionError::SnapshotNonCanonical);
        }
        let network_id = execution_snapshot_read::<32>(&mut cursor)?;
        let profile_id = execution_snapshot_read::<32>(&mut cursor)?;
        if &network_id != expected_network_id {
            return Err(QRunV06ExecutionError::WrongNetwork);
        }
        if &profile_id != expected_profile_id {
            return Err(QRunV06ExecutionError::WrongProfile);
        }
        let height = execution_snapshot_u64(&mut cursor)?;
        let timestamp = execution_snapshot_u64(&mut cursor)?;
        let tip_hash = execution_snapshot_read::<32>(&mut cursor)?;
        let expected_root = execution_snapshot_read::<32>(&mut cursor)?;

        let ledger_bytes =
            execution_snapshot_read_component(&mut cursor, MAX_ENCODED_SNAPSHOT_BYTES)?;
        let amm_bytes = execution_snapshot_read_component(&mut cursor, MAX_AMM_SNAPSHOT_BYTES)?;
        let registry_bytes =
            execution_snapshot_read_component(&mut cursor, MAX_QRUN_V06_REGISTRY_SNAPSHOT_BYTES)?;
        let orderbook_bytes =
            execution_snapshot_read_component(&mut cursor, MAX_QRUN_V06_ORDERBOOK_SNAPSHOT_BYTES)?;
        let tokenomics = match execution_snapshot_read::<1>(&mut cursor)?[0] {
            0 => None,
            1 => Some(QRunV06TokenomicsState::decode_snapshot(
                &execution_snapshot_read_component(
                    &mut cursor,
                    QRUN_V06_TOKENOMICS_SNAPSHOT_BYTES,
                )?,
                expected_network_id,
            )?),
            _ => return Err(QRunV06ExecutionError::SnapshotNonCanonical),
        };
        let genesis_descriptor = match execution_snapshot_read::<1>(&mut cursor)?[0] {
            0 => None,
            1 => Some(QRunV06GenesisDescriptor::decode(
                &execution_snapshot_read_component(
                    &mut cursor,
                    crate::qrun_v06_genesis_descriptor_candidate::QRUN_V06_GENESIS_DESCRIPTOR_BYTES,
                )?,
            )?),
            _ => return Err(QRunV06ExecutionError::SnapshotNonCanonical),
        };
        let quote_asset_authorization = if version >= EXECUTION_SNAPSHOT_VERSION {
            match execution_snapshot_read::<1>(&mut cursor)?[0] {
                0 => None,
                1 => Some(QRunV06PersistedQuoteAssetAuthorization::decode(
                    &execution_snapshot_read::<QUOTE_ASSET_EXECUTION_PIN_BYTES>(&mut cursor)?,
                )?),
                _ => return Err(QRunV06ExecutionError::SnapshotNonCanonical),
            }
        } else {
            None
        };
        if cursor.position() as usize != payload.len() {
            return Err(QRunV06ExecutionError::SnapshotNonCanonical);
        }

        let ledger = LedgerState::decode_snapshot(&ledger_bytes, expected_network_id)?;
        if ledger.height() != height
            || ledger.last_timestamp() != timestamp
            || ledger.tip_hash() != tip_hash
        {
            return Err(QRunV06ExecutionError::SnapshotNonCanonical);
        }
        let amm = QzxbAmmStateCandidate::decode_snapshot(&amm_bytes)
            .map_err(QRunV06ExecutionError::Amm)?;
        let registry =
            QRunV06AssetRegistryCandidate::decode_snapshot(&registry_bytes, expected_network_id)
                .map_err(QRunV06ExecutionError::AssetRegistry)?;
        let orderbook = OrderBook::decode_snapshot(&orderbook_bytes, expected_network_id)
            .map_err(QRunV06ExecutionError::OrderBook)?;
        let unified = QRunV06UnifiedAssetState::new_with_registry(ledger, amm, registry)
            .map_err(QRunV06ExecutionError::Unified)?;
        let mut restored = Self::new_with_orderbook(unified, profile_id, orderbook)?;
        restored.tokenomics = tokenomics;
        restored.genesis_descriptor = genesis_descriptor;
        restored.quote_asset_authorization = quote_asset_authorization;
        restored.verify_invariants()?;
        if restored.height() != height
            || restored.last_timestamp() != timestamp
            || restored.tip_hash() != tip_hash
            || restored.state_root()? != expected_root
        {
            return Err(QRunV06ExecutionError::StateRootMismatch);
        }
        if version == EXECUTION_SNAPSHOT_VERSION && restored.encode_snapshot()?.as_slice() != bytes
        {
            return Err(QRunV06ExecutionError::SnapshotNonCanonical);
        }
        Ok(restored)
    }

    fn validate_block_header(&self, block: &QRunV06Block) -> Result<(), QRunV06ExecutionError> {
        self.verify_invariants()?;
        if block.network_id != self.network_id() {
            return Err(QRunV06ExecutionError::WrongNetwork);
        }
        if block.profile_id != self.profile_id {
            return Err(QRunV06ExecutionError::WrongProfile);
        }
        if block.height == 0 {
            return Err(QRunV06ExecutionError::InvalidHeight);
        }
        if block.timestamp == 0 {
            return Err(QRunV06ExecutionError::InvalidTimestamp);
        }
        let expected_height = self
            .height()
            .checked_add(1)
            .ok_or(QRunV06ExecutionError::InvalidHeight)?;
        if block.height != expected_height {
            return Err(QRunV06ExecutionError::HeightMismatch {
                expected: expected_height,
                actual: block.height,
            });
        }
        if block.parent_hash != self.tip_hash() {
            return Err(QRunV06ExecutionError::ParentHashMismatch);
        }
        if block.timestamp <= self.last_timestamp() {
            return Err(QRunV06ExecutionError::TimestampNotIncreasing {
                previous: self.last_timestamp(),
                actual: block.timestamp,
            });
        }
        if zero(&block.producer) {
            return Err(QRunV06ExecutionError::Malformed);
        }
        if self.unified.fee_pool() != 0 {
            return Err(QRunV06ExecutionError::FeePoolNotEmptyAtBlockStart);
        }
        Ok(())
    }

    fn bind_quote_asset_authorization(
        &mut self,
        asset_id: [u8; 32],
        block_height: u64,
        authorization: Option<&QRunV06TrustAuthorizedQuoteAsset>,
    ) -> Result<(), QRunV06ExecutionError> {
        if asset_id == self.unified.native_asset_id() {
            return Ok(());
        }
        let authorization =
            authorization.ok_or(QRunV06ExecutionError::MissingQuoteAssetAuthorization)?;
        authorization
            .require_for_pair(
                &self.network_id(),
                &self.profile_id,
                &asset_id,
                block_height,
            )
            .map_err(|_| QRunV06ExecutionError::QuoteAssetAuthorizationMismatch)?;
        let next = QRunV06PersistedQuoteAssetAuthorization::from_authorized(authorization);
        next.validate()?;
        if let Some(current) = &self.quote_asset_authorization {
            if next.profile_trust_epoch < current.profile_trust_epoch
                || next.qualification_epoch < current.qualification_epoch
                || (next.q6qa_bundle_commitment != current.q6qa_bundle_commitment
                    && next.qualification_epoch <= current.qualification_epoch)
                || (next.asset_id != current.asset_id
                    && (next.profile_trust_epoch <= current.profile_trust_epoch
                        || next.qualification_epoch <= current.qualification_epoch))
            {
                return Err(QRunV06ExecutionError::QuoteAssetAuthorizationRollback);
            }
        }
        self.quote_asset_authorization = Some(next);
        Ok(())
    }

    fn validate_quote_asset_decimals_for_block(
        &self,
        block: &QRunV06Block,
        authorization: Option<&QRunV06TrustAuthorizedQuoteAsset>,
    ) -> Result<(), QRunV06ExecutionError> {
        let Some(asset_id) = self.required_quote_asset_for_block(block)? else {
            return Ok(());
        };
        if asset_id == self.unified.native_asset_id() {
            return Ok(());
        }

        // A Q6QA trust pin may be prepublished before a market pair is created.
        // Decimal equality is required only once this asset is actually used by a pair.
        let asset_is_in_market_pair = self
            .orderbook
            .pair_rules_iter()
            .any(|rules| rules.quote == asset_id)
            || self
                .unified
                .amm()
                .pair_asset_pairs_iter()
                .any(|(asset_a, asset_b)| asset_a == asset_id || asset_b == asset_id);
        if !asset_is_in_market_pair {
            return Ok(());
        }

        let authorization =
            authorization.ok_or(QRunV06ExecutionError::MissingQuoteAssetAuthorization)?;
        authorization
            .require_for_pair(
                &self.network_id(),
                &self.profile_id,
                &asset_id,
                block.height,
            )
            .map_err(|_| QRunV06ExecutionError::QuoteAssetAuthorizationMismatch)?;

        let metadata = self.unified.registry().asset(&asset_id).ok_or(
            QRunV06ExecutionError::AssetRegistry(AssetRegistryError::AssetNotFound),
        )?;
        let q6qa_decimals = authorization.qualification().decimals();
        if metadata.decimals != q6qa_decimals {
            return Err(QRunV06ExecutionError::QuoteAssetDecimalsMismatch {
                asset_id,
                q6qa_decimals,
                registry_decimals: metadata.decimals,
            });
        }
        Ok(())
    }

    fn apply_orderbook_operation<A: TransactionAuthenticator>(
        &mut self,
        signed: &QRunV06SignedOrderBookOperation,
        block: &QRunV06Block,
        operation_index: usize,
        authenticator: &A,
        quote_authorization: Option<&QRunV06TrustAuthorizedQuoteAsset>,
    ) -> Result<(), QRunV06ExecutionError> {
        let _ = signed.encode()?;
        match &signed.operation {
            QRunV06OrderBookOperation::CreatePair {
                base,
                quote,
                base_lot_atoms,
                quote_tick_atoms,
                max_price_ticks,
                max_quantity_lots,
                min_notional,
                maker_fee_bps,
                taker_fee_bps,
                fee_collector,
            } => {
                if *quote != self.unified.native_asset_id() {
                    self.bind_quote_asset_authorization(*quote, block.height, quote_authorization)?;
                }
                if !self.unified.is_asset_registered(base) {
                    return Err(QRunV06ExecutionError::Unified(
                        UnifiedAssetError::AssetNotRegistered(*base),
                    ));
                }
                if !self.unified.is_asset_registered(quote) {
                    return Err(QRunV06ExecutionError::Unified(
                        UnifiedAssetError::AssetNotRegistered(*quote),
                    ));
                }
                self.unified.ensure_asset_transfer_enabled(base)?;
                self.unified.ensure_asset_transfer_enabled(quote)?;
                let mut protected_assets: std::collections::BTreeSet<[u8; 32]> = self
                    .unified
                    .registry()
                    .registered_asset_ids()
                    .into_iter()
                    .collect();
                protected_assets.insert(self.unified.native_asset_id());
                let fee_collector_is_vault = protected_assets.iter().any(|asset| {
                    orderbook_vault_account(self.network_id(), *asset) == *fee_collector
                });
                if self.unified.amm().is_pool_account_id(fee_collector) || fee_collector_is_vault {
                    return Err(QRunV06ExecutionError::Malformed);
                }
                self.unified.apply_signed_orderbook_transition(
                    signed,
                    block.timestamp,
                    None,
                    authenticator,
                )?;
                self.orderbook.register_pair(
                    *base,
                    *quote,
                    *base_lot_atoms,
                    *quote_tick_atoms,
                    *max_price_ticks,
                    *max_quantity_lots,
                    *min_notional,
                    *maker_fee_bps,
                    *taker_fee_bps,
                    *fee_collector,
                )?;
            }
            QRunV06OrderBookOperation::Deposit { asset, amount } => {
                if !self.orderbook.registered_asset_ids().contains(asset) {
                    return Err(QRunV06ExecutionError::OrderBook(
                        OrderBookError::InvalidAsset,
                    ));
                }
                let vault = orderbook_vault_account(self.network_id(), *asset);
                self.unified.apply_signed_orderbook_transition(
                    signed,
                    block.timestamp,
                    Some((*asset, signed.sender, vault, *amount)),
                    authenticator,
                )?;
                self.orderbook
                    .deposit_balance(*asset, signed.sender, *amount)?;
            }
            QRunV06OrderBookOperation::Withdraw { asset, amount } => {
                if !self.orderbook.registered_asset_ids().contains(asset) {
                    return Err(QRunV06ExecutionError::OrderBook(
                        OrderBookError::InvalidAsset,
                    ));
                }
                let vault = orderbook_vault_account(self.network_id(), *asset);
                self.orderbook
                    .withdraw_balance(*asset, signed.sender, *amount)?;
                self.unified.apply_signed_orderbook_transition(
                    signed,
                    block.timestamp,
                    Some((*asset, vault, signed.sender, *amount)),
                    authenticator,
                )?;
            }
            QRunV06OrderBookOperation::PlaceLimit {
                pair,
                side,
                price_ticks,
                quantity_lots,
                tif,
                expires_at_height,
            } => {
                let (base_asset, quote_asset) = {
                    let rules = self
                        .orderbook
                        .pair_rules(pair)
                        .ok_or(OrderBookError::PairNotFound)?;
                    (rules.base, rules.quote)
                };
                if quote_asset != self.unified.native_asset_id() {
                    self.bind_quote_asset_authorization(
                        quote_asset,
                        block.height,
                        quote_authorization,
                    )?;
                }
                self.unified.ensure_asset_transfer_enabled(&base_asset)?;
                self.unified.ensure_asset_transfer_enabled(&quote_asset)?;
                self.unified.apply_signed_orderbook_transition(
                    signed,
                    block.timestamp,
                    None,
                    authenticator,
                )?;
                let index =
                    u32::try_from(operation_index).map_err(|_| QRunV06ExecutionError::Malformed)?;
                let transaction_id = signed.signing_digest()?;
                self.orderbook.place(PlaceLimit {
                    pair: *pair,
                    owner: signed.sender,
                    side: *side,
                    price_ticks: *price_ticks,
                    quantity_lots: *quantity_lots,
                    tif: *tif,
                    expires_at_height: *expires_at_height,
                    priority: Priority {
                        height: block.height,
                        tx_index: index,
                        op_index: index,
                    },
                    transaction_id,
                    operation_index: index,
                })?;
            }
            QRunV06OrderBookOperation::Cancel { order_id } => {
                self.unified.apply_signed_orderbook_transition(
                    signed,
                    block.timestamp,
                    None,
                    authenticator,
                )?;
                self.orderbook.cancel(*order_id, signed.sender)?;
            }
        }
        self.verify_invariants()?;
        Ok(())
    }

    fn execute_operations<A: TransactionAuthenticator>(
        &mut self,
        block: &QRunV06Block,
        authenticator: &A,
        quote_authorization: Option<&QRunV06TrustAuthorizedQuoteAsset>,
    ) -> Result<QRunV06BlockApplySummary, QRunV06ExecutionError> {
        // Recompute the quote requirement from the parent state and this block before
        // any expiry, refund, transfer or other mutation. This also catches legacy
        // snapshots that already contain an external-quote pair but lack a Q6QA pin.
        if let Some(required_quote_asset) = self.required_quote_asset_for_block(block)? {
            self.bind_quote_asset_authorization(
                required_quote_asset,
                block.height,
                quote_authorization,
            )?;
        }
        let orders_expired = self.orderbook.expire(block.height)?.len();
        self.verify_invariants()?;

        let mut txids = std::collections::BTreeSet::new();
        let mut native_transfers = 0usize;
        let mut amm_operations = 0usize;
        let mut asset_registrations = 0usize;
        let mut asset_admin_operations = 0usize;
        let mut orderbook_operations = 0usize;
        let mut category_releases = 0usize;
        let mut protocol_burns = 0usize;

        for (operation_index, operation) in block.operations.iter().enumerate() {
            match operation {
                QRunV06BlockOperation::NativeTransfer(transaction) => {
                    let txid = transaction_id(transaction)?;
                    if !txids.insert(txid) {
                        return Err(QRunV06ExecutionError::DuplicateTransaction);
                    }
                    self.unified.apply_signed_native_transaction(
                        transaction,
                        block.timestamp,
                        authenticator,
                    )?;
                    native_transfers += 1;
                }
                QRunV06BlockOperation::Amm(operation) => {
                    self.unified.apply_signed_market_operation(
                        operation,
                        block.timestamp,
                        authenticator,
                    )?;
                    amm_operations += 1;
                }
                QRunV06BlockOperation::AssetRegistration(registration) => {
                    self.unified.register_signed_asset(
                        registration,
                        block.timestamp,
                        authenticator,
                    )?;
                    asset_registrations += 1;
                }
                QRunV06BlockOperation::AssetAdmin(operation) => {
                    self.unified.apply_signed_asset_admin_operation(
                        operation,
                        block.timestamp,
                        authenticator,
                    )?;
                    asset_admin_operations += 1;
                }
                QRunV06BlockOperation::OrderBook(operation) => {
                    self.apply_orderbook_operation(
                        operation,
                        block,
                        operation_index,
                        authenticator,
                        quote_authorization,
                    )?;
                    orderbook_operations += 1;
                }
                QRunV06BlockOperation::CategoryRelease(release) => {
                    self.apply_signed_category_release(release, block.timestamp, authenticator)?;
                    category_releases += 1;
                }
                QRunV06BlockOperation::ProtocolBurnReserveRetirement(retirement) => {
                    self.apply_signed_burn_reserve_retirement(
                        retirement,
                        block.timestamp,
                        authenticator,
                    )?;
                    protocol_burns += 1;
                }
            }
        }

        // Recheck Q6QA decimals after ordered operations stage any same-block registrations.
        // A mismatch aborts this cloned transition before its state root can be committed.
        self.validate_quote_asset_decimals_for_block(block, quote_authorization)?;
        self.verify_invariants()?;
        let fees_paid_to_producer = self.unified.settle_v06_block_fees(block.producer)?;
        let mining_reward_atoms = if let Some(tokenomics) = &self.tokenomics {
            let reward = tokenomics.expected_mining_reward_atoms(block.height)?;
            if reward > 0 {
                self.unified
                    .apply_v06_mining_reward(block.producer, reward)?;
                self.tokenomics
                    .as_mut()
                    .ok_or(QRunV06ExecutionError::TokenomicsGenesisRequiresEmptyLedger)?
                    .record_mining_reward(block.height, reward)?;
            }
            reward
        } else {
            0
        };
        self.unified
            .advance_v06_block_header(block.height, block.timestamp, &block.parent_hash)?;
        self.verify_invariants()?;

        let root = self.state_root()?;

        Ok(QRunV06BlockApplySummary {
            height: block.height,
            block_id: [0; 32],
            state_root: root,
            mining_reward_atoms,
            operations_applied: block.operations.len(),
            native_transfers,
            amm_operations,
            asset_registrations,
            asset_admin_operations,
            orderbook_operations,
            category_releases,
            protocol_burns,
            orders_expired,
            fees_paid_to_producer,
        })
    }

    /// Build the post-state root for a candidate block without changing the caller's state.
    pub fn preview_state_root_after<A: TransactionAuthenticator>(
        &self,
        block: &QRunV06Block,
        authenticator: &A,
    ) -> Result<[u8; 32], QRunV06ExecutionError> {
        self.preview_state_root_after_with_quote_asset_authorization(block, authenticator, None)
    }

    pub fn preview_state_root_after_with_quote_asset_authorization<A: TransactionAuthenticator>(
        &self,
        block: &QRunV06Block,
        authenticator: &A,
        quote_authorization: Option<&QRunV06TrustAuthorizedQuoteAsset>,
    ) -> Result<[u8; 32], QRunV06ExecutionError> {
        let _ = encode_qrun_v06_block(block)?;
        self.validate_block_header(block)?;
        let mut next = self.clone();
        let _ = next.execute_operations(block, authenticator, quote_authorization)?;
        next.state_root()
    }

    /// Legacy path remains usable for native-quote pairs. Once an external quote asset
    /// is selected, it fails closed because the caller must use the authorization-aware path.
    pub fn apply_block<A: TransactionAuthenticator>(
        &mut self,
        block: &QRunV06Block,
        authenticator: &A,
    ) -> Result<QRunV06BlockApplySummary, QRunV06ExecutionError> {
        self.apply_block_with_quote_asset_authorization(block, authenticator, None)
    }

    /// Atomically execute canonical QFB6 with a fresh Q6TS/Q6QA-authorized quote object.
    /// The persisted pin becomes part of the execution root and Q6SN v5 snapshot.
    pub fn apply_block_with_quote_asset_authorization<A: TransactionAuthenticator>(
        &mut self,
        block: &QRunV06Block,
        authenticator: &A,
        quote_authorization: Option<&QRunV06TrustAuthorizedQuoteAsset>,
    ) -> Result<QRunV06BlockApplySummary, QRunV06ExecutionError> {
        let canonical = encode_qrun_v06_block(block)?;
        self.validate_block_header(block)?;
        let mut next = self.clone();
        let mut summary = next.execute_operations(block, authenticator, quote_authorization)?;
        if summary.state_root != block.state_root {
            return Err(QRunV06ExecutionError::StateRootMismatch);
        }
        let block_id = qrun_v06_block_id_from_bytes(&canonical);
        next.unified
            .commit_v06_block_id(&block.parent_hash, block_id)?;
        summary.block_id = block_id;
        *self = next;
        Ok(summary)
    }
}

pub fn encode_qrun_v06_block(block: &QRunV06Block) -> Result<Vec<u8>, QRunV06ExecutionError> {
    if zero(&block.network_id) {
        return Err(QRunV06ExecutionError::InvalidNetwork);
    }
    if zero(&block.profile_id) {
        return Err(QRunV06ExecutionError::InvalidProfile);
    }
    if block.height == 0 {
        return Err(QRunV06ExecutionError::InvalidHeight);
    }
    if block.timestamp == 0 || zero(&block.producer) {
        return Err(QRunV06ExecutionError::InvalidTimestamp);
    }
    if block.operations.len() > MAX_QRUN_V06_BLOCK_OPERATIONS {
        return Err(QRunV06ExecutionError::TooManyOperations(
            block.operations.len(),
        ));
    }

    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(&QRUN_V06_BLOCK_MAGIC);
    bytes.extend_from_slice(&QRUN_V06_BLOCK_VERSION.to_be_bytes());
    bytes.extend_from_slice(&block.network_id);
    bytes.extend_from_slice(&block.profile_id);
    bytes.extend_from_slice(&block.height.to_be_bytes());
    bytes.extend_from_slice(&block.timestamp.to_be_bytes());
    bytes.extend_from_slice(&block.parent_hash);
    bytes.extend_from_slice(&block.state_root);
    bytes.extend_from_slice(&block.producer);
    bytes.extend_from_slice(
        &u16::try_from(block.operations.len())
            .map_err(|_| QRunV06ExecutionError::Malformed)?
            .to_be_bytes(),
    );

    for operation in &block.operations {
        let (tag, payload) = encode_operation(operation)?;
        let length = u32::try_from(payload.len()).map_err(|_| QRunV06ExecutionError::Malformed)?;
        bytes.push(tag);
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(&payload);
        if bytes.len() > MAX_QRUN_V06_BLOCK_BYTES {
            return Err(QRunV06ExecutionError::Oversize {
                actual: bytes.len(),
                limit: MAX_QRUN_V06_BLOCK_BYTES,
            });
        }
    }
    if bytes.len() > MAX_QRUN_V06_BLOCK_BYTES {
        return Err(QRunV06ExecutionError::Oversize {
            actual: bytes.len(),
            limit: MAX_QRUN_V06_BLOCK_BYTES,
        });
    }
    Ok(bytes)
}

pub fn decode_qrun_v06_block(bytes: &[u8]) -> Result<QRunV06Block, QRunV06ExecutionError> {
    if bytes.len() > MAX_QRUN_V06_BLOCK_BYTES {
        return Err(QRunV06ExecutionError::Oversize {
            actual: bytes.len(),
            limit: MAX_QRUN_V06_BLOCK_BYTES,
        });
    }
    const HEADER_LEN: usize = 4 + 2 + 32 + 32 + 8 + 8 + 32 + 32 + 32 + 2;
    if bytes.len() < HEADER_LEN {
        return Err(QRunV06ExecutionError::Malformed);
    }
    let mut cursor = Cursor::new(bytes);
    if read_array::<4>(&mut cursor)? != QRUN_V06_BLOCK_MAGIC {
        return Err(QRunV06ExecutionError::BadMagic);
    }
    let version = read_u16(&mut cursor)?;
    if version != QRUN_V06_BLOCK_VERSION {
        return Err(QRunV06ExecutionError::UnsupportedVersion(version));
    }
    let network_id = read_array::<32>(&mut cursor)?;
    let profile_id = read_array::<32>(&mut cursor)?;
    let height = read_u64(&mut cursor)?;
    let timestamp = read_u64(&mut cursor)?;
    let parent_hash = read_array::<32>(&mut cursor)?;
    let state_root = read_array::<32>(&mut cursor)?;
    let producer = read_array::<32>(&mut cursor)?;
    let count = read_u16(&mut cursor)? as usize;
    if count > MAX_QRUN_V06_BLOCK_OPERATIONS {
        return Err(QRunV06ExecutionError::TooManyOperations(count));
    }
    let mut operations = Vec::with_capacity(count);
    for _ in 0..count {
        let tag = read_u8(&mut cursor)?;
        let length = read_u32(&mut cursor)? as usize;
        if length == 0 || length > MAX_QRUN_V06_BLOCK_BYTES {
            return Err(QRunV06ExecutionError::Malformed);
        }
        let mut payload = vec![0u8; length];
        cursor
            .read_exact(&mut payload)
            .map_err(|_| QRunV06ExecutionError::Malformed)?;
        operations.push(decode_operation(tag, &payload)?);
    }
    if cursor.position() as usize != bytes.len() {
        return Err(QRunV06ExecutionError::Malformed);
    }
    let block = QRunV06Block {
        network_id,
        profile_id,
        height,
        timestamp,
        parent_hash,
        state_root,
        producer,
        operations,
    };
    if encode_qrun_v06_block(&block)?.as_slice() != bytes {
        return Err(QRunV06ExecutionError::Malformed);
    }
    Ok(block)
}

pub fn qrun_v06_block_id(block: &QRunV06Block) -> Result<[u8; 32], QRunV06ExecutionError> {
    let canonical = encode_qrun_v06_block(block)?;
    Ok(qrun_v06_block_id_from_bytes(&canonical))
}

fn qrun_v06_block_id_from_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(BLOCK_ID_DOMAIN);
    hash.update(bytes);
    hash.finalize().into()
}

fn encode_operation(
    operation: &QRunV06BlockOperation,
) -> Result<(u8, Vec<u8>), QRunV06ExecutionError> {
    match operation {
        QRunV06BlockOperation::NativeTransfer(tx) => Ok((1, encode_transaction(tx)?)),
        QRunV06BlockOperation::Amm(operation) => Ok((2, operation.encode()?)),
        QRunV06BlockOperation::AssetRegistration(registration) => {
            Ok((3, encode_asset_registration(registration)?))
        }
        QRunV06BlockOperation::AssetAdmin(operation) => {
            Ok((4, encode_asset_admin_operation(operation)?))
        }
        QRunV06BlockOperation::OrderBook(operation) => Ok((5, operation.encode()?)),
        QRunV06BlockOperation::CategoryRelease(operation) => Ok((6, operation.encode()?)),
        QRunV06BlockOperation::ProtocolBurnReserveRetirement(operation) => {
            Ok((7, operation.encode()?))
        }
    }
}

fn decode_operation(
    tag: u8,
    payload: &[u8],
) -> Result<QRunV06BlockOperation, QRunV06ExecutionError> {
    match tag {
        1 => Ok(QRunV06BlockOperation::NativeTransfer(decode_transaction(
            payload,
        )?)),
        2 => Ok(QRunV06BlockOperation::Amm(AmmSignedOperation::decode(
            payload,
        )?)),
        3 => Ok(QRunV06BlockOperation::AssetRegistration(
            decode_asset_registration(payload)?,
        )),
        4 => Ok(QRunV06BlockOperation::AssetAdmin(
            decode_asset_admin_operation(payload)?,
        )),
        5 => Ok(QRunV06BlockOperation::OrderBook(
            QRunV06SignedOrderBookOperation::decode(payload)?,
        )),
        6 => Ok(QRunV06BlockOperation::CategoryRelease(
            QRunV06SignedCategoryRelease::decode(payload)?,
        )),
        7 => Ok(QRunV06BlockOperation::ProtocolBurnReserveRetirement(
            QRunV06SignedBurnReserveRetirement::decode(payload)?,
        )),
        _ => Err(QRunV06ExecutionError::Malformed),
    }
}

fn encode_asset_registration(value: &AssetRegistration) -> Result<Vec<u8>, QRunV06ExecutionError> {
    if value.signature.is_empty() || value.signature.len() > MAX_QRUN_V06_ASSET_SIGNATURE_BYTES {
        return Err(QRunV06ExecutionError::InvalidAssetRegistration);
    }
    value.signing_digest()?;
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(&value.network_id);
    out.extend_from_slice(&value.issuer);
    out.extend_from_slice(&value.issuer_nonce.to_be_bytes());
    out.extend_from_slice(&value.salt);
    put_string(&mut out, &value.name, MAX_NAME_BYTES)?;
    put_string(&mut out, &value.symbol, MAX_SYMBOL_BYTES)?;
    out.push(value.decimals);
    match &value.supply_policy {
        AssetSupplyPolicy::Fixed { total_supply } => {
            out.push(1);
            out.extend_from_slice(&total_supply.to_be_bytes());
        }
        AssetSupplyPolicy::IssuerCapped { max_supply } => {
            out.push(2);
            out.extend_from_slice(&max_supply.to_be_bytes());
        }
    }
    out.extend_from_slice(&value.initial_supply.to_be_bytes());
    out.extend_from_slice(&value.initial_recipient);
    encode_trust_policy(&mut out, &value.trust_policy);
    out.extend_from_slice(&value.expires_at.to_be_bytes());
    put_signature(&mut out, &value.signature)?;
    Ok(out)
}

fn decode_asset_registration(bytes: &[u8]) -> Result<AssetRegistration, QRunV06ExecutionError> {
    let mut cursor = Cursor::new(bytes);
    let network_id = read_array::<32>(&mut cursor)?;
    let issuer = read_array::<32>(&mut cursor)?;
    let issuer_nonce = read_u64(&mut cursor)?;
    let salt = read_array::<32>(&mut cursor)?;
    let name = read_string(&mut cursor, MAX_NAME_BYTES)?;
    let symbol = read_string(&mut cursor, MAX_SYMBOL_BYTES)?;
    let decimals = read_u8(&mut cursor)?;
    let supply_policy = match read_u8(&mut cursor)? {
        1 => AssetSupplyPolicy::Fixed {
            total_supply: read_u128(&mut cursor)?,
        },
        2 => AssetSupplyPolicy::IssuerCapped {
            max_supply: read_u128(&mut cursor)?,
        },
        _ => return Err(QRunV06ExecutionError::InvalidAssetRegistration),
    };
    let initial_supply = read_u128(&mut cursor)?;
    let initial_recipient = read_array::<32>(&mut cursor)?;
    let trust_policy = decode_trust_policy(&mut cursor)?;
    let expires_at = read_u64(&mut cursor)?;
    let signature = read_signature(&mut cursor)?;
    ensure_cursor_end(&cursor, bytes)?;
    let value = AssetRegistration {
        network_id,
        issuer,
        issuer_nonce,
        salt,
        name,
        symbol,
        decimals,
        supply_policy,
        initial_supply,
        initial_recipient,
        trust_policy,
        expires_at,
        signature,
    };
    value.signing_digest()?;
    if encode_asset_registration(&value)?.as_slice() != bytes {
        return Err(QRunV06ExecutionError::InvalidAssetRegistration);
    }
    Ok(value)
}

fn encode_asset_admin_operation(
    value: &SignedAssetAdminOperation,
) -> Result<Vec<u8>, QRunV06ExecutionError> {
    if value.signature.is_empty() || value.signature.len() > MAX_QRUN_V06_ASSET_SIGNATURE_BYTES {
        return Err(QRunV06ExecutionError::InvalidAssetAdminOperation);
    }
    value.signing_digest()?;
    let mut out = Vec::with_capacity(192);
    out.extend_from_slice(&value.network_id);
    out.extend_from_slice(&value.issuer);
    out.extend_from_slice(&value.issuer_nonce.to_be_bytes());
    out.extend_from_slice(&value.expires_at.to_be_bytes());
    match &value.action {
        AssetAdminAction::Mint {
            asset_id,
            recipient,
            amount,
        } => {
            out.push(1);
            out.extend_from_slice(asset_id);
            out.extend_from_slice(recipient);
            out.extend_from_slice(&amount.to_be_bytes());
        }
        AssetAdminAction::SetTransfersEnabled { asset_id, enabled } => {
            out.push(2);
            out.extend_from_slice(asset_id);
            out.push(u8::from(*enabled));
        }
    }
    put_signature(&mut out, &value.signature)?;
    Ok(out)
}

fn decode_asset_admin_operation(
    bytes: &[u8],
) -> Result<SignedAssetAdminOperation, QRunV06ExecutionError> {
    let mut cursor = Cursor::new(bytes);
    let network_id = read_array::<32>(&mut cursor)?;
    let issuer = read_array::<32>(&mut cursor)?;
    let issuer_nonce = read_u64(&mut cursor)?;
    let expires_at = read_u64(&mut cursor)?;
    let action = match read_u8(&mut cursor)? {
        1 => AssetAdminAction::Mint {
            asset_id: read_array::<32>(&mut cursor)?,
            recipient: read_array::<32>(&mut cursor)?,
            amount: read_u128(&mut cursor)?,
        },
        2 => {
            let asset_id = read_array::<32>(&mut cursor)?;
            let enabled = match read_u8(&mut cursor)? {
                0 => false,
                1 => true,
                _ => return Err(QRunV06ExecutionError::InvalidAssetAdminOperation),
            };
            AssetAdminAction::SetTransfersEnabled { asset_id, enabled }
        }
        _ => return Err(QRunV06ExecutionError::InvalidAssetAdminOperation),
    };
    let signature = read_signature(&mut cursor)?;
    ensure_cursor_end(&cursor, bytes)?;
    let value = SignedAssetAdminOperation {
        network_id,
        issuer,
        issuer_nonce,
        expires_at,
        action,
        signature,
    };
    value.signing_digest()?;
    if encode_asset_admin_operation(&value)?.as_slice() != bytes {
        return Err(QRunV06ExecutionError::InvalidAssetAdminOperation);
    }
    Ok(value)
}

fn encode_trust_policy(out: &mut Vec<u8>, policy: &AssetTrustPolicy) {
    match policy {
        AssetTrustPolicy::Unverified => out.push(0),
        AssetTrustPolicy::IssuerAttested { evidence_hash } => {
            out.push(1);
            out.extend_from_slice(evidence_hash);
        }
        AssetTrustPolicy::CustodianAttested {
            custodian,
            evidence_hash,
        } => {
            out.push(2);
            out.extend_from_slice(custodian);
            out.extend_from_slice(evidence_hash);
        }
        AssetTrustPolicy::BridgeAttested {
            bridge_id,
            evidence_hash,
        } => {
            out.push(3);
            out.extend_from_slice(bridge_id);
            out.extend_from_slice(evidence_hash);
        }
    }
}

fn decode_trust_policy(
    cursor: &mut Cursor<&[u8]>,
) -> Result<AssetTrustPolicy, QRunV06ExecutionError> {
    match read_u8(cursor)? {
        0 => Ok(AssetTrustPolicy::Unverified),
        1 => Ok(AssetTrustPolicy::IssuerAttested {
            evidence_hash: read_array::<32>(cursor)?,
        }),
        2 => Ok(AssetTrustPolicy::CustodianAttested {
            custodian: read_array::<32>(cursor)?,
            evidence_hash: read_array::<32>(cursor)?,
        }),
        3 => Ok(AssetTrustPolicy::BridgeAttested {
            bridge_id: read_array::<32>(cursor)?,
            evidence_hash: read_array::<32>(cursor)?,
        }),
        _ => Err(QRunV06ExecutionError::InvalidAssetRegistration),
    }
}

fn put_string(out: &mut Vec<u8>, value: &str, max: usize) -> Result<(), QRunV06ExecutionError> {
    if value.len() > max || value.len() > u16::MAX as usize {
        return Err(QRunV06ExecutionError::InvalidAssetRegistration);
    }
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn read_string(cursor: &mut Cursor<&[u8]>, max: usize) -> Result<String, QRunV06ExecutionError> {
    let len = read_u16(cursor)? as usize;
    if len == 0 || len > max {
        return Err(QRunV06ExecutionError::Malformed);
    }
    let mut bytes = vec![0u8; len];
    cursor
        .read_exact(&mut bytes)
        .map_err(|_| QRunV06ExecutionError::Malformed)?;
    String::from_utf8(bytes).map_err(|_| QRunV06ExecutionError::Malformed)
}

fn put_signature(out: &mut Vec<u8>, signature: &[u8]) -> Result<(), QRunV06ExecutionError> {
    if signature.is_empty()
        || signature.len() > MAX_QRUN_V06_ASSET_SIGNATURE_BYTES
        || signature.len() > u16::MAX as usize
    {
        return Err(QRunV06ExecutionError::InvalidSignature);
    }
    out.extend_from_slice(&(signature.len() as u16).to_be_bytes());
    out.extend_from_slice(signature);
    Ok(())
}

fn read_signature(cursor: &mut Cursor<&[u8]>) -> Result<Vec<u8>, QRunV06ExecutionError> {
    let len = read_u16(cursor)? as usize;
    if len == 0 || len > MAX_QRUN_V06_ASSET_SIGNATURE_BYTES {
        return Err(QRunV06ExecutionError::InvalidSignature);
    }
    let mut signature = vec![0u8; len];
    cursor
        .read_exact(&mut signature)
        .map_err(|_| QRunV06ExecutionError::Malformed)?;
    Ok(signature)
}

fn ensure_cursor_end(cursor: &Cursor<&[u8]>, bytes: &[u8]) -> Result<(), QRunV06ExecutionError> {
    if cursor.position() as usize != bytes.len() {
        return Err(QRunV06ExecutionError::Malformed);
    }
    Ok(())
}

fn read_array<const N: usize>(
    cursor: &mut Cursor<&[u8]>,
) -> Result<[u8; N], QRunV06ExecutionError> {
    let mut value = [0u8; N];
    cursor
        .read_exact(&mut value)
        .map_err(|_| QRunV06ExecutionError::Malformed)?;
    Ok(value)
}
fn read_u8(cursor: &mut Cursor<&[u8]>) -> Result<u8, QRunV06ExecutionError> {
    Ok(read_array::<1>(cursor)?[0])
}
fn read_u16(cursor: &mut Cursor<&[u8]>) -> Result<u16, QRunV06ExecutionError> {
    Ok(u16::from_be_bytes(read_array(cursor)?))
}
fn read_u32(cursor: &mut Cursor<&[u8]>) -> Result<u32, QRunV06ExecutionError> {
    Ok(u32::from_be_bytes(read_array(cursor)?))
}
fn read_u64(cursor: &mut Cursor<&[u8]>) -> Result<u64, QRunV06ExecutionError> {
    Ok(u64::from_be_bytes(read_array(cursor)?))
}
fn read_u128(cursor: &mut Cursor<&[u8]>) -> Result<u128, QRunV06ExecutionError> {
    Ok(u128::from_be_bytes(read_array(cursor)?))
}
fn zero(value: &[u8; 32]) -> bool {
    value.iter().all(|byte| *byte == 0)
}

fn execution_snapshot_put_component(
    out: &mut Vec<u8>,
    component: &[u8],
) -> Result<(), QRunV06ExecutionError> {
    let length =
        u32::try_from(component.len()).map_err(|_| QRunV06ExecutionError::SnapshotOversize)?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(component);
    if out.len().saturating_add(32) > MAX_QRUN_V06_EXECUTION_SNAPSHOT_BYTES {
        return Err(QRunV06ExecutionError::SnapshotOversize);
    }
    Ok(())
}

fn execution_snapshot_read<const N: usize>(
    cursor: &mut Cursor<&[u8]>,
) -> Result<[u8; N], QRunV06ExecutionError> {
    let mut value = [0u8; N];
    cursor
        .read_exact(&mut value)
        .map_err(|_| QRunV06ExecutionError::SnapshotMalformed)?;
    Ok(value)
}

fn execution_snapshot_u16(cursor: &mut Cursor<&[u8]>) -> Result<u16, QRunV06ExecutionError> {
    Ok(u16::from_be_bytes(execution_snapshot_read(cursor)?))
}

fn execution_snapshot_u32(cursor: &mut Cursor<&[u8]>) -> Result<u32, QRunV06ExecutionError> {
    Ok(u32::from_be_bytes(execution_snapshot_read(cursor)?))
}

fn execution_snapshot_u64(cursor: &mut Cursor<&[u8]>) -> Result<u64, QRunV06ExecutionError> {
    Ok(u64::from_be_bytes(execution_snapshot_read(cursor)?))
}

fn execution_snapshot_read_component(
    cursor: &mut Cursor<&[u8]>,
    max_bytes: usize,
) -> Result<Vec<u8>, QRunV06ExecutionError> {
    let length = execution_snapshot_u32(cursor)? as usize;
    if length == 0 || length > max_bytes {
        return Err(QRunV06ExecutionError::SnapshotMalformed);
    }
    let mut component = vec![0u8; length];
    cursor
        .read_exact(&mut component)
        .map_err(|_| QRunV06ExecutionError::SnapshotMalformed)?;
    Ok(component)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qrun_v06_asset_registry_candidate::{AssetAdminAction, AssetSupplyPolicy};
    use crate::qrun_v06_orderbook_candidate::{QRunV06OrderBookOperation as OrderOp, Side, Tif};
    use crate::qzxb_amm_candidate::{qzxb_native_asset_id, AmmOperation, QzxbAmmStateCandidate};
    use crate::state_machine::{transaction_signing_digest, AccountId, LedgerState};
    use crate::transaction_auth::{
        AccountPublicKey, Ed25519TransactionAuthenticator, Ed25519TransactionSigner,
        TransactionAuthenticatorKind,
    };

    const NETWORK: [u8; 32] = [0xC6; 32];
    const PROFILE: [u8; 32] = [0xC7; 32];
    const ALICE: [u8; 32] = [0xC8; 32];
    const BOB: [u8; 32] = [0xC9; 32];
    const PRODUCER: [u8; 32] = [0xCA; 32];

    struct DigestAuthenticator;
    impl TransactionAuthenticator for DigestAuthenticator {
        fn verify(
            &self,
            sender: &AccountId,
            digest: &[u8; 32],
            signature: &[u8],
        ) -> Result<(), ()> {
            if !zero(sender) && signature == digest {
                Ok(())
            } else {
                Err(())
            }
        }
    }

    fn fixture() -> QRunV06CanonicalExecutionState {
        let ledger = LedgerState::genesis(NETWORK, vec![(ALICE, 20_000), (BOB, 1_000)]).unwrap();
        let amm = QzxbAmmStateCandidate::new(NETWORK, 32, 64, 512).unwrap();
        let unified = QRunV06UnifiedAssetState::new(ledger, amm).unwrap();
        QRunV06CanonicalExecutionState::new(unified, PROFILE).unwrap()
    }

    fn transfer(
        sender: [u8; 32],
        recipient: [u8; 32],
        nonce: u64,
        amount: u64,
        fee: u64,
    ) -> Transaction {
        let mut tx = Transaction {
            network_id: NETWORK,
            sender,
            recipient,
            nonce,
            amount,
            fee,
            expires_at: 10_000,
            signature: Vec::new(),
        };
        tx.signature = transaction_signing_digest(&tx).unwrap().to_vec();
        tx
    }

    fn signed_orderbook(
        sender: [u8; 32],
        nonce: u64,
        operation: OrderOp,
    ) -> QRunV06SignedOrderBookOperation {
        let mut signed = QRunV06SignedOrderBookOperation {
            network_id: NETWORK,
            sender,
            nonce,
            expires_at: 10_000,
            operation,
            signature: Vec::new(),
        };
        signed.signature = signed.signing_digest().unwrap().to_vec();
        signed
    }

    fn signed_burn_reserve_retirement(
        expected_burned_atoms: u128,
        amount_atoms: u128,
        valid_until_timestamp: u64,
    ) -> QRunV06SignedBurnReserveRetirement {
        let policy_fingerprint = QRunV06TokenomicsState::genesis(
            NETWORK,
            ALICE,
            QRunV06MiningScheduleCandidate::cp0422_research_candidate(),
        )
        .unwrap()
        .policy_fingerprint();
        let mut retirement = QRunV06SignedBurnReserveRetirement {
            network_id: NETWORK,
            policy_fingerprint,
            expected_burned_atoms,
            amount_atoms,
            valid_until_timestamp,
            purpose_digest: [0xD4; 32],
            evidence_digest: [0xD5; 32],
            founder_signature: Vec::new(),
        };
        retirement.founder_signature = retirement.signing_digest().unwrap().to_vec();
        retirement
    }

    fn signed_category_release(
        bucket: crate::qrun_v06_tokenomics_candidate::QRunV06AllocationBucket,
        nonce: u64,
        recipient: [u8; 32],
        amount_atoms: u128,
        valid_until_timestamp: u64,
    ) -> QRunV06SignedCategoryRelease {
        let mut release = QRunV06SignedCategoryRelease {
            network_id: NETWORK,
            bucket,
            nonce,
            recipient,
            amount_atoms,
            valid_until_timestamp,
            purpose_digest: [0xD1; 32],
            evidence_digest: [0xD2; 32],
            milestone_policy_digest: [0xD3; 32],
            founder_signature: Vec::new(),
            recipient_acceptance_signature: Vec::new(),
        };
        release.founder_signature = release.signing_digest().unwrap().to_vec();
        release.recipient_acceptance_signature =
            release.recipient_acceptance_digest().unwrap().to_vec();
        release
    }

    fn cp0528_state(founder: [u8; 32]) -> QRunV06CanonicalExecutionState {
        QRunV06CanonicalExecutionState::cp0528_genesis_candidate(
            NETWORK,
            PROFILE,
            founder,
            QRunV06MiningScheduleCandidate::cp0422_research_candidate(),
        )
        .unwrap()
    }

    fn block_for(
        state: &QRunV06CanonicalExecutionState,
        operations: Vec<QRunV06BlockOperation>,
    ) -> QRunV06Block {
        QRunV06Block {
            network_id: NETWORK,
            profile_id: PROFILE,
            height: state.height() + 1,
            timestamp: state.last_timestamp() + 100,
            parent_hash: state.tip_hash(),
            state_root: [0; 32],
            producer: PRODUCER,
            operations,
        }
    }

    #[test]
    fn qfb6_v5_roundtrips_signed_category_release_canonically() {
        let state = cp0528_state(ALICE);
        let release = signed_category_release(
            crate::qrun_v06_tokenomics_candidate::QRunV06AllocationBucket::CommunityAirdrop,
            1,
            BOB,
            50_000,
            10_000,
        );
        let block = block_for(
            &state,
            vec![QRunV06BlockOperation::CategoryRelease(release)],
        );
        let encoded = encode_qrun_v06_block(&block).unwrap();
        let decoded = decode_qrun_v06_block(&encoded).unwrap();
        assert_eq!(decoded, block);
        assert_eq!(encoded[4..6], QRUN_V06_BLOCK_VERSION.to_be_bytes());
        assert_eq!(QRUN_V06_BLOCK_VERSION, 5);
    }

    #[test]
    fn qfb6_v5_roundtrips_and_executes_signed_burn_reserve_retirement_atomically() {
        let mut state = cp0528_state(ALICE);
        let retirement = signed_burn_reserve_retirement(0, 123_456, 10_000);
        let sink =
            protocol_burn_sink_account(NETWORK, state.tokenomics().unwrap().policy_fingerprint());
        let ledger_before = state.unified().ledger().total_value().unwrap();
        let founder_before = state.unified().ledger().account(&ALICE).unwrap().balance;

        let mut block = block_for(
            &state,
            vec![QRunV06BlockOperation::ProtocolBurnReserveRetirement(
                retirement.clone(),
            )],
        );
        let encoded = encode_qrun_v06_block(&block).unwrap();
        assert_eq!(u16::from_be_bytes([encoded[4], encoded[5]]), 5);
        assert_eq!(decode_qrun_v06_block(&encoded).unwrap(), block);
        block.state_root = state
            .preview_state_root_after(&block, &DigestAuthenticator)
            .unwrap();
        let summary = state.apply_block(&block, &DigestAuthenticator).unwrap();

        let tokenomics = state.tokenomics().unwrap();
        assert_eq!(summary.protocol_burns, 1);
        assert_eq!(
            tokenomics.issued_by_bucket_atoms(QRunV06AllocationBucket::ProtocolBurnReserve),
            123_456
        );
        assert_eq!(tokenomics.burned_atoms(), 123_456);
        assert_eq!(
            tokenomics.live_supply_atoms().unwrap(),
            QRUN_V06_FOUNDER_GENESIS_ATOMS + summary.mining_reward_atoms
        );
        assert_eq!(
            tokenomics
                .unissued_by_bucket_atoms(QRunV06AllocationBucket::ProtocolBurnReserve)
                .unwrap(),
            QRunV06AllocationBucket::ProtocolBurnReserve.budget_atoms() - 123_456
        );
        assert_eq!(
            state.unified().ledger().total_value().unwrap(),
            ledger_before + summary.mining_reward_atoms
        );
        assert_eq!(
            state.unified().ledger().account(&ALICE).unwrap().balance,
            founder_before
        );
        assert!(state.unified().ledger().account(&sink).is_none());

        let before_replay = state.clone();
        let replay = block_for(
            &state,
            vec![QRunV06BlockOperation::ProtocolBurnReserveRetirement(
                retirement,
            )],
        );
        assert_eq!(
            state.preview_state_root_after(&replay, &DigestAuthenticator),
            Err(QRunV06ExecutionError::Tokenomics(
                QRunV06TokenomicsError::BurnCounterMismatch {
                    expected: 123_456,
                    actual: 0,
                }
            ))
        );
        assert_eq!(state, before_replay);
    }

    #[test]
    fn protocol_burn_sink_cannot_receive_block_mining_reward() {
        let state = cp0528_state(ALICE);
        let retirement = signed_burn_reserve_retirement(0, 77_000, 10_000);
        let sink =
            protocol_burn_sink_account(NETWORK, state.tokenomics().unwrap().policy_fingerprint());
        let mut block = block_for(
            &state,
            vec![QRunV06BlockOperation::ProtocolBurnReserveRetirement(
                retirement,
            )],
        );
        block.producer = sink;

        assert_eq!(
            state.preview_state_root_after(&block, &DigestAuthenticator),
            Err(QRunV06ExecutionError::ProtocolBurnSinkNotEmpty)
        );
        assert_eq!(state.tokenomics().unwrap().burned_atoms(), 0);
        assert!(state.unified().ledger().account(&sink).is_none());
    }

    #[test]
    fn burn_reserve_retirement_verifies_real_ed25519_founder_signature_and_fails_closed() {
        let founder = Ed25519TransactionSigner::from_seed([0xE6; 32]);
        let mut state = cp0528_state(founder.account_id());
        let policy_fingerprint = state.tokenomics().unwrap().policy_fingerprint();
        let mut retirement = QRunV06SignedBurnReserveRetirement {
            network_id: NETWORK,
            policy_fingerprint,
            expected_burned_atoms: 0,
            amount_atoms: 77_000,
            valid_until_timestamp: 10_000,
            purpose_digest: [0xE7; 32],
            evidence_digest: [0xE8; 32],
            founder_signature: Vec::new(),
        };
        retirement.founder_signature = founder.sign_digest(&retirement.signing_digest().unwrap());
        let authenticator = Ed25519TransactionAuthenticator::select(
            TransactionAuthenticatorKind::Ed25519V1,
            [AccountPublicKey {
                account_id: founder.account_id(),
                public_key: founder.public_key(),
            }],
        )
        .unwrap();

        let mut block = block_for(
            &state,
            vec![QRunV06BlockOperation::ProtocolBurnReserveRetirement(
                retirement.clone(),
            )],
        );
        block.state_root = state
            .preview_state_root_after(&block, &authenticator)
            .unwrap();
        let summary = state.apply_block(&block, &authenticator).unwrap();
        assert_eq!(state.tokenomics().unwrap().burned_atoms(), 77_000);
        assert_eq!(
            state.tokenomics().unwrap().live_supply_atoms().unwrap(),
            QRUN_V06_FOUNDER_GENESIS_ATOMS + summary.mining_reward_atoms
        );

        let before = state.clone();
        let mut wrong_signature = retirement;
        wrong_signature.founder_signature[0] ^= 0x80;
        let bad = block_for(
            &state,
            vec![QRunV06BlockOperation::ProtocolBurnReserveRetirement(
                wrong_signature,
            )],
        );
        assert_eq!(
            state.preview_state_root_after(&bad, &authenticator),
            Err(QRunV06ExecutionError::InvalidProtocolBurn)
        );
        assert_eq!(state, before);
    }

    #[test]
    fn burn_reserve_retirement_rejects_expiry_wrong_policy_and_over_cap_atomically() {
        let state = cp0528_state(ALICE);
        let before = state.clone();

        let expired = signed_burn_reserve_retirement(0, 100, 99);
        let expired_block = block_for(
            &state,
            vec![QRunV06BlockOperation::ProtocolBurnReserveRetirement(
                expired,
            )],
        );
        assert_eq!(
            state.preview_state_root_after(&expired_block, &DigestAuthenticator),
            Err(QRunV06ExecutionError::InvalidProtocolBurn)
        );

        let mut wrong_policy = signed_burn_reserve_retirement(0, 100, 10_000);
        wrong_policy.policy_fingerprint[0] ^= 1;
        wrong_policy.founder_signature = wrong_policy.signing_digest().unwrap().to_vec();
        let wrong_policy_block = block_for(
            &state,
            vec![QRunV06BlockOperation::ProtocolBurnReserveRetirement(
                wrong_policy,
            )],
        );
        assert_eq!(
            state.preview_state_root_after(&wrong_policy_block, &DigestAuthenticator),
            Err(QRunV06ExecutionError::InvalidProtocolBurn)
        );

        let over_cap = signed_burn_reserve_retirement(
            0,
            QRunV06AllocationBucket::ProtocolBurnReserve.budget_atoms() + 1,
            10_000,
        );
        let over_cap_block = block_for(
            &state,
            vec![QRunV06BlockOperation::ProtocolBurnReserveRetirement(
                over_cap,
            )],
        );
        assert_eq!(
            state.preview_state_root_after(&over_cap_block, &DigestAuthenticator),
            Err(QRunV06ExecutionError::InvalidProtocolBurn)
        );
        assert_eq!(state, before);
    }

    #[test]
    fn category_release_verifies_real_ed25519_founder_and_recipient_signatures() {
        use crate::qrun_v06_tokenomics_candidate::QRunV06AllocationBucket;

        let founder = Ed25519TransactionSigner::from_seed([0xE1; 32]);
        let recipient = Ed25519TransactionSigner::from_seed([0xE2; 32]);
        let mut state = QRunV06CanonicalExecutionState::cp0528_genesis_candidate(
            NETWORK,
            PROFILE,
            founder.account_id(),
            QRunV06MiningScheduleCandidate::cp0422_research_candidate(),
        )
        .unwrap();
        let mut release = QRunV06SignedCategoryRelease {
            network_id: NETWORK,
            bucket: QRunV06AllocationBucket::DeveloperSecurityContributors,
            nonce: 1,
            recipient: recipient.account_id(),
            amount_atoms: 77_000,
            valid_until_timestamp: 10_000,
            purpose_digest: [0xE3; 32],
            evidence_digest: [0xE4; 32],
            milestone_policy_digest: [0xE5; 32],
            founder_signature: Vec::new(),
            recipient_acceptance_signature: Vec::new(),
        };
        release.founder_signature = founder.sign_digest(&release.signing_digest().unwrap());
        release.recipient_acceptance_signature =
            recipient.sign_digest(&release.recipient_acceptance_digest().unwrap());

        let authenticator = Ed25519TransactionAuthenticator::select(
            TransactionAuthenticatorKind::Ed25519V1,
            [
                AccountPublicKey {
                    account_id: founder.account_id(),
                    public_key: founder.public_key(),
                },
                AccountPublicKey {
                    account_id: recipient.account_id(),
                    public_key: recipient.public_key(),
                },
            ],
        )
        .unwrap();
        let mut block = block_for(
            &state,
            vec![QRunV06BlockOperation::CategoryRelease(release)],
        );
        block.state_root = state
            .preview_state_root_after(&block, &authenticator)
            .unwrap();
        state.apply_block(&block, &authenticator).unwrap();
        assert_eq!(
            state
                .unified()
                .ledger()
                .account(&recipient.account_id())
                .unwrap()
                .balance,
            77_000
        );
        assert_eq!(state.tokenomics().unwrap().founder_release_nonce(), 1);
    }

    #[test]
    fn founder_release_is_dual_signed_capped_nonce_bound_and_atomic() {
        use crate::qrun_v06_tokenomics_candidate::QRunV06AllocationBucket;

        let mut state = cp0528_state(ALICE);
        let release = signed_category_release(
            QRunV06AllocationBucket::CommunityAirdrop,
            1,
            BOB,
            50_000,
            10_000,
        );
        let mut block = block_for(
            &state,
            vec![QRunV06BlockOperation::CategoryRelease(release.clone())],
        );
        block.state_root = state
            .preview_state_root_after(&block, &DigestAuthenticator)
            .unwrap();
        let summary = state.apply_block(&block, &DigestAuthenticator).unwrap();
        assert_eq!(summary.category_releases, 1);
        assert_eq!(
            state.unified().ledger().account(&BOB).unwrap().balance,
            50_000
        );
        let tokenomics = state.tokenomics().unwrap();
        assert_eq!(tokenomics.founder_release_nonce(), 1);
        assert_eq!(
            tokenomics.issued_by_bucket_atoms(QRunV06AllocationBucket::CommunityAirdrop),
            50_000
        );
        assert_eq!(
            tokenomics.last_release_id(),
            release.signing_digest().unwrap()
        );
        assert_eq!(
            tokenomics.live_supply_atoms().unwrap(),
            state.unified().ledger().total_value().unwrap()
        );

        // Replaying the same authorization is rejected by the monotonic nonce.
        let before = state.clone();
        let replay = block_for(
            &state,
            vec![QRunV06BlockOperation::CategoryRelease(release)],
        );
        assert!(matches!(
            state.preview_state_root_after(&replay, &DigestAuthenticator),
            Err(QRunV06ExecutionError::Tokenomics(
                QRunV06TokenomicsError::InvalidReleaseNonce {
                    expected: 2,
                    actual: 1
                }
            ))
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn category_release_rejects_wrong_signer_expiry_founder_and_over_cap_without_mutation() {
        use crate::qrun_v06_tokenomics_candidate::QRunV06AllocationBucket;

        let state = cp0528_state(ALICE);
        let before = state.clone();

        let mut wrong_founder = signed_category_release(
            QRunV06AllocationBucket::DeveloperSecurityContributors,
            1,
            BOB,
            10_000,
            10_000,
        );
        wrong_founder.founder_signature[0] ^= 0x80;
        let bad_founder_block = block_for(
            &state,
            vec![QRunV06BlockOperation::CategoryRelease(wrong_founder)],
        );
        assert_eq!(
            state.preview_state_root_after(&bad_founder_block, &DigestAuthenticator),
            Err(QRunV06ExecutionError::InvalidCategoryRelease)
        );
        assert_eq!(state, before);

        let mut wrong_recipient = signed_category_release(
            QRunV06AllocationBucket::DeveloperSecurityContributors,
            1,
            BOB,
            10_000,
            10_000,
        );
        wrong_recipient.recipient_acceptance_signature[0] ^= 0x80;
        let bad_recipient_block = block_for(
            &state,
            vec![QRunV06BlockOperation::CategoryRelease(wrong_recipient)],
        );
        assert_eq!(
            state.preview_state_root_after(&bad_recipient_block, &DigestAuthenticator),
            Err(QRunV06ExecutionError::InvalidCategoryRelease)
        );
        assert_eq!(state, before);

        let expired = signed_category_release(
            QRunV06AllocationBucket::DeveloperSecurityContributors,
            1,
            BOB,
            10_000,
            99,
        );
        let expired_block = block_for(
            &state,
            vec![QRunV06BlockOperation::CategoryRelease(expired)],
        );
        assert_eq!(
            state.preview_state_root_after(&expired_block, &DigestAuthenticator),
            Err(QRunV06ExecutionError::InvalidCategoryRelease)
        );
        assert_eq!(state, before);

        let owner_recipient = signed_category_release(
            QRunV06AllocationBucket::DeveloperSecurityContributors,
            1,
            ALICE,
            10_000,
            10_000,
        );
        let owner_block = block_for(
            &state,
            vec![QRunV06BlockOperation::CategoryRelease(owner_recipient)],
        );
        assert_eq!(
            state.preview_state_root_after(&owner_block, &DigestAuthenticator),
            Err(QRunV06ExecutionError::InvalidCategoryRelease)
        );
        assert_eq!(state, before);

        let over_cap = signed_category_release(
            QRunV06AllocationBucket::DeveloperSecurityContributors,
            1,
            BOB,
            1_000_000_000u128 * 100_000_000 + 1,
            10_000,
        );
        let over_cap_block = block_for(
            &state,
            vec![QRunV06BlockOperation::CategoryRelease(over_cap)],
        );
        assert!(matches!(
            state.preview_state_root_after(&over_cap_block, &DigestAuthenticator),
            Err(QRunV06ExecutionError::Tokenomics(
                QRunV06TokenomicsError::BucketBudgetExceeded(
                    QRunV06AllocationBucket::DeveloperSecurityContributors
                )
            ))
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn category_release_requires_cp0528_policy_and_forbids_mining_or_burn_envelopes() {
        use crate::qrun_v06_tokenomics_candidate::QRunV06AllocationBucket;

        let state = cp0528_state(ALICE);
        assert!(state.tokenomics().is_some());
        for bucket in [
            QRunV06AllocationBucket::MiningNetworkSecurity,
            QRunV06AllocationBucket::ProtocolBurnReserve,
            QRunV06AllocationBucket::FounderAllocation,
        ] {
            let invalid = QRunV06SignedCategoryRelease {
                network_id: NETWORK,
                bucket,
                nonce: 1,
                recipient: BOB,
                amount_atoms: 1,
                valid_until_timestamp: 10_000,
                purpose_digest: [0xD1; 32],
                evidence_digest: [0xD2; 32],
                milestone_policy_digest: [0xD3; 32],
                founder_signature: vec![1; 64],
                recipient_acceptance_signature: vec![2; 64],
            };
            assert!(matches!(
                invalid.encode(),
                Err(QRunV06TokenomicsError::InvalidCategoryRelease)
            ));
        }

        let market_only = fixture();
        let release =
            signed_category_release(QRunV06AllocationBucket::CommunityAirdrop, 1, BOB, 1, 10_000);
        let block = block_for(
            &market_only,
            vec![QRunV06BlockOperation::CategoryRelease(release)],
        );
        assert_eq!(
            market_only.preview_state_root_after(&block, &DigestAuthenticator),
            Err(QRunV06ExecutionError::TokenomicsGenesisRequiresEmptyLedger)
        );
    }

    #[test]
    fn qfb6_v5_roundtrips_each_operation_family_canonically() {
        let signer = Ed25519TransactionSigner::from_seed([0x55; 32]);
        let issuer = signer.account_id();
        let mut registration = AssetRegistration {
            network_id: NETWORK,
            issuer,
            issuer_nonce: 1,
            salt: [0x56; 32],
            name: "Canonical Test Asset".to_string(),
            symbol: "CTA".to_string(),
            decimals: 8,
            supply_policy: AssetSupplyPolicy::IssuerCapped { max_supply: 10_000 },
            initial_supply: 100,
            initial_recipient: issuer,
            trust_policy: AssetTrustPolicy::IssuerAttested {
                evidence_hash: [0x57; 32],
            },
            expires_at: 50_000,
            signature: Vec::new(),
        };
        let digest = registration.signing_digest().unwrap();
        registration.signature = signer.sign_digest(&digest);

        let mut admin = SignedAssetAdminOperation {
            network_id: NETWORK,
            issuer,
            issuer_nonce: 2,
            expires_at: 50_000,
            action: AssetAdminAction::SetTransfersEnabled {
                asset_id: registration.asset_id(),
                enabled: false,
            },
            signature: Vec::new(),
        };
        let digest = admin.signing_digest().unwrap();
        admin.signature = signer.sign_digest(&digest);

        let mut amm = AmmSignedOperation {
            network_id: NETWORK,
            sender: issuer,
            nonce: 1,
            expires_at: 50_000,
            operation: AmmOperation::RegisterAsset {
                asset_id: [0x58; 32],
            },
            signature: Vec::new(),
        };
        amm.signature = signer.sign_digest(&amm.signing_digest().unwrap());

        let native = transfer(issuer, BOB, 1, 7, 1);
        let orderbook = signed_orderbook(
            issuer,
            2,
            OrderOp::CreatePair {
                base: [0x5A; 32],
                quote: [0x5B; 32],
                base_lot_atoms: 1,
                quote_tick_atoms: 1,
                max_price_ticks: 1_000,
                max_quantity_lots: 1_000,
                min_notional: 1,
                maker_fee_bps: 10,
                taker_fee_bps: 20,
                fee_collector: PRODUCER,
            },
        );
        let block = QRunV06Block {
            network_id: NETWORK,
            profile_id: PROFILE,
            height: 1,
            timestamp: 100,
            parent_hash: [0; 32],
            state_root: [0x59; 32],
            producer: PRODUCER,
            operations: vec![
                QRunV06BlockOperation::NativeTransfer(native),
                QRunV06BlockOperation::Amm(amm),
                QRunV06BlockOperation::AssetRegistration(registration),
                QRunV06BlockOperation::AssetAdmin(admin),
                QRunV06BlockOperation::OrderBook(orderbook),
            ],
        };
        let encoded = encode_qrun_v06_block(&block).unwrap();
        let decoded = decode_qrun_v06_block(&encoded).unwrap();
        assert_eq!(decoded, block);
        assert_eq!(encode_qrun_v06_block(&decoded).unwrap(), encoded);
        assert_eq!(
            qrun_v06_block_id(&block).unwrap(),
            qrun_v06_block_id(&decoded).unwrap()
        );
    }

    #[test]
    fn block_execution_commits_native_transfer_and_pays_only_this_blocks_fees() {
        let mut state = fixture();
        let tx = transfer(ALICE, BOB, 1, 100, 5);
        let mut block = block_for(&state, vec![QRunV06BlockOperation::NativeTransfer(tx)]);
        block.state_root = state
            .preview_state_root_after(&block, &DigestAuthenticator)
            .unwrap();

        let summary = state.apply_block(&block, &DigestAuthenticator).unwrap();
        assert_eq!(summary.height, 1);
        assert_eq!(summary.native_transfers, 1);
        assert_eq!(summary.fees_paid_to_producer, 5);
        assert_eq!(
            state.unified().ledger().account(&ALICE).unwrap().balance,
            19_895
        );
        assert_eq!(
            state.unified().ledger().account(&BOB).unwrap().balance,
            1_100
        );
        assert_eq!(
            state.unified().ledger().account(&PRODUCER).unwrap().balance,
            5
        );
        assert_eq!(state.unified().ledger().fee_pool(), 0);
        assert_eq!(state.height(), 1);
        assert_eq!(state.tip_hash(), summary.block_id);
    }

    #[test]
    fn qfb6_amm_quote_decimal_mismatch_rejects_same_block_registration_atomically() {
        let mut state = fixture();
        let original_root = state.state_root().unwrap();

        let mut registration = AssetRegistration {
            network_id: NETWORK,
            issuer: ALICE,
            issuer_nonce: 1,
            salt: [0x6A; 32],
            name: "Decimal Mismatch Quote".to_string(),
            symbol: "DMQ".to_string(),
            decimals: 6,
            supply_policy: AssetSupplyPolicy::Fixed {
                total_supply: 50_000,
            },
            initial_supply: 50_000,
            initial_recipient: ALICE,
            trust_policy: AssetTrustPolicy::Unverified,
            expires_at: 50_000,
            signature: Vec::new(),
        };
        registration.signature = registration.signing_digest().unwrap().to_vec();
        let asset_id = registration.asset_id();
        let native = qzxb_native_asset_id(NETWORK).unwrap();
        let pair_id = QzxbAmmStateCandidate::pair_id_for_assets(native, asset_id).unwrap();

        let create_pair = {
            let mut operation = AmmSignedOperation {
                network_id: NETWORK,
                sender: ALICE,
                nonce: 1,
                expires_at: 50_000,
                operation: AmmOperation::CreatePair {
                    token_a: native,
                    token_b: asset_id,
                },
                signature: Vec::new(),
            };
            operation.signature = operation.signing_digest().unwrap().to_vec();
            operation
        };
        let block = block_for(
            &state,
            vec![
                QRunV06BlockOperation::AssetRegistration(registration),
                QRunV06BlockOperation::Amm(create_pair),
            ],
        );
        let authorization =
            crate::qrun_v06_profile_trust_candidate::test_trust_authorized_quote_asset_candidate_with_decimals(
                NETWORK, PROFILE, asset_id, [0xDA; 32], [0xDB; 32], 3, 1, 10, 1, 1, 18,
            );
        let expected_error = QRunV06ExecutionError::QuoteAssetDecimalsMismatch {
            asset_id,
            q6qa_decimals: 18,
            registry_decimals: 6,
        };

        assert_eq!(
            state.preview_state_root_after_with_quote_asset_authorization(
                &block,
                &DigestAuthenticator,
                Some(&authorization),
            ),
            Err(expected_error.clone())
        );
        assert_eq!(
            state.apply_block_with_quote_asset_authorization(
                &block,
                &DigestAuthenticator,
                Some(&authorization),
            ),
            Err(expected_error)
        );
        assert_eq!(state.state_root().unwrap(), original_root);
        assert!(state.unified().registry().asset(&asset_id).is_none());
        assert_eq!(state.unified().registry().issuer_nonce(&ALICE), 0);
        assert!(state.unified().amm().pair_assets(&pair_id).is_err());
    }

    #[test]
    fn block_can_register_asset_then_create_amm_pair_in_canonical_order() {
        let mut state = fixture();
        // The test authenticator is deliberately digest-shaped; production uses the
        // configured Ed25519/ML-DSA verifier and external key custody.
        let mut registration = AssetRegistration {
            network_id: NETWORK,
            issuer: ALICE,
            issuer_nonce: 1,
            salt: [0x63; 32],
            name: "QRun Quote Candidate".to_string(),
            symbol: "QQC".to_string(),
            decimals: 8,
            supply_policy: AssetSupplyPolicy::Fixed {
                total_supply: 50_000,
            },
            initial_supply: 50_000,
            initial_recipient: ALICE,
            trust_policy: AssetTrustPolicy::Unverified,
            expires_at: 50_000,
            signature: Vec::new(),
        };
        registration.signature = registration.signing_digest().unwrap().to_vec();
        let asset_id = registration.asset_id();
        let native = qzxb_native_asset_id(NETWORK).unwrap();
        let pair_id = QzxbAmmStateCandidate::pair_id_for_assets(native, asset_id).unwrap();
        let create_pair = {
            let mut operation = AmmSignedOperation {
                network_id: NETWORK,
                sender: ALICE,
                nonce: 1,
                expires_at: 50_000,
                operation: AmmOperation::CreatePair {
                    token_a: native,
                    token_b: asset_id,
                },
                signature: Vec::new(),
            };
            operation.signature = operation.signing_digest().unwrap().to_vec();
            operation
        };
        let add_liquidity = {
            let mut operation = AmmSignedOperation {
                network_id: NETWORK,
                sender: ALICE,
                nonce: 2,
                expires_at: 50_000,
                operation: AmmOperation::AddLiquidity {
                    pair_id,
                    amount0_desired: 100,
                    amount1_desired: 100,
                    min_lp_shares: 1,
                },
                signature: Vec::new(),
            };
            operation.signature = operation.signing_digest().unwrap().to_vec();
            operation
        };

        let mut block = block_for(
            &state,
            vec![
                QRunV06BlockOperation::AssetRegistration(registration),
                QRunV06BlockOperation::Amm(create_pair),
                QRunV06BlockOperation::Amm(add_liquidity),
            ],
        );
        let quote_authorization =
            crate::qrun_v06_profile_trust_candidate::test_trust_authorized_quote_asset_candidate_with_decimals(
                NETWORK, PROFILE, asset_id, [0xD7; 32], [0xD8; 32], 3, 1, 10, 1, 1, 8,
            );
        let wrong_quote_authorization =
            crate::qrun_v06_profile_trust_candidate::test_trust_authorized_quote_asset_candidate(
                NETWORK, PROFILE, [0xE7; 32], [0xE8; 32], [0xE9; 32], 3, 1, 10, 1, 1,
            );
        assert_eq!(
            state.preview_state_root_after(&block, &DigestAuthenticator),
            Err(QRunV06ExecutionError::MissingQuoteAssetAuthorization)
        );
        assert_eq!(
            state.preview_state_root_after_with_quote_asset_authorization(
                &block,
                &DigestAuthenticator,
                Some(&wrong_quote_authorization),
            ),
            Err(QRunV06ExecutionError::QuoteAssetAuthorizationMismatch)
        );
        block.state_root = state
            .preview_state_root_after_with_quote_asset_authorization(
                &block,
                &DigestAuthenticator,
                Some(&quote_authorization),
            )
            .unwrap();
        let summary = state
            .apply_block_with_quote_asset_authorization(
                &block,
                &DigestAuthenticator,
                Some(&quote_authorization),
            )
            .unwrap();
        assert_eq!(summary.asset_registrations, 1);
        assert_eq!(summary.amm_operations, 2);
        assert_eq!(
            state.unified().registry().current_supply(&asset_id),
            Ok(50_000)
        );
        state.unified().verify_invariants().unwrap();
        // The already-created external-quote pool remains gated on later blocks.
        let mut swap = AmmSignedOperation {
            network_id: NETWORK,
            sender: ALICE,
            nonce: 3,
            expires_at: 50_000,
            operation: AmmOperation::SwapExactIn {
                token_in: native,
                token_out: asset_id,
                amount_in: 10,
                min_amount_out: 1,
            },
            signature: Vec::new(),
        };
        swap.signature = swap.signing_digest().unwrap().to_vec();
        let mut swap_block = block_for(&state, vec![QRunV06BlockOperation::Amm(swap)]);
        assert_eq!(
            state.preview_state_root_after(&swap_block, &DigestAuthenticator),
            Err(QRunV06ExecutionError::MissingQuoteAssetAuthorization)
        );
        let swap_authorization =
            crate::qrun_v06_profile_trust_candidate::test_trust_authorized_quote_asset_candidate_with_decimals(
                NETWORK, PROFILE, asset_id, [0xD7; 32], [0xD8; 32], 3, 1, 10, 1, 2, 8,
            );
        assert_eq!(
            state.preview_state_root_after_with_quote_asset_authorization(
                &swap_block,
                &DigestAuthenticator,
                Some(&wrong_quote_authorization),
            ),
            Err(QRunV06ExecutionError::QuoteAssetAuthorizationMismatch)
        );
        let quote_balance_before = state.unified().amm().balance_of(&asset_id, &ALICE);
        swap_block.state_root = state
            .preview_state_root_after_with_quote_asset_authorization(
                &swap_block,
                &DigestAuthenticator,
                Some(&swap_authorization),
            )
            .unwrap();
        let swap_summary = state
            .apply_block_with_quote_asset_authorization(
                &swap_block,
                &DigestAuthenticator,
                Some(&swap_authorization),
            )
            .unwrap();
        assert_eq!(swap_summary.amm_operations, 1);
        assert!(state.unified().amm().balance_of(&asset_id, &ALICE) > quote_balance_before);
        state.unified().verify_invariants().unwrap();
    }

    #[test]
    fn one_account_nonce_sequence_spans_native_transfer_and_amm_ops_in_same_block() {
        let mut state = fixture();
        let mut registration = AssetRegistration {
            network_id: NETWORK,
            issuer: ALICE,
            issuer_nonce: 1,
            salt: [0x64; 32],
            name: "Mixed Execution Quote".to_string(),
            symbol: "MEQ".to_string(),
            decimals: 8,
            supply_policy: AssetSupplyPolicy::Fixed {
                total_supply: 50_000,
            },
            initial_supply: 50_000,
            initial_recipient: ALICE,
            trust_policy: AssetTrustPolicy::Unverified,
            expires_at: 50_000,
            signature: Vec::new(),
        };
        registration.signature = registration.signing_digest().unwrap().to_vec();
        let asset_id = registration.asset_id();
        let native = qzxb_native_asset_id(NETWORK).unwrap();
        let pair_id = QzxbAmmStateCandidate::pair_id_for_assets(native, asset_id).unwrap();

        let mut create_pair = AmmSignedOperation {
            network_id: NETWORK,
            sender: ALICE,
            nonce: 2,
            expires_at: 50_000,
            operation: AmmOperation::CreatePair {
                token_a: native,
                token_b: asset_id,
            },
            signature: Vec::new(),
        };
        create_pair.signature = create_pair.signing_digest().unwrap().to_vec();

        let mut add_liquidity = AmmSignedOperation {
            network_id: NETWORK,
            sender: ALICE,
            nonce: 3,
            expires_at: 50_000,
            operation: AmmOperation::AddLiquidity {
                pair_id,
                amount0_desired: 100,
                amount1_desired: 100,
                min_lp_shares: 1,
            },
            signature: Vec::new(),
        };
        add_liquidity.signature = add_liquidity.signing_digest().unwrap().to_vec();

        let mut block = block_for(
            &state,
            vec![
                QRunV06BlockOperation::AssetRegistration(registration),
                QRunV06BlockOperation::NativeTransfer(transfer(ALICE, BOB, 1, 100, 1)),
                QRunV06BlockOperation::Amm(create_pair),
                QRunV06BlockOperation::Amm(add_liquidity),
            ],
        );
        block.producer = BOB;
        let quote_authorization =
            crate::qrun_v06_profile_trust_candidate::test_trust_authorized_quote_asset_candidate_with_decimals(
                NETWORK, PROFILE, asset_id, [0xDA; 32], [0xDB; 32], 3, 1, 10, 1, 1, 8,
            );
        block.state_root = state
            .preview_state_root_after_with_quote_asset_authorization(
                &block,
                &DigestAuthenticator,
                Some(&quote_authorization),
            )
            .unwrap();
        let summary = state
            .apply_block_with_quote_asset_authorization(
                &block,
                &DigestAuthenticator,
                Some(&quote_authorization),
            )
            .unwrap();

        assert_eq!(summary.native_transfers, 1);
        assert_eq!(summary.amm_operations, 2);
        assert_eq!(summary.fees_paid_to_producer, 1);
        assert_eq!(state.unified().ledger().account(&ALICE).unwrap().nonce, 3);
        assert_eq!(
            state.unified().ledger().account(&ALICE).unwrap().balance,
            19_799
        );
        assert_eq!(
            state.unified().ledger().account(&BOB).unwrap().balance,
            1_101
        );
        assert_eq!(state.unified().amm().balance_of(&native, &pair_id), 100);
        state.unified().verify_invariants().unwrap();
    }

    #[test]
    fn issuer_admin_mint_in_following_block_updates_supply_and_asset_balance() {
        let mut state = fixture();
        let mut registration = AssetRegistration {
            network_id: NETWORK,
            issuer: ALICE,
            issuer_nonce: 1,
            salt: [0x65; 32],
            name: "Issuer Mint Test".to_string(),
            symbol: "IMT".to_string(),
            decimals: 8,
            supply_policy: AssetSupplyPolicy::IssuerCapped { max_supply: 1_000 },
            initial_supply: 100,
            initial_recipient: ALICE,
            trust_policy: AssetTrustPolicy::Unverified,
            expires_at: 50_000,
            signature: Vec::new(),
        };
        registration.signature = registration.signing_digest().unwrap().to_vec();
        let asset_id = registration.asset_id();

        let mut first = block_for(
            &state,
            vec![QRunV06BlockOperation::AssetRegistration(registration)],
        );
        first.state_root = state
            .preview_state_root_after(&first, &DigestAuthenticator)
            .unwrap();
        state.apply_block(&first, &DigestAuthenticator).unwrap();
        assert_eq!(
            state.unified().registry().current_supply(&asset_id),
            Ok(100)
        );

        let mut mint = SignedAssetAdminOperation {
            network_id: NETWORK,
            issuer: ALICE,
            issuer_nonce: 2,
            expires_at: 50_000,
            action: AssetAdminAction::Mint {
                asset_id,
                recipient: BOB,
                amount: 50,
            },
            signature: Vec::new(),
        };
        mint.signature = mint.signing_digest().unwrap().to_vec();
        let mut second = block_for(&state, vec![QRunV06BlockOperation::AssetAdmin(mint)]);
        second.state_root = state
            .preview_state_root_after(&second, &DigestAuthenticator)
            .unwrap();
        let summary = state.apply_block(&second, &DigestAuthenticator).unwrap();

        assert_eq!(summary.asset_admin_operations, 1);
        assert_eq!(state.unified().registry().issuer_nonce(&ALICE), 2);
        assert_eq!(
            state.unified().registry().current_supply(&asset_id),
            Ok(150)
        );
        assert_eq!(state.unified().amm().balance_of(&asset_id, &BOB), 50);
        state.unified().verify_invariants().unwrap();
    }

    #[test]
    fn qfb6_external_quote_pair_requires_fresh_trust_authorization_and_persists_pin() {
        let mut state = fixture();
        let mut base_registration = AssetRegistration {
            network_id: NETWORK,
            issuer: ALICE,
            issuer_nonce: 1,
            salt: [0xD5; 32],
            name: "Qualified LOB Base".to_string(),
            symbol: "QLB".to_string(),
            decimals: 8,
            supply_policy: AssetSupplyPolicy::Fixed { total_supply: 100 },
            initial_supply: 100,
            initial_recipient: BOB,
            trust_policy: crate::qrun_v06_asset_registry_candidate::AssetTrustPolicy::Unverified,
            expires_at: 50_000,
            signature: Vec::new(),
        };
        base_registration.signature = base_registration.signing_digest().unwrap().to_vec();
        let base_asset = base_registration.asset_id();

        let mut quote_registration = AssetRegistration {
            network_id: NETWORK,
            issuer: ALICE,
            issuer_nonce: 2,
            salt: [0xD6; 32],
            name: "Qualified External Quote".to_string(),
            symbol: "QEQ".to_string(),
            decimals: 6,
            supply_policy: AssetSupplyPolicy::Fixed { total_supply: 100 },
            initial_supply: 100,
            initial_recipient: ALICE,
            trust_policy: crate::qrun_v06_asset_registry_candidate::AssetTrustPolicy::Unverified,
            expires_at: 50_000,
            signature: Vec::new(),
        };
        quote_registration.signature = quote_registration.signing_digest().unwrap().to_vec();
        let quote_asset = quote_registration.asset_id();

        let quote_authorization =
            crate::qrun_v06_profile_trust_candidate::test_trust_authorized_quote_asset_candidate(
                NETWORK,
                PROFILE,
                quote_asset,
                [0xD7; 32],
                [0xD8; 32],
                3,
                1,
                10,
                1,
                1,
            );

        let pair_id = OrderBook::pair_id(NETWORK, base_asset, quote_asset).unwrap();
        let create_pair = signed_orderbook(
            ALICE,
            1,
            OrderOp::CreatePair {
                base: base_asset,
                quote: quote_asset,
                base_lot_atoms: 1,
                quote_tick_atoms: 1,
                max_price_ticks: 100,
                max_quantity_lots: 100,
                min_notional: 1,
                maker_fee_bps: 0,
                taker_fee_bps: 0,
                fee_collector: PRODUCER,
            },
        );
        let mut block = block_for(
            &state,
            vec![
                QRunV06BlockOperation::AssetRegistration(base_registration),
                QRunV06BlockOperation::AssetRegistration(quote_registration),
                QRunV06BlockOperation::OrderBook(create_pair),
            ],
        );

        assert_eq!(
            state.preview_state_root_after(&block, &DigestAuthenticator),
            Err(QRunV06ExecutionError::MissingQuoteAssetAuthorization)
        );

        block.state_root = state
            .preview_state_root_after_with_quote_asset_authorization(
                &block,
                &DigestAuthenticator,
                Some(&quote_authorization),
            )
            .unwrap();
        state
            .apply_block_with_quote_asset_authorization(
                &block,
                &DigestAuthenticator,
                Some(&quote_authorization),
            )
            .unwrap();

        assert!(state.orderbook().has_pair(&pair_id));
        assert_eq!(
            state.quote_asset_authorization_commitment(),
            Some([0xD7; 32])
        );
        assert_eq!(state.quote_asset_authorization_epoch(), Some(3));

        // Q6SN v5 persists the Q6QA/Q6PN trust identity and keeps it in the
        // canonical execution root after restart.
        let snapshot = state.encode_snapshot().unwrap();
        assert_eq!(u16::from_be_bytes([snapshot[4], snapshot[5]]), 5);
        let restored =
            QRunV06CanonicalExecutionState::decode_snapshot(&snapshot, &NETWORK, &PROFILE).unwrap();
        assert_eq!(restored.state_root().unwrap(), state.state_root().unwrap());
        assert_eq!(
            restored.quote_asset_authorization_commitment(),
            Some([0xD7; 32])
        );
        assert_eq!(restored.quote_asset_authorization_epoch(), Some(3));

        let restored_root = restored.state_root().unwrap();
        let mismatched_after_restart =
            crate::qrun_v06_profile_trust_candidate::test_trust_authorized_quote_asset_candidate_with_decimals(
                NETWORK, PROFILE, quote_asset, [0xDA; 32], [0xD8; 32], 4, 1, 10, 2, 2, 18,
            );
        let followup_block = block_for(
            &restored,
            vec![QRunV06BlockOperation::NativeTransfer(transfer(
                ALICE, BOB, 2, 10, 1,
            ))],
        );
        assert_eq!(
            restored.preview_state_root_after_with_quote_asset_authorization(
                &followup_block,
                &DigestAuthenticator,
                Some(&mismatched_after_restart),
            ),
            Err(QRunV06ExecutionError::QuoteAssetDecimalsMismatch {
                asset_id: quote_asset,
                q6qa_decimals: 18,
                registry_decimals: 6,
            })
        );
        assert_eq!(restored.state_root().unwrap(), restored_root);

        // The quote authorization is included in the canonical execution root, not
        // merely in an unchecked sidecar. Recomputing the outer snapshot checksum
        // after mutating its Q6QA commitment must still fail the stored state-root check.
        let mut tampered_snapshot = snapshot.clone();
        let quote_commitment_offset = tampered_snapshot
            .windows(32)
            .position(|window| window == [0xD7; 32])
            .expect("Q6QA commitment must be present in Q6SN v5");
        tampered_snapshot[quote_commitment_offset] ^= 1;
        let payload_len = tampered_snapshot.len() - 32;
        let mut checksum = Sha256::new();
        checksum.update(EXECUTION_SNAPSHOT_CHECKSUM_DOMAIN);
        checksum.update(&tampered_snapshot[..payload_len]);
        let checksum: [u8; 32] = checksum.finalize().into();
        tampered_snapshot[payload_len..].copy_from_slice(&checksum);
        assert_eq!(
            QRunV06CanonicalExecutionState::decode_snapshot(&tampered_snapshot, &NETWORK, &PROFILE,),
            Err(QRunV06ExecutionError::StateRootMismatch)
        );

        // Q6SN v4 snapshots have no quote-pin flag. They remain readable and retain
        // their old no-quote-pin state root after being decoded by the v5 reader.
        let legacy_state = fixture();
        let mut legacy_v4 = legacy_state.encode_snapshot().unwrap();
        assert_eq!(u16::from_be_bytes([legacy_v4[4], legacy_v4[5]]), 5);
        let legacy_payload_len = legacy_v4.len() - 32;
        assert_eq!(legacy_v4[legacy_payload_len - 1], 0);
        legacy_v4.remove(legacy_payload_len - 1);
        let legacy_payload_len = legacy_v4.len() - 32;
        legacy_v4[4..6].copy_from_slice(&4u16.to_be_bytes());
        let mut legacy_checksum = Sha256::new();
        legacy_checksum.update(EXECUTION_SNAPSHOT_CHECKSUM_DOMAIN);
        legacy_checksum.update(&legacy_v4[..legacy_payload_len]);
        let legacy_checksum: [u8; 32] = legacy_checksum.finalize().into();
        legacy_v4[legacy_payload_len..].copy_from_slice(&legacy_checksum);
        let legacy_restored =
            QRunV06CanonicalExecutionState::decode_snapshot(&legacy_v4, &NETWORK, &PROFILE)
                .unwrap();
        assert_eq!(
            legacy_restored.state_root().unwrap(),
            legacy_state.state_root().unwrap()
        );
        assert_eq!(legacy_restored.quote_asset_authorization_commitment(), None);

        // Once an external quote asset is active, even an otherwise empty next block
        // needs a currently valid authorization. The legacy API fails closed.
        let mut next_block = block_for(&restored, Vec::new());
        let next_height_authorization =
            crate::qrun_v06_profile_trust_candidate::test_trust_authorized_quote_asset_candidate(
                NETWORK,
                PROFILE,
                quote_asset,
                [0xD7; 32],
                [0xD8; 32],
                3,
                1,
                10,
                1,
                2,
            );
        let mut no_auth = restored.clone();
        assert_eq!(
            no_auth.apply_block(&next_block, &DigestAuthenticator),
            Err(QRunV06ExecutionError::MissingQuoteAssetAuthorization)
        );

        // A legacy-restored state may still contain an external-quote pair but lack
        // the CP-0544 authorization pin. An ordinary empty block must still discover
        // the existing pair and fail closed before expiry/refund/other mutations.
        let mut legacy_unpinned_parent = restored.clone();
        legacy_unpinned_parent.clear_test_quote_asset_authorization();
        let legacy_unpinned_child = block_for(&legacy_unpinned_parent, Vec::new());
        assert_eq!(
            legacy_unpinned_parent.apply_block(&legacy_unpinned_child, &DigestAuthenticator,),
            Err(QRunV06ExecutionError::MissingQuoteAssetAuthorization)
        );

        assert_eq!(
            restored.preview_state_root_after_with_quote_asset_authorization(
                &next_block,
                &DigestAuthenticator,
                Some(&quote_authorization),
            ),
            Err(QRunV06ExecutionError::QuoteAssetAuthorizationMismatch)
        );
        next_block.state_root = restored
            .preview_state_root_after_with_quote_asset_authorization(
                &next_block,
                &DigestAuthenticator,
                Some(&next_height_authorization),
            )
            .unwrap();
        let mut next_with_auth = restored.clone();
        next_with_auth
            .apply_block_with_quote_asset_authorization(
                &next_block,
                &DigestAuthenticator,
                Some(&next_height_authorization),
            )
            .unwrap();
        assert_eq!(next_with_auth.height(), restored.height() + 1);

        // An expired authorization is not accepted for a block at its exclusive end height.
        let expired_authorization =
            crate::qrun_v06_profile_trust_candidate::test_trust_authorized_quote_asset_candidate(
                NETWORK,
                PROFILE,
                quote_asset,
                [0xD7; 32],
                [0xD8; 32],
                3,
                1,
                2,
                1,
                2,
            );
        assert_eq!(
            restored.preview_state_root_after_with_quote_asset_authorization(
                &next_block,
                &DigestAuthenticator,
                Some(&expired_authorization),
            ),
            Err(QRunV06ExecutionError::QuoteAssetAuthorizationMismatch)
        );

        let rolled_back_authorization =
            crate::qrun_v06_profile_trust_candidate::test_trust_authorized_quote_asset_candidate(
                NETWORK,
                PROFILE,
                quote_asset,
                [0xD9; 32],
                [0xDA; 32],
                2,
                1,
                10,
                1,
                2,
            );
        assert_eq!(
            restored.preview_state_root_after_with_quote_asset_authorization(
                &next_block,
                &DigestAuthenticator,
                Some(&rolled_back_authorization),
            ),
            Err(QRunV06ExecutionError::QuoteAssetAuthorizationRollback)
        );
    }

    #[test]
    fn qfb6_limit_order_match_is_fully_backed_by_amm_vault_and_shared_nonce() {
        let mut state = fixture();
        let native = qzxb_native_asset_id(NETWORK).unwrap();
        let mut registration = AssetRegistration {
            network_id: NETWORK,
            issuer: ALICE,
            issuer_nonce: 1,
            salt: [0x71; 32],
            name: "LOB Base Asset".to_string(),
            symbol: "LBA".to_string(),
            decimals: 8,
            supply_policy: AssetSupplyPolicy::Fixed {
                total_supply: 1_000,
            },
            initial_supply: 1_000,
            initial_recipient: BOB,
            trust_policy: AssetTrustPolicy::Unverified,
            expires_at: 50_000,
            signature: Vec::new(),
        };
        registration.signature = registration.signing_digest().unwrap().to_vec();
        let base_asset = registration.asset_id();
        let pair_id = OrderBook::pair_id(NETWORK, base_asset, native).unwrap();

        let create_pair = signed_orderbook(
            ALICE,
            1,
            OrderOp::CreatePair {
                base: base_asset,
                quote: native,
                base_lot_atoms: 1,
                quote_tick_atoms: 1,
                max_price_ticks: 100,
                max_quantity_lots: 1_000,
                min_notional: 1,
                maker_fee_bps: 10,
                taker_fee_bps: 20,
                fee_collector: PRODUCER,
            },
        );
        let seller_deposit = signed_orderbook(
            BOB,
            1,
            OrderOp::Deposit {
                asset: base_asset,
                amount: 100,
            },
        );
        let buyer_deposit = signed_orderbook(
            ALICE,
            2,
            OrderOp::Deposit {
                asset: native,
                amount: 100,
            },
        );
        let ask = signed_orderbook(
            BOB,
            2,
            OrderOp::PlaceLimit {
                pair: pair_id,
                side: Side::Sell,
                price_ticks: 2,
                quantity_lots: 10,
                tif: Tif::Gtc,
                expires_at_height: 20,
            },
        );
        let bid = signed_orderbook(
            ALICE,
            3,
            OrderOp::PlaceLimit {
                pair: pair_id,
                side: Side::Buy,
                price_ticks: 3,
                quantity_lots: 10,
                tif: Tif::Ioc,
                expires_at_height: 20,
            },
        );
        // Maker and taker fees total two quote atoms; the collector withdraws only
        // spendable fee balance from the LOB sub-ledger back to its canonical account.
        let fee_withdraw = signed_orderbook(
            PRODUCER,
            1,
            OrderOp::Withdraw {
                asset: native,
                amount: 2,
            },
        );

        let mut block = block_for(
            &state,
            vec![
                QRunV06BlockOperation::AssetRegistration(registration),
                QRunV06BlockOperation::OrderBook(create_pair),
                QRunV06BlockOperation::OrderBook(seller_deposit),
                QRunV06BlockOperation::OrderBook(buyer_deposit),
                QRunV06BlockOperation::OrderBook(ask),
                QRunV06BlockOperation::OrderBook(bid),
                QRunV06BlockOperation::OrderBook(fee_withdraw),
            ],
        );
        block.state_root = state
            .preview_state_root_after(&block, &DigestAuthenticator)
            .unwrap();
        let summary = state.apply_block(&block, &DigestAuthenticator).unwrap();

        let base_vault = orderbook_vault_account(NETWORK, base_asset);
        let quote_vault = orderbook_vault_account(NETWORK, native);
        assert_eq!(summary.orderbook_operations, 6);
        assert_eq!(summary.orders_expired, 0);
        assert_eq!(state.orderbook().fills().len(), 1);
        assert_eq!(state.orderbook().orders().count(), 0);
        assert_eq!(state.orderbook().balance(&base_asset, &ALICE), 10);
        assert_eq!(state.orderbook().balance(&base_asset, &BOB), 90);
        assert_eq!(state.orderbook().balance(&native, &BOB), 19);
        assert_eq!(state.orderbook().balance(&native, &PRODUCER), 0);
        assert_eq!(
            state.orderbook().total_asset_balance(base_asset).unwrap(),
            100
        );
        assert_eq!(state.orderbook().total_asset_balance(native).unwrap(), 98);
        assert_eq!(
            state.unified().amm().balance_of(&base_asset, &base_vault),
            100
        );
        assert_eq!(state.unified().amm().balance_of(&native, &quote_vault), 98);
        assert_eq!(
            state.unified().ledger().account(&PRODUCER).unwrap().balance,
            2
        );
        assert_eq!(state.unified().ledger().account(&ALICE).unwrap().nonce, 3);
        assert_eq!(state.unified().ledger().account(&BOB).unwrap().nonce, 2);
        assert_eq!(
            state.unified().ledger().account(&PRODUCER).unwrap().nonce,
            1
        );
        state.verify_invariants().unwrap();

        // A normal TXN2 transfer must not bypass the OrderBook sub-ledger and drain its vault.
        let before = state.state_root().unwrap();
        let attack = transfer(ALICE, quote_vault, 4, 1, 0);
        let mut attack_block =
            block_for(&state, vec![QRunV06BlockOperation::NativeTransfer(attack)]);
        attack_block.state_root = [0; 32];
        assert!(matches!(
            state.apply_block(&attack_block, &DigestAuthenticator),
            Err(QRunV06ExecutionError::Unified(
                UnifiedAssetError::InvalidOrderBookTransfer
            ))
        ));
        assert_eq!(state.state_root().unwrap(), before);

        let mut amm_bypass = AmmSignedOperation {
            network_id: NETWORK,
            sender: ALICE,
            nonce: 4,
            expires_at: 10_000,
            operation: AmmOperation::TransferAsset {
                asset_id: native,
                recipient: quote_vault,
                amount: 1,
            },
            signature: Vec::new(),
        };
        amm_bypass.signature = amm_bypass.signing_digest().unwrap().to_vec();
        let mut amm_attack_block = block_for(&state, vec![QRunV06BlockOperation::Amm(amm_bypass)]);
        amm_attack_block.state_root = [0; 32];
        assert!(matches!(
            state.apply_block(&amm_attack_block, &DigestAuthenticator),
            Err(QRunV06ExecutionError::Unified(
                UnifiedAssetError::InvalidOrderBookTransfer
            ))
        ));
        assert_eq!(state.state_root().unwrap(), before);
    }

    #[test]
    fn qfb6_processes_due_order_expiry_before_user_operations() {
        let mut state = fixture();
        let native = qzxb_native_asset_id(NETWORK).unwrap();
        let mut registration = AssetRegistration {
            network_id: NETWORK,
            issuer: ALICE,
            issuer_nonce: 1,
            salt: [0x72; 32],
            name: "Expiry Base Asset".to_string(),
            symbol: "EBA".to_string(),
            decimals: 8,
            supply_policy: AssetSupplyPolicy::Fixed { total_supply: 100 },
            initial_supply: 100,
            initial_recipient: BOB,
            trust_policy: AssetTrustPolicy::Unverified,
            expires_at: 50_000,
            signature: Vec::new(),
        };
        registration.signature = registration.signing_digest().unwrap().to_vec();
        let base_asset = registration.asset_id();
        let pair_id = OrderBook::pair_id(NETWORK, base_asset, native).unwrap();

        let first_operations = vec![
            QRunV06BlockOperation::AssetRegistration(registration),
            QRunV06BlockOperation::OrderBook(signed_orderbook(
                ALICE,
                1,
                OrderOp::CreatePair {
                    base: base_asset,
                    quote: native,
                    base_lot_atoms: 1,
                    quote_tick_atoms: 1,
                    max_price_ticks: 100,
                    max_quantity_lots: 100,
                    min_notional: 1,
                    maker_fee_bps: 0,
                    taker_fee_bps: 0,
                    fee_collector: PRODUCER,
                },
            )),
            QRunV06BlockOperation::OrderBook(signed_orderbook(
                BOB,
                1,
                OrderOp::Deposit {
                    asset: base_asset,
                    amount: 100,
                },
            )),
            QRunV06BlockOperation::OrderBook(signed_orderbook(
                BOB,
                2,
                OrderOp::PlaceLimit {
                    pair: pair_id,
                    side: Side::Sell,
                    price_ticks: 2,
                    quantity_lots: 100,
                    tif: Tif::Gtc,
                    expires_at_height: 2,
                },
            )),
        ];
        let mut first = block_for(&state, first_operations);
        first.state_root = state
            .preview_state_root_after(&first, &DigestAuthenticator)
            .unwrap();
        let first_summary = state.apply_block(&first, &DigestAuthenticator).unwrap();
        assert_eq!(first_summary.orders_expired, 0);
        assert_eq!(state.orderbook().orders().count(), 1);
        assert_eq!(
            state
                .orderbook()
                .total_escrow_for_asset(base_asset)
                .unwrap(),
            100
        );

        let mut second = block_for(&state, Vec::new());
        second.state_root = state
            .preview_state_root_after(&second, &DigestAuthenticator)
            .unwrap();
        let second_summary = state.apply_block(&second, &DigestAuthenticator).unwrap();
        assert_eq!(second_summary.orders_expired, 1);
        assert_eq!(state.orderbook().orders().count(), 0);
        assert_eq!(
            state
                .orderbook()
                .total_escrow_for_asset(base_asset)
                .unwrap(),
            0
        );
        assert_eq!(state.orderbook().balance(&base_asset, &BOB), 100);
        assert_eq!(
            state
                .unified()
                .amm()
                .balance_of(&base_asset, &orderbook_vault_account(NETWORK, base_asset)),
            100
        );
        state.verify_invariants().unwrap();
    }

    #[test]
    fn asset_freeze_blocks_new_orders_but_cancel_remains_available() {
        let mut state = fixture();
        let native = qzxb_native_asset_id(NETWORK).unwrap();
        let mut registration = AssetRegistration {
            network_id: NETWORK,
            issuer: ALICE,
            issuer_nonce: 1,
            salt: [0x73; 32],
            name: "Freeze Policy Asset".to_string(),
            symbol: "FPA".to_string(),
            decimals: 8,
            supply_policy: AssetSupplyPolicy::Fixed { total_supply: 100 },
            initial_supply: 100,
            initial_recipient: BOB,
            trust_policy: AssetTrustPolicy::Unverified,
            expires_at: 50_000,
            signature: Vec::new(),
        };
        registration.signature = registration.signing_digest().unwrap().to_vec();
        let asset = registration.asset_id();
        let pair = OrderBook::pair_id(NETWORK, asset, native).unwrap();

        let mut first = block_for(
            &state,
            vec![
                QRunV06BlockOperation::AssetRegistration(registration),
                QRunV06BlockOperation::OrderBook(signed_orderbook(
                    ALICE,
                    1,
                    OrderOp::CreatePair {
                        base: asset,
                        quote: native,
                        base_lot_atoms: 1,
                        quote_tick_atoms: 1,
                        max_price_ticks: 100,
                        max_quantity_lots: 100,
                        min_notional: 1,
                        maker_fee_bps: 0,
                        taker_fee_bps: 0,
                        fee_collector: PRODUCER,
                    },
                )),
                QRunV06BlockOperation::OrderBook(signed_orderbook(
                    BOB,
                    1,
                    OrderOp::Deposit { asset, amount: 100 },
                )),
                QRunV06BlockOperation::OrderBook(signed_orderbook(
                    BOB,
                    2,
                    OrderOp::PlaceLimit {
                        pair,
                        side: Side::Sell,
                        price_ticks: 2,
                        quantity_lots: 10,
                        tif: Tif::Gtc,
                        expires_at_height: 20,
                    },
                )),
            ],
        );
        first.state_root = state
            .preview_state_root_after(&first, &DigestAuthenticator)
            .unwrap();
        state.apply_block(&first, &DigestAuthenticator).unwrap();
        assert_eq!(state.orderbook().orders().count(), 1);
        assert_eq!(state.orderbook().total_escrow_for_asset(asset).unwrap(), 10);

        let mut freeze = SignedAssetAdminOperation {
            network_id: NETWORK,
            issuer: ALICE,
            issuer_nonce: 2,
            expires_at: 50_000,
            action: AssetAdminAction::SetTransfersEnabled {
                asset_id: asset,
                enabled: false,
            },
            signature: Vec::new(),
        };
        freeze.signature = freeze.signing_digest().unwrap().to_vec();
        let mut second = block_for(
            &state,
            vec![
                QRunV06BlockOperation::AssetAdmin(freeze),
                QRunV06BlockOperation::OrderBook(signed_orderbook(
                    BOB,
                    3,
                    OrderOp::Cancel {
                        order_id: state.orderbook().orders().next().unwrap().id,
                    },
                )),
            ],
        );
        second.state_root = state
            .preview_state_root_after(&second, &DigestAuthenticator)
            .unwrap();
        state.apply_block(&second, &DigestAuthenticator).unwrap();
        assert_eq!(state.orderbook().orders().count(), 0);
        assert_eq!(state.orderbook().balance(&asset, &BOB), 100);
        assert_eq!(state.orderbook().total_escrow_for_asset(asset).unwrap(), 0);

        let before = state.state_root().unwrap();
        let frozen_order = signed_orderbook(
            BOB,
            4,
            OrderOp::PlaceLimit {
                pair,
                side: Side::Sell,
                price_ticks: 2,
                quantity_lots: 1,
                tif: Tif::Gtc,
                expires_at_height: 20,
            },
        );
        let mut third = block_for(&state, vec![QRunV06BlockOperation::OrderBook(frozen_order)]);
        third.state_root = [0; 32];
        assert!(matches!(
            state.apply_block(&third, &DigestAuthenticator),
            Err(QRunV06ExecutionError::Unified(
                UnifiedAssetError::AssetTransfersDisabled(frozen_asset)
            )) if frozen_asset == asset
        ));
        assert_eq!(state.state_root().unwrap(), before);
    }

    #[test]
    fn qfb6_aggregate_snapshot_roundtrips_market_fill_escrow_and_continues_execution() {
        let mut state = fixture();
        let native = qzxb_native_asset_id(NETWORK).unwrap();
        let mut registration = AssetRegistration {
            network_id: NETWORK,
            issuer: ALICE,
            issuer_nonce: 1,
            salt: [0xD1; 32],
            name: "Checkpoint Base Asset".to_string(),
            symbol: "CBA".to_string(),
            decimals: 8,
            supply_policy: AssetSupplyPolicy::Fixed { total_supply: 100 },
            initial_supply: 100,
            initial_recipient: BOB,
            trust_policy: AssetTrustPolicy::CustodianAttested {
                custodian: PRODUCER,
                evidence_hash: [0xD2; 32],
            },
            expires_at: 50_000,
            signature: Vec::new(),
        };
        registration.signature = registration.signing_digest().unwrap().to_vec();
        let base_asset = registration.asset_id();
        let pair = OrderBook::pair_id(NETWORK, base_asset, native).unwrap();

        let operations = vec![
            QRunV06BlockOperation::AssetRegistration(registration),
            QRunV06BlockOperation::OrderBook(signed_orderbook(
                ALICE,
                1,
                OrderOp::CreatePair {
                    base: base_asset,
                    quote: native,
                    base_lot_atoms: 1,
                    quote_tick_atoms: 1,
                    max_price_ticks: 100,
                    max_quantity_lots: 100,
                    min_notional: 1,
                    maker_fee_bps: 0,
                    taker_fee_bps: 0,
                    fee_collector: PRODUCER,
                },
            )),
            QRunV06BlockOperation::OrderBook(signed_orderbook(
                BOB,
                1,
                OrderOp::Deposit {
                    asset: base_asset,
                    amount: 100,
                },
            )),
            QRunV06BlockOperation::OrderBook(signed_orderbook(
                ALICE,
                2,
                OrderOp::Deposit {
                    asset: native,
                    amount: 100,
                },
            )),
            QRunV06BlockOperation::OrderBook(signed_orderbook(
                BOB,
                2,
                OrderOp::PlaceLimit {
                    pair,
                    side: Side::Sell,
                    price_ticks: 2,
                    quantity_lots: 10,
                    tif: Tif::Gtc,
                    expires_at_height: 20,
                },
            )),
            QRunV06BlockOperation::OrderBook(signed_orderbook(
                ALICE,
                3,
                OrderOp::PlaceLimit {
                    pair,
                    side: Side::Buy,
                    price_ticks: 3,
                    quantity_lots: 5,
                    tif: Tif::Ioc,
                    expires_at_height: 20,
                },
            )),
        ];
        let mut first = block_for(&state, operations);
        first.state_root = state
            .preview_state_root_after(&first, &DigestAuthenticator)
            .unwrap();
        let summary = state.apply_block(&first, &DigestAuthenticator).unwrap();
        assert_eq!(summary.orderbook_operations, 5);
        assert_eq!(state.orderbook().fills().len(), 1);
        assert_eq!(state.orderbook().orders().count(), 1);
        let open_order_id = state.orderbook().orders().next().unwrap().id;
        assert_eq!(state.orderbook().orders().next().unwrap().remaining_lots, 5);
        assert_eq!(
            state
                .orderbook()
                .total_escrow_for_asset(base_asset)
                .unwrap(),
            5
        );
        state.verify_invariants().unwrap();

        let expected_root = state.state_root().unwrap();
        let snapshot = state.encode_snapshot().unwrap();
        assert!(snapshot.len() < MAX_QRUN_V06_EXECUTION_SNAPSHOT_BYTES);
        let mut restored =
            QRunV06CanonicalExecutionState::decode_snapshot(&snapshot, &NETWORK, &PROFILE).unwrap();
        assert_eq!(restored, state);
        assert_eq!(restored.state_root().unwrap(), expected_root);
        assert_eq!(restored.height(), 1);
        assert_eq!(restored.tip_hash(), state.tip_hash());
        assert_eq!(restored.unified().registry().issuer_nonce(&ALICE), 1);
        assert_eq!(restored.orderbook().fills(), state.orderbook().fills());
        assert_eq!(
            restored
                .orderbook()
                .total_escrow_for_asset(base_asset)
                .unwrap(),
            5
        );
        assert_eq!(
            restored.orderbook().balance(&native, &ALICE),
            state.orderbook().balance(&native, &ALICE)
        );

        assert_eq!(
            QRunV06CanonicalExecutionState::decode_snapshot(&snapshot, &[0xD3; 32], &PROFILE),
            Err(QRunV06ExecutionError::WrongNetwork)
        );
        assert_eq!(
            QRunV06CanonicalExecutionState::decode_snapshot(&snapshot, &NETWORK, &[0xD4; 32]),
            Err(QRunV06ExecutionError::WrongProfile)
        );
        let mut corrupted = snapshot.clone();
        let corruption_index = corrupted.len() / 2;
        corrupted[corruption_index] ^= 1;
        assert_eq!(
            QRunV06CanonicalExecutionState::decode_snapshot(&corrupted, &NETWORK, &PROFILE,),
            Err(QRunV06ExecutionError::SnapshotChecksumMismatch)
        );

        // Continue after the simulated restart. A cancel consumes Bob's next order-book nonce.
        let cancel = signed_orderbook(
            BOB,
            3,
            OrderOp::Cancel {
                order_id: open_order_id,
            },
        );
        let mut next = block_for(&state, vec![QRunV06BlockOperation::OrderBook(cancel)]);
        next.state_root = state
            .preview_state_root_after(&next, &DigestAuthenticator)
            .unwrap();
        state.apply_block(&next, &DigestAuthenticator).unwrap();
        restored.apply_block(&next, &DigestAuthenticator).unwrap();
        assert_eq!(restored, state);
        assert_eq!(restored.state_root().unwrap(), state.state_root().unwrap());
        assert_eq!(restored.orderbook().orders().count(), 0);
        assert_eq!(
            restored
                .orderbook()
                .total_escrow_for_asset(base_asset)
                .unwrap(),
            0
        );
        assert_eq!(restored.orderbook().balance(&base_asset, &BOB), 95);
    }

    #[test]
    fn wrong_profile_bad_root_and_duplicate_tx_fail_atomically() {
        let mut state = fixture();
        let tx = transfer(ALICE, BOB, 1, 10, 1);
        let block = block_for(
            &state,
            vec![QRunV06BlockOperation::NativeTransfer(tx.clone())],
        );
        let before = state.clone();
        let mut wrong_profile = block.clone();
        wrong_profile.profile_id = [0xEE; 32];
        assert_eq!(
            state.apply_block(&wrong_profile, &DigestAuthenticator),
            Err(QRunV06ExecutionError::WrongProfile)
        );
        let mut bad_root = block.clone();
        bad_root.state_root = [0xFE; 32];
        assert_eq!(
            state.apply_block(&bad_root, &DigestAuthenticator),
            Err(QRunV06ExecutionError::StateRootMismatch)
        );
        let duplicate = block_for(
            &state,
            vec![
                QRunV06BlockOperation::NativeTransfer(tx.clone()),
                QRunV06BlockOperation::NativeTransfer(tx),
            ],
        );
        assert_eq!(
            state.preview_state_root_after(&duplicate, &DigestAuthenticator),
            Err(QRunV06ExecutionError::DuplicateTransaction)
        );
        assert_eq!(state, before);
    }

    #[test]
    fn expired_or_tampered_native_transfer_is_rejected_without_state_change() {
        let mut state = fixture();
        let mut tx = transfer(ALICE, BOB, 1, 10, 1);
        tx.expires_at = 50;
        tx.signature = transaction_signing_digest(&tx).unwrap().to_vec();
        let mut block = block_for(&state, vec![QRunV06BlockOperation::NativeTransfer(tx)]);
        block.timestamp = 50;
        let before = state.clone();
        assert!(state.apply_block(&block, &DigestAuthenticator).is_err());
        assert_eq!(state, before);

        let mut bad = transfer(ALICE, BOB, 1, 10, 1);
        bad.amount += 1;
        let mut bad_block = block_for(&state, vec![QRunV06BlockOperation::NativeTransfer(bad)]);
        bad_block.state_root = [0; 32];
        assert!(state.apply_block(&bad_block, &DigestAuthenticator).is_err());
        assert_eq!(state, before);
    }

    #[test]
    fn qfb6_snapshot_preserves_release_nonce_and_allows_next_release_after_restore() {
        use crate::qrun_v06_tokenomics_candidate::QRunV06AllocationBucket;

        let mut state = cp0528_state(ALICE);
        let release1 = signed_category_release(
            QRunV06AllocationBucket::CommunityAirdrop,
            1,
            BOB,
            100,
            10_000,
        );
        let mut block1 = block_for(
            &state,
            vec![QRunV06BlockOperation::CategoryRelease(release1.clone())],
        );
        block1.state_root = state
            .preview_state_root_after(&block1, &DigestAuthenticator)
            .unwrap();
        state.apply_block(&block1, &DigestAuthenticator).unwrap();

        let snapshot = state.encode_snapshot().unwrap();
        let mut restored =
            QRunV06CanonicalExecutionState::decode_snapshot(&snapshot, &NETWORK, &PROFILE).unwrap();
        assert_eq!(restored, state);
        assert_eq!(restored.tokenomics().unwrap().founder_release_nonce(), 1);
        assert_eq!(
            restored.tokenomics().unwrap().last_release_id(),
            release1.signing_digest().unwrap()
        );

        let release2 = signed_category_release(
            QRunV06AllocationBucket::MarketingPartners,
            2,
            BOB,
            200,
            10_000,
        );
        let mut block2 = block_for(
            &restored,
            vec![QRunV06BlockOperation::CategoryRelease(release2.clone())],
        );
        block2.state_root = restored
            .preview_state_root_after(&block2, &DigestAuthenticator)
            .unwrap();
        restored.apply_block(&block2, &DigestAuthenticator).unwrap();

        let accounting = restored.tokenomics().unwrap();
        assert_eq!(accounting.founder_release_nonce(), 2);
        assert_eq!(
            accounting.last_release_id(),
            release2.signing_digest().unwrap()
        );
        assert_eq!(
            accounting.issued_by_bucket_atoms(QRunV06AllocationBucket::CommunityAirdrop),
            100
        );
        assert_eq!(
            accounting.issued_by_bucket_atoms(QRunV06AllocationBucket::MarketingPartners),
            200
        );
        assert_eq!(
            accounting.live_supply_atoms().unwrap(),
            restored.unified().ledger().total_value().unwrap()
        );
    }

    #[test]
    fn qfb6_v5_decoder_rejects_legacy_v3_bytes_instead_of_reinterpreting_them() {
        let state = fixture();
        let block = block_for(&state, Vec::new());
        let mut legacy_v3 = encode_qrun_v06_block(&block).unwrap();
        legacy_v3[4..6].copy_from_slice(&3u16.to_be_bytes());
        assert_eq!(
            decode_qrun_v06_block(&legacy_v3),
            Err(QRunV06ExecutionError::UnsupportedVersion(3))
        );
        let mut legacy_v2 = encode_qrun_v06_block(&block).unwrap();
        legacy_v2[4..6].copy_from_slice(&2u16.to_be_bytes());
        assert_eq!(
            decode_qrun_v06_block(&legacy_v2),
            Err(QRunV06ExecutionError::UnsupportedVersion(2))
        );
    }

    #[test]
    fn cp0528_genesis_credits_one_billion_founder_and_binds_all_other_buckets_unissued() {
        let state = QRunV06CanonicalExecutionState::cp0528_genesis_candidate(
            NETWORK,
            PROFILE,
            ALICE,
            QRunV06MiningScheduleCandidate::cp0422_research_candidate(),
        )
        .unwrap();
        let accounting = state.tokenomics().unwrap();
        assert_eq!(accounting.founder_account(), ALICE);
        assert_eq!(
            accounting.gross_issued_atoms().unwrap(),
            QRUN_V06_FOUNDER_GENESIS_ATOMS
        );
        assert_eq!(
            state.unified().ledger().total_value().unwrap(),
            QRUN_V06_FOUNDER_GENESIS_ATOMS
        );
        assert_eq!(
            state.unified().ledger().account(&ALICE).unwrap().balance as u128,
            QRUN_V06_FOUNDER_GENESIS_ATOMS
        );
        assert_eq!(
            accounting.issued_by_bucket_atoms(
                crate::qrun_v06_tokenomics_candidate::QRunV06AllocationBucket::MiningNetworkSecurity
            ),
            0
        );
        assert_eq!(
            state.tokenomics().unwrap().live_supply_atoms().unwrap(),
            QRUN_V06_FOUNDER_GENESIS_ATOMS
        );

        let encoded = state.encode_snapshot().unwrap();
        let restored =
            QRunV06CanonicalExecutionState::decode_snapshot(&encoded, &NETWORK, &PROFILE).unwrap();
        assert_eq!(restored, state);
        assert_eq!(restored.state_root().unwrap(), state.state_root().unwrap());
        assert!(restored.tokenomics().is_some());
    }

    #[test]
    fn cp0528_mining_reward_is_height_derived_capped_and_snapshot_replayable() {
        let mut state = QRunV06CanonicalExecutionState::cp0528_genesis_candidate(
            NETWORK,
            PROFILE,
            ALICE,
            QRunV06MiningScheduleCandidate::cp0422_research_candidate(),
        )
        .unwrap();
        let mut block = block_for(&state, Vec::new());
        block.state_root = state
            .preview_state_root_after(&block, &DigestAuthenticator)
            .unwrap();
        let summary = state.apply_block(&block, &DigestAuthenticator).unwrap();
        assert_eq!(summary.mining_reward_atoms, 35_673_515_981);
        assert_eq!(
            state.unified().ledger().account(&PRODUCER).unwrap().balance,
            35_673_515_981u64
        );
        assert_eq!(
            state
                .tokenomics()
                .unwrap()
                .issued_by_bucket_atoms(
                    crate::qrun_v06_tokenomics_candidate::QRunV06AllocationBucket::MiningNetworkSecurity
                ),
            35_673_515_981
        );
        assert_eq!(
            state.unified().ledger().total_value().unwrap(),
            QRUN_V06_FOUNDER_GENESIS_ATOMS + 35_673_515_981
        );

        let encoded = state.encode_snapshot().unwrap();
        let restored =
            QRunV06CanonicalExecutionState::decode_snapshot(&encoded, &NETWORK, &PROFILE).unwrap();
        assert_eq!(restored, state);
        assert_eq!(restored.state_root().unwrap(), state.state_root().unwrap());

        let mut next = block_for(&restored, Vec::new());
        next.state_root = restored
            .preview_state_root_after(&next, &DigestAuthenticator)
            .unwrap();
        let mut resumed = restored;
        let resumed_summary = resumed.apply_block(&next, &DigestAuthenticator).unwrap();
        assert_eq!(resumed_summary.mining_reward_atoms, 35_673_515_981);
        assert_eq!(
            resumed
                .tokenomics()
                .unwrap()
                .issued_by_bucket_atoms(
                    crate::qrun_v06_tokenomics_candidate::QRunV06AllocationBucket::MiningNetworkSecurity
                ),
            71_347_031_962
        );
    }

    #[test]
    fn cp0528_execution_rejects_consensus_profile_with_different_mining_schedule() {
        let state = QRunV06CanonicalExecutionState::cp0528_genesis_candidate(
            NETWORK,
            PROFILE,
            ALICE,
            QRunV06MiningScheduleCandidate::cp0422_research_candidate(),
        )
        .unwrap();
        let mut params = ConsensusParameters::candidate_testnet().unwrap();
        params.protocol_version = 6;
        state.validate_consensus_parameters(&params).unwrap();

        params.issuance = crate::issuance_schedule::IssuanceParameters::new(
            params.issuance.maximum_supply(),
            params.issuance.initial_subsidy() + 1,
            params.issuance.blocks_per_halving(),
        )
        .unwrap();
        assert_eq!(
            state.validate_consensus_parameters(&params),
            Err(QRunV06ExecutionError::TokenomicsConsensusMismatch)
        );
    }
}
