//! QRun v0.5 adapter joining the 10B Genesis to durable PoW fork choice.
//!
//! Candidate runtime integration. It reuses PTB2 consensus and the PFS2 durable branch store,
//! but is not yet the production peer/RPC service or a Mainnet-ready consensus profile.
//! Since QRun Genesis allocates the entire supply, any reward computed against the live supply
//! is zero. The adapter rejects profiles with a different cap and validates supply on every
//! stored branch after recovery and successful imports.

use crate::{
    chain_admission::ReferenceTimeProvider,
    consensus::{pow_digest, ConsensusError, ConsensusParameters, PowHeader, Uint256},
    private_testnet_driver::PrivateTestnetChain,
    private_testnet_fork_store::{ForkStoreError, PrivateTestnetForkStore},
    private_testnet_wire::{
        decode_candidate_network_block, encode_candidate_network_block, PrivateTestnetWireError,
    },
    qrun_v05_checkpoint_candidate::{QRunCheckpointError, QRunV05PowCheckpoint},
    qrun_v05_fee_pow_wire_candidate::{
        encode_qrun_v05_fee_pow_block, qrun_v05_fee_pow_state_commitment,
    },
    qrun_v05_genesis_candidate::{QRunGenesisError, QRunGenesisV05},
    qrun_v05_profile_identity_candidate::{
        PROPOSED_OWNER_ACCOUNT_ID, PROPOSED_QRUN_V05_NETWORK_ID,
    },
    state_machine::{
        transaction_id, AccountId, Block, LedgerState, NetworkId, QRunV05FeeBlock, StateError,
        Transaction, TransactionAuthenticator, MAX_TOTAL_SUPPLY_ATOMS,
    },
};
use std::path::Path;

#[derive(Debug)]
pub enum QRunV05PowRuntimeError {
    Genesis(QRunGenesisError),
    Consensus(ConsensusError),
    Store(ForkStoreError),
    Wire(PrivateTestnetWireError),
    Ledger(StateError),
    WrongSupplyProfile,
    WrongNetwork,
    UnsupportedEnvelopeMode,
    SupplyMismatch { expected: u128, actual: u128 },
    InvalidCandidate(String),
    MiningExhausted { attempts: u64 },
    UnknownArchivedBranch,
    Checkpoint(QRunCheckpointError),
}

impl From<QRunGenesisError> for QRunV05PowRuntimeError {
    fn from(error: QRunGenesisError) -> Self {
        Self::Genesis(error)
    }
}
impl From<ConsensusError> for QRunV05PowRuntimeError {
    fn from(error: ConsensusError) -> Self {
        Self::Consensus(error)
    }
}
impl From<ForkStoreError> for QRunV05PowRuntimeError {
    fn from(error: ForkStoreError) -> Self {
        Self::Store(error)
    }
}
impl From<PrivateTestnetWireError> for QRunV05PowRuntimeError {
    fn from(error: PrivateTestnetWireError) -> Self {
        Self::Wire(error)
    }
}
impl From<StateError> for QRunV05PowRuntimeError {
    fn from(error: StateError) -> Self {
        Self::Ledger(error)
    }
}
impl From<QRunCheckpointError> for QRunV05PowRuntimeError {
    fn from(error: QRunCheckpointError) -> Self {
        Self::Checkpoint(error)
    }
}

/// QRun Genesis + deterministic PoW validation + persisted branch selection.
/// Network listeners should submit complete PTB2 envelopes through submit_block.
pub struct QRunV05PowForkRuntime {
    network_id: NetworkId,
    owner_account: AccountId,
    genesis_commitment: [u8; 32],
    params: ConsensusParameters,
    store: PrivateTestnetForkStore,
    fee_only: bool,
    producer_account: AccountId,
}

impl QRunV05PowForkRuntime {
    pub fn open<A: TransactionAuthenticator>(
        directory: impl AsRef<Path>,
        network_id: NetworkId,
        owner_account: AccountId,
        params: ConsensusParameters,
        authenticator: &A,
        clock: &dyn ReferenceTimeProvider,
    ) -> Result<Self, QRunV05PowRuntimeError> {
        Self::open_inner(
            directory,
            network_id,
            owner_account,
            params,
            authenticator,
            clock,
            None,
            None,
        )
    }

    /// Open a new durable suffix store from an independently anchored QRCP checkpoint.
    /// The caller must retain checkpoint bytes and its commitment outside the mutable store.
    pub fn open_from_checkpoint<A: TransactionAuthenticator>(
        directory: impl AsRef<Path>,
        network_id: NetworkId,
        owner_account: AccountId,
        params: ConsensusParameters,
        authenticator: &A,
        clock: &dyn ReferenceTimeProvider,
        checkpoint_bytes: &[u8],
        checkpoint_commitment: [u8; 32],
        minimum_checkpoint_height: u64,
        expected_manifest_anchor: Option<[u8; 32]>,
    ) -> Result<Self, QRunV05PowRuntimeError> {
        let genesis = QRunGenesisV05::new(network_id, owner_account)?;
        let proposed_qrun_identity = network_id == PROPOSED_QRUN_V05_NETWORK_ID
            && owner_account == PROPOSED_OWNER_ACCOUNT_ID;
        if params.protocol_version == 5 && !proposed_qrun_identity {
            return Err(QRunV05PowRuntimeError::WrongNetwork);
        }
        if params.protocol_version == 5 {
            let store = PrivateTestnetForkStore::open_qrun_v05_fee_only_from_checkpoint(
                directory,
                genesis.ledger().clone(),
                params.clone(),
                authenticator,
                clock,
                checkpoint_bytes,
                checkpoint_commitment,
                minimum_checkpoint_height,
                expected_manifest_anchor,
            )?;
            let runtime = Self {
                network_id,
                owner_account,
                genesis_commitment: genesis.commitment(),
                params,
                store,
                fee_only: true,
                producer_account: owner_account,
            };
            runtime.validate_all_branch_supplies()?;
            return Ok(runtime);
        }

        // Legacy fixture profiles retain their historical checkpoint path. QRun v0.5 above uses
        // the profile-locked QRCP-to-QFP5 PFS2 store so the execution mode cannot downgrade.
        let base_chain = QRunV05PowCheckpoint::restore_chain_anchored(
            checkpoint_bytes,
            &network_id,
            &genesis.commitment(),
            &params,
            checkpoint_commitment,
            minimum_checkpoint_height,
        )?;
        Self::open_inner(
            directory,
            network_id,
            owner_account,
            params,
            authenticator,
            clock,
            expected_manifest_anchor,
            Some(base_chain),
        )
    }

    /// Reopen only if the branch manifest matches an anchor stored independently by the operator.
    pub fn open_anchored<A: TransactionAuthenticator>(
        directory: impl AsRef<Path>,
        network_id: NetworkId,
        owner_account: AccountId,
        params: ConsensusParameters,
        authenticator: &A,
        clock: &dyn ReferenceTimeProvider,
        expected_manifest_anchor: [u8; 32],
    ) -> Result<Self, QRunV05PowRuntimeError> {
        Self::open_inner(
            directory,
            network_id,
            owner_account,
            params,
            authenticator,
            clock,
            Some(expected_manifest_anchor),
            None,
        )
    }

    fn open_inner<A: TransactionAuthenticator>(
        directory: impl AsRef<Path>,
        network_id: NetworkId,
        owner_account: AccountId,
        params: ConsensusParameters,
        authenticator: &A,
        clock: &dyn ReferenceTimeProvider,
        anchor: Option<[u8; 32]>,
        base_chain: Option<PrivateTestnetChain>,
    ) -> Result<Self, QRunV05PowRuntimeError> {
        params.validate()?;
        if params.issuance.maximum_supply() != MAX_TOTAL_SUPPLY_ATOMS
            || params
                .issuance
                .reward_for_block(1, MAX_TOTAL_SUPPLY_ATOMS)
                .map_err(|error| QRunV05PowRuntimeError::InvalidCandidate(error.to_string()))?
                != 0
        {
            return Err(QRunV05PowRuntimeError::WrongSupplyProfile);
        }
        let genesis = QRunGenesisV05::new(network_id, owner_account)?;
        let actual = genesis.total_supply_atoms()?;
        if actual != MAX_TOTAL_SUPPLY_ATOMS {
            return Err(QRunV05PowRuntimeError::SupplyMismatch {
                expected: MAX_TOTAL_SUPPLY_ATOMS,
                actual,
            });
        }
        let genesis_commitment = genesis.commitment();
        let proposed_qrun_identity = network_id == PROPOSED_QRUN_V05_NETWORK_ID
            && owner_account == PROPOSED_OWNER_ACCOUNT_ID;
        if params.protocol_version == 5 && !proposed_qrun_identity {
            return Err(QRunV05PowRuntimeError::WrongNetwork);
        }
        let fee_only = params.protocol_version == 5 && proposed_qrun_identity;
        if fee_only && base_chain.is_some() {
            return Err(QRunV05PowRuntimeError::InvalidCandidate(
                "QRun checkpoint-rooted startup must use the QFP5 checkpoint-store API".into(),
            ));
        }
        let store = if fee_only {
            match anchor {
                Some(expected) => PrivateTestnetForkStore::open_qrun_v05_fee_only_anchored(
                    directory,
                    genesis.ledger().clone(),
                    params.clone(),
                    authenticator,
                    clock,
                    expected,
                )?,
                None => PrivateTestnetForkStore::open_qrun_v05_fee_only(
                    directory,
                    genesis.ledger().clone(),
                    params.clone(),
                    authenticator,
                    clock,
                )?,
            }
        } else {
            match base_chain {
                Some(base) => PrivateTestnetForkStore::open_from_base_chain(
                    directory,
                    base,
                    params.clone(),
                    authenticator,
                    clock,
                    anchor,
                )?,
                None => match anchor {
                    Some(expected) => PrivateTestnetForkStore::open_anchored(
                        directory,
                        genesis.ledger().clone(),
                        params.clone(),
                        authenticator,
                        clock,
                        expected,
                    )?,
                    None => PrivateTestnetForkStore::open(
                        directory,
                        genesis.ledger().clone(),
                        params.clone(),
                        authenticator,
                        clock,
                    )?,
                },
            }
        };
        let runtime = Self {
            network_id,
            owner_account,
            genesis_commitment,
            params,
            store,
            fee_only,
            producer_account: owner_account,
        };
        runtime.validate_all_branch_supplies()?;
        Ok(runtime)
    }

    /// Mine a block on the selected branch. QRun v0.5 uses the producer-bound QFP5 fee-only
    /// envelope; legacy fixture profiles retain PTB2 solely for compatibility tests.
    pub fn mine_candidate<A: TransactionAuthenticator>(
        &self,
        timestamp: u64,
        transactions: Vec<Transaction>,
        authenticator: &A,
        max_attempts: u64,
    ) -> Result<Vec<u8>, QRunV05PowRuntimeError> {
        self.mine_candidate_for_producer(
            timestamp,
            transactions,
            self.producer_account,
            authenticator,
            max_attempts,
        )
    }

    /// Set the fee beneficiary used by this process's miner. A producer receives only the fees
    /// actually paid by included transactions; QRun v0.5 never creates a block subsidy.
    pub fn set_producer_account(
        &mut self,
        producer: AccountId,
    ) -> Result<(), QRunV05PowRuntimeError> {
        if producer == [0; 32] {
            return Err(QRunV05PowRuntimeError::InvalidCandidate(
                "producer account must be nonzero".into(),
            ));
        }
        self.producer_account = producer;
        Ok(())
    }

    pub fn is_qrun_v05_fee_only(&self) -> bool {
        self.fee_only
    }

    pub fn mine_candidate_for_producer<A: TransactionAuthenticator>(
        &self,
        timestamp: u64,
        transactions: Vec<Transaction>,
        producer: AccountId,
        authenticator: &A,
        max_attempts: u64,
    ) -> Result<Vec<u8>, QRunV05PowRuntimeError> {
        if self.fee_only {
            return self.mine_fee_candidate(
                timestamp,
                transactions,
                producer,
                authenticator,
                max_attempts,
            );
        }
        self.mine_legacy_candidate(timestamp, transactions, authenticator, max_attempts)
    }

    fn mine_legacy_candidate<A: TransactionAuthenticator>(
        &self,
        timestamp: u64,
        transactions: Vec<Transaction>,
        authenticator: &A,
        max_attempts: u64,
    ) -> Result<Vec<u8>, QRunV05PowRuntimeError> {
        if max_attempts == 0 {
            return Err(QRunV05PowRuntimeError::MiningExhausted { attempts: 0 });
        }
        let chain: PrivateTestnetChain = self.store.archive().canonical_chain().clone();
        if timestamp <= chain.state().last_timestamp() {
            return Err(QRunV05PowRuntimeError::InvalidCandidate(
                "candidate timestamp must exceed parent timestamp".into(),
            ));
        }
        let mut block = Block {
            height: chain.state().height().checked_add(1).ok_or_else(|| {
                QRunV05PowRuntimeError::InvalidCandidate("height overflow".into())
            })?,
            timestamp,
            parent_hash: chain.state().tip_hash(),
            state_root: [0; 32],
            transactions,
        };
        block.state_root = chain
            .state()
            .preview_state_root_after(&block, authenticator)?;
        let target = chain
            .expected_target(None)
            .map_err(|error| QRunV05PowRuntimeError::InvalidCandidate(error.to_string()))?;
        let mut header = PowHeader {
            protocol_version: self.params.protocol_version,
            network_id: self.network_id,
            height: block.height,
            timestamp,
            parent_hash: block.parent_hash,
            previous_consensus_hash: chain.chain_tip().tip_hash,
            state_root: block.state_root,
            target,
            nonce: 0,
        };
        for nonce in 0..max_attempts {
            header.nonce = nonce;
            let digest = pow_digest(&header, self.params.pow)?;
            if Uint256::from_be_bytes(digest) <= target {
                return encode_candidate_network_block(&header, &block).map_err(Into::into);
            }
        }
        Err(QRunV05PowRuntimeError::MiningExhausted {
            attempts: max_attempts,
        })
    }

    fn mine_fee_candidate<A: TransactionAuthenticator>(
        &self,
        timestamp: u64,
        transactions: Vec<Transaction>,
        producer: AccountId,
        authenticator: &A,
        max_attempts: u64,
    ) -> Result<Vec<u8>, QRunV05PowRuntimeError> {
        if max_attempts == 0 {
            return Err(QRunV05PowRuntimeError::MiningExhausted { attempts: 0 });
        }
        if producer == [0; 32] {
            return Err(QRunV05PowRuntimeError::InvalidCandidate(
                "producer account must be nonzero".into(),
            ));
        }
        let chain: PrivateTestnetChain = self.store.archive().canonical_chain().clone();
        if timestamp <= chain.state().last_timestamp() {
            return Err(QRunV05PowRuntimeError::InvalidCandidate(
                "candidate timestamp must exceed parent timestamp".into(),
            ));
        }
        let height =
            chain.state().height().checked_add(1).ok_or_else(|| {
                QRunV05PowRuntimeError::InvalidCandidate("height overflow".into())
            })?;
        let mut fee_block = QRunV05FeeBlock {
            body: Block {
                height,
                timestamp,
                parent_hash: chain.state().tip_hash(),
                state_root: [0; 32],
                transactions,
            },
            producer,
        };
        fee_block.body.state_root = chain
            .state()
            .preview_qrun_v05_fee_state_root_after(&fee_block, authenticator)?;
        let commitment = qrun_v05_fee_pow_state_commitment(&fee_block).map_err(|error| {
            QRunV05PowRuntimeError::InvalidCandidate(format!("QFP5 commitment: {error:?}"))
        })?;
        let target = chain
            .expected_target(None)
            .map_err(|error| QRunV05PowRuntimeError::InvalidCandidate(error.to_string()))?;
        let mut header = PowHeader {
            protocol_version: self.params.protocol_version,
            network_id: self.network_id,
            height,
            timestamp,
            parent_hash: fee_block.body.parent_hash,
            previous_consensus_hash: chain.chain_tip().tip_hash,
            state_root: commitment,
            target,
            nonce: 0,
        };
        for nonce in 0..max_attempts {
            header.nonce = nonce;
            let digest = pow_digest(&header, self.params.pow)?;
            if Uint256::from_be_bytes(digest) <= target {
                return encode_qrun_v05_fee_pow_block(&header, &fee_block).map_err(|error| {
                    QRunV05PowRuntimeError::InvalidCandidate(format!("encode QFP5: {error:?}"))
                });
            }
        }
        Err(QRunV05PowRuntimeError::MiningExhausted {
            attempts: max_attempts,
        })
    }

    /// Validate and persist a candidate branch. Reorganizations use shared PoW fork choice.
    pub fn submit_block<A: TransactionAuthenticator>(
        &mut self,
        envelope: &[u8],
        authenticator: &A,
        clock: &dyn ReferenceTimeProvider,
    ) -> Result<[u8; 32], QRunV05PowRuntimeError> {
        let candidate = decode_candidate_network_block(envelope)?;
        if candidate.fee_block.is_some() != self.fee_only {
            return Err(QRunV05PowRuntimeError::UnsupportedEnvelopeMode);
        }
        if candidate.header.network_id != self.network_id {
            return Err(QRunV05PowRuntimeError::WrongNetwork);
        }
        let outcome = self.store.submit(envelope, authenticator, clock)?;
        self.validate_all_branch_supplies()?;
        Ok(outcome.canonical_tip)
    }

    fn validate_all_branch_supplies(&self) -> Result<(), QRunV05PowRuntimeError> {
        let canonical_supply = self
            .store
            .archive()
            .canonical_chain()
            .state()
            .total_value()?;
        if canonical_supply != MAX_TOTAL_SUPPLY_ATOMS {
            return Err(QRunV05PowRuntimeError::SupplyMismatch {
                expected: MAX_TOTAL_SUPPLY_ATOMS,
                actual: canonical_supply,
            });
        }
        for envelope in self.store.archive().archive_envelopes() {
            let candidate = decode_candidate_network_block(&envelope)?;
            let digest = pow_digest(&candidate.header, self.params.pow)?;
            let branch = self
                .store
                .archive()
                .branch_chain(&digest)
                .ok_or(QRunV05PowRuntimeError::UnknownArchivedBranch)?;
            let actual = branch.state().total_value()?;
            if actual != MAX_TOTAL_SUPPLY_ATOMS {
                return Err(QRunV05PowRuntimeError::SupplyMismatch {
                    expected: MAX_TOTAL_SUPPLY_ATOMS,
                    actual,
                });
            }
        }
        Ok(())
    }

    pub fn network_id(&self) -> NetworkId {
        self.network_id
    }
    pub fn owner_account(&self) -> AccountId {
        self.owner_account
    }
    pub fn genesis_commitment(&self) -> [u8; 32] {
        self.genesis_commitment
    }
    pub fn canonical_height(&self) -> u64 {
        self.store.canonical_height()
    }
    pub fn canonical_tip(&self) -> [u8; 32] {
        self.store.canonical_tip()
    }
    pub fn canonical_state_root(&self) -> [u8; 32] {
        self.store.archive().canonical_chain().state().state_root()
    }
    pub fn canonical_state(&self) -> &LedgerState {
        self.store.archive().canonical_chain().state()
    }

    /// Height of the latest trusted checkpoint/base for bounded archive-range service.
    pub fn archive_base_height(&self) -> u64 {
        self.store.archive().base_height()
    }

    /// Digest of the trusted checkpoint/base tip for bounded archive-range service.
    pub fn archive_base_tip(&self) -> [u8; 32] {
        self.store.archive().genesis_tip()
    }

    /// Export a size-bounded page of the canonical chain at absolute heights.
    /// Historical data before the checkpoint base must come from a separately authenticated source.
    pub fn canonical_envelopes_range(
        &self,
        start_height: u64,
        max_blocks: usize,
        max_bytes: usize,
    ) -> Result<Vec<Vec<u8>>, QRunV05PowRuntimeError> {
        self.store
            .archive()
            .canonical_envelopes_range(start_height, max_blocks, max_bytes)
            .map_err(|error| QRunV05PowRuntimeError::InvalidCandidate(error.to_string()))
    }

    /// Rebuild transaction locations from the selected branch after restart or reorganization.
    /// A transaction present only in a losing branch is never reported as canonically included.
    pub fn canonical_transaction_locations(
        &self,
    ) -> Result<Vec<([u8; 32], u64)>, QRunV05PowRuntimeError> {
        let envelopes = self
            .store
            .archive()
            .canonical_envelopes()
            .map_err(|error| QRunV05PowRuntimeError::InvalidCandidate(error.to_string()))?;
        let mut locations = Vec::new();
        for envelope in envelopes {
            let candidate = decode_candidate_network_block(&envelope)?;
            for transaction in &candidate.block.transactions {
                locations.push((transaction_id(transaction)?, candidate.block.height));
            }
        }
        Ok(locations)
    }

    pub fn retained_branch_count(&self) -> usize {
        self.store.archive().archive_len()
    }
    pub fn manifest_anchor(&self) -> Result<[u8; 32], QRunV05PowRuntimeError> {
        self.store.manifest_anchor().map_err(Into::into)
    }

    /// Export a canonical, profile-bound checkpoint for the long-term archive pipeline.
    /// A non-Genesis checkpoint must link to the prior checkpoint commitment. Export does not
    /// itself make the checkpoint trusted; consumers must obtain its commitment independently.
    pub fn export_checkpoint(
        &self,
        parent_checkpoint_commitment: [u8; 32],
    ) -> Result<Vec<u8>, QRunCheckpointError> {
        let chain = self.store.archive().canonical_chain();
        QRunV05PowCheckpoint::capture(
            self.network_id,
            self.genesis_commitment,
            &self.params,
            chain,
            parent_checkpoint_commitment,
        )?
        .encode(&self.params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_admission::{
        ReferenceTimeError, ReferenceTimeProvenance, ReferenceTimeSample,
    };
    use std::{
        fs,
        path::PathBuf,
        process,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);
    struct TestDir(PathBuf);
    impl TestDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "qrun_v05_pow_fork_runtime_{}_{}",
                process::id(),
                NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct EmptyAuthenticator;
    impl TransactionAuthenticator for EmptyAuthenticator {
        fn verify(&self, _: &AccountId, _: &[u8; 32], _: &[u8]) -> Result<(), ()> {
            Err(())
        }
    }
    struct FixedClock;
    impl ReferenceTimeProvider for FixedClock {
        fn sample(&self) -> Result<ReferenceTimeSample, ReferenceTimeError> {
            Ok(ReferenceTimeSample {
                unix_seconds: 1_000_000,
                provenance: ReferenceTimeProvenance::ConfiguredProvider,
                source_id: "qrun-pow-runtime-test-clock",
            })
        }
    }
    fn params() -> ConsensusParameters {
        let mut params = ConsensusParameters::candidate_testnet().unwrap();
        params.initial_target = Uint256::MAX;
        params.pow_limit = Uint256::MAX;
        params.pow.memory_kib = 8 * 1024;
        params.pow.iterations = 1;
        params
    }

    fn make_qfp5_fee_envelope(
        network: NetworkId,
        owner: AccountId,
        params: &ConsensusParameters,
    ) -> Vec<u8> {
        use crate::{
            qrun_v05_fee_pow_wire_candidate::{
                encode_qrun_v05_fee_pow_block, qrun_v05_fee_pow_state_commitment,
            },
            state_machine::QRunV05FeeBlock,
        };
        let genesis = QRunGenesisV05::new(network, owner).unwrap();
        let ledger = genesis.ledger().clone();
        let mut fee_block = QRunV05FeeBlock {
            body: Block {
                height: 1,
                timestamp: 1,
                parent_hash: ledger.tip_hash(),
                state_root: [0; 32],
                transactions: Vec::new(),
            },
            producer: [0x77; 32],
        };
        fee_block.body.state_root = ledger
            .preview_qrun_v05_fee_state_root_after(&fee_block, &EmptyAuthenticator)
            .unwrap();
        let header = PowHeader {
            protocol_version: params.protocol_version,
            network_id: network,
            height: 1,
            timestamp: 1,
            parent_hash: fee_block.body.parent_hash,
            previous_consensus_hash: ledger.tip_hash(),
            state_root: qrun_v05_fee_pow_state_commitment(&fee_block).unwrap(),
            target: params.initial_target,
            nonce: 0,
        };
        encode_qrun_v05_fee_pow_block(&header, &fee_block).unwrap()
    }

    fn make_test_envelope<A: TransactionAuthenticator>(
        chain: &crate::private_testnet_driver::PrivateTestnetChain,
        params: &ConsensusParameters,
        transactions: Vec<Transaction>,
        timestamp: u64,
        nonce: u64,
        authenticator: &A,
    ) -> Vec<u8> {
        let mut block = Block {
            height: chain.state().height() + 1,
            timestamp,
            parent_hash: chain.state().tip_hash(),
            state_root: [0; 32],
            transactions,
        };
        block.state_root = chain
            .state()
            .preview_state_root_after(&block, authenticator)
            .unwrap();
        let header = PowHeader {
            protocol_version: params.protocol_version,
            network_id: chain.state().network_id(),
            height: block.height,
            timestamp,
            parent_hash: block.parent_hash,
            previous_consensus_hash: chain.chain_tip().tip_hash,
            state_root: block.state_root,
            target: chain.expected_target(None).unwrap(),
            nonce,
        };
        encode_candidate_network_block(&header, &block).unwrap()
    }

    #[test]
    fn qrun_fee_only_runtime_mines_submits_and_replays_qfp5_blocks() {
        let dir = TestDir::new();
        let network = PROPOSED_QRUN_V05_NETWORK_ID;
        let owner = PROPOSED_OWNER_ACCOUNT_ID;
        let mut params = params();
        params.protocol_version = 5;
        let clock = FixedClock;

        let mut runtime = QRunV05PowForkRuntime::open(
            &dir.0,
            network,
            owner,
            params.clone(),
            &EmptyAuthenticator,
            &clock,
        )
        .unwrap();
        assert!(runtime.is_qrun_v05_fee_only());
        assert_eq!(runtime.canonical_height(), 0);
        assert_eq!(
            runtime.canonical_state().total_value().unwrap(),
            MAX_TOTAL_SUPPLY_ATOMS
        );
        assert_eq!(
            runtime.canonical_state().account(&owner).unwrap().balance as u128,
            MAX_TOTAL_SUPPLY_ATOMS
        );

        let envelope = runtime
            .mine_candidate(1, Vec::new(), &EmptyAuthenticator, 1)
            .unwrap();
        assert!(envelope.starts_with(b"QFP5"));
        runtime
            .submit_block(&envelope, &EmptyAuthenticator, &clock)
            .unwrap();
        assert_eq!(runtime.canonical_height(), 1);
        assert_eq!(
            runtime.canonical_state().total_value().unwrap(),
            MAX_TOTAL_SUPPLY_ATOMS
        );
        let committed_root = runtime.canonical_state_root();
        let committed_tip = runtime.canonical_tip();
        drop(runtime);

        let reopened = QRunV05PowForkRuntime::open(
            &dir.0,
            network,
            owner,
            params,
            &EmptyAuthenticator,
            &clock,
        )
        .unwrap();
        assert!(reopened.is_qrun_v05_fee_only());
        assert_eq!(reopened.canonical_height(), 1);
        assert_eq!(reopened.canonical_tip(), committed_tip);
        assert_eq!(reopened.canonical_state_root(), committed_root);
        assert_eq!(
            reopened.canonical_state().total_value().unwrap(),
            MAX_TOTAL_SUPPLY_ATOMS
        );
        assert_eq!(
            reopened.canonical_state().account(&owner).unwrap().balance as u128,
            MAX_TOTAL_SUPPLY_ATOMS
        );
    }

    #[test]
    fn reorg_drops_receipts_from_losing_branch_and_restores_winning_branch_index() {
        use crate::{
            consensus::pow_digest,
            private_testnet_wire::decode_candidate_network_block,
            transaction_auth::{
                AccountPublicKey, Ed25519TransactionAuthenticator, Ed25519TransactionSigner,
                TransactionAuthenticatorKind,
            },
        };

        let dir = TestDir::new();
        let network = [0x51; 32];
        let signer = Ed25519TransactionSigner::from_seed([0x47; 32]);
        let owner = signer.account_id();
        let recipient_a = [0x81; 32];
        let recipient_b = [0x82; 32];
        let authenticator = Ed25519TransactionAuthenticator::select(
            TransactionAuthenticatorKind::Ed25519V1,
            [AccountPublicKey {
                account_id: owner,
                public_key: signer.public_key(),
            }],
        )
        .unwrap();
        let clock = FixedClock;
        let params = params();
        let genesis = QRunGenesisV05::new(network, owner).unwrap();
        let base_chain = crate::private_testnet_driver::PrivateTestnetChain::new(
            genesis.ledger().clone(),
            params.clone(),
        )
        .unwrap();

        let mut tx_a = Transaction {
            network_id: network,
            sender: owner,
            recipient: recipient_a,
            nonce: 1,
            amount: 111,
            fee: 1,
            expires_at: 10_000,
            signature: Vec::new(),
        };
        signer.sign_transaction(&mut tx_a).unwrap();
        let mut tx_b = Transaction {
            network_id: network,
            sender: owner,
            recipient: recipient_b,
            nonce: 1,
            amount: 222,
            fee: 1,
            expires_at: 10_000,
            signature: Vec::new(),
        };
        signer.sign_transaction(&mut tx_b).unwrap();

        let envelope_a = make_test_envelope(
            &base_chain,
            &params,
            vec![tx_a.clone()],
            100,
            10,
            &authenticator,
        );
        let envelope_b = make_test_envelope(
            &base_chain,
            &params,
            vec![tx_b.clone()],
            100,
            11,
            &authenticator,
        );
        let digest_a = pow_digest(
            &decode_candidate_network_block(&envelope_a).unwrap().header,
            params.pow,
        )
        .unwrap();
        let digest_b = pow_digest(
            &decode_candidate_network_block(&envelope_b).unwrap().header,
            params.pow,
        )
        .unwrap();
        assert_ne!(digest_a, digest_b);

        let (winner, loser, winner_txid, loser_txid) = if digest_a < digest_b {
            (
                &envelope_a,
                &envelope_b,
                transaction_id(&tx_a).unwrap(),
                transaction_id(&tx_b).unwrap(),
            )
        } else {
            (
                &envelope_b,
                &envelope_a,
                transaction_id(&tx_b).unwrap(),
                transaction_id(&tx_a).unwrap(),
            )
        };

        let mut runtime = QRunV05PowForkRuntime::open(
            &dir.0,
            network,
            owner,
            params.clone(),
            &authenticator,
            &clock,
        )
        .unwrap();
        runtime
            .submit_block(winner, &authenticator, &clock)
            .unwrap();
        assert_eq!(
            runtime.canonical_transaction_locations().unwrap(),
            vec![(winner_txid, 1)]
        );
        runtime.submit_block(loser, &authenticator, &clock).unwrap();
        assert_eq!(
            runtime.canonical_transaction_locations().unwrap(),
            vec![(winner_txid, 1)]
        );

        // Extend the losing branch so cumulative work makes that branch canonical.
        let decoded_loser = decode_candidate_network_block(loser).unwrap();
        let mut losing_chain = crate::private_testnet_driver::PrivateTestnetChain::new(
            genesis.ledger().clone(),
            params.clone(),
        )
        .unwrap();
        losing_chain
            .append_live(
                &decoded_loser.block,
                &decoded_loser.header,
                None,
                &authenticator,
                &clock,
            )
            .unwrap();
        let child = make_test_envelope(&losing_chain, &params, Vec::new(), 101, 12, &authenticator);
        runtime
            .submit_block(&child, &authenticator, &clock)
            .unwrap();

        assert_eq!(runtime.canonical_height(), 2);
        assert_eq!(
            runtime.canonical_transaction_locations().unwrap(),
            vec![(loser_txid, 1)]
        );
        assert_eq!(
            runtime
                .canonical_state()
                .account(
                    &decode_candidate_network_block(loser)
                        .unwrap()
                        .block
                        .transactions[0]
                        .recipient
                )
                .unwrap()
                .balance,
            if loser_txid == transaction_id(&tx_a).unwrap() {
                111
            } else {
                222
            }
        );
        assert_eq!(
            runtime.canonical_state().total_value().unwrap(),
            MAX_TOTAL_SUPPLY_ATOMS
        );
        assert_ne!(winner_txid, loser_txid);
    }

    #[test]
    fn qrun_fee_only_runtime_resumes_from_checkpoint_and_reopens_qfp5_suffix() {
        let base_dir = TestDir::new();
        let suffix_dir = TestDir::new();
        let network = PROPOSED_QRUN_V05_NETWORK_ID;
        let owner = PROPOSED_OWNER_ACCOUNT_ID;
        let mut params = params();
        params.protocol_version = 5;

        let mut base = QRunV05PowForkRuntime::open(
            &base_dir.0,
            network,
            owner,
            params.clone(),
            &EmptyAuthenticator,
            &FixedClock,
        )
        .unwrap();
        assert!(base.is_qrun_v05_fee_only());
        let first = base
            .mine_candidate(100, Vec::new(), &EmptyAuthenticator, 1)
            .unwrap();
        assert!(first.starts_with(b"QFP5"));
        base.submit_block(&first, &EmptyAuthenticator, &FixedClock)
            .unwrap();
        assert_eq!(base.canonical_height(), 1);
        let base_root = base.canonical_state_root();
        let checkpoint_bytes = base.export_checkpoint([0x91; 32]).unwrap();
        let checkpoint_commitment = QRunV05PowCheckpoint::commitment_for_bytes(&checkpoint_bytes);

        let mut suffix = QRunV05PowForkRuntime::open_from_checkpoint(
            &suffix_dir.0,
            network,
            owner,
            params.clone(),
            &EmptyAuthenticator,
            &FixedClock,
            &checkpoint_bytes,
            checkpoint_commitment,
            1,
            None,
        )
        .unwrap();
        assert!(suffix.is_qrun_v05_fee_only());
        assert_eq!(suffix.canonical_height(), 1);
        assert_eq!(suffix.canonical_state_root(), base_root);
        assert_eq!(
            suffix.canonical_state().total_value().unwrap(),
            MAX_TOTAL_SUPPLY_ATOMS
        );

        let continuation = suffix
            .mine_candidate(101, Vec::new(), &EmptyAuthenticator, 1)
            .unwrap();
        assert!(continuation.starts_with(b"QFP5"));
        suffix
            .submit_block(&continuation, &EmptyAuthenticator, &FixedClock)
            .unwrap();
        assert_eq!(suffix.canonical_height(), 2);
        let suffix_root = suffix.canonical_state_root();
        let manifest_anchor = suffix.manifest_anchor().unwrap();
        drop(suffix);

        assert!(QRunV05PowForkRuntime::open_from_checkpoint(
            &suffix_dir.0,
            network,
            owner,
            params.clone(),
            &EmptyAuthenticator,
            &FixedClock,
            &checkpoint_bytes,
            checkpoint_commitment,
            1,
            None,
        )
        .is_err());

        let reopened = QRunV05PowForkRuntime::open_from_checkpoint(
            &suffix_dir.0,
            network,
            owner,
            params,
            &EmptyAuthenticator,
            &FixedClock,
            &checkpoint_bytes,
            checkpoint_commitment,
            1,
            Some(manifest_anchor),
        )
        .unwrap();
        assert!(reopened.is_qrun_v05_fee_only());
        assert_eq!(reopened.canonical_height(), 2);
        assert_eq!(reopened.canonical_state_root(), suffix_root);
        assert_eq!(
            reopened.canonical_state().total_value().unwrap(),
            MAX_TOTAL_SUPPLY_ATOMS
        );
    }

    #[test]
    fn legacy_pow_runtime_rejects_qfp5_without_publishing_or_mutating_state() {
        let dir = TestDir::new();
        let network = [0x51; 32];
        let owner = [0x62; 32];
        let params = params();
        let envelope = make_qfp5_fee_envelope(network, owner, &params);
        let mut runtime = QRunV05PowForkRuntime::open(
            &dir.0,
            network,
            owner,
            params,
            &EmptyAuthenticator,
            &FixedClock,
        )
        .unwrap();
        let anchor_before = runtime.manifest_anchor().unwrap();

        assert!(matches!(
            runtime.submit_block(&envelope, &EmptyAuthenticator, &FixedClock),
            Err(QRunV05PowRuntimeError::UnsupportedEnvelopeMode)
        ));
        assert_eq!(runtime.canonical_height(), 0);
        assert_eq!(runtime.retained_branch_count(), 0);
        assert_eq!(runtime.manifest_anchor().unwrap(), anchor_before);
        assert_eq!(
            runtime.canonical_state().total_value().unwrap(),
            MAX_TOTAL_SUPPLY_ATOMS
        );
    }

    #[test]
    fn qrun_pow_runtime_mines_persists_and_reopens_full_supply_chain() {
        let dir = TestDir::new();
        let network = [0x51; 32];
        let owner = [0x2a; 32];
        let params = params();
        let mut runtime = QRunV05PowForkRuntime::open(
            &dir.0,
            network,
            owner,
            params.clone(),
            &EmptyAuthenticator,
            &FixedClock,
        )
        .unwrap();
        assert_eq!(runtime.canonical_height(), 0);
        assert_eq!(
            runtime.canonical_state().total_value().unwrap(),
            MAX_TOTAL_SUPPLY_ATOMS
        );

        let envelope = runtime
            .mine_candidate(100, Vec::new(), &EmptyAuthenticator, 1)
            .unwrap();
        runtime
            .submit_block(&envelope, &EmptyAuthenticator, &FixedClock)
            .unwrap();
        assert_eq!(runtime.canonical_height(), 1);
        assert_eq!(
            runtime.canonical_state().total_value().unwrap(),
            MAX_TOTAL_SUPPLY_ATOMS
        );
        let checkpoint_bytes = runtime.export_checkpoint([0x91; 32]).unwrap();
        let checkpoint_commitment = QRunV05PowCheckpoint::commitment_for_bytes(&checkpoint_bytes);
        let restored_checkpoint = QRunV05PowCheckpoint::decode_anchored(
            &checkpoint_bytes,
            &network,
            &runtime.genesis_commitment(),
            &params,
            checkpoint_commitment,
            1,
        )
        .unwrap();
        assert_eq!(restored_checkpoint.height, 1);
        assert_eq!(
            restored_checkpoint.state_root,
            runtime.canonical_state_root()
        );
        assert_eq!(
            restored_checkpoint.cumulative_work,
            runtime.store.archive().canonical_chain().cumulative_work()
        );
        let restored_chain = QRunV05PowCheckpoint::restore_chain_anchored(
            &checkpoint_bytes,
            &network,
            &runtime.genesis_commitment(),
            &params,
            checkpoint_commitment,
            1,
        )
        .unwrap();
        assert_eq!(
            restored_chain.chain_tip().height,
            runtime.canonical_height()
        );
        assert_eq!(restored_chain.chain_tip().tip_hash, runtime.canonical_tip());
        assert_eq!(
            restored_chain.chain_tip().cumulative_work,
            runtime.store.archive().canonical_chain().cumulative_work()
        );
        assert_eq!(
            restored_chain.state().state_root(),
            runtime.canonical_state_root()
        );
        assert_eq!(
            restored_chain.state().total_value().unwrap(),
            MAX_TOTAL_SUPPLY_ATOMS
        );
        // Exercise checkpoint-rooted durable suffix storage, not only checkpoint decoding.
        let suffix_dir = TestDir::new();
        let mut segmented = QRunV05PowForkRuntime::open_from_checkpoint(
            &suffix_dir.0,
            network,
            owner,
            params.clone(),
            &EmptyAuthenticator,
            &FixedClock,
            &checkpoint_bytes,
            checkpoint_commitment,
            1,
            None,
        )
        .unwrap();
        assert_eq!(segmented.canonical_height(), 1);
        assert_eq!(
            segmented.canonical_tip(),
            restored_chain.chain_tip().tip_hash
        );
        assert_eq!(
            segmented.canonical_state_root(),
            runtime.canonical_state_root()
        );
        let continuation = segmented
            .mine_candidate(101, Vec::new(), &EmptyAuthenticator, 1)
            .unwrap();
        segmented
            .submit_block(&continuation, &EmptyAuthenticator, &FixedClock)
            .unwrap();
        assert_eq!(segmented.canonical_height(), 2);
        assert_eq!(
            segmented.canonical_state().total_value().unwrap(),
            MAX_TOTAL_SUPPLY_ATOMS
        );
        let suffix_root = segmented.canonical_state_root();
        let suffix_manifest_anchor = segmented.manifest_anchor().unwrap();
        drop(segmented);

        // Reopening an existing checkpoint-rooted segment without the out-of-band manifest
        // anchor must fail closed instead of accepting a local-only rollback of its suffix.
        assert!(QRunV05PowForkRuntime::open_from_checkpoint(
            &suffix_dir.0,
            network,
            owner,
            params.clone(),
            &EmptyAuthenticator,
            &FixedClock,
            &checkpoint_bytes,
            checkpoint_commitment,
            1,
            None,
        )
        .is_err());

        let segmented_reopened = QRunV05PowForkRuntime::open_from_checkpoint(
            &suffix_dir.0,
            network,
            owner,
            params.clone(),
            &EmptyAuthenticator,
            &FixedClock,
            &checkpoint_bytes,
            checkpoint_commitment,
            1,
            Some(suffix_manifest_anchor),
        )
        .unwrap();
        assert_eq!(segmented_reopened.canonical_height(), 2);
        assert_eq!(segmented_reopened.canonical_state_root(), suffix_root);

        let root = runtime.canonical_state_root();
        let commitment = runtime.genesis_commitment();
        drop(runtime);

        let reopened = QRunV05PowForkRuntime::open(
            &dir.0,
            network,
            owner,
            params,
            &EmptyAuthenticator,
            &FixedClock,
        )
        .unwrap();
        assert_eq!(reopened.genesis_commitment(), commitment);
        assert_eq!(reopened.canonical_height(), 1);
        assert_eq!(reopened.canonical_state_root(), root);
        assert_eq!(
            reopened.canonical_state().total_value().unwrap(),
            MAX_TOTAL_SUPPLY_ATOMS
        );
    }
}
