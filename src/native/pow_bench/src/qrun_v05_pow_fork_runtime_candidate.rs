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
    qrun_v05_genesis_candidate::{QRunGenesisError, QRunGenesisV05},
    state_machine::{
        transaction_id, AccountId, Block, LedgerState, NetworkId, StateError, Transaction,
        TransactionAuthenticator, MAX_TOTAL_SUPPLY_ATOMS,
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
    SupplyMismatch { expected: u128, actual: u128 },
    InvalidCandidate(String),
    MiningExhausted { attempts: u64 },
    UnknownArchivedBranch,
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

/// QRun Genesis + deterministic PoW validation + persisted branch selection.
/// Network listeners should submit complete PTB2 envelopes through submit_block.
pub struct QRunV05PowForkRuntime {
    network_id: NetworkId,
    owner_account: AccountId,
    genesis_commitment: [u8; 32],
    params: ConsensusParameters,
    store: PrivateTestnetForkStore,
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
        let store = match anchor {
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
        };
        let runtime = Self {
            network_id,
            owner_account,
            genesis_commitment,
            params,
            store,
        };
        runtime.validate_all_branch_supplies()?;
        Ok(runtime)
    }

    /// Mine a PTB2 envelope on the selected branch. The attempt count is explicitly bounded.
    /// This method uses candidate consensus parameters, not an approved Mainnet mining profile.
    pub fn mine_candidate<A: TransactionAuthenticator>(
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

    /// Validate and persist a candidate branch. Reorganizations use shared PoW fork choice.
    pub fn submit_block<A: TransactionAuthenticator>(
        &mut self,
        envelope: &[u8],
        authenticator: &A,
        clock: &dyn ReferenceTimeProvider,
    ) -> Result<[u8; 32], QRunV05PowRuntimeError> {
        let candidate = decode_candidate_network_block(envelope)?;
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
