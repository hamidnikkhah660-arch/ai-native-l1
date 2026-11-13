//! CP-0590 permissionless full-history base-runtime seam.
//!
//! This runtime deliberately has no Q6EA, Provider, Q6TS, or QAP1 dependency. It opens a
//! Genesis-rooted durable store only after the caller supplies an independently verified
//! profile pin, then validates, executes, and durably commits native QFP6 envelopes by replaying
//! the complete local archive. It is a base-node admission API, not yet a socket listener,
//! peer-discovery/sync daemon, miner supervisor, RPC server, or public Mainnet launcher.

use crate::consensus::{pow_digest, ConsensusParameters};
use crate::qrun_v06_pow_wire_candidate::{
    decode_qrun_v06_pow_block, MAX_QRUN_V06_POW_ENVELOPE_BYTES,
};
use crate::{
    external_cas_anchor_candidate::ExternalCasProviderTransport,
    qrun_v06_canonical_execution_candidate::QRunV06CanonicalExecutionState,
    qrun_v06_node_runtime_candidate::{
        QRunV06NodeAnchorGate, QRunV06NodeRuntime, QRunV06NodeRuntimeError,
    },
    qrun_v06_pow_fork_choice_candidate::QRunV06PowForkChoice,
    qrun_v06_pow_fork_choice_candidate::QRunV06QuoteAssetAuthorizationProvider,
    qrun_v06_pow_fork_store_candidate::{
        QRunV06DurableCommit, QRunV06DurableForkStore, QRunV06ForkStoreError,
    },
    qrun_v06_profile_pin_candidate::QRunV06VerifiedProfilePin,
    qrun_v06_qap1_coordinator_candidate::{
        QRunV06Qap1AnchorTransport, QRunV06Qap1ExternalCoordinator,
    },
    state_machine::TransactionAuthenticator,
    v4_fat1_trust_candidate::MlDsa65Verifier,
};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QRunV06PermissionlessRuntimeError {
    Store(String),
    UnresolvedQap1Intent,
    Qap1Recovery(String),
}

impl std::fmt::Display for QRunV06PermissionlessRuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(error) => write!(f, "QFP6 permissionless base runtime failed: {error}"),
            Self::Qap1Recovery(error) => write!(f, "QFP6 QAP1 recovery failed: {error}"),
            Self::UnresolvedQap1Intent => f.write_str(
                "QFP6 permissionless base runtime refuses a store with unresolved QAP1 intent; recover through the anchored runtime first",
            ),
        }
    }
}
impl std::error::Error for QRunV06PermissionlessRuntimeError {}

impl From<QRunV06ForkStoreError> for QRunV06PermissionlessRuntimeError {
    fn from(value: QRunV06ForkStoreError) -> Self {
        Self::Store(value.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QRunV06PermissionlessRuntimeStatus {
    pub network_id: [u8; 32],
    pub profile_id: [u8; 32],
    pub height: u64,
    pub tip: [u8; 32],
    pub state_root: [u8; 32],
    pub manifest_generation: u64,
    pub manifest_anchor: [u8; 32],
    pub consensus_fingerprint: [u8; 32],
}

pub const QRUN_V06_HISTORY_SYNC_MAX_BATCH_BLOCKS: usize = 128;
pub const QRUN_V06_HISTORY_SYNC_MAX_BATCH_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QRunV06HistorySyncError {
    EmptyBatch,
    BatchTooLarge,
    WrongNetwork,
    WrongProfile,
    InvalidEnvelope(String),
    NonContiguous,
    ApplyFailed {
        index: usize,
        committed_blocks: usize,
        reason: String,
    },
}

impl std::fmt::Display for QRunV06HistorySyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "QFP6 permissionless history sync rejected batch: {self:?}"
        )
    }
}
impl std::error::Error for QRunV06HistorySyncError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QRunV06HistorySyncReport {
    pub imported_blocks: usize,
    pub resulting_height: u64,
    pub resulting_tip: [u8; 32],
    pub resulting_state_root: [u8; 32],
}
/// Permissionless base admission with no mandatory external-anchor dependency.
pub struct QRunV06PermissionlessNodeRuntime {
    store: QRunV06DurableForkStore,
    network_id: [u8; 32],
    profile_id: [u8; 32],
}

impl QRunV06PermissionlessNodeRuntime {
    /// Open a verified-Genesis durable store directly into the QAP1-required node runtime.
    /// Unlike `open`, this constructor allows a saved QAP1 intent to reach the recovery
    /// constructor, which must reconcile it against independently pinned Provider and Q6EA
    /// authorities before exposing an admission-capable runtime.
    ///
    /// All trust inputs (manifest anchor, Genesis digest, profile pin, Provider/Q6EA pins and
    /// verifier keys) must come from independent provisioning channels. Local manifest values
    /// are never promoted into trust anchors here.
    #[allow(clippy::too_many_arguments)]
    pub fn open_qap1<A, P, PV, AV, Q, T>(
        directory: impl AsRef<Path>,
        genesis_state: QRunV06CanonicalExecutionState,
        params: ConsensusParameters,
        authenticator: &T,
        trusted_manifest_anchor: Option<[u8; 32]>,
        verified_profile_pin: &QRunV06VerifiedProfilePin,
        anchor_gate: A,
        coordinator: QRunV06Qap1ExternalCoordinator<P, PV, AV, Q>,
        genesis_digest: [u8; 32],
        quote_authorizer: &mut QRunV06QuoteAssetAuthorizationProvider<'_>,
    ) -> Result<QRunV06NodeRuntime<A>, QRunV06PermissionlessRuntimeError>
    where
        A: QRunV06NodeAnchorGate,
        P: ExternalCasProviderTransport,
        PV: MlDsa65Verifier + Clone,
        AV: MlDsa65Verifier,
        Q: QRunV06Qap1AnchorTransport,
        T: TransactionAuthenticator,
    {
        let descriptor = verified_profile_pin.descriptor();
        let provider_pin = coordinator.provider_pin();
        let qfp6_pin = coordinator.qfp6_pin();
        if provider_pin != verified_profile_pin.bundle().external_cas_pin()
            || qfp6_pin.external_cas_pin() != provider_pin
            || qfp6_pin.genesis_descriptor_commitment() != descriptor.commitment()
            || provider_pin.network_id != descriptor.network_id()
            || provider_pin.genesis_digest != genesis_digest
        {
            return Err(QRunV06PermissionlessRuntimeError::Qap1Recovery(
                "Q6PN, Provider, Q6EA, Genesis digest and descriptor commitments are not the same independently pinned domain".into(),
            ));
        }
        let store = QRunV06DurableForkStore::open_with_verified_profile_pin(
            directory,
            genesis_state,
            params,
            authenticator,
            trusted_manifest_anchor,
            verified_profile_pin,
        )?;
        QRunV06NodeRuntime::recover_qap1_after_process_restart(
            store,
            anchor_gate,
            coordinator,
            genesis_digest,
            authenticator,
            quote_authorizer,
        )
        .map_err(|error: QRunV06NodeRuntimeError| {
            QRunV06PermissionlessRuntimeError::Qap1Recovery(error.to_string())
        })
    }
    /// Open from the complete Genesis-rooted history. The verified profile pin must have been
    /// authenticated out of band; this constructor does not invent or fetch trust material.
    pub fn open<A: TransactionAuthenticator>(
        directory: impl AsRef<Path>,
        genesis_state: QRunV06CanonicalExecutionState,
        params: ConsensusParameters,
        authenticator: &A,
        trusted_manifest_anchor: Option<[u8; 32]>,
        verified_profile_pin: &QRunV06VerifiedProfilePin,
    ) -> Result<Self, QRunV06PermissionlessRuntimeError> {
        let descriptor = verified_profile_pin.descriptor();
        let network_id = descriptor.network_id();
        let profile_id = descriptor.profile_id();
        let store = QRunV06DurableForkStore::open_with_verified_profile_pin(
            directory,
            genesis_state,
            params,
            authenticator,
            trusted_manifest_anchor,
            verified_profile_pin,
        )?;
        if store.has_qap1_intent()? {
            return Err(QRunV06PermissionlessRuntimeError::UnresolvedQap1Intent);
        }
        Ok(Self {
            store,
            network_id,
            profile_id,
        })
    }

    /// Native-only base admission. A successful return means local durable commit, not a
    /// globally acknowledged/network-finalized transaction or block.
    pub fn submit_envelope<A: TransactionAuthenticator>(
        &mut self,
        envelope: &[u8],
        authenticator: &A,
    ) -> Result<QRunV06DurableCommit, QRunV06PermissionlessRuntimeError> {
        if self.store.has_qap1_intent()? {
            return Err(QRunV06PermissionlessRuntimeError::UnresolvedQap1Intent);
        }
        Ok(self.store.submit(envelope, authenticator)?)
    }

    /// Import one bounded, parent-first canonical history batch from an authenticated peer.
    /// The batch must continue exactly from this node's current canonical tip. Every QFP6
    /// envelope is decoded and checked for network/profile and contiguous height/parent links
    /// before any block is committed. Consensus, PoW, execution and durable replay checks remain
    /// authoritative in the durable fork store. If a later commit fails, the error reports the
    /// durable prefix already imported; the caller resumes from the returned local status.
    pub fn import_history_batch<A: TransactionAuthenticator>(
        &mut self,
        envelopes: &[Vec<u8>],
        authenticator: &A,
    ) -> Result<QRunV06HistorySyncReport, QRunV06HistorySyncError> {
        if envelopes.is_empty() {
            return Err(QRunV06HistorySyncError::EmptyBatch);
        }
        if envelopes.len() > QRUN_V06_HISTORY_SYNC_MAX_BATCH_BLOCKS {
            return Err(QRunV06HistorySyncError::BatchTooLarge);
        }
        let initial = self
            .status()
            .map_err(|error| QRunV06HistorySyncError::InvalidEnvelope(error.to_string()))?;
        let mut expected_consensus_parent = initial.tip;
        let expected_execution_parent = self
            .store
            .graph()
            .map_err(|error| QRunV06HistorySyncError::InvalidEnvelope(error.to_string()))?
            .canonical_state()
            .tip_hash();
        let mut expected_height = initial
            .height
            .checked_add(1)
            .ok_or(QRunV06HistorySyncError::BatchTooLarge)?;
        let params = self
            .store
            .graph()
            .map_err(|error| QRunV06HistorySyncError::InvalidEnvelope(error.to_string()))?
            .consensus_parameters()
            .clone();
        let mut total_bytes = 0usize;

        for (index, envelope) in envelopes.iter().enumerate() {
            if envelope.is_empty() || envelope.len() > MAX_QRUN_V06_POW_ENVELOPE_BYTES {
                return Err(QRunV06HistorySyncError::BatchTooLarge);
            }
            total_bytes = total_bytes
                .checked_add(envelope.len())
                .ok_or(QRunV06HistorySyncError::BatchTooLarge)?;
            if total_bytes > QRUN_V06_HISTORY_SYNC_MAX_BATCH_BYTES {
                return Err(QRunV06HistorySyncError::BatchTooLarge);
            }
            let decoded = decode_qrun_v06_pow_block(envelope)
                .map_err(|error| QRunV06HistorySyncError::InvalidEnvelope(error.to_string()))?;
            if decoded.header.network_id != self.network_id
                || decoded.block.network_id != self.network_id
            {
                return Err(QRunV06HistorySyncError::WrongNetwork);
            }
            if decoded.block.profile_id != self.profile_id {
                return Err(QRunV06HistorySyncError::WrongProfile);
            }
            if decoded.header.height != expected_height
                || decoded.block.height != expected_height
                || decoded.header.previous_consensus_hash != expected_consensus_parent
                || decoded.header.parent_hash != decoded.block.parent_hash
                || (index == 0 && decoded.block.parent_hash != expected_execution_parent)
            {
                return Err(QRunV06HistorySyncError::NonContiguous);
            }
            expected_consensus_parent = pow_digest(&decoded.header, params.pow)
                .map_err(|error| QRunV06HistorySyncError::InvalidEnvelope(error.to_string()))?;
            expected_height = expected_height
                .checked_add(1)
                .ok_or(QRunV06HistorySyncError::BatchTooLarge)?;
        }

        let mut imported = 0usize;
        for (index, envelope) in envelopes.iter().enumerate() {
            if let Err(error) = self.submit_envelope(envelope, authenticator) {
                return Err(QRunV06HistorySyncError::ApplyFailed {
                    index,
                    committed_blocks: imported,
                    reason: error.to_string(),
                });
            }
            imported += 1;
        }
        let status = self
            .status()
            .map_err(|error| QRunV06HistorySyncError::ApplyFailed {
                index: imported,
                committed_blocks: imported,
                reason: error.to_string(),
            })?;
        Ok(QRunV06HistorySyncReport {
            imported_blocks: imported,
            resulting_height: status.height,
            resulting_tip: status.tip,
            resulting_state_root: status.state_root,
        })
    }
    /// Import a parent-first history segment onto any retained fork-choice branch.
    /// Unlike `import_history_batch`, the first envelope may extend a known non-canonical
    /// ancestor. Every block is still committed through the durable fork store, whose
    /// independent PoW/consensus/execution checks select the canonical branch by cumulative work.
    /// A failure after one or more successful submits leaves that valid prefix durable; the
    /// caller resumes from the exact branch tip it received.
    pub fn import_history_branch_batch<A: TransactionAuthenticator>(
        &mut self,
        start_height: u64,
        expected_parent_consensus_hash: [u8; 32],
        expected_parent_execution_hash: [u8; 32],
        envelopes: &[Vec<u8>],
        authenticator: &A,
    ) -> Result<QRunV06HistorySyncReport, QRunV06HistorySyncError> {
        if envelopes.is_empty() {
            return Err(QRunV06HistorySyncError::EmptyBatch);
        }
        if envelopes.len() > QRUN_V06_HISTORY_SYNC_MAX_BATCH_BLOCKS {
            return Err(QRunV06HistorySyncError::BatchTooLarge);
        }
        let initial_graph = self
            .fork_choice_snapshot()
            .map_err(|error| QRunV06HistorySyncError::InvalidEnvelope(error.to_string()))?;
        let parent_tip = initial_graph
            .tip_for_hash(&expected_parent_consensus_hash)
            .ok_or(QRunV06HistorySyncError::NonContiguous)?;
        let parent_state = initial_graph
            .state_for_tip(&expected_parent_consensus_hash)
            .ok_or(QRunV06HistorySyncError::NonContiguous)?;
        if parent_tip.height.checked_add(1) != Some(start_height)
            || parent_state.tip_hash() != expected_parent_execution_hash
        {
            return Err(QRunV06HistorySyncError::NonContiguous);
        }
        let params = initial_graph.consensus_parameters().clone();
        let mut expected_consensus_parent = expected_parent_consensus_hash;
        let mut expected_execution_parent = expected_parent_execution_hash;
        let mut expected_height = start_height;
        let mut total_bytes = 0usize;
        let mut imported = 0usize;

        for (index, envelope) in envelopes.iter().enumerate() {
            if envelope.is_empty() || envelope.len() > MAX_QRUN_V06_POW_ENVELOPE_BYTES {
                return Err(QRunV06HistorySyncError::BatchTooLarge);
            }
            total_bytes = total_bytes
                .checked_add(envelope.len())
                .ok_or(QRunV06HistorySyncError::BatchTooLarge)?;
            if total_bytes > QRUN_V06_HISTORY_SYNC_MAX_BATCH_BYTES {
                return Err(QRunV06HistorySyncError::BatchTooLarge);
            }
            let decoded = decode_qrun_v06_pow_block(envelope)
                .map_err(|error| QRunV06HistorySyncError::InvalidEnvelope(error.to_string()))?;
            if decoded.header.network_id != self.network_id
                || decoded.block.network_id != self.network_id
            {
                return Err(QRunV06HistorySyncError::WrongNetwork);
            }
            if decoded.block.profile_id != self.profile_id {
                return Err(QRunV06HistorySyncError::WrongProfile);
            }
            if decoded.header.height != expected_height
                || decoded.block.height != expected_height
                || decoded.header.previous_consensus_hash != expected_consensus_parent
                || decoded.header.parent_hash != decoded.block.parent_hash
                || decoded.block.parent_hash != expected_execution_parent
            {
                return Err(QRunV06HistorySyncError::NonContiguous);
            }
            let next_consensus_parent = pow_digest(&decoded.header, params.pow)
                .map_err(|error| QRunV06HistorySyncError::InvalidEnvelope(error.to_string()))?;
            if let Err(error) = self.submit_envelope(envelope, authenticator) {
                return Err(QRunV06HistorySyncError::ApplyFailed {
                    index,
                    committed_blocks: imported,
                    reason: error.to_string(),
                });
            }
            let graph = self.fork_choice_snapshot().map_err(|error| {
                QRunV06HistorySyncError::ApplyFailed {
                    index: index + 1,
                    committed_blocks: imported + 1,
                    reason: error.to_string(),
                }
            })?;
            let next_state = graph.state_for_tip(&next_consensus_parent).ok_or_else(|| {
                QRunV06HistorySyncError::ApplyFailed {
                    index: index + 1,
                    committed_blocks: imported + 1,
                    reason: "durably submitted history block is absent from the fork archive"
                        .into(),
                }
            })?;
            expected_consensus_parent = next_consensus_parent;
            expected_execution_parent = next_state.tip_hash();
            expected_height = expected_height
                .checked_add(1)
                .ok_or(QRunV06HistorySyncError::BatchTooLarge)?;
            imported += 1;
        }

        let status = self
            .status()
            .map_err(|error| QRunV06HistorySyncError::InvalidEnvelope(error.to_string()))?;
        Ok(QRunV06HistorySyncReport {
            imported_blocks: imported,
            resulting_height: status.height,
            resulting_tip: status.tip,
            resulting_state_root: status.state_root,
        })
    }

    /// Return an immutable branch-graph snapshot for mempool validation and mining-template
    /// construction. The durable store remains the sole authority for subsequent commits.
    pub fn fork_choice_snapshot(
        &self,
    ) -> Result<QRunV06PowForkChoice, QRunV06PermissionlessRuntimeError> {
        Ok(self.store.graph()?.clone())
    }

    pub fn status(
        &self,
    ) -> Result<QRunV06PermissionlessRuntimeStatus, QRunV06PermissionlessRuntimeError> {
        Ok(QRunV06PermissionlessRuntimeStatus {
            network_id: self.network_id,
            profile_id: self.profile_id,
            height: self.store.canonical_height()?,
            tip: self.store.canonical_tip()?,
            state_root: self.store.canonical_state_root()?,
            manifest_generation: self.store.generation()?,
            manifest_anchor: self.store.manifest_anchor()?,
            consensus_fingerprint: self.store.consensus_fingerprint()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct RejectAllTransactions;

    impl crate::state_machine::TransactionAuthenticator for RejectAllTransactions {
        fn verify(
            &self,
            _account: &crate::state_machine::AccountId,
            _digest: &[u8; 32],
            _signature: &[u8],
        ) -> Result<(), ()> {
            Err(())
        }
    }

    #[test]
    fn cp0604_permissionless_runtime_bootstraps_and_recovers_verified_genesis_store() {
        use crate::{
            consensus::{ConsensusParameters, Uint256},
            external_cas_anchor_candidate::ExternalCasPin,
            qrun_v06_checkpoint_candidate::qrun_v06_consensus_fingerprint,
            qrun_v06_cp0604_supply_candidate::Cp0604FounderControlledSupply,
            qrun_v06_genesis_descriptor_candidate::QRunV06GenesisDescriptor,
            qrun_v06_profile_pin_candidate::{
                QRunV06ProfilePinCandidate, QRunV06VerifiedProfilePin,
            },
            qrun_v06_tokenomics_candidate::QRunV06MiningScheduleCandidate,
            v4_fat1_trust_candidate::ML_DSA_65_PUBLIC_KEY_BYTES,
        };

        const NETWORK: [u8; 32] = [0xA1; 32];
        const PROFILE: [u8; 32] = [0xB2; 32];
        const FOUNDER: [u8; 32] = [0xC3; 32];
        let mut params = ConsensusParameters::qrun_v06_sha256d_candidate().unwrap();
        params.target_block_time_secs = 30;
        params.difficulty_window_blocks = 2;
        params.difficulty_min_ratio_divisor = 4;
        params.difficulty_max_ratio = 4;
        params.initial_target = Uint256::from_be_bytes([0x7F; 32]);
        params.pow_limit = Uint256::MAX;
        params.validate().unwrap();

        let schedule = QRunV06MiningScheduleCandidate::cp0422_research_candidate();
        let policy = Cp0604FounderControlledSupply::genesis(NETWORK, FOUNDER, schedule).unwrap();
        let descriptor = QRunV06GenesisDescriptor::new(
            NETWORK,
            PROFILE,
            FOUNDER,
            1,
            qrun_v06_consensus_fingerprint(&params).unwrap(),
            policy.policy_fingerprint(),
        )
        .unwrap();
        let genesis = QRunV06CanonicalExecutionState::cp0604_genesis_candidate_with_descriptor(
            descriptor, schedule,
        )
        .unwrap();
        assert_eq!(
            genesis
                .unified()
                .ledger()
                .account(&FOUNDER)
                .unwrap()
                .balance as u128,
            crate::qrun_v06_cp0604_supply_candidate::CP0604_FOUNDER_GENESIS_ATOMS
        );

        let bundle = QRunV06ProfilePinCandidate::new(
            descriptor,
            ExternalCasPin {
                provider_id: [0xD1; 32],
                network_id: NETWORK,
                genesis_digest: [0xD2; 32],
                receipt_key_id: [0xD3; 32],
                receipt_public_key: [0xD4; ML_DSA_65_PUBLIC_KEY_BYTES],
            },
        )
        .unwrap();
        let pin_bytes = bundle.encode().unwrap();
        let independent_commitment = bundle.commitment().unwrap();
        let verified_pin =
            QRunV06VerifiedProfilePin::decode(&pin_bytes, independent_commitment).unwrap();

        let directory = std::env::temp_dir().join(format!(
            "qfp6-permissionless-cp0604-runtime-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        let authenticator = RejectAllTransactions;
        let first = QRunV06PermissionlessNodeRuntime::open(
            &directory,
            genesis.clone(),
            params.clone(),
            &authenticator,
            None,
            &verified_pin,
        )
        .unwrap();
        let first_status = first.status().unwrap();
        assert_eq!(first_status.network_id, NETWORK);
        assert_eq!(first_status.profile_id, PROFILE);
        assert_eq!(first_status.height, 0);
        assert_ne!(first_status.state_root, [0; 32]);
        assert_eq!(first_status.manifest_generation, 0);
        drop(first);

        // The checkpoint restore path must accept the same CP-0604 policy identity.
        let checkpoint_source_dir = directory.with_extension("checkpoint-source");
        let checkpoint_restore_dir = directory.with_extension("checkpoint-restore");
        let checkpoint_source = QRunV06DurableForkStore::open_with_verified_profile_pin(
            &checkpoint_source_dir,
            genesis.clone(),
            params.clone(),
            &authenticator,
            None,
            &verified_pin,
        )
        .unwrap();
        let (checkpoint_bytes, checkpoint_anchor) =
            checkpoint_source.export_canonical_checkpoint().unwrap();
        drop(checkpoint_source);
        let checkpoint_restored =
            QRunV06DurableForkStore::open_from_checkpoint_with_verified_profile_pin(
                &checkpoint_restore_dir,
                &checkpoint_bytes,
                params.clone(),
                checkpoint_anchor,
                &verified_pin,
                &authenticator,
                None,
            )
            .unwrap();
        assert_eq!(checkpoint_restored.canonical_height().unwrap(), 0);
        assert_eq!(
            checkpoint_restored.canonical_state_root().unwrap(),
            first_status.state_root
        );
        drop(checkpoint_restored);

        let recovered = QRunV06PermissionlessNodeRuntime::open(
            &directory,
            genesis,
            params,
            &authenticator,
            Some(first_status.manifest_anchor),
            &verified_pin,
        )
        .unwrap();
        let recovered_status = recovered.status().unwrap();
        assert_eq!(recovered_status.height, first_status.height);
        assert_eq!(recovered_status.tip, first_status.tip);
        assert_eq!(recovered_status.state_root, first_status.state_root);
        assert_eq!(
            recovered_status.manifest_generation,
            first_status.manifest_generation
        );
        drop(recovered);
        std::fs::remove_dir_all(directory).unwrap();
        std::fs::remove_dir_all(checkpoint_source_dir).unwrap();
        std::fs::remove_dir_all(checkpoint_restore_dir).unwrap();
    }

    #[test]
    fn unresolved_anchor_intent_fails_closed_with_recovery_direction() {
        let error = QRunV06PermissionlessRuntimeError::UnresolvedQap1Intent;
        assert!(error.to_string().contains("unresolved QAP1 intent"));
        assert!(error.to_string().contains("anchored runtime"));
    }

    #[test]
    fn store_errors_are_preserved_as_diagnostic_text() {
        let error = QRunV06PermissionlessRuntimeError::Store("manifest checksum mismatch".into());
        assert!(error.to_string().contains("manifest checksum mismatch"));
    }
}
