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
    qrun_v06_canonical_execution_candidate::{
        qrun_v06_block_id, QRunV06BlockOperation, QRunV06CanonicalExecutionState,
    },
    qrun_v06_local_anchor_vault_candidate::QRunV06LocalAnchorVault,
    qrun_v06_node_runtime_candidate::{
        QRunV06NodeAnchorGate, QRunV06NodeRuntime, QRunV06NodeRuntimeError,
    },
    qrun_v06_pow_fork_choice_candidate::QRunV06QuoteAssetAuthorizationProvider,
    qrun_v06_pow_fork_choice_candidate::{QRunV06PowForkChoice, MAX_QRUN_V06_FORK_ARCHIVE_BLOCKS},
    qrun_v06_pow_fork_store_candidate::{
        QRunV06DurableCommit, QRunV06DurableForkStore, QRunV06ForkStoreError,
    },
    qrun_v06_profile_pin_candidate::QRunV06VerifiedProfilePin,
    qrun_v06_profile_trust_candidate::QRunV06TrustAuthorizedProfilePin,
    qrun_v06_qap1_coordinator_candidate::{
        QRunV06Qap1AnchorTransport, QRunV06Qap1ExternalCoordinator,
    },
    state_machine::{
        transaction_id_with_signature_limit, Transaction, TransactionAuthenticator,
        QRUN_V06_MAX_NATIVE_TX_SIGNATURE_BYTES,
    },
    v4_fat1_trust_candidate::MlDsa65Verifier,
};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QRunV06PermissionlessRuntimeError {
    Store(String),
    UnresolvedQap1Intent,
    Qap1Recovery(String),
    LocalAnchorVault(String),
    LocalAnchorRecoveryRequired,
}

impl std::fmt::Display for QRunV06PermissionlessRuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(error) => write!(f, "QFP6 permissionless base runtime failed: {error}"),
            Self::Qap1Recovery(error) => write!(f, "QFP6 QAP1 recovery failed: {error}"),
            Self::UnresolvedQap1Intent => f.write_str(
                "QFP6 permissionless base runtime refuses a store with unresolved QAP1 intent; recover through the anchored runtime first",
            ),
            Self::LocalAnchorVault(error) => write!(f, "QFP6 local dual-disk anchor persistence failed: {error}"),
            Self::LocalAnchorRecoveryRequired => f.write_str(
                "QFP6 local anchor persistence is unresolved; stop and reopen through the local vault recovery path",
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

/// Immutable canonical account read bound to one exact QFP6 tip and execution root.
/// Missing accounts are represented as None, never as a fabricated funded balance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QRunV06CanonicalAccountRead {
    pub network_id: [u8; 32],
    pub profile_id: [u8; 32],
    pub native_asset_id: [u8; 32],
    pub account_id: [u8; 32],
    pub balance_atoms: Option<u64>,
    pub nonce: Option<u64>,
    pub height: u64,
    pub tip: [u8; 32],
    pub state_root: [u8; 32],
}
/// Canonical CP-0651 supply facts from one exact execution snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QRunV06CanonicalSupplyRead {
    pub network_id: [u8; 32],
    pub profile_id: [u8; 32],
    pub native_asset_id: [u8; 32],
    pub ledger_total_atoms: u128,
    pub owner_genesis_atoms: u128,
    pub maximum_supply_atoms: u128,
    pub block_subsidy_atoms: u128,
    pub accounting_labels_total_atoms: u128,
    pub policy_fingerprint: [u8; 32],
    pub height: u64,
    pub tip: [u8; 32],
    pub state_root: [u8; 32],
}

/// One QFB6 operation as exposed by the read-only explorer surface.
/// Native transfer fields are decoded from the canonical block body; signatures are never
/// copied into this response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06CanonicalBlockOperationRead {
    pub index: usize,
    pub kind: &'static str,
    pub transaction: Option<QRunV06CanonicalTransactionFields>,
}

/// Canonical TXN2 identity and public transfer fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QRunV06CanonicalTransactionFields {
    pub transaction_id: [u8; 32],
    pub sender: [u8; 32],
    pub recipient: [u8; 32],
    pub nonce: u64,
    pub amount_atoms: u64,
    pub fee_atoms: u64,
    pub expires_at: u64,
}

/// A canonical block read. QFB6 execution block ID and QFP6 PoW consensus tip
/// are distinct commitments and are returned separately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06CanonicalBlockRead {
    pub network_id: [u8; 32],
    pub profile_id: [u8; 32],
    pub height: u64,
    pub timestamp: u64,
    pub parent_hash: [u8; 32],
    pub execution_block_id: [u8; 32],
    pub consensus_tip: [u8; 32],
    pub state_root: [u8; 32],
    pub producer: [u8; 32],
    pub operation_count: usize,
    pub operations: Vec<QRunV06CanonicalBlockOperationRead>,
    pub canonical_height: u64,
    pub canonical_tip: [u8; 32],
    pub canonical_state_root: [u8; 32],
}

/// A native transaction receipt reconstructed from retained, validated QFP6 block bodies.
/// reorged means its containing block remains in the local fork archive but is not an
/// ancestor of the current canonical tip. It is not a mempool or finality statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QRunV06CanonicalTransactionRead {
    pub transaction: QRunV06CanonicalTransactionFields,
    pub inclusion_status: &'static str,
    pub block_height: u64,
    pub block_timestamp: u64,
    pub execution_block_id: [u8; 32],
    pub consensus_tip: [u8; 32],
    pub block_state_root: [u8; 32],
    pub producer: [u8; 32],
    pub confirmations: u64,
    pub canonical_height: u64,
    pub canonical_tip: [u8; 32],
    pub canonical_state_root: [u8; 32],
}

const QRUN_V06_READ_API_MAX_ARCHIVE_BYTES: usize = 16 * 1024 * 1024;

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

fn canonical_transaction_fields(
    tx: &Transaction,
) -> Result<QRunV06CanonicalTransactionFields, QRunV06PermissionlessRuntimeError> {
    let transaction_id =
        transaction_id_with_signature_limit(tx, QRUN_V06_MAX_NATIVE_TX_SIGNATURE_BYTES)
            .map_err(|error| QRunV06PermissionlessRuntimeError::Store(format!("{error:?}")))?;
    Ok(QRunV06CanonicalTransactionFields {
        transaction_id,
        sender: tx.sender,
        recipient: tx.recipient,
        nonce: tx.nonce,
        amount_atoms: tx.amount,
        fee_atoms: tx.fee,
        expires_at: tx.expires_at,
    })
}

/// Permissionless base admission with no mandatory external-anchor dependency.
pub struct QRunV06PermissionlessNodeRuntime {
    store: QRunV06DurableForkStore,
    network_id: [u8; 32],
    profile_id: [u8; 32],
    local_anchor_vault: Option<QRunV06LocalAnchorVault>,
    local_anchor_failed: bool,
    // Keep prior segment writer locks alive after rollover so retired stores cannot be reopened
    // for writes while this runtime remains active.
    retired_segments: Vec<QRunV06DurableForkStore>,
    auto_checkpoint_rollover: Option<(PathBuf, QRunV06VerifiedProfilePin)>,
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
            local_anchor_vault: None,
            local_anchor_failed: false,
            retired_segments: Vec::new(),
            auto_checkpoint_rollover: None,
        })
    }

    /// Bootstrap a genuinely fresh Genesis-only store and immediately pin its generation-zero
    /// manifest in a separate append-only anchor vault before exposing the runtime.
    /// Existing history, an existing/partial vault, or any nonzero generation fails closed.
    /// Open a fresh public-testnet Joiner and derive its sequence-1 vault root from
    /// the locally verified Genesis. The caller must have already verified the Q6PN
    /// profile pin, Q6GD descriptor, Genesis snapshot hash, and Q6GA public-testnet
    /// authorization. This path refuses any pre-existing generation/height and any
    /// unresolved QAP1 intent; it never adopts existing local or remote history.
    ///
    /// This method is intended only for an explicitly opted-in zero-value Public Testnet
    /// Joiner. Production and existing-history recovery must continue to use an
    /// independently pinned root through open_with_fresh_genesis_anchor_vault.
    pub fn open_with_verified_genesis_fresh_anchor_vault<A: TransactionAuthenticator>(
        directory: impl AsRef<Path>,
        genesis_state: QRunV06CanonicalExecutionState,
        params: ConsensusParameters,
        authenticator: &A,
        verified_profile_pin: &QRunV06VerifiedProfilePin,
        vault_directory: impl AsRef<Path>,
    ) -> Result<Self, QRunV06PermissionlessRuntimeError> {
        Self::open_with_fresh_genesis_anchor_vault_inner(
            directory,
            genesis_state,
            params,
            authenticator,
            verified_profile_pin,
            None,
            vault_directory,
        )
    }

    pub fn open_with_fresh_genesis_anchor_vault<A: TransactionAuthenticator>(
        directory: impl AsRef<Path>,
        genesis_state: QRunV06CanonicalExecutionState,
        params: ConsensusParameters,
        authenticator: &A,
        verified_profile_pin: &QRunV06VerifiedProfilePin,
        trusted_genesis_anchor: [u8; 32],
        vault_directory: impl AsRef<Path>,
    ) -> Result<Self, QRunV06PermissionlessRuntimeError> {
        Self::open_with_fresh_genesis_anchor_vault_inner(
            directory,
            genesis_state,
            params,
            authenticator,
            verified_profile_pin,
            Some(trusted_genesis_anchor),
            vault_directory,
        )
    }

    fn open_with_fresh_genesis_anchor_vault_inner<A: TransactionAuthenticator>(
        directory: impl AsRef<Path>,
        genesis_state: QRunV06CanonicalExecutionState,
        params: ConsensusParameters,
        authenticator: &A,
        verified_profile_pin: &QRunV06VerifiedProfilePin,
        trusted_genesis_anchor: Option<[u8; 32]>,
        vault_directory: impl AsRef<Path>,
    ) -> Result<Self, QRunV06PermissionlessRuntimeError> {
        let descriptor = verified_profile_pin.descriptor();
        let network_id = descriptor.network_id();
        let profile_id = descriptor.profile_id();
        let store = QRunV06DurableForkStore::open_with_verified_profile_pin(
            directory,
            genesis_state,
            params,
            authenticator,
            None,
            verified_profile_pin,
        )?;
        if store.has_qap1_intent()? {
            return Err(QRunV06PermissionlessRuntimeError::UnresolvedQap1Intent);
        }
        if store.generation()? != 0 || store.graph()?.canonical_tip().height != 0 {
            return Err(QRunV06PermissionlessRuntimeError::LocalAnchorVault(
                "fresh Genesis anchor provisioning requires a generation-zero, height-zero store; existing history is never adopted automatically".into(),
            ));
        }
        let genesis_anchor = store.manifest_anchor()?;
        if let Some(trusted_genesis_anchor) = trusted_genesis_anchor {
            if genesis_anchor != trusted_genesis_anchor {
                return Err(QRunV06PermissionlessRuntimeError::LocalAnchorVault(
                    "fresh Genesis manifest differs from the independently pinned Genesis anchor"
                        .into(),
                ));
            }
        }
        let vault = QRunV06LocalAnchorVault::provision_genesis_root(
            vault_directory,
            network_id,
            profile_id,
            genesis_anchor,
        )
        .map_err(QRunV06PermissionlessRuntimeError::LocalAnchorVault)?;
        if vault.tip().manifest_generation != 0 || vault.tip().manifest_anchor != genesis_anchor {
            return Err(QRunV06PermissionlessRuntimeError::LocalAnchorVault(
                "fresh Genesis anchor vault did not reopen at the exact store root".into(),
            ));
        }
        Ok(Self {
            store,
            network_id,
            profile_id,
            local_anchor_vault: Some(vault),
            local_anchor_failed: false,
            retired_segments: Vec::new(),
            auto_checkpoint_rollover: None,
        })
    }
    /// Open the local single-owner runtime using the exact current tip of the C:-side vault.
    /// The store accepts that pin only if it is an exact manifest ancestor, then fully replays
    /// the remaining chain before the vault can be advanced to a single committed successor.
    pub fn open_with_local_anchor_vault<A: TransactionAuthenticator>(
        directory: impl AsRef<Path>,
        genesis_state: QRunV06CanonicalExecutionState,
        params: ConsensusParameters,
        authenticator: &A,
        trusted_manifest_anchor: [u8; 32],
        trusted_manifest_generation: u64,
        verified_profile_pin: &QRunV06VerifiedProfilePin,
        vault_directory: impl AsRef<Path>,
    ) -> Result<Self, QRunV06PermissionlessRuntimeError> {
        let descriptor = verified_profile_pin.descriptor();
        let network_id = descriptor.network_id();
        let profile_id = descriptor.profile_id();
        let mut vault = QRunV06LocalAnchorVault::open(vault_directory, network_id, profile_id)
            .map_err(QRunV06PermissionlessRuntimeError::LocalAnchorVault)?;
        let tip = vault.tip();
        if tip.manifest_generation != trusted_manifest_generation
            || tip.manifest_anchor != trusted_manifest_anchor
        {
            return Err(QRunV06PermissionlessRuntimeError::LocalAnchorVault(
                "supplied trusted anchor differs from the independently loaded C: vault tip".into(),
            ));
        }
        let store =
            QRunV06DurableForkStore::open_with_verified_profile_pin_and_trusted_anchor_ancestor(
                directory,
                genesis_state,
                params,
                authenticator,
                trusted_manifest_anchor,
                trusted_manifest_generation,
                verified_profile_pin,
            )?;
        if store.has_qap1_intent()? {
            return Err(QRunV06PermissionlessRuntimeError::UnresolvedQap1Intent);
        }
        // Successful store open proves the exact C: anchor/generation occurs in the fully
        // linked manifest chain; the store has also replayed and validated all branch entries.
        vault
            .reconcile_replayed_tip(store.generation()?, store.manifest_anchor()?)
            .map_err(QRunV06PermissionlessRuntimeError::LocalAnchorVault)?;
        Ok(Self {
            store,
            network_id,
            profile_id,
            local_anchor_vault: Some(vault),
            local_anchor_failed: false,
            retired_segments: Vec::new(),
            auto_checkpoint_rollover: None,
        })
    }

    /// Reopen a checkpoint-rooted segment only when its exact checkpoint and generation-zero
    /// manifest are bound by the latest C: witness. Segment-local generations are translated
    /// through that witness before the runtime is exposed for block admission.
    pub fn open_from_checkpoint_with_local_anchor_vault<A: TransactionAuthenticator>(
        directory: impl AsRef<Path>,
        checkpoint_bytes: &[u8],
        checkpoint_anchor: [u8; 32],
        params: ConsensusParameters,
        authenticator: &A,
        verified_profile_pin: &QRunV06VerifiedProfilePin,
        vault_directory: impl AsRef<Path>,
    ) -> Result<Self, QRunV06PermissionlessRuntimeError> {
        let descriptor = verified_profile_pin.descriptor();
        let network_id = descriptor.network_id();
        let profile_id = descriptor.profile_id();
        let consensus_fingerprint =
            crate::qrun_v06_checkpoint_candidate::qrun_v06_consensus_fingerprint(&params)
                .map_err(|error| QRunV06PermissionlessRuntimeError::Store(format!("{error:?}")))?;
        if descriptor.consensus_fingerprint() != consensus_fingerprint {
            return Err(QRunV06PermissionlessRuntimeError::LocalAnchorVault(
                "Q6PN consensus fingerprint differs from checkpoint runtime parameters".into(),
            ));
        }
        let checkpoint =
            crate::qrun_v06_checkpoint_candidate::QRunV06CheckpointCandidate::decode_snapshot(
                checkpoint_bytes,
                &params,
                &network_id,
                &profile_id,
                checkpoint_anchor,
            )
            .map_err(|error| {
                QRunV06PermissionlessRuntimeError::LocalAnchorVault(format!(
                    "checkpoint validation failed: {error:?}"
                ))
            })?;
        if checkpoint.commitment().map_err(|error| {
            QRunV06PermissionlessRuntimeError::LocalAnchorVault(format!("{error:?}"))
        })? != checkpoint_anchor
            || checkpoint.genesis_descriptor_commitment() != descriptor.commitment()
            || checkpoint.consensus_fingerprint() != consensus_fingerprint
        {
            return Err(QRunV06PermissionlessRuntimeError::LocalAnchorVault(
                "checkpoint commitment/Genesis/consensus identity differs from Q6PN".into(),
            ));
        }
        let checkpoint_state_root = checkpoint.execution_state().state_root().map_err(|error| {
            QRunV06PermissionlessRuntimeError::LocalAnchorVault(format!("{error:?}"))
        })?;
        let mut vault = QRunV06LocalAnchorVault::open(vault_directory, network_id, profile_id)
            .map_err(QRunV06PermissionlessRuntimeError::LocalAnchorVault)?;
        let witness = vault.latest_checkpoint_segment_witness().ok_or_else(|| {
            QRunV06PermissionlessRuntimeError::LocalAnchorVault(
                "checkpoint-rooted startup requires a C: checkpoint-segment witness".into(),
            )
        })?;
        if witness.checkpoint_commitment != checkpoint_anchor
            || witness.checkpoint_base_height != checkpoint.height()
            || witness.checkpoint_tip_hash != checkpoint.execution_tip_hash()
            || witness.checkpoint_state_root != checkpoint_state_root
            || witness.checkpoint_cumulative_work != checkpoint.cumulative_work().to_be_bytes()
            || witness.network_id != network_id
            || witness.profile_id != profile_id
            || witness.genesis_descriptor_commitment != descriptor.commitment()
            || witness.consensus_fingerprint != consensus_fingerprint
        {
            return Err(QRunV06PermissionlessRuntimeError::LocalAnchorVault(
                "checkpoint bytes do not match the exact C: segment witness".into(),
            ));
        }
        let tip = vault.tip();
        let root_generation = witness
            .predecessor_global_generation
            .checked_add(1)
            .ok_or_else(|| {
                QRunV06PermissionlessRuntimeError::LocalAnchorVault(
                    "global segment generation overflow".into(),
                )
            })?;
        let (trusted_manifest_anchor, trusted_manifest_generation) =
            if tip.manifest_generation == witness.predecessor_global_generation {
                if tip.sequence != witness.predecessor_vault_sequence
                    || tip.manifest_anchor != witness.predecessor_manifest_anchor
                    || tip.record_digest != witness.predecessor_record_digest
                {
                    return Err(QRunV06PermissionlessRuntimeError::LocalAnchorVault(
                        "pending witness predecessor is not the exact current C: vault tip".into(),
                    ));
                }
                (witness.segment_root_manifest_anchor, 0)
            } else if tip.manifest_generation >= root_generation {
                (
                    tip.manifest_anchor,
                    tip.manifest_generation
                        .checked_sub(root_generation)
                        .ok_or_else(|| {
                            QRunV06PermissionlessRuntimeError::LocalAnchorVault(
                                "segment-local generation mapping underflow".into(),
                            )
                        })?,
                )
            } else {
                return Err(QRunV06PermissionlessRuntimeError::LocalAnchorVault(
                    "C: vault tip is inconsistent with checkpoint witness generation".into(),
                ));
            };
        let store = QRunV06DurableForkStore::open_from_checkpoint_with_verified_profile_pin_and_trusted_anchor_ancestor(
            directory,
            checkpoint_bytes,
            params,
            checkpoint_anchor,
            verified_profile_pin,
            authenticator,
            trusted_manifest_anchor,
            trusted_manifest_generation,
        )?;
        if store.has_qap1_intent()? {
            return Err(QRunV06PermissionlessRuntimeError::UnresolvedQap1Intent);
        }
        if store.checkpoint_anchor()? != Some(checkpoint_anchor)
            || store.manifest_anchor_at_generation(0)? != Some(witness.segment_root_manifest_anchor)
            || store.graph()?.base_height() != checkpoint.height()
            || store.graph()?.base_tip() != checkpoint.consensus_tip_digest()
        {
            return Err(QRunV06PermissionlessRuntimeError::LocalAnchorVault(
                "checkpoint segment root manifest/base state differs from C: witness".into(),
            ));
        }
        vault
            .reconcile_checkpoint_segment_root()
            .map_err(QRunV06PermissionlessRuntimeError::LocalAnchorVault)?;
        let local_generation = store.generation()?;
        let local_anchor = store.manifest_anchor()?;
        let reconciled = vault
            .append_segment_successor(local_generation, local_anchor)
            .map_err(QRunV06PermissionlessRuntimeError::LocalAnchorVault)?;
        let expected_global_generation = witness
            .predecessor_global_generation
            .checked_add(1)
            .and_then(|base| base.checked_add(local_generation))
            .ok_or_else(|| {
                QRunV06PermissionlessRuntimeError::LocalAnchorVault(
                    "global segment generation overflow".into(),
                )
            })?;
        if reconciled.manifest_generation != expected_global_generation
            || reconciled.manifest_anchor != local_anchor
        {
            return Err(QRunV06PermissionlessRuntimeError::LocalAnchorVault(
                "C: vault tip does not equal the checkpoint segment's mapped local tip".into(),
            ));
        }
        Ok(Self {
            store,
            network_id,
            profile_id,
            local_anchor_vault: Some(vault),
            local_anchor_failed: false,
            retired_segments: Vec::new(),
            auto_checkpoint_rollover: None,
        })
    }

    /// Enable automatic checkpoint rollover immediately before a submission would exceed the
    /// current segment's archive capacity. The segment root is a local storage namespace, not
    /// a trust anchor; each selected segment is still verified against the C: witness chain.
    pub fn enable_auto_checkpoint_rollover(
        &mut self,
        segments_root: impl AsRef<Path>,
        verified_profile_pin: QRunV06VerifiedProfilePin,
    ) -> Result<(), QRunV06PermissionlessRuntimeError> {
        if self.local_anchor_vault.is_none() {
            return Err(QRunV06PermissionlessRuntimeError::LocalAnchorVault(
                "automatic checkpoint rollover requires the local C: anchor vault".into(),
            ));
        }
        let descriptor = verified_profile_pin.descriptor();
        let active_fingerprint =
            crate::qrun_v06_checkpoint_candidate::qrun_v06_consensus_fingerprint(
                self.store.graph()?.consensus_parameters(),
            )
            .map_err(|error| QRunV06PermissionlessRuntimeError::Store(format!("{error:?}")))?;
        if descriptor.network_id() != self.network_id
            || descriptor.profile_id() != self.profile_id
            || descriptor.consensus_fingerprint() != active_fingerprint
        {
            return Err(QRunV06PermissionlessRuntimeError::LocalAnchorVault(
                "automatic rollover Q6PN does not match the active runtime".into(),
            ));
        }
        self.auto_checkpoint_rollover =
            Some((segments_root.as_ref().to_path_buf(), verified_profile_pin));
        Ok(())
    }

    fn rotate_if_archive_capacity_reached<A: TransactionAuthenticator>(
        &mut self,
        authenticator: &A,
    ) -> Result<(), QRunV06PermissionlessRuntimeError> {
        if self.store.archive_len()?
            < crate::qrun_v06_pow_fork_choice_candidate::MAX_QRUN_V06_FORK_ARCHIVE_BLOCKS
        {
            return Ok(());
        }
        let Some((segments_root, verified_profile_pin)) = self.auto_checkpoint_rollover.as_ref()
        else {
            return Ok(());
        };
        let segments_root = segments_root.clone();
        let verified_profile_pin = verified_profile_pin.clone();
        let next_sequence = self
            .local_anchor_vault
            .as_ref()
            .and_then(QRunV06LocalAnchorVault::latest_checkpoint_segment_witness)
            .map(|witness| witness.sequence.checked_add(1))
            .unwrap_or(Some(1))
            .ok_or_else(|| {
                QRunV06PermissionlessRuntimeError::LocalAnchorVault(
                    "checkpoint segment sequence overflow".into(),
                )
            })?;
        let next_directory = segments_root.join(format!("segment-{next_sequence:020}"));
        self.rotate_to_checkpoint_segment(next_directory, authenticator, &verified_profile_pin)?;
        Ok(())
    }

    /// Rotate the active durable store to a fresh checkpoint-rooted segment. The C: witness
    /// is appended before its generation-zero manifest anchor; only after that anchor is
    /// read-back verified does the runtime switch stores. The retired store's writer lock is
    /// retained for the lifetime of this runtime.
    pub fn rotate_to_checkpoint_segment<A: TransactionAuthenticator>(
        &mut self,
        new_directory: impl AsRef<Path>,
        authenticator: &A,
        verified_profile_pin: &QRunV06VerifiedProfilePin,
    ) -> Result<[u8; 32], QRunV06PermissionlessRuntimeError> {
        if self.local_anchor_failed {
            return Err(QRunV06PermissionlessRuntimeError::LocalAnchorRecoveryRequired);
        }
        if self.store.has_qap1_intent()? {
            return Err(QRunV06PermissionlessRuntimeError::UnresolvedQap1Intent);
        }
        let descriptor = verified_profile_pin.descriptor();
        let params = self.store.graph()?.consensus_parameters().clone();
        let active_consensus_fingerprint =
            crate::qrun_v06_checkpoint_candidate::qrun_v06_consensus_fingerprint(&params)
                .map_err(|error| QRunV06PermissionlessRuntimeError::Store(format!("{error:?}")))?;
        if descriptor.network_id() != self.network_id
            || descriptor.profile_id() != self.profile_id
            || descriptor.consensus_fingerprint() != active_consensus_fingerprint
        {
            return Err(QRunV06PermissionlessRuntimeError::LocalAnchorVault(format!(
                "rotation Q6PN mismatch: network={}, profile={}, consensus={}, pin_fp={:02x?}, store_fp={:02x?}",
                descriptor.network_id() == self.network_id,
                descriptor.profile_id() == self.profile_id,
                descriptor.consensus_fingerprint() == active_consensus_fingerprint,
                descriptor.consensus_fingerprint(),
                active_consensus_fingerprint,
            )));
        }
        let vault_ref = self.local_anchor_vault.as_ref().ok_or_else(|| {
            QRunV06PermissionlessRuntimeError::LocalAnchorVault(
                "checkpoint rotation requires the local C: anchor vault".into(),
            )
        })?;
        let current_vault_tip = vault_ref.tip();
        let current_local_generation = self.store.generation()?;
        let current_global_generation =
            if let Some(witness) = vault_ref.latest_checkpoint_segment_witness() {
                witness
                    .predecessor_global_generation
                    .checked_add(1)
                    .and_then(|base| base.checked_add(current_local_generation))
                    .ok_or_else(|| {
                        QRunV06PermissionlessRuntimeError::LocalAnchorVault(
                            "active segment global generation overflow".into(),
                        )
                    })?
            } else {
                current_local_generation
            };
        if current_vault_tip.manifest_generation != current_global_generation
            || current_vault_tip.manifest_anchor != self.store.manifest_anchor()?
        {
            return Err(QRunV06PermissionlessRuntimeError::LocalAnchorVault(
                "active store and C: vault are not at the exact same mapped tip; rotation refused"
                    .into(),
            ));
        }

        let active_graph = self.store.graph()?;
        let canonical_span = active_graph
            .canonical_tip()
            .height
            .checked_sub(active_graph.base_height())
            .ok_or_else(|| {
                QRunV06PermissionlessRuntimeError::LocalAnchorVault(
                    "canonical checkpoint span underflow".into(),
                )
            })?;
        if self.store.archive_len()? as u64 != canonical_span {
            return Err(QRunV06PermissionlessRuntimeError::LocalAnchorVault(
                "checkpoint rollover refused while competing/noncanonical branches remain; a canonical-only checkpoint would discard fork-choice candidates".into(),
            ));
        }
        let (checkpoint_bytes, checkpoint_anchor) = self.store.export_canonical_checkpoint()?;
        let checkpoint =
            crate::qrun_v06_checkpoint_candidate::QRunV06CheckpointCandidate::decode_snapshot(
                &checkpoint_bytes,
                &params,
                &self.network_id,
                &self.profile_id,
                checkpoint_anchor,
            )
            .map_err(|error| {
                QRunV06PermissionlessRuntimeError::LocalAnchorVault(format!(
                    "exported checkpoint failed self-validation: {error:?}"
                ))
            })?;
        if checkpoint.genesis_descriptor_commitment() != descriptor.commitment()
            || checkpoint.consensus_fingerprint() != descriptor.consensus_fingerprint()
        {
            return Err(QRunV06PermissionlessRuntimeError::LocalAnchorVault(
                "exported checkpoint identity differs from the independently verified Q6PN".into(),
            ));
        }

        let new_directory = new_directory.as_ref();
        let segments_root = new_directory.parent().ok_or_else(|| {
            QRunV06PermissionlessRuntimeError::LocalAnchorVault(
                "checkpoint segment directory has no parent namespace".into(),
            )
        })?;
        match std::fs::symlink_metadata(segments_root) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir_all(segments_root).map_err(|error| {
                    QRunV06PermissionlessRuntimeError::LocalAnchorVault(format!(
                        "cannot create checkpoint segments root: {error}"
                    ))
                })?;
            }
            Err(error) => {
                return Err(QRunV06PermissionlessRuntimeError::LocalAnchorVault(
                    format!("cannot inspect checkpoint segments root: {error}"),
                ));
            }
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(QRunV06PermissionlessRuntimeError::LocalAnchorVault(
                    "checkpoint segments root must be a real non-symlink directory".into(),
                ));
            }
            Ok(_) => {}
        }
        let root_metadata = std::fs::symlink_metadata(segments_root).map_err(|error| {
            QRunV06PermissionlessRuntimeError::LocalAnchorVault(format!(
                "checkpoint segments root metadata after creation: {error}"
            ))
        })?;
        if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
            return Err(QRunV06PermissionlessRuntimeError::LocalAnchorVault(
                "checkpoint segments root changed to a non-directory or symlink".into(),
            ));
        }
        match std::fs::symlink_metadata(new_directory) {
            Ok(_) => {
                return Err(QRunV06PermissionlessRuntimeError::LocalAnchorVault(
                    "new checkpoint segment path must not already exist; refusing reuse".into(),
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(QRunV06PermissionlessRuntimeError::LocalAnchorVault(
                    format!("cannot inspect new checkpoint segment path: {error}"),
                ));
            }
        }

        let network_id = self.network_id;
        let profile_id = self.profile_id;
        let mut witness_written = false;
        let result = {
            let vault = self.local_anchor_vault.as_mut().ok_or_else(|| {
                QRunV06PermissionlessRuntimeError::LocalAnchorVault(
                    "local C: anchor vault disappeared during rotation".into(),
                )
            })?;
            (|| {
                let new_store =
                    QRunV06DurableForkStore::open_from_checkpoint_with_verified_profile_pin(
                        new_directory,
                        &checkpoint_bytes,
                        params,
                        checkpoint_anchor,
                        verified_profile_pin,
                        authenticator,
                        None,
                    )?;
                if new_store.generation()? != 0
                    || new_store.archive_len()? != 0
                    || new_store.checkpoint_anchor()? != Some(checkpoint_anchor)
                    || new_store.graph()?.base_height() != checkpoint.height()
                    || new_store.graph()?.base_tip() != checkpoint.consensus_tip_digest()
                {
                    return Err(QRunV06PermissionlessRuntimeError::LocalAnchorVault(
                        "fresh checkpoint segment did not open at the exact generation-zero base"
                            .into(),
                    ));
                }
                let segment_root_anchor =
                    new_store.manifest_anchor_at_generation(0)?.ok_or_else(|| {
                        QRunV06PermissionlessRuntimeError::LocalAnchorVault(
                            "fresh checkpoint segment has no generation-zero manifest".into(),
                        )
                    })?;
                let predecessor = vault.tip();
                let previous_witness = vault.latest_checkpoint_segment_witness();
                let sequence = previous_witness
                    .map(|witness| witness.sequence.checked_add(1))
                    .unwrap_or(Some(1))
                    .ok_or_else(|| {
                        QRunV06PermissionlessRuntimeError::LocalAnchorVault(
                            "checkpoint witness sequence overflow".into(),
                        )
                    })?;
                let witness =
                    crate::qrun_v06_local_anchor_vault_candidate::QRunV06CheckpointSegmentWitness {
                        sequence,
                        predecessor_vault_sequence: predecessor.sequence,
                        predecessor_global_generation: predecessor.manifest_generation,
                        predecessor_manifest_anchor: predecessor.manifest_anchor,
                        predecessor_record_digest: predecessor.record_digest,
                        checkpoint_commitment: checkpoint_anchor,
                        segment_root_manifest_anchor: segment_root_anchor,
                        checkpoint_base_height: checkpoint.height(),
                        checkpoint_tip_hash: checkpoint.execution_tip_hash(),
                        checkpoint_state_root: checkpoint.execution_state().state_root().map_err(
                            |error| {
                                QRunV06PermissionlessRuntimeError::LocalAnchorVault(format!(
                                    "{error:?}"
                                ))
                            },
                        )?,
                        checkpoint_cumulative_work: checkpoint.cumulative_work().to_be_bytes(),
                        network_id,
                        profile_id,
                        genesis_descriptor_commitment: descriptor.commitment(),
                        consensus_fingerprint: descriptor.consensus_fingerprint(),
                        previous_witness_digest: previous_witness
                            .map(|witness| witness.witness_digest)
                            .unwrap_or([0; 32]),
                        witness_digest: [0; 32],
                    };
                vault
                    .append_checkpoint_segment_witness(witness)
                    .map_err(QRunV06PermissionlessRuntimeError::LocalAnchorVault)?;
                witness_written = true;
                let root_tip = vault
                    .reconcile_checkpoint_segment_root()
                    .map_err(QRunV06PermissionlessRuntimeError::LocalAnchorVault)?;
                let expected_root_generation = predecessor
                    .manifest_generation
                    .checked_add(1)
                    .ok_or_else(|| {
                        QRunV06PermissionlessRuntimeError::LocalAnchorVault(
                            "global root generation overflow".into(),
                        )
                    })?;
                if root_tip.manifest_generation != expected_root_generation
                    || root_tip.manifest_anchor != segment_root_anchor
                {
                    return Err(QRunV06PermissionlessRuntimeError::LocalAnchorVault(
                        "C: vault did not durably publish the exact checkpoint segment root".into(),
                    ));
                }
                Ok(new_store)
            })()
        };
        let new_store = match result {
            Ok(store) => store,
            Err(error) => {
                if witness_written {
                    self.local_anchor_failed = true;
                }
                return Err(error);
            }
        };
        let retired = std::mem::replace(&mut self.store, new_store);
        self.retired_segments.push(retired);
        Ok(checkpoint_anchor)
    }

    fn persist_local_anchor_after_commit(
        &mut self,
        commit: &QRunV06DurableCommit,
    ) -> Result<(), QRunV06PermissionlessRuntimeError> {
        if self.local_anchor_failed {
            return Err(QRunV06PermissionlessRuntimeError::LocalAnchorRecoveryRequired);
        }
        if let Some(vault) = self.local_anchor_vault.as_mut() {
            let result = if vault.latest_checkpoint_segment_witness().is_some() {
                vault.append_segment_successor(commit.generation, commit.manifest_anchor)
            } else {
                vault.append_successor(commit.generation, commit.manifest_anchor)
            };
            if let Err(error) = result {
                self.local_anchor_failed = true;
                return Err(QRunV06PermissionlessRuntimeError::LocalAnchorVault(error));
            }
        }
        Ok(())
    }

    pub fn local_anchor_requires_reopen(&self) -> bool {
        self.local_anchor_failed
    }

    pub fn local_anchor_persistence_status(&self) -> &'static str {
        if self.local_anchor_failed {
            "REOPEN_REQUIRED"
        } else if self.local_anchor_vault.is_some() {
            "LOCAL_C_VAULT_PER_COMMIT_PERSISTED"
        } else {
            "NOT_CONFIGURED"
        }
    }

    pub fn local_anchor_vault_tip(
        &self,
    ) -> Option<crate::qrun_v06_local_anchor_vault_candidate::QRunV06LocalAnchorVaultTip> {
        self.local_anchor_vault.as_ref().map(|vault| vault.tip())
    }

    /// Open a trust-authorized profile with fresh Q6QA verification while replaying the
    /// complete durable history. Any external-quote block lacking valid height-bound trust
    /// evidence aborts startup; the ordinary open() API remains fail-closed for such archives.
    pub fn open_with_quote_asset_authorization<A: TransactionAuthenticator>(
        directory: impl AsRef<Path>,
        genesis_state: QRunV06CanonicalExecutionState,
        params: ConsensusParameters,
        authenticator: &A,
        trusted_manifest_anchor: Option<[u8; 32]>,
        authorized_profile_pin: &QRunV06TrustAuthorizedProfilePin,
        quote_authorizer: &mut QRunV06QuoteAssetAuthorizationProvider<'_>,
    ) -> Result<Self, QRunV06PermissionlessRuntimeError> {
        let descriptor = authorized_profile_pin.verified_profile_pin().descriptor();
        if descriptor.consensus_fingerprint()
            != crate::qrun_v06_checkpoint_candidate::qrun_v06_consensus_fingerprint(&params)
                .map_err(|error| QRunV06PermissionlessRuntimeError::Store(format!("{error:?}")))?
        {
            return Err(QRunV06PermissionlessRuntimeError::Store(
                "Q6PN consensus fingerprint differs from the pinned Q6CP profile".into(),
            ));
        }
        if genesis_state.genesis_descriptor() != Some(descriptor)
            || genesis_state.network_id() != descriptor.network_id()
            || genesis_state.profile_id() != descriptor.profile_id()
        {
            return Err(QRunV06PermissionlessRuntimeError::Store(
                "Q6PN Genesis descriptor differs from the supplied canonical Genesis".into(),
            ));
        }
        let (founder_account, policy_fingerprint) = genesis_state
            .genesis_economic_policy_identity()
            .ok_or_else(|| {
                QRunV06PermissionlessRuntimeError::Store(
                    "Genesis economic policy identity is absent".into(),
                )
            })?;
        if founder_account != descriptor.founder_account()
            || policy_fingerprint != descriptor.tokenomics_policy_fingerprint()
        {
            return Err(QRunV06PermissionlessRuntimeError::Store(
                "Genesis founder/economic-policy identity differs from the Q6PN descriptor".into(),
            ));
        }
        let network_id = descriptor.network_id();
        let profile_id = descriptor.profile_id();
        let store = QRunV06DurableForkStore::open_with_trust_authorized_profile_pin_and_quote_asset_authorization(
            directory,
            genesis_state,
            params,
            authenticator,
            trusted_manifest_anchor,
            authorized_profile_pin,
            quote_authorizer,
        )?;
        if store.has_qap1_intent()? {
            return Err(QRunV06PermissionlessRuntimeError::UnresolvedQap1Intent);
        }
        Ok(Self {
            store,
            network_id,
            profile_id,
            local_anchor_vault: None,
            local_anchor_failed: false,
            retired_segments: Vec::new(),
            auto_checkpoint_rollover: None,
        })
    }

    /// Native-only base admission. A successful return means local durable commit, not a
    /// globally acknowledged/network-finalized transaction or block. External quote activity
    /// fails closed through this compatibility entry point.
    pub fn submit_envelope<A: TransactionAuthenticator>(
        &mut self,
        envelope: &[u8],
        authenticator: &A,
    ) -> Result<QRunV06DurableCommit, QRunV06PermissionlessRuntimeError> {
        if self.local_anchor_failed {
            return Err(QRunV06PermissionlessRuntimeError::LocalAnchorRecoveryRequired);
        }
        if self.store.has_qap1_intent()? {
            return Err(QRunV06PermissionlessRuntimeError::UnresolvedQap1Intent);
        }
        self.rotate_if_archive_capacity_reached(authenticator)?;
        let commit = self.store.submit(envelope, authenticator)?;
        self.persist_local_anchor_after_commit(&commit)?;
        Ok(commit)
    }

    pub fn submit_envelope_with_quote_asset_authorization<A: TransactionAuthenticator>(
        &mut self,
        envelope: &[u8],
        authenticator: &A,
        quote_authorizer: &mut QRunV06QuoteAssetAuthorizationProvider<'_>,
    ) -> Result<QRunV06DurableCommit, QRunV06PermissionlessRuntimeError> {
        if self.local_anchor_failed {
            return Err(QRunV06PermissionlessRuntimeError::LocalAnchorRecoveryRequired);
        }
        if self.store.has_qap1_intent()? {
            return Err(QRunV06PermissionlessRuntimeError::UnresolvedQap1Intent);
        }
        let commit = self.store.submit_with_quote_asset_authorization(
            envelope,
            authenticator,
            quote_authorizer,
        )?;
        self.persist_local_anchor_after_commit(&commit)?;
        Ok(commit)
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
        self.import_history_batch_with_quote_asset_authorization(envelopes, authenticator, None)
    }

    pub fn import_history_batch_with_quote_asset_authorization<A: TransactionAuthenticator>(
        &mut self,
        envelopes: &[Vec<u8>],
        authenticator: &A,
        mut quote_authorizer: Option<&mut QRunV06QuoteAssetAuthorizationProvider<'_>>,
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
            let result = match quote_authorizer.as_deref_mut() {
                Some(provider) => self.submit_envelope_with_quote_asset_authorization(
                    envelope,
                    authenticator,
                    provider,
                ),
                None => self.submit_envelope(envelope, authenticator),
            };
            if let Err(error) = result {
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
        self.import_history_branch_batch_with_quote_asset_authorization(
            start_height,
            expected_parent_consensus_hash,
            expected_parent_execution_hash,
            envelopes,
            authenticator,
            None,
        )
    }

    pub fn import_history_branch_batch_with_quote_asset_authorization<
        A: TransactionAuthenticator,
    >(
        &mut self,
        start_height: u64,
        expected_parent_consensus_hash: [u8; 32],
        expected_parent_execution_hash: [u8; 32],
        envelopes: &[Vec<u8>],
        authenticator: &A,
        mut quote_authorizer: Option<&mut QRunV06QuoteAssetAuthorizationProvider<'_>>,
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
            let submit_result = match quote_authorizer.as_deref_mut() {
                Some(provider) => self.submit_envelope_with_quote_asset_authorization(
                    envelope,
                    authenticator,
                    provider,
                ),
                None => self.submit_envelope(envelope, authenticator),
            };
            if let Err(error) = submit_result {
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

    /// Read one retained canonical block body by height.
    /// Genesis/checkpoint base state has no retained body and is reported as unavailable.
    pub fn canonical_block_read(
        &self,
        height: u64,
    ) -> Result<Option<QRunV06CanonicalBlockRead>, QRunV06PermissionlessRuntimeError> {
        let status = self.status()?;
        let graph = self.store.graph()?.clone();
        let graph_tip = graph.canonical_tip();
        if graph_tip.height != status.height || graph_tip.tip_hash != status.tip {
            return Err(QRunV06PermissionlessRuntimeError::Store(
                "canonical block lookup changed across its runtime snapshot".into(),
            ));
        }
        if height <= graph.base_height() || height > status.height {
            return Ok(None);
        }

        let page = graph
            .canonical_history_page(height, 1, MAX_QRUN_V06_POW_ENVELOPE_BYTES)
            .map_err(|error| QRunV06PermissionlessRuntimeError::Store(error.to_string()))?;
        if page.snapshot_height != status.height || page.snapshot_tip != status.tip {
            return Err(QRunV06PermissionlessRuntimeError::Store(
                "canonical block page is not bound to the current runtime snapshot".into(),
            ));
        }
        let Some(envelope) = page.envelopes.first() else {
            return Ok(None);
        };
        if page.envelopes.len() != 1 {
            return Err(QRunV06PermissionlessRuntimeError::Store(
                "canonical block page returned an unexpected number of envelopes".into(),
            ));
        }
        let decoded = decode_qrun_v06_pow_block(envelope)
            .map_err(|error| QRunV06PermissionlessRuntimeError::Store(error.to_string()))?;
        let consensus_tip = pow_digest(&decoded.header, graph.consensus_parameters().pow)
            .map_err(|error| QRunV06PermissionlessRuntimeError::Store(error.to_string()))?;
        let execution_block_id = qrun_v06_block_id(&decoded.block)
            .map_err(|error| QRunV06PermissionlessRuntimeError::Store(format!("{error:?}")))?;
        let state = graph.state_for_tip(&consensus_tip).ok_or_else(|| {
            QRunV06PermissionlessRuntimeError::Store(
                "canonical block is absent from the retained fork graph".into(),
            )
        })?;
        let computed_root = state
            .state_root()
            .map_err(|error| QRunV06PermissionlessRuntimeError::Store(format!("{error:?}")))?;
        if decoded.block.height != height
            || state.height() != height
            || state.tip_hash() != execution_block_id
            || decoded.block.state_root != computed_root
            || !graph.is_ancestor_tip(&consensus_tip, &status.tip)
        {
            return Err(QRunV06PermissionlessRuntimeError::Store(
                "canonical block body, retained execution state and selected tip disagree".into(),
            ));
        }

        let mut operations = Vec::with_capacity(decoded.block.operations.len());
        for (index, operation) in decoded.block.operations.iter().enumerate() {
            let (kind, transaction) = match operation {
                QRunV06BlockOperation::NativeTransfer(tx) => {
                    let transaction = canonical_transaction_fields(tx)?;
                    ("native_transfer", Some(transaction))
                }
                QRunV06BlockOperation::Amm(_) => ("amm", None),
                QRunV06BlockOperation::AssetRegistration(_) => ("asset_registration", None),
                QRunV06BlockOperation::AssetAdmin(_) => ("asset_admin", None),
                QRunV06BlockOperation::OrderBook(_) => ("order_book", None),
                QRunV06BlockOperation::CategoryRelease(_) => ("category_release", None),
                QRunV06BlockOperation::ProtocolBurnReserveRetirement(_) => {
                    ("protocol_burn_reserve_retirement", None)
                }
            };
            operations.push(QRunV06CanonicalBlockOperationRead {
                index,
                kind,
                transaction,
            });
        }

        Ok(Some(QRunV06CanonicalBlockRead {
            network_id: decoded.block.network_id,
            profile_id: decoded.block.profile_id,
            height: decoded.block.height,
            timestamp: decoded.block.timestamp,
            parent_hash: decoded.block.parent_hash,
            execution_block_id,
            consensus_tip,
            state_root: computed_root,
            producer: decoded.block.producer,
            operation_count: decoded.block.operations.len(),
            operations,
            canonical_height: status.height,
            canonical_tip: status.tip,
            canonical_state_root: status.state_root,
        }))
    }

    /// Find a native TXN2 transaction in the retained fork archive.
    /// Canonical inclusion wins over a stale side-branch copy; otherwise the newest retained
    /// noncanonical inclusion is returned with inclusion_status = reorged.
    pub fn canonical_transaction_read(
        &self,
        transaction_id: &[u8; 32],
    ) -> Result<Option<QRunV06CanonicalTransactionRead>, QRunV06PermissionlessRuntimeError> {
        let status = self.status()?;
        let graph = self.store.graph()?.clone();
        let graph_tip = graph.canonical_tip();
        if graph_tip.height != status.height || graph_tip.tip_hash != status.tip {
            return Err(QRunV06PermissionlessRuntimeError::Store(
                "transaction lookup changed across its runtime snapshot".into(),
            ));
        }

        let envelopes = graph
            .archive_envelopes_bounded(
                MAX_QRUN_V06_FORK_ARCHIVE_BLOCKS,
                QRUN_V06_READ_API_MAX_ARCHIVE_BYTES,
            )
            .map_err(|error| QRunV06PermissionlessRuntimeError::Store(error.to_string()))?;
        let mut canonical_match = None;
        let mut reorged_match: Option<QRunV06CanonicalTransactionRead> = None;

        for envelope in envelopes {
            let decoded = decode_qrun_v06_pow_block(&envelope)
                .map_err(|error| QRunV06PermissionlessRuntimeError::Store(error.to_string()))?;
            let consensus_tip = pow_digest(&decoded.header, graph.consensus_parameters().pow)
                .map_err(|error| QRunV06PermissionlessRuntimeError::Store(error.to_string()))?;
            let execution_block_id = qrun_v06_block_id(&decoded.block)
                .map_err(|error| QRunV06PermissionlessRuntimeError::Store(format!("{error:?}")))?;
            let state = graph.state_for_tip(&consensus_tip).ok_or_else(|| {
                QRunV06PermissionlessRuntimeError::Store(
                    "archived transaction block is absent from its fork graph".into(),
                )
            })?;
            let computed_root = state
                .state_root()
                .map_err(|error| QRunV06PermissionlessRuntimeError::Store(format!("{error:?}")))?;
            if state.height() != decoded.block.height
                || state.tip_hash() != execution_block_id
                || decoded.block.state_root != computed_root
            {
                return Err(QRunV06PermissionlessRuntimeError::Store(
                    "archived transaction body disagrees with its retained execution state".into(),
                ));
            }

            let is_canonical = graph.is_ancestor_tip(&consensus_tip, &status.tip);
            for operation in &decoded.block.operations {
                let QRunV06BlockOperation::NativeTransfer(tx) = operation else {
                    continue;
                };
                let fields = canonical_transaction_fields(tx)?;
                if &fields.transaction_id != transaction_id {
                    continue;
                }
                let read = QRunV06CanonicalTransactionRead {
                    transaction: fields,
                    inclusion_status: if is_canonical { "canonical" } else { "reorged" },
                    block_height: decoded.block.height,
                    block_timestamp: decoded.block.timestamp,
                    execution_block_id,
                    consensus_tip,
                    block_state_root: computed_root,
                    producer: decoded.block.producer,
                    confirmations: if is_canonical {
                        status
                            .height
                            .saturating_sub(decoded.block.height)
                            .saturating_add(1)
                    } else {
                        0
                    },
                    canonical_height: status.height,
                    canonical_tip: status.tip,
                    canonical_state_root: status.state_root,
                };
                if is_canonical {
                    canonical_match = Some(read);
                } else if reorged_match
                    .as_ref()
                    .is_none_or(|existing| read.block_height > existing.block_height)
                {
                    reorged_match = Some(read);
                }
            }
        }

        Ok(canonical_match.or(reorged_match))
    }

    /// Read a native account from the selected canonical execution state.
    /// The global state root commits this value but is not itself an account inclusion proof.
    pub fn canonical_account_read(
        &self,
        account_id: &[u8; 32],
    ) -> Result<QRunV06CanonicalAccountRead, QRunV06PermissionlessRuntimeError> {
        let status = self.status()?;
        let graph = self.store.graph()?;
        let graph_tip = graph.canonical_tip();
        let state = graph.canonical_state();
        let computed_root = state
            .state_root()
            .map_err(|error| QRunV06PermissionlessRuntimeError::Store(format!("{error:?}")))?;
        // QFP6 consensus tip and QFB6 execution block ID are distinct domains.
        // Compare runtime status against the graph's consensus tip, not state.tip_hash().
        if state.height() != status.height
            || graph_tip.height != status.height
            || graph_tip.tip_hash != status.tip
            || computed_root != status.state_root
        {
            return Err(QRunV06PermissionlessRuntimeError::Store(
                "canonical account read changed across its status/root snapshot".into(),
            ));
        }
        let account = state.unified().ledger().account(account_id);
        Ok(QRunV06CanonicalAccountRead {
            network_id: status.network_id,
            profile_id: status.profile_id,
            native_asset_id: state.unified().native_asset_id(),
            account_id: *account_id,
            balance_atoms: account.map(|value| value.balance),
            nonce: account.map(|value| value.nonce),
            height: status.height,
            tip: status.tip,
            state_root: status.state_root,
        })
    }
    /// Read fixed-supply accounting directly from the selected canonical execution state.
    pub fn canonical_supply_read(
        &self,
    ) -> Result<QRunV06CanonicalSupplyRead, QRunV06PermissionlessRuntimeError> {
        let status = self.status()?;
        let graph = self.store.graph()?;
        let graph_tip = graph.canonical_tip();
        let state = graph.canonical_state();
        let computed_root = state
            .state_root()
            .map_err(|error| QRunV06PermissionlessRuntimeError::Store(format!("{error:?}")))?;
        // QFP6 consensus tip and QFB6 execution block ID are distinct domains.
        // Compare runtime status against the graph's consensus tip, not state.tip_hash().
        if state.height() != status.height
            || graph_tip.height != status.height
            || graph_tip.tip_hash != status.tip
            || computed_root != status.state_root
        {
            return Err(QRunV06PermissionlessRuntimeError::Store(
                "canonical supply read changed across its status/root snapshot".into(),
            ));
        }
        let policy = state.cp0651_supply().ok_or_else(|| {
            QRunV06PermissionlessRuntimeError::Store(
                "CP-0651 fixed-supply policy is absent from canonical state".into(),
            )
        })?;
        let ledger_total_atoms = state
            .unified()
            .ledger()
            .total_value()
            .map_err(|error| QRunV06PermissionlessRuntimeError::Store(format!("{error:?}")))?;
        Ok(QRunV06CanonicalSupplyRead {
            network_id: status.network_id,
            profile_id: status.profile_id,
            native_asset_id: state.unified().native_asset_id(),
            ledger_total_atoms,
            owner_genesis_atoms: policy.owner_genesis_atoms(),
            maximum_supply_atoms: policy.maximum_supply_atoms(),
            block_subsidy_atoms: policy.block_subsidy_atoms(),
            accounting_labels_total_atoms: policy.accounting_labels_total_atoms(),
            policy_fingerprint: policy.policy_fingerprint(),
            height: status.height,
            tip: status.tip,
            state_root: status.state_root,
        })
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

    struct DigestTransactions;

    impl crate::state_machine::TransactionAuthenticator for DigestTransactions {
        fn verify(
            &self,
            _account: &crate::state_machine::AccountId,
            digest: &[u8; 32],
            signature: &[u8],
        ) -> Result<(), ()> {
            if signature == digest {
                Ok(())
            } else {
                Err(())
            }
        }
    }

    #[test]
    fn cp0651_canonical_account_read_reports_exact_genesis_atoms_and_survives_restart() {
        use crate::{
            consensus::{ConsensusParameters, Uint256},
            external_cas_anchor_candidate::ExternalCasPin,
            qrun_v06_canonical_execution_candidate::QRunV06BlockOperation,
            qrun_v06_checkpoint_candidate::qrun_v06_consensus_fingerprint,
            qrun_v06_cp0651_supply_candidate::{Cp0651FixedSupply, CP0651_OWNER_GENESIS_ATOMS},
            qrun_v06_genesis_descriptor_candidate::QRunV06GenesisDescriptor,
            qrun_v06_miner_candidate::mine_qfp6_block_on_tip_from_nonce,
            qrun_v06_profile_pin_candidate::{
                QRunV06ProfilePinCandidate, QRunV06VerifiedProfilePin,
            },
            state_machine::{
                transaction_id_with_signature_limit, transaction_signing_digest, Transaction,
                QRUN_V06_MAX_NATIVE_TX_SIGNATURE_BYTES,
            },
            v4_fat1_trust_candidate::ML_DSA_65_PUBLIC_KEY_BYTES,
        };
        use std::sync::atomic::AtomicBool;

        const NETWORK: [u8; 32] = [0x71; 32];
        const PROFILE: [u8; 32] = [0x72; 32];
        const OWNER: [u8; 32] = [0x73; 32];
        const RECIPIENT: [u8; 32] = [0x78; 32];
        const PRODUCER: [u8; 32] = [0x79; 32];
        let mut params = ConsensusParameters::qrun_v06_cp0651_fee_only_candidate().unwrap();
        params.target_block_time_secs = 30;
        params.difficulty_window_blocks = 2;
        params.difficulty_min_ratio_divisor = 4;
        params.difficulty_max_ratio = 4;
        params.initial_target = Uint256::from_be_bytes([0x7F; 32]);
        params.pow_limit = Uint256::MAX;
        params.validate().unwrap();

        let policy = Cp0651FixedSupply::genesis(NETWORK, OWNER).unwrap();
        let descriptor = QRunV06GenesisDescriptor::new(
            NETWORK,
            PROFILE,
            OWNER,
            1,
            qrun_v06_consensus_fingerprint(&params).unwrap(),
            policy.policy_fingerprint(),
        )
        .unwrap();
        let genesis =
            QRunV06CanonicalExecutionState::cp0651_genesis_candidate_with_descriptor(descriptor)
                .unwrap();
        assert_eq!(
            genesis.unified().ledger().account(&OWNER).unwrap().balance as u128,
            CP0651_OWNER_GENESIS_ATOMS
        );

        let bundle = QRunV06ProfilePinCandidate::new(
            descriptor,
            ExternalCasPin {
                provider_id: [0x74; 32],
                network_id: NETWORK,
                genesis_digest: [0x75; 32],
                receipt_key_id: [0x76; 32],
                receipt_public_key: [0x77; ML_DSA_65_PUBLIC_KEY_BYTES],
            },
        )
        .unwrap();
        let pin_bytes = bundle.encode().unwrap();
        let pin_commitment = bundle.commitment().unwrap();
        let verified_pin = QRunV06VerifiedProfilePin::decode(&pin_bytes, pin_commitment).unwrap();
        let directory =
            std::env::temp_dir().join(format!("qfp6-cp0651-account-read-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        let authenticator = DigestTransactions;
        let mut runtime = QRunV06PermissionlessNodeRuntime::open(
            &directory,
            genesis.clone(),
            params.clone(),
            &authenticator,
            None,
            &verified_pin,
        )
        .unwrap();
        let status = runtime.status().unwrap();
        let owner_read = runtime.canonical_account_read(&OWNER).unwrap();
        assert_eq!(owner_read.network_id, NETWORK);
        assert_eq!(owner_read.profile_id, PROFILE);
        assert_eq!(owner_read.account_id, OWNER);
        assert_eq!(
            owner_read.balance_atoms,
            Some(CP0651_OWNER_GENESIS_ATOMS as u64)
        );
        assert_eq!(owner_read.height, 0);
        assert_eq!(owner_read.tip, status.tip);
        assert_eq!(owner_read.state_root, status.state_root);
        assert_eq!(owner_read.nonce, Some(0));
        let account_hex = OWNER
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let (status_code, account_json) =
            crate::qrun_v06_node_supervisor_candidate::qfp6_read_api_response(
                "GET",
                &format!("/v1/account/{account_hex}"),
                &runtime,
            );
        assert_eq!(status_code, 200);
        let account_value: serde_json::Value = serde_json::from_slice(&account_json).unwrap();
        assert_eq!(
            account_value["balance_atoms"].as_str(),
            Some("100000000000000000")
        );
        assert_eq!(account_value["height"].as_str(), Some("0"));
        assert_eq!(account_value["proof_type"], "global_state_root_only");
        let (supply_status, supply_json) =
            crate::qrun_v06_node_supervisor_candidate::qfp6_read_api_response(
                "GET",
                "/v1/supply",
                &runtime,
            );
        assert_eq!(supply_status, 200);
        let supply_value: serde_json::Value = serde_json::from_slice(&supply_json).unwrap();
        assert_eq!(
            supply_value["ledger_total_atoms"].as_str(),
            Some("100000000000000000")
        );
        assert_eq!(
            supply_value["owner_genesis_atoms"].as_str(),
            Some("100000000000000000")
        );
        assert_eq!(
            supply_value["maximum_supply_atoms"].as_str(),
            Some("700000000000000000")
        );
        assert_eq!(supply_value["block_subsidy_atoms"].as_str(), Some("0"));
        assert_eq!(
            supply_value["accounting_labels_total_atoms"].as_str(),
            Some("600000000000000000")
        );
        assert_eq!(supply_value["accounting_labels_are_minted"], false);
        assert!(account_value["account_inclusion_proof"].is_null());
        let (post_status, _) = crate::qrun_v06_node_supervisor_candidate::qfp6_read_api_response(
            "POST",
            "/v1/status",
            &runtime,
        );
        assert_eq!(post_status, 405);

        let http_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut http_client =
            std::net::TcpStream::connect(http_listener.local_addr().unwrap()).unwrap();
        let request = format!("GET /v1/account/{account_hex} HTTP/1.1\r\nHost: localhost\r\n\r\n");
        std::io::Write::write_all(&mut http_client, request.as_bytes()).unwrap();
        crate::qrun_v06_node_supervisor_candidate::serve_qfp6_read_api_once(
            &http_listener,
            &runtime,
        )
        .unwrap();
        let mut http_response = Vec::new();
        std::io::Read::read_to_end(&mut http_client, &mut http_response).unwrap();
        let http_response = String::from_utf8(http_response).unwrap();
        assert!(http_response.starts_with("HTTP/1.1 200 OK\r\n"));
        let (_, response_body) = http_response.split_once("\r\n\r\n").unwrap();
        let http_value: serde_json::Value = serde_json::from_str(response_body).unwrap();
        assert_eq!(
            http_value["balance_atoms"].as_str(),
            Some("100000000000000000")
        );
        let absent = runtime.canonical_account_read(&[0x7A; 32]).unwrap();
        assert_eq!(absent.balance_atoms, None);
        assert_eq!(absent.nonce, None);
        assert_eq!(absent.state_root, status.state_root);

        // Commit one signed native transfer and verify its canonical block/receipt surfaces.
        let mut tx = Transaction {
            network_id: NETWORK,
            sender: OWNER,
            recipient: RECIPIENT,
            nonce: 1,
            amount: 25,
            fee: 2,
            expires_at: 500,
            signature: Vec::new(),
        };
        tx.signature = transaction_signing_digest(&tx).unwrap().to_vec();
        let expected_txid =
            transaction_id_with_signature_limit(&tx, QRUN_V06_MAX_NATIVE_TX_SIGNATURE_BYTES)
                .unwrap();
        let graph = runtime.fork_choice_snapshot().unwrap();
        let transfer_block = mine_qfp6_block_on_tip_from_nonce(
            &graph,
            &graph.canonical_tip().tip_hash,
            100,
            PRODUCER,
            vec![QRunV06BlockOperation::NativeTransfer(tx)],
            &authenticator,
            0,
            4_096,
            &AtomicBool::new(false),
        )
        .unwrap();
        runtime
            .submit_envelope(&transfer_block.envelope, &authenticator)
            .unwrap();

        let canonical_block = runtime.canonical_block_read(1).unwrap().unwrap();
        assert_eq!(canonical_block.height, 1);
        assert_eq!(canonical_block.operation_count, 1);
        assert_eq!(canonical_block.operations[0].kind, "native_transfer");
        assert_eq!(
            canonical_block.operations[0]
                .transaction
                .unwrap()
                .transaction_id,
            expected_txid
        );
        let canonical_receipt = runtime
            .canonical_transaction_read(&expected_txid)
            .unwrap()
            .unwrap();
        assert_eq!(canonical_receipt.inclusion_status, "canonical");
        assert_eq!(canonical_receipt.block_height, 1);
        assert_eq!(canonical_receipt.confirmations, 1);

        let txid_hex = expected_txid
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let (block_http_status, block_json) =
            crate::qrun_v06_node_supervisor_candidate::qfp6_read_api_response(
                "GET",
                "/v1/block/1",
                &runtime,
            );
        assert_eq!(block_http_status, 200);
        let block_value: serde_json::Value = serde_json::from_slice(&block_json).unwrap();
        assert_eq!(block_value["height"].as_str(), Some("1"));
        assert_eq!(block_value["operations"][0]["type"], "native_transfer");
        let (tx_http_status, tx_json) =
            crate::qrun_v06_node_supervisor_candidate::qfp6_read_api_response(
                "GET",
                &format!("/v1/transaction/{txid_hex}"),
                &runtime,
            );
        assert_eq!(tx_http_status, 200);
        let tx_value: serde_json::Value = serde_json::from_slice(&tx_json).unwrap();
        assert_eq!(tx_value["transaction_id"].as_str(), Some(txid_hex.as_str()));
        assert_eq!(tx_value["status"], "canonical");
        assert_eq!(tx_value["confirmations"].as_str(), Some("1"));
        assert_eq!(tx_value["mempool_checked"], false);

        let (invalid_height_status, _) =
            crate::qrun_v06_node_supervisor_candidate::qfp6_read_api_response(
                "GET",
                "/v1/block/01",
                &runtime,
            );
        assert_eq!(invalid_height_status, 400);
        let (invalid_txid_status, _) =
            crate::qrun_v06_node_supervisor_candidate::qfp6_read_api_response(
                "GET",
                "/v1/transaction/not-a-transaction-id",
                &runtime,
            );
        assert_eq!(invalid_txid_status, 400);
        let (block_post_status, _) =
            crate::qrun_v06_node_supervisor_candidate::qfp6_read_api_response(
                "POST",
                "/v1/block/1",
                &runtime,
            );
        assert_eq!(block_post_status, 405);
        let (missing_tx_status, missing_tx_json) =
            crate::qrun_v06_node_supervisor_candidate::qfp6_read_api_response(
                "GET",
                &format!("/v1/transaction/{}", "00".repeat(32)),
                &runtime,
            );
        assert_eq!(missing_tx_status, 404);
        let missing_tx_value: serde_json::Value = serde_json::from_slice(&missing_tx_json).unwrap();
        assert_eq!(missing_tx_value["mempool_checked"], false);
        assert_eq!(
            missing_tx_value["pending_status"],
            "not_available_from_this_endpoint"
        );

        // Build a longer competing branch from Genesis. The transfer block remains archived,
        // but its receipt must change to reorged once the two-block branch wins fork choice.
        let competing_parent = runtime.fork_choice_snapshot().unwrap();
        let competing_first = mine_qfp6_block_on_tip_from_nonce(
            &competing_parent,
            &competing_parent.base_tip(),
            130,
            [0x7B; 32],
            Vec::new(),
            &authenticator,
            0,
            4_096,
            &AtomicBool::new(false),
        )
        .unwrap();
        runtime
            .submit_envelope(&competing_first.envelope, &authenticator)
            .unwrap();
        let competing_graph = runtime.fork_choice_snapshot().unwrap();
        let competing_second = mine_qfp6_block_on_tip_from_nonce(
            &competing_graph,
            &competing_first.block_digest,
            160,
            [0x7C; 32],
            Vec::new(),
            &authenticator,
            0,
            4_096,
            &AtomicBool::new(false),
        )
        .unwrap();
        runtime
            .submit_envelope(&competing_second.envelope, &authenticator)
            .unwrap();

        let after_reorg = runtime.status().unwrap();
        assert_eq!(after_reorg.height, 2);
        let reorged_receipt = runtime
            .canonical_transaction_read(&expected_txid)
            .unwrap()
            .unwrap();
        assert_eq!(reorged_receipt.inclusion_status, "reorged");
        assert_eq!(reorged_receipt.confirmations, 0);
        assert_eq!(reorged_receipt.canonical_height, 2);
        let canonical_height_one = runtime.canonical_block_read(1).unwrap().unwrap();
        assert_eq!(canonical_height_one.operation_count, 0);
        assert_ne!(
            canonical_height_one.consensus_tip,
            transfer_block.block_digest
        );
        assert_eq!(runtime.canonical_block_read(2).unwrap().unwrap().height, 2);

        let (reorg_http_status, reorg_json) =
            crate::qrun_v06_node_supervisor_candidate::qfp6_read_api_response(
                "GET",
                &format!("/v1/transaction/{txid_hex}"),
                &runtime,
            );
        assert_eq!(reorg_http_status, 200);
        let reorg_value: serde_json::Value = serde_json::from_slice(&reorg_json).unwrap();
        assert_eq!(reorg_value["status"], "reorged");
        assert_eq!(reorg_value["confirmations"].as_str(), Some("0"));

        let owner_read = runtime.canonical_account_read(&OWNER).unwrap();
        let supply_snapshot = runtime.canonical_supply_read().unwrap();
        let status = runtime.status().unwrap();
        drop(runtime);

        let recovered = QRunV06PermissionlessNodeRuntime::open(
            &directory,
            genesis,
            params,
            &authenticator,
            Some(status.manifest_anchor),
            &verified_pin,
        )
        .unwrap();
        assert_eq!(
            recovered.canonical_account_read(&OWNER).unwrap(),
            owner_read
        );
        assert_eq!(recovered.canonical_supply_read().unwrap(), supply_snapshot);
        let recovered_receipt = recovered
            .canonical_transaction_read(&expected_txid)
            .unwrap()
            .unwrap();
        assert_eq!(recovered_receipt.inclusion_status, "reorged");
        assert_eq!(recovered_receipt.confirmations, 0);
        assert_eq!(
            recovered.canonical_block_read(2).unwrap().unwrap().height,
            2
        );
        drop(recovered);
        let _ = std::fs::remove_dir_all(&directory);
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
        // CP-0604 Genesis uses the legacy 10B mining schedule, not CP-0651 fee-only economics.
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
    fn fresh_genesis_anchor_vault_persists_first_commit_and_recovers_one_commit_after_restart() {
        use crate::{
            consensus::{ConsensusParameters, Uint256},
            external_cas_anchor_candidate::ExternalCasPin,
            qrun_v06_checkpoint_candidate::qrun_v06_consensus_fingerprint,
            qrun_v06_cp0604_supply_candidate::Cp0604FounderControlledSupply,
            qrun_v06_genesis_descriptor_candidate::QRunV06GenesisDescriptor,
            qrun_v06_local_anchor_vault_candidate::QRunV06LocalAnchorVault,
            qrun_v06_miner_candidate::mine_qfp6_block_on_tip_from_nonce,
            qrun_v06_pow_fork_store_candidate::QRunV06DurableForkStore,
            qrun_v06_profile_pin_candidate::{
                QRunV06ProfilePinCandidate, QRunV06VerifiedProfilePin,
            },
            qrun_v06_tokenomics_candidate::QRunV06MiningScheduleCandidate,
            v4_fat1_trust_candidate::ML_DSA_65_PUBLIC_KEY_BYTES,
        };
        use std::{fs, sync::atomic::AtomicBool};

        const NETWORK: [u8; 32] = [0x91; 32];
        const PROFILE: [u8; 32] = [0x92; 32];
        const FOUNDER: [u8; 32] = [0x93; 32];
        const PRODUCER: [u8; 32] = [0x94; 32];
        // CP-0604 Genesis uses the legacy 10B mining schedule, not CP-0651 fee-only economics.
        let mut params = ConsensusParameters::qrun_v06_sha256d_candidate().unwrap();
        params.target_block_time_secs = 30;
        params.difficulty_window_blocks = 2;
        params.difficulty_min_ratio_divisor = 4;
        params.difficulty_max_ratio = 4;
        params.initial_target = Uint256::MAX;
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
        let bundle = QRunV06ProfilePinCandidate::new(
            descriptor,
            ExternalCasPin {
                provider_id: [0x95; 32],
                network_id: NETWORK,
                genesis_digest: [0x96; 32],
                receipt_key_id: [0x97; 32],
                receipt_public_key: [0x98; ML_DSA_65_PUBLIC_KEY_BYTES],
            },
        )
        .unwrap();
        let bundle_bytes = bundle.encode().unwrap();
        let verified_pin =
            QRunV06VerifiedProfilePin::decode(&bundle_bytes, bundle.commitment().unwrap()).unwrap();
        let root = std::env::temp_dir().join(format!(
            "qfp6-fresh-genesis-anchor-runtime-{}",
            std::process::id(),
        ));
        let _ = fs::remove_dir_all(&root);
        let data_dir = root.join("joining-data");
        let vault_dir = root.join("joining-vault");
        fs::create_dir_all(&data_dir).unwrap();
        let authenticator = RejectAllTransactions;
        let expected_genesis_dir = root.join("expected-genesis");
        fs::create_dir_all(&expected_genesis_dir).unwrap();
        let expected_store = QRunV06DurableForkStore::open_with_verified_profile_pin(
            &expected_genesis_dir,
            genesis.clone(),
            params.clone(),
            &authenticator,
            None,
            &verified_pin,
        )
        .unwrap();
        let expected_genesis_anchor = expected_store.manifest_anchor().unwrap();
        drop(expected_store);
        fs::remove_dir_all(&expected_genesis_dir).unwrap();
        let mut runtime =
            QRunV06PermissionlessNodeRuntime::open_with_verified_genesis_fresh_anchor_vault(
                &data_dir,
                genesis.clone(),
                params.clone(),
                &authenticator,
                &verified_pin,
                &vault_dir,
            )
            .unwrap();
        let genesis_status = runtime.status().unwrap();
        assert_eq!(genesis_status.height, 0);
        assert_eq!(genesis_status.manifest_generation, 0);
        let genesis_anchor = genesis_status.manifest_anchor;
        assert_eq!(
            runtime.local_anchor_vault_tip().unwrap().manifest_anchor,
            genesis_anchor
        );
        let graph = runtime.fork_choice_snapshot().unwrap();
        let first = mine_qfp6_block_on_tip_from_nonce(
            &graph,
            &graph.canonical_tip().tip_hash,
            100,
            PRODUCER,
            Vec::new(),
            &authenticator,
            0,
            8,
            &AtomicBool::new(false),
        )
        .unwrap();
        runtime
            .submit_envelope(&first.envelope, &authenticator)
            .unwrap();
        assert_eq!(runtime.status().unwrap().height, 1);
        assert_eq!(
            runtime
                .local_anchor_vault_tip()
                .unwrap()
                .manifest_generation,
            1
        );
        drop(runtime);

        // Data generation 2 is committed while the independent Vault deliberately remains at 1.
        let mut interrupted_store =
            QRunV06DurableForkStore::open_with_verified_profile_pin_and_trusted_anchor_ancestor(
                &data_dir,
                genesis.clone(),
                params.clone(),
                &authenticator,
                genesis_anchor,
                0,
                &verified_pin,
            )
            .unwrap();
        let graph = interrupted_store.graph().unwrap().clone();
        let second = mine_qfp6_block_on_tip_from_nonce(
            &graph,
            &graph.canonical_tip().tip_hash,
            130,
            PRODUCER,
            Vec::new(),
            &authenticator,
            0,
            8,
            &AtomicBool::new(false),
        )
        .unwrap();
        interrupted_store
            .submit(&second.envelope, &authenticator)
            .unwrap();
        drop(interrupted_store);
        let lagging_tip = QRunV06LocalAnchorVault::open(&vault_dir, NETWORK, PROFILE)
            .unwrap()
            .tip();
        assert_eq!(lagging_tip.manifest_generation, 1);
        let recovered = QRunV06PermissionlessNodeRuntime::open_with_local_anchor_vault(
            &data_dir,
            genesis.clone(),
            params.clone(),
            &authenticator,
            lagging_tip.manifest_anchor,
            lagging_tip.manifest_generation,
            &verified_pin,
            &vault_dir,
        )
        .unwrap();
        assert_eq!(recovered.status().unwrap().height, 2);
        assert_eq!(
            recovered
                .local_anchor_vault_tip()
                .unwrap()
                .manifest_generation,
            2
        );
        drop(recovered);
        assert!(
            QRunV06PermissionlessNodeRuntime::open_with_fresh_genesis_anchor_vault(
                &data_dir,
                genesis,
                params,
                &authenticator,
                &verified_pin,
                expected_genesis_anchor,
                &vault_dir,
            )
            .is_err()
        );
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn checkpoint_segment_runtime_automatically_rolls_at_1024_and_recovers_unanchored_commit() {
        use crate::{
            consensus::{ConsensusParameters, Uint256},
            external_cas_anchor_candidate::ExternalCasPin,
            qrun_v06_canonical_execution_candidate::QRunV06CanonicalExecutionState,
            qrun_v06_checkpoint_candidate::{
                qrun_v06_consensus_fingerprint, QRunV06CheckpointCandidate,
            },
            qrun_v06_cp0651_supply_candidate::Cp0651FixedSupply,
            qrun_v06_genesis_descriptor_candidate::QRunV06GenesisDescriptor,
            qrun_v06_local_anchor_vault_candidate::QRunV06LocalAnchorVault,
            qrun_v06_miner_candidate::mine_qfp6_block_on_tip_from_nonce,
            qrun_v06_pow_fork_store_candidate::QRunV06DurableForkStore,
            qrun_v06_profile_pin_candidate::{
                QRunV06ProfilePinCandidate, QRunV06VerifiedProfilePin,
            },
            v4_fat1_trust_candidate::ML_DSA_65_PUBLIC_KEY_BYTES,
        };
        use std::{fs, sync::atomic::AtomicBool};

        const NETWORK: [u8; 32] = [0x61; 32];
        const PROFILE: [u8; 32] = [0x62; 32];
        const FOUNDER: [u8; 32] = [0x63; 32];
        const PRODUCER: [u8; 32] = [0x64; 32];

        let mut params = ConsensusParameters::qrun_v06_cp0651_fee_only_candidate().unwrap();
        params.target_block_time_secs = 30;
        params.difficulty_window_blocks = 2;
        params.difficulty_min_ratio_divisor = 4;
        params.difficulty_max_ratio = 4;
        params.initial_target = Uint256::from_be_bytes([0x7F; 32]);
        params.pow_limit = Uint256::MAX;
        params.validate().unwrap();

        let policy = Cp0651FixedSupply::genesis(NETWORK, FOUNDER).unwrap();
        let descriptor = QRunV06GenesisDescriptor::new(
            NETWORK,
            PROFILE,
            FOUNDER,
            1,
            qrun_v06_consensus_fingerprint(&params).unwrap(),
            policy.policy_fingerprint(),
        )
        .unwrap();
        let genesis = QRunV06CanonicalExecutionState::cp0651_genesis_candidate_with_descriptor(
            descriptor.clone(),
        )
        .unwrap();
        let bundle = QRunV06ProfilePinCandidate::new(
            descriptor,
            ExternalCasPin {
                provider_id: [0x65; 32],
                network_id: NETWORK,
                genesis_digest: [0x66; 32],
                receipt_key_id: [0x67; 32],
                receipt_public_key: [0x68; ML_DSA_65_PUBLIC_KEY_BYTES],
            },
        )
        .unwrap();
        let bundle_bytes = bundle.encode().unwrap();
        let verified_pin =
            QRunV06VerifiedProfilePin::decode(&bundle_bytes, bundle.commitment().unwrap()).unwrap();

        let root = std::env::temp_dir().join(format!(
            "qfp6-checkpoint-witness-runtime-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let genesis_dir = root.join("genesis");
        let segments_root = root.join("genesis.checkpoint-segments");
        let segment_dir = segments_root.join("segment-00000000000000000001");
        let vault_dir = root.join("c-vault");
        fs::create_dir_all(&genesis_dir).unwrap();
        let authenticator = RejectAllTransactions;
        let mut genesis_store = QRunV06DurableForkStore::open_with_verified_profile_pin(
            &genesis_dir,
            genesis.clone(),
            params.clone(),
            &authenticator,
            None,
            &verified_pin,
        )
        .unwrap();
        for height in 1..=1_024u64 {
            let graph = genesis_store.graph().unwrap().clone();
            let block = mine_qfp6_block_on_tip_from_nonce(
                &graph,
                &graph.canonical_tip().tip_hash,
                100 + height * 30,
                PRODUCER,
                Vec::new(),
                &authenticator,
                0,
                100_000,
                &AtomicBool::new(false),
            )
            .unwrap();
            genesis_store
                .submit(&block.envelope, &authenticator)
                .unwrap();
        }
        let predecessor_generation = genesis_store.generation().unwrap();
        let predecessor_anchor = genesis_store.manifest_anchor().unwrap();
        let (checkpoint_bytes, checkpoint_anchor) =
            genesis_store.export_canonical_checkpoint().unwrap();
        drop(genesis_store);

        let checkpoint = QRunV06CheckpointCandidate::decode_snapshot(
            &checkpoint_bytes,
            &params,
            &NETWORK,
            &PROFILE,
            checkpoint_anchor,
        )
        .unwrap();
        crate::qrun_v06_local_anchor_vault_candidate::provision_test_root(
            &vault_dir,
            NETWORK,
            PROFILE,
            predecessor_generation,
            predecessor_anchor,
        )
        .unwrap();
        let mut runtime = QRunV06PermissionlessNodeRuntime::open_with_local_anchor_vault(
            &genesis_dir,
            genesis.clone(),
            params.clone(),
            &authenticator,
            predecessor_anchor,
            predecessor_generation,
            &verified_pin,
            &vault_dir,
        )
        .unwrap();
        runtime
            .enable_auto_checkpoint_rollover(&segments_root, verified_pin.clone())
            .unwrap();
        assert_eq!(runtime.status().unwrap().height, checkpoint.height());
        let graph = runtime.fork_choice_snapshot().unwrap();
        let second_block = mine_qfp6_block_on_tip_from_nonce(
            &graph,
            &graph.canonical_tip().tip_hash,
            100 + 1_025 * 30,
            PRODUCER,
            Vec::new(),
            &authenticator,
            0,
            100_000,
            &AtomicBool::new(false),
        )
        .unwrap();
        let second_commit = runtime
            .submit_envelope(&second_block.envelope, &authenticator)
            .unwrap();
        assert_eq!(runtime.status().unwrap().height, checkpoint.height() + 1);
        assert_eq!(
            runtime
                .local_anchor_vault_tip()
                .unwrap()
                .manifest_generation,
            predecessor_generation + 2
        );
        drop(runtime);

        // Simulate a crash after the D: segment manifest commit but before the C: anchor append.
        let c_tip = QRunV06LocalAnchorVault::open(&vault_dir, NETWORK, PROFILE)
            .unwrap()
            .tip();
        let pinned_local_generation = c_tip
            .manifest_generation
            .checked_sub(predecessor_generation + 1)
            .unwrap();
        assert_eq!(pinned_local_generation, 1);
        let mut interrupted_store =
            QRunV06DurableForkStore::open_from_checkpoint_with_verified_profile_pin_and_trusted_anchor_ancestor(
                &segment_dir,
                &checkpoint_bytes,
                params.clone(),
                checkpoint_anchor,
                &verified_pin,
                &authenticator,
                c_tip.manifest_anchor,
                pinned_local_generation,
            )
            .unwrap();
        let graph = interrupted_store.graph().unwrap().clone();
        let third_block = mine_qfp6_block_on_tip_from_nonce(
            &graph,
            &graph.canonical_tip().tip_hash,
            100 + 1_026 * 30,
            PRODUCER,
            Vec::new(),
            &authenticator,
            0,
            100_000,
            &AtomicBool::new(false),
        )
        .unwrap();
        let third_commit = interrupted_store
            .submit(&third_block.envelope, &authenticator)
            .unwrap();
        assert_eq!(interrupted_store.generation().unwrap(), 2);
        drop(interrupted_store);
        assert_eq!(
            QRunV06LocalAnchorVault::open(&vault_dir, NETWORK, PROFILE)
                .unwrap()
                .tip()
                .manifest_generation,
            predecessor_generation + 2,
            "C: must remain exactly one segment-local commit behind before recovery"
        );

        let recovered =
            QRunV06PermissionlessNodeRuntime::open_from_checkpoint_with_local_anchor_vault(
                &segment_dir,
                &checkpoint_bytes,
                checkpoint_anchor,
                params,
                &authenticator,
                &verified_pin,
                &vault_dir,
            )
            .unwrap();
        assert_eq!(recovered.status().unwrap().height, checkpoint.height() + 2);
        assert_eq!(
            recovered
                .local_anchor_vault_tip()
                .unwrap()
                .manifest_generation,
            predecessor_generation + 3
        );
        assert_eq!(
            recovered.status().unwrap().manifest_anchor,
            third_commit.manifest_anchor
        );
        assert_ne!(second_commit.manifest_anchor, third_commit.manifest_anchor);
        drop(recovered);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn local_dual_disk_runtime_persists_each_commit_and_recovers_one_unanchored_generation() {
        use crate::{
            consensus::{ConsensusParameters, Uint256},
            external_cas_anchor_candidate::ExternalCasPin,
            qrun_v06_canonical_execution_candidate::QRunV06CanonicalExecutionState,
            qrun_v06_checkpoint_candidate::qrun_v06_consensus_fingerprint,
            qrun_v06_cp0651_supply_candidate::Cp0651FixedSupply,
            qrun_v06_genesis_descriptor_candidate::QRunV06GenesisDescriptor,
            qrun_v06_local_anchor_vault_candidate::QRunV06LocalAnchorVault,
            qrun_v06_miner_candidate::mine_qfp6_block_on_tip_from_nonce,
            qrun_v06_pow_fork_store_candidate::QRunV06DurableForkStore,
            qrun_v06_profile_pin_candidate::{
                QRunV06ProfilePinCandidate, QRunV06VerifiedProfilePin,
            },
            v4_fat1_trust_candidate::ML_DSA_65_PUBLIC_KEY_BYTES,
        };
        use std::{fs, sync::atomic::AtomicBool};

        const NETWORK: [u8; 32] = [0xA1; 32];
        const PROFILE: [u8; 32] = [0xB2; 32];
        const FOUNDER: [u8; 32] = [0xC3; 32];
        const PRODUCER: [u8; 32] = [0xD5; 32];

        let mut params = ConsensusParameters::qrun_v06_cp0651_fee_only_candidate().unwrap();
        params.target_block_time_secs = 30;
        params.difficulty_window_blocks = 2;
        params.difficulty_min_ratio_divisor = 4;
        params.difficulty_max_ratio = 4;
        params.initial_target = Uint256::from_be_bytes([0x7F; 32]);
        params.pow_limit = Uint256::MAX;
        params.validate().unwrap();

        let policy = Cp0651FixedSupply::genesis(NETWORK, FOUNDER).unwrap();
        let descriptor = QRunV06GenesisDescriptor::new(
            NETWORK,
            PROFILE,
            FOUNDER,
            1,
            qrun_v06_consensus_fingerprint(&params).unwrap(),
            policy.policy_fingerprint(),
        )
        .unwrap();
        let genesis = QRunV06CanonicalExecutionState::cp0651_genesis_candidate_with_descriptor(
            descriptor.clone(),
        )
        .unwrap();
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
        let bundle_bytes = bundle.encode().unwrap();
        let verified_pin =
            QRunV06VerifiedProfilePin::decode(&bundle_bytes, bundle.commitment().unwrap()).unwrap();

        let root = std::env::temp_dir().join(format!(
            "qfp6-local-dual-disk-runtime-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let data_dir = root.join("data");
        let vault_dir = root.join("c-vault");
        fs::create_dir_all(&data_dir).unwrap();

        let authenticator = RejectAllTransactions;
        let bootstrap = QRunV06PermissionlessNodeRuntime::open(
            &data_dir,
            genesis.clone(),
            params.clone(),
            &authenticator,
            None,
            &verified_pin,
        )
        .unwrap();
        let genesis_status = bootstrap.status().unwrap();
        drop(bootstrap);
        crate::qrun_v06_local_anchor_vault_candidate::provision_test_root(
            &vault_dir,
            NETWORK,
            PROFILE,
            genesis_status.manifest_generation,
            genesis_status.manifest_anchor,
        )
        .unwrap();

        let mut runtime = QRunV06PermissionlessNodeRuntime::open_with_local_anchor_vault(
            &data_dir,
            genesis.clone(),
            params.clone(),
            &authenticator,
            genesis_status.manifest_anchor,
            genesis_status.manifest_generation,
            &verified_pin,
            &vault_dir,
        )
        .unwrap();
        let graph = runtime.fork_choice_snapshot().unwrap();
        let first_block = mine_qfp6_block_on_tip_from_nonce(
            &graph,
            &graph.canonical_tip().tip_hash,
            100,
            PRODUCER,
            Vec::new(),
            &authenticator,
            0,
            100_000,
            &AtomicBool::new(false),
        )
        .unwrap();
        let first_commit = runtime
            .submit_envelope(&first_block.envelope, &authenticator)
            .unwrap();
        assert_eq!(
            QRunV06LocalAnchorVault::open(&vault_dir, NETWORK, PROFILE)
                .unwrap()
                .tip()
                .manifest_generation,
            first_commit.generation,
            "a successful runtime commit must already be present in the C: vault"
        );
        assert_eq!(
            QRunV06LocalAnchorVault::open(&vault_dir, NETWORK, PROFILE)
                .unwrap()
                .tip()
                .manifest_anchor,
            first_commit.manifest_anchor
        );
        drop(runtime);

        // Simulate a process interruption in the narrow interval after D: manifest commit
        // but before the C: vault append. A fresh runtime must replay from the exact C: tip,
        // then append only this single verified successor before becoming usable.
        let c_tip = QRunV06LocalAnchorVault::open(&vault_dir, NETWORK, PROFILE)
            .unwrap()
            .tip();
        let mut interrupted_store = QRunV06DurableForkStore::open_with_verified_profile_pin(
            &data_dir,
            genesis.clone(),
            params.clone(),
            &authenticator,
            Some(c_tip.manifest_anchor),
            &verified_pin,
        )
        .unwrap();
        let graph = interrupted_store.graph().unwrap().clone();
        let second_block = mine_qfp6_block_on_tip_from_nonce(
            &graph,
            &graph.canonical_tip().tip_hash,
            130,
            PRODUCER,
            Vec::new(),
            &authenticator,
            0,
            100_000,
            &AtomicBool::new(false),
        )
        .unwrap();
        let second_commit = interrupted_store
            .submit(&second_block.envelope, &authenticator)
            .unwrap();
        assert_eq!(second_commit.generation, c_tip.manifest_generation + 1);
        drop(interrupted_store);

        let recovered = QRunV06PermissionlessNodeRuntime::open_with_local_anchor_vault(
            &data_dir,
            genesis,
            params,
            &authenticator,
            c_tip.manifest_anchor,
            c_tip.manifest_generation,
            &verified_pin,
            &vault_dir,
        )
        .unwrap();
        let recovered_status = recovered.status().unwrap();
        let recovered_vault_tip = QRunV06LocalAnchorVault::open(&vault_dir, NETWORK, PROFILE)
            .unwrap()
            .tip();
        assert_eq!(
            recovered_status.manifest_generation,
            second_commit.generation
        );
        assert_eq!(
            recovered_vault_tip.manifest_generation,
            second_commit.generation
        );
        assert_eq!(
            recovered_vault_tip.manifest_anchor,
            second_commit.manifest_anchor
        );
        assert!(!recovered.local_anchor_requires_reopen());
        drop(recovered);
        fs::remove_dir_all(root).unwrap();
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
