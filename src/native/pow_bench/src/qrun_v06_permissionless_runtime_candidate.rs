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
    qrun_v06_canonical_execution_candidate::QRunV06CanonicalExecutionState,
    qrun_v06_pow_fork_choice_candidate::QRunV06PowForkChoice,
    qrun_v06_pow_fork_store_candidate::{
        QRunV06DurableCommit, QRunV06DurableForkStore, QRunV06ForkStoreError,
    },
    qrun_v06_profile_pin_candidate::QRunV06VerifiedProfilePin,
    state_machine::TransactionAuthenticator,
};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QRunV06PermissionlessRuntimeError {
    Store(String),
    UnresolvedQap1Intent,
}

impl std::fmt::Display for QRunV06PermissionlessRuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(error) => write!(f, "QFP6 permissionless base runtime failed: {error}"),
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
