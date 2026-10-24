//! Research-grade wire framing primitives for protocol experiments.
//! This is not production networking or cryptographic code.

/// Research-only MTP and branch-bound ASERT anchor policy; not wired to canonical consensus.
pub mod asert_anchor_policy_candidate;
pub mod asset_operation_auth_candidate;
pub mod asset_state_adaptive_commitment_candidate;
pub mod asset_state_bucketed_commitment_candidate;
pub mod asset_state_candidate;
pub mod asset_state_candidate_store;
pub mod asset_state_incremental_commitment_candidate;
pub mod asset_transactions;
pub mod auth_transport;
/// Research-only bounded program-pool claim accounting; not wired into canonical consensus.
pub mod bounded_reward_pools_candidate;
pub mod canonical_provider;
pub mod chain_admission;
pub mod chain_import;
pub mod chain_view;
pub mod consensus;
pub mod credential_binding;
/// Candidate-only bounded Noise XX transport pinned to an explicit peer trust set.
pub mod devnet_noise_transport_candidate;
/// Candidate-only, zero-balance Devnet profile/Genesis manifest; not yet wired to a node runtime.
pub mod devnet_profile_candidate;
/// Candidate-only signed peer-identity envelope for the loopback Devnet runtime.
pub mod devnet_signed_peer_identity_candidate;
/// Research-only difficulty adjustment candidates; not wired to canonical block admission.
pub mod difficulty_adjustment_candidates;
/// CP-0313 canonical external append-only CAS record and ML-DSA receipt candidate; no provider runtime or consensus callsite.
pub mod external_cas_anchor_candidate;
pub mod governance_root_chain;
pub mod identity_generation_store;
pub mod identity_policy;
pub mod identity_session;
/// Research-only bounded global/per-peer ingress budgets; deliberately not wired into the node.
pub mod ingress_budget_candidate;
/// Research-only composition of bounded ingress queue and worker leases; not node-wired.
pub mod ingress_pipeline_candidate;
/// Research-only bounded ingress queue with deadline/cancellation/backpressure semantics.
pub mod ingress_queue_candidate;
/// Research-only bounded worker leases with cooperative cancellation/deadline propagation.
pub mod ingress_worker_candidate;
pub mod issuance_schedule;
pub mod key_provider;
/// CP-0391 candidate accounting for the owner-directed v0.4 eight-bucket supply budgets; not runtime-wired.
pub mod monetary_allocation_v04_candidate;
/// CP-0392 candidate canonical Genesis manifest bound to the v0.4 allocation policy; not wired into node runtime.
pub mod monetary_genesis_v04_candidate;
/// CP-0397 explicit, parameterized v0.4 mining-schedule contract; no approved default or runtime callsite.
pub mod monetary_issuance_v04_candidate;
/// CP-0393 candidate bridge from the v0.4 manifest to the deterministic ledger substrate; no runtime integration.
pub mod monetary_ledger_v04_candidate;
/// CP-0213 policy arithmetic candidate; not wired into canonical consensus or block import.
pub mod monetary_policy_v3_candidate;
/// CP-0398 profile-bound atomic mining-only v0.4 state transition; not wired into node runtime.
pub mod monetary_transition_v04_candidate;
pub mod noise_deployment_config;
pub mod noise_issuer_registry;
pub mod noise_key_provisioning;
/// Windows CurrentUser-DPAPI storage for role- and network-bound offline signing seeds.
pub mod offline_signing_key_store;
pub mod p2p_contract;
pub mod peer_policy;
/// Research-only in-process generation lease for archive commits racing a canonical reorg.
pub mod private_testnet_archive_generation_coordinator_candidate;
/// Research-only in-memory server/receiver fault-injection harness.
pub mod private_testnet_archive_range_loopback_candidate;
/// Research-only receiver-side archive page validation and commit-after-verify model.
pub mod private_testnet_archive_range_receiver_candidate;
/// Research-only bounded archive payload range serving; not connected to public networking.
pub mod private_testnet_archive_range_server_candidate;
/// Research-only durable archive-range WAL; not connected to canonical state or live sync.
pub mod private_testnet_archive_range_store_candidate;
/// Research-only bounded paginated archive planner; not wired into node or public wire.
pub mod private_testnet_archive_sync_candidate;
/// Candidate-only canonical PCP4 snapshot codec; not yet durable-store or fork-choice integrated.
pub mod private_testnet_checkpoint_candidate;
pub mod private_testnet_consensus;
pub mod private_testnet_driver;
/// Candidate-only bounded branch archive and cumulative-work fork-choice/replay.
pub mod private_testnet_fork_choice;
/// Candidate-only PFS2 durable PTB2 branch store with single-writer recovery.
pub mod private_testnet_fork_store;
/// Research candidate: deterministic, bounded transaction pool; deliberately not wired into the node.
pub mod private_testnet_mempool_candidate;
/// Candidate-only MBK3 fork choice/replay; not yet connected to PFS2/P2P/runtime.
pub mod private_testnet_monetary_fork_choice;
pub mod private_testnet_monetary_fork_store;
/// Candidate-only PMT3 framing for MBK3 monetary blocks; not connected to live Devnet.
pub mod private_testnet_monetary_wire;
/// Candidate-only verifier for binding PFM5 metadata to a fully replayed Genesis archive.
pub mod private_testnet_pfm5_archive_binding_candidate;
/// Candidate-only durable PFM3 store for PMT3 monetary branch archives.
/// Candidate-only PFM5 manifest codec; not integrated with durable storage or archive replay.
pub mod private_testnet_pfm5_manifest_candidate;
pub mod private_testnet_v4_hybrid_fork_choice_candidate;
pub mod private_testnet_v4_hybrid_fork_store_candidate;
/// Candidate-only PTB2 envelope for linked PoW headers + canonical block-body transport.
pub mod private_testnet_wire;
pub mod protocol_profile;
pub mod recovery;
pub mod reference_time;
pub mod reference_time_store;
pub mod reference_time_tcp;
/// Research-only durable file wrapper for reward-pool snapshots; not canonical persistence.
pub mod reward_pool_durable_store;
pub mod store_writer_lock;
/// CP-0217 isolated V3 state-root/snapshot candidate; not consensus-wired.
pub mod v3_state_candidate;
/// CP-0218 isolated staged V3 transfer/issuance/governance candidate; no production verifiers or consensus callsites.
pub mod v3_transition_candidate;
/// CP-0216 isolated V3 codec candidate; not wired to consensus.
pub mod v3_wire_candidate;
/// CP-0226 isolated legacy-V3/native-V4 hybrid identity binding; PQ verifier remains injected.
pub mod v4_account_identity_candidate;
/// CP-0227 durable local FAT1 floor provider; not an independent anti-rollback trust domain.
pub mod v4_fat1_disk_floor_candidate;
/// CP-0291 ML-DSA-65 verifier adapter candidate; formal verification of components does not replace deployment audit or runtime integration.
pub mod v4_fat1_mldsa65_candidate;
/// CP-0226 isolated signed FAT1 validator/anti-rollback contract; no persistent trust store or consensus callsite.
pub mod v4_fat1_trust_candidate;
/// CP-0226 isolated STV4 fork-activation crash/reorg recovery classifier; not consensus-wired.
pub mod v4_fork_activation_recovery_candidate;
/// CP-0222 isolated GNV4 manifest codec candidate; no canonical Genesis or consensus callsites.
pub mod v4_manifest_candidate;
/// CP-0225 isolated STV4 boundary encoder/validator; not migration/consensus-wired.
pub mod v4_state_boundary_candidate;
/// Candidate-only bounded admission pool for signed TXN4 transfers; not connected to live peer/RPC runtime.
pub mod v4_transaction_mempool_candidate;

// Test-only state classifier for anti-rollback recovery design; no runtime/API exposure.
#[cfg(test)]
mod anti_rollback_recovery_state_model;
#[cfg(test)]
mod external_anchor_disk_harness;
// Test-only cross-store commit transition model; no runtime/API exposure or storage protocol.
#[cfg(test)]
mod anti_rollback_commit_transition_model;
// CP-0234: authenticated receipt/CAS contract model only; no runtime provider or HSM integration.
/// Hidden research harness for transaction rejection and atomic rollback; not consensus-wired.
#[doc(hidden)]
pub mod cp0130_z_transaction_rejection_matrix;
pub mod signature_policy;
pub mod snapshot_store;
pub mod state_machine;
pub mod stream;
/// Research-only 10B supply/miner-emission candidate; not connected to consensus.
pub mod ten_b_issuance_candidate;
pub mod timestamp_policy;
/// Research-only allocation/halving comparison with exact Rust/Python fixed vectors; not consensus.
pub mod tokenomics_design_candidate;
pub mod transaction_auth;
pub mod transport;
#[cfg(test)]
mod v4_fat1_external_anchor_contract_model;
pub mod verifier;

// Backward-compatible public names; protocol_profile.rs is the single current source.
pub use protocol_profile::{
    WIRE_HEADER_LEN as HEADER_LEN, WIRE_MAGIC as MAGIC, WIRE_MAX_CONTROL_TESTNET as MAX_CONTROL,
    WIRE_MAX_FRAME_TESTNET as MAX_FRAME, WIRE_VERSION as PROTOCOL_VERSION,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum MessageType {
    Hello = protocol_profile::HELLO_TYPE,
    Ping = protocol_profile::PING_TYPE,
    Pong = protocol_profile::PONG_TYPE,
    GetHeaders = protocol_profile::GET_HEADERS_TYPE,
    Headers = protocol_profile::HEADERS_TYPE,
    GetBlocks = 12,
    Blocks = 13,
    TxInv = 20,
    GetTx = 21,
    Tx = 22,
    GetAddr = 30,
    Addr = 31,
    Status = protocol_profile::STATUS_TYPE,
    Caps = protocol_profile::CAPS_TYPE,
    Error = protocol_profile::ERROR_TYPE,
    BlockImportReceipt = protocol_profile::BLOCK_IMPORT_RECEIPT_TYPE,
}

impl MessageType {
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            protocol_profile::HELLO_TYPE => Some(Self::Hello),
            protocol_profile::PING_TYPE => Some(Self::Ping),
            protocol_profile::PONG_TYPE => Some(Self::Pong),
            protocol_profile::GET_HEADERS_TYPE => Some(Self::GetHeaders),
            protocol_profile::HEADERS_TYPE => Some(Self::Headers),
            12 => Some(Self::GetBlocks),
            13 => Some(Self::Blocks),
            20 => Some(Self::TxInv),
            21 => Some(Self::GetTx),
            22 => Some(Self::Tx),
            30 => Some(Self::GetAddr),
            31 => Some(Self::Addr),
            protocol_profile::STATUS_TYPE => Some(Self::Status),
            protocol_profile::CAPS_TYPE => Some(Self::Caps),
            protocol_profile::ERROR_TYPE => Some(Self::Error),
            protocol_profile::BLOCK_IMPORT_RECEIPT_TYPE => Some(Self::BlockImportReceipt),
            _ => None,
        }
    }

    pub fn is_control(self) -> bool {
        matches!(
            self,
            Self::Hello | Self::Ping | Self::Pong | Self::Status | Self::Caps | Self::Error
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    Incomplete,
    BadMagic,
    UnsupportedVersion(u16),
    PayloadTooLarge { declared: usize, limit: usize },
    LengthOverflow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub version: u16,
    pub message_type: u16,
    pub request_id: u64,
    pub payload: Vec<u8>,
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

pub fn encode_frame(
    version: u16,
    message_type: u16,
    request_id: u64,
    payload: &[u8],
) -> Result<Vec<u8>, ParseError> {
    let control = MessageType::from_u16(message_type)
        .map(|m| m.is_control())
        .unwrap_or(false);

    let limit = if control { MAX_CONTROL } else { MAX_FRAME };
    if payload.len() > limit {
        return Err(ParseError::PayloadTooLarge {
            declared: payload.len(),
            limit,
        });
    }

    let total = HEADER_LEN
        .checked_add(payload.len())
        .ok_or(ParseError::LengthOverflow)?;
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&MAGIC.to_be_bytes());
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(&message_type.to_be_bytes());
    out.extend_from_slice(&request_id.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

pub fn decode_frame(bytes: &[u8]) -> Result<Frame, ParseError> {
    if bytes.len() < HEADER_LEN {
        return Err(ParseError::Incomplete);
    }

    if read_u32(bytes, 0) != MAGIC {
        return Err(ParseError::BadMagic);
    }

    let version = read_u16(bytes, 4);
    if version != PROTOCOL_VERSION {
        return Err(ParseError::UnsupportedVersion(version));
    }

    let message_type = read_u16(bytes, 6);
    let request_id = read_u64(bytes, 8);
    let declared = read_u32(bytes, 16) as usize;

    let control = MessageType::from_u16(message_type)
        .map(|m| m.is_control())
        .unwrap_or(false);

    let limit = if control { MAX_CONTROL } else { MAX_FRAME };
    if declared > limit {
        return Err(ParseError::PayloadTooLarge { declared, limit });
    }

    let total = HEADER_LEN
        .checked_add(declared)
        .ok_or(ParseError::LengthOverflow)?;

    if bytes.len() < total {
        return Err(ParseError::Incomplete);
    }

    Ok(Frame {
        version,
        message_type,
        request_id,
        payload: bytes[HEADER_LEN..total].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_known_message() {
        let encoded = encode_frame(1, MessageType::Ping as u16, 42, b"abc").unwrap();
        let decoded = decode_frame(&encoded).unwrap();
        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.message_type, MessageType::Ping as u16);
        assert_eq!(decoded.request_id, 42);
        assert_eq!(decoded.payload, b"abc");
    }

    #[test]
    fn rejects_bad_magic() {
        let mut frame = encode_frame(1, MessageType::Ping as u16, 1, b"x").unwrap();
        frame[0] ^= 1;
        assert_eq!(decode_frame(&frame), Err(ParseError::BadMagic));
    }

    #[test]
    fn rejects_unsupported_version_before_payload_copy() {
        let mut frame = encode_frame(1, MessageType::Ping as u16, 1, b"x").unwrap();
        frame[4..6].copy_from_slice(&2u16.to_be_bytes());
        assert_eq!(decode_frame(&frame), Err(ParseError::UnsupportedVersion(2)));
    }

    #[test]
    fn rejects_oversize_control() {
        let mut frame = vec![0u8; HEADER_LEN];
        frame[0..4].copy_from_slice(&MAGIC.to_be_bytes());
        frame[4..6].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        frame[6..8].copy_from_slice(&(MessageType::Ping as u16).to_be_bytes());
        frame[16..20].copy_from_slice(&((MAX_CONTROL + 1) as u32).to_be_bytes());
        assert!(matches!(
            decode_frame(&frame),
            Err(ParseError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn rejects_oversize_frame() {
        let mut frame = vec![0u8; HEADER_LEN];
        frame[0..4].copy_from_slice(&MAGIC.to_be_bytes());
        frame[4..6].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        frame[6..8].copy_from_slice(&(MessageType::Blocks as u16).to_be_bytes());
        frame[16..20].copy_from_slice(&((MAX_FRAME + 1) as u32).to_be_bytes());
        assert!(matches!(
            decode_frame(&frame),
            Err(ParseError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn rejects_truncated_payload() {
        let encoded = encode_frame(1, MessageType::Headers as u16, 9, b"payload").unwrap();
        let truncated = &encoded[..encoded.len() - 1];
        assert_eq!(decode_frame(truncated), Err(ParseError::Incomplete));
    }

    #[test]
    fn unknown_message_type_still_has_bounded_frame() {
        let encoded = encode_frame(1, 999, 7, b"future").unwrap();
        let decoded = decode_frame(&encoded).unwrap();
        assert_eq!(decoded.message_type, 999);
        assert_eq!(decoded.payload, b"future");
    }
}

pub mod token_forge;
