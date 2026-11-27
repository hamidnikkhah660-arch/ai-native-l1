//! Isolated QFP6 PoW envelope for the CP-0528-aware canonical QFB6 v3 execution block.
//!
//! QFP5/QFB5 remains unchanged. QFP6 binds the complete canonical QFB6 v4 bytes,
//! including Ledger, AMM, Asset Registry, OrderBook and CP-0528 tokenomics/release state,
//! into the PoW header hash. This is a wire/PoW candidate only: it is not yet
//! connected to node admission, persistence, or peer transport.

use crate::{
    consensus::{verify_pow, ConsensusError, ConsensusParameters, PowHeader, Uint256},
    qrun_v06_canonical_execution_candidate::{
        decode_qrun_v06_block, encode_qrun_v06_block, qrun_v06_block_id, QRunV06Block,
        QRunV06ExecutionError, MAX_QRUN_V06_BLOCK_BYTES,
    },
};
use sha2::{Digest, Sha256};

pub const QRUN_V06_POW_WIRE_VERSION: u16 = 3;
pub const QRUN_V06_PROTOCOL_VERSION: u16 = 6;
const MAGIC: [u8; 4] = *b"QFP6";
const HEADER_LEN: usize = 4 + 2 + 2 + 32 + 8 + 8 + 32 + 32 + 32 + 32 + 8 + 4;
const COMMITMENT_DOMAIN: &[u8] = b"QRUN-V06-POW-QFB6-COMMITMENT-V3\0";

pub const MAX_QRUN_V06_POW_ENVELOPE_BYTES: usize = HEADER_LEN + MAX_QRUN_V06_BLOCK_BYTES;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QRunV06PowWireError {
    Oversize,
    Incomplete,
    BadMagic,
    UnsupportedVersion(u16),
    InvalidProtocolVersion,
    InvalidNetworkId,
    InvalidTarget,
    HeaderBodyMismatch(&'static str),
    Execution(QRunV06ExecutionError),
    Consensus(ConsensusError),
}

impl From<QRunV06ExecutionError> for QRunV06PowWireError {
    fn from(value: QRunV06ExecutionError) -> Self {
        Self::Execution(value)
    }
}

impl From<ConsensusError> for QRunV06PowWireError {
    fn from(value: ConsensusError) -> Self {
        Self::Consensus(value)
    }
}

impl std::fmt::Display for QRunV06PowWireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Oversize => write!(f, "QRun QFP6 envelope exceeds its byte limit"),
            Self::Incomplete => write!(f, "QRun QFP6 envelope is incomplete or has trailing bytes"),
            Self::BadMagic => write!(f, "QRun QFP6 magic is invalid"),
            Self::UnsupportedVersion(version) => {
                write!(f, "QRun QFP6 wire version {version} is unsupported")
            }
            Self::InvalidProtocolVersion => {
                write!(f, "QRun QFP6 requires protocol version 6")
            }
            Self::InvalidNetworkId => write!(f, "QRun QFP6 network ID cannot be zero"),
            Self::InvalidTarget => write!(f, "QRun QFP6 PoW target cannot be zero"),
            Self::HeaderBodyMismatch(field) => {
                write!(f, "QRun QFP6 header disagrees with {field}")
            }
            Self::Execution(error) => write!(f, "QRun QFB6 execution envelope: {error:?}"),
            Self::Consensus(error) => write!(f, "QRun QFP6 consensus validation: {error}"),
        }
    }
}

impl std::error::Error for QRunV06PowWireError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV06PowBlock {
    pub header: PowHeader,
    pub block: QRunV06Block,
}

/// Bind the combined QFB6 execution root and complete canonical payload to QFP6.
///
/// The producer, order-book state, escrow, registry, AMM and native ledger are
/// transitively committed through the canonical QFB6 block ID and state root.
pub fn qrun_v06_pow_state_commitment(
    block: &QRunV06Block,
) -> Result<[u8; 32], QRunV06PowWireError> {
    let canonical = encode_qrun_v06_block(block)?;
    let block_id = qrun_v06_block_id(block)?;

    let mut hasher = Sha256::new();
    hasher.update(COMMITMENT_DOMAIN);
    hasher.update(block.network_id);
    hasher.update(block.profile_id);
    hasher.update(block.height.to_be_bytes());
    hasher.update(block.timestamp.to_be_bytes());
    hasher.update(block.parent_hash);
    hasher.update(block.state_root);
    hasher.update(block_id);
    hasher.update((canonical.len() as u64).to_be_bytes());
    Ok(hasher.finalize().into())
}

/// Ensure the PoW header describes exactly this QFB6 block and its combined root.
fn check_header_body_binding(
    header: &PowHeader,
    block: &QRunV06Block,
) -> Result<(), QRunV06PowWireError> {
    if header.protocol_version != QRUN_V06_PROTOCOL_VERSION {
        return Err(QRunV06PowWireError::InvalidProtocolVersion);
    }
    if header.network_id.iter().all(|byte| *byte == 0) {
        return Err(QRunV06PowWireError::InvalidNetworkId);
    }
    if header.network_id != block.network_id {
        return Err(QRunV06PowWireError::HeaderBodyMismatch("network_id"));
    }
    if header.height != block.height {
        return Err(QRunV06PowWireError::HeaderBodyMismatch("height"));
    }
    if header.timestamp != block.timestamp {
        return Err(QRunV06PowWireError::HeaderBodyMismatch("timestamp"));
    }
    if header.parent_hash != block.parent_hash {
        return Err(QRunV06PowWireError::HeaderBodyMismatch("parent_hash"));
    }
    if header.target.is_zero() {
        return Err(QRunV06PowWireError::InvalidTarget);
    }
    if header.state_root != qrun_v06_pow_state_commitment(block)? {
        return Err(QRunV06PowWireError::HeaderBodyMismatch(
            "qfb6_execution_commitment",
        ));
    }
    Ok(())
}

/// Encode QFP6 wire v2 as a fixed-width PoW header followed by one canonical QFB6 v3 payload.
///
/// Layout: magic, wire version, protocol version, network, height, timestamp,
/// parent, previous consensus tip, PoW commitment, target, nonce, body length,
/// and canonical QFB6 bytes.
pub fn encode_qrun_v06_pow_block(
    header: &PowHeader,
    block: &QRunV06Block,
) -> Result<Vec<u8>, QRunV06PowWireError> {
    check_header_body_binding(header, block)?;
    let body = encode_qrun_v06_block(block)?;
    let body_len = u32::try_from(body.len()).map_err(|_| QRunV06PowWireError::Oversize)?;

    let mut output = Vec::with_capacity(HEADER_LEN + body.len());
    output.extend_from_slice(&MAGIC);
    output.extend_from_slice(&QRUN_V06_POW_WIRE_VERSION.to_be_bytes());
    output.extend_from_slice(&header.protocol_version.to_be_bytes());
    output.extend_from_slice(&header.network_id);
    output.extend_from_slice(&header.height.to_be_bytes());
    output.extend_from_slice(&header.timestamp.to_be_bytes());
    output.extend_from_slice(&header.parent_hash);
    output.extend_from_slice(&header.previous_consensus_hash);
    output.extend_from_slice(&header.state_root);
    output.extend_from_slice(&header.target.to_be_bytes());
    output.extend_from_slice(&header.nonce.to_be_bytes());
    output.extend_from_slice(&body_len.to_be_bytes());
    output.extend_from_slice(&body);

    if output.len() > MAX_QRUN_V06_POW_ENVELOPE_BYTES {
        return Err(QRunV06PowWireError::Oversize);
    }
    Ok(output)
}

/// Decode QFP6 with strict length, version, header/body binding and canonicality checks.
pub fn decode_qrun_v06_pow_block(bytes: &[u8]) -> Result<QRunV06PowBlock, QRunV06PowWireError> {
    if bytes.len() > MAX_QRUN_V06_POW_ENVELOPE_BYTES {
        return Err(QRunV06PowWireError::Oversize);
    }
    if bytes.len() < HEADER_LEN {
        return Err(QRunV06PowWireError::Incomplete);
    }

    let mut offset = 0usize;
    if take_array::<4>(bytes, &mut offset)? != MAGIC {
        return Err(QRunV06PowWireError::BadMagic);
    }
    let version = take_u16(bytes, &mut offset)?;
    if version != QRUN_V06_POW_WIRE_VERSION {
        return Err(QRunV06PowWireError::UnsupportedVersion(version));
    }

    let protocol_version = take_u16(bytes, &mut offset)?;
    let network_id = take_array::<32>(bytes, &mut offset)?;
    let height = take_u64(bytes, &mut offset)?;
    let timestamp = take_u64(bytes, &mut offset)?;
    let parent_hash = take_array::<32>(bytes, &mut offset)?;
    let previous_consensus_hash = take_array::<32>(bytes, &mut offset)?;
    let state_root = take_array::<32>(bytes, &mut offset)?;
    let target = Uint256::from_be_bytes(take_array::<32>(bytes, &mut offset)?);
    let nonce = take_u64(bytes, &mut offset)?;
    let body_len = take_u32(bytes, &mut offset)? as usize;

    if body_len > MAX_QRUN_V06_BLOCK_BYTES {
        return Err(QRunV06PowWireError::Oversize);
    }
    if HEADER_LEN.checked_add(body_len) != Some(bytes.len()) {
        return Err(QRunV06PowWireError::Incomplete);
    }

    let block = decode_qrun_v06_block(&bytes[HEADER_LEN..])?;
    let header = PowHeader {
        protocol_version,
        network_id,
        height,
        timestamp,
        parent_hash,
        previous_consensus_hash,
        state_root,
        target,
        nonce,
    };
    check_header_body_binding(&header, &block)?;

    let decoded = QRunV06PowBlock { header, block };
    if encode_qrun_v06_pow_block(&decoded.header, &decoded.block)?.as_slice() != bytes {
        return Err(QRunV06PowWireError::Incomplete);
    }
    Ok(decoded)
}

/// Verify the QFP6 header with the supplied frozen/candidate consensus parameters.
pub fn verify_qrun_v06_pow_block(
    envelope: &QRunV06PowBlock,
    parameters: &ConsensusParameters,
) -> Result<[u8; 32], QRunV06PowWireError> {
    check_header_body_binding(&envelope.header, &envelope.block)?;
    if parameters.protocol_version != QRUN_V06_PROTOCOL_VERSION {
        return Err(QRunV06PowWireError::InvalidProtocolVersion);
    }
    Ok(verify_pow(&envelope.header, parameters)?)
}

fn take_slice<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    length: usize,
) -> Result<&'a [u8], QRunV06PowWireError> {
    let end = offset
        .checked_add(length)
        .ok_or(QRunV06PowWireError::Incomplete)?;
    let part = bytes
        .get(*offset..end)
        .ok_or(QRunV06PowWireError::Incomplete)?;
    *offset = end;
    Ok(part)
}

fn take_array<const N: usize>(
    bytes: &[u8],
    offset: &mut usize,
) -> Result<[u8; N], QRunV06PowWireError> {
    take_slice(bytes, offset, N)?
        .try_into()
        .map_err(|_| QRunV06PowWireError::Incomplete)
}

fn take_u16(bytes: &[u8], offset: &mut usize) -> Result<u16, QRunV06PowWireError> {
    Ok(u16::from_be_bytes(take_array(bytes, offset)?))
}

fn take_u32(bytes: &[u8], offset: &mut usize) -> Result<u32, QRunV06PowWireError> {
    Ok(u32::from_be_bytes(take_array(bytes, offset)?))
}

fn take_u64(bytes: &[u8], offset: &mut usize) -> Result<u64, QRunV06PowWireError> {
    Ok(u64::from_be_bytes(take_array(bytes, offset)?))
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        consensus::{pow_digest, PowAlgorithm, PowParameters},
        qrun_v06_canonical_execution_candidate::{
            QRunV06BlockOperation, QRunV06CanonicalExecutionState,
        },
        qrun_v06_unified_asset_candidate::QRunV06UnifiedAssetState,
        qzxb_amm_candidate::QzxbAmmStateCandidate,
        state_machine::{AccountId, LedgerState, TransactionAuthenticator},
    };

    const NETWORK: [u8; 32] = [0xD6; 32];
    const PROFILE: [u8; 32] = [0xD7; 32];
    const OWNER: [u8; 32] = [0xD8; 32];
    const PRODUCER: [u8; 32] = [0xD9; 32];

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

    fn fixture() -> QRunV06PowBlock {
        let ledger = LedgerState::genesis(NETWORK, vec![(OWNER, 50_000)]).unwrap();
        let amm = QzxbAmmStateCandidate::new(NETWORK, 32, 64, 512).unwrap();
        let unified = QRunV06UnifiedAssetState::new(ledger, amm).unwrap();
        let state = QRunV06CanonicalExecutionState::new(unified, PROFILE).unwrap();

        let mut block = QRunV06Block {
            network_id: NETWORK,
            profile_id: PROFILE,
            height: state.height() + 1,
            timestamp: state.last_timestamp() + 100,
            parent_hash: state.tip_hash(),
            state_root: [0; 32],
            producer: PRODUCER,
            operations: Vec::<QRunV06BlockOperation>::new(),
        };
        block.state_root = state
            .preview_state_root_after(&block, &DigestAuthenticator)
            .unwrap();

        let mut header = PowHeader {
            protocol_version: QRUN_V06_PROTOCOL_VERSION,
            network_id: NETWORK,
            height: block.height,
            timestamp: block.timestamp,
            parent_hash: block.parent_hash,
            previous_consensus_hash: state.tip_hash(),
            state_root: [0; 32],
            target: Uint256::MAX,
            nonce: 17,
        };
        header.state_root = qrun_v06_pow_state_commitment(&block).unwrap();
        QRunV06PowBlock { header, block }
    }

    fn cheap_pow_parameters() -> PowParameters {
        PowParameters {
            algorithm: PowAlgorithm::Argon2id,
            memory_kib: 8,
            iterations: 1,
            lanes: 1,
            output_bytes: 32,
        }
    }

    #[test]
    fn qfp6_v3_round_trip_binds_qfb6_v4_tokenomics_release_root_and_producer_to_pow_digest() {
        let envelope = fixture();
        let bytes = encode_qrun_v06_pow_block(&envelope.header, &envelope.block).unwrap();
        assert_eq!(&bytes[..4], b"QFP6");
        assert_eq!(decode_qrun_v06_pow_block(&bytes).unwrap(), envelope);

        let original_digest = pow_digest(&envelope.header, cheap_pow_parameters()).unwrap();
        let mut changed = envelope.block.clone();
        changed.producer[31] ^= 1;
        let changed_commitment = qrun_v06_pow_state_commitment(&changed).unwrap();
        assert_ne!(changed_commitment, envelope.header.state_root);

        let mut changed_header = envelope.header;
        changed_header.state_root = changed_commitment;
        let changed_digest = pow_digest(&changed_header, cheap_pow_parameters()).unwrap();
        assert_ne!(original_digest, changed_digest);

        assert!(matches!(
            encode_qrun_v06_pow_block(&envelope.header, &changed),
            Err(QRunV06PowWireError::HeaderBodyMismatch(
                "qfb6_execution_commitment"
            ))
        ));
    }

    #[test]
    fn qfp6_rejects_wrong_magic_version_trailing_bytes_and_body_tampering() {
        let envelope = fixture();
        let canonical = encode_qrun_v06_pow_block(&envelope.header, &envelope.block).unwrap();

        let mut bad_magic = canonical.clone();
        bad_magic[0] ^= 1;
        assert_eq!(
            decode_qrun_v06_pow_block(&bad_magic),
            Err(QRunV06PowWireError::BadMagic)
        );

        let mut bad_version = canonical.clone();
        bad_version[4..6].copy_from_slice(&99u16.to_be_bytes());
        assert_eq!(
            decode_qrun_v06_pow_block(&bad_version),
            Err(QRunV06PowWireError::UnsupportedVersion(99))
        );

        let mut legacy_v2 = canonical.clone();
        legacy_v2[4..6].copy_from_slice(&2u16.to_be_bytes());
        assert_eq!(
            decode_qrun_v06_pow_block(&legacy_v2),
            Err(QRunV06PowWireError::UnsupportedVersion(2))
        );

        let mut trailing = canonical.clone();
        trailing.push(0);
        assert_eq!(
            decode_qrun_v06_pow_block(&trailing),
            Err(QRunV06PowWireError::Incomplete)
        );

        let mut tampered_body = canonical;
        // QFB6's producer follows its fixed 150-byte prefix.
        tampered_body[HEADER_LEN + 150] ^= 1;
        assert!(matches!(
            decode_qrun_v06_pow_block(&tampered_body),
            Err(QRunV06PowWireError::HeaderBodyMismatch(
                "qfb6_execution_commitment"
            ))
        ));
    }

    #[test]
    fn qfp6_rejects_protocol_network_parent_and_zero_target_mismatches() {
        let envelope = fixture();

        let mut bad_protocol = envelope.header;
        bad_protocol.protocol_version = 5;
        assert_eq!(
            encode_qrun_v06_pow_block(&bad_protocol, &envelope.block),
            Err(QRunV06PowWireError::InvalidProtocolVersion)
        );

        let mut bad_network = envelope.header;
        bad_network.network_id[0] ^= 1;
        assert_eq!(
            encode_qrun_v06_pow_block(&bad_network, &envelope.block),
            Err(QRunV06PowWireError::HeaderBodyMismatch("network_id"))
        );

        let mut bad_parent = envelope.header;
        bad_parent.parent_hash[0] ^= 1;
        assert_eq!(
            encode_qrun_v06_pow_block(&bad_parent, &envelope.block),
            Err(QRunV06PowWireError::HeaderBodyMismatch("parent_hash"))
        );

        let mut zero_target = envelope.header;
        zero_target.target = Uint256::from_be_bytes([0; 32]);
        assert_eq!(
            encode_qrun_v06_pow_block(&zero_target, &envelope.block),
            Err(QRunV06PowWireError::InvalidTarget)
        );
    }

    #[test]
    fn qfp6_verifies_with_protocol_six_consensus_parameters() {
        let envelope = fixture();
        let mut parameters = ConsensusParameters::candidate_testnet().unwrap();
        parameters.protocol_version = QRUN_V06_PROTOCOL_VERSION;
        parameters.pow_limit = Uint256::MAX;
        parameters.initial_target = Uint256::MAX;
        parameters.pow = cheap_pow_parameters();

        let verified = verify_qrun_v06_pow_block(&envelope, &parameters).expect("valid QFP6 PoW");
        assert_eq!(
            verified,
            pow_digest(&envelope.header, cheap_pow_parameters()).unwrap()
        );

        parameters.protocol_version = 5;
        assert_eq!(
            verify_qrun_v06_pow_block(&envelope, &parameters),
            Err(QRunV06PowWireError::InvalidProtocolVersion)
        );
    }
}
