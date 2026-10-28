//! Candidate QRun v0.5 fee-only PoW envelope. Not connected to public networking.
//!
//! QFP5 uses PowHeader.state_root as a domain-separated commitment to BOTH the
//! post-execution state root and the exact canonical QFB5 envelope. This ensures
//! the PoW digest changes if the producer or any other fee-block byte changes,
//! including a zero-fee block where producer payout would otherwise leave state unchanged.

use crate::{
    consensus::{PowHeader, Uint256},
    state_machine::{
        decode_qrun_v05_fee_block, encode_qrun_v05_fee_block, qrun_v05_fee_block_id,
        QRunV05FeeBlock, StateError, MAX_ENCODED_BLOCK_BYTES,
    },
};
use sha2::{Digest, Sha256};

pub const QRUN_V05_FEE_POW_WIRE_VERSION: u16 = 1;
const MAGIC: &[u8; 4] = b"QFP5";
const HEADER_LEN: usize = 196;
const QFB5_FIXED_OVERHEAD: usize = 4 + 2 + 4 + 32;
const COMMITMENT_DOMAIN: &[u8] = b"QUANTUMZXB-QRUN-FEE-POW-STATE-COMMITMENT-V05\0";
pub const MAX_QRUN_V05_FEE_POW_ENVELOPE_BYTES: usize =
    HEADER_LEN + MAX_ENCODED_BLOCK_BYTES + QFB5_FIXED_OVERHEAD;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QRunV05FeePowWireError {
    Oversize,
    Incomplete,
    BadMagic,
    UnsupportedVersion(u16),
    InvalidNetworkId,
    InvalidProtocolVersion,
    InvalidBlock,
    HeaderBodyMismatch(&'static str),
}

impl std::fmt::Display for QRunV05FeePowWireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Oversize => write!(f, "QRun QFP5 envelope exceeds its byte limit"),
            Self::Incomplete => write!(f, "QRun QFP5 envelope is incomplete or has trailing bytes"),
            Self::BadMagic => write!(f, "QRun QFP5 magic is invalid"),
            Self::UnsupportedVersion(version) => {
                write!(f, "QRun QFP5 version {version} is unsupported")
            }
            Self::InvalidNetworkId => write!(f, "QRun QFP5 network ID cannot be zero"),
            Self::InvalidProtocolVersion => write!(f, "QRun QFP5 protocol version cannot be zero"),
            Self::InvalidBlock => write!(f, "QRun QFP5 fee block is not canonical"),
            Self::HeaderBodyMismatch(field) => write!(f, "QRun QFP5 header disagrees with {field}"),
        }
    }
}
impl std::error::Error for QRunV05FeePowWireError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QRunV05FeePowBlock {
    pub header: PowHeader,
    pub block: QRunV05FeeBlock,
}

/// Commit both the executed ledger root and the complete fee-block identity.
/// The result is placed in PowHeader.state_root so the existing PoW digest binds the producer.
pub fn qrun_v05_fee_pow_state_commitment(
    block: &QRunV05FeeBlock,
) -> Result<[u8; 32], QRunV05FeePowWireError> {
    let canonical = encode_qrun_v05_fee_block(block)
        .map_err(|_: StateError| QRunV05FeePowWireError::InvalidBlock)?;
    let block_id = qrun_v05_fee_block_id(block)
        .map_err(|_: StateError| QRunV05FeePowWireError::InvalidBlock)?;
    let mut hasher = Sha256::new();
    hasher.update(COMMITMENT_DOMAIN);
    hasher.update(block.body.state_root);
    hasher.update(block_id);
    hasher.update((canonical.len() as u64).to_be_bytes());
    Ok(hasher.finalize().into())
}

fn check_header_body_binding(
    header: &PowHeader,
    block: &QRunV05FeeBlock,
) -> Result<(), QRunV05FeePowWireError> {
    if header.network_id.iter().all(|byte| *byte == 0) {
        return Err(QRunV05FeePowWireError::InvalidNetworkId);
    }
    if header.protocol_version == 0 {
        return Err(QRunV05FeePowWireError::InvalidProtocolVersion);
    }
    if header.height != block.body.height {
        return Err(QRunV05FeePowWireError::HeaderBodyMismatch("height"));
    }
    if header.timestamp != block.body.timestamp {
        return Err(QRunV05FeePowWireError::HeaderBodyMismatch("timestamp"));
    }
    if header.parent_hash != block.body.parent_hash {
        return Err(QRunV05FeePowWireError::HeaderBodyMismatch("parent_hash"));
    }
    if header.state_root != qrun_v05_fee_pow_state_commitment(block)? {
        return Err(QRunV05FeePowWireError::HeaderBodyMismatch(
            "fee_pow_state_commitment",
        ));
    }
    if header.target.is_zero() {
        return Err(QRunV05FeePowWireError::HeaderBodyMismatch("target"));
    }
    Ok(())
}

pub fn encode_qrun_v05_fee_pow_block(
    header: &PowHeader,
    block: &QRunV05FeeBlock,
) -> Result<Vec<u8>, QRunV05FeePowWireError> {
    check_header_body_binding(header, block)?;
    let body = encode_qrun_v05_fee_block(block)
        .map_err(|_: StateError| QRunV05FeePowWireError::InvalidBlock)?;
    if body.len() > MAX_ENCODED_BLOCK_BYTES + QFB5_FIXED_OVERHEAD {
        return Err(QRunV05FeePowWireError::Oversize);
    }
    let body_len = u32::try_from(body.len()).map_err(|_| QRunV05FeePowWireError::Oversize)?;
    let mut output = Vec::with_capacity(HEADER_LEN + body.len());
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&QRUN_V05_FEE_POW_WIRE_VERSION.to_be_bytes());
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
    if output.len() > MAX_QRUN_V05_FEE_POW_ENVELOPE_BYTES {
        return Err(QRunV05FeePowWireError::Oversize);
    }
    Ok(output)
}

pub fn decode_qrun_v05_fee_pow_block(
    bytes: &[u8],
) -> Result<QRunV05FeePowBlock, QRunV05FeePowWireError> {
    if bytes.len() > MAX_QRUN_V05_FEE_POW_ENVELOPE_BYTES {
        return Err(QRunV05FeePowWireError::Oversize);
    }
    if bytes.len() < HEADER_LEN {
        return Err(QRunV05FeePowWireError::Incomplete);
    }
    if &bytes[..4] != MAGIC {
        return Err(QRunV05FeePowWireError::BadMagic);
    }
    let version = u16::from_be_bytes([bytes[4], bytes[5]]);
    if version != QRUN_V05_FEE_POW_WIRE_VERSION {
        return Err(QRunV05FeePowWireError::UnsupportedVersion(version));
    }
    let mut offset = 6usize;
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
    if body_len > MAX_ENCODED_BLOCK_BYTES + QFB5_FIXED_OVERHEAD {
        return Err(QRunV05FeePowWireError::Oversize);
    }
    if bytes.len() != HEADER_LEN.saturating_add(body_len) {
        return Err(QRunV05FeePowWireError::Incomplete);
    }
    let block = decode_qrun_v05_fee_block(&bytes[HEADER_LEN..])
        .map_err(|_: StateError| QRunV05FeePowWireError::InvalidBlock)?;
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
    let decoded = QRunV05FeePowBlock { header, block };
    if encode_qrun_v05_fee_pow_block(&decoded.header, &decoded.block)? != bytes {
        return Err(QRunV05FeePowWireError::Incomplete);
    }
    Ok(decoded)
}

fn take_slice<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    length: usize,
) -> Result<&'a [u8], QRunV05FeePowWireError> {
    let end = offset
        .checked_add(length)
        .ok_or(QRunV05FeePowWireError::Incomplete)?;
    let part = bytes
        .get(*offset..end)
        .ok_or(QRunV05FeePowWireError::Incomplete)?;
    *offset = end;
    Ok(part)
}
fn take_array<const N: usize>(
    bytes: &[u8],
    offset: &mut usize,
) -> Result<[u8; N], QRunV05FeePowWireError> {
    take_slice(bytes, offset, N)?
        .try_into()
        .map_err(|_| QRunV05FeePowWireError::Incomplete)
}
fn take_u16(bytes: &[u8], offset: &mut usize) -> Result<u16, QRunV05FeePowWireError> {
    Ok(u16::from_be_bytes(take_array(bytes, offset)?))
}
fn take_u32(bytes: &[u8], offset: &mut usize) -> Result<u32, QRunV05FeePowWireError> {
    Ok(u32::from_be_bytes(take_array(bytes, offset)?))
}
fn take_u64(bytes: &[u8], offset: &mut usize) -> Result<u64, QRunV05FeePowWireError> {
    Ok(u64::from_be_bytes(take_array(bytes, offset)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        consensus::{pow_digest, PowAlgorithm, PowParameters},
        state_machine::{AccountId, LedgerState, TransactionAuthenticator, MAX_TOTAL_SUPPLY_ATOMS},
    };

    struct EmptyAuthenticator;
    impl TransactionAuthenticator for EmptyAuthenticator {
        fn verify(&self, _: &AccountId, _: &[u8; 32], _: &[u8]) -> Result<(), ()> {
            Err(())
        }
    }

    fn fixture() -> (PowHeader, QRunV05FeeBlock) {
        let network_id = [0x31; 32];
        let owner = [0x22; 32];
        let producer = [0x77; 32];
        let state =
            LedgerState::genesis(network_id, vec![(owner, MAX_TOTAL_SUPPLY_ATOMS as u64)]).unwrap();
        let mut block = QRunV05FeeBlock {
            body: crate::state_machine::Block {
                height: 1,
                timestamp: 1,
                parent_hash: state.tip_hash(),
                state_root: [0; 32],
                transactions: Vec::new(),
            },
            producer,
        };
        block.body.state_root = state
            .preview_qrun_v05_fee_state_root_after(&block, &EmptyAuthenticator)
            .unwrap();
        let header = PowHeader {
            protocol_version: 5,
            network_id,
            height: 1,
            timestamp: 1,
            parent_hash: block.body.parent_hash,
            previous_consensus_hash: state.tip_hash(),
            state_root: qrun_v05_fee_pow_state_commitment(&block).unwrap(),
            target: Uint256::from_be_bytes([0xff; 32]),
            nonce: 17,
        };
        (header, block)
    }

    #[test]
    fn qfp5_round_trip_binds_producer_and_inner_state_root_to_pow_header() {
        let (header, block) = fixture();
        let bytes = encode_qrun_v05_fee_pow_block(&header, &block).unwrap();
        assert_eq!(&bytes[..4], b"QFP5");
        assert_eq!(
            decode_qrun_v05_fee_pow_block(&bytes).unwrap(),
            QRunV05FeePowBlock {
                header,
                block: block.clone()
            }
        );

        let mut changed_block = block.clone();
        changed_block.producer[31] ^= 1;
        let changed_commitment = qrun_v05_fee_pow_state_commitment(&changed_block).unwrap();
        assert_ne!(changed_commitment, header.state_root);

        // Verify that the commitment actually changes the hash consumed by the PoW function.
        let pow = PowParameters {
            algorithm: PowAlgorithm::Argon2id,
            memory_kib: 8,
            iterations: 1,
            lanes: 1,
            output_bytes: 32,
        };
        let mut changed_header = header.clone();
        changed_header.state_root = changed_commitment;
        assert_ne!(
            pow_digest(&header, pow).unwrap(),
            pow_digest(&changed_header, pow).unwrap()
        );

        let mut changed_producer = bytes.clone();
        *changed_producer.last_mut().unwrap() ^= 1;
        assert!(matches!(
            decode_qrun_v05_fee_pow_block(&changed_producer),
            Err(QRunV05FeePowWireError::HeaderBodyMismatch(
                "fee_pow_state_commitment"
            ))
        ));

        let mut changed_commitment = bytes.clone();
        changed_commitment[120] ^= 1;
        assert!(matches!(
            decode_qrun_v05_fee_pow_block(&changed_commitment),
            Err(QRunV05FeePowWireError::HeaderBodyMismatch(
                "fee_pow_state_commitment"
            ))
        ));
    }

    #[test]
    fn qfp5_rejects_bad_version_trailing_bytes_and_wrong_magic() {
        let (header, block) = fixture();
        let canonical = encode_qrun_v05_fee_pow_block(&header, &block).unwrap();
        let mut bad_magic = canonical.clone();
        bad_magic[0] ^= 1;
        assert_eq!(
            decode_qrun_v05_fee_pow_block(&bad_magic),
            Err(QRunV05FeePowWireError::BadMagic)
        );
        let mut bad_version = canonical.clone();
        bad_version[5] = 2;
        assert_eq!(
            decode_qrun_v05_fee_pow_block(&bad_version),
            Err(QRunV05FeePowWireError::UnsupportedVersion(2))
        );
        let mut trailing = canonical;
        trailing.push(0);
        assert_eq!(
            decode_qrun_v05_fee_pow_block(&trailing),
            Err(QRunV05FeePowWireError::Incomplete)
        );
    }
}
