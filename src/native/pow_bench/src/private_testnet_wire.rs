//! Candidate-only wire envelope for private-testnet blocks with a detached PoW header.
//!
//! PTB2 transports the existing canonical BLK2 block body alongside the candidate PoW header.
//! It does not alter BLK2 encoding and is not the frozen production/mainnet wire format.
//! The envelope provides framing/canonical decoding only; peer authentication and consensus
//! validation must be performed separately by the caller.

use crate::{
    consensus::{PowHeader, Uint256},
    qrun_v05_fee_pow_wire_candidate::{
        decode_qrun_v05_fee_pow_block, QRunV05FeePowWireError, MAX_QRUN_V05_FEE_POW_ENVELOPE_BYTES,
    },
    state_machine::{
        decode_block, encode_block, Block, QRunV05FeeBlock, StateError, MAX_ENCODED_BLOCK_BYTES,
    },
};

const MAGIC: &[u8; 4] = b"PTB2";
pub const PRIVATE_TESTNET_WIRE_VERSION: u16 = 2;
const ENVELOPE_HEADER_LEN: usize = 196;
pub const MAX_PRIVATE_TESTNET_ENVELOPE_BYTES: usize = ENVELOPE_HEADER_LEN + MAX_ENCODED_BLOCK_BYTES;
pub const MAX_CANDIDATE_NETWORK_ENVELOPE_BYTES: usize =
    if MAX_PRIVATE_TESTNET_ENVELOPE_BYTES > MAX_QRUN_V05_FEE_POW_ENVELOPE_BYTES {
        MAX_PRIVATE_TESTNET_ENVELOPE_BYTES
    } else {
        MAX_QRUN_V05_FEE_POW_ENVELOPE_BYTES
    };

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivateTestnetWireError {
    Oversize,
    Incomplete,
    BadMagic,
    UnsupportedWireVersion,
    InvalidNetworkId,
    InvalidProtocolVersion,
    InvalidBlockEncoding,
    QRunFeePowWire(QRunV05FeePowWireError),
    HeaderBodyMismatch(&'static str),
}

impl std::fmt::Display for PrivateTestnetWireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Oversize => write!(f, "private-testnet envelope exceeds its byte limit"),
            Self::Incomplete => write!(
                f,
                "private-testnet envelope is incomplete or has trailing bytes"
            ),
            Self::BadMagic => write!(f, "private-testnet envelope magic is invalid"),
            Self::UnsupportedWireVersion => {
                write!(f, "private-testnet wire version is unsupported")
            }
            Self::InvalidNetworkId => write!(f, "private-testnet header network ID cannot be zero"),
            Self::InvalidProtocolVersion => {
                write!(f, "private-testnet header protocol version cannot be zero")
            }
            Self::InvalidBlockEncoding => write!(f, "private-testnet block body is not canonical"),
            Self::QRunFeePowWire(error) => write!(f, "QRun QFP5 envelope rejected: {error}"),
            Self::HeaderBodyMismatch(field) => {
                write!(
                    f,
                    "private-testnet PoW header does not match block field {field}"
                )
            }
        }
    }
}

impl std::error::Error for PrivateTestnetWireError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateNetworkBlock {
    pub header: PowHeader,
    /// Body view retained for PTB2-compatible callers. QFP5 callers must use fee_block.
    pub block: Block,
    /// Present only when the input used QFP5/QFB5. Execution mode must be bound by fork choice.
    pub fee_block: Option<QRunV05FeeBlock>,
}

fn check_header_body_binding(
    header: &PowHeader,
    block: &Block,
) -> Result<(), PrivateTestnetWireError> {
    if header.network_id.iter().all(|byte| *byte == 0) {
        return Err(PrivateTestnetWireError::InvalidNetworkId);
    }
    if header.protocol_version == 0 {
        return Err(PrivateTestnetWireError::InvalidProtocolVersion);
    }
    if header.height != block.height {
        return Err(PrivateTestnetWireError::HeaderBodyMismatch("height"));
    }
    if header.timestamp != block.timestamp {
        return Err(PrivateTestnetWireError::HeaderBodyMismatch("timestamp"));
    }
    if header.parent_hash != block.parent_hash {
        return Err(PrivateTestnetWireError::HeaderBodyMismatch("parent_hash"));
    }
    if header.state_root != block.state_root {
        return Err(PrivateTestnetWireError::HeaderBodyMismatch("state_root"));
    }
    if header.target.is_zero() {
        return Err(PrivateTestnetWireError::HeaderBodyMismatch("target"));
    }
    Ok(())
}

/// Encode the PTB2 candidate envelope. The block body bytes remain exactly the existing BLK2.
pub fn encode_candidate_network_block(
    header: &PowHeader,
    block: &Block,
) -> Result<Vec<u8>, PrivateTestnetWireError> {
    check_header_body_binding(header, block)?;
    let body = encode_block(block)
        .map_err(|_: StateError| PrivateTestnetWireError::InvalidBlockEncoding)?;
    if body.len() > MAX_ENCODED_BLOCK_BYTES {
        return Err(PrivateTestnetWireError::Oversize);
    }

    let body_len = u32::try_from(body.len()).map_err(|_| PrivateTestnetWireError::Oversize)?;
    let mut output = Vec::with_capacity(ENVELOPE_HEADER_LEN + body.len());
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&PRIVATE_TESTNET_WIRE_VERSION.to_be_bytes());
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

    debug_assert_eq!(output.len(), ENVELOPE_HEADER_LEN + body.len());
    if output.len() > MAX_PRIVATE_TESTNET_ENVELOPE_BYTES {
        return Err(PrivateTestnetWireError::Oversize);
    }
    Ok(output)
}

/// Strictly decode a PTB2 envelope; rejects unsupported versions, non-canonical bodies,
/// truncated or trailing bytes, and detached-header/body mismatches.
fn decode_ptb2_candidate_network_block(
    bytes: &[u8],
) -> Result<CandidateNetworkBlock, PrivateTestnetWireError> {
    if bytes.len() > MAX_PRIVATE_TESTNET_ENVELOPE_BYTES {
        return Err(PrivateTestnetWireError::Oversize);
    }
    if bytes.len() < ENVELOPE_HEADER_LEN {
        return Err(PrivateTestnetWireError::Incomplete);
    }
    if &bytes[..4] != MAGIC {
        return Err(PrivateTestnetWireError::BadMagic);
    }
    if u16::from_be_bytes([bytes[4], bytes[5]]) != PRIVATE_TESTNET_WIRE_VERSION {
        return Err(PrivateTestnetWireError::UnsupportedWireVersion);
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

    if body_len > MAX_ENCODED_BLOCK_BYTES {
        return Err(PrivateTestnetWireError::Oversize);
    }
    if bytes.len() != ENVELOPE_HEADER_LEN.saturating_add(body_len) {
        return Err(PrivateTestnetWireError::Incomplete);
    }

    let body = decode_block(&bytes[ENVELOPE_HEADER_LEN..])
        .map_err(|_| PrivateTestnetWireError::InvalidBlockEncoding)?;
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
    check_header_body_binding(&header, &body)?;
    Ok(CandidateNetworkBlock {
        header,
        block: body,
        fee_block: None,
    })
}

/// Decode only known canonical candidate formats. Consumers must still bind the decoded
/// execution variant to their immutable chain profile before admission.
pub fn decode_candidate_network_block(
    bytes: &[u8],
) -> Result<CandidateNetworkBlock, PrivateTestnetWireError> {
    if bytes.len() >= 4 && &bytes[..4] == b"QFP5" {
        if bytes.len() > MAX_CANDIDATE_NETWORK_ENVELOPE_BYTES {
            return Err(PrivateTestnetWireError::Oversize);
        }
        let decoded = decode_qrun_v05_fee_pow_block(bytes)
            .map_err(PrivateTestnetWireError::QRunFeePowWire)?;
        return Ok(CandidateNetworkBlock {
            header: decoded.header,
            block: decoded.block.body.clone(),
            fee_block: Some(decoded.block),
        });
    }
    decode_ptb2_candidate_network_block(bytes)
}

fn take_slice<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    length: usize,
) -> Result<&'a [u8], PrivateTestnetWireError> {
    let end = offset
        .checked_add(length)
        .ok_or(PrivateTestnetWireError::Incomplete)?;
    let part = bytes
        .get(*offset..end)
        .ok_or(PrivateTestnetWireError::Incomplete)?;
    *offset = end;
    Ok(part)
}

fn take_array<const N: usize>(
    bytes: &[u8],
    offset: &mut usize,
) -> Result<[u8; N], PrivateTestnetWireError> {
    take_slice(bytes, offset, N)?
        .try_into()
        .map_err(|_| PrivateTestnetWireError::Incomplete)
}

fn take_u16(bytes: &[u8], offset: &mut usize) -> Result<u16, PrivateTestnetWireError> {
    Ok(u16::from_be_bytes(take_array(bytes, offset)?))
}

fn take_u32(bytes: &[u8], offset: &mut usize) -> Result<u32, PrivateTestnetWireError> {
    Ok(u32::from_be_bytes(take_array(bytes, offset)?))
}

fn take_u64(bytes: &[u8], offset: &mut usize) -> Result<u64, PrivateTestnetWireError> {
    Ok(u64::from_be_bytes(take_array(bytes, offset)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        consensus::ConsensusParameters,
        state_machine::{AccountId, LedgerState, TransactionAuthenticator},
    };

    struct EmptyAuthenticator;

    impl TransactionAuthenticator for EmptyAuthenticator {
        fn verify(&self, _: &AccountId, _: &[u8; 32], _: &[u8]) -> Result<(), ()> {
            Ok(())
        }
    }

    fn fixture() -> (PowHeader, Block) {
        let params = ConsensusParameters::candidate_testnet().unwrap();
        let network_id = [0xB6; 32];
        let state = LedgerState::genesis(network_id, vec![([1; 32], 1_000)]).unwrap();
        let mut block = Block {
            height: state.height() + 1,
            timestamp: 100,
            parent_hash: state.tip_hash(),
            state_root: [0; 32],
            transactions: Vec::new(),
        };
        block.state_root = state
            .preview_state_root_after(&block, &EmptyAuthenticator)
            .unwrap();
        let header = PowHeader {
            protocol_version: params.protocol_version,
            network_id,
            height: block.height,
            timestamp: block.timestamp,
            parent_hash: block.parent_hash,
            previous_consensus_hash: [0xE5; 32],
            state_root: block.state_root,
            target: params.initial_target,
            nonce: 0x0102_0304_0506_0708,
        };
        (header, block)
    }

    #[test]
    fn round_trip_keeps_canonical_block_body_and_header_binding() {
        let (header, block) = fixture();
        let bytes = encode_candidate_network_block(&header, &block).unwrap();
        assert_eq!(&bytes[..4], b"PTB2");
        let decoded = decode_candidate_network_block(&bytes).unwrap();
        assert_eq!(decoded.header, header);
        assert_eq!(decoded.block, block);
        assert_eq!(
            crate::state_machine::encode_block(&decoded.block).unwrap(),
            crate::state_machine::encode_block(&block).unwrap()
        );
        assert_eq!(
            encode_candidate_network_block(&decoded.header, &decoded.block).unwrap(),
            bytes
        );
    }

    #[test]
    fn rejects_truncation_at_each_header_boundary_and_trailing_data() {
        let (header, block) = fixture();
        let bytes = encode_candidate_network_block(&header, &block).unwrap();
        for length in [
            0, 1, 3, 4, 5, 6, 7, 37, 39, 40, 43, 55, 87, 119, 151, 159, 163,
        ] {
            assert_eq!(
                decode_candidate_network_block(&bytes[..length]),
                Err(PrivateTestnetWireError::Incomplete),
                "length={length}"
            );
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert_eq!(
            decode_candidate_network_block(&trailing),
            Err(PrivateTestnetWireError::Incomplete)
        );
    }

    #[test]
    fn rejects_wrong_magic_and_unsupported_envelope_version() {
        let (header, block) = fixture();
        let bytes = encode_candidate_network_block(&header, &block).unwrap();
        let mut bad_magic = bytes.clone();
        bad_magic[0] ^= 1;
        assert_eq!(
            decode_candidate_network_block(&bad_magic),
            Err(PrivateTestnetWireError::BadMagic)
        );
        let mut bad_version = bytes;
        bad_version[5] = 3;
        assert_eq!(
            decode_candidate_network_block(&bad_version),
            Err(PrivateTestnetWireError::UnsupportedWireVersion)
        );
    }

    #[test]
    fn rejects_detached_header_body_conflicts_on_encode_and_decode() {
        let (header, block) = fixture();
        let mut changed_header = header;
        changed_header.state_root[0] ^= 1;
        assert_eq!(
            encode_candidate_network_block(&changed_header, &block),
            Err(PrivateTestnetWireError::HeaderBodyMismatch("state_root"))
        );

        let mut bytes = encode_candidate_network_block(&header, &block).unwrap();
        // state root begins at envelope offset 4 + 2 + 2 + 32 + 8 + 8 + 32 + 32
        bytes[120] ^= 1;
        assert_eq!(
            decode_candidate_network_block(&bytes),
            Err(PrivateTestnetWireError::HeaderBodyMismatch("state_root"))
        );
    }

    #[test]
    fn rejects_zero_network_and_protocol_versions() {
        let (mut header, block) = fixture();
        header.network_id = [0; 32];
        assert_eq!(
            encode_candidate_network_block(&header, &block),
            Err(PrivateTestnetWireError::InvalidNetworkId)
        );
        let (mut header, block) = fixture();
        header.protocol_version = 0;
        assert_eq!(
            encode_candidate_network_block(&header, &block),
            Err(PrivateTestnetWireError::InvalidProtocolVersion)
        );
    }

    #[test]
    fn rejects_malformed_body_and_oversized_envelope() {
        let (header, block) = fixture();
        let mut bytes = encode_candidate_network_block(&header, &block).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        assert_eq!(
            decode_candidate_network_block(&bytes),
            Err(PrivateTestnetWireError::InvalidBlockEncoding)
        );
        assert_eq!(
            decode_candidate_network_block(&vec![0; MAX_PRIVATE_TESTNET_ENVELOPE_BYTES + 1]),
            Err(PrivateTestnetWireError::Oversize)
        );
    }

    #[test]
    fn rejects_inconsistent_declared_body_length_without_allocating_from_claim() {
        let (header, block) = fixture();
        let mut bytes = encode_candidate_network_block(&header, &block).unwrap();
        bytes[192..196].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(
            decode_candidate_network_block(&bytes),
            Err(PrivateTestnetWireError::Oversize)
        );
    }
}
