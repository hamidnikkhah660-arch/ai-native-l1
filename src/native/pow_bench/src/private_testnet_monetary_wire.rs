//! Candidate-only PMT3 envelope for versioned MBK3 monetary blocks plus detached PoW headers.
//!
//! PMT3 is deliberately distinct from PTB2. The inner MBK3 body commits the miner and subsidy;
//! the detached header commits the same body state root and is verified by the chain driver.
//! This codec is not yet connected to the live Devnet socket/archive/WAL runtime.

use crate::{
    consensus::{PowHeader, Uint256},
    state_machine::{
        decode_monetary_block, decode_v4_hybrid_monetary_block, encode_monetary_block,
        encode_v4_hybrid_monetary_block, MonetaryBlock, StateError, V4HybridMonetaryBlock,
        MAX_ENCODED_BLOCK_BYTES, MAX_ENCODED_V4_HYBRID_MONETARY_BLOCK_BYTES,
    },
};

const MAGIC: &[u8; 4] = b"PMT3";
pub const PRIVATE_TESTNET_MONETARY_WIRE_VERSION: u16 = 3;
const ENVELOPE_HEADER_LEN: usize = 196;
const MONETARY_BLOCK_OVERHEAD: usize = 4 + 2 + 4 + 32 + 8;
const MAX_ENCODED_MONETARY_BLOCK_BYTES: usize = MAX_ENCODED_BLOCK_BYTES + MONETARY_BLOCK_OVERHEAD;
pub const MAX_PRIVATE_TESTNET_MONETARY_ENVELOPE_BYTES: usize =
    ENVELOPE_HEADER_LEN + MAX_ENCODED_MONETARY_BLOCK_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonetaryWireError {
    Oversize,
    Incomplete,
    BadMagic,
    UnsupportedWireVersion,
    InvalidNetworkId,
    InvalidProtocolVersion,
    InvalidBlockEncoding,
    HeaderBodyMismatch(&'static str),
}

impl std::fmt::Display for MonetaryWireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Oversize => write!(f, "PMT3 monetary envelope exceeds its byte limit"),
            Self::Incomplete => write!(
                f,
                "PMT3 monetary envelope is truncated or has trailing bytes"
            ),
            Self::BadMagic => write!(f, "PMT3 monetary envelope magic is invalid"),
            Self::UnsupportedWireVersion => write!(f, "PMT3 monetary wire version is unsupported"),
            Self::InvalidNetworkId => write!(f, "PMT3 header network ID cannot be zero"),
            Self::InvalidProtocolVersion => {
                write!(f, "PMT3 header protocol version cannot be zero")
            }
            Self::InvalidBlockEncoding => write!(f, "MBK3 monetary body is not canonical"),
            Self::HeaderBodyMismatch(field) => write!(
                f,
                "PMT3 PoW header does not match monetary body field {field}"
            ),
        }
    }
}

impl std::error::Error for MonetaryWireError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateMonetaryNetworkBlock {
    pub header: PowHeader,
    pub block: MonetaryBlock,
}

fn check_header_body_binding(
    header: &PowHeader,
    block: &MonetaryBlock,
) -> Result<(), MonetaryWireError> {
    if header.network_id.iter().all(|byte| *byte == 0) {
        return Err(MonetaryWireError::InvalidNetworkId);
    }
    if header.protocol_version == 0 {
        return Err(MonetaryWireError::InvalidProtocolVersion);
    }
    if header.height != block.body.height {
        return Err(MonetaryWireError::HeaderBodyMismatch("height"));
    }
    if header.timestamp != block.body.timestamp {
        return Err(MonetaryWireError::HeaderBodyMismatch("timestamp"));
    }
    if header.parent_hash != block.body.parent_hash {
        return Err(MonetaryWireError::HeaderBodyMismatch("parent_hash"));
    }
    if header.state_root != block.body.state_root {
        return Err(MonetaryWireError::HeaderBodyMismatch("state_root"));
    }
    if header.target.is_zero() {
        return Err(MonetaryWireError::HeaderBodyMismatch("target"));
    }
    Ok(())
}

/// Encode a PMT3 monetary candidate. Miner/reward are inside MBK3 bytes, not detached metadata.
pub fn encode_candidate_monetary_network_block(
    header: &PowHeader,
    block: &MonetaryBlock,
) -> Result<Vec<u8>, MonetaryWireError> {
    check_header_body_binding(header, block)?;
    let body = encode_monetary_block(block)
        .map_err(|_: StateError| MonetaryWireError::InvalidBlockEncoding)?;
    if body.len() > MAX_ENCODED_MONETARY_BLOCK_BYTES {
        return Err(MonetaryWireError::Oversize);
    }
    let body_len = u32::try_from(body.len()).map_err(|_| MonetaryWireError::Oversize)?;
    let mut output = Vec::with_capacity(ENVELOPE_HEADER_LEN + body.len());
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&PRIVATE_TESTNET_MONETARY_WIRE_VERSION.to_be_bytes());
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
    if output.len() > MAX_PRIVATE_TESTNET_MONETARY_ENVELOPE_BYTES {
        return Err(MonetaryWireError::Oversize);
    }
    Ok(output)
}

/// Strict PMT3 decoder. It rejects unrecognized versions, noncanonical MBK3 bytes and
/// any detached-header/body mismatch; state/PoW validity is enforced by the chain driver.
pub fn decode_candidate_monetary_network_block(
    bytes: &[u8],
) -> Result<CandidateMonetaryNetworkBlock, MonetaryWireError> {
    if bytes.len() > MAX_PRIVATE_TESTNET_MONETARY_ENVELOPE_BYTES {
        return Err(MonetaryWireError::Oversize);
    }
    if bytes.len() < ENVELOPE_HEADER_LEN {
        return Err(MonetaryWireError::Incomplete);
    }
    if &bytes[..4] != MAGIC {
        return Err(MonetaryWireError::BadMagic);
    }
    if u16::from_be_bytes([bytes[4], bytes[5]]) != PRIVATE_TESTNET_MONETARY_WIRE_VERSION {
        return Err(MonetaryWireError::UnsupportedWireVersion);
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
    if body_len > MAX_ENCODED_MONETARY_BLOCK_BYTES {
        return Err(MonetaryWireError::Oversize);
    }
    if bytes.len() != ENVELOPE_HEADER_LEN.saturating_add(body_len) {
        return Err(MonetaryWireError::Incomplete);
    }

    let block = decode_monetary_block(&bytes[ENVELOPE_HEADER_LEN..])
        .map_err(|_| MonetaryWireError::InvalidBlockEncoding)?;
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
    Ok(CandidateMonetaryNetworkBlock { header, block })
}

const MAGIC_V4: &[u8; 4] = b"PMT4";
pub const PRIVATE_TESTNET_V4_HYBRID_MONETARY_WIRE_VERSION: u16 = 4;
pub const MAX_PRIVATE_TESTNET_V4_HYBRID_MONETARY_ENVELOPE_BYTES: usize =
    ENVELOPE_HEADER_LEN + MAX_ENCODED_V4_HYBRID_MONETARY_BLOCK_BYTES;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateV4HybridMonetaryNetworkBlock {
    pub header: PowHeader,
    pub block: V4HybridMonetaryBlock,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V4HybridMonetaryWireError {
    Oversize,
    Incomplete,
    BadMagic,
    UnsupportedWireVersion,
    InvalidNetworkId,
    InvalidProtocolVersion,
    InvalidBlockEncoding,
    HeaderBodyMismatch(&'static str),
}

impl std::fmt::Display for V4HybridMonetaryWireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Oversize => write!(f, "PMT4 monetary envelope exceeds its byte limit"),
            Self::Incomplete => write!(
                f,
                "PMT4 monetary envelope is truncated or has trailing bytes"
            ),
            Self::BadMagic => write!(f, "PMT4 envelope magic is invalid"),
            Self::UnsupportedWireVersion => write!(f, "PMT4 wire version is unsupported"),
            Self::InvalidNetworkId => write!(f, "PMT4 header network ID cannot be zero"),
            Self::InvalidProtocolVersion => {
                write!(f, "PMT4 header protocol version cannot be zero")
            }
            Self::InvalidBlockEncoding => write!(f, "MBK4 hybrid monetary body is not canonical"),
            Self::HeaderBodyMismatch(field) => {
                write!(
                    f,
                    "PMT4 detached PoW header does not match MBK4 field {field}"
                )
            }
        }
    }
}

impl std::error::Error for V4HybridMonetaryWireError {}

fn check_v4_hybrid_header_body_binding(
    header: &PowHeader,
    block: &V4HybridMonetaryBlock,
) -> Result<(), V4HybridMonetaryWireError> {
    if header.network_id.iter().all(|byte| *byte == 0) {
        return Err(V4HybridMonetaryWireError::InvalidNetworkId);
    }
    if header.protocol_version == 0 {
        return Err(V4HybridMonetaryWireError::InvalidProtocolVersion);
    }
    if header.height != block.height {
        return Err(V4HybridMonetaryWireError::HeaderBodyMismatch("height"));
    }
    if header.timestamp != block.timestamp {
        return Err(V4HybridMonetaryWireError::HeaderBodyMismatch("timestamp"));
    }
    if header.parent_hash != block.parent_hash {
        return Err(V4HybridMonetaryWireError::HeaderBodyMismatch("parent_hash"));
    }
    if header.state_root != block.state_root {
        return Err(V4HybridMonetaryWireError::HeaderBodyMismatch("state_root"));
    }
    if header.target.is_zero() {
        return Err(V4HybridMonetaryWireError::HeaderBodyMismatch("target"));
    }
    if block
        .transactions
        .iter()
        .any(|tx| tx.authorization.network_id != header.network_id)
    {
        return Err(V4HybridMonetaryWireError::HeaderBodyMismatch(
            "transaction.network_id",
        ));
    }
    Ok(())
}

/// Encode PMT4 with a canonical MBK4 body; PMT3/MBK3 remain byte-for-byte unchanged.
/// PoW validity is checked by the chain driver and is not asserted by this wire codec.
pub fn encode_candidate_v4_hybrid_monetary_network_block(
    header: &PowHeader,
    block: &V4HybridMonetaryBlock,
) -> Result<Vec<u8>, V4HybridMonetaryWireError> {
    check_v4_hybrid_header_body_binding(header, block)?;
    let body = encode_v4_hybrid_monetary_block(block)
        .map_err(|_: StateError| V4HybridMonetaryWireError::InvalidBlockEncoding)?;
    if body.len() > MAX_ENCODED_V4_HYBRID_MONETARY_BLOCK_BYTES {
        return Err(V4HybridMonetaryWireError::Oversize);
    }
    let body_len = u32::try_from(body.len()).map_err(|_| V4HybridMonetaryWireError::Oversize)?;
    let mut output = Vec::with_capacity(ENVELOPE_HEADER_LEN + body.len());
    output.extend_from_slice(MAGIC_V4);
    output.extend_from_slice(&PRIVATE_TESTNET_V4_HYBRID_MONETARY_WIRE_VERSION.to_be_bytes());
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
    if output.len() > MAX_PRIVATE_TESTNET_V4_HYBRID_MONETARY_ENVELOPE_BYTES {
        return Err(V4HybridMonetaryWireError::Oversize);
    }
    Ok(output)
}

/// Strict PMT4 decoder. It checks exact envelope/body length and detached-header binding,
/// and it invokes the strict MBK4/TXN4 canonical decoders. Signature and PoW validity remain
/// state-admission/consensus responsibilities.
pub fn decode_candidate_v4_hybrid_monetary_network_block(
    bytes: &[u8],
) -> Result<CandidateV4HybridMonetaryNetworkBlock, V4HybridMonetaryWireError> {
    if bytes.len() > MAX_PRIVATE_TESTNET_V4_HYBRID_MONETARY_ENVELOPE_BYTES {
        return Err(V4HybridMonetaryWireError::Oversize);
    }
    if bytes.len() < ENVELOPE_HEADER_LEN {
        return Err(V4HybridMonetaryWireError::Incomplete);
    }
    if &bytes[..4] != MAGIC_V4 {
        return Err(V4HybridMonetaryWireError::BadMagic);
    }
    if u16::from_be_bytes([bytes[4], bytes[5]]) != PRIVATE_TESTNET_V4_HYBRID_MONETARY_WIRE_VERSION {
        return Err(V4HybridMonetaryWireError::UnsupportedWireVersion);
    }

    let mut offset = 6usize;
    let protocol_version =
        take_u16(bytes, &mut offset).map_err(|_| V4HybridMonetaryWireError::Incomplete)?;
    let network_id =
        take_array::<32>(bytes, &mut offset).map_err(|_| V4HybridMonetaryWireError::Incomplete)?;
    let height = take_u64(bytes, &mut offset).map_err(|_| V4HybridMonetaryWireError::Incomplete)?;
    let timestamp =
        take_u64(bytes, &mut offset).map_err(|_| V4HybridMonetaryWireError::Incomplete)?;
    let parent_hash =
        take_array::<32>(bytes, &mut offset).map_err(|_| V4HybridMonetaryWireError::Incomplete)?;
    let previous_consensus_hash =
        take_array::<32>(bytes, &mut offset).map_err(|_| V4HybridMonetaryWireError::Incomplete)?;
    let state_root =
        take_array::<32>(bytes, &mut offset).map_err(|_| V4HybridMonetaryWireError::Incomplete)?;
    let target = Uint256::from_be_bytes(
        take_array::<32>(bytes, &mut offset).map_err(|_| V4HybridMonetaryWireError::Incomplete)?,
    );
    let nonce = take_u64(bytes, &mut offset).map_err(|_| V4HybridMonetaryWireError::Incomplete)?;
    let body_len =
        take_u32(bytes, &mut offset).map_err(|_| V4HybridMonetaryWireError::Incomplete)? as usize;
    if body_len > MAX_ENCODED_V4_HYBRID_MONETARY_BLOCK_BYTES {
        return Err(V4HybridMonetaryWireError::Oversize);
    }
    if bytes.len() != ENVELOPE_HEADER_LEN.saturating_add(body_len) {
        return Err(V4HybridMonetaryWireError::Incomplete);
    }
    let block = decode_v4_hybrid_monetary_block(&bytes[ENVELOPE_HEADER_LEN..])
        .map_err(|_| V4HybridMonetaryWireError::InvalidBlockEncoding)?;
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
    check_v4_hybrid_header_body_binding(&header, &block)?;
    Ok(CandidateV4HybridMonetaryNetworkBlock { header, block })
}

fn take_slice<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    length: usize,
) -> Result<&'a [u8], MonetaryWireError> {
    let end = offset
        .checked_add(length)
        .ok_or(MonetaryWireError::Incomplete)?;
    let part = bytes
        .get(*offset..end)
        .ok_or(MonetaryWireError::Incomplete)?;
    *offset = end;
    Ok(part)
}

fn take_array<const N: usize>(
    bytes: &[u8],
    offset: &mut usize,
) -> Result<[u8; N], MonetaryWireError> {
    take_slice(bytes, offset, N)?
        .try_into()
        .map_err(|_| MonetaryWireError::Incomplete)
}

fn take_u16(bytes: &[u8], offset: &mut usize) -> Result<u16, MonetaryWireError> {
    Ok(u16::from_be_bytes(take_array(bytes, offset)?))
}

fn take_u32(bytes: &[u8], offset: &mut usize) -> Result<u32, MonetaryWireError> {
    Ok(u32::from_be_bytes(take_array(bytes, offset)?))
}

fn take_u64(bytes: &[u8], offset: &mut usize) -> Result<u64, MonetaryWireError> {
    Ok(u64::from_be_bytes(take_array(bytes, offset)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        consensus::ConsensusParameters,
        state_machine::{
            AccountId, Block, MonetaryLedgerState, TransactionAuthenticator,
            MONETARY_PUBLIC_GOODS_BUDGET_ATOMS,
        },
    };

    struct EmptyAuthenticator;
    impl TransactionAuthenticator for EmptyAuthenticator {
        fn verify(&self, _: &AccountId, _: &[u8; 32], _: &[u8]) -> Result<(), ()> {
            Ok(())
        }
    }

    fn fixture() -> (PowHeader, MonetaryBlock) {
        let params = ConsensusParameters::candidate_testnet().unwrap();
        let network_id = [0xB6; 32];
        let state = MonetaryLedgerState::genesis(
            network_id,
            [1; 32],
            vec![([2; 32], MONETARY_PUBLIC_GOODS_BUDGET_ATOMS as u64)],
        )
        .unwrap();
        let mut block = MonetaryBlock {
            body: Block {
                height: 1,
                timestamp: 100,
                parent_hash: state.tip_hash(),
                state_root: [0; 32],
                transactions: Vec::new(),
            },
            miner: [3; 32],
            claimed_subsidy_atoms: state.expected_miner_reward().unwrap(),
        };
        block.body.state_root = state
            .preview_state_root_after(&block, &EmptyAuthenticator)
            .unwrap();
        let header = PowHeader {
            protocol_version: params.protocol_version,
            network_id,
            height: block.body.height,
            timestamp: block.body.timestamp,
            parent_hash: block.body.parent_hash,
            previous_consensus_hash: state.tip_hash(),
            state_root: block.body.state_root,
            target: params.initial_target,
            nonce: 0x0102_0304_0506_0708,
        };
        (header, block)
    }

    #[test]
    fn round_trip_preserves_monetary_body_and_pow_header_binding() {
        let (header, block) = fixture();
        let bytes = encode_candidate_monetary_network_block(&header, &block).unwrap();
        assert_eq!(&bytes[..4], b"PMT3");
        assert_eq!(
            decode_candidate_v4_hybrid_monetary_network_block(&bytes),
            Err(V4HybridMonetaryWireError::BadMagic)
        );
        let decoded = decode_candidate_monetary_network_block(&bytes).unwrap();
        assert_eq!(decoded.header, header);
        assert_eq!(decoded.block, block);
        assert_eq!(
            encode_candidate_monetary_network_block(&decoded.header, &decoded.block).unwrap(),
            bytes
        );
    }

    #[test]
    fn rejects_truncation_trailing_data_magic_version_and_header_mismatch() {
        let (header, block) = fixture();
        let bytes = encode_candidate_monetary_network_block(&header, &block).unwrap();
        for length in [
            0, 1, 3, 4, 5, 6, 7, 37, 39, 40, 43, 55, 87, 119, 151, 159, 163, 195,
        ] {
            assert_eq!(
                decode_candidate_monetary_network_block(&bytes[..length]),
                Err(MonetaryWireError::Incomplete)
            );
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            decode_candidate_monetary_network_block(&trailing),
            Err(MonetaryWireError::Incomplete)
        );
        let mut wrong_magic = bytes.clone();
        wrong_magic[0] ^= 1;
        assert_eq!(
            decode_candidate_monetary_network_block(&wrong_magic),
            Err(MonetaryWireError::BadMagic)
        );
        let mut wrong_version = bytes.clone();
        wrong_version[5] = 4;
        assert_eq!(
            decode_candidate_monetary_network_block(&wrong_version),
            Err(MonetaryWireError::UnsupportedWireVersion)
        );
        let mut wrong_state_root = header;
        wrong_state_root.state_root[0] ^= 1;
        assert_eq!(
            encode_candidate_monetary_network_block(&wrong_state_root, &block),
            Err(MonetaryWireError::HeaderBodyMismatch("state_root"))
        );
    }
}

#[cfg(test)]
mod pmt4_tests {
    use super::*;
    use crate::{
        consensus::ConsensusParameters,
        state_machine::{MonetaryLedgerState, MONETARY_PUBLIC_GOODS_BUDGET_ATOMS},
    };

    fn fixture() -> (PowHeader, V4HybridMonetaryBlock) {
        let params = ConsensusParameters::candidate_testnet().unwrap();
        let network_id = [0xB7; 32];
        let state = MonetaryLedgerState::genesis(
            network_id,
            [1; 32],
            vec![([2; 32], MONETARY_PUBLIC_GOODS_BUDGET_ATOMS as u64)],
        )
        .unwrap();
        let block = V4HybridMonetaryBlock {
            height: 1,
            timestamp: 100,
            parent_hash: state.tip_hash(),
            state_root: [0x44; 32],
            transactions: Vec::new(),
            miner: [3; 32],
            claimed_subsidy_atoms: state.expected_miner_reward().unwrap(),
        };
        let header = PowHeader {
            protocol_version: params.protocol_version,
            network_id,
            height: block.height,
            timestamp: block.timestamp,
            parent_hash: block.parent_hash,
            previous_consensus_hash: state.tip_hash(),
            state_root: block.state_root,
            target: params.initial_target,
            nonce: 0x0807_0605_0403_0201,
        };
        (header, block)
    }

    #[test]
    fn pmt4_round_trip_preserves_mbk4_and_detached_pow_header() {
        let (header, block) = fixture();
        let encoded = encode_candidate_v4_hybrid_monetary_network_block(&header, &block).unwrap();
        assert_eq!(&encoded[..4], b"PMT4");
        assert_eq!(
            decode_candidate_monetary_network_block(&encoded),
            Err(MonetaryWireError::BadMagic)
        );
        assert_eq!(
            u16::from_be_bytes([encoded[4], encoded[5]]),
            PRIVATE_TESTNET_V4_HYBRID_MONETARY_WIRE_VERSION
        );
        let decoded = decode_candidate_v4_hybrid_monetary_network_block(&encoded).unwrap();
        assert_eq!(decoded.header, header);
        assert_eq!(decoded.block, block);
        assert_eq!(
            encode_candidate_v4_hybrid_monetary_network_block(&decoded.header, &decoded.block)
                .unwrap(),
            encoded
        );
    }

    #[test]
    fn pmt4_rejects_truncation_suffix_wrong_version_and_header_body_mismatch() {
        let (header, block) = fixture();
        let encoded = encode_candidate_v4_hybrid_monetary_network_block(&header, &block).unwrap();
        for length in [
            0, 1, 3, 4, 5, 6, 7, 37, 39, 40, 43, 55, 87, 119, 151, 159, 163, 195,
        ] {
            assert_eq!(
                decode_candidate_v4_hybrid_monetary_network_block(&encoded[..length]),
                Err(V4HybridMonetaryWireError::Incomplete)
            );
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            decode_candidate_v4_hybrid_monetary_network_block(&trailing),
            Err(V4HybridMonetaryWireError::Incomplete)
        );
        let mut wrong_magic = encoded.clone();
        wrong_magic[0] ^= 1;
        assert_eq!(
            decode_candidate_v4_hybrid_monetary_network_block(&wrong_magic),
            Err(V4HybridMonetaryWireError::BadMagic)
        );
        let mut wrong_version = encoded.clone();
        wrong_version[5] = 3;
        assert_eq!(
            decode_candidate_v4_hybrid_monetary_network_block(&wrong_version),
            Err(V4HybridMonetaryWireError::UnsupportedWireVersion)
        );
        let mut wrong_root = header;
        wrong_root.state_root[0] ^= 1;
        assert_eq!(
            encode_candidate_v4_hybrid_monetary_network_block(&wrong_root, &block),
            Err(V4HybridMonetaryWireError::HeaderBodyMismatch("state_root"))
        );
    }
}
