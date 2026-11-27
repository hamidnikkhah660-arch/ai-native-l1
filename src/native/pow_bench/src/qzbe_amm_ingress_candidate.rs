//! Bounded QZAS/1 framing for canonical signed QAX1 AMM operations.
//! This is transport framing only; the receiver must still validate network, nonce,
//! expiry, signature, balances, consensus state and pair invariants before admitting an operation.
use crate::qzxb_amm_candidate::{AmmSignedOperation, MAX_AMM_SIGNED_OPERATION_BYTES};
use sha2::{Digest, Sha256};
use std::fmt;

pub const AMM_INGRESS_MAGIC: [u8; 4] = *b"QZAS";
pub const AMM_INGRESS_VERSION: u16 = 1;
pub const AMM_INGRESS_REQUEST_HEADER_BYTES: usize = 4 + 2 + 4;
pub const AMM_INGRESS_ACK_MAGIC: [u8; 4] = *b"QZAA";
pub const AMM_INGRESS_ACK_VERSION: u16 = 1;
pub const AMM_INGRESS_ACK_BYTES: usize = 4 + 2 + 1 + 4 + 32;
const AMM_INGRESS_OPERATION_ID_DOMAIN: &[u8] = b"QZXB-AMM-INGRESS-ID-V1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AmmIngressStatus {
    Accepted = 1,
    Duplicate = 2,
    Rejected = 3,
    PoolFull = 4,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmmIngressAck {
    pub status: AmmIngressStatus,
    pub mempool_count: u32,
    pub operation_id: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AmmIngressFrameError {
    WrongHeaderLength,
    WrongMagic,
    UnsupportedVersion(u16),
    InvalidPayloadLength,
    Oversize { actual: usize, limit: usize },
    WrongAckLength,
    UnknownStatus(u8),
    MalformedSignedOperation,
}

impl fmt::Display for AmmIngressFrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for AmmIngressFrameError {}

pub fn encode_request(operation: &AmmSignedOperation) -> Result<Vec<u8>, AmmIngressFrameError> {
    let payload = operation
        .encode()
        .map_err(|_| AmmIngressFrameError::MalformedSignedOperation)?;
    if payload.is_empty() {
        return Err(AmmIngressFrameError::InvalidPayloadLength);
    }
    if payload.len() > MAX_AMM_SIGNED_OPERATION_BYTES {
        return Err(AmmIngressFrameError::Oversize {
            actual: payload.len(),
            limit: MAX_AMM_SIGNED_OPERATION_BYTES,
        });
    }
    let length =
        u32::try_from(payload.len()).map_err(|_| AmmIngressFrameError::InvalidPayloadLength)?;
    let mut out = Vec::with_capacity(AMM_INGRESS_REQUEST_HEADER_BYTES + payload.len());
    out.extend_from_slice(&AMM_INGRESS_MAGIC);
    out.extend_from_slice(&AMM_INGRESS_VERSION.to_be_bytes());
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

pub fn decode_request_header(header: &[u8]) -> Result<usize, AmmIngressFrameError> {
    if header.len() != AMM_INGRESS_REQUEST_HEADER_BYTES {
        return Err(AmmIngressFrameError::WrongHeaderLength);
    }
    if header[..4] != AMM_INGRESS_MAGIC {
        return Err(AmmIngressFrameError::WrongMagic);
    }
    let version = u16::from_be_bytes([header[4], header[5]]);
    if version != AMM_INGRESS_VERSION {
        return Err(AmmIngressFrameError::UnsupportedVersion(version));
    }
    let length = u32::from_be_bytes(
        header[6..10]
            .try_into()
            .map_err(|_| AmmIngressFrameError::WrongHeaderLength)?,
    ) as usize;
    if length == 0 {
        return Err(AmmIngressFrameError::InvalidPayloadLength);
    }
    if length > MAX_AMM_SIGNED_OPERATION_BYTES {
        return Err(AmmIngressFrameError::Oversize {
            actual: length,
            limit: MAX_AMM_SIGNED_OPERATION_BYTES,
        });
    }
    Ok(length)
}

pub fn operation_id(canonical_signed_operation: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(AMM_INGRESS_OPERATION_ID_DOMAIN);
    hash.update(canonical_signed_operation);
    hash.finalize().into()
}

pub fn encode_ack(ack: &AmmIngressAck) -> [u8; AMM_INGRESS_ACK_BYTES] {
    let mut out = [0u8; AMM_INGRESS_ACK_BYTES];
    out[..4].copy_from_slice(&AMM_INGRESS_ACK_MAGIC);
    out[4..6].copy_from_slice(&AMM_INGRESS_ACK_VERSION.to_be_bytes());
    out[6] = ack.status as u8;
    out[7..11].copy_from_slice(&ack.mempool_count.to_be_bytes());
    out[11..43].copy_from_slice(&ack.operation_id);
    out
}

pub fn decode_ack(bytes: &[u8]) -> Result<AmmIngressAck, AmmIngressFrameError> {
    if bytes.len() != AMM_INGRESS_ACK_BYTES {
        return Err(AmmIngressFrameError::WrongAckLength);
    }
    if bytes[..4] != AMM_INGRESS_ACK_MAGIC {
        return Err(AmmIngressFrameError::WrongMagic);
    }
    let version = u16::from_be_bytes([bytes[4], bytes[5]]);
    if version != AMM_INGRESS_ACK_VERSION {
        return Err(AmmIngressFrameError::UnsupportedVersion(version));
    }
    let status = match bytes[6] {
        1 => AmmIngressStatus::Accepted,
        2 => AmmIngressStatus::Duplicate,
        3 => AmmIngressStatus::Rejected,
        4 => AmmIngressStatus::PoolFull,
        value => return Err(AmmIngressFrameError::UnknownStatus(value)),
    };
    let mempool_count = u32::from_be_bytes(
        bytes[7..11]
            .try_into()
            .map_err(|_| AmmIngressFrameError::WrongAckLength)?,
    );
    let operation_id = bytes[11..43]
        .try_into()
        .map_err(|_| AmmIngressFrameError::WrongAckLength)?;
    Ok(AmmIngressAck {
        status,
        mempool_count,
        operation_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qzxb_amm_candidate::{AmmOperation, AmmSignedOperation};

    fn sample() -> AmmSignedOperation {
        AmmSignedOperation {
            network_id: [0x31; 32],
            sender: [0x41; 32],
            nonce: 7,
            expires_at: 100,
            operation: AmmOperation::RegisterAsset {
                asset_id: [0x55; 32],
            },
            signature: vec![0xA5; 64],
        }
    }

    #[test]
    fn request_header_and_payload_round_trip_with_bounded_length() {
        let encoded = encode_request(&sample()).unwrap();
        assert_eq!(
            decode_request_header(&encoded[..AMM_INGRESS_REQUEST_HEADER_BYTES]).unwrap(),
            encoded.len() - AMM_INGRESS_REQUEST_HEADER_BYTES
        );
        let decoded =
            AmmSignedOperation::decode(&encoded[AMM_INGRESS_REQUEST_HEADER_BYTES..]).unwrap();
        assert_eq!(decoded, sample());
    }

    #[test]
    fn request_header_fails_closed_on_wrong_version_empty_and_oversize() {
        let mut header = [0u8; AMM_INGRESS_REQUEST_HEADER_BYTES];
        header[..4].copy_from_slice(&AMM_INGRESS_MAGIC);
        header[4..6].copy_from_slice(&99u16.to_be_bytes());
        assert_eq!(
            decode_request_header(&header),
            Err(AmmIngressFrameError::UnsupportedVersion(99))
        );
        header[4..6].copy_from_slice(&AMM_INGRESS_VERSION.to_be_bytes());
        assert_eq!(
            decode_request_header(&header),
            Err(AmmIngressFrameError::InvalidPayloadLength)
        );
        header[6..10].copy_from_slice(&((MAX_AMM_SIGNED_OPERATION_BYTES as u32) + 1).to_be_bytes());
        assert!(matches!(
            decode_request_header(&header),
            Err(AmmIngressFrameError::Oversize { .. })
        ));
    }

    #[test]
    fn acknowledgement_round_trips_status_count_and_operation_id() {
        let ack = AmmIngressAck {
            status: AmmIngressStatus::Accepted,
            mempool_count: 12,
            operation_id: [0x72; 32],
        };
        assert_eq!(decode_ack(&encode_ack(&ack)).unwrap(), ack);
    }
}
