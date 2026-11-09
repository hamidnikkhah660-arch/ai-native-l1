//! Versioned, bounded TXN2 submission framing for the isolated QZBE candidate runtime.
//!
//! The transport framing is independent of transaction consensus encoding. Requests carry one
//! canonical TXN2 byte string; acknowledgements distinguish admission, duplicate, and rejection.
//! This module deliberately does not open sockets or authorize public-network launch.
use crate::state_machine::MAX_TRANSACTION_BYTES;

pub const REQUEST_MAGIC: &[u8; 4] = b"QZTS";
pub const ACK_MAGIC: &[u8; 4] = b"QZTA";
pub const GOSSIP_MAGIC: &[u8; 4] = b"QZTG";
pub const PROTOCOL_VERSION: u16 = 1;
pub const REQUEST_HEADER_BYTES: usize = 10;
pub const GOSSIP_HEADER_BYTES: usize = 42;
pub const ACK_BYTES: usize = 43;
const MIN_TXN2_BYTES: usize = 137;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TxIngressStatus {
    Accepted = 0,
    Duplicate = 1,
    Rejected = 2,
}

impl TryFrom<u8> for TxIngressStatus {
    type Error = TxIngressCodecError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Accepted),
            1 => Ok(Self::Duplicate),
            2 => Ok(Self::Rejected),
            _ => Err(TxIngressCodecError::UnknownStatus(value)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxIngressAck {
    pub status: TxIngressStatus,
    pub mempool_count: u32,
    pub transaction_id: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxIngressCodecError {
    InvalidTransactionLength(usize),
    InvalidGossipLength(usize),
    BadMagic,
    ProfileMismatch,
    UnsupportedVersion(u16),
    UnknownStatus(u8),
    InvalidAckLength(usize),
}

/// Encode one canonical TXN2 transaction into a bounded QZTS/1 request.
pub fn encode_request(transaction_wire: &[u8]) -> Result<Vec<u8>, TxIngressCodecError> {
    if !(MIN_TXN2_BYTES..=MAX_TRANSACTION_BYTES).contains(&transaction_wire.len()) {
        return Err(TxIngressCodecError::InvalidTransactionLength(
            transaction_wire.len(),
        ));
    }
    let length = u32::try_from(transaction_wire.len())
        .map_err(|_| TxIngressCodecError::InvalidTransactionLength(transaction_wire.len()))?;
    let mut out = Vec::with_capacity(REQUEST_HEADER_BYTES + transaction_wire.len());
    out.extend_from_slice(REQUEST_MAGIC);
    out.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(transaction_wire);
    Ok(out)
}

/// Validate a request header before the caller allocates or reads its declared payload.
pub fn decode_request_header(
    header: &[u8; REQUEST_HEADER_BYTES],
) -> Result<usize, TxIngressCodecError> {
    if &header[..4] != REQUEST_MAGIC {
        return Err(TxIngressCodecError::BadMagic);
    }
    let version = u16::from_be_bytes([header[4], header[5]]);
    if version != PROTOCOL_VERSION {
        return Err(TxIngressCodecError::UnsupportedVersion(version));
    }
    let length = u32::from_be_bytes([header[6], header[7], header[8], header[9]]) as usize;
    if !(MIN_TXN2_BYTES..=MAX_TRANSACTION_BYTES).contains(&length) {
        return Err(TxIngressCodecError::InvalidTransactionLength(length));
    }
    Ok(length)
}

/// Encode one bounded TXN2 transaction for authenticated peer gossip. The profile fingerprint
/// is carried explicitly so a correctly authenticated peer cannot replay a transaction envelope
/// across incompatible runtime profiles. Noise already binds the network ID into its prologue.
pub fn encode_gossip_frame(
    profile_id: &[u8; 32],
    transaction_wire: &[u8],
) -> Result<Vec<u8>, TxIngressCodecError> {
    if !(MIN_TXN2_BYTES..=MAX_TRANSACTION_BYTES).contains(&transaction_wire.len()) {
        return Err(TxIngressCodecError::InvalidTransactionLength(
            transaction_wire.len(),
        ));
    }
    let length = u32::try_from(transaction_wire.len())
        .map_err(|_| TxIngressCodecError::InvalidTransactionLength(transaction_wire.len()))?;
    let mut out = Vec::with_capacity(GOSSIP_HEADER_BYTES + transaction_wire.len());
    out.extend_from_slice(GOSSIP_MAGIC);
    out.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    out.extend_from_slice(profile_id);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(transaction_wire);
    Ok(out)
}

/// Validate a complete bounded QZTG/1 frame, profile binding, and exact payload length.
/// Returns a borrowed canonical TXN2 payload and never allocates based on untrusted lengths.
pub fn decode_gossip_frame<'a>(
    expected_profile_id: &[u8; 32],
    frame: &'a [u8],
) -> Result<&'a [u8], TxIngressCodecError> {
    if frame.len() < GOSSIP_HEADER_BYTES {
        return Err(TxIngressCodecError::InvalidGossipLength(frame.len()));
    }
    if &frame[..4] != GOSSIP_MAGIC {
        return Err(TxIngressCodecError::BadMagic);
    }
    let version = u16::from_be_bytes([frame[4], frame[5]]);
    if version != PROTOCOL_VERSION {
        return Err(TxIngressCodecError::UnsupportedVersion(version));
    }
    if &frame[6..38] != expected_profile_id {
        return Err(TxIngressCodecError::ProfileMismatch);
    }
    let payload_len = u32::from_be_bytes([frame[38], frame[39], frame[40], frame[41]]) as usize;
    if !(MIN_TXN2_BYTES..=MAX_TRANSACTION_BYTES).contains(&payload_len)
        || frame.len() != GOSSIP_HEADER_BYTES.saturating_add(payload_len)
    {
        return Err(TxIngressCodecError::InvalidGossipLength(frame.len()));
    }
    Ok(&frame[GOSSIP_HEADER_BYTES..])
}

pub fn encode_ack(ack: TxIngressAck) -> [u8; ACK_BYTES] {
    let mut out = [0u8; ACK_BYTES];
    out[..4].copy_from_slice(ACK_MAGIC);
    out[4..6].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    out[6] = ack.status as u8;
    out[7..11].copy_from_slice(&ack.mempool_count.to_be_bytes());
    out[11..43].copy_from_slice(&ack.transaction_id);
    out
}

pub fn decode_ack(bytes: &[u8]) -> Result<TxIngressAck, TxIngressCodecError> {
    if bytes.len() != ACK_BYTES {
        return Err(TxIngressCodecError::InvalidAckLength(bytes.len()));
    }
    if &bytes[..4] != ACK_MAGIC {
        return Err(TxIngressCodecError::BadMagic);
    }
    let version = u16::from_be_bytes([bytes[4], bytes[5]]);
    if version != PROTOCOL_VERSION {
        return Err(TxIngressCodecError::UnsupportedVersion(version));
    }
    let status = TxIngressStatus::try_from(bytes[6])?;
    let mempool_count = u32::from_be_bytes([bytes[7], bytes[8], bytes[9], bytes[10]]);
    let mut transaction_id = [0u8; 32];
    transaction_id.copy_from_slice(&bytes[11..43]);
    Ok(TxIngressAck {
        status,
        mempool_count,
        transaction_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qzts_request_round_trips_bounded_transaction_and_rejects_bad_header() {
        let wire = vec![0x5a; MIN_TXN2_BYTES];
        let request = encode_request(&wire).unwrap();
        let header: [u8; REQUEST_HEADER_BYTES] =
            request[..REQUEST_HEADER_BYTES].try_into().unwrap();
        assert_eq!(decode_request_header(&header), Ok(wire.len()));
        assert_eq!(&request[REQUEST_HEADER_BYTES..], wire.as_slice());

        let mut bad_magic = header;
        bad_magic[0] ^= 1;
        assert_eq!(
            decode_request_header(&bad_magic),
            Err(TxIngressCodecError::BadMagic)
        );
        let mut bad_version = header;
        bad_version[5] = 2;
        assert_eq!(
            decode_request_header(&bad_version),
            Err(TxIngressCodecError::UnsupportedVersion(2))
        );
        assert!(matches!(
            encode_request(&[]),
            Err(TxIngressCodecError::InvalidTransactionLength(0))
        ));
    }

    #[test]
    fn qztg_gossip_frame_round_trips_and_binds_profile_and_exact_length() {
        let profile = [0x52; 32];
        let wrong_profile = [0x53; 32];
        let wire = vec![0x6b; MIN_TXN2_BYTES];
        let encoded = encode_gossip_frame(&profile, &wire).unwrap();
        assert_eq!(&encoded[..4], GOSSIP_MAGIC);
        assert_eq!(decode_gossip_frame(&profile, &encoded), Ok(wire.as_slice()));
        assert_eq!(
            decode_gossip_frame(&wrong_profile, &encoded),
            Err(TxIngressCodecError::ProfileMismatch)
        );

        let mut bad_magic = encoded.clone();
        bad_magic[0] ^= 1;
        assert_eq!(
            decode_gossip_frame(&profile, &bad_magic),
            Err(TxIngressCodecError::BadMagic)
        );
        let mut bad_version = encoded.clone();
        bad_version[5] = 2;
        assert_eq!(
            decode_gossip_frame(&profile, &bad_version),
            Err(TxIngressCodecError::UnsupportedVersion(2))
        );
        let mut truncated = encoded.clone();
        truncated.pop();
        assert!(matches!(
            decode_gossip_frame(&profile, &truncated),
            Err(TxIngressCodecError::InvalidGossipLength(_))
        ));
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(matches!(
            decode_gossip_frame(&profile, &trailing),
            Err(TxIngressCodecError::InvalidGossipLength(_))
        ));
        assert!(matches!(
            encode_gossip_frame(&profile, &[]),
            Err(TxIngressCodecError::InvalidTransactionLength(0))
        ));
    }

    #[test]
    fn qzta_ack_round_trips_and_rejects_unknown_status() {
        let ack = TxIngressAck {
            status: TxIngressStatus::Accepted,
            mempool_count: 17,
            transaction_id: [0x3c; 32],
        };
        let encoded = encode_ack(ack);
        assert_eq!(decode_ack(&encoded).unwrap(), ack);
        let mut bad = encoded;
        bad[6] = 9;
        assert_eq!(decode_ack(&bad), Err(TxIngressCodecError::UnknownStatus(9)));
    }
}
