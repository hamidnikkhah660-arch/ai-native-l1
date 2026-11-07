//! CP-0401 bounded QHWR v1 application envelope codec.
//!
//! Pure codec only: no sockets, peer authentication, or provider IO.

use crate::private_testnet_pfm5_external_cas_highwater_wire_candidate::Pfm5ExternalCasHighWaterSignedResponseV1;
use crate::v4_fat1_trust_candidate::ML_DSA_65_SIGNATURE_BYTES;

pub const QHWR_MAGIC: [u8; 4] = *b"QHWR";
pub const QHWR_VERSION: u16 = 1;
pub const QHWR_HEADER_LEN: usize = 12;
pub const QHWR_MAX_PAYLOAD_BYTES: usize = 8_192;
pub const QHWA_V1_WIRE_BYTES: usize = 414;
const TYPE_REQUEST: u8 = 1;
const TYPE_RESPONSE: u8 = 2;
const OP_READ: u8 = 1;
const OP_COMPARE_AND_ADVANCE: u8 = 2;
const OP_ERROR: u8 = 255;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum QhwrErrorStatus {
    MalformedRequest = 1,
    UnsupportedVersionOrOperation = 2,
    UnauthorizedPeer = 3,
    ChallengeReplayOrExpired = 4,
    StateConflict = 5,
    InvalidTransition = 6,
    ProviderUnavailable = 7,
    DurableCommitOutcomeUnknown = 8,
}
impl TryFrom<u16> for QhwrErrorStatus {
    type Error = QhwrCodecError;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::MalformedRequest),
            2 => Ok(Self::UnsupportedVersionOrOperation),
            3 => Ok(Self::UnauthorizedPeer),
            4 => Ok(Self::ChallengeReplayOrExpired),
            5 => Ok(Self::StateConflict),
            6 => Ok(Self::InvalidTransition),
            7 => Ok(Self::ProviderUnavailable),
            8 => Ok(Self::DurableCommitOutcomeUnknown),
            _ => Err(QhwrCodecError::InvalidStatus),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QhwrRequest {
    Read {
        challenge: [u8; 32],
    },
    CompareAndAdvance {
        challenge: [u8; 32],
        expected_state_digest: [u8; 32],
        next_state_wire: [u8; QHWA_V1_WIRE_BYTES],
    },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QhwrOperation {
    Read,
    CompareAndAdvance,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QhwrResponse {
    SignedState {
        operation: QhwrOperation,
        response: Pfm5ExternalCasHighWaterSignedResponseV1,
    },
    Error(QhwrErrorStatus),
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QhwrCodecError {
    InvalidLength,
    PayloadTooLarge,
    InvalidMagic,
    UnsupportedVersion,
    InvalidMessageType,
    InvalidOperation,
    InvalidStatus,
    InvalidBody,
    ZeroChallenge,
}

fn is_zero(value: &[u8; 32]) -> bool {
    value.iter().all(|byte| *byte == 0)
}
fn take32(bytes: &[u8], cursor: &mut usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[*cursor..*cursor + 32]);
    *cursor += 32;
    out
}
fn header(message_type: u8, operation: u8, body: &[u8]) -> Result<Vec<u8>, QhwrCodecError> {
    if body.len() + QHWR_HEADER_LEN > QHWR_MAX_PAYLOAD_BYTES {
        return Err(QhwrCodecError::PayloadTooLarge);
    }
    let len = u32::try_from(body.len()).map_err(|_| QhwrCodecError::PayloadTooLarge)?;
    let mut out = Vec::with_capacity(QHWR_HEADER_LEN + body.len());
    out.extend_from_slice(&QHWR_MAGIC);
    out.extend_from_slice(&QHWR_VERSION.to_be_bytes());
    out.push(message_type);
    out.push(operation);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(body);
    Ok(out)
}
fn decode_header(bytes: &[u8]) -> Result<(u8, u8, &[u8]), QhwrCodecError> {
    if bytes.len() < QHWR_HEADER_LEN {
        return Err(QhwrCodecError::InvalidLength);
    }
    if bytes.len() > QHWR_MAX_PAYLOAD_BYTES {
        return Err(QhwrCodecError::PayloadTooLarge);
    }
    if bytes[..4] != QHWR_MAGIC {
        return Err(QhwrCodecError::InvalidMagic);
    }
    if u16::from_be_bytes([bytes[4], bytes[5]]) != QHWR_VERSION {
        return Err(QhwrCodecError::UnsupportedVersion);
    }
    let body_len = u32::from_be_bytes(bytes[8..12].try_into().unwrap()) as usize;
    if bytes.len() != QHWR_HEADER_LEN + body_len {
        return Err(QhwrCodecError::InvalidLength);
    }
    Ok((bytes[6], bytes[7], &bytes[QHWR_HEADER_LEN..]))
}

impl QhwrRequest {
    pub fn encode(&self) -> Result<Vec<u8>, QhwrCodecError> {
        match self {
            Self::Read { challenge } => {
                if is_zero(challenge) {
                    return Err(QhwrCodecError::ZeroChallenge);
                }
                header(TYPE_REQUEST, OP_READ, challenge)
            }
            Self::CompareAndAdvance {
                challenge,
                expected_state_digest,
                next_state_wire,
            } => {
                if is_zero(challenge) {
                    return Err(QhwrCodecError::ZeroChallenge);
                }
                let mut body = Vec::with_capacity(68 + QHWA_V1_WIRE_BYTES);
                body.extend_from_slice(challenge);
                body.extend_from_slice(expected_state_digest);
                body.extend_from_slice(&(QHWA_V1_WIRE_BYTES as u32).to_be_bytes());
                body.extend_from_slice(next_state_wire);
                header(TYPE_REQUEST, OP_COMPARE_AND_ADVANCE, &body)
            }
        }
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, QhwrCodecError> {
        let (kind, op, body) = decode_header(bytes)?;
        if kind != TYPE_REQUEST {
            return Err(QhwrCodecError::InvalidMessageType);
        }
        let mut cursor = 0;
        let value = match op {
            OP_READ if body.len() == 32 => Self::Read {
                challenge: take32(body, &mut cursor),
            },
            OP_COMPARE_AND_ADVANCE if body.len() == 68 + QHWA_V1_WIRE_BYTES => {
                let challenge = take32(body, &mut cursor);
                let expected_state_digest = take32(body, &mut cursor);
                let len = u32::from_be_bytes(body[cursor..cursor + 4].try_into().unwrap()) as usize;
                cursor += 4;
                if len != QHWA_V1_WIRE_BYTES {
                    return Err(QhwrCodecError::InvalidBody);
                }
                let mut next_state_wire = [0u8; QHWA_V1_WIRE_BYTES];
                next_state_wire.copy_from_slice(&body[cursor..cursor + len]);
                cursor += len;
                if cursor != body.len() {
                    return Err(QhwrCodecError::InvalidBody);
                }
                Self::CompareAndAdvance {
                    challenge,
                    expected_state_digest,
                    next_state_wire,
                }
            }
            OP_READ | OP_COMPARE_AND_ADVANCE => return Err(QhwrCodecError::InvalidBody),
            _ => return Err(QhwrCodecError::InvalidOperation),
        };
        let challenge = match &value {
            Self::Read { challenge } | Self::CompareAndAdvance { challenge, .. } => challenge,
        };
        if is_zero(challenge) {
            return Err(QhwrCodecError::ZeroChallenge);
        }
        Ok(value)
    }
}

impl QhwrResponse {
    pub fn encode(&self) -> Result<Vec<u8>, QhwrCodecError> {
        match self {
            Self::Error(status) => header(TYPE_RESPONSE, OP_ERROR, &(*status as u16).to_be_bytes()),
            Self::SignedState {
                operation,
                response,
            } => {
                if is_zero(&response.challenge) || response.wire_state.len() != QHWA_V1_WIRE_BYTES {
                    return Err(QhwrCodecError::InvalidBody);
                }
                let mut body = Vec::with_capacity(
                    80 + 8 + 4 + QHWA_V1_WIRE_BYTES + 4 + ML_DSA_65_SIGNATURE_BYTES,
                );
                body.extend_from_slice(&response.challenge);
                body.extend_from_slice(&response.key_id);
                body.extend_from_slice(&response.key_generation.to_be_bytes());
                body.extend_from_slice(&(response.wire_state.len() as u32).to_be_bytes());
                body.extend_from_slice(&response.wire_state);
                body.extend_from_slice(&(ML_DSA_65_SIGNATURE_BYTES as u32).to_be_bytes());
                body.extend_from_slice(&response.signature);
                let operation = match operation {
                    QhwrOperation::Read => OP_READ,
                    QhwrOperation::CompareAndAdvance => OP_COMPARE_AND_ADVANCE,
                };
                header(TYPE_RESPONSE, operation, &body)
            }
        }
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, QhwrCodecError> {
        let (kind, op, body) = decode_header(bytes)?;
        if kind != TYPE_RESPONSE {
            return Err(QhwrCodecError::InvalidMessageType);
        }
        if op == OP_ERROR {
            if body.len() != 2 {
                return Err(QhwrCodecError::InvalidBody);
            }
            return Ok(Self::Error(QhwrErrorStatus::try_from(u16::from_be_bytes(
                [body[0], body[1]],
            ))?));
        }
        let operation = match op {
            OP_READ => QhwrOperation::Read,
            OP_COMPARE_AND_ADVANCE => QhwrOperation::CompareAndAdvance,
            _ => return Err(QhwrCodecError::InvalidOperation),
        };
        let expected = 32 + 32 + 8 + 4 + QHWA_V1_WIRE_BYTES + 4 + ML_DSA_65_SIGNATURE_BYTES;
        if body.len() != expected {
            return Err(QhwrCodecError::InvalidBody);
        }
        let mut cursor = 0;
        let challenge = take32(body, &mut cursor);
        if is_zero(&challenge) {
            return Err(QhwrCodecError::ZeroChallenge);
        }
        let key_id = take32(body, &mut cursor);
        let key_generation = u64::from_be_bytes(body[cursor..cursor + 8].try_into().unwrap());
        cursor += 8;
        let wire_len = u32::from_be_bytes(body[cursor..cursor + 4].try_into().unwrap()) as usize;
        cursor += 4;
        if wire_len != QHWA_V1_WIRE_BYTES {
            return Err(QhwrCodecError::InvalidBody);
        }
        let wire_state = body[cursor..cursor + wire_len].to_vec();
        cursor += wire_len;
        let sig_len = u32::from_be_bytes(body[cursor..cursor + 4].try_into().unwrap()) as usize;
        cursor += 4;
        if sig_len != ML_DSA_65_SIGNATURE_BYTES || cursor + sig_len != body.len() {
            return Err(QhwrCodecError::InvalidBody);
        }
        let mut signature = [0u8; ML_DSA_65_SIGNATURE_BYTES];
        signature.copy_from_slice(&body[cursor..cursor + sig_len]);
        Ok(Self::SignedState {
            operation,
            response: Pfm5ExternalCasHighWaterSignedResponseV1 {
                challenge,
                key_id,
                key_generation,
                wire_state,
                signature,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn challenge() -> [u8; 32] {
        [0xA5; 32]
    }

    #[test]
    fn read_request_roundtrips() {
        let value = QhwrRequest::Read {
            challenge: challenge(),
        };
        let bytes = value.encode().unwrap();
        assert_eq!(bytes.len(), QHWR_HEADER_LEN + 32);
        assert_eq!(QhwrRequest::decode(&bytes).unwrap(), value);
    }
    #[test]
    fn cas_request_roundtrips_with_exact_qhwa_width() {
        let value = QhwrRequest::CompareAndAdvance {
            challenge: challenge(),
            expected_state_digest: [0x5A; 32],
            next_state_wire: [0xC3; QHWA_V1_WIRE_BYTES],
        };
        let bytes = value.encode().unwrap();
        assert_eq!(bytes.len(), QHWR_HEADER_LEN + 68 + QHWA_V1_WIRE_BYTES);
        assert_eq!(QhwrRequest::decode(&bytes).unwrap(), value);
    }
    #[test]
    fn rejects_truncation_trailing_bytes_oversize_and_bad_magic() {
        let bytes = QhwrRequest::Read {
            challenge: challenge(),
        }
        .encode()
        .unwrap();
        assert_eq!(
            QhwrRequest::decode(&bytes[..bytes.len() - 1]),
            Err(QhwrCodecError::InvalidLength)
        );
        let mut extra = bytes.clone();
        extra.push(0);
        assert_eq!(
            QhwrRequest::decode(&extra),
            Err(QhwrCodecError::InvalidLength)
        );
        let mut magic = bytes.clone();
        magic[0] ^= 1;
        assert_eq!(
            QhwrRequest::decode(&magic),
            Err(QhwrCodecError::InvalidMagic)
        );
        assert_eq!(
            decode_header(&vec![0; QHWR_MAX_PAYLOAD_BYTES + 1]),
            Err(QhwrCodecError::PayloadTooLarge)
        );
    }
    #[test]
    fn rejects_unknown_version_type_operation_and_zero_challenge() {
        let bytes = QhwrRequest::Read {
            challenge: challenge(),
        }
        .encode()
        .unwrap();
        let mut version = bytes.clone();
        version[5] = 2;
        assert_eq!(
            QhwrRequest::decode(&version),
            Err(QhwrCodecError::UnsupportedVersion)
        );
        let mut kind = bytes.clone();
        kind[6] = TYPE_RESPONSE;
        assert_eq!(
            QhwrRequest::decode(&kind),
            Err(QhwrCodecError::InvalidMessageType)
        );
        let mut op = bytes.clone();
        op[7] = 9;
        assert_eq!(
            QhwrRequest::decode(&op),
            Err(QhwrCodecError::InvalidOperation)
        );
        assert_eq!(
            QhwrRequest::Read { challenge: [0; 32] }.encode(),
            Err(QhwrCodecError::ZeroChallenge)
        );
    }
    #[test]
    fn error_response_roundtrips_and_unknown_status_rejected() {
        let value = QhwrResponse::Error(QhwrErrorStatus::StateConflict);
        let bytes = value.encode().unwrap();
        assert_eq!(QhwrResponse::decode(&bytes).unwrap(), value);
        let mut bad = bytes;
        bad[QHWR_HEADER_LEN + 1] = 99;
        assert_eq!(
            QhwrResponse::decode(&bad),
            Err(QhwrCodecError::InvalidStatus)
        );
    }
    #[test]
    fn signed_response_roundtrips_fixed_widths() {
        let value = QhwrResponse::SignedState {
            operation: QhwrOperation::CompareAndAdvance,
            response: Pfm5ExternalCasHighWaterSignedResponseV1 {
                challenge: challenge(),
                key_id: [0x44; 32],
                key_generation: 3,
                wire_state: vec![0x77; QHWA_V1_WIRE_BYTES],
                signature: [0x88; ML_DSA_65_SIGNATURE_BYTES],
            },
        };
        let bytes = value.encode().unwrap();
        assert!(bytes.len() <= QHWR_MAX_PAYLOAD_BYTES);
        assert_eq!(QhwrResponse::decode(&bytes).unwrap(), value);
    }
}
