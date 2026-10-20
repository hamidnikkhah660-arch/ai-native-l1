//! Authenticated transport prototype for protocol research.
//! Uses HMAC-SHA-256 from RustCrypto; this is not a final production transport.

use crate::MAX_FRAME;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;
pub const AUTH_VERSION: u16 = 1;
pub const AUTH_HELLO_LEN: usize = 65;
pub const AUTH_ACK_LEN: usize = 97;
pub const RECORD_HEADER_LEN: usize = 18;
pub const AUTH_TAG_LEN: usize = 32;
pub const MAX_AUTH_RECORD: usize = RECORD_HEADER_LEN + MAX_FRAME + AUTH_TAG_LEN;
pub const AUTH_MAGIC: u32 = 0x41314155; // "A1AU"

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    InvalidHello,
    InvalidAck,
    BadMac,
    BadMagic,
    UnsupportedVersion(u16),
    Oversize(usize),
    Truncated,
    Replay { expected: u64, got: u64 },
    InvalidRecordLength,
    Randomness,
}

fn mac_bytes(key: &[u8], parts: &[&[u8]]) -> [u8; AUTH_TAG_LEN] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts arbitrary key length");
    for part in parts {
        mac.update(part);
    }
    let out = mac.finalize().into_bytes();
    out.into()
}

fn role_byte(role: u8) -> Option<u8> {
    matches!(role, 1 | 2).then_some(role)
}

pub fn make_auth_hello(psk: &[u8], role: u8, nonce: [u8; 32]) -> Result<Vec<u8>, AuthError> {
    let role = role_byte(role).ok_or(AuthError::InvalidHello)?;
    let tag = mac_bytes(psk, &[b"AIN1-AUTH-HELLO\0", &[role], &nonce]);
    let mut out = Vec::with_capacity(AUTH_HELLO_LEN);
    out.push(role);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&tag);
    Ok(out)
}

pub fn verify_auth_hello(psk: &[u8], payload: &[u8]) -> Result<(u8, [u8; 32]), AuthError> {
    if payload.len() != AUTH_HELLO_LEN {
        return Err(AuthError::InvalidHello);
    }
    let role = role_byte(payload[0]).ok_or(AuthError::InvalidHello)?;
    let nonce: [u8; 32] = payload[1..33]
        .try_into()
        .map_err(|_| AuthError::InvalidHello)?;
    let expected = mac_bytes(psk, &[b"AIN1-AUTH-HELLO\0", &[role], &nonce]);
    if !constant_time_eq(&expected, &payload[33..]) {
        return Err(AuthError::BadMac);
    }
    Ok((role, nonce))
}

pub fn make_auth_ack(psk: &[u8], client_nonce: [u8; 32], server_nonce: [u8; 32]) -> Vec<u8> {
    let role = [2u8];
    let tag = mac_bytes(
        psk,
        &[b"AIN1-AUTH-ACK\0", &role, &client_nonce, &server_nonce],
    );
    let mut out = Vec::with_capacity(AUTH_ACK_LEN);
    out.push(2);
    out.extend_from_slice(&client_nonce);
    out.extend_from_slice(&server_nonce);
    out.extend_from_slice(&tag);
    out
}

pub fn verify_auth_ack(
    psk: &[u8],
    payload: &[u8],
    expected_client_nonce: [u8; 32],
) -> Result<[u8; 32], AuthError> {
    if payload.len() != AUTH_ACK_LEN || payload[0] != 2 {
        return Err(AuthError::InvalidAck);
    }
    let client: [u8; 32] = payload[1..33]
        .try_into()
        .map_err(|_| AuthError::InvalidAck)?;
    if client != expected_client_nonce {
        return Err(AuthError::InvalidAck);
    }
    let server: [u8; 32] = payload[33..65]
        .try_into()
        .map_err(|_| AuthError::InvalidAck)?;
    let expected = mac_bytes(psk, &[b"AIN1-AUTH-ACK\0", &[2u8], &client, &server]);
    if !constant_time_eq(&expected, &payload[65..]) {
        return Err(AuthError::BadMac);
    }
    Ok(server)
}

pub fn derive_direction_key(
    psk: &[u8],
    client_nonce: [u8; 32],
    server_nonce: [u8; 32],
    direction: u8,
) -> [u8; 32] {
    let label = if direction == 0 {
        b"c2s".as_slice()
    } else {
        b"s2c".as_slice()
    };
    mac_bytes(
        psk,
        &[b"AIN1-SESSION\0", label, &client_nonce, &server_nonce],
    )
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn seal_record(key: &[u8], seq: u64, inner_frame: &[u8]) -> Result<Vec<u8>, AuthError> {
    if inner_frame.len() > MAX_FRAME {
        return Err(AuthError::Oversize(inner_frame.len()));
    }
    let mut header = Vec::with_capacity(RECORD_HEADER_LEN);
    header.extend_from_slice(&AUTH_MAGIC.to_be_bytes());
    header.extend_from_slice(&AUTH_VERSION.to_be_bytes());
    header.extend_from_slice(&seq.to_be_bytes());
    header.extend_from_slice(&(inner_frame.len() as u32).to_be_bytes());
    let tag = mac_bytes(key, &[b"AIN1-RECORD\0", &header, inner_frame]);
    let mut out = header;
    out.extend_from_slice(inner_frame);
    out.extend_from_slice(&tag);
    Ok(out)
}

pub fn open_record(key: &[u8], expected_seq: u64, record: &[u8]) -> Result<Vec<u8>, AuthError> {
    if record.len() < RECORD_HEADER_LEN + AUTH_TAG_LEN {
        return Err(AuthError::Truncated);
    }
    let magic = u32::from_be_bytes(record[0..4].try_into().unwrap());
    if magic != AUTH_MAGIC {
        return Err(AuthError::BadMagic);
    }
    let version = u16::from_be_bytes(record[4..6].try_into().unwrap());
    if version != AUTH_VERSION {
        return Err(AuthError::UnsupportedVersion(version));
    }
    let seq = u64::from_be_bytes(record[6..14].try_into().unwrap());
    if seq != expected_seq {
        return Err(AuthError::Replay {
            expected: expected_seq,
            got: seq,
        });
    }
    let len = u32::from_be_bytes(record[14..18].try_into().unwrap()) as usize;
    if len > MAX_FRAME {
        return Err(AuthError::Oversize(len));
    }
    let total = RECORD_HEADER_LEN
        .checked_add(len)
        .and_then(|x| x.checked_add(AUTH_TAG_LEN))
        .ok_or(AuthError::InvalidRecordLength)?;
    if record.len() != total {
        return Err(AuthError::InvalidRecordLength);
    }
    let inner = &record[RECORD_HEADER_LEN..RECORD_HEADER_LEN + len];
    let tag = &record[RECORD_HEADER_LEN + len..total];
    let expected = mac_bytes(
        key,
        &[b"AIN1-RECORD\0", &record[..RECORD_HEADER_LEN], inner],
    );
    if !constant_time_eq(&expected, tag) {
        return Err(AuthError::BadMac);
    }
    Ok(inner.to_vec())
}

pub fn random_nonce() -> Result<[u8; 32], AuthError> {
    let mut nonce = [0u8; 32];
    getrandom::getrandom(&mut nonce).map_err(|_| AuthError::Randomness)?;
    Ok(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode_frame;

    fn psk() -> [u8; 32] {
        [7u8; 32]
    }
    fn nonces() -> ([u8; 32], [u8; 32]) {
        ([1u8; 32], [2u8; 32])
    }

    #[test]
    fn hello_roundtrip_and_wrong_key_rejects() {
        let (c, _) = nonces();
        let msg = make_auth_hello(&psk(), 1, c).unwrap();
        assert_eq!(verify_auth_hello(&psk(), &msg).unwrap(), (1, c));
        assert_eq!(verify_auth_hello(&[8u8; 32], &msg), Err(AuthError::BadMac));
    }

    #[test]
    fn ack_binds_client_and_server_nonce() {
        let (c, s) = nonces();
        let msg = make_auth_ack(&psk(), c, s);
        assert_eq!(verify_auth_ack(&psk(), &msg, c).unwrap(), s);
        let mut bad = msg.clone();
        bad[40] ^= 1;
        assert!(matches!(
            verify_auth_ack(&psk(), &bad, c),
            Err(AuthError::BadMac)
        ));
    }

    #[test]
    fn directional_keys_differ() {
        let (c, s) = nonces();
        assert_ne!(
            derive_direction_key(&psk(), c, s, 0),
            derive_direction_key(&psk(), c, s, 1)
        );
    }

    #[test]
    fn record_roundtrip_tamper_and_replay_fail() {
        let (c, s) = nonces();
        let k = derive_direction_key(&psk(), c, s, 0);
        let frame = encode_frame(1, 2, 9, b"hello").unwrap();
        let rec = seal_record(&k, 0, &frame).unwrap();
        assert_eq!(open_record(&k, 0, &rec).unwrap(), frame);
        assert!(matches!(
            open_record(&k, 1, &rec),
            Err(AuthError::Replay { .. })
        ));
        let mut tampered = rec.clone();
        tampered[RECORD_HEADER_LEN] ^= 1;
        assert_eq!(open_record(&k, 0, &tampered), Err(AuthError::BadMac));
    }

    #[test]
    fn oversize_rejected_before_payload_copy() {
        let mut rec = vec![0u8; RECORD_HEADER_LEN + AUTH_TAG_LEN];
        rec[0..4].copy_from_slice(&AUTH_MAGIC.to_be_bytes());
        rec[4..6].copy_from_slice(&AUTH_VERSION.to_be_bytes());
        rec[14..18].copy_from_slice(&((MAX_FRAME + 1) as u32).to_be_bytes());
        assert_eq!(
            open_record(&psk(), 0, &rec),
            Err(AuthError::Oversize(MAX_FRAME + 1))
        );
    }
}
