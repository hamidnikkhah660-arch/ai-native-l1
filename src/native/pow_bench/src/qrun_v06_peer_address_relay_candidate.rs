//! Candidate-only Q6AR address relay codec for QFP6.
//!
//! Q6AR advertisements are network/profile bound and time-limited. A Noise source may be
//! pinned or anonymous; anonymous origins are explicitly marked low-trust. Each advertised
//! endpoint remains untrusted until an operator explicitly approves its independently verified key.
//! An opt-in listener callback can persist candidate metadata from pinned relays, but candidates
//! are never automatically trusted, selected, or connected.
use crate::qrun_v06_noise_transport_candidate::QRunV06NoiseSession;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const Q6AR_MAGIC: [u8; 4] = *b"Q6AR";
pub const Q6AR_VERSION: u16 = 1;
pub const Q6AR_HEADER_BYTES: usize = 84;
pub const Q6AR_MAX_ADDRESSES: usize = 32;
pub const Q6AR_MAX_TTL_SECS: u32 = 24 * 60 * 60;
pub const Q6AR_MAX_FUTURE_SKEW_SECS: u64 = 5 * 60;
pub const Q6AR_MAX_FRAME_BYTES: usize = Q6AR_HEADER_BYTES + Q6AR_MAX_ADDRESSES * 51;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Q6arAddress {
    pub endpoint: SocketAddr,
    pub noise_static_public_key: [u8; 32],
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Q6arAdvertisement {
    pub network_id: [u8; 32],
    pub profile_id: [u8; 32],
    pub issued_at_secs: u64,
    pub ttl_secs: u32,
    pub addresses: Vec<Q6arAddress>,
}

/// The session that relayed an advertisement. An unpinned key is self-asserted by Noise XX
/// and may be MITM-controlled; it is metadata, not an authenticated identity or trust decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Q6arRelayOrigin {
    pub relay_static_public_key: [u8; 32],
    pub relay_static_key_pinned: bool,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Q6arReceivedAdvertisement {
    pub advertisement: Q6arAdvertisement,
    pub relay_origin: Q6arRelayOrigin,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Q6arError {
    Malformed,
    WrongNetwork,
    WrongProfile,
    UnauthenticatedSession,
    InvalidTimestamp,
    Expired,
    TooManyAddresses,
    InvalidEndpoint,
    InvalidPeerKey,
    DuplicateAddress,
    NonCanonical,
    Oversized,
}
impl std::fmt::Display for Q6arError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Q6arError {}

fn is_public_endpoint(endpoint: SocketAddr) -> bool {
    if endpoint.port() == 0 {
        return false;
    }
    match endpoint.ip() {
        IpAddr::V4(ip) => {
            let o = ip.octets();
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_private()
                && !ip.is_link_local()
                && !ip.is_multicast()
                && !ip.is_broadcast()
                && o[0] != 0
                && !(o[0] == 100 && (64..=127).contains(&o[1]))
                && !(o[0] == 192 && o[1] == 0 && o[2] == 0)
                && !(o[0] == 198 && (o[1] == 18 || o[1] == 19))
        }
        IpAddr::V6(ip) => {
            let o = ip.octets();
            !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast()
                && !(o[0] & 0xfe == 0xfc) // unique-local fc00::/7
                && !(o[0] == 0xfe && o[1] & 0xc0 == 0x80) // link-local fe80::/10
                && !(o[0] == 0x20 && o[1] == 0x01 && o[2] == 0x0d && o[3] == 0xb8) // documentation
                && ip.to_ipv4_mapped().is_none()
        }
    }
}
fn encode_address(address: &Q6arAddress) -> Result<Vec<u8>, Q6arError> {
    if !is_public_endpoint(address.endpoint) {
        return Err(Q6arError::InvalidEndpoint);
    }
    if address.noise_static_public_key == [0; 32] {
        return Err(Q6arError::InvalidPeerKey);
    }
    let mut out = Vec::with_capacity(51);
    match address.endpoint.ip() {
        IpAddr::V4(ip) => {
            out.push(4);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(6);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&address.endpoint.port().to_be_bytes());
    out.extend_from_slice(&address.noise_static_public_key);
    Ok(out)
}
fn validate_envelope_shape(value: &Q6arAdvertisement) -> Result<(), Q6arError> {
    if value.network_id == [0; 32]
        || value.profile_id == [0; 32]
        || value.issued_at_secs == 0
        || value.ttl_secs == 0
        || value.ttl_secs > Q6AR_MAX_TTL_SECS
    {
        return Err(Q6arError::InvalidTimestamp);
    }
    if value.addresses.is_empty() || value.addresses.len() > Q6AR_MAX_ADDRESSES {
        return Err(Q6arError::TooManyAddresses);
    }
    let mut encoded = Vec::with_capacity(value.addresses.len());
    for address in &value.addresses {
        encoded.push(encode_address(address)?);
    }
    encoded.sort();
    for pair in encoded.windows(2) {
        if pair[0] == pair[1] {
            return Err(Q6arError::DuplicateAddress);
        }
        if pair[0][..pair[0].len() - 32] == pair[1][..pair[1].len() - 32] {
            return Err(Q6arError::DuplicateAddress);
        }
        if pair[0][pair[0].len() - 32..] == pair[1][pair[1].len() - 32..] {
            return Err(Q6arError::DuplicateAddress);
        }
    }
    Ok(())
}

/// Encode a deterministic Q6AR v1 frame. Address entries are sorted by their canonical wire bytes.
pub fn encode_q6ar(value: &Q6arAdvertisement) -> Result<Vec<u8>, Q6arError> {
    validate_envelope_shape(value)?;
    let mut entries: Vec<Vec<u8>> = value
        .addresses
        .iter()
        .map(encode_address)
        .collect::<Result<_, _>>()?;
    entries.sort();
    let mut out =
        Vec::with_capacity(Q6AR_HEADER_BYTES + entries.iter().map(Vec::len).sum::<usize>());
    out.extend_from_slice(&Q6AR_MAGIC);
    out.extend_from_slice(&Q6AR_VERSION.to_be_bytes());
    out.extend_from_slice(&value.network_id);
    out.extend_from_slice(&value.profile_id);
    out.extend_from_slice(&value.issued_at_secs.to_be_bytes());
    out.extend_from_slice(&value.ttl_secs.to_be_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_be_bytes());
    for entry in entries {
        out.extend_from_slice(&entry);
    }
    if out.len() > Q6AR_MAX_FRAME_BYTES {
        return Err(Q6arError::Oversized);
    }
    Ok(out)
}

/// Decode Q6AR against the local, already verified profile and current wall-clock time.
pub fn decode_q6ar(
    bytes: &[u8],
    expected_network_id: &[u8; 32],
    expected_profile_id: &[u8; 32],
    now_secs: u64,
) -> Result<Q6arAdvertisement, Q6arError> {
    if bytes.len() < Q6AR_HEADER_BYTES
        || bytes.len() > Q6AR_MAX_FRAME_BYTES
        || bytes[..4] != Q6AR_MAGIC
    {
        return Err(Q6arError::Malformed);
    }
    if u16::from_be_bytes(bytes[4..6].try_into().map_err(|_| Q6arError::Malformed)?) != Q6AR_VERSION
    {
        return Err(Q6arError::Malformed);
    }
    let network_id: [u8; 32] = bytes[6..38].try_into().map_err(|_| Q6arError::Malformed)?;
    let profile_id: [u8; 32] = bytes[38..70].try_into().map_err(|_| Q6arError::Malformed)?;
    if &network_id != expected_network_id {
        return Err(Q6arError::WrongNetwork);
    }
    if &profile_id != expected_profile_id {
        return Err(Q6arError::WrongProfile);
    }
    let issued_at_secs =
        u64::from_be_bytes(bytes[70..78].try_into().map_err(|_| Q6arError::Malformed)?);
    let ttl_secs = u32::from_be_bytes(bytes[78..82].try_into().map_err(|_| Q6arError::Malformed)?);
    let count =
        u16::from_be_bytes(bytes[82..84].try_into().map_err(|_| Q6arError::Malformed)?) as usize;
    if issued_at_secs == 0
        || ttl_secs == 0
        || ttl_secs > Q6AR_MAX_TTL_SECS
        || issued_at_secs > now_secs.saturating_add(Q6AR_MAX_FUTURE_SKEW_SECS)
    {
        return Err(Q6arError::InvalidTimestamp);
    }
    if now_secs
        > issued_at_secs
            .checked_add(ttl_secs as u64)
            .ok_or(Q6arError::InvalidTimestamp)?
    {
        return Err(Q6arError::Expired);
    }
    if count == 0 || count > Q6AR_MAX_ADDRESSES {
        return Err(Q6arError::TooManyAddresses);
    }
    let mut cursor = Q6AR_HEADER_BYTES;
    let mut addresses = Vec::with_capacity(count);
    let mut previous: Option<Vec<u8>> = None;
    for _ in 0..count {
        let start = cursor;
        let family = *bytes.get(cursor).ok_or(Q6arError::Malformed)?;
        cursor += 1;
        let ip = match family {
            4 => {
                let octets: [u8; 4] = bytes
                    .get(cursor..cursor + 4)
                    .ok_or(Q6arError::Malformed)?
                    .try_into()
                    .map_err(|_| Q6arError::Malformed)?;
                cursor += 4;
                IpAddr::V4(Ipv4Addr::from(octets))
            }
            6 => {
                let octets: [u8; 16] = bytes
                    .get(cursor..cursor + 16)
                    .ok_or(Q6arError::Malformed)?
                    .try_into()
                    .map_err(|_| Q6arError::Malformed)?;
                cursor += 16;
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            _ => return Err(Q6arError::Malformed),
        };
        let port = u16::from_be_bytes(
            bytes
                .get(cursor..cursor + 2)
                .ok_or(Q6arError::Malformed)?
                .try_into()
                .map_err(|_| Q6arError::Malformed)?,
        );
        cursor += 2;
        let key: [u8; 32] = bytes
            .get(cursor..cursor + 32)
            .ok_or(Q6arError::Malformed)?
            .try_into()
            .map_err(|_| Q6arError::Malformed)?;
        cursor += 32;
        let endpoint = SocketAddr::new(ip, port);
        let address = Q6arAddress {
            endpoint,
            noise_static_public_key: key,
        };
        let canonical = encode_address(&address)?;
        if canonical.as_slice() != &bytes[start..cursor] {
            return Err(Q6arError::NonCanonical);
        }
        if let Some(prev) = &previous {
            if prev >= &canonical {
                return Err(if prev == &canonical {
                    Q6arError::DuplicateAddress
                } else {
                    Q6arError::NonCanonical
                });
            }
        }
        previous = Some(canonical);
        addresses.push(address);
    }
    if cursor != bytes.len() {
        return Err(Q6arError::Malformed);
    }
    let value = Q6arAdvertisement {
        network_id,
        profile_id,
        issued_at_secs,
        ttl_secs,
        addresses,
    };
    validate_envelope_shape(&value)?;
    Ok(value)
}

/// Decode from any QFP6 Noise session. Unpinned Noise XX sources are explicitly marked
/// untrusted and their advertised endpoints must remain low-trust candidates until each
/// endpoint completes its own key-verified handshake. This mirrors Bitcoin-style untrusted
/// address gossip without confusing transport encryption with peer authentication.
pub fn decode_q6ar_from_session(
    bytes: &[u8],
    session: &QRunV06NoiseSession,
    now_secs: u64,
) -> Result<Q6arReceivedAdvertisement, Q6arError> {
    let relay_key = *session.remote_static_public_key();
    if relay_key == [0; 32] {
        return Err(Q6arError::UnauthenticatedSession);
    }
    let advertisement = decode_q6ar(bytes, session.network_id(), session.profile_id(), now_secs)?;
    Ok(Q6arReceivedAdvertisement {
        advertisement,
        relay_origin: Q6arRelayOrigin {
            relay_static_public_key: relay_key,
            relay_static_key_pinned: session.remote_static_key_pinned(),
        },
    })
}

/// Strict variant for seed/bootstrap use: the relay's Noise static key must be operator-pinned.
pub fn decode_q6ar_from_pinned_session(
    bytes: &[u8],
    session: &QRunV06NoiseSession,
    now_secs: u64,
) -> Result<Q6arAdvertisement, Q6arError> {
    let received = decode_q6ar_from_session(bytes, session, now_secs)?;
    if !received.relay_origin.relay_static_key_pinned {
        return Err(Q6arError::UnauthenticatedSession);
    }
    Ok(received.advertisement)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Q6arAdvertisement {
        Q6arAdvertisement {
            network_id: [1; 32],
            profile_id: [2; 32],
            issued_at_secs: 1_000,
            ttl_secs: 600,
            addresses: vec![
                Q6arAddress {
                    endpoint: "1.1.1.1:8333".parse().unwrap(),
                    noise_static_public_key: [1; 32],
                },
                Q6arAddress {
                    endpoint: "8.8.8.8:8333".parse().unwrap(),
                    noise_static_public_key: [8; 32],
                },
            ],
        }
    }
    #[test]
    fn roundtrips_canonical_public_endpoints() {
        let value = fixture();
        let wire = encode_q6ar(&value).unwrap();
        let decoded = decode_q6ar(&wire, &[1; 32], &[2; 32], 1_200).unwrap();
        assert_eq!(decoded, value);
        assert_eq!(encode_q6ar(&decoded).unwrap(), wire);
    }
    #[test]
    fn rejects_wrong_network_profile_and_expired_records() {
        let wire = encode_q6ar(&fixture()).unwrap();
        assert_eq!(
            decode_q6ar(&wire, &[9; 32], &[2; 32], 1_100),
            Err(Q6arError::WrongNetwork)
        );
        assert_eq!(
            decode_q6ar(&wire, &[1; 32], &[9; 32], 1_100),
            Err(Q6arError::WrongProfile)
        );
        assert_eq!(
            decode_q6ar(&wire, &[1; 32], &[2; 32], 1_601),
            Err(Q6arError::Expired)
        );
    }
    #[test]
    fn rejects_private_unknown_or_duplicate_peer_endpoints() {
        let mut value = fixture();
        value.addresses[0].endpoint = "10.0.0.1:8333".parse().unwrap();
        assert_eq!(encode_q6ar(&value), Err(Q6arError::InvalidEndpoint));
        let mut value = fixture();
        value.addresses[1] = value.addresses[0].clone();
        assert_eq!(encode_q6ar(&value), Err(Q6arError::DuplicateAddress));
        let mut value = fixture();
        value.addresses[0].noise_static_public_key = [0; 32];
        assert_eq!(encode_q6ar(&value), Err(Q6arError::InvalidPeerKey));
    }
    #[test]
    fn rejects_noncanonical_entry_order_and_trailing_bytes() {
        let wire = encode_q6ar(&fixture()).unwrap();
        let mut trailing = wire.clone();
        trailing.push(0);
        assert_eq!(
            decode_q6ar(&trailing, &[1; 32], &[2; 32], 1_100),
            Err(Q6arError::Malformed)
        );
        let mut reordered = wire.clone();
        let first_len = 39;
        let second_len = 39;
        let a = reordered[Q6AR_HEADER_BYTES..Q6AR_HEADER_BYTES + first_len].to_vec();
        let b = reordered
            [Q6AR_HEADER_BYTES + first_len..Q6AR_HEADER_BYTES + first_len + second_len]
            .to_vec();
        reordered[Q6AR_HEADER_BYTES..Q6AR_HEADER_BYTES + second_len].copy_from_slice(&b);
        reordered[Q6AR_HEADER_BYTES + second_len..Q6AR_HEADER_BYTES + first_len + second_len]
            .copy_from_slice(&a);
        assert_eq!(
            decode_q6ar(&reordered, &[1; 32], &[2; 32], 1_100),
            Err(Q6arError::NonCanonical)
        );
    }
    #[test]
    fn enforces_ttl_and_count_bounds() {
        let mut value = fixture();
        value.ttl_secs = Q6AR_MAX_TTL_SECS + 1;
        assert_eq!(encode_q6ar(&value), Err(Q6arError::InvalidTimestamp));
        let mut value = fixture();
        value.addresses.clear();
        assert_eq!(encode_q6ar(&value), Err(Q6arError::TooManyAddresses));
    }
}
