//! Q6PD v1 signed peer-record codec for Bitcoin-inspired, opt-in peer discovery.
//!
//! Q6PD v2 authenticates a peer's endpoint, optional TLS SNI and exact Noise key. The store
//! persists sequence watermarks and peer records; the node supervisor exchanges signed
//! announcements/inventories and applies bounded automatic dialing. Self-signatures establish
//! key continuity, not third-party reputation or consensus authority.
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const Q6PD_MAGIC: [u8; 4] = *b"Q6PD";
pub const Q6PD_LEGACY_VERSION: u16 = 1;
pub const Q6PD_VERSION: u16 = 2;
pub const Q6PD_MAX_TTL_SECS: u32 = 24 * 60 * 60;
pub const Q6PD_MAX_FUTURE_SKEW_SECS: u64 = 5 * 60;
pub const Q6PD_MAX_SERVER_NAME_BYTES: usize = 253;
pub const Q6PD_MAX_RECORD_BYTES: usize =
    4 + 2 + 32 + 32 + 32 + 32 + 32 + 1 + 16 + 2 + 2 + Q6PD_MAX_SERVER_NAME_BYTES + 8 + 8 + 4 + 64;
const Q6PD_SIGNING_DOMAIN_V1: &[u8] = b"QFP6-Q6PD-PEER-RECORD-V1\0";
const Q6PD_SIGNING_DOMAIN: &[u8] = b"QFP6-Q6PD-PEER-RECORD-V2\0";
const Q6PD_PEER_ID_DOMAIN: &[u8] = b"QFP6-Q6PD-PEER-ID-V1\0";
const Q6PD_SIGNATURE_BYTES: usize = 64;
/// Smallest supported signed record (legacy v1, IPv4). V2 records add a 2-byte SNI length.
pub const Q6PD_MIN_RECORD_BYTES: usize =
    4 + 2 + 32 + 32 + 32 + 32 + 32 + 1 + 4 + 2 + 8 + 8 + 4 + Q6PD_SIGNATURE_BYTES;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Q6pdError {
    Malformed,
    UnsupportedVersion,
    WrongNetwork,
    WrongProfile,
    InvalidIdentityKey,
    InvalidPeerId,
    InvalidNoiseKey,
    InvalidEndpoint,
    InvalidSequence,
    InvalidTimestamp,
    Expired,
    InvalidSignature,
}
impl std::fmt::Display for Q6pdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Q6pdError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedQ6pdPeerRecord {
    pub network_id: [u8; 32],
    pub profile_id: [u8; 32],
    /// SHA-256-derived stable identifier of the Ed25519 identity public key.
    pub peer_id: [u8; 32],
    pub identity_public_key: [u8; 32],
    /// Noise static key bound to the signed peer identity.
    pub noise_static_public_key: [u8; 32],
    /// Public numeric TCP endpoint used after optional TLS termination.
    pub endpoint: SocketAddr,
    /// Optional DNS name sent as TLS SNI (for example a Funnel TCP relay). It is covered
    /// by the Ed25519 signature and is accepted only for TCP port 443.
    pub tls_server_name: Option<String>,
    /// Callers must persist a per-peer high-water mark and reject stale sequence values.
    pub sequence: u64,
    pub issued_at_secs: u64,
    pub ttl_secs: u32,
}

pub fn q6pd_peer_id_for_identity_public_key(identity_public_key: &[u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(Q6PD_PEER_ID_DOMAIN);
    hash.update(identity_public_key);
    hash.finalize().into()
}

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
                && o[0] < 224
                && !(o[0] == 100 && (64..=127).contains(&o[1]))
                && !(o[0] == 192 && o[1] == 0 && o[2] == 0)
                && !(o[0] == 192 && o[1] == 0 && o[2] == 2)
                && !(o[0] == 198 && (o[1] == 18 || o[1] == 19 || o[1] == 51 && o[2] == 100))
                && !(o[0] == 203 && o[1] == 0 && o[2] == 113)
        }
        IpAddr::V6(ip) => {
            let o = ip.octets();
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_multicast()
                && !(o[0] & 0xfe == 0xfc)
                && !(o[0] == 0xfe && o[1] & 0xc0 == 0x80)
                && !(o[0] == 0x20 && o[1] == 0x01 && o[2] == 0x0d && o[3] == 0xb8)
                && ip.to_ipv4_mapped().is_none()
        }
    }
}

/// Return the strict endpoint policy used for DNS seed address failover.
/// DNS answers are transport routes only; every route must authenticate the same pinned Noise key.
pub fn is_public_q6pd_endpoint(endpoint: SocketAddr) -> bool {
    is_public_endpoint(endpoint)
}

fn is_valid_tls_server_name(name: &str) -> bool {
    if name.is_empty()
        || name.len() > Q6PD_MAX_SERVER_NAME_BYTES
        || !name.is_ascii()
        || name.bytes().any(|byte| byte.is_ascii_uppercase())
        || name.ends_with('.')
    {
        return false;
    }
    let labels: Vec<&str> = name.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

fn encode_unsigned(
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
    identity_public_key: &[u8; 32],
    noise_static_public_key: &[u8; 32],
    endpoint: SocketAddr,
    tls_server_name: Option<&str>,
    sequence: u64,
    issued_at_secs: u64,
    ttl_secs: u32,
) -> Result<Vec<u8>, Q6pdError> {
    if *network_id == [0; 32] || *profile_id == [0; 32] {
        return Err(Q6pdError::Malformed);
    }
    VerifyingKey::from_bytes(identity_public_key).map_err(|_| Q6pdError::InvalidIdentityKey)?;
    if *noise_static_public_key == [0; 32] {
        return Err(Q6pdError::InvalidNoiseKey);
    }
    if !is_public_endpoint(endpoint) {
        return Err(Q6pdError::InvalidEndpoint);
    }
    if let Some(name) = tls_server_name {
        if endpoint.port() != 443 || !is_valid_tls_server_name(name) {
            return Err(Q6pdError::InvalidEndpoint);
        }
    }
    if sequence == 0 {
        return Err(Q6pdError::InvalidSequence);
    }
    if issued_at_secs == 0 || ttl_secs == 0 || ttl_secs > Q6PD_MAX_TTL_SECS {
        return Err(Q6pdError::InvalidTimestamp);
    }

    let mut out = Vec::with_capacity(Q6PD_MAX_RECORD_BYTES - Q6PD_SIGNATURE_BYTES);
    out.extend_from_slice(&Q6PD_MAGIC);
    out.extend_from_slice(&Q6PD_VERSION.to_be_bytes());
    out.extend_from_slice(network_id);
    out.extend_from_slice(profile_id);
    out.extend_from_slice(&q6pd_peer_id_for_identity_public_key(identity_public_key));
    out.extend_from_slice(identity_public_key);
    out.extend_from_slice(noise_static_public_key);
    match endpoint.ip() {
        IpAddr::V4(ip) => {
            out.push(4);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(6);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&endpoint.port().to_be_bytes());
    let server_name = tls_server_name.unwrap_or("").as_bytes();
    out.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
    out.extend_from_slice(server_name);
    out.extend_from_slice(&sequence.to_be_bytes());
    out.extend_from_slice(&issued_at_secs.to_be_bytes());
    out.extend_from_slice(&ttl_secs.to_be_bytes());
    Ok(out)
}

/// Sign a self-announcement. The identity secret is supplied by the caller and is never
/// serialized; the resulting record binds the public endpoint and exact Noise static key.
pub fn sign_q6pd_peer_record(
    network_id: [u8; 32],
    profile_id: [u8; 32],
    noise_static_public_key: [u8; 32],
    endpoint: SocketAddr,
    sequence: u64,
    issued_at_secs: u64,
    ttl_secs: u32,
    identity_key: &SigningKey,
) -> Result<Vec<u8>, Q6pdError> {
    sign_q6pd_peer_record_with_tls_server_name(
        network_id,
        profile_id,
        noise_static_public_key,
        endpoint,
        None,
        sequence,
        issued_at_secs,
        ttl_secs,
        identity_key,
    )
}

pub fn sign_q6pd_peer_record_with_tls_server_name(
    network_id: [u8; 32],
    profile_id: [u8; 32],
    noise_static_public_key: [u8; 32],
    endpoint: SocketAddr,
    tls_server_name: Option<&str>,
    sequence: u64,
    issued_at_secs: u64,
    ttl_secs: u32,
    identity_key: &SigningKey,
) -> Result<Vec<u8>, Q6pdError> {
    let identity_public_key = identity_key.verifying_key().to_bytes();
    let mut unsigned = encode_unsigned(
        &network_id,
        &profile_id,
        &identity_public_key,
        &noise_static_public_key,
        endpoint,
        tls_server_name,
        sequence,
        issued_at_secs,
        ttl_secs,
    )?;
    let mut preimage = Vec::with_capacity(Q6PD_SIGNING_DOMAIN.len() + unsigned.len());
    preimage.extend_from_slice(Q6PD_SIGNING_DOMAIN);
    preimage.extend_from_slice(&unsigned);
    unsigned.extend_from_slice(&identity_key.sign(&preimage).to_bytes());
    Ok(unsigned)
}

/// Verify the signature, network/profile, key binding, endpoint and TTL of one Q6PD record.
/// Sequence replay protection is deliberately stateful and must be enforced by the caller.
pub fn verify_q6pd_peer_record(
    wire: &[u8],
    expected_network_id: &[u8; 32],
    expected_profile_id: &[u8; 32],
    now_secs: u64,
) -> Result<VerifiedQ6pdPeerRecord, Q6pdError> {
    const MIN_LEN: usize = Q6PD_MIN_RECORD_BYTES;
    if wire.len() < MIN_LEN || wire.len() > Q6PD_MAX_RECORD_BYTES || wire[..4] != Q6PD_MAGIC {
        return Err(Q6pdError::Malformed);
    }
    let mut cursor = 4usize;
    let version = u16::from_be_bytes(
        wire[cursor..cursor + 2]
            .try_into()
            .map_err(|_| Q6pdError::Malformed)?,
    );
    cursor += 2;
    if version != Q6PD_LEGACY_VERSION && version != Q6PD_VERSION {
        return Err(Q6pdError::UnsupportedVersion);
    }
    let network_id: [u8; 32] = wire[cursor..cursor + 32]
        .try_into()
        .map_err(|_| Q6pdError::Malformed)?;
    cursor += 32;
    let profile_id: [u8; 32] = wire[cursor..cursor + 32]
        .try_into()
        .map_err(|_| Q6pdError::Malformed)?;
    cursor += 32;
    if &network_id != expected_network_id {
        return Err(Q6pdError::WrongNetwork);
    }
    if &profile_id != expected_profile_id {
        return Err(Q6pdError::WrongProfile);
    }
    let peer_id: [u8; 32] = wire[cursor..cursor + 32]
        .try_into()
        .map_err(|_| Q6pdError::Malformed)?;
    cursor += 32;
    let identity_public_key: [u8; 32] = wire[cursor..cursor + 32]
        .try_into()
        .map_err(|_| Q6pdError::Malformed)?;
    cursor += 32;
    let noise_static_public_key: [u8; 32] = wire[cursor..cursor + 32]
        .try_into()
        .map_err(|_| Q6pdError::Malformed)?;
    cursor += 32;
    if peer_id != q6pd_peer_id_for_identity_public_key(&identity_public_key) {
        return Err(Q6pdError::InvalidPeerId);
    }
    VerifyingKey::from_bytes(&identity_public_key).map_err(|_| Q6pdError::InvalidIdentityKey)?;
    if noise_static_public_key == [0; 32] {
        return Err(Q6pdError::InvalidNoiseKey);
    }
    let family = *wire.get(cursor).ok_or(Q6pdError::Malformed)?;
    cursor += 1;
    let ip = match family {
        4 => {
            let octets: [u8; 4] = wire
                .get(cursor..cursor + 4)
                .ok_or(Q6pdError::Malformed)?
                .try_into()
                .map_err(|_| Q6pdError::Malformed)?;
            cursor += 4;
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        6 => {
            let octets: [u8; 16] = wire
                .get(cursor..cursor + 16)
                .ok_or(Q6pdError::Malformed)?
                .try_into()
                .map_err(|_| Q6pdError::Malformed)?;
            cursor += 16;
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        _ => return Err(Q6pdError::Malformed),
    };
    let port = u16::from_be_bytes(
        wire.get(cursor..cursor + 2)
            .ok_or(Q6pdError::Malformed)?
            .try_into()
            .map_err(|_| Q6pdError::Malformed)?,
    );
    cursor += 2;
    let endpoint = SocketAddr::new(ip, port);
    if !is_public_endpoint(endpoint) {
        return Err(Q6pdError::InvalidEndpoint);
    }
    let tls_server_name = if version == Q6PD_LEGACY_VERSION {
        None
    } else {
        let name_len = u16::from_be_bytes(
            wire.get(cursor..cursor + 2)
                .ok_or(Q6pdError::Malformed)?
                .try_into()
                .map_err(|_| Q6pdError::Malformed)?,
        ) as usize;
        cursor += 2;
        if name_len > Q6PD_MAX_SERVER_NAME_BYTES {
            return Err(Q6pdError::Malformed);
        }
        if name_len == 0 {
            None
        } else {
            let name_bytes = wire
                .get(cursor..cursor + name_len)
                .ok_or(Q6pdError::Malformed)?;
            cursor += name_len;
            let name = std::str::from_utf8(name_bytes)
                .map_err(|_| Q6pdError::Malformed)?
                .to_owned();
            if endpoint.port() != 443 || !is_valid_tls_server_name(&name) {
                return Err(Q6pdError::InvalidEndpoint);
            }
            Some(name)
        }
    };
    let sequence = u64::from_be_bytes(
        wire.get(cursor..cursor + 8)
            .ok_or(Q6pdError::Malformed)?
            .try_into()
            .map_err(|_| Q6pdError::Malformed)?,
    );
    cursor += 8;
    if sequence == 0 {
        return Err(Q6pdError::InvalidSequence);
    }
    let issued_at_secs = u64::from_be_bytes(
        wire.get(cursor..cursor + 8)
            .ok_or(Q6pdError::Malformed)?
            .try_into()
            .map_err(|_| Q6pdError::Malformed)?,
    );
    cursor += 8;
    let ttl_secs = u32::from_be_bytes(
        wire.get(cursor..cursor + 4)
            .ok_or(Q6pdError::Malformed)?
            .try_into()
            .map_err(|_| Q6pdError::Malformed)?,
    );
    cursor += 4;
    if issued_at_secs == 0
        || ttl_secs == 0
        || ttl_secs > Q6PD_MAX_TTL_SECS
        || issued_at_secs > now_secs.saturating_add(Q6PD_MAX_FUTURE_SKEW_SECS)
    {
        return Err(Q6pdError::InvalidTimestamp);
    }
    if now_secs
        > issued_at_secs
            .checked_add(ttl_secs as u64)
            .ok_or(Q6pdError::InvalidTimestamp)?
    {
        return Err(Q6pdError::Expired);
    }
    let signature_offset = cursor;
    if wire.len() != signature_offset + Q6PD_SIGNATURE_BYTES {
        return Err(Q6pdError::Malformed);
    }
    let signer = VerifyingKey::from_bytes(&identity_public_key)
        .map_err(|_| Q6pdError::InvalidIdentityKey)?;
    let signature = Signature::from_slice(&wire[signature_offset..])
        .map_err(|_| Q6pdError::InvalidSignature)?;
    let signing_domain = if version == Q6PD_LEGACY_VERSION {
        Q6PD_SIGNING_DOMAIN_V1
    } else {
        Q6PD_SIGNING_DOMAIN
    };
    let mut preimage = Vec::with_capacity(signing_domain.len() + signature_offset);
    preimage.extend_from_slice(signing_domain);
    preimage.extend_from_slice(&wire[..signature_offset]);
    signer
        .verify_strict(&preimage, &signature)
        .map_err(|_| Q6pdError::InvalidSignature)?;

    Ok(VerifiedQ6pdPeerRecord {
        network_id,
        profile_id,
        peer_id,
        identity_public_key,
        noise_static_public_key,
        endpoint,
        tls_server_name,
        sequence,
        issued_at_secs,
        ttl_secs,
    })
}

/// Signed self-announcement and bounded inventory exchange inside an authenticated Noise session.
pub const Q6PD_ANNOUNCE_REQUEST_MAGIC: [u8; 4] = *b"Q6PA";
pub const Q6PD_ANNOUNCE_RESPONSE_MAGIC: [u8; 4] = *b"Q6PK";
pub const Q6PD_ANNOUNCE_VERSION: u16 = 1;
pub const Q6PD_ANNOUNCE_HEADER_BYTES: usize = 8;
pub const Q6PD_ANNOUNCE_RESPONSE_BYTES: usize = 7;

/// Wrap one canonical signed peer record for delivery to an authenticated peer.
pub fn encode_q6pd_announce_request(record_wire: &[u8]) -> Result<Vec<u8>, Q6pdError> {
    if record_wire.len() < 100
        || record_wire.len() > Q6PD_MAX_RECORD_BYTES
        || record_wire.get(..4) != Some(&Q6PD_MAGIC)
        || record_wire.len() > u16::MAX as usize
    {
        return Err(Q6pdError::Malformed);
    }
    let mut out = Vec::with_capacity(Q6PD_ANNOUNCE_HEADER_BYTES + record_wire.len());
    out.extend_from_slice(&Q6PD_ANNOUNCE_REQUEST_MAGIC);
    out.extend_from_slice(&Q6PD_ANNOUNCE_VERSION.to_be_bytes());
    out.extend_from_slice(&(record_wire.len() as u16).to_be_bytes());
    out.extend_from_slice(record_wire);
    Ok(out)
}

/// Return the signed record bytes from a bounded announcement frame.
pub fn decode_q6pd_announce_request(frame: &[u8]) -> Result<&[u8], Q6pdError> {
    if frame.len() < Q6PD_ANNOUNCE_HEADER_BYTES
        || frame.get(..4) != Some(&Q6PD_ANNOUNCE_REQUEST_MAGIC)
        || u16::from_be_bytes([frame[4], frame[5]]) != Q6PD_ANNOUNCE_VERSION
    {
        return Err(Q6pdError::Malformed);
    }
    let record_len = u16::from_be_bytes([frame[6], frame[7]]) as usize;
    if record_len < 100
        || record_len > Q6PD_MAX_RECORD_BYTES
        || frame.len() != Q6PD_ANNOUNCE_HEADER_BYTES + record_len
        || frame.get(Q6PD_ANNOUNCE_HEADER_BYTES..Q6PD_ANNOUNCE_HEADER_BYTES + 4)
            != Some(&Q6PD_MAGIC)
    {
        return Err(Q6pdError::Malformed);
    }
    Ok(&frame[Q6PD_ANNOUNCE_HEADER_BYTES..])
}

/// A short authenticated acknowledgement; status zero means the signed record was persisted.
pub fn encode_q6pd_announce_response(accepted: bool) -> [u8; Q6PD_ANNOUNCE_RESPONSE_BYTES] {
    let mut out = [0u8; Q6PD_ANNOUNCE_RESPONSE_BYTES];
    out[..4].copy_from_slice(&Q6PD_ANNOUNCE_RESPONSE_MAGIC);
    out[4..6].copy_from_slice(&Q6PD_ANNOUNCE_VERSION.to_be_bytes());
    out[6] = u8::from(!accepted);
    out
}

pub fn decode_q6pd_announce_response(frame: &[u8]) -> Result<(), Q6pdError> {
    if frame.len() != Q6PD_ANNOUNCE_RESPONSE_BYTES
        || frame.get(..4) != Some(&Q6PD_ANNOUNCE_RESPONSE_MAGIC)
        || u16::from_be_bytes([frame[4], frame[5]]) != Q6PD_ANNOUNCE_VERSION
        || frame[6] != 0
    {
        return Err(Q6pdError::Malformed);
    }
    Ok(())
}

/// Bounded Q6PD peer-record pull exchange carried inside an authenticated Noise session.
pub const Q6PD_PULL_REQUEST_MAGIC: [u8; 4] = *b"Q6PG";
pub const Q6PD_PULL_RESPONSE_MAGIC: [u8; 4] = *b"Q6PS";
pub const Q6PD_PULL_VERSION: u16 = 1;
pub const Q6PD_PULL_REQUEST_BYTES: usize = 80;
pub const Q6PD_PULL_RESPONSE_HEADER_BYTES: usize = 80;
pub const Q6PD_MAX_RECORDS_PER_FRAME: usize = 16;
pub const Q6PD_MAX_PULL_FRAME_BYTES: usize =
    Q6PD_PULL_RESPONSE_HEADER_BYTES + Q6PD_MAX_RECORDS_PER_FRAME * (2 + Q6PD_MAX_RECORD_BYTES);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Q6pdPullRequest {
    pub request_id: u64,
    pub network_id: [u8; 32],
    pub profile_id: [u8; 32],
    pub max_records: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Q6pdPullResponse {
    pub request_id: u64,
    pub network_id: [u8; 32],
    pub profile_id: [u8; 32],
    pub records: Vec<VerifiedQ6pdPeerRecord>,
    /// Original signed wire records, retained for replay-aware durable ingestion.
    pub record_wires: Vec<Vec<u8>>,
}

fn validate_pull_request(request: &Q6pdPullRequest) -> Result<(), Q6pdError> {
    if request.request_id == 0
        || request.network_id == [0; 32]
        || request.profile_id == [0; 32]
        || request.max_records == 0
        || request.max_records as usize > Q6PD_MAX_RECORDS_PER_FRAME
    {
        return Err(Q6pdError::Malformed);
    }
    Ok(())
}

pub fn encode_q6pd_pull_request(request: &Q6pdPullRequest) -> Result<Vec<u8>, Q6pdError> {
    validate_pull_request(request)?;
    let mut out = Vec::with_capacity(Q6PD_PULL_REQUEST_BYTES);
    out.extend_from_slice(&Q6PD_PULL_REQUEST_MAGIC);
    out.extend_from_slice(&Q6PD_PULL_VERSION.to_be_bytes());
    out.extend_from_slice(&request.network_id);
    out.extend_from_slice(&request.profile_id);
    out.extend_from_slice(&request.request_id.to_be_bytes());
    out.extend_from_slice(&request.max_records.to_be_bytes());
    Ok(out)
}

pub fn decode_q6pd_pull_request(
    bytes: &[u8],
    expected_network_id: &[u8; 32],
    expected_profile_id: &[u8; 32],
) -> Result<Q6pdPullRequest, Q6pdError> {
    if bytes.len() != Q6PD_PULL_REQUEST_BYTES || bytes[..4] != Q6PD_PULL_REQUEST_MAGIC {
        return Err(Q6pdError::Malformed);
    }
    if u16::from_be_bytes(bytes[4..6].try_into().map_err(|_| Q6pdError::Malformed)?)
        != Q6PD_PULL_VERSION
    {
        return Err(Q6pdError::UnsupportedVersion);
    }
    let network_id: [u8; 32] = bytes[6..38].try_into().map_err(|_| Q6pdError::Malformed)?;
    let profile_id: [u8; 32] = bytes[38..70].try_into().map_err(|_| Q6pdError::Malformed)?;
    if &network_id != expected_network_id {
        return Err(Q6pdError::WrongNetwork);
    }
    if &profile_id != expected_profile_id {
        return Err(Q6pdError::WrongProfile);
    }
    let request = Q6pdPullRequest {
        request_id: u64::from_be_bytes(bytes[70..78].try_into().map_err(|_| Q6pdError::Malformed)?),
        network_id,
        profile_id,
        max_records: u16::from_be_bytes(
            bytes[78..80].try_into().map_err(|_| Q6pdError::Malformed)?,
        ),
    };
    validate_pull_request(&request)?;
    Ok(request)
}

/// Encode a response containing only independently valid, signed peer records. Records are
/// canonically ordered by peer ID; duplicates and oversized inventories are rejected.
pub fn encode_q6pd_pull_response(
    request: &Q6pdPullRequest,
    records: &[Vec<u8>],
    now_secs: u64,
) -> Result<Vec<u8>, Q6pdError> {
    validate_pull_request(request)?;
    if records.len() > request.max_records as usize {
        return Err(Q6pdError::Malformed);
    }
    let mut verified = Vec::with_capacity(records.len());
    for wire in records {
        let record =
            verify_q6pd_peer_record(wire, &request.network_id, &request.profile_id, now_secs)?;
        verified.push((record.peer_id, wire));
    }
    verified.sort_by_key(|(peer_id, _)| *peer_id);
    for pair in verified.windows(2) {
        if pair[0].0 == pair[1].0 {
            return Err(Q6pdError::InvalidPeerId);
        }
    }

    let mut out = Vec::with_capacity(Q6PD_PULL_RESPONSE_HEADER_BYTES);
    out.extend_from_slice(&Q6PD_PULL_RESPONSE_MAGIC);
    out.extend_from_slice(&Q6PD_PULL_VERSION.to_be_bytes());
    out.extend_from_slice(&request.network_id);
    out.extend_from_slice(&request.profile_id);
    out.extend_from_slice(&request.request_id.to_be_bytes());
    out.extend_from_slice(&(verified.len() as u16).to_be_bytes());
    for (_, wire) in verified {
        let len: u16 = wire.len().try_into().map_err(|_| Q6pdError::Malformed)?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(wire);
    }
    if out.len() > Q6PD_MAX_PULL_FRAME_BYTES {
        return Err(Q6pdError::Malformed);
    }
    Ok(out)
}

/// Verify request correlation and every signed record in a bounded response. The caller
/// must still apply its persistent per-peer sequence watermark before retaining a record.
pub fn decode_q6pd_pull_response(
    bytes: &[u8],
    request: &Q6pdPullRequest,
    now_secs: u64,
) -> Result<Q6pdPullResponse, Q6pdError> {
    validate_pull_request(request)?;
    if bytes.len() < Q6PD_PULL_RESPONSE_HEADER_BYTES
        || bytes.len() > Q6PD_MAX_PULL_FRAME_BYTES
        || bytes[..4] != Q6PD_PULL_RESPONSE_MAGIC
    {
        return Err(Q6pdError::Malformed);
    }
    if u16::from_be_bytes(bytes[4..6].try_into().map_err(|_| Q6pdError::Malformed)?)
        != Q6PD_PULL_VERSION
    {
        return Err(Q6pdError::UnsupportedVersion);
    }
    let network_id: [u8; 32] = bytes[6..38].try_into().map_err(|_| Q6pdError::Malformed)?;
    let profile_id: [u8; 32] = bytes[38..70].try_into().map_err(|_| Q6pdError::Malformed)?;
    let request_id =
        u64::from_be_bytes(bytes[70..78].try_into().map_err(|_| Q6pdError::Malformed)?);
    let count =
        u16::from_be_bytes(bytes[78..80].try_into().map_err(|_| Q6pdError::Malformed)?) as usize;
    if network_id != request.network_id
        || profile_id != request.profile_id
        || request_id != request.request_id
        || count > request.max_records as usize
        || count > Q6PD_MAX_RECORDS_PER_FRAME
    {
        return Err(Q6pdError::Malformed);
    }

    let mut cursor = Q6PD_PULL_RESPONSE_HEADER_BYTES;
    let mut records = Vec::with_capacity(count);
    let mut record_wires = Vec::with_capacity(count);
    let mut previous_peer_id: Option<[u8; 32]> = None;
    for _ in 0..count {
        let len = u16::from_be_bytes(
            bytes
                .get(cursor..cursor + 2)
                .ok_or(Q6pdError::Malformed)?
                .try_into()
                .map_err(|_| Q6pdError::Malformed)?,
        ) as usize;
        cursor += 2;
        if !(Q6PD_MIN_RECORD_BYTES..=Q6PD_MAX_RECORD_BYTES).contains(&len) {
            return Err(Q6pdError::Malformed);
        }
        let end = cursor.checked_add(len).ok_or(Q6pdError::Malformed)?;
        let wire = bytes.get(cursor..end).ok_or(Q6pdError::Malformed)?;
        let record = verify_q6pd_peer_record(wire, &network_id, &profile_id, now_secs)?;
        if previous_peer_id.is_some_and(|previous| previous >= record.peer_id) {
            return Err(Q6pdError::InvalidPeerId);
        }
        previous_peer_id = Some(record.peer_id);
        records.push(record);
        record_wires.push(wire.to_vec());
        cursor = end;
    }
    if cursor != bytes.len() {
        return Err(Q6pdError::Malformed);
    }
    Ok(Q6pdPullResponse {
        request_id,
        network_id,
        profile_id,
        records,
        record_wires,
    })
}

/// Bidirectional inventory gossip: send a bounded batch of independently signed peer
/// records to the connected peer. The receiver validates every record and applies its own
/// persistent per-peer sequence watermarks before returning the acknowledgement.
pub const Q6PD_GOSSIP_PUSH_REQUEST_MAGIC: [u8; 4] = *b"Q6PX";
pub const Q6PD_GOSSIP_PUSH_RESPONSE_MAGIC: [u8; 4] = *b"Q6PY";
pub const Q6PD_GOSSIP_PUSH_VERSION: u16 = 1;
pub const Q6PD_GOSSIP_PUSH_HEADER_BYTES: usize = 80;
pub const Q6PD_GOSSIP_PUSH_ACK_BYTES: usize = 88;
pub const Q6PD_MAX_GOSSIP_PUSH_FRAME_BYTES: usize =
    Q6PD_GOSSIP_PUSH_HEADER_BYTES + Q6PD_MAX_RECORDS_PER_FRAME * (2 + Q6PD_MAX_RECORD_BYTES);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Q6pdGossipPushRequest {
    pub request_id: u64,
    pub network_id: [u8; 32],
    pub profile_id: [u8; 32],
    pub records: Vec<VerifiedQ6pdPeerRecord>,
    pub record_wires: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Q6pdGossipPushCounts {
    pub inserted: u16,
    pub updated: u16,
    pub duplicate: u16,
    pub rejected: u16,
}

pub fn encode_q6pd_gossip_push_request(
    request_id: u64,
    network_id: &[u8; 32],
    profile_id: &[u8; 32],
    record_wires: &[Vec<u8>],
    now_secs: u64,
) -> Result<Vec<u8>, Q6pdError> {
    if request_id == 0
        || *network_id == [0; 32]
        || *profile_id == [0; 32]
        || record_wires.len() > Q6PD_MAX_RECORDS_PER_FRAME
    {
        return Err(Q6pdError::Malformed);
    }
    let mut verified = Vec::with_capacity(record_wires.len());
    for wire in record_wires {
        let record = verify_q6pd_peer_record(wire, network_id, profile_id, now_secs)?;
        verified.push((record.peer_id, wire));
    }
    verified.sort_by_key(|(peer_id, _)| *peer_id);
    for pair in verified.windows(2) {
        if pair[0].0 == pair[1].0 {
            return Err(Q6pdError::InvalidPeerId);
        }
    }

    let mut out = Vec::with_capacity(Q6PD_MAX_GOSSIP_PUSH_FRAME_BYTES);
    out.extend_from_slice(&Q6PD_GOSSIP_PUSH_REQUEST_MAGIC);
    out.extend_from_slice(&Q6PD_GOSSIP_PUSH_VERSION.to_be_bytes());
    out.extend_from_slice(network_id);
    out.extend_from_slice(profile_id);
    out.extend_from_slice(&request_id.to_be_bytes());
    out.extend_from_slice(&(verified.len() as u16).to_be_bytes());
    for (_, wire) in verified {
        let len: u16 = wire.len().try_into().map_err(|_| Q6pdError::Malformed)?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(wire);
    }
    if out.len() > Q6PD_MAX_GOSSIP_PUSH_FRAME_BYTES {
        return Err(Q6pdError::Malformed);
    }
    Ok(out)
}

pub fn decode_q6pd_gossip_push_request(
    bytes: &[u8],
    expected_network_id: &[u8; 32],
    expected_profile_id: &[u8; 32],
    now_secs: u64,
) -> Result<Q6pdGossipPushRequest, Q6pdError> {
    if bytes.len() < Q6PD_GOSSIP_PUSH_HEADER_BYTES
        || bytes.len() > Q6PD_MAX_GOSSIP_PUSH_FRAME_BYTES
        || bytes.get(..4) != Some(&Q6PD_GOSSIP_PUSH_REQUEST_MAGIC)
    {
        return Err(Q6pdError::Malformed);
    }
    if u16::from_be_bytes([bytes[4], bytes[5]]) != Q6PD_GOSSIP_PUSH_VERSION {
        return Err(Q6pdError::UnsupportedVersion);
    }
    let network_id: [u8; 32] = bytes[6..38].try_into().map_err(|_| Q6pdError::Malformed)?;
    let profile_id: [u8; 32] = bytes[38..70].try_into().map_err(|_| Q6pdError::Malformed)?;
    if &network_id != expected_network_id {
        return Err(Q6pdError::WrongNetwork);
    }
    if &profile_id != expected_profile_id {
        return Err(Q6pdError::WrongProfile);
    }
    let request_id =
        u64::from_be_bytes(bytes[70..78].try_into().map_err(|_| Q6pdError::Malformed)?);
    let count =
        u16::from_be_bytes(bytes[78..80].try_into().map_err(|_| Q6pdError::Malformed)?) as usize;
    if request_id == 0 || count > Q6PD_MAX_RECORDS_PER_FRAME {
        return Err(Q6pdError::Malformed);
    }

    let mut cursor = Q6PD_GOSSIP_PUSH_HEADER_BYTES;
    let mut records = Vec::with_capacity(count);
    let mut record_wires = Vec::with_capacity(count);
    let mut previous_peer_id: Option<[u8; 32]> = None;
    for _ in 0..count {
        let len = u16::from_be_bytes(
            bytes
                .get(cursor..cursor + 2)
                .ok_or(Q6pdError::Malformed)?
                .try_into()
                .map_err(|_| Q6pdError::Malformed)?,
        ) as usize;
        cursor += 2;
        if !(Q6PD_MIN_RECORD_BYTES..=Q6PD_MAX_RECORD_BYTES).contains(&len) {
            return Err(Q6pdError::Malformed);
        }
        let end = cursor.checked_add(len).ok_or(Q6pdError::Malformed)?;
        let wire = bytes.get(cursor..end).ok_or(Q6pdError::Malformed)?;
        let record = verify_q6pd_peer_record(wire, &network_id, &profile_id, now_secs)?;
        if previous_peer_id.is_some_and(|previous| previous >= record.peer_id) {
            return Err(Q6pdError::InvalidPeerId);
        }
        previous_peer_id = Some(record.peer_id);
        records.push(record);
        record_wires.push(wire.to_vec());
        cursor = end;
    }
    if cursor != bytes.len() {
        return Err(Q6pdError::Malformed);
    }
    Ok(Q6pdGossipPushRequest {
        request_id,
        network_id,
        profile_id,
        records,
        record_wires,
    })
}

pub fn encode_q6pd_gossip_push_response(
    request: &Q6pdGossipPushRequest,
    counts: Q6pdGossipPushCounts,
) -> [u8; Q6PD_GOSSIP_PUSH_ACK_BYTES] {
    let mut out = [0u8; Q6PD_GOSSIP_PUSH_ACK_BYTES];
    out[..4].copy_from_slice(&Q6PD_GOSSIP_PUSH_RESPONSE_MAGIC);
    out[4..6].copy_from_slice(&Q6PD_GOSSIP_PUSH_VERSION.to_be_bytes());
    out[6..38].copy_from_slice(&request.network_id);
    out[38..70].copy_from_slice(&request.profile_id);
    out[70..78].copy_from_slice(&request.request_id.to_be_bytes());
    out[78..80].copy_from_slice(&(request.records.len() as u16).to_be_bytes());
    out[80..82].copy_from_slice(&counts.inserted.to_be_bytes());
    out[82..84].copy_from_slice(&counts.updated.to_be_bytes());
    out[84..86].copy_from_slice(&counts.duplicate.to_be_bytes());
    out[86..88].copy_from_slice(&counts.rejected.to_be_bytes());
    out
}

pub fn decode_q6pd_gossip_push_response(
    bytes: &[u8],
    request: &Q6pdGossipPushRequest,
) -> Result<Q6pdGossipPushCounts, Q6pdError> {
    if bytes.len() != Q6PD_GOSSIP_PUSH_ACK_BYTES
        || bytes.get(..4) != Some(&Q6PD_GOSSIP_PUSH_RESPONSE_MAGIC)
        || u16::from_be_bytes([bytes[4], bytes[5]]) != Q6PD_GOSSIP_PUSH_VERSION
        || bytes[6..38] != request.network_id
        || bytes[38..70] != request.profile_id
        || u64::from_be_bytes(bytes[70..78].try_into().map_err(|_| Q6pdError::Malformed)?)
            != request.request_id
        || u16::from_be_bytes([bytes[78], bytes[79]]) as usize != request.records.len()
    {
        return Err(Q6pdError::Malformed);
    }
    let counts = Q6pdGossipPushCounts {
        inserted: u16::from_be_bytes([bytes[80], bytes[81]]),
        updated: u16::from_be_bytes([bytes[82], bytes[83]]),
        duplicate: u16::from_be_bytes([bytes[84], bytes[85]]),
        rejected: u16::from_be_bytes([bytes[86], bytes[87]]),
    };
    let total = counts.inserted as usize
        + counts.updated as usize
        + counts.duplicate as usize
        + counts.rejected as usize;
    if total != request.records.len() {
        return Err(Q6pdError::Malformed);
    }
    Ok(counts)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NETWORK: [u8; 32] = [0x31; 32];
    const PROFILE: [u8; 32] = [0x42; 32];

    fn signed_record() -> (Vec<u8>, SigningKey) {
        let identity = SigningKey::from_bytes(&[0x53; 32]);
        let noise = [0x64; 32];
        let endpoint = "8.8.8.8:30336".parse().unwrap();
        let wire =
            sign_q6pd_peer_record(NETWORK, PROFILE, noise, endpoint, 7, 1_000, 600, &identity)
                .unwrap();
        (wire, identity)
    }

    #[test]
    fn signed_record_round_trips_and_binds_noise_key_and_endpoint() {
        let (wire, identity) = signed_record();
        let decoded = verify_q6pd_peer_record(&wire, &NETWORK, &PROFILE, 1_100).unwrap();
        assert_eq!(
            decoded.peer_id,
            q6pd_peer_id_for_identity_public_key(&identity.verifying_key().to_bytes())
        );
        assert_eq!(decoded.noise_static_public_key, [0x64; 32]);
        assert_eq!(decoded.endpoint, "8.8.8.8:30336".parse().unwrap());
        assert_eq!(decoded.sequence, 7);
    }

    #[test]
    fn signed_record_rejects_wrong_network_and_profile() {
        let (wire, _) = signed_record();
        assert_eq!(
            verify_q6pd_peer_record(&wire, &[0x99; 32], &PROFILE, 1_100),
            Err(Q6pdError::WrongNetwork)
        );
        assert_eq!(
            verify_q6pd_peer_record(&wire, &NETWORK, &[0x98; 32], 1_100),
            Err(Q6pdError::WrongProfile)
        );
    }

    #[test]
    fn signed_record_rejects_tampering_and_expiry() {
        let (wire, _) = signed_record();
        let mut tampered = wire.clone();
        tampered[168] ^= 0x01;
        assert_eq!(
            verify_q6pd_peer_record(&tampered, &NETWORK, &PROFILE, 1_100),
            Err(Q6pdError::InvalidSignature)
        );
        assert_eq!(
            verify_q6pd_peer_record(&wire, &NETWORK, &PROFILE, 1_601),
            Err(Q6pdError::Expired)
        );
    }

    #[test]
    fn signed_record_rejects_non_public_endpoint_and_invalid_ttl() {
        let identity = SigningKey::from_bytes(&[0x53; 32]);
        assert_eq!(
            sign_q6pd_peer_record(
                NETWORK,
                PROFILE,
                [0x64; 32],
                "127.0.0.1:30336".parse().unwrap(),
                1,
                1_000,
                600,
                &identity
            ),
            Err(Q6pdError::InvalidEndpoint)
        );
        assert_eq!(
            sign_q6pd_peer_record(
                NETWORK,
                PROFILE,
                [0x64; 32],
                "8.8.8.8:30336".parse().unwrap(),
                1,
                1_000,
                Q6PD_MAX_TTL_SECS + 1,
                &identity
            ),
            Err(Q6pdError::InvalidTimestamp)
        );
    }

    #[test]
    fn signed_record_rejects_future_timestamp_and_malformed_length() {
        let (wire, _) = signed_record();
        assert_eq!(
            verify_q6pd_peer_record(&wire, &NETWORK, &PROFILE, 500),
            Err(Q6pdError::InvalidTimestamp)
        );
        assert_eq!(
            verify_q6pd_peer_record(&wire[..wire.len() - 1], &NETWORK, &PROFILE, 1_100),
            Err(Q6pdError::Malformed)
        );
    }

    #[test]
    fn q6pd_pull_request_round_trips_and_binds_network_profile() {
        let request = Q6pdPullRequest {
            request_id: 9,
            network_id: NETWORK,
            profile_id: PROFILE,
            max_records: 8,
        };
        let frame = encode_q6pd_pull_request(&request).unwrap();
        assert_eq!(frame.len(), Q6PD_PULL_REQUEST_BYTES);
        assert_eq!(
            decode_q6pd_pull_request(&frame, &NETWORK, &PROFILE).unwrap(),
            request
        );
        assert_eq!(
            decode_q6pd_pull_request(&frame, &[0x99; 32], &PROFILE),
            Err(Q6pdError::WrongNetwork)
        );
    }

    #[test]
    fn q6pd_pull_response_round_trips_verified_records() {
        let (wire, _) = signed_record();
        let request = Q6pdPullRequest {
            request_id: 10,
            network_id: NETWORK,
            profile_id: PROFILE,
            max_records: 4,
        };
        let frame = encode_q6pd_pull_response(&request, &[wire], 1_100).unwrap();
        let response = decode_q6pd_pull_response(&frame, &request, 1_100).unwrap();
        assert_eq!(response.request_id, 10);
        assert_eq!(response.records.len(), 1);
        assert_eq!(response.records[0].sequence, 7);
    }

    #[test]
    fn q6pd_pull_response_rejects_request_mismatch_and_tampering() {
        let (wire, _) = signed_record();
        let request = Q6pdPullRequest {
            request_id: 11,
            network_id: NETWORK,
            profile_id: PROFILE,
            max_records: 4,
        };
        let frame = encode_q6pd_pull_response(&request, &[wire], 1_100).unwrap();
        let wrong_request = Q6pdPullRequest {
            request_id: 12,
            ..request.clone()
        };
        assert_eq!(
            decode_q6pd_pull_response(&frame, &wrong_request, 1_100),
            Err(Q6pdError::Malformed)
        );
        let mut tampered = frame;
        tampered[Q6PD_PULL_RESPONSE_HEADER_BYTES + 2 + 168] ^= 1;
        assert_eq!(
            decode_q6pd_pull_response(&tampered, &request, 1_100),
            Err(Q6pdError::InvalidSignature)
        );
    }

    #[test]
    fn q6pd_gossip_push_round_trips_signed_records_and_ack_counts() {
        let (wire, _) = signed_record();
        let frame =
            encode_q6pd_gossip_push_request(77, &NETWORK, &PROFILE, &[wire], 1_100).unwrap();
        let request = decode_q6pd_gossip_push_request(&frame, &NETWORK, &PROFILE, 1_100).unwrap();
        assert_eq!(request.request_id, 77);
        assert_eq!(request.records.len(), 1);
        assert_eq!(request.records[0].sequence, 7);
        let ack = encode_q6pd_gossip_push_response(
            &request,
            Q6pdGossipPushCounts {
                inserted: 1,
                updated: 0,
                duplicate: 0,
                rejected: 0,
            },
        );
        assert_eq!(
            decode_q6pd_gossip_push_response(&ack, &request).unwrap(),
            Q6pdGossipPushCounts {
                inserted: 1,
                updated: 0,
                duplicate: 0,
                rejected: 0,
            }
        );
        let mut tampered = frame;
        tampered[Q6PD_GOSSIP_PUSH_HEADER_BYTES + 2 + 168] ^= 1;
        assert_eq!(
            decode_q6pd_gossip_push_request(&tampered, &NETWORK, &PROFILE, 1_100),
            Err(Q6pdError::InvalidSignature)
        );
    }
}
