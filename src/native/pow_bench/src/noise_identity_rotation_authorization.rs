//! Mandatory dual-attestation verification for QFP6 peer identity rotation.
//! Signatures cover a deterministic, versioned, length-delimited intent encoding.
use ed25519_dalek::{Signature, VerifyingKey};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;

const DOMAIN: &[u8] = b"QFP6-NOISE-ROTATION-INTENT\0v2";
struct UniqueJson(Value);

impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = UniqueJson;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("JSON without duplicate object keys")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> {
                Ok(UniqueJson(Value::Bool(v)))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
                Ok(UniqueJson(Value::Number(v.into())))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(UniqueJson(Value::Number(v.into())))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Self::Value, E> {
                let n = serde_json::Number::from_f64(v)
                    .ok_or_else(|| E::custom("non-finite JSON number"))?;
                Ok(UniqueJson(Value::Number(n)))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(UniqueJson(Value::String(v.to_owned())))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(UniqueJson(Value::String(v)))
            }
            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueJson(Value::Null))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueJson(Value::Null))
            }
            fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
                UniqueJson::deserialize(d)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = seq.next_element::<UniqueJson>()? {
                    values.push(value.0);
                }
                Ok(UniqueJson(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some((key, value)) = map.next_entry::<String, UniqueJson>()? {
                    if values.contains_key(&key) {
                        return Err(de::Error::custom(format!(
                            "duplicate JSON object key: {key}"
                        )));
                    }
                    values.insert(key, value.0);
                }
                Ok(UniqueJson(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(UniqueVisitor)
    }
}

fn parse_unique_json(bytes: &[u8], label: &'static str) -> Result<Value, String> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = UniqueJson::deserialize(&mut deserializer)
        .map_err(|_| format!("{label} JSON invalid or contains duplicate keys"))?;
    deserializer
        .end()
        .map_err(|_| format!("{label} JSON has trailing data"))?;
    Ok(value.0)
}
const MAX_AUTH: usize = 64 * 1024;

fn field<'a>(v: &'a Value, key: &str) -> Result<&'a str, String> {
    v.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| format!("authorization intent field {key} is required"))
}
fn number(v: &Value, key: &str) -> Result<u64, String> {
    v.get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("authorization intent field {key} must be an unsigned integer"))
}
pub(super) fn sha(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn hex32(s: &str, label: &str) -> Result<[u8; 32], String> {
    if s.len() != 64 || !s.is_ascii() || s.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(format!(
            "{label} must be 64 lowercase hexadecimal characters"
        ));
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|_| format!("{label} is invalid hexadecimal"))?;
    }
    if out == [0; 32] {
        return Err(format!("{label} must not be zero"));
    }
    Ok(out)
}
fn push_field(out: &mut Vec<u8>, name: &str, value: &[u8]) -> Result<(), String> {
    let nl = u32::try_from(name.len()).map_err(|_| "intent field name too long")?;
    let vl = u32::try_from(value.len()).map_err(|_| "intent field value too long")?;
    out.extend_from_slice(&nl.to_be_bytes());
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&vl.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}
pub(super) fn canonical_intent(intent: &Value) -> Result<Vec<u8>, String> {
    let mut out = DOMAIN.to_vec();
    // Fixed field order is part of the v2 wire contract; no JSON reserialization is signed.
    for name in [
        "manifest_sha256",
        "prepared_identity_sha256",
        "dpc1_sha256",
        "irg1_sha256",
        "previous_npi1_sha256",
        "network_id_hex",
        "profile_id_hex",
        "issuer_id",
        "previous_generation",
        "new_generation",
        "peer_not_before_unix",
        "peer_not_after_unix",
        "role",
        "generation_name",
        "new_identity_sha256",
        "previous_identity_sha256",
        "previous_public_key_sha256_fingerprint",
        "new_public_key_sha256_fingerprint",
        "endpoint",
        "endpoint_evidence_sha256",
        "fingerprint_evidence_sha256",
        "policy_sha256",
        "operator_id",
        "owner_authorization_id",
        "activation_scope",
        "overlap_policy_id",
        "rollback_window_seconds",
        "issued_at_unix",
        "expires_at_unix",
        "nonce",
    ] {
        let value = match name {
            "issuer_id"
            | "previous_generation"
            | "new_generation"
            | "peer_not_before_unix"
            | "peer_not_after_unix"
            | "rollback_window_seconds"
            | "issued_at_unix"
            | "expires_at_unix" => number(intent, name)?.to_string(),
            _ => field(intent, name)?.to_owned(),
        };
        push_field(&mut out, name, value.as_bytes())?;
    }
    Ok(out)
}

/// Successful output from the dual-attestation verifier. Pin fingerprints are hashes of the
/// exact public keys whose signatures were verified; pin provenance remains an external trust input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDualAttestation {
    pub intent_digest: [u8; 32],
    pub profile_id: [u8; 32],
    pub nonce: [u8; 32],
    pub owner_pin_fingerprint: [u8; 32],
    pub operator_pin_fingerprint: [u8; 32],
}

/// Verify both independent signatures and bind the authorization to the exact local inputs.
#[allow(clippy::too_many_arguments)]
pub fn verify_dual_attestation(
    manifest_bytes: &[u8],
    prepared_identity_bytes: &[u8],
    prepared_previous_identity_bytes: &[u8],
    endpoint_evidence_bytes: &[u8],
    fingerprint_evidence_bytes: &[u8],
    policy_bytes: &[u8],
    authorization_bytes: &[u8],
    operator_public: &[u8],
    operator_pin: &str,
    operator_signature: &[u8],
    owner_public: &[u8],
    owner_pin: &str,
    owner_signature: &[u8],
    dpc1: &[u8],
    irg1: &[u8],
    previous_npi1: &[u8],
    network_id: &[u8; 32],
    issuer_id: u32,
    previous_generation: u64,
    new_generation: u64,
    new_noise_public: &[u8; 32],
    previous_noise_public: &[u8; 32],
    peer_not_before_unix: u64,
    peer_not_after_unix: u64,
    now: u64,
) -> Result<VerifiedDualAttestation, String> {
    if manifest_bytes.is_empty()
        || manifest_bytes.len() > MAX_AUTH
        || prepared_identity_bytes.is_empty()
        || prepared_identity_bytes.len() > MAX_AUTH
        || prepared_previous_identity_bytes.is_empty()
        || prepared_previous_identity_bytes.len() > MAX_AUTH
        || endpoint_evidence_bytes.is_empty()
        || endpoint_evidence_bytes.len() > MAX_AUTH
        || fingerprint_evidence_bytes.is_empty()
        || fingerprint_evidence_bytes.len() > MAX_AUTH
        || policy_bytes.is_empty()
        || policy_bytes.len() > MAX_AUTH
        || authorization_bytes.is_empty()
        || authorization_bytes.len() > MAX_AUTH
    {
        return Err("manifest, prepared identity, or authorization size is invalid".into());
    }
    if peer_not_before_unix > peer_not_after_unix {
        return Err("NPI1 validity window is inverted".into());
    }
    if operator_public.len() != 32
        || owner_public.len() != 32
        || operator_signature.len() != 64
        || owner_signature.len() != 64
    {
        return Err("operator/owner public keys must be 32 bytes and signatures 64 bytes".into());
    }
    let operator_fp = sha(operator_public);
    let owner_fp = sha(owner_public);
    if hex(&operator_fp) != operator_pin || hex(&owner_fp) != owner_pin {
        return Err("independent signer public-key pin mismatch".into());
    }
    if operator_fp == owner_fp {
        return Err("owner and independent operator keys must be distinct".into());
    }
    let operator_key = VerifyingKey::from_bytes(
        operator_public
            .try_into()
            .map_err(|_| "operator key length")?,
    )
    .map_err(|_| "operator public key invalid")?;
    let owner_key =
        VerifyingKey::from_bytes(owner_public.try_into().map_err(|_| "owner key length")?)
            .map_err(|_| "owner public key invalid")?;
    let op_sig =
        Signature::from_slice(operator_signature).map_err(|_| "operator signature malformed")?;
    let own_sig =
        Signature::from_slice(owner_signature).map_err(|_| "owner signature malformed")?;

    let manifest = parse_unique_json(manifest_bytes, "rotation manifest")?;
    let prepared = parse_unique_json(prepared_identity_bytes, "prepared identity")?;
    let prepared_previous = parse_unique_json(
        prepared_previous_identity_bytes,
        "prepared previous identity",
    )?;
    let auth = parse_unique_json(authorization_bytes, "dual authorization")?;
    if field(&auth, "schema")? != "qfp6-noise-identity-rotation-authorization/v3" {
        return Err("unsupported dual authorization schema".into());
    }
    let intent = auth
        .get("intent")
        .ok_or("authorization intent is missing")?;
    if field(&manifest, "schema")? != "qfp6-noise-identity-rotation-preparation/v1"
        || field(&manifest, "status")? != "PREPARED_NOT_ACTIVATED"
    {
        return Err("manifest is not a supported prepared, inactive rotation".into());
    }
    for flag in [
        "activation_authorized",
        "active_identity_modified",
        "active_protected_key_modified",
        "node_started",
        "listener_opened",
    ] {
        if manifest.get(flag).and_then(Value::as_bool) != Some(false) {
            return Err(format!("manifest safety flag {flag} is not false"));
        }
    }
    let expected = [
        ("manifest_sha256", hex(&sha(manifest_bytes))),
        (
            "prepared_identity_sha256",
            hex(&sha(prepared_identity_bytes)),
        ),
        ("dpc1_sha256", hex(&sha(dpc1))),
        ("irg1_sha256", hex(&sha(irg1))),
        ("previous_npi1_sha256", hex(&sha(previous_npi1))),
        (
            "previous_identity_sha256",
            hex(&sha(prepared_previous_identity_bytes)),
        ),
        (
            "endpoint_evidence_sha256",
            hex(&sha(endpoint_evidence_bytes)),
        ),
        (
            "fingerprint_evidence_sha256",
            hex(&sha(fingerprint_evidence_bytes)),
        ),
        ("policy_sha256", hex(&sha(policy_bytes))),
        ("network_id_hex", hex(network_id)),
        ("issuer_id", issuer_id.to_string()),
        ("previous_generation", previous_generation.to_string()),
        ("new_generation", new_generation.to_string()),
        ("peer_not_before_unix", peer_not_before_unix.to_string()),
        ("peer_not_after_unix", peer_not_after_unix.to_string()),
        (
            "new_public_key_sha256_fingerprint",
            hex(&sha(new_noise_public)),
        ),
    ];
    for (key, value) in expected {
        let actual = match key {
            "issuer_id"
            | "previous_generation"
            | "new_generation"
            | "peer_not_before_unix"
            | "peer_not_after_unix" => number(intent, key)?.to_string(),
            _ => field(intent, key)?.to_owned(),
        };
        if actual != value {
            return Err(format!("authorization intent does not bind actual {key}"));
        }
    }
    for key in [
        "role",
        "generation_name",
        "new_identity_sha256",
        "previous_identity_sha256",
        "previous_public_key_sha256_fingerprint",
        "new_public_key_sha256_fingerprint",
        "network_id_hex",
        "profile_id_hex",
    ] {
        if field(intent, key).is_ok()
            && field(&manifest, key).is_ok()
            && field(intent, key)? != field(&manifest, key)?
        {
            return Err(format!(
                "authorization intent does not match manifest field {key}"
            ));
        }
    }
    if field(&manifest, "new_identity_sha256")? != hex(&sha(prepared_identity_bytes)) {
        return Err("prepared identity bytes do not match manifest hash".into());
    }
    let role = field(&manifest, "role")?;
    if field(&prepared, "role")? != role {
        return Err("prepared identity role differs from manifest".into());
    }
    let prepared_network = prepared
        .get("network_id_hex")
        .and_then(Value::as_str)
        .or_else(|| prepared.get("network_id").and_then(Value::as_str))
        .ok_or("prepared identity network ID missing")?;
    if prepared_network != field(&manifest, "network_id_hex")? {
        return Err("prepared identity network differs from manifest".into());
    }
    let public_hex = if role == "seed" {
        field(&prepared, "noise_static_public_key_hex")?
    } else {
        field(&prepared, "public_static_key")?
    };
    if public_hex != field(&manifest, "new_public_key_hex")?
        || hex(&sha(new_noise_public)) != field(&manifest, "new_public_key_sha256_fingerprint")?
    {
        return Err(
            "prepared identity public key does not match the requested new Noise key".into(),
        );
    }
    if field(&prepared_previous, "role")? != role
        || field(&prepared_previous, "network_id_hex")
            .or_else(|_| field(&prepared_previous, "network_id"))?
            != field(&manifest, "network_id_hex")?
    {
        return Err(
            "prepared previous identity role/network differs from rotation manifest".into(),
        );
    }
    let previous_public_hex = if role == "seed" {
        field(&prepared_previous, "noise_static_public_key_hex")?
    } else {
        field(&prepared_previous, "public_static_key")?
    };
    let previous_public = hex32(previous_public_hex, "prepared previous Noise public key")?;
    if previous_public != *previous_noise_public
        || hex(&sha(&previous_public))
            != field(&manifest, "previous_public_key_sha256_fingerprint")?
    {
        return Err(
            "prepared previous identity public key fingerprint differs from manifest".into(),
        );
    }
    let current_profile = prepared
        .get("profile_id_hex")
        .and_then(Value::as_str)
        .or_else(|| prepared.get("profile_id").and_then(Value::as_str))
        .ok_or("prepared identity profile ID missing")?;
    let previous_profile = prepared_previous
        .get("profile_id_hex")
        .and_then(Value::as_str)
        .or_else(|| prepared_previous.get("profile_id").and_then(Value::as_str))
        .ok_or("prepared previous identity profile ID missing")?;
    if current_profile != field(&manifest, "profile_id_hex")? || previous_profile != current_profile
    {
        return Err("prepared identity profile binding mismatch".into());
    }
    if manifest.get("generation").and_then(Value::as_u64) != Some(new_generation) {
        return Err("manifest generation differs from NPI1 successor generation".into());
    }
    if number(intent, "new_generation")? != new_generation
        || number(intent, "previous_generation")? != previous_generation
        || new_generation
            != previous_generation
                .checked_add(1)
                .ok_or("generation overflow")?
    {
        return Err("authorization generation sequence mismatch".into());
    }
    if field(intent, "activation_scope")? != "ZERO_VALUE_PUBLIC_TESTNET_ONLY" {
        return Err("authorization scope is not zero-value Public Testnet only".into());
    }
    if field(intent, "operator_id")? == field(intent, "owner_authorization_id")? {
        return Err("operator and owner identities must be distinct".into());
    }
    let nonce = hex32(field(intent, "nonce")?, "authorization nonce")?;
    let _ = nonce;
    hex32(
        field(intent, "endpoint_evidence_sha256")?,
        "endpoint evidence hash",
    )?;
    hex32(
        field(intent, "fingerprint_evidence_sha256")?,
        "fingerprint evidence hash",
    )?;
    let endpoint: SocketAddr = field(intent, "endpoint")?
        .parse()
        .map_err(|_| "endpoint must be a numeric SocketAddr")?;
    if endpoint.port() == 0 || endpoint.ip().is_unspecified() || endpoint.ip().is_multicast() {
        return Err("endpoint must be specified unicast with nonzero port".into());
    }
    if field(intent, "overlap_policy_id")?.len() < 8 {
        return Err("overlap policy identifier missing".into());
    }
    let rollback = number(intent, "rollback_window_seconds")?;
    if !(300..=86_400).contains(&rollback) {
        return Err("rollback window outside 5m..24h".into());
    }
    let issued = number(intent, "issued_at_unix")?;
    let expires = number(intent, "expires_at_unix")?;
    if issued > now.saturating_add(300)
        || expires <= now
        || expires <= issued
        || expires - issued > 86_400
    {
        return Err("authorization expired, future-dated, or validity too long".into());
    }

    let profile_id = hex32(field(intent, "profile_id_hex")?, "authorization profile ID")?;
    let canonical = canonical_intent(intent)?;
    let digest = sha(&canonical);
    let mut operator_message = b"QFP6-ROTATION-OPERATOR-SIGNATURE\0v1".to_vec();
    operator_message.extend_from_slice(&digest);
    operator_key
        .verify_strict(&operator_message, &op_sig)
        .map_err(|_| "independent operator signature verification failed")?;
    let mut owner_message = b"QFP6-ROTATION-OWNER-SIGNATURE\0v1".to_vec();
    owner_message.extend_from_slice(&digest);
    owner_message.extend_from_slice(&operator_fp);
    owner_message.extend_from_slice(&sha(operator_signature));
    owner_key
        .verify_strict(&owner_message, &own_sig)
        .map_err(|_| "owner signature over operator attestation failed")?;
    Ok(VerifiedDualAttestation {
        intent_digest: digest,
        profile_id,
        nonce,
        owner_pin_fingerprint: owner_fp,
        operator_pin_fingerprint: operator_fp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    struct Fixture {
        manifest: Vec<u8>,
        prepared: Vec<u8>,
        prepared_previous: Vec<u8>,
        endpoint_evidence: Vec<u8>,
        fingerprint_evidence: Vec<u8>,
        policy: Vec<u8>,
        auth: Vec<u8>,
        operator_public: Vec<u8>,
        operator_pin: String,
        operator_signature: Vec<u8>,
        owner_public: Vec<u8>,
        owner_pin: String,
        owner_signature: Vec<u8>,
        dpc1: Vec<u8>,
        irg1: Vec<u8>,
        deployment_authority_public: [u8; 32],
        deployment_authority: SigningKey,
        governance: SigningKey,
        recovery: SigningKey,
        root_chain_wire: Vec<u8>,
        previous: Vec<u8>,
        issuer: SigningKey,
        network: [u8; 32],
        new_public: [u8; 32],
        previous_public: [u8; 32],
        peer_not_before: u64,
        peer_not_after: u64,
        now: u64,
    }

    fn fixture() -> Fixture {
        let now: u64 = 1_800_000_000;
        let issuer = SigningKey::from_bytes(&[0x19; 32]);
        let operator = SigningKey::from_bytes(&[0x31; 32]);
        let owner = SigningKey::from_bytes(&[0x72; 32]);
        let operator_public = operator.verifying_key().to_bytes().to_vec();
        let owner_public = owner.verifying_key().to_bytes().to_vec();
        let operator_fp = hex(&sha(&operator_public));
        let owner_fp = hex(&sha(&owner_public));
        let network = [0x33; 32];
        let profile = "44".repeat(32);
        let new_public = [0x55; 32];
        let new_public_hex = hex(&new_public);
        let peer_not_before = now.saturating_sub(60);
        let peer_not_after = now.saturating_add(86_400);
        let old_public = [0x22; 32];
        let old_public_hex = hex(&old_public);
        let previous_record = crate::identity_policy::KeyRecord {
            key_id: 700,
            generation: 1,
            algorithm: crate::identity_policy::KeyAlgorithm::NoiseX25519,
            purpose: crate::identity_policy::KeyPurpose::PeerAuth,
            state: crate::identity_policy::KeyState::Active,
            not_before: peer_not_before,
            not_after: peer_not_after,
            public_key: old_public.to_vec(),
        };
        let previous = crate::devnet_signed_peer_identity_candidate::sign_signed_peer_identity(
            network,
            9001,
            7,
            &previous_record,
            None,
            &issuer,
        )
        .unwrap();
        let deployment_authority = SigningKey::from_bytes(&[0xd3; 32]);
        let governance = SigningKey::from_bytes(&[0xd4; 32]);
        let recovery = SigningKey::from_bytes(&[0xd5; 32]);
        // GRC1 v1 header with zero transitions: Governance is the pinned epoch-1 anchor.
        let mut root_chain_wire = Vec::with_capacity(40);
        root_chain_wire.extend_from_slice(b"GRC1");
        root_chain_wire.extend_from_slice(&1u16.to_be_bytes());
        root_chain_wire.extend_from_slice(&network);
        root_chain_wire.extend_from_slice(&0u16.to_be_bytes());
        let governance_public = governance.verifying_key().to_bytes();
        let deployment_authority_public = deployment_authority.verifying_key().to_bytes();
        let dpc1 = crate::noise_deployment_config::encode_signed_deployment_config(
            network,
            1,
            governance_public,
            governance_public,
            recovery.verifying_key().to_bytes(),
            1,
            1,
            &root_chain_wire,
            &deployment_authority,
        )
        .unwrap();
        let irg1 = crate::noise_issuer_registry::encode_signed_registry(
            network,
            1,
            &[crate::noise_issuer_registry::IssuerEntry {
                issuer_id: 7,
                public_key: issuer.verifying_key().to_bytes(),
                status: crate::noise_issuer_registry::IssuerStatus::Active,
            }],
            &governance,
        )
        .unwrap();
        let endpoint_evidence = b"operator verified endpoint reachability evidence".to_vec();
        let fingerprint_evidence =
            b"operator verified Noise fingerprint through independent channel".to_vec();
        let policy = b"rotation overlap policy v1: bounded overlap and rollback".to_vec();
        let prepared_value = json!({
            "schema":"qfp6-public-testnet-seed-noise-identity/v1", "role":"seed",
            "network_id_hex":hex(&network), "profile_id_hex":profile,
            "noise_static_public_key_hex":new_public_hex
        });
        let prepared = serde_json::to_vec(&prepared_value).unwrap();
        let prepared_previous = serde_json::to_vec(&json!({
            "schema":"qfp6-public-testnet-seed-noise-identity/v1", "role":"seed",
            "network_id_hex":hex(&network), "profile_id_hex":profile,
            "noise_static_public_key_hex":old_public_hex
        }))
        .unwrap();
        let manifest_value = json!({
            "schema":"qfp6-noise-identity-rotation-preparation/v1", "status":"PREPARED_NOT_ACTIVATED",
            "role":"seed", "generation":2, "generation_name":"generation-000002",
            "network_id_hex":hex(&network), "profile_id_hex":profile,
            "new_identity_sha256":hex(&sha(&prepared)), "previous_identity_sha256":hex(&sha(&prepared_previous)),
            "previous_public_key_sha256_fingerprint":hex(&sha(&old_public)),
            "new_public_key_hex":new_public_hex,
            "new_public_key_sha256_fingerprint":hex(&sha(&new_public)),
            "activation_authorized":false, "active_identity_modified":false,
            "active_protected_key_modified":false, "node_started":false, "listener_opened":false
        });
        let manifest = serde_json::to_vec(&manifest_value).unwrap();
        let intent = json!({
            "manifest_sha256":hex(&sha(&manifest)), "prepared_identity_sha256":hex(&sha(&prepared)),
            "dpc1_sha256":hex(&sha(&dpc1)), "irg1_sha256":hex(&sha(&irg1)),
            "previous_npi1_sha256":hex(&sha(&previous)), "network_id_hex":hex(&network),
            "profile_id_hex":profile, "issuer_id":7, "previous_generation":1, "new_generation":2,
            "peer_not_before_unix":peer_not_before, "peer_not_after_unix":peer_not_after,
            "role":"seed", "generation_name":"generation-000002",
            "new_identity_sha256":hex(&sha(&prepared)), "previous_identity_sha256":hex(&sha(&prepared_previous)),
            "previous_public_key_sha256_fingerprint":hex(&sha(&old_public)),
            "new_public_key_sha256_fingerprint":hex(&sha(&new_public)),
            "endpoint":"[2001:db8::1]:30333", "endpoint_evidence_sha256":hex(&sha(&endpoint_evidence)),
            "fingerprint_evidence_sha256":hex(&sha(&fingerprint_evidence)), "policy_sha256":hex(&sha(&policy)), "operator_id":"operator-B",
            "owner_authorization_id":"owner-A", "activation_scope":"ZERO_VALUE_PUBLIC_TESTNET_ONLY",
            "overlap_policy_id":"rotation-overlap-policy-v1", "rollback_window_seconds":3600,
            "issued_at_unix":now-60, "expires_at_unix":now+3600, "nonce":"88".repeat(32)
        });
        let canonical = canonical_intent(&intent).unwrap();
        let digest = sha(&canonical);
        let mut operator_message = b"QFP6-ROTATION-OPERATOR-SIGNATURE\0v1".to_vec();
        operator_message.extend_from_slice(&digest);
        let operator_signature = operator.sign(&operator_message).to_bytes().to_vec();
        let mut owner_message = b"QFP6-ROTATION-OWNER-SIGNATURE\0v1".to_vec();
        owner_message.extend_from_slice(&digest);
        owner_message.extend_from_slice(&sha(&operator_public));
        owner_message.extend_from_slice(&sha(&operator_signature));
        let owner_signature = owner.sign(&owner_message).to_bytes().to_vec();
        let auth = serde_json::to_vec(&json!({
            "schema":"qfp6-noise-identity-rotation-authorization/v3", "intent":intent
        }))
        .unwrap();
        Fixture {
            manifest,
            prepared,
            prepared_previous,
            endpoint_evidence,
            fingerprint_evidence,
            policy,
            auth,
            operator_public,
            operator_pin: operator_fp,
            operator_signature,
            owner_public,
            owner_pin: owner_fp,
            owner_signature,
            dpc1,
            irg1,
            deployment_authority_public,
            deployment_authority,
            governance,
            recovery,
            root_chain_wire,
            previous,
            issuer,
            network,
            new_public,
            previous_public: old_public,
            peer_not_before,
            peer_not_after,
            now,
        }
    }

    fn verify(f: &Fixture) -> Result<VerifiedDualAttestation, String> {
        verify_dual_attestation(
            &f.manifest,
            &f.prepared,
            &f.prepared_previous,
            &f.endpoint_evidence,
            &f.fingerprint_evidence,
            &f.policy,
            &f.auth,
            &f.operator_public,
            &f.operator_pin,
            &f.operator_signature,
            &f.owner_public,
            &f.owner_pin,
            &f.owner_signature,
            &f.dpc1,
            &f.irg1,
            &f.previous,
            &f.network,
            7,
            1,
            2,
            &f.new_public,
            &f.previous_public,
            f.peer_not_before,
            f.peer_not_after,
            f.now,
        )
    }

    #[test]
    fn prepared_previous_identity_is_hash_bound() {
        let mut f = fixture();
        f.prepared_previous.push(b' ');
        assert!(verify(&f).is_err());
    }

    #[test]
    fn evidence_and_policy_bytes_are_hash_bound() {
        let mut f = fixture();
        f.policy.push(b'!');
        assert!(verify(&f).is_err());
        let mut f = fixture();
        f.endpoint_evidence.push(b'!');
        assert!(verify(&f).is_err());
    }

    #[test]
    fn signer_pins_are_independent_and_mandatory() {
        let mut f = fixture();
        f.operator_pin = "99".repeat(32);
        assert!(verify(&f).is_err());
    }
    #[test]
    fn prepared_previous_identity_key_must_match_verified_previous_npi1_key() {
        let mut f = fixture();
        f.previous_public = [0x23; 32];
        assert!(verify(&f).is_err());
    }
    #[test]
    fn npi1_validity_window_is_bound_to_the_dual_attestation() {
        let f = fixture();
        assert!(verify(&f).is_ok());
        let mut changed_not_before = f.peer_not_before.saturating_add(1);
        assert!(verify_dual_attestation(
            &f.manifest,
            &f.prepared,
            &f.prepared_previous,
            &f.endpoint_evidence,
            &f.fingerprint_evidence,
            &f.policy,
            &f.auth,
            &f.operator_public,
            &f.operator_pin,
            &f.operator_signature,
            &f.owner_public,
            &f.owner_pin,
            &f.owner_signature,
            &f.dpc1,
            &f.irg1,
            &f.previous,
            &f.network,
            7,
            1,
            2,
            &f.new_public,
            &f.previous_public,
            changed_not_before,
            f.peer_not_after,
            f.now
        )
        .is_err());
        changed_not_before = f.peer_not_before;
        let changed_not_after = f.peer_not_after.saturating_sub(1);
        assert!(verify_dual_attestation(
            &f.manifest,
            &f.prepared,
            &f.prepared_previous,
            &f.endpoint_evidence,
            &f.fingerprint_evidence,
            &f.policy,
            &f.auth,
            &f.operator_public,
            &f.operator_pin,
            &f.operator_signature,
            &f.owner_public,
            &f.owner_pin,
            &f.owner_signature,
            &f.dpc1,
            &f.irg1,
            &f.previous,
            &f.network,
            7,
            1,
            2,
            &f.new_public,
            &f.previous_public,
            changed_not_before,
            changed_not_after,
            f.now
        )
        .is_err());
    }

    #[test]
    fn valid_independent_operator_and_owner_signatures_pass() {
        let result = verify(&fixture());
        assert!(result.is_ok(), "{result:?}");
    }

    #[test]
    fn operator_signature_tampering_is_rejected() {
        let mut f = fixture();
        f.operator_signature[0] ^= 1;
        assert!(verify(&f).is_err());
    }

    #[test]
    fn owner_signature_tampering_is_rejected() {
        let mut f = fixture();
        f.owner_signature[0] ^= 1;
        assert!(verify(&f).is_err());
    }

    #[test]
    fn same_signer_key_is_rejected() {
        let mut f = fixture();
        f.owner_public = f.operator_public.clone();
        f.owner_pin = f.operator_pin.clone();
        assert!(verify(&f).is_err());
    }

    #[test]
    fn command_input_digest_mismatch_is_rejected() {
        let mut f = fixture();
        f.dpc1.push(0);
        assert!(verify(&f).is_err());
    }

    #[test]
    fn expired_authorization_is_rejected() {
        let mut f = fixture();
        f.now += 7200;
        assert!(verify(&f).is_err());
    }
    #[test]
    fn duplicate_top_level_json_keys_are_rejected() {
        assert!(parse_unique_json(br#"{"schema":"a","schema":"b"}"#, "test").is_err());
    }

    #[test]
    fn duplicate_nested_json_keys_are_rejected() {
        assert!(parse_unique_json(br#"{"intent":{"nonce":"one","nonce":"two"}}"#, "test").is_err());
    }

    #[test]
    fn unique_json_and_trailing_data_rules_are_enforced() {
        assert!(parse_unique_json(br#"{"a":1,"nested":[true,null,"x"]}"#, "test").is_ok());
        assert!(parse_unique_json(br#"{"a":1} {"b":2}"#, "test").is_err());
    }

    #[test]
    fn anchored_successor_proof_requires_exact_c_d_npi1_nrt1_and_dual_bindings() {
        use crate::{
            devnet_signed_peer_identity_candidate::sign_signed_peer_identity,
            identity_generation_store::{
                encode_signed_rotation_statement, IdentityGenerationStateStore,
            },
            identity_policy::{encode, KeyAlgorithm, KeyPurpose, KeyRecord, KeyState},
            peer_identity_anchor_vault::{
                PeerAnchorEvent, PeerAnchorEventKind, PeerIdentityAnchorScope,
                PeerIdentityAnchorVault,
            },
            peer_identity_successor_proof::{
                verify_anchored_successor_proof, AnchoredSuccessorProofEvidence,
                DualAttestationEvidence,
            },
        };
        use crate::{
            noise_deployment_config::{
                verify_signed_deployment_config, DeploymentConfigStateStore,
            },
            noise_issuer_registry::IssuerRegistryStateStore,
        };
        use std::{fs, path::PathBuf};

        let f = fixture();
        let root: PathBuf = std::env::temp_dir().join(format!(
            "anchored-successor-proof-{}-{}",
            std::process::id(),
            f.now
        ));
        fs::create_dir_all(root.join("anchor-c")).unwrap();
        fs::create_dir_all(root.join("highwater-d")).unwrap();
        fs::create_dir_all(root.join("trust-state")).unwrap();

        let old_record = KeyRecord {
            key_id: 700,
            generation: 1,
            algorithm: KeyAlgorithm::NoiseX25519,
            purpose: KeyPurpose::PeerAuth,
            state: KeyState::Active,
            not_before: f.peer_not_before,
            not_after: f.peer_not_after,
            public_key: f.previous_public.to_vec(),
        };
        let new_record = KeyRecord {
            key_id: 700,
            generation: 2,
            algorithm: KeyAlgorithm::NoiseX25519,
            purpose: KeyPurpose::PeerAuth,
            state: KeyState::Active,
            not_before: f.peer_not_before,
            not_after: f.peer_not_after,
            public_key: f.new_public.to_vec(),
        };
        let old_record_bytes = encode(&old_record).unwrap();
        let new_record_bytes = encode(&new_record).unwrap();
        let old_record_digest = sha(&old_record_bytes);
        let new_record_digest = sha(&new_record_bytes);
        let issuer_public = f.issuer.verifying_key().to_bytes();
        let nrt1 = encode_signed_rotation_statement(
            f.network,
            9001,
            7,
            &old_record_bytes,
            &new_record_bytes,
            &f.issuer,
        )
        .unwrap();
        let successor_npi1 =
            sign_signed_peer_identity(f.network, 9001, 7, &new_record, Some(&nrt1), &f.issuer)
                .unwrap();
        let dual = verify(&f).unwrap();

        let scope = PeerIdentityAnchorScope {
            network_id: f.network,
            profile_id: [0x44; 32],
            genesis_root: [0x66; 32],
            role: 1,
            issuer_id: 7,
            issuer_public_key_fingerprint: sha(&issuer_public),
            key_purpose: KeyPurpose::PeerAuth as u8,
            credential_id: 9001,
            key_id: 700,
        };
        let mut vault =
            PeerIdentityAnchorVault::open(root.join("anchor-c"), scope.clone()).unwrap();
        let deployment =
            verify_signed_deployment_config(&f.dpc1, &f.network, &f.deployment_authority_public, 1)
                .unwrap();
        let deployment_state = DeploymentConfigStateStore::open(
            root.join("trust-state").join("deployment.dcs1"),
            &f.network,
            &f.deployment_authority_public,
            1,
        )
        .unwrap();
        deployment_state.observe(&deployment).unwrap();
        let issuer_registry_state = IssuerRegistryStateStore::open_with_root_chain(
            root.join("trust-state").join("issuers.irh1"),
            &f.network,
            deployment.root_chain.clone(),
            1,
        )
        .unwrap();
        issuer_registry_state
            .accept_signed_registry(&f.irg1, 7)
            .unwrap();

        let store = IdentityGenerationStateStore::open(
            root.join("highwater-d").join("identity.highwater"),
            &f.network,
            700,
            KeyPurpose::PeerAuth,
            9001,
            7,
            issuer_public,
        )
        .unwrap();
        store
            .observe_signed_record(&old_record_bytes, &old_record, None)
            .unwrap();

        vault
            .enroll_genesis(PeerAnchorEvent {
                kind: PeerAnchorEventKind::EnrolledActive,
                generation: 1,
                previous_generation: 0,
                lifecycle: 1,
                noise_fingerprint: sha(&f.previous_public),
                npi1_digest: sha(&f.previous),
                key_record_digest: old_record_digest,
                previous_key_record_digest: [0; 32],
                nrt1_digest: [0; 32],
                intent_digest: [0; 32],
                nonce: [0; 32],
                owner_pin_fingerprint: dual.owner_pin_fingerprint,
                operator_pin_fingerprint: dual.operator_pin_fingerprint,
            })
            .unwrap();
        vault
            .prepare_rotation(PeerAnchorEvent {
                kind: PeerAnchorEventKind::RotationPrepared,
                generation: 2,
                previous_generation: 1,
                lifecycle: 1,
                noise_fingerprint: sha(&f.new_public),
                npi1_digest: sha(&successor_npi1),
                key_record_digest: new_record_digest,
                previous_key_record_digest: old_record_digest,
                nrt1_digest: sha(&nrt1),
                intent_digest: dual.intent_digest,
                nonce: dual.nonce,
                owner_pin_fingerprint: dual.owner_pin_fingerprint,
                operator_pin_fingerprint: dual.operator_pin_fingerprint,
            })
            .unwrap();
        vault.activate_prepared(dual.nonce).unwrap();

        fn evidence_for<'a>(
            f: &'a Fixture,
            issuer_public: &'a [u8; 32],
            successor_npi1: &'a [u8],
            rotation: &'a [u8],
            verification_epoch: u64,
        ) -> AnchoredSuccessorProofEvidence<'a> {
            AnchoredSuccessorProofEvidence {
                issuer_public_key: issuer_public,
                verification_epoch,
                previous_npi1: &f.previous,
                successor_npi1,
                nrt1: rotation,
                dual_attestation: DualAttestationEvidence {
                    manifest: &f.manifest,
                    prepared_identity: &f.prepared,
                    prepared_previous_identity: &f.prepared_previous,
                    endpoint_evidence: &f.endpoint_evidence,
                    fingerprint_evidence: &f.fingerprint_evidence,
                    policy: &f.policy,
                    authorization: &f.auth,
                    operator_public: &f.operator_public,
                    operator_pin: &f.operator_pin,
                    operator_signature: &f.operator_signature,
                    owner_public: &f.owner_public,
                    owner_pin: &f.owner_pin,
                    owner_signature: &f.owner_signature,
                    dpc1: &f.dpc1,
                    irg1: &f.irg1,
                    deployment_authority_public_key: &f.deployment_authority_public,
                    minimum_dpc1_sequence: 1,
                    minimum_dpc1_root_epoch: 1,
                },
            }
        }
        let proof = verify_anchored_successor_proof(
            &vault,
            &store,
            &scope,
            &deployment_state,
            &issuer_registry_state,
            evidence_for(&f, &issuer_public, &successor_npi1, &nrt1, f.now),
        )
        .unwrap();
        assert_eq!(proof.previous_generation, 1);
        assert_eq!(proof.successor_generation, 2);
        assert_eq!(proof.previous_record_digest, old_record_digest);
        assert_eq!(proof.successor_record_digest, new_record_digest);
        assert_eq!(proof.intent_digest, dual.intent_digest);
        assert_eq!(proof.nonce, dual.nonce);
        assert_eq!(proof.profile_id, scope.profile_id);
        assert_eq!(proof.deployment_config_sequence, 1);
        assert_eq!(proof.issuer_registry_sequence, 1);
        assert_eq!(proof.governance_root_epoch, 1);
        assert_eq!(proof.issuer_registry_key_fingerprint, sha(&issuer_public));

        let wrong_authority = [0xee; 32];
        let mut bad_authority = evidence_for(&f, &issuer_public, &successor_npi1, &nrt1, f.now);
        bad_authority
            .dual_attestation
            .deployment_authority_public_key = &wrong_authority;
        assert!(matches!(
            verify_anchored_successor_proof(
                &vault,
                &store,
                &scope,
                &deployment_state,
                &issuer_registry_state,
                bad_authority
            ),
            Err(crate::peer_identity_successor_proof::AnchoredSuccessorProofError::Dpc1(_))
        ));
        let mut below_dpc1_floor = evidence_for(&f, &issuer_public, &successor_npi1, &nrt1, f.now);
        below_dpc1_floor.dual_attestation.minimum_dpc1_sequence = 2;
        assert!(matches!(
            verify_anchored_successor_proof(
                &vault,
                &store,
                &scope,
                &deployment_state,
                &issuer_registry_state,
                below_dpc1_floor
            ),
            Err(crate::peer_identity_successor_proof::AnchoredSuccessorProofError::Dpc1(_))
        ));

        let mut tampered_dpc1 = f.dpc1.clone();
        let last_dpc1_byte = tampered_dpc1.len() - 1;
        tampered_dpc1[last_dpc1_byte] ^= 1;
        let mut bad_dpc1_signature =
            evidence_for(&f, &issuer_public, &successor_npi1, &nrt1, f.now);
        bad_dpc1_signature.dual_attestation.dpc1 = &tampered_dpc1;
        assert!(matches!(
            verify_anchored_successor_proof(
                &vault,
                &store,
                &scope,
                &deployment_state,
                &issuer_registry_state,
                bad_dpc1_signature
            ),
            Err(crate::peer_identity_successor_proof::AnchoredSuccessorProofError::Dpc1(_))
        ));

        let mut wrong_network_dpc1 = f.dpc1.clone();
        wrong_network_dpc1[6] ^= 1;
        let mut wrong_dpc1_network =
            evidence_for(&f, &issuer_public, &successor_npi1, &nrt1, f.now);
        wrong_dpc1_network.dual_attestation.dpc1 = &wrong_network_dpc1;
        assert!(matches!(
            verify_anchored_successor_proof(
                &vault,
                &store,
                &scope,
                &deployment_state,
                &issuer_registry_state,
                wrong_dpc1_network
            ),
            Err(crate::peer_identity_successor_proof::AnchoredSuccessorProofError::Dpc1(_))
        ));

        let stale_registry_dpc1 = crate::noise_deployment_config::encode_signed_deployment_config(
            f.network,
            2,
            f.governance.verifying_key().to_bytes(),
            f.governance.verifying_key().to_bytes(),
            f.recovery.verifying_key().to_bytes(),
            1,
            2,
            &f.root_chain_wire,
            &f.deployment_authority,
        )
        .unwrap();
        let stale_deployment = verify_signed_deployment_config(
            &stale_registry_dpc1,
            &f.network,
            &f.deployment_authority_public,
            1,
        )
        .unwrap();
        let stale_deployment_state = DeploymentConfigStateStore::open(
            root.join("trust-state").join("deployment-seq2.dcs1"),
            &f.network,
            &f.deployment_authority_public,
            1,
        )
        .unwrap();
        stale_deployment_state.observe(&stale_deployment).unwrap();
        let stale_dpc1_evidence = evidence_for(&f, &issuer_public, &successor_npi1, &nrt1, f.now);
        assert!(matches!(
            verify_anchored_successor_proof(
                &vault,
                &store,
                &scope,
                &stale_deployment_state,
                &issuer_registry_state,
                stale_dpc1_evidence
            ),
            Err(crate::peer_identity_successor_proof::AnchoredSuccessorProofError::Dpc1(_))
        ));

        let mut below_registry_floor =
            evidence_for(&f, &issuer_public, &successor_npi1, &nrt1, f.now);
        below_registry_floor.dual_attestation.dpc1 = &stale_registry_dpc1;
        assert!(matches!(
            verify_anchored_successor_proof(&vault, &store, &scope, &stale_deployment_state, &issuer_registry_state, below_registry_floor),
            Err(crate::peer_identity_successor_proof::AnchoredSuccessorProofError::RegistryBelowDeploymentFloor)
        ));

        let mut tampered_registry = f.irg1.clone();
        let last_registry_byte = tampered_registry.len() - 1;
        tampered_registry[last_registry_byte] ^= 1;
        let mut bad_registry_signature =
            evidence_for(&f, &issuer_public, &successor_npi1, &nrt1, f.now);
        bad_registry_signature.dual_attestation.irg1 = &tampered_registry;
        assert!(matches!(
            verify_anchored_successor_proof(
                &vault,
                &store,
                &scope,
                &deployment_state,
                &issuer_registry_state,
                bad_registry_signature
            ),
            Err(crate::peer_identity_successor_proof::AnchoredSuccessorProofError::Irg1(_))
        ));

        let mut wrong_network_registry = f.irg1.clone();
        wrong_network_registry[6] ^= 1;
        let mut wrong_registry_network =
            evidence_for(&f, &issuer_public, &successor_npi1, &nrt1, f.now);
        wrong_registry_network.dual_attestation.irg1 = &wrong_network_registry;
        assert!(matches!(
            verify_anchored_successor_proof(
                &vault,
                &store,
                &scope,
                &deployment_state,
                &issuer_registry_state,
                wrong_registry_network
            ),
            Err(crate::peer_identity_successor_proof::AnchoredSuccessorProofError::Irg1(_))
        ));

        let newer_registry = crate::noise_issuer_registry::encode_signed_registry(
            f.network,
            2,
            &[crate::noise_issuer_registry::IssuerEntry {
                issuer_id: 7,
                public_key: issuer_public,
                status: crate::noise_issuer_registry::IssuerStatus::Active,
            }],
            &f.governance,
        )
        .unwrap();
        let newer_registry_state = IssuerRegistryStateStore::open_with_root_chain(
            root.join("trust-state").join("issuers-seq2.irh1"),
            &f.network,
            deployment.root_chain.clone(),
            1,
        )
        .unwrap();
        newer_registry_state
            .accept_signed_registry(&newer_registry, 7)
            .unwrap();
        let stale_irg1_evidence = evidence_for(&f, &issuer_public, &successor_npi1, &nrt1, f.now);
        assert!(matches!(
            verify_anchored_successor_proof(
                &vault,
                &store,
                &scope,
                &deployment_state,
                &newer_registry_state,
                stale_irg1_evidence
            ),
            Err(crate::peer_identity_successor_proof::AnchoredSuccessorProofError::Irg1(_))
        ));

        let revoked_registry = crate::noise_issuer_registry::encode_signed_registry(
            f.network,
            1,
            &[crate::noise_issuer_registry::IssuerEntry {
                issuer_id: 7,
                public_key: issuer_public,
                status: crate::noise_issuer_registry::IssuerStatus::Revoked,
            }],
            &f.governance,
        )
        .unwrap();
        let mut revoked_issuer = evidence_for(&f, &issuer_public, &successor_npi1, &nrt1, f.now);
        revoked_issuer.dual_attestation.irg1 = &revoked_registry;
        assert!(matches!(
            verify_anchored_successor_proof(
                &vault,
                &store,
                &scope,
                &deployment_state,
                &issuer_registry_state,
                revoked_issuer
            ),
            Err(crate::peer_identity_successor_proof::AnchoredSuccessorProofError::Irg1(_))
        ));

        let wrong_issuer = SigningKey::from_bytes(&[0xd6; 32]);
        let wrong_issuer_registry = crate::noise_issuer_registry::encode_signed_registry(
            f.network,
            1,
            &[crate::noise_issuer_registry::IssuerEntry {
                issuer_id: 7,
                public_key: wrong_issuer.verifying_key().to_bytes(),
                status: crate::noise_issuer_registry::IssuerStatus::Active,
            }],
            &f.governance,
        )
        .unwrap();
        let wrong_registry_state = IssuerRegistryStateStore::open_with_root_chain(
            root.join("trust-state").join("issuers-wrong-key.irh1"),
            &f.network,
            deployment.root_chain.clone(),
            1,
        )
        .unwrap();
        wrong_registry_state
            .accept_signed_registry(&wrong_issuer_registry, 7)
            .unwrap();
        let mut wrong_registry_key =
            evidence_for(&f, &issuer_public, &successor_npi1, &nrt1, f.now);
        wrong_registry_key.dual_attestation.irg1 = &wrong_issuer_registry;
        assert_eq!(
            verify_anchored_successor_proof(&vault, &store, &scope, &deployment_state, &wrong_registry_state, wrong_registry_key),
            Err(crate::peer_identity_successor_proof::AnchoredSuccessorProofError::RegistryIssuerKeyMismatch)
        );

        assert_eq!(
            verify_anchored_successor_proof(
                &vault,
                &store,
                &scope,
                &deployment_state,
                &issuer_registry_state,
                evidence_for(
                    &f,
                    &issuer_public,
                    &successor_npi1,
                    &nrt1,
                    f.peer_not_after.saturating_add(1),
                ),
            ),
            Err(crate::peer_identity_successor_proof::AnchoredSuccessorProofError::SuccessorOutsideValidityWindow)
        );

        let mut tampered_nrt1 = nrt1.clone();
        tampered_nrt1[0] ^= 1;
        assert_eq!(
            verify_anchored_successor_proof(
                &vault,
                &store,
                &scope,
                &deployment_state,
                &issuer_registry_state,
                evidence_for(&f, &issuer_public, &successor_npi1, &tampered_nrt1, f.now),
            ),
            Err(crate::peer_identity_successor_proof::AnchoredSuccessorProofError::ArtifactDigestMismatch)
        );
        let mut wrong_scope = scope.clone();
        wrong_scope.key_id = 701;
        assert_eq!(
            verify_anchored_successor_proof(
                &vault,
                &store,
                &wrong_scope,
                &deployment_state,
                &issuer_registry_state,
                evidence_for(&f, &issuer_public, &successor_npi1, &nrt1, f.now),
            ),
            Err(crate::peer_identity_successor_proof::AnchoredSuccessorProofError::AnchorScopeMismatch)
        );

        drop(vault);
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }
}
