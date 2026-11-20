//! Verify a signed, version-bound rotation authorization. This tool never activates keys.
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    net::SocketAddr,
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_FILE: u64 = 64 * 1024;
const AUTH_SCHEMA: &str = "qfp6-noise-identity-rotation-authorization/v1";

fn read_regular(path: &str, max: u64, label: &str) -> Result<Vec<u8>, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|e| format!("cannot inspect {label}: {e}"))?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > max {
        return Err(format!("{label} is not a bounded regular file"));
    }
    let bytes = fs::read(path).map_err(|e| format!("cannot read {label}: {e}"))?;
    if bytes.len() as u64 != metadata.len() {
        return Err(format!("{label} changed while being read"));
    }
    Ok(bytes)
}
fn hex32(value: &str, label: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.is_ascii() || value.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(format!(
            "{label} must be 64 lowercase hexadecimal characters"
        ));
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16)
            .map_err(|_| format!("{label} contains invalid hexadecimal"))?;
    }
    if out == [0; 32] {
        return Err(format!("{label} must not be zero"));
    }
    Ok(out)
}
fn field<'a>(v: &'a Value, name: &str) -> Result<&'a str, String> {
    v.get(name)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| format!("authorization field {name} is required"))
}
fn bool_field(v: &Value, name: &str) -> Result<bool, String> {
    v.get(name)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("authorization field {name} must be boolean"))
}
fn u64_field(v: &Value, name: &str) -> Result<u64, String> {
    v.get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("authorization field {name} must be an unsigned integer"))
}
fn sha(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn verify_authorization(
    manifest_bytes: &[u8],
    authorization_bytes: &[u8],
    signature_bytes: &[u8],
    authority_public_key: &[u8],
    expected_authority_fingerprint: &str,
    expected_seed_endpoint: &str,
    expected_seed_fingerprint: &str,
    now_unix: u64,
) -> Result<(), String> {
    if manifest_bytes.is_empty() || manifest_bytes.len() as u64 > MAX_FILE {
        return Err("manifest size invalid".into());
    }
    if authorization_bytes.is_empty() || authorization_bytes.len() as u64 > MAX_FILE {
        return Err("authorization size invalid".into());
    }
    if signature_bytes.len() != 64 {
        return Err("Ed25519 signature must be exactly 64 bytes".into());
    }
    if authority_public_key.len() != 32 {
        return Err("pinned authority public key must be exactly 32 bytes".into());
    }

    let expected_authority = hex32(
        expected_authority_fingerprint,
        "expected authority fingerprint",
    )?;
    let expected_seed_fp = hex32(expected_seed_fingerprint, "expected Seed fingerprint")?;
    let actual_authority_fp = sha(authority_public_key);
    if actual_authority_fp != expected_authority {
        return Err("owner authority public-key pin mismatch".into());
    }

    let verifying_key = VerifyingKey::from_bytes(
        authority_public_key
            .try_into()
            .map_err(|_| "invalid authority public key length")?,
    )
    .map_err(|_| "owner authority public key is invalid")?;
    let signature = Signature::from_slice(signature_bytes)
        .map_err(|_| "owner authorization signature is malformed")?;
    verifying_key
        .verify_strict(authorization_bytes, &signature)
        .map_err(|_| "owner authorization signature verification failed")?;

    let manifest: Value =
        serde_json::from_slice(manifest_bytes).map_err(|_| "rotation manifest JSON invalid")?;
    let auth: Value =
        serde_json::from_slice(authorization_bytes).map_err(|_| "authorization JSON invalid")?;
    if field(&auth, "schema")? != AUTH_SCHEMA {
        return Err("unsupported authorization schema".into());
    }

    let manifest_hash = hex(&sha(manifest_bytes));
    if field(&auth, "manifest_sha256")? != manifest_hash {
        return Err("authorization is not bound to this exact manifest".into());
    }
    if field(&manifest, "status")? != "PREPARED_NOT_ACTIVATED" {
        return Err("manifest is not a prepared inactive generation".into());
    }
    if manifest
        .get("activation_authorized")
        .and_then(Value::as_bool)
        != Some(false)
        || manifest
            .get("active_identity_modified")
            .and_then(Value::as_bool)
            != Some(false)
        || manifest
            .get("active_protected_key_modified")
            .and_then(Value::as_bool)
            != Some(false)
        || manifest.get("node_started").and_then(Value::as_bool) != Some(false)
        || manifest.get("listener_opened").and_then(Value::as_bool) != Some(false)
    {
        return Err("manifest contains unsafe activation or runtime flags".into());
    }

    for name in [
        "role",
        "generation_name",
        "network_id_hex",
        "profile_id_hex",
        "new_identity_sha256",
        "new_public_key_sha256_fingerprint",
        "previous_public_key_sha256_fingerprint",
    ] {
        let m = if name == "generation_name" {
            field(&manifest, name)?
        } else {
            field(&manifest, name)?
        };
        if field(&auth, name)? != m {
            return Err(format!(
                "authorization does not match manifest field {name}"
            ));
        }
    }
    let generation = manifest
        .get("generation")
        .and_then(Value::as_u64)
        .ok_or("manifest generation invalid")?;
    if u64_field(&auth, "generation")? != generation {
        return Err("authorization generation mismatch".into());
    }

    let role = field(&manifest, "role")?;
    if role != "seed" && role != "joining" {
        return Err("unsupported rotation role".into());
    }
    hex32(field(&manifest, "network_id_hex")?, "manifest network ID")?;
    hex32(field(&manifest, "profile_id_hex")?, "manifest profile ID")?;
    hex32(
        field(&manifest, "new_identity_sha256")?,
        "new identity hash",
    )?;
    hex32(
        field(&manifest, "new_public_key_sha256_fingerprint")?,
        "new public fingerprint",
    )?;
    hex32(
        field(&manifest, "previous_public_key_sha256_fingerprint")?,
        "previous public fingerprint",
    )?;

    let endpoint_text = field(&auth, "seed_endpoint")?;
    if endpoint_text != expected_seed_endpoint {
        return Err("signed Seed endpoint differs from the independently supplied endpoint".into());
    }
    let endpoint: SocketAddr = endpoint_text
        .parse()
        .map_err(|_| "Seed endpoint must be a numeric SocketAddr")?;
    if endpoint.port() == 0 || endpoint.ip().is_unspecified() || endpoint.ip().is_multicast() {
        return Err("Seed endpoint must be a specified unicast IP and nonzero port".into());
    }
    let signed_seed_fp = hex32(
        field(&auth, "seed_public_key_sha256_fingerprint")?,
        "signed Seed fingerprint",
    )?;
    if signed_seed_fp != expected_seed_fp {
        return Err(
            "signed Seed fingerprint differs from the independently supplied Seed pin".into(),
        );
    }
    if role == "seed"
        && signed_seed_fp
            != hex32(
                field(&manifest, "new_public_key_sha256_fingerprint")?,
                "new Seed fingerprint",
            )?
    {
        return Err("Seed rotation authorization does not bind its new public identity".into());
    }

    if !bool_field(&auth, "endpoint_independently_verified")? {
        return Err("independent endpoint verification is not attested".into());
    }
    if !bool_field(&auth, "fingerprint_independently_verified")? {
        return Err("independent fingerprint verification is not attested".into());
    }
    hex32(
        field(&auth, "endpoint_verification_evidence_sha256")?,
        "endpoint evidence hash",
    )?;
    hex32(
        field(&auth, "fingerprint_verification_evidence_sha256")?,
        "fingerprint evidence hash",
    )?;
    if field(&auth, "independent_operator_id")? == field(&auth, "owner_authorization_id")? {
        return Err("independent verifier and owner approver must be distinct identities".into());
    }
    if field(&auth, "activation_scope")? != "ZERO_VALUE_PUBLIC_TESTNET_ONLY" {
        return Err("authorization scope exceeds zero-value Public Testnet".into());
    }
    if field(&auth, "overlap_policy_id")?.len() < 8 {
        return Err("documented overlap/rollback policy ID is missing".into());
    }
    let rollback = u64_field(&auth, "rollback_window_seconds")?;
    if !(300..=86_400).contains(&rollback) {
        return Err("rollback window must be between 5 minutes and 24 hours".into());
    }

    let issued = u64_field(&auth, "issued_at_unix")?;
    let expires = u64_field(&auth, "expires_at_unix")?;
    if issued > now_unix.saturating_add(300)
        || expires <= now_unix
        || expires <= issued
        || expires - issued > 86_400
    {
        return Err(
            "authorization is expired, future-dated, or has an excessive validity period".into(),
        );
    }
    field(&auth, "owner_authorization_id")?;
    field(&auth, "independent_operator_id")?;
    Ok(())
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() != 7 {
        return Err("usage: noise_identity_rotation_authorization_verify <manifest> <authorization-json> <signature-64b> <authority-public-key-32b> <authority-fingerprint-sha256> <expected-seed-endpoint> <expected-seed-fingerprint>".into());
    }
    let manifest = read_regular(&args[0], MAX_FILE, "rotation manifest")?;
    let authorization = read_regular(&args[1], MAX_FILE, "signed authorization")?;
    let signature = read_regular(&args[2], 64, "authorization signature")?;
    let authority = read_regular(&args[3], 32, "owner authority public key")?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock precedes Unix epoch")?
        .as_secs();
    verify_authorization(
        &manifest,
        &authorization,
        &signature,
        &authority,
        &args[4],
        &args[5],
        &args[6],
        now,
    )?;
    println!("OWNER_ONLY_PREFLIGHT=VALID");
    println!("MANIFEST_BINDING=PASS");
    println!("OWNER_SIGNATURE=PASS");
    println!("ENDPOINT_AND_FINGERPRINT_CLAIMS=OWNER_ASSERTED_ONLY");
    println!("INDEPENDENT_OPERATOR_SIGNATURE=NOT_VERIFIED");
    println!("ZERO_VALUE_SCOPE_AND_ROLLBACK_POLICY=PASS");
    println!("ROTATE_PEER_AUTHORIZED=FALSE");
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ROTATION_AUTHORIZATION=REJECTED: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    fn fixture(now: u64) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, String, String, String) {
        let signing = SigningKey::from_bytes(&[0x5a; 32]);
        let public = signing.verifying_key().to_bytes().to_vec();
        let authority_fp = hex(&sha(&public));
        let new_fp = "11".repeat(32);
        let old_fp = "22".repeat(32);
        let network = "33".repeat(32);
        let profile = "44".repeat(32);
        let manifest = json!({
            "schema":"qfp6-noise-identity-rotation-preparation/v1",
            "status":"PREPARED_NOT_ACTIVATED","role":"seed","generation":1,
            "generation_name":"generation-000001","network_id_hex":network,
            "profile_id_hex":profile,"new_identity_sha256":"55".repeat(32),
            "new_public_key_sha256_fingerprint":new_fp,
            "previous_public_key_sha256_fingerprint":old_fp,
            "activation_authorized":false,"active_identity_modified":false,
            "active_protected_key_modified":false,"node_started":false,"listener_opened":false
        });
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let auth = json!({
            "schema":AUTH_SCHEMA,"manifest_sha256":hex(&sha(&manifest_bytes)),
            "role":"seed","generation":1,"generation_name":"generation-000001",
            "network_id_hex":network,"profile_id_hex":profile,
            "new_identity_sha256":"55".repeat(32),
            "new_public_key_sha256_fingerprint":new_fp,
            "previous_public_key_sha256_fingerprint":old_fp,
            "seed_endpoint":"[2001:db8::1]:30333",
            "seed_public_key_sha256_fingerprint":new_fp,
            "endpoint_independently_verified":true,"fingerprint_independently_verified":true,
            "endpoint_verification_evidence_sha256":"66".repeat(32),
            "fingerprint_verification_evidence_sha256":"77".repeat(32),
            "independent_operator_id":"independent-operator-B",
            "owner_authorization_id":"owner-approval-A",
            "activation_scope":"ZERO_VALUE_PUBLIC_TESTNET_ONLY",
            "overlap_policy_id":"rotation-overlap-policy-v1",
            "rollback_window_seconds":3600,
            "issued_at_unix":now-60,"expires_at_unix":now+3600
        });
        let auth_bytes = serde_json::to_vec(&auth).unwrap();
        let sig = signing.sign(&auth_bytes).to_bytes().to_vec();
        (
            manifest_bytes,
            auth_bytes,
            sig,
            public,
            authority_fp,
            "[2001:db8::1]:30333".into(),
            new_fp,
        )
    }

    #[test]
    fn signed_exact_generation_authorization_passes_without_activation() {
        let now = 1_800_000_000;
        let (m, a, s, p, afp, endpoint, seedfp) = fixture(now);
        assert!(verify_authorization(&m, &a, &s, &p, &afp, &endpoint, &seedfp, now).is_ok());
    }
    #[test]
    fn wrong_owner_authority_pin_is_rejected() {
        let now = 1_800_000_000;
        let (m, a, s, p, _, endpoint, seedfp) = fixture(now);
        assert!(
            verify_authorization(&m, &a, &s, &p, &"88".repeat(32), &endpoint, &seedfp, now)
                .is_err()
        );
    }
    #[test]
    fn modified_authorization_signature_is_rejected() {
        let now = 1_800_000_000;
        let (m, a, mut s, p, afp, endpoint, seedfp) = fixture(now);
        s[0] ^= 1;
        assert!(verify_authorization(&m, &a, &s, &p, &afp, &endpoint, &seedfp, now).is_err());
    }
    #[test]
    fn authorization_for_another_manifest_is_rejected() {
        let now = 1_800_000_000;
        let (mut m, a, s, p, afp, endpoint, seedfp) = fixture(now);
        m.push(b' ');
        assert!(verify_authorization(&m, &a, &s, &p, &afp, &endpoint, &seedfp, now).is_err());
    }
    #[test]
    fn expired_authorization_is_rejected() {
        let now = 1_800_000_000;
        let (m, a, s, p, afp, endpoint, seedfp) = fixture(now);
        assert!(
            verify_authorization(&m, &a, &s, &p, &afp, &endpoint, &seedfp, now + 7200).is_err()
        );
    }
    #[test]
    fn endpoint_or_seed_pin_mismatch_is_rejected() {
        let now = 1_800_000_000;
        let (m, a, s, p, afp, endpoint, seedfp) = fixture(now);
        assert!(
            verify_authorization(&m, &a, &s, &p, &afp, "[2001:db8::2]:30333", &seedfp, now)
                .is_err()
        );
        assert!(
            verify_authorization(&m, &a, &s, &p, &afp, &endpoint, &"99".repeat(32), now).is_err()
        );
    }
}
