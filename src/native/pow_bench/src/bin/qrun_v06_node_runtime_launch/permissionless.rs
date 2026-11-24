//! Separate Genesis-rooted permissionless base-runtime launcher.
//! It never loads the legacy Provider/Q6EA/QAP1 services. Q6TS/Q6QA are opt-in only
//! when the independently committed Q6PN v2 carries an external quote-asset trust pin.
use super::{
    load_pinned_q6cp_profile, parse_hex32, read_bounded, resolve_path, MAX_BOOTSTRAP_BYTES,
    MAX_CONFIG_BYTES, MAX_GENESIS_SNAPSHOT_BYTES,
};
use ai_native_l1_pow_bench::{
    noise_key_provisioning::load_protected_noise_private_key,
    qfp6_device_identity_candidate::{derive_noise_static_public_key, verify_device_root_binding},
    qrun_v06_bootstrap_trust_domain_candidate::BootstrapTrustDomainPolicy,
    qrun_v06_canonical_execution_candidate::QRunV06CanonicalExecutionState,
    qrun_v06_checkpoint_candidate::MAX_QRUN_V06_CHECKPOINT_BYTES,
    qrun_v06_cp0651_supply_candidate::CP0651_OWNER_GENESIS_ATOMS,
    qrun_v06_genesis_approval_candidate::QRunV06GenesisApproval,
    qrun_v06_genesis_descriptor_candidate::QRunV06GenesisDescriptor,
    qrun_v06_history_sync_service_candidate::{
        pull_q6ar_candidates_from_pinned_peer,
        pull_q6pd_peer_records_from_dns_seed_with_announcement,
        pull_q6pd_peer_records_from_pinned_peer_with_announcement, QRunV06HistorySyncClientConfig,
    },
    qrun_v06_hybrid_auth_candidate::QRunV06HybridTransactionAuthenticator,
    qrun_v06_local_anchor_vault_candidate::QRunV06LocalAnchorVault,
    qrun_v06_node_supervisor_candidate::{
        run_qfp6_permissionless_mining_supervisor_open,
        run_qfp6_permissionless_mining_supervisor_open_with_q6ar_candidate,
        run_qfp6_permissionless_mining_supervisor_open_with_q6pd_candidate,
        run_qfp6_permissionless_mining_supervisor_with_bootstrap,
        run_qfp6_permissionless_mining_supervisor_with_bootstrap_and_q6ar_candidate,
        run_qfp6_permissionless_mining_supervisor_with_q6ar_candidate_and_quote_asset_authorization,
        run_qfp6_permissionless_mining_supervisor_with_quote_asset_authorization,
        validate_qfp6_pinned_bootstrap_peers, QRunV06PermissionlessMiningSupervisorConfig,
        QRunV06PinnedBootstrapPeer,
    },
    qrun_v06_peer_address_manager_candidate::QRunV06PeerAddressBookCandidate,
    qrun_v06_peer_discovery_candidate::Q6PD_MAX_TTL_SECS,
    qrun_v06_peer_discovery_store_candidate::Q6pdPeerRecordStore,
    qrun_v06_peer_identity_candidate::{
        create_software_zero_value_testnet_q6pd_identity, load_q6pd_node_identity,
    },
    qrun_v06_permissionless_runtime_candidate::QRunV06PermissionlessNodeRuntime,
    qrun_v06_permissionless_service_candidate::QRunV06PermissionlessMempool,
    qrun_v06_pow_fork_choice_candidate::QRunV06QuoteAssetAuthorizationProvider,
    qrun_v06_pow_fork_store_candidate::QRUN_V06_CHECKPOINT_FILE_NAME,
    qrun_v06_profile_pin_candidate::QRunV06VerifiedProfilePin,
    qrun_v06_profile_trust_candidate::{
        authorize_qrun_v06_profile_pin_from_source, PinnedQRunV06ProfileTrustAuthority,
        QRunV06FreshQuoteAssetAuthorizationProvider, QRunV06ProfileTrustSource,
        QRunV06TrustAuthorizedProfilePin,
    },
    qrun_v06_profile_trust_dynamodb_floor_candidate::AwsDynamoDbQ6tsReadOnlyProfileTrustFloorStore,
    qrun_v06_transaction_mempool_candidate::QRunV06MempoolLimits,
    v4_fat1_mldsa65_candidate::LibcruxMlDsa65VerifierCandidate,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, ToSocketAddrs},
    path::{Component, Path, PathBuf},
    sync::atomic::AtomicBool,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use zeroize::{Zeroize, Zeroizing};

const PUBLIC_TESTNET_LISTENER_ROUND_TIMEOUT: Duration = Duration::from_secs(30);
const PUBLIC_TESTNET_LISTENER_MAX_SESSIONS_PER_ROUND: usize = 6;
// Scheduling policy only: keep the return-to-listener gap short on the zero-value testnet.
// This does not alter the Q6CP consensus target, hash function, or per-block validity rules.
const PUBLIC_TESTNET_MAX_NONCE_ATTEMPTS_PER_SLICE: u64 = 4_096;

fn apply_public_testnet_listener_round_timeout(
    supervisor: &mut QRunV06PermissionlessMiningSupervisorConfig,
    public_testnet: bool,
) {
    if public_testnet {
        // Noise XX has an 8-second absolute handshake budget. A 250 ms listener round
        // cancelled the bounded handshake workers before public TLS/Funnel RTTs completed.
        // Keep private/overlay polling unchanged; give the public zero-value path enough
        // room for the handshake and the first bounded history-sync exchanges.
        supervisor.listener_round_timeout = PUBLIC_TESTNET_LISTENER_ROUND_TIMEOUT;
        supervisor.max_sessions_per_listener_round = PUBLIC_TESTNET_LISTENER_MAX_SESSIONS_PER_ROUND;
    }
}

fn apply_public_testnet_mining_slice(
    supervisor: &mut QRunV06PermissionlessMiningSupervisorConfig,
    public_testnet: bool,
) {
    if public_testnet {
        supervisor.max_nonce_attempts_per_block = supervisor
            .max_nonce_attempts_per_block
            .min(PUBLIC_TESTNET_MAX_NONCE_ATTEMPTS_PER_SLICE);
    }
}
const MAX_PEERS_BYTES: u64 = 16 * 1024;
const MAX_TRUST_DOMAIN_REGISTRY_BYTES: u64 = 64 * 1024;
const MAX_TRUST_DOMAIN_REGISTRY_RELAYS: usize = 256;
const MAX_Q6TS_SIGNED_ENVELOPE_BYTES: u64 = 16 * 1024;
const MAX_Q6QA_BUNDLE_BYTES: u64 = 16 * 1024;

/// Read only a bounded regular file. Trust material may not be transparently redirected through
/// a symlink or device node; the caller still obtains trust from independent pins/signatures.
fn read_regular_bounded(path: &Path, max_bytes: u64, label: &str) -> Result<Vec<u8>, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("{label} metadata: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(format!("{label} must be a regular non-symlink file"));
    }
    read_bounded(path, max_bytes, label)
}

struct PermissionlessFileQ6tsTrustSource {
    path: PathBuf,
}

impl QRunV06ProfileTrustSource for PermissionlessFileQ6tsTrustSource {
    type Error = String;

    fn read_current_signed_record(
        &mut self,
        _network_id: &[u8; 32],
        _profile_id: &[u8; 32],
    ) -> Result<Vec<u8>, Self::Error> {
        read_regular_bounded(
            &self.path,
            MAX_Q6TS_SIGNED_ENVELOPE_BYTES,
            "current Q6TS signed trust envelope",
        )
    }
}

struct PermissionlessQuoteAuthorizationInputs {
    q6qa_bundle_bytes: Vec<u8>,
    authority: PinnedQRunV06ProfileTrustAuthority,
    floor_store: AwsDynamoDbQ6tsReadOnlyProfileTrustFloorStore,
    trust_source: PermissionlessFileQ6tsTrustSource,
}

fn load_permissionless_quote_authorization_inputs(
    base: &Path,
    cfg: &Value,
    profile_pin_bytes: &[u8],
    verified_pin: &QRunV06VerifiedProfilePin,
) -> Result<Option<PermissionlessQuoteAuthorizationInputs>, String> {
    if verified_pin.quote_asset_trust_pin().is_none() {
        for key in [
            "q6qa_bundle_path",
            "q6ts_signed_envelope_path",
            "q6ts_authority_ed25519_public_key_path",
            "q6ts_authority_mldsa65_public_key_path",
            "q6ts_authority_keyset_id",
            "q6ts_floor_aws_cli_path",
            "q6ts_floor_aws_region",
            "q6ts_floor_aws_table",
        ] {
            if cfg.get(key).is_some() {
                return Err(format!(
                    "permissionless_runtime.{key} is forbidden because Q6PN has no quote-asset trust pin"
                ));
            }
        }
        return Ok(None);
    }

    let required_path = |key: &str| -> Result<PathBuf, String> {
        let resolved = resolve_path(
            base,
            req(cfg, key).map_err(|error| format!("Q6QA/Q6TS configuration: {error}"))?,
        );
        if !resolved.is_absolute() {
            return Err(format!(
                "permissionless_runtime.{key} must resolve to an absolute path"
            ));
        }
        Ok(resolved)
    };

    let q6qa_path = required_path("q6qa_bundle_path")?;
    let q6qa_bundle_bytes = read_regular_bounded(
        &q6qa_path,
        MAX_Q6QA_BUNDLE_BYTES,
        "pinned Q6QA qualification bundle",
    )?;

    let q6ts_source_path = required_path("q6ts_signed_envelope_path")?;
    let ed25519_path = required_path("q6ts_authority_ed25519_public_key_path")?;
    let mldsa65_path = required_path("q6ts_authority_mldsa65_public_key_path")?;
    let ed25519_bytes =
        read_regular_bounded(&ed25519_path, 32, "Q6TS Ed25519 authority public key")?;
    let mldsa65_bytes = read_regular_bounded(
        &mldsa65_path,
        ai_native_l1_pow_bench::v4_fat1_trust_candidate::ML_DSA_65_PUBLIC_KEY_BYTES as u64,
        "Q6TS ML-DSA-65 authority public key",
    )?;
    if ed25519_bytes.len() != 32
        || mldsa65_bytes.len()
            != ai_native_l1_pow_bench::v4_fat1_trust_candidate::ML_DSA_65_PUBLIC_KEY_BYTES
    {
        return Err("Q6TS authority public-key file length is invalid".into());
    }
    let authority = PinnedQRunV06ProfileTrustAuthority {
        ed25519_public_key: ed25519_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "invalid Q6TS Ed25519 authority key length")?,
        mldsa65_public_key: mldsa65_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "invalid Q6TS ML-DSA-65 authority key length")?,
    };
    let actual_keyset_id = authority
        .keyset_id()
        .map_err(|error| format!("Q6TS authority keyset is invalid: {error}"))?;
    let expected_keyset_id = parse_hex32(
        "permissionless_runtime.q6ts_authority_keyset_id",
        req(cfg, "q6ts_authority_keyset_id")?,
    )?;
    if actual_keyset_id != expected_keyset_id {
        return Err("Q6TS authority keyset differs from the independently pinned keyset ID".into());
    }

    let aws_cli_path = req(cfg, "q6ts_floor_aws_cli_path")?.to_string();
    if aws_cli_path.len() > 1024 || aws_cli_path.contains('\0') {
        return Err("Q6TS floor AWS CLI path is invalid or exceeds its bound".into());
    }
    let aws_region = req(cfg, "q6ts_floor_aws_region")?.to_string();
    let table = req(cfg, "q6ts_floor_aws_table")?.to_string();
    if aws_region.len() > 128 || table.len() > 255 {
        return Err("Q6TS floor AWS region/table name exceeds its bound".into());
    }
    let floor_store =
        AwsDynamoDbQ6tsReadOnlyProfileTrustFloorStore::new(&aws_cli_path, aws_region, table)
            .map_err(|error| {
                format!("Q6TS independently administered read-only floor unavailable: {error}")
            })?;

    let trust_source = PermissionlessFileQ6tsTrustSource {
        path: q6ts_source_path,
    };
    // Confirm the source file is present and bounded now; each block admission still re-reads it.
    let current_q6ts = read_regular_bounded(
        &trust_source.path,
        MAX_Q6TS_SIGNED_ENVELOPE_BYTES,
        "current Q6TS signed trust envelope",
    )?;
    if current_q6ts.is_empty() || profile_pin_bytes.is_empty() || q6qa_bundle_bytes.is_empty() {
        return Err("Q6PN/Q6TS/Q6QA trust inputs must all be non-empty".into());
    }

    Ok(Some(PermissionlessQuoteAuthorizationInputs {
        q6qa_bundle_bytes,
        authority,
        floor_store,
        trust_source,
    }))
}

/// Reject duplicate keys in every JSON object before materializing the registry as Value.
/// Keys are decoded through serde_json::String, so escaped spellings of the same key collide.
struct JsonObjectKeyScanner<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> JsonObjectKeyScanner<'a> {
    fn skip_whitespace(&mut self) {
        while matches!(
            self.bytes.get(self.cursor),
            Some(b' ' | b'\t' | b'\r' | b'\n')
        ) {
            self.cursor += 1;
        }
    }

    fn scan_string_token(&mut self) -> Result<&'a [u8], String> {
        let start = self.cursor;
        if self.bytes.get(self.cursor) != Some(&b'"') {
            return Err("expected a JSON string while checking duplicate object keys".into());
        }
        self.cursor += 1;
        while let Some(byte) = self.bytes.get(self.cursor).copied() {
            match byte {
                b'\\' => {
                    self.cursor += 1;
                    if self.cursor >= self.bytes.len() {
                        return Err("truncated JSON escape while checking object keys".into());
                    }
                    self.cursor += 1;
                }
                b'"' => {
                    self.cursor += 1;
                    return Ok(&self.bytes[start..self.cursor]);
                }
                _ => self.cursor += 1,
            }
        }
        Err("unterminated JSON string while checking object keys".into())
    }

    fn parse_value(&mut self, depth: usize) -> Result<(), String> {
        if depth > 16 {
            return Err("Q6AR trust-domain registry JSON nesting exceeds 16 levels".into());
        }
        self.skip_whitespace();
        match self.bytes.get(self.cursor).copied() {
            Some(b'{') => self.parse_object(depth + 1),
            Some(b'[') => self.parse_array(depth + 1),
            Some(b'"') => {
                self.scan_string_token()?;
                Ok(())
            }
            Some(_) => {
                let start = self.cursor;
                while let Some(byte) = self.bytes.get(self.cursor).copied() {
                    if matches!(byte, b',' | b']' | b'}' | b' ' | b'\t' | b'\r' | b'\n') {
                        break;
                    }
                    self.cursor += 1;
                }
                if self.cursor == start {
                    return Err("invalid JSON value while checking duplicate object keys".into());
                }
                Ok(())
            }
            None => Err("unexpected end of JSON while checking duplicate object keys".into()),
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<(), String> {
        self.cursor += 1;
        self.skip_whitespace();
        if self.bytes.get(self.cursor) == Some(&b'}') {
            self.cursor += 1;
            return Ok(());
        }
        let mut keys = std::collections::BTreeSet::new();
        loop {
            self.skip_whitespace();
            let token = self.scan_string_token()?;
            let key: String = serde_json::from_slice(token)
                .map_err(|error| format!("invalid JSON object key: {error}"))?;
            if !keys.insert(key) {
                return Err(
                    "Q6AR trust-domain registry contains a duplicate JSON object key".into(),
                );
            }
            self.skip_whitespace();
            if self.bytes.get(self.cursor) != Some(&b':') {
                return Err("expected ':' after JSON object key".into());
            }
            self.cursor += 1;
            self.parse_value(depth)?;
            self.skip_whitespace();
            match self.bytes.get(self.cursor) {
                Some(b',') => self.cursor += 1,
                Some(b'}') => {
                    self.cursor += 1;
                    return Ok(());
                }
                _ => return Err("expected ',' or '}' after JSON object value".into()),
            }
        }
    }

    fn parse_array(&mut self, depth: usize) -> Result<(), String> {
        self.cursor += 1;
        self.skip_whitespace();
        if self.bytes.get(self.cursor) == Some(&b']') {
            self.cursor += 1;
            return Ok(());
        }
        loop {
            self.parse_value(depth)?;
            self.skip_whitespace();
            match self.bytes.get(self.cursor) {
                Some(b',') => self.cursor += 1,
                Some(b']') => {
                    self.cursor += 1;
                    return Ok(());
                }
                _ => return Err("expected ',' or ']' after JSON array value".into()),
            }
        }
    }
}

fn reject_duplicate_json_object_keys(bytes: &[u8]) -> Result<(), String> {
    let mut scanner = JsonObjectKeyScanner { bytes, cursor: 0 };
    scanner.parse_value(0)?;
    scanner.skip_whitespace();
    if scanner.cursor != bytes.len() {
        return Err("trailing data after Q6AR trust-domain registry JSON".into());
    }
    Ok(())
}

/// Permissionless QFP6 admits only CP-0651: 7B total ceiling, 1B owner Genesis,
/// six non-circulating 1B accounting labels, and zero block subsidy. Historical
/// CP-0528/CP-0604 snapshots remain decodable but cannot start this runtime.
fn validate_permissionless_cp0651_genesis(
    genesis: &QRunV06CanonicalExecutionState,
    owner_account: &[u8; 32],
    policy_fingerprint: &[u8; 32],
) -> Result<(), String> {
    let supply = genesis.cp0651_supply().ok_or_else(|| {
        "permissionless QFP6 requires CP-0651 fixed-supply 7B/1B/six-labels/zero-subsidy Genesis".to_string()
    })?;
    if genesis.tokenomics().is_some()
        || genesis.cp0604_supply().is_some()
        || supply.owner_account() != *owner_account
        || supply.policy_fingerprint() != *policy_fingerprint
        || supply.maximum_supply_atoms() != 7 * CP0651_OWNER_GENESIS_ATOMS
        || supply.owner_genesis_atoms() != CP0651_OWNER_GENESIS_ATOMS
        || supply.last_block_height() != 0
        || supply.block_subsidy_atoms() != 0
        || supply.accounting_labels_total_atoms() != 6 * CP0651_OWNER_GENESIS_ATOMS
    {
        return Err("permissionless Genesis CP-0651 owner/policy identity, label budget, or zero pre-mining height mismatch".into());
    }
    let owner_balance = genesis
        .unified()
        .ledger()
        .account(owner_account)
        .map_or(0u128, |account| account.balance as u128);
    if owner_balance != CP0651_OWNER_GENESIS_ATOMS {
        return Err(
            "permissionless CP-0651 Genesis must credit exactly 1B QZXB to the owner".into(),
        );
    }
    let ledger_total = genesis
        .unified()
        .ledger()
        .total_value()
        .map_err(|error| format!("permissionless Genesis Ledger total failed: {error:?}"))?;
    supply
        .validate_ledger_supply(ledger_total)
        .map_err(|error| {
            format!("permissionless Genesis CP-0651 fixed-supply invariant failed: {error:?}")
        })
}

fn req<'a>(v: &'a Value, key: &str) -> Result<&'a str, String> {
    v.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| format!("permissionless_runtime.{key} is required"))
}
fn path(base: &Path, v: &Value, key: &str) -> Result<PathBuf, String> {
    let p = resolve_path(base, req(v, key)?);
    if !p.is_absolute() {
        return Err(format!(
            "permissionless_runtime.{key} must resolve to an absolute path"
        ));
    }
    Ok(p)
}
/// Normalize absolute path components for a conservative, platform-aware overlap check.
/// Parent traversal is rejected rather than interpreted. Components are case-folded because
/// the Windows filesystem used by this launcher is case-insensitive by default.
fn normalized_absolute_path_components(path: &Path, label: &str) -> Result<Vec<String>, String> {
    if !path.is_absolute() {
        return Err(format!("{label} must resolve to an absolute path"));
    }
    let mut normalized = Vec::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => {
                normalized.push(prefix.as_os_str().to_string_lossy().to_lowercase());
            }
            Component::RootDir => normalized.push(std::path::MAIN_SEPARATOR.to_string()),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(format!(
                    "{label} must not contain parent-directory traversal"
                ));
            }
            Component::Normal(part) => {
                normalized.push(part.to_string_lossy().to_lowercase());
            }
        }
    }
    if normalized.is_empty() {
        return Err(format!("{label} did not resolve to a usable absolute path"));
    }
    Ok(normalized)
}

fn path_components_overlap(a: &[String], b: &[String]) -> bool {
    let is_prefix = |candidate: &[String], full: &[String]| {
        candidate.len() <= full.len()
            && candidate
                .iter()
                .zip(full.iter())
                .all(|(left, right)| left == right)
    };
    is_prefix(a, b) || is_prefix(b, a)
}

/// Keep the independently persisted Anchor Vault outside both mutable runtime trees.
/// This is a lexical path isolation guard; it does not prove that paths are on distinct
/// physical disks or that junctions/reparse points cannot alias the same storage.
fn validate_anchor_vault_path_separation(
    vault_path: &Path,
    data_path: &Path,
    mempool_path: &Path,
) -> Result<(), String> {
    let vault =
        normalized_absolute_path_components(vault_path, "trusted_manifest_anchor_vault_path")?;
    for (label, candidate) in [
        ("data_directory", data_path),
        ("mempool_directory", mempool_path),
    ] {
        let other = normalized_absolute_path_components(candidate, label)?;
        if path_components_overlap(&vault, &other) {
            return Err(format!(
                "trusted_manifest_anchor_vault_path must be separate and non-nested from {label}"
            ));
        }
    }
    Ok(())
}

fn endpoint(name: &str, text: &str, allow_unspecified: bool) -> Result<SocketAddr, String> {
    let a: SocketAddr = text
        .parse()
        .map_err(|_| format!("{name} must be a numeric SocketAddr"))?;
    if a.port() == 0 || a.ip().is_multicast() || (!allow_unspecified && a.ip().is_unspecified()) {
        return Err(format!("{name} is not a valid unicast endpoint"));
    }
    Ok(a)
}
fn requires_public_listener_opt_in(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(address) => {
            let octets = address.octets();
            let shared = octets[0] == 100 && (64..=127).contains(&octets[1]);
            address.is_unspecified()
                || !(address.is_loopback()
                    || address.is_private()
                    || address.is_link_local()
                    || shared)
        }
        std::net::IpAddr::V6(address) => {
            let octets = address.octets();
            let unique_local = octets[0] & 0xfe == 0xfc;
            let link_local = octets[0] == 0xfe && octets[1] & 0xc0 == 0x80;
            address.is_unspecified() || !(address.is_loopback() || unique_local || link_local)
        }
    }
}

fn validate_public_listener_opt_in(runtime: &Value, listen: SocketAddr) -> Result<(), String> {
    if requires_public_listener_opt_in(listen.ip())
        && runtime
            .get("allow_public_listener")
            .and_then(Value::as_bool)
            != Some(true)
    {
        return Err("wildcard/public listen_address requires permissionless_runtime.allow_public_listener=true".into());
    }
    Ok(())
}
fn is_valid_public_dns_name(host: &str) -> bool {
    if host.is_empty()
        || host.len() > 253
        || host.ends_with('.')
        || host.parse::<IpAddr>().is_ok()
        || host
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return false;
    }
    let lower = host.to_ascii_lowercase();
    if lower == "localhost"
        || [
            ".localhost",
            ".local",
            ".internal",
            ".test",
            ".invalid",
            ".example",
        ]
        .iter()
        .any(|suffix| lower.ends_with(suffix))
    {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|label| {
            let bytes = label.as_bytes();
            !bytes.is_empty()
                && bytes.len() <= 63
                && bytes[0].is_ascii_alphanumeric()
                && bytes[bytes.len() - 1].is_ascii_alphanumeric()
                && bytes
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        })
}

fn resolve_bootstrap_endpoint_with<F>(
    name: &str,
    text: &str,
    allow_dns_relay: bool,
    mut resolve: F,
) -> Result<(SocketAddr, Option<String>), String>
where
    F: FnMut(&str, u16) -> Result<Vec<SocketAddr>, String>,
{
    // Preserve the existing numeric SocketAddr behavior, including local-only test fixtures.
    if let Ok(address) = endpoint(name, text, false) {
        return Ok((address, None));
    }
    if !allow_dns_relay {
        return Err(format!(
            "{name} must be a numeric SocketAddr; DNS relay endpoints are allowed only for zero-value Public Testnet"
        ));
    }

    // DNS names are deliberately limited to FQDN:443. The hostname is retained in the
    // hash-pinned bootstrap file; the resolved numeric address is fixed for this process run.
    let (host, port_text) = text
        .rsplit_once(':')
        .ok_or_else(|| format!("{name} must be an FQDN:443 relay endpoint"))?;
    if host.contains(':') || host.starts_with('[') || host.ends_with(']') {
        return Err(format!(
            "{name} DNS relay endpoint must use an unbracketed FQDN"
        ));
    }
    let port = port_text
        .parse::<u16>()
        .map_err(|_| format!("{name} DNS relay port is invalid"))?;
    if port != 443 {
        return Err(format!("{name} DNS relay endpoint must use TCP port 443"));
    }
    if !is_valid_public_dns_name(host) {
        return Err(format!(
            "{name} DNS relay hostname is not a valid public FQDN"
        ));
    }

    let mut addresses = resolve(host, port)
        .map_err(|error| format!("{name} DNS resolution failed for {host}: {error}"))?;
    if addresses.is_empty() || addresses.len() > 16 {
        return Err(format!(
            "{name} DNS resolution must return between 1 and 16 addresses"
        ));
    }
    addresses.sort_unstable();
    addresses.dedup();
    if addresses
        .iter()
        .any(|address| address.port() != port || !is_publicly_routable_peer_ip(address.ip()))
    {
        return Err(format!(
            "{name} DNS relay must resolve only to globally routable unicast addresses"
        ));
    }
    Ok((addresses[0], Some(host.to_ascii_lowercase())))
}

fn load_peers(
    path: &Path,
    expected_sha: [u8; 32],
    allow_dns_relay: bool,
) -> Result<Vec<QRunV06PinnedBootstrapPeer>, String> {
    load_peers_with_resolver(path, expected_sha, allow_dns_relay, |host, port| {
        (host, port)
            .to_socket_addrs()
            .map(|addresses| addresses.collect())
            .map_err(|error| error.to_string())
    })
}

fn load_peers_with_resolver<F>(
    path: &Path,
    expected_sha: [u8; 32],
    allow_dns_relay: bool,
    mut resolve: F,
) -> Result<Vec<QRunV06PinnedBootstrapPeer>, String>
where
    F: FnMut(&str, u16) -> Result<Vec<SocketAddr>, String>,
{
    let bytes = read_bounded(path, MAX_PEERS_BYTES, "permissionless bootstrap peer set")?;
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    if digest != expected_sha {
        return Err(
            "bootstrap peer set SHA-256 mismatch against independently pinned config".into(),
        );
    }
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("invalid bootstrap peer JSON: {e}"))?;
    let rows = value
        .as_array()
        .ok_or("bootstrap peer set must be a JSON array")?;
    if rows.len() > 64 {
        return Err("bootstrap peer set must contain at most 64 peers".into());
    }
    let mut peers = Vec::with_capacity(rows.len());
    for (i, row) in rows.iter().enumerate() {
        let (address, tls_server_name) = resolve_bootstrap_endpoint_with(
            &format!("bootstrap peer {i}"),
            row.get("address")
                .and_then(Value::as_str)
                .ok_or("bootstrap peer address missing")?,
            allow_dns_relay,
            |host, port| resolve(host, port),
        )?;
        let key = row
            .get("noise_static_public_key")
            .and_then(Value::as_str)
            .ok_or("bootstrap peer Noise key missing")?;
        peers.push(QRunV06PinnedBootstrapPeer {
            address,
            noise_static_public_key: parse_hex32("bootstrap peer Noise key", key)?,
            tls_server_name,
        });
    }
    if !peers.is_empty() {
        validate_qfp6_pinned_bootstrap_peers(&peers)
            .map_err(|e| format!("invalid bootstrap peer pins: {e:?}"))?;
    }
    Ok(peers)
}

fn q6ar_candidate_address_book_enabled(cfg: &Value) -> Result<bool, String> {
    match cfg.get("enable_q6ar_candidate_address_book") {
        None => Ok(false),
        Some(Value::Bool(enabled)) => Ok(*enabled),
        Some(_) => Err(
            "permissionless_runtime.enable_q6ar_candidate_address_book must be a boolean".into(),
        ),
    }
}

/// Enable signed Q6PD peer-record exchange; default OFF to preserve older node behavior.
fn q6pd_peer_discovery_enabled(cfg: &Value) -> Result<bool, String> {
    match cfg.get("enable_q6pd_peer_discovery") {
        None => Ok(false),
        Some(Value::Bool(enabled)) => Ok(*enabled),
        Some(_) => {
            Err("permissionless_runtime.enable_q6pd_peer_discovery must be a boolean".into())
        }
    }
}

/// Pull only from explicitly selected pinned peers after those peers have been upgraded.
fn q6pd_peer_pull_enabled(cfg: &Value) -> Result<bool, String> {
    match cfg.get("enable_q6pd_peer_pull") {
        None => Ok(false),
        Some(Value::Bool(enabled)) => Ok(*enabled),
        Some(_) => Err("permissionless_runtime.enable_q6pd_peer_pull must be a boolean".into()),
    }
}

/// A genesis-rooted Seed has no upstream peer to pin: it receives signed Q6PD
/// announcements from joining nodes, relays the verified records, and may dial
/// those signed candidates. Joining nodes still require at least one pinned seed.
fn q6pd_peer_pull_requires_operator_pinned_seed(node_role: &str, peer_count: usize) -> bool {
    !node_role.eq_ignore_ascii_case("seed") && peer_count == 0
}

/// Publish this node's own TPM-bound signed endpoint record; default OFF.
fn q6pd_self_announcement_enabled(cfg: &Value) -> Result<bool, String> {
    match cfg.get("enable_q6pd_self_announcement") {
        None => Ok(false),
        Some(Value::Bool(enabled)) => Ok(*enabled),
        Some(_) => {
            Err("permissionless_runtime.enable_q6pd_self_announcement must be a boolean".into())
        }
    }
}

/// Standalone operator address book; independent of Q6AR candidate exchange.
fn peer_address_book_enabled(cfg: &Value) -> Result<bool, String> {
    match cfg.get("enable_peer_address_book") {
        None => Ok(false),
        Some(Value::Bool(enabled)) => Ok(*enabled),
        Some(_) => Err("permissionless_runtime.enable_peer_address_book must be a boolean".into()),
    }
}

/// Pull inventory only from bootstrap relays that the operator has separately verified
/// already support Q6PQ/Q6PL. Defaults off so older peers never receive an unknown frame.
fn q6ar_candidate_pull_enabled(cfg: &Value) -> Result<bool, String> {
    match cfg.get("enable_q6ar_candidate_pull") {
        None => Ok(false),
        Some(Value::Bool(enabled)) => Ok(*enabled),
        Some(_) => {
            Err("permissionless_runtime.enable_q6ar_candidate_pull must be a boolean".into())
        }
    }
}

/// Explicitly authorize a registry fingerprint change. This setting is covered by the
/// independently pinned permissionless config SHA-256 and defaults to disabled.
fn q6ar_trust_domains_rotation_authorized(cfg: &Value) -> Result<bool, String> {
    match cfg.get("q6ar_trust_domains_rotation_authorized") {
        None => Ok(false),
        Some(Value::Bool(authorized)) => Ok(*authorized),
        Some(_) => Err(
            "permissionless_runtime.q6ar_trust_domains_rotation_authorized must be a boolean"
                .into(),
        ),
    }
}

/// Decode a locally provisioned trust-domain registry whose bytes are pinned by the
/// independently hashed permissionless runtime config. Domains are never read from peers.
fn decode_q6ar_trust_domain_registry(
    bytes: &[u8],
    expected_sha: [u8; 32],
    pinned_relays: &[[u8; 32]],
) -> Result<BootstrapTrustDomainPolicy, String> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_TRUST_DOMAIN_REGISTRY_BYTES {
        return Err("Q6AR trust-domain registry is empty or exceeds its byte limit".into());
    }
    let actual_sha: [u8; 32] = Sha256::digest(bytes).into();
    if actual_sha != expected_sha {
        return Err(
            "Q6AR trust-domain registry SHA-256 mismatch against independently pinned config"
                .into(),
        );
    }
    reject_duplicate_json_object_keys(bytes)?;
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("invalid Q6AR trust-domain registry JSON: {error}"))?;
    let object = value
        .as_object()
        .ok_or("Q6AR trust-domain registry must be a JSON object")?;
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "version" | "max_candidates_per_domain" | "max_relays_per_domain" | "assignments"
        )
    }) {
        return Err("Q6AR trust-domain registry contains an unknown top-level field".into());
    }
    if value.get("version").and_then(Value::as_u64) != Some(1) {
        return Err("Q6AR trust-domain registry version must be exactly 1".into());
    }
    let max_candidates = value
        .get("max_candidates_per_domain")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or("Q6AR trust-domain registry max_candidates_per_domain is required")?;
    let max_relays = value
        .get("max_relays_per_domain")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or("Q6AR trust-domain registry max_relays_per_domain is required")?;
    let rows = value
        .get("assignments")
        .and_then(Value::as_array)
        .filter(|rows| !rows.is_empty() && rows.len() <= MAX_TRUST_DOMAIN_REGISTRY_RELAYS)
        .ok_or("Q6AR trust-domain registry assignments must contain 1..=256 rows")?;
    let mut assignments = Vec::with_capacity(rows.len());
    for (index, row) in rows.iter().enumerate() {
        let entry = row
            .as_object()
            .ok_or_else(|| format!("Q6AR trust-domain assignment {index} must be an object"))?;
        if entry
            .keys()
            .any(|key| !matches!(key.as_str(), "relay_static_public_key" | "trust_domain_id"))
        {
            return Err(format!(
                "Q6AR trust-domain assignment {index} contains an unknown field"
            ));
        }
        let relay = row
            .get("relay_static_public_key")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                format!("Q6AR trust-domain assignment {index} is missing relay_static_public_key")
            })?;
        let domain = row
            .get("trust_domain_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                format!("Q6AR trust-domain assignment {index} is missing trust_domain_id")
            })?;
        assignments.push((
            parse_hex32("q6ar_trust_domains.relay_static_public_key", relay)?,
            parse_hex32("q6ar_trust_domains.trust_domain_id", domain)?,
        ));
    }
    let policy = BootstrapTrustDomainPolicy::new(assignments, max_candidates, max_relays)
        .map_err(|error| format!("invalid Q6AR operator trust-domain policy: {error:?}"))?;
    for relay in pinned_relays {
        policy.domain_for(relay).map_err(|error| {
            format!(
                "pinned Q6AR relay {} has no operator trust-domain assignment: {error:?}",
                relay
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            )
        })?;
    }
    Ok(policy)
}

fn load_q6ar_trust_domain_registry(
    base: &Path,
    cfg: &Value,
    pinned_relays: &[[u8; 32]],
) -> Result<BootstrapTrustDomainPolicy, String> {
    let registry_path = path(base, cfg, "q6ar_trust_domains_path")?;
    let expected_sha = parse_hex32(
        "q6ar_trust_domains_sha256",
        req(cfg, "q6ar_trust_domains_sha256")?,
    )?;
    let bytes = read_bounded(
        &registry_path,
        MAX_TRUST_DOMAIN_REGISTRY_BYTES,
        "Q6AR operator trust-domain registry",
    )?;
    decode_q6ar_trust_domain_registry(&bytes, expected_sha, pinned_relays)
}

/// Separate operator policy for approved peer-book pins when Q6AR is disabled.
/// The exact same bounded trust-domain schema is used, but it has independent path/hash pins.
fn load_peer_trust_domain_registry(
    base: &Path,
    cfg: &Value,
    approved_peer_keys: &[[u8; 32]],
) -> Result<BootstrapTrustDomainPolicy, String> {
    let registry_path = path(base, cfg, "peer_trust_domains_path")?;
    let expected_sha = parse_hex32(
        "peer_trust_domains_sha256",
        req(cfg, "peer_trust_domains_sha256")?,
    )?;
    let bytes = read_bounded(
        &registry_path,
        MAX_TRUST_DOMAIN_REGISTRY_BYTES,
        "operator peer trust-domain registry",
    )?;
    decode_q6ar_trust_domain_registry(&bytes, expected_sha, approved_peer_keys)
}

fn approved_peer_outbound_sync_enabled(cfg: &Value) -> Result<bool, String> {
    match cfg.get("enable_approved_peer_outbound_sync") {
        None => Ok(false),
        Some(Value::Bool(enabled)) => Ok(*enabled),
        Some(_) => Err(
            "permissionless_runtime.enable_approved_peer_outbound_sync must be a boolean".into(),
        ),
    }
}

fn select_approved_bootstrap_peers(
    candidates: &[(SocketAddr, [u8; 32])],
    configured_bootstrap_peers: &[QRunV06PinnedBootstrapPeer],
    policy: &BootstrapTrustDomainPolicy,
    max_attempts: usize,
) -> Result<Vec<QRunV06PinnedBootstrapPeer>, String> {
    if candidates.is_empty() || max_attempts == 0 {
        return Err(
            "approved bootstrap peer selection requires candidates and a nonzero attempt budget"
                .into(),
        );
    }
    let domain_order_input: Vec<([u8; 32], QRunV06PinnedBootstrapPeer)> = candidates
        .iter()
        .map(|(address, noise_static_public_key)| {
            // If the approved Noise identity is one of the hash-pinned configured DNS
            // relays, keep its current launch-time DNS answer and TLS SNI. Q6AR stores
            // numeric SocketAddr pins only, so rebuilding from that book alone would
            // otherwise silently strip the SNI and break TLS-terminated Funnel relays.
            let configured = configured_bootstrap_peers
                .iter()
                .find(|peer| peer.noise_static_public_key == *noise_static_public_key);
            let (selected_address, tls_server_name) = match configured {
                Some(peer) if peer.tls_server_name.is_some() => {
                    (peer.address, peer.tls_server_name.clone())
                }
                _ => (*address, None),
            };
            (
                *noise_static_public_key,
                QRunV06PinnedBootstrapPeer {
                    address: selected_address,
                    noise_static_public_key: *noise_static_public_key,
                    tls_server_name,
                },
            )
        })
        .collect();
    let selected: Vec<QRunV06PinnedBootstrapPeer> = policy
        .order_relays_by_domain(&domain_order_input)
        .map_err(|error| {
            format!("cannot order approved bootstrap peers by operator trust domain: {error:?}")
        })?
        .into_iter()
        .take(max_attempts)
        .collect();
    validate_qfp6_pinned_bootstrap_peers(&selected)
        .map_err(|error| format!("operator-approved peer pins invalid: {error:?}"))?;
    Ok(selected)
}

fn max_approved_peer_sync_attempts(cfg: &Value) -> Result<usize, String> {
    let value = match cfg.get("max_approved_peer_sync_attempts") {
        None => 1,
        Some(value) => value.as_u64().ok_or(
            "permissionless_runtime.max_approved_peer_sync_attempts must be an unsigned integer",
        )?,
    };
    let value =
        usize::try_from(value).map_err(|_| "max_approved_peer_sync_attempts is out of range")?;
    if !(1..=4).contains(&value) {
        return Err(
            "permissionless_runtime.max_approved_peer_sync_attempts must be between 1 and 4".into(),
        );
    }
    Ok(value)
}

const LOCAL_ANCHOR_VAULT_SCHEMA: &str = "qfp6-local-anchor-vault/v1";
const LOCAL_ANCHOR_VAULT_DOMAIN: &[u8] = b"QFP6-LOCAL-ANCHOR-VAULT-RECORD-V1\0";
const MAX_LOCAL_ANCHOR_VAULT_RECORDS: usize = 100_000;
const MAX_LOCAL_ANCHOR_VAULT_RECORD_BYTES: u64 = 4096;

fn local_anchor_vault_directory(cfg: &Value) -> Result<PathBuf, String> {
    if let Some(value) = cfg.get("trusted_manifest_anchor_vault_path") {
        let text = value
            .as_str()
            .filter(|text| !text.trim().is_empty())
            .ok_or("trusted_manifest_anchor_vault_path must be a non-empty absolute path")?;
        let path = PathBuf::from(text);
        if !path.is_absolute() {
            return Err("trusted_manifest_anchor_vault_path must be absolute".into());
        }
        return Ok(path);
    }
    let local_app_data = std::env::var_os("LOCALAPPDATA")
        .ok_or("LOCALAPPDATA is unavailable; QFP6 local anchor vault cannot be located")?;
    let root = PathBuf::from(local_app_data);
    if !root.is_absolute() {
        return Err("LOCALAPPDATA did not resolve to an absolute path".into());
    }
    Ok(root.join("AI_NATIVE_L1").join("QFP6").join("anchor-vault"))
}

fn checkpoint_segments_directory(data_dir: &Path) -> Result<PathBuf, String> {
    let parent = data_dir
        .parent()
        .ok_or("permissionless data_directory has no parent for checkpoint segments")?;
    let name = data_dir
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .ok_or("permissionless data_directory has no usable final component")?;
    let root = parent.join(format!("{name}.checkpoint-segments"));
    match fs::symlink_metadata(&root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "cannot inspect checkpoint segments directory: {error}"
            ));
        }
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err("checkpoint segments root must be a real non-symlink directory".into());
        }
        Ok(_) => {}
    }
    Ok(root)
}

fn read_checkpoint_segment(data_dir: &Path, sequence: u64) -> Result<(PathBuf, Vec<u8>), String> {
    let root = checkpoint_segments_directory(data_dir)?;
    let segment_dir = root.join(format!("segment-{sequence:020}"));
    let metadata = fs::symlink_metadata(&segment_dir)
        .map_err(|error| format!("checkpoint segment directory metadata: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("active checkpoint segment must be a real non-symlink directory".into());
    }
    let checkpoint_path = segment_dir.join(QRUN_V06_CHECKPOINT_FILE_NAME);
    let checkpoint_bytes = read_regular_bounded(
        &checkpoint_path,
        MAX_QRUN_V06_CHECKPOINT_BYTES as u64,
        "active QFP6 checkpoint snapshot",
    )?;
    Ok((segment_dir, checkpoint_bytes))
}

fn parse_local_anchor_record_digest(label: &str, text: &str) -> Result<[u8; 32], String> {
    if text.len() != 64
        || !text.is_ascii()
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "{label} must be exactly 64 lowercase hexadecimal characters"
        ));
    }
    let mut digest = [0u8; 32];
    for (index, slot) in digest.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|_| format!("{label} contains a non-hexadecimal byte"))?;
    }
    Ok(digest)
}

fn local_anchor_record_digest(record: &Value) -> Result<[u8; 32], String> {
    let sequence = record
        .get("sequence")
        .and_then(Value::as_u64)
        .filter(|value| *value > 0)
        .ok_or("local anchor record sequence is invalid")?;
    let generation = record
        .get("manifest_generation")
        .and_then(Value::as_u64)
        .ok_or("local anchor record manifest_generation is invalid")?;
    let network = parse_hex32(
        "local anchor record network_id_hex",
        record
            .get("network_id_hex")
            .and_then(Value::as_str)
            .ok_or("local anchor record network_id_hex is missing")?,
    )?;
    let profile = parse_hex32(
        "local anchor record profile_id_hex",
        record
            .get("profile_id_hex")
            .and_then(Value::as_str)
            .ok_or("local anchor record profile_id_hex is missing")?,
    )?;
    let anchor = parse_hex32(
        "local anchor record manifest_anchor_hex",
        record
            .get("manifest_anchor_hex")
            .and_then(Value::as_str)
            .ok_or("local anchor record manifest_anchor_hex is missing")?,
    )?;
    let previous = parse_local_anchor_record_digest(
        "local anchor record previous_record_sha256",
        record
            .get("previous_record_sha256")
            .and_then(Value::as_str)
            .ok_or("local anchor record previous_record_sha256 is missing")?,
    )?;
    if anchor == [0; 32] {
        return Err("local anchor record manifest anchor must not be zero".into());
    }
    let mut hash = Sha256::new();
    hash.update(LOCAL_ANCHOR_VAULT_DOMAIN);
    hash.update(sequence.to_be_bytes());
    hash.update(network);
    hash.update(profile);
    hash.update(generation.to_be_bytes());
    hash.update(anchor);
    hash.update(previous);
    Ok(hash.finalize().into())
}

fn trusted_manifest_floor(cfg: &Value) -> Result<(u64, [u8; 32]), String> {
    let generation = cfg
        .get("trusted_manifest_floor_generation")
        .and_then(Value::as_u64)
        .ok_or("permissionless trusted_manifest_floor_generation must be an unsigned integer")?;
    let anchor_text = cfg
        .get("trusted_manifest_floor_anchor")
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty())
        .ok_or("permissionless trusted_manifest_floor_anchor must be a non-empty 64-hex string")?;
    let anchor = parse_hex32("trusted_manifest_floor_anchor", anchor_text)?;
    Ok((generation, anchor))
}
/// Verify the full append-only vault chain on the separate local system volume.
/// This detects D:-only rollback while the C: vault remains intact. It is not a TPM
/// monotonic counter and cannot defeat full-machine/two-disk rollback.
fn validate_local_anchor_vault(
    cfg: &Value,
    expected_network_id: &[u8; 32],
    expected_profile_id: &[u8; 32],
    data_latest_generation: u64,
    configured_root_anchor: &[u8; 32],
    external_floor_generation: u64,
    external_floor_anchor: &[u8; 32],
) -> Result<(u64, [u8; 32]), String> {
    let root = local_anchor_vault_directory(cfg)?;
    let root_meta = fs::symlink_metadata(&root)
        .map_err(|error| format!("local QFP6 anchor vault unavailable: {error}"))?;
    if root_meta.file_type().is_symlink() || !root_meta.is_dir() {
        return Err("local QFP6 anchor vault must be a real directory".into());
    }
    let records_dir = root.join("records");
    let records_meta = fs::symlink_metadata(&records_dir)
        .map_err(|error| format!("local QFP6 anchor vault records unavailable: {error}"))?;
    if records_meta.file_type().is_symlink() || !records_meta.is_dir() {
        return Err("local QFP6 anchor vault records path must be a real directory".into());
    }

    let mut paths = Vec::<(u64, PathBuf)>::new();
    for entry in fs::read_dir(&records_dir)
        .map_err(|error| format!("cannot enumerate local anchor vault records: {error}"))?
    {
        let entry =
            entry.map_err(|error| format!("cannot read local anchor vault entry: {error}"))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let sequence_text = name
            .strip_prefix("q6av-")
            .and_then(|value| value.strip_suffix(".json"))
            .ok_or_else(|| format!("unexpected local anchor vault entry: {name}"))?;
        if sequence_text.len() != 20 || !sequence_text.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(format!(
                "invalid local anchor vault record filename: {name}"
            ));
        }
        let sequence = sequence_text
            .parse::<u64>()
            .map_err(|_| format!("invalid local anchor vault sequence in filename: {name}"))?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("local anchor record metadata: {error}"))?;
        if metadata.file_type().is_symlink()
            || !metadata.file_type().is_file()
            || metadata.len() > MAX_LOCAL_ANCHOR_VAULT_RECORD_BYTES
        {
            return Err(format!(
                "local anchor record must be a bounded regular file: {name}"
            ));
        }
        paths.push((sequence, path));
    }
    paths.sort_by_key(|(sequence, _)| *sequence);
    if paths.is_empty() || paths.len() > MAX_LOCAL_ANCHOR_VAULT_RECORDS {
        return Err("local QFP6 anchor vault is empty or exceeds its record-count limit".into());
    }

    let mut previous_digest = [0u8; 32];
    let mut previous_generation = None::<u64>;
    let mut root_anchor = None::<[u8; 32]>;
    let mut latest_anchor = None::<[u8; 32]>;
    let mut latest_generation = None::<u64>;
    let mut external_floor_matched = false;
    for (index, (sequence, path)) in paths.iter().enumerate() {
        let expected_sequence = (index as u64)
            .checked_add(1)
            .ok_or("local anchor vault sequence overflow")?;
        if *sequence != expected_sequence {
            return Err(format!(
                "local QFP6 anchor vault sequence gap: expected {expected_sequence}, found {sequence}"
            ));
        }
        let bytes = read_regular_bounded(
            path,
            MAX_LOCAL_ANCHOR_VAULT_RECORD_BYTES,
            "local QFP6 anchor vault record",
        )?;
        let record: Value = serde_json::from_slice(&bytes)
            .map_err(|error| format!("invalid local QFP6 anchor vault JSON: {error}"))?;
        if record.get("schema").and_then(Value::as_str) != Some(LOCAL_ANCHOR_VAULT_SCHEMA)
            || record.get("sequence").and_then(Value::as_u64) != Some(*sequence)
        {
            return Err(format!(
                "local QFP6 anchor vault schema/sequence mismatch: {}",
                path.display()
            ));
        }
        let network = parse_hex32(
            "local anchor record network_id_hex",
            record
                .get("network_id_hex")
                .and_then(Value::as_str)
                .ok_or("local anchor network ID missing")?,
        )?;
        let profile = parse_hex32(
            "local anchor record profile_id_hex",
            record
                .get("profile_id_hex")
                .and_then(Value::as_str)
                .ok_or("local anchor profile ID missing")?,
        )?;
        let generation = record
            .get("manifest_generation")
            .and_then(Value::as_u64)
            .ok_or("local anchor record manifest_generation missing")?;
        let anchor = parse_hex32(
            "local anchor record manifest_anchor_hex",
            record
                .get("manifest_anchor_hex")
                .and_then(Value::as_str)
                .ok_or("local anchor value missing")?,
        )?;
        let previous = parse_local_anchor_record_digest(
            "local anchor record previous_record_sha256",
            record
                .get("previous_record_sha256")
                .and_then(Value::as_str)
                .ok_or("local anchor predecessor digest missing")?,
        )?;
        if network != *expected_network_id || profile != *expected_profile_id {
            return Err("local QFP6 anchor vault belongs to a different network/profile".into());
        }
        if generation == external_floor_generation {
            if anchor != *external_floor_anchor {
                return Err(
                    "local QFP6 anchor vault does not match the independently pinned generation floor"
                        .into(),
                );
            }
            external_floor_matched = true;
        }
        if previous != previous_digest {
            return Err(format!(
                "local QFP6 anchor vault predecessor mismatch at sequence {sequence}"
            ));
        }
        if let Some(old_generation) = previous_generation {
            let expected_generation = old_generation
                .checked_add(1)
                .ok_or("local anchor vault generation overflow")?;
            if generation != expected_generation {
                return Err(format!(
                    "local QFP6 anchor vault generation gap: expected {expected_generation}, found {generation}"
                ));
            }
        }
        let expected_digest = local_anchor_record_digest(&record)?;
        let stored_digest = parse_hex32(
            "local anchor record record_sha256",
            record
                .get("record_sha256")
                .and_then(Value::as_str)
                .ok_or("local anchor record digest missing")?,
        )?;
        if stored_digest != expected_digest {
            return Err(format!(
                "local QFP6 anchor vault checksum mismatch at sequence {sequence}"
            ));
        }
        previous_digest = stored_digest;
        previous_generation = Some(generation);
        if root_anchor.is_none() {
            root_anchor = Some(anchor);
        }
        latest_generation = Some(generation);
        latest_anchor = Some(anchor);
    }

    if root_anchor != Some(*configured_root_anchor) {
        return Err("permissionless trusted_manifest_anchor does not match the immutable sequence-1 C: vault root".into());
    }
    if !external_floor_matched {
        return Err(format!(
            "local QFP6 anchor vault is below or missing independently pinned floor generation {external_floor_generation}"
        ));
    }
    let vault_generation = latest_generation.ok_or("local anchor vault has no tip generation")?;
    let vault_anchor = latest_anchor.ok_or("local anchor vault has no tip anchor")?;
    let checked_vault = QRunV06LocalAnchorVault::open(
        local_anchor_vault_directory(cfg)?,
        *expected_network_id,
        *expected_profile_id,
    )
    .map_err(|error| format!("C: anchor vault/witness-chain verification failed: {error}"))?;
    if checked_vault.root_anchor() != *configured_root_anchor
        || checked_vault.tip().manifest_generation != vault_generation
        || checked_vault.tip().manifest_anchor != vault_anchor
    {
        return Err(
            "C: anchor vault API verification disagrees with the independently parsed record chain"
                .into(),
        );
    }
    if checked_vault.latest_checkpoint_segment_witness().is_none()
        && vault_generation > data_latest_generation
    {
        return Err(format!(
            "C: anchor generation {vault_generation} is ahead of Genesis-rooted D: manifest generation {data_latest_generation}; possible data-volume rollback"
        ));
    }
    Ok((vault_generation, vault_anchor))
}

fn trusted_manifest_anchor(
    cfg: &Value,
    data_dir: &Path,
    expected_network_id: &[u8; 32],
    expected_profile_id: &[u8; 32],
) -> Result<Option<(u64, [u8; 32])>, String> {
    let manifests = data_dir.join("manifests");
    let entries = match fs::symlink_metadata(&manifests) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0usize,
        Err(e) => return Err(format!("cannot inspect existing manifest directory: {e}")),
        Ok(meta) if meta.file_type().is_symlink() || !meta.is_dir() => {
            return Err("manifest path must be a real directory".into())
        }
        Ok(_) => fs::read_dir(&manifests)
            .map_err(|e| format!("cannot read manifest directory: {e}"))?
            .count(),
    };
    let joining_role = cfg.get("node_role").and_then(Value::as_str) == Some("joining");
    match (entries > 0, cfg.get("trusted_manifest_anchor")) {
        (true, Some(value)) => {
            let text = value.as_str().filter(|s| !s.trim().is_empty()).ok_or("trusted_manifest_anchor must be a non-empty 64-hex string")?;
            let configured_root_anchor = parse_hex32("trusted_manifest_anchor", text)?;
            let data_latest_generation = (entries as u64).checked_sub(1).ok_or("existing manifest count underflow")?;
            let (floor_generation, floor_anchor) = trusted_manifest_floor(cfg)?;
            let vault_tip = validate_local_anchor_vault(
                cfg,
                expected_network_id,
                expected_profile_id,
                data_latest_generation,
                &configured_root_anchor,
                floor_generation,
                &floor_anchor,
            )?;
            Ok(Some(vault_tip))
        }
        (true, None) => Err("existing durable history requires independently pinned permissionless_runtime.trusted_manifest_anchor; refusing local-only rollback trust".into()),
        (false, Some(value)) if joining_role => {
            // A Joining node may be pre-provisioned from a checkpoint before its first local
            // manifest exists. Select that path only after the complete C: vault and Q6SW
            // witness chain validate. A missing vault preserves fresh-Genesis bootstrap.
            let text = value
                .as_str()
                .filter(|text| !text.trim().is_empty())
                .ok_or("trusted_manifest_anchor must be a non-empty 64-hex string")?;
            let configured_root_anchor = parse_hex32("trusted_manifest_anchor", text)?;
            let vault_path = local_anchor_vault_directory(cfg)?;
            match fs::symlink_metadata(&vault_path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound
                    && cfg.get("trusted_manifest_floor_generation").is_none()
                    && cfg.get("trusted_manifest_floor_anchor").is_none() => Ok(None),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err(
                    "external manifest floor is configured but the pre-provisioned Joining anchor vault is missing"
                        .into(),
                ),
                Err(error) => Err(format!(
                    "cannot inspect pre-provisioned Joining C: anchor vault: {error}"
                )),
                Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => Err(
                    "pre-provisioned Joining C: anchor vault must be a real directory".into(),
                ),
                Ok(_) => {
                    let (floor_generation, floor_anchor) = trusted_manifest_floor(cfg)?;
                    validate_local_anchor_vault(
                        cfg,
                        expected_network_id,
                        expected_profile_id,
                        0,
                        &configured_root_anchor,
                        floor_generation,
                        &floor_anchor,
                    )
                    .map(Some)
                },
            }
        },
        (false, Some(_)) => Err("trusted_manifest_anchor must be omitted for a fresh Genesis-only data directory".into()),
        (false, None)
            if cfg.get("trusted_manifest_floor_generation").is_some()
                || cfg.get("trusted_manifest_floor_anchor").is_some() =>
        {
            Err("independent manifest floor requires trusted_manifest_anchor".into())
        }
        (false, None) => Ok(None),
    }
}
const PUBLIC_TESTNET_MODE: &str = "public-testnet-zero-value-candidate";
const PUBLIC_TESTNET_ACK: &str = "ZERO_VALUE_PUBLIC_TESTNET_NO_MAINNET_NO_MARKET";
const PUBLIC_TESTNET_INBOUND_ACK: &str = "ANONYMOUS_NOISE_XX_UNAUTHENTICATED";
const PUBLIC_TESTNET_SOFTWARE_KEYS_ACK: &str = "SOFTWARE_KEY_CUSTODY_ZERO_VALUE_TESTNET_ONLY";
const MAINNET_NATIVE_MODE: &str = "mainnet-native-value-candidate";
const MAINNET_NATIVE_ACK: &str = "QZXB_MAINNET_NATIVE_VALUE_OWNER_AUTHORIZATION_REQUIRED";
const MAINNET_NATIVE_INBOUND_ACK: &str = "PINNED_NOISE_STATIC_KEY_ALLOWLIST_REQUIRED";

fn software_testnet_key_custody_enabled(cfg: &Value, public_testnet: bool) -> Result<bool, String> {
    match cfg.get("allow_software_testnet_key_custody") {
        None | Some(Value::Bool(false)) => {
            if cfg
                .get("software_testnet_key_custody_acknowledgement")
                .is_some()
            {
                return Err(
                    "software_testnet_key_custody_acknowledgement is forbidden unless software testnet key custody is enabled"
                        .into(),
                );
            }
            Ok(false)
        }
        Some(Value::Bool(true)) => {
            if !public_testnet {
                return Err(
                    "software-custodied keys are restricted to the zero-value Public Testnet path"
                        .into(),
                );
            }
            if req(cfg, "software_testnet_key_custody_acknowledgement")?
                != PUBLIC_TESTNET_SOFTWARE_KEYS_ACK
            {
                return Err(format!(
                    "software_testnet_key_custody_acknowledgement must be exactly '{PUBLIC_TESTNET_SOFTWARE_KEYS_ACK}'"
                ));
            }
            if cfg
                .get("require_device_root_binding")
                .and_then(Value::as_bool)
                == Some(true)
            {
                return Err(
                    "software-custodied testnet keys cannot satisfy require_device_root_binding"
                        .into(),
                );
            }
            if [
                "device_root_metadata_path",
                "device_root_binding_path",
                "q6pd_identity_key_path",
                "q6pd_identity_binding_path",
            ]
            .iter()
            .any(|key| cfg.get(*key).is_some())
            {
                return Err(
                    "software testnet identity must not be mixed with TPM identity paths".into(),
                );
            }
            Ok(true)
        }
        Some(_) => Err(
            "permissionless_runtime.allow_software_testnet_key_custody must be a boolean".into(),
        ),
    }
}

const PUBLIC_TESTNET_DERIVED_GENESIS_ANCHOR_ACK: &str =
    "VERIFIED_GENESIS_DERIVED_ANCHOR_ZERO_VALUE_TESTNET_ONLY";

fn derive_fresh_joiner_anchor_from_verified_genesis(
    cfg: &Value,
    public_testnet: bool,
) -> Result<bool, String> {
    match cfg.get("derive_fresh_joiner_anchor_from_verified_genesis") {
        None | Some(Value::Bool(false)) => {
            if cfg
                .get("fresh_genesis_anchor_derivation_acknowledgement")
                .is_some()
            {
                return Err(
                    "fresh_genesis_anchor_derivation_acknowledgement is forbidden unless Genesis-derived Joiner anchoring is enabled"
                        .into(),
                );
            }
            Ok(false)
        }
        Some(Value::Bool(true)) => {
            if !public_testnet {
                return Err(
                    "Genesis-derived local anchors are restricted to zero-value Public Testnet"
                        .into(),
                );
            }
            if req(cfg, "node_role")? != "joining" {
                return Err(
                    "Genesis-derived local anchors are allowed only for a fresh joining node"
                        .into(),
                );
            }
            if req(cfg, "fresh_genesis_anchor_derivation_acknowledgement")?
                != PUBLIC_TESTNET_DERIVED_GENESIS_ANCHOR_ACK
            {
                return Err(format!(
                    "fresh_genesis_anchor_derivation_acknowledgement must be exactly '{PUBLIC_TESTNET_DERIVED_GENESIS_ANCHOR_ACK}'"
                ));
            }
            if cfg.get("trusted_manifest_anchor").is_some() {
                return Err(
                    "trusted_manifest_anchor must be omitted when deriving a fresh Joiner root from verified Genesis"
                        .into(),
                );
            }
            Ok(true)
        }
        Some(_) => Err(
            "permissionless_runtime.derive_fresh_joiner_anchor_from_verified_genesis must be a boolean"
                .into(),
        ),
    }
}

fn load_software_testnet_private_key_from_env(
    variable_name: &str,
) -> Result<Zeroizing<[u8; 32]>, String> {
    let mut encoded = std::env::var(variable_name).map_err(|_| {
        format!("required testnet secret environment variable {variable_name} is missing")
    })?;
    if encoded.len() != 64
        || !encoded.is_ascii()
        || encoded
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        encoded.zeroize();
        return Err(format!(
            "testnet secret {variable_name} must be exactly 64 lowercase hexadecimal characters"
        ));
    }
    let mut secret = Zeroizing::new([0u8; 32]);
    for (index, slot) in secret.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16)
            .map_err(|_| format!("testnet secret {variable_name} is malformed"))?;
    }
    encoded.zeroize();
    if secret.iter().all(|byte| *byte == 0) {
        return Err(format!("testnet secret {variable_name} must not be zero"));
    }
    Ok(secret)
}

fn validate_runtime_mode(cfg: &Value, public_testnet: bool, mainnet: bool) -> Result<(), String> {
    if public_testnet && mainnet {
        return Err("Public Testnet and Mainnet runtime modes are mutually exclusive".into());
    }
    let expected_mode = if public_testnet {
        PUBLIC_TESTNET_MODE
    } else if mainnet {
        MAINNET_NATIVE_MODE
    } else {
        "permissionless-full-history-candidate"
    };
    if req(cfg, "mode")? != expected_mode {
        return Err(format!(
            "permissionless_runtime.mode must be exactly '{expected_mode}' for this CLI path"
        ));
    }
    if cfg.get("allow_candidate_runtime").and_then(Value::as_bool) != Some(true) {
        return Err("permissionless_runtime.allow_candidate_runtime=true is required".into());
    }

    if public_testnet {
        if cfg.get("allow_public_listener").and_then(Value::as_bool) != Some(true) {
            return Err(
                "public-testnet mode requires permissionless_runtime.allow_public_listener=true"
                    .into(),
            );
        }
        if req(cfg, "public_testnet_acknowledgement")? != PUBLIC_TESTNET_ACK {
            return Err(format!(
                "public_testnet_acknowledgement must be exactly '{PUBLIC_TESTNET_ACK}'"
            ));
        }
        if req(cfg, "public_inbound_security_acknowledgement")? != PUBLIC_TESTNET_INBOUND_ACK {
            return Err(format!(
                "public_inbound_security_acknowledgement must be exactly '{PUBLIC_TESTNET_INBOUND_ACK}'"
            ));
        }
        if !matches!(req(cfg, "node_role")?, "seed" | "joining") {
            return Err(
                "permissionless_runtime.node_role must be exactly 'seed' or 'joining'".into(),
            );
        }
    } else if mainnet {
        if cfg.get("allow_public_listener").and_then(Value::as_bool) != Some(true) {
            return Err("Mainnet-native mode requires allow_public_listener=true".into());
        }
        if req(cfg, "mainnet_native_acknowledgement")? != MAINNET_NATIVE_ACK {
            return Err(format!(
                "mainnet_native_acknowledgement must be exactly '{MAINNET_NATIVE_ACK}'"
            ));
        }
        if req(cfg, "public_inbound_security_acknowledgement")? != MAINNET_NATIVE_INBOUND_ACK {
            return Err(format!(
                "public_inbound_security_acknowledgement must be exactly '{MAINNET_NATIVE_INBOUND_ACK}'"
            ));
        }
        if cfg.get("public_testnet_acknowledgement").is_some() {
            return Err(
                "Mainnet-native config must not carry a Public Testnet acknowledgement".into(),
            );
        }
    } else if cfg.get("allow_public_listener").and_then(Value::as_bool) == Some(true) {
        return Err(
            "public listener opt-in is accepted only by an explicit Public Testnet or Mainnet-native path"
                .into(),
        );
    }
    Ok(())
}

fn validate_q6ga_local_devnet_scope(
    cfg: &Value,
    public_testnet: bool,
    bootstrap_peer_count: usize,
) -> Result<(), String> {
    if public_testnet
        || req(cfg, "mode")? != "permissionless-full-history-candidate"
        || req(cfg, "listen_address")? != "127.0.0.1:30333"
        || cfg.get("allow_public_listener").and_then(Value::as_bool) != Some(false)
        || cfg
            .get("enable_approved_peer_outbound_sync")
            .and_then(Value::as_bool)
            != Some(false)
        || cfg
            .get("enable_q6ar_candidate_address_book")
            .and_then(Value::as_bool)
            != Some(false)
        || bootstrap_peer_count != 0
    {
        return Err(
            "Q6GA v1 approval is restricted to 127.0.0.1:30333 with zero bootstrap peers and outbound/Q6AR disabled; public Testnet requires a separate approval profile"
                .into(),
        );
    }
    Ok(())
}

fn ipv4_in_prefix(address: Ipv4Addr, network: Ipv4Addr, prefix: u32) -> bool {
    let mask = u32::MAX << (32 - prefix);
    (u32::from(address) & mask) == (u32::from(network) & mask)
}

fn ipv6_in_prefix(address: Ipv6Addr, network: Ipv6Addr, prefix: u32) -> bool {
    let mask = u128::MAX << (128 - prefix);
    (u128::from(address) & mask) == (u128::from(network) & mask)
}

/// Strict admission filter for bootstrap endpoints. This is intentionally
/// narrower than "not RFC1918": documentation, benchmarking, transition,
/// shared-CGNAT, and other special-purpose ranges are rejected as peers.
fn is_publicly_routable_peer_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(address) => {
            !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_private()
                && !address.is_link_local()
                && !address.is_multicast()
                && !address.is_broadcast()
                && !ipv4_in_prefix(address, Ipv4Addr::new(0, 0, 0, 0), 8)
                && !ipv4_in_prefix(address, Ipv4Addr::new(100, 64, 0, 0), 10)
                && !ipv4_in_prefix(address, Ipv4Addr::new(192, 0, 0, 0), 24)
                && !ipv4_in_prefix(address, Ipv4Addr::new(192, 0, 2, 0), 24)
                && !ipv4_in_prefix(address, Ipv4Addr::new(192, 88, 99, 0), 24)
                && !ipv4_in_prefix(address, Ipv4Addr::new(198, 18, 0, 0), 15)
                && !ipv4_in_prefix(address, Ipv4Addr::new(198, 51, 100, 0), 24)
                && !ipv4_in_prefix(address, Ipv4Addr::new(203, 0, 113, 0), 24)
                && !ipv4_in_prefix(address, Ipv4Addr::new(240, 0, 0, 0), 4)
        }
        IpAddr::V6(address) => {
            let octets = address.octets();
            let ipv4_mapped = octets[..10].iter().all(|byte| *byte == 0)
                && octets[10] == 0xff
                && octets[11] == 0xff;
            if ipv4_mapped {
                return is_publicly_routable_peer_ip(IpAddr::V4(Ipv4Addr::new(
                    octets[12], octets[13], octets[14], octets[15],
                )));
            }

            let unique_local = octets[0] & 0xfe == 0xfc;
            let link_local = octets[0] == 0xfe && octets[1] & 0xc0 == 0x80;
            !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_multicast()
                && !unique_local
                && !link_local
                && !ipv6_in_prefix(
                    address,
                    Ipv6Addr::from([
                        0x00, 0x64, 0xff, 0x9b, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    ]),
                    48,
                )
                && !ipv6_in_prefix(
                    address,
                    Ipv6Addr::from([0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                    64,
                )
                && !ipv6_in_prefix(
                    address,
                    Ipv6Addr::from([0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                    23,
                )
                && !ipv6_in_prefix(
                    address,
                    Ipv6Addr::from([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                    32,
                )
                && !ipv6_in_prefix(
                    address,
                    Ipv6Addr::from([0x20, 0x01, 0x00, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                    48,
                )
                && !ipv6_in_prefix(
                    address,
                    Ipv6Addr::from([0x20, 0x01, 0x00, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                    28,
                )
                && !ipv6_in_prefix(
                    address,
                    Ipv6Addr::from([0x20, 0x01, 0x00, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                    28,
                )
                && !ipv6_in_prefix(
                    address,
                    Ipv6Addr::from([0x20, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                    16,
                )
                && !ipv6_in_prefix(
                    address,
                    Ipv6Addr::from([0x3f, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                    20,
                )
        }
    }
}

fn validate_public_testnet_topology(
    cfg: &Value,
    listen: SocketAddr,
    peers: &[QRunV06PinnedBootstrapPeer],
) -> Result<(), String> {
    // NAT-friendly joining clients may participate through outbound-only sessions.
    // They must bind exclusively to loopback, have a pinned public bootstrap peer,
    // enable Q6PD discovery/pull, and never publish an unreachable self endpoint.
    // A Seed or public relay continues through the original public-listener policy.
    let outbound_only_joiner = req(cfg, "node_role")? == "joining"
        && cfg
            .get("enable_q6pd_self_announcement")
            .and_then(Value::as_bool)
            == Some(false);
    if outbound_only_joiner {
        if !listen.ip().is_loopback() || listen.port() == 0 {
            return Err(
                "outbound-only public-testnet joining nodes must bind a nonzero loopback listener"
                    .into(),
            );
        }
        if !q6pd_peer_discovery_enabled(cfg)? || !q6pd_peer_pull_enabled(cfg)? {
            return Err(
                "outbound-only joining nodes require Q6PD discovery and signed-record pull".into(),
            );
        }
        if peers.is_empty() {
            return Err(
                "outbound-only joining nodes require an independently pinned bootstrap peer".into(),
            );
        }
        if peers
            .iter()
            .any(|peer| !is_publicly_routable_peer_ip(peer.address.ip()))
        {
            return Err(
                "outbound-only bootstrap peers must use publicly routable unicast IP addresses"
                    .into(),
            );
        }
        return Ok(());
    }

    if !requires_public_listener_opt_in(listen.ip()) {
        return Err(
            "public-testnet mode must bind 0.0.0.0 or a public unicast address, not a private/loopback interface"
                .into(),
        );
    }
    if !listen.ip().is_unspecified() && !is_publicly_routable_peer_ip(listen.ip()) {
        return Err(
            "a non-wildcard public-testnet listen address must be globally routable unicast".into(),
        );
    }
    match req(cfg, "node_role")? {
        "seed" if !peers.is_empty() => {
            return Err(
                "a public-testnet seed must start from Genesis with an empty pinned bootstrap set"
                    .into(),
            );
        }
        "joining" if peers.is_empty() => {
            return Err("a public-testnet joining node requires at least one independently verified pinned bootstrap peer".into());
        }
        "joining" => {
            if peers
                .iter()
                .any(|peer| !is_publicly_routable_peer_ip(peer.address.ip()))
            {
                return Err(
                    "public-testnet bootstrap peers must use publicly routable unicast IP addresses"
                        .into(),
                );
            }
        }
        "seed" => {}
        _ => return Err("invalid public-testnet node_role".into()),
    }
    Ok(())
}

/// Mainnet-native candidate topology: a publicly reachable listener is permitted only
/// when every inbound Noise identity is pinned and at least one non-empty bootstrap peer
/// set is frozen into the signed Q6GA v3 authorization.
fn validate_mainnet_native_topology(
    cfg: &Value,
    listen: SocketAddr,
    peers: &[QRunV06PinnedBootstrapPeer],
) -> Result<(), String> {
    if !requires_public_listener_opt_in(listen.ip()) {
        return Err(
            "Mainnet-native mode must bind a public unicast address or explicit wildcard".into(),
        );
    }
    if !listen.ip().is_unspecified() && !is_publicly_routable_peer_ip(listen.ip()) {
        return Err("Mainnet-native listener address must be globally routable unicast".into());
    }
    if peers.is_empty() {
        return Err(
            "Mainnet-native mode requires a non-empty, independently pinned bootstrap peer set"
                .into(),
        );
    }
    validate_qfp6_pinned_bootstrap_peers(peers)
        .map_err(|error| format!("Mainnet-native bootstrap peer pins invalid: {error:?}"))?;
    if peers.iter().any(|peer| {
        peer.tls_server_name.is_some() || !is_publicly_routable_peer_ip(peer.address.ip())
    }) {
        return Err(
            "Mainnet-native bootstrap peers must use globally routable unicast IP addresses".into(),
        );
    }
    if cfg.get("allow_public_listener").and_then(Value::as_bool) != Some(true) {
        return Err("Mainnet-native topology requires allow_public_listener=true".into());
    }
    Ok(())
}

pub fn run_permissionless_node(
    config_path: &Path,
    expected_config_sha: &[u8; 32],
) -> Result<(), String> {
    run_permissionless_node_with_visibility(config_path, expected_config_sha, false, false)
}

pub fn run_public_testnet_node(
    config_path: &Path,
    expected_config_sha: &[u8; 32],
) -> Result<(), String> {
    run_permissionless_node_with_visibility(config_path, expected_config_sha, true, false)
}

pub fn run_mainnet_native_node(
    config_path: &Path,
    expected_config_sha: &[u8; 32],
) -> Result<(), String> {
    run_permissionless_node_with_visibility(config_path, expected_config_sha, false, true)
}

fn run_permissionless_node_with_visibility(
    config_path: &Path,
    expected_config_sha: &[u8; 32],
    public_testnet: bool,
    mainnet: bool,
) -> Result<(), String> {
    let bytes = read_bounded(config_path, MAX_CONFIG_BYTES, "permissionless config")?;
    let actual: [u8; 32] = Sha256::digest(&bytes).into();
    if &actual != expected_config_sha {
        return Err(
            "permissionless config digest mismatch; supply the independently pinned SHA-256".into(),
        );
    }
    let root: Value = serde_json::from_slice(&bytes)
        .map_err(|e| format!("invalid permissionless config JSON: {e}"))?;
    let cfg = root
        .get("permissionless_runtime")
        .ok_or("permissionless_runtime section missing")?;
    validate_runtime_mode(cfg, public_testnet, mainnet)?;
    let software_testnet_key_custody = software_testnet_key_custody_enabled(cfg, public_testnet)?;
    let derive_joiner_anchor_from_verified_genesis =
        derive_fresh_joiner_anchor_from_verified_genesis(cfg, public_testnet)?;
    let base = config_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let profile_path = path(base, cfg, "q6pn_profile_pin_path")?;
    let profile_commitment = parse_hex32(
        "q6pn_profile_pin_commitment",
        req(cfg, "q6pn_profile_pin_commitment")?,
    )?;
    let profile_bytes = read_bounded(&profile_path, MAX_BOOTSTRAP_BYTES, "Q6PN profile pin")?;
    let verified_pin = QRunV06VerifiedProfilePin::decode(&profile_bytes, profile_commitment)
        .map_err(|e| format!("Q6PN independent commitment verification failed: {e:?}"))?;
    let mut quote_inputs =
        load_permissionless_quote_authorization_inputs(base, cfg, &profile_bytes, &verified_pin)?;
    let descriptor = verified_pin.descriptor();
    let q6gd_path = path(base, cfg, "q6gd_descriptor_path")?;
    let q6gd_sha = parse_hex32(
        "q6gd_descriptor_sha256",
        req(cfg, "q6gd_descriptor_sha256")?,
    )?;
    let q6gd_bytes = read_regular_bounded(&q6gd_path, 4096, "Q6GD Genesis descriptor")?;
    let q6gd_actual: [u8; 32] = Sha256::digest(&q6gd_bytes).into();
    if q6gd_actual != q6gd_sha {
        return Err("Q6GD descriptor SHA-256 mismatch".into());
    }
    let separate_descriptor = QRunV06GenesisDescriptor::decode(&q6gd_bytes)
        .map_err(|error| format!("Q6GD descriptor decode failed: {error:?}"))?;
    if &separate_descriptor != descriptor {
        return Err(
            "standalone Q6GD descriptor does not exactly match the descriptor pinned by Q6PN"
                .into(),
        );
    }
    let q6pn_sha = parse_hex32(
        "q6pn_profile_pin_sha256",
        req(cfg, "q6pn_profile_pin_sha256")?,
    )?;
    let q6pn_actual: [u8; 32] = Sha256::digest(&profile_bytes).into();
    if q6pn_actual != q6pn_sha {
        return Err("Q6PN profile SHA-256 mismatch".into());
    }
    let peer_path = path(base, cfg, "bootstrap_peers_path")?;
    let peer_sha = parse_hex32(
        "bootstrap_peers_sha256",
        req(cfg, "bootstrap_peers_sha256")?,
    )?;
    let peers = load_peers(&peer_path, peer_sha, public_testnet)?;
    if !public_testnet && !mainnet {
        validate_q6ga_local_devnet_scope(cfg, false, peers.len())?;
    }
    let q6cp_path = path(base, cfg, "q6cp_profile_path")?;
    let q6cp_sha = parse_hex32("q6cp_profile_sha256", req(cfg, "q6cp_profile_sha256")?)?;
    let (_, profile) = load_pinned_q6cp_profile(&q6cp_path, &q6cp_sha, descriptor)?;
    let params = profile.parameters().clone();
    let genesis_path = path(base, cfg, "genesis_snapshot_path")?;
    let genesis_sha = parse_hex32(
        "genesis_snapshot_sha256",
        req(cfg, "genesis_snapshot_sha256")?,
    )?;
    let genesis_bytes = read_bounded(
        &genesis_path,
        MAX_GENESIS_SNAPSHOT_BYTES,
        "QFP6 Genesis snapshot",
    )?;
    let digest: [u8; 32] = Sha256::digest(&genesis_bytes).into();
    if digest != genesis_sha {
        return Err("Genesis snapshot SHA-256 mismatch".into());
    }
    let (approval_path, approval_sha, approval_label) = if public_testnet {
        (
            path(base, cfg, "public_testnet_authorization_path")?,
            parse_hex32(
                "public_testnet_authorization_sha256",
                req(cfg, "public_testnet_authorization_sha256")?,
            )?,
            "Q6GA public-testnet authorization",
        )
    } else if mainnet {
        (
            path(base, cfg, "mainnet_native_authorization_path")?,
            parse_hex32(
                "mainnet_native_authorization_sha256",
                req(cfg, "mainnet_native_authorization_sha256")?,
            )?,
            "Q6GA v3 Mainnet-native authorization",
        )
    } else {
        (
            path(base, cfg, "owner_genesis_approval_path")?,
            parse_hex32(
                "owner_genesis_approval_sha256",
                req(cfg, "owner_genesis_approval_sha256")?,
            )?,
            "Q6GA local Genesis approval",
        )
    };
    let approval_bytes = read_regular_bounded(&approval_path, 16 * 1024, approval_label)?;
    let approval_actual: [u8; 32] = Sha256::digest(&approval_bytes).into();
    if approval_actual != approval_sha {
        return Err(format!("{approval_label} SHA-256 mismatch"));
    }
    let owner_approval = QRunV06GenesisApproval::decode(&approval_bytes).map_err(|error| {
        format!("{approval_label} dual-signature verification failed: {error:?}")
    })?;
    if public_testnet {
        owner_approval
            .verify_public_testnet_bindings(
                descriptor,
                &q6gd_sha,
                &q6cp_sha,
                &q6pn_sha,
                &genesis_sha,
            )
            .map_err(|error| {
                format!("Q6GA public-testnet owner/artifact/economics binding failed: {error:?}")
            })?;
        println!("owner_genesis_approval=Q6GA_ED25519_MLDSA65_VERIFIED");
        println!("owner_genesis_approval_scope=ZERO_VALUE_PUBLIC_TESTNET_ONLY");
        println!("mainnet_authorization=NOT_GRANTED");
        println!("market_authorization=NOT_GRANTED");
    } else if mainnet {
        owner_approval
            .verify_mainnet_native_bindings(
                descriptor,
                &q6gd_sha,
                &q6cp_sha,
                &q6pn_sha,
                &genesis_sha,
                &peer_sha,
            )
            .map_err(|error| {
                format!("Q6GA v3 Mainnet-native owner/artifact/peer-set binding failed: {error:?}")
            })?;
        println!("owner_genesis_approval=Q6GA_ED25519_MLDSA65_VERIFIED");
        println!("owner_genesis_approval_scope=MAINNET_NATIVE_VALUE_ONLY");
        println!("mainnet_native_authorization=VERIFIED");
        println!("market_authorization=NOT_GRANTED_BY_Q6GA_V3");
        println!("public_mining_subsidy=NOT_AUTHORIZED_ZERO_BY_CP0651");
    } else {
        owner_approval
            .verify_bindings(
                descriptor,
                &q6gd_sha,
                &q6cp_sha,
                &q6pn_sha,
                &genesis_sha,
                &peer_sha,
            )
            .map_err(|error| format!("Q6GA owner/artifact/economics binding failed: {error:?}"))?;
        println!("owner_genesis_approval=Q6GA_ED25519_MLDSA65_VERIFIED");
        println!("owner_genesis_approval_scope=LOCAL_CANDIDATE_ONLY_NOT_MAINNET_AUTHORIZATION");
    }
    super::super::verify_genesis_snapshot(
        &genesis_bytes,
        &descriptor.network_id(),
        &descriptor.profile_id(),
        &descriptor.founder_account(),
        &descriptor.consensus_fingerprint(),
        &descriptor.tokenomics_policy_fingerprint(),
        descriptor,
    )?;
    let genesis = QRunV06CanonicalExecutionState::decode_snapshot(
        &genesis_bytes,
        &descriptor.network_id(),
        &descriptor.profile_id(),
    )
    .map_err(|e| format!("Genesis snapshot decode failed: {e:?}"))?;
    // Bind decoded Genesis economics to the exact Q6CP parameters before opening
    // any durable store or network listener. CP-0651 requires a 1B owner
    // Genesis, six 1B accounting labels, and zero block subsidy.
    validate_permissionless_cp0651_genesis(
        &genesis,
        &descriptor.founder_account(),
        &descriptor.tokenomics_policy_fingerprint(),
    )?;
    genesis
        .validate_consensus_parameters(&params)
        .map_err(|e| format!("Genesis CP-0651/Q6CP monetary-policy binding failed: {e:?}"))?;
    let data_dir = path(base, cfg, "data_directory")?;
    let mempool_dir = path(base, cfg, "mempool_directory")?;
    if data_dir == mempool_dir
        || data_dir.starts_with(&mempool_dir)
        || mempool_dir.starts_with(&data_dir)
    {
        return Err(
            "data_directory and mempool_directory must be separate, non-nested directories".into(),
        );
    }
    let anchor_vault_dir = local_anchor_vault_directory(cfg)?;
    validate_anchor_vault_path_separation(&anchor_vault_dir, &data_dir, &mempool_dir)?;
    let enable_q6ar_candidate = q6ar_candidate_address_book_enabled(cfg)?;
    let enable_q6pd_peer_discovery = q6pd_peer_discovery_enabled(cfg)?;
    let enable_q6pd_peer_pull = q6pd_peer_pull_enabled(cfg)?;
    let enable_q6pd_self_announcement = q6pd_self_announcement_enabled(cfg)?;
    if enable_q6pd_peer_pull && !enable_q6pd_peer_discovery {
        return Err("enable_q6pd_peer_pull requires enable_q6pd_peer_discovery=true".into());
    }
    if enable_q6pd_self_announcement && !enable_q6pd_peer_discovery {
        return Err(
            "enable_q6pd_self_announcement requires enable_q6pd_peer_discovery=true".into(),
        );
    }
    if enable_q6pd_self_announcement && !public_testnet {
        return Err(
            "Q6PD self-announcement is restricted to the zero-value Public Testnet candidate"
                .into(),
        );
    }
    let q6pd_identity_config_keys = [
        "q6pd_identity_key_path",
        "q6pd_identity_binding_path",
        "q6pd_self_advertise_endpoint",
    ];
    let q6pd_optional_endpoint_config_keys = ["q6pd_self_advertise_tls_server_name"];
    if enable_q6pd_self_announcement {
        if cfg.get("q6pd_self_advertise_endpoint").is_none() {
            return Err(
                "enable_q6pd_self_announcement requires q6pd_self_advertise_endpoint".into(),
            );
        }
        if software_testnet_key_custody {
            if [
                "q6pd_identity_key_path",
                "q6pd_identity_binding_path",
                "device_root_metadata_path",
                "device_root_binding_path",
            ]
            .iter()
            .any(|key| cfg.get(*key).is_some())
            {
                return Err(
                    "ephemeral testnet self-announcement must not include persisted or TPM identity paths"
                        .into(),
                );
            }
        } else {
            for key in ["q6pd_identity_key_path", "q6pd_identity_binding_path"] {
                if cfg.get(key).is_none() {
                    return Err(format!("enable_q6pd_self_announcement requires {key}"));
                }
            }
            if cfg.get("device_root_metadata_path").is_none() {
                return Err(
                    "enable_q6pd_self_announcement requires device_root_metadata_path".into(),
                );
            }
        }
    } else if q6pd_identity_config_keys
        .iter()
        .chain(q6pd_optional_endpoint_config_keys.iter())
        .any(|key| cfg.get(*key).is_some())
    {
        return Err(
            "Q6PD identity paths and endpoint require enable_q6pd_self_announcement=true".into(),
        );
    }
    if enable_q6pd_peer_discovery && !public_testnet {
        return Err(
            "Q6PD peer discovery is restricted to the zero-value Public Testnet candidate".into(),
        );
    }
    let enable_peer_address_book = peer_address_book_enabled(cfg)?;
    let enable_address_book = enable_q6ar_candidate || enable_peer_address_book;
    let enable_q6ar_candidate_pull = q6ar_candidate_pull_enabled(cfg)?;
    let enable_approved_peer_sync = approved_peer_outbound_sync_enabled(cfg)?;
    let max_approved_attempts = max_approved_peer_sync_attempts(cfg)?;
    if enable_q6ar_candidate_pull && !enable_q6ar_candidate {
        return Err(
            "enable_q6ar_candidate_pull requires enable_q6ar_candidate_address_book=true".into(),
        );
    }
    if enable_approved_peer_sync && !enable_address_book {
        return Err(
            "enable_approved_peer_outbound_sync requires enable_peer_address_book=true or enable_q6ar_candidate_address_book=true"
                .into(),
        );
    }
    if enable_peer_address_book && !enable_approved_peer_sync {
        return Err(
            "enable_peer_address_book requires enable_approved_peer_outbound_sync=true".into(),
        );
    }
    if enable_q6pd_peer_discovery {
        // A genesis-rooted seed may serve signed records and accept incoming announcements
        // before it knows any other peer. Only nodes that pull/dial need a pinned bootstrap;
        // that stricter requirement is enforced below by enable_q6pd_peer_pull.
        if cfg.get("q6pd_peer_record_store_path").is_none() {
            return Err("enable_q6pd_peer_discovery requires q6pd_peer_record_store_path".into());
        }
    } else if cfg.get("q6pd_peer_record_store_path").is_some() {
        return Err("q6pd_peer_record_store_path requires enable_q6pd_peer_discovery=true".into());
    }
    if enable_q6pd_peer_pull
        && q6pd_peer_pull_requires_operator_pinned_seed(req(cfg, "node_role")?, peers.len())
    {
        return Err("enable_q6pd_peer_pull requires at least one operator-pinned, Q6PD-capable bootstrap peer for joining nodes".into());
    }
    if enable_q6ar_candidate
        && (cfg.get("peer_trust_domains_path").is_some()
            || cfg.get("peer_trust_domains_sha256").is_some())
    {
        return Err("peer_trust_domains_path/sha256 are only for standalone peer-book mode".into());
    }
    if !enable_peer_address_book
        && (cfg.get("peer_trust_domains_path").is_some()
            || cfg.get("peer_trust_domains_sha256").is_some())
    {
        return Err(
            "peer trust-domain registry settings require enable_peer_address_book=true".into(),
        );
    }
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock invalid for peer address book: {error}"))?
        .as_millis()
        .try_into()
        .map_err(|_| "system clock exceeds peer address-book millisecond range".to_string())?;
    let mut q6ar_address_book = if enable_address_book {
        let address_book_path = if enable_peer_address_book {
            path(base, cfg, "peer_address_book_path")?
        } else {
            path(base, cfg, "q6ar_candidate_address_book_path")?
        };
        if address_book_path == data_dir
            || address_book_path.starts_with(&data_dir)
            || data_dir.starts_with(&address_book_path)
            || address_book_path == mempool_dir
            || address_book_path.starts_with(&mempool_dir)
            || mempool_dir.starts_with(&address_book_path)
        {
            return Err(
                "peer address-book path must be separate from data and mempool directories".into(),
            );
        }
        let mut book = QRunV06PeerAddressBookCandidate::open(
            &address_book_path,
            descriptor.network_id(),
            descriptor.profile_id(),
        )
        .map_err(|error| format!("operator peer address-book open failed: {error}"))?;
        for peer in &peers {
            book.pin_manual_peer(
                &peer.address.to_string(),
                peer.noise_static_public_key,
                now_ms,
            )
            .map_err(|error| {
                format!("cannot seed peer address book from configured operator pins: {error}")
            })?;
        }
        Some(book)
    } else {
        None
    };
    let mut q6pd_peer_record_store = if enable_q6pd_peer_discovery {
        let record_store_path = path(base, cfg, "q6pd_peer_record_store_path")?;
        let record_components =
            normalized_absolute_path_components(&record_store_path, "q6pd_peer_record_store_path")?;
        for (label, candidate) in [
            ("data_directory", &data_dir),
            ("mempool_directory", &mempool_dir),
        ] {
            let candidate_components = normalized_absolute_path_components(candidate, label)?;
            if path_components_overlap(&record_components, &candidate_components) {
                return Err(format!(
                    "q6pd_peer_record_store_path must be separate and non-nested from {label}"
                ));
            }
        }
        if enable_address_book {
            let address_book_path = if enable_peer_address_book {
                path(base, cfg, "peer_address_book_path")?
            } else {
                path(base, cfg, "q6ar_candidate_address_book_path")?
            };
            let address_components =
                normalized_absolute_path_components(&address_book_path, "peer_address_book_path")?;
            if path_components_overlap(&record_components, &address_components) {
                return Err("q6pd_peer_record_store_path must be separate and non-nested from the Q6AR/peer address book".into());
            }
        }
        Some(
            Q6pdPeerRecordStore::open(
                &record_store_path,
                descriptor.network_id(),
                descriptor.profile_id(),
                now_ms,
            )
            .map_err(|error| format!("Q6PD signed peer-record store open failed: {error}"))?,
        )
    } else {
        None
    };
    let q6pd_self_announcement_config = if enable_q6pd_self_announcement {
        let identity_key_path = if software_testnet_key_custody {
            None
        } else {
            Some(path(base, cfg, "q6pd_identity_key_path")?)
        };
        let identity_binding_path = if software_testnet_key_custody {
            None
        } else {
            Some(path(base, cfg, "q6pd_identity_binding_path")?)
        };
        let device_root_metadata_path = if software_testnet_key_custody {
            None
        } else {
            Some(path(base, cfg, "device_root_metadata_path")?)
        };
        let noise_key_path = path(base, cfg, "node_noise_private_key_path")?;
        let record_store_path = path(base, cfg, "q6pd_peer_record_store_path")?;
        let endpoint_text = cfg
            .get("q6pd_self_advertise_endpoint")
            .and_then(Value::as_str)
            .ok_or("q6pd_self_advertise_endpoint must be a numeric IP:port socket address")?;
        let advertise_endpoint: SocketAddr = endpoint_text
            .parse()
            .map_err(|error| format!("invalid q6pd_self_advertise_endpoint: {error}"))?;
        if advertise_endpoint.port() == 0 {
            return Err("Q6PD self-advertise endpoint must use a fixed non-zero TCP port".into());
        }
        let tls_server_name = cfg
            .get("q6pd_self_advertise_tls_server_name")
            .map(|value| {
                value
                    .as_str()
                    .filter(|name| !name.trim().is_empty())
                    .map(str::to_owned)
                    .ok_or("q6pd_self_advertise_tls_server_name must be a non-empty DNS name")
            })
            .transpose()?;
        if tls_server_name.is_some() && advertise_endpoint.port() != 443 {
            return Err("Q6PD self-advertise TLS SNI requires endpoint port 443".into());
        }
        let mut protected_paths = vec![
            ("node_noise_private_key_path", noise_key_path),
            ("q6pd_peer_record_store_path", record_store_path),
            ("data_directory", data_dir.clone()),
            ("mempool_directory", mempool_dir.clone()),
            (
                "trusted_manifest_anchor_vault_path",
                anchor_vault_dir.clone(),
            ),
        ];
        if let Some(path) = identity_key_path.as_ref() {
            protected_paths.push(("q6pd_identity_key_path", path.clone()));
        }
        if let Some(path) = identity_binding_path.as_ref() {
            protected_paths.push(("q6pd_identity_binding_path", path.clone()));
        }
        if let Some(path) = device_root_metadata_path.as_ref() {
            protected_paths.push(("device_root_metadata_path", path.clone()));
        }
        let normalized: Vec<(String, Vec<String>)> = protected_paths
            .iter()
            .map(|(label, candidate)| {
                Ok((
                    (*label).to_string(),
                    normalized_absolute_path_components(candidate, label)?,
                ))
            })
            .collect::<Result<_, String>>()?;
        for left in 0..normalized.len() {
            for right in left + 1..normalized.len() {
                if path_components_overlap(&normalized[left].1, &normalized[right].1) {
                    return Err(format!(
                        "{} must be a distinct, non-overlapping path from {}",
                        normalized[left].0, normalized[right].0
                    ));
                }
            }
        }
        Some((
            identity_key_path,
            identity_binding_path,
            device_root_metadata_path,
            advertise_endpoint,
            tls_server_name,
        ))
    } else {
        None
    };
    let mut bootstrap_trust_domains = None;
    let mut supervisor_peers = peers.clone();
    if enable_approved_peer_sync {
        let book = q6ar_address_book
            .as_ref()
            .ok_or("approved peer sync has no address book")?;
        // Inventory the complete bounded approved set before applying the configured attempt
        // budget. Truncating first would let address ordering hide independently assigned domains.
        let approved_candidates = book.approved_peer_pins(now_ms, usize::MAX);
        if approved_candidates.is_empty() {
            return Err("approved peer outbound sync is enabled, but no operator-approved peer is currently eligible (check persistent backoff or add a peer pin)".into());
        }
        let candidate_peer_keys: Vec<[u8; 32]> = approved_candidates
            .iter()
            .map(|(_, noise_static_public_key)| *noise_static_public_key)
            .collect();
        let policy = if enable_q6ar_candidate {
            load_q6ar_trust_domain_registry(base, cfg, &candidate_peer_keys)?
        } else {
            load_peer_trust_domain_registry(base, cfg, &candidate_peer_keys)?
        };
        supervisor_peers = select_approved_bootstrap_peers(
            &approved_candidates,
            &peers,
            &policy,
            max_approved_attempts,
        )?;
        bootstrap_trust_domains = Some(policy);
    }
    if enable_q6pd_peer_pull
        && q6pd_peer_pull_requires_operator_pinned_seed(
            req(cfg, "node_role")?,
            supervisor_peers.len(),
        )
    {
        return Err(
            "Q6PD peer pull requires an operator-pinned Q6PD-capable bootstrap peer for joining nodes".into(),
        );
    }
    let q6ar_relay_pins: Vec<[u8; 32]> = if enable_q6ar_candidate {
        supervisor_peers
            .iter()
            .map(|peer| peer.noise_static_public_key)
            .collect()
    } else {
        Vec::new()
    };
    let outbound_trust_domains = if enable_q6ar_candidate {
        let policy = match bootstrap_trust_domains.take() {
            Some(policy) => policy,
            None => load_q6ar_trust_domain_registry(base, cfg, &q6ar_relay_pins)?,
        };
        Some(policy)
    } else if enable_peer_address_book {
        let policy = bootstrap_trust_domains
            .take()
            .ok_or("standalone peer address book has no approved-peer trust-domain policy")?;
        Some(policy)
    } else {
        if cfg.get("q6ar_trust_domains_path").is_some()
            || cfg.get("q6ar_trust_domains_sha256").is_some()
            || cfg.get("q6ar_trust_domains_rotation_authorized").is_some()
        {
            return Err(
                "Q6AR trust-domain settings require enable_q6ar_candidate_address_book=true".into(),
            );
        }
        None
    };
    let q6ar_rotation_authorized = if enable_q6ar_candidate {
        q6ar_trust_domains_rotation_authorized(cfg)?
    } else {
        false
    };
    if enable_q6ar_candidate {
        if let (Some(book), Some(policy)) =
            (q6ar_address_book.as_mut(), outbound_trust_domains.as_ref())
        {
            let binding_result = if q6ar_rotation_authorized {
                book.rotate_trust_domain_registry(policy, now_ms)
            } else {
                book.bind_trust_domain_registry(policy, now_ms)
            };
            binding_result.map_err(|error| {
                format!(
                    "Q6AR address book trust-domain registry binding/rotation failed closed: {error}"
                )
            })?;
        }
    }
    let listen = endpoint(
        "permissionless_runtime.listen_address",
        req(cfg, "listen_address")?,
        true,
    )?;
    if public_testnet {
        validate_public_testnet_topology(cfg, listen, &supervisor_peers)?;
    } else if mainnet {
        validate_mainnet_native_topology(cfg, listen, &supervisor_peers)?;
    } else {
        validate_public_listener_opt_in(cfg, listen)?;
    }
    let read_api_address = if let Some(value) = cfg.get("read_api_listen_address") {
        let raw = value
            .as_str()
            .ok_or("permissionless_runtime.read_api_listen_address must be a socket address")?;
        let address: SocketAddr = raw
            .parse()
            .map_err(|error| format!("invalid read API listen address: {error}"))?;
        if address.port() == 0 {
            return Err("read API listener must use a fixed non-zero port".into());
        }
        let public_opt_in = cfg.get("allow_public_read_api").and_then(Value::as_bool) == Some(true);
        if !address.ip().is_loopback() && (!mainnet || !public_opt_in) {
            return Err("non-loopback read API binding requires Mainnet mode and allow_public_read_api=true".into());
        }
        if address == listen {
            return Err("read API listener must use a port separate from P2P".into());
        }
        if supervisor_peers.iter().any(|peer| peer.address == address) {
            return Err("read API listener cannot alias a pinned outbound peer".into());
        }
        Some(address)
    } else {
        if cfg.get("allow_public_read_api").and_then(Value::as_bool) == Some(true) {
            return Err("allow_public_read_api=true requires read_api_listen_address".into());
        }
        None
    };
    if supervisor_peers.iter().any(|peer| peer.address == listen) {
        return Err("P2P listener cannot alias a pinned outbound peer".into());
    }
    // Do not expose a TCP socket until all cryptographic inputs, durable state, the
    // mempool journal, and restored pending transactions have passed validation.
    let key_path = path(base, cfg, "node_noise_private_key_path")?;
    let local_key = if software_testnet_key_custody {
        load_software_testnet_private_key_from_env("QFP6_TESTNET_NOISE_PRIVATE_KEY_HEX")?
    } else {
        Zeroizing::new(
            load_protected_noise_private_key(&key_path, &descriptor.network_id())
                .map_err(|e| format!("protected local Noise key unavailable: {e:?}"))?,
        )
    };
    if software_testnet_key_custody {
        let public_key = derive_noise_static_public_key(&*local_key)
            .map_err(|error| format!("testnet Noise public-key derivation failed: {error}"))?;
        println!(
            "QFP6_TESTNET_NOISE_STATIC_PUBLIC_KEY={}",
            super::super::hex(&public_key)
        );
        println!("QFP6_TESTNET_KEY_CUSTODY=RAILWAY_SERVICE_SECRET; MAINNET=FORBIDDEN");
    }
    let require_device_root_binding = match cfg.get("require_device_root_binding") {
        None => false,
        Some(Value::Bool(required)) => *required,
        Some(_) => {
            return Err(
                "permissionless_runtime.require_device_root_binding must be a boolean".into(),
            )
        }
    };
    let metadata_configured = cfg.get("device_root_metadata_path").is_some();
    let binding_configured = cfg.get("device_root_binding_path").is_some();
    if software_testnet_key_custody && (metadata_configured || binding_configured) {
        return Err(
            "software-custodied testnet keys cannot be combined with TPM Device Root paths".into(),
        );
    }
    if metadata_configured != binding_configured && !enable_q6pd_self_announcement {
        return Err("TPM Device Root binding requires both device_root_metadata_path and device_root_binding_path".into());
    }
    if require_device_root_binding && (!metadata_configured || !binding_configured) {
        return Err("require_device_root_binding=true but no TPM Device Root metadata/binding paths were configured".into());
    }
    if software_testnet_key_custody {
        println!(
            "QFP6_DEVICE_IDENTITY=SOFTWARE_KEY_CUSTODY_ZERO_VALUE_TESTNET_ONLY; PRIVATE_KEYS=SERVICE_SECRET; TPM_BINDING=NOT_CLAIMED"
        );
    } else if metadata_configured && binding_configured {
        let metadata_path = path(base, cfg, "device_root_metadata_path")?;
        let binding_path = path(base, cfg, "device_root_binding_path")?;
        if metadata_path == binding_path || metadata_path == key_path || binding_path == key_path {
            return Err("TPM Device Root metadata, binding record, and protected Noise key must be three distinct files".into());
        }
        let local_noise_public = derive_noise_static_public_key(&*local_key).map_err(|error| {
            format!("cannot derive local Noise public identity for TPM binding: {error}")
        })?;
        verify_device_root_binding(
            &metadata_path,
            &binding_path,
            &local_noise_public,
            &descriptor.network_id(),
            &descriptor.profile_id(),
        )
        .map_err(|error| format!("TPM Device Root to Noise identity binding rejected before listener startup: {error}"))?;
        eprintln!("QFP6_DEVICE_IDENTITY=TPM_BOUND_LOCAL_ONLY; TPM_PRIVATE_EXPORT=BLOCKED; NOISE_KEY=EXISTING_NPK1; NETWORK_ACCESS=NOT_USED");
    } else if enable_q6pd_self_announcement {
        eprintln!("QFP6_DEVICE_IDENTITY=Q6PD_TPM_IDENTITY_BINDING_REQUIRED; noise-only-root-binding=NOT_CONFIGURED");
    } else {
        eprintln!("QFP6_DEVICE_IDENTITY=UNBOUND; require_device_root_binding=false; legacy local Noise identity remains active");
    }
    let mut q6pd_node_identity = None;
    let q6pd_self_announcement_report = if let Some((
        identity_key_path,
        identity_binding_path,
        device_root_metadata_path,
        advertise_endpoint,
        tls_server_name,
    )) = q6pd_self_announcement_config.as_ref()
    {
        q6pd_node_identity = Some(if software_testnet_key_custody {
            let identity_seed =
                load_software_testnet_private_key_from_env("QFP6_TESTNET_Q6PD_IDENTITY_SEED_HEX")?;
            create_software_zero_value_testnet_q6pd_identity(
                &*local_key,
                &*identity_seed,
                &descriptor.network_id(),
                &descriptor.profile_id(),
            )
            .map_err(|error| {
                format!("software zero-value testnet Q6PD identity creation failed: {error}")
            })?
        } else {
            load_q6pd_node_identity(
                identity_key_path
                    .as_deref()
                    .ok_or("TPM-bound Q6PD identity key path is unavailable")?,
                identity_binding_path
                    .as_deref()
                    .ok_or("TPM-bound Q6PD identity binding path is unavailable")?,
                device_root_metadata_path
                    .as_deref()
                    .ok_or("TPM Device Root metadata path is unavailable")?,
                &key_path,
                &descriptor.network_id(),
                &descriptor.profile_id(),
            )
            .map_err(|error| {
                format!("TPM-bound Q6PD node identity rejected before publication: {error}")
            })?
        });
        let identity = q6pd_node_identity
            .as_ref()
            .ok_or("Q6PD node identity was not loaded")?;
        let store = q6pd_peer_record_store
            .as_mut()
            .ok_or("Q6PD self-announcement enabled but peer-record store is unavailable")?;
        let sequence = store
            .sequence_for_peer(&identity.info().peer_id)
            .unwrap_or(0)
            .checked_add(1)
            .ok_or("Q6PD self-announcement sequence exhausted")?;
        let issued_at_secs = now_ms / 1000;
        let wire = identity
            .sign_announcement_with_tls_server_name(
                *advertise_endpoint,
                tls_server_name.as_deref(),
                sequence,
                issued_at_secs,
                Q6PD_MAX_TTL_SECS,
            )
            .map_err(|error| format!("Q6PD self-announcement could not be signed: {error}"))?;
        let ingest = store
            .ingest(&wire, now_ms)
            .map_err(|error| format!("Q6PD self-announcement could not be persisted: {error}"))?;
        Some((
            identity.info().peer_id,
            *advertise_endpoint,
            tls_server_name.clone(),
            sequence,
            ingest,
        ))
    } else {
        None
    };
    let q6pd_self_announcement = q6pd_node_identity
        .as_ref()
        .zip(q6pd_self_announcement_config.as_ref())
        .map(|(identity, (_, _, _, endpoint, tls_server_name))| {
            (identity, *endpoint, tls_server_name.clone())
        });
    let authenticator = QRunV06HybridTransactionAuthenticator::new(LibcruxMlDsa65VerifierCandidate);
    let pq_verifier = LibcruxMlDsa65VerifierCandidate;
    let mut trust_authorized_pin: Option<QRunV06TrustAuthorizedProfilePin> = None;
    let mut quote_authorizer: Option<Box<QRunV06QuoteAssetAuthorizationProvider<'_>>> = None;
    if let Some(inputs) = quote_inputs.as_mut() {
        let authorized_pin = authorize_qrun_v06_profile_pin_from_source(
            Some(&profile_bytes),
            &mut inputs.trust_source,
            &inputs.authority,
            &pq_verifier,
            &mut inputs.floor_store,
            descriptor.network_id(),
            descriptor.profile_id(),
        )
        .map_err(|error| format!("Q6TS/Q6PN independent trust authorization failed: {error:?}"))?;
        if authorized_pin
            .verified_profile_pin()
            .quote_asset_trust_pin()
            .is_none()
        {
            return Err("Q6TS-authorized Q6PN lost its required quote-asset trust pin".into());
        }

        let mut fresh_provider = QRunV06FreshQuoteAssetAuthorizationProvider::new(
            &profile_bytes,
            &inputs.q6qa_bundle_bytes,
            &inputs.authority,
            &pq_verifier,
            &mut inputs.floor_store,
            &mut inputs.trust_source,
            &authenticator,
        );
        let callback = move |
            state: &ai_native_l1_pow_bench::qrun_v06_canonical_execution_candidate::QRunV06CanonicalExecutionState,
            block: &ai_native_l1_pow_bench::qrun_v06_canonical_execution_candidate::QRunV06Block,
            quote_asset_id: [u8; 32],
        | {
            fresh_provider
                .authorize_for_block(
                    &state.network_id(),
                    &state.profile_id(),
                    &quote_asset_id,
                    block.height,
                )
                .map_err(|error| format!("fresh Q6TS/Q6QA authorization failed: {error:?}"))
        };
        quote_authorizer = Some(Box::new(callback));
        trust_authorized_pin = Some(authorized_pin);
    }

    let trusted_vault_tip = trusted_manifest_anchor(
        cfg,
        &data_dir,
        &descriptor.network_id(),
        &descriptor.profile_id(),
    )?;
    let mut runtime = if let Some(authorized_pin) = trust_authorized_pin.as_ref() {
        let provider = quote_authorizer
            .as_deref_mut()
            .ok_or("Q6TS authorized profile has no fresh Q6QA provider")?;
        QRunV06PermissionlessNodeRuntime::open_with_quote_asset_authorization(
            &data_dir,
            genesis,
            params,
            &authenticator,
            trusted_vault_tip.map(|(_, anchor)| anchor),
            authorized_pin,
            provider,
        )
        .map_err(|e| format!("Q6TS/Q6QA-authorized permissionless store open failed: {e:?}"))?
    } else if let Some((vault_generation, vault_anchor)) = trusted_vault_tip {
        let vault_directory = local_anchor_vault_directory(cfg)?;
        let segments_root = checkpoint_segments_directory(&data_dir)?;
        let vault = QRunV06LocalAnchorVault::open(
            &vault_directory,
            descriptor.network_id(),
            descriptor.profile_id(),
        )
        .map_err(|error| format!("C: anchor vault/witness-chain open failed: {error}"))?;
        let mut runtime = if let Some(witness) = vault.latest_checkpoint_segment_witness() {
            let (segment_dir, checkpoint_bytes) =
                read_checkpoint_segment(&data_dir, witness.sequence)?;
            QRunV06PermissionlessNodeRuntime::open_from_checkpoint_with_local_anchor_vault(
                &segment_dir,
                &checkpoint_bytes,
                witness.checkpoint_commitment,
                params,
                &authenticator,
                &verified_pin,
                &vault_directory,
            )
            .map_err(|error| {
                format!("C:/D: checkpoint-segment anchored store open/recovery failed: {error:?}")
            })?
        } else {
            QRunV06PermissionlessNodeRuntime::open_with_local_anchor_vault(
                &data_dir,
                genesis,
                params,
                &authenticator,
                vault_anchor,
                vault_generation,
                &verified_pin,
                &vault_directory,
            )
            .map_err(|error| {
                format!(
                    "C:/D: Genesis-rooted dual-disk anchored store open/recovery failed: {error:?}"
                )
            })?
        };
        runtime
            .enable_auto_checkpoint_rollover(&segments_root, verified_pin.clone())
            .map_err(|error| {
                format!("automatic checkpoint rollover configuration failed: {error:?}")
            })?;
        runtime
    } else if public_testnet && req(cfg, "node_role")? == "joining" {
        let vault_directory = local_anchor_vault_directory(cfg)?;
        let segments_root = checkpoint_segments_directory(&data_dir)?;
        let mut runtime = if derive_joiner_anchor_from_verified_genesis {
            QRunV06PermissionlessNodeRuntime::open_with_verified_genesis_fresh_anchor_vault(
                &data_dir,
                genesis,
                params,
                &authenticator,
                &verified_pin,
                &vault_directory,
            )
            .map_err(|error| {
                format!("verified fresh Joining Genesis/Vault bootstrap failed: {error:?}")
            })?
        } else {
            let trusted_genesis_anchor = parse_hex32(
                "trusted_manifest_anchor",
                req(cfg, "trusted_manifest_anchor")?,
            )?;
            QRunV06PermissionlessNodeRuntime::open_with_fresh_genesis_anchor_vault(
                &data_dir,
                genesis,
                params,
                &authenticator,
                &verified_pin,
                trusted_genesis_anchor,
                &vault_directory,
            )
            .map_err(|error| format!("fresh Joining Genesis/Vault bootstrap failed: {error:?}"))?
        };
        runtime
            .enable_auto_checkpoint_rollover(&segments_root, verified_pin.clone())
            .map_err(|error| {
                format!("fresh Joining checkpoint rollover setup failed: {error:?}")
            })?;
        runtime
    } else {
        QRunV06PermissionlessNodeRuntime::open(
            &data_dir,
            genesis,
            params,
            &authenticator,
            None,
            &verified_pin,
        )
        .map_err(|e| format!("Genesis-rooted permissionless durable store open failed: {e:?}"))?
    };
    let mut mempool =
        QRunV06PermissionlessMempool::open(&mempool_dir, QRunV06MempoolLimits::default())
            .map_err(|e| format!("Q6MJ mempool journal open failed: {e:?}"))?;
    // Public Testnet uses the founder account committed by the verified Genesis descriptor.
    // This prevents an arbitrary/zero producer address from being introduced by deployment config.
    let producer = if public_testnet {
        descriptor.founder_account()
    } else {
        parse_hex32("producer_account", req(cfg, "producer_account")?)?
    };
    if producer == [0; 32] {
        return Err("producer_account must not be zero".into());
    }
    // The supervisor owns the one-time Q6MJ/Q6MM startup reconciliation.
    let mut supervisor_config = QRunV06PermissionlessMiningSupervisorConfig::default();
    apply_public_testnet_listener_round_timeout(&mut supervisor_config, public_testnet);
    if let Some(n) = cfg.get("max_nonce_attempts_per_block") {
        supervisor_config.max_nonce_attempts_per_block = n
            .as_u64()
            .ok_or("max_nonce_attempts_per_block must be an unsigned integer")?;
    }
    supervisor_config
        .validate()
        .map_err(|e| format!("permissionless supervisor config invalid: {e:?}"))?;
    apply_public_testnet_mining_slice(&mut supervisor_config, public_testnet);
    let listener = TcpListener::bind(listen)
        .map_err(|e| format!("permissionless P2P listener bind failed: {e}"))?;
    let read_api_listener = if let Some(address) = read_api_address {
        let api = TcpListener::bind(address)
            .map_err(|error| format!("read-only RPC listener bind failed: {error}"))?;
        api.set_nonblocking(true)
            .map_err(|error| format!("read-only RPC listener nonblocking setup failed: {error}"))?;
        Some(api)
    } else {
        None
    };
    let shutdown = AtomicBool::new(false);
    println!("QFP6 PERMISSIONLESS BASE RUNTIME: STARTING (candidate qualification only)");
    println!("network_id={}", super::super::hex(&descriptor.network_id()));
    println!("profile_id={}", super::super::hex(&descriptor.profile_id()));
    println!(
        "genesis_snapshot_sha256={}",
        super::super::hex(&genesis_sha)
    );
    println!("listener={listen}");
    println!("bootstrap_peer_count={}", peers.len());
    println!(
        "listener_round_timeout_ms={}",
        supervisor_config.listener_round_timeout.as_millis()
    );
    println!(
        "listener_max_sessions_per_round={}",
        supervisor_config.max_sessions_per_listener_round
    );
    if public_testnet {
        println!(
            "public_testnet_max_nonce_attempts_per_slice={}",
            supervisor_config.max_nonce_attempts_per_block
        );
    }
    if public_testnet {
        println!("public_testnet_mode=ZERO_VALUE_CANDIDATE_ONLY");
        println!("public_testnet_role={}", req(cfg, "node_role")?);
        println!("public_value_claim=NONE");
        println!("public_market_or_usdt=NOT_PROVIDED");
        println!("public_inbound_noise=ANONYMOUS_UNAUTHENTICATED_XX");
        println!("remote_static_key_is_identity=FALSE");
        println!(
            "automatic_peer_discovery={}",
            if enable_q6pd_peer_discovery {
                "Q6PD_SIGNED_RECORD_GOSSIP; AUTO_DIAL_1_PER_30S"
            } else if enable_q6ar_candidate_pull {
                "PINNED_Q6AR_RELAY_REFRESH_300S"
            } else {
                "OFF"
            }
        );
        println!(
            "automatic_peer_dial={}",
            if enable_q6pd_peer_pull {
                "Q6PD_SIGNED_RECORDS_NOISE_KEY_PINNED_AUTO_DIAL_1_PER_30S"
            } else if enable_approved_peer_sync {
                "OPERATOR_SELECTED_ADDRESS_BOOK_PINS_ONLY_1_PER_30S"
            } else if !supervisor_peers.is_empty() {
                "CONFIGURED_BOOTSTRAP_PINS_ONLY_1_PER_30S"
            } else {
                "OFF"
            }
        );
        println!("unapproved_q6ar_candidates_auto_dialed=FALSE");
    } else if mainnet {
        println!("mainnet_native_mode=VALUE_BEARING_CANDIDATE");
        println!("mainnet_inbound_noise=NOISE_XX_STATIC_KEY_ALLOWLIST_REQUIRED");
        println!("mainnet_bootstrap_peer_count={}", supervisor_peers.len());
        println!("mainnet_peer_discovery=OPERATOR_PINNED_ONLY");
        println!("mainnet_market_authorization=SEPARATE_NOT_GRANTED_BY_Q6GA_V3");
    }
    if trust_authorized_pin.is_some() && quote_authorizer.is_some() {
        println!("Q6TS=DUAL_SIGNATURE_AUTHORIZED; Q6TS_FLOOR=INDEPENDENT_READ_ONLY; Q6QA=FRESH_HEIGHT_BOUND");
        println!("external_quote_asset_admission=Q6QA_REQUIRED");
    } else {
        println!(
            "Q6TS=NOT_CONFIGURED_NO_Q6PN_QUOTE_PIN; Q6TS_FLOOR=NOT_CONFIGURED; Q6QA=NOT_CONFIGURED"
        );
        println!("external_quote_asset_admission=DENIED_FAIL_CLOSED");
    }
    println!("Provider=NOT_REQUIRED; Q6EA=NOT_REQUIRED; QAP1=NOT_REQUIRED");
    println!(
        "founder_account_id={}",
        super::super::hex(&descriptor.founder_account())
    );
    println!("cp0651_owner_genesis_allocation_target_qzxb=1000000000");
    println!("cp0651_accounting_labels_circulating=FALSE; block_subsidy_qzxb=0");
    if let Some(book) = q6ar_address_book.as_ref() {
        println!("peer_address_book=ENABLED");
        println!(
            "peer_address_book_records_at_start={}",
            book.records().count()
        );
        println!("q6ar_candidate_address_book={enable_q6ar_candidate}");
        println!("q6ar_candidate_pull_enabled={enable_q6ar_candidate_pull}");
        if enable_q6ar_candidate {
            println!("q6ar_pinned_relay_count={}", q6ar_relay_pins.len());
            println!(
                "q6ar_trust_domain_registry=BOUND; relay_assignments={}",
                outbound_trust_domains
                    .as_ref()
                    .map_or(0, BootstrapTrustDomainPolicy::relay_count)
            );
            println!("q6ar_advertised_keys_auto_trusted=false");
            println!("q6ar_discovered_peers_auto_connected=false");
        } else {
            println!("q6ar_candidate_refresh=OFF; standalone_operator_peer_book=true");
        }
        println!("approved_peer_outbound_sync_enabled={enable_approved_peer_sync}");
        println!("approved_peer_sync_attempt_limit={max_approved_attempts}");
        println!("pinned_outbound_peer_count={}", supervisor_peers.len());
    } else {
        println!("peer_address_book=DISABLED_DEFAULT");
        println!("q6ar_candidate_address_book=DISABLED_DEFAULT");
    }
    if enable_q6ar_candidate_pull && supervisor_peers.is_empty() {
        return Err(
            "Q6AR candidate pull requires at least one operator-pinned bootstrap relay".into(),
        );
    }
    if enable_q6ar_candidate_pull {
        let book = q6ar_address_book
            .as_mut()
            .ok_or("Q6AR candidate pull has no address book")?;
        let trust_domains = outbound_trust_domains
            .as_ref()
            .ok_or("Q6AR candidate pull has no bound trust-domain registry")?;
        for peer in &supervisor_peers {
            match pull_q6ar_candidates_from_pinned_peer(
                peer.address,
                &local_key,
                &peer.noise_static_public_key,
                &descriptor.network_id(),
                &descriptor.profile_id(),
                QRunV06HistorySyncClientConfig::default(),
                peer.tls_server_name.as_deref(),
                book,
                trust_domains,
            ) {
                Ok(count) => println!(
                    "q6ar_candidate_pull_complete relay={} candidates_persisted={count}",
                    peer.address
                ),
                Err(error) => println!(
                    "q6ar_candidate_pull_failed relay={} error={error}; history_bootstrap_remains_authoritative=true",
                    peer.address
                ),
            }
        }
    }
    if enable_q6pd_peer_discovery {
        let store = q6pd_peer_record_store
            .as_ref()
            .ok_or("Q6PD discovery enabled but candidate store was not opened")?;
        println!("q6pd_peer_discovery=SIGNED_RECORD_SERVING");
        match q6pd_self_announcement_report.as_ref() {
            Some((peer_id, endpoint, tls_server_name, sequence, ingest)) => println!(
                "q6pd_self_announcement=SIGNED_PUBLIC_TCP_ENDPOINT peer_id={:02x?} endpoint={} tls_sni={:?} sequence={} ttl_seconds={} store_result={:?}",
                peer_id, endpoint, tls_server_name, sequence, Q6PD_MAX_TTL_SECS, ingest
            ),
            None => println!("q6pd_self_announcement=OFF"),
        }
        println!(
            "q6pd_peer_pull={}",
            if enable_q6pd_peer_pull && supervisor_peers.is_empty() {
                "ON_ROOT_SEED_INBOUND_SIGNED_RECORDS_PLUS_AUTO_DIAL_30S"
            } else if enable_q6pd_peer_pull {
                "ON_PINNED_BOOTSTRAP_REFRESH_300S_PLUS_SIGNED_CANDIDATE_AUTO_DIAL_30S"
            } else {
                "OFF"
            }
        );
        println!(
            "q6pd_candidate_records_at_start={}",
            store.candidate_count()
        );
        println!(
            "q6pd_candidate_auto_trust=false; q6pd_candidate_auto_dial={}",
            enable_q6pd_peer_pull
        );
    }
    if enable_q6pd_peer_pull {
        let local_q6pd_announcement_wire = q6pd_node_identity.as_ref().and_then(|identity| {
            q6pd_peer_record_store
                .as_ref()
                .and_then(|store| store.record_wire_for_peer(&identity.info().peer_id, now_ms))
        });
        let store = q6pd_peer_record_store
            .as_mut()
            .ok_or("Q6PD peer pull enabled but candidate store was not opened")?;
        // Query up to three independent configured seed peers on first start, matching the
        // multi-seed bootstrap pattern. Later cycles rotate across the complete configured set.
        // The genesis-rooted Seed is itself the first bootstrap endpoint: it has no upstream
        // Seed to pull from, so it receives signed announcements and auto-dials those records.
        if supervisor_peers.is_empty() && req(cfg, "node_role")? == "seed" {
            println!("q6pd_initial_pull=ROOT_SEED_NO_UPSTREAM; inbound_signed_record_ingest=ON; signed_candidate_auto_dial=ON");
        }
        // Older peers may not support Q6PD yet; one failed seed never blocks the node.
        // A configured DNS seed is resolved to all public A/AAAA routes at contact time.
        // Every route keeps the same TLS SNI and exact operator-pinned Noise key.
        for peer in supervisor_peers.iter().take(3) {
            let pull_config = QRunV06HistorySyncClientConfig {
                connect_timeout: std::time::Duration::from_secs(5),
                io_timeout: std::time::Duration::from_secs(10),
                ..QRunV06HistorySyncClientConfig::default()
            };
            let pull_result = if let Some(hostname) = peer.tls_server_name.as_deref() {
                pull_q6pd_peer_records_from_dns_seed_with_announcement(
                    hostname,
                    peer.address.port(),
                    &local_key,
                    &peer.noise_static_public_key,
                    &descriptor.network_id(),
                    &descriptor.profile_id(),
                    pull_config,
                    16,
                    local_q6pd_announcement_wire.as_deref(),
                    store,
                )
            } else {
                pull_q6pd_peer_records_from_pinned_peer_with_announcement(
                    peer.address,
                    &local_key,
                    &peer.noise_static_public_key,
                    &descriptor.network_id(),
                    &descriptor.profile_id(),
                    pull_config,
                    None,
                    16,
                    local_q6pd_announcement_wire.as_deref(),
                    store,
                )
            };
            match pull_result {
                Ok(report) => println!(
                    "q6pd_initial_pull_complete peer={} received={} inserted={} updated={} duplicate={} rejected={}",
                    peer.tls_server_name.as_deref().unwrap_or(&peer.address.to_string()),
                    report.records_received,
                    report.records_inserted,
                    report.records_updated,
                    report.records_duplicate,
                    report.records_rejected
                ),
                Err(error) => println!(
                    "q6pd_initial_pull_failed peer={} error={error}; startup_continues=true",
                    peer.tls_server_name.as_deref().unwrap_or(&peer.address.to_string())
                ),
            }
        }
    } else if enable_q6pd_peer_discovery {
        println!("q6pd_peer_pull=OFF; no Q6PD request is sent to bootstrap peers");
    } else {
        println!("q6pd_peer_discovery=OFF");
    }

    if read_api_listener.is_some() && supervisor_peers.is_empty() {
        return Err("read-only RPC requires pinned bootstrap peers in this candidate".into());
    }
    let supervisor_report = if supervisor_peers.is_empty() {
        println!("bootstrap_mode=GENESIS_ROOTED_NO_SEED_PEERS");
        if let Some(book) = q6ar_address_book.as_mut() {
            let trust_domains = outbound_trust_domains
                .as_ref()
                .ok_or("peer address book has no outbound trust-domain registry")?;
            match quote_authorizer.as_deref_mut() {
                Some(provider) => run_qfp6_permissionless_mining_supervisor_with_q6ar_candidate_and_quote_asset_authorization(
                    &listener,
                    supervisor_config,
                    &local_key,
                    &q6ar_relay_pins,
                    &descriptor.network_id(),
                    &descriptor.profile_id(),
                    &shutdown,
                    &mut runtime,
                    &authenticator,
                    producer,
                    &mut mempool,
                    book,
                    trust_domains,
                    provider,
                )
                .map_err(|e| format!("permissionless open-network/Q6AR/Q6QA supervisor stopped: {e}"))?,
                None => run_qfp6_permissionless_mining_supervisor_open_with_q6ar_candidate(
                    &listener,
                    supervisor_config,
                    &local_key,
                    &q6ar_relay_pins,
                    &descriptor.network_id(),
                    &descriptor.profile_id(),
                    &shutdown,
                    &mut runtime,
                    &authenticator,
                    producer,
                    &mut mempool,
                    book,
                    trust_domains,
                )
                .map_err(|e| format!("permissionless open-network/Q6AR supervisor stopped: {e}"))?,
            }
        } else if enable_q6pd_peer_discovery {
            let store = q6pd_peer_record_store
                .as_mut()
                .ok_or("Q6PD discovery enabled but candidate store was not opened")?;
            run_qfp6_permissionless_mining_supervisor_open_with_q6pd_candidate(
                &listener,
                supervisor_config,
                &local_key,
                &descriptor.network_id(),
                &descriptor.profile_id(),
                &shutdown,
                &mut runtime,
                &authenticator,
                producer,
                &mut mempool,
                quote_authorizer.as_deref_mut(),
                store,
                enable_q6pd_peer_pull,
                q6pd_self_announcement.clone(),
            )
            .map_err(|e| format!("permissionless open-network/Q6PD supervisor stopped: {e}"))?
        } else {
            match quote_authorizer.as_deref_mut() {
                Some(provider) => {
                    run_qfp6_permissionless_mining_supervisor_with_quote_asset_authorization(
                        &listener,
                        supervisor_config,
                        &local_key,
                        &q6ar_relay_pins,
                        &descriptor.network_id(),
                        &descriptor.profile_id(),
                        &shutdown,
                        &mut runtime,
                        &authenticator,
                        producer,
                        &mut mempool,
                        provider,
                    )
                    .map_err(|e| {
                        format!("permissionless open-network/Q6QA supervisor stopped: {e}")
                    })?
                }
                None => run_qfp6_permissionless_mining_supervisor_open(
                    &listener,
                    supervisor_config,
                    &local_key,
                    &descriptor.network_id(),
                    &descriptor.profile_id(),
                    &shutdown,
                    &mut runtime,
                    &authenticator,
                    producer,
                    &mut mempool,
                )
                .map_err(|e| format!("permissionless open-network supervisor stopped: {e}"))?,
            }
        }
    } else {
        // Keep each authenticated history session comfortably inside the finite 30-second
        // public listener window. Reconnects resume the same pinned source snapshot.
        let sync_config = QRunV06HistorySyncClientConfig {
            max_blocks_per_page: 4,
            max_pages: 3,
            max_rounds: 512,
            ..QRunV06HistorySyncClientConfig::default()
        };
        let report = if let Some(book) = q6ar_address_book.as_mut() {
            let peer_attempt_limit = if enable_approved_peer_sync {
                max_approved_attempts
            } else {
                supervisor_peers.len().min(64)
            };
            run_qfp6_permissionless_mining_supervisor_with_bootstrap_and_q6ar_candidate(
                &listener,
                supervisor_config,
                &local_key,
                &supervisor_peers,
                &q6ar_relay_pins,
                &descriptor.network_id(),
                &descriptor.profile_id(),
                &shutdown,
                &mut runtime,
                &authenticator,
                producer,
                &mut mempool,
                sync_config,
                peer_attempt_limit,
                book,
                outbound_trust_domains
                    .as_ref()
                    .ok_or("peer address book has no outbound trust-domain registry")?,
                quote_authorizer.as_deref_mut(),
                read_api_listener.as_ref(),
                q6pd_peer_record_store.as_mut(),
                enable_q6pd_peer_pull,
                q6pd_self_announcement,
            )
            .map_err(|e| format!("permissionless bootstrap/Q6AR/Q6QA supervisor stopped: {e}"))?
        } else {
            run_qfp6_permissionless_mining_supervisor_with_bootstrap(
                &listener,
                supervisor_config,
                &local_key,
                &supervisor_peers,
                &descriptor.network_id(),
                &descriptor.profile_id(),
                &shutdown,
                &mut runtime,
                &authenticator,
                producer,
                &mut mempool,
                sync_config,
                quote_authorizer.as_deref_mut(),
                read_api_listener.as_ref(),
                q6pd_peer_record_store.as_mut(),
                enable_q6pd_peer_pull,
                q6pd_self_announcement,
            )
            .map_err(|e| format!("permissionless bootstrap/Q6QA supervisor stopped: {e}"))?
        };
        println!(
            "permissionless_bootstrap_complete={}",
            report.bootstrap_sync.complete
        );
        println!("bootstrap_height={}", report.bootstrap_sync.final_height);
        report.supervisor
    };
    // Export the exact post-shutdown store/vault state for owner audit.
    // The immutable sequence-1 root pin is never rewritten from local state.
    let final_status = runtime
        .status()
        .map_err(|error| format!("cannot read final QFP6 runtime/vault status: {error}"))?;
    if mainnet {
        println!("permissionless_inbound_peer_policy=PINNED_NOISE_STATIC_KEY_ALLOWLIST");
        println!("bootstrap_peer_authentication=PINNED_OUTBOUND_AND_INBOUND");
    } else {
        println!("permissionless_inbound_peer_policy=ANONYMOUS_UNAUTHENTICATED_NOISE_XX");
        println!("bootstrap_peer_authentication=PINNED_OUTBOUND_ONLY");
    }
    println!(
        "blocks_committed={}",
        supervisor_report.blocks_durably_committed
    );
    println!("ending_height={}", supervisor_report.ending_height);
    println!(
        "final_manifest_generation={}",
        final_status.manifest_generation
    );
    println!(
        "final_manifest_anchor={}",
        super::super::hex(&final_status.manifest_anchor)
    );
    println!("final_canonical_height={}", final_status.height);
    println!(
        "final_canonical_tip={}",
        super::super::hex(&final_status.tip)
    );
    println!(
        "final_canonical_state_root={}",
        super::super::hex(&final_status.state_root)
    );
    println!(
        "anchor_persistence_status={}",
        runtime.local_anchor_persistence_status()
    );
    if let Some(vault_tip) = runtime.local_anchor_vault_tip() {
        println!("local_anchor_vault_sequence={}", vault_tip.sequence);
        println!(
            "local_anchor_vault_generation={}",
            vault_tip.manifest_generation
        );
        println!(
            "local_anchor_vault_anchor={}",
            super::super::hex(&vault_tip.manifest_anchor)
        );
    }
    println!(
        "pending_mempool_transactions={}",
        supervisor_report.pending_mempool_transactions
    );
    println!("runtime_status=STOPPED");
    println!("production_authorized=false");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        apply_public_testnet_listener_round_timeout, apply_public_testnet_mining_slice,
        approved_peer_outbound_sync_enabled, decode_q6ar_trust_domain_registry, endpoint,
        is_publicly_routable_peer_ip, load_peers, load_peers_with_resolver,
        max_approved_peer_sync_attempts, peer_address_book_enabled,
        q6ar_candidate_address_book_enabled, q6ar_candidate_pull_enabled,
        q6ar_trust_domains_rotation_authorized, q6pd_peer_discovery_enabled,
        q6pd_peer_pull_enabled, q6pd_peer_pull_requires_operator_pinned_seed,
        q6pd_self_announcement_enabled, read_regular_bounded, select_approved_bootstrap_peers,
        validate_anchor_vault_path_separation, validate_mainnet_native_topology,
        validate_permissionless_cp0651_genesis, validate_public_listener_opt_in,
        validate_public_testnet_topology, validate_q6ga_local_devnet_scope, validate_runtime_mode,
        BootstrapTrustDomainPolicy, QRunV06PermissionlessMiningSupervisorConfig,
        QRunV06PinnedBootstrapPeer,
    };
    use sha2::{Digest, Sha256};
    use std::time::Duration;

    #[test]
    fn public_testnet_listener_round_keeps_noise_handshake_worker_alive() {
        let mut public_config = QRunV06PermissionlessMiningSupervisorConfig::default();
        let private_default = public_config.listener_round_timeout;
        apply_public_testnet_listener_round_timeout(&mut public_config, true);
        assert_eq!(
            public_config.listener_round_timeout,
            Duration::from_secs(30)
        );
        assert!(public_config.listener_round_timeout > Duration::from_secs(8));

        // Keep each uninterrupted public-testnet mining slice well below the absolute Noise
        // handshake budget, then return to the accept loop without changing consensus rules.
        public_config.max_nonce_attempts_per_block = 1_000_000;
        apply_public_testnet_mining_slice(&mut public_config, true);
        assert_eq!(public_config.max_nonce_attempts_per_block, 4_096);

        let mut lower_public_config = QRunV06PermissionlessMiningSupervisorConfig::default();
        lower_public_config.max_nonce_attempts_per_block = 1_024;
        apply_public_testnet_mining_slice(&mut lower_public_config, true);
        assert_eq!(lower_public_config.max_nonce_attempts_per_block, 1_024);

        let mut overlay_config = QRunV06PermissionlessMiningSupervisorConfig::default();
        apply_public_testnet_listener_round_timeout(&mut overlay_config, false);
        assert_eq!(overlay_config.listener_round_timeout, private_default);
        assert_eq!(private_default, Duration::from_millis(250));
        let private_nonce_budget = overlay_config.max_nonce_attempts_per_block;
        apply_public_testnet_mining_slice(&mut overlay_config, false);
        assert_eq!(
            overlay_config.max_nonce_attempts_per_block,
            private_nonce_budget
        );
    }

    #[test]
    fn anchor_vault_path_must_not_overlap_data_or_mempool() {
        use std::path::PathBuf;

        let base = std::env::temp_dir().join("qfp6-anchor-path-separation");
        let data = base.join("data");
        let mempool = base.join("mempool");
        let vault = base.join("anchor-vault");

        assert!(validate_anchor_vault_path_separation(&vault, &data, &mempool).is_ok());
        assert!(validate_anchor_vault_path_separation(&data, &data, &mempool).is_err());
        assert!(
            validate_anchor_vault_path_separation(&data.join("anchor-vault"), &data, &mempool)
                .is_err()
        );
        assert!(validate_anchor_vault_path_separation(&base, &data, &mempool).is_err());
        assert!(validate_anchor_vault_path_separation(&mempool, &data, &mempool).is_err());
        assert!(validate_anchor_vault_path_separation(
            &mempool.join("anchor-vault"),
            &data,
            &mempool
        )
        .is_err());
        assert!(validate_anchor_vault_path_separation(
            &PathBuf::from(data.to_string_lossy().to_uppercase()),
            &data,
            &mempool
        )
        .is_err());
        assert!(validate_anchor_vault_path_separation(
            &base.join("..").join("anchor-vault"),
            &data,
            &mempool
        )
        .is_err());
    }

    #[test]
    fn q6ga_owner_approval_is_loopback_only_and_fails_closed_on_scope_changes() {
        let base = serde_json::json!({
            "mode": "permissionless-full-history-candidate",
            "listen_address": "127.0.0.1:30333",
            "allow_public_listener": false,
            "enable_approved_peer_outbound_sync": false,
            "enable_q6ar_candidate_address_book": false
        });
        assert!(validate_q6ga_local_devnet_scope(&base, false, 0).is_ok());

        let mut changed = base.clone();
        changed["listen_address"] = serde_json::json!("192.168.1.20:30333");
        assert!(validate_q6ga_local_devnet_scope(&changed, false, 0).is_err());

        let mut changed = base.clone();
        changed["enable_approved_peer_outbound_sync"] = serde_json::json!(true);
        assert!(validate_q6ga_local_devnet_scope(&changed, false, 0).is_err());

        let mut changed = base.clone();
        changed["enable_q6ar_candidate_address_book"] = serde_json::json!(true);
        assert!(validate_q6ga_local_devnet_scope(&changed, false, 0).is_err());

        assert!(validate_q6ga_local_devnet_scope(&base, false, 1).is_err());
        assert!(validate_q6ga_local_devnet_scope(&base, true, 0).is_err());
    }

    #[test]
    fn q6qa_q6ts_and_authority_inputs_must_be_bounded_regular_files() {
        let directory = std::env::temp_dir().join(format!(
            "qfp6-permissionless-trust-files-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("q6qa.bundle");
        std::fs::write(&path, b"signed-test-fixture").unwrap();

        assert_eq!(
            read_regular_bounded(&path, 64, "Q6QA test bundle").unwrap(),
            b"signed-test-fixture"
        );
        assert!(read_regular_bounded(&path, 4, "Q6QA test bundle").is_err());
        assert!(read_regular_bounded(&directory, 64, "Q6TS directory").is_err());

        #[cfg(windows)]
        {
            let link = directory.join("q6ts-link");
            if std::os::windows::fs::symlink_file(&path, &link).is_ok() {
                assert!(read_regular_bounded(&link, 64, "Q6TS linked envelope").is_err());
            }
        }
        #[cfg(unix)]
        {
            let link = directory.join("q6ts-link");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert!(read_regular_bounded(&link, 64, "Q6TS linked envelope").is_err());
        }

        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn q6pd_peer_discovery_flag_is_disabled_by_default_and_requires_boolean() {
        assert!(!q6pd_peer_discovery_enabled(&serde_json::json!({})).unwrap());
        assert!(q6pd_peer_discovery_enabled(
            &serde_json::json!({"enable_q6pd_peer_discovery": true})
        )
        .unwrap());
        assert!(!q6pd_peer_discovery_enabled(
            &serde_json::json!({"enable_q6pd_peer_discovery": false})
        )
        .unwrap());
        assert!(q6pd_peer_discovery_enabled(
            &serde_json::json!({"enable_q6pd_peer_discovery": "true"})
        )
        .is_err());
    }

    #[test]
    fn q6pd_self_announcement_flag_is_disabled_by_default_and_requires_boolean() {
        assert!(!q6pd_self_announcement_enabled(&serde_json::json!({})).unwrap());
        assert!(q6pd_self_announcement_enabled(
            &serde_json::json!({"enable_q6pd_self_announcement": true})
        )
        .unwrap());
        assert!(!q6pd_self_announcement_enabled(
            &serde_json::json!({"enable_q6pd_self_announcement": false})
        )
        .unwrap());
        assert!(q6pd_self_announcement_enabled(
            &serde_json::json!({"enable_q6pd_self_announcement": "true"})
        )
        .is_err());
    }

    #[test]
    fn genesis_root_seed_may_auto_dial_signed_records_without_upstream_seed() {
        assert!(!q6pd_peer_pull_requires_operator_pinned_seed("seed", 0));
        assert!(q6pd_peer_pull_requires_operator_pinned_seed("joining", 0));
        assert!(!q6pd_peer_pull_requires_operator_pinned_seed("joining", 1));
    }

    #[test]
    fn q6pd_peer_pull_flag_is_disabled_by_default_and_requires_boolean() {
        assert!(!q6pd_peer_pull_enabled(&serde_json::json!({})).unwrap());
        assert!(
            q6pd_peer_pull_enabled(&serde_json::json!({"enable_q6pd_peer_pull": true})).unwrap()
        );
        assert!(
            !q6pd_peer_pull_enabled(&serde_json::json!({"enable_q6pd_peer_pull": false})).unwrap()
        );
        assert!(
            q6pd_peer_pull_enabled(&serde_json::json!({"enable_q6pd_peer_pull": "true"})).is_err()
        );
    }

    #[test]
    fn standalone_peer_address_book_flag_is_disabled_by_default_and_requires_boolean() {
        assert!(!peer_address_book_enabled(&serde_json::json!({})).unwrap());
        assert!(
            peer_address_book_enabled(&serde_json::json!({"enable_peer_address_book": true}))
                .unwrap()
        );
        assert!(!peer_address_book_enabled(
            &serde_json::json!({"enable_peer_address_book": false})
        )
        .unwrap());
        assert!(peer_address_book_enabled(
            &serde_json::json!({"enable_peer_address_book": "true"})
        )
        .is_err());
    }

    #[test]
    fn approved_peer_outbound_sync_is_disabled_by_default_and_bounded() {
        assert!(!approved_peer_outbound_sync_enabled(&serde_json::json!({})).unwrap());
        assert!(approved_peer_outbound_sync_enabled(
            &serde_json::json!({"enable_approved_peer_outbound_sync": true})
        )
        .unwrap());
        assert_eq!(
            max_approved_peer_sync_attempts(&serde_json::json!({})).unwrap(),
            1
        );
        assert_eq!(
            max_approved_peer_sync_attempts(
                &serde_json::json!({"max_approved_peer_sync_attempts": 4})
            )
            .unwrap(),
            4
        );
        assert!(max_approved_peer_sync_attempts(
            &serde_json::json!({"max_approved_peer_sync_attempts": 5})
        )
        .is_err());
    }

    #[test]
    fn approved_bootstrap_attempts_cover_distinct_domains_before_reusing_one() {
        let candidates = vec![
            ("192.0.2.1:8333".parse().unwrap(), [1; 32]),
            ("192.0.2.2:8333".parse().unwrap(), [2; 32]),
            ("192.0.2.3:8333".parse().unwrap(), [3; 32]),
            ("192.0.2.4:8333".parse().unwrap(), [4; 32]),
            ("192.0.2.5:8333".parse().unwrap(), [5; 32]),
        ];
        let policy = BootstrapTrustDomainPolicy::new(
            [
                ([1; 32], [10; 32]),
                ([2; 32], [10; 32]),
                ([3; 32], [20; 32]),
                ([4; 32], [20; 32]),
                ([5; 32], [30; 32]),
            ],
            16,
            4,
        )
        .unwrap();

        let selected = select_approved_bootstrap_peers(&candidates, &[], &policy, 4).unwrap();
        assert_eq!(
            selected
                .iter()
                .map(|peer| peer.noise_static_public_key)
                .collect::<Vec<_>>(),
            vec![[1; 32], [3; 32], [5; 32], [2; 32]]
        );

        let limited = select_approved_bootstrap_peers(&candidates, &[], &policy, 2).unwrap();
        assert_eq!(
            limited
                .iter()
                .map(|peer| peer.noise_static_public_key)
                .collect::<Vec<_>>(),
            vec![[1; 32], [3; 32]]
        );

        let configured_relay = QRunV06PinnedBootstrapPeer {
            address: "1.1.1.1:443".parse().unwrap(),
            noise_static_public_key: [1; 32],
            tls_server_name: Some("seed.tailnet.ts.net".to_owned()),
        };
        let relay_selection =
            select_approved_bootstrap_peers(&candidates, &[configured_relay], &policy, 1).unwrap();
        assert_eq!(relay_selection[0].address, "1.1.1.1:443".parse().unwrap());
        assert_eq!(
            relay_selection[0].tls_server_name.as_deref(),
            Some("seed.tailnet.ts.net")
        );
    }

    #[test]
    fn q6ar_address_book_is_opt_in_and_rejects_non_boolean_flags() {
        assert!(!q6ar_candidate_address_book_enabled(&serde_json::json!({})).unwrap());
        assert!(q6ar_candidate_address_book_enabled(
            &serde_json::json!({"enable_q6ar_candidate_address_book": true})
        )
        .unwrap());
        assert!(!q6ar_candidate_address_book_enabled(
            &serde_json::json!({"enable_q6ar_candidate_address_book": false})
        )
        .unwrap());
        assert!(q6ar_candidate_address_book_enabled(
            &serde_json::json!({"enable_q6ar_candidate_address_book": "true"})
        )
        .is_err());
    }

    #[test]
    fn q6ar_candidate_pull_is_opt_in_and_requires_a_boolean() {
        assert!(!q6ar_candidate_pull_enabled(&serde_json::json!({})).unwrap());
        assert!(q6ar_candidate_pull_enabled(
            &serde_json::json!({ "enable_q6ar_candidate_pull": true })
        )
        .unwrap());
        assert!(!q6ar_candidate_pull_enabled(
            &serde_json::json!({ "enable_q6ar_candidate_pull": false })
        )
        .unwrap());
        assert!(q6ar_candidate_pull_enabled(
            &serde_json::json!({ "enable_q6ar_candidate_pull": "true" })
        )
        .is_err());
    }

    #[test]
    fn q6ar_registry_rotation_requires_explicit_boolean_operator_authorization() {
        assert!(!q6ar_trust_domains_rotation_authorized(&serde_json::json!({})).unwrap());
        assert!(q6ar_trust_domains_rotation_authorized(
            &serde_json::json!({"q6ar_trust_domains_rotation_authorized": true})
        )
        .unwrap());
        assert!(!q6ar_trust_domains_rotation_authorized(
            &serde_json::json!({"q6ar_trust_domains_rotation_authorized": false})
        )
        .unwrap());
        assert!(q6ar_trust_domains_rotation_authorized(
            &serde_json::json!({"q6ar_trust_domains_rotation_authorized": "true"})
        )
        .is_err());
    }

    #[test]
    fn q6ar_trust_domain_registry_requires_pinned_digest_and_all_active_relays() {
        let registry = serde_json::json!({
            "version": 1,
            "max_candidates_per_domain": 24,
            "max_relays_per_domain": 4,
            "assignments": [
                {
                    "relay_static_public_key": "0101010101010101010101010101010101010101010101010101010101010101",
                    "trust_domain_id": "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"
                },
                {
                    "relay_static_public_key": "0202020202020202020202020202020202020202020202020202020202020202",
                    "trust_domain_id": "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"
                }
            ]
        });
        let bytes = serde_json::to_vec(&registry).unwrap();
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        let policy =
            decode_q6ar_trust_domain_registry(&bytes, digest, &[[1; 32], [2; 32]]).unwrap();
        assert_eq!(policy.relay_count(), 2);
        assert_eq!(policy.domain_for(&[1; 32]).unwrap(), [10; 32]);
        assert_eq!(policy.domain_for(&[2; 32]).unwrap(), [10; 32]);

        assert!(decode_q6ar_trust_domain_registry(&bytes, [0; 32], &[[1; 32]]).is_err());
        assert!(decode_q6ar_trust_domain_registry(&bytes, digest, &[[3; 32]]).is_err());
    }

    #[test]
    fn q6ar_trust_domain_registry_rejects_ambiguous_or_unknown_schema() {
        let duplicate = serde_json::json!({
            "version": 1,
            "max_candidates_per_domain": 24,
            "max_relays_per_domain": 4,
            "assignments": [
                {
                    "relay_static_public_key": "0101010101010101010101010101010101010101010101010101010101010101",
                    "trust_domain_id": "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"
                },
                {
                    "relay_static_public_key": "0101010101010101010101010101010101010101010101010101010101010101",
                    "trust_domain_id": "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
                }
            ]
        });
        let duplicate_bytes = serde_json::to_vec(&duplicate).unwrap();
        let duplicate_digest: [u8; 32] = Sha256::digest(&duplicate_bytes).into();
        assert!(
            decode_q6ar_trust_domain_registry(&duplicate_bytes, duplicate_digest, &[[1; 32]])
                .is_err()
        );

        let unknown_field = serde_json::json!({
            "version": 1,
            "max_candidates_per_domain": 24,
            "max_relays_per_domain": 4,
            "assignments": [{
                "relay_static_public_key": "0101010101010101010101010101010101010101010101010101010101010101",
                "trust_domain_id": "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
                "operator_name": "untrusted-remote-label"
            }]
        });
        let unknown_bytes = serde_json::to_vec(&unknown_field).unwrap();
        let unknown_digest: [u8; 32] = Sha256::digest(&unknown_bytes).into();
        assert!(
            decode_q6ar_trust_domain_registry(&unknown_bytes, unknown_digest, &[[1; 32]]).is_err()
        );

        // Duplicate object keys are ambiguous and must fail closed at both levels.
        let duplicate_top_level = br#"{
            "version": 1,
            "ver\u0073ion": 1,
            "max_candidates_per_domain": 24,
            "max_relays_per_domain": 4,
            "assignments": [{
                "relay_static_public_key": "0101010101010101010101010101010101010101010101010101010101010101",
                "trust_domain_id": "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"
            }]
        }"#;
        let duplicate_top_level_digest: [u8; 32] = Sha256::digest(duplicate_top_level).into();
        assert!(decode_q6ar_trust_domain_registry(
            duplicate_top_level,
            duplicate_top_level_digest,
            &[[1; 32]]
        )
        .is_err());

        let duplicate_assignment_field = br#"{
            "version": 1,
            "max_candidates_per_domain": 24,
            "max_relays_per_domain": 4,
            "assignments": [{
                "relay_static_public_key": "0101010101010101010101010101010101010101010101010101010101010101",
                "relay_static_public_key": "0202020202020202020202020202020202020202020202020202020202020202",
                "trust_domain_id": "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"
            }]
        }"#;
        let duplicate_assignment_digest: [u8; 32] =
            Sha256::digest(duplicate_assignment_field).into();
        assert!(decode_q6ar_trust_domain_registry(
            duplicate_assignment_field,
            duplicate_assignment_digest,
            &[[1; 32]]
        )
        .is_err());
    }

    #[test]
    fn permissionless_genesis_accepts_only_cp0651_fixed_seven_billion_policy() {
        use ai_native_l1_pow_bench::{
            qrun_v06_canonical_execution_candidate::QRunV06CanonicalExecutionState,
            qrun_v06_tokenomics_candidate::QRunV06MiningScheduleCandidate,
        };
        const NETWORK: [u8; 32] = [0x61; 32];
        const PROFILE: [u8; 32] = [0x62; 32];
        const OWNER: [u8; 32] = [0x63; 32];
        let schedule = QRunV06MiningScheduleCandidate::cp0422_research_candidate();

        let legacy_0528 = QRunV06CanonicalExecutionState::cp0528_genesis_candidate(
            NETWORK, PROFILE, OWNER, schedule,
        )
        .unwrap();
        assert!(validate_permissionless_cp0651_genesis(&legacy_0528, &OWNER, &[0x64; 32]).is_err());

        let legacy_0604 = QRunV06CanonicalExecutionState::cp0604_genesis_candidate(
            NETWORK, PROFILE, OWNER, schedule,
        )
        .unwrap();
        assert!(validate_permissionless_cp0651_genesis(&legacy_0604, &OWNER, &[0x65; 32]).is_err());

        let current =
            QRunV06CanonicalExecutionState::cp0651_genesis_candidate(NETWORK, PROFILE, OWNER)
                .unwrap();
        let policy_fingerprint = current.cp0651_supply().unwrap().policy_fingerprint();
        assert!(
            validate_permissionless_cp0651_genesis(&current, &OWNER, &policy_fingerprint).is_ok()
        );
        assert!(
            validate_permissionless_cp0651_genesis(&current, &[0x66; 32], &policy_fingerprint)
                .is_err()
        );
        assert!(validate_permissionless_cp0651_genesis(&current, &OWNER, &[0x67; 32]).is_err());
    }

    #[test]
    fn permissionless_listener_accepts_wildcard_bind_but_peer_endpoints_must_be_specific() {
        assert_eq!(
            endpoint("listen", "0.0.0.0:30333", true).unwrap().port(),
            30333
        );
        assert!(endpoint("peer", "0.0.0.0:30333", false).is_err());
        assert!(endpoint("peer", "239.1.1.1:30333", false).is_err());
        assert!(endpoint("peer", "127.0.0.1:30333", false).is_ok());
        assert!(endpoint("listen", "0.0.0.0:0", true).is_err());
    }

    #[test]
    fn public_listener_bind_requires_explicit_candidate_opt_in() {
        use serde_json::json;
        use std::net::SocketAddr;
        let wildcard: SocketAddr = "0.0.0.0:30333".parse().unwrap();
        assert!(validate_public_listener_opt_in(&json!({}), wildcard).is_err());
        assert!(validate_public_listener_opt_in(
            &json!({"allow_public_listener": false}),
            wildcard
        )
        .is_err());
        assert!(
            validate_public_listener_opt_in(&json!({"allow_public_listener": true}), wildcard)
                .is_ok()
        );
        let private: SocketAddr = "10.0.0.2:30333".parse().unwrap();
        assert!(validate_public_listener_opt_in(&json!({}), private).is_ok());
    }

    #[test]
    fn empty_bootstrap_seed_set_is_accepted_only_as_a_hash_pinned_array() {
        use std::{fs, path::PathBuf};
        let path: PathBuf =
            std::env::temp_dir().join(format!("qfp6-empty-seeds-{}.json", std::process::id()));
        fs::write(&path, b"[]").unwrap();
        let digest: [u8; 32] = Sha256::digest(b"[]").into();
        assert!(load_peers(&path, digest, false).unwrap().is_empty());
        assert!(load_peers(&path, [0xA5; 32], false).is_err());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn public_testnet_dns_relay_requires_fqdn_port_443_and_public_addresses() {
        use super::resolve_bootstrap_endpoint_with;

        let resolved = resolve_bootstrap_endpoint_with(
            "bootstrap peer",
            "seed.example.net:443",
            true,
            |host, port| {
                assert_eq!(host, "seed.example.net");
                assert_eq!(port, 443);
                Ok(vec!["1.1.1.1:443".parse().unwrap()])
            },
        )
        .unwrap();
        assert_eq!(resolved.0, "1.1.1.1:443".parse().unwrap());
        assert_eq!(resolved.1.as_deref(), Some("seed.example.net"));

        assert!(resolve_bootstrap_endpoint_with(
            "bootstrap peer",
            "seed.example.net:8443",
            true,
            |_, _| panic!("resolver must not run for a disallowed relay port"),
        )
        .is_err());
        assert!(resolve_bootstrap_endpoint_with(
            "bootstrap peer",
            "localhost:443",
            true,
            |_, _| panic!("resolver must not run for localhost"),
        )
        .is_err());
        assert!(resolve_bootstrap_endpoint_with(
            "bootstrap peer",
            "seed.example.net:443",
            false,
            |_, _| panic!("DNS must remain disabled outside Public Testnet"),
        )
        .is_err());
    }

    #[test]
    fn public_testnet_dns_relay_rejects_private_or_mixed_dns_answers() {
        use super::resolve_bootstrap_endpoint_with;

        for answers in [
            vec!["10.0.0.8:443".parse().unwrap()],
            vec![
                "1.1.1.1:443".parse().unwrap(),
                "192.168.1.20:443".parse().unwrap(),
            ],
        ] {
            assert!(resolve_bootstrap_endpoint_with(
                "bootstrap peer",
                "seed.example.net:443",
                true,
                |_, _| Ok(answers.clone()),
            )
            .is_err());
        }
    }

    #[test]
    fn hash_pinned_bootstrap_file_loads_dns_relay_with_noise_pin() {
        use std::{fs, path::PathBuf};

        let key = "11".repeat(32);
        let bytes =
            format!(r#"[{{"address":"seed.example.net:443","noise_static_public_key":"{key}"}}]"#)
                .into_bytes();
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        let path: PathBuf =
            std::env::temp_dir().join(format!("qfp6-dns-relay-peers-{}.json", std::process::id()));
        fs::write(&path, &bytes).unwrap();

        let loaded = load_peers_with_resolver(&path, digest, true, |host, port| {
            assert_eq!(host, "seed.example.net");
            assert_eq!(port, 443);
            Ok(vec!["1.1.1.1:443".parse().unwrap()])
        })
        .unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].address, "1.1.1.1:443".parse().unwrap());
        assert_eq!(loaded[0].noise_static_public_key, [0x11; 32]);
        assert_eq!(
            loaded[0].tls_server_name.as_deref(),
            Some("seed.example.net")
        );

        assert!(load_peers_with_resolver(&path, digest, false, |_, _| {
            panic!("DNS must remain disabled outside Public Testnet")
        })
        .is_err());

        fs::remove_file(path).unwrap();
    }

    fn public_testnet_cfg(role: &str) -> serde_json::Value {
        serde_json::json!({
            "mode": "public-testnet-zero-value-candidate",
            "allow_candidate_runtime": true,
            "allow_public_listener": true,
            "public_testnet_acknowledgement": "ZERO_VALUE_PUBLIC_TESTNET_NO_MAINNET_NO_MARKET",
            "public_inbound_security_acknowledgement": "ANONYMOUS_NOISE_XX_UNAUTHENTICATED",
            "node_role": role
        })
    }

    #[test]
    fn public_testnet_mode_requires_exact_flags_acknowledgements_and_role() {
        let good = public_testnet_cfg("seed");
        assert!(validate_runtime_mode(&good, true, false).is_ok());
        assert!(validate_runtime_mode(&good, false, false).is_err());
        assert!(validate_runtime_mode(&good, false, true).is_err());

        let mut wrong_mode = good.clone();
        wrong_mode["mode"] = serde_json::json!("permissionless-full-history-candidate");
        assert!(validate_runtime_mode(&wrong_mode, true, false).is_err());

        let mut missing_candidate = good.clone();
        missing_candidate["allow_candidate_runtime"] = serde_json::json!(false);
        assert!(validate_runtime_mode(&missing_candidate, true, false).is_err());

        let mut missing_listener = good.clone();
        missing_listener["allow_public_listener"] = serde_json::json!(false);
        assert!(validate_runtime_mode(&missing_listener, true, false).is_err());

        let mut missing_ack = good.clone();
        missing_ack["public_testnet_acknowledgement"] = serde_json::json!("yes");
        assert!(validate_runtime_mode(&missing_ack, true, false).is_err());

        let mut missing_security_ack = good.clone();
        missing_security_ack["public_inbound_security_acknowledgement"] =
            serde_json::json!("pinned");
        assert!(validate_runtime_mode(&missing_security_ack, true, false).is_err());

        let mut wrong_role = good;
        wrong_role["node_role"] = serde_json::json!("validator");
        assert!(validate_runtime_mode(&wrong_role, true, false).is_err());

        let private_mode = serde_json::json!({
            "mode": "permissionless-full-history-candidate",
            "allow_candidate_runtime": true
        });
        assert!(validate_runtime_mode(&private_mode, false, false).is_ok());
        let public_opt_in_on_private_cli = serde_json::json!({
            "mode": "permissionless-full-history-candidate",
            "allow_candidate_runtime": true,
            "allow_public_listener": true
        });
        assert!(validate_runtime_mode(&public_opt_in_on_private_cli, false, false).is_err());
    }

    fn mainnet_native_cfg() -> serde_json::Value {
        serde_json::json!({
            "mode": "mainnet-native-value-candidate",
            "allow_candidate_runtime": true,
            "allow_public_listener": true,
            "mainnet_native_acknowledgement": "QZXB_MAINNET_NATIVE_VALUE_OWNER_AUTHORIZATION_REQUIRED",
            "public_inbound_security_acknowledgement": "PINNED_NOISE_STATIC_KEY_ALLOWLIST_REQUIRED"
        })
    }

    #[test]
    fn mainnet_native_mode_requires_explicit_v3_scope_and_pinned_inbound_policy() {
        let good = mainnet_native_cfg();
        assert!(validate_runtime_mode(&good, false, true).is_ok());
        assert!(validate_runtime_mode(&good, true, false).is_err());
        assert!(validate_runtime_mode(&good, true, true).is_err());

        let mut wrong_mode = good.clone();
        wrong_mode["mode"] = serde_json::json!("public-testnet-zero-value-candidate");
        assert!(validate_runtime_mode(&wrong_mode, false, true).is_err());

        let mut missing_ack = good.clone();
        missing_ack["mainnet_native_acknowledgement"] = serde_json::json!("yes");
        assert!(validate_runtime_mode(&missing_ack, false, true).is_err());

        let mut anonymous_inbound = good.clone();
        anonymous_inbound["public_inbound_security_acknowledgement"] =
            serde_json::json!("ANONYMOUS_NOISE_XX_UNAUTHENTICATED");
        assert!(validate_runtime_mode(&anonymous_inbound, false, true).is_err());

        let mut mixed_testnet_scope = good.clone();
        mixed_testnet_scope["public_testnet_acknowledgement"] =
            serde_json::json!("ZERO_VALUE_PUBLIC_TESTNET_NO_MAINNET_NO_MARKET");
        assert!(validate_runtime_mode(&mixed_testnet_scope, false, true).is_err());
    }

    #[test]
    fn mainnet_native_topology_requires_nonempty_publicly_routable_pinned_peers() {
        use serde_json::json;
        use std::net::SocketAddr;

        let cfg = mainnet_native_cfg();
        let wildcard: SocketAddr = "0.0.0.0:30333".parse().unwrap();
        let peer = QRunV06PinnedBootstrapPeer {
            address: "1.1.1.1:30333".parse().unwrap(),
            noise_static_public_key: [0x79; 32],
            tls_server_name: None,
        };
        assert!(
            validate_mainnet_native_topology(&cfg, wildcard, std::slice::from_ref(&peer)).is_ok()
        );
        let relay_peer = QRunV06PinnedBootstrapPeer {
            address: "1.1.1.1:443".parse().unwrap(),
            noise_static_public_key: [0x7B; 32],
            tls_server_name: Some("seed.tailnet.ts.net".to_owned()),
        };
        assert!(
            validate_mainnet_native_topology(&cfg, wildcard, &[relay_peer]).is_err(),
            "Mainnet-native topology must reject the Public Testnet TLS/SNI relay path"
        );
        assert!(validate_mainnet_native_topology(&cfg, wildcard, &[]).is_err());

        let private_peer = QRunV06PinnedBootstrapPeer {
            address: "10.0.0.2:30333".parse().unwrap(),
            noise_static_public_key: [0x7A; 32],
            tls_server_name: None,
        };
        assert!(validate_mainnet_native_topology(&cfg, wildcard, &[private_peer]).is_err());

        let private_listener: SocketAddr = "192.168.1.20:30333".parse().unwrap();
        assert!(validate_mainnet_native_topology(
            &cfg,
            private_listener,
            std::slice::from_ref(&peer)
        )
        .is_err());

        let mut no_public_opt_in = cfg.clone();
        no_public_opt_in["allow_public_listener"] = json!(false);
        assert!(validate_mainnet_native_topology(
            &no_public_opt_in,
            wildcard,
            std::slice::from_ref(&peer)
        )
        .is_err());
    }

    #[test]
    fn bootstrap_peer_ip_filter_rejects_special_use_ranges_and_handles_mapped_ipv4() {
        use std::net::IpAddr;

        for address in [
            "1.1.1.1",
            "8.8.8.8",
            "2606:4700:4700::1111",
            "::ffff:1.1.1.1",
        ] {
            assert!(
                is_publicly_routable_peer_ip(address.parse::<IpAddr>().unwrap()),
                "{address} should be accepted"
            );
        }

        for address in [
            "0.1.2.3",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.2",
            "192.0.0.8",
            "192.0.2.1",
            "192.88.99.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "240.0.0.1",
            "224.0.0.1",
            "192.168.1.1",
            "::",
            "::1",
            "::ffff:192.168.1.1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
            "64:ff9b:1::1",
            "100::1",
            "2001:db8::1",
            "2001:2::1",
            "2001:10::1",
            "2001:20::1",
            "2002::1",
            "3fff::1",
        ] {
            assert!(
                !is_publicly_routable_peer_ip(address.parse::<IpAddr>().unwrap()),
                "{address} must be rejected"
            );
        }
    }

    #[test]
    fn public_testnet_seed_and_joining_topology_are_enforced() {
        use serde_json::json;
        use std::net::SocketAddr;

        let wildcard: SocketAddr = "0.0.0.0:30333".parse().unwrap();
        let seed = json!({"node_role": "seed"});
        assert!(validate_public_testnet_topology(&seed, wildcard, &[]).is_ok());

        let valid_peer = QRunV06PinnedBootstrapPeer {
            address: "1.1.1.1:30333".parse().unwrap(),
            noise_static_public_key: [0x71; 32],
            tls_server_name: None,
        };
        assert!(validate_public_testnet_topology(
            &json!({"node_role": "seed"}),
            wildcard,
            std::slice::from_ref(&valid_peer)
        )
        .is_err());
        assert!(
            validate_public_testnet_topology(&json!({"node_role": "joining"}), wildcard, &[])
                .is_err()
        );
        assert!(validate_public_testnet_topology(
            &json!({"node_role": "joining"}),
            wildcard,
            std::slice::from_ref(&valid_peer)
        )
        .is_ok());

        let private_peer = QRunV06PinnedBootstrapPeer {
            address: "100.64.0.2:30333".parse().unwrap(),
            noise_static_public_key: [0x72; 32],
            tls_server_name: None,
        };
        assert!(validate_public_testnet_topology(
            &json!({"node_role": "joining"}),
            wildcard,
            &[private_peer]
        )
        .is_err());

        let documentation_listen: SocketAddr = "192.0.2.10:30333".parse().unwrap();
        assert!(validate_public_testnet_topology(&seed, documentation_listen, &[]).is_err());

        let loopback: SocketAddr = "127.0.0.1:31000".parse().unwrap();
        let outbound_only = json!({
            "node_role": "joining",
            "enable_q6pd_peer_discovery": true,
            "enable_q6pd_peer_pull": true,
            "enable_q6pd_self_announcement": false
        });
        assert!(validate_public_testnet_topology(
            &outbound_only,
            loopback,
            std::slice::from_ref(&valid_peer)
        )
        .is_ok());
        assert!(validate_public_testnet_topology(&outbound_only, loopback, &[]).is_err());

        let discovery_disabled = json!({
            "node_role": "joining",
            "enable_q6pd_peer_discovery": false,
            "enable_q6pd_peer_pull": true,
            "enable_q6pd_self_announcement": false
        });
        assert!(validate_public_testnet_topology(
            &discovery_disabled,
            loopback,
            std::slice::from_ref(&valid_peer)
        )
        .is_err());

        assert!(validate_public_testnet_topology(
            &outbound_only,
            wildcard,
            std::slice::from_ref(&valid_peer)
        )
        .is_err());
    }
}

#[cfg(test)]
mod manifest_anchor_tests {
    use super::{local_anchor_record_digest, trusted_manifest_anchor};
    use serde_json::{json, Value};
    use std::{fs, path::PathBuf};

    fn test_dir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(1);
        let sequence = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "qfp6-permissionless-anchor-{}-{sequence}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn write_vault_record(
        vault: &PathBuf,
        sequence: u64,
        network: [u8; 32],
        profile: [u8; 32],
        generation: u64,
        anchor: [u8; 32],
        previous: [u8; 32],
    ) -> [u8; 32] {
        let records = vault.join("records");
        fs::create_dir_all(&records).unwrap();
        let mut record = json!({
            "schema": "qfp6-local-anchor-vault/v1",
            "sequence": sequence,
            "network_id_hex": hex(&network),
            "profile_id_hex": hex(&profile),
            "manifest_generation": generation,
            "manifest_anchor_hex": hex(&anchor),
            "previous_record_sha256": hex(&previous),
        });
        let digest = local_anchor_record_digest(&record).unwrap();
        record["record_sha256"] = Value::String(hex(&digest));
        fs::write(
            records.join(format!("q6av-{sequence:020}.json")),
            serde_json::to_vec_pretty(&record).unwrap(),
        )
        .unwrap();
        digest
    }

    #[test]
    fn existing_manifest_history_requires_anchor_and_matching_local_vault() {
        let dir = test_dir();
        let network = [0x22; 32];
        let profile = [0x33; 32];
        assert_eq!(
            trusted_manifest_anchor(&json!({}), &dir, &network, &profile).unwrap(),
            None
        );

        let manifests = dir.join("manifests");
        fs::create_dir_all(&manifests).unwrap();
        fs::write(
            manifests.join("qfp6-manifest-00000000000000000000.q6mf"),
            b"fixture",
        )
        .unwrap();
        assert!(trusted_manifest_anchor(&json!({}), &dir, &network, &profile).is_err());

        let vault = dir.join("vault");
        let anchor = [0x11; 32];
        write_vault_record(&vault, 1, network, profile, 0, anchor, [0; 32]);
        let cfg = json!({
            "trusted_manifest_anchor": hex(&anchor),
            "trusted_manifest_floor_generation": 0,
            "trusted_manifest_floor_anchor": hex(&anchor),
            "trusted_manifest_anchor_vault_path": vault.to_string_lossy().to_string()
        });
        assert_eq!(
            trusted_manifest_anchor(&cfg, &dir, &network, &profile).unwrap(),
            Some((0, anchor))
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn local_vault_rejects_generation_rollback_and_network_profile_mismatch() {
        let dir = test_dir();
        let network = [0x22; 32];
        let profile = [0x33; 32];
        let manifests = dir.join("manifests");
        fs::create_dir_all(&manifests).unwrap();
        fs::write(
            manifests.join("qfp6-manifest-00000000000000000000.q6mf"),
            b"fixture",
        )
        .unwrap();

        let vault = dir.join("vault");
        let anchor = [0x11; 32];
        write_vault_record(&vault, 1, network, profile, 1, anchor, [0; 32]);
        let cfg = json!({
            "trusted_manifest_anchor": hex(&anchor),
            "trusted_manifest_anchor_vault_path": vault.to_string_lossy().to_string()
        });
        assert!(trusted_manifest_anchor(&cfg, &dir, &network, &profile).is_err());
        assert!(trusted_manifest_anchor(&cfg, &dir, &[0x44; 32], &profile).is_err());
        assert!(trusted_manifest_anchor(&cfg, &dir, &network, &[0x55; 32]).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn local_vault_rejects_record_checksum_tampering_and_sequence_gaps() {
        let dir = test_dir();
        let network = [0x22; 32];
        let profile = [0x33; 32];
        let manifests = dir.join("manifests");
        fs::create_dir_all(&manifests).unwrap();
        fs::write(
            manifests.join("qfp6-manifest-00000000000000000000.q6mf"),
            b"fixture",
        )
        .unwrap();

        let vault = dir.join("vault");
        let anchor = [0x11; 32];
        write_vault_record(&vault, 1, network, profile, 0, anchor, [0; 32]);
        let record_path = vault.join("records").join("q6av-00000000000000000001.json");
        let mut record: Value = serde_json::from_slice(&fs::read(&record_path).unwrap()).unwrap();
        record["manifest_anchor_hex"] = Value::String(hex(&[0x77; 32]));
        fs::write(&record_path, serde_json::to_vec_pretty(&record).unwrap()).unwrap();

        let cfg = json!({
            "trusted_manifest_anchor": hex(&anchor),
            "trusted_manifest_anchor_vault_path": vault.to_string_lossy().to_string()
        });
        assert!(trusted_manifest_anchor(&cfg, &dir, &network, &profile).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn local_vault_chain_requires_exact_previous_record_digest() {
        let dir = test_dir();
        let network = [0x22; 32];
        let profile = [0x33; 32];
        let manifests = dir.join("manifests");
        fs::create_dir_all(&manifests).unwrap();
        for generation in 0..=1 {
            fs::write(
                manifests.join(format!("qfp6-manifest-{generation:020}.q6mf")),
                b"fixture",
            )
            .unwrap();
        }

        let vault = dir.join("vault");
        let anchor = [0x12; 32];
        let first_digest = write_vault_record(&vault, 1, network, profile, 0, [0x11; 32], [0; 32]);
        write_vault_record(&vault, 2, network, profile, 1, anchor, [0x99; 32]);
        let cfg = json!({
            "trusted_manifest_anchor": hex(&[0x11; 32]),
            "trusted_manifest_floor_generation": 0,
            "trusted_manifest_floor_anchor": hex(&[0x11; 32]),
            "trusted_manifest_anchor_vault_path": vault.to_string_lossy().to_string()
        });
        assert_ne!(first_digest, [0x99; 32]);
        assert!(trusted_manifest_anchor(&cfg, &dir, &network, &profile).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn local_vault_missing_is_fail_closed_for_existing_history() {
        let dir = test_dir();
        let network = [0x22; 32];
        let profile = [0x33; 32];
        let manifests = dir.join("manifests");
        fs::create_dir_all(&manifests).unwrap();
        fs::write(
            manifests.join("qfp6-manifest-00000000000000000000.q6mf"),
            b"fixture",
        )
        .unwrap();
        let missing_vault = dir.join("vault-not-created");
        let cfg = json!({
            "trusted_manifest_anchor": hex(&[0x11; 32]),
            "trusted_manifest_anchor_vault_path": missing_vault.to_string_lossy().to_string()
        });
        assert!(trusted_manifest_anchor(&cfg, &dir, &network, &profile).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn local_vault_rejects_sequence_gap_even_when_record_hashes_are_valid() {
        let dir = test_dir();
        let network = [0x22; 32];
        let profile = [0x33; 32];
        let manifests = dir.join("manifests");
        fs::create_dir_all(&manifests).unwrap();
        fs::write(
            manifests.join("qfp6-manifest-00000000000000000000.q6mf"),
            b"fixture",
        )
        .unwrap();

        let vault = dir.join("vault");
        let first = write_vault_record(&vault, 1, network, profile, 0, [0x11; 32], [0; 32]);
        write_vault_record(&vault, 3, network, profile, 2, [0x33; 32], first);
        let cfg = json!({
            "trusted_manifest_anchor": hex(&[0x11; 32]),
            "trusted_manifest_anchor_vault_path": vault.to_string_lossy().to_string()
        });
        assert!(trusted_manifest_anchor(&cfg, &dir, &network, &profile).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn local_vault_tip_may_lag_one_generation_but_root_pin_is_immutable() {
        let dir = test_dir();
        let network = [0x22; 32];
        let profile = [0x33; 32];
        let manifests = dir.join("manifests");
        fs::create_dir_all(&manifests).unwrap();
        for generation in 0..=1 {
            fs::write(
                manifests.join(format!("qfp6-manifest-{generation:020}.q6mf")),
                b"fixture",
            )
            .unwrap();
        }
        let vault = dir.join("vault");
        let root_anchor = [0x11; 32];
        write_vault_record(&vault, 1, network, profile, 0, root_anchor, [0; 32]);
        let cfg = json!({
            "trusted_manifest_anchor": hex(&root_anchor),
            "trusted_manifest_floor_generation": 0,
            "trusted_manifest_floor_anchor": hex(&root_anchor),
            "trusted_manifest_anchor_vault_path": vault.to_string_lossy().to_string()
        });
        assert_eq!(
            trusted_manifest_anchor(&cfg, &dir, &network, &profile).unwrap(),
            Some((0, root_anchor))
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn external_manifest_floor_rejects_a_locally_valid_vault_rolled_back_below_floor() {
        let dir = test_dir();
        let network = [0x22; 32];
        let profile = [0x33; 32];
        let manifests = dir.join("manifests");
        fs::create_dir_all(&manifests).unwrap();
        fs::write(
            manifests.join("qfp6-manifest-00000000000000000000.q6mf"),
            b"fixture",
        )
        .unwrap();

        let vault = dir.join("vault");
        let root_anchor = [0x11; 32];
        write_vault_record(&vault, 1, network, profile, 0, root_anchor, [0; 32]);
        let cfg = json!({
            "trusted_manifest_anchor": hex(&root_anchor),
            "trusted_manifest_floor_generation": 1,
            "trusted_manifest_floor_anchor": hex(&[0x22; 32]),
            "trusted_manifest_anchor_vault_path": vault.to_string_lossy().to_string()
        });
        assert!(trusted_manifest_anchor(&cfg, &dir, &network, &profile).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn external_manifest_floor_rejects_wrong_anchor_at_pinned_generation() {
        let dir = test_dir();
        let network = [0x22; 32];
        let profile = [0x33; 32];
        let manifests = dir.join("manifests");
        fs::create_dir_all(&manifests).unwrap();
        fs::write(
            manifests.join("qfp6-manifest-00000000000000000000.q6mf"),
            b"fixture",
        )
        .unwrap();

        let vault = dir.join("vault");
        let root_anchor = [0x11; 32];
        write_vault_record(&vault, 1, network, profile, 0, root_anchor, [0; 32]);
        let cfg = json!({
            "trusted_manifest_anchor": hex(&root_anchor),
            "trusted_manifest_floor_generation": 0,
            "trusted_manifest_floor_anchor": hex(&[0x44; 32]),
            "trusted_manifest_anchor_vault_path": vault.to_string_lossy().to_string()
        });
        assert!(trusted_manifest_anchor(&cfg, &dir, &network, &profile).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn existing_history_requires_external_floor_even_when_root_pin_is_present() {
        let dir = test_dir();
        let network = [0x22; 32];
        let profile = [0x33; 32];
        let manifests = dir.join("manifests");
        fs::create_dir_all(&manifests).unwrap();
        fs::write(
            manifests.join("qfp6-manifest-00000000000000000000.q6mf"),
            b"fixture",
        )
        .unwrap();
        let vault = dir.join("vault");
        let root_anchor = [0x11; 32];
        write_vault_record(&vault, 1, network, profile, 0, root_anchor, [0; 32]);
        let cfg = json!({
            "trusted_manifest_anchor": hex(&root_anchor),
            "trusted_manifest_anchor_vault_path": vault.to_string_lossy().to_string()
        });
        assert!(trusted_manifest_anchor(&cfg, &dir, &network, &profile).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn joining_role_uses_preloaded_checkpoint_vault_without_data_manifests() {
        let dir = test_dir();
        let network = [0x22; 32];
        let profile = [0x33; 32];
        let anchor = [0x51; 32];
        let missing_vault = dir.join("fresh-vault-not-yet-created");
        let fresh_cfg = json!({
            "node_role": "joining",
            "trusted_manifest_anchor": hex(&anchor),
            "trusted_manifest_anchor_vault_path": missing_vault.to_string_lossy().to_string()
        });
        assert_eq!(
            trusted_manifest_anchor(&fresh_cfg, &dir, &network, &profile).unwrap(),
            None
        );

        let vault_path = dir.join("preloaded-checkpoint-vault");
        let mut vault = ai_native_l1_pow_bench::qrun_v06_local_anchor_vault_candidate::QRunV06LocalAnchorVault::provision_genesis_root(
            &vault_path,
            network,
            profile,
            anchor,
        )
        .unwrap();
        let tip = vault.tip();
        vault
            .append_checkpoint_segment_witness(
                ai_native_l1_pow_bench::qrun_v06_local_anchor_vault_candidate::QRunV06CheckpointSegmentWitness {
                    sequence: 1,
                    predecessor_vault_sequence: tip.sequence,
                    predecessor_global_generation: tip.manifest_generation,
                    predecessor_manifest_anchor: tip.manifest_anchor,
                    predecessor_record_digest: tip.record_digest,
                    checkpoint_commitment: [0x61; 32],
                    segment_root_manifest_anchor: [0x62; 32],
                    checkpoint_base_height: 1024,
                    checkpoint_tip_hash: [0x63; 32],
                    checkpoint_state_root: [0x64; 32],
                    checkpoint_cumulative_work: [0x65; 32],
                    network_id: network,
                    profile_id: profile,
                    genesis_descriptor_commitment: [0x66; 32],
                    consensus_fingerprint: [0x67; 32],
                    previous_witness_digest: [0; 32],
                    witness_digest: [0; 32],
                },
            )
            .unwrap();
        let checkpoint_cfg = json!({
            "node_role": "joining",
            "trusted_manifest_anchor": hex(&anchor),
            "trusted_manifest_floor_generation": 0,
            "trusted_manifest_floor_anchor": hex(&anchor),
            "trusted_manifest_anchor_vault_path": vault_path.to_string_lossy().to_string
        });
        assert_eq!(
            trusted_manifest_anchor(&checkpoint_cfg, &dir, &network, &profile).unwrap(),
            Some((0, anchor))
        );
        fs::remove_dir_all(dir).unwrap();
    }
}

#[cfg(test)]
mod software_testnet_ephemeral_key_policy_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn genesis_derived_anchor_is_only_for_acknowledged_fresh_public_testnet_joiners() {
        let cfg = json!({
            "node_role": "joining",
            "derive_fresh_joiner_anchor_from_verified_genesis": true,
            "fresh_genesis_anchor_derivation_acknowledgement":
                PUBLIC_TESTNET_DERIVED_GENESIS_ANCHOR_ACK
        });
        assert_eq!(
            derive_fresh_joiner_anchor_from_verified_genesis(&cfg, true),
            Ok(true)
        );
        assert!(derive_fresh_joiner_anchor_from_verified_genesis(&cfg, false).is_err());

        let wrong_role = json!({
            "node_role": "seed",
            "derive_fresh_joiner_anchor_from_verified_genesis": true,
            "fresh_genesis_anchor_derivation_acknowledgement":
                PUBLIC_TESTNET_DERIVED_GENESIS_ANCHOR_ACK
        });
        assert!(derive_fresh_joiner_anchor_from_verified_genesis(&wrong_role, true).is_err());
    }

    #[test]
    fn genesis_derived_anchor_requires_exact_ack_and_forbids_mixed_external_pin() {
        let no_ack = json!({
            "node_role": "joining",
            "derive_fresh_joiner_anchor_from_verified_genesis": true
        });
        assert!(derive_fresh_joiner_anchor_from_verified_genesis(&no_ack, true).is_err());

        let mixed_pin = json!({
            "node_role": "joining",
            "derive_fresh_joiner_anchor_from_verified_genesis": true,
            "fresh_genesis_anchor_derivation_acknowledgement":
                PUBLIC_TESTNET_DERIVED_GENESIS_ANCHOR_ACK,
            "trusted_manifest_anchor": "11".repeat(32)
        });
        assert!(derive_fresh_joiner_anchor_from_verified_genesis(&mixed_pin, true).is_err());

        let disabled_with_ack = json!({
            "node_role": "joining",
            "derive_fresh_joiner_anchor_from_verified_genesis": false,
            "fresh_genesis_anchor_derivation_acknowledgement":
                PUBLIC_TESTNET_DERIVED_GENESIS_ANCHOR_ACK
        });
        assert!(
            derive_fresh_joiner_anchor_from_verified_genesis(&disabled_with_ack, true).is_err()
        );
    }

    #[test]
    fn software_ephemeral_keys_require_explicit_zero_value_testnet_acknowledgement() {
        let cfg = json!({
            "allow_software_testnet_key_custody": true,
            "software_testnet_key_custody_acknowledgement": PUBLIC_TESTNET_SOFTWARE_KEYS_ACK
        });
        assert_eq!(software_testnet_key_custody_enabled(&cfg, true), Ok(true));
        assert!(software_testnet_key_custody_enabled(&cfg, false).is_err());
    }

    #[test]
    fn software_ephemeral_keys_fail_closed_without_ack_or_when_mixed_with_tpm_paths() {
        let no_ack = json!({"allow_software_testnet_key_custody": true});
        assert!(software_testnet_key_custody_enabled(&no_ack, true).is_err());

        let mixed = json!({
            "allow_software_testnet_key_custody": true,
            "software_testnet_key_custody_acknowledgement": PUBLIC_TESTNET_SOFTWARE_KEYS_ACK,
            "device_root_metadata_path": "/run/not-used/device-root.json"
        });
        assert!(software_testnet_key_custody_enabled(&mixed, true).is_err());

        let disabled_with_ack = json!({
            "allow_software_testnet_key_custody": false,
            "software_testnet_key_custody_acknowledgement": PUBLIC_TESTNET_SOFTWARE_KEYS_ACK
        });
        assert!(software_testnet_key_custody_enabled(&disabled_with_ack, true).is_err());
    }
}
