//! Offline, loopback-Devnet trust artifact provisioner.
//!
//! Private signing seeds are generated in-process and stored only as role/network-bound
//! Windows CurrentUser-DPAPI ASK1 files. The tool never accepts key bytes in CLI arguments and
//! never prints seed material. Public DPC1/IRG1/NPI1 artifacts can be copied to a test node.
//!
//! This is an operational candidate, not a production key ceremony. DPAPI files are tied to the
//! current Windows user/machine and are not portable backups. Run key generation/signing offline
//! under a dedicated Windows account; define and rehearse a separate recovery backup before value.

use ai_native_l1_pow_bench::{
    devnet_signed_peer_identity_candidate::{
        sign_signed_peer_identity, verify_signed_peer_identity,
    },
    identity_generation_store::encode_signed_rotation_statement,
    identity_policy::{encode as encode_key_record, KeyAlgorithm, KeyPurpose, KeyRecord, KeyState},
    noise_deployment_config::{
        encode_signed_deployment_config, verify_signed_deployment_config,
        MAX_SIGNED_DEPLOYMENT_CONFIG_LEN,
    },
    noise_issuer_registry::{
        encode_signed_registry, validate_registry_transition, verify_signed_registry, IssuerEntry,
        IssuerStatus, MAX_REGISTRY_WIRE_LEN,
    },
    offline_signing_key_store::{
        load_protected_signing_seed, store_protected_signing_seed, SigningKeyRole,
    },
};
use ed25519_dalek::SigningKey;
use std::{
    collections::BTreeMap,
    env,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

const MAX_PEER_IDENTITY_LEN: usize =
    ai_native_l1_pow_bench::devnet_signed_peer_identity_candidate::MAX_SIGNED_PEER_IDENTITY_LEN;

fn usage() -> &'static str {
    "Offline Devnet trust provisioner (Windows CurrentUser DPAPI)\n\
     \n\
     Generate a role-bound signing key:\n\
       devnet_trust_provisioner keygen --network-id-hex HEX64 --role ROLE --output-key-file PATH --output-public-file PATH\n\
     ROLE is deployment-authority, governance-root, offline-recovery, or peer-issuer.\n\
     \n\
     Create first bootstrap files DPC1 and IRG1:\n\
       devnet_trust_provisioner bootstrap --network-id-hex HEX64 --deployment-key-file PATH --governance-key-file PATH --recovery-key-file PATH --issuer-key-file PATH --issuer-id N --output-dir PATH\n\
     \n\
     Advance issuer retirement/revocation status (never reactivates or changes issuer keys):\n\
       devnet_trust_provisioner update-issuer-status --network-id-hex HEX64 --deployment-config-file PATH --deployment-key-file PATH --minimum-config-sequence N --previous-registry-file PATH --governance-key-file PATH --issuer-id N --new-status retired|revoked --output-file PATH\n\
     \n\
     Sign a peer Noise public key into NPI1:\n\
       devnet_trust_provisioner issue-peer --network-id-hex HEX64 --deployment-config-file PATH --deployment-key-file PATH --minimum-config-sequence N --issuer-registry-file PATH --issuer-key-file PATH --issuer-id N --credential-id U128 --key-id N --noise-public-key-hex HEX64 --not-before UNIX --not-after UNIX --output-file PATH\n\
     \n\
     Rotate an existing peer key using an issuer-signed exact-successor NRT1 statement:\n\
       devnet_trust_provisioner rotate-peer --network-id-hex HEX64 --deployment-config-file PATH --deployment-key-file PATH --minimum-config-sequence N --issuer-registry-file PATH --issuer-key-file PATH --issuer-id N --previous-identity-file PATH --new-noise-public-key-hex HEX64 --not-before UNIX --not-after UNIX --output-file PATH\n\
     \n\
     Public-key hex is public data. Never pass private seeds on a command line. Keep ASK1 files offline."
}

fn parse_options(args: impl Iterator<Item = String>) -> Result<BTreeMap<String, String>, String> {
    let mut result = BTreeMap::new();
    let mut args = args.peekable();
    while let Some(flag) = args.next() {
        if !flag.starts_with("--") {
            return Err("expected a named --option".into());
        }
        if matches!(flag.as_str(), "--help" | "-h") {
            return Err(usage().into());
        }
        if matches!(
            flag.as_str(),
            "--private-key-hex"
                | "--private-key-file"
                | "--private-key-stdin"
                | "--seed-hex"
                | "--signing-seed-hex"
        ) {
            return Err("private signing seeds are never accepted as command-line inputs; use role-bound DPAPI key files".into());
        }
        let value = args
            .next()
            .ok_or_else(|| format!("missing value for {flag}"))?;
        if value.starts_with("--") {
            return Err(format!("missing value for {flag}"));
        }
        if result.insert(flag.clone(), value).is_some() {
            return Err(format!("{flag} was specified more than once"));
        }
    }
    Ok(result)
}

fn take_required(options: &mut BTreeMap<String, String>, flag: &str) -> Result<String, String> {
    options
        .remove(flag)
        .ok_or_else(|| format!("missing required option {flag}"))
}

fn no_extra_options(options: BTreeMap<String, String>) -> Result<(), String> {
    if let Some(flag) = options.keys().next() {
        return Err(format!("unknown option {flag}"));
    }
    Ok(())
}

fn parse_hex32(value: &str, label: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 {
        return Err(format!("{label} must be exactly 64 hexadecimal characters"));
    }
    let mut out = [0u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| format!("{label} contains invalid hexadecimal"))?;
    }
    if out.iter().all(|byte| *byte == 0) {
        return Err(format!("{label} cannot be all zero"));
    }
    Ok(out)
}

fn parse_nonzero_u32(value: String, label: &str) -> Result<u32, String> {
    let parsed = value
        .parse::<u32>()
        .map_err(|_| format!("{label} must be an integer"))?;
    if parsed == 0 {
        return Err(format!("{label} must be nonzero"));
    }
    Ok(parsed)
}

fn parse_nonzero_u64(value: String, label: &str) -> Result<u64, String> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| format!("{label} must be an integer"))?;
    if parsed == 0 {
        return Err(format!("{label} must be nonzero"));
    }
    Ok(parsed)
}

fn decode_hex32(value: &str, label: &str) -> Result<[u8; 32], String> {
    parse_hex32(value, label)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn load_signing_key(
    path: &Path,
    network_id: &[u8; 32],
    role: SigningKeyRole,
) -> Result<SigningKey, String> {
    let mut seed = load_protected_signing_seed(path, network_id, role)?;
    let signing_key = SigningKey::from_bytes(&seed);
    seed.fill(0);
    Ok(signing_key)
}

fn read_bounded_public_file(path: &Path, max_len: usize, label: &str) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| format!("cannot inspect {label}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > max_len as u64
    {
        return Err(format!(
            "{label} must be a bounded regular non-symlink file"
        ));
    }
    let file = File::open(path).map_err(|_| format!("cannot open {label}"))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(max_len.saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| format!("cannot read {label}"))?;
    if bytes.is_empty() || bytes.len() > max_len {
        return Err(format!("{label} exceeds its size limit"));
    }
    Ok(bytes)
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if path.file_name().is_none() || !parent_directory(path).is_dir() {
        return Err("output file must be in an existing directory".into());
    }
    let result = (|| -> io::Result<()> {
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        file.write_all(bytes)?;
        file.flush()?;
        file.sync_all()?;
        Ok(())
    })();
    result.map_err(|_| "could not create output file; overwrite is never allowed".into())
}

fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn keygen(mut options: BTreeMap<String, String>) -> Result<(), String> {
    let network_id = parse_hex32(
        &take_required(&mut options, "--network-id-hex")?,
        "network ID",
    )?;
    let role = SigningKeyRole::parse(&take_required(&mut options, "--role")?)?;
    let key_path = PathBuf::from(take_required(&mut options, "--output-key-file")?);
    let public_path = PathBuf::from(take_required(&mut options, "--output-public-file")?);
    no_extra_options(options)?;
    if key_path == public_path || key_path.exists() || public_path.exists() {
        return Err("both output paths must be different and not already exist".into());
    }
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|_| "secure random generation failed")?;
    let public_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    if let Err(error) = store_protected_signing_seed(&key_path, &network_id, role, &seed) {
        seed.fill(0);
        return Err(error);
    }
    seed.fill(0);
    let public_output = format!("{}\n", hex(&public_key));
    if let Err(error) = write_new_file(&public_path, public_output.as_bytes()) {
        let _ = fs::remove_file(&key_path);
        return Err(error);
    }
    println!("key_role={}", role.as_str());
    println!("network_id_hex={}", hex(&network_id));
    println!("protected_key_file={}", key_path.display());
    println!("public_key_file={}", public_path.display());
    println!("public_key_hex={}", hex(&public_key));
    println!("protection=Windows_CurrentUser_DPAPI_ASK1");
    println!("private_seed_printed=false");
    Ok(())
}

fn build_bootstrap_artifacts(
    network_id: [u8; 32],
    deployment_authority: &SigningKey,
    governance_root: &SigningKey,
    recovery: &SigningKey,
    issuer_id: u32,
    issuer: &SigningKey,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    if network_id.iter().all(|b| *b == 0) || issuer_id == 0 {
        return Err("network and issuer IDs must be nonzero".into());
    }
    let role_public_keys = [
        deployment_authority.verifying_key().to_bytes(),
        governance_root.verifying_key().to_bytes(),
        recovery.verifying_key().to_bytes(),
        issuer.verifying_key().to_bytes(),
    ];
    let mut unique = role_public_keys.to_vec();
    unique.sort_unstable();
    unique.dedup();
    if unique.len() != role_public_keys.len() {
        return Err(
            "deployment, governance, recovery and issuer roles must use distinct keys".into(),
        );
    }

    // Initial root anchor is pinned as the governance root; the offline recovery role is distinct.
    let mut root_chain = Vec::with_capacity(40);
    root_chain.extend_from_slice(b"GRC1");
    root_chain.extend_from_slice(&1u16.to_be_bytes());
    root_chain.extend_from_slice(&network_id);
    root_chain.extend_from_slice(&0u16.to_be_bytes());

    let deployment_wire = encode_signed_deployment_config(
        network_id,
        1,
        governance_root.verifying_key().to_bytes(),
        governance_root.verifying_key().to_bytes(),
        recovery.verifying_key().to_bytes(),
        1,
        1,
        &root_chain,
        deployment_authority,
    )
    .map_err(|error| format!("DPC1 construction rejected: {error:?}"))?;

    let registry_wire = encode_signed_registry(
        network_id,
        1,
        &[IssuerEntry {
            issuer_id,
            public_key: issuer.verifying_key().to_bytes(),
            status: IssuerStatus::Active,
        }],
        governance_root,
    )
    .map_err(|error| format!("IRG1 construction rejected: {error:?}"))?;

    let verified_deployment = verify_signed_deployment_config(
        &deployment_wire,
        &network_id,
        &deployment_authority.verifying_key().to_bytes(),
        1,
    )
    .map_err(|error| format!("self-check of DPC1 failed: {error:?}"))?;
    let verified_registry = verify_signed_registry(
        &registry_wire,
        &network_id,
        &verified_deployment.governance_public_key,
    )
    .map_err(|error| format!("self-check of IRG1 failed: {error:?}"))?;
    if verified_registry
        .active_key(issuer_id)
        .map_err(|error| format!("issuer self-check failed: {error:?}"))?
        != issuer.verifying_key().to_bytes()
    {
        return Err("signed issuer key did not match expected role".into());
    }
    Ok((deployment_wire, registry_wire))
}

fn bootstrap(mut options: BTreeMap<String, String>) -> Result<(), String> {
    let network_id = parse_hex32(
        &take_required(&mut options, "--network-id-hex")?,
        "network ID",
    )?;
    let deployment_path = PathBuf::from(take_required(&mut options, "--deployment-key-file")?);
    let governance_path = PathBuf::from(take_required(&mut options, "--governance-key-file")?);
    let recovery_path = PathBuf::from(take_required(&mut options, "--recovery-key-file")?);
    let issuer_path = PathBuf::from(take_required(&mut options, "--issuer-key-file")?);
    let issuer_id = parse_nonzero_u32(take_required(&mut options, "--issuer-id")?, "issuer ID")?;
    let output_dir = PathBuf::from(take_required(&mut options, "--output-dir")?);
    no_extra_options(options)?;

    if output_dir.file_name().is_none()
        || output_dir.exists()
        || !parent_directory(&output_dir).is_dir()
    {
        return Err("output directory must be a new directory under an existing parent".into());
    }
    let deployment = load_signing_key(
        &deployment_path,
        &network_id,
        SigningKeyRole::DeploymentAuthority,
    )?;
    let governance = load_signing_key(
        &governance_path,
        &network_id,
        SigningKeyRole::GovernanceRoot,
    )?;
    let recovery = load_signing_key(&recovery_path, &network_id, SigningKeyRole::OfflineRecovery)?;
    let issuer = load_signing_key(&issuer_path, &network_id, SigningKeyRole::PeerIssuer)?;
    let (deployment_wire, registry_wire) = build_bootstrap_artifacts(
        network_id,
        &deployment,
        &governance,
        &recovery,
        issuer_id,
        &issuer,
    )?;

    fs::create_dir(&output_dir).map_err(|_| "could not create new bootstrap output directory")?;
    let dpc_path = output_dir.join("deployment.dpc1");
    let irg_path = output_dir.join("issuer-registry.irg1");
    let result = write_new_file(&dpc_path, &deployment_wire)
        .and_then(|_| write_new_file(&irg_path, &registry_wire));
    if let Err(error) = result {
        let _ = fs::remove_file(&dpc_path);
        let _ = fs::remove_file(&irg_path);
        let _ = fs::remove_dir(&output_dir);
        return Err(error);
    }

    println!("trust_bundle_dir={}", output_dir.display());
    println!("deployment_config_file={}", dpc_path.display());
    println!("issuer_registry_file={}", irg_path.display());
    println!("network_id_hex={}", hex(&network_id));
    println!(
        "deployment_authority_public_key_hex={}",
        hex(&deployment.verifying_key().to_bytes())
    );
    println!(
        "governance_root_public_key_hex={}",
        hex(&governance.verifying_key().to_bytes())
    );
    println!(
        "offline_recovery_public_key_hex={}",
        hex(&recovery.verifying_key().to_bytes())
    );
    println!("issuer_id={issuer_id}");
    println!(
        "issuer_public_key_hex={}",
        hex(&issuer.verifying_key().to_bytes())
    );
    println!("private_seed_printed=false");
    Ok(())
}

fn parse_target_issuer_status(value: &str) -> Result<IssuerStatus, String> {
    match value {
        "retired" => Ok(IssuerStatus::Retired),
        "revoked" => Ok(IssuerStatus::Revoked),
        "active" => Err("update-issuer-status cannot activate or reactivate an issuer".into()),
        _ => Err("--new-status must be retired or revoked".into()),
    }
}

fn build_updated_registry_artifact(
    network_id: [u8; 32],
    deployment_wire: &[u8],
    deployment_authority_public_key: &[u8; 32],
    minimum_config_sequence: u64,
    previous_registry_wire: &[u8],
    issuer_id: u32,
    new_status: IssuerStatus,
    governance_signing_key: &SigningKey,
) -> Result<Vec<u8>, String> {
    if issuer_id == 0 {
        return Err("issuer ID must be nonzero".into());
    }
    if new_status == IssuerStatus::Active {
        return Err("issuer update cannot activate or reactivate an issuer".into());
    }
    let deployment = verify_signed_deployment_config(
        deployment_wire,
        &network_id,
        deployment_authority_public_key,
        minimum_config_sequence,
    )
    .map_err(|error| format!("DPC1 verification failed: {error:?}"))?;
    if governance_signing_key.verifying_key().to_bytes() != deployment.governance_public_key {
        return Err(
            "governance signing key does not match the current DPC1 governance root".into(),
        );
    }
    let previous = verify_signed_registry(
        previous_registry_wire,
        &network_id,
        &deployment.governance_public_key,
    )
    .map_err(|error| format!("previous IRG1 verification failed: {error:?}"))?;
    if previous.sequence() < deployment.minimum_registry_sequence {
        return Err("previous issuer registry is below the DPC1 minimum registry sequence".into());
    }
    let selected_index = previous
        .entries()
        .iter()
        .position(|entry| entry.issuer_id == issuer_id)
        .ok_or("issuer ID is not present in the previous registry")?;
    let current_status = previous.entries()[selected_index].status;
    if current_status == new_status {
        return Err(
            "issuer already has the requested status; refusing a no-op registry revision".into(),
        );
    }
    let sequence = previous
        .sequence()
        .checked_add(1)
        .ok_or("issuer registry sequence is exhausted")?;
    let mut entries = previous.entries().to_vec();
    entries[selected_index].status = new_status;

    let next_wire = encode_signed_registry(network_id, sequence, &entries, governance_signing_key)
        .map_err(|error| format!("new IRG1 encoding rejected: {error:?}"))?;
    let next = verify_signed_registry(&next_wire, &network_id, &deployment.governance_public_key)
        .map_err(|error| format!("new IRG1 self-check failed: {error:?}"))?;
    validate_registry_transition(&previous, &next)
        .map_err(|error| format!("issuer lifecycle transition rejected: {error:?}"))?;
    Ok(next_wire)
}

fn update_issuer_status(mut options: BTreeMap<String, String>) -> Result<(), String> {
    let network_id = parse_hex32(
        &take_required(&mut options, "--network-id-hex")?,
        "network ID",
    )?;
    let deployment_path = PathBuf::from(take_required(&mut options, "--deployment-config-file")?);
    let deployment_key_path = PathBuf::from(take_required(&mut options, "--deployment-key-file")?);
    let minimum_config_sequence = parse_nonzero_u64(
        take_required(&mut options, "--minimum-config-sequence")?,
        "minimum config sequence",
    )?;
    let previous_registry_path =
        PathBuf::from(take_required(&mut options, "--previous-registry-file")?);
    let governance_key_path = PathBuf::from(take_required(&mut options, "--governance-key-file")?);
    let issuer_id = parse_nonzero_u32(take_required(&mut options, "--issuer-id")?, "issuer ID")?;
    let new_status = parse_target_issuer_status(&take_required(&mut options, "--new-status")?)?;
    let output_path = PathBuf::from(take_required(&mut options, "--output-file")?);
    no_extra_options(options)?;

    let deployment_wire = read_bounded_public_file(
        &deployment_path,
        MAX_SIGNED_DEPLOYMENT_CONFIG_LEN,
        "DPC1 deployment config",
    )?;
    let previous_registry_wire = read_bounded_public_file(
        &previous_registry_path,
        MAX_REGISTRY_WIRE_LEN,
        "previous IRG1 issuer registry",
    )?;
    let deployment_key = load_signing_key(
        &deployment_key_path,
        &network_id,
        SigningKeyRole::DeploymentAuthority,
    )?;
    let governance_key = load_signing_key(
        &governance_key_path,
        &network_id,
        SigningKeyRole::GovernanceRoot,
    )?;
    let artifact = build_updated_registry_artifact(
        network_id,
        &deployment_wire,
        &deployment_key.verifying_key().to_bytes(),
        minimum_config_sequence,
        &previous_registry_wire,
        issuer_id,
        new_status,
        &governance_key,
    )?;
    write_new_file(&output_path, &artifact)?;
    let verified = verify_signed_registry(
        &artifact,
        &network_id,
        &governance_key.verifying_key().to_bytes(),
    )
    .map_err(|error| format!("updated registry self-check failed: {error:?}"))?;
    println!("issuer_registry_file={}", output_path.display());
    println!("network_id_hex={}", hex(&network_id));
    println!("issuer_id={issuer_id}");
    println!(
        "issuer_status={}",
        match new_status {
            IssuerStatus::Retired => "retired",
            IssuerStatus::Revoked => "revoked",
            IssuerStatus::Active => "active",
        }
    );
    println!("issuer_registry_sequence={}", verified.sequence());
    println!("issuer_public_keys_changed=false");
    println!("private_seed_printed=false");
    Ok(())
}

fn build_peer_identity_artifact(
    network_id: [u8; 32],
    deployment_wire: &[u8],
    deployment_authority_public_key: &[u8; 32],
    minimum_config_sequence: u64,
    registry_wire: &[u8],
    issuer_id: u32,
    credential_id: u128,
    key_id: u32,
    noise_public_key: [u8; 32],
    not_before: u64,
    not_after: u64,
    issuer_signing_key: &SigningKey,
) -> Result<Vec<u8>, String> {
    if issuer_id == 0
        || credential_id == 0
        || key_id == 0
        || noise_public_key.iter().all(|b| *b == 0)
        || not_before > not_after
    {
        return Err("peer identity IDs, key and validity window are invalid".into());
    }
    let deployment = verify_signed_deployment_config(
        deployment_wire,
        &network_id,
        deployment_authority_public_key,
        minimum_config_sequence,
    )
    .map_err(|error| format!("DPC1 verification failed: {error:?}"))?;
    let registry = verify_signed_registry(
        registry_wire,
        &network_id,
        &deployment.governance_public_key,
    )
    .map_err(|error| format!("IRG1 verification failed: {error:?}"))?;
    if registry.sequence() < deployment.minimum_registry_sequence {
        return Err("issuer registry is below the deployment-config minimum sequence".into());
    }
    let selected_issuer_key = registry
        .active_key(issuer_id)
        .map_err(|error| format!("requested issuer is not active: {error:?}"))?;
    if selected_issuer_key != issuer_signing_key.verifying_key().to_bytes() {
        return Err("issuer signing key does not match the selected active registry entry".into());
    }

    let record = KeyRecord {
        key_id,
        generation: 1,
        algorithm: KeyAlgorithm::NoiseX25519,
        purpose: KeyPurpose::PeerAuth,
        state: KeyState::Active,
        not_before,
        not_after,
        public_key: noise_public_key.to_vec(),
    };
    sign_signed_peer_identity(
        network_id,
        credential_id,
        issuer_id,
        &record,
        None,
        issuer_signing_key,
    )
    .map_err(|error| format!("NPI1 construction rejected: {error:?}"))
}

fn build_rotated_peer_identity_artifact(
    network_id: [u8; 32],
    deployment_wire: &[u8],
    deployment_authority_public_key: &[u8; 32],
    minimum_config_sequence: u64,
    registry_wire: &[u8],
    issuer_id: u32,
    previous_identity_wire: &[u8],
    new_noise_public_key: [u8; 32],
    not_before: u64,
    not_after: u64,
    issuer_signing_key: &SigningKey,
) -> Result<(Vec<u8>, u32, u32), String> {
    if issuer_id == 0
        || new_noise_public_key.iter().all(|byte| *byte == 0)
        || not_before > not_after
    {
        return Err("peer rotation parameters or validity window are invalid".into());
    }
    let deployment = verify_signed_deployment_config(
        deployment_wire,
        &network_id,
        deployment_authority_public_key,
        minimum_config_sequence,
    )
    .map_err(|error| format!("DPC1 verification failed: {error:?}"))?;
    let registry = verify_signed_registry(
        registry_wire,
        &network_id,
        &deployment.governance_public_key,
    )
    .map_err(|error| format!("IRG1 verification failed: {error:?}"))?;
    if registry.sequence() < deployment.minimum_registry_sequence {
        return Err("issuer registry is below the DPC1 minimum registry sequence".into());
    }
    let issuer_public_key = registry
        .active_key(issuer_id)
        .map_err(|error| format!("requested issuer is not active: {error:?}"))?;
    if issuer_public_key != issuer_signing_key.verifying_key().to_bytes() {
        return Err("issuer signing key does not match the active registry entry".into());
    }
    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "system clock precedes UNIX epoch")?
        .as_secs();
    let previous = verify_signed_peer_identity(
        previous_identity_wire,
        &network_id,
        issuer_id,
        &issuer_public_key,
        epoch,
    )
    .map_err(|error| format!("previous NPI1 verification failed: {error}"))?;
    if previous.record.state == KeyState::Revoked {
        return Err("a revoked peer key cannot be rotated or reactivated".into());
    }
    if previous.noise_public_key == new_noise_public_key {
        return Err("rotation requires a different Noise public key".into());
    }
    let next_generation = previous
        .record
        .generation
        .checked_add(1)
        .ok_or("peer key generation counter is exhausted")?;
    let next_record = KeyRecord {
        key_id: previous.record.key_id,
        generation: next_generation,
        algorithm: KeyAlgorithm::NoiseX25519,
        purpose: KeyPurpose::PeerAuth,
        state: KeyState::Active,
        not_before,
        not_after,
        public_key: new_noise_public_key.to_vec(),
    };
    let next_record_bytes = encode_key_record(&next_record)
        .map_err(|error| format!("new peer record encoding failed: {error:?}"))?;
    let rotation_wire = encode_signed_rotation_statement(
        network_id,
        previous.credential_id,
        issuer_id,
        &previous.record_bytes,
        &next_record_bytes,
        issuer_signing_key,
    )
    .map_err(|error| format!("NRT1 rotation statement rejected: {error:?}"))?;
    let next_identity = sign_signed_peer_identity(
        network_id,
        previous.credential_id,
        issuer_id,
        &next_record,
        Some(&rotation_wire),
        issuer_signing_key,
    )
    .map_err(|error| format!("rotated NPI1 construction rejected: {error:?}"))?;
    Ok((next_identity, previous.record.generation, next_generation))
}

fn rotate_peer(mut options: BTreeMap<String, String>) -> Result<(), String> {
    let network_id = parse_hex32(
        &take_required(&mut options, "--network-id-hex")?,
        "network ID",
    )?;
    let deployment_path = PathBuf::from(take_required(&mut options, "--deployment-config-file")?);
    let deployment_key_path = PathBuf::from(take_required(&mut options, "--deployment-key-file")?);
    let minimum_config_sequence = parse_nonzero_u64(
        take_required(&mut options, "--minimum-config-sequence")?,
        "minimum config sequence",
    )?;
    let registry_path = PathBuf::from(take_required(&mut options, "--issuer-registry-file")?);
    let issuer_key_path = PathBuf::from(take_required(&mut options, "--issuer-key-file")?);
    let issuer_id = parse_nonzero_u32(take_required(&mut options, "--issuer-id")?, "issuer ID")?;
    let previous_identity_path =
        PathBuf::from(take_required(&mut options, "--previous-identity-file")?);
    let new_noise_public_key = decode_hex32(
        &take_required(&mut options, "--new-noise-public-key-hex")?,
        "new Noise public key",
    )?;
    let not_before = take_required(&mut options, "--not-before")?
        .parse::<u64>()
        .map_err(|_| "not-before must be a UNIX timestamp")?;
    let not_after = take_required(&mut options, "--not-after")?
        .parse::<u64>()
        .map_err(|_| "not-after must be a UNIX timestamp")?;
    let output_path = PathBuf::from(take_required(&mut options, "--output-file")?);
    no_extra_options(options)?;

    let deployment_wire = read_bounded_public_file(
        &deployment_path,
        MAX_SIGNED_DEPLOYMENT_CONFIG_LEN,
        "DPC1 deployment config",
    )?;
    let registry_wire = read_bounded_public_file(
        &registry_path,
        MAX_REGISTRY_WIRE_LEN,
        "IRG1 issuer registry",
    )?;
    let previous_wire = read_bounded_public_file(
        &previous_identity_path,
        MAX_PEER_IDENTITY_LEN,
        "previous NPI1 peer identity",
    )?;
    let deployment_key = load_signing_key(
        &deployment_key_path,
        &network_id,
        SigningKeyRole::DeploymentAuthority,
    )?;
    let issuer_key = load_signing_key(&issuer_key_path, &network_id, SigningKeyRole::PeerIssuer)?;
    let (artifact, previous_generation, new_generation) = build_rotated_peer_identity_artifact(
        network_id,
        &deployment_wire,
        &deployment_key.verifying_key().to_bytes(),
        minimum_config_sequence,
        &registry_wire,
        issuer_id,
        &previous_wire,
        new_noise_public_key,
        not_before,
        not_after,
        &issuer_key,
    )?;
    write_new_file(&output_path, &artifact)?;
    println!("peer_identity_file={}", output_path.display());
    println!("network_id_hex={}", hex(&network_id));
    println!("issuer_id={issuer_id}");
    println!("previous_generation={previous_generation}");
    println!("new_generation={new_generation}");
    println!("new_noise_public_key_hex={}", hex(&new_noise_public_key));
    println!("signed_rotation_statement=NRT1");
    println!("private_seed_printed=false");
    Ok(())
}

fn issue_peer(mut options: BTreeMap<String, String>) -> Result<(), String> {
    let network_id = parse_hex32(
        &take_required(&mut options, "--network-id-hex")?,
        "network ID",
    )?;
    let deployment_path = PathBuf::from(take_required(&mut options, "--deployment-config-file")?);
    let deployment_key_path = PathBuf::from(take_required(&mut options, "--deployment-key-file")?);
    let minimum_config_sequence = parse_nonzero_u64(
        take_required(&mut options, "--minimum-config-sequence")?,
        "minimum config sequence",
    )?;
    let registry_path = PathBuf::from(take_required(&mut options, "--issuer-registry-file")?);
    let issuer_key_path = PathBuf::from(take_required(&mut options, "--issuer-key-file")?);
    let issuer_id = parse_nonzero_u32(take_required(&mut options, "--issuer-id")?, "issuer ID")?;
    let credential_id = take_required(&mut options, "--credential-id")?
        .parse::<u128>()
        .map_err(|_| "credential ID must be an unsigned 128-bit integer")?;
    let key_id = parse_nonzero_u32(take_required(&mut options, "--key-id")?, "key ID")?;
    let noise_public_key = decode_hex32(
        &take_required(&mut options, "--noise-public-key-hex")?,
        "Noise public key",
    )?;
    let not_before = take_required(&mut options, "--not-before")?
        .parse::<u64>()
        .map_err(|_| "not-before must be a UNIX timestamp")?;
    let not_after = take_required(&mut options, "--not-after")?
        .parse::<u64>()
        .map_err(|_| "not-after must be a UNIX timestamp")?;
    let output_path = PathBuf::from(take_required(&mut options, "--output-file")?);
    no_extra_options(options)?;
    if credential_id == 0 || not_before > not_after {
        return Err("credential ID and validity window are invalid".into());
    }

    let deployment_wire = read_bounded_public_file(
        &deployment_path,
        MAX_SIGNED_DEPLOYMENT_CONFIG_LEN,
        "DPC1 deployment config",
    )?;
    let registry_wire = read_bounded_public_file(
        &registry_path,
        MAX_REGISTRY_WIRE_LEN,
        "IRG1 issuer registry",
    )?;
    let deployment_key = load_signing_key(
        &deployment_key_path,
        &network_id,
        SigningKeyRole::DeploymentAuthority,
    )?;
    let issuer_key = load_signing_key(&issuer_key_path, &network_id, SigningKeyRole::PeerIssuer)?;
    let artifact = build_peer_identity_artifact(
        network_id,
        &deployment_wire,
        &deployment_key.verifying_key().to_bytes(),
        minimum_config_sequence,
        &registry_wire,
        issuer_id,
        credential_id,
        key_id,
        noise_public_key,
        not_before,
        not_after,
        &issuer_key,
    )?;
    write_new_file(&output_path, &artifact)?;
    println!("peer_identity_file={}", output_path.display());
    println!("network_id_hex={}", hex(&network_id));
    println!("issuer_id={issuer_id}");
    println!("credential_id={credential_id}");
    println!("key_id={key_id}");
    println!("noise_public_key_hex={}", hex(&noise_public_key));
    println!("private_seed_printed=false");
    Ok(())
}

fn main_result() -> Result<(), String> {
    #[cfg(not(windows))]
    {
        return Err("devnet_trust_provisioner currently requires Windows CurrentUser DPAPI".into());
    }
    #[cfg(windows)]
    {
        let mut args = env::args().skip(1);
        let command = args.next().ok_or_else(|| usage().to_string())?;
        let options = parse_options(args)?;
        match command.as_str() {
            "keygen" => keygen(options),
            "bootstrap" => bootstrap(options),
            "update-issuer-status" => update_issuer_status(options),
            "issue-peer" => issue_peer(options),
            "rotate-peer" => rotate_peer(options),
            _ => Err(usage().into()),
        }
    }
}

fn main() {
    if let Err(error) = main_result() {
        eprintln!("DEVNET_TRUST_PROVISIONER_ERROR: {error}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ai_native_l1_pow_bench::identity_generation_store::IdentityGenerationStateStore;
    use ed25519_dalek::SigningKey;

    fn sk(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    #[test]
    fn bootstrap_artifacts_verify_and_role_keys_are_distinct() {
        let network = [0x42; 32];
        let authority = sk(0x91);
        let governance = sk(0x92);
        let recovery = sk(0x93);
        let issuer = sk(0x94);
        let (deployment_wire, registry_wire) =
            build_bootstrap_artifacts(network, &authority, &governance, &recovery, 17, &issuer)
                .unwrap();
        let deployment = verify_signed_deployment_config(
            &deployment_wire,
            &network,
            &authority.verifying_key().to_bytes(),
            1,
        )
        .unwrap();
        let registry =
            verify_signed_registry(&registry_wire, &network, &deployment.governance_public_key)
                .unwrap();
        assert_eq!(deployment.sequence, 1);
        assert_eq!(deployment.root_chain.current_epoch(), 1);
        assert_eq!(registry.sequence(), 1);
        assert_eq!(
            registry.active_key(17).unwrap(),
            issuer.verifying_key().to_bytes()
        );
        assert!(build_bootstrap_artifacts(
            network,
            &authority,
            &governance,
            &governance,
            17,
            &issuer
        )
        .is_err());
    }

    #[test]
    fn peer_artifacts_reject_tamper_wrong_network_and_mismatched_issuer_key() {
        let network = [0x52; 32];
        let authority = sk(0xa1);
        let governance = sk(0xa2);
        let recovery = sk(0xa3);
        let issuer = sk(0xa4);
        let other_issuer = sk(0xa5);
        let (deployment_wire, registry_wire) =
            build_bootstrap_artifacts(network, &authority, &governance, &recovery, 27, &issuer)
                .unwrap();
        let peer_key = [0x33; 32];
        let valid = build_peer_identity_artifact(
            network,
            &deployment_wire,
            &authority.verifying_key().to_bytes(),
            1,
            &registry_wire,
            27,
            800,
            700,
            peer_key,
            100,
            u64::MAX,
            &issuer,
        )
        .unwrap();
        let verified = ai_native_l1_pow_bench::devnet_signed_peer_identity_candidate::verify_signed_peer_identity(
            &valid, &network, 27, &issuer.verifying_key().to_bytes(), 101,
        ).unwrap();
        assert_eq!(verified.noise_public_key, peer_key);
        assert!(build_peer_identity_artifact(
            [0x53; 32],
            &deployment_wire,
            &authority.verifying_key().to_bytes(),
            1,
            &registry_wire,
            27,
            800,
            700,
            peer_key,
            100,
            u64::MAX,
            &issuer,
        )
        .is_err());
        assert!(build_peer_identity_artifact(
            network,
            &deployment_wire,
            &authority.verifying_key().to_bytes(),
            1,
            &registry_wire,
            27,
            800,
            700,
            peer_key,
            100,
            u64::MAX,
            &other_issuer,
        )
        .is_err());
        let mut tampered = deployment_wire.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(build_peer_identity_artifact(
            network,
            &tampered,
            &authority.verifying_key().to_bytes(),
            1,
            &registry_wire,
            27,
            800,
            700,
            peer_key,
            100,
            u64::MAX,
            &issuer,
        )
        .is_err());
    }

    #[test]
    fn peer_key_rotation_is_exact_successor_and_persists_generation_floor() {
        let network = [0x72; 32];
        let authority = sk(0xb1);
        let governance = sk(0xb2);
        let recovery = sk(0xb3);
        let issuer = sk(0xb4);
        let (deployment_wire, registry_wire) =
            build_bootstrap_artifacts(network, &authority, &governance, &recovery, 47, &issuer)
                .unwrap();
        let authority_public = authority.verifying_key().to_bytes();
        let previous_wire = build_peer_identity_artifact(
            network,
            &deployment_wire,
            &authority_public,
            1,
            &registry_wire,
            47,
            88001,
            701,
            [0x31; 32],
            100,
            u64::MAX,
            &issuer,
        )
        .unwrap();
        let (rotated_wire, from_generation, to_generation) = build_rotated_peer_identity_artifact(
            network,
            &deployment_wire,
            &authority_public,
            1,
            &registry_wire,
            47,
            &previous_wire,
            [0x32; 32],
            100,
            u64::MAX,
            &issuer,
        )
        .unwrap();
        assert_eq!((from_generation, to_generation), (1, 2));
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let previous = verify_signed_peer_identity(
            &previous_wire,
            &network,
            47,
            &issuer.verifying_key().to_bytes(),
            now,
        )
        .unwrap();
        let rotated = verify_signed_peer_identity(
            &rotated_wire,
            &network,
            47,
            &issuer.verifying_key().to_bytes(),
            now,
        )
        .unwrap();
        assert_eq!(rotated.record.generation, 2);
        assert_eq!(rotated.record.public_key, [0x32; 32]);
        assert!(rotated.rotation_wire.is_some());

        let root = std::env::temp_dir().join(format!(
            "ain1-offline-peer-rotation-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        let highwater_path = root.join("peer.highwater");
        {
            let store = IdentityGenerationStateStore::open(
                &highwater_path,
                &network,
                701,
                KeyPurpose::PeerAuth,
                88001,
                47,
                issuer.verifying_key().to_bytes(),
            )
            .unwrap();
            store
                .observe_signed_record(&previous.record_bytes, &previous.record, None)
                .unwrap();
            store
                .observe_signed_record(
                    &rotated.record_bytes,
                    &rotated.record,
                    rotated.rotation_wire.as_deref(),
                )
                .unwrap();
            assert_eq!(store.high_generation().unwrap(), Some(2));
        }
        let store = IdentityGenerationStateStore::open(
            &highwater_path,
            &network,
            701,
            KeyPurpose::PeerAuth,
            88001,
            47,
            issuer.verifying_key().to_bytes(),
        )
        .unwrap();
        assert_eq!(
            store.observe_signed_record(&previous.record_bytes, &previous.record, None),
            Err(ai_native_l1_pow_bench::identity_generation_store::IdentityGenerationError::GenerationRollback)
        );
        store
            .observe_signed_record(&rotated.record_bytes, &rotated.record, None)
            .unwrap();
        assert_eq!(store.high_generation().unwrap(), Some(2));
        drop(store);
        let _ = fs::remove_dir_all(&root);

        assert!(build_rotated_peer_identity_artifact(
            network,
            &deployment_wire,
            &authority_public,
            1,
            &registry_wire,
            47,
            &previous_wire,
            [0x31; 32],
            100,
            u64::MAX,
            &issuer,
        )
        .unwrap_err()
        .contains("different Noise public key"));
        let other_issuer = sk(0xb5);
        assert!(build_rotated_peer_identity_artifact(
            network,
            &deployment_wire,
            &authority_public,
            1,
            &registry_wire,
            47,
            &previous_wire,
            [0x33; 32],
            100,
            u64::MAX,
            &other_issuer,
        )
        .unwrap_err()
        .contains("does not match"));
    }

    #[test]
    fn issuer_status_updates_are_monotonic_terminal_and_key_immutable() {
        let network = [0x62; 32];
        let authority = sk(0xb1);
        let governance = sk(0xb2);
        let recovery = sk(0xb3);
        let issuer = sk(0xb4);
        let (deployment_wire, initial_registry) =
            build_bootstrap_artifacts(network, &authority, &governance, &recovery, 37, &issuer)
                .unwrap();
        let authority_public = authority.verifying_key().to_bytes();
        let minimum_config_sequence = 1;

        let retired_wire = build_updated_registry_artifact(
            network,
            &deployment_wire,
            &authority_public,
            minimum_config_sequence,
            &initial_registry,
            37,
            IssuerStatus::Retired,
            &governance,
        )
        .unwrap();
        let retired = verify_signed_registry(
            &retired_wire,
            &network,
            &governance.verifying_key().to_bytes(),
        )
        .unwrap();
        assert_eq!(retired.sequence(), 2);
        assert_eq!(retired.entries()[0].status, IssuerStatus::Retired);
        assert_eq!(
            retired.entries()[0].public_key,
            issuer.verifying_key().to_bytes()
        );

        let revoked_wire = build_updated_registry_artifact(
            network,
            &deployment_wire,
            &authority_public,
            minimum_config_sequence,
            &retired_wire,
            37,
            IssuerStatus::Revoked,
            &governance,
        )
        .unwrap();
        let revoked = verify_signed_registry(
            &revoked_wire,
            &network,
            &governance.verifying_key().to_bytes(),
        )
        .unwrap();
        assert_eq!(revoked.sequence(), 3);
        assert_eq!(revoked.entries()[0].status, IssuerStatus::Revoked);
        assert_eq!(
            revoked.entries()[0].public_key,
            issuer.verifying_key().to_bytes()
        );

        assert!(build_updated_registry_artifact(
            network,
            &deployment_wire,
            &authority_public,
            minimum_config_sequence,
            &revoked_wire,
            37,
            IssuerStatus::Active,
            &governance,
        )
        .unwrap_err()
        .contains("cannot activate"));
        assert!(build_updated_registry_artifact(
            network,
            &deployment_wire,
            &authority_public,
            minimum_config_sequence,
            &revoked_wire,
            37,
            IssuerStatus::Retired,
            &governance,
        )
        .unwrap_err()
        .contains("StatusRollback"));
        assert!(build_updated_registry_artifact(
            network,
            &deployment_wire,
            &authority_public,
            minimum_config_sequence,
            &revoked_wire,
            37,
            IssuerStatus::Revoked,
            &governance,
        )
        .unwrap_err()
        .contains("no-op"));
        assert!(build_updated_registry_artifact(
            network,
            &deployment_wire,
            &authority_public,
            minimum_config_sequence,
            &initial_registry,
            37,
            IssuerStatus::Revoked,
            &sk(0xb5),
        )
        .unwrap_err()
        .contains("does not match"));
        assert!(parse_target_issuer_status("active").is_err());
        assert_eq!(
            parse_target_issuer_status("retired").unwrap(),
            IssuerStatus::Retired
        );
        assert_eq!(
            parse_target_issuer_status("revoked").unwrap(),
            IssuerStatus::Revoked
        );
    }

    #[test]
    fn option_parser_rejects_duplicate_options_and_private_seed_arguments() {
        assert!(parse_options(
            [
                "--role".to_string(),
                "peer-issuer".to_string(),
                "--role".to_string(),
                "governance-root".to_string()
            ]
            .into_iter()
        )
        .is_err());
        let err = parse_options(["--private-key-hex".to_string(), "abcd".to_string()].into_iter())
            .unwrap_err();
        assert!(err.contains("never accepted"));
    }
}
