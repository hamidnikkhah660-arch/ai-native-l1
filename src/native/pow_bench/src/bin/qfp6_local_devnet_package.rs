use ai_native_l1_pow_bench::{
    consensus::ConsensusParameters, external_cas_anchor_candidate::ExternalCasPin,
    qrun_v06_canonical_execution_candidate::QRunV06CanonicalExecutionState,
    qrun_v06_consensus_profile_candidate::QRunV06ConsensusProfile,
    qrun_v06_cp0651_supply_candidate::Cp0651FixedSupply,
    qrun_v06_genesis_descriptor_candidate::QRunV06GenesisDescriptor,
    qrun_v06_profile_pin_candidate::QRunV06ProfilePinCandidate,
    v4_fat1_trust_candidate::ML_DSA_65_PUBLIC_KEY_BYTES,
};
use libcrux_ml_dsa::ml_dsa_65::portable;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_hex32(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.is_ascii() {
        return Err("owner account ID must be exactly 64 hexadecimal characters".into());
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16)
            .map_err(|_| "owner account ID contains non-hexadecimal characters")?;
    }
    if out == [0; 32] {
        return Err("owner account ID must not be zero".into());
    }
    Ok(out)
}

fn random32(label: &str) -> Result<[u8; 32], String> {
    let mut out = [0u8; 32];
    getrandom::getrandom(&mut out).map_err(|e| format!("OS CSPRNG failed for {label}: {e}"))?;
    if out == [0; 32] {
        return Err(format!("OS CSPRNG returned a zero {label}"));
    }
    Ok(out)
}

fn hash_domain(domain: &[u8], fields: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain);
    for field in fields {
        h.update((field.len() as u64).to_be_bytes());
        h.update(field);
    }
    h.finalize().into()
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
    file.write_all(bytes)
        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    file.sync_all()
        .map_err(|e| format!("cannot flush {}: {e}", path.display()))
}

fn main_result() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let mut output = None::<PathBuf>;
    let mut owner_hex = None::<String>;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--output-dir" => {
                if output.is_some() {
                    return Err("--output-dir specified more than once".into());
                }
                output = Some(PathBuf::from(
                    args.next().ok_or("--output-dir needs a value")?,
                ));
            }
            "--owner-account-id-hex" => {
                if owner_hex.is_some() {
                    return Err("--owner-account-id-hex specified more than once".into());
                }
                owner_hex = Some(args.next().ok_or("--owner-account-id-hex needs a value")?);
            }
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }

    let out_dir = output.ok_or("missing --output-dir")?;
    let owner = parse_hex32(&owner_hex.ok_or("missing --owner-account-id-hex")?)?;
    if !out_dir.is_absolute() {
        return Err("--output-dir must be an absolute path".into());
    }
    if out_dir.exists() {
        let mut entries =
            fs::read_dir(&out_dir).map_err(|e| format!("cannot inspect output directory: {e}"))?;
        if entries.next().is_some() {
            return Err("output directory is not empty; refusing to overwrite any artifact".into());
        }
    } else {
        fs::create_dir_all(&out_dir).map_err(|e| format!("cannot create output directory: {e}"))?;
    }
    fs::create_dir_all(out_dir.join("protected"))
        .map_err(|e| format!("cannot create protected directory: {e}"))?;
    fs::create_dir_all(out_dir.join("runtime"))
        .map_err(|e| format!("cannot create runtime directory: {e}"))?;

    let network_id = random32("network ID")?;
    let profile_id = random32("profile ID")?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("system clock is before Unix epoch: {e}"))?
        .as_secs();
    if timestamp == 0 {
        return Err("invalid Genesis timestamp".into());
    }

    let policy = Cp0651FixedSupply::genesis(network_id, owner)
        .map_err(|e| format!("CP-0651 Genesis policy construction failed: {e:?}"))?;
    let tokenomics_fingerprint = policy.policy_fingerprint();

    let params = ConsensusParameters::qrun_v06_cp0651_fee_only_candidate()
        .map_err(|e| format!("CP-0651 QFP6 candidate parameters failed: {e:?}"))?;
    let consensus_fingerprint = QRunV06ConsensusProfile::fingerprint_parameters(&params)
        .map_err(|e| format!("consensus fingerprint failed: {e:?}"))?;

    let descriptor = QRunV06GenesisDescriptor::new(
        network_id,
        profile_id,
        owner,
        timestamp,
        consensus_fingerprint,
        tokenomics_fingerprint,
    )
    .map_err(|e| format!("Q6GD construction failed: {e:?}"))?;

    let q6cp =
        QRunV06ConsensusProfile::new(network_id, profile_id, descriptor.commitment(), params)
            .map_err(|e| format!("Q6CP construction failed: {e:?}"))?;
    q6cp.validate_against(&descriptor)
        .map_err(|e| format!("Q6CP/Q6GD binding failed: {e:?}"))?;
    let q6cp_bytes = q6cp
        .encode()
        .map_err(|e| format!("Q6CP encoding failed: {e:?}"))?;

    let genesis =
        QRunV06CanonicalExecutionState::cp0651_genesis_candidate_with_descriptor(descriptor)
            .map_err(|e| format!("CP-0651 Genesis state construction failed: {e:?}"))?;
    genesis
        .verify_invariants()
        .map_err(|e| format!("CP-0651 Genesis invariant failed: {e:?}"))?;
    let genesis_state_root = genesis
        .state_root()
        .map_err(|e| format!("Genesis state-root calculation failed: {e:?}"))?;
    let genesis_bytes = genesis
        .encode_snapshot()
        .map_err(|e| format!("Genesis snapshot encoding failed: {e:?}"))?;

    // Q6PN v1 retains legacy external-CAS identity fields. This local full-history profile
    // deliberately does not configure Q6TS/Q6QA/Q6EA; the ephemeral public key below is
    // an inert shape-valid placeholder and is not an operating provider or trust authority.
    let mldsa_seed = random32("ephemeral local-only Q6PN placeholder seed")?;
    let generated = portable::generate_key_pair(mldsa_seed);
    let receipt_public_key: [u8; ML_DSA_65_PUBLIC_KEY_BYTES] = *generated.verification_key.as_ref();
    drop(generated);

    let provider_id = hash_domain(
        b"QRUN-LOCAL-ONLY-DORMANT-CAS-PROVIDER-V1\0",
        &[&network_id, &profile_id],
    );
    let receipt_key_id = sha256(&receipt_public_key);
    let external_cas_pin = ExternalCasPin {
        provider_id,
        network_id,
        genesis_digest: sha256(&genesis_bytes),
        receipt_key_id,
        receipt_public_key,
    };
    let q6pn = QRunV06ProfilePinCandidate::new(descriptor, external_cas_pin)
        .map_err(|e| format!("Q6PN local-only profile bundle construction failed: {e:?}"))?;
    let q6pn_bytes = q6pn
        .encode()
        .map_err(|e| format!("Q6PN encoding failed: {e:?}"))?;
    let q6pn_commitment = q6pn
        .commitment()
        .map_err(|e| format!("Q6PN commitment calculation failed: {e:?}"))?;

    let bootstrap_bytes = b"[]\n";
    let config = json!({
        "local_only_notice": "SINGLE_OPERATOR_LOOPBACK_DEVNET_ONLY_NOT_PUBLIC_TESTNET_NOT_MAINNET",
        "permissionless_runtime": {
            "mode": "permissionless-full-history-candidate",
            "allow_candidate_runtime": true,
            "allow_public_listener": false,
            "q6gd_descriptor_path": "genesis-descriptor.q6gd",
            "q6gd_descriptor_sha256": hex(&sha256(&descriptor.encode())),
            "q6pn_profile_pin_path": "q6pn-profile.q6pn",
            "q6pn_profile_pin_commitment": hex(&q6pn_commitment),
            "q6pn_profile_pin_sha256": hex(&sha256(&q6pn_bytes)),
            "q6cp_profile_path": "consensus-profile.q6cp",
            "q6cp_profile_sha256": hex(&sha256(&q6cp_bytes)),
            "genesis_snapshot_path": "genesis-snapshot.q6sn",
            "genesis_snapshot_sha256": hex(&sha256(&genesis_bytes)),
            "bootstrap_peers_path": "bootstrap-peers.json",
            "bootstrap_peers_sha256": hex(&sha256(bootstrap_bytes)),
            "node_noise_private_key_path": "protected/node-noise-static-key.npk",
            "listen_address": "127.0.0.1:30333",
            "producer_account": hex(&owner),
            "data_directory": "runtime/data",
            "mempool_directory": "runtime/mempool",
            "enable_q6ar_candidate_address_book": false,
            "enable_approved_peer_outbound_sync": false
        }
    });
    let config_bytes = serde_json::to_vec_pretty(&config)
        .map_err(|e| format!("permissionless config JSON encode failed: {e}"))?;
    let config_bytes = [config_bytes, b"\n".to_vec()].concat();

    let descriptor_bytes = descriptor.encode();
    write_new(&out_dir.join("genesis-descriptor.q6gd"), &descriptor_bytes)?;
    write_new(&out_dir.join("consensus-profile.q6cp"), &q6cp_bytes)?;
    write_new(&out_dir.join("genesis-snapshot.q6sn"), &genesis_bytes)?;
    write_new(&out_dir.join("q6pn-profile.q6pn"), &q6pn_bytes)?;
    write_new(&out_dir.join("bootstrap-peers.json"), bootstrap_bytes)?;
    write_new(&out_dir.join("permissionless-config.json"), &config_bytes)?;

    let manifest = json!({
        "package": "QFP6 local single-operator CP-0651 devnet",
        "schema": "qfp6-local-only-devnet/v1",
        "scope": "LOCAL_SINGLE_OPERATOR_LOOPBACK_ONLY",
        "created_at_unix": timestamp,
        "network_id_hex": hex(&network_id),
        "profile_id_hex": hex(&profile_id),
        "owner_account_id_hex": hex(&owner),
        "genesis_timestamp_unix": timestamp,
        "genesis_height": 0,
        "genesis_owner_allocation_qzxb": "1000000000",
        "gross_supply_ceiling_qzxb": "7000000000",
        "six_accounting_labels_are_spendable": false,
        "block_subsidy_qzxb": "0",
        "producer_compensation": "canonical_transaction_fees_only",
        "consensus_fingerprint_hex": hex(&consensus_fingerprint),
        "tokenomics_policy_fingerprint_hex": hex(&tokenomics_fingerprint),
        "genesis_state_root_hex": hex(&genesis_state_root),
        "genesis_descriptor_commitment_hex": hex(&descriptor.commitment()),
        "q6gd_sha256": hex(&sha256(&descriptor_bytes)),
        "q6cp_sha256": hex(&sha256(&q6cp_bytes)),
        "q6pn_sha256": hex(&sha256(&q6pn_bytes)),
        "q6pn_local_self_pin_commitment_hex": hex(&q6pn_commitment),
        "genesis_snapshot_sha256": hex(&sha256(&genesis_bytes)),
        "bootstrap_peers_sha256": hex(&sha256(bootstrap_bytes)),
        "bootstrap_peer_count": 0,
        "noise_transport": "local_loopback_only; no public inbound exposure",
        "q6pn_legacy_external_cas_fields": "inert local-only placeholder; no Provider/Q6EA/Q6TS/Q6QA configured",
        "q6ts_required_for_profile": false,
        "independent_consensus_review": "PENDING",
        "independent_cryptography_review": "PENDING",
        "independent_economics_review": "PENDING",
        "genesis_owner_signature_present": false,
        "owner_genesis_approval_format": "Q6GA_V1_ED25519_MLDSA65",
        "owner_genesis_approval_sha256": null,
        "public_testnet_authorized": false,
        "public_mining_authorized": false,
        "mainnet_authorized": false,
        "real_value_issuance_or_transfer": false
    });
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| format!("local devnet manifest JSON encode failed: {e}"))?;
    write_new(
        &out_dir.join("local-devnet-manifest.json"),
        &[manifest_bytes, b"\n".to_vec()].concat(),
    )?;

    println!("LOCAL_QFP6_DEVNET_PACKAGE=CREATED");
    println!("scope=LOCAL_SINGLE_OPERATOR_LOOPBACK_ONLY");
    println!("network_id_hex={}", hex(&network_id));
    println!("profile_id_hex={}", hex(&profile_id));
    println!("owner_account_id_hex={}", hex(&owner));
    println!("genesis_timestamp_unix={timestamp}");
    println!("genesis_height=0");
    println!("owner_genesis_allocation_qzxb=1000000000");
    println!("block_subsidy_qzxb=0");
    println!(
        "genesis_descriptor_commitment_hex={}",
        hex(&descriptor.commitment())
    );
    println!("consensus_fingerprint_hex={}", hex(&consensus_fingerprint));
    println!(
        "tokenomics_policy_fingerprint_hex={}",
        hex(&tokenomics_fingerprint)
    );
    println!("genesis_state_root_hex={}", hex(&genesis_state_root));
    println!("genesis_snapshot_sha256={}", hex(&sha256(&genesis_bytes)));
    println!("q6gd_sha256={}", hex(&sha256(&descriptor_bytes)));
    println!("q6cp_sha256={}", hex(&sha256(&q6cp_bytes)));
    println!("q6pn_sha256={}", hex(&sha256(&q6pn_bytes)));
    println!(
        "q6pn_local_self_pin_commitment_hex={}",
        hex(&q6pn_commitment)
    );
    println!(
        "permissionless_config_sha256={}",
        hex(&sha256(&config_bytes))
    );
    println!("bootstrap_peers_sha256={}", hex(&sha256(bootstrap_bytes)));
    println!("genesis_snapshot_bytes={}", genesis_bytes.len());
    println!("q6gd_bytes={}", descriptor_bytes.len());
    println!("q6cp_bytes={}", q6cp_bytes.len());
    println!("q6pn_bytes={}", q6pn_bytes.len());
    println!("bootstrap_peer_count=0");
    println!("q6pn_placeholder_provider_key_persisted=false");
    println!("production_authorized=false");
    Ok(())
}

fn main() {
    if let Err(error) = main_result() {
        eprintln!("QFP6_LOCAL_DEVNET_PACKAGE_ERROR: {error}");
        std::process::exit(2);
    }
}
