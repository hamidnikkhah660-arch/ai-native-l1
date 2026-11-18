//! Read-only QFP6 CP-0651 Genesis snapshot auditor.
//! This tool never creates Genesis, signs it, changes the ledger, or contacts a node.
//! It reports the 1B owner balance only after verifying the canonical height-zero snapshot.

use ai_native_l1_pow_bench::{
    qrun_v06_canonical_execution_candidate::QRunV06CanonicalExecutionState,
    qrun_v06_cp0651_supply_candidate::CP0651_OWNER_GENESIS_ATOMS,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{env, fs, path::Path, process::ExitCode};

const MAX_SNAPSHOT_BYTES: u64 = 64 * 1024 * 1024;
const CP0651_MAX_SUPPLY_ATOMS: u128 = 700_000_000_000_000_000;
const CP0651_LABELS_TOTAL_ATOMS: u128 = 600_000_000_000_000_000;

fn parse_hex32(value: &str, name: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.is_ascii() {
        return Err(format!("{name} must be exactly 64 hexadecimal characters"));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16)
            .map_err(|_| format!("{name} contains a non-hexadecimal character"))?;
    }
    if out == [0; 32] {
        return Err(format!("{name} must be nonzero"));
    }
    Ok(out)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 15) as usize] as char);
    }
    out
}

fn verify_snapshot(
    bytes: &[u8],
    expected_network: &[u8; 32],
    expected_profile: &[u8; 32],
    expected_owner: &[u8; 32],
) -> Result<(u128, [u8; 32], [u8; 32]), String> {
    let state =
        QRunV06CanonicalExecutionState::decode_snapshot(bytes, expected_network, expected_profile)
            .map_err(|error| format!("QFP6 snapshot decode failed: {error:?}"))?;
    state
        .verify_invariants()
        .map_err(|error| format!("QFP6 execution invariants failed: {error:?}"))?;
    if state.height() != 0 {
        return Err("only a canonical height-zero Genesis snapshot can be audited".into());
    }
    let descriptor = state
        .genesis_descriptor()
        .ok_or("Genesis snapshot has no immutable Q6GD descriptor")?;
    if descriptor.network_id() != *expected_network
        || descriptor.profile_id() != *expected_profile
        || descriptor.founder_account() != *expected_owner
        || descriptor.genesis_timestamp() != state.last_timestamp()
    {
        return Err("Q6GD network/profile/owner/timestamp binding mismatch".into());
    }
    if state.tokenomics().is_some() || state.cp0604_supply().is_some() {
        return Err("legacy CP-0528/CP-0604 economics are not valid CP-0651 Genesis".into());
    }
    let supply = state
        .cp0651_supply()
        .ok_or("Genesis snapshot has no CP-0651 fixed-supply state")?;
    if supply.owner_account() != *expected_owner
        || supply.policy_fingerprint() != descriptor.tokenomics_policy_fingerprint()
        || supply.last_block_height() != 0
        || supply.maximum_supply_atoms() != CP0651_MAX_SUPPLY_ATOMS
        || supply.owner_genesis_atoms() != CP0651_OWNER_GENESIS_ATOMS
        || supply.accounting_labels_total_atoms() != CP0651_LABELS_TOTAL_ATOMS
        || supply.block_subsidy_atoms() != 0
    {
        return Err("CP-0651 owner/policy/7B/1B/six-labels/zero-subsidy binding mismatch".into());
    }
    let owner_balance = state
        .unified()
        .ledger()
        .account(expected_owner)
        .map_or(0u128, |account| account.balance as u128);
    let ledger_total = state
        .unified()
        .ledger()
        .total_value()
        .map_err(|error| format!("Ledger total calculation failed: {error:?}"))?;
    supply
        .validate_ledger_supply(ledger_total)
        .map_err(|error| format!("CP-0651 Ledger supply invariant failed: {error:?}"))?;
    if owner_balance != CP0651_OWNER_GENESIS_ATOMS || ledger_total != CP0651_OWNER_GENESIS_ATOMS {
        return Err(
            "owner balance and issued Ledger supply must both equal exactly 1B QZXB".into(),
        );
    }
    let root = state
        .state_root()
        .map_err(|error| format!("Genesis state-root calculation failed: {error:?}"))?;
    Ok((owner_balance, root, descriptor.commitment()))
}

fn run(args: &[String]) -> Result<(), String> {
    if args == ["--help"] {
        println!("qfp6_genesis_audit --snapshot ABSOLUTE_PATH --network-id-hex HEX64 --profile-id-hex HEX64 --owner-account-id-hex HEX64");
        println!("Read-only only: verifies CP-0651 7B/1B/six-label/zero-subsidy height-zero Genesis; does not query a live node.");
        return Ok(());
    }
    if args.len() != 8
        || args[0] != "--snapshot"
        || args[2] != "--network-id-hex"
        || args[4] != "--profile-id-hex"
        || args[6] != "--owner-account-id-hex"
    {
        return Err("expected --snapshot ABSOLUTE_PATH --network-id-hex HEX64 --profile-id-hex HEX64 --owner-account-id-hex HEX64".into());
    }
    let path = Path::new(&args[1]);
    if !path.is_absolute() {
        return Err("snapshot path must be absolute".into());
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect Genesis snapshot: {error}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_SNAPSHOT_BYTES
    {
        return Err("Genesis snapshot must be a nonempty regular file no larger than 64 MiB; symlinks are refused".into());
    }
    let network = parse_hex32(&args[3], "network ID")?;
    let profile = parse_hex32(&args[5], "profile ID")?;
    let owner = parse_hex32(&args[7], "owner account ID")?;
    let bytes = fs::read(path).map_err(|error| format!("cannot read Genesis snapshot: {error}"))?;
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    let (balance, root, descriptor) = verify_snapshot(&bytes, &network, &profile, &owner)?;
    let output = json!({
        "audit": "PASS",
        "policy": "CP-0651",
        "maximum_supply_atoms": CP0651_MAX_SUPPLY_ATOMS.to_string(),
        "accounting_labels_total_atoms": CP0651_LABELS_TOTAL_ATOMS.to_string(),
        "block_subsidy_atoms": "0",
        "snapshot_sha256": hex(&digest),
        "network_id": hex(&network),
        "profile_id": hex(&profile),
        "owner_account_id": hex(&owner),
        "owner_balance_atoms": balance.to_string(),
        "owner_balance_qzxb": "1000000000",
        "ledger_issued_supply_atoms": balance.to_string(),
        "genesis_state_root": hex(&root),
        "q6gd_commitment": hex(&descriptor),
        "height": 0,
        "network_class": "genesis_snapshot_audit_not_live_node",
        "read_only": true,
        "mainnet_authorized": false
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&output).map_err(|e| e.to_string())?
    );
    Ok(())
}

fn main() -> ExitCode {
    let args = env::args().skip(1).collect::<Vec<_>>();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("QFP6 GENESIS AUDIT REFUSED: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ai_native_l1_pow_bench::{
        qrun_v06_canonical_execution_candidate::QRunV06CanonicalExecutionState,
        qrun_v06_cp0651_supply_candidate::Cp0651FixedSupply,
        qrun_v06_genesis_descriptor_candidate::QRunV06GenesisDescriptor,
        qrun_v06_tokenomics_candidate::QRunV06MiningScheduleCandidate,
    };

    #[test]
    fn verifies_only_cp0651_genesis_and_exact_owner_balance() {
        let network = [0x71; 32];
        let profile = [0x72; 32];
        let owner = [0x73; 32];
        let policy = Cp0651FixedSupply::genesis(network, owner).unwrap();
        let descriptor = QRunV06GenesisDescriptor::new(
            network,
            profile,
            owner,
            1_800_000_000,
            [0x74; 32],
            policy.policy_fingerprint(),
        )
        .unwrap();
        let state =
            QRunV06CanonicalExecutionState::cp0651_genesis_candidate_with_descriptor(descriptor)
                .unwrap();
        let bytes = state.encode_snapshot().unwrap();
        let (balance, root, commitment) =
            verify_snapshot(&bytes, &network, &profile, &owner).unwrap();
        assert_eq!(balance, CP0651_OWNER_GENESIS_ATOMS);
        assert_ne!(root, [0; 32]);
        assert_ne!(commitment, [0; 32]);
        assert!(verify_snapshot(&bytes, &network, &profile, &[0x75; 32]).is_err());
    }

    #[test]
    fn rejects_legacy_cp0528_and_cp0604_genesis() {
        let network = [0x81; 32];
        let profile = [0x82; 32];
        let owner = [0x83; 32];
        let schedule = QRunV06MiningScheduleCandidate::cp0422_research_candidate();
        let legacy_0528 = QRunV06CanonicalExecutionState::cp0528_genesis_candidate(
            network, profile, owner, schedule,
        )
        .unwrap();
        let bytes = legacy_0528.encode_snapshot().unwrap();
        assert!(verify_snapshot(&bytes, &network, &profile, &owner).is_err());
        let legacy_0604 = QRunV06CanonicalExecutionState::cp0604_genesis_candidate(
            network, profile, owner, schedule,
        )
        .unwrap();
        let bytes = legacy_0604.encode_snapshot().unwrap();
        assert!(verify_snapshot(&bytes, &network, &profile, &owner).is_err());
    }
}
