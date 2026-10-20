use ai_native_l1_pow_bench::bounded_reward_pools_candidate::{
    ClaimSignature, PoolAccounting, RewardClaim, RewardPool, RewardPoolConfig,
};
use ed25519_dalek::{Signer, SigningKey};
use std::collections::{BTreeMap, BTreeSet};

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

fn main() {
    // Deterministic test fixtures only. Their private seeds are never serialized or printed.
    let keys = [
        SigningKey::from_bytes(&[11; 32]),
        SigningKey::from_bytes(&[22; 32]),
        SigningKey::from_bytes(&[33; 32]),
    ];
    let authorized_signers: BTreeSet<[u8; 32]> = keys
        .iter()
        .map(|key| key.verifying_key().to_bytes())
        .collect();
    let pool_ceilings_atoms: BTreeMap<RewardPool, u128> = [
        (RewardPool::Adoption, 100),
        (RewardPool::DeveloperEcosystem, 100),
        (RewardPool::Security, 50),
        (RewardPool::CommunityInfrastructure, 50),
    ]
    .into_iter()
    .collect();
    let config = RewardPoolConfig {
        network_id: [0xA1; 32],
        maximum_supply_atoms: 1_000,
        initially_issued_atoms: 100,
        miner_budget_atoms: 600,
        pool_ceilings_atoms,
        authorized_signers,
        signature_threshold: 2,
    };
    let mut accounting = PoolAccounting::new(config.clone()).expect("valid fixture config");
    accounting
        .record_mining_reward(8)
        .expect("valid fixture mining reward");

    let mut claim = RewardClaim {
        network_id: config.network_id,
        pool: RewardPool::Adoption,
        amount_atoms: 25,
        recipient: [0x77; 32],
        claim_id: [18; 32],
        valid_from_epoch: 5,
        expires_at_epoch: 10,
        signatures: Vec::new(),
    };
    let message = claim.signing_bytes();
    claim.signatures = keys[..2]
        .iter()
        .map(|key| ClaimSignature {
            signer_public_key: key.verifying_key().to_bytes(),
            signature: key.sign(&message).to_bytes(),
        })
        .collect();
    accounting
        .apply_claim(&claim, 6)
        .expect("valid fixture claim");
    let snapshot = accounting.snapshot_bytes().expect("valid fixture snapshot");

    println!("{{");
    println!("  \"schema\": \"cpw-reward-pool-snapshot-v1\",");
    println!("  \"test_fixture_only\": true,");
    println!("  \"config\": {{");
    println!("    \"network_id_hex\": \"{}\",", hex(&config.network_id));
    println!(
        "    \"maximum_supply_atoms\": \"{}\",",
        config.maximum_supply_atoms
    );
    println!(
        "    \"initially_issued_atoms\": \"{}\",",
        config.initially_issued_atoms
    );
    println!(
        "    \"miner_budget_atoms\": \"{}\",",
        config.miner_budget_atoms
    );
    println!(
        "    \"signature_threshold\": {},",
        config.signature_threshold
    );
    println!("    \"pool_ceilings_atoms\": [");
    for (index, pool) in RewardPool::ALL.iter().enumerate() {
        println!(
            "      {{\"pool_id\": {}, \"amount_atoms\": \"{}\"}}{}",
            pool.id(),
            config.pool_ceilings_atoms[pool],
            if index + 1 == RewardPool::ALL.len() {
                ""
            } else {
                ","
            }
        );
    }
    println!("    ],");
    println!("    \"authorized_signer_public_keys_hex\": [");
    let signers: Vec<[u8; 32]> = config.authorized_signers.iter().copied().collect();
    for (index, signer) in signers.iter().enumerate() {
        println!(
            "      \"{}\"{}",
            hex(signer),
            if index + 1 == signers.len() { "" } else { "," }
        );
    }
    println!("    ]");
    println!("  }},");
    println!("  \"expected_state\": {{");
    println!("    \"issued_atoms\": \"{}\",", accounting.issued_atoms());
    println!(
        "    \"miner_issued_atoms\": \"{}\",",
        accounting.miner_issued_atoms()
    );
    println!("    \"recipient_hex\": \"{}\",", hex(&[0x77; 32]));
    println!("    \"recipient_balance_atoms\": \"25\",");
    println!("    \"applied_claim_id_hex\": \"{}\"", hex(&[18; 32]));
    println!("  }},");
    println!("  \"snapshot_hex\": \"{}\"", hex(&snapshot));
    println!("}}");
}
