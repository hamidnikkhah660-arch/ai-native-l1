//! Candidate frozen identity for the future QRun v0.5 10B QZXB Genesis.
//!
//! This binds one domain-separated network identity and the owner's public account ID, but it
//! deliberately does not activate Mainnet. Consensus/difficulty, producer fee settlement, full
//! history recovery, peer bootstrap, external anti-rollback, and independent review remain gates.
use crate::qrun_v05_genesis_candidate::{QRunGenesisError, QRunGenesisV05};
#[cfg(test)]
use crate::state_machine::MAX_TOTAL_SUPPLY_ATOMS;
use crate::state_machine::{AccountId, NetworkId};
#[cfg(test)]
use sha2::{Digest, Sha256};

#[cfg(test)]
const NETWORK_ID_DOMAIN: &[u8] = b"QUANTUMZXB-QRUN-MAINNET-NETWORK-ID-V05\0";

/// SHA-256 of `QUANTUMZXB-QRUN-MAINNET-NETWORK-ID-V05\0`.
/// This is only the proposed identity; it does not turn any running node into Mainnet.
pub const PROPOSED_QRUN_V05_NETWORK_ID: NetworkId = [
    0x70, 0xfd, 0xcd, 0xbe, 0x6f, 0x0a, 0xfa, 0x1e, 0xdb, 0x0c, 0x4f, 0xb4, 0xa8, 0x52, 0x52, 0x83,
    0x13, 0x76, 0xf7, 0xb9, 0xec, 0xf2, 0xa1, 0x3a, 0x86, 0xdc, 0xf6, 0x19, 0x79, 0xcd, 0xca, 0xd7,
];

/// Public account ID read from the owner's persistent QZXB wallet. Never a secret key.
pub const PROPOSED_OWNER_ACCOUNT_ID: AccountId = [
    0x0f, 0x52, 0x1d, 0xeb, 0xfc, 0x16, 0xbd, 0x0f, 0xa2, 0xcb, 0xe4, 0x4b, 0xe3, 0x96, 0x87, 0x57,
    0x02, 0x75, 0x0f, 0xb3, 0xba, 0xed, 0x37, 0x20, 0xf1, 0x8b, 0xd0, 0xad, 0x8b, 0xc7, 0x4c, 0x88,
];

/// Genesis state root computed from the canonical state-root encoding at height zero.
pub const PROPOSED_GENESIS_STATE_ROOT: [u8; 32] = [
    0x9d, 0x8a, 0xb7, 0xe2, 0xc4, 0x15, 0xe8, 0x39, 0x90, 0xa6, 0x32, 0x74, 0xe7, 0x85, 0x1e, 0x6e,
    0xbd, 0x89, 0x18, 0x68, 0xa7, 0x44, 0x22, 0xa6, 0xe6, 0xed, 0x41, 0x88, 0x95, 0xf2, 0x78, 0x87,
];

/// Commitment for the proposed network ID, owner, fixed supply, and Genesis state root.
pub const PROPOSED_GENESIS_COMMITMENT: [u8; 32] = [
    0x08, 0x15, 0xc0, 0x1a, 0x85, 0x37, 0x3c, 0xaf, 0x7f, 0x50, 0xb5, 0x3a, 0xae, 0xb7, 0xa2, 0x69,
    0xef, 0x4a, 0x15, 0x1f, 0x2a, 0x3b, 0xa3, 0x17, 0x1a, 0xcc, 0x8e, 0xe2, 0xb5, 0x2f, 0x89, 0x08,
];

pub const PROPOSED_POST_GENESIS_MINTING: bool = false;
pub const PROPOSED_BLOCK_SUBSIDY_ATOMS: u128 = 0;

/// Builds the candidate Genesis state using the proposed identity. Not a public launch API.
pub fn build_candidate_genesis() -> Result<QRunGenesisV05, QRunGenesisError> {
    QRunGenesisV05::new(PROPOSED_QRUN_V05_NETWORK_ID, PROPOSED_OWNER_ACCOUNT_ID)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn proposed_identity_builds_the_exact_full_supply_candidate_genesis() {
        let genesis = build_candidate_genesis().unwrap();
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(NETWORK_ID_DOMAIN)),
            PROPOSED_QRUN_V05_NETWORK_ID
        );
        assert_eq!(genesis.network_id(), PROPOSED_QRUN_V05_NETWORK_ID);
        assert_eq!(genesis.owner_account(), PROPOSED_OWNER_ACCOUNT_ID);
        assert_eq!(
            genesis.total_supply_atoms().unwrap(),
            MAX_TOTAL_SUPPLY_ATOMS
        );
        assert_eq!(genesis.owner_balance_atoms(), 1_000_000_000_000_000_000);
        assert_eq!(genesis.ledger().account_count(), 1);
        assert_eq!(genesis.state_root(), PROPOSED_GENESIS_STATE_ROOT);
        assert_eq!(genesis.commitment(), PROPOSED_GENESIS_COMMITMENT);
        assert_eq!(
            hex(&genesis.commitment()),
            "0815c01a85373caf7f50b53aaeb7a269ef4a151f2a3ba3171acc8ee2b52f8908"
        );
        assert!(!PROPOSED_POST_GENESIS_MINTING);
        assert_eq!(PROPOSED_BLOCK_SUBSIDY_ATOMS, 0);
    }

    #[test]
    fn proposed_identity_commitment_changes_for_a_different_owner_or_network() {
        let genesis = build_candidate_genesis().unwrap();
        let different_owner =
            QRunGenesisV05::new(PROPOSED_QRUN_V05_NETWORK_ID, [0x7b; 32]).unwrap();
        let different_network = QRunGenesisV05::new([0x7c; 32], PROPOSED_OWNER_ACCOUNT_ID).unwrap();
        assert_ne!(genesis.commitment(), different_owner.commitment());
        assert_ne!(genesis.commitment(), different_network.commitment());
    }
}
