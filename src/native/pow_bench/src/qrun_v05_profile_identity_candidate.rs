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
    0xee, 0xe2, 0xe7, 0x28, 0x82, 0xd7, 0x70, 0xab, 0x6f, 0xd7, 0x81, 0x5c, 0x90, 0x5b, 0x49, 0xe3,
    0x96, 0x50, 0xc7, 0x4e, 0x8f, 0x12, 0x1b, 0x26, 0xcb, 0xd4, 0x9e, 0x33, 0x3a, 0x37, 0x15, 0xc8,
];

/// Genesis state root computed from the canonical state-root encoding at height zero.
pub const PROPOSED_GENESIS_STATE_ROOT: [u8; 32] = [
    0x40, 0x64, 0xe1, 0xda, 0xfe, 0xc1, 0xc1, 0x8e, 0xd5, 0xfb, 0x03, 0x5f, 0x17, 0xb5, 0x15, 0xe1,
    0x1d, 0x5a, 0xb3, 0x14, 0xde, 0xa0, 0xa2, 0x0e, 0x22, 0x94, 0xf2, 0x30, 0x47, 0x0f, 0xf4, 0x40,
];

/// Commitment for the proposed network ID, owner, fixed supply, and Genesis state root.
pub const PROPOSED_GENESIS_COMMITMENT: [u8; 32] = [
    0x61, 0x3b, 0xb4, 0xf3, 0x6c, 0x8e, 0x57, 0xe7, 0x3d, 0xd0, 0x43, 0x08, 0x80, 0x9b, 0x9d, 0xec,
    0xdd, 0x1b, 0x44, 0x11, 0xe0, 0x83, 0x8f, 0x94, 0x8e, 0xe2, 0xaa, 0x7e, 0xaa, 0xcb, 0xab, 0x97,
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
            "613bb4f36c8e57e73dd04308809b9decdd1b4411e0838f948ee2aa7eaacbab97"
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
