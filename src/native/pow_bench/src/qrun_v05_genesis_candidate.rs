//! QRun v0.5 full-supply Genesis candidate requested on 2026-10-28.
//!
//! IMPORTANT: this builds a deterministic in-memory candidate state only. It is not wired into
//! the QZBE production node/runtime, does not launch Mainnet, and does not by itself make coins
//! live or transferable on a public network. Because the entire 10B cap is credited at Genesis,
//! compatible production consensus must set all subsequent issuance/rewards to zero (fee-only
//! miner compensation) and reject any legacy Genesis profile.
use crate::state_machine::{AccountId, LedgerState, NetworkId, StateError, MAX_TOTAL_SUPPLY_ATOMS};
use sha2::{Digest, Sha256};

const GENESIS_DOMAIN: &[u8] = b"QUANTUMZXB-QRUN-GENESIS-V05\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QRunGenesisError {
    ZeroNetworkId,
    ZeroOwnerAccount,
    Ledger(StateError),
    SupplyMismatch { expected: u128, actual: u128 },
}

/// Genesis candidate with 100% of the capped native QZXB supply credited to the owner.
pub struct QRunGenesisV05 {
    network_id: NetworkId,
    owner_account: AccountId,
    ledger: LedgerState,
    commitment: [u8; 32],
}

impl QRunGenesisV05 {
    pub fn new(network_id: NetworkId, owner_account: AccountId) -> Result<Self, QRunGenesisError> {
        if network_id.iter().all(|byte| *byte == 0) {
            return Err(QRunGenesisError::ZeroNetworkId);
        }
        if owner_account.iter().all(|byte| *byte == 0) {
            return Err(QRunGenesisError::ZeroOwnerAccount);
        }
        let owner_balance = u64::try_from(MAX_TOTAL_SUPPLY_ATOMS).map_err(|_| {
            QRunGenesisError::SupplyMismatch {
                expected: MAX_TOTAL_SUPPLY_ATOMS,
                actual: 0,
            }
        })?;
        let ledger = LedgerState::genesis(network_id, vec![(owner_account, owner_balance)])
            .map_err(QRunGenesisError::Ledger)?;
        let actual = ledger.total_value().map_err(QRunGenesisError::Ledger)?;
        if actual != MAX_TOTAL_SUPPLY_ATOMS {
            return Err(QRunGenesisError::SupplyMismatch {
                expected: MAX_TOTAL_SUPPLY_ATOMS,
                actual,
            });
        }
        let mut hasher = Sha256::new();
        hasher.update(GENESIS_DOMAIN);
        hasher.update(network_id);
        hasher.update(owner_account);
        hasher.update(MAX_TOTAL_SUPPLY_ATOMS.to_be_bytes());
        hasher.update(ledger.state_root());
        let commitment = hasher.finalize().into();
        Ok(Self {
            network_id,
            owner_account,
            ledger,
            commitment,
        })
    }

    pub fn network_id(&self) -> NetworkId {
        self.network_id
    }
    pub fn owner_account(&self) -> AccountId {
        self.owner_account
    }
    pub fn owner_balance_atoms(&self) -> u128 {
        MAX_TOTAL_SUPPLY_ATOMS
    }
    pub fn total_supply_atoms(&self) -> Result<u128, StateError> {
        self.ledger.total_value()
    }
    pub fn state_root(&self) -> [u8; 32] {
        self.ledger.state_root()
    }
    pub fn commitment(&self) -> [u8; 32] {
        self.commitment
    }
    pub fn ledger(&self) -> &LedgerState {
        &self.ledger
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_machine::ATOMS_PER_COIN;

    const NETWORK: NetworkId = [0x51; 32];
    const OWNER: AccountId = [0x2a; 32];

    #[test]
    fn qrun_genesis_credits_exactly_ten_billion_to_the_selected_owner() {
        let genesis = QRunGenesisV05::new(NETWORK, OWNER).unwrap();
        assert_eq!(MAX_TOTAL_SUPPLY_ATOMS, 10_000_000_000 * ATOMS_PER_COIN);
        assert_eq!(genesis.owner_account(), OWNER);
        assert_eq!(genesis.owner_balance_atoms(), 1_000_000_000_000_000_000);
        assert_eq!(
            genesis.total_supply_atoms().unwrap(),
            1_000_000_000_000_000_000
        );
        assert_eq!(genesis.ledger().account_count(), 1);
    }

    #[test]
    fn qrun_genesis_rejects_zero_network_and_owner() {
        assert!(matches!(
            QRunGenesisV05::new([0; 32], OWNER),
            Err(QRunGenesisError::ZeroNetworkId)
        ));
        assert!(matches!(
            QRunGenesisV05::new(NETWORK, [0; 32]),
            Err(QRunGenesisError::ZeroOwnerAccount)
        ));
    }

    #[test]
    fn qrun_genesis_commitment_binds_the_network_and_owner() {
        let first = QRunGenesisV05::new(NETWORK, OWNER).unwrap();
        let repeat = QRunGenesisV05::new(NETWORK, OWNER).unwrap();
        let other_owner = QRunGenesisV05::new(NETWORK, [0x2b; 32]).unwrap();
        let other_network = QRunGenesisV05::new([0x52; 32], OWNER).unwrap();
        assert_eq!(first.commitment(), repeat.commitment());
        assert_ne!(first.commitment(), other_owner.commitment());
        assert_ne!(first.commitment(), other_network.commitment());
        assert_ne!(first.state_root(), other_owner.state_root());
        assert_ne!(first.state_root(), other_network.state_root());
    }
}
